//! Driver for virtio-vsock: one stream connection to a host listener (CID 2, port `HOST_PORT`),
//! with the same IPC interface as the console driver (`vanir_user::console`): `OP_WRITE`
//! replied `CODE_OK` once the device has taken the bytes, `CODE_BUSY` when every slot is used.
//!
//! The stream is opened at start and reopened after the host resets it. Data respects the
//! host's advertised receive credit (`buf_alloc` minus what we sent beyond its `fwd_cnt`).

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use vanir_user::console::{CODE_BAD_OP, CODE_BUSY, CODE_OK, OP_WRITE};
use vanir_user::{NOTIFY_IRQ, NOTIFY_TIMER, RECV_EXPECT_IRQ, RECV_TIMEOUT, err, println};
use virtio::{Buffer, Dma, Queue, Transport};

vanir_user::entry!(main);

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const HOST_CID: u64 = 2;
const HOST_PORT: u32 = 5000;
const LOCAL_PORT: u32 = 1024;

const HEADER: u64 = 44;
const SLOTS: usize = 8;
const SLOT_SIZE: u64 = 4096 + HEADER;
const RX_BUFFERS: usize = 8;
const RX_SIZE: u64 = 4096;
/// What we tell the host it may send us (we discard host data, but must account for it).
const OUR_BUF_ALLOC: u32 = (RX_BUFFERS as u64 * RX_SIZE) as u32;
/// Retry connecting after a refusal or reset after this many ticks.
const RETRY_TICKS: u64 = 20;

const TYPE_STREAM: u16 = 1;
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Down,
    Connecting,
    Up,
}

#[derive(Clone, Copy)]
struct Write {
    client: u64,
    len: u32,
    /// Descriptor id once posted to the transmit queue.
    posted: Option<u16>,
}

struct Driver {
    tx: Queue,
    rx: Queue,
    guest_cid: u64,
    slots: [(u64, u64); SLOTS],
    writes: [Option<Write>; SLOTS],
    /// Submission order of waiting writes (slot indices), oldest first.
    order: [usize; SLOTS],
    queued: usize,
    control: (u64, u64),
    control_busy: Option<u16>,
    /// Control packet to send once the control buffer is free.
    control_wanted: Option<u16>,
    rx_buffers: [(u64, u64); RX_BUFFERS],
    rx_ids: [u16; RX_BUFFERS],
    link: Link,
    retry_at: Option<u64>,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    tx_cnt: u32,
    fwd_cnt: u32,
    connects: u32,
}

fn put<T>(addr: u64, value: T) {
    unsafe { write_volatile(addr as *mut T, value) }
}

fn get<T>(addr: u64) -> T {
    unsafe { read_volatile(addr as *const T) }
}

impl Driver {
    /// Fill a packet header at `va`.
    fn header(&self, va: u64, op: u16, len: u32) {
        put(va, self.guest_cid);
        put(va + 8, HOST_CID);
        put(va + 16, LOCAL_PORT);
        put(va + 20, HOST_PORT);
        put(va + 24, len);
        put(va + 28, TYPE_STREAM);
        put(va + 30, op);
        put(va + 32, 0u32); // flags
        put(va + 36, OUR_BUF_ALLOC);
        put(va + 40, self.fwd_cnt);
    }

    fn send_control(&mut self, op: u16) {
        if self.control_busy.is_some() {
            self.control_wanted = Some(op);
            return;
        }
        let (va, pa) = self.control;
        self.header(va, op, 0);
        self.control_busy = self.tx.submit(&[Buffer { phys: pa, len: HEADER as u32, device_writes: false }]);
    }

    fn credit(&self) -> u32 {
        self.peer_buf_alloc.saturating_sub(self.tx_cnt.wrapping_sub(self.peer_fwd_cnt))
    }

    /// Move things forward: connect if down, post waiting writes the host has room for.
    fn pump(&mut self) {
        match self.link {
            Link::Down if self.retry_at.is_none_or(|t| vanir_user::uptime() >= t) => {
                self.retry_at = None;
                self.link = Link::Connecting;
                self.send_control(OP_REQUEST);
            }
            Link::Up => {
                while self.queued > 0 {
                    let slot = self.order[0];
                    let w = self.writes[slot].unwrap();
                    if w.len > self.credit() {
                        self.send_control(OP_CREDIT_REQUEST);
                        break;
                    }
                    let (va, pa) = self.slots[slot];
                    self.header(va, OP_RW, w.len);
                    let Some(id) = self.tx.submit(&[Buffer { phys: pa, len: HEADER as u32 + w.len, device_writes: false }]) else {
                        break;
                    };
                    self.tx_cnt = self.tx_cnt.wrapping_add(w.len);
                    self.writes[slot].as_mut().unwrap().posted = Some(id);
                    self.order.copy_within(1..self.queued, 0);
                    self.queued -= 1;
                }
            }
            _ => {}
        }
    }

    /// Handle completions on both queues after an interrupt.
    fn on_interrupt(&mut self) {
        while let Some((id, _)) = self.tx.take_used() {
            if self.control_busy == Some(id) {
                self.control_busy = None;
                if let Some(op) = self.control_wanted.take() {
                    self.send_control(op);
                }
            } else if let Some(slot) = self.writes.iter().position(|w| w.is_some_and(|w| w.posted == Some(id))) {
                let w = self.writes[slot].take().unwrap();
                let _ = vanir_user::reply(w.client, CODE_OK, &[]);
            }
        }
        while let Some((id, len)) = self.rx.take_used() {
            let i = self.rx_ids.iter().position(|&r| r == id).expect("unknown rx buffer");
            let (va, pa) = self.rx_buffers[i];
            if len as u64 >= HEADER {
                self.on_packet(va);
            }
            self.rx_ids[i] = self.rx.submit(&[Buffer { phys: pa, len: RX_SIZE as u32, device_writes: true }]).unwrap();
        }
    }

    fn on_packet(&mut self, va: u64) {
        let op: u16 = get(va + 30);
        if get::<u32>(va + 20) != LOCAL_PORT {
            return;
        }
        self.peer_buf_alloc = get(va + 36);
        self.peer_fwd_cnt = get(va + 40);
        match op {
            OP_RESPONSE => {
                self.link = Link::Up;
                self.connects += 1;
                println!("virtio-vsock: connected to host port {} (connection {})", HOST_PORT, self.connects);
            }
            OP_RST | OP_SHUTDOWN => {
                if self.link == Link::Up {
                    println!("virtio-vsock: host closed the connection");
                }
                self.link = Link::Down;
                self.retry_at = Some(vanir_user::uptime() + RETRY_TICKS);
                self.tx_cnt = 0;
                self.fwd_cnt = 0;
                // Writes already handed to the device are gone with the connection; the ones
                // still waiting go out on the next one.
            }
            OP_RW => {
                // We don't read host data, but must count it as consumed for the host's credit.
                self.fwd_cnt = self.fwd_cnt.wrapping_add(get::<u32>(va + 24));
                self.send_control(OP_CREDIT_UPDATE);
            }
            OP_CREDIT_REQUEST => self.send_control(OP_CREDIT_UPDATE),
            _ => {} // CREDIT_UPDATE: already recorded above
        }
    }

    fn busy(&self) -> bool {
        self.control_busy.is_some() || self.link == Link::Connecting || self.writes.iter().any(|w| w.is_some_and(|w| w.posted.is_some()))
    }
}

fn main() -> u64 {
    let mut dma = Dma::new().expect("no DMA region");
    let device = Transport::new(0).expect("no virtio-vsock granted");
    device.start(0).expect("feature negotiation failed");
    let mut rx = device.queue(RX_QUEUE, RX_BUFFERS as u16, &mut dma).expect("rx queue");
    let tx = device.queue(TX_QUEUE, SLOTS as u16 + 1, &mut dma).expect("tx queue");
    let guest_cid: u64 = get(device.device_config.expect("no device config"));
    let rx_buffers: [(u64, u64); RX_BUFFERS] = core::array::from_fn(|_| dma.alloc(RX_SIZE, 64).expect("DMA too small"));
    let rx_ids = rx_buffers.map(|(_, pa)| rx.submit(&[Buffer { phys: pa, len: RX_SIZE as u32, device_writes: true }]).unwrap());
    device.driver_ok();
    println!("virtio-vsock: guest CID {}", guest_cid);

    let mut d = Driver {
        tx,
        rx,
        guest_cid,
        slots: core::array::from_fn(|_| dma.alloc(SLOT_SIZE, 64).expect("DMA too small")),
        writes: [None; SLOTS],
        order: [0; SLOTS],
        queued: 0,
        control: dma.alloc(HEADER, 64).expect("DMA too small"),
        control_busy: None,
        control_wanted: None,
        rx_buffers,
        rx_ids,
        link: Link::Down,
        retry_at: None,
        peer_buf_alloc: 0,
        peer_fwd_cnt: 0,
        tx_cnt: 0,
        fwd_cnt: 0,
        connects: 0,
    };

    let mut msg = [0u8; 4096];
    loop {
        d.pump();
        let mut flags = if d.busy() { RECV_EXPECT_IRQ } else { 0 };
        let mut ticks = 0;
        if let Some(at) = d.retry_at {
            flags |= RECV_TIMEOUT;
            ticks = at.saturating_sub(vanir_user::uptime()).max(1);
        }
        let (sender, op, len) = vanir_user::syscall6(
            vanir_user::SYS_RECV,
            [msg.as_mut_ptr() as u64, msg.len() as u64, flags, ticks, 0, 0],
        );
        if err::is_error(sender) {
            println!("virtio-vsock: recv failed: {}", err::name(sender));
            continue;
        }
        match (sender, op) {
            (0, NOTIFY_IRQ) => d.on_interrupt(),
            (0, NOTIFY_TIMER) => {}
            (_, OP_WRITE) => {
                let Some(slot) = d.writes.iter().position(Option::is_none) else {
                    let _ = vanir_user::reply(sender, CODE_BUSY, &[]);
                    continue;
                };
                let (va, _) = d.slots[slot];
                unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), (va + HEADER) as *mut u8, len as usize) };
                d.writes[slot] = Some(Write { client: sender, len: len as u32, posted: None });
                d.order[d.queued] = slot;
                d.queued += 1;
            }
            (_, _) => {
                let _ = vanir_user::reply(sender, CODE_BAD_OP, &[]);
            }
        }
    }
}
