//! Driver for a virtio network device, with the `vanir_user::nic` IPC interface: Ethernet frames
//! in and out, one per message on the way out and in batches on the way in. It knows nothing
//! about IP; its one client is the network stack task.
//!
//! Every receive buffer stays posted. Received frames wait in the used ring until the client
//! asks for them (`OP_RECV_FRAMES`). Only when the client has emptied the ring does the driver
//! turn the receive interrupt on and post `NOTIFY_RX` at the next frame; while frames keep coming
//! the interrupt stays off and the client polls, as Linux's NAPI does. Transmit buffers are
//! reclaimed when a send needs one, so transmit interrupts stay off too.

#![no_std]
#![no_main]

use core::ptr::{copy_nonoverlapping, read_volatile, write_bytes};
use vanir_user::nic::{CODE_BAD_FRAME, CODE_BAD_OP, CODE_BUSY, CODE_OK, Info, MAX_FRAME, NOTIFY_RX, OP_INFO, OP_RECV_FRAMES, OP_SEND_FRAME};
use vanir_user::{NOTIFY_IRQ, RECV_EXPECT_IRQ, err, notify, println, recv_flags, reply};
use virtio::{Buffer, Dma, Queue, Transport};

vanir_user::entry!(main);

const RX_QUEUE: u16 = 0;
const TX_QUEUE: u16 = 1;
const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// `virtio_net_hdr` with `VIRTIO_F_VERSION_1`: flags, GSO type and sizes, checksum offsets and
/// `num_buffers`. We offload nothing, so it is all zero on the way out and ignored on the way in.
const NET_HEADER: usize = 12;
const BUFFERS: usize = 16;
/// A full frame and the header fit in one buffer.
const BUFFER_SIZE: u64 = 2048;
const MIN_FRAME: usize = 14;

struct Driver {
    rx: Queue,
    tx: Queue,
    rx_buffers: [(u64, u64); BUFFERS],
    /// Request id of each posted receive buffer.
    rx_ids: [u16; BUFFERS],
    tx_buffers: [(u64, u64); BUFFERS],
    /// Request id of each transmit buffer the device still has.
    tx_busy: [Option<u16>; BUFFERS],
    /// Who gets `NOTIFY_RX`, and whether the receive interrupt is on for it.
    client: Option<u64>,
    armed: bool,
    info: Info,
    #[cfg(feature = "crash-after-10-frames")]
    received: u32,
}

impl Driver {
    fn post_rx(&mut self, i: usize) {
        let pa = self.rx_buffers[i].1;
        self.rx_ids[i] = self.rx.submit(&[Buffer { phys: pa, len: BUFFER_SIZE as u32, device_writes: true }]).expect("rx queue full");
    }

    /// A receive interrupt: tell the client frames are waiting, then stay quiet until it has
    /// taken them all.
    fn on_interrupt(&mut self) {
        if self.armed && self.rx.peek_used().is_some() {
            self.armed = false;
            self.rx.set_interrupts(false);
            if let Some(client) = self.client {
                let _ = notify(client, NOTIFY_RX);
            }
        }
    }

    /// Fill `out` with waiting frames (u16 length, frame); returns the bytes used.
    fn take_frames(&mut self, client: u64, out: &mut [u8]) -> usize {
        self.client = Some(client);
        if self.rx.in_flight() == 0 {
            self.info.rx_ring_full += 1; // every buffer filled: the device is dropping frames
        }
        let mut n = 0;
        while let Some((id, len)) = self.rx.peek_used() {
            let frame_len = (len as usize).saturating_sub(NET_HEADER);
            if frame_len >= MIN_FRAME && n + 2 + frame_len > out.len() {
                break; // stays in the ring for the next call
            }
            self.rx.take_used();
            let i = self.rx_ids.iter().position(|&r| r == id).expect("unknown rx buffer");
            if (MIN_FRAME..=BUFFER_SIZE as usize - NET_HEADER).contains(&frame_len) {
                let src = (self.rx_buffers[i].0 + NET_HEADER as u64) as *const u8;
                out[n..n + 2].copy_from_slice(&(frame_len as u16).to_le_bytes());
                unsafe { copy_nonoverlapping(src, out[n + 2..].as_mut_ptr(), frame_len) };
                let dst = &out[n + 2..n + 8];
                if dst == [0xff; 6] {
                    self.info.rx_broadcast += 1;
                } else if dst[0] & 1 != 0 {
                    self.info.rx_multicast += 1;
                }
                self.info.rx_packets += 1;
                self.info.rx_bytes += frame_len as u64;
                n += 2 + frame_len;
            } else {
                self.info.errors += 1;
            }
            self.post_rx(i);
            #[cfg(feature = "crash-after-10-frames")]
            {
                self.received += 1;
                if self.received == 10 && vanir_user::getpid() >> 16 == 0 {
                    println!("virtio-net: crashing after 10 frames");
                    unsafe { read_volatile(0x10 as *const u8) };
                }
            }
        }
        if self.rx.peek_used().is_none() {
            // Drained: interrupt at the next frame. One may have arrived just before the
            // interrupt went back on, so look again.
            self.armed = true;
            self.rx.set_interrupts(true);
            if self.rx.peek_used().is_some() {
                self.armed = false;
                self.rx.set_interrupts(false);
                let _ = notify(client, NOTIFY_RX);
            }
        }
        n
    }

    fn send(&mut self, frame: &[u8]) -> u64 {
        if !(MIN_FRAME..=MAX_FRAME).contains(&frame.len()) {
            self.info.errors += 1;
            return CODE_BAD_FRAME;
        }
        while let Some((id, _)) = self.tx.take_used() {
            if let Some(b) = self.tx_busy.iter_mut().find(|b| **b == Some(id)) {
                *b = None;
            }
        }
        let Some(i) = self.tx_busy.iter().position(Option::is_none) else {
            self.info.errors += 1;
            return CODE_BUSY;
        };
        let (va, pa) = self.tx_buffers[i];
        unsafe {
            write_bytes(va as *mut u8, 0, NET_HEADER);
            copy_nonoverlapping(frame.as_ptr(), (va + NET_HEADER as u64) as *mut u8, frame.len());
        }
        let len = (NET_HEADER + frame.len()) as u32;
        self.tx_busy[i] = Some(self.tx.submit(&[Buffer { phys: pa, len, device_writes: false }]).expect("tx queue full"));
        self.info.tx_packets += 1;
        self.info.tx_bytes += frame.len() as u64;
        CODE_OK
    }
}

fn main() -> u64 {
    let device = match Transport::new(0) {
        Ok(d) => d,
        Err(e) => {
            println!("virtio-net: no device granted: {:?}", e);
            return 1;
        }
    };
    let mut dma = Dma::new().expect("no DMA region");
    device.start(VIRTIO_NET_F_MAC).expect("feature negotiation failed");
    let mut rx = device.queue(RX_QUEUE, BUFFERS as u16, &mut dma).expect("rx queue");
    let mut tx = device.queue(TX_QUEUE, BUFFERS as u16, &mut dma).expect("tx queue");
    let config = device.device_config.expect("no device config");
    let mac: [u8; 6] = core::array::from_fn(|i| unsafe { read_volatile((config + i as u64) as *const u8) });
    rx.set_interrupts(false);
    tx.set_interrupts(false);
    let alloc = |dma: &mut Dma| dma.alloc(BUFFER_SIZE, 64).expect("DMA too small");
    let rx_buffers: [(u64, u64); BUFFERS] = core::array::from_fn(|_| alloc(&mut dma));
    let tx_buffers: [(u64, u64); BUFFERS] = core::array::from_fn(|_| alloc(&mut dma));
    let mut d = Driver {
        rx,
        tx,
        rx_buffers,
        rx_ids: [0; BUFFERS],
        tx_buffers,
        tx_busy: [None; BUFFERS],
        client: None,
        armed: false,
        info: Info { mac, link_up: 1, ..Info::default() },
        #[cfg(feature = "crash-after-10-frames")]
        received: 0,
    };
    for i in 0..BUFFERS {
        d.post_rx(i);
    }
    device.driver_ok();
    println!(
        "virtio-net: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, {} rx and {} tx buffers",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], BUFFERS, BUFFERS
    );

    let mut msg = [0u8; 4096];
    let mut out = [0u8; 4096];
    loop {
        // Frames can arrive at any time, so there is always an interrupt to wait for.
        let m = match recv_flags(&mut msg, RECV_EXPECT_IRQ) {
            Ok(m) => m,
            Err(e) => {
                println!("virtio-net: recv failed: {}", err::name(e));
                continue;
            }
        };
        match (m.sender, m.op) {
            (0, NOTIFY_IRQ) => d.on_interrupt(),
            (0, _) => {}
            (client, OP_RECV_FRAMES) => {
                let n = d.take_frames(client, &mut out);
                let _ = reply(client, CODE_OK, &out[..n]);
            }
            (client, OP_SEND_FRAME) => {
                let code = d.send(&msg[..m.len]);
                let _ = reply(client, code, &[]);
            }
            (client, OP_INFO) => {
                let bytes = unsafe { core::slice::from_raw_parts(&d.info as *const Info as *const u8, core::mem::size_of::<Info>()) };
                let _ = reply(client, CODE_OK, bytes);
            }
            (client, _) => {
                let _ = reply(client, CODE_BAD_OP, &[]);
            }
        }
    }
}
