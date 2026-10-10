//! Driver for a virtio block device, in 4 KiB blocks, with the `vanir_user::block` IPC
//! interface. Up to `SLOTS` requests are in flight at once; each is replied when the device
//! completes it.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use vanir_user::block::{
    BLOCK_SIZE, CODE_BAD_OP, CODE_BUSY, CODE_IO_ERROR, CODE_OK, CODE_OUT_OF_RANGE, OP_FLUSH, OP_INFO, OP_READ, OP_WRITE, split,
};
use vanir_user::{NOTIFY_IRQ, RECV_EXPECT_IRQ, err, println, recv_flags, reply};
use virtio::{Buffer, Dma, Transport};

vanir_user::entry!(main);

const REQUEST_QUEUE: u16 = 0;
const SLOTS: usize = 8;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
const TYPE_IN: u32 = 0;
const TYPE_OUT: u32 = 1;
const TYPE_FLUSH: u32 = 4;
const SECTORS_PER_BLOCK: u64 = (BLOCK_SIZE / 512) as u64;

/// One request's DMA memory: 16-byte header, then the status byte, then a block of data.
#[derive(Clone, Copy)]
struct Slot {
    va: u64,
    pa: u64,
}

impl Slot {
    const HEADER: u64 = 0;
    const STATUS: u64 = 16;
    const DATA: u64 = 64;
    const SIZE: u64 = 64 + BLOCK_SIZE as u64;
}

#[derive(Clone, Copy)]
struct InFlight {
    id: u16,
    client: u64,
    reads: bool,
}

fn put<T>(addr: u64, value: T) {
    unsafe { write_volatile(addr as *mut T, value) }
}

fn get<T>(addr: u64) -> T {
    unsafe { read_volatile(addr as *const T) }
}

fn main() -> u64 {
    let mut dma = Dma::new().expect("no DMA region");
    let device = Transport::new(0).expect("no virtio block device granted");
    let features = device.start(VIRTIO_BLK_F_FLUSH).expect("feature negotiation failed");
    let mut queue = device.queue(REQUEST_QUEUE, 3 * SLOTS as u16, &mut dma).expect("request queue");
    let capacity = get::<u64>(device.device_config.expect("no device config")) / SECTORS_PER_BLOCK;
    device.driver_ok();
    let can_flush = features & VIRTIO_BLK_F_FLUSH != 0;
    println!("virtio-blk: {} blocks ({} MiB), flush {}", capacity, capacity * BLOCK_SIZE as u64 >> 20, can_flush);

    let slots: [Slot; SLOTS] = core::array::from_fn(|_| {
        let (va, pa) = dma.alloc(Slot::SIZE, 64).expect("DMA too small");
        Slot { va, pa }
    });
    let mut busy: [Option<InFlight>; SLOTS] = [None; SLOTS];
    #[cfg(feature = "crash-after-10")]
    let mut writes = 0u32;

    let mut msg = [0u8; BLOCK_SIZE];
    loop {
        let waiting = busy.iter().any(Option::is_some);
        let m = match recv_flags(&mut msg, if waiting { RECV_EXPECT_IRQ } else { 0 }) {
            Ok(m) => m,
            Err(e) => {
                println!("virtio-blk: recv failed: {}", err::name(e));
                continue;
            }
        };

        if m.sender == 0 && m.op == NOTIFY_IRQ {
            while let Some((id, _)) = queue.take_used() {
                let Some(i) = busy.iter().position(|b| b.is_some_and(|f| f.id == id)) else { continue };
                let done = busy[i].take().unwrap();
                let s = slots[i];
                let code = if get::<u8>(s.va + Slot::STATUS) == 0 { CODE_OK } else { CODE_IO_ERROR };
                let data = unsafe { core::slice::from_raw_parts((s.va + Slot::DATA) as *const u8, BLOCK_SIZE) };
                let _ = reply(done.client, code, if done.reads && code == CODE_OK { data } else { &[] });
            }
            continue;
        }

        let (code, block) = split(m.op);
        let kind = match code {
            OP_INFO => {
                let _ = reply(m.sender, CODE_OK, &capacity.to_le_bytes());
                continue;
            }
            OP_READ => TYPE_IN,
            OP_WRITE if m.len == BLOCK_SIZE => TYPE_OUT,
            OP_FLUSH if can_flush => TYPE_FLUSH,
            OP_FLUSH => {
                let _ = reply(m.sender, CODE_OK, &[]); // no write cache to flush
                continue;
            }
            _ => {
                let _ = reply(m.sender, CODE_BAD_OP, &[]);
                continue;
            }
        };
        if kind != TYPE_FLUSH && block >= capacity {
            let _ = reply(m.sender, CODE_OUT_OF_RANGE, &[]);
            continue;
        }
        let Some(i) = busy.iter().position(Option::is_none) else {
            let _ = reply(m.sender, CODE_BUSY, &[]);
            continue;
        };
        let s = slots[i];
        put(s.va + Slot::HEADER, kind);
        put(s.va + Slot::HEADER + 4, 0u32);
        put(s.va + Slot::HEADER + 8, if kind == TYPE_FLUSH { 0 } else { block * SECTORS_PER_BLOCK });
        put(s.va + Slot::STATUS, 0xffu8);
        if kind == TYPE_OUT {
            unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), (s.va + Slot::DATA) as *mut u8, BLOCK_SIZE) };
        }
        let header = Buffer { phys: s.pa + Slot::HEADER, len: 16, device_writes: false };
        let data = Buffer { phys: s.pa + Slot::DATA, len: BLOCK_SIZE as u32, device_writes: kind == TYPE_IN };
        let status = Buffer { phys: s.pa + Slot::STATUS, len: 1, device_writes: true };
        let id = if kind == TYPE_FLUSH { queue.submit(&[header, status]) } else { queue.submit(&[header, data, status]) };
        busy[i] = Some(InFlight { id: id.expect("queue full"), client: m.sender, reads: kind == TYPE_IN });

        #[cfg(feature = "crash-after-10")]
        if kind == TYPE_OUT {
            writes += 1;
            if writes == 10 && vanir_user::getpid() >> 16 == 0 {
                println!("virtio-blk: crashing with a write in flight");
                unsafe { core::ptr::read_volatile(0x10 as *const u8) };
            }
        }
    }
}
