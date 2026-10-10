//! Driver for a virtio console (port 0, no multiport): sends bytes to the host.
//!
//! IPC interface (`vanir_user::console`): `OP_WRITE` with up to 4 KiB of bytes, replied with
//! `CODE_OK` once the device has taken them, or `CODE_BUSY` if every transmit slot is in flight.
//! Requests from several clients can be in flight at once.

#![no_std]
#![no_main]

use vanir_user::console::{CODE_BAD_OP, CODE_BUSY, CODE_OK, OP_WRITE};
use vanir_user::{NOTIFY_IRQ, RECV_EXPECT_IRQ, err, println, recv_flags, reply};
use virtio::{Buffer, Dma, Transport};

vanir_user::entry!(main);

const TRANSMIT_QUEUE: u16 = 1;
const SLOTS: usize = 8;
const SLOT_SIZE: u64 = 4096;

/// A write in flight: the descriptor id the device will hand back, and who to reply to.
#[derive(Clone, Copy)]
struct InFlight {
    id: u16,
    client: u64,
}

fn main() -> u64 {
    let mut dma = Dma::new().expect("no DMA region");
    let device = Transport::new(0).expect("no virtio console granted");
    device.start(0).expect("feature negotiation failed");
    let mut tx = device.queue(TRANSMIT_QUEUE, SLOTS as u16, &mut dma).expect("transmit queue");
    device.driver_ok();
    let slot_buffers: [(u64, u64); SLOTS] = core::array::from_fn(|_| dma.alloc(SLOT_SIZE, 64).expect("DMA too small"));
    let mut slots: [Option<InFlight>; SLOTS] = [None; SLOTS];
    #[cfg(feature = "crash-after-50")]
    let mut writes = 0u32;

    let mut msg = [0u8; SLOT_SIZE as usize];
    loop {
        let busy = slots.iter().any(Option::is_some);
        let m = match recv_flags(&mut msg, if busy { RECV_EXPECT_IRQ } else { 0 }) {
            Ok(m) => m,
            Err(e) => {
                println!("virtio-console: recv failed: {}", err::name(e));
                continue;
            }
        };

        if m.sender == 0 && m.op == NOTIFY_IRQ {
            while let Some((id, _)) = tx.take_used() {
                if let Some(slot) = slots.iter_mut().find(|s| s.is_some_and(|f| f.id == id)) {
                    let done = slot.take().unwrap();
                    let _ = reply(done.client, CODE_OK, &[]); // the client may have died meanwhile
                }
            }
            continue;
        }

        if m.op != OP_WRITE {
            let _ = reply(m.sender, CODE_BAD_OP, &[]);
            continue;
        }
        let Some(free) = slots.iter().position(Option::is_none) else {
            let _ = reply(m.sender, CODE_BUSY, &[]);
            continue;
        };
        let (va, pa) = slot_buffers[free];
        unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), va as *mut u8, m.len) };
        let id = tx.submit(&[Buffer { phys: pa, len: m.len as u32, device_writes: false }]).expect("queue full");
        slots[free] = Some(InFlight { id, client: m.sender });

        #[cfg(feature = "crash-after-50")]
        {
            writes += 1;
            if writes == 50 && vanir_user::getpid() >> 16 == 0 {
                println!("virtio-console: crashing with a write in flight");
                unsafe { core::ptr::read_volatile(0x10 as *const u8) };
            }
        }
    }
}
