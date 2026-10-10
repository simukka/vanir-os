//! Driver for a virtio console (port 0, no multiport): sends bytes to the host.

#![no_std]
#![no_main]

use vanir_user::{NOTIFY_IRQ, RECV_EXPECT_IRQ, println, recv_flags};
use virtio::{Buffer, Dma, Transport};

vanir_user::entry!(main);

const TRANSMIT_QUEUE: u16 = 1;

fn main() -> u64 {
    let mut dma = Dma::new().expect("no DMA region");
    let device = Transport::new(0).expect("no virtio console granted");
    device.start(0).expect("feature negotiation failed");
    let mut tx = device.queue(TRANSMIT_QUEUE, 16, &mut dma).expect("transmit queue");
    device.driver_ok();

    let text = b"hello host, from the virtio-console driver\n";
    let (va, pa) = dma.alloc(text.len() as u64, 1).unwrap();
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), va as *mut u8, text.len()) };
    let id = tx.submit(&[Buffer { phys: pa, len: text.len() as u32, device_writes: false }]).unwrap();

    let mut buf = [0u8; 16];
    loop {
        let m = recv_flags(&mut buf, RECV_EXPECT_IRQ).expect("recv");
        if m.sender == 0 && m.op == NOTIFY_IRQ {
            if let Some((done, _)) = tx.take_used() {
                println!("virtio-console: transmit {} done, signalled by interrupt (bits {:#x})", done == id, m.len);
                return 0;
            }
        }
    }
}
