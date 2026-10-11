//! smoltcp's view of the NIC: a `Device` whose frames come from, and go to, the NIC driver task
//! over IPC (`vanir_user::nic`).
//!
//! Received frames arrive in batches (`fetch`); `Interface::poll` then takes them one by one. Each frame smoltcp sends is
//! one `OP_SEND_FRAME` message.

use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use vanir_user::nic::{self, CODE_BUSY, CODE_OK, MAX_FRAME, OP_RECV_FRAMES, OP_SEND_FRAME};
use vanir_user::{err, send, yield_now};

/// Give up on a frame if the driver is still busy after this many tries.
const SEND_TRIES: u32 = 64;

pub struct Nic {
    pub rx: Batch,
    pub tx: Sender,
}

/// Frames received from the driver, as it sends them: u16 length, then the frame.
pub struct Batch {
    buf: [u8; 4096],
    len: usize,
    at: usize,
}

pub struct Sender {
    pub driver: u64,
    buf: [u8; MAX_FRAME],
    /// Frames we could not hand to the driver (busy, or gone).
    pub dropped: u64,
    /// The driver died; find it again.
    pub dead: bool,
}

impl Nic {
    pub fn new(driver: u64) -> Nic {
        Nic { rx: Batch { buf: [0; 4096], len: 0, at: 0 }, tx: Sender { driver, buf: [0; MAX_FRAME], dropped: 0, dead: false } }
    }

    pub fn driver(&self) -> u64 {
        self.tx.driver
    }

    /// Talk to a (restarted) driver from now on.
    pub fn set_driver(&mut self, driver: u64) {
        self.tx.driver = driver;
        self.tx.dead = false;
    }

    /// Take the frames the driver has (into the batch, replacing what smoltcp already took).
    /// Returns how many bytes came; 0 means the driver will post `NOTIFY_RX` for the next.
    pub fn fetch(&mut self) -> Result<usize, u64> {
        self.rx.len = 0;
        self.rx.at = 0;
        match send(self.tx.driver, OP_RECV_FRAMES, &[], &mut self.rx.buf) {
            Ok((CODE_OK, n)) => {
                self.rx.len = n;
                Ok(n)
            }
            Ok((code, _)) => Err(code),
            Err(e) => {
                if e == err::DEAD {
                    self.tx.dead = true;
                }
                Err(e)
            }
        }
    }
}

impl Batch {
    /// The next frame's place in `buf`.
    fn next(&mut self) -> Option<core::ops::Range<usize>> {
        if self.at + 2 > self.len {
            return None;
        }
        let n = u16::from_le_bytes([self.buf[self.at], self.buf[self.at + 1]]) as usize;
        let start = self.at + 2;
        self.at = (start + n).min(self.len);
        Some(start..self.at)
    }
}

impl Sender {
    fn send(&mut self, len: usize) {
        if self.dead {
            self.dropped += 1;
            return;
        }
        for _ in 0..SEND_TRIES {
            match send(self.driver, OP_SEND_FRAME, &self.buf[..len], &mut []) {
                Ok((CODE_OK, _)) => return,
                Ok((CODE_BUSY, _)) => yield_now(),
                Ok(_) => break,
                Err(e) => {
                    self.dead = e == err::DEAD;
                    break;
                }
            }
        }
        self.dropped += 1;
    }
}

pub struct Rx<'a>(&'a [u8]);
pub struct Tx<'a>(&'a mut Sender);

impl phy::Device for Nic {
    type RxToken<'a> = Rx<'a>;
    type TxToken<'a> = Tx<'a>;

    fn receive(&mut self, _: Instant) -> Option<(Rx<'_>, Tx<'_>)> {
        let frame = self.rx.next()?;
        Some((Rx(&self.rx.buf[frame]), Tx(&mut self.tx)))
    }

    fn transmit(&mut self, _: Instant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = nic::MAX_FRAME;
        caps
    }
}

impl phy::RxToken for Rx<'_> {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(self.0)
    }
}

impl phy::TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let len = len.min(MAX_FRAME);
        let r = f(&mut self.0.buf[..len]);
        self.0.send(len);
        r
    }
}
