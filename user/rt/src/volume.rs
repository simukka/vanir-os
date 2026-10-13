//! The service's volume (RFD 3), as a handle with typed errors.

use core::sync::atomic::{AtomicBool, Ordering};
use vanir_user::block;
use vanir_user::{err, lookup, println, sleep};

pub use vanir_user::block::BLOCK_SIZE;

/// Set when a write is refused as `Fenced`; the runtime calls `Service::fenced` and clears it.
pub(crate) static FENCED: AtomicBool = AtomicBool::new(false);

/// Why a volume operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The descriptor declares no volume.
    NotDeclared,
    /// This instance isn't the volume's writer (or its epoch was overtaken).
    Fenced,
    /// Storage has no key for the volume yet.
    Locked,
    /// A block failed its integrity check.
    Integrity,
    /// A block past the volume's end, or a volume whose size differs from the descriptor's.
    OutOfRange,
    Io,
    /// Storage refused (e.g. a slot without a volume).
    NotAllowed,
    /// The storage task restarted; the handle has found the new one, so try again.
    StorageGone,
    /// Any other code.
    Other(u64),
}

impl Error {
    fn from_code(code: u64) -> Error {
        match code {
            block::CODE_FENCED => Error::Fenced,
            block::CODE_LOCKED => Error::Locked,
            block::CODE_INTEGRITY => Error::Integrity,
            block::CODE_OUT_OF_RANGE => Error::OutOfRange,
            block::CODE_IO_ERROR => Error::Io,
            block::CODE_NOT_ALLOWED => Error::NotAllowed,
            err::DEAD => Error::StorageGone,
            c => Error::Other(c),
        }
    }

    /// Its name, as storage's codes are named (`FENCED`, `LOCKED`, ...).
    pub fn name(&self) -> &'static str {
        match self {
            Error::NotDeclared => "NOT_DECLARED",
            Error::Fenced => "FENCED",
            Error::Locked => "LOCKED",
            Error::Integrity => "INTEGRITY",
            Error::OutOfRange => "OUT_OF_RANGE",
            Error::Io => "IO_ERROR",
            Error::NotAllowed => "NOT_ALLOWED",
            Error::StorageGone => "DEAD",
            Error::Other(c) => block::code_name(*c),
        }
    }
}

/// The volume the service's descriptor declares.
pub struct Volume {
    disk: u64,
    blocks: u64,
    /// The instance's name, for the line that says it became the writer.
    name: [u8; 64],
    name_len: usize,
}

impl Volume {
    /// Find storage and wait (up to 10 s) while it is locked, reading block 0 to check the
    /// volume opens.
    pub(crate) fn open(blocks: u64, name: &str) -> Result<Volume, Error> {
        if blocks == 0 {
            return Err(Error::NotDeclared);
        }
        let disk = lookup("disk").map_err(|_| Error::StorageGone)?;
        let mut v = Volume { disk, blocks, name: [0; 64], name_len: name.len().min(64) };
        v.name[..v.name_len].copy_from_slice(&name.as_bytes()[..v.name_len]);
        let mut buf = [0u8; BLOCK_SIZE];
        let mut result = v.read(0, &mut buf);
        for _ in 0..1000 {
            if result != Err(Error::Locked) {
                break;
            }
            sleep(1);
            result = v.read(0, &mut buf);
        }
        result.map(|_| v)
    }

    /// Data blocks, as the descriptor declares.
    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    /// Storage posts the writer bit before it answers a request it held (RFD 3, P1): say so
    /// before the request's result is used.
    fn check(&mut self, r: Result<(), u64>) -> Result<(), Error> {
        if vanir_user::posted() & block::NOTIFY_WRITER != 0 {
            println!("{}: now the writer of its volume", core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?"));
        }
        r.map_err(|code| {
            if code == err::DEAD
                && let Ok(d) = lookup("disk")
            {
                self.disk = d;
            }
            Error::from_code(code)
        })
    }

    pub fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        let r = block::read(self.disk, block, buf);
        self.check(r)
    }

    pub fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        let r = block::write(self.disk, block, buf);
        if r == Err(block::CODE_FENCED) {
            FENCED.store(true, Ordering::Relaxed);
        }
        self.check(r)
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        let r = block::flush(self.disk);
        self.check(r)
    }
}
