//! The service's volume (RFD 3), as a handle with typed errors: storage's, in a slot; blocks in
//! memory, on the host.

#[cfg(target_os = "none")]
use vanir_abi::err;
use vanir_abi::proto::block;

pub use vanir_abi::proto::block::BLOCK_SIZE;

/// Set when a write is refused as `Fenced`; the runtime calls `Service::fenced` and clears it.
#[cfg(target_os = "none")]
pub(crate) static FENCED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

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
    #[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
pub struct Volume {
    disk: u64,
    blocks: u64,
    /// The instance's name, for the line that says it became the writer.
    name: [u8; 64],
    name_len: usize,
}

#[cfg(target_os = "none")]
impl Volume {
    /// Find storage and wait (up to 10 s) while it is locked, reading block 0 to check the
    /// volume opens.
    pub(crate) fn open(blocks: u64, name: &str) -> Result<Volume, Error> {
        if blocks == 0 {
            return Err(Error::NotDeclared);
        }
        use vanir_user::{lookup, sleep};
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
            vanir_user::println!("{}: now the writer of its volume", core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?"));
        }
        r.map_err(|code| {
            if code == err::DEAD
                && let Ok(d) = vanir_user::lookup("disk")
            {
                self.disk = d;
            }
            Error::from_code(code)
        })
    }

    pub fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        let r = vanir_user::block::read(self.disk, block, buf);
        self.check(r)
    }

    pub fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        let r = vanir_user::block::write(self.disk, block, buf);
        if r == Err(block::CODE_FENCED) {
            FENCED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        self.check(r)
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        let r = vanir_user::block::flush(self.disk);
        if r == Err(block::CODE_FENCED) {
            FENCED.store(true, core::sync::atomic::Ordering::Relaxed);
        }
        self.check(r)
    }
}

/// The volume the service's descriptor declares: on the host, blocks in memory that the test
/// can read, and fence (`host::Host`).
#[cfg(not(target_os = "none"))]
pub struct Volume {
    disk: std::rc::Rc<std::cell::RefCell<crate::host::Disk>>,
}

#[cfg(not(target_os = "none"))]
impl Volume {
    pub(crate) fn open(blocks: u64, host: &crate::host::Backend) -> Result<Volume, Error> {
        if blocks == 0 {
            return Err(Error::NotDeclared);
        }
        Ok(Volume { disk: host.disk.clone() })
    }

    /// Data blocks, as the descriptor declares.
    pub fn blocks(&self) -> u64 {
        self.disk.borrow().blocks.len() as u64
    }

    pub fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        let mut d = self.disk.borrow_mut();
        let b = d.blocks.get(block as usize).ok_or(Error::OutOfRange)?;
        buf.copy_from_slice(&b[..]);
        d.reads += 1;
        Ok(())
    }

    pub fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        let mut d = self.disk.borrow_mut();
        if d.fenced {
            d.fence_seen = true;
            return Err(Error::Fenced);
        }
        let b = d.blocks.get_mut(block as usize).ok_or(Error::OutOfRange)?;
        b.copy_from_slice(buf);
        d.writes += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        let mut d = self.disk.borrow_mut();
        if d.fenced {
            d.fence_seen = true;
            return Err(Error::Fenced);
        }
        d.flushes += 1;
        Ok(())
    }
}
