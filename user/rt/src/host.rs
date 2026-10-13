//! The host backend (RFD 9, open question 5): a service's unit tests, with `cargo test` on any
//! target but `x86_64-unknown-none`. `Host` calls the service as the runtime in a slot does
//! (`start`, then the first `tick`; `request` behind the same checks; `fenced` after a call
//! whose write was refused; `drain` before an exit), with no network: requests are bytes, the
//! clock moves when the test says, and the volume is blocks in memory.
//!
//! ```ignore
//! let mut h = Host::<Counter>::new("counter").volume(16).setting("persist_ticks", 100);
//! h.start().unwrap();
//! assert_eq!(h.get("/count").body, "1\n");
//! h.advance(100); // the timer's tick writes the count
//! assert_eq!(h.block(0)[0], 1);
//! ```

use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use vanir_abi::listen::{ListenInfo, SLOT, Setting};

use crate::ctx::{Ctx, Response, answer, settings_fit};
use crate::http::parse;
use crate::{BLOCK_SIZE, Error, Service};

/// The volume's blocks, and what has been done to them.
#[derive(Default)]
pub(crate) struct Disk {
    pub blocks: Vec<[u8; BLOCK_SIZE]>,
    pub reads: u64,
    pub writes: u64,
    pub flushes: u64,
    /// Writes and flushes are refused as `Fenced`.
    pub fenced: bool,
    /// One was, since the service was last told.
    pub fence_seen: bool,
}

/// What `Ctx` reads on the host instead of syscalls.
#[derive(Default)]
pub(crate) struct Backend {
    pub now: u64,
    pub disk: Rc<RefCell<Disk>>,
}

/// An answer: its status and body (empty for HEAD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

/// Service `S`, run by the test.
pub struct Host<S: Service> {
    info: ListenInfo,
    disk: Rc<RefCell<Disk>>,
    now: u64,
    run: Option<(S, Ctx)>,
    next_tick: Option<u64>,
    exit: Option<u64>,
}

impl<S: Service> Host<S> {
    /// An instance of `service` v1, in slot "host", listening on port 80, without a volume or
    /// settings.
    pub fn new(service: &str) -> Self {
        let mut info = ListenInfo::default();
        let n = service.len().min(info.service.len());
        info.service[..n].copy_from_slice(&service.as_bytes()[..n]);
        info.service_len = n as u64;
        info.flags = SLOT;
        info.count = 1;
        info.ports[0] = [80, 64, 64, 0];
        info.version = 1;
        Host { info, disk: Default::default(), now: 0, run: None, next_tick: None, exit: None }
    }

    /// The signed version it runs as.
    pub fn version(mut self, version: u64) -> Self {
        self.info.version = version;
        self
    }

    /// A volume of `blocks` zeroed blocks, as `volume = { blocks = N }` declares.
    pub fn volume(mut self, blocks: u64) -> Self {
        self.info.volume_blocks = blocks;
        self.disk.borrow_mut().blocks = vec![[0; BLOCK_SIZE]; blocks as usize];
        self
    }

    /// A setting in its descriptor, as `[config]` has it.
    pub fn setting(mut self, key: &str, value: u64) -> Self {
        let i = self.info.settings_count as usize;
        assert!(i < self.info.settings.len(), "at most {} settings", self.info.settings.len());
        assert!(!key.is_empty() && key.len() <= 16, "setting keys are 1..16 bytes");
        let mut s = Setting { key: [0; 16], value };
        s.key[..key.len()].copy_from_slice(key.as_bytes());
        self.info.settings[i] = s;
        self.info.settings_count += 1;
        self
    }

    /// Start the instance: settings it doesn't have refuse it, as in a slot (`Error::Other(0)`);
    /// else `start`, then the first `tick`.
    pub fn start(&mut self) -> Result<(), Error> {
        let mut ctx = Ctx::new::<S>(self.info, "host");
        ctx.host = Backend { now: self.now, disk: self.disk.clone() };
        if !settings_fit::<S>(&ctx) {
            return Err(Error::Other(0));
        }
        let svc = S::start(&mut ctx)?;
        self.run = Some((svc, ctx));
        self.exit = None;
        self.next_tick = Some(self.now);
        self.after_callback();
        self.advance(0);
        Ok(())
    }

    /// The instance crashes and its slot starts it again: no `drain`; what it kept in memory
    /// is gone; the volume stays.
    pub fn restart(&mut self) -> Result<(), Error> {
        self.run = None;
        self.start()
    }

    fn running(&mut self) -> &mut (S, Ctx) {
        assert!(self.exit.is_none(), "the instance has exited");
        self.run.as_mut().expect("start() the instance first")
    }

    /// `fenced()`, if a call refused a write since the service was last told.
    fn after_callback(&mut self) {
        let seen = core::mem::take(&mut self.disk.borrow_mut().fence_seen);
        if seen && let Some((svc, ctx)) = self.run.as_mut() {
            svc.fenced(ctx);
        }
    }

    /// `GET path`.
    pub fn get(&mut self, path: &str) -> Reply {
        self.request(format!("GET {path} HTTP/1.1\r\nHost: host\r\n\r\n").as_bytes())
    }

    /// A whole request, header (and body) as sent: parsed and checked as in a slot.
    pub fn request(&mut self, raw: &[u8]) -> Reply {
        let (svc, ctx) = self.running();
        let mut res = Response::new();
        let mut head = false;
        let called = match parse(raw).expect("an incomplete request") {
            Err(code) => {
                res.set_status(code);
                false
            }
            Ok(r) => {
                head = r.method == b"HEAD";
                answer(svc, ctx, &r, &mut res)
            }
        };
        let exit = ctx.exit;
        if called {
            self.after_callback();
        }
        if let Some(code) = exit {
            self.drain();
            self.exit = Some(code);
        }
        let body = if head { String::new() } else { String::from_utf8_lossy(res.body()).into_owned() };
        Reply { status: res.status(), body }
    }

    /// Move the clock on `ticks` (10 ms each), calling `tick` whenever it is due.
    pub fn advance(&mut self, ticks: u64) {
        let until = self.now + ticks;
        while let Some(t) = self.next_tick.filter(|&t| t <= until) {
            self.now = self.now.max(t);
            let now = self.now;
            let (svc, ctx) = self.running();
            ctx.host.now = now;
            self.next_tick = svc.tick(ctx).map(|d| now + d.max(1));
            self.after_callback();
        }
        self.now = until;
        if let Some((_, ctx)) = self.run.as_mut() {
            ctx.host.now = until;
        }
    }

    /// The instance is drained (or exits): `drain`.
    pub fn drain(&mut self) {
        let (svc, ctx) = self.running();
        svc.drain(ctx);
        self.after_callback();
    }

    /// From now on, writes and flushes are refused as `Fenced` (another instance is the
    /// writer), or not.
    pub fn fence(&mut self, fenced: bool) {
        self.disk.borrow_mut().fenced = fenced;
    }

    /// Block `n` of the volume.
    pub fn block(&self, n: u64) -> [u8; BLOCK_SIZE] {
        self.disk.borrow().blocks[n as usize]
    }

    /// Blocks written to the volume so far.
    pub fn writes(&self) -> u64 {
        self.disk.borrow().writes
    }

    /// Ticks since the test began.
    pub fn now(&self) -> u64 {
        self.now
    }

    /// The code it exited with (`ctx.exit_after_response`), once it has.
    pub fn exit_code(&self) -> Option<u64> {
        self.exit
    }

    /// The service itself, to look at its state (also after it exited).
    pub fn service(&mut self) -> &mut S {
        &mut self.run.as_mut().expect("start() the instance first").0
    }
}
