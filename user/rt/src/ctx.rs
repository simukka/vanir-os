//! What both backends share: `Ctx`, `Response`, and the checks made before a service is called,
//! so `cargo test` on the host tests the code a slot runs.

use core::fmt::{self, Write};
use vanir_abi::listen::ListenInfo;

use crate::http::{BODY_LIMIT, Request};
use crate::{Error, Service, Volume};

/// The most body a response carries.
pub(crate) const BODY: usize = 448;

/// Bytes formatted into a fixed buffer; what doesn't fit is dropped.
pub(crate) struct Buf<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
}

impl Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

/// What a service answers: a status (200 unless set) and a body written with `write!`.
pub struct Response {
    status: u16,
    body: [u8; BODY],
    len: usize,
}

impl Response {
    pub(crate) fn new() -> Response {
        Response { status: 200, body: [0; BODY], len: 0 }
    }

    pub fn set_status(&mut self, status: u16) {
        self.status = status;
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn body(&self) -> &[u8] {
        &self.body[..self.len]
    }
}

impl Write for Response {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut w = Buf { buf: &mut self.body, len: self.len };
        w.write_str(s)?;
        self.len = w.len;
        Ok(())
    }
}

/// What the runtime gives a service: who it is, its settings, its volume, the time.
pub struct Ctx {
    name: [u8; 64],
    name_len: usize,
    pub(crate) info: ListenInfo,
    config: &'static [(&'static str, u64)],
    pub(crate) exit: Option<u64>,
    /// The host backend's clock and volume.
    #[cfg(not(target_os = "none"))]
    pub(crate) host: crate::host::Backend,
}

impl Ctx {
    /// For service `S`, from what its slot (`task`, e.g. "small-0") was told at load.
    pub(crate) fn new<S: Service>(info: ListenInfo, task: &str) -> Ctx {
        let mut ctx = Ctx {
            name: [0; 64],
            name_len: 0,
            info,
            config: S::CONFIG,
            exit: None,
            #[cfg(not(target_os = "none"))]
            host: Default::default(),
        };
        let mut w = Buf { buf: &mut ctx.name, len: 0 };
        if info.is_slot() {
            let service = core::str::from_utf8(info.service()).unwrap_or("?");
            let _ = write!(w, "{} v{} on {}", service, info.version, task);
        } else {
            let _ = write!(w, "{}", task);
        }
        ctx.name_len = w.len;
        ctx
    }

    /// `<service> v<version> on <slot>` in a slot, else the task's name.
    pub fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }

    /// The signed version running.
    pub fn version(&self) -> u64 {
        self.info.version
    }

    /// Setting `key`: the descriptor's value if it has one, else the default in
    /// `Service::CONFIG` (0 for a key the service doesn't list).
    pub fn config(&self, key: &str) -> u64 {
        self.info
            .setting(key)
            .or_else(|| self.config.iter().find(|(k, _)| *k == key).map(|(_, v)| *v))
            .unwrap_or(0)
    }

    /// Open the volume the descriptor declares (`Error::NotDeclared` without one).
    pub fn volume(&mut self) -> Result<Volume, Error> {
        #[cfg(target_os = "none")]
        return Volume::open(self.info.volume_blocks, self.name());
        #[cfg(not(target_os = "none"))]
        return Volume::open(self.info.volume_blocks, &self.host);
    }

    /// Timer ticks (10 ms) since boot.
    pub fn uptime(&self) -> u64 {
        #[cfg(target_os = "none")]
        return vanir_user::uptime();
        #[cfg(not(target_os = "none"))]
        return self.host.now;
    }

    /// Exit with `code` once the current response has gone out (after `drain()`).
    pub fn exit_after_response(&mut self, code: u64) {
        self.exit = Some(code);
    }
}

/// Whether the descriptor asks only for settings service `S` has; says which it doesn't (RFD 9,
/// P5).
pub(crate) fn settings_fit<S: Service>(ctx: &Ctx) -> bool {
    let mut fit = true;
    for s in ctx.info.settings() {
        if !S::CONFIG.iter().any(|(k, _)| k.as_bytes() == s.key()) {
            crate::println!("{}: setting {} isn't one this service has", ctx.name(), core::str::from_utf8(s.key()).unwrap_or("?"));
            fit = false;
        }
    }
    fit
}

/// Answer a complete request: what the runtime refuses itself (501, 413, 405), else the
/// service's answer. Returns whether the service was called.
pub(crate) fn answer<S: Service>(svc: &mut S, ctx: &mut Ctx, r: &Request, res: &mut Response) -> bool {
    if r.chunked {
        res.set_status(501);
    } else if r.content_length.unwrap_or(0) > BODY_LIMIT {
        res.set_status(413);
    } else if r.method != b"GET" && r.method != b"HEAD" {
        res.set_status(405);
    } else {
        svc.request(ctx, r, res);
        return true;
    }
    false
}
