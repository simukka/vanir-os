//! The host backend calls a service as the runtime does: `start`, then the first `tick`; ticks
//! when due; `fenced` after a call whose write was refused; `drain` before an exit; the checks
//! before `request`; settings from the descriptor over the defaults. (On the host only.)

#![cfg(not(target_os = "none"))]

use std::fmt::Write;
use vanir_rt::host::Host;
use vanir_rt::{BLOCK_SIZE, Ctx, Error, Request, Response, Service, Volume};

/// Records what it was called with.
struct Probe {
    volume: Option<Volume>,
    ticks: Vec<u64>,
    fenced: u32,
    drained: u32,
}

impl Service for Probe {
    const CONFIG: &'static [(&'static str, u64)] = &[("period", 50), ("other", 7)];

    fn start(ctx: &mut Ctx) -> Result<Self, Error> {
        let volume = match ctx.volume() {
            Ok(v) => Some(v),
            Err(Error::NotDeclared) => None,
            Err(e) => return Err(e),
        };
        Ok(Probe { volume, ticks: vec![], fenced: 0, drained: 0 })
    }

    fn request(&mut self, ctx: &mut Ctx, req: &Request, res: &mut Response) {
        match req.path {
            b"/config" => {
                let _ = write!(res, "{} {} {}", ctx.config("period"), ctx.config("other"), ctx.config("missing"));
            }
            b"/write" => {
                let r = self.volume.as_mut().unwrap().write(0, &[1; BLOCK_SIZE]);
                let _ = write!(res, "{}", r.map_or_else(|e| e.name(), |_| "OK"));
            }
            b"/far" => {
                let r = self.volume.as_mut().unwrap().read(1000, &mut [0; BLOCK_SIZE]);
                let _ = write!(res, "{}", r.map_or_else(|e| e.name(), |_| "OK"));
            }
            b"/exit" => ctx.exit_after_response(3),
            b"/name" => {
                let _ = write!(res, "{}", ctx.name());
            }
            _ => res.set_status(404),
        }
    }

    fn tick(&mut self, ctx: &mut Ctx) -> Option<u64> {
        self.ticks.push(ctx.uptime());
        Some(ctx.config("period"))
    }

    fn drain(&mut self, _ctx: &mut Ctx) {
        self.drained += 1;
    }

    fn fenced(&mut self, _ctx: &mut Ctx) {
        self.fenced += 1;
    }
}

#[test]
fn ticks_come_when_due() {
    let mut h = Host::<Probe>::new("probe").setting("period", 30);
    h.start().unwrap();
    assert_eq!(h.service().ticks, [0], "the first tick comes right after start");
    h.advance(29);
    assert_eq!(h.service().ticks, [0]);
    h.advance(1);
    h.advance(65);
    assert_eq!(h.service().ticks, [0, 30, 60, 90]);
    assert_eq!(h.now(), 95);
}

#[test]
fn settings_from_the_descriptor_over_the_defaults() {
    let mut h = Host::<Probe>::new("probe").setting("other", 9);
    h.start().unwrap();
    assert_eq!(h.get("/config").body, "50 9 0");
    assert_eq!(h.get("/name").body, "probe v1 on host");
    let mut h = Host::<Probe>::new("probe").version(4);
    h.start().unwrap();
    assert_eq!(h.get("/name").body, "probe v4 on host");
    assert!(Host::<Probe>::new("probe").setting("unknown", 1).start().is_err());
}

#[test]
fn a_refused_write_calls_fenced_once() {
    let mut h = Host::<Probe>::new("probe").volume(4);
    h.start().unwrap();
    assert_eq!(h.get("/write").body, "OK");
    assert_eq!((h.service().fenced, h.writes()), (0, 1));
    h.fence(true);
    assert_eq!(h.get("/write").body, "FENCED");
    assert_eq!(h.service().fenced, 1);
    assert_eq!(h.get("/far").body, "OUT_OF_RANGE");
    assert_eq!(h.service().fenced, 1, "a read isn't fenced");
    h.fence(false);
    assert_eq!(h.get("/write").body, "OK");
    assert_eq!(h.service().fenced, 1);
}

#[test]
fn an_exit_drains_first() {
    let mut h = Host::<Probe>::new("probe");
    h.start().unwrap();
    assert_eq!(h.get("/exit").status, 200);
    assert_eq!(h.exit_code(), Some(3));
    assert_eq!(h.service().drained, 1);
}

#[test]
fn the_runtime_refuses_before_the_service_sees_it() {
    let mut h = Host::<Probe>::new("probe");
    h.start().unwrap();
    assert_eq!(h.request(b"PUT /x HTTP/1.1\r\n\r\n").status, 405);
    assert_eq!(h.request(b"GET /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").status, 501);
    assert_eq!(h.request(b"GET /x HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").status, 413);
    assert_eq!(h.request(b"nonsense\r\n\r\n").status, 400);
    assert_eq!(h.get("/x").status, 404);
}
