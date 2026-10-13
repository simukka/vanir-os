//! A stateful service on the runtime (RFD 9, P6; RFD 3): counts requests to `/count` in block 0
//! of its volume. `/` answers with the instance's name.
//!
//! **Setting `persist_ticks`** (signed in its descriptor, RFD 9, P5). 0, the default: each
//! `/count` reads the count, adds one and writes it back. Above 0: the first `/count` does that
//! (so it waits for, and proves, that this instance is the writer); the rest add one in memory,
//! and the count is written back every `persist_ticks` and before the instance drains or exits.
//! A crash loses the counts since the last write. A write refused as `FENCED` (another instance
//! is the writer) drops the cached count, so the next request goes to the volume again.
//!
//! An error answers 503 with storage's code (e.g. `FENCED`: this instance isn't the writer).
//!
//! Its tests run on the host (`cargo test -p counter --target x86_64-unknown-linux-gnu`), with
//! `vanir_rt::host`.

#![cfg_attr(target_os = "none", no_std, no_main)]

use core::fmt::Write;
use vanir_rt::{BLOCK_SIZE, Ctx, Error, Request, Response, Service, Volume, println};

/// `volume-probe`: how often to try a write.
#[cfg(feature = "volume-probe")]
const PROBE_TICKS: u64 = 10;

struct Counter {
    volume: Volume,
    persist_ticks: u64,
    /// With `persist_ticks`: the count once read from the volume, whether it changed since it
    /// was written, and when to write it next.
    cached: Option<u64>,
    dirty: bool,
    next_persist: u64,
    /// `volume-probe`: when to probe next, the last result printed, and how many probes.
    #[cfg(feature = "volume-probe")]
    probe: (u64, Option<&'static str>, u32),
}

impl Counter {
    /// Read block 0's count, add one, write it back.
    fn count_on_volume(&mut self) -> Result<u64, Error> {
        let mut buf = [0u8; BLOCK_SIZE];
        self.volume.read(0, &mut buf)?;
        let n = u64::from_le_bytes(buf[..8].try_into().unwrap()) + 1;
        buf[..8].copy_from_slice(&n.to_le_bytes());
        self.volume.write(0, &buf)?;
        Ok(n)
    }

    fn count(&mut self, now: u64) -> Result<u64, Error> {
        if self.persist_ticks == 0 {
            return self.count_on_volume();
        }
        if let Some(n) = self.cached {
            self.cached = Some(n + 1);
            self.dirty = true;
            return Ok(n + 1);
        }
        let n = self.count_on_volume()?;
        (self.cached, self.dirty, self.next_persist) = (Some(n), false, now + self.persist_ticks);
        Ok(n)
    }

    /// Write the cached count back if it changed and it's time (or `now` is None: before
    /// draining or exiting).
    fn persist(&mut self, ctx: &Ctx, now: Option<u64>) {
        let Some(n) = self.cached else { return };
        if now.is_some_and(|t| t < self.next_persist) {
            return;
        }
        self.next_persist = ctx.uptime() + self.persist_ticks;
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..8].copy_from_slice(&n.to_le_bytes());
        match self.volume.write(0, &buf) {
            Ok(()) => println!("{}: count {} written to the volume", ctx.name(), n),
            Err(e) => {
                // Not the writer any more (or storage restarted): what we counted is lost, and
                // the next request goes to the volume.
                println!("{}: writing count {} failed: {}; cache dropped", ctx.name(), n, e.name());
                self.cached = None;
            }
        }
    }

    /// `volume-probe`: write scratch block 1, and print a change in the result.
    #[cfg(feature = "volume-probe")]
    fn probe(&mut self, ctx: &Ctx) {
        let result = match self.volume.write(1, &[0x5a; BLOCK_SIZE]) {
            Ok(()) => "OK",
            Err(e) => e.name(),
        };
        if self.probe.1 != Some(result) {
            println!("{}: writes {}", ctx.name(), result);
            self.probe.1 = Some(result);
        }
        self.probe.0 = ctx.uptime() + PROBE_TICKS;
        self.probe.2 += 1;
        // First start only: a slot's id is already at generation 1 once loaded.
        #[cfg(feature = "crash-after-probes")]
        if self.probe.2 == 20 && vanir_rt::raw::getpid() >> 16 <= 1 {
            println!("{}: crashing after 20 probes", ctx.name());
            unsafe { core::ptr::read_volatile(0x10 as *const u8) };
        }
    }
}

impl Service for Counter {
    const CONFIG: &'static [(&'static str, u64)] = &[("persist_ticks", 0)];

    fn start(ctx: &mut Ctx) -> Result<Self, Error> {
        let mut volume = match ctx.volume() {
            Ok(v) => v,
            Err(e) => {
                println!("{}: cannot open its volume: {}", ctx.name(), e.name());
                return Err(e);
            }
        };
        let mut buf = [0u8; BLOCK_SIZE];
        volume.read(0, &mut buf)?;
        println!("{}: volume opened, count {}", ctx.name(), u64::from_le_bytes(buf[..8].try_into().unwrap()));
        #[allow(unused_mut)]
        let mut counter = Counter {
            volume,
            persist_ticks: ctx.config("persist_ticks"),
            cached: None,
            dirty: false,
            next_persist: 0,
            #[cfg(feature = "volume-probe")]
            probe: (0, None, 0),
        };
        #[cfg(feature = "volume-probe")]
        {
            // It can't name itself the writer: only the agent may (RFD 3, P1).
            use vanir_rt::raw::{block, getpid, lookup};
            let disk = lookup("disk").unwrap_or(0);
            let e = block::epoch(disk, 1 << 40, 0, getpid()).err().unwrap_or(block::CODE_OK);
            println!("{}: naming itself the writer: {}", ctx.name(), block::code_name(e));
            counter.probe(ctx);
        }
        Ok(counter)
    }

    fn request(&mut self, ctx: &mut Ctx, req: &Request, res: &mut Response) {
        match req.path {
            b"/" => {
                let _ = write!(res, "hello from {}\n", ctx.name());
            }
            b"/count" => match self.count(ctx.uptime()) {
                Ok(n) => {
                    let _ = write!(res, "{}\n", n);
                }
                Err(e) => {
                    res.set_status(503);
                    let _ = write!(res, "{}\n", e.name());
                }
            },
            #[cfg(feature = "exit-on-request")]
            b"/exit" => {
                let _ = write!(res, "bye\n");
                ctx.exit_after_response(0);
            }
            _ => res.set_status(404),
        }
    }

    fn tick(&mut self, ctx: &mut Ctx) -> Option<u64> {
        let now = ctx.uptime();
        let mut next: Option<u64> = None;
        if self.persist_ticks > 0 {
            self.persist(ctx, Some(now));
            // Nothing cached yet: look again in a period.
            next = Some(if self.cached.is_some() { self.next_persist.max(now + 1) } else { now + self.persist_ticks });
        }
        #[cfg(feature = "volume-probe")]
        {
            if now >= self.probe.0 {
                self.probe(ctx);
            }
            next = Some(next.map_or(self.probe.0, |n| n.min(self.probe.0)));
        }
        next.map(|t| t.saturating_sub(now).max(1))
    }

    fn drain(&mut self, ctx: &mut Ctx) {
        // The next writer reads the count once we are done: write it first.
        self.persist(ctx, None);
    }

    fn fenced(&mut self, _ctx: &mut Ctx) {
        self.cached = None;
    }
}

vanir_rt::service!(Counter, connections = 64);

#[cfg(test)]
mod tests {
    use super::Counter;
    use vanir_rt::Error;
    use vanir_rt::host::{Host, Reply};

    fn count_in(block: [u8; vanir_rt::BLOCK_SIZE]) -> u64 {
        u64::from_le_bytes(block[..8].try_into().unwrap())
    }

    fn ok(body: &str) -> Reply {
        Reply { status: 200, body: body.into() }
    }

    #[test]
    fn counts_on_the_volume() {
        let mut h = Host::<Counter>::new("counter").volume(16);
        h.start().unwrap();
        assert_eq!(h.get("/"), ok("hello from counter v1 on host\n"));
        assert_eq!(h.get("/count"), ok("1\n"));
        assert_eq!(h.get("/count"), ok("2\n"));
        assert_eq!(count_in(h.block(0)), 2);
        // A new instance carries on from the volume.
        h.restart().unwrap();
        assert_eq!(h.get("/count"), ok("3\n"));
    }

    #[test]
    fn cached_counts_are_written_on_the_timer() {
        let mut h = Host::<Counter>::new("counter").volume(16).setting("persist_ticks", 100);
        h.start().unwrap();
        for n in 1..=3 {
            assert_eq!(h.get("/count"), ok(&format!("{n}\n")));
        }
        // The first count went to the volume; the next two only to memory.
        assert_eq!((count_in(h.block(0)), h.writes()), (1, 1));
        h.advance(99);
        assert_eq!(count_in(h.block(0)), 1);
        h.advance(1);
        assert_eq!((count_in(h.block(0)), h.writes()), (3, 2));
        // Nothing new: nothing written.
        h.advance(500);
        assert_eq!(h.writes(), 2);
    }

    #[test]
    fn a_crash_loses_cached_counts_and_a_drain_keeps_them() {
        let mut h = Host::<Counter>::new("counter").volume(16).setting("persist_ticks", 100);
        h.start().unwrap();
        h.get("/count");
        h.get("/count");
        h.restart().unwrap();
        assert_eq!(h.get("/count"), ok("2\n"), "the second count was only in memory");
        h.get("/count");
        h.drain();
        assert_eq!(count_in(h.block(0)), 3);
    }

    #[test]
    fn a_refused_write_drops_the_cache() {
        let mut h = Host::<Counter>::new("counter").volume(16).setting("persist_ticks", 100);
        h.start().unwrap();
        h.get("/count");
        h.get("/count");
        h.fence(true);
        h.advance(100); // the timed write is refused
        assert!(h.service().cached.is_none());
        assert_eq!(h.get("/count"), Reply { status: 503, body: "FENCED\n".into() });
        assert_eq!(count_in(h.block(0)), 1);
        h.fence(false);
        assert_eq!(h.get("/count"), ok("2\n"));
    }

    #[test]
    fn the_runtime_answers_what_counter_doesnt() {
        let mut h = Host::<Counter>::new("counter").volume(16);
        h.start().unwrap();
        assert_eq!(h.get("/nothing").status, 404);
        assert_eq!(h.request(b"POST /count HTTP/1.1\r\nContent-Length: 0\r\n\r\n").status, 405);
        assert_eq!(h.request(b"HEAD / HTTP/1.1\r\n\r\n"), ok(""));
        assert_eq!(h.request(b"GET / HTTP/2.0\r\n\r\n").status, 505);
        assert_eq!(count_in(h.block(0)), 0, "no request counted");
    }

    #[test]
    fn refused_without_a_volume_or_with_a_setting_it_doesnt_have() {
        assert_eq!(Host::<Counter>::new("counter").start().err(), Some(Error::NotDeclared));
        let mut h = Host::<Counter>::new("counter").volume(16).setting("greeting", 1);
        assert!(h.start().is_err());
    }
}
