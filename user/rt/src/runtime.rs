//! The event loop: `user/http`'s server, with the service's code where its routes were.

use core::fmt::Write;
use core::sync::atomic::Ordering;
use vanir_user::net::{self, CODE_CLOSED, EV_ACCEPT, EV_CLOSED, EV_DRAIN, EV_READ, EV_WRITE, Event};
use vanir_user::telemetry::{self, DEFAULT_INTERVAL_TICKS, Record};
use vanir_user::{block, err, getpid, lookup, println, rdtsc, sleep, task_listen, task_name, uptime};

use crate::ctx::{Buf, Ctx, Response, answer, settings_fit};
use crate::http::{HEADER_LIMIT, HEADER_TICKS, IDLE_TICKS, parse, reason};
use crate::volume::FENCED;
use crate::{Error, Service};

/// Bytes of a response: its header and body.
const OUT: usize = 512;
/// Upper bounds of the latency buckets, in milliseconds (the last bucket is everything above).
const LATENCY_MS: [u64; 10] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000];

#[derive(Clone, Copy)]
struct Conn {
    /// 0: a free entry.
    handle: u32,
    buf: [u8; HEADER_LIMIT],
    len: usize,
    /// Body bytes still to skip (of a request we answered without reading its body).
    discard: usize,
    /// When the current request's first byte came, in ticks and TSC cycles.
    started: Option<u64>,
    started_tsc: u64,
    /// When the last response went out (or the connection opened).
    idle_since: u64,
    /// Response bytes net had no room for yet.
    out: [u8; OUT],
    out_len: usize,
    out_at: usize,
    close_after: bool,
}

impl Conn {
    const FREE: Conn = Conn {
        handle: 0,
        buf: [0; HEADER_LIMIT],
        len: 0,
        discard: 0,
        started: None,
        started_tsc: 0,
        idle_since: 0,
        out: [0; OUT],
        out_len: 0,
        out_at: 0,
        close_after: false,
    };
}

/// The runtime's state, with room for `N` connections; `service!` makes it a static.
pub struct Runtime<const N: usize> {
    net: u64,
    port: u16,
    conns: [Conn; N],
    listener: Option<u32>,
    draining: bool,
    done_sent: bool,
    requests: u64,
    /// Responses by status class: 2xx, 4xx, 5xx.
    status: [u64; 3],
    latency: [u64; LATENCY_MS.len() + 1],
    cycles_per_tick: u64,
    telemetry: Option<u64>,
    interval: u64,
    next_snapshot: u64,
    /// The volume's writer bit is worth looking for.
    has_volume: bool,
}

impl<const N: usize> Runtime<N> {
    pub const fn new() -> Self {
        Runtime {
            net: 0,
            port: 80,
            conns: [Conn::FREE; N],
            listener: None,
            draining: false,
            done_sent: false,
            requests: 0,
            status: [0; 3],
            latency: [0; LATENCY_MS.len() + 1],
            cycles_per_tick: 0,
            telemetry: None,
            interval: DEFAULT_INTERVAL_TICKS,
            next_snapshot: 0,
            has_volume: false,
        }
    }
}

impl<const N: usize> Default for Runtime<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Run service `S`: what `service!` calls. Returns the exit code.
pub fn run<S: Service, const N: usize>(rt: &mut Runtime<N>) -> u64 {
    let mut task = [0u8; 32];
    let me = task_name(getpid(), &mut task).unwrap_or("service").len();
    let mut ctx = Ctx::new::<S>(task_listen(getpid()).unwrap_or_default(), core::str::from_utf8(&task[..me]).unwrap_or("?"));
    rt.has_volume = ctx.info.volume_blocks > 0;
    if let Some(p) = ctx.info.ports[..(ctx.info.count as usize).min(8)].first() {
        rt.port = p[0];
    }
    // What the descriptor asks for must be what this build can do (RFD 9, P4 and P5).
    let mut fit = settings_fit::<S>(&ctx);
    if let Some((max, _)) = ctx.info.port(rt.port)
        && max as usize > N
    {
        println!("{}: its descriptor allows {} connections; this build has room for {}", ctx.name(), max, N);
        fit = false;
    }
    let started = if fit { S::start(&mut ctx) } else { Err(Error::Other(0)) };
    let mut svc = match started {
        Ok(s) => s,
        Err(_) => {
            // Never ready: the agent fails the deployment at its deadline, and stops us.
            loop {
                sleep(1000);
            }
        }
    };
    rt.cycles_per_tick = vanir_user::tsc_per_tick();
    rt.attach(ctx.name());

    let mut events = [Event::default(); 128];
    let mut next_tick = Some(uptime());
    loop {
        let now = uptime();
        if now >= rt.next_snapshot {
            rt.snapshot(now);
            rt.next_snapshot = now + rt.interval;
        }
        if let Some(t) = next_tick
            && now >= t
        {
            next_tick = svc.tick(&mut ctx).map(|d| uptime() + d.max(1));
            rt.after_callback(&mut svc, &mut ctx);
        }
        let mut next = rt.check_deadlines(now);
        if rt.telemetry.is_some() {
            next = Some(next.map_or(rt.next_snapshot, |n| n.min(rt.next_snapshot)));
        }
        if let Some(t) = next_tick {
            next = Some(next.map_or(t, |n| n.min(t)));
        }
        if rt.draining && !rt.done_sent && rt.conns.iter().all(|c| c.handle == 0) {
            svc.drain(&mut ctx);
            rt.after_callback(&mut svc, &mut ctx);
            rt.done_sent = true;
            println!("{}: drained, {} requests served", ctx.name(), rt.requests);
            let _ = net::done(rt.net);
        }
        let ticks = next.map_or(0, |n| n.saturating_sub(now).max(1));
        let n = match net::wait(rt.net, ticks, &mut events) {
            Ok(n) => n,
            Err(e) if e == err::DEAD => {
                println!("{}: the network stack was restarted", ctx.name());
                rt.attach(ctx.name());
                continue;
            }
            Err(e) => {
                println!("{}: wait failed: {}", ctx.name(), net::code_name(e));
                sleep(10);
                continue;
            }
        };
        rt.check_writer(ctx.name());
        let now = uptime();
        for e in &events[..n] {
            if e.flags & EV_DRAIN != 0 {
                rt.start_drain(ctx.name());
            }
            if e.flags & EV_ACCEPT != 0 && Some(e.handle) == rt.listener {
                rt.accept_all(e.handle, now);
            }
            let Some(i) = rt.slot(e.handle) else { continue };
            if e.flags & EV_WRITE != 0 && !rt.flush(i) {
                continue;
            }
            if e.flags & EV_READ != 0 {
                rt.on_readable(i, now, &mut svc, &mut ctx);
            } else if e.flags & EV_CLOSED != 0 {
                rt.close(i);
            }
        }
        if let Some(code) = ctx.exit {
            svc.drain(&mut ctx);
            rt.after_callback(&mut svc, &mut ctx);
            println!("{}: exiting after {} requests, as asked", ctx.name(), rt.requests);
            return code;
        }
    }
}

impl<const N: usize> Runtime<N> {
    /// Find `net` (again, after a restart), listen, and say we're ready.
    fn attach(&mut self, name: &str) {
        self.conns.iter_mut().for_each(|c| c.handle = 0);
        self.listener = None;
        loop {
            match lookup("net") {
                Ok(id) if id != self.net => {
                    self.net = id;
                    break;
                }
                _ => sleep(1),
            }
        }
        loop {
            match net::listen(self.net, self.port) {
                Ok(h) => {
                    self.listener = Some(h);
                    break;
                }
                Err(e) if e == err::DEAD => return self.attach(name),
                Err(e) => {
                    println!("{}: listen on port {} refused: {}", name, self.port, net::code_name(e));
                    sleep(100);
                }
            }
        }
        let _ = net::ready(self.net);
        println!("{}: serving HTTP on port {}", name, self.port);
    }

    /// After any call into the service: report a refused write (`fenced`).
    fn after_callback<S: Service>(&mut self, svc: &mut S, ctx: &mut Ctx) {
        if FENCED.swap(false, Ordering::Relaxed) {
            svc.fenced(ctx);
        }
    }

    /// Whether storage said we are the volume's writer now (RFD 3, P1), while we waited. (The
    /// volume handle looks after each of its own requests.)
    fn check_writer(&self, name: &str) {
        if self.has_volume && vanir_user::posted() & block::NOTIFY_WRITER != 0 {
            println!("{}: now the writer of its volume", name);
        }
    }

    fn slot(&self, handle: u32) -> Option<usize> {
        self.conns.iter().position(|c| c.handle != 0 && c.handle == handle)
    }

    fn close(&mut self, i: usize) {
        let c = &mut self.conns[i];
        if c.handle != 0 {
            let _ = net::close(self.net, c.handle);
            c.handle = 0;
        }
    }

    fn accept_all(&mut self, listener: u32, now: u64) {
        while let Ok(Some(a)) = net::accept(self.net, listener) {
            match self.conns.iter().position(|c| c.handle == 0) {
                Some(i) => {
                    let c = &mut self.conns[i];
                    c.handle = a.handle;
                    c.len = 0;
                    c.discard = 0;
                    c.started = None;
                    c.idle_since = now;
                    c.out_len = 0;
                    c.out_at = 0;
                    c.close_after = false;
                }
                None => {
                    let _ = net::close(self.net, a.handle); // no room: refuse
                }
            }
        }
    }

    /// Send what is waiting in the connection's out buffer. Returns false if it was closed.
    fn flush(&mut self, i: usize) -> bool {
        let c = &mut self.conns[i];
        while c.out_at < c.out_len {
            match net::send_data(self.net, c.handle, &c.out[c.out_at..c.out_len]) {
                Ok(0) => return true, // EV_WRITE will come
                Ok(n) => c.out_at += n,
                Err(_) => {
                    self.close(i);
                    return false;
                }
            }
        }
        c.out_len = 0;
        c.out_at = 0;
        if c.close_after {
            self.close(i);
            return false;
        }
        true
    }

    fn respond(&mut self, i: usize, status: u16, body: &[u8], head: bool, keep_alive: bool, now: u64) {
        // After these we can't trust where the next request starts (or it took too long).
        let unsure = matches!(status, 400 | 408 | 413 | 431 | 501 | 505);
        let keep_alive = keep_alive && !self.draining && !unsure;
        let c = &mut self.conns[i];
        let mut w = Buf { buf: &mut c.out, len: 0 };
        let _ = write!(
            w,
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: {}\r\n\r\n",
            status,
            reason(status),
            body.len(),
            if keep_alive { "keep-alive" } else { "close" }
        );
        let header = w.len;
        let n = if head { 0 } else { body.len().min(OUT - header) };
        c.out[header..header + n].copy_from_slice(&body[..n]);
        c.out_len = header + n;
        c.out_at = 0;
        c.close_after = !keep_alive;
        if c.started.is_some() {
            let us = (rdtsc() - c.started_tsc) * 10_000 / self.cycles_per_tick.max(1);
            let bucket = LATENCY_MS.iter().position(|&ms| us <= ms * 1000).unwrap_or(LATENCY_MS.len());
            self.latency[bucket] += 1;
        }
        c.started = None;
        c.idle_since = now;
        self.requests += 1;
        match status {
            200..=299 => self.status[0] += 1,
            400..=499 => self.status[1] += 1,
            _ => self.status[2] += 1,
        }
    }

    /// Read what has arrived and answer every complete request.
    fn on_readable<S: Service>(&mut self, i: usize, now: u64, svc: &mut S, ctx: &mut Ctx) {
        loop {
            let c = &mut self.conns[i];
            if c.out_len != 0 {
                return; // finish sending the last response first
            }
            if c.len < HEADER_LIMIT {
                match net::recv(self.net, c.handle, &mut c.buf[c.len..]) {
                    Ok(n) => c.len += n,
                    Err(CODE_CLOSED) | Err(_) => {
                        self.close(i);
                        return;
                    }
                }
            }
            if c.discard > 0 {
                let n = c.discard.min(c.len);
                c.buf.copy_within(n..c.len, 0);
                c.len -= n;
                c.discard -= n;
                if c.discard > 0 {
                    return; // more body to throw away when it comes
                }
            }
            if c.len == 0 {
                return;
            }
            if c.started.is_none() {
                c.started = Some(now);
                c.started_tsc = rdtsc();
            }
            let mut res = Response::new();
            let (body_skip, keep_alive, head): (usize, bool, bool);
            let mut called = false;
            match parse(&c.buf[..c.len]) {
                None if c.len == HEADER_LIMIT => {
                    res.set_status(431);
                    (body_skip, keep_alive, head) = (c.len, false, false);
                }
                None => return, // wait for the rest of the header
                Some(Err(code)) => {
                    res.set_status(code);
                    (body_skip, keep_alive, head) = (c.len, false, false);
                }
                Some(Ok(r)) => {
                    called = answer(svc, ctx, &r, &mut res);
                    let length = r.content_length.unwrap_or(0);
                    (body_skip, keep_alive, head) = (r.header_len + length, r.keep_alive && res.status() != 413, r.method == b"HEAD");
                }
            }
            if called {
                self.after_callback(svc, ctx);
            }
            let c = &mut self.conns[i];
            let skip = body_skip.min(c.len);
            c.buf.copy_within(skip..c.len, 0);
            c.len -= skip;
            c.discard = body_skip - skip;
            self.respond(i, res.status(), res.body(), head, keep_alive, now);
            if !self.flush(i) || ctx.exit.is_some() {
                return;
            }
        }
    }

    /// Close connections past their deadlines; returns the next deadline.
    fn check_deadlines(&mut self, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        for i in 0..N {
            let c = &self.conns[i];
            if c.handle == 0 {
                continue;
            }
            let (started, out_len) = (c.started, c.out_len);
            let deadline = match c.started {
                Some(t) => t + HEADER_TICKS,
                None => c.idle_since + IDLE_TICKS,
            };
            if now >= deadline {
                if started.is_some() && out_len == 0 {
                    self.respond(i, 408, b"", false, false, now);
                    self.flush(i);
                }
                self.close(i);
            } else {
                next = Some(next.map_or(deadline, |n| n.min(deadline)));
            }
        }
        next
    }

    /// Send our counters to telemetry, if there is one we may talk to.
    fn snapshot(&mut self, now: u64) {
        if self.telemetry.is_none() {
            self.telemetry = lookup("telemetry").ok();
        }
        let Some(t) = self.telemetry else { return };
        let mut r = Record::new("http");
        r.num("t", now)
            .num("requests", self.requests)
            .num("status_2xx", self.status[0])
            .num("status_4xx", self.status[1])
            .num("status_5xx", self.status[2]);
        let mut key = [0u8; 24];
        for (i, &n) in self.latency.iter().enumerate() {
            let mut w = Buf { buf: &mut key, len: 0 };
            let _ = match LATENCY_MS.get(i) {
                Some(ms) => write!(w, "latency_le_{}ms", ms),
                None => write!(w, "latency_over_{}ms", LATENCY_MS[LATENCY_MS.len() - 1]),
            };
            let len = w.len;
            r.num(core::str::from_utf8(&key[..len]).unwrap(), n);
        }
        match telemetry::counters(t, &r) {
            Ok(interval) => self.interval = interval,
            Err(_) => self.telemetry = None,
        }
    }

    fn start_drain(&mut self, name: &str) {
        println!("{}: draining", name);
        self.draining = true;
        if let Some(l) = self.listener.take() {
            let _ = net::close(self.net, l);
        }
    }
}
