//! A small HTTP/1.1 server on the network stack task (`vanir_user::net`): GET and HEAD,
//! keep-alive, fixed buffers, one event loop.
//!
//! `/` answers with the task's name (so tests can tell instances apart) and `/count` with the
//! number of requests served. Limits: a request's header must fit in `HEADER_LIMIT` bytes (else
//! 431) and arrive within `HEADER_TICKS` of its first byte (else 408); bodies are refused above
//! `BODY_LIMIT` (413).
//!
//! Every snapshot interval we send telemetry our request counters by status class and a
//! latency histogram (from a request's first byte to its response, in fixed buckets).
//!
//! **With a volume** (a slot image whose descriptor declares one, RFD 3), `/count` counts in
//! block 0 of the volume instead: it reads the count, adds one and writes it back, and answers
//! 503 with storage's code if any of that fails (e.g. FENCED: this instance isn't the writer).
//! We read block 0 before saying we're ready, and never say so if that fails. With
//! `volume-probe` (tests), we also write scratch block 1 once before saying we're ready and
//! every 100 ms after, and print each change in the result, so tests see fencing without client
//! traffic. With `count-cached`, `/count` counts in memory instead: the first request reads
//! and writes block 0 as above (so it waits for, and proves, that we are the writer), the rest
//! only add one, and the count is written back every `PERSIST_TICKS` and before we drain or
//! exit. A crash loses the counts since the last write, and a write that fails (FENCED: another
//! instance is the writer now) throws the cached count away, so the next request goes to the
//! volume again. It also checks, once, that we can't name a writer ourselves (`OP_EPOCH`), and in a
//! slot without a volume that the storage task refuses us. If the storage task restarts, we
//! find it again. When we become the volume's writer, the storage task posts us a bit
//! (`block::NOTIFY_WRITER`), and we print that we have it.
//!
//! When `net` tells us to drain, we stop accepting and answer each connection's next request
//! with `Connection: close`, then say `OP_DONE` once none are left. Idle connections are left
//! to their clients (closing one as its client sends a request would fail that request), or to
//! the drain's deadline.

#![no_std]
#![no_main]

use core::fmt::Write;
use vanir_user::net::{self, CODE_CLOSED, EV_ACCEPT, EV_CLOSED, EV_DRAIN, EV_READ, EV_WRITE, Event};
use vanir_user::telemetry::{self, DEFAULT_INTERVAL_TICKS, Record};
use vanir_user::block::{self, BLOCK_SIZE, CODE_LOCKED};
use vanir_user::{err, getpid, lookup, println, rdtsc, sleep, task_listen, task_name, uptime};

vanir_user::entry!(main);

const PORT: u16 = 80;
const CONNECTIONS: usize = 80;
const HEADER_LIMIT: usize = 4096;
const BODY_LIMIT: usize = 16 * 1024;
/// A request's header must be complete this many ticks after its first byte.
const HEADER_TICKS: u64 = 500;
/// A keep-alive connection idle this long between requests is closed.
const IDLE_TICKS: u64 = 1500;
const OUT: usize = 512;
/// `volume-probe`: how often to try a write.
#[cfg(feature = "volume-probe")]
const PROBE_TICKS: u64 = 10;
/// `count-cached`: how often the cached count is written to the volume.
#[cfg(feature = "count-cached")]
const PERSIST_TICKS: u64 = 1000;
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

struct Server {
    net: u64,
    name: [u8; 32],
    name_len: usize,
    conns: [Conn; CONNECTIONS],
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
    /// The storage task, if our descriptor declares a volume.
    disk: Option<u64>,
    /// The volume couldn't be opened: never say we're ready.
    volume_failed: bool,
    /// `volume-probe`: when to probe next, and the last result printed.
    #[cfg(feature = "volume-probe")]
    probe: (u64, Option<u64>),
    #[cfg(feature = "crash-after-probes")]
    probes: u32,
    #[cfg(feature = "exit-on-request")]
    exit: bool,
    /// `count-cached`: the count, once read from the volume; whether it has changed since it was
    /// written; when to write it next.
    #[cfg(feature = "count-cached")]
    cached: (Option<u64>, bool, u64),
}

/// Bytes formatted into a fixed buffer.
struct Buf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for Buf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let n = b.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&b[..n]);
        self.len += n;
        Ok(())
    }
}

/// Print that instance `name` became its volume's writer, if the storage task's bit is posted.
fn writer_bit(name: &[u8]) {
    if vanir_user::posted() & block::NOTIFY_WRITER != 0 {
        println!("{}: now the writer of its volume", core::str::from_utf8(name).unwrap_or("?"));
    }
}

/// `/count` with a volume: read block 0's count, add one, write it back.
fn count_on_disk(disk: u64) -> Result<u64, u64> {
    let mut buf = [0u8; BLOCK_SIZE];
    block::read(disk, 0, &mut buf)?;
    let n = u64::from_le_bytes(buf[..8].try_into().unwrap()) + 1;
    buf[..8].copy_from_slice(&n.to_le_bytes());
    block::write(disk, 0, &buf)?;
    Ok(n)
}

/// `/count` with `count-cached`: in memory, once the volume has been read (and written, which
/// only the writer may do).
#[cfg(feature = "count-cached")]
fn count_cached(disk: u64, cached: &mut (Option<u64>, bool, u64)) -> Result<u64, u64> {
    if let (Some(n), _, at) = *cached {
        *cached = (Some(n + 1), true, at);
        return Ok(n + 1);
    }
    let n = count_on_disk(disk)?;
    *cached = (Some(n), false, uptime() + PERSIST_TICKS);
    Ok(n)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn parse_number(s: &[u8]) -> Option<usize> {
    if s.is_empty() || s.len() > 18 {
        return None;
    }
    s.iter().try_fold(0usize, |n, &c| c.is_ascii_digit().then(|| n * 10 + (c - b'0') as usize))
}

/// What a request asks for, once its header is complete.
struct Request<'a> {
    method: &'a [u8],
    path: &'a [u8],
    keep_alive: bool,
    content_length: Option<usize>,
    chunked: bool,
    /// Bytes of header, including the blank line.
    header_len: usize,
}

fn parse(buf: &[u8]) -> Option<Result<Request<'_>, u16>> {
    let end = find(buf, b"\r\n\r\n")? + 4;
    let mut lines = buf[..end - 4].split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = lines.next().unwrap_or(&[]);
    let mut parts = line.split(|&b| b == b' ').filter(|p| !p.is_empty());
    let (Some(method), Some(path), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Some(Err(400));
    };
    let mut keep_alive = version == b"HTTP/1.1";
    if !keep_alive && version != b"HTTP/1.0" {
        return Some(Err(505));
    }
    let (mut content_length, mut chunked) = (None, false);
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else { return Some(Err(400)) };
        let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
        if eq_ignore_case(name, b"connection") {
            if eq_ignore_case(value, b"close") {
                keep_alive = false;
            } else if eq_ignore_case(value, b"keep-alive") {
                keep_alive = true;
            }
        } else if eq_ignore_case(name, b"content-length") {
            match parse_number(value) {
                Some(n) => content_length = Some(n),
                None => return Some(Err(400)),
            }
        } else if eq_ignore_case(name, b"transfer-encoding") {
            chunked = true;
        }
    }
    Some(Ok(Request { method, path, keep_alive, content_length, chunked, header_len: end }))
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

impl Server {
    fn name(&self) -> &str {
        core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?")
    }

    /// Find `net` (again, after a restart), listen, and say we're ready.
    fn attach(&mut self) {
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
        #[cfg(feature = "try-mgmt-net")]
        match lookup("mgmt-net").map(|mgmt| net::listen(mgmt, PORT)) {
            Ok(Err(e)) => println!("{}: talking to mgmt-net: {}", self.name(), net::code_name(e)),
            Ok(Ok(_)) => println!("{}: talking to mgmt-net: ALLOWED", self.name()),
            Err(e) => println!("{}: no mgmt-net: {}", self.name(), err::name(e)),
        }
        #[cfg(feature = "listen-81")]
        match net::listen(self.net, 81) {
            Ok(_) => println!("{}: listening on port 81", self.name()),
            Err(e) => println!("{}: listen on port 81 refused: {}", self.name(), net::code_name(e)),
        }
        loop {
            match net::listen(self.net, PORT) {
                Ok(h) => {
                    self.listener = Some(h);
                    break;
                }
                Err(e) if e == err::DEAD => return self.attach(),
                Err(e) => {
                    println!("{}: listen on port {} refused: {}", self.name(), PORT, net::code_name(e));
                    sleep(100);
                }
            }
        }
        // Test only: version 2 and later never say they are ready (a deployment that fails).
        let never = cfg!(feature = "never-ready-v2") && task_listen(getpid()).is_ok_and(|i| i.version >= 2);
        if !never && !self.volume_failed {
            let _ = net::ready(self.net);
        }
        println!("{}: serving HTTP on port {}", self.name(), PORT);
    }

    /// Read block 0 of the volume, waiting while storage is locked: the volume is usable.
    fn open_volume(&mut self) {
        let Some(disk) = self.disk else { return };
        let mut buf = [0u8; BLOCK_SIZE];
        let mut result = block::read(disk, 0, &mut buf);
        for _ in 0..1000 {
            if result != Err(CODE_LOCKED) {
                break;
            }
            sleep(1);
            result = block::read(disk, 0, &mut buf);
        }
        match result {
            Ok(()) => println!("{}: volume opened, count {}", self.name(), u64::from_le_bytes(buf[..8].try_into().unwrap())),
            Err(e) => {
                println!("{}: cannot open its volume: {}", self.name(), block::code_name(e));
                self.volume_failed = true;
            }
        }
        #[cfg(feature = "volume-probe")]
        if !self.volume_failed {
            let e = block::epoch(disk, 1 << 40, 0, getpid()).err().unwrap_or(block::CODE_OK);
            println!("{}: naming itself the writer: {}", self.name(), block::code_name(e));
            self.probe(0);
        }
    }

    /// The storage task died: find the new one.
    #[cfg(feature = "volume-probe")]
    fn find_disk_again(&mut self) {
        if let Ok(d) = lookup("disk") {
            self.disk = Some(d);
        }
    }

    /// Whether the storage task said we are its volume's writer now (RFD 3, P1): it posts the bit
    /// before answering a request it held, so we look after each request too. A count we cache
    /// (`count-cached`) is only ever read once we are the writer, so there is nothing to throw
    /// away; the line is for the tests.
    fn check_writer(&mut self) {
        if self.disk.is_some() {
            writer_bit(&self.name[..self.name_len]);
        }
    }

    /// `volume-probe`: write scratch block 1 if it's time, and print a change in the result.
    /// Returns when to probe next.
    #[cfg(feature = "volume-probe")]
    fn probe(&mut self, now: u64) -> Option<u64> {
        let disk = self.disk?;
        if self.volume_failed {
            return None;
        }
        if now >= self.probe.0 {
            let code = block::write(disk, 1, &[0x5a; BLOCK_SIZE]).err().unwrap_or(block::CODE_OK);
            self.check_writer();
            if self.probe.1 != Some(code) {
                println!("{}: writes {}", self.name(), block::code_name(code));
                self.probe.1 = Some(code);
            }
            if code == err::DEAD {
                self.find_disk_again();
            }
            self.probe.0 = now + PROBE_TICKS;
            #[cfg(feature = "crash-after-probes")]
            {
                self.probes += 1;
                // First start only: a slot's id is already at generation 1 once loaded.
                if self.probes == 20 && getpid() >> 16 <= 1 {
                    println!("{}: crashing after 20 probes", self.name());
                    unsafe { core::ptr::read_volatile(0x10 as *const u8) };
                }
            }
        }
        Some(self.probe.0)
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
        #[cfg(feature = "crash-after-50-requests")]
        if self.requests == 50 && getpid() >> 16 == 0 {
            println!("{}: crashing after 50 requests", self.name());
            unsafe { core::ptr::read_volatile(0x10 as *const u8) };
        }
    }

    /// Read what has arrived and answer every complete request.
    fn on_readable(&mut self, i: usize, now: u64) {
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
            let (status, body_skip, keep_alive, head): (u16, usize, bool, bool);
            let mut body = [0u8; 64];
            let mut body_len = 0;
            match parse(&c.buf[..c.len]) {
                None if c.len == HEADER_LIMIT => {
                    (status, body_skip, keep_alive, head) = (431, c.len, false, false);
                }
                None => return, // wait for the rest of the header
                Some(Err(code)) => (status, body_skip, keep_alive, head) = (code, c.len, false, false),
                Some(Ok(r)) => {
                    let header_len = r.header_len;
                    let length = r.content_length.unwrap_or(0);
                    let is_get = r.method == b"GET";
                    let is_head = r.method == b"HEAD";
                    let mut w = Buf { buf: &mut body, len: 0 };
                    let code = if r.chunked {
                        501
                    } else if length > BODY_LIMIT {
                        413
                    } else if !is_get && !is_head {
                        405
                    } else if r.path == b"/" {
                        let _ = write!(w, "hello from {}\n", core::str::from_utf8(&self.name[..self.name_len]).unwrap_or("?"));
                        200
                    } else if let (b"/count", Some(disk)) = (r.path, self.disk) {
                        #[cfg(feature = "count-cached")]
                        let counted = count_cached(disk, &mut self.cached);
                        #[cfg(not(feature = "count-cached"))]
                        let counted = count_on_disk(disk);
                        writer_bit(&self.name[..self.name_len]);
                        match counted {
                            Ok(n) => {
                                let _ = write!(w, "{}\n", n);
                                200
                            }
                            Err(e) if e == err::DEAD => {
                                if let Ok(d) = lookup("disk") {
                                    self.disk = Some(d);
                                }
                                let _ = write!(w, "{}\n", block::code_name(e));
                                503
                            }
                            Err(e) => {
                                let _ = write!(w, "{}\n", block::code_name(e));
                                503
                            }
                        }
                    } else if r.path == b"/count" {
                        let _ = write!(w, "{}\n", self.requests + 1);
                        200
                    } else if cfg!(feature = "exit-on-request") && r.path == b"/exit" {
                        let _ = write!(w, "bye\n");
                        #[cfg(feature = "exit-on-request")]
                        {
                            self.exit = true;
                        }
                        200
                    } else {
                        404
                    };
                    body_len = w.len;
                    (status, body_skip, keep_alive, head) = (code, header_len + length, r.keep_alive && code != 413, is_head);
                }
            }
            let c = &mut self.conns[i];
            let skip = body_skip.min(c.len);
            c.buf.copy_within(skip..c.len, 0);
            c.len -= skip;
            c.discard = body_skip - skip;
            self.respond(i, status, &body[..body_len], head, keep_alive, now);
            if !self.flush(i) {
                return;
            }
        }
    }

    /// Close connections past their deadlines; returns the next deadline.
    fn check_deadlines(&mut self, now: u64) -> Option<u64> {
        let mut next: Option<u64> = None;
        for i in 0..CONNECTIONS {
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

    /// `count-cached`: write the cached count to block 0 if it changed and it's time (or `now`
    /// is None: before draining or exiting). Returns when to look again.
    #[cfg(feature = "count-cached")]
    fn persist(&mut self, now: Option<u64>) -> Option<u64> {
        let (Some(n), dirty, at) = self.cached else { return None };
        if now.is_some_and(|t| t < at) {
            return Some(at);
        }
        let next = uptime() + PERSIST_TICKS;
        self.cached = (Some(n), false, next);
        if !dirty {
            return Some(next);
        }
        let mut buf = [0u8; BLOCK_SIZE];
        buf[..8].copy_from_slice(&n.to_le_bytes());
        match self.disk.map(|d| block::write(d, 0, &buf)) {
            Some(Ok(())) => {
                println!("{}: count {} written to the volume", self.name(), n);
                Some(next)
            }
            Some(Err(e)) => {
                // Not the writer any more (or storage restarted): what we counted is lost, and
                // the next request goes to the volume.
                println!("{}: writing count {} failed: {}; cache dropped", self.name(), n, block::code_name(e));
                self.cached = (None, false, 0);
                if e == err::DEAD
                    && let Ok(d) = lookup("disk")
                {
                    self.disk = Some(d);
                }
                None
            }
            None => None,
        }
    }

    fn start_drain(&mut self) {
        println!("{}: draining", self.name());
        self.draining = true;
        if let Some(l) = self.listener.take() {
            let _ = net::close(self.net, l);
        }
    }
}

/// The server's state: far too big for the stack, so it lives here.
static mut SERVER: Server = Server {
    net: 0,
    name: [0; 32],
    name_len: 0,
    conns: [Conn::FREE; CONNECTIONS],
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
    disk: None,
    volume_failed: false,
    #[cfg(feature = "volume-probe")]
    probe: (0, None),
    #[cfg(feature = "crash-after-probes")]
    probes: 0,
    #[cfg(feature = "exit-on-request")]
    exit: false,
    #[cfg(feature = "count-cached")]
    cached: (None, false, 0),
};

fn main() -> u64 {
    let s = unsafe { &mut *(&raw mut SERVER) };
    let mut name = [0u8; 32];
    let me = task_name(getpid(), &mut name).unwrap_or("http").len();
    s.name = name;
    s.name_len = me;
    // In a generic slot (RFD 2), say which service and version this is, and where.
    if let Ok(info) = task_listen(getpid())
        && info.is_slot()
    {
        let mut w = Buf { buf: &mut s.name, len: 0 };
        let service = core::str::from_utf8(info.service()).unwrap_or("?");
        let slot = core::str::from_utf8(&name[..me]).unwrap_or("?");
        let _ = write!(w, "{} v{} on {}", service, info.version, slot);
        s.name_len = w.len;
        if info.volume_blocks > 0 {
            match lookup("disk") {
                Ok(disk) => s.disk = Some(disk),
                Err(_) => {
                    println!("{}: no storage task for its volume", s.name());
                    s.volume_failed = true;
                }
            }
        } else if cfg!(feature = "volume-probe")
            && let Ok(disk) = lookup("disk")
        {
            let e = block::capacity(disk).err().unwrap_or(block::CODE_OK);
            println!("{}: no volume declared; the storage task says {}", s.name(), block::code_name(e));
        }
    }
    s.open_volume();
    s.cycles_per_tick = vanir_user::tsc_per_tick();
    s.attach();

    let mut events = [Event::default(); 128];
    loop {
        let now = uptime();
        if now >= s.next_snapshot {
            s.snapshot(now);
            s.next_snapshot = now + s.interval;
        }
        let mut next = s.check_deadlines(now);
        if s.telemetry.is_some() {
            next = Some(next.map_or(s.next_snapshot, |n| n.min(s.next_snapshot)));
        }
        #[cfg(feature = "volume-probe")]
        if let Some(p) = s.probe(now) {
            next = Some(next.map_or(p, |n| n.min(p)));
        }
        #[cfg(feature = "count-cached")]
        if let Some(p) = s.persist(Some(now)) {
            next = Some(next.map_or(p, |n| n.min(p)));
        }
        if s.draining && !s.done_sent && s.conns.iter().all(|c| c.handle == 0) {
            // The next writer reads the count once we are done: write it first.
            #[cfg(feature = "count-cached")]
            s.persist(None);
            s.done_sent = true;
            println!("{}: drained, {} requests served", s.name(), s.requests);
            let _ = net::done(s.net);
        }
        let ticks = next.map_or(0, |n| n.saturating_sub(now).max(1));
        let n = match net::wait(s.net, ticks, &mut events) {
            Ok(n) => n,
            Err(e) if e == err::DEAD => {
                println!("{}: the network stack was restarted", s.name());
                s.attach();
                continue;
            }
            Err(e) => {
                println!("{}: wait failed: {}", s.name(), net::code_name(e));
                sleep(10);
                continue;
            }
        };
        s.check_writer();
        let now = uptime();
        for e in &events[..n] {
            if e.flags & EV_DRAIN != 0 {
                s.start_drain();
            }
            if e.flags & EV_ACCEPT != 0 && Some(e.handle) == s.listener {
                s.accept_all(e.handle, now);
            }
            let Some(i) = s.slot(e.handle) else { continue };
            if e.flags & EV_WRITE != 0 && !s.flush(i) {
                continue;
            }
            if e.flags & EV_READ != 0 {
                s.on_readable(i, now);
            } else if e.flags & EV_CLOSED != 0 {
                s.close(i);
            }
        }
        #[cfg(feature = "exit-on-request")]
        if s.exit {
            #[cfg(feature = "count-cached")]
            s.persist(None);
            println!("{}: exiting after {} requests, as asked", s.name(), s.requests);
            return 0;
        }
    }
}
