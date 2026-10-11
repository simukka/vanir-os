//! A small HTTP/1.1 server on the network stack task (`vanir_user::net`): GET and HEAD,
//! keep-alive, fixed buffers, one event loop.
//!
//! `/` answers with the task's name (so tests can tell instances apart) and `/count` with the
//! number of requests served. Limits: a request's header must fit in `HEADER_LIMIT` bytes (else
//! 431) and arrive within `HEADER_TICKS` of its first byte (else 408); bodies are refused above
//! `BODY_LIMIT` (413).
//!
//! When `net` tells us to drain, we stop accepting, answer what is in flight with
//! `Connection: close`, close idle connections, and say `OP_DONE` once none are left.

#![no_std]
#![no_main]

use core::fmt::Write;
use vanir_user::net::{self, CODE_CLOSED, EV_ACCEPT, EV_CLOSED, EV_DRAIN, EV_READ, EV_WRITE, Event};
use vanir_user::{err, getpid, lookup, println, sleep, task_name, uptime};

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

#[derive(Clone, Copy)]
struct Conn {
    /// 0: a free entry.
    handle: u32,
    buf: [u8; HEADER_LIMIT],
    len: usize,
    /// Body bytes still to skip (of a request we answered without reading its body).
    discard: usize,
    /// When the current request's first byte came.
    started: Option<u64>,
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
    #[cfg(feature = "exit-on-request")]
    exit: bool,
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
        let _ = net::ready(self.net);
        println!("{}: serving HTTP on port {}", self.name(), PORT);
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
        let keep_alive = keep_alive && !self.draining && status < 400;
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
        c.started = None;
        c.idle_since = now;
        self.requests += 1;
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
            c.started.get_or_insert(now);
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
            let (started, out_len, len) = (c.started, c.out_len, c.len);
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
            } else if self.draining && started.is_none() && out_len == 0 && len == 0 {
                self.close(i); // idle while draining: nothing in flight
            } else {
                next = Some(next.map_or(deadline, |n| n.min(deadline)));
            }
        }
        next
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
    #[cfg(feature = "exit-on-request")]
    exit: false,
};

fn main() -> u64 {
    let s = unsafe { &mut *(&raw mut SERVER) };
    let mut name = [0u8; 32];
    let me = task_name(getpid(), &mut name).unwrap_or("http").len();
    s.name = name;
    s.name_len = me;
    s.attach();

    let mut events = [Event::default(); 128];
    loop {
        let now = uptime();
        let next = s.check_deadlines(now);
        if s.draining && !s.done_sent && s.conns.iter().all(|c| c.handle == 0) {
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
            println!("{}: exiting after {} requests, as asked", s.name(), s.requests);
            return 0;
        }
    }
}
