//! Telemetry: forwards the kernel event log to the host as newline-delimited JSON through the
//! console driver, adds a heartbeat every second, and forwards `OP_LOG` text, `OP_STORAGE`
//! events (volume created, locked, unlocked, integrity error), network events (`OP_NET`), other
//! events such as crashes (`OP_EVENT`) and counter snapshots (`OP_COUNTERS`) from other tasks.
//!
//! Without an uplink driver, telemetry goes to the control plane through the node agent (RFD 2,
//! P7), which *pulls* it (`OP_PULL`): if we pushed to the agent while it sends to `net`, and
//! `net` to us, the three could deadlock. Lines wait in a 16 KiB ring until pulled; when it is
//! full the oldest are dropped and counted.
//!
//! The snapshot interval is ours to give out: each `OP_COUNTERS` is answered with it, so every
//! reporter follows when the host changes it (`OP_SET_INTERVAL`, from the control task).
//!
//! Every kernel event keeps its sequence number, so the host can tell when events were lost;
//! if the kernel's ring wrapped before we read it, a `dropped` record says how many.

#![no_std]
#![no_main]

use core::fmt::{self, Write};
use vanir_user::events::{self, Event};
use vanir_user::telemetry::{self, DEFAULT_INTERVAL_TICKS, OP_COUNTERS, OP_EVENT, OP_LOG, OP_NET, OP_PULL, OP_SET_INTERVAL};
use vanir_user::{NOTIFY_TIMER, console, err, lookup, println, recv_timeout, reply, sleep, task_index, task_name, uptime};

vanir_user::entry!(main);

const HEARTBEAT_TICKS: u64 = 100;
/// Batch output into console writes of at most this many bytes (the IPC limit is 4 KiB).
const BATCH: usize = 3584;

/// Bytes of lines kept for the agent to pull.
const RING: usize = 16384;

/// JSON lines waiting to go to the host.
struct Out {
    buf: [u8; 4096],
    len: usize,
    /// The uplink driver, or None when the agent pulls (`ring`).
    console: Option<u64>,
    link_name: &'static str,
    ring: [u8; RING],
    ring_len: usize,
    /// Lines dropped from the ring since the agent last pulled.
    ring_dropped: u64,
}

impl Out {
    /// Move whole lines from the ring into `out` (for `OP_PULL`); returns the length.
    fn pull(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        if self.ring_dropped != 0 {
            let mut line = vanir_user::LineWriter::new();
            let _ = write!(line, "{{\"t\":{},\"event\":\"dropped\",\"lines\":{}}}\n", uptime(), self.ring_dropped);
            n = line.as_bytes().len().min(out.len());
            out[..n].copy_from_slice(&line.as_bytes()[..n]);
            self.ring_dropped = 0;
        }
        // Up to the last newline that fits.
        let room = (out.len() - n).min(self.ring_len);
        let take = self.ring[..room].iter().rposition(|&b| b == b'\n').map_or(0, |p| p + 1);
        out[n..n + take].copy_from_slice(&self.ring[..take]);
        self.ring.copy_within(take..self.ring_len, 0);
        self.ring_len -= take;
        n + take
    }

    /// Keep `bytes` (whole lines) for the agent, dropping the oldest lines if there is no room.
    fn keep(&mut self, bytes: &[u8]) {
        let bytes = &bytes[..bytes.len().min(RING)];
        while self.ring_len + bytes.len() > RING {
            let first = self.ring[..self.ring_len].iter().position(|&b| b == b'\n').map_or(self.ring_len, |p| p + 1);
            self.ring.copy_within(first..self.ring_len, 0);
            self.ring_len -= first;
            self.ring_dropped += 1;
        }
        self.ring[self.ring_len..self.ring_len + bytes.len()].copy_from_slice(bytes);
        self.ring_len += bytes.len();
    }

    /// Send what has been collected, waiting out a console-driver restart if need be.
    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        let Some(console) = self.console else {
            let (buf, len) = (self.buf, self.len);
            self.keep(&buf[..len]);
            self.len = 0;
            return;
        };
        let mut console = console;
        loop {
            match console::write(console, &self.buf[..self.len]) {
                Ok(()) => break,
                Err(e) if console::is_dead(e) => {
                    let old = console;
                    console = loop {
                        match lookup(self.link_name) {
                            Ok(id) if id != old => break id,
                            _ => sleep(1),
                        }
                    };
                }
                Err(e) => {
                    println!("telemetry: console write failed: {}", err::name(e));
                    break;
                }
            }
        }
        self.console = Some(console);
        self.len = 0;
    }

    /// Finish a JSON line; send the batch if it is getting full.
    fn end_line(&mut self) {
        let _ = self.write_str("\n");
        if self.len > BATCH {
            self.flush();
        }
    }
}

impl Write for Out {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            self.flush();
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

/// A task id as "slot" or "slot.generation".
struct Id(u64);

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "\"{}", task_index(self.0))?;
        if self.0 >> 16 != 0 {
            write!(f, ".{}", self.0 >> 16)?;
        }
        f.write_str("\"")
    }
}

/// A task's name as a JSON string.
struct Name(u64);

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 64];
        write!(f, "\"{}\"", task_name(self.0, &mut buf).unwrap_or("?"))
    }
}

/// Text as a JSON string.
struct Text<'a>(&'a [u8]);

impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("\"")?;
        for &b in self.0 {
            match b {
                b'"' => f.write_str("\\\"")?,
                b'\\' => f.write_str("\\\\")?,
                b'\n' => f.write_str("\\n")?,
                0x20..=0x7e => f.write_char(b as char)?,
                _ => write!(f, "\\u{:04x}", b)?,
            }
        }
        f.write_str("\"")
    }
}

fn event_line(out: &mut Out, e: &Event) {
    let _ = write!(out, "{{\"seq\":{},\"t\":{},\"task\":{},\"id\":{},", e.seq, e.tick, Name(e.task), Id(e.task));
    let _ = match e.kind {
        events::TASK_START => write!(out, "\"event\":\"start\""),
        events::EXIT => write!(out, "\"event\":\"exit\",\"code\":{}", e.a),
        events::FAULT => write!(out, "\"event\":\"fault\",\"vector\":{},\"rip\":\"{:#x}\",\"cr2\":\"{:#x}\"", e.a, e.b, e.c),
        events::OVER_BUDGET => write!(out, "\"event\":\"over_budget\",\"budget\":{}", e.a),
        events::RESTART => write!(out, "\"event\":\"restart\",\"previous\":{}", Id(e.a)),
        events::IPC_REFUSED => write!(
            out,
            "\"event\":\"ipc_refused\",\"target\":{},\"error\":\"{}\"",
            Name(e.a),
            err::name(e.b)
        ),
        events::IMAGE_REJECTED => write!(out, "\"event\":\"image_rejected\",\"reason\":\"{}\"", events::rejection(e.a)),
        events::IMAGE_LOADED => write!(out, "\"event\":\"image_loaded\",\"version\":{}", e.a),
        events::IMAGE_UNLOADED => write!(out, "\"event\":\"image_unloaded\",\"version\":{}", e.a),
        events::STOPPED => write!(out, "\"event\":\"stopped\""),
        kind => write!(out, "\"event\":\"unknown\",\"kind\":{}", kind),
    };
    let _ = out.write_str("}");
    out.end_line();
}

/// A storage task's event (`telemetry::OP_STORAGE`). The sender's name comes from the kernel, so
/// a task can report events only as itself.
fn storage_line(out: &mut Out, sender: u64, msg: &[u8]) {
    let kind = u64::from_le_bytes(msg[..8].try_into().unwrap());
    let block = u64::from_le_bytes(msg[8..16].try_into().unwrap());
    let name = Text(&msg[16..]);
    let _ = write!(out, "{{\"t\":{},\"task\":{},\"id\":{},", uptime(), Name(sender), Id(sender));
    let _ = match kind {
        telemetry::VOLUME_CREATED => write!(out, "\"event\":\"volume_created\",\"volume\":{},\"start\":{}", name, block),
        telemetry::STORAGE_LOCKED => write!(out, "\"event\":\"storage_locked\""),
        telemetry::STORAGE_UNLOCKED => write!(out, "\"event\":\"storage_unlocked\",\"by\":{}", name),
        telemetry::INTEGRITY_ERROR => write!(out, "\"event\":\"integrity_error\",\"volume\":{},\"block\":{}", name, block),
        kind => write!(out, "\"event\":\"unknown\",\"storage_kind\":{}", kind),
    };
    let _ = out.write_str("}");
    out.end_line();
}

/// `key=value`, if the key is a plain name.
fn field(f: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = f.iter().position(|&b| b == b'=')?;
    let key = &f[..eq];
    key.iter().all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_').then_some((key, &f[eq + 1..]))
}

/// A `Record` (`name key=value ...`) as a JSON line: `{"t":..,"task":..,"id":..,<kind>:<name>,
/// <key>:<value>,...}`. Numbers stay numbers. A `t` field (the reporter's uptime) replaces ours.
/// The sender's name comes from the kernel, so a task can only report as itself.
fn record_line(out: &mut Out, sender: u64, kind: &str, record: &[u8]) {
    let mut fields = record.split(|&b| b == b' ').filter(|f| !f.is_empty());
    let Some(name) = fields.next() else { return };
    let t = fields.clone().filter_map(field).find(|(k, _)| *k == b"t").map(|(_, v)| v);
    match t.filter(|v| !v.is_empty() && v.iter().all(u8::is_ascii_digit)) {
        Some(v) => {
            let _ = write!(out, "{{\"t\":{}", core::str::from_utf8(v).unwrap());
        }
        None => {
            let _ = write!(out, "{{\"t\":{}", uptime());
        }
    }
    let _ = write!(out, ",\"task\":{},\"id\":{},\"{}\":{}", Name(sender), Id(sender), kind, Text(name));
    if kind == "scope" {
        let _ = out.write_str(",\"event\":\"counters\"");
    }
    for (key, value) in fields.filter_map(field).filter(|(k, _)| *k != b"t") {
        let _ = write!(out, ",{}:", Text(key));
        if !value.is_empty() && value.len() <= 19 && value.iter().all(u8::is_ascii_digit) {
            let _ = out.write_str(core::str::from_utf8(value).unwrap());
        } else {
            let _ = write!(out, "{}", Text(value));
        }
    }
    let _ = out.write_str("}");
    out.end_line();
}

/// Forward every event the kernel has logged since the last call.
fn drain_events(out: &mut Out) {
    let mut batch = [Event::default(); 32];
    loop {
        let (n, dropped) = match events::read(&mut batch) {
            Ok(r) => r,
            Err(e) => {
                println!("telemetry: cannot read events: {}", err::name(e));
                return;
            }
        };
        if dropped != 0 {
            let _ = write!(out, "{{\"t\":{},\"event\":\"dropped\",\"count\":{}}}", uptime(), dropped);
            out.end_line();
        }
        for e in &batch[..n] {
            event_line(out, e);
        }
        if n < batch.len() {
            return;
        }
    }
}

fn heartbeat(out: &mut Out, n: u64) {
    let Ok(s) = events::stats() else { return };
    let _ = write!(
        out,
        "{{\"t\":{},\"event\":\"heartbeat\",\"n\":{},\"frames\":{},\"irqs\":{},\"events\":{},\"tasks\":[",
        s.uptime_ticks, n, s.frames_in_use, s.device_interrupts, s.events_logged
    );
    let mut first = true;
    for [id, state, ticks] in s.task.iter().copied().filter(|t| t[0] != 0) {
        let state = ["running", "blocked", "exited", "faulted", "over_budget", "rejected", "empty", "stopped"].get(state as usize).unwrap_or(&"?");
        let _ = write!(
            out,
            "{}{{\"task\":{},\"id\":{},\"state\":\"{}\",\"ticks\":{}}}",
            if first { "" } else { "," },
            Name(id),
            Id(id),
            state,
            ticks
        );
        first = false;
    }
    let _ = out.write_str("]}");
    out.end_line();
}

fn main() -> u64 {
    // The host link is the task named "uplink" (any driver with the console interface), or
    // else the virtio console, or else the agent pulls (OP_PULL).
    let console = lookup("uplink").or_else(|_| lookup("virtio-console")).ok();
    assert!(console.is_some() || lookup("agent").is_ok(), "no uplink task, console or agent");
    let link_name = if lookup("uplink").is_ok() { "uplink" } else { "virtio-console" };
    let mut out = Out { buf: [0; 4096], len: 0, console, link_name, ring: [0; RING], ring_len: 0, ring_dropped: 0 };
    let mut msg = [0u8; 4096];
    let mut interval = DEFAULT_INTERVAL_TICKS;
    let mut next_heartbeat = uptime() + HEARTBEAT_TICKS;
    let mut heartbeats = 0;
    loop {
        let wait = next_heartbeat.saturating_sub(uptime()).max(1);
        match recv_timeout(&mut msg, wait) {
            Ok(m) if m.sender == 0 && m.op == NOTIFY_TIMER => {}
            Ok(m) if m.op == OP_LOG => {
                let _ = reply(m.sender, 0, &[]);
                drain_events(&mut out); // keep the stream in order: kernel events first
                let _ = write!(out, "{{\"t\":{},\"event\":\"log\",\"from\":{},\"msg\":{}}}", uptime(), Name(m.sender), Text(&msg[..m.len]));
                out.end_line();
            }
            Ok(m) if m.op == telemetry::OP_STORAGE && m.len >= 16 => {
                let _ = reply(m.sender, 0, &[]);
                drain_events(&mut out);
                storage_line(&mut out, m.sender, &msg[..m.len]);
            }
            Ok(m) if m.op == OP_NET || m.op == OP_EVENT => {
                let _ = reply(m.sender, 0, &[]);
                drain_events(&mut out);
                record_line(&mut out, m.sender, "event", &msg[..m.len]);
            }
            Ok(m) if m.op == OP_COUNTERS => {
                let _ = reply(m.sender, 0, &interval.to_le_bytes());
                record_line(&mut out, m.sender, "scope", &msg[..m.len]);
            }
            Ok(m) if m.op == OP_PULL => {
                let mut name = [0u8; 16];
                if task_name(m.sender, &mut name) != Ok("agent") {
                    let _ = reply(m.sender, 2, &[]);
                    continue;
                }
                drain_events(&mut out);
                out.flush();
                let mut lines = [0u8; 4096];
                let n = out.pull(&mut lines);
                let _ = reply(m.sender, 0, &lines[..n]);
            }
            Ok(m) if m.op == OP_SET_INTERVAL && m.len == 8 => {
                let mut name = [0u8; 16];
                if !matches!(task_name(m.sender, &mut name), Ok("control" | "agent")) {
                    let _ = reply(m.sender, 2, &[]);
                    continue;
                }
                let ms = u64::from_le_bytes(msg[..8].try_into().unwrap()).clamp(100, 60_000);
                interval = ms / 10;
                let _ = reply(m.sender, 0, &[]);
                let _ = write!(out, "{{\"t\":{},\"event\":\"interval\",\"ticks\":{}}}", uptime(), interval);
                out.end_line();
            }
            Ok(m) => {
                let _ = reply(m.sender, 1, &[]);
            }
            Err(e) => println!("telemetry: recv failed: {}", err::name(e)),
        }
        drain_events(&mut out);
        if uptime() >= next_heartbeat {
            heartbeats += 1;
            heartbeat(&mut out, heartbeats);
            next_heartbeat += HEARTBEAT_TICKS;
        }
        out.flush();
        #[cfg(feature = "exit-after-3-heartbeats")]
        if heartbeats == 3 {
            return 0;
        }
        let _ = heartbeats;
    }
}
