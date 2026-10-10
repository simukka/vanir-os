//! Telemetry: forwards the kernel event log to the host as newline-delimited JSON through the
//! console driver, adds a heartbeat every second, and forwards `OP_LOG` text from other tasks.
//!
//! Every kernel event keeps its sequence number, so the host can tell when events were lost;
//! if the kernel's ring wrapped before we read it, a `dropped` record says how many.

#![no_std]
#![no_main]

use core::fmt::{self, Write};
use vanir_user::events::{self, Event};
use vanir_user::telemetry::OP_LOG;
use vanir_user::{NOTIFY_TIMER, console, err, lookup, println, recv_timeout, reply, sleep, task_index, task_name, uptime};

vanir_user::entry!(main);

const HEARTBEAT_TICKS: u64 = 100;
/// Batch output into console writes of at most this many bytes (the IPC limit is 4 KiB).
const BATCH: usize = 3584;

/// JSON lines waiting to go to the host.
struct Out {
    buf: [u8; 4096],
    len: usize,
    console: u64,
    link_name: &'static str,
}

impl Out {
    /// Send what has been collected, waiting out a console-driver restart if need be.
    fn flush(&mut self) {
        if self.len == 0 {
            return;
        }
        loop {
            match console::write(self.console, &self.buf[..self.len]) {
                Ok(()) => break,
                Err(e) if console::is_dead(e) => {
                    let old = self.console;
                    self.console = loop {
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
        kind => write!(out, "\"event\":\"unknown\",\"kind\":{}", kind),
    };
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
        let state = ["running", "blocked", "exited", "faulted", "over_budget"].get(state as usize).unwrap_or(&"?");
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
    // else the virtio console.
    let console = lookup("uplink").or_else(|_| lookup("virtio-console")).expect("no uplink task");
    let link_name = if lookup("uplink").is_ok() { "uplink" } else { "virtio-console" };
    let mut out = Out { buf: [0; 4096], len: 0, console, link_name };
    let mut msg = [0u8; 512];
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
