//! The supervisor: the kernel reports every task's death here, and this task decides what to do.
//! Policy (RFD 2, P5): a task that exited 0 is done; a task that faulted, exited non-zero or ran
//! out of CPU budget is always restarted, with exponential backoff between restarts so a crash
//! loop can't eat the CPU: 1 tick (10 ms) after a crash, doubling up to `MAX_BACKOFF`, and back
//! to 1 tick once the task has run `RESET_TICKS` since its last restart. Every crash is reported
//! to telemetry with the restart count and the backoff.
//!
//! The agent asks it to stop and start tasks (`supervisor::OP_STOP`, `OP_START`, RFD 2, P4): a
//! stopped task is reported as stopped and never restarted; starting one again resets its
//! backoff. It also asks it to reboot an empty node into a new image (`OP_REBOOT`).
//!
//! Test features: `halt-on-exit` stops the system when any task exits (tests whose servers never
//! go idle); `give-up-after-3` / `give-up-after-3000` stop restarting a task after that many
//! restarts, so a run whose only work is a crash loop can end; `backoff-fast` restarts at once;
//! `reset-after-2s` shortens the reset window.

#![no_std]
#![no_main]

use core::fmt::Write;
use vanir_user::supervisor::{OP_REBOOT, OP_START, OP_STOP};
use vanir_user::telemetry::{self, Record};
use vanir_user::{
    DeathRecord, LineWriter, MAX_TASKS, NOTIFY_DEATH, NOTIFY_TIMER, err, lookup, println, recv, recv_timeout, restart, task_index,
    task_name, uptime,
};

vanir_user::entry!(main);

/// The longest wait before a restart: 30 s.
const MAX_BACKOFF: u64 = 3000;
/// A task that has run this long since its last restart starts again from the shortest backoff.
#[cfg(not(feature = "reset-after-2s"))]
const RESET_TICKS: u64 = 6000;
#[cfg(feature = "reset-after-2s")]
const RESET_TICKS: u64 = 200;

#[cfg(feature = "give-up-after-3")]
const GIVE_UP: Option<u32> = Some(3);
#[cfg(feature = "give-up-after-3000")]
const GIVE_UP: Option<u32> = Some(3000);
#[cfg(not(any(feature = "give-up-after-3", feature = "give-up-after-3000")))]
const GIVE_UP: Option<u32> = None;

/// Log every event up to this many restarts of a task, then only every 500th.
const VERBOSE_RESTARTS: u32 = 10;

/// What the supervisor remembers about one task slot.
#[derive(Clone, Copy, Default)]
struct Slot {
    /// Restarts so far, ever.
    restarts: u32,
    /// The wait before the last restart, in ticks (0: none yet, or reset).
    backoff: u64,
    /// When it was last restarted.
    restarted_at: u64,
    /// A restart waiting for its backoff: (due tick, the dead task's id).
    pending: Option<(u64, u64)>,
}

/// Print a decision, and send it to the telemetry task if there is one we may talk to.
fn report(telemetry: Option<u64>, args: core::fmt::Arguments) {
    let mut line = LineWriter::new();
    let _ = line.write_fmt(args);
    println!("supervisor: {}", core::str::from_utf8(line.as_bytes()).unwrap_or("?"));
    if let Some(t) = telemetry {
        let _ = telemetry::log(t, line.as_bytes()); // best effort: telemetry may be gone
    }
}

/// The wait before the next restart of a task that just crashed.
fn next_backoff(slot: &Slot, now: u64) -> u64 {
    if cfg!(feature = "backoff-fast") {
        return 0;
    }
    if slot.backoff == 0 || now.saturating_sub(slot.restarted_at) >= RESET_TICKS {
        1
    } else {
        (slot.backoff * 2).min(MAX_BACKOFF)
    }
}

fn do_restart(slots: &mut [Slot; MAX_TASKS], task: usize, id: u64, telemetry: Option<u64>) {
    let slot = &mut slots[task];
    slot.pending = None;
    slot.restarts += 1;
    slot.restarted_at = uptime();
    let verbose = slot.restarts <= VERBOSE_RESTARTS || slot.restarts % 500 == 0;
    match restart(id) {
        Ok(id) if verbose => println!("supervisor: restarted task {} (restart {}, id {:#x})", task, slot.restarts, id),
        Ok(_) => {}
        Err(e) => report(telemetry, format_args!("restart of task {} failed: {}", task, err::name(e))),
    }
}

fn main() -> u64 {
    let telemetry = lookup("telemetry").ok();
    let mut slots = [Slot::default(); MAX_TASKS];
    let mut buf = [0u8; 256];
    loop {
        // Wait for a death, or until the next pending restart is due.
        let due = slots.iter().filter_map(|s| s.pending).map(|(at, _)| at).min();
        let m = match due {
            Some(at) => recv_timeout(&mut buf, at.saturating_sub(uptime())),
            None => recv(&mut buf),
        };
        match m {
            Ok(m) if m.sender == 0 && m.op == NOTIFY_TIMER => {}
            Ok(m) if m.sender == 0 && m.op == NOTIFY_DEATH => match DeathRecord::from_bytes(&buf[..m.len]) {
                Some(d) => on_death(&mut slots, &d, telemetry),
                None => println!("supervisor: malformed death record"),
            },
            Ok(m) if (m.op == OP_STOP || m.op == OP_START) && m.len == 8 => {
                // Only tasks whose `sends` name us get here: in practice, the agent.
                let id = u64::from_le_bytes(buf[..8].try_into().unwrap());
                let (code, data) = on_request(&mut slots, m.op, id);
                let _ = vanir_user::reply(m.sender, code, &data.to_le_bytes());
            }
            Ok(m) if m.op == OP_REBOOT => {
                report(telemetry, format_args!("rebooting at the request of task {}", task_index(m.sender)));
                let e = vanir_user::reboot();
                let _ = vanir_user::reply(m.sender, 0x100 | (e & 0xff), &[]);
            }
            Ok(m) => {
                let _ = vanir_user::reply(m.sender, 1, &[]);
            }
            Err(e) => println!("supervisor: recv failed: {}", err::name(e)),
        }
        let now = uptime();
        for task in 0..MAX_TASKS {
            if let Some((at, id)) = slots[task].pending
                && at <= now
            {
                do_restart(&mut slots, task, id, telemetry);
            }
        }
    }
}

/// Stop a task, or start a stopped one again. Returns (reply code, new id): code 0 on
/// success, otherwise the kernel's error.
fn on_request(slots: &mut [Slot; MAX_TASKS], op: u64, id: u64) -> (u64, u64) {
    let Some(slot) = slots.get_mut(task_index(id) as usize) else { return (0x100 | (err::BAD_TARGET & 0xff), 0) };
    slot.pending = None;
    let result = if op == OP_STOP { vanir_user::stop(id).map(|()| 0) } else { restart(id) };
    match result {
        Ok(new) => {
            if op == OP_START {
                slot.backoff = 0;
                slot.restarted_at = uptime();
                println!("supervisor: started task {} again (id {:#x})", task_index(id), new);
            }
            (0, new)
        }
        // Reply codes must have the top bit clear; the low bits say which kernel error it was.
        Err(e) => (0x100 | (e & 0xff), 0),
    }
}

fn on_death(slots: &mut [Slot; MAX_TASKS], d: &DeathRecord, telemetry: Option<u64>) {
    let task = task_index(d.id) as usize;
    let Some(slot) = slots.get_mut(task) else { return };
    let verbose = slot.restarts < VERBOSE_RESTARTS || (slot.restarts + 1) % 500 == 0;
    #[cfg(feature = "halt-on-exit")]
    if d.kind == 1 {
        println!("supervisor: task {} exited with code {}; stopping the system", task, d.code);
        vanir_user::halt(d.code);
    }
    match d.kind {
        1 if d.code == 0 => {
            println!("supervisor: task {} exited cleanly", task);
            return;
        }
        1 => println!("supervisor: task {} exited with code {}", task, d.code),
        2 if verbose => println!(
            "supervisor: task {} faulted: vector {} at rip {:#x}, cr2 {:#x}, error {:#x}",
            task, d.code, d.rip, d.cr2, d.error_code
        ),
        3 if verbose => println!("supervisor: task {} used up its CPU budget", task),
        4 => {
            let why = vanir_user::events::rejection(d.code);
            report(telemetry, format_args!("task {} image rejected ({}): not starting it", task, why));
            return;
        }
        5 => {
            println!("supervisor: task {} stopped", task);
            slot.pending = None;
            return;
        }
        _ => {}
    }
    if let Some(limit) = GIVE_UP
        && slot.restarts >= limit
    {
        report(telemetry, format_args!("giving up on task {} after {} restarts", task, slot.restarts));
        return;
    }
    let now = uptime();
    let backoff = next_backoff(slot, now);
    slot.backoff = backoff;
    if verbose {
        println!("supervisor: restarting task {} in {} ticks (restart {})", task, backoff, slot.restarts + 1);
        if let Some(t) = telemetry {
            let kind = ["", "exit", "fault", "over_budget"].get(d.kind as usize).unwrap_or(&"?");
            let mut name = [0u8; 32];
            let mut r = Record::new("crash");
            r.text("of", task_name(d.id, &mut name).unwrap_or("?")).num("index", task as u64).text("kind", kind).num("code", d.code).num("restarts", slot.restarts as u64);
            r.num("backoff_ms", backoff * 10);
            let _ = telemetry::event(t, &r);
        }
    }
    if backoff == 0 {
        do_restart(slots, task, d.id, telemetry);
    } else {
        slot.pending = Some((now + backoff, d.id));
    }
}
