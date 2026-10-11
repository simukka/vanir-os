//! The supervisor: the kernel reports every task's death here, and this task decides what to do.
//! Policy: a task that exited 0 is done; a task that faulted, exited non-zero or ran out of CPU
//! budget is restarted, up to `MAX_RESTARTS` times, then left dead.
//!
//! With the `halt-on-exit` feature (for tests whose servers never go idle), the first task to
//! exit, cleanly or not, stops the system.

#![no_std]
#![no_main]

use core::fmt::Write;
use vanir_user::{DeathRecord, LineWriter, NOTIFY_DEATH, err, lookup, println, recv, restart, task_index, telemetry};

vanir_user::entry!(main);

#[cfg(not(feature = "restart-3000"))]
const MAX_RESTARTS: u32 = 3;
#[cfg(feature = "restart-3000")]
const MAX_RESTARTS: u32 = 3000;

/// Log every event up to this many restarts of a task, then only every 500th.
const VERBOSE_RESTARTS: u32 = 5;

/// Print a decision, and send it to the telemetry task if there is one we may talk to.
fn report(telemetry: Option<u64>, args: core::fmt::Arguments) {
    let mut line = LineWriter::new();
    let _ = line.write_fmt(args);
    println!("supervisor: {}", core::str::from_utf8(line.as_bytes()).unwrap_or("?"));
    if let Some(t) = telemetry {
        let _ = telemetry::log(t, line.as_bytes()); // best effort: telemetry may be gone
    }
}

fn main() -> u64 {
    let telemetry = lookup("telemetry").ok();
    let mut restarts = [0u32; 17];
    let mut buf = [0u8; 256];
    loop {
        let m = match recv(&mut buf) {
            Ok(m) => m,
            Err(e) => {
                println!("supervisor: recv failed: {}", err::name(e));
                continue;
            }
        };
        if m.sender != 0 || m.op != NOTIFY_DEATH {
            // Nobody else is meant to talk to the supervisor yet.
            let _ = vanir_user::reply(m.sender, 1, &[]);
            continue;
        }
        let Some(d) = DeathRecord::from_bytes(&buf[..m.len]) else {
            println!("supervisor: malformed death record");
            continue;
        };
        let task = task_index(d.id) as usize;
        let count = &mut restarts[task];
        let verbose = *count < VERBOSE_RESTARTS || (*count + 1) % 500 == 0;
        #[cfg(feature = "halt-on-exit")]
        if d.kind == 1 {
            println!("supervisor: task {} exited with code {}; stopping the system", task, d.code);
            vanir_user::halt(d.code);
        }
        match d.kind {
            1 if d.code == 0 => {
                println!("supervisor: task {} exited cleanly", task);
                continue;
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
                continue;
            }
            _ => {}
        }
        if *count >= MAX_RESTARTS {
            report(telemetry, format_args!("giving up on task {} after {} restarts", task, *count));
            continue;
        }
        *count += 1;
        match restart(d.id) {
            Ok(id) if verbose => println!("supervisor: restarted task {} (restart {}, id {:#x})", task, *count, id),
            Ok(_) => {}
            Err(e) => report(telemetry, format_args!("restart of task {} failed: {}", task, err::name(e))),
        }
    }
}
