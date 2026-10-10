//! The supervisor: the kernel reports every task's death here, and this task decides what to do.
//! Policy: a task that exited 0 is done; a task that faulted, exited non-zero or ran out of CPU
//! budget is restarted, up to `MAX_RESTARTS` times, then left dead.

#![no_std]
#![no_main]

use vanir_user::{DeathRecord, NOTIFY_DEATH, err, println, recv, restart, task_index};

vanir_user::entry!(main);

#[cfg(not(feature = "restart-3000"))]
const MAX_RESTARTS: u32 = 3;
#[cfg(feature = "restart-3000")]
const MAX_RESTARTS: u32 = 3000;

/// Log every event up to this many restarts of a task, then only every 500th.
const VERBOSE_RESTARTS: u32 = 5;

fn main() -> u64 {
    let mut restarts = [0u32; 16];
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
            _ => {}
        }
        if *count >= MAX_RESTARTS {
            println!("supervisor: giving up on task {} after {} restarts", task, *count);
            continue;
        }
        *count += 1;
        match restart(d.id) {
            Ok(id) if verbose => println!("supervisor: restarted task {} (restart {}, id {:#x})", task, *count, id),
            Ok(_) => {}
            Err(e) => println!("supervisor: restart of task {} failed: {}", task, err::name(e)),
        }
    }
}
