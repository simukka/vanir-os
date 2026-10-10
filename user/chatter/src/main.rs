//! Sends `line 0` .. `line 199` to the host through the console driver. If the driver dies, it
//! waits for the supervisor to restart it (a new task id) and resends the line that failed.

#![no_std]
#![no_main]

use core::fmt::Write;
use vanir_user::{console, err, lookup, println, sleep};

vanir_user::entry!(main);

const LINES: u32 = 200;

fn main() -> u64 {
    let mut driver = lookup("virtio-console").expect("no virtio-console task");
    let mut restarts_seen = 0;
    for i in 0..LINES {
        let mut line = vanir_user::LineWriter::new();
        let _ = writeln!(line, "line {}", i);
        loop {
            match console::write(driver, line.as_bytes()) {
                Ok(()) => break,
                Err(e) if console::is_dead(e) => {
                    // Wait for a new incarnation of the driver, then resend this line.
                    driver = loop {
                        match lookup("virtio-console") {
                            Ok(id) if id != driver => break id,
                            _ => sleep(1),
                        }
                    };
                    restarts_seen += 1;
                }
                Err(e) => {
                    println!("chatter: write failed: {}", err::name(e));
                    return 1;
                }
            }
        }
    }
    println!("chatter: sent {} lines, driver restarted {} times", LINES, restarts_seen);
    0
}
