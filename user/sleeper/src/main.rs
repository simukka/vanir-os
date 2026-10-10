//! Sleeps for 10 ticks per task number (task 2 sleeps 20 ticks), then checks it woke neither
//! early nor more than a few ticks late.

#![no_std]
#![no_main]

use vanir_user::{getpid, println, sleep, task_index, uptime};

vanir_user::entry!(main);

/// How late a wake-up may be, in ticks, before it counts as broken.
const SLACK: u64 = 3;

fn main() -> u64 {
    let task = task_index(getpid());
    let asked = 10 * task;
    let start = uptime();
    sleep(asked);
    let slept = uptime() - start;
    println!("sleeper {}: woke after {} ticks (asked for {})", task, slept, asked);
    if slept < asked || slept > asked + SLACK { 1 } else { 0 }
}
