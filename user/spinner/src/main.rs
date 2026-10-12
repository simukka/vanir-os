//! Busy-waits between prints without making syscalls, so only the timer can take the CPU away.
//! Prints `spinner <letter> <i>`, where the letter comes from the pid (pid 1 = A).

#![no_std]
#![no_main]

use vanir_user::{getpid, println, spin_cycles, task_index};

vanir_user::entry!(main);

const ROUNDS: u64 = 10;
const SPIN: u64 = 20_000_000; // TSC cycles between prints, several milliseconds

fn main() -> u64 {
    let letter = (b'A' + (task_index(getpid()) as u8 - 1)) as char;
    // Spin for 2 s of uptime instead, so a test has time to watch something else happen.
    if cfg!(feature = "spin-2s") {
        let start = vanir_user::uptime();
        while vanir_user::uptime() < start + 200 {
            spin_cycles(SPIN / 4);
        }
        println!("spinner {}: spun for 2 s", letter);
        return 0;
    }
    for i in 0..ROUNDS {
        spin_cycles(SPIN);
        println!("spinner {} {}", letter, i);
    }
    0
}
