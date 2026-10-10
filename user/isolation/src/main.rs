//! Address-space isolation: run two (or more) copies. Each writes its own value to the same
//! virtual address, spins long enough to be preempted so the others run and write theirs, then
//! checks its value is unchanged.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};
use vanir_user::{getpid, println, spin_cycles, task_index, yield_now};

vanir_user::entry!(main);

static mut VALUE: u64 = 0;

fn main() -> u64 {
    let pid = task_index(getpid());
    let mine = pid * 0x1111_1111_1111;
    unsafe { write_volatile(&raw mut VALUE, mine) };
    yield_now(); // let the other copies write their values now
    spin_cycles(100_000_000); // tens of milliseconds: several time slices
    let seen = unsafe { read_volatile(&raw const VALUE) };
    if seen == mine {
        println!("isolation pid {}: ok", pid);
        0
    } else {
        println!("isolation pid {}: value changed to {:#x}", pid, seen);
        1
    }
}
