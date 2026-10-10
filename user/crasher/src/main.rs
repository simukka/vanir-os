//! Faults as soon as it starts: something for the supervisor to restart.

#![no_std]
#![no_main]

use vanir_user::{getpid, println};

vanir_user::entry!(main);

fn main() -> u64 {
    let generation = getpid() >> 16;
    if generation < 5 {
        println!("crasher: start {}, about to fault", generation);
    }
    unsafe { core::ptr::read_volatile(0x10 as *const u8) };
    0
}
