//! Faults as soon as it starts: something for the supervisor to restart.
//!
//! With `crash-3-then-wait` (for the backoff reset test): the first three starts fault at once,
//! the fourth runs 2.5 s before faulting, the fifth faults at once, and the sixth exits 0.

#![no_std]
#![no_main]

use vanir_user::{getpid, println, uptime};

vanir_user::entry!(main);

fn main() -> u64 {
    let generation = getpid() >> 16;
    if generation < 12 {
        println!("crasher: start {} at tick {}, about to fault", generation, uptime());
    }
    #[cfg(feature = "crash-3-then-wait")]
    match generation {
        3 => vanir_user::sleep(250),
        5.. => return 0,
        _ => {}
    }
    unsafe { core::ptr::read_volatile(0x10 as *const u8) };
    0
}
