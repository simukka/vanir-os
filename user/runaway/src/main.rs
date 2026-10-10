//! Spins forever without a syscall. Only preemption keeps other processes running, and only a
//! CPU budget can end it.

#![no_std]
#![no_main]

vanir_user::entry!(main);

fn main() -> u64 {
    loop {
        core::hint::spin_loop();
    }
}
