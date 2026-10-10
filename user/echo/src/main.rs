//! IPC server: replies to every message with the same bytes. Operation `OP_CRASH` makes it fault
//! instead, so tests can kill a server while a client waits for its reply.

#![no_std]
#![no_main]

use vanir_user::{println, recv, reply};

vanir_user::entry!(main);

pub const OP_ECHO: u64 = 1;
pub const OP_CRASH: u64 = 2;

fn main() -> u64 {
    let mut buf = [0u8; 4096];
    loop {
        let m = match recv(&mut buf) {
            Ok(m) => m,
            Err(e) => {
                println!("echo: recv failed: {}", vanir_user::err::name(e));
                return 1;
            }
        };
        if m.op == OP_CRASH {
            unsafe { core::ptr::read_volatile(0 as *const u8) }; // fault while the client waits
        }
        if let Err(e) = reply(m.sender, 0, &buf[..m.len]) {
            println!("echo: reply failed: {}", vanir_user::err::name(e));
        }
    }
}
