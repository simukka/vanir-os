//! Run as `deadlock-a` and `deadlock-b`, each allowed to send to the other: both send at once,
//! so neither can ever receive. The kernel must detect it.

#![no_std]
#![no_main]

use vanir_user::{getpid, lookup, println, send};

vanir_user::entry!(main);

fn main() -> u64 {
    let a = lookup("deadlock-a").expect("no deadlock-a");
    let b = lookup("deadlock-b").expect("no deadlock-b");
    let peer = if getpid() == a { b } else { a };
    let result = send(peer, 1, b"", &mut []);
    println!("deadlock: send returned {:?}, which should be impossible", result);
    1
}
