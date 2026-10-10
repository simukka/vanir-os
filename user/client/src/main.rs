//! IPC client for the `echo` server. By default: 100 round trips with a varying message, each
//! reply checked byte for byte, plus an oversized message that must be refused. Features turn it
//! into one of the IPC error tests instead.

#![no_std]
#![no_main]

use vanir_user::err::{self, name};
use vanir_user::{lookup, println, rdtsc, send};

vanir_user::entry!(main);

const OP_ECHO: u64 = 1;
#[allow(dead_code)]
const OP_CRASH: u64 = 2;

fn main() -> u64 {
    let echo = lookup("echo").expect("no echo task");

    #[cfg(feature = "bad-buffer")]
    {
        let unmapped = unsafe { core::slice::from_raw_parts(0x1000_0000 as *const u8, 16) };
        let result = send(echo, OP_ECHO, unmapped, &mut [0u8; 16]);
        println!("client: send from an unmapped buffer: {}", name(result.err().unwrap_or(0)));
        if result != Err(err::BAD_BUFFER) {
            return 1;
        }
        // The server must be unaffected.
        let mut reply = [0u8; 4];
        return match send(echo, OP_ECHO, b"ping", &mut reply) {
            Ok((0, 4)) if &reply == b"ping" => {
                println!("client: echo still serving");
                0
            }
            _ => 1,
        };
    }

    #[cfg(feature = "not-allowed")]
    {
        let other = lookup("spinner").expect("no spinner task");
        let result = send(other, OP_ECHO, b"hi", &mut []);
        println!("client: send to a task not in `sends`: {}", name(result.err().unwrap_or(0)));
        return if result == Err(err::NOT_ALLOWED) { 0 } else { 1 };
    }

    #[cfg(feature = "crash-server")]
    {
        let result = send(echo, OP_CRASH, b"", &mut []);
        println!("client: server died while we waited: {}", name(result.err().unwrap_or(0)));
        if result != Err(err::DEAD) {
            return 1;
        }
        // A dead server stays dead to its old id.
        let again = send(echo, OP_ECHO, b"", &mut []);
        println!("client: sending to it again: {}", name(again.err().unwrap_or(0)));
        return if again == Err(err::DEAD) { 0 } else { 1 };
    }

    #[cfg(feature = "stale-id")]
    {
        // Kill echo, wait for the supervisor to restart it, then try the id from before.
        let old = echo;
        let result = send(old, OP_CRASH, b"", &mut []);
        println!("client: echo died: {}", name(result.err().unwrap_or(0)));
        let new = loop {
            match lookup("echo") {
                Ok(id) if id != old => break id,
                _ => vanir_user::yield_now(),
            }
        };
        println!("client: echo is back with id {:#x} (was {:#x})", new, old);
        let stale = send(old, OP_ECHO, b"hi", &mut [0u8; 2]);
        println!("client: send to the old id: {}", name(stale.err().unwrap_or(0)));
        let mut reply = [0u8; 2];
        let fresh = send(new, OP_ECHO, b"hi", &mut reply);
        let fresh_ok = fresh == Ok((0, 2)) && &reply == b"hi";
        println!("client: send to the new id: {}", if fresh_ok { "ok" } else { "FAILED" });
        return if stale == Err(err::DEAD) && fresh_ok { 0 } else { 1 };
    }

    #[allow(unreachable_code)]
    {
        let mut msg = [0u8; 256];
        let mut reply = [0u8; 256];
        let start = rdtsc();
        for round in 0..100u32 {
            let len = 1 + (round as usize * 7) % msg.len();
            for (i, b) in msg[..len].iter_mut().enumerate() {
                *b = (round as usize + i) as u8;
            }
            match send(echo, OP_ECHO, &msg[..len], &mut reply) {
                Ok((0, n)) if n == len && reply[..n] == msg[..len] => {}
                other => {
                    println!("client: round {} wrong reply: {:?}", round, other.map(|(c, n)| (c, n)).map_err(name));
                    return 1;
                }
            }
        }
        let cycles = rdtsc() - start;
        println!("client: 100 round trips ok ({} cycles each)", cycles / 100);

        let big = [0u8; 4097];
        let result = send(echo, OP_ECHO, &big, &mut reply);
        println!("client: 4097-byte message: {}", name(result.err().unwrap_or(0)));
        if result != Err(err::TOO_LONG) {
            return 1;
        }
        0
    }
}
