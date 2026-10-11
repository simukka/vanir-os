//! Test stand-in for a local key store, run as the task named "keys": serves the storage master
//! key to the task named "disk" (the kernel vouches for the name), and to no one else. The
//! storage task asks for it whenever it starts, so a restarted storage task unlocks again. The
//! real key comes from the host after attestation instead (user/attest).

#![no_std]
#![no_main]

use vanir_user::block::{CODE_NOT_ALLOWED, CODE_OK};
use vanir_user::keys::OP_MASTER_KEY;
use vanir_user::{err, println, recv, reply, task_name};

vanir_user::entry!(main);

#[cfg(not(feature = "wrong-key"))]
const KEY: [u8; 32] = *b"vanir-test-master-key-0123456789";
#[cfg(feature = "wrong-key")]
const KEY: [u8; 32] = *b"vanir-WRONG-master-key-012345678";

fn main() -> u64 {
    let mut msg = [0u8; 64];
    loop {
        let m = match recv(&mut msg) {
            Ok(m) => m,
            Err(e) => {
                println!("keys: recv failed: {}", err::name(e));
                continue;
            }
        };
        let mut name = [0u8; 64];
        if m.op == OP_MASTER_KEY && task_name(m.sender, &mut name) == Ok("disk") {
            let _ = reply(m.sender, CODE_OK, &KEY);
        } else {
            let _ = reply(m.sender, CODE_NOT_ALLOWED, &[]);
        }
    }
}
