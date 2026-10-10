//! Test stand-in for key release: hands the storage task a fixed master key. The real key comes
//! from the host after attestation (F4). Runs as the task named "keys".

#![no_std]
#![no_main]

use vanir_user::block::{self, code_name};
use vanir_user::{lookup, println};

vanir_user::entry!(main);

#[cfg(not(feature = "wrong-key"))]
const KEY: [u8; 32] = *b"vanir-test-master-key-0123456789";
#[cfg(feature = "wrong-key")]
const KEY: [u8; 32] = *b"vanir-WRONG-master-key-012345678";

fn main() -> u64 {
    let storage = lookup("disk").expect("no disk task");
    match block::unlock(storage, &KEY) {
        Ok(()) => 0,
        Err(e) => {
            println!("unlocker: unlock failed: {}", code_name(e));
            1
        }
    }
}
