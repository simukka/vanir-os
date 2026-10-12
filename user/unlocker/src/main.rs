//! Test stand-in for a local key store, run as the task named "keys": serves the storage master
//! key, and each service's volume key (RFD 3, P2), to the task named "disk" (the kernel vouches
//! for the name), and to no one else. The storage task asks for the master key whenever it
//! starts, so a restarted storage task unlocks again, and for a service's key when it needs it.
//! The real keys come from the host after attestation instead (user/attest): the master key from
//! the host that released it, service keys from the control plane.
//!
//! A service's test key is HKDF-SHA256 of a fixed seed and the service's name.

#![no_std]
#![no_main]

use hkdf::Hkdf;
use sha2::Sha256;
use vanir_user::block::{CODE_NOT_ALLOWED, CODE_OK};
use vanir_user::keys::{OP_MASTER_KEY, OP_SERVICE_KEY};
use vanir_user::{err, println, recv, reply, task_name};

vanir_user::entry!(main);

#[cfg(not(feature = "wrong-key"))]
const KEY: [u8; 32] = *b"vanir-test-master-key-0123456789";
#[cfg(feature = "wrong-key")]
const KEY: [u8; 32] = *b"vanir-WRONG-master-key-012345678";

/// The seed service keys are made from.
#[cfg(not(feature = "wrong-key"))]
const SERVICE_SEED: &[u8] = b"vanir-test-service-seed";
#[cfg(feature = "wrong-key")]
const SERVICE_SEED: &[u8] = b"vanir-WRONG-service-seed";

fn service_key(name: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, SERVICE_SEED).expand(name, &mut key).expect("32 bytes is a valid HKDF output length");
    key
}

fn main() -> u64 {
    let mut msg = [0u8; 64];
    // Refusals printed (only the first: storage asks again on every request until it has one).
    let mut refused = 0u32;
    // `service-keys-once`: the services whose keys were handed over.
    #[cfg(feature = "service-keys-once")]
    let mut given = [[0u8; 32]; 8];
    loop {
        let m = match recv(&mut msg) {
            Ok(m) => m,
            Err(e) => {
                println!("keys: recv failed: {}", err::name(e));
                continue;
            }
        };
        let mut name = [0u8; 64];
        if task_name(m.sender, &mut name) != Ok("disk") {
            let _ = reply(m.sender, CODE_NOT_ALLOWED, &[]);
            continue;
        }
        match m.op {
            OP_MASTER_KEY => drop(reply(m.sender, CODE_OK, &KEY)),
            OP_SERVICE_KEY if m.len <= 32 => {
                let service = &msg[..m.len];
                let shown = core::str::from_utf8(service).unwrap_or("?");
                if cfg!(feature = "no-service-keys") {
                    refused += 1;
                    if refused == 1 {
                        println!("keys: no key for service {}", shown);
                    }
                    let _ = reply(m.sender, CODE_NOT_ALLOWED, &[]);
                    continue;
                }
                #[cfg(feature = "service-keys-once")]
                {
                    let padded = vanir_user::block::service_name(service);
                    if given.contains(&padded) {
                        refused += 1;
                        if refused == 1 {
                            println!("keys: {}'s key was handed over already", shown);
                        }
                        let _ = reply(m.sender, CODE_NOT_ALLOWED, &[]);
                        continue;
                    }
                    if let Some(free) = given.iter_mut().find(|g| g[0] == 0) {
                        *free = padded;
                    }
                }
                println!("keys: key for service {}", shown);
                let _ = reply(m.sender, CODE_OK, &service_key(service));
            }
            _ => drop(reply(m.sender, CODE_NOT_ALLOWED, &[])),
        }
    }
}
