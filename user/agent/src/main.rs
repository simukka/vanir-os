//! The node agent (RFD 2, P7): the only task that loads service images into slots.
//!
//! It dials the control plane, keeps the slots in the state the control plane wants, and reports
//! what it has (`control`); the lifecycle of each instance is in `lifecycle`. Test scripts
//! (features, see Cargo.toml) carrying signed slot images can stand in for the control plane.

#![no_std]
#![no_main]

mod control;
#[cfg(feature = "test-images")]
mod images;
mod lifecycle;

use vanir_user::{err, events, lookup, println, slot};

vanir_user::entry!(main);

/// A signed service image: the ELF, its descriptor and its signature file.
#[derive(Clone, Copy)]
pub struct Image {
    pub name: &'static str,
    pub elf: &'static [u8],
    pub descriptor: &'static [u8],
    pub sig: &'static [u8],
}

impl Image {
    /// The service it is an instance of, from its descriptor.
    pub fn service(&self) -> &'static [u8] {
        let name = &self.descriptor[8..40];
        &name[..name.iter().position(|&b| b == 0).unwrap_or(32)]
    }

    pub fn version(&self) -> u64 {
        u64::from_le_bytes(self.descriptor[40..48].try_into().unwrap())
    }

    /// SHA-256 of its signed statement: how the control plane names an image.
    pub fn hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(&self.sig[..self.sig.len().min(112)]).into()
    }

    /// The drain deadline's default and maximum, in seconds.
    pub fn drain_secs(&self) -> (u64, u64) {
        let at = |i: usize| u32::from_le_bytes(self.descriptor[i..i + 4].try_into().unwrap()) as u64;
        (at(72), at(76))
    }
}

/// The id of slot `name` (e.g. "small-0").
fn slot_id(name: &str) -> u64 {
    lookup(name).unwrap_or_else(|_| panic!("agent: no slot named {name}"))
}

/// Stage `image` into slot `name` and load it. Returns the slot's new id, or the error and
/// rejection reason.
#[allow(dead_code)]
fn load(name: &str, image: &Image) -> Result<u64, (u64, u64)> {
    let slot = slot_id(name);
    slot::stage_all(slot, image.elf).map_err(|e| (e, 0))?;
    slot::load(slot, image.sig, image.descriptor)
}

/// `load`, reporting the outcome.
#[allow(dead_code)]
fn load_and_report(name: &str, image: &Image) -> Result<u64, (u64, u64)> {
    let result = load(name, image);
    match result {
        Ok(id) => println!("agent: loaded {} into {} (id {:#x})", image.name, name, id),
        Err((err::REJECTED, why)) => println!("agent: {} into {}: REJECTED ({})", image.name, name, events::rejection(why)),
        Err((e, _)) => println!("agent: {} into {}: {}", image.name, name, err::name(e)),
    }
    result
}

/// Empty slot `name` once its service has ended, retrying while it still runs. Returns the
/// error that stopped it, if not one of those.
#[allow(dead_code)]
fn unload_when_done(name: &str) -> Result<(), u64> {
    let slot = slot_id(name);
    loop {
        match slot::unload(slot) {
            Ok(()) => return Ok(()),
            Err(err::BAD_ARGUMENT) => vanir_user::sleep(1), // still running
            Err(e) => return Err(e),
        }
    }
}

fn main() -> u64 {
    #[cfg(feature = "test-images")]
    if let Some(code) = images::script() {
        return code;
    }
    let mut agent = lifecycle::Agent::new();
    let mut control = control::Control::new();
    loop {
        control.turn(&mut agent);
        // Test only: end the run when the control plane says so, once nothing is under way.
        #[cfg(feature = "exit-on-end")]
        if control.end && agent.idle() {
            control.turn(&mut agent); // a last report
            println!("agent: the control plane says the test is over");
            return 0;
        }
        // Test only: end the run after failing to connect three times in a row.
        #[cfg(feature = "exit-after-failures")]
        if control.failures >= 3 {
            println!("agent: no control plane after {} attempts", control.failures);
            return 0;
        }
    }
}
