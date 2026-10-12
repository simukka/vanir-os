//! The node agent (RFD 2, P7): the only task that loads service images into slots.
//!
//! Until there is a control plane to talk to, test scripts (features, see Cargo.toml) stand in
//! for it, carrying the signed slot images they load. Without a script the agent waits.

#![no_std]
#![no_main]

#[cfg(feature = "test-images")]
mod images;

use vanir_user::{err, events, lookup, println, recv, slot};

vanir_user::entry!(main);

/// A signed service image: the ELF, its descriptor and its signature file.
#[derive(Clone, Copy)]
pub struct Image {
    pub name: &'static str,
    pub elf: &'static [u8],
    pub descriptor: &'static [u8],
    pub sig: &'static [u8],
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
    println!("agent: no control plane yet; waiting");
    let mut buf = [0u8; 64];
    loop {
        let _ = recv(&mut buf);
    }
}
