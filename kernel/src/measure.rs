//! Measured boot: before any task runs, the kernel extends TPM PCR 12 with what it is about to
//! run, so a TPM quote proves it. In order:
//!
//! 1. SHA-256 of the kernel file;
//! 2. SHA-256 of the app manifest (the task table's source);
//! 3. for each task in table order, SHA-256 of its signed statement (the first 80 bytes of its
//!    `.sig`: program, version, image hash), or 32 zero bytes if its image was rejected.
//!
//! tools/expected-pcrs.py computes the same value from the build output alone.

use spin::Mutex;

use crate::tpm;

pub const PCR: u32 = 12;
const MAX_ENTRIES: usize = 16;

/// The measurement log: what was extended into PCR 12, in order.
#[allow(dead_code)] // read by the attestation task's syscall
pub struct Entry {
    pub what: &'static str,
    pub digest: [u8; 32],
}

static LOG: Mutex<[Option<Entry>; MAX_ENTRIES]> = Mutex::new([const { None }; MAX_ENTRIES]);

struct Hex<'a>(&'a [u8]);

impl core::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{:02x}", b))
    }
}

/// Measure the boot. `tasks` holds each task's name and signed statement (None if rejected).
pub fn boot(kernel: &[u8], manifest: &str, tasks: &[(&'static str, Option<&[u8]>)]) {
    if !tpm::init() {
        println!("[kernel] tpm: none found; the boot is not measured");
        return;
    }
    let mut log = LOG.lock();
    let mut n = 0;
    let mut measure = |what: &'static str, digest: [u8; 32]| {
        if let Err(code) = tpm::extend(PCR, &digest) {
            panic!("tpm: extending PCR {PCR} failed with {code:#x}");
        }
        println!("[kernel] tpm: measured {:<14} {}", what, Hex(&digest));
        log[n] = Some(Entry { what, digest });
        n += 1;
    };
    measure("kernel", tpm::sha256(kernel));
    measure("manifest", tpm::sha256(manifest.as_bytes()));
    for (name, statement) in tasks {
        measure(name, statement.map_or([0; 32], tpm::sha256));
    }
    match tpm::read(PCR) {
        Ok(value) => println!("[kernel] tpm: PCR{} = {}", PCR, Hex(&value)),
        Err(code) => println!("[kernel] tpm: reading PCR {} failed with {:#x}", PCR, code),
    }
}
