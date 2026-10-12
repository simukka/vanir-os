//! Measured boot: before any task runs, the kernel extends TPM PCR 12 with what it is about to
//! run, so a TPM quote proves it. In order:
//!
//! 1. SHA-256 of the kernel file;
//! 2. SHA-256 of the app manifest (the task table's source);
//! 3. for each task in table order, SHA-256 of its signed statement (the first 80 bytes of its
//!    `.sig`: program, version, image hash), or 32 zero bytes if its image was rejected.
//!
//! tools/expected-pcrs.py computes the same value from the build output alone.
//!
//! At run time (RFD 2, P6), each service image loaded into or unloaded from a slot is measured
//! into PCR 13, and recorded in the run-time log the kernel keeps for the verifier, so a quote
//! shows what runs now, not only what booted. Generic slots aren't measured at boot.
//!
//! The kernel shares the TPM with the attestation task, which sends it commands directly. The
//! TPM runs one command at a time, so the task takes a lock around its commands
//! (`tpm_lock`/`tpm_unlock`) and the kernel extends PCR 13 only while nobody holds it: a load
//! then fails with `BUSY` instead of waiting.

use spin::Mutex;

use crate::process::RUNTIME_LOG;
use crate::tpm;

pub const PCR: u32 = 12;
pub const RUNTIME_PCR: u32 = 13;
const MAX_ENTRIES: usize = 16;

/// The measurement log: what was extended into PCR 12, in order.
#[derive(Clone, Copy)]
pub struct Entry {
    pub what: &'static str,
    pub digest: [u8; 32],
}

static LOG: Mutex<[Option<Entry>; MAX_ENTRIES]> = Mutex::new([const { None }; MAX_ENTRIES]);

/// Copy of the measurement log.
pub fn log() -> [Option<Entry>; MAX_ENTRIES] {
    *LOG.lock()
}

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

/// Run-time log operations.
pub const LOAD: u8 = 1;
pub const UNLOAD: u8 = 2;

/// A run-time log entry, as the verifier replays it: PCR 13 is extended with its SHA-256.
///
/// ```text
///  0   1  operation: 1 load, 2 unload
///  1   1  slot (task table index; slot ids are index + 1)
///  2   6  zero
///  8  32  service name, zero padded
/// 40   8  version
/// 48  32  SHA-256 of the image's signed statement (which covers image and descriptor)
/// ```
pub const ENTRY_LEN: usize = 80;

struct Runtime {
    entries: [[u8; ENTRY_LEN]; RUNTIME_LOG],
    count: usize,
    /// The attestation task holds the TPM.
    held: bool,
}

static RUNTIME: Mutex<Runtime> = Mutex::new(Runtime { entries: [[0; ENTRY_LEN]; RUNTIME_LOG], count: 0, held: false });

/// Why a run-time measurement didn't happen. Nothing was recorded.
pub enum Refused {
    /// The attestation task holds the TPM, or the TPM failed the extend.
    Busy,
    /// The log is full.
    Full,
}

/// Measure a slot operation into PCR 13 and append it to the run-time log, or refuse.
pub fn runtime(op: u8, slot: usize, name: &[u8], version: u64, statement_hash: &[u8; 32]) -> Result<usize, Refused> {
    let mut log = RUNTIME.lock();
    if log.held {
        return Err(Refused::Busy);
    }
    if log.count == RUNTIME_LOG {
        return Err(Refused::Full);
    }
    let mut entry = [0u8; ENTRY_LEN];
    entry[0] = op;
    entry[1] = slot as u8;
    entry[8..8 + name.len().min(32)].copy_from_slice(&name[..name.len().min(32)]);
    entry[40..48].copy_from_slice(&version.to_le_bytes());
    entry[48..80].copy_from_slice(statement_hash);
    if tpm::present() {
        if let Err(code) = tpm::extend(RUNTIME_PCR, &tpm::sha256(&entry)) {
            println!("[kernel] tpm: extending PCR {} failed with {:#x}", RUNTIME_PCR, code);
            return Err(Refused::Busy);
        }
        match tpm::read(RUNTIME_PCR) {
            Ok(value) => println!("[kernel] tpm: PCR{} = {}", RUNTIME_PCR, Hex(&value)),
            Err(code) => println!("[kernel] tpm: reading PCR {} failed with {:#x}", RUNTIME_PCR, code),
        }
    }
    let n = log.count;
    log.entries[n] = entry;
    log.count += 1;
    println!(
        "[kernel] run-time log entry {}: {} {} version {} (task {})",
        n,
        if op == LOAD { "load" } else { "unload" },
        core::str::from_utf8(name).unwrap_or("?"),
        version,
        slot + 1
    );
    Ok(n)
}

/// Copy run-time log entries from `start` into `out` (whole entries). Returns (copied, total).
pub fn runtime_log(start: usize, out: &mut [u8]) -> (usize, usize) {
    let log = RUNTIME.lock();
    let n = (out.len() / ENTRY_LEN).min(log.count.saturating_sub(start));
    for i in 0..n {
        out[ENTRY_LEN * i..ENTRY_LEN * (i + 1)].copy_from_slice(&log.entries[start + i]);
    }
    (n, log.count)
}

/// The attestation task takes (true) or drops (false) the TPM. The kernel drops it for the
/// task when it dies.
pub fn hold_tpm(held: bool) {
    RUNTIME.lock().held = held;
}
