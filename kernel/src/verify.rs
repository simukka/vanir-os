//! Task image signatures. Each program ships with `<program>.sig` (made by tools/sign-image.py):
//! a statement "program P, version V, SHA-256 H", signed with Ed25519. The public key is
//! compiled into the kernel, so only images signed with the matching private key run.
//!
//! Service images loaded into generic slots at run time (RFD 2, P1/P2) come with a descriptor
//! (`<name>.desc`, what the service may do) and a `VNRSIG02` statement that covers both: name,
//! version, SHA-256 of the image, SHA-256 of the descriptor. Same key.

use ed25519_compact::{PublicKey, Signature};
use sha2::{Digest, Sha256};

static SIGNING_KEY: &[u8; 32] = include_bytes!(env!("VANIR_SIGNING_PUB"));

const MAGIC: &[u8; 8] = b"VNRSIG01";
const SIGNED_LEN: usize = 80;
const SIG_FILE_LEN: usize = SIGNED_LEN + 64;

/// Why an image was refused (reported in events and to the supervisor as a number).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    NoImage = 1,
    NoSignature = 2,
    Malformed = 3,
    BadSignature = 4,
    WrongProgram = 5,
    WrongHash = 6,
    TooOld = 7,
    /// Run-time loads (`check_slot`) only, from here on.
    BadDescriptor = 8,
    WrongDescriptor = 9,
    ClassMismatch = 10,
    TooLarge = 11,
    BadElf = 12,
    BelowFloor = 13,
    /// Built for an ABI this kernel doesn't serve (RFD 9, P2).
    Abi = 14,
}

impl Rejection {
    pub fn describe(self) -> &'static str {
        vanir_abi::events::rejection(self as u64)
    }
}

// The reasons user code sees (`vanir_abi::events::REJECT_*`) are these numbers.
const _: () = {
    use vanir_abi::events::*;
    assert!(Rejection::NoImage as u64 == REJECT_NO_IMAGE);
    assert!(Rejection::NoSignature as u64 == REJECT_NO_SIGNATURE);
    assert!(Rejection::Malformed as u64 == REJECT_MALFORMED);
    assert!(Rejection::BadSignature as u64 == REJECT_BAD_SIGNATURE);
    assert!(Rejection::WrongProgram as u64 == REJECT_WRONG_PROGRAM);
    assert!(Rejection::WrongHash as u64 == REJECT_WRONG_HASH);
    assert!(Rejection::TooOld as u64 == REJECT_TOO_OLD);
    assert!(Rejection::BadDescriptor as u64 == REJECT_BAD_DESCRIPTOR);
    assert!(Rejection::WrongDescriptor as u64 == REJECT_WRONG_DESCRIPTOR);
    assert!(Rejection::ClassMismatch as u64 == REJECT_CLASS_MISMATCH);
    assert!(Rejection::TooLarge as u64 == REJECT_TOO_LARGE);
    assert!(Rejection::BadElf as u64 == REJECT_BAD_ELF);
    assert!(Rejection::BelowFloor as u64 == REJECT_BELOW_FLOOR);
    assert!(Rejection::Abi as u64 == REJECT_ABI);
};

/// Check `image` against signature file `sig` for `program`. Returns the signed version and the
/// signed statement (program, version, hash: what gets measured into the TPM).
pub fn check(
    program: &str,
    image: Option<&[u8]>,
    sig: Option<&'static [u8]>,
    min_version: u64,
) -> Result<(u64, &'static [u8]), Rejection> {
    let image = image.ok_or(Rejection::NoImage)?;
    let sig = sig.ok_or(Rejection::NoSignature)?;
    if sig.len() != SIG_FILE_LEN || &sig[..8] != MAGIC {
        return Err(Rejection::Malformed);
    }
    let (signed, signature) = sig.split_at(SIGNED_LEN);
    let key = PublicKey::from_slice(SIGNING_KEY).map_err(|_| Rejection::BadSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Rejection::Malformed)?;
    key.verify(signed, &signature).map_err(|_| Rejection::BadSignature)?;

    // The statement is authentic; now check it is about this image, for this task.
    let name = &signed[8..40];
    let name_len = name.iter().position(|&b| b == 0).unwrap_or(32);
    if &name[..name_len] != program.as_bytes() {
        return Err(Rejection::WrongProgram);
    }
    let hash: [u8; 32] = Sha256::digest(image).into();
    if signed[48..80] != hash {
        return Err(Rejection::WrongHash);
    }
    let version = u64::from_le_bytes(signed[40..48].try_into().unwrap());
    if version < min_version {
        return Err(Rejection::TooOld);
    }
    Ok((version, signed))
}

const MAGIC_V2: &[u8; 8] = b"VNRSIG02";
/// magic, name (32), version (8), image SHA-256, descriptor SHA-256.
pub const SIGNED_LEN_V2: usize = 112;
pub const SIG_FILE_LEN_V2: usize = SIGNED_LEN_V2 + 64;

use vanir_abi::descriptor as desc;

/// The longest descriptor `slot_load` takes.
pub const DESCRIPTOR_MAX: usize = desc::LEN_V2;
/// The largest volume a descriptor may declare: 256 MiB.
const MAX_VOLUME_BLOCKS: u64 = 65536;

/// What a service may do (RFD 2, P1), from its signed descriptor: format 1 or 2, laid out as
/// `vanir_abi::descriptor` says.
#[derive(Clone, Copy)]
pub struct Descriptor {
    name: [u8; 32],
    pub version: u64,
    pub min_version: u64,
    /// (port, max_connections, max_per_source); the first `listen_count` are in use.
    pub listen: [(u16, u16, u16); desc::MAX_LISTEN],
    pub listen_count: usize,
    /// Data blocks of the service's volume (RFD 3, P1); 0 if it has none.
    pub volume_blocks: u64,
    /// The ABI version the image was built against (RFD 9, P2); 1.0 for format 1.
    pub abi: (u32, u32),
    /// Settings (RFD 9, P5): key (zero padded) and value; the first `settings_count` are in use.
    #[allow(dead_code)] // task_listen hands them to the instance (R2c)
    pub settings: [([u8; desc::KEY_LEN], u64); desc::MAX_SETTINGS],
    #[allow(dead_code)]
    pub settings_count: usize,
    /// SHA-256 of the signed statement: what the run-time log records.
    pub statement_hash: [u8; 32],
}

impl Descriptor {
    pub fn name(&self) -> &[u8] {
        desc::padded(&self.name)
    }
}

/// A zero-padded name field: its bytes up to the first zero, which must all be printable with
/// only zeros after them.
fn padded_name(field: &[u8]) -> Option<&[u8]> {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let ok = len > 0 && field[..len].iter().all(|b| b.is_ascii_graphic()) && field[len..].iter().all(|&b| b == 0);
    ok.then_some(&field[..len])
}

fn parse_descriptor(d: &[u8]) -> Option<Descriptor> {
    let format = desc::format(d)?;
    let reserved = if format == 1 { desc::AT_RESERVED_V1 } else { desc::AT_RESERVED_V2 };
    if desc::u32_at(d, desc::AT_LISTEN_COUNT + 4) != 0 || d[reserved..].iter().any(|&b| b != 0) {
        return None;
    }
    padded_name(&d[desc::AT_NAME..desc::AT_NAME + desc::NAME_LEN])?;
    padded_name(&d[desc::AT_SLOT_CLASS..desc::AT_SLOT_CLASS + desc::SLOT_CLASS_LEN])?;
    let listen_count = desc::listen_count(d);
    if listen_count > desc::MAX_LISTEN {
        return None;
    }
    let mut listen = [(0, 0, 0); desc::MAX_LISTEN];
    for (i, entry) in listen.iter_mut().enumerate().take(listen_count) {
        let (port, max, per_source, zero) = desc::listen(d, i);
        if port == 0 || max == 0 || per_source == 0 || per_source > max || zero != 0 {
            return None;
        }
        *entry = (port, max, per_source);
    }
    if (1..listen_count).any(|i| listen[..i].iter().any(|l| l.0 == listen[i].0)) {
        return None; // a port listed twice
    }
    let (drain_default, drain_max) = desc::drain_secs(d);
    if drain_default > drain_max {
        return None; // the drain deadline's default is above its maximum
    }
    let volume_blocks = desc::volume_blocks(d);
    if volume_blocks > MAX_VOLUME_BLOCKS {
        return None;
    }
    // Settings (format 2): valid keys, each once; the unused entries all zero.
    let settings_count = desc::settings_count(d);
    let mut settings = [([0; desc::KEY_LEN], 0); desc::MAX_SETTINGS];
    if format == 2 {
        if settings_count > desc::MAX_SETTINGS {
            return None;
        }
        for (i, s) in settings.iter_mut().enumerate() {
            *s = desc::setting(d, i);
            let used = i < settings_count;
            if used != desc::valid_key(&s.0) || (!used && s.1 != 0) {
                return None;
            }
        }
        if (1..settings_count).any(|i| settings[..i].iter().any(|s| s.0 == settings[i].0)) {
            return None; // a key given twice
        }
    }
    Some(Descriptor {
        name: d[desc::AT_NAME..desc::AT_NAME + desc::NAME_LEN].try_into().unwrap(),
        version: desc::version(d),
        min_version: desc::min_version(d),
        listen,
        listen_count,
        volume_blocks,
        abi: desc::abi(d),
        settings,
        settings_count,
        statement_hash: [0; 32],
    })
}

/// Check a service image staged into a slot of class `class`, with its signature file and
/// descriptor (RFD 2, P2, steps 1 to 3). Returns the descriptor.
pub fn check_slot(image: &[u8], sig: &[u8], descriptor: &[u8], class: &str) -> Result<Descriptor, Rejection> {
    if image.is_empty() {
        return Err(Rejection::NoImage);
    }
    if sig.is_empty() {
        return Err(Rejection::NoSignature);
    }
    if sig.len() != SIG_FILE_LEN_V2 || &sig[..8] != MAGIC_V2 {
        return Err(Rejection::Malformed);
    }
    let (signed, signature) = sig.split_at(SIGNED_LEN_V2);
    let key = PublicKey::from_slice(SIGNING_KEY).map_err(|_| Rejection::BadSignature)?;
    let signature = Signature::from_slice(signature).map_err(|_| Rejection::Malformed)?;
    key.verify(signed, &signature).map_err(|_| Rejection::BadSignature)?;

    // The statement is authentic; now check it is about this image and this descriptor.
    let hash: [u8; 32] = Sha256::digest(image).into();
    if signed[48..80] != hash {
        return Err(Rejection::WrongHash);
    }
    let desc_hash: [u8; 32] = Sha256::digest(descriptor).into();
    if signed[80..112] != desc_hash {
        return Err(Rejection::WrongDescriptor);
    }
    let mut d = parse_descriptor(descriptor).ok_or(Rejection::BadDescriptor)?;
    let version = desc::u64_at(signed, 40);
    if d.name[..] != signed[8..40] || d.version != version {
        return Err(Rejection::BadDescriptor);
    }
    // The floor is the descriptor's min_version (RFD 2, P6; RFD 8 lists what that leaves open).
    if version < d.min_version {
        return Err(Rejection::BelowFloor);
    }
    if padded_name(&descriptor[desc::AT_SLOT_CLASS..desc::AT_SLOT_CLASS + desc::SLOT_CLASS_LEN]) != Some(class.as_bytes()) {
        return Err(Rejection::ClassMismatch);
    }
    // Built for this ABI (RFD 9, P2): the same major version, and no newer minor.
    if d.abi.0 != vanir_abi::ABI_MAJOR || d.abi.1 > vanir_abi::ABI_MINOR {
        return Err(Rejection::Abi);
    }
    d.statement_hash = Sha256::digest(signed).into();
    Ok(d)
}
