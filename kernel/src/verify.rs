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
}

impl Rejection {
    pub fn describe(self) -> &'static str {
        match self {
            Rejection::NoImage => "no image",
            Rejection::NoSignature => "no signature",
            Rejection::Malformed => "malformed signature file",
            Rejection::BadSignature => "signature does not verify",
            Rejection::WrongProgram => "signed for another program",
            Rejection::WrongHash => "image does not match its signature",
            Rejection::TooOld => "version older than the manifest allows",
            Rejection::BadDescriptor => "malformed descriptor",
            Rejection::WrongDescriptor => "descriptor does not match its signature",
            Rejection::ClassMismatch => "descriptor asks for another slot class",
            Rejection::TooLarge => "image needs more memory than its slot class has",
            Rejection::BadElf => "not a loadable ELF image",
            Rejection::BelowFloor => "version below its min_version",
        }
    }
}

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

const DESC_MAGIC: &[u8; 8] = b"VNRDSC01";
/// A descriptor is exactly this long (tools/sign-image.py writes it).
pub const DESCRIPTOR_LEN: usize = 256;
const MAX_LISTEN: usize = 8;

/// What a service may do (RFD 2, P1), from its signed descriptor. Layout (little endian):
///
/// ```text
///   0   8  magic "VNRDSC01"
///   8  32  name, zero padded (the service)
///  40   8  version (must equal the signed version)
///  48   8  min_version: the oldest version that may still run
///  56  16  slot class, zero padded
///  72   4  drain deadline default, seconds
///  76   4  drain deadline maximum, seconds
///  80   4  listen entries in use (at most 8)
///  84   4  zero
///  88  64  8 listen entries: port, max_connections, max_per_source, 0 (u16 each)
/// 152 104  zero (reserved: RFD 3's storage fields)
/// ```
#[derive(Clone, Copy)]
pub struct Descriptor {
    name: [u8; 32],
    pub version: u64,
    pub min_version: u64,
    /// (port, max_connections, max_per_source); the first `listen_count` are in use.
    pub listen: [(u16, u16, u16); MAX_LISTEN],
    pub listen_count: usize,
    /// SHA-256 of the signed statement: what the run-time log records.
    pub statement_hash: [u8; 32],
}

impl Descriptor {
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name.iter().position(|&b| b == 0).unwrap_or(32)]
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A zero-padded name field: its bytes up to the first zero, which must all be printable with
/// only zeros after them.
fn padded_name(field: &[u8]) -> Option<&[u8]> {
    let len = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    let ok = len > 0 && field[..len].iter().all(|b| b.is_ascii_graphic()) && field[len..].iter().all(|&b| b == 0);
    ok.then_some(&field[..len])
}

fn parse_descriptor(d: &[u8]) -> Option<Descriptor> {
    if d.len() != DESCRIPTOR_LEN || &d[..8] != DESC_MAGIC || u32_at(d, 84) != 0 || d[152..].iter().any(|&b| b != 0) {
        return None;
    }
    padded_name(&d[8..40])?;
    padded_name(&d[56..72])?;
    let listen_count = u32_at(d, 80) as usize;
    if listen_count > MAX_LISTEN {
        return None;
    }
    let mut listen = [(0, 0, 0); MAX_LISTEN];
    for (i, entry) in listen.iter_mut().enumerate().take(listen_count) {
        let at = 88 + 8 * i;
        *entry = (u16_at(d, at), u16_at(d, at + 2), u16_at(d, at + 4));
        let (port, max, per_source) = *entry;
        if port == 0 || max == 0 || per_source == 0 || per_source > max || u16_at(d, at + 6) != 0 {
            return None;
        }
    }
    if (1..listen_count).any(|i| listen[..i].iter().any(|l| l.0 == listen[i].0)) {
        return None; // a port listed twice
    }
    if u32_at(d, 72) > u32_at(d, 76) {
        return None; // the drain deadline's default is above its maximum
    }
    Some(Descriptor {
        name: d[8..40].try_into().unwrap(),
        version: u64_at(d, 40),
        min_version: u64_at(d, 48),
        listen,
        listen_count,
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
    let version = u64_at(signed, 40);
    if d.name[..] != signed[8..40] || d.version != version {
        return Err(Rejection::BadDescriptor);
    }
    // The floor is the descriptor's min_version (RFD 2, P6; RFD 8 lists what that leaves open).
    if version < d.min_version {
        return Err(Rejection::BelowFloor);
    }
    if padded_name(&descriptor[56..72]) != Some(class.as_bytes()) {
        return Err(Rejection::ClassMismatch);
    }
    d.statement_hash = Sha256::digest(signed).into();
    Ok(d)
}
