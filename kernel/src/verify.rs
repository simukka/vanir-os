//! Task image signatures. Each program ships with `<program>.sig` (made by tools/sign-image.py):
//! a statement "program P, version V, SHA-256 H", signed with Ed25519. The public key is
//! compiled into the kernel, so only images signed with the matching private key run.

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
