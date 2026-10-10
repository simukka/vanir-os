//! Attestation: on request, quote PCRs 0, 4, 7 and 12 over the requester's nonce with the TPM's
//! attestation key, and reply with one JSON line the host can verify (tools/verify-quote.py):
//! the signed TPMS_ATTEST, the ECDSA signature, the key, the PCR values, and the kernel's
//! measurement log for PCR 12.
//!
//! Key release: at start the task makes an X25519 key pair from TPM randomness and quotes over
//! SHA-256(nonce || public key), so a verifier knows the key belongs to the attested system. The
//! host then seals the storage master key to it (X25519, HKDF-SHA256 salted with the nonce,
//! ChaCha20-Poly1305); OP_UNWRAP opens it here and hands it to the storage task. The master key
//! is never sent in the clear, and the private key never leaves this task.

#![no_std]
#![no_main]

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use core::fmt::{self, Write};
use ed25519_compact::x25519;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tpm2::{AttestationKey, Tpm};
use vanir_user::attest::{OP_QUOTE, OP_UNWRAP};
use vanir_user::block::{self, code_name};
use vanir_user::{err, lookup, measurements, println, recv, reply};

vanir_user::entry!(main);

const PCRS: [u32; 4] = [0, 4, 7, 12];

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{:02x}", b))
    }
}

/// A JSON line built in place.
struct Line {
    buf: [u8; 4096],
    len: usize,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let b = s.as_bytes();
        let end = self.len + b.len();
        if end > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(b);
        self.len = end;
        Ok(())
    }
}

fn quote(
    tpm: &Tpm,
    key: &AttestationKey,
    kx_public: &[u8; 32],
    log: &[u8],
    entries: usize,
    nonce: &[u8],
    out: &mut Line,
) -> Result<(), tpm2::Error> {
    // Binding the key-exchange public key into the quote.
    let qualifying: [u8; 32] = Sha256::new().chain_update(nonce).chain_update(kx_public).finalize().into();
    let mut buf = [0u8; tpm2::BUF];
    let q = tpm.quote(&mut buf, key, &qualifying, &PCRS)?;
    let _ = write!(
        out,
        "{{\"event\":\"quote\",\"nonce\":\"{}\",\"kx_pub\":\"{}\",\"attest\":\"{}\",\"sig_r\":\"{}\",\"sig_s\":\"{}\",\"ak_x\":\"{}\",\"ak_y\":\"{}\",\"pcrs\":{{",
        Hex(nonce),
        Hex(kx_public),
        Hex(q.attest),
        Hex(q.r),
        Hex(q.s),
        Hex(&key.x),
        Hex(&key.y)
    );
    for (i, &pcr) in PCRS.iter().enumerate() {
        let value = tpm.pcr_read(pcr)?;
        let _ = write!(out, "{}\"{}\":\"{}\"", if i == 0 { "" } else { "," }, pcr, Hex(&value));
    }
    let _ = out.write_str("},\"log\":[");
    for i in 0..entries {
        let entry = &log[48 * i..48 * (i + 1)];
        let name_len = entry[..16].iter().position(|&b| b == 0).unwrap_or(16);
        let name = core::str::from_utf8(&entry[..name_len]).unwrap_or("?");
        let _ = write!(out, "{}{{\"what\":\"{}\",\"digest\":\"{}\"}}", if i == 0 { "" } else { "," }, name, Hex(&entry[16..]));
    }
    let _ = out.write_str("]}\n");
    Ok(())
}

/// Open the master key the host sealed to our key-exchange key (host public key, then
/// ciphertext and tag) and give it to the storage task. Returns a reply code (0 = unlocked).
fn unwrap_and_unlock(secret: &x25519::SecretKey, nonce: &[u8], sealed: &[u8]) -> u64 {
    let Ok(host) = x25519::PublicKey::from_slice(&sealed[..32]) else { return 2 };
    let Ok(shared) = host.dh(secret) else { return 2 };
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(nonce), &*shared).expand(b"vanir key release", &mut key).unwrap();
    let mut master: [u8; 32] = sealed[32..64].try_into().unwrap();
    let tag = Tag::try_from(&sealed[64..80]).unwrap();
    let opened = ChaCha20Poly1305::new(&key.into()).decrypt_inout_detached(&Nonce::default(), nonce, master.as_mut_slice().into(), &tag);
    if opened.is_err() {
        println!("attest: the sealed key does not open");
        return 3;
    }
    let Ok(storage) = lookup("disk") else { return 4 };
    match block::unlock(storage, &master) {
        Ok(()) => {
            println!("attest: storage unlocked with the released key");
            0
        }
        Err(e) => {
            println!("attest: unlock failed: {}", code_name(e));
            5
        }
    }
}

fn main() -> u64 {
    let mut log = [0u8; 48 * 16];
    let (entries, base) = match measurements(&mut log) {
        Ok(m) => m,
        Err(e) => {
            println!("attest: no TPM: {}", err::name(e));
            return 1;
        }
    };
    let tpm = Tpm::new(base);
    let key = match tpm.create_attestation_key() {
        Ok(k) => k,
        Err(e) => {
            println!("attest: cannot create the attestation key: {:?}", e);
            return 1;
        }
    };
    println!("attest: attestation key ready (P-256, x {}...)", Hex(&key.x[..8]));
    let mut seed = [0u8; 32];
    if let Err(e) = tpm.get_random(&mut seed) {
        println!("attest: no randomness from the TPM: {:?}", e);
        return 1;
    }
    let kx_secret = x25519::SecretKey::new(seed);
    let kx_public: [u8; 32] = *kx_secret.recover_public_key().expect("valid scalar");
    // The nonce of the last quote: key release is bound to it.
    let mut last_nonce = [0u8; 32];
    let mut last_nonce_len = None;

    let mut msg = [0u8; 128];
    loop {
        let m = match recv(&mut msg) {
            Ok(m) => m,
            Err(e) => {
                println!("attest: recv failed: {}", err::name(e));
                continue;
            }
        };
        if m.op == OP_UNWRAP {
            let code = match last_nonce_len {
                Some(n) if m.len == 80 => unwrap_and_unlock(&kx_secret, &last_nonce[..n], &msg[..80]),
                _ => 1,
            };
            let _ = reply(m.sender, code, &[]);
            continue;
        }
        if m.op != OP_QUOTE || m.len > 32 {
            let _ = reply(m.sender, 1, &[]);
            continue;
        }
        let mut line = Line { buf: [0; 4096], len: 0 };
        match quote(&tpm, &key, &kx_public, &log, entries, &msg[..m.len], &mut line) {
            Ok(()) => {
                last_nonce[..m.len].copy_from_slice(&msg[..m.len]);
                last_nonce_len = Some(m.len);
                let _ = reply(m.sender, 0, &line.buf[..line.len]);
            }
            Err(e) => {
                println!("attest: quote failed: {:?}", e);
                let _ = reply(m.sender, 2, &[]);
            }
        }
    }
}
