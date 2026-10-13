//! Noise `IK_25519_ChaChaPoly_SHA256` (<https://noiseprotocol.org/noise.html>), both sides and
//! transport messages, with no heap: the node agent dials the control plane, whose static key it
//! already knows (RFD 2, P7), and answers another node's agent that dials it to fetch a volume
//! (RFD 3, P5).
//!
//! ```text
//!   IK:
//!     <- s
//!     ...
//!     -> e, es, s, ss
//!     <- e, ee, se
//! ```
//!
//! No rekeying: a connection lasts until either side drops it, and a new one handshakes again.

#![no_std]

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use ed25519_compact::x25519::{PublicKey, SecretKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub const PROTOCOL: &[u8] = b"Noise_IK_25519_ChaChaPoly_SHA256";
pub const DH_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
/// Largest Noise message.
pub const MAX_MESSAGE: usize = 65535;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// A buffer is too small for the message.
    TooLong,
    /// A message doesn't decrypt: the wrong key, or it was changed.
    Decrypt,
    /// A public key is invalid (low order).
    BadKey,
    /// The nonce counter ran out.
    Exhausted,
}

/// The Noise HKDF, two outputs from a chaining key and input key material: RFC 5869 extract
/// with the chaining key as salt, then expand with empty info.
fn hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(ck), ikm).expand(&[], &mut okm).expect("64 bytes is a valid length");
    (okm[..32].try_into().unwrap(), okm[32..].try_into().unwrap())
}

/// Encrypts or decrypts with a key and a counter nonce.
#[derive(Clone)]
pub struct CipherState {
    key: Option<[u8; 32]>,
    n: u64,
}

impl CipherState {
    fn new() -> CipherState {
        CipherState { key: None, n: 0 }
    }

    fn keyed(key: [u8; 32]) -> CipherState {
        CipherState { key: Some(key), n: 0 }
    }

    fn nonce(&self) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&self.n.to_le_bytes());
        n.into()
    }

    /// Encrypt `buf[..len]` in place and append the tag; returns the new length.
    pub fn encrypt(&mut self, ad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let Some(key) = self.key else { return Ok(len) };
        if len + TAG_LEN > buf.len() {
            return Err(Error::TooLong);
        }
        if self.n == u64::MAX {
            return Err(Error::Exhausted);
        }
        let tag = ChaCha20Poly1305::new(&key.into())
            .encrypt_inout_detached(&self.nonce(), ad, (&mut buf[..len]).into())
            .map_err(|_| Error::TooLong)?;
        buf[len..len + TAG_LEN].copy_from_slice(&tag);
        self.n += 1;
        Ok(len + TAG_LEN)
    }

    /// Decrypt `buf[..len]` (ciphertext and tag) in place; returns the plaintext length.
    pub fn decrypt(&mut self, ad: &[u8], buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let Some(key) = self.key else { return Ok(len) };
        if len < TAG_LEN {
            return Err(Error::Decrypt);
        }
        if self.n == u64::MAX {
            return Err(Error::Exhausted);
        }
        let (body, tag) = buf[..len].split_at_mut(len - TAG_LEN);
        let tag = Tag::try_from(&*tag).map_err(|_| Error::Decrypt)?;
        ChaCha20Poly1305::new(&key.into())
            .decrypt_inout_detached(&self.nonce(), ad, body.into(), &tag)
            .map_err(|_| Error::Decrypt)?;
        self.n += 1;
        Ok(len - TAG_LEN)
    }
}

struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn new() -> SymmetricState {
        // The protocol name is exactly 32 bytes, so h starts as the name itself.
        let mut h = [0u8; 32];
        h.copy_from_slice(PROTOCOL);
        SymmetricState { ck: h, h, cipher: CipherState::new() }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = Sha256::new().chain_update(self.h).chain_update(data).finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let (ck, k) = hkdf2(&self.ck, ikm);
        self.ck = ck;
        self.cipher = CipherState::keyed(k);
    }

    /// Encrypt `buf[..len]` in place with h as associated data, then mix the ciphertext in.
    fn encrypt_and_hash(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let h = self.h;
        let n = self.cipher.encrypt(&h, buf, len)?;
        self.mix_hash(&buf[..n]);
        Ok(n)
    }

    fn decrypt_and_hash(&mut self, buf: &mut [u8], len: usize) -> Result<usize, Error> {
        let h = self.h;
        // Hash the ciphertext as received, before decrypting it in place.
        let ciphertext_hash: [u8; 32] = Sha256::new().chain_update(h).chain_update(&buf[..len]).finalize().into();
        let n = self.cipher.decrypt(&h, buf, len)?;
        self.h = ciphertext_hash;
        Ok(n)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let (k1, k2) = hkdf2(&self.ck, &[]);
        (CipherState::keyed(k1), CipherState::keyed(k2))
    }
}

fn dh(secret: &SecretKey, public: &PublicKey) -> Result<[u8; 32], Error> {
    public.dh(secret).map(|shared| *shared).map_err(|_| Error::BadKey)
}

/// The initiator of an IK handshake.
pub struct Initiator {
    state: SymmetricState,
    s: SecretKey,
    e: SecretKey,
    rs: PublicKey,
}

/// A finished handshake: send with `send`, receive with `recv`.
pub struct Transport {
    pub send: CipherState,
    pub recv: CipherState,
    /// The handshake hash, unique to this session.
    pub handshake_hash: [u8; 32],
}

impl Initiator {
    /// `s`: our static key; `e`: a fresh ephemeral key (32 random bytes each); `rs`: the
    /// responder's static public key, known in advance; `prologue`: bound into the handshake.
    pub fn new(s: [u8; 32], e: [u8; 32], rs: [u8; 32], prologue: &[u8]) -> Result<Initiator, Error> {
        let mut state = SymmetricState::new();
        state.mix_hash(prologue);
        state.mix_hash(&rs);
        let rs = PublicKey::from_slice(&rs).map_err(|_| Error::BadKey)?;
        Ok(Initiator { state, s: SecretKey::new(s), e: SecretKey::new(e), rs })
    }

    pub fn ephemeral_public(&self) -> [u8; 32] {
        *self.e.recover_public_key().expect("valid scalar")
    }

    pub fn static_public(&self) -> [u8; 32] {
        *self.s.recover_public_key().expect("valid scalar")
    }

    /// The first message (`e, es, s, ss` and `payload`) into `out`; returns its length.
    pub fn write_message(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        let need = DH_LEN + DH_LEN + TAG_LEN + payload.len() + TAG_LEN;
        if need > out.len() || need > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let e_pub = self.ephemeral_public();
        out[..32].copy_from_slice(&e_pub);
        self.state.mix_hash(&e_pub);
        self.state.mix_key(&dh(&self.e, &self.rs)?);
        let s_pub = self.static_public();
        out[32..64].copy_from_slice(&s_pub);
        let n = self.state.encrypt_and_hash(&mut out[32..], 32)?;
        self.state.mix_key(&dh(&self.s, &self.rs)?);
        let at = 32 + n;
        out[at..at + payload.len()].copy_from_slice(payload);
        let m = self.state.encrypt_and_hash(&mut out[at..], payload.len())?;
        Ok(at + m)
    }

    /// The responder's message (`e, ee, se` and a payload, decrypted in place: returns its
    /// offset and length), and the transport.
    pub fn read_message(mut self, msg: &mut [u8]) -> Result<(Transport, core::ops::Range<usize>), Error> {
        if msg.len() < DH_LEN + TAG_LEN {
            return Err(Error::Decrypt);
        }
        let re: [u8; 32] = msg[..32].try_into().unwrap();
        self.state.mix_hash(&re);
        let re = PublicKey::from_slice(&re).map_err(|_| Error::BadKey)?;
        self.state.mix_key(&dh(&self.e, &re)?);
        self.state.mix_key(&dh(&self.s, &re)?);
        let len = msg.len() - 32;
        let n = self.state.decrypt_and_hash(&mut msg[32..], len)?;
        let (send, recv) = self.state.split();
        Ok((Transport { send, recv, handshake_hash: self.state.h }, 32..32 + n))
    }
}

/// The responder of an IK handshake: it learns the initiator's static key from the first
/// message, and the caller decides whether that key is the one it expects.
pub struct Responder {
    state: SymmetricState,
    s: SecretKey,
    e: SecretKey,
    re: Option<PublicKey>,
    rs: Option<PublicKey>,
}

impl Responder {
    /// `s`: our static key; `e`: a fresh ephemeral key; `prologue`: bound into the handshake.
    pub fn new(s: [u8; 32], e: [u8; 32], prologue: &[u8]) -> Responder {
        let s = SecretKey::new(s);
        let mut state = SymmetricState::new();
        state.mix_hash(prologue);
        state.mix_hash(&*s.recover_public_key().expect("valid scalar"));
        Responder { state, s, e: SecretKey::new(e), re: None, rs: None }
    }

    /// The initiator's first message (`e, es, s, ss` and a payload, decrypted in place): returns
    /// the initiator's static key and the payload's range.
    pub fn read_message(&mut self, msg: &mut [u8]) -> Result<([u8; 32], core::ops::Range<usize>), Error> {
        if msg.len() < DH_LEN + DH_LEN + TAG_LEN + TAG_LEN {
            return Err(Error::Decrypt);
        }
        let re: [u8; 32] = msg[..32].try_into().unwrap();
        self.state.mix_hash(&re);
        let re = PublicKey::from_slice(&re).map_err(|_| Error::BadKey)?;
        self.state.mix_key(&dh(&self.s, &re)?);
        let n = self.state.decrypt_and_hash(&mut msg[32..], DH_LEN + TAG_LEN)?;
        let rs_bytes: [u8; 32] = msg[32..32 + n].try_into().unwrap();
        let rs = PublicKey::from_slice(&rs_bytes).map_err(|_| Error::BadKey)?;
        self.state.mix_key(&dh(&self.s, &rs)?);
        let at = 32 + DH_LEN + TAG_LEN;
        let len = msg.len() - at;
        let m = self.state.decrypt_and_hash(&mut msg[at..], len)?;
        self.re = Some(re);
        self.rs = Some(rs);
        Ok((rs_bytes, at..at + m))
    }

    /// Our answer (`e, ee, se` and `payload`) into `out`: returns its length and the transport.
    pub fn write_message(mut self, payload: &[u8], out: &mut [u8]) -> Result<(usize, Transport), Error> {
        let (Some(re), Some(rs)) = (self.re, self.rs) else { return Err(Error::Decrypt) };
        let need = DH_LEN + payload.len() + TAG_LEN;
        if need > out.len() || need > MAX_MESSAGE {
            return Err(Error::TooLong);
        }
        let e_pub = *self.e.recover_public_key().expect("valid scalar");
        out[..32].copy_from_slice(&e_pub);
        self.state.mix_hash(&e_pub);
        self.state.mix_key(&dh(&self.e, &re)?);
        self.state.mix_key(&dh(&self.e, &rs)?);
        out[32..32 + payload.len()].copy_from_slice(payload);
        let n = self.state.encrypt_and_hash(&mut out[32..], payload.len())?;
        let (recv, send) = self.state.split();
        Ok((32 + n, Transport { send, recv, handshake_hash: self.state.h }))
    }
}

/// The public key of a 32-byte X25519 secret.
pub fn public_key(secret: [u8; 32]) -> [u8; 32] {
    *SecretKey::new(secret).recover_public_key().expect("valid scalar")
}
