//! A small TPM 2.0 client over the CRB interface, for a task granted the TPM: create an
//! attestation key and quote PCRs with it. Commands are marshalled by hand (big-endian, as the
//! TPM 2.0 spec part 3 lays them out).

#![no_std]

use core::ptr::{read_volatile, write_volatile};

const CTRL_REQ: u64 = 0x40;
const CTRL_START: u64 = 0x4c;
const CTRL_CMD_LADDR: u64 = 0x5c;
const CTRL_RSP_ADDR: u64 = 0x68;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
const CC_CREATE_PRIMARY: u32 = 0x131;
const CC_QUOTE: u32 = 0x158;
const CC_PCR_READ: u32 = 0x17e;
const CC_FLUSH_CONTEXT: u32 = 0x165;
const CC_GET_RANDOM: u32 = 0x17b;
const RH_ENDORSEMENT: u32 = 0x4000_000b;
const RS_PW: u32 = 0x4000_0009;
const ALG_SHA256: u16 = 0x000b;
const ALG_ECC: u16 = 0x0023;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
const ECC_NIST_P256: u16 = 0x0003;
/// fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | noDA | restricted | sign.
/// noDA: using the key is exempt from dictionary-attack lockout, which a VM that is often killed
/// without TPM2_Shutdown (an "unorderly shutdown") would otherwise trip.
const AK_ATTRIBUTES: u32 = 0x0005_0472;

pub const BUF: usize = 2048;

/// Warnings that mean "send the command again": TPM_RC_YIELDED, TPM_RC_TESTING, TPM_RC_RETRY.
const RETRY_CODES: [u32; 3] = [0x908, 0x90a, 0x922];
const RETRIES: u32 = 100;

#[derive(Debug)]
pub enum Error {
    /// The TPM answered with this response code.
    Tpm(u32),
    /// The response didn't parse.
    Malformed,
}

/// The TPM's CRB page, mapped into this task.
pub struct Tpm {
    base: u64,
}

pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    pub fn bytes(&mut self, b: &[u8]) {
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }
    pub fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }
    pub fn u16(&mut self, v: u16) {
        self.bytes(&v.to_be_bytes());
    }
    pub fn u32(&mut self, v: u32) {
        self.bytes(&v.to_be_bytes());
    }
    /// A TPM2B: u16 size, then the bytes.
    pub fn sized(&mut self, b: &[u8]) {
        self.u16(b.len() as u16);
        self.bytes(b);
    }
    /// An authorization area with one empty-password session.
    fn password_session(&mut self) {
        self.u32(9);
        self.u32(RS_PW);
        self.u16(0);
        self.u8(0);
        self.u16(0);
    }
}

/// Reads a response.
pub struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let b = self.buf.get(self.at..self.at + n).ok_or(Error::Malformed)?;
        self.at += n;
        Ok(b)
    }
    pub fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    pub fn sized(&mut self) -> Result<&'a [u8], Error> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }
}

/// PCR selection on the SHA-256 bank (PCRs 0-23).
fn pcr_select(w: &mut Writer, pcrs: &[u32]) {
    w.u32(1);
    w.u16(ALG_SHA256);
    w.u8(3);
    let mut bits = [0u8; 3];
    for &p in pcrs {
        bits[(p / 8) as usize] |= 1 << (p % 8);
    }
    w.bytes(&bits);
}

/// An attestation key: its handle in the TPM and its P-256 public point.
pub struct AttestationKey {
    pub handle: u32,
    pub x: [u8; 32],
    pub y: [u8; 32],
}

/// A quote: the TPM-signed TPMS_ATTEST structure and the ECDSA signature (r, s).
pub struct Quote<'a> {
    pub attest: &'a [u8],
    pub r: &'a [u8],
    pub s: &'a [u8],
}

impl Tpm {
    /// `base`: where the kernel mapped the CRB page (`measurements` returns it).
    pub fn new(base: u64) -> Tpm {
        Tpm { base }
    }

    fn reg32(&self, offset: u64) -> u32 {
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    fn set32(&self, offset: u64, value: u32) {
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Build a command with `body`, run it (again while the TPM asks for a retry), and return
    /// the response parameters (after the 10-byte header) in `buf`.
    pub fn call<'b>(&self, buf: &'b mut [u8; BUF], tag: u16, code: u32, body: impl FnOnce(&mut Writer)) -> Result<Reader<'b>, Error> {
        let mut command = [0u8; BUF];
        let len = {
            let mut w = Writer { buf: &mut command[..], len: 0 };
            w.u16(tag);
            w.u32(0);
            w.u32(code);
            body(&mut w);
            w.len
        };
        command[2..6].copy_from_slice(&(len as u32).to_be_bytes());
        for _ in 0..RETRIES {
            buf[..len].copy_from_slice(&command[..len]);
            match self.execute(buf, len) {
                Err(Error::Tpm(rc)) if RETRY_CODES.contains(&rc) => vanir_user::yield_now(),
                Ok(size) => return Ok(Reader { buf: &buf[..size], at: 10 }),
                Err(e) => return Err(e),
            }
        }
        Err(Error::Tpm(RETRY_CODES[2]))
    }

    /// Send `buf[..len]` and leave the response in `buf`; returns its length.
    fn execute(&self, buf: &mut [u8; BUF], len: usize) -> Result<usize, Error> {
        let cmd = self.base + (self.reg32(CTRL_CMD_LADDR) as u64 & 0xfff);
        let rsp = self.base + (unsafe { read_volatile((self.base + CTRL_RSP_ADDR) as *const u64) } & 0xfff);
        self.set32(CTRL_REQ, 1);
        while self.reg32(CTRL_REQ) & 1 != 0 {
            core::hint::spin_loop();
        }
        for (i, &b) in buf[..len].iter().enumerate() {
            unsafe { write_volatile((cmd + i as u64) as *mut u8, b) };
        }
        self.set32(CTRL_START, 1);
        while self.reg32(CTRL_START) & 1 != 0 {
            core::hint::spin_loop();
        }
        let byte = |i: usize| unsafe { read_volatile((rsp + i as u64) as *const u8) };
        let size = u32::from_be_bytes(core::array::from_fn(|i| byte(2 + i))) as usize;
        let code = u32::from_be_bytes(core::array::from_fn(|i| byte(6 + i)));
        if code != 0 {
            return Err(Error::Tpm(code));
        }
        let size = size.min(BUF);
        for (i, b) in buf[..size].iter_mut().enumerate() {
            *b = byte(i);
        }
        Ok(size)
    }

    /// Create the attestation key: a restricted ECDSA P-256 signing key, primary under the
    /// endorsement hierarchy. The same TPM gives the same key every time (it is derived from the
    /// endorsement seed and this template).
    pub fn create_attestation_key(&self) -> Result<AttestationKey, Error> {
        let mut buf = [0u8; BUF];
        let mut r = self.call(&mut buf, ST_SESSIONS, CC_CREATE_PRIMARY, |w| {
            w.u32(RH_ENDORSEMENT);
            w.password_session();
            w.sized(&[0, 0, 0, 0]); // TPM2B_SENSITIVE_CREATE: empty auth, no data
            let mut template = [0u8; 64];
            let len = {
                let mut t = Writer { buf: &mut template, len: 0 };
                t.u16(ALG_ECC);
                t.u16(ALG_SHA256);
                t.u32(AK_ATTRIBUTES);
                t.u16(0); // no auth policy
                t.u16(ALG_NULL); // symmetric: none
                t.u16(ALG_ECDSA); // scheme
                t.u16(ALG_SHA256);
                t.u16(ECC_NIST_P256);
                t.u16(ALG_NULL); // kdf
                t.u16(0); // unique.x
                t.u16(0); // unique.y
                t.len
            };
            w.sized(&template[..len]);
            w.u16(0); // outsideInfo
            w.u32(0); // creationPCR: none
        })?;
        let handle = r.u32()?;
        let _parameter_size = r.u32()?;
        let public = r.sized()?;
        let mut p = Reader { buf: public, at: 0 };
        // type, nameAlg, attributes, authPolicy, symmetric, scheme+hash, curve, kdf
        p.bytes(2 + 2 + 4)?;
        p.sized()?;
        p.bytes(2 + 4 + 2 + 2)?;
        let x = p.sized()?;
        let y = p.sized()?;
        if x.len() != 32 || y.len() != 32 {
            return Err(Error::Malformed);
        }
        Ok(AttestationKey { handle, x: x.try_into().unwrap(), y: y.try_into().unwrap() })
    }

    /// Quote `pcrs` (SHA-256 bank) over `nonce` with the attestation key. The result borrows
    /// `buf`.
    pub fn quote<'b>(&self, buf: &'b mut [u8; BUF], key: &AttestationKey, nonce: &[u8], pcrs: &[u32]) -> Result<Quote<'b>, Error> {
        let mut r = self.call(buf, ST_SESSIONS, CC_QUOTE, |w| {
            w.u32(key.handle);
            w.password_session();
            w.sized(nonce); // qualifyingData
            w.u16(ALG_NULL); // use the key's own scheme
            pcr_select(w, pcrs);
        })?;
        let _parameter_size = r.u32()?;
        let attest = r.sized()?;
        let _sig_alg = r.u16()?;
        let _hash = r.u16()?;
        let rr = r.sized()?;
        let ss = r.sized()?;
        Ok(Quote { attest, r: rr, s: ss })
    }

    /// Read one PCR of the SHA-256 bank.
    pub fn pcr_read(&self, pcr: u32) -> Result<[u8; 32], Error> {
        let mut buf = [0u8; BUF];
        let mut r = self.call(&mut buf, ST_NO_SESSIONS, CC_PCR_READ, |w| pcr_select(w, &[pcr]))?;
        r.u32()?; // update counter
        r.bytes(4 + 2 + 1 + 3)?; // selection echoed back
        if r.u32()? != 1 {
            return Err(Error::Malformed);
        }
        r.sized()?.try_into().map_err(|_| Error::Malformed)
    }

    /// Fill `out` (up to 32 bytes) from the TPM's random number generator.
    pub fn get_random(&self, out: &mut [u8]) -> Result<(), Error> {
        let mut buf = [0u8; BUF];
        let mut r = self.call(&mut buf, ST_NO_SESSIONS, CC_GET_RANDOM, |w| w.u16(out.len() as u16))?;
        let bytes = r.sized()?;
        if bytes.len() != out.len() {
            return Err(Error::Malformed);
        }
        out.copy_from_slice(bytes);
        Ok(())
    }

    /// Free a transient object (the attestation key) inside the TPM.
    pub fn flush(&self, handle: u32) -> Result<(), Error> {
        let mut buf = [0u8; BUF];
        self.call(&mut buf, ST_NO_SESSIONS, CC_FLUSH_CONTEXT, |w| w.u32(handle)).map(|_| ())
    }
}
