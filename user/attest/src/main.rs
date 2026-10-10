//! Attestation: on request, quote PCRs 0, 4, 7 and 12 over the requester's nonce with the TPM's
//! attestation key, and reply with one JSON line the host can verify (tools/verify-quote.py):
//! the signed TPMS_ATTEST, the ECDSA signature, the key, the PCR values, and the kernel's
//! measurement log for PCR 12.

#![no_std]
#![no_main]

use core::fmt::{self, Write};
use tpm2::{AttestationKey, Tpm};
use vanir_user::attest::OP_QUOTE;
use vanir_user::{err, measurements, println, recv, reply};

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

fn quote(tpm: &Tpm, key: &AttestationKey, log: &[u8], entries: usize, nonce: &[u8], out: &mut Line) -> Result<(), tpm2::Error> {
    let mut buf = [0u8; tpm2::BUF];
    let q = tpm.quote(&mut buf, key, nonce, &PCRS)?;
    let _ = write!(
        out,
        "{{\"event\":\"quote\",\"nonce\":\"{}\",\"attest\":\"{}\",\"sig_r\":\"{}\",\"sig_s\":\"{}\",\"ak_x\":\"{}\",\"ak_y\":\"{}\",\"pcrs\":{{",
        Hex(nonce),
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

    let mut msg = [0u8; 64];
    loop {
        let m = match recv(&mut msg) {
            Ok(m) => m,
            Err(e) => {
                println!("attest: recv failed: {}", err::name(e));
                continue;
            }
        };
        if m.op != OP_QUOTE || m.len > 32 {
            let _ = reply(m.sender, 1, &[]);
            continue;
        }
        let mut line = Line { buf: [0; 4096], len: 0 };
        match quote(&tpm, &key, &log, entries, &msg[..m.len], &mut line) {
            Ok(()) => {
                let _ = reply(m.sender, 0, &line.buf[..line.len]);
            }
            Err(e) => {
                println!("attest: quote failed: {:?}", e);
                let _ = reply(m.sender, 2, &[]);
            }
        }
    }
}
