//! Commands from the control plane, read line by line from the uplink:
//!
//!   attest <nonce hex, up to 32 bytes>   -> the attestation task's JSON quote, sent back
//!   key <hex: host X25519 key, sealed key> -> the attestation task opens it, unlocks storage
//!   interval <ms>                         -> telemetry's counter snapshot interval
//!   bye                                   -> end this task (the host is done with us)
//!
//! Replies go back over the uplink as JSON lines, next to the telemetry stream.

#![no_std]
#![no_main]

use vanir_user::attest::{OP_QUOTE, OP_UNWRAP};
use vanir_user::{console, err, lookup, println, send, telemetry};

vanir_user::entry!(main);

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decode `hex` into `out`; returns the length, or None if it isn't hex or doesn't fit.
fn unhex(hex: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = hex.len() / 2;
    (hex.len() % 2 == 0 && n <= out.len()).then_some(())?;
    for i in 0..n {
        out[i] = hex_digit(hex[2 * i])? << 4 | hex_digit(hex[2 * i + 1])?;
    }
    Some(n)
}

/// Run one command line; returns the reply line to send to the host.
fn handle<'a>(line: &[u8], attest: Option<u64>, out: &'a mut [u8; 4096]) -> &'a [u8] {
    let error = |out: &'a mut [u8; 4096], msg: &[u8]| -> &'a [u8] {
        out[..msg.len()].copy_from_slice(msg);
        &out[..msg.len()]
    };
    if let Some(ms) = line.strip_prefix(b"interval ") {
        let ms = core::str::from_utf8(ms).ok().and_then(|m| m.parse::<u64>().ok());
        let telemetry = lookup("telemetry").ok();
        return match (ms, telemetry) {
            (Some(ms), Some(t)) => match send(t, telemetry::OP_SET_INTERVAL, &ms.to_le_bytes(), &mut []) {
                Ok((0, _)) => error(out, b"{\"event\":\"interval_set\"}\n"),
                _ => error(out, b"{\"event\":\"error\",\"msg\":\"telemetry refused the interval\"}\n"),
            },
            (None, _) => error(out, b"{\"event\":\"error\",\"msg\":\"bad interval\"}\n"),
            (_, None) => error(out, b"{\"event\":\"error\",\"msg\":\"no telemetry task\"}\n"),
        };
    }
    if let Some(sealed_hex) = line.strip_prefix(b"key ") {
        let mut sealed = [0u8; 80];
        let Some(80) = unhex(sealed_hex, &mut sealed) else {
            return error(out, b"{\"event\":\"error\",\"msg\":\"bad key message\"}\n");
        };
        let Some(attest) = attest else {
            return error(out, b"{\"event\":\"error\",\"msg\":\"no attestation task\"}\n");
        };
        return match send(attest, OP_UNWRAP, &sealed, &mut []) {
            Ok((0, _)) => error(out, b"{\"event\":\"unlocked\"}\n"),
            _ => error(out, b"{\"event\":\"error\",\"msg\":\"unlock failed\"}\n"),
        };
    }
    let Some(nonce_hex) = line.strip_prefix(b"attest ") else {
        let msg = b"{\"event\":\"error\",\"msg\":\"unknown command\"}\n";
        out[..msg.len()].copy_from_slice(msg);
        return &out[..msg.len()];
    };
    let mut nonce = [0u8; 32];
    let Some(n) = unhex(nonce_hex, &mut nonce) else {
        return error(out, b"{\"event\":\"error\",\"msg\":\"bad nonce\"}\n");
    };
    let Some(attest) = attest else {
        return error(out, b"{\"event\":\"error\",\"msg\":\"no attestation task\"}\n");
    };
    match send(attest, OP_QUOTE, &nonce[..n], out) {
        Ok((0, len)) => &out[..len],
        _ => error(out, b"{\"event\":\"error\",\"msg\":\"quote failed\"}\n"),
    }
}

fn main() -> u64 {
    let uplink = lookup("uplink").expect("no uplink task");
    let attest = lookup("attest").ok();
    let mut line = [0u8; 512];
    let mut len = 0;
    loop {
        let mut chunk = [0u8; 256];
        let n = match console::read(uplink, &mut chunk) {
            Ok(n) => n,
            Err(e) => {
                println!("control: read failed: {}", err::name(e));
                return 1;
            }
        };
        for &b in &chunk[..n] {
            if b != b'\n' {
                if len < line.len() {
                    line[len] = b;
                    len += 1;
                }
                continue;
            }
            let shown = &line[..len.min(24)];
            println!("control: command: {}...", core::str::from_utf8(shown).unwrap_or("?"));
            if &line[..len] == b"bye" {
                return 0;
            }
            let mut out = [0u8; 4096];
            let reply = handle(&line[..len], attest, &mut out);
            if let Err(e) = console::write(uplink, reply) {
                println!("control: reply failed: {}", err::name(e));
            }
            len = 0;
        }
    }
}
