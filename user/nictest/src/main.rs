//! NIC driver test, with no network stack: answers ARP requests and ICMP echo requests for a
//! fixed address by building the reply frames by hand, then exits after `PINGS` echoes.
//!
//! It finds the driver (the task named "nic") again if the driver is restarted.

#![no_std]
#![no_main]

use vanir_user::nic::{self, CODE_BUSY, CODE_OK, OP_RECV_FRAMES, OP_SEND_FRAME};
use vanir_user::{err, lookup, println, recv_timeout, send, sleep, yield_now};

vanir_user::entry!(main);

/// Our address on the test network (tools/net-peer.py is 10.0.9.1).
const IP: [u8; 4] = [10, 0, 9, 2];
const PINGS: u32 = 20;

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The reply to `frame`, if it is an ARP request or ICMP echo request for us: (reply, is a ping).
fn answer(frame: &[u8], mac: [u8; 6], out: &mut [u8; nic::MAX_FRAME]) -> Option<(usize, bool)> {
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let body = &frame[14..];
    out[..6].copy_from_slice(&frame[6..12]);
    out[6..12].copy_from_slice(&mac);
    out[12..14].copy_from_slice(&frame[12..14]);
    match ethertype {
        0x0806 if body.len() >= 28 && body[6..8] == [0, 1] && body[24..28] == IP => {
            let reply = &mut out[14..42];
            reply[..6].copy_from_slice(&body[..6]); // hardware and protocol types and sizes
            reply[6..8].copy_from_slice(&[0, 2]);
            reply[8..14].copy_from_slice(&mac);
            reply[14..18].copy_from_slice(&IP);
            reply[18..28].copy_from_slice(&body[8..18]); // the asker's MAC and address
            Some((42, false))
        }
        0x0800 if body.len() >= 28 && body[9] == 1 && body[16..20] == IP => {
            let header = ((body[0] & 0xf) as usize) * 4;
            let total = u16::from_be_bytes([body[2], body[3]]) as usize;
            if header < 20 || total > body.len() || total < header + 8 || body[header] != 8 {
                return None;
            }
            let reply = &mut out[14..14 + total];
            reply.copy_from_slice(&body[..total]);
            reply[12..16].copy_from_slice(&body[16..20]);
            reply[16..20].copy_from_slice(&body[12..16]);
            reply[8] = 64;
            reply[10..12].copy_from_slice(&[0, 0]);
            let sum = checksum(&reply[..header]);
            reply[10..12].copy_from_slice(&sum.to_be_bytes());
            let icmp = &mut reply[header..];
            icmp[0] = 0; // echo reply
            icmp[2..4].copy_from_slice(&[0, 0]);
            let sum = checksum(icmp);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            Some((14 + total, true))
        }
        _ => None,
    }
}

/// The driver's id, once it is running (after a restart, the new one).
fn find_driver(old: Option<u64>) -> u64 {
    loop {
        match lookup("nic") {
            Ok(id) if Some(id) != old => return id,
            _ => sleep(1),
        }
    }
}

fn main() -> u64 {
    let mut driver = find_driver(None);
    let mac = loop {
        match nic::info(driver) {
            Ok(info) => break info.mac,
            Err(e) if e == err::DEAD => driver = find_driver(Some(driver)),
            Err(_) => sleep(1),
        }
    };
    println!("nictest: answering ARP and ping for 10.0.9.2");
    let mut frames = [0u8; 4096];
    let mut out = [0u8; nic::MAX_FRAME];
    let mut pings = 0;
    let mut restarts = 0;
    loop {
        let (code, n) = match send(driver, OP_RECV_FRAMES, &[], &mut frames) {
            Ok(r) => r,
            Err(e) if e == err::DEAD => {
                driver = find_driver(Some(driver));
                restarts += 1;
                println!("nictest: the driver was restarted");
                continue;
            }
            Err(e) => {
                println!("nictest: receive failed: {}", err::name(e));
                return 1;
            }
        };
        if code != CODE_OK {
            println!("nictest: receive failed: code {}", code);
            return 1;
        }
        if n == 0 {
            // Wait for NOTIFY_RX; poll now and then in case the driver was restarted.
            let mut buf = [0u8; 16];
            let _ = recv_timeout(&mut buf, 50);
            continue;
        }
        let mut replies = [(0usize, false); 64];
        let mut count = 0;
        let mut pending = [[0u8; 128]; 64];
        nic::frames(&frames[..n], |frame| {
            if count < replies.len()
                && let Some((len, ping)) = answer(frame, mac, &mut out)
                && len <= 128
            {
                pending[count][..len].copy_from_slice(&out[..len]);
                replies[count] = (len, ping);
                count += 1;
            }
        });
        for (frame, &(len, ping)) in pending.iter().zip(&replies[..count]) {
            loop {
                match send(driver, OP_SEND_FRAME, &frame[..len], &mut []) {
                    Ok((CODE_BUSY, _)) => yield_now(),
                    Ok(_) => break,
                    Err(_) => break, // the driver died: the peer asks again
                }
            }
            if ping {
                pings += 1;
            }
        }
        if pings >= PINGS {
            println!("nictest: answered {} pings (driver restarted {} times)", pings, restarts);
            return 0;
        }
    }
}
