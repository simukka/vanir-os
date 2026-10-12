//! The connection to the control plane (RFD 2, P7), and reconciling against what it wants.
//!
//! - **The node dials out** through the management stack (`mgmt-net`, `connects = true`) to the
//!   address built in (`VANIR_CP_ADDR`), and reconnects with backoff (100 ms doubling to 10 s)
//!   whenever the connection drops. Deployments go on meanwhile.
//! - **Noise `IK`.** The control plane's static key is pinned in the image (`VANIR_CP_PUB`). Our
//!   static and ephemeral keys are fresh for each connection (RDRAND), and the first handshake
//!   message carries a TPM quote over SHA-256(our ephemeral key || our static key) from
//!   `attest` (`OP_QUOTE_FOR`), binding this handshake to an attested boot. Without a TPM it
//!   says `no-tpm`, which a control plane may refuse.
//! - **Frames.** Each Noise message goes over TCP behind a 2-byte big-endian length. Inside the
//!   transport, the first byte says what it is:
//!
//!   | Type | From | Contents |
//!   |---|---|---|
//!   | `S` | control plane | desired state: length (u32 LE), the document, Ed25519 signature |
//!   | `C` | control plane | image chunk: hash (32), offset (u32 LE), bytes |
//!   | `E` | control plane | image end: hash (32), signature file (176), descriptor (256) |
//!   | `R` | agent | report (text) |
//!   | `G` | agent | get image: hash (32), slot name |
//!   | `T` | agent | telemetry JSON lines, pulled from the telemetry task |
//!
//! - **Desired state** is a text document signed with a second pinned key
//!   (`VANIR_CP_SIGN_PUB`), applied only if its generation is higher than the last one applied,
//!   so a replayed or reordered command does nothing:
//!
//!   ```text
//!   vanir-desired 1
//!   generation 7
//!   live web small-1 <statement hash, hex> [drain <secs>]   # web's live instance
//!   stop web [drain <secs>]                                 # drain and stop every instance
//!   commit web                                              # unload web's stopped slots
//!   ```
//!
//!   The agent keeps reconciling towards the last one it applied: it fetches the images it
//!   lacks into the named slot, deploys, rolls back to a stopped slot that holds the wanted
//!   image, drains, and commits.
//! - **Reports** (`R`) say what it has: the generation applied, each slot's service, version,
//!   image hash and state. Sent after the handshake, on every change, and every 5 s.

use crate::Image;
use crate::lifecycle::{Agent, MAX_SLOTS, State};
use ed25519_compact::{PublicKey, Signature};
use noise::{Initiator, Transport};
use vanir_user::attest::OP_QUOTE_FOR;
use vanir_user::net::{self, CODE_WOULD_BLOCK, EV_CLOSED, EV_READ, EV_WRITE, Event};
use vanir_user::{LineWriter, err, lookup, println, send, slot, telemetry, uptime};

use core::fmt::Write;

const CP_NOISE_PUB: &[u8; 32] = include_bytes!(env!("VANIR_CP_PUB"));
const CP_SIGN_PUB: &[u8; 32] = include_bytes!(env!("VANIR_CP_SIGN_PUB"));
/// Bound into the handshake: both sides must agree on what this is.
const PROLOGUE: &[u8] = b"vanir-agent 1";

const REPORT_TICKS: u64 = 500;
const HANDSHAKE_TICKS: u64 = 500;
const MAX_FRAME: usize = 65535;
const MAX_DOC: usize = 3072;

/// 32 random bytes from the CPU (RDRAND, which user code may run).
fn random() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let value = loop {
            let (v, ok): (u64, u8);
            unsafe { core::arch::asm!("rdrand {v}", "setc {ok}", v = out(reg) v, ok = out(reg_byte) ok) };
            if ok != 0 {
                break v;
            }
        };
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    out
}

fn hex(bytes: &[u8], out: &mut LineWriter) {
    for b in bytes {
        let _ = write!(out, "{:02x}", b);
    }
}

fn unhex32(s: &[u8]) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = digit(s[2 * i])? << 4 | digit(s[2 * i + 1])?;
    }
    Some(out)
}

fn number(s: &[u8]) -> Option<u64> {
    core::str::from_utf8(s).ok()?.parse().ok()
}

/// Where the connection is.
enum Link {
    /// Not connected; try again at this tick.
    Down { retry: u64 },
    /// TCP handshake in progress.
    Connecting { conn: u32, since: u64 },
    /// Our first Noise message is out; waiting for the answer.
    Handshake { conn: u32, since: u64, initiator: Initiator },
    Up { conn: u32, transport: Transport },
}

/// An image being fetched into a slot.
#[derive(Clone, Copy)]
struct Fetch {
    slot: usize,
    hash: [u8; 32],
    /// The request went out on the current connection.
    asked: bool,
}

/// Signature file and descriptor of images fetched into each slot (they outlive the frames
/// they came in, as `Image` borrows them).
static mut FETCHED: [([u8; 176], [u8; 256]); MAX_SLOTS] = [([0; 176], [0; 256]); MAX_SLOTS];
static mut RX: [u8; MAX_FRAME + 2] = [0; MAX_FRAME + 2];
static mut FRAME: [u8; MAX_FRAME] = [0; MAX_FRAME];

pub struct Control {
    mgmt: u64,
    attest: Option<u64>,
    telemetry: Option<u64>,
    link: Link,
    backoff: u64,
    rx_len: usize,
    /// The last desired state applied, and its generation.
    desired: [u8; MAX_DOC],
    desired_len: usize,
    generation: u64,
    /// Why the last desired state was refused, if it was.
    refused: Option<&'static str>,
    fetch: Option<Fetch>,
    next_report: u64,
    /// Failed connection attempts in a row (test feature `exit-after-failures`).
    pub failures: u32,
    /// The desired state said `end` (test feature `exit-on-end`).
    pub end: bool,
}

impl Control {
    pub fn new() -> Control {
        let mgmt = loop {
            match lookup("mgmt-net") {
                Ok(id) => break id,
                Err(_) => vanir_user::sleep(1),
            }
        };
        Control {
            mgmt,
            attest: lookup("attest").ok(),
            telemetry: lookup("telemetry").ok(),
            link: Link::Down { retry: 0 },
            backoff: 10,
            rx_len: 0,
            desired: [0; MAX_DOC],
            desired_len: 0,
            generation: 0,
            refused: None,
            fetch: None,
            next_report: 0,
            failures: 0,
            end: false,
        }
    }

    pub fn connected(&self) -> bool {
        matches!(self.link, Link::Up { .. })
    }

    /// One turn of the loop: move the connection along, read what came, reconcile, report.
    pub fn turn(&mut self, agent: &mut Agent) {
        let now = uptime();
        self.link_step(now);
        let conn = match self.link {
            Link::Connecting { conn, .. } | Link::Handshake { conn, .. } | Link::Up { conn, .. } => Some(conn),
            Link::Down { .. } => None,
        };
        if let Some(conn) = conn {
            let mut events = [Event::default(); 16];
            let n = net::wait(self.mgmt, 2, &mut events).unwrap_or(0);
            for e in events[..n].iter().filter(|e| e.handle == conn) {
                if e.flags & EV_WRITE != 0 && matches!(self.link, Link::Connecting { .. }) {
                    self.start_handshake(conn, now);
                }
                if e.flags & (EV_READ | EV_CLOSED) != 0 {
                    self.read(conn, agent);
                }
            }
        } else {
            vanir_user::sleep(2);
        }
        agent.advance();
        self.reconcile(agent);
        if self.connected() {
            if agent.changed || uptime() >= self.next_report {
                agent.changed = false;
                self.report(agent);
            }
            self.forward_telemetry();
        }
    }

    fn down(&mut self, why: &str) {
        let now = uptime();
        if let Link::Connecting { conn, .. } | Link::Handshake { conn, .. } | Link::Up { conn, .. } = self.link {
            let _ = net::close(self.mgmt, conn);
        }
        if !self.connected() {
            self.failures += 1;
        }
        println!("agent: control plane connection down ({}); retrying in {} ticks", why, self.backoff);
        self.link = Link::Down { retry: now + self.backoff };
        self.backoff = (self.backoff * 2).min(1000);
        self.rx_len = 0;
        if let Some(f) = self.fetch.as_mut() {
            f.asked = false; // ask again on the next connection
        }
    }

    fn link_step(&mut self, now: u64) {
        match self.link {
            Link::Down { retry } if now >= retry => {
                let (addr, port) = cp_addr();
                match net::connect(self.mgmt, addr, port) {
                    Ok(conn) => self.link = Link::Connecting { conn, since: now },
                    Err(e) => {
                        println!("agent: connecting to the control plane: {}", net::code_name(e));
                        self.link = Link::Down { retry: now + self.backoff };
                    }
                }
            }
            Link::Connecting { since, .. } | Link::Handshake { since, .. } if now - since > HANDSHAKE_TICKS => self.down("timed out"),
            _ => {}
        }
    }

    fn start_handshake(&mut self, conn: u32, now: u64) {
        let rs = *CP_NOISE_PUB;
        let Ok(mut initiator) = Initiator::new(random(), random(), rs, PROLOGUE) else {
            return self.down("bad control plane key");
        };
        // The quote binds both our keys for this handshake to the boot the TPM measured.
        let mut quote = [0u8; 4096];
        let quote_len = self.quote(initiator.ephemeral_public(), initiator.static_public(), &mut quote);
        let frame = unsafe { &mut *(&raw mut FRAME) };
        let Ok(n) = initiator.write_message(&quote[..quote_len], frame) else { return self.down("handshake message") };
        if self.send_raw(conn, n).is_err() {
            return self.down("send failed");
        }
        self.link = Link::Handshake { conn, since: now, initiator };
    }

    /// A quote over (ephemeral key, static key) into `out`, or `no-tpm`.
    fn quote(&self, e: [u8; 32], s: [u8; 32], out: &mut [u8; 4096]) -> usize {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&e);
        msg[32..].copy_from_slice(&s);
        if cfg!(feature = "quote-wrong-key") {
            msg[63] ^= 1; // test: a quote that binds some other key
        }
        if let Some(attest) = self.attest
            && let Ok((0, n)) = send(attest, OP_QUOTE_FOR, &msg, out)
        {
            return n;
        }
        out[..6].copy_from_slice(b"no-tpm");
        6
    }

    /// Send FRAME[..n] behind its 2-byte length.
    fn send_raw(&mut self, conn: u32, n: usize) -> Result<(), u64> {
        let frame = unsafe { &*(&raw const FRAME) };
        let len = (n as u16).to_be_bytes();
        self.send_all(conn, &len)?;
        self.send_all(conn, &frame[..n])
    }

    fn send_all(&mut self, conn: u32, mut bytes: &[u8]) -> Result<(), u64> {
        let start = uptime();
        while !bytes.is_empty() {
            let n = net::send_data(self.mgmt, conn, bytes)?;
            bytes = &bytes[n..];
            if n == 0 {
                if uptime() - start > HANDSHAKE_TICKS {
                    return Err(err::TOO_LONG);
                }
                let mut events = [Event::default(); 4];
                let _ = net::wait(self.mgmt, 1, &mut events);
            }
        }
        Ok(())
    }

    /// Encrypt and send a frame of `kind` with `body`.
    fn send_frame(&mut self, kind: u8, body: &[u8]) {
        let Link::Up { conn, ref mut transport } = self.link else { return };
        let frame = unsafe { &mut *(&raw mut FRAME) };
        frame[0] = kind;
        frame[1..1 + body.len()].copy_from_slice(body);
        let Ok(n) = transport.send.encrypt(&[], frame, 1 + body.len()) else { return };
        if self.send_raw(conn, n).is_err() {
            self.down("send failed");
        }
    }

    /// Read what has arrived and handle every whole frame.
    fn read(&mut self, conn: u32, agent: &mut Agent) {
        let rx = unsafe { &mut *(&raw mut RX) };
        loop {
            if self.rx_len == rx.len() {
                return self.down("frame too long");
            }
            match net::recv(self.mgmt, conn, &mut rx[self.rx_len..]) {
                Ok(0) | Err(CODE_WOULD_BLOCK) => break,
                Ok(n) => self.rx_len += n,
                Err(_) => return self.down("closed"),
            }
            while self.rx_len >= 2 {
                let len = u16::from_be_bytes([rx[0], rx[1]]) as usize;
                if self.rx_len < 2 + len {
                    break;
                }
                let frame = unsafe { &mut *(&raw mut FRAME) };
                frame[..len].copy_from_slice(&rx[2..2 + len]);
                rx.copy_within(2 + len..self.rx_len, 0);
                self.rx_len -= 2 + len;
                self.frame(len, agent);
                if matches!(self.link, Link::Down { .. }) {
                    return;
                }
            }
        }
    }

    fn frame(&mut self, len: usize, agent: &mut Agent) {
        let frame = unsafe { &mut *(&raw mut FRAME) };
        match core::mem::replace(&mut self.link, Link::Down { retry: 0 }) {
            Link::Handshake { conn, initiator, .. } => match initiator.read_message(&mut frame[..len]) {
                Ok((transport, _)) => {
                    println!("agent: connected to the control plane");
                    self.link = Link::Up { conn, transport };
                    self.backoff = 10;
                    self.failures = 0;
                    if let Some(f) = self.fetch.as_mut() {
                        f.asked = false;
                    }
                    self.report(agent);
                }
                Err(_) => {
                    self.link = Link::Connecting { conn, since: uptime() }; // so `down` closes it
                    self.down("handshake failed: not the pinned control plane");
                }
            },
            Link::Up { conn, mut transport } => {
                let plain = transport.recv.decrypt(&[], frame, len);
                self.link = Link::Up { conn, transport };
                match plain {
                    Ok(n) if n > 0 => self.message(n, agent),
                    _ => self.down("a frame did not decrypt"),
                }
            }
            other => self.link = other,
        }
    }

    fn message(&mut self, n: usize, agent: &mut Agent) {
        let frame = unsafe { &*(&raw const FRAME) };
        let body = &frame[1..n];
        match frame[0] {
            b'S' => self.desired_state(body),
            b'C' if body.len() >= 36 => {
                let hash: [u8; 32] = body[..32].try_into().unwrap();
                let offset = u32::from_le_bytes(body[32..36].try_into().unwrap()) as u64;
                if let Some(f) = self.fetch.filter(|f| f.hash == hash)
                    && let Err(e) = slot::stage(agent.get(f.slot).id, offset, &body[36..])
                {
                    println!("agent: staging a fetched image failed: {}", err::name(e));
                    self.fetch = None;
                }
            }
            b'E' if body.len() == 32 + 176 + 256 => {
                let hash: [u8; 32] = body[..32].try_into().unwrap();
                let Some(f) = self.fetch.filter(|f| f.hash == hash) else { return };
                let fetched = unsafe { &mut *(&raw mut FETCHED) };
                fetched[f.slot].0.copy_from_slice(&body[32..208]);
                fetched[f.slot].1.copy_from_slice(&body[208..464]);
                let (sig, desc) = (&fetched[f.slot].0, &fetched[f.slot].1);
                let image = Image { name: "fetched", elf: &[], descriptor: desc, sig };
                if image.hash() != hash {
                    println!("agent: a fetched image's signature file isn't the one asked for");
                    self.fetch = None;
                    return;
                }
                println!("agent: fetched {} v{} into {}", core::str::from_utf8(image.service()).unwrap_or("?"), image.version(), agent.get(f.slot).name);
                self.fetch = None;
                agent.deploy(f.slot, Some(image), self.drain_for(image.service()));
            }
            kind => println!("agent: unknown frame type {}", kind),
        }
    }

    /// A signed desired-state document: check it and apply it if it is newer.
    fn desired_state(&mut self, body: &[u8]) {
        let refuse = |s: &mut Control, why: &'static str| {
            println!("agent: desired state refused: {}", why);
            s.refused = Some(why);
            s.next_report = 0;
        };
        let Some(len) = body.get(..4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize) else { return refuse(self, "malformed") };
        if len > MAX_DOC || body.len() != 4 + len + 64 {
            return refuse(self, "malformed");
        }
        let (doc, sig) = (&body[4..4 + len], &body[4 + len..]);
        let key = PublicKey::from_slice(CP_SIGN_PUB).expect("pinned key");
        let ok = Signature::from_slice(sig).is_ok_and(|sig| key.verify(doc, &sig).is_ok());
        if !ok {
            return refuse(self, "bad signature");
        }
        let mut lines = doc.split(|&b| b == b'\n');
        if lines.next() != Some(b"vanir-desired 1") {
            return refuse(self, "not a desired-state document");
        }
        let generation = lines.next().and_then(|l| l.strip_prefix(b"generation ")).and_then(number);
        let Some(generation) = generation else { return refuse(self, "no generation") };
        if generation <= self.generation {
            return refuse(self, "stale generation (replayed?)");
        }
        self.desired[..len].copy_from_slice(doc);
        self.desired_len = len;
        self.generation = generation;
        self.refused = None;
        self.next_report = 0;
        println!("agent: desired state generation {} applied", generation);
        self.end = doc.split(|&b| b == b'\n').any(|l| l == b"end");
    }

    /// The `drain <secs>` asked for `service` in the desired state, if any.
    fn drain_for(&self, service: &[u8]) -> Option<u64> {
        let doc = &self.desired[..self.desired_len];
        for line in doc.split(|&b| b == b'\n') {
            let words: [&[u8]; 8] = words(line);
            if (words[0] == b"live" || words[0] == b"stop") && words[1] == service {
                let at = words.iter().position(|&w| w == b"drain")?;
                return number(words[at + 1]);
            }
        }
        None
    }

    /// Move towards the desired state: one step per service per turn.
    fn reconcile(&mut self, agent: &mut Agent) {
        let doc = self.desired;
        for line in doc[..self.desired_len].split(|&b| b == b'\n') {
            let w = words(line);
            match w[0] {
                b"live" => {
                    let (service, slot_name, hash) = (w[1], w[2], unhex32(w[3]));
                    let Some(hash) = hash else { continue };
                    if agent.busy(service) {
                        continue;
                    }
                    let live = agent.live(service);
                    if live.is_some_and(|k| agent.get(k).image.is_some_and(|i| i.hash() == hash)) {
                        continue;
                    }
                    // Roll back to a stopped slot that still holds the wanted image.
                    let kept = (0..MAX_SLOTS).find(|&k| {
                        agent.slots[k].is_some_and(|s| s.state == State::Stopped && s.image.is_some_and(|i| i.hash() == hash))
                    });
                    if let Some(k) = kept {
                        agent.deploy(k, None, self.drain_for(service));
                        continue;
                    }
                    let Some(k) = core::str::from_utf8(slot_name).ok().and_then(|n| agent.find_slot(n)) else { continue };
                    match agent.get(k).state {
                        State::Empty if self.fetch.is_none() => {
                            self.fetch = Some(Fetch { slot: k, hash, asked: false });
                        }
                        State::Stopped | State::Failed => agent.commit(agent.get(k).service()),
                        _ => {}
                    }
                }
                b"stop" => {
                    let service = w[1];
                    if !agent.busy(service)
                        && let Some(k) = agent.live(service)
                    {
                        agent.drain(k, self.drain_for(service));
                    }
                }
                b"commit" => {
                    let service = w[1];
                    if !agent.busy(service) && agent.live(service).is_some() {
                        agent.commit(service);
                    }
                }
                _ => {}
            }
        }
        // Ask for the image being fetched, once per connection.
        if let Some(f) = self.fetch
            && !f.asked
            && self.connected()
        {
            let mut body = [0u8; 64];
            body[..32].copy_from_slice(&f.hash);
            let name = agent.get(f.slot).name.as_bytes();
            body[32..32 + name.len()].copy_from_slice(name);
            self.send_frame(b'G', &body[..32 + name.len()]);
            self.fetch.as_mut().unwrap().asked = true;
        }
    }

    fn report(&mut self, agent: &Agent) {
        let mut text = [0u8; 2048];
        let mut len = 0;
        let mut put = |line: &LineWriter| {
            let b = line.as_bytes();
            if len + b.len() + 1 <= text.len() {
                text[len..len + b.len()].copy_from_slice(b);
                text[len + b.len()] = b'\n';
                len += b.len() + 1;
            }
        };
        let mut line = LineWriter::new();
        let _ = write!(line, "report {}", self.generation);
        if let Some(why) = self.refused {
            let _ = write!(line, " refused {}", why);
        }
        put(&line);
        for s in agent.slots.iter().flatten() {
            let mut line = LineWriter::new();
            let service = core::str::from_utf8(s.service()).unwrap_or("?");
            let _ = write!(line, "slot {} {} {} ", s.name, if service.is_empty() { "-" } else { service }, s.version());
            match s.image {
                Some(i) => hex(&i.hash(), &mut line),
                None => {
                    let _ = line.write_str("-");
                }
            }
            let _ = write!(line, " {}", s.state.name());
            put(&line);
        }
        self.send_frame(b'R', &text[..len]);
        self.next_report = uptime() + REPORT_TICKS;
    }

    /// Pass on what telemetry has for the control plane.
    fn forward_telemetry(&mut self) {
        let Some(t) = self.telemetry else { return };
        let mut lines = [0u8; 4096];
        match send(t, telemetry::OP_PULL, &[], &mut lines) {
            Ok((0, n)) if n > 0 => self.send_frame(b'T', &lines[..n]),
            _ => {}
        }
    }
}

/// The first eight space-separated words of `line` (missing ones empty).
fn words(line: &[u8]) -> [&[u8]; 8] {
    let mut out: [&[u8]; 8] = [&[]; 8];
    for (o, w) in out.iter_mut().zip(line.split(|&b| b == b' ').filter(|w| !w.is_empty())) {
        *o = w;
    }
    out
}

/// The control plane's address, built in (`VANIR_CP_ADDR`, e.g. 10.0.2.2:7000).
fn cp_addr() -> ([u8; 4], u16) {
    let s = env!("VANIR_CP_ADDR").as_bytes();
    let (ip, port) = s.split_at(s.iter().position(|&b| b == b':').expect("VANIR_CP_ADDR: address:port"));
    let mut addr = [0u8; 4];
    for (a, part) in addr.iter_mut().zip(ip.split(|&b| b == b'.')) {
        *a = number(part).unwrap_or(0) as u8;
    }
    (addr, number(&port[1..]).unwrap_or(7000) as u16)
}
