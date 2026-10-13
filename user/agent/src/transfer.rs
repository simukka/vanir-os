//! Moving a service's volume to another node (RFD 3, P4 and P5), directly between the two
//! nodes' agents over the management network.
//!
//! - **Tickets** come in the signed desired state, one per node:
//!
//!   ```text
//!   transfer <service> send <peer node> <peer key> epoch <n> expires <secs>
//!   transfer <service> receive <peer node> <address:port> <peer key> epoch <n> expires <secs>
//!   ```
//!
//!   The peer's key is the static key its agent uses with the control plane (one per boot);
//!   the expiry counts from when we applied the document. A ticket missing from a later
//!   document is withdrawn: the connection closes.
//! - **The target dials the source.** The source listens on the management network's port 7
//!   only while it holds a `send` ticket, and accepts one connection.
//! - **Noise `IK`**, prologue `vanir-transfer 1`: the target knows the source's key from its
//!   ticket; its first message names the service. The source closes the connection unless the
//!   target's key and the service are the ones its ticket names.
//! - **Frames**, as with the control plane: a 2-byte big-endian length, then a Noise transport
//!   message whose first byte says what it is.
//!
//! One transfer at a time: tickets for a second one wait until the first is withdrawn.

use crate::lifecycle::Agent;
use noise::{Initiator, Responder, Transport};
use vanir_user::net::{self, CODE_WOULD_BLOCK, EV_ACCEPT, EV_CLOSED, EV_READ, EV_WRITE, Event};
use vanir_user::{LineWriter, err, println, uptime};

use core::fmt::Write;

/// Bound into the handshake: both sides must agree on what this is.
const PROLOGUE: &[u8] = b"vanir-transfer 1";
/// The management network port the source listens on.
pub const PORT: u16 = 7;
/// Largest frame: a block (4096), its number, counter and tag, and the Noise tag.
const MAX_FRAME: usize = 8192;
/// How long a connection and handshake may take.
const HANDSHAKE_TICKS: u64 = 500;
/// How long the target waits between attempts to reach the source.
const DIAL_RETRY_TICKS: u64 = 100;
/// Connections the source may close before answering, before the target gives up: one closed
/// early may only mean the source isn't listening yet (the management network's NAT accepts on
/// its behalf, then closes), but a source that refuses us closes every one.
const MAX_EARLY_CLOSES: u32 = 5;

static mut RX: [u8; MAX_FRAME + 2] = [0; MAX_FRAME + 2];
static mut FRAME: [u8; MAX_FRAME] = [0; MAX_FRAME];

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Send,
    Receive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Ticket {
    pub service: [u8; 32],
    pub role: Role,
    pub peer: [u8; 16],
    pub addr: [u8; 4],
    pub port: u16,
    pub key: [u8; 32],
    pub epoch: u64,
    /// The tick it expires at.
    pub expires: u64,
}

impl Ticket {
    /// A `transfer` line's words (see the module comment); `now` is when it was applied.
    pub fn parse(w: &[&[u8]; 10], now: u64) -> Option<Ticket> {
        let mut t = Ticket { service: vanir_user::block::service_name(w[1]), role: Role::Send, peer: [0; 16], addr: [0; 4], port: 0, key: [0; 32], epoch: 0, expires: 0 };
        if w[1].is_empty() || w[1].len() > 32 || w[3].len() > 16 {
            return None;
        }
        t.peer[..w[3].len()].copy_from_slice(w[3]);
        let rest = match w[2] {
            b"send" => &w[4..],
            b"receive" => {
                t.role = Role::Receive;
                (t.addr, t.port) = crate::control::address(w[4])?;
                &w[5..]
            }
            _ => return None,
        };
        t.key = crate::control::unhex32(rest[0])?;
        if rest[1] != b"epoch" || rest[3] != b"expires" {
            return None;
        }
        t.epoch = crate::control::number(rest[2])?;
        t.expires = now + crate::control::number(rest[4])? * 100;
        Some(t)
    }

    /// The same transfer (a later document repeating the ticket keeps it going).
    fn same(&self, other: &Ticket) -> bool {
        Ticket { expires: 0, ..*self } == Ticket { expires: 0, ..*other }
    }

    pub fn service(&self) -> &[u8] {
        &self.service[..self.service.iter().position(|&b| b == 0).unwrap_or(32)]
    }

    fn peer(&self) -> &str {
        core::str::from_utf8(&self.peer[..self.peer.iter().position(|&b| b == 0).unwrap_or(16)]).unwrap_or("?")
    }
}

/// Where the connection to the peer is.
enum Link {
    /// Source: waiting for the target to dial in.
    Listening,
    /// Target: not connected; dial at this tick.
    Dial { at: u64 },
    Connecting { conn: u32, since: u64 },
    /// Target: our first message is out.
    Initiated { conn: u32, since: u64, initiator: Initiator },
    /// Source: a connection came in; waiting for its first message.
    Accepted { conn: u32, since: u64 },
    Up { conn: u32, transport: Transport },
    /// Finished or given up: nothing more happens until the ticket is withdrawn.
    Closed,
}

/// What the transfer has done, as reported to the control plane.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Waiting,
    Connected,
    /// Given up, and why.
    Aborted(&'static str),
}

impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Phase::Waiting => "waiting",
            Phase::Connected => "connected",
            Phase::Aborted(_) => "aborted",
        }
    }
}

pub struct Transfer {
    pub ticket: Ticket,
    link: Link,
    pub phase: Phase,
    rx_len: usize,
    /// Target: connections closed before the source answered.
    early_closes: u32,
}

/// The node's side of every transfer: the listener, and the one transfer under way.
pub struct Transfers {
    mgmt: u64,
    listener: Option<u32>,
    /// We said `OP_READY` to the management stack (once, so connections reach us).
    ready: bool,
    pub current: Option<Transfer>,
    /// Something changed that the control plane should hear about.
    pub changed: bool,
}

impl Transfers {
    pub fn new(mgmt: u64) -> Transfers {
        Transfers { mgmt, listener: None, ready: false, current: None, changed: false }
    }

    /// The handles we want events for.
    pub fn busy(&self) -> bool {
        self.listener.is_some() || self.current.as_ref().is_some_and(|t| !matches!(t.link, Link::Closed | Link::Listening))
    }

    /// The tickets in a newly applied desired state: start new ones, keep repeated ones, and
    /// withdraw the rest.
    pub fn tickets(&mut self, doc: &[u8], now: u64) {
        let mut wanted = None;
        for line in doc.split(|&b| b == b'\n') {
            let w = crate::control::words(line);
            if w[0] == b"transfer" {
                match Ticket::parse(&w, now) {
                    Some(t) if wanted.is_none() => wanted = Some(t),
                    Some(_) => println!("agent: transfer: one at a time; ignoring a second ticket"),
                    None => println!("agent: transfer: a malformed ticket"),
                }
            }
        }
        if let Some(t) = &self.current
            && wanted.is_some_and(|w| t.ticket.same(&w))
        {
            return;
        }
        if let Some(t) = self.current.take() {
            println!("agent: transfer {}: ticket withdrawn", core::str::from_utf8(t.ticket.service()).unwrap_or("?"));
            self.close(&t);
            self.changed = true;
        }
        if let Some(ticket) = wanted {
            let shown = core::str::from_utf8(ticket.service()).unwrap_or("?");
            let link = match ticket.role {
                Role::Send => {
                    println!("agent: transfer {}: waiting for node {} to dial in", shown, ticket.peer());
                    Link::Listening
                }
                Role::Receive => {
                    println!("agent: transfer {}: dialing node {}", shown, ticket.peer());
                    Link::Dial { at: now }
                }
            };
            self.current = Some(Transfer { ticket, link, phase: Phase::Waiting, rx_len: 0, early_closes: 0 });
            self.changed = true;
        }
        self.keep_listener();
    }

    /// Listen while a `send` ticket wants it, and only then.
    fn keep_listener(&mut self) {
        let want = self.current.as_ref().is_some_and(|t| t.ticket.role == Role::Send && matches!(t.link, Link::Listening));
        match (want, self.listener) {
            (true, None) => match net::listen(self.mgmt, PORT) {
                Ok(h) => {
                    self.listener = Some(h);
                    if !self.ready {
                        self.ready = net::ready(self.mgmt).is_ok();
                    }
                }
                Err(e) => println!("agent: transfer: listening on port {}: {}", PORT, net::code_name(e)),
            },
            (false, Some(h)) => {
                let _ = net::close(self.mgmt, h);
                self.listener = None;
            }
            _ => {}
        }
    }

    fn close(&self, t: &Transfer) {
        if let Link::Connecting { conn, .. } | Link::Initiated { conn, .. } | Link::Accepted { conn, .. } | Link::Up { conn, .. } = t.link {
            let _ = net::close(self.mgmt, conn);
        }
    }

    /// Give up on the transfer, and say why.
    fn abort(&mut self, why: &'static str) {
        let Some(mut t) = self.current.take() else { return };
        println!("agent: transfer {}: aborted ({})", core::str::from_utf8(t.ticket.service()).unwrap_or("?"), why);
        self.close(&t);
        t.link = Link::Closed;
        t.phase = Phase::Aborted(why);
        self.current = Some(t);
        self.changed = true;
        self.keep_listener();
    }

    /// Move the connection along: dial, time out, expire.
    pub fn step(&mut self, now: u64, _agent: &mut Agent) {
        let Some(t) = &self.current else { return };
        if now >= t.ticket.expires && !matches!(t.link, Link::Closed) {
            return self.abort("ticket expired");
        }
        match t.link {
            Link::Dial { at } if now >= at => {
                let (addr, port) = (t.ticket.addr, t.ticket.port);
                let link = match net::connect(self.mgmt, addr, port) {
                    Ok(conn) => Link::Connecting { conn, since: now },
                    Err(e) => {
                        println!("agent: transfer: dialing node {}: {}", t.ticket.peer(), net::code_name(e));
                        Link::Dial { at: now + DIAL_RETRY_TICKS }
                    }
                };
                self.current.as_mut().unwrap().link = link;
            }
            // Until the source answers, it may not be listening yet: dial again.
            Link::Connecting { conn, since } if now - since > HANDSHAKE_TICKS => {
                let _ = net::close(self.mgmt, conn);
                self.current.as_mut().unwrap().link = Link::Dial { at: now };
            }
            Link::Initiated { since, .. } | Link::Accepted { since, .. } if now - since > HANDSHAKE_TICKS => self.abort("handshake timed out"),
            _ => {}
        }
    }

    /// An event on the management stack that isn't the control plane's.
    pub fn event(&mut self, e: Event, agent: &mut Agent) {
        if Some(e.handle) == self.listener && e.flags & EV_ACCEPT != 0 {
            return self.accept();
        }
        let Some(t) = &self.current else { return };
        let conn = match t.link {
            Link::Connecting { conn, .. } | Link::Initiated { conn, .. } | Link::Accepted { conn, .. } | Link::Up { conn, .. } => conn,
            _ => return,
        };
        if e.handle != conn {
            return;
        }
        if e.flags & EV_WRITE != 0 && matches!(t.link, Link::Connecting { .. }) {
            self.initiate(conn);
        }
        if e.flags & (EV_READ | EV_CLOSED) != 0 {
            self.read(conn, agent);
        }
    }

    /// Take every waiting connection: the first while we listen, none after.
    fn accept(&mut self) {
        let Some(listener) = self.listener else { return };
        while let Ok(Some(a)) = net::accept(self.mgmt, listener) {
            let t = self.current.as_mut().filter(|t| matches!(t.link, Link::Listening));
            let Some(t) = t else {
                let _ = net::close(self.mgmt, a.handle);
                continue;
            };
            println!("agent: transfer: a connection from {}.{}.{}.{}", a.addr[0], a.addr[1], a.addr[2], a.addr[3]);
            t.link = Link::Accepted { conn: a.handle, since: uptime() };
            t.rx_len = 0;
        }
        self.keep_listener();
    }

    /// The peer closed the connection. Before the source has answered, the target dials again,
    /// a few times; otherwise the transfer is over.
    fn closed(&mut self, conn: u32) {
        let t = self.current.as_mut().unwrap();
        if matches!(t.link, Link::Connecting { .. } | Link::Initiated { .. }) && t.early_closes < MAX_EARLY_CLOSES {
            t.early_closes += 1;
            t.link = Link::Dial { at: uptime() + DIAL_RETRY_TICKS };
            let _ = net::close(self.mgmt, conn);
            return;
        }
        let why = if t.early_closes > 0 { "the peer keeps closing the connection" } else { "the peer closed the connection" };
        self.abort(why)
    }

    /// Target: the TCP connection is up; send the first handshake message, naming the service.
    fn initiate(&mut self, conn: u32) {
        let t = self.current.as_mut().unwrap();
        let Ok(mut initiator) = Initiator::new(crate::control::node_key(), crate::control::random(), t.ticket.key, PROLOGUE) else {
            return self.abort("bad peer key in the ticket");
        };
        let frame = unsafe { &mut *(&raw mut FRAME) };
        let service = t.ticket.service;
        let Ok(n) = initiator.write_message(&service, frame) else { return self.abort("handshake message") };
        t.link = Link::Initiated { conn, since: uptime(), initiator };
        t.rx_len = 0;
        if self.send_raw(conn, n).is_err() {
            self.abort("send failed");
        }
    }

    /// Send FRAME[..n] behind its 2-byte length.
    fn send_raw(&mut self, conn: u32, n: usize) -> Result<(), u64> {
        let frame = unsafe { &*(&raw const FRAME) };
        self.send_all(conn, &(n as u16).to_be_bytes())?;
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
    #[allow(dead_code)]
    fn send_frame(&mut self, kind: u8, body: &[u8]) -> Result<(), ()> {
        let Some(Transfer { link: Link::Up { conn, transport }, .. }) = self.current.as_mut() else { return Err(()) };
        let conn = *conn;
        let frame = unsafe { &mut *(&raw mut FRAME) };
        frame[0] = kind;
        frame[1..1 + body.len()].copy_from_slice(body);
        let n = transport.send.encrypt(&[], frame, 1 + body.len()).map_err(|_| ())?;
        if self.send_raw(conn, n).is_err() {
            self.abort("send failed");
            return Err(());
        }
        Ok(())
    }

    /// Read what has arrived and handle every whole frame.
    fn read(&mut self, conn: u32, agent: &mut Agent) {
        let rx = unsafe { &mut *(&raw mut RX) };
        loop {
            let Some(t) = self.current.as_mut() else { return };
            if t.rx_len == rx.len() {
                return self.abort("frame too long");
            }
            match net::recv(self.mgmt, conn, &mut rx[t.rx_len..]) {
                Ok(0) | Err(CODE_WOULD_BLOCK) => return,
                Ok(n) => t.rx_len += n,
                Err(_) => return self.closed(conn),
            }
            while let Some(t) = self.current.as_mut()
                && t.rx_len >= 2
            {
                let len = u16::from_be_bytes([rx[0], rx[1]]) as usize;
                if t.rx_len < 2 + len {
                    break;
                }
                let frame = unsafe { &mut *(&raw mut FRAME) };
                frame[..len].copy_from_slice(&rx[2..2 + len]);
                rx.copy_within(2 + len..t.rx_len, 0);
                t.rx_len -= 2 + len;
                self.frame(conn, len, agent);
                if !self.current.as_ref().is_some_and(|t| matches!(t.link, Link::Up { .. } | Link::Initiated { .. } | Link::Accepted { .. })) {
                    return;
                }
            }
        }
    }

    fn frame(&mut self, conn: u32, len: usize, agent: &mut Agent) {
        let frame = unsafe { &mut *(&raw mut FRAME) };
        let t = self.current.as_mut().unwrap();
        let shown = core::str::from_utf8(t.ticket.service()).unwrap_or("?");
        match core::mem::replace(&mut t.link, Link::Closed) {
            Link::Accepted { .. } => {
                // Source: who is it, and for what?
                let mut responder = Responder::new(crate::control::node_key(), crate::control::random(), PROLOGUE);
                let Ok((key, payload)) = responder.read_message(&mut frame[..len]) else {
                    t.link = Link::Accepted { conn, since: 0 };
                    return self.abort("handshake failed");
                };
                if key != t.ticket.key || frame[payload] != t.ticket.service {
                    println!("agent: transfer {}: closed a connection: not the peer my ticket names", shown);
                    t.link = Link::Accepted { conn, since: 0 };
                    return self.abort("not the peer my ticket names");
                }
                let mut msg = [0u8; 64];
                let Ok((n, transport)) = responder.write_message(&[], &mut msg) else { return self.abort("handshake message") };
                frame[..n].copy_from_slice(&msg[..n]);
                t.link = Link::Up { conn, transport };
                if self.send_raw(conn, n).is_err() {
                    return self.abort("send failed");
                }
                self.connected(agent);
            }
            Link::Initiated { initiator, .. } => match initiator.read_message(&mut frame[..len]) {
                Ok((transport, _)) => {
                    t.link = Link::Up { conn, transport };
                    self.connected(agent);
                }
                Err(_) => {
                    t.link = Link::Accepted { conn, since: 0 }; // so `abort` closes it
                    self.abort("handshake failed: not the peer my ticket names")
                }
            },
            Link::Up { conn, mut transport } => {
                let plain = transport.recv.decrypt(&[], frame, len);
                t.link = Link::Up { conn, transport };
                match plain {
                    Ok(n) if n > 0 => self.message(n, agent),
                    _ => self.abort("a frame did not decrypt"),
                }
            }
            other => t.link = other,
        }
    }

    fn connected(&mut self, _agent: &mut Agent) {
        let t = self.current.as_mut().unwrap();
        println!("agent: transfer {}: connected to node {}", core::str::from_utf8(t.ticket.service()).unwrap_or("?"), t.ticket.peer());
        t.phase = Phase::Connected;
        self.changed = true;
    }

    fn message(&mut self, n: usize, _agent: &mut Agent) {
        let frame = unsafe { &*(&raw const FRAME) };
        println!("agent: transfer: unknown frame type {} ({} bytes)", frame[0], n);
    }

    /// The report line for the transfer under way, if any.
    pub fn report(&self, line: &mut LineWriter) -> bool {
        let Some(t) = &self.current else { return false };
        let role = if t.ticket.role == Role::Send { "send" } else { "receive" };
        let _ = write!(line, "transfer {} {} {}", core::str::from_utf8(t.ticket.service()).unwrap_or("?"), role, t.phase.name());
        if let Phase::Aborted(why) = t.phase {
            let _ = write!(line, " {}", why);
        }
        true
    }
}
