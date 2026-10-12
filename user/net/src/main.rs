//! The network stack task: smoltcp (ARP, IPv4, TCP, DHCP) over a NIC driver task, serving TCP
//! to service tasks over IPC (`vanir_user::net`).
//!
//! - Frames come from the driver in batches when it posts `NOTIFY_RX`, and go out one per
//!   message. Only we send to the driver, so the two can't deadlock.
//! - A task may listen only on the ports its manifest entry declares (the kernel vouches for
//!   that: `task_listen`), and only instances of one service share a port.
//! - smoltcp has no accept queue: one socket holds one connection. For each port in use we keep
//!   a few sockets listening; once one is connected we give it to the live instance of the
//!   port's service, which accepts it, and set another socket listening.
//! - Services wait in `OP_WAIT`, whose reply we hold until one of their handles has something
//!   to do. Everything else is answered at once.
//! - Before smoltcp sees a received frame we check it (`Gate`): blocked sources, bad
//!   checksums, and for each new connection the per-source cap, the port's connection cap and
//!   its cap on half-open connections, which drops the oldest handshake first (smoltcp has no
//!   SYN cookies).
//! - Routing (RFD 1, P3, P4): each service has one live instance, which gets its new
//!   connections; a task with `routes = true` changes it (`OP_ROUTE`, only to an instance that
//!   said `OP_READY`) and drains instances (`OP_DRAIN`): no new connections, an `EV_DRAIN`,
//!   and at the deadline a reset for what is still open (counted as `drain_forced`). The drain
//!   is answered once the instance says `OP_DONE` and has no connections left.
//! - Every table is fixed at build time: no heap.
//!
//! The same program runs the data stack (`net`, driver `nic`) and the management stack
//! (`mgmt-net`, driver `nic-mgmt`).

#![no_std]
#![no_main]

mod device;
mod filter;
mod guard;

use core::fmt::Write;
use device::Nic;
use guard::{Blocklist, Talkers};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::dhcpv4;
use smoltcp::socket::tcp::{self, State};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv4Cidr};
use vanir_user::net::*;
use vanir_user::nic::{self, NOTIFY_RX};
use vanir_user::telemetry::{self, DEFAULT_INTERVAL_TICKS, Record};
use vanir_user::{NOTIFY_POST, NOTIFY_TIMER, SYS_RECV, RECV_TIMEOUT, TICK_HZ, err, getpid, lookup, println, rdtsc, reply, sleep, syscall6, task_index, task_listen, task_name, uptime};

vanir_user::entry!(main);

/// Sockets in the pool, each with its own receive and transmit buffers.
const SOCKETS: usize = 96;
const BUFFER: usize = 4096;
const MAX_PORTS: usize = 8;
const MAX_SERVICES: usize = 8;
const MAX_INSTANCES: usize = 8;
/// The `port` of an outbound connection's `Use::Owned` (no listening port: `OP_CONNECT`).
const OUTBOUND: u8 = 0xff;
/// Local ports for outbound connections: 49152 and up.
const EPHEMERAL: u16 = 49152;
/// Sockets kept listening on each port in use.
const LISTENING: usize = 4;
/// Most half-open connections (handshakes in progress) per port; past it, a new SYN takes the
/// place of the oldest.
const HALF_OPEN: usize = 16;
/// A handshake not finished in this many ticks is dropped.
const HANDSHAKE_TICKS: u64 = 200;
/// Above these rates (per second, over a snapshot interval) we report an attack.
const SYN_FLOOD_PER_S: u64 = 300;
const LIMIT_DROPS_PER_S: u64 = 20;
/// A connection its instance doesn't accept in this many ticks is reset.
const ACCEPT_TICKS: u64 = 500;
/// A connection with nothing from the peer for this long is reset.
const IDLE: Duration = Duration::from_secs(60);
/// Look at the driver at least this often, in case it restarted and forgot to notify us.
const HOUSEKEEPING_TICKS: u64 = 100;
/// Share of each tick (percent) we may spend on received frames. Past it, frames wait in the
/// driver's ring until the next tick (the device drops what doesn't fit), so a flood can't
/// take the whole CPU from the services and the other stack.
const BUDGET_PERCENT: u64 = 50;

/// CPU time spent on received frames, measured with the TSC.
struct Budget {
    cycles_per_tick: u64,
    tick: u64,
    used: u64,
    /// Ticks in which the budget ran out, since the last load report, and in all.
    exhausted: u64,
    exhausted_total: u64,
    flagged: bool,
}

impl Budget {
    fn new() -> Budget {
        let cycles_per_tick = vanir_user::tsc_per_tick();
        Budget { cycles_per_tick, tick: 0, used: 0, exhausted: 0, exhausted_total: 0, flagged: false }
    }

    fn spend(&mut self, now: u64, cycles: u64) {
        if now != self.tick {
            (self.tick, self.used, self.flagged) = (now, 0, false);
        }
        self.used += cycles;
        if !self.left(now) && !self.flagged {
            self.flagged = true;
            self.exhausted += 1;
            self.exhausted_total += 1;
        }
    }

    fn left(&self, now: u64) -> bool {
        now != self.tick || self.used < self.cycles_per_tick * BUDGET_PERCENT / 100
    }
}

static mut NAME: [u8; 32] = [0; 32];

static mut RX_BUFFERS: [[u8; BUFFER]; SOCKETS] = [[0; BUFFER]; SOCKETS];
static mut TX_BUFFERS: [[u8; BUFFER]; SOCKETS] = [[0; BUFFER]; SOCKETS];
static mut SOCKET_STORAGE: [SocketStorage<'static>; SOCKETS + 1] = [SocketStorage::EMPTY; SOCKETS + 1];

/// What a pool socket is doing for us.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Use {
    Free,
    Listening { port: u8 },
    /// Connected, waiting for `instance` to accept it.
    Pending { port: u8, instance: u8 },
    Owned { port: u8, instance: u8 },
    /// Closed by its owner; smoltcp is finishing the close.
    Closing,
}

#[derive(Clone, Copy)]
struct Slot {
    handle: SocketHandle,
    /// Bumped whenever the slot changes hands, so old handles stop working.
    generation: u16,
    use_: Use,
    /// When `use_` last changed (ticks).
    since: u64,
    /// When a listening socket got its SYN.
    syn_since: Option<u64>,
    /// The owner was told to wait for room to send.
    want_write: bool,
    /// An owned connection was found reset (and counted).
    reset_seen: bool,
}

#[derive(Clone, Copy)]
struct Port {
    number: u16,
    service: u8,
    max_connections: u16,
    max_per_source: u16,
}

#[derive(Clone, Copy)]
struct Service {
    name: [u8; 32],
    len: usize,
    /// The instance new connections go to.
    live: Option<u8>,
}

#[derive(Clone, Copy)]
struct Instance {
    /// Task id, generation included: a restarted task is a new instance.
    id: u64,
    service: u8,
    /// Bumped when the entry is reused, for listener handles.
    generation: u16,
    ready: bool,
    drain: Option<Drain>,
    /// A drain finished: it gets no connections, and waits to be stopped.
    drained: bool,
    /// Ports (bit per `ports` entry) it listens on.
    listening: u8,
    /// Its `OP_WAIT`, if one is held: (deadline tick).
    waiting: Option<Option<u64>>,
    counters: InstanceCounters,
}

/// An instance being drained.
#[derive(Clone, Copy)]
struct Drain {
    /// Who asked; its `OP_DRAIN` is answered when the drain is over (0: answered already,
    /// `DRAIN_NOWAIT`).
    by: u64,
    deadline: u64,
    /// `EV_DRAIN` not yet delivered.
    tell: bool,
    /// The deadline passed and what was left got reset.
    forced: bool,
    /// The instance said `OP_DONE`.
    done: bool,
}

/// Per instance, cumulative (a restarted task is a new instance and starts from zero).
#[derive(Clone, Copy, Default)]
struct InstanceCounters {
    accepted: u64,
    /// Reset because the instance didn't accept them in time.
    refused: u64,
    /// Reset by the peer, or by us for being idle.
    reset: u64,
    bytes_in: u64,
    bytes_out: u64,
    drain_forced: u64,
}

/// The stack's own counters, cumulative.
#[derive(Clone, Copy, Default)]
struct Counters {
    ipv4_bad_checksum: u64,
    /// TCP segments for a port nobody listens on (smoltcp answers with a reset).
    tcp_no_listener: u64,
    /// Connections reset because their service had no live instance.
    refused_no_instance: u64,
    /// TSC cycles spent on received frames.
    cycles: u64,
    /// New connection attempts (SYNs) for our ports.
    syn: u64,
    /// Half-open connections dropped to make room for newer ones.
    half_open_dropped: u64,
    handshake_timeouts: u64,
    /// SYNs dropped because their source had `max_per_source` connections to the port.
    dropped_per_source: u64,
    /// SYNs dropped because the port had `max_connections`.
    dropped_max_connections: u64,
    /// Packets dropped because their source is on the blocklist.
    blocklist_hits: u64,
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    /// The DHCP client, unless the address is static.
    dhcp: Option<SocketHandle>,
    nic: Nic,
    name: &'static str,
    nic_name: &'static str,
    budget: Budget,
    /// Frames received when the load was last reported.
    reported_frames: u64,
    counters: Counters,
    /// Where counters and events go, if we may send there.
    telemetry: Option<u64>,
    interval: u64,
    next_snapshot: u64,
    /// `counters.cycles` at the last snapshot.
    snapshot_cycles: u64,
    /// Counters at the last snapshot, for rates.
    last: Counters,
    last_exhausted: u64,
    blocklist: Blocklist,
    talkers: Talkers,
    slots: [Slot; SOCKETS],
    ports: [Option<Port>; MAX_PORTS],
    services: [Option<Service>; MAX_SERVICES],
    instances: [Option<Instance>; MAX_INSTANCES],
    next_generation: u16,
    /// Connections handed to instances (accepted).
    handed_out: u64,
    /// The next local port for an outbound connection, as an offset from `EPHEMERAL`.
    next_local_port: u16,
}

fn instant(ticks: u64) -> Instant {
    Instant::from_millis((ticks * 10) as i64)
}

fn connection_handle(slot: usize, generation: u16) -> u32 {
    (slot as u32 + 1) | (generation as u32) << 16
}

const LISTENER: u32 = 0x8000;

fn listener_handle(instance: usize, port: usize, generation: u16) -> u32 {
    LISTENER | (instance as u32) << 4 | port as u32 | (generation as u32) << 16
}

impl Stack {
    fn socket(&mut self, slot: usize) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.slots[slot].handle)
    }

    fn set_use(&mut self, slot: usize, use_: Use, now: u64) {
        let s = &mut self.slots[slot];
        if matches!(use_, Use::Owned { .. } | Use::Free | Use::Closing) {
            s.generation = s.generation.wrapping_add(1).max(1);
        }
        s.use_ = use_;
        s.since = now;
        s.syn_since = None;
        s.want_write = false;
        s.reset_seen = false;
    }

    /// Reset a connection and give its slot back.
    fn reset(&mut self, slot: usize, now: u64) {
        self.socket(slot).abort();
        self.set_use(slot, Use::Free, now);
    }

    /// A free socket: closed ones first, then one in TIME-WAIT (which we cut short).
    fn free_slot(&mut self) -> Option<usize> {
        let mut time_wait = None;
        for i in 0..SOCKETS {
            if self.slots[i].use_ != Use::Free {
                continue;
            }
            let s = self.socket(i);
            match s.state() {
                // Closed with an endpoint still set: an RST is waiting to go out.
                State::Closed if s.remote_endpoint().is_none() => return Some(i),
                State::TimeWait => time_wait = time_wait.or(Some(i)),
                _ => {}
            }
        }
        time_wait
    }

    fn listen_on(&mut self, port: usize, now: u64) -> bool {
        let Some(i) = self.free_slot() else { return false };
        let number = self.ports[port].unwrap().number;
        let s = self.socket(i);
        s.abort();
        if s.listen(number).is_err() {
            return false;
        }
        self.set_use(i, Use::Listening { port: port as u8 }, now);
        true
    }

    // ---- Instances, services and ports ----------------------------------------------------

    fn instance_of(&self, sender: u64) -> Option<usize> {
        self.instances.iter().position(|i| i.is_some_and(|i| i.id == sender))
    }

    /// The caller's instance, made on first use. An earlier incarnation of the same task (it
    /// was restarted) is forgotten first.
    fn instance_for(&mut self, sender: u64, now: u64) -> Result<usize, u64> {
        if let Some(k) = self.instance_of(sender) {
            return Ok(k);
        }
        if let Some(k) = self.instances.iter().position(|i| i.is_some_and(|i| task_index(i.id) == task_index(sender))) {
            self.forget(k, now);
        }
        let info = task_listen(sender).map_err(|_| CODE_NOT_ALLOWED)?;
        if info.count == 0 && !info.may_connect() {
            return Err(CODE_NOT_ALLOWED);
        }
        let service = self.service_for(info.service()).ok_or(CODE_NO_SOCKETS)?;
        let k = self.instances.iter().position(Option::is_none).ok_or(CODE_NO_SOCKETS)?;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.instances[k] = Some(Instance {
            id: sender,
            service: service as u8,
            generation: self.next_generation,
            ready: false,
            listening: 0,
            drain: None,
            drained: false,
            waiting: None,
            counters: InstanceCounters::default(),
        });
        Ok(k)
    }

    fn service_for(&mut self, name: &[u8]) -> Option<usize> {
        if let Some(s) = self.services.iter().position(|s| s.is_some_and(|s| &s.name[..s.len] == name)) {
            return Some(s);
        }
        let s = self.services.iter().position(Option::is_none)?;
        let mut service = Service { name: [0; 32], len: name.len().min(32), live: None };
        service.name[..service.len].copy_from_slice(&name[..service.len]);
        self.services[s] = Some(service);
        Some(s)
    }

    fn port_for(&mut self, number: u16, service: usize, max_connections: u16, max_per_source: u16) -> Option<usize> {
        if let Some(p) = self.ports.iter().position(|p| p.is_some_and(|p| p.number == number)) {
            // The kernel lets only instances of one service declare a port.
            return (self.ports[p].unwrap().service as usize == service).then_some(p);
        }
        let p = self.ports.iter().position(Option::is_none)?;
        self.ports[p] = Some(Port { number, service: service as u8, max_connections, max_per_source });
        Some(p)
    }

    /// An instance has gone (died, or was restarted): reset its connections, drop its listeners.
    fn forget(&mut self, k: usize, now: u64) {
        for i in 0..SOCKETS {
            if matches!(self.slots[i].use_, Use::Owned { instance, .. } | Use::Pending { instance, .. } if instance as usize == k) {
                self.reset(i, now);
            }
        }
        if let Some(d) = self.instances[k].unwrap().drain
            && d.by != 0
        {
            let forced = self.instances[k].unwrap().counters.drain_forced;
            let _ = reply(d.by, CODE_OK, &forced.to_le_bytes()); // gone counts as drained
        }
        let instance = self.instances[k].take().unwrap();
        let service = self.services[instance.service as usize].as_mut().unwrap();
        if service.live == Some(k as u8) {
            service.live = None;
        }
        let mut name = [0u8; 32];
        println!("{}: instance {} is gone", self.name, task_name(instance.id, &mut name).unwrap_or("?"));
    }

    fn name_of(&self, service: usize) -> &str {
        let s = self.services[service].as_ref().unwrap();
        core::str::from_utf8(&s.name[..s.len]).unwrap_or("?")
    }

    // ---- Keeping sockets in order ---------------------------------------------------------

    /// Run after each poll: hand out new connections, drop stale handshakes, free closed
    /// sockets, and keep each port in use listening.
    fn tend(&mut self, now: u64) {
        for i in 0..SOCKETS {
            let state = self.socket(i).state();
            match self.slots[i].use_ {
                Use::Listening { port } => match state {
                    State::Listen => {}
                    State::SynReceived => {
                        let since = *self.slots[i].syn_since.get_or_insert(now);
                        if now - since > HANDSHAKE_TICKS {
                            self.counters.handshake_timeouts += 1;
                            self.reset(i, now);
                        }
                    }
                    State::Closed => self.set_use(i, Use::Free, now),
                    _ => self.hand_out(i, port as usize, now),
                },
                Use::Pending { instance, .. } if state == State::Closed || now - self.slots[i].since > ACCEPT_TICKS => {
                    if state != State::Closed {
                        self.instances[instance as usize].as_mut().unwrap().counters.refused += 1;
                    }
                    self.reset(i, now);
                }
                Use::Owned { instance, .. } if state == State::Closed && !self.slots[i].reset_seen => {
                    self.slots[i].reset_seen = true;
                    self.instances[instance as usize].as_mut().unwrap().counters.reset += 1;
                }
                Use::Closing if matches!(state, State::Closed | State::TimeWait) => self.set_use(i, Use::Free, now),
                _ => {}
            }
        }
        for p in 0..MAX_PORTS {
            let Some(port) = self.ports[p] else { continue };
            let in_use = self.instances.iter().flatten().any(|i| i.listening & 1 << p != 0);
            let (mut listening, mut half_open, mut connections) = (0, 0, 0);
            for i in 0..SOCKETS {
                match self.slots[i].use_ {
                    Use::Listening { port } if port as usize == p => {
                        if !in_use {
                            self.reset(i, now);
                        } else {
                            match self.socket(i).state() {
                                State::Listen => listening += 1,
                                State::SynReceived => half_open += 1,
                                _ => connections += 1,
                            }
                        }
                    }
                    Use::Pending { port, .. } | Use::Owned { port, .. } if port as usize == p => connections += 1,
                    _ => {}
                }
            }
            let room = (port.max_connections as usize).saturating_sub(connections + half_open);
            let target = LISTENING.min(HALF_OPEN.saturating_sub(half_open)).min(room);
            while in_use && listening < target && self.listen_on(p, now) {
                listening += 1;
            }
        }
    }

    /// A listening socket is connected: give it to the live instance of the port's service.
    fn hand_out(&mut self, slot: usize, port: usize, now: u64) {
        let service = self.ports[port].unwrap().service as usize;
        let live = self.services[service].unwrap().live.map(|k| k as usize);
        match live.filter(|&k| self.instances[k].is_some_and(|i| i.listening & 1 << port != 0)) {
            Some(k) => self.set_use(slot, Use::Pending { port: port as u8, instance: k as u8 }, now),
            None => {
                self.counters.refused_no_instance += 1;
                self.reset(slot, now);
            }
        }
    }

    /// What instance `k`'s handles have to report, into `out`; returns how many.
    fn events(&mut self, k: usize, out: &mut [Event]) -> usize {
        let instance = self.instances[k].unwrap();
        let mut n = 0;
        let mut push = |e: Event| {
            if n < out.len() {
                out[n] = e;
                n += 1;
            }
        };
        for p in 0..MAX_PORTS {
            if instance.listening & 1 << p != 0
                && self.slots.iter().any(|s| s.use_ == Use::Pending { port: p as u8, instance: k as u8 })
            {
                push(Event { handle: listener_handle(k, p, instance.generation), flags: EV_ACCEPT });
            }
        }
        for i in 0..SOCKETS {
            let Use::Owned { instance: owner, .. } = self.slots[i].use_ else { continue };
            if owner as usize != k {
                continue;
            }
            let want_write = self.slots[i].want_write;
            let s = self.socket(i);
            let mut flags = 0;
            // An outbound connection still in its handshake can't receive yet, but isn't closed.
            if s.can_recv() || (!s.may_recv() && s.state() != State::SynSent) {
                flags |= EV_READ;
            }
            if s.state() == State::Closed {
                flags |= EV_CLOSED;
            }
            if want_write && s.can_send() {
                flags |= EV_WRITE;
                self.slots[i].want_write = false;
            }
            if flags != 0 {
                push(Event { handle: connection_handle(i, self.slots[i].generation), flags });
            }
        }
        if let Some(d) = self.instances[k].as_mut().unwrap().drain.as_mut()
            && d.tell
        {
            d.tell = false;
            push(Event { handle: 0, flags: EV_DRAIN });
        }
        n
    }

    /// Answer every held `OP_WAIT` that has events, or whose time is up.
    fn serve_waiters(&mut self, now: u64) {
        let mut events = [Event::default(); 256];
        for k in 0..MAX_INSTANCES {
            let Some(Instance { id, waiting: Some(deadline), .. }) = self.instances[k] else { continue };
            let n = self.events(k, &mut events);
            if n == 0 && deadline.is_none_or(|d| now < d) {
                continue;
            }
            self.instances[k].as_mut().unwrap().waiting = None;
            let bytes = unsafe { core::slice::from_raw_parts(events.as_ptr() as *const u8, n * core::mem::size_of::<Event>()) };
            if reply(id, CODE_OK, bytes) == Err(err::DEAD) {
                self.forget(k, now);
            }
        }
    }

    /// The earliest held `OP_WAIT` or drain deadline.
    fn next_deadline(&self) -> Option<u64> {
        let drains = self.instances.iter().flatten().filter_map(|i| i.drain.filter(|d| !d.forced).map(|d| d.deadline));
        self.instances.iter().flatten().filter_map(|i| i.waiting.flatten()).chain(drains).min()
    }

    // ---- Requests ---------------------------------------------------------------------------

    /// The pool slot a connection handle names, if `sender` owns it.
    fn connection(&self, sender: u64, handle: u32) -> Result<usize, u64> {
        let index = (handle & 0xffff) as usize;
        if handle & LISTENER != 0 || index == 0 || index > SOCKETS {
            return Err(CODE_BAD_HANDLE);
        }
        let slot = &self.slots[index - 1];
        match slot.use_ {
            Use::Owned { instance, .. }
                if slot.generation == (handle >> 16) as u16 && self.instances[instance as usize].is_some_and(|i| i.id == sender) =>
            {
                Ok(index - 1)
            }
            _ => Err(CODE_BAD_HANDLE),
        }
    }

    /// The (instance, port) a listener handle names, if `sender` holds it.
    fn listener(&self, sender: u64, handle: u32) -> Result<(usize, usize), u64> {
        let (k, p) = (((handle >> 4) & 0x7ff) as usize, (handle & 0xf) as usize);
        if handle & LISTENER == 0 || k >= MAX_INSTANCES || p >= MAX_PORTS {
            return Err(CODE_BAD_HANDLE);
        }
        match self.instances[k] {
            Some(i) if i.id == sender && i.generation == (handle >> 16) as u16 && i.listening & 1 << p != 0 => Ok((k, p)),
            _ => Err(CODE_BAD_HANDLE),
        }
    }

    /// Handle one request. Returns the reply (code, length in `out`), or None if it is held.
    fn request(&mut self, sender: u64, op: u64, msg: &[u8], out: &mut [u8; 4096], now: u64) -> Option<(u64, usize)> {
        let word = |at: usize| msg.get(at..at + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
        let r = match op {
            OP_LISTEN => {
                let Some(port) = msg.get(..2).map(|b| u16::from_le_bytes([b[0], b[1]])) else { return Some((CODE_BAD_OP, 0)) };
                self.listen(sender, port, now).map(|h| {
                    out[..4].copy_from_slice(&h.to_le_bytes());
                    4
                })
            }
            OP_WAIT => {
                let ticks = msg.get(..8).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                let Some(k) = self.instance_of(sender) else { return Some((CODE_BAD_HANDLE, 0)) };
                self.instances[k].as_mut().unwrap().waiting = Some((ticks != 0).then(|| now + ticks));
                return None; // answered by serve_waiters
            }
            OP_ACCEPT => word(0).ok_or(CODE_BAD_OP).and_then(|h| self.listener(sender, h)).and_then(|(k, p)| {
                let pending = Use::Pending { port: p as u8, instance: k as u8 };
                let Some(i) = (0..SOCKETS).filter(|&i| self.slots[i].use_ == pending).min_by_key(|&i| self.slots[i].since) else {
                    return Err(CODE_WOULD_BLOCK);
                };
                self.set_use(i, Use::Owned { port: p as u8, instance: k as u8 }, now);
                self.handed_out += 1;
                self.instances[k].as_mut().unwrap().counters.accepted += 1;
                #[cfg(feature = "crash-after-50-connections")]
                if self.handed_out == 50 && getpid() >> 16 == 0 {
                    println!("{}: crashing after handing out 50 connections", self.name);
                    unsafe { core::ptr::read_volatile(0x10 as *const u8) };
                }
                let remote = self.socket(i).remote_endpoint().unwrap();
                let addr = match remote.addr {
                    smoltcp::wire::IpAddress::Ipv4(a) => a.octets(),
                };
                let accepted = Accepted { handle: connection_handle(i, self.slots[i].generation), addr, port: remote.port, _pad: 0 };
                let bytes = unsafe { core::slice::from_raw_parts(&accepted as *const Accepted as *const u8, core::mem::size_of::<Accepted>()) };
                out[..bytes.len()].copy_from_slice(bytes);
                Ok(bytes.len())
            }),
            OP_RECV => {
                let (Some(h), Some(max)) = (word(0), word(4)) else { return Some((CODE_BAD_OP, 0)) };
                self.connection(sender, h).and_then(|i| {
                    let s = self.socket(i);
                    let max = (max as usize).min(out.len());
                    let r = match s.recv_slice(&mut out[..max]) {
                        Ok(0) if s.state() == State::SynSent => Err(CODE_WOULD_BLOCK),
                        Ok(0) if !s.may_recv() => Err(CODE_CLOSED),
                        Ok(0) => Err(CODE_WOULD_BLOCK),
                        Ok(n) => Ok(n),
                        Err(_) => Err(CODE_CLOSED),
                    };
                    if let (Ok(n), Use::Owned { instance, .. }) = (r, self.slots[i].use_) {
                        self.instances[instance as usize].as_mut().unwrap().counters.bytes_in += n as u64;
                    }
                    r
                })
            }
            OP_SEND => word(0).ok_or(CODE_BAD_OP).and_then(|h| self.connection(sender, h)).and_then(|i| {
                let s = self.socket(i);
                if !s.may_send() {
                    return Err(CODE_CLOSED);
                }
                let n = s.send_slice(&msg[4..]).map_err(|_| CODE_CLOSED)?;
                if n < msg.len() - 4 {
                    self.slots[i].want_write = true;
                }
                if let Use::Owned { instance, .. } = self.slots[i].use_ {
                    self.instances[instance as usize].as_mut().unwrap().counters.bytes_out += n as u64;
                }
                out[..4].copy_from_slice(&(n as u32).to_le_bytes());
                Ok(4)
            }),
            OP_CLOSE | OP_SHUTDOWN => {
                let Some(h) = word(0) else { return Some((CODE_BAD_OP, 0)) };
                if h & LISTENER != 0 && op == OP_CLOSE {
                    self.listener(sender, h).map(|(k, p)| {
                        self.instances[k].as_mut().unwrap().listening &= !(1 << p);
                        // Connections it never accepted go to the live instance, if it listens.
                        for i in 0..SOCKETS {
                            if self.slots[i].use_ == (Use::Pending { port: p as u8, instance: k as u8 }) {
                                self.hand_out(i, p, now);
                            }
                        }
                        0
                    })
                } else {
                    self.connection(sender, h).map(|i| {
                        self.socket(i).close();
                        if op == OP_CLOSE {
                            self.set_use(i, Use::Closing, now);
                        }
                        0
                    })
                }
            }
            OP_ROUTE | OP_DRAIN => {
                let routes = task_listen(sender).is_ok_and(|i| i.may_route());
                let id = msg.get(..8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                let ticks = msg.get(8..16).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
                match (routes, id, op) {
                    (false, _, _) => {
                        let mut name = [0u8; 32];
                        println!("{}: {} may not route", self.name, task_name(sender, &mut name).unwrap_or("?"));
                        Err(CODE_NOT_ALLOWED)
                    }
                    (_, None, _) | (_, _, OP_DRAIN) if ticks.is_none() => Err(CODE_BAD_OP),
                    (_, Some(id), OP_ROUTE) => self.route(id),
                    (_, Some(id), _) => {
                        let flags = msg.get(16..24).map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()));
                        let nowait = flags & DRAIN_NOWAIT != 0;
                        match self.drain(if nowait { 0 } else { sender }, id, ticks.unwrap(), now) {
                            None if nowait => Ok(0),
                            other => return other,
                        }
                    }
                    _ => Err(CODE_BAD_OP),
                }
            }
            OP_CONNECT => match (msg.get(..4), msg.get(4..6)) {
                (Some(addr), Some(port)) => {
                    let addr: [u8; 4] = addr.try_into().unwrap();
                    self.connect(sender, addr, u16::from_le_bytes([port[0], port[1]]), now).map(|h| {
                        out[..4].copy_from_slice(&h.to_le_bytes());
                        4
                    })
                }
                _ => Err(CODE_BAD_OP),
            },
            OP_STATUS => {
                let routes = task_listen(sender).is_ok_and(|i| i.may_route());
                match msg.get(..8).map(|b| u64::from_le_bytes(b.try_into().unwrap())) {
                    _ if !routes => Err(CODE_NOT_ALLOWED),
                    None => Err(CODE_BAD_OP),
                    Some(id) => {
                        let (status, forced) = self.status(id);
                        out[..8].copy_from_slice(&status.to_le_bytes());
                        out[8..16].copy_from_slice(&forced.to_le_bytes());
                        Ok(16)
                    }
                }
            }
            OP_DONE => match self.instance_of(sender) {
                Some(k) => {
                    if let Some(d) = self.instances[k].as_mut().unwrap().drain.as_mut() {
                        d.done = true;
                    }
                    Ok(0)
                }
                None => Err(CODE_BAD_HANDLE),
            },
            OP_BLOCK => {
                let routes = task_listen(sender).is_ok_and(|i| i.may_route());
                match msg.get(..16) {
                    _ if !routes => Err(CODE_NOT_ALLOWED),
                    None => Err(CODE_BAD_OP),
                    Some(m) => {
                        let addr: [u8; 4] = m[..4].try_into().unwrap();
                        let prefix = u32::from_le_bytes(m[4..8].try_into().unwrap()).min(32);
                        let ticks = u64::from_le_bytes(m[8..16].try_into().unwrap());
                        self.blocklist.add(addr, prefix, now + ticks, now);
                        println!("{}: blocking {}.{}.{}.{}/{} for {} ticks", self.name, addr[0], addr[1], addr[2], addr[3], prefix, ticks);
                        let mut range = Text::new();
                        let _ = write!(range, "{}.{}.{}.{}/{}", addr[0], addr[1], addr[2], addr[3], prefix);
                        let mut r = Record::new("blocklist_added");
                        r.text("range", range.as_str()).num("ticks", ticks);
                        self.event(&r);
                        Ok(0)
                    }
                }
            }
            OP_READY => self.instance_for(sender, now).map(|k| {
                let instance = self.instances[k].as_mut().unwrap();
                instance.ready = true;
                let service = instance.service as usize;
                if self.services[service].unwrap().live.is_none() {
                    self.services[service].as_mut().unwrap().live = Some(k as u8);
                    let mut name = [0u8; 32];
                    let instance = task_name(sender, &mut name).unwrap_or("?");
                    println!("{}: {} is live for service {}", self.name, instance, self.name_of(service));
                    let mut r = Record::new("route_changed");
                    r.text("service", self.name_of(service)).text("live", instance);
                    self.event(&r);
                }
                0
            }),
            _ => Err(CODE_BAD_OP),
        };
        Some(match r {
            Ok(n) => (CODE_OK, n),
            Err(code) => (code, 0),
        })
    }

    /// Open an outbound connection for `sender` (`connects = true`, RFD 2, P7: the node dials
    /// out). It is owned at once, like an accepted connection; sending waits (`EV_WRITE`) until
    /// the handshake is done, and a refused connection reads as closed.
    fn connect(&mut self, sender: u64, addr: [u8; 4], port: u16, now: u64) -> Result<u32, u64> {
        let mut name = [0u8; 32];
        if !task_listen(sender).is_ok_and(|i| i.may_connect()) {
            println!("{}: {} may not connect out", self.name, task_name(sender, &mut name).unwrap_or("?"));
            return Err(CODE_NOT_ALLOWED);
        }
        let k = self.instance_for(sender, now)?;
        let i = self.free_slot().ok_or(CODE_NO_SOCKETS)?;
        let local = EPHEMERAL + self.next_local_port % 16384;
        self.next_local_port = self.next_local_port.wrapping_add(1);
        let handle = self.slots[i].handle;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.abort();
        let remote = (IpAddress::Ipv4(Ipv4Address::from(addr)), port);
        if socket.connect(self.iface.context(), remote, local).is_err() {
            return Err(CODE_NOT_READY); // no address yet (DHCP), or a bad endpoint
        }
        self.set_use(i, Use::Owned { port: OUTBOUND, instance: k as u8 }, now);
        self.slots[i].want_write = true;
        println!(
            "{}: {} connects to {}.{}.{}.{}:{}",
            self.name,
            task_name(sender, &mut name).unwrap_or("?"),
            addr[0],
            addr[1],
            addr[2],
            addr[3],
            port
        );
        Ok(connection_handle(i, self.slots[i].generation))
    }

    /// Instance `id`'s `STATUS_*`, and its drain_forced count.
    fn status(&self, id: u64) -> (u64, u64) {
        let Some(k) = self.instance_of(id) else { return (STATUS_UNKNOWN, 0) };
        let i = self.instances[k].unwrap();
        let live = self.services[i.service as usize].is_some_and(|s| s.live == Some(k as u8));
        let status = match () {
            _ if i.drained => STATUS_DRAINED,
            _ if i.drain.is_some() => STATUS_DRAINING,
            _ if live => STATUS_LIVE,
            _ if i.ready => STATUS_READY,
            _ => STATUS_STARTING,
        };
        (status, i.counters.drain_forced)
    }

    /// Make instance `id` its service's live instance.
    fn route(&mut self, id: u64) -> Result<usize, u64> {
        let mut name = [0u8; 32];
        let instance = task_name(id, &mut name).unwrap_or("?");
        let Some(k) = self.instance_of(id).filter(|&k| self.instances[k].unwrap().ready && self.instances[k].unwrap().drain.is_none()) else {
            println!("{}: {} can't be made live: it hasn't said it is ready", self.name, instance);
            return Err(CODE_NOT_READY);
        };
        let service = self.instances[k].unwrap().service as usize;
        let previous = self.services[service].unwrap().live;
        self.services[service].as_mut().unwrap().live = Some(k as u8);
        println!("{}: {} is live for service {}", self.name, instance, self.name_of(service));
        let mut previous_name = [0u8; 32];
        let previous = previous.filter(|&p| p as usize != k).and_then(|p| self.instances[p as usize]);
        let previous = previous.map_or("none", |p| task_name(p.id, &mut previous_name).unwrap_or("?"));
        let mut r = Record::new("route_changed");
        r.text("service", self.name_of(service)).text("live", instance).text("previous", previous);
        self.event(&r);
        Ok(0)
    }

    /// Start draining instance `id`; the reply to `by` waits until it is drained.
    fn drain(&mut self, by: u64, id: u64, ticks: u64, now: u64) -> Option<(u64, usize)> {
        let mut name = [0u8; 32];
        let Some(k) = self.instance_of(id).filter(|&k| self.instances[k].unwrap().drain.is_none()) else {
            return Some((CODE_BAD_HANDLE, 0));
        };
        let instance = self.instances[k].as_mut().unwrap();
        instance.drain = Some(Drain { by, deadline: now + ticks, tell: true, forced: false, done: false });
        let service = instance.service as usize;
        if self.services[service].unwrap().live == Some(k as u8) {
            self.services[service].as_mut().unwrap().live = None; // new connections get a reset
        }
        let instance = task_name(id, &mut name).unwrap_or("?");
        println!("{}: draining {} (deadline in {} ticks)", self.name, instance, ticks);
        let mut r = Record::new("drain_started");
        r.text("instance", instance).num("deadline_ticks", ticks);
        self.event(&r);
        None
    }

    /// Move drains along: reset what is left at the deadline, and answer the drains that are
    /// over (the instance is done and has no connections).
    fn tend_drains(&mut self, now: u64) {
        for k in 0..MAX_INSTANCES {
            let Some(Instance { id, drain: Some(d), .. }) = self.instances[k] else { continue };
            let mine = |u: Use| matches!(u, Use::Owned { instance, .. } | Use::Pending { instance, .. } if instance as usize == k);
            if now >= d.deadline && !d.forced {
                let mut forced = 0;
                for i in 0..SOCKETS {
                    if mine(self.slots[i].use_) && self.socket(i).state() != State::Closed {
                        self.socket(i).abort();
                        forced += 1;
                    }
                }
                let instance = self.instances[k].as_mut().unwrap();
                instance.counters.drain_forced += forced;
                instance.drain.as_mut().unwrap().forced = true;
            }
            let open = (0..SOCKETS).any(|i| mine(self.slots[i].use_));
            if d.done && !open {
                let forced = self.instances[k].unwrap().counters.drain_forced;
                self.instances[k].as_mut().unwrap().drain = None;
                self.instances[k].as_mut().unwrap().drained = true;
                self.instances[k].as_mut().unwrap().listening = 0;
                if d.by != 0 {
                    let _ = reply(d.by, CODE_OK, &forced.to_le_bytes());
                }
                let mut name = [0u8; 32];
                let instance = task_name(id, &mut name).unwrap_or("?");
                println!("{}: {} is drained ({} connections reset at the deadline)", self.name, instance, forced);
                let mut r = Record::new("drained");
                r.text("instance", instance).num("drain_forced", forced);
                self.event(&r);
            }
        }
    }

    fn listen(&mut self, sender: u64, port: u16, now: u64) -> Result<u32, u64> {
        let mut name = [0u8; 32];
        let info = task_listen(sender).map_err(|_| CODE_NOT_ALLOWED)?;
        let Some((max_connections, per_source)) = info.port(port) else {
            let task = task_name(sender, &mut name).unwrap_or("?");
            println!("{}: {} may not listen on port {}: not in its manifest entry", self.name, task, port);
            let mut r = Record::new("listen_refused");
            r.text("task", task).num("port", port as u64);
            self.event(&r);
            return Err(CODE_NOT_ALLOWED);
        };
        let k = self.instance_for(sender, now)?;
        let service = self.instances[k].unwrap().service as usize;
        let p = self.port_for(port, service, max_connections, per_source).ok_or(CODE_NOT_ALLOWED)?;
        let instance = self.instances[k].as_mut().unwrap();
        instance.listening |= 1 << p;
        println!("{}: {} listens on port {} (service {})", self.name, task_name(sender, &mut name).unwrap_or("?"), port, self.name_of(service));
        Ok(listener_handle(k, p, self.instances[k].unwrap().generation))
    }

    // ---- The interface ------------------------------------------------------------------------

    /// Take a batch of frames from the driver. Returns whether there may be more.
    fn receive(&mut self) -> bool {
        match self.nic.fetch() {
            Ok(0) => false,
            Ok(_) => {
                let mut gate = Gate {
                    slots: &mut self.slots,
                    sockets: &mut self.sockets,
                    ports: &self.ports,
                    counters: &mut self.counters,
                    blocklist: &self.blocklist,
                    talkers: &mut self.talkers,
                    now: uptime(),
                    promised: [0; MAX_PORTS],
                };
                self.nic.rx.retain(|frame| gate.admit(frame));
                true
            }
            Err(_) => {
                self.find_driver();
                false
            }
        }
    }

    /// Under load, say so once per housekeeping period: how often the budget ran out, and how
    /// often the driver found its ring full (the device drops frames then).
    fn report_load(&mut self) {
        let frames = self.nic.received - core::mem::replace(&mut self.reported_frames, self.nic.received);
        // A tick or two over budget is a preemption mid-batch, not load.
        if self.budget.exhausted < HOUSEKEEPING_TICKS / 10 {
            self.budget.exhausted = 0;
            return;
        }
        let full = nic::info(self.nic.driver()).map_or(0, |i| i.rx_ring_full);
        println!(
            "{}: busy: CPU budget used up in {} of the last {} ticks; {} frames in; driver ring full {} times so far",
            self.name, self.budget.exhausted, HOUSEKEEPING_TICKS, frames, full
        );
        self.budget.exhausted = 0;
    }

    /// Send an event to telemetry (if we may).
    fn event(&mut self, record: &Record) {
        if let Some(t) = self.telemetry
            && telemetry::net_event(t, record).is_err()
        {
            self.telemetry = None;
        }
    }

    /// Once per snapshot interval: compare rates with the thresholds, report an attack (with
    /// the top talkers) or tripped limits, and start counting afresh.
    fn detect(&mut self, now: u64) {
        let (c, l) = (self.counters, self.last);
        let per_s = |n: u64| n * TICK_HZ / self.interval.max(1);
        let syn = per_s(c.syn - l.syn);
        let drops = per_s(c.dropped_per_source + c.dropped_max_connections - l.dropped_per_source - l.dropped_max_connections);
        let exhausted = self.budget.exhausted_total - self.last_exhausted;
        let reason = if syn > SYN_FLOOD_PER_S {
            Some("syn_flood")
        } else if drops > LIMIT_DROPS_PER_S {
            Some("connection_limits")
        } else if exhausted * 2 > self.interval {
            Some("packet_flood")
        } else {
            None
        };
        if let Some(reason) = reason {
            let mut top = Text::new();
            for (addr, n) in self.talkers.top::<5>().into_iter().flatten() {
                let _ = write!(top, "{}{}.{}.{}.{}:{}", if top.len == 0 { "" } else { "," }, addr[0], addr[1], addr[2], addr[3], n);
            }
            println!("{}: attack suspected ({}): {} SYN/s, {} drops/s; top talkers {}", self.name, reason, syn, drops, top.as_str());
            let mut r = Record::new("attack_suspected");
            r.num("t", now).text("reason", reason).num("syn_per_s", syn).num("drops_per_s", drops).text("top", top.as_str());
            self.event(&r);
        }
        for (limit, n) in [("per_source", c.dropped_per_source - l.dropped_per_source), ("max_connections", c.dropped_max_connections - l.dropped_max_connections)] {
            if n > 0 {
                let mut r = Record::new("limit_tripped");
                r.num("t", now).text("limit", limit).num("dropped", n);
                self.event(&r);
            }
        }
        self.talkers.reset();
        self.last = c;
        self.last_exhausted = self.budget.exhausted_total;
    }

    /// Send one counter snapshot per scope: the interface, the stack, each instance.
    fn snapshot(&mut self, now: u64) {
        if self.telemetry.is_none() {
            // Telemetry may have been restarted; or we may not talk to it at all.
            self.telemetry = lookup("telemetry").ok();
        }
        let Some(t) = self.telemetry else { return };
        let info = nic::info(self.nic.driver()).unwrap_or_default();
        let mut r = Record::new("interface");
        r.num("t", now)
            .num("rx_packets", info.rx_packets)
            .num("rx_bytes", info.rx_bytes)
            .num("tx_packets", info.tx_packets)
            .num("tx_bytes", info.tx_bytes)
            .num("rx_ring_full", info.rx_ring_full)
            .num("errors", info.errors)
            .num("rx_multicast", info.rx_multicast)
            .num("rx_broadcast", info.rx_broadcast)
            .num("tx_dropped", self.nic.tx.dropped);
        match telemetry::counters(t, &r) {
            Ok(interval) => self.interval = interval,
            Err(_) => {
                self.telemetry = None;
                return;
            }
        }

        let (mut used, mut listening, mut connections) = (0, 0, 0);
        for s in &self.slots {
            match s.use_ {
                Use::Free => {}
                Use::Listening { .. } => listening += 1,
                Use::Pending { .. } | Use::Owned { .. } => connections += 1,
                Use::Closing => {}
            }
            used += (s.use_ != Use::Free) as u64;
        }
        let c = self.counters;
        let window = self.interval * self.budget.cycles_per_tick;
        let cpu = (c.cycles - core::mem::replace(&mut self.snapshot_cycles, c.cycles)) * 1000 / window.max(1);
        let mut r = Record::new("net");
        r.num("t", now)
            .num("sockets", SOCKETS as u64)
            .num("sockets_used", used)
            .num("listening", listening)
            .num("connections", connections)
            .num("frames_in", self.nic.received)
            .num("ipv4_bad_checksum", c.ipv4_bad_checksum)
            .num("tcp_no_listener", c.tcp_no_listener)
            .num("refused_no_instance", c.refused_no_instance)
            .num("budget_exhausted_ticks", self.budget.exhausted_total)
            .num("cpu_permille", cpu.min(1000));
        let _ = telemetry::counters(t, &r);

        let half_open = (0..SOCKETS)
            .filter(|&i| matches!(self.slots[i].use_, Use::Listening { .. }) && self.socket(i).state() == State::SynReceived)
            .count();
        let mut r = Record::new("protection");
        r.num("t", now)
            .num("syn", c.syn)
            .num("half_open", half_open as u64)
            .num("half_open_dropped", c.half_open_dropped)
            .num("handshake_timeouts", c.handshake_timeouts)
            .num("dropped_by_limits", c.dropped_per_source + c.dropped_max_connections)
            .num("dropped_per_source", c.dropped_per_source)
            .num("dropped_max_connections", c.dropped_max_connections)
            .num("blocklist_hits", c.blocklist_hits)
            .num("blocklist_entries", self.blocklist.len(now) as u64);
        let _ = telemetry::counters(t, &r);

        for k in 0..MAX_INSTANCES {
            let Some(instance) = self.instances[k] else { continue };
            let open = self.slots.iter().filter(|s| matches!(s.use_, Use::Owned { instance, .. } if instance as usize == k)).count();
            let mut name = [0u8; 32];
            let c = instance.counters;
            let mut r = Record::new("instance");
            r.num("t", now)
                .text("instance", task_name(instance.id, &mut name).unwrap_or("?"))
                .text("service", self.name_of(instance.service as usize))
                .num("live", (self.services[instance.service as usize].unwrap().live == Some(k as u8)) as u64)
                .num("accepted", c.accepted)
                .num("refused", c.refused)
                .num("reset", c.reset)
                .num("open", open as u64)
                .num("bytes_in", c.bytes_in)
                .num("bytes_out", c.bytes_out)
                .num("drain_forced", c.drain_forced);
            let _ = telemetry::counters(t, &r);
        }
    }

    /// After the driver died: talk to its next incarnation, once it runs.
    fn find_driver(&mut self) {
        if let Ok(id) = lookup(self.nic_name)
            && id != self.nic.driver()
        {
            println!("{}: the NIC driver was restarted", self.name);
            self.nic.set_driver(id);
        }
    }

    fn poll(&mut self, now: u64) {
        self.iface.poll(instant(now), &mut self.nic, &mut self.sockets);
        let Some(dhcp) = self.dhcp else { return };
        match self.sockets.get_mut::<dhcpv4::Socket>(dhcp).poll() {
            Some(dhcpv4::Event::Configured(config)) => {
                println!("{}: address {} from DHCP, gateway {:?}", self.name, config.address, config.router);
                self.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    let _ = addrs.push(IpCidr::Ipv4(config.address));
                });
                match config.router {
                    Some(router) => drop(self.iface.routes_mut().add_default_ipv4_route(router)),
                    None => drop(self.iface.routes_mut().remove_default_ipv4_route()),
                }
            }
            Some(dhcpv4::Event::Deconfigured) => {
                if self.iface.ipv4_addr().is_some() {
                    println!("{}: DHCP lease lost", self.name);
                }
                self.iface.update_ip_addrs(|addrs| addrs.clear());
                self.iface.routes_mut().remove_default_ipv4_route();
            }
            None => {}
        }
    }

    /// Ticks until smoltcp next needs a poll.
    fn poll_delay(&mut self, now: u64) -> Option<u64> {
        self.iface.poll_delay(instant(now), &self.sockets).map(|d| d.total_millis().div_ceil(10))
    }
}

/// A little text, for event fields.
struct Text {
    buf: [u8; 160],
    len: usize,
}

impl Text {
    fn new() -> Text {
        Text { buf: [0; 160], len: 0 }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Write for Text {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let n = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + n].copy_from_slice(&s.as_bytes()[..n]);
        self.len += n;
        Ok(())
    }
}

/// What the check on received frames may touch: everything but the NIC, whose batch it filters.
struct Gate<'a> {
    slots: &'a mut [Slot; SOCKETS],
    sockets: &'a mut SocketSet<'static>,
    ports: &'a [Option<Port>; MAX_PORTS],
    counters: &'a mut Counters,
    blocklist: &'a Blocklist,
    talkers: &'a mut Talkers,
    now: u64,
    /// Listening sockets promised to SYNs earlier in this batch, per port.
    promised: [usize; MAX_PORTS],
}

impl Gate<'_> {
    /// Set a free socket listening on port `p`.
    fn listen_another(&mut self, p: usize, number: u16) -> bool {
        for i in 0..SOCKETS {
            if self.slots[i].use_ != Use::Free {
                continue;
            }
            let s = self.sockets.get_mut::<tcp::Socket>(self.slots[i].handle);
            if s.state() == State::Closed && s.remote_endpoint().is_none() && s.listen(number).is_ok() {
                let slot = &mut self.slots[i];
                (slot.use_, slot.since, slot.syn_since) = (Use::Listening { port: p as u8 }, self.now, None);
                return true;
            }
        }
        false
    }

    /// Whether a received frame goes on to smoltcp. Counts what smoltcp would drop without
    /// telling us, drops blocked sources, and applies the connection limits to each new
    /// connection before a socket takes it.
    fn admit(&mut self, frame: &[u8]) -> bool {
        let Some(ip) = filter::ipv4(frame) else { return true };
        if self.blocklist.blocks(ip.src, self.now) {
            self.counters.blocklist_hits += 1;
            return false;
        }
        self.talkers.observe(ip.src);
        if !ip.checksum_ok {
            self.counters.ipv4_bad_checksum += 1;
            return false;
        }
        let Some(tcp) = filter::tcp(ip.payload).filter(|_| ip.proto == 6) else { return true };
        let Some(p) = self.ports.iter().position(|q| q.is_some_and(|q| q.number == tcp.dst_port)) else {
            self.counters.tcp_no_listener += 1;
            return true;
        };
        if tcp.flags & (filter::TCP_SYN | filter::TCP_ACK | filter::TCP_RST) != filter::TCP_SYN {
            return true;
        }
        self.counters.syn += 1;
        let port = self.ports[p].unwrap();
        let source = IpAddress::Ipv4(Ipv4Address::from(ip.src));
        let (mut listening, mut half_open, mut connections, mut from_source) = (0, 0, 0, 0);
        let mut oldest: Option<(u64, usize)> = None;
        for i in 0..SOCKETS {
            let use_ = self.slots[i].use_;
            match use_ {
                Use::Listening { port } | Use::Pending { port, .. } | Use::Owned { port, .. } if port as usize == p => {}
                _ => continue,
            }
            let s = self.sockets.get::<tcp::Socket>(self.slots[i].handle);
            let state = s.state();
            if let Some(remote) = s.remote_endpoint() {
                if remote.addr == source && remote.port == tcp.src_port && state == State::SynReceived {
                    return true; // a retransmitted SYN: smoltcp answers it again
                }
                from_source += (remote.addr == source && state != State::Closed) as u16;
            }
            match (use_, state) {
                (Use::Listening { .. }, State::Listen) => listening += 1,
                (Use::Listening { .. }, State::SynReceived) => {
                    half_open += 1;
                    let since = self.slots[i].syn_since.unwrap_or(self.now);
                    if oldest.is_none_or(|(t, _)| since < t) {
                        oldest = Some((since, i));
                    }
                }
                _ => connections += 1,
            }
        }
        if from_source >= port.max_per_source {
            self.counters.dropped_per_source += 1;
            return false;
        }
        if half_open + connections + self.promised[p] >= port.max_connections as usize {
            self.counters.dropped_max_connections += 1;
            return false;
        }
        if listening <= self.promised[p] {
            // No listening socket left for it: set another one listening while the port has
            // room for handshakes, else the oldest handshake makes room.
            let opened = half_open + self.promised[p] < HALF_OPEN && self.listen_another(p, port.number);
            if opened {
                // the new socket takes it
            } else if let Some((_, i)) = oldest {
                let s = self.sockets.get_mut::<tcp::Socket>(self.slots[i].handle);
                s.abort();
                let _ = s.listen(port.number);
                self.slots[i].syn_since = None;
                self.counters.half_open_dropped += 1;
            } else {
                self.counters.dropped_max_connections += 1;
                return false;
            }
        }
        self.promised[p] += 1;
        true
    }
}

/// `net` drives `nic`; `<x>-net` drives `nic-<x>` (e.g. `mgmt-net` and `nic-mgmt`).
fn nic_name(name: &str) -> &'static str {
    match name {
        "mgmt-net" => "nic-mgmt",
        _ => "nic",
    }
}

fn main() -> u64 {
    let name_buf = unsafe { &mut *(&raw mut NAME) };
    let name: &'static str = task_name(getpid(), name_buf).unwrap_or("net");
    let nic_name = nic_name(name);
    let driver = loop {
        match lookup(nic_name) {
            Ok(id) => break id,
            Err(_) => {
                println!("{}: no task named {}", name, nic_name);
                return 1;
            }
        }
    };
    let info = loop {
        match nic::info(driver) {
            Ok(info) => break info,
            Err(_) => sleep(1),
        }
    };
    let mut nic = Nic::new(driver);
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(info.mac)));
    config.random_seed = rdtsc();
    let mut iface = Interface::new(config, &mut nic, instant(uptime()));

    let storage = unsafe { &mut *(&raw mut SOCKET_STORAGE) };
    let rx = unsafe { &mut *(&raw mut RX_BUFFERS) };
    let tx = unsafe { &mut *(&raw mut TX_BUFFERS) };
    let mut sockets = SocketSet::new(&mut storage[..]);
    let slots: [Slot; SOCKETS] = {
        let mut buffers = rx.iter_mut().zip(tx.iter_mut());
        core::array::from_fn(|_| {
            let (rx, tx) = buffers.next().unwrap();
            let mut socket = tcp::Socket::new(tcp::SocketBuffer::new(&mut rx[..]), tcp::SocketBuffer::new(&mut tx[..]));
            socket.set_timeout(Some(IDLE));
            socket.set_ack_delay(None); // 10 ms ticks would make delayed ACKs slow
            socket.set_nagle_enabled(false); // services send whole responses
            Slot { handle: sockets.add(socket), generation: 1, use_: Use::Free, since: 0, syn_since: None, want_write: false, reset_seen: false }
        })
    };

    // The test feature gives the data stack a fixed address (its NIC is on the dgram backend,
    // which has no DHCP server); the management stack always uses DHCP.
    let dhcp = if cfg!(feature = "static-addr") && name == "net" {
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(10, 0, 9, 2), 24)));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 9, 1));
        println!("{}: address 10.0.9.2/24 (static)", name);
        None
    } else {
        Some(sockets.add(dhcpv4::Socket::new()))
    };

    println!(
        "{}: on {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}), {} sockets, {} KiB of socket buffers",
        name, nic_name, info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5], SOCKETS, SOCKETS * 2 * BUFFER / 1024
    );
    let mut stack = Stack {
        iface,
        sockets,
        dhcp,
        nic,
        name,
        nic_name,
        budget: Budget::new(),
        reported_frames: 0,
        counters: Counters::default(),
        telemetry: lookup("telemetry").ok(),
        interval: DEFAULT_INTERVAL_TICKS,
        next_snapshot: 0,
        snapshot_cycles: 0,
        last: Counters::default(),
        last_exhausted: 0,
        blocklist: Blocklist::new(),
        talkers: Talkers::new(),
        slots,
        ports: [None; MAX_PORTS],
        services: [None; MAX_SERVICES],
        instances: [None; MAX_INSTANCES],
        next_generation: 0,
        handed_out: 0,
            next_local_port: 0,
    };

    let mut msg = [0u8; 4096];
    let mut out = [0u8; 4096];
    let mut want_rx = true;
    let mut next_housekeeping = uptime() + HOUSEKEEPING_TICKS;
    loop {
        let now = uptime();
        let start = rdtsc();
        let receiving = want_rx && stack.budget.left(now);
        if receiving {
            want_rx = stack.receive();
        }
        stack.poll(now);
        stack.tend(now);
        stack.poll(now); // send what tending changed (RSTs)
        stack.tend_drains(now);
        stack.serve_waiters(now);
        if receiving {
            let cycles = rdtsc() - start;
            stack.budget.spend(now, cycles);
            stack.counters.cycles += cycles;
        }
        if now >= stack.next_snapshot {
            stack.snapshot(now);
            stack.detect(now);
            stack.next_snapshot = now + stack.interval;
        }
        if now >= next_housekeeping {
            next_housekeeping = now + HOUSEKEEPING_TICKS;
            stack.report_load();
            if stack.nic.tx.dead {
                stack.find_driver();
            }
            want_rx = true; // re-arms a restarted driver's notification
        }

        // Wait for a request, a notification, or the next timer; only poll if frames are waiting.
        let wake = [stack.poll_delay(now).map(|d| now + d.max(1)), stack.next_deadline(), Some(next_housekeeping), Some(stack.next_snapshot)];
        let wake = wake.into_iter().flatten().min().unwrap();
        let ticks = match want_rx {
            true if stack.budget.left(uptime()) => 0,
            true => 1, // out of budget: frames wait for the next tick
            false => wake.saturating_sub(uptime()).max(1),
        };
        let (sender, op, len) = syscall6(SYS_RECV, [msg.as_mut_ptr() as u64, msg.len() as u64, RECV_TIMEOUT, ticks, 0, 0]);
        if err::is_error(sender) {
            println!("{}: recv failed: {}", name, err::name(sender));
            continue;
        }
        match (sender, op) {
            (0, NOTIFY_POST) => want_rx |= len & NOTIFY_RX != 0,
            (0, NOTIFY_TIMER) | (0, _) => {}
            (sender, op) => {
                let now = uptime();
                if let Some((code, n)) = stack.request(sender, op, &msg[..len as usize], &mut out, now) {
                    let _ = reply(sender, code, &out[..n]);
                }
            }
        }
    }
}
