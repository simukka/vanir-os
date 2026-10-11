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
//! - Every table is fixed at build time: no heap.
//!
//! The same program runs the data stack (`net`, driver `nic`) and the management stack
//! (`mgmt-net`, driver `nic-mgmt`).

#![no_std]
#![no_main]

mod device;

use device::Nic;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::tcp::{self, State};
#[cfg(not(feature = "static-addr"))]
use smoltcp::socket::dhcpv4;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpCidr};
#[cfg(feature = "static-addr")]
use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use vanir_user::net::*;
use vanir_user::nic::{self, NOTIFY_RX};
use vanir_user::{NOTIFY_POST, NOTIFY_TIMER, SYS_RECV, RECV_TIMEOUT, err, getpid, lookup, println, rdtsc, reply, sleep, syscall6, task_index, task_listen, task_name, uptime};

vanir_user::entry!(main);

/// Sockets in the pool, each with its own receive and transmit buffers.
const SOCKETS: usize = 96;
const BUFFER: usize = 4096;
const MAX_PORTS: usize = 8;
const MAX_SERVICES: usize = 8;
const MAX_INSTANCES: usize = 8;
/// Sockets kept listening on each port in use.
const LISTENING: usize = 4;
/// A handshake not finished in this many ticks is dropped.
const HANDSHAKE_TICKS: u64 = 300;
/// A connection its instance doesn't accept in this many ticks is reset.
const ACCEPT_TICKS: u64 = 500;
/// A connection with nothing from the peer for this long is reset.
const IDLE: Duration = Duration::from_secs(60);
/// Look at the driver at least this often, in case it restarted and forgot to notify us.
const HOUSEKEEPING_TICKS: u64 = 100;

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
}

#[derive(Clone, Copy)]
struct Port {
    number: u16,
    service: u8,
    max_connections: u16,
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
    /// Ports (bit per `ports` entry) it listens on.
    listening: u8,
    /// Its `OP_WAIT`, if one is held: (deadline tick).
    waiting: Option<Option<u64>>,
}

struct Stack {
    iface: Interface,
    sockets: SocketSet<'static>,
    #[cfg(not(feature = "static-addr"))]
    dhcp: SocketHandle,
    nic: Nic,
    nic_name: &'static str,
    slots: [Slot; SOCKETS],
    ports: [Option<Port>; MAX_PORTS],
    services: [Option<Service>; MAX_SERVICES],
    instances: [Option<Instance>; MAX_INSTANCES],
    next_generation: u16,
    /// Connections handed to instances (accepted).
    handed_out: u64,
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
        if info.count == 0 {
            return Err(CODE_NOT_ALLOWED);
        }
        let service = self.service_for(info.service()).ok_or(CODE_NO_SOCKETS)?;
        let k = self.instances.iter().position(Option::is_none).ok_or(CODE_NO_SOCKETS)?;
        self.next_generation = self.next_generation.wrapping_add(1);
        self.instances[k] =
            Some(Instance { id: sender, service: service as u8, generation: self.next_generation, ready: false, listening: 0, waiting: None });
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

    fn port_for(&mut self, number: u16, service: usize, max_connections: u16) -> Option<usize> {
        if let Some(p) = self.ports.iter().position(|p| p.is_some_and(|p| p.number == number)) {
            // The kernel lets only instances of one service declare a port.
            return (self.ports[p].unwrap().service as usize == service).then_some(p);
        }
        let p = self.ports.iter().position(Option::is_none)?;
        self.ports[p] = Some(Port { number, service: service as u8, max_connections });
        Some(p)
    }

    /// An instance has gone (died, or was restarted): reset its connections, drop its listeners.
    fn forget(&mut self, k: usize, now: u64) {
        for i in 0..SOCKETS {
            if matches!(self.slots[i].use_, Use::Owned { instance, .. } | Use::Pending { instance, .. } if instance as usize == k) {
                self.reset(i, now);
            }
        }
        let instance = self.instances[k].take().unwrap();
        let service = self.services[instance.service as usize].as_mut().unwrap();
        if service.live == Some(k as u8) {
            service.live = None;
        }
        let mut name = [0u8; 32];
        println!("net: instance {} is gone", task_name(instance.id, &mut name).unwrap_or("?"));
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
                            self.reset(i, now);
                        }
                    }
                    State::Closed => self.set_use(i, Use::Free, now),
                    _ => self.hand_out(i, port as usize, now),
                },
                Use::Pending { .. } if state == State::Closed || now - self.slots[i].since > ACCEPT_TICKS => self.reset(i, now),
                Use::Closing if matches!(state, State::Closed | State::TimeWait) => self.set_use(i, Use::Free, now),
                _ => {}
            }
        }
        for p in 0..MAX_PORTS {
            let Some(port) = self.ports[p] else { continue };
            let in_use = self.instances.iter().flatten().any(|i| i.listening & 1 << p != 0);
            let mut listening = 0;
            let mut connections = 0;
            for i in 0..SOCKETS {
                match self.slots[i].use_ {
                    Use::Listening { port } if port as usize == p => {
                        if !in_use {
                            self.reset(i, now);
                        } else if self.socket(i).state() == State::Listen {
                            listening += 1;
                        } else {
                            connections += 1;
                        }
                    }
                    Use::Pending { port, .. } | Use::Owned { port, .. } if port as usize == p => connections += 1,
                    _ => {}
                }
            }
            let room = (port.max_connections as usize).saturating_sub(connections);
            while in_use && listening < LISTENING.min(room) && self.listen_on(p, now) {
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
            None => self.reset(slot, now),
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
            if s.can_recv() || !s.may_recv() {
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

    /// The earliest held `OP_WAIT` deadline.
    fn next_deadline(&self) -> Option<u64> {
        self.instances.iter().flatten().filter_map(|i| i.waiting.flatten()).min()
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
                #[cfg(feature = "crash-after-50-connections")]
                if self.handed_out == 50 && getpid() >> 16 == 0 {
                    println!("net: crashing after handing out 50 connections");
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
                    match s.recv_slice(&mut out[..max]) {
                        Ok(0) if !s.may_recv() => Err(CODE_CLOSED),
                        Ok(0) => Err(CODE_WOULD_BLOCK),
                        Ok(n) => Ok(n),
                        Err(_) => Err(CODE_CLOSED),
                    }
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
                out[..4].copy_from_slice(&(n as u32).to_le_bytes());
                Ok(4)
            }),
            OP_CLOSE | OP_SHUTDOWN => {
                let Some(h) = word(0) else { return Some((CODE_BAD_OP, 0)) };
                if h & LISTENER != 0 && op == OP_CLOSE {
                    self.listener(sender, h).map(|(k, p)| {
                        self.instances[k].as_mut().unwrap().listening &= !(1 << p);
                        for i in 0..SOCKETS {
                            if self.slots[i].use_ == (Use::Pending { port: p as u8, instance: k as u8 }) {
                                self.reset(i, now);
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
            OP_READY => self.instance_for(sender, now).map(|k| {
                let instance = self.instances[k].as_mut().unwrap();
                instance.ready = true;
                let service = instance.service as usize;
                if self.services[service].unwrap().live.is_none() {
                    self.services[service].as_mut().unwrap().live = Some(k as u8);
                    let mut name = [0u8; 32];
                    println!("net: {} is live for service {}", task_name(sender, &mut name).unwrap_or("?"), self.name_of(service));
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

    fn listen(&mut self, sender: u64, port: u16, now: u64) -> Result<u32, u64> {
        let mut name = [0u8; 32];
        let info = task_listen(sender).map_err(|_| CODE_NOT_ALLOWED)?;
        let Some((max_connections, _per_source)) = info.port(port) else {
            println!("net: {} may not listen on port {}: not in its manifest entry", task_name(sender, &mut name).unwrap_or("?"), port);
            return Err(CODE_NOT_ALLOWED);
        };
        let k = self.instance_for(sender, now)?;
        let service = self.instances[k].unwrap().service as usize;
        let p = self.port_for(port, service, max_connections).ok_or(CODE_NOT_ALLOWED)?;
        let instance = self.instances[k].as_mut().unwrap();
        instance.listening |= 1 << p;
        println!("net: {} listens on port {} (service {})", task_name(sender, &mut name).unwrap_or("?"), port, self.name_of(service));
        Ok(listener_handle(k, p, self.instances[k].unwrap().generation))
    }

    // ---- The interface ------------------------------------------------------------------------

    /// Take a batch of frames from the driver. Returns whether there may be more.
    fn receive(&mut self) -> bool {
        match self.nic.fetch() {
            Ok(n) => n > 0,
            Err(_) => {
                self.find_driver();
                false
            }
        }
    }

    /// After the driver died: talk to its next incarnation, once it runs.
    fn find_driver(&mut self) {
        if let Ok(id) = lookup(self.nic_name)
            && id != self.nic.driver()
        {
            println!("net: the NIC driver was restarted");
            self.nic.set_driver(id);
        }
    }

    fn poll(&mut self, now: u64) {
        self.iface.poll(instant(now), &mut self.nic, &mut self.sockets);
        #[cfg(not(feature = "static-addr"))]
        match self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp).poll() {
            Some(dhcpv4::Event::Configured(config)) => {
                println!("net: address {} from DHCP, gateway {:?}", config.address, config.router);
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
                    println!("net: DHCP lease lost");
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

/// `net` drives `nic`; `<x>-net` drives `nic-<x>` (e.g. `mgmt-net` and `nic-mgmt`).
fn nic_name(name: &str) -> &'static str {
    match name {
        "mgmt-net" => "nic-mgmt",
        _ => "nic",
    }
}

fn main() -> u64 {
    let mut name_buf = [0u8; 32];
    let name = task_name(getpid(), &mut name_buf).unwrap_or("net");
    let nic_name = nic_name(name);
    let driver = loop {
        match lookup(nic_name) {
            Ok(id) => break id,
            Err(_) => {
                println!("net: no task named {}", nic_name);
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
    #[cfg_attr(not(feature = "static-addr"), allow(unused_mut))]
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
            Slot { handle: sockets.add(socket), generation: 1, use_: Use::Free, since: 0, syn_since: None, want_write: false }
        })
    };

    #[cfg(feature = "static-addr")]
    {
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address::new(10, 0, 9, 2), 24)));
        });
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 9, 1));
        println!("net: address 10.0.9.2/24 (static)");
    }
    #[cfg(not(feature = "static-addr"))]
    let dhcp = sockets.add(dhcpv4::Socket::new());

    println!(
        "net: {} on {} ({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}), {} sockets, {} KiB of socket buffers",
        name, nic_name, info.mac[0], info.mac[1], info.mac[2], info.mac[3], info.mac[4], info.mac[5], SOCKETS, SOCKETS * 2 * BUFFER / 1024
    );
    let mut stack = Stack {
        iface,
        sockets,
        #[cfg(not(feature = "static-addr"))]
        dhcp,
        nic,
        nic_name,
        slots,
        ports: [None; MAX_PORTS],
        services: [None; MAX_SERVICES],
        instances: [None; MAX_INSTANCES],
        next_generation: 0,
        handed_out: 0,
    };

    let mut msg = [0u8; 4096];
    let mut out = [0u8; 4096];
    let mut want_rx = true;
    let mut next_housekeeping = uptime() + HOUSEKEEPING_TICKS;
    loop {
        let now = uptime();
        if want_rx {
            want_rx = stack.receive();
        }
        stack.poll(now);
        stack.tend(now);
        stack.poll(now); // send what tending changed (RSTs)
        stack.serve_waiters(now);
        if now >= next_housekeeping {
            next_housekeeping = now + HOUSEKEEPING_TICKS;
            if stack.nic.tx.dead {
                stack.find_driver();
            }
            want_rx = true; // re-arms a restarted driver's notification
        }

        // Wait for a request, a notification, or the next timer; only poll if frames are waiting.
        let wake = [stack.poll_delay(now).map(|d| now + d.max(1)), stack.next_deadline(), Some(next_housekeeping)];
        let wake = wake.into_iter().flatten().min().unwrap();
        let ticks = if want_rx { 0 } else { wake.saturating_sub(uptime()).max(1) };
        let (sender, op, len) = syscall6(SYS_RECV, [msg.as_mut_ptr() as u64, msg.len() as u64, RECV_TIMEOUT, ticks, 0, 0]);
        if err::is_error(sender) {
            println!("net: recv failed: {}", err::name(sender));
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
