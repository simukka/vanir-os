//! The instance lifecycle (RFD 2, P4) and the local swap (P3). The agent owns every slot's
//! state and reports each transition:
//!
//! ```text
//!  EMPTY ──load──▶ STARTING ──ready──▶ READY ──promote──▶ LIVE
//!    ▲               │                                     │
//!    │            timeout                                drain
//!    │               ▼                                     ▼
//!    ├──────────── FAILED                              DRAINING
//!    └── unload ◀── STOPPED ◀── stop ◀── DRAINED ◀─────────┘
//! ```
//!
//! A service with a volume (RFD 3) has one writer, named by an epoch the control plane assigns
//! with the deployment. The agent hands it to `storage` (`block::epoch`) at the moment the RFD
//! fixes: with no old instance, before routing to the new one; with one, once it has drained and
//! before it is stopped. Until V3, the new instance's writes are refused in between. When
//! `storage` restarts, it has forgotten the writer, so the agent sends each live writer's epoch
//! again.
//!
//! Nothing here blocks: operations (`Op`) advance a step at a time in `advance`, called from
//! the agent's loop, so the agent keeps serving its other work (the control plane) while a
//! drain runs for minutes.

use crate::Image;
use vanir_user::net::{self, STATUS_DRAINED, STATUS_GONE, STATUS_LIVE, STATUS_READY};
use vanir_user::telemetry::{self, Record};
use vanir_user::block::{self, CODE_LOCKED};
use vanir_user::{err, events, lookup, println, slot, supervisor, uptime};

/// Most slots the agent tracks.
pub const MAX_SLOTS: usize = 16;
/// The names of the slots tracked (`Slot::name` points here).
static mut NAMES: [[u8; 16]; MAX_SLOTS] = [[0; 16]; MAX_SLOTS];

/// How long a new instance has to say it is ready: 10 s.
pub const READY_TIMEOUT: u64 = 1000;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Empty,
    Starting,
    Ready,
    Live,
    Draining,
    Drained,
    Stopped,
    Failed,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::Empty => "EMPTY",
            State::Starting => "STARTING",
            State::Ready => "READY",
            State::Live => "LIVE",
            State::Draining => "DRAINING",
            State::Drained => "DRAINED",
            State::Stopped => "STOPPED",
            State::Failed => "FAILED",
        }
    }
}

/// One slot as the agent sees it.
#[derive(Clone, Copy)]
pub struct Slot {
    /// Its name in the task table (`small-0`).
    pub name: &'static str,
    /// Current id (a new generation on every load and start).
    pub id: u64,
    pub state: State,
    /// The image it holds, while it holds one.
    pub image: Option<Image>,
    /// The writer epoch and lease `storage` accepted for this slot (RFD 3), while it holds them.
    pub epoch: Option<(u64, u64)>,
    /// An epoch `storage` refused for this slot, until one is accepted (reported to the control
    /// plane).
    pub epoch_refused: Option<u64>,
}

impl Slot {
    pub fn service(&self) -> &'static [u8] {
        self.image.map_or(&[], |i| i.service())
    }

    pub fn version(&self) -> u64 {
        self.image.map_or(0, |i| i.version())
    }
}

/// A deployment in progress: `new` becomes the live instance of its service and the live one
/// before it (`old`) drains and stops. A rollback is the same with `new` a stopped slot that
/// still holds the previous version.
#[derive(Clone, Copy)]
pub struct Deploy {
    /// The slot becoming live (for a drain-only operation, the same as `old`).
    pub new: usize,
    pub old: Option<usize>,
    pub step: Step,
    /// The drain deadline for `old`, in ticks (already capped by its descriptor).
    pub drain_ticks: u64,
    /// The writer epoch and lease for `new`, if its service has a volume (RFD 3).
    pub epoch: Option<(u64, u64)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Load the image into `new`, or start `new` again from the image it holds.
    Start,
    /// Drain `old` and stop it, with nothing taking its place (the service is going away).
    Drain,
    WaitReady { until: u64 },
    Promote,
    WaitDrained,
    Done,
    Failed,
}

#[allow(dead_code)]
pub struct Agent {
    pub slots: [Option<Slot>; MAX_SLOTS],
    pub deploys: [Option<Deploy>; 4],
    net: u64,
    supervisor: u64,
    telemetry: Option<u64>,
    /// The storage task (RFD 3), as last looked up, and whether it restarted since the live
    /// writers' epochs were last sent to it.
    disk: Option<u64>,
    resend_epochs: bool,
    /// A slot changed state since this was last cleared (the control plane wants a report).
    pub changed: bool,
}

/// The drain deadline in ticks for an instance of `image`: the descriptor's default, or `asked`
/// (seconds) capped at its maximum (RFD 2, determination 5).
pub fn drain_ticks(image: &Image, asked: Option<u64>) -> u64 {
    let (default, max) = image.drain_secs();
    let secs = asked.map_or(default, |a| a.min(max));
    if let Some(a) = asked
        && a > max
    {
        println!("agent: drain deadline {} s asked; the descriptor allows at most {} s", a, max);
    }
    secs * vanir_user::TICK_HZ
}

#[allow(dead_code)]
impl Agent {
    pub fn new() -> Agent {
        let id = |name| loop {
            match lookup(name) {
                Ok(id) => break id,
                Err(_) => vanir_user::sleep(1),
            }
        };
        Agent {
            slots: [None; MAX_SLOTS],
            deploys: [None; 4],
            net: id("net"),
            supervisor: id("supervisor"),
            telemetry: lookup("telemetry").ok(),
            disk: lookup("disk").ok(),
            resend_epochs: false,
            changed: false,
        }
    }

    /// The index of slot `name`, tracking it from now on.
    pub fn slot(&mut self, name: &str) -> usize {
        self.find_slot(name).unwrap_or_else(|| panic!("agent: no slot named {name}"))
    }

    /// The index of slot `name` if the task table has one, tracking it from now on.
    pub fn find_slot(&mut self, name: &str) -> Option<usize> {
        if let Some(k) = self.slots.iter().position(|s| s.is_some_and(|s| s.name == name)) {
            return Some(k);
        }
        let id = lookup(name).ok()?;
        let k = self.slots.iter().position(Option::is_none)?;
        // Keep our own copy of the name: names come from the control plane too.
        let names = unsafe { &mut *(&raw mut NAMES) };
        let len = name.len().min(16);
        names[k][..len].copy_from_slice(&name.as_bytes()[..len]);
        let name = core::str::from_utf8(&names[k][..len]).unwrap_or("?");
        self.slots[k] = Some(Slot { name, id, state: State::Empty, image: None, epoch: None, epoch_refused: None });
        Some(k)
    }

    pub fn supervisor(&self) -> u64 {
        self.supervisor
    }

    pub fn get(&self, k: usize) -> Slot {
        self.slots[k].unwrap()
    }

    /// The live slot of `service`, if there is one.
    pub fn live(&self, service: &[u8]) -> Option<usize> {
        self.slots.iter().position(|s| s.is_some_and(|s| s.state == State::Live && s.service() == service))
    }

    /// Record a transition, print it, and report it to telemetry.
    pub fn set(&mut self, k: usize, to: State) {
        let s = self.slots[k].as_mut().unwrap();
        let from = s.state;
        s.state = to;
        self.changed = true;
        let s = *s;
        let service = core::str::from_utf8(s.service()).unwrap_or("?");
        println!("agent: {} ({} v{}): {} -> {}", s.name, service, s.version(), from.name(), to.name());
        if let Some(t) = self.telemetry {
            let mut r = Record::new("instance");
            r.text("slot", s.name).text("service", service).num("version", s.version()).text("from", from.name()).text("to", to.name());
            let _ = telemetry::event(t, &r);
        }
    }

    /// Start deploying `image` into empty slot `new` (or, with no image, starting the stopped
    /// slot `new` again: a rollback). `drain_secs` overrides the old instance's drain deadline;
    /// `epoch` (epoch, lease) makes the new instance its volume's writer (RFD 3).
    pub fn deploy(&mut self, new: usize, image: Option<Image>, drain_secs: Option<u64>, epoch: Option<(u64, u64)>) -> bool {
        if let Some(image) = image {
            if self.get(new).state != State::Empty {
                println!("agent: {} isn't empty", self.get(new).name);
                return false;
            }
            self.slots[new].as_mut().unwrap().image = Some(image);
        } else if self.get(new).state != State::Stopped {
            println!("agent: {} holds nothing to start again", self.get(new).name);
            return false;
        }
        let image = self.get(new).image.unwrap();
        let old = self.live(image.service());
        let drain = old.map_or(0, |o| drain_ticks(&self.get(o).image.unwrap(), drain_secs));
        let Some(d) = self.deploys.iter().position(|d| d.is_none_or(|d| matches!(d.step, Step::Done | Step::Failed))) else {
            return false;
        };
        self.deploys[d] = Some(Deploy { new, old, step: Step::Start, drain_ticks: drain, epoch });
        true
    }

    /// Drain the instance in slot `k` and stop it, with nothing taking its place.
    pub fn drain(&mut self, k: usize, drain_secs: Option<u64>) -> bool {
        if self.get(k).state != State::Live {
            return false;
        }
        let drain_ticks = drain_ticks(&self.get(k).image.unwrap(), drain_secs);
        let Some(d) = self.deploys.iter().position(|d| d.is_none_or(|d| matches!(d.step, Step::Done | Step::Failed))) else {
            return false;
        };
        self.deploys[d] = Some(Deploy { new: k, old: Some(k), step: Step::Drain, drain_ticks, epoch: None });
        true
    }

    /// Whether a deployment of `service` is under way.
    pub fn busy(&self, service: &[u8]) -> bool {
        let holds = |k: usize| self.get(k).service() == service;
        self.deploys
            .iter()
            .flatten()
            .filter(|d| !matches!(d.step, Step::Done | Step::Failed))
            .any(|d| holds(d.new) || d.old.is_some_and(holds))
    }

    /// Whether every deployment has finished (done or failed).
    pub fn idle(&self) -> bool {
        self.deploys.iter().flatten().all(|d| matches!(d.step, Step::Done | Step::Failed))
    }

    /// Hand slot `k`'s instance epoch `epoch` (RFD 3). Ok(true) once `storage` has it; Ok(false)
    /// to try again later (storage restarting or still locked); Err(code) if it refused.
    pub fn assign_epoch(&mut self, k: usize, epoch: (u64, u64)) -> Result<bool, u64> {
        let Some(disk) = self.disk else {
            println!("agent: no storage task for {}'s volume", self.get(k).name);
            return Err(block::CODE_BAD_OP);
        };
        let s = self.get(k);
        match block::epoch(disk, epoch.0, epoch.1, s.id) {
            Ok(()) => {
                println!("agent: {} holds epoch {}", s.name, epoch.0);
                for other in self.slots.iter_mut().flatten() {
                    if other.service() == s.service() {
                        other.epoch = None;
                    }
                }
                let slot = self.slots[k].as_mut().unwrap();
                slot.epoch = Some(epoch);
                slot.epoch_refused = None;
                self.changed = true;
                Ok(true)
            }
            Err(e) if e == err::DEAD || e == CODE_LOCKED => Ok(false),
            Err(e) => {
                println!("agent: epoch {} for {}: {}", epoch.0, s.name, block::code_name(e));
                self.slots[k].as_mut().unwrap().epoch_refused = Some(epoch.0);
                self.changed = true;
                Err(e)
            }
        }
    }

    /// Notice a restarted `storage`, and send it each live writer's epoch again.
    fn keep_epochs(&mut self) {
        if let Ok(id) = lookup("disk")
            && Some(id) != self.disk
        {
            self.resend_epochs |= self.disk.is_some();
            self.disk = Some(id);
        }
        if !self.resend_epochs {
            return;
        }
        let mut done = true;
        for k in 0..MAX_SLOTS {
            if let Some(s) = self.slots[k]
                && let Some(epoch) = s.epoch
                && s.state == State::Live
            {
                done &= self.assign_epoch(k, epoch).unwrap_or(true);
            }
        }
        self.resend_epochs = !done;
    }

    /// Move every deployment along as far as it can go now.
    pub fn advance(&mut self) {
        self.keep_epochs();
        for d in 0..self.deploys.len() {
            while let Some(deploy) = self.deploys[d] {
                let step = self.step(deploy);
                if step == deploy.step {
                    break;
                }
                self.deploys[d].as_mut().unwrap().step = step;
            }
        }
    }

    /// One step of a deployment; returns the next step (the same one while it waits).
    fn step(&mut self, d: Deploy) -> Step {
        let now = uptime();
        let new = self.get(d.new);
        match d.step {
            Step::Start => {
                let started = match new.state {
                    State::Empty => self.load(d.new),
                    _ => self.start(d.new),
                };
                if !started {
                    return Step::Failed;
                }
                self.set(d.new, State::Starting);
                // A service with a volume doesn't say it's ready until it has opened it (RFD 3).
                Step::WaitReady { until: now + READY_TIMEOUT }
            }
            Step::Drain => {
                let old = d.old.unwrap();
                if let Err(e) = net::drain_nowait(self.net, self.get(old).id, d.drain_ticks) {
                    println!("agent: draining {} failed: {}", self.get(old).name, net::code_name(e));
                }
                self.set(old, State::Draining);
                Step::WaitDrained
            }
            Step::WaitReady { until } => match net::status(self.net, new.id) {
                Ok((STATUS_READY | STATUS_LIVE, _)) => {
                    self.set(d.new, State::Ready);
                    Step::Promote
                }
                _ if now >= until => {
                    println!("agent: {} didn't say it was ready in time; stopping it", new.name);
                    let _ = supervisor::stop(self.supervisor, new.id);
                    self.set(d.new, State::Failed);
                    Step::Failed
                }
                _ => d.step,
            },
            Step::Promote => {
                // With no old instance, the new one becomes the writer before it gets traffic.
                if d.old.is_none()
                    && let Some(epoch) = d.epoch
                {
                    match self.assign_epoch(d.new, epoch) {
                        Ok(true) => {}
                        Ok(false) => return d.step,
                        Err(_) => {
                            let _ = supervisor::stop(self.supervisor, new.id);
                            self.set(d.new, State::Failed);
                            return Step::Failed;
                        }
                    }
                }
                if let Err(e) = net::route(self.net, new.id) {
                    println!("agent: routing to {} failed: {}", new.name, net::code_name(e));
                    return d.step;
                }
                self.set(d.new, State::Live);
                let Some(old) = d.old else { return Step::Done };
                if let Err(e) = net::drain_nowait(self.net, self.get(old).id, d.drain_ticks) {
                    println!("agent: draining {} failed: {}", self.get(old).name, net::code_name(e));
                }
                self.set(old, State::Draining);
                Step::WaitDrained
            }
            Step::WaitDrained => {
                let old = d.old.unwrap();
                match net::status(self.net, self.get(old).id) {
                    Ok((STATUS_DRAINED | STATUS_GONE, forced)) => {
                        if self.get(old).state != State::Drained {
                            println!("agent: {} drained ({} connections reset at the deadline)", self.get(old).name, forced);
                            self.set(old, State::Drained);
                        }
                        // The epoch moves once the old instance has drained, before it stops
                        // (RFD 3, P3). A refusal leaves the new instance live without it.
                        if d.new != old
                            && let Some(epoch) = d.epoch
                            && self.assign_epoch(d.new, epoch) == Ok(false)
                        {
                            return d.step;
                        }
                        match supervisor::stop(self.supervisor, self.get(old).id) {
                            Ok(()) => self.set(old, State::Stopped),
                            Err(e) => println!("agent: stopping {} failed: {}", self.get(old).name, err::name(e)),
                        }
                        Step::Done
                    }
                    _ => d.step,
                }
            }
            Step::Done | Step::Failed => d.step,
        }
    }

    /// Stage and load the slot's image. The slot's id changes.
    fn load(&mut self, k: usize) -> bool {
        let s = self.get(k);
        let image = s.image.unwrap();
        // An image fetched from the control plane was staged as it arrived.
        if !image.elf.is_empty()
            && let Err(e) = slot::stage_all(s.id, image.elf)
        {
            println!("agent: staging into {} failed: {}", s.name, err::name(e));
            return false;
        }
        loop {
            match slot::load(s.id, image.sig, image.descriptor) {
                Ok(id) => {
                    self.slots[k].as_mut().unwrap().id = id;
                    return true;
                }
                Err((err::BUSY, _)) => vanir_user::sleep(1), // the TPM is in use for a moment
                Err((e, why)) => {
                    match e {
                        err::REJECTED => println!("agent: {} into {}: REJECTED ({})", image.name, s.name, events::rejection(why)),
                        _ => println!("agent: {} into {}: {}", image.name, s.name, err::name(e)),
                    }
                    self.slots[k].as_mut().unwrap().image = None;
                    return false;
                }
            }
        }
    }

    /// Start a stopped slot again from the image it holds. The slot's id changes.
    fn start(&mut self, k: usize) -> bool {
        match supervisor::start(self.supervisor, self.get(k).id) {
            Ok(id) => {
                self.slots[k].as_mut().unwrap().id = id;
                true
            }
            Err(e) => {
                println!("agent: starting {} failed: {}", self.get(k).name, err::name(e));
                false
            }
        }
    }

    /// Commit `service`: empty every stopped slot that holds it (RFD 2, P3: the old version is
    /// kept until then, for a rollback). If that leaves no instance of a service with a volume,
    /// `storage` forgets its key (RFD 3, P2).
    pub fn commit(&mut self, service: &[u8]) {
        let volume = self.slots.iter().flatten().any(|s| s.service() == service && s.image.is_some_and(|i| i.volume_blocks() > 0));
        self.unload_stopped(service);
        if volume
            && !self.slots.iter().flatten().any(|s| s.service() == service)
            && let Some(disk) = self.disk
        {
            let shown = core::str::from_utf8(service).unwrap_or("?");
            match block::forget_key(disk, service) {
                Ok(()) => println!("agent: no instance of {} left; storage forgot its key", shown),
                Err(e) => println!("agent: forgetting {}'s key: {}", shown, block::code_name(e)),
            }
        }
    }

    fn unload_stopped(&mut self, service: &[u8]) {
        for k in 0..MAX_SLOTS {
            let Some(s) = self.slots[k] else { continue };
            if !(s.service() == service && matches!(s.state, State::Stopped | State::Failed)) {
                continue;
            }
            loop {
                match slot::unload(s.id) {
                    Ok(()) => break,
                    Err(err::BUSY) => vanir_user::sleep(1),
                    Err(e) => {
                        println!("agent: unloading {} failed: {}", s.name, err::name(e));
                        return;
                    }
                }
            }
            self.set(k, State::Empty);
            self.slots[k].as_mut().unwrap().image = None;
        }
    }

    /// The stopped slot holding `service`, for a rollback.
    pub fn stopped(&self, service: &[u8]) -> Option<usize> {
        self.slots.iter().position(|s| s.is_some_and(|s| s.state == State::Stopped && s.service() == service))
    }
}
