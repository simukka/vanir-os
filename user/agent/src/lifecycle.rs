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
//! Nothing here blocks: operations (`Op`) advance a step at a time in `advance`, called from
//! the agent's loop, so the agent keeps serving its other work (the control plane) while a
//! drain runs for minutes.

use crate::Image;
use vanir_user::net::{self, STATUS_DRAINED, STATUS_GONE, STATUS_LIVE, STATUS_READY};
use vanir_user::telemetry::{self, Record};
use vanir_user::{err, events, lookup, println, slot, supervisor, uptime};

/// Most slots the agent tracks.
pub const MAX_SLOTS: usize = 16;
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
    pub new: usize,
    pub old: Option<usize>,
    pub step: Step,
    /// The drain deadline for `old`, in ticks (already capped by its descriptor).
    pub drain_ticks: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Step {
    /// Load the image into `new`, or start `new` again from the image it holds.
    Start,
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
        }
    }

    /// The index of slot `name`, tracking it from now on.
    pub fn slot(&mut self, name: &'static str) -> usize {
        if let Some(k) = self.slots.iter().position(|s| s.is_some_and(|s| s.name == name)) {
            return k;
        }
        let id = lookup(name).unwrap_or_else(|_| panic!("agent: no slot named {name}"));
        let k = self.slots.iter().position(Option::is_none).expect("agent: too many slots");
        self.slots[k] = Some(Slot { name, id, state: State::Empty, image: None });
        k
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
    /// slot `new` again: a rollback). `drain_secs` overrides the old instance's drain deadline.
    pub fn deploy(&mut self, new: usize, image: Option<Image>, drain_secs: Option<u64>) -> bool {
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
        let Some(d) = self.deploys.iter().position(Option::is_none) else { return false };
        self.deploys[d] = Some(Deploy { new, old, step: Step::Start, drain_ticks: drain });
        true
    }

    /// Whether every deployment has finished (done or failed).
    pub fn idle(&self) -> bool {
        self.deploys.iter().flatten().all(|d| matches!(d.step, Step::Done | Step::Failed))
    }

    /// Move every deployment along as far as it can go now.
    pub fn advance(&mut self) {
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
                // RFD 3: a service with a volume isn't ready until it has opened it.
                Step::WaitReady { until: now + READY_TIMEOUT }
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
                        println!("agent: {} drained ({} connections reset at the deadline)", self.get(old).name, forced);
                        self.set(old, State::Drained);
                        // RFD 3: a service with a volume isn't finished until its handoff is.
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
        if let Err(e) = slot::stage_all(s.id, image.elf) {
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
    /// kept until then, for a rollback).
    pub fn commit(&mut self, service: &[u8]) {
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
