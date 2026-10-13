//! Processes: a static task table, one address space each, a round-robin scheduler, and
//! synchronous IPC between processes.
//!
//! There is one kernel stack. Every trap saves the user's registers there as a `TrapFrame`; to
//! switch processes the scheduler stores that frame in the current process, copies the next
//! process's saved frame over it, and switches CR3. The trap path's `iretq` then resumes the next
//! process.
//!
//! The kernel never waits in the middle of a syscall. A process that must wait (in `send` or
//! `recv`) is marked blocked with its registers saved and the scheduler moves on; when another
//! process later completes the operation, the kernel writes the results into the blocked
//! process's saved registers and marks it ready. A blocked sender's arguments stay in those
//! saved registers, so no message queue is needed.

use core::arch::asm;
use core::fmt;
use core::mem::size_of;
use spin::Mutex;

use crate::interrupts::TrapFrame;
use crate::memory::{self, AddressSpace, PAGE_SIZE};
use crate::verify::{self, Rejection};
use crate::{apic, elf, events, gdt, irq, measure, modules, pci, tpm};

/// A process the image runs, declared in the app manifest (see apps/README.md, kernel/build.rs).
pub struct Task {
    pub name: &'static str,
    /// The program: the boot module (`build/<program>.elf`) holding its image.
    pub program: &'static str,
    /// CPU budget in timer ticks; 0 = unlimited. A process that uses it up is killed.
    pub budget_ticks: u64,
    /// Told when other tasks die, and may restart them.
    pub supervisor: bool,
    /// Indices of the tasks this one may send IPC messages to.
    pub sends: &'static [usize],
    /// Kinds of PCI device granted (indices into `pci::KINDS`), one device each.
    pub devices: &'static [usize],
    /// Size of the task's DMA region in pages (0 = none).
    pub dma_pages: u64,
    /// May read the kernel event log and system statistics.
    pub events: bool,
    /// Oldest signed version of the program that may run (rollback protection).
    pub min_version: u64,
    /// Gets the TPM's registers mapped, and the measurement logs (for attestation). It shares
    /// the TPM with the kernel through `tpm_lock`.
    pub tpm: bool,
    /// The network service this task is an instance of (default: its name).
    pub service: &'static str,
    /// TCP ports it may listen on; the network stack asks with `task_listen`.
    pub listen: &'static [Listen],
    /// May change the network stack's routing (live instances, drains, blocklist).
    pub routes: bool,
    /// May load signed service images into slots (`slot_stage`, `slot_load`, `slot_unload`).
    pub loads: bool,
    /// May open outbound connections through a network stack (`net` asks with `task_listen`).
    pub connects: bool,
    /// A generic slot (RFD 2, P1): its class. It runs whatever service image is loaded into it;
    /// `program`, `service` and `listen` are empty, and come from the image's descriptor.
    pub class: Option<&'static SlotClass>,
}

/// A class of generic slots, declared in the manifest with `[[slot_class]]`.
pub struct SlotClass {
    pub name: &'static str,
    /// Most frames a service in the slot may use: its image's pages, stack and page tables.
    pub memory_pages: u64,
    /// Size of the slot's image area: the largest image it can hold.
    pub image_pages: u64,
}

/// A port a task may listen on, with its connection limits.
pub struct Listen {
    pub port: u16,
    pub max_connections: u16,
    pub max_per_source: u16,
}

include!(concat!(env!("OUT_DIR"), "/tasks.rs"));

/// Rows in the `Stats` record user code reads (`vanir_user::MAX_TASKS`); the manifest's
/// `MAX_PROCESSES` is at most this.
const STATS_TASKS: usize = 64;
const _: () = assert!(MAX_PROCESSES <= STATS_TASKS);
const USER_STACK_TOP: u64 = 0x7fff_ffff_f000;
/// 64 KiB: drivers and servers keep several 4 KiB block or message buffers on their stacks.
const USER_STACK_PAGES: u64 = 16;

/// Largest message or reply, in bytes; bounds the time one syscall spends copying.
pub const MAX_MESSAGE: u64 = 4096;

/// Most devices one task may be granted.
const MAX_TASK_DEVICES: usize = 4;
/// Where granted devices' BARs appear in a task: device `d`'s BAR `b` is mapped at
/// `DEVICE_BASE + d * DEVICE_STRIDE + b * BAR_STRIDE`.
const DEVICE_BASE: u64 = 0x10_0000_0000;
const DEVICE_STRIDE: u64 = 0x1000_0000;
const BAR_STRIDE: u64 = 0x200_0000;
/// Where a task's DMA region appears.
const DMA_BASE: u64 = 0x20_0000_0000;
/// Where the TPM's CRB page appears in the task granted `tpm = true`.
const TPM_BASE: u64 = 0x30_0000_0000;

/// What a task slot is given at boot and keeps across restarts.
#[derive(Clone, Copy)]
struct Grants {
    /// The program's ELF image: a boot module, or for a generic slot the image loaded into its
    /// image area (empty while nothing is loaded).
    image: &'static [u8],
    /// A generic slot's image area: physically contiguous (physical address, pages), set aside at
    /// boot. Images are staged into it and restarts reload from it.
    image_area: Option<(u64, u64)>,
    /// PCI devices (indices for `pci::get`).
    devices: [Option<usize>; MAX_TASK_DEVICES],
    /// Physically contiguous DMA region: (physical address, pages).
    dma: Option<(u64, u64)>,
}

/// Kernel error codes returned by IPC syscalls. The top bit is set, so they never collide with a
/// server's reply codes (which must have it clear).
pub mod err {
    pub const DEAD: u64 = 1 << 63;
    pub const NOT_ALLOWED: u64 = DEAD | 1;
    pub const BAD_TARGET: u64 = DEAD | 2;
    pub const BAD_BUFFER: u64 = DEAD | 3;
    pub const TOO_LONG: u64 = DEAD | 4;
    pub const BAD_ARGUMENT: u64 = DEAD | 5;
    /// The TPM is in use (the attestation task holds its lock); try again.
    pub const BUSY: u64 = DEAD | 6;
    /// The run-time measurement log is full: no more loads until the node reboots.
    pub const LOG_FULL: u64 = DEAD | 7;
    /// The image was refused; rdx holds the reason (`verify::Rejection`).
    pub const REJECTED: u64 = DEAD | 8;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ready,
    Running,
    /// In `send`, waiting for the target (slot) to `recv`.
    SendBlocked(usize),
    /// Message delivered, waiting for that slot to `reply`.
    ReplyBlocked(usize),
    /// In `recv`, waiting for a message.
    RecvBlocked,
    /// In `sleep`, until the clock reaches this tick.
    Sleeping(u64),
    Exited(u64),
    Faulted(u64),
    OverBudget,
    /// Its image failed signature checks at boot; it never runs and can't be restarted.
    Rejected(Rejection),
    /// A generic slot with no image loaded. Not restartable; `slot_load` starts it.
    Empty,
    /// Stopped by the supervisor (`stop`): ended on purpose, so not to be restarted unless
    /// asked.
    Stopped,
}

impl State {
    fn is_dead(self) -> bool {
        matches!(self, State::Exited(_) | State::Faulted(_) | State::OverBudget | State::Rejected(_) | State::Empty | State::Stopped)
    }
}

/// How a process ended, as reported to the supervisor (`DeathRecord`).
#[derive(Clone, Copy, Default)]
struct Death {
    rip: u64,
    cr2: u64,
    error_code: u64,
    /// Not yet delivered to the supervisor.
    unreported: bool,
}

/// What the supervisor's `recv` gets when a task dies: sender 0, op `NOTIFY_DEATH`.
#[repr(C)]
struct DeathRecord {
    id: u64,
    /// 1 exited, 2 faulted, 3 over CPU budget, 4 image rejected, 5 stopped.
    kind: u64,
    /// Exit code, or the fault's vector.
    code: u64,
    rip: u64,
    cr2: u64,
    error_code: u64,
    ticks: u64,
}

pub const NOTIFY_DEATH: u64 = 1;
/// `recv` from sender 0 with this op: device interrupts; the length register holds the bits.
pub const NOTIFY_IRQ: u64 = 2;
/// `recv` from sender 0 with this op: the timeout given with `RECV_TIMEOUT` expired.
pub const NOTIFY_TIMER: u64 = 3;
/// `recv` flag (in rdx): give up after r10 ticks with a `NOTIFY_TIMER` notification.
pub const RECV_TIMEOUT: u64 = 2;
/// `recv` from sender 0 with this op: bits another task posted with `notify`; the length
/// register holds them.
pub const NOTIFY_POST: u64 = 4;

/// `recv` flag (in rdx): this task has device work in flight and an interrupt will come, so the
/// kernel should idle for it rather than conclude that nothing can ever run again.
pub const RECV_EXPECT_IRQ: u64 = 1;

/// Give up idling if no process has become ready for this many ticks (5 s) while tasks wait on
/// interrupts: something is stuck, and a test should not hang forever.
const STALL_TICKS: u64 = 500;

struct Process {
    /// Index in the task table and the process table.
    slot: usize,
    /// Bumped on every restart, so an id held from before a restart no longer matches.
    generation: u64,
    task: &'static Task,
    /// Freed (None) as soon as the process ends.
    space: Option<AddressSpace>,
    /// Saved user registers while not running.
    context: TrapFrame,
    state: State,
    ticks: u64,
    death: Death,
    grants: Grants,
    /// While blocked in a `recv` with `RECV_TIMEOUT`: the tick it gives up.
    recv_deadline: Option<u64>,
    /// Bits posted by other tasks with `notify`, not yet received.
    posted: u64,
    /// The signed version running (0 for an empty slot).
    version: u64,
    /// A generic slot's service, from its image's descriptor. None for tasks and empty slots.
    loaded: Option<verify::Descriptor>,
    /// Bytes staged into a generic slot's image area since it was last emptied.
    staged: u64,
}

impl Process {
    /// Task id as user code sees it: `slot + 1` in the low 16 bits (0 means "the kernel"), the
    /// generation above.
    fn id(&self) -> u64 {
        (self.slot as u64 + 1) | self.generation << 16
    }

    fn space(&self) -> &AddressSpace {
        self.space.as_ref().expect("address space of a dead process")
    }

    /// "pid 2 (echo)", or "pid 2.1 (echo)" after its first restart.
    fn describe(&self) -> Describe<'_> {
        Describe(self)
    }
}

struct Describe<'a>(&'a Process);

impl fmt::Display for Describe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let p = self.0;
        write!(f, "pid {}", p.slot + 1)?;
        if p.generation != 0 {
            write!(f, ".{}", p.generation)?;
        }
        write!(f, " ({})", p.task.name)
    }
}

struct Table {
    procs: [Option<Process>; MAX_PROCESSES],
    current: usize,
    /// Frames in use before any task was loaded; every task's memory is freed when it ends.
    baseline_frames: u64,
    supervisor: Option<usize>,
    /// When the scheduler last started idling with no sleepers (only waiting on interrupts).
    stalled_since: Option<u64>,
}

impl Table {
    fn current(&mut self) -> &mut Process {
        self.procs[self.current].as_mut().expect("no current process")
    }

    fn get(&mut self, slot: usize) -> &mut Process {
        self.procs[slot].as_mut().expect("empty slot")
    }

    /// The slot an id names, if it is a task in the table. Does not check the generation.
    fn slot_of(&self, id: u64) -> Option<usize> {
        let index = (id & 0xffff) as usize;
        (1..=MAX_PROCESSES).contains(&index).then(|| index - 1).filter(|&s| self.procs[s].is_some())
    }

    /// Two mutable processes at once (for copying a message between them).
    fn pair(&mut self, a: usize, b: usize) -> (&mut Process, &mut Process) {
        assert_ne!(a, b);
        let (lo, hi) = self.procs.split_at_mut(a.max(b));
        let (first, second) = (lo[a.min(b)].as_mut().unwrap(), hi[0].as_mut().unwrap());
        if a < b { (first, second) } else { (second, first) }
    }
}

static TABLE: Mutex<Table> =
    Mutex::new(Table {
    procs: [const { None }; MAX_PROCESSES],
    current: 0,
    baseline_frames: 0,
    supervisor: None,
    stalled_since: None,
});

/// Check every task's image, measure the boot, load the tasks, then enter the first one.
/// `kernel_file` is the kernel's own image, for the measurement. Never returns.
pub fn start(kernel_file: &[u8]) -> ! {
    assert!(!TASKS.is_empty() && TASKS.len() <= MAX_PROCESSES, "need 1..={MAX_PROCESSES} tasks");
    let mut table = TABLE.lock();
    table.supervisor = TASKS.iter().position(|t| t.supervisor);

    // Grants first: DMA regions are permanent, so they belong in the baseline, not the leak check.
    let mut claimed = [false; pci::MAX_DEVICES];
    let mut grants = [Grants { image: &[], image_area: None, devices: [None; MAX_TASK_DEVICES], dma: None }; MAX_PROCESSES];
    let mut vectors = irq::DEVICE_VECTORS;
    for (slot, task) in TASKS.iter().enumerate() {
        if let Some(class) = task.class {
            // Image areas are permanent, like DMA regions.
            grants[slot].image_area = Some((memory::alloc_contiguous(class.image_pages), class.image_pages));
            continue;
        }
        grants[slot].image = modules::find(task.program)
            .unwrap_or_else(|| panic!("{}: no boot module for program {}", task.name, task.program));
        grants[slot].devices = claim_devices(task, &mut claimed);
        for (bit, device) in grants[slot].devices.iter().enumerate() {
            let Some(device) = *device else { continue };
            let vector = vectors.next().expect("out of device interrupt vectors");
            if pci::enable_msix(device, vector) {
                irq::route(vector, slot, bit);
            }
        }
        if task.dma_pages != 0 {
            grants[slot].dma = Some((memory::alloc_contiguous(task.dma_pages), task.dma_pages));
        }
    }
    // Mapping the TPM's registers allocates kernel page tables: do it before the baseline too.
    tpm::init();
    table.baseline_frames = memory::frames_in_use();

    let mut measured: [(&'static str, Option<&[u8]>); MAX_PROCESSES] = [("", None); MAX_PROCESSES];
    let mut tasks = 0;
    for (slot, task) in TASKS.iter().enumerate() {
        let grants = grants[slot];
        let mut p = Process {
            slot,
            generation: 0,
            task,
            space: None,
            context: TrapFrame::default(),
            state: State::Ready,
            ticks: 0,
            death: Death::default(),
            grants,
            recv_deadline: None,
            posted: 0,
            version: 0,
            loaded: None,
            staged: 0,
        };
        if task.class.is_some() {
            p.state = State::Empty;
            table.procs[slot] = Some(p);
            continue;
        }
        let checked = verify::check(task.program, modules::find(task.program), signature_of(task.program), task.min_version);
        measured[tasks] = (task.name, checked.ok().map(|(_, statement)| statement));
        tasks += 1;
        match checked {
            Ok((version, _statement)) => {
                let (space, context) = load(task, &grants).unwrap_or_else(|e| panic!("cannot load {}: {e:?}", task.name));
                p.space = Some(space);
                p.context = context;
                p.version = version;
                events::log(events::TASK_START, p.id(), version, 0, 0);
                println!("[kernel] {}: {}-byte ELF, signed version {}, entry {:#x}", p.describe(), grants.image.len(), version, p.context.rip);
            }
            Err(why) => {
                p.state = State::Rejected(why);
                p.death.unreported = table.supervisor.is_some();
                events::log(events::IMAGE_REJECTED, p.id(), why as u64, 0, 0);
                println!("[kernel] {}: image REJECTED: {}", p.describe(), why.describe());
            }
        }
        table.procs[slot] = Some(p);
    }

    measure::boot(kernel_file, MANIFEST, &measured[..tasks]);
    reserve_slots(table.baseline_frames);

    let Some(first) = table.procs.iter().flatten().position(|p| p.state == State::Ready) else {
        finish(&table, false) // every image was rejected
    };
    table.current = first;
    let first = table.current();
    first.state = State::Running;
    first.space().activate();
    let (rip, rsp) = (first.context.rip, first.context.rsp);
    drop(table);
    println!("[kernel] entering ring 3");
    enter_user(rip, rsp)
}

/// Check that memory can hold every slot at its class's limit, and say what the slots are. Tasks'
/// memory is fixed once loaded (there is no syscall to grow it), and restarts free before they
/// reload, so after this check a load can't fail for want of memory.
fn reserve_slots(baseline: u64) {
    let slots = TASKS.iter().filter(|t| t.class.is_some());
    let reserve: u64 = slots.clone().map(|t| t.class.unwrap().memory_pages).sum();
    if reserve == 0 {
        return;
    }
    let available = memory::frames_available();
    assert!(available >= reserve, "slots need {reserve} frames at their limits; only {available} are free");
    println!(
        "[kernel] {} slot(s) in {} class(es): {} frames set aside, {} free, {} in use before tasks",
        slots.count(),
        SLOT_CLASSES.len(),
        reserve,
        available,
        baseline
    );
}

/// The signature file shipped with `program` (boot module `<program>.sig`).
fn signature_of(program: &str) -> Option<&'static [u8]> {
    let mut name = [0u8; 40];
    let name = name.get_mut(..program.len() + 4)?;
    name[..program.len()].copy_from_slice(program.as_bytes());
    name[program.len()..].copy_from_slice(b".sig");
    modules::find(core::str::from_utf8(name).ok()?)
}

/// For each device kind the task asks for, take the next unclaimed device of that kind.
fn claim_devices(task: &Task, claimed: &mut [bool; pci::MAX_DEVICES]) -> [Option<usize>; MAX_TASK_DEVICES] {
    assert!(task.devices.len() <= MAX_TASK_DEVICES, "{}: too many devices", task.name);
    let mut devices = [None; MAX_TASK_DEVICES];
    for (i, &kind) in task.devices.iter().enumerate() {
        devices[i] = pci::of_kind(kind).find(|&d| !claimed[d]);
        match devices[i] {
            Some(d) => claimed[d] = true,
            None => println!("[kernel] {}: no {} device found", task.name, pci::KINDS[kind].0),
        }
    }
    devices
}

/// A fresh address space with `task` loaded, its stack, granted devices and DMA region mapped,
/// and its starting registers.
fn load(task: &Task, grants: &Grants) -> Result<(AddressSpace, TrapFrame), elf::LoadError> {
    let space = AddressSpace::new();
    let entry = elf::load(grants.image, &space)?;
    for page in 1..=USER_STACK_PAGES {
        space.map_user_page(USER_STACK_TOP - page * PAGE_SIZE, true, false);
    }
    if let Some((phys, pages)) = grants.dma {
        for page in 0..pages {
            space.map_user_pinned(DMA_BASE + page * PAGE_SIZE, phys + page * PAGE_SIZE);
        }
    }
    if task.tpm && tpm::present() {
        space.map_user_device(TPM_BASE, tpm::CRB_PHYS);
    }
    for (d, device) in grants.devices.iter().enumerate() {
        let Some(device) = device.and_then(pci::get) else { continue };
        for (b, bar) in device.bars.iter().enumerate() {
            if bar.size == 0 || bar.msix {
                continue; // absent, or the MSI-X table: interrupt routing stays with the kernel
            }
            assert!(bar.size <= BAR_STRIDE, "{}: BAR {} too large to map", task.name, b);
            let base = DEVICE_BASE + d as u64 * DEVICE_STRIDE + b as u64 * BAR_STRIDE;
            for offset in (0..bar.size.max(PAGE_SIZE)).step_by(PAGE_SIZE as usize) {
                space.map_user_device(base + offset, bar.phys + offset);
            }
        }
    }
    Ok((space, initial_context(entry, USER_STACK_TOP)))
}

/// Timer interrupt: charge the tick to the running process, then preempt it, or kill it if it
/// has used up its CPU budget.
pub fn tick(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    wake_sleepers(&mut table);
    let p = table.current();
    p.ticks += 1;
    let budget = p.task.budget_ticks;
    if budget != 0 && p.ticks >= budget {
        println!("[kernel] {} killed: CPU budget of {} ticks used up", p.describe(), budget);
        events::log(events::OVER_BUDGET, p.id(), budget, 0, 0);
        return end_current(&mut table, frame, State::OverBudget);
    }
    block(&mut table, frame, State::Ready);
}

/// `sleep(ticks)`: wait at least that many timer ticks (10 ms each). 0 just yields.
pub fn sleep(frame: &mut TrapFrame) {
    let ticks = frame.rdi;
    frame.rax = 0;
    let state = if ticks == 0 { State::Ready } else { State::Sleeping(apic::now() + ticks) };
    block(&mut TABLE.lock(), frame, state);
}

/// `uptime() -> ticks` since boot.
pub fn uptime(frame: &mut TrapFrame) {
    frame.rax = apic::now();
}

/// A device interrupt arrived while user code ran: wake its task if it waits in `recv`, and if
/// one woke, let the scheduler run (drivers are latency-sensitive; clients wait on them).
pub fn irq_arrived(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if wake_irq_waiters(&mut table) {
        block(&mut table, frame, State::Ready);
    }
}

/// Deliver pending interrupt bits to tasks waiting in `recv`. Returns whether any woke.
fn wake_irq_waiters(table: &mut Table) -> bool {
    let mut woke = false;
    for p in table.procs.iter_mut().flatten() {
        if p.state == State::RecvBlocked && irq::pending(p.slot) {
            p.context.rax = 0;
            p.context.rdx = NOTIFY_IRQ;
            p.context.rsi = irq::take(p.slot);
            p.state = State::Ready;
            woke = true;
        }
    }
    woke
}

/// Make every sleeper whose time has come ready.
fn wake_sleepers(table: &mut Table) {
    let now = apic::now();
    for p in table.procs.iter_mut().flatten() {
        if matches!(p.state, State::Sleeping(until) if until <= now) {
            p.state = State::Ready;
        }
        if p.state == State::RecvBlocked && p.recv_deadline.is_some_and(|d| d <= now) {
            p.recv_deadline = None;
            p.context.rax = 0;
            p.context.rdx = NOTIFY_TIMER;
            p.context.rsi = 0;
            p.state = State::Ready;
        }
    }
}

/// `sched_yield()`: give up the rest of this time slice.
pub fn yield_now(frame: &mut TrapFrame) {
    frame.rax = 0;
    block(&mut TABLE.lock(), frame, State::Ready);
}

pub fn current_id() -> u64 {
    TABLE.lock().current().id()
}

/// `exit(code)`: end the current process and resume the next one in `frame`.
pub fn exit(frame: &mut TrapFrame, code: u64) {
    let mut table = TABLE.lock();
    let p = table.current();
    println!("[kernel] {} exited with code {} (called from CPL {})", p.describe(), code, frame.cs & 3);
    events::log(events::EXIT, p.id(), code, 0, 0);
    end_current(&mut table, frame, State::Exited(code));
}

/// A fault in user mode ends that process, not the kernel; the next process resumes in `frame`.
pub fn kill(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let p = table.current();
    println!("[kernel] {} killed by vector {}", p.describe(), frame.vector);
    let cr2 = if frame.vector == 14 { x86_64::registers::control::Cr2::read_raw() } else { 0 };
    p.death = Death { rip: frame.rip, cr2, error_code: frame.error_code, unreported: false };
    events::log(events::FAULT, p.id(), frame.vector, frame.rip, cr2);
    end_current(&mut table, frame, State::Faulted(frame.vector));
}

/// The current process has ended: free its memory, fail every IPC waiting on it with DEAD, tell
/// the supervisor, and resume the next process.
fn end_current(table: &mut Table, frame: &mut TrapFrame, outcome: State) {
    let dead = table.current;
    end_task(table, dead, outcome);
    switch_to_next(table, frame);
}

/// Process `dead` has ended (not necessarily the current one): free its memory, fail every
/// IPC waiting on it with DEAD, and tell the supervisor.
fn end_task(table: &mut Table, dead: usize, outcome: State) {
    if table.supervisor == Some(dead) {
        // The supervisor is trusted to keep the system running; without it nothing can.
        println!("[kernel] the supervisor died; stopping");
        crate::halt(3);
    }
    let has_supervisor = table.supervisor.is_some();
    let p = table.get(dead);
    if p.task.tpm {
        measure::hold_tpm(false); // a lock nobody can drop would block every load
    }
    if !matches!(outcome, State::Faulted(_)) {
        p.death = Death::default();
    }
    p.death.unreported = has_supervisor;
    p.state = outcome;
    p.space = None;
    for p in table.procs.iter_mut().flatten() {
        if matches!(p.state, State::SendBlocked(s) | State::ReplyBlocked(s) if s == dead) {
            p.context.rax = err::DEAD;
            p.context.rdx = 0;
            p.state = State::Ready;
        }
    }
    if let Some(sup) = table.supervisor
        && table.get(sup).state == State::RecvBlocked
    {
        let (buf, cap) = (table.get(sup).context.rdi, table.get(sup).context.rsi);
        let mut regs = table.get(sup).context;
        if report_death(table, sup, buf, cap, &mut regs) {
            let sup = table.get(sup);
            sup.context = regs;
            sup.state = State::Ready;
        }
    }
}

/// If a death is waiting to be reported, write its record to the supervisor's buffer and set
/// `regs` to the `recv` results (sender 0, op NOTIFY_DEATH). Returns whether one was reported.
fn report_death(table: &mut Table, sup: usize, buf: u64, cap: u64, regs: &mut TrapFrame) -> bool {
    let Some(dead) = table.procs.iter().flatten().position(|p| p.death.unreported) else { return false };
    let p = table.get(dead);
    let (kind, code) = match p.state {
        State::Exited(code) => (1, code),
        State::Faulted(vector) => (2, vector),
        State::OverBudget => (3, 0),
        State::Rejected(why) => (4, why as u64),
        State::Stopped => (5, 0),
        _ => unreachable!("only dead processes have deaths to report"),
    };
    let record = DeathRecord {
        id: p.id(),
        kind,
        code,
        rip: p.death.rip,
        cr2: p.death.cr2,
        error_code: p.death.error_code,
        ticks: p.ticks,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(&record as *const DeathRecord as *const u8, size_of::<DeathRecord>())
    };
    if cap < bytes.len() as u64 {
        regs.rax = err::TOO_LONG;
        return true;
    }
    if memory::copy_to_user_space(table.get(sup).space(), buf, bytes).is_err() {
        regs.rax = err::BAD_BUFFER;
        return true;
    }
    table.get(dead).death.unreported = false;
    regs.rax = 0;
    regs.rdx = NOTIFY_DEATH;
    regs.rsi = bytes.len() as u64;
    true
}

/// Save the running process's registers, give it `state` (Ready to preempt it, or a blocked
/// state), and resume the next ready process, which may be the same one.
fn block(table: &mut Table, frame: &mut TrapFrame, state: State) {
    let p = table.current();
    p.context = *frame;
    p.state = state;
    switch_to_next(table, frame);
}

/// Resume the next ready process (round-robin after the current one) by loading its saved
/// registers into `frame` and its address space into CR3. If none is ready but some are
/// sleeping, idle until one wakes; if nothing can ever become ready, stop the machine.
fn switch_to_next(table: &mut Table, frame: &mut TrapFrame) {
    loop {
        wake_sleepers(table);
        wake_irq_waiters(table);
        for step in 1..=MAX_PROCESSES {
            let i = (table.current + step) % MAX_PROCESSES;
            if let Some(p) = table.procs[i].as_mut().filter(|p| p.state == State::Ready) {
                p.state = State::Running;
                p.recv_deadline = None; // however it woke, a pending recv timeout is moot
                *frame = p.context;
                if i != table.current {
                    // Reloading CR3 flushes the TLB, so skip it when staying put.
                    p.space().activate();
                }
                table.current = i;
                table.stalled_since = None;
                return;
            }
        }
        let procs = || table.procs.iter().flatten();
        // Time will wake sleepers and receivers with a timeout.
        let sleeping = procs().any(|p| matches!(p.state, State::Sleeping(_)) || (p.state == State::RecvBlocked && p.recv_deadline.is_some()));
        // A blocked recv's flags are still in its saved registers.
        let awaiting_device = procs().any(|p| p.state == State::RecvBlocked && p.context.rdx & RECV_EXPECT_IRQ != 0);
        if !sleeping && !awaiting_device {
            finish(table, false)
        }
        if !sleeping {
            let since = *table.stalled_since.get_or_insert(apic::now());
            if apic::now() - since >= STALL_TICKS {
                println!("[kernel] no process has run for {} ticks while waiting on devices", STALL_TICKS);
                finish(table, false)
            }
        }
        idle();
    }
}

/// Halt until the next interrupt. We hold the process table, which is safe because interrupts
/// taken in kernel mode never touch it: the timer only advances the clock. `sti; hlt` is one
/// step (the CPU takes no interrupt between the two), so a tick can't slip in before the halt.
fn idle() {
    unsafe { asm!("sti", "hlt", "cli", options(nomem, nostack)) };
}

// ---- IPC -------------------------------------------------------------------------------------

/// `send(target, op, msg, len, reply_buf, reply_cap) -> (code, reply_len)` in rax, rdx.
///
/// Delivers straight away if the target is waiting in `recv`; otherwise waits for it to. Either
/// way the sender then waits for the reply. Errors come back in rax without blocking.
pub fn send(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let me = table.current;
    // The arguments stay in `frame`: a blocked sender's saved registers are its pending message.
    let (target, msg, len, reply_buf, reply_cap) = (frame.rdi, frame.rdx, frame.r10, frame.r8, frame.r9);

    let Some(to) = table.slot_of(target).filter(|&s| s != me) else {
        return fail(frame, err::BAD_TARGET);
    };
    if !table.current().task.sends.contains(&to) {
        events::log(events::IPC_REFUSED, table.current().id(), target, err::NOT_ALLOWED, 0);
        return fail(frame, err::NOT_ALLOWED);
    }
    let peer = table.get(to);
    if peer.state.is_dead() || peer.id() != target {
        return fail(frame, err::DEAD);
    }
    if len > MAX_MESSAGE || reply_cap > MAX_MESSAGE {
        return fail(frame, err::TOO_LONG);
    }
    let space = table.current().space();
    if !space.check_range(msg, len, false) || !space.check_range(reply_buf, reply_cap, true) {
        events::log(events::IPC_REFUSED, table.current().id(), target, err::BAD_BUFFER, 0);
        return fail(frame, err::BAD_BUFFER);
    }

    if table.get(to).state == State::RecvBlocked {
        // The receiver's buffer arguments are in its saved registers.
        let (buf, cap) = (table.get(to).context.rdi, table.get(to).context.rsi);
        if len > cap {
            return fail(frame, err::TOO_LONG);
        }
        table.current().context = *frame;
        deliver(&mut table, me, to, buf);
        return block(&mut table, frame, State::ReplyBlocked(to));
    }
    block(&mut table, frame, State::SendBlocked(to));
}

/// Return a kernel error from `send`: code in rax, reply length 0.
fn fail(frame: &mut TrapFrame, code: u64) {
    frame.rax = code;
    frame.rdx = 0;
}

/// Copy the message held in `from`'s saved `send` registers into `to`'s buffer at `buf`, set
/// `to`'s `recv` results, and make `to` ready (or leave it running if it is current).
fn deliver(table: &mut Table, from: usize, to: usize, buf: u64) {
    let current = table.current;
    let (sender, receiver) = table.pair(from, to);
    let (op, msg, len) = (sender.context.rsi, sender.context.rdx, sender.context.r10);
    memory::copy_between(sender.space(), msg, receiver.space(), buf, len).expect("buffers were checked");
    let regs = if to == current { None } else { Some(&mut receiver.context) };
    let id = sender.id();
    if let Some(ctx) = regs {
        ctx.rax = id;
        ctx.rdx = op;
        ctx.rsi = len;
        receiver.state = State::Ready;
    }
}

/// `recv(buf, cap, flags) -> (sender, op, len)` in rax, rdx, rsi. Takes the next waiting
/// sender, round-robin from after the last one served, or waits for one. Kernel notifications
/// (deaths for the supervisor, then device interrupts) come first. Flags: `RECV_EXPECT_IRQ`.
pub fn recv(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let me = table.current;
    let (buf, cap) = (frame.rdi, frame.rsi);
    if cap > MAX_MESSAGE {
        frame.rax = err::TOO_LONG;
        return;
    }
    if !table.current().space().check_range(buf, cap, true) {
        frame.rax = err::BAD_BUFFER;
        return;
    }

    // The supervisor hears about deaths, and drivers about interrupts, before ordinary messages.
    if table.supervisor == Some(me) && report_death(&mut table, me, buf, cap, frame) {
        return;
    }
    let bits = irq::take(me);
    if bits != 0 {
        frame.rax = 0;
        frame.rdx = NOTIFY_IRQ;
        frame.rsi = bits;
        return;
    }
    let posted = core::mem::take(&mut table.current().posted);
    if posted != 0 {
        frame.rax = 0;
        frame.rdx = NOTIFY_POST;
        frame.rsi = posted;
        return;
    }

    for step in 1..=MAX_PROCESSES {
        let from = (me + step) % MAX_PROCESSES;
        let Some(sender) = table.procs[from].as_mut() else { continue };
        if sender.state != State::SendBlocked(me) {
            continue;
        }
        if sender.context.r10 > cap {
            // Doesn't fit: fail that send rather than truncate it, and keep looking.
            sender.context.rax = err::TOO_LONG;
            sender.state = State::Ready;
            continue;
        }
        let (id, op, len) = (sender.id(), sender.context.rsi, sender.context.r10);
        deliver(&mut table, from, me, buf);
        table.get(from).state = State::ReplyBlocked(me);
        frame.rax = id;
        frame.rdx = op;
        frame.rsi = len;
        return;
    }
    if frame.rdx & RECV_TIMEOUT != 0 && frame.r10 == 0 {
        // A timeout of 0 only polls: nothing is waiting, so the time is up already.
        frame.rax = 0;
        frame.rdx = NOTIFY_TIMER;
        frame.rsi = 0;
        return;
    }
    table.current().recv_deadline = (frame.rdx & RECV_TIMEOUT != 0).then(|| apic::now() + frame.r10);
    block(&mut table, frame, State::RecvBlocked);
}

/// `reply(sender, code, buf, len) -> status`. Copies the reply into the waiting sender's reply
/// buffer and wakes it with `(code, len)`. Never blocks the caller.
pub fn reply(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let me = table.current;
    let (target, code, buf, len) = (frame.rdi, frame.rsi, frame.rdx, frame.r10);
    frame.rax = 0;

    if code & err::DEAD != 0 {
        frame.rax = err::BAD_ARGUMENT; // the top bit is reserved for kernel errors
        return;
    }
    let Some(to) = table.slot_of(target) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let client = table.get(to);
    if client.id() != target || client.state != State::ReplyBlocked(me) {
        frame.rax = err::DEAD; // not waiting for our reply (gone, restarted, or never asked)
        return;
    }
    let (reply_buf, reply_cap) = (client.context.r8, client.context.r9);
    if len > reply_cap {
        client.context.rax = err::TOO_LONG;
        client.context.rdx = 0;
        client.state = State::Ready;
        frame.rax = err::TOO_LONG;
        return;
    }
    let (server, client) = table.pair(me, to);
    if memory::copy_between(server.space(), buf, client.space(), reply_buf, len).is_err() {
        frame.rax = err::BAD_BUFFER; // the server's buffer; the client keeps waiting
        return;
    }
    client.context.rax = code;
    client.context.rdx = len;
    client.state = State::Ready;
}

/// `notify(target, bits) -> 0`: post `bits` (not 0) to a task this one may send to, or that may
/// send to it, without waiting. They reach the target's next `recv` as sender 0, op
/// `NOTIFY_POST`, ORed with any others not yet received. This is how a server tells a client that
/// something is ready while only the client ever sends to the server, so the two can't deadlock
/// sending to each other (RFD 3's writer bit goes from `storage` to slots, which nothing may send
/// to).
pub fn notify(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let me = table.current;
    let (target, bits) = (frame.rdi, frame.rsi);
    let Some(to) = table.slot_of(target).filter(|&s| s != me) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    if !table.current().task.sends.contains(&to) && !table.get(to).task.sends.contains(&me) {
        events::log(events::IPC_REFUSED, table.current().id(), target, err::NOT_ALLOWED, 0);
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let peer = table.get(to);
    if peer.state.is_dead() || peer.id() != target {
        frame.rax = err::DEAD;
        return;
    }
    if bits == 0 {
        frame.rax = err::BAD_ARGUMENT;
        return;
    }
    peer.posted |= bits;
    if peer.state == State::RecvBlocked {
        peer.context.rax = 0;
        peer.context.rdx = NOTIFY_POST;
        peer.context.rsi = core::mem::take(&mut peer.posted);
        peer.state = State::Ready;
    }
    frame.rax = 0;
}

/// `lookup(name, len) -> id` of the task with that name, or BAD_TARGET.
pub fn lookup(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let (name, len) = (frame.rdi, frame.rsi);
    let mut buf = [0u8; 64];
    let Some(buf) = buf.get_mut(..len as usize) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    if crate::usercopy::copy_from_user(buf, name).is_err() {
        frame.rax = err::BAD_BUFFER;
        return;
    }
    let found = table.procs.iter_mut().flatten().find(|p| p.task.name.as_bytes() == buf);
    frame.rax = found.map_or(err::BAD_TARGET, |p| p.id());
}

// ---- Supervisor ------------------------------------------------------------------------------

/// `restart(id) -> new id`: reload a dead task from its ELF into fresh memory, with zeroed
/// registers and a new generation. Supervisor only.
pub fn restart(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if table.supervisor != Some(table.current) {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let id = frame.rdi;
    let Some(slot) = table.slot_of(id) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let p = table.get(slot);
    let old_id = p.id();
    if p.id() != id || !p.state.is_dead() || matches!(p.state, State::Rejected(_) | State::Empty) {
        frame.rax = err::BAD_ARGUMENT; // already restarted, still alive, or nothing to run
        return;
    }
    if let Some((phys, pages)) = p.grants.dma {
        // A fresh start sees a clean DMA region, as at boot.
        unsafe { memory::phys_to_virt(phys).write_bytes(0, (pages * PAGE_SIZE) as usize) };
    }
    irq::take(slot); // interrupts meant for the previous incarnation
    // The image loaded before (boot module or slot image area) loaded then, so it loads again.
    let (space, context) = load(p.task, &p.grants).unwrap_or_else(|e| panic!("cannot reload {}: {e:?}", p.task.name));
    p.space = Some(space);
    p.context = context;
    p.generation += 1;
    p.state = State::Ready;
    p.ticks = 0;
    p.death = Death::default();
    p.posted = 0;
    frame.rax = p.id();
    events::log(events::RESTART, p.id(), old_id, 0, 0);
}

/// `stop(id)`: end live task `id` on purpose. It dies like any task (memory freed, IPC waiting
/// on it fails with DEAD) and is reported as stopped (death kind 5), which the supervisor
/// doesn't restart. Supervisor only; the agent asks it (RFD 2, P4).
pub fn stop(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let me = table.current;
    if table.supervisor != Some(me) {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let Some(slot) = table.slot_of(frame.rdi).filter(|&s| s != me) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let p = table.get(slot);
    if p.id() != frame.rdi || p.state.is_dead() {
        frame.rax = err::DEAD;
        return;
    }
    println!("[kernel] {} stopped", p.describe());
    events::log(events::STOPPED, p.id(), 0, 0, 0);
    p.recv_deadline = None;
    irq::take(slot);
    // The task never runs again, so drop what it was waiting on too: a client blocked in
    // `send` to it, or it in `send`/`recv`, is handled by end_task and the state change.
    end_task(&mut table, slot, State::Stopped);
    frame.rax = 0;
}

/// `reboot()`: reset the machine, so it boots whatever image is installed now (RFD 2, P3:
/// evacuate and update). Supervisor only; the agent asks it, and only when it runs no instances.
/// Under QEMU with `-no-reboot`, QEMU exits with status 0 instead.
pub fn reboot(frame: &mut TrapFrame) {
    let table = TABLE.lock();
    if table.supervisor != Some(table.current) {
        drop(table);
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    println!("[kernel] rebooting");
    crate::reset()
}

/// `halt(code)`: stop the system now, reporting every task's state as when nothing can run.
/// Supervisor only: it decides when a run is over (e.g. tests whose servers never go idle).
pub fn halt(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if table.supervisor != Some(table.current) {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    println!("[kernel] the supervisor stopped the system (code {})", frame.rdi);
    let current = table.current;
    table.get(current).context = *frame;
    finish(&table, true)
}

/// `task_state(id) -> (state, current id)`: 0 running or ready, 1 blocked in IPC, 2 exited,
/// 3 faulted, 4 over budget, 5 image rejected, 6 empty slot, 7 stopped. Supervisor only.
pub fn task_state(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if table.supervisor != Some(table.current) {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let Some(slot) = table.slot_of(frame.rdi) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let p = table.get(slot);
    frame.rax = state_code(p.state);
    frame.rdx = p.id();
}

/// 0 running or ready, 1 blocked (IPC or sleep), 2 exited, 3 faulted, 4 over budget, 5 image
/// rejected, 6 empty slot, 7 stopped.
fn state_code(state: State) -> u64 {
    match state {
        State::Ready | State::Running => 0,
        State::SendBlocked(_) | State::ReplyBlocked(_) | State::RecvBlocked | State::Sleeping(_) => 1,
        State::Exited(_) => 2,
        State::Faulted(_) => 3,
        State::OverBudget => 4,
        State::Rejected(_) => 5,
        State::Empty => 6,
        State::Stopped => 7,
    }
}

// ---- Devices -------------------------------------------------------------------------------

/// The current task's granted device `index`, if it has one.
fn my_device(table: &mut Table, index: u64) -> Option<&'static pci::Device> {
    let index = usize::try_from(index).ok().filter(|&i| i < MAX_TASK_DEVICES)?;
    table.current().grants.devices[index].and_then(pci::get)
}

/// `dma_info() -> (address, physical address, length)` of this task's DMA region. The physical
/// address is what a device needs; the region is contiguous and stays the task slot's for life.
/// `measurements(buf, cap) -> (count, tpm address)`: the boot measurement log as 48-byte
/// entries (16-byte zero-padded name, 32-byte SHA-256), and where the TPM is mapped. Only for the
/// task with `tpm = true`; BAD_ARGUMENT if there is no TPM.
pub fn measurements(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if !table.current().task.tpm {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    if !tpm::present() {
        frame.rax = err::BAD_ARGUMENT;
        return;
    }
    let mut out = [0u8; 48 * 16];
    let mut count = 0;
    for entry in measure::log().iter().flatten() {
        let record = &mut out[48 * count..48 * (count + 1)];
        let name = entry.what.as_bytes();
        record[..name.len().min(16)].copy_from_slice(&name[..name.len().min(16)]);
        record[16..].copy_from_slice(&entry.digest);
        count += 1;
    }
    if frame.rsi < (48 * count) as u64 {
        frame.rax = err::TOO_LONG;
        return;
    }
    match memory::copy_to_user_space(table.current().space(), frame.rdi, &out[..48 * count]) {
        Ok(()) => {
            frame.rax = count as u64;
            frame.rdx = TPM_BASE;
        }
        Err(_) => frame.rax = err::BAD_BUFFER,
    }
}

pub fn dma_info(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    match table.current().grants.dma {
        Some((phys, pages)) => {
            frame.rax = DMA_BASE;
            frame.rdx = phys;
            frame.rsi = pages * PAGE_SIZE;
        }
        None => frame.rax = err::BAD_ARGUMENT,
    }
}

/// `device_bar(device, bar) -> (address, size)` of a mapped BAR of a granted device.
pub fn device_bar(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let (index, b) = (frame.rdi, frame.rsi);
    let bar = my_device(&mut table, index).and_then(|d| d.bars.get(b as usize)).filter(|bar| bar.size != 0 && !bar.msix);
    match bar {
        Some(bar) => {
            frame.rax = DEVICE_BASE + index * DEVICE_STRIDE + b * BAR_STRIDE;
            frame.rdx = bar.size;
        }
        None => frame.rax = err::BAD_ARGUMENT,
    }
}

/// `pci_config_read(device, offset) -> u32` from a granted device's configuration space.
/// Read-only: configuration (including interrupt routing) stays with the kernel.
pub fn pci_config_read(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let offset = frame.rsi;
    frame.rax = match my_device(&mut table, frame.rdi) {
        Some(d) if offset < 256 && offset % 4 == 0 => d.read(offset as u8) as u64,
        _ => err::BAD_ARGUMENT,
    };
}

// ---- Telemetry --------------------------------------------------------------------------

/// `read_events(buf, cap) -> (count, dropped)`: kernel events after the last ones read, as
/// `events::Event` records. Only for the task with `events = true`.
pub fn read_events(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if !table.current().task.events {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let (buf, cap) = (frame.rdi, frame.rsi);
    let mut out = [events::Event::default(); 32];
    let max = (cap as usize / events::EVENT_SIZE).min(out.len());
    if !table.current().space().check_range(buf, (max * events::EVENT_SIZE) as u64, true) {
        frame.rax = err::BAD_BUFFER;
        return;
    }
    let (count, dropped) = events::read(&mut out[..max]);
    let bytes = unsafe { core::slice::from_raw_parts(out.as_ptr() as *const u8, count * events::EVENT_SIZE) };
    memory::copy_to_user_space(table.current().space(), buf, bytes).expect("checked above");
    frame.rax = count as u64;
    frame.rdx = dropped;
}

/// System statistics for heartbeats, as written by `stats(buf)`.
#[repr(C)]
struct Stats {
    uptime_ticks: u64,
    frames_in_use: u64,
    device_interrupts: u64,
    events_logged: u64,
    tasks: u64,
    /// Per task: id, state (as `task_state`), CPU ticks.
    task: [[u64; 3]; STATS_TASKS],
}

/// `stats(buf, cap) -> bytes`: a `Stats` record. Only for the task with `events = true`.
pub fn stats(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if !table.current().task.events {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let mut stats = Stats {
        uptime_ticks: apic::now(),
        frames_in_use: memory::frames_in_use(),
        device_interrupts: irq::count(),
        events_logged: events::logged(),
        tasks: 0,
        task: [[0; 3]; STATS_TASKS],
    };
    for p in table.procs.iter().flatten() {
        stats.task[p.slot] = [p.id(), state_code(p.state), p.ticks];
        stats.tasks += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(&stats as *const Stats as *const u8, size_of::<Stats>()) };
    if frame.rsi < bytes.len() as u64 {
        frame.rax = err::TOO_LONG;
        return;
    }
    match memory::copy_to_user_space(table.current().space(), frame.rdi, bytes) {
        Ok(()) => frame.rax = bytes.len() as u64,
        Err(_) => frame.rax = err::BAD_BUFFER,
    }
}

/// `task_name(id, buf, cap) -> len`: the manifest name of a task (any generation of its id).
pub fn task_name(frame: &mut TrapFrame) {
    let table = TABLE.lock();
    let Some(slot) = table.slot_of(frame.rdi) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let (buf, cap) = (frame.rsi, frame.rdx);
    let name = table.procs[slot].as_ref().unwrap().task.name.as_bytes();
    let space = table.procs[table.current].as_ref().unwrap().space();
    if cap < name.len() as u64 {
        frame.rax = err::TOO_LONG;
        return;
    }
    match memory::copy_to_user_space(space, buf, name) {
        Ok(()) => frame.rax = name.len() as u64,
        Err(_) => frame.rax = err::BAD_BUFFER,
    }
}

/// What `task_listen` writes: a task's service, flags (bit 0: may route; bit 1: may connect
/// out; bit 2: is a generic slot; bit 3: may load slots) and ports, each as (port,
/// max_connections, max_per_source, 0), its signed version, and its volume's size (RFD 3).
#[repr(C)]
struct ListenInfo {
    service: [u8; 32],
    service_len: u64,
    flags: u64,
    count: u64,
    ports: [[u16; 4]; 8],
    version: u64,
    volume_blocks: u64,
}

/// `task_listen(id, buf, cap) -> bytes`: the network declarations of task `id` (any generation)
/// as a `ListenInfo`: from the manifest, or for a slot from its service's signed descriptor. The
/// network stack uses it to check who may listen where; the kernel vouches for it as it does for
/// task names.
pub fn task_listen(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let Some(slot) = table.slot_of(frame.rdi) else {
        frame.rax = err::BAD_TARGET;
        return;
    };
    let p = table.get(slot);
    let task = p.task;
    let flags = task.routes as u64 | (task.connects as u64) << 1 | (task.class.is_some() as u64) << 2 | (task.loads as u64) << 3;
    let volume_blocks = p.loaded.map_or(0, |d| d.volume_blocks);
    let mut info =
        ListenInfo { service: [0; 32], service_len: 0, flags, count: 0, ports: [[0; 4]; 8], version: p.version, volume_blocks };
    let service = match &p.loaded {
        Some(d) => d.name(),
        None => task.service.as_bytes(),
    };
    info.service[..service.len()].copy_from_slice(service);
    info.service_len = service.len() as u64;
    match &p.loaded {
        Some(d) => {
            for (out, &(port, max, per_source)) in info.ports.iter_mut().zip(&d.listen[..d.listen_count]) {
                *out = [port, max, per_source, 0];
                info.count += 1;
            }
        }
        None => {
            for (out, l) in info.ports.iter_mut().zip(task.listen) {
                *out = [l.port, l.max_connections, l.max_per_source, 0];
                info.count += 1;
            }
        }
    }
    let bytes = unsafe { core::slice::from_raw_parts(&info as *const ListenInfo as *const u8, size_of::<ListenInfo>()) };
    if frame.rdx < bytes.len() as u64 {
        frame.rax = err::TOO_LONG;
        return;
    }
    match memory::copy_to_user_space(table.current().space(), frame.rsi, bytes) {
        Ok(()) => frame.rax = bytes.len() as u64,
        Err(_) => frame.rax = err::BAD_BUFFER,
    }
}

// ---- Slots: loading service images at run time (RFD 2, P1, P2, P6) --------------------------

/// The generic slot `id` names (any generation), for the task allowed to load images.
fn loader_target(table: &mut Table, id: u64) -> Result<usize, u64> {
    if !table.current().task.loads {
        return Err(err::NOT_ALLOWED);
    }
    let slot = table.slot_of(id).ok_or(err::BAD_TARGET)?;
    if table.get(slot).task.class.is_none() {
        return Err(err::BAD_TARGET);
    }
    Ok(slot)
}

/// A slot's image area in the kernel's direct map.
fn image_area(p: &Process) -> &'static mut [u8] {
    let (phys, pages) = p.grants.image_area.expect("a slot has an image area");
    unsafe { core::slice::from_raw_parts_mut(memory::phys_to_virt(phys), (pages * PAGE_SIZE) as usize) }
}

/// Zero what was staged into a slot's image area and forget it.
fn clear_image(p: &mut Process) {
    let staged = p.staged as usize;
    image_area(p)[..staged].fill(0);
    p.staged = 0;
    p.grants.image = &[];
}

/// `slot_stage(slot, offset, buf, len) -> 0`: copy `len` bytes of a service image into an empty
/// slot's image area at `offset`, so an image arriving in pieces never needs a buffer its size.
/// TOO_LONG past the end of the area; BAD_ARGUMENT unless the slot is empty.
pub fn slot_stage(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let slot = match loader_target(&mut table, frame.rdi) {
        Ok(slot) => slot,
        Err(e) => return frame.rax = e,
    };
    let (offset, buf, len) = (frame.rsi, frame.rdx, frame.r10);
    let p = table.get(slot);
    if p.state != State::Empty {
        frame.rax = err::BAD_ARGUMENT; // unload it first
        return;
    }
    let area = image_area(p);
    let Some(end) = offset.checked_add(len).filter(|&end| end <= area.len() as u64) else {
        frame.rax = err::TOO_LONG;
        return;
    };
    if crate::usercopy::copy_from_user(&mut area[offset as usize..end as usize], buf).is_err() {
        frame.rax = err::BAD_BUFFER;
        return;
    }
    p.staged = p.staged.max(end);
    frame.rax = 0;
}

/// `slot_load(slot, sig, sig_len, desc, desc_len) -> new id`: check the staged image against its
/// signature and descriptor, check it fits the slot's class, measure it, and start it (RFD 2,
/// P2). Fails, changing nothing, with REJECTED (reason in rdx; the staged image is discarded),
/// BUSY (the TPM is in use: try again) or LOG_FULL; BAD_ARGUMENT if the slot isn't empty or
/// nothing is staged.
pub fn slot_load(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let slot = match loader_target(&mut table, frame.rdi) {
        Ok(slot) => slot,
        Err(e) => return frame.rax = e,
    };
    let (sig_ptr, sig_len, desc_ptr, desc_len) = (frame.rsi, frame.rdx, frame.r10, frame.r8);
    let mut sig = [0u8; verify::SIG_FILE_LEN_V2];
    let mut desc = [0u8; verify::DESCRIPTOR_LEN];
    let (Some(sig), Some(desc)) = (sig.get_mut(..sig_len as usize), desc.get_mut(..desc_len as usize)) else {
        frame.rax = err::TOO_LONG;
        return;
    };
    if crate::usercopy::copy_from_user(sig, sig_ptr).is_err() || crate::usercopy::copy_from_user(desc, desc_ptr).is_err() {
        frame.rax = err::BAD_BUFFER;
        return;
    }
    let p = table.get(slot);
    if p.state != State::Empty || p.staged == 0 {
        frame.rax = err::BAD_ARGUMENT;
        return;
    }
    let class = p.task.class.unwrap();
    let image: &'static [u8] = &image_area(p)[..p.staged as usize];

    // Steps 1-3: signature, version floor, class. Then build its address space, which shows how
    // much memory it needs; nothing outside this syscall can see it until it starts.
    let rejected = |table: &mut Table, frame: &mut TrapFrame, why: Rejection| {
        let p = table.get(slot);
        clear_image(p);
        events::log(events::IMAGE_REJECTED, p.id(), why as u64, 0, 0);
        println!("[kernel] {}: image REJECTED: {}", p.describe(), why.describe());
        frame.rax = err::REJECTED;
        frame.rdx = why as u64;
    };
    let descriptor = match verify::check_slot(image, sig, desc, class.name) {
        Ok(d) => d,
        Err(why) => return rejected(&mut table, frame, why),
    };
    p.grants.image = image;
    let before = memory::frames_in_use();
    let Ok((space, context)) = load(p.task, &p.grants) else {
        p.grants.image = &[];
        return rejected(&mut table, frame, Rejection::BadElf);
    };
    let pages = memory::frames_in_use() - before;
    if pages > class.memory_pages {
        drop(space);
        println!("[kernel] {}: the image needs {} frames; class {} allows {}", p.describe(), pages, class.name, class.memory_pages);
        p.grants.image = &[];
        return rejected(&mut table, frame, Rejection::TooLarge);
    }

    // Step 5: measure, or give up with nothing recorded.
    if let Err(why) = measure::runtime(measure::LOAD, slot, descriptor.name(), descriptor.version, &descriptor.statement_hash) {
        drop(space);
        p.grants.image = &[];
        frame.rax = match why {
            measure::Refused::Busy => err::BUSY,
            measure::Refused::Full => err::LOG_FULL,
        };
        return;
    }

    // Step 6: record the descriptor and start it, as a new generation of the slot.
    p.space = Some(space);
    p.context = context;
    p.generation += 1;
    p.state = State::Ready;
    p.ticks = 0;
    p.death = Death::default();
    p.posted = 0;
    p.version = descriptor.version;
    p.loaded = Some(descriptor);
    irq::take(slot);
    events::log(events::IMAGE_LOADED, p.id(), descriptor.version, 0, 0);
    println!(
        "[kernel] {}: loaded {} version {} ({}-byte image, {} frames of {})",
        p.describe(),
        core::str::from_utf8(descriptor.name()).unwrap_or("?"),
        descriptor.version,
        image.len(),
        pages,
        class.memory_pages
    );
    frame.rax = p.id();
}

/// `slot_unload(slot) -> 0`: empty a slot whose service has ended (or discard a staged image
/// that was never loaded): zero its image area, forget its descriptor, and measure the unload.
/// BAD_ARGUMENT while it runs; BUSY or LOG_FULL as for `slot_load`.
pub fn slot_unload(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let slot = match loader_target(&mut table, frame.rdi) {
        Ok(slot) => slot,
        Err(e) => return frame.rax = e,
    };
    let p = table.get(slot);
    if !p.state.is_dead() {
        frame.rax = err::BAD_ARGUMENT;
        return;
    }
    if let Some(d) = p.loaded {
        if let Err(why) = measure::runtime(measure::UNLOAD, slot, d.name(), d.version, &d.statement_hash) {
            frame.rax = match why {
                measure::Refused::Busy => err::BUSY,
                measure::Refused::Full => err::LOG_FULL,
            };
            return;
        }
        events::log(events::IMAGE_UNLOADED, p.id(), d.version, 0, 0);
        println!("[kernel] {}: unloaded {} version {}", p.describe(), core::str::from_utf8(d.name()).unwrap_or("?"), d.version);
    }
    clear_image(p);
    p.loaded = None;
    p.version = 0;
    p.state = State::Empty;
    p.death.unreported = false; // nothing left to restart
    frame.rax = 0;
}

/// `tpm_lock()` / `tpm_unlock()`: the task with `tpm = true` holds the TPM around its commands,
/// so the kernel never extends PCR 13 in the middle of one.
pub fn tpm_lock(frame: &mut TrapFrame, held: bool) {
    let mut table = TABLE.lock();
    if !table.current().task.tpm {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    measure::hold_tpm(held);
    frame.rax = 0;
}

/// `runtime_log(buf, cap, start) -> (count, total)`: run-time log entries from `start`
/// (`measure::ENTRY_LEN` bytes each), for the task with `tpm = true`.
pub fn runtime_log(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    if !table.current().task.tpm {
        frame.rax = err::NOT_ALLOWED;
        return;
    }
    let mut out = [0u8; measure::ENTRY_LEN * 32];
    let cap = (frame.rsi as usize).min(out.len());
    let (count, total) = measure::runtime_log(frame.rdx as usize, &mut out[..cap]);
    match memory::copy_to_user_space(table.current().space(), frame.rdi, &out[..count * measure::ENTRY_LEN]) {
        Ok(()) => {
            frame.rax = count as u64;
            frame.rdx = total as u64;
        }
        Err(_) => frame.rax = err::BAD_BUFFER,
    }
}

// ---- The end ---------------------------------------------------------------------------------

/// Nothing can run, or the supervisor stopped the system (`stopped`). If nothing can run and a
/// process is still waiting on a send or a reply, nothing can ever wake it: that's a deadlock.
/// Otherwise (everything ended, or only servers waiting in `recv`) the system is done.
///
/// Exit status: 0 all clean, 1 some exited non-zero, 2 some were killed, 4 deadlock.
fn finish(table: &Table, stopped: bool) -> ! {
    let mut status = 0;
    println!("[kernel] {}:", if stopped { "stopped" } else { "no process can run" });
    for p in table.procs.iter().flatten() {
        let outcome = match p.state {
            State::Exited(0) => "exited 0",
            State::Exited(_) => {
                status = status.max(1);
                "exited non-zero"
            }
            State::Faulted(_) => {
                status = status.max(2);
                "faulted"
            }
            State::OverBudget => {
                status = status.max(2);
                "over CPU budget"
            }
            State::Rejected(_) => {
                status = status.max(2);
                "image rejected"
            }
            State::Empty => "empty slot",
            State::Stopped => "stopped",
            State::RecvBlocked => "waiting for messages",
            State::SendBlocked(_) | State::ReplyBlocked(_) if stopped => "waiting in send",
            State::SendBlocked(_) | State::ReplyBlocked(_) => {
                status = 4;
                "DEADLOCKED in send"
            }
            State::Ready | State::Running | State::Sleeping(_) if stopped => "running",
            State::Ready | State::Running | State::Sleeping(_) => unreachable!(),
        };
        println!("[kernel]   {}: {}, {} ticks", p.describe(), outcome, p.ticks);
    }
    if status == 4 {
        println!("[kernel] deadlock: processes are waiting on each other");
    }
    // Tasks still waiting in recv hold their memory; only check for leaks when all have ended.
    let in_use = memory::frames_in_use();
    if table.procs.iter().flatten().all(|p| p.state.is_dead()) {
        if in_use == table.baseline_frames {
            println!("[kernel] frames in use: {} (all task memory freed)", in_use);
        } else {
            println!("[kernel] frames in use: {} (LEAK: {} before tasks)", in_use, table.baseline_frames);
        }
    } else {
        println!("[kernel] frames in use: {} ({} before tasks)", in_use, table.baseline_frames);
    }
    crate::halt(status)
}

/// User registers for a process that hasn't run yet: all general-purpose registers zero.
fn initial_context(entry: u64, stack_top: u64) -> TrapFrame {
    let sel = gdt::selectors();
    TrapFrame {
        rip: entry,
        cs: sel.user_code.0 as u64,
        rflags: 0x202, // IF=1, reserved bit 1
        rsp: stack_top,
        ss: sel.user_data.0 as u64,
        ..TrapFrame::default()
    }
}

/// Build the frame `iretq` expects and "return" into ring 3. The RPL bits in the selectors
/// (from the DPL 3 descriptors) are what make the CPU switch to CPL 3. Every general-purpose
/// register is zeroed first so no kernel value (pointers, stack addresses) leaks to user code.
fn enter_user(entry: u64, stack_top: u64) -> ! {
    let sel = gdt::selectors();
    unsafe {
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "xor eax, eax",
            "xor ebx, ebx",
            "xor ecx, ecx",
            "xor edx, edx",
            "xor esi, esi",
            "xor edi, edi",
            "xor ebp, ebp",
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "iretq",
            ss = in(reg) sel.user_data.0 as u64,
            rsp = in(reg) stack_top,
            rflags = in(reg) 0x202u64, // IF=1, reserved bit 1
            cs = in(reg) sel.user_code.0 as u64,
            rip = in(reg) entry,
            options(noreturn),
        )
    }
}
