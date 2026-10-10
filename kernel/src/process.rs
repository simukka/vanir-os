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
use crate::{elf, gdt};

/// A process the image runs, declared in the app manifest (see apps/README.md, kernel/build.rs).
pub struct Task {
    pub name: &'static str,
    pub image: &'static [u8],
    /// CPU budget in timer ticks; 0 = unlimited. A process that uses it up is killed.
    pub budget_ticks: u64,
    /// Told when other tasks die, and may restart them.
    pub supervisor: bool,
    /// Indices of the tasks this one may send IPC messages to.
    pub sends: &'static [usize],
}

include!(concat!(env!("OUT_DIR"), "/tasks.rs"));

const MAX_PROCESSES: usize = 8;
const USER_STACK_TOP: u64 = 0x7fff_ffff_f000;
const USER_STACK_PAGES: u64 = 4;

/// Largest message or reply, in bytes; bounds the time one syscall spends copying.
pub const MAX_MESSAGE: u64 = 4096;

/// Kernel error codes returned by IPC syscalls. The top bit is set, so they never collide with a
/// server's reply codes (which must have it clear).
pub mod err {
    pub const DEAD: u64 = 1 << 63;
    pub const NOT_ALLOWED: u64 = DEAD | 1;
    pub const BAD_TARGET: u64 = DEAD | 2;
    pub const BAD_BUFFER: u64 = DEAD | 3;
    pub const TOO_LONG: u64 = DEAD | 4;
    pub const BAD_ARGUMENT: u64 = DEAD | 5;
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
    Exited(u64),
    Faulted(u64),
    OverBudget,
}

impl State {
    fn is_dead(self) -> bool {
        matches!(self, State::Exited(_) | State::Faulted(_) | State::OverBudget)
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
    /// 1 exited, 2 faulted, 3 over CPU budget.
    kind: u64,
    /// Exit code, or the fault's vector.
    code: u64,
    rip: u64,
    cr2: u64,
    error_code: u64,
    ticks: u64,
}

pub const NOTIFY_DEATH: u64 = 1;

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
    Mutex::new(Table { procs: [const { None }; MAX_PROCESSES], current: 0, baseline_frames: 0, supervisor: None });

/// Load every task, then enter the first one. Never returns.
pub fn start() -> ! {
    assert!(!TASKS.is_empty() && TASKS.len() <= MAX_PROCESSES, "need 1..={MAX_PROCESSES} tasks");
    let mut table = TABLE.lock();
    table.baseline_frames = memory::frames_in_use();
    table.supervisor = TASKS.iter().position(|t| t.supervisor);
    for (slot, task) in TASKS.iter().enumerate() {
        let (space, context) = load(task);
        let space = Some(space);
        let p = Process { slot, generation: 0, task, space, context, state: State::Ready, ticks: 0, death: Death::default() };
        println!("[kernel] {}: {}-byte ELF, entry {:#x}", p.describe(), task.image.len(), p.context.rip);
        table.procs[slot] = Some(p);
    }

    table.current = 0;
    let first = table.current();
    first.state = State::Running;
    first.space().activate();
    let (rip, rsp) = (first.context.rip, first.context.rsp);
    drop(table);
    println!("[kernel] entering ring 3");
    enter_user(rip, rsp)
}

/// A fresh address space with `task` loaded and its stack mapped, and its starting registers.
fn load(task: &Task) -> (AddressSpace, TrapFrame) {
    let space = AddressSpace::new();
    let entry = elf::load(task.image, &space).unwrap_or_else(|e| panic!("cannot load {}: {e:?}", task.name));
    for page in 1..=USER_STACK_PAGES {
        space.map_user_page(USER_STACK_TOP - page * PAGE_SIZE, true, false);
    }
    (space, initial_context(entry, USER_STACK_TOP))
}

/// Timer interrupt: charge the tick to the running process, then preempt it, or kill it if it
/// has used up its CPU budget.
pub fn tick(frame: &mut TrapFrame) {
    debug_assert!(frame.from_user(), "timer tick in kernel mode");
    let mut table = TABLE.lock();
    let p = table.current();
    p.ticks += 1;
    let budget = p.task.budget_ticks;
    if budget != 0 && p.ticks >= budget {
        println!("[kernel] {} killed: CPU budget of {} ticks used up", p.describe(), budget);
        return end_current(&mut table, frame, State::OverBudget);
    }
    block(&mut table, frame, State::Ready);
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
    end_current(&mut table, frame, State::Exited(code));
}

/// A fault in user mode ends that process, not the kernel; the next process resumes in `frame`.
pub fn kill(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let p = table.current();
    println!("[kernel] {} killed by vector {}", p.describe(), frame.vector);
    let cr2 = if frame.vector == 14 { x86_64::registers::control::Cr2::read_raw() } else { 0 };
    p.death = Death { rip: frame.rip, cr2, error_code: frame.error_code, unreported: false };
    end_current(&mut table, frame, State::Faulted(frame.vector));
}

/// The current process has ended: free its memory, fail every IPC waiting on it with DEAD, tell
/// the supervisor, and resume the next process.
fn end_current(table: &mut Table, frame: &mut TrapFrame, outcome: State) {
    let dead = table.current;
    if table.supervisor == Some(dead) {
        // The supervisor is trusted to keep the system running; without it nothing can.
        println!("[kernel] the supervisor died; stopping");
        crate::halt(3);
    }
    let has_supervisor = table.supervisor.is_some();
    let p = table.current();
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
    switch_to_next(table, frame);
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
/// registers into `frame` and its address space into CR3. With none ready, stop the machine.
fn switch_to_next(table: &mut Table, frame: &mut TrapFrame) {
    for step in 1..=MAX_PROCESSES {
        let i = (table.current + step) % MAX_PROCESSES;
        if let Some(p) = table.procs[i].as_mut().filter(|p| p.state == State::Ready) {
            p.state = State::Running;
            *frame = p.context;
            if i != table.current {
                // Reloading CR3 flushes the TLB, so skip it when staying put.
                p.space().activate();
            }
            table.current = i;
            return;
        }
    }
    finish(table)
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

/// `recv(buf, cap) -> (sender, op, len)` in rax, rdx, rsi. Takes the next waiting sender,
/// round-robin from after the last one served, or waits for one.
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

    // The supervisor hears about deaths before ordinary messages.
    if table.supervisor == Some(me) && report_death(&mut table, me, buf, cap, frame) {
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
    if p.id() != id || !p.state.is_dead() {
        frame.rax = err::BAD_ARGUMENT; // already restarted, or still alive
        return;
    }
    let (space, context) = load(p.task);
    p.space = Some(space);
    p.context = context;
    p.generation += 1;
    p.state = State::Ready;
    p.ticks = 0;
    p.death = Death::default();
    frame.rax = p.id();
}

/// `task_state(id) -> (state, current id)`: 0 running or ready, 1 blocked in IPC, 2 exited,
/// 3 faulted, 4 over budget. Supervisor only.
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
    frame.rax = match p.state {
        State::Ready | State::Running => 0,
        State::SendBlocked(_) | State::ReplyBlocked(_) | State::RecvBlocked => 1,
        State::Exited(_) => 2,
        State::Faulted(_) => 3,
        State::OverBudget => 4,
    };
    frame.rdx = p.id();
}

// ---- The end ---------------------------------------------------------------------------------

/// Nothing can run. If a process is still waiting on a send or a reply, nothing can ever wake
/// it: that's a deadlock. Otherwise (everything ended, or only servers waiting in `recv`) the
/// system is done.
///
/// Exit status: 0 all clean, 1 some exited non-zero, 2 some were killed, 4 deadlock.
fn finish(table: &Table) -> ! {
    let mut status = 0;
    println!("[kernel] no process can run:");
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
            State::RecvBlocked => "waiting for messages",
            State::SendBlocked(_) | State::ReplyBlocked(_) => {
                status = 4;
                "DEADLOCKED in send"
            }
            State::Ready | State::Running => unreachable!(),
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
