//! Processes: a static task table, one address space each, and a round-robin scheduler.
//!
//! There is one kernel stack. Every trap saves the user's registers there as a `TrapFrame`; to
//! switch processes the scheduler stores that frame in the current process, copies the next
//! process's saved frame over it, and switches CR3. The trap path's `iretq` then resumes the next
//! process. The kernel never blocks in the middle of a syscall, so nothing else needs saving.

use core::arch::asm;
use core::fmt;
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
    #[allow(dead_code)] // used by the supervisor syscalls
    pub supervisor: bool,
    /// Indices of the tasks this one may send IPC messages to.
    #[allow(dead_code)] // used by IPC
    pub sends: &'static [usize],
}

include!(concat!(env!("OUT_DIR"), "/tasks.rs"));

const MAX_PROCESSES: usize = 8;
const USER_STACK_TOP: u64 = 0x7fff_ffff_f000;
const USER_STACK_PAGES: u64 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Ready,
    Running,
    Exited(u64),
    Faulted(u64),
    OverBudget,
}

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
}

struct Table {
    procs: [Option<Process>; MAX_PROCESSES],
    current: usize,
    /// Frames in use before any task was loaded; every task's memory is freed when it ends.
    baseline_frames: u64,
}

impl Process {
    /// Task id as user code sees it: `slot + 1` in the low 16 bits (0 means "the kernel"), the
    /// generation above.
    fn id(&self) -> u64 {
        (self.slot as u64 + 1) | self.generation << 16
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

impl Table {
    fn current(&mut self) -> &mut Process {
        self.procs[self.current].as_mut().expect("no current process")
    }
}

static TABLE: Mutex<Table> =
    Mutex::new(Table { procs: [const { None }; MAX_PROCESSES], current: 0, baseline_frames: 0 });

/// Load every task, then enter the first one. Never returns.
pub fn start() -> ! {
    assert!(!TASKS.is_empty() && TASKS.len() <= MAX_PROCESSES, "need 1..={MAX_PROCESSES} tasks");
    let mut table = TABLE.lock();
    table.baseline_frames = memory::frames_in_use();
    for (slot, task) in TASKS.iter().enumerate() {
        let space = AddressSpace::new();
        let entry = elf::load(task.image, &space)
            .unwrap_or_else(|e| panic!("cannot load {}: {e:?}", task.name));
        for page in 1..=USER_STACK_PAGES {
            space.map_user_page(USER_STACK_TOP - page * PAGE_SIZE, true, false);
        }
        let context = initial_context(entry, USER_STACK_TOP);
        let space = Some(space);
        let p = Process { slot, generation: 0, task, space, context, state: State::Ready, ticks: 0 };
        println!("[kernel] {}: {}-byte ELF, entry {:#x}", p.describe(), task.image.len(), entry);
        table.procs[slot] = Some(p);
    }

    table.current = 0;
    let first = table.current();
    first.state = State::Running;
    first.space.as_ref().unwrap().activate();
    let (rip, rsp) = (first.context.rip, first.context.rsp);
    drop(table);
    println!("[kernel] entering ring 3");
    enter_user(rip, rsp)
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
        p.state = State::OverBudget;
        p.space = None;
        return switch_to_next(&mut table, frame);
    }
    preempt(&mut table, frame);
}

/// `sched_yield()`: give up the rest of this time slice.
pub fn yield_now(frame: &mut TrapFrame) {
    frame.rax = 0;
    preempt(&mut TABLE.lock(), frame);
}

/// Save the running process's registers, put it back in the ready queue, and resume the next
/// ready process (which is the same one if nothing else is ready).
fn preempt(table: &mut Table, frame: &mut TrapFrame) {
    let p = table.current();
    p.context = *frame;
    p.state = State::Ready;
    switch_to_next(table, frame);
}

pub fn current_id() -> u64 {
    TABLE.lock().current().id()
}

/// `exit(code)`: end the current process and resume the next one in `frame`.
pub fn exit(frame: &mut TrapFrame, code: u64) {
    let mut table = TABLE.lock();
    let p = table.current();
    println!("[kernel] {} exited with code {} (called from CPL {})", p.describe(), code, frame.cs & 3);
    p.state = State::Exited(code);
    p.space = None;
    switch_to_next(&mut table, frame);
}

/// A fault in user mode ends that process, not the kernel; the next process resumes in `frame`.
pub fn kill(frame: &mut TrapFrame) {
    let mut table = TABLE.lock();
    let p = table.current();
    println!("[kernel] {} killed by vector {}", p.describe(), frame.vector);
    p.state = State::Faulted(frame.vector);
    p.space = None;
    switch_to_next(&mut table, frame);
}

/// Resume the next ready process (round-robin after the current one) by loading its saved
/// registers into `frame` and its address space into CR3. With none left, stop the machine.
fn switch_to_next(table: &mut Table, frame: &mut TrapFrame) {
    for step in 1..=MAX_PROCESSES {
        let i = (table.current + step) % MAX_PROCESSES;
        if let Some(p) = table.procs[i].as_mut().filter(|p| p.state == State::Ready) {
            p.state = State::Running;
            *frame = p.context;
            if i != table.current {
                // Reloading CR3 flushes the TLB, so skip it when staying put.
                p.space.as_ref().unwrap().activate();
            }
            table.current = i;
            return;
        }
    }
    finish(table)
}

/// Every process has ended. Exit status: 0 all exited 0, 1 some exited non-zero, 2 some were
/// killed (fault or CPU budget).
fn finish(table: &Table) -> ! {
    let mut status = 0;
    println!("[kernel] all processes finished:");
    for p in table.procs.iter().flatten() {
        let outcome = match p.state {
            State::Exited(0) => "exited 0",
            State::Exited(_) => {
                status = status.max(1);
                "exited non-zero"
            }
            State::Faulted(_) => {
                status = 2;
                "faulted"
            }
            State::OverBudget => {
                status = 2;
                "over CPU budget"
            }
            State::Ready | State::Running => unreachable!(),
        };
        println!("[kernel]   {}: {}, {} ticks", p.describe(), outcome, p.ticks);
    }
    let in_use = memory::frames_in_use();
    if in_use == table.baseline_frames {
        println!("[kernel] frames in use: {} (all task memory freed)", in_use);
    } else {
        println!("[kernel] frames in use: {} (LEAK: {} before tasks)", in_use, table.baseline_frames);
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
