//! Runtime shared by every vanir-os user program: the `_start` entry stub, syscall wrappers,
//! `print!`/`println!`, and a panic handler.
//!
//! A program provides its entry with `vanir_user::entry!(main)`, where `main() -> u64` returns the
//! exit code.

#![no_std]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;

pub const SYS_WRITE: u64 = 1;
pub const SYS_SCHED_YIELD: u64 = 24;
pub const SYS_GETPID: u64 = 39;
pub const SYS_EXIT: u64 = 60;
pub const SYS_SEND: u64 = 100;
pub const SYS_RECV: u64 = 101;
pub const SYS_REPLY: u64 = 102;
pub const SYS_RESTART: u64 = 103;
pub const SYS_TASK_STATE: u64 = 104;
pub const SYS_LOOKUP: u64 = 105;
pub const SYS_SLEEP: u64 = 106;
pub const SYS_UPTIME: u64 = 107;

/// Returned by the kernel when a simple syscall (write, getpid, ...) fails.
pub const ERROR: u64 = u64::MAX;

/// Errors from the IPC syscalls. The top bit is set; reply codes from servers never have it.
pub mod err {
    pub const DEAD: u64 = 1 << 63;
    pub const NOT_ALLOWED: u64 = DEAD | 1;
    pub const BAD_TARGET: u64 = DEAD | 2;
    pub const BAD_BUFFER: u64 = DEAD | 3;
    pub const TOO_LONG: u64 = DEAD | 4;
    pub const BAD_ARGUMENT: u64 = DEAD | 5;

    pub fn is_error(code: u64) -> bool {
        code & DEAD != 0
    }

    pub fn name(code: u64) -> &'static str {
        match code {
            DEAD => "DEAD",
            NOT_ALLOWED => "NOT_ALLOWED",
            BAD_TARGET => "BAD_TARGET",
            BAD_BUFFER => "BAD_BUFFER",
            TOO_LONG => "TOO_LONG",
            BAD_ARGUMENT => "BAD_ARGUMENT",
            _ => "OK",
        }
    }
}

pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let ret;
    unsafe {
        asm!("int 0x80", inlateout("rax") number => ret, in("rdi") arg0, in("rsi") arg1, options(nostack));
    }
    ret
}

/// Raw six-argument syscall; returns (rax, rdx, rsi).
pub fn syscall6(number: u64, args: [u64; 6]) -> (u64, u64, u64) {
    let (rax, rdx, rsi);
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => rax,
            in("rdi") args[0],
            inlateout("rsi") args[1] => rsi,
            inlateout("rdx") args[2] => rdx,
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            options(nostack),
        );
    }
    (rax, rdx, rsi)
}

/// Send `msg` with operation `op` to task `target` and wait for the reply, which is written to
/// the start of `reply`. Returns the server's reply code and the reply length, or a kernel error.
pub fn send(target: u64, op: u64, msg: &[u8], reply: &mut [u8]) -> Result<(u64, usize), u64> {
    let (code, len, _) = syscall6(
        SYS_SEND,
        [target, op, msg.as_ptr() as u64, msg.len() as u64, reply.as_mut_ptr() as u64, reply.len() as u64],
    );
    if err::is_error(code) { Err(code) } else { Ok((code, len as usize)) }
}

pub struct Message {
    /// Sender's task id; 0 for a notification from the kernel.
    pub sender: u64,
    pub op: u64,
    pub len: usize,
}

/// Wait for a message, written to the start of `buf`.
pub fn recv(buf: &mut [u8]) -> Result<Message, u64> {
    let (sender, op, len) = syscall6(SYS_RECV, [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0]);
    if err::is_error(sender) { Err(sender) } else { Ok(Message { sender, op, len: len as usize }) }
}

/// Answer the message from `sender` with `code` (top bit clear) and `data`.
pub fn reply(sender: u64, code: u64, data: &[u8]) -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_REPLY, [sender, code, data.as_ptr() as u64, data.len() as u64, 0, 0]);
    if status == 0 { Ok(()) } else { Err(status) }
}

/// Operation of a kernel notification (sender 0) telling the supervisor a task died; the message
/// is a `DeathRecord`.
pub const NOTIFY_DEATH: u64 = 1;

/// How a task ended, as the kernel reports it to the supervisor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DeathRecord {
    pub id: u64,
    /// 1 exited, 2 faulted, 3 over CPU budget.
    pub kind: u64,
    /// Exit code, or the fault's vector.
    pub code: u64,
    pub rip: u64,
    pub cr2: u64,
    pub error_code: u64,
    pub ticks: u64,
}

impl DeathRecord {
    pub fn from_bytes(bytes: &[u8]) -> Option<DeathRecord> {
        (bytes.len() == core::mem::size_of::<DeathRecord>())
            .then(|| unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DeathRecord) })
    }
}

/// Supervisor only: reload a dead task into fresh memory. Returns its new id.
pub fn restart(id: u64) -> Result<u64, u64> {
    let (new_id, _, _) = syscall6(SYS_RESTART, [id, 0, 0, 0, 0, 0]);
    if err::is_error(new_id) { Err(new_id) } else { Ok(new_id) }
}

/// Supervisor only: (state, current id). State: 0 running/ready, 1 blocked in IPC, 2 exited,
/// 3 faulted, 4 over budget.
pub fn task_state(id: u64) -> Result<(u64, u64), u64> {
    let (state, current, _) = syscall6(SYS_TASK_STATE, [id, 0, 0, 0, 0, 0]);
    if err::is_error(state) { Err(state) } else { Ok((state, current)) }
}

/// The id of the task called `name` in the app manifest.
pub fn lookup(name: &str) -> Result<u64, u64> {
    let (id, _, _) = syscall6(SYS_LOOKUP, [name.as_ptr() as u64, name.len() as u64, 0, 0, 0, 0]);
    if err::is_error(id) { Err(id) } else { Ok(id) }
}

pub fn write(bytes: &[u8]) -> u64 {
    syscall2(SYS_WRITE, bytes.as_ptr() as u64, bytes.len() as u64)
}

/// This task's id: its 1-based position in the app manifest in the low 16 bits, and how many
/// times it has been restarted above that.
pub fn getpid() -> u64 {
    syscall2(SYS_GETPID, 0, 0)
}

/// The 1-based task number from an id, without the restart generation.
pub fn task_index(id: u64) -> u64 {
    id & 0xffff
}

pub fn yield_now() {
    syscall2(SYS_SCHED_YIELD, 0, 0);
}

/// Timer ticks (10 ms each) per second.
pub const TICK_HZ: u64 = 100;

/// Wait at least `ticks` timer ticks. Uses no CPU while waiting.
pub fn sleep(ticks: u64) {
    syscall2(SYS_SLEEP, ticks, 0);
}

/// Timer ticks since boot.
pub fn uptime() -> u64 {
    syscall2(SYS_UPTIME, 0, 0)
}

pub fn exit(code: u64) -> ! {
    syscall2(SYS_EXIT, code, 0);
    unreachable!()
}

pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    unsafe { asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    (hi as u64) << 32 | lo as u64
}

/// Busy-wait for `cycles` TSC cycles without making any syscall.
pub fn spin_cycles(cycles: u64) {
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

pub struct Stdout;

impl Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if write(s.as_bytes()) == ERROR { Err(fmt::Error) } else { Ok(()) }
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{ let _ = core::fmt::Write::write_fmt(&mut $crate::Stdout, format_args!($($arg)*)); }};
}

#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => { $crate::print!("{}\n", format_args!($($arg)*)) };
}

/// Define the program's entry: `entry!(main)` with `fn main() -> u64`.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(no_mangle)]
        extern "C" fn vanir_main() -> u64 {
            $main()
        }
    };
}

unsafe extern "C" {
    fn vanir_main() -> u64;
}

/// Registers as the kernel handed them over: rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15.
static mut ENTRY_REGS: [u64; 15] = [0; 15];

// Entry point: record every register before any compiled code can change one.
global_asm!(
    r#"
.section .text.entry
.global _start
_start:
    mov [rip + {regs} + 0x00], rax
    mov [rip + {regs} + 0x08], rbx
    mov [rip + {regs} + 0x10], rcx
    mov [rip + {regs} + 0x18], rdx
    mov [rip + {regs} + 0x20], rsi
    mov [rip + {regs} + 0x28], rdi
    mov [rip + {regs} + 0x30], rbp
    mov [rip + {regs} + 0x38], r8
    mov [rip + {regs} + 0x40], r9
    mov [rip + {regs} + 0x48], r10
    mov [rip + {regs} + 0x50], r11
    mov [rip + {regs} + 0x58], r12
    mov [rip + {regs} + 0x60], r13
    mov [rip + {regs} + 0x68], r14
    mov [rip + {regs} + 0x70], r15
    call {start}
    ud2
"#,
    regs = sym ENTRY_REGS,
    start = sym start,
);

extern "C" fn start() -> ! {
    // The kernel must not leak register contents into ring 3.
    if unsafe { (*(&raw const ENTRY_REGS)).iter().any(|&r| r != 0) } {
        write(b"kernel leaked non-zero registers into ring 3\n");
        exit(3);
    }
    exit(unsafe { vanir_main() })
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    exit(101)
}
