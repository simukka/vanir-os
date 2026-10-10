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

/// Returned by the kernel when a syscall fails.
pub const ERROR: u64 = u64::MAX;

pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let ret;
    unsafe {
        asm!("int 0x80", inlateout("rax") number => ret, in("rdi") arg0, in("rsi") arg1, options(nostack));
    }
    ret
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
    ($($arg:tt)*) => { let _ = core::fmt::Write::write_fmt(&mut $crate::Stdout, format_args!($($arg)*)); };
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
