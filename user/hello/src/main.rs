//! The user program: runs in ring 3 and talks to the kernel only through `int 0x80`.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::panic::PanicInfo;

const SYS_WRITE: u64 = 1;
const SYS_EXIT: u64 = 60;

fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let ret;
    unsafe {
        asm!("int 0x80", inlateout("rax") number => ret, in("rdi") arg0, in("rsi") arg1, options(nostack));
    }
    ret
}

fn write(bytes: &[u8]) -> u64 {
    syscall2(SYS_WRITE, bytes.as_ptr() as u64, bytes.len() as u64)
}

fn exit(code: u64) -> ! {
    syscall2(SYS_EXIT, code, 0);
    unreachable!()
}

/// Registers as the kernel handed them over: rax, rbx, rcx, rdx, rsi, rdi, rbp, r8-r15.
static mut ENTRY_REGS: [u64; 15] = [0; 15];

// Entry point: record every register before any compiled code can change one, then call main.
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
    call {main}
    ud2
"#,
    regs = sym ENTRY_REGS,
    main = sym main,
);

extern "C" fn main() -> ! {
    // The kernel must not leak register contents into ring 3.
    if unsafe { (*(&raw const ENTRY_REGS)).iter().any(|&r| r != 0) } {
        write(b"kernel leaked non-zero registers into ring 3\n");
        exit(3);
    }

    write(b"hello from ring 3\n");

    #[cfg(feature = "bad-pointer")]
    {
        let unmapped = unsafe { core::slice::from_raw_parts(0x1000_0000 as *const u8, 16) };
        // Starts in the top stack page and runs off the end of the mapped stack.
        let straddling = unsafe { core::slice::from_raw_parts(0x7fff_ffff_eff0 as *const u8, 32) };
        let rejected = write(unmapped) == u64::MAX && write(straddling) == u64::MAX;
        write(if rejected { b"bad pointers rejected\n" } else { b"bad pointer ACCEPTED\n" });
        exit(if rejected { 0 } else { 1 });
    }

    #[cfg(feature = "exec-stack")]
    {
        let code = core::hint::black_box([0xc3u8]); // `ret`
        let f: extern "C" fn() = unsafe { core::mem::transmute(code.as_ptr()) };
        write(b"calling code on the stack...\n");
        f();
        write(b"NX BROKEN: executed code on the stack\n");
        exit(1);
    }

    #[cfg(feature = "write-code")]
    {
        write(b"writing to our own code...\n");
        unsafe { core::ptr::write_volatile(main as *const () as *mut u8, 0xc3) };
        write(b"W^X BROKEN: code page was writable\n");
        exit(1);
    }

    #[cfg(feature = "poke-kernel")]
    {
        write(b"reading kernel memory at 0xffffffff80000000...\n");
        let value = unsafe { core::ptr::read_volatile(0xffff_ffff_8000_0000 as *const u64) };
        // Only reached if isolation is broken.
        write(b"ISOLATION BROKEN: kernel memory was readable\n");
        let _ = value;
    }

    // The kernel rejects buffers outside the user half.
    if write(unsafe { core::slice::from_raw_parts(0xffff_ffff_8000_0000 as *const u8, 8) }) != u64::MAX {
        exit(1);
    }

    exit(0)
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    exit(101)
}
