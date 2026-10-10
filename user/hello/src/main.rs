//! The user program: runs in ring 3 and talks to the kernel only through `int 0x80`.

#![no_std]
#![no_main]

use core::arch::asm;
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

#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
extern "C" fn _start() -> ! {
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
