//! Load the embedded user program and drop to ring 3.

use core::arch::asm;

use crate::gdt;
use crate::interrupts::TrapFrame;
use crate::memory::{self, PAGE_SIZE};

/// Flat binary produced from user/hello by the Makefile (objcopy -O binary).
static HELLO: &[u8] = include_bytes!("../../build/hello.bin");

/// Must match the address in user/hello/linker.ld.
const USER_CODE_BASE: u64 = 0x40_0000;
const USER_STACK_TOP: u64 = 0x7fff_ffff_f000;
const USER_STACK_PAGES: u64 = 4;

pub fn run_hello() -> ! {
    // Code and data share one flat image, so its pages are writable.
    for (i, chunk) in HELLO.chunks(PAGE_SIZE as usize).enumerate() {
        let frame = memory::map_user_page(USER_CODE_BASE + i as u64 * PAGE_SIZE, true);
        unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), memory::phys_to_virt(frame), chunk.len()) };
    }
    for i in 1..=USER_STACK_PAGES {
        memory::map_user_page(USER_STACK_TOP - i * PAGE_SIZE, true);
    }

    println!(
        "[kernel] loaded {} bytes at {:#x}, entering ring 3",
        HELLO.len(),
        USER_CODE_BASE
    );
    enter_user(USER_CODE_BASE, USER_STACK_TOP)
}

/// A fault in user mode ends the process, not the kernel. With one process there is nothing left
/// to run, so this stops the machine; once there is a scheduler it will run the next process.
pub fn kill(frame: &TrapFrame) -> ! {
    println!("[kernel] process killed by vector {}", frame.vector);
    crate::halt(2)
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
