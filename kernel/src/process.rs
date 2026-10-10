//! Load the embedded user program and drop to ring 3.

use core::arch::asm;

use crate::{elf, gdt};
use crate::interrupts::TrapFrame;
use crate::memory::{AddressSpace, PAGE_SIZE};

/// The user program's ELF, copied (and stripped) from user/hello by the Makefile.
static HELLO: &[u8] = include_bytes!("../../build/hello.elf");

const USER_STACK_TOP: u64 = 0x7fff_ffff_f000;
const USER_STACK_PAGES: u64 = 4;

pub fn run_hello() -> ! {
    let space = AddressSpace::new();
    let entry = elf::load(HELLO, &space).unwrap_or_else(|e| panic!("cannot load user program: {e:?}"));
    for i in 1..=USER_STACK_PAGES {
        space.map_user_page(USER_STACK_TOP - i * PAGE_SIZE, true, false);
    }
    space.activate();

    println!(
        "[kernel] loaded {}-byte ELF, entry {:#x}, entering ring 3",
        HELLO.len(),
        entry
    );
    enter_user(entry, USER_STACK_TOP)
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
