//! Load the embedded user program and drop to ring 3.

use core::arch::asm;

use crate::gdt;
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

/// Build the frame `iretq` expects and "return" into ring 3. The RPL bits in the selectors
/// (from the DPL 3 descriptors) are what make the CPU switch to CPL 3.
fn enter_user(entry: u64, stack_top: u64) -> ! {
    let sel = gdt::selectors();
    unsafe {
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
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
