//! Kernel access to user memory that fails with an error instead of crashing the kernel.
//!
//! The copy is one `rep movsb` at a known address. If it page-faults (unmapped or protected user
//! page), `trap_handler` sees the fault's `rip` there and resumes at `usercopy_fixup`, which
//! returns an error. Linux calls this an exception table; we have exactly one entry.

use core::arch::global_asm;

use crate::cpu;
use crate::interrupts::TrapFrame;
use crate::memory::USER_END;

global_asm!(
    r#"
.section .text
.global usercopy_raw
.global usercopy_fault_ip
.global usercopy_fixup
// rdi = dst, rsi = src, rdx = len. Returns 0 on success, 1 if the copy faulted.
usercopy_raw:
    mov rcx, rdx
usercopy_fault_ip:
    rep movsb
    xor eax, eax
    ret
usercopy_fixup:
    mov eax, 1
    ret
"#
);

unsafe extern "C" {
    fn usercopy_raw(dst: *mut u8, src: *const u8, len: usize) -> u64;
    static usercopy_fault_ip: [u8; 0];
    static usercopy_fixup: [u8; 0];
}

#[derive(Debug)]
pub struct BadAddress;

/// True if `[addr, addr + len)` lies entirely in the user half.
pub fn is_user_range(addr: u64, len: u64) -> bool {
    addr.checked_add(len).is_some_and(|end| end <= USER_END)
}

/// Copy `dst.len()` bytes from user address `src`.
pub fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), BadAddress> {
    // Without this check a kernel address would copy successfully and leak kernel memory.
    if !is_user_range(src, dst.len() as u64) {
        return Err(BadAddress);
    }
    cpu::stac();
    let faulted = unsafe { usercopy_raw(dst.as_mut_ptr(), src as *const u8, dst.len()) };
    cpu::clac();
    if faulted == 0 { Ok(()) } else { Err(BadAddress) }
}

/// Called for kernel-mode page faults. If the fault is in the user copy, redirect it to the
/// fixup path and return true; the kernel then continues as if the copy returned an error.
pub fn fixup(frame: &mut TrapFrame) -> bool {
    if frame.rip == (&raw const usercopy_fault_ip) as u64 {
        frame.rip = (&raw const usercopy_fixup) as u64;
        true
    } else {
        false
    }
}
