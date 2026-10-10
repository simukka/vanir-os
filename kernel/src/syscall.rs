//! `int 0x80` system calls. ABI: rax = number, rdi/rsi = args, result in rax (u64::MAX = error).

use crate::interrupts::TrapFrame;
use crate::memory::USER_END;
use crate::serial;

pub const SYS_WRITE: u64 = 1;
pub const SYS_EXIT: u64 = 60;

const ERROR: u64 = u64::MAX;

pub fn dispatch(frame: &mut TrapFrame) {
    assert!(frame.from_user(), "syscall from kernel mode");
    frame.rax = match frame.rax {
        SYS_WRITE => sys_write(frame.rdi, frame.rsi),
        SYS_EXIT => sys_exit(frame.rdi, frame.cs),
        _ => ERROR,
    };
}

/// write(ptr, len) to the serial port. Only user-half buffers are accepted, so a process can't
/// make the kernel print kernel memory. (An unmapped user buffer still faults the kernel.)
fn sys_write(ptr: u64, len: u64) -> u64 {
    match ptr.checked_add(len) {
        Some(end) if end <= USER_END => {
            serial::write_bytes(unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) });
            len
        }
        _ => ERROR,
    }
}

fn sys_exit(code: u64, cs: u64) -> ! {
    println!("[kernel] process exited with code {} (called from CPL {})", code, cs & 3);
    crate::halt(if code == 0 { 0 } else { 1 })
}
