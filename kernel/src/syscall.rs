//! `int 0x80` system calls. ABI: rax = number, rdi/rsi = args, result in rax (u64::MAX = error).

use crate::interrupts::TrapFrame;
use crate::{process, serial};
use crate::usercopy::{self, copy_from_user};

pub const SYS_WRITE: u64 = 1;
pub const SYS_GETPID: u64 = 39;
pub const SYS_EXIT: u64 = 60;

const ERROR: u64 = u64::MAX;

pub fn dispatch(frame: &mut TrapFrame) {
    assert!(frame.from_user(), "syscall from kernel mode");
    match frame.rax {
        SYS_WRITE => frame.rax = sys_write(frame.rdi, frame.rsi),
        SYS_GETPID => frame.rax = process::current_pid(),
        // May switch processes: `frame` then holds the next process's registers.
        SYS_EXIT => process::exit(frame, frame.rdi),
        _ => frame.rax = ERROR,
    }
}

/// write(ptr, len) to the serial port. The buffer is copied in chunks, so a bad pointer returns
/// ERROR (possibly after earlier chunks were written) instead of faulting the kernel.
fn sys_write(ptr: u64, len: u64) -> u64 {
    if !usercopy::is_user_range(ptr, len) {
        return ERROR;
    }

    // Test only: touch the user buffer without stac. SMAP must fault the kernel here.
    #[cfg(feature = "smap-selftest")]
    unsafe {
        core::ptr::read_volatile(ptr as *const u8);
    }

    let mut buf = [0u8; 256];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(buf.len() as u64) as usize;
        if copy_from_user(&mut buf[..n], ptr + done).is_err() {
            return ERROR;
        }
        serial::write_bytes(&buf[..n]);
        done += n as u64;
    }
    len
}
