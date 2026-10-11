//! `int 0x80` system calls. ABI: rax = number; arguments in rdi, rsi, rdx, r10, r8, r9; results
//! in rax (then rdx, rsi). Simple calls return u64::MAX on error; IPC calls return the
//! `process::err` codes, which have the top bit set.

use crate::interrupts::TrapFrame;
use crate::{process, serial};
use crate::usercopy::{self, copy_from_user};

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
pub const SYS_TASK_NAME: u64 = 108;
pub const SYS_DEVICE_BAR: u64 = 110;
pub const SYS_PCI_CONFIG_READ: u64 = 111;
pub const SYS_DMA_INFO: u64 = 112;
pub const SYS_READ_EVENTS: u64 = 113;
pub const SYS_STATS: u64 = 114;
pub const SYS_MEASUREMENTS: u64 = 115;
pub const SYS_NOTIFY: u64 = 116;
pub const SYS_HALT: u64 = 117;
pub const SYS_TASK_LISTEN: u64 = 118;

const ERROR: u64 = u64::MAX;

pub fn dispatch(frame: &mut TrapFrame) {
    assert!(frame.from_user(), "syscall from kernel mode");
    match frame.rax {
        SYS_WRITE => frame.rax = sys_write(frame.rdi, frame.rsi),
        SYS_GETPID => frame.rax = process::current_id(),
        // These may switch processes: `frame` then holds the next process's registers.
        SYS_SCHED_YIELD => process::yield_now(frame),
        SYS_EXIT => process::exit(frame, frame.rdi),
        SYS_SEND => process::send(frame),
        SYS_RECV => process::recv(frame),
        SYS_REPLY => process::reply(frame),
        SYS_LOOKUP => process::lookup(frame),
        SYS_SLEEP => process::sleep(frame),
        SYS_UPTIME => process::uptime(frame),
        SYS_DEVICE_BAR => process::device_bar(frame),
        SYS_PCI_CONFIG_READ => process::pci_config_read(frame),
        SYS_DMA_INFO => process::dma_info(frame),
        SYS_TASK_NAME => process::task_name(frame),
        SYS_READ_EVENTS => process::read_events(frame),
        SYS_STATS => process::stats(frame),
        SYS_MEASUREMENTS => process::measurements(frame),
        SYS_RESTART => process::restart(frame),
        SYS_NOTIFY => process::notify(frame),
        SYS_HALT => process::halt(frame),
        SYS_TASK_LISTEN => process::task_listen(frame),
        SYS_TASK_STATE => process::task_state(frame),
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
