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

/// Returned by the kernel when a simple syscall (write, getpid, ...) fails.
pub const ERROR: u64 = u64::MAX;

/// Errors from the IPC syscalls. The top bit is set; reply codes from servers never have it.
pub mod err {
    pub const DEAD: u64 = 1 << 63;
    pub const NOT_ALLOWED: u64 = DEAD | 1;
    pub const BAD_TARGET: u64 = DEAD | 2;
    pub const BAD_BUFFER: u64 = DEAD | 3;
    pub const TOO_LONG: u64 = DEAD | 4;
    pub const BAD_ARGUMENT: u64 = DEAD | 5;

    pub fn is_error(code: u64) -> bool {
        code & DEAD != 0
    }

    pub fn name(code: u64) -> &'static str {
        match code {
            DEAD => "DEAD",
            NOT_ALLOWED => "NOT_ALLOWED",
            BAD_TARGET => "BAD_TARGET",
            BAD_BUFFER => "BAD_BUFFER",
            TOO_LONG => "TOO_LONG",
            BAD_ARGUMENT => "BAD_ARGUMENT",
            _ => "OK",
        }
    }
}

pub fn syscall2(number: u64, arg0: u64, arg1: u64) -> u64 {
    let ret;
    unsafe {
        asm!("int 0x80", inlateout("rax") number => ret, in("rdi") arg0, in("rsi") arg1, options(nostack));
    }
    ret
}

/// Raw six-argument syscall; returns (rax, rdx, rsi).
pub fn syscall6(number: u64, args: [u64; 6]) -> (u64, u64, u64) {
    let (rax, rdx, rsi);
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => rax,
            in("rdi") args[0],
            inlateout("rsi") args[1] => rsi,
            inlateout("rdx") args[2] => rdx,
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            options(nostack),
        );
    }
    (rax, rdx, rsi)
}

/// Send `msg` with operation `op` to task `target` and wait for the reply, which is written to
/// the start of `reply`. Returns the server's reply code and the reply length, or a kernel error.
pub fn send(target: u64, op: u64, msg: &[u8], reply: &mut [u8]) -> Result<(u64, usize), u64> {
    let (code, len, _) = syscall6(
        SYS_SEND,
        [target, op, msg.as_ptr() as u64, msg.len() as u64, reply.as_mut_ptr() as u64, reply.len() as u64],
    );
    if err::is_error(code) { Err(code) } else { Ok((code, len as usize)) }
}

pub struct Message {
    /// Sender's task id; 0 for a notification from the kernel.
    pub sender: u64,
    pub op: u64,
    pub len: usize,
}

/// Kernel notification (sender 0) op: device interrupts; `Message::len` holds the pending bits
/// (one per granted device, in manifest order).
pub const NOTIFY_IRQ: u64 = 2;

/// `recv` flag: device work is in flight, so an interrupt will come. Without it, the kernel
/// may end the run when nothing else can happen.
pub const RECV_EXPECT_IRQ: u64 = 1;

/// Wait for a message, written to the start of `buf`.
pub fn recv(buf: &mut [u8]) -> Result<Message, u64> {
    recv_flags(buf, 0)
}

/// `recv` with flags (`RECV_EXPECT_IRQ`).
pub fn recv_flags(buf: &mut [u8], flags: u64) -> Result<Message, u64> {
    recv_raw(buf, flags, 0)
}

/// Kernel notification (sender 0) op: a `recv_timeout` expired.
pub const NOTIFY_TIMER: u64 = 3;
/// `recv` flag: give up after a number of ticks with `NOTIFY_TIMER`.
pub const RECV_TIMEOUT: u64 = 2;

/// Wait for a message for at most `ticks` (at least 1); then get sender 0, op `NOTIFY_TIMER`.
pub fn recv_timeout(buf: &mut [u8], ticks: u64) -> Result<Message, u64> {
    recv_raw(buf, RECV_TIMEOUT, ticks)
}

fn recv_raw(buf: &mut [u8], flags: u64, ticks: u64) -> Result<Message, u64> {
    let (sender, op, len) = syscall6(SYS_RECV, [buf.as_mut_ptr() as u64, buf.len() as u64, flags, ticks, 0, 0]);
    if err::is_error(sender) { Err(sender) } else { Ok(Message { sender, op, len: len as usize }) }
}

/// Answer the message from `sender` with `code` (top bit clear) and `data`.
pub fn reply(sender: u64, code: u64, data: &[u8]) -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_REPLY, [sender, code, data.as_ptr() as u64, data.len() as u64, 0, 0]);
    if status == 0 { Ok(()) } else { Err(status) }
}

/// Operation of a kernel notification (sender 0) telling the supervisor a task died; the message
/// is a `DeathRecord`.
pub const NOTIFY_DEATH: u64 = 1;

/// How a task ended, as the kernel reports it to the supervisor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DeathRecord {
    pub id: u64,
    /// 1 exited, 2 faulted, 3 over CPU budget, 4 image rejected at boot (`code` = reason).
    pub kind: u64,
    /// Exit code, or the fault's vector.
    pub code: u64,
    pub rip: u64,
    pub cr2: u64,
    pub error_code: u64,
    pub ticks: u64,
}

impl DeathRecord {
    pub fn from_bytes(bytes: &[u8]) -> Option<DeathRecord> {
        (bytes.len() == core::mem::size_of::<DeathRecord>())
            .then(|| unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DeathRecord) })
    }
}

/// Supervisor only: reload a dead task into fresh memory. Returns its new id.
pub fn restart(id: u64) -> Result<u64, u64> {
    let (new_id, _, _) = syscall6(SYS_RESTART, [id, 0, 0, 0, 0, 0]);
    if err::is_error(new_id) { Err(new_id) } else { Ok(new_id) }
}

/// Supervisor only: (state, current id). State: 0 running/ready, 1 blocked in IPC, 2 exited,
/// 3 faulted, 4 over budget.
pub fn task_state(id: u64) -> Result<(u64, u64), u64> {
    let (state, current, _) = syscall6(SYS_TASK_STATE, [id, 0, 0, 0, 0, 0]);
    if err::is_error(state) { Err(state) } else { Ok((state, current)) }
}

/// Where the kernel maps granted devices' BARs (see `device_bar`).
pub const DEVICE_BASE: u64 = 0x10_0000_0000;
pub const DEVICE_STRIDE: u64 = 0x1000_0000;
pub const BAR_STRIDE: u64 = 0x200_0000;

/// Address and size of BAR `bar` of this task's granted device `device` (manifest order).
/// Fails for missing devices, absent BARs, and the BAR holding the MSI-X table.
pub fn device_bar(device: u64, bar: u64) -> Result<(u64, u64), u64> {
    let (addr, size, _) = syscall6(SYS_DEVICE_BAR, [device, bar, 0, 0, 0, 0]);
    if err::is_error(addr) { Err(addr) } else { Ok((addr, size)) }
}

/// Read a 32-bit word of a granted device's PCI configuration space.
pub fn pci_config_read(device: u64, offset: u64) -> Result<u32, u64> {
    let (value, _, _) = syscall6(SYS_PCI_CONFIG_READ, [device, offset, 0, 0, 0, 0]);
    if err::is_error(value) { Err(value) } else { Ok(value as u32) }
}

/// This task's DMA region: (address, physical address for the device, length in bytes).
/// Physically contiguous, owned by the task slot for life, zeroed on every (re)start.
pub fn dma_info() -> Result<(u64, u64, u64), u64> {
    let (addr, phys, len) = syscall6(SYS_DMA_INFO, [0; 6]);
    if err::is_error(addr) { Err(addr) } else { Ok((addr, phys, len)) }
}

/// Block-device IPC interface, served by the virtio-blk driver and (per volume) by the storage
/// task. Blocks are 4 KiB; the block number rides in `op` above the operation code, so a write
/// message is exactly one block.
pub mod block {
    use super::{send, yield_now};

    pub const BLOCK_SIZE: usize = 4096;

    /// Reply: the block's 4096 bytes.
    pub const OP_READ: u64 = 1;
    /// Message: the block's 4096 bytes.
    pub const OP_WRITE: u64 = 2;
    /// Replied once everything written before it is on stable storage.
    pub const OP_FLUSH: u64 = 3;
    /// Reply: capacity in blocks (u64, little endian).
    pub const OP_INFO: u64 = 4;

    pub const CODE_OK: u64 = 0;
    pub const CODE_BUSY: u64 = 1;
    pub const CODE_BAD_OP: u64 = 2;
    pub const CODE_OUT_OF_RANGE: u64 = 3;
    pub const CODE_IO_ERROR: u64 = 4;
    /// Storage task: no key yet (see F4); try again later.
    pub const CODE_LOCKED: u64 = 5;
    /// Storage task: the block failed its integrity check.
    pub const CODE_INTEGRITY: u64 = 6;
    /// Storage task: refused (e.g. OP_UNLOCK from a task that may not unlock).
    pub const CODE_NOT_ALLOWED: u64 = 7;

    /// Storage task: message is the 32-byte master key. Only the tasks named "keys" or
    /// "attest" may send it; until then every other request gets CODE_LOCKED.
    pub const OP_UNLOCK: u64 = 5;

    pub fn unlock(storage: u64, master_key: &[u8; 32]) -> Result<(), u64> {
        call(storage, OP_UNLOCK, master_key, &mut []).map(|_| ())
    }

    pub fn op(code: u64, block: u64) -> u64 {
        code | block << 8
    }

    /// Split an `op` into (operation code, block number).
    pub fn split(op: u64) -> (u64, u64) {
        (op & 0xff, op >> 8)
    }

    /// Send `msg` with `op` to `server`, retrying while it is busy. Returns the reply length;
    /// fails with the server's code or a kernel error.
    fn call(server: u64, op: u64, msg: &[u8], reply: &mut [u8]) -> Result<usize, u64> {
        loop {
            match send(server, op, msg, reply) {
                Ok((CODE_OK, n)) => return Ok(n),
                Ok((CODE_BUSY, _)) => yield_now(),
                Ok((code, _)) => return Err(code),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn read(server: u64, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), u64> {
        call(server, op(OP_READ, block), &[], buf).map(|_| ())
    }

    pub fn write(server: u64, block: u64, data: &[u8; BLOCK_SIZE]) -> Result<(), u64> {
        call(server, op(OP_WRITE, block), data, &mut []).map(|_| ())
    }

    pub fn flush(server: u64) -> Result<(), u64> {
        call(server, OP_FLUSH, &[], &mut []).map(|_| ())
    }

    /// Capacity in blocks.
    pub fn capacity(server: u64) -> Result<u64, u64> {
        let mut out = [0u8; 8];
        call(server, OP_INFO, &[], &mut out)?;
        Ok(u64::from_le_bytes(out))
    }

    pub fn code_name(code: u64) -> &'static str {
        match code {
            CODE_OK => "OK",
            CODE_BUSY => "BUSY",
            CODE_BAD_OP => "BAD_OP",
            CODE_OUT_OF_RANGE => "OUT_OF_RANGE",
            CODE_IO_ERROR => "IO_ERROR",
            CODE_LOCKED => "LOCKED",
            CODE_INTEGRITY => "INTEGRITY",
            CODE_NOT_ALLOWED => "NOT_ALLOWED",
            _ => super::err::name(code),
        }
    }
}

/// Client side of the console driver's IPC interface (`user/virtio-console`).
pub mod console {
    use super::{err, send, yield_now};

    /// Write the message's bytes to the host. Replied once the device has taken them.
    pub const OP_WRITE: u64 = 1;
    pub const CODE_OK: u64 = 0;
    /// Every transmit slot is in flight; try again.
    pub const CODE_BUSY: u64 = 1;
    pub const CODE_BAD_OP: u64 = 2;
    /// Read bytes the host sent (drivers with a host-to-guest path, e.g. virtio-vsock). The
    /// message is the most bytes wanted (u32, little endian); the reply carries what arrived,
    /// waiting until something does.
    pub const OP_READ: u64 = 3;

    /// Wait for bytes from the host, into `buf`. Returns how many arrived.
    pub fn read(driver: u64, buf: &mut [u8]) -> Result<usize, u64> {
        let want = (buf.len() as u32).to_le_bytes();
        match send(driver, OP_READ, &want, buf) {
            Ok((CODE_OK, n)) => Ok(n),
            Ok((code, _)) => Err(code),
            Err(e) => Err(e),
        }
    }

    /// Send `bytes` (at most 4 KiB) to the host through the driver task `driver`, retrying while
    /// it is busy. Fails with the kernel error (e.g. `err::DEAD` if the driver died) or the
    /// driver's code.
    pub fn write(driver: u64, bytes: &[u8]) -> Result<(), u64> {
        loop {
            match send(driver, OP_WRITE, bytes, &mut []) {
                Ok((CODE_OK, _)) => return Ok(()),
                Ok((CODE_BUSY, _)) => yield_now(),
                Ok((code, _)) => return Err(code),
                Err(e) => return Err(e),
            }
        }
    }

    pub fn is_dead(e: u64) -> bool {
        e == err::DEAD
    }
}

/// The manifest name of task `id` (any generation), written into `buf`.
pub fn task_name(id: u64, buf: &mut [u8]) -> Result<&str, u64> {
    let (len, _, _) = syscall6(SYS_TASK_NAME, [id, buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0]);
    if err::is_error(len) {
        return Err(len);
    }
    core::str::from_utf8(&buf[..len as usize]).map_err(|_| err::BAD_ARGUMENT)
}

/// The kernel event log (for the task with `events = true`).
pub mod events {
    use super::{SYS_READ_EVENTS, SYS_STATS, err, syscall6};

    pub const TASK_START: u64 = 1;
    pub const EXIT: u64 = 2;
    pub const FAULT: u64 = 3;
    pub const OVER_BUDGET: u64 = 4;
    pub const RESTART: u64 = 5;
    pub const IPC_REFUSED: u64 = 6;
    pub const IMAGE_REJECTED: u64 = 7;

    /// Why the kernel refused a task image (`IMAGE_REJECTED`'s `a`, a death record's `code`).
    pub fn rejection(reason: u64) -> &'static str {
        match reason {
            1 => "no image",
            2 => "no signature",
            3 => "malformed signature file",
            4 => "signature does not verify",
            5 => "signed for another program",
            6 => "image does not match its signature",
            7 => "version older than the manifest allows",
            _ => "unknown",
        }
    }

    /// See kernel/src/events.rs for what `a`, `b`, `c` hold for each kind.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Event {
        pub seq: u64,
        pub tick: u64,
        pub kind: u64,
        pub task: u64,
        pub a: u64,
        pub b: u64,
        pub c: u64,
    }

    /// Events since the last read, oldest first: (how many were written to `out`, how many
    /// were lost because the kernel's ring wrapped first).
    pub fn read(out: &mut [Event]) -> Result<(usize, u64), u64> {
        let bytes = core::mem::size_of_val(out) as u64;
        let (count, dropped, _) = syscall6(SYS_READ_EVENTS, [out.as_mut_ptr() as u64, bytes, 0, 0, 0, 0]);
        if err::is_error(count) { Err(count) } else { Ok((count as usize, dropped)) }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct Stats {
        pub uptime_ticks: u64,
        pub frames_in_use: u64,
        pub device_interrupts: u64,
        pub events_logged: u64,
        pub tasks: u64,
        /// Per task slot: id, state (0 running/ready, 1 blocked, 2 exited, 3 faulted,
        /// 4 over budget), CPU ticks.
        pub task: [[u64; 3]; 8],
    }

    pub fn stats() -> Result<Stats, u64> {
        let mut s = Stats::default();
        let size = core::mem::size_of::<Stats>() as u64;
        let (n, _, _) = syscall6(SYS_STATS, [&mut s as *mut Stats as u64, size, 0, 0, 0, 0]);
        if err::is_error(n) { Err(n) } else { Ok(s) }
    }
}

/// The boot measurement log and where the TPM is mapped (for the task with `tpm = true`):
/// (count, TPM address). Entries are 48 bytes: 16-byte zero-padded name, 32-byte SHA-256.
pub fn measurements(buf: &mut [u8]) -> Result<(usize, u64), u64> {
    let (count, tpm, _) = syscall6(SYS_MEASUREMENTS, [buf.as_mut_ptr() as u64, buf.len() as u64, 0, 0, 0, 0]);
    if err::is_error(count) { Err(count) } else { Ok((count as usize, tpm)) }
}

/// Client side of the attestation task (`user/attest`).
pub mod attest {
    /// Message: a nonce (up to 32 bytes). Reply: one JSON line with the quote, which is over
    /// SHA-256(nonce || the attest task's X25519 public key for this boot).
    pub const OP_QUOTE: u64 = 1;
    /// Message: the host's X25519 public key (32 bytes) and the master key sealed to ours (48
    /// bytes). The attest task opens it and unlocks the storage task. Reply code 0 on success.
    pub const OP_UNWRAP: u64 = 2;
}

/// Client side of the telemetry task (`user/telemetry`).
pub mod telemetry {
    use super::send;

    /// Forward a line of text to the host as a `log` event.
    pub const OP_LOG: u64 = 1;

    /// Send `text` to telemetry task `id`. Fails like `send`.
    pub fn log(id: u64, text: &[u8]) -> Result<(), u64> {
        send(id, OP_LOG, text, &mut []).map(|_| ())
    }
}

/// The id of the task called `name` in the app manifest.
pub fn lookup(name: &str) -> Result<u64, u64> {
    let (id, _, _) = syscall6(SYS_LOOKUP, [name.as_ptr() as u64, name.len() as u64, 0, 0, 0, 0]);
    if err::is_error(id) { Err(id) } else { Ok(id) }
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

/// Timer ticks (10 ms each) per second.
pub const TICK_HZ: u64 = 100;

/// Wait at least `ticks` timer ticks. Uses no CPU while waiting.
pub fn sleep(ticks: u64) {
    syscall2(SYS_SLEEP, ticks, 0);
}

/// Timer ticks since boot.
pub fn uptime() -> u64 {
    syscall2(SYS_UPTIME, 0, 0)
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

/// Collects formatted output and sends it in one `write`, so a line can't be split by a
/// preemption between pieces and interleaved with another task's output. Output longer than
/// the buffer goes out in buffer-sized writes.
pub struct LineWriter {
    buf: [u8; 256],
    len: usize,
}

impl LineWriter {
    pub const fn new() -> LineWriter {
        LineWriter { buf: [0; 256], len: 0 }
    }

    /// What has been written so far (and not flushed).
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    pub fn flush(&mut self) {
        if self.len != 0 {
            write(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl Write for LineWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &b in s.as_bytes() {
            if self.len == self.buf.len() {
                self.flush();
            }
            self.buf[self.len] = b;
            self.len += 1;
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let mut out = $crate::LineWriter::new();
        let _ = core::fmt::Write::write_fmt(&mut out, format_args!($($arg)*));
        out.flush();
    }};
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
