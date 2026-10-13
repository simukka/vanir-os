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
pub const SYS_NOTIFY: u64 = 116;
pub const SYS_HALT: u64 = 117;
pub const SYS_TASK_LISTEN: u64 = 118;
pub const SYS_SLOT_STAGE: u64 = 119;
pub const SYS_SLOT_LOAD: u64 = 120;
pub const SYS_SLOT_UNLOAD: u64 = 121;
pub const SYS_TPM_LOCK: u64 = 122;
pub const SYS_TPM_UNLOCK: u64 = 123;
pub const SYS_RUNTIME_LOG: u64 = 124;
pub const SYS_STOP: u64 = 125;
pub const SYS_REBOOT: u64 = 126;

/// The most tasks (fixed tasks and slots) a manifest may declare; size per-task tables with it.
pub const MAX_TASKS: usize = 64;

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
    /// The TPM is in use; try again.
    pub const BUSY: u64 = DEAD | 6;
    /// The run-time measurement log is full: no more loads until the node reboots.
    pub const LOG_FULL: u64 = DEAD | 7;
    /// The image was refused (the reason comes with it: `events::rejection`).
    pub const REJECTED: u64 = DEAD | 8;

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
            BUSY => "BUSY",
            LOG_FULL => "LOG_FULL",
            REJECTED => "REJECTED",
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
/// Kernel notification (sender 0) op: bits other tasks posted with `notify`; `Message::len`
/// holds them.
pub const NOTIFY_POST: u64 = 4;

/// Post `bits` to task `target` (which must be in our `sends`, or have us in its own) without
/// waiting: it gets them in its next `recv` as op `NOTIFY_POST`. Fails like `send` (DEAD,
/// NOT_ALLOWED, ...).
pub fn notify(target: u64, bits: u64) -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_NOTIFY, [target, bits, 0, 0, 0, 0]);
    if status == 0 { Ok(()) } else { Err(status) }
}
/// `recv` flag: give up after a number of ticks with `NOTIFY_TIMER`.
pub const RECV_TIMEOUT: u64 = 2;

/// Wait for a message for at most `ticks`; then get sender 0, op `NOTIFY_TIMER`. With 0, only
/// take a message (or notification) that is already waiting.
pub fn recv_timeout(buf: &mut [u8], ticks: u64) -> Result<Message, u64> {
    recv_raw(buf, RECV_TIMEOUT, ticks)
}

/// Take the bits posted to us with `notify` since we last looked (0 if none), without waiting.
/// Only for a task nothing sends to (a slot's instance): a message waiting would be refused.
pub fn posted() -> u64 {
    match recv_timeout(&mut [], 0) {
        Ok(m) if m.sender == 0 && m.op == NOTIFY_POST => m.len as u64,
        _ => 0,
    }
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

/// Supervisor only: end live task `id` on purpose; it is reported as stopped (death kind 5).
pub fn stop(id: u64) -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_STOP, [id, 0, 0, 0, 0, 0]);
    if status == 0 { Ok(()) } else { Err(status) }
}

/// Supervisor only: reset the machine (returns only on error).
pub fn reboot() -> u64 {
    syscall6(SYS_REBOOT, [0; 6]).0
}

/// Requests to the supervisor (from the agent, RFD 2, P4). Message: a task id (u64). Reply
/// code 0 and the new id (u64) on success; otherwise 0x100 | the kernel error's low bits.
pub mod supervisor {
    use super::send;

    /// Stop the task: it is reported as stopped and not restarted.
    pub const OP_STOP: u64 = 1;
    /// Start a dead task again (e.g. a stopped slot, for a rollback), with its backoff reset.
    pub const OP_START: u64 = 2;
    /// Reboot the node into the image installed now (message: anything). Only answered if it
    /// fails.
    pub const OP_REBOOT: u64 = 3;

    fn call(supervisor: u64, op: u64, id: u64) -> Result<u64, u64> {
        let mut out = [0u8; 8];
        match send(supervisor, op, &id.to_le_bytes(), &mut out) {
            Ok((0, 8)) => Ok(u64::from_le_bytes(out)),
            Ok((code, _)) => Err(code & 0xff | super::err::DEAD),
            Err(e) => Err(e),
        }
    }

    pub fn stop(supervisor: u64, id: u64) -> Result<(), u64> {
        call(supervisor, OP_STOP, id).map(|_| ())
    }

    /// Returns the task's new id.
    pub fn start(supervisor: u64, id: u64) -> Result<u64, u64> {
        call(supervisor, OP_START, id)
    }

    /// Returns only if the supervisor refused.
    pub fn reboot(supervisor: u64) -> u64 {
        call(supervisor, OP_REBOOT, 0).err().unwrap_or(0)
    }
}

/// Supervisor only: stop the system, as if nothing could run any more (tests end this way when
/// their servers never go idle). Returns only on error.
pub fn halt(code: u64) -> u64 {
    syscall6(SYS_HALT, [code, 0, 0, 0, 0, 0]).0
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
    /// Storage task (RFD 3): a write to a service's volume from an instance that doesn't hold
    /// its writer epoch, or an epoch below the one recorded.
    pub const CODE_FENCED: u64 = 8;

    /// Storage task: message is the 32-byte master key. Only the tasks named "keys" or
    /// "attest" may send it; until then every other request gets CODE_LOCKED. (A storage task
    /// that may send to "keys" also asks it for the key itself when it starts: see `keys`.)
    pub const OP_UNLOCK: u64 = 5;

    pub fn unlock(storage: u64, master_key: &[u8; 32]) -> Result<(), u64> {
        call(storage, OP_UNLOCK, master_key, &mut []).map(|_| ())
    }

    /// Storage task (RFD 3, P1): message is epoch, lease_until and the writer's task id (u64s,
    /// little endian). Makes that instance the writer of its service's volume at that epoch,
    /// creating the volume if needed. Only the task with `loads = true` may send it. An epoch
    /// above the recorded one is recorded and flushed before the reply; the recorded epoch again
    /// is accepted while there is no writer or the writer's slot is unchanged; anything else
    /// gets CODE_FENCED.
    pub const OP_EPOCH: u64 = 6;

    pub fn epoch(storage: u64, epoch: u64, lease_until: u64, writer: u64) -> Result<(), u64> {
        let mut msg = [0u8; 24];
        msg[..8].copy_from_slice(&epoch.to_le_bytes());
        msg[8..16].copy_from_slice(&lease_until.to_le_bytes());
        msg[16..].copy_from_slice(&writer.to_le_bytes());
        call(storage, OP_EPOCH, &msg, &mut []).map(|_| ())
    }

    /// Storage task (RFD 3, P2): message is a service name (32 bytes, zero padded) and that
    /// service's 32-byte key. Only "keys" and "attest" may send it. A service's volume answers
    /// CODE_LOCKED until its key is here (a storage task that may send to "keys" asks it too).
    /// The key it already has again is a no-op.
    pub const OP_SERVICE_KEY: u64 = 7;
    /// Storage task (RFD 3, P2): message is a service name (32 bytes, zero padded). Forget that
    /// service's key, once no instance of it is left on the node. Only the task with
    /// `loads = true` may send it.
    pub const OP_FORGET_KEY: u64 = 8;

    /// A service name zero padded to 32 bytes, as `OP_SERVICE_KEY` and `OP_FORGET_KEY` carry it.
    pub fn service_name(service: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let n = service.len().min(32);
        out[..n].copy_from_slice(&service[..n]);
        out
    }

    pub fn service_key(storage: u64, service: &[u8], key: &[u8; 32]) -> Result<(), u64> {
        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&service_name(service));
        msg[32..].copy_from_slice(key);
        call(storage, OP_SERVICE_KEY, &msg, &mut []).map(|_| ())
    }

    pub fn forget_key(storage: u64, service: &[u8]) -> Result<(), u64> {
        call(storage, OP_FORGET_KEY, &service_name(service), &mut []).map(|_| ())
    }

    /// Storage task (RFD 3, P3): message is a service name (32 bytes, zero padded) and the
    /// candidate's task id (u64, little endian), or 0. From now until the candidate holds the
    /// service volume's epoch, its reads, writes and flushes are held and answered once it does.
    /// 0, or another candidate, calls the handoff off: what was held is answered at once, as if
    /// it had just arrived. Only the task with `loads = true` may send it.
    pub const OP_HANDOFF: u64 = 9;

    pub fn handoff(storage: u64, service: &[u8], candidate: u64) -> Result<(), u64> {
        let mut msg = [0u8; 40];
        msg[..32].copy_from_slice(&service_name(service));
        msg[32..].copy_from_slice(&candidate.to_le_bytes());
        call(storage, OP_HANDOFF, &msg, &mut []).map(|_| ())
    }

    /// Storage task, moving a service's volume to another node (RFD 3, P4–P5). Only the task
    /// with `loads = true` may send these; each message starts with the service name (32
    /// bytes, zero padded). Blocks travel as they are on disk: ciphertext, write counter and tag.
    ///
    /// Source: the ciphertext of data block `b` (in the op's block field), whose counter and
    /// tag `OP_EXPORT_ENTRY` then gives (b, counter, tag: 32 bytes), as they were when it was
    /// read. A block never written has counter 0, and isn't sent.
    pub const OP_EXPORT: u64 = 10;
    pub const OP_EXPORT_ENTRY: u64 = 11;
    /// Metadata block `m` as it is on disk: 170 (counter, tag) entries of 24 bytes.
    pub const OP_EXPORT_META: u64 = 12;
    /// The volume's size in data blocks (u64) and its header's 96 bytes (counter, tag, sealed
    /// fields).
    pub const OP_EXPORT_HEADER: u64 = 13;
    /// Target: name, size (u64) and the source's header: the volume is made, or emptied, with
    /// that header. Refused while an instance writes it or a handoff waits on it.
    pub const OP_IMPORT_HEADER: u64 = 14;
    /// Target: name, then b, counter (u64s) and tag (16) of the block `OP_IMPORT` brings next
    /// (its message is the ciphertext alone, so it doesn't start with the name).
    pub const OP_IMPORT_ENTRY: u64 = 15;
    /// Target: block `b`'s ciphertext. It must open with the service key, the volume name, `b`
    /// and the counter from `OP_IMPORT_ENTRY` (else CODE_INTEGRITY); then it is stored as it is.
    /// A counter lower than the one the block has already is ignored.
    pub const OP_IMPORT: u64 = 16;
    /// Source: name and 1 or 0. While on, each write the writer makes is made and then held,
    /// unanswered, until `OP_MIRROR_ACK`: the agent fetches it (`OP_MIRROR_PENDING` gives its
    /// block number, or nothing) and sends it to the target. Off answers a held write.
    pub const OP_MIRROR: u64 = 17;
    pub const OP_MIRROR_PENDING: u64 = 18;
    pub const OP_MIRROR_ACK: u64 = 19;
    /// Wipe the volume (header and counters: every block reads as never written) and free its
    /// space for a volume of the same size. Refused while an instance writes it.
    pub const OP_DROP: u64 = 22;

    /// Bit the storage task posts (`notify`) to an instance that has just become its volume's
    /// writer, before it answers any request it held (RFD 3, P1). From then on nobody else writes
    /// the volume, so what the instance caches stays current.
    pub const NOTIFY_WRITER: u64 = 1;

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
            CODE_FENCED => "FENCED",
            _ => super::err::name(code),
        }
    }
}

/// The NIC driver's IPC interface (`user/virtio-net`): Ethernet frames in and out. The driver
/// knows nothing about IP; its one client is the network stack task.
pub mod nic {
    /// Message: one Ethernet frame (14..=1514 bytes, no FCS). Replied once the device has it.
    pub const OP_SEND_FRAME: u64 = 1;
    /// Reply: the frames received so far, each a little-endian u16 length and then the frame,
    /// as many as fit in 4 KiB. Never waits. If that empties the receive ring, the driver
    /// re-enables its receive interrupt and posts `NOTIFY_RX` to the caller when the next frame
    /// arrives; while frames keep coming the interrupt stays off and the caller polls (NAPI).
    pub const OP_RECV_FRAMES: u64 = 2;
    /// Reply: `Info`.
    pub const OP_INFO: u64 = 3;

    /// Bit posted to the receiving client when frames arrive.
    pub const NOTIFY_RX: u64 = 1;

    pub const CODE_OK: u64 = 0;
    /// Every transmit buffer is in use; try again.
    pub const CODE_BUSY: u64 = 1;
    pub const CODE_BAD_OP: u64 = 2;
    /// Not a frame we can send (too short or too long).
    pub const CODE_BAD_FRAME: u64 = 3;

    /// Largest frame: a 1500-byte payload and the 14-byte Ethernet header.
    pub const MAX_FRAME: usize = 1514;

    /// The interface's address and counters (cumulative since the driver started).
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Info {
        pub mac: [u8; 6],
        pub link_up: u8,
        pub _pad: u8,
        pub rx_packets: u64,
        pub rx_bytes: u64,
        pub tx_packets: u64,
        pub tx_bytes: u64,
        /// Times the receive ring was found full: the device drops frames while it is.
        pub rx_ring_full: u64,
        /// Frames refused: too short, too long, or no transmit buffer free.
        pub errors: u64,
        pub rx_multicast: u64,
        pub rx_broadcast: u64,
    }

    /// Call `f` with each frame of an `OP_RECV_FRAMES` reply.
    pub fn frames(reply: &[u8], mut f: impl FnMut(&[u8])) {
        let mut at = 0;
        while at + 2 <= reply.len() {
            let len = u16::from_le_bytes([reply[at], reply[at + 1]]) as usize;
            let Some(frame) = reply.get(at + 2..at + 2 + len) else { return };
            f(frame);
            at += 2 + len;
        }
    }

    pub fn info(driver: u64) -> Result<Info, u64> {
        let mut out = [0u8; core::mem::size_of::<Info>()];
        match super::send(driver, OP_INFO, &[], &mut out) {
            Ok((CODE_OK, n)) if n == out.len() => Ok(unsafe { core::ptr::read_unaligned(out.as_ptr() as *const Info) }),
            Ok((code, _)) => Err(code),
            Err(e) => Err(e),
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
    pub const IMAGE_LOADED: u64 = 8;
    pub const IMAGE_UNLOADED: u64 = 9;
    pub const STOPPED: u64 = 10;

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
            8 => "malformed descriptor",
            9 => "descriptor does not match its signature",
            10 => "descriptor asks for another slot class",
            11 => "image needs more memory than its slot class has",
            12 => "not a loadable ELF image",
            13 => "version below its min_version",
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
    #[derive(Clone, Copy)]
    pub struct Stats {
        pub uptime_ticks: u64,
        pub frames_in_use: u64,
        pub device_interrupts: u64,
        pub events_logged: u64,
        pub tasks: u64,
        /// Per task slot: id, state (0 running/ready, 1 blocked, 2 exited, 3 faulted,
        /// 4 over budget, 5 image rejected, 6 empty slot), CPU ticks.
        pub task: [[u64; 3]; super::MAX_TASKS],
    }

    pub fn stats() -> Result<Stats, u64> {
        let mut s = Stats { uptime_ticks: 0, frames_in_use: 0, device_interrupts: 0, events_logged: 0, tasks: 0, task: [[0; 3]; super::MAX_TASKS] };
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
    /// Message: the first entry wanted (u64). Reply: one JSON line of run-time log entries from
    /// there, up to the count the last quote covered; code 1 when there are none.
    pub const OP_RUNTIME_LOG: u64 = 3;
    /// From the agent only. Message: a nonce (32 bytes) and the agent's X25519 key (32 bytes).
    /// Reply: the JSON quote line as for `OP_QUOTE`, with `kx_pub` the agent's key and
    /// `seal_pub` the attest task's own key for this boot, over SHA-256(nonce || kx_pub ||
    /// seal_pub): the control plane seals service keys to `seal_pub` (RFD 3, P2).
    pub const OP_QUOTE_FOR: u64 = 4;
    /// From the agent only (RFD 3, P2). Message: a service name (32 bytes, zero padded) and a
    /// blob the control plane sealed to `seal_pub` (80 bytes: its X25519 public key, the sealed
    /// key, the tag). The attest task opens it and gives the key to the storage task. Reply
    /// code 0 when storage has it, 3 when the blob doesn't open (for this service), 4 or 5 when
    /// storage isn't there or refused (try again).
    pub const OP_UNWRAP_VOLUME: u64 = 5;
}

/// The key server (the task named "keys", `user/unlocker`): a stand-in for a local key store.
pub mod keys {
    /// Reply: the 32-byte storage master key. Only the task named "disk" gets it.
    pub const OP_MASTER_KEY: u64 = 1;
    /// Message: a service name (up to 32 bytes). Reply: that service's 32-byte volume key (RFD 3,
    /// P2). Only the task named "disk" gets it.
    pub const OP_SERVICE_KEY: u64 = 2;
}

/// Client side of the telemetry task (`user/telemetry`).
pub mod telemetry {
    use super::send;

    /// Forward a line of text to the host as a `log` event.
    pub const OP_LOG: u64 = 1;
    /// A storage event: kind (u64), block (u64), then a task name (the volume, or who unlocked).
    pub const OP_STORAGE: u64 = 2;

    /// Storage event kinds. VOLUME_CREATED: block = first block of the volume on the disk;
    /// UNLOCKED: name = the task that gave the key; INTEGRITY_ERROR: block = the volume's block.
    pub const VOLUME_CREATED: u64 = 1;
    pub const STORAGE_LOCKED: u64 = 2;
    pub const STORAGE_UNLOCKED: u64 = 3;
    pub const INTEGRITY_ERROR: u64 = 4;

    /// Send `text` to telemetry task `id`. Fails like `send`.
    pub fn log(id: u64, text: &[u8]) -> Result<(), u64> {
        send(id, OP_LOG, text, &mut []).map(|_| ())
    }

    /// Report a storage event to telemetry task `id`. Fails like `send`.
    pub fn storage(id: u64, kind: u64, block: u64, name: &[u8]) -> Result<(), u64> {
        let mut msg = [0u8; 16 + 32];
        let n = name.len().min(32);
        msg[..8].copy_from_slice(&kind.to_le_bytes());
        msg[8..16].copy_from_slice(&block.to_le_bytes());
        msg[16..16 + n].copy_from_slice(&name[..n]);
        send(id, OP_STORAGE, &msg[..16 + n], &mut []).map(|_| ())
    }

    /// A network event (`Record`: the event's name, then its fields), e.g. a routing change.
    pub const OP_NET: u64 = 3;
    /// A counter snapshot (`Record`: the scope, then the counters, cumulative). Reply: the
    /// snapshot interval in ticks (u64), which the host may change; send the next one then.
    pub const OP_COUNTERS: u64 = 4;
    /// From the task named "control" or "agent" only: set the snapshot interval, in milliseconds (u64),
    /// bounded to 100 ms..60 s.
    pub const OP_SET_INTERVAL: u64 = 5;

    /// Any other event (`Record`: the event's name, then its fields), e.g. a crash reported by
    /// the supervisor.
    pub const OP_EVENT: u64 = 6;
    /// From the task named "agent", when there is no uplink driver: the JSON lines waiting to
    /// go to the control plane (whole lines, at most 4 KiB), oldest first.
    pub const OP_PULL: u64 = 7;

    /// Counter snapshots go out this often until the host says otherwise (RFD 1: 1 s).
    pub const DEFAULT_INTERVAL_TICKS: u64 = 100;

    /// A line of text, `name key=value key=value ...`, that telemetry turns into a JSON
    /// record: numbers stay numbers, anything else becomes a string. Built in a fixed buffer;
    /// what doesn't fit is left out.
    pub struct Record {
        buf: [u8; 2048],
        len: usize,
    }

    impl Record {
        pub fn new(name: &str) -> Record {
            let mut r = Record { buf: [0; 2048], len: 0 };
            r.put(name.as_bytes());
            r
        }

        fn put(&mut self, bytes: &[u8]) {
            for &b in bytes {
                if self.len < self.buf.len() {
                    // Spaces and '=' separate fields; keep them out of values.
                    self.buf[self.len] = if b == b' ' || b == b'=' || !(0x21..0x7f).contains(&b) { b'_' } else { b };
                    self.len += 1;
                }
            }
        }

        pub fn num(&mut self, key: &str, value: u64) -> &mut Record {
            let mut digits = [0u8; 20];
            let mut i = digits.len();
            let mut v = value;
            loop {
                i -= 1;
                digits[i] = b'0' + (v % 10) as u8;
                v /= 10;
                if v == 0 {
                    break;
                }
            }
            self.text_bytes(key, &digits[i..])
        }

        pub fn text(&mut self, key: &str, value: &str) -> &mut Record {
            self.text_bytes(key, value.as_bytes())
        }

        pub fn text_bytes(&mut self, key: &str, value: &[u8]) -> &mut Record {
            if self.len + key.len() + value.len() + 2 <= self.buf.len() {
                self.buf[self.len] = b' ';
                self.len += 1;
                self.put(key.as_bytes());
                self.buf[self.len] = b'=';
                self.len += 1;
                self.put(value);
            }
            self
        }

        pub fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }

    /// Report a network event to telemetry task `id`.
    pub fn net_event(id: u64, record: &Record) -> Result<(), u64> {
        send(id, OP_NET, record.as_bytes(), &mut []).map(|_| ())
    }

    /// Report any other event to telemetry task `id`.
    pub fn event(id: u64, record: &Record) -> Result<(), u64> {
        send(id, OP_EVENT, record.as_bytes(), &mut []).map(|_| ())
    }

    /// Send a counter snapshot to telemetry task `id`; returns the interval for the next one.
    pub fn counters(id: u64, record: &Record) -> Result<u64, u64> {
        let mut interval = [0u8; 8];
        match send(id, OP_COUNTERS, record.as_bytes(), &mut interval) {
            Ok((0, 8)) => Ok(u64::from_le_bytes(interval).max(1)),
            Ok(_) => Ok(DEFAULT_INTERVAL_TICKS),
            Err(e) => Err(e),
        }
    }
}

/// TSC cycles per timer tick, measured over a few ticks (so it takes about 60 ms).
pub fn tsc_per_tick() -> u64 {
    sleep(1); // start on a tick boundary
    let (t0, c0) = (uptime(), rdtsc());
    sleep(5);
    (rdtsc() - c0) / (uptime() - t0).max(1)
}

/// Client side of the network stack task (`user/net`): TCP on the ports the caller's manifest
/// entry declares (`listen`). Handles name listeners and connections; each carries a generation
/// number, so a handle kept after its connection closed can't name a newer one. Calls never
/// wait, except `OP_WAIT`, which returns when any of the caller's handles has something to do.
pub mod net {
    use super::send;

    /// Message: the port (u16). Reply: a listener handle (u32). `CODE_NOT_ALLOWED` if the
    /// caller's manifest entry doesn't declare the port.
    pub const OP_LISTEN: u64 = 1;
    /// Message: the most ticks to wait (u64; 0 = no limit). Reply: `Event`s for the caller's
    /// handles that have something to do, or none if the time ran out.
    pub const OP_WAIT: u64 = 2;
    /// Message: a listener handle. Reply: `Accepted`, or `CODE_WOULD_BLOCK`.
    pub const OP_ACCEPT: u64 = 3;
    /// Message: a connection handle and the most bytes wanted (u32 each). Reply: received bytes,
    /// `CODE_WOULD_BLOCK` if there are none yet, `CODE_CLOSED` once the peer has closed or reset.
    pub const OP_RECV: u64 = 4;
    /// Message: a connection handle (u32), then bytes. Reply: how many were taken (u32), maybe
    /// 0; `EV_WRITE` comes when there is room again.
    pub const OP_SEND: u64 = 5;
    /// Message: a handle. Closes the connection (or stops listening) and frees the handle.
    pub const OP_CLOSE: u64 = 6;
    /// Message: a connection handle. Sends a FIN; reading goes on until the peer closes.
    pub const OP_SHUTDOWN: u64 = 7;
    /// The caller is ready to serve: only then can it become its service's live instance.
    pub const OP_READY: u64 = 8;
    /// A draining instance has finished its work (see `EV_DRAIN`).
    pub const OP_DONE: u64 = 9;
    /// Routing (tasks with `routes = true`): message an instance's task id (u64), which
    /// becomes its service's live instance. `CODE_NOT_READY` if it hasn't said `OP_READY`.
    pub const OP_ROUTE: u64 = 10;
    /// Routing: message an instance's task id and a deadline in ticks (u64 each). The instance
    /// gets no new connections and an `EV_DRAIN`; connections still open at the deadline are
    /// reset. Replied when the instance is drained: connections reset at the deadline (u64).
    pub const OP_DRAIN: u64 = 11;
    /// Routing: message `Block`. Drop packets from that range until it expires.
    pub const OP_BLOCK: u64 = 12;
    /// From a task with `routes = true`. Message: an instance's task id (u64). Reply: its
    /// status (u64, `STATUS_*`) and its `drain_forced` count (u64).
    pub const OP_STATUS: u64 = 13;
    /// From a task with `connects = true`. Message: IPv4 address (4 bytes) and port (u16).
    /// Reply: a connection handle (u32), usable at once; `EV_WRITE` comes once it is connected,
    /// `EV_CLOSED` if it fails. `CODE_NOT_READY` while the stack has no address.
    pub const OP_CONNECT: u64 = 14;

    /// `OP_STATUS` answers. UNKNOWN: not an instance (yet, or any more: it hasn't listened, or
    /// it has gone).
    pub const STATUS_UNKNOWN: u64 = 0;
    pub const STATUS_GONE: u64 = STATUS_UNKNOWN;
    /// Listening, but hasn't said `OP_READY`.
    pub const STATUS_STARTING: u64 = 1;
    pub const STATUS_READY: u64 = 2;
    pub const STATUS_LIVE: u64 = 3;
    pub const STATUS_DRAINING: u64 = 4;
    pub const STATUS_DRAINED: u64 = 5;

    /// `OP_DRAIN` flag (third u64 of the message): answer at once instead of when the drain is
    /// over; follow it with `OP_STATUS`.
    pub const DRAIN_NOWAIT: u64 = 1;

    pub const CODE_OK: u64 = 0;
    pub const CODE_WOULD_BLOCK: u64 = 1;
    pub const CODE_BAD_OP: u64 = 2;
    pub const CODE_NOT_ALLOWED: u64 = 3;
    pub const CODE_BAD_HANDLE: u64 = 4;
    /// The socket pool is used up.
    pub const CODE_NO_SOCKETS: u64 = 5;
    pub const CODE_CLOSED: u64 = 6;
    pub const CODE_NOT_READY: u64 = 7;

    /// A listener has a connection to accept.
    pub const EV_ACCEPT: u32 = 1;
    /// A connection has bytes to read, or the peer closed it (`OP_RECV` says which).
    pub const EV_READ: u32 = 2;
    /// A connection has room to send again after an `OP_SEND` took less than it was given.
    pub const EV_WRITE: u32 = 4;
    /// The connection is closed or reset: close the handle.
    pub const EV_CLOSED: u32 = 8;
    /// (Handle 0.) This instance is draining: finish the requests in flight, accept nothing new,
    /// close connections as they go idle, then say `OP_DONE`.
    pub const EV_DRAIN: u32 = 16;

    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Event {
        pub handle: u32,
        pub flags: u32,
    }

    /// A new connection: its handle, and the client's address and port.
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Accepted {
        pub handle: u32,
        pub addr: [u8; 4],
        pub port: u16,
        pub _pad: u16,
    }

    /// An `OP_BLOCK` entry: addresses matching `addr` in the top `prefix` bits, for `ticks`.
    #[repr(C)]
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Block {
        pub addr: [u8; 4],
        pub prefix: u32,
        pub ticks: u64,
    }

    /// Send a request whose reply is at most `reply.len()`; fails with the code or kernel error.
    fn call(net: u64, op: u64, msg: &[u8], reply: &mut [u8]) -> Result<usize, u64> {
        match send(net, op, msg, reply) {
            Ok((CODE_OK, n)) => Ok(n),
            Ok((code, _)) => Err(code),
            Err(e) => Err(e),
        }
    }

    pub fn listen(net: u64, port: u16) -> Result<u32, u64> {
        let mut h = [0u8; 4];
        call(net, OP_LISTEN, &port.to_le_bytes(), &mut h)?;
        Ok(u32::from_le_bytes(h))
    }

    /// Wait up to `ticks` (0: no limit) for events; returns how many were written to `out`.
    pub fn wait(net: u64, ticks: u64, out: &mut [Event]) -> Result<usize, u64> {
        let bytes = unsafe { core::slice::from_raw_parts_mut(out.as_mut_ptr() as *mut u8, core::mem::size_of_val(out)) };
        let n = call(net, OP_WAIT, &ticks.to_le_bytes(), bytes)?;
        Ok(n / core::mem::size_of::<Event>())
    }

    /// The next connection on `listener`, if one is waiting.
    pub fn accept(net: u64, listener: u32) -> Result<Option<Accepted>, u64> {
        let mut a = [0u8; core::mem::size_of::<Accepted>()];
        match call(net, OP_ACCEPT, &listener.to_le_bytes(), &mut a) {
            Ok(_) => Ok(Some(unsafe { core::ptr::read_unaligned(a.as_ptr() as *const Accepted) })),
            Err(CODE_WOULD_BLOCK) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Bytes received on `conn`: Ok(0) if none yet, `Err(CODE_CLOSED)` once the peer is done.
    pub fn recv(net: u64, conn: u32, buf: &mut [u8]) -> Result<usize, u64> {
        let mut msg = [0u8; 8];
        msg[..4].copy_from_slice(&conn.to_le_bytes());
        msg[4..].copy_from_slice(&(buf.len().min(4096) as u32).to_le_bytes());
        let max = buf.len().min(4096);
        match call(net, OP_RECV, &msg, &mut buf[..max]) {
            Err(CODE_WOULD_BLOCK) => Ok(0),
            r => r,
        }
    }

    /// Send up to 4092 bytes of `data` on `conn`; returns how many were taken.
    pub fn send_data(net: u64, conn: u32, data: &[u8]) -> Result<usize, u64> {
        let mut msg = [0u8; 4096];
        let n = data.len().min(msg.len() - 4);
        msg[..4].copy_from_slice(&conn.to_le_bytes());
        msg[4..4 + n].copy_from_slice(&data[..n]);
        let mut taken = [0u8; 4];
        call(net, OP_SEND, &msg[..4 + n], &mut taken)?;
        Ok(u32::from_le_bytes(taken) as usize)
    }

    pub fn close(net: u64, handle: u32) -> Result<(), u64> {
        call(net, OP_CLOSE, &handle.to_le_bytes(), &mut []).map(|_| ())
    }

    pub fn shutdown(net: u64, conn: u32) -> Result<(), u64> {
        call(net, OP_SHUTDOWN, &conn.to_le_bytes(), &mut []).map(|_| ())
    }

    pub fn ready(net: u64) -> Result<(), u64> {
        call(net, OP_READY, &[], &mut []).map(|_| ())
    }

    pub fn done(net: u64) -> Result<(), u64> {
        call(net, OP_DONE, &[], &mut []).map(|_| ())
    }

    pub fn route(net: u64, instance: u64) -> Result<(), u64> {
        call(net, OP_ROUTE, &instance.to_le_bytes(), &mut []).map(|_| ())
    }

    /// Drain `instance`, resetting what is left after `ticks`; returns how many were reset.
    pub fn drain(net: u64, instance: u64, ticks: u64) -> Result<u64, u64> {
        let mut msg = [0u8; 16];
        msg[..8].copy_from_slice(&instance.to_le_bytes());
        msg[8..].copy_from_slice(&ticks.to_le_bytes());
        let mut forced = [0u8; 8];
        call(net, OP_DRAIN, &msg, &mut forced)?;
        Ok(u64::from_le_bytes(forced))
    }

    /// Connect to `addr:port`; returns the connection handle.
    pub fn connect(net: u64, addr: [u8; 4], port: u16) -> Result<u32, u64> {
        let mut msg = [0u8; 6];
        msg[..4].copy_from_slice(&addr);
        msg[4..].copy_from_slice(&port.to_le_bytes());
        let mut h = [0u8; 4];
        call(net, OP_CONNECT, &msg, &mut h)?;
        Ok(u32::from_le_bytes(h))
    }

    /// An instance's status (`STATUS_*`) and how many of its connections a drain reset.
    pub fn status(net: u64, instance: u64) -> Result<(u64, u64), u64> {
        let mut out = [0u8; 16];
        call(net, OP_STATUS, &instance.to_le_bytes(), &mut out)?;
        Ok((u64::from_le_bytes(out[..8].try_into().unwrap()), u64::from_le_bytes(out[8..].try_into().unwrap())))
    }

    /// Start draining `instance` with a deadline in `ticks`, without waiting for it to end.
    pub fn drain_nowait(net: u64, instance: u64, ticks: u64) -> Result<(), u64> {
        let mut msg = [0u8; 24];
        msg[..8].copy_from_slice(&instance.to_le_bytes());
        msg[8..16].copy_from_slice(&ticks.to_le_bytes());
        msg[16..].copy_from_slice(&DRAIN_NOWAIT.to_le_bytes());
        call(net, OP_DRAIN, &msg, &mut []).map(|_| ())
    }

    pub fn block(net: u64, entry: &Block) -> Result<(), u64> {
        let bytes = unsafe { core::slice::from_raw_parts(entry as *const Block as *const u8, core::mem::size_of::<Block>()) };
        call(net, OP_BLOCK, bytes, &mut []).map(|_| ())
    }

    pub fn code_name(code: u64) -> &'static str {
        match code {
            CODE_OK => "OK",
            CODE_WOULD_BLOCK => "WOULD_BLOCK",
            CODE_BAD_OP => "BAD_OP",
            CODE_NOT_ALLOWED => "NOT_ALLOWED",
            CODE_BAD_HANDLE => "BAD_HANDLE",
            CODE_NO_SOCKETS => "NO_SOCKETS",
            CODE_CLOSED => "CLOSED",
            CODE_NOT_READY => "NOT_READY",
            _ => super::err::name(code),
        }
    }
}

/// A task's network declarations (`task_listen`): from the manifest, or for a slot from its
/// service's signed descriptor.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ListenInfo {
    service: [u8; 32],
    service_len: u64,
    /// Bit 0: may route (`routes = true`); bit 1: may connect out (`connects = true`); bit 2: is
    /// a generic slot (RFD 2).
    pub flags: u64,
    pub count: u64,
    /// (port, max_connections, max_per_source, 0)
    pub ports: [[u16; 4]; 8],
    /// The signed version running (0 for an empty slot).
    pub version: u64,
    /// Data blocks of its service's volume, from the signed descriptor (RFD 3); 0 for none.
    pub volume_blocks: u64,
}

impl ListenInfo {
    pub fn service(&self) -> &[u8] {
        &self.service[..(self.service_len as usize).min(32)]
    }

    pub fn may_route(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn may_connect(&self) -> bool {
        self.flags & 2 != 0
    }

    pub fn is_slot(&self) -> bool {
        self.flags & 4 != 0
    }

    /// The task with `loads = true`: the agent.
    pub fn may_load(&self) -> bool {
        self.flags & 8 != 0
    }

    /// (max_connections, max_per_source) if the task may listen on `port`.
    pub fn port(&self, port: u16) -> Option<(u16, u16)> {
        self.ports[..(self.count as usize).min(8)].iter().find(|p| p[0] == port).map(|p| (p[1], p[2]))
    }
}

/// The network declarations of task `id` (any generation): its service, ports and flags.
pub fn task_listen(id: u64) -> Result<ListenInfo, u64> {
    let mut info = ListenInfo::default();
    let size = core::mem::size_of::<ListenInfo>() as u64;
    let (n, _, _) = syscall6(SYS_TASK_LISTEN, [id, &mut info as *mut ListenInfo as u64, size, 0, 0, 0]);
    if err::is_error(n) { Err(n) } else { Ok(info) }
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

/// Loading service images into generic slots (RFD 2), for the task with `loads = true`.
pub mod slot {
    use super::{SYS_SLOT_LOAD, SYS_SLOT_STAGE, SYS_SLOT_UNLOAD, err, syscall6};

    /// Copy part of an image into empty slot `slot`'s image area, at `offset`.
    pub fn stage(slot: u64, offset: u64, bytes: &[u8]) -> Result<(), u64> {
        let (status, _, _) = syscall6(SYS_SLOT_STAGE, [slot, offset, bytes.as_ptr() as u64, bytes.len() as u64, 0, 0]);
        if status == 0 { Ok(()) } else { Err(status) }
    }

    /// Stage a whole image in 64 KiB pieces.
    pub fn stage_all(slot: u64, image: &[u8]) -> Result<(), u64> {
        for (i, chunk) in image.chunks(64 * 1024).enumerate() {
            stage(slot, (i * 64 * 1024) as u64, chunk)?;
        }
        Ok(())
    }

    /// Check and start the staged image with its signature file and descriptor. Returns the
    /// slot's new id, or `Err((err::REJECTED, reason))`, `Err((err::BUSY, 0))`, ...
    pub fn load(slot: u64, sig: &[u8], descriptor: &[u8]) -> Result<u64, (u64, u64)> {
        let args = [slot, sig.as_ptr() as u64, sig.len() as u64, descriptor.as_ptr() as u64, descriptor.len() as u64, 0];
        let (id, reason, _) = syscall6(SYS_SLOT_LOAD, args);
        if err::is_error(id) { Err((id, reason)) } else { Ok(id) }
    }

    /// Empty a slot whose service has ended.
    pub fn unload(slot: u64) -> Result<(), u64> {
        let (status, _, _) = syscall6(SYS_SLOT_UNLOAD, [slot, 0, 0, 0, 0, 0]);
        if status == 0 { Ok(()) } else { Err(status) }
    }
}

/// For the task with `tpm = true`: hold the TPM around commands, so the kernel never extends a
/// PCR in the middle of one.
pub fn tpm_lock() -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_TPM_LOCK, [0; 6]);
    if status == 0 { Ok(()) } else { Err(status) }
}

pub fn tpm_unlock() -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_TPM_UNLOCK, [0; 6]);
    if status == 0 { Ok(()) } else { Err(status) }
}

/// Bytes per run-time log entry: operation (1 load, 2 unload), slot index, 6 zero bytes,
/// service name (32), version (8), SHA-256 of the signed statement (32).
pub const RUNTIME_ENTRY_LEN: usize = 80;

/// For the task with `tpm = true`: run-time log entries from `start` into `buf`. Returns
/// (entries copied, entries in the log).
pub fn runtime_log(buf: &mut [u8], start: usize) -> Result<(usize, usize), u64> {
    let (count, total, _) = syscall6(SYS_RUNTIME_LOG, [buf.as_mut_ptr() as u64, buf.len() as u64, start as u64, 0, 0, 0]);
    if err::is_error(count) { Err(count) } else { Ok((count as usize, total as usize)) }
}
