//! Runtime shared by every vanir-os user program: the `_start` entry stub, syscall wrappers,
//! `print!`/`println!`, and a panic handler.
//!
//! A program provides its entry with `vanir_user::entry!(main)`, where `main() -> u64` returns the
//! exit code.

#![no_std]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;

// The ABI, defined once for the kernel and user code (RFD 9, P1); re-exported under the paths
// programs have always used.
pub use vanir_abi::err;
pub use vanir_abi::ipc::{NOTIFY_DEATH, NOTIFY_IRQ, NOTIFY_POST, NOTIFY_TIMER, RECV_EXPECT_IRQ, RECV_TIMEOUT};
pub use vanir_abi::layout::{BAR_STRIDE, DEVICE_BASE, DEVICE_STRIDE};
pub use vanir_abi::listen::ListenInfo;
pub use vanir_abi::sys::*;
pub use vanir_abi::task::{DeathRecord, MAX_TASKS, RUNTIME_ENTRY_LEN};

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

/// Wait for a message, written to the start of `buf`.
pub fn recv(buf: &mut [u8]) -> Result<Message, u64> {
    recv_flags(buf, 0)
}

/// `recv` with flags (`RECV_EXPECT_IRQ`).
pub fn recv_flags(buf: &mut [u8], flags: u64) -> Result<Message, u64> {
    recv_raw(buf, flags, 0)
}

/// Post `bits` to task `target` (which must be in our `sends`, or have us in its own) without
/// waiting: it gets them in its next `recv` as op `NOTIFY_POST`. Fails like `send` (DEAD,
/// NOT_ALLOWED, ...).
pub fn notify(target: u64, bits: u64) -> Result<(), u64> {
    let (status, _, _) = syscall6(SYS_NOTIFY, [target, bits, 0, 0, 0, 0]);
    if status == 0 { Ok(()) } else { Err(status) }
}

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
    pub use vanir_abi::proto::supervisor::*;

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
    pub use vanir_abi::proto::block::*;

    pub fn unlock(storage: u64, master_key: &[u8; 32]) -> Result<(), u64> {
        call(storage, OP_UNLOCK, master_key, &mut []).map(|_| ())
    }

    pub fn epoch(storage: u64, epoch: u64, lease_until: u64, writer: u64) -> Result<(), u64> {
        let mut msg = [0u8; 24];
        msg[..8].copy_from_slice(&epoch.to_le_bytes());
        msg[8..16].copy_from_slice(&lease_until.to_le_bytes());
        msg[16..].copy_from_slice(&writer.to_le_bytes());
        call(storage, OP_EPOCH, &msg, &mut []).map(|_| ())
    }

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

    pub fn handoff(storage: u64, service: &[u8], candidate: u64) -> Result<(), u64> {
        let mut msg = [0u8; 40];
        msg[..32].copy_from_slice(&service_name(service));
        msg[32..].copy_from_slice(&candidate.to_le_bytes());
        call(storage, OP_HANDOFF, &msg, &mut []).map(|_| ())
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
}

/// The NIC driver's IPC interface (`user/virtio-net`): Ethernet frames in and out. The driver
/// knows nothing about IP; its one client is the network stack task.
pub mod nic {
    pub use vanir_abi::proto::nic::*;

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
    pub use vanir_abi::proto::console::*;

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

    pub use vanir_abi::events::*;

    /// Events since the last read, oldest first: (how many were written to `out`, how many
    /// were lost because the kernel's ring wrapped first).
    pub fn read(out: &mut [Event]) -> Result<(usize, u64), u64> {
        let bytes = core::mem::size_of_val(out) as u64;
        let (count, dropped, _) = syscall6(SYS_READ_EVENTS, [out.as_mut_ptr() as u64, bytes, 0, 0, 0, 0]);
        if err::is_error(count) { Err(count) } else { Ok((count as usize, dropped)) }
    }

    pub fn stats() -> Result<Stats, u64> {
        let mut s = Stats::ZERO;
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
    pub use vanir_abi::proto::attest::*;
}

/// The key server (the task named "keys", `user/unlocker`): a stand-in for a local key store.
pub mod keys {
    pub use vanir_abi::proto::keys::*;
}

/// Client side of the telemetry task (`user/telemetry`).
pub mod telemetry {
    use super::send;
    pub use vanir_abi::proto::telemetry::*;

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
    pub use vanir_abi::proto::net::*;

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

/// For the task with `tpm = true`: run-time log entries from `start` into `buf`. Returns
/// (entries copied, entries in the log).
pub fn runtime_log(buf: &mut [u8], start: usize) -> Result<(usize, usize), u64> {
    let (count, total, _) = syscall6(SYS_RUNTIME_LOG, [buf.as_mut_ptr() as u64, buf.len() as u64, start as u64, 0, 0, 0]);
    if err::is_error(count) { Err(count) } else { Ok((count as usize, total as usize)) }
}
