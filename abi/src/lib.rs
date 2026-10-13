//! What the kernel and user programs must agree on, defined once (RFD 9, P1): syscall numbers,
//! error codes, notifications and flags, task states, the address layout tasks see, and the
//! records the kernel writes into a task's memory. The kernel and `vanir_user` both use these
//! definitions, so a change on one side is a change on the other.
//!
//! Data only: constants, `#[repr(C)]` records with public fields, and small safe functions that
//! read them (accessors, names of codes). No syscalls, no `unsafe`, no state, no dependencies.
//! `tests/snapshot.rs` pins every value and every record's layout; change one only on purpose.

#![no_std]
#![forbid(unsafe_code)]

/// `int 0x80` system calls: rax = number; arguments in rdi, rsi, rdx, r10, r8, r9; results in
/// rax (then rdx, rsi). Simple calls return `ERROR` when they fail; IPC calls return `err` codes.
pub mod sys {
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

    /// Returned by the kernel when a simple syscall (write, getpid, ...) fails.
    pub const ERROR: u64 = u64::MAX;

    /// Timer ticks (10 ms each) per second: `uptime`, `sleep` and `recv` timeouts count ticks.
    pub const TICK_HZ: u64 = 100;
}

/// Errors from the IPC syscalls. The top bit is set, so they never collide with a server's
/// reply codes (which must have it clear).
pub mod err {
    pub const DEAD: u64 = 1 << 63;
    pub const NOT_ALLOWED: u64 = DEAD | 1;
    pub const BAD_TARGET: u64 = DEAD | 2;
    pub const BAD_BUFFER: u64 = DEAD | 3;
    pub const TOO_LONG: u64 = DEAD | 4;
    pub const BAD_ARGUMENT: u64 = DEAD | 5;
    /// The TPM is in use (the attestation task holds its lock); try again.
    pub const BUSY: u64 = DEAD | 6;
    /// The run-time measurement log is full: no more loads until the node reboots.
    pub const LOG_FULL: u64 = DEAD | 7;
    /// The image was refused; rdx holds the reason (`events::REJECT_*`, `events::rejection`).
    pub const REJECTED: u64 = DEAD | 8;

    pub const fn is_error(code: u64) -> bool {
        code & DEAD != 0
    }

    pub const fn name(code: u64) -> &'static str {
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

/// Messages, notifications and `recv` flags.
pub mod ipc {
    /// Largest message or reply, in bytes; bounds the time one syscall spends copying.
    pub const MAX_MESSAGE: u64 = 4096;

    /// Kernel notification (sender 0) op: a task died; the message is a `task::DeathRecord`.
    /// Only the supervisor gets it.
    pub const NOTIFY_DEATH: u64 = 1;
    /// Kernel notification (sender 0) op: device interrupts; the length register holds the
    /// pending bits (one per granted device, in manifest order).
    pub const NOTIFY_IRQ: u64 = 2;
    /// Kernel notification (sender 0) op: the timeout given with `RECV_TIMEOUT` expired.
    pub const NOTIFY_TIMER: u64 = 3;
    /// Kernel notification (sender 0) op: bits other tasks posted with `notify`; the length
    /// register holds them.
    pub const NOTIFY_POST: u64 = 4;

    /// `recv` flag (in rdx): this task has device work in flight and an interrupt will come, so
    /// the kernel should idle for it rather than conclude that nothing can ever run again.
    pub const RECV_EXPECT_IRQ: u64 = 1;
    /// `recv` flag (in rdx): give up after r10 ticks with a `NOTIFY_TIMER` notification.
    pub const RECV_TIMEOUT: u64 = 2;
}

/// Tasks: how many, their states, how they end, and the logs the kernel keeps about them.
pub mod task {
    /// The most tasks (fixed tasks and slots) a manifest may declare; per-task tables (e.g.
    /// `events::Stats`) have this many rows.
    pub const MAX_TASKS: usize = 64;

    /// Task states, as `task_state` and `events::Stats` give them.
    pub const STATE_RUNNING: u64 = 0;
    /// Blocked in IPC, or sleeping.
    pub const STATE_BLOCKED: u64 = 1;
    pub const STATE_EXITED: u64 = 2;
    pub const STATE_FAULTED: u64 = 3;
    pub const STATE_OVER_BUDGET: u64 = 4;
    /// Its image failed the signature checks at boot.
    pub const STATE_REJECTED: u64 = 5;
    /// A generic slot with no image loaded.
    pub const STATE_EMPTY: u64 = 6;
    /// Stopped by the supervisor.
    pub const STATE_STOPPED: u64 = 7;

    /// `DeathRecord::kind`.
    pub const DEATH_EXITED: u64 = 1;
    pub const DEATH_FAULTED: u64 = 2;
    pub const DEATH_OVER_BUDGET: u64 = 3;
    /// The image was rejected at boot; `code` is the reason (`events::REJECT_*`).
    pub const DEATH_REJECTED: u64 = 4;
    /// Stopped by the supervisor (`stop`).
    pub const DEATH_STOPPED: u64 = 5;

    /// How a task ended, as the kernel reports it to the supervisor (`ipc::NOTIFY_DEATH`).
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    pub struct DeathRecord {
        pub id: u64,
        /// `DEATH_*`.
        pub kind: u64,
        /// Exit code, the fault's vector, or the rejection reason.
        pub code: u64,
        pub rip: u64,
        pub cr2: u64,
        pub error_code: u64,
        pub ticks: u64,
    }

    impl DeathRecord {
        /// The record in a `NOTIFY_DEATH` message, if it is one.
        pub fn from_bytes(bytes: &[u8]) -> Option<DeathRecord> {
            if bytes.len() != core::mem::size_of::<DeathRecord>() {
                return None;
            }
            let f = |i: usize| u64::from_le_bytes([
                bytes[i * 8],
                bytes[i * 8 + 1],
                bytes[i * 8 + 2],
                bytes[i * 8 + 3],
                bytes[i * 8 + 4],
                bytes[i * 8 + 5],
                bytes[i * 8 + 6],
                bytes[i * 8 + 7],
            ]);
            Some(DeathRecord { id: f(0), kind: f(1), code: f(2), rip: f(3), cr2: f(4), error_code: f(5), ticks: f(6) })
        }
    }

    /// Bytes per boot measurement log entry (`measurements`): 16-byte zero-padded name, 32-byte
    /// SHA-256.
    pub const MEASUREMENT_ENTRY_LEN: usize = 48;
    /// Bytes per run-time log entry (`runtime_log`): operation (1 load, 2 unload), slot index, 6
    /// zero bytes, service name (32), version (8), SHA-256 of the signed statement (32).
    pub const RUNTIME_ENTRY_LEN: usize = 80;
}

/// Where the kernel maps things into a task's address space.
pub mod layout {
    /// Granted devices' BARs: device `d`'s BAR `b` is at
    /// `DEVICE_BASE + d * DEVICE_STRIDE + b * BAR_STRIDE` (see `device_bar`).
    pub const DEVICE_BASE: u64 = 0x10_0000_0000;
    pub const DEVICE_STRIDE: u64 = 0x1000_0000;
    pub const BAR_STRIDE: u64 = 0x200_0000;
    /// The task's DMA region (see `dma_info`).
    pub const DMA_BASE: u64 = 0x20_0000_0000;
    /// The TPM's CRB page, in the task granted `tpm = true`.
    pub const TPM_BASE: u64 = 0x30_0000_0000;
}

/// The kernel event log and statistics, for the task with `events = true`.
pub mod events {
    use crate::task::MAX_TASKS;

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

    /// One event. Fields `a`, `b`, `c` depend on `kind`: TASK_START a = signed version; EXIT
    /// a = code; FAULT a = vector, b = rip, c = cr2; OVER_BUDGET a = budget; RESTART a = previous
    /// id; IPC_REFUSED a = target, b = error; IMAGE_REJECTED a = reason (`REJECT_*`);
    /// IMAGE_LOADED, IMAGE_UNLOADED a = version.
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

    /// What `stats` writes.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct Stats {
        pub uptime_ticks: u64,
        pub frames_in_use: u64,
        pub device_interrupts: u64,
        pub events_logged: u64,
        pub tasks: u64,
        /// Frames that can still be allocated.
        pub frames_available: u64,
        /// Per task slot: id, state (`task::STATE_*`), CPU ticks.
        pub task: [[u64; 3]; MAX_TASKS],
    }

    impl Stats {
        pub const ZERO: Stats = Stats {
            uptime_ticks: 0,
            frames_in_use: 0,
            device_interrupts: 0,
            events_logged: 0,
            tasks: 0,
            frames_available: 0,
            task: [[0; 3]; MAX_TASKS],
        };
    }

    /// Why the kernel refused a task image: `IMAGE_REJECTED`'s `a`, a death record's `code`,
    /// `slot_load`'s rdx with `err::REJECTED`.
    pub const REJECT_NO_IMAGE: u64 = 1;
    pub const REJECT_NO_SIGNATURE: u64 = 2;
    pub const REJECT_MALFORMED: u64 = 3;
    pub const REJECT_BAD_SIGNATURE: u64 = 4;
    pub const REJECT_WRONG_PROGRAM: u64 = 5;
    pub const REJECT_WRONG_HASH: u64 = 6;
    pub const REJECT_TOO_OLD: u64 = 7;
    /// Run-time loads (`slot_load`) only, from here on.
    pub const REJECT_BAD_DESCRIPTOR: u64 = 8;
    pub const REJECT_WRONG_DESCRIPTOR: u64 = 9;
    pub const REJECT_CLASS_MISMATCH: u64 = 10;
    pub const REJECT_TOO_LARGE: u64 = 11;
    pub const REJECT_BAD_ELF: u64 = 12;
    pub const REJECT_BELOW_FLOOR: u64 = 13;

    pub const fn rejection(reason: u64) -> &'static str {
        match reason {
            REJECT_NO_IMAGE => "no image",
            REJECT_NO_SIGNATURE => "no signature",
            REJECT_MALFORMED => "malformed signature file",
            REJECT_BAD_SIGNATURE => "signature does not verify",
            REJECT_WRONG_PROGRAM => "signed for another program",
            REJECT_WRONG_HASH => "image does not match its signature",
            REJECT_TOO_OLD => "version older than the manifest allows",
            REJECT_BAD_DESCRIPTOR => "malformed descriptor",
            REJECT_WRONG_DESCRIPTOR => "descriptor does not match its signature",
            REJECT_CLASS_MISMATCH => "descriptor asks for another slot class",
            REJECT_TOO_LARGE => "image needs more memory than its slot class has",
            REJECT_BAD_ELF => "not a loadable ELF image",
            REJECT_BELOW_FLOOR => "version below its min_version",
            _ => "unknown",
        }
    }
}

/// A task's network declarations (`task_listen`): from the manifest, or for a slot from its
/// service's signed descriptor.
pub mod listen {
    /// `ListenInfo::flags`: may route (`routes = true`).
    pub const ROUTES: u64 = 1;
    /// May connect out (`connects = true`).
    pub const CONNECTS: u64 = 2;
    /// A generic slot (RFD 2).
    pub const SLOT: u64 = 4;
    /// May load slots (`loads = true`): the agent.
    pub const LOADS: u64 = 8;
    /// Most ports one task may declare.
    pub const MAX_PORTS: usize = 8;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ListenInfo {
        /// The service's name, zero padded; `service()` gives the used part.
        pub service: [u8; 32],
        pub service_len: u64,
        /// `ROUTES`, `CONNECTS`, `SLOT`, `LOADS`.
        pub flags: u64,
        pub count: u64,
        /// (port, max_connections, max_per_source, 0); the first `count` are in use.
        pub ports: [[u16; 4]; MAX_PORTS],
        /// The signed version running (0 for an empty slot).
        pub version: u64,
        /// Data blocks of its service's volume, from the signed descriptor (RFD 3); 0 for none.
        pub volume_blocks: u64,
    }

    impl ListenInfo {
        pub fn service(&self) -> &[u8] {
            &self.service[..(self.service_len as usize).min(32)]
        }

        pub const fn may_route(&self) -> bool {
            self.flags & ROUTES != 0
        }

        pub const fn may_connect(&self) -> bool {
            self.flags & CONNECTS != 0
        }

        pub const fn is_slot(&self) -> bool {
            self.flags & SLOT != 0
        }

        /// The task with `loads = true`: the agent.
        pub const fn may_load(&self) -> bool {
            self.flags & LOADS != 0
        }

        /// (max_connections, max_per_source) if the task may listen on `port`.
        pub fn port(&self, port: u16) -> Option<(u16, u16)> {
            self.ports[..(self.count as usize).min(MAX_PORTS)].iter().find(|p| p[0] == port).map(|p| (p[1], p[2]))
        }
    }
}
