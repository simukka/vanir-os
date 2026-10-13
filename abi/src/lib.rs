//! What the kernel and user programs must agree on, defined once (RFD 9, P1): syscall numbers,
//! error codes, notifications and flags, task states, the address layout tasks see, and the
//! records the kernel writes into a task's memory. The kernel and `vanir_user` both use these
//! definitions, so a change on one side is a change on the other.
//!
//! Data only: constants, `#[repr(C)]` records with public fields, and small safe functions that
//! read them (accessors, names of codes). No syscalls, no `unsafe`, no state, no dependencies.
//! `tests/snapshot.rs` pins every value and every record's layout; change one only on purpose.
//!
//! **Records are read by size** (RFD 9, P2). A syscall that writes a record (`stats`,
//! `task_listen`, the supervisor's death notice) copies as much of it as fits in the caller's
//! buffer and returns the record's whole size. So a record may grow, **at its end only**: a
//! program built against the smaller record gets the fields it knows, and one built against the
//! larger record, on an older kernel, finds the new fields zero (callers zero their buffer
//! first). Records read as arrays (`events::Event`, the measurement and run-time log entries)
//! can't grow, since their size is the array's stride; growing one needs a new syscall.

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
        /// The record in a `NOTIFY_DEATH` message, read by size: the fields the message holds,
        /// the rest zero (a kernel older than this record). None if it doesn't hold the id and
        /// kind.
        pub fn from_bytes(bytes: &[u8]) -> Option<DeathRecord> {
            if bytes.len() < 16 {
                return None;
            }
            let f = |i: usize| match bytes.get(i * 8..i * 8 + 8) {
                Some(b) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                None => 0,
            };
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

/// The IPC protocols between tasks: op and code numbers, notify bits and records, for the
/// servers (`storage`, `net`, the drivers, ...) and their clients. The kernel doesn't read
/// these; it carries the messages. Clients' functions are in `vanir_user`.
pub mod proto {
    /// Requests to the supervisor (from the agent, RFD 2, P4). Message: a task id (u64). Reply
    /// code 0 and the new id (u64) on success; otherwise 0x100 | the kernel error's low bits.
    pub mod supervisor {
        /// Stop the task: it is reported as stopped and not restarted.
        pub const OP_STOP: u64 = 1;
        /// Start a dead task again (e.g. a stopped slot, for a rollback), with its backoff reset.
        pub const OP_START: u64 = 2;
        /// Reboot the node into the image installed now (message: anything). Only answered if it
        /// fails.
        pub const OP_REBOOT: u64 = 3;
    }

    /// Block-device IPC interface, served by the virtio-blk driver and (per volume) by the storage
    /// task. Blocks are 4 KiB; the block number rides in `op` above the operation code, so a write
    /// message is exactly one block.
    pub mod block {
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

        /// Storage task (RFD 3, P1): message is epoch, lease_until and the writer's task id (u64s,
        /// little endian). Makes that instance the writer of its service's volume at that epoch,
        /// creating the volume if needed. Only the task with `loads = true` may send it. An epoch
        /// above the recorded one is recorded and flushed before the reply; the recorded epoch again
        /// is accepted while there is no writer or the writer's slot is unchanged; anything else
        /// gets CODE_FENCED.
        pub const OP_EPOCH: u64 = 6;

        /// Storage task (RFD 3, P2): message is a service name (32 bytes, zero padded) and that
        /// service's 32-byte key. Only "keys" and "attest" may send it. A service's volume answers
        /// CODE_LOCKED until its key is here (a storage task that may send to "keys" asks it too).
        /// The key it already has again is a no-op.
        pub const OP_SERVICE_KEY: u64 = 7;
        /// Storage task (RFD 3, P2): message is a service name (32 bytes, zero padded). Forget that
        /// service's key, once no instance of it is left on the node. Only the task with
        /// `loads = true` may send it.
        pub const OP_FORGET_KEY: u64 = 8;

        /// Storage task (RFD 3, P3): message is a service name (32 bytes, zero padded) and the
        /// candidate's task id (u64, little endian), or 0. From now until the candidate holds the
        /// service volume's epoch, its reads, writes and flushes are held and answered once it does.
        /// 0, or another candidate, calls the handoff off: what was held is answered at once, as if
        /// it had just arrived. Only the task with `loads = true` may send it.
        pub const OP_HANDOFF: u64 = 9;

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
        /// Source, at a move's handoff: the volume becomes read-only (no writer; writes get
        /// CODE_FENCED, and the same epoch can't be asserted again) and is flushed. Only a higher
        /// epoch (`OP_EPOCH`) makes it writable again.
        pub const OP_HAND_OVER: u64 = 20;
        /// SHA-256 over the volume's header (96 bytes) and every metadata block: it identifies the
        /// volume's exact state without decrypting it (RFD 3, P1's volume digest).
        pub const OP_DIGEST: u64 = 21;
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
                _ => crate::err::name(code),
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
    }

    /// Client side of the console driver's IPC interface (`user/virtio-console`).
    pub mod console {
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
    }

    /// Client side of the network stack task (`user/net`): TCP on the ports the caller's manifest
    /// entry declares (`listen`). Handles name listeners and connections; each carries a generation
    /// number, so a handle kept after its connection closed can't name a newer one. Calls never
    /// wait, except `OP_WAIT`, which returns when any of the caller's handles has something to do.
    pub mod net {
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
                _ => crate::err::name(code),
            }
        }
    }
}

// The records' sizes, checked on every target that builds this crate (the kernel's and the
// tasks'); `tests/snapshot.rs` checks every field's offset on the host.
const _: () = {
    use core::mem::size_of;
    assert!(size_of::<task::DeathRecord>() == 56);
    assert!(size_of::<events::Event>() == 56);
    assert!(size_of::<events::Stats>() == 1584);
    assert!(size_of::<listen::ListenInfo>() == 136);
    assert!(size_of::<proto::nic::Info>() == 72);
    assert!(size_of::<proto::net::Event>() == 8);
    assert!(size_of::<proto::net::Accepted>() == 12);
    assert!(size_of::<proto::net::Block>() == 16);
};
