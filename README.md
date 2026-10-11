# vanir-os

> **Full manual:** [`docs/index.html`](docs/index.html) (serve it with GitHub Pages from `/docs`).
> It covers the same ground with diagrams, a from-scratch guide to each layer, and a section
> for coding agents; [`docs/llms.txt`](docs/llms.txt) is the agent index.

A minimal x86-64 kernel in Rust, booted by [Limine](https://github.com/limine-bootloader/limine), that runs
isolated ring-3 processes. It provides serial output, GDT/TSS, IDT, an ELF loader, a page-table tree
per process, a 100 Hz local APIC timer with round-robin preemption, synchronous IPC between
processes, a supervisor task that restarts failed ones, unprivileged device-driver tasks (virtio
console, vsock and block), telemetry streamed to a host agent, signed task images, a Secure Boot
chain, measured boot, TPM remote attestation, and encrypted per-task storage whose key the host
releases only to an attested boot.

## Processes

- **Static task table.** The processes are fixed at build time (no `fork`/`exec`) by an app
  manifest: `make run APP=tests/apps/two-spinners.toml`. It sets each task's CPU budget, which
  tasks it may send messages to, and which task is the supervisor. See
  [apps/README.md](apps/README.md) for the format.
- **One kernel stack.** A trap saves the user's registers on it; a context switch stores that
  frame in the current process, copies the next process's saved frame over it, switches `CR3`,
  and returns through the normal `iretq`. Kernel code never waits mid-syscall: a process that
  must wait is marked blocked with its registers saved, and whoever completes the operation
  writes the results into those saved registers.
- **Outcomes.** A process ends by `exit`, by faulting, or by using up its CPU budget; the others
  keep running. When nothing can run the kernel prints a summary and halts. Tasks waiting in
  `recv` count as idle servers; tasks stuck in `send` mean a deadlock.

## IPC

Synchronous send/receive/reply, as in [Hubris](https://hubris.oxide.computer/): a client's `send`
waits until the server has received the message and replied. Messages and replies are copied
between address spaces by the kernel, up to 4 KiB each. A task may only send to the tasks listed
in its manifest `sends`.

Task ids carry a generation that changes when a task is restarted, so a client holding an id
from before a restart gets `DEAD` instead of silently reaching a fresh server that lost its state.

| Error (top bit set) | Meaning |
|---|---|
| `DEAD` | the target has died, or was restarted since the id was obtained |
| `NOT_ALLOWED` | the target is not in the sender's `sends` (or: supervisor-only call) |
| `BAD_TARGET` | no such task, or sending to yourself |
| `BAD_BUFFER` | a buffer is unmapped, read-only where it must be written, or not in user memory |
| `TOO_LONG` | a message or reply is over 4 KiB or bigger than the receiving buffer |
| `BAD_ARGUMENT` | a reply code with the top bit set; restart of a live or already-restarted task |

## Supervisor

The manifest may mark one task `supervisor = true` (see `user/supervisor`). The kernel reports
every other task's death to it as a message from sender 0 carrying a death record (how it ended,
exit code or fault vector, `rip`, `cr2`, error code, ticks used). The supervisor decides what to
do and may call `restart(id)`, which reloads the task's ELF into fresh memory with a new
generation. The policy lives in the supervisor, not the kernel. If the supervisor itself dies, the
kernel halts.

## Drivers

Device drivers are ordinary tasks. The kernel discovers PCI devices at boot and a manifest grants
one to a task (`devices = ["virtio-console"]`). The driver gets:

- the device's register BARs mapped into its address space (uncached), except the BAR holding the
  MSI-X table: the kernel programs interrupt routing itself;
- read-only access to the device's PCI configuration space;
- a physically contiguous DMA region (`dma_pages`), the same physical pages for the life of the
  task slot and zeroed on every restart;
- the device's interrupts as notifications in `recv` (sender 0, `NOTIFY_IRQ`). A driver with work
  in flight passes `RECV_EXPECT_IRQ` so the kernel idles for it instead of ending the run.

A crashing driver is restarted by the supervisor like any task; it resets the device and carries
on, and its clients see `DEAD` and retry against the new id (`console-restart`).

**Limit:** there is no IOMMU yet. A driver programs its device with physical addresses, so a
malicious driver could make the device read or write any memory, kernel included. Driver tasks are
isolated from mistakes (bad pointers, crashes, runaway loops), not from malice. QEMU can emulate
Intel VT-d (`-device intel-iommu`) to close this later.

## Telemetry

The kernel logs events at its control points into a 128-entry ring: task start, exit, fault
(vector, `rip`, `cr2`), CPU-budget kill, restart, refused IPC sends. The task with `events = true`
(`user/telemetry`) forwards them as newline-delimited JSON through the uplink driver, with a
heartbeat every second, any `log` lines other tasks send it (the supervisor reports its
decisions) and storage events (see Storage):

```json
{"seq":5,"t":1,"task":"crasher","id":"2","event":"fault","vector":14,"rip":"0x400182","cr2":"0x10"}
{"seq":6,"t":2,"task":"crasher","id":"2.1","event":"restart","previous":"2"}
{"t":3,"event":"log","from":"supervisor","msg":"giving up on task 2 after 3 restarts"}
{"t":5,"event":"dropped","count":37}
{"t":102,"event":"heartbeat","n":1,"frames":89,"irqs":3,"events":11,"tasks":[{"task":"supervisor","id":"1","state":"blocked","ticks":2}]}
```

`t` is in 10 ms ticks since boot; ids are `slot` or `slot.generation`. Kernel events carry `seq`;
if the ring wraps before telemetry reads it, a `dropped` record says how many were lost.

The uplink is the virtio console by default (QEMU writes it to `build/telemetry.log`), or vsock
with `TRANSPORT=vsock` and a manifest whose `uplink` task runs `virtio-vsock`. `tools/host-agent.py`
reads either, checks it (valid JSON, sequence gaps all covered by `dropped`, heartbeat spacing) and
summarises it:

```sh
tools/host-agent.py build/telemetry.log                         # console uplink
tools/host-agent.py --listen-vsock 5000 &                       # vsock uplink: listen first,
make run TRANSPORT=vsock ACCEL=kvm APP=tests/apps/telemetry-vsock.toml   # then boot
```

vsock needs `/dev/vhost-vsock` (the `kvm` group) and KVM.

## Boot chain and attestation

With `BOOT=uefi-secure` every link checks the next before running it:

| Link | Checks | How | Refuses (test) |
|---|---|---|---|
| UEFI firmware (OVMF, Secure Boot on) | the boot loader | `BOOTX64.EFI` signed with `sbsign` | `sb-unsigned-loader` |
| Limine | its config | config hash embedded with `limine enroll-config` | `sb-edited-config` |
| Limine | the kernel | BLAKE2b hash pinned in `limine.conf` | `sb-tampered-kernel` |
| Kernel | every task image | Ed25519 signature (`tools/sign-image.py`), key compiled in | `sig-*` |

Task images ship as boot modules beside the kernel, each with a `.sig`: program name, version and
SHA-256 of the ELF, signed. The kernel refuses an image that is unsigned, changed, signed for
another program, signed by another key, or older than the manifest's `min_version`. A refused task
never runs; the supervisor and telemetry are told why. Images can be updated without rebuilding
the kernel, as long as they are signed.

**Measured boot** (`TPM=1`, a software TPM): the firmware measures the boot loader and the Secure
Boot state into PCRs 0-7. Before any task runs, the kernel extends **PCR 12** with SHA-256 of the
kernel file, of the app manifest, and of each task's signed statement (zeros for a refused image).
`tools/expected-pcrs.py` computes PCR 12 from the build output alone.

**Attestation**: the `attest` task (manifest `tpm = true`) holds an attestation key in the TPM.
When the host sends `attest <nonce>` over the vsock uplink, `control` asks `attest`, which returns
a TPM quote of PCRs 0, 4, 7 and 12 over that nonce. `tools/verify-quote.py` checks it is genuine
TPM output, over this nonce, correctly signed, consistent with the reported PCRs and the kernel's
measurement log, and equal to an approved reference:

```sh
make image BOOT=uefi-secure APP=tests/apps/attest.toml USER_FEATURES=control/one-shot
tools/host-agent.py --listen-vsock 5000 --save build/telemetry.log --attest &
make run BOOT=uefi-secure ACCEL=kvm TPM=1 TRANSPORT=vsock APP=tests/apps/attest.toml USER_FEATURES=control/one-shot
tools/verify-quote.py --record build/attest-reference.json \
    --expected-pcr12 $(tools/expected-pcrs.py --app tests/apps/attest.toml)      # known-good boot
tools/verify-quote.py --reference build/attest-reference.json                     # later boots
```

**What this does not prove yet:**

- **Development keys.** Secure Boot uses Debian's snakeoil keys, whose private key is public, and
  the image key is a local dev key in `keys/`. Production needs your own keys, kept offline.
- **Trust on first use.** The attestation key is not yet tied to the TPM's endorsement
  certificate (TPM2 credential activation), so the verifier trusts the key recorded with the
  reference.
- **Recorded firmware values.** PCRs 0, 4 and 7 are compared with a recorded known-good boot,
  not computed independently; only PCR 12 is.
- **No IOMMU.** A signed but malicious driver can still use its device's DMA to subvert the system
  after measurement. Signing narrows who can run such code; it does not make drivers safe.

## Storage

`DISK=1` attaches `build/disk.img` (64 MiB, kept between runs) as a virtio block device. Three
tasks share the work, named by convention so they can find each other:

| Task | Program | Role |
|---|---|---|
| `blockdev` | `virtio-blk` | the driver: reads and writes raw 4 KiB blocks. Only `disk` may send to it. |
| `disk` | `storage` | the storage task: gives every client its own encrypted volume |
| `keys` or `attest` | `unlocker`, `attest` | hands `disk` the master key |

Clients send `disk` block requests (`vanir_user::block`: read, write, flush, info) with block
numbers relative to their volume. There is no file system: a volume is 256 numbered 4 KiB blocks
(1 MiB). The volume is chosen by the client's manifest name, which the storage task gets from the
kernel (`task_name` of the sender), so a client can neither name nor reach another task's volume;
blocks past the end are refused. A task's first request creates its volume.

**On disk** (all 4 KiB blocks):

```
block 0     superblock: "VNRSTOR2", next free block                  plain text
block 1     volume table: 64 entries of name[32], start, size        plain text
then per volume (258 blocks, in creation order):
  2 metadata blocks   per data block: write counter (u64) and tag (16 bytes)
  256 data blocks     XChaCha20-Poly1305 ciphertext, same size as the plain text
```

A disk without the magic is formatted on first use. Block `b` of a volume is encrypted with the
volume key, nonce = `b` ‖ counter, and associated data = volume name ‖ `b` ‖ counter; the counter
goes up on every write, so a nonce is never reused. Ciphertext that was changed, moved to another
block or volume, or paired with another counter fails to decrypt: the client gets `INTEGRITY` and
telemetry an `integrity_error`. A block never written (counter 0) reads as zeros.

**Keys.** One 32-byte master key; each volume's key is HKDF-SHA256(master, salt
`"vanir-storage-v1"`, info = volume name). The master key is only ever in the storage task's
memory: the task starts **locked**, answering `LOCKED` to everything, and stays so until it gets
the key, from one of two places:

- **The key server** (`keys`, `user/unlocker`): a test stand-in for a local key store, with the
  key compiled in. If `disk` may send to `keys`, it asks for the key when it starts. `keys` gives
  it only to the task named `disk`.
- **The host, after attestation** (`tests/apps/attest-storage.toml`). The key lives on the host
  (`keys/master.key`, made by `host-agent.py`, never in the image). The flow:
  1. The host sends `attest <nonce>`. The `attest` task makes a fresh X25519 key pair for this
     boot and returns a TPM quote over SHA-256(nonce ‖ X25519 public key), so the key pair is
     bound to the attested boot and this challenge.
  2. The host verifies the quote against its approved reference (as in Boot chain and
     attestation). If anything differs it logs `key_refused` with the reasons and stops.
  3. Otherwise it seals the master key to the guest's X25519 key: an ephemeral X25519 exchange,
     HKDF-SHA256(salt = nonce, info `"vanir key release"`), ChaCha20-Poly1305 with the nonce as
     associated data. It sends `key <host public key ‖ ciphertext ‖ tag>` and logs `key_released`.
  4. `control` passes it to `attest`, which opens it and sends the master key to `disk`
     (`OP_UNLOCK`, accepted only from tasks named `keys` or `attest`).

  A boot that measures differently (a changed kernel, manifest or task image) gets no key, and the
  sealed key is useless to anything but that boot's `attest` task.

**Restarts.** The supervisor restarts `disk` and `blockdev` like any task. A restarted
`blockdev` resets the device; `disk` sees `DEAD`, finds the new driver and resends, keeping its
key (`storage-blk-restart`). A restarted `disk` starts locked and must get the key again: from
`keys` it asks itself (`storage-restart`); clients see `DEAD` and resend to the new id.

**Telemetry.** If `disk` may send to `telemetry`, it reports:

```json
{"t":6,"task":"disk","id":"3","event":"storage_locked"}
{"t":6,"task":"disk","id":"3","event":"storage_unlocked","by":"keys"}
{"t":7,"task":"disk","id":"3","event":"volume_created","volume":"client-a","start":2}
{"t":9,"task":"disk","id":"3","event":"integrity_error","volume":"client-a","block":0}
```

`task` comes from the kernel, so no other task can report storage events in `disk`'s name.

```sh
make run DISK=1 DISK_RESET=1 APP=tests/apps/storage.toml   # fresh disk: two clients write and check
make run DISK=1 APP=tests/apps/storage.toml                # same disk: they find their data
make run DISK=1 DISK_CORRUPT=client-a:0 ...                # flip a byte of client-a's block 0 first
```

**Limitations, plainly:**

- **No rollback protection.** An attacker who can write the disk can put back an older data block
  together with its older counter and tag, and it decrypts fine. Detecting that needs a root of
  freshness (a Merkle tree over the metadata with its root in TPM NV storage or a monotonic
  counter), which is not built.
- **Plain-text layout.** The superblock and volume table are not encrypted or authenticated: task
  names, volume positions, and which blocks were ever written (non-zero counters) are visible,
  and changing the table can make a task lose its volume (denial of service, not disclosure).
- **Not crash-consistent.** A write puts the data block on disk, then the metadata block. A crash
  between the two leaves that block failing its integrity check until it is rewritten. Nothing
  is guaranteed to be on stable storage until the client flushes.
- **Fixed-size volumes.** 256 blocks for every task; there is no `volume_blocks` manifest key,
  and volumes are never freed or resized.
- **Key only in memory, and only from the host once.** In the attested flow the host says `bye`
  after releasing the key, so a `disk` restarted later stays locked until the next boot (its
  `storage_locked` event tells the host). Re-attesting on that event is not built.
- **No IOMMU.** `blockdev` programs its device with physical addresses; a malicious driver could
  have it DMA anywhere, including into `disk`'s memory where the key is.
- **The hypervisor sees everything.** The master key and plain text sit in guest memory, which the
  host can read; protecting against the host needs confidential computing (AMD SEV-SNP, Intel TDX).
  Encryption at rest protects the disk image, not the running VM.

## Syscalls

Arguments in `rdi, rsi, rdx, r10, r8, r9`; results in `rax` (then `rdx`, `rsi`).

| Syscall | Number | |
|---|---|---|
| `write(ptr, len)` | 1 | to the serial port; bad pointers return an error |
| `sched_yield()` | 24 | give up the rest of the time slice |
| `getpid()` | 39 | task id: 1, 2, ... in manifest order (restart generation in bits 16+) |
| `exit(code)` | 60 | |
| `send(target, op, msg, len, reply_buf, reply_cap)` | 100 | → `(code, reply_len)` |
| `recv(buf, cap)` | 101 | → `(sender, op, len)`; sender 0 is the kernel |
| `reply(sender, code, buf, len)` | 102 | never blocks |
| `restart(id)` | 103 | supervisor only → new id |
| `task_state(id)` | 104 | supervisor only → `(state, current id)` |
| `lookup(name, len)` | 105 | → id of the task with that manifest name |
| `sleep(ticks)` | 106 | uses no CPU while waiting |
| `uptime()` | 107 | ticks (10 ms) since boot |
| `task_name(id, buf, cap)` | 108 | → length of the task's manifest name |
| `device_bar(device, bar)` | 110 | → `(address, size)` of a granted device's mapped BAR |
| `pci_config_read(device, offset)` | 111 | read-only, granted devices only |
| `dma_info()` | 112 | → `(address, physical address, length)` of the DMA region |
| `read_events(buf, cap)` | 113 | event reader only → `(count, dropped)` |
| `stats(buf, cap)` | 114 | event reader only: uptime, memory, interrupts, per-task state |
| `measurements(buf, cap)` | 115 | TPM task only → `(count, TPM address)`; the boot measurement log |

`recv` flags (in `rdx`): `RECV_EXPECT_IRQ` (1), `RECV_TIMEOUT` (2, ticks in `r10`; then sender 0,
`NOTIFY_TIMER`). Kernel notifications come as sender 0 with op `NOTIFY_DEATH` (1, supervisor),
`NOTIFY_IRQ` (2, drivers) or `NOTIFY_TIMER` (3).

## Protections

| Protection | What it stops | Test |
|---|---|---|
| Supervisor-only kernel pages | user code reading kernel memory | `poke-kernel` |
| SMAP (`stac`/`clac` around user copies, `clac` on every trap) | the kernel touching user memory by accident | `smap-selftest` |
| SMEP | the kernel executing user pages | (enabled, no test) |
| Fault-tolerant `copy_from_user` | a bad syscall pointer crashing the kernel | `bad-pointer` |
| NX on non-code pages | executing data or stack | `exec-stack` |
| W^X segments, `CR0.WP` | modifying code | `write-code` |
| Registers zeroed before `iretq` | kernel values leaking into ring 3 | every run |
| Page-table tree per process | processes reading or writing each other's memory | `address-spaces` |
| Kill on fault, not halt | one process's crash stopping the others | `fault-isolated` |
| Timer preemption | a process that never yields hogging the CPU | `preemption` |
| CPU budgets | a runaway process running forever | `cpu-budget` |
| IPC `sends` allowlist | tasks talking to services they were not given | `ipc-not-allowed` |
| Kernel-checked IPC copies | a bad buffer in a message crashing the kernel or the server | `ipc-bad-buffer` |
| Restart generations in task ids | clients silently reaching a restarted server | `stale-id` |
| Device grants; MSI-X table not mapped | drivers touching other devices or redirecting interrupts | `device-no-grant`, `device-msix` |
| Per-slot DMA regions, zeroed on restart | a dead driver's device scribbling on reused memory | `dma-region` |
| Signed task images, `min_version` | unsigned, modified, swapped or rolled-back programs | `sig-*` |
| Secure Boot chain | a modified boot loader, config or kernel | `sb-*` |
| Measured boot + TPM quotes | a host trusting a VM that booted something else | `measured-*`, `attest-*` |
| Only the storage task may use the block driver | tasks reading the raw disk | `storage-no-driver` |
| A volume per task, chosen by kernel-checked name | tasks reading or writing each other's data | `storage-isolation` |
| Encryption at rest (XChaCha20-Poly1305) | plain text on the disk image | `storage-at-rest` |
| Authenticated blocks, bound to volume, block and counter | changed or moved ciphertext read as data | `storage-tampered`, `storage-bad-block` |
| Key per volume from a master key; locked until it arrives | reading the disk without the key | `storage-wrong-key`, `storage-locked` |
| Key released only to an attested boot | a modified system getting the key | `attest-unlock-refused` |
| Frames freed on death | memory exhaustion from restart loops | `restart-no-leak` |

## System dependencies

| Dependency | Used for | Debian/Ubuntu package |
|---|---|---|
| Rust (stable) via `rustup` | building kernel and user program | — (see below) |
| `x86_64-unknown-none` Rust target | bare-metal compilation | — (see below) |
| `make` | build orchestration | `make` |
| `git` | fetching Limine on first build | `git` |
| C compiler (`cc`) | building the `limine` host tool | `gcc` |
| `objcopy` (GNU binutils) | stripping the user ELF before it is embedded | `binutils` |
| `xorriso` | creating the bootable ISO | `xorriso` |
| `qemu-system-x86_64` | running the kernel (`-cpu max` for SMEP/SMAP, or KVM with `ACCEL=kvm`) | `qemu-system-x86` |
| Python 3.11+ with `cryptography` | signing images, verifying quotes, test tools | `python3-cryptography` |
| OVMF | UEFI firmware for `BOOT=uefi-secure` | `ovmf` |
| `sbsign`, `openssl`, `b2sum` | signing the boot loader, pinning hashes | `sbsigntool`, `openssl`, `coreutils` |
| `swtpm` | software TPM for `TPM=1` | `swtpm`, `swtpm-tools` |

Install on Debian/Ubuntu:

```sh
sudo apt install make git gcc binutils xorriso qemu-system-x86
sudo apt install python3-cryptography ovmf sbsigntool swtpm swtpm-tools   # boot chain, TPM
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # if Rust isn't installed
rustup target add x86_64-unknown-none
```

Nightly Rust is not required. The Limine bootloader binaries (branch `v11.x-binary`) are cloned into
`limine/` automatically the first time you build.

## Building and running

```sh
make                                  # build build/vanir-os.iso
make run                              # boot in QEMU, serial output on the terminal
make test                             # boot every scenario in tests/run.sh; prints PASS/FAIL each
make test ACCEL=kvm                   # same, under KVM (needs access to /dev/kvm)
ONLY='^storage' make test             # just the cases whose names match
make run APP=tests/apps/budget.toml   # choose the app manifest
make run TRANSPORT=vsock ACCEL=kvm ... # add a vhost-vsock device (see Telemetry)
make run DISK=1 APP=tests/apps/storage.toml   # attach build/disk.img (see Storage); DISK_RESET=1
                                      # starts it from zeros, DISK_CORRUPT=volume:block damages it
make run USER_FEATURES=hello/poke-kernel   # turn on a test feature (see tests/run.sh)
make run-debug                        # also log interrupts and CPU resets to qemu.log
make clean                            # remove build outputs (make distclean also removes limine/)
```

QEMU exits with status `(code << 1) | 1` via the `isa-debug-exit` device:

| Status | Meaning |
|---|---|
| 1 | every process exited 0 (`make run` treats this as success) |
| 3 | some process exited with a non-zero code |
| 5 | some process was killed by a fault or its CPU budget |
| 7 | kernel fault or panic, or the supervisor died |
| 9 | deadlock: processes waiting on each other with nothing left to run |

## Layout

```
kernel/build.rs           generates the task table from the app manifest
kernel/src/main.rs        Limine requests, kernel entry, halt/panic
kernel/src/cpu.rs         enables SMEP, SMAP, NX, CR0.WP
kernel/src/apic.rs        local APIC timer (calibrated against the PIT), PIC remap
kernel/src/serial.rs      COM1 serial output
kernel/src/gdt.rs         GDT + TSS (kernel stack for ring 3 -> 0 transitions)
kernel/src/interrupts.rs  IDT and the shared trap entry path
kernel/src/memory.rs      frame allocator, per-process page tables, kernel MMIO mappings
kernel/src/elf.rs         ELF loader (per-segment permissions, W^X)
kernel/src/usercopy.rs    copy_from_user with page-fault recovery
kernel/src/process.rs     task and process tables, scheduler, budgets, IPC, supervisor and device calls
kernel/src/pci.rs         PCI discovery, BAR sizing, MSI-X setup (device kinds in pci_kinds.rs)
kernel/src/irq.rs         device interrupts to task notifications
kernel/src/events.rs      kernel event log
kernel/src/modules.rs     task images and signatures as Limine boot modules
kernel/src/verify.rs      Ed25519 task image signatures
kernel/src/tpm.rs         TPM 2.0 (CRB): PCR extend/read, kernel use at boot only
kernel/src/measure.rs     measured boot into PCR 12
kernel/src/syscall.rs     int 0x80 dispatch
user/lib/                 shared user runtime: _start, syscall wrappers, println!
user/hello/               greeting plus the attack tests (features)
user/spinner/             busy-waits between prints; shows preemption
user/isolation/           checks its memory is not shared with other processes
user/runaway/             spins forever; ended by its CPU budget
user/echo/                IPC server: replies with the message it got
user/client/              IPC client for echo (features for the error cases)
user/deadlock/            two copies send to each other at once
user/supervisor/          restarts failed tasks up to a limit
user/crasher/             faults as soon as it starts
user/sleeper/             checks sleep wakes on time
user/devprobe/            checks device grants
user/dmatest/             checks the DMA region across a restart
user/virtio/              virtio 1.x PCI transport and split virtqueues for drivers
user/virtio-console/      console driver (OP_WRITE); crash-after-50 test feature
user/virtio-vsock/        vsock driver: one stream to host CID 2 port 5000
user/virtio-blk/          block driver: 4 KiB block read/write/flush; crash-after-10 test feature
user/storage/             storage task: encrypted volume per task, locked until it gets the key
user/blktest/             block client: writes, reads back and checks a pattern
user/unlocker/            key server ("keys"): test stand-in that gives "disk" the master key
user/chatter/             writes 200 numbered lines through the console driver
user/telemetry/           event log + heartbeats -> JSON lines -> uplink
user/tpm2/                TPM 2.0 client: attestation key, quote, PCR read
user/attest/              answers quote requests with a JSON quote; opens the released key
user/control/             reads host commands from the uplink (attest <nonce>, key <sealed>)
apps/                     app manifests (the default image, and the format)
tests/apps/               the manifests the tests boot
tools/host-agent.py       receives and checks telemetry (file, stdin, Unix socket, vsock)
tools/check_lines.py      checks numbered lines arrived in order
tools/sign-image.py       makes the image-signing key; signs task images
tools/expected-pcrs.py    computes PCR 12 from the build output
tools/verify-quote.py     verifies a TPM quote against a recorded reference
tools/vanir_attest.py     quote checks and key sealing shared by verify-quote and host-agent
tools/corrupt-disk.py     flips a byte of a volume's block in the disk image
tools/with-swtpm.sh       runs QEMU with a software TPM
keys/                     image-signing key and storage master key (generated, not in git)
user/linker.ld            user programs are ELF, linked at 0x400000
tests/run.sh              boots each scenario and checks QEMU status and output
```
