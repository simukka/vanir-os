# vanir-os

A minimal x86-64 kernel in Rust, booted by [Limine](https://github.com/limine-bootloader/limine), that runs
isolated ring-3 processes. It provides serial output, GDT/TSS, IDT, an ELF loader, a page-table tree
per process, a 100 Hz local APIC timer with round-robin preemption, synchronous IPC between
processes, a supervisor task that restarts failed ones, and `int 0x80` syscalls.

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

Install on Debian/Ubuntu:

```sh
sudo apt install make git gcc binutils xorriso qemu-system-x86
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
make run APP=tests/apps/budget.toml   # choose the app manifest
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
kernel/src/process.rs     task and process tables, scheduler, budgets, IPC, supervisor calls
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
apps/                     app manifests (the default image, and the format)
tests/apps/               the manifests the tests boot
user/linker.ld            user programs are ELF, linked at 0x400000
tests/run.sh              boots each scenario and checks QEMU status and output
```
