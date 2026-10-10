# vanir-os

A minimal x86-64 kernel in Rust, booted by [Limine](https://github.com/limine-bootloader/limine), that runs
isolated ring-3 processes. It provides serial output, GDT/TSS, IDT, an ELF loader, a page-table tree
per process, a 100 Hz local APIC timer with round-robin preemption, and `int 0x80` syscalls.

## Processes

- **Static task table.** The processes are fixed at build time (no `fork`/`exec`):
  `make TASKS="spinner spinner runaway:20"` embeds those programs, and `name:N` gives a task a CPU
  budget of N timer ticks.
- **One kernel stack.** A trap saves the user's registers on it; a context switch stores that
  frame in the current process, copies the next process's saved frame over it, switches `CR3`,
  and returns through the normal `iretq`. Kernel code never blocks mid-syscall.
- **Outcomes.** A process ends by `exit`, by faulting, or by using up its CPU budget; the others
  keep running. When none are left the kernel prints a summary and halts.

| Syscall | Number | |
|---|---|---|
| `write(ptr, len)` | 1 | to the serial port; bad pointers return an error |
| `sched_yield()` | 24 | give up the rest of the time slice |
| `getpid()` | 39 | pids start at 1, in task-table order |
| `exit(code)` | 60 | |

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
make run TASKS="spinner spinner"      # choose the task table
make run USER_FEATURES=poke-kernel    # turn on one of hello's attack tests (see tests/run.sh)
make run-debug                        # also log interrupts and CPU resets to qemu.log
make clean                            # remove build outputs (make distclean also removes limine/)
```

QEMU exits with status `(code << 1) | 1` via the `isa-debug-exit` device:

| Status | Meaning |
|---|---|
| 1 | every process exited 0 (`make run` treats this as success) |
| 3 | some process exited with a non-zero code |
| 5 | some process was killed by a fault or its CPU budget |
| 7 | kernel fault or panic |

## Layout

```
kernel/build.rs           generates the task table from TASKS
kernel/src/main.rs        Limine requests, kernel entry, halt/panic
kernel/src/cpu.rs         enables SMEP, SMAP, NX, CR0.WP
kernel/src/apic.rs        local APIC timer (calibrated against the PIT), PIC remap
kernel/src/serial.rs      COM1 serial output
kernel/src/gdt.rs         GDT + TSS (kernel stack for ring 3 -> 0 transitions)
kernel/src/interrupts.rs  IDT and the shared trap entry path
kernel/src/memory.rs      frame allocator, per-process page tables, kernel MMIO mappings
kernel/src/elf.rs         ELF loader (per-segment permissions, W^X)
kernel/src/usercopy.rs    copy_from_user with page-fault recovery
kernel/src/process.rs     task table, process table, scheduler, exit/kill/budgets
kernel/src/syscall.rs     int 0x80 write/sched_yield/getpid/exit
user/lib/                 shared user runtime: _start, syscall wrappers, println!
user/hello/               greeting plus the attack tests (features)
user/spinner/             busy-waits between prints; shows preemption
user/isolation/           checks its memory is not shared with other processes
user/runaway/             spins forever; ended by its CPU budget
user/linker.ld            user programs are ELF, linked at 0x400000
tests/run.sh              boots each scenario and checks QEMU status and output
```
