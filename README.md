# vanir-os

A minimal x86-64 kernel in Rust, booted by [Limine](https://github.com/limine-bootloader/limine), that runs one
isolated ring-3 process. It provides serial output, GDT/TSS, IDT, an ELF loader, user page mappings,
an `iretq` into ring 3, and `int 0x80` `write`/`exit` syscalls.

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

A user fault kills the process; with a single process that stops the machine.

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
| `qemu-system-x86_64` | running the kernel (with `-cpu max`, for SMEP/SMAP) | `qemu-system-x86` |

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
make run USER_FEATURES=poke-kernel    # run one scenario by hand (see tests/run.sh for the list)
make run-debug                        # also log interrupts and CPU resets to qemu.log
make clean                            # remove build outputs (make distclean also removes limine/)
```

QEMU exits with status `(code << 1) | 1` via the `isa-debug-exit` device:

| Status | Meaning |
|---|---|
| 1 | process called `exit(0)` (`make run` treats this as success) |
| 3 | process exited with a non-zero code |
| 5 | process faulted (expected for `poke-kernel`) |
| 7 | kernel fault or panic |

## Layout

```
kernel/src/main.rs        Limine requests, kernel entry, halt/panic
kernel/src/cpu.rs         enables SMEP, SMAP, NX, CR0.WP
kernel/src/serial.rs      COM1 serial output
kernel/src/gdt.rs         GDT + TSS (kernel stack for ring 3 -> 0 transitions)
kernel/src/interrupts.rs  IDT and the shared trap entry path
kernel/src/memory.rs      frame allocator and user page mapping
kernel/src/elf.rs         ELF loader (per-segment permissions, W^X)
kernel/src/usercopy.rs    copy_from_user with page-fault recovery
kernel/src/process.rs     loads the user program, enters ring 3, kills it on a fault
kernel/src/syscall.rs     int 0x80 write/exit
user/hello/               the user program (ELF linked at 0x400000)
tests/run.sh              boots each scenario and checks QEMU status and output
```
