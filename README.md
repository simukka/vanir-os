# vanir-os

A minimal x86-64 kernel in Rust, booted by [Limine](https://github.com/limine-bootloader/limine), that runs one
isolated ring-3 process. It provides serial output, GDT/TSS, IDT, user page mappings, an `iretq` into
ring 3, and `int 0x80` `write`/`exit` syscalls.

## System dependencies

| Dependency | Used for | Debian/Ubuntu package |
|---|---|---|
| Rust (stable) via `rustup` | building kernel and user program | — (see below) |
| `x86_64-unknown-none` Rust target | bare-metal compilation | — (see below) |
| `make` | build orchestration | `make` |
| `git` | fetching Limine on first build | `git` |
| C compiler (`cc`) | building the `limine` host tool | `gcc` |
| `objcopy` (GNU binutils) | turning the user ELF into a flat binary | `binutils` |
| `xorriso` | creating the bootable ISO | `xorriso` |
| `qemu-system-x86_64` | running the kernel | `qemu-system-x86` |

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
make test                             # boot headless; prints PASS if the process ran and exited 0
make run USER_FEATURES=poke-kernel    # isolation test: user code reads kernel memory and must #PF
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
kernel/src/serial.rs      COM1 serial output
kernel/src/gdt.rs         GDT + TSS (kernel stack for ring 3 -> 0 transitions)
kernel/src/interrupts.rs  IDT and the shared trap entry path
kernel/src/memory.rs      frame allocator and user page mapping
kernel/src/process.rs     loads the user program and enters ring 3
kernel/src/syscall.rs     int 0x80 write/exit
user/hello/               the user program (flat binary loaded at 0x400000)
```
