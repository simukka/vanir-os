---
rfd: 9
title: A stable ABI and a runtime for writing services
state: prediscussion
authors: simukka
date: 2026-10-13
labels: abi, developer-experience, deployment
---

# RFD 9: A stable ABI and a runtime for writing services

## Summary

Services that run in vanir-os's slots ([RFD 2](0002-deployment.md)) are written today against
`vanir_user` (`user/lib`), the same library the drivers, the network stack, `storage` and the
agent use, and built inside this repository's workspace. Nothing in it is promised to stay
the same, and nothing separates what a service may use from what only system tasks may use.
This RFD proposes:

- an **ABI crate**, `vanir-abi`: the syscall numbers, error codes, IPC operations and shared
  record layouts, as data only, used by the kernel *and* user code, with a version
- a **runtime crate**, `vanir-rt`: what a service author writes against (entry, lifecycle,
  typed handles for the network, the volume and telemetry, an HTTP server), on top of
  `vanir-abi`
- **packaging**: building a service outside this repository into a signed slot image and
  descriptor, and running it locally
- an **ABI version** recorded in every image, which the kernel checks at load

The proposals are drafts for discussion; nothing is decided yet.

## Background

### What exists today

- `user/lib` (`vanir_user`, 1408 lines) is used by all 33 user programs. It has the entry point
  (`entry!`, which records the registers the kernel hands over), `print!`/`println!`, the raw
  syscalls, and the client side of each task protocol: `net`, `block`, `telemetry`, `nic`,
  `console`, `supervisor`, `slot`, `attest`, `keys`.
- **The ABI is written twice.** The kernel defines its own syscall numbers
  (`kernel/src/syscall.rs`), error codes (`kernel/src/process.rs`, `err`) and record layouts
  (`Stats`, `ListenInfo`), and `user/lib` repeats them. They are kept in step by hand: adding
  `frames_available` to `Stats` (load tests, 2026-10-13) meant editing both, and a mismatch
  shows up only at run time.
- **System and service APIs are mixed.** A service such as `http` uses about a fifth of the
  library: `entry!`, `println!`, `lookup`, `uptime`/`sleep`, `task_listen`, `posted`, and the
  service side of `net` (listen, accept, wait, recv, send, close, ready, done), `block` (read,
  write, flush) and `telemetry` (`Record`, `counters`). Next to these sit calls only system
  tasks may make: `slot::load`, `tpm_lock`, `device_bar`, `dma_info`, `events::stats`,
  `restart`, `reboot`, `block::unlock`/`epoch`/`handoff`, `net::route`/`drain`. The kernel and
  the server tasks refuse them by manifest (`loads`, `routes`, `events`, `devices`, `sends`),
  so this is about clarity and stability, not security.
- **Services are configured with cargo features.** `counter` is `http` built with a volume
  descriptor; the cached counter is `http/count-cached`. A feature changes every instance of
  `http` in a build, and a service author can't add one without editing a system program.
- **Building and signing happen in this repository.** The Makefile's `SLOT_IMAGES` lists each
  slot image as `name:program:descriptor`, and `tools/sign-image.py sign-slot` signs the ELF and
  compiles the descriptor (`tests/slots/*.toml`: name, version, `min_version`, `slot_class`,
  `listen`, `volume`) into the 256-byte layout the kernel reads (`kernel/src/verify.rs`). The
  target is `x86_64-unknown-none`, linked with `user/linker.ld`.
- **Everything is static.** There is no allocator; programs keep fixed buffers in statics (e.g.
  `http`'s `SERVER`). Each task is single-threaded: it serves one request at a time from its
  own event loop.

### Why now

The load tests (`counter-load`, `counter-cached-load`) showed what a small service can do:
about 1,700 requests/s writing every count to the volume, and about 14,800 caching it in
memory. Writing the second meant adding a feature to a system binary and threading it through
`http`'s event loop by hand: the drain, the writer bit, the timer and the persist. With a
runtime it would be a small, separate service. The same goes for anything an agent or developer
wants to deploy.

## Goals

- A service can be written, built, signed and deployed without changing this repository.
- One definition of the ABI, shared by the kernel and user code, so a mismatch fails to build.
- A service author sees only what services may use, as typed handles rather than raw ids and
  `u64` codes.
- The lifecycle (ready, drain, `done`, the writer bit, the snapshot interval) is correct by
  default. A service shouldn't be able to forget to say `done` or to persist before draining.
- Old images keep working, or are refused clearly at load, when the ABI changes.

## Non-goals

- Languages other than Rust (a C header generated from `vanir-abi` is a possible follow-up).
- Threads, or shared memory between tasks.
- A general-purpose `std` port.
- Changing what the kernel enforces: capabilities stay in the manifest and the signed
  descriptor.

## Proposals

### P1. Three crates instead of one

| Crate | Contents | Used by |
|---|---|---|
| `vanir-abi` | syscall numbers, `err` codes, IPC op and code numbers per protocol (`net`, `block`, `telemetry`, ...), notify bits, `#[repr(C)]` records (`Stats`, `ListenInfo`, `Event`), `ABI_VERSION`. Constants and types only, `no_std`, no code. | the kernel, `vanir-sys`, `vanir-rt` |
| `vanir-sys` | today's `vanir_user`: raw syscalls and every protocol's client, system calls included | drivers, `net`, `storage`, the agent, the supervisor, telemetry |
| `vanir-rt` | the service runtime (P3) | services |

`vanir-sys` is `user/lib` renamed, using `vanir-abi`'s definitions instead of its own. The
kernel does the same, which removes the duplication. `vanir-rt` uses `vanir-sys` internally
but re-exports nothing from it.

### P2. Versioning the ABI

- `vanir-abi` has `ABI_VERSION` (major.minor). Within a major version, changes are additive
  only: new syscalls and ops get new numbers, and records grow only at the end.
- **Records are read by size.** The caller passes its buffer size and the kernel copies
  `min(size, its own)`, returning its own size. Today `stats` refuses a smaller buffer with
  `TOO_LONG`, so an old program breaks as soon as the record grows.
- **Images carry the version.** It goes in the slot descriptor (a new field, `abi`) or in an ELF
  note that `sign-image.py` reads. Either way it is covered by the signature. The kernel refuses
  an image whose major version it doesn't support, with a reason in the `rejected` event, as it
  does for a bad signature.
- The manifest's system tasks are built with the kernel, so the check matters for slot images.

### P3. The runtime

A sketch of what a service looks like:

```rust
#![no_std]
#![no_main]
use vanir_rt::{http, Service, Ctx, Volume};

struct Counter { volume: Volume, count: Option<u64> }

impl Service for Counter {
    fn start(ctx: &mut Ctx) -> Result<Self, vanir_rt::Error> {
        Ok(Counter { volume: ctx.volume()?, count: None })   // NotDeclared without one
    }
    fn request(&mut self, ctx: &mut Ctx, req: &http::Request, res: &mut http::Response) {
        // ...
    }
    fn every(&mut self, ctx: &mut Ctx) -> Option<u64> { /* persist; next deadline */ None }
    fn drain(&mut self, ctx: &mut Ctx) { /* persist before `done` */ }
}

vanir_rt::service!(Counter);
```

- **The runtime owns the event loop:** waiting on `net`, accept, keep-alive, the drain (stop
  accepting, `Connection: close`, then `done` once connections are gone and `drain` has
  returned), `ready` once `start` succeeds, the writer bit, the snapshot interval and telemetry
  counters (requests by status, latency).
- **Typed handles:**
  - `Net`/`Listener`/`Conn` for raw TCP services.
  - `Volume`, which knows its size and whether this instance is the writer, and turns
    `FENCED`, `LOCKED` and `INTEGRITY` into an `Error` enum.
  - `Telemetry`, holding `Record`s.
  - `Clock`, for `uptime` and deadlines.
- **HTTP:** `vanir_rt::http` is `user/http`'s parser and response writer, moved out. It keeps
  today's limits (header size and time, body size, chunked encoding refused).
- **Memory:** no heap by default. An `alloc` feature provides a fixed arena in the data segment,
  sized at build time and bounded by the slot class's `memory_pages`. Running out of arena memory
  is an error, never a fault.
- **Panics** are reported to telemetry and end the task with a code. The supervisor's crash
  policy ([RFD 7](0007-crash-policy.md)) applies as it does now.

### P4. Capabilities come from the descriptor

At start the runtime reads `task_listen` (service, ports, volume size) and offers only what the
descriptor declares. `ctx.volume()` without a declared volume is `Error::NotDeclared`, and
listening on an undeclared port can't be expressed. The kernel's checks stay as they are; this
only makes mistakes show up early and readably.

### P5. Building and packaging outside the repository

- `vanir-rt` provides the target settings and linker script (through a `build.rs` that emits
  the link arguments), so `cargo build --target x86_64-unknown-none` is enough.
- `vanir-pack` (from `tools/sign-image.py sign-slot`) turns an ELF and a `Service.toml` (the
  descriptor's fields plus `abi`) into `NAME.elf`, `NAME.desc` and `NAME.sig`. In development it
  signs with the dev slot key; in production the signing key belongs to whoever deploys
  ([RFD 8](0008-deployment-threats.md)).
- **Running locally:** something like `make run-service SERVICE=path/to/NAME` boots a node with
  the agent in script mode (as `agent/script-volume-serve` does for the load tests) and forwards
  the service's port to the host.
- A template repository with `counter` and `hello` as examples.

### P6. Porting what exists

- Move `count-cached` and the volume counter out of `http` into an example service, `counter`
  (both modes), and keep `http` as the plain web server for the RFD 1 and 2 tests.
- Keep the load tests: `counter-load` and `counter-cached-load` should give the same numbers
  through the runtime, within noise. The runtime's overhead is part of what they measure.

## Phasing (rough)

1. **R1:** `vanir-abi`, with the kernel and `user/lib` both using it. No change in behaviour;
   the full suite passes.
2. **R2:** records read by size (P2), `ABI_VERSION`, and the `abi` field checked at load.
3. **R3:** `vanir-rt` with HTTP. Port `counter` to it and compare the load tests.
4. **R4:** `vanir-pack`, the template, and a service built outside the repository and deployed
   through the mock control plane.

## Open questions

1. **Names:** `vanir-rt` or `vanir-os-runtime`; and whether `vanir-sys` keeps the `vanir_user`
   name to keep the change small.
2. **What is promised:** only `vanir-abi`, or `vanir-rt`'s API too? Until RFDs 1 to 3 settle,
   promising only the ABI leaves the runtime free to change.
3. **A trait or async?** A callback trait fits a single-threaded event loop and needs no heap. A
   small `no_std` executor would read more naturally for services that call other services, but
   costs complexity.
4. **Calling other services:** should the runtime wrap IPC to other tasks (allowed by
   `sends`) as typed clients, or leave raw `send`/`recv` for now?
5. **Testing on the host:** a host backend for `vanir-rt` (net and volume faked in memory)
   would let service authors unit-test with `cargo test`. Is that worth keeping two backends?
6. **Where the version lives:** in the descriptor (simple, already signed) or in an ELF note
   (travels with the binary)?
7. **Configuration:** services are configured by cargo feature today. Should the descriptor
   carry key-value settings the runtime exposes (`ctx.config("persist_seconds")`), signed with
   the image?
8. **Third-party signing:** who may sign slot images for a node, and is the dev slot key ever
   acceptable outside tests?

## References

- [RFD 1](0001-network-services.md): sockets, routing, drain.
- [RFD 2](0002-deployment.md): slots, descriptors, signing, the agent.
- [RFD 3](0003-service-volumes.md): volumes, writers, the writer bit.
- [RFD 7](0007-crash-policy.md): what happens when a service crashes.
- [RFD 8](0008-deployment-threats.md): who may deploy what.
- `user/lib/src/lib.rs`, `kernel/src/syscall.rs`, `kernel/src/verify.rs`,
  `tools/sign-image.py`, `tests/slots/`.
