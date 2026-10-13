---
rfd: 9
title: A stable ABI and a runtime for writing services
state: discussion
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
- **configuration in the signed descriptor**: settings a service reads at start
  (`ctx.config("persist_ticks")`), so a service is configured per image rather than per build
- an **ABI version** recorded in every image, which the kernel checks at load

Building and signing services outside this repository moves to its own RFD (determination 1).

## Determinations

Decided in discussion (2026-10-13):

1. **Packaging and outside builds move to their own RFD.** A service built outside this
   repository needs a node to trust a slot-signing key other than the dev key, which is RFD 8's
   question (who may deploy what). R1–R4 here work inside the repository: slot images are still
   listed in the Makefile's `SLOT_IMAGES` and signed by `tools/sign-image.py`.
2. **Telling the old writer that it has lost the volume is a follow-up to RFD 3**, not part of
   this RFD. Today only the new writer is told (`block::NOTIFY_WRITER`); an instance that caches
   what it read (the cached counter) learns it was fenced only when its next write fails. The
   follow-up (with RFD 3's recovery after a handoff) would post the old writer a bit when a
   higher epoch is set. The runtime will turn that bit into a `fenced` hook once it exists
   (P3); until then a failed write is the only signal.
3. **Configuration in the signed descriptor is in scope** (P5, was open question 7).
4. **The kernel uses `vanir-abi`** (was open question 8; decided 2026-10-13, built in R1). It
   stays constants, records and safe functions that read them: no syscalls, no `unsafe`, no
   dependencies.

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

- A service can be written against `vanir-rt` alone, and configured without rebuilding it.
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
- Building, signing and trusting services outside this repository (determination 1).

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
- **Images carry the version**, in the slot descriptor (format `VNRDSC02`, P5), so it is covered
  by the signature. The descriptor's TOML gets `abi = "1.0"`. The kernel refuses
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
- **Sizes are fixed at compile time.** There is no heap, so the connection table and buffers
  are statics, sized by associated constants of `Service` (`CONNECTIONS`, `HEADER_LIMIT`, ...)
  with today's values as defaults. The runtime checks them against the descriptor at start
  (e.g. `max_connections` above `CONNECTIONS` is an error, not a silent cap).
- **Losing the volume:** the runtime calls `fenced(&mut self)` when this instance stops being
  the writer, so a service drops what it cached. Until RFD 3's follow-up adds the bit
  (determination 2), the runtime calls it when a volume write returns `FENCED`.
- **An escape hatch:** `vanir_rt::raw` (behind an `unstable` feature) gives the task's raw
  syscalls and IPC, for what the runtime doesn't wrap yet (e.g. calling another service, open
  question 4). What services use it for shows which typed wrappers are missing.

### P4. Capabilities come from the descriptor

At start the runtime reads `task_listen` (service, ports, volume size) and offers only what the
descriptor declares. `ctx.volume()` without a declared volume is `Error::NotDeclared`, and
listening on an undeclared port can't be expressed. The kernel's checks stay as they are; this
only makes mistakes show up early and readably.

### P5. Configuration in the signed descriptor

Services are configured by cargo features today: `http/count-cached` changes every `http` in a
build, and only someone who can edit `http` can add one. Instead, the descriptor carries
settings, signed with the image, and the runtime hands them to the service.

- **Format:** `[config]` in a slot descriptor's TOML (`tests/slots/*.toml`), with integer
  values only for now:

  ```toml
  [config]
  persist_ticks = 1000
  ```

- **Layout:** the 256-byte descriptor has 96 reserved bytes, not enough for the ABI version and
  a useful number of settings. A new format, `VNRDSC02`, is 512 bytes: today's fields as they
  are, then the ABI version (offset 160, 8 bytes), the number of settings (168, 8 bytes), and
  up to 12 settings of a 16-byte zero-padded key and a `u64` value (176–464), the rest zero. The
  kernel accepts both formats while any `VNRDSC01` image is in use.
- **Reaching the service:** the kernel already copies descriptor fields to a slot's task through
  `task_listen` (`ListenInfo`). Settings are added at the end, read by size (P2). The runtime
  offers `ctx.config(key) -> Option<u64>`.
- **Declared by the service:** a service lists its settings and defaults
  (`const CONFIG: &[(&str, u64)]`). The runtime refuses to start with a setting it doesn't
  list, so a typo in the descriptor is an error at load, not a silently ignored setting.
- **A change of configuration is a deployment.** The descriptor's hash is in the signed
  statement, so new settings mean a new signed version, which the agent deploys like any other
  (drain, handoff, rollback, RFD 2). Nothing changes a running instance's settings.
- **In this repository:** the cached counter becomes `counter` with `persist_ticks`
  (0: write every count to the volume). The load tests boot two descriptors of one image, not
  two builds.

### P6. Porting what exists

- Move `count-cached` and the volume counter out of `http` into an example service, `counter`
  (both modes, chosen by `persist_ticks`, P5), and keep `http` as the plain web server for the
  RFD 1 and 2 tests.
- Keep the load tests: `counter-load` and `counter-cached-load` should give the same numbers
  through the runtime, within noise. The runtime's overhead is part of what they measure.

## Phasing (rough)

1. **R1:** `vanir-abi`, with the kernel and `user/lib` both using it. No change in behaviour;
   the full suite passes.
2. **R2:** records read by size (P2), `ABI_VERSION`, descriptor format `VNRDSC02` with the ABI
   version and settings (P5), checked at load; settings reach the task through `task_listen`.
3. **R3:** `vanir-rt` with HTTP, `config` and the `fenced` hook (on a failed write until RFD 3's
   follow-up). Port `counter` to it, with `persist_ticks`, and compare the load tests.
4. **R4:** `make run-service` (a node with the agent in script mode, the service's port
   forwarded), and the host test backend if open question 5 says so.

## Open questions

1. **Names:** `vanir-rt` or `vanir-os-runtime`; and whether `vanir-sys` keeps the `vanir_user`
   name to keep the change small. (Leaning: keep `vanir_user` through R1, rename after; use
   `vanir-rt`.)
2. **What is promised:** only `vanir-abi`, or `vanir-rt`'s API too? (Leaning: only `vanir-abi`
   until a second, different service has used the runtime.)
3. **A trait or async?** A callback trait fits a single-threaded event loop and needs no heap. A
   small `no_std` executor would read more naturally for services that call other services, but
   costs complexity. (Leaning: a trait.)
4. **Calling other services:** typed clients for IPC to other tasks (allowed by `sends`), or
   `vanir_rt::raw` until there is a second protocol to wrap? (Leaning: `raw` for now.)
5. **Testing on the host:** a host backend for `vanir-rt` would let service authors unit-test
   with `cargo test`. Is that worth a second backend? (Leaning: a small one: a volume faked in
   memory, `request()` called directly, no network.)
6. **Where the version lives:** settled by P5 unless we object: the descriptor (`VNRDSC02`),
   not an ELF note, since the kernel already parses and verifies the descriptor.
7. **Settings beyond integers:** strings (e.g. a name to greet) need more room than 8 bytes. Add
   a string area to `VNRDSC02` now, or wait for a service that needs one?
8. ~~Does the kernel use `vanir-abi`?~~ Yes: determination 4.

## References

- [RFD 1](0001-network-services.md): sockets, routing, drain.
- [RFD 2](0002-deployment.md): slots, descriptors, signing, the agent.
- [RFD 3](0003-service-volumes.md): volumes, writers, the writer bit.
- [RFD 7](0007-crash-policy.md): what happens when a service crashes.
- [RFD 8](0008-deployment-threats.md): who may deploy what; where packaging and outside builds
  go (determination 1).
- `user/lib/src/lib.rs`, `kernel/src/syscall.rs`, `kernel/src/verify.rs`,
  `tools/sign-image.py`, `tests/slots/`.
