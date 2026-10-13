# Step 12 plan: a stable ABI and a service runtime (RFD 9)

Status: R1 implemented (R1a–R1c).

## R1: one definition of the ABI (RFD 9, P1)

### Goal

Implement [RFD 9](../rfd/0009-service-runtime.md), phase R1: a crate, `vanir-abi`, that holds
everything the kernel and user programs must agree on, used by both. After R1:

- each syscall number, error code, notification, flag, state code and shared record is defined
  once; a change on one side changes the other, or fails to build
- the IPC protocols between tasks (`block`, `net`, `telemetry`, ...) have their op and code
  numbers and records in `vanir-abi` too, so a service runtime (R3) can use them without
  `vanir_user`
- a host test pins every value and every record's size and field offsets as they are before R1,
  so the move provably changes nothing
- no program's source changes beyond its imports, nothing behaves differently, and the full
  suite passes

Out of scope: versioning and records read by size (R2), the `VNRDSC02` descriptor and settings
(R2), the runtime (R3), renaming `vanir_user` (RFD 9 open question 1: after R1), and the Python
tools' copies of the descriptor layout and rejection names (R2 changes the descriptor, so it
takes those on).

**Assumes RFD 9 open question 8 is answered yes:** the kernel depends on `vanir-abi`. Without
that, R1 removes only the user side's half of the duplication, and isn't worth doing alone.

### What we have

- **The kernel's half:** syscall numbers in `kernel/src/syscall.rs` (`SYS_*`, `ERROR`); error
  codes in `kernel/src/process.rs` (`mod err`); notifications and `recv` flags
  (`NOTIFY_DEATH`/`IRQ`/`TIMER`/`POST`, `RECV_TIMEOUT`, `RECV_EXPECT_IRQ`); `DeathRecord`,
  `Stats` (`STATS_TASKS` = 64), `ListenInfo` and `state_code` in `process.rs`; the address
  layout (`DEVICE_BASE`, `DEVICE_STRIDE`, `BAR_STRIDE`, `DMA_BASE`, `TPM_BASE`); `MAX_MESSAGE`;
  event kinds and `Event` in `kernel/src/events.rs`; rejection reasons (`verify::Rejection`,
  1–13); the 48-byte measurement entry.
- **The user half:** `user/lib/src/lib.rs` (`vanir_user`, 1408 lines) repeats all of these by
  hand: `SYS_*`, `err`, the notifications and flags, `DeathRecord`, `events::Stats` (with
  `MAX_TASKS` = 64), `events::Event`, `ListenInfo`, `DEVICE_BASE`..., and the rejection names
  (`events::rejection`).
- **The copies have already drifted**, in comments only so far:
  - `DeathRecord`'s kinds: the kernel has 5 = stopped, `vanir_user` stops at 4.
  - `Stats`' task states: the kernel has 7 = stopped, `vanir_user` stops at 6 (telemetry's
    table of names has it).
- **The IPC protocols** are defined once, in `vanir_user`'s modules: `supervisor`, `block`,
  `nic` (`Info`), `console`, `attest`, `keys`, `telemetry`, `net`, `slot`. The kernel doesn't use
  them. Each module mixes constants with client functions (`block::read`, `net::listen`, ...).
- **Build:** one workspace; everything builds for `x86_64-unknown-none` (`.cargo/config.toml`),
  the kernel with `cargo build -p vanir-kernel`, programs with `cargo build -p <prog>`. The
  `noise` crate also builds for the host, for its test vectors (`HOST_CHECKS` in
  `tests/run.sh`). 29 programs depend on `vanir-user`.

### Design decisions

| Decision | Choice | Why |
|---|---|---|
| Where | `abi/` at the top of the workspace, package `vanir-abi`, crate `vanir_abi`; `no_std`, no dependencies | the kernel uses it, so it isn't a `user/` crate |
| What it may contain | constants, `#[repr(C)]` records with `pub` fields, `const fn` accessors, and tables of names for codes (`rejection_name`). No syscalls, no `unsafe`, no state | RFD 9, P1: data only, so the kernel can depend on it without depending on user code |
| Layout | `vanir_abi::{sys, err, notify, task, layout, events, death, listen, reject}` for the kernel ABI; `vanir_abi::proto::{block, net, nic, console, telemetry, supervisor, attest, keys, slot}` for the protocols between tasks | the kernel ABI and the IPC protocols version separately in R2 (RFD 9, P2: syscalls are the kernel's; protocols are the server tasks') |
| Call sites | `vanir_user` keeps every path it has (`vanir_user::err::DEAD`, `vanir_user::block::OP_READ`, `vanir_user::events::Stats`) by re-exporting (`pub use vanir_abi::proto::block::*` inside `mod block`, next to its client functions). The kernel does the same in its modules (`process::err`, `syscall::SYS_*`) | no change to 29 programs or to the kernel's call sites; the diff is definitions moving, which is what a reviewer needs to check |
| Records the kernel fills | `Stats`, `ListenInfo`, `Event`, `DeathRecord` move with `pub` fields; the kernel builds them as it does now. `ListenInfo`'s accessors (`service()`, `is_slot()`, ...) move with it as `const fn` | today the kernel's copies have private fields and the user's have accessors; one definition needs both |
| `STATS_TASKS` / `MAX_TASKS` | one constant, `task::MAX_TASKS` = 64 | the same number under two names, sizing the same record |
| Rejection reasons | `reject::*` constants 1–13 and `reject::name(u64)`; the kernel keeps its `Rejection` enum, converted by `as u64` and checked against the constants in a `const` assertion | the kernel matches on the enum; the numbers and names live once |
| Proof that nothing changed | **R1a starts** with a host test (`abi/tests/snapshot.rs`, `cargo test -p vanir-abi --target x86_64-unknown-linux-gnu`) asserting every constant's value and every record's `size_of` and `offset_of!` per field, as literals taken from today's sources (extracted by a script from both the kernel's and `vanir_user`'s copies, which must agree). Added to `HOST_CHECKS` | a value or offset that moves fails a test that runs in seconds, instead of a boot that fails at random |
| Comments | where the copies disagree, `vanir-abi` takes the kernel's (it is what runs) | the two drifted comments above |

### Sub-steps

#### R1a: the crate, the snapshot, the kernel ABI

1. Extract today's values with a script (scratch, not committed) from both copies, kernel and
   `vanir_user`, and stop if they disagree on anything but comments. Write them into
   `abi/tests/snapshot.rs` as literals: every `SYS_*`, `err::*`, notification, flag, state and
   death kind, rejection reason, address constant, `MAX_TASKS`, `MAX_MESSAGE`, event kind; and
   `size_of` and field offsets of `Stats`, `ListenInfo`, `Event`, `DeathRecord` (computed by
   building today's records on the host).
2. Create `vanir-abi` with the kernel ABI modules; add it to the workspace and `HOST_CHECKS`
   (`abi-snapshot`).
3. The kernel uses it: `syscall.rs`, `process.rs` (`err`, notifications, flags, records, layout,
   `state_code` returning `task::STATE_*`), `events.rs`, `verify.rs` (rejection numbers). Its
   modules re-export, so its call sites stay.
4. `vanir_user` uses it, re-exporting under today's paths; its own copies go.
5. Build every program and the kernel, run `abi-snapshot`, then the full suite.

#### R1b: the IPC protocols

1. Extend the snapshot with every protocol constant and `nic::Info`'s layout.
2. Move `proto::*` into `vanir-abi`: op and code numbers, notify bits, `BLOCK_SIZE`,
   `MAX_FRAME`, `DEFAULT_INTERVAL_TICKS`, storage event kinds, `nic::Info`, `net`'s event flags
   and `Event`. Client functions and `telemetry::Record` (a builder, so code) stay in
   `vanir_user`.
3. `vanir_user`'s protocol modules re-export them next to their functions.
4. Build, `abi-snapshot`, full suite; one run of `counter-load` with `--bench` to confirm the
   numbers are within noise of `1bcb805`'s (nothing on the request path should change).

#### R1c: documentation

- The manual: a short section on `vanir-abi` (what belongs in it, what doesn't, the snapshot
  test) and the file map; `user/lib`'s module docs point at it.
- The plan's "As built" notes; RFD 9's open question 8 recorded as decided if the discussion
  confirms it.

### Risks and how we'll know

- **A value or layout changes in the move.** The snapshot test fails. It is written before any
  definition moves, from the sources as they are.
- **The kernel picks up something user-only.** `vanir-abi` has no dependencies and no
  `unsafe`; adding either is visible in its `Cargo.toml` or fails the "data only" review.
- **Name clashes in re-exports** (`OP_INFO` exists in `block`, `nic` and `console`; `CODE_OK`
  in several): each protocol stays its own module, re-exported into the module of the same
  name, never glob-imported at the top of `vanir_user`.
- **Paths change for a program.** The full build of all 29 programs catches it; no program's
  source should change, so `git diff --stat user/` beyond `user/lib` must be empty.
- **Host build of `vanir-abi` differs from the target build.** Both are `x86_64`, `repr(C)`
  with fixed-width fields, so layouts match; the snapshot runs on the host, and the kernel's
  `const` assertions (`size_of::<Stats>()` etc.) run on the target.

### As built

Where it departs from the plan:

- **The snapshot's values were generated, not copied by hand.** A script read every
  `pub const` from both copies (the kernel's and `vanir_user`'s, before the move) and evaluated
  them: the 60 names defined on both sides agreed. Codes the kernel had only as numbers in its
  code (task states in `state_code`, death kinds in `report_death`, `task_listen`'s flag bits,
  `verify::Rejection`) were read from those functions. Record layouts came from compiling both
  copies of each record on the host and printing every field's offset: the kernel's four
  records matched `vanir_user`'s field for field.
- **A third copy:** the kernel's `Rejection::describe` repeated `vanir_user`'s rejection
  names. It now calls `vanir_abi::events::rejection`, and the kernel checks each `Rejection`
  variant against `REJECT_*` at compile time.
- **New names for numbers that had none:** `task::STATE_*`, `task::DEATH_*`, `listen::ROUTES`
  (and `CONNECTS`, `SLOT`, `LOADS`), `events::REJECT_*`, `task::MEASUREMENT_ENTRY_LEN`,
  `Stats::ZERO`. The kernel uses them; programs that compared against literals (e.g. the
  supervisor's death kinds) still do, and still work.
- **`DeathRecord::from_bytes`** reads its fields with `u64::from_le_bytes` instead of
  `read_unaligned`, since the crate forbids `unsafe`.
- **Records' sizes are also checked at compile time** in `vanir-abi` itself, so the target
  build (kernel and tasks) fails if one changes, not only the host test.
- **R1b moved code names and `block::op`/`split` with the constants** (they only read them).
  `telemetry::Record` stayed in `vanir_user`: it is a builder, not a record (the first try of
  the move script took it, and the scratch build caught it). Client functions stayed, each
  protocol module re-exporting `vanir_abi::proto::<name>::*`.
- **Results:** `abi-snapshot` pins 201 values, 13 names and 56 layout entries. No file under
  `user/` outside `user/lib` changed. Full suite after R1a and again after R1b: 152 passed (the
  two load tests skipped, as without `--bench`).
- **`counter-load` after R1b** (KVM, 60 s): 1695 requests/s at 8 clients, against 1687 before
  R1; 97,430 counts with none lost or repeated. Within noise, as expected: nothing on the
  request path changed.
- **RFD 9's open question 8** (the kernel uses `vanir-abi`) is what R1 assumed; it stays open in
  the RFD until the discussion settles it.

