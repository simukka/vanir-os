# Step 12 plan: a stable ABI and a service runtime (RFD 9)

Status: R1 implemented (R1a–R1c); R2 planned.

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
- **RFD 9's open question 8** (the kernel uses `vanir-abi`), which R1 assumed, was decided yes
  after R1 landed: RFD 9, determination 4.

## R2: versioning, records read by size, settings in the descriptor (RFD 9, P2 and P5)

### Goal

Implement RFD 9, phase R2. After R2:

- a record the kernel writes into a task (`Stats`, `ListenInfo`, `DeathRecord`) can grow at its
  end without breaking a program built against the smaller one, and a program built against a
  larger one works on an older kernel (the new fields read as zero)
- `vanir-abi` has a version, `ABI_VERSION` (major 1, minor 0), with written rules for what a
  minor version may change
- a slot image records the ABI version it was built against, in its signed descriptor, and the
  kernel refuses one it can't serve, with a reason (`REJECT_ABI`)
- a slot image's descriptor carries up to 12 integer **settings** (`[config]` in its TOML),
  signed with the image, which its instance reads through `task_listen`
  (`ListenInfo::setting("persist_ticks")`)
- the descriptor's layout is defined once for Rust (`vanir_abi::descriptor`: the kernel parses
  it, the agent reads it), and checked against `tools/sign-image.py`, which writes it

Out of scope: the runtime and `ctx.config` (R3; R2 gives the raw `ListenInfo::setting`), moving
`count-cached` to a setting (R3, with the port of `counter`), string settings (RFD 9, open
question 7), versioning the IPC protocols between tasks (their records follow the same
growth rule, but no server checks versions yet), and settings for fixed tasks (manifests).

### What we have

- **Records written whole or not at all:** `stats` and `task_listen` refuse a buffer smaller
  than the kernel's record with `TOO_LONG`, and the supervisor's death notice
  (`report_death`) does the same. `vanir_user` passes `size_of` of its own copy, so today the
  two must be identical. `read_events` copies whole `Event`s (an array: its stride is the
  record's size). `measurements` and `runtime_log` copy fixed-size entries.
- **Records have already grown in the middle:** `frames_available` went in before `Stats`'
  task array (load tests, `1bcb805`), which moved the array. Within a version that must not
  happen again; `vanir-abi`'s snapshot would now catch it.
- **The descriptor** (`VNRDSC01`, 256 bytes, `kernel/src/verify.rs`) is compiled from TOML by
  `tools/sign-image.py` (`descriptor()`), hashed into the signed statement (`VNRSIG02`), and
  parsed by `verify::parse_descriptor`; bytes 160..256 must be zero. `slot_load` copies it
  into a 256-byte buffer, so a longer one is `TOO_LONG`.
- **Four readers of its layout:** the kernel (`parse_descriptor`), `tools/sign-image.py`
  (writes it), the agent (`Image::service`, `version`, `volume_blocks`, `drain_secs` read
  offsets 8, 40, 152, 72), and `tools/control-plane.py` / `tools/expected-pcrs.py` (offsets 8,
  40, 152). The agent's `try-tampered-desc` test copies a descriptor into a `[u8; 256]`.
- **Nine slot images** (`SLOT_IMAGES` in the Makefile, `tests/slots/*.toml`), embedded in the
  agent (`include_bytes!` from `VANIR_SLOTS`). The control plane names an image by the SHA-256
  of its signed statement, which covers the descriptor's hash, so a new descriptor is a new
  image name; that is expected (RFD 9, P5: a change of settings is a deployment).
- **Rejections** are numbered 1–13 (`vanir_abi::events::REJECT_*`, checked against the
  kernel's `Rejection` at compile time).

### Design decisions

| Decision | Choice | Why |
|---|---|---|
| Reading by size | `stats`, `task_listen` and the death notice copy `min(cap, size_of)` bytes and return the kernel's full size (`stats`, `task_listen`: rax; the death notice: the message length, as for any `recv`). No more `TOO_LONG` for a short buffer. `vanir_user` zeroes its record before the call | RFD 9, P2. A program's fields past what the kernel wrote stay zero; fields past what the program knows are dropped |
| `DeathRecord::from_bytes` | accepts any length: the fields present are read, the rest are zero | the supervisor built against a newer `vanir-abi` still reads an older kernel's notice |
| Arrays of records | `Event` (`read_events`), the measurement and run-time log entries are **frozen** for major version 1; growing one needs a new syscall | their size is their stride: a reader can't skip unknown bytes without knowing the writer's size |
| Version | `vanir_abi::ABI_VERSION = (1, 0)` (major, minor; `u32` each). Minor versions may add syscalls, error codes, flags, record fields at the end, and descriptor fields in reserved space; anything else is a new major | P2. The rules are in the crate's docs, next to the number |
| What the kernel accepts | an image whose major equals the kernel's and whose minor is at most the kernel's; else `REJECT_ABI` (14), "built for an ABI this kernel doesn't serve" | an image built for minor 3 may call what a minor-1 kernel lacks; failing at load is clearer than `BAD_ARGUMENT` at run time |
| Where the image's version comes from | `abi = "1.0"` in the descriptor TOML if given (tests); otherwise `sign-image.py` reads `ABI_VERSION` from `abi/src/lib.rs` | the version an image was built against is the crate's; writing it by hand in every TOML would drift. The override lets a test sign an image for an ABI the kernel doesn't serve |
| Descriptor format 2 | `VNRDSC02`, 512 bytes. 0..160 as format 1; 160: ABI major (`u32`), minor (`u32`); 168: settings in use (`u64`, at most 12); 176..464: 12 settings, each a 16-byte zero-padded key and a `u64` value; 464..512 zero | RFD 9, P5 (determination 3). The first 160 bytes don't move, so the Python tools that read offsets 8, 40 and 152 keep working |
| Format 1 still accepted | a 256-byte `VNRDSC01` descriptor loads as ABI 1.0 with no settings. `sign-image.py` writes format 2 unless the TOML says `format = 1`; `tests/slots/hello.toml` does, so the slot tests that load `hello` keep the format-1 path tested | images signed before R2 keep loading; dropping format 1 is a later decision |
| Settings' keys | 1–16 bytes of `[a-z0-9_]`, starting with a letter, each key once; unused entries all zero. Anything else is `REJECT_BAD_DESCRIPTOR`. `sign-image.py` refuses the same at compile time | keys are names a service declares (RFD 9, P5); the kernel checks because a descriptor can be signed by any tool |
| The layout in Rust | `vanir_abi::descriptor`: magics, lengths, offsets, `MAX_SETTINGS`, `KEY_LEN`, and safe readers (`name`, `version`, `volume_blocks`, `drain_secs`, `abi`, `settings`) over `&[u8]`. The kernel's `parse_descriptor` and the agent's `Image` use them | the third and fourth copies of the layout go; the kernel keeps its validation, which is policy |
| Layout across languages | a fixture, `abi/tests/descriptor-v2.bin`, made by `sign-image.py` from `abi/tests/descriptor-v2.toml` (every field set, 12 settings). `abi/tests/descriptor.rs` reads it with `vanir_abi::descriptor`; the host check `descriptor-format` rebuilds it with `sign-image.py` and compares bytes | the Python writer and the Rust readers can't drift apart silently |
| Reaching the task | `ListenInfo` grows at its end: ABI major and minor of the image (`u32` each; 0 for fixed tasks), settings in use (`u64`), 12 × (key `[u8; 16]`, value `u64`): 136 → 440 bytes. `ListenInfo::setting(key) -> Option<u64>` | the first record to grow under R2a's rule; fixed tasks get none |
| Who reads settings in R2 | `http` prints its slot's settings once at start (`counter v1 on small-0: setting persist_ticks = 1000`) | the test needs an instance to show what it got; R3's runtime replaces this |

### Sub-steps

#### R2a: records read by size

1. Kernel: `stats`, `task_listen` and `report_death` copy `min(cap, size)` and return the full
   size; the doc comments of those syscalls say so.
2. `vanir-abi`: `DeathRecord::from_bytes` accepts any length; the growth rules in the crate's
   docs.
3. A test program feature, `hello/abi-sizes` (a fixed task), calls `task_listen` with buffers
   of 64 bytes, exactly 136, and 200 (zeroed first) and prints what came back: the returned
   size and whether the bytes past 136 stayed zero. Test case `abi-read-by-size`.
4. `abi-snapshot` unchanged (no value or layout changes); full suite.

#### R2b: the ABI version and format-2 descriptors

1. `vanir-abi`: `ABI_VERSION`; `events::REJECT_ABI` = 14 and its name; `descriptor` module
   (format 1 and 2 layouts, readers). Snapshot: the new values, on purpose, in this commit.
2. `sign-image.py`: format 2 by default, `format = 1`, `abi = "M.N"` and `[config]` in the TOML,
   with the key rules; reads `ABI_VERSION` from `abi/src/lib.rs`.
3. Kernel: `slot_load` takes up to 512 bytes; `parse_descriptor` accepts both formats through
   `vanir_abi::descriptor`, checks the settings, and `check_slot` refuses an unserved ABI with
   `Rejection::Abi`. `verify::Descriptor` keeps the ABI version and the settings.
4. Agent: `Image` reads through `vanir_abi::descriptor`; `try-tampered-desc` copies a
   descriptor of any length.
5. `tests/slots/hello.toml`: `format = 1`. A new slot image, `web-abi-next` (http, `abi =
   "1.1"`), and an agent feature `try-abi-next`; test case `slot-abi-refused` expects
   `REJECT_ABI` and its name in the agent's report and telemetry.
6. Fixture and host check `descriptor-format`. Full suite (every slot image is rebuilt in
   format 2; the control plane names them by their new hashes without other changes).

#### R2c: settings reach the instance

1. `vanir-abi`: `ListenInfo` grows (snapshot updated on purpose); `ListenInfo::setting`.
2. Kernel: `task_listen` fills the ABI version and settings from the loaded descriptor.
3. `http`: prints its slot's settings at start.
4. A slot image `counter-config` (http with a volume and `[config] persist_ticks = 1000`) and an
   agent feature `try-settings` that loads it; test case `slot-settings` expects the line from
   `http`. `abi-read-by-size` now also shows a 136-byte buffer still working against the
   440-byte record.
5. Full suite, and `counter-load` once with `--bench`.

#### R2d: documentation

- The manual: descriptor format 2 and settings (15, deployment; the TOML keys), the ABI
  version and the rules for a minor version (16, syscalls), records read by size, the new
  rejection reason, the new tests and host check; `apps/README.md` if it documents slot TOML.
- RFD 9: open question 6 recorded as settled by P5 (version in the descriptor), and P2's "records
  read by size" as built.
- The plan's "As built" notes.

### Risks and how we'll know

- **A short buffer hides a real bug** (a program passing the wrong size now gets a partial
  record instead of `TOO_LONG`). `vanir_user`'s wrappers always pass `size_of` of the whole
  record and check the returned size is at least what they need for the fields they use;
  `abi-read-by-size` covers the cases.
- **Every image's name changes** (new descriptors, new statement hashes). Anything that pinned a
  hash would break; the control plane computes them from `build/slots/*.sig` at start, and
  `expected-pcrs.py` from the same files. The full suite after R2b shows it.
- **The PCR 13 log** records the statement hash, so `measured-*`/`slot-attest` expectations
  change with the images; they are computed, not pinned, so they follow.
- **Format 1 rots.** `hello` stays format 1, and `slot-unload-no-leak`, which loads it over and
  over, keeps that path running in every suite.
- **The kernel refuses settings it should accept, or the reverse.** The key rules are in one
  place in each language (the kernel's `parse_descriptor`, `sign-image.py`); the fixture carries
  12 settings with keys at the edges (1 and 16 bytes). Refusal of a malformed signed descriptor
  isn't tested end to end (`sign-image.py` won't produce one); noted as a gap.
