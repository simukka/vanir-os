# Step 10 plan: deployment (RFD 2)

Status: in progress: D1 and D2 done. See "As built" at the end for where the implementation departs from this plan.

## Goal

Implement [RFD 2](../rfd/0002-deployment.md), phases D1–D5. Signed service images are loaded
into generic slots at run time, each with a signed descriptor. A node agent swaps a service
locally under load, drains and stops instances, and reconciles against a mock control plane over
an attested Noise channel. Services move between two QEMU nodes, and an empty node reboots into
a new image. After this step:

- a service that keeps crashing keeps being restarted, with growing delays, and never given up on
- the kernel loads a signed image and descriptor into an empty slot, and refuses unsigned,
  tampered, rolled-back or oversized ones, each with a reason
- a slot uses only its class's memory, budget and `sends`, and listens only on the ports its
  descriptor declares
- PCR 13 and the kernel's run-time log show every image loaded and unloaded since boot, and a
  host verifier replays the log against the quote
- `web` v1 → v2 is swapped on one node under load with no failed request, and rolled back the
  same way
- the agent dials the mock control plane, proves its key with a TPM quote, applies signed
  desired state, and picks up where it left off after the connection drops
- a service moves between two nodes under load with no failed request; a node with instances
  refuses to update, and an evacuated one reboots into the new image and rejoins

Out of scope: RFD 3 (volumes; the flows have marked hooks where it will wait, P3/P4), RFD 4
(slots sized at load), RFD 7 (crash policies beyond backoff), the fixes in RFD 8, and the real
control plane. Writing a new node image to an A/B boot partition is also out: in D5 the test
harness restarts QEMU with the new ISO, standing in for that.

## What we have

- **Tasks are fixed at build time.** `kernel/build.rs` turns the manifest into `TASKS`;
  `process::start` finds each image among the Limine boot modules, checks it with
  `verify::check`, measures it into PCR 12 and loads it. A restart reloads the same boot module.
  Nothing can bring in an image after boot.
- **Memory isn't reserved per task.** `load` allocates frames as it maps (ELF segments, a 64 KiB
  stack, page tables) and frees them when the task ends. There's no per-task memory limit.
  `MAX_PROCESSES` is a constant, 16.
- **Signatures** (`tools/sign-image.py`, `VNRSIG01`): program name, version, SHA-256 of the ELF,
  with Ed25519. The manifest's `min_version` is the rollback floor.
- **Measurement** (`kernel/src/measure.rs`): PCR 12, a 16-entry log, written only before tasks
  run. `kernel/src/tpm.rs` busy-waits on the CRB. `attest` maps the CRB page itself (`tpm = true`)
  and quotes PCRs 0, 4, 7 and 12, binding its X25519 key into the quote.
- **Supervisor**: restarts on fault, budget overrun or non-zero exit, gives up after 3
  (`restart-3000` for the leak test); exit 0 means done. Its only input is kernel death records.
  There's no syscall to stop a running task.
- **Routing** (`net`, RFD 1 N6): `OP_READY`, `OP_ROUTE`, `OP_DRAIN` (reply held until drained),
  `OP_DONE`, `OP_BLOCK`. `routes = true` grants it. The test task `switcher` drives it.
- **Network**: `net` and `mgmt-net` only listen; there is no outbound connect. Slirp lets a guest
  reach the host at 10.0.2.2.
- **Host channel**: `control` reads commands from the vsock uplink (`attest`, `key`,
  `interval`); `tools/host-agent.py` is the host end. vsock needs KVM.
- **Crypto in user space**: `ed25519-compact` (with X25519), `sha2`, `hkdf`, `chacha20poly1305`.

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Slots in the manifest | `[[slot_class]]` with `name`, `count`, `memory_pages`, `image_pages`, `budget`, `sends`; `build.rs` expands each into `count` table entries named `<class>-<i>` | slots are ordinary table entries, so scheduling, IPC, ids and restarts work unchanged |
| Table size | `build.rs` emits `MAX_PROCESSES` = tasks + slots, at most 64. User code sizes per-task arrays with `vanir_user::MAX_TASKS = 64`, and `Stats` grows to 64 rows | the manifest decides (RFD 2, P1); one fixed cap keeps the user ABI stable |
| Slot memory | each slot gets a frame quota (`memory_pages`, counting page tables and stack). The allocator holds back every slot's unused quota, so fixed tasks can't take it. A slot past its quota faults (a crash: restarted with backoff) | loading never fails for want of memory, without moving to per-slot frame pools |
| Image storage | each slot gets a contiguous region of `image_pages` at boot; `slot_stage(slot, offset, buf, len)` copies chunks into it, so the agent never holds a whole image | the agent streams an image from the network in 4 KiB pieces; restarts reload from the region |
| Descriptor format | the signing tool compiles the descriptor's TOML to a fixed 256-byte binary (`VNRDSC01`: name, version, `min_version`, class, drain default/max, up to 8 listen entries) | the kernel has no TOML parser or heap; `build.rs` already does the same for manifests |
| Signature format | `VNRSIG02`: name, version, SHA-256 of image, SHA-256 of descriptor, signed with the boot key. Boot images keep `VNRSIG01`, and a v1 statement can't be loaded into a slot | the descriptor is signed with its image (P1); a slot image can't be loaded without one |
| Load | `slot_load(slot, sig, desc, desc_len)`: verify, check `min_version`, check class and image size, take the TPM lock or fail `BUSY`, append to the log or fail `LOG_FULL`, extend PCR 13, record the descriptor, start. Granted by `loads = true` (at most one task) | P2, in the RFD's order; nothing changes before every check has passed |
| Unload | `slot_unload(slot)`: the slot must be dead; zero the image region, drop the descriptor, measure an `unload` entry | the log shows what can run now, not only what was loaded |
| Run-time log | a static array in the kernel; length from the manifest key `runtime_log` (default 1024). An 80-byte entry: op, slot, name, version, SHA-256 of the signed statement. PCR 13 is extended with SHA-256 of each entry | determinations 7 and 9; the verifier replays the entries byte for byte |
| TPM lock | `tpm_lock()` / `tpm_unlock()` for the `tpm = true` task. The kernel releases it if that task dies. `slot_load` never waits for it | determination 8; the kernel never blocks inside a syscall |
| Reading the log | `runtime_log(buf, cap, start) -> (count, total)`, for the `tpm = true` task. `attest` quotes PCR 13 too, and sends the log in chunks after the quote | 1024 × 80 bytes doesn't fit one message |
| `task_listen` for slots | answers from the loaded descriptor: service name and ports | `net` is unchanged and still trusts only the kernel |
| Stopping | new syscall `stop(id)`, supervisor only: ends a live task with a new death kind `STOPPED` (5). The agent asks the supervisor (`OP_STOP`, `OP_START`); the supervisor never restarts `STOPPED` | a stop doesn't depend on the service cooperating, and the supervisor can tell a stop from a crash |
| Exit 0 from a slot | done, not restarted, as for fixed tasks; `STOPPED` is final too | P4. A service that can be made to exit cleanly stays down: RFD 8 #2, left open |
| Restart backoff | a pending-restart table in the supervisor, woken by `recv` with `RECV_TIMEOUT`. 1 tick (10 ms) doubling to 3000 ticks (30 s); the count resets after 6000 ticks without a crash. Test feature `backoff-fast` caps it at 1 tick | determination 7 defaults, in the scheduler's 10 ms resolution |
| Readiness and drains | `net` gets `OP_STATUS(id)` (ready, live, draining, drained) and an `OP_DRAIN` flag to answer at once; the agent polls on its own tick | the agent keeps one event loop and never blocks on a drain (switcher keeps the held reply) |
| Lifecycle owner | `user/agent` from D2 on. A feature-gated script mode with images embedded (`include_bytes!`) stands in for the control plane until D4 | the real state machine is tested from D3; tests run under TCG without a network |
| Outbound connections | `OP_CONNECT` in `net`, allowed only to tasks with the manifest flag `connects = true` (returned by `task_listen`) | P7: the node dials out; services can't |
| Channel | Noise `IK_25519_ChaChaPoly_SHA256` in a new `user/noise` crate, no heap. The node's static key is made each boot and bound to a quote by `attest` (`OP_QUOTE_FOR`, agent only). The control plane's Noise key is pinned in the agent at build time (`VANIR_CP_PUB`) | determination 7. Two pinned keys rather than one Ed25519 key converted to X25519, so each can be rotated alone (RFD 8 #6 applies to both) |
| Commands | desired-state documents signed with a second control-plane key, Ed25519, also pinned in the agent (`VANIR_CP_SIGN_PUB`), each with a generation; the agent applies only a higher generation | P7: idempotent and replay-proof, and signed apart from the transport |
| Telemetry | the agent serves `console::OP_WRITE`, so a manifest names it `uplink`, and telemetry reaches the control plane through it unchanged | P7 with no change to telemetry |
| Mock control plane | `tools/control-plane.py`: Noise responder, quote check (`vanir_attest`), desired state, image server, and for D5 a TCP load balancer in front of two nodes | one tool, as `net-peer.py` is for networking |

## Sub-steps

Each sub-step is a commit with every test passing under TCG and KVM (vsock and TPM cases are
KVM-only, as today).

### D1: restart with backoff

- Supervisor: per-task crash count, last crash tick, and next restart tick. Death records
  schedule a restart instead of doing it; `recv` with `RECV_TIMEOUT` set to the nearest due
  restart. No `MAX_RESTARTS`.
- Each crash reported to telemetry as a structured event (new `telemetry::OP_SUPERVISOR`): task,
  kind, code, restart count, backoff in ms. `host-agent.py` decodes it.
- `restart-3000` becomes `backoff-fast`.
- Tests:
  - `crash-loop`: `crasher` crashes forever next to a spinner. Restarts happen at 1, 2, 4, 8 …
    ticks (checked from the events' ticks, ±1); the spinner finishes on time; the run ends by
    `halt-on-exit` from the spinner, with the crasher still being restarted.
  - `backoff-reset` (feature `reset-after-2s`, test only): crash 3 times, run 2.5 s, crash again;
    the backoff is back to 1 tick.
  - `restart-no-leak` with `backoff-fast`: 3000 restarts, all memory freed.
  - Update `supervisor-restart` and `telemetry`, which expect "giving up after 3".

### D2: slots, descriptors, run-time loading and measurement

- `build.rs`: `[[slot_class]]`, `loads`, `connects`, `runtime_log`; emits `MAX_PROCESSES`, the
  slot entries and per-slot quotas. Rejects a class whose `sends` names a slot, or more than 64
  entries in total.
- Kernel:
  - `Grants` gains the image region and quota. A slot starts `Empty` (a new state, not dead, not
    restartable).
  - Frame accounting per address space against its quota; the global reserve.
  - `verify::check_slot` for `VNRSIG02` + descriptor; new rejections `NoDescriptor`,
    `WrongDescriptor`, `ClassMismatch`, `TooLarge`.
  - Syscalls `slot_stage`, `slot_load`, `slot_unload`, `tpm_lock`, `tpm_unlock`, `runtime_log`.
  - `measure.rs`: PCR 13 and the run-time log. New events `IMAGE_LOADED`, `IMAGE_UNLOADED`; a
    refused load uses `IMAGE_REJECTED` with the slot id.
  - `task_listen` and `task_name` for slots come from the descriptor and the slot name.
- `tools/sign-image.py sign-slot KEY ELF DESC.toml OUT --version N` writes `.desc` and `.sig`.
  The Makefile builds `http` twice for tests: `web-v1` and `web-v2` (feature `banner-v2`, signed
  version 2).
- `attest`: takes the TPM lock around each command, quotes PCR 13 too, and sends the run-time
  log. `verify-quote.py` replays it.
- `user/agent` (first version): with `script-load`, loads embedded images into named slots
  and reports each result.
- Test app `slots.toml`: supervisor, nic, net, agent (`loads = true`), two `small` slots.
- Tests (`NET=user` where HTTP is involved):
  - `slot-load`: `web-v1` is loaded into `small-0` and answers `GET /`; `pid … (small-0)` serves
    `web`.
  - `slot-unsigned`, `slot-tampered-image`, `slot-tampered-desc`, `slot-rogue-key`,
    `slot-boot-sig` (a `VNRSIG01` statement), `slot-too-old` (`min_version` above the version):
    each is refused with its reason, nothing is measured, and the slot stays empty.
  - `slot-class` (the descriptor asks for `large`) and `slot-image-size`: refused.
  - `slot-memory-quota` (http feature `grow`): the slot faults at its quota, is restarted, and
    the other slot keeps serving.
  - `slot-ports` (descriptor without port 81, http feature `listen-81`): `NOT_ALLOWED`.
  - `slot-not-allowed`: `slot_load` from a task without `loads` gets `NOT_ALLOWED`.
  - `slot-occupied`: loading into a live slot gets `BAD_ARGUMENT`.
  - `slot-restart`: a crashing slot service is restarted from its region; the log has one
    `load` entry, not one per restart.
  - `slot-unload-no-leak`: load, stop, unload, 200 times; frames return to baseline.
  - `slot-measured` (`TPM=1 ACCEL=kvm`): PCR 13 equals the replayed log.
  - `slot-attest` (`TPM=1 TRANSPORT=vsock ATTEST=1`): `verify-quote.py` accepts the quote and
    log, and names the loaded images; `--tamper-log` makes it fail.
  - `slot-tpm-busy` (attest feature `hold-lock-1s`): `slot_load` returns `BUSY` until the lock is
    released, then succeeds.
  - `slot-log-full` (`runtime_log = 3`): the fourth measured operation gets `LOG_FULL`.

### D3: the lifecycle and the local swap

- `net`: `OP_STATUS`, and `OP_DRAIN`'s no-wait flag.
- Supervisor: `OP_START`, `OP_STOP` from the agent (the only task it takes messages from),
  using `stop` and `restart`; backoff is reset on start.
- Kernel: `stop(id)` and the `STOPPED` death kind.
- Agent: the state machine of P4 for each slot (EMPTY, STARTING, READY, LIVE, DRAINING, DRAINED,
  STOPPED, FAILED), with every transition reported to telemetry (`OP_LIFECYCLE`). `deploy`
  (load candidate, wait ready with a timeout, promote, drain the old one, stop it),
  `rollback` (start the old slot from its image, promote, drain the new one), `commit` (unload
  the old slot). The drain deadline is the descriptor's default unless the command sets one,
  capped at the descriptor's maximum. Hooks marked `// RFD 3` before READY and before STOPPED.
- Test app `deploy.toml`: as `slots.toml`, with the agent's `script-swap` feature.
- Tests:
  - `deploy-under-load`: `net-peer.py` keeps 8 keep-alive clients requesting; v1 is live, v2 is
    deployed into the other slot, v1 drains and stops. No request fails; responses change from
    v1 to v2; the agent logs every transition in order.
  - `rollback-under-load`: the same, then a rollback to v1 from its retained image; no request
    fails; no new `load` entry in the log.
  - `deploy-not-ready` (http feature `never-ready`): the candidate times out, is stopped, and
    the slot goes to FAILED; v1 stays live throughout.
  - `drain-deadline-cap`: a deadline above the descriptor's maximum is clipped to it (seen in the
    drain event).
  - `stop-not-restarted`: a stopped instance stays stopped, and so does one that exits 0 by
    itself; one that exits non-zero is restarted.
  - `deploy-commit`: after commit, the old slot is empty and a third version can be loaded into
    it.
- Manual: a Deployment section (slots, descriptors, the lifecycle, the swap), the new manifest
  keys and syscalls, and the test catalogue.

### D4: the agent and the mock control plane

- `net`: `OP_CONNECT` (`connects = true` only); a socket from it behaves like an accepted one.
- `user/noise`: the `IK` initiator and transport messages, without rekeying. A host-side unit
  test checks it against the cacophony test vectors.
- `attest`: `OP_QUOTE_FOR(nonce, key)`, accepted only from the task with `loads = true`.
- Agent: boots, makes an X25519 key, gets a quote over it, dials the control plane through
  `mgmt-net` (address and port from a build-time setting), and runs the handshake. Then it
  sends a report (slots, images, states, drain progress, last generation applied), receives
  desired state, closes the gap, and reports again on every change and every 5 s. Images
  are fetched by hash in chunks and staged as they arrive. Reconnects with backoff (100 ms
  doubling to 10 s). Serves `console::OP_WRITE` as `uplink`.
- `tools/control-plane.py`: listens on the host, checks the quote (`vanir_attest`) and that it
  binds the handshake key, serves images, signs desired state, and takes a scenario script.
- Test app `agent.toml`: the full platform set (supervisor, telemetry, attest, nic, net,
  nic-mgmt, mgmt-net, agent, two small slots).
- Tests (`NET=user NET_MGMT=user`; those with `TPM=1` are KVM-only):
  - `agent-connect`: handshake, quote verified, first report received.
  - `agent-wrong-cp-key`: a control plane with another static key fails the handshake; the agent
    retries and applies nothing.
  - `agent-unbound-key` (control-plane option): a quote over a different key is refused by the
    control plane; with `TPM=1`.
  - `agent-unsigned-state` and `agent-replay`: unsigned desired state, or a lower generation,
    is ignored and reported.
  - `agent-deploy`: desired state "web v2 live" while `net-peer.py` keeps requesting; no
    request fails.
  - `agent-reconnect`: the control plane drops the connection mid-transfer and mid-drain; the
    agent reconnects, resumes, and the final state matches with exactly one `load` entry per
    image.
  - `agent-drain`: desired state "drain web" with a 2 s deadline; drained and stopped, counts
    reported.
  - `agent-telemetry`: kernel events and counters arrive at the control plane through the
    agent.
- `switcher` and `control` stay for the RFD 1 tests and the older attestation tests.

### D5: moves between nodes, then evacuate and update

- Makefile: `NODE=a|b` gives each QEMU its own MACs, hostfwd ports, TPM state and serial log;
  `tests/run.sh` gains a two-node case type that starts both and the control plane.
- `control-plane.py`: a TCP load balancer on one host port, with a backend per node; `move` and
  `evacuate` scenarios.
- Agent: reports `empty` when it has no instances; `update` is refused with instances, otherwise
  the agent asks the supervisor (`OP_REBOOT`), which halts with a reboot code. The harness
  restarts that node from the new ISO (built with `SIGN_VERSION=2`, a different kernel banner).
- Tests (all `SLOW=1`):
  - `move-under-load`: `web` on node A; `net-peer.py` requests through the load balancer; the
    control plane loads it on B, waits for ready, switches the backend, drains A. No request
    fails; A holds its image until commit.
  - `update-refused`: `update` on a node with an instance is refused and reported.
  - `evacuate-update`: evacuate A to B under load; A reports empty, reboots into the new image,
    attests (PCR 12 changed as expected), and rejoins; `web` moves back. No request fails.
- Manual: moves, evacuation, the control-plane interface; README status: step 10.

## Risks and how we'll know

- **TPM time inside a syscall.** `slot_load` extends PCR 13 with interrupts off. swtpm takes
  well under a millisecond; real TPMs can take tens. `slot-measured` prints the cycles spent;
  if it's long on hardware, the extend moves to a kernel continuation run on the next tick.
- **Quota accounting gaps.** Page tables are allocated deep in `memory.rs`; missing one lets a
  slot exceed its quota silently. `slot-memory-quota` checks that the fault comes at the quota,
  and the leak tests check that every frame comes back.
- **The table change ripples.** Per-task arrays in `supervisor`, `net`, `telemetry` and
  `Stats` assume 16 or 17. Grep for them in D2 and run the whole suite before adding slots.
- **Image size.** `http` must fit `image_pages`. `build.rs` can't see slot images, so the
  Makefile checks each test image against its class and fails the build if it doesn't fit.
- **Noise correctness.** Hand-written without a heap. The test vectors run before the agent
  uses it, and the Python side uses an independent implementation.
- **Two QEMU nodes under TCG.** Slow, and the load balancer adds a hop. Keep D5's tests to
  short loads and mark them `SLOW=1`; if TCG is too slow for no failed requests, run them under
  KVM only.
- **Run-time log in every quote.** 80 KB of entries at full log. Fine for tests; later the
  verifier can ask for entries after the last one it has.

## As built

Where it departs from the plan so far:

- **D1 test features.** Tests whose only work is a crash loop can't end if restarts never stop,
  so `supervisor-restart`, `restart-no-leak` and the telemetry cases use `give-up-after-3` or
  `give-up-after-3000` (with `backoff-fast`, which restarts at once). `crash-loop` uses
  `halt-on-exit` and `spinner/spin-2s` instead. Crash events go to telemetry through a new
  generic `telemetry::OP_EVENT`, with the crashed task in `of` and `index`.
- **Slot memory is checked at load, not at run time.** A task's memory is fixed once it is
  loaded (no syscall grows it), so the kernel counts the frames a slot image's address space
  takes when it builds it, and refuses the image if that is over `memory_pages`
  (`slot-memory`, reason "image needs more memory than its slot class has"). The boot check
  that free memory covers every slot at its limit replaces the reserve kept in the allocator.
- **Same program, two versions.** `web-v1` and `web-v2` are the same `http` ELF signed with
  different descriptors; `http` in a slot calls itself `web v1 on small-0`, so tests can tell
  them apart without building `http` twice.
- **Refusals.** New reasons `BadDescriptor`, `WrongDescriptor`, `ClassMismatch`, `TooLarge`,
  `BadElf` and `BelowFloor` ("version below its min_version": the boot message talks about
  the manifest). Staging past the image area fails with `TOO_LONG` (`slot-image-size`).
- **Test names.** `slot-tampered-image` and `slot-tampered-desc` replace `slot-tampered`;
  `slot-below-floor` replaces `slot-too-old`; `slot-occupied` stages over a slot holding an
  image that has ended (any slot that isn't empty refuses).
- **Run-time log transport.** A quote says how many run-time entries it covers
  (`runtime_count`); `control` then fetches them from `attest` (`OP_RUNTIME_LOG`, 20 per JSON
  line) and forwards them. `attest` holds the TPM lock over a whole quote (quote, PCR reads,
  entry count) so the three agree. `host-agent.py` waits for those entries before releasing a
  key, and `--attest-delay` lets `slot-attest` challenge after the load.
