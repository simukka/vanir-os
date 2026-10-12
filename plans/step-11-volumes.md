# Step 11 plan: service volumes (RFD 3)

Status: V1 planned. V2–V4 will be added here once V1 is built.

## Goal

Implement [RFD 3](../rfd/0003-service-volumes.md), phase V1: volumes that belong to a service,
writer epochs with leases recorded, and read-only candidates. After V1:

- a service image loaded into a slot gets the volume its signed descriptor declares, named after
  the service, whichever slot it runs in
- only the instance holding the volume's epoch can write it; any other instance of the service
  can read it, and its writes get `CODE_FENCED`
- the control plane assigns epochs in desired state, and the agent hands them to `storage`;
  `storage` refuses an epoch lower than the one recorded, across reboots and restarts
- a volume's size is fixed by the version that created it; a later version declaring another
  size can't open it
- fixed tasks keep their per-task volumes, and a fixed task can't reach a service's volume even
  if their names match

Out of scope: keys per service (V2: volumes are still keyed from the node's master key),
queueing during a handoff and telling the new writer (V3), transfers and moves (V4), enforcing
leases (P6). **In V1, writes are refused during a handoff** (from the routing change until the
old instance has drained). That breaks determination 2 until V3 makes those writes wait. No
service relies on it in between.

## What we have

- **Storage** (`user/storage/src/main.rs`, `VNRSTOR2`): block 0 superblock, block 1 the volume
  table (64 × {name[32], start, size}, plain text), then per volume `META_BLOCKS` of counters
  and tags followed by 256 data blocks. The volume is found by the sender's `task_name`, and
  created on first use. Volume keys are HKDF-SHA256(master, salt `vanir-storage-v1`, info = name).
  Volumes are never freed; allocation is a bump pointer.
- **Slots** (RFD 2): a slot's task name is `<class>-<i>`. Its service, version and ports come
  from the signed descriptor through `task_listen`, which `net` already trusts. The descriptor's
  bytes 152..256 are reserved "for RFD 3's storage fields" and must be zero.
- **Ids** change on every restart and every load (the generation above the low 16 bits); the
  low 16 bits name the slot.
- **The agent** runs deployments as a step machine (`user/agent/src/lifecycle.rs`), with
  `// RFD 3` hooks at "not ready until it has opened its volume" (`:272`) and "not finished until
  its handoff is" (`:315`). Desired state is a signed text document (`live <service> <slot>
  <hash> [drain <secs>]`, …); script features stand in for the control plane in one-node tests.
- **`net` only tracks instances that listen** (`instance_for`: no ports and no `connects`
  means `NOT_ALLOWED`), so a slot service must listen to report ready.
- **Disk tests** use `DISK=1`, `DISK_RESET=1` and `DISK_CORRUPT=<volume>:<block>`
  (`tools/corrupt-disk.py`); `storage-persist` relies on the disk left by the test before it.

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Descriptor field | bytes 152..160: `volume_blocks` (u64, 0 = no volume); 160..256 stay zero. `sign-image.py` accepts `volume = { blocks = N }`, 1 ≤ N ≤ 65536. The kernel rejects anything else as `BadDescriptor` | signed with the image; the kernel already parses the descriptor and has no other place to learn it |
| How `storage` learns it | `ListenInfo` gains `volume_blocks`, and flag bit 3 = `loads` (the agent) | `storage` trusts `task_listen` as `net` does; no new syscall |
| Which volume a request reaches | a sender with flag bit 2 (slot) reaches its **service's** volume, if its descriptor declares one, otherwise `CODE_NOT_ALLOWED`. Any other sender reaches its **task's** volume, as today | RFD 3, P1; fixed tasks and their tests are unchanged |
| Kinds kept apart | the table entry gains a kind byte (task or service); service volumes use the HKDF salt `vanir-service-v1`, task volumes keep `vanir-storage-v1` | a fixed task named `counter` and a service `counter` get different volumes and keys, so ciphertext from one never opens in the other |
| Volume header | a new first block in every volume: magic `VNRVOL01`, kind, name, size, epoch, lease. Sealed like a data block with block number `u64::MAX` in the nonce and AAD, counter in the table entry. Format becomes `VNRSTOR3`; older disks are reformatted | the epoch is part of the volume and goes with it in a move (V4); sealing it stops someone with the disk from editing it (rolling it back is the RFD's open question) |
| Variable size | volumes take `1 + ceil(blocks / 170) + blocks` blocks from the bump pointer; task volumes stay 256 data blocks | the descriptor sets the size; still never freed |
| Size is fixed | a service volume whose recorded size differs from the sender's descriptor answers `CODE_OUT_OF_RANGE` to everything, and prints both sizes | RFD 3, P1: resizing is RFD 4's question |
| Epoch assignment | new `OP_EPOCH` from the task with `loads = true` only: (epoch, lease_until, writer id). `storage` finds the service from the writer's `task_listen`, creates the volume if needed, and applies it: an epoch above the recorded one is written to the header and flushed before the reply; the same epoch is accepted again if there is no writer in memory or the writer is unchanged (re-assertion after a restart); anything else gets `CODE_FENCED` | determination 7: the control plane chooses, the node applies; monotonic across reboots |
| Who the writer is | the writer's **slot** (`task_index`), kept in memory only. A restarted writer stays the writer; another slot's instance doesn't | restarts change ids but are the same instance (RFD 2, P4); a slot number means nothing on another node, so it isn't written to the volume |
| Reads and writes | any instance of the service may read; writes and flushes from anything but the writer get `CODE_FENCED` (new, 8). Before any epoch is assigned, nobody may write | RFD 3, P1: read-only candidates; no implicit writer |
| Leases | `lease_until` (u64, ms in the control plane's clock) is stored in the header and reported, never acted on | determination 8; clocks are P6's question |
| Epochs in desired state | `live <service> <slot> <hash> [drain <secs>] [epoch <n> <lease ms>]`. The control plane sends one for services whose image declares a volume | determination 7 |
| When the agent applies it | with no old instance: before routing to the new one (the hook at `:272` moves to `Promote`). With an old one: once it has drained, before it is stopped (the hook at `:315`). A refused epoch fails the deployment step and is reported (`epoch-refused`); the old instance stays live if it hadn't drained, otherwise the slot goes to FAILED | the moment V3 will keep; until then the new instance's writes are refused between routing and the old one draining |
| Storage restarts | the agent looks up `storage`'s id on every tick; when it has changed, it re-sends the epoch for every live service with a volume | `storage` keeps the writer in memory only |
| Reports | each slot line gains `epoch <n>` when it is the writer | the control plane sees what was applied |
| A test service | `http` uses its volume if `task_listen` says it has one: each `GET /count` reads block 0, adds one, writes it back and answers the count and storage's code. It reads block 0 before `OP_READY` (the hook at `:272` is the service's job). Feature `volume-probe` also writes scratch block 1 every 100 ms and prints each change of result (`counter v1 on small-0: writes OK`, `… writes FENCED`) | V3 needs a read-modify-write service under load anyway; the probe shows fencing without client traffic |
| Telemetry | `storage` events `epoch_changed` (volume, epoch, writer slot) and `write_fenced` (volume, slot; once per instance per epoch) | P7, without one event per refused write |

## Sub-steps

Each sub-step is a commit with every test passing under TCG and KVM (vsock and TPM cases are
KVM-only, as today).

### V1a: on-disk format

- `storage`: `VNRSTOR3`, kind byte in the table, a sealed header block per volume (read on first
  use after unlock, written at creation), variable-size layout. Task volumes behave as before.
- `tools/corrupt-disk.py`: `DISK_CORRUPT=<volume>:header`.
- Tests:
  - every `storage-*` and `attest-*storage*` test passes unchanged (the format change is
    invisible to them).
  - `storage-old-format`: a disk written with `VNRSTOR2` is reformatted, with a message.
  - `storage-header-tampered`: `DISK_CORRUPT=client-a:header`; client-a gets `INTEGRITY`,
    client-b reads back correctly.

### V1b: service volumes and epochs

- Kernel: descriptor bytes 152..160, `ListenInfo.volume_blocks` and flag bit 3.
- `sign-image.py`: `volume = { blocks = N }`.
- `vanir_user::block`: `CODE_FENCED`, `OP_EPOCH`, `epoch(storage, epoch, lease_until, writer)`.
- `storage`: service volumes, `OP_EPOCH`, fencing, the size check, telemetry events.
- `http`: volume mode and `volume-probe`. The Makefile builds `http` once more with
  `volume-probe` and signs it as `counter` v1, v2 and v3 (`volume = { blocks = 16 }`, v3 with 32)
  in class `small`.
- Agent: `deploy(slot, image, drain, epoch)`, applying epochs at the two hooks, re-sending
  them when `storage` restarts, and reporting them. New script features below.
- Test app `volumes.toml`: `deploy.toml` plus `blockdev`, `disk` (storage), `keys`; the agent
  and the `small` class may send to `disk`.
- Tests (`DISK=1`):
  - `volume-fence` (`script-volume-swap`): counter v1 in small-0 with epoch 1 (writes OK);
    v2 in small-1 reads v1's count and its writes are FENCED; after v1 drains, epoch 2 goes to
    small-1: v2's writes OK, v1's FENCED. `epoch_changed` twice, `write_fenced` for each.
  - `volume-epoch-stale` (`script-volume-stale`): after epoch 2, assigning epoch 1 to small-0 is
    refused with `FENCED`, and small-1 stays the writer.
  - `volume-persist` (after `volume-fence`, without `DISK_RESET`): the count is where it was,
    epoch 2 is recorded, epoch 2 is accepted again (re-assertion) and epoch 1 is refused.
  - `volume-size-fixed` (`script-volume-resize`): counter v3 (32 blocks) can't open the 16-block
    volume (`OUT_OF_RANGE`), never says ready, fails, and v2 stays live and the writer.
  - `volume-none`: `web` (no volume declared) asking `disk` gets `NOT_ALLOWED`.
  - `volume-kinds`: a fixed task named `counter` (blktest) and the service `counter` write and
    read back their own data; neither sees the other's.
  - `volume-epoch-not-allowed`: `OP_EPOCH` from a task without `loads` gets `NOT_ALLOWED`.
  - `volume-storage-restart` (`storage/crash-after-16`): after `storage` restarts, the agent
    re-sends epoch 1, and counter v1's writes go on.
  - `volume-writer-restart`: the writer crashes and is restarted in the same slot; it is
    still the writer.

### V1c: epochs from the control plane

- Agent: parse `epoch <n> <lease ms>` on `live`; report `epoch <n>`, and `epoch-refused`.
- `control-plane.py`: assigns epochs for images with a volume (one more each deploy or
  rollback), and a scenario that sends a stale one.
- Test app `agent-volumes.toml`: `agent.toml` plus the disk tasks.
- Tests (`NET=user NET_MGMT=user DISK=1`):
  - `agent-volume`: counter v1, then v2, through desired state; the reports show epoch 1, then
    epoch 2 on small-1, and a `GET /count` through `net-peer.py` keeps counting up across the
    deploy (requests during the handoff may get FENCED in V1; the test allows that, and V3
    will forbid it).
  - `agent-epoch-stale`: a document with a higher generation but a lower epoch is applied,
    `storage` refuses the epoch, and the report says `epoch-refused`; the writer is unchanged.
- Manual: Storage (format v3, service volumes, epochs, `CODE_FENCED`), the descriptor's
  `volume` key, the desired-state grammar, the test catalogue, and the limitations list (writes
  refused during a handoff until V3; leases recorded, not enforced; keys still from the node's
  master key until V2).

## Risks and how we'll know

- **The handoff refuses writes in V1.** Deliberate (see Goal), but easy to forget. The
  limitations list in the manual says so, and `agent-volume` allows FENCED during the handoff only
  until V3 changes that test.
- **Re-assertion is looser than raising.** After a reboot or a `storage` restart, any slot of the
  service can be given the recorded epoch again. Only the agent can send `OP_EPOCH`, and it only
  sends what the control plane assigned, so this trusts the agent as RFD 2 already does.
- **A slot reloaded with the same service** after the writer was stopped and unloaded inherits
  the writer role, since `storage` only knows the slot. No other instance of the service runs on
  the node then, so nothing is fenced wrongly. The agent assigns a fresh epoch on its next deploy
  anyway.
- **`ListenInfo` grows.** `net` and `http` pass their buffer sizes to `task_listen`; everything is
  rebuilt together, and `TOO_LONG` would show a mismatch at once.
- **Header flushes add latency** only to epoch changes, not to writes. `volume-fence` prints how
  long `OP_EPOCH` took.
- **A per-request read-modify-write in `http`** is two IPC round trips plus sealing; under TCG
  `agent-volume` may be slow. If it is, it keeps a short load and runs with `SLOW=1`.
- **The format change** reformats any disk left from before; `storage-persist` and
  `attest-unlock-persist` use disks made earlier in the same run, so they are unaffected.
