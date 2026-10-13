# Step 11 plan: service volumes (RFD 3)

Status: V1, V2 and V3 implemented (V1a–V1c, V2a–V2b, V3). V4 will be added here.

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
| Volume header | a new first block in every volume: magic `VNRVOL01`, kind, name, size, epoch, lease. Sealed like a data block with block number `u64::MAX` in the nonce and AAD; its counter and tag sit in plain text at the front of the header block itself. Format becomes `VNRSTOR3`; older disks are reformatted | the epoch is part of the volume and goes with it in a move (V4); sealing it stops someone with the disk from editing it (rolling it back is the RFD's open question) |
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

## V2: keys per service (RFD 3, P2)

### Goal

A service's volume is keyed from a key that belongs to the service, held by the control plane,
and released only to an attested node that runs the service. After V2:

- a service volume's key is HKDF-SHA256(service key, salt `vanir-service-v2`, info = name);
  the node's master key keys only fixed tasks' volumes
- the control plane makes one key per service, keeps it, and sends it only to a node that
  attested in its handshake, **sealed to `attest`'s per-boot key**: the agent forwards a blob it
  can't open, and `attest` opens it and hands the key to `disk`
- a seal names its service, so a blob for one service can't unlock another's volume
- without its service's key, a service volume answers `CODE_LOCKED` (task volumes and other
  services are unaffected), so the instance never says it is ready and the deployment fails
- once no instance of a service is left on the node (commit), the agent tells `disk` to forget
  its key: a node only holds keys for the services it runs
- one-node tests without a control plane keep working: the `keys` stand-in serves service keys
  as it serves the master key

Out of scope: V3 (handoff), V4 (moves, where the target gets the same key the same way), keeping
the control plane's keys in an HSM or TPM (RFD 8, vector 7), rotating a service's key.

### What we have

- **Master-key release** (`user/attest`): at boot `attest` makes an X25519 key from TPM
  randomness; `OP_QUOTE` quotes over SHA-256(nonce || that key); the host seals the master key
  to it (`vanir_attest.seal_key`: X25519, HKDF-SHA256 salted with the nonce, ChaCha20-Poly1305);
  `OP_UNWRAP` opens it and sends `disk` `OP_UNLOCK`. `disk` accepts that only from `keys` or
  `attest`.
- **The agent's handshake** carries a quote from `OP_QUOTE_FOR` over SHA-256(ephemeral || the
  agent's static key), with `kx_pub` = the agent's key; `control-plane.py` checks it
  (`check_quote`), and `--require-attestation` refuses `no-tpm`. Attested runs need KVM and
  swtpm (`agent-attested`, `agent-tpm.toml`).
- **`keys`** (`user/unlocker`) is a test stand-in that serves the master key to `disk`.
- **V1**: service volumes keyed from the master key with salt `vanir-service-v1`.

### Design decisions

| Decision | Choice | Why |
|---|---|---|
| Who sees a service key in plain text | the control plane, `attest` and `disk` only. The control plane seals each key to `attest`'s per-boot X25519 key; the agent carries the sealed blob | the agent can dial out (`connects = true`) and loads images; if it is compromised, it shouldn't be able to read every volume on the node as well. The alternative, sending the key inside the Noise channel to the agent, is simpler but makes the agent a key holder |
| How the control plane knows `attest`'s key | `OP_QUOTE_FOR` quotes over SHA-256(nonce ‖ agent key ‖ attest's key) and adds `seal_pub` to the JSON line; `vanir_attest.check` hashes `seal_pub` in when present | one quote binds both: the handshake's keys and the key to seal to belong to the same measured boot |
| The seal | X25519 (a fresh control-plane key per seal) with `seal_pub`, HKDF-SHA256 (salt = the fresh public key, info `vanir-volume-key-v1`), ChaCha20-Poly1305 with associated data = service name. Blob: fresh public key (32), sealed key (32), tag (16) | as the master key's seal, plus the service name, so a blob moved to another service doesn't open |
| Delivery | new frame `K` (control plane → agent): service name (32, zero padded), blob (80). Sent after the handshake for every service the desired state puts on the node, and with each desired state that adds one. The agent forwards it to `attest` (`OP_UNWRAP_VOLUME`), which sends `disk` `OP_SERVICE_KEY` (service, key) | the control plane already decides what runs where; the key goes where the service goes |
| Who may give `disk` a service key | `attest`, and `keys` (the stand-in). `disk` asks `keys` itself, as for the master key, when it needs a service's key and may send to `keys` | one-node tests keep running under TCG with no TPM or control plane |
| Without a key | requests to that service's volume get `CODE_LOCKED`, and so does `OP_EPOCH` for it (the agent retries that already). Task volumes still need only the master key | a missing key costs only that service |
| Unattested nodes | the control plane sends no `K` frame to a node that said `no-tpm`, and says so | P2: keys only to attested nodes |
| Forgetting | `OP_FORGET_KEY(service)` from the `loads = true` task; the agent sends it after committing a service of which no instance is left. `disk` drops the key and marks the volume's header unchecked | P2: a node only holds keys for the volumes it runs |
| Where the control plane keeps keys | `build/cp-volume-keys/<service>`, 32 random bytes made on first use, mode 0600 | survives across runs, as `volume-persist` needs; an HSM is RFD 8, vector 7 |
| Key changes | the salt changes to `vanir-service-v2`, so volumes written under V1 don't open (`INTEGRITY`). Every test that reuses a disk makes it in the same run | nothing holds real data |

### Sub-steps

#### V2a: service keys in storage, from the stand-in

- `vanir_user::block`: `OP_SERVICE_KEY` (service, key), `OP_FORGET_KEY` (service).
  `vanir_user::keys`: `OP_SERVICE_KEY` (service → key).
- `disk`: a table of service keys (as many as volumes); service volumes keyed from them; asks
  `keys` for a missing one; `CODE_LOCKED` without one; `OP_FORGET_KEY` from the agent.
- `keys`: serves a per-service test key (HKDF of its fixed seed and the name); feature
  `no-service-keys` refuses them; `wrong-key` changes them too.
- Agent: `OP_FORGET_KEY` after a commit leaves no instance of a service.
- Tests (`DISK=1`):
  - every `volume-*` test passes unchanged (`keys` is in `volumes.toml`).
  - `volume-no-key` (`keys/no-service-keys`): counter v1 can't open its volume (LOCKED), never
    says it is ready, and the deployment fails.
  - `volume-wrong-key` (after `volume-fence`, `keys/wrong-key`): counter's header doesn't open
    (INTEGRITY).
  - `volume-forget` (`script-volume-forget`): deploy, stop, commit; `disk` forgets counter's key,
    and a stray read from counter's slot afterwards is LOCKED.

#### V2b: sealed keys from the control plane

- `attest`: `OP_QUOTE_FOR` binds `seal_pub`; `OP_UNWRAP_VOLUME` (service, blob) from the agent
  only, which opens it and sends `disk` `OP_SERVICE_KEY`.
- `vanir_attest.py`: `check` hashes `seal_pub` in; `seal_volume_key(key, seal_pub, service)`.
- Agent: forwards `K` frames to `attest`; reports `key-refused <service>` if `attest` can't open
  one.
- `control-plane.py`: per-service keys; sends `K` to attested nodes for the services desired
  there; options `--seal-for <other service>` (a blob sealed for the wrong service) and
  `--no-keys`.
- Test app `agent-volumes-tpm.toml`: `agent-volumes.toml` with `attest` and without `keys`.
- Tests (`TPM=1 ACCEL=kvm`, `NET=user NET_MGMT=user DISK=1`):
  - `agent-volume-key`: counter v1 is deployed; the control plane seals counter's key to the
    node; `attest` opens it and `disk` has it; counter opens its volume and goes live. The serial
    log never shows the key (the control plane prints its SHA-256 only).
  - `agent-volume-key-swap` (`--seal-for web`): `attest` refuses the blob, counter's volume stays
    LOCKED, and the report says `key-refused counter`.
  - `agent-volume-unattested` (no TPM, TCG): the control plane sends no key; the deployment
    fails with counter's volume LOCKED.
- Manual: Storage (service keys), the key-release diagram with both paths, the desired-state
  section (`K` frames), RFD 8 vector 7 in the limitations.

### Risks and how we'll know

- **Changing the handshake quote** breaks every attested agent test if the two sides disagree.
  `agent-attested` and `agent-unbound-key` run in V2b before any new test is added.
- **Order at start.** `K` may arrive before `disk` is up, or before the instance asks; `attest`
  keeps no keys, so the agent re-forwards a `K` frame it couldn't deliver on its next turn, and
  `disk` treats a key it already has as a no-op.
- **`keys` as a second source of service keys** is a test stand-in. An app with both `attest`
  and `keys` would accept either; the attested test app has no `keys`.
- **`disk` forgetting a key while an instance still reads.** The agent only forgets after a
  commit leaves no instance; `volume-forget` checks a read afterwards is LOCKED, not served.

## V3: handoff without refusing writes (RFD 3, P3)

### Goal

During a local swap, the new instance's requests wait instead of failing. After V3:

- from the routing change until the epoch moves, `storage` holds the candidate's reads, writes
  and flushes, and answers them in order once the candidate holds the epoch (determinations 2
  and 5)
- when an instance becomes the writer, `storage` posts it a notify bit before it answers any
  held request, so a service knows when its cache can be trusted (determination 9)
- if the handoff is called off (the epoch is refused), the held requests are answered as if
  they had just arrived: reads succeed, writes get `CODE_FENCED`
- `agent-volume` no longer allows `FENCED` during the swap: every count is answered, none
  repeats, and none is skipped

Out of scope: moves (V4), where the same holding starts on the target before the control plane
routes to it.

### What we have

- **Deferred replies.** `reply` (`kernel/src/process.rs:861`) answers any caller that is
  blocked waiting for this server, at any time, so `storage` can keep a request and answer it
  later. A caller that died or restarted in between makes the reply fail with `DEAD`.
- **Notify bits** (`notify`, `:902`) need the sender to be allowed to *send* to the target. No
  task may send to a slot (`kernel/build.rs` resolves `sends` among tasks only), so `storage`
  can't notify an instance today. A slot's `sends` names `disk`.
- **The agent's swap** (`user/agent/src/lifecycle.rs`): `Promote` routes to the new instance
  and drains the old; `WaitDrained` gives the new instance its epoch once the old has drained,
  then stops the old. A refused epoch leaves the new instance live without it.
- **`storage`** answers every request at once, from one loop in `main`. `may_write` fences
  everything but the writer's slot.
- **`http`** with a volume reads and writes block 0 for each `/count`, and caches nothing. It
  waits in `net::wait`, not `recv`, so it doesn't see notify bits yet.
- **`count-under-deploy`** (`tools/net-peer.py`) checks that no count repeats and allows 503
  `FENCED`.

### Design decisions

| Decision | Choice | Why |
|---|---|---|
| Starting the hold | new `block::OP_HANDOFF(candidate id)` from the `loads = true` task, sent by the agent in `Promote` just before `net::route`; `storage` finds the volume from the candidate's descriptor. Candidate 0 calls the handoff off | the agent knows the moment routing changes; nobody else does |
| What is held | the candidate's `OP_READ`, `OP_WRITE` and `OP_FLUSH`, with their data. `OP_INFO` is answered at once | reads wait too (determination 5); `OP_INFO` reveals nothing that changes |
| Where | a table of held requests in `storage` (sender, op, length, 4 KiB of data, when it arrived), 8 entries, in a static (the stack is 64 KiB). If full, `CODE_BUSY`, which `block`'s callers already retry | each instance has at most one request outstanding, so one entry per slot is enough (RFD 3, P8) |
| Releasing | when `OP_EPOCH` makes the candidate the writer: post the bit, then run each held request through the normal path, in arrival order, and answer it | the same checks as any request; nothing special to get wrong |
| Calling it off | `OP_HANDOFF(0)` or a handoff to another candidate: the held requests run through the normal path at once (reads succeed, writes FENCED). The agent calls it off when the epoch is refused after the drain | a refusal must not leave the candidate blocked forever |
| The writer bit | `block::NOTIFY_WRITER` (bit 0), posted to the new writer's id whenever `OP_EPOCH` raises the epoch | determination 9 |
| Notify to a slot | the kernel lets a task notify any task that may **send to it** (a server telling its client), as well as those it may send to | `notify` exists for exactly this case, its doc comment says so; it carries only bits and never blocks |
| Seeing the bit | `vanir_user::posted()`: `recv` with a zero timeout, for tasks nobody sends to; `http` calls it after each `net::wait` and prints "now the writer of its volume" once | `http` never calls `recv`; polling costs one syscall per turn |
| `storage` restarting during a handoff | the held requests are lost and their callers get `DEAD` (as `http` already handles); the agent sends the handoff again with the epochs it resends (`keep_epochs`) | same as any `storage` restart |
| Telemetry | event `handoff` (volume, requests held, longest wait in ticks) when held requests are released or called off | RFD 3, P7 |

### Sub-steps

V3 is one sub-step.

- Kernel: `notify` also allowed to a task whose `sends` names the caller.
- `vanir_user`: `block::OP_HANDOFF`, `block::handoff(storage, candidate)`,
  `block::NOTIFY_WRITER`; `posted()`.
- `storage`: the request path moves out of `main` into `Storage::serve`; per volume, the
  candidate's slot; the held table; release and call-off; the bit; prints "counter: holding
  small-1's requests (handoff)" and "counter: released N held request(s) to small-1, longest
  wait T ticks" / "handoff to small-1 called off; N held request(s) answered".
- Agent: `OP_HANDOFF` before routing when there is an old instance and an epoch; calls it off
  when the epoch is refused; sends it again after a `storage` restart.
- `http`: polls `posted()`; prints the bit once.
- Peer: `count-under-deploy` no longer allows FENCED, and checks the counts are 1..N with none
  missing.
- Tests:
  - `agent-volume` (changed): 0 FENCED, counts 1..N, "small-1: now the writer of its volume",
    and storage's release line.
  - `volume-fence` (changed): storage holds small-1's requests, releases them after epoch 2,
    and counter v2 prints the writer bit.
  - `volume-handoff-off` (new, `script-volume-handoff-off`): counter v2 is deployed over v1
    with epoch 1, which is refused after the drain; the handoff is called off, its held probe
    write is answered FENCED, and v2 never writes.
- Manual: Storage (holding during a handoff, `OP_HANDOFF`, the writer bit), notify's rule, the
  limitations (writes are no longer refused during a swap), the test catalogue.

### Risks and how we'll know

- **A candidate held forever.** If the old instance never drains, the drain deadline still ends
  it, and the epoch moves. If the epoch is refused, the agent calls the handoff off;
  `volume-handoff-off` checks it.
- **The probe timing in `volume-fence`.** With no traffic, the old instance drains in a few
  ticks and the probe (every 100 ms) may not land in the window, so the release line may say 0
  requests; the test checks the line, not the number.
- **Widening `notify`.** A server may now post bits to its clients. Bits carry no data and
  can't block, and a client already trusts the servers it sends to.

## As built

Where it departs from the plan so far:

- **V1a: the header holds its own counter and tag.** They sit in plain text at the front of the
  header block, before the sealed fields; the 64-byte table entry had no room for them, and this
  way the header is whole when the volume moves (V4). The header is checked on a volume's first
  read or write after each unlock, not on `OP_INFO`, so a wrong key still shows as a failed read.
  `DISK_OLD=1` stamps a `VNRSTOR2` superblock for `storage-old-format`.
- **A refused epoch after the drain** leaves the new instance live without it (the plan said
  FAILED): it is already routed, and the old one has drained. The agent marks the slot
  (`epoch_refused`, for V1c's report) and the control plane can send a higher epoch. With no
  old instance, a refusal does fail the deployment, before any traffic.
- **Fewer, broader tests.** `volume-epoch-stale` and `volume-epoch-not-allowed` are part of
  `volume-fence`: after the swap it starts v1 again outside any deployment (its writes are
  FENCED), and offers epoch 1 again (refused). Each `counter` instance with `volume-probe` also
  tries `OP_EPOCH` itself (NOT_ALLOWED). `volume-none` uses `web` with `volume-probe`, which in a
  slot without a volume asks `disk` once.
- **Test helpers.** `volume-kinds` has its own app (`volumes-kinds.toml`): the fixed task
  `counter` (blktest, `start-after-2s`) would otherwise end every volume test when it exits under
  `halt-on-exit`. `volume-writer-restart` uses a new `http` feature, `crash-after-probes`. A
  slot's id is at generation 1 once loaded, so "first start only" there means generation ≤ 1.
  The probe writes once before `OP_READY` as well, so a candidate's refused write is always
  printed before its epoch can arrive. All the volume tests need `NET=user` (the app has a NIC).
- **`http` finds `disk` again** after `DEAD`, as the agent does each tick.
- **V1c: `live` offers the epoch to a live instance too.** If the right image is already live
  and only the epoch changed, the agent offers it once (a refused epoch isn't retried until the
  control plane asks for another). `agent-epoch-stale` checks the refusal and then that a higher
  epoch is accepted. The mock control plane raises a service's epoch whenever its live instance
  (slot or image) changes. `agent-volume`'s peer is a new `net-peer.py` scenario,
  `count-under-deploy`: every count answered 200 must be new (833 counts, none repeated, 5
  FENCED during the handoff in the run that was checked). `words()` in the agent's
  desired-state parser takes ten words, since `live` with `drain` and `epoch` has nine.
- **V2a: a service volume needs only its service's key.** Task volumes need the master key,
  service volumes their service's key, so a node whose master key is never released (the
  attested agent app) still opens service volumes. `disk` asks `keys` for a missing service key
  on each request until it has one, so `keys` prints a refusal only once.
- **V2a: `volume-forget` uses `keys/service-keys-once`.** A slot is unloaded at commit, so no
  stray read can come from it; instead `keys` hands each service's key over once, and counter
  deployed again after the commit can't open its volume (LOCKED, FAILED). `volume-wrong-key`
  runs after `volume-persist`, on the disk `volume-fence` leaves.
- **V2b: `seal_pub` is `attest`'s existing per-boot key** (the one the master key is sealed
  to), named `seal_pub` in `OP_QUOTE_FOR`'s line; `OP_QUOTE` for the host is unchanged.
- **V2b: no `--no-keys` option.** `agent-volume-unattested` covers a node that gets no keys:
  its app (`agent-volumes-no-tpm.toml`) has neither `attest` nor `keys`, since `attest` without
  a TPM exits and `halt-on-exit` would stop the run.
- **V2b: the agent keeps each sealed blob** and passes it on again when `disk` has a new id (a
  restarted `disk` has no keys), until a commit leaves no instance of the service. No test
  restarts `disk` under the attested app yet. The control plane sends a node its keys with each
  desired state, and again on the first report of a new connection.
- **V2b: a failed deployment may never be reported as FAILED.** The agent commits a failed slot
  and fetches the image again in the same turn, so `volume-no-key` (the mock control plane's
  scenario for the swap and unattested cases) waits for an instance that started and went away.
  The retry loop itself is older behaviour.
- **V3: `OP_HANDOFF` carries the service name** as well as the candidate's id (40 bytes), so the
  agent can call a handoff off by service even if the candidate has gone. Calling off (or
  naming another candidate) serves what was held before the reply to the agent.
- **V3: `http` looks for the writer bit after each storage call,** not only after `net::wait`,
  so its "now the writer of its volume" line comes before the result of the request that was
  held, which shows the order `storage` guarantees.
- **V3: the scripts pause in the handoff.** `settle_after_routing` waits 300 ms once the new
  instance is routed to, so the probe's write is always held, and `volume-fence` and
  `volume-handoff-off` check exactly one held request. In the run that was checked,
  `agent-volume`'s peer saw 801 counts, highest 801, none repeated or missing, none FENCED.
