---
rfd: 3
title: Service volumes, handoff, transfer and replication
state: discussion
authors: simukka
date: 2026-10-11
labels: storage, deployment, replication, security
---

# RFD 3: Service volumes, handoff, transfer and replication

## Summary

Stateful services keep their data on their node's disk. When a service is deployed or moves
([RFD 2](0002-deployment.md)), its data has to follow without losing acknowledged
writes and without refusing new ones. This RFD covers:

- volumes that belong to a service rather than to a task, with exactly one writer at a time
- handing the writer from one instance to the next without refusing writes
- keys per service, released only to attested nodes
- moving volumes between nodes
- transferring volumes directly between nodes *(sparse: questions only)*
- replicating volumes so a node's loss doesn't lose data *(sparse: questions only)*

The first four are decided and ready for a plan. The last two record the direction and the
questions; their design comes later.

## Determinations

Decided in discussion (2026-10-11):

1. **Stateful services keep their data on the node's disk**, in a volume that belongs to the
   service and has exactly one writer at a time. The volume moves with the service when it
   changes nodes. Preventing data loss across these moves is a requirement.
2. **Writes keep working during a handoff,** whether it's a local swap or a move between
   nodes. Clients may see added latency, but not refused writes.
3. **Volumes transfer directly between nodes,** not through the control plane.
4. **Surviving the loss of a node** (replication) is in this RFD, but designed later. Until
   then, no acknowledged write is lost during *planned* moves only.

Revised in discussion (2026-10-12):

5. **No reads from a stale copy during a handoff.** Once routing has changed, the candidate's
   reads wait along with its writes, so it can't write anything based on data the old instance
   is still changing (P3).
6. **No `concurrent_writes`.** Forwarding writes from two instances can't be made safe at the
   block level, and no service needs it yet (P3).
7. **The control plane assigns epochs; `storage` applies them.** A handoff never waits on a
   round trip to the control plane (P1).
8. **Writer epochs are leases,** recorded in the volume's metadata from V1, though only
   replication (P6) acts on their expiry.

## Background

The storage task (step 6) gives each task its own volume, a fixed range of the disk found by
the task's manifest name. Every block is encrypted with XChaCha20-Poly1305 under a key derived
from a master key and the volume name. A block's seal binds the volume name, the block number
*within the volume*, and a per-block write counter (`binding` in `user/storage/src/main.rs`).
The master key is released only to an attested boot: the host seals it to `attest`'s
key-exchange key, and `attest` hands it to `storage`.

[RFD 2](0002-deployment.md) makes services move: generic slots, run-time loading, local swaps
and moves between nodes. Its flows have hooks where they will wait on storage. Those hooks do
nothing yet. A volume keyed by task name can't follow a service across slots, and a key derived
from one node's master key can't follow it across nodes.

## Terminology

Terms from RFDs 1 and 2 (node, service, slot, instance, live, candidate, drain, commit) apply. New here:

- **Volume:** a service's data on a node's disk.
- **Writer:** the one instance allowed to write a volume.
- **Epoch:** a number identifying the current writer. Only the control plane assigns it.
- **Lease:** how long a writer's epoch stays valid without renewal by the control plane.
- **Handoff:** moving the writer from one instance to another.
- **Mirror:** a copy of a volume on another node that receives every write before it is
  acknowledged.
- **Volume digest:** a hash over every block's counter and tag, identifying the exact state of a
  volume without decrypting it.

## Proposals

### P1. Volumes belong to the service, with one writer

A volume belongs to the **service** (not to a task name, as today). The descriptor declares it:

```toml
volume = { blocks = 256 }
```

The volume name, and so the name every block's seal binds, is the service name. Volumes made
under task names don't carry over. Nothing holds real data yet, so nothing is migrated. A
volume's size can't change between versions; resizing joins slot sizes in
[RFD 4](0004-slots-sized-at-load.md).

**One writer, fenced by an epoch.** Each volume has a writer epoch. `storage` accepts writes
only from the instance holding the current epoch, and records the epoch in the volume's
metadata. An instance with an older epoch gets `CODE_FENCED`, even if it still thinks it's the
writer. This rules out two writers on one node ("split brain"), the usual way data gets lost in
failovers.

**The control plane assigns, `storage` applies.** When a deployment starts, the control plane
gives the candidate epoch e+1, valid once the instance holding e has drained. The node's
`storage` makes the switch itself at that moment. Only the control plane chooses epochs, but the
handoff doesn't wait on it, and a slow or unreachable control plane can't stretch the write stall.

**Epochs only fence on one node.** `storage` on node A can refuse a stale instance on A, but
it can't stop node B. Planned moves don't need more, because the handoff runs over the mirror
connection between the two (P4). Failover does (P6): a node that is partitioned still believes
it is the writer. So each epoch carries a **lease**. The writer's node renews it with the
control plane, and if it isn't renewed, `storage` stops accepting writes when it expires. The
control plane promotes another copy only once the old lease has expired. V1 records the epoch
and lease expiry in the volume's metadata; nothing acts on the expiry until P6.

**Read-only candidates.** Before routing changes, a candidate can read the volume while the live
instance writes, for its readiness checks. Its writes are refused. One consequence: a new
version can't change the data format before it's live. Formats have to stay compatible both ways
while either version can run, so rollback works. This is a rule for services; vanir-os can't
enforce it.

**Becoming the writer.** When the candidate takes the epoch, `storage` tells it, in the reply to
its first request after the switch. The instance must throw away anything it cached while it was
read-only, because the old instance may have changed those blocks since.

### P2. Keys belong to the service, not the node

A volume that moves needs a key both nodes can get, without every node sharing one master key.
Proposed: the control plane holds a key per service volume. It seals the key to the attested
node running the volume's writer or candidate, as the host seals the master key to `attest`
today. A node then only ever holds keys for the volumes it runs. The control plane checks a
node's attestation before giving it an epoch or a key.

There is one key per volume. Being read-only is something `storage` enforces through the epoch,
not something the key can express: XChaCha20-Poly1305 is symmetric, so anything that can
decrypt a block can also seal one.

The seal already binds only the volume name and volume-relative block numbers, so a volume can
sit anywhere on another node's disk. Only the key derivation changes: from the node's master
key to the service's key.

The cost: the control plane holds every volume's key, so whoever compromises it can read every
volume it can get the sealed blocks of. This is [RFD 8](0008-deployment-threats.md), vector 7.

### P3. Handoff without refusing writes

Two instances overlap during any handoff: the old one finishes its requests while the new one
takes new ones (RFD 2, P3). Both can't write the volume at once, because each caches the
volume's contents in memory and would overwrite the other's writes. For the same reason, the new
instance can't keep reading while the old one is still writing: it would write back changes
based on stale data. So the epoch moves at one moment, and the design keeps that moment short
and keeps writes working around it:

1. **No copy at the handoff.** For a move, the target is brought up to date and then mirrored
   before the handoff (P4). When the epoch moves, there is nothing left to copy.
2. **Requests wait, not fail.** Between RFD 1's routing change and the epoch moving, the new
   instance's reads and writes queue in its `storage` and go ahead as soon as it holds the
   epoch. The wait lasts as long as the old instance's in-flight write requests, usually
   milliseconds, and the drain deadline bounds it.

Where this meets RFD 2's flows:

| RFD 2 step | What storage does |
|---|---|
| candidate reports ready | the candidate has opened the volume read-only; for a move, the target is mirrored |
| routing changes | the candidate's reads and writes start queueing |
| old instance drains | its in-flight writes finish and are flushed; then the epoch moves, the candidate is told, and queued requests proceed |
| old instance is `DRAINED` | only after the epoch has moved, so no acknowledged write is still only in its memory |
| control plane commits | for a move, the source wipes its copy |

A local swap is the same, without the copy and mirror: both instances share one disk and one
`storage` task.

### P4. Moving a volume between nodes

What a move must guarantee, whatever the transfer protocol (P5):

- The blocks travel **still encrypted**, as sealed on disk, so neither the network nor the
  source node's agent sees plain text. The target checks every block with the key as it
  arrives.
- **Copy, then catch up, then mirror.** The target copies every block while the source keeps
  writing. Each block's write counter (which already exists, for nonces) shows what changed
  since, and the target repeats until it is close to current. Then the source's `storage`
  switches to synchronous mirroring: each write goes to the target as well, and is
  acknowledged only once both have it.
- **A partition during mirroring** must not lose writes or stop the service. If the target
  stops answering before the handoff, the source gives up on the move after a timeout and goes
  back to writing alone; its writes stall for at most that timeout. The control plane can retry
  the move.
- **Check before the handoff.** Once the source has flushed the old instance's last writes, it
  and the target compare volume digests. The epoch moves only if they match.
- **Mirror back until the commit.** After the handoff the mirror reverses: each of the target's
  writes also goes to the source before it is acknowledged. The source's copy stays whole, so if
  anything fails before the commit, the control plane can give the epoch back to the source
  without losing writes.
- **No takeback without the control plane.** Only the control plane can give the epoch back.
  If it can't be reached during a handoff, whichever node holds the epoch keeps it, and keeps
  mirroring to the other if it can.
- **Commit.** The source wipes its copy only after the control plane commits the move.

No acknowledged write can be lost: until the epoch moves, every acknowledged write is on the
source (and on the target once mirroring starts); after it moves until the commit, every
acknowledged write is on both; after the commit, every write is made on the target.

### P5. Transfer protocol *(sparse)*

Transfers go directly between nodes over the management network (determination 3, RFD 1 P1).
The control plane only sets them up:

```
               control plane
        transfer ticket ╱    ╲ transfer ticket
       (peer, volume,  ╱      ╲  epoch, expiry)
                      ▼        ▼
   node A (source) ◀════════════ node B (target)
   storage ─ agent ─ mgmt-net   mgmt-net ─ agent ─ storage
              sealed blocks, then mirrored writes
```

Why direct: volumes can be large, and routing every byte through the control plane makes it a
bandwidth bottleneck and a single point of failure for every move in the fleet. The cost is
that nodes, which normally only dial out, have to accept a connection from each other.

Starting points:

- **Transfer tickets.** The control plane gives both nodes a signed ticket naming the peer (its
  address and per-boot key), the volume, the epoch and an expiry. A node accepts only the
  connection the ticket names, only while the ticket is valid.
- **Who dials whom.** Probably the target dials the source, so the source, which is serving
  traffic, accepts exactly one expected connection.
- **Channel.** A Noise `KK` handshake, both nodes' per-boot keys (each bound to an attestation
  quote, RFD 2 P7) named in the ticket. The control plane already holds the volume keys (P2),
  so trusting its ticket for the peer's identity adds no new trust; the ticket doesn't need to
  carry attestation evidence.
- **One connection, four phases:** bulk copy, catch-up rounds, mirroring until the handoff, then
  mirroring back until the commit or an abort. A dropped connection resumes from what the target
  already holds.

Questions:

1. **Rate limiting.** A bulk copy shouldn't starve the service's own disk I/O, or the
   management network the control plane needs. Who sets the limit?
2. **Throughput.** Each block crosses `storage`, the agent and `mgmt-net` by IPC copy (at most
   4 KiB per message). Fast enough, or does this need leases (RFD 1, P8)? Step 8's benchmarks
   should measure it.
3. **Mirror latency.** Mirroring adds a round trip between nodes to every write. Is there a
   latency limit above which the control plane shouldn't pick a target (e.g. across sites)?
4. **Failure cases to specify:** the source dies during bulk copy or mirroring, the target dies,
   a ticket expires mid-transfer. (The control plane being unreachable during a handoff is
   covered in P4.)

### P6. Replication *(sparse)*

One disk is one copy. Disks wear out, boards die, and power supplies, blades and whole racks
drop out. For data that matters, a write should be on more than one node before the client is
told it succeeded.

Starting points:

- P4's mirror already does this: replication can be that mirror kept running all the time,
  rather than only during a move.
- Replicas store sealed blocks, so a replica node only needs the volume key when it is promoted
  to writer. If the writer's node is lost, the key comes from the control plane (P2).
- Epochs (P1) already fence an old writer on its own node, and leases (P1) bound how long a
  partitioned writer keeps writing. Failover means waiting out the old writer's lease, then the
  control plane assigning a new epoch to a replica.

Questions:

1. **How many copies**, and is that set per service (in the descriptor) or fleet-wide?
2. **Synchronous or asynchronous?** Synchronous loses nothing but adds a round trip to every
   write and stalls writes when a replica is slow. Asynchronous is fast but loses the last
   writes on failure. Can a service choose?
3. **Lease length and clocks.** A lease trades failover time against renewal traffic. Expiry on
   the writer's node and on the control plane needs clocks that agree to within a known bound;
   what bound can vanir-os's timers promise?
4. **Quorum.** With two copies there is no majority. Is the control plane the tie-breaker, or do
   we need three copies (or a witness)?
5. **Rebuilding.** A lost replica is rebuilt by a bulk copy (P5). How is that throttled against
   the service's own I/O?
6. **Placement.** Replicas belong in different failure domains (chassis, rack, power feed). How
   does the control plane learn a node's failure domain?
7. **Reads from replicas**: allowed (stale reads), or writer only?
8. **Several disks in one node:** does local redundancy belong here, or in the storage task?
9. **Moves with replicas** could promote a replica on the target instead of copying. Does that
   replace P4, or sit beside it?

Backups and point-in-time restore (protecting against a service corrupting its own data, which
replication copies faithfully) need their own RFD.

### P7. Telemetry

Added to RFD 1's snapshots (P5 there):

| Scope | Counters |
|---|---|
| Volume | writer epoch; lease expiry; blocks read and written; requests queued during a handoff and the longest wait; writes refused with `CODE_FENCED` |
| Transfer | blocks copied, blocks still changed, mirror round-trip time, digest mismatches, aborts |

Events: epoch changes, lease expiries, handoffs started and finished, transfers started,
mirrored, handed off, committed and aborted.

### P8. Resources

- **Disk space.** A local swap shares the volume, so it costs nothing. A move needs a full copy
  of the volume on the target node, so each node keeps free space for incoming volumes, and the
  control plane has to know each node's free space.
- **Memory.** Requests queued during a handoff need a fixed-size queue in `storage`. When it is
  full, further requests wait for space rather than fail.

## Phasing (rough; the plan will detail it)

| Phase | Delivers | Proves | After RFD 2 |
|---|---|---|---|
| V1 | service-owned volumes, writer epochs and lease fields, read-only candidates (P1) | a fenced writer is refused; a candidate can't write | D2 |
| V2 | keys per service, released by attestation (P2) | a node without the epoch gets no key; volume opens on a node with the key | D2 |
| V3 | handoff in a local swap (P3) | swap under read-modify-write load with no acknowledged write lost, no write refused, and no update made from stale data | D3 |
| V4 | direct transfer, mirroring both ways, digests and moves (P4, P5) | two QEMU nodes: move under write load, nothing lost or refused; a partition or failure before commit leaves the source whole and serving | D5 |
| later | leases enforced, replication (P6) | | |

## Open questions

The questions in P5 and P6, and:

1. **Rolling back blocks on disk.** Counters and tags live on the same disk as the blocks, so
   someone with the disk can put back an older block together with its counter and tag, and it
   decrypts. A volume digest stops this only if it is kept somewhere the attacker can't write,
   like the control plane or TPM NV storage, and kept current with every write. Is that worth
   its cost, and where would it live?

## References

- [RFD 1](0001-network-services.md): network services
- [RFD 2](0002-deployment.md): deployment
- [RFD 4](0004-slots-sized-at-load.md): slots sized at load
- [RFD 8](0008-deployment-threats.md): attack vectors in deployment
- vanir-os manual, `docs/index.html`, Storage
- `user/storage/src/main.rs`: the volume format and block sealing
- `user/attest/src/main.rs`: how the master key is released today
