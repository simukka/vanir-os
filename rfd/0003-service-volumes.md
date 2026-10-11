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
- transferring volumes directly between nodes *(sparse: questions only)*
- replicating volumes so a node's loss doesn't lose data *(sparse: questions only)*

The first three are decided and ready for a plan. The last two record the direction and the
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

## Background

The storage task (step 6) gives each task its own volume, a fixed range of the disk found by
the task's manifest name. Every block is encrypted with XChaCha20-Poly1305 under a key derived
from a master key and the volume name. A block's seal binds the volume name, the block number
*within the volume*, and a per-block write counter (`binding` in `user/storage/src/main.rs`).
The master key is released only to an attested boot.

[RFD 2](0002-deployment.md) makes services move: generic slots, run-time loading, local swaps and moves between
nodes. A volume keyed by task name can't follow a service across slots, and a key derived from
one node's master key can't follow it across nodes.

## Terminology

Terms from RFDs 1 and 2 (node, service, slot, instance, live, candidate, drain, commit) apply. New here:

- **Volume:** a service's data on a node's disk.
- **Writer:** the one instance allowed to write a volume.
- **Epoch:** a number identifying the current writer. Only the control plane raises it.
- **Handoff:** moving the writer from one instance to another.
- **Mirror:** a copy of a volume on another node that receives every write before it is
  acknowledged.

## Proposals

### P1. Volumes belong to the service, with one writer

A volume belongs to the **service** (not to a task name, as today). The descriptor declares it:

```toml
volume = { blocks = 256 }
concurrent_writes = false   # see P3
```

**One writer, fenced by an epoch.** Each volume has a writer epoch. `storage` accepts writes
only from the instance holding the current epoch, and records the epoch in the volume's
metadata. An instance with an older epoch gets `CODE_FENCED`, even if it still thinks it's the
writer, e.g. after a network partition. This rules out two writers ("split brain"), the usual
way data gets lost in failovers.

**Read-only candidates.** A candidate can read the volume while the live instance writes, but
can't write until it holds the epoch. One consequence: a new version can't change the data
format before it's live. Formats have to stay compatible both ways while either version can
run, so rollback works. This is a rule for services; vanir-os can't enforce it.

### P2. Keys belong to the service, not the node

A volume that moves needs a key both nodes can get, without every node sharing one master key.
Proposed: the control plane holds a key per service volume. It releases the key wrapped to the
attested node that holds the writer epoch (or a read-only key to a candidate), through `attest`
as today. A node then only ever holds keys for the volumes it runs. The control plane checks a
node's attestation before giving it an epoch or a key.

The seal already binds only the volume name and volume-relative block numbers, so a volume can
sit anywhere on another node's disk. Only the key derivation changes: from the node's master
key to the service's key.

### P3. Handoff without refusing writes

Two instances overlap during any handoff: the old one finishes its requests while the new one
takes new ones (RFD 2, P3). Both can't write the volume at once, because each caches the
volume's contents in memory and would overwrite the other's writes. So the epoch still moves at
one moment, and the design keeps that moment short and keeps writes working around it:

1. **No copy at the handoff.** For a move, the target is brought up to date and then mirrored
   before the handoff (P4). When the epoch moves, there is nothing left to copy.
2. **Writes wait, not fail.** Between RFD 1's routing change and the epoch moving, the new
   instance's writes queue in its `storage` and go ahead as soon as it holds the epoch. Reads
   never wait. The wait lasts as long as the old instance's in-flight write requests, usually
   milliseconds, and the drain deadline bounds it.
3. **Optional forwarding.** A service whose data tolerates two writers (an append-only log, for
   instance) can declare `concurrent_writes = true`. Its old instance's late writes are then
   forwarded to the new writer instead of the new instance waiting. vanir-os can't check that
   claim; it is the service's responsibility, like format compatibility.

Where this meets RFD 2's flows:

| RFD 2 step | What storage does |
|---|---|
| candidate reports ready | the candidate has opened the volume read-only; for a move, the target is mirrored |
| routing changes | the candidate's writes start queueing |
| old instance drains | its in-flight writes finish and are flushed; then the epoch moves and queued writes proceed |
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
  stops answering, the source gives up on the move after a timeout and goes back to writing
  alone; its writes stall for at most that timeout. The control plane can retry the move.
- **Commit.** The source wipes its copy only after the target confirms and the control plane
  commits the move. If anything fails before the commit, the source's copy is still whole and
  it can take the epoch back.

No acknowledged write can be lost: until the epoch moves, every acknowledged write is on the
source (and on the target once mirroring starts); after it moves, every write is made on the
target.

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
  quote, RFD 2 P7) named in the ticket.
- **One connection, three phases:** bulk copy, catch-up rounds, then mirroring until the
  handoff or an abort. A dropped connection resumes from what the target already holds.

Questions:

1. Is the `KK` handshake enough, or should the ticket also carry attestation evidence so each
   node verifies its peer itself rather than trusting the control plane's word?
2. **Rate limiting.** A bulk copy shouldn't starve the service's own disk I/O, or the
   management network the control plane needs. Who sets the limit?
3. **Throughput.** Each block crosses `storage`, the agent and `mgmt-net` by IPC copy (at most
   4 KiB per message). Fast enough, or does this need leases (RFD 1, P8)? Step 8's benchmarks
   should measure it.
4. **Mirror latency.** Mirroring adds a round trip between nodes to every write. Is there a
   latency limit above which the control plane shouldn't pick a target (e.g. across sites)?
5. **Final check.** Is checking each block's seal enough, or should the target confirm a digest
   of the whole volume (counters and tags) with the source before the commit?
6. **Failure cases to specify:** the source dies during bulk copy or mirroring, the target dies,
   the control plane is unreachable during the handoff, a ticket expires mid-transfer.

### P6. Replication *(sparse)*

One disk is one copy. Disks wear out, boards die, and power supplies, blades and whole racks
drop out. For data that matters, a write should be on more than one node before the client is
told it succeeded.

Starting points:

- P4's mirror already does this: replication can be that mirror kept running all the time,
  rather than only during a move.
- Replicas store sealed blocks, so a replica node only needs the volume key when it is promoted
  to writer.
- Epochs (P1) already fence an old writer. Failover means the control plane raising the epoch
  for a replica.

Questions:

1. **How many copies**, and is that set per service (in the descriptor) or fleet-wide?
2. **Synchronous or asynchronous?** Synchronous loses nothing but adds a round trip to every
   write and stalls writes when a replica is slow. Asynchronous is fast but loses the last
   writes on failure. Can a service choose?
3. **Who decides the writer is dead?** The control plane, from missed heartbeats? How does it
   avoid promoting a replica while the old writer is only partitioned and still answering
   clients? Epochs fence storage, not the old writer's network.
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
| Volume | writer epoch; blocks read and written; writes queued during a handoff and the longest wait; writes refused with `CODE_FENCED` |
| Transfer | blocks copied, blocks still changed, mirror round-trip time, aborts |

Events: epoch changes, handoffs started and finished, transfers started, mirrored, handed off,
committed and aborted.

### P8. Resources

- **Disk space.** A local swap shares the volume, so it costs nothing. A move needs a full copy
  of the volume on the target node, so each node keeps free space for incoming volumes, and the
  control plane has to know each node's free space.
- **Memory.** Writes queued during a handoff need a fixed-size queue in `storage`. When it is
  full, further writes wait for space rather than fail.

## Phasing (rough; the plan will detail it)

| Phase | Delivers | Proves | After RFD 2 |
|---|---|---|---|
| V1 | service-owned volumes, writer epochs, read-only candidates (P1) | a fenced writer is refused; a candidate can't write | D2 |
| V2 | keys per service, released by attestation (P2) | a node without the epoch gets no key; volume opens on a node with the key | D2 |
| V3 | handoff in a local swap (P3) | swap under write load with no acknowledged write lost and no write refused | D3 |
| V4 | direct transfer, mirroring and moves (P4, P5) | two QEMU nodes: move under write load, nothing lost or refused; a partition or failure before commit leaves the source whole and serving | D5 |
| later | replication (P6) | | |

## Open questions

The questions in P5 and P6. The first three proposals are decided enough to plan.

## References

- [RFD 1](0001-network-services.md): network services
- [RFD 2](0002-deployment.md): deployment
- vanir-os manual, `docs/index.html`, Storage
- `user/storage/src/main.rs`: the volume format and block sealing
