---
rfd: 2
title: Deployment, blue-green swaps and moves
state: committed
authors: simukka
date: 2026-10-11
labels: deployment, control-plane, supervisor, attestation
---

# RFD 2: Deployment, blue-green swaps and moves

## Summary

Services on vanir-os are deployed continuously, with a blue-green strategy, and move between
nodes so nodes can be updated. This RFD proposes the node's side:

- generic slots that signed service images are loaded into at run time
- service descriptors, signed with the image, that say what a service may do
- three deployment flows: a local swap, a move to another node, and evacuating a node to
  update it
- an instance lifecycle, with draining built on [RFD 1](0001-network-services.md)'s routing
  and connection draining
- restarting crashed services
- a node agent that talks to the control plane, and attestation of what it loads

Services with data also need [RFD 3](0003-service-volumes.md); the flows here wait on it at
defined points. The control plane itself (scheduling, the load balancers, the fleet view) is
out of scope. It gets its own RFD, and this one only fixes the interface the node gives it.

## Determinations

Decided in discussion (2026-10-11):

1. **A node's image is only swapped when it has no active slots.** To update a node, the
   control plane first moves every slot to other nodes, then reboots the empty node into its
   new image. Moving a slot means starting it on another node, so **run-time image loading is
   required**, not optional (P3).
2. **Nodes swap slots locally**, for continuous deployment of a service without moving it
   (P3, P4).
3. **Storage waits are defined by RFD 3.** The flows here wait on it at two points: before a
   candidate reports ready, and before a drained instance stops (P3, P4).
4. **A crashed service is always restarted,** however often it crashes, with exponential
   backoff between restarts so a crash loop can't eat the CPU. Every crash is reported as an
   event (P5). Smarter policies (rollback, quarantine, crash budgets) are a follow-up:
   [RFD 7](0007-crash-policy.md).
5. **Drain deadlines:** the descriptor sets a default and a maximum. The control plane may pick
   any deadline up to the maximum for one deployment (P4).
6. **Slots come in a few fixed classes** declared in the manifest, and a descriptor names the
   class it needs (P1). Slots sized from the descriptor at load time are a follow-up:
   [RFD 4](0004-slots-sized-at-load.md).
7. **Until a control plane exists, this RFD sets the defaults** for what it will later choose.
   The control plane's own RFD may change them:

   | Setting | Default |
   |---|---|
   | Channel security | Noise `IK` handshake (X25519, ChaCha20-Poly1305, SHA-256); the node's key bound to its attestation (P6) |
   | Drain deadline | the descriptor's default (30 s if it sets none); no override |
   | Restart backoff | 10 ms, doubling to at most 30 s; reset after 60 s without a crash |
   | Run-time measurement log | 1024 entries (about 80 KB of kernel memory); the manifest may change it (P6) |

8. **The kernel and `attest` share the TPM through a lock the kernel holds** (2026-10-12).
   `attest` takes it around each TPM command; the kernel extends the run-time PCR under it, so
   measurement stays in the kernel (P2, P6).
9. **The kernel keeps the run-time measurement log** (2026-10-12), as it does for boot, so an
   agent crash can't make a node unattestable (P6).

## Background

- Today a node runs a fixed set of tasks, declared in a manifest at build time and loaded as
  signed boot modules. Nothing can load an image at run time.
- The kernel verifies each image's Ed25519 signature and rollback version, and measures it into
  the TPM. A host can check the measurements by attestation, and the `attest` task can quote
  PCRs over a nonce.
- The supervisor restarts failed tasks, and gives up after `MAX_RESTARTS` (3). An attacker who
  can crash a service 3 times takes it down for good.
- `MAX_PROCESSES` is 8.
- RFD 1 gives each service routing to a live instance, and draining of an instance's
  connections.

## Goals

1. Deploy a new version of a service with no dropped requests, and roll it back the same way.
2. Move a service to another node with no dropped requests.
3. Drain a service, and evacuate a whole node, on the control plane's command.
4. Run only signed images, and let the control plane verify by attestation what a node runs
   now, not only what it booted.
5. Keep each step testable under QEMU, with a test proving each protection.

## Non-goals

- The network itself ([RFD 1](0001-network-services.md)) and storage
  ([RFD 3](0003-service-volumes.md)).
- The control plane: scheduling, load balancers, the fleet view.
- Provisioning new machines (PXE or UEFI HTTP boot, enrolling our Secure Boot key, registering a
  TPM). That belongs to the control plane's RFD, though it constrains what the image contains.

## Terminology

RFD 1's terms (node, service, instance, live, drain) apply. New here:

- **Control plane:** the off-node system that decides what runs where.
- **Slot:** a task that can run one version of one service. Slots are generic: a node has a
  fixed pool of them, and a service occupies a slot when the agent loads its image there.
- **Descriptor:** what a service may do, signed with its image.
- **Candidate:** an instance holding the version being deployed, on the same node or another.
  *Live* and *candidate* are roles, not colours: they alternate between slots on each
  deployment. We name roles instead of colours because people disagree about which colour
  means "new".
- **Evacuate:** move every instance off a node, so the node can be updated.
- **Commit:** the control plane declaring a deployment or move final, after which the old
  version may be unloaded.

## Architecture

```
                          control plane
                               │ management network (RFD 1's mgmt-net; node dials out)
 ┌──────────────── node ───────┼──────────────────────────────────────────┐
 │                             ▼                                          │
 │                          agent ──▶ kernel      (load images into slots)│
 │                            │  ├──▶ supervisor  (start/stop, restarts)  │
 │                            │  ├──▶ net         (route, drain: RFD 1)   │
 │                            │  ├──▶ storage     (RFD 3)                 │
 │                            │  └──▶ attest      (quotes)                │
 │                                                                        │
 │  slot 0: web v7 (live)   slot 1: web v8 (candidate)   slot 2: (empty)  │
 └────────────────────────────────────────────────────────────────────────┘
```

## Proposals

### P1. Generic slots, and service descriptors signed with the image

Services move between nodes, so a node's manifest can't name every service that might land on
it. The manifest declares a **pool of generic slots** in a few classes, and what each may use:

```toml
[[slot_class]]
name = "small"
count = 4
memory_pages = 256
budget = 20
sends = ["net", "storage", "telemetry"]   # nothing else: no devices, no DMA

[[slot_class]]
name = "large"
count = 2
memory_pages = 4096
budget = 60
sends = ["net", "storage", "telemetry"]
```

The kernel sets up every slot's memory at boot, as it does for tasks today, so loading an image
allocates nothing. The control plane knows each node's classes and places a service only on a
node with a free slot of its class. Sizing slots from the descriptor at load time instead is
[RFD 4](0004-slots-sized-at-load.md).

What a service is allowed to do comes with its image, in a **service descriptor**, signed
together with the image:

```toml
name = "web"
version = 8
min_version = 7          # oldest version that may still run (P6)
slot_class = "small"
listen = [{ port = 80, max_connections = 64 }]   # RFD 1, P2
drain = { default_secs = 30, max_secs = 300 }
```

RFD 3 adds the descriptor's storage fields. The kernel verifies the signature when the image is
loaded (image names are already part of what is signed), and tells `net` and `storage` what the
slot holds, as it already vouches for task names.

`MAX_PROCESSES` has to grow. A node needs 11 fixed tasks (supervisor, telemetry, attest, keys,
storage, blockdev, two NIC drivers, `net`, `mgmt-net`, agent) plus its slot pool. A local swap
needs one empty slot per service being deployed at once. The table should be sized by the
manifest rather than a constant.

### P2. Loading images at run time

The agent (granted this in the manifest) loads an image and descriptor into a stopped slot
through a new syscall. The kernel:

1. verifies the signature with the same Ed25519 key as boot images
2. checks the version against the descriptor's `min_version` (P6)
3. checks the descriptor fits the slot's class
4. resets the slot (memory zeroed, as on restart)
5. measures the image and descriptor (P6); if `attest` holds the TPM lock, the syscall fails
   with `BUSY` before changing anything, and the agent retries; if the measurement log is
   full, it fails with `LOG_FULL` (P6)
6. records the descriptor, and starts the task

A refused image is reported as an event with the reason, as boot images are today.

### P3. Deployments: three flows

| Flow | When | Traffic moved by |
|---|---|---|
| **Local swap** | a new version of a service, on the node already running it | `net`'s routing table on that node (RFD 1, P3) |
| **Move** | a service changes nodes (rebalancing, or evacuating a node) | the control plane's load balancers |
| **Evacuate and update** | the kernel, a driver, `net` or the agent changes | a move for each instance, then a reboot of the empty node |

A node's image is only swapped once it has no instances (determination 1), so a node never
reboots with traffic on it. A whole-node A/B image (boot the new one, commit when healthy,
otherwise boot the old one) is still how the empty node updates. It just never runs with
instances on it.

**Local swap:**

1. The agent loads `web` v8 into an empty slot (P2).
2. The candidate starts and reports ready after its own checks. For a service with a volume,
   these include opening it ([RFD 3](0003-service-volumes.md)).
3. The agent tells `net` to make the candidate live (RFD 1, P3).
4. The old instance drains (P4).
5. The old instance stops. Its slot keeps the image until the control plane commits the
   deployment, so a rollback is the same flow with the roles reversed.

**Move** (to node B):

1. The control plane picks node B and checks its attestation.
2. B's agent loads the image into an empty slot. For a service with a volume, B's copy is
   brought up to date first ([RFD 3](0003-service-volumes.md)).
3. The candidate on B reports ready.
4. The control plane adds B to its load balancer and removes A.
5. A drains (P4) and stops. A keeps its image until the control plane commits the move.

**Evacuate and update:** the control plane moves each instance off the node. When it has none,
the agent reports it empty, and only then accepts a new node image and reboots into it. A node
with instances refuses.

### P4. The instance lifecycle and draining

The agent owns each instance's state, and reports every transition to telemetry:

```
 EMPTY ──load──▶ STARTING ──ready──▶ READY ──promote──▶ LIVE
    ▲               │                  │                  │
    │            timeout             demote             drain
    │               ▼                  ▼                  ▼
    ├──────────── FAILED            READY ◀──(abort)─ DRAINING
    └────── unload ◀── STOPPED ◀── stop ◀── DRAINED ◀─────┘
```

Draining uses RFD 1's connection draining (P4 there), with:

- **The deadline** from the descriptor's default, unless the control plane chose another for
  this deployment, at most the descriptor's maximum (determination 5; e.g. shorter for an
  urgent evacuation).
- **Storage.** For a service with a volume, the instance isn't finished until RFD 3's handoff
  is.
- **Stopping.** Once `net` reports the instance drained, the agent stops it with exit code 0,
  which the supervisor treats as "done, don't restart".

### P5. Restarting crashed services

The supervisor always restarts a crashed service (determination 4), with exponential backoff:
10 ms after the first crash, doubling to at most 30 s, reset after 60 s without a crash. This
replaces giving up after 3 restarts, which let anyone who could crash a service take it down
for good. Backoff stops a crash loop from eating the CPU. Every crash is reported as an event
with the task, the fault and the restart count. What to do beyond restarting is
[RFD 7](0007-crash-policy.md).

### P6. Attestation of what runs

- The kernel measures each image loaded at run time, with its descriptor, into a separate PCR
  (e.g. PCR 13), so a quote shows what runs now, not only what booted.
- **Sharing the TPM.** Until now the kernel used the TPM only before tasks start, and `attest`
  sends it commands directly through its mapped CRB page. The TPM runs one command at a time,
  so the kernel keeps a lock: `attest` takes it with a new `tpm_lock` syscall around each
  command and drops it with `tpm_unlock`. The kernel extends only while holding it. Extends
  don't go through `attest`, which could otherwise drop a real measurement and record a fake
  one. `attest` keeps its mapping, so it can still add entries to PCR 13, but not remove the
  kernel's: a PCR that doesn't match the kernel's log shows it. PCRs only grow, so the
  kernel keeps the event log (what was loaded, in order) for the verifier, as it does for boot
  measurements, and `attest` sends it with each quote. A log kept by the agent would be lost if
  the agent crashed, leaving the node unattestable until it reboots. The log has a fixed size
  set in the manifest (1024 entries by default, determination 7), so it needs no allocation;
  when it is full the kernel refuses further loads (`LOG_FULL`), and the control plane
  evacuates and reboots the node.
- The control plane checks a node's attestation before giving it traffic.
- **Conflict: anti-rollback vs. rollback.** Rollback versions (the `sig-rollback` test) refuse
  older images, but a rollback needs the previous version to stay loadable. Proposal: the
  descriptor's `min_version`, not the newest version seen, is what's enforced. The control
  plane only raises it, in a later release, once a deployment is committed. This stops a
  replayed command, not a compromised agent or control plane presenting an old release with its
  own descriptor: see [RFD 8](0008-deployment-threats.md).

### P7. The node agent and the control-plane interface

- **A new task, `agent`.** It is the only task allowed to load images, to send to the
  supervisor (start and stop slots) and to `net` (routing, drain, blocklists), and the only
  client of `mgmt-net`. RFD 3 adds what it sends to `storage`.
- **The node dials out** to the control plane. It accepts connections only where RFD 3's
  transfers between nodes need them, and then only from the peer the control plane named.
- **Identity.** The node proves its identity with a TPM attestation quote (the AK and quote
  code exist). The control plane proves its own with a key pinned in the measured image.
- **Commands** are signed by the control plane and carry a generation number, which makes them
  idempotent: replaying one does nothing.
- **Reconciliation.** The agent reports the state it has (slots, images, instance states, drain
  progress); the control plane sends the state it wants; the agent closes the gap. This holds
  up better than a stream of one-off commands when connections drop.
- **The channel: a Noise handshake by default** (determination 7). The node dials out and
  already knows the control plane's static key (pinned in its image), which is the Noise `IK`
  pattern. The node makes a fresh X25519 key each boot and puts its public key in the
  qualifying data of a TPM quote (the `attest` task already quotes over a nonce). That proves
  the key belongs to an attested boot of a known image, without the key ever leaving the
  node. Noise needs no heap and builds on crypto we already ship (ChaCha20-Poly1305, SHA-256,
  HKDF) plus X25519. TLS stays possible if the control plane's own RFD needs it; it would mean
  an allocator in the agent.
- **Telemetry** (RFD 1, P5) goes to the control plane through the agent.
- **Out-of-band access.** BMC/IPMI and serial-over-LAN for nodes the network can't reach.
  vanir-os's serial console already works there.

Today's vsock host agent (`tools/host-agent.py`) is a stand-in for the control plane in tests.

### P8. Telemetry

Added to RFD 1's events: instance transitions, images loaded and refused (with the reason),
crashes and restarts (with the backoff), deployments and moves committed. Added to snapshots:
slots in use per class.

## Phasing (rough; the plan will detail it)

| Phase | Delivers | Proves | Needs |
|---|---|---|---|
| D1 | restart with backoff in the supervisor (P5) | a service that keeps crashing keeps being restarted, with growing delays | — |
| D2 | run-time loading into generic slots, descriptors, measurement (P1, P2, P6) | unsigned, rolled-back, tampered or oversized images refused; ports limited to the descriptor; the quote shows the new image | RFD 1 N2 |
| D3 | the lifecycle and the local swap (P3, P4) | swap under load with no failed requests; rollback | RFD 1 N6 |
| D4 | the node agent with a mock control plane (P7) | reconciliation; drains on command; a dropped connection resumes | RFD 1 N3 |
| D5 | moves between nodes, then evacuate and update (P3) | two QEMU nodes: a service moves under load with no failed requests; a node with instances refuses to update; an evacuated node reboots into the new image and rejoins | D4 |
| later | slots sized at load (RFD 4), crash policies (RFD 7) | | |

RFD 3's phases follow D3 (volumes during a local swap) and D5 (volumes during a move).

## Open questions

None remain. Follow-ups: [RFD 4](0004-slots-sized-at-load.md) (slots sized at load),
[RFD 7](0007-crash-policy.md) (crash policy) and [RFD 8](0008-deployment-threats.md) (known
attack vectors).

## References

- [RFD 1](0001-network-services.md): network services
- [RFD 3](0003-service-volumes.md): service volumes
- [RFD 8](0008-deployment-threats.md): attack vectors in deployment
- Noise protocol framework, <https://noiseprotocol.org/noise.html>
- vanir-os manual, `docs/index.html`, in particular Supervisor and Boot chain
