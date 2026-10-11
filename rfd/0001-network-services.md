---
rfd: 1
title: Network services
state: discussion
authors: simukka
date: 2026-10-11
labels: networking, telemetry, security
---

# RFD 1: Network services

## Summary

vanir-os will run network services on dedicated servers, VMs and blades, with a control plane
managing them. This RFD proposes the node's network:

- NIC driver tasks and network stack tasks (smoltcp), separate for the management and data
  networks, with services in tasks of their own, each isolated as tasks are today
- a socket interface for services, limited to the ports each service declares
- routing a service's port to one of its instances, and draining an instance's connections,
  which deployments build on
- traffic telemetry, and protections against abuse and denial of service

Two other RFDs build on this one:

- [RFD 2](0002-deployment.md), deployment: slots, run-time loading, blue-green swaps, moves,
  the node agent and the control-plane interface
- [RFD 3](0003-service-volumes.md), service volumes: handoff, transfer and replication

This RFD records the reasoning behind the design. The step plan (`plans/step-9-net.md`) comes
once it has been discussed.

## Determinations

Decided in discussion (2026-10-11):

1. **Management and data traffic use separate network stacks**, each with its own NIC driver
   task and NIC (P1).
2. **TCP only.** UDP services (DNS, QUIC) are out of scope.
3. **NICs: virtio-net only.** Real NIC drivers wait until the target hardware is known. The NIC
   driver task's interface (P1) is the only commitment.
4. **Draining is best effort, up to a deadline.** Connections still open at the deadline are
   terminated (P4). Letting services ask clients to reconnect earlier is a follow-up:
   [RFD 6](0006-reconnect-hints.md).
5. **Counter snapshots default to one a second, and the control plane can change the
   interval** per node (P5). Adaptive snapshots are a follow-up:
   [RFD 5](0005-adaptive-telemetry.md).
6. **Until a control plane exists, the RFDs set the defaults** for what it will later choose.
   Here: a snapshot interval of 1 s. RFD 2 lists the others.

## Background

### What exists today (steps 1–6)

- A fixed set of tasks, declared in a manifest at build time and loaded as signed boot modules.
- Send/receive/reply IPC with a per-task `sends` allowlist. Messages are at most 4 KiB
  (`MAX_MESSAGE`).
- Driver tasks for virtio console, vsock and block devices, each with a device grant, MSI-X
  interrupts and a DMA region.
- A telemetry task that sends JSON lines over vsock to a host agent.

### Constraints that matter here

| Constraint | Today | Why it matters for networking |
|---|---|---|
| Tasks | `MAX_PROCESSES = 8` | two NIC drivers and two stacks take half of that (RFD 2 grows it) |
| IPC | copies, at most 4 KiB a message | each packet is copied several times; this limits throughput |
| CPU | one core | the stacks and every service share it |
| Time | 100 Hz ticks and uptime only; no wall clock | 10 ms TCP timer resolution; TLS certificates and logs need real time |
| DMA | no IOMMU yet (step 7) | a compromised NIC driver could DMA anywhere in RAM |

## Goals

1. Serve TCP (HTTP first) from a task, reachable from the network.
2. Contain faults and compromise the way the rest of vanir-os does: a bug in packet parsing
   compromises the stack task, not the kernel or other services.
3. Give deployments (RFD 2) what they need from the network: moving a service's new
   connections to another instance in one step, and draining the old instance's connections.
4. Report traffic well enough that the control plane can decide where traffic goes, and notice
   when a node is under attack.
5. Keep each step testable under QEMU (TCG and KVM), with a test proving each protection, as
   in earlier steps.

## Non-goals

- Deployment: slots, loading images, swaps and moves ([RFD 2](0002-deployment.md)).
- Storage ([RFD 3](0003-service-volumes.md)).
- The control plane and the fleet's load balancers.
- TLS. The design leaves room for a TLS task, but choosing a library and managing certificates
  are separate decisions.
- IPv6 at first, though nothing should rule it out.
- UDP services (determination 2) and real NIC drivers (determination 3).
- Absorbing volumetric DDoS. That has to happen upstream (P6).

## Terminology

- **Node:** one machine running vanir-os, whether a server, VM or blade.
- **Management network:** how a node talks to the control plane. **Data network:** how clients
  reach services.
- **Service:** a named network function, e.g. `web`, listening on one or more ports.
- **Instance:** a task running a service. A service can have more than one instance on a node
  during a deployment (RFD 2).
- **Live instance:** the instance `net` gives a service's new connections to.
- **Drain:** stop giving an instance new connections, and let it finish its current ones.

## Architecture

```
                          control plane
                               │ management network
 ┌──────────────── node ───────┼──────────────────────────────────────────┐
 │                             ▼                                          │
 │  nic-mgmt ◀──▶ mgmt-net ◀──▶ agent (RFD 2)                             │
 │                                 │ route, drain, blocklist              │
 │                                 ▼                                      │
 │  nic-data ◀──▶ net (smoltcp) ◀──┬──▶ web instance 1 (live)             │
 │   DMA/IOMMU      sockets,       └──▶ web instance 2 (draining)         │
 │                  routing,                                              │
 │                  limits,                                               │
 │                  counters ──▶ telemetry                                │
 └────────────────────────────────────────────────────────────────────────┘
```

Only service instances talk to `net`, and only the agent talks to `mgmt-net` and tells `net`
how to route.

## Proposals

### P1. Driver and stack are separate tasks, and each network has its own

- **NIC driver task:** a virtio-net driver built on the virtio-blk pattern, with RX and TX
  queues in its DMA region. Its interface is "send frame" and "receive frame". It knows nothing
  about IP, so moving to another NIC only replaces this task.
- **Network stack task (`net`):** smoltcp builds on stable Rust, needs no heap (sockets use
  fixed buffers we provide), and handles ARP, IPv4, TCP and DHCPv4 (which runs over UDP inside
  `net`; services get TCP only). This task owns every socket and enforces who may use which.
- **Service tasks:** each talks to `net` over IPC and has no device, DMA region or raw
  sockets.

**Two stacks** (determination 1). Each network gets its own NIC, driver task and stack task,
built from the same code with different manifests:

- `mgmt-net` serves only the agent: control-plane traffic, and transfers between nodes
  (RFD 3).
- `net` serves only services. It is the one exposed to clients.

A flood or a compromise of the data stack can't touch the management stack's memory, CPU budget
or sockets, so the control plane can still reach the node to drain or withdraw it. On a VM this
means two virtio-net devices. On hardware it means two ports, or a dedicated management NIC.

Alternatives considered:

- *A stack in the kernel:* this is fastest, but it puts the code that parses the most untrusted
  input in ring 0, against the main rule of this project.
- *A stack in each service:* this keeps a service's sockets private to it, but several stacks
  sharing one NIC need a demultiplexer below them that does most of a stack's work anyway.
- *Stack and driver in one task:* this saves one copy per packet, but a driver bug would then
  expose the stack's sockets and a stack bug would expose the DMA region. We'd only merge them
  if benchmarks show the copy matters.
- *One stack for both networks:* this needs fewer tasks, but the control plane would then lose
  its route to a node exactly when the node is under attack. Rejected.

Hubris has the same split: its `net` task wraps smoltcp with sockets declared in the
manifest (UDP only there).

### P2. Sockets, limited to declared ports

A service declares the ports it listens on:

```toml
listen = [{ port = 80, max_connections = 64 }]   # TCP
```

In this RFD's phases the declaration is in the manifest, as for any task. RFD 2 moves it into a
service descriptor signed with the image. Either way, the kernel vouches for which task holds
which declaration, as it already vouches for task names. `net` lets an instance bind only its
service's ports, and only instances of the same service can share a port. Socket buffers come
from a fixed pool in `net`, sized at build time.

The IPC interface is `OP_ACCEPT`, `OP_RECV`, `OP_SEND`, `OP_CLOSE` and `OP_SHUTDOWN`. Each call
carries a connection handle, and handles include a generation number so a stale one can't name
someone else's connection. This works the same way as task ids.

### P3. Routing a service to its live instance

`net` keeps a routing table: for each service, which instance is live. New connections to the
service's ports go to the live instance. Existing connections stay with the instance that
accepted them. Changing the live instance is one atomic update to the table, so no new
connection is lost or sent to the wrong instance. Only the agent may change the table.

An instance only becomes live after it says it is **ready** (its own checks passed), so `net`
never routes to an instance that can't serve yet. Readiness is separate from liveness: the
supervisor knows whether a task is alive; only the service knows whether it is ready.

### P4. Draining an instance's connections

1. `net` stops giving the instance new connections. New SYNs for the port go to the live
   instance, or get a RST if none is live.
2. `net` notifies the instance (`NOTIFY_DRAIN`, a kernel-style notification through IPC). The
   service finishes the requests in flight. It answers further requests on keep-alive
   connections with `Connection: close`, and stops accepting.
3. Each connection ends either when the client closes it, or at the deadline the agent gave
   with the drain (determination 4). At the deadline `net` sends a RST and counts it as
   `drain_forced`.
4. The instance tells `net` when it has finished its work. With no connections left and the
   instance finished, `net` reports it drained to the agent.

Long-lived connections (WebSockets, streaming) never finish by themselves, so the deadline ends
them. Asking clients to reconnect sooner is [RFD 6](0006-reconnect-hints.md). Where deadlines
come from, and what happens to a drained instance, is RFD 2.

### P5. Telemetry

Counters are kept on the node, and rates are computed by the control plane. Each counter is a
cumulative u64, sent in a snapshot along with the boot id and the uptime in ticks. Snapshots
go out once a second by default, and the control plane can set another interval per node, e.g.
faster while investigating a problem, within limits the node enforces. A restarted task's
counters start at zero again, which the control plane detects from the restart event.

| Scope | Counters |
|---|---|
| Interface | rx/tx bytes, rx/tx packets, drops when the ring is full, errors, multicast/broadcast |
| `net` task | socket table use, ARP entries, retransmits, checksum failures, packets with no matching socket, CPU budget used |
| Service, per instance | connections accepted, refused, reset, open now; bytes in/out; drain state; `drain_forced` |
| Service (HTTP) | requests by status class (2xx, 4xx, 5xx); a latency histogram with fixed buckets |
| Protection | SYNs, half-open connections, connections dropped by limits, blocklist hits, top talkers (P6) |
| Management stack | the same interface and `net` counters, kept separately, so data-network load is visible apart from control traffic |

Events (state changes) stay separate from counters: routing changes, drains started and
finished, limits tripped, attacks suspected. Events are reported each time they happen, and
counters only in snapshots.

**Bandwidth** comes from interface and instance byte counters. Per-client bandwidth is only
tracked for top talkers, as tracking every client doesn't fit in fixed memory.

**Transport.** In tests, telemetry keeps going over vsock. In a fleet, it goes over the
management network through the agent (RFD 2). Logging every packet is a non-goal, as it would
cost more than the traffic.

### P6. Denial of service

What a single node can and can't do needs to be explicit:

- **A node can't absorb a volumetric attack.** Traffic that fills the link is gone before
  `net` sees it. Volumetric defence happens upstream (provider scrubbing, the control plane
  withdrawing the node, anycast). This RFD only promises that the node reports what it sees.
- **The node must survive what reaches it.** Its memory is fixed, so it can't run out of
  memory. It *can* run out of socket slots, CPU or restarts, and each needs a limit:

| Attack | Limit |
|---|---|
| SYN flood (smoltcp has no SYN cookies) | a cap on half-open connections per port; a short handshake timeout; oldest half-open dropped first |
| Connection exhaustion | `max_connections` per service; a per-source cap in a small fixed hash table |
| Slowloris (slow headers or bodies) | deadlines for headers and the body in the HTTP task; an idle timeout in `net` |
| Large requests | a size cap for headers and bodies; refused with 431 or 413 |
| Packet flood to `net` | a CPU budget for `net`; interrupts masked and the ring polled under load, as Linux's NAPI does; drops counted |
| Crash loops (a request that crashes a service) | the supervisor always restarts, with backoff ([RFD 2](0002-deployment.md)), so crashing a service never takes it down for good |
| Starving the management plane | management on its own NIC and stack (determination 1), so a flood on the data network doesn't cut off the control plane |

- **Detection on the node stays simple.** Fixed thresholds on SYN rate, the half-open ratio,
  new connections per second and drops raise an `attack_suspected` event with top talkers. Top
  talkers come from a fixed-size heavy-hitter sketch (e.g. Space-Saving with 32 entries), which
  needs no heap.
- **The control plane decides; the node enforces.** The control plane sees every node, so it
  tells real attacks from busy days, and pushes a fixed-size CIDR blocklist (with expiry) that
  `net` applies before any socket lookup.

### P7. Hardware

- **NICs.** virtio-net only for now (determination 3). Dedicated servers and blades will need
  real NIC drivers (Intel e1000e or i40e, Mellanox ConnectX, Broadcom, ...), chosen once the
  target hardware is known. Each is a large driver, and only e1000e can be tested under QEMU.
- **The IOMMU (step 7) comes first.** A NIC driver handles bytes from the network. Without DMA
  confinement, compromising it compromises the node.
- **Addressing.** DHCP on both networks, with the control plane able to pin addresses. Whether
  nodes need a DNS resolver is open.
- **Time.** The control plane provides wall-clock time (or NTP does), for logs and later
  certificates.

### P8. Performance

- **Copies.** A received byte is copied from DMA to the driver, then to `net`, then to the
  service, at most 4 KiB per IPC. If step 8's benchmarks show the copies matter, the fix is
  Hubris-style *leases* (a sender lends a buffer that the receiver reads or writes directly)
  rather than shared memory.
- **One core, 100 Hz.** TCP timers get 10 ms resolution and the services share one core. This
  is fine at first. SMP and finer timers are separate work.

## Phasing (rough; the plan will detail it)

None of these phases need RFD 2: they use tasks declared in the manifest, as today.

| Phase | Delivers | Proves |
|---|---|---|
| N1 | virtio-net driver | frames in and out; driver restart doesn't hang the device |
| N2 | `net` task (smoltcp, DHCP), sockets limited to declared ports (P2), an HTTP task, `hostfwd` tests | `curl` gets 200; an undeclared port is refused; `net` and HTTP restarts recover |
| N3 | a second instance as `mgmt-net` on its own NIC | a flood on the data NIC leaves the management stack reachable |
| N4 | counters and events (P5), interval set by the host | numbers match a known transfer; a changed interval takes effect |
| N5 | limits and detection (P6) | each attack in the table has a test that is contained |
| N6 | routing and draining (P3, P4), with two instances declared in the manifest and the host agent standing in for RFD 2's agent | switch the live instance under load with no failed requests; deadline enforced and counted |

Dependencies: step 7 (IOMMU) before any NIC is used on a real network, and step 8 (benchmarks)
should cover N2.

## Open questions

None remain. Everything raised is decided (see [Determinations](#determinations)) or belongs to
another RFD:

| RFD | Topic |
|---|---|
| [2](0002-deployment.md) | deployment: slots, run-time loading, swaps, moves, node agent |
| [3](0003-service-volumes.md) | service volumes: handoff, transfer between nodes, replication |
| [4](0004-slots-sized-at-load.md) | slots sized from the descriptor at load time |
| [5](0005-adaptive-telemetry.md) | adaptive telemetry snapshots |
| [6](0006-reconnect-hints.md) | asking clients to reconnect before a drain deadline |
| [7](0007-crash-policy.md) | policies for services that keep crashing |

## References

- Hubris: the `net` task and manifest-declared sockets, <https://hubris.oxide.computer/>
- smoltcp, <https://github.com/smoltcp-rs/smoltcp>
- Oxide's RFD process, <https://rfd.shared.oxide.computer/rfd/0001>
- vanir-os manual, `docs/index.html`, in particular Drivers and Telemetry
- `plans/step-7-iommu.md` and `plans/step-8-bench.md`
