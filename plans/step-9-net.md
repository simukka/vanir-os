# Step 9 plan: network services (RFD 1)

Status: implemented (N1–N6), except the N5 attack tests (`dos-*`), which are still to write. See
"As built" at the end for where the implementation departs from this plan.

## Goal

Implement [RFD 1](../rfd/0001-network-services.md), phases N1–N6: an HTTP service in its own
task, reachable from the network through a NIC driver task and a network stack task, with a
separate management stack, traffic telemetry, DoS limits, and routing and draining between two
instances. Everything uses tasks declared in the manifest. Slots, run-time loading and the node
agent are RFD 2 and come later.

After this step:

- `curl` from the host gets a page served by a task, through virtio-net and smoltcp
- a service can only listen on ports its manifest entry declares
- a flood on the data NIC leaves the management stack answering
- interface, stack and per-instance counters reach the host agent, at an interval the host can
  change
- each attack in RFD 1's table (P6) has a test that shows it contained
- the live instance of a service can be switched under load with no failed request, and the old
  one drained, with forced closes counted at the deadline

Out of scope: RFD 2 (slots, loading, the agent, restart with backoff), RFD 3 (volumes), TLS,
UDP services, IPv6, real NICs. Nothing from this step should face a real network before step 7
(IOMMU) is done; QEMU's networks are fine for development and tests.

## What we have and what QEMU gives us

- QEMU 7.2 on the dev host. Network backends we'll use:
  - `-netdev user` (slirp) with `hostfwd=tcp:127.0.0.1:<port>-:80`: a NAT with its own DHCP
    server (guest 10.0.2.15). The host connects with ordinary sockets (`curl`, Python). Slirp
    ends TCP on the host side, so the host *can't* send raw or malformed packets through it.
  - `-netdev dgram` (new in 7.2) or `-netdev socket,udp=`: Ethernet frames carried in UDP
    datagrams to a host port. A Python tool on the host can send and receive any frame it
    likes: SYN floods, half-open connections, bad checksums. No DHCP there, so the guest needs a
    static address on this backend.
  - `-device virtio-net-pci,disable-legacy=on,addr=...`: we pin PCI addresses so the data and
    management NICs are always found in the same order.
- `user/virtio` already has the transport, queues and DMA allocator that virtio-console, vsock
  and blk use. A virtio-net driver is the same shape: RX queue 0, TX queue 1.
- `kernel/src/pci_kinds.rs` lists grantable devices; virtio-net isn't there yet.
- `MAX_PROCESSES` is 8. Two NIC drivers, two stacks, two HTTP instances, telemetry and the
  supervisor are 8 already, with nothing left for a test task.
- The vsock driver already shows how a task holds a reply until data arrives (`OP_READ`). `net`
  needs the same, for many callers.
- Test harness: each case boots once and checks the serial output, or runs a `cmd:` check over
  it. Long-running servers use a test feature to exit after N requests (as telemetry does with
  `exit-after-3-heartbeats`).

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Stack | smoltcp 0.12, `default-features = false`, features `medium-ethernet`, `proto-ipv4`, `socket-tcp`, `socket-dhcpv4` | stable Rust, no heap: `SocketSet` and buffers live in fixed arrays we own |
| NIC features | `VIRTIO_F_VERSION_1` and `VIRTIO_NET_F_MAC` only; no checksum offload, TSO or mergeable buffers | the simplest device model; smoltcp computes checksums |
| Frame buffers | 2 KiB each, 16 RX and 16 TX in the driver's DMA region (`dma_pages = 16`) | a 1514-byte frame plus the 12-byte virtio-net header fits in one buffer |
| Driver interface | `OP_SEND_FRAME` (one frame per message), `OP_RECV_FRAMES` (held until frames arrive; returns as many as fit in 4 KiB) | one IPC call per batch on receive keeps copies and context switches down |
| Port declarations | a new manifest key, `listen = [{ port = 80, max_connections = 64 }]`; the kernel stores it per task and returns it through a new syscall, `task_listen(id)` | the kernel vouches for it, as it does for task names; `net` can't be lied to by a client |
| Socket interface | `OP_LISTEN`, `OP_WAIT`, `OP_ACCEPT`, `OP_RECV`, `OP_SEND`, `OP_CLOSE`, `OP_SHUTDOWN`; handles carry a generation number | `OP_WAIT` blocks until any of the caller's sockets has something to do, so a single-threaded service runs one event loop; `OP_RECV`/`OP_SEND` then never block |
| Accepting | `net` keeps up to `max_connections` smoltcp sockets per port in the listening state | smoltcp has no accept backlog: one socket holds one connection |
| Drain notice | an event returned by `OP_WAIT`, not a kernel notification | needs no kernel change; the service only listens to `net` anyway |
| `net` event loop | `recv` with `RECV_TIMEOUT` set from smoltcp's `poll_delay`, rounded up to ticks; the clock is `uptime()` | no extra timer machinery; 10 ms resolution is acceptable for now (RFD 1, P8) |
| Addressing | DHCP by default; a static address from the test feature `static-addr` for the dgram backend | slirp provides DHCP; the raw-frame tests need a known address |
| Routing control | in this step, a test task `switcher` sends the routing and drain commands from a script (feature-gated), standing in for RFD 2's agent | no control channel yet; keeps the tests deterministic |
| Telemetry | new `telemetry::OP_NET` events, and `OP_COUNTERS` snapshots; `tools/host-agent.py` decodes both | same path as storage events in step 6 |
| Host side of tests | `tools/net-peer.py`: HTTP load (over hostfwd) and raw frames (over dgram); the Makefile runs it next to QEMU and its output is checked with the serial log | one tool for both backends |

## Sub-steps

Each sub-step is a commit with every test passing under TCG and KVM.

### N1: the virtio-net driver

- `pci_kinds.rs`: add `("virtio-net", 0x1af4, &[0x1041, 0x1000])`.
- `user/virtio-net`: negotiate `VERSION_1 | MAC`, read the MAC from device config, set up RX and
  TX queues in the DMA region, keep every RX buffer posted, MSI-X for both queues. Implements
  `OP_SEND_FRAME`, `OP_RECV_FRAMES` and `OP_INFO` (MAC, link status).
- `user/lib`: `pub mod nic` with the ops and codes.
- Makefile: `NET=user` adds a data NIC on slirp; `NET=dgram` adds it on the dgram backend.
  `NET_PORT` picks the host port for `hostfwd` (default 8080).
- Test app `nic-echo.toml`: the driver and a test task that answers ARP and ICMP echo by
  hand-building frames (no stack yet).
- Tests:
  - `nic-arp-ping` (`NET=dgram`): `net-peer.py` sends an ARP request and 20 pings, all
    answered with the right MAC.
  - `nic-restart` (driver feature `crash-after-10-frames`): the supervisor restarts the driver
    and the pings after the restart are answered too, so the device was reset cleanly.
  - `nic-no-grant`: a task without the grant gets nothing.

### N2: the stack, sockets and an HTTP service

- `user/net`: smoltcp `Interface` over a `Device` that talks to the driver by IPC. DHCP on
  start (or `static-addr`). The socket table, the handle generations, and the pending-reply
  table for `OP_WAIT` callers.
- Kernel: manifest key `listen` (parsed in `kernel/build.rs`, which rejects bad entries and two
  tasks claiming a port unless they share a `service` name); syscall `task_listen(id)`.
  `OP_LISTEN` checks the caller's id against it.
- Manifest key `service = "web"` on a task names the service it is an instance of (default: the
  task name). Only instances of one service may share a port.
- `user/http`: HTTP/1.1, `GET` and `HEAD`, keep-alive, fixed buffers. Serves `/` with the task
  name (so tests can see which instance answered) and `/count`. Feature
  `exit-after-N-requests` (N = 100) for tests.
- `MAX_PROCESSES` goes to 16 here: N3 and N6 need more than 8 tasks.
- Tests:
  - `http-get` (`NET=user`): `net-peer.py` does 100 GETs over keep-alive and 100 over new
    connections; all return 200 with the right body.
  - `http-undeclared-port` (http feature `listen-81`): `OP_LISTEN` on port 81 is refused with
    `CODE_NOT_ALLOWED` and logged; port 80 still works.
  - `http-port-clash`: two different services declaring port 80 are rejected by `build.rs`.
    This never boots, so it can't be a boot case. `make test` gets a small build-check stage
    for manifests that must fail, with the expected message.
  - `net-restart` (net feature `crash-after-50-requests`): `net` is restarted, DHCP runs again,
    HTTP reopens its listener (it sees `DEAD` and finds `net` again by name), and the client's
    later requests succeed. Requests in flight at the crash fail, which the case allows.
  - `http-restart`: the same for the HTTP task.

### N3: the management stack

- A second NIC (`NET_MGMT=user`, its own `hostfwd` port) with its own `virtio-net` and `net`
  tasks, named `nic-mgmt` and `mgmt-net`. Same programs, different manifest entries.
- A test task `mgmt-echo` on `mgmt-net` (port 7), standing in for the agent.
- Tests:
  - `mgmt-separate`: GETs on the data port and echoes on the management port both work, and
    `mgmt-echo` can't reach `net` (not in its `sends`), nor HTTP `mgmt-net`.
  - `mgmt-under-flood` (`NET=dgram`, `NET_MGMT=user`): `net-peer.py` floods the data NIC with
    frames while echoing on the management port; every echo is answered within 1 s. The data
    stack's CPU budget and drops are visible in the output.

### N4: counters and events

- `net` and the driver keep RFD 1's counters (P5): interface, `net`, per instance, protection
  (filled in by N5). HTTP keeps requests by status class and a fixed-bucket latency histogram.
- Snapshots go to telemetry (`OP_COUNTERS`) every second; telemetry forwards them as JSON lines.
  Events (`OP_NET`): routing changes, drains, limits tripped, attacks suspected.
- The host can set the interval: a `set_interval` message from the host agent over vsock (the
  only channel to the host that carries data both ways today), applied by telemetry, bounded to
  100 ms–60 s.
- Tests:
  - `net-counters`: after `net-peer.py` transfers a known number of bytes in a known number of
    requests, the snapshot's counters match (within the TCP and HTTP header overhead, which the
    case computes).
  - `net-interval` (`TRANSPORT=vsock ACCEL=kvm`): the host sets 200 ms; snapshots arrive at that
    interval (checked from their uptime stamps).

### N5: limits and detection

The limits from RFD 1's table (P6), each with a test driven by `net-peer.py` over the dgram
backend unless noted:

| Test | Attack | Pass when |
|---|---|---|
| `dos-syn-flood` | 10,000 SYNs from many source addresses, never completed | half-open count stays at the cap; a real client connects during the flood; `attack_suspected` raised with top talkers |
| `dos-conn-exhaust` | one source opens connections until refused | that source is capped by the per-source limit; another source still connects |
| `dos-slowloris` (`NET=user`) | 60 connections sending a header byte a second | each is closed at the header deadline; normal requests succeed meanwhile |
| `dos-big-request` (`NET=user`) | a 64 KiB header, then a 10 MiB body | 431 and 413; the service keeps serving |
| `dos-packet-flood` | line-rate garbage frames | `net` stays within its budget; drops counted; HTTP still answers (slowly) |
| `dos-blocklist` | a source on a blocklist set by the switcher task | its SYNs are dropped before socket lookup and counted as blocklist hits |

- Packet floods: when a receive batch is full, `net` masks the driver's RX interrupt and polls
  until the ring drains (a mode flag in `OP_RECV_FRAMES`), then unmasks.
- Top talkers: a 32-entry Space-Saving sketch, reset at each snapshot.
- Negative checks, as in earlier steps: raise each limit to "unlimited" in a scratch build and
  confirm its test fails.

### N6: routing and draining

- `net`'s routing table (RFD 1, P3): per service, the live instance. `OP_READY` from an instance
  (only then can it be made live), `OP_ROUTE` (make an instance live), `OP_DRAIN` (with a
  deadline in ticks) from tasks allowed to: in this step, the test task `switcher`, later RFD 2's
  agent. A manifest flag `routes = true` grants it, checked by the kernel like `supervisor`.
- Draining (RFD 1, P4): no new connections; a drain event through `OP_WAIT`; HTTP answers with
  `Connection: close` and stops accepting; RST at the deadline, counted as `drain_forced`; the
  instance says it has finished (`OP_DONE`), then `net` reports drained to `switcher`.
- Test app `blue-green.toml`: `web-1` and `web-2` (both `service = "web"`), `switcher` with
  feature scripts.
- Tests:
  - `swap-under-load`: `net-peer.py` keeps 8 keep-alive clients requesting; `switcher` makes
    `web-2` live after 200 requests and drains `web-1`. No request fails; responses switch from
    `web-1` to `web-2`; `web-1` drains before its deadline with `drain_forced` = 0.
  - `drain-deadline`: one client holds a connection open without sending; `web-1` is drained
    with a 2 s deadline; the connection is reset at the deadline and `drain_forced` = 1.
  - `route-not-ready`: making an instance live before it said ready is refused.
  - `route-not-allowed`: a task without `routes = true` gets `CODE_NOT_ALLOWED`.
- Manual (docs/index.html): a Networking section (drivers, stacks, sockets, routing and draining,
  limits, telemetry), the new manifest keys and syscall, `NET`/`NET_MGMT`/`NET_PORT`, the test
  catalogue, the repo map, and agent notes in `docs/llms.txt`. README status: step 9.

## Risks and how we'll know

- **smoltcp without alloc.** Its `no_std` support without a heap is documented, but each
  `SocketSet` entry and buffer must be a fixed array. `net`'s memory use is printed at start and
  checked against its manifest limit in N2.
- **IPC cost.** Every packet crosses the driver and `net`, and every HTTP byte crosses `net` and
  the service, with 4 KiB per message. N2 measures requests per second under TCG and KVM; if
  it's far too slow, step 8's benchmarks look at leases (RFD 1, P8) before N5.
- **Timer resolution.** 10 ms ticks make TCP's delayed ACK and retransmit timers coarse. Watch
  for stalls in `http-get` under TCG; smoltcp's ACK delay can be turned off.
- **Slirp limits.** Slirp is slow and does its own TCP, so it can't show raw-packet behaviour.
  Everything attack-shaped uses the dgram backend.
- **Device order.** Two virtio-net devices are claimed in PCI order. Pinned addresses make that
  stable; if not, add a device index to `devices` grants (`"virtio-net#1"`).
- **Test time.** Flood and drain tests run for seconds. Keep each under 20 s with TCG, and tag
  the slow ones so `ONLY=` can skip them during development.
- **Supervisor gives up after 3.** `net-restart` and `http-restart` restart once, so they're
  unaffected; restart with backoff is RFD 2's D1.

## As built

Commits: N1 `8e7d526`, N2 `1e88b9b`, N3 `9ce4490`, N4 `5608138`, N5 `1d28bcd` (limits without
their tests), N6 `ff87a78`. The manual's Networking section describes the result.

Where it departs from the plan:

- **Two more syscalls and a recv mode.** `notify(target, bits)` lets the NIC driver tell `net`
  that frames arrived without sending to it (if both sent to each other they could deadlock);
  receivers get `NOTIFY_POST`. `halt(code)` lets the supervisor end a run; with its
  `halt-on-exit` feature, tests end when any task exits. `recv` with a zero timeout only polls.
  `task_listen` returns the service name and the `routes` flag along with the ports.
- **`OP_RECV_FRAMES` never waits.** When a call empties the ring, the driver turns its receive
  interrupt on and posts `NOTIFY_RX` at the next frame; until then the client polls. This is
  the NAPI mode the plan put in N5, from N1 on, instead of a held reply plus a mode flag.
- **Ending tests.** HTTP's test feature is `exit-on-request` (the peer's `GET /exit`), not
  `exit-after-N-requests`, so each scenario ends the run when it is done. `net`'s crash feature
  counts connections handed out (`crash-after-50-connections`).
- **CPU budget.** `net` may spend half of each tick on received frames, measured with the TSC
  (time preempted counts too), from N3 on.
- **Counters.** smoltcp doesn't expose retransmits or its ARP cache, so those are missing; we
  count IPv4 checksum failures and segments for unused ports ourselves, before smoltcp.
- **Per-source cap.** Counted over the 96-socket table at each SYN rather than a separate hash
  table: the table holds exactly the connections that count.
- **Half-open cap.** A burst of SYNs gets more listening sockets, up to 16 handshakes per port,
  before the oldest handshake is dropped; dropping at 4 (the listening sockets) failed real
  clients connecting together (found by `swap-under-load`).
- **`static-addr`** applies only to the task named `net`, so the management stack keeps DHCP.
- **Draining.** HTTP doesn't close idle connections when told to drain (closing one as its
  client sends would fail that request); it answers each connection's next request with
  `Connection: close`. `drain-deadline` holds an idle connection.
- **Switcher scripts are timed** (3 s after `web-1` is live) rather than counting 200 requests.
- **Not done:** the `dos-*` tests and the negative checks for each limit.
