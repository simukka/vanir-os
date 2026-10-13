# App manifests

An app manifest lists every process the kernel runs, fixed at build time. Pick one with
`make run APP=apps/<name>.toml` (default `apps/default.toml`); tests use `tests/apps/`.

```toml
[[task]]
name = "client"        # unique task name; also the program, unless `program` is set
program = "hello"      # optional: build/<program>.elf (any program under user/)
budget = 50            # optional: CPU budget in 10 ms timer ticks (default: unlimited)
supervisor = true      # optional: this task is told when others die (at most one)
sends = ["echo"]       # optional: tasks this one may send IPC messages to
devices = ["virtio-console"]  # optional: PCI devices to drive (see kernel/src/pci_kinds.rs)
dma_pages = 16         # optional: physically contiguous DMA region, in 4 KiB pages (max 256)
events = true          # optional: may read the kernel event log and stats (at most one task)
min_version = 2        # optional: refuse images of this program signed with an older version
tpm = true             # optional: gets the TPM mapped, for attestation (at most one task)
listen = [{ port = 80, max_connections = 64, max_per_source = 16 }]
                       # optional: TCP ports it may listen on (max_connections default 64,
                       # max_per_source default max_connections; at most 8 entries)
service = "web"        # optional: the network service it is an instance of (default: its name)
routes = true          # optional: may route, drain and blocklist in the network stacks
loads = true           # optional: may load service images into slots (at most one: the agent)
connects = true        # optional: may open outbound connections through a network stack
```

Generic slots (RFD 2) run service images the agent loads at run time; see "Deployment" in
docs/index.html. A class becomes `count` table entries named `<class>-0`, `<class>-1`, ...,
after the tasks:

```toml
runtime_log = 1024     # optional, top level: run-time measurement log entries (default 1024)

[[slot_class]]
name = "small"
count = 2
memory_pages = 256     # most frames a service in it may use
image_pages = 128      # its image area: the largest image it can hold
budget = 20            # optional: CPU budget, as for tasks
sends = ["net"]        # optional: tasks its services may send to
```

Tasks get ids 1, 2, ... in manifest order (programs can also find one with `lookup(name)`). The
build fails on unknown keys, duplicate names, unknown `sends` targets or device names, or more than
one supervisor, event reader, TPM task or loader, more than 64 tasks and slots, or a port
declared by two different services. Each `devices` entry claims the next unclaimed device of that kind
at boot; a missing device is logged and the task runs without it.

Storage (see "Storage" in docs/index.html) goes by task names too: the block driver is
`blockdev`, the storage task `disk` (give it `sends = ["blockdev"]`, plus `"keys"` to fetch the key
from the key server and `"telemetry"` to report storage events), and only tasks named `keys` or
`attest` may unlock it. Each client's volume is named after the client.

Telemetry sends through the task named `uplink` if there is one (e.g. `program = "virtio-vsock"`),
otherwise through `virtio-console`.

Networks (see "Networking" in docs/index.html) go by names too: the stack `net` drives the NIC
driver `nic`, and `mgmt-net` drives `nic-mgmt` (declare the data driver first: each `devices`
entry claims the next device of its kind). Give each driver `sends = ["<its stack>"]` (it posts
`NOTIFY_RX`), each stack `sends = ["<its driver>"]` (plus `"telemetry"` for counters), and each
service `sends = ["net"]`.

`apps/service.toml` is the node `make run-service` boots (RFD 9): one service, deployed by the
agent into `small-0`. Its descriptors are in `apps/services/<program>.toml` (keys in
`tools/sign-image.py`); the slot class is `small`, so a service gets 256 frames and a 512 KiB
image.
