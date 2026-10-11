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
```

Tasks get ids 1, 2, ... in manifest order (programs can also find one with `lookup(name)`). The
build fails on unknown keys, duplicate names, unknown `sends` targets or device names, or more than
one supervisor, event reader or TPM task. Each `devices` entry claims the next unclaimed device of that kind
at boot; a missing device is logged and the task runs without it.

Storage (see "Storage" in the top-level README) goes by task names too: the block driver is
`blockdev`, the storage task `disk` (give it `sends = ["blockdev"]`, plus `"keys"` to fetch the key
from the key server and `"telemetry"` to report storage events), and only tasks named `keys` or
`attest` may unlock it. Each client's volume is named after the client.

Telemetry sends through the task named `uplink` if there is one (e.g. `program = "virtio-vsock"`),
otherwise through `virtio-console`.
