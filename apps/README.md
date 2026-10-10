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
```

Tasks get ids 1, 2, ... in manifest order (programs can also find one with `lookup(name)`). The
build fails on unknown keys, duplicate names, unknown `sends` targets or device names, or more than
one supervisor or event reader. Each `devices` entry claims the next unclaimed device of that kind
at boot; a missing device is logged and the task runs without it.

Telemetry sends through the task named `uplink` if there is one (e.g. `program = "virtio-vsock"`),
otherwise through `virtio-console`.
