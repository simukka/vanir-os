<p align="center"><img src="logo.png" alt="vanir-os" width="560"></p>

A minimal x86-64 kernel in stable Rust, booted by [Limine](https://github.com/limine-bootloader/limine).
In the style of Oxide's [Hubris](https://hubris.oxide.computer/), a fixed set of tasks is declared
at build time. Each task runs isolated in ring 3, and tasks talk only by synchronous messages.
Drivers, the supervisor, telemetry, attestation and encrypted storage are ordinary tasks.

**Documentation:** [the vanir-os manual](https://simukka.github.io/vanir-os/) ([`docs/index.html`](docs/index.html))
explains each layer from scratch, then covers the full reference and how to work on the code.
Coding agents should start with [`docs/llms.txt`](docs/llms.txt).

## What it does

- Per-task page tables, with SMEP, SMAP, NX and W^X. A fault kills the task, not the system.
- A 100 Hz preemptive scheduler with CPU budgets.
- Send/receive/reply IPC with a per-task allowlist. Restarted tasks get a new task id, so old ids stop working.
- A supervisor task that decides which failed tasks to restart.
- Unprivileged driver tasks for virtio console, vsock and block devices, using device grants, MSI-X interrupts and DMA regions.
- Kernel events streamed to a host agent as JSON lines.
- Signed task images, a UEFI Secure Boot chain, measured boot into a TPM, and remote attestation.
- An encrypted volume for each task (XChaCha20-Poly1305). The host releases the key only to an attested boot.
- TCP services: a virtio-net driver task, a network stack task (smoltcp) limited to the ports each
  service declares, separate data and management networks, traffic counters, and switching a
  service's live instance under load with draining.
- Deployment: signed service images loaded into generic slots at run time and measured into the
  TPM, swaps and rollbacks under load, restarts with backoff, and a node agent that dials an
  attested control plane over Noise to move services between nodes and update empty ones.

There are 123 boot tests, and each protection has one that proves it. They pass under both QEMU's
emulator and KVM.

## Quick start

```sh
sudo apt install make git gcc binutils xorriso qemu-system-x86 \
    python3-cryptography ovmf sbsigntool swtpm swtpm-tools
rustup target add x86_64-unknown-none   # stable Rust; nightly isn't needed

make run                                # build and boot in QEMU
make test                               # run all 123 test scenarios
make test ACCEL=kvm                     # the same under KVM
make run APP=tests/apps/storage.toml DISK=1   # choose a set of tasks; attach a disk
```

Limine is downloaded on the first build. The [manual](docs/index.html#build) covers the build
options, exit codes and test format, and the [dependencies](docs/index.html#dependencies) in full.

## Status

This is a learning project, built step by step. Steps 1–6 are done: hardening; processes and
scheduling; IPC and a supervisor; drivers and telemetry; signed and measured boot; storage.
Step 9, network services ([`plans/step-9-net.md`](plans/step-9-net.md)), is done except its
attack tests. Step 10, deployment ([`plans/step-10-deploy.md`](plans/step-10-deploy.md)), is
done: services loaded into slots at run time, swapped, rolled back and moved between nodes by a
node agent that answers to an attested control plane. Still to come: the IOMMU ([`plans/step-7-iommu.md`](plans/step-7-iommu.md)), which
any real network use needs first, and benchmarks ([`plans/step-8-bench.md`](plans/step-8-bench.md)). The manual lists the
[known limitations](docs/index.html#limitations).
