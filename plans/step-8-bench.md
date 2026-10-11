# Benchmark plan: vanir-os vs Ubuntu Server

Status: planned, not implemented.

## Goal

Reproducible numbers comparing vanir-os with Ubuntu 24.04 on the operations both systems can
perform today. Both run under identical KVM settings, timings are in CPU cycles, and pass/fail
criteria are fixed before the first run.

This is a microbenchmark comparison, not proof of server-equivalent performance. vanir-os has one
process, a handful of syscalls, and no timer, network or disk yet. The comparison widens as the
roadmap adds features (see [Later metrics](#later-metrics)).

## Fairness rules

- **KVM, not emulation.** `make test` uses QEMU's software emulator, where timings are meaningless.
  Benchmarks use `-enable-kvm -cpu host`.
- **Identical VM settings** for every guest: `-M q35 -smp 1 -m 1G`, QEMU pinned to one host core
  with `taskset`.
- **Host tuning (optional, needs sudo):** performance CPU governor, turbo off. Results record
  whether the host was tuned.
- **Clock:** the CPU cycle counter, read with serialising instructions
  (`lfence; rdtsc` … `rdtscp; lfence`). The development host has a constant-rate TSC.
- **Statistics:** 1,000 warm-up iterations, then 100,000 timed iterations. Report min, median,
  p99 and max; never the mean alone. Each guest boots 5 times and the median run is reported.
- **Mitigations:** the development CPU (i7-7500U) is Meltdown-affected, so Linux runs with KPTI
  and every syscall switches page tables. vanir-os has no KPTI yet. Every Linux guest runs with
  both `mitigations=auto` and `mitigations=off`, and results always list vanir's missing
  mitigations next to its numbers. A vanir syscall "win" on this CPU is partly the cost of a
  protection it doesn't have.

## Metrics

| Metric | vanir-os | Linux |
|---|---|---|
| Syscall round-trip, `int 0x80` (like-for-like) | `getpid` (syscall 39) via `int 0x80` | `getpid` via `int 0x80` (`eax=20`, 32-bit ABI) |
| Syscall round-trip, native | — | `getpid` via `syscall` |
| Recovered fault (indicative only) | `write` from an unmapped buffer | `SIGSEGV` handler that recovers |
| Boot to first user instruction | QEMU start → first `BENCH` line | same, minimal Linux and full Ubuntu |
| Memory footprint | guest memory in use with the process running | same |

The fault row is not like-for-like: Linux delivers a signal, vanir returns an error from a syscall.
If the Ubuntu kernel has 32-bit compatibility disabled, the Linux `int 0x80` row is reported as
`unsupported`.

## Implementation

### 1. Let the kernel embed different user programs
- Makefile: `USER_PROG ?= hello` builds `user/$(USER_PROG)` and copies it to `build/user.elf`, which
  the kernel embeds (replacing `build/hello.elf`).
- Add syscall 39 `getpid` (returns 1), the same number Linux uses.

### 2. `user/bench`: the vanir benchmark program
- Times each `getpid` call, subtracting the measured cost of an empty timed section.
- Samples go into a static array, are sorted with `core`'s `sort_unstable`, and print as one line:
  `BENCH syscall_int80 n=100000 min=… p50=… p99=… max=…` (cycles).
- Same format for the recovered-fault measurement.

### 3. `bench/linux/bench.c`: the Linux equivalent
- Statically linked; same loop, warm-up, overhead subtraction and output format.
- Measures `getpid` via `syscall`, via `int 0x80`, and a recovered `SIGSEGV`.

### 4. Guests: `bench/fetch.sh`
- Downloads the Ubuntu 24.04 (noble) cloud image and the matching `vmlinuz`/`initrd` from
  `cloud-images.ubuntu.com/noble/current/unpacked/`, verified against `SHA256SUMS`, into
  `bench/images/` (gitignored, about 600 MB).
- **Minimal Linux:** Ubuntu's kernel plus a `cpio` initramfs whose `/init` is the benchmark.
  Isolates kernel cost; the fair boot-time comparison.
- **Full Ubuntu Server:** the cloud image booted with `-kernel`/`-initrd` so the command line
  (including `mitigations=`) is controlled. A cloud-init NoCloud seed disk (built with `xorriso`,
  volume label `cidata`) runs the benchmark from `runcmd` and powers off.
- Each Linux guest records `/sys/devices/system/cpu/vulnerabilities/*` alongside its results.

### 5. Runner: `bench/run.py` and `make bench`
- Boots every guest with the shared QEMU settings, timestamps each serial line on the host, and
  parses `BENCH` lines.
- Writes raw results to `bench/results/<date>.json` and regenerates the table in
  `bench/RESULTS.md`, recording CPU model, host kernel, QEMU version, guest kernel version,
  mitigation status and host tuning.
- `bench/tune-host.sh` applies the optional host tuning (run by the user, needs sudo).

### New host dependencies
`python3`, `cpio`, and `gcc` with static glibc (`libc6-dev`, which provides `libc.a`); all are
present on the development host. `cloud-localds` is not needed; `xorriso` builds the seed disk.

## Pass/fail criteria (proposed; confirm before the first run)

1. vanir `int 0x80` median ≤ Ubuntu `int 0x80` median, with `mitigations=auto`.
2. vanir boot-to-user time ≤ minimal Linux boot-to-user time.
3. Every published result lists vanir's missing mitigations (currently KPTI) next to it.

## Done when

`make bench` produces `bench/RESULTS.md` from a clean checkout, and five consecutive runs agree
within ±5% at the median.

## Later metrics

| Metric | Needs |
|---|---|
| Context switch, process spawn | step 2 (scheduler) |
| IPC round-trip vs pipes/futexes | step 3 (IPC) |
| Network throughput (`iperf3`) | step 4 (virtio-vsock/net) |
| Disk throughput (`fio`) | step 6 (virtio-blk) |
| The real application workload | the target deployment |

After step 2, re-run the suite to measure the cost of `CR3` switches and timer interrupts; PCID is
deferred until those numbers show the need.

## Open decisions

- Pass/fail thresholds above (proposed, not yet agreed).
- Approval of the ~600 MB image download.
