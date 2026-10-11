# Step 7 plan: IOMMU (Intel VT-d DMA remapping)

Status: planned, not implemented.

## Goal

A driver task's device can reach its own DMA region and nothing else. Today a driver programs
its device with physical addresses, and nothing stops it from pointing the device at kernel
memory, another task's memory, or the storage task's master key. The README lists this as a
limitation in Drivers, Boot chain and attestation, and Storage. After this step:

- the kernel turns on VT-d DMA remapping before any driver runs
- every granted device gets its own translation table, mapping only its task's DMA region
- devices without a grant can't DMA at all
- a blocked DMA is logged as a kernel event, and the driver that caused it is killed (the
  supervisor restarts it like any crash)
- PCR 12 records whether the IOMMU was on, so the host can refuse to release keys to a boot
  without it

Out of scope: interrupt remapping, ATS/device TLBs, scalable mode, AMD-Vi, giving a device more
than one region, letting drivers change their mappings at run time.

## What we have and what QEMU gives us

- QEMU 7.2 on the dev host: `-device intel-iommu` (q35 only; both boot paths already use q35).
  Defaults: `aw-bits=39`, so second-level tables are 3 levels; `intremap=auto`. We pass
  `intremap=off`: interrupt remapping under KVM needs `kernel-irqchip=split`, and we don't need
  it for DMA protection. The IOMMU device must come before the devices it translates on the
  command line.
- QEMU publishes one DMAR table with one remapping unit (DRHD) whose scope is "all PCI devices"
  (`INCLUDE_PCI_ALL`). Real hardware has several units with explicit device scopes; we parse
  both forms but only test the first.
- The kernel already knows each granted device's bus/device/function (PCI discovery), each
  task's DMA region (physically contiguous, pinned, the same pages for the life of the slot),
  and how to map MMIO pages uncached into the kernel (the TPM CRB page).
- There is no ACPI code yet. Limine hands us the RSDP (`RsdpRequest`).

## Design decisions

| Decision | Choice | Why |
|---|---|---|
| Device addresses (IOVA) | identity: IOVA = the region's physical address | drivers and `dma_info` stay unchanged; the IOMMU only decides what is reachable |
| Domains | one per granted device, its own second-level table | a compromised device can't reach another driver's region |
| Ungranted devices | no context entry, so every DMA faults | default deny |
| Table format | legacy mode (root + context tables), second-level paging, 3 or 4 levels from `CAP.SAGAW` | simplest mode QEMU and real VT-d both support |
| Invalidation | register-based (CCMD, IOTLB registers), no queued invalidation | mappings are set once at boot; nothing changes at run time |
| Fault reporting | fault event MSI to a kernel vector; read and clear the fault recording registers | prompt, and no polling in the timer path |
| Fault policy | kernel event `dma_blocked` (device, address, reason), then kill the owning driver | the device only goes where its driver points it |
| Driver death | clear the device's Bus Master Enable when its driver dies; set it again at restart | a dead driver's device can't keep writing into the region while it is zeroed |
| No IOMMU present | boot as today, with a warning when a manifest grants DMA; kernel feature `require-iommu` refuses to start DMA tasks instead | keeps BIOS-only and older setups working; attestation shows the difference |
| Makefile | `IOMMU=1` adds the device; becomes the default at G5, with `IOMMU=0` to compare | tests can cover both |

Not planned: ATS. QEMU's virtio devices don't use it, and a device with ATS can ask to bypass
translation, so it stays off.

## Sub-steps

Each sub-step is a commit with every test passing under TCG and KVM.

### G1: ACPI and the DMAR table

- `RsdpRequest`; RSDP, then XSDT (or RSDT for ACPI 1.0), checksums verified.
- Map ACPI tables through the kernel MMIO mapper rather than the HHDM: base revision 3 doesn't
  promise the HHDM covers ACPI or reserved memory. Check what Limine returns for the RSDP under
  revision 3 (physical, per the protocol) on both BIOS and UEFI.
- Parse DMAR: host address width, DRHD units (register base, flags, device scopes), RMRRs
  (reserved regions a device needs identity-mapped; QEMU has none; log them if present).
- Map each unit's register page uncached; read and log `VER`, `CAP` and `ECAP`.
- New module `kernel/src/acpi.rs`, and `kernel/src/iommu.rs` for the unit.
- Tests: `iommu-found` (`IOMMU=1`: unit found, capabilities logged), `no-iommu` (no unit,
  boot unchanged, warning for DMA grants).

### G2: translation tables, turned on

- Root table (256 entries, one per bus), context tables per bus, a second-level table per
  granted device mapping its DMA region read/write with identity IOVA. Domain id = task slot.
- Pick 3 or 4 levels from `SAGAW` and the address width; refuse to enable on anything else.
- Order: write the tables, set the root pointer (`GCMD.SRTP`, wait for `GSTS.RTPS`), invalidate
  the context cache and IOTLB globally, then `GCMD.TE` (wait for `GSTS.TES`). All before the
  first task starts.
- Write-buffer flush when `CAP.RWBF` says so; flush CPU caches for table writes when
  `ECAP.C` is clear (QEMU is coherent, real hardware may not be).
- Table frames are kernel-owned, never mapped into any task.
- Tests: every driver test (`console-*`, `telemetry*`, `blk-*`, `storage-*`, `attest-*`)
  passes with `IOMMU=1`, i.e. legitimate DMA still works.

### G3: faults

- Program the fault event registers (`FEDATA`/`FEADDR`) with a kernel vector and the BSP's APIC
  id; unmask (`FECTL`).
- Handler: walk the fault recording registers, read source id (bus/device/function), address,
  reason and read/write, clear each record, clear `FSTS`.
- Map the source id to a task through the grant table. Log event `DMA_BLOCKED` (a = source id,
  b = address, c = reason | write << 8) and kill that task (new death kind for the supervisor;
  telemetry prints `dma_blocked`).
- Clear Bus Master Enable on a driver's death, set it when the slot restarts.
- Tests: in G4, because they need a misbehaving driver.

### G4: attack tests

- virtio-blk test feature `dma-escape`: issue a read whose data buffer is just past the end of
  its own DMA region. The device writes 4 KiB from the disk there.
- Kernel test feature `dma-canary`: allocate a page right after virtio-blk's DMA region (the
  contiguous allocator makes this deterministic), fill it with a pattern, and check it at
  `finish`.
- Tests:
  - `dma-escape` (`IOMMU=1`): fault logged with the right device and address, driver killed
    and restarted, canary intact.
  - `dma-escape-unprotected` (`IOMMU=0`): canary overwritten. This proves the test exercises
    the threat and documents what happens without an IOMMU.
  - `dma-ungranted`: a device with no grant (a second virtio-blk, no driver) can't DMA;
    checked by the context entry being absent, since nothing drives it.
- Negative checks as in earlier steps: temporarily map the whole of memory for a device and
  confirm `dma-escape` fails.

### G5: attestation, default on, docs

- Extend PCR 12 with a measurement of the IOMMU state (`"iommu: on"` and the unit's register
  base, or `"iommu: off"`) before any task runs; `tools/expected-pcrs.py` gets `--iommu`.
  A host whose reference was recorded with the IOMMU on refuses the key to a boot without it
  (test `attest-no-iommu-refused`).
- `IOMMU=1` becomes the Makefile default; `IOMMU=0` turns it off.
- README:
  - Drivers: what is now enforced; replace the "no IOMMU" limit.
  - Boot chain and Storage: update the limitations lists.
  - Protections table: new rows for DMA confinement and default-deny devices.
  - Building: `IOMMU`; layout entries for `acpi.rs` and `iommu.rs`.
- Limitations to state plainly:
  - no interrupt remapping, so a device can still send arbitrary MSIs (interrupt injection,
    not memory access)
  - identity IOVAs reveal physical addresses to devices (they already know them today)
  - a driver can still have its device read or corrupt anything in its own region, including
    data its clients sent it in plain text (storage encrypts before blocks reach the driver)
  - tested only on QEMU's emulated VT-d with one remapping unit
  - the hypervisor still sees all memory

## Risks and how we'll know

- **Getting the table format wrong** shows up as every DMA faulting: G2's test is the whole
  existing driver suite passing with `IOMMU=1`.
- **KVM and intel-iommu**: run G1's tests under KVM first; if `intremap=off` isn't enough,
  fall back to `-M q35,kernel-irqchip=split`.
- **OVMF with an IOMMU** (`BOOT=uefi-secure`): the firmware may enable or leave state in the
  unit. Disable translation before writing tables, then enable it; test under both boot paths
  in G2.
- **ACPI memory not mapped**: G1 maps tables explicitly; check both BIOS (SeaBIOS) and UEFI.
- **MSIs blocked by remapping**: in VT-d the interrupt address range (0xFEEx_xxxx) isn't
  translated by DMA remapping, so MSI-X keeps working without interrupt remapping. The
  `console-*` and `blk-*` tests cover it.
