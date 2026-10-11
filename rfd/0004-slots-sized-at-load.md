---
rfd: 4
title: Slots sized at load time
state: prediscussion
authors: simukka
date: 2026-10-11
labels: kernel, memory, scheduling, deployment
---

# RFD 4: Slots sized at load time

*Sparse: this RFD records the need and the questions. The design comes later.*

## The need

[RFD 2](0002-deployment.md) (determination 6) starts with slots in a few fixed classes:
the manifest declares, say, four small slots and two large ones, and the kernel sets up their
memory at boot. That is simple, and loading an image allocates nothing. But it wastes memory:
a small service in a large slot strands most of it. And a node runs out of one class while it
has room in another, so the control plane can't place a service the node could hold.

The alternative is for the descriptor to say what the service needs (memory, CPU budget, DMA
none) and for the kernel to carve the slot from a node-wide pool when it loads the image.

## What changes

- The kernel allocates and frees task memory at run time. Today every task's frames are set up
  at boot and keep the same pages for the life of the slot.
- The control plane places by resources (free memory, free CPU budget) rather than by counting
  free slots of a class.
- The number of slots is limited by memory, not by the manifest.

## Questions

1. **Fragmentation.** Task memory is physically contiguous in places (DMA regions, though slots
   have none). With frames freed and reused, can a large service fail to load on a node that
   has enough free memory in total? Does the kernel need to compact, or only allocate in
   fixed-size chunks?
2. **Zeroing and reuse.** Freed memory must be zeroed before another service gets it. Is that
   done at free time or at load time, and what does it cost for large slots?
3. **CPU budgets.** Today budgets are per task in the manifest. With slots sized at load, how
   does the node refuse a service whose budget would oversubscribe the CPU?
4. **Attestation.** Fixed classes are part of the measured manifest. If sizes come from the
   descriptor, they're measured with the image (RFD 2, P6). Is that enough for the verifier to
   know a service couldn't starve the platform tasks?
5. **Limits on the descriptor.** Should the manifest still cap what any one service may ask
   for, so a signed but oversized descriptor can't take a whole node?
6. **Is it worth it?** How much memory do fixed classes actually waste on realistic fleets?
   Measure with RFD 2's classes before building this.
