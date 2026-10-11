---
rfd: 7
title: Policies for services that keep crashing
state: prediscussion
authors: simukka
date: 2026-10-11
labels: supervisor, reliability, deployment, security
---

# RFD 7: Policies for services that keep crashing

*Sparse: this RFD records the need and the questions. The design comes later.*

## The need

Ideally a service never crashes. When it does, [RFD 2](0002-deployment.md)
(determination 4) always restarts it, however often it crashes, with exponential backoff
between restarts (10 ms doubling to 30 s, reset after 60 s without a crash), and reports every
crash. Restarting forever means an attacker can't take a service down for good by crashing it,
and backoff stops a loop from eating the CPU.

Restarting isn't always the best response, though:

- A new version that crashes on every request should be rolled back, not restarted forever.
- A service that crashes on one client's requests is being attacked, or has a bug that client
  triggers, and restarting it only lets the attack go on.
- With backoff at its cap, a service in a loop is down most of the time, and nobody is told
  this is different from an occasional crash.

## Questions

1. **What counts as a crash loop?** How many crashes in what window? Set per service in the
   descriptor, fleet-wide, or learned from each service's normal crash rate?
2. **Who acts?** The node (e.g. swapping back to the previous version if its slot still holds
   it) acts fast, but deployment policy then lives on the node. The control plane sees every
   node, but is slower.
3. **Deployment-aware rollback.** Should crashes in the first minutes after a swap count for
   more, so a bad deploy rolls back quickly?
4. **Finding the trigger.** Can the node tie crashes to a client or a request (e.g. by noting
   the connections open at the time of each crash), and block that source through [RFD 1](0001-network-services.md)'s
   blocklist (P6)?
5. **Platform tasks.** `net`, `storage` and the drivers also restart forever today. Do they
   need a different policy, e.g. evacuating the node after repeated `storage` crashes?
6. **Backoff parameters.** Are RFD 2's defaults right, and should a service be able to set its
   own in the descriptor?
7. **State after a crash.** Does a crashed service lose its writer epoch, or keep it across a
   restart ([RFD 3](0003-service-volumes.md), P1)? A restart today keeps the task's identity but gets a new task id.
