---
rfd: 5
title: Adaptive telemetry snapshots
state: prediscussion
authors: simukka
date: 2026-10-11
labels: telemetry, observability, security
---

# RFD 5: Adaptive telemetry snapshots

*Sparse: this RFD records the idea and the questions. The design comes later.*

## The need

[RFD 1](0001-network-services.md) (determination 5, P5) sends counter snapshots once a second
by default, and lets the control plane change the interval per node. That relies on the control
plane noticing something first. Sharp changes (a traffic spike, the start of an attack, a crash
loop) often happen faster than the control plane can react. A one-second snapshot already
blurs them, and the most useful detail is from the first seconds.

The idea: the node itself sends snapshots more often while its counters are changing sharply,
and goes back to the normal interval when they settle.

## Starting points

- RFD 1's counters are cumulative, so extra snapshots never conflict with regular ones. The
  control plane gets more points on the same curves.
- The node already computes thresholds for `attack_suspected` (RFD 1, P6). The same signals
  could switch to faster snapshots.
- Events already go out immediately. This is only about counters.

## Questions

1. **What triggers it?** Fixed thresholds on rates (bytes, SYNs, drops, crashes), a change
   relative to a moving average, or the `attack_suspected` signal only?
2. **How fast, and for how long?** e.g. every 100 ms for the next 30 s, with a cap so a node
   under attack doesn't flood the management network with telemetry.
3. **Which counters?** All of them, or only those that changed sharply? Sending a subset keeps
   messages small but complicates the control plane's view.
4. **Fleet-wide effects.** An attack hitting many nodes at once makes all of them switch at the
   same moment, and the control plane receives the most data exactly when it is busiest. Does
   the control plane need to be able to veto or cap it?
5. **Who owns the policy?** Thresholds fixed in the node image, set by the control plane, or
   declared per service in its descriptor?
6. **Ring buffering instead.** An alternative: the node keeps a short high-resolution history
   (e.g. 100 ms samples for the last 60 s) in a ring buffer and sends it only when asked or when
   an event fires. That costs nothing on the network until it's needed. Is that better, or
   complementary?
