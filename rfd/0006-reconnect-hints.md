---
rfd: 6
title: Asking clients to reconnect before a drain deadline
state: prediscussion
authors: simukka
date: 2026-10-11
labels: networking, deployment
---

# RFD 6: Asking clients to reconnect before a drain deadline

*Sparse: this RFD records the idea and the questions. The design comes later.*

## The need

[RFD 1](0001-network-services.md) drains an instance on a best-effort basis: it stops taking
new connections, closes keep-alive connections after their current request, and terminates
whatever is still open at the deadline (determination 4). Short requests finish well before
that. Long-lived connections (WebSockets, server-sent events, streaming, long polls) don't
finish by themselves, so every drain ends them abruptly at the deadline. Clients see an error
instead of a clean reconnect, and they all reconnect at the same moment.

The idea: when a drain starts, the service tells each long-lived client to reconnect, through
whatever its protocol offers, so clients move to the new instance gradually and cleanly
before the deadline.

## Starting points

- Protocols already have the signals: a WebSocket close frame (code 1001, "going away"),
  HTTP/2 `GOAWAY`, an SSE event the client understands, or ending a long poll early.
- RFD 1 already notifies the instance (`NOTIFY_DRAIN`). This RFD is about what the service
  does with it, and what vanir-os could offer to help.

## Questions

1. **Library or protocol?** Is this a helper in the service library for common protocols, or
   only guidance for service authors?
2. **Spreading reconnects.** Should hints be spread over part of the drain window (e.g. the
   first half) so a large instance doesn't send every client to the new one in the same
   second?
3. **Can `net` help** without understanding the protocol, e.g. with a TCP-level signal? Probably
   not cleanly, but worth stating why.
4. **Measuring it.** RFD 1 counts `drain_forced`. Should hints have their own counters (hinted,
   reconnected before the deadline) so the control plane can tell whether a service supports
   them?
5. **Clients that ignore hints** are still terminated at the deadline. Is that enough, or should
   the descriptor declare whether a service sends hints?
