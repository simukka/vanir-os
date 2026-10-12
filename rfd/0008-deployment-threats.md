---
rfd: 8
title: Attack vectors in deployment
state: prediscussion
authors: simukka
date: 2026-10-12
labels: deployment, security, attestation, supervisor
---

# RFD 8: Attack vectors in deployment

*Sparse: this RFD records known weaknesses in [RFD 2](0002-deployment.md)'s design, so the core
can be built first. Fixes come later.*

## The need

RFD 2 accepts some weaknesses to keep its first version small. Each is listed here with the
attacker it assumes and a possible fix. The attacker that matters most is one who has
compromised the agent, or the control plane itself: either can ask the kernel to load any
signed image.

## Attack vectors

1. **Rollback through an old descriptor.** The floor is the descriptor's `min_version`
   (RFD 2, P6), and the descriptor is signed with the image it limits. Every release vouches for
   itself, so presenting v3 with v3's descriptor (`min_version = 1`) loads it, bringing back
   whatever v3 got wrong. Signed commands with generation numbers stop a network attacker
   replaying commands, but not a compromised agent or control plane.
   *Possible fix:* the kernel keeps a floor per service that only rises: the maximum of the
   node manifest's baseline, every accepted descriptor's `min_version`, and signed floor
   statements from the release key. Floor raises are measured, so a quote shows them.
   Remaining gap: after a reboot the floor is the baseline until the control plane resends
   statements (attestation would show it; TPM NV counters would close it).
2. **Clean exit as a permanent stop.** The supervisor treats exit code 0 as "done, don't
   restart" (RFD 2, P4). A service that can be made to exit cleanly stays down, the hole RFD 2's
   P5 closes for crashes. *Possible fix:* the agent tells the supervisor which slots it is
   stopping; any other exit counts as a crash.
3. **Losing the run-time event log.** Settled in RFD 2 (determination 9): the kernel keeps
   it. What remains: anything that can trigger loads can fill the fixed-size log, after which
   the node refuses loads until it is evacuated and rebooted (denial of service).
4. **One key for boot and slot images.** Run-time images are signed with the boot images' key
   (RFD 2, P2), so a signature doesn't say which kind of image it is for. Slot classes limit the
   harm (no devices, few sends). *Possible fix:* a signed image kind in the signature file.
5. **Shared TPM at run time.** Settled in RFD 2 (determination 8): a lock the kernel holds,
   which `attest` takes around each command. What remains: `attest` keeps its raw mapping, so a
   compromised `attest` can hold the lock forever and block every load (denial of service, not
   forgery), and can add entries to the run-time PCR (detectable against the kernel's log).
   *Possible fix:* the kernel owns the TPM and runs `attest`'s commands for it through a
   syscall, refusing extends; this needs the kernel to wait on slow commands like quotes
   without blocking everything else.
6. **The control plane's key is pinned in the image** (RFD 2, P7). Rotating it, for example
   after it leaks, means evacuating and updating every node.
7. **The control plane holds every volume's key** ([RFD 3](0003-service-volumes.md), P2). Whoever
   compromises it can read any volume whose sealed blocks they can get, from a disk or a
   transfer. *Possible fix:* keep the keys in an HSM or the control plane's own TPM, sealed so
   they are only released wrapped to an attested node's per-boot key and never seen in plain
   text by the control plane's software.

## Questions

1. Which of these must be fixed before vanir-os runs untrusted traffic, and which are accepted?
2. Is a compromised control plane in scope at all, or only a compromised node task?
