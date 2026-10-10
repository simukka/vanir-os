#!/usr/bin/env python3
"""Host side of vanir-os telemetry: read the newline-delimited JSON the telemetry task sends over
the virtio console, check it, and summarise it.

Sources:
  host-agent.py build/telemetry.log        a file (QEMU -chardev file,...)
  host-agent.py -                          stdin (tests/run.sh output: the part after the
                                           "--- build/telemetry.log ---" marker is used)
  host-agent.py --socket build/tel.sock    a Unix socket (QEMU -chardev socket,...,server=on)
  host-agent.py --listen-vsock 5000        accept the guest's vsock connection (CID 2, port 5000)
  ... --save FILE                          also copy the raw stream to FILE as it arrives
  ... --attest                             once connected, challenge the guest with a fresh
                                           nonce ("attest <hex>"); the challenge is logged

Checks (--check makes any failure the exit status):
  - every line is a JSON object with an "event"
  - kernel event sequence numbers only increase, and every gap is covered by a preceding
    "dropped" record
  - heartbeats arrive about once a second (--heartbeat-ticks), and at least
    --expect-heartbeats of them
  - --expect EVENT=N: at least N events of that type
"""
import argparse
import json
import secrets
import socket
import sys
from collections import Counter

MARKER = "--- build/telemetry.log ---\n"


def stream_lines(sock, save, append=False):
    """Lines from a connected socket until the peer goes away, copied to `save` if given."""
    out = open(save, "a" if append else "w", encoding="utf-8") if save else None
    pending = b""
    while True:
        try:
            data = sock.recv(65536)
        except (ConnectionResetError, OSError):
            data = b""
        if not data:
            break
        if out:
            out.write(data.decode("utf-8", "replace"))
            out.flush()
        pending += data
        *lines, pending = pending.split(b"\n")
        for line in lines:
            yield line.decode("utf-8", "replace")
    if pending:
        yield pending.decode("utf-8", "replace")


def lines_from(args):
    if args.listen_vsock:
        listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((socket.VMADDR_CID_ANY, args.listen_vsock))
        listener.listen(1)
        if args.save:
            open(args.save, "w").close()  # truncate, and tell anyone waiting that we listen
        conn, (cid, port) = listener.accept()
        print(f"host-agent: guest CID {cid} connected from port {port}", file=sys.stderr)
        if args.attest:
            nonce = secrets.token_hex(32)
            challenge = json.dumps({"event": "challenge", "nonce": nonce})
            if args.save:
                with open(args.save, "a", encoding="utf-8") as f:
                    f.write(challenge + "\n")
            yield challenge
            conn.sendall(f"attest {nonce}\n".encode())
        yield from stream_lines(conn, args.save, append=True)
        return
    if args.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(args.socket)
        yield from stream_lines(sock, args.save)
        return
    text = sys.stdin.read() if args.source == "-" else open(args.source, encoding="utf-8", errors="replace").read()
    if MARKER in text:
        text = text.split(MARKER, 1)[1]
    yield from text.splitlines()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("source", nargs="?", default="build/telemetry.log")
    p.add_argument("--socket")
    p.add_argument("--listen-vsock", type=int, metavar="PORT")
    p.add_argument("--save", metavar="FILE")
    p.add_argument("--attest", action="store_true")
    p.add_argument("--check", action="store_true")
    p.add_argument("--quiet", action="store_true", help="only the summary, not each event")
    p.add_argument("--expect-heartbeats", type=int, default=0)
    p.add_argument("--heartbeat-ticks", type=int, default=100)
    p.add_argument("--expect", action="append", default=[], metavar="EVENT=N")
    args = p.parse_args()

    problems = []
    counts = Counter()
    last_seq = 0
    dropped_reported = 0
    gap_total = 0
    unexplained = 0
    last_heartbeat = None
    worst_interval = 0

    for n, line in enumerate(lines_from(args), 1):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event = record["event"]
        except (ValueError, KeyError, TypeError):
            problems.append(f"line {n}: not a telemetry record: {line[:80]!r}")
            continue
        counts[event] += 1
        if not args.quiet:
            print(line)

        if event == "dropped":
            dropped_reported += record["count"]
        if "seq" in record:
            seq = record["seq"]
            if seq <= last_seq:
                problems.append(f"line {n}: sequence went backwards ({last_seq} -> {seq})")
            gap_total += seq - last_seq - 1
            if gap_total > dropped_reported + unexplained:
                missing = gap_total - dropped_reported - unexplained
                problems.append(f"line {n}: {missing} events missing without a dropped record")
                unexplained += missing
            last_seq = seq
        if event == "heartbeat":
            t = record["t"]
            if last_heartbeat is not None:
                interval = t - last_heartbeat
                worst_interval = max(worst_interval, abs(interval - args.heartbeat_ticks))
                if abs(interval - args.heartbeat_ticks) > args.heartbeat_ticks // 2:
                    problems.append(f"line {n}: heartbeat {interval} ticks after the previous one")
            last_heartbeat = t

    if counts["heartbeat"] < args.expect_heartbeats:
        problems.append(f"{counts['heartbeat']} heartbeats, expected {args.expect_heartbeats}")
    for want in args.expect:
        event, _, number = want.partition("=")
        if counts[event] < int(number or 1):
            problems.append(f"{counts[event]} {event} events, expected at least {number}")

    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    print(f"host-agent: {summary}; last seq {last_seq}, {gap_total} missing, {dropped_reported} reported dropped,"
          f" heartbeat jitter up to {worst_interval} ticks")
    for problem in problems:
        print(f"host-agent: PROBLEM: {problem}")
    if args.check and problems:
        sys.exit(1)


if __name__ == "__main__":
    main()
