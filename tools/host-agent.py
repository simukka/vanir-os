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
                                           nonce ("attest <hex>"); the challenge is logged; then
                                           tell it "bye"
  ... --set-interval MS                    once connected, set the counter snapshot interval
                                           ("interval <ms>", through the control task)
  ... --release-key KEY --reference REF    with --attest: if the quote verifies against REF,
                                           seal the 32-byte master key KEY (made if missing) to
                                           the guest and send it; log key_released/key_refused

Checks (--check makes any failure the exit status):
  - every line is a JSON object with an "event"
  - kernel event sequence numbers only increase, and every gap is covered by a preceding
    "dropped" record
  - heartbeats arrive about once a second (--heartbeat-ticks), and at least
    --expect-heartbeats of them
  - --expect EVENT=N: at least N events of that type
  - --expect-interval TICKS: once telemetry reports that interval, each reporter's counter
    snapshots (per task and scope) arrive that many ticks apart
"""
import argparse
import json
import os
import secrets
import socket
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vanir_attest import check, compare, seal_key  # noqa: E402


def master_key(path):
    """The storage master key: 32 bytes in `path`, created (mode 0600) if it isn't there."""
    if not os.path.exists(path):
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
            f.write(secrets.token_bytes(32))
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        sys.exit(f"{path}: need exactly 32 bytes")
    return key

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
        if args.set_interval:
            conn.sendall(f"interval {args.set_interval}\n".encode())
        if not args.attest:
            yield from stream_lines(conn, args.save, append=True)
            return

        def note(record):
            line = json.dumps(record)
            if args.save:
                with open(args.save, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            return line

        nonce = secrets.token_hex(32)
        yield note({"event": "challenge", "nonce": nonce})
        conn.sendall(f"attest {nonce}\n".encode())
        for line in stream_lines(conn, args.save, append=True):
            yield line
            try:
                record = json.loads(line)
            except ValueError:
                continue
            event = record.get("event")
            if event == "quote" and args.release_key:
                problems = check(record, nonce) + compare(record, json.load(open(args.reference)))
                if problems:
                    yield note({"event": "key_refused", "reasons": problems})
                    conn.sendall(b"bye\n")
                else:
                    conn.sendall(f"key {seal_key(master_key(args.release_key), record['kx_pub'], nonce)}\n".encode())
                    yield note({"event": "key_released"})
            elif event == "quote" or (event in ("unlocked", "error") and args.release_key):
                conn.sendall(b"bye\n")
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
    p.add_argument("--set-interval", type=int, metavar="MS")
    p.add_argument("--expect-interval", type=int, metavar="TICKS")
    p.add_argument("--release-key", metavar="KEY")
    p.add_argument("--reference", metavar="REF")
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
    interval_set = False
    snapshots = {}  # (task, scope, instance) -> uptimes of counter snapshots since the change

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
        if event == "interval":
            interval_set = record.get("ticks") == args.expect_interval
        if event == "counters" and interval_set:
            snapshots.setdefault((record.get("task"), record.get("scope"), record.get("instance")), []).append(record["t"])
        if event == "heartbeat":
            t = record["t"]
            if last_heartbeat is not None:
                interval = t - last_heartbeat
                worst_interval = max(worst_interval, abs(interval - args.heartbeat_ticks))
                if abs(interval - args.heartbeat_ticks) > args.heartbeat_ticks // 2:
                    problems.append(f"line {n}: heartbeat {interval} ticks after the previous one")
            last_heartbeat = t

    if args.expect_interval:
        if not interval_set:
            problems.append(f"telemetry never reported an interval of {args.expect_interval} ticks")
        checked = 0
        tolerance = max(2, args.expect_interval // 5)
        for key, times in sorted(snapshots.items(), key=str):
            # A reporter learns the new interval from the reply to its next snapshot.
            gaps = [b - a for a, b in zip(times[1:], times[2:])]
            bad = [g for g in gaps if abs(g - args.expect_interval) > tolerance]
            checked += len(gaps)
            if bad:
                problems.append(f"{'/'.join(str(k) for k in key if k)}: snapshot gaps {bad} ticks, expected {args.expect_interval}")
        if checked < 5:
            problems.append(f"only {checked} snapshot gaps to check")
        else:
            print(f"host-agent: {checked} snapshot gaps of {args.expect_interval} ticks (+-{tolerance})")
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
