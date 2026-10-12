#!/usr/bin/env python3
"""Check the supervisor's restart backoff from a test run's serial output (stdin).

  check-backoff.py --expect 1,2,4,8,16 [--task 2]

The supervisor prints "restarting task T in B ticks (restart N)" for each crash, and the crasher
prints "crasher: start G at tick U" each time it starts. Passes when the first backoffs are
exactly the expected ones, and each start came at least that backoff after the one before it.
"""
import argparse
import re
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--expect", required=True, help="comma-separated backoffs in ticks, in order")
    p.add_argument("--task", type=int, default=2)
    args = p.parse_args()
    want = [int(b) for b in args.expect.split(",")]
    out = sys.stdin.read()

    backoffs = {int(n): int(b) for b, n in re.findall(rf"restarting task {args.task} in (\d+) ticks \(restart (\d+)\)", out)}
    starts = {int(g): int(t) for g, t in re.findall(r"crasher: start (\d+) at tick (\d+)", out)}
    ok = True
    for n, b in enumerate(want, 1):
        if backoffs.get(n) != b:
            print(f"FAIL: restart {n}: backoff {backoffs.get(n)}, expected {b}")
            ok = False
            continue
        if n not in starts or n - 1 not in starts:
            print(f"FAIL: restart {n}: no start times for generations {n - 1} and {n}")
            ok = False
            continue
        gap = starts[n] - starts[n - 1]
        if gap < b:
            print(f"FAIL: restart {n}: started {gap} ticks after the previous start, before its {b}-tick backoff")
            ok = False
        else:
            print(f"ok: restart {n}: backoff {b}, {gap} ticks after the previous start")
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
