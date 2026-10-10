#!/usr/bin/env python3
"""Check that the host received `<prefix>0` .. `<prefix>N-1` in order (read from stdin, after the
`--- build/telemetry.log ---` marker that tests/run.sh adds). A line may repeat once: a write
the device finished just before its driver died is resent by the client."""
import sys

prefix, count = sys.argv[1], int(sys.argv[2])
text = sys.stdin.read()
log = text.split("--- build/telemetry.log ---\n", 1)[-1].splitlines()
got = [int(l[len(prefix):]) for l in log if l.startswith(prefix)]
expected, repeats = 0, 0
for n in got:
    if n == expected:
        expected += 1
    elif n == expected - 1:
        repeats += 1
    else:
        sys.exit(f"after {prefix}{expected - 1}: got {prefix}{n}")
if expected != count:
    sys.exit(f"received {expected} of {count} lines")
print(f"all {count} lines in order ({repeats} resent)")
