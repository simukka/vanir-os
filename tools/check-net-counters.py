#!/usr/bin/env python3
"""Check the guest's network counters against what tools/net-peer.py net-counters did.

Reads a test run's output on stdin: the peer's "totals" line, and the telemetry stream (after
"--- build/telemetry.log ---"). Passes when one counter snapshot of the web instance shows
exactly the bytes the peer sent and received, the HTTP task's snapshot shows its requests by
status, and the interface's byte counters exceed the instance's by no more than header
overhead for the frames counted (plus one DHCP exchange).
"""
import json
import re
import sys

ETH_IP_TCP_MIN = 14 + 20 + 20 - 12  # an ARP frame (42 bytes) is the smallest we send or get
HEADERS_MAX = 14 + 60 + 60          # Ethernet, IPv4 and TCP with every option
DHCP_ALLOWANCE = 2 * 600            # two DHCP messages each way, which carry no TCP payload

text = sys.stdin.read()
m = re.search(r"peer: totals: requests=(\d+) ok=(\d+) not_found=(\d+) sent=(\d+) received=(\d+)", text)
if not m:
    sys.exit("no totals from the peer")
requests, ok, not_found, sent, received = map(int, m.groups())
records = []
for line in text.split("--- build/telemetry.log ---", 1)[-1].splitlines():
    try:
        records.append(json.loads(line))
    except ValueError:
        pass
counters = [r for r in records if r.get("event") == "counters"]

instances = [r for r in counters if r.get("scope") == "instance" and r.get("instance") == "web"]
match = [r for r in instances if r["bytes_in"] == sent and r["bytes_out"] == received]
if not match:
    last = instances[-1] if instances else {}
    sys.exit(f"no instance snapshot with bytes_in={sent} bytes_out={received} (last: in={last.get('bytes_in')} out={last.get('bytes_out')})")
inst = match[0]
print(f"instance web at t={inst['t']}: bytes_in={sent}, bytes_out={received}, accepted={inst['accepted']}: match")

http = [r for r in counters if r.get("scope") == "http" and r.get("requests") == requests]
if not http or http[0]["status_2xx"] != ok or http[0]["status_4xx"] != not_found:
    sys.exit(f"no http snapshot with requests={requests} 2xx={ok} 4xx={not_found}")
latency = sum(v for k, v in http[0].items() if k.startswith("latency_"))
if latency != requests:
    sys.exit(f"latency histogram holds {latency} requests, not {requests}")
print(f"http: {requests} requests, {ok} 2xx, {not_found} 4xx, all in the latency histogram: match")

iface = [r for r in counters if r.get("scope") == "interface" and r["t"] == inst["t"] and r["task"] == inst["task"]]
if not iface:
    sys.exit("no interface snapshot from the same round")
i = iface[0]
for direction, payload in (("rx", sent), ("tx", received)):
    frames, total = i[f"{direction}_packets"], i[f"{direction}_bytes"]
    low, high = payload + ETH_IP_TCP_MIN * frames, payload + HEADERS_MAX * frames + DHCP_ALLOWANCE
    if not low <= total <= high:
        sys.exit(f"interface {direction}_bytes={total} for {frames} frames carrying {payload} bytes: outside {low}..{high}")
    print(f"interface {direction}: {total} bytes in {frames} frames for {payload} bytes of payload: within {low}..{high}")
print("counters match")
