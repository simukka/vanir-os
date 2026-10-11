#!/usr/bin/env python3
"""Host side of the network tests: talks to a vanir-os guest while tests/run.sh boots it.

  net-peer.py SCENARIO [--timeout S]

Two ways in, matching the Makefile's NET / NET_MGMT backends:
  - "user" (slirp): ordinary TCP sockets to 127.0.0.1:NET_PORT (guest port 80) and
    127.0.0.1:NET_MGMT_PORT (guest port 7). Slirp ends TCP on the host side, so only
    well-formed traffic gets through.
  - "dgram": raw Ethernet frames in UDP datagrams to QEMU's port NET_DGRAM_PORT, from the next
    port up. The guest is 10.0.9.2 and we are 10.0.9.1 (MAC 52:54:00:99:99:99); we can send
    any frame we like.

Each scenario prints "peer: ..." lines that the test case checks; the last says PASS or FAIL.
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

GUEST_MAC = bytes.fromhex("525400000001")
PEER_MAC = bytes.fromhex("525400999999")
GUEST_IP = bytes([10, 0, 9, 2])
PEER_IP = bytes([10, 0, 9, 1])

NET_PORT = int(os.environ.get("NET_PORT", 8080))
NET_MGMT_PORT = int(os.environ.get("NET_MGMT_PORT", 8081))
NET_DGRAM_PORT = int(os.environ.get("NET_DGRAM_PORT", 18090))

SCENARIOS = {}


def scenario(fn):
    SCENARIOS[fn.__name__.replace("_", "-")] = fn
    return fn


def say(*args):
    print("peer:", *args, flush=True)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class Link:
    """Raw Ethernet frames to and from the guest over QEMU's dgram backend."""

    def __init__(self, port=NET_DGRAM_PORT):
        self.qemu = ("127.0.0.1", port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        self.sock.bind(("127.0.0.1", port + 1))

    def send(self, frame):
        try:
            self.sock.sendto(frame, self.qemu)
        except OSError:
            pass  # QEMU isn't up yet

    def recv(self, timeout):
        """The next frame, or None after `timeout` seconds."""
        self.sock.settimeout(max(timeout, 0.001))
        try:
            return self.sock.recv(65536)
        except (socket.timeout, OSError):
            return None

    def frames_until(self, deadline):
        while (left := deadline - time.monotonic()) > 0:
            frame = self.recv(left)
            if frame is not None:
                yield frame


def ethernet(dst, ethertype, payload, src=PEER_MAC):
    return dst + src + struct.pack("!H", ethertype) + payload


def arp_request(target_ip=GUEST_IP, sender_ip=PEER_IP, sender_mac=PEER_MAC):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + sender_mac + sender_ip + b"\0" * 6 + target_ip
    return ethernet(b"\xff" * 6, 0x0806, body, src=sender_mac)


def ipv4(src, dst, proto, payload, ident=0, ttl=64):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0, ttl, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def icmp_echo(seq, ident=0x7672, payload=b"vanir-ping-" + b"x" * 45):
    body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    body = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return ethernet(GUEST_MAC, 0x0800, ipv4(PEER_IP, GUEST_IP, 1, body, ident=seq))


def parse_ipv4(frame):
    """(src, dst, proto, payload) of an IPv4 frame, else None."""
    if len(frame) < 34 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    return ip[12:16], ip[16:20], ip[9], ip[ihl:total]


def resolve(link, deadline):
    """ARP for the guest until it answers; returns the MAC it gave."""
    while time.monotonic() < deadline:
        link.send(arp_request())
        for frame in link.frames_until(time.monotonic() + 0.2):
            if frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x02" and frame[28:32] == GUEST_IP:
                return frame[22:28]
    return None


@scenario
def arp_ping(args):
    """ARP for the guest, then ping it until 20 echoes come back (nictest answers by hand)."""
    link = Link()
    deadline = time.monotonic() + args.timeout
    mac = resolve(link, deadline)
    if mac is None:
        say("no ARP reply; FAIL")
        return 1
    say(f"ARP reply: {mac.hex(':')} ({'the right MAC' if mac == GUEST_MAC else 'WRONG MAC'})")
    answered = sent = 0
    seq = 0
    while answered < 20 and time.monotonic() < deadline:
        seq += 1
        sent += 1
        link.send(icmp_echo(seq))
        for frame in link.frames_until(time.monotonic() + 0.5):
            ip = parse_ipv4(frame)
            if ip and ip[2] == 1 and ip[3][0] == 0 and struct.unpack("!H", ip[3][6:8])[0] == seq:
                good = frame[6:12] == GUEST_MAC and checksum(ip[3]) == 0
                answered += good
                break
    ok = answered >= 20 and mac == GUEST_MAC
    say(f"{answered} pings answered of {sent} sent; {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    p.add_argument("--timeout", type=float, default=60, help="give up after this many seconds")
    args = p.parse_args()
    random.seed(9)
    sys.exit(SCENARIOS[args.scenario](args))


if __name__ == "__main__":
    main()
