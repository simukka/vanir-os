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


class HttpError(Exception):
    pass


class Http:
    """A minimal HTTP/1.1 client over one TCP connection (so tests see exactly what happens)."""

    def __init__(self, port=NET_PORT, timeout=3.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.pending = b""
        self.closed = False

    def close(self):
        self.sock.close()

    def _fill(self):
        data = self.sock.recv(65536)
        if not data:
            raise HttpError("connection closed")
        self.pending += data

    def request(self, path="/", keep_alive=True, method="GET", extra=b""):
        """(status, headers, body); the connection is closed after if the server said so."""
        conn = b"keep-alive" if keep_alive else b"close"
        try:
            self.sock.sendall(f"{method} {path} HTTP/1.1\r\nHost: vanir\r\n".encode() + b"Connection: " + conn + b"\r\n" + extra + b"\r\n")
            while b"\r\n\r\n" not in self.pending:
                self._fill()
        except OSError as e:
            raise HttpError(str(e)) from e
        head, self.pending = self.pending.split(b"\r\n\r\n", 1)
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split()[1])
        headers = {k.strip().lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:])}
        length = int(headers.get("content-length", 0)) if method != "HEAD" else 0
        try:
            while len(self.pending) < length:
                self._fill()
        except OSError as e:
            raise HttpError(str(e)) from e
        body, self.pending = self.pending[:length], self.pending[length:]
        if headers.get("connection", "").lower() == "close":
            self.closed = True
        return status, headers, body.decode("latin-1")


def get(path="/", port=NET_PORT, timeout=3.0):
    """One request on a new connection: (status, body), or raises HttpError."""
    try:
        c = Http(port, timeout)
    except OSError as e:
        raise HttpError(str(e)) from e
    try:
        status, _, body = c.request(path, keep_alive=False)
        return status, body
    finally:
        c.close()


def wait_ready(deadline, port=NET_PORT, path="/"):
    """Retry GETs until the guest answers one; returns the body, or None."""
    while time.monotonic() < deadline:
        try:
            status, body = get(path, port, timeout=2)
            if status == 200:
                return body
        except HttpError:
            pass
        time.sleep(0.2)
    return None


def finish(ok, port=NET_PORT):
    """Ask the HTTP task to exit (exit-on-request), ending the run; say how it went."""
    try:
        get("/exit", port, timeout=2)
    except HttpError:
        pass
    say("PASS" if ok else "FAIL")
    return 0 if ok else 1


@scenario
def http_get(args):
    """100 GETs over one keep-alive connection, then 100 over new connections."""
    deadline = time.monotonic() + args.timeout
    body = wait_ready(deadline)
    if body is None:
        say("the guest never answered")
        return finish(False)
    say(f"first answer: {body.strip()!r}")
    want = "hello from web\n"
    ok = 0
    start = time.monotonic()
    c = Http()
    for _ in range(100):
        try:
            status, headers, body = c.request("/")
            ok += status == 200 and body == want and headers.get("connection") == "keep-alive"
        except HttpError as e:
            say(f"keep-alive request failed: {e}")
            break
    c.close()
    rate = ok / (time.monotonic() - start)
    say(f"keep-alive: {ok}/100 ok ({rate:.0f} requests/s)")
    fresh = 0
    start = time.monotonic()
    for _ in range(100):
        try:
            status, body = get("/")
            fresh += status == 200 and body == want
        except HttpError as e:
            say(f"request on a new connection failed: {e}")
    rate = fresh / (time.monotonic() - start)
    say(f"new connections: {fresh}/100 ok ({rate:.0f} requests/s)")
    return finish(ok == 100 and fresh == 100)


@scenario
def http_restart(args):
    """GETs on new connections while the guest restarts net or the HTTP task: the requests in
    flight at the crash may fail, the ones after must not."""
    deadline = time.monotonic() + args.timeout
    if wait_ready(deadline) is None:
        say("the guest never answered")
        return finish(False)
    results = []
    while len(results) < 400 and time.monotonic() < deadline - 5:
        try:
            status, _ = get("/", timeout=2)
            results.append(status == 200)
        except HttpError:
            results.append(False)
            time.sleep(0.1)
        if len(results) >= 150 and all(results[-50:]):
            break
    failed = results.count(False)
    first_failure = results.index(False) if False in results else None
    after = results[first_failure:] if first_failure is not None else []
    say(f"{results.count(True)} requests ok, {failed} failed")
    if first_failure is not None:
        say(f"first failure at request {first_failure + 1}; the last 50 all ok: {all(results[-50:])}")
    return finish(failed > 0 and len(after) > 50 and all(results[-50:]))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    p.add_argument("--timeout", type=float, default=60, help="give up after this many seconds")
    args = p.parse_args()
    random.seed(9)
    sys.exit(SCENARIOS[args.scenario](args))


if __name__ == "__main__":
    main()
