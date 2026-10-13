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
import threading
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
    """Raw Ethernet frames to and from the guest over QEMU's dgram backend. We answer ARP for
    10.0.9.1, the guest's gateway, so the guest can reach us and any address behind us."""

    def __init__(self, port=NET_DGRAM_PORT):
        self.qemu = ("127.0.0.1", port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 22)
        self.sock.bind(("127.0.0.1", port + 1))
        self.handlers = []

    def poll(self, timeout):
        """Take frames for up to `timeout` seconds (at least one look), answering ARP and handing
        the rest to `handlers`."""
        deadline = time.monotonic() + timeout
        while True:
            frame = self.recv(max(deadline - time.monotonic(), 0.001))
            if frame is None:
                return
            if frame[12:14] == b"\x08\x06" and frame[20:22] == b"\x00\x01" and frame[38:42] == PEER_IP:
                body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + PEER_MAC + PEER_IP + frame[22:28] + frame[28:32]
                self.send(ethernet(frame[6:12], 0x0806, body))
                continue
            for handler in list(self.handlers):
                handler(frame)
            if time.monotonic() >= deadline:
                return

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


TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 1, 2, 4, 8, 16


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b"", window=65535):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return ethernet(GUEST_MAC, 0x0800, ipv4(src, dst, 6, header + payload))


class RawTcp:
    """A TCP client made of raw frames, for tests that need to control every packet. Simple:
    in-order data only, retransmits its own data until acknowledged."""

    def __init__(self, link, src=PEER_IP, sport=None, dport=80):
        self.link, self.src, self.dport = link, src, dport
        self.sport = sport or random.randint(20000, 60000)
        self.seq = random.randint(0, 1 << 31)
        self.ack = 0
        self.acked = self.seq
        self.data = b""
        self.state = "closed"
        self.reset = self.fin = False
        link.handlers.append(self.on_frame)

    def drop(self):
        if self.on_frame in self.link.handlers:
            self.link.handlers.remove(self.on_frame)

    def send_segment(self, flags, payload=b"", seq=None):
        self.link.send(tcp_segment(self.src, GUEST_IP, self.sport, self.dport, self.seq if seq is None else seq, self.ack, flags, payload))

    def on_frame(self, frame):
        ip = parse_ipv4(frame)
        if not ip or ip[2] != 6 or ip[1] != self.src or ip[0] != GUEST_IP:
            return
        tcp = ip[3]
        sport, dport, seq, ack, off, flags = struct.unpack("!HHIIBB", tcp[:14])
        if sport != self.dport or dport != self.sport:
            return
        payload = tcp[(off >> 4) * 4:]
        if flags & TCP_RST:
            self.reset = True
            self.state = "closed"
            return
        if flags & TCP_ACK:
            self.acked = max(self.acked, ack)  # our sequence numbers start below 2**31: no wrap
        if self.state == "syn-sent" and flags & TCP_SYN and flags & TCP_ACK:
            self.ack = (seq + 1) & 0xFFFFFFFF
            self.seq += 1
            self.state = "established"
            self.send_segment(TCP_ACK)
            return
        if self.state != "established":
            return
        if payload and seq == self.ack:
            self.data += payload
            self.ack = (self.ack + len(payload)) & 0xFFFFFFFF
        if flags & TCP_FIN and (seq + len(payload)) & 0xFFFFFFFF == self.ack:
            self.ack = (self.ack + 1) & 0xFFFFFFFF
            self.fin = True
        if payload or flags & TCP_FIN:
            self.send_segment(TCP_ACK)

    def connect(self, timeout=3.0):
        self.state = "syn-sent"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.state == "syn-sent" and not self.reset:
            self.send_segment(TCP_SYN)
            self.link.poll(min(0.5, deadline - time.monotonic()))
        return self.state == "established"

    def send(self, data, timeout=3.0):
        start = self.seq
        self.seq += len(data)
        deadline = time.monotonic() + timeout
        while self.acked < self.seq and time.monotonic() < deadline and not self.reset:
            for at in range(0, len(data), 1400):
                self.send_segment(TCP_PSH | TCP_ACK, data[at:at + 1400], seq=start + at)
            self.link.poll(0.3)
        return not self.reset

    def wait_for(self, done, timeout):
        deadline = time.monotonic() + timeout
        while not done() and not self.reset and time.monotonic() < deadline:
            self.link.poll(min(0.05, max(deadline - time.monotonic(), 0.001)))
        return done()

    def close(self):
        if self.state == "established" and not self.reset:
            self.send_segment(TCP_FIN | TCP_ACK)
            self.seq += 1
        self.drop()


def raw_get(link, path="/", src=PEER_IP, timeout=5.0):
    """GET over raw frames: (status, body), or None if it failed."""
    c = RawTcp(link, src)
    try:
        if not c.connect(timeout):
            return None
        c.send(f"GET {path} HTTP/1.1\r\nHost: vanir\r\nConnection: close\r\n\r\n".encode())

        def complete():
            if b"\r\n\r\n" not in c.data:
                return c.fin
            head, body = c.data.split(b"\r\n\r\n", 1)
            length = [int(l.split(b":")[1]) for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")]
            return c.fin or (length and len(body) >= length[0])

        if not c.wait_for(complete, timeout) or b"\r\n\r\n" not in c.data:
            return None
        head, body = c.data.split(b"\r\n\r\n", 1)
        return int(head.split()[1]), body.decode("latin-1")
    finally:
        c.close()


def raw_wait_ready(link, deadline):
    while time.monotonic() < deadline:
        r = raw_get(link, timeout=2)
        if r and r[0] == 200:
            return r[1]
        time.sleep(0.2)
    return None


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
        self.sent = self.received = 0  # bytes, for checking the guest's counters
        self.served = 0

    def close(self):
        self.sock.close()

    def _fill(self):
        data = self.sock.recv(65536)
        if not data:
            raise HttpError("connection closed")
        self.received += len(data)
        self.pending += data

    def request(self, path="/", keep_alive=True, method="GET", extra=b""):
        """(status, headers, body); the connection is closed after if the server said so."""
        conn = b"keep-alive" if keep_alive else b"close"
        try:
            request = f"{method} {path} HTTP/1.1\r\nHost: vanir\r\n".encode() + b"Connection: " + conn + b"\r\n" + extra + b"\r\n"
            self.sock.sendall(request)
            self.sent += len(request)
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
        self.served += 1
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
def http_get(args, want="hello from web\n"):
    """100 GETs over one keep-alive connection, then 100 over new connections."""
    deadline = time.monotonic() + args.timeout
    body = wait_ready(deadline)
    if body is None:
        say("the guest never answered")
        return finish(False)
    say(f"first answer: {body.strip()!r}")
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
def slot_http_get(args):
    """http_get against web v1 loaded into slot small-0 at run time (RFD 2)."""
    return http_get(args, want="hello from web v1 on small-0\n")


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


@scenario
def net_counters(args):
    """A known transfer: 60 requests on one connection (some 404s), then a pause for snapshots.
    tools/check-net-counters.py compares the guest's counters with the totals we print."""
    deadline = time.monotonic() + args.timeout
    c = None
    while time.monotonic() < deadline and c is None:
        try:
            c = Http(timeout=2)
            if c.request("/")[0] != 200:
                raise HttpError("not ready")
        except (OSError, HttpError):
            c = None
            time.sleep(0.2)
    if c is None:
        say("the guest never answered")
        return finish(False)
    statuses = [200]
    for i in range(59):
        path = ["/", "/count", "/missing"][i % 3]
        statuses.append(c.request(path)[0])
    c.close()
    time.sleep(2.5)  # two snapshots with nothing moving
    say(f"totals: requests={len(statuses)} ok={statuses.count(200)} not_found={statuses.count(404)} sent={c.sent} received={c.received}")
    return finish(set(statuses) == {200, 404})


@scenario
def serve_a_while(args):
    """GETs for 4 seconds (telemetry interval tests), then end the run."""
    deadline = time.monotonic() + args.timeout
    if wait_ready(deadline) is None:
        say("the guest never answered")
        return finish(False)
    end = time.monotonic() + 4
    ok = n = 0
    while time.monotonic() < end:
        n += 1
        try:
            ok += get("/")[0] == 200
        except HttpError:
            pass
        time.sleep(0.05)
    say(f"{ok}/{n} GETs ok")
    return finish(ok == n)


def wait_for_instance(name, deadline):
    """Retry GETs until `name` answers one (the switcher makes it live)."""
    while time.monotonic() < deadline:
        try:
            if get("/", timeout=2) == (200, f"hello from {name}\n"):
                return True
        except HttpError:
            pass
        time.sleep(0.2)
    return False


def under_load(args, path):
    """Eight keep-alive clients request without pause while traffic moves through the instances
    in `path` (the names after "hello from "). No request may fail, and each client must see
    exactly that sequence of instances, ending with 50 answers from the last."""
    deadline = time.monotonic() + args.timeout - 5
    if not wait_for_instance(path[0], deadline):
        say(f"{path[0]} never answered")
        return finish(False)
    answers = [[] for _ in range(8)]
    failures = []
    stop = threading.Event()

    def client(i):
        c = None
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                if c is None:
                    c = Http()
                status, _, body = c.request("/")
                if status == 200:
                    answers[i].append(body.strip().removeprefix("hello from "))
                else:
                    failures.append(f"status {status}")
                if c.closed:  # Connection: close (the old instance is draining): reconnect
                    c.close()
                    c = None
            except (HttpError, OSError) as e:
                served = c.served if c else 0
                last = answers[i][-1] if answers[i] else "none"
                failures.append(f"{e} (client {i}, request {served + 1} on its connection, last answer from {last})")
                c = None

    def seen(a):
        """The instances a client saw, in order, repeats folded."""
        return [x for k, x in enumerate(a) if k == 0 or a[k - 1] != x]

    def finished(a):
        return seen(a) == path and len(a) - (max(k for k, x in enumerate(a) if k == 0 or a[k - 1] != x)) >= 50

    threads = [threading.Thread(target=client, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    while time.monotonic() < deadline and not all(finished(list(a)) for a in answers):
        time.sleep(0.1)
    stop.set()
    for t in threads:
        t.join()
    followed = sum(1 for a in answers if seen(a) == path)
    total = sum(len(a) for a in answers)
    counts = ", ".join(f"{sum(a.count(n) for a in answers)} from {n}" for n in dict.fromkeys(path))
    say(f"{total} requests: {counts}, {len(failures)} failed")
    for f in failures[:5]:
        say(f"failure: {f}")
    for a in answers:
        if seen(a) != path:
            say(f"a client saw {seen(a)}")
    say(f"clients that followed {' -> '.join(path)}: {followed}/8")
    time.sleep(1)  # let the drain finish
    return finish(not failures and followed == 8)


@scenario
def count_under_deploy(args):
    """Four keep-alive clients ask counter for /count, then for / (which instance answered),
    while the agent deploys counter v2 over v1 (RFD 3). Every request must be answered 200 (V3:
    the new instance's requests wait during the handoff, so none is FENCED), and the counts must
    be exactly 1..N: a repeat would be an update made from stale data, a gap a lost write."""
    return count_through(args, ["counter v1 on small-0", "counter v2 on small-1"], 30)


@scenario
def count_under_move(args):
    """As count-under-deploy, while counter and its volume move from node a to node b, through
    the control plane's load balancer (RFD 3, V4c)."""
    return count_through(args, ["counter v1 on small-0", "counter v1 on small-1"], 60)


def count_through(args, path, last):
    """Four clients count through the instances in `path`, until each has had `last` answers
    from the last one."""
    deadline = time.monotonic() + args.timeout - 5
    if not wait_for_instance(path[0], deadline):
        say(f"{path[0]} never answered")
        return finish(False)
    counts, fenced, failures = [], [], []
    answers = [[] for _ in range(4)]
    stop = threading.Event()

    def client(i):
        c = None
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                if c is None:
                    c = Http()
                status, _, body = c.request("/count")
                if status == 200:
                    counts.append(int(body))
                elif status == 503 and body.strip() == "FENCED":
                    fenced.append(i)
                else:
                    failures.append(f"/count: {status} {body.strip()!r}")
                if not c.closed:
                    status, _, body = c.request("/")
                    if status == 200:
                        answers[i].append(body.strip().removeprefix("hello from "))
                if c.closed:
                    c.close()
                    c = None
            except (HttpError, OSError) as e:
                failures.append(f"{e} (client {i})")
                c = None

    def seen(a):
        return [x for k, x in enumerate(a) if k == 0 or a[k - 1] != x]

    threads = [threading.Thread(target=client, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    while time.monotonic() < deadline and not all(seen(list(a)) == path and list(a).count(path[-1]) >= last for a in answers):
        time.sleep(0.1)
    stop.set()
    for t in threads:
        t.join()
    repeats = len(counts) - len(set(counts))
    missing = len(set(range(1, max(counts, default=0) + 1)) - set(counts))
    followed = sum(1 for a in answers if seen(a) == path)
    say(f"{len(counts)} counts, highest {max(counts, default=0)}, {repeats} repeated, {missing} missing; {len(fenced)} FENCED; {len(failures)} failed")
    for f in failures[:5]:
        say(f"failure: {f}")
    say(f"clients that followed {' -> '.join(path)}: {followed}/4")
    time.sleep(1)
    return finish(not failures and not fenced and repeats == 0 and missing == 0 and followed == 4 and len(counts) > 0)


@scenario
def count_steady(args):
    """Four keep-alive clients count on counter v1 in small-0 for 30 s, through the control
    plane's load balancer, while its volume is copied and mirrored to another node (RFD 3, V4b).
    Every request must be answered 200, and the counts must be exactly 1..N."""
    deadline = time.monotonic() + args.timeout - 5
    if not wait_for_instance("counter v1 on small-0", deadline):
        say("counter v1 on small-0 never answered")
        return finish(False)
    counts, failures, slow = [], [], []
    stop = threading.Event()

    def client(i):
        c = None
        while not stop.is_set():
            try:
                if c is None:
                    c = Http()
                started = time.monotonic()
                status, _, body = c.request("/count")
                slow.append(time.monotonic() - started)
                if status == 200:
                    counts.append(int(body))
                else:
                    failures.append(f"/count: {status} {body.strip()!r}")
                if c.closed:
                    c.close()
                    c = None
            except (HttpError, OSError) as e:
                failures.append(f"{e} (client {i})")
                c = None

    threads = [threading.Thread(target=client, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    time.sleep(min(30, max(0, deadline - time.monotonic())))
    stop.set()
    for t in threads:
        t.join()
    repeats = len(counts) - len(set(counts))
    missing = len(set(range(1, max(counts, default=0) + 1)) - set(counts))
    say(f"{len(counts)} counts, highest {max(counts, default=0)}, {repeats} repeated, {missing} missing; {len(failures)} failed; "
        f"slowest {max(slow, default=0):.2f} s")
    for f in failures[:5]:
        say(f"failure: {f}")
    return finish(not failures and repeats == 0 and missing == 0 and len(counts) > 0)


@scenario
def swap_under_load(args):
    """The switcher makes web-2 live and drains web-1 (RFD 1)."""
    return under_load(args, ["web-1", "web-2"])


@scenario
def deploy_under_load(args):
    """The agent deploys web v2 into small-1 while web v1 serves from small-0 (RFD 2)."""
    return under_load(args, ["web v1 on small-0", "web v2 on small-1"])


@scenario
def rollback_under_load(args):
    """The agent deploys web v2, then rolls back to v1 from the image small-0 kept (RFD 2)."""
    return under_load(args, ["web v1 on small-0", "web v2 on small-1", "web v1 on small-0"])


@scenario
def move_under_load(args):
    """web moves from node a to node b, through the control plane's load balancer (RFD 2, D5;
    NET_PORT is the load balancer's port)."""
    return under_load(args, ["web v1 on small-0", "web v1 on small-1"])


@scenario
def evacuate_under_load(args):
    """web moves from node a to node b, node a updates and reboots, and web moves back."""
    return under_load(args, ["web v1 on small-0", "web v1 on small-1", "web v1 on small-0"])


@scenario
def drain_deadline(args):
    """Hold a connection to web-1 open without sending anything while it is drained: it is
    reset at the drain's deadline."""
    deadline = time.monotonic() + args.timeout - 5
    if not wait_for_instance("web-1", deadline):
        say("web-1 never answered")
        return finish(False)
    held = socket.create_connection(("127.0.0.1", NET_PORT), timeout=30)
    start = time.monotonic()
    try:
        data = held.recv(4096)
        how = "closed" if not data else f"answered {data[:20]!r}"
    except OSError as e:
        how = f"reset ({e.__class__.__name__})"
    say(f"the held connection ended after {time.monotonic() - start:.1f} s: {how}")
    return finish(wait_for_instance("web-2", deadline))


class Echo:
    """A client of mgmt-echo (port 7, through NET_MGMT_PORT): each line comes back."""

    def __init__(self, timeout=3.0):
        self.sock = socket.create_connection(("127.0.0.1", NET_MGMT_PORT), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.n = 0

    def round_trip(self):
        """Seconds for one line to come back; raises OSError on failure."""
        self.n += 1
        line = f"ping {self.n}\n".encode()
        start = time.monotonic()
        self.sock.sendall(line)
        got = b""
        while not got.endswith(b"\n"):
            data = self.sock.recv(4096)
            if not data:
                raise OSError("connection closed")
            got += data
        if got != line:
            raise OSError(f"echoed {got!r}")
        return time.monotonic() - start


def echo_ready(deadline):
    while time.monotonic() < deadline:
        try:
            e = Echo(timeout=2)
            e.round_trip()
            return e
        except OSError:
            time.sleep(0.2)
    return None


@scenario
def mgmt_separate(args):
    """GETs on the data network and echoes on the management network, interleaved."""
    deadline = time.monotonic() + args.timeout
    if wait_ready(deadline) is None:
        say("the data network never answered")
        return finish(False)
    echo = echo_ready(deadline)
    if echo is None:
        say("the management network never answered")
        return finish(False)
    gets = echoes = 0
    for _ in range(20):
        try:
            status, body = get("/")
            gets += status == 200 and body == "hello from web\n"
            echo.round_trip()
            echoes += 1
        except (HttpError, OSError) as e:
            say(f"failed: {e}")
    say(f"data: {gets}/20 GETs ok; management: {echoes}/20 echoes ok")
    return finish(gets == 20 and echoes == 20)


def flood_frames(count=64, size=1000):
    """Frames the data stack must look at and throw away: unknown EtherTypes and IPv4 with a
    bad checksum, all addressed to the guest."""
    frames = []
    for i in range(count):
        junk = random.randbytes(size)
        if i % 2:
            frames.append(ethernet(GUEST_MAC, 0x88B5, junk))
        else:
            packet = bytearray(ipv4(bytes([198, 51, 100, i]), GUEST_IP, 17, junk))
            packet[10] ^= 0xFF
            frames.append(ethernet(GUEST_MAC, 0x0800, bytes(packet)))
    return frames


def flood(link, seconds, frames, stats):
    """Send `frames` round and round as fast as we can for `seconds` (in a thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    end = time.monotonic() + seconds
    sent = 0
    while time.monotonic() < end:
        for f in frames:
            try:
                sock.sendto(f, link.qemu)
            except OSError:
                pass
        sent += len(frames)
    stats["sent"] = sent
    stats["seconds"] = seconds


@scenario
def mgmt_under_flood(args):
    """Flood the data NIC (dgram) while echoing on the management network every 100 ms: every
    echo must come back within 1 s. Then the data stack must still serve."""
    link = Link()
    deadline = time.monotonic() + args.timeout
    if raw_wait_ready(link, deadline) is None:
        say("the data network never answered")
        return 1
    echo = echo_ready(deadline)
    if echo is None:
        say("the management network never answered")
        return 1
    stats = {}
    t = threading.Thread(target=flood, args=(link, 6, flood_frames(), stats))
    t.start()
    times = []
    failures = 0
    while t.is_alive():
        try:
            times.append(echo.round_trip())
        except OSError as e:
            failures += 1
            say(f"echo failed: {e}")
            break
        time.sleep(0.1)
    t.join()
    say(f"flood: {stats['sent']} frames in {stats['seconds']} s ({stats['sent'] / stats['seconds']:.0f} frames/s)")
    worst = max(times) if times else 0
    late = sum(x > 1.0 for x in times)
    say(f"management echoes during the flood: {len(times)}, {late} later than 1 s, worst {worst * 1000:.0f} ms")
    link.poll(0.5)  # let the backlog drain
    after = raw_get(link, timeout=5)
    say(f"data stack after the flood: {after[0] if after else 'no answer'}")
    ok = len(times) >= 20 and late == 0 and failures == 0 and after and after[0] == 200
    raw_get(link, "/exit", timeout=2)
    say("PASS" if ok else "FAIL")
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
