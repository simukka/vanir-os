#!/usr/bin/env python3
"""A mock control plane for vanir-os nodes (RFD 2, P7), for tests.

  control-plane.py gen-keys DIR              Noise key (cp-noise.key/.pub) and desired-state
                                             signing key (cp-sign.key/.pub) for the agent to pin
  control-plane.py SCENARIO [options]        listen, and drive the node(s) through a scenario

The node's agent dials in (the guest reaches the host at 10.0.2.2 through slirp). We answer the
Noise IK handshake with our static key, check the quote in the first message binds the agent's
keys for this handshake (unless the node has no TPM: `no-tpm`), then exchange frames: we send
signed desired state (S) and images (C chunks, E end) when asked (G); the agent sends reports
(R) and telemetry lines (T, written to --telemetry). See user/agent/src/control.rs.

Nodes are named by their reports ("node a"). With --lb PORT and --backend NAME=PORT, we also
run a TCP load balancer: each new client connection goes to the first node in the backend list,
which scenarios change to move a service between nodes (tests/two-nodes.sh runs two).

Scenarios print "control-plane: PASS" or "control-plane: FAIL ..." at the end.
"""
import argparse
import glob
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vanir_attest import check, compare  # noqa: E402
from vanir_noise import Responder, public  # noqa: E402

PROLOGUE = b"vanir-agent 1"
CHUNK = 32768
SCENARIOS = {}


def scenario(fn):
    SCENARIOS[fn.__name__.replace("_", "-")] = fn
    return fn


def say(*args):
    print("control-plane:", *args, flush=True)


def gen_keys(directory):
    os.makedirs(directory, exist_ok=True)

    def write(name, data, private):
        path = os.path.join(directory, name)
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644), "wb") as f:
            f.write(data)

    noise = X25519PrivateKey.generate()
    write("cp-noise.key", noise.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                               serialization.NoEncryption()), True)
    write("cp-noise.pub", public(open(os.path.join(directory, "cp-noise.key"), "rb").read()), False)
    sign = Ed25519PrivateKey.generate()
    write("cp-sign.key", sign.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()), True)
    write("cp-sign.pub", sign.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), False)


def load_images(directory):
    """Slot images by the SHA-256 of their signed statement: name -> (hash, elf, sig, desc)."""
    images = {}
    for sig_path in glob.glob(os.path.join(directory, "*.sig")):
        name = os.path.basename(sig_path)[:-4]
        sig = open(sig_path, "rb").read()
        if len(sig) != 176:
            continue
        elf = open(os.path.join(directory, name + ".elf"), "rb").read()
        desc = open(os.path.join(directory, name + ".desc"), "rb").read()
        images[name] = (hashlib.sha256(sig[:112]).digest(), elf, sig, desc)
    return images


class Node:
    """One connection from a node's agent."""

    def __init__(self, cp, sock):
        self.cp, self.sock = cp, sock
        self.lock = threading.Lock()
        self.alive = True
        self.handshaken = False

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("closed")
            data += chunk
        return data

    def recv_message(self):
        (length,) = struct.unpack(">H", self.recv_exact(2))
        return self.recv_exact(length)

    def send_message(self, msg):
        self.sock.sendall(struct.pack(">H", len(msg)) + msg)

    def send_frame(self, kind, body):
        with self.lock:
            self.send_message(self.send.encrypt(b"", kind + body))

    def handshake(self):
        responder = Responder(self.cp.noise_key, os.urandom(32), PROLOGUE)
        try:
            payload = responder.read(self.recv_message())
        except Exception as e:  # noqa: BLE001 - any failure here is a failed handshake
            raise ConnectionError(f"handshake failed ({type(e).__name__}): not a node that knows our key")
        self.static, self.ephemeral = responder.rs, responder.re
        self.attested = self.cp.check_quote(payload, responder.re, responder.rs)
        msg, self.send, self.recv = responder.write(b"")
        self.send_message(msg)

    def run(self):
        try:
            self.handshake()
            self.handshaken = True
            self.cp.connected(self)
            while True:
                frame = self.recv.decrypt(b"", self.recv_message())
                self.cp.frame(self, frame[:1], frame[1:])
        except (ConnectionError, OSError, ValueError, InvalidTag) as e:
            if self.alive:
                say(f"connection ended: {e}")
        finally:
            self.alive = False
            self.sock.close()
            self.cp.disconnected(self)


class ControlPlane:
    def __init__(self, args):
        self.args = args
        self.noise_key = open(args.noise_key, "rb").read()
        self.sign_key = serialization.load_pem_private_key(open(args.sign_key, "rb").read(), password=None)
        self.images = load_images(args.slots)
        self.by_hash = {h: (name, elf, sig, desc) for name, (h, elf, sig, desc) in self.images.items()}
        self.nodes = {}  # name -> its current connection
        self.latest = {}  # name -> its last report
        self.reports = 0
        self.generations = {}  # name -> last generation sent
        self.epochs = {}  # service -> (epoch, slot, image) last asked for (RFD 3)
        self.backends = {}  # name -> data port, for the load balancer
        self.lb = []  # names new client connections go to (the first one)
        self.handshake_failures = 0
        self.connections = 0
        self.attested = None
        self.drop_after_chunks = None
        self.changed = threading.Condition()
        self.telemetry = open(args.telemetry, "w") if args.telemetry else None

    @property
    def node(self):
        return self.nodes.get("a")

    @property
    def report(self):
        return self.latest.get("a")

    # ---- the load balancer ----

    def balance(self, port):
        listener = socket.create_server(("127.0.0.1", port), reuse_port=True)
        while True:
            client, _ = listener.accept()
            threading.Thread(target=self.proxy, args=(client,), daemon=True).start()

    def proxy(self, client):
        with self.changed:
            name = self.lb[0] if self.lb else None
        if name is None:
            client.close()
            return
        try:
            upstream = socket.create_connection(("127.0.0.1", self.backends[name]), timeout=5)
        except OSError:
            client.close()
            return
        upstream.settimeout(None)

        def pump(a, b):
            try:
                while data := a.recv(65536):
                    b.sendall(data)
            except OSError:
                pass
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()
        pump(client, upstream)

    def route(self, *names):
        with self.changed:
            self.lb = list(names)
        say(f"load balancer: new connections go to node {names[0] if names else 'nowhere'}")

    # ---- the network side ----

    def serve(self):
        listener = socket.create_server(("127.0.0.1", self.args.port), reuse_port=True)
        while True:
            sock, _ = listener.accept()
            threading.Thread(target=Node(self, sock).run, daemon=True).start()

    def check_quote(self, payload, ephemeral, static):
        """Whether the node proved an attested boot holds this handshake's keys. Raises
        ConnectionError if we require that and it didn't."""
        if payload == b"no-tpm":
            if self.args.require_attestation:
                raise ConnectionError("refused: the node has no TPM and we require attestation")
            return False
        quote = json.loads(payload)
        problems = check(quote, ephemeral.hex(), runtime=None)
        if quote.get("kx_pub") != static.hex():
            problems.append("the quote doesn't bind this handshake's static key")
        if self.args.reference:
            problems += compare(quote, json.load(open(self.args.reference)))
        if problems:
            raise ConnectionError("refused: " + "; ".join(problems))
        say("node attested: the quote binds this handshake's keys to a measured boot")
        return True

    def connected(self, node):
        with self.changed:
            self.connections += 1
            self.attested = node.attested
            self.changed.notify_all()
        say(f"node connected ({'attested' if node.attested else 'no TPM'}), connection {self.connections}")

    def disconnected(self, node):
        with self.changed:
            for name, n in list(self.nodes.items()):
                if n is node:
                    del self.nodes[name]
            if not node.handshaken:
                self.handshake_failures += 1
            self.changed.notify_all()

    def frame(self, node, kind, body):
        if kind == b"R":
            report = parse_report(body.decode())
            name = report["node"]
            with self.changed:
                if report != self.latest.get(name):
                    head = f"node {name} image {report['image']} generation {report['generation']}"
                    head += f" update refused ({report['update_refused']} instances)" if report["update_refused"] else ""
                    head += f" refused {report['refused']}" if report["refused"] else ""
                    slots = [f"{s} {v['service']} v{v['version']} {v['state']}" for s, v in report["slots"].items()]
                    say("report: " + "; ".join([head] + slots))
                self.nodes[name] = node
                self.latest[name] = report
                self.reports += 1
                self.changed.notify_all()
        elif kind == b"G":
            digest, slot = body[:32], body[32:].decode()
            threading.Thread(target=self.send_image, args=(node, digest, slot), daemon=True).start()
        elif kind == b"T":
            if self.telemetry:
                self.telemetry.write(body.decode(errors="replace"))
                self.telemetry.flush()
        else:
            say(f"unknown frame {kind!r}")

    def send_image(self, node, digest, slot):
        if digest not in self.by_hash:
            say(f"node asked for an image we don't have: {digest.hex()[:16]}")
            return
        name, elf, sig, desc = self.by_hash[digest]
        say(f"sending {name} ({len(elf)} bytes) into {slot}")
        try:
            for i, offset in enumerate(range(0, len(elf), CHUNK)):
                if self.drop_after_chunks is not None and i == self.drop_after_chunks:
                    self.drop_after_chunks = None
                    say(f"dropping the connection after {i} chunks of {name}")
                    node.alive = False
                    node.sock.shutdown(socket.SHUT_RDWR)
                    return
                node.send_frame(b"C", digest + struct.pack("<I", offset) + elf[offset:offset + CHUNK])
            node.send_frame(b"E", digest + sig + desc)
        except OSError as e:
            say(f"sending {name} failed: {e}")

    # ---- the scenario side ----

    def send_desired(self, generation, lines, key=None, node="a"):
        doc = "\n".join(["vanir-desired 1", f"generation {generation}"] + lines).encode()
        signature = (key or self.sign_key).sign(doc)
        self.wait(lambda: node in self.nodes, f"connection from node {node}")
        say(f"desired state {generation} for node {node}: " + "; ".join(lines))
        self.generations[node] = generation
        self.nodes[node].send_frame(b"S", struct.pack("<I", len(doc)) + doc + signature)
        return doc, signature

    def tell(self, node, lines):
        """Send `node` the next generation of desired state."""
        return self.send_desired(self.generations.get(node, 0) + 1, lines, node=node)

    def resend(self, doc, signature, why):
        generation = doc.decode().split("\n")[1]
        say(f"sending {generation} again ({why})")
        self.node.send_frame(b"S", struct.pack("<I", len(doc)) + doc + signature)

    def wait(self, predicate, what, timeout=None):
        deadline = time.monotonic() + (timeout or self.args.timeout)
        with self.changed:
            while not predicate():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError(f"no {what}")
                self.changed.wait(min(left, 0.5))

    def wait_slots(self, what, node="a", **want):
        """Wait for a report whose slots match: slot=(service, version, state) or slot=state."""
        def ok():
            report = self.latest.get(node)
            if not report:
                return False
            for slot, w in want.items():
                s = report["slots"].get(slot.replace("_", "-"))
                if s is None:
                    return False
                got = s["state"] if isinstance(w, str) else (s["service"], s["version"], s["state"])
                if got != w:
                    return False
            return True
        self.wait(ok, what)
        say(f"reached: {what}")

    def live(self, service, slot, image, drain=None, epoch=None):
        """A `live` line. For an image with a volume, the writer epoch goes up by one whenever
        the live instance changes (another slot or image); `epoch` overrides it."""
        line = f"live {service} {slot} {self.images[image][0].hex()}"
        line += f" drain {drain}" if drain is not None else ""
        if volume_blocks(self.images[image][3]):
            last, last_slot, last_image = self.epochs.get(service, (0, None, None))
            if epoch is None:
                epoch = last if (slot, image) == (last_slot, last_image) else last + 1
            self.epochs[service] = (epoch, slot, image)
            lease = int(time.time() * 1000) + 30_000  # recorded by the node, not yet enforced
            line += f" epoch {epoch} {lease}"
        return line


def volume_blocks(desc):
    """The volume a descriptor declares (RFD 3), in blocks; 0 for none."""
    return struct.unpack_from("<Q", desc, 152)[0]


def parse_report(text):
    """report <generation> node <name> image <version> [update-refused <n>] [refused <why>],
    then a line per slot: slot <name> <service> <version> <hash> <state> [epoch <n>]
    [epoch-refused <n>]"""
    lines = text.strip().split("\n")
    head = lines[0].split()
    report = {"generation": int(head[1]), "node": head[3], "image": int(head[5]), "update_refused": None, "refused": None, "slots": {}}
    rest = head[6:]
    if rest[:1] == ["update-refused"]:
        report["update_refused"] = int(rest[1])
        rest = rest[2:]
    if rest[:1] == ["refused"]:
        report["refused"] = " ".join(rest[1:])
    for line in lines[1:]:
        _, name, service, version, digest, state, *extra = line.split()
        slot = {"service": service, "version": int(version), "hash": digest, "state": state, "epoch": None, "epoch_refused": None}
        for key, value in zip(extra[::2], extra[1::2]):
            slot[key.replace("-", "_")] = int(value)
        report["slots"][name] = slot
    return report


# ---- scenarios ----------------------------------------------------------------------------

@scenario
def connect(cp):
    """The node dials in, attests if it can, and reports; then the test ends."""
    cp.wait(lambda: cp.report is not None, "report")
    say(f"first report: generation {cp.report['generation']}, slots {', '.join(cp.report['slots']) or 'none yet'}")
    cp.send_desired(1, ["end"])
    cp.wait(lambda: cp.report and cp.report["generation"] == 1, "report of generation 1")
    return True


@scenario
def wrong_key(cp):
    """We aren't the control plane the node pinned: every handshake fails, and the node never
    reports or takes a command."""
    cp.wait(lambda: cp.handshake_failures >= 3, "three failed handshakes")
    say(f"{cp.handshake_failures} handshakes failed; reports: {cp.reports}")
    return cp.reports == 0


@scenario
def signed_state(cp):
    """Desired state signed with another key, a replayed one and an older one are refused."""
    cp.wait(lambda: cp.report is not None, "report")
    rogue = Ed25519PrivateKey.generate()
    cp.send_desired(5, ["end"], key=rogue)
    cp.wait(lambda: cp.report["refused"] == "bad signature", "refusal of a bad signature")
    say("refused: signed with another key")
    doc, sig = cp.send_desired(2, [])
    cp.wait(lambda: cp.report["generation"] == 2 and not cp.report["refused"], "generation 2")
    cp.resend(doc, sig, "a replay")
    cp.wait(lambda: cp.report["refused"] == "stale generation (replayed?)", "refusal of a replay")
    say("refused: replayed generation 2")
    cp.send_desired(1, ["end"])
    cp.wait(lambda: cp.report["refused"] == "stale generation (replayed?)" and cp.report["generation"] == 2, "refusal of generation 1")
    say("refused: older generation 1")
    cp.send_desired(3, ["end"])
    cp.wait(lambda: cp.report["generation"] == 3, "generation 3")
    return True


@scenario
def deploy(cp):
    """web v1 live in small-0, then v2 deployed into small-1 (the peer keeps requesting), then
    committed: small-0 is emptied."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.send_desired(1, [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web v1 live in small-0", small_0=("web", 1, "LIVE"))
    time.sleep(3)
    cp.send_desired(2, [cp.live("web", "small-1", "web-v2")])
    cp.wait_slots("web v2 live in small-1, v1 stopped", small_1=("web", 2, "LIVE"), small_0="STOPPED")
    cp.send_desired(3, [cp.live("web", "small-1", "web-v2"), "commit web"])
    cp.wait_slots("web v1 unloaded", small_0="EMPTY")
    return True


@scenario
def reconnect(cp):
    """The connection drops in the middle of an image transfer, and right after a deployment
    is asked for; the node reconnects, picks up where it was, and gets there."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.drop_after_chunks = 3
    cp.send_desired(1, [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web v1 live in small-0", small_0=("web", 1, "LIVE"))
    cp.send_desired(2, [cp.live("web", "small-1", "web-v2", drain=5)])
    connections = cp.connections
    cp.wait(lambda: cp.report["generation"] == 2, "report of generation 2")
    say("dropping the connection during the deployment")
    cp.node.alive = False
    cp.node.sock.shutdown(socket.SHUT_RDWR)
    cp.wait(lambda: cp.connections > connections, "a new connection")
    cp.wait_slots("web v2 live in small-1, v1 stopped", small_1=("web", 2, "LIVE"), small_0="STOPPED")
    say(f"connections: {cp.connections}")
    cp.send_desired(3, [cp.live("web", "small-1", "web-v2"), "end"])
    cp.wait(lambda: cp.report["generation"] == 3, "report of generation 3")
    return cp.connections >= 3


@scenario
def drain(cp):
    """web v1 live, then drained and stopped on command, with a 2 s deadline."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.send_desired(1, [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web v1 live in small-0", small_0=("web", 1, "LIVE"))
    cp.send_desired(2, ["stop web drain 2"])
    cp.wait_slots("web v1 stopped", small_0=("web", 1, "STOPPED"))
    cp.send_desired(3, ["end"])
    cp.wait(lambda: cp.report["generation"] == 3, "report of generation 3")
    return True


@scenario
def update_refused(cp):
    """A node running an instance refuses to update (RFD 2, determination 1)."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.tell("a", [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web v1 live in small-0", small_0=("web", 1, "LIVE"))
    cp.tell("a", [cp.live("web", "small-0", "web-v1"), "update"])
    cp.wait(lambda: cp.report["update_refused"] == 1, "the update refused")
    say("node a refused the update: it runs 1 instance")
    cp.tell("a", [cp.live("web", "small-0", "web-v1"), "end"])
    cp.wait(lambda: cp.report["generation"] == 3, "report of generation 3")
    return True


def slot_epoch(cp, slot, node="a"):
    """(epoch, epoch refused) in `slot` in the latest report."""
    s = cp.latest.get(node, {}).get("slots", {}).get(slot, {})
    return s.get("epoch"), s.get("epoch_refused")


@scenario
def volume(cp):
    """counter v1 live in small-0 with epoch 1, then v2 deployed into small-1 with epoch 2 while
    the peer keeps counting (RFD 3, V1)."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.send_desired(1, [cp.live("counter", "small-0", "counter-v1")])
    cp.wait_slots("counter v1 live in small-0", small_0=("counter", 1, "LIVE"))
    cp.wait(lambda: slot_epoch(cp, "small-0") == (1, None), "epoch 1 in small-0")
    say("reached: small-0 holds epoch 1")
    time.sleep(3)
    cp.send_desired(2, [cp.live("counter", "small-1", "counter-v2")])
    cp.wait_slots("counter v2 live in small-1, v1 stopped", small_1=("counter", 2, "LIVE"), small_0="STOPPED")
    cp.wait(lambda: slot_epoch(cp, "small-1") == (2, None) and slot_epoch(cp, "small-0") == (None, None), "epoch 2 in small-1 only")
    say("reached: small-1 holds epoch 2")
    return True


@scenario
def epoch_stale(cp):
    """After epoch 2, desired state with a newer generation but epoch 1 for the same instance:
    the node applies it, storage refuses the epoch, and the report says so (RFD 3, V1)."""
    cp.wait(lambda: cp.report is not None, "report")
    cp.send_desired(1, [cp.live("counter", "small-0", "counter-v1", epoch=2)])
    cp.wait_slots("counter v1 live in small-0", small_0=("counter", 1, "LIVE"))
    cp.wait(lambda: slot_epoch(cp, "small-0") == (2, None), "epoch 2 in small-0")
    say("reached: small-0 holds epoch 2")
    cp.send_desired(2, [cp.live("counter", "small-0", "counter-v1", epoch=1)])
    cp.wait(lambda: cp.report["generation"] == 2 and slot_epoch(cp, "small-0") == (2, 1), "epoch 1 refused")
    say("reached: epoch 1 refused, small-0 still holds epoch 2")
    cp.send_desired(3, [cp.live("counter", "small-0", "counter-v1", epoch=3), "end"])
    cp.wait(lambda: cp.report["generation"] == 3 and slot_epoch(cp, "small-0") == (3, None), "epoch 3 in small-0")
    say("reached: small-0 holds epoch 3")
    return True


def move_web(cp, src, src_slot, dst, dst_slot):
    """Move web from node `src` to node `dst` (RFD 2, P3: a move): start it on `dst`, wait until
    it is live there, send new connections to `dst`, then drain and stop it on `src`, and commit."""
    cp.tell(dst, [cp.live("web", dst_slot, "web-v1")])
    cp.wait_slots(f"web live on node {dst}", node=dst, **{dst_slot: ("web", 1, "LIVE")})
    cp.route(dst)
    cp.tell(src, ["stop web drain 30"])
    cp.wait_slots(f"web stopped on node {src}", node=src, **{src_slot: "STOPPED"})
    cp.tell(src, ["commit web"])
    cp.wait_slots(f"web unloaded from node {src}", node=src, **{src_slot: "EMPTY"})


@scenario
def move(cp):
    """web moves from node a (small-0) to node b (small-1) under load, through the load
    balancer; then node a, now empty, ends."""
    cp.wait(lambda: "a" in cp.latest and "b" in cp.latest, "reports from nodes a and b")
    cp.tell("a", [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web live on node a", node="a", small_0=("web", 1, "LIVE"))
    cp.route("a")
    time.sleep(5)  # serve from node a for a while
    move_web(cp, "a", "small-0", "b", "small-1")
    cp.tell("a", ["end"])
    return True


@scenario
def evacuate(cp):
    """Node a runs web, refuses an update, is evacuated to node b, accepts the update, reboots
    into its new image (signed version 2), reconnects, and web moves back to it. All under load."""
    cp.wait(lambda: "a" in cp.latest and "b" in cp.latest, "reports from nodes a and b")
    first_image = cp.latest["a"]["image"]
    cp.tell("a", [cp.live("web", "small-0", "web-v1")])
    cp.wait_slots("web live on node a", node="a", small_0=("web", 1, "LIVE"))
    cp.route("a")
    time.sleep(3)
    cp.tell("a", [cp.live("web", "small-0", "web-v1"), "update"])
    cp.wait(lambda: cp.latest["a"]["update_refused"] == 1, "node a refusing the update")
    say("node a refused the update: it runs 1 instance")
    move_web(cp, "a", "small-0", "b", "small-1")
    connections = cp.connections
    cp.tell("a", ["update"])
    cp.wait(lambda: cp.connections > connections and cp.latest["a"]["image"] != first_image, "node a back with a new image", timeout=cp.args.timeout)
    say(f"node a rejoined with image version {cp.latest['a']['image']} (was {first_image})")
    cp.generations["a"] = 0  # a rebooted agent starts from no desired state
    move_web(cp, "b", "small-1", "a", "small-0")
    cp.tell("b", ["end"])
    return True


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "gen-keys":
        if len(sys.argv) != 3:
            sys.exit("usage: control-plane.py gen-keys DIR")
        gen_keys(sys.argv[2])
        return
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("scenario", choices=sorted(SCENARIOS))
    p.add_argument("--port", type=int, default=7000)
    p.add_argument("--noise-key", default="keys/cp-noise.key")
    p.add_argument("--sign-key", default="keys/cp-sign.key")
    p.add_argument("--slots", default="build/slots")
    p.add_argument("--telemetry", default="build/cp-telemetry.log", help="where telemetry from the node goes")
    p.add_argument("--require-attestation", action="store_true")
    p.add_argument("--reference", help="also compare quotes with this reference (verify-quote.py --record)")
    p.add_argument("--timeout", type=float, default=60)
    p.add_argument("--lb", type=int, metavar="PORT", help="run a load balancer on this port")
    p.add_argument("--linger", type=float, default=1, metavar="SECONDS",
                   help="keep serving (the load balancer too) this long after the scenario")
    p.add_argument("--backend", action="append", default=[], metavar="NAME=PORT", help="a node's data port")
    args = p.parse_args()
    if not os.path.exists(args.noise_key):  # e.g. a rogue key for a test
        key = X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption())
        with open(os.open(args.noise_key, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key)
    cp = ControlPlane(args)
    threading.Thread(target=cp.serve, daemon=True).start()
    for b in args.backend:
        name, port = b.split("=")
        cp.backends[name] = int(port)
    if args.lb:
        threading.Thread(target=cp.balance, args=(args.lb,), daemon=True).start()
    try:
        ok = SCENARIOS[args.scenario](cp)
    except TimeoutError as e:
        say(f"FAIL: {e}")
        sys.exit(1)
    say("PASS" if ok else "FAIL")
    sys.stdout.flush()
    time.sleep(args.linger)  # let the last frames go out, and clients finish through the balancer
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
