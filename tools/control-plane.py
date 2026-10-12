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
        self.node = None
        self.report = None
        self.reports = 0
        self.handshake_failures = 0
        self.connections = 0
        self.attested = None
        self.drop_after_chunks = None
        self.changed = threading.Condition()
        self.telemetry = open(args.telemetry, "w") if args.telemetry else None

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
            self.node = node
            self.connections += 1
            self.attested = node.attested
            self.changed.notify_all()
        say(f"node connected ({'attested' if node.attested else 'no TPM'}), connection {self.connections}")

    def disconnected(self, node):
        with self.changed:
            if self.node is node:
                self.node = None
            if not node.handshaken:
                self.handshake_failures += 1
            self.changed.notify_all()

    def frame(self, node, kind, body):
        if kind == b"R":
            report = parse_report(body.decode())
            with self.changed:
                if report != self.report:
                    head = f"generation {report['generation']}" + (f" refused {report['refused']}" if report["refused"] else "")
                    slots = [f"{s} {v['service']} v{v['version']} {v['state']}" for s, v in report["slots"].items()]
                    say("report: " + "; ".join([head] + slots))
                self.report = report
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

    def send_desired(self, generation, lines, key=None):
        doc = "\n".join(["vanir-desired 1", f"generation {generation}"] + lines).encode()
        signature = (key or self.sign_key).sign(doc)
        self.wait(lambda: self.node is not None, "a connection")
        say(f"desired state {generation}: " + "; ".join(lines))
        self.node.send_frame(b"S", struct.pack("<I", len(doc)) + doc + signature)
        return doc, signature

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

    def wait_slots(self, what, **want):
        """Wait for a report whose slots match: slot=(service, version, state) or slot=state."""
        def ok():
            if not self.report:
                return False
            for slot, w in want.items():
                s = self.report["slots"].get(slot.replace("_", "-"))
                if s is None:
                    return False
                got = s["state"] if isinstance(w, str) else (s["service"], s["version"], s["state"])
                if got != w:
                    return False
            return True
        self.wait(ok, what)
        say(f"reached: {what}")

    def live(self, service, slot, image, drain=None):
        line = f"live {service} {slot} {self.images[image][0].hex()}"
        return line + (f" drain {drain}" if drain is not None else "")


def parse_report(text):
    lines = text.strip().split("\n")
    head = lines[0].split()
    report = {"generation": int(head[1]), "refused": " ".join(head[3:]) if len(head) > 2 else None, "slots": {}}
    for line in lines[1:]:
        _, name, service, version, digest, state = line.split()
        report["slots"][name] = {"service": service, "version": int(version), "hash": digest, "state": state}
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
    args = p.parse_args()
    if not os.path.exists(args.noise_key):  # e.g. a rogue key for a test
        key = X25519PrivateKey.generate().private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption())
        with open(os.open(args.noise_key, os.O_WRONLY | os.O_CREAT, 0o600), "wb") as f:
            f.write(key)
    cp = ControlPlane(args)
    threading.Thread(target=cp.serve, daemon=True).start()
    try:
        ok = SCENARIOS[args.scenario](cp)
    except TimeoutError as e:
        say(f"FAIL: {e}")
        sys.exit(1)
    say("PASS" if ok else "FAIL")
    time.sleep(1)  # let the last frames go out
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
