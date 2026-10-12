"""Noise IK_25519_ChaChaPoly_SHA256, both sides, for the host tools (tools/control-plane.py) and
for checking user/noise against the cacophony test vectors. Written from the Noise spec
(https://noiseprotocol.org/noise.html), independently of the Rust code."""
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

PROTOCOL = b"Noise_IK_25519_ChaChaPoly_SHA256"
MAX_NONCE = 2**64 - 1


def public(secret):
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def dh(secret, public_key):
    return X25519PrivateKey.from_private_bytes(secret).exchange(X25519PublicKey.from_public_bytes(public_key))


def hkdf(ck, ikm, n=2):
    temp = hmac.new(ck, ikm, hashlib.sha256).digest()
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = hmac.new(temp, prev + bytes([i]), hashlib.sha256).digest()
        out.append(prev)
    return out


class Cipher:
    def __init__(self, key=None):
        self.key, self.n = key, 0

    def _nonce(self):
        return bytes(4) + struct.pack("<Q", self.n)

    def encrypt(self, ad, plaintext):
        if self.key is None:
            return plaintext
        out = ChaCha20Poly1305(self.key).encrypt(self._nonce(), plaintext, ad)
        self.n += 1
        return out

    def decrypt(self, ad, ciphertext):
        if self.key is None:
            return ciphertext
        out = ChaCha20Poly1305(self.key).decrypt(self._nonce(), ciphertext, ad)
        self.n += 1
        return out


class Symmetric:
    def __init__(self, prologue):
        self.h = PROTOCOL if len(PROTOCOL) == 32 else hashlib.sha256(PROTOCOL).digest()
        self.ck = self.h
        self.cipher = Cipher()
        self.mix_hash(prologue)

    def mix_hash(self, data):
        self.h = hashlib.sha256(self.h + data).digest()

    def mix_key(self, ikm):
        self.ck, k = hkdf(self.ck, ikm)
        self.cipher = Cipher(k)

    def encrypt_and_hash(self, plaintext):
        c = self.cipher.encrypt(self.h, plaintext)
        self.mix_hash(c)
        return c

    def decrypt_and_hash(self, ciphertext):
        p = self.cipher.decrypt(self.h, ciphertext)
        self.mix_hash(ciphertext)
        return p

    def split(self):
        k1, k2 = hkdf(self.ck, b"")
        return Cipher(k1), Cipher(k2)


class Initiator:
    def __init__(self, s, e, rs, prologue=b""):
        self.sym, self.s, self.e, self.rs = Symmetric(prologue), s, e, rs
        self.sym.mix_hash(rs)

    def write(self, payload):
        e_pub = public(self.e)
        self.sym.mix_hash(e_pub)
        self.sym.mix_key(dh(self.e, self.rs))
        s = self.sym.encrypt_and_hash(public(self.s))
        self.sym.mix_key(dh(self.s, self.rs))
        return e_pub + s + self.sym.encrypt_and_hash(payload)

    def read(self, msg):
        re = msg[:32]
        self.sym.mix_hash(re)
        self.sym.mix_key(dh(self.e, re))
        self.sym.mix_key(dh(self.s, re))
        payload = self.sym.decrypt_and_hash(msg[32:])
        send, recv = self.sym.split()
        return payload, send, recv


class Responder:
    """The control plane's side. After `read`, `rs` is the initiator's static key and `re` its
    ephemeral key."""

    def __init__(self, s, e, prologue=b""):
        self.sym, self.s, self.e = Symmetric(prologue), s, e
        self.sym.mix_hash(public(s))

    def read(self, msg):
        self.re = msg[:32]
        self.sym.mix_hash(self.re)
        self.sym.mix_key(dh(self.s, self.re))
        self.rs = self.sym.decrypt_and_hash(msg[32:80])
        self.sym.mix_key(dh(self.s, self.rs))
        return self.sym.decrypt_and_hash(msg[80:])

    def write(self, payload):
        e_pub = public(self.e)
        self.sym.mix_hash(e_pub)
        self.sym.mix_key(dh(self.e, self.re))
        self.sym.mix_key(dh(self.e, self.rs))
        msg = e_pub + self.sym.encrypt_and_hash(payload)
        initiator_send, initiator_recv = self.sym.split()
        # Returns (message, our send cipher, our receive cipher): we send with the key the
        # initiator receives with.
        return msg, initiator_recv, initiator_send


def check_vector(v):
    """Run a cacophony vector through both sides; returns a list of problems."""
    b = bytes.fromhex
    problems = []
    init = Initiator(b(v["init_static"]), b(v["init_ephemeral"]), b(v["init_remote_static"]), b(v["init_prologue"]))
    resp = Responder(b(v["resp_static"]), b(v["resp_ephemeral"]), b(v["resp_prologue"]))
    msgs = v["messages"]
    m0 = init.write(b(msgs[0]["payload"]))
    if m0.hex() != msgs[0]["ciphertext"]:
        problems.append("message 0 differs")
    if resp.read(m0).hex() != msgs[0]["payload"]:
        problems.append("message 0 doesn't read back")
    m1, r_send, r_recv = resp.write(b(msgs[1]["payload"]))
    if m1.hex() != msgs[1]["ciphertext"]:
        problems.append("message 1 differs")
    payload, i_send, i_recv = init.read(m1)
    if payload.hex() != msgs[1]["payload"]:
        problems.append("message 1 doesn't read back")
    if init.sym.h.hex() != v["handshake_hash"]:
        problems.append("handshake hash differs")
    for k, m in enumerate(msgs[2:], 2):
        sender, receiver = (i_send, r_recv) if k % 2 == 0 else (r_send, i_recv)
        c = sender.encrypt(b"", b(m["payload"]))
        if c.hex() != m["ciphertext"]:
            problems.append(f"transport message {k} differs")
        if receiver.decrypt(b"", c).hex() != m["payload"]:
            problems.append(f"transport message {k} doesn't read back")
    return problems
