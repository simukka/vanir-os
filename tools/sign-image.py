#!/usr/bin/env python3
"""Sign vanir-os task images.

  sign-image.py gen-key KEY PUB                 new Ed25519 key pair (PEM private, raw 32-byte public)
  sign-image.py sign KEY PROGRAM ELF OUT [--version N]
  sign-image.py sign-all KEY DIR PROGRAM... [--version N]   DIR/<program>.elf -> DIR/<program>.sig

The signature file (144 bytes) is what the kernel checks before running a task:

  0   8   magic "VNRSIG01"
  8   32  program name, zero padded (must match the task's `program`)
  40  8   version, little endian (must be >= the manifest's `min_version`)
  48  32  SHA-256 of the ELF
  80  64  Ed25519 signature over bytes 0..80
"""
import argparse
import hashlib
import os
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAGIC = b"VNRSIG01"


def gen_key(key_path, pub_path):
    key = Ed25519PrivateKey.generate()
    with open(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(pub_path, "wb") as f:
        f.write(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def sign(key_path, program, elf_path, out_path, version):
    name = program.encode()
    if len(name) > 32:
        sys.exit(f"program name {program!r} longer than 32 bytes")
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(elf_path, "rb") as f:
        digest = hashlib.sha256(f.read()).digest()
    signed = MAGIC + name.ljust(32, b"\0") + struct.pack("<Q", version) + digest
    with open(out_path, "wb") as f:
        f.write(signed + key.sign(signed))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen-key")
    g.add_argument("key")
    g.add_argument("pub")
    s = sub.add_parser("sign")
    s.add_argument("key")
    s.add_argument("program")
    s.add_argument("elf")
    s.add_argument("out")
    s.add_argument("--version", type=int, default=1)
    a = sub.add_parser("sign-all")
    a.add_argument("key")
    a.add_argument("dir")
    a.add_argument("programs", nargs="+")
    a.add_argument("--version", type=int, default=1)
    args = p.parse_args()
    if args.cmd == "gen-key":
        gen_key(args.key, args.pub)
    elif args.cmd == "sign":
        sign(args.key, args.program, args.elf, args.out, args.version)
    else:
        for program in args.programs:
            base = os.path.join(args.dir, program)
            sign(args.key, program, base + ".elf", base + ".sig", args.version)


if __name__ == "__main__":
    main()
