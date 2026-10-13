#!/usr/bin/env python3
"""Sign vanir-os task images.

  sign-image.py gen-key KEY PUB                 new Ed25519 key pair (PEM private, raw 32-byte public)
  sign-image.py sign KEY PROGRAM ELF OUT [--version N]
  sign-image.py sign-all KEY DIR PROGRAM... [--version N]   DIR/<program>.elf -> DIR/<program>.sig
  sign-image.py sign-slot KEY ELF DESC.toml OUT             a service image for a slot (RFD 2):
                                                            OUT.desc and OUT.sig
  sign-image.py descriptor DESC.toml OUT                    the descriptor alone (fixtures)
  sign-image.py port DESC.toml                              the first port it listens on (make run-service)

The signature file (144 bytes) is what the kernel checks before running a task:

  0   8   magic "VNRSIG01"
  8   32  program name, zero padded (must match the task's `program`)
  40  8   version, little endian (must be >= the manifest's `min_version`)
  48  32  SHA-256 of the ELF
  80  64  Ed25519 signature over bytes 0..80

A service image for a generic slot comes with a descriptor, compiled from TOML into the layout
the kernel reads (vanir_abi::descriptor, abi/src/lib.rs: format 2, 512 bytes; format 1, 256
bytes, with `format = 1`), and a 176-byte signature file that covers both:

  0   8   magic "VNRSIG02"
  8   32  service name, zero padded
  40  8   version, little endian
  48  32  SHA-256 of the ELF
  80  32  SHA-256 of the descriptor
  112 64  Ed25519 signature over bytes 0..112

  name = "web"                 # the service, 1..32 bytes
  version = 2
  min_version = 1              # oldest version that may still run (default 0)
  slot_class = "small"
  listen = [{ port = 80, max_connections = 64, max_per_source = 16 }]
  drain = { default_secs = 30, max_secs = 300 }   # (defaults)
  volume = { blocks = 256 }    # the service's volume (RFD 3), 1..65536 blocks; none if absent
  abi = "1.0"                  # the ABI it was built against (default: ABI_MAJOR.ABI_MINOR in
                               # abi/src/lib.rs); format 2 only
  format = 2                   # 1 writes the older 256-byte format (no abi, no config)

  [config]                     # settings (RFD 9, P5), format 2 only: at most 12; keys 1..16
  persist_ticks = 1000         # bytes of a-z, 0-9, _ starting with a letter; u64 values
"""
import argparse
import hashlib
import os
import re
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MAGIC = b"VNRSIG01"
MAGIC_V2 = b"VNRSIG02"
DESC_MAGIC = b"VNRDSC01"
DESC_MAGIC_V2 = b"VNRDSC02"
MAX_SETTINGS = 12
KEY = re.compile(rb"[a-z][a-z0-9_]{0,15}")


def abi_version():
    """(major, minor) from vanir-abi, the version a service built in this repository uses."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "abi", "src", "lib.rs")
    src = open(path).read()
    find = lambda name: int(re.search(rf"pub const {name}: u32 = (\d+);", src).group(1))
    return find("ABI_MAJOR"), find("ABI_MINOR")


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


def descriptor(path):
    """Compile a descriptor TOML into the kernel's layout; returns (bytes, name, version)."""
    import tomllib
    with open(path, "rb") as f:
        d = tomllib.load(f)
    known = {"name", "version", "min_version", "slot_class", "listen", "drain", "volume", "abi", "format", "config"}
    if set(d) - known:
        sys.exit(f"{path}: unknown keys {sorted(set(d) - known)}")
    name, cls = d["name"].encode(), d["slot_class"].encode()
    if not 1 <= len(name) <= 32 or not 1 <= len(cls) <= 16:
        sys.exit(f"{path}: name must be 1..32 bytes, slot_class 1..16")
    version, floor = d["version"], d.get("min_version", 0)
    drain = d.get("drain", {})
    default = drain.get("default_secs", 30)
    maximum = drain.get("max_secs", max(default, 300))
    listen = d.get("listen", [])
    if len(listen) > 8:
        sys.exit(f"{path}: at most 8 listen entries")
    out = DESC_MAGIC + name.ljust(32, b"\0") + struct.pack("<QQ", version, floor) + cls.ljust(16, b"\0")
    out += struct.pack("<IIII", default, maximum, len(listen), 0)
    for entry in listen:
        mc = entry.get("max_connections", 64)
        out += struct.pack("<HHHH", entry["port"], mc, entry.get("max_per_source", mc), 0)
    out = out.ljust(152, b"\0")
    volume = d.get("volume")
    if volume is not None:
        if set(volume) != {"blocks"} or not 1 <= volume["blocks"] <= 65536:
            sys.exit(f"{path}: volume must be {{ blocks = N }}, 1 <= N <= 65536")
    out += struct.pack("<Q", volume["blocks"] if volume else 0)
    fmt = d.get("format", 2)
    if fmt == 1:
        if "abi" in d or "config" in d:
            sys.exit(f"{path}: format 1 has no abi or config")
        out = out.ljust(256, b"\0")
        assert len(out) == 256
        return out, name, version
    if fmt != 2:
        sys.exit(f"{path}: format must be 1 or 2")
    out = DESC_MAGIC_V2 + out[8:]
    if "abi" in d:
        m = re.fullmatch(r"(\d+)\.(\d+)", str(d["abi"]))
        if not m:
            sys.exit(f"{path}: abi must be \"MAJOR.MINOR\"")
        major, minor = int(m.group(1)), int(m.group(2))
    else:
        major, minor = abi_version()
    config = d.get("config", {})
    if len(config) > MAX_SETTINGS:
        sys.exit(f"{path}: at most {MAX_SETTINGS} settings")
    out += struct.pack("<IIQ", major, minor, len(config))
    for key, value in config.items():
        k = key.encode()
        if not KEY.fullmatch(k):
            sys.exit(f"{path}: setting {key!r}: keys are 1..16 bytes of a-z, 0-9, _, starting with a letter")
        if not isinstance(value, int) or not 0 <= value < 2**64:
            sys.exit(f"{path}: setting {key!r}: values are integers 0..2^64-1")
        out += k.ljust(16, b"\0") + struct.pack("<Q", value)
    out = out.ljust(512, b"\0")
    assert len(out) == 512
    return out, name, version


def sign_slot(key_path, elf_path, desc_path, out):
    desc, name, version = descriptor(desc_path)
    with open(key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(elf_path, "rb") as f:
        image_hash = hashlib.sha256(f.read()).digest()
    signed = MAGIC_V2 + name.ljust(32, b"\0") + struct.pack("<Q", version) + image_hash + hashlib.sha256(desc).digest()
    with open(out + ".desc", "wb") as f:
        f.write(desc)
    with open(out + ".sig", "wb") as f:
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
    t = sub.add_parser("sign-slot")
    t.add_argument("key")
    t.add_argument("elf")
    t.add_argument("descriptor")
    t.add_argument("out")
    dsc = sub.add_parser("descriptor")
    dsc.add_argument("descriptor")
    dsc.add_argument("out")
    prt = sub.add_parser("port", help="print the first port a descriptor listens on (make run-service)")
    prt.add_argument("descriptor")
    args = p.parse_args()
    if args.cmd == "sign-slot":
        sign_slot(args.key, args.elf, args.descriptor, args.out)
    elif args.cmd == "port":
        import tomllib
        with open(args.descriptor, "rb") as f:
            listen = tomllib.load(f).get("listen", [])
        if not listen:
            sys.exit(f"{args.descriptor}: listens on no port")
        print(listen[0]["port"])
    elif args.cmd == "descriptor":
        with open(args.out, "wb") as f:
            f.write(descriptor(args.descriptor)[0])
    elif args.cmd == "gen-key":
        gen_key(args.key, args.pub)
    elif args.cmd == "sign":
        sign(args.key, args.program, args.elf, args.out, args.version)
    else:
        for program in args.programs:
            base = os.path.join(args.dir, program)
            sign(args.key, program, base + ".elf", base + ".sig", args.version)


if __name__ == "__main__":
    main()
