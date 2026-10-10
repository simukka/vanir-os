#!/usr/bin/env python3
"""Compute the PCR 12 value a boot should produce, from the build output alone (see
kernel/src/measure.rs): extend with SHA-256 of the kernel file, of the app manifest, then of each
task's signed statement (first 80 bytes of its .sig), in manifest order; a rejected task
contributes 32 zero bytes.

  expected-pcrs.py --boot build/esp/boot --app tests/apps/hello.toml [--rejected NAME ...]
"""
import argparse
import hashlib
import tomllib


def extend(pcr, digest):
    return hashlib.sha256(pcr + digest).digest()


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--boot", default="build/esp/boot", help="directory with vanir-kernel, *.sig")
    p.add_argument("--app", required=True, help="the app manifest the kernel was built with")
    p.add_argument("--rejected", action="append", default=[], help="task whose image was rejected")
    p.add_argument("--log", action="store_true", help="print each measurement too")
    args = p.parse_args()

    with open(args.app, "rb") as f:
        manifest = f.read()
    entries = [("kernel", hashlib.sha256(open(f"{args.boot}/vanir-kernel", "rb").read()).digest()),
               ("manifest", hashlib.sha256(manifest).digest())]
    for task in tomllib.loads(manifest.decode())["task"]:
        name = task["name"]
        program = task.get("program", name)
        if name in args.rejected:
            entries.append((name, bytes(32)))
        else:
            with open(f"{args.boot}/{program}.sig", "rb") as f:
                entries.append((name, hashlib.sha256(f.read()[:80]).digest()))

    pcr = bytes(32)
    for what, digest in entries:
        pcr = extend(pcr, digest)
        if args.log:
            print(f"{what:<14} {digest.hex()}")
    print(pcr.hex())


if __name__ == "__main__":
    main()
