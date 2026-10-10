#!/usr/bin/env python3
"""Flip one byte of a volume's data block in a storage-task disk image (tests of the integrity
check): corrupt-disk.py build/disk.img client-a:0"""
import sys

BLOCK = 4096
META_BLOCKS = 2  # user/storage: per-volume metadata blocks before the data

image, target = sys.argv[1], sys.argv[2]
volume, _, block = target.partition(":")
with open(image, "r+b") as f:
    if f.read(8) != b"VNRSTOR2":
        sys.exit(f"{image}: not a storage-task disk")
    f.seek(BLOCK)
    table = f.read(BLOCK)
    for i in range(0, BLOCK, 64):
        name = table[i:i + 32].rstrip(b"\0").decode()
        if name == volume:
            start = int.from_bytes(table[i + 32:i + 40], "little")
            at = (start + META_BLOCKS + int(block)) * BLOCK + 100
            f.seek(at)
            byte = f.read(1)
            f.seek(at)
            f.write(bytes([byte[0] ^ 0x01]))
            print(f"corrupted {volume} block {block} (disk offset {at})")
            break
    else:
        sys.exit(f"no volume {volume}")
