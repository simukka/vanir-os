#!/usr/bin/env python3
"""Flip one byte of a volume's data block, or of its header, in a storage-task disk image (tests
of the integrity check): corrupt-disk.py build/disk.img client-a:0 (or client-a:header)"""
import sys

BLOCK = 4096
META_PER_BLOCK = BLOCK // 24  # user/storage: counter and tag per data block


def meta_blocks(blocks):
    return -(-blocks // META_PER_BLOCK)


image, target = sys.argv[1], sys.argv[2]
volume, _, block = target.partition(":")
with open(image, "r+b") as f:
    if f.read(8) != b"VNRSTOR3":
        sys.exit(f"{image}: not a storage-task disk")
    f.seek(BLOCK)
    table = f.read(BLOCK)
    for i in range(0, BLOCK, 64):
        name = table[i:i + 32].rstrip(b"\0").decode()
        if name == volume:
            start = int.from_bytes(table[i + 32:i + 40], "little")
            blocks = int.from_bytes(table[i + 40:i + 48], "little")
            if block == "header":
                at = start * BLOCK + 40  # inside the sealed fields, after counter and tag
            else:
                at = (start + 1 + meta_blocks(blocks) + int(block)) * BLOCK + 100
            f.seek(at)
            byte = f.read(1)
            f.seek(at)
            f.write(bytes([byte[0] ^ 0x01]))
            print(f"corrupted {volume} block {block} (disk offset {at})")
            break
    else:
        sys.exit(f"no volume {volume}")
