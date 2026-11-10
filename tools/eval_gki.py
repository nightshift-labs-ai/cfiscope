#!/usr/bin/env python3
"""Reproduce the README numbers on a public Android GKI kernel.

    python3 tools/eval_gki.py Image [vmlinux.elf]

Image: the kernel from boot-6.1.img in
https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip
vmlinux.elf (optional): the same kernel with kallsyms restored by
https://github.com/marin-m/vmlinux-to-elf, used only to score the result.
"""
import os, struct, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cfiscope.core import resolve

BASE = 0xffffffc008000000

def functions(path):
    with open(path, "rb") as fh:
        d = fh.read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]; n = struct.unpack_from("<H", d, 0x3c)[0]
    S = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(n)]
    out = set()
    for s in S:
        if s[1] == 2:
            for i in range(s[5] // 24):
                _, info, _, _, val, _ = struct.unpack_from("<IBBHQQ", d, s[4] + 24 * i)
                if info & 15 == 2 and val:
                    out.add(val)
    return out

if len(sys.argv) < 2:
    sys.exit(__doc__)
with open(sys.argv[1], "rb") as fh:
    image = fh.read()
t0 = time.time()
sites, stats = resolve([(BASE, image)], "aarch64")
print("seconds %.1f" % (time.time() - t0)); print(stats)
counts = sorted(len(s.targets) for s in sites)
print("resolved %.1f%%" % (100 * stats["resolved"] / stats["sites"]))
print("1..8 candidates:", sum(1 for c in counts if 1 <= c <= 8), " 1..16:", sum(1 for c in counts if 1 <= c <= 16))
if len(sys.argv) > 2:
    funcs = functions(sys.argv[2])
    targets = {t for s in sites for t in s.targets}
    hit = sum(1 for t in targets if t in funcs)
    print("distinct targets", len(targets), "at a kallsyms function", hit, "(%.2f%%)" % (100 * hit / len(targets)))
