#!/usr/bin/env python3
"""Score the scanner on a public x86-64 Android GKI kernel, against its own System.map.

    python3 tools/eval_gki_x86.py vmlinux System.map

From https://android.googlesource.com/kernel/prebuilts/6.1/x86-64 (kernel-6.1 and System.map).
kernel-6.1 is a bzImage: decompress its LZ4 payload to get vmlinux. Each function that kCFI
protects has a __cfi_<name> symbol in System.map, so the map says exactly which addresses are real targets.
"""
import os, struct, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cfiscope.core import resolve

PREAMBLES = (16, 5)


def code(path):
    with open(path, "rb") as fh:
        d = fh.read()
    phoff = struct.unpack_from("<Q", d, 0x20)[0]; n = struct.unpack_from("<H", d, 0x38)[0]
    out = []
    for i in range(n):
        ptype, flags, off, vaddr, _, filesz = struct.unpack_from("<IIQQQQ", d, phoff + 56 * i)
        if ptype == 1 and flags & 1 and vaddr >> 63:
            out.append((vaddr, d[off:off + filesz]))
    return out


def main():
    # Name collisions between static functions make names ambiguous, so go from each __cfi_ symbol to
    # its function by distance: usually 16 bytes (padded preamble), sometimes 5 (no padding).
    cfi = []
    text = {}
    for line in open(sys.argv[2]):
        addr, kind, name = line.split()[:3]
        if name.startswith("__cfi_"):
            cfi.append((int(addr, 16), name[6:]))
        elif kind in "tT":
            text.setdefault(int(addr, 16), []).append(name)
    truth = set()
    unplaced = 0
    for a, n in cfi:
        for gap in PREAMBLES:
            if n in text.get(a + gap, []):
                truth.add(a + gap)
                break
        else:
            unplaced += 1
    print("__cfi_ symbols", len(cfi), "placed at their function", len(truth), "not placed", unplaced)
    t0 = time.time()
    sites, stats = resolve(code(sys.argv[1]), "x86_64")
    print("seconds %.1f" % (time.time() - t0)); print(stats)
    counts = sorted(len(s.targets) for s in sites)
    print("resolved %.1f%%" % (100 * stats["resolved"] / stats["sites"]))
    print("1..8 candidates:", sum(1 for c in counts if 1 <= c <= 8), " 1..16:", sum(1 for c in counts if 1 <= c <= 16))
    targets = {t for s in sites for t in s.targets}
    hit = len(targets & truth)
    print("__cfi_ functions placed", len(truth), "distinct targets", len(targets))
    print("targets that are __cfi_ functions: %d (%.2f%%)" % (hit, 100 * hit / max(1, len(targets))))
    print("__cfi_ functions found as targets: %d (%.2f%%)" % (hit, 100 * hit / max(1, len(truth))))
    extra = sorted(targets - truth)
    named = sum(1 for t in extra if t in text)
    print("other targets: %d, of which at a named text symbol %d, not at any symbol %d" % (len(extra), named, len(extra) - named))
    print("sites with a recognised call:", sum(1 for s in sites if s.call_ea), "of", len(sites))


main()
