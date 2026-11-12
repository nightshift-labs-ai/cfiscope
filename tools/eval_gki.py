#!/usr/bin/env python3
"""Reproduce the README numbers on a public Android GKI kernel.

    python3 tools/eval_gki.py [--base 0xffffffc080000000] Image [vmlinux.elf]

Image: the kernel from boot-6.1.img in
https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip
vmlinux.elf (optional): the same kernel with kallsyms restored by
https://github.com/marin-m/vmlinux-to-elf. It scores the result (does each candidate start at a kallsyms
function?) and, as on the command line with that ELF and in IDA with its names, its _etext and _sinittext symbols
bound .rodata: candidates there, outside the code areas named there, are left out (core.kernel_text(); a line also
gives the Image alone, as with --raw).
--base: where the kernel image starts (default 0xffffffc008000000, the 6.1 GKI; 6.6 and later GKI
kernels start at 0xffffffc080000000). With a wrong base the precision line drops to about 0%.
"""
import os, struct, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cfiscope.core import kernel_text, resolve, CODE_AREAS, TEXT_BOUND_NAMES

BASE = 0xffffffc008000000

def functions(path):
    """(addresses of STT_FUNC symbols, {name: address} of the kernel text bounds of any symbol type)."""
    with open(path, "rb") as fh:
        d = fh.read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]; n = struct.unpack_from("<H", d, 0x3c)[0]
    S = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(n)]
    out, bounds = set(), {}
    for s in S:
        if s[1] == 2:
            st = S[s[6]]
            for i in range(s[5] // 24):
                nm, info, _, _, val, _ = struct.unpack_from("<IBBHQQ", d, s[4] + 24 * i)
                if info & 15 == 2 and val:
                    out.add(val)
                if nm and val:
                    name = d[st[4] + nm:d.index(b"\0", st[4] + nm)].decode("utf-8", "replace")
                    if name in TEXT_BOUND_NAMES:
                        bounds.setdefault(name, val)
    return out, bounds

if len(sys.argv) > 2 and sys.argv[1] == "--base":
    BASE = int(sys.argv[2], 0)
    del sys.argv[1:3]
if len(sys.argv) < 2:
    sys.exit(__doc__)
with open(sys.argv[1], "rb") as fh:
    image = fh.read()
funcs, text = None, None
if len(sys.argv) > 2:
    funcs, bounds = functions(sys.argv[2])
    text = kernel_text(bounds)
    areas = ", ".join("%#x-%#x" % (bounds[a], bounds[b]) for a, b in CODE_AREAS if a in bounds and b in bounds)
    print("candidates left out between _etext and _sinittext (%#x-%#x) except in the code areas named there (%s)"
          % (bounds["_etext"], bounds["_sinittext"], areas or "none") if text else
          "kernel code not named in the ELF's symbols: nothing left out")
t0 = time.time()
sites, stats = resolve([(BASE, image)], "aarch64", text)
print("seconds %.1f" % (time.time() - t0)); print(stats)
counts = sorted(len(s.targets) for s in sites)
print("resolved %.1f%%" % (100 * stats["resolved"] / stats["sites"]))
print("1..8 candidates:", sum(1 for c in counts if 1 <= c <= 8), " 1..16:", sum(1 for c in counts if 1 <= c <= 16))
if funcs is not None:
    targets = {t for s in sites for t in s.targets}
    hit = sum(1 for t in targets if t in funcs)
    print("distinct targets", len(targets), "at a kallsyms function", hit, "(%.2f%%)" % (100 * hit / len(targets)))
    if text is not None:
        raw_sites, raw = resolve([(BASE, image)], "aarch64")
        raw_targets = {t for s in raw_sites for t in s.targets}
        print("the Image alone (no text bounds, as --raw): resolved %d, exactly one %d; distinct targets %d, at a "
              "kallsyms function %d" % (raw["resolved"], raw["single_target"], len(raw_targets),
                                        sum(1 for t in raw_targets if t in funcs)))
