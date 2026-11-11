#!/usr/bin/env python3
"""Reproduce the README numbers for the Linux 5.x jump-table CFI on a public Android GKI 5.15 kernel.

    python3 tools/eval_gki_oldcfi.py [--base 0xffffffc008000000] [--cxxfilt] Image [vmlinux.elf]

Image: the kernel from boot-5.15.img in
https://dl.google.com/android/gki/gki-certified-boot-android13-5.15-2024-01_r1.zip
(python3 tools/extract_bootimg.py boot-5.15.img Image).
vmlinux.elf (optional): the same kernel with kallsyms restored by
https://github.com/marin-m/vmlinux-to-elf, used only to score the result: which words are kernel text,
where functions start, the jump-table entry names (foo.cfi_jt) and the __typeid_<type>_global_addr symbols.
--cxxfilt: also compare the type-name demangler with c++filt (binutils), if installed.
"""
import bisect, os, statistics, struct, subprocess, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cfiscope import core  # noqa: E402

BASE = 0xffffffc008000000


def symbols(path):
    """[(address, name, type)] from the ELF symbol table."""
    with open(path, "rb") as fh:
        d = fh.read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]; n = struct.unpack_from("<H", d, 0x3c)[0]
    S = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(n)]
    out = []
    for s in S:
        if s[1] == 2:
            st = S[s[6]]
            for i in range(s[5] // 24):
                nm, info, _, _, val, _ = struct.unpack_from("<IBBHQQ", d, s[4] + 24 * i)
                if nm and val:
                    e = d.index(b"\0", st[4] + nm)
                    out.append((val, d[st[4] + nm:e].decode("utf-8", "replace"), info & 15))
    return out


def pct(a, b):
    return "%d / %d (%.1f%%)" % (a, b, 100.0 * a / b) if b else "%d / 0" % a


args = sys.argv[1:]
if args[:1] == ["--base"]:
    BASE = int(args[1], 0)
    args = args[2:]
cxxfilt = "--cxxfilt" in args
args = [a for a in args if a != "--cxxfilt"]
if not args:
    sys.exit(__doc__)
with open(args[0], "rb") as fh:
    image = fh.read()
t0 = time.time()
sites, stats = core.resolve([(BASE, image)], "aarch64")
print("seconds %.1f" % (time.time() - t0))
print(stats)
if stats.get("scheme") != "jump-table CFI":
    sys.exit("no jump-table CFI found")
resolved = [s for s in sites if s.call_ea and s.targets]
print("sites %d: range %d, single %d, slowpath %d; with candidates %d (calls %d); checks with no call linked %d"
      % (stats["sites"], stats["range_sites"], stats["single_sites"], stats["slowpath_sites"], stats["resolved"],
         stats["calls_with_candidates"], stats["checks_without_call"]))
if len(args) < 2:
    sys.exit(0)

syms = symbols(args[1])
names_at, addr = {}, {}
for a, n, _ in syms:
    names_at.setdefault(a, []).append(n)
    addr.setdefault(n, a)
jt = core.find_jump_table([(BASE, image)])
print("jump table %#x..%#x, %d entries; __cfi_jt_start..__cfi_jt_end %#x..%#x: %s"
      % (jt.start, jt.end, len(jt.targets), addr.get("__cfi_jt_start", 0), addr.get("__cfi_jt_end", 0),
         "same" if (jt.start, jt.end) == (addr.get("__cfi_jt_start"), addr.get("__cfi_jt_end")) else "DIFFERENT"))
slow = [n for n in ("__cfi_slowpath", "__cfi_slowpath_diag") if n in addr]
print("slow-path function found from the code:", stats["slowpath_functions"], "symbols:",
      ["%s %#x" % (n, addr[n]) for n in slow])

# Kernel text: _stext.._etext without the jump table, plus init text.
# (The same text the research prototype counted; .exit.text only counts as code for the "outside" line.)
text = [(addr["_stext"], jt.start), (jt.end, addr["_etext"]), (addr["_sinittext"], addr["_einittext"])]
exit_text = [(addr["__exittext_begin"], addr["__exittext_end"])] if "__exittext_end" in addr else []
in_text = lambda a: any(lo <= a < hi for lo, hi in text + exit_text)
blr = set()
for lo, hi in text:
    off, end = lo - BASE, hi - BASE
    for i, (w,) in enumerate(struct.iter_unpack("<I", image[off:end - (end - off) % 4])):
        if w & 0xfffffc1f == 0xd63f0000:
            blr.add(lo + 4 * i)
rb = [s for s in resolved if s.call_ea in blr]
counts = sorted(len(s.targets) for s in rb)
print("blr in kernel text resolved: %s; candidates per resolved blr: median %d, mean %.1f, max %d, exactly one %d"
      % (pct(len(rb), len(blr)), statistics.median_low(counts), sum(counts) / len(counts), counts[-1],
         sum(1 for c in counts if c == 1)))
print("br (tail calls) resolved: %d; sites outside kernel text (init and exit text included): %d"
      % (sum(1 for s in resolved if s.is_tail), sum(1 for s in sites if not in_text(s.check_ea))))

# Precision 1: each candidate is a function start, and the entry's name matches its target's.
func_starts = {a for a, n, t in syms if t == 2 and not n.startswith("__typeid_") and not n.endswith(".cfi_jt")}
cands = {t for s in sites for t in s.targets}
entries = set()
for s in sites:
    for x in [s] + s.extra_checks:
        k0 = jt.entry_index(x.jt_base) if x.targets else None
        if k0 is not None:
            entries.update(jt.start + 8 * k for k in range(k0, k0 + x.jt_count))
consistent = 0
for e in entries:
    t, en = jt.targets[jt.entry_index(e)], names_at.get(e, [])
    tn = names_at.get(jt.targets[jt.entry_index(e)], [])
    if any(x.endswith(".cfi_jt") and x[:-7] in tn for x in en) or any(x + ".cfi" in tn for x in en):
        consistent += 1
print("distinct candidates at a kallsyms function start: %s" % pct(sum(1 for t in cands if t in func_starts), len(cands)))
print("jump-table entries used, entry name foo.cfi_jt -> target foo (or foo -> foo.cfi): %s" % pct(consistent, len(entries)))

# Precision 2: the range a check reads from the code starts at the __typeid symbol of the id its slow path passes.
by_id = {}
for a, n, _ in syms:
    m = core._TYPEID_SYMBOL.match(n)
    if m:
        by_id[core.cfi_type_id(m.group(1))] = a
for kind in ("range", "single"):
    checks = [x for s in sites for x in [s] + s.extra_checks if x.kind == kind and x.targets and x.type_id is not None]
    print("%s checks with candidates and a slow-path id: first entry == __typeid symbol of that id: %s"
          % (kind, pct(sum(1 for x in checks if by_id.get(x.type_id) == x.jt_base), len(checks))))

# Linking: the check and the call it was linked to lie in the same function.
fa = sorted(func_starts)
fn = lambda a: fa[bisect.bisect_right(fa, a) - 1]
linked = [s for s in sites if s.call_ea]
print("linked sites whose check and call are in the same kallsyms function: %s"
      % pct(sum(1 for s in linked if fn(s.call_ea) == fn(s.check_ea)), len(linked)))

named = core.name_jt_types(sites, [(a, n) for a, n, _ in syms])
sp = [s for s in sites if s.kind == "slowpath"]
print("checks named from __typeid symbols: %d; slow-path-only sites %d: call linked %d, flagged 'candidates unknown' %d,"
      " call copies on a check's slow path %d" % (named, len(sp), sum(1 for s in sp if s.call_ea),
                                                  sum(1 for s in sp if s.note and "unknown" in s.note),
                                                  sum(1 for s in sp if s.note and "copy" in s.note)))
if cxxfilt:
    mangled = sorted({core._TYPEID_SYMBOL.match(n).group(1) for _, n, _ in syms if core._TYPEID_SYMBOL.match(n)})
    out = subprocess.run(["c++filt"], input="\n".join(mangled), capture_output=True, text=True).stdout.splitlines()
    same = sum(1 for m, o in zip(mangled, out) if o == "typeinfo name for %s" % core.demangle_type(m))
    print("type names equal to c++filt: %s" % pct(same, len(mangled)))
