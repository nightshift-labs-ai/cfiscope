#!/usr/bin/env python3
"""Reproduce the README numbers for the Linux 5.x jump-table CFI on a public Android GKI 5.15 kernel.

    python3 tools/eval_gki_oldcfi.py [--base 0xffffffc008000000] [--cxxfilt] Image [vmlinux.elf]

Image: the kernel from boot-5.15.img in
https://dl.google.com/android/gki/gki-certified-boot-android13-5.15-2024-01_r1.zip
(python3 tools/extract_bootimg.py boot-5.15.img Image).
Android 12 GKI 5.10, same steps: https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-2024-01_r1.zip
(boot-5.10.img; README 'Two kernels were measured').
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
      " (of them the CFI runtime's own, passing no type id: %d)"
      % (stats["sites"], stats["range_sites"], stats["single_sites"], stats["slowpath_sites"], stats["resolved"],
         stats["calls_with_candidates"], stats["checks_without_call"], stats["runtime_checks"]))
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
# Only checks whose range was read at the check itself count; a range copied from another check of the same id
# agrees with the symbol by construction, so those are reported apart.
for kind in ("range", "single"):
    checks = [x for s in sites for x in [s] + s.extra_checks if x.kind == kind and x.targets and x.type_id is not None]
    own = [x for x in checks if x.jt_range_from == "code"]
    print("%s checks with candidates and a slow-path id, range read at the check: first entry == __typeid symbol of that"
          " id: %s; range copied from another check of the same id: %d" % (
              kind, pct(sum(1 for x in own if by_id.get(x.type_id) == x.jt_base), len(own)), len(checks) - len(own)))

# Linking: the check and the call it was linked to lie in the same function.
fa = sorted(func_starts)
fn = lambda a: fa[bisect.bisect_right(fa, a) - 1]
linked = [s for s in sites if s.call_ea]
print("linked sites whose check and call are in the same kallsyms function: %s"
      % pct(sum(1 for s in linked if fn(s.call_ea) == fn(s.check_ea)), len(linked)))

# Where the unresolved blr are (the inlined slow-path row needs the find_check_fn symbol). Function = nearest preceding kallsyms function (assembly without a symbol of its own
# is counted under the symbol before it). The last two rows are a heuristic: an extr/ror #3 of a register by itself or a
# bl to __cfi_slowpath(_diag) in the 32 words before the call, inside the same function, suggests a check this scanner
# does not decode; none of them suggests a call without a CFI check (assembly, __nocfi code, BPF dispatch...).
fname = {a: n for a, n, t in syms if a in func_starts and t == 2}
slowfns = {addr[n] for n in ("__cfi_slowpath", "__cfi_slowpath_diag") if n in addr}
find_check = addr.get("find_check_fn")

# Callers: checks with no linked call are not call sites. The runtime's own (Site.runtime_check, from the code) are
# left out of callers lists; the others are listed after the calls and not counted.
unlinked = [s for s in sites if not s.call_ea and s.kind != "slowpath"]
cfi_check = addr.get("__cfi_check")
in_cfi_check = lambda s: cfi_check is not None and fname.get(fn(s.check_ea)) == "__cfi_check"
rt_checks = [s for s in unlinked if s.runtime_check]
print("checks with no linked call: %d; the CFI runtime's own (code: no type id passed): %d, inside __cfi_check by"
      " symbols: %d of the %d checks there; the other %d (callers lists them last, not counted): inside __cfi_check %d"
      % (len(unlinked), len(rt_checks), sum(1 for s in rt_checks if in_cfi_check(s)),
         sum(1 for s in sites if in_cfi_check(s)), len(unlinked) - len(rt_checks),
         sum(1 for s in unlinked if not s.runtime_check and in_cfi_check(s))))
print("distinct candidates of the runtime's own checks (their callers list no longer shows such a check): %d of %d"
      % (len({t for s in rt_checks for t in s.targets}), len(cands)))


def is_bl(p, target):
    w = struct.unpack_from("<I", image, p - BASE)[0]
    return w & 0xfc000000 == 0x94000000 and p + 4 * (((w & 0x3ffffff) ^ 0x2000000) - 0x2000000) == target


def tracepoint_probe_call(a):
    """blr xR whose xR was read with ldar from [xM] and x0 from [xM, #8] in the 6 words before: the probe loop of an
    inlined tracepoint (struct tracepoint_func: func at 0, data at 8). A pattern match, not a proof."""
    word = lambda p: struct.unpack_from("<I", image, p - BASE)[0]
    r, m = (word(a) >> 5) & 31, None
    for p in range(a - 4, a - 28, -4):
        if word(p) & 0xfffffc00 == 0xc8dffc00 and word(p) & 31 == r:
            m = (word(p) >> 5) & 31
            break
    return m is not None and any(word(p) == 0xf9400400 | (m << 5) for p in range(a - 4, a - 28, -4))


by_call = {}
for s in sites:
    if s.call_ea:
        by_call.setdefault(s.call_ea, s)
split = {}
for a in sorted(blr - {s.call_ea for s in resolved}):
    name = fname.get(fn(a), "")
    if a in by_call:
        key = "linked to a check without candidates in the image (slow-path-only types, ranges not found)"
    elif find_check is not None and any(is_bl(p, find_check) for p in range(a - 4, max(fn(a), a - 64) - 4, -4)):
        key = "inlined CFI slow path: bl find_check_fn, then blr to __cfi_check of the kernel or module holding the pointer (part of a check, not a program call)"
    elif name.startswith(("__traceiter_android_vh_", "__traceiter_android_rvh_")):
        key = "in Android vendor-hook iterators (__traceiter_android_[r]vh_*, called without a CFI check)"
    elif name.startswith("__traceiter_"):
        key = "in tracepoint iterators (__traceiter_*, called without a CFI check)"
    elif tracepoint_probe_call(a):
        key = "inlined tracepoint loops elsewhere (ldar xR, [xM]; ldr x0, [xM, #8]; blr xR: probe func/data pair)"
    else:
        key = "elsewhere, no extr/ror #3 and no __cfi_slowpath call in the 32 words before"
        for p in range(a - 4, max(fn(a), a - 128) - 4, -4):
            w = struct.unpack_from("<I", image, p - BASE)[0]
            off = ((w & 0x3ffffff) ^ 0x2000000) - 0x2000000
            if (w & 0xffe0fc00 == 0x93c00c00 and (w >> 16 & 31) == (w >> 5 & 31)) or \
                    (w & 0xfc000000 == 0x94000000 and p + 4 * off in slowfns):
                key = "elsewhere, with an extr/ror #3 or a __cfi_slowpath call in the 32 words before (likely undecoded checks)"
                break
    split[key] = split.get(key, 0) + 1
print("unresolved blr in kernel text: %d" % sum(split.values()))
for key, n in sorted(split.items(), key=lambda kv: -kv[1]):
    print("  %5d  %s" % (n, key))
runtime = sum(n for key, n in split.items() if key.startswith("inlined CFI slow path"))
# The scanner finds the runtime's calls without symbols, as the blr of a decoded check's inlined slow path.
found_rt = {x.runtime_call_ea for t in sites for x in [t] + t.extra_checks if x.runtime_call_ea}
sym_rt = {a for a in blr - {s.call_ea for s in resolved} if find_check is not None
          and any(is_bl(p, find_check) for p in range(a - 4, max(fn(a), a - 64) - 4, -4))}
print("CFI runtime calls found from the code (inlined slow paths of decoded checks): %d; in the symbol-based bucket: %s;"
      " found but not in it: %d" % (len(found_rt), pct(len(found_rt & sym_rt), len(sym_rt)), len(found_rt - sym_rt)))
print("blr in kernel text resolved, leaving out the CFI runtime's own calls: %s" % pct(len(rb), len(blr) - runtime))

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
