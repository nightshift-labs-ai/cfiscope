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
With vmlinux.elf, the last lines rank by static slots (kcfi_types.rank_slots(), unreleased): the Image's BTF names
each call's struct member, vmlinux.elf's words and OBJECT symbols say which candidates are stored in a slot of it (at
its offset, or by array stride); the counts, the counts under the rule before review s197 (one word at the offset
modulo a struct size was enough), and the time of each step.
"""
import os, statistics, struct, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from cfiscope import cli, kcfi_types
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
t0 = time.time()
sites, stats = resolve([(BASE, image)], "aarch64", text)
seconds = time.time() - t0
if "outside_text" in stats:
    # Only the code areas that reach into the gap keep candidates there (GKI 6.1 names its idmap code inside .text).
    etext, sinittext = bounds["_etext"], bounds["_sinittext"]
    areas = ", ".join("%#x-%#x" % (bounds[a], bounds[b]) for a, b in CODE_AREAS if a in bounds and b in bounds
                      and bounds[a] < bounds[b] and bounds[a] < sinittext and bounds[b] > etext)
    print("candidates left out between _etext and _sinittext (%#x-%#x) except in the code areas named there (%s): %d"
          % (etext, sinittext, areas or "none", stats["outside_text"]))
elif funcs is not None:
    # No bounds, or jump-table CFI, whose candidates are branch targets and are not filtered (core.resolve()).
    print("kernel code not named in the ELF's symbols: nothing left out" if text is None else
          "jump-table CFI: candidates are branch targets, nothing left out")
print("seconds %.1f" % seconds); print(stats)
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


def slot_ranking(sites, image, elf_path):
    """Candidates stored in a slot of the call's struct member, listed first: counts on this kernel."""
    t0 = time.time()
    names = kcfi_types.load_type_names(image)
    t1 = time.time()
    if names is None:
        print("slots: no BTF in the Image, so no struct members and no ranking")
        return
    kcfi_types.name_sites(sites, names)
    kcfi_types.name_members(sites, [(BASE, image)], "aarch64", names)
    t2 = time.time()
    with open(elf_path, "rb") as fh:
        elf = fh.read()
    offsets = cli.slot_offsets(elf, {t for s in sites if s.kind == "kcfi" for t in s.targets})
    t3 = time.time()
    st = kcfi_types.rank_slots(sites, offsets, names)
    t4 = time.time()
    print("slots: BTF type names %.2f s, members %.2f s, slot scan of %s %.2f s, ranking %.2f s"
          % (t1 - t0, t2 - t1, os.path.basename(elf_path), t3 - t2, t4 - t3))
    print(kcfi_types.slot_summary(st))
    named = [s for s in sites if s.kind == "kcfi" and s.members and s.targets]
    hit = [s for s in named if s.slot_backed]
    full, part = [len(s.targets) for s in hit], [len(s.slot_backed) for s in hit]
    exact = [len(s.slot_backed) - len(s.slot_stride) for s in hit]
    print("calls with a member and candidates %d; with a slot-backed candidate %d (shorter first part %d, all of the "
          "list %d); calls whose slot-backed candidates are all by array stride %d"
          % (len(named), len(hit), st["slot_calls_shorter"], len(hit) - st["slot_calls_shorter"],
             st["slot_calls_stride_only"]))
    print("slot-backed (call, candidate) pairs %d, of them by array stride only %d"
          % (sum(part), sum(len(s.slot_stride) for s in hit)))
    # the rule before review s197: any one word at the member's offset modulo a struct size (8-byte structs left out)
    old_calls = old_pairs = old_modulo = 0
    for s in named:
        sizes = [z for z in names.member_sizes.get((s.hash, s.member_offset), ()) if z > max(s.member_offset, 8)]
        got = {t for t in s.targets for _obj, o in offsets.get(t, ())
               if o == s.member_offset or any(o % z == s.member_offset for z in sizes)}
        old_calls += bool(got)
        old_pairs += len(got)
        old_modulo += len(got - {t for t in s.targets for _obj, o in offsets.get(t, ()) if o == s.member_offset})
    print("with the rule before (one word at the offset modulo a struct size is enough): %d calls, %d pairs, %d of them "
          "only modulo" % (old_calls, old_pairs, old_modulo))
    print("those calls: median list %s, median slot-backed part %s; lists over 16: %d, of them slot-backed part of 16 or "
          "fewer %d, with 1 to 16 at the member's offset (IDA cross-references) %d; largest list %d (its slot-backed "
          "part %d); largest slot-backed part %d"
          % (statistics.median(full), statistics.median(part), sum(1 for n in full if n > 16),
             sum(1 for n, k in zip(full, part) if n > 16 and k <= 16),
             sum(1 for n, k in zip(full, exact) if n > 16 and 1 <= k <= 16), max(full),
             max(len(s.slot_backed) for s in hit if len(s.targets) == max(full)), max(part)))
    by_name = {}
    _a, _r, syms = cli.load_elf(elf)
    for ea, nm in syms.items():
        by_name.setdefault(nm, ea)
    nm = cli.Names(syms)
    for fn, off in (("sock_sendmsg", None), ("kernel_sendmsg_locked", None), ("inet_sendmsg", 0x58),
                    ("inet6_sendmsg", 0x58)):
        ea = by_name.get(fn)
        got = [s for s in named if s.call_ea and nm.function(s.call_ea) and nm.function(s.call_ea)[0] == ea
               and (off is None or s.call_ea == ea + off) and s.members and s.members[0].endswith("sendmsg"
               if fn == "sock_sendmsg" else "sendmsg_locked" if fn == "kernel_sendmsg_locked" else "sendmsg")]
        for s in got[:1]:
            print("  %s+0x%x %s: %d -> %d (%s)%s" % (fn, s.call_ea - ea, s.members[0], len(s.targets),
                                                  len(s.slot_backed),
                                                  ", ".join(nm(t) for t in s.targets if t in s.slot_backed),
                                                  " by array stride: %d" % len(s.slot_stride) if s.slot_stride else ""))


if funcs is not None:
    slot_ranking(sites, image, sys.argv[2])
