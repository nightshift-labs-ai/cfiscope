"""Before/after of what CFIScope writes into an IDA database, on a real kernel, through fake ida_* modules.

There is no IDA here: this loads the kernel's executable segments and symbol names into the same fake IDA modules the
stub tests use (tests/test_plugin_stub.py), runs the plugin's own IDA layer (scan, annotate, lookups) and prints
what it wrote: the comment on the call, the cross-references, the two jump lists and the pseudocode comment.
Real IDA will show the same text; its own disassembly, names and layout around it are not modelled.

    python3 -I tools/showcase_ida_stub.py gki.elf sock_sendmsg+0xb4 tcp_sendmsg
"""
import bisect, os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "tests")); sys.path.insert(0, ROOT)
import test_plugin_stub as T  # noqa: E402
from cfiscope import cli  # noqa: E402

def main(argv):
    path, call, callee = argv[1], argv[2], argv[3]
    with open(path, "rb") as fh:
        d = fh.read()
    arch, ranges, symbols = cli.load_elf(d)
    segs, mem = [], {}
    for base, data in ranges:
        segs.append(T.Seg(base, base + len(data), 1, 2)); mem[base] = data
    w = T.World(segs, mem); w.proc = "ARM" if arch == "aarch64" else "metapc"
    w.input_path = os.path.abspath(path)
    il = T.install(w)
    eas = sorted(symbols)
    w.nlist = [(ea, symbols[ea]) for ea in eas]
    sys.modules["ida_name"].get_ea_name = lambda ea: symbols.get(ea, "")
    class F:
        def __init__(self, s, e):
            self.start_ea, self.end_ea = s, e
    def get_func(ea):
        i = bisect.bisect_right(eas, ea) - 1
        if i < 0:
            return None
        end = eas[i + 1] if i + 1 < len(eas) else eas[i] + 0x1000
        return F(eas[i], end) if ea < end else None
    sys.modules["ida_funcs"].get_func = get_func
    sys.modules["ida_funcs"].get_func_name = lambda ea: symbols.get(ea, "")
    names = cli.Names(symbols)
    def addr(text):
        base, _, off = text.partition("+")
        ea = cli.parse_target(base, names)
        ea = min(ea) if isinstance(ea, (set, list, tuple)) else ea
        return ea + (int(off, 16) if off else 0)
    call_ea, callee_ea = addr(call), addr(callee)
    sites, stats = il.scan()
    site = il.site_at(sites, call_ea)
    at = site.call_ea or site.check_ea
    word = struct.unpack_from("<I", next(m[at - b: at - b + 4] for b, m in mem.items() if b <= at < b + len(m)))[0] if arch == "aarch64" else None
    insn = ("blr x%d" % ((word >> 5) & 31)) if word is not None and word & 0xfffffc1f == 0xd63f0000 else "(indirect call)"
    print("BEFORE (no CFIScope): %s  %s  %s" % (hex(at), names(at), insn))
    print("  comment: none; code xrefs from this call: none (indirect)")
    res = il.annotate(sites)
    print()
    print("AFTER Scan kCFI calls (Ctrl-Alt-K): %d sites, %d comments, %d cross-references in the whole database" % (stats["sites"], res["comments"], res["xrefs"]))
    print("%s  %s  %s    ; %s" % (hex(at), names(at), insn, w.cmts.get(at, "")))
    tos = sorted({t for (f, t, _) in w.crefs if f == at})
    print("  code xrefs from this call (%d): %s" % (len(tos), ", ".join(il.target_name(t) for t in tos)))
    print()
    print("Candidates for this call (Ctrl-Alt-T): window '%s'" % il.targets_title(site))
    for ea, nm, note in il.targets_rows(site):
        print("  %s  %s%s" % (hex(ea), nm, ("  " + note) if note else ""))
    print()
    rows = il.callers_rows(sites, callee_ea)
    print("Callers of this function (Ctrl-Alt-C) on %s: %d row(s)" % (names(callee_ea), len(rows)))
    for ea, nm, note in rows:
        print("  %s  %s  %s" % (hex(ea), nm, note))
    print()
    print("Pseudocode line of the call (with Hex-Rays):  // %s" % il.pseudocode_text(site))

if __name__ == "__main__":
    main(sys.argv)
