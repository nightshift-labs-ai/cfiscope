"""Before/after of what CFIScope writes into an IDA database, on a real kernel, through fake ida_* modules.

There is no IDA here: this loads the kernel's executable segments and symbol names into the same fake IDA modules the
stub tests use (tests/test_plugin_stub.py), runs the plugin's own IDA layer (scan, annotate, lookups) and prints
what it wrote: the comment on the call, the cross-references, the two jump lists and the pseudocode comment.
Real IDA will show the same text; its own disassembly, names and layout around it are not modelled.

    python3 -I tools/showcase_ida_stub.py gki.elf sock_sendmsg+0xb4 tcp_sendmsg [--no] [--list]

--no: Scan as after answering No to "Create functions" (annotate(sites, create_functions=False)); without it, as
after Yes (the call xrefs; the functions themselves are not modelled).
--list: also the call-site list that opens at the end of Scan: its row count, how long its rows took to build, and
the row of the call next to the command line's --sites line for it.
"""
import bisect, os, struct, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "tests")); sys.path.insert(0, ROOT)
import test_plugin_stub as T  # noqa: E402
from cfiscope import cli  # noqa: E402

def load(path):
    """The fake database of an ELF file: its executable code as segments, its function symbols as IDA's names and
    functions, laid out as the command line lays them out. Returns (idalayer, world, arch, mem, symbols)."""
    with open(path, "rb") as fh:
        d = fh.read()
    arch, ranges, symbols = cli.load_elf(d)
    segs, mem = [], {}
    for base, data in ranges:
        segs.append(T.Seg(base, base + len(data), 1, 2)); mem[base] = data
    w = T.World(segs, mem); w.proc = "ARM" if arch == "aarch64" else "metapc"
    w.input_path = os.path.abspath(path)
    il = T.install(w)
    sys.modules["ida_kernwin"].msg = lambda text: print("Output window: " + text, end="")   # e.g. the split-BTF hint on a .ko
    eas = sorted(symbols)
    w.nlist = [(ea, symbols[ea]) for ea in eas]
    sys.modules["ida_name"].get_ea_name = lambda ea: symbols.get(ea, "")
    class F:
        def __init__(self, s, e):
            self.start_ea, self.end_ea, self.tailqty = s, e, 0
    def get_func(ea):
        i = bisect.bisect_right(eas, ea) - 1
        if i < 0:
            return None
        end = eas[i + 1] if i + 1 < len(eas) else eas[i] + 0x1000
        return F(eas[i], end) if ea < end else None
    sys.modules["ida_funcs"].get_func = get_func
    sys.modules["ida_funcs"].get_func_name = lambda ea: symbols.get(ea, "")
    return il, w, arch, mem, symbols


def main(argv):
    create = "--no" not in argv
    path, call, callee = [a for a in argv if a not in ("--no", "--list")][1:4]
    il, w, arch, mem, symbols = load(path)
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
    res = il.annotate(sites, create_functions=create)
    print()
    if create:
        print("AFTER Scan kCFI calls (Alt-Shift-K): %d sites, %d comments, %d cross-references in the whole database" % (stats["sites"], res["comments"], res["xrefs"]))
    else:
        print('AFTER Scan kCFI calls (Alt-Shift-K), answered No to "Create functions": %d sites, %d comments, %d call and '
              '%d data cross-references in the whole database; %d skipped (no function there)'
              % (stats["sites"], res["comments"], res["xrefs"], res["data_xrefs_inside_function"],
                 res["xrefs_skipped_no_function"]))
    print("%s  %s  %s    ; %s" % (hex(at), names(at), insn, w.cmts.get(at, "")))
    tos = sorted({t for (f, t, _) in w.crefs if f == at})
    print("  code xrefs from this call (%d): %s" % (len(tos), ", ".join(il.target_name(t) for t in tos)))
    if not create:
        tos = sorted({t for (f, t, _) in w.data_xrefs if f == at})
        print("  data xrefs from this call (%d): %s" % (len(tos), ", ".join(il.target_name(t) for t in tos)))
    print()
    print("Candidates for this call (Alt-Shift-T): window '%s'" % il.targets_title(site))
    for ea, nm, note in il.targets_rows(site):
        print("  %s  %s%s" % (hex(ea), nm, ("  " + note) if note else ""))
    print()
    rows = il.callers_rows(sites, callee_ea)
    print("Callers of this function (Alt-Shift-X) on %s: %d row(s)" % (names(callee_ea), len(rows)))
    for ea, nm, note in rows:
        print("  %s  %s  %s" % (hex(ea), nm, note))
    print()
    print("Pseudocode line of the call (with Hex-Rays):  // %s" % il.pseudocode_text(site))
    if "--list" in argv:
        start = time.perf_counter()
        chooser = il.sites_chooser(sites)       # what Scan opens at its end (and CFIScope: List kCFI call sites)
        took = time.perf_counter() - start
        print()
        print("Call-site list (opens after Scan; CFIScope: List kCFI call sites): window '%s', %d rows, built in %.2f s"
              % (il.sites_title(sites), chooser.OnGetSize(), took))
        print("  columns: " + " | ".join(c[0] for c in il.SITES_COLUMNS))
        n = next(i for i, r in enumerate(chooser.rows) if r[0] == at)
        print("  row %d:  %s" % (n, " | ".join(chooser.OnGetLine(n))))
        print("  command line --sites:  %s" % cli._site_line(site, names, 8))

if __name__ == "__main__":
    main(sys.argv)
