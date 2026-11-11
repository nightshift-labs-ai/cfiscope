"""Runs the IDA layer on fake ida_* modules, feeding it a compiled fixture."""
import importlib, os, struct, sys, types, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from test_core import sections  # noqa: E402

class Seg:
    def __init__(self, s, e, perm, type_):
        self.start_ea, self.end_ea, self.perm, self.type = s, e, perm, type_

class World:
    def __init__(self, segs, mem):
        self.segs, self.mem, self.cmts, self.crefs, self.funcs, self.drefs = segs, mem, {}, set(), set(), set()

def install(world):
    m = {n: types.ModuleType(n) for n in "ida_bytes ida_funcs ida_ida ida_idaapi ida_kernwin ida_name ida_segment ida_xref".split()}
    m["ida_idaapi"].BADADDR = 2**64 - 1
    m["ida_bytes"].get_bytes = lambda ea, n: world.mem[ea]
    m["ida_bytes"].get_cmt = lambda ea, rep: world.cmts.get(ea)
    def set_cmt(ea, text, rep):
        if text: world.cmts[ea] = text
        else: world.cmts.pop(ea, None)
        return True
    m["ida_bytes"].set_cmt = set_cmt
    m["ida_segment"].SEGPERM_EXEC = 1; m["ida_segment"].SEG_CODE = 2
    m["ida_segment"].get_segm_qty = lambda: len(world.segs)
    m["ida_segment"].getnseg = lambda i: world.segs[i]
    m["ida_ida"].inf_get_procname = lambda: world.proc
    m["ida_ida"].inf_is_64bit = lambda: True
    m["ida_xref"].fl_CN, m["ida_xref"].fl_JN, m["ida_xref"].XREF_USER = 17, 19, 32
    m["ida_xref"].add_cref = lambda f, t, k: world.crefs.add((f, t, k)) or True
    m["ida_xref"].del_cref = lambda f, t, e: {world.crefs.discard(x) for x in list(world.crefs) if x[:2] == (f, t)} or True
    m["ida_xref"].get_first_dref_to = lambda ea: 1 if ea in world.drefs else 2**64 - 1
    far = lambda f: sorted({t for (a, t, _) in world.crefs if a == f})
    m["ida_xref"].get_first_fcref_from = lambda f: (far(f) or [2**64 - 1])[0]
    m["ida_xref"].get_next_fcref_from = lambda f, cur: next((t for t in far(f) if t > cur), 2**64 - 1)
    m["ida_funcs"].get_func = lambda ea: None
    m["ida_funcs"].get_func_name = lambda ea: "sub_%x" % ea
    m["ida_funcs"].add_func = lambda ea: world.funcs.add(ea) or True
    m["ida_name"].get_ea_name = lambda ea: ""
    class Choose:
        CHCOL_HEX, CH_RESTORE, NOTHING_CHANGED = 1, 2, 0
        def __init__(self, title, cols, flags=0): pass
    m["ida_kernwin"].Choose = Choose
    m["ida_kernwin"].jumpto = lambda ea: True
    sys.modules.update(m)
    sys.modules.pop("cfiscope.idalayer", None)
    return importlib.import_module("cfiscope.idalayer")

class IdaLayer(unittest.TestCase):
    def make(self, name, proc, perm=1, type_=2):
        d, S, text = sections(os.path.join(HERE, "fixtures", name + ".o"))
        segs, mem, base = [], {}, 0x100000
        for _, data in sorted(text.items()):
            segs.append(Seg(base, base + len(data), perm, type_)); mem[base] = data
            base += (len(data) + 0x1000) & ~0xfff
        w = World(segs, mem); w.proc = proc
        return w, install(w)

    def test_flow(self):
        for name, proc in (("x86_64-kernel", "metapc"), ("aarch64-kernel", "ARM")):
            with self.subTest(name):
                w, il = self.make(name, proc)
                sites, stats = il.scan()
                self.assertGreater(stats["sites"], 0)
                self.assertEqual(stats["unresolved"], 0)
                res = il.annotate(sites)
                self.assertEqual(res["comments"], stats["sites"])
                self.assertEqual(res["xrefs"], sum(len(s.targets) for s in sites))
                self.assertTrue(all(v.startswith("kCFI 0x") for v in w.cmts.values()))
                self.assertEqual(il.remove_annotations(sites), res["xrefs"])
                self.assertEqual(w.cmts, {}); self.assertEqual(w.crefs, set())
                self.assertEqual(il.remove_annotations(sites), 0)  # nothing left to remove

    def test_user_comment_kept(self):
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        ea = sites[0].call_ea
        w.cmts[ea] = "my note"
        self.assertEqual(il.annotate(sites)["kept_user_comments"], 1)
        il.remove_annotations(sites)
        self.assertEqual(w.cmts[ea], "my note")

    def test_target_inside_merged_function(self):
        # IDA may start the function at the __cfi_ preamble, 16 bytes before the kCFI target.
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        t = sites[0].targets[0]
        class F:
            start_ea, end_ea = t - 16, t + 64
        sys.modules["ida_funcs"].get_func = lambda ea: F if F.start_ea <= ea < F.end_ea else None
        sys.modules["ida_funcs"].get_func_name = lambda ea: "__cfi_impl" if ea == F.start_ea else ""
        self.assertEqual(il.target_name(t), "__cfi_impl+0x10")
        sys.modules["ida_name"].get_ea_name = lambda ea: "impl" if ea == t else ""
        self.assertEqual(il.target_name(t), "impl")
        rows = il.callers_rows(sites, F.start_ea)
        self.assertIn(sites[0].call_ea or sites[0].check_ea, [r[0] for r in rows])

    def test_address_taken_ranked_first(self):
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        s = next(x for x in sites if len(x.targets) >= 2)
        w.drefs.add(s.targets[-1])
        self.assertEqual(il.ranked(s)[0], s.targets[-1])

    def test_raw_load_without_permissions_scans_everything(self):
        w, il = self.make("x86_64-plain", "metapc", perm=0, type_=0)
        self.assertGreater(il.scan()[1]["sites"], 0)

if __name__ == "__main__":
    unittest.main()
