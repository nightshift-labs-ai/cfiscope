"""Runs the IDA layer on fake ida_* modules, feeding it a compiled fixture."""
import importlib, os, struct, sys, types, unittest
from unittest import mock
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
from test_core import sections  # noqa: E402

class Seg:
    def __init__(self, s, e, perm, type_):
        self.start_ea, self.end_ea, self.perm, self.type = s, e, perm, type_

class World:
    def __init__(self, segs, mem):
        self.segs, self.mem, self.cmts, self.crefs, self.funcs, self.drefs = segs, mem, {}, set(), set(), set()
        self.nlist = []   # (ea, name) as IDA's name list holds them
        self.input_path = None
        self.flags = {}   # ea -> IDA flags: FF_DATA (0x400) for a data item's start, FF_TAIL (0x200) inside an item
        self.planned_funcs = set()   # call-xref targets IDA's auto-analysis would make functions (xref.hpp fl_CN)
        self.data_xrefs = set()      # (from, to, type) added with add_dref; drefs above holds other "address taken" targets
        self.auto_ok = True          # ida_auto.auto_is_ok(): auto-analysis has finished
        self.auto_enabled = True     # ida_ida.inf_is_auto_enabled(): auto-analysis is turned on
        self.netnodes = {}           # netnode name -> {(tag, key): value} of its hash values (ida_netnode)

def install(world):
    m = {n: types.ModuleType(n) for n in "ida_auto ida_bytes ida_funcs ida_ida ida_idaapi ida_kernwin ida_nalt ida_name ida_netnode ida_segment ida_xref".split()}
    m["ida_auto"].auto_is_ok = lambda: world.auto_ok
    m["ida_auto"].auto_wait = lambda: setattr(world, "auto_ok", True) or True
    m["ida_nalt"].get_input_file_path = lambda: world.input_path
    m["ida_idaapi"].BADADDR = 2**64 - 1
    m["ida_bytes"].get_bytes = lambda ea, n: next((data[ea - b:ea - b + n] for b, data in world.mem.items()
                                                   if b <= ea < b + len(data)), None)
    m["ida_bytes"].get_cmt = lambda ea, rep: world.cmts.get(ea)
    def set_cmt(ea, text, rep):
        if text: world.cmts[ea] = text
        else: world.cmts.pop(ea, None)
        return True
    m["ida_bytes"].set_cmt = set_cmt
    m["ida_segment"].SEGPERM_EXEC = 1; m["ida_segment"].SEG_CODE = 2
    m["ida_segment"].get_segm_qty = lambda: len(world.segs)
    m["ida_segment"].getnseg = lambda i: world.segs[i]
    m["ida_segment"].getseg = lambda ea: next((g for g in world.segs if g.start_ea <= ea < g.end_ea), None)
    m["ida_bytes"].get_flags = lambda ea: world.flags.get(ea, 0)
    m["ida_bytes"].is_data = lambda f: f & 0x600 == 0x400
    m["ida_bytes"].is_tail = lambda f: f & 0x600 == 0x200
    m["ida_ida"].inf_get_procname = lambda: world.proc
    m["ida_ida"].inf_is_64bit = lambda: True
    m["ida_ida"].inf_is_auto_enabled = lambda: world.auto_enabled
    m["ida_xref"].fl_CN, m["ida_xref"].fl_JN, m["ida_xref"].XREF_USER, m["ida_xref"].dr_O = 17, 19, 32, 1
    def add_cref(f, t, k):
        # xref.hpp: fl_CF (16) and fl_CN (17) "create a function at the referenced location" (through auto-analysis).
        # Assumed, not checked in IDA: also where t lies inside a function that starts elsewhere.
        if (k & 0x1F) in (16, 17) and getattr(sys.modules["ida_funcs"].get_func(t), "start_ea", None) != t:
            world.planned_funcs.add(t)
        world.crefs.add((f, t, k))
        return True
    m["ida_xref"].add_cref = add_cref
    m["ida_xref"].del_cref = lambda f, t, e: {world.crefs.discard(x) for x in list(world.crefs) if x[:2] == (f, t)} or True
    def add_dref(f, t, k):
        # xref.hpp notes function creation for fl_CF and fl_CN only; dr_O ("Offset") has no such note, and ida.hpp's
        # AF_PROCPTR creates a function for a data xref from data, not from an instruction. Assumed, not checked in IDA:
        # a user dr_O from an instruction makes IDA create no code and no function at t, so no planned_funcs here.
        world.data_xrefs.add((f, t, k))
        return True
    m["ida_xref"].add_dref = add_dref
    m["ida_xref"].del_dref = lambda f, t: {world.data_xrefs.discard(x) for x in list(world.data_xrefs) if x[:2] == (f, t)} and None
    dto = lambda t: sorted(({1} if t in world.drefs else set()) | {a for (a, b, _) in world.data_xrefs if b == t})
    m["ida_xref"].get_first_dref_to = lambda ea: (dto(ea) or [2**64 - 1])[0]
    m["ida_xref"].get_next_dref_to = lambda ea, cur: next((a for a in dto(ea) if a > cur), 2**64 - 1)
    dfrom = lambda f: sorted({b for (a, b, _) in world.data_xrefs if a == f})
    m["ida_xref"].get_first_dref_from = lambda f: (dfrom(f) or [2**64 - 1])[0]
    m["ida_xref"].get_next_dref_from = lambda f, cur: next((t for t in dfrom(f) if t > cur), 2**64 - 1)
    far = lambda f: sorted({t for (a, t, _) in world.crefs if a == f})
    m["ida_xref"].get_first_fcref_from = lambda f: (far(f) or [2**64 - 1])[0]
    m["ida_xref"].get_next_fcref_from = lambda f, cur: next((t for t in far(f) if t > cur), 2**64 - 1)
    m["ida_funcs"].get_func = lambda ea: None
    m["ida_funcs"].get_func_name = lambda ea: "sub_%x" % ea
    m["ida_funcs"].add_func = lambda ea: world.funcs.add(ea) or True
    m["ida_name"].get_ea_name = lambda ea: ""
    m["ida_name"].get_nlist_size = lambda: len(world.nlist)
    m["ida_name"].get_nlist_ea = lambda i: world.nlist[i][0]
    m["ida_name"].get_nlist_name = lambda i: world.nlist[i][1]
    m["ida_name"].get_name_ea = lambda frm, name: next((ea for ea, n in world.nlist if n == name), 2**64 - 1)
    class Choose:
        CHCOL_HEX, CH_RESTORE, NOTHING_CHANGED = 1, 2, 0
        def __init__(self, title, cols, flags=0): pass
    m["ida_kernwin"].Choose = Choose
    m["ida_netnode"].BADNODE, m["ida_netnode"].MAXSPECSIZE, m["ida_netnode"].htag = 2**64 - 1, 1024, 72

    class netnode:
        """Named netnodes and their hash values, as ida_netnode.pyi and the SDK's swig/netnode.i give them:
        netnode(name, namlen=0, do_create=False) (BADNODE when the name does not exist and do_create is false),
        hashset_buf(idx, str, tag=htag) -> bool (a str only; MAXSPECSIZE bytes at most), hashstr_buf(idx, tag=htag)
        -> str or None, index(), kill()."""
        def __init__(self, *args):
            name = args[0] if args and isinstance(args[0], str) else None
            if name is not None and name not in world.netnodes and len(args) > 2 and args[2]:
                world.netnodes[name] = {}
            self.name = name if name in world.netnodes else None

        def index(self):
            return 2**64 - 1 if self.name is None else 0xFF000000 + sorted(world.netnodes).index(self.name)

        def hashset_buf(self, idx, py_str, tag=72):
            if self.name is None or not isinstance(py_str, str) or len(py_str.encode()) > 1024:
                return False
            world.netnodes[self.name][(tag, idx)] = py_str
            return True

        def hashstr_buf(self, idx, tag=72):
            return None if self.name is None else world.netnodes[self.name].get((tag, idx))

        def kill(self):
            world.netnodes.pop(self.name, None)
            self.name = None
    m["ida_netnode"].netnode = netnode
    m["ida_kernwin"].jumpto = lambda ea: True
    sys.modules.update(m)
    sys.modules.pop("cfiscope.idalayer", None)
    return importlib.import_module("cfiscope.idalayer")

class IdaLayer(unittest.TestCase):
    def make(self, name, proc, perm=1, type_=2, ext=".o"):
        d, S, text = sections(os.path.join(HERE, "fixtures", name + ext))
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
            start_ea, end_ea, tailqty = t - 16, t + 64, 0
        sys.modules["ida_funcs"].get_func = lambda ea: F if F.start_ea <= ea < F.end_ea else None
        sys.modules["ida_funcs"].get_func_name = lambda ea: "__cfi_impl" if ea == F.start_ea else ""
        self.assertEqual(il.target_name(t), "__cfi_impl+0x10")
        sys.modules["ida_name"].get_ea_name = lambda ea: "impl" if ea == t else ""
        self.assertEqual(il.target_name(t), "impl")
        rows = il.callers_rows(sites, F.start_ea)
        self.assertIn(sites[0].call_ea or sites[0].check_ea, [r[0] for r in rows])

    def test_kcfi_call_not_recognised_listed_at_check(self):
        # A kCFI check whose call was not recognised still counts as a call site; it is listed at its check address
        # (v0.1.17 behaviour), never at address 0.
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        t = sites[0].targets[0]
        lone = il.core.Site(check_ea=0x1000, call_ea=0, hash=sites[0].hash, disp=sites[0].disp, targets=[t])
        rows = il.callers_rows([lone], t)
        self.assertEqual([r[0] for r in rows], [0x1000])

    def test_address_taken_ranked_first(self):
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        s = next(x for x in sites if len(x.targets) >= 2)
        w.drefs.add(s.targets[-1])
        self.assertEqual(il.ranked(s)[0], s.targets[-1])

    def inside(self, sites):
        """Every candidate lies 0x10 into a function IDA has (as when IDA starts it at the x86 __cfi_ preamble)."""
        targets = {t for s in sites for t in s.targets}
        sys.modules["ida_funcs"].get_func = lambda ea: types.SimpleNamespace(start_ea=ea - 0x10, end_ea=ea + 4,
                                                                             tailqty=0) if ea in targets else None

    def test_own_data_xref_is_not_address_taken(self):
        # After No, a candidate inside a function gets a data xref from the call; that is no stored pointer, so it must
        # not mark the candidate "address taken" (or reorder a later comment). A data xref from elsewhere still does.
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        self.inside(sites)
        self.assertTrue(il.annotate(sites, create_functions=False)["data_xrefs_inside_function"])
        self.assertTrue(w.data_xrefs)
        for s in sites:
            self.assertEqual([r[2] for r in il.targets_rows(s)], [""] * len(s.targets))
            self.assertEqual(w.cmts[s.call_ea or s.check_ea], il.describe(s))
        X = sys.modules["ida_xref"]
        s = next(x for x in sites if len(x.targets) >= 2 and (x.call_ea, x.targets[-1], X.dr_O | X.XREF_USER) in w.data_xrefs)
        w.data_xrefs.add((0xffff0000, s.targets[-1], X.dr_O))    # a pointer in data after the code: listed after ours
        self.assertEqual(il.targets_rows(s)[0][:3:2], (s.targets[-1], "address taken"))

    def test_rescan_keeps_one_xref_per_call_and_candidate(self):
        # A candidate inside a function: No gives a data xref, a later Scan answered Yes replaces it with the call xref,
        # and a later No turns it back; Remove annotations deletes either kind.
        w, il = self.make("x86_64-plain", "metapc")
        sites, _ = il.scan()
        self.inside(sites)
        X = sys.modules["ida_xref"]
        pairs = {(s.call_ea, t) for s in sites if s.call_ea and 0 < len(s.targets) <= il.DEFAULT_XREF_LIMIT for t in s.targets}
        self.assertTrue(pairs)
        il.annotate(sites, create_functions=False)
        self.assertEqual((w.crefs, w.data_xrefs), (set(), {p + (X.dr_O | X.XREF_USER,) for p in pairs}))
        il.annotate(sites)
        self.assertEqual((w.crefs, w.data_xrefs), ({p + (X.fl_CN | X.XREF_USER,) for p in pairs}, set()))
        il.annotate(sites, create_functions=False)
        self.assertEqual((w.crefs, w.data_xrefs), (set(), {p + (X.dr_O | X.XREF_USER,) for p in pairs}))
        self.assertEqual(il.remove_annotations(sites), len(pairs))
        self.assertEqual((w.crefs, w.data_xrefs), (set(), set()))

    def test_raw_load_without_permissions_scans_everything(self):
        w, il = self.make("x86_64-plain", "metapc", perm=0, type_=0)
        self.assertGreater(il.scan()[1]["sites"], 0)

    def test_jump_table_cfi_flow(self):
        """Linux 5.x jump-table CFI: the same comments, xrefs and removal, with the type in the comment."""
        import json
        with open(os.path.join(HERE, "fixtures", "jtcfi_truth.json")) as fh:
            truth = json.load(fh)
        w, il = self.make("aarch64-jtcfi", "ARM", ext=".elf")
        base = w.segs[0].start_ea
        shift = lambda a: base + int(a, 16) - int(truth["base"], 16)
        w.nlist = [(shift(v), k) for k, v in sorted(truth["symbols"].items())]
        names = {shift(v): k for k, v in truth["symbols"].items()}
        sys.modules["ida_name"].get_ea_name = lambda ea: names.get(ea, "")
        sites, stats = il.scan()
        self.assertEqual((stats["scheme"], stats["sites"], stats["named_checks"]), ("jump-table CFI", 11, 10))
        self.assertEqual(il.scheme_name(sites), "jump-table CFI")
        res = il.annotate(sites)
        self.assertEqual(res["comments"], 11)                     # Scan still comments both unlinked checks
        rt = shift(truth["sites"][-1]["runtime_call"])           # the inlined slow path's call into __cfi_check
        self.assertEqual(res["runtime_comments"], 1)
        self.assertTrue(w.cmts[rt].startswith("jtCFI runtime: calls __cfi_check (kernel's or the pointer's module's) for int (file*, int)"), w.cmts[rt])
        self.assertEqual(res["xrefs"], 7 * 3 + 1)                  # seven calls of int (file*, int), one of void (void*)
        by_call = {s.call_ea: s for s in sites}
        for want in truth["sites"]:
            s = by_call[shift(want["call"])]
            text = w.cmts[s.call_ea]
            self.assertTrue(text.startswith("jtCFI "), text)
            if want["candidates"]:
                self.assertEqual(text, "jtCFI %s: %d candidate(s): %s" % (
                    truth["type_names"][want["type"]], len(want["candidates"]), ", ".join(want["candidates"])))
                self.assertEqual({t for (f, t, _) in w.crefs if f == s.call_ea},
                                 {shift(truth["symbols"][n]) for n in want["candidates"]})
                self.assertIn("of %s: " % truth["type_names"][want["type"]], il.pseudocode_text(s))
            else:
                self.assertIn("no candidate in this image", text)
                self.assertIn("type id " + want["type_id"], text)
                self.assertEqual(il.pseudocode_text(s), "CFIScope: no candidate in this image of type id %s "
                                 "(slow-path check only)" % want["type_id"])
        # IDA keeps one name per address: with the __typeid names lost, the input ELF still names the types.
        w.nlist = [x for x in w.nlist if not x[1].startswith("__typeid_")]
        self.assertEqual(il.scan()[1]["named_checks"], 0)
        w.input_path = os.path.join(HERE, "fixtures", "aarch64-jtcfi.elf")
        sites2, stats2 = il.scan()
        self.assertEqual(stats2["named_checks"], 9)    # not the runtime's check: it has no id, file names no address
        self.assertEqual({il.core.type_label(s) for s in sites2 if s.targets and not s.runtime_check},
                         {"int (file*, int)", "void (void*)"})
        w.input_path = os.path.join(HERE, "fixtures", "missing.elf")
        self.assertEqual(il.scan()[1]["named_checks"], 0)
        lo = by_call[shift(truth["sites"][1]["call"])]               # b.lo: the call sits after the check here
        self.assertIs(il.site_at(sites, lo.call_ea), lo)
        self.assertIn("int (file*, int)", il.targets_title(lo))
        rows = il.callers_rows(sites, shift(truth["symbols"]["g_one"]))
        self.assertEqual([r[0] for r in rows], [shift(truth["sites"][4]["call"])])
        # Candidates whose jump-table entry is referenced as data rank first and are marked "address taken".
        hs = by_call[shift(truth["sites"][0]["call"])]
        w.drefs.add(shift(truth["symbols"]["f_c.cfi_jt"]))
        self.assertEqual(il.ranked(hs)[0], shift(truth["symbols"]["f_c"]))
        self.assertEqual([r[2] for r in il.targets_rows(hs)], ["address taken", "", ""])
        w.drefs.discard(shift(truth["symbols"]["f_c.cfi_jt"]))
        # On a jump-table entry (where pointers to the function point), callers are those of the function itself.
        self.assertEqual(il.callers_rows(sites, shift(truth["symbols"]["g_one.cfi_jt"])), rows)
        self.assertEqual(il.callers_rows(sites, shift(truth["symbols"]["f_a.cfi_jt"])),
                         il.callers_rows(sites, shift(truth["symbols"]["f_a"])))
        rows = il.callers_rows(sites, shift(truth["symbols"]["f_a.cfi_jt"]))
        # Seven calls, then the check whose call was not linked (not a call site); never the runtime's own check.
        unlinked, runtime = (shift(c["check"]) for c in truth["checks"])
        self.assertEqual([r[0] for r in rows], [shift(w["call"]) for w in truth["sites"] if "f_a" in w["candidates"]]
                         + [unlinked])
        self.assertEqual(rows[-1][2], "type check only (call not linked), 3 candidate(s)")
        self.assertEqual(il.callers_title(sites, shift(truth["symbols"]["f_a"]), rows), "jump-table CFI callers: 7 call "
                         "site(s) can reach f_a (+1 type check(s) whose call was not linked, listed last)")
        self.assertIn(runtime, {s.check_ea for s in sites})      # it is still a site (Scan comments it)
        # The cursor exactly on a call (or check) always selects that site, even inside another site's span.
        for s in sites:
            if s.call_ea:
                self.assertIs(il.site_at(sites, s.call_ea), s)
        self.assertEqual(il.remove_annotations(sites), res["xrefs"])
        self.assertEqual(w.cmts, {}); self.assertEqual(w.crefs, set())

    def test_jump_table_cfi_callers_runtime_by_function(self):
        """A runtime check the code test missed is still left out: by IDA's function name, or because its function
        has no blr/br."""
        import json
        with open(os.path.join(HERE, "fixtures", "jtcfi_truth.json")) as fh:
            truth = json.load(fh)
        w, il = self.make("aarch64-jtcfi", "ARM", ext=".elf")
        base = w.segs[0].start_ea
        shift = lambda a: base + int(a, 16) - int(truth["base"], 16)
        starts = sorted((shift(v), k) for k, v in truth["symbols"].items() if not k.startswith("__typeid_"))
        func_name = {"__cfi_check": "__cfi_check"}
        tails = set()                                         # functions given a tail chunk (func_t.tailqty)
        class F:
            def __init__(self, lo, hi): self.start_ea, self.end_ea, self.tailqty = lo, hi, int(lo in tails)
        def get_func(ea):
            for (lo, _), (hi, _) in zip(starts, starts[1:]):
                if lo <= ea < hi:
                    return F(lo, hi)
        names = {a: k for a, k in starts}
        sys.modules["ida_funcs"].get_func = get_func
        sys.modules["ida_funcs"].get_func_name = lambda ea: func_name.get(names.get(ea), names.get(ea, ""))
        sites, _ = il.scan()
        unlinked, runtime = (shift(c["check"]) for c in truth["checks"])
        f_a = shift(truth["symbols"]["f_a"])
        next(s for s in sites if s.check_ea == runtime).runtime_check = False
        self.assertTrue(il.in_cfi_runtime(runtime))
        self.assertFalse(il.in_cfi_runtime(unlinked))
        self.assertEqual(il.callers_rows(sites, f_a)[-1][0], unlinked)
        func_name["__cfi_check"] = "renamed"                    # by code only: no blr/br in that function
        sites, _ = il.scan()
        next(s for s in sites if s.check_ea == runtime).runtime_check = False
        self.assertTrue(il.in_cfi_runtime(runtime))
        self.assertNotIn(runtime, [r[0] for r in il.callers_rows(sites, f_a)])
        # By the name alone: with the code test reporting a blr (fresh scan, so nothing cached), only IDA's function
        # name __cfi_check marks it; renamed, it is kept.
        func_name["__cfi_check"] = "__cfi_check"
        sites, _ = il.scan()
        next(s for s in sites if s.check_ea == runtime).runtime_check = False
        with mock.patch.object(il.core, "has_indirect_call", lambda mem: True):
            self.assertTrue(il.in_cfi_runtime(runtime))
            self.assertNotIn(runtime, [r[0] for r in il.callers_rows(sites, f_a)])
            func_name["__cfi_check"] = "renamed"
            self.assertFalse(il.in_cfi_runtime(runtime))
            self.assertEqual([r[0] for r in il.callers_rows(sites, f_a)][-2:], [unlinked, runtime])
        # A function with tail chunks: its entry chunk has no blr/br, but a tail may, so only the name can mark it.
        sites, _ = il.scan()
        next(s for s in sites if s.check_ea == runtime).runtime_check = False
        tails.add(shift(truth["symbols"]["__cfi_check"]))
        self.assertFalse(il.in_cfi_runtime(runtime))                # renamed, with a tail: kept
        self.assertEqual([r[0] for r in il.callers_rows(sites, f_a)][-2:], [unlinked, runtime])
        func_name["__cfi_check"] = "__cfi_check"
        self.assertTrue(il.in_cfi_runtime(runtime))                 # named __cfi_check: left out, tail or not
        tails.clear()
        func_name["__cfi_check"] = "renamed"
        sys.modules["ida_funcs"].get_func = lambda ea: None     # no function there: listed as an unlinked check
        sites, _ = il.scan()
        next(s for s in sites if s.check_ea == runtime).runtime_check = False
        self.assertEqual([r[0] for r in il.callers_rows(sites, f_a)][-2:], [unlinked, runtime])

class BTFTypeNames(unittest.TestCase):
    """kCFI hashes named by C function type from the BTF in the input file (fake IDA modules)."""

    def test_named_from_input_file_btf(self):
        w, il = IdaLayer.make(None, "kcfi_types_a64", "ARM")
        sites, stats = il.scan()
        by_hash = {s.hash: s for s in sites}
        self.assertNotIn("kcfi_hashes_named", stats)          # no input file: unchanged
        self.assertNotIn("(file*", il.describe(by_hash[0x4f4ccb9d]))
        self.assertRegex(il.pseudocode_text(by_hash[0x1300e12b]), r"^CFIScope: 1 candidate: 0x[0-9a-fA-F]+$")
        w.input_path = os.path.join(HERE, "fixtures", "kcfi_types_btf.o")   # a file holding BTF
        sites, stats = il.scan()
        by_hash = {s.hash: s for s in sites}
        self.assertEqual(stats["kcfi_hashes_named"], 3)
        self.assertIn("0x4F4CCB9D int (struct file *, int): 1 candidate(s)", il.describe(by_hash[0x4f4ccb9d]))
        self.assertIn("(hash 0x4F4CCB9D, int (struct file *, int))", il.targets_title(by_hash[0x4f4ccb9d]))
        self.assertIn("0x4A7B6FDC: no implementation", il.describe(by_hash[0x4a7b6fdc]))   # not in this BTF
        self.assertRegex(il.pseudocode_text(by_hash[0x1300e12b]),
                         r"^CFIScope: 1 candidate of long \(short, int\): 0x[0-9a-fA-F]+$")
        self.assertEqual(il.pseudocode_text(by_hash[0x4a7b6fdc]), "CFIScope: 0 candidates in this image")


class NoXrefsIntoData(unittest.TestCase):
    """tests/test_core.kernel_with_rodata_hash() in one RWX segment, as IDA loads a vmlinux-to-elf ELF: the hash value
    in 'rodata' yields a candidate at KB + 0x1004 next to the real one at KB + 0x24."""

    def make(self, *functions):
        """functions: offsets of more functions of the call's type (test_core.with_functions)."""
        from test_core import kernel_with_rodata_hash, with_functions, KB
        code, bounds = kernel_with_rodata_hash()
        code = with_functions(code, *functions)
        w = World([Seg(KB, KB + len(code), 7, 2)], {KB: code}); w.proc = "ARM"
        il = install(w)
        sys.modules["ida_funcs"].get_func = lambda ea: ea in w.funcs or None
        return w, il, KB, bounds

    def test_no_xref_or_function_at_data(self):
        w, il, kb, _ = self.make()
        sites, stats = il.scan()                              # no names, no input file: both candidates
        self.assertEqual(sites[0].targets, [kb + 0x24, kb + 0x1004])
        self.assertNotIn("outside_text", stats)
        for flags in (0x400, 0x200):                          # IDA holds it as data, or it is inside another item
            w.flags = {kb + 0x1004: flags}; w.crefs.clear(); w.funcs.clear()
            res = il.annotate(sites)
            self.assertEqual({(f, t) for f, t, _ in w.crefs}, {(sites[0].call_ea, kb + 0x24)})
            self.assertEqual((res["xrefs"], res["xrefs_skipped_not_code"]), (1, 1))
            self.assertEqual(il.define_functions(sites), {"functions_created": 1, "skipped_not_code": 1})
            self.assertEqual(w.funcs, {kb + 0x24})
            self.assertEqual(il.remove_annotations(sites), 1)
        # The same bytes, but in a data segment while the database has a code segment: no xref, no function.
        w.flags = {}; w.crefs.clear(); w.funcs.clear()
        w.segs = [Seg(kb, kb + 0x1000, 5, 2), Seg(kb + 0x1000, kb + 0x2100, 4, 3)]
        self.assertEqual(il.annotate(sites)["xrefs_skipped_not_code"], 1)
        self.assertEqual(il.define_functions(sites), {"functions_created": 1, "skipped_not_code": 1})
        self.assertEqual({t for _, t, _ in w.crefs} | w.funcs, {kb + 0x24})
        # Raw load: no segment is code or executable, every segment is scanned, and only the item flags count.
        w.segs = [Seg(kb, kb + 0x2100, 0, 0)]; w.crefs.clear(); w.funcs.clear()
        self.assertEqual(il.annotate(sites)["xrefs"], 2)

    def test_existing_function_not_counted_as_skipped(self):
        # Both candidates already lie in functions IDA has, the data one in a literal pool inside a function at
        # KB + 0x1000: no function is created, and neither counts as skipped.
        w, il, kb, _ = self.make()
        sites, _ = il.scan()
        w.flags = {kb + 0x1004: 0x400}
        w.funcs = {kb + 0x24}
        sys.modules["ida_funcs"].get_func = lambda ea: ea in w.funcs or kb + 0x1000 <= ea < kb + 0x1100 or None
        self.assertEqual(il.define_functions(sites), {"functions_created": 0, "skipped_not_code": 0})
        self.assertEqual(w.funcs, {kb + 0x24})

    def test_bytes_at(self):
        il_bytes_at = self.make()[1]._bytes_at
        ranges = [(0x1000, bytes(range(16)))]
        self.assertEqual(il_bytes_at(ranges, 0x1000), bytes(range(16)))
        self.assertEqual(il_bytes_at(ranges, 0x1004, 4), bytes(range(4, 8)))
        self.assertEqual(il_bytes_at(ranges, 0x100c), bytes(range(12, 16)))
        for ea in (0xfff, 0x100d, 0x1010):                    # before the range, or fewer than 4 bytes left
            self.assertIsNone(il_bytes_at(ranges, ea), hex(ea))

    def test_input_file_without_bytes_at_its_bounds(self):
        # The input ELF's _sinittext lies past its code, so neither the file nor the database has bytes there: the
        # layout cannot be checked and the file's names are not used (the database has none here).
        import tempfile
        from test_cli import kernel_elf
        w, il, kb, _ = self.make()
        with tempfile.TemporaryDirectory() as tmp:
            w.input_path = os.path.join(tmp, "k.elf")
            kernel_elf(w.input_path, extra={"_sinittext": kb + 0x3000, "_einittext": kb + 0x3100})
            sites, stats = il.scan()
            self.assertEqual(sites[0].targets, [kb + 0x24, kb + 0x1004])
            self.assertNotIn("outside_text", stats)
            kernel_elf(w.input_path)                          # the same file with _sinittext in its code: used
            self.assertEqual(il.scan()[0][0].targets, [kb + 0x24])

    def test_text_bounds_from_names(self):
        w, il, kb, bounds = self.make()
        w.nlist = sorted((ea, n) for n, ea in bounds.items())
        sites, stats = il.scan()
        self.assertEqual((sites[0].targets, stats["outside_text"]), ([kb + 0x24], 1))
        self.assertEqual(il.annotate(sites)["xrefs"], 1)
        self.assertEqual(il.define_functions(sites), {"functions_created": 1, "skipped_not_code": 0})

    def test_text_bounds_from_input_file(self):
        # IDA keeps one name per address: with _stext lost to another name, the input ELF's symbols bound the text,
        # unless the database was rebased (then its bytes at the file's _stext differ).
        import tempfile
        from test_cli import kernel_elf
        w, il, kb, bounds = self.make()
        w.nlist = [(ea, n) for n, ea in bounds.items() if n != "_stext"] + [(kb, "__irqentry_text_start")]
        self.assertEqual(il.scan()[0][0].targets, [kb + 0x24, kb + 0x1004])
        with tempfile.TemporaryDirectory() as tmp:
            w.input_path = os.path.join(tmp, "k.elf")
            kernel_elf(w.input_path)
            sites, stats = il.scan()
            self.assertEqual((sites[0].targets, stats["outside_text"]), ([kb + 0x24], 1))
            # The file's bytes at its _stext but not at its _sinittext (another build): its symbols are not used.
            code = w.mem[kb]
            w.mem[kb] = code[:0x2000] + struct.pack("<I", 0xd503201f) + code[0x2004:]
            self.assertEqual(il.scan()[0][0].targets, [kb + 0x24, kb + 0x1004])
            w.mem[kb] = code
            w.nlist = []
            code = w.mem.pop(kb)
            w.segs = [Seg(kb + 0x10000, kb + 0x10000 + len(code), 7, 2)]; w.mem = {kb + 0x10000: code}
            sites, stats = il.scan()
            self.assertEqual(sites[0].targets, [kb + 0x10024, kb + 0x11004])
            self.assertNotIn("outside_text", stats)

    def test_one_name_per_address_without_input_file(self):
        # IDA keeps one name per address, and the input file is gone (database moved to another machine).
        # Exit text: x86-64 never names it, and on arm64 __exittext_begin shares its address with _einittext. A
        # function after _einittext is kept whichever name the database kept; only the 'rodata' hit is left out.
        w, il, kb, bounds = self.make(0x2104)
        for exit_names in ([], [(kb + 0x2100, "__exittext_end")]):
            w.nlist = sorted([(ea, n) for n, ea in bounds.items()] + exit_names)
            sites, stats = il.scan()
            self.assertEqual((sites[0].targets, stats["outside_text"]), ([kb + 0x24, kb + 0x2104], 1))
        # idmap code between _etext and _sinittext (arm64 6.6 and later), its start named enter_vhe in the database:
        # with only __idmap_text_end the area cannot be placed, so nothing is left out (not its functions).
        w, il, kb, bounds = self.make(0x1800)
        w.nlist = sorted([(ea, n) for n, ea in bounds.items()] + [(kb + 0x1800, "enter_vhe"),
                                                                   (kb + 0x1900, "__idmap_text_end")])
        sites, stats = il.scan()
        self.assertEqual(sites[0].targets, [kb + 0x24, kb + 0x1004, kb + 0x1800])
        self.assertNotIn("outside_text", stats)
        w.nlist = sorted((ea, "__idmap_text_start" if n == "enter_vhe" else n) for ea, n in w.nlist)
        sites, stats = il.scan()
        self.assertEqual((sites[0].targets, stats["outside_text"]), ([kb + 0x24, kb + 0x1800], 1))


if __name__ == "__main__":
    unittest.main()
