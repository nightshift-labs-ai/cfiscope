"""Loads cfiscope_entry.py on fake ida_* modules: scan cache, rescan after a rebase, menus, right-click hooks and
the pseudocode comments. It proves the plugin wiring runs, not that IDA or Hex-Rays behave like the fakes."""
import importlib, json, os, sys, types, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
import test_plugin_stub as T  # noqa: E402


def load_entry(name="x86_64-kernel", proc="metapc", ext=".o"):
    w, _ = T.IdaLayer("test_flow").make(name, proc, ext=ext)
    kw, ia = sys.modules["ida_kernwin"], sys.modules["ida_idaapi"]
    log = {"msgs": [], "menu": [], "popup": [], "registered": [], "hooked": 0, "asked": [], "world": w}
    kw.msg = lambda t: log["msgs"].append(t)
    kw.show_wait_box = lambda t: None
    kw.hide_wait_box = lambda: None
    kw.warning = lambda t: log["msgs"].append("WARN " + t)
    kw.action_handler_t = type("action_handler_t", (), {})
    kw.AST_ENABLE_ALWAYS, kw.SETMENU_APP, kw.BWN_DISASM, kw.BWN_PSEUDOCODE = 1, 0, 27, 46
    kw.action_desc_t = lambda name, label, handler, key: name
    kw.register_action = lambda d: log["registered"].append(d) or True
    kw.unregister_action = lambda n: log["registered"].remove(n) or True
    kw.attach_action_to_menu = lambda path, n, f: log["menu"].append((path, n)) or True
    kw.get_widget_type = lambda w: w
    kw.attach_action_to_popup = lambda w, p, n, path: log["popup"].append((w, n, path)) or True
    kw.ask_yn, kw.ASKBTN_NO, kw.ASKBTN_YES, kw.ASKBTN_CANCEL = (lambda default, text: 0), 0, 1, -1
    lines = types.ModuleType("ida_lines")
    lines.SCOLOR_AUTOCMT = "\x04"
    lines.COLSTR = lambda text, tag: "\x01" + tag + text + "\x02" + tag
    sys.modules["ida_lines"] = lines

    class UI_Hooks:
        def hook(self):
            log["hooked"] += 1
            return True

        def unhook(self):
            log["hooked"] -= 1
            return True
    kw.UI_Hooks = UI_Hooks
    ia.plugin_t = type("plugin_t", (), {})
    ia.PLUGIN_KEEP = 1
    sys.modules.pop("cfiscope_entry", None)
    return w, importlib.import_module("cfiscope_entry"), log


INTERRUPTED = ("[CFIScope] interrupted: the action stopped part-way; run it again (Scan kCFI calls or Remove "
               "annotations) to finish\n")


class Entry(unittest.TestCase):
    def test_cache_and_rebase(self):
        w, E, log = load_entry()
        s1 = E.scan_or_warn()
        self.assertEqual(len(s1), 21)
        self.assertIs(E.scan_or_warn(), s1)
        seg = w.segs[0]
        w.mem[seg.start_ea + 0x1000] = w.mem.pop(seg.start_ea)
        seg.start_ea += 0x1000; seg.end_ea += 0x1000
        s2 = E.scan_or_warn()
        self.assertIsNot(s2, s1)
        self.assertEqual(len(s2), 21)
        self.assertTrue(any("scanning again" in m for m in log["msgs"]))

    def test_create_functions_reports_skipped(self):
        # "Create functions" answered yes: functions at the candidates IDA has none for, none where IDA holds data.
        w, E, log = load_entry()
        w.funcs = set()
        sys.modules["ida_funcs"].get_func = lambda ea: ea in w.funcs or None
        sys.modules["ida_kernwin"].ask_yn = lambda default, text: 1
        sites = E.scan_or_warn()
        targets = sorted({t for s in sites for t in s.targets})
        w.flags = {targets[0]: 0x400}
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertIn("[CFIScope] functions created: %d; candidates skipped (data, or not in a code segment): 1\n"
                      % (len(targets) - 1), log["msgs"])
        self.assertEqual(w.funcs, set(targets[1:]))

    def answers(self, log, create=0, wait=None):
        """ask_yn by question: create-functions -> create; any other question -> wait. Records each question with the
        number of xrefs and functions-to-be that existed when it was asked."""
        w = log["world"]
        def ask_yn(default, text):
            log["asked"].append((text.split("?")[0], len(w.crefs), len(w.planned_funcs)))
            return create if text.startswith("Create functions") else wait
        sys.modules["ida_kernwin"].ask_yn = ask_yn

    def test_no_creates_no_function(self):
        # "No": no add_func, and no call xref to a candidate without a function (IDA would make one: fl_CN).
        w, E, log = load_entry()
        sites = E.scan_or_warn()
        targets = sorted({t for s in sites for t in s.targets})
        w.funcs = set(targets[::2])                               # IDA already has functions at half of them
        F = lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 4, tailqty=0)
        sys.modules["ida_funcs"].get_func = lambda ea: F(ea) if ea in w.funcs else None
        self.answers(log, create=0)
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual(log["asked"], [("Create functions at candidates IDA has not recognised", 0, 0)])
        self.assertEqual(w.funcs, set(targets[::2]))
        self.assertEqual(w.planned_funcs, set())
        self.assertTrue(w.crefs)
        self.assertTrue({t for _, t, _ in w.crefs} <= w.funcs)
        res = [m for m in log["msgs"] if '"xrefs_skipped_no_function"' in m]
        self.assertEqual(len(res), 1)
        self.assertNotIn('"xrefs_skipped_no_function": 0}', res[0])
        # Remove annotations takes out every xref the scan added.
        self.assertEqual(E.RemoveAction().activate(None), 1)
        self.assertEqual(w.crefs, set())

    def test_no_data_xref_to_candidate_inside_a_function(self):
        # "No": a candidate inside a function IDA has, not at its start (on x86 IDA may start the function at the
        # __cfi_ preamble, 16 bytes earlier), gets a user data xref (dr_O) instead of a call xref, which "creates a
        # function at the referenced location" (xref.hpp, fl_CN), so it can still be followed from the call; a candidate
        # with no function gets neither. Remove annotations deletes the data xrefs too.
        w, E, log = load_entry()
        sites = E.scan_or_warn()
        targets = sorted({t for s in sites for t in s.targets})
        inside, none = set(targets[1::3]), set(targets[2::3])     # 0x10 into a function IDA has; no function at all
        F = lambda ea: types.SimpleNamespace(start_ea=ea - 0x10 if ea in inside else ea, end_ea=ea + 4, tailqty=0)
        sys.modules["ida_funcs"].get_func = lambda ea: F(ea) if ea in targets and ea not in none else None
        self.answers(log, create=0)
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual(w.planned_funcs, set())
        limit = sys.modules["cfiscope.idalayer"].DEFAULT_XREF_LIMIT
        X = sys.modules["ida_xref"]
        pairs = [(s.call_ea, t) for s in sites if s.call_ea and 0 < len(s.targets) <= limit for t in s.targets]
        self.assertEqual({(f, t) for f, t, _ in w.crefs}, {p for p in pairs if p[1] not in inside | none})
        self.assertEqual(w.data_xrefs, {p + (X.dr_O | X.XREF_USER,) for p in pairs if p[1] in inside})
        res = json.loads(next(m for m in log["msgs"] if '"data_xrefs_inside_function"' in m)[len("[CFIScope] "):])
        self.assertEqual((res["data_xrefs_inside_function"], res["xrefs_skipped_no_function"]),
                         (sum(t in inside for _, t in pairs), sum(t in none for _, t in pairs)))
        self.assertTrue(res["data_xrefs_inside_function"] and res["xrefs_skipped_no_function"])
        self.assertEqual(E.RemoveAction().activate(None), 1)
        self.assertIn("[CFIScope] xrefs removed: %d\n" % len(set(pairs) - {p for p in pairs if p[1] in none}),
                      log["msgs"])
        self.assertEqual((w.crefs, w.data_xrefs), (set(), set()))

    def test_yes_asked_before_xrefs(self):
        w, E, log = load_entry()
        w.funcs = set()
        sys.modules["ida_funcs"].get_func = lambda ea: ea in w.funcs or None
        self.answers(log, create=1)
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual(log["asked"], [("Create functions at candidates IDA has not recognised", 0, 0)])
        self.assertTrue(w.crefs)
        self.assertTrue({t for _, t, _ in w.crefs} <= w.funcs | w.planned_funcs)

    def test_cancel_create_functions_stops_scan(self):
        # Cancel/Esc on "Create functions?" stops before anything is written (it is asked before annotating).
        w, E, log = load_entry()
        self.answers(log, create=-1)
        self.assertEqual(E.ScanAction().activate(None), 0)
        self.assertEqual(log["asked"], [("Create functions at candidates IDA has not recognised", 0, 0)])
        self.assertEqual(w.cmts, {})
        self.assertEqual(w.crefs, set())

    def test_wait_boxes(self):
        # Every wait box is closed; the scan's boxes hide Cancel (nothing polls user_cancelled()); add_func runs
        # inside one, so IDAPython does not show its own interrupt dialog.
        w, E, log = load_entry()
        kw = sys.modules["ida_kernwin"]
        boxes = []
        kw.show_wait_box = lambda t: boxes.append(t)
        kw.hide_wait_box = lambda: boxes.append(None)
        inside = []
        def add_func(ea):
            inside.append(len([b for b in boxes if b]) - boxes.count(None))
            w.funcs.add(ea)
            return True
        sys.modules["ida_funcs"].add_func = add_func
        w.funcs = set()
        sys.modules["ida_funcs"].get_func = lambda ea: ea in w.funcs or None
        self.answers(log, create=1)
        self.assertEqual(E.ScanAction().activate(None), 1)
        texts = [b for b in boxes if b]
        self.assertEqual(len(texts), 2)
        self.assertTrue(all(t.startswith("HIDECANCEL\n") for t in texts), texts)
        self.assertEqual(boxes.count(None), len(texts))
        self.assertTrue(inside and set(inside) == {1}, inside)

    def test_interrupt_is_reported(self):
        # Cancel in IDAPython's "Running Python script" box raises KeyboardInterrupt, which except Exception misses.
        w, E, log = load_entry()
        def add_func(ea):
            raise KeyboardInterrupt("User interrupted")
        sys.modules["ida_funcs"].add_func = add_func
        self.answers(log, create=1)
        self.assertEqual(E.ScanAction().activate(None), 0)
        self.assertEqual([m for m in log["msgs"] if "interrupted" in m],
                         [INTERRUPTED])
        self.assertFalse([m for m in log["msgs"] if m.startswith("WARN")])
        # Remove annotations is guarded the same way, and the line does not send the user to Scan only.
        sys.modules["ida_xref"].del_cref = lambda *a: (_ for _ in ()).throw(KeyboardInterrupt("User interrupted"))
        log["msgs"].clear()
        self.assertEqual(E.RemoveAction().activate(None), 0)
        self.assertEqual([m for m in log["msgs"] if "interrupted" in m], [INTERRUPTED])

    def test_waits_for_auto_analysis(self):
        # ask_yn: -1 Cancel (nothing happens), 1 Yes (auto_wait, then scan), 0 No (scan now).
        for wait, expect_scan, expect_waited in ((-1, False, False), (1, True, True), (0, True, False)):
            with self.subTest(wait=wait):
                w, E, log = load_entry()
                w.auto_ok = False
                waited = []
                sys.modules["ida_auto"].auto_wait = lambda: waited.append(1) or setattr(w, "auto_ok", True) or True
                self.answers(log, create=0, wait=wait)
                self.assertEqual(E.ScanAction().activate(None), int(expect_scan))
                self.assertEqual(log["asked"][0][0], "IDA is still analysing this database.\nWait for auto-analysis to "
                                                     "finish before scanning")
                self.assertEqual(bool(w.cmts), expect_scan)
                self.assertEqual(E.STATE["sites"] is not None, expect_scan)
                self.assertEqual(waited, [1] if expect_waited else [])
        # auto_wait returns false (Cancel in its wait box): nothing is scanned or written.
        w, E, log = load_entry()
        w.auto_ok = False
        sys.modules["ida_auto"].auto_wait = lambda: False
        self.answers(log, create=0, wait=1)
        self.assertEqual(E.ScanAction().activate(None), 0)
        self.assertEqual((w.cmts, w.crefs, E.STATE["sites"]), ({}, set(), None))

    def test_analysis_turned_off_counts_as_finished(self):
        # Analysis disabled (INFFL_AUTO off): its queues stay full, so no question and no auto_wait; Scan runs.
        w, E, log = load_entry()
        w.auto_ok, w.auto_enabled = False, False
        waited = []
        sys.modules["ida_auto"].auto_wait = lambda: waited.append(1) or True
        self.answers(log, create=0, wait=-1)
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual([q for q in log["asked"] if q[0].startswith("IDA is still")], [])
        self.assertEqual(waited, [])
        self.assertTrue(w.cmts)

    def test_menus_and_popup(self):
        _, E, log = load_entry()
        p = E.PLUGIN_ENTRY()
        self.assertEqual(p.init(), 1)
        self.assertEqual(len(log["registered"]), 4)
        self.assertEqual(log["hooked"], 1)
        p.hooks.finish_populating_widget_popup(46, "popup")   # pseudocode view
        p.hooks.finish_populating_widget_popup(99, "popup")   # some other view: nothing added
        self.assertEqual([n for _, n, _ in log["popup"]], ["cfiscope:scan", "cfiscope:targets", "cfiscope:callers"])
        p.term()
        self.assertEqual(log["hooked"], 0)
        self.assertEqual(log["registered"], [])


class Line:
    def __init__(self, text):
        self.line = text


class FakeCfunc:
    """A decompiled function: pseudocode lines, an eamap (address -> statements) and each statement's (x, y)."""

    def __init__(self, lines, eamap, coords):
        self.sv, self.eamap, self.coords = [Line(t) for t in lines], eamap, coords

    def get_eamap(self):
        return self.eamap

    def get_pseudocode(self):
        return self.sv

    def find_item_coords(self, item):
        return self.coords[item]

    def text(self):
        return [line.line for line in self.sv]


def fake_hexrays(log, available=True):
    hx = types.ModuleType("ida_hexrays")
    log.update(hx_hooked=0, hx_flushed=0)

    class Hexrays_Hooks:
        def hook(self):
            log["hx_hooked"] += 1
            return True

        def unhook(self):
            log["hx_hooked"] -= 1
            return True
    hx.Hexrays_Hooks = Hexrays_Hooks
    hx.init_hexrays_plugin = lambda flags=0: available
    hx.clear_cached_cfuncs = lambda: log.update(hx_flushed=log["hx_flushed"] + 1)
    sys.modules["ida_hexrays"] = hx
    return hx


class Pseudocode(unittest.TestCase):
    def setUp(self):
        self.addCleanup(sys.modules.pop, "ida_hexrays", None)
        self.w, self.E, self.log = load_entry()
        sys.modules["ida_name"].get_ea_name = lambda ea: "f_%x" % ea

    def scanned_plugin(self):
        fake_hexrays(self.log)
        p = self.E.PLUGIN_ENTRY()
        p.init()
        self.assertEqual(self.log["hx_hooked"], 1)
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        return p, self.E.STATE["sites"]

    def test_comments_on_the_mapped_lines(self):
        p, sites = self.scanned_plugin()
        self.assertEqual(self.log["hx_flushed"], 1)
        short = next(s for s in sites if len(s.targets) == 3)
        long_ = next(s for s in sites if len(s.targets) == 6)
        names = lambda s: ["f_%x" % t for t in sorted(s.targets)]
        lines = ["int do_call(void)", "{", "  v1 = 0;", "  return fp(v1);", "  g(v1);", "}"]
        cf = FakeCfunc(lines, {short.call_ea: ["ret", "lost"], long_.call_ea: ["expr", "dup"], 0x1234: ["other"]},
                       {"ret": (2, 3), "lost": (0, 99), "expr": (2, 4), "dup": (9, 4), "other": (2, 2)})
        self.assertEqual(self.E.STATE["hx"].func_printed(cf), 0)
        out = cf.text()
        self.assertEqual(out[:3], lines[:3])
        self.assertEqual(out[5], lines[5])
        self.assertEqual(out[3], lines[3] + "\x01\x04  // CFIScope: 3 candidates: %s\x02\x04" % ", ".join(names(short)))
        self.assertEqual(out[4], lines[4] + "\x01\x04  // CFIScope: 6 candidates: %s and 1 more\x02\x04"
                         % ", ".join(names(long_)[:5]))
        self.assertFalse(any("failed" in m for m in self.log["msgs"]))
        p.term()
        self.assertEqual(self.log["hx_hooked"], 0)

    def test_text_for_one_and_zero_candidates(self):
        self.scanned_plugin()
        il = self.E.idalayer
        self.assertEqual(il.pseudocode_text(types.SimpleNamespace(targets=[0x10])), "CFIScope: 1 candidate: f_10")
        self.assertEqual(il.pseudocode_text(types.SimpleNamespace(targets=[])), "CFIScope: 0 candidates in this image")

    def test_untouched_without_sites_scan_or_after_remove(self):
        lines = ["void f(void)", "{", "  g();", "}"]
        p = self.E.PLUGIN_ENTRY()
        fake_hexrays(self.log)
        p.init()
        site = self.E.scan_or_warn()[0]            # a lookup scans, but nothing is annotated yet
        cf = FakeCfunc(lines, {site.call_ea: ["s"]}, {"s": (2, 2)})
        self.assertEqual(self.E.STATE["hx"].func_printed(cf), 0)
        self.assertEqual(cf.text(), lines)
        self.E.ScanAction().activate(None)
        other = FakeCfunc(lines, {0x1234: ["s"]}, {"s": (2, 2)})   # a function with no kCFI site
        self.assertEqual(self.E.STATE["hx"].func_printed(other), 0)
        self.assertEqual(other.text(), lines)
        self.E.RemoveAction().activate(None)
        self.assertEqual(self.log["hx_flushed"], 2)
        self.assertEqual(self.E.STATE["hx"].func_printed(cf), 0)
        self.assertEqual(cf.text(), lines)
        self.E.ScanAction().activate(None)
        self.w.segs[-1].end_ea += 0x1000                 # segments changed since the scan: stale, skipped
        self.assertEqual(self.E.STATE["hx"].func_printed(cf), 0)
        self.assertEqual(cf.text(), lines)
        self.assertFalse(any("failed" in m for m in self.log["msgs"]))

    def test_no_decompiler(self):
        for setup in (lambda: sys.modules.__setitem__("ida_hexrays", None),   # import fails
                      lambda: fake_hexrays(self.log, available=False)):       # init_hexrays_plugin() is false
            with self.subTest(setup=setup):
                self.log["hx_hooked"] = 0
                setup()
                self.E.STATE["hx"] = None
                p = self.E.PLUGIN_ENTRY()
                self.assertEqual(p.init(), 1)
                self.assertEqual(self.E.ScanAction().activate(None), 1)
                self.assertIsNone(self.E.STATE["hx"])
                self.assertEqual(self.log["hx_hooked"], 0)
                self.assertGreater(len(self.w.cmts), 0)              # disassembly comments as before
                self.assertFalse(any("WARN" in m for m in self.log["msgs"]))
                p.term()

    def test_exception_in_hook_is_swallowed(self):
        self.scanned_plugin()
        hooks = self.E.STATE["hx"]

        class Broken:
            def get_eamap(self):
                raise RuntimeError("boom")
        self.assertEqual(hooks.func_printed(Broken()), 0)
        self.assertEqual(hooks.func_printed(Broken()), 0)
        self.assertEqual(sum("pseudocode comment failed" in m for m in self.log["msgs"]), 1)   # logged once
        self.assertEqual(hooks.func_printed(None), 0)


NODE = "$ cfiscope"


class Reopen(unittest.TestCase):
    """Scan leaves a marker in a netnode; after the database is reopened, the first pseudocode print or lookup rebuilds
    the scan from the code (read-only) so the pseudocode comments come back without pressing Scan."""

    def setUp(self):
        self.addCleanup(sys.modules.pop, "ida_hexrays", None)
        self.w, self.E, self.log = load_entry()
        sys.modules["ida_name"].get_ea_name = lambda ea: "f_%x" % ea

    def scan(self, create=0):
        fake_hexrays(self.log)
        p = self.E.PLUGIN_ENTRY()
        p.init()
        Entry.answers(self, self.log, create=create)
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        return p

    def reopen(self, p, fresh_module=False):
        """Close the database (term) and open it again: the database keeps comments, xrefs and netnodes; the plugin
        module either survives (same STATE) or is imported again. Afterwards nothing may ask, write or create."""
        p.term()
        if fresh_module:
            sys.modules.pop("cfiscope_entry", None)
            self.E = importlib.import_module("cfiscope_entry")
        self.scans = []
        il = sys.modules["cfiscope.idalayer"]
        real = il.scan
        il.scan = lambda: self.scans.append(1) or real()
        self.addCleanup(setattr, il, "scan", real)
        self.loads = []                             # the marker is looked at once per database, not on every print
        real_load = il.load_marker
        il.load_marker = lambda: self.loads.append(1) or real_load()
        self.addCleanup(setattr, il, "load_marker", real_load)
        def forbidden(*a, **k):
            raise AssertionError("the restore must not ask or write: %r" % (a,))
        kw, X, F, B = (sys.modules[n] for n in ("ida_kernwin", "ida_xref", "ida_funcs", "ida_bytes"))
        for mod, name in ((kw, "ask_yn"), (kw, "show_wait_box"), (kw, "warning"), (X, "add_cref"), (X, "del_cref"),
                          (X, "add_dref"), (X, "del_dref"), (F, "add_func"), (B, "set_cmt")):
            setattr(mod, name, forbidden)
        self.before = (dict(self.w.cmts), set(self.w.crefs), set(self.w.data_xrefs), set(self.w.funcs),
                       set(self.w.planned_funcs), {n: dict(v) for n, v in self.w.netnodes.items()})
        self.log["msgs"].clear()
        p = self.E.PLUGIN_ENTRY()
        p.init()
        return p

    def unchanged(self):
        # netnodes too: reading the marker must not create its netnode (a database write)
        self.assertEqual((self.w.cmts, self.w.crefs, self.w.data_xrefs, self.w.funcs, self.w.planned_funcs,
                          self.w.netnodes), self.before)

    def printed(self, sites=None):
        """A decompiled function holding the call of the first scanned site; its printed lines."""
        if sites is None:
            sites = self.first_sites
        cf = FakeCfunc(["void f(void)", "{", "  g();", "}"], {sites[0].call_ea: ["s"]}, {"s": (2, 2)})
        flushed = self.log["hx_flushed"]
        self.assertEqual(self.E.STATE["hx"].func_printed(cf), 0)
        self.assertEqual(self.log["hx_flushed"], flushed)   # never clear_cached_cfuncs inside a decompiler callback
        return cf.text()[2]

    def scanned(self, create=0):
        p = self.scan(create)
        self.first_sites = self.E.STATE["sites"]
        return p

    def test_scan_stores_marker(self):
        il = sys.modules["cfiscope.idalayer"]
        for create in (0, 1):
            with self.subTest(create=create):
                self.scanned(create)
                marker = json.loads(self.w.netnodes[NODE][(72, "scan")])
                self.assertEqual(marker, {"v": 1, "layout": il.layout_id(), "create_functions": bool(create)})
                self.assertEqual(il.load_marker(), marker)

    def test_reopen_restores_pseudocode_comments(self):
        for fresh in (False, True):
            with self.subTest(fresh_module=fresh):
                self.setUp()
                p = self.reopen(self.scanned(), fresh_module=fresh)
                self.assertIsNone(self.E.STATE["sites"])
                self.assertIn("// CFIScope: ", self.printed())
                self.assertEqual(self.scans, [1])
                self.assertIn("// CFIScope: ", self.printed())      # restored once, not on every print
                self.assertEqual(self.scans, [1])
                self.assertEqual(sum("restored the scan saved in this database" in m for m in self.log["msgs"]), 1)
                self.unchanged()
                p.term()

    def test_no_marker_no_scan(self):
        # A database Scan never annotated: printing pseudocode scans nothing and adds nothing.
        fake_hexrays(self.log)
        p = self.E.PLUGIN_ENTRY()
        p.init()
        site = sys.modules["cfiscope.idalayer"].scan()[0][0]
        p = self.reopen(p)
        self.assertEqual(self.printed([site]), "  g();")
        self.assertEqual(self.printed([site]), "  g();")
        self.assertEqual((self.scans, self.E.STATE["sites"]), ([], None))
        self.assertEqual(self.loads, [1])
        self.unchanged()

    def test_skipped_while_analysis_runs(self):
        p = self.reopen(self.scanned())
        self.w.auto_ok = False
        self.assertEqual(self.printed(), "  g();")
        self.assertEqual(self.scans, [])
        self.w.auto_ok = True                       # analysis finished: the next print restores
        self.assertIn("// CFIScope: ", self.printed())
        self.assertEqual(self.scans, [1])
        self.unchanged()

    def test_analysis_turned_off_restores(self):
        p = self.reopen(self.scanned(), fresh_module=True)
        self.w.auto_ok, self.w.auto_enabled = False, False
        self.assertIn("// CFIScope: ", self.printed())
        self.unchanged()

    def test_lookup_restores(self):
        for action, at in (("TargetsAction", lambda s: s.call_ea), ("CallersAction", lambda s: s.targets[0])):
            with self.subTest(action=action):
                self.setUp()
                kw = sys.modules["ida_kernwin"]
                shown = []
                kw.Choose.Show = lambda chooser: shown.append(chooser.rows) or True
                self.addCleanup(delattr, kw.Choose, "Show")
                p = self.reopen(self.scanned(), fresh_module=True)
                kw.get_screen_ea = lambda: at(self.first_sites[0])
                box, scanned_in_box = [False], []           # a lookup the user asked for may show its wait box
                kw.show_wait_box = lambda t: box.__setitem__(0, True)
                kw.hide_wait_box = lambda: box.__setitem__(0, False)
                il = sys.modules["cfiscope.idalayer"]
                counted = il.scan
                il.scan = lambda: scanned_in_box.append(box[0]) or counted()
                flushed = self.log["hx_flushed"]
                self.assertEqual(getattr(self.E, action)().activate(None), 1)
                self.assertEqual(len(shown), 1)
                self.assertEqual(self.scans, [1])
                self.assertEqual(scanned_in_box, [True])    # the restore reuses the lookup's scan, run behind its box
                self.assertEqual(self.log["hx_flushed"], flushed + 1)  # decompiled before the lookup: printed again
                self.assertIn("// CFIScope: ", self.printed())
                self.assertEqual(self.scans, [1])
                self.unchanged()

    def test_lookup_hooks_a_decompiler_loaded_later(self):
        # Hex-Rays not there yet when the plugin started with the database: a lookup's restore installs the hook, as
        # Scan does, so the pseudocode comments still come back.
        p = self.scanned()
        sys.modules["ida_hexrays"] = None
        p = self.reopen(p, fresh_module=True)
        self.assertIsNone(self.E.STATE["hx"])
        fake_hexrays(self.log)
        kw = sys.modules["ida_kernwin"]
        kw.Choose.Show = lambda chooser: True
        self.addCleanup(delattr, kw.Choose, "Show")
        kw.get_screen_ea = lambda: self.first_sites[0].call_ea
        kw.show_wait_box = lambda t: None
        self.assertEqual(self.E.TargetsAction().activate(None), 1)
        self.assertEqual(self.log["hx_hooked"], 1)
        self.assertIn("// CFIScope: ", self.printed())
        self.assertEqual(self.scans, [1])
        self.unchanged()

    def test_lookup_restore_without_decompiler(self):
        # No decompiler for this database: the lookup still restores the scan, but does not claim comments are on.
        p = self.scanned()
        sys.modules["ida_hexrays"] = None
        p = self.reopen(p, fresh_module=True)
        kw = sys.modules["ida_kernwin"]
        kw.Choose.Show = lambda chooser: True
        self.addCleanup(delattr, kw.Choose, "Show")
        kw.get_screen_ea = lambda: self.first_sites[0].call_ea
        kw.show_wait_box = lambda t: None
        self.assertEqual(self.E.TargetsAction().activate(None), 1)
        self.assertIsNone(self.E.STATE["hx"])
        restored = [m for m in self.log["msgs"] if "restored the scan saved in this database" in m]
        self.assertEqual(len(restored), 1)
        self.assertNotIn("pseudocode comments", restored[0])
        self.assertIn("(%d checks, read-only)" % len(self.first_sites), restored[0])
        self.unchanged()

    def test_rebased_since_scan_not_restored(self):
        p = self.scanned()
        seg = self.w.segs[0]
        self.w.mem[seg.start_ea + 0x1000] = self.w.mem.pop(seg.start_ea)
        seg.start_ea += 0x1000; seg.end_ea += 0x1000
        p = self.reopen(p)
        moved = [types.SimpleNamespace(call_ea=self.first_sites[0].call_ea + 0x1000)]
        self.assertEqual(self.printed(moved), "  g();")
        self.assertEqual(self.printed(moved), "  g();")
        self.assertEqual(self.scans, [])
        self.assertEqual(self.loads, [1])
        self.assertEqual(sum("segments changed since" in m for m in self.log["msgs"]), 1)   # said once, not per print
        self.unchanged()

    def test_unreadable_marker_is_ignored(self):
        p = self.reopen(self.scanned())
        self.w.netnodes[NODE][(72, "scan")] = self.before[-1][NODE][(72, "scan")] = "{not json"
        self.assertEqual(self.printed(), "  g();")
        self.assertEqual(self.scans, [])
        self.assertEqual(self.log["msgs"], ["[CFIScope] %s loaded\n" % self.E.__version__])
        self.unchanged()

    def test_failing_restore_is_soft(self):
        # An error, or Cancel in IDAPython's own "Running Python script" box (KeyboardInterrupt), during the restore:
        # one message in the Output window (an interrupt: one line), the decompiler prints as usual, no second try.
        for error in (RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only."),
                      KeyboardInterrupt("User interrupted")):
            with self.subTest(error=type(error).__name__):
                self.setUp()
                p = self.reopen(self.scanned())
                def boom():
                    raise error
                sys.modules["cfiscope.idalayer"].scan = boom
                self.assertEqual(self.printed(), "  g();")
                self.assertEqual(self.printed(), "  g();")
                said = [m for m in self.log["msgs"] if "could not restore" in m]
                self.assertEqual(len(said), 1)
                if isinstance(error, KeyboardInterrupt):    # one plain line, as guarded() prints for an interrupt
                    self.assertEqual(said[0].count("\n"), 1)
                    self.assertNotIn("Traceback", said[0])
                else:                                       # one message, with the traceback to report
                    self.assertIn("Traceback", said[0])
                self.assertFalse(any("pseudocode comment failed" in m for m in self.log["msgs"]))
                self.unchanged()

    def test_remove_clears_marker(self):
        p = self.scanned()
        self.assertIn(NODE, self.w.netnodes)
        self.assertEqual(self.E.RemoveAction().activate(None), 1)
        self.assertNotIn(NODE, self.w.netnodes)
        p = self.reopen(p)
        self.assertEqual(self.printed(), "  g();")
        self.assertEqual(self.scans, [])

    def test_scan_without_sites_clears_marker(self):
        p = self.scanned()
        self.assertIn(NODE, self.w.netnodes)
        sys.modules["cfiscope.idalayer"].scan = lambda: ([], {"sites": 0})
        self.addCleanup(setattr, sys.modules["cfiscope.idalayer"], "scan", sys.modules["cfiscope.idalayer"].scan)
        self.E.STATE["sites"] = None
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        self.assertNotIn(NODE, self.w.netnodes)

    def test_rescan_defaults_to_the_last_answer(self):
        self.scanned(create=1)
        asked = []
        sys.modules["ida_kernwin"].ask_yn = lambda default, text: asked.append(default) or 1
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        self.assertEqual(asked, [1])            # ASKBTN_YES: the stored answer
        sys.modules["ida_kernwin"].ask_yn = lambda default, text: asked.append(default) or 0
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        self.assertEqual(asked, [1, 1])
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        self.assertEqual(asked, [1, 1, 0])      # after No, No is the default

    def test_term_forgets_the_database(self):
        # The plugin module may outlive the database (term, then init for the next one): nothing of the old scan stays.
        p = self.scanned()
        il = sys.modules["cfiscope.idalayer"]
        self.assertTrue(il.CALLS)
        p.term()
        self.assertEqual([self.E.STATE[k] for k in ("sites", "stats", "layout", "pseudo", "hx")], [None] * 5)
        self.assertEqual((il.CALLS, il.JT["table"], il.JT["entry_of"]), (set(), None, {}))


class JumpTableCfi(unittest.TestCase):
    """The plugin actions on the hand-assembled Linux 5.x jump-table CFI fixture."""

    def setUp(self):
        import json
        self.addCleanup(sys.modules.pop, "ida_hexrays", None)
        self.w, self.E, self.log = load_entry("aarch64-jtcfi", "ARM", ".elf")
        with open(os.path.join(HERE, "fixtures", "jtcfi_truth.json")) as fh:
            self.truth = json.load(fh)
        base = self.w.segs[0].start_ea
        self.shift = lambda a: base + int(a, 16) - int(self.truth["base"], 16)
        names = {self.shift(v): k for k, v in self.truth["symbols"].items() if not k.startswith("__")}
        self.w.nlist = sorted((self.shift(v), k) for k, v in self.truth["symbols"].items())
        sys.modules["ida_name"].get_ea_name = lambda ea: names.get(ea, "")

    def test_scan_lists_and_pseudocode(self):
        fake_hexrays(self.log)
        shown = []
        kw = sys.modules["ida_kernwin"]
        kw.Choose.Show = lambda chooser: shown.append((chooser.title, chooser.rows)) or True
        orig_init = kw.Choose.__init__
        kw.Choose.__init__ = lambda chooser, title, cols, flags=0: setattr(chooser, "title", title)
        self.addCleanup(setattr, kw.Choose, "__init__", orig_init)
        p = self.E.PLUGIN_ENTRY()
        p.init()
        self.assertEqual(self.E.ScanAction().activate(None), 1)
        sites = self.E.STATE["sites"]
        self.assertEqual(len(sites), 11)
        self.assertFalse(any("WARN" in m for m in self.log["msgs"]))
        hs = self.truth["sites"][0]
        call = self.shift(hs["call"])
        cf = FakeCfunc(["int f(void)", "{", "  return fp(file, 0);", "}"], {call: ["c"]}, {"c": (2, 2)})
        self.E.STATE["hx"].func_printed(cf)
        self.assertEqual(cf.text()[2], "  return fp(file, 0);\x01\x04  // CFIScope: 3 candidates of int (file*, int): "
                         "f_a, f_b, f_c\x02\x04")
        kw.get_screen_ea = lambda: call
        self.assertEqual(self.E.TargetsAction().activate(None), 1)
        title, rows = shown[-1]
        self.assertEqual(title, "jump-table CFI candidates for the call at 0x%X (int (file*, int))" % call)
        self.assertEqual([r[1] for r in rows], ["f_a", "f_b", "f_c"])
        kw.get_screen_ea = lambda: self.shift(self.truth["symbols"]["g_one"])
        self.assertEqual(self.E.CallersAction().activate(None), 1)
        self.assertEqual(shown[-1][0], "jump-table CFI callers: 1 call site(s) can reach g_one")
        kw.get_screen_ea = lambda: self.shift(self.truth["symbols"]["f_b"])
        self.assertEqual(self.E.CallersAction().activate(None), 1)
        title, rows = shown[-1]
        self.assertEqual(title, "jump-table CFI callers: 7 call site(s) can reach f_b (+1 type check(s) whose call "
                         "was not linked, listed last)")
        self.assertEqual(len(rows), 8)
        self.assertEqual(self.E.RemoveAction().activate(None), 1)
        self.assertEqual(self.w.cmts, {})
        p.term()


if __name__ == "__main__":
    unittest.main()
