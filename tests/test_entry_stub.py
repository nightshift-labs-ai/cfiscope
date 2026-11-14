"""Loads cfiscope_entry.py on fake ida_* modules: scan cache, rescan after a rebase, menus, right-click hooks and
the pseudocode comments. It proves the plugin wiring runs, not that IDA or Hex-Rays behave like the fakes."""
import importlib, json, os, sys, types, unittest
from unittest import mock
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
import test_plugin_stub as T  # noqa: E402


def load_entry(name="x86_64-kernel", proc="metapc", ext=".o"):
    w, _ = T.IdaLayer("test_flow").make(name, proc, ext=ext)
    kw, ia = sys.modules["ida_kernwin"], sys.modules["ida_idaapi"]
    log = {"msgs": [], "menu": [], "popup": [], "registered": [], "hooked": 0, "asked": [], "world": w, "keys": {},
           "shown": [], "pick": -1, "closed": [], "jumped": []}
    kw.msg = lambda t: log["msgs"].append(t)
    kw.show_wait_box = lambda t: None
    kw.hide_wait_box = lambda: None
    kw.warning = lambda t: log["msgs"].append("WARN " + t)
    kw.action_handler_t = type("action_handler_t", (), {})
    kw.AST_ENABLE_ALWAYS, kw.SETMENU_APP, kw.BWN_DISASM, kw.BWN_PSEUDOCODE = 1, 0, 27, 46
    kw.action_desc_t = lambda name, label, handler, key: log["keys"].__setitem__(name, key) or name
    # Choose(title, cols, flags=0); Show(modal=False): a modal chooser returns the picked row or NO_SELECTION (-1).
    kw.Choose.__init__ = lambda chooser, title, cols, flags=0: setattr(chooser, "title", title)
    def show(chooser, modal=False):
        log["shown"].append((chooser.title, modal, chooser))
        return log["pick"] if modal else 0
    kw.Choose.Show = show
    kw.close_chooser = lambda title: log["closed"].append(title) or True     # close_chooser(title: str) -> bool
    kw.jumpto = lambda ea: log["jumped"].append(ea) or True
    kw.get_screen_ea = lambda: 2**64 - 1
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


def funcs_at(w):
    """ida_funcs.get_func over w.funcs: a function starting at each address there (func_t-like), else None."""
    return lambda ea: types.SimpleNamespace(start_ea=ea, end_ea=ea + 4, tailqty=0) if ea in w.funcs else None


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
        sys.modules["ida_funcs"].get_func = funcs_at(w)
        sys.modules["ida_kernwin"].ask_yn = lambda default, text: 1
        sites = E.scan_or_warn()
        targets = sorted({t for s in sites for t in s.targets})
        w.flags = {targets[0]: 0x400}
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertIn("[CFIScope] functions created: %d; candidates skipped (data, or not in a code segment): 1\n"
                      % (len(targets) - 1), log["msgs"])
        self.assertEqual(w.funcs, set(targets[1:]))
        self.assertIn("(none to 1 candidate IDA holds as data or outside the code segments)", log["msgs"][0])

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
        with mock.patch.dict(os.environ, {"CFISCOPE_DEBUG": "1"}):     # the raw counts too
            self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual(log["asked"], [("Create functions at candidates IDA has not recognised", 0, 0)])
        self.assertEqual(w.funcs, set(targets[::2]))
        self.assertEqual(w.planned_funcs, set())
        self.assertTrue(w.crefs)
        self.assertTrue({t for _, t, _ in w.crefs} <= w.funcs)
        res = [m for m in log["msgs"] if '"xrefs_skipped_no_function"' in m]
        self.assertEqual(len(res), 1)
        self.assertNotIn('"xrefs_skipped_no_function": 0}', res[0])
        skipped = json.loads(res[0][len("[CFIScope] "):])["xrefs_skipped_no_function"]
        self.assertIn("(none to %d candidates that have no function: you answered No to creating functions)" % skipped,
                      log["msgs"][0])
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
        with mock.patch.dict(os.environ, {"CFISCOPE_DEBUG": "1"}):     # the raw counts too
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
        self.assertIn("%d cross-references added (%d of them data cross-references to candidates inside a function; "
                      "none to %d candidates that have no function: you answered No to creating functions)"
                      % (res["xrefs"] + res["data_xrefs_inside_function"], res["data_xrefs_inside_function"],
                         res["xrefs_skipped_no_function"]), log["msgs"][0])
        self.assertEqual(E.RemoveAction().activate(None), 1)
        self.assertIn("[CFIScope] xrefs removed: %d\n" % len(set(pairs) - {p for p in pairs if p[1] in none}),
                      log["msgs"])
        self.assertEqual((w.crefs, w.data_xrefs), (set(), set()))

    def test_yes_asked_before_xrefs(self):
        w, E, log = load_entry()
        w.funcs = set()
        sys.modules["ida_funcs"].get_func = funcs_at(w)
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
        sys.modules["ida_funcs"].get_func = funcs_at(w)
        self.answers(log, create=1)
        self.assertEqual(E.ScanAction().activate(None), 1)
        texts = [b for b in boxes if b]
        self.assertEqual(len(texts), 3)         # scan, annotate, and the call-site list's rows
        self.assertEqual(texts[2], "HIDECANCEL\nCFIScope: listing call sites")
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

    # Keys a CFIScope default must not take: IDA 9's published default shortcuts that use Alt or Ctrl+Alt
    # (docs.hex-rays.com/core/user-interface/reference/shortcuts, read 2026-11-13), Keypatch's Ctrl-Alt-K, and keys
    # that common Linux desktops keep for themselves (GNOME/Ubuntu: Ctrl-Alt-T terminal, Ctrl-Alt-L lock screen,
    # Ctrl-Alt-Delete log out, Alt-Shift-Tab windows). Also IDA 9.x's "Find a value" (Alt-Shift-V, release notes) and
    # the keys of the IDAPython examples in the SDK (print_registers.py Alt-Shift-C; Ctrl-Alt-C).
    TAKEN = ["Alt-Enter", "Alt-M", "Alt-T", "Alt-B", "Alt-I", "Alt-C", "Ctrl-Alt-B", "Ctrl-Alt-S", "Alt-R", "Alt-P",
             "Alt-Q", "Alt-A", "Alt-L", "Alt-X", "Ctrl-Shift-M", "Ctrl-Alt-K", "Ctrl-Alt-T", "Ctrl-Alt-L",
             "Ctrl-Alt-Delete", "Alt-Shift-Tab", "Alt-Shift-V", "Alt-Shift-C", "Ctrl-Alt-C", "Ctrl-Alt-Shift-M"]

    def test_default_hotkeys(self):
        _, E, log = load_entry()
        E.PLUGIN_ENTRY().init()
        self.assertEqual(log["keys"], {"cfiscope:scan": "Alt-Shift-K", "cfiscope:targets": "Alt-Shift-T",
                                       "cfiscope:callers": "Alt-Shift-X", "cfiscope:sites": "", "cfiscope:remove": ""})
        norm = lambda k: frozenset(k.lower().replace("+", "-").split("-"))
        taken = {norm(k) for k in self.TAKEN}
        for name, key in log["keys"].items():
            if key:
                self.assertNotIn(norm(key), taken, name)

    def test_menus_and_popup(self):
        _, E, log = load_entry()
        p = E.PLUGIN_ENTRY()
        self.assertEqual(p.init(), 1)
        self.assertEqual(len(log["registered"]), 5)
        self.assertIn(("Edit/Plugins/", "cfiscope:sites"), log["menu"])
        self.assertEqual(log["hooked"], 1)
        p.hooks.finish_populating_widget_popup(46, "popup")   # pseudocode view
        p.hooks.finish_populating_widget_popup(99, "popup")   # some other view: nothing added
        p.hooks.finish_populating_widget_popup(27, "popup")   # disassembly view
        self.assertEqual([(w, n, path) for w, n, path in log["popup"]],
                         [(v, n, "CFIScope/") for v in (46, 27)
                          for n in ("cfiscope:scan", "cfiscope:targets", "cfiscope:callers", "cfiscope:sites")])
        p.term()
        self.assertEqual(log["hooked"], 0)
        self.assertEqual(log["registered"], [])


class Line:
    def __init__(self, text):
        self.line = text


class FakeCfunc:
    """A decompiled function: pseudocode lines, an eamap (address -> statements) and each statement's (x, y)."""

    def __init__(self, lines, eamap, coords, entry_ea=None):
        self.sv, self.eamap, self.coords, self.entry_ea = [Line(t) for t in lines], eamap, coords, entry_ea

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
    # get_widget_vdui(f: TWidget) -> vdui_t, or None ("nullptr"): log["vdui"] is a vdui_t with .cfunc and .cpos.lnnum
    hx.get_widget_vdui = lambda widget: log.get("vdui")
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

    def lookup(self, action, lnnum, cf, screen_ea=None, widget=46):
        """Run a lookup action from a view (46 pseudocode, 27 disassembly) whose cursor is on pseudocode line lnnum."""
        if screen_ea is not None:
            sys.modules["ida_kernwin"].get_screen_ea = lambda: screen_ea
        self.log["vdui"] = types.SimpleNamespace(cfunc=cf, cpos=types.SimpleNamespace(lnnum=lnnum))
        return action().activate(types.SimpleNamespace(widget=widget))

    def test_targets_from_the_pseudocode_line(self):
        # The call(s) printed on the cursor's line decide, not get_screen_ea() and its nearest-check guess.
        _, sites = self.scanned_plugin()
        il, shown = self.E.idalayer, self.log["shown"]
        a, b, c = sorted(sites, key=lambda s: s.call_ea)[:3]
        lines = ["int f(void)", "{", "  x = fp(1);", "  y = gp(2) + hp(3);", "  return 0;", "}"]
        cf = FakeCfunc(lines, {a.call_ea: ["a"], c.call_ea: ["c"], b.call_ea: ["b"], 0x1234: ["o"]},
                       {"a": (6, 2), "b": (6, 3), "c": (15, 3), "o": (2, 4)}, entry_ea=0x5000)
        self.assertEqual(self.lookup(self.E.TargetsAction, 2, cf, screen_ea=b.call_ea), 1)
        self.assertEqual(shown[-1][:2], (il.targets_title(a), False))
        # Two calls on line 3: a modal picker lists them by address; the picked one's list opens.
        self.log["pick"] = 1
        self.assertEqual(self.lookup(self.E.TargetsAction, 3, cf, screen_ea=a.call_ea), 1)
        (ptitle, pmodal, picker), (title, modal, _) = shown[-2], shown[-1]
        self.assertEqual((ptitle, pmodal), ("CFIScope: 2 calls on this pseudocode line", True))
        self.assertEqual([picker.OnGetLine(n) for n in range(picker.OnGetSize())],
                         [["0x%x" % s.call_ea, il.describe(s)] for s in (b, c)])
        self.assertEqual((title, modal), (il.targets_title(c), False))
        # Esc in the picker (NO_SELECTION): no list and no warning (not even the "unexpected error" one).
        self.log["pick"], n = -1, len(shown)
        self.assertEqual(self.lookup(self.E.TargetsAction, 3, cf), 0)
        self.assertEqual(len(shown), n + 1)
        self.assertFalse(any(m.startswith("WARN") for m in self.log["msgs"]))
        # A line with no scanned call: a warning, no list from a neighbouring check.
        near = a.check_ea + 1
        self.assertIs(il.site_at(sites, near), a)                        # what the old guess would have used
        n = len(shown)
        self.assertEqual(self.lookup(self.E.TargetsAction, 4, cf, screen_ea=near), 0)
        self.assertEqual(len(shown), n)
        self.assertIn("WARN No kCFI call on this pseudocode line. Put the cursor on the line of the indirect call "
                      "(after Scan it has a CFIScope comment).", self.log["msgs"])

    def test_one_call_on_two_statements_of_a_line_needs_no_picker(self):
        # The decompiler can map one call address to two statements printed on the same line: still one call.
        _, sites = self.scanned_plugin()
        il, shown = self.E.idalayer, self.log["shown"]
        a = sorted(sites, key=lambda s: s.call_ea)[0]
        cf = FakeCfunc(["int f(void)", "{", "  return fp(1) + 1;", "}"], {a.call_ea: ["call", "ret"]},
                       {"call": (9, 2), "ret": (2, 2)}, entry_ea=0x5000)
        self.log["pick"] = 0
        self.assertEqual(self.lookup(self.E.TargetsAction, 2, cf), 1)
        self.assertEqual([(title, modal) for title, modal, _ in shown],          # Scan's call-site list, then this
                         [("CFIScope: 21 kCFI call sites", False), (il.targets_title(a), False)])

    def test_targets_by_exact_address_when_the_line_has_no_call(self):
        # A call Hex-Rays splits over several lines, the cursor on its argument line: no scanned call on that line,
        # so a call or check exactly at get_screen_ea() is used; a neighbouring one never is.
        _, sites = self.scanned_plugin()
        il, shown = self.E.idalayer, self.log["shown"]
        a, b = sorted(sites, key=lambda s: s.call_ea)[:2]
        lines = ["int f(void)", "{", "  x = fp(", "         1);", "  return 0;", "}"]
        cf = FakeCfunc(lines, {a.call_ea: ["a"], 0x1234: ["o"]}, {"a": (6, 2), "o": (9, 3)}, entry_ea=0x5000)
        self.assertEqual(self.lookup(self.E.TargetsAction, 3, cf, screen_ea=a.call_ea), 1)
        self.assertEqual(shown[-1][:2], (il.targets_title(a), False))
        self.assertEqual(self.lookup(self.E.TargetsAction, 4, cf, screen_ea=b.check_ea), 1)
        self.assertEqual(shown[-1][:2], (il.targets_title(b), False))
        self.assertFalse(any(m.startswith("WARN") for m in self.log["msgs"]))
        self.assertEqual([t for t, modal, _ in shown if modal], [])      # one site each: no picker
        near = a.check_ea + 1
        self.assertIs(il.site_at(sites, near), a)
        self.assertNotIn(near, {e for s in sites for e in (s.call_ea, s.check_ea)})
        n = len(shown)
        self.assertEqual(self.lookup(self.E.TargetsAction, 3, cf, screen_ea=near), 0)
        self.assertEqual(len(shown), n)
        self.assertEqual(sum(m.startswith("WARN No kCFI call on this pseudocode line") for m in self.log["msgs"]), 1)

    def test_callers_from_pseudocode_use_the_decompiled_function(self):
        _, sites = self.scanned_plugin()
        il, shown = self.E.idalayer, self.log["shown"]
        target = sorted(sites[0].targets)[0]
        cf = FakeCfunc(["void impl(void)", "{", "  g();", "}"], {}, {}, entry_ea=target)
        self.assertEqual(self.lookup(self.E.CallersAction, 2, cf, screen_ea=target + 8), 1)
        rows = il.callers_rows(sites, target)
        self.assertTrue(rows)
        self.assertEqual(shown[-1][:2], (il.callers_title(sites, target, rows), False))

    def test_lookups_fall_back_to_the_disassembly_path(self):
        # A disassembly view, a pseudocode view without a vdui_t, or no decompiler: get_screen_ea() as before.
        _, sites = self.scanned_plugin()
        il, shown = self.E.idalayer, self.log["shown"]
        a, b = sorted(sites, key=lambda s: s.call_ea)[:2]
        cf = FakeCfunc(["void f(void)", "{", "  fp(1);", "}"], {b.call_ea: ["b"]}, {"b": (2, 2)}, entry_ea=0x5000)
        self.assertEqual(self.lookup(self.E.TargetsAction, 2, cf, screen_ea=a.call_ea, widget=27), 1)
        self.assertEqual(shown[-1][0], il.targets_title(a))
        self.log["vdui"] = None
        self.assertEqual(self.E.TargetsAction().activate(types.SimpleNamespace(widget=46)), 1)
        self.assertEqual(shown[-1][0], il.targets_title(a))
        for gone in (lambda: fake_hexrays(self.log, available=False), lambda: sys.modules.__setitem__("ida_hexrays", None)):
            gone()
            self.log["vdui"] = types.SimpleNamespace(cfunc=cf, cpos=types.SimpleNamespace(lnnum=2))
            self.assertEqual(self.E.TargetsAction().activate(types.SimpleNamespace(widget=46)), 1)
            self.assertEqual(shown[-1][0], il.targets_title(a))
        self.assertFalse(any(m.startswith("WARN") for m in self.log["msgs"]))

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
                del shown[:]                                # the call-site list Scan opened before the reopen
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

    def test_decompiler_loaded_after_init_is_hooked(self):
        # Hex-Rays loads after this plugin (plugin load order): its plugin_loaded event, or ready_to_run, installs the
        # decompiler hook once, so the first decompile after reopening still restores. Without a decompiler: nothing.
        p = self.scanned()
        sys.modules["ida_hexrays"] = None
        p = self.reopen(p, fresh_module=True)
        self.assertIsNone(self.E.STATE["hx"])
        p.hooks.plugin_loaded(None)
        p.hooks.ready_to_run()
        self.assertIsNone(self.E.STATE["hx"])
        fake_hexrays(self.log, available=False)
        p.hooks.plugin_loaded(None)
        self.assertIsNone(self.E.STATE["hx"])
        fake_hexrays(self.log)
        p.hooks.plugin_loaded(None)
        p.hooks.ready_to_run()
        p.hooks.plugin_loaded(None)
        self.assertEqual(self.log["hx_hooked"], 1)          # hooked once
        self.assertIn("// CFIScope: ", self.printed())
        self.assertEqual(self.scans, [1])
        self.unchanged()
        p.term()
        self.assertEqual(self.log["hx_hooked"], 0)

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

    def test_pseudocode_lookups_after_reopen(self):
        """From a pseudocode window after reopening: the restore runs (one scan, cache flushed) before the decompiler
        view is fetched (ux177 + reopen177 merge; merge check s177 MINOR)."""
        for action in ("TargetsAction", "CallersAction"):
            with self.subTest(action=action):
                self.setUp()
                kw = sys.modules["ida_kernwin"]
                shown = []
                kw.Choose.Show = lambda chooser, modal=False: shown.append((chooser.title, modal)) or (1 if modal else True)
                self.addCleanup(delattr, kw.Choose, "Show")
                p = self.reopen(self.scanned(), fresh_module=True)
                del shown[:]                                # the call-site list Scan opened before the reopen
                kw.show_wait_box = lambda t: None
                kw.hide_wait_box = lambda: None
                kw.warning = lambda t: self.log["msgs"].append("WARN " + t)
                sites = self.first_sites
                a, b, c = sorted(sites, key=lambda s: s.call_ea)[:3]
                cf = FakeCfunc(["int f(void)", "{", "  x = fp(1);", "  y = gp(2) + hp(3);", "}"],
                                 {a.call_ea: ["a"], b.call_ea: ["b"], c.call_ea: ["c"]},
                                 {"a": (6, 2), "b": (6, 3), "c": (15, 3)}, entry_ea=sorted(a.targets)[0])
                hx = sys.modules["ida_hexrays"]
                flushed0 = self.log["hx_flushed"]
                seen_flush = []
                vdui = types.SimpleNamespace(cfunc=cf, cpos=types.SimpleNamespace(lnnum=3))
                hx.get_widget_vdui = lambda w: seen_flush.append(self.log["hx_flushed"]) or vdui
                kw.get_screen_ea = lambda: 2**64 - 1
                r = getattr(self.E, action)().activate(types.SimpleNamespace(widget=46))
                self.assertEqual(r, 1, self.log["msgs"])
                self.assertEqual(self.scans, [1])                 # one scan: the lookup's, reused by the restore
                self.assertEqual(self.log["hx_flushed"], flushed0 + 1)
                self.assertEqual(seen_flush, [flushed0 + 1])      # vdui fetched after the restore's flush
                il = self.E.idalayer
                if action == "TargetsAction":
                    self.assertEqual(shown[0], ("CFIScope: 2 calls on this pseudocode line", True))
                    self.assertEqual(shown[1][0], il.targets_title(c))
                else:
                    self.assertTrue(shown and not shown[-1][1])
                self.assertIn("// CFIScope: ", self.printed())
                self.assertEqual(self.scans, [1])
                self.unchanged()
                p.term()


class NoIndirectCall(unittest.TestCase):
    """ko189: Scan on a kCFI module that makes no indirect call (GKI zram.ko; here kcfi_quirks_a64.o, Clang kCFI, no
    blr) warned that the binary "may not be built with -fsanitize=kcfi"; it now says the code has no indirect call."""

    def test_scan_warning(self):
        w, E, log = load_entry("kcfi_quirks_a64", "ARM")
        self.assertEqual(E.ScanAction().activate(None), 1)
        warns = [m for m in log["msgs"] if m.startswith("WARN")]
        self.assertEqual(len(warns), 1)
        self.assertIn("makes no indirect call (no blr instruction)", warns[0])
        self.assertNotIn("GCC", warns[0])
        self.assertIn("[CFIScope] Scan: 0 kCFI call sites; the code makes no indirect call (no blr instruction).\n",
                      log["msgs"])

    def test_other_warning_unchanged(self):
        # An x86-64 object with no check: no blr count (aarch64 only), the old warning.
        w, E, log = load_entry("x86_64-kernel")
        for seg in w.segs:
            w.mem[seg.start_ea] = b"\x90" * len(w.mem[seg.start_ea])
        self.assertEqual(E.ScanAction().activate(None), 1)
        warns = [m for m in log["msgs"] if m.startswith("WARN")]
        self.assertEqual(len(warns), 1)
        self.assertIn("may not be built with -fsanitize=kcfi", warns[0])


NEXT = " Next: Alt-Shift-T on a call, Alt-Shift-X on a function.\n"


class ScanMessage(unittest.TestCase):
    """Review s193 (judge #3): Scan's result in the Output window was two raw JSON dicts ("disps": [-20], ...). Now it
    is one sentence; the dicts are printed only with the environment variable CFISCOPE_DEBUG=1."""

    def scan(self, name="x86_64-kernel", proc="metapc", create=1, debug=None, btf=True, ext=".o"):
        """Scan through ScanAction with "Create functions" answered create; the [CFIScope] lines it printed."""
        with mock.patch.dict(os.environ):
            os.environ.pop("CFISCOPE_DEBUG", None)
            if debug is not None:
                os.environ["CFISCOPE_DEBUG"] = debug
            w, E, log = load_entry(name, proc, ext=ext)
            if btf:
                w.input_path = os.path.join(HERE, "fixtures", name + ext)
            sys.modules["ida_kernwin"].ask_yn = lambda default, text: create
            self.assertEqual(E.ScanAction().activate(None), 1)
        return [m for m in log["msgs"] if m.startswith("[CFIScope]")]

    def test_one_sentence_on_both_fixtures(self):
        for name, proc in (("x86_64-kernel", "metapc"), ("aarch64-kernel", "ARM")):
            with self.subTest(name):
                msgs = self.scan(name, proc)
                self.assertFalse([m for m in msgs if "{" in m], msgs)            # no raw JSON
                self.assertEqual(msgs[0], "[CFIScope] Scan: 21 kCFI call sites (21 types, all named from the file's "
                                 "BTF); 21 with candidates (median 3); 21 comments and 76 cross-references added." + NEXT)

    def test_without_btf_and_after_no(self):
        # No BTF: hashes, not types. "No" with no function at any candidate: no xref, and the sentence says why.
        msgs = self.scan(create=0, btf=False)
        self.assertEqual(msgs[0], "[CFIScope] Scan: 21 kCFI call sites (21 type hashes); 21 with candidates (median 3); "
                         "21 comments and 0 cross-references added (none to 76 candidates that have no function: you "
                         "answered No to creating functions)." + NEXT)

    def test_json_only_with_debug_flag(self):
        for flag in ("", "0"):
            with self.subTest(flag=flag):
                self.assertFalse([m for m in self.scan(debug=flag) if "{" in m])
        msgs = self.scan(debug="1")
        self.assertTrue(msgs[0].startswith("[CFIScope] Scan: 21 kCFI call sites"), msgs)
        stats, res = (json.loads(m[len("[CFIScope] "):]) for m in msgs[1:3])
        self.assertEqual((stats["sites"], stats["disps"], res["comments"], res["xrefs"]), (21, [-20], 21, 76))

    def test_jump_table_cfi(self):
        # jtcfi_truth.json: 22 candidates over the 9 calls; 11 site comments + 1 on the CFI runtime's call (call_inline)
        msgs = self.scan("aarch64-jtcfi", "ARM", btf=False, ext=".elf")
        self.assertEqual(msgs[0], "[CFIScope] Scan: 11 jump-table CFI call sites (3 type ids); 10 with candidates "
                         "(median 3), 1 with none in this file; 12 comments and 22 cross-references added." + NEXT)

    def test_own_comment_kept(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("CFISCOPE_DEBUG", None)
            w, E, log = load_entry()
            sites = E.scan_or_warn()
            w.cmts[sites[0].call_ea] = "my note"
            sys.modules["ida_kernwin"].ask_yn = lambda default, text: 1
            self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertIn("; 20 comments and 76 cross-references added (1 comment of your own kept).", log["msgs"][0])
        self.assertEqual(w.cmts[sites[0].call_ea], "my note")

    def test_no_site(self):
        msgs = self.scan("kcfi_quirks_a64", "ARM", btf=False)
        self.assertEqual(msgs, ["[CFIScope] Scan: 0 kCFI call sites; the code makes no indirect call (no blr "
                                "instruction).\n"])


class SiteList(unittest.TestCase):
    """Judge s193 #2: after Scan the result was counts in the Output window only, and the call sites had to be found by
    hand. Scan now ends by opening a non-modal list of every call site (also the action CFIScope: List kCFI call sites
    and the right-click submenu): Address, Function+off, Member (mem194: the struct member the call loads its pointer
    from), Type, Candidates (a number column), First candidates."""

    def scan(self, name="x86_64-kernel", proc="metapc", create=1, ext=".o"):
        w, E, log = load_entry(name, proc, ext=ext)
        w.input_path = os.path.join(HERE, "fixtures", name + ext)      # the fixture's BTF names the types
        Entry.answers(self, log, create=create)
        return w, E, log

    def test_scan_opens_the_list(self):
        for name, proc in (("x86_64-kernel", "metapc"), ("aarch64-kernel", "ARM")):
            with self.subTest(name):
                w, E, log = self.scan(name, proc)
                self.assertEqual(E.ScanAction().activate(None), 1)
                title, modal, chooser = log["shown"][-1]
                self.assertEqual((title, modal), ("CFIScope: 21 kCFI call sites", False))     # non-modal
                il, C = E.idalayer, sys.modules["ida_kernwin"].Choose
                self.assertEqual([c[0] for c in il.SITES_COLUMNS],
                                 ["Address", "Function+off", "Member", "Type", "Candidates", "First candidates"])
                self.assertEqual(il.SITES_COLUMNS[4][1] & C.CHCOL_FORMAT, C.CHCOL_DEC)   # sorts as a number
                self.assertEqual(il.SITES_COLUMNS[0][1] & C.CHCOL_FORMAT, C.CHCOL_HEX)
                self.assertEqual(chooser.OnGetSize(), 21)
                sites = E.STATE["sites"]
                lines = [chooser.OnGetLine(n) for n in range(21)]
                self.assertEqual([int(l[0], 16) for l in lines], [s.call_ea or s.check_ea for s in sites])
                for (ea, place, member, typ, count, first), s in zip(lines, sites):
                    # the same names and count as the comment Scan wrote at the call (describe()); these calls go
                    # through a parameter, not a struct member: no member
                    self.assertEqual(member, "")
                    self.assertEqual(w.cmts[int(ea, 16)], "kCFI 0x%08X %s: %s candidate(s): %s"
                                     % (s.hash, typ, count, first))
                    self.assertEqual(int(count), len(s.targets))
                do_call_2 = [l for l in lines if l[3] == "long (short, int)"]
                self.assertEqual(len(do_call_2), 1)
                self.assertEqual(do_call_2[0][4], "3")
                n = lines.index(do_call_2[0])
                self.assertEqual(chooser.OnSelectLine(n), (C.NOTHING_CHANGED,))      # Enter jumps to the call
                self.assertEqual(log["jumped"], [int(do_call_2[0][0], 16)])

    def test_no_btf_shows_the_hash(self):
        w, E, log = self.scan()
        w.input_path = None
        self.assertEqual(E.ScanAction().activate(None), 1)
        chooser = log["shown"][-1][2]
        self.assertEqual([chooser.OnGetLine(n)[3] for n in range(3)],
                         ["hash 0x%08X" % s.hash for s in E.STATE["sites"][:3]])

    def test_order_as_in_the_comment(self):
        # A candidate whose address is taken comes first, in the list as in the comment.
        w, E, log = self.scan()
        sites = E.scan_or_warn()
        s = next(x for x in sites if len(x.targets) >= 2)
        w.drefs.add(s.targets[-1])
        sys.modules["ida_name"].get_ea_name = lambda ea: "f_%x" % ea
        self.assertEqual(E.ScanAction().activate(None), 1)
        sites = E.STATE["sites"]
        chooser = log["shown"][-1][2]
        k = [x.check_ea for x in sites].index(s.check_ea)
        first = chooser.OnGetLine(k)[5]
        self.assertTrue(first.startswith("f_%x, " % s.targets[-1]), first)
        self.assertTrue(w.cmts[sites[k].call_ea or sites[k].check_ea].endswith(": " + first))

    def test_action_before_scan_writes_nothing(self):
        w, E, log = self.scan()
        p = E.PLUGIN_ENTRY()
        p.init()
        self.assertEqual(E.SitesAction().activate(None), 1)
        self.assertEqual(log["shown"][-1][:2], ("CFIScope: 21 kCFI call sites", False))
        self.assertEqual(log["shown"][-1][2].OnGetSize(), 21)
        self.assertEqual((w.cmts, w.crefs, w.data_xrefs, log["asked"], w.netnodes), ({}, set(), set(), [], {}))
        p.term()

    def test_a_list_from_another_scan_is_closed(self):
        # IDA only brings an open chooser of the same title to the front, so a list of an older scan is closed first.
        w, E, log = self.scan()
        self.assertEqual(E.SitesAction().activate(None), 1)
        self.assertEqual(E.SitesAction().activate(None), 1)        # same scan: nothing closed
        self.assertEqual((len(log["shown"]), log["closed"]), (2, []))
        self.assertEqual(E.ScanAction().activate(None), 1)          # Scan scans again
        self.assertEqual(log["closed"], ["CFIScope: 21 kCFI call sites"])
        self.assertEqual(log["shown"][-1][2].OnGetSize(), 21)
        seg = w.segs[0]                                              # a rebase: the lookups scan again
        w.mem[seg.start_ea + 0x1000] = w.mem.pop(seg.start_ea)
        seg.start_ea += 0x1000; seg.end_ea += 0x1000
        self.assertEqual(E.SitesAction().activate(None), 1)
        self.assertEqual(len(log["closed"]), 2)
        self.assertEqual(int(log["shown"][-1][2].OnGetLine(0)[0], 16), E.STATE["sites"][0].call_ea)

    def test_no_site(self):
        w, E, log = load_entry("kcfi_quirks_a64", "ARM")
        self.assertEqual(E.SitesAction().activate(None), 0)
        self.assertIn("WARN No kCFI call site found. Scan kCFI calls says why.", log["msgs"])
        self.assertEqual(E.ScanAction().activate(None), 1)
        self.assertEqual(log["shown"], [])


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
        title, rows = shown[0]                  # the call-site list Scan opens
        self.assertEqual((title, len(rows)), ("CFIScope: 11 jump-table CFI call sites", 11))
        self.assertIn((call, "0x%x" % call, "", "int (file*, int)", 3, "f_a, f_b, f_c"), rows)   # no member: not kCFI
        slow = next(r for r in rows if r[0] == self.shift(self.truth["sites"][5]["call"]))
        self.assertEqual(slow[4], 0)
        self.assertTrue(slow[5].startswith("no candidate in this image ("), slow)
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
