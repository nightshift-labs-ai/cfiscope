"""Loads cfiscope_entry.py on fake ida_* modules: scan cache, rescan after a rebase, menus, right-click hooks and
the pseudocode comments. It proves the plugin wiring runs, not that IDA or Hex-Rays behave like the fakes."""
import importlib, os, sys, types, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
import test_plugin_stub as T  # noqa: E402


def load_entry(name="x86_64-kernel", proc="metapc", ext=".o"):
    w, _ = T.IdaLayer("test_flow").make(name, proc, ext=ext)
    kw, ia = sys.modules["ida_kernwin"], sys.modules["ida_idaapi"]
    log = {"msgs": [], "menu": [], "popup": [], "registered": [], "hooked": 0}
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
    kw.ask_yn, kw.ASKBTN_NO, kw.ASKBTN_YES = (lambda default, text: 0), 0, 1
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
        self.assertEqual(len(sites), 7)
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
        self.assertEqual(shown[-1][0], "jump-table CFI callers of g_one")
        self.assertEqual(self.E.RemoveAction().activate(None), 1)
        self.assertEqual(self.w.cmts, {})
        p.term()


if __name__ == "__main__":
    unittest.main()
