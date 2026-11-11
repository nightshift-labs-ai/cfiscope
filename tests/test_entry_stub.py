"""Loads cfiscope_entry.py on fake ida_* modules: scan cache, rescan after a rebase, menus and right-click hooks.
It proves the plugin wiring runs, not that IDA behaves like the fakes."""
import importlib, os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
import test_plugin_stub as T  # noqa: E402


def load_entry():
    w, _ = T.IdaLayer("test_flow").make("x86_64-kernel", "metapc")
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


if __name__ == "__main__":
    unittest.main()
