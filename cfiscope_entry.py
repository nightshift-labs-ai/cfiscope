"""CFIScope: resolve Linux/Android kCFI indirect calls in IDA.

Edit > Plugins > CFIScope actions:
  * Scan kCFI calls: comment every check, add xrefs for short candidate lists.
  * Candidates for this call / Callers of this function: jump lists.
  * Remove annotations.
With the Hex-Rays decompiler, scanned call sites also get a comment in pseudocode (display only).
"""
import traceback
import json
import os
import sys

import ida_idaapi
import ida_kernwin
import ida_lines

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cfiscope import __version__, idalayer  # noqa: E402

# pseudo: call address -> site, set by Scan and cleared by Remove annotations; hx: the decompiler hook.
STATE = {"sites": None, "stats": None, "layout": None, "pseudo": None, "hx": None, "hx_error": False}


def ensure_scan():
    if STATE["sites"] is not None and STATE["layout"] != idalayer.layout():
        report("segments changed since the last scan (rebase?): scanning again")
        STATE["sites"] = None
        STATE["pseudo"] = None
    if STATE["sites"] is None:
        STATE["layout"] = idalayer.layout()
        STATE["sites"], STATE["stats"] = idalayer.scan()
    return STATE["sites"]


def scan_or_warn():
    """Run the scan once behind a wait box, or show the plugin's own warning (unsupported database) and return None."""
    if STATE["sites"] is not None and STATE["layout"] == idalayer.layout():
        return STATE["sites"]
    problem = None
    sites = None
    ida_kernwin.show_wait_box("CFIScope: scanning code segments")
    try:
        sites = ensure_scan()
    except RuntimeError as e:
        problem = str(e)
    finally:
        ida_kernwin.hide_wait_box()
    if problem:
        ida_kernwin.warning(problem)
        return None
    return sites


def report(text):
    ida_kernwin.msg("[CFIScope] %s\n" % text)



ISSUES_URL = "https://github.com/nightshift-labs-ai/cfiscope/issues"


def guarded(activate):
    """Any unexpected error becomes one warning plus the traceback in the Output window."""
    def wrapper(self, ctx):
        try:
            return activate(self, ctx)
        except Exception:  # noqa: BLE001  (last line of defence inside IDA)
            ida_kernwin.msg("[CFIScope] unexpected error:\n%s\n" % traceback.format_exc())
            ida_kernwin.warning("CFIScope: unexpected error, details are in the Output window.\nPlease report it: %s" % ISSUES_URL)
            return 0
    return wrapper


def pseudocode_lines(cfunc):
    """{line index: [comment, ...]} for the call sites Scan annotated in this function. Never scans."""
    by_ea = STATE["pseudo"]
    if not by_ea or STATE["layout"] != idalayer.layout():
        return {}
    eamap = cfunc.get_eamap()
    lines = {}
    for ea in eamap:
        site = by_ea.get(ea)
        if site is None:
            continue
        text = idalayer.pseudocode_text(site)
        for insn in eamap[ea]:
            coords = cfunc.find_item_coords(insn)  # (x, y), the order of the stub's two-argument form
            if isinstance(coords, (tuple, list)) and len(coords) == 2 and isinstance(coords[1], int):
                texts = lines.setdefault(coords[1], [])
                if text not in texts:
                    texts.append(text)
    return lines


def add_pseudocode_comments(cfunc):
    """Display-only text appended to the printed lines; nothing is stored in the database."""
    lines = pseudocode_lines(cfunc)
    if not lines:
        return 0
    sv = cfunc.get_pseudocode()
    done = 0
    for y, texts in sorted(lines.items()):
        if 0 <= y < len(sv):
            sv[y].line += ida_lines.COLSTR("  // " + "; ".join(texts), ida_lines.SCOLOR_AUTOCMT)
            done += 1
    return done


def hook_pseudocode():
    """Install the decompiler hook once, if Hex-Rays is there. Without it CFIScope works as before."""
    if STATE["hx"] is not None:
        return True
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return False

        class PseudocodeHooks(ida_hexrays.Hexrays_Hooks):
            def func_printed(self, cfunc):
                try:
                    add_pseudocode_comments(cfunc)
                except Exception:  # noqa: BLE001  a hook must never break the decompiler
                    try:
                        if not STATE["hx_error"]:
                            STATE["hx_error"] = True
                            report("pseudocode comment failed (shown once):\n%s" % traceback.format_exc())
                    except Exception:  # noqa: BLE001
                        pass
                return 0

        hooks = PseudocodeHooks()
        if hooks.hook():
            STATE["hx"] = hooks
    except Exception:  # noqa: BLE001  no decompiler, or an unexpected one: carry on without the hook
        STATE["hx"] = None
    return STATE["hx"] is not None


def unhook_pseudocode():
    hooks, STATE["hx"] = STATE["hx"], None
    if hooks is not None:
        try:
            hooks.unhook()
        except Exception:  # noqa: BLE001
            traceback.print_exc()


def flush_pseudocode():
    """Drop cached decompilations so the next decompile prints (or stops printing) our comments."""
    if STATE["hx"] is None:
        return
    try:
        import ida_hexrays
        ida_hexrays.clear_cached_cfuncs()
    except Exception:  # noqa: BLE001
        pass


class ScanAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        problem = None
        ida_kernwin.show_wait_box("CFIScope: scanning code segments")
        try:
            STATE["sites"] = STATE["pseudo"] = None
            sites = ensure_scan()
            res = idalayer.annotate(sites)
        except RuntimeError as e:
            problem = str(e)
        finally:
            ida_kernwin.hide_wait_box()
        if problem:
            ida_kernwin.warning(problem)
            return 0
        report(json.dumps(STATE["stats"]))
        report(json.dumps(res))
        if not sites:
            ida_kernwin.warning("No kCFI checks found. This binary may not be built with -fsanitize=kcfi "
                                "(Linux 6.1+ CONFIG_CFI_CLANG); GCC kernels and the older jump-table CFI "
                                "of Linux 5.x Clang builds are not supported.")
            return 1
        STATE["pseudo"] = {s.call_ea or s.check_ea: s for s in sites}
        if hook_pseudocode():
            flush_pseudocode()
            report("pseudocode comments on: functions decompiled from now on show the candidates at their call sites")
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                              "Create functions at candidates IDA has not recognised?") == ida_kernwin.ASKBTN_YES:
            report("functions created: %d" % idalayer.define_functions(sites))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class TargetsAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        sites = scan_or_warn()
        if sites is None:
            return 0
        site = idalayer.site_at(sites, ida_kernwin.get_screen_ea())
        if site is None:
            ida_kernwin.warning("No kCFI check at or near the cursor.")
            return 0
        idalayer.Chooser("kCFI candidates for the call at 0x%X (hash 0x%08X)" % (site.call_ea or site.check_ea, site.hash),
                         idalayer.targets_rows(site)).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CallersAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        sites = scan_or_warn()
        if sites is None:
            return 0
        ea = ida_kernwin.get_screen_ea()
        rows = idalayer.callers_rows(sites, ea)
        if not rows:
            ida_kernwin.warning("No kCFI call site can reach this function.")
            return 0
        idalayer.Chooser("kCFI callers of %s" % idalayer.target_name(ea), rows).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class RemoveAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        sites = scan_or_warn()
        if sites is None:
            return 0
        report("xrefs removed: %d" % idalayer.remove_annotations(sites))
        STATE["pseudo"] = None
        flush_pseudocode()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("cfiscope:scan", "CFIScope: Scan kCFI calls", ScanAction, "Ctrl-Alt-K"),
    ("cfiscope:targets", "CFIScope: Candidates for this call", TargetsAction, "Ctrl-Alt-T"),
    ("cfiscope:callers", "CFIScope: Callers of this function", CallersAction, "Ctrl-Alt-C"),
    ("cfiscope:remove", "CFIScope: Remove annotations", RemoveAction, ""),
]


class PopupHooks(ida_kernwin.UI_Hooks):
    """Adds the three lookups to the right-click menu of disassembly and pseudocode views."""

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None):
        try:
            if ida_kernwin.get_widget_type(widget) in (ida_kernwin.BWN_DISASM, ida_kernwin.BWN_PSEUDOCODE):
                for name, _, _, _ in ACTIONS[:3]:
                    ida_kernwin.attach_action_to_popup(widget, popup_handle, name, "CFIScope/")
        except Exception:  # a context menu must never break because of this plugin
            traceback.print_exc()


class CFIScopePlugin(ida_idaapi.plugin_t):
    flags = 0
    comment = "Resolve kCFI indirect calls from their type hashes"
    help = comment
    wanted_name = "CFIScope"
    wanted_hotkey = ""

    def init(self):
        for name, label, handler, key in ACTIONS:
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, handler(), key))
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
        self.hooks = PopupHooks()
        self.hooks.hook()
        hook_pseudocode()
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("cfiscope:scan")

    def term(self):
        if getattr(self, "hooks", None) is not None:
            self.hooks.unhook()
            self.hooks = None
        unhook_pseudocode()
        for name, _, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return CFIScopePlugin()
