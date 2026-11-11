"""CFIScope: resolve Linux/Android kCFI indirect calls in IDA.

Edit > Plugins > CFIScope actions:
  * Scan kCFI calls: comment every check, add xrefs for short candidate lists.
  * Candidates for this call / Callers of this function: jump lists.
  * Remove annotations.
"""
import traceback
import json
import os
import sys

import ida_idaapi
import ida_kernwin

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cfiscope import __version__, idalayer  # noqa: E402

STATE = {"sites": None, "stats": None, "layout": None}


def ensure_scan():
    if STATE["sites"] is not None and STATE["layout"] != idalayer.layout():
        report("segments changed since the last scan (rebase?): scanning again")
        STATE["sites"] = None
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

class ScanAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        problem = None
        ida_kernwin.show_wait_box("CFIScope: scanning code segments")
        try:
            STATE["sites"] = None
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
        report("xrefs removal attempted: %d" % idalayer.remove_annotations(sites))
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
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("cfiscope:scan")

    def term(self):
        if getattr(self, "hooks", None) is not None:
            self.hooks.unhook()
            self.hooks = None
        for name, _, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return CFIScopePlugin()
