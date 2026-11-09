"""CFIScope: resolve Linux/Android kCFI indirect calls in IDA.

Edit > Plugins > CFIScope actions:
  * Scan kCFI calls: comment every check, add xrefs for short candidate lists.
  * Candidates for this call / Callers of this function: jump lists.
  * Remove annotations.
"""
import json
import os
import sys

import ida_idaapi
import ida_kernwin

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from cfiscope import __version__, idalayer  # noqa: E402

STATE = {"sites": None, "stats": None}


def ensure_scan():
    if STATE["sites"] is None:
        STATE["sites"], STATE["stats"] = idalayer.scan()
    return STATE["sites"]


def report(text):
    ida_kernwin.msg("[CFIScope] %s\n" % text)


class ScanAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ida_kernwin.show_wait_box("CFIScope: scanning code segments")
        try:
            STATE["sites"] = None
            sites = ensure_scan()
            res = idalayer.annotate(sites)
        except RuntimeError as e:
            ida_kernwin.warning(str(e))
            return 0
        finally:
            ida_kernwin.hide_wait_box()
        report(json.dumps(STATE["stats"]))
        report(json.dumps(res))
        if not sites:
            ida_kernwin.warning("No kCFI checks found. This binary may not be built with -fsanitize=kcfi.")
            return 1
        if ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                              "Create functions at candidates IDA has not recognised?") == ida_kernwin.ASKBTN_YES:
            report("functions created: %d" % idalayer.define_functions(sites))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class TargetsAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        sites = ensure_scan()
        site = idalayer.site_at(sites, ida_kernwin.get_screen_ea())
        if site is None:
            ida_kernwin.warning("No kCFI check at or near the cursor.")
            return 0
        idalayer.Chooser("kCFI 0x%08X candidates" % site.hash, idalayer.targets_rows(site)).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CallersAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        sites = ensure_scan()
        ea = ida_kernwin.get_screen_ea()
        rows = idalayer.callers_rows(sites, ea)
        if not rows:
            ida_kernwin.warning("No kCFI call site can reach this function.")
            return 0
        idalayer.Chooser("kCFI callers", rows).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class RemoveAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        report("xrefs removed: %d" % idalayer.remove_annotations(ensure_scan()))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("cfiscope:scan", "CFIScope: Scan kCFI calls", ScanAction, "Ctrl-Alt-K"),
    ("cfiscope:targets", "CFIScope: Candidates for this call", TargetsAction, "Ctrl-Alt-T"),
    ("cfiscope:callers", "CFIScope: Callers of this function", CallersAction, "Ctrl-Alt-C"),
    ("cfiscope:remove", "CFIScope: Remove annotations", RemoveAction, ""),
]


class CFIScopePlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "Resolve kCFI indirect calls from their type hashes"
    help = comment
    wanted_name = "CFIScope"
    wanted_hotkey = ""

    def init(self):
        for name, label, handler, key in ACTIONS:
            ida_kernwin.register_action(ida_kernwin.action_desc_t(name, label, handler(), key))
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", name, ida_kernwin.SETMENU_APP)
        report("%s loaded" % __version__)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.process_ui_action("cfiscope:scan")

    def term(self):
        for name, _, _, _ in ACTIONS:
            ida_kernwin.unregister_action(name)


def PLUGIN_ENTRY():
    return CFIScopePlugin()
