"""CFIScope: resolve Linux/Android kCFI indirect calls in IDA (and the aarch64 jump-table CFI of Linux 5.x).

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

import ida_auto
import ida_ida
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
    # HIDECANCEL: the scan never polls user_cancelled(), so a Cancel button would do nothing (kernwin.hpp).
    ida_kernwin.show_wait_box("HIDECANCEL\nCFIScope: scanning code segments")
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


def analysis_finished():
    """True when IDA's auto-analysis is done, or the user chose to scan anyway; False to stop (Cancel).
    A scan during analysis sees unexplored bytes as code and misses the data xrefs that rank candidates."""
    if ida_auto.auto_is_ok() or not ida_ida.inf_is_auto_enabled():   # analysis turned off: its queues never empty
        return True
    answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_YES, "IDA is still analysing this database.\n"
                                "Wait for auto-analysis to finish before scanning? (No: scan now)")
    if answer == ida_kernwin.ASKBTN_NO:
        return True
    if answer != ida_kernwin.ASKBTN_YES:
        return False
    ida_kernwin.show_wait_box("CFIScope: waiting for IDA's auto-analysis")
    try:
        return bool(ida_auto.auto_wait())   # False if the user clicked Cancel (auto.hpp)
    finally:
        ida_kernwin.hide_wait_box()


def report(text):
    ida_kernwin.msg("[CFIScope] %s\n" % text)



ISSUES_URL = "https://github.com/nightshift-labs-ai/cfiscope/issues"


def guarded(activate):
    """Any unexpected error becomes one warning plus the traceback in the Output window; an interrupt (Cancel in
    IDAPython's own wait box, shown when no plugin wait box is up) becomes one line there."""
    def wrapper(self, ctx):
        try:
            return activate(self, ctx)
        except KeyboardInterrupt:  # IDAPython's own "Running Python script" box was cancelled
            ida_kernwin.msg("[CFIScope] interrupted: the action stopped part-way; run it again (Scan kCFI calls or Remove annotations) to finish\n")
            return 0
        except Exception:  # noqa: BLE001  (last line of defence inside IDA)
            ida_kernwin.msg("[CFIScope] unexpected error:\n%s\n" % traceback.format_exc())
            ida_kernwin.warning("CFIScope: unexpected error, details are in the Output window.\nPlease report it: %s" % ISSUES_URL)
            return 0
    return wrapper


def sites_by_line(cfunc, by_ea):
    """{pseudocode line index: [site, ...]}: the lines that print the statements of each site's call (by_ea: call
    address, or the check's when no call was linked, -> site)."""
    eamap = cfunc.get_eamap()
    lines = {}
    for ea in eamap:
        site = by_ea.get(ea)
        if site is None:
            continue
        for insn in eamap[ea]:
            coords = cfunc.find_item_coords(insn)  # (x, y), the order of the stub's two-argument form
            if isinstance(coords, (tuple, list)) and len(coords) == 2 and isinstance(coords[1], int):
                found = lines.setdefault(coords[1], [])
                if all(s is not site for s in found):
                    found.append(site)
    return lines


def pseudocode_lines(cfunc):
    """{line index: [comment, ...]} for the call sites Scan annotated in this function. Never scans."""
    by_ea = STATE["pseudo"]
    if not by_ea or STATE["layout"] != idalayer.layout():
        return {}
    lines = {}
    for y, found in sites_by_line(cfunc, by_ea).items():
        texts = lines[y] = []
        for site in found:
            text = idalayer.pseudocode_text(site)
            if text not in texts:
                texts.append(text)
    return lines


def pseudocode_view(ctx):
    """The decompiler's view (vdui_t) when the action runs in a pseudocode window, else None: then the lookups use
    get_screen_ea() as in disassembly (also without the decompiler)."""
    widget = getattr(ctx, "widget", None)
    if widget is None or ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
        return None
    try:
        import ida_hexrays
    except ImportError:
        return None
    if not ida_hexrays.init_hexrays_plugin():
        return None
    vu = ida_hexrays.get_widget_vdui(widget)
    return vu if vu is not None and vu.cfunc is not None else None


def sites_on_line(vu, sites):
    """The scanned sites whose call the decompiler printed on the cursor's line, by address: the line that carries
    their pseudocode comment."""
    by_ea = {s.call_ea or s.check_ea: s for s in sites}
    found = sites_by_line(vu.cfunc, by_ea).get(vu.cpos.lnnum, [])
    return sorted(found, key=lambda s: s.call_ea or s.check_ea)


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
        if not analysis_finished():
            return 0
        STATE["sites"] = STATE["pseudo"] = None
        sites = scan_or_warn()
        if sites is None:
            return 0
        # Asked before any xref is added: a call xref makes IDA create a function at its target (xref.hpp, fl_CN),
        # so after "No" only a candidate at the start of a function IDA has gets one; a candidate inside a function
        # gets a data xref (dr_O) instead, and one with no function none.
        answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, "Create functions at candidates IDA has not recognised?") \
            if sites else ida_kernwin.ASKBTN_NO
        if answer == ida_kernwin.ASKBTN_CANCEL:
            return 0
        create = answer == ida_kernwin.ASKBTN_YES
        made = None
        ida_kernwin.show_wait_box("HIDECANCEL\nCFIScope: annotating call sites")
        try:
            res = idalayer.annotate(sites, create_functions=create)
            if create:
                made = idalayer.define_functions(sites)
        finally:
            ida_kernwin.hide_wait_box()
        report(json.dumps(STATE["stats"]))
        report(json.dumps(res))
        if not sites:
            ida_kernwin.warning("No kCFI checks found, and no aarch64 jump-table CFI either. This binary may not be "
                                "built with -fsanitize=kcfi (Linux 6.1+ CONFIG_CFI_CLANG) or with the older "
                                "jump-table CFI of Linux 5.x as in Android GKI 5.15 (aarch64 only); GCC kernels "
                                "are not supported.")
            return 1
        STATE["pseudo"] = {s.call_ea or s.check_ea: s for s in sites}
        if hook_pseudocode():
            flush_pseudocode()
            report("pseudocode comments on: functions decompiled from now on show the candidates at their call sites")
        if made is not None:
            report("functions created: %(functions_created)d; candidates skipped (data, or not in a code segment): "
                   "%(skipped_not_code)d" % made)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class TargetsAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        sites = scan_or_warn()
        if sites is None:
            return 0
        vu = pseudocode_view(ctx)
        if vu is None:
            site = idalayer.site_at(sites, ida_kernwin.get_screen_ea())
            if site is None:
                ida_kernwin.warning("No %s check at or near the cursor." % idalayer.scheme_name(sites))
                return 0
        else:
            # Pseudocode: the call(s) on the cursor's line, never a neighbouring check's.
            found = sites_on_line(vu, sites)
            if not found:
                ida_kernwin.warning("No %s call on this pseudocode line. Put the cursor on the line of the indirect "
                                    "call (after Scan it has a CFIScope comment)." % idalayer.scheme_name(sites))
                return 0
            site = found[0] if len(found) == 1 else idalayer.pick_site(found)
            if site is None:
                return 0
        idalayer.Chooser(idalayer.targets_title(site), idalayer.targets_rows(site)).Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class CallersAction(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        sites = scan_or_warn()
        if sites is None:
            return 0
        vu = pseudocode_view(ctx)
        ea = vu.cfunc.entry_ea if vu is not None else ida_kernwin.get_screen_ea()   # pseudocode: the decompiled function
        rows = idalayer.callers_rows(sites, ea)
        if not rows:
            ida_kernwin.warning("No %s call site can reach this function." % idalayer.scheme_name(sites))
            return 0
        idalayer.Chooser(idalayer.callers_title(sites, ea, rows), rows).Show()
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


# Default keys: none of IDA 9's published defaults, and not Ctrl-Alt-T (a terminal on GNOME/Ubuntu, so IDA never sees
# it) or Ctrl-Alt-K (Keypatch). Options > Shortcuts rebinds them.
ACTIONS = [
    ("cfiscope:scan", "CFIScope: Scan kCFI calls", ScanAction, "Alt-Shift-K"),
    ("cfiscope:targets", "CFIScope: Candidates for this call", TargetsAction, "Alt-Shift-T"),
    ("cfiscope:callers", "CFIScope: Callers of this function", CallersAction, "Alt-Shift-X"),
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
