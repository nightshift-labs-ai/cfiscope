"""IDA side of CFIScope: read code segments, write comments and cross-references."""
import os

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_segment
import ida_xref

from . import core

COMMENT_TAG = "kCFI"
JT_COMMENT_TAG = "jtCFI"      # Linux 5.x jump-table CFI sites
OWN_TAGS = (COMMENT_TAG, JT_COMMENT_TAG)
DEFAULT_XREF_LIMIT = 16
BADADDR = ida_idaapi.BADADDR


def current_arch():
    proc = ida_ida.inf_get_procname().lower()
    if not ida_ida.inf_is_64bit():
        return None
    if proc in ("metapc", "pc"):
        return "x86_64"
    if proc.startswith("arm"):
        return "aarch64"
    return None


def code_ranges():
    """Executable or code segments; every segment if a raw load set neither."""
    segments = [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())]
    segments = [seg for seg in segments if seg is not None]
    chosen = [seg for seg in segments
              if seg.perm & ida_segment.SEGPERM_EXEC or seg.type == ida_segment.SEG_CODE]
    out = []
    for seg in chosen or segments:
        data = ida_bytes.get_bytes(seg.start_ea, seg.end_ea - seg.start_ea)
        if data:
            out.append((seg.start_ea, data))
    return out


def layout():
    """Segment bounds; if they change (for example after Edit > Segments > Rebase program), cached sites are stale."""
    segments = [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())]
    return tuple((seg.start_ea, seg.end_ea) for seg in segments if seg is not None)


def typeid_names():
    """(address, name) of the __typeid_<type>_global_addr names (kallsyms keeps them).

    IDA keeps one name per address, and each of these shares its address with a `foo.cfi_jt` entry name, so the
    database may have lost them: the input file's own ELF symbol table, if it is still there, is read as well.
    Names from the file come without an address (the database may be rebased); they are matched by type id."""
    out = []
    for i in range(ida_name.get_nlist_size()):
        name = ida_name.get_nlist_name(i)
        if name and name.startswith("__typeid_"):
            out.append((ida_name.get_nlist_ea(i), name))
    try:
        from . import cli
        path = ida_nalt.get_input_file_path()
        if path and os.path.isfile(path):
            with open(path, "rb") as fh:
                data = fh.read()
            if data[:4] == b"\x7fELF":
                every = []
                cli.load_elf(data, every)
                out.extend((None, name) for _, name in every if name.startswith("__typeid_"))
    except Exception:  # noqa: BLE001  names are a bonus: an unreadable input file only means fewer of them
        pass
    return out


def scan():
    arch = current_arch()
    if arch is None:
        raise RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only.")
    sites, stats = core.resolve(code_ranges(), arch)
    if stats.get("scheme") == "jump-table CFI":
        stats = dict(stats, named_types=core.name_jt_types(sites, typeid_names()))
    return sites, stats


def scheme_name(sites):
    """'kCFI', or 'jump-table CFI' for a Linux 5.x kernel."""
    return "jump-table CFI" if sites and sites[0].kind != "kcfi" else "kCFI"


def is_address_taken(ea):
    return ida_xref.get_first_dref_to(ea) != BADADDR


def target_name(ea):
    """Name of the address itself; if it has none, the containing function plus an offset."""
    name = ida_name.get_ea_name(ea)
    if name:
        return name
    func = ida_funcs.get_func(ea)
    if func is not None:
        fname = ida_funcs.get_func_name(func.start_ea)
        if fname:
            return fname if func.start_ea == ea else "%s+0x%x" % (fname, ea - func.start_ea)
    return "0x%x" % ea


def ranked(site):
    """Address-taken candidates first: only they can really be stored in a pointer."""
    return sorted(site.targets, key=lambda t: (not is_address_taken(t), t))


def _jt_describe(site, targets):
    label = core.type_label(site) or "type unknown"
    if not targets:
        if site.kind == "slowpath":
            why = site.note or "only __cfi_slowpath checks this call: its targets can only be in modules"
            return "%s %s: no candidate in this image (%s)" % (JT_COMMENT_TAG, label, why)
        return "%s %s: candidates unknown (the check's jump-table range was not found)" % (JT_COMMENT_TAG, label)
    names = ", ".join(target_name(t) for t in targets[:6])
    if len(targets) > 6:
        names += ", +%d more" % (len(targets) - 6)
    return "%s %s: %d candidate(s): %s" % (JT_COMMENT_TAG, label, len(targets), names)


def describe(site):
    targets = ranked(site)
    if getattr(site, "kind", "kcfi") != "kcfi":
        return _jt_describe(site, targets)
    if not targets:
        return "%s 0x%08X: no implementation in this image" % (COMMENT_TAG, site.hash)
    names = ", ".join(target_name(t) for t in targets[:6])
    more = len(targets) - 6
    if more > 0:
        names += ", +%d more" % more
    return "%s 0x%08X: %d candidate(s): %s" % (COMMENT_TAG, site.hash, len(targets), names)


def pseudocode_text(site, limit=5):
    """Trailing pseudocode comment: the count and the first `limit` candidates, in the same order as describe()."""
    targets = ranked(site)
    of = ""
    if getattr(site, "kind", "kcfi") != "kcfi":
        of = " of " + core.type_label(site) if core.type_label(site) else ""
        if not targets and site.kind == "slowpath":
            return "CFIScope: no candidate in this image%s (slow-path check only)" % of
        if not targets:
            return "CFIScope: candidates unknown%s" % of
    if not targets:
        return "CFIScope: 0 candidates in this image"
    names = ", ".join(target_name(t) for t in targets[:limit])
    if len(targets) > limit:
        names += " and %d more" % (len(targets) - limit)
    return "CFIScope: %d candidate%s%s: %s" % (len(targets), "" if len(targets) == 1 else "s", of, names)


def annotate(sites, xref_limit=DEFAULT_XREF_LIMIT):
    """Comment every check; add user xrefs where the candidate list is short."""
    res = {"comments": 0, "xrefs": 0, "kept_user_comments": 0}
    for s in sites:
        ea = s.call_ea or s.check_ea
        old = ida_bytes.get_cmt(ea, False)
        if old and not old.startswith(OWN_TAGS):
            res["kept_user_comments"] += 1
        else:
            ida_bytes.set_cmt(ea, describe(s), False)
            res["comments"] += 1
        if s.call_ea and 0 < len(s.targets) <= xref_limit:
            # Call-type even for tail calls: a jump xref could fold a target into the caller as a chunk.
            for t in s.targets:
                if ida_xref.add_cref(s.call_ea, t, ida_xref.fl_CN | ida_xref.XREF_USER):
                    res["xrefs"] += 1
    return res


def far_crefs_from(ea):
    """Jump and call references from ea (no ordinary flow), as IDA stores them."""
    found, ref = set(), ida_xref.get_first_fcref_from(ea)
    while ref != ida_idaapi.BADADDR and ref not in found:
        found.add(ref)
        ref = ida_xref.get_next_fcref_from(ea, ref)
    return found


def remove_annotations(sites, xref_limit=DEFAULT_XREF_LIMIT):
    """Remove our comments and the call xrefs to the candidates. Returns the number of xrefs that existed
    and were deleted (del_cref's own return value says whether the target instruction will be deleted,
    not whether a reference was removed, so it is not used for the count)."""
    removed = 0
    for s in sites:
        ea = s.call_ea or s.check_ea
        old = ida_bytes.get_cmt(ea, False)
        if old and old.startswith(OWN_TAGS):
            ida_bytes.set_cmt(ea, "", False)
        if s.call_ea and 0 < len(s.targets) <= xref_limit:
            existing = far_crefs_from(s.call_ea)
            for t in s.targets:
                if t in existing:
                    ida_xref.del_cref(s.call_ea, t, False)
                    removed += 1
    return removed


def define_functions(sites):
    """A kCFI preamble, or a CFI jump-table entry's branch, marks a real entry point: create functions IDA missed."""
    made = 0
    for t in sorted({t for s in sites for t in s.targets}):
        if ida_funcs.get_func(t) is None and ida_funcs.add_func(t):
            made += 1
    return made


class Chooser(ida_kernwin.Choose):
    def __init__(self, title, rows):
        columns = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX],
                   ["Name", 44], ["Note", 26]]
        super().__init__(title, columns, flags=ida_kernwin.Choose.CH_RESTORE)
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        ea, name, note = self.rows[n]
        return ["0x%x" % ea, name, note]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


def site_at(sites, ea):
    func = ida_funcs.get_func(ea)
    best = None
    for s in sites:
        lo = min(s.check_ea, s.call_ea or s.check_ea)      # a jump-table CFI call can sit before its check (b.lo)
        end = max(s.check_ea, s.call_ea or s.check_ea) + 4
        if lo <= ea < end:
            return s
        if func is not None and func.start_ea <= s.check_ea < func.end_ea:
            if best is None or abs(s.check_ea - ea) < abs(best.check_ea - ea):
                best = s
    return best


def targets_title(site):
    at = site.call_ea or site.check_ea
    if site.kind == "kcfi":
        return "kCFI candidates for the call at 0x%X (hash 0x%08X)" % (at, site.hash)
    return "jump-table CFI candidates for the call at 0x%X (%s)" % (at, core.type_label(site) or "type unknown")


def targets_rows(site):
    return [(t, target_name(t), "address taken" if is_address_taken(t) else "")
            for t in ranked(site)]


def callers_rows(sites, ea):
    func = ida_funcs.get_func(ea)
    # The kCFI target may sit inside IDA's function (e.g. after a __cfi_ preamble IDA merged in),
    # so accept the cursor address, the function start, or any target inside the function.
    lo, hi = (func.start_ea, func.end_ea) if func is not None else (ea, ea + 1)
    rows = []
    for s in sites:
        if ea in s.targets or any(lo <= t < hi for t in s.targets):
            at = s.call_ea or s.check_ea
            rows.append((at, target_name(at), "%d candidate(s)" % len(s.targets)))
    return rows
