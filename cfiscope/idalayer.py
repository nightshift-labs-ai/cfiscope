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


# The last jump-table CFI scan: its jump table, target -> first entry, function start -> has no blr/br (in_cfi_runtime).
JT = {"table": None, "entry_of": {}, "runtime_fn": {}}


def scan():
    arch = current_arch()
    if arch is None:
        raise RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only.")
    ranges = code_ranges()
    sites, stats = core.resolve(ranges, arch)
    JT["table"] = None
    if stats.get("scheme") == "jump-table CFI":
        stats = dict(stats, named_checks=core.name_jt_types(sites, typeid_names()))
        JT["table"] = core.find_jump_table(ranges)    # so that a foo.cfi_jt entry can stand for foo (callers_rows)
    jt = JT["table"]
    JT["runtime_fn"] = {}
    JT["entry_of"] = {} if jt is None else {t: jt.start + k * jt.entry_size for k, t in reversed(list(enumerate(jt.targets)))}
    return sites, stats


def scheme_name(sites):
    """'kCFI', or 'jump-table CFI' for a Linux 5.x kernel."""
    return "jump-table CFI" if sites and sites[0].kind != "kcfi" else "kCFI"


def is_address_taken(ea):
    return ida_xref.get_first_dref_to(ea) != BADADDR


def pointer_taken(site, target):
    """Is target's address stored anywhere? With jump-table CFI, pointers to foo point at its entry foo.cfi_jt."""
    entry = JT["entry_of"].get(target) if getattr(site, "kind", "kcfi") != "kcfi" else None
    return (entry is not None and is_address_taken(entry)) or is_address_taken(target)


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
    return sorted(site.targets, key=lambda t: (not pointer_taken(site, t), t))


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


def runtime_calls(sites):
    """{address: site} of the CFI runtime's own calls (jump-table CFI): the blr of a check's inlined slow path,
    which calls __cfi_check of the kernel or module holding the pointer, with the type id. Not program calls, so they get a note, not candidates."""
    out = {}
    for s in sites:
        for x in [s] + list(s.extra_checks):
            if getattr(x, "runtime_call_ea", 0):
                out.setdefault(x.runtime_call_ea, x)
    return out


def describe_runtime(site):
    return ("%s runtime: calls __cfi_check (kernel's or the pointer's module's) for %s (slow path of the check at 0x%X); not a program call"
            % (JT_COMMENT_TAG, core.type_label(site) or "this type", site.check_ea))


def annotate(sites, xref_limit=DEFAULT_XREF_LIMIT):
    """Comment every check; add user xrefs where the candidate list is short."""
    res = {"comments": 0, "xrefs": 0, "kept_user_comments": 0, "runtime_comments": 0}
    for ea, x in runtime_calls(sites).items():
        old = ida_bytes.get_cmt(ea, False)
        if old and not old.startswith(OWN_TAGS):
            res["kept_user_comments"] += 1
        else:
            ida_bytes.set_cmt(ea, describe_runtime(x), False)
            res["runtime_comments"] += 1
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
    for ea in runtime_calls(sites):
        old = ida_bytes.get_cmt(ea, False)
        if old and old.startswith(OWN_TAGS):
            ida_bytes.set_cmt(ea, "", False)
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
    """The site whose call or check is at ea; else the narrowest check-to-call span holding ea; else the nearest
    check in the same function. (A jump-table CFI call can sit before its check, or far from it.)"""
    func = ida_funcs.get_func(ea)
    span = near = None
    for s in sites:
        if ea == s.call_ea or ea == s.check_ea:
            return s
        lo = min(s.check_ea, s.call_ea or s.check_ea)
        end = max(s.check_ea, s.call_ea or s.check_ea) + 4
        if lo <= ea < end and (span is None or end - lo < span[0]):
            span = (end - lo, s)
        if func is not None and func.start_ea <= s.check_ea < func.end_ea:
            if near is None or abs(s.check_ea - ea) < abs(near.check_ea - ea):
                near = s
    return span[1] if span else near


def targets_title(site):
    at = site.call_ea or site.check_ea
    if site.kind == "kcfi":
        return "kCFI candidates for the call at 0x%X (hash 0x%08X)" % (at, site.hash)
    return "jump-table CFI candidates for the call at 0x%X (%s)" % (at, core.type_label(site) or "type unknown")


def targets_rows(site):
    return [(t, target_name(t), "address taken" if pointer_taken(site, t) else "")
            for t in ranked(site)]


def in_cfi_runtime(ea):
    """Is ea in the CFI runtime's check function: one named __cfi_check, or one with no blr/br (it calls no checked
    pointer itself, so its checks guard no call)? False outside a function."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    if ida_funcs.get_func_name(func.start_ea) == core.RUNTIME_CHECK_FUNCTION:
        return True
    if not func.start_ea <= ea < func.end_ea:      # in a tail chunk: the bytes read below are not its code
        return False
    known = JT["runtime_fn"].get(func.start_ea)
    if known is None:
        code = ida_bytes.get_bytes(func.start_ea, func.end_ea - func.start_ea)
        known = JT["runtime_fn"][func.start_ea] = bool(code) and not core.has_indirect_call(code)
    return known


def callers_rows(sites, ea):
    """(address, name, note) of the call sites that can reach the function at ea, then of the type checks whose
    call was not linked (note core.UNLINKED; not call sites). The CFI runtime's own checks are left out."""
    jt = JT["table"]
    if jt is not None and jt.start <= ea < jt.end:
        # A jump-table entry (foo.cfi_jt): every pointer to foo points here, so answer for foo itself.
        target = jt.targets[(ea - jt.start) // jt.entry_size]
        if not jt.start <= target < jt.end:
            ea = target
    func = ida_funcs.get_func(ea)
    # The kCFI target may sit inside IDA's function (e.g. after a __cfi_ preamble IDA merged in),
    # so accept the cursor address, the function start, or any target inside the function.
    lo, hi = (func.start_ea, func.end_ea) if func is not None else (ea, ea + 1)
    calls, checks = core.callers(sites, lambda t: t == ea or lo <= t < hi, in_cfi_runtime)
    rows = [(s.call_ea, target_name(s.call_ea), "%d candidate(s)" % len(s.targets)) for s in calls]
    rows += [(s.check_ea, target_name(s.check_ea), "%s, %d candidate(s)" % (core.UNLINKED, len(s.targets)))
             for s in checks]
    return rows


def callers_title(sites, ea, rows):
    """Title of the callers list: counts call sites only, as the command line does."""
    checks = sum(1 for r in rows if r[2].startswith(core.UNLINKED))
    return "%s callers: %s" % (scheme_name(sites), core.callers_header(len(rows) - checks, checks, target_name(ea)))
