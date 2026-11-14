"""IDA side of CFIScope: read code segments, write comments and cross-references."""
import hashlib
import json
import os

import ida_bytes
import ida_funcs
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_netnode
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


def layout_id(bounds=None):
    """Short digest of layout() (or of the given bounds), kept in the scan marker."""
    bounds = layout() if bounds is None else bounds
    return hashlib.sha256(repr(tuple(tuple(b) for b in bounds)).encode()).hexdigest()[:16]


# Scan's marker in the database: a netnode named with the "$ " prefix netnode.hpp advises, one hash value holding JSON
# (well under MAXSPECSIZE). Comments and xrefs are saved with the database; the scan itself is only in memory.
MARKER_NODE = "$ cfiscope"
MARKER_KEY = "scan"


def save_marker(create_functions):
    """Record that Scan annotated this database: the layout digest and the answer to "Create functions"."""
    marker = {"v": 1, "layout": layout_id(), "create_functions": bool(create_functions)}
    return bool(ida_netnode.netnode(MARKER_NODE, 0, True).hashset_buf(MARKER_KEY, json.dumps(marker)))


def load_marker():
    """The marker save_marker() stored, or None when there is none or it cannot be read."""
    node = ida_netnode.netnode(MARKER_NODE)
    if node.index() == ida_netnode.BADNODE:
        return None
    try:
        marker = json.loads(node.hashstr_buf(MARKER_KEY))
    except (TypeError, ValueError):
        return None
    if not isinstance(marker, dict) or marker.get("v") != 1 or not isinstance(marker.get("layout"), str):
        return None
    return marker


def clear_marker():
    """Delete the marker (Remove annotations, or a Scan that found nothing)."""
    node = ida_netnode.netnode(MARKER_NODE)
    if node.index() != ida_netnode.BADNODE:
        node.kill()


def input_elf():
    """(every, bounds, ranges) from the input file, if it is still where it was loaded from and is an ELF; else None.
    every: (address, name) of its function symbols, several per address; bounds: {name: address} of its kernel text
    bound symbols (core.TEXT_BOUND_NAMES); ranges: its code, as the command line reads it."""
    try:
        from . import cli
        path = ida_nalt.get_input_file_path()
        if path and os.path.isfile(path):
            with open(path, "rb") as fh:
                data = fh.read()
            if data[:4] == b"\x7fELF":
                every, bounds = [], {}
                _, ranges, _ = cli.load_elf(data, every, bounds)
                return every, bounds, ranges
    except Exception:  # noqa: BLE001  names are a bonus: an unreadable input file only means fewer of them
        pass
    return None


def input_type_names():
    """kcfi_types.TypeNames from the BTF in the input file (ELF .BTF section, or a BTF blob in a raw kernel image),
    if the file is still where it was loaded from and holds BTF; else None."""
    try:
        from . import kcfi_types
        path = ida_nalt.get_input_file_path()
        if path and os.path.isfile(path):
            with open(path, "rb") as fh:
                return kcfi_types.load_type_names(fh.read())
    except Exception:  # noqa: BLE001  type names are a bonus, as symbol names are
        pass
    return None


def input_has_split_btf():
    """Does the input file (still where it was loaded from) carry a module's split BTF, which input_type_names()
    cannot read without its kernel's BTF?"""
    try:
        from . import kcfi_types
        path = ida_nalt.get_input_file_path()
        if path and os.path.isfile(path):
            with open(path, "rb") as fh:
                return kcfi_types.has_split_btf(fh.read())
    except Exception:  # noqa: BLE001  a hint only
        pass
    return False


def input_slot_offsets(ranges, sites):
    """(cli.slot_offsets() of the input file for the candidates of sites (kcfi_types.rank_slots()), None) if the file is
    still where it was loaded from, is an ELF and the database has its layout: each of the file's code ranges, as the
    command line lays them out, starts with the same bytes at the same address here (not rebased; a relocatable file
    that IDA laid out elsewhere fails this). Else ({}, why not), and the lists keep their order."""
    path = ida_nalt.get_input_file_path()
    try:
        from . import cli
        if not path or not os.path.isfile(path):
            return {}, "the input file is not at %s" % (path or "a known path")
        with open(path, "rb") as fh:
            data = fh.read()
        if data[:4] != b"\x7fELF":
            return {}, ("the input file %s is not an ELF (the ranking needs its OBJECT symbols: open an ELF such as "
                        "vmlinux-to-elf output)" % path)
        _, file_ranges, _ = cli.load_elf(data)
        if not file_ranges or not all(_bytes_at(ranges, b) is not None and _bytes_at(ranges, b) == _bytes_at([(b, m)], b)
                                      for b, m in file_ranges):
            return {}, ("the database does not have the layout of %s (rebased, or its sections laid out elsewhere)"
                        % path)
        return cli.slot_offsets(data, {t for s in sites for t in s.targets}), None
    except Exception as e:  # noqa: BLE001  the order is a bonus, as names are
        return {}, "%s could not be read (%s)" % (path, e)


def typeid_names(elf=False):
    """(address, name) of the __typeid_<type>_global_addr names (kallsyms keeps them).

    IDA keeps one name per address, and each of these shares its address with a `foo.cfi_jt` entry name, so the
    database may have lost them: the input file's own ELF symbol table, if it is still there, is read as well
    (elf: input_elf(), read here if not given).
    Names from the file come without an address (the database may be rebased); they are matched by type id."""
    out = []
    for i in range(ida_name.get_nlist_size()):
        name = ida_name.get_nlist_name(i)
        if name and name.startswith("__typeid_"):
            out.append((ida_name.get_nlist_ea(i), name))
    if elf is False:
        elf = input_elf()
    if elf is not None:
        out.extend((None, name) for _, name in elf[0] if name.startswith("__typeid_"))
    return out


def _bytes_at(ranges, ea, n=64):
    """Up to n bytes at ea from (base, bytes) ranges; None unless at least 4 are there."""
    for base, mem in ranges:
        if base <= ea and ea + 4 <= base + len(mem):
            return bytes(mem[ea - base:ea - base + n])
    return None


def text_bounds(ranges, elf=None):
    """{name: address} of the kernel text bounds (core.TEXT_BOUND_NAMES): the database's names and, since IDA keeps
    one name per address and these share theirs with other names (_stext with __irqentry_text_start, _etext with
    __start_rodata in GKI kernels), the input file's symbols (elf: input_elf()) when the database still has the
    file's layout: the same bytes at the file's _stext and _sinittext (not rebased)."""
    named = {}
    for name in sorted(core.TEXT_BOUND_NAMES):
        ea = ida_name.get_name_ea(BADADDR, name)
        if ea != BADADDR:
            named[name] = ea
    if elf is not None:
        bounds, file_ranges = elf[1], elf[2]
        if all(n in bounds and _bytes_at(file_ranges, bounds[n]) is not None
               and _bytes_at(file_ranges, bounds[n]) == _bytes_at(ranges, bounds[n]) for n in ("_stext", "_sinittext")):
            for name, ea in bounds.items():
                named.setdefault(name, ea)
    return named


# The last jump-table CFI scan: its jump table, target -> first entry, function start -> has no blr/br (in_cfi_runtime).
JT = {"table": None, "entry_of": {}, "runtime_fn": {}}
# Call addresses of the scanned sites. A data xref from one of them is CFIScope's own (annotate, after No), not a
# stored pointer: an indirect call takes no function's address.
CALLS = set()
# The last kCFI scan's kernel text bounds (core.kernel_text(); None without them), the offsets of its checks' hashes
# (Site.disp) and the input's BTF type names (kcfi_types.TypeNames, or None): Functions of this type finds functions as
# Scan finds candidates, and names their type.
KCFI = {"text": None, "disps": [], "names": None}


def forget():
    """Drop what the last scan left in this module (the plugin's term: the module may outlive its database)."""
    JT.update(table=None, entry_of={}, runtime_fn={})
    CALLS.clear()
    KCFI.update(text=None, disps=[], names=None)


def scan():
    arch = current_arch()
    if arch is None:
        raise RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only.")
    ranges = code_ranges()
    elf = input_elf()
    # With the kernel's text bounds named, kCFI candidates outside kernel code (a hash value in .rodata) are left out.
    text = core.kernel_text(text_bounds(ranges, elf))
    sites, stats = core.resolve(ranges, arch, text)
    KCFI.update(text=text, disps=list(stats.get("disps") or []), names=None)
    JT["table"] = None
    if stats.get("scheme") == "jump-table CFI":
        stats = dict(stats, named_checks=core.name_jt_types(sites, typeid_names(elf)))
        JT["table"] = core.find_jump_table(ranges)    # so that a foo.cfi_jt entry can stand for foo (callers_rows)
    elif sites:
        names = KCFI["names"] = input_type_names()
        if names is not None:      # kCFI hashes named by C function type from the input file's BTF
            from . import kcfi_types
            named, total = kcfi_types.name_sites(sites, names)
            stats = dict(stats, kcfi_hashes_named=named, btf_prototypes=names.protos)
            if arch == "aarch64":  # and the struct member each call loads its pointer from (as the command line does)
                stats.update(kcfi_types.name_members(sites, ranges, arch, names))
                if any(s.members for s in sites):    # its candidates stored in a slot of that member come first
                    offsets, why = input_slot_offsets(ranges, sites)
                    if why:     # review s197: say so, once per scan, rather than show plain lists with no word
                        ida_kernwin.msg("[CFIScope] slot ranking skipped: %s; the candidate lists keep their order\n"
                                        % why)
                    stats.update(kcfi_types.rank_slots(sites, offsets, names))
        elif input_has_split_btf():  # review s189 NIT 6: say why a module's hashes are not named, once per scan
            ida_kernwin.msg("[CFIScope] this module's BTF is split BTF (it continues its kernel's BTF), which the IDA "
                            "plugin does not read: kCFI hashes are not named by C type here; the command line names "
                            "them: python3 -m cfiscope MODULE.ko --sites --btf KERNEL (a vmlinux or raw Image of the "
                            "same build)\n")
    jt = JT["table"]
    JT["runtime_fn"] = {}
    CALLS.clear()
    CALLS.update(s.call_ea for s in sites if s.call_ea)
    JT["entry_of"] = {} if jt is None else {t: jt.start + k * jt.entry_size for k, t in reversed(list(enumerate(jt.targets)))}
    return sites, stats


def scheme_name(sites):
    """'kCFI', or 'jump-table CFI' for a Linux 5.x kernel."""
    return "jump-table CFI" if sites and sites[0].kind != "kcfi" else "kCFI"


def is_address_taken(ea):
    """Is there a data xref to ea, not counting CFIScope's own from a call site (CALLS)?"""
    seen, ref = set(), ida_xref.get_first_dref_to(ea)
    while ref != BADADDR and ref not in seen:
        if ref not in CALLS:
            return True
        seen.add(ref)
        ref = ida_xref.get_next_dref_to(ea, ref)
    return False


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


def ranked(site, taken=None):
    """The candidates stored in a slot of the call's struct member first (Site.slot_backed, kcfi_types.rank_slots()):
    at its offset, then by array stride only (core.slot_rank()); then address-taken candidates: only they can really be
    stored in a pointer. Every candidate is kept. taken: a dict that keeps each candidate's pointer_taken() answer
    across the sites of one pass (the call-site list), so it is asked once."""
    slot = getattr(site, "slot_backed", None) or ()     # core.slot_rank(), inline below: this runs for every
    stride = getattr(site, "slot_stride", None) or ()   # candidate of every list (the call-site list)
    if taken is None:
        return sorted(site.targets, key=lambda t: (2 if t not in slot else 1 if t in stride else 0,
                                                   not pointer_taken(site, t), t))
    jt = getattr(site, "kind", "kcfi") != "kcfi"      # pointer_taken() depends on the target and, for these, its entry

    def key(t):
        known = taken.get((jt, t))
        if known is None:
            known = taken[(jt, t)] = pointer_taken(site, t)
        return (2 if t not in slot else 1 if t in stride else 0, not known, t)
    return sorted(site.targets, key=key)


def candidate_names(site, targets):
    """The candidates part of describe(): the first 6 names of targets (ranked()), ', +N more', or why there are none.
    With candidates stored in a slot of the call's member: 'in a proto_ops.sendmsg_locked slot: tcp_sendmsg_locked;
    same type only: 10 more' (core.slot_text(): every name when there are 6 or fewer, else up to 6 of those)."""
    if targets and getattr(site, "slot_backed", None):
        return core.slot_text(site, targets, target_name, 6)
    if targets:
        names = ", ".join(target_name(t) for t in targets[:6])
        if len(targets) > 6:
            names += ", +%d more" % (len(targets) - 6)
        return names
    if getattr(site, "kind", "kcfi") == "kcfi":
        return "no implementation in this image"
    if site.kind == "slowpath":
        why = site.note or "only __cfi_slowpath checks this call: its targets can only be in modules"
        return "no candidate in this image (%s)" % why
    return "candidates unknown (the check's jump-table range was not found)"


def site_member(site):
    """The struct member a kCFI call loads its pointer from, as the command line prints it (core.member_label():
    'proto_ops.sendmsg', or 'one of 2 members (...)'); '' when not known (no BTF, no decodable load, x86-64)."""
    return core.member_label(site) or ""


def describe(site):
    targets = ranked(site)
    if getattr(site, "kind", "kcfi") != "kcfi":
        head = "%s %s" % (JT_COMMENT_TAG, core.type_label(site) or "type unknown")
    else:
        typed = " %s" % site.type_name if getattr(site, "type_name", None) else ""
        member = site_member(site)
        head = "%s %s0x%08X%s" % (COMMENT_TAG, member + " " if member else "", site.hash, typed)
    if not targets:
        return "%s: %s" % (head, candidate_names(site, targets))
    return "%s: %d candidate(s): %s" % (head, len(targets), candidate_names(site, targets))


def site_type(site):
    """Type column of the call-site list: the kCFI hash's C prototype when BTF named it, else the hash; for jump-table
    CFI, the type(s) its checks name (core.type_label())."""
    if getattr(site, "kind", "kcfi") != "kcfi":
        return core.type_label(site) or "type unknown"
    return site.type_name if getattr(site, "type_name", None) else "hash 0x%08X" % site.hash


def sites_rows(sites):
    """(address, function+offset, member, type, candidates, first candidates) of every call site, in scan order: the
    fields of a `python3 -m cfiscope --sites` line (the call, or the check when no call was linked; the struct member
    it calls through, site_member(); its count), with the type as site_type() and the names as the comment gives them
    (describe(): address-taken first)."""
    taken, rows = {}, []
    for s in sites:
        at = s.call_ea or s.check_ea
        targets = ranked(s, taken)
        rows.append((at, target_name(at), site_member(s), site_type(s), len(targets), candidate_names(s, targets)))
    return rows


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
    elif getattr(site, "type_name", None):       # kCFI hash named from BTF
        of = " of " + site.type_name
    member = site_member(site)                   # 'CFIScope: proto_ops.sendmsg, 14 candidates of ...'
    member = member + ", " if member else ""
    if not targets:
        return "CFIScope: %s0 candidates in this image%s" % (member, of)
    if getattr(site, "slot_backed", None):    # stored in a slot of the call's member: named first (as in the comment)
        names = core.slot_text(site, targets, target_name, limit, " and %d more")
    else:
        names = ", ".join(target_name(t) for t in targets[:limit])
        if len(targets) > limit:
            names += " and %d more" % (len(targets) - limit)
    return "CFIScope: %s%d candidate%s%s: %s" % (member, len(targets), "" if len(targets) == 1 else "s", of, names)


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


def _code_segment(seg):
    return bool(seg.perm & ida_segment.SEGPERM_EXEC) or seg.type == ida_segment.SEG_CODE


def target_check():
    """A test for a candidate before it gets a cross-reference or a function: it must lie in a segment the scan reads
    (executable or code; any segment when the database has neither, as after a raw load) and must not be an item IDA
    holds as data, nor inside another item. (Without the kernel's symbols, a type hash that happens to occur in
    .rodata yields a candidate there.)"""
    segs = [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())]
    any_code = any(seg is not None and _code_segment(seg) for seg in segs)
    seen = {}

    def ok(ea):
        if ea not in seen:
            seg = ida_segment.getseg(ea)
            if seg is None or (any_code and not _code_segment(seg)):
                seen[ea] = False
            else:
                flags = ida_bytes.get_flags(ea)
                seen[ea] = not (ida_bytes.is_data(flags) or ida_bytes.is_tail(flags))
        return seen[ea]
    return ok


def xref_targets(site, xref_limit=DEFAULT_XREF_LIMIT):
    """The candidates of a call that Scan gives cross-references: all of a list of at most xref_limit; of a longer
    list, those stored at the offset of the call's member (core.slot_kind() 'offset'; not those by array stride only,
    weaker evidence) when there are at most xref_limit of them; else none."""
    if not site.call_ea or not site.targets:
        return []
    if len(site.targets) <= xref_limit:
        return site.targets
    at = [t for t in site.targets if core.slot_kind(site, t) == "offset"]
    return at if len(at) <= xref_limit else []


def annotate(sites, xref_limit=DEFAULT_XREF_LIMIT, create_functions=True):
    """Comment every check; add user xrefs where the candidate list is short, never to a candidate target_check() rejects
    (counted in xrefs_skipped_not_code). A call xref (fl_CN) makes IDA create a function at its target (xref.hpp), so
    with create_functions=False only a candidate at the start of a function IDA has gets one (counted in xrefs); a
    candidate inside a function IDA has gets a user data xref (dr_O) instead (counted in data_xrefs_inside_function),
    for which xref.hpp notes no such effect (ida.hpp AF_PROCPTR is for data xrefs from data; that it makes no function
    is assumed, not checked in IDA), and a candidate with no function gets none (counted in xrefs_skipped_no_function).
    A call and candidate pair keeps one xref: an earlier Scan's xref of the other kind is replaced. The candidates are
    those of xref_targets(): a list longer than xref_limit gets xrefs to its candidates stored at the member's offset
    when at most xref_limit of them (counted in slot_only_lists)."""
    res = {"comments": 0, "xrefs": 0, "kept_user_comments": 0, "runtime_comments": 0, "xrefs_skipped_not_code": 0,
           "data_xrefs_inside_function": 0, "xrefs_skipped_no_function": 0, "slot_only_lists": 0}
    ok = target_check()
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
        chosen = xref_targets(s, xref_limit)
        if chosen:
            res["slot_only_lists"] += len(chosen) < len(s.targets)
            drefs = data_refs_from(s.call_ea)
            # Call-type even for tail calls: a jump xref could fold a target into the caller as a chunk.
            for t in chosen:
                if not ok(t):
                    res["xrefs_skipped_not_code"] += 1
                    continue
                start = None if create_functions else getattr(ida_funcs.get_func(t), "start_ea", None)
                if create_functions or start == t:
                    if t in drefs:
                        ida_xref.del_dref(s.call_ea, t)
                    if ida_xref.add_cref(s.call_ea, t, ida_xref.fl_CN | ida_xref.XREF_USER):
                        res["xrefs"] += 1
                elif start is None:
                    res["xrefs_skipped_no_function"] += 1
                else:
                    if t in far_crefs_from(s.call_ea):
                        ida_xref.del_cref(s.call_ea, t, False)
                    if ida_xref.add_dref(s.call_ea, t, ida_xref.dr_O | ida_xref.XREF_USER):
                        res["data_xrefs_inside_function"] += 1
    return res


def far_crefs_from(ea):
    """Jump and call references from ea (no ordinary flow), as IDA stores them."""
    found, ref = set(), ida_xref.get_first_fcref_from(ea)
    while ref != ida_idaapi.BADADDR and ref not in found:
        found.add(ref)
        ref = ida_xref.get_next_fcref_from(ea, ref)
    return found


def data_refs_from(ea):
    """Data references from ea, as IDA stores them."""
    found, ref = set(), ida_xref.get_first_dref_from(ea)
    while ref != ida_idaapi.BADADDR and ref not in found:
        found.add(ref)
        ref = ida_xref.get_next_dref_from(ea, ref)
    return found


def remove_annotations(sites, xref_limit=DEFAULT_XREF_LIMIT):
    """Remove our comments and the call and data xrefs to the candidates. Returns the number of xrefs that existed
    and were deleted (del_cref's own return value says whether the target instruction will be deleted,
    not whether a reference was removed, so it is not used for the count). Of a list longer than xref_limit, only the
    xrefs to the candidates Scan gives them (xref_targets()) are deleted, so a cross-reference you added to another
    candidate stays; those Scan added stay too when this scan cannot read the slots (the input file gone since)."""
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
        chosen = s.targets if len(s.targets) <= xref_limit else xref_targets(s, xref_limit)
        if s.call_ea and chosen:
            existing, data = far_crefs_from(s.call_ea), data_refs_from(s.call_ea)
            for t in chosen:
                if t in existing:
                    ida_xref.del_cref(s.call_ea, t, False)
                    removed += 1
                if t in data:
                    ida_xref.del_dref(s.call_ea, t)
                    removed += 1
    return removed


def define_functions(sites):
    """A kCFI preamble, or a CFI jump-table entry's branch, marks a real entry point: create functions IDA missed,
    never at a candidate target_check() rejects (data, or outside the code segments)."""
    ok = target_check()
    made = skipped = 0
    for t in sorted({t for s in sites for t in s.targets}):
        if ida_funcs.get_func(t) is not None:
            continue
        if not ok(t):
            skipped += 1
        elif ida_funcs.add_func(t):
            made += 1
    return {"functions_created": made, "skipped_not_code": skipped}


class Chooser(ida_kernwin.Choose):
    """Non-modal jump list. rows: (address, column text, ...), one value per column after Address; Enter jumps."""
    COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Name", 44], ["Note", 26]]

    def __init__(self, title, rows, columns=None):
        super().__init__(title, columns or self.COLUMNS, flags=ida_kernwin.Choose.CH_RESTORE)
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        row = self.rows[n]
        return ["0x%x" % row[0]] + [str(v) for v in row[1:]]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED, )


# The call-site list: Candidates is a number column (CHCOL_DEC), so clicking its header sorts by count.
SITES_COLUMNS = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Function+off", 30], ["Member", 28], ["Type", 44],
                 ["Candidates", 6 | ida_kernwin.Choose.CHCOL_DEC], ["First candidates", 60]]


def sites_title(sites):
    return "CFIScope: %s %s call site%s" % (format(len(sites), ","), scheme_name(sites), "" if len(sites) == 1 else "s")


def sites_chooser(sites):
    """The non-modal list of every scanned call site (sites_rows()); Enter on a row jumps to the call."""
    return Chooser(sites_title(sites), sites_rows(sites), SITES_COLUMNS)


class SitePicker(ida_kernwin.Choose):
    """Modal list of the calls on one pseudocode line; Show(True) returns the picked row, or a negative value."""
    def __init__(self, title, sites):
        super().__init__(title, [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Call", 80]])
        self.sites = sites

    def OnGetSize(self):
        return len(self.sites)

    def OnGetLine(self, n):
        site = self.sites[n]
        return ["0x%x" % (site.call_ea or site.check_ea), describe(site)]


def pick_site(sites):
    """Ask which of several calls on a pseudocode line; None on Esc."""
    n = SitePicker("CFIScope: %d calls on this pseudocode line" % len(sites), sites).Show(True)
    return sites[n] if isinstance(n, int) and 0 <= n < len(sites) else None


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
        typed = ", " + site.type_name if getattr(site, "type_name", None) else ""
        member = site_member(site)
        return "kCFI candidates for the call at 0x%X (%shash 0x%08X%s)" % (at, member + ", " if member else "",
                                                                         site.hash, typed)
    return "jump-table CFI candidates for the call at 0x%X (%s)" % (at, core.type_label(site) or "type unknown")


def targets_rows(site):
    """(address, name, note) of every candidate, in ranked() order; note: 'stored in a proto_ops.sendmsg slot' or 'by
    array stride' for the slot-backed ones (core.slot_note()), else 'address taken' or nothing."""
    rows = []
    for t in ranked(site):
        kind = core.slot_kind(site, t)
        rows.append((t, target_name(t), core.slot_note(site, kind) if kind else
                     "address taken" if pointer_taken(site, t) else ""))
    return rows


def in_cfi_runtime(ea):
    """Is ea in the CFI runtime's check function: one named __cfi_check, or one with no blr/br (it calls no checked
    pointer itself, so its checks guard no call)? False outside a function. A function with tail chunks is judged by
    its name only: the code test reads the entry chunk alone."""
    func = ida_funcs.get_func(ea)
    if func is None:
        return False
    if ida_funcs.get_func_name(func.start_ea) == core.RUNTIME_CHECK_FUNCTION:
        return True
    if func.tailqty:            # a blr/br in a tail chunk (ea itself may be in one) is not in the entry chunk's bytes
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
    hit = lambda t: t == ea or lo <= t < hi       # noqa: E731
    calls, checks = core.callers(sites, hit, in_cfi_runtime)
    # review s197: the calls whose member slot holds the function first, and the note says so ('same type only' for
    # the others, when the call ranks some candidates first)
    calls = core.slot_callers_first(calls, hit)
    rows = []
    for s in calls:     # a kCFI check whose call was not recognised still counts as a call site: listed at its check
        kind = core.callee_slot(s, hit)[0]
        note = (site_member(s) + ", " if site_member(s) else "") + "%d candidate(s)" % len(s.targets)
        rows.append((s.call_ea or s.check_ea, target_name(s.call_ea or s.check_ea),
                     note + (", " + core.slot_note(s, None if kind == "type" else kind) if kind else "")))
    rows += [(s.check_ea, target_name(s.check_ea), "%s, %d candidate(s)" % (core.UNLINKED, len(s.targets)))
             for s in checks]
    return rows


def callers_title(sites, ea, rows):
    """Title of the callers list: counts call sites only, as the command line does."""
    checks = sum(1 for r in rows if r[2].startswith(core.UNLINKED))
    return "%s callers: %s" % (scheme_name(sites), core.callers_header(len(rows) - checks, checks, target_name(ea)))


# ---- Functions of this type: every function with the kCFI hash of the function under the cursor ----

def _window(ea, size=64):
    """[(start, bytes)] of the code within size bytes of ea, in ea's segment: enough for core.function_hash()."""
    seg = ida_segment.getseg(ea)
    if seg is None:
        return []
    lo, hi = max(seg.start_ea, ea - size), min(seg.end_ea, ea + size)
    data = ida_bytes.get_bytes(lo, hi - lo) if hi > lo else None
    return [(lo, data)] if data else []


def _type_disps():
    """Where the type hash sits in front of a function: the scan's checks say; with none, aarch64 kCFI's default."""
    return KCFI["disps"] or core.DEFAULT_DISPS.get(current_arch(), [])


def type_problem(sites, stats):
    """Why Functions of this type cannot answer in this database (as the command line's --implements refuses), or
    None."""
    if scheme_name(sites) != "kCFI":
        return ("Functions of this type is for kCFI: this database uses the jump-table CFI of Linux 5.x, whose "
                "functions carry no type hash in front of them.")
    if not sites and (stats or {}).get("blr_instructions"):
        return ("No kCFI check guards the %d indirect calls (blr) of this database: it is not built with kCFI, so its "
                "functions carry no type hash." % stats["blr_instructions"])
    if not _type_disps():
        return ("No kCFI check in this database: on x86-64 where a function's type hash sits in front of it is read "
                "from the checks (kernels differ).")
    return None


def _after_preamble(func, disps):
    """x86-64: the entries after a __cfi_ preamble that IDA made the start of func: for each `mov r32, imm32` in its
    first 16 bytes, the address whose hash its imm32 would be (at each offset in disps)."""
    head = ida_bytes.get_bytes(func.start_ea, 16) or b""
    out = []
    for i, byte in enumerate(head):
        if 0xb8 <= byte <= 0xbf:
            for d in disps:
                e = func.start_ea + i + 1 - d
                if func.start_ea < e < func.end_ea and e not in out:
                    out.append(e)
    return out


def type_entry(sites, ea):
    """(entry, kCFI hash) of the function at ea, for Functions of this type: the hash in front of the start of IDA's
    function holding ea (or of ea, outside a function), when core.function_hash() takes the word there (a call site
    checks it, BTF names it, or its form); else, only when a call site checks it or BTF names it, the hash in front of
    ea itself, of a scanned candidate inside the function or, on x86-64, of the entry after a __cfi_ preamble that IDA
    made the function's start. None if there is none: a static function whose address is never taken has no hash."""
    arch, disps = current_arch(), _type_disps()
    checked = {s.hash for s in sites if s.kind == "kcfi"}
    named = KCFI["names"].by_hash if KCFI["names"] is not None else ()
    func = ida_funcs.get_func(ea)
    first = func.start_ea if func is not None else ea
    later = [ea] if ea != first else []
    if func is not None:
        later += sorted({t for s in sites for t in s.targets if func.start_ea < t < func.end_ea})
        if arch == "x86_64":
            later += _after_preamble(func, disps)
    for e, form in [(first, True)] + [(e, False) for e in later]:
        got = core.function_hash(_window(e), arch, e, disps, checked, named, form)
        if got is not None:
            return e, got[0]
    return None


def type_functions(sites, h):
    """Sorted addresses of every function with the kCFI hash h in front of it, as the command line's --implements finds
    them (core.implementations(), with the scan's text bounds): the candidates of a call site that checks h, else the
    code segments read again and searched for h."""
    known = any(s.kind == "kcfi" and s.hash == h for s in sites)
    return core.implementations([] if known else code_ranges(), current_arch(), h, _type_disps(), sites, KCFI["text"])


def type_title(entry, h, count):
    """'kCFI functions of the type of impl_2_1 (hash 0x1300E12B, long (short, int)): 3' (the type from BTF)."""
    label = KCFI["names"].label(h) if KCFI["names"] is not None else None
    return "kCFI functions of the type of %s (hash 0x%08X%s): %d" % (target_name(entry), h, ", " + label if label else "",
                                                                    count)


def type_rows(entry, functions):
    """(address, name, note) of each function: note 'this function' for the entry, 'address taken' when IDA has a data
    reference to it (is_address_taken())."""
    rows = []
    for t in functions:
        notes = (["this function"] if t == entry else []) + (["address taken"] if is_address_taken(t) else [])
        rows.append((t, target_name(t), ", ".join(notes)))
    return rows
