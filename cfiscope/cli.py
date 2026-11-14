"""Command-line use of the CFIScope scanner, with no IDA.

    python3 -m cfiscope vmlinux                      # summary
    python3 -m cfiscope vmlinux --sites              # every call site and its candidates
    python3 -m cfiscope vmlinux --callers tcp_sendmsg
    python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
    python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
    python3 -m cfiscope vmlinux --sites --btf vmlinux.btf   # name kCFI hashes by C type
    python3 -m cfiscope vmlinux --implements file_operations.unlocked_ioctl   # every function of that member's type

Input is a 64-bit little-endian ELF (a vmlinux, or a kernel whose symbols
were restored with vmlinux-to-elf, or a relocatable .o/.ko), or a raw kernel
image with --raw.  Symbols print names and, when the ELF names _stext,
_etext, _sinittext and _einittext, leave out kCFI candidates between _etext
and _sinittext outside the code areas named there (core.kernel_text()); the
scan itself reads code bytes alone.  Add --json for machine output.
kCFI hashes are named by their C function type when BTF is available: from
--btf (an ELF with a .BTF section, a raw kernel image, or a raw BTF file), or
else from the input itself when it carries BTF (--no-btf turns that off).
For a loadable module (.ko), --with VMLINUX also lists the kernel's functions
with each call's type hash (by the kernel ELF's symbols), since a module
mostly calls through tables that the kernel or other modules fill.
--implements SPEC lists every function whose kCFI preamble hash is that of a struct
member, a C function type, a mangled type, a hash, or a named function's own type,
whether or not a call site of the input checks it.
"""
import argparse
import array
import bisect
import json
import os
import re
import struct
import sys

from . import core, kcfi_types
from .core import name_jt_types, resolve, type_label

EM_X86_64, EM_AARCH64 = 62, 183
ARCH_BY_MACHINE = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}
PT_LOAD, PF_X = 1, 1
SHT_SYMTAB, SHT_RELA, SHT_NOBITS, SHF_ALLOC, SHF_EXECINSTR = 2, 4, 8, 2, 4
STT_OBJECT, STT_FUNC = 1, 2
R_ABS64 = {EM_X86_64: 1, EM_AARCH64: 257}      # R_X86_64_64, R_AARCH64_ABS64: a 64-bit absolute address


class InputError(Exception):
    pass


def _sections(d):
    shoff = struct.unpack_from("<Q", d, 0x28)[0]
    shentsize, shnum = struct.unpack_from("<HH", d, 0x3a)
    if not shoff or shentsize != 64:
        return []
    if shoff + 64 * shnum > len(d):
        raise InputError("section header table runs past the end of the file")
    return [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(shnum)]


_BOUND_NAMES = {n.encode() for n in core.TEXT_BOUND_NAMES}


def _function_symbols(d, secs, place, every=None, bounds=None):
    """Return {address: name} for STT_FUNC symbols; place(shndx, value) -> address or None.
    every, if a list, also receives each (address, name), several names per address included.
    bounds, if a dict, receives {name: address} of the kernel text bounds (core.TEXT_BOUND_NAMES) of any symbol type."""
    names = {}
    for s in secs:
        if s[1] != SHT_SYMTAB or s[6] >= len(secs):
            continue
        strtab = secs[s[6]]
        for i in range(s[5] // 24):
            off = s[4] + 24 * i
            if off + 24 > len(d):
                break
            nm, info, _other, shndx, value, _size = struct.unpack_from("<IBBHQQ", d, off)
            if not nm or (info & 15 != STT_FUNC and bounds is None):
                continue
            ea = place(shndx, value)
            if ea is None:
                continue
            start = strtab[4] + nm
            end = d.find(b"\0", start)
            if end < 0:
                continue
            if info & 15 != STT_FUNC:
                if d[start:end] in _BOUND_NAMES:
                    bounds.setdefault(d[start:end].decode(), ea)
                continue
            name = d[start:end].decode("utf-8", "replace")
            names.setdefault(ea, name)
            if bounds is not None and name in core.TEXT_BOUND_NAMES:
                bounds.setdefault(name, ea)
            if every is not None:
                every.append((ea, name))
    return names


def load_elf(d, every=None, bounds=None):
    """Return (arch, ranges, symbols) from a 64-bit little-endian ELF (every, bounds: see _function_symbols)."""
    if len(d) < 64 or d[:4] != b"\x7fELF":
        raise InputError("not an ELF file (use --raw for a raw kernel image)")
    if d[4] != 2 or d[5] != 1:
        raise InputError("only 64-bit little-endian ELF is supported")
    e_type, machine = struct.unpack_from("<HH", d, 0x10)
    arch = ARCH_BY_MACHINE.get(machine)
    if arch is None:
        raise InputError("unsupported ELF machine %d (x86-64 and AArch64 only)" % machine)
    try:
        secs = _sections(d)
    except InputError:
        if e_type == 1:
            raise
        print("cfiscope: section headers unreadable, names unavailable", file=sys.stderr)
        secs = []
    ranges = []
    if e_type == 1:  # relocatable (.o / .ko): lay executable sections out one after another
        bases = _code_bases(secs)
        for i, base in bases.items():
            ranges.append((base, d[secs[i][4]:secs[i][4] + secs[i][5]]))

        def place(shndx, value):
            return bases[shndx] + value if shndx in bases else None
    else:
        phoff = struct.unpack_from("<Q", d, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
        if phoff and phentsize == 56 and phoff + 56 * phnum <= len(d):
            for i in range(phnum):
                p_type, p_flags, p_offset, p_vaddr, _pa, p_filesz, _memsz, _al = \
                    struct.unpack_from("<IIQQQQQQ", d, phoff + 56 * i)
                if p_type == PT_LOAD and p_flags & PF_X and p_filesz:
                    ranges.append((p_vaddr, d[p_offset:p_offset + p_filesz]))
        if not ranges:  # no usable program headers: fall back to executable sections
            for s in secs:
                if s[2] & SHF_EXECINSTR and s[5] and s[1] != 8 and s[3]:
                    ranges.append((s[3], d[s[4]:s[4] + s[5]]))

        def place(shndx, value):
            return value or None
    if not ranges:
        raise InputError("no executable code found in the ELF")
    return arch, ranges, _function_symbols(d, secs, place, every, bounds)


def _code_bases(secs):
    """{section index: address} of the executable sections of a relocatable ELF, laid out one after another from
    0x100000 (load_elf())."""
    bases, base = {}, 0x100000
    for i, s in enumerate(secs):
        if s[2] & SHF_EXECINSTR and s[5] and s[1] != SHT_NOBITS:
            bases[i] = base
            base += (s[5] + 0x1fff) & ~0xfff
    return bases


def _symbols(d, secs):
    """(section index, value, size, type) of the STT_FUNC and STT_OBJECT symbols."""
    out = []
    for s in secs:
        if s[1] != SHT_SYMTAB:
            continue
        for off in range(s[4], min(s[4] + s[5], len(d) - 23), 24):
            _nm, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, off)
            if info & 15 in (STT_OBJECT, STT_FUNC):
                out.append((shndx, value, size, info & 15))
    return out


def slot_offsets(d, wanted):
    """{function address in wanted: {byte offset of each 8-byte slot holding it inside a static object}}, from an ELF
    (kcfi_types.rank_slots()). A linked image (a vmlinux, vmlinux-to-elf output): every 8-aligned word of its loaded
    segments, each slot in the nearest STT_FUNC or STT_OBJECT symbol at or below it, kept when that one is an object.
    A relocatable one (.o, .ko): the 64-bit absolute relocations into its allocated sections that are not code, which
    point at a function where load_elf() lays the code out, each in the object of its section that holds it. {} for
    anything else (a raw image: no symbols)."""
    if len(d) < 64 or d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1 or not wanted:
        return {}
    e_type, machine = struct.unpack_from("<HH", d, 0x10)
    try:
        secs = _sections(d)
    except InputError:
        return {}
    stored, symbols = [], []
    if e_type == 1:
        code = _code_bases(secs)
        data, base = {}, 1 << 40        # data sections: far from the code and from each other
        for i, s in enumerate(secs):
            if s[2] & SHF_ALLOC and i not in code:
                data[i] = base
                symbols.append((base, 0, False))        # a section start ends the objects of the one before
                base += (s[5] + 0xffff) & ~0xfff
        symbols += [(data[n] + v, z, t == STT_OBJECT) for n, v, z, t in _symbols(d, secs) if n in data]
        abs64 = R_ABS64.get(machine)
        for s in secs:
            if s[1] != SHT_RELA or s[7] not in data or s[6] >= len(secs):
                continue
            symtab = secs[s[6]]
            for off in range(s[4], min(s[4] + s[5], len(d) - 23), 24):
                r_offset, r_info, addend = struct.unpack_from("<QQq", d, off)
                if r_info & 0xffffffff != abs64:
                    continue
                at = symtab[4] + 24 * (r_info >> 32)
                if at + 24 > len(d):
                    continue
                shndx, value = struct.unpack_from("<HQ", d, at + 6)
                if shndx in code and code[shndx] + value + addend in wanted:
                    stored.append((data[s[7]] + r_offset, code[shndx] + value + addend))
    else:
        symbols = [(v, z, t == STT_OBJECT) for _n, v, z, t in _symbols(d, secs) if v]
        phoff = struct.unpack_from("<Q", d, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", d, 0x36)
        if not phoff or phentsize != 56 or phoff + 56 * phnum > len(d):
            return {}
        for i in range(phnum):
            p_type, _fl, p_offset, p_vaddr, _pa, p_filesz, _memsz, _al = struct.unpack_from("<IIQQQQQQ", d, phoff + 56 * i)
            if p_type != PT_LOAD or not p_filesz:
                continue
            skip = -p_vaddr % 8
            start, end = p_offset + skip, min(p_offset + p_filesz, len(d))
            if end - start < 8:
                continue
            words = memoryview(d)[start:start + (end - start) // 8 * 8].cast("Q")
            if sys.byteorder != "little":
                words = array.array("Q", words)
                words.byteswap()
            base = p_vaddr + skip
            stored += [(base + 8 * k, v) for k, v in enumerate(words) if v in wanted]
    symbols.sort()
    return core.object_offsets(stored, symbols)


class Names:
    """Address -> 'name' or 'name+0x10' using the nearest function symbol below."""

    def __init__(self, symbols):
        self.by_ea = symbols
        self.eas = sorted(symbols)
        self.by_name = {}
        for ea, nm in sorted(symbols.items()):
            self.by_name.setdefault(nm, []).append(ea)

    def function(self, ea):
        """(start, end, name) of the symbol holding ea, the next symbol being its end; None if there is none."""
        i = bisect.bisect_right(self.eas, ea) - 1
        if i < 0 or i + 1 >= len(self.eas) or self.eas[i + 1] - self.eas[i] > 0x100000:
            return None
        return self.eas[i], self.eas[i + 1], self.by_ea[self.eas[i]]

    def __call__(self, ea):
        if ea in self.by_ea:
            return self.by_ea[ea]
        i = bisect.bisect_right(self.eas, ea) - 1
        if i >= 0 and ea - self.eas[i] < 0x100000:
            return "%s+0x%x" % (self.by_ea[self.eas[i]], ea - self.eas[i])
        return "0x%x" % ea


class Kernel:
    """--with: the functions of a kernel ELF (a vmlinux, or vmlinux-to-elf output) that carry the type hash of each
    kCFI call site of the input (a module), found as resolve() finds them, with the kernel's own text bounds."""

    def __init__(self, path, arch, sites, extra=()):
        """extra: more type hashes whose functions the kernel lists (self.extra; --implements)."""
        with open(path, "rb") as fh:
            data = fh.read()
        bounds = {}
        if data[:4] != b"\x7fELF":
            raise InputError("--with %s: not an ELF file; give the kernel as an ELF with symbols (a vmlinux, or the "
                             "output of vmlinux-to-elf)" % path)
        try:
            karch, kranges, symbols = load_elf(data, None, bounds)
        except (InputError, struct.error) as e:
            raise InputError("--with %s: %s" % (path, e))
        del data
        if karch != arch:
            raise InputError("--with %s: an %s file, the input is %s" % (path, karch, arch))
        self.label = os.path.basename(path)
        self.names = Names(symbols)
        by_hash, _ = core.preamble_index(kranges, arch, {s.hash for s in sites} | set(extra),
                                         sorted({s.disp for s in sites}), core.kernel_text(bounds))
        self.by_check = {s.check_ea: sorted(by_hash.get(s.hash, ())) for s in sites}
        self.extra = {h: sorted(by_hash.get(h, ())) for h in extra}

    def targets(self, site):
        return self.by_check.get(site.check_ea, [])

    def stats(self, sites):
        k = [self.targets(s) for s in sites]
        return {"file": self.label, "named_functions": len(self.names.by_ea),
                "sites_with_kernel_candidates": sum(1 for t in k if t),
                "sites_only_in_kernel": sum(1 for s, t in zip(sites, k) if t and not s.targets),
                "sites_in_neither": sum(1 for s, t in zip(sites, k) if not t and not s.targets)}


def parse_target(text, names):
    """A set of addresses: one for a number, every function of that name for a name."""
    try:
        return {int(text, 0)}
    except ValueError:
        pass
    if text in names.by_name:
        return set(names.by_name[text])
    raise InputError("unknown function %r (no such symbol; give an address instead)" % text)


def runtime_test(names, ranges):
    """in_runtime for core.callers: is the address in __cfi_check, or in a function with no blr/br (by symbols)?"""
    def in_runtime(ea):
        fn = names.function(ea)
        if fn is None:
            return False
        lo, hi, name = fn
        if name == core.RUNTIME_CHECK_FUNCTION:
            return True
        for base, mem in ranges:
            if base <= lo and hi <= base + len(mem):
                return not core.has_indirect_call(mem[lo - base:hi - base])
        return False
    return in_runtime


def _site_dict(s, names, limit, type_names=None, kernel=None, slots=False, callee=None):
    """slots: did the slot ranking run (kcfi_types.rank_slots(); not with --raw, which has no symbols)? callee: with
    --callers, a test of the function's addresses (callee_slot_backed)."""
    ordered = core.slot_first(s)        # the candidates stored in a slot of the call's member first (kCFI with BTF)
    out = {
        "call": "0x%x" % s.call_ea if s.call_ea else None,
        "check": "0x%x" % s.check_ea,
        "in": names(s.call_ea or s.check_ea),
        "hash": "0x%08x" % s.hash,
        "tail_call": s.is_tail,
        "candidates": len(s.targets),
        "targets": [{"ea": "0x%x" % t, "name": names(t)} for t in ordered[:limit]],
    }
    if kernel is not None:      # only with --with
        kt = kernel.targets(s)
        out["kernel_candidates"] = len(kt)
        out["kernel_targets"] = [{"ea": "0x%x" % t, "name": kernel.names(t)} for t in kt[:limit]]
    if s.kind == "kcfi" and type_names is not None:     # only with BTF: output is unchanged without it
        out["type"] = s.type_name
        out["type_mangled"] = s.type_mangled
        out["type_examples"] = sorted({e for _m, _r, ex in type_names.lookup(s.hash) for e in ex})
        # the struct member the call loads its pointer from (aarch64): named only when BTF has exactly one of the
        # call's type at that offset; members lists every one, member_offset is the load's byte offset (null: none)
        out["member"] = s.members[0] if len(s.members) == 1 else None
        out["members"] = list(s.members)
        out["member_offset"] = s.member_offset
        if slots:   # each candidate: stored in a slot of that member in the image's static data (listed first)?
            out["slot_backed_candidates"] = len(s.slot_backed)          # 'offset' or 'stride' below
            out["slot_stride_candidates"] = len(s.slot_stride)          # 'stride': only by array stride
            for t in out["targets"]:
                t["slot_backed"] = core.slot_kind(s, int(t["ea"], 16)) or False
            if callee is not None:      # --callers: is the function itself slot-backed for this call?
                kind = core.callee_slot(s, callee)[0]
                out["callee_slot_backed"] = kind if kind in ("offset", "stride") else False
    if s.kind != "kcfi":     # jump-table CFI: the hash is the 64-bit type id
        out["hash"] = "0x%016x" % s.type_id if s.type_id is not None else None
        out.update(_jt_dict(s))
        if s.extra_checks:
            out["other_checks"] = [dict(check="0x%x" % x.check_ea, **_jt_dict(x)) for x in s.extra_checks]
    return out


def _jt_dict(s):
    return {
        "kind": s.kind,
        "type_id": "0x%016x" % s.type_id if s.type_id is not None else None,
        "type": s.type_name,
        "type_mangled": s.type_mangled,
        "jump_table_range": ["0x%x" % s.jt_base, s.jt_count] if s.jt_count and s.jt_base else None,
        "note": s.note,
        "range_from": s.jt_range_from,
        "runtime_call": "0x%x" % s.runtime_call_ea if s.runtime_call_ea else None,
        "runtime_check": s.runtime_check,
    }


# Strings that only the pre-6.1 jump-table CFI leaves in a kernel image.
OLD_CFI_MARKERS = (b".cfi_jt", b"__cfi_check", b"CFI failure (target:")


def _site_line(s, names, limit, kernel=None, member_limit=3, callee=None):
    """One line of --sites or --callers (limit: names shown; 0, as for the head line of --targets, counts the slot
    groups instead). callee: with --callers, a test of the function's addresses: the line ends with whether a slot of the
    call's member holds it ('  [tcp_sendmsg: same type only]'), when the call ranks some candidates first."""
    where = "0x%x" % (s.call_ea or s.check_ea)
    shown = ", ".join(names(t) for t in s.targets[:limit])
    more = " ..." if len(s.targets) > limit else ""
    kind = "jump" if s.is_tail else "call"
    if s.kind != "kcfi":
        kind = "%s %s" % (kind if s.call_ea else core.unlinked_label(s), s.kind)
        if s.kind == "slowpath" and not s.targets:
            count = "no candidate in this image (%s)" % (s.note or "module functions only")
        else:
            count = "%d candidate(s)" % len(s.targets)
        return "%s  %-40s %s %s  %s%s%s" % (
            where, names(s.call_ea or s.check_ea), kind, type_label(s) or "type unknown", count,
            ": " if shown else "", shown + more)
    typed = " (%s)" % s.type_name if s.type_name else ""
    member = core.member_label(s, member_limit)     # the struct member it calls through (aarch64, with BTF)
    if member:
        kind += " " + member
    count = "%d candidate(s)" % len(s.targets)
    if s.slot_backed:       # stored in a slot of that member: named first; the rest named too when the list fits
        if limit:
            shown, more = core.slot_text(s, core.slot_first(s), names, limit), ""
        else:
            count += ", " + core.slot_counts(s)
    line = "%s  %-40s %s hash 0x%08x%s  %s%s%s" % (
        where, names(s.call_ea or s.check_ea), kind, s.hash, typed, count,
        ": " if shown else "", shown + more)
    if kernel is not None:      # --with: the kernel's functions of this type
        kt = kernel.targets(s)
        shown = ", ".join(kernel.names(t) for t in kt[:limit])
        line += "; in %s %d%s%s" % (kernel.label, len(kt), ": " if shown else "",
                                    shown + (" ..." if len(kt) > limit else ""))
    if callee is not None:
        kind, t = core.callee_slot(s, callee)
        if kind:
            line += "  [%s: %s]" % (names(t), core.slot_label(s) if kind == "offset" else core.BY_STRIDE
                                    if kind == "stride" else core.SAME_TYPE_ONLY)
    return line


def _print_jt_summary(st):
    jt = st["jump_table"]
    print("arch %s, %d named functions" % (st["arch"], st["named_functions"]))
    print("Linux 5.x jump-table CFI: jump table %s-%s, %d entries of %d bytes"
          % (jt["start"], jt["end"], jt["entries"], jt["entry_size"]))
    print("checked sites %d: range checks %d, single-member checks %d, slow path only %d (type ids %d; checks named from __typeid symbols %d)"
          % (st["sites"], st["range_sites"], st["single_sites"], st["slowpath_sites"], st["hashes"],
             st.get("named_checks", 0)))
    print("indirect calls (blr/br) %d, with candidates %d" % (st["indirect_calls"], st["calls_with_candidates"]))
    print("sites with candidates %d, none %d, exactly one %d" % (st["resolved"], st["unresolved"], st["single_target"]))
    print("median candidates per site with candidates %d (over all sites %d), max %d"
          % (st["median_candidates_resolved"], st["median_candidates"], st["max_candidates"]))


def _relocatable(a, data):
    """Is the input a relocatable ELF (.o, .ko), the only kind that carries split BTF?"""
    return not a.raw and data[:4] == b"\x7fELF" and len(data) >= 18 and struct.unpack_from("<H", data, 16)[0] == 1


def _type_names(a, data, sites=True, keep_btf=False):
    """kcfi_types.TypeNames from --btf, else from the input's own BTF; None if there is none.  A module's own split
    BTF is read on top of --btf (its kernel's BTF), which it continues, when there is a call site to name (review
    s189 NIT 7: no split-BTF warning on a module with none). keep_btf: kcfi_types.TypeNames (--implements struct.member)."""
    if a.btf:
        with open(a.btf, "rb") as fh:
            btf_data = fh.read()
        if sites and _relocatable(a, data) and not a.no_btf:
            try:
                names = kcfi_types.load_split_type_names(data, btf_data, keep_btf)
            except (kcfi_types.BTFError, struct.error) as e:
                print("cfiscope: the module's BTF was not read (%s); kCFI hashes named from %s alone"
                      % (e, a.btf), file=sys.stderr)
                names = None
            if names is not None:
                return names
        try:
            names = kcfi_types.load_type_names(btf_data, keep_btf)
        except (kcfi_types.BTFError, struct.error) as e:
            raise InputError("%s: unreadable BTF (%s)" % (a.btf, e))
        if names is None:
            raise InputError("%s: no BTF found (no .BTF section, BTF header or raw BTF)" % a.btf)
        return names
    if a.no_btf:
        return None
    if _relocatable(a, data) and kcfi_types.has_split_btf(data):
        print("cfiscope: this module's BTF is split BTF (it continues its kernel's BTF): add --btf with its kernel "
              "(a vmlinux or raw Image of the same build) to name kCFI hashes by C type", file=sys.stderr)
        return None
    try:
        return kcfi_types.load_type_names(data, keep_btf)
    except (kcfi_types.BTFError, struct.error) as e:
        print("cfiscope: the input's BTF is unreadable, kCFI hashes not named (%s)" % e, file=sys.stderr)
        return None


_HASH_SPEC = re.compile(r"0[xX][0-9a-fA-F]+\Z")
_MEMBER_SPEC = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+\Z")
SPEC_FORMS = ("struct.member, a C function type as this tool prints types such as 'long (struct file *, unsigned int, "
              "unsigned long)', a mangled type such as _ZTSFlP4filejmE, a hash such as 0x1ebda935, or a function's name")


def _implements_disps(arch, sites, stats):
    """The offsets at which --implements reads the type hash in front of a function: those of the input's kCFI checks;
    with none, aarch64's (core.DEFAULT_DISPS, with a note) when the code makes no indirect call either (a kCFI module
    may make none: GKI zram.ko). InputError for jump-table CFI, for aarch64 code with indirect calls but no check (not
    built with kCFI), and for x86-64 with no check (where x86-64 kernels keep the hash differs)."""
    if stats.get("scheme") == "jump-table CFI":
        raise InputError("--implements is for kCFI: this kernel uses the jump-table CFI of Linux 5.x, whose functions "
                         "carry no type hash in front of them")
    if sites:
        return stats["disps"]
    if stats.get("blr_instructions"):
        raise InputError("--implements: this input makes %d indirect calls (blr) and no kCFI check guards them: it is "
                         "not built with kCFI (CONFIG_CFI_CLANG), so its functions carry no type hash"
                         % stats["blr_instructions"])
    if arch not in core.DEFAULT_DISPS:
        raise InputError("--implements: no kCFI check in this input, so it may not be built with kCFI, and where it "
                         "would keep the type hash in front of a function is not known (x86-64 kernels differ)")
    print("cfiscope: no kCFI check in this input (and no indirect call, so whether it is built with kCFI cannot be "
          "told): the type hash is read from the word before each function, where aarch64 kCFI keeps it",
          file=sys.stderr)
    return core.DEFAULT_DISPS[arch]


def _needs_btf(spec, what):
    return ("--implements %s needs BTF to read the %s's kCFI hash, and none was read (add --btf PATH: a vmlinux or raw "
            "Image of the same build), or give the hash (such as 0x1ebda935)" % (spec, what))


def _spec_hashes(spec, names, ranges, arch, sites, disps, type_names):
    """(kind, member or function named by SPEC or None, [(kCFI hash, mangled name or None)]) for --implements, kind one
    of "hash", "type", "function", "member": one hash for a hash or a mangled type; for a C type or a struct member
    (from BTF), the plain and the integer-normalized mangling of each match (main() keeps those the input uses, then
    _pick_hash() one); for a function, the hash in front of it (core.preamble_hash(), when core.hash_evidence() takes
    it). InputError when SPEC names none."""
    text = spec.strip()
    if _HASH_SPEC.match(text):
        if int(text, 16) >> 32:
            raise InputError("--implements %s: a kCFI hash has 32 bits" % text)
        return "hash", None, [(int(text, 16), None)]
    if text.startswith("_ZTS"):
        return "type", None, [(kcfi_types.kcfi_hash(text), text)]
    if "(" in text:
        if type_names is None:
            raise InputError(_needs_btf(repr(text), "type"))
        found = type_names.type_candidates(text)
        if not found:
            raise InputError("--implements: no function type %r in BTF (write it as this tool prints types, e.g. 'long "
                             "(struct file *, unsigned int, unsigned long)', or give its hash)" % text)
        return "type", None, found
    if text in names.by_name:
        checked = {s.hash for s in sites if s.kind == "kcfi"}
        named = type_names.by_hash if type_names is not None else ()
        found = []
        for ea in names.by_name[text]:
            h = core.preamble_hash(ranges, arch, ea, disps)
            if h is not None and core.hash_evidence(h, arch, checked, named) and (h, None) not in found:
                found.append((h, None))
        if not found:
            raise InputError("--implements: no kCFI hash in front of %s (a function whose address is never taken, such "
                             "as a static one, has none)" % text)
        return "function", text, found
    if _MEMBER_SPEC.match(text):
        if type_names is None or type_names.btf is None:
            raise InputError(_needs_btf(text, "member"))
        try:
            return "member", text, kcfi_types.member_candidates(type_names.btf, text)
        except kcfi_types.SpecError as e:
            raise InputError("--implements: %s" % e)
    raise InputError("--implements %r: no struct member, C function type, hash or function of that name (give %s)"
                     % (spec, SPEC_FORMS))


def _pick_hash(spec, cands, found):
    """The (hash, mangled) of cands (in order of preference) that some function carries (found: hash -> functions),
    else the first. InputError when functions here carry several of them."""
    used = [c for c in cands if found(c[0])]
    if len({h for h, _m in used}) > 1:
        raise InputError("--implements %s names %d types that functions here carry (%s): give one hash"
                         % (spec, len({h for h, _m in used}), ", ".join(sorted({"0x%08x" % h for h, _m in used}))))
    return (used or cands)[0]


def _implements_header(count, h, type_name, label):
    return "%d function(s) with kCFI hash 0x%08x%s%s" % (count, h, " (%s)" % type_name if type_name else "",
                                                        ", the type of %s" % label if label else "")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m cfiscope",
                                 description="Resolve kCFI (and aarch64 Linux 5.x jump-table CFI) indirect calls "
                                             "in a kernel image without IDA.")
    ap.add_argument("input", help="ELF (vmlinux, .o, .ko) or, with --raw, a raw kernel image")
    ap.add_argument("--raw", action="store_true", help="input is raw code bytes (needs --arch and --base)")
    ap.add_argument("--arch", choices=["x86_64", "aarch64"], help="architecture for --raw")
    ap.add_argument("--base", type=lambda v: int(v, 0), help="load address for --raw, e.g. 0xffffffc008000000")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--sites", action="store_true", help="list every call site with its candidates")
    mode.add_argument("--callers", metavar="FUNC",
                      help="call sites that can reach FUNC (name or address); with --with, a name that is not the "
                           "module's is looked up in the kernel (the module's own symbol wins; an address is the "
                           "module's)")
    mode.add_argument("--targets", metavar="ADDR", help="candidates for the call or check at ADDR")
    mode.add_argument("--implements", metavar="SPEC",
                      help="every function whose kCFI preamble hash is that of SPEC, whether or not a call site "
                           "checks it: " + SPEC_FORMS + " (its own type); a member or C type needs BTF")
    ap.add_argument("--max-list", type=int, default=None,
                    help="names shown per site (default: 8 in text, all with --json); a list that has candidates "
                         "stored in a slot of the call's member names every candidate when it fits, else up to this "
                         "many of those and counts the rest (--targets lists every candidate; --implements lists "
                         "every function unless given)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--btf", metavar="PATH",
                    help="name kCFI hashes by C function type from this BTF: an ELF with a .BTF section, a raw "
                         "kernel image, or a raw BTF file (default: the input's own BTF, if it has any)")
    ap.add_argument("--no-btf", action="store_true", help="do not look for BTF in the input")
    ap.add_argument("--with", dest="with_kernel", metavar="VMLINUX",
                    help="for a module (.ko): also list, for each call site, the functions of this kernel ELF (a "
                         "vmlinux or vmlinux-to-elf output, the module's own kernel build) with the call's type hash")
    a = ap.parse_args(argv)

    try:
        with open(a.input, "rb") as fh:
            data = fh.read()
        if a.raw:
            if a.arch is None or a.base is None:
                raise InputError("--raw needs --arch and --base")
            arch, ranges, symbols, every, bounds = a.arch, [(a.base, data)], {}, [], {}
        else:
            every, bounds = [], {}
            arch, ranges, symbols = load_elf(data, every, bounds)
        names = Names(symbols)
        sites, stats = resolve(ranges, arch, core.kernel_text(bounds))
        stats = dict(stats, arch=arch, named_functions=len(symbols))
        if stats.get("scheme") == "jump-table CFI":
            stats["named_checks"] = name_jt_types(sites, every)
        # review s176 N3: the input's own BTF is read only when there is a kCFI call to name (--btf is always read)
        implementing = a.implements is not None
        type_names = (_type_names(a, data, bool(sites) or implementing, implementing)
                      if stats.get("scheme") != "jump-table CFI" and (a.btf or sites or implementing) else None)
        if a.btf and stats.get("scheme") == "jump-table CFI":  # review s176 N2: say so instead of ignoring it silently
            print("cfiscope: --btf is for kCFI type hashes; ignored for this jump-table CFI kernel", file=sys.stderr)
        if type_names is not None:
            stats["kcfi_hashes_named"], _ = kcfi_types.name_sites(sites, type_names)
            stats["btf_prototypes"] = type_names.protos
            if arch == "aarch64" and not implementing:    # the member each call loads its pointer from (x86-64: no)
                stats.update(kcfi_types.name_members(sites, ranges, arch, type_names))
                if not a.raw and any(s.members for s in sites):   # its candidates stored in a slot of that member first
                    wanted = {t for s in sites if s.kind == "kcfi" for t in s.targets}
                    stats.update(kcfi_types.rank_slots(sites, slot_offsets(data, wanted), type_names))
        cands = disps = None
        if implementing:        # the spec's hash(es), before --with so that the kernel lists their functions too
            disps = _implements_disps(arch, sites, stats)
            kind, label, cands = _spec_hashes(a.implements, names, ranges, arch, sites, disps, type_names)
            normalized = kcfi_types.normalized_scheme(sites)    # which mangling the input's call sites use, if known
            if normalized is not None:
                cands = [c for c in cands if c[1] is None or c[1].endswith(".normalized") == normalized] or cands
        kernel = None
        if a.with_kernel and stats.get("scheme") == "jump-table CFI":
            print("cfiscope: --with is for kCFI type hashes; ignored for this jump-table CFI kernel", file=sys.stderr)
        elif a.with_kernel and sites:
            kernel = Kernel(a.with_kernel, arch, sites, sorted({h for h, _m in cands or ()}))
            stats["kernel"] = kernel.stats(sites)
        elif a.with_kernel:      # review s189 NIT 4: say so instead of ignoring it silently (the file is not read)
            print("cfiscope: --with ignored: this input has no kCFI call site (%s not read)" % a.with_kernel,
                  file=sys.stderr)
        if implementing:
            text = core.kernel_text(bounds)
            fns = {}
            for h, _m in cands:
                if h not in fns:
                    fns[h] = core.implementations(ranges, arch, h, disps, sites, text)
            h, mangled = _pick_hash(a.implements, cands, fns.get)
        kwant = None      # --callers of a kernel function (--with): its addresses in the kernel
        if a.callers or a.targets:
            try:
                want = parse_target(a.callers or a.targets, names)
            except InputError:
                if a.callers and kernel is not None:
                    try:
                        kwant, want = parse_target(a.callers, kernel.names), set()
                    except InputError:
                        raise InputError("unknown function %r (not in this module nor in %s; give an address "
                                         "instead)" % (a.callers, kernel.label))
                elif a.callers and not a.with_kernel and _relocatable(a, data):  # review s189 MINOR 2
                    raise InputError("unknown function %r (no such symbol in this module; a kernel function? add "
                                     "--with VMLINUX, its kernel ELF; or give an address)" % a.callers)
                else:
                    raise
    except (OSError, InputError, ValueError, OverflowError, struct.error) as e:
        print("cfiscope: %s" % e, file=sys.stderr)
        return 2

    if implementing:
        found = type_names.lookup(h) if type_names is not None else []
        type_name = " | ".join(r for _m, r, _e in found) or None
        type_mangled = " | ".join(m for m, _r, _e in found) or mangled
        limit = None if a.max_list is None else max(a.max_list, 0)       # None: every function
        kt = kernel.extra[h] if kernel is not None else None
        if a.json:
            doc = {"spec": a.implements, "member": label if kind == "member" else None,
                   "hash": "0x%08x" % h, "type": type_name, "type_mangled": type_mangled, "functions": len(fns[h]),
                   "targets": [{"ea": "0x%x" % t, "name": names(t)} for t in fns[h][:limit]]}
            if kt is not None:
                doc["kernel_functions"] = len(kt)
                doc["kernel_targets"] = [{"ea": "0x%x" % t, "name": kernel.names(t)} for t in kt[:limit]]
            json.dump({"stats": stats, "implements": doc}, sys.stdout, indent=1)
            print()
            return 0
        print(_implements_header(len(fns[h]), h, type_name, label))
        groups = [(fns[h], names)]
        if kt is not None:          # --with: the kernel's functions of that type, as --targets lists them
            groups.append((kt, kernel.names))
        for k, (group, name) in enumerate(groups):
            if k:
                print("  in %s (%d):" % (kernel.label, len(group)))
            for t in group[:limit]:
                print("    0x%x  %s" % (t, name(t)))
            if limit is not None and len(group) > limit:
                print("    ... %d more" % (len(group) - limit))
        return 0
    if a.callers and kwant is not None:
        calls, checks = [s for s in sites if kwant.intersection(kernel.targets(s))], []
        chosen = calls
        label = "%s (in %s%s)" % (a.callers, kernel.label,
                                  ", %d functions of that name" % len(kwant) if len(kwant) > 1 else "")
        header = core.callers_header(len(calls), 0, label)
    elif a.callers:
        # Call sites first; then type checks whose call was not linked (not counted); the CFI runtime's own checks
        # (in __cfi_check: they guard no call) are left out.
        calls, checks = core.callers(sites, want.__contains__, runtime_test(names, ranges))
        calls = core.slot_callers_first(calls, want.__contains__)   # those whose member slot holds the function first
        chosen = calls + checks
        label = a.callers if len(want) > 1 else names(min(want))
        if len(want) > 1:
            label += " (%d functions of that name)" % len(want)
        if kernel is not None and a.callers in kernel.names.by_name:  # review s189 MINOR 3: the module's name wins
            label += " (in this module; %s also has a function of that name, not searched)" % kernel.label
        header = core.callers_header(len(calls), len(checks), label)
    elif a.targets:
        chosen = [s for s in sites if want & {s.call_ea, s.check_ea}]
        if not chosen:
            print("cfiscope: no %s check or call at %s"
                  % ("CFI" if stats.get("scheme") else "kCFI", a.targets), file=sys.stderr)
            return 1
        header = "candidates for the site at %s" % a.targets
    elif a.sites:
        chosen, header = sites, None
    else:
        chosen, header = None, None

    if a.json:
        out = {"stats": stats}
        if a.callers:
            out["callers"] = {"call_sites": len(calls), "unlinked_checks": len(checks)}
            if kernel is not None:   # --with: where the name was found (the module's own symbol wins)
                out["callers"]["target_in"] = "kernel" if kwant is not None else "module"
        if chosen is not None:
            limit = 1 << 30 if a.targets or a.max_list is None else a.max_list
            callee = want.__contains__ if a.callers and kwant is None else None
            out["sites"] = [_site_dict(s, names, limit, type_names, kernel, "slot_calls" in stats, callee)
                            for s in chosen]
        json.dump(out, sys.stdout, indent=1)
        print()
        return 0
    if chosen is None and stats.get("scheme") == "jump-table CFI":
        _print_jt_summary(stats)
        return 0
    if chosen is None:
        st = stats
        print("arch %s, %d named functions" % (st["arch"], st["named_functions"]))
        print("call sites %d (type hashes %d)" % (st["sites"], st["hashes"]))
        print("with candidates %d, none %d, exactly one %d" % (st["resolved"], st["unresolved"], st["single_target"]))
        print("median candidates per site with candidates %d (over all sites %d), max %d"
              % (st["median_candidates_resolved"], st["median_candidates"], st["max_candidates"]))
        if "kcfi_hashes_named" in st and st["sites"]:
            print(kcfi_types.named_summary(st["kcfi_hashes_named"], st["hashes"])
                  + " from %d BTF function prototypes" % st["btf_prototypes"])
        if "member_offsets" in st and st["sites"]:
            print(kcfi_types.member_summary(st))
        if "slot_calls" in st and st["sites"]:
            print(kcfi_types.slot_summary(st))
        elif a.raw and any(s.members for s in sites):     # review s197: say what turns the slot ranking on
            print("slot ranking: needs the input's OBJECT symbols (an ELF such as vmlinux-to-elf output); not with --raw")
        if "outside_text" in st and st["sites"]:
            print("candidates outside kernel code left out: %d (between the _etext and _sinittext symbols, outside "
                  "the code areas named there)" % st["outside_text"])
        if "kernel" in st:
            print("with --with %(file)s (%(named_functions)d named functions): sites with candidates in the kernel "
                  "%(sites_with_kernel_candidates)d; with none in this file but some in the kernel "
                  "%(sites_only_in_kernel)d; in neither %(sites_in_neither)d" % st["kernel"])
        if not st["sites"] and any(m in data for m in OLD_CFI_MARKERS):
            print("no kCFI checks found: this kernel uses the older jump-table Clang CFI of Linux 5.x "
                  "(it contains .cfi_jt / __cfi_check), but CFIScope found no aarch64 jump table of 8-byte "
                  "`bti c; b` entries with checks that use it; it reads that form (as in Android 13 GKI 5.15), "
                  "not x86-64 or jump tables without BTI")
        elif not st["sites"] and st.get("blr_instructions") == 0:
            print("no kCFI checks found, and the code makes no indirect call (no blr instruction): kCFI has nothing "
                  "to check here, so this does not tell whether it was built with kCFI (a loadable module may "
                  "simply make no indirect call)" + (", or --arch/--base is wrong" if a.raw else ""))
        elif not st["sites"]:
            print("no kCFI checks found: this kernel was probably built without Clang kCFI "
                  "(CONFIG_CFI_CLANG on Linux 6.1 or later), for example by GCC; no aarch64 jump-table CFI "
                  "of Linux 5.x (Android 12/13 GKI) was found either"
                  + (", or --arch/--base is wrong" if a.raw else ""))
        return 0
    if header:
        print(header)
    if a.targets:
        for s in chosen:
            print(_site_line(s, names, 0, member_limit=None).rstrip(" ."))
            groups = core.slot_groups(s, core.slot_first(s)) if s.slot_backed else [(None, s.targets)]
            for label, group in groups:     # every candidate; those stored in a member slot first, under their group
                if label:
                    print("  %s:" % label)
                for t in group:
                    print("    0x%x  %s" % (t, names(t)))
            if kernel is not None:
                print("  in %s (%d):" % (kernel.label, len(kernel.targets(s))))
                for t in kernel.targets(s):
                    print("    0x%x  %s" % (t, kernel.names(t)))
        return 0
    callee = want.__contains__ if a.callers and kwant is None else None
    for s in chosen:
        print(_site_line(s, names, 8 if a.max_list is None else a.max_list, kernel, callee=callee))
    return 0
