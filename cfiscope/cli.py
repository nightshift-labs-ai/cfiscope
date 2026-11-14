"""Command-line use of the CFIScope scanner, with no IDA.

    python3 -m cfiscope vmlinux                      # summary
    python3 -m cfiscope vmlinux --sites              # every call site and its candidates
    python3 -m cfiscope vmlinux --callers tcp_sendmsg
    python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
    python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
    python3 -m cfiscope vmlinux --sites --btf vmlinux.btf   # name kCFI hashes by C type

Input is a 64-bit little-endian ELF (a vmlinux, or a kernel whose symbols
were restored with vmlinux-to-elf, or a relocatable .o/.ko), or a raw kernel
image with --raw.  Symbols print names and, when the ELF names _stext,
_etext, _sinittext and _einittext, leave out kCFI candidates between _etext
and _sinittext outside the code areas named there (core.kernel_text()); the
scan itself reads code bytes alone.  Add --json for machine output.
kCFI hashes are named by their C function type when BTF is available: from
--btf (an ELF with a .BTF section, a raw kernel image, or a raw BTF file), or
else from the input itself when it carries BTF (--no-btf turns that off).
"""
import argparse
import bisect
import json
import struct
import sys

from . import core, kcfi_types
from .core import name_jt_types, resolve, type_label

EM_X86_64, EM_AARCH64 = 62, 183
ARCH_BY_MACHINE = {EM_X86_64: "x86_64", EM_AARCH64: "aarch64"}
PT_LOAD, PF_X = 1, 1
SHT_SYMTAB, SHF_EXECINSTR = 2, 4
STT_FUNC = 2


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
        bases, base = {}, 0x100000
        for i, s in enumerate(secs):
            if s[2] & SHF_EXECINSTR and s[5] and s[1] != 8:  # skip NOBITS
                bases[i] = base
                ranges.append((base, d[s[4]:s[4] + s[5]]))
                base += (s[5] + 0x1fff) & ~0xfff

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


def _site_dict(s, names, limit, type_names=None):
    out = {
        "call": "0x%x" % s.call_ea if s.call_ea else None,
        "check": "0x%x" % s.check_ea,
        "in": names(s.call_ea or s.check_ea),
        "hash": "0x%08x" % s.hash,
        "tail_call": s.is_tail,
        "candidates": len(s.targets),
        "targets": [{"ea": "0x%x" % t, "name": names(t)} for t in s.targets[:limit]],
    }
    if s.kind == "kcfi" and type_names is not None:     # only with BTF: output is unchanged without it
        out["type"] = s.type_name
        out["type_mangled"] = s.type_mangled
        out["type_examples"] = sorted({e for _m, _r, ex in type_names.lookup(s.hash) for e in ex})
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


def _site_line(s, names, limit):
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
    return "%s  %-40s %s hash 0x%08x%s  %d candidate(s)%s%s" % (
        where, names(s.call_ea or s.check_ea), kind, s.hash, typed, len(s.targets),
        ": " if shown else "", shown + more)


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


def _type_names(a, data):
    """kcfi_types.TypeNames from --btf, else from the input's own BTF; None if there is none."""
    if a.btf:
        with open(a.btf, "rb") as fh:
            btf_data = fh.read()
        try:
            names = kcfi_types.load_type_names(btf_data)
        except (kcfi_types.BTFError, struct.error) as e:
            raise InputError("%s: unreadable BTF (%s)" % (a.btf, e))
        if names is None:
            raise InputError("%s: no BTF found (no .BTF section, BTF header or raw BTF)" % a.btf)
        return names
    if a.no_btf:
        return None
    try:
        return kcfi_types.load_type_names(data)
    except (kcfi_types.BTFError, struct.error) as e:
        print("cfiscope: the input's BTF is unreadable, kCFI hashes not named (%s)" % e, file=sys.stderr)
        return None


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
    mode.add_argument("--callers", metavar="FUNC", help="call sites that can reach FUNC (name or address)")
    mode.add_argument("--targets", metavar="ADDR", help="candidates for the call or check at ADDR")
    ap.add_argument("--max-list", type=int, default=None,
                    help="candidates shown per site (default: 8 in text, all with --json)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--btf", metavar="PATH",
                    help="name kCFI hashes by C function type from this BTF: an ELF with a .BTF section, a raw "
                         "kernel image, or a raw BTF file (default: the input's own BTF, if it has any)")
    ap.add_argument("--no-btf", action="store_true", help="do not look for BTF in the input")
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
        type_names = (_type_names(a, data) if stats.get("scheme") != "jump-table CFI" and (a.btf or sites)
                      else None)
        if a.btf and stats.get("scheme") == "jump-table CFI":  # review s176 N2: say so instead of ignoring it silently
            print("cfiscope: --btf is for kCFI type hashes; ignored for this jump-table CFI kernel", file=sys.stderr)
        if type_names is not None:
            stats["kcfi_hashes_named"], _ = kcfi_types.name_sites(sites, type_names)
            stats["btf_prototypes"] = type_names.protos
        if a.callers or a.targets:
            want = parse_target(a.callers or a.targets, names)
    except (OSError, InputError, ValueError, OverflowError, struct.error) as e:
        print("cfiscope: %s" % e, file=sys.stderr)
        return 2

    if a.callers:
        # Call sites first; then type checks whose call was not linked (not counted); the CFI runtime's own checks
        # (in __cfi_check: they guard no call) are left out.
        calls, checks = core.callers(sites, want.__contains__, runtime_test(names, ranges))
        chosen = calls + checks
        label = a.callers if len(want) > 1 else names(min(want))
        if len(want) > 1:
            label += " (%d functions of that name)" % len(want)
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
        if chosen is not None:
            limit = 1 << 30 if a.targets or a.max_list is None else a.max_list
            out["sites"] = [_site_dict(s, names, limit, type_names) for s in chosen]
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
        if "outside_text" in st and st["sites"]:
            print("candidates outside kernel code left out: %d (between the _etext and _sinittext symbols, outside "
                  "the code areas named there)" % st["outside_text"])
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
            print(_site_line(s, names, 0).rstrip(" ."))
            for t in s.targets:
                print("    0x%x  %s" % (t, names(t)))
        return 0
    for s in chosen:
        print(_site_line(s, names, 8 if a.max_list is None else a.max_list))
    return 0
