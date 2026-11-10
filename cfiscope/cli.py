"""Command-line use of the CFIScope scanner, with no IDA.

    python3 -m cfiscope vmlinux                      # summary
    python3 -m cfiscope vmlinux --sites              # every call site and its candidates
    python3 -m cfiscope vmlinux --callers tcp_sendmsg
    python3 -m cfiscope vmlinux --targets 0xffffffc0081234a8
    python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000

Input is a 64-bit little-endian ELF (a vmlinux, or a kernel whose symbols
were restored with vmlinux-to-elf, or a relocatable .o/.ko), or a raw kernel
image with --raw.  Symbols, when the ELF has them, are used only to print
names; the scan itself reads code bytes alone.  Add --json for machine output.
"""
import argparse
import bisect
import json
import struct
import sys

from .core import resolve

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


def _function_symbols(d, secs, place):
    """Return {address: name} for STT_FUNC symbols; place(shndx, value) -> address or None."""
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
            if info & 15 != STT_FUNC or not nm:
                continue
            ea = place(shndx, value)
            if ea is None:
                continue
            start = strtab[4] + nm
            end = d.find(b"\0", start)
            if end < 0:
                continue
            names.setdefault(ea, d[start:end].decode("utf-8", "replace"))
    return names


def load_elf(d):
    """Return (arch, ranges, symbols) from a 64-bit little-endian ELF."""
    if len(d) < 64 or d[:4] != b"\x7fELF":
        raise InputError("not an ELF file (use --raw for a raw kernel image)")
    if d[4] != 2 or d[5] != 1:
        raise InputError("only 64-bit little-endian ELF is supported")
    e_type, machine = struct.unpack_from("<HH", d, 0x10)
    arch = ARCH_BY_MACHINE.get(machine)
    if arch is None:
        raise InputError("unsupported ELF machine %d (x86-64 and AArch64 only)" % machine)
    secs = _sections(d)
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
        if phoff and phentsize == 56:
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
    return arch, ranges, _function_symbols(d, secs, place)


class Names:
    """Address -> 'name' or 'name+0x10' using the nearest function symbol below."""

    def __init__(self, symbols):
        self.by_ea = symbols
        self.eas = sorted(symbols)
        self.by_name = {}
        for ea, nm in symbols.items():
            self.by_name.setdefault(nm, ea)

    def __call__(self, ea):
        if ea in self.by_ea:
            return self.by_ea[ea]
        i = bisect.bisect_right(self.eas, ea) - 1
        if i >= 0 and ea - self.eas[i] < 0x100000:
            return "%s+0x%x" % (self.by_ea[self.eas[i]], ea - self.eas[i])
        return "0x%x" % ea


def parse_target(text, names):
    try:
        return int(text, 0)
    except ValueError:
        pass
    if text in names.by_name:
        return names.by_name[text]
    raise InputError("unknown function %r (no such symbol; give an address instead)" % text)


def _site_dict(s, names, limit):
    return {
        "call": "0x%x" % s.call_ea if s.call_ea else None,
        "check": "0x%x" % s.check_ea,
        "in": names(s.check_ea),
        "hash": "0x%08x" % s.hash,
        "tail_call": s.is_tail,
        "candidates": len(s.targets),
        "targets": [{"ea": "0x%x" % t, "name": names(t)} for t in s.targets[:limit]],
    }


def _site_line(s, names, limit):
    where = "0x%x" % (s.call_ea or s.check_ea)
    shown = ", ".join(names(t) for t in s.targets[:limit])
    more = " ..." if len(s.targets) > limit else ""
    kind = "jump" if s.is_tail else "call"
    return "%s  %-40s %s hash 0x%08x  %d candidate(s)%s%s" % (
        where, names(s.check_ea), kind, s.hash, len(s.targets),
        ": " if shown else "", shown + more)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python3 -m cfiscope",
                                 description="Resolve kCFI indirect calls in a kernel image without IDA.")
    ap.add_argument("input", help="ELF (vmlinux, .o, .ko) or, with --raw, a raw kernel image")
    ap.add_argument("--raw", action="store_true", help="input is raw code bytes (needs --arch and --base)")
    ap.add_argument("--arch", choices=["x86_64", "aarch64"], help="architecture for --raw")
    ap.add_argument("--base", type=lambda v: int(v, 0), help="load address for --raw, e.g. 0xffffffc008000000")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--sites", action="store_true", help="list every call site with its candidates")
    mode.add_argument("--callers", metavar="FUNC", help="call sites that can reach FUNC (name or address)")
    mode.add_argument("--targets", metavar="ADDR", help="candidates for the call or check at ADDR")
    ap.add_argument("--max-list", type=int, default=8, help="candidates shown per site (default 8)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)

    try:
        with open(a.input, "rb") as fh:
            data = fh.read()
        if a.raw:
            if a.arch is None or a.base is None:
                raise InputError("--raw needs --arch and --base")
            arch, ranges, symbols = a.arch, [(a.base, data)], {}
        else:
            arch, ranges, symbols = load_elf(data)
        names = Names(symbols)
        sites, stats = resolve(ranges, arch)
        stats = dict(stats, arch=arch, named_functions=len(symbols))
        if a.callers or a.targets:
            want = parse_target(a.callers or a.targets, names)
    except (OSError, InputError, ValueError, struct.error) as e:
        print("cfiscope: %s" % e, file=sys.stderr)
        return 2

    if a.callers:
        chosen = [s for s in sites if want in s.targets]
        header = "%d call site(s) can reach %s" % (len(chosen), names(want))
    elif a.targets:
        chosen = [s for s in sites if want in (s.call_ea, s.check_ea)]
        if not chosen:
            print("cfiscope: no kCFI check or call at 0x%x" % want, file=sys.stderr)
            return 1
        header = "candidates for the site at 0x%x" % want
    elif a.sites:
        chosen, header = sites, None
    else:
        chosen, header = None, None

    if a.json:
        out = {"stats": stats}
        if chosen is not None:
            limit = 1 << 30 if a.targets else a.max_list
            out["sites"] = [_site_dict(s, names, limit) for s in chosen]
        json.dump(out, sys.stdout, indent=1)
        print()
        return 0
    if chosen is None:
        st = stats
        print("arch %s, %d named functions" % (st["arch"], st["named_functions"]))
        print("call sites %d (type hashes %d)" % (st["sites"], st["hashes"]))
        print("with candidates %d, none %d, exactly one %d" % (st["resolved"], st["unresolved"], st["single_target"]))
        print("median candidates %d, max %d" % (st["median_candidates"], st["max_candidates"]))
        if not st["sites"]:
            print("no kCFI checks found: this kernel was probably built without Clang kCFI "
                  "(CONFIG_CFI_CLANG), for example by GCC" + (", or --arch/--base is wrong" if a.raw else ""))
        return 0
    if header:
        print(header)
    if a.targets:
        for s in chosen:
            print(_site_line(s, names, 0))
            for t in s.targets:
                print("    0x%x  %s" % (t, names(t)))
        return 0
    for s in chosen:
        print(_site_line(s, names, a.max_list))
    return 0
