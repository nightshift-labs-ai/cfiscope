"""kCFI call-site and target recovery. Pure Python, no IDA imports.

Clang's -fsanitize=kcfi (Linux CONFIG_CFI_CLANG, Android GKI) leaves a 32-bit
function-type hash in front of every function and compares it at every
indirect call.  Both ends survive in a stripped binary, so matching them gives
the set of functions a given indirect call may reach.
"""
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field

X86_SITE = re.compile(
    rb"\x41\xba(.{4})([\x44\x45])\x03([\x40-\x7f])", re.DOTALL)
A64_ANCHOR = re.compile(rb"\x40\x00\x00\x54..[\x30\x31]\xd4", re.DOTALL)


@dataclass
class Site:
    check_ea: int          # first instruction of the check
    call_ea: int           # the indirect call/jump (0 if not recognised)
    hash: int
    disp: int              # hash offset from the target, negative
    is_tail: bool = False  # jump rather than call
    targets: list = field(default_factory=list)


def _s8(v):
    return v - 256 if v > 127 else v


def _x86_site(mem, base, m):
    hash_ = (-struct.unpack("<I", m.group(1))[0]) & 0xffffffff
    modrm = m.group(3)[0]
    if (modrm >> 3) & 7 != 2:      # destination must be r10d
        return None
    if modrm & 7 == 4:             # SIB form: rsp/r12 base
        disp_at = m.end() + 1
    else:
        disp_at = m.end()
    if disp_at >= len(mem):
        return None
    disp = _s8(mem[disp_at])
    p = disp_at + 1
    # je over ud2: short (74 02) or near (0f 84 02 00 00 00)
    if mem[p:p + 2] == b"\x74\x02":
        p += 2
    elif mem[p:p + 6] == b"\x0f\x84\x02\x00\x00\x00":
        p += 6
    else:
        return None
    if mem[p:p + 2] != b"\x0f\x0b":
        return None
    p += 2
    call_ea, tail = 0, False
    q = p
    if q < len(mem) and mem[q] == 0x2e:      # cs prefix used by retpoline thunks
        q += 1
    if q < len(mem) and mem[q] in (0x41, 0x40):
        q += 1
    if q + 1 < len(mem) and mem[q] == 0xff:
        op = (mem[q + 1] >> 3) & 7
        if op in (2, 4):
            call_ea, tail = base + p, op == 4
    elif q < len(mem) and mem[q] in (0xe8, 0xe9):   # direct call to a thunk
        call_ea, tail = base + p, mem[q] == 0xe9
    return Site(base + m.start(), call_ea, hash_, disp, tail)


def _a64_site(mem, base, m):
    if m.start() % 4 or m.start() < 16 or m.end() + 4 > len(mem):
        return None
    ldur, lo, hi, cmp_ = struct.unpack_from("<4I", mem, m.start() - 16)
    if ldur & 0xffe00c00 != 0xb8400000:           # ldur wT, [xN, #imm9]
        return None
    wt = ldur & 31
    imm9 = (ldur >> 12) & 0x1ff
    disp = imm9 - 512 if imm9 & 0x100 else imm9
    if lo & 0xffe00000 != 0x72800000 or hi & 0xffe00000 != 0x72a00000:
        return None
    rd = lo & 31
    if hi & 31 != rd:
        return None
    if cmp_ != 0x6b00001f | (rd << 16) | (wt << 5):
        return None
    hash_ = ((lo >> 5) & 0xffff) | (((hi >> 5) & 0xffff) << 16)
    branch = struct.unpack_from("<I", mem, m.end())[0]
    # br / blr / braa(z) / blraa(z) families
    opc = branch & 0xfe9ff800
    call_ea, tail = 0, False
    if opc == 0xd61f0000 or opc == 0xd61f0800:
        is_link = bool(branch & (1 << 21))
        call_ea, tail = base + m.end(), not is_link
    return Site(base + m.start() - 16, call_ea, hash_, disp, tail)


def scan_sites(mem, base, arch):
    """Return every kCFI check in one contiguous code range."""
    mem = bytes(mem)
    out = []
    if arch == "x86_64":
        for m in X86_SITE.finditer(mem):
            s = _x86_site(mem, base, m)
            if s:
                out.append(s)
    elif arch == "aarch64":
        for m in A64_ANCHOR.finditer(mem):
            s = _a64_site(mem, base, m)
            if s:
                out.append(s)
    else:
        raise ValueError("unsupported arch: %r" % (arch,))
    return out


def find_preambles(mem, base, arch, wanted):
    """Yield (hash, hash_ea) for stored preamble hashes in `wanted`.

    x86-64 stores `mov <reg32>, imm32`, aarch64 a bare aligned word.
    """
    mem = bytes(mem)
    if arch == "x86_64":
        pat = re.compile(rb"[\xb8-\xbf](.{4})", re.DOTALL)
        pos = 0
        while True:
            m = pat.search(mem, pos)
            if not m:
                return
            pos = m.start() + 1
            h = struct.unpack("<I", m.group(1))[0]
            if h in wanted:
                yield h, base + m.start() + 1
    else:
        count = len(mem) // 4
        for i, (w,) in zip(range(count), struct.iter_unpack("<I", mem[:count * 4])):
            if w in wanted:
                yield w, base + i * 4


def looks_like_entry(mem, off, arch):
    """Cheap filter: reject matches that cannot begin a function."""
    if off < 0 or off + 4 > len(mem):
        return False
    if arch == "aarch64":
        if off % 4:
            return False
        w = struct.unpack_from("<I", mem, off)[0]
        return w != 0 and (w >> 25) != 0   # not padding or a UDF word
    return mem[off] not in (0x00, 0xcc)



def _median_resolved(counts):
    """Median list length over the sites that have at least one candidate (counts is sorted)."""
    r = [c for c in counts if c]
    return r[len(r) // 2] if r else 0

def resolve(ranges, arch):
    """ranges: list of (base, bytes).  Returns (sites, stats)."""
    sites = []
    for base, mem in ranges:
        sites.extend(scan_sites(mem, base, arch))
    wanted = {s.hash for s in sites}
    disps = sorted({s.disp for s in sites})
    by_hash = defaultdict(set)
    for base, mem in ranges:
        for h, ea in find_preambles(mem, base, arch, wanted):
            for d in disps:
                t = ea - d
                if base <= t < base + len(mem) and looks_like_entry(mem, t - base, arch):
                    by_hash[h].add(t)
    for s in sites:
        s.targets = sorted(by_hash.get(s.hash, ()))
    counts = sorted(len(s.targets) for s in sites)
    n = len(sites)
    stats = {
        "sites": n,
        "hashes": len(wanted),
        "resolved": sum(1 for c in counts if c),
        "unresolved": sum(1 for c in counts if not c),
        "single_target": sum(1 for c in counts if c == 1),
        "median_candidates": counts[n // 2] if n else 0,  # over all sites, unresolved (0) included
        "median_candidates_resolved": _median_resolved(counts),
        "max_candidates": counts[-1] if n else 0,
        "disps": disps,
    }
    return sites, stats
