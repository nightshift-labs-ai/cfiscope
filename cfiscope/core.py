"""kCFI call-site and target recovery. Pure Python, no IDA imports.

Clang's -fsanitize=kcfi (Linux CONFIG_CFI_CLANG, Android GKI) leaves a 32-bit
function-type hash in front of every function and compares it at every
indirect call.  Both ends survive in a stripped binary, so matching them gives
the set of functions a given indirect call may reach.
"""
import array
import hashlib
import re
import struct
import sys
from collections import Counter, defaultdict
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
    # Jump-table CFI (Linux 5.x) only; kCFI sites keep the defaults.
    kind: str = "kcfi"     # "kcfi", or "range" / "single" / "slowpath" for jump-table CFI
    type_id: int = None    # 64-bit cross-DSO type id (MD5 of the mangled type name), when known
    type_name: str = None  # demangled type, e.g. "int (file*, int)", when symbols name it
    type_mangled: str = None  # e.g. "_ZTSFiP4fileiE"
    jt_base: int = 0       # first jump-table entry the check accepts
    jt_count: int = 0      # number of entries it accepts
    jt_range_from: str = None  # "code" (read at this check), or "same-id check" (copied from another check of its id)
    runtime_call_ea: int = 0   # blr of this check's inlined slow path: the CFI runtime calling __cfi_check (kernel's or a module's)
    runtime_check: bool = False  # guards no call, passes no type id, pointer in x1: the CFI runtime's own (__cfi_check)
    extra_checks: list = field(default_factory=list)   # other checks guarding the same call (their own Sites)
    note: str = None       # caveat for the user, e.g. a slow-path-only site whose type does have functions here


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
    """ranges: list of (base, bytes).  Returns (sites, stats).

    kCFI first; an aarch64 image with no kCFI check but with a CFI jump table is read as the
    older jump-table CFI instead (its stats carry "scheme": "jump-table CFI").
    """
    sites, stats = _resolve_kcfi(ranges, arch)
    if not sites and arch == "aarch64":
        old = resolve_jump_table_cfi(ranges)
        if old is not None:
            return old
    return sites, stats


def _resolve_kcfi(ranges, arch):
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


# ---------------------------------------------------------------------------
# Linux 5.x jump-table CFI on aarch64 (Clang -fsanitize=cfi -fsanitize-cfi-cross-dso,
# Android 12/13 GKI).  Every address-taken function gets an entry `bti c; b <function>` in
# one jump table; the functions of one type sit next to each other, and the address taken is
# the entry.  A checked call either tests that the pointer lies in its type's run of entries
#     adrp xB, page ; add xB, xB, #off ; sub xS, xF, xB ; ror xT, xS, #3 ; cmp xT, #N ; b.hs slow
# or, for a type with one member, compares it with that entry (cmp xF, xB ; b.ne slow).
# The slow path loads the 64-bit type id into x0 and calls __cfi_slowpath(_diag), which is
# also all that is left when a type has no member in this image.  Fixed-width words only:
# no disassembler needed.

_BTI_C, _PACIASP = 0xd503245f, 0xd503233f
_CALLER_SAVED = frozenset(list(range(19)) + [30])
_JT_RUN = re.compile(rb"(?:\x5f\x24\x03\xd5...[\x14-\x17])+", re.DOTALL)   # (bti c; b imm26)+
_ROR_ANCHOR = re.compile(rb".[\x08-\x0f][\xc0-\xdf]\x93", re.DOTALL)  # ror xT, xS, #2/#3 (extr xT, xS, xS)
RANGE_GAP = 4


def _is_sub_reg(w):
    return w & 0xffe0fc00 == 0xcb000000       # sub xd, xn, xm (no shift)


_RANGE_ANCHOR = re.compile(rb".[\x00-\x03][\x00-\x1f]\xcb.[\x08-\x0f][\xc0-\xdf]\x93", re.DOTALL)  # sub; ror #2/#3
_SINGLE_ANCHOR = re.compile(rb"[\x1f\x3f\x5f\x7f\x9f\xbf\xdf\xff][\x00-\x03][\x00-\x1f]\xeb"
                            rb"[\x01\x21\x41\x61\x81\xa1\xc1\xe1]..\x54", re.DOTALL)    # cmp xA, xB; b.ne
_BRANCH_REG = re.compile(rb"[\x00\x20\x40\x60\x80\xa0\xc0\xe0][\x00-\x03][\x1f\x3f]\xd6")  # br / blr xN
_BL = re.compile(rb"...[\x94-\x97]", re.DOTALL)
JT_MIN_ENTRIES = 2


def _aligned(pattern, mem, step=4):
    """Matches of pattern that start on a 4-byte boundary (a misaligned match does not hide an aligned one)."""
    pos = 0
    while True:
        m = pattern.search(mem, pos)
        if m is None:
            return
        if m.start() & 3:
            pos = m.start() + 1
            continue
        yield m
        pos = m.start() + step if step else m.end()


class _Code:
    """One code range as 32-bit words."""

    def __init__(self, base, mem):
        self.base, self.mem = base, bytes(mem)
        self.w = array.array("I")
        self.w.frombytes(self.mem[:len(self.mem) & ~3])
        if sys.byteorder == "big":
            self.w.byteswap()

    def ea(self, i):
        return self.base + 4 * i

    def index(self, ea):
        d = ea - self.base
        return d >> 2 if 0 <= d < 4 * len(self.w) and not d & 3 else None


def _locate(codes, ea):
    for c in codes:
        i = c.index(ea)
        if i is not None:
            return c, i
    return None


def _imm26(w):
    v = w & 0x3ffffff
    return v - 0x4000000 if v & 0x2000000 else v


def _imm19(w):
    v = (w >> 5) & 0x7ffff
    return v - 0x80000 if v & 0x40000 else v


def _is_b(w):
    return w & 0xfc000000 == 0x14000000


def _is_bl(w):
    return w & 0xfc000000 == 0x94000000


def _is_bcond(w):
    return w & 0xff000010 == 0x54000000


def _ends_flow(w):
    """ret / retaa / eret / brk / br: the next word is not reached by falling through."""
    return (w & 0xfffffc1f == 0xd65f0000 or w & 0xfffffbff == 0xd65f0bff or w == 0xd69f03e0
            or w & 0xffe0001f == 0xd4200000 or w & 0xfffffc1f == 0xd61f0000)


def _is_mov_reg(w):
    return w & 0xffe0ffe0 == 0xaa0003e0          # mov xd, xm (orr xd, xzr, xm)


def _ls_written(w):
    rt, rn, rt2 = w & 31, (w >> 5) & 31, (w >> 10) & 31
    simd = (w >> 26) & 1
    if w & 0x3b000000 == 0x18000000:            # ldr (literal) / prfm
        return () if simd or w >> 30 == 3 else (rt,)
    if w & 0x3a000000 == 0x28000000:            # ldp / stp (all indexing modes)
        out = [rt, rt2] if (w >> 22) & 1 and not simd else []
        if (w >> 23) & 3 in (1, 3):
            out.append(rn)                        # pre/post-index writeback
        return tuple(out)
    if w & 0x3a000000 == 0x38000000:            # ldr / str register forms, atomics
        out = []
        opc, size = (w >> 22) & 3, w >> 30
        if not (w >> 24) & 1:
            mode = (w >> 10) & 3
            if not (w >> 21) & 1 and mode in (1, 3):
                out.append(rn)                    # pre/post-index writeback
            elif (w >> 21) & 1 and mode & 1:
                out.append(rn)                    # ldraa/ldrab (conservative)
            if (w >> 21) & 1 and mode == 0 and not simd:
                out.append(rt)                    # atomic memory operation
        if not simd and opc != 0 and not (size == 3 and opc == 2):
            out.append(rt)                        # a load (prfm excluded)
        return tuple(out)
    return (rt, rn, rt2, (w >> 16) & 31)        # exclusives, CAS, SIMD structures: assume all


def _written(w):
    """General registers an instruction may write (a superset when unsure); calls clobber x0-x18 and x30."""
    op0 = (w >> 25) & 15
    if op0 & 14 == 8:                           # data processing, immediate
        return (w & 31,)
    if op0 & 7 == 5:                            # data processing, register
        return () if w & 0x3fe00000 == 0x3a400000 else (w & 31,)   # ccmp/ccmn write flags only
    if op0 & 14 == 10:                          # branches, exceptions, system
        if _is_bl(w) or w & 0xfffffc1f == 0xd63f0000 or w & 0xfffff800 == 0xd63f0800:
            return _CALLER_SAVED
        if w & 0xfff00000 == 0xd5300000 or w & 0xfff80000 == 0xd5280000:   # mrs, sysl
            return (w & 31,)
        return ()
    if op0 & 5 == 4:                            # loads and stores
        return _ls_written(w)
    return (w & 31,)


def _stops_walk(w, k, i):
    """A backward walk from word i stops at word k: a function start, or code that does not fall through.
    An unconditional b that jumps forward into the stretch already walked (k < target <= i) is stepped over:
    it only skips a block placed in between (a rotated loop), whose words the walk checked anyway."""
    if _is_b(w):
        return not k < k + _imm26(w) <= i
    return _ends_flow(w) or w == _BTI_C or w == _PACIASP


def _adrp(w, pc):
    imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return ((pc & ~0xfff) + (imm << 12)) & 0xffffffffffffffff


def _adr(w, pc):
    imm = (((w >> 5) & 0x7ffff) << 2) | ((w >> 29) & 3)
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc + imm) & 0xffffffffffffffff


def _const_reg(c, i, r, limit):
    """Value of xr just before word i, if a straight walk back finds adrp(+add) or adr (through mov copies)."""
    add = 0
    seen_add = False
    W = c.w
    for k in range(i - 1, max(i - limit, 0) - 1, -1):
        w = W[k]
        if _stops_walk(w, k, i):
            return None                               # left the straight path, or reached a function start
        if w & 0x9f000000 == 0x90000000 and w & 31 == r:
            return (_adrp(w, c.ea(k)) + add) & 0xffffffffffffffff
        if w & 0x9f000000 == 0x10000000 and w & 31 == r:
            return (_adr(w, c.ea(k)) + add) & 0xffffffffffffffff
        if w & 0xff800000 == 0x91000000 and w & 31 == r and not seen_add:   # add xr, xs, #imm
            add = ((w >> 10) & 0xfff) << (12 if (w >> 22) & 1 else 0)
            seen_add, r = True, (w >> 5) & 31
            continue
        if _is_mov_reg(w) and w & 31 == r:
            r = (w >> 16) & 31
            continue
        if r in _written(w):
            return None
    return None


def _mov_imm(c, i, r, limit=64):
    """N from `mov wr/xr, #N` (movz, shift 0) before word i."""
    W = c.w
    for k in range(i - 1, max(i - limit, 0) - 1, -1):
        w = W[k]
        if _stops_walk(w, k, i):
            return None
        if w & 0x7fe00000 == 0x52800000 and w & 31 == r:
            return (w >> 5) & 0xffff
        if r in _written(w):
            return None
    return None


def _type_id_before(c, i, limit=16):
    """The 64-bit constant that movz/movn + movk put in x0 before word i (the bl to the slow path)."""
    parts = {}
    W = c.w
    for k in range(i - 1, max(i - limit, 0) - 1, -1):
        w = W[k]
        if _ends_flow(w) or _is_b(w) or _is_bl(w):
            return None
        if w & 31 != 0:
            continue
        top = w & 0xff800000
        hw, imm = (w >> 21) & 3, (w >> 5) & 0xffff
        if top == 0xf2800000:                     # movk x0
            parts.setdefault(hw, imm)
        elif top in (0xd2800000, 0x92800000):     # movz / movn x0
            v = imm << (16 * hw)
            if top == 0x92800000:
                v = ~v & 0xffffffffffffffff
            for h, p in parts.items():
                v = (v & ~(0xffff << (16 * h))) | (p << (16 * h))
            return v
        elif 0 in _written(w):
            return None
    return None


def _x1_source(c, i, limit=16):
    """xR in `mov x1, xR` before the bl at word i (the pointer the slow path checks)."""
    W = c.w
    for k in range(i - 1, max(i - limit, 0) - 1, -1):
        w = W[k]
        if _ends_flow(w) or _is_b(w) or _is_bl(w):
            return None
        if _is_mov_reg(w) and w & 31 == 1:
            return (w >> 16) & 31
        if 1 in _written(w):
            return None
    return None


class JumpTable:
    """The CFI jump table: entry k at start + k * entry_size branches to targets[k]."""

    def __init__(self, start, entry_size, targets):
        self.start, self.entry_size, self.targets = start, entry_size, targets

    @property
    def end(self):
        return self.start + self.entry_size * len(self.targets)

    def entry_index(self, ea):
        if ea is None or not self.start <= ea < self.end or (ea - self.start) % self.entry_size:
            return None
        return (ea - self.start) // self.entry_size


def find_jump_table(ranges):
    """The longest run of 8-byte `bti c; b <function>` entries in the code ranges, or None."""
    best = None
    for base, mem in ranges:
        if base & 3:
            continue
        mem = bytes(mem)
        for m in _aligned(_JT_RUN, mem, step=0):
            n = (m.end() - m.start()) // 8
            if best is None or n > best[0]:
                best = (n, base, mem, m.start())
    if best is None or best[0] < JT_MIN_ENTRIES:
        return None
    n, base, mem, off = best
    targets = []
    for k in range(n):
        w = struct.unpack_from("<I", mem, off + 8 * k + 4)[0]
        targets.append((base + off + 8 * k + 4 + 4 * _imm26(w)) & 0xffffffffffffffff)
    return JumpTable(base + off, 8, targets)


class _Check:
    def __init__(self, kind, code, i, xF, base, count, entry_size, call_at, slow_at, cond):
        self.kind, self.code, self.i, self.xF = kind, code, i, xF
        self.base, self.count, self.entry_size = base, count, entry_size
        self.call_at, self.slow_at, self.cond = call_at, slow_at, cond
        self.slow_bl = None
        self.type_id = None
        self.calls = []


def _range_check(c, i, gap=0):
    """sub xS, xF, xB at word i, ror xT, xS, #s at i+1+gap, cmp xT, #N (or a register holding N), b.cond.

    gap: unrelated words the compiler scheduled between the sub and the ror (none may write xS or xF)."""
    W = c.w
    if i + 1 + gap >= len(W):
        return None
    sub, ror = W[i], W[i + 1 + gap]
    xS = sub & 31
    if (ror >> 5) & 31 != xS or (ror >> 16) & 31 != xS:
        return None
    xF, xB, xT = (sub >> 5) & 31, (sub >> 16) & 31, ror & 31
    if 31 in (xF, xB, xS):
        return None
    if any(r in _written(W[g]) for g in range(i + 1, i + 1 + gap) for r in (xS, xF)):
        return None
    n = k = None
    for k in range(i + 2 + gap, min(i + 5 + gap, len(W) - 1)):
        q = W[k]
        if q & 0xff80001f == 0xf100001f and (q >> 5) & 31 == xT:          # cmp xT, #imm
            n = ((q >> 10) & 0xfff) << (12 if (q >> 22) & 1 else 0)
            break
        if q & 0xffe0fc1f == 0xeb00001f and (q >> 5) & 31 == xT:          # cmp xT, xK
            n = _mov_imm(c, k, (q >> 16) & 31)
            break
        if xT in _written(q):
            return None
    if n is None or k + 1 >= len(W):
        return None
    bc = W[k + 1]
    cond = bc & 15
    if not _is_bcond(bc) or cond not in (2, 3, 8, 9):    # hs, lo, hi, ls
        return None
    count = n + 1 if cond in (8, 9) else n               # hi/ls compare with the last index, hs/lo with the count
    taken = k + 1 + _imm19(bc)
    call_at, slow_at = (k + 2, taken) if cond in (2, 8) else (taken, k + 2)
    base = _const_reg(c, i, xB, 400)
    return _Check("range", c, i, xF, base, count, 1 << ((ror >> 10) & 63), call_at, slow_at, cond)


def _single_check(c, i, jt):
    """cmp xA, xB; b.ne at word i, where one register holds the address of a jump-table entry."""
    W = c.w
    q, bc = W[i], W[i + 1]
    a, b = (q >> 5) & 31, (q >> 16) & 31
    if 31 in (a, b):
        return None
    for xF, xB in ((a, b), (b, a)):
        v = _const_reg(c, i, xB, 64)
        if jt.entry_index(v) is not None:
            break
    else:
        return None
    return _Check("single", c, i, xF, v, 1, jt.entry_size, i + 2, i + 1 + _imm19(bc), 1)


def _slow_call(codes, c, k, limit=32, hops=2):
    """(code, word, type id) of the first call on the straight path from word k that receives a 64-bit constant
    in x0 (built by movz/movn + movk): the slow path's bl __cfi_slowpath(_diag), or the blr of an inlined copy
    of it.  Follows up to two unconditional b (slow paths often share their call).  None if there is none."""
    W, end, h, x0 = c.w, k + limit, 0, None
    while k < end and k < len(W):
        w = W[k]
        op = w & 0xff80001f
        if op == 0xd2800000 or op == 0x92800000:                  # movz / movn x0
            x0 = ((w >> 5) & 0xffff) << (16 * ((w >> 21) & 3))
            if op == 0x92800000:
                x0 = ~x0 & 0xffffffffffffffff
        elif op == 0xf2800000:                                    # movk x0
            if x0 is not None:
                sh = 16 * ((w >> 21) & 3)
                x0 = (x0 & ~(0xffff << sh)) | (((w >> 5) & 0xffff) << sh)
        elif _is_bl(w) or w & 0xfffffc1f == 0xd63f0000:
            if x0 is not None and x0 >> 32:
                return c, k, x0
            x0 = None
        elif _is_b(w):
            if h == hops:
                return None
            loc = _locate(codes, c.ea(k) + 4 * _imm26(w))
            if loc is None:
                return None
            c, k = loc
            W, end, h = c.w, k + limit, h + 1
            continue
        elif _ends_flow(w):
            return None
        elif 0 in _written(w):
            x0 = None
        k += 1
    return None


def _def_of(c, i, r, limit):
    """Word that last wrote xr on the straight path before word i, or None."""
    W = c.w
    for k in range(i - 1, max(i - limit, 0) - 1, -1):
        w = W[k]
        if _stops_walk(w, k, i):
            return None
        if r in _written(w):
            return k
    return None


def _check_at_branch(c, j, slow_bl):
    """A range check whose cmp; b.cond sit at words j-1, j, with the rotate and subtract anywhere before
    (hoisted out of a loop, say).  The register holding the pointer comes from `mov x1, xR` on the slow path."""
    W = c.w
    if j < 1:
        return None
    q, bc = W[j - 1], W[j]
    xT = (q >> 5) & 31
    if q & 0xff80001f == 0xf100001f:
        n = ((q >> 10) & 0xfff) << (12 if (q >> 22) & 1 else 0)
    elif q & 0xffe0fc1f == 0xeb00001f:
        n = _mov_imm(c, j - 1, (q >> 16) & 31)
    else:
        return None
    r = _def_of(c, j - 1, xT, 400)
    if n is None or r is None:
        return None
    ror = W[r]
    xS = (ror >> 5) & 31
    if ror & 0xffe00000 != 0x93c00000 or (ror >> 16) & 31 != xS or (ror >> 10) & 63 not in (2, 3):
        return None
    sb = _def_of(c, r, xS, 64)
    if sb is None or W[sb] & 0xffe0fc00 != 0xcb000000:
        return None
    xF, xB = (W[sb] >> 5) & 31, (W[sb] >> 16) & 31
    ptr = _x1_source(slow_bl[0], slow_bl[1])
    if ptr is None:
        ptr = xF if _def_of(c, j - 1, xF, j - sb) is None else None
    if ptr is None or 31 in (xF, xB):
        return None
    cond = bc & 15
    taken = j + _imm19(bc)
    call_at, slow_at = (j + 1, taken) if cond in (2, 8) else (taken, j + 1)
    chk = _Check("range", c, j - 1, ptr, _const_reg(c, sb, xB, 400), n + 1 if cond in (8, 9) else n,
                 1 << ((ror >> 10) & 63), call_at, slow_at, cond)
    return chk


def _hoisted_check(c, k):
    """For a slow-path call at word k that no parsed check owns: the check that branches to its block."""
    W = c.w
    start = fall = None
    for j in range(k - 1, max(k - 24, 0) - 1, -1):
        w = W[j]
        if _is_bcond(w):
            start, fall = j + 1, j
            break
        if _ends_flow(w) or _is_b(w):
            start = j + 1
            break
    if start is None:
        return None
    if fall is not None:
        return _check_at_branch(c, fall, (c, k)) if W[fall] & 15 in (3, 9) else None
    for j in range(start - 1, max(start - 2048, 0) - 1, -1):
        w = W[j]
        if _is_bcond(w) and w & 15 in (2, 8) and j + _imm19(w) == start:
            return _check_at_branch(c, j, (c, k))
    return None


def _bl_target(c, k):
    return (c.ea(k) + 4 * _imm26(c.w[k])) & 0xffffffffffffffff


def _link_forward(codes, c, k, regs, limit=48, hops=2):
    """(code, word, b followed) of the first blr/br of a register in regs (or a mov copy of it) on the
    straight path from word k, following up to `hops` unconditional b; None if there is none."""
    regs = set(regs)
    W, end, h = c.w, k + limit, 0
    while k < end and k < len(W):
        w = W[k]
        if w & 0xffdffc1f == 0xd61f0000:                 # br / blr xN
            if (w >> 5) & 31 in regs:
                return c, k, h
            if not w & 0x00200000:
                return None                              # br elsewhere: the path ends
        if _is_b(w):
            if h == hops:
                return None
            loc = _locate(codes, c.ea(k) + 4 * _imm26(w))
            if loc is None:
                return None
            c, k = loc
            W, end, h = c.w, k + limit, h + 1
            continue
        if _ends_flow(w):
            return None
        if _is_mov_reg(w):
            if (w >> 16) & 31 in regs:
                regs.add(w & 31)
            else:
                regs.discard(w & 31)
        else:
            regs.difference_update(_written(w))
        if not regs:
            return None
        k += 1
    return None


def _candidates(jt, chk):
    """Function targets of the entries a check accepts, or None if they are not all in the table."""
    if chk.entry_size != jt.entry_size:
        return None
    first = jt.entry_index(chk.base)
    if first is None or chk.count < 1 or first + chk.count > len(jt.targets):
        return None
    return jt.targets[first:first + chk.count]


def resolve_jump_table_cfi(ranges):
    """Sites and stats for an aarch64 image built with the Linux 5.x jump-table CFI; None if it has no jump table."""
    codes = [_Code(base, mem) for base, mem in ranges if not base & 3 and len(mem) >= 8]
    jt = find_jump_table([(c.base, c.mem) for c in codes])
    if jt is None:
        return None
    checks = []
    for c in codes:
        for m in _aligned(_RANGE_ANCHOR, c.mem):
            chk = _range_check(c, m.start() >> 2)
            if chk is not None:
                checks.append(chk)
        for m in _aligned(_ROR_ANCHOR, c.mem):    # sub and ror with up to RANGE_GAP other words between them
            j = m.start() >> 2
            if j < 1 or (_is_sub_reg(c.w[j - 1]) and c.w[j - 1] & 31 == (c.w[j] >> 5) & 31):
                continue                          # adjacent: the anchor above handles it
            for gap in range(1, RANGE_GAP + 1):
                if j - 1 - gap >= 0 and _is_sub_reg(c.w[j - 1 - gap]) and c.w[j - 1 - gap] & 31 == (c.w[j] >> 5) & 31:
                    chk = _range_check(c, j - 1 - gap, gap)
                    if chk is not None:
                        checks.append(chk)
                    break
        for m in _aligned(_SINGLE_ANCHOR, c.mem):
            chk = _single_check(c, m.start() >> 2, jt)
            if chk is not None:
                checks.append(chk)
    # Each check's slow path passes the 64-bit type id; the function most of them call is __cfi_slowpath(_diag).
    called = Counter()
    for chk in checks:
        _slow_path(codes, chk)
        if chk.slow_bl is not None and _is_bl(chk.slow_bl[0].w[chk.slow_bl[1]]):
            called[_bl_target(*chk.slow_bl)] += 1
    top = max(called.values()) if called else 0
    slow_fns = {t for t, n in called.items() if 4 * n >= top}
    if not slow_fns:
        return None
    # A cmp/b.ne against one entry with no slow path behind it is an ordinary function-pointer comparison
    # (`if (ops->fn == foo)`), not a CFI check.
    checks = [chk for chk in checks if chk.kind != "single" or (chk.slow_bl is not None and chk.type_id is not None)]
    all_calls, slow_calls = [], []
    for c in codes:
        all_calls.extend((c, m.start() >> 2) for m in _aligned(_BRANCH_REG, c.mem))
        for m in _aligned(_BL, c.mem):
            k = m.start() >> 2
            if _bl_target(c, k) in slow_fns:
                slow_calls.append((c, k))
    # Slow-path calls no check owns: a check hoisted apart (rotate before a loop, compare inside), or a type
    # with no function in this image, whose call goes to the slow path unconditionally.
    owned = {(id(chk.slow_bl[0]), chk.slow_bl[1]) for chk in checks if chk.slow_bl is not None}
    lone = []
    for c, k in slow_calls:
        if (id(c), k) in owned:
            continue
        chk = _hoisted_check(c, k)
        if chk is not None:
            _slow_path(codes, chk)
            checks.append(chk)
            if chk.slow_bl is not None:
                owned.add((id(chk.slow_bl[0]), chk.slow_bl[1]))
        if (id(c), k) not in owned:
            lone.append((c, k))
    # Checks whose base register was not found: the same type id elsewhere names the range.
    base_of = defaultdict(set)
    for chk in checks:
        if chk.type_id is not None and chk.base is not None:
            base_of[chk.type_id].add(chk.base)
    for chk in checks:
        chk.base_from = "code" if chk.base is not None else None
        if chk.base is None and len(base_of.get(chk.type_id, ())) == 1:
            chk.base, chk.base_from = next(iter(base_of[chk.type_id])), "same-id check"
    # Link each check to the call it guards: forward along the straight path, then calls that reuse an earlier check.
    guards = defaultdict(list)                     # (code id, word) -> checks guarding that call
    where = {}
    for chk in checks:
        loc = _link_forward(codes, chk.code, chk.call_at, {chk.xF}) if 0 <= chk.call_at < len(chk.code.w) else None
        if loc is None and chk.slow_bl is not None and 0 <= chk.call_at < len(chk.code.w):
            # The pointer may have been copied to another register before the call (mov x20, x2 between the
            # check and the blr x20): the slow path passes the register that is really called in x1.
            r = _x1_source(*chk.slow_bl)
            if r is not None and r != chk.xF:
                loc = _link_forward(codes, chk.code, chk.call_at, {r})
                if loc is not None:
                    chk.xF = r
        if loc is not None:
            guards[(id(loc[0]), loc[1])].append(chk)
            where[(id(loc[0]), loc[1])] = loc[:2]
    by_word = {(id(chk.code), chk.i): chk for chk in checks}
    for c, k in all_calls:
        if (id(c), k) in guards:
            continue
        r = (c.w[k] >> 5) & 31
        W = c.w
        for j in range(k - 1, max(k - 160, 0) - 1, -1):
            chk = by_word.get((id(c), j))
            if chk is not None and chk.xF == r:
                guards[(id(c), k)].append(chk)
                where[(id(c), k)] = (c, k)
                break
            w = W[j]
            if _stops_walk(w, j, k) or r in _written(w):
                break
    sites, linked = [], set()
    for key, chks in guards.items():
        c, k = where[key]
        chks.sort(key=lambda x: x.code.ea(x.i))
        parts, seen = [], set()
        for x in chks:                             # the same check can be found twice (forward and from its slow path)
            p = _check_site(jt, x, c.ea(k), not c.w[k] & 0x00200000)
            if (p.kind, p.jt_base, p.jt_count, p.type_id) not in seen:
                seen.add((p.kind, p.jt_base, p.jt_count, p.type_id))
                parts.append(p)
        site = parts[0]
        if len(parts) > 1:                         # one call reached from several checks (calls merged by the compiler)
            site.targets = sorted({t for p in parts for t in p.targets})
            site.extra_checks = parts[1:]
        sites.append(site)
        linked.update(id(x) for x in chks)
    for x in checks:
        if id(x) not in linked:
            s = _check_site(jt, x, 0, False)
            # No call after it, no slow-path call passing a type id, and the pointer in x1: the runtime's __cfi_check,
            # which receives the id as an argument (x0), range-checks the pointer (x1) and returns or branches to
            # __cfi_check_fail. (GKI 5.15 and 5.10: every runtime check uses x1; the 12 linked program checks on 5.15
            # whose slow path was not decoded use x8, x20, x21 or x22; had one been unlinked, a test without x1 would
            # have hidden it from Callers.)
            s.runtime_check = x.slow_bl is None and x.xF == 1
            sites.append(s)
    # A type id names one range: every parsed check of that id accepts the same entries.
    ranges_of = defaultdict(set)
    for chk in checks:
        if chk.type_id is not None and _candidates(jt, chk) is not None:
            ranges_of[chk.type_id].add((chk.base, chk.count))
    # Calls reached only through the slow path ("slowpath": no candidate in this image, the pointer failed or
    # skipped the in-image check, so only module functions of the type remain): a type with no function here, or a
    # copy of the call that the compiler placed right after the slow-path call.
    owner = {}
    for chk in checks:
        if chk.slow_bl is not None:
            owner.setdefault((id(chk.slow_bl[0]), chk.slow_bl[1]), chk)
    by_call = {}
    for c, k in slow_calls:
        chk = owner.get((id(c), k))
        tid = chk.type_id if chk is not None else _type_id_before(c, k)
        r = _x1_source(c, k)
        loc = _link_forward(codes, c, k + 1, {r}, limit=24) if r is not None and r not in _CALLER_SAVED else None
        if loc is not None and (id(loc[0]), loc[1]) in guards:
            continue                               # the slow path rejoins a call whose inline check was read
        if chk is not None and (loc is None or loc[2] or id(chk) not in linked):
            continue                               # an inline check's slow path that rejoins nothing we can follow
        s = Site(c.ea(k), 0, tid or 0, 0)
        s.kind, s.type_id = "slowpath", tid
        if chk is not None:
            s.note = ("call copy on the slow path of the check at 0x%x: reached only when the pointer is not one "
                      "of this image's functions of the type" % chk.code.ea(chk.i))
        elif tid in ranges_of:
            s.note = ("this type has functions in this image (another check names them), so an inline check "
                      "was probably not decoded: candidates unknown")
        if loc is not None:
            s.call_ea, s.is_tail = loc[0].ea(loc[1]), not loc[0].w[loc[1]] & 0x00200000
            if loc[2] and chk is None and len(ranges_of.get(tid, ())) == 1:
                # It jumps back to a call that an inline check of this type guards, one this scanner did not
                # decode; the type has functions here, and another check of the same id gives their entries.
                s.jt_base, s.jt_count = next(iter(ranges_of[tid]))
                s.kind = "range" if s.jt_count > 1 else "single"
                s.jt_range_from = "same-id check"
                s.note = ("inline check not decoded; its range is taken from another check of the same type id")
                first = jt.entry_index(s.jt_base)
                s.targets = sorted(set(jt.targets[first:first + s.jt_count]))
        prev = by_call.get(s.call_ea) if s.call_ea else None
        if prev is not None:                       # two slow-path calls before one call: one site
            prev.extra_checks.append(s)
            prev.targets = sorted(set(prev.targets) | set(s.targets))
            continue
        if s.call_ea:
            by_call[s.call_ea] = s
        sites.append(s)
    sites.sort(key=lambda s: (s.call_ea or s.check_ea, s.check_ea))
    counts = sorted(len(s.targets) for s in sites)
    n = len(sites)
    kinds = Counter(s.kind for s in sites)
    stats = {
        "scheme": "jump-table CFI",
        "sites": n,
        "hashes": len({x.type_id for x in checks if x.type_id is not None} |
                      {s.type_id for s in sites if s.type_id is not None}),
        "resolved": sum(1 for c in counts if c),
        "unresolved": sum(1 for c in counts if not c),
        "single_target": sum(1 for c in counts if c == 1),
        "median_candidates": counts[n // 2] if n else 0,
        "median_candidates_resolved": _median_resolved(counts),
        "max_candidates": counts[-1] if n else 0,
        "disps": [],
        "range_sites": kinds["range"],
        "single_sites": kinds["single"],
        "slowpath_sites": kinds["slowpath"],
        "checks": len(checks),
        "checks_without_range": sum(1 for x in checks if _candidates(jt, x) is None),
        "checks_range_copied": sum(1 for chk in checks if getattr(chk, "base_from", None) == "same-id check"),
        "runtime_calls": len({x.runtime_call_ea for t in sites for x in [t] + t.extra_checks if x.runtime_call_ea}),
        "checks_without_call": sum(1 for s in sites if not s.call_ea and s.kind != "slowpath"),
        "runtime_checks": sum(1 for s in sites if s.runtime_check),
        "indirect_calls": len(all_calls),
        "calls_with_candidates": len({s.call_ea for s in sites if s.call_ea and s.targets}),
        "jump_table": {"start": "0x%x" % jt.start, "end": "0x%x" % jt.end,
                       "entries": len(jt.targets), "entry_size": jt.entry_size},
        "slowpath_functions": ["0x%x" % t for t in sorted(slow_fns)],
    }
    return sites, stats


def _slow_path(codes, chk):
    """Find the check's slow-path call and type id."""
    chk.slow_bl = None
    if not 0 <= chk.slow_at < len(chk.code.w):
        return
    found = _slow_call(codes, chk.code, chk.slow_at)
    if found is not None:
        chk.slow_bl, chk.type_id = (found[0], found[1]), found[2]


def _check_site(jt, chk, call_ea, tail):
    s = Site(chk.code.ea(chk.i), call_ea, chk.type_id or 0, 0, tail, sorted(set(_candidates(jt, chk) or ())))
    s.kind, s.type_id = chk.kind, chk.type_id
    s.jt_base, s.jt_count = chk.base or 0, chk.count
    s.jt_range_from = getattr(chk, "base_from", None) if chk.base is not None else None
    if chk.slow_bl is not None and chk.slow_bl[0].w[chk.slow_bl[1]] & 0xfffffc1f == 0xd63f0000:
        s.runtime_call_ea = chk.slow_bl[0].ea(chk.slow_bl[1])   # inlined __cfi_slowpath: not a program call
    return s


# ---- type names (jump-table CFI) ----

_TYPEID_SYMBOL = re.compile(r"^__typeid_(_ZTS.+)_global_addr$")
_BUILTIN = {"v": "void", "w": "wchar_t", "b": "bool", "c": "char", "a": "signed char", "h": "unsigned char",
            "s": "short", "t": "unsigned short", "i": "int", "j": "unsigned int", "l": "long",
            "m": "unsigned long", "x": "long long", "y": "unsigned long long", "n": "__int128",
            "o": "unsigned __int128", "f": "float", "d": "double", "e": "long double", "g": "__float128",
            "z": "..."}


def cfi_type_id(mangled):
    """The 64-bit cross-DSO CFI id of a mangled type name: the first 8 bytes of its MD5, little-endian."""
    data = mangled.encode("utf-8")
    try:
        digest = hashlib.md5(data, usedforsecurity=False).digest()
    except TypeError:                     # Python 3.8
        digest = hashlib.md5(data).digest()
    return int.from_bytes(digest[:8], "little")


class _Demangler:
    """Just enough of the Itanium C++ ABI for the C function types that Linux CFI hashes (_ZTSF...E)."""

    def __init__(self, text):
        self.s, self.p, self.subs = text, 0, []

    def _peek(self):
        return self.s[self.p:self.p + 1]

    def _number(self):
        start = self.p
        while self._peek().isdigit():
            self.p += 1
        if start == self.p:
            raise ValueError("number expected")
        return int(self.s[start:self.p])

    def type(self):
        c = self._peek()
        if not c:
            raise ValueError("truncated")
        if c in _BUILTIN:
            self.p += 1
            return ("name", _BUILTIN[c])
        if c.isdigit() or self.s.startswith("St", self.p):      # a name, or std::name
            prefix = ""
            if c == "S":
                self.p, prefix = self.p + 2, "std::"
            n = self._number()
            name = self.s[self.p:self.p + n]
            if len(name) != n:
                raise ValueError("truncated name")
            self.p += n
            t = ("name", prefix + name)
        elif c == "P":
            self.p += 1
            t = ("ptr", self.type())
        elif c in "rVK":
            quals = []
            for q, word in (("r", "restrict"), ("V", "volatile"), ("K", "const")):
                if self._peek() == q:
                    self.p += 1
                    quals.append(word)
            t = ("qual", " ".join(reversed(quals)), self.type())
        elif c == "F":
            self.p += 1
            if self._peek() == "Y":
                self.p += 1
            ret, args = self.type(), []
            while self._peek() != "E":
                args.append(self.type())
            self.p += 1
            t = ("func", ret, args)
        elif c == "A":
            self.p += 1
            n = self._number() if self._peek() != "_" else ""
            if self._peek() != "_":
                raise ValueError("array")
            self.p += 1
            t = ("array", str(n), self.type())
        elif c == "S":
            self.p += 1
            if self._peek() == "_":
                idx = 0
            else:
                start = self.p
                while self._peek() and self._peek() != "_":
                    self.p += 1
                idx = int(self.s[start:self.p], 36) + 1
            self.p += 1
            return self.subs[idx]
        else:
            raise ValueError("unsupported %r" % c)
        self.subs.append(t)
        return t


def _format_type(t, decl=""):
    kind = t[0]
    if kind == "name":
        return t[1] + decl
    if kind == "ptr":
        inner = t[1]
        if inner[0] in ("func", "array"):
            return _format_type(inner, "(*" + decl + ")")
        return _format_type(inner, "*" + decl)
    if kind == "qual":
        return _format_type(t[2], " " + t[1] + decl)
    if kind == "func":
        args = t[2]
        if len(args) == 1 and args[0] == ("name", "void"):
            args = []
        text = ", ".join(_format_type(a) for a in args)
        return _format_type(t[1], " " + decl + "(" + text + ")")
    if kind == "array":
        return _format_type(t[2], (" " + decl if decl else "") + " [" + t[1] + "]")
    raise ValueError(kind)


def demangle_type(mangled):
    """'_ZTSFiP4fileiE' -> 'int (file*, int)' (c++filt's spelling); None if the name is outside the subset."""
    if not mangled.startswith("_ZTS"):
        return None
    body, _, suffix = mangled[4:].partition(".")
    try:
        d = _Demangler(body)
        t = d.type()
        if d.p != len(body):
            return None
        text = _format_type(t)
    except (ValueError, IndexError, RecursionError):
        return None
    return text + (" [%s]" % suffix if suffix else "")


def name_jt_types(sites, symbols):
    """Give jump-table CFI sites their type names from `__typeid_<mangled>_global_addr` symbols.

    symbols: iterable of (address, name).  The id in a slow path is MD5 of the mangled name; a check whose slow
    path was not read is named by the symbol at its first entry.  Returns the number of named checks."""
    by_id, by_ea = {}, {}
    for ea, name in symbols:
        m = _TYPEID_SYMBOL.match(name)
        if m:
            by_id[cfi_type_id(m.group(1))] = m.group(1)
            by_ea.setdefault(ea, m.group(1))
    named = 0
    for s in sites:
        for x in [s] + list(s.extra_checks):
            if x.kind == "kcfi":
                continue
            mangled = by_id.get(x.type_id) if x.type_id is not None else None
            if mangled is None and x.type_id is None and x.kind != "slowpath" and x.jt_base in by_ea:
                mangled = by_ea[x.jt_base]
                x.type_id = x.hash = cfi_type_id(mangled)
            if mangled:
                x.type_mangled, x.type_name = mangled, demangle_type(mangled) or mangled
                named += 1
                if x.kind == "slowpath" and not x.targets and x.note is None:
                    x.note = ("this type has functions in this image (it has a __typeid symbol), so an inline "
                              "check was probably not decoded: candidates unknown")
    return named


def type_label(site):
    """The type(s) a jump-table CFI site checks: names when known, else 64-bit ids; '' if unknown."""
    out = []
    for x in [site] + list(site.extra_checks):
        text = x.type_name or ("type id 0x%016x" % x.type_id if x.type_id is not None else "")
        if text and text not in out:
            out.append(text)
    return " | ".join(out)


# ---- callers of a function ----

RUNTIME_CHECK_FUNCTION = "__cfi_check"   # jump-table CFI: the runtime's check function (kernel and each module)


def has_indirect_call(mem):
    """Does this aarch64 code hold a blr or br? A function without one calls no checked pointer itself."""
    return next(_aligned(_BRANCH_REG, bytes(mem)), None) is not None


def callers(sites, reaches, in_runtime=None):
    """(calls, checks) among the sites with a candidate for which reaches(target) is true, each in address order.

    calls: sites with a linked call instruction, the only ones that are call sites.  checks: type checks whose call
    was not linked, without the CFI runtime's own checks, which guard no call: Site.runtime_check (read from the
    code), or a jump-table CFI check for which in_runtime(check address) is true (the caller's test by function
    name or bounds, when it has them)."""
    calls, checks = [], []
    for s in sites:
        if not any(reaches(t) for t in s.targets):
            continue
        if s.call_ea or getattr(s, "kind", "kcfi") == "kcfi":  # kCFI: every check is a call site, as before 0.1.18
            calls.append(s)
        elif not (s.runtime_check or (s.kind != "kcfi" and in_runtime is not None and in_runtime(s.check_ea))):
            checks.append(s)
    return calls, checks


UNLINKED = "type check only (call not linked)"       # a range or single-member check whose call was not linked
RUNTIME_CHECK = "CFI runtime check (guards no call)"  # inside __cfi_check: listed by --sites, never a caller
SLOWPATH_UNLINKED = "check (call not linked)"         # a slow-path-only site (no inline check) whose call was not linked


def unlinked_label(s):
    """--sites label of a jump-table CFI site with no linked call."""
    if getattr(s, "runtime_check", False):
        return RUNTIME_CHECK
    return SLOWPATH_UNLINKED if s.kind == "slowpath" else UNLINKED


def callers_header(calls, checks, label):
    """'6 call site(s) can reach tcp_sendmsg', plus the number of unlinked type checks listed after them."""
    text = "%d call site(s) can reach %s" % (calls, label)
    if checks:
        text += " (+%d type check(s) whose call was not linked, listed last)" % checks
    return text
