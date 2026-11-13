"""Name kCFI type hashes by their C function type. Pure Python, no IDA imports.

Clang's kCFI hash of a function type is the low 32 bits of xxHash64 of "_ZTS" followed by the type's
Itanium mangling, e.g. long (short, int) -> "_ZTSFlsiE" -> 0x1300e12b.  BTF (the kernel's own type
information, CONFIG_DEBUG_INFO_BTF) keeps every function prototype, so mangling those prototypes again
gives a table hash -> type for the hashes a kernel's call sites check.  This covers the C types the
kernel uses: builtins, pointers, const / volatile / restrict, named and typedef-named structs, unions
and enums, function pointers, arrays (decayed in parameters), varargs, and Itanium substitutions.
"""
import struct
from collections import defaultdict

from .core import demangle_type

# ---- xxHash64 ----

_M = (1 << 64) - 1
_P1, _P2, _P3 = 11400714785074694791, 14029467366897019727, 1609587929392839161
_P4, _P5 = 9650029242287828579, 2870177450012600261


def _rotl(x, r):
    return ((x << r) | (x >> (64 - r))) & _M


def _round(acc, inp):
    return (_rotl((acc + inp * _P2) & _M, 31) * _P1) & _M


def xxh64(data, seed=0):
    """xxHash64 of bytes (the reference algorithm)."""
    n, i = len(data), 0
    if n >= 32:
        v = [(seed + _P1 + _P2) & _M, (seed + _P2) & _M, seed & _M, (seed - _P1) & _M]
        while i + 32 <= n:
            for k, w in enumerate(struct.unpack_from("<4Q", data, i)):
                v[k] = _round(v[k], w)
            i += 32
        h = (_rotl(v[0], 1) + _rotl(v[1], 7) + _rotl(v[2], 12) + _rotl(v[3], 18)) & _M
        for x in v:
            h = ((h ^ _round(0, x)) * _P1 + _P4) & _M
    else:
        h = (seed + _P5) & _M
    h = (h + n) & _M
    while i + 8 <= n:
        h ^= _round(0, struct.unpack_from("<Q", data, i)[0])
        h = (_rotl(h, 27) * _P1 + _P4) & _M
        i += 8
    if i + 4 <= n:
        h ^= (struct.unpack_from("<I", data, i)[0] * _P1) & _M
        h = (_rotl(h, 23) * _P2 + _P3) & _M
        i += 4
    while i < n:
        h ^= (data[i] * _P5) & _M
        h = (_rotl(h, 11) * _P1) & _M
        i += 1
    h ^= h >> 33
    h = (h * _P2) & _M
    h ^= h >> 29
    h = (h * _P3) & _M
    h ^= h >> 32
    return h


def kcfi_hash(mangled):
    """32-bit kCFI hash of a mangled type name, with or without its '_ZTS' prefix."""
    if not mangled.startswith("_ZTS"):
        mangled = "_ZTS" + mangled
    return xxh64(mangled.encode("utf-8")) & 0xffffffff


# ---- Itanium mangling of C function types ----
# A canonical type is a tuple:
#   ("b", code)                builtin, e.g. ("b", "i")
#   ("n", name)                struct / union / enum (or a typedef naming an anonymous one)
#   ("s", name)                std::name (only AArch64's va_list, struct __va_list)
#   ("p", t)                   pointer
#   ("q", quals, t)            quals: a string of "r", "V", "K" (restrict, volatile, const)
#   ("a", n, t)                array of n (n None: unknown bound)
#   ("f", ret, params, varargs)

class Unmangleable(ValueError):
    pass


def _seq_id(i):
    if i == 0:
        return "S_"
    i -= 1
    digits = ""
    while True:
        digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"[i % 36] + digits
        i //= 36
        if not i:
            break
    return "S%s_" % digits


def _plain(t):
    """Mangling of t without substitutions (used as the substitution key)."""
    k = t[0]
    if k == "b":
        return t[1]
    if k == "n":
        return "%d%s" % (len(t[1].encode("utf-8")), t[1])
    if k == "s":                          # std::name (AArch64's va_list is std::__va_list)
        return "St%d%s" % (len(t[1]), t[1])
    if k == "p":
        return "P" + _plain(t[1])
    if k == "q":
        return t[1] + _plain(t[2])
    if k == "a":
        return "A%s_%s" % ("" if t[1] is None else t[1], _plain(t[2]))
    if k == "f":
        return "F" + _plain(t[1]) + _params(t[2], t[3], _plain) + "E"
    raise Unmangleable(k)


def _params(params, varargs, fn):
    if not params and not varargs:
        return "v"
    return "".join(fn(p) for p in params) + ("z" if varargs else "")


class _Mangler:
    def __init__(self):
        self.subs = {}

    def type(self, t):
        if t[0] == "b":
            return t[1]
        key = _plain(t)
        if key in self.subs:
            return _seq_id(self.subs[key])
        k = t[0]
        if k in ("n", "s"):
            out = key
        elif k == "p":
            out = "P" + self.type(t[1])
        elif k == "q":
            out = t[1] + self.type(t[2])
        elif k == "a":
            out = "A%s_%s" % ("" if t[1] is None else t[1], self.type(t[2]))
        else:
            ret = self.type(t[1])
            out = "F" + ret + _params(t[2], t[3], self.type) + "E"
        self.subs[key] = len(self.subs)
        return out


def mangle(t):
    """'_ZTS' + the Itanium mangling of a canonical function type (see above)."""
    if t[0] != "f":
        raise Unmangleable("not a function type")
    return "_ZTS" + _Mangler().type(t)


# ---- BTF ----

BTF_MAGIC = 0xEB9F
(K_INT, K_PTR, K_ARRAY, K_STRUCT, K_UNION, K_ENUM, K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT,
 K_FUNC, K_FUNC_PROTO, K_VAR, K_DATASEC, K_FLOAT, K_DECL_TAG, K_TYPE_TAG, K_ENUM64) = range(1, 20)

# Base type names as clang (and GCC, for pahole-converted DWARF) write them.
_INT_NAMES = {
    "char": "c", "signed char": "a", "unsigned char": "h", "_Bool": "b", "bool": "b",
    "short": "s", "short int": "s", "signed short": "s", "unsigned short": "t", "short unsigned int": "t",
    "unsigned short int": "t",
    "int": "i", "signed int": "i", "signed": "i", "unsigned int": "j", "unsigned": "j",
    "long": "l", "long int": "l", "signed long": "l", "unsigned long": "m", "long unsigned int": "m",
    "unsigned long int": "m",
    "long long": "x", "long long int": "x", "unsigned long long": "y", "long long unsigned int": "y",
    "unsigned long long int": "y",
    "__int128": "n", "__int128 unsigned": "o", "unsigned __int128": "o",
}
_FLOAT_NAMES = {"float": "f", "double": "d", "long double": "e", "__float128": "g", "_Float16": "DF16_"}


class BTFError(ValueError):
    pass


class BTF:
    """A parsed .BTF blob: self.types[i] = (kind, name, kind_flag, size_or_type, extra) for type id i."""

    def __init__(self, blob):
        if len(blob) < 24:
            raise BTFError("BTF too short")
        magic, _ver, _flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
        if magic != BTF_MAGIC:
            raise BTFError("no BTF magic (only little-endian BTF is read)")
        type_off, type_len, str_off, str_len = struct.unpack_from("<4I", blob, 8)
        t0, s0 = hdr_len + type_off, hdr_len + str_off
        if t0 + type_len > len(blob) or s0 + str_len > len(blob):
            raise BTFError("BTF sections run past the end")
        self.strings = blob[s0:s0 + str_len]
        self.types = [(0, "", 0, 0, None)]
        p, end = t0, t0 + type_len
        while p < end:
            name_off, info, st = struct.unpack_from("<3I", blob, p)
            p += 12
            vlen, kind, kflag = info & 0xffff, (info >> 24) & 0x1f, info >> 31
            extra = None
            if kind == K_INT:
                extra = struct.unpack_from("<I", blob, p)[0]
                p += 4
            elif kind == K_ARRAY:
                extra = struct.unpack_from("<3I", blob, p)
                p += 12
            elif kind in (K_STRUCT, K_UNION, K_DATASEC, K_ENUM64):
                extra = [struct.unpack_from("<3I", blob, p + 12 * i) for i in range(vlen)]
                p += 12 * vlen
            elif kind in (K_ENUM, K_FUNC_PROTO):
                extra = [struct.unpack_from("<2I", blob, p + 8 * i) for i in range(vlen)]
                p += 8 * vlen
            elif kind in (K_VAR, K_DECL_TAG):
                p += 4
            elif kind not in (K_PTR, K_FWD, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FLOAT,
                              K_TYPE_TAG):
                raise BTFError("unknown BTF kind %d" % kind)
            self.types.append((kind, self.name(name_off), kflag, st, extra))
        if p != end:
            raise BTFError("BTF type section is truncated")
        # A module's .BTF is split BTF: its names and type ids continue those of vmlinux's BTF, which is not here.
        n = len(self.types)
        for kind, name_off, refs in _offsets(blob, t0, end):
            if name_off >= str_len or any(r >= n for r in refs):
                raise BTFError("split BTF (a module's .BTF refers to vmlinux's types); give the kernel's BTF instead")

    def name(self, off):
        e = self.strings.find(b"\0", off)
        return self.strings[off:e if e >= 0 else len(self.strings)].decode("utf-8", "replace")

    def canon(self, tid, depth=0, typedef_name=None):
        """Canonical type (see mangle()) of BTF type id tid."""
        if depth > 64:
            raise Unmangleable("type chain too deep")
        if tid >= len(self.types):
            raise Unmangleable("bad type id %d" % tid)
        kind, name, kflag, st, extra = self.types[tid]
        if tid == 0:
            return ("b", "v")
        if kind == K_INT:
            code = _INT_NAMES.get(name)
            if code is None:
                raise Unmangleable("unknown int type %r" % name)
            return ("b", code)
        if kind == K_FLOAT:
            if name not in _FLOAT_NAMES:
                raise Unmangleable("unknown float type %r" % name)
            return ("b", _FLOAT_NAMES[name])
        if kind == K_PTR:
            return ("p", self.canon(st, depth + 1))
        if kind in (K_CONST, K_VOLATILE, K_RESTRICT):
            q = {K_CONST: "K", K_VOLATILE: "V", K_RESTRICT: "r"}[kind]
            inner = self.canon(st, depth + 1, typedef_name)
            if inner[0] == "q":
                q, inner = q + inner[1], inner[2]
            if inner[0] == "f":              # qualifiers on a function type are ignored in C
                return inner
            return ("q", "".join(c for c in "rVK" if c in q), inner)
        if kind == K_TYPE_TAG:
            return self.canon(st, depth + 1, typedef_name)
        if kind == K_TYPEDEF:
            return self.canon(st, depth + 1, name)
        if kind in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FWD):
            if name == "__va_list" and kind in (K_STRUCT, K_FWD):
                return ("s", name)      # AAPCS64: va_list is struct std::__va_list, mangled St9__va_list
            if name:
                return ("n", name)
            if typedef_name:
                return ("n", typedef_name)
            raise Unmangleable("anonymous struct, union or enum")
        if kind == K_ARRAY:
            return ("a", extra[2], self.canon(extra[0], depth + 1))
        if kind == K_FUNC:
            return self.canon(st, depth + 1)
        if kind == K_FUNC_PROTO:
            ret = _unqualified(self.canon(st, depth + 1))
            params, varargs = [], False
            for i, (_n, ptid) in enumerate(extra):
                if ptid == 0:
                    if i != len(extra) - 1:
                        raise Unmangleable("void parameter")
                    varargs = True
                    continue
                params.append(_param(self.canon(ptid, depth + 1)))
            return ("f", ret, params, varargs)
        raise Unmangleable("kind %d" % kind)


def _offsets(blob, p, end):
    """(kind, name_off, [referenced type ids]) of each BTF type record, for the split-BTF check."""
    while p < end:
        name_off, info, st = struct.unpack_from("<3I", blob, p)
        p += 12
        vlen, kind = info & 0xffff, (info >> 24) & 0x1f
        refs = [st] if kind in (K_PTR, K_TYPEDEF, K_VOLATILE, K_CONST, K_RESTRICT, K_FUNC, K_FUNC_PROTO, K_VAR,
                                K_TYPE_TAG, K_DECL_TAG) else []
        if kind == K_INT:
            p += 4
        elif kind == K_ARRAY:
            refs += struct.unpack_from("<2I", blob, p)
            p += 12
        elif kind in (K_STRUCT, K_UNION, K_DATASEC):    # members {name_off, type, offset}; DATASEC {type, offset, size}
            at = 0 if kind == K_DATASEC else 4
            refs += [struct.unpack_from("<I", blob, p + 12 * i + at)[0] for i in range(vlen)]
            p += 12 * vlen
        elif kind == K_ENUM64:
            p += 12 * vlen
        elif kind == K_FUNC_PROTO:
            refs += [struct.unpack_from("<I", blob, p + 8 * i + 4)[0] for i in range(vlen)]
            p += 8 * vlen
        elif kind == K_ENUM:
            p += 8 * vlen
        elif kind in (K_VAR, K_DECL_TAG):
            p += 4
        yield kind, name_off, refs


def _unqualified(t):
    return t[2] if t[0] == "q" else t


def _param(t):
    """A parameter's type as it enters the function type: top-level qualifiers dropped, arrays and functions
    decayed to pointers."""
    t = _unqualified(t)
    if t[0] == "a":
        return ("p", t[2])
    if t[0] == "f":
        return ("p", t)
    return t


def _check_header(blob, off):
    if off + 24 > len(blob):
        return None
    magic, ver, flags, hdr_len, type_off, type_len, str_off, str_len = struct.unpack_from("<HBBIIIII", blob, off)
    if magic != BTF_MAGIC or ver != 1 or flags != 0 or hdr_len not in (24, 32) or type_off != 0:
        return None
    if str_off != type_off + type_len or not type_len or not str_len or type_len % 4:
        return None
    total = hdr_len + str_off + str_len
    if off + total > len(blob) or blob[off + hdr_len + str_off] != 0:
        return None
    return total


def find_btf(data):
    """The .BTF blob of an ELF (section .BTF), a raw BTF file, or one found inside a raw kernel image
    (the largest blob whose header is sane).  None if there is none."""
    if data[:4] == b"\x7fELF" and len(data) >= 64 and data[4] == 2 and data[5] == 1:
        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3a)
        if shoff and shentsize == 64 and shoff + 64 * shnum <= len(data) and shstrndx < shnum:
            secs = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + 64 * i) for i in range(shnum)]
            strs = secs[shstrndx]
            for s in secs:
                start = strs[4] + s[0]
                if data[start:start + 5] == b".BTF\0" and s[1] != 8:
                    return data[s[4]:s[4] + s[5]]
    if _check_header(data, 0):
        return data[:_check_header(data, 0)]
    best = None
    i = data.find(b"\x9f\xeb\x01\x00")
    while i >= 0:
        n = _check_header(data, i)
        if n and (best is None or n > best[1]):
            best = (i, n)
        i = data.find(b"\x9f\xeb\x01\x00", i + 1)
    return data[best[0]:best[0] + best[1]] if best else None


class TypeNames:
    """hash -> [(mangled, readable type, [example names])] from every FUNC_PROTO of a BTF blob.

    Example names are the functions (BTF FUNC) of that prototype, else 'struct.member' for function
    pointers in structs and unions, else the typedef that names the pointer type."""

    def __init__(self, btf, examples=3):
        self.by_hash = defaultdict(dict)
        self.protos = self.unmangleable = 0
        funcs, others = defaultdict(list), defaultdict(list)    # FUNC_PROTO id -> names
        for tid, (kind, name, _kf, st, extra) in enumerate(btf.types):
            if kind == K_FUNC:
                funcs[st].append(name)
            elif kind in (K_STRUCT, K_UNION):
                for mname_off, mtid, _off in extra:
                    proto = _proto_behind(btf, mtid)
                    if proto:
                        others[proto].append("%s.%s" % (name or "(anonymous)", btf.name(mname_off)))
            elif kind == K_TYPEDEF:
                proto = _proto_behind(btf, st)
                if proto:
                    others[proto].append(name)
        seen = {}                          # mangled -> ([function names], [other names])
        for tid, (kind, _name, _kf, _st, _extra) in enumerate(btf.types):
            if kind != K_FUNC_PROTO:
                continue
            self.protos += 1
            try:
                mangled = mangle(btf.canon(tid))
            except Unmangleable:
                self.unmangleable += 1
                continue
            fs, os_ = seen.setdefault(mangled, ([], []))
            fs.extend(n for n in funcs.get(tid, ()) if len(fs) < examples)
            os_.extend(n for n in others.get(tid, ()) if len(os_) < examples)
        for mangled, (fs, os_) in seen.items():
            names = []
            for n in fs + os_:                 # functions first, then struct members and typedefs
                if n not in names and len(names) < examples:
                    names.append(n)
            self.by_hash[kcfi_hash(mangled)][mangled] = names

    def lookup(self, h):
        """[(mangled, readable, examples)] for a 32-bit hash, [] if no prototype gives it."""
        out = []
        for mangled, ex in sorted(self.by_hash.get(h, {}).items()):
            out.append((mangled, demangle_type(mangled) or mangled, list(ex)))
        return out

    def label(self, h):
        """Readable type(s) of a hash ('int (file*, int)'), ' | ' between collisions; None if unknown."""
        names = [r for _m, r, _e in self.lookup(h)]
        return " | ".join(names) if names else None


def _proto_behind(btf, tid, depth=0):
    """FUNC_PROTO id that a member or typedef type points at (through pointers, qualifiers, typedefs)."""
    while depth < 16 and 0 < tid < len(btf.types):
        kind, _n, _kf, st, _e = btf.types[tid]
        if kind == K_FUNC_PROTO:
            return tid
        if kind not in (K_PTR, K_CONST, K_VOLATILE, K_RESTRICT, K_TYPEDEF, K_TYPE_TAG):
            return None
        tid, depth = st, depth + 1
    return None


def load_type_names(data):
    """TypeNames from an ELF, raw BTF or raw kernel image; None if it holds no BTF."""
    blob = find_btf(data)
    if blob is None:
        return None
    return TypeNames(BTF(blob))


def name_sites(sites, names):
    """Set type_name / type_mangled of the kCFI sites whose hash a TypeNames names.

    Returns (named, total): distinct kCFI hashes named, distinct kCFI hashes at these sites."""
    hashes, named = set(), set()
    for s in sites:
        if getattr(s, "kind", "kcfi") != "kcfi":
            continue
        hashes.add(s.hash)
        found = names.lookup(s.hash)
        if found:
            named.add(s.hash)
            s.type_mangled = " | ".join(m for m, _r, _e in found)
            s.type_name = " | ".join(r for _m, r, _e in found)
    return len(named), len(hashes)


def named_summary(named, total):
    """'kCFI hashes named: N of M (x%)'."""
    pct = int(1000 * named / total) / 10.0 if total else 0.0    # rounded down: 100.0% only when all are named
    return "kCFI hashes named: %d of %d (%.1f%%)" % (named, total, pct)
