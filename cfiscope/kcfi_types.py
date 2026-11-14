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
#   ("b", code)                builtin, e.g. ("b", "i"); plain char is ("b", "c", "u2i8" or "u2u8") (its signedness)
#   ("n", name, tag)           struct / union / enum (tag "struct" / "union" / "enum"; "" for a typedef naming an
#                              anonymous one; the tag is only used for the C label, c_type)
#   ("s", name)                std::name (only AArch64's va_list, struct __va_list)
#   ("p", t)                   pointer
#   ("q", quals, t)            quals: a string of "r", "V", "K" (restrict, volatile, const)
#   ("a", n, t)                array of n (n None: unknown bound)
#   ("f", ret, params, varargs)  params None: no prototype (K&R "()"), mangled with no parameter code

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
    if params is None:                    # K&R "()": clang mangles a FunctionNoProtoType as F<ret>E
        return ""
    if not params and not varargs:
        return "v"
    return "".join(fn(p) for p in params) + ("z" if varargs else "")


# -fsanitize-cfi-icall-experimental-normalize-integers (CONFIG_CFI_ICALL_NORMALIZE_INTEGERS, kernels with Rust):
# integer builtins become vendor types by size and signedness, substituted by one representative per name, and
# the mangled name gets the suffix ".normalized".
_NORM = {"a": "u2i8", "h": "u2u8", "b": "u2u8", "s": "u3i16", "t": "u3u16", "i": "u3i32", "j": "u3u32",
         "l": "u3i64", "m": "u3u64", "x": "u3i64", "y": "u3u64", "n": "u4i128", "o": "u4u128"}


class _Mangler:
    def __init__(self, normalize=False):
        self.subs = {}
        self.normalize = normalize

    def type(self, t):
        if t[0] == "b":
            v = (t[2] if len(t) > 2 else _NORM.get(t[1])) if self.normalize else None
            if v is None:
                return t[1]
            key = "#" + v
            if key in self.subs:
                return _seq_id(self.subs[key])
            self.subs[key] = len(self.subs)
            return v
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


_C_BASE = {"v": "void", "b": "_Bool", "c": "char", "a": "signed char", "h": "unsigned char", "s": "short",
           "t": "unsigned short", "i": "int", "j": "unsigned int", "l": "long", "m": "unsigned long",
           "x": "long long", "y": "unsigned long long", "n": "__int128", "o": "unsigned __int128",
           "f": "float", "d": "double", "e": "long double", "g": "__float128", "DF16_": "_Float16"}
_C_QUALS = (("K", "const"), ("V", "volatile"), ("r", "restrict"))


def c_type(t, inner=""):
    """C text of a canonical type t (see mangle()) around the declarator text `inner` ('' = abstract type), e.g.
    'int (struct file *, void (*)(int))'."""
    k = t[0]
    if k == "b":
        base = _C_BASE.get(t[1], t[1])
    elif k == "n":
        base = (t[2] + " " if len(t) > 2 and t[2] else "") + t[1]
    elif k == "s":
        base = "va_list" if t[1] == "__va_list" else "std::" + t[1]
    elif k == "q":
        quals = " ".join(w for c, w in _C_QUALS if c in t[1])
        if t[2][0] == "p":                   # a qualified pointer: 'char *const'
            return _pointer(t[2][1], "*" + quals + (" " + inner if inner else ""))
        return quals + " " + c_type(t[2], inner)
    elif k == "p":
        return _pointer(t[1], "*" + inner)
    elif k == "a":
        return c_type(t[2], "%s[%s]" % (inner, "" if t[1] is None else t[1]))
    elif k == "f":
        if t[2] is None:                     # K&R "()"
            return c_type(t[1], inner + "()")
        params = [c_type(p) for p in t[2]] + (["..."] if t[3] else [])
        return c_type(t[1], "%s(%s)" % (inner, ", ".join(params) or "void"))
    else:
        raise Unmangleable(k)
    return base + (" " + inner if inner else "")


def _pointer(pointee, text):
    """A pointer declarator around the pointee: parentheses when it points at a function or an array."""
    return c_type(pointee, "(%s)" % text if pointee[0] in ("f", "a") else text)


def mangle(t, normalize=False):
    """'_ZTS' + the Itanium mangling of a canonical function type (see above); with normalize, the
    integer-normalized form ('_ZTSFu3i64u3i16u3i32E.normalized')."""
    if t[0] != "f":
        raise Unmangleable("not a function type")
    return "_ZTS" + _Mangler(normalize).type(t) + (".normalized" if normalize else "")


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


def _layout(blob):
    """(start of the types, end of the types, start of the strings, string length) of a BTF blob."""
    if len(blob) < 24:
        raise BTFError("BTF too short")
    magic, _ver, _flags, hdr_len = struct.unpack_from("<HBBI", blob, 0)
    if magic != BTF_MAGIC:
        raise BTFError("no BTF magic (only little-endian BTF is read)")
    type_off, type_len, str_off, str_len = struct.unpack_from("<4I", blob, 8)
    t0, s0 = hdr_len + type_off, hdr_len + str_off
    if t0 + type_len > len(blob) or s0 + str_len > len(blob):
        raise BTFError("BTF sections run past the end")
    return t0, t0 + type_len, s0, str_len


def is_split(blob):
    """Is this split BTF, as in a module's .BTF: names or type ids beyond its own, which continue vmlinux's BTF?"""
    t0, end, _s0, str_len = _layout(blob)
    recs = list(_offsets(blob, t0, end))
    return any(name_off >= str_len or any(r > len(recs) for r in refs) for _kind, name_off, refs in recs)


class BTF:
    """A parsed .BTF blob: self.types[i] = (kind, name, kind_flag, size_or_type, extra) for type id i.

    base: the parsed BTF that a split BTF (a module's .BTF) continues, its kernel's: type ids and string offsets then
    run on from base's, and self.types and self.strings hold both."""

    def __init__(self, blob, base=None):
        t0, end, s0, str_len = _layout(blob)
        self.strings = (base.strings if base is not None else b"") + blob[s0:s0 + str_len]
        self.types = list(base.types) if base is not None else [(0, "", 0, 0, None)]
        first = len(self.types)
        p = t0
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
        if base is None:
            for kind, name_off, refs in _offsets(blob, t0, end):
                if name_off >= str_len or any(r >= n for r in refs):
                    raise BTFError("split BTF (a module's .BTF refers to vmlinux's types); give the kernel's BTF "
                                   "instead")
            return
        # On a base: every name must start a string and every type id exist. The split BTF of one build on the
        # kernel BTF of another fails this (its offsets land inside strings), rather than being misread.
        strings = self.strings
        for kind, name_off, refs in _offsets(blob, t0, end):
            if name_off >= len(strings) or (name_off and strings[name_off - 1] != 0) or any(r >= n for r in refs):
                raise BTFError("this split BTF does not continue the given kernel BTF (BTF of another kernel build?)")
        if first == n:
            raise BTFError("empty split BTF")

    def name(self, off):
        e = self.strings.find(b"\0", off)
        return self.strings[off:e if e >= 0 else len(self.strings)].decode("utf-8", "replace")

    def linkage_names(self):
        """{anonymous struct/union/enum type id: the name of the first typedef that names it directly}: C and Clang
        give such a type that typedef's name for linkage ("typedef struct {..} X, *PX": a PX parameter mangles as P1X)."""
        names = getattr(self, "_linkage", None)
        if names is None:
            names = self._linkage = {}
            for kind, name, _kf, st, _extra in self.types:
                if (kind == K_TYPEDEF and name and 0 < st < len(self.types) and not self.types[st][1]
                        and self.types[st][0] in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64)):
                    names.setdefault(st, name)
        return names

    def canon(self, tid, depth=0, typedef_name=None):
        """Canonical type (see mangle()) of BTF type id tid. Results (and failures) are kept per (tid, depth, typedef name),
        so shared types are read once (review s176: a crafted DAG made this exponential)."""
        memo = self.__dict__.setdefault("_canon_memo", {})
        key = (tid, depth, typedef_name)   # s176 check M1: the depth too, so the 64-level cap holds
        if key in memo:
            got = memo[key]
            if isinstance(got, Unmangleable):
                raise got.with_traceback(None)   # s176 check m3: no traceback growing with every re-raise
            return got
        try:
            memo[key] = self._canon(tid, depth, typedef_name)
        except Unmangleable as e:
            memo[key] = e
            raise
        return memo[key]

    def _canon(self, tid, depth=0, typedef_name=None):
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
            if code == "c":                  # BTF_INT_SIGNED: plain char's signedness, for normalized integers (pahole leaves
                                             # plain char unmarked: unsigned, as kernels >= 6.2 build it on every arch)
                return ("b", "c", "u2i8" if (extra >> 24) & 1 else "u2u8")
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
            if inner[0] == "a":              # C: a qualified array type is an array of qualified elements (s176 m1)
                return _qual_elems(q, inner)
            return ("q", "".join(c for c in "rVK" if c in q), inner)
        if kind == K_TYPE_TAG:
            return self.canon(st, depth + 1, typedef_name)
        if kind == K_TYPEDEF:
            return self.canon(st, depth + 1, name)
        if kind in (K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FWD):
            if name == "__va_list" and kind in (K_STRUCT, K_FWD):
                return ("s", name)      # AAPCS64: va_list is struct std::__va_list, mangled St9__va_list
            if name:  # the tag only matters for the C label (c_type); the mangling is the name alone
                tag = {K_STRUCT: "struct", K_UNION: "union", K_ENUM: "enum", K_ENUM64: "enum"}.get(kind)
                return ("n", name, tag or ("union" if kflag else "struct"))   # K_FWD: kflag 1 = union
            # the typedef on the path first: BTF dedup can merge identical anonymous types of several typedefs; the
            # first direct typedef only when the path had none, as through a pointer typedef (review s176 m2)
            linkage = typedef_name or self.linkage_names().get(tid)
            if linkage:
                return ("n", linkage, "")
            raise Unmangleable("anonymous struct, union or enum")
        if kind == K_ARRAY:
            # review s176 F1/M1: BTF writes 0 elements for both "T []" and GNU "T [0]"; read it as "[]" (Clang: A_),
            # the commoner one in prototypes. TypeNames also enters the "[0]" form (A0_), see zero_bound().
            return ("a", extra[2] or None, self.canon(extra[0], depth + 1))
        if kind == K_FUNC:
            return self.canon(st, depth + 1)
        if kind == K_FUNC_PROTO:
            ret = self.canon(st, depth + 1)       # clang keeps a top-level const / volatile on the return type
            if len(extra) == 1 and extra[0][1] == 0:
                return ("f", ret, None, False)    # int (*)(): clang's BTF writes one unnamed varargs parameter
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


def _qual_elems(q, a):
    """The array type a with the qualifiers q moved onto its (innermost) element type, as C and Clang read
    'const T' for an array type T: 'const arr4_t *' is 'const int (*)[4]', mangled PA4_Ki (review s176 m1)."""
    e = a[2]
    if e[0] == "a":
        return ("a", a[1], _qual_elems(q, e))
    if e[0] == "q":
        q, e = q + e[1], e[2]
    return ("a", a[1], ("q", "".join(c for c in "rVK" if c in q), e))


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


MAX_TYPE_NODES = 512   # a canonical prototype larger than this (expanded) is skipped; the largest on GKI 6.1-6.12 has 51


def tree_size(t, _seen=None):
    """Nodes of canonical type t when expanded as a tree; shared sub-tuples are counted per use but computed once."""
    seen = {} if _seen is None else _seen
    if not isinstance(t, tuple):
        if isinstance(t, list):
            return sum(tree_size(x, seen) for x in t)
        return 0
    n = seen.get(id(t))
    if n is None:
        n = seen[id(t)] = 1 + sum(tree_size(x, seen) for x in t)
    return n


def zero_bound(t):
    """t with every unknown-bound array ("a", None, ...) read as a GNU zero-length one ("a", 0, ...): BTF writes both
    the same way (review s176 F1/M1)."""
    if not isinstance(t, tuple) or not t:
        return t
    k = t[0]
    if k == "a":
        return ("a", 0 if t[1] is None else t[1], zero_bound(t[2]))
    if k == "p":
        return ("p", zero_bound(t[1]))
    if k == "q":
        return ("q", t[1], zero_bound(t[2]))
    if k == "f":
        params = t[2] if t[2] is None else type(t[2])(zero_bound(p) for p in t[2])
        return ("f", zero_bound(t[1]), params, t[3])
    return t


class TypeNames:
    """hash -> [(mangled, readable type, [example names])] from every FUNC_PROTO of a BTF blob.

    Example names are the functions (BTF FUNC) of that prototype, else 'struct.member' for function
    pointers in structs and unions, else the typedef that names the pointer type.

    members: {(kCFI hash, byte offset): ['struct.member', ...]} of every function-pointer member (member_slots()), for
    naming the member a call loads its pointer from (name_members())."""

    def __init__(self, btf, examples=3):
        self.by_hash = defaultdict(dict)
        self.plain_of = defaultdict(set)     # integer-normalized mangled name -> the plain mangled names behind it
        self.readable = {}                   # plain mangled name -> C text (c_type of its canonical type)
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
        proto_mangled = defaultdict(set)   # FUNC_PROTO id -> its mangled names as a C type (no K&R variant)
        for tid, (kind, _name, _kf, _st, _extra) in enumerate(btf.types):
            if kind != K_FUNC_PROTO:
                continue
            self.protos += 1
            try:
                t = btf.canon(tid)
                if tree_size(t) > MAX_TYPE_NODES:   # shared parts still expand in mangle() and c_type()
                    raise Unmangleable("type too large")
                mangle(t)
            except Unmangleable:
                self.unmangleable += 1
                continue
            variants = [(t, True)]
            if not btf.types[tid][4] and tid in funcs:
                # A function defined "long f()" (K&R) and one defined "long f(void)" have the same BTF
                # (FUNC_PROTO, vlen 0) but different kCFI hashes (_ZTSFlE, _ZTSFlvE).  The K&R type is
                # entered too, without example names, since BTF cannot say which functions are K&R.
                variants.append((("f", t[1], None, False), False))
            for v, with_names in list(variants):
                z = zero_bound(v)
                if z != v:                     # "T (*)[]" in BTF may also have been a GNU "T (*)[0]" (A0_)
                    variants.append((z, with_names))
            for v, with_names in variants:
                plain = mangle(v)
                if plain not in self.readable:
                    self.readable[plain] = c_type(v)
                for mangled in (plain, mangle(v, normalize=True)):   # plain and integer-normalized kCFI
                    if mangled != plain:
                        self.plain_of[mangled].add(plain)
                    if with_names:
                        proto_mangled[tid].add(mangled)
                    fs, os_ = seen.setdefault(mangled, ([], []))
                    if with_names:
                        fs.extend(n for n in funcs.get(tid, ()) if len(fs) < examples)
                        os_.extend(n for n in others.get(tid, ()) if len(os_) < examples)
        hash_of = {}
        for mangled, (fs, os_) in seen.items():
            names = []
            for n in fs + os_:                 # functions first, then struct members and typedefs
                if n not in names and len(names) < examples:
                    names.append(n)
            h = hash_of[mangled] = kcfi_hash(mangled)
            self.by_hash[h][mangled] = names
        self.member_sizes = {}               # (hash, offset) -> sizes of the structs with such a member there
        self.members = member_slots(btf, {tid: {hash_of[m] for m in ms} for tid, ms in proto_mangled.items()},
                                    self.member_sizes)

    def lookup(self, h):
        """[(mangled, readable, examples)] for a 32-bit hash, [] if no prototype gives it."""
        out = []
        for mangled, ex in sorted(self.by_hash.get(h, {}).items()):
            readable = self.readable.get(mangled) or demangle_type(mangled)
            if mangled in self.plain_of:       # one normalized name can stand for several C types (long, long long)
                readable = " | ".join(sorted(self.readable.get(p) or demangle_type(p) or p
                                             for p in self.plain_of[mangled])) + " [normalized]"
            out.append((mangled, readable or mangled, list(ex)))
        return out

    def label(self, h):
        """Readable C type(s) of a hash ('int (struct file *, int)'), ' | ' between collisions; None if unknown."""
        names = [r for _m, r, _e in self.lookup(h)]
        return " | ".join(names) if names else None


MAX_MEMBER_ENTRIES = 1 << 21   # member_slots() gives up (returns {}) beyond this many entries: crafted BTF, not a kernel
MAX_MEMBER_ARRAY = 64      # array members of up to this many elements are indexed element by element


class _TooMany(Exception):
    pass


def member_slots(btf, hashes, sizes=None):
    """{(kCFI hash, byte offset): sorted ['struct.member', ...]} for every function-pointer member of every named
    struct or union in BTF (and every one a typedef names), at its byte offset from the start of that struct. Members
    of embedded struct and union members (by value, anonymous or not, at any depth) and of arrays (of up to
    MAX_MEMBER_ARRAY elements) are entered at their offset in the outer struct too, under the name of the struct that
    declares them: 'proto_ops.sendmsg' wherever a struct proto_ops is embedded; an anonymous struct or union takes
    the name of the nearest named one around it. hashes: {FUNC_PROTO id: its kCFI hashes} (TypeNames).
    {} when BTF nests a struct in itself or the entries would pass MAX_MEMBER_ENTRIES (crafted BTF, not a kernel): no
    member is named then, rather than some of them. sizes, if a dict, receives {(hash, offset): {byte size of each
    struct or union that has such a member at that offset, embedded ones included}} (rank_slots(): arrays of them)."""
    types = btf.types
    link = btf.linkage_names()
    memo = {}                     # (type id, label of an anonymous one) -> [(offset, hash, 'struct.member')]
    busy = set()                  # the structs being expanded: one inside itself means crafted BTF
    count = [0]

    def strip(t):
        n = 0
        while n < 16 and 0 < t < len(types) and types[t][0] in (K_TYPEDEF, K_CONST, K_VOLATILE, K_RESTRICT, K_TYPE_TAG):
            t, n = types[t][3], n + 1
        return t

    def entries(tid, label):
        key = (tid, label)
        got = memo.get(key)
        if got is not None:
            return got
        if tid in busy:
            raise _TooMany()
        busy.add(tid)
        out = []
        _kind, _name, kflag, _size, extra = types[tid]
        for name_off, mtid, moff in extra:
            off = ((moff & 0xffffff) if kflag else moff) // 8
            mname = btf.name(name_off)
            reps, mt = (0,), mtid
            t = strip(mt)
            if 0 < t < len(types) and types[t][0] == K_ARRAY:   # T m[N]: element j at m + j * sizeof(T)
                elem, _index, n = types[t][4]
                size = _type_size(btf, elem)
                if not 0 < n <= MAX_MEMBER_ARRAY or not size:
                    continue
                reps, mt = tuple(j * size for j in range(n)), elem
                t = strip(mt)
            if not 0 < t < len(types):
                continue
            before = len(out)
            if types[t][0] in (K_STRUCT, K_UNION):
                inner = types[t][1] or link.get(t)
                sub = entries(t, inner or label + ("." + mname if mname else ""))
                out.extend((off + r + o, h, n_) for r in reps for o, h, n_ in sub)
            elif types[t][0] == K_PTR:                  # a function pointer: one pointer level, not iw_handler *
                proto = strip(types[t][3])
                if 0 < proto < len(types) and types[proto][0] == K_FUNC_PROTO:
                    text = "%s.%s" % (label, mname)
                    out.extend((off + r, h, text) for r in reps for h in hashes.get(proto, ()))
            count[0] += len(out) - before
            if count[0] > MAX_MEMBER_ENTRIES:
                raise _TooMany()
        busy.discard(tid)
        memo[key] = out
        return out

    slots, by_size = defaultdict(set), defaultdict(set)
    try:
        for tid, (kind, name, _kf, size, extra) in enumerate(types):
            if kind in (K_STRUCT, K_UNION) and extra and (name or link.get(tid)):
                for off, h, label in entries(tid, name or link[tid]):
                    slots[(h, off)].add(label)
                    by_size[(h, off)].add(size)
    except (_TooMany, RecursionError):
        return {}
    if sizes is not None:
        sizes.update(by_size)
    return {k: sorted(v) for k, v in slots.items()}


def _type_size(btf, tid, depth=0):
    """Byte size of a BTF type (through typedefs, qualifiers and arrays); 0 if unknown."""
    while depth < 16 and 0 < tid < len(btf.types):
        kind, _n, _kf, st, extra = btf.types[tid]
        if kind in (K_INT, K_STRUCT, K_UNION, K_ENUM, K_ENUM64, K_FLOAT):
            return st
        if kind == K_PTR:
            return 8
        if kind == K_ARRAY:
            return extra[2] * _type_size(btf, extra[0], depth + 1)
        if kind not in (K_TYPEDEF, K_CONST, K_VOLATILE, K_RESTRICT, K_TYPE_TAG):
            return 0
        tid, depth = st, depth + 1
    return 0


def name_members(sites, ranges, arch, names):
    """Set member_offset and members (core.Site) of the aarch64 kCFI sites: the byte offset of the load that fetched the
    called pointer (core.member_offsets()) and the struct members of names (a TypeNames) that have the call's type
    hash at that offset. Returns {"member_offsets": sites with an offset, "members_named": sites with at least one
    member, "members_unique": sites with exactly one}. Other architectures: x86-64 is not read (all zero)."""
    out = {"member_offsets": 0, "members_named": 0, "members_unique": 0}
    if arch != "aarch64":
        return out
    from .core import member_offsets
    slots = getattr(names, "members", None) or {}
    for s in sites:
        if getattr(s, "kind", "kcfi") == "kcfi":
            s.member_offset, s.members = None, []
    found = member_offsets(ranges, sites)
    for s in sites:
        off = found.get(s.check_ea) if getattr(s, "kind", "kcfi") == "kcfi" else None
        if off is None:
            continue
        s.member_offset = off
        s.members = list(slots.get((s.hash, off), ()))
        out["member_offsets"] += 1
        out["members_named"] += bool(s.members)
        out["members_unique"] += len(s.members) == 1
    return out


def rank_slots(sites, offsets, names):
    """Set slot_backed and slot_stride (core.Site) of each kCFI site with a struct member (name_members()). Slot-backed:
    the candidates that the image's static data stores at the member's offset inside an object, and, by array stride
    (slot_stride, listed after those), those stored at that offset modulo the size of a struct that has the member there
    in an object that holds another candidate of the call at such an offset (an array of such structs has several
    elements; one word proves nothing, as kallsyms gives no object size, so a word is charged to whatever object lies
    below it; a struct of 8 bytes is not used, as every 8-aligned slot would match it). offsets: {function address:
    {(object address, offset in it)}} (core.object_offsets()); names: the TypeNames that named the members
    (member_sizes). The candidate lists are not changed: core.slot_first() puts these first. A slot is evidence, not
    proof: a function stored there may be called through another table, and a pointer set at run time or in a module's
    table is in no slot here.
    Returns {"slot_calls": sites with at least one, "slot_calls_shorter": those that also have candidates of the same
    type only, "slot_calls_stride_only": those whose slot-backed candidates are all by array stride, "stored_candidates":
    distinct kCFI candidates stored in some object, "distinct_candidates": all}."""
    sizes_of = getattr(names, "member_sizes", None) or {}
    out = {"slot_calls": 0, "slot_calls_shorter": 0, "slot_calls_stride_only": 0}
    every = set()
    for s in sites:
        s.slot_backed, s.slot_stride = set(), set()
        if getattr(s, "kind", "kcfi") != "kcfi":
            continue
        every.update(s.targets)
        off = s.member_offset
        if not s.members or off is None:
            continue
        sizes = [z for z in sizes_of.get((s.hash, off), ()) if z > max(off, 8)]
        exact, held = set(), defaultdict(set)       # held: object -> {(offset, candidate)} of this call's candidates
        for t in s.targets:
            for obj, o in offsets.get(t, ()):
                if o == off:
                    exact.add(t)
                if sizes:
                    held[obj].add((o, t))
        stride = set()
        for pairs in held.values():
            for z in sizes:
                hits = [(o, t) for o, t in pairs if o % z == off]
                if len({o for o, _t in hits}) >= 2:         # two elements of an array of such structs, at least
                    stride.update(t for o, t in hits if o != off)
        s.slot_stride = stride - exact
        s.slot_backed = exact | s.slot_stride
        if s.slot_backed:
            out["slot_calls"] += 1
            out["slot_calls_shorter"] += len(s.slot_backed) < len(s.targets)
            out["slot_calls_stride_only"] += not exact
    out["stored_candidates"] = sum(1 for t in every if t in offsets)
    out["distinct_candidates"] = len(every)
    return out


def slot_summary(st):
    """Summary line of rank_slots()'s counts."""
    return ("kCFI calls with a candidate stored in a slot of their struct member: %d (by array stride only: %d), those "
            "candidates listed first (%d of the %d lists also hold candidates of the same type only); kCFI candidates "
            "stored in a static object: %d of %d" % (st["slot_calls"], st["slot_calls_stride_only"],
                                                      st["slot_calls_shorter"], st["slot_calls"],
                                                      st["stored_candidates"], st["distinct_candidates"]))


def member_summary(st):
    """Summary line of name_members()'s counts."""
    return ("kCFI calls through a struct member: load offset decoded at %d, a BTF member of the call's type at that "
            "offset for %d (exactly one for %d)" % (st["member_offsets"], st["members_named"], st["members_unique"]))


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


def has_split_btf(data):
    """Does this ELF (a module, .ko) carry split BTF, which needs its kernel's BTF to be read?"""
    blob = find_btf(data)
    try:
        return blob is not None and is_split(blob)
    except (BTFError, struct.error):
        return False


def load_split_type_names(data, kernel_data):
    """TypeNames from a module's split BTF (data: the .ko) read on top of its kernel's BTF (kernel_data: an ELF with
    a .BTF section, a raw kernel image or raw BTF); None if data has no split BTF. BTFError if kernel_data has no
    BTF or the module's does not continue it."""
    if not has_split_btf(data):
        return None
    base = find_btf(kernel_data)
    if base is None:
        raise BTFError("no BTF found (no .BTF section, BTF header or raw BTF)")
    return TypeNames(BTF(find_btf(data), base=BTF(base)))


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
