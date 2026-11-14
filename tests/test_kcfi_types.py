"""kCFI hash -> C function type: xxHash64, Itanium mangling of C function types, and BTF."""
import time
import os, struct, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)
from cfiscope import kcfi_types as K
from test_core import sections, symbols
FIX = os.path.join(HERE, "fixtures")


def read(name):
    with open(os.path.join(FIX, name), "rb") as fh:
        return fh.read()


def proto_ids(btf):
    """{function name: FUNC_PROTO id}: BTF FUNCs, and the members of the fixture's 'struct protos'."""
    out = {}
    for kind, name, _kf, st, extra in btf.types:
        if kind == K.K_FUNC:
            out[name] = st
    for kind, name, _kf, st, extra in btf.types:
        if kind == K.K_STRUCT and name == "protos":
            for moff, mtid, _o in extra:
                out.setdefault(btf.name(moff), K._proto_behind(btf, mtid))
    return out


def _extra(t):
    kind, extra = t[0], t[4]
    if kind == K.K_INT:
        return 4
    if kind == K.K_ARRAY:
        return 12
    if kind in (K.K_STRUCT, K.K_UNION, K.K_DATASEC, K.K_ENUM64):
        return 12 * len(extra)
    if kind in (K.K_ENUM, K.K_FUNC_PROTO):
        return 8 * len(extra)
    return 4 if kind in (K.K_VAR, K.K_DECL_TAG) else 0


def split_btf(blob, k):
    """(base, split): a BTF blob cut into a "kernel" BTF of its first k types and a "module" split BTF of the rest, as
    pahole writes a module's .BTF: the split's type ids continue the base's, and its strings follow the base's
    (here a copy of all strings, so every non-zero name offset in the split's records moves up by the base's string
    length)."""
    hdr_len = struct.unpack_from("<I", blob, 4)[0]
    type_off, type_len, str_off, str_len = struct.unpack_from("<4I", blob, 8)
    t0, s0 = hdr_len + type_off, hdr_len + str_off
    strings = blob[s0:s0 + str_len]
    names = []          # (record start, [offsets of the record's string offsets]) per type
    p = t0
    while p < t0 + type_len:
        _n, info, _st = struct.unpack_from("<3I", blob, p)
        vlen, kind = info & 0xffff, (info >> 24) & 0x1f
        at, q = [p], p + 12
        if kind in (K.K_INT, K.K_VAR, K.K_DECL_TAG):
            q += 4
        elif kind == K.K_ARRAY:
            q += 12
        elif kind in (K.K_STRUCT, K.K_UNION, K.K_ENUM64):
            at += [q + 12 * i for i in range(vlen)]
            q += 12 * vlen
        elif kind == K.K_DATASEC:
            q += 12 * vlen
        elif kind in (K.K_ENUM, K.K_FUNC_PROTO):
            at += [q + 8 * i for i in range(vlen)]
            q += 8 * vlen
        names.append((p, q, at))
        p = q
    cut = names[k][0] if k < len(names) else t0 + type_len
    def blob_of(types, strs):
        return struct.pack("<HBBI4I", 0xEB9F, 1, 0, 24, 0, len(types), len(types), len(strs)) + types + strs
    base = blob_of(bytes(blob[t0:cut]), strings)
    split = bytearray(blob[cut:t0 + type_len])
    for _p, _q, at in names[k:]:
        for a in at:
            off = struct.unpack_from("<I", split, a - cut)[0]
            if off:
                struct.pack_into("<I", split, a - cut, off + len(strings))
    return base, blob_of(bytes(split), strings)


class Hash(unittest.TestCase):
    def test_xxh64_reference(self):
        self.assertEqual(K.xxh64(b""), 0xEF46DB3751D8E999)
        self.assertEqual(K.xxh64(b"a" * 40), K.xxh64(bytes(b"a" * 40)))

    def test_verified_clang_hashes(self):
        # Both checked against clang -fsanitize=kcfi output.
        self.assertEqual(K.kcfi_hash("_ZTSFlsiE"), 0x1300e12b)
        self.assertEqual(K.kcfi_hash("_ZTSFiP7sk_buffPKcPFviEE"), 0x2c94c37f)
        self.assertEqual(K.kcfi_hash("FlsiE"), 0x1300e12b)


class Mangle(unittest.TestCase):
    def test_builtins_and_void(self):
        f = ("f", ("b", "l"), [("b", "s"), ("b", "i")], False)
        self.assertEqual(K.mangle(f), "_ZTSFlsiE")
        self.assertEqual(K.mangle(("f", ("b", "v"), [], False)), "_ZTSFvvE")
        self.assertEqual(K.mangle(("f", ("b", "i"), [("p", ("q", "K", ("b", "c")))], True)), "_ZTSFiPKczE")

    def test_substitutions(self):
        skb = ("p", ("n", "sk_buff"))
        self.assertEqual(K.mangle(("f", ("b", "i"), [skb, skb], False)), "_ZTSFiP7sk_buffS0_E")
        cc = ("p", ("q", "K", ("b", "c")))
        self.assertEqual(K.mangle(("f", ("b", "i"), [cc, cc], False)), "_ZTSFiPKcS0_E")
        pte = ("n", "pte_t")
        self.assertEqual(K.mangle(("f", pte, [pte, ("n", "anon_e")], False)), "_ZTSF5pte_tS_6anon_eE")

    def test_param_decay(self):
        # Clang's DWARF (and so BTF) already decays parameters; a BTF writer that does not still mangles right.
        self.assertEqual(K._param(("a", 4, ("b", "i"))), ("p", ("b", "i")))
        f = ("f", ("b", "v"), [("b", "i")], False)
        self.assertEqual(K._param(f), ("p", f))
        self.assertEqual(K._param(("q", "K", ("b", "i"))), ("b", "i"))

    def test_aarch64_va_list(self):
        # AAPCS64 va_list is std::__va_list. 0x37b1f161 is the hash at btf_show's call of show->showfn in the
        # GKI 6.1 kernel (candidates btf_seq_show, btf_snprintf_show), void (struct btf_show *, const char *, va_list).
        f = ("f", ("b", "v"), [("p", ("n", "btf_show")), ("p", ("q", "K", ("b", "c"))), ("s", "__va_list")], False)
        self.assertEqual(K.mangle(f), "_ZTSFvP8btf_showPKcSt9__va_listE")
        self.assertEqual(K.kcfi_hash(K.mangle(f)), 0x37b1f161)
        # Made-up counts: rounded down, so 100.0% only when every hash is named (GKI 6.1 really gives 4184 of 4184).
        self.assertEqual(K.named_summary(4182, 4184), "kCFI hashes named: 4182 of 4184 (99.9%)")
        self.assertEqual(K.named_summary(3, 3), "kCFI hashes named: 3 of 3 (100.0%)")

    def test_seq_ids(self):
        self.assertEqual([K._seq_id(i) for i in (0, 1, 10, 11, 36, 37)], ["S_", "S0_", "S9_", "SA_", "SZ_", "S10_"])

    def test_function_pointer_param_is_substituted(self):
        fp = ("p", ("f", ("b", "v"), [("b", "i")], False))
        self.assertEqual(K.mangle(("f", ("b", "v"), [fp, fp], False)), "_ZTSFvPFviES0_E")


class FixtureBTF(unittest.TestCase):
    """tests/fixtures/kcfi_types.c built twice by zig cc (clang): aarch64 kCFI and bpf BTF."""

    def test_every_function_hash_matches_its_preamble(self):
        d, S, text = sections(os.path.join(FIX, "kcfi_types_a64.o"))
        syms = symbols(d, S)
        btf = K.BTF(K.find_btf(read("kcfi_types_btf.o")))
        protos = proto_ids(btf)
        checked = 0
        for name, (sh, val) in sorted(syms.items()):
            if sh not in text or val < 4 or name == "call_some":   # call_some: kCFI only, no BTF
                continue
            with self.subTest(name):
                want = struct.unpack_from("<I", text[sh], val - 4)[0]
                got = K.kcfi_hash(K.mangle(btf.canon(protos[name])))
                self.assertEqual(got, want, name)
                checked += 1
        self.assertEqual(checked, 17)

    def test_oracle_corpus(self):
        """175 kernel-style prototypes (kcfi_oracle.c), hashes from clang; 162 reach BTF (the bpf target rejects
        the rest). Every one matches in both modes except K&R 'f()' definitions, which BTF records like 'f(void)'
        (the kernel forbids them: -Werror=strict-prototypes)."""
        import json
        with open(os.path.join(FIX, "kcfi_oracle_truth.json")) as fh:
            truth = [x for x in json.load(fh)["functions"] if x["in_btf"]]
        btf = K.BTF(K.find_btf(read("kcfi_oracle_btf.o")))
        protos = proto_ids(btf)
        for kind, name, _kf, st, extra in btf.types:      # bodies the bpf target cannot build: struct members
            if kind in (K.K_STRUCT, K.K_UNION):
                for moff, mtid, _o in extra:
                    pid = K._proto_behind(btf, mtid)
                    if pid:
                        protos.setdefault(btf.name(moff), pid)
        miss, missn = [], []
        for x in truth:
            t = btf.canon(protos[x["fn"]])
            if K.kcfi_hash(K.mangle(t)) != x["hash"]:
                miss.append(x["fn"])
            if K.kcfi_hash(K.mangle(t, normalize=True)) != x["hash_normalized_ints"]:  # x86-64
                missn.append(x["fn"])
        self.assertEqual(len(truth), 162)
        self.assertEqual(sorted(miss), ["n_noproto", "n_noproto_int"])
        self.assertEqual(sorted(missn), ["n_noproto", "n_noproto_int"])

    def test_normalized_integers_match_arm64_preamble(self):
        """kcfi_types_a64_norm.o = kcfi_types.c for aarch64 with -fsanitize-cfi-icall-experimental-normalize-integers
        (zig 0.17.1 / clang 22.1.8). arm64's plain char is unsigned (u2u8); the fixture's BTF comes from the bpf
        target, where it is signed, so plain char is set to arm64's here. (Kernel BTF from pahole does not mark plain char
        signed, and every kernel since Linux 6.2 builds it unsigned, so the unmarked default, unsigned, fits there.)"""
        def arm64_char(t):
            if t[0] == "b":
                return ("b", "c", "u2u8") if t[1] == "c" else t
            if t[0] in ("p",):
                return ("p", arm64_char(t[1]))
            if t[0] == "q":
                return ("q", t[1], arm64_char(t[2]))
            if t[0] == "a":
                return ("a", t[1], arm64_char(t[2]))
            if t[0] == "f":
                return ("f", arm64_char(t[1]), None if t[2] is None else [arm64_char(x) for x in t[2]], t[3])
            return t
        d, S, text = sections(os.path.join(FIX, "kcfi_types_a64_norm.o"))
        syms = symbols(d, S)
        btf = K.BTF(K.find_btf(read("kcfi_types_btf.o")))
        protos = proto_ids(btf)
        checked = 0
        for name, (sh, val) in sorted(syms.items()):
            if sh not in text or val < 4 or name == "call_some":
                continue
            with self.subTest(name):
                want = struct.unpack_from("<I", text[sh], val - 4)[0]
                self.assertEqual(K.kcfi_hash(K.mangle(arm64_char(btf.canon(protos[name])), normalize=True)), want, name)
                checked += 1
        self.assertEqual(checked, 17)

    def test_type_names_table(self):
        tn = K.load_type_names(read("kcfi_types_btf.o"))
        self.assertEqual(tn.unmangleable, 0)
        self.assertEqual(tn.lookup(0x2c94c37f),
                         [("_ZTSFiP7sk_buffPKcPFviEE", "int (struct sk_buff *, const char *, void (*)(int))", ["f_skb"])])
        self.assertEqual(tn.label(0x5cc832a4), "int (struct sk_buff *, struct sk_buff *)")
        mangled, readable, ex = tn.lookup(0x4f4ccb9d)[0]
        self.assertEqual(mangled, "_ZTSFiP4fileiE")
        self.assertIn("ops_open", ex)
        self.assertIn("ops.open", ex)            # the struct member of the same type
        self.assertIsNone(tn.label(0x12345678))

    def test_c_labels(self):
        """Labels read as kernel C: struct/union/enum tags kept, a typedef that names an anonymous type kept, C
        declarators for pointers to functions; the canonical type (typedefs of named types resolved, parameters
        decayed, top-level qualifiers dropped), because that is what the hash covers."""
        data = read("kcfi_types_btf.o")
        btf = K.BTF(K.find_btf(data))
        tn = K.load_type_names(data)
        protos = proto_ids(btf)
        want = {
            "f_ls": "long (short, int)",
            "f_skb": "int (struct sk_buff *, const char *, void (*)(int))",
            "f_void": "void (void)",
            "f_two": "int (struct sk_buff *, struct sk_buff *)",
            "f_cc": "int (const char *, const char *)",
            "f_u64": "unsigned long long (unsigned int, unsigned long long, _Bool)",
            "f_uc": "unsigned char (signed char, char, unsigned short)",
            "f_pte": "pte_t (pte_t, anon_e)",
            "f_enum": "int (enum color, union u *)",
            "f_va": "int (const char *, ...)",
            "f_vp": "void *(const volatile void *, long long, unsigned long long)",
            "f_arr": "int (int *, char *, int)",
            "f_cbt": "void (void (*)(int), void (*)(int), struct file **)",
            "f_fp2": "int (int (*)(struct file *, int), struct file *)",
            "f_dbl": "double (float, double)",
            "ops_open": "int (struct file *, int)",
            "ops_release": "void (struct file *, struct file *)",
        }
        for name, text in sorted(want.items()):
            with self.subTest(name):
                h = K.kcfi_hash(K.mangle(btf.canon(protos[name])))
                self.assertEqual(tn.label(h), text)

    def test_c_type_declarators(self):
        b = lambda c: ("b", c)
        self.assertEqual(K.c_type(("p", ("q", "r", ("p", b("c"))))), "char *restrict *")
        self.assertEqual(K.c_type(("p", ("a", 4, b("i")))), "int (*)[4]")
        self.assertEqual(K.c_type(("p", ("p", ("f", b("v"), [b("i")], False)))), "void (**)(int)")
        self.assertEqual(K.c_type(("f", ("p", ("f", b("i"), [], False)), [b("l")], False)), "int (*(long))(void)")
        self.assertEqual(K.c_type(("q", "K", ("n", "x", "struct"))), "const struct x")

    def test_find_btf_raw_and_embedded(self):
        blob = K.find_btf(read("kcfi_types_btf.o"))
        self.assertEqual(K.find_btf(blob), blob)                                  # raw BTF file
        image = b"\x00" * 1000 + b"\x9f\xeb\x01\x00junk" + b"\x11" * 501 + blob + b"\xff" * 300
        self.assertEqual(K.find_btf(image), blob)                                 # inside a raw image
        self.assertIsNone(K.find_btf(b"\x9f\xeb\x01\x00" + b"\x00" * 100))
        self.assertIsNone(K.find_btf(read("kcfi_types_a64.o")))                   # no .BTF section

    def test_split_btf_refused(self):
        # A module's split BTF names strings and types of vmlinux's BTF: refused rather than misread.
        blob = bytearray(K.find_btf(read("kcfi_types_btf.o")))
        hdr_len = struct.unpack_from("<I", blob, 4)[0]
        struct.pack_into("<I", blob, hdr_len, 3000000)                 # first type's name in vmlinux's strings
        with self.assertRaises(K.BTFError):
            K.BTF(bytes(blob))
        blob = bytearray(K.find_btf(read("kcfi_types_btf.o")))
        b = K.BTF(bytes(blob))
        ptr = next(i for i, t in enumerate(b.types) if t[0] == K.K_PTR)
        off = hdr_len + sum(12 + _extra(t) for t in b.types[1:ptr])
        struct.pack_into("<I", blob, off + 8, 70000)                    # a pointer to a vmlinux type id
        with self.assertRaises(K.BTFError):
            K.BTF(bytes(blob))

    def test_split_btf_on_its_base(self):
        # ko189: a module's split BTF read on top of its kernel's BTF names the same prototypes as the whole BTF.
        whole = K.find_btf(read("kcfi_types_btf.o"))
        full = K.TypeNames(K.BTF(whole))
        types = K.BTF(whole).types
        t0 = struct.unpack_from("<I", whole, 4)[0]
        refs = [r for _k, _n, r in K._offsets(whole, t0, t0 + struct.unpack_from("<I", whole, 12)[0])]
        # A kernel's BTF stands alone: cut only where the first k types refer to none after them.
        closed = [k for k in range(1, len(types) - 1) if all(x <= k for r in refs[:k] for x in r)]
        self.assertGreaterEqual(len(closed), 3)
        for k in (closed[0], closed[len(closed) // 2], closed[-1]):
            with self.subTest(k=k):
                base, split = split_btf(whole, k)
                self.assertTrue(K.is_split(split))
                self.assertFalse(K.is_split(base))
                with self.assertRaises(K.BTFError):
                    K.BTF(split)                                        # alone: refused, as before
                both = K.BTF(split, base=K.BTF(base))
                self.assertEqual([t[:4] for t in both.types], [t[:4] for t in types])
                names = K.TypeNames(both)
                self.assertEqual(names.protos, full.protos)
                self.assertEqual({h: sorted(v) for h, v in names.by_hash.items()},
                                 {h: sorted(v) for h, v in full.by_hash.items()})
        self.assertFalse(K.is_split(whole))

    def test_split_btf_on_another_base(self):
        # The split BTF of one build on the kernel BTF of another: refused, not misread.
        whole = K.find_btf(read("kcfi_types_btf.o"))
        n = len(K.BTF(whole).types)
        base, split = split_btf(whole, n // 2)
        other = K.find_btf(read("kcfi_quirks_btf.o"))
        with self.assertRaises(K.BTFError):
            K.BTF(split, base=K.BTF(other))

    def test_datasec_offsets_are_not_type_ids(self):
        # vmlinux's .data..percpu DATASEC has variable offsets far above its type count: not split BTF.
        blob = bytearray(K.find_btf(read("kcfi_types_btf.o")))
        hdr_len = struct.unpack_from("<I", blob, 4)[0]
        b = K.BTF(bytes(blob))
        ds = next(i for i, t in enumerate(b.types) if t[0] == K.K_DATASEC)
        off = hdr_len + sum(12 + _extra(t) for t in b.types[1:ds])
        struct.pack_into("<I", blob, off + 12 + 4, 5000000)            # first variable's offset
        self.assertEqual(len(K.BTF(bytes(blob)).types), len(b.types))

    def test_param_adjustments(self):
        btf = K.BTF(K.find_btf(read("kcfi_types_btf.o")))
        protos = proto_ids(btf)
        # int f_arr(int a[4], char *restrict p, const int k): decay, top-level restrict and const dropped
        self.assertEqual(K.mangle(btf.canon(protos["f_arr"])), "_ZTSFiPiPciE")
        # void *f_vp(const volatile void *, ...): pointee qualifiers kept in V K order
        self.assertEqual(K.mangle(btf.canon(protos["f_vp"])), "_ZTSFPvPVKvxyE")


class QuirksBTF(unittest.TestCase):
    """tests/fixtures/kcfi_quirks.c (aarch64 kCFI + bpf BTF): const return types, K&R () prototypes.
    Found by the review_s175 ground-truth corpus (175 functions; these were its 4 mismatches)."""

    def preamble_hashes(self):
        d, S, text = sections(os.path.join(FIX, "kcfi_quirks_a64.o"))
        out = {}
        for name, (sh, val) in symbols(d, S).items():
            if sh in text and val >= 4:
                out[name] = struct.unpack_from("<I", text[sh], val - 4)[0]
        return out

    def test_mangling(self):
        btf = K.BTF(K.find_btf(read("kcfi_quirks_btf.o")))
        protos = proto_ids(btf)
        self.assertEqual(K.mangle(btf.canon(protos["q_const_ret_toplevel"])), "_ZTSFKivE")
        self.assertEqual(K.mangle(btf.canon(protos["q_volatile_ret"])), "_ZTSFVliE")
        self.assertEqual(K.mangle(btf.canon(protos["fp_noproto_cb"])), "_ZTSFvPFiEE")
        self.assertEqual(K.mangle(btf.canon(protos["fp_void_cb"])), "_ZTSFvPFivEE")

    def test_every_function_hash_is_named(self):
        # BTF cannot tell long f() from long f(void) (both FUNC_PROTO vlen=0), so a FUNC's empty prototype is
        # also entered under its K&R hash; every function's preamble hash must be in the table.
        hashes = self.preamble_hashes()
        self.assertEqual(len(hashes), 8)
        tn = K.load_type_names(read("kcfi_quirks_btf.o"))
        for name, h in sorted(hashes.items()):
            with self.subTest(name):
                self.assertTrue(tn.lookup(h), "%s 0x%08x not named" % (name, h))
        self.assertEqual([m for m, _r, _e in tn.lookup(hashes["n_noproto"])], ["_ZTSFlE"])
        self.assertEqual([m for m, _r, _e in tn.lookup(hashes["n_void_params"])], ["_ZTSFlvE"])
        self.assertEqual(tn.lookup(hashes["n_noproto_int"])[0][2], [])    # K&R guess: no example names


class ArraysBTF(unittest.TestCase):
    """tests/fixtures/kcfi_arrays.c (aarch64 kCFI + bpf BTF): BTF writes 0 elements for both 'u32 (*)[]' and
    'u32 (*)[0]'; Clang mangles them A_ and A0_ (review s176 F1/M1: the 2 unnamed GKI 6.1 vendor-hook hashes)."""

    def test_every_function_hash_is_named(self):
        d, S, text = sections(os.path.join(FIX, "kcfi_arrays_a64.o"))
        hashes = {name: struct.unpack_from("<I", text[sh], val - 4)[0]
                  for name, (sh, val) in symbols(d, S).items() if sh in text and val >= 4}
        self.assertEqual(sorted(hashes), ["probe_sized", "probe_unknown", "probe_zero", "q_blocks", "q_const_arr"])
        tn = K.load_type_names(read("kcfi_arrays_btf.o"))
        want = {"probe_unknown": ("_ZTSFvPvPjPA_jE", "void (void *, unsigned int *, unsigned int (*)[])"),
                "probe_zero": ("_ZTSFvPvPjPA0_jE", "void (void *, unsigned int *, unsigned int (*)[0])"),
                "probe_sized": ("_ZTSFvPvPjPA7_jE", "void (void *, unsigned int *, unsigned int (*)[7])"),
                # review s176 m1: the qualifier goes on the elements (Clang PA4_Ki), also in the C label
                "q_const_arr": ("_ZTSFvPA4_KiE", "void (const int (*)[4])"),
                "q_blocks": ("_ZTSFiPA16_KhPA16_hE", "int (const unsigned char (*)[16], unsigned char (*)[16])")}
        for name, (mangled, label) in sorted(want.items()):
            with self.subTest(name):
                got = tn.lookup(hashes[name])
                self.assertEqual([(m, r) for m, r, _e in got], [(mangled, label)], "%s 0x%08x" % (name, hashes[name]))


class CraftedBTF(unittest.TestCase):
    """review s176 NIT: a crafted chain of FUNC_PROTOs, each taking two pointers to the next, made canon() exponential
    (5.96 s at 18 levels; the depth cap allows ~32). A plugin that opens untrusted binaries must not hang on one."""

    @staticmethod
    def chain(levels):
        strs = b"\0int\0"
        types = [struct.pack("<3I", 1, (K.K_INT << 24), 4) + struct.pack("<I", (1 << 24) | 32)]   # id 1: int
        for k in range(levels):  # id 2+2k: FUNC_PROTO(p, p) with p = id 3+2k: PTR -> the next FUNC_PROTO
            pid = 2 + 2 * k
            nxt, tgt = (pid + 2, pid + 1) if k < levels - 1 else (1, 1)
            types.append(struct.pack("<3I", 0, (K.K_FUNC_PROTO << 24) | 2, 1) + struct.pack("<2I", 0, tgt) * 2)
            types.append(struct.pack("<3I", 0, (K.K_PTR << 24), nxt))
        tsec = b"".join(types)
        return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(tsec), len(tsec), len(strs)) + tsec + strs

    def test_exponential_chain_is_fast(self):
        start = time.monotonic()
        tn = K.TypeNames(K.BTF(self.chain(30)))
        self.assertLess(time.monotonic() - start, 5.0)
        self.assertEqual(tn.protos, 30)
        self.assertGreater(tn.unmangleable, 0)      # the huge ones are skipped, not hung on
        self.assertLess(tn.unmangleable, 30)        # the small ones near the end of the chain are still named


class CraftedDepth(unittest.TestCase):
    """s176 final check M1: the canon memo must keep the 64-level cap: a failure cached on a deep walk must not fail a
    shallow use of the same type, and results must not depend on the order prototypes are read."""

    @staticmethod
    def chain_btf(n=70, off=30):
        strs = b"\0int\0"
        types = [struct.pack("<3I", 1, K.K_INT << 24, 4) + struct.pack("<I", (1 << 24) | 32)]          # 1 int
        first = 4
        types.append(struct.pack("<3I", 0, (K.K_FUNC_PROTO << 24) | 1, 1) + struct.pack("<2I", 0, first))
        types.append(struct.pack("<3I", 0, (K.K_FUNC_PROTO << 24) | 1, 1) + struct.pack("<2I", 0, first + off))
        for i in range(n):  # a chain of n pointers ending at int; proto 2 starts at its head, proto 3 off pointers in
            types.append(struct.pack("<3I", 0, K.K_PTR << 24, first + i + 1 if i < n - 1 else 1))
        tsec = b"".join(types)
        return struct.pack("<HBBIIIII", 0xEB9F, 1, 0, 24, 0, len(tsec), len(tsec), len(strs)) + tsec + strs

    def outcome(self, btf, tid):
        try:
            K.mangle(btf.canon(tid))
            return "ok"
        except K.Unmangleable:
            return "too deep"

    def test_order_does_not_matter(self):
        for order in ((2, 3), (3, 2)):
            btf = K.BTF(self.chain_btf())
            got = {tid: self.outcome(btf, tid) for tid in order}
            self.assertEqual(got, {2: "too deep", 3: "ok"}, order)


class AnonTypedefBTF(unittest.TestCase):
    """tests/fixtures/kcfi_anon.c: an anonymous struct or enum is mangled under its first typedef's name, also when a
    prototype reaches it through a pointer typedef (review s176 m2: such prototypes were unmangleable)."""

    def test_every_function_hash_is_named(self):
        d, S, text = sections(os.path.join(FIX, "kcfi_anon_a64.o"))
        hashes = {name: struct.unpack_from("<I", text[sh], val - 4)[0]
                  for name, (sh, val) in symbols(d, S).items() if sh in text and val >= 4}
        self.assertEqual(sorted(hashes), ["anon_direct", "anon_enum_direct", "anon_enum_ptr", "anon_ptr_both",
                                          "anon_ptr_td"])
        tn = K.load_type_names(read("kcfi_anon_btf.o"))
        want = {"anon_ptr_td": ("_ZTSFiP4a2_tE", "int (a2_t *)"),
                "anon_direct": ("_ZTSFiP4a2_tE", "int (a2_t *)"),
                "anon_ptr_both": ("_ZTSFiP4a2_tS0_E", "int (a2_t *, a2_t *)"),
                "anon_enum_ptr": ("_ZTSFiP4e2_tE", "int (e2_t *)"),
                "anon_enum_direct": ("_ZTSFi4e2_tE", "int (e2_t)")}
        for name, (mangled, label) in sorted(want.items()):
            with self.subTest(name):
                got = tn.lookup(hashes[name])
                self.assertEqual([(m, r) for m, r, _e in got], [(mangled, label)], "%s 0x%08x" % (name, hashes[name]))


class Normalized(unittest.TestCase):
    """-fsanitize-cfi-icall-experimental-normalize-integers (kernels with Rust): u3i32-style integers, '.normalized'."""

    def test_clang_hash(self):
        # long (short, int) built by clang with the flag: 0xe1d7ea79 (review_s175 ground-truth corpus, x86_64)
        f = ("f", ("b", "l"), [("b", "s"), ("b", "i")], False)
        self.assertEqual(K.mangle(f, normalize=True), "_ZTSFu3i64u3i16u3i32E.normalized")
        self.assertEqual(K.kcfi_hash(K.mangle(f, normalize=True)), 0xe1d7ea79)
        # long and long long are the same vendor type, substituted by one representative
        g = ("f", ("b", "v"), [("b", "l"), ("b", "x"), ("p", ("b", "l"))], False)
        self.assertEqual(K.mangle(g, normalize=True), "_ZTSFvu3i64S_PS_E.normalized")

    def test_every_function_hash_is_named(self):
        d, S, text = sections(os.path.join(FIX, "kcfi_types_x64_norm.o"))
        tn = K.load_type_names(read("kcfi_types_btf.o"))
        checked = 0
        for name, (sh, val) in sorted(symbols(d, S).items()):
            if sh not in text or val < 5 or name == "call_some" or name.startswith("__cfi_"):
                continue
            with self.subTest(name):
                self.assertEqual(text[sh][val - 5], 0xB8)           # mov eax, imm32 in front of the function
                h = struct.unpack_from("<I", text[sh], val - 4)[0]
                found = [m for m, _r, _e in tn.lookup(h)]
                self.assertTrue(found and all(m.endswith(".normalized") for m in found), "%s 0x%08x" % (name, h))
                checked += 1
        self.assertEqual(checked, 17)
        self.assertEqual(tn.label(0xe1d7ea79), "long (short, int) [normalized]")
        self.assertEqual(tn.label(0x1300e12b), "long (short, int)")          # the plain hash stays named too


if __name__ == "__main__":
    unittest.main()
