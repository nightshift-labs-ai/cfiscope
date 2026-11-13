"""kCFI hash -> C function type: xxHash64, Itanium mangling of C function types, and BTF."""
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

    def test_type_names_table(self):
        tn = K.load_type_names(read("kcfi_types_btf.o"))
        self.assertEqual(tn.unmangleable, 0)
        self.assertEqual(tn.lookup(0x2c94c37f),
                         [("_ZTSFiP7sk_buffPKcPFviEE", "int (sk_buff*, char const*, void (*)(int))", ["f_skb"])])
        self.assertEqual(tn.label(0x5cc832a4), "int (sk_buff*, sk_buff*)")
        mangled, readable, ex = tn.lookup(0x4f4ccb9d)[0]
        self.assertEqual(mangled, "_ZTSFiP4fileiE")
        self.assertIn("ops_open", ex)
        self.assertIn("ops.open", ex)            # the struct member of the same type
        self.assertIsNone(tn.label(0x12345678))

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
