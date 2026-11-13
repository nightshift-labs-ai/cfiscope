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

    def test_param_adjustments(self):
        btf = K.BTF(K.find_btf(read("kcfi_types_btf.o")))
        protos = proto_ids(btf)
        # int f_arr(int a[4], char *restrict p, const int k): decay, top-level restrict and const dropped
        self.assertEqual(K.mangle(btf.canon(protos["f_arr"])), "_ZTSFiPiPciE")
        # void *f_vp(const volatile void *, ...): pointee qualifiers kept in V K order
        self.assertEqual(K.mangle(btf.canon(protos["f_vp"])), "_ZTSFPvPVKvxyE")


if __name__ == "__main__":
    unittest.main()
