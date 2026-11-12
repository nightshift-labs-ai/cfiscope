"""Scores the scanner against objects whose answers the compiler knows."""
import json, os, struct, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import core
FIX = os.path.join(HERE, "fixtures")


def sections(path):
    with open(path, "rb") as fh:
        d = fh.read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]; n = struct.unpack_from("<H", d, 0x3c)[0]
    si = struct.unpack_from("<H", d, 0x3e)[0]
    S = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(n)]
    names = d[S[si][4]:S[si][4] + S[si][5]]
    out = {}
    for i, s in enumerate(S):
        nm = names[s[0]:names.index(b"\0", s[0])]
        if nm.startswith(b".text") and s[5]:
            out[i] = d[s[4]:s[4] + s[5]]
    return d, S, out


def symbols(d, S):
    out = {}
    for s in S:
        if s[1] == 2:
            st = S[s[6]]
            for i in range(s[5] // 24):
                nm, info, o, sh, val, sz = struct.unpack_from("<IBBHQQ", d, s[4] + 24 * i)
                if info & 15 == 2:
                    e = d.index(b"\0", st[4] + nm)
                    out[d[st[4] + nm:e].decode()] = (sh, val)
    return out


class Fixtures(unittest.TestCase):
    def test_all(self):
        with open(os.path.join(FIX, "truth.json")) as fh:
            truth = json.load(fh)
        for name, t in sorted(truth.items()):
            with self.subTest(name):
                d, S, text = sections(os.path.join(FIX, name + ".o"))
                syms = symbols(d, S)
                bases, ranges, base = {}, [], 0x100000
                for idx, mem in sorted(text.items()):
                    bases[idx] = base
                    ranges.append((base, mem))
                    base += (len(mem) + 0x1000) & ~0xfff
                sites, stats = core.resolve(ranges, t["arch"])
                self.assertEqual(stats["sites"], len(t["signatures"]))
                self.assertEqual(stats["unresolved"], 0)
                addr = {k: bases[v[0]] + v[1] for k, v in syms.items() if v[0] in bases}
                expected = {frozenset(addr[n] for n in names)
                            for names in t["signatures"].values()}
                got = {frozenset(s.targets) for s in sites}
                self.assertEqual(got, expected)


def x86_check(hash_, disp, tail):
    """Bytes of the sequence documented for Linux: mov r10d; add r10d,[r11+disp]; je; ud2."""
    neg = struct.pack("<I", (-hash_) & 0xffffffff)
    return b"\x41\xba" + neg + b"\x45\x03\x53" + struct.pack("<b", disp) + b"\x74\x02\x0f\x0b" + tail


class Decoders(unittest.TestCase):
    def test_linux_layout_with_retpoline_thunk(self):
        h = 0x12345678
        target_off = 0x40
        code = bytearray(b"\xcc" * 0x80)
        call = x86_check(h, -15, b"\xe8\x00\x00\x00\x00")
        code[0:len(call)] = call
        code[target_off - 15 - 1:target_off - 15 + 4] = b"\xb8" + struct.pack("<I", h)
        code[target_off] = 0x55
        sites, stats = core.resolve([(0x1000, bytes(code))], "x86_64")
        self.assertEqual(stats["sites"], 1)
        self.assertEqual(sites[0].targets, [0x1000 + target_off])
        self.assertEqual(sites[0].call_ea, 0x1000 + len(call) - 5)

    def test_tail_jump_flag(self):
        code = x86_check(0x1111, -4, b"\x41\xff\xe3") + b"\xcc" * 8
        sites, _ = core.resolve([(0, code)], "x86_64")
        self.assertTrue(sites[0].is_tail)

    def test_wrong_destination_register_rejected(self):
        code = bytearray(x86_check(0x1111, -4, b"\xff\xd0"))
        code[8] = 0x4b                # modrm reg = 1 (r9d), not r10d
        self.assertEqual(core.resolve([(0, bytes(code))], "x86_64")[1]["sites"], 0)

    def test_a64_movk_register_mismatch_rejected(self):
        words = [0xb85fc070, 0x7296b4b1, 0x72aadcb2, 0x6b11021f, 0x54000040, 0xd4304460, 0xd63f0060]
        code = struct.pack("<7I", *words)
        self.assertEqual(core.resolve([(0, code)], "aarch64")[1]["sites"], 0)

    def test_empty(self):
        self.assertEqual(core.resolve([(0, b"\x90" * 64)], "x86_64")[1]["sites"], 0)

    def test_unknown_arch(self):
        with self.assertRaises(ValueError):
            core.resolve([(0, b"")], "mips")


KB = 0xffffffc008000000     # where the tiny kernel below is loaded
KHASH = 0x2a5f1c3d


def kernel_with_rodata_hash():
    """A tiny aarch64 kernel: in text, one kCFI call and the one function of its type; after _etext, in 'rodata',
    the same hash value followed by a non-zero word (as in a string), which looks like a preamble and its function.
    Returns (code at KB, {text bound symbol: address}). The real target is KB + 0x24, the data one KB + 0x1004."""
    lo, hi = KHASH & 0xffff, KHASH >> 16
    text = [0xb85fc110,                   # ldur w16, [x8, #-4]
            0x72800000 | lo << 5 | 17,    # movk w17, #lo
            0x72a00000 | hi << 5 | 17,    # movk w17, #hi, lsl #16
            0x6b11021f,                   # cmp w16, w17
            0x54000040,                   # b.eq +8
            0xd4304500,                   # brk #0x8228
            0xd63f0100,                   # blr x8
            0xd65f03c0,                   # ret
            KHASH,                        # kCFI preamble
            0xd65f03c0]                   # impl: ret
    code = bytearray(0x2100)
    struct.pack_into("<%dI" % len(text), code, 0, *text)
    struct.pack_into("<2I", code, 0x1000, KHASH, 0x4e494c4e)     # the hash value inside data ("...NLIN")
    struct.pack_into("<I", code, 0x2000, 0xd65f03c0)             # init text
    bounds = {"_stext": KB, "_etext": KB + 0x40, "_sinittext": KB + 0x2000, "_einittext": KB + 0x2100}
    return bytes(code), bounds


def with_functions(code, *offsets):
    """code with one more function of the call's type (its hash word, then `ret`) starting at each offset, the code
    grown with zeros when an offset lies past its end."""
    code = bytearray(code)
    for off in offsets:
        code.extend(bytes(max(0, off + 4 - len(code))))
        struct.pack_into("<2I", code, off - 4, KHASH, 0xd65f03c0)
    return bytes(code)


class TextBounds(unittest.TestCase):
    def test_candidates_outside_kernel_text_left_out(self):
        code, bounds = kernel_with_rodata_hash()
        sites, stats = core.resolve([(KB, code)], "aarch64")
        self.assertEqual(sites[0].targets, [KB + 0x24, KB + 0x1004])   # no bounds: the data hit is a candidate
        self.assertNotIn("outside_text", stats)
        text = core.kernel_text(bounds)
        self.assertEqual(text, [(0, KB + 0x40), (KB + 0x2000, 1 << 64)])
        sites, stats = core.resolve([(KB, code)], "aarch64", text)
        self.assertEqual(sites[0].targets, [KB + 0x24])
        self.assertEqual((stats["outside_text"], stats["resolved"], stats["single_target"]), (1, 1, 1))

    def test_init_and_other_named_code_kept(self):
        code, bounds = kernel_with_rodata_hash()
        # the data hit inside init text, or inside an arm64 code area outside .text (idmap code since 6.6): kept
        for extra in ({"_sinittext": KB + 0x1000}, {"__idmap_text_start": KB + 0x1000, "__idmap_text_end": KB + 0x1100}):
            sites, _ = core.resolve([(KB, code)], "aarch64", core.kernel_text(dict(bounds, **extra)))
            self.assertEqual(sites[0].targets, [KB + 0x24, KB + 0x1004], extra)

    def test_code_area_inside_text(self):
        # GKI 6.1 names its idmap code inside _stext.._etext: a function after that area, still in .text, is kept.
        code, bounds = kernel_with_rodata_hash()
        text = core.kernel_text(dict(bounds, __idmap_text_start=KB + 0x10, __idmap_text_end=KB + 0x20))
        self.assertEqual(core.resolve([(KB, code)], "aarch64", text)[0][0].targets, [KB + 0x24])

    def test_without_all_four_bounds_nothing_changes(self):
        code, bounds = kernel_with_rodata_hash()
        plain = core.resolve([(KB, code)], "aarch64")
        for missing in ("_stext", "_etext", "_sinittext", "_einittext"):   # without init bounds, init text would be lost
            named = {k: v for k, v in bounds.items() if k != missing}
            self.assertIsNone(core.kernel_text(named))
            self.assertEqual(core.resolve([(KB, code)], "aarch64", core.kernel_text(named)), plain)
        self.assertIsNone(core.kernel_text(dict(bounds, _etext=KB)))   # _etext not after _stext
        self.assertIsNone(core.kernel_text(dict(bounds, _sinittext=KB + 0x20)))   # init text before _etext
        self.assertIsNone(core.kernel_text(dict(bounds, _einittext=KB + 0x2000)))   # empty init text

    def test_only_the_gap_after_text_is_filtered(self):
        # x86-64 names no exit text (no __exittext_begin/_end): a function after _einittext, in .exit.text, is kept,
        # as is one before _stext (arm64 head text); only the hit between _etext and _sinittext is left out.
        code, bounds = kernel_with_rodata_hash()
        code = with_functions(code, 0x2104)
        for named in (bounds, dict(bounds, _stext=KB + 0x28)):
            sites, stats = core.resolve([(KB, code)], "aarch64", core.kernel_text(named))
            self.assertEqual((sites[0].targets, stats["outside_text"]), ([KB + 0x24, KB + 0x2104], 1), named)


class KcfiCallers(unittest.TestCase):
    def test_kcfi_check_without_call_is_still_a_call_site(self):
        from cfiscope import core
        s = core.Site(check_ea=0x1000, call_ea=0, hash=1, disp=0, is_tail=False, targets=[0x2000])
        calls, checks = core.callers([s], lambda t: t == 0x2000)
        self.assertEqual((calls, checks), ([s], []))

if __name__ == "__main__":
    unittest.main()
