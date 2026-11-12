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


class KcfiCallers(unittest.TestCase):
    def test_kcfi_check_without_call_is_still_a_call_site(self):
        from cfiscope import core
        s = core.Site(check_ea=0x1000, call_ea=0, hash=1, disp=0, is_tail=False, targets=[0x2000])
        calls, checks = core.callers([s], lambda t: t == 0x2000)
        self.assertEqual((calls, checks), ([s], []))

if __name__ == "__main__":
    unittest.main()
