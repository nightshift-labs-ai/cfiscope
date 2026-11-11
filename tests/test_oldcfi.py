"""Linux 5.x jump-table CFI (aarch64): the hand-assembled fixture from tools/gen_fixtures.py, scored against
jtcfi_truth.json, plus decoder and demangler checks."""
import contextlib, io, json, os, struct, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli, core  # noqa: E402
FIX = os.path.join(HERE, "fixtures")
ELF = os.path.join(FIX, "aarch64-jtcfi.elf")


def truth():
    with open(os.path.join(FIX, "jtcfi_truth.json")) as fh:
        return json.load(fh)


def load():
    with open(ELF, "rb") as fh:
        d = fh.read()
    every = []
    arch, ranges, symbols = cli.load_elf(d, every)
    return arch, ranges, symbols, every


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main([str(a) for a in argv])
    return rc, out.getvalue(), err.getvalue()


class Fixture(unittest.TestCase):
    def setUp(self):
        self.t = truth()
        self.arch, self.ranges, self.symbols, self.every = load()
        self.sites, self.stats = core.resolve(self.ranges, self.arch)
        self.name_of = {int(v, 16): k for k, v in self.t["symbols"].items() if not k.startswith("__")}

    def test_jump_table(self):
        jt = core.find_jump_table(self.ranges)
        start, n = self.t["jump_table"]
        self.assertEqual((jt.start, len(jt.targets), jt.entry_size), (int(start, 16), n, 8))
        self.assertEqual([self.name_of[x] for x in jt.targets], ["f_a", "f_b", "f_c", "g_one"])
        self.assertEqual(self.stats["scheme"], "jump-table CFI")
        self.assertEqual(self.stats["slowpath_functions"], [self.t["slowpath"]])

    def test_every_site_exact(self):
        self.assertEqual(self.stats["sites"], len(self.t["sites"]))
        by_call = {s.call_ea: s for s in self.sites}
        for want in self.t["sites"]:
            with self.subTest(want["function"]):
                s = by_call[int(want["call"], 16)]
                self.assertEqual(s.kind, want["kind"])
                self.assertEqual([self.name_of[x] for x in s.targets], want["candidates"])
                self.assertEqual("0x%016x" % s.type_id, want["type_id"])
                self.assertFalse(s.is_tail)
        self.assertEqual(self.stats["calls_with_candidates"], 5)
        self.assertEqual(self.stats["indirect_calls"], 6)

    def test_type_names(self):
        self.assertEqual(core.name_jt_types(self.sites, self.every), 5)
        names = self.t["type_names"]
        by_call = {s.call_ea: s for s in self.sites}
        for want in self.t["sites"]:
            s = by_call[int(want["call"], 16)]
            if want["kind"] == "slowpath":       # no __typeid symbol: no function of that type here
                self.assertIsNone(s.type_name)
                self.assertEqual(core.type_label(s), "type id " + want["type_id"])
                self.assertIsNone(s.note)
            else:
                self.assertEqual(s.type_name, names[want["type"]])
                self.assertEqual(s.type_mangled, want["type"])

    def test_cli_json_by_name(self):
        rc, out, _ = run(ELF, "--sites", "--json")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        got = {s["call"]: s for s in doc["sites"]}
        for want in self.t["sites"]:
            s = got[want["call"]]
            self.assertEqual(s["kind"], want["kind"])
            self.assertEqual([x["name"] for x in s["targets"]], want["candidates"])
            self.assertEqual(s["type_id"], want["type_id"])
            self.assertEqual(s["hash"], want["type_id"])
            self.assertEqual(s["in"].split("+")[0], want["function"])
        rc, out, _ = run(ELF, "--callers", "g_one")
        self.assertIn("1 call site(s) can reach g_one", out)
        self.assertIn("void (void*)", out)
        rc, out, _ = run(ELF, "--targets", self.t["sites"][0]["call"])
        self.assertEqual(rc, 0)
        self.assertIn("int (file*, int)", out)
        for fn in ("f_a", "f_b", "f_c"):
            self.assertIn(fn, out)

    def test_cli_summary_and_raw(self):
        rc, out, _ = run(ELF)
        self.assertIn("jump-table CFI: jump table %s-" % self.t["jump_table"][0], out)
        self.assertIn("4 entries of 8 bytes", out)
        base, code = self.ranges[0]
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(code)
            rc, out, _ = run(raw, "--raw", "--arch", "aarch64", "--base", hex(base), "--json")
            st = json.loads(out)["stats"]
            self.assertEqual((st["sites"], st["calls_with_candidates"], st["named_types"]), (6, 5, 0))
            # adrp is relative to the pc: a base off by whole pages only moves every address.
            rc, out, _ = run(raw, "--raw", "--arch", "aarch64", "--base", hex(base + 0x1000), "--sites", "--json")
            calls = sorted(int(s["call"], 16) for s in json.loads(out)["sites"])
            self.assertEqual(calls, sorted(int(w["call"], 16) + 0x1000 for w in self.t["sites"]))

    def test_kcfi_objects_unchanged(self):
        for name in ("aarch64-kernel", "aarch64-plain"):
            with open(os.path.join(FIX, name + ".o"), "rb") as fh:
                arch, ranges, _ = cli.load_elf(fh.read())
            sites, stats = core.resolve(ranges, arch)
            self.assertNotIn("scheme", stats)
            self.assertTrue(all(s.kind == "kcfi" for s in sites))

    def test_no_slow_path_means_no_scheme(self):
        # The jump table alone, without checks, is not enough to switch scanners.
        base, code = self.ranges[0]
        jt = int(self.t["jump_table"][0], 16) - base
        blob = b"\x1f\x20\x03\xd5" * (jt // 4) + code[jt:jt + 32]
        self.assertIsNone(core.resolve_jump_table_cfi([(base, blob)]))
        self.assertNotIn("scheme", core.resolve([(base, blob)], "aarch64")[1])


class Decoding(unittest.TestCase):
    def test_type_id_is_md5_prefix(self):
        # The id vfs_read passes to __cfi_slowpath_diag in the GKI 5.15 kernel for int (struct file *, int).
        self.assertEqual(core.cfi_type_id("_ZTSFiP4fileiE"), 0x95a8373040082c4d)

    def test_demangle(self):
        cases = {
            "_ZTSFiP4fileiE": "int (file*, int)",
            "_ZTSFvvE": "void ()",
            "_ZTSFiP11task_structPK11user_regsetjjPKvS5_E":
                "int (task_struct*, user_regset const*, unsigned int, unsigned int, void const*, void const*)",
            "_ZTSFiPFvPvES_E": "int (void (*)(void*), void*)",
            "_ZTSFiPA4_iE": "int (int (*) [4])",
            "_ZTSFiPKczE": "int (char const*, ...)",
            "_ZTSFvP8btf_showPKcSt9__va_listE": "void (btf_show*, char const*, std::__va_list)",
            "_ZTSFiP4fileiE.generalized": "int (file*, int) [generalized]",
        }
        for mangled, want in cases.items():
            self.assertEqual(core.demangle_type(mangled), want, mangled)
        for bad in ("_ZTSFiP4file", "_ZTSFiQE", "foo", "_ZTSFiS_E"):
            self.assertIsNone(core.demangle_type(bad), bad)

    def test_written_registers(self):
        self.assertEqual(set(core._written(0xa9bf7bfd)), {31})            # stp x29, x30, [sp, #-16]!: only sp
        self.assertEqual(set(core._written(0xa8c17bfd)), {29, 30, 31})    # ldp x29, x30, [sp], #16
        self.assertEqual(set(core._written(0xf90007e8)), set())           # str x8, [sp, #8]
        self.assertEqual(set(core._written(0xf94007e8)), {8})             # ldr x8, [sp, #8]
        self.assertIn(8, core._written(0x94000000))                       # bl: x8 is caller-saved
        self.assertNotIn(19, core._written(0x94000000))
        self.assertEqual(set(core._written(0xfa401904)), set())           # ccmp x8, #0, #4, ne: flags only

    def test_rotated_loop_b_is_stepped_over(self):
        # adrp x9; add x9; b L; <block reached elsewhere>; L: sub x10, x8, x9 -> base still found.
        base = 0x400000
        words = [0x90000009, 0x91010129, 0x14000003, 0xd503201f, 0xd503201f, 0xcb09010a]
        c = core._Code(base, struct.pack("<6I", *words))
        self.assertEqual(core._const_reg(c, 5, 9, 64), base + 0x40)
        words[2] = 0xd65f03c0                                             # ret instead of b: stop
        c = core._Code(base, struct.pack("<6I", *words))
        self.assertIsNone(core._const_reg(c, 5, 9, 64))


if __name__ == "__main__":
    unittest.main()
