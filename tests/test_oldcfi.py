"""Linux 5.x jump-table CFI (aarch64): the hand-assembled fixture from tools/gen_fixtures.py, scored against
jtcfi_truth.json, plus decoder and demangler checks."""
import contextlib, io, json, os, struct, sys, tempfile, unittest
from unittest import mock
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
        self.assertEqual(self.stats["sites"], len(self.t["sites"]) + len(self.t["checks"]))
        by_call = {s.call_ea: s for s in self.sites}
        for want in self.t["sites"]:
            with self.subTest(want["function"]):
                s = by_call[int(want["call"], 16)]
                self.assertEqual(s.kind, want["kind"])
                self.assertEqual([self.name_of[x] for x in s.targets], want["candidates"])
                self.assertEqual("0x%016x" % s.type_id, want["type_id"])
                self.assertFalse(s.is_tail)
        self.assertEqual(self.stats["calls_with_candidates"], 8)
        self.assertEqual(self.stats["indirect_calls"], 11)
        # Checks with no linked call: one in a program function (its call goes through memory), and the CFI runtime's
        # own check in __cfi_check, which passes no type id and guards no call.
        by_check = {s.check_ea: s for s in self.sites if not s.call_ea}
        self.assertEqual(sorted(by_check), sorted(int(w["check"], 16) for w in self.t["checks"]))
        for want in self.t["checks"]:
            s = by_check[int(want["check"], 16)]
            self.assertEqual((s.kind, s.runtime_check), (want["kind"], want["runtime_check"]))
            self.assertEqual([self.name_of[x] for x in s.targets], want["candidates"])
            self.assertEqual(s.type_id, None if want["runtime_check"] else int(want["type_id"], 16))
        self.assertEqual((self.stats["checks_without_call"], self.stats["runtime_checks"]), (2, 1))
        # call_gap: a mov between sub and ror; read as one range check that starts at its sub (call_gap+0x14),
        # not only through the slow path as a hoisted check starting at the cmp.
        # The inlined slow path's blr is the CFI runtime calling __cfi_check (kernel's or a module's): recorded, never a call site.
        for want in self.t["sites"]:
            s = by_call[int(want["call"], 16)]
            self.assertEqual(s.runtime_call_ea, int(want["runtime_call"], 16) if "runtime_call" in want else 0)
        self.assertNotIn(int(self.t["sites"][-1]["runtime_call"], 16), by_call)
        self.assertEqual(self.stats["runtime_calls"], 1)
        gap = by_call[int(self.t["sites"][6]["call"], 16)]
        self.assertEqual(gap.check_ea, int(self.t["symbols"]["call_gap"], 16) + 0x14)

    def test_callers_leave_out_runtime_checks(self):
        sym = self.t["symbols"]
        f_b = int(sym["f_b"], 16)
        calls_want = [int(w["call"], 16) for w in self.t["sites"] if "f_b" in w["candidates"]]
        unlinked, runtime = (int(w["check"], 16) for w in self.t["checks"])
        # Code alone (no names): the runtime's check is left out, the other unlinked check comes after the calls.
        calls, checks = core.callers(self.sites, lambda t: t == f_b)
        self.assertEqual([s.call_ea for s in calls], calls_want)
        self.assertEqual([s.check_ea for s in checks], [unlinked])
        # With names or function bounds, a runtime check is left out even if the code test missed it.
        rt = next(s for s in self.sites if s.check_ea == runtime)
        rt.runtime_check = False
        self.assertEqual([s.check_ea for s in core.callers(self.sites, lambda t: t == f_b)[1]], [unlinked, runtime])
        names = cli.Names(self.symbols)
        test = cli.runtime_test(names, self.ranges)
        self.assertEqual([s.check_ea for s in core.callers(self.sites, lambda t: t == f_b, test)[1]], [unlinked])
        # By the name alone: with the code test reporting a blr everywhere, only the name __cfi_check marks it.
        with mock.patch.object(core, "has_indirect_call", lambda mem: True):
            test = cli.runtime_test(names, self.ranges)
            self.assertTrue(test(runtime))
            self.assertFalse(test(unlinked))
            self.assertEqual([s.check_ea for s in core.callers(self.sites, lambda t: t == f_b, test)[1]], [unlinked])
        renamed = cli.Names({ea: ("other" if n == "__cfi_check" else n) for ea, n in self.symbols.items()})
        test = cli.runtime_test(renamed, self.ranges)          # by code: a function with no blr/br
        self.assertTrue(test(runtime))
        self.assertFalse(test(unlinked))
        with mock.patch.object(core, "has_indirect_call", lambda mem: True):   # neither name nor code: kept
            self.assertFalse(cli.runtime_test(renamed, self.ranges)(runtime))
        self.assertEqual([s.check_ea for s in core.callers(self.sites, lambda t: t == f_b, test)[1]], [unlinked])
        self.assertEqual(core.callers_header(7, 1, "f_b"),
                         "7 call site(s) can reach f_b (+1 type check(s) whose call was not linked, listed last)")
        self.assertEqual(core.callers_header(6, 0, "f_b"), "6 call site(s) can reach f_b")

    def test_unlinked_check_without_slow_path_not_in_x1_stays(self):
        # The runtime's check tests the pointer in x1 (sub x8, x1, x8). With the pointer in x2 instead, the same check
        # (no linked call, no slow path) is not the runtime's by the code: an unlinked program check whose slow path
        # was not decoded looks like that, and Callers must keep it after the calls.
        unlinked, runtime = (int(w["check"], 16) for w in self.t["checks"])
        base, code = self.ranges[0]
        off = runtime - base
        w = struct.unpack_from("<I", code, off)[0]
        self.assertEqual((w & 0xffe0fc00, (w >> 5) & 31), (0xcb000000, 1))      # sub xS, x1, xB
        patched = bytearray(code)
        struct.pack_into("<I", patched, off, (w & ~(31 << 5)) | (2 << 5))      # sub xS, x2, xB
        sites, stats = core.resolve([(base, bytes(patched))], self.arch)
        s = next(x for x in sites if x.check_ea == runtime)
        self.assertEqual((s.kind, s.call_ea, s.type_id, s.runtime_check), ("range", 0, None, False))
        self.assertEqual(stats["runtime_checks"], 0)
        f_b = int(self.t["symbols"]["f_b"], 16)
        self.assertEqual([x.check_ea for x in core.callers(sites, lambda t: t == f_b)[1]], [unlinked, runtime])
        with tempfile.TemporaryDirectory() as tmp:          # --raw: no names, so only the code decides
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(patched)
            rc, out, _ = run(raw, "--raw", "--arch", "aarch64", "--base", hex(base), "--callers", hex(f_b))
        lines = out.splitlines()
        self.assertEqual(lines[0], "7 call site(s) can reach %s (+2 type check(s) whose call was not linked, listed "
                                   "last)" % hex(f_b))
        self.assertTrue(lines[-1].startswith("0x%x " % runtime), lines[-1])
        self.assertIn(" type check only (call not linked) range ", lines[-1])

    def test_sites_label_slow_path_only_without_call(self):
        # A slow-path-only site (no inline check was decoded for it): with its call not linked it keeps the 0.1.17 label
        # "check (call not linked)", not "type check only (call not linked)" (that is for range and single checks).
        import dataclasses
        names = cli.Names(self.symbols)
        slow = next(s for s in self.sites if s.kind == "slowpath")
        line = cli._site_line(dataclasses.replace(slow, call_ea=0), names, 8)
        self.assertIn(" check (call not linked) slowpath type id 0x", line)
        self.assertNotIn("type check only", line)
        unlinked = next(s for s in self.sites if s.check_ea == int(self.t["checks"][0]["check"], 16))
        self.assertIn(" type check only (call not linked) range ", cli._site_line(unlinked, names, 8))

    def test_cli_callers_count_calls_only(self):
        rc, out, _ = run(ELF, "--callers", "f_b")
        lines = out.splitlines()
        self.assertEqual(lines[0], "7 call site(s) can reach f_b (+1 type check(s) whose call was not linked, listed last)")
        self.assertEqual(len(lines), 1 + 7 + 1)
        self.assertTrue(all(" call range " in x for x in lines[1:8]))
        self.assertIn("call_unlinked+0x14", lines[8])
        self.assertIn("type check only (call not linked) range int (file*, int)", lines[8])
        self.assertNotIn("__cfi_check", out)
        rc, out, _ = run(ELF, "--sites")  # --sites still lists the runtime's own check, labelled as such
        rt = [x for x in out.splitlines() if "__cfi_check+" in x]
        self.assertEqual(len(rt), 1)
        self.assertIn("CFI runtime check (guards no call) range int (file*, int)", rt[0])
        self.assertIn("type check only (call not linked)", next(x for x in out.splitlines() if "call_unlinked+" in x))
        rc, out, _ = run(ELF, "--callers", "f_b", "--json")
        doc = json.loads(out)
        self.assertEqual(doc["callers"], {"call_sites": 7, "unlinked_checks": 1})
        self.assertEqual([s["check"] for s in doc["sites"] if s["call"] is None], [self.t["checks"][0]["check"]])
        # --sites still lists both checks; --json marks the runtime's.
        rc, out, _ = run(ELF, "--sites", "--json")
        flags = {s["check"]: s["runtime_check"] for s in json.loads(out)["sites"] if s["call"] is None}
        self.assertEqual(flags, {w["check"]: w["runtime_check"] for w in self.t["checks"]})
        # A raw image has no names: the code test alone leaves the runtime's check out.
        base, code = self.ranges[0]
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(code)
            rc, out, _ = run(raw, "--raw", "--arch", "aarch64", "--base", hex(base), "--callers", self.t["symbols"]["f_b"])
        self.assertTrue(out.startswith("7 call site(s) can reach %s (+1 type check(s)" % self.t["symbols"]["f_b"]), out)
        self.assertNotIn(self.t["checks"][1]["check"][2:], out)

    def test_type_names(self):
        self.assertEqual(core.name_jt_types(self.sites, self.every), 10)
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
            self.assertEqual((st["sites"], st["calls_with_candidates"], st["named_checks"]), (11, 8, 0))
            # adrp is relative to the pc: a base off by whole pages only moves every address.
            rc, out, _ = run(raw, "--raw", "--arch", "aarch64", "--base", hex(base + 0x1000), "--sites", "--json")
            calls = sorted(int(s["call"], 16) for s in json.loads(out)["sites"] if s["call"])
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
