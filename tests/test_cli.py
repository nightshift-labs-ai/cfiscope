"""The command-line scanner gives the compiler's answers, by name, with no IDA."""
import contextlib, io, json, os, struct, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli
FIX = os.path.join(HERE, "fixtures")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main([str(a) for a in argv])
    return rc, out.getvalue(), err.getvalue()


def truth():
    with open(os.path.join(FIX, "truth.json")) as fh:
        return json.load(fh)


class Cli(unittest.TestCase):
    def test_sites_by_name_match_compiler(self):
        for name, t in sorted(truth().items()):
            with self.subTest(name):
                rc, out, _ = run(os.path.join(FIX, name + ".o"), "--sites", "--json", "--max-list", "100")
                self.assertEqual(rc, 0)
                doc = json.loads(out)
                self.assertEqual(doc["stats"]["arch"], t["arch"])
                self.assertEqual(doc["stats"]["unresolved"], 0)
                got = {frozenset(x["name"] for x in s["targets"]) for s in doc["sites"]}
                expected = {frozenset(v) for v in t["signatures"].values()}
                self.assertEqual(got, expected)

    def test_callers_and_targets(self):
        t = truth()["x86_64-kernel"]
        sig, impls = sorted(t["signatures"].items())[0]
        path = os.path.join(FIX, "x86_64-kernel.o")
        rc, out, _ = run(path, "--callers", impls[-1], "--json")
        self.assertEqual(rc, 0)
        sites = json.loads(out)["sites"]
        self.assertEqual(len(sites), 1)
        self.assertEqual({x["name"] for x in sites[0]["targets"]}, set(impls))
        call = sites[0]["call"] or sites[0]["check"]
        rc, out, _ = run(path, "--targets", call)
        self.assertEqual(rc, 0)
        for fn in impls:
            self.assertIn(fn, out)

    def test_raw_image(self):
        # The .text of a fully linked-looking range: take one object's code as raw bytes.
        path = os.path.join(FIX, "aarch64-plain.o")
        with open(path, "rb") as fh:
            d = fh.read()
        arch, ranges, _ = cli.load_elf(d)
        base, code = max(ranges, key=lambda r: len(r[1]))
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(code)
            rc, out, _ = run(raw, "--raw", "--arch", arch, "--base", hex(base), "--json")
            self.assertEqual(rc, 0)
            self.assertGreater(json.loads(out)["stats"]["sites"], 0)
            rc, _, err = run(raw, "--raw")
            self.assertEqual(rc, 2)
            self.assertIn("--arch", err)

    def test_old_jump_table_cfi_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = os.path.join(tmp, "Image")
            with open(img, "wb") as fh:
                fh.write(b"\x1f\x20\x03\xd5" * 64 + b"\0.cfi_jt\0__cfi_check\0")
            rc, out, _ = run(img, "--raw", "--arch", "aarch64", "--base", "0xffffffc008000000")
            self.assertEqual(rc, 0)
            self.assertIn("older jump-table Clang CFI", out)
            self.assertNotIn("GCC", out)

    def test_bad_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            junk = os.path.join(tmp, "junk")
            with open(junk, "wb") as fh:
                fh.write(b"not an elf" * 10)
            rc, _, err = run(junk)
            self.assertEqual(rc, 2)
            self.assertIn("not an ELF", err)
            rc, _, err = run(os.path.join(tmp, "missing"))
            self.assertEqual(rc, 2)
            elf32 = os.path.join(tmp, "elf32")
            with open(elf32, "wb") as fh:
                fh.write(b"\x7fELF\x01\x01" + b"\0" * 58)
            rc, _, err = run(elf32)
            self.assertEqual(rc, 2)
            self.assertIn("64-bit", err)
        rc, _, err = run(os.path.join(FIX, "x86_64-kernel.o"), "--callers", "no_such_function")
        self.assertEqual(rc, 2)
        self.assertIn("unknown function", err)


def kernel_elf(path, bound_type=0x12, bounds=True, extra=None):
    """tests/test_core.kernel_with_rodata_hash() as an ELF (gen_fixtures' writer), with its text bound symbols typed
    bound_type: 0x12 (global FUNC) as vmlinux-to-elf writes them, 0x10 (global NOTYPE) as in a vmlinux.
    extra: {name: address} added to (or replacing) those bound symbols."""
    sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, "..", "tools"))
    from test_core import kernel_with_rodata_hash, KB
    import gen_fixtures
    code, named = kernel_with_rodata_hash()
    named.update(extra or {})
    symbols = [("caller", KB), ("impl", KB + 0x24)] + (sorted(named.items()) if bounds else [])
    d = bytearray(gen_fixtures.elf64_aarch64(code, KB, symbols))
    sym = next(s for s in cli._sections(bytes(d)) if s[1] == 2)
    for i in range(3, len(symbols) + 1):          # entries 3.. are the bound symbols (0 is the null symbol)
        d[sym[4] + 24 * i + 4] = bound_type
    with open(path, "wb") as fh:
        fh.write(d)
    return KB


class TextBounds(unittest.TestCase):
    def test_elf_bounds_leave_out_rodata_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bound_type in (0x12, 0x10):
                path = os.path.join(tmp, "k%x.elf" % bound_type)
                kb = kernel_elf(path, bound_type)
                rc, out, _ = run(path, "--sites", "--json")
                self.assertEqual(rc, 0)
                doc = json.loads(out)
                self.assertEqual([t["name"] for t in doc["sites"][0]["targets"]], ["impl"])
                self.assertEqual(doc["stats"]["outside_text"], 1)
                rc, out, _ = run(path)
                self.assertIn("candidates outside kernel code left out: 1", out)
            # Without the bound symbols, or as a raw image, nothing is left out (and no new line or key appears).
            path = os.path.join(tmp, "nobounds.elf")
            kernel_elf(path, bounds=False)
            raw = os.path.join(tmp, "Image")
            with open(path, "rb") as fh:
                code = cli.load_elf(fh.read())[1][0][1]
            with open(raw, "wb") as fh:
                fh.write(code)
            for argv in ([path], [raw, "--raw", "--arch", "aarch64", "--base", hex(kb)]):
                rc, out, _ = run(*(argv + ["--sites", "--json"]))
                doc = json.loads(out)
                self.assertEqual([t["ea"] for t in doc["sites"][0]["targets"]], [hex(kb + 0x24), hex(kb + 0x1004)])
                self.assertNotIn("outside_text", doc["stats"])
                self.assertNotIn("outside kernel code", run(*argv)[1])

    def test_no_left_out_line_without_sites(self):
        # The bounds known but no kCFI check (its load made a nop): the summary has no line on candidates left out.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "k.elf")
            kernel_elf(path)
            with open(path, "rb") as fh:
                d = bytearray(fh.read())
            i = d.index(struct.pack("<I", 0xb85fc110))          # ldur w16, [x8, #-4]
            d[i:i + 4] = struct.pack("<I", 0xd503201f)          # nop
            with open(path, "wb") as fh:
                fh.write(d)
            rc, out, _ = run(path, "--json")
            st = json.loads(out)["stats"]
            self.assertEqual((rc, st["sites"], st["outside_text"]), (0, 0, 0))
            rc, out, _ = run(path)
            self.assertEqual(rc, 0)
            self.assertIn("call sites 0", out)
            self.assertNotIn("outside kernel code", out)


class EvalGki(unittest.TestCase):
    """tools/eval_gki.py names the bounds it filters with: only the code areas that reach between _etext and
    _sinittext, and only when kCFI candidates were filtered (jump-table CFI candidates never are)."""

    def eval_gki(self, image, elf, base):
        argv = [sys.executable, os.path.join(HERE, "..", "tools", "eval_gki.py"), "--base", hex(base), image, elf]
        done = subprocess.run(argv, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_bounds_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            elf, image = os.path.join(tmp, "k.elf"), os.path.join(tmp, "Image")
            # Listed: the entry trampoline between _etext and _sinittext. Not listed: idmap code inside .text (as GKI 6.1
            # names it), an area starting at _sinittext and an empty one, which keep nothing between the two.
            kb = 0xffffffc008000000
            kernel_elf(elf, extra={"__idmap_text_start": kb + 0x10, "__idmap_text_end": kb + 0x20,
                                   "__entry_tramp_text_start": kb + 0x1800, "__entry_tramp_text_end": kb + 0x1900,
                                   "__hibernate_exit_text_start": kb + 0x2000, "__hibernate_exit_text_end": kb + 0x2010,
                                   "__relocate_new_kernel_start": kb + 0x1a00, "__relocate_new_kernel_end": kb + 0x1a00})
            with open(elf, "rb") as fh:
                code = cli.load_elf(fh.read())[1][0][1]
            with open(image, "wb") as fh:
                fh.write(code)
            self.assertEqual(self.eval_gki(image, elf, kb)[0],
                             "candidates left out between _etext and _sinittext (%#x-%#x) except in the code areas "
                             "named there (%#x-%#x): 1" % (kb + 0x40, kb + 0x2000, kb + 0x1800, kb + 0x1900))
            kernel_elf(elf, bounds=False)
            self.assertEqual(self.eval_gki(image, elf, kb)[0],
                             "kernel code not named in the ELF's symbols: nothing left out")
            # A jump-table CFI kernel whose ELF names the four bounds: its candidates are not filtered.
            sys.path.insert(0, os.path.join(HERE, "..", "tools"))
            import gen_fixtures
            every = []
            with open(os.path.join(FIX, "aarch64-jtcfi.elf"), "rb") as fh:
                base, code = cli.load_elf(fh.read(), every)[1][0]
            end = base + len(code)
            with open(elf, "wb") as fh:
                fh.write(gen_fixtures.elf64_aarch64(code, base, [(name, ea) for ea, name in every] + [
                    ("_stext", base), ("_etext", end), ("_sinittext", end + 0x1000), ("_einittext", end + 0x1100)]))
            with open(image, "wb") as fh:
                fh.write(code)
            lines = self.eval_gki(image, elf, base)
            self.assertEqual(lines[0], "jump-table CFI: candidates are branch targets, nothing left out")
            self.assertIn("'scheme': 'jump-table CFI'", lines[2])


class Version(unittest.TestCase):
    def test_package_matches_manifest(self):
        from cfiscope import __version__
        with open(os.path.join(HERE, "..", "ida-plugin.json")) as fh:
            self.assertEqual(json.load(fh)["plugin"]["version"], __version__)


class BTFNames(unittest.TestCase):
    """kCFI hashes named by C function type from BTF (tests/fixtures/kcfi_types.c, built by zig cc)."""
    A64 = os.path.join(FIX, "kcfi_types_a64.o")
    BTF = os.path.join(FIX, "kcfi_types_btf.o")

    def test_sites_text(self):
        rc, out, _ = run(self.A64, "--sites", "--btf", self.BTF)
        self.assertEqual(rc, 0)
        self.assertIn("call hash 0x4f4ccb9d (int (struct file *, int))  1 candidate(s): ops_open", out)
        self.assertIn("call hash 0x1300e12b (long (short, int))  1 candidate(s): f_ls", out)
        self.assertIn("call hash 0x4a7b6fdc  0 candidate(s)", out)        # int (unsigned long): not in this BTF

    def test_summary_and_json(self):
        rc, out, _ = run(self.A64, "--btf", self.BTF)
        self.assertEqual(rc, 0)
        self.assertIn("kCFI hashes named: 3 of 4 (75.0%)", out)
        rc, out, _ = run(self.A64, "--sites", "--json", "--btf", self.BTF)
        doc = json.loads(out)
        self.assertEqual(doc["stats"]["kcfi_hashes_named"], 3)
        by_hash = {s["hash"]: s for s in doc["sites"]}
        self.assertEqual(by_hash["0xf2e4b17f"]["type"], "void (struct file *, struct file *)")
        self.assertEqual(by_hash["0xf2e4b17f"]["type_mangled"], "_ZTSFvP4fileS0_E")
        self.assertIn("ops.release", by_hash["0xf2e4b17f"]["type_examples"])
        self.assertIsNone(by_hash["0x4a7b6fdc"]["type"])

    def test_unchanged_without_btf(self):
        rc, out, _ = run(self.A64, "--sites", "--json")
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        self.assertNotIn("kcfi_hashes_named", doc["stats"])
        self.assertNotIn("type", doc["sites"][0])
        rc, out, _ = run(self.A64)
        self.assertNotIn("named", out.replace("named functions", ""))

    def test_input_with_its_own_btf(self):
        # A raw image holding both the code and a BTF blob: the BTF is found and used without --btf.
        from cfiscope import kcfi_types
        with open(self.A64, "rb") as fh:
            arch, ranges, _ = cli.load_elf(fh.read())
        base, code = ranges[0]
        with open(self.BTF, "rb") as fh:
            blob = kcfi_types.find_btf(fh.read())
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(code + b"\0" * 64 + blob)
            rc, out, _ = run(raw, "--raw", "--arch", arch, "--base", hex(base), "--json")
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out)["stats"]["kcfi_hashes_named"], 3)
            rc, out, _ = run(raw, "--raw", "--arch", arch, "--base", hex(base), "--json", "--no-btf")
            self.assertNotIn("kcfi_hashes_named", json.loads(out)["stats"])

    def test_btf_option_without_btf(self):
        rc, _, err = run(self.A64, "--btf", os.path.join(FIX, "aarch64-plain.o"))
        self.assertEqual(rc, 2)
        self.assertIn("no BTF found", err)


class BTFOnJumpTableCFI(unittest.TestCase):
    def test_btf_ignored_with_a_note(self):
        # review s176 N2: --btf names kCFI hashes only; on a jump-table CFI input it was ignored without a word
        rc, out, err = run(os.path.join(FIX, "aarch64-jtcfi.elf"), "--btf", "/nonexistent/x.btf")
        self.assertEqual(rc, 0)
        self.assertIn("--btf is for kCFI type hashes; ignored for this jump-table CFI kernel", err)


class QuickTryFixtureBTF(unittest.TestCase):
    """s176: the Quick-try fixtures carry the BTF of t.c (tools/add_btf_section.py), so the first try names types."""

    def test_fixtures_name_every_hash(self):
        for arch in ("x86_64", "aarch64"):
            rc, out, _ = run(os.path.join(FIX, arch + "-kernel.o"))
            self.assertEqual(rc, 0)
            self.assertIn("kCFI hashes named: 21 of 21 (100.0%)", out, arch)

    def test_add_btf_section_round_trip(self):
        sys.path.insert(0, os.path.join(HERE, "..", "tools"))
        try:
            import add_btf_section as A
        finally:
            sys.path.pop(0)
        btf = A.btf_of(os.path.join(HERE, "fixtures", "x86_64-kernel.o"))
        self.assertEqual(btf[:2], b"\x9f\xeb")  # BTF magic 0xeb9f, little-endian
        with open(os.path.join(FIX, "aarch64-plain.o"), "rb") as fh:
            plain = fh.read()
        out = A.add_btf(plain, btf)
        hdrs0, names0, strndx = A.sections(plain)
        hdrs1, names1, _ = A.sections(out)
        self.assertEqual(names1, names0 + [".BTF"])
        for i, (h0, h1) in enumerate(zip(hdrs0, hdrs1)):  # every old section keeps its bytes (names: + ".BTF")
            old, new = plain[h0[4]:h0[4] + h0[5]], out[h1[4]:h1[4] + h1[5]]
            if i == strndx:
                self.assertEqual(new, old + b".BTF\x00")
            elif h0[1] != 8:  # not SHT_NOBITS
                self.assertEqual(new, old)
        h = hdrs1[-1]
        self.assertEqual(out[h[4]:h[4] + h[5]], btf)
        with self.assertRaises(SystemExit):
            A.add_btf(out, btf)  # a second .BTF is refused


if __name__ == "__main__":
    unittest.main()
