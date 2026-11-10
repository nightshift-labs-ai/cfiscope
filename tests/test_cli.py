"""The command-line scanner gives the compiler's answers, by name, with no IDA."""
import contextlib, io, json, os, struct, sys, tempfile, unittest
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


class Version(unittest.TestCase):
    def test_package_matches_manifest(self):
        from cfiscope import __version__
        with open(os.path.join(HERE, "..", "ida-plugin.json")) as fh:
            self.assertEqual(json.load(fh)["plugin"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
