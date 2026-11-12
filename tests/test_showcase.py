"""tools/showcase_ida_stub.py on a fixture: the before/after it prints comes from the plugin's own IDA layer."""
import contextlib, io, os, subprocess, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "showcase_ida_stub.py")


class Showcase(unittest.TestCase):
    def test_fixture(self):
        out = subprocess.run([sys.executable, "-I", TOOL, os.path.join(HERE, "fixtures", "x86_64-kernel.o"),
                              "do_call_2+0x1a", "impl_2_1"], capture_output=True, text=True, check=True).stdout
        self.assertIn("comment: none; code xrefs from this call: none", out)
        self.assertIn("21 sites, 21 comments, 76 cross-references", out)
        self.assertIn("; kCFI 0x1300E12B: 3 candidate(s): impl_2_0, impl_2_1, impl_2_2", out)
        self.assertIn("code xrefs from this call (3): impl_2_0, impl_2_1, impl_2_2", out)
        self.assertIn("on impl_2_1: 1 row(s)\n  0x11e03a  do_call_2+0x1a  3 candidate(s)", out)
        self.assertIn("// CFIScope: 3 candidates: impl_2_0, impl_2_1, impl_2_2", out)


if __name__ == "__main__":
    unittest.main()
