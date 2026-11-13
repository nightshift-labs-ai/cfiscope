"""tools/showcase_ida_stub.py on a fixture: the before/after it prints comes from the plugin's own IDA layer."""
import os, struct, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli  # noqa: E402
TOOL = os.path.join(HERE, "..", "tools", "showcase_ida_stub.py")


def not_a_function(src, name, dst):
    """Copy the ELF object src to dst with symbol `name` made STT_NOTYPE, so the showcase's fake database puts its
    address inside the function of the symbol before it (here the __cfi_ preamble, as IDA may do on x86)."""
    with open(src, "rb") as fh:
        d = bytearray(fh.read())
    secs = cli._sections(bytes(d))
    hits = 0
    for s in secs:
        if s[1] != 2:                                             # SHT_SYMTAB
            continue
        strtab = secs[s[6]]
        for off in range(s[4], s[4] + s[5], 24):
            start = strtab[4] + struct.unpack_from("<I", d, off)[0]
            if d[start:d.index(b"\0", start)] == name.encode():
                d[off + 4] &= 0xF0
                hits += 1
    assert hits == 1, hits
    with open(dst, "wb") as fh:
        fh.write(d)


class Showcase(unittest.TestCase):
    def test_fixture(self):
        out = subprocess.run([sys.executable, "-I", TOOL, os.path.join(HERE, "fixtures", "x86_64-kernel.o"),
                              "do_call_2+0x1a", "impl_2_1"], capture_output=True, text=True, check=True).stdout
        self.assertIn("comment: none; code xrefs from this call: none", out)
        self.assertIn("21 sites, 21 comments, 76 cross-references", out)
        # s176: the fixture carries the BTF of t.c (tools/add_btf_section.py), so the Quick try shows the C type too
        self.assertIn("; kCFI 0x1300E12B long (short, int): 3 candidate(s): impl_2_0, impl_2_1, impl_2_2", out)
        self.assertIn("(hash 0x1300E12B, long (short, int))", out)
        self.assertIn("code xrefs from this call (3): impl_2_0, impl_2_1, impl_2_2", out)
        self.assertIn("on impl_2_1: 1 row(s)\n  0x11e03a  do_call_2+0x1a  3 candidate(s)", out)
        self.assertIn("// CFIScope: 3 candidates of long (short, int): impl_2_0, impl_2_1, impl_2_2", out)

    def test_fixture_no(self):
        # --no answers No to "Create functions" (annotate(sites, create_functions=False)). Without impl_2_1's symbol,
        # impl_2_1 lies inside the function the fake starts at __cfi_impl_2_1: a data xref, no call xref.
        with tempfile.TemporaryDirectory() as tmp:
            obj = os.path.join(tmp, "x86_64-kernel.o")
            not_a_function(os.path.join(HERE, "fixtures", "x86_64-kernel.o"), "impl_2_1", obj)
            out = subprocess.run([sys.executable, "-I", TOOL, obj, "do_call_2+0x1a", "impl_2_0", "--no"],
                                 capture_output=True, text=True, check=True).stdout
        self.assertIn('AFTER Scan kCFI calls (Ctrl-Alt-K), answered No to "Create functions": 21 sites, 21 comments, '
                      '75 call and 1 data cross-references in the whole database; 0 skipped (no function there)', out)
        self.assertIn("code xrefs from this call (2): impl_2_0, impl_2_2", out)
        self.assertIn("data xrefs from this call (1): __cfi_impl_2_1+0x20", out)


if __name__ == "__main__":
    unittest.main()
