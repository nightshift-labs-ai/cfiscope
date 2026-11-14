"""tools/showcase_ida_stub.py on a fixture: the before/after it prints comes from the plugin's own IDA layer."""
import contextlib, importlib.util, io, json, os, struct, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli  # noqa: E402
TOOL = os.path.join(HERE, "..", "tools", "showcase_ida_stub.py")


def showcase_module():
    spec = importlib.util.spec_from_file_location("showcase_ida_stub", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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
        self.assertNotIn("Call-site list", out)       # only with --list: the README block stays as it is

    def test_call_site_list_equals_cli_sites(self):
        # Judge s193 #2: the list Scan opens has one row per `--sites` line, with its address, function+offset, type,
        # count and first names, in the fake database the showcase lays out as the command line does (same addresses).
        S = showcase_module()
        for name in ("x86_64-kernel.o", "aarch64-kernel.o"):
            with self.subTest(name):
                path = os.path.join(HERE, "fixtures", name)
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    self.assertEqual(cli.main([path, "--sites", "--json"]), 0)
                want = json.loads(buf.getvalue())["sites"]
                il = S.load(path)[0]
                sites, _ = il.scan()
                chooser = il.sites_chooser(sites)
                self.assertEqual(chooser.OnGetSize(), 21)
                self.assertEqual(len(want), 21)
                for n, c in enumerate(want):
                    names = [t["name"] for t in c["targets"]]
                    first = ", ".join(names[:6]) + (", +%d more" % (len(names) - 6) if len(names) > 6 else "")
                    self.assertEqual(chooser.OnGetLine(n), ["0x%x" % int(c["call"] or c["check"], 16), c["in"],
                                                            c["member"] or "", c["type"], str(c["candidates"]), first])
                self.assertIn(["", "long (short, int)", "3", "impl_2_0, impl_2_1, impl_2_2"],
                              [chooser.OnGetLine(n)[2:] for n in range(21)])

    def test_list_flag(self):
        out = subprocess.run([sys.executable, "-I", TOOL, os.path.join(HERE, "fixtures", "x86_64-kernel.o"),
                              "do_call_2+0x1a", "impl_2_1", "--list"], capture_output=True, text=True, check=True).stdout
        self.assertRegex(out, r"Call-site list \(opens after Scan; CFIScope: List kCFI call sites\): window 'CFIScope: 21 "
                              r"kCFI call sites', 21 rows, built in \d+\.\d\d s\n")
        self.assertIn("  columns: Address | Function+off | Member | Type | Candidates | First candidates\n"
                      "  row 2:  0x11e03a | do_call_2+0x1a |  | long (short, int) | 3 | impl_2_0, impl_2_1, impl_2_2\n"
                      "  command line --sites:  0x11e03a  do_call_2+0x1a                           jump hash 0x1300e12b "
                      "(long (short, int))  3 candidate(s): impl_2_0, impl_2_1, impl_2_2\n", out)

    def test_fixture_no(self):
        # --no answers No to "Create functions" (annotate(sites, create_functions=False)). Without impl_2_1's symbol,
        # impl_2_1 lies inside the function the fake starts at __cfi_impl_2_1: a data xref, no call xref.
        with tempfile.TemporaryDirectory() as tmp:
            obj = os.path.join(tmp, "x86_64-kernel.o")
            not_a_function(os.path.join(HERE, "fixtures", "x86_64-kernel.o"), "impl_2_1", obj)
            out = subprocess.run([sys.executable, "-I", TOOL, obj, "do_call_2+0x1a", "impl_2_0", "--no"],
                                 capture_output=True, text=True, check=True).stdout
        self.assertIn('AFTER Scan kCFI calls (Alt-Shift-K), answered No to "Create functions": 21 sites, 21 comments, '
                      '75 call and 1 data cross-references in the whole database; 0 skipped (no function there)', out)
        self.assertIn("code xrefs from this call (2): impl_2_0, impl_2_2", out)
        self.assertIn("data xrefs from this call (1): __cfi_impl_2_1+0x20", out)

    def test_module_with_split_btf(self):
        # Review s193: on a module with split BTF (GKI bluetooth.ko, 8021q.ko) the scan prints a hint with
        # ida_kernwin.msg, which the showcase's fake modules lacked: AttributeError, so the VERIFICATION .ko numbers
        # did not reproduce. Here kcfi_types_a64.o carries split BTF, as a .ko does (test_cli.ModuleSplitBTF).
        from test_cli import ModuleSplitBTF
        with tempfile.TemporaryDirectory() as tmp:
            module, _ = ModuleSplitBTF().module(tmp)
            r = subprocess.run([sys.executable, "-I", TOOL, module, "call_some+0x60", "ops_open"],
                               capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertIn("Output window: [CFIScope] this module's BTF is split BTF", r.stdout)
        self.assertIn("4 sites, 4 comments, 3 cross-references in the whole database", r.stdout)
        self.assertIn("; kCFI 0x4F4CCB9D: 1 candidate(s): ops_open", r.stdout)      # no type: split BTF not read
        self.assertIn("on ops_open: 1 row(s)", r.stdout)

    @unittest.skipUnless(os.path.isfile(os.path.join(os.environ.get("CFISCOPE_KO_DIR", ""), "bluetooth.ko")),
                         "set CFISCOPE_KO_DIR to a folder with the GKI bluetooth.ko and 8021q.ko of docs/VERIFICATION.md")
    def test_real_modules(self):
        # docs/VERIFICATION.md, "The IDA layer on a module": 253 / 253 / 1,176 and 6 / 6 / 7.
        ko = os.environ["CFISCOPE_KO_DIR"]
        for name, call, callee, want in (
                ("bluetooth.ko", "compute_ecdh_secret+0x160", "hci_conn_failed", "253 sites, 253 comments, 1176"),
                ("8021q.ko", "vlan_dev_hard_header+0x120", "vlan_dev_hard_header", "6 sites, 6 comments, 7")):
            with self.subTest(name):
                out = subprocess.run([sys.executable, "-I", TOOL, os.path.join(ko, name), call, callee],
                                     capture_output=True, text=True, check=True).stdout
                self.assertIn(want + " cross-references in the whole database", out)


if __name__ == "__main__":
    unittest.main()
