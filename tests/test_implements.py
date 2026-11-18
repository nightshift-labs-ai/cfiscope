"""--implements SPEC (judge s193 #3): every function of the input whose kCFI preamble hash is that of a struct member
(file_operations.unlocked_ioctl), a C function type as the tool prints types, a mangled type, a hash, or the type of a
named function, whether or not some call site of the input checks that hash (in a module, the handlers of a kernel
table have no call site, so no Candidates list shows them)."""
import contextlib, io, json, os, struct, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli, core, kcfi_types as K  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
MEMBERS = os.path.join(FIX, "kcfi_members_a64.o")     # kcfi_members.c: aarch64 kCFI code + its BTF
QUIRKS, QUIRKS_BTF = os.path.join(FIX, "kcfi_quirks_a64.o"), os.path.join(FIX, "kcfi_quirks_btf.o")
GKI = os.environ.get("CFISCOPE_GKI_ELF", "")
KO = os.environ.get("CFISCOPE_KO_DIR", "")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main([str(a) for a in argv])
    return rc, out.getvalue(), err.getvalue()


def implements(path, spec, *more):
    rc, out, err = run(path, "--implements", spec, "--json", *more)
    if rc:
        raise AssertionError("rc %d: %s" % (rc, err))
    return json.loads(out)["implements"]


def names_of(doc):
    return [t["name"] for t in doc["targets"]]


def sites_of(path, *more):
    rc, out, err = run(path, "--sites", "--json", *more)
    assert rc == 0, err
    return json.loads(out)["sites"]


def truth():
    with open(os.path.join(FIX, "truth.json")) as fh:
        return json.load(fh)


class Fixtures(unittest.TestCase):
    """The impl_N_* groups of tests/fixtures/t.c (truth.json: the functions of one type each) come back by hash, by type
    and by function, on every fixture of truth.json; the hash is the one each group's call site checks."""

    def test_every_group_by_hash(self):
        for name, t in sorted(truth().items()):
            path = os.path.join(FIX, name + ".o")
            groups = {frozenset(v) for v in t["signatures"].values()}
            for s in sites_of(path):
                with self.subTest(fixture=name, hash=s["hash"]):
                    doc = implements(path, s["hash"])
                    self.assertEqual(doc["hash"], s["hash"])
                    self.assertIn(frozenset(names_of(doc)), groups)
                    self.assertEqual(names_of(doc), [x["name"] for x in s["targets"]])   # = the call's candidates
                    self.assertEqual(doc["functions"], len(doc["targets"]))

    def test_every_group_by_type_and_by_function(self):
        for name in ("x86_64-kernel", "aarch64-kernel"):        # the Quick-try fixtures carry t.c's BTF
            path = os.path.join(FIX, name + ".o")
            groups = {frozenset(v) for v in truth()[name]["signatures"].values()}
            for s in sites_of(path):
                with self.subTest(fixture=name, type=s["type"]):
                    group = [x["name"] for x in s["targets"]]
                    self.assertIn(frozenset(group), groups)
                    doc = implements(path, s["type"])
                    self.assertEqual((doc["hash"], doc["type"], names_of(doc)), (s["hash"], s["type"], group))
                    self.assertEqual(implements(path, s["type_mangled"])["hash"], s["hash"])
                    doc = implements(path, group[-1])                 # a function: the functions of its type
                    self.assertEqual((doc["hash"], names_of(doc)), (s["hash"], group))

    def test_text(self):
        # long (short, int) is do_call_2's type in t.c (README Quick try); its hash 0x1300e12b is in the README's
        # objdump excerpt of x86_64-plain.o.
        for name in ("x86_64-kernel", "aarch64-kernel"):
            path = os.path.join(FIX, name + ".o")
            s = next(x for x in sites_of(path) if x["in"].startswith("do_call_2+"))
            rows = ["    %s  %s" % (x["ea"], x["name"]) for x in s["targets"]]
            self.assertEqual([x["name"] for x in s["targets"]], ["impl_2_0", "impl_2_1", "impl_2_2"])
            for spec in ("long (short, int)", "long(short,int)", " long ( short , int ) ", "0x1300e12b", "0x1300E12B",
                         "_ZTSFlsiE"):
                with self.subTest(fixture=name, spec=spec):
                    rc, out, err = run(path, "--implements", spec)
                    self.assertEqual((rc, err), (0, ""))
                    self.assertEqual(out.splitlines(), ["3 function(s) with kCFI hash 0x1300e12b (long (short, int))"]
                                     + rows)
            rc, out, _ = run(path, "--implements", "impl_2_1")
            self.assertEqual(out.splitlines()[0], "3 function(s) with kCFI hash 0x1300e12b (long (short, int)), "
                                                  "the type of impl_2_1")
            rc, out, _ = run(path, "--implements", "0x1300e12b", "--no-btf")     # no BTF: the hash alone
            self.assertEqual(out.splitlines(), ["3 function(s) with kCFI hash 0x1300e12b"] + rows)

    def test_max_list(self):
        path = os.path.join(FIX, "aarch64-kernel.o")
        rc, out, _ = run(path, "--implements", "long (short, int)", "--max-list", "1")
        lines = out.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertTrue(lines[1].endswith("  impl_2_0"), lines)
        self.assertEqual(lines[2], "    ... 2 more")
        doc = implements(path, "long (short, int)", "--max-list", "1")
        self.assertEqual((doc["functions"], names_of(doc)), (3, ["impl_2_0"]))

    def test_json(self):
        doc = implements(os.path.join(FIX, "aarch64-kernel.o"), "long (short, int)")
        self.assertEqual(sorted(doc), ["functions", "hash", "member", "spec", "targets", "type", "type_mangled"])
        self.assertEqual((doc["spec"], doc["member"], doc["hash"], doc["type_mangled"], doc["functions"]),
                         ("long (short, int)", None, "0x1300e12b", "_ZTSFlsiE", 3))
        rc, out, _ = run(os.path.join(FIX, "aarch64-kernel.o"), "--implements", "0x1300e12b", "--json")
        self.assertIn("stats", json.loads(out))
        self.assertNotIn("sites", json.loads(out))


class Members(unittest.TestCase):
    """kcfi_members.c: struct members by name, embedded and anonymous ones included, with the errors."""

    def test_members(self):
        want = {"a_ops.send": ["send_x", "send_y"], "b_ops.send": ["send_x", "send_y"],
                "b_ops.recv": ["send_x", "send_y"], "c_ops.poll": ["poll_x", "poll_y"],
                "d_ops.poll": ["poll_x", "poll_y"], "a_ops.close": ["msg_close"],
                "a_ops.open": ["call_global", "msg_open"],        # int (struct msg *): call_global has that type too
                "inner_ops.notify": ["notify_x"], "outer.in.notify": ["notify_x"], "anon_holder.u_cb": ["u_cb_x"]}
        for spec, fns in sorted(want.items()):
            with self.subTest(spec):
                doc = implements(MEMBERS, spec)
                self.assertEqual((doc["member"], sorted(names_of(doc))), (spec, fns))
        doc = implements(MEMBERS, "a_ops.send")
        self.assertEqual((doc["hash"], doc["type"]), ("0xfd39cd44", "int (struct msg *, int)"))   # call_a_send's
        rc, out, _ = run(MEMBERS, "--implements", "a_ops.send")
        self.assertEqual(out.splitlines()[0], "2 function(s) with kCFI hash 0xfd39cd44 (int (struct msg *, int)), "
                                              "the type of a_ops.send")

    def test_a_type_no_call_site_checks(self):
        # call_a_send's own type: no call in the object goes through it, so no candidate list has it
        h = "0x%08x" % K.kcfi_hash("_ZTSFiP5a_opsP3msgE")
        self.assertNotIn(h, {s["hash"] for s in sites_of(MEMBERS)})
        for spec in (h, "int (struct a_ops *, struct msg *)", "call_a_send"):
            with self.subTest(spec):
                doc = implements(MEMBERS, spec)
                self.assertEqual((doc["hash"], names_of(doc)), (h, ["call_a_send"]))

    def test_errors(self):
        for spec, why in (("a_ops.nosuch", "struct a_ops has no member 'nosuch'"),
                          ("nosuch_ops.send", "no struct or union named 'nosuch_ops' in BTF"),
                          ("a_ops.flags", "a_ops.flags is not a function pointer (long)"),
                          ("outer.in", "outer.in is not a function pointer (struct inner_ops)"),
                          ("anon_holder.raw", "anon_holder.raw is not a function pointer (long)"),
                          ("a_ops.send.x", "a_ops.send is not a struct or union"),
                          ("int (struct nosuch *)", "no function type 'int (struct nosuch *)' in BTF"),
                          ("no_such_function", "no struct member, C function type, hash or function"),
                          ("0x123456789", "a kCFI hash has 32 bits"),
                          ("", "no struct member, C function type, hash or function")):
            with self.subTest(spec):
                rc, out, err = run(MEMBERS, "--implements", spec)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn(why, err)

    def test_needs_btf(self):
        for spec in ("a_ops.send", "int (struct msg *, int)"):
            with self.subTest(spec):
                rc, out, err = run(MEMBERS, "--implements", spec, "--no-btf")
                self.assertEqual((rc, out), (2, ""))
                self.assertIn("needs BTF", err)
                self.assertIn("give the hash", err)
        self.assertEqual(sorted(names_of(implements(MEMBERS, "0xfd39cd44", "--no-btf"))), ["send_x", "send_y"])

    def test_with_split_btf(self):
        # a module's split BTF on top of its kernel's (test_cli.ModuleSplitBTF): types by name need --btf KERNEL
        sys.path.insert(0, os.path.join(HERE, "..", "tools"))
        try:
            import add_btf_section as A
        finally:
            sys.path.pop(0)
        from test_kcfi_types import split_btf
        with open(MEMBERS, "rb") as fh:
            code = fh.read()
        blob = K.find_btf(code)
        base, split = split_btf(blob, (len(K.BTF(blob).types) - 1) // 2)
        with tempfile.TemporaryDirectory() as tmp:
            module, kernel = os.path.join(tmp, "m.ko"), os.path.join(tmp, "base.btf")
            with open(module, "wb") as fh:
                fh.write(A.add_btf(strip_btf(code), split))
            with open(kernel, "wb") as fh:
                fh.write(base)
            rc, out, err = run(module, "--implements", "a_ops.send")
            self.assertEqual(rc, 2)
            self.assertIn("split BTF", err)
            self.assertIn("needs BTF", err)
            doc = implements(module, "a_ops.send", "--btf", kernel)
            self.assertEqual(sorted(names_of(doc)), ["send_x", "send_y"])


def strip_btf(obj):
    """obj with its .BTF section renamed, so that add_btf_section can add another."""
    i = obj.index(b".BTF\0")
    return obj[:i] + b".XTF\0" + obj[i + 5:]


class WithKernel(unittest.TestCase):
    """--with VMLINUX: the kernel's functions of the type too, as --targets lists them (test_cli.module_and_kernel: a
    module whose impl_2_* lost their hash, and a kernel ELF of the same code with k_ names)."""

    def test_with(self):
        from test_cli import module_and_kernel
        with tempfile.TemporaryDirectory() as tmp:
            module, kernel = module_and_kernel(tmp)
            rc, out, err = run(module, "--implements", "0x1300e12b", "--with", kernel)
            self.assertEqual(rc, 0, err)
            lines = out.splitlines()
            # review s201: the module's group has a header too when the kernel's follows
            self.assertEqual(lines[:3], ["0 function(s) with kCFI hash 0x1300e12b", "  in module.o (0):",
                                         "  in kernel.elf (3):"])
            self.assertEqual([x.split()[1] for x in lines[3:]], ["k_impl_2_0", "k_impl_2_1", "k_impl_2_2"])
            rc, out, _ = run(module, "--implements", "0x1300e12b", "--with", kernel, "--max-list", "1")
            self.assertEqual(out.splitlines()[3:], [out.splitlines()[3], "    ... 2 more"])
            doc = implements(module, "0x36b1c5a6", "--with", kernel)       # int (void): impl_1_* in both
            self.assertEqual(names_of(doc), ["impl_1_%d" % k for k in range(6)])
            self.assertEqual((doc["kernel_functions"], [t["name"] for t in doc["kernel_targets"]]),
                             (6, ["k_impl_1_%d" % k for k in range(6)]))
            self.assertNotIn("kernel_functions", implements(module, "0x36b1c5a6"))
            rc, out, _ = run(module, "--implements", "0x36b1c5a6", "--with", kernel, "--max-list", "2")
            self.assertEqual([x.strip() for x in out.splitlines() if not x.startswith("    0x")],
                             ["6 function(s) with kCFI hash 0x36b1c5a6", "in module.o (6):", "... 4 more",
                              "in kernel.elf (6):", "... 4 more"])

    def test_module_with_no_call_site(self):
        # review s201 MINOR: --with was ignored for a module with no kCFI call site (GKI zram.ko), though --implements
        # reads such a module (at -4): the kernel's functions of the hash are listed
        from test_cli import module_and_kernel
        with tempfile.TemporaryDirectory() as tmp:
            _module, kernel = module_and_kernel(tmp)
            rc, out, err = run(QUIRKS, "--implements", "0x1300e12b", "--with", kernel)
            self.assertEqual(rc, 0, err)
            self.assertNotIn("--with ignored", err)
            lines = out.splitlines()
            self.assertEqual(lines[:3], ["0 function(s) with kCFI hash 0x1300e12b", "  in kcfi_quirks_a64.o (0):",
                                         "  in kernel.elf (3):"])
            self.assertEqual([x.split()[1] for x in lines[3:]], ["k_impl_2_0", "k_impl_2_1", "k_impl_2_2"])
            doc = implements(QUIRKS, "0x1300e12b", "--with", kernel)
            self.assertEqual((doc["functions"], doc["kernel_functions"]), (0, 3))
            self.assertNotIn("kernel", json.loads(run(QUIRKS, "--implements", "0x1300e12b", "--with", kernel,
                                                      "--json")[1])["stats"])
            rc, out, err = run(QUIRKS, "--with", kernel)          # without --implements: ignored, as before
            self.assertIn("--with ignored: this input has no kCFI call site", err)

    def test_kernel_function_name(self):
        # review s201 NIT: a name the module lacks is looked up in the --with kernel, as --callers does
        from test_cli import module_and_kernel
        with tempfile.TemporaryDirectory() as tmp:
            module, kernel = module_and_kernel(tmp)
            rc, out, err = run(module, "--implements", "k_impl_2_1", "--with", kernel)
            self.assertEqual(rc, 0, err)
            lines = out.splitlines()
            self.assertEqual(lines[:3], ["0 function(s) with kCFI hash 0x1300e12b, the type of k_impl_2_1 (in "
                                         "kernel.elf)", "  in module.o (0):", "  in kernel.elf (3):"])
            self.assertEqual([x.split()[1] for x in lines[3:]], ["k_impl_2_0", "k_impl_2_1", "k_impl_2_2"])
            doc = implements(module, "impl_1_0", "--with", kernel)            # the module's own name wins
            self.assertEqual((doc["hash"], doc["functions"], doc["kernel_functions"]), ("0x36b1c5a6", 6, 6))
            rc, out, err = run(module, "--implements", "k_impl_2_1")          # without --with: a hint
            self.assertEqual((rc, out), (2, ""))
            self.assertIn("a kernel function? add --with VMLINUX", err)
            rc, out, err = run(module, "--implements", "no_such_function", "--with", kernel)
            self.assertEqual((rc, out), (2, ""))
            self.assertIn("not a function of this module nor of kernel.elf", err)


class NotKcfi(unittest.TestCase):
    def test_jump_table_cfi(self):
        rc, out, err = run(os.path.join(FIX, "aarch64-jtcfi.elf"), "--implements", "0x1ebda935")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("jump-table CFI", err)

    def test_no_check_x86(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            with open(raw, "wb") as fh:
                fh.write(b"\x90" * 4096)
            rc, out, err = run(raw, "--raw", "--arch", "x86_64", "--base", "0x1000", "--implements", "0x1ebda935")
            self.assertEqual((rc, out), (2, ""))
            self.assertIn("no kCFI check", err)

    def test_no_check_aarch64(self):
        # indirect calls (blr x8) that no kCFI check guards: not a kCFI build. No indirect call at all: it cannot be
        # told (a kCFI module may make none), so the word before each function is read, and here none has the hash.
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "Image")
            for code, blr in ((b"\x1f\x20\x03\xd5" * 1023 + b"\x00\x01\x3f\xd6", True),
                              (b"\x1f\x20\x03\xd5" * 1024, False)):
                with self.subTest(blr=blr):
                    with open(raw, "wb") as fh:
                        fh.write(code)
                    rc, out, err = run(raw, "--raw", "--arch", "aarch64", "--base", "0x1000", "--implements",
                                       "0x1ebda935")
                    if blr:
                        self.assertEqual((rc, out), (2, ""))
                        self.assertIn("1 indirect calls (blr) and no kCFI check guards them: it is not built with kCFI",
                                      err)
                    else:
                        self.assertEqual((rc, out), (0, "0 function(s) with kCFI hash 0x1ebda935\n"))
                        self.assertIn("whether it is built with kCFI cannot be told", err)

    def test_no_check_aarch64_module(self):
        # kCFI code that makes no indirect call (as GKI zram.ko): the hashes are still in front of its functions,
        # in the word before each (aarch64 kCFI), and the list says so on stderr
        h = "0x%08x" % K.kcfi_hash("_ZTSFlvE")              # long (void): n_void_params, not the K&R n_noproto
        for spec, more in ((h, ()), ("long (void)", ("--btf", QUIRKS_BTF)), ("n_void_params", ())):
            with self.subTest(spec):
                rc, out, err = run(QUIRKS, "--implements", spec, *more)
                self.assertEqual(rc, 0, err)
                self.assertTrue(out.startswith("1 function(s) with kCFI hash %s" % h), out)
                self.assertTrue(out.splitlines()[1].endswith("  n_void_params"), out)
                self.assertIn("no kCFI check in this input", err)
        doc = implements(QUIRKS, "0x%08x" % K.kcfi_hash("_ZTSFlE"))     # long (): the K&R one
        self.assertEqual(names_of(doc), ["n_noproto"])

    def test_mangled_typo(self):
        # review s201 NIT: a mangled name with a typo gave an empty list silently
        path = os.path.join(FIX, "aarch64-kernel.o")
        for spec, more, why in (("_ZTS", (), "BTF has no type of that hash"),
                                ("_ZTSFlsiX", (), "BTF has no type of that hash"),
                                ("_ZTS", ("--no-btf",), "no BTF was read to check it")):
            with self.subTest(spec=spec, more=more):
                rc, out, err = run(path, "--implements", spec, *more)
                self.assertEqual(rc, 0)
                self.assertTrue(out.startswith("0 function(s) with kCFI hash 0x"), out)
                self.assertIn("no function here carries 0x", err)
                self.assertIn(why + ": is the mangled name right?", err)
        rc, out, err = run(path, "--implements", "_ZTSFlsiE")
        self.assertEqual((rc, err, out.split()[0]), (0, "", "3"))

    def test_function_without_hash(self):
        # x86-64: __cfi_impl_2_1 is the preamble itself; nothing in front of it is a kCFI hash
        rc, out, err = run(os.path.join(FIX, "x86_64-kernel.o"), "--implements", "__cfi_impl_2_1")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("no kCFI hash in front of __cfi_impl_2_1", err)


class FunctionHash(unittest.TestCase):
    """core.function_hash() on hand-made code: the word in front of a function is its kCFI hash only when a check, BTF
    or its place says so (a function with none has the previous function's last word there, or some other code)."""

    RET, NOP, BL = 0xd65f03c0, 0xd503201f, 0x94000010

    def code(self, before):
        return [(0x1000, struct.pack("<4I", 0xd503233f, before, 0xd503233f, self.RET))]   # paciasp; WORD; entry

    def test_aarch64(self):
        ranges = self.code(0x5a5aa5a5)
        self.assertEqual(core.function_hash(ranges, "aarch64", 0x1008, [-4]), (0x5a5aa5a5, "preamble"))
        self.assertIsNone(core.function_hash(ranges, "aarch64", 0x1009, [-4]))        # not aligned
        self.assertIsNone(core.function_hash(ranges, "aarch64", 0x1000, [-4]))        # nothing in front
        self.assertIsNone(core.function_hash(ranges, "aarch64", 0x1008, [-4], form=False))
        # ret, nop, bl, udf, b, brk, br; review s201: isb, mrs, msr (the system class, which GKI 6.1 has in front of
        # do_nanosleep, ret_to_user and el1_trap), eret, eretaa, drps, svc, hvc, smc
        for word in (self.RET, self.NOP, self.BL, 0, 0x14000003, 0xd4200020, 0xd61f0100, 0xd5033fdf, 0xd53cd048,
                     0xd5184609, 0xd69f03e0, 0xd69f0bff, 0xd6bf03e0, 0xd4000001, 0xd4000002, 0xd4000003):
            with self.subTest(hex(word)):
                ranges = self.code(word)
                self.assertIsNone(core.function_hash(ranges, "aarch64", 0x1008, [-4]))
                self.assertEqual(core.function_hash(ranges, "aarch64", 0x1008, [-4], checked={word}), (word, "checked"))
                self.assertEqual(core.function_hash(ranges, "aarch64", 0x1008, [-4], named={word}), (word, "named"))

    def test_patchable_entry(self):
        # aarch64-kernel.o keeps its hashes 36 bytes before the function, 8 NOPs between: only NOPs may stand there
        hashed = struct.pack("<11I", 0x12345678, *[self.NOP] * 8 + [0xd503233f, self.RET])
        ranges = [(0x3000, hashed)]
        self.assertEqual(core.function_hash(ranges, "aarch64", 0x3024, [-36]), (0x12345678, "preamble"))
        code = [(0x3000, hashed[:28] + struct.pack("<I", 0xaa0003e2) + hashed[32:])]    # mov x2, x0 among them
        self.assertIsNone(core.function_hash(code, "aarch64", 0x3024, [-36]))
        self.assertEqual(core.function_hash(code, "aarch64", 0x3024, [-36], named={0x12345678}), (0x12345678, "named"))

    def test_x86_64(self):
        code = b"\xcc" * 4 + b"\x90" * 11 + b"\xb8" + struct.pack("<I", 0x1300e12b) + b"\x55\x48\x89\xe5\xc3"
        ranges = [(0x2000, code)]
        self.assertEqual(core.function_hash(ranges, "x86_64", 0x2000 + 20, [-4]), (0x1300e12b, "preamble"))
        self.assertIsNone(core.function_hash(ranges, "x86_64", 0x2000 + 16, [-4]))   # no mov r32, imm32 in front
        padded = b"\x90" * 11 + b"\xb8" + struct.pack("<I", 0x1300e12b) + b"\x90" * 16 + b"\x55\x48\x89\xe5\xc3"
        self.assertEqual(core.function_hash([(0, padded)], "x86_64", 32, [-20]), (0x1300e12b, "preamble"))
        broken = padded[:20] + b"\xcc" + padded[21:]
        self.assertIsNone(core.function_hash([(0, broken)], "x86_64", 32, [-20]))
        self.assertEqual(core.function_hash([(0, broken)], "x86_64", 32, [-20], checked={0x1300e12b}),
                         (0x1300e12b, "checked"))

    def test_implementations(self):
        mem = struct.pack("<8I", 0x11111111, 0xd503233f, self.RET, 0x22222222, 0xd503233f, 0x11111111, 0xd503233f,
                          self.RET)
        ranges = [(0x4000, mem)]
        self.assertEqual(core.implementations(ranges, "aarch64", 0x11111111, [-4]), [0x4004, 0x4018])
        self.assertEqual(core.implementations(ranges, "aarch64", 0x22222222, [-4]), [0x4010])
        self.assertEqual(core.implementations(ranges, "aarch64", 0x33333333, [-4]), [])
        self.assertEqual(core.implementations(ranges, "aarch64", 0x11111111, [-4], text=[(0x4010, 0x5000)]), [0x4018])


def spread_quirks(tmp):
    """kcfi_quirks_a64.o (no call site, no BTF of its own) with the word in front of n_void_params, its kCFI hash
    0x72923c8f, written over the first instruction of n_noproto_int too: n_noproto_int+0x4 then has that word in front
    of it, as a mid-function address has the word of an instruction or a literal that a hash by form cannot be told
    from (review s201: GKI 6.1 init_kernel_el, 0xffffffc0)."""
    with open(QUIRKS, "rb") as fh:
        d = bytearray(fh.read())
    _arch, ranges, symbols = cli.load_elf(bytes(d))
    by = {n: ea for ea, n in symbols.items()}
    base, mem = next((b, m) for b, m in ranges if b <= by["n_noproto_int"] < b + len(m))
    at = bytes(d).index(bytes(mem)) + by["n_noproto_int"] - base
    struct.pack_into("<I", d, at, 0x72923c8f)
    path = os.path.join(tmp, "spread.o")
    with open(path, "wb") as fh:
        fh.write(bytes(d))
    return path, by


class FormOnly(unittest.TestCase):
    """Review s201 MAJOR: a word that no check or BTF knows is a function's hash only by its form, which instruction
    words and literals can have too: it is refused when it also stands in front of an address that is no function
    symbol, and the message says why there is no hash."""

    def test_spread(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, by = spread_quirks(tmp)
            rc, out, err = run(path, "--implements", "n_void_params")
            self.assertEqual((rc, out), (2, ""))
            self.assertIn("the word in front of n_void_params, 0x72923c8f, is no type hash that a check or BTF knows",
                          err)
            self.assertIn("1 of the 2 places it stands in front of are not the start of a function symbol (such as "
                          "n_noproto_int+0x4)", err)
            self.assertIn("give the hash", err)
            doc = implements(path, "0x72923c8f")                   # a hash is taken as it is
            self.assertEqual(names_of(doc), ["n_void_params", "n_noproto_int+0x4"])
            doc = implements(path, "n_void_params", "--btf", QUIRKS_BTF)      # BTF names it: no doubt
            self.assertEqual(names_of(doc), ["n_void_params", "n_noproto_int+0x4"])
        self.assertEqual(names_of(implements(QUIRKS, "n_void_params")), ["n_void_params"])   # unpatched: by form

    def test_why_no_hash(self):
        # do_call_7's hash 0x959afb16 decodes as bl: without BTF the form rule cannot take it (review s201 MINOR)
        path = os.path.join(FIX, "aarch64-kernel.o")
        rc, out, err = run(path, "--implements", "do_call_7", "--no-btf")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("no kCFI hash that a check or BTF knows in front of do_call_7: the word there, 0x959afb16, "
                      "decodes as an instruction (bl)", err)
        self.assertIn("give --btf", err)
        self.assertNotIn("never taken", err)
        rc, out, err = run(os.path.join(FIX, "aarch64-plain.o"), "--implements", "do_call_13")   # b, no BTF here
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("0x177195e9, decodes as an instruction (b)", err)


class BtfNamed(unittest.TestCase):
    """Review s201: a function's hash that decodes as b or bl is taken because BTF names it (on GKI 6.1, 2,229 of the
    48,021 words in front of a function that BTF names): do_call_7's 0x959afb16 is bl, do_call_13's 0x177195e9 is b."""

    def test_btf_named(self):
        btf = os.path.join(FIX, "aarch64-kernel.o")              # t.c's BTF (aarch64-plain.o has none)
        for path in (btf, os.path.join(FIX, "aarch64-plain.o")):
            for fn, h, impl in (("do_call_7", "0x959afb16", "unsigned int (unsigned int (*)(void *, unsigned int, "
                                                            "short))"),
                                ("do_call_13", "0x177195e9", "char (char (*)(long long, int))")):
                with self.subTest(path=os.path.basename(path), fn=fn):
                    self.assertFalse(any(s["hash"] == h for s in sites_of(path)))      # no check knows it
                    doc = implements(path, fn, "--btf", btf)
                    self.assertEqual((doc["hash"], doc["type"], names_of(doc)), (h, impl, [fn]))


class Normalized(unittest.TestCase):
    """Review s201: integer-normalized types (CONFIG_CFI_ICALL_NORMALIZE_INTEGERS, GKI 6.12): kcfi_types.c built with
    -fsanitize-cfi-icall-experimental-normalize-integers, its BTF apart. A C type, a member and a function give the
    normalized hash the code carries, and the plain build the plain one."""

    BTF = os.path.join(FIX, "kcfi_types_btf.o")

    def test_normalized(self):
        for obj in ("kcfi_types_a64_norm.o", "kcfi_types_x64_norm.o"):
            path = os.path.join(FIX, obj)
            for spec, h, fn in (("long (short, int)", "0xe1d7ea79", "f_ls"), ("ops.open", "0xc259b344", "ops_open"),
                                ("f_ls", "0xe1d7ea79", "f_ls")):
                with self.subTest(obj=obj, spec=spec):
                    doc = implements(path, spec, "--btf", self.BTF)
                    self.assertEqual((doc["hash"], names_of(doc)), (h, [fn]))
                    self.assertTrue(doc["type"].endswith(" [normalized]"), doc["type"])
        plain = os.path.join(FIX, "kcfi_types_a64.o")
        for spec, h in (("long (short, int)", "0x1300e12b"), ("ops.open", "0x4f4ccb9d")):
            with self.subTest(obj="kcfi_types_a64.o", spec=spec):
                self.assertEqual(implements(plain, spec, "--btf", self.BTF)["hash"], h)

    def test_two_hashes_carried(self):
        # SPEC giving two hashes that functions carry is refused (_pick_hash); GKIKnownAnswers has a real one
        found = {0x11111111: [0x1000], 0x22222222: [0x2000]}.get
        with self.assertRaises(cli.InputError) as e:
            cli._pick_hash("x.cb", [(0x11111111, "_ZTSFvvE"), (0x22222222, "_ZTSFivE")], found)
        self.assertIn("names 2 types that functions here carry (0x11111111, 0x22222222): give one hash", str(e.exception))
        self.assertEqual(cli._pick_hash("x.cb", [(0x33333333, "a"), (0x22222222, "b")], found), (0x22222222, "b"))
        self.assertEqual(cli._pick_hash("x.cb", [(0x33333333, "a"), (0x44444444, "b")], found), (0x33333333, "a"))


@unittest.skipUnless(os.path.isfile(GKI), "set CFISCOPE_GKI_ELF to the gki.elf of the README walkthrough")
class GKIKnownAnswers(unittest.TestCase):
    """The judge's numbers on GKI 6.1 (s193): 136 functions of long (struct file *, unsigned int, unsigned long), 134 of
    them ioctl handlers (118 named *_ioctl, 16 such as snd_pcm_ioctl_compat), plus memfd_fcntl and pipe_fcntl;
    proto_ops.sendmsg: the 14 candidates of sock_sendmsg+0xb4."""

    SENDMSG = ["tun_sendmsg", "sock_no_sendmsg", "netlink_sendmsg", "inet_sendmsg", "unix_stream_sendmsg",
               "unix_dgram_sendmsg", "unix_seqpacket_sendmsg", "inet6_sendmsg", "packet_sendmsg", "packet_sendmsg_spkt",
               "pfkey_sendmsg", "vsock_dgram_sendmsg", "vsock_connectible_sendmsg", "xsk_sendmsg"]

    def test_ioctl(self):
        doc = implements(GKI, "long (struct file *, unsigned int, unsigned long)")
        self.assertEqual(doc["functions"], 136)
        self.assertEqual(sorted(n for n in names_of(doc) if "ioctl" not in n), ["memfd_fcntl", "pipe_fcntl"])
        for spec in ("file_operations.unlocked_ioctl", "file_operations.compat_ioctl", doc["hash"]):
            with self.subTest(spec):
                again = implements(GKI, spec)
                self.assertEqual((again["hash"], names_of(again)), (doc["hash"], names_of(doc)))

    def test_sendmsg(self):
        doc = implements(GKI, "proto_ops.sendmsg")
        self.assertEqual((doc["hash"], doc["type"]), ("0x1ebda935", "int (struct socket *, struct msghdr *, unsigned long)"))
        self.assertEqual(sorted(names_of(doc)), sorted(self.SENDMSG))
        rc, out, _ = run(GKI, "--targets", "0xffffffc008cc55ac", "--json")
        self.assertEqual(sorted(names_of(doc)), sorted(t["name"] for t in json.loads(out)["sites"][0]["targets"]))
        doc = implements(GKI, "tcp_sendmsg")
        self.assertEqual((doc["hash"], doc["functions"]), ("0x87bcba6f", 11))

    def test_not_hashes(self):
        # review s201 MAJOR: the word in front of these is an instruction (mrs, isb, eret) or a literal (0xffffffc0,
        # the high half of a pointer), which listed 25 to 24,877 "functions", most of them mid-function addresses
        for fn, why in (("do_nanosleep", "0xd53cd048, decodes as an instruction"),
                        ("ret_to_user", "0xd5033fdf, decodes as an instruction"),
                        ("el1_trap", "0xd5033fdf, decodes as an instruction"),
                        ("cpu_resume", "0xd69f03e0, decodes as an instruction"),
                        ("init_kernel_el", "are not the start of a function symbol")):
            with self.subTest(fn):
                rc, out, err = run(GKI, "--implements", fn)
                self.assertEqual((rc, out), (2, ""))
                self.assertIn(why, err)

    def test_two_types(self):
        # two struct instance_attribute in BTF (edac and another), with show members of two types functions carry
        rc, out, err = run(GKI, "--implements", "instance_attribute.show")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("names 2 types that functions here carry (0x6ba31d66, 0x707735d4): give one hash", err)


@unittest.skipUnless(os.path.isfile(os.path.join(KO, "bluetooth.ko")) and os.path.isfile(os.path.join(KO, "kernel-6.1")),
                     "set CFISCOPE_KO_DIR to a folder with the GKI bluetooth.ko and kernel-6.1 of docs/VERIFICATION.md")
class KOKnownAnswers(unittest.TestCase):
    """bluetooth.ko (split BTF, with --btf kernel-6.1): the proto_ops handlers, which no call site of the module checks."""

    def test_proto_ops(self):
        ko, btf = os.path.join(KO, "bluetooth.ko"), os.path.join(KO, "kernel-6.1")
        checked = {s["hash"] for s in sites_of(ko, "--btf", btf)}
        doc = implements(ko, "proto_ops.ioctl", "--btf", btf)
        self.assertEqual(sorted(names_of(doc)), ["bt_sock_ioctl", "hci_sock_compat_ioctl", "hci_sock_ioctl"])
        self.assertNotIn(doc["hash"], checked)
        doc = implements(ko, "proto_ops.sendmsg", "--btf", btf)
        self.assertEqual(sorted(names_of(doc)), ["hci_sock_sendmsg", "iso_sock_sendmsg", "l2cap_sock_sendmsg",
                                                 "sco_sock_sendmsg"])
        self.assertNotIn(doc["hash"], checked)
        rc, _, err = run(ko, "--implements", "proto_ops.ioctl")
        self.assertEqual(rc, 2)
        self.assertIn("needs BTF", err)


if __name__ == "__main__":
    unittest.main()
