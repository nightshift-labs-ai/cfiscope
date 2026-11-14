"""The struct member each aarch64 kCFI call loads its pointer from (internal review s193 #1): `sock->ops->sendmsg(...)` is
`ldr x8, [x8, #136]` ... `blr x8` on GKI 6.1, and BTF has exactly one member of the call's type at byte 136: proto_ops.sendmsg.

Golden strings marked "458eeeb" were printed by the code before this change (git archive 458eeeb) for the same input:
a call whose pointer load is not decoded, or matches no member, must print exactly what it printed before."""
import contextlib, hashlib, io, json, os, struct, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli, core, kcfi_types as K  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
MEMBERS = os.path.join(FIX, "kcfi_members_a64.o")      # tests/fixtures/kcfi_members.c: aarch64 kCFI code + its BTF


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(argv)
    return rc, out.getvalue()


def object_constants(path, prefix):
    """{name: value} of the 8-byte constants named prefix* in an ELF object (the off_* offsetof values of
    kcfi_members.c, as the compiler computed them)."""
    with open(path, "rb") as fh:
        d = fh.read()
    secs = cli._sections(d)
    out = {}
    for s in secs:
        if s[1] != 2:                                             # SHT_SYMTAB
            continue
        strtab = secs[s[6]]
        for off in range(s[4], s[4] + s[5], 24):
            nm, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", d, off)
            start = strtab[4] + nm
            name = d[start:d.index(b"\0", start)].decode()
            if name.startswith(prefix) and size == 8 and 0 < shndx < len(secs):
                out[name] = struct.unpack_from("<Q", d, secs[shndx][4] + value)[0]
    return out


# ---- the walk back from a check to the load of its pointer, on hand-made words ----

def ldr(t, n, imm):            # ldr xT, [xN, #imm] (unsigned offset, imm a multiple of 8)
    return 0xf9400000 | (imm // 8) << 10 | n << 5 | t


def ldur(t, n, imm):           # ldur xT, [xN, #imm9]
    return 0xf8400000 | (imm & 0x1ff) << 12 | n << 5 | t


def check(t, n):               # ldur wT, [xN, #-4]: the first word of an aarch64 kCFI check
    return 0xb8400000 | (-4 & 0x1ff) << 12 | n << 5 | t


def mov(d, s):
    return 0xaa0003e0 | s << 16 | d


NOP, BASE = 0xd503201f, 0x400000


def offset_of(words, reg=8):
    """member_offsets() for a check of xreg placed after words (the check, then movk/cmp/b.eq/brk/blr stand-ins)."""
    code = list(words) + [check(16, reg), NOP, NOP, NOP, NOP, NOP, 0xd63f0000 | reg << 5]
    site = core.Site(BASE + 4 * len(words), BASE + 4 * (len(code) - 1), 0x1234, -4)
    return core.member_offsets([(BASE, struct.pack("<%dI" % len(code), *code))], [site]).get(site.check_ea)


class MemberWalk(unittest.TestCase):
    def test_ldr_and_ldur(self):
        self.assertEqual(offset_of([NOP, ldr(8, 0, 136), NOP]), 136)
        self.assertEqual(offset_of([ldur(8, 0, 24)]), 24)
        self.assertEqual(offset_of([ldr(8, 8, 0)]), 0)                       # ldr x8, [x8]: base defined earlier

    def test_mov_copy_and_null_check(self):
        self.assertEqual(offset_of([ldr(9, 0, 136), mov(8, 9)]), 136)
        cbz = 0xb4000000 | 8 << 5 | 8                                         # cbz x8, +32 (past the check): no write
        self.assertEqual(offset_of([ldr(8, 0, 216), cbz, NOP]), 216)

    def test_not_a_member_load(self):
        self.assertIsNone(offset_of([0xa9400000 | 2 << 15 | 9 << 10 | 0 << 5 | 8]))   # ldp x8, x9, [x0, #16]
        self.assertIsNone(offset_of([0xa9400000 | 2 << 15 | 8 << 10 | 0 << 5 | 9]))   # ldp x9, x8: x8 is Rt2
        self.assertIsNone(offset_of([0xf8617808]))                           # ldr x8, [x0, x1, lsl #3]
        self.assertIsNone(offset_of([0xf8408408]))                           # ldr x8, [x0], #8 (post-index)
        self.assertIsNone(offset_of([ldr(8, 31, 16)]))                       # a stack slot: [sp, #16]
        self.assertIsNone(offset_of([ldur(8, 29, -8)]))                      # [x29, #-8]
        self.assertIsNone(offset_of([0x90000009, ldr(8, 9, 0x2a8)]))         # adrp x9, g; ldr x8, [x9, :lo12:g]
        self.assertIsNone(offset_of([ldr(31, 0, 8), mov(8, 31)]))            # mov x8, xzr (ldr xzr: no source)
        self.assertIsNone(offset_of([NOP] * 20))                             # nothing within the walk

    def test_calls_clobber_caller_saved_only(self):
        bl = 0x94000000 | 0x100
        self.assertIsNone(offset_of([ldr(8, 0, 136), bl]))                   # x8 is clobbered by the call
        self.assertEqual(offset_of([ldr(19, 0, 136), bl], reg=19), 136)      # x19 survives it

    def test_a_branch_landing_between_load_and_check(self):
        # b.ne from word 0 to word 3, between the load (word 2) and the check (word 4): another path reaches the
        # check without that load, so the offset is not known
        bne = 0x54000001 | 3 << 5
        self.assertIsNone(offset_of([bne, NOP, ldr(8, 0, 136), NOP]))
        bne_to_load = 0x54000001 | 2 << 5                                     # landing on the load itself is fine
        self.assertEqual(offset_of([bne_to_load, NOP, ldr(8, 0, 136), NOP]), 136)

    def test_walk_stops_at_a_function_start(self):
        self.assertIsNone(offset_of([ldr(8, 0, 136), 0xd65f03c0, NOP]))      # ret in between
        self.assertIsNone(offset_of([ldr(8, 0, 136), 0xd503245f, NOP]))      # bti c: a function starts here

    def test_label(self):
        s = core.Site(0, 0, 0, -4)
        self.assertIsNone(core.member_label(s))
        s.members = ["proto_ops.sendmsg"]
        self.assertEqual(core.member_label(s), "proto_ops.sendmsg")
        s.members = ["a.f", "b.g", "c.h", "d.i", "e.j"]
        self.assertEqual(core.member_label(s), "one of 5 members (a.f, b.g, c.h, +2 more)")
        self.assertEqual(core.member_label(s, None), "one of 5 members (a.f, b.g, c.h, d.i, e.j)")


# ---- the member map from BTF ----

class FakeBTF:
    """types and names as kcfi_types.BTF keeps them, for crafted shapes."""
    def __init__(self, types, names):
        self.types, self.names = types, names

    def name(self, off):
        return self.names[off]

    def linkage_names(self):
        return {}


class MemberSlots(unittest.TestCase):
    def setUp(self):
        with open(MEMBERS, "rb") as fh:
            self.data = fh.read()
        self.names = K.load_type_names(self.data)
        self.off = object_constants(MEMBERS, "off_")

    def test_offsets_from_offsetof(self):
        h_send = K.kcfi_hash("_ZTSFiP3msgiE")                 # int (struct msg *, int)
        h_poll = K.kcfi_hash("_ZTSFlP3msglE")                 # long (struct msg *, long)
        m = self.names.members
        self.assertEqual(m[(h_send, self.off["off_a_ops_send"])], ["a_ops.send"])
        self.assertEqual(m[(h_send, self.off["off_b_ops_send"])], ["b_ops.send"])
        self.assertEqual(m[(h_send, self.off["off_b_ops_recv"])], ["b_ops.recv"])
        self.assertEqual(self.off["off_c_ops_poll"], self.off["off_d_ops_poll"])
        self.assertEqual(m[(h_poll, self.off["off_c_ops_poll"])], ["c_ops.poll", "d_ops.poll"])
        # embedded by value: named after the struct that declares the member, at its offset in the outer struct
        h_notify = K.kcfi_hash("_ZTSFvP3msgjE")
        self.assertEqual(m[(h_notify, self.off["off_outer_notify"])], ["inner_ops.notify"])
        self.assertEqual(m[(h_notify, 0)], ["inner_ops.notify"])
        h_cb = K.kcfi_hash("_ZTSFvP3msgsE")                   # in an anonymous union
        self.assertEqual(m[(h_cb, self.off["off_anon_holder_u_cb"])], ["anon_holder.u_cb"])
        self.assertEqual(len(self.off), 7)

    def test_crafted_btf_names_nothing(self):
        # struct A { struct A a; } cannot be C; BTF that says so gives no member names (and no endless recursion)
        fp = [(0, "", 0, 0, None), (K.K_FUNC_PROTO, "", 0, 0, []), (K.K_PTR, "", 0, 1, None)]
        loop = fp + [(K.K_STRUCT, "A", 0, 16, [(1, 3, 0), (2, 2, 64)])]
        self.assertEqual(K.member_slots(FakeBTF(loop, {1: "a", 2: "f"}), {1: {7}}), {})
        ok = fp + [(K.K_STRUCT, "A", 0, 16, [(2, 2, 64)])]
        self.assertEqual(K.member_slots(FakeBTF(ok, {2: "f"}), {1: {7}}), {(7, 8): ["A.f"]})
        # fan-out past MAX_MEMBER_ENTRIES: none rather than some
        wide = fp + [(K.K_STRUCT, "B", 0, 8 * 64, [(2, 2, 64 * j) for j in range(64)])]
        saved = K.MAX_MEMBER_ENTRIES
        K.MAX_MEMBER_ENTRIES = 10
        try:
            self.assertEqual(K.member_slots(FakeBTF(wide, {2: "f"}), {1: {7}}), {})
        finally:
            K.MAX_MEMBER_ENTRIES = saved

    def test_pointer_to_function_pointer_is_not_a_member(self):
        # const iw_handler *standard (iw_handler_def): loading it gives a table, not the function called
        t = [(0, "", 0, 0, None), (K.K_FUNC_PROTO, "", 0, 0, []), (K.K_PTR, "", 0, 1, None), (K.K_PTR, "", 0, 2, None),
             (K.K_STRUCT, "S", 0, 16, [(1, 3, 0), (2, 2, 64)])]
        self.assertEqual(K.member_slots(FakeBTF(t, {1: "table", 2: "fn"}), {1: {7}}), {(7, 8): ["S.fn"]})

    FP = [(0, "", 0, 0, None), (K.K_FUNC_PROTO, "", 0, 0, []), (K.K_PTR, "", 0, 1, None),
          (K.K_INT, "long", 0, 8, None)]                 # 1: a prototype, 2: a pointer to it, 3: long

    def test_array_of_function_pointers(self):
        # struct S { long t; void (*fns[3])(void); }: element j at 8 + 8 * j
        t = self.FP + [(K.K_ARRAY, "", 0, 0, (2, 3, 3)), (K.K_STRUCT, "S", 0, 32, [(1, 3, 0), (2, 4, 64)])]
        self.assertEqual(K.member_slots(FakeBTF(t, {1: "t", 2: "fns"}), {1: {7}}),
                         {(7, 8): ["S.fns"], (7, 16): ["S.fns"], (7, 24): ["S.fns"]})

    def test_array_of_structs_uses_the_element_size(self):
        # struct E { long pad; fn_t fn; long more; } (24 bytes); struct T { struct E es[3]; }: E.fn at 8, 32, 56
        t = self.FP + [(K.K_STRUCT, "E", 0, 24, [(1, 3, 0), (2, 2, 64), (3, 3, 128)]),
                       (K.K_ARRAY, "", 0, 0, (4, 3, 3)), (K.K_STRUCT, "T", 0, 72, [(4, 5, 0)])]
        self.assertEqual(K.member_slots(FakeBTF(t, {1: "pad", 2: "fn", 3: "more", 4: "es"}), {1: {7}}),
                         {(7, 8): ["E.fn"], (7, 32): ["E.fn"], (7, 56): ["E.fn"]})

    def test_named_member_of_anonymous_type(self):
        # struct S { long t; struct { fn_t fn; } ops; }: 'S.ops.fn' at 8 (an unnamed one would give 'S.fn')
        t = self.FP + [(K.K_STRUCT, "", 0, 8, [(1, 2, 0)]), (K.K_STRUCT, "S", 0, 16, [(2, 3, 0), (3, 4, 64)])]
        self.assertEqual(K.member_slots(FakeBTF(t, {1: "fn", 2: "t", 3: "ops"}), {1: {7}}), {(7, 8): ["S.ops.fn"]})
        t[5] = (K.K_STRUCT, "S", 0, 16, [(2, 3, 0), (0, 4, 64)])
        self.assertEqual(K.member_slots(FakeBTF(t, {0: "", 1: "fn", 2: "t"}), {1: {7}}), {(7, 8): ["S.fn"]})


# ---- the command line on the fixture ----

OLD_PARAM = ("0x10024c  call_param+0x2c                          call hash 0xfd39cd44 (int (struct msg *, int))  2 "
             "candidate(s): send_x, send_y")                                                      # 458eeeb
OLD_GLOBAL = ("0x10028c  call_global+0x2c                         call hash 0xfd39cd44 (int (struct msg *, int))  2 "
              "candidate(s): send_x, send_y")                                                     # 458eeeb
OLD_SITES_SHA256 = {    # `--sites` output of 458eeeb: these calls load no struct member, so nothing may change
    "aarch64-kernel.o": "4024b51f2bd0967a8d85af8c5bc89e994f4286eb5be5260edf768a3b6e349fea",
    "x86_64-kernel.o": "5922d6d8889b7746ae3152d3f908ea8c4f90663599bacda0e502f017319a8fed",   # x86-64: not read
    "kcfi_types_a64.o": "0ced6afb8228f09ae3dd2827965d40babc59d6abf9d065f686186a36ab649530",
    "aarch64-plain.o": "37c124afd08fe157101ef14f89bfdf21ff215a7bfebb097bd96d4872d784a19b",
}
WANT = {"call_a_send": ("a_ops.send", "off_a_ops_send"), "call_b_send": ("b_ops.send", "off_b_ops_send"),
        "call_b_recv": ("b_ops.recv", "off_b_ops_recv"), "call_outer": ("inner_ops.notify", "off_outer_notify"),
        "call_anon": ("anon_holder.u_cb", "off_anon_holder_u_cb")}


class MemberCLI(unittest.TestCase):
    def setUp(self):
        self.off = object_constants(MEMBERS, "off_")

    def test_sites_lines(self):
        rc, out = run([MEMBERS, "--sites"])
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 8)
        # test_slots.py: send_x is stored at byte 16 of a_tbl (a_ops.send), send_y in no a_ops.send slot
        self.assertIn("0x1000a4  call_a_send+0x2c                         call a_ops.send hash 0xfd39cd44 (int (struct "
                      "msg *, int))  2 candidate(s): in a a_ops.send slot: send_x; same type only: 1 more", lines)
        self.assertIn("0x100164  call_c_poll+0x2c                         call one of 2 members (c_ops.poll, "
                      "d_ops.poll) hash 0xd23933cf (long (struct msg *, long))  2 candidate(s): in a slot of one of 2 "
                      "members: poll_x, poll_y", lines)
        self.assertIn("call b_ops.send hash 0xfd39cd44 (int (struct msg *, int))  2 candidate(s): in a b_ops.send slot: "
                      "send_y; same type only: 1 more", out)
        self.assertIn("call inner_ops.notify hash", out)
        self.assertIn("call anon_holder.u_cb hash", out)
        # no member load: byte for byte what the code printed before
        self.assertIn(OLD_PARAM, lines)
        self.assertIn(OLD_GLOBAL, lines)

    def test_json(self):
        rc, out = run([MEMBERS, "--sites", "--json"])
        self.assertEqual(rc, 0)
        doc = json.loads(out)
        by_fn = {s["in"].split("+")[0]: s for s in doc["sites"]}
        for fn, (member, off) in WANT.items():
            with self.subTest(fn):
                self.assertEqual((by_fn[fn]["member"], by_fn[fn]["members"], by_fn[fn]["member_offset"]),
                                 (member, [member], self.off[off]))
        poll = by_fn["call_c_poll"]
        self.assertEqual((poll["member"], poll["members"], poll["member_offset"]),
                         (None, ["c_ops.poll", "d_ops.poll"], self.off["off_c_ops_poll"]))
        for fn in ("call_param", "call_global"):
            self.assertEqual((by_fn[fn]["member"], by_fn[fn]["members"], by_fn[fn]["member_offset"]), (None, [], None))
        st = doc["stats"]
        self.assertEqual((st["member_offsets"], st["members_named"], st["members_unique"]), (6, 6, 5))

    def test_summary_and_targets(self):
        rc, out = run([MEMBERS])
        self.assertIn("kCFI calls through a struct member: load offset decoded at 6, a BTF member of the call's type at "
                      "that offset for 6 (exactly one for 5)\n", out)
        rc, out = run([MEMBERS, "--targets", "0x100164"])
        self.assertIn("call one of 2 members (c_ops.poll, d_ops.poll) hash 0xd23933cf", out)
        rc, out = run([MEMBERS, "--targets", "0x10024c"])
        self.assertEqual(out, "candidates for the site at 0x10024c\n0x10024c  call_param+0x2c                          "
                              "call hash 0xfd39cd44 (int (struct msg *, int))  2 candidate(s)\n"
                              "    0x100010  send_x\n    0x100020  send_y\n")                       # 458eeeb

    def test_without_btf_nothing_changes(self):
        rc, out = run([MEMBERS, "--sites", "--no-btf"])
        self.assertNotIn("a_ops", out)
        rc, js = run([MEMBERS, "--sites", "--json", "--no-btf"])
        self.assertNotIn("member", js)

    def test_fixtures_without_member_loads_unchanged(self):
        for name, digest in OLD_SITES_SHA256.items():
            with self.subTest(name):
                rc, out = run([os.path.join(FIX, name), "--sites"])
                self.assertEqual((rc, hashlib.sha256(out.encode()).hexdigest()), (0, digest))


# ---- the IDA layer, through the fake ida_* modules of tools/showcase_ida_stub.py ----

class MemberIDA(unittest.TestCase):
    def setUp(self):
        from test_showcase import showcase_module
        self.il, self.w = showcase_module().load(MEMBERS)[:2]
        self.sites, self.stats = self.il.scan()
        self.by_call = {s.call_ea: s for s in self.sites}

    def test_comments(self):
        il = self.il
        res = il.annotate(self.sites)
        self.assertEqual(res["comments"], 8)
        cm = self.w.cmts
        # candidates stored in a slot of the member come first (test_slots.py)
        self.assertEqual(cm[0x1000a4], "kCFI a_ops.send 0xFD39CD44 int (struct msg *, int): 2 candidate(s): in a a_ops.send "
                                       "slot: send_x; same type only: 1 more")
        self.assertEqual(cm[0x1000e4], "kCFI b_ops.send 0xFD39CD44 int (struct msg *, int): 2 candidate(s): in a b_ops.send "
                                       "slot: send_y; same type only: 1 more")
        self.assertEqual(cm[0x100164], "kCFI one of 2 members (c_ops.poll, d_ops.poll) 0xD23933CF long (struct msg *, "
                                       "long): 2 candidate(s): in a slot of one of 2 members: poll_x, poll_y")
        self.assertEqual(cm[0x1001ac], "kCFI inner_ops.notify 0xB519E0BC void (struct msg *, unsigned int): 1 candidate(s): "
                                       "in a inner_ops.notify slot: notify_x")
        # no member load: the comments 458eeeb wrote
        self.assertEqual(cm[0x10024c], "kCFI 0xFD39CD44 int (struct msg *, int): 2 candidate(s): send_x, send_y")
        self.assertEqual(cm[0x10028c], "kCFI 0xFD39CD44 int (struct msg *, int): 2 candidate(s): send_x, send_y")
        self.assertEqual((self.stats["member_offsets"], self.stats["members_named"], self.stats["members_unique"]),
                         (6, 6, 5))

    def test_pseudocode_titles_and_lists(self):
        il, a, p = self.il, self.by_call[0x1000a4], self.by_call[0x10024c]
        self.assertEqual(il.pseudocode_text(a), "CFIScope: a_ops.send, 2 candidates of int (struct msg *, int): in a "
                                                "a_ops.send slot: send_x; same type only: 1 more")
        self.assertEqual(il.pseudocode_text(p), "CFIScope: 2 candidates of int (struct msg *, int): send_x, send_y")
        self.assertEqual(il.targets_title(a), "kCFI candidates for the call at 0x1000A4 (a_ops.send, hash 0xFD39CD44, "
                                              "int (struct msg *, int))")
        self.assertEqual(il.targets_title(p), "kCFI candidates for the call at 0x10024C (hash 0xFD39CD44, int (struct "
                                              "msg *, int))")                                    # 458eeeb
        chooser = il.sites_chooser(self.sites)
        rows = [chooser.OnGetLine(n) for n in range(chooser.OnGetSize())]
        self.assertEqual([c[0] for c in il.SITES_COLUMNS][2], "Member")
        self.assertIn(["0x1000a4", "call_a_send+0x2c", "a_ops.send", "int (struct msg *, int)", "2",
                       "in a a_ops.send slot: send_x; same type only: 1 more"], rows)
        self.assertIn(["0x10024c", "call_param+0x2c", "", "int (struct msg *, int)", "2", "send_x, send_y"], rows)
        self.assertIn("one of 2 members (c_ops.poll, d_ops.poll)", [r[2] for r in rows])
        callers = il.callers_rows(self.sites, 0x100010)                   # send_x
        self.assertIn((0x1000a4, "call_a_send+0x2c", "a_ops.send, 2 candidate(s)"), callers)
        self.assertIn((0x10024c, "call_param+0x2c", "2 candidate(s)"), callers)                # 458eeeb


# ---- known answers on the public GKI 6.1 kernel (CFISCOPE_GKI_ELF: its gki.elf, vmlinux-to-elf output) ----

GKI = os.environ.get("CFISCOPE_GKI_ELF", "")
OLD_GKI_TARGETS = {   # 458eeeb `--targets` site lines of calls whose pointer load is not decoded / matches no member
    0xffffffc008045884: "0xffffffc008045884  trans_pgd_create_copy+0x50               call hash 0x3871c787 (void *(void "
                        "*))  4 candidate(s)",
    0xffffffc008014440: "0xffffffc008014440  __traceiter_initcall_start+0x44          call hash 0x09463f0a (void (void *, "
                        "int (*)(void)))  4 candidate(s)",
}


@unittest.skipUnless(os.path.isfile(GKI), "set CFISCOPE_GKI_ELF to the GKI 6.1 gki.elf of the README walkthrough")
class GKIKnownAnswers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(GKI, "rb") as fh:
            d = fh.read()
        bounds = {}
        arch, ranges, syms = cli.load_elf(d, bounds=bounds)
        cls.sites, _ = core.resolve(ranges, arch, core.kernel_text(bounds))
        names = K.load_type_names(d)
        K.name_sites(cls.sites, names)
        cls.counts = K.name_members(cls.sites, ranges, arch, names)
        cls.names = cli.Names(syms)
        del d

    def site(self, text):
        fn, off = text.split("+")
        ea = self.names.by_name[fn][0] + int(off, 16)
        return next(s for s in self.sites if s.call_ea == ea)

    def test_known_answers(self):
        # an earlier prototype from internal review s193 and the kernel source: sock->ops->sendmsg, sk->sk_prot->sendmsg, ...
        for call, member, off in (("sock_sendmsg+0xb4", "proto_ops.sendmsg", 136),
                                  ("kernel_sendmsg_locked+0x64", "proto_ops.sendmsg_locked", 216),
                                  ("inet_sendmsg+0x58", "proto.sendmsg", 104),
                                  ("inet6_sendmsg+0x58", "proto.sendmsg", 104)):
            with self.subTest(call):
                s = self.site(call)
                self.assertEqual((s.members, s.member_offset), ([member], off))

    def test_no_member_lines_unchanged(self):
        for ea, line in OLD_GKI_TARGETS.items():
            s = next(x for x in self.sites if x.call_ea == ea)
            self.assertEqual(s.members, [])
            self.assertEqual(cli._site_line(s, self.names, 0, member_limit=None).rstrip(" ."), line)

    def test_cli_targets(self):
        rc, out = run([GKI, "--targets", "0xffffffc008cc55ac"])
        self.assertEqual(rc, 0)
        self.assertIn("sock_sendmsg+0xb4                        call proto_ops.sendmsg hash 0x1ebda935 (int (struct "
                      "socket *, struct msghdr *, unsigned long))  14 candidate(s), 13 in a proto_ops.sendmsg slot\n", out)
        rc, out = run([GKI, "--targets", "0xffffffc008045884"])
        self.assertEqual(out.splitlines()[1], OLD_GKI_TARGETS[0xffffffc008045884])


if __name__ == "__main__":
    unittest.main()
