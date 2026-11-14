"""Candidates stored in a matching static slot are listed first (internal review s193 #2). A call that loads its pointer
from a struct member (test_members.py) may reach any function of its type, but a function whose address sits, in the
image's static data, at that member's offset inside an object (or at that offset modulo the struct's size: an array of
such structs) is more likely: `kernel_sendmsg_locked+0x64` loads proto_ops.sendmsg_locked, and of its 11 candidates only
tcp_sendmsg_locked is stored at byte 216 of an object (inet_stream_ops, inet6_stream_ops) in GKI 6.1.

This ranks; it never filters: every candidate stays in every list, the slot-backed ones first."""
import contextlib, io, json, os, sys, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli, core, kcfi_types as K  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
SLOTS = os.path.join(FIX, "kcfi_slots_a64.o")       # tests/fixtures/kcfi_slots.c: aarch64 kCFI code + its BTF
NET = ["net_xmit_a", "net_xmit_b", "net_xmit_c"]
FILE = ["file_write", "file_read"]
ALL = ["file_write", "file_read", "runtime_only", "net_xmit_a", "net_xmit_b", "net_xmit_c"]   # address order
SLOT_OF = {"call_net": NET, "call_file_write": ["file_write"], "call_file_read": ["file_read"]}
MEMBER_OF = {"call_net": "net_ops.xmit", "call_file_write": "file_ops.write", "call_file_read": "file_ops.read"}


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(argv)
    return rc, out.getvalue()


def sites_json(path, *extra):
    rc, out = run([path, "--sites", "--json"] + list(extra))
    assert rc == 0, rc
    return json.loads(out)


class FixtureCLI(unittest.TestCase):
    def test_right_struct_first(self):
        # net_ops.xmit, file_ops.write and file_ops.read share a type: all 6 functions are candidates of each call, but
        # only those stored in a slot of the member the call loads come first (net_xmit_c only modulo sizeof(net_ops))
        doc = sites_json(SLOTS)
        by_fn = {s["in"].split("+")[0]: s for s in doc["sites"]}
        self.assertEqual(sorted(by_fn), sorted(SLOT_OF))
        for fn, slot in SLOT_OF.items():
            with self.subTest(fn):
                s = by_fn[fn]
                self.assertEqual(s["member"], MEMBER_OF[fn])
                rest = [n for n in ALL if n not in slot]
                self.assertEqual([t["name"] for t in s["targets"]], slot + rest)
                self.assertEqual([t["slot_backed"] for t in s["targets"]], [True] * len(slot) + [False] * len(rest))
                self.assertEqual((s["candidates"], s["slot_backed_candidates"]), (6, len(slot)))
        st = doc["stats"]
        self.assertEqual((st["slot_calls"], st["slot_calls_shorter"]), (3, 3))
        self.assertEqual((st["stored_candidates"], st["distinct_candidates"]), (5, 6))     # runtime_only: stored by code

    def test_nothing_dropped(self):
        # the same candidates, and as many, as without the ranking (--no-btf: no member, so no slot), for every site
        ranked, plain = sites_json(SLOTS)["sites"], sites_json(SLOTS, "--no-btf")["sites"]
        self.assertEqual(len(ranked), len(plain))
        for a, b in zip(ranked, plain):
            self.assertEqual((a["call"], a["candidates"]), (b["call"], b["candidates"]))
            self.assertEqual(sorted(t["ea"] for t in a["targets"]), sorted(t["ea"] for t in b["targets"]))
            self.assertEqual(len(a["targets"]), a["candidates"])
        self.assertEqual([t["name"] for t in plain[0]["targets"]], ALL)       # address order without BTF, as before
        self.assertNotIn("slot_backed", json.dumps(plain))

    def test_sites_lines(self):
        rc, out = run([SLOTS, "--sites"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines(), [
            "0x1000ac  call_net+0x2c                            call net_ops.xmit hash 0xfd39cd44 (int (struct msg *, "
            "int))  6 candidate(s): in a net_ops.xmit slot: net_xmit_a, net_xmit_b, net_xmit_c; same type only: 3 more",
            "0x1000ec  call_file_write+0x2c                     call file_ops.write hash 0xfd39cd44 (int (struct msg *, "
            "int))  6 candidate(s): in a file_ops.write slot: file_write; same type only: 5 more",
            "0x10012c  call_file_read+0x2c                      call file_ops.read hash 0xfd39cd44 (int (struct msg *, "
            "int))  6 candidate(s): in a file_ops.read slot: file_read; same type only: 5 more"])
        rc, out = run([SLOTS, "--sites", "--max-list", "2"])
        self.assertIn("6 candidate(s): in a net_ops.xmit slot: net_xmit_a, net_xmit_b, +1 more; same type only: 3 more\n",
                      out)

    def test_targets_lists_every_candidate(self):
        rc, out = run([SLOTS, "--targets", "0x1000ac"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "candidates for the site at 0x1000ac\n"
                              "0x1000ac  call_net+0x2c                            call net_ops.xmit hash 0xfd39cd44 (int "
                              "(struct msg *, int))  6 candidate(s), 3 in a net_ops.xmit slot\n"
                              "  in a net_ops.xmit slot:\n"
                              "    0x100034  net_xmit_a\n    0x100044  net_xmit_b\n    0x100054  net_xmit_c\n"
                              "  same type only:\n"
                              "    0x100004  file_write\n    0x100014  file_read\n    0x100024  runtime_only\n")

    def test_summary(self):
        rc, out = run([SLOTS])
        self.assertIn("kCFI calls with a candidate stored in a slot of their struct member: 3, those candidates listed "
                      "first (3 of the 3 lists also hold candidates of the same type only); kCFI candidates stored in a "
                      "static object: 5 of 6\n", out)
        rc, out = run([SLOTS, "--no-btf"])
        self.assertNotIn("slot", out)

    def test_no_member_no_slot(self):
        # x86-64 is not read for members, so nothing is ranked there: --sites unchanged (test_members pins the bytes)
        doc = sites_json(os.path.join(FIX, "x86_64-kernel.o"))
        self.assertFalse(any(t["slot_backed"] for s in doc["sites"] for t in s["targets"]))
        self.assertEqual(doc["stats"].get("slot_calls", 0), 0)


class Matching(unittest.TestCase):
    """kcfi_types.rank_slots() on hand-made offsets: equal to the member offset, or equal modulo a struct size."""

    def site(self, targets, off=16, members=("net_ops.xmit",)):
        s = core.Site(0x1000, 0x1010, 0x1234, -4, targets=list(targets))
        s.member_offset, s.members = off, list(members)
        return s

    class Names:
        member_sizes = {(0x1234, 16): [24]}

    def test_equal_and_modulo(self):
        s = self.site([0x10, 0x20, 0x30, 0x40])
        offsets = {0x10: {16}, 0x20: {40}, 0x30: {24, 8}, 0x40: {17 + 24}}
        st = K.rank_slots([s], offsets, self.Names())
        self.assertEqual(s.slot_backed, {0x10, 0x20})
        self.assertEqual(core.slot_first(s), [0x10, 0x20, 0x30, 0x40])
        self.assertEqual((st["slot_calls"], st["slot_calls_shorter"]), (1, 1))

    def test_order_inside_each_group_is_kept(self):
        s = self.site([0x10, 0x20, 0x30, 0x40])
        K.rank_slots([s], {0x40: {16}, 0x20: {16}}, self.Names())
        self.assertEqual(core.slot_first(s), [0x20, 0x40, 0x10, 0x30])
        self.assertEqual(sorted(core.slot_first(s)), s.targets)

    def test_no_member_ranks_nothing(self):
        s = self.site([0x10, 0x20], members=())
        st = K.rank_slots([s], {0x10: {16}}, self.Names())
        self.assertEqual((s.slot_backed, core.slot_first(s), st["slot_calls"]), (set(), [0x10, 0x20], 0))
        s = self.site([0x10, 0x20], off=None)
        K.rank_slots([s], {0x10: {16}}, self.Names())
        self.assertEqual(s.slot_backed, set())

    def test_label(self):
        s = self.site([0x10])
        self.assertEqual(core.slot_label(s), "in a net_ops.xmit slot")
        s.members = ["c_ops.poll", "d_ops.poll"]
        self.assertEqual(core.slot_label(s), "in a slot of one of 2 members")


class ObjectOffsets(unittest.TestCase):
    """core.object_offsets(): each stored word belongs to the nearest symbol at or below it, if that is an object."""

    def test_containing_object(self):
        syms = [(0x1000, 0, True), (0x1100, 0, False), (0x2000, 0x10, True)]
        stored = [(0x1008, 0xa), (0x10f8, 0xb), (0x1108, 0xc), (0x2008, 0xd), (0x2010, 0xe), (0x0ff8, 0xf)]
        self.assertEqual(core.object_offsets(stored, syms), {0xa: {8}, 0xb: {0xf8}, 0xd: {8}})


class FixtureIDA(unittest.TestCase):
    """The IDA layer through the fake ida_* modules of tools/showcase_ida_stub.py (same addresses as the command line)."""

    def setUp(self):
        from test_showcase import showcase_module
        self.il, self.w = showcase_module().load(SLOTS)[:2]
        self.sites, self.stats = self.il.scan()
        self.by_fn = {self.il.target_name(s.call_ea).split("+")[0]: s for s in self.sites}

    def test_ranked_order_and_comment(self):
        il = self.il
        for fn, slot in SLOT_OF.items():
            with self.subTest(fn):
                s = self.by_fn[fn]
                self.assertEqual([il.target_name(t) for t in il.ranked(s)], slot + [n for n in ALL if n not in slot])
        il.annotate(self.sites)
        self.assertEqual(self.w.cmts[self.by_fn["call_net"].call_ea],
                         "kCFI net_ops.xmit 0xFD39CD44 int (struct msg *, int): 6 candidate(s): in a net_ops.xmit slot: "
                         "net_xmit_a, net_xmit_b, net_xmit_c; same type only: 3 more")
        self.assertEqual(self.w.cmts[self.by_fn["call_file_read"].call_ea],
                         "kCFI file_ops.read 0xFD39CD44 int (struct msg *, int): 6 candidate(s): in a file_ops.read slot: "
                         "file_read; same type only: 5 more")
        self.assertEqual(il.pseudocode_text(self.by_fn["call_net"]),
                         "CFIScope: net_ops.xmit, 6 candidates of int (struct msg *, int): in a net_ops.xmit slot: "
                         "net_xmit_a, net_xmit_b, net_xmit_c; same type only: 3 more")
        self.assertEqual(self.stats["slot_calls"], 3)

    def test_candidates_window_keeps_every_candidate(self):
        rows = self.il.targets_rows(self.by_fn["call_net"])
        self.assertEqual([(self.il.target_name(ea), note) for ea, _n, note in rows],
                         [(n, "stored in a net_ops.xmit slot") for n in NET] + [(n, "") for n in ALL if n not in NET])

    def test_call_site_list(self):
        chooser = self.il.sites_chooser(self.sites)
        rows = [chooser.OnGetLine(n) for n in range(chooser.OnGetSize())]
        self.assertIn(["0x1000ac", "call_net+0x2c", "net_ops.xmit", "int (struct msg *, int)", "6",
                       "in a net_ops.xmit slot: net_xmit_a, net_xmit_b, net_xmit_c; same type only: 3 more"], rows)

    def test_xref_cap_counts_slot_backed_first(self):
        # a list longer than the cap gets cross-references to its slot-backed candidates when they fit under the cap
        il, w = self.il, self.w
        res = il.annotate(self.sites, xref_limit=3)
        got = {(f, il.target_name(t)) for f, t, _fl in w.crefs}
        net, fw, fr = (self.by_fn[n].call_ea for n in ("call_net", "call_file_write", "call_file_read"))
        self.assertEqual(got, {(net, n) for n in NET} | {(fw, "file_write"), (fr, "file_read")})
        self.assertEqual((res["xrefs"], res["slot_only_lists"]), (5, 3))
        self.assertEqual(il.remove_annotations(self.sites, xref_limit=3), 5)
        self.assertEqual(w.crefs, set())
        res = il.annotate(self.sites, xref_limit=2)      # 3 slot-backed candidates do not fit under 2: none for call_net
        self.assertEqual({f for f, _t, _fl in w.crefs}, {fw, fr})
        self.assertEqual(il.annotate(self.sites)["slot_only_lists"], 0)   # 6 <= 16: every candidate, as before

    def test_no_slots_without_the_input_file(self):
        self.w.input_path = os.path.join(FIX, "missing.o")
        sites, stats = self.il.scan()
        s = next(x for x in sites if x.call_ea == self.by_fn["call_net"].call_ea)
        self.assertEqual(([self.il.target_name(t) for t in self.il.ranked(s)], stats.get("slot_calls", 0)), (ALL, 0))


# ---- known answers on the public GKI 6.1 kernel (CFISCOPE_GKI_ELF: its gki.elf, vmlinux-to-elf output) ----

GKI = os.environ.get("CFISCOPE_GKI_ELF", "")
INET_SLOTS = {"tcp_sendmsg", "raw_sendmsg", "udp_sendmsg", "ping_v4_sendmsg", "udpv6_sendmsg", "rawv6_sendmsg",
              "ping_v6_sendmsg"}       # the struct proto implementations of sendmsg stored in this kernel


@unittest.skipUnless(os.path.isfile(GKI), "set CFISCOPE_GKI_ELF to the GKI 6.1 gki.elf of the README walkthrough")
class GKIKnownAnswers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(GKI, "rb") as fh:
            d = fh.read()
        bounds = {}
        arch, ranges, syms = cli.load_elf(d, bounds=bounds)
        cls.sites, _ = core.resolve(ranges, arch, core.kernel_text(bounds))
        cls.before = {s.check_ea: list(s.targets) for s in cls.sites}
        names = K.load_type_names(d)
        K.name_sites(cls.sites, names)
        K.name_members(cls.sites, ranges, arch, names)
        offsets = cli.slot_offsets(d, {t for s in cls.sites for t in s.targets})
        cls.stats = K.rank_slots(cls.sites, offsets, names)
        cls.names = cli.Names(syms)
        del d, ranges

    def site(self, text):
        fn, off = text.split("+")
        ea = self.names.by_name[fn][0] + int(off, 16)
        return next(s for s in self.sites if s.call_ea == ea)

    def slot_names(self, text):
        s = self.site(text)
        return len(s.targets), {self.names(t) for t in s.slot_backed}

    def test_known_answers(self):
        self.assertEqual(self.slot_names("kernel_sendmsg_locked+0x64"), (11, {"tcp_sendmsg_locked"}))
        self.assertEqual(self.slot_names("inet_sendmsg+0x58"), (11, INET_SLOTS))
        self.assertEqual(self.slot_names("inet6_sendmsg+0x58"), (11, INET_SLOTS))
        n, slot = self.slot_names("sock_sendmsg+0xb4")
        self.assertEqual((n, len(slot)), (14, 13))
        self.assertNotIn("sock_no_sendmsg", slot)       # stored in no table of vmlinux (module ops tables use it)

    def test_nothing_dropped_anywhere(self):
        for s in self.sites:
            self.assertEqual(s.targets, self.before[s.check_ea])
            got = core.slot_first(s)
            self.assertEqual((len(got), sorted(got)), (len(s.targets), sorted(s.targets)))
            self.assertTrue(s.slot_backed <= set(s.targets))

    def test_cli_targets(self):
        rc, out = run([GKI, "--targets", "0xffffffc008cc5778"])
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertTrue(lines[1].endswith("  11 candidate(s), 1 in a proto_ops.sendmsg_locked slot"), lines[1])
        self.assertEqual(lines[2:4], ["  in a proto_ops.sendmsg_locked slot:", "    0xffffffc008e04cd0  tcp_sendmsg_locked"])
        self.assertEqual(lines[4], "  same type only:")
        self.assertEqual(len(lines), 15)
        self.assertIn("    0xffffffc008e05a98  tcp_sendmsg", lines[5:])


if __name__ == "__main__":
    unittest.main()
