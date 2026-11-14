"""Candidates stored in a matching static slot are listed first (internal review s193 #2). A call that loads its pointer
from a struct member (test_members.py) may reach any function of its type, but a function whose address sits, in the
image's static data, at that member's offset inside an object is more likely (and, listed after those, one at that
offset modulo the struct's size in an object holding another candidate of the call at such an offset: an array of such
structs, review s197): `kernel_sendmsg_locked+0x64` loads proto_ops.sendmsg_locked, and of its 11 candidates only
tcp_sendmsg_locked is stored at byte 216 of an object (inet_stream_ops, inet6_stream_ops) in GKI 6.1.

This ranks; it never filters: every candidate stays in every list, the slot-backed ones first."""
import contextlib, io, json, os, struct, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE); sys.path.insert(0, os.path.join(HERE, ".."))
from cfiscope import cli, core, kcfi_types as K  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
SLOTS = os.path.join(FIX, "kcfi_slots_a64.o")       # tests/fixtures/kcfi_slots.c: aarch64 kCFI code + its BTF
ALL = ["file_write", "file_read", "runtime_only", "net_xmit_a", "net_xmit_b", "net_xmit_c", "wide_cb",
       "net_xmit_rw"]   # address order
# each call: (stored at the member's offset, stored only by array stride); every other candidate: same type only
GROUPS = {"call_net": (["net_xmit_a", "net_xmit_b", "net_xmit_rw"], ["net_xmit_c"]),
          "call_file_write": (["file_write"], []), "call_file_read": (["file_read"], [])}
MEMBER_OF = {"call_net": "net_ops.xmit", "call_file_write": "file_ops.write", "call_file_read": "file_ops.read"}


def ordered(fn):
    offset, stride = GROUPS[fn]
    return offset + stride + [n for n in ALL if n not in offset + stride]


def run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = cli.main(argv)
    return rc, out.getvalue()


def sites_json(path, *extra):
    rc, out = run([path, "--sites", "--json"] + list(extra))
    assert rc == 0, rc
    return json.loads(out)


def patch_symbols(src, dst, changes):
    """Copy the ELF object src to dst with symbols changed: changes {name: (new STT type or None, new size or None)}."""
    with open(src, "rb") as fh:
        d = bytearray(fh.read())
    secs, hits = cli._sections(bytes(d)), set()
    for s in secs:
        if s[1] != 2:                                             # SHT_SYMTAB
            continue
        strtab = secs[s[6]]
        for off in range(s[4], s[4] + s[5], 24):
            start = strtab[4] + struct.unpack_from("<I", d, off)[0]
            name = bytes(d[start:d.index(b"\0", start)]).decode()
            if name in changes:
                kind, size = changes[name]
                if kind is not None:
                    d[off + 4] = (d[off + 4] & 0xF0) | kind
                if size is not None:
                    struct.pack_into("<Q", d, off + 16, size)
                hits.add(name)
    assert hits == set(changes), hits
    with open(dst, "wb") as fh:
        fh.write(d)


class FixtureCLI(unittest.TestCase):
    def test_right_struct_first(self):
        # net_ops.xmit, file_ops.write and file_ops.read share a type: all 8 functions are candidates of each call, but
        # only those stored in a slot of the member the call loads come first: at its offset, then by array stride
        # (net_xmit_c, byte 40 of net_tbl, which holds a candidate at byte 16 too); wide_cb is the only word at 16 modulo
        # 24 in wide_one, so not slot-backed
        doc = sites_json(SLOTS)
        by_fn = {s["in"].split("+")[0]: s for s in doc["sites"]}
        self.assertEqual(sorted(by_fn), sorted(GROUPS))
        for fn, (offset, stride) in GROUPS.items():
            with self.subTest(fn):
                s = by_fn[fn]
                self.assertEqual(s["member"], MEMBER_OF[fn])
                self.assertEqual([t["name"] for t in s["targets"]], ordered(fn))
                self.assertEqual([t["slot_backed"] for t in s["targets"]],
                                 ["offset"] * len(offset) + ["stride"] * len(stride) + [False] * (8 - len(offset + stride)))
                self.assertEqual((s["candidates"], s["slot_backed_candidates"], s["slot_stride_candidates"]),
                                 (8, len(offset + stride), len(stride)))
        st = doc["stats"]
        self.assertEqual((st["slot_calls"], st["slot_calls_shorter"], st["slot_calls_stride_only"]), (3, 3, 0))
        self.assertEqual((st["stored_candidates"], st["distinct_candidates"]), (7, 8))     # runtime_only: stored by code

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
        # a list that fits under --max-list names every candidate, in its group (review s197: the candidates of the same
        # type only were counted, never named, whatever the limit)
        rc, out = run([SLOTS, "--sites"])
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines(), [
            "0x1000ac  call_net+0x2c                            call net_ops.xmit hash 0xfd39cd44 (int (struct msg *, "
            "int))  8 candidate(s): in a net_ops.xmit slot: net_xmit_a, net_xmit_b, net_xmit_rw; by array stride: "
            "net_xmit_c; same type only: file_write, file_read, runtime_only, wide_cb",
            "0x1000ec  call_file_write+0x2c                     call file_ops.write hash 0xfd39cd44 (int (struct msg *, "
            "int))  8 candidate(s): in a file_ops.write slot: file_write; same type only: file_read, runtime_only, "
            "net_xmit_a, net_xmit_b, net_xmit_c, wide_cb, net_xmit_rw",
            "0x10012c  call_file_read+0x2c                      call file_ops.read hash 0xfd39cd44 (int (struct msg *, "
            "int))  8 candidate(s): in a file_ops.read slot: file_read; same type only: file_write, runtime_only, "
            "net_xmit_a, net_xmit_b, net_xmit_c, wide_cb, net_xmit_rw"])
        # a longer list: up to the limit of the slot-backed ones named, the rest of each group counted
        rc, out = run([SLOTS, "--sites", "--max-list", "2"])
        self.assertIn("8 candidate(s): in a net_ops.xmit slot: net_xmit_a, net_xmit_b, +1 more; by array stride: 1 more; "
                      "same type only: 4 more\n", out)
        rc, out = run([SLOTS, "--sites", "--max-list", "6"])
        self.assertIn("8 candidate(s): in a net_ops.xmit slot: net_xmit_a, net_xmit_b, net_xmit_rw; by array stride: "
                      "net_xmit_c; same type only: 4 more\n", out)
        self.assertIn("8 candidate(s): in a file_ops.write slot: file_write; same type only: 7 more\n", out)

    def test_targets_lists_every_candidate(self):
        rc, out = run([SLOTS, "--targets", "0x1000ac"])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "candidates for the site at 0x1000ac\n"
                              "0x1000ac  call_net+0x2c                            call net_ops.xmit hash 0xfd39cd44 (int "
                              "(struct msg *, int))  8 candidate(s), 3 in a net_ops.xmit slot, 1 by array stride\n"
                              "  in a net_ops.xmit slot:\n"
                              "    0x100034  net_xmit_a\n    0x100044  net_xmit_b\n    0x100150  net_xmit_rw\n"
                              "  by array stride:\n"
                              "    0x100054  net_xmit_c\n"
                              "  same type only:\n"
                              "    0x100004  file_write\n    0x100014  file_read\n    0x100024  runtime_only\n"
                              "    0x100140  wide_cb\n")

    def test_callers_marked_and_slot_backed_first(self):
        # review s197: --callers says, for each call, whether the function is stored in a slot of the call's member, and
        # lists those calls first (call_file_read comes last by address)
        rc, out = run([SLOTS, "--callers", "file_read", "--max-list", "1"])
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertEqual(lines[0], "3 call site(s) can reach file_read")
        self.assertEqual([ln.split()[1] for ln in lines[1:]], ["call_file_read+0x2c", "call_net+0x2c",
                                                               "call_file_write+0x2c"])
        self.assertTrue(lines[1].endswith("8 candidate(s): in a file_ops.read slot: file_read; same type only: 7 more  "
                                          "[file_read: in a file_ops.read slot]"), lines[1])
        self.assertTrue(lines[2].endswith("  [file_read: same type only]"), lines[2])
        self.assertTrue(lines[3].endswith("  [file_read: same type only]"), lines[3])
        rc, out = run([SLOTS, "--callers", "net_xmit_c"])
        self.assertEqual([ln.split()[1] for ln in out.splitlines()[1:]], ["call_net+0x2c", "call_file_write+0x2c",
                                                                          "call_file_read+0x2c"])
        self.assertTrue(out.splitlines()[1].endswith("  [net_xmit_c: by array stride]"))
        rc, out = run([SLOTS, "--callers", "file_read", "--json"])
        doc = json.loads(out)
        self.assertEqual([(s["in"], s["callee_slot_backed"]) for s in doc["sites"]],
                         [("call_file_read+0x2c", "offset"), ("call_net+0x2c", False), ("call_file_write+0x2c", False)])
        rc, out = run([SLOTS, "--callers", "file_read", "--no-btf"])     # nothing ranked: address order, no marker
        self.assertEqual([ln.split()[1] for ln in out.splitlines()[1:]], ["call_net+0x2c", "call_file_write+0x2c",
                                                                          "call_file_read+0x2c"])
        self.assertNotIn("[", out)

    def test_summary(self):
        rc, out = run([SLOTS])
        self.assertIn("kCFI calls with a candidate stored in a slot of their struct member: 3 (by array stride only: 0), "
                      "those candidates listed first (3 of the 3 lists also hold candidates of the same type only); kCFI "
                      "candidates stored in a static object: 7 of 8\n", out)
        rc, out = run([SLOTS, "--no-btf"])
        self.assertNotIn("slot", out)

    def test_no_member_no_slot(self):
        # x86-64 is not read for members, so nothing is ranked there: no slot field (test_members pins --sites bytes)
        doc = sites_json(os.path.join(FIX, "x86_64-kernel.o"))
        self.assertNotIn("slot_backed", json.dumps(doc["sites"]))
        self.assertEqual(doc["stats"].get("slot_calls", 0), 0)

    def test_raw_image_says_why_nothing_is_ranked(self):
        # review s197: --raw names the members but has no symbols, so no slot is read: no slot_backed field (it read
        # 'false' for every candidate) and the summary says what turns the ranking on
        with open(SLOTS, "rb") as fh:
            d = fh.read()
        text = cli._sections(d)[1]                            # .text, at 0x100000 as load_elf() lays it out
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "code.bin")
            with open(raw, "wb") as fh:
                fh.write(d[text[4]:text[4] + text[5]])
            argv = [raw, "--raw", "--arch", "aarch64", "--base", "0x100000", "--btf", SLOTS]
            rc, out = run(argv + ["--targets", "0x1000ac", "--json"])
            self.assertEqual(rc, 0)
            doc = json.loads(out)
            self.assertEqual(doc["sites"][0]["member"], "net_ops.xmit")
            self.assertNotIn("slot", json.dumps(doc))
            rc, out = run(argv)
        self.assertIn("\nslot ranking: needs the input's OBJECT symbols (an ELF such as vmlinux-to-elf output); not "
                      "with --raw\n", out)
        self.assertNotIn("slot ranking", run([SLOTS])[1])

    def test_relocation_into_a_second_data_section(self):
        # net_xmit_rw is static: net_rw (.data, not const) holds it through `.text + 0x150`, so the addend counts
        rel = cli.slot_offsets(open(SLOTS, "rb").read(), {0x100150, 0x100140, 0x100024})
        self.assertEqual(sorted(rel), [0x100140, 0x100150])
        self.assertEqual([o for _obj, o in rel[0x100150]], [16])
        self.assertEqual([o for _obj, o in rel[0x100140]], [40])

    def test_section_start_ends_the_objects_before(self):
        # a word before the first object of its section is in no object, even when the object before it (in the
        # section laid out before) has no size: here net_rw's symbol is made NOTYPE and hook's size 0
        with tempfile.TemporaryDirectory() as tmp:
            obj = os.path.join(tmp, "slots.o")
            patch_symbols(SLOTS, obj, {"net_rw": (0, None), "hook": (None, 0)})
            with open(obj, "rb") as fh:
                rel = cli.slot_offsets(fh.read(), {0x100150, 0x100140})
        self.assertEqual(sorted(rel), [0x100140])


class Matching(unittest.TestCase):
    """kcfi_types.rank_slots() on hand-made (object, offset) pairs: equal to the member offset, or equal modulo a struct
    size in an object that holds another candidate of the call at such an offset (an array)."""
    A, B, C = 0x1000, 0x2000, 0x3000

    def site(self, targets, off=16, members=("net_ops.xmit",)):
        s = core.Site(0x1000, 0x1010, 0x1234, -4, targets=list(targets))
        s.member_offset, s.members = off, list(members)
        return s

    class Names:
        member_sizes = {(0x1234, 16): [24]}

    def test_equal_and_stride(self):
        A, B, C = self.A, self.B, self.C
        s = self.site([0x10, 0x20, 0x30, 0x40, 0x50])
        offsets = {0x10: {(A, 16)}, 0x20: {(B, 40)}, 0x50: {(B, 16)}, 0x30: {(A, 24), (A, 8)}, 0x40: {(C, 41)}}
        st = K.rank_slots([s], offsets, self.Names())
        self.assertEqual((s.slot_backed, s.slot_stride), ({0x10, 0x20, 0x50}, {0x20}))
        self.assertEqual(core.slot_first(s), [0x10, 0x50, 0x20, 0x30, 0x40])
        self.assertEqual([core.slot_kind(s, t) for t in s.targets], ["offset", "stride", None, None, "offset"])
        self.assertEqual((st["slot_calls"], st["slot_calls_shorter"], st["slot_calls_stride_only"]), (1, 1, 0))

    def test_lone_congruent_word_is_no_evidence(self):
        # review s197: kallsyms gives objects no size, so a word at 16 modulo 24 is charged to whatever object is below
        # it; one such word (or one per object) is not an array
        s = self.site([0x10, 0x20])
        st = K.rank_slots([s], {0x10: {(self.A, 40)}, 0x20: {(self.B, 64)}}, self.Names())
        self.assertEqual((s.slot_backed, st["slot_calls"]), (set(), 0))

    def test_stride_only(self):
        s = self.site([0x10, 0x20, 0x30])
        st = K.rank_slots([s], {0x10: {(self.A, 40)}, 0x20: {(self.A, 64)}}, self.Names())
        self.assertEqual((s.slot_backed, s.slot_stride), ({0x10, 0x20}, {0x10, 0x20}))
        self.assertEqual((st["slot_calls"], st["slot_calls_stride_only"]), (1, 1))

    def test_eight_byte_struct_is_no_evidence(self):
        # struct { fn_t fn; } (8 bytes): every 8-aligned slot is at offset 0 modulo 8, so only equality counts for it
        class Names:
            member_sizes = {(0x1234, 0): [8, 16]}
        s = self.site([0x10, 0x20, 0x30, 0x40], off=0)
        K.rank_slots([s], {0x10: {(self.A, 0)}, 0x20: {(self.A, 8)}, 0x30: {(self.B, 32)}, 0x40: {(self.B, 0)}}, Names())
        self.assertEqual((s.slot_backed, s.slot_stride), ({0x10, 0x30, 0x40}, {0x30}))

    def test_every_candidate_slot_backed(self):
        s = self.site([0x10, 0x20])
        st = K.rank_slots([s], {0x10: {(self.A, 16)}, 0x20: {(self.B, 16)}}, self.Names())
        self.assertEqual((st["slot_calls"], st["slot_calls_shorter"]), (1, 0))

    def test_order_inside_each_group_is_kept(self):
        s = self.site([0x10, 0x20, 0x30, 0x40])
        K.rank_slots([s], {0x40: {(self.A, 16)}, 0x20: {(self.B, 16)}}, self.Names())
        self.assertEqual(core.slot_first(s), [0x20, 0x40, 0x10, 0x30])
        self.assertEqual(sorted(core.slot_first(s)), s.targets)

    def test_no_member_ranks_nothing(self):
        s = self.site([0x10, 0x20], members=())
        st = K.rank_slots([s], {0x10: {(self.A, 16)}}, self.Names())
        self.assertEqual((s.slot_backed, core.slot_first(s), st["slot_calls"]), (set(), [0x10, 0x20], 0))
        s = self.site([0x10, 0x20], off=None)
        K.rank_slots([s], {0x10: {(self.A, 16)}}, self.Names())
        self.assertEqual(s.slot_backed, set())

    def test_label(self):
        s = self.site([0x10])
        self.assertEqual(core.slot_label(s), "in a net_ops.xmit slot")
        s.members = ["c_ops.poll", "d_ops.poll"]
        self.assertEqual(core.slot_label(s), "in a slot of one of 2 members")

    def test_text_names_all_when_the_list_fits(self):
        A, B = self.A, self.B
        s = self.site([0x10, 0x20, 0x30, 0x40, 0x50])
        K.rank_slots([s], {0x10: {(A, 16)}, 0x20: {(A, 40)}}, self.Names())
        name = "f%x".__mod__
        order = core.slot_first(s)
        self.assertEqual(core.slot_text(s, order, name, 5), "in a net_ops.xmit slot: f10; by array stride: f20; same "
                                                           "type only: f30, f40, f50")
        self.assertEqual(core.slot_text(s, order, name, 4), "in a net_ops.xmit slot: f10; by array stride: f20; same "
                                                           "type only: 3 more")
        self.assertEqual(core.slot_text(s, order, name, 1), "in a net_ops.xmit slot: f10; by array stride: 1 more; same "
                                                           "type only: 3 more")
        self.assertEqual(core.slot_text(s, order, name, 1, " and %d more"),
                         "in a net_ops.xmit slot: f10; by array stride: 1 more; same type only: 3 more")


class ObjectOffsets(unittest.TestCase):
    """core.object_offsets(): each stored word belongs to the nearest symbol at or below it, if that is an object."""

    def test_containing_object(self):
        syms = [(0x1000, 0, True), (0x1100, 0, False), (0x2000, 0x10, True)]
        stored = [(0x1008, 0xa), (0x10f8, 0xb), (0x1108, 0xc), (0x2008, 0xd), (0x2010, 0xe), (0x0ff8, 0xf)]
        self.assertEqual(core.object_offsets(stored, syms),
                         {0xa: {(0x1000, 8)}, 0xb: {(0x1000, 0xf8)}, 0xd: {(0x2000, 8)}})


class FixtureIDA(unittest.TestCase):
    """The IDA layer through the fake ida_* modules of tools/showcase_ida_stub.py (same addresses as the command line)."""

    def setUp(self):
        from test_showcase import showcase_module
        self.il, self.w = showcase_module().load(SLOTS)[:2]
        self.sites, self.stats = self.il.scan()
        self.by_fn = {self.il.target_name(s.call_ea).split("+")[0]: s for s in self.sites}
        self.ea = {self.il.target_name(t): t for t in self.sites[0].targets}

    def scan_output(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            sites, stats = self.il.scan()
        return sites, stats, out.getvalue()

    def test_ranked_order_and_comment(self):
        il = self.il
        for fn in GROUPS:
            with self.subTest(fn):
                self.assertEqual([il.target_name(t) for t in il.ranked(self.by_fn[fn])], ordered(fn))
        il.annotate(self.sites)
        self.assertEqual(self.w.cmts[self.by_fn["call_net"].call_ea],
                         "kCFI net_ops.xmit 0xFD39CD44 int (struct msg *, int): 8 candidate(s): in a net_ops.xmit slot: "
                         "net_xmit_a, net_xmit_b, net_xmit_rw; by array stride: net_xmit_c; same type only: 4 more")
        self.assertEqual(self.w.cmts[self.by_fn["call_file_read"].call_ea],
                         "kCFI file_ops.read 0xFD39CD44 int (struct msg *, int): 8 candidate(s): in a file_ops.read slot: "
                         "file_read; same type only: 7 more")
        self.assertEqual(il.pseudocode_text(self.by_fn["call_net"]),
                         "CFIScope: net_ops.xmit, 8 candidates of int (struct msg *, int): in a net_ops.xmit slot: "
                         "net_xmit_a, net_xmit_b, net_xmit_rw; by array stride: net_xmit_c; same type only: 4 more")
        self.assertEqual(self.stats["slot_calls"], 3)

    def test_short_list_names_every_candidate(self):
        # review s197: a list of at most 6 (the comment) or 5 (pseudocode) names its candidates of the same type only too
        s = core.Site(0x1000, 0x1010, 0x1234, -4, targets=[self.ea[n] for n in ("file_write", "file_read", "net_xmit_a")])
        s.members, s.member_offset, s.slot_backed = ["net_ops.xmit"], 16, {self.ea["net_xmit_a"]}
        self.assertEqual(self.il.candidate_names(s, self.il.ranked(s)),
                         "in a net_ops.xmit slot: net_xmit_a; same type only: file_write, file_read")
        self.assertTrue(self.il.pseudocode_text(s).endswith(": in a net_ops.xmit slot: net_xmit_a; same type only: "
                                                            "file_write, file_read"))

    def test_slot_backed_before_address_taken(self):
        # an address-taken candidate (a data xref to it) comes after the slot-backed ones, before the rest
        self.w.drefs.add(self.ea["wide_cb"])
        il = self.il
        self.assertEqual([il.target_name(t) for t in il.ranked(self.by_fn["call_file_write"])],
                         ["file_write", "wide_cb", "file_read", "runtime_only", "net_xmit_a", "net_xmit_b", "net_xmit_c",
                          "net_xmit_rw"])
        self.assertEqual([il.target_name(t) for t in il.ranked(self.by_fn["call_net"], {})][:5],
                         ["net_xmit_a", "net_xmit_b", "net_xmit_rw", "net_xmit_c", "wide_cb"])

    def test_candidates_window_keeps_every_candidate(self):
        rows = self.il.targets_rows(self.by_fn["call_net"])
        self.assertEqual([(self.il.target_name(ea), note) for ea, _n, note in rows],
                         [(n, "stored in a net_ops.xmit slot") for n in GROUPS["call_net"][0]] +
                         [("net_xmit_c", "by array stride")] +
                         [(n, "") for n in ("file_write", "file_read", "runtime_only", "wide_cb")])

    def test_call_site_list(self):
        chooser = self.il.sites_chooser(self.sites)
        rows = [chooser.OnGetLine(n) for n in range(chooser.OnGetSize())]
        self.assertIn(["0x1000ac", "call_net+0x2c", "net_ops.xmit", "int (struct msg *, int)", "8",
                       "in a net_ops.xmit slot: net_xmit_a, net_xmit_b, net_xmit_rw; by array stride: net_xmit_c; same "
                       "type only: 4 more"], rows)

    def test_callers_marked_and_slot_backed_first(self):
        # review s197: the Callers rows say whether the function is stored in a slot of each call's member, those first
        il = self.il
        rows = il.callers_rows(self.sites, self.ea["file_read"])
        self.assertEqual([(il.target_name(ea), note) for ea, _n, note in rows],
                         [("call_file_read+0x2c", "file_ops.read, 8 candidate(s), stored in a file_ops.read slot"),
                          ("call_net+0x2c", "net_ops.xmit, 8 candidate(s), same type only"),
                          ("call_file_write+0x2c", "file_ops.write, 8 candidate(s), same type only")])
        rows = il.callers_rows(self.sites, self.ea["net_xmit_c"])
        self.assertEqual(rows[0][2], "net_ops.xmit, 8 candidate(s), by array stride")

    def test_xref_cap_counts_offset_matches_first(self):
        # a list longer than the cap gets cross-references to its candidates stored at the member's offset when they fit
        # under the cap; never to those found by array stride only (review s197), and Remove annotations then deletes
        # only those on such a list, so a cross-reference of your own to another candidate stays
        il, w = self.il, self.w
        res = il.annotate(self.sites, xref_limit=3)
        got = {(f, il.target_name(t)) for f, t, _fl in w.crefs}
        net, fw, fr = (self.by_fn[n].call_ea for n in ("call_net", "call_file_write", "call_file_read"))
        self.assertEqual(got, {(net, n) for n in GROUPS["call_net"][0]} | {(fw, "file_write"), (fr, "file_read")})
        self.assertEqual((res["xrefs"], res["slot_only_lists"]), (5, 3))
        mine = (net, self.ea["file_write"], 17 | 32)              # fl_CN | XREF_USER, added by hand
        w.crefs.add(mine)
        self.assertEqual(il.remove_annotations(self.sites, xref_limit=3), 5)
        self.assertEqual(w.crefs, {mine})
        w.crefs.clear()
        il.annotate(self.sites, xref_limit=4)            # 3 at the offset fit; net_xmit_c (by stride) gets none
        self.assertEqual({il.target_name(t) for f, t, _fl in w.crefs if f == net}, set(GROUPS["call_net"][0]))
        il.remove_annotations(self.sites, xref_limit=4)
        res = il.annotate(self.sites, xref_limit=2)      # 3 at the offset do not fit under 2: none for call_net
        self.assertEqual({f for f, _t, _fl in w.crefs}, {fw, fr})
        self.assertEqual(il.annotate(self.sites)["slot_only_lists"], 0)   # 8 <= 16: every candidate, as before

    def test_scan_sentence_counts_those_lists(self):
        from test_entry_stub import load_entry
        _w, E, _log = load_entry()
        res = {"comments": 3, "runtime_comments": 0, "xrefs": 5, "data_xrefs_inside_function": 0,
               "xrefs_skipped_no_function": 0, "xrefs_skipped_not_code": 0, "kept_user_comments": 0,
               "slot_only_lists": 3}
        stats = dict(self.stats, max_candidates=20)
        self.assertIn("(none for lists of more than 16, except to their candidates stored in a slot of the call's member "
                      "in 3 of them).", E.scan_sentence(stats, res))
        self.assertIn("(none for lists of more than 16).", E.scan_sentence(stats, dict(res, slot_only_lists=0)))

    def test_no_slots_without_the_input_file(self):
        self.w.input_path = os.path.join(FIX, "missing.o")
        sites, stats, out = self.scan_output()
        s = next(x for x in sites if x.call_ea == self.by_fn["call_net"].call_ea)
        self.assertEqual(([self.il.target_name(t) for t in self.il.ranked(s)], stats.get("slot_calls", 0)), (ALL, 0))
        self.assertEqual(out, "Output window: [CFIScope] slot ranking skipped: the input file is not at %s; the "
                              "candidate lists keep their order\n" % self.w.input_path)

    def test_no_slots_when_the_database_differs_from_the_file(self):
        # the database's bytes at the start of a code range of the file differ (rebased, or laid out elsewhere): no order
        base = min(self.w.mem)
        data = bytearray(self.w.mem[base])
        data[8] ^= 0xff                                  # inside file_write, not a hash or a call
        self.w.mem[base] = bytes(data)
        sites, stats, out = self.scan_output()
        s = next(x for x in sites if x.call_ea == self.by_fn["call_net"].call_ea)
        self.assertEqual(([self.il.target_name(t) for t in self.il.ranked(s)], stats.get("slot_calls", 0)), (ALL, 0))
        self.assertIn("slot ranking skipped: the database does not have the layout of %s" % self.w.input_path, out)

    def test_no_message_when_ranked(self):
        self.assertEqual(self.scan_output()[2], "")


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
        for call in ("kernel_sendmsg_locked+0x64", "inet_sendmsg+0x58", "inet6_sendmsg+0x58", "sock_sendmsg+0xb4"):
            self.assertEqual(self.site(call).slot_stride, set())          # all at the member's offset
        self.assertEqual(self.slot_names("kernel_sendmsg_locked+0x64"), (11, {"tcp_sendmsg_locked"}))
        self.assertEqual(self.slot_names("inet_sendmsg+0x58"), (11, INET_SLOTS))
        self.assertEqual(self.slot_names("inet6_sendmsg+0x58"), (11, INET_SLOTS))
        n, slot = self.slot_names("sock_sendmsg+0xb4")
        self.assertEqual((n, len(slot)), (14, 13))
        self.assertNotIn("sock_no_sendmsg", slot)       # stored in no table of vmlinux (module ops tables use it)

    def test_lone_modulo_word_is_not_a_slot(self):
        # review s197: sock_diag_rcv is stored at byte 592 of bpf_sk_lookup_assign_proto (kallsyms gives no sizes, so the
        # word is charged to the object below it): 592 modulo 248 is 96, sk_buff.destructor, but no other word there holds
        # a candidate of the call, so it is not slot-backed (it is a netlink_kernel_cfg.input initializer)
        n, slot = self.slot_names("packet_rcv+0x280")
        self.assertEqual(self.site("packet_rcv+0x280").members, ["sk_buff.destructor"])
        self.assertNotIn("sock_diag_rcv", slot)

    def test_one_line_names_every_candidate_that_fits(self):
        # review s197: `--sites --max-list 20` hid sock_no_sendmsg behind 'same type only: 1 more'
        line = cli._site_line(self.site("sock_sendmsg+0xb4"), self.names, 20)
        self.assertTrue(line.endswith("; same type only: sock_no_sendmsg"), line)
        self.assertIn("14 candidate(s): in a proto_ops.sendmsg slot: tun_sendmsg, netlink_sendmsg,", line)
        line = cli._site_line(self.site("kernel_sendmsg_locked+0x64"), self.names, 3)
        self.assertTrue(line.endswith("11 candidate(s): in a proto_ops.sendmsg_locked slot: tcp_sendmsg_locked; same type "
                                      "only: 10 more"), line)

    def test_callers_of_tcp_sendmsg(self):
        # the two proto.sendmsg calls store tcp_sendmsg in a slot of their member and come first; kernel_sendmsg_locked's
        # call is a type-only match for it
        want = set(self.names.by_name["tcp_sendmsg"])
        calls, _ = core.callers(self.sites, want.__contains__, lambda ea: False)
        calls = core.slot_callers_first(calls, want.__contains__)
        self.assertEqual([(self.names(s.call_ea), core.callee_slot(s, want.__contains__)[0]) for s in calls],
                         [("inet_sendmsg+0x58", "offset"), ("inet6_sendmsg+0x58", "offset"),
                          ("kernel_sendmsg_locked+0x64", "type")])

    def test_nothing_dropped_anywhere(self):
        for s in self.sites:
            self.assertEqual(s.targets, self.before[s.check_ea])
            got = core.slot_first(s)
            self.assertEqual((len(got), sorted(got)), (len(s.targets), sorted(s.targets)))
            self.assertTrue(s.slot_stride <= s.slot_backed <= set(s.targets))

    def test_cli_targets(self):
        rc, out = run([GKI, "--targets", "0xffffffc008cc5778"])
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertTrue(lines[1].endswith("  11 candidate(s), 1 in a proto_ops.sendmsg_locked slot"), lines[1])
        self.assertEqual(lines[2:4], ["  in a proto_ops.sendmsg_locked slot:", "    0xffffffc008e04cd0  tcp_sendmsg_locked"])
        self.assertEqual(lines[4], "  same type only:")
        self.assertEqual(len(lines), 15)
        self.assertIn("    0xffffffc008e05a98  tcp_sendmsg", lines[5:])


# ---- a real module (CFISCOPE_KO_DIR: the GKI 6.1 bluetooth.ko and kernel-6.1 of docs/VERIFICATION.md) ----

KO = os.environ.get("CFISCOPE_KO_DIR", "")


@unittest.skipUnless(os.path.isfile(os.path.join(KO, "bluetooth.ko")) and os.path.isfile(os.path.join(KO, "kernel-6.1")),
                     "set CFISCOPE_KO_DIR to a folder with the GKI bluetooth.ko and kernel-6.1 of docs/VERIFICATION.md")
class KOKnownAnswers(unittest.TestCase):
    def test_hci_conn_failed(self):
        # a module's data holds zeros where pointers go: its R_AARCH64_ABS64 relocations say what is stored there, here
        # `.text + addend` at byte 24 (hci_cb.connect_cfm) of l2cap_cb, sco_cb and iso_cb
        doc = sites_json(os.path.join(KO, "bluetooth.ko"), "--btf", os.path.join(KO, "kernel-6.1"))
        s = next(x for x in doc["sites"] if x["in"] == "hci_conn_failed+0xbc")
        self.assertEqual((s["member"], s["candidates"]), ("hci_cb.connect_cfm", 12))
        self.assertEqual([(t["name"], t["slot_backed"]) for t in s["targets"][:4]],
                         [("l2cap_connect_cfm", "offset"), ("sco_connect_cfm", "offset"), ("iso_connect_cfm", "offset"),
                          (s["targets"][3]["name"], False)])
        st = doc["stats"]
        self.assertEqual((st["slot_calls"], st["stored_candidates"], st["distinct_candidates"]), (128, 314, 603))


if __name__ == "__main__":
    unittest.main()
