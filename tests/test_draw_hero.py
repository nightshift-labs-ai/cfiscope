"""docs/img/hero.svg and hero.png (tools/draw_hero.py): drawn from the command line's output on GKI 6.1, not from IDA.

Always: the SVG parses with xml.etree, loads nothing and has nothing GitHub's sanitiser strips, both files are under
100 KB, the tool's own words are exactly the two headings and the caption, the boxes, arrows and blue highlights
agree with the texts, and the PNG is this SVG rasterised (its tEXt chunk carries the SVG's sha256; inside every
rectangle of the SVG its pixels have the rectangle's colour).  tools/draw_hero.py on the small aarch64 test fixture:
the caption names the input file, and a bad offset or a PNG it cannot palettise gives a plain message.
With CFISCOPE_GKI_ELF=path/to/gki.elf (the README walkthrough's kernel): every other text equals a field of a fresh
`python3 -m cfiscope` run, the candidates stand under the group headers `--targets` prints (review s197: the slot
groups), each caller carries the tag its `--callers` line ends with, and tools/draw_hero.py redraws the SVG byte for
byte.
"""
import contextlib, hashlib, importlib.util, io, json, os, re, struct, subprocess, sys, tempfile, unittest, zlib
import xml.etree.ElementTree as ET
from unittest import mock
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, ROOT)
from cfiscope import cli  # noqa: E402
IMG = os.path.join(ROOT, "docs", "img")
SVG, PNG, DOC = (os.path.join(IMG, n) for n in ("hero.svg", "hero.png", "README.md"))
TOOL = os.path.join(ROOT, "tools", "draw_hero.py")
NS = "{http://www.w3.org/2000/svg}"
ELF = os.environ.get("CFISCOPE_GKI_ELF")
SITE, CALLEE = "sock_sendmsg+0xb4", "tcp_sendmsg"
MAX_BYTES = 100 * 1024

# The tool's own words, typed again here: a changed word must fail.  Every other text is checked against the CLI.
HEADINGS = ("Which functions may this indirect call reach?",
            "Which indirect calls may reach this function (same kCFI type)?")
CAPTION = "Drawn from python3 -m cfiscope gki.elf output, not an IDA screenshot"

CALL_FIELDS = {"site": ["in", "insn", "call", "hash", "type", "count"],
               "caller": ["in", "insn", "call", "hash", "count", "type", "slot"]}
BLUE_BOX, CALL_BOX, FUNC_BOX = ("#e6efff", "#2f6fdd"), ("#fff4e5", "#d4761c"), ("#ffffff", "#8c959f")
TYPE_ONLY_BOX, GREY = ("#eef0f2", "#8c959f"), "#59636e"
BLUE_INK, BLUE_EDGE = "#0b4fc4", "#2f6fdd"
TYPE_ONLY_TAG = ": same type only]"
RUNNER = ("import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); "
          "runpy.run_module('cfiscope', run_name='__main__', alter_sys=True)")


def tag(e):
    return e.tag[len(NS):] if e.tag.startswith(NS) else e.tag


def cls(e):
    return (e.get("class") or "").split()


def kids(e, name, klass=None):
    return [c for c in e if tag(c) == name and (klass is None or klass in cls(c))]


def box(g):
    r = kids(g, "rect")[0]
    return tuple(float(r.get(k)) for k in ("x", "y", "width", "height")) + ((r.get("fill"), r.get("stroke")),)


def texts(g):
    return [(cls(t)[0], t.text) for t in g.iter(NS + "text")]


def tip(edge):
    """(start x, start y, arrow tip x, arrow tip y) of an edge group, after checking that the curve ends at the base of
    its arrowhead and that the head points right, at the target."""
    d = kids(edge, "path")[0].get("d").replace("M", "").replace("C", " ").split()
    pts = [tuple(map(float, p.split(","))) for p in kids(edge, "polygon")[0].get("points").split()]
    (bx0, by0), (tx, ty), (bx1, by1) = pts
    assert (float(d[-2]), float(d[-1])) == (tx - 7, ty), (d, pts)
    assert bx0 == bx1 == tx - 8 and by0 == ty - 4.5 and by1 == ty + 4.5, pts
    return float(d[0]), float(d[1]), tx, ty


def load_svg(path=SVG):
    with open(path, "rb") as fh:
        raw = fh.read()
    return raw, ET.fromstring(raw)


def panels(root):
    groups = {g.get("id"): g for g in kids(root, "g")}
    return groups["targets"], groups["callers"]


def run_cli(*args):
    return subprocess.run([sys.executable, "-I", "-c", RUNNER, ROOT, ELF] + list(args), capture_output=True,
                          text=True, check=True).stdout


def decode(data, ea):
    """The aarch64 instruction at ea, by the ELF's program headers, decoded here independently of draw_hero.py."""
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phnum, = struct.unpack_from("<H", data, 0x38)
    for i in range(phnum):
        p_type, _f, off, vaddr, _pa, filesz = struct.unpack_from("<IIQQQQ", data, phoff + 56 * i)
        if p_type == 1 and vaddr <= ea < vaddr + filesz:
            w, = struct.unpack_from("<I", data, off + ea - vaddr)
            if w >> 10 == 0xd63f0000 >> 10 and w & 31 == 0:
                return "blr x%d" % ((w >> 5) & 31)
            return "word 0x%08x" % w
    return None


def png_chunks(path):
    """[(kind, body), ...] of a PNG, each chunk's CRC checked."""
    with open(path, "rb") as fh:
        d = fh.read()
    assert d[:8] == b"\x89PNG\r\n\x1a\n", path
    pos, chunks = 8, []
    while pos < len(d):
        n, kind = struct.unpack_from(">I4s", d, pos)
        body = d[pos + 8:pos + 8 + n]
        assert struct.unpack_from(">I", d, pos + 8 + n)[0] == zlib.crc32(kind + body) & 0xffffffff, kind
        chunks.append((kind, body))
        pos += 12 + n
    return chunks


class Picture(unittest.TestCase):
    """The committed SVG and PNG, with no kernel needed."""

    @classmethod
    def setUpClass(cls_):
        cls_.raw, cls_.root = load_svg()

    def test_well_formed_small_and_safe(self):
        self.assertEqual(tag(self.root), "svg")
        self.assertLess(len(self.raw), MAX_BYTES)
        self.assertLess(os.path.getsize(PNG), MAX_BYTES)
        for bad in (b"<!DOCTYPE", b"<!ENTITY", b"@import", b"url(", b"<?xml-stylesheet", b"base64"):
            self.assertNotIn(bad, self.raw)
        allowed = {"svg", "g", "rect", "text", "path", "polygon"}
        for e in self.root.iter():
            self.assertIn(tag(e), allowed)            # no script, style, image, foreignObject, a, use, animation
            for k, v in e.attrib.items():
                self.assertFalse(k.lower().startswith("on") or "href" in k.lower(), k)
                if k == "font-family":
                    self.assertIn(v, ("monospace", "sans-serif"))

    def test_own_words_are_the_headings_and_caption(self):
        p1, p2 = panels(self.root)
        self.assertEqual([t.text for t in kids(p1, "text", "heading")], [HEADINGS[0]])
        self.assertEqual([t.text for t in kids(p2, "text", "heading")], [HEADINGS[1]])
        self.assertEqual([t.text for t in kids(self.root, "text")], [CAPTION])
        self.assertEqual(kids(self.root, "text")[0].get("class"), "caption")
        bottom = max(box(p)[1] + box(p)[3] for p in (p1, p2))
        self.assertGreater(float(kids(self.root, "text")[0].get("y")), bottom)
        for p in (p1, p2):
            head = kids(p, "text", "heading")[0]
            self.assertLess(float(head.get("y")), min(box(g)[1] for g in p if tag(g) == "g" and "edge" not in cls(g)
                                                      and "group" not in cls(g)))
            for g in kids(p, "g", "group"):         # a group header too sits under the heading
                self.assertLess(float(head.get("y")), float(kids(g, "text")[0].get("y")) - 13)
        everything = [t.text for t in self.root.iter(NS + "text")]
        self.assertEqual(sorted(t for t in everything if t in HEADINGS + (CAPTION,)), sorted(HEADINGS + (CAPTION,)))
        # Every other text is in a box (or the callers count) of a panel, with a class the fresh-run test checks.
        for p, groups in ((p1, {"site", "candidate", "edge", "group"}), (p2, {"caller", "callee", "edge"})):
            self.assertEqual({cls(g)[0] for g in kids(p, "g")}, groups)
            self.assertEqual([cls(t)[0] for t in kids(p, "text")], ["heading"] + (["count"] if p is p2 else []))

    def test_boxes_arrows_and_highlights_agree(self):
        p1, p2 = panels(self.root)
        site, = kids(p1, "g", "site")
        self.assertEqual([c for c, _t in texts(site)], CALL_FIELDS["site"])
        cands = kids(p1, "g", "candidate")
        count = dict(texts(site))["count"]
        self.assertTrue(count.startswith("%d candidate(s), " % len(cands)), count)     # and the slot groups counted
        # review s197: the slot groups. A group header stands right above the first candidate of its group, the first
        # one above the first candidate; a candidate of the same type only is grey, dashed, under 'same type only:'.
        order = [g for g in kids(p1, "g") if cls(g)[0] in ("group", "candidate")]
        self.assertEqual(cls(order[0])[0], "group")
        header = None
        for i, g in enumerate(order):
            if cls(g)[0] == "group":
                (k, header), = texts(g)
                self.assertEqual(k, "label")
                nxt = box(order[i + 1])
                label_y = float(kids(g, "text")[0].get("y"))
                self.assertTrue(nxt[1] - 12 < label_y < nxt[1], (header, label_y, nxt))
                continue
            lone = header == "same type only:"
            self.assertEqual("type-only" in cls(g), lone, texts(g))
            if lone:
                self.assertEqual(box(g)[4], TYPE_ONLY_BOX)
                self.assertEqual(kids(g, "rect")[0].get("stroke-dasharray"), "5 4")
                self.assertEqual(kids(g, "text")[0].get("fill"), GREY)
        self.assertEqual([texts(g)[0][1] for g in order if cls(g)[0] == "group"],
                         ["in a proto_ops.sendmsg slot:", "same type only:"])
        callers, (callee,) = kids(p2, "g", "caller"), kids(p2, "g", "callee")
        self.assertEqual(kids(p2, "text", "count")[0].text, "%d call site(s)" % len(callers))
        caller_funcs = [dict(texts(c))["in"].partition("+")[0] for c in callers]
        names = [texts(c)[0][1] for c in cands]
        sx, sy, sw, sh, _ = box(site)
        edges = kids(p1, "g", "edge")
        self.assertEqual(len(edges), len(cands))
        for c, e in zip(cands, edges):
            x, y, w, h, colours = box(c)
            (k, name), = texts(c)
            self.assertEqual(k, "name")
            blue = name in caller_funcs
            self.assertEqual("also-caller" in cls(c), blue, name)
            self.assertEqual(colours, BLUE_BOX if blue else TYPE_ONLY_BOX if "type-only" in cls(c) else FUNC_BOX, name)
            self.assertEqual(kids(c, "text")[0].get("fill") == BLUE_INK, blue, name)
            self.assertEqual(kids(e, "path")[0].get("stroke") == BLUE_EDGE, blue, name)
            self.assertEqual(kids(e, "path")[0].get("stroke-dasharray") == "5 4", "type-only" in cls(c), name)
            self.assertEqual("type-only" in cls(e), "type-only" in cls(c), name)
            self.assertEqual(tip(e), (sx + sw, sy + sh / 2, x, y + h / 2))
        self.assertTrue(any("also-caller" in cls(c) for c in cands))
        self.assertEqual(len(kids(p2, "g", "edge")), len(callers))
        tx, ty, tw, th, _ = box(callee)
        for c, e in zip(callers, kids(p2, "g", "edge")):
            x, y, w, h, colours = box(c)
            self.assertEqual(colours, CALL_BOX)
            self.assertEqual([k for k, _t in texts(c)], CALL_FIELDS["caller"])
            lone = dict(texts(c))["slot"].endswith(TYPE_ONLY_TAG)        # the callee is of the same type only here
            self.assertEqual(kids(e, "path")[0].get("stroke-dasharray") == "5 4", lone)
            name_ink = [t for t in kids(c, "text") if cls(t) == ["in"]][0].get("fill")
            self.assertEqual(name_ink == BLUE_INK, dict(texts(c))["in"].partition("+")[0] in names)
            x0, y0, x1, y1 = tip(e)
            self.assertEqual((x0, y0, x1), (x + w, y + h / 2, tx))
            self.assertTrue(ty < y1 < ty + th)
        # Each text sits inside its box, at the widest monospace glyph assumed by draw_hero.py (0.62 em).
        for g in kids(p1, "g") + kids(p2, "g"):
            if "edge" in cls(g) or "group" in cls(g):
                continue
            x, y, w, h, _ = box(g)
            for t in kids(g, "text"):
                tx_, ty_ = float(t.get("x")), float(t.get("y"))
                self.assertTrue(x < tx_ and tx_ + len(t.text) * int(t.get("font-size")) * 0.62 <= x + w, t.text)
                self.assertTrue(y < ty_ - int(t.get("font-size")) * 0.75 and ty_ < y + h, t.text)

    def test_png_is_the_svg_size_times_1_5(self):
        with open(PNG, "rb") as fh:
            head = fh.read(24)
        self.assertEqual(head[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(head[12:16], b"IHDR")
        w, h = struct.unpack(">II", head[16:24])
        size = (float(self.root.get("width")), float(self.root.get("height")))
        self.assertEqual((w, h), (round(size[0] * 1.5), round(size[1] * 1.5)))

    def test_png_is_this_svg(self):
        """The README shows hero.png, so it must be hero.svg rasterised: its tEXt chunk carries the sha256 of this
        hero.svg (a redrawn SVG needs a new PNG), and at two points inside each rectangle of the SVG, times 1.5, its
        pixel has that rectangle's fill colour (a blank or wrong PNG fails)."""
        chunks = png_chunks(PNG)
        self.assertEqual([k for k, _b in chunks], [b"IHDR", b"PLTE", b"tEXt", b"IDAT", b"IEND"])
        body = dict(chunks)
        w, h, depth, ctype, _comp, _filt, interlace = struct.unpack(">IIBBBBB", body[b"IHDR"])
        self.assertEqual((depth, ctype, interlace), (8, 3, 0))           # palette_png's output: 8-bit palette
        # sha256 of the SVG as tools/draw_hero.py writes it (LF line ends, also after a CRLF checkout).
        sha = hashlib.sha256(self.raw.replace(b"\r\n", b"\n")).hexdigest()
        self.assertEqual(body[b"tEXt"], b"Comment\0rasterised from hero.svg, sha256 " + sha.encode(),
                         "docs/img/hero.png is not hero.svg rasterised: redraw it (docs/img/README.md)")
        plte = body[b"PLTE"]
        palette = ["#%02x%02x%02x" % tuple(plte[i:i + 3]) for i in range(0, len(plte), 3)]
        raw = zlib.decompress(b"".join(b for k, b in chunks if k == b"IDAT"))
        self.assertEqual(len(raw), h * (w + 1))
        rows = [raw[y * (w + 1):(y + 1) * (w + 1)] for y in range(h)]
        self.assertEqual({r[0] for r in rows}, {0})                        # filter 0 on every row, as palette_png
        rects = list(self.root.iter(NS + "rect"))
        p1, p2 = panels(self.root)
        self.assertEqual(len(rects), 1 + 2 + 1 + len(kids(p1, "g", "candidate")) + len(kids(p2, "g", "caller")) + 1)
        for r in rects:          # the background, the 2 panels, the call, each candidate, each caller, the callee
            x, y, rw, rh = (float(r.get(k)) for k in ("x", "y", "width", "height"))
            for px, py in ((x + rw - 6, y + 3), (x + rw - 6, y + rh - 3)):    # clear of the text, edges and corners
                self.assertEqual(palette[rows[int(py * 1.5)][1 + int(px * 1.5)]], r.get("fill"), (px, py))

    def test_readme_snippet(self):
        with open(DOC, encoding="utf-8") as fh:
            doc = fh.read()
        snippet = re.search(r"```markdown\n(.*?)```", doc, re.S).group(1)
        # README.md carries the snippet as it is here: under the status sentence, above the first section.
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as fh:
            readme = fh.read()
        self.assertIn(snippet.strip(), readme)
        at = readme.index(snippet.strip())
        self.assertLess(readme.index("has not been run in IDA yet"), at)
        self.assertLess(at, readme.index("\n## "))
        paths = re.findall(r'(?:src|href)="([^"]+)"|\]\(([^)#]+)\)', snippet)
        paths = [a or b for a, b in paths if "://" not in (a or b)]
        self.assertEqual(sorted(set(paths)), ["docs/img/README.md", "docs/img/hero.png", "docs/img/hero.svg"])
        for p in paths:
            self.assertTrue(os.path.exists(os.path.join(ROOT, p)), p)
        self.assertIn("not an IDA screenshot", snippet)
        p1, p2 = panels(self.root)
        site = dict(texts(kids(p1, "g", "site")[0]))
        n_cands, n_callers = len(kids(p1, "g", "candidate")), len(kids(p2, "g", "caller"))
        blue = [texts(c)[0][1] for c in kids(p1, "g", "candidate") if "also-caller" in cls(c)]
        self.assertIn("`%s` in `%s`" % (site["insn"], site["in"].partition("+")[0]), snippet)
        self.assertIn("the %d functions of that type" % n_cands, snippet)
        callee = texts(kids(p2, "g", "callee")[0])[0][1]
        self.assertIn("the %d indirect calls that may reach `%s` (same kCFI type" % (n_callers, callee), snippet)
        self.assertIn("In blue, %s:" % " and ".join("`%s`" % b for b in blue), snippet)
        # review s197: the groups and the callers' tags, in the caption and the alt text
        lone = [texts(c)[0][1] for c in kids(p1, "g", "candidate") if "type-only" in cls(c)]
        headers = [texts(g)[0][1] for g in kids(p1, "g", "group")]
        self.assertIn("the %d stored in a `%s` slot" % (n_cands - len(lone), site["hash"].split()[1]), snippet)
        self.assertIn("%s (same type only" % ", ".join("`%s`" % n for n in lone), snippet)
        # The alt text: every name, hash and type of the picture, and the counts (in words).
        alt = re.search(r'alt="([^"]+)"', snippet).group(1)
        self.assertIn("%d candidates: %s." % (n_cands, ", ".join(texts(c)[0][1] for c in kids(p1, "g", "candidate"))),
                      alt)
        self.assertIn("%s at %s, %s, type %s," % (site["insn"], site["in"], site["hash"], site["type"]), alt)
        callers = [dict(texts(c)) for c in kids(p2, "g", "caller")]
        at = ["%s (%s)" % (c["in"], c["hash"]) for c in callers]      # each call's member and hash
        self.assertIn("the %d indirect calls that may reach %s (same kCFI type), at %s and %s, each with type %s, %s;"
                      % (n_callers, callee, ", ".join(at[:-1]), at[-1], callers[0]["type"],
                         callers[0]["count"].replace("(s)", "s")), alt)
        for c in callers:     # "each with": the same type and count for every caller
            self.assertEqual((c["type"], c["count"]), (callers[0]["type"], callers[0]["count"]))
        for h in headers:     # the group headers and each caller's tag, as the picture writes them
            self.assertIn(h, alt)
        for c in callers:
            self.assertIn("%s for %s" % (c["slot"], c["in"]), alt)


FIXTURE = os.path.join(ROOT, "tests", "fixtures", "aarch64-kernel.o")
FIXTURE_ARGS = ["--site", "do_call_2+0x24", "--callee", "impl_2_0"]


_TOOL_MODULE = []


def tool_module():
    """tools/draw_hero.py as a module, loaded by its path (once)."""
    if not _TOOL_MODULE:
        spec = importlib.util.spec_from_file_location("draw_hero", TOOL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _TOOL_MODULE.append(module)
    return _TOOL_MODULE[0]


def png_file(path, depth):
    """A 2 x 2 white RGB PNG of the given bit depth (filter 0 rows)."""
    draw_hero = tool_module()
    row = b"\0" + b"\xff" * (2 * 3 * depth // 8)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n" + draw_hero._chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 2, depth, 2, 0, 0, 0))
                 + draw_hero._chunk(b"IDAT", zlib.compress(row * 2)) + draw_hero._chunk(b"IEND", b""))


class Tool(unittest.TestCase):
    """tools/draw_hero.py on the small aarch64 test fixture (no kernel needed): the caption and the messages."""

    def run_tool(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "x.svg")
            p = subprocess.run([sys.executable, "-I", TOOL, FIXTURE, "-o", out] + list(args), capture_output=True,
                               text=True)
            svg = None
            if os.path.exists(out):
                with open(out, "rb") as fh:
                    svg = fh.read()
        return p, svg

    def test_caption_names_the_input_file(self):
        p, svg = self.run_tool(*FIXTURE_ARGS)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual([t.text for t in kids(ET.fromstring(svg), "text")],
                         ["Drawn from python3 -m cfiscope aarch64-kernel.o output, not an IDA screenshot"])

    def test_member_is_written_as_the_command_line_writes_it(self):
        # the struct member (review s195, merge of mem194): 'call a_ops.send hash 0x...', as `--sites` prints it
        h = tool_module().hash_text
        self.assertEqual(h({"tail_call": False, "hash": "0x1"}), "call hash 0x1")
        self.assertEqual(h({"tail_call": True, "hash": "0x1", "members": ["a.f"]}), "jump a.f hash 0x1")
        four = {"tail_call": False, "hash": "0x1", "members": ["a.f", "b.g", "c.h", "d.i"]}
        self.assertEqual(h(four), "call one of 4 members (a.f, b.g, c.h, +1 more) hash 0x1")          # --callers
        self.assertEqual(h(four, None), "call one of 4 members (a.f, b.g, c.h, d.i) hash 0x1")        # --targets
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "x.svg")
            obj = os.path.join(ROOT, "tests", "fixtures", "kcfi_members_a64.o")
            p = subprocess.run([sys.executable, "-I", TOOL, obj, "-o", out, "--site", "call_a_send+0x2c", "--callee",
                                "send_x"],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            got = [t.text for t in ET.parse(out).getroot().iter(NS + "text") if "hash" in cls(t)]
        self.assertEqual(got[:2], ["call a_ops.send hash 0xfd39cd44", "call a_ops.send hash 0xfd39cd44"])
        self.assertIn("call b_ops.recv hash 0xfd39cd44", got)

    def test_bad_offset_is_a_message(self):
        p, svg = self.run_tool("--site", "do_call_2+zz", "--callee", "impl_2_0")
        self.assertEqual((p.returncode, p.stderr), (1, "draw_hero: do_call_2+zz: bad offset 'zz'\n"))
        self.assertIsNone(svg)

    def test_png_message_says_what_palette_png_did(self):
        """main() says '128 colours' only when palette_png rewrote the PNG; a 16-bit PNG is kept as rendered."""
        draw_hero = tool_module()
        for depth, said, ctype in ((8, "128 colours", 3), (16, "kept as rendered", 2)):
            with tempfile.TemporaryDirectory() as tmp:
                svg, png = os.path.join(tmp, "x.svg"), os.path.join(tmp, "x.png")
                out = io.StringIO()
                with mock.patch.object(draw_hero, "rasterise",
                                       lambda s, p, w, h, d=depth: png_file(p, d) or "a test converter"), \
                        contextlib.redirect_stdout(out):
                    self.assertEqual(draw_hero.main([FIXTURE, "-o", svg, "--png", png] + FIXTURE_ARGS), 0)
                self.assertIn("wrote %s with a test converter, %s" % (png, said), out.getvalue())
                self.assertNotIn("128 colours" if depth == 16 else "kept as rendered", out.getvalue())
                with open(png, "rb") as fh:
                    self.assertEqual(fh.read(26)[25], ctype)       # IHDR colour type: 3 = palette, 2 = RGB unchanged
                if depth == 8:      # main() passes its SVG: the tEXt chunk names x.svg and its sha256
                    with open(svg, "rb") as fh:
                        sha = hashlib.sha256(fh.read()).hexdigest()
                    self.assertEqual([b for k, b in png_chunks(png) if k == b"tEXt"],
                                     [b"Comment\0rasterised from x.svg, sha256 " + sha.encode()])


@unittest.skipUnless(ELF, "set CFISCOPE_GKI_ELF to the README walkthrough's gki.elf to check the picture against it")
class FreshRun(unittest.TestCase):
    """Every text but the headings and the caption equals a fresh `python3 -m cfiscope` run on gki.elf."""

    @classmethod
    def setUpClass(cls_):
        with open(ELF, "rb") as fh:
            data = fh.read()
        _arch, _ranges, symbols = cli.load_elf(data)
        names = cli.Names(symbols)
        base, _, off = SITE.partition("+")
        cls_.addr = "0x%x" % (names.by_name[base][0] + int(off, 16))
        cls_.targets = json.loads(run_cli("--targets", cls_.addr, "--json"))["sites"][0]
        cls_.callers = json.loads(run_cli("--callers", CALLEE, "--json"))
        cls_.targets_text = run_cli("--targets", cls_.addr).splitlines()
        cls_.callers_text = run_cli("--callers", CALLEE, "--max-list", "0").splitlines()
        cls_.insn = {s["call"]: decode(data, int(s["call"], 16)) for s in [cls_.targets] + cls_.callers["sites"]}
        del data, _ranges
        cls_.raw, cls_.root = load_svg()

    def check_call(self, group, s, line, member_limit=3):
        got = texts(group)
        ms = s.get("members") or []         # the struct member, as the text line writes it (--targets: all of them)
        shown = ms if member_limit is None else ms[:member_limit]
        more = ", +%d more" % (len(ms) - len(shown)) if len(ms) > len(shown) else ""
        member = ms[0] if len(ms) == 1 else "one of %d members (%s%s)" % (len(ms), ", ".join(shown), more) if ms else ""
        want = {"in": s["in"], "insn": self.insn[s["call"]], "call": s["call"],
                "hash": "%s %shash %s" % ("jump" if s["tail_call"] else "call", member + " " if member else "",
                                          s["hash"]),
                "type": s["type"], "count": "%d candidate(s)" % s["candidates"]}
        if member_limit is None:      # the first panel's count line: as the head line of --targets counts the groups
            k = s["slot_backed_candidates"] - s["slot_stride_candidates"]
            want["count"] += ", %d in a %s slot" % (k, ms[0]) if k else ""
            self.assertEqual(s["slot_stride_candidates"], 0)
        else:                         # a caller: the tag its --callers line ends with
            want["slot"] = re.search(r"  (\[[^\]]+\])$", line).group(1)
            kind = s["callee_slot_backed"]
            self.assertEqual(want["slot"], "[%s: %s]" % (CALLEE, "in a %s slot" % ms[0] if kind == "offset"
                                                         else "same type only"))
        self.assertEqual(got, [(k, want[k]) for k, _t in got])
        self.assertEqual(sorted(k for k, _t in got), sorted(want))
        # The pieces of the CLI's own text line for this site, as that line writes them.
        self.assertTrue(line.startswith(s["call"] + "  " + s["in"]), line)
        for k in ("hash", "count"):
            self.assertIn(want[k], line)
        self.assertIn("%s (%s)" % (want["hash"], want["type"]), line)

    def test_first_panel_is_the_call_and_every_candidate(self):
        p1, _ = panels(self.root)
        self.assertEqual(self.targets["in"], SITE)
        self.assertEqual(self.targets["call"], self.addr)
        self.assertEqual(self.insn[self.addr], "blr x8")
        self.assertEqual(self.targets_text[0], "candidates for the site at %s" % self.addr)
        self.check_call(kids(p1, "g", "site")[0], self.targets, self.targets_text[1], None)
        want = [t["name"] for t in self.targets["targets"]]
        self.assertEqual(len(want), self.targets["candidates"])
        self.assertEqual([texts(c) for c in kids(p1, "g", "candidate")], [[("name", n)] for n in want])
        # candidate lines (4 spaces), under 'in a ... slot:' and 'same type only:' when some are slot-backed
        self.assertEqual([ln.split() for ln in self.targets_text[2:] if ln.startswith("    ")],
                         [[t["ea"], t["name"]] for t in self.targets["targets"]])
        # the picture's group headers and candidates, in order, are those lines (review s197)
        self.assertEqual([t for g in kids(p1, "g") if cls(g)[0] in ("group", "candidate") for _k, t in texts(g)],
                         [ln.strip() if ln.startswith("  ") and not ln.startswith("    ") else ln.split()[1]
                          for ln in self.targets_text[2:]])
        self.assertEqual(["type-only" in cls(c) for c in kids(p1, "g", "candidate")],
                         [not t["slot_backed"] for t in self.targets["targets"]])
        caller_funcs = {s["in"].partition("+")[0] for s in self.callers["sites"]}
        self.assertEqual([texts(c)[0][1] for c in kids(p1, "g", "candidate") if "also-caller" in cls(c)],
                         [n for n in want if n in caller_funcs])

    def test_second_panel_is_every_call_that_may_reach_the_callee(self):
        _, p2 = panels(self.root)
        sites = self.callers["sites"]
        self.assertEqual(self.callers["callers"], {"call_sites": len(sites), "unlinked_checks": 0})
        self.assertEqual(self.callers_text[0], "%d call site(s) can reach %s" % (len(sites), CALLEE))
        groups = kids(p2, "g", "caller")
        self.assertEqual(len(groups), len(sites))
        for g, s, line in zip(groups, sites, self.callers_text[1:]):
            self.check_call(g, s, line)
            self.assertIn(CALLEE, [t["name"] for t in s["targets"]])
        self.assertEqual(texts(kids(p2, "g", "callee")[0]), [("name", CALLEE)])
        self.assertEqual(kids(p2, "text", "count")[0].text, "%d call site(s)" % self.callers["callers"]["call_sites"])

    def test_every_text_is_checked(self):
        p1, p2 = panels(self.root)
        checked = [t for g in kids(p1, "g") + kids(p2, "g") for t in g.iter(NS + "text")]
        rest = [t.text for t in self.root.iter(NS + "text") if t not in checked]
        own = list(HEADINGS) + [CAPTION]
        self.assertEqual(sorted(rest), sorted(own + ["%d call site(s)" % self.callers["callers"]["call_sites"]]))

    def test_redraw_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "hero.svg")
            subprocess.run([sys.executable, "-I", TOOL, ELF, "-o", out], capture_output=True, check=True)
            with open(out, "rb") as fh:
                self.assertEqual(fh.read(), self.raw, "docs/img/hero.svg is stale: redraw it (docs/img/README.md)")


if __name__ == "__main__":
    unittest.main()
