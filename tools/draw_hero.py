#!/usr/bin/env python3
"""Draw docs/img/hero.svg from the command line's output on a kCFI kernel. Not an IDA screenshot: no IDA runs here.

    python3 -I tools/draw_hero.py gki.elf [-o docs/img/hero.svg] [--png docs/img/hero.png]
                                  [--site sock_sendmsg+0xb4] [--callee tcp_sendmsg]

It runs the command-line tool twice, as `python3 -m cfiscope` does (a subprocess, in isolated mode):

    python3 -m cfiscope gki.elf --targets <address of --site> --json
    python3 -m cfiscope gki.elf --callers <--callee> --json

and draws two panels: the indirect call at --site, with its kCFI hash and C type, fanning out to every candidate;
and every indirect call that may reach --callee (a call of its kCFI type), converging on it.  Every name, address,
hash, type and count in the picture is a field of that output, written as the text output writes it ("call hash
0x1ebda935", "14 candidate(s)", "3 call site(s)").  The instruction (`blr x8`) is decoded from the 4 bytes at the
call's address (aarch64 blr and br only).  The tool's own words are the two headings and the caption (HEADINGS,
CAPTION; the caption names the input file).  A candidate is drawn blue when a call of the second panel is inside it,
and that call's function name is blue too.

Plain Python, standard library only.  The SVG uses the generic monospace and sans-serif fonts and has no external
font, script, style sheet, image or link.  The same input gives the same bytes.  tests/test_draw_hero.py checks the
picture against a fresh run of the command line (with CFISCOPE_GKI_ELF=path/to/gki.elf).

--png OUT also rasterises the SVG at 1.5 times its size: with rsvg-convert if it is on PATH, else with Node and the
`playwright` package (Chromium; found through NODE_PATH), then stores it with a 256-colour palette (palette_png)
to stay under 100 KB, with the SVG's name and sha256 in a tEXt chunk.  Without either converter it says so and writes
the SVG only.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import shutil
import struct
import subprocess
import sys
import zlib
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from cfiscope import cli  # noqa: E402  (the ELF reader only: the address of --site and the call instructions)

HEADINGS = ("Which functions may this indirect call reach?",
            "Which indirect calls may reach this function (same kCFI type)?")
CAPTION = "Drawn from python3 -m cfiscope %s output, not an IDA screenshot"     # %s: the input file's name
MAX_CANDIDATES, MAX_CALLERS = 16, 6
SCALE = 1.5

# Runs the package as `python3 -m cfiscope` does, isolated (-I: no user site, no PYTHONPATH, no current directory).
RUNNER = ("import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); "
          "runpy.run_module('cfiscope', run_name='__main__', alter_sys=True)")

# Colours: call sites orange, candidate functions white (blue: holds a call of the second panel), the callee green.
INK, GREY, TYPE_INK, INSN_INK, BLUE_INK = "#1f2328", "#59636e", "#6639ba", "#9a4b00", "#0b4fc4"
CALL_BOX = ("#fff4e5", "#d4761c")
FUNC_BOX = ("#ffffff", "#8c959f")
BLUE_BOX = ("#e6efff", "#2f6fdd")
CALLEE_BOX = ("#e9f7ec", "#2e8b57")
PANEL_BOX = ("#f6f8fa", "#d0d7de")
EDGE, BLUE_EDGE = "#8c959f", "#2f6fdd"

FS, FS_NAME, FS_HEAD, FS_CAPTION = 13, 14, 17, 13
CHAR = 0.62          # assumed advance of a monospace glyph, in em (DejaVu Sans Mono: 0.602; a little slack for others)
LINE = 19
PAD, INNER, GAP = 24, 16, 150


def run_cli(elf, *args):
    p = subprocess.run([sys.executable, "-I", "-c", RUNNER, ROOT, elf] + list(args), capture_output=True, text=True)
    if p.returncode:
        raise SystemExit("draw_hero: python3 -m cfiscope %s %s failed (rc %d): %s"
                         % (elf, " ".join(args), p.returncode, p.stderr.strip()))
    return json.loads(p.stdout)


def load(elf):
    with open(elf, "rb") as fh:
        data = fh.read()
    arch, ranges, symbols = cli.load_elf(data)
    return arch, ranges, cli.Names(symbols)


def address(text, names):
    """An address, or function+offset by the ELF's symbols."""
    try:
        return int(text, 0)
    except ValueError:
        pass
    base, plus, off = text.partition("+")
    eas = names.by_name.get(base)
    if not eas or len(eas) > 1:
        raise SystemExit("draw_hero: %s: %s functions named %r; give an address" % (text, len(eas or ()), base))
    try:
        return eas[0] + (int(off, 0) if plus else 0)
    except ValueError:
        raise SystemExit("draw_hero: %s: bad offset %r" % (text, off)) from None


def instruction(arch, ranges, ea):
    """'blr x8' or 'br x16' for the aarch64 instruction at ea; None for anything else."""
    if arch != "aarch64":
        return None
    for base, mem in ranges:
        if base <= ea and ea + 4 <= base + len(mem):
            w = struct.unpack_from("<I", mem, ea - base)[0]
            for op, word in (("blr", 0xd63f0000), ("br", 0xd61f0000)):
                if w & 0xfffffc1f == word:
                    return "%s x%d" % (op, (w >> 5) & 31)
    return None


def hash_text(s):
    return "%s hash %s" % ("jump" if s["tail_call"] else "call", s["hash"])


def count_text(n, what="candidate(s)"):
    return "%d %s" % (n, what)


def width(text, size):
    return len(text) * size * CHAR


def num(v):
    v = round(v, 1)
    return "%d" % v if v == int(v) else "%.1f" % v


class Svg:
    def __init__(self):
        self.out = []

    def add(self, line):
        self.out.append(line)

    def rect(self, x, y, w, h, colours, rx=5, extra=""):
        self.add('<rect x="%s" y="%s" width="%s" height="%s" rx="%d" fill="%s" stroke="%s"%s/>'
                 % (num(x), num(y), num(w), num(h), rx, colours[0], colours[1], extra))

    def text(self, cls, x, y, s, size=FS, fill=INK, bold=False, family=None):
        self.add('<text class="%s" x="%s" y="%s" font-size="%d" fill="%s"%s%s>%s</text>'
                 % (cls, num(x), num(y), size, fill, ' font-weight="bold"' if bold else "",
                    ' font-family="%s"' % family if family else "", escape(s)))

    def edge(self, x0, y0, x1, y1, colour, sw):
        """A curve from (x0, y0) to an arrowhead whose tip is at (x1, y1)."""
        mid = (x0 + x1) / 2
        self.add('<g class="edge"><path d="M%s %s C%s %s %s %s %s %s" fill="none" stroke="%s" stroke-width="%s"/>'
                 '<polygon points="%s,%s %s,%s %s,%s" fill="%s"/></g>'
                 % (num(x0), num(y0), num(mid), num(y0), num(mid), num(y1), num(x1 - 7), num(y1), colour, num(sw),
                    num(x1 - 8), num(y1 - 4.5), num(x1), num(y1), num(x1 - 8), num(y1 + 4.5), colour))


def call_lines(s, insn, with_count_line):
    """The rows of a call-site box: [(class, text, size, colour, bold), ...] per line."""
    first = [("in", s["in"], FS_NAME, INK, True)]
    if insn:
        first.append(("insn", insn, FS, INSN_INK, False))
    rows = [first, [("call", s["call"], FS, GREY, False)]]
    if with_count_line:
        rows.append([("hash", hash_text(s), FS, INK, False)])
    else:
        rows.append([("hash", hash_text(s), FS, INK, False), ("count", count_text(s["candidates"]), FS, INK, False)])
    if s.get("type"):
        rows.append([("type", s["type"], FS, TYPE_INK, False)])
    if with_count_line:
        rows.append([("count", count_text(s["candidates"]), FS, INK, False)])
    return rows


def row_width(row):
    return sum(width(t, size) for _c, t, size, _f, _b in row) + 14 * (len(row) - 1)


def box_size(rows):
    return math.ceil(24 + max(row_width(r) for r in rows)), 14 + LINE * len(rows)


def draw_call(g, cls, x, y, rows, w, h, blue_name=False):
    g.add('<g class="%s">' % cls)
    g.rect(x, y, w, h, CALL_BOX)
    for i, row in enumerate(rows):
        tx, ty = x + 12, y + 7 + LINE * i + 14
        for c, t, size, fill, bold in row:
            if c == "in" and blue_name:
                fill = BLUE_INK
            g.text(c, tx, ty, t, size, fill, bold)
            tx += width(t, size) + 14
    g.add("</g>")


def draw(site, callers_doc, callee, insns, source="gki.elf"):
    """The SVG text, from the --targets site, the --callers document and the instruction of each call; source is the
    input file's name, for the caption."""
    callers = callers_doc["sites"]
    cands = [t["name"] for t in site["targets"]]
    caller_funcs = {c["in"].partition("+")[0] for c in callers}
    blue = [n in caller_funcs for n in cands]

    srows = call_lines(site, insns.get(site["call"]), True)
    sw, sh = box_size(srows)
    crows = [call_lines(c, insns.get(c["call"]), False) for c in callers]
    cw = max(box_size(r)[0] for r in crows)
    ch = max(box_size(r)[1] for r in crows)
    left = max(sw, cw)
    col_x = PAD + INNER + left + GAP
    cand_w = math.ceil(20 + max(width(n, FS) for n in cands))
    callee_w = math.ceil(24 + width(callee, FS_NAME + 1))
    panel_w = math.ceil(INNER + left + GAP + INNER +
                        max(cand_w, callee_w, width(count_text(len(callers), "call site(s)"), FS)))
    head_w = math.ceil(max(len(h) for h in HEADINGS) * FS_HEAD * 0.62 + 2 * INNER)   # sans-serif bold: under 0.62 em
    panel_w = max(panel_w, head_w)
    panel_w += panel_w % 2             # even sizes: the PNG at 1.5 times is a whole number of pixels
    W = PAD + panel_w + PAD

    g = Svg()
    # Panel 1: the call and its candidates.
    p1y = PAD
    top = p1y + 50
    col_h = len(cands) * 28 - 4
    body = max(col_h, sh)
    mid = top + body / 2
    p1h = 50 + body + INNER
    # Panel 2: the callers and the callee.
    p2y = p1y + p1h + 20
    top2 = p2y + 50
    pitch = ch + 14
    body2 = len(callers) * pitch - 14
    p2h = 50 + body2 + INNER
    H = p2y + p2h + 34
    H += H % 2

    g.add('<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s" '
          'font-family="monospace" font-size="%d">' % (num(W), num(H), num(W), num(H), FS))
    g.add('<rect x="0" y="0" width="%s" height="%s" fill="#ffffff"/>' % (num(W), num(H)))

    g.add('<g id="targets">')
    g.rect(PAD, p1y, panel_w, p1h, PANEL_BOX, rx=8)
    g.text("heading", PAD + INNER, p1y + 30, HEADINGS[0], FS_HEAD, INK, True, "sans-serif")
    sx, sy = PAD + INNER, mid - sh / 2
    ys = [top + body / 2 - col_h / 2 + 28 * i for i in range(len(cands))]
    for i, yi in enumerate(ys):
        g.edge(sx + sw, mid, col_x, yi + 12, BLUE_EDGE if blue[i] else EDGE, 1.6 if blue[i] else 1.1)
    draw_call(g, "site", sx, sy, srows, sw, sh)
    for n, yi, b in zip(cands, ys, blue):
        g.add('<g class="candidate%s">' % (" also-caller" if b else ""))
        g.rect(col_x, yi, cand_w, 24, BLUE_BOX if b else FUNC_BOX, rx=4)
        g.text("name", col_x + 10, yi + 16.5, n, FS, BLUE_INK if b else INK, b)
        g.add("</g>")
    g.add("</g>")

    g.add('<g id="callers">')
    g.rect(PAD, p2y, panel_w, p2h, PANEL_BOX, rx=8)
    g.text("heading", PAD + INNER, p2y + 30, HEADINGS[1], FS_HEAD, INK, True, "sans-serif")
    ty = top2 + body2 / 2
    tcy = ty - 16
    for i in range(len(callers)):
        cy = top2 + pitch * i + ch / 2
        spread = (i - (len(callers) - 1) / 2) * 7
        g.edge(PAD + INNER + cw, cy, col_x, ty + spread, EDGE, 1.3)
    for i, (c, rows) in enumerate(zip(callers, crows)):
        draw_call(g, "caller", PAD + INNER, top2 + pitch * i, rows, cw, ch, c["in"].partition("+")[0] in cands)
    g.add('<g class="callee">')
    g.rect(col_x, tcy, callee_w, 32, CALLEE_BOX, rx=5)
    g.text("name", col_x + 12, tcy + 21, callee, FS_NAME + 1, INK, True)
    g.add("</g>")
    g.text("count", col_x, tcy + 32 + 20, count_text(callers_doc["callers"]["call_sites"], "call site(s)"), FS, GREY)
    g.add("</g>")

    g.text("caption", PAD, H - 14, CAPTION % source, FS_CAPTION, GREY, False, "sans-serif")
    g.add("</svg>")
    return "\n".join(g.out) + "\n", (W, H)


# Node + playwright (Chromium): node -e PNG_JS in.svg out.png width height scale; exit 3 if playwright is missing.
PNG_JS = ("let pw; try { pw = require('playwright'); } catch (e) { process.exit(3); }"
          "const fs = require('fs'); const [inp, out, w, h, s] = process.argv.slice(1);"
          "(async () => { const b = await pw.chromium.launch();"
          " const pg = await b.newPage({ viewport: { width: +w, height: +h }, deviceScaleFactor: +s });"
          " await pg.setContent('<html><body style=\"margin:0;background:#fff\">' + fs.readFileSync(inp, 'utf8')"
          " + '</body></html>');"
          " await pg.screenshot({ path: out, clip: { x: 0, y: 0, width: +w, height: +h } }); await b.close(); })()"
          ".catch(e => { console.error(e.message); process.exit(1); });")


def rasterise(svg_path, png_path, w, h):
    """PNG at SCALE times the SVG's size; returns the converter's name, or None if there is none."""
    if shutil.which("rsvg-convert"):
        subprocess.run(["rsvg-convert", "-z", str(SCALE), "-b", "#ffffff", "-o", png_path, svg_path], check=True)
        return "rsvg-convert"
    if not shutil.which("node"):
        return None
    p = subprocess.run(["node", "-e", PNG_JS, svg_path, png_path, num(w), num(h), str(SCALE)])
    if p.returncode == 3:
        return None
    if p.returncode:
        raise SystemExit("draw_hero: rasterising with Node and playwright failed (rc %d)" % p.returncode)
    return "playwright (Chromium)"


def _chunk(kind, body):
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xffffffff)


def source_text(svg_path):
    """The tEXt chunk's text that ties the PNG to the SVG it was rasterised from (tests/test_draw_hero.py checks it)."""
    with open(svg_path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return b"Comment\0rasterised from %s, sha256 %s" % (os.path.basename(svg_path).encode("latin-1"), digest.encode())


def palette_png(path, svg_path=None):
    """Rewrite an 8-bit RGB or RGBA PNG as a 256-colour palette PNG (alpha dropped: the picture is opaque): the 256
    most frequent colours, every other colour mapped to the nearest of them (anti-aliased text edges).  About a third
    of Chromium's size; the same input gives the same bytes.  With svg_path, a tEXt chunk names the SVG and its
    sha256 (source_text), so a test can tell a PNG left over from an older SVG.  False (file unchanged) for any other
    PNG."""
    with open(path, "rb") as fh:
        d = fh.read()
    pos, idat, ihdr = 8, [], None
    while pos < len(d):
        n, kind = struct.unpack_from(">I4s", d, pos)
        if kind == b"IHDR":
            ihdr = struct.unpack_from(">IIBBBBB", d, pos + 8)
        elif kind == b"IDAT":
            idat.append(d[pos + 8:pos + 8 + n])
        pos += 12 + n
    w, h, depth, ctype, _c, _f, interlace = ihdr
    if depth != 8 or ctype not in (2, 6) or interlace:
        return False
    bpp = 3 if ctype == 2 else 4
    raw, stride = zlib.decompress(b"".join(idat)), w * bpp
    prev, pixels = bytearray(stride), []
    for y in range(h):
        f, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + prev[i]) & 255
            elif f == 3:
                line[i] = (line[i] + (a + prev[i]) // 2) & 255
            elif f == 4:
                b, c = prev[i], prev[i - bpp] if i >= bpp else 0
                pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        pixels.append([bytes(line[i:i + 3]) for i in range(0, stride, bpp)])
        prev = line
    palette = [c for c, _n in collections.Counter(p for row in pixels for p in row).most_common(256)]
    index = {c: i for i, c in enumerate(palette)}

    def nearest(c):
        if c not in index:
            index[c] = min(range(len(palette)), key=lambda i: sum((x - y) ** 2 for x, y in zip(c, palette[i])))
        return index[c]
    data = b"".join(b"\0" + bytes(nearest(c) for c in row) for row in pixels)
    with open(path, "wb") as fh:
        fh.write(b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 3, 0, 0, 0))
                 + _chunk(b"PLTE", b"".join(palette)) + (_chunk(b"tEXt", source_text(svg_path)) if svg_path else b"")
                 + _chunk(b"IDAT", zlib.compress(data, 9)) + _chunk(b"IEND", b""))
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(prog="tools/draw_hero.py", description=__doc__.split("\n")[0])
    ap.add_argument("elf", help="a kCFI kernel ELF with symbols, e.g. gki.elf from the README walkthrough")
    ap.add_argument("-o", "--output", default=os.path.join(ROOT, "docs", "img", "hero.svg"))
    ap.add_argument("--png", metavar="OUT", help="also write a PNG (rsvg-convert, or Node + playwright)")
    ap.add_argument("--site", default="sock_sendmsg+0xb4",
                    help="the call of the first panel (function+offset or address)")
    ap.add_argument("--callee", default="tcp_sendmsg", help="the function of the second panel")
    a = ap.parse_args(argv)

    arch, ranges, names = load(a.elf)
    ea = address(a.site, names)
    targets = run_cli(a.elf, "--targets", "0x%x" % ea, "--json")
    sites = [s for s in targets["sites"] if s["call"] == "0x%x" % ea]
    if len(sites) != 1:
        raise SystemExit("draw_hero: %s (0x%x) is not a kCFI call site" % (a.site, ea))
    site = sites[0]
    callers = run_cli(a.elf, "--callers", a.callee, "--json")
    if callers["callers"]["unlinked_checks"] or not callers["sites"]:
        raise SystemExit("draw_hero: --callers %s: %d call sites and %d unlinked checks; this draws call sites only"
                         % (a.callee, callers["callers"]["call_sites"], callers["callers"]["unlinked_checks"]))
    if not 0 < site["candidates"] <= MAX_CANDIDATES or len(site["targets"]) != site["candidates"]:
        raise SystemExit("draw_hero: %s has %d candidates; the picture draws 1 to %d"
                         % (a.site, site["candidates"], MAX_CANDIDATES))
    if len(callers["sites"]) > MAX_CALLERS:
        raise SystemExit("draw_hero: %d calls reach %s; the picture draws at most %d"
                         % (len(callers["sites"]), a.callee, MAX_CALLERS))
    insns = {s["call"]: instruction(arch, ranges, int(s["call"], 16)) for s in [site] + callers["sites"]}
    del ranges
    svg, (w, h) = draw(site, callers, a.callee, insns, os.path.basename(a.elf))
    with open(a.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(svg)
    print("wrote %s: %d bytes, %s x %s" % (a.output, len(svg.encode()), num(w), num(h)))
    if a.png:
        how = rasterise(a.output, a.png, w, h)
        if how is None:
            print("no PNG: neither rsvg-convert nor Node with the playwright package was found", file=sys.stderr)
        elif palette_png(a.png, a.output):
            print("wrote %s with %s, 256 colours: %d bytes" % (a.png, how, os.path.getsize(a.png)))
        else:
            print("wrote %s with %s, kept as rendered (not an 8-bit non-interlaced RGB or RGBA PNG): %d bytes"
                  % (a.png, how, os.path.getsize(a.png)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
