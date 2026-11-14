# docs/img

`hero.svg` and `hero.png` are the picture at the top of the README. `tools/draw_hero.py` draws them from `python3 -m cfiscope gki.elf` output on the public Android GKI android14-6.1 aarch64 kernel of the README walkthrough. They are not IDA screenshots: CFIScope has not been run inside real IDA yet.

## What the picture shows

- **Top panel, "Which functions may this indirect call reach?":** the kCFI-checked indirect call at `sock_sendmsg+0xb4` (orange box). The box holds its instruction, `blr x8`, its address and `call proto_ops.sendmsg hash 0x1ebda935`: the struct member the call loads its pointer from (unreleased, aarch64; see [VERIFICATION](../VERIFICATION.md#struct-members-aarch64)), then the hash. Under them are the C type the kernel's BTF gives that hash, `int (struct socket *, struct msghdr *, unsigned long)`, and the number of candidates. One arrow goes to each of the 14 candidates, in the order the command line lists them: the 13 stored in a `proto_ops.sendmsg` slot of the kernel's static data first, then `sock_no_sendmsg`, by address within each group (unreleased; see [VERIFICATION](../VERIFICATION.md#candidates-stored-in-a-matching-slot)).
- **Bottom panel, "Which indirect calls may reach this function (same kCFI type)?":** the 3 indirect calls that `--callers tcp_sendmsg` finds, converging on `tcp_sendmsg` (green). Each box holds the call's instruction, address, struct member and hash (`call proto_ops.sendmsg_locked hash 0x87bcba6f`, `call proto.sendmsg hash 0x87bcba6f`), candidate count and type: 11 candidates each, `tcp_sendmsg` one of them. They match `tcp_sendmsg` by its kCFI type, and for `kernel_sendmsg_locked+0x64` that is all: it is a type-only match. That call loads its pointer from offset 216, where BTF puts `proto_ops.sendmsg_locked` (a member with the call's hash), and a scan of `gki.elf`'s static data finds `tcp_sendmsg_locked`, and none of the call's other 10 candidates, stored at that offset of an object. `tcp_sendmsg` is stored in `proto.sendmsg` slots, the member that `inet_sendmsg+0x58` and `inet6_sendmsg+0x58` load (offset 104). CFIScope now does that scan itself (unreleased): `--targets` on that call lists `tcp_sendmsg_locked` under `in a proto_ops.sendmsg_locked slot:` and the other 10 under `same type only:`. The picture does not mark the groups.
- **Blue:** `inet_sendmsg` and `inet6_sendmsg` are candidates of the top call, and two of the bottom calls are inside them (`inet_sendmsg+0x58`, `inet6_sendmsg+0x58`). Read together: the call in `sock_sendmsg` may reach `inet_sendmsg`, and the indirect call in `inet_sendmsg` may reach `tcp_sendmsg`. Candidates are the functions of the call's type, which is what kCFI proves; that a given call reaches one at run time is not proved.
- **The tool's own words are only the two panel headings and the caption** (`HEADINGS` and `CAPTION` in `tools/draw_hero.py`; the caption names the input file, `gki.elf` here). Every other text is a field of the command line's `--json` output, written the way its text output writes it (`call proto_ops.sendmsg hash 0x1ebda935`, `14 candidate(s)`, `3 call site(s)`). The one exception is the instruction, which is decoded from the 4 bytes at the call's address.

## How they were made

1. **Input:** `gki.elf`, made as in the README walkthrough: `boot-6.1.img` from [gki-certified-boot-android14-6.1-2024-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip), then `tools/extract_bootimg.py` and vmlinux-to-elf.
   - sha256 of the zip: `68e7b6936161e1ad610cd152ec3eb90446d6b76fd46b64fc48e9b9d89e57d826`.
   - sha256 of the `gki.elf` used here: `c4e833c012157c59f9439fde75a53c785bcb3e8ee361d5c090eff52c4e981f49`.
2. **SVG:**

   ```
   python3 -I tools/draw_hero.py gki.elf -o docs/img/hero.svg
   ```

   - **What it runs:** the command line, twice, as subprocesses (isolated mode; `runpy` runs the package the way `python3 -m cfiscope` does):

     ```
     python3 -m cfiscope gki.elf --targets 0xffffffc008cc55ac --json    # the address of sock_sendmsg+0xb4, from gki.elf's symbols
     python3 -m cfiscope gki.elf --callers tcp_sendmsg --json
     ```

     `--site` and `--callee` choose another call or function.
   - **Format:** plain `<text>` in the generic `monospace` font (`sans-serif` for the headings and the caption). There are no fonts, scripts, styles, images or links. The same input gives the same bytes.
   - **Result:** 10,005 bytes, 974 x 896 (redrawn in review s195, when the command line began to print the struct member; 9,938 bytes, 904 x 896 before; redrawn 2026-11-14 for the slot order, same size).
3. **PNG:**
   - **Command:** `--png docs/img/hero.png` rasterises the SVG at 1.5 times its size. It uses `rsvg-convert` if that is on PATH, else Node with the `playwright` package (Chromium). Then `palette_png` stores the PNG with a 256-colour palette: the 256 most frequent colours, the anti-aliased edges mapped to the nearest of them. A `tEXt` chunk (`Comment`) names the SVG and its sha256: `rasterised from hero.svg, sha256 ...`.
   - **Here:** there is no `rsvg-convert` (so that path was never tried), and it was Playwright's Chromium headless shell (`chromium_headless_shell-1155`). The system's monospace font is DejaVu Sans Mono. The Python runs here had a virtual-memory limit (`ulimit -v`) under which Chromium does not start, so the three steps that `--png` runs were run one by one: `draw_hero.py` for the SVG, then `node -e` with `draw_hero.PNG_JS` (the headless shell found its shared libraries, such as `libnss3.so`, through `LD_LIBRARY_PATH` in a user-level folder), then `draw_hero.palette_png(png, svg)`.
   - **Result:** 1461 x 1344 px, 96,131 bytes (Chromium's own PNG was 272,488 bytes; redrawn the same way in review s195 and again for the slot order, 2026-11-14: `node -e` run with `LD_LIBRARY_PATH` and `NODE_PATH` set, outside the memory limit).

To redraw after a change to the scanner or to its output: run step 2, then step 3, then `tests/test_draw_hero.py` with the kernel (below).

## Checked by `tests/test_draw_hero.py`

- **Without the kernel** (part of the normal test run):
  - **Safe SVG:** it parses with `xml.etree`. It has only `svg`, `g`, `rect`, `text`, `path` and `polygon` elements, generic fonts only, and no event attribute, `href`, `url(`, `@import`, DOCTYPE, entity or base64.
  - **Size:** the SVG and the PNG are each under 100 KB. The PNG is the SVG's size times 1.5.
  - **The PNG is this SVG** (the README shows the PNG): its `tEXt` chunk carries the sha256 of `hero.svg`, so a PNG left over from an older SVG fails. At two points inside each of the SVG's 22 rectangles (times 1.5), the PNG's pixel has the rectangle's fill colour, so a blank or wrong PNG fails.
  - **The tool's own words, typed again in the test:** the headings, exactly `Which functions may this indirect call reach?` (top) and `Which indirect calls may reach this function (same kCFI type)?` (bottom), each at the top of its panel. The caption, exactly `Drawn from python3 -m cfiscope gki.elf output, not an IDA screenshot`, under both panels. No other text sits outside the boxes, apart from the bottom panel's `3 call site(s)`.
  - **The drawing:**
    - One arrow per candidate, from the right edge of the call's box to the left edge of the candidate's box. One arrow per caller, to the `tcp_sendmsg` box.
    - The counts equal the number of boxes.
    - Blue marks exactly the candidates whose name is the function of a bottom call, the arrows to them, and the names of those calls.
    - Each text fits inside its box at 0.62 em per character.
  - **The snippet below:** its three paths exist, its names, members, hashes, types and counts are the picture's, and README.md carries it unchanged, under the status sentence and above the first section.
  - **The tool on the small aarch64 test fixture** (`tests/fixtures/aarch64-kernel.o`): the caption names that file; `--site do_call_2+zz` stops with `draw_hero: do_call_2+zz: bad offset 'zz'` and no traceback; and the PNG message says `256 colours` only when `palette_png` rewrote the PNG (then with the `tEXt` chunk), `kept as rendered` for a 16-bit one.
  - **The struct member** (review s195): `hash_text` writes `call a.f hash ...` and `one of N members (...)` as the command line does, and on `tests/fixtures/kcfi_members_a64.o` the boxes read `call a_ops.send hash 0xfd39cd44`.
- **With `CFISCOPE_GKI_ELF=path/to/gki.elf`:**
  - **A fresh run of both commands**, in `--json` and in text:
    - Each text in each box equals its field: function+offset, address, member and hash, type and count.
    - The candidates, in order, equal the `--targets` list (its names and addresses in the text output too). The callers, in order, equal the `--callers` list, and `3 call site(s)` matches its header.
    - The member and hash, type and count pieces appear in the command line's text line for that call.
  - **The instruction:** the test decodes it again from `gki.elf`'s bytes, independently of the tool: `blr x8`.
  - **Every text is accounted for:** it is checked against the command line, or it is a heading or the caption.
  - **Redraw:** `tools/draw_hero.py` gives `hero.svg` byte for byte.
  - **Command:** `CFISCOPE_GKI_ELF=~/gki.elf python3 -m unittest discover -s tests -p test_draw_hero.py`. It runs the command line 6 times on the 39 MB kernel, about 15 s.

## README snippet

README.md carries it, right after the paragraph that ends `the IDA layer has not been run in IDA yet (see [Status](#status)).` and before `## Without CFIScope`, so the status sentence stays above the picture. The test checks the snippet against the picture, and that README.md carries it there unchanged.

```markdown
<a href="docs/img/hero.svg"><img src="docs/img/hero.png" width="900" alt="Diagram drawn from python3 -m cfiscope output on the GKI android14-6.1 kernel, not an IDA screenshot. Top: the indirect call blr x8 at sock_sendmsg+0xb4, call proto_ops.sendmsg hash 0x1ebda935, type int (struct socket *, struct msghdr *, unsigned long), with arrows to its 14 candidates: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg, sock_no_sendmsg. The first 13 are stored in a proto_ops.sendmsg slot of the kernel's static data. Bottom: the 3 indirect calls that may reach tcp_sendmsg (same kCFI type), at kernel_sendmsg_locked+0x64 (call proto_ops.sendmsg_locked hash 0x87bcba6f), inet_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f) and inet6_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f), each with type int (struct sock *, struct msghdr *, unsigned long), 11 candidates; kernel_sendmsg_locked+0x64 is a type-only match (it calls proto_ops.sendmsg_locked)."></a>

<sub>Drawn by `tools/draw_hero.py` from `python3 -m cfiscope gki.elf` output on the public GKI android14-6.1 kernel of [Try it](#try-it); not an IDA screenshot. Top: the kCFI-checked `blr x8` in `sock_sendmsg`, the struct member it loads its pointer from (`proto_ops.sendmsg`), its C type from the kernel's BTF, and the 14 functions of that type it may reach, the 13 stored in a `proto_ops.sendmsg` slot of the kernel's static data first (`sock_no_sendmsg` is stored in none). Bottom: the 3 indirect calls that may reach `tcp_sendmsg` (same kCFI type; `kernel_sendmsg_locked+0x64` is a type-only match: it calls `proto_ops.sendmsg_locked`). In blue, `inet_sendmsg` and `inet6_sendmsg`: candidates of the top call that hold two of the bottom calls. How it is made and checked: [docs/img](docs/img/README.md).</sub>
```
