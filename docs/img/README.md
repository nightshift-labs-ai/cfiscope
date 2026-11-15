# docs/img

`hero.svg` and `hero.png` are the picture at the top of the README. `tools/draw_hero.py` draws them from `python3 -m cfiscope gki.elf` output on the public Android GKI android14-6.1 aarch64 kernel of the README walkthrough. They are not IDA screenshots: CFIScope has not been run inside real IDA yet.

## What the picture shows

- **Top panel, "Which functions may this indirect call reach?":** the kCFI-checked indirect call at `sock_sendmsg+0xb4` (orange box). The box holds its instruction, `blr x8`, its address and `call proto_ops.sendmsg hash 0x1ebda935`: the struct member the call loads its pointer from (new in 0.1.23, aarch64; see [VERIFICATION](../VERIFICATION.md#struct-members-aarch64)), then the hash. Under them are the C type the kernel's BTF gives that hash, `int (struct socket *, struct msghdr *, unsigned long)`, and the count line of `--targets`, `14 candidate(s), 13 in a proto_ops.sendmsg slot`. One arrow goes to each of the 14 candidates, in the order and under the group headers that `--targets` prints (new in 0.1.23; see [VERIFICATION](../VERIFICATION.md#candidates-stored-in-a-matching-slot)): under `in a proto_ops.sendmsg slot:` the 13 stored at that member's offset in an object of the kernel's static data, then under `same type only:` `sock_no_sendmsg`, which is stored in no object of this image (module tables use it), drawn grey with a dashed box and a dashed arrow. Within each group they are in address order.
- **Bottom panel, "Which indirect calls may reach this function (same kCFI type)?":** the 3 indirect calls that `--callers tcp_sendmsg` finds, converging on `tcp_sendmsg` (green), in its order: the calls whose member slot holds `tcp_sendmsg` first (new in 0.1.23). Each box holds the call's instruction, address, struct member and hash (`call proto.sendmsg hash 0x87bcba6f`, `call proto_ops.sendmsg_locked hash 0x87bcba6f`), candidate count and type: 11 candidates each, `tcp_sendmsg` one of them. Its last line is the tag the `--callers` line ends with. `inet_sendmsg+0x58` and `inet6_sendmsg+0x58` load `proto.sendmsg` (offset 104), and `tcp_sendmsg` is stored at byte 104 of `tcp_prot` and `tcpv6_prot`: `[tcp_sendmsg: in a proto.sendmsg slot]`, in green. `kernel_sendmsg_locked+0x64` matches `tcp_sendmsg` by its kCFI type only: it loads offset 216, where BTF puts `proto_ops.sendmsg_locked`, and of its 11 candidates only `tcp_sendmsg_locked` is stored at that offset of an object. Its tag is `[tcp_sendmsg: same type only]`, in grey, and its arrow is dashed.
- **Blue:** `inet_sendmsg` and `inet6_sendmsg` are candidates of the top call, and two of the bottom calls are inside them (`inet_sendmsg+0x58`, `inet6_sendmsg+0x58`). Read together: the call in `sock_sendmsg` may reach `inet_sendmsg`, and the indirect call in `inet_sendmsg` may reach `tcp_sendmsg`. Candidates are the functions of the call's type, which is what kCFI proves; that a given call reaches one at run time is not proved.
- **The tool's own words are only the two panel headings and the caption** (`HEADINGS` and `CAPTION` in `tools/draw_hero.py`; the caption names the input file, `gki.elf` here). Every other text is a field of the command line's `--json` output, written the way its text output writes it (`call proto_ops.sendmsg hash 0x1ebda935`, `14 candidate(s), 13 in a proto_ops.sendmsg slot`, the group headers `in a proto_ops.sendmsg slot:` and `same type only:`, the tag `[tcp_sendmsg: same type only]`, `3 call site(s)`). The one exception is the instruction, which is decoded from the 4 bytes at the call's address.

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
   - **Result:** 10,726 bytes, 978 x 998 (redrawn in review s197, 2026-11-14, with the slot groups and the callers' tags; 10,005 bytes, 974 x 896 before, from review s195, when the command line began to print the struct member; 9,938 bytes, 904 x 896 before that).
3. **PNG:**
   - **Command:** `--png docs/img/hero.png` rasterises the SVG at 1.5 times its size. It uses `rsvg-convert` if that is on PATH, else Node with the `playwright` package (Chromium). Then `palette_png` stores the PNG with a 128-colour palette: the 128 most frequent colours, the anti-aliased edges mapped to the nearest of them (256 until review s197; with the slot groups drawn, 256 colours gave 105,587 bytes, over the 100 KB the test allows, and 128 gave 92,643). A `tEXt` chunk (`Comment`) names the SVG and its sha256: `rasterised from hero.svg, sha256 ...`.
   - **Here:** there is no `rsvg-convert` (so that path was never tried), and it was Playwright's Chromium headless shell (`chromium_headless_shell-1155`). The system's monospace font is DejaVu Sans Mono. The Python runs here had a virtual-memory limit (`ulimit -v`) under which Chromium does not start, so the three steps that `--png` runs were run one by one: `draw_hero.py` for the SVG, then `node -e` with `draw_hero.PNG_JS` (the headless shell found its shared libraries, such as `libnss3.so`, through `LD_LIBRARY_PATH` in a user-level folder), then `draw_hero.palette_png(png, svg)`.
   - **Result:** 1467 x 1497 px, 92,643 bytes (Chromium's own PNG was 302,563 bytes; redrawn the same way in review s197, 2026-11-14: `node -e` run with `LD_LIBRARY_PATH` and `NODE_PATH` set, outside the memory limit).

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
    - The slot groups (review s197): a group header stands right above the first candidate of its group; the candidates under `same type only:` are grey, with a dashed box and arrow; a bottom call whose tag ends `same type only]` has a dashed arrow.
    - Each text fits inside its box at 0.62 em per character.
  - **The snippet below:** its three paths exist, its names, members, hashes, types and counts are the picture's, and README.md carries it unchanged, under the status sentence and above the first section.
  - **The tool on the small aarch64 test fixture** (`tests/fixtures/aarch64-kernel.o`): the caption names that file; `--site do_call_2+zz` stops with `draw_hero: do_call_2+zz: bad offset 'zz'` and no traceback; and the PNG message says `128 colours` only when `palette_png` rewrote the PNG (then with the `tEXt` chunk), `kept as rendered` for a 16-bit one.
  - **The struct member** (review s195): `hash_text` writes `call a.f hash ...` and `one of N members (...)` as the command line does, and on `tests/fixtures/kcfi_members_a64.o` the boxes read `call a_ops.send hash 0xfd39cd44`.
- **With `CFISCOPE_GKI_ELF=path/to/gki.elf`:**
  - **A fresh run of both commands**, in `--json` and in text:
    - Each text in each box equals its field: function+offset, address, member and hash, type and count.
    - The candidates, in order, equal the `--targets` list (its names and addresses in the text output too), and the group headers and candidates, in order, equal its group header and candidate lines; the grey ones are those whose `slot_backed` is false. The callers, in order, equal the `--callers` list, `3 call site(s)` matches its header, and each caller's tag is the end of its `--callers` line and agrees with `callee_slot_backed`.
    - The member and hash, type and count pieces appear in the command line's text line for that call.
  - **The instruction:** the test decodes it again from `gki.elf`'s bytes, independently of the tool: `blr x8`.
  - **Every text is accounted for:** it is checked against the command line, or it is a heading or the caption.
  - **Redraw:** `tools/draw_hero.py` gives `hero.svg` byte for byte.
  - **Command:** `CFISCOPE_GKI_ELF=~/gki.elf python3 -m unittest discover -s tests -p test_draw_hero.py`. It runs the command line 6 times on the 39 MB kernel: 19.8 and 21.1 s in two runs here (review s197).

## README snippet

README.md carries it, right after the paragraph that ends `the IDA layer has not been run in IDA yet (see [Status](#status)).` and before `## Without CFIScope`, so the status sentence stays above the picture. The test checks the snippet against the picture, and that README.md carries it there unchanged.

```markdown
<a href="docs/img/hero.svg"><img src="docs/img/hero.png" width="900" alt="Diagram drawn from python3 -m cfiscope output on the GKI android14-6.1 kernel, not an IDA screenshot. Top: the indirect call blr x8 at sock_sendmsg+0xb4, call proto_ops.sendmsg hash 0x1ebda935, type int (struct socket *, struct msghdr *, unsigned long), 14 candidate(s), 13 in a proto_ops.sendmsg slot, with arrows to its 14 candidates: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg, sock_no_sendmsg. The first 13 stand under the header in a proto_ops.sendmsg slot: (stored in such a slot of the kernel's static data); sock_no_sendmsg stands under same type only:, grey, with a dashed arrow. Bottom: the 3 indirect calls that may reach tcp_sendmsg (same kCFI type), at inet_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f), inet6_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f) and kernel_sendmsg_locked+0x64 (call proto_ops.sendmsg_locked hash 0x87bcba6f), each with type int (struct sock *, struct msghdr *, unsigned long), 11 candidates; tagged [tcp_sendmsg: in a proto.sendmsg slot] for inet_sendmsg+0x58, [tcp_sendmsg: in a proto.sendmsg slot] for inet6_sendmsg+0x58 and [tcp_sendmsg: same type only] for kernel_sendmsg_locked+0x64, whose arrow is dashed grey (it calls proto_ops.sendmsg_locked)."></a>

<sub>Drawn by `tools/draw_hero.py` from `python3 -m cfiscope gki.elf` output on the public GKI android14-6.1 kernel of [Try it](#try-it); not an IDA screenshot. Top: the kCFI-checked `blr x8` in `sock_sendmsg`, the struct member it loads its pointer from (`proto_ops.sendmsg`), its C type from the kernel's BTF, and the 14 functions of that type it may reach, under the group headers of `--targets`: the 13 stored in a `proto_ops.sendmsg` slot of the kernel's static data, then `sock_no_sendmsg` (same type only, grey and dashed: it is stored in no object of this image; module tables use it). Bottom: the 3 indirect calls that may reach `tcp_sendmsg` (same kCFI type), each tagged as `--callers` tags it: `tcp_sendmsg` is stored in a `proto.sendmsg` slot, the member that `inet_sendmsg+0x58` and `inet6_sendmsg+0x58` load, and is of the same type only for `kernel_sendmsg_locked+0x64` (dashed: it calls `proto_ops.sendmsg_locked`). In blue, `inet_sendmsg` and `inet6_sendmsg`: candidates of the top call that hold two of the bottom calls. How it is made and checked: [docs/img](docs/img/README.md).</sub>
```
