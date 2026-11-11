# Changelog

Taken from the GitHub release notes. Newest first.

## Unreleased (branch `oldcfi`)

- **Linux 5.x jump-table CFI on aarch64 (Android 12/13 GKI).** When an aarch64 image has no kCFI checks but has a CFI jump table (the longest run of 8-byte `bti c; b <function>` entries), CFIScope reads the older Clang CFI: range checks (`sub; ror #3; cmp; b.hs/b.hi/b.lo/b.ls`, count as an immediate or in a register, also hoisted out of loops), single-member checks (`cmp; b.ne`) and calls checked only by `__cfi_slowpath(_diag)`. The base register is traced back through `adrp`/`add` and `mov` copies; candidates are the branch targets of the entries the check accepts. Each site gets a kind (`range`, `single`, `slowpath`), the 64-bit type id from its slow path and, with `__typeid_<type>_global_addr` symbols, the demangled type (`int (file*, int)`). Hand-decoded, no new dependency.
- Same IDA actions, comments (`jtCFI <type>: ...`), cross-references, lists and pseudocode comments as for kCFI. Command line: summary, `--sites`, `--callers`, `--targets` and `--json` (new fields `kind`, `type_id`, `type`, `type_mangled`, `jump_table_range`, `note`, `other_checks`; `hash` is the 64-bit id). kCFI output is unchanged.
- Measured on gki-certified-boot-android13-5.15-2024-01_r1 with `tools/eval_gki_oldcfi.py`: 14,000 of 21,738 `blr` in kernel text get candidates (64.4%), median 6 per call; all 24,912 distinct candidates start at a kallsyms function; every check with candidates whose slow path passes a type id starts at that type's `__typeid` symbol (12,076 range, 2,155 single). Android 12 GKI 5.10 not tested; module targets not listed; tracepoint and vendor-hook calls carry no CFI check.
- Known-answer fixture `tests/fixtures/aarch64-jtcfi.elf` (hand-assembled by `tools/gen_fixtures.py --jtcfi-only`) with `tests/test_oldcfi.py`; stub tests run the new kind through the IDA layer. IDA API names: 72 checked against the official stubs, 0 missing.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.15 (2026-11-11)

- **Candidates in Hex-Rays pseudocode.** After a scan, a decompiler hook (`Hexrays_Hooks.func_printed`) appends a comment such as `// CFIScope: 3 candidates: impl_2_0, impl_2_1, impl_2_2` to the pseudocode line of each kCFI call site in the function being printed: at most 5 names, then "and N more"; a site without candidates gets "CFIScope: 0 candidates in this image". The line is found with `cfunc.get_eamap()` (call address to statements) and `cfunc.find_item_coords()`. The hook reuses the scan results, never scans, and only changes the printed text: nothing new is stored in the database. Remove annotations turns the comments off; Scan and Remove annotations flush the decompiler cache (`clear_cached_cfuncs`) so that the next decompile shows the change.
- The hook is installed only if `ida_hexrays` imports and `init_hexrays_plugin()` returns true (tried when the plugin loads and again at each Scan that finds call sites), and it is removed when the plugin unloads. An exception inside it is caught, reported once in the Output window, and the hook returns 0. Without the decompiler, CFIScope works as before.
- Stub tests (`tests/test_entry_stub.py`, a fake `ida_hexrays` with a small decompiled function): the mapped lines get the right text, other lines and functions without kCFI sites are untouched, nothing is added before a scan, after Remove annotations or after the segments change, a missing or disabled decompiler means no hook and no error, and an exception inside the hook returns 0.
- IDA API names used: 68 checked against the official IDAPython stubs (now including the methods the hook calls on `cfunc_t`, `eamap_t`, `cinsnptrvec_t`, `strvec_t` and `simpleline_t`), 0 missing.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.14 (2026-11-11)

- **Remove annotations reports xrefs actually removed.** It now deletes only the call references to candidates that exist (read with `get_first_fcref_from` / `get_next_fcref_from`) and counts those; the Output line says "xrefs removed: N" instead of "xrefs removal attempted". We did not use `del_cref`'s return value for the count because the SDK documents it as "true if the referenced instruction will be deleted" (xref.hpp), not as "reference removed". Stub test: removal count equals the xrefs added, and a second removal reports 0.
- **Version fix:** v0.1.13 bumped ida-plugin.json but not `cfiscope.__version__` (the plugin's "loaded" line in the Output window said 0.1.12). Both now say 0.1.14; `tests/test_cli.py` checks they match.
- IDA API names used: 51 checked against the official IDAPython stubs, 0 missing.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.13 (2026-11-11)

Measured on two newer public Android GKI kernels (README Verification):

| | android15-6.6 | android16-6.12 |
|---|---|---|
| Indirect call sites (type hashes) | 14,694 (4,466) | 16,164 (4,626) |
| With at least one candidate | 87.9% | 88.0% |
| Candidate start precision | 99.34% | 99.34% |

- `tools/eval_gki.py --base <address>`: 6.6 and later GKI kernels start at 0xffffffc080000000 (6.1: 0xffffffc008000000, still the default). The 6.1 numbers in the README reproduce unchanged.
- Images: the public gki-certified-boot zips from dl.google.com, kernel extracted with `tools/extract_bootimg.py`, symbols from vmlinux-to-elf.

No change to the scanner or the plugin.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.12 (2026-11-11)

The command-line tool now recognises the older Clang CFI. On a kernel with the pre-6.1 jump-table CFI (it contains .cfi_jt, __cfi_check or "CFI failure (target:"), for example Android 12/13 GKI 5.10/5.15, a scan that finds 0 sites now says so, instead of suggesting a GCC build. Checked on the public android13-5.15-2024-01_r1 GKI Image (old-CFI message) and the android14-6.1 kernel (unchanged: 13,897 sites). New test in tests/test_cli.py (20 tests in total).

Built by an AI agent (Claude, operated by Nightshift Labs). The plugin has not been run in real IDA yet.

## v0.1.11 (2026-11-11)

Right-click menu and plugin-wiring tests:

- Scan, Candidates for this call and Callers of this function are now also on the right-click menu of disassembly and pseudocode views (CFIScope submenu), through a UI_Hooks.finish_populating_widget_popup hook that is removed when the plugin unloads. The README notes that many Linux desktops take Ctrl-Alt-T for a terminal and that Keypatch uses Ctrl-Alt-K, so judges can use the menus or rebind the keys.
- New tests/test_entry_stub.py loads the plugin entry on fake ida_* modules and checks the scan cache, the rescan after a rebase, the menus and the right-click hook (19 tests in total, `python3 -m unittest discover -s tests`). The IDA API name check now covers 49 names, 0 missing in the official stubs.

Built by an AI agent (Claude, operated by Nightshift Labs). The plugin has not been run in real IDA yet.

## v0.1.10 (2026-11-11)

Accuracy and robustness fixes from a fresh judge-style review that re-ran every README number on public kernels:

- The README said "median 4 candidates per resolved site". That median included the sites with no candidate. Per site that has candidates the median is 6, on both the aarch64 and the x86-64 GKI kernel. The summary, the JSON (`median_candidates_resolved`) and both Verification tables now give both numbers.
- x86-64 scoring: 244 of the 622 "other" candidates sit at weak (W) syscall-stub symbols in System.map. `tools/eval_gki_x86.py` used to count only t/T symbols; it now reports them separately.
- New `tools/extract_bootimg.py` extracts the kernel from the Android boot image, so the aarch64 walkthrough has an exact command. Its output is byte-identical to a hand extraction.
- The README now says which kernels are supported: Clang kCFI on Linux 6.1 or later. GCC kernels and the older jump-table CFI of Linux 5.x (Android 12/13 GKI 5.10/5.15) are not supported. The CLI and the plugin give that reason when a scan finds 0 sites.
- Plugin: candidate names come from the exact address. If IDA starts the function at the `__cfi_` preamble, a candidate is now shown as `name+0x10` or by its own name, not by the preamble's name. Callers of this function also matches when the kCFI target lies inside IDA's function.
- Plugin: the scan cache is checked against the segment layout. After Edit > Segments > Rebase program, the next action scans again instead of using stale addresses.
- README: where the test objects are after `hcli plugin install`, where the scan counts appear (Output window), and the test command `python3 -m unittest discover -s tests`.
- `--targets` no longer ends its header with "...".

Tests: 16 unit tests, 5 stub tests (one new: preamble-merged function), and the IDA API name check against the official stubs (44 names, 0 missing). Built by an AI agent (Claude, operated by Nightshift Labs). The plugin has not been run in real IDA yet.

## v0.1.9 (2026-11-10)

Documentation and reproduction fixes after following the README literally:

- New tools/extract_bzimage.py gets vmlinux from the x86-64 GKI bzImage, and the Verification section gives the full commands. tools/eval_gki_x86.py now says what to do when handed a bzImage instead of crashing.
- The --targets example uses a real call site from the public GKI kernel.
- The test objects are described accurately: the generator writes the known answers, and Clang builds the objects.
- Install notes that the plugin index can lag behind releases.

Plugin change: cross-references for tail calls are now call-type, because the IDA SDK says a call xref creates a function at the target, and a jump xref could fold the target into the caller.

Both Verification tables reproduce with the published commands. Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.1.8 (2026-11-10)

Command-line fixes from an independent review: each site is named by its call instruction (matching the address column), --json keeps every candidate unless --max-list is given, --callers covers every function of that name, piping into head exits quietly, malformed program headers give a clean error, and unreadable section headers on a linked file only lose the names. The README also gains a byte-level 'How it works' from a bundled test object and real output on the public GKI kernel (sock_sendmsg candidates, callers of tcp_sendmsg).

Built by an AI agent (Claude, operated by Nightshift Labs). The IDA layer has not yet been run inside real IDA.

## v0.1.7 (2026-11-10)

An unexpected error in any action now shows one warning, with the traceback in the Output window, instead of a traceback dialog.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.1.6 (2026-11-10)

Accuracy pass after an independent review: the plugin's load message now prints the same version as ida-plugin.json (a test checks this), the 'Candidates for this call' list title names the call address it chose (with the cursor away from a check, the nearest check in the same function is used, now documented), the README says the scanner, not the IDA layer, was scored on the GKI kernels, and the note that candidates are type-compatible sets (median 4, largest 1,458 on GKI aarch64) sits next to the feature list.

Built by an AI agent (Claude, operated by Nightshift Labs). The IDA layer has not yet been run inside real IDA.

## v0.1.5 (2026-11-10)

New: command-line scanner with no IDA, `python3 -m cfiscope <vmlinux|.o|.ko>` (summary, --sites, --callers FUNC, --targets ADDR, --raw --arch --base for bare kernel images, --json). On the public GKI aarch64 kernel from the README walkthrough, --raw reproduces the README totals (13,897 call sites, 11,961 with candidates) in under a second. tests/test_cli.py checks it by symbol name against the compiler's own candidate sets.

Built by an AI agent (Claude, operated by Nightshift Labs). The IDA layer has not yet been run inside real IDA.

## v0.1.4 (2026-11-10)

Show targets, Show callers and Remove xrefs now show the plugin's own warning on an unsupported database (32-bit, or not x86-64/AArch64) instead of a Python traceback, and run the first scan behind a wait box. Found by a review of every IDAPython call against the IDA 9.5 SDK sources (no load or API problems found). Not yet run inside real IDA; see the README. Built by an AI agent (Nightshift Labs).

## v0.1.3 (2026-11-09)

x86-64 now verified on a real Android GKI kernel against its System.map. Not yet run inside real IDA; see the README. Built by an AI agent.

## v0.1.2 (2026-11-09)

Fixes from a review against the official IDAPython sources. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.

## v0.1.1 (2026-11-09)

README: why it matters, a walkthrough and credits. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.

## v0.1.0 (2026-11-09)

First release. Not yet run inside real IDA; see the README for what was verified. Built by an AI agent.
