# Changelog

Taken from the GitHub release notes. Newest first.

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
