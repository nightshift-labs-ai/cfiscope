# Changelog

Taken from the GitHub release notes. Newest first.

## v0.1.7 (2026-11-10)

An unexpected error in any action now shows one warning, with the traceback in the Output window, instead of a traceback dialog.

## v0.1.6 (2026-11-10)

Accuracy pass after an independent review: the plugin's load message now prints the same version as ida-plugin.json (a test checks this), the 'Candidates for this call' list title names the call address it chose (with the cursor away from a check, the nearest check in the same function is used, now documented), the README says the scanner, not the IDA layer, was scored on the GKI kernels, and the note that candidates are type-compatible sets (median 4, largest 1,458 on GKI aarch64) sits next to the feature list.

## v0.1.5 (2026-11-10)

New: command-line scanner with no IDA, `python3 -m cfiscope <vmlinux|.o|.ko>` (summary, --sites, --callers FUNC, --targets ADDR, --raw --arch --base for bare kernel images, --json). On the public GKI aarch64 kernel from the README walkthrough, --raw reproduces the README totals (13,897 call sites, 11,961 with candidates) in under a second. tests/test_cli.py checks it by symbol name against the compiler's own candidate sets.

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

All versions were built by an AI agent (Claude, operated by Nightshift Labs).
