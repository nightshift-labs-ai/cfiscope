# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a short list of functions it can actually reach.

- **Scan kCFI calls** (`Ctrl-Alt-K`): finds every check, comments the call site with the type hash and candidate count, adds cross-references when the candidate list is short (at most 16), and offers to create functions at candidates IDA has not recognised. Your own comments are kept.
- **Candidates for this call** (`Ctrl-Alt-T`): a jump list of every function the call under the cursor can reach.
- **Callers of this function** (`Ctrl-Alt-C`): every indirect call site that can reach this function, an answer the normal xrefs window cannot give.
- **Remove annotations**: removes the comments and cross-references the scan added.

Supported targets: aarch64 (tested on a real kernel) and x86-64 (tested on compiler-built objects only; see below).

## Status: read this first

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is below: the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later.

Candidates are type-compatible functions: kCFI proves a function has the right type hash, not that this call ever reaches it. Treat a long list as a type filter and a short one as a strong lead.

## Verification

Real kernel: `gki-certified-boot-android14-6.1-2024-01_r1` (public Google download), aarch64, stripped. Reproduce with `tools/eval_gki.py`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,897, using 4,184 distinct type hashes, in 0.5 s |
| Sites with at least one candidate | 11,961 (86.1%) |
| Sites with exactly one candidate | 1,694 |
| Median candidates per resolved site | 4 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,092 / 8,999 |
| Distinct candidate functions that start at a kallsyms symbol (symbols restored by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf), used only to score) | 30,357 of 30,567 (99.31%) |

The 1,936 sites with no candidate carry a hash that no function in this image has; a likely reason is callees that live in loadable modules, not checked one by one.

Compiler ground truth: `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the signature table the compiler produced (`tools/gen_fixtures.py`).

`tests/test_plugin_stub.py` runs the IDA layer against fake `ida_*` modules, and `tests/check_ida_api.py` confirms all 45 IDA API names used exist in the official stubs. Neither is a test in real IDA.

Not verified: behaviour inside real IDA; x86-64 on a real distribution kernel (no public kCFI x86 kernel was at hand, only compiler-built objects).

## How it works

`cfiscope/core.py` has no IDA dependency: it finds the per-architecture check sequences, reads the expected hash from each, indexes the hash stored just before every function, and joins the two. `cfiscope/idalayer.py` is the thin IDA layer.

## Licence

MIT.
