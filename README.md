# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a list of the type-compatible functions it may reach, usually a short one.

- **Scan kCFI calls** (`Ctrl-Alt-K`): finds every check, comments the call site with the type hash and candidate count, adds cross-references when the candidate list is short (at most 16), and offers to create functions at candidates IDA has not recognised. Your own comments are kept.
- **Candidates for this call** (`Ctrl-Alt-T`): a jump list of every function the call under the cursor can reach. If the cursor is not on a kCFI check or its call, the nearest check in the same function is used; the list's title names the call address it chose.
- **Callers of this function** (`Ctrl-Alt-C`): every indirect call site that can reach this function, an answer the normal xrefs window cannot give.
- **Remove annotations**: removes the comments and cross-references the scan added.

Candidates are type-compatible functions: kCFI proves a function has the right type hash, not that a given call ever reaches it. Most lists are short (median 4 on the GKI kernel below), but a few common types have hundreds or more (the largest list there has 1,458). Treat a long list as a type filter and a short one as a strong lead.

Supported targets: aarch64 and x86-64. The scanner was scored on a real Android GKI kernel for each (numbers below); the IDA layer has not been run in IDA yet (see Status).

## Why it matters

Kernel attack surface runs through function pointers: `file_operations`, `net_device_ops`, tracepoints, callbacks. In a stripped binary every one of those calls is a dead end for static analysis, and tracing them by hand or with a debugger is slow, and impossible on a kernel you only have as a file. kCFI happens to record the answer, because the compiler must know which types may be called, and CFIScope turns that record into cross-references you can follow.

## Try it

Quick try, no download (about a minute): the repository ships small objects built with Clang kCFI from `tests/fixtures/t.c`, with the compiler's own answer for every call in `tests/fixtures/truth.json`.

1. Open `tests/fixtures/x86_64-kernel.o` (or `aarch64-kernel.o`) in IDA.
2. Press `Ctrl-Alt-K`. It should find 21 kCFI call sites, one per function-pointer type in `t.c`, each with candidates.
3. In `do_call_2`, `Ctrl-Alt-T` should list `impl_2_0`, `impl_2_1`, `impl_2_2`; on `impl_2_1`, `Ctrl-Alt-C` should list that call in `do_call_2`.

The same scan from the command line, real output:

```
$ python3 -m cfiscope tests/fixtures/x86_64-kernel.o --sites --max-list 4
0x108033  do_call_0+0x5   jump hash 0x7230bf2a  4 candidate(s): impl_0_0, impl_0_1, impl_0_2, impl_0_3
0x116033  do_call_1+0x5   jump hash 0x36b1c5a6  6 candidate(s): impl_1_0, impl_1_1, impl_1_2, impl_1_3 ...
0x11e03a  do_call_2+0xc   jump hash 0x1300e12b  3 candidate(s): impl_2_0, impl_2_1, impl_2_2
...
```

(Addresses are where the command-line tool lays out the object's sections; IDA will place them elsewhere.)

A real kernel:

1. Download the public aarch64 Android kernel used for the numbers below: [gki-certified-boot-android14-6.1-2024-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip), extract the kernel from `boot-6.1.img`, and restore its symbols with [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf).
2. Open the resulting ELF in IDA and let auto-analysis finish.
3. Press `Ctrl-Alt-K`. Then on any `blr` preceded by a kCFI check, press `Ctrl-Alt-T` to list the functions it can reach, or on a function, press `Ctrl-Alt-C` to list the indirect calls that can reach it.

## Status: read this first

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is below: the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later.


## Without IDA (scripts, other tools, CI)

The scanner is plain Python 3 with no dependencies, so the same answers are available from the command line, for example to feed another disassembler or a pipeline:

```
python3 -m cfiscope vmlinux                         # summary
python3 -m cfiscope vmlinux --sites                 # every call site and its candidates
python3 -m cfiscope vmlinux --callers tcp_sendmsg   # indirect calls that can reach a function
python3 -m cfiscope vmlinux --targets 0xffffffc0081234a8
python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
```

Run it from this folder. Input is a 64-bit ELF (a `vmlinux`, a kernel with symbols restored by vmlinux-to-elf, or a `.o`/`.ko`) or, with `--raw`, a bare kernel image. Symbols are only used to print names. `--json` gives machine-readable output. On the GKI aarch64 `Image` from the walkthrough above, `--raw` prints the same totals as the table below in under a second.

## Verification

Real kernel: `gki-certified-boot-android14-6.1-2024-01_r1` (public Google download), aarch64, stripped. Reproduce with `tools/eval_gki.py`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,897, using 4,184 distinct type hashes, in 0.5 s |
| Sites with at least one candidate | 11,961 (86.1%) |
| Sites with exactly one candidate | 1,694 |
| Median candidates per resolved site | 4 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,092 / 8,999 |
| Candidate start precision: distinct candidates that begin exactly at a kallsyms function symbol (symbols restored by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf), used only to score). This checks that candidates are real function starts, not that a call reaches them | 30,357 of 30,567 (99.31%) |

The 1,936 sites with no candidate carry a hash that no function in this image has; a likely reason is callees that live in loadable modules, not checked one by one.

Real x86-64 kernel: the public GKI prebuilt `kernel-6.1` from [kernel/prebuilts/6.1/x86-64](https://android.googlesource.com/kernel/prebuilts/6.1/x86-64) (6.1.84), scored against its own `System.map`, which names a `__cfi_` preamble for each protected function. Reproduce with `tools/eval_gki_x86.py`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,770, using 4,257 distinct type hashes, in 0.4 s |
| Sites with at least one candidate | 11,833 (85.9%) |
| Sites with exactly one candidate | 1,652 |
| Median candidates per resolved site | 4 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,093 / 8,601 |
| Distinct candidates that are a `__cfi_`-protected function | 32,393 of 33,015 (98.12%) |

The other 622 candidates are not at any symbol in the map; many sit in unnamed syscall stubs, and they were not checked one by one. Only 63.50% of the protected functions appear as candidates, which is expected for a kernel image alone: a function's hash only matches when some call site in the image uses that type.

Compiler ground truth: `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the signature table the compiler produced (`tools/gen_fixtures.py`). `tests/test_cli.py` checks that `python3 -m cfiscope` lists, by symbol name, exactly the compiler's candidate sets for the same objects, and that bad input gives a clear error.

`tests/test_plugin_stub.py` runs the IDA layer against fake `ida_*` modules, and `tests/check_ida_api.py` confirms all 45 IDA API names used exist in the official stubs. Neither is a test in real IDA.

Not verified: behaviour inside real IDA.

## How it works

`cfiscope/core.py` has no IDA dependency: it finds the per-architecture check sequences, reads the expected hash from each, indexes the hash stored just before every function, and joins the two. `cfiscope/idalayer.py` is the thin IDA layer.

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs".

## Licence

MIT.
