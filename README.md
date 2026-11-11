# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a list of the type-compatible functions it may reach, usually a short one.

- **Scan kCFI calls** (`Ctrl-Alt-K`): finds every check, comments the call site with the type hash and candidate count, adds cross-references when the candidate list is short (at most 16), and offers to create functions at candidates IDA has not recognised. Your own comments are kept.
- **Candidates for this call** (`Ctrl-Alt-T`): a jump list of every function the call under the cursor can reach. If the cursor is not on a kCFI check or its call, the nearest check in the same function is used; the list's title names the call address it chose.
- **Callers of this function** (`Ctrl-Alt-C`): every indirect call site that can reach this function, an answer the normal xrefs window cannot give.
- **Remove annotations**: removes the comments and cross-references the scan added.

All four actions are under Edit > Plugins. Scan and the two lookups are also on the right-click menu of disassembly and pseudocode views (CFIScope submenu). Many Linux desktops take `Ctrl-Alt-T` for a terminal and Keypatch uses `Ctrl-Alt-K`: use the menus, or rebind the keys in Options > Shortcuts.

Candidates are type-compatible functions: kCFI proves a function has the right type hash, not that a given call ever reaches it. Most lists are short (median 6 candidates per call that has any, on both GKI kernels below), but a few common types have hundreds or more (the largest list there has 1,458). Treat a long list as a type filter and a short one as a strong lead.

Supported targets: aarch64 and x86-64 kernels built by Clang with kCFI (`CONFIG_CFI_CLANG` on Linux 6.1 or later), for example Android GKI android14-6.1 and later. Not supported: GCC-built kernels (most desktop distribution kernels have no kCFI checks to read) and the older jump-table CFI of Linux 5.x Clang builds (Android 12/13 GKI 5.10/5.15); on those the scan finds 0 sites and says so. The scanner was scored on a real Android GKI kernel for each architecture (numbers below); the IDA layer has not been run in IDA yet (see Status).

## Why it matters

Kernel attack surface runs through function pointers: `file_operations`, `net_device_ops`, tracepoints, callbacks. In a stripped binary every one of those calls is a dead end for static analysis, and tracing them by hand or with a debugger is slow, and impossible on a kernel you only have as a file. kCFI happens to record the answer, because the compiler must know which types may be called, and CFIScope turns that record into cross-references you can follow.

## Try it

Quick try, no download (about a minute): the repository ships small objects built with Clang kCFI from `tests/fixtures/t.c`, with the known answer for every call in `tests/fixtures/truth.json`: the generator wrote each function-pointer type and its implementations into `t.c`, and Clang built the objects.

1. Open `tests/fixtures/x86_64-kernel.o` (or `aarch64-kernel.o`) in IDA. After `hcli plugin install cfiscope` the fixtures are in `$IDAUSR/plugins/cfiscope/tests/fixtures/` (`~/.idapro/plugins/...` on Linux and macOS, `%APPDATA%\Hex-Rays\IDA Pro\plugins\...` on Windows).
2. Press `Ctrl-Alt-K`. It should find 21 kCFI call sites, one per function-pointer type in `t.c`, each with candidates (the counts are printed in the Output window).
3. In `do_call_2`, `Ctrl-Alt-T` should list `impl_2_0`, `impl_2_1`, `impl_2_2`; on `impl_2_1`, `Ctrl-Alt-C` should list that call in `do_call_2`.

The same scan from the command line, real output:

```
$ python3 -m cfiscope tests/fixtures/x86_64-kernel.o --sites --max-list 4
0x108033  do_call_0+0x13  jump hash 0x7230bf2a  4 candidate(s): impl_0_0, impl_0_1, impl_0_2, impl_0_3
0x116033  do_call_1+0x13  jump hash 0x36b1c5a6  6 candidate(s): impl_1_0, impl_1_1, impl_1_2, impl_1_3 ...
0x11e03a  do_call_2+0x1a  jump hash 0x1300e12b  3 candidate(s): impl_2_0, impl_2_1, impl_2_2
...
```

(Spacing condensed. Addresses are where the command-line tool lays out the object's sections; IDA will place them elsewhere.)

A real kernel:

1. Download the public aarch64 Android kernel used for the numbers below: [gki-certified-boot-android14-6.1-2024-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip), extract the kernel with `python3 tools/extract_bootimg.py boot-6.1.img Image` (no dependencies), and restore its symbols with [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): `vmlinux-to-elf Image gki.elf`.
2. Open the resulting ELF in IDA and let auto-analysis finish.
3. Press `Ctrl-Alt-K`. Then on any `blr` preceded by a kCFI check, press `Ctrl-Alt-T` to list the functions it can reach, or on a function, press `Ctrl-Alt-C` to list the indirect calls that can reach it.

## What you will see (real output, not an IDA screenshot)

We have no IDA, so this is the command-line tool, which runs the same scanner as the plugin, on the public GKI aarch64 kernel from the walkthrough with its symbols restored by vmlinux-to-elf (57,453 named functions). The plugin puts the same answers in its comments, cross-references and jump lists.

Which functions can the indirect call in `sock_sendmsg` reach?

```
$ python3 -m cfiscope gki.elf --sites --max-list 20 | grep sock_sendmsg+
0xffffffc008cc55ac  sock_sendmsg+0xb4  call hash 0x1ebda935  14 candidate(s): tun_sendmsg, sock_no_sendmsg,
    netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg,
    packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg
```

Which indirect calls can reach `tcp_sendmsg`?

```
$ python3 -m cfiscope gki.elf --callers tcp_sendmsg --max-list 3
3 call site(s) can reach tcp_sendmsg
0xffffffc008cc5778  kernel_sendmsg_locked+0x64  call hash 0x87bcba6f  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
0xffffffc008e433c8  inet_sendmsg+0x58           call hash 0x87bcba6f  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
0xffffffc008ead820  inet6_sendmsg+0x58          call hash 0x87bcba6f  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
```

(Long lines wrapped by hand; spacing condensed.)

## Status: read this first

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is below: the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later. The plugin index can lag behind the [GitHub releases](https://github.com/nightshift-labs-ai/cfiscope/releases); if `hcli plugin status` shows an older version, copy the folder from the latest release.


## Without IDA (scripts, other tools, CI)

The scanner is plain Python 3 with no dependencies, so the same answers are available from the command line, for example to feed another disassembler or a pipeline:

```
python3 -m cfiscope vmlinux                         # summary
python3 -m cfiscope vmlinux --sites                 # every call site and its candidates
python3 -m cfiscope vmlinux --callers tcp_sendmsg   # indirect calls that can reach a function
python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
```

Run it from this folder. Input is a 64-bit ELF (a `vmlinux`, a kernel with symbols restored by vmlinux-to-elf, or a `.o`/`.ko`) or, with `--raw`, a bare kernel image. Symbols are only used to print names. `--json` gives machine-readable output. On the GKI aarch64 `Image` from the walkthrough above, `--raw` prints the same totals as the table below in under a second.

## Verification

Real kernel: `gki-certified-boot-android14-6.1-2024-01_r1` (public Google download), aarch64, stripped. Reproduce with `python3 tools/eval_gki.py Image gki.elf` (`Image` and `gki.elf` as in the walkthrough).

| Measure | Result |
|---|---|
| Indirect call sites found | 13,897, using 4,184 distinct type hashes, in 0.5 s |
| Sites with at least one candidate | 11,961 (86.1%) |
| Sites with exactly one candidate | 1,694 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,092 / 8,999 |
| Candidate start precision: distinct candidates that begin exactly at a kallsyms function symbol (symbols restored by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf), used only to score). This checks that candidates are real function starts, not that a call reaches them | 30,357 of 30,567 (99.31%) |

The 1,936 sites with no candidate carry a hash that no function in this image has; a likely reason is callees that live in loadable modules, not checked one by one.

Real x86-64 kernel: the public GKI prebuilt `kernel-6.1` from [kernel/prebuilts/6.1/x86-64](https://android.googlesource.com/kernel/prebuilts/6.1/x86-64) (6.1.84), scored against its own `System.map`, which names a `__cfi_` preamble for each protected function. Reproduce with `python3 tools/extract_bzimage.py kernel-6.1 vmlinux`, then `python3 tools/eval_gki_x86.py vmlinux System.map`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,770, using 4,257 distinct type hashes, in 0.4 s |
| Sites with at least one candidate | 11,833 (85.9%) |
| Sites with exactly one candidate | 1,652 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,093 / 8,601 |
| Distinct candidates that are a `__cfi_`-protected function | 32,393 of 33,015 (98.12%) |

The other 622 candidates: 244 sit at weak (`W`) symbols in the map, mostly syscall entry stubs such as `__ia32_sys_msgctl`, and 378 are at no symbol in the map; those 378 were not checked one by one. Only 63.50% of the protected functions appear as candidates, which is expected for a kernel image alone: a function's hash only matches when some call site in the image uses that type.

Known-answer objects: `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the table of signatures and implementations that `tools/gen_fixtures.py` wrote into the source; function offsets come from the compiled objects. `tests/test_cli.py` checks that `python3 -m cfiscope` lists, by symbol name, exactly the known candidate sets for the same objects, and that bad input gives a clear error.

Run all of these with `python3 -m unittest discover -s tests` (no IDA needed). `tests/test_plugin_stub.py` runs the IDA layer and `tests/test_entry_stub.py` the plugin wiring (menus, right-click hooks, rescan after a rebase) against fake `ida_*` modules, and `python3 tests/check_ida_api.py <dir with ida_*.pyi>` (the stubs ship in the `idapro` pip package) confirms all 49 IDA API names used exist in the official stubs. None of these is a test in real IDA.

Not verified: behaviour inside real IDA.

## How it works

The two ends that kCFI leaves in the binary, from the bundled `tests/fixtures/x86_64-plain.o` (`objdump -d -M intel`; comments added):

```
do_call_2:                                  ; the indirect call
  mov    r10d,0xecff1ed5                    ; minus the expected type hash 0x1300e12b
  add    r10d,DWORD PTR [rax-0x4]           ; plus the hash stored 4 bytes before the target
  je     ok                                 ; zero: same function type
  ud2                                       ; otherwise trap
ok:
  jmp    rax                                ; the call itself (a tail call here)

__cfi_impl_2_1:                             ; in front of every function of that type
  nop ... nop
  mov    eax,0x1300e12b                     ; the type hash; never executed, read by the checks
impl_2_1:
```

CFIScope reads the hash from every check, indexes the hash stored in front of every function, and joins the two: this call gets `impl_2_0`, `impl_2_1`, `impl_2_2`. On aarch64 the check loads the 32-bit word in front of the target, compares it with the hash, and branches over a `brk` trap before the `blr`; CFIScope anchors on that `b.eq` + `brk` pair.

`cfiscope/core.py` has no IDA dependency: it finds the per-architecture check sequences, reads the expected hash from each, indexes the hash stored just before every function, and joins the two. `cfiscope/idalayer.py` is the thin IDA layer.

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs".

## Licence

MIT.
