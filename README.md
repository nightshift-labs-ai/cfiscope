# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a list of the type-compatible functions it may reach, usually a short one.

- **Scan kCFI calls** (`Ctrl-Alt-K`): finds every check, comments the call site with the type hash and candidate count, adds cross-references when the candidate list is short (at most 16), and offers to create functions at candidates IDA has not recognised. Your own comments are kept.
- **Candidates for this call** (`Ctrl-Alt-T`): a jump list of every function the call under the cursor can reach. If the cursor is not on a kCFI check or its call, the nearest check in the same function is used; the list's title names the call address it chose.
- **Callers of this function** (`Ctrl-Alt-C`): every indirect call site that can reach this function, an answer the normal xrefs window cannot give. Only calls are counted: with the Linux 5.x jump-table CFI, a check whose call was not linked comes after the calls as a type check only, and the CFI runtime's own checks (in `__cfi_check`, which guard no call) are left out.
- **Remove annotations**: removes the comments and cross-references the scan added, and turns the pseudocode comments off.
- **Pseudocode comments** (with the Hex-Rays decompiler): after a scan, the pseudocode line of each kCFI call gets a trailing comment such as `// CFIScope: 3 candidates: impl_2_0, impl_2_1, impl_2_2` (at most 5 names, then "and N more"). The line is found through the decompiler's address map when a function is printed; the comment is display text only, nothing is saved in the database. Not yet run in IDA and not tested with the real decompiler, only against a fake `ida_hexrays` module.

All four actions are under Edit > Plugins. Scan and the two lookups are also on the right-click menu of disassembly and pseudocode views (CFIScope submenu). Many Linux desktops take `Ctrl-Alt-T` for a terminal and Keypatch uses `Ctrl-Alt-K`: use the menus, or rebind the keys in Options > Shortcuts.

Candidates are type-compatible functions: kCFI proves a function has the right type hash, not that a given call ever reaches it. Most lists are short (median 6 candidates per call that has any on both 6.1 GKI kernels below, 6 and 7 on the 6.6 and 6.12 ones), but a few common types have hundreds or more (the largest lists have 1,458 to 1,580). Treat a long list as a type filter and a short one as a strong lead.

Supported targets: aarch64 and x86-64 kernels built by Clang with kCFI (`CONFIG_CFI_CLANG` on Linux 6.1 or later), for example Android GKI android14-6.1 and later. Since v0.1.17 also aarch64 kernels built with the older jump-table CFI of Linux 5.x, measured on an Android 12 GKI 5.10 and an Android 13 GKI 5.15 kernel (see [Linux 5.x jump-table CFI](#linux-5x-jump-table-cfi-android-1213-gki-510-and-515) for what it reads and what it does not). Not supported: GCC-built kernels (most desktop distribution kernels have no kCFI checks to read) and x86-64 kernels with the jump-table CFI; on those the scan finds 0 sites and says so. The scanner was scored on a real Android GKI kernel for each architecture (numbers below); the IDA layer has not been run in IDA yet (see Status).

## Why it matters

Kernel attack surface runs through function pointers: `file_operations`, `net_device_ops`, tracepoints, callbacks. In a stripped binary every one of those calls is a dead end for static analysis, and tracing them by hand or with a debugger is slow, and impossible on a kernel you only have as a file. kCFI happens to record the answer, because the compiler must know which types may be called, and CFIScope turns that record into cross-references you can follow.

## Status: read this first

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is below: the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.0 or later. The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/cfiscope/releases) (on Nov 12 it still offered 0.1.15, which has no Linux 5.x support and no headless runner); if `hcli plugin status` shows an older version, install a release zip directly: `hcli plugin install https://github.com/nightshift-labs-ai/cfiscope/archive/refs/tags/v0.1.18.zip`.


## Try it

Install the current release (the plugin index can lag a day behind; see [Install](#install)):

```
hcli plugin install https://github.com/nightshift-labs-ai/cfiscope/archive/refs/tags/v0.1.18.zip
```

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

## What the plugin writes into IDA (fake IDA, not a screenshot)

`tools/showcase_ida_stub.py` loads the same kernel's code segments and symbol names into the fake IDA modules of the stub tests, runs the plugin's own IDA layer (Scan, the two lists, the pseudocode comment) and prints what it wrote. These are the exact strings the plugin hands to IDA; real IDA has not run them and draws its own listing around them. The fake database has no data cross-references, so no candidate is marked "address taken" here; in IDA, candidates whose address is stored in data are marked and listed first, so the first names in a comment can differ.

```
$ python3 -I tools/showcase_ida_stub.py gki.elf sock_sendmsg+0xb4 tcp_sendmsg
BEFORE (no CFIScope): 0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8
  comment: none; code xrefs from this call: none (indirect)

AFTER Scan kCFI calls (Ctrl-Alt-K): 13897 sites, 13897 comments, 44724 cross-references in the whole database
0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8    ; kCFI 0x1EBDA935: 14 candidate(s): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, +8 more
  code xrefs from this call (14): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg

Candidates for this call (Ctrl-Alt-T): window 'kCFI candidates for the call at 0xFFFFFFC008CC55AC (hash 0x1EBDA935)'
  0xffffffc00897842c  tun_sendmsg
  0xffffffc008cd2ac4  sock_no_sendmsg
  0xffffffc008d8cd98  netlink_sendmsg
  0xffffffc008e43370  inet_sendmsg
  0xffffffc008ea71dc  unix_stream_sendmsg
  0xffffffc008ea9910  unix_dgram_sendmsg
  0xffffffc008eaa360  unix_seqpacket_sendmsg
  0xffffffc008ead7c8  inet6_sendmsg
  0xffffffc008f24f88  packet_sendmsg
  0xffffffc008f2a988  packet_sendmsg_spkt
  0xffffffc008f2dc00  pfkey_sendmsg
  0xffffffc008f6b58c  vsock_dgram_sendmsg
  0xffffffc008f6cc48  vsock_connectible_sendmsg
  0xffffffc008f72e10  xsk_sendmsg

Callers of this function (Ctrl-Alt-C) on tcp_sendmsg: 3 row(s)
  0xffffffc008cc5778  kernel_sendmsg_locked+0x64  11 candidate(s)
  0xffffffc008e433c8  inet_sendmsg+0x58  11 candidate(s)
  0xffffffc008ead820  inet6_sendmsg+0x58  11 candidate(s)

Pseudocode line of the call (with Hex-Rays):  // CFIScope: 14 candidates: tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg and 9 more
```

## Without IDA (scripts, other tools, CI)

The scanner is plain Python 3 with no dependencies, so the same answers are available from the command line, for example to feed another disassembler or a pipeline:

```
python3 -m cfiscope vmlinux                         # summary
python3 -m cfiscope vmlinux --sites                 # every call site and its candidates
python3 -m cfiscope vmlinux --callers tcp_sendmsg   # indirect calls that can reach a function
python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
```

Run it from this folder. Input is a 64-bit ELF (a `vmlinux`, a kernel with symbols restored by vmlinux-to-elf, or a `.o`/`.ko`) or, with `--raw`, a bare kernel image. Symbols are only used to print names. `--json` gives machine-readable output. On the GKI aarch64 `Image` from the walkthrough above, `--raw` prints the same totals as the table below in about a second (0.91 to 1.00 s in three runs on the machine named under the table below).

Headless inside IDA, with idalib (cfiscope 0.1.17 or later; IDA 9.0 or newer; set up the `idapro` module as Hex-Rays describes):

```
python3 tools/cfiscope_headless.py vmlinux [--define-functions] [--remove] [--no-analysis]
```

It opens the file as a database, adds the same comments and cross-references as **CFIScope: Scan kCFI calls**, prints the same statistics and saves the database. It calls the plugin's own `cfiscope.idalayer`; like the rest of the IDA layer it has only been run against fake modules (`tests/test_headless_stub.py`), not a real idalib.

## Verification

Real kernel: `gki-certified-boot-android14-6.1-2024-01_r1` (public Google download), aarch64, stripped. Reproduce with `python3 tools/eval_gki.py Image gki.elf` (`Image` and `gki.elf` as in the walkthrough).

| Measure | Result |
|---|---|
| Indirect call sites found | 13,897, using 4,184 distinct type hashes, in about 1 s (see below) |
| Sites with at least one candidate | 11,961 (86.1%) |
| Sites with exactly one candidate | 1,694 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,092 / 8,999 |
| Candidate start precision: distinct candidates that begin exactly at a kallsyms function symbol (symbols restored by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf), used only to score). This checks that candidates are real function starts, not that a call reaches them | 30,357 of 30,567 (99.31%) |

Scan time: the script prints it; three runs gave 0.9, 0.9 and 1.1 s (1.1 to 1.4 s for the whole command) on an Intel i9-13900H laptop under WSL2, in single-threaded Python. Expect a different figure on another machine.

The 1,936 sites with no candidate carry a hash that no function in this image has; a likely reason is callees that live in loadable modules, not checked one by one.

Newer aarch64 GKI kernels, measured the same way: [gki-certified-boot-android15-6.6-2025-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android15-6.6-2025-01_r1.zip) and [gki-certified-boot-android16-6.12-2025-06_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android16-6.12-2025-06_r1.zip), kernel extracted with `tools/extract_bootimg.py`, symbols restored by vmlinux-to-elf, then `python3 tools/eval_gki.py --base 0xffffffc080000000 Image gki.elf` (these kernels start at a different address than 6.1).

| Measure | android15-6.6 | android16-6.12 |
|---|---|---|
| Indirect call sites found (distinct type hashes) | 14,694 (4,466) | 16,164 (4,626) |
| Sites with at least one candidate | 12,917 (87.9%) | 14,232 (88.0%) |
| Sites with exactly one candidate | 1,974 | 2,019 |
| Median candidates per site with at least one (over all sites) | 6 (5) | 7 (5) |
| Sites with 1 to 8 candidates / 1 to 16 | 7,435 / 9,681 | 8,404 / 10,684 |
| Largest candidate list | 1,536 | 1,580 |
| Candidate start precision (distinct candidates at a kallsyms function symbol) | 33,743 of 33,967 (99.34%) | 35,248 of 35,481 (99.34%) |

Real x86-64 kernel: the public GKI prebuilt `kernel-6.1` from [kernel/prebuilts/6.1/x86-64](https://android.googlesource.com/kernel/prebuilts/6.1/x86-64) (6.1.84), scored against its own `System.map`, which names a `__cfi_` preamble for each protected function. Reproduce with `python3 tools/extract_bzimage.py kernel-6.1 vmlinux`, then `python3 tools/eval_gki_x86.py vmlinux System.map`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,770, using 4,257 distinct type hashes |
| Sites with at least one candidate | 11,833 (85.9%) |
| Sites with exactly one candidate | 1,652 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,093 / 8,601 |
| Distinct candidates that are a `__cfi_`-protected function | 32,393 of 33,015 (98.12%) |

The other 622 candidates: 244 sit at weak (`W`) symbols in the map, mostly syscall entry stubs such as `__ia32_sys_msgctl`, and 378 are at no symbol in the map; those 378 were not checked one by one. Only 63.50% of the protected functions appear as candidates, which is expected for a kernel image alone: a function's hash only matches when some call site in the image uses that type.

Known-answer objects: `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the table of signatures and implementations that `tools/gen_fixtures.py` wrote into the source; function offsets come from the compiled objects. `tests/test_cli.py` checks that `python3 -m cfiscope` lists, by symbol name, exactly the known candidate sets for the same objects, and that bad input gives a clear error.

Run all of these with `python3 -m unittest discover -s tests` (no IDA needed). `tests/test_plugin_stub.py` runs the IDA layer and `tests/test_entry_stub.py` the plugin wiring (menus, right-click hooks, rescan after a rebase, pseudocode comments on a fake decompiler) against fake `ida_*` modules, and `python3 tests/check_ida_api.py <dir with ida_*.pyi>` (the stubs ship in the `idapro` pip package) confirms all 73 IDA API names used, including the decompiler methods the pseudocode hook calls and `func_t.tailqty`, exist in the official stubs. None of these is a test in real IDA.

Not verified: behaviour inside real IDA.

## Linux 5.x jump-table CFI (Android 12/13 GKI 5.10 and 5.15)

Needs cfiscope 0.1.18 or later (see [Install](#install) if `hcli` gives an older version).

Before kCFI, Clang's CFI for the kernel (`CONFIG_CFI_CLANG` on Linux 5.x, used by Android 12 and 13 GKI) worked differently: every function whose address is taken gets an 8-byte entry `bti c; b <function>` in one jump table, the functions of one type sit next to each other in it, and a checked call tests that the pointer lies in its type's run of entries before calling it:

```
adrp x8, ... ; add x8, x8, #0x3a8     ; first entry of the type's run
sub  x8, x23, x8 ; ror x8, x8, #3      ; index of the pointer's entry
cmp  x8, #0xa6                         ; 166 entries
b.hs slow_path                         ; otherwise __cfi_slowpath_diag(type id, pointer, ...)
blr  x23
```

So the candidates of a call are written in the code: CFIScope reads the base and the count, then each entry's branch target. This is the compiler's own list of the functions of that type in the image that the check lets through, with no hash collisions. When there are no kCFI checks in an aarch64 image, the scan looks for this form instead; the actions, comments (`jtCFI <type>: N candidate(s): ...`), cross-references, lists and pseudocode comments are the same as for kCFI. Supported shapes: range checks (`b.hs`/`b.hi` with the call on the fall-through, `b.lo`/`b.ls` with the call at the branch target, count as an immediate or in a register, up to four unrelated instructions between the subtract and the rotate), single-member types (`cmp; b.ne`), checks whose subtract and rotate were hoisted out of a loop, and calls checked only through `__cfi_slowpath`/`__cfi_slowpath_diag`. When a check's slow path is inlined (`bl find_check_fn`, then a `blr` to the `__cfi_check` of the kernel or module that holds the pointer with the type id in `x0`), that `blr` is the CFI runtime's own call, not a program call: CFIScope labels it (`jtCFI runtime: calls __cfi_check ...`) instead of listing candidates. On the GKI 5.15 kernel below it finds 890 of them from the code alone, all among the 1,015 counted with symbols; the GKI 5.10 kernel has none (its slow paths call `__cfi_slowpath`). Each site also gets the type's 64-bit id (passed to the slow path; it is the first 8 bytes of MD5 of the mangled type name), and, when the kernel's symbols include the `__typeid_<type>_global_addr` names that kallsyms keeps, the type itself, for example `int (file*, int)`. In IDA these names are taken from the database and, because IDA keeps one name per address and each of them shares its address with a `foo.cfi_jt` entry, also from the input ELF's symbol table if that file is still where it was loaded from.

Command line, on the Android 13 GKI kernel below with symbols restored by vmlinux-to-elf (real output):

```
$ python3 -m cfiscope gki515.elf --sites --max-list 4 | grep vfs_read+
0xffffffc00853ffbc  vfs_read+0xe8                            call range int (file*, int)  2 candidate(s): vfs_fsync, selinux_file_permission
0xffffffc0085400c0  vfs_read+0x1ec                           call range long (file*, char*, unsigned long, long long*)  166 candidate(s): kvm_vm_stats_read, kvm_vcpu_stats_read, cpu_latency_qos_read, snapshot_read ...
0xffffffc00854021c  vfs_read+0x348                           call range long (kiocb*, iov_iter*)  64 candidate(s): devkmsg_write, generic_file_write_iter, __generic_file_write_iter, generic_file_direct_write ...
```

The summary for the whole kernel (real output):

```
$ python3 -m cfiscope gki515.elf
arch aarch64, 95566 named functions
Linux 5.x jump-table CFI: jump table 0xffffffc0096da488-0xffffffc00971c3f0, 33773 entries of 8 bytes
checked sites 16350: range checks 12117, single-member checks 2146, slow path only 2087 (type ids 3433; checks named from __typeid symbols 14550)
indirect calls (blr/br) 23224, with candidates 14053
sites with candidates 14209, none 2141, exactly one 2145
median candidates per site with candidates 6 (over all sites 5), max 1310
```

Its call totals differ from the table below on purpose: the summary counts every `blr` and `br` in the executable segments (21,739 `blr` and 1,485 `br`), the table counts only `blr` in kernel text (21,738), which leaves out one call with candidates in exit text (`dm_exit+0x4c`): 14,053 here, 14,052 there. On the 5.10 kernel the summary says 22,461 and 14,137 (20,940 `blr`, 1,521 `br`; again one call in exit text, `dm_exit+0x40`).

Which indirect calls can reach `tcp_sendmsg` on that kernel (real output):

```
$ python3 -m cfiscope gki515.elf --callers tcp_sendmsg --max-list 3
6 call site(s) can reach tcp_sendmsg
0xffffffc00921bd4c  kernel_sendmsg_locked+0x5c               call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
0xffffffc0092276c0  sock_no_sendpage_locked+0xc4             call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
0xffffffc009234540  skb_send_sock_locked+0x180               call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
0xffffffc009434050  inet_sendmsg+0x5c                        call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
0xffffffc0094c3d7c  inet6_sendmsg+0x5c                       call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
0xffffffc00969f60c  ieee802154_sock_sendmsg+0x38             call range int (sock*, msghdr*, unsigned long)  11 candidate(s): tcp_sendmsg_locked, tcp_sendmsg, raw_sendmsg ...
```

Only calls are counted. A check whose call was not linked would follow them, marked `type check only (call not linked)`, and the first line would add `(+N type check(s) whose call was not linked, listed last)`; the IDA list does the same, with that line in its title. The CFI runtime's own checks are left out: `__cfi_check` receives a type id and a pointer, tests the pointer against that type's range and returns or branches to `__cfi_check_fail`, so its checks guard no call. CFIScope recognises them from the code (a check with no linked call whose failure path passes no type id and that tests the pointer in `x1`, where `__cfi_check` receives it) and, where names or function bounds are known, by the function's name or by a function with no `blr`/`br`. `--sites` and Scan still show every check; `--json` marks these with `runtime_check`. In `--sites`, a site with no linked call is labelled `CFI runtime check (guards no call)` (the runtime's), `type check only (call not linked)` (another range or single-member check) or `check (call not linked)` (a slow-path-only site: no inline check was decoded for it).

Measured on `gki-certified-boot-android13-5.15-2024-01_r1` ([zip](https://dl.google.com/android/gki/gki-certified-boot-android13-5.15-2024-01_r1.zip), kernel extracted with `python3 tools/extract_bootimg.py boot-5.15.img Image`, symbols restored by vmlinux-to-elf), with `python3 tools/eval_gki_oldcfi.py --cxxfilt Image gki515.elf`. The symbols are only used to score: which words are kernel text, where functions start, the names of the jump-table entries, and the `__typeid` symbols.

| Measure | Result |
|---|---|
| Jump table found from the code alone | 33,773 entries; same bounds as `__cfi_jt_start` / `__cfi_jt_end` |
| `blr` in kernel text (`_stext`..`_etext` without the jump table, plus init text) with candidates | 14,052 of 21,738 (64.6%) |
| The same, leaving out the CFI runtime's own 1,015 calls into `__cfi_check` | 14,052 of 20,723 (67.8%) |
| Candidates per resolved `blr` | median 6, mean 29.2, largest 1,310; exactly one: 2,144 |
| Distinct candidates that start exactly at a kallsyms function | 24,976 of 24,976 |
| Jump-table entries used whose name matches the target (`foo.cfi_jt` branches to `foo`) | 24,976 of 24,976 |
| Checks whose range was read at the check and whose first entry is the `__typeid` symbol of the id their own slow path passes | range 10,890 of 10,890; single 2,041 of 2,041 (1,036 range and 105 single checks take their range from another check of the same type id and are not counted here) |
| Entry counts read from the code (`cmp xT, #N`): neighbouring type runs of different type ids that overlap; runs that extend past the next type's `__typeid` symbol; checks whose range, read at the check, gives no candidates (it leaves the table, or its first entry is not an entry) | 0 of 2,488 pairs (1,718 of them start with a range run, whose count is read from the code); 0 of 2,489 runs (and every check of a type id reads the same run); 0 of 13,083 checks |
| Linked check and call in the same function | 16,003 of 16,003 |
| Type names equal to `c++filt` | 2,777 of 2,777 |

The two "24,976 of 24,976" rows only show that the jump table itself was decoded right: every entry of this table targets a kallsyms function start, so they would pass for any slice of the table and say nothing about the base and count read at each check. The base and the count are checked by the two rows after them, which can fail: the `__typeid` row checks the first entry, and the entry-count row checks that no count is read too large. For that row, a type's run is the first entry and the number of entries its checks read: range checks whose base was read at the check, with the count from `cmp xT, #N` or the register holding N (1,719 type ids), and single-member checks, one entry (770 type ids); ranges copied from another check of the same id and checks whose slow path passes no type id (the runtime's own, and 11 linked checks on this kernel) are left out. Sorted by first entry, a pair of neighbouring runs of different type ids overlaps when the second starts before the first ends; a run also fails if it extends past the next `__typeid` symbol in the table (2,777 there). A check whose range was read at the check but gives no candidates would drop out of the runs unseen, so it counts as a failure too (all 13,083 such checks, the runtime's and those with no type id included, have candidates; with every count made 100,000 too large in both parsers, 11,042 of them fail). A count read too large fails this row (with the inline range-check parser changed to read every count one too large: 1,244 of 2,487 pairs overlap, 1,319 of 2,515 runs pass a `__typeid` symbol and 3 of 13,085 checks leave the table, while both kallsyms rows stay at 100%); a count read too small would not. For one type at a time, a count one too large fails the row for 1,341 of the 1,719 range types (1,340 by an overlap or a `__typeid` symbol, and the last run in the table by leaving it), and for 1,184 of 1,605 on GKI 5.10, where only the overlap and the table end apply; the rest escape because the entry right after their run is read by no check of the row and has no `__typeid` symbol. The `__typeid` and entry-count rows check consistency (the base and the count read from the code, the type id from the slow path and the kernel's own symbols agree); the last two check the linking (each check and the call it was linked to lie in the same kallsyms function) and the type-name demangler (against `c++filt`). None of these rows proves that a call can reach every candidate. A candidate list is a type filter, as with kCFI.

Limits, read before relying on it:

- **Two kernels were measured.** On Android 12 GKI `gki-certified-boot-android12-5.10-2024-01_r1` ([zip](https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-2024-01_r1.zip), kernel from `boot-5.10.img`; same scanner, same `tools/eval_gki_oldcfi.py`, symbols from vmlinux-to-elf): 14,136 of 20,939 `blr` in kernel text get candidates (67.5%), median 6; all 23,399 distinct candidates start at a kallsyms function and every entry's name matches its target; the jump table ends where its entries end, and the rest up to `__cfi_jt_end` is zero padding. That kernel's kallsyms keeps only one `__typeid` name, so its types show as 64-bit ids and the `__typeid` row of the table above cannot be checked there, nor the `__typeid` half of the entry-count row; its other half finds no overlap: 0 of 2,344 pairs of neighbouring runs (2,345 type ids: 1,605 range, 740 single), every check of an id reading the same run, and 0 of 12,896 checks whose range was read at the check without candidates. The scanner reads only 8-byte `bti c; b` jump-table entries; a build without BTI lays its jump table out differently (we expect 4-byte `b` entries, not checked), and CFIScope does not look for that. x86-64 kernels with this CFI are not read.
- **Module targets are not listed.** A call whose type has no function in the kernel image is checked only by `__cfi_slowpath`; CFIScope shows its type and "no candidate in this image" (2,087 slow-path-only sites on this kernel, the two cases below included). The same applies to a copy of a call that the compiler placed on a check's slow path: it runs only when the pointer is not one of the image's functions of that type. When symbols are available, 241 of these slow-path sites belong to a type that does have functions in the image, which means an inline check was not decoded; those are marked "candidates unknown".
- **Tracepoint and vendor-hook calls are not checked by design** (the kernel calls them without CFI), so there is nothing to read and they stay unresolved, like assembly and `__nocfi` code. These, the slow-path-only calls and the checks this scanner does not decode make up the 7,686 unresolved `blr`. `tools/eval_gki_oldcfi.py` splits them: 1,950 are linked to a check that has no candidates in the image (slow-path-only types, ranges not found); 1,537 sit in tracepoint and vendor-hook iterators (`__traceiter_*`; none of these functions has a `ror #3` or a `__cfi_slowpath` call before the call); 1,015 are the CFI runtime's own calls: an inlined slow path calls `find_check_fn` and then the `__cfi_check` of the kernel or module that holds the pointer through a register; 2,030 look like tracepoint loops inlined into other functions (the probe's function and data read as a pair: `ldar xR, [xM]; ldr x0, [xM, #8]; blr xR`), which are also called without a check; 225 have a `ror #3` or a `__cfi_slowpath` call in the 32 instructions before them (most likely checks this scanner does not decode, such as a `sub` and `ror` more than four instructions apart); and 929 have none of these (most likely calls without a CFI check: assembly, `__nocfi` code, BPF dispatch). The last three numbers come from pattern matches, not from decoding. Leaving out the runtime's own calls, 14,052 of 20,723 `blr` (67.8%) get candidates.
- **Linking is linear.** A check is linked to the first `blr` of its register on the straight path after it (following up to two unconditional branches), or to a later call that reuses it. The register holding the type's first entry is found by walking back from the check, stopping at function starts and at code that does not fall through. Checks whose base or call is found only through the control-flow graph are missed (on this kernel, the walk finds no base for 1,033 checks: 979 of them take the range of another check with the same type id (the table's 1,036 + 105 = 1,141 counts listed sites instead: 954 of these checks, plus 187 slow-path sites whose undecoded inline check got its range the same way; the other 25 guard a call together with a check of the same range and are listed once), 54 have no range; 156 checks have no linked call: 141 are the CFI runtime's own, all the checks inside `__cfi_check`, which Callers leaves out; the other 15 are listed by Callers after the calls and not counted. GKI 5.10: 140, of them 131 in `__cfi_check`).
- **Not run in IDA.** Like the rest of CFIScope, the IDA side was tested only against fake `ida_*` modules (`tests/test_plugin_stub.py`, `tests/test_entry_stub.py`). The scanner is the same code as the command line.

Known-answer test: `tests/fixtures/aarch64-jtcfi.elf` is assembled by `tools/gen_fixtures.py --jtcfi-only` (no compiler): a 4-entry jump table and nine calls (a `b.hs` range check, a `b.lo` check with the base in a register copy and the count in a register, a `b.hi` check, a check hoisted out of a loop, a single-member check, a slow-path-only call, a range check with an unrelated instruction between the subtract and the rotate, the same with the pointer copied to another register there and called through it, and a check whose slow path is inlined), plus two checks with no linked call: one whose pointer is stored and called after a reload, and the check inside a small `__cfi_check` runtime function. `tests/test_oldcfi.py` checks each call's kind, type id, type name and exact candidates against `tests/fixtures/jtcfi_truth.json`, and that Callers counts the seven calls of `f_b`, lists the first unlinked check after them and leaves out the runtime's. The command line gives:

```
$ python3 -m cfiscope tests/fixtures/aarch64-jtcfi.elf --sites
0xffffffc008000088  call_hs+0x28                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080000fc  call_lo+0x48                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000130  call_hi+0x24                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000188  call_hoisted+0x2c                        call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080001dc  call_single+0x20                         call single void (void*)  1 candidate(s): g_one
0xffffffc008000230  call_slow+0x28                           call slowpath type id 0x07ff5a213d37b1a6  no candidate in this image (module functions only)
0xffffffc008000268  call_gap+0x28                            call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080002bc  call_gapcopy+0x28                        call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc00800030c  call_inline+0x24                         call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000358  call_unlinked+0x14                       type check only (call not linked) range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080003c0  __cfi_check+0x24                         CFI runtime check (guards no call) range int (file*, int)  3 candidate(s): f_a, f_b, f_c
```

and its callers of `f_b`: seven calls, then the unlinked check in `call_unlinked`; the runtime's check in `__cfi_check` is left out:

```
$ python3 -m cfiscope tests/fixtures/aarch64-jtcfi.elf --callers f_b
7 call site(s) can reach f_b (+1 type check(s) whose call was not linked, listed last)
0xffffffc008000088  call_hs+0x28                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080000fc  call_lo+0x48                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000130  call_hi+0x24                             call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000188  call_hoisted+0x2c                        call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000268  call_gap+0x28                            call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc0080002bc  call_gapcopy+0x28                        call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc00800030c  call_inline+0x24                         call range int (file*, int)  3 candidate(s): f_a, f_b, f_c
0xffffffc008000358  call_unlinked+0x14                       type check only (call not linked) range int (file*, int)  3 candidate(s): f_a, f_b, f_c
```

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
