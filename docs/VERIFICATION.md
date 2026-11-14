# Verification

What was checked, and how. The summary is in the [README](../README.md#status). The Linux 5.x jump-table CFI has its own measurements in [JTCFI.md](JTCFI.md).

## What the plugin writes into IDA (fake IDA, not a screenshot)

`tools/showcase_ida_stub.py` loads the same kernel's code segments and symbol names into the fake IDA modules of the stub tests, runs the plugin's own IDA layer (Scan, the two lists, the pseudocode comment) and prints what it wrote. These are the exact strings the plugin hands to IDA; real IDA has not run them and draws its own listing around them. The fake database puts every address inside the function of the symbol before it, so the count is 44718 after Yes to "Create functions"; after No (add `--no` to the command below) it is 44695 call and 23 data cross-references, the 23 to 8 candidates inside the function of the symbol before them, and none skipped. In IDA the split after No depends on the functions IDA found. The fake database has no data cross-references of its own (CFIScope's from call sites never count), so no candidate is marked "address taken" here; in IDA, candidates whose address is stored in data are marked and listed first, so the first names in a comment can differ.

```
$ python3 -I tools/showcase_ida_stub.py gki.elf sock_sendmsg+0xb4 tcp_sendmsg
BEFORE (no CFIScope): 0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8
  comment: none; code xrefs from this call: none (indirect)

AFTER Scan kCFI calls (Alt-Shift-K): 13897 sites, 13897 comments, 44718 cross-references in the whole database
0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8    ; kCFI 0x1EBDA935 int (struct socket *, struct msghdr *, unsigned long): 14 candidate(s): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, +8 more
  code xrefs from this call (14): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg

Candidates for this call (Alt-Shift-T): window 'kCFI candidates for the call at 0xFFFFFFC008CC55AC (hash 0x1EBDA935, int (struct socket *, struct msghdr *, unsigned long))'
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

Callers of this function (Alt-Shift-X) on tcp_sendmsg: 3 row(s)
  0xffffffc008cc5778  kernel_sendmsg_locked+0x64  11 candidate(s)
  0xffffffc008e433c8  inet_sendmsg+0x58  11 candidate(s)
  0xffffffc008ead820  inet6_sendmsg+0x58  11 candidate(s)

Pseudocode line of the call (with Hex-Rays):  // CFIScope: 14 candidates of int (struct socket *, struct msghdr *, unsigned long): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg and 9 more
```

## kCFI on real kernels

Real kernel: `gki-certified-boot-android14-6.1-2024-01_r1` (public Google download), aarch64, stripped. Reproduce with `python3 tools/eval_gki.py Image gki.elf` (`Image` and `gki.elf` as in the [walkthrough](../README.md#try-it)). The script scans `Image` with the kernel-code bounds that `gki.elf` names (`_etext`, `_sinittext` and the code areas between them, as described in [HOW_IT_WORKS.md](HOW_IT_WORKS.md)), so it leaves out what the command line leaves out on `gki.elf` and the plugin with those names, and it also prints the numbers for `Image` alone.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,897, using 4,184 distinct type hashes, in 0.8 to 3.1 s (see below) |
| Sites with at least one candidate | 11,960 (86.1%) |
| Sites with exactly one candidate | 1,695 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,091 / 8,998 |
| kCFI hashes named by C type from the kernel's own BTF (`python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000`) | all 4,184 (13,897 of 13,897 sites) from 29,786 BTF prototypes (128,248 types; both counts agree with `bpftool btf dump`); no hash given two types |
| Candidate start precision: distinct candidates that begin exactly at a kallsyms function symbol (symbols restored by [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf); besides scoring, they bound kernel code, which leaves out 6 candidates in `.rodata`). This checks that candidates are real function starts, not that a call reaches them | 30,357 of 30,561 (99.33%) |

Scan time: the script prints it for the scan with the bounds: 0.8 to 3.1 s in 18 runs (median 1.6 s). The whole command also reads the symbols of `gki.elf` and scans `Image` a second time without the bounds: 2.2 to 6.0 s wall-clock in the same runs (median about 4 s), of which 2.1 to 2.6 s CPU time. Measured on an Intel i9-13900H laptop under WSL2 (4 cores) while other jobs were running (load average 3.9 to 6.5), in single-threaded Python; the wall-clock time followed the load. Expect a different figure on another machine.

The 6 candidates left out are in `.rodata`: the hash value occurs in strings or other data (hash `0x4f5f504f` is the text `OP_O`; it gave a vendor-hook call 4 "candidates" in strings). Without the bounds (`Image` alone) they made 30,567 distinct candidates, 30,357 at a kallsyms function (99.31%), and Scan added 6 cross-references to them (in the fake IDA modules of the showcase above; 44,724 then, 44,718 now). The 204 candidates that do not start at a kallsyms function are all in kernel text (199) or init text (5), and each begins with code after its hash word: 166 are `mov x0, #-ENOSYS; ret` stubs of the syscall-handler type, 12 bytes apart in runs after named handlers such as `sys_ni_syscall` (they look like the weak `COND_SYSCALL` stubs of syscalls this kernel does not build); 24 return at once (`ret`, or one `mov` of a constant into `w0`/`x0` and `ret`); 11 start with a `paciasp` prologue; 3 are other short code. The kallsyms names that vmlinux-to-elf restored include none of them; we have not checked them against another symbol source.

The 1,937 sites with no candidate carry a hash that no function in this image has; a likely reason is callees that live in loadable modules, not checked one by one.

Newer aarch64 GKI kernels, measured the same way: [gki-certified-boot-android15-6.6-2025-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android15-6.6-2025-01_r1.zip) and [gki-certified-boot-android16-6.12-2025-06_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android16-6.12-2025-06_r1.zip), kernel extracted with `tools/extract_bootimg.py`, symbols restored by vmlinux-to-elf, then `python3 tools/eval_gki.py --base 0xffffffc080000000 Image gki.elf` (these kernels start at a different address than 6.1).

| Measure | android15-6.6 | android16-6.12 |
|---|---|---|
| Indirect call sites found (distinct type hashes) | 14,694 (4,466) | 16,164 (4,626) |
| Sites with at least one candidate | 12,917 (87.9%) | 14,232 (88.0%) |
| Sites with exactly one candidate | 1,975 | 2,019 |
| Median candidates per site with at least one (over all sites) | 6 (5) | 6 (5) |
| Sites with 1 to 8 candidates / 1 to 16 | 7,435 / 9,681 | 8,404 / 10,684 |
| Largest candidate list | 1,536 | 1,580 |
| Candidate start precision (distinct candidates at a kallsyms function symbol) | 33,743 of 33,960 (99.36%) | 35,248 of 35,480 (99.35%) |
| kCFI hashes named by C type from the kernel's own BTF (`python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc080000000`) | 4,466 of 4,466 (100%), all 14,694 sites | 4,621 of 4,626 (99.8%), 15,964 of 16,164 sites, all as integer-normalized hashes (Rust is enabled); the 5 left, 200 sites, are all inside Rust functions of its `core` library (`core::fmt`, `core::error`), whose types BTF does not describe |

Left out as outside kernel code: 7 candidates on 6.6 and 1 on 6.12, all in `.rodata`. The one on 6.12 is not in a string: the word `cfi_bpf_hash` holds the type hash `0xf6292f28` on purpose, so the word after it, `cfi_bpf_subprog_hash`, looked like a function of that type (both in the `ro_after_init` data, which lies inside `__start_rodata`..`__end_rodata`). It was in the lists of the 187 calls of that type, each 7 long; without the bounds (`Image` alone) the 6.12 median is 7 and its precision row 35,248 of 35,481. Of the candidates not at a kallsyms function (217 on 6.6, 232 on 6.12), 181 and 189 are `-ENOSYS` stubs as on 6.1. On 6.6 and 6.12 the idmap code (`__idmap_text_start`..`__idmap_text_end`) lies between `_etext` and `_sinittext` and holds 2 candidates, which is why the code areas named there are kept.

Real x86-64 kernel: the public GKI prebuilt `kernel-6.1` from [kernel/prebuilts/6.1/x86-64](https://android.googlesource.com/kernel/prebuilts/6.1/x86-64) (6.1.84), scored against its own `System.map`, which names a `__cfi_` preamble for each protected function. Reproduce with `python3 tools/extract_bzimage.py kernel-6.1 vmlinux`, then `python3 tools/eval_gki_x86.py vmlinux System.map`.

| Measure | Result |
|---|---|
| Indirect call sites found | 13,770, using 4,257 distinct type hashes |
| Sites with at least one candidate | 11,833 (85.9%) |
| Sites with exactly one candidate | 1,652 |
| Median candidates per site with at least one candidate (over all sites, unresolved included: 4) | 6 |
| Sites with 1 to 8 candidates / 1 to 16 | 7,093 / 8,601 |
| Distinct candidates that are a `__cfi_`-protected function | 32,393 of 33,015 (98.12%) |

The other 622 candidates: 244 sit at weak (`W`) symbols in the map, mostly syscall entry stubs such as `__ia32_sys_msgctl`, and 378 are at no symbol in the map; those 378 were not checked one by one. This `vmlinux` comes from a bzImage, whose build strips its symbols, so the table is measured without kernel-code bounds (re-run with this version: the same figures). The script's last line scans it again with the bounds its `System.map` names, as the command line would for a `vmlinux` that kept its symbols: 0 of the 33,015 candidates are left out, and no list changes. The map names no function between `_etext` and `_sinittext` (`.rodata` and `.data` lie there), and x86-64 exit text, whose bounds it does not name, comes after init text and is kept. Only 63.50% of the protected functions appear as candidates, which is expected for a kernel image alone: a function's hash only matches when some call site in the image uses that type.

## Loadable modules (.ko)

Real modules: three GKI `system_dlkm` modules from the public prebuilts repository [kernel/prebuilts/6.1/arm64](https://android.googlesource.com/kernel/prebuilts/6.1/arm64) at commit `ad5f1ad22dd4` (head of `android14-qpr3-release`; kernel build 11484633, `6.1.68-android14-11-ga7f647f49daf-ab11484633`, the vermagic of all three), with the kernel of the same build from the same commit (`kernel-6.1`, a raw `Image`; symbols restored with vmlinux-to-elf as `kernel-6.1.elf`). This is a later build of the same android14-6.1 branch than the 2024-01 kernel above. Each file is `https://android.googlesource.com/kernel/prebuilts/6.1/arm64/+/ad5f1ad22dd47c7b244ec697c5e61f90783a06c2/<name>?format=TEXT` (base64 of the file):

| File | sha256 |
|---|---|
| `zram.ko` (62,073 bytes) | `e87f95a05a5f3517c9179dcc27d9402e3f3c824032fbca4a690f818b4f2c488c` |
| `8021q.ko` (127,785 bytes) | `57acf7dff06168d04bcd616eb314e199e8ddb8125150fe540eccd021299a57c4` |
| `bluetooth.ko` (1,405,257 bytes) | `d9beb2a2c000bebfb7cdec2a1374364f5339d5541e4bee182314d62299f3b0e9` |
| `kernel-6.1` (34,699,776 bytes) | `8bba13cac33e7c2cf8dcd3b2b2d3bff350c975a4b754b59c6b57289ebee8c08a` |

```
python3 -m cfiscope bluetooth.ko                      # summary
python3 -m cfiscope bluetooth.ko --sites              # every call site, candidates in the module
python3 -m cfiscope bluetooth.ko --sites --btf kernel-6.1 --with kernel-6.1.elf   # + C types, + the kernel's functions
python3 -m cfiscope bluetooth.ko --callers ecdh_compute_value --with kernel-6.1.elf
```

| Measure | `zram.ko` | `8021q.ko` | `bluetooth.ko` |
|---|---|---|---|
| Loads (ET_REL; executable sections laid out from 0x100000, names from `.symtab`) | yes | yes | yes |
| Named functions (`STT_FUNC` in `.symtab`) | 41 | 56 | 1,255 |
| kCFI call sites (distinct hashes) | 0 (0) | 6 (5) | 253 (48) |
| `blr` in the module's code (counted separately) | 0 | 6 | 253 |
| Sites with a candidate in the module / with none | - | 5 / 1 | 234 / 19 |
| Sites with exactly one candidate in the module | - | 3 | 16 |
| Median / largest list in the module (sites with candidates) | - | 1 / 2 | 12 / 95 |
| `--with kernel-6.1.elf` (unreleased): sites with candidates in the kernel | - | 4 | 23 |
| `--with`: sites with none in the module but some in the kernel / in neither | - | 0 / 1 | 6 / 13 |
| Hashes named by C type, `--btf kernel-6.1` (the module's split BTF on the kernel's, unreleased) | - | 5 of 5 | 48 of 48 (7 of 48 from the kernel's BTF alone) |

Every `blr` in the two modules that have any is a kCFI-checked call, and the scan finds each one (their `br` are switch jump tables, which kCFI does not check). No relocation touches a check or a type hash: of the 382, 467 and 10,583 relocations in the three modules' code, none falls inside a check sequence or on a candidate's hash word (the 1, 1 and 49 that fall on the word before a function symbol are `R_AARCH64_CALL26` on the `bl` ending the function before, which has no hash), so the scan reads them from the file as they are. Each module scans in under 0.1 s; with `--with` about 0.6 s and 100 MB, with `--btf` 1.7 to 3.6 s and about 170 MB (whole command, wall clock).

What the lists mean on a module: a module calls mostly through operation tables that the kernel or other modules fill, so its own functions are only part of the answer. In `8021q.ko`, 5 of the 6 lists include the calling function itself: `vlan_dev_hard_header+0x120` calls the `header_ops->create` of the device under the VLAN, and the module's candidates are `vlan_passthru_hard_header` and `vlan_dev_hard_header` (right for a VLAN on a VLAN); `--with` adds the kernel's `eth_header`, `ipgre_header` and `ip6gre_header`. In `bluetooth.ko`, `compute_ecdh_secret+0x160` (type `int (struct kpp_request *)`) has no candidate in the module and one in the kernel, `ecdh_compute_value`. Of the 13 sites with no candidate in either, 6 share hash `0x4306bc2d`, `void (struct hci_dev *, unsigned int)`, whose BTF example is `hci_dev.notify`, a callback that HCI drivers such as `btusb` set; they are separate modules and were not scanned. The kernel candidates are the same with the 2024-01 `gki.elf` of the walkthrough (another build of the same branch): all 2,507 kernel entries of the 253 `bluetooth.ko` sites, and the same counts for both modules. The module's split BTF is refused on the 2024-01 `Image` (another build: its names land inside the other kernel's strings), with a warning, and the hashes are then named from that kernel's BTF alone.

Problems found on these modules, fixed (unreleased; each with a test that failed first):
- `zram.ko` (0 `blr`) was reported as "probably built without Clang kCFI ... for example by GCC". Now: "the code makes no indirect call (no blr instruction) ... this does not tell whether it was built with kCFI". The Scan warning and the headless runner say the same (fake IDA modules only).
- A module's BTF is split BTF (it continues its kernel's), so the scan said "the input's BTF is unreadable", and `--btf <kernel>` named only the types in the kernel's BTF (7 of 48 in `bluetooth.ko`). Now the module's BTF is read on top of `--btf` (48 of 48), and without `--btf` the scan says to add it.
- A call whose callee is in the kernel had no way to show it. Now `--with VMLINUX` (command line only) lists the kernel's functions of each call's type next to the module's.

The IDA layer on a module: `tools/showcase_ida_stub.py` runs it on the real `bluetooth.ko` and `8021q.ko` through the fake `ida_*` modules of the tests: 253 sites, 253 comments and 1,176 cross-references for `bluetooth.ko`, 6 / 6 / 7 for `8021q.ko`, all to the module's own functions; a call with none says "no implementation in this image". It has not run in real IDA. Inside IDA there is no `--with`, and a module's split BTF is not read (no types shown).

## Known-answer objects and the test suite

Known-answer objects: `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the table of signatures and implementations that `tools/gen_fixtures.py` wrote into the source; function offsets come from the compiled objects. `tests/test_cli.py` checks that `python3 -m cfiscope` lists, by symbol name, exactly the known candidate sets for the same objects, and that bad input gives a clear error.

Run all of these with `python3 -m unittest discover -s tests` (no IDA needed). `tests/test_plugin_stub.py` runs the IDA layer and `tests/test_entry_stub.py` the plugin wiring (menus, right-click hooks, rescan after a rebase, pseudocode comments and the pseudocode-line lookups on a fake decompiler, restoring the scan after the database is reopened on a fake netnode) against fake `ida_*` modules, and `python3 tests/check_ida_api.py <dir with ida_*.pyi>` (the stubs ship in the `idapro` pip package) confirms all 109 IDA API names used, including the decompiler methods the pseudocode hook and lookups call, `func_t.tailqty`, the `netnode` methods of the scan marker and the `UI_Hooks` events that hook a decompiler loaded later, exist in the official stubs; `python3 tests/check_ida_names.py <stub dir>...` checks that the 73 `ida_*` / `idc` names alone also exist in older stubs (0 missing in those of IDA 9.1, 9.2, 9.3 and 9.4: PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11). None of these is a test in real IDA.

Not verified: behaviour inside real IDA.
