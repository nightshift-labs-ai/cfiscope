# Verification

What was checked, and how. The summary is in the [README](../README.md#status). The Linux 5.x jump-table CFI has its own measurements in [JTCFI.md](JTCFI.md).

## What the plugin writes into IDA (fake IDA, not a screenshot)

`tools/showcase_ida_stub.py` loads the same kernel's code segments and symbol names into the fake IDA modules of the stub tests, runs the plugin's own IDA layer (Scan, the two lists, the pseudocode comment) and prints what it wrote. These are the exact strings the plugin hands to IDA; real IDA has not run them and draws its own listing around them. The fake database puts every address inside the function of the symbol before it, so the count is 49578 after Yes to "Create functions"; after No (add `--no` to the command below) it is 49555 call and 23 data cross-references, the 23 to 8 candidates inside the function of the symbol before them, and none skipped (re-run 2026-11-14 in review s197; the code before the slot ranking, cfi193 `8e2089f`, gives 44718, and 44695 and 23, re-run the same day; the 4,860 more go to the candidates stored at the member's offset in 1,142 lists of more than 16, see [Candidates stored in a matching slot](#candidates-stored-in-a-matching-slot)). In IDA the split after No depends on the functions IDA found. The fake database has no data cross-references of its own (CFIScope's from call sites never count), so no candidate is marked "address taken" here. The candidates stored in a slot of the call's member come first in both (the plugin reads the slots from the input file), and the Callers rows put the calls whose member slot holds `tcp_sendmsg` first and say so; in IDA, the address-taken candidates would come first within each group, so the first names in a comment can differ.

```
$ python3 -I tools/showcase_ida_stub.py gki.elf sock_sendmsg+0xb4 tcp_sendmsg
BEFORE (no CFIScope): 0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8
  comment: none; code xrefs from this call: none (indirect)

AFTER Scan kCFI calls (Alt-Shift-K): 13897 sites, 13897 comments, 49578 cross-references in the whole database
0xffffffc008cc55ac  sock_sendmsg+0xb4  blr x8    ; kCFI proto_ops.sendmsg 0x1EBDA935 int (struct socket *, struct msghdr *, unsigned long): 14 candidate(s): in a proto_ops.sendmsg slot: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, +7 more; same type only: 1 more
  code xrefs from this call (14): tun_sendmsg, sock_no_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg

Candidates for this call (Alt-Shift-T): window 'kCFI candidates for the call at 0xFFFFFFC008CC55AC (proto_ops.sendmsg, hash 0x1EBDA935, int (struct socket *, struct msghdr *, unsigned long))'
  0xffffffc00897842c  tun_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008d8cd98  netlink_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008e43370  inet_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008ea71dc  unix_stream_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008ea9910  unix_dgram_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008eaa360  unix_seqpacket_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008ead7c8  inet6_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008f24f88  packet_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008f2a988  packet_sendmsg_spkt  stored in a proto_ops.sendmsg slot
  0xffffffc008f2dc00  pfkey_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008f6b58c  vsock_dgram_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008f6cc48  vsock_connectible_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008f72e10  xsk_sendmsg  stored in a proto_ops.sendmsg slot
  0xffffffc008cd2ac4  sock_no_sendmsg

Callers of this function (Alt-Shift-X) on tcp_sendmsg: 3 row(s)
  0xffffffc008e433c8  inet_sendmsg+0x58  proto.sendmsg, 11 candidate(s), stored in a proto.sendmsg slot
  0xffffffc008ead820  inet6_sendmsg+0x58  proto.sendmsg, 11 candidate(s), stored in a proto.sendmsg slot
  0xffffffc008cc5778  kernel_sendmsg_locked+0x64  proto_ops.sendmsg_locked, 11 candidate(s), same type only

Pseudocode line of the call (with Hex-Rays):  // CFIScope: proto_ops.sendmsg, 14 candidates of int (struct socket *, struct msghdr *, unsigned long): in a proto_ops.sendmsg slot: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg and 8 more; same type only: 1 more
```

### The call-site list

Scan ends by opening a list of every call site (also **CFIScope: List kCFI call sites**; new in 0.1.23). Add `--list` to the command above for its row count, the time its rows took to build and the row of the call next to the command line's `--sites` line for it (re-run 2026-11-14 in review s197, byte for byte):

```
Call-site list (opens after Scan; CFIScope: List kCFI call sites): window 'CFIScope: 13,897 kCFI call sites', 13897 rows, built in 0.12 s
  columns: Address | Function+off | Member | Type | Candidates | First candidates
  row 11703:  0xffffffc008cc55ac | sock_sendmsg+0xb4 | proto_ops.sendmsg | int (struct socket *, struct msghdr *, unsigned long) | 14 | in a proto_ops.sendmsg slot: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, +7 more; same type only: 1 more
  command line --sites:  0xffffffc008cc55ac  sock_sendmsg+0xb4                        call proto_ops.sendmsg hash 0x1ebda935 (int (struct socket *, struct msghdr *, unsigned long))  14 candidate(s): in a proto_ops.sendmsg slot: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, +5 more; same type only: 1 more
```

All 13,897 rows were also compared with `python3 -m cfiscope gki.elf --sites --json --max-list 6` (address, function and offset, member, type, count, first six names): 0 differ (with the Member column, which is filled in 9,764 rows, the calls of the [struct-member table](#struct-members-aarch64) with at least one member). `tests/test_showcase.py` does the same for the 21 rows of each Quick-try fixture, and for all 13,897 rows of GKI 6.1 when `CFISCOPE_GKI_ELF` names `gki.elf` (skipped otherwise; 6.1 s and 363 MB here with the Member column, 7.2 s and 426 MB with the slot ranking, which reads the input file once more, re-run 2026-11-14, and 9.0 s and 431 MB in review s197, one run under GNU `time`; its Member check is the `--sites` text: the member, or `one of N members (...)` with the first three). The rows are built at once, so that IDA can sort and filter them: 0.12 to 0.15 s over three runs (load average about 2 on 4 cores), 0.09 to 0.10 s over three runs with the Member column (review s195, load average about 1.3), 0.11 to 0.12 s with the slot ranking (three runs, load average about 0.5 to 1.1), and 0.12 to 0.14 s after review s197 against 0.11 to 0.14 s for `7e11e09` (three runs each, alternating, load average about 2), since each candidate's "address taken" test is asked once per list (30,561 distinct candidates in 403,385 list entries). In real IDA those tests and the names are IDA API calls; that time was not measured. As in the comments, the fake database marks no candidate "address taken", so within each group the first names here are in address order; in IDA, address-taken candidates would come first within each group (by design; not run in IDA). The test's expected First candidates follow the command line's `slot_backed` values and counts: every name in its group when the list has 6 or fewer, else up to 6 slot-backed names (at the member's offset, then by array stride) and the rest of each group counted.

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

## Struct members (aarch64)

New in 0.1.23; aarch64 only. For each kCFI call, CFIScope walks back from the check (`ldur wT, [xN, #-4]`) to the instruction that wrote `xN`. When that is a 64-bit `ldr xN, [xM, #imm]` or `ldur xN, [xM, #imm]` (reached through `mov` copies, and past `cbz xN`, which reads `xN` but does not write it), the immediate is the byte offset of the field the pointer came from. The member map holds every function-pointer member in BTF under (kCFI hash of its prototype, plain and integer-normalized; byte offset): the members of named structs and unions and of those a typedef names, and also the members of embedded structs and unions (anonymous or not) and of arrays of up to 64 elements, at their offset in the outer struct and under the name of the struct that declares them. A pointer to a function pointer (`const iw_handler *standard`) is not a member of the function's type. A call is named when exactly one member matches. When several match, all are listed (`one of N members (...)`).

The walk gives no offset when:
- it leaves straight-line code (`ret`, `b`, `bti c` and the like within 16 words);
- `xN` comes from anything but those loads (`ldp`, a register offset, an index writeback, a call that clobbers it);
- the base is `sp` or `x29` (a pointer spilled to the stack);
- the base was set by `adrp` on the straight path walked back from the load (the immediate is then the low 12 bits of a global's address). An `adrp` further back, or behind a branch, is not seen: a linear scan back to the nearest `bti c` or `paciasp` finds an `adrp` as the base's last write for 20 decoded offsets on GKI 6.1 (23 on 6.6, 34 on 6.12), for example `__delay+0x84` at 1592 (its `adrp x21` is in the function's first block, behind a `b`). 1 of them on each kernel matches a member: `tracing_set_tracer+0x1d0` (`tracer.init`, offset 8) on 6.1, and on 6.6 and 6.12 a `__kvm_nvhe_handle_trap` call with several members;
- a `b`, `b.cond`, `cbz`/`cbnz` or `tbz`/`tbnz` in the same code lands between the load and the check (another path may load the pointer from elsewhere). A `br` through a register, as in a switch table, is not followed.

Reproduce with the summary of `python3 -m cfiscope gki.elf`, line `kCFI calls through a struct member: ...` (re-run 2026-11-14 on each kernel's `gki.elf`, symbols restored by vmlinux-to-elf; the 6.6 and 6.12 kernels of the tables above):

| Measure | GKI 6.1 | GKI 6.6 | GKI 6.12 |
|---|---|---|---|
| kCFI call sites | 13,897 | 14,694 | 16,164 |
| Load offset decoded | 11,905 | 12,126 | 12,623 |
| At least one BTF member of the call's type at that offset | 9,764 | 9,675 | 9,984 |
| Exactly one member | 8,937 | 8,821 | 9,284 |
| (hash, offset) pairs in the member map | 15,660 | 17,190 | 17,765 |
| Time: member map / walk and lookup (best of 3, in-process) | 0.10 s / 0.29 s | 0.11 s / 0.30 s | 0.13 s / 0.31 s |

The whole `--callers tcp_sendmsg` command on 6.1 took 2.94 to 3.11 s, and 2.31 to 2.68 s with the code before this change (three runs each, alternating; load average about 2.5 on the machine named above). Re-run in review s195: 3.03 to 3.27 s, against 2.30 to 2.44 s for 458eeeb (load average 0.7 to 1.0), and after the merge into cfi193 2.73 to 2.89 s, against 2.19 to 2.25 s for 5c6ddbf (load average 0.4 to 0.8); 0.5 to 0.8 s longer run for run. Maximum resident memory of the summary command (GNU `time`): 301,772 KB, 236,504 KB before (6.6: 319,264 / 249,752 KB; 6.12: 340,944 / 273,992 KB).

Known answers (`tests/test_members.py`, run when `CFISCOPE_GKI_ELF` names the 6.1 `gki.elf`):

| Call | Load offset | Member |
|---|---|---|
| `sock_sendmsg+0xb4` | 136 | `proto_ops.sendmsg` |
| `kernel_sendmsg_locked+0x64` | 216 | `proto_ops.sendmsg_locked` |
| `inet_sendmsg+0x58` | 104 | `proto.sendmsg` |
| `inet6_sendmsg+0x58` | 104 | `proto.sendmsg` |

On 6.6 and 6.12 the same four calls (`sock_sendmsg+0xc0` and `+0xbc`, `kernel_sendmsg_locked+0x60`) get the same members; `proto_ops.sendmsg_locked` is at offset 208 there. Of the 827 calls on 6.1 with several members, 439 have 2 and none more than 8.

An earlier prototype from our own internal review (s193; not in this repository) found 7,608 offsets, 5,222 matches and 4,894 single matches on 6.1. Re-running its rules shows why it found fewer: it stopped at any instruction whose first register field was `xN`, so 4,808 of its walks ended at a `cbz xN` (a null check such as `if (ops->fn)`), which writes nothing. This code walks past those, follows `mov` copies, reads `ldur` too, and refuses the cases listed above. Its member map also takes in embedded named structs and arrays, under the declaring struct's name, so `proto_ops.sendmsg` stays one name wherever a `struct proto_ops` is embedded.

What a name means: BTF has exactly one function-pointer member of the call's type at the loaded offset. That the call really goes through it is not proven, because the base register's type is not known:
- A load at offset 0 from a pointer to a lone function pointer (`(*pp)()`) looks like a struct's first member. On 6.1, 844 named calls load from offset 0, 771 of them with one member.
- A pointer cast from another type, or a constant index into an array of function pointers, is matched like a member too.
- A pointer the compiler has already moved into the struct is read from the wrong origin: `gic_enable_of_quirks+0x54` (GKI 6.6, 6.12) keeps a pointer to `gic_quirk.init` (byte 24 of the 40-byte `struct gic_quirk`) in a loop (`add x22, x1, #24`) and loads `[x22, #0]`, so it is named `vhost_task.fn` (the one member of the call's type, `_Bool (void *)`, at offset 0). On 6.12 `gic_enable_quirks+0x80` gets the same name the same way.

Modules: `bluetooth.ko --btf kernel-6.1` (the files of the next section) decodes 222 of 253 load offsets and names 216 calls, each with exactly one member, for example `bt_sock_recvmsg+0x10c` -> `bt_sock.skb_msg_name`. The IDA plugin does not read a module's split BTF, so it shows no member there.

x86-64 is not read. There the pointer is loaded by a `mov` before the call to the retpoline thunk; that is a follow-up. x86-64 output is unchanged: the x86-64 Quick-try fixture's `--sites` output is byte-identical to that of the code before (a test).

The IDA side was checked against fake IDA modules only, never in IDA:
- the comment (`kCFI proto_ops.sendmsg 0x1EBDA935 int (struct socket *, ...): 14 candidate(s): ...`);
- the pseudocode comment (`CFIScope: proto_ops.sendmsg, 14 candidates of ...`);
- the Candidates window title and the Callers rows (see the showcase block at the top);
- the Member column of the call-site list.

No new IDA API name is used. Tests in `tests/test_members.py`:
- the walk on hand-made instruction words;
- the member map on crafted BTF: an array of function pointers, an array of 24-byte structs (each element at its own offset), a named member of anonymous type (`S.ops.fn`), a struct nested in itself, a pointer to a function pointer;
- the member map on a new fixture, `tests/fixtures/kcfi_members.c`, built by `zig cc -fsanitize=kcfi` for aarch64 with its own BTF. `a_ops.send`, `b_ops.send` and `b_ops.recv` share a type at offsets 16, 0 and 24; `c_ops.poll` and `d_ops.poll` share one at the same offset. It also has an embedded struct, an anonymous union, a call through a parameter and one through a global. The true offsets are read from `offsetof` constants compiled into the object;
- the command line, JSON and fake-IDA strings;
- that calls with no decoded load or no member print exactly what the code before printed (golden lines from it on the fixture and on GKI 6.1, and the `--sites` output of four older fixtures by sha256).

## Candidates stored in a matching slot

New in 0.1.23; aarch64, for the calls with a struct member of the [previous section](#struct-members-aarch64). How it works: [HOW_IT_WORKS.md](HOW_IT_WORKS.md#candidates-stored-in-a-matching-slot). A candidate is slot-backed for a call when the image's static data stores its address at the call's member offset inside an object (the nearest `OBJECT` symbol at or below the word; kallsyms names them on GKI), or at that offset modulo the size of a struct with that member there (an array of such structs; not an 8-byte struct, which every aligned word would match; leaving it out took 4 of 5,605 calls on GKI 6.1 out of the slot-backed ones). Slot-backed candidates are listed first; no candidate is removed.

Reproduce with `python3 tools/eval_gki.py Image gki.elf` (6.1) and `python3 tools/eval_gki.py --base 0xffffffc080000000 Image gki.elf` (6.6, 6.12), the lines from `slots:` on (re-run 2026-11-14; the kernels of [kCFI on real kernels](#kcfi-on-real-kernels)). The script names the members from the `Image`'s code and BTF and reads the slots from `gki.elf`; the command line's summary line `kCFI calls with a candidate stored in a slot of their struct member: ...` on `gki.elf` gives the same first counts.

| Measure | GKI 6.1 | GKI 6.6 | GKI 6.12 |
|---|---|---|---|
| Distinct kCFI candidates stored in a static object (any offset) | 17,959 of 30,561 | 20,739 of 33,960 | 21,350 of 35,480 |
| Calls with a struct member and at least one candidate | 8,600 | 8,511 | 8,729 |
| ... with at least one slot-backed candidate | 5,601 | 5,598 | 5,837 |
| ... of them also with candidates of the same type only (the first part is shorter) | 3,818 | 3,863 | 4,037 |
| ... of them with every candidate slot-backed | 1,783 | 1,735 | 1,800 |
| ... of them whose slot-backed candidates all match only modulo a struct size | 395 | 381 | 222 |
| Median list / median slot-backed part (calls with one) | 6 / 2 | 7 / 2 | 6 / 2 |
| Lists of more than 16 / of them with 16 or fewer slot-backed | 1,625 / 1,155 | 1,669 / 1,177 | 1,698 / 1,204 |
| Largest list (its slot-backed part) | 1,458 (25) | 1,536 (26) | 1,580 (33) |
| Largest slot-backed part | 1,318 | 1,301 | 766 |
| Time: slot scan of `gki.elf` / ranking (in-process, one run) | 0.24 s / 0.06 s | 0.24 s / 0.06 s | 0.53 s / 0.08 s |

Known answers (`tests/test_slots.py`, run when `CFISCOPE_GKI_ELF` names the 6.1 `gki.elf`; the same on 6.6 and 6.12 by the script):

| Call | Member | Candidates | Slot-backed |
|---|---|---|---|
| `sock_sendmsg+0xb4` | `proto_ops.sendmsg` | 14 | 13: all but `sock_no_sendmsg`, which is stored nowhere in the image (module ops tables use it) |
| `kernel_sendmsg_locked+0x64` | `proto_ops.sendmsg_locked` | 11 | 1: `tcp_sendmsg_locked` (at byte 216 of `inet_stream_ops` and `inet6_stream_ops`) |
| `inet_sendmsg+0x58`, `inet6_sendmsg+0x58` | `proto.sendmsg` | 11 | 7: `tcp_sendmsg`, `raw_sendmsg`, `udp_sendmsg`, `ping_v4_sendmsg`, `udpv6_sendmsg`, `rawv6_sendmsg`, `ping_v6_sendmsg` |

`tcp_sendmsg` is stored at byte 104 of `tcp_prot` and `tcpv6_prot` only, so it is slot-backed for the two `proto.sendmsg` calls and of the same type only for `kernel_sendmsg_locked+0x64`. The largest slot-backed part on 6.1 is `dev_attr_show+0x34` (`device_attribute.show`): 1,318 of its 1,359 candidates, the `show` functions of the kernel's static device attributes. The 711-candidate `trace_event_functions.trace` calls (such as `print_trace_fmt+0x120`) keep 695.

Cost on the command line: `python3 -m cfiscope gki.elf --callers tcp_sendmsg` took 3.22 to 3.42 s, against 2.92 to 3.16 s for the code before (cfi193 `8e2089f`; three runs each, alternating, load average 1.7 to 2.7), and 310,476 to 310,696 KB maximum resident memory against 301,780 to 301,824 KB (GNU `time`). The ranking runs only when some call has a struct member (aarch64 with BTF); x86-64 output is unchanged.

Modules: a `.ko`'s data holds zeros where pointers go, so its 64-bit absolute relocations (`R_AARCH64_ABS64`, `R_X86_64_64`) into allocated data sections are read instead, each in the `OBJECT` symbol of its section that holds it. `bluetooth.ko --btf kernel-6.1` (the files of the next section): 128 calls with a slot-backed candidate, 82 of them with candidates of the same type only too; 314 of its 603 distinct candidates are stored in a static object of the module (1.98 s, 207,708 KB for the summary). For example `hci_conn_failed+0xbc` (`hci_cb.connect_cfm`, 12 candidates) lists `l2cap_connect_cfm`, `sco_connect_cfm` and `iso_connect_cfm` first. `bt_sock_recvmsg+0x10c` keeps `l2cap_skb_msg_name` without a slot: L2CAP sets that pointer at run time. The IDA plugin does not read a module's split BTF, so it names no member and ranks nothing there.

An earlier prototype from our own internal review (s193; not in this repository) measured on 6.1 the same 17,959 of 30,561 stored candidates, but 3,168 calls with a slot-backed candidate, 2,071 shorter lists, a median slot-backed part of 3 (lists of 6), 575 lists going from more than 16 to 16 or fewer, and a largest slot-backed part of 695. It ranked only the calls its own member walk named (5,222, against 9,764 here, see the previous section), took the struct size from the member's declaring struct, and counted 8-byte structs for the modulo.

The IDA side (fake IDA modules only, never in IDA): the order of `ranked()` (slot-backed, then address taken), the comment and pseudocode comment (`... 14 candidate(s): in a proto_ops.sendmsg slot: tun_sendmsg, ..., +7 more; same type only: 1 more`), the Candidates notes (`stored in a proto_ops.sendmsg slot`), the call-site list's First candidates, and the 16-cross-reference cap: a list of more than 16 now gets cross-references to its slot-backed candidates when there are at most 16 of them (1,155 lists on GKI 6.1, 50,048 cross-references in all against 44,718; Scan's sentence says `none for lists of more than 16, except to their candidates stored in a slot of the call's member in 1,155 of them`). Remove annotations now looks at the lists of more than 16 too. The plugin reads the slots from the input file, and only when the database has the file's layout (each code range of the file starts with the same bytes at the same address); for a `.o` or `.ko` that depends on where IDA puts its sections, which was not checked in IDA. No new IDA API name.

Tests in `tests/test_slots.py` (20 at first, 3 of them need `CFISCOPE_GKI_ELF`; 38 now). 19 were written before the code: on the code before, the run reported 11 failures and 9 errors (subtests counted; the GKI class failed in its setup), and the two that check that nothing is dropped and that nothing is ranked without the input file passed there, as they should. The 20th (an 8-byte struct) came with that rule and fails without it:
- a new fixture, `tests/fixtures/kcfi_slots.c` (`python3 tools/gen_fixtures.py --slots-only`, zig cc kCFI for aarch64 with its own BTF): `net_ops.xmit`, `file_ops.write` and `file_ops.read` share a type, so each call has the same 6 candidates, and only the functions stored in a slot of the member it loads come first (`net_xmit_c` only through the modulo: byte 40 of `net_tbl`, `struct net_ops` being 24 bytes); `runtime_only` is stored by code at run time and stays in every list;
- nothing is dropped: on the fixture the same candidates as with `--no-btf`, and on GKI 6.1 every site's list unchanged and `slot_first()` a permutation of it;
- the command line (`--sites`, `--targets`, `--json`, summary), the matching on hand-made offsets (equal, modulo, an 8-byte struct, the order inside each group), the containing object, and the fake-IDA order, comment, notes, call-site list and cross-reference cap;
- the GKI 6.1 known answers above.

Mutations of commit `3a0c728`, each run against `tests/test_slots.py`: comparing with the member offset plus 8 (18 failures, with `CFISCOPE_GKI_ELF` set), filtering instead of ranking in `core.slot_first()` (8 failures and 1 error, with it set), and the same in the IDA layer's `ranked()` (6 failures, without it). Each was caught. The existing `tests/test_members.py`, `test_showcase.py` and `test_draw_hero.py` expectations were updated to the new order and text; `docs/img/hero.svg` and `hero.png` were redrawn (the top panel lists `sock_no_sendmsg` last now).

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
| `--with kernel-6.1.elf`: sites with candidates in the kernel | - | 4 | 23 |
| `--with`: sites with none in the module but some in the kernel / in neither | - | 0 / 1 | 6 / 13 |
| Hashes named by C type, `--btf kernel-6.1` (the module's split BTF on the kernel's) | - | 5 of 5 | 48 of 48 (7 of 48 from the kernel's BTF alone) |

Every `blr` in the two modules that have any is a kCFI-checked call, and the scan finds each one (their `br` are switch jump tables, which kCFI does not check). No relocation touches a check or a type hash: of the 382, 467 and 10,583 relocations in the three modules' code, none falls inside a check sequence or on a candidate's hash word (the 1, 1 and 49 that fall on the word before a function symbol are `R_AARCH64_CALL26` on the `bl` ending the function before, which has no hash), so the scan reads them from the file as they are. Each module scans in under 0.1 s; with `--with` about 0.6 s and 100 MB, with `--btf` 1.7 to 3.6 s and about 170 MB (whole command, wall clock).

What the lists mean on a module: a module calls mostly through operation tables that the kernel or other modules fill, so its own functions are only part of the answer. In `8021q.ko`, 5 of the 6 lists include the calling function itself: `vlan_dev_hard_header+0x120` calls the `header_ops->create` of the device under the VLAN, and the module's candidates are `vlan_passthru_hard_header` and `vlan_dev_hard_header` (right for a VLAN on a VLAN); `--with` adds the kernel's `eth_header`, `ipgre_header` and `ip6gre_header`. In `bluetooth.ko`, `compute_ecdh_secret+0x160` (type `int (struct kpp_request *)`) has no candidate in the module and one in the kernel, `ecdh_compute_value`. Of the 13 sites with no candidate in either, 6 share hash `0x4306bc2d`, `void (struct hci_dev *, unsigned int)`, whose BTF example is `hci_dev.notify`, a callback that HCI drivers such as `btusb` set; they are separate modules and were not scanned. The kernel candidates are the same with the 2024-01 `gki.elf` of the walkthrough (another build of the same branch): all 2,507 kernel entries of the 253 `bluetooth.ko` sites, and the same counts for both modules. The module's split BTF is refused on the 2024-01 `Image` (another build: its names land inside the other kernel's strings), with a warning, and the hashes are then named from that kernel's BTF alone.

Problems found on these modules, fixed in 0.1.23 (each with a test that failed first):
- `zram.ko` (0 `blr`) was reported as "probably built without Clang kCFI ... for example by GCC". Now: "the code makes no indirect call (no blr instruction) ... this does not tell whether it was built with kCFI". The Scan warning and the headless runner say the same (fake IDA modules only).
- A module's BTF is split BTF (it continues its kernel's), so the scan said "the input's BTF is unreadable", and `--btf <kernel>` named only the types in the kernel's BTF (7 of 48 in `bluetooth.ko`). Now the module's BTF is read on top of `--btf` (48 of 48), and without `--btf` the scan says to add it.
- A call whose callee is in the kernel had no way to show it. Now `--with VMLINUX` (command line only) lists the kernel's functions of each call's type next to the module's.

The IDA layer on a module: `tools/showcase_ida_stub.py` runs it on the real `bluetooth.ko` and `8021q.ko` through the fake `ida_*` modules of the tests: 253 sites, 253 comments and 1,176 cross-references for `bluetooth.ko`, 6 / 6 / 7 for `8021q.ko`, all to the module's own functions; a call with none says "no implementation in this image". It first prints the split-BTF hint the scan writes to the Output window (`Output window: [CFIScope] this module's BTF is split BTF ...`); before review s193 the showcase's fake modules lacked `ida_kernwin.msg` and both runs stopped there with an `AttributeError` (the plugin itself was not affected). `tests/test_showcase.py` now runs the showcase on a module-like object with split BTF, and on the two real modules when `CFISCOPE_KO_DIR` names a folder holding them (skipped otherwise); re-run 2026-11-14 with the files above: 253 / 253 / 1,176 and 6 / 6 / 7. It has not run in real IDA. Inside IDA there is no `--with`, and a module's split BTF is not read (no types shown).

## Known-answer objects and the test suite

Known-answer objects: `tests/test_members.py` checks the struct member of each call on `tests/fixtures/kcfi_members_a64.o` against `offsetof` (see [Struct members](#struct-members-aarch64)). `tests/test_slots.py` checks which candidates of each call on `tests/fixtures/kcfi_slots_a64.o` come first (see [Candidates stored in a matching slot](#candidates-stored-in-a-matching-slot)). `tests/test_core.py` scores the scanner on objects built with clang kCFI for x86-64 and aarch64, with and without frame pointers and patchable function entries, against the table of signatures and implementations that `tools/gen_fixtures.py` wrote into the source; function offsets come from the compiled objects. `tests/test_cli.py` checks that `python3 -m cfiscope` lists, by symbol name, exactly the known candidate sets for the same objects, and that bad input gives a clear error.

Run all of these with `python3 -m unittest discover -s tests` (no IDA needed). `tests/test_plugin_stub.py` runs the IDA layer and `tests/test_entry_stub.py` the plugin wiring (menus, right-click hooks, the call-site list, rescan after a rebase, pseudocode comments and the pseudocode-line lookups on a fake decompiler, restoring the scan after the database is reopened on a fake netnode) against fake `ida_*` modules, and `python3 tests/check_ida_api.py <dir with ida_*.pyi>` (the stubs ship in the `idapro` pip package) confirms all 113 IDA API names used, including the decompiler methods the pseudocode hook and lookups call, `func_t.tailqty`, the `netnode` methods of the scan marker, the `UI_Hooks` events that hook a decompiler loaded later and, for the call-site list, `Choose.CHCOL_DEC`, `Choose.OnSelectLine` and `close_chooser`, exist in the official stubs; `python3 tests/check_ida_names.py <stub dir>...` checks that the 74 `ida_*` / `idc` names alone also exist in older stubs (0 missing in those of IDA 9.1, 9.2, 9.3 and 9.4: PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11). None of these is a test in real IDA.

Not verified: behaviour inside real IDA.
