# Linux 5.x jump-table CFI (Android 12/13 GKI 5.10 and 5.15)

Back to the [README](../README.md). How kCFI is read is in [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

Needs cfiscope 0.1.18 or later (see [Install](../README.md#install) if `hcli` gives an older version).

## What CFIScope reads

Before kCFI, Clang's CFI for the kernel (`CONFIG_CFI_CLANG` on Linux 5.x, used by Android 12 and 13 GKI) worked differently: every function whose address is taken gets an 8-byte entry `bti c; b <function>` in one jump table, the functions of one type sit next to each other in it, and a checked call tests that the pointer lies in its type's run of entries before calling it:

```
adrp x8, ... ; add x8, x8, #0x3a8     ; first entry of the type's run
sub  x8, x23, x8 ; ror x8, x8, #3      ; index of the pointer's entry
cmp  x8, #0xa6                         ; 166 entries
b.hs slow_path                         ; otherwise __cfi_slowpath_diag(type id, pointer, ...)
blr  x23
```

So the candidates of a call are written in the code: CFIScope reads the base and the count, then each entry's branch target. This is the compiler's own list of the functions of that type in the image that the check lets through, with no hash collisions. When there are no kCFI checks in an aarch64 image, the scan looks for this form instead; the actions, comments (`jtCFI <type>: N candidate(s): ...`), cross-references, lists and pseudocode comments are the same as for kCFI. Supported shapes: range checks (`b.hs`/`b.hi` with the call on the fall-through, `b.lo`/`b.ls` with the call at the branch target, count as an immediate or in a register, up to four unrelated instructions between the subtract and the rotate), single-member types (`cmp; b.ne`), checks whose subtract and rotate were hoisted out of a loop, and calls checked only through `__cfi_slowpath`/`__cfi_slowpath_diag`. When a check's slow path is inlined (`bl find_check_fn`, then a `blr` to the `__cfi_check` of the kernel or module that holds the pointer with the type id in `x0`), that `blr` is the CFI runtime's own call, not a program call: CFIScope labels it (`jtCFI runtime: calls __cfi_check ...`) instead of listing candidates. On the GKI 5.15 kernel below it finds 890 of them from the code alone, all among the 1,015 counted with symbols; the GKI 5.10 kernel has none (its slow paths call `__cfi_slowpath`). Each site also gets the type's 64-bit id (passed to the slow path; it is the first 8 bytes of MD5 of the mangled type name), and, when the kernel's symbols include the `__typeid_<type>_global_addr` names that kallsyms keeps, the type itself, for example `int (file*, int)`. In IDA these names are taken from the database and, because IDA keeps one name per address and each of them shares its address with a `foo.cfi_jt` entry, also from the input ELF's symbol table if that file is still where it was loaded from.

## Real output

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

Which indirect calls may reach `tcp_sendmsg` on that kernel (same CFI type; real output):

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

## Measurements

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

## Limits

Limits, read before relying on it:

- **Two kernels were measured.** On Android 12 GKI `gki-certified-boot-android12-5.10-2024-01_r1` ([zip](https://dl.google.com/android/gki/gki-certified-boot-android12-5.10-2024-01_r1.zip), kernel from `boot-5.10.img`; same scanner, same `tools/eval_gki_oldcfi.py`, symbols from vmlinux-to-elf): 14,136 of 20,939 `blr` in kernel text get candidates (67.5%), median 6; all 23,399 distinct candidates start at a kallsyms function and every entry's name matches its target; the jump table ends where its entries end, and the rest up to `__cfi_jt_end` is zero padding. That kernel's kallsyms keeps only one `__typeid` name, so its types show as 64-bit ids and the `__typeid` row of the table above cannot be checked there, nor the `__typeid` half of the entry-count row; its other half finds no overlap: 0 of 2,344 pairs of neighbouring runs (2,345 type ids: 1,605 range, 740 single), every check of an id reading the same run, and 0 of 12,896 checks whose range was read at the check without candidates. The scanner reads only 8-byte `bti c; b` jump-table entries; a build without BTI lays its jump table out differently (we expect 4-byte `b` entries, not checked), and CFIScope does not look for that. x86-64 kernels with this CFI are not read.
- **Module targets are not listed.** A call whose type has no function in the kernel image is checked only by `__cfi_slowpath`; CFIScope shows its type and "no candidate in this image" (2,087 slow-path-only sites on this kernel, the two cases below included). The same applies to a copy of a call that the compiler placed on a check's slow path: it runs only when the pointer is not one of the image's functions of that type. When symbols are available, 241 of these slow-path sites belong to a type that does have functions in the image, which means an inline check was not decoded; those are marked "candidates unknown".
- **Tracepoint and vendor-hook calls are not checked by design** (the kernel calls them without CFI), so there is nothing to read and they stay unresolved, like assembly and `__nocfi` code. These, the slow-path-only calls and the checks this scanner does not decode make up the 7,686 unresolved `blr`. `tools/eval_gki_oldcfi.py` splits them: 1,950 are linked to a check that has no candidates in the image (slow-path-only types, ranges not found); 1,537 sit in tracepoint and vendor-hook iterators (`__traceiter_*`; none of these functions has a `ror #3` or a `__cfi_slowpath` call before the call); 1,015 are the CFI runtime's own calls: an inlined slow path calls `find_check_fn` and then the `__cfi_check` of the kernel or module that holds the pointer through a register; 2,030 look like tracepoint loops inlined into other functions (the probe's function and data read as a pair: `ldar xR, [xM]; ldr x0, [xM, #8]; blr xR`), which are also called without a check; 225 have a `ror #3` or a `__cfi_slowpath` call in the 32 instructions before them (most likely checks this scanner does not decode, such as a `sub` and `ror` more than four instructions apart); and 929 have none of these (most likely calls without a CFI check: assembly, `__nocfi` code, BPF dispatch). The last three numbers come from pattern matches, not from decoding. Leaving out the runtime's own calls, 14,052 of 20,723 `blr` (67.8%) get candidates.
- **Linking is linear.** A check is linked to the first `blr` of its register on the straight path after it (following up to two unconditional branches), or to a later call that reuses it. The register holding the type's first entry is found by walking back from the check, stopping at function starts and at code that does not fall through. Checks whose base or call is found only through the control-flow graph are missed (on this kernel, the walk finds no base for 1,033 checks: 979 of them take the range of another check with the same type id (the table's 1,036 + 105 = 1,141 counts listed sites instead: 954 of these checks, plus 187 slow-path sites whose undecoded inline check got its range the same way; the other 25 guard a call together with a check of the same range and are listed once), 54 have no range; 156 checks have no linked call: 141 are the CFI runtime's own, all the checks inside `__cfi_check`, which Callers leaves out; the other 15 are listed by Callers after the calls and not counted. GKI 5.10: 140, of them 131 in `__cfi_check`).
- **Not run in IDA.** Like the rest of CFIScope, the IDA side was tested only against fake `ida_*` modules (`tests/test_plugin_stub.py`, `tests/test_entry_stub.py`). The scanner is the same code as the command line.

## Known-answer test

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
