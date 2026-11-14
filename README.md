# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a list of the type-compatible functions it may reach, usually a short one.

The scanner was scored on a real Android GKI kernel for each architecture ([numbers](docs/VERIFICATION.md)); the IDA layer has not been run in IDA yet (see [Status](#status)).

## What you will see (real output, not an IDA screenshot)

We have no IDA, so this is the command-line tool, which runs the same scanner as the plugin, on the public GKI aarch64 kernel from the [walkthrough](#try-it) with its symbols restored by vmlinux-to-elf (57,453 named functions). The plugin puts the same answers in its comments, cross-references and jump lists.

Which functions can the indirect call in `sock_sendmsg` reach?

```
$ python3 -m cfiscope gki.elf --sites --max-list 20 | grep sock_sendmsg+
0xffffffc008cc55ac  sock_sendmsg+0xb4  call hash 0x1ebda935 (int (struct socket *, struct msghdr *, unsigned long))  14 candidate(s): tun_sendmsg, sock_no_sendmsg,
    netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg,
    packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg
```

Which indirect calls can reach `tcp_sendmsg`?

```
$ python3 -m cfiscope gki.elf --callers tcp_sendmsg --max-list 3
3 call site(s) can reach tcp_sendmsg
0xffffffc008cc5778  kernel_sendmsg_locked+0x64  call hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
0xffffffc008e433c8  inet_sendmsg+0x58           call hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
0xffffffc008ead820  inet6_sendmsg+0x58          call hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): sock_no_sendmsg_locked, tcp_sendmsg_locked, tcp_sendmsg ...
```

(Long lines wrapped by hand; spacing condensed.)

The type after each hash comes from the kernel's own BTF (new in 0.1.22, see [Features](#features)); this is the output of the code on `gki.elf`, re-run 2026-11-13.

## What the plugin writes into IDA (fake IDA, not a screenshot)

`tools/showcase_ida_stub.py` loads the same kernel's code segments and symbol names into the fake IDA modules of the stub tests, runs the plugin's own IDA layer (Scan, the two lists, the pseudocode comment) and prints what it wrote. These are the exact strings the plugin hands to IDA; real IDA has not run them and draws its own listing around them. How the counts come about: [docs/VERIFICATION.md](docs/VERIFICATION.md#what-the-plugin-writes-into-ida-fake-ida-not-a-screenshot).

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

More: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.1 or later.

The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/cfiscope/releases). If `hcli plugin status` shows an older version than the latest release, install the release zip directly:

```
hcli plugin install https://github.com/nightshift-labs-ai/cfiscope/archive/refs/tags/v0.1.22.zip
```

## Try it

The menu names below are under Edit > Plugins, with their default keys. Scan and the two lookups are also on the right-click menu (CFIScope submenu).

Quick try, no download (about a minute). The repository ships small objects built with Clang kCFI from `tests/fixtures/t.c`, with the known answer for every call in `tests/fixtures/truth.json`.

1. Open `tests/fixtures/x86_64-kernel.o` (or `aarch64-kernel.o`) in IDA. After `hcli plugin install cfiscope` the fixtures are in `$IDAUSR/plugins/cfiscope/tests/fixtures/` (`~/.idapro/plugins/...` on Linux and macOS, `%APPDATA%\Hex-Rays\IDA Pro\plugins\...` on Windows).
2. Choose **CFIScope: Scan kCFI calls** (`Alt-Shift-K`) and answer its question about creating functions (either answer works for these steps). The Output window should then say `Scan: 21 kCFI call sites (21 types, all named from the file's BTF); 21 with candidates (median 3); ...`: one call site per function-pointer type in `t.c`, each with candidates.
3. Put the cursor on the call in `do_call_2` and choose **CFIScope: Candidates for this call** (`Alt-Shift-T`). It should list `impl_2_0`, `impl_2_1`, `impl_2_2`; the call's comment and the list title name the type, `long (short, int)`, from the BTF of `t.c` that these two fixtures carry.
4. Put the cursor on `impl_2_1` and choose **CFIScope: Callers of this function** (`Alt-Shift-X`). It should list that call in `do_call_2`.

A real kernel:

1. Download the public aarch64 Android kernel used for the output above and the [numbers](docs/VERIFICATION.md): [gki-certified-boot-android14-6.1-2024-01_r1.zip](https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip), unzip it (it holds `boot-6.1.img`), extract the kernel with `python3 tools/extract_bootimg.py boot-6.1.img Image` (no dependencies), and restore its symbols with [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf): `vmlinux-to-elf Image gki.elf`.
2. Open the resulting ELF in IDA and let auto-analysis finish.
3. Choose **CFIScope: Scan kCFI calls**.
4. On any `blr` preceded by a kCFI check, choose **CFIScope: Candidates for this call** to list the functions it can reach. On a function, choose **CFIScope: Callers of this function** to list the indirect calls that can reach it.

## Features

- **Scan kCFI calls** (`Alt-Shift-K`): comments every kCFI call site with the type hash and candidate count. Adds cross-references when the list is short (at most 16) and offers to create functions at candidates IDA has not recognised. It asks first; Cancel writes nothing.
- **Candidates for this call** (`Alt-Shift-T`): a jump list of every function the call under the cursor can reach. In pseudocode it takes the call on the cursor's line and asks which one if the line has several.
- **Callers of this function** (`Alt-Shift-X`): every indirect call site that can reach this function (in pseudocode, the decompiled function), an answer the normal xrefs window cannot give.
- **Remove annotations**: removes the comments and cross-references the scan added. Functions created when you answered Yes stay.
- **Pseudocode comments** (with the Hex-Rays decompiler): the pseudocode line of each kCFI call gets a trailing comment such as `// CFIScope: 3 candidates of long (short, int): impl_2_0, impl_2_1, impl_2_2` (the type when the file has BTF). After you reopen a scanned database they come back without a new Scan (unreleased): the first decompiled function or lookup re-reads the code, read-only.
- **kCFI hashes named by C function type** (0.1.22): when the kernel carries BTF (`CONFIG_DEBUG_INFO_BTF`), or with `--btf PATH`, each hash is shown as its type, e.g. `hash 0x4f4ccb9d (int (struct file *, int))` (CFIScope mangles every BTF prototype the way Clang does and hashes it: `cfiscope/kcfi_types.py`). Named: all 4,184 hashes on GKI 6.1, all 4,466 on GKI 6.6, 4,621 of 4,626 on the Rust-enabled GKI 6.12 (the 5 left are inside Rust code); details in [VERIFICATION](docs/VERIFICATION.md). The IDA layer does the same from the input file's BTF, checked only against fake IDA modules.
- **Loadable modules (.ko)** (unreleased): a module is read as it is (no relocation touches a check or a hash). On the GKI android14-6.1 `bluetooth.ko` from the public prebuilts ([details](docs/VERIFICATION.md#loadable-modules-ko)): 253 call sites, 234 with candidates among the module's own functions. On the command line, `--with vmlinux` adds the kernel's functions of each call's type (23 sites have some, e.g. `compute_ecdh_secret` -> `ecdh_compute_value`) and `--btf` with the module's own kernel names all 48 hashes from the module's split BTF; 13 sites have no candidate in the module or the kernel (12 of them take a `struct hci_dev *`: callbacks that driver modules set, which were not scanned). In IDA, Scan on a `.ko` lists the module's functions only, without types (the plugin does not read split BTF; the Output window says so and gives the `--btf` command; checked only against fake IDA modules).
- **Linux 5.x jump-table CFI** (aarch64, Android 12/13 GKI 5.10 and 5.15, since v0.1.17): reads each call's candidates from the compiler's jump table. See [docs/JTCFI.md](docs/JTCFI.md).
- **Command line and headless**: the scanner is plain Python 3 with no dependencies; `tools/cfiscope_headless.py` adds the same comments and cross-references as Scan, headless with idalib (IDA 9.1 or newer). See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#without-ida-scripts-other-tools-ci).

```
python3 -m cfiscope vmlinux                         # summary
python3 -m cfiscope vmlinux --sites                 # every call site and its candidates
python3 -m cfiscope vmlinux --callers tcp_sendmsg   # indirect calls that can reach a function
python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
python3 -m cfiscope Image --raw --arch aarch64 --base 0xffffffc008000000
python3 -m cfiscope vmlinux --sites --btf vmlinux   # name hashes by C type from BTF (automatic when the input has BTF)
python3 -m cfiscope foo.ko --sites --with vmlinux --btf vmlinux   # a module: + the kernel's functions, + its types
```

```
python3 tools/cfiscope_headless.py vmlinux [--define-functions] [--remove] [--no-analysis]
```

Full description of each action: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#the-actions-in-full).

## Limitations

- **Not yet run inside real IDA.** The IDA layer was tested only against fake `ida_*` modules, the pseudocode comments and lookups, and the restore after reopening, only against fake `ida_hexrays` and `ida_netnode`.
- **Candidates are type-compatible functions.** kCFI proves a function has the right type hash, not that a given call ever reaches it.
- **Some lists are long.** On each of the four kCFI GKI kernels measured, the median is 6 candidates per call that has any, but the largest list has 1,458 to 1,812.
- **No candidates for some calls.** On GKI 6.1, 1,937 of 13,897 sites carry a hash that no function in the image has.
- **Modules (.ko):** the lists hold the module's own functions; the kernel's need `--with` (command line only), and callees in other modules are not found. Measured on three GKI 6.1 modules.
- **Not supported:** GCC-built kernels and x86-64 kernels with the jump-table CFI. The scan finds 0 sites and says so.
- **Jump-table CFI:** aarch64 only, two kernels measured. Tracepoint and vendor-hook calls are not checked by design and stay unresolved. See [docs/JTCFI.md](docs/JTCFI.md#limits).
- **Text bounds in IDA:** leaving out candidates in `.rodata` and data in practice needs the input ELF still at its path.
- **Pseudocode comments** are display text only; the database keeps just a small "scanned" marker. After a rebase, run Scan again to get them back.
- **Hotkeys:** `Alt-Shift-K`, `T`, `X` are not among IDA 9's published default shortcuts, Keypatch's or GNOME's window-manager keys; another plugin may still use them. Rebind in Options > Shortcuts.

## Status

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is in [docs/VERIFICATION.md](docs/VERIFICATION.md): the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

Run the tests yourself, no IDA needed: `python3 -m unittest discover -s tests` (163 tests: the scanner on compiler-built objects with known answers, the IDA layer and the plugin wiring on fake `ida_*` modules; one, on the real GKI modules of [VERIFICATION](docs/VERIFICATION.md#loadable-modules-ko), is skipped unless `CFISCOPE_KO_DIR` names the folder that holds them).

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs".

## Licence

MIT.
