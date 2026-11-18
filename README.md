# CFIScope

Resolve **indirect calls** in Linux and Android kernels built with kCFI, directly in IDA, from a stripped binary.

Clang's `-fsanitize=kcfi` (`CONFIG_CFI_CLANG`, enabled on Android GKI) writes a 32-bit function-type hash in front of every function that may be called indirectly (48,021 of the 57,453 named functions of the GKI 6.1 kernel below; static functions whose address is never taken get none) and checks it at every indirect call. Both ends survive stripping. CFIScope matches them, so an unresolved `blr x8` or `call rax` becomes a list of the type-compatible functions it may reach, usually a short one.

The scanner was scored on a real Android GKI kernel for each architecture ([numbers](docs/VERIFICATION.md)); the IDA layer has not been run in IDA yet (see [Status](#status)).

<a href="docs/img/hero.svg"><img src="docs/img/hero.png" width="900" alt="Diagram drawn from python3 -m cfiscope output on the GKI android14-6.1 kernel, not an IDA screenshot. Top: the indirect call blr x8 at sock_sendmsg+0xb4, call proto_ops.sendmsg hash 0x1ebda935, type int (struct socket *, struct msghdr *, unsigned long), 14 candidate(s), 13 in a proto_ops.sendmsg slot, with arrows to its 14 candidates: tun_sendmsg, netlink_sendmsg, inet_sendmsg, unix_stream_sendmsg, unix_dgram_sendmsg, unix_seqpacket_sendmsg, inet6_sendmsg, packet_sendmsg, packet_sendmsg_spkt, pfkey_sendmsg, vsock_dgram_sendmsg, vsock_connectible_sendmsg, xsk_sendmsg, sock_no_sendmsg. The first 13 stand under the header in a proto_ops.sendmsg slot: (stored in such a slot of the kernel's static data); sock_no_sendmsg stands under same type only:, grey, with a dashed arrow. Bottom: the 3 indirect calls that may reach tcp_sendmsg (same kCFI type), at inet_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f), inet6_sendmsg+0x58 (call proto.sendmsg hash 0x87bcba6f) and kernel_sendmsg_locked+0x64 (call proto_ops.sendmsg_locked hash 0x87bcba6f), each with type int (struct sock *, struct msghdr *, unsigned long), 11 candidates; tagged [tcp_sendmsg: in a proto.sendmsg slot] for inet_sendmsg+0x58, [tcp_sendmsg: in a proto.sendmsg slot] for inet6_sendmsg+0x58 and [tcp_sendmsg: same type only] for kernel_sendmsg_locked+0x64, whose arrow is dashed grey (it calls proto_ops.sendmsg_locked)."></a>

<sub>Drawn by `tools/draw_hero.py` from `python3 -m cfiscope gki.elf` output on the public GKI android14-6.1 kernel of [Try it](#try-it); not an IDA screenshot. Top: the kCFI-checked `blr x8` in `sock_sendmsg`, the struct member it loads its pointer from (`proto_ops.sendmsg`), its C type from the kernel's BTF, and the 14 functions of that type it may reach, under the group headers of `--targets`: the 13 stored in a `proto_ops.sendmsg` slot of the kernel's static data, then `sock_no_sendmsg` (same type only, grey and dashed: it is stored in no object of this image; module tables use it). Bottom: the 3 indirect calls that may reach `tcp_sendmsg` (same kCFI type), each tagged as `--callers` tags it: `tcp_sendmsg` is stored in a `proto.sendmsg` slot, the member that `inet_sendmsg+0x58` and `inet6_sendmsg+0x58` load, and is of the same type only for `kernel_sendmsg_locked+0x64` (dashed: it calls `proto_ops.sendmsg_locked`). In blue, `inet_sendmsg` and `inet6_sendmsg`: candidates of the top call that hold two of the bottom calls. How it is made and checked: [docs/img](docs/img/README.md).</sub>

## Without CFIScope

The call at `sock_sendmsg+0xb4` is `blr x8`: the target is loaded from `sock->ops` at run time, so the binary names no callee. The usual fallback is a name search. In the GKI 6.1 kernel below, 31 functions are named `*_sendmsg` (`nm gki.elf | grep -v __ksymtab | grep -c '_sendmsg$'`): 13 have this call's type, the other 18 (such as `tcp_sendmsg`, which takes a `struct sock *`) would fail its kCFI check, and the search misses `packet_sendmsg_spkt`. Source-level call-graph tools need the source and its LLVM IR, which vendor kernels and modules do not ship. CFIScope lists the call's 14 candidates, all of its type, from the binary alone, the 13 that the kernel's static data stores in a `proto_ops.sendmsg` slot first (next block; 3.10 to 3.26 s for that command here, three runs).

## What you will see (real output, not an IDA screenshot)

We have no IDA, so this is the command-line tool, which runs the same scanner as the plugin, on the public GKI aarch64 kernel from the [walkthrough](#try-it) with its symbols restored by vmlinux-to-elf (57,453 named functions). The plugin puts the same answers in its comments, cross-references and jump lists.

Which functions may the indirect call in `sock_sendmsg` reach?

```
$ python3 -m cfiscope gki.elf --targets 0xffffffc008cc55ac
candidates for the site at 0xffffffc008cc55ac
0xffffffc008cc55ac  sock_sendmsg+0xb4                        call proto_ops.sendmsg hash 0x1ebda935 (int (struct socket *, struct msghdr *, unsigned long))  14 candidate(s), 13 in a proto_ops.sendmsg slot
  in a proto_ops.sendmsg slot:
    0xffffffc00897842c  tun_sendmsg
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
  same type only:
    0xffffffc008cd2ac4  sock_no_sendmsg
```

All 14 are listed. The 13 under `in a proto_ops.sendmsg slot` are stored, somewhere in the kernel's static data, at byte 136 of an object (an ops table such as `inet_stream_ops`), the offset this call loads; `sock_no_sendmsg` is stored in no object of this image (module tables use it), so it comes last. A slot is evidence, not proof.

Which indirect calls may reach `tcp_sendmsg` (same kCFI type)?

```
$ python3 -m cfiscope gki.elf --callers tcp_sendmsg --max-list 3
3 call site(s) can reach tcp_sendmsg
0xffffffc008e433c8  inet_sendmsg+0x58                        call proto.sendmsg hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): in a proto.sendmsg slot: tcp_sendmsg, raw_sendmsg, udp_sendmsg, +4 more; same type only: 4 more  [tcp_sendmsg: in a proto.sendmsg slot]
0xffffffc008ead820  inet6_sendmsg+0x58                       call proto.sendmsg hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): in a proto.sendmsg slot: tcp_sendmsg, raw_sendmsg, udp_sendmsg, +4 more; same type only: 4 more  [tcp_sendmsg: in a proto.sendmsg slot]
0xffffffc008cc5778  kernel_sendmsg_locked+0x64               call proto_ops.sendmsg_locked hash 0x87bcba6f (int (struct sock *, struct msghdr *, unsigned long))  11 candidate(s): in a proto_ops.sendmsg_locked slot: tcp_sendmsg_locked; same type only: 10 more  [tcp_sendmsg: same type only]
```

The tag at the end of each line says whether the image stores `tcp_sendmsg` in a slot of the member that call loads, and those calls come first. `tcp_sendmsg` is stored at byte 104 of `tcp_prot` and `tcpv6_prot`, a `proto.sendmsg` slot, the member the first two calls load. The third is a type-only match: `kernel_sendmsg_locked+0x64` loads offset 216 (`proto_ops.sendmsg_locked` in BTF), and of its 11 candidates only `tcp_sendmsg_locked` is stored at that offset of an object (`inet_stream_ops`, `inet6_stream_ops`); `tcp_sendmsg` is among the 10 of the same type only.

The type after each hash comes from the kernel's own BTF (new in 0.1.22, see [Features](#features)). The struct member before `hash` (new in 0.1.23, aarch64) is the one BTF member of the call's type at the byte offset the call loads its pointer from: a match, not proof (see [Limitations](#limitations)). Here it is right: `sock->ops->sendmsg` is a load from byte 136 of `struct proto_ops`. The slot groups and tags (new in 0.1.23) come from a scan of the image's static data for the candidates' addresses (see [Features](#features)). This is the output of the code on `gki.elf`, re-run 2026-11-14 (review s197), byte for byte.

Which functions have the type of `file_operations.unlocked_ioctl`, whether or not a call in this image checks it (unreleased)?

```
$ python3 -m cfiscope gki.elf --implements file_operations.unlocked_ioctl --max-list 4
136 function(s) with kCFI hash 0xe01408cd (long (struct file *, unsigned int, unsigned long)), the type of file_operations.unlocked_ioctl
    0xffffffc008055064  kvm_device_ioctl
    0xffffffc00805513c  kvm_no_compat_ioctl
    0xffffffc0080553f0  kvm_vm_ioctl
    0xffffffc008057774  kvm_vcpu_ioctl
    ... 132 more
```

Every function with that member's type hash in front of it: 134 ioctl handlers, plus `memfd_fcntl` and `pipe_fcntl`, which have the same C type (a type match, not proof of use). A C type, a hash or a function's name works too. In this kernel the call at `vfs_ioctl+0x38` checks the same type, so `--targets 0xffffffc0083a9f8c` gives the same 136 with the 81 stored in a `file_operations.unlocked_ioctl` slot first. `--implements` is for the types no call checks, as in a module: `python3 -m cfiscope bluetooth.ko --implements bt_sock_ioctl` lists `bt_sock_ioctl`, `hci_sock_ioctl` and `hci_sock_compat_ioctl`, which no candidate list of the module has ([Try it](#try-it)). This output was re-run on `gki.elf` for impl200 (review s243), byte for byte.

## What the plugin writes into IDA (fake IDA, not a screenshot)

`tools/showcase_ida_stub.py` loads the same kernel's code segments and symbol names into the fake IDA modules of the stub tests, runs the plugin's own IDA layer (Scan, the two lists, the pseudocode comment) and prints what it wrote. These are the exact strings the plugin hands to IDA; real IDA has not run them and draws its own listing around them. How the counts come about: [docs/VERIFICATION.md](docs/VERIFICATION.md#what-the-plugin-writes-into-ida-fake-ida-not-a-screenshot).

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

__cfi_impl_2_1:                             ; in front of each function of that type that may be called indirectly
  nop ... nop
  mov    eax,0x1300e12b                     ; the type hash; never executed, read by the checks
impl_2_1:
```

CFIScope reads the hash from every check, indexes the hash stored in front of each function that has one, and joins the two: this call gets `impl_2_0`, `impl_2_1`, `impl_2_2`. On aarch64 the check loads the 32-bit word in front of the target, compares it with the hash, and branches over a `brk` trap before the `blr`; CFIScope anchors on that `b.eq` + `brk` pair.

`cfiscope/core.py` has no IDA dependency: it finds the per-architecture check sequences, reads the expected hash from each, indexes the hash stored just before each function that has one, and joins the two. `cfiscope/idalayer.py` is the thin IDA layer.

More: [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md).

## Install

```
hcli plugin install cfiscope
```

Or copy this folder into your IDA `plugins` directory. IDA 9.1 or later.

The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/cfiscope/releases). If `hcli plugin status` shows an older version than the latest release, install the release zip directly:

```
hcli plugin install https://github.com/nightshift-labs-ai/cfiscope/archive/refs/tags/v0.1.23.zip
```

## Try it

The menu names below are under Edit > Plugins, with their default keys. Scan, the three lookups and the call-site list are also on the right-click menu (CFIScope submenu). After `hcli plugin install cfiscope` the plugin folder is `~/.idapro/plugins/cfiscope` on Linux and macOS and `%APPDATA%\Hex-Rays\IDA Pro\plugins\cfiscope` on Windows (`$IDAUSR/plugins/cfiscope` if you set `IDAUSR`). It holds the test objects (`tests/fixtures/`), the helper scripts (`tools/`) and the command-line tool (`cfiscope/`). The commands below use the Linux and macOS path.

Quick try, no download (about a minute). The plugin ships small objects built with Clang kCFI from `tests/fixtures/t.c`, with the known answer for every call in `tests/fixtures/truth.json`.

1. Copy one out of the plugin folder first, so that IDA does not write its database into it (an upgrade replaces the folder): `cp ~/.idapro/plugins/cfiscope/tests/fixtures/x86_64-kernel.o ~/` (Windows: `copy "%APPDATA%\Hex-Rays\IDA Pro\plugins\cfiscope\tests\fixtures\x86_64-kernel.o" %USERPROFILE%\`). Open the copy in IDA (`aarch64-kernel.o` works the same way).
2. Choose **CFIScope: Scan kCFI calls** (`Alt-Shift-K`) and answer its question about creating functions (either answer works for these steps). The Output window should then say `Scan: 21 kCFI call sites (21 types, all named from the file's BTF); 21 with candidates (median 3); ...` (checked against fake IDA modules): one call site per function-pointer type in `t.c`, each with candidates. Scan then opens a window, **CFIScope: 21 kCFI call sites**, with one row per call site: address, function and offset, member (empty here: these calls go through parameters), type, number of candidates and the first ones (checked against fake IDA modules). Enter on a row jumps to the call; **CFIScope: List kCFI call sites** opens it again. If the list has the keyboard focus, click back into the IDA View before pressing `G` in the next steps.
3. Press `G`, type `do_call_2`, and put the cursor on its indirect call: the `jmp rax` after the `ud2`, at `do_call_2+0x1a` (in `aarch64-kernel.o` the `br x2` at `do_call_2+0x24`). Choose **CFIScope: Candidates for this call** (`Alt-Shift-T`). It should list `impl_2_0`, `impl_2_1`, `impl_2_2`; the call's comment and the list title name the type, `long (short, int)`, from the BTF of `t.c` that these two fixtures carry (checked against fake IDA modules).
4. Press `G`, type `impl_2_1` and choose **CFIScope: Callers of this function** (`Alt-Shift-X`). It should list that call in `do_call_2` (checked against fake IDA modules). Then choose **CFIScope: Functions of this type** (right-click > CFIScope; no default key; unreleased): a window `kCFI functions of the type of impl_2_1 (hash 0x1300E12B, long (short, int)): 3` with `impl_2_0`, `impl_2_1` (noted `this function`) and `impl_2_2` (checked against fake IDA modules).
5. The struct member behind each call (a BTF match; new in 0.1.23; aarch64): copy out and open `tests/fixtures/kcfi_members_a64.o` the same way and Scan. The comment on `call_a_send+0x2c` should begin `kCFI a_ops.send 0xFD39CD44 int (struct msg *, int): 2 candidate(s)`, and the call-site list's Member column says `a_ops.send` there and `one of 2 members (c_ops.poll, d_ops.poll)` for `call_c_poll+0x2c` (checked against fake IDA modules). Without IDA: `cd ~/.idapro/plugins/cfiscope && python3 -m cfiscope tests/fixtures/kcfi_members_a64.o --sites` prints the same members, and `python3 -m cfiscope tests/fixtures/kcfi_slots_a64.o --targets 0x1000ac` lists the 8 candidates of a `net_ops.xmit` call: the 3 stored at that member's offset first, then `net_xmit_c` (`by array stride`), then the 4 of the same type only. In IDA that order needs the database at the addresses the command line gives a `.o`, which depends on how IDA lays out its sections (not checked in IDA); on the real kernel below it does not.

A real kernel (the public aarch64 Android kernel used for the output above and the [numbers](docs/VERIFICATION.md)):

1. Download it, extract the kernel and restore its symbols, in your home folder:
   ```
   cd ~
   curl -LO https://dl.google.com/android/gki/gki-certified-boot-android14-6.1-2024-01_r1.zip
   unzip gki-certified-boot-android14-6.1-2024-01_r1.zip       # holds boot-6.1.img
   python3 ~/.idapro/plugins/cfiscope/tools/extract_bootimg.py boot-6.1.img Image     # no dependencies
   vmlinux-to-elf Image gki.elf
   ```
   Install [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf#readme) first, as its README says (snap, yay or `uv tool install vmlinux-to-elf`). `pip install vmlinux-to-elf` worked for us on Linux, where pip built its `minilzo` dependency with the C compiler.
2. Open `gki.elf` in IDA. Auto-analysis of this 39 MB kernel (57,453 named functions) takes a while, and you need not wait for it: Scan asks "Wait for auto-analysis to finish before scanning?", and No scans at once. The call sites and candidates are read from the code bytes, so they are the same; the order within each group of a list (functions whose address is taken first; the slot-backed groups come first either way), the call-site list's Function+off column and, if you answer No to "Create functions", the cross-references depend on what IDA has analysed so far (run Scan again after analysis to refresh them).
3. Meanwhile, the same answers in about 3 seconds on the command line (3.10 to 3.26 s each here, three runs of each, with the slot ranking):
   ```
   cd ~/.idapro/plugins/cfiscope
   python3 -m cfiscope ~/gki.elf --callers tcp_sendmsg
   python3 -m cfiscope ~/gki.elf --targets 0xffffffc008cc55ac
   ```
4. Choose **CFIScope: Scan kCFI calls**. The Output window should say `Scan: 13,897 kCFI call sites (4,184 types, all named from the file's BTF); 11,960 with candidates (median 6), ...`, and the call-site window lists all 13,897 with their types and candidate counts (both checked against fake IDA modules).
5. Click into the IDA View, press `G`, type `0xffffffc008cc55ac` (the `blr x8` at `sock_sendmsg+0xb4`) and choose **CFIScope: Candidates for this call**: the 14 functions of the block above, the 13 noted `stored in a proto_ops.sendmsg slot` first (within each group IDA lists those whose address is taken first, so the order can differ); the window title and the call's comment name the member, `proto_ops.sendmsg` (checked against fake IDA modules). Press `G`, type `tcp_sendmsg` and choose **CFIScope: Callers of this function**: 3 call sites of its kCFI type, the two noted `stored in a proto.sendmsg slot` first and `kernel_sendmsg_locked+0x64` last, noted `same type only` (checked against fake IDA modules).

A real module (1.4 MB, no conversion): the GKI android14-6.1 `bluetooth.ko` of [VERIFICATION](docs/VERIFICATION.md#loadable-modules-ko), from the public AOSP prebuilts (gitiles serves a file as base64 with `?format=TEXT`).

1. Fetch it:
   ```
   cd ~
   curl -s 'https://android.googlesource.com/kernel/prebuilts/6.1/arm64/+/ad5f1ad22dd47c7b244ec697c5e61f90783a06c2/bluetooth.ko?format=TEXT' | base64 -d > bluetooth.ko
   sha256sum bluetooth.ko      # d9beb2a2c000bebfb7cdec2a1374364f5339d5541e4bee182314d62299f3b0e9
   ```
2. Open `bluetooth.ko` in IDA and choose **CFIScope: Scan kCFI calls**. The Output window should say that the plugin does not read the module's split BTF, then `Scan: 253 kCFI call sites (48 type hashes); 234 with candidates (median 12), 19 with none in this file; ...` (checked against fake IDA modules).
3. Click into the IDA View, press `G`, type `bt_sock_recvmsg` and put the cursor on its `blr` at `bt_sock_recvmsg+0x10c`: **Candidates for this call** should list `l2cap_skb_msg_name`, and on `l2cap_security_cfm` **Callers of this function** should list 4 call sites (checked against fake IDA modules; `--callers l2cap_security_cfm` on the command line gives the same 4).
4. The C types come from the command line with the kernel of the same build (`kernel-6.1`, 34.7 MB, same commit); `vmlinux-to-elf kernel-6.1 kernel-6.1.elf` and `--with ~/kernel-6.1.elf` add the kernel's own candidates:
   ```
   curl -s 'https://android.googlesource.com/kernel/prebuilts/6.1/arm64/+/ad5f1ad22dd47c7b244ec697c5e61f90783a06c2/kernel-6.1?format=TEXT' | base64 -d > kernel-6.1
   cd ~/.idapro/plugins/cfiscope
   python3 -m cfiscope ~/bluetooth.ko --sites --btf ~/kernel-6.1      # all 48 hashes named
   python3 -m cfiscope ~/bluetooth.ko --implements proto_ops.ioctl --btf ~/kernel-6.1
   ```
   The last one lists `bt_sock_ioctl`, `hci_sock_ioctl` and `hci_sock_compat_ioctl` (unreleased): the module's functions of that type, which no call site of the module checks, so no candidate list has them. The module stores the first two in its `proto_ops` tables at the `ioctl` slot (byte 72); `hci_sock_compat_ioctl` has the same type but sits in the `compat_ioctl` slot (byte 80). Without the kernel download, `python3 -m cfiscope ~/bluetooth.ko --implements bt_sock_ioctl` lists the same three (in IDA: **Functions of this type** on `bt_sock_ioctl`; not checked even against fake IDA modules on this file).

## Features

- **Scan kCFI calls** (`Alt-Shift-K`): comments every kCFI call site with the type hash and candidate count. Adds cross-references when the list is short (at most 16), or to a longer list's candidates stored at the offset of the call's member when those are at most 16 (new in 0.1.23; not to those found by array stride only), and offers to create functions at candidates IDA has not recognised. It asks first; Cancel writes nothing.
- **Candidates for this call** (`Alt-Shift-T`): a jump list of every function the call under the cursor may reach (its kCFI type). In pseudocode it takes the call on the cursor's line and asks which one if the line has several.
- **Callers of this function** (`Alt-Shift-X`): every indirect call site that may reach this function, by its kCFI type (in pseudocode, the decompiled function). With struct members (new in 0.1.23), the calls whose member slot holds the function come first, and each row says `stored in a proto.sendmsg slot`, `by array stride` or `same type only` (`--callers` ends its lines with the same tag). IDA's own xrefs window shows such a call only after Scan, and only when its list has at most 16 candidates or the function is one of at most 16 stored at the offset of the call's member (Scan adds cross-references to those only); this list also works before Scan and includes the other calls.
- **Functions of a type** (unreleased): `--implements SPEC` lists every function whose kCFI hash is that of a struct member (`file_operations.unlocked_ioctl`, from BTF), a C type as the tool prints it, a hash, or a named function's own type, whether or not a call site checks it (`--with` adds the kernel's). In IDA, **CFIScope: Functions of this type** (no default key) lists the functions of the type of the function under the cursor (checked against fake IDA modules only, not checked in IDA). GKI 6.1: 136 functions for `file_operations.unlocked_ioctl`, and for `proto_ops.sendmsg` the 14 candidates of `sock_sendmsg+0xb4`; `bluetooth.ko`: the 3 functions of the `proto_ops.ioctl` type (`hci_sock_compat_ioctl` is stored as `compat_ioctl`) and its 4 `proto_ops.sendmsg` handlers, which no candidate list has. A member or C type needs BTF; a function's own hash counts when a check or BTF knows it or the word sits where a kCFI preamble's would, and such a word is refused when it also stands in front of an address that starts no function (details: [HOW_IT_WORKS](docs/HOW_IT_WORKS.md#functions-of-a-type)).
- **List kCFI call sites** (new in 0.1.23; no default key; Scan opens it at its end): a non-modal window of every call site, with columns Address, Function+off, Member (the struct member, see below), Type (the C prototype from BTF, else the hash), Candidates (a number column, `CHCOL_DEC`) and First candidates; Enter jumps to the call. The rows are those of `python3 -m cfiscope FILE --sites`, the names in the comment's order. Checked against fake IDA modules only: 21 rows on each Quick-try fixture and 13,897 on GKI 6.1, each equal to its `--sites` line, built in 0.15 s or less there.
- **The struct member each call loads its pointer from (a BTF match)** (new in 0.1.23; aarch64 only): `sock_sendmsg+0xb4` is `blr x8`, and CFIScope says it calls through `proto_ops.sendmsg`. It walks back from the kCFI check to the `ldr` that loaded the called pointer and looks up the load's byte offset, with the call's type hash, among the function-pointer members in BTF (embedded and anonymous structs and unions included). One match names the member; several print `one of N members (...)`, rather than picking one. It shows on the command line (`--sites`, `--callers`, `--targets`, the summary, and `member` / `members` / `member_offset` in `--json`) and in the IDA comment, pseudocode comment, Candidates window title, Callers rows and a Member column of the call-site list (the IDA side checked against fake IDA modules only). On GKI 6.1, 9,764 of 13,897 calls are matched to a member and 8,937 to exactly one. GKI 6.6 gives 9,675 / 8,821 and GKI 6.12 9,984 / 9,284 ([VERIFICATION](docs/VERIFICATION.md#struct-members-aarch64)). The member is the only one BTF has of that type at that offset; that the call really goes through it is not proven.
- **Candidates stored in a matching slot first** (new in 0.1.23; aarch64, with BTF and the input's symbols, so not with `--raw`): for a call with a struct member, the candidates that the image's static data stores at that member's offset in an object are listed first, then those found `by array stride` (at that offset modulo the size of a struct of more than 16 bytes with that member there, in an object that holds another candidate of the call at such an offset: weaker evidence), then the rest under `same type only`; no candidate is left out. A list that fits the limit names every candidate (`2 candidate(s): in a a_ops.send slot: send_x; same type only: send_y`); a longer one names the slot-backed ones and counts the rest (`11 candidate(s): in a proto_ops.sendmsg_locked slot: tcp_sendmsg_locked; same type only: 10 more`). It shows in `--sites`, `--callers` (tagged, see above), `--targets` (the groups in full), `--json` (`slot_backed`: `offset`, `stride` or false, per candidate), the IDA comment, pseudocode comment, Candidates window, Callers and call-site list, and lists of more than 16 get cross-references to their candidates stored at the member's offset when there are at most 16 (the IDA side checked against fake IDA modules only). On GKI 6.1, 5,345 calls have such a candidate (139 of them only by array stride), and 1,142 lists of more than 16 have 1 to 16 at the member's offset ([VERIFICATION](docs/VERIFICATION.md#candidates-stored-in-a-matching-slot)). A slot is evidence, not proof.
- **Remove annotations**: removes the comments and cross-references the scan added. On a list of more than 16 it deletes only those to the candidates Scan gives cross-references (new in 0.1.23), so one you added to another candidate stays; on a shorter list, any cross-reference from the call to a candidate goes. Functions created when you answered Yes stay.
- **Pseudocode comments** (with the Hex-Rays decompiler): the pseudocode line of each kCFI call gets a trailing comment such as `// CFIScope: 3 candidates of long (short, int): impl_2_0, impl_2_1, impl_2_2` (the type when the file has BTF). After you reopen a scanned database they come back without a new Scan (new in 0.1.23): the first decompiled function or lookup re-reads the code, read-only.
- **kCFI hashes named by C function type** (0.1.22): when the kernel carries BTF (`CONFIG_DEBUG_INFO_BTF`), or with `--btf PATH`, each hash is shown as its type, e.g. `hash 0x4f4ccb9d (int (struct file *, int))` (CFIScope mangles every BTF prototype the way Clang does and hashes it: `cfiscope/kcfi_types.py`). Named: all 4,184 hashes on GKI 6.1, all 4,466 on GKI 6.6, 4,621 of 4,626 on the Rust-enabled GKI 6.12 (the 5 left are inside Rust code); details in [VERIFICATION](docs/VERIFICATION.md). The IDA layer does the same from the input file's BTF, checked only against fake IDA modules.
- **Loadable modules (.ko)** (new in 0.1.23): a module is read as it is (no relocation touches a check or a hash). On the GKI android14-6.1 `bluetooth.ko` from the public prebuilts ([details](docs/VERIFICATION.md#loadable-modules-ko)): 253 call sites, 234 with candidates among the module's own functions. On the command line, `--with vmlinux` adds the kernel's functions of each call's type (23 sites have some, e.g. `compute_ecdh_secret` -> `ecdh_compute_value`) and `--btf` with the module's own kernel names all 48 hashes from the module's split BTF; 13 sites have no candidate in the module or the kernel (12 of them take a `struct hci_dev *`: callbacks that driver modules set, which were not scanned). In IDA, Scan on a `.ko` lists the module's functions only, without types (the plugin does not read split BTF; the Output window says so and gives the `--btf` command; checked only against fake IDA modules).
- **Linux 5.x jump-table CFI** (aarch64, Android 12/13 GKI 5.10 and 5.15, since v0.1.17): reads each call's candidates from the compiler's jump table. See [docs/JTCFI.md](docs/JTCFI.md).
- **Command line and headless**: the scanner is plain Python 3 with no dependencies; `tools/cfiscope_headless.py` adds the same comments and cross-references as Scan, headless with idalib (IDA 9.1 or newer). The command-line tool is the `cfiscope` folder inside the plugin folder: run `python3 -m cfiscope` there (`cd ~/.idapro/plugins/cfiscope`), or `python3 ~/.idapro/plugins/cfiscope/cfiscope FILE` from any folder. See [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md#without-ida-scripts-other-tools-ci).

```
cd ~/.idapro/plugins/cfiscope                       # the plugin folder, or a clone of this repository
python3 -m cfiscope vmlinux                         # summary
python3 -m cfiscope vmlinux --sites                 # every call site and its candidates
python3 -m cfiscope vmlinux --callers tcp_sendmsg   # indirect calls that may reach a function (same kCFI type)
python3 -m cfiscope vmlinux --targets 0xffffffc008cc55ac
python3 -m cfiscope vmlinux --implements file_operations.unlocked_ioctl   # every function of that member's type
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
- **Struct members:** aarch64 only (x86-64 is not read yet); with BTF only; straight-line code only (a load the walk cannot follow, or one with a branch landing between it and the check, gives no member). A call through a pointer to a lone function pointer (`(*pp)()`, offset 0) cannot be told from a struct's first member. A pointer the compiler has already moved into the struct is read from the wrong origin: `gic_enable_of_quirks+0x54` (GKI 6.6, 6.12) keeps a pointer to `gic_quirk.init` (byte 24) in a loop and loads `[x22, #0]`, so it is named `vhost_task.fn`.
- **Some lists are long.** On each of the four kCFI GKI kernels measured, the median is 6 candidates per call that has any, but the largest list has 1,458 to 1,812. Candidates stored in a slot of the call's member (aarch64) come first: on GKI 6.1, 5,345 calls have some, with a median of 2 (their whole lists: 6), and 1,116 of the 1,535 such lists of more than 16 have 16 or fewer in a slot; the largest lists (1,458 candidates, 61 calls) have at most 16 (GKI 6.6: 5,366 calls, 1,187 of 1,602; GKI 6.12: 5,700, 1,251 of 1,627). The rest of each list stays below them: a pointer set at run time, or stored in a module's table, is in no slot of the image.
- **Slots:** a slot is evidence, not proof: another struct with a member of the same type at that offset matches too. Matches `by array stride` are weaker: on GKI 6.1, in two samples of 10 per stride size, the holding object was an array of structs of that size for 7 of 20 with a 24-byte stride, 13 of 20 with 32 to 48 bytes and 20 of 20 above ([VERIFICATION](docs/VERIFICATION.md#candidates-stored-in-a-matching-slot)). Missed: arrays of structs of 16 bytes or less (only their first element counts), an array embedded in another object at an offset that is not a multiple of its stride, and a lone element stored at a stride offset of some other object.
- **Functions of a type** (unreleased): the hash says a function has the member's type, not that anything stores it in that member (`file_operations.unlocked_ioctl` also lists `memfd_fcntl` and `pipe_fcntl`); a function with no hash in front of it (a static one whose address is never taken) is not listed; an input with no kCFI check and no indirect call is read at -4 on aarch64, while aarch64 code whose indirect calls no check guards, and x86-64 with no check, are refused. On aarch64, a function's hash that no check or BTF knows is taken by its form, so without BTF a real hash that decodes as an instruction (b, bl, ret, a system instruction...) is missed: 2,257 of the 48,021 BTF-named words in front of GKI 6.1's functions (give `--btf` or the hash). The IDA action was checked against fake IDA modules only, not in IDA.
- **No candidates for some calls.** On GKI 6.1, 1,937 of 13,897 sites carry a hash that no function in the image has.
- **Modules (.ko):** the lists hold the module's own functions; the kernel's need `--with` (command line only), and callees in other modules are not found. Measured on three GKI 6.1 modules.
- **Not supported:** GCC-built kernels and x86-64 kernels with the jump-table CFI. The scan finds 0 sites and says so.
- **Jump-table CFI:** aarch64 only, two kernels measured. Tracepoint and vendor-hook calls are not checked by design and stay unresolved. See [docs/JTCFI.md](docs/JTCFI.md#limits).
- **The input file in IDA:** leaving out candidates in `.rodata` and data, the C types and struct members (from its BTF) and the slot ranking need the input ELF still at its path; the slot ranking also needs the database at the file's addresses (for a `.o` or `.ko` that depends on IDA's section layout; not checked in IDA). When the file is there but not an ELF or not at those addresses, Scan says in the Output window that it skipped the ranking (checked against fake IDA modules).
- **Pseudocode comments** are display text only; the database keeps just a small "scanned" marker. After a rebase, run Scan again to get them back.
- **Hotkeys:** `Alt-Shift-K`, `T`, `X` are not among IDA 9's published default shortcuts, Keypatch's or GNOME's window-manager keys; another plugin may still use them. Rebind in Options > Shortcuts.

## Status

**CFIScope has not yet been run inside real IDA.** It was built without an IDA installation. What was checked, and how, is in [docs/VERIFICATION.md](docs/VERIFICATION.md): the scanner is scored against real kernels and compiler ground truth, while the IDA calls are only checked to exist in the official stubs and run against fake modules. If you try it in IDA and something is off, please open an issue.

Run the tests yourself, no IDA needed: `python3 -m unittest discover -s tests` (293 tests: the scanner on compiler-built objects with known answers, the IDA layer and the plugin wiring on fake `ida_*` modules, and the picture above against its SVG; 21 are skipped unless you name the real files they need: three need `CFISCOPE_KO_DIR`, the folder with the GKI modules (and, for two of the three, `kernel-6.1`) of [VERIFICATION](docs/VERIFICATION.md#loadable-modules-ko), and eighteen need `CFISCOPE_GKI_ELF`, the `gki.elf` of the walkthrough).

CFIScope was built by an AI agent (Claude, operated by Nightshift Labs).

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs".

## Licence

MIT.
