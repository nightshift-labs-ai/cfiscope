#!/usr/bin/env python3
"""Copy the .BTF section of one ELF object into another (64-bit little-endian ELF), so the fixture kernels carry the
BTF of the source they were built from and the kCFI hashes in them get C type names.

    python3 tools/add_btf_section.py t_btf.o tests/fixtures/x86_64-kernel.o out.o

t_btf.o is tests/fixtures/t.c built for BTF:  zig cc -target bpfel-freestanding-none -g -O2 -c t.c -o t_btf.o
(GNU objcopy --add-section does the same, but cannot read BPF objects and may not know aarch64 ones.)
Plain Python, no dependencies. The new section goes at the end of the file, after a copy of the section headers.
"""
import struct
import sys


def sections(d):
    if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
        raise SystemExit("not a 64-bit little-endian ELF file")
    shoff, = struct.unpack_from("<Q", d, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
    hdrs = [list(struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize)) for i in range(shnum)]
    strtab = hdrs[shstrndx]
    names = [d[strtab[4] + h[0]:d.index(b"\0", strtab[4] + h[0])].decode() for h in hdrs]
    return hdrs, names, shstrndx


def read(path):
    with open(path, "rb") as fh:
        return fh.read()


def btf_of(path):
    d = read(path)
    hdrs, names, _ = sections(d)
    if ".BTF" not in names:
        raise SystemExit("%s has no .BTF section" % path)
    h = hdrs[names.index(".BTF")]
    return d[h[4]:h[4] + h[5]]


def add_btf(dst, btf):
    d = bytearray(dst)
    hdrs, names, shstrndx = sections(bytes(d))
    if ".BTF" in names:
        raise SystemExit("the target already has a .BTF section")

    def put(blob, align):
        while len(d) % align:
            d.append(0)
        off = len(d)
        d.extend(blob)
        return off
    old = hdrs[shstrndx]
    strtab = bytes(d[old[4]:old[4] + old[5]])
    name_off = len(strtab)
    old[4], old[5] = put(strtab + b".BTF\0", 1), len(strtab) + 5    # section names, now with ".BTF"
    btf_off = put(btf, 4)
    # name, SHT_PROGBITS, no flags, addr 0, offset, size, link 0, info 0, align 4, entsize 0
    hdrs.append([name_off, 1, 0, 0, btf_off, len(btf), 0, 0, 4, 0])
    shoff = put(b"".join(struct.pack("<IIQQQQIIQQ", *h) for h in hdrs), 8)
    struct.pack_into("<Q", d, 0x28, shoff)
    struct.pack_into("<H", d, 0x3c, len(hdrs))
    return bytes(d)


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    out = add_btf(read(sys.argv[2]), btf_of(sys.argv[1]))
    with open(sys.argv[3], "wb") as fh:
        fh.write(out)
    print("wrote %s (%d bytes, .BTF %d bytes)" % (sys.argv[3], len(out), len(btf_of(sys.argv[3]))))


if __name__ == "__main__":
    main()
