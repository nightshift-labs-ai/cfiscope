#!/usr/bin/env python3
"""Get vmlinux out of an x86 bzImage whose payload is LZ4-compressed (the GKI kernel-6.1 is).

    python3 tools/extract_bzimage.py kernel-6.1 vmlinux

Plain Python, no dependencies. Other compressions: use scripts/extract-vmlinux from the kernel tree.
"""
import struct, sys

LZ4_LEGACY = b"\x02\x21\x4c\x18"


def lz4_block(src, out):
    i, n = 0, len(src)
    while i < n:
        token = src[i]; i += 1
        count = token >> 4
        if count == 15:
            while True:
                more = src[i]; i += 1; count += more
                if more != 255:
                    break
        out += src[i:i + count]; i += count
        if i >= n:
            break
        offset = src[i] | src[i + 1] << 8; i += 2
        count = token & 15
        if count == 15:
            while True:
                more = src[i]; i += 1; count += more
                if more != 255:
                    break
        count += 4
        start = len(out) - offset
        if offset >= count:
            out += out[start:start + count]
        else:
            out += (bytes(out[start:]) * (count // offset + 1))[:count]


def payload(image):
    if image[0x202:0x206] != b"HdrS":
        sys.exit("not a bzImage (no HdrS signature at 0x202)")
    start = (image[0x1F1] + 1) * 512 + struct.unpack_from("<I", image, 0x248)[0]
    return image[start:start + struct.unpack_from("<I", image, 0x24C)[0]]


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as handle:
        data = payload(handle.read())
    if data[:4] != LZ4_LEGACY:
        sys.exit("payload is not legacy LZ4; use scripts/extract-vmlinux from the kernel tree")
    out, i = bytearray(), 4
    while i + 4 <= len(data):
        size = struct.unpack_from("<I", data, i)[0]
        if data[i:i + 4] == LZ4_LEGACY:
            i += 4
            continue
        if i + 4 + size > len(data):  # the trailing uncompressed-size field
            break
        lz4_block(data[i + 4:i + 4 + size], out)
        i += 4 + size
    with open(sys.argv[2], "wb") as handle:
        handle.write(out)
    print("wrote %s, %d bytes" % (sys.argv[2], len(out)))


if __name__ == "__main__":
    main()
