#!/usr/bin/env python3
"""Copy the kernel out of an Android boot image (boot.img header versions 0-4).

    python3 tools/extract_bootimg.py boot-6.1.img Image

Plain Python, no dependencies. The kernel starts one page after the header: 4096 bytes for
header versions 3 and 4 (GKI), the header's own page_size for versions 0-2.
"""
import struct, sys


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    with open(sys.argv[1], "rb") as fh:
        d = fh.read()
    if d[:8] != b"ANDROID!":
        sys.exit("%s is not an Android boot image (no ANDROID! magic)" % sys.argv[1])
    kernel_size = struct.unpack_from("<I", d, 8)[0]
    version = struct.unpack_from("<I", d, 40)[0]
    page = 4096 if version >= 3 else struct.unpack_from("<I", d, 36)[0]
    if not kernel_size or page + kernel_size > len(d):
        sys.exit("header version %d: kernel size %d does not fit the file" % (version, kernel_size))
    with open(sys.argv[2], "wb") as fh:
        fh.write(d[page:page + kernel_size])
    print("header version %d, wrote %s, %d bytes" % (version, sys.argv[2], kernel_size))


main()
