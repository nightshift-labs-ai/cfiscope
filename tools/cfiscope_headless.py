#!/usr/bin/env python3
"""CFIScope without the IDA window, through idalib (IDA 9.0 or newer).

    python3 tools/cfiscope_headless.py <vmlinux, Image or .ko> [--no-analysis] [--define-functions] [--remove]

Opens the file as an IDA database and does what CFIScope: Scan kCFI calls does: a comment at every checked call
and user xrefs to short candidate lists. --define-functions also creates functions at candidates IDA has not
recognised; --remove takes CFIScope's comments and xrefs out again. Prints the same statistics and saves the
database. It calls the plugin's own cfiscope.idalayer functions. Hex-Rays pseudocode comments are a display
hook of the interactive plugin, so they do not apply here. Not yet run with a real idalib: we have no IDA licence.
Without IDA at all, `python3 -m cfiscope <file>` gives the same candidate lists.

idalib setup (from Hex-Rays): install the idapro wheel shipped in <IDA>/idalib/python and run its
py-activate-idalib.py once, or set IDADIR to your IDA folder.
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Apply CFIScope to a kernel with idalib (no IDA window).")
    parser.add_argument("input", help="kernel file to open in IDA (vmlinux, Image, .ko, or an existing database)")
    parser.add_argument("--no-analysis", action="store_true", help="skip IDA's auto-analysis (faster)")
    parser.add_argument("--define-functions", action="store_true", help="create functions at candidates IDA has not recognised")
    parser.add_argument("--remove", action="store_true", help="remove CFIScope's comments and xrefs instead of adding them")
    args = parser.parse_args(argv)
    if not os.path.isfile(args.input):
        parser.error("no such file: %s" % args.input)

    try:
        import idapro  # must be imported before any ida_* module
    except ImportError as error:
        print("cfiscope_headless: idalib is not available (%s). It needs IDA 9.0 or newer; see the top of this file." % error, file=sys.stderr)
        return 2
    if idapro.open_database(args.input, not args.no_analysis) != 0:
        print("cfiscope_headless: IDA could not open %s" % args.input, file=sys.stderr)
        return 1
    try:
        from cfiscope import idalayer
        try:
            sites, stats = idalayer.scan()
        except RuntimeError as error:
            print("cfiscope_headless: %s" % error, file=sys.stderr)
            return 3
        print("[CFIScope] %s" % json.dumps(stats))
        if args.remove:
            print("[CFIScope] xrefs removed: %d" % idalayer.remove_annotations(sites))
            return 0
        if not sites:
            print("[CFIScope] no kCFI checks found: this binary may not be built with -fsanitize=kcfi (Linux 6.1+ CONFIG_CFI_CLANG)")
            return 0
        print("[CFIScope] %s" % json.dumps(idalayer.annotate(sites)))
        if args.define_functions:
            print("[CFIScope] functions created: %d" % idalayer.define_functions(sites))
        return 0
    finally:
        idapro.close_database(True)


if __name__ == "__main__":
    sys.exit(main())
