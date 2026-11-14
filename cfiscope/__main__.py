import os
import sys

if __package__:
    from .cli import main
else:
    # Run by path (python3 <plugin folder>/cfiscope FILE, or .../cfiscope/__main__.py): no parent package, so import
    # the package from the folder that holds it, whatever the working directory.
    HERE = os.path.dirname(os.path.abspath(__file__))
    if sys.path and os.path.abspath(sys.path[0] or os.curdir) == HERE:
        del sys.path[0]         # the package's own folder: its modules are not top-level modules
    sys.path.insert(0, os.path.dirname(HERE))
    from cfiscope.cli import main

try:
    code = main()
    sys.stdout.flush()
except BrokenPipeError:  # e.g. piped into head: stop quietly
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    code = 0
sys.exit(code)
