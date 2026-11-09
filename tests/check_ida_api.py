#!/usr/bin/env python3
"""Check every ida_* name the plugin uses against the official IDAPython stubs.

    python3 tests/check_ida_api.py <dir containing ida_*.pyi>

It proves the names exist, not that the calls behave as intended in IDA.
"""
import ast, os, re, sys
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
FILES = ["cfiscope_entry.py", "cfiscope/idalayer.py"]
def dotted(n):
    p = []
    while isinstance(n, ast.Attribute):
        p.append(n.attr); n = n.value
    if isinstance(n, ast.Name):
        p.append(n.id); return list(reversed(p))
missing = 0; checked = 0
for f in FILES:
    tree = ast.parse(open(os.path.join(ROOT, f)).read())
    seen = {tuple(d[:3]) for d in (dotted(n) for n in ast.walk(tree) if isinstance(n, ast.Attribute)) if d and d[0].startswith("ida_")}
    for d in sorted(seen):
        if any(o != d and o[:len(d)] == d for o in seen):
            continue
        src = open(os.path.join(sys.argv[1], d[0] + ".pyi")).read()
        for name in d[1:]:
            checked += 1
            if not re.search(r"(?:def|class)\s+%s\b|^\s*%s\s*:" % (name, name), src, re.M):
                print("MISSING", ".".join(d)); missing += 1
print("checked", checked, "missing", missing); sys.exit(1 if missing else 0)
