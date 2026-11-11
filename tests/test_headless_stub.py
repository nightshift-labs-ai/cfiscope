#!/usr/bin/env python3
"""tools/cfiscope_headless.py with a FAKE idapro and a FAKE cfiscope.idalayer. Checks the orchestration only
(open, scan, annotate / remove / define, close + save, exit codes); this is not a test with a real idalib."""
import os, subprocess, sys, tempfile, types
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools"))
import cfiscope  # noqa: E402
calls = []
idapro = types.ModuleType("idapro")
idapro.open_database = lambda path, analysis: calls.append(("open", analysis)) or 0
idapro.close_database = lambda save: calls.append(("close", save))
layer = types.ModuleType("cfiscope.idalayer")
sites = [types.SimpleNamespace(call_ea=0x10, check_ea=0x8, targets=[0x100, 0x200])]
result = {"sites": sites}
def scan():
    calls.append(("scan",))
    if isinstance(result["sites"], Exception):
        raise result["sites"]
    return result["sites"], {"sites": len(result["sites"])}
layer.scan = scan
layer.annotate = lambda s: calls.append(("annotate", len(s))) or {"comments": len(s), "xrefs": 2, "kept_user_comments": 0}
layer.remove_annotations = lambda s: calls.append(("remove", len(s))) or 2
layer.define_functions = lambda s: calls.append(("define", len(s))) or 1
saved = {name: sys.modules.get(name) for name in ("idapro", "cfiscope.idalayer")}
saved_attr = cfiscope.__dict__.get("idalayer")
sys.modules.update(idapro=idapro, **{"cfiscope.idalayer": layer})
cfiscope.idalayer = layer
import cfiscope_headless as h  # noqa: E402
with tempfile.NamedTemporaryFile() as f:
    assert h.main([f.name, "--define-functions"]) == 0
    assert calls == [("open", True), ("scan",), ("annotate", 1), ("define", 1), ("close", True)], calls
    del calls[:]; assert h.main([f.name, "--remove", "--no-analysis"]) == 0
    assert calls == [("open", False), ("scan",), ("remove", 1), ("close", True)], calls
    result["sites"] = []; del calls[:]
    assert h.main([f.name]) == 0 and calls == [("open", True), ("scan",), ("close", True)], calls
    result["sites"] = RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only."); del calls[:]
    assert h.main([f.name]) == 3 and calls == [("open", True), ("scan",), ("close", True)], calls
    idapro.open_database = lambda path, analysis: 1; del calls[:]
    assert h.main([f.name]) == 1 and calls == [], calls
    run = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "cfiscope_headless.py"), f.name], capture_output=True, text=True)
    assert run.returncode == 2 and "idalib is not available" in run.stderr, (run.returncode, run.stderr)
# unittest discover imports every test script in one process: put the real modules back.
for name, module in saved.items():
    if module is None:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = module
if saved_attr is None:
    del cfiscope.idalayer
else:
    cfiscope.idalayer = saved_attr
print("headless stub test OK (fake idapro and cfiscope.idalayer)")
