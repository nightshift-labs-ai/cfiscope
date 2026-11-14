#!/usr/bin/env python3
"""tools/cfiscope_headless.py with a FAKE idapro and a FAKE cfiscope.idalayer. Checks the orchestration only
(open, scan, annotate / remove / define, close + save, exit codes); this is not a test with a real idalib."""
import contextlib, io, os, subprocess, sys, tempfile, types
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
    return result["sites"], dict({"sites": len(result["sites"])}, **result.get("stats", {}))
layer.scan = scan
layer.annotate = lambda s, create_functions: calls.append(("annotate", len(s), create_functions)) or \
    {"comments": len(s), "xrefs": 2, "kept_user_comments": 0}
layer.remove_annotations = lambda s: calls.append(("remove", len(s))) or 2
layer.define_functions = lambda s: calls.append(("define", len(s))) or {"functions_created": 3, "skipped_not_code": 2}
# The scan marker a later IDA session restores from (stored after annotate, deleted by --remove or a scan of nothing).
layer.save_marker = lambda create_functions: calls.append(("marker", create_functions)) or True
layer.clear_marker = lambda: calls.append(("marker", None))
saved = {name: sys.modules.get(name) for name in ("idapro", "cfiscope.idalayer")}
saved_attr = cfiscope.__dict__.get("idalayer")
sys.modules.update(idapro=idapro, **{"cfiscope.idalayer": layer})
cfiscope.idalayer = layer
import cfiscope_headless as h  # noqa: E402
with tempfile.NamedTemporaryFile() as f:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert h.main([f.name, "--define-functions"]) == 0
    assert calls == [("open", True), ("scan",), ("annotate", 1, True), ("define", 1), ("marker", True), ("close", True)], calls
    assert out.getvalue().splitlines()[-1] == \
        "[CFIScope] functions created: 3; candidates skipped (data, or not in a code segment): 2", out.getvalue()
    # Without --define-functions: annotate is told not to add call xrefs that would make IDA create functions.
    del calls[:]; assert h.main([f.name]) == 0
    assert calls == [("open", True), ("scan",), ("annotate", 1, False), ("marker", False), ("close", True)], calls
    del calls[:]; assert h.main([f.name, "--remove", "--no-analysis"]) == 0
    assert calls == [("open", False), ("scan",), ("remove", 1), ("marker", None), ("close", True)], calls
    result["sites"] = []; del calls[:]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert h.main([f.name]) == 0 and calls == [("open", True), ("scan",), ("marker", None), ("close", True)], calls
    assert "may not be built with -fsanitize=kcfi" in out.getvalue(), out.getvalue()
    # ko189: an aarch64 database with no blr at all (a kCFI module that makes no indirect call) is not called non-kCFI.
    result["stats"] = {"blr_instructions": 0}; del calls[:]; out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert h.main([f.name]) == 0 and calls == [("open", True), ("scan",), ("marker", None), ("close", True)], calls
    assert "the code makes no indirect call (no blr instruction)" in out.getvalue(), out.getvalue()
    assert "may not be built" not in out.getvalue(), out.getvalue()
    del result["stats"]
    result["sites"] = RuntimeError("CFIScope supports 64-bit x86 and AArch64 databases only."); del calls[:]
    assert h.main([f.name]) == 3 and calls == [("open", True), ("scan",), ("close", True)], calls
    idapro.open_database = lambda path, analysis: 1; del calls[:]
    assert h.main([f.name]) == 1 and calls == [], calls
    run = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "cfiscope_headless.py"), f.name], capture_output=True, text=True)
    assert run.returncode == 2 and "idalib is not available" in run.stderr, (run.returncode, run.stderr)
    # --no-analysis skips the auto-analysis that creates functions, so its help points to --define-functions.
    # Wide COLUMNS: argparse wraps help to the terminal width and may break "--define-functions" at its hyphen.
    out, columns = io.StringIO(), os.environ.get("COLUMNS")
    os.environ["COLUMNS"] = "1000"
    try:
        with contextlib.redirect_stdout(out), contextlib.suppress(SystemExit):
            h.main(["--help"])
    finally:
        if columns is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = columns
    assert "--define-functions to get cross-references" in " ".join(out.getvalue().split()), out.getvalue()
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
