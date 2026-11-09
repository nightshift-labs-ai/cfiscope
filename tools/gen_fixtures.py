#!/usr/bin/env python3
"""Build kCFI test objects with known answers.  Requires ziglang (pip install ziglang).

The C file declares many function signatures, several implementations each and one
indirect call per signature.  truth.json records, per signature, the function
offsets the compiler produced, so the scanner can be scored against them.
"""
import json, os, random, struct, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "..", "tests", "fixtures")
ZIG = [sys.executable, "-m", "ziglang", "cc"]
VARIANTS = {
    "x86_64-plain":    ("x86_64",  []),
    "x86_64-kernel":   ("x86_64",  ["-fpatchable-function-entry=16", "-Xclang", "-fpatchable-function-entry-offset=16"]),
    "x86_64-noframe":  ("x86_64",  ["-fomit-frame-pointer"]),
    "aarch64-plain":   ("aarch64", []),
    "aarch64-kernel":  ("aarch64", ["-fpatchable-function-entry=8", "-Xclang", "-fpatchable-function-entry-offset=8"]),
}
TYPES = ["int","long","char","short","unsigned","void*","const char*","long long"]

def gen(rng):
    sigs, src, order = [], [], {}
    for i in range(24):
        ret = rng.choice(TYPES)
        args = [rng.choice(TYPES) for _ in range(rng.randint(0, 4))]
        sigs.append((ret, tuple(args)))
    sigs = list(dict.fromkeys(sigs))
    for i, (ret, args) in enumerate(sigs):
        params = ", ".join(f"{t} a{j}" for j, t in enumerate(args)) or "void"
        src.append(f"typedef {ret} (*fp{i})({params});")
        names = []
        for k in range(rng.randint(1, 6)):
            n = f"impl_{i}_{k}"
            names.append(n)
            body = "; ".join(f"(void)a{j}" for j in range(len(args)))
            src.append(f"__attribute__((noinline)) {ret} {n}({params}) {{ {body}; sink += {i*7+k}; return ({ret})sink; }}")
        order[i] = names
        call = ", ".join(f"({t})0" for t in args)
        src.append(f"__attribute__((noinline)) {ret} do_call_{i}(fp{i} f) {{ return f({call}); }}")
        src.append(f"fp{i} tbl{i}[] = {{ {', '.join(names)} }};")
    return "volatile long sink;\n" + "\n".join(src) + "\n", order

def symtab(path):
    d = open(path, "rb").read()
    shoff = struct.unpack_from("<Q", d, 0x28)[0]; n = struct.unpack_from("<H", d, 0x3c)[0]
    S = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + 64 * i) for i in range(n)]
    out = {}
    for s in S:
        if s[1] == 2:  # SHT_SYMTAB
            strs = S[s[6]]
            for i in range(s[5] // 24):
                nm, info, oth, shndx, val, size = struct.unpack_from("<IBBHQQ", d, s[4] + 24 * i)
                if info & 15 == 2:
                    e = d.index(b"\0", strs[4] + nm)
                    out[d[strs[4] + nm:e].decode()] = val
    return out

def main():
    rng = random.Random(1234)
    src, order = gen(rng)
    os.makedirs(FIX, exist_ok=True)
    open(os.path.join(FIX, "t.c"), "w").write(src)
    truth = {}
    for name, (arch, extra) in VARIANTS.items():
        o = os.path.join(FIX, name + ".o")
        subprocess.check_call(ZIG + ["-target", arch + "-linux-musl", "-O1", "-fsanitize=kcfi",
                                     "-fno-sanitize=undefined", "-ffunction-sections", "-c",
                                     os.path.join(FIX, "t.c"), "-o", o] + extra)
        truth[name] = {"arch": arch, "signatures": {str(i): names for i, names in order.items()},
                       "symbols": {k: v for k, v in symtab(o).items()}}
    json.dump(truth, open(os.path.join(FIX, "truth.json"), "w"), indent=0, sort_keys=True)
main()
