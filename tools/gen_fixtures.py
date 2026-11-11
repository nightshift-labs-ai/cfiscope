#!/usr/bin/env python3
"""Build test objects with known answers.

kCFI objects (needs ziglang: pip install ziglang): the C file declares many function
signatures, several implementations each and one indirect call per signature.  truth.json
records which functions this generator wrote for each signature, and their offsets in the
compiled objects, so the scanner can be scored.

Jump-table CFI (Linux 5.x, aarch64) fixture, no compiler needed: aarch64-jtcfi.elf is
assembled word by word below in the shapes Clang uses in Android GKI 5.15 kernels, and
jtcfi_truth.json lists every call site with its expected kind, type and candidates.

    python3 tools/gen_fixtures.py              # both
    python3 tools/gen_fixtures.py --jtcfi-only # only the jump-table CFI fixture
"""
import hashlib, json, os, random, struct, subprocess, sys
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

def build_kcfi():
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


# ---- jump-table CFI fixture (hand-assembled aarch64) ----

JT_BASE = 0xffffffc008000000


def _type_id(mangled):
    return int.from_bytes(hashlib.md5(mangled.encode()).digest()[:8], "little")


class Asm:
    """Two-pass word assembler: emit() takes a word or a function of (pc, labels) giving one."""

    def __init__(self, base):
        self.base, self.items, self.labels = base, [], {}

    def label(self, name):
        self.labels[name] = self.base + 4 * len(self.items)

    def emit(self, *words):
        self.items.extend(words)

    def align(self, n):
        while (4 * len(self.items)) % n:
            self.emit(NOP)

    def words(self):
        return [w(self.base + 4 * i, self.labels) if callable(w) else w for i, w in enumerate(self.items)]


NOP, BTI_C, PACIASP, AUTIASP, RET = 0xd503201f, 0xd503245f, 0xd503233f, 0xd50323bf, 0xd65f03c0
PUSH, POP = 0xa9bf7bfd, 0xa8c17bfd          # stp x29, x30, [sp, #-16]! / ldp x29, x30, [sp], #16
HS, LO, HI, NE = 2, 3, 8, 1
def movw(rd, imm): return 0x52800000 | imm << 5 | rd
def movz(rd, imm, hw=0): return 0xd2800000 | hw << 21 | imm << 5 | rd
def movk(rd, imm, hw): return 0xf2800000 | hw << 21 | imm << 5 | rd
def mov(rd, rm): return 0xaa0003e0 | rm << 16 | rd
def add_imm(rd, rn, imm): return 0x91000000 | imm << 10 | rn << 5 | rd
def sub(rd, rn, rm): return 0xcb000000 | rm << 16 | rn << 5 | rd
def ror(rd, rs, s): return 0x93c00000 | rs << 16 | s << 10 | rs << 5 | rd
def cmp_imm(rn, imm): return 0xf100001f | imm << 10 | rn << 5
def cmp_reg(rn, rm): return 0xeb00001f | rm << 16 | rn << 5
def subs_w(rd, rn, imm): return 0x71000000 | imm << 10 | rn << 5 | rd
def blr(rn): return 0xd63f0000 | rn << 5
def adrp(rd, label): return lambda pc, L: (0x90000000 | rd | ((((L[label] & ~0xfff) - (pc & ~0xfff)) >> 12) & 3) << 29
                                          | (((((L[label] & ~0xfff) - (pc & ~0xfff)) >> 14) & 0x7ffff) << 5))
def lo12(rd, rn, label, plus=0): return lambda pc, L: add_imm(rd, rn, (L[label] + plus) & 0xfff)
def b(label): return lambda pc, L: 0x14000000 | ((L[label] - pc) >> 2) & 0x3ffffff
def bl(label): return lambda pc, L: 0x94000000 | ((L[label] - pc) >> 2) & 0x3ffffff
def bcond(cond, label): return lambda pc, L: 0x54000000 | (((L[label] - pc) >> 2) & 0x7ffff) << 5 | cond
def load_id(tid): return [movz(0, tid & 0xffff)] + [movk(0, (tid >> 16 * h) & 0xffff, h) for h in (1, 2, 3)]


def jtcfi_program():
    T_FILE, T_VOID, T_READ = "_ZTSFiP4fileiE", "_ZTSFvPvE", "_ZTSFlP4filePcmPxE"
    a = Asm(JT_BASE)
    members = [("f_a", T_FILE), ("f_b", T_FILE), ("f_c", T_FILE), ("g_one", T_VOID)]
    for k, (name, _) in enumerate(members):                    # the functions behind the jump table
        a.label(name)
        a.emit(BTI_C, movw(0, k + 1), RET, NOP)
    a.label("__cfi_slowpath_diag")
    a.emit(BTI_C, RET, NOP, NOP)
    prologue, epilogue = [PACIASP, PUSH], [POP, AUTIASP, RET]

    # 1. range check, b.hs to an out-of-line slow path that jumps back to the call
    a.label("call_hs")
    a.emit(*prologue)
    a.emit(mov(21, 1), adrp(9, "jt"), lo12(9, 9, "jt"), sub(10, 21, 9), ror(10, 10, 3), cmp_imm(10, 3),
           bcond(HS, "slow_hs"))
    a.label("back_hs")
    a.emit(movw(1, 0))
    a.label("site_hs")
    a.emit(blr(21), *epilogue)
    a.label("slow_hs")
    a.emit(*load_id(_type_id(T_FILE)))
    a.emit(mov(1, 21), bl("__cfi_slowpath_diag"), b("back_hs"))

    # 2. range check, b.lo to the call (slow path on the fall-through), base copied with mov, count in a register
    a.label("call_lo")
    a.emit(*prologue)
    a.emit(adrp(20, "jt"), lo12(20, 20, "jt"), mov(19, 20), mov(21, 1), sub(9, 21, 19), ror(9, 9, 3),
           movw(10, 3), cmp_reg(9, 10), bcond(LO, "do_lo"))
    a.emit(*load_id(_type_id(T_FILE)))
    a.emit(mov(1, 21), bl("__cfi_slowpath_diag"))
    a.label("do_lo")
    a.emit(movz(0, 0))
    a.label("site_lo")
    a.emit(blr(21), *epilogue)

    # 3. range check against the last index: cmp #2; b.hi means 3 entries
    a.label("call_hi")
    a.emit(*prologue)
    a.emit(mov(22, 1), adrp(8, "jt"), lo12(8, 8, "jt"), sub(8, 22, 8), ror(8, 8, 3), cmp_imm(8, 2),
           bcond(HI, "slow_hi"))
    a.label("back_hi")
    a.label("site_hi")
    a.emit(blr(22), *epilogue)
    a.label("slow_hi")
    a.emit(*load_id(_type_id(T_FILE)))
    a.emit(mov(1, 22), bl("__cfi_slowpath_diag"), b("back_hi"))

    # 4. hoisted check: subtract and rotate before a loop, compare inside it
    a.label("call_hoisted")
    a.emit(*prologue)
    a.emit(mov(21, 1), adrp(9, "jt"), lo12(9, 9, "jt"), sub(9, 21, 9), movw(20, 2), ror(24, 9, 3))
    a.label("loop")
    a.emit(cmp_imm(24, 3), bcond(HS, "slow_hoisted"))
    a.label("back_hoisted")
    a.emit(movz(0, 0))
    a.label("site_hoisted")
    a.emit(blr(21), subs_w(20, 20, 1), bcond(NE, "loop"), *epilogue)
    a.label("slow_hoisted")
    a.emit(*load_id(_type_id(T_FILE)))
    a.emit(mov(1, 21), bl("__cfi_slowpath_diag"), b("back_hoisted"))

    # 5. single-member type: equality with its one entry, b.ne to the slow path
    a.label("call_single")
    a.emit(*prologue)
    a.emit(mov(21, 1), adrp(9, "jt"), lo12(9, 9, "jt", 24), cmp_reg(21, 9), bcond(NE, "slow_single"))
    a.label("back_single")
    a.emit(movz(0, 0))
    a.label("site_single")
    a.emit(blr(21), *epilogue)
    a.label("slow_single")
    a.emit(*load_id(_type_id(T_VOID)))
    a.emit(mov(1, 21), bl("__cfi_slowpath_diag"), b("back_single"))

    # 6. a type with no function in this image: only the slow path, then the call
    a.label("call_slow")
    a.emit(*prologue)
    a.emit(mov(22, 1), *load_id(_type_id(T_READ)))
    a.emit(mov(1, 22), bl("__cfi_slowpath_diag"), movz(0, 0))
    a.label("site_slow")
    a.emit(blr(22), *epilogue)

    # 7. range check with an unrelated instruction scheduled between the subtract and the rotate
    a.label("call_gap")
    a.emit(*prologue)
    a.emit(mov(21, 1), adrp(9, "jt"), lo12(9, 9, "jt"), sub(10, 21, 9), movw(0, 7), ror(10, 10, 3), cmp_imm(10, 3),
           bcond(HS, "slow_gap"))
    a.label("back_gap")
    a.label("site_gap")
    a.emit(blr(21), *epilogue)
    a.label("slow_gap")
    a.emit(*load_id(_type_id(T_FILE)))
    a.emit(mov(1, 21), bl("__cfi_slowpath_diag"), b("back_gap"))

    a.align(64)
    a.label("jt")                                              # 4 entries: bti c; b <function>
    for name, _ in members:
        a.label(name + ".cfi_jt")
        a.emit(BTI_C, b(name))
    a.label("jt_end")
    a.emit(RET, NOP, NOP, NOP)
    words = a.words()
    L = a.labels
    symbols = [(n, L[n]) for n in ("f_a", "f_b", "f_c", "g_one", "__cfi_slowpath_diag", "call_hs", "call_lo",
                                   "call_hi", "call_hoisted", "call_single", "call_slow", "call_gap")]
    symbols += [(n + ".cfi_jt", L[n + ".cfi_jt"]) for n, _ in members]
    symbols += [("__typeid_%s_global_addr" % T_FILE, L["jt"]), ("__typeid_%s_global_addr" % T_VOID, L["g_one.cfi_jt"]),
                ("__cfi_jt_start", L["jt"]), ("__cfi_jt_end", L["jt_end"])]
    fa = ["f_a", "f_b", "f_c"]
    sites = [
        dict(function="call_hs", call=L["site_hs"], kind="range", type=T_FILE, candidates=fa),
        dict(function="call_lo", call=L["site_lo"], kind="range", type=T_FILE, candidates=fa),
        dict(function="call_hi", call=L["site_hi"], kind="range", type=T_FILE, candidates=fa),
        dict(function="call_hoisted", call=L["site_hoisted"], kind="range", type=T_FILE, candidates=fa),
        dict(function="call_single", call=L["site_single"], kind="single", type=T_VOID, candidates=["g_one"]),
        dict(function="call_slow", call=L["site_slow"], kind="slowpath", type=T_READ, candidates=[]),
        dict(function="call_gap", call=L["site_gap"], kind="range", type=T_FILE, candidates=fa),
    ]
    for site in sites:
        site["type_id"] = "0x%016x" % _type_id(site["type"])
        site["call"] = "0x%x" % site["call"]
    truth = dict(base="0x%x" % JT_BASE, jump_table=["0x%x" % L["jt"], len(members)],
                 slowpath="0x%x" % L["__cfi_slowpath_diag"], sites=sites,
                 symbols={n: "0x%x" % v for n, v in symbols},
                 type_names={T_FILE: "int (file*, int)", T_VOID: "void (void*)",
                             T_READ: "long (file*, char*, unsigned long, long long*)"})
    return struct.pack("<%dI" % len(words), *words), symbols, truth


def elf64_aarch64(code, base, symbols):
    """A minimal ET_EXEC: one R+X PT_LOAD with the code, .text, .symtab (STT_FUNC), .strtab, .shstrtab."""
    strtab = b"\0"
    syms = [b"\0" * 24]
    for name, value in symbols:
        syms.append(struct.pack("<IBBHQQ", len(strtab), 0x12, 0, 1, value, 0))
        strtab += name.encode() + b"\0"
    symtab = b"".join(syms)
    shstr = b"\0.text\0.symtab\0.strtab\0.shstrtab\0"
    text_off = 0x1000
    sym_off = text_off + len(code)
    str_off = sym_off + len(symtab)
    shs_off = str_off + len(strtab)
    sh_off = (shs_off + len(shstr) + 7) & ~7
    eh = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    eh += struct.pack("<HHIQQQIHHHHHH", 2, 183, 1, base, 64, sh_off, 0, 64, 56, 1, 64, 5, 4)
    ph = struct.pack("<IIQQQQQQ", 1, 5, text_off, base, base, len(code), len(code), 0x1000)
    out = bytearray(eh + ph)
    out += b"\0" * (text_off - len(out)) + code + symtab + strtab + shstr
    out += b"\0" * (sh_off - len(out))
    sh = [struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
          struct.pack("<IIQQQQIIQQ", 1, 1, 6, base, text_off, len(code), 0, 0, 4, 0),
          struct.pack("<IIQQQQIIQQ", 7, 2, 0, 0, sym_off, len(symtab), 3, 1, 8, 24),
          struct.pack("<IIQQQQIIQQ", 15, 3, 0, 0, str_off, len(strtab), 0, 0, 1, 0),
          struct.pack("<IIQQQQIIQQ", 23, 3, 0, 0, shs_off, len(shstr), 0, 0, 1, 0)]
    return bytes(out + b"".join(sh))


def write_jtcfi():
    code, symbols, truth = jtcfi_program()
    os.makedirs(FIX, exist_ok=True)
    with open(os.path.join(FIX, "aarch64-jtcfi.elf"), "wb") as fh:
        fh.write(elf64_aarch64(code, JT_BASE, symbols))
    with open(os.path.join(FIX, "jtcfi_truth.json"), "w") as fh:
        json.dump(truth, fh, indent=1, sort_keys=True)
        fh.write("\n")


if __name__ == "__main__":
    if "--jtcfi-only" not in sys.argv[1:]:
        build_kcfi()
    write_jtcfi()
