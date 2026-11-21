"""For mapped HAL function pairs (scratch/halmap_*.json), collect constant r0-r3 args at all BL call sites
in each image and report argument tuples used only by MT1959 (and only by MT1939)."""
import sys, json, glob, struct, collections, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
A = open("/work/dumps/dumpA_0-2M.bin", "rb").read(); B = open("/work/mt1959/WH16NS60_1.01_stock.bin", "rb").read()
def u16(img, a): return struct.unpack_from("<H", img, a)[0]
def callers(img):
    d = collections.defaultdict(list)
    for a in range(0x10000, 0x1d0000, 2):
        h1, h2 = u16(img, a), u16(img, a + 2)
        if (h1 & 0xf800) == 0xf000 and (h2 & 0xf800) == 0xf800:
            off = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
            if off & 0x400000: off -= 0x800000
            d[a + 4 + off].append(a)
    return d
def args_at(img, call):
    for back in range(24, 0, -2):
        start = call - back; ins = list(md.disasm(img[start:call], start))
        if not ins or ins[-1].address + ins[-1].size != call: continue
        regs = {}
        for i in ins:
            s = f"{i.mnemonic} {i.op_str}"; b = i.bytes
            if len(b) == 2 and ((b[0] | b[1] << 8) & 0xf800) == 0x4800:
                la = ((i.address + 4) & ~3) + b[0] * 4; regs[i.op_str.split(",")[0]] = struct.unpack_from("<I", img, la)[0]; continue
            m = re.match(r"movs (r\d), #(0x[0-9a-f]+|\d+)$", s)
            if m: regs[m.group(1)] = int(m.group(2), 0); continue
            m = re.match(r"(lsls|adds|subs) (r\d), (r\d), #(0x[0-9a-f]+|\d+)$", s)
            if m and m.group(3) in regs:
                v, k = regs[m.group(3)], int(m.group(4), 0)
                regs[m.group(2)] = (v << k) & 0xffffffff if m.group(1) == "lsls" else (v + k if m.group(1) == "adds" else v - k); continue
            m = re.match(r"(adds|subs) (r\d), #(0x[0-9a-f]+|\d+)$", s)
            if m and m.group(2) in regs:
                regs[m.group(2)] += int(m.group(3), 0) * (1 if m.group(1) == "adds" else -1); continue
            d = i.op_str.split(",")[0] if i.op_str else None
            if d in regs and not i.mnemonic.startswith(("str", "cmp", "tst")): regs.pop(d)
            if i.mnemonic in ("bl", "blx", "push", "pop"): regs = {}
        return tuple(regs.get(f"r{k}") for k in range(4))
    return (None,) * 4
mp = {}
for f in glob.glob("/work/scratch/halmap_*.json"):
    mp.update({int(k, 16): int(v[0], 16) for k, v in json.load(open(f)).items()})
cA, cB = callers(A), callers(B)
for ta, tb in sorted(mp.items()):
    sa = collections.Counter(args_at(A, c) for c in cA.get(ta, []))
    sb = collections.Counter(args_at(B, c) for c in cB.get(tb, []))
    fmt = lambda t: "(" + ",".join("?" if x is None else hex(x) for x in t) + ")"
    onlyB = {k: v for k, v in sb.items() if k not in sa and any(x is not None for x in k)}
    onlyA = {k: v for k, v in sa.items() if k not in sb and any(x is not None for x in k)}
    if onlyB or onlyA:
        print(f"{ta:#x}->{tb:#x}  calls A={sum(sa.values())} B={sum(sb.values())}")
        if onlyB: print("   only MT1959:", ", ".join(f"{fmt(k)}x{v}" for k, v in sorted(onlyB.items(), key=str)))
        if onlyA: print("   only MT1939:", ", ".join(f"{fmt(k)}x{v}" for k, v in sorted(onlyA.items(), key=str)))
