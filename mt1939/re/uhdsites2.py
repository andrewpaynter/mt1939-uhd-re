"""Thorough census of MT1959 UHD-only tests: `cmp rX,#0xC7` and `lsrs rX,#2 ; cmp rX,#0x32`.
For each: containing function, and in the next N instrs: MMIO literals (0x04xxxxxx), BL targets,
and r0/r1 constants right before calls to DSP write 0x5B64C / front-end param write 0x5BBE2.
Usage: re/run re/uhdsites2.py [N]"""
import sys, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
IMG = open("/work/mt1959/combined_1.01.bin", "rb").read()
REG = [(0x10000, 0x15c000), (0x1b0000, 0x1c8000), (0x01F78000, 0x01F78000 + 0x727dc)]
N = int(sys.argv[1]) if len(sys.argv) > 1 else 30
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
u16 = lambda a: struct.unpack_from("<H", IMG, a)[0]
u32 = lambda a: struct.unpack_from("<I", IMG, a)[0]
def fstart(a):
    for x in range(a & ~1, a - 0x3000, -2):
        h = u16(x)
        if (h & 0xff00) == 0xb500 or ((h & 0xfe00) == 0xb400 and h & 0x100): return x
def window(a):
    mm, calls, notes = set(), [], []
    last = {}
    for i in md.disasm(IMG[a:a + N * 4 + 8], a):
        b = i.bytes
        if len(b) == 2:
            h = b[0] | b[1] << 8
            if (h & 0xf800) == 0x4800:
                v = u32(((i.address + 4) & ~3) + (h & 0xff) * 4); last[(h >> 8) & 7] = v
                if 0x04000000 <= v < 0x05000000: mm.add(hex(v))
            elif (h & 0xf800) == 0x2000: last[(h >> 8) & 7] = h & 0xff
        if i.mnemonic in ("bl", "blx"):
            t = int(i.op_str.lstrip("#"), 16); calls.append(hex(t))
            if t in (0x5b64c, 0x5b670): notes.append(f"DSP[{hex(last.get(0, -1))}]")
            if t == 0x5bbe2: notes.append(f"FEparam[{hex(last.get(1, -1))}]")
        if len(calls) > 8: break
    return sorted(mm), calls, notes
sites = []
for lo, hi in REG:
    for a in range(lo, min(hi, len(IMG) - 4), 2):
        h = u16(a)
        if (h & 0xf8ff) == 0x28c7: sites.append((a, "==C7"))
        if (h & 0xf8ff) == 0x2832:
            p = u16(a - 2)
            if (p & 0xffc0) == 0x0880: sites.append((a, ">>2==32"))
seen = set()
for a, k in sites:
    f = fstart(a)
    mm, calls, notes = window(a)
    print(f"{a:#09x} fn {f:#09x} {k:8s} mmio {mm} {' '.join(notes)} calls {calls[:6]}")

def c8class_nearby(a, back=24, fwd=0):
    """True if a `movs rX,#0xC8` + `bics` (C8-class test) sits within `back` bytes before a."""
    for x in range(a - back, a, 2):
        h = u16(x)
        if (h & 0xf8ff) == 0x20c8:
            for y in range(x + 2, x + 10, 2):
                if (u16(y) & 0xffc0) == 0x4380: return True
    return False
