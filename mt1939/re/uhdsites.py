"""List MT1959 UHD-class type tests ((type>>2)==0x32, type==0xC7) with the enclosing function,
MMIO literals and calls within the following ~40 instructions."""
import sys, struct, re
sys.path.insert(0, "/work/re")
from typechecks import census
B = open("/work/mt1959/WH16NS60_1.01_stock.bin", "rb").read()
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cb = census(B, 0x01FF9E00, [(0x10000, 0x15c000), (0x1b0000, 0x1c8000)])
sites = sorted(set(cb.get((2, 50), []) + cb.get((None, 199), [])))
def u16(a): return struct.unpack_from("<H", B, a)[0]
def fstart(a):
    for x in range(a & ~1, max(a - 0x2000, 0x10000), -2):
        h = u16(x)
        if (h & 0xff00) == 0xb500 or ((h & 0xfe00) == 0xb400 and h & 0x100): return x
for s in sites:
    lits, calls = [], []
    for i in list(md.disasm(B[s:s + 120], s))[:40]:
        b = i.bytes
        if len(b) == 2 and ((b[0] | b[1] << 8) & 0xf800) == 0x4800:
            v = struct.unpack_from("<I", B, ((i.address + 4) & ~3) + b[0] * 4)[0]
            if 0x04000000 <= v < 0x05000000: lits.append(hex(v))
        if i.mnemonic in ("bl", "blx"): calls.append(i.op_str.replace("#", ""))
    print(f"{s:#x} fn {fstart(s):#x}  mmio {sorted(set(lits))}  calls {calls[:6]}")
