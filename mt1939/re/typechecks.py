"""Census of tests on the disc-type byte: ldr rB,=TYPE ; ldrb rX,[rB(,#k)] ; (ands/lsrs) ; cmp rX,#imm"""
import sys, struct, re, collections
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
def census(img, typeaddr, regions):
    out = collections.defaultdict(list)
    for lo, hi in regions:
        for lit in range(lo, hi, 4):
            if struct.unpack_from("<I", img, lit)[0] != typeaddr: continue
            for a in range(max(lo, lit - 1020), lit, 2):
                h = struct.unpack_from("<H", img, a)[0]
                if (h & 0xf800) != 0x4800 or ((a + 4) & ~3) + (h & 0xff) * 4 != lit: continue
                rb = f"r{(h >> 8) & 7}"; val = None; mask = None; shift = None; vr = None
                for i in list(md.disasm(img[a + 2:a + 40], a + 2))[:12]:
                    s = f"{i.mnemonic} {i.op_str}"
                    m = re.match(rf"ldrb (r\d), \[{rb}\]$", s)
                    if m and vr is None: vr = m.group(1); continue
                    if vr is None: continue
                    m = re.match(rf"lsrs {vr}, {vr}, #(\w+)", s) or re.match(rf"lsrs {vr}, (?:r\d), #(\w+)", s)
                    if m: shift = int(m.group(1), 0); continue
                    m = re.match(rf"ands {vr}, (r\d)", s)
                    if m: mask = "reg"; continue
                    m = re.match(rf"cmp {vr}, #(\w+)", s)
                    if m: out[(shift, int(m.group(1), 0))].append(i.address); break
                    if i.mnemonic in ("bl", "blx", "pop", "bx", "b"): break
    return out
A = B = None
if __name__ == "__main__":
  A = open("/work/dumps/dumpA_0-2M.bin", "rb").read(); B = open("/work/mt1959/WH16NS60_1.01_stock.bin", "rb").read()
  ca = census(A, 0x01FF9DD3, [(0x10000, 0x1d0000)]); cb = census(B, 0x01FF9E00, [(0x10000, 0x15c000), (0x1b0000, 0x1c8000)])
  keys = sorted(set(ca) | set(cb), key=lambda k: (k[0] or 0, k[1]))
  print("(shift, cmp)    MT1939  MT1959")
  for k in keys:
      print(f"  {str(k):14} {len(ca.get(k, [])):5}  {len(cb.get(k, [])):5}   {'B-only sites ' + ' '.join(hex(x) for x in cb[k][:8]) if k not in ca else ''}{'A-only sites ' + ' '.join(hex(x) for x in ca[k][:8]) if k not in cb else ''}")
