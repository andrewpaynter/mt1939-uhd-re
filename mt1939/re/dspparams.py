"""Census of servo-DSP parameter writes (mailbox 0x04206000: [+0x10]=value, [+0]=0x900000|index).
Finds BL/BLX calls to the write function(s) and the constant index loaded into r0 just before.
Usage: re/run re/dspparams.py   (compares MT1939 dump vs MT1959 combined image)"""
import struct, sys, pickle
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

def load(p): return open(p, "rb").read()

def callers(img, targets, regions):
    """Return list of (call_addr, target) for Thumb BL/BLX whose dest is in targets."""
    out = []
    for lo, hi in regions:
        for a in range(lo, min(hi, len(img) - 4), 2):
            h1, h2 = struct.unpack_from("<HH", img, a)
            if (h1 & 0xf800) == 0xf000 and (h2 & 0xe800) == 0xe800:
                off = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
                if off & 0x400000: off -= 0x800000
                d = a + 4 + off
                if not (h2 & 0x1000): d &= ~3
                if d in targets: out.append((a, d))
    return out

def r0_const(img, call):
    """Best-effort constant in r0 at call: scan back up to 12 instrs for movs r0,#/ldr r0,=."""
    for back in range(2, 26, 2):
        a = call - back
        h = struct.unpack_from("<H", img, a)[0]
        if (h & 0xff00) == 0x2000: return h & 0xff                     # movs r0,#imm
        if (h & 0xff00) == 0x4800:                                     # ldr r0,[pc,#]
            lit = ((a + 4) & ~3) + (h & 0xff) * 4
            return struct.unpack_from("<I", img, lit)[0]
        if (h & 0xffc7) == 0x0000 and h != 0: pass
        if (h & 0xf800) == 0xf000: return None                         # crossed another call
        if (h & 0x0007) == 0 and (h & 0xf800) in (0x6800, 0x7800, 0x8800, 0x5800): return None  # r0 loaded from mem
        if (h & 0xffc7) in (0x0000,) : pass
    return None

def census(img, targets, regions):
    res = {}
    for a, d in callers(img, targets, regions):
        k = r0_const(img, a)
        res.setdefault(k, []).append(a)
    return res

if __name__ == "__main__":
    A = load("/work/dumps/dumpA_0-2M.bin")
    B = load("/work/mt1959/combined_1.01.bin")
    tA = {int(x, 16) for x in sys.argv[1].split(",")} if len(sys.argv) > 1 else {0x5be7c}
    tB = {int(x, 16) for x in sys.argv[2].split(",")} if len(sys.argv) > 2 else {0x5b64c}
    cA = census(A, tA, [(0x10000, 0x1d0000)])
    cB = census(B, tB, [(0x10000, 0x15c000), (0x1b0000, 0x1c8000), (0x01F78000, 0x01F78000 + 0x727dc)])
    keys = sorted(set(cA) | set(cB), key=lambda k: (k is None, k or 0))
    for k in keys:
        a, b = cA.get(k, []), cB.get(k, [])
        flag = "" if a and b else ("  <-- MT1959 ONLY" if b else "  <-- MT1939 only")
        ks = "?" if k is None else hex(k)
        print(f"{ks:>10}: A {len(a):3d} B {len(b):3d}  {[hex(x) for x in a[:4]]} {[hex(x) for x in b[:4]]}{flag}")
