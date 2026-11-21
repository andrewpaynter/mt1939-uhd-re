"""Resolve MT1959 ARM veneer chains (ldr pc,[pc,#-4] / ARM b) and list every veneer address that ends at a target.
Usage: from veneers import into; into(img, 0x5b64c) -> [veneer addrs]"""
import struct
def hop(img, a):
    for _ in range(4):
        a &= ~1
        if a + 8 > len(img): return a
        w = struct.unpack_from("<I", img, a)[0]
        if w == 0xe51ff004: a = struct.unpack_from("<I", img, a + 4)[0]; continue
        if (w >> 24) == 0xea:
            off = w & 0xffffff
            if off & 0x800000: off -= 1 << 24
            a = a + 8 + off * 4; continue
        break
    return a & ~1
REGIONS = [(0x147cd0, 0x149090), (0x01FE8000, 0x01FEA8DC), (0x0dc000, 0x0dd000), (0x148000, 0x148100), (0x01fba000, 0x01fbb000)]
def into(img, target):
    out = []
    for lo, hi in REGIONS:
        for a in range(lo, min(hi, len(img) - 8), 4):
            w = struct.unpack_from("<I", img, a)[0]
            if (w == 0xe51ff004 or (w >> 24) == 0xea) and hop(img, a) == target & ~1: out.append(a)
    return out
