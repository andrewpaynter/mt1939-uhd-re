"""Calls to the front-end param accessor with a constant index in r0 (read) or r1 (write)."""
import sys, struct, os
sys.path.insert(0, "/work/re"); sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/../re")
from dspparams import callers
img = open(sys.argv[1], "rb").read(); tgt = int(sys.argv[2], 16); reg = int(sys.argv[3])
regions = [(0x10000, 0x1d0000)] if len(img) < 0x1000000 else [(0x10000, 0x15c000), (0x1b0000, 0x1c8000), (0x01F78000, 0x01F78000 + 0x727dc)]
def rconst(a, r):
    for back in range(2, 30, 2):
        h = struct.unpack_from("<H", img, a - back)[0]
        if (h & 0xf800) == 0x2000 and ((h >> 8) & 7) == r: return h & 0xff
        if (h & 0xf800) == 0xf000: return None
    return None
from collections import defaultdict
out = defaultdict(list)
for a, d in callers(img, {tgt}, regions): out[rconst(a, reg)].append(a)
for k in sorted(out, key=lambda k: (k is None, k or 0)):
    print(("?" if k is None else hex(k)), len(out[k]), [hex(x) for x in out[k][:12]])
