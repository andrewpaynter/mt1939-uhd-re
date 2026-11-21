"""Map MT1939 functions (BL targets in a range) to identical MT1959 functions via xmatch; cache to scratch/halmap.json"""
import sys, json, collections
sys.path.insert(0, "/work/re")
import xmatch
from xmatch import A, md
import struct
def u16(img,a): return struct.unpack_from("<H",img,a)[0]
def bl_targets(img, lo, hi):
    c = collections.Counter()
    for a in range(0x10000, 0x1d0000, 2):
        h1, h2 = u16(img,a), u16(img,a+2)
        if (h1 & 0xf800) == 0xf000 and (h2 & 0xf800) == 0xf800:
            off = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
            if off & 0x400000: off -= 0x800000
            d = a + 4 + off
            if lo <= d < hi: c[d] += 1
    return c
lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
tg = bl_targets(A, lo, hi)
out = {}
for t, n in sorted(tg.items()):
    if n < 3: continue
    m = xmatch.match(t, ninsn=24, top=2)
    if m and m[0][2] >= 0.9 and (len(m) < 2 or m[1][1] < m[0][1] * 0.5):
        out[hex(t)] = (m[0][0], n)
json.dump(out, open(f"/work/scratch/halmap_{lo:x}_{hi:x}.json", "w"), indent=0)
print(len(tg), "targets;", len(out), "mapped"); print(list(out.items())[:15])
