"""Compare MMIO register usage (32-bit literals in 0x04000000-0x04FFFFFF) between two images.
Usage: re/run re/hwregs.py [imgA] [imgB]   (defaults: MT1939 dump vs MT1959 WH16NS60 1.01)"""
import struct, sys, collections
A = sys.argv[1] if len(sys.argv) > 1 else "/work/dumps/dumpA_0-2M.bin"
B = sys.argv[2] if len(sys.argv) > 2 else "/work/mt1959/WH16NS60_1.01_stock.bin"
def regs(path, lo=0x10000, hi=0x1E0000):
    b = open(path, "rb").read(); c = collections.Counter()
    for a in range(lo, hi, 4):
        v = struct.unpack_from("<I", b, a)[0]
        if 0x04000000 <= v < 0x05000000: c[v] += 1
    return c
ra, rb = regs(A), regs(B)
blk = lambda c: collections.Counter({k: sum(v for r, v in c.items() if r >> 12 == k) for k in {r >> 12 for r in c}})
ba, bb = blk(ra), blk(rb)
print(f"literals: A={sum(ra.values())} distinct={len(ra)}  B={sum(rb.values())} distinct={len(rb)}")
print(f"4K blocks: A={len(ba)} B={len(bb)} common={len(set(ba)&set(bb))}")
print("\n4K blocks ONLY in B (MT1959):"); [print(f"  {k<<12:#010x}: {bb[k]} refs") for k in sorted(set(bb)-set(ba))]
print("\n4K blocks ONLY in A (MT1939):"); [print(f"  {k<<12:#010x}: {ba[k]} refs") for k in sorted(set(ba)-set(bb))]
print("\nCommon blocks with big usage change (A -> B):")
for k in sorted(set(ba)&set(bb)):
    if abs(ba[k]-bb[k]) >= max(8, 0.5*ba[k]): print(f"  {k<<12:#010x}: {ba[k]} -> {bb[k]}")
for blkaddr in (0x04206, 0x04030, 0x040b0, 0x040c0, 0x040d0, 0x04087, 0x04204):
    oa = {r for r in ra if r >> 12 == blkaddr}; ob = {r for r in rb if r >> 12 == blkaddr}
    print(f"\nblock {blkaddr<<12:#x}: A regs {len(oa)}, B regs {len(ob)}; only-B: {[hex(x) for x in sorted(ob-oa)][:30]}; only-A: {[hex(x) for x in sorted(oa-ob)][:30]}")
for r in (0x04206080, 0x04030020, 0x0403006C):
    print(f"refs {r:#x}: A={ra[r]} B={rb[r]}")
