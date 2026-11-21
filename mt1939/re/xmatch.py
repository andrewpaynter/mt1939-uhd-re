"""Cross-firmware function matcher (BinDiff-lite) for MT1939 -> MT1959.
Normalizes Thumb instructions (call targets, PC-relative literals, branch offsets abstracted;
MMIO literals 0x04xxxxxx kept since the register map is shared) and votes with n-gram shingles.
Usage: re/run re/xmatch.py 0x10377c 0xb9fb0 ...     (addresses in the MT1939 dump)"""
import struct, sys, collections, pickle, os
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
A = open(os.environ.get("FWA", "/work/dumps/dumpA_0-2M.bin"), "rb").read()
B = open(os.environ.get("FWB", "/work/mt1959/WH16NS60_1.01_stock.bin"), "rb").read()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = False
N = 6
def lit(img, ins):
    b = ins.bytes
    if len(b) == 2:
        h = b[0] | b[1] << 8
        if (h & 0xf800) == 0x4800:
            la = ((ins.address + 4) & ~3) + (h & 0xff) * 4
            if la + 4 <= len(img): return struct.unpack_from("<I", img, la)[0]
    return None
def tok(img, ins):
    m = ins.mnemonic
    if m in ("bl", "blx"): return "CALL"
    if m.startswith("b") and m not in ("bic", "bics") and "#" in ins.op_str: return m.split(".")[0] + " L"
    v = lit(img, ins)
    if v is not None:
        rd = ins.op_str.split(",")[0]
        return f"ldr {rd},=" + (hex(v) if 0x04000000 <= v < 0x05000000 or v < 0x10000 else "PTR")
    if m.startswith("add") and "pc" in ins.op_str: return "adr"
    return m + " " + ins.op_str
def stream(img, lo, hi):
    out = []; a = lo
    while a < hi:
        got = False
        for ins in md.disasm(img[a:a + 4], a, 1):
            out.append((a, tok(img, ins))); a += ins.size; got = True
        if not got: out.append((a, "??")); a += 2
    return out
CACHE = "/work/scratch/xmatch_" + os.path.basename(os.environ.get("FWB", "mt1959")) + ".pkl"
def indexB():
    if os.path.exists(CACHE): return pickle.load(open(CACHE, "rb"))
    s = []
    for lo, hi in ([(0x10000, 0x1d0000)] if os.environ.get("FWB", "").endswith("dumpA_0-2M.bin") else [(0x10000, 0x15c000), (0x1b0000, 0x1c8000)]): s += stream(B, lo, hi)
    idx = collections.defaultdict(list)
    for i in range(len(s) - N):
        idx["\x1f".join(t for _, t in s[i:i + N])].append(i)
    r = (s, dict(idx)); pickle.dump(r, open(CACHE, "wb")); return r
def match(addr, ninsn=60, top=3):
    addr &= ~1
    sa = []; a = addr
    while len(sa) < ninsn:
        got = False
        for ins in md.disasm(A[a:a + 4], a, 1): sa.append((a, tok(A, ins))); a += ins.size; got = True
        if not got: sa.append((a, "??")); a += 2
    sB, idx = indexB()
    votes = collections.Counter()
    for i in range(len(sa) - N):
        for j in idx.get("\x1f".join(t for _, t in sa[i:i + N]), []):
            if len(idx["\x1f".join(t for _, t in sa[i:i + N])]) > 20: break   # skip ubiquitous shingles
            votes[sB[j - i][0] if j - i >= 0 else None] += 1
    return [(hex(b) if b is not None else None, v, round(v / (len(sa) - N), 2)) for b, v in votes.most_common(top)]
if __name__ == "__main__":
    for x in sys.argv[1:]: print(x, match(int(x, 16)))
