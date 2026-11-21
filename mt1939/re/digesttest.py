"""Digest-algorithm candidate tester for the 0x04063000 hw hash engine.

Decider for the project: reproduce one stored segment digest offline (e.g. rec0
over flash 0x11000-0x15FFF = 7ec0accc8595e2ab9f4f0a6522f92292). `_aescore.py`
holds a FIPS-197-verified pure-python AES-128 (encrypt). This script sweeps
hash/MAC candidates against the four segment records.

Status 2026-11-21: NONE of ~80 tested candidates reproduce rec0 (see the
progress-log entry "digest algorithm — engine fully mapped; ~80 candidates ruled
out"). The committed candidates() below is a representative subset; the fuller
sweep (MD5 32-combo IV/pad/endian, MD4, FNV-128, AES-192/256, AES-CMAC, AES
decrypt-direction chaining, record-header/IV/length variants) was run from scratch
scripts and is documented in the doc, not all re-committed here.

★ SOLVED (see re/cmac.py): the digest is AES-128-CMAC under a PUBLIC non-zero key
(BD2094...E8AB), over image[start..=end] with each 16-byte block byte-reversed and
the output byte-reversed. This sweep missed it because it only tried a ZERO key and
per-WORD byte-swaps. This file is kept as the historical negative record; use
re/cmac.py for anything real.
Run:  re/run re/digesttest.py
"""
import sys, hashlib
sys.path.insert(0, "/work/re")
from _aescore import encrypt_block, key_expansion

RECS = [
    (0x011000, 0x015fff, "7ec0accc8595e2ab9f4f0a6522f92292"),
    (0x017000, 0x0fffff, "4e5d45f3e3454ecc9309fd7fd7d038b2"),
    (0x100000, 0x1cffff, "3bab0c06f1c4c655f5877dcf74a5f584"),
    (0x010400, 0x01045f, "021cfc500d4c02455d298ded98745adb"),
]
FW = open("/work/dumps/dumpA_0-2M.bin", "rb").read()
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
wswap = lambda b: b"".join(b[i:i+4][::-1] for i in range(0, len(b), 4))
E = lambda k, p: encrypt_block(p, key_expansion(k))

def candidates(data):
    """name -> 16-byte digest. Extend here."""
    c = {}
    m = hashlib.md5(data).digest()
    c["md5"] = m; c["md5 wswap"] = wswap(m); c["md5 rev"] = m[::-1]
    for a in ("sha1", "sha256", "blake2b", "blake2s"):
        h = hashlib.new(a, data).digest(); c[a+"[:16]"] = h[:16]; c[a+"[-16:]"] = h[-16:]
    for lbl, tf in (("raw", lambda b: b), ("wswap", wswap)):
        blks = [tf(data[i:i+16]) for i in range(0, len(data), 16)]
        for name, fn in (
            ("cbcmac0", None), ("DM", None), ("MMO", None), ("MP", None)):
            H = bytes(16)
            for M in blks:
                if name == "cbcmac0": H = E(bytes(16), xor(H, M))
                elif name == "DM": H = xor(E(M, H), H)
                elif name == "MMO": H = xor(E(H, M), M)
                elif name == "MP": H = xor(xor(E(H, M), M), H)
            c[f"{name} {lbl}"] = H; c[f"{name} {lbl} os"] = wswap(H)
    return c

def run(which=(0,)):
    for idx in which:
        s, e, tgt = RECS[idx]
        data = FW[s:e+1]
        print(f"rec{idx} 0x{s:06x}..0x{e:06x} len={len(data)} target={tgt}")
        for n, v in candidates(data).items():
            print(f"  {'*** MATCH ***' if v.hex()==tgt else '            '} {n:16} {v.hex()}")

if __name__ == "__main__":
    run((0,))
