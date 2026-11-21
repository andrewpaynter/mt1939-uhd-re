"""Parse the firmware-image segment/integrity table at image offset 0x10400.

Each record is 0x1C (28) bytes:
    word0 = flags   (bit0 = 'verify this segment'; 0xFFFFFFFF = end-of-list)
    word1 = start   (flash/image byte address, inclusive)
    word2 = end     (flash/image byte address, INCLUSIVE)
    word3..word6 = 128-bit digest (the hw hash engine at 0x04063000 compares against this)

The updater (handler 0xA3416) stages a full 2 MB image into DRAM, then the
finalize/verify (0x195980 -> 0x1957b4) walks this table and, for every record
whose flags bit0 is set, hashes [start..end] and compares the 4 output words
against word3..word6. A patched image must therefore carry a recomputed digest
for every segment it changes (including rec3, which covers the table itself).

Usage:  re/run re/segtable.py
"""
import sys; sys.path.insert(0, "/work/re")
from fw import u32

TABLE = 0x10400

def records(table=TABLE, maxrec=32):
    a = table
    for _ in range(maxrec):
        w0 = u32(a)
        if w0 == 0xFFFFFFFF:
            yield (a, w0, None, None, None); return
        start, end = u32(a + 4), u32(a + 8)
        digest = bytes().join(u32(a + 4 * k).to_bytes(4, "little") for k in range(3, 7))
        yield (a, w0, start, end, digest)
        a += 0x1C

if __name__ == "__main__":
    print(f"segment table @0x{TABLE:06x}")
    for a, flags, start, end, digest in records():
        if end is None:
            print(f"  @0x{a:06x}  END (0xFFFFFFFF)"); break
        size = end - start + 1
        print(f"  @0x{a:06x}  flags={flags:08x}  0x{start:06x}..0x{end:06x} "
              f"(0x{size:x} bytes)  digest={digest.hex()}")
    print("\nNOT covered by any record (untouched by a firmware update):")
    print("  0x000000-0x0103FF (boot block + image header)")
    print("  0x1D0000-0x1FFFFF (log save area, per-unit CALIBRATION 0x1E0000-0x1EFFFF, 0x1F0000)")
