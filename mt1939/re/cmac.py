"""MT1939/MT1959 firmware-integrity digest = AES-128-CMAC. SOLVED 2026-11-21.

The per-segment 128-bit "digest" the updater (0x1957B4) and boot block verify via
the hardware engine at 0x04063000 is **AES-128-CMAC** (RFC 4493, zero IV) under a
*public, fixed* integrity key, computed over image[start..=end] with each 16-byte
block byte-reversed, and the 16-byte result byte-reversed before storage.

This was identified from the MakeMKV-community reverse-engineering crate
`mediatek-optical` by MattJackson (github.com/MattJackson/mediatek-optical,
src/envelope/image/cmac.rs) and then VERIFIED here: it reproduces all four stored
digests of our WH16NS40 1.00 dump exactly (run this file). So patched-segment
digests ARE regenerable offline — the old "can't recompute" blocker is removed.

Key facts:
  - AES-128-CMAC, standard K1/K2 subkeys, zero IV.
  - KEY = BD209408E35E526A36235234434FE8AB  (public integrity key; NOT a secret /
    NOT an AACS key. Shared by MT1939 and MT1959. It is a hardwired constant in the
    hash engine, which is why no key-load appears in the firmware's hash path.)
  - Per-segment input transform: data = image[start..=end]; reverse each 16-byte
    block (aligned to start); cmac = AES-CMAC(KEY, reversed); store cmac[::-1].
  - Table at image 0x10400: 16 entries x 28 bytes, struct "<3L16s" =
    {enabled u32 (1=active, 0xFFFFFFFF=unused), start u32, end u32, digest[16]}.
  - Re-sign order: sign all data segments first; the entry that covers the table
    itself (rec3, 0x10400..0x1045F) is signed LAST over the updated table bytes.

Run:  re/run re/cmac.py      (verify the dump)   — or host:  python3 -I re/cmac.py
"""
import sys, os, struct
_RE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/work/re"); sys.path.insert(0, _RE)
from _aescore import encrypt_block, key_expansion

CMAC_KEY = bytes.fromhex("BD209408E35E526A36235234434FE8AB")
TABLE_OFFSET = 0x10400
ENTRY_FMT = "<3L16s"   # enabled, start, end, digest(stored byte-reversed)
ENTRY_SIZE = 28
ENTRY_COUNT = 16
_W = key_expansion(CMAC_KEY)
_xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))

def _dbl(b):
    v = int.from_bytes(b, "big"); msb = b[0] & 0x80
    v = (v << 1) & ((1 << 128) - 1)
    if msb: v ^= 0x87
    return v.to_bytes(16, "big")

def aes_cmac(msg):
    L = encrypt_block(bytes(16), _W); K1 = _dbl(L); K2 = _dbl(K1)
    if not msg:
        blocks = [_xor(bytes([0x80]) + bytes(15), K1)]
    else:
        n = (len(msg) + 15) // 16
        blocks = [msg[i*16:(i+1)*16] for i in range(n)]
        if len(blocks[-1]) == 16:
            blocks[-1] = _xor(blocks[-1], K1)
        else:
            pad = blocks[-1] + bytes([0x80]) + bytes(15 - len(blocks[-1]))
            blocks[-1] = _xor(pad, K2)
    X = bytes(16)
    for b in blocks: X = encrypt_block(_xor(X, b), _W)
    return X

def _rev16(data):
    return b"".join(data[i:i+16][::-1] for i in range(0, len(data), 16))

def seg_digest(image, start, end):
    """Stored-form digest for image[start..=end] (end inclusive)."""
    return aes_cmac(_rev16(image[start:end+1]))[::-1]

def table_entries(image):
    out = []
    for i in range(ENTRY_COUNT):
        off = TABLE_OFFSET + i * ENTRY_SIZE
        en, s, e, dig = struct.unpack_from(ENTRY_FMT, image, off)
        out.append((i, en, s, e, dig))
    return out

def verify(image):
    ok = True
    for i, en, s, e, dig in table_entries(image):
        if en == 0xFFFFFFFF:  # unused
            continue
        if en != 1:
            print(f"  rec{i}: refused (enabled=0x{en:08x})"); ok = False; continue
        got = seg_digest(image, s, e)
        m = got == dig
        ok &= m
        print(f"  rec{i}: 0x{s:06x}..0x{e:06x}  {'OK' if m else 'MISMATCH '+got.hex()}")
    return ok

def resign(image):
    """Return a re-signed copy of `image` (2 MiB bytes): recompute the CMAC of
    every active table entry, writing the entry that covers the table itself LAST
    (so it hashes the updated table bytes). Mirrors the crate's re-sign ordering.
    Refuses the circular cases the crate refuses."""
    img = bytearray(image)
    entries = table_entries(img)
    active = [(i, s, e) for (i, en, s, e, _d) in entries if en == 1]
    if not active:
        raise ValueError("no active entries")
    # classify: which active entry covers the table region (0x10400)
    def covers_table(s, e): return s <= TABLE_OFFSET <= e
    tbl = [(i, s, e) for (i, s, e) in active if covers_table(s, e)]
    if len(tbl) > 1:
        raise ValueError("more than one active entry covers the table (circular)")
    for i, s, e in tbl:
        # must not cover its own digest bytes
        dig_off = TABLE_OFFSET + i * ENTRY_SIZE + 12
        if s <= dig_off <= e:
            raise ValueError("table entry covers its own digest (circular)")
    data_first = [(i, s, e) for (i, s, e) in active if not covers_table(s, e)]
    def write_digest(i, s, e):
        d = seg_digest(img, s, e)
        off = TABLE_OFFSET + i * ENTRY_SIZE + 12
        img[off:off+16] = d
    for i, s, e in data_first:
        write_digest(i, s, e)
    for i, s, e in tbl:            # table-covering entry signed last
        write_digest(i, s, e)
    return bytes(img)

if __name__ == "__main__":
    p = "/work/dumps/dumpA_0-2M.bin"
    if not os.path.exists(p): p = os.path.join(_RE, "..", "dumps", "dumpA_0-2M.bin")
    img = open(p, "rb").read()
    print(f"verifying {p} ({len(img)} bytes)")
    print("ALL DIGESTS VERIFIED" if verify(img) else "VERIFICATION FAILED")
