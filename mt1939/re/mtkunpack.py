"""Unpacker for the MT1959 packed code overlay (format per MakeMKV forum t=41920, ibizara/RibShark;
reimplemented here). Header @region: u32 out_size, u32 span, 288 lit/len code lengths, 32 dist code lengths,
bitstream @+0x148 (MSB-first). Canonical Huffman; sym<256 literal, 256..287 -> match length sym-253;
distance = (dsym<<7) | 7 raw bits. Then Thumb BL fixup: packed BLs hold overlay-absolute targets
(new_imm = raw_imm - (off+4)).
Usage: re/run re/mtkunpack.py <image> <region_off> <out.bin> [ram_base]"""
import sys, struct
def canon(lengths):
    maxl = max(lengths); bl_count = [0] * (maxl + 1)
    for l in lengths:
        if l: bl_count[l] += 1
    code = 0; next_code = [0] * (maxl + 2)
    for bits in range(1, maxl + 1):
        code = (code + bl_count[bits - 1]) << 1; next_code[bits] = code
    table = {}
    for sym, l in enumerate(lengths):
        if l: table[(l, next_code[l])] = sym; next_code[l] += 1
    return table, maxl
class Bits:
    def __init__(s, data): s.d = data; s.p = 0
    def bit(s):
        b = (s.d[s.p >> 3] >> (7 - (s.p & 7))) & 1; s.p += 1; return b
    def bits(s, n):
        v = 0
        for _ in range(n): v = (v << 1) | s.bit()
        return v
def decode_sym(br, table, maxl):
    code = 0
    for l in range(1, maxl + 1):
        code = (code << 1) | br.bit()
        s = table.get((l, code))
        if s is not None: return s
    raise ValueError(f"bad code at bit {br.p}")
def unpack(img, off):
    out_size, span = struct.unpack_from("<II", img, off)
    ll = list(img[off + 8:off + 8 + 288]); dl = list(img[off + 0x128:off + 0x128 + 32])
    lt, lm = canon(ll); dt, dm = canon(dl)
    br = Bits(img[off + 0x148:off + span]); total = (span - 0x148) * 8
    out = bytearray()
    while len(out) < out_size and br.p < total - 1:
        try: s = decode_sym(br, lt, lm)
        except (ValueError, IndexError): break
        if s < 256: out.append(s); continue
        length = s - 253
        ds = decode_sym(br, dt, dm); dist = (ds << 7) | br.bits(7)
        if dist == 0 or dist > len(out): raise ValueError(f"bad dist {dist} at out {len(out):#x}")
        for _ in range(length): out.append(out[-dist])
    return out_size, span, out, br.p
def fixup_bl(buf):
    """Convert packed overlay-absolute BL targets to PC-relative. Returns count."""
    n = 0; a = 0
    while a + 4 <= len(buf):
        h1, h2 = struct.unpack_from("<HH", buf, a)
        if (h1 & 0xf800) == 0xf000 and (h2 & 0xf800) == 0xf800:
            raw = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
            if raw & 0x400000: raw -= 0x800000
            new = raw - (a + 4)
            if -0x400000 <= new < 0x400000:
                new &= 0x7fffff
                struct.pack_into("<HH", buf, a, 0xf000 | (new >> 12) & 0x7ff, 0xf800 | (new >> 1) & 0x7ff)
                n += 1; a += 4; continue
        a += 2
    return n
if __name__ == "__main__":
    img = open(sys.argv[1], "rb").read(); off = int(sys.argv[2], 16)
    out_size, span, out, bitpos = unpack(img, off)
    print(f"declared out {out_size:#x}, span {span:#x}; produced {len(out):#x}; consumed {bitpos // 8:#x} of {span - 0x148:#x} stream bytes")
    open(sys.argv[3] + ".raw", "wb").write(out)
    fx = bytearray(out); n = fixup_bl(fx); open(sys.argv[3], "wb").write(fx)
    print(f"BL fixups applied: {n}; wrote {sys.argv[3]} (+ .raw)")
