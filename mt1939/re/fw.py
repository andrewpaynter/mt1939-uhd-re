"""Helpers for poking at the MT1939 WH16NS40 1.00 firmware dump (flash offset == CPU address assumed)."""
import struct, re, sys
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
FW = open("/work/dumps/dumpA_0-2M.bin", "rb").read()
_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM); _thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for c in (_arm, _thumb): c.detail = False

def u32(a): return struct.unpack_from("<I", FW, a)[0]
def u16(a): return struct.unpack_from("<H", FW, a)[0]

def dis(addr, n=20, thumb=None):
    """Disassemble n instructions at addr. Odd addr or thumb=True -> Thumb."""
    if thumb is None: thumb = bool(addr & 1)
    addr &= ~1
    md = _thumb if thumb else _arm
    out = []
    for i in md.disasm(FW[addr:addr + n * 4 + 8], addr):
        out.append(f"{i.address:06x}: {i.bytes.hex():<10} {i.mnemonic:<8} {i.op_str}")
        if len(out) >= n: break
    return "\n".join(out)

def find(b):
    return [m.start() for m in re.finditer(re.escape(b), FW)]

def refs32(value):
    """Places where a 32-bit little-endian literal equals value (or value|1)."""
    out = []
    for v in {value, value | 1}:
        out += find(struct.pack("<I", v))
    return sorted(out)

if __name__ == "__main__":
    a = int(sys.argv[1], 16); n = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    t = sys.argv[3] == "t" if len(sys.argv) > 3 else None
    print(dis(a, n, t))

def disa(addr, n=40):
    """Thumb disassembly with literal-pool values and call targets annotated."""
    addr &= ~1; out = []
    for i in _thumb.disasm(FW[addr:addr + n * 4 + 8], addr):
        line = f"{i.address:06x}: {i.mnemonic:<7} {i.op_str}"
        b = i.bytes
        if len(b) == 2:
            h = b[0] | b[1] << 8
            if (h & 0xf800) == 0x4800:
                lit = ((i.address + 4) & ~3) + (h & 0xff) * 4
                if lit + 4 <= len(FW): line += f"    ; =0x{u32(lit):08x}"
        out.append(line)
        if len(out) >= n: break
    return "\n".join(out)

def bl_callers(target):
    """Thumb BL instructions (32-bit pair) that call target."""
    out = []
    t = target & ~1
    for a in range(0, len(FW) - 4, 2):
        h1, h2 = u16(a), u16(a + 2)
        if (h1 & 0xf800) == 0xf000 and (h2 & 0xe800) == 0xe800:
            off = ((h1 & 0x7ff) << 12) | ((h2 & 0x7ff) << 1)
            if off & 0x400000: off -= 0x800000
            dest = a + 4 + off
            if (h2 & 0x1000) and dest == t: out.append(a)          # BL
            if not (h2 & 0x1000) and (dest & ~3) == (t & ~3): out.append(a)  # BLX to ARM
    return out

def loglit(event, nargs, desc):
    """32-bit literal passed to the log function 0xF59CC for a record."""
    return (event << 16) | (nargs << 8) | desc
def logsites(event, nargs, desc):
    return [a for a in find(struct.pack("<I", loglit(event, nargs, desc))) if a % 4 == 0]
