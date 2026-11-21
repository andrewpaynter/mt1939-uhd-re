"""MMIO access census: resolves Thumb `ldr rB,=BASE ; (adds/subs rB,#k) ; ldr/str rX,[rB,#off]` to
concrete register addresses (basic intra-block constant tracking, linear sweep).
mmio_census(img, regions) -> {regaddr: {'r':set(insn addrs), 'w':set(insn addrs)}}"""
import struct, collections, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = False
MEM = re.compile(r"\[(r\d+|sb|sl|fp|ip)(?:, #(-?0x[0-9a-f]+|-?\d+))?\]")
def mmio_census(img, regions, lo=0x04000000, hi=0x05000000):
    res = collections.defaultdict(lambda: {"r": set(), "w": set()})
    for a0, a1 in regions:
        a = a0; regs = {}
        while a < a1:
            ins = next(md.disasm(img[a:a+4], a, 1), None)
            if ins is None: regs.clear(); a += 2; continue
            m, ops = ins.mnemonic, ins.op_str; a += ins.size
            b = ins.bytes
            if len(b) == 2 and ((b[0] | b[1] << 8) & 0xf800) == 0x4800:
                la = ((ins.address + 4) & ~3) + (b[0] * 4)
                rd = ops.split(",")[0]
                if la + 4 <= len(img): regs[rd] = struct.unpack_from("<I", img, la)[0]
                continue
            if m in ("push", "pop", "bx", "bl", "blx", "b") or m.startswith("b") and m not in ("bic","bics") :
                if m in ("bl","blx"): [regs.pop(r, None) for r in ("r0","r1","r2","r3")]
                elif m not in ("bne","beq","bmi","bpl","bhs","blo","bhi","bls","bge","blt","bgt","ble","bcs","bcc","bvs","bvc"): regs.clear()
                continue
            mm = re.match(r"(adds|subs|add|sub) (r\d), (?:(r\d), )?#(0x[0-9a-f]+|\d+)$", f"{m} {ops}")
            if mm:
                d, s, k = mm.group(2), mm.group(3) or mm.group(2), int(mm.group(4), 0)
                if s in regs: regs[d] = regs[s] + (k if m.startswith("add") else -k)
                else: regs.pop(d, None)
                continue
            if m.startswith(("ldr", "str")) and "[" in ops:
                mo = MEM.search(ops)
                if mo and mo.group(1) in regs and ", r" not in ops.split("[")[1]:
                    ad = regs[mo.group(1)] + (int(mo.group(2), 0) if mo.group(2) else 0)
                    if lo <= ad < hi: res[ad]["w" if m.startswith("str") else "r"].add(ins.address)
                if m.startswith("ldr"): regs.pop(ops.split(",")[0], None)
                continue
            d = ops.split(",")[0] if ops else None
            if d in regs: regs.pop(d)
    return res
