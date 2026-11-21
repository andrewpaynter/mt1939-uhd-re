"""Find Thumb code that loads a RAM address from a literal pool and stores a byte to it."""
from fw import *
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_REG, ARM_OP_IMM, ARM_OP_MEM
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB); md.detail = True

def loaders(target):
    """Addresses of Thumb 'ldr Rd,[pc,#imm]' that load `target`."""
    out = []
    for lit in [a for a in find(struct.pack("<I", target)) if a % 4 == 0]:
        for a in range(max(0, lit - 1020), lit, 2):
            h = u16(a)
            if (h & 0xf800) == 0x4800 and ((a + 4) & ~3) + (h & 0xff) * 4 == lit:
                out.append((a, (h >> 8) & 7))
    return out

def stores(target, window=12):
    res = []
    for a, rd in loaders(target):
        insns = list(md.disasm(FW[a:a + window * 2 + 8], a))[:window]
        consts = {}
        for i in insns[1:]:
            ops = i.operands
            if i.mnemonic in ("movs", "mov") and len(ops) == 2 and ops[1].type == ARM_OP_IMM:
                consts[ops[0].reg] = ops[1].imm
            if i.mnemonic.startswith("strb") and ops[1].type == ARM_OP_MEM and ops[1].mem.base == md.reg_name and False: pass
            if i.mnemonic.startswith("strb") and ops[1].type == ARM_OP_MEM:
                base = i.reg_name(ops[1].mem.base)
                if base == f"r{rd}" and ops[1].mem.disp == 0 and ops[1].mem.index == 0:
                    src = ops[0].reg
                    res.append((i.address, i.reg_name(src), consts.get(src)))
            # stop if rd is overwritten
            if len(ops) and ops[0].type == ARM_OP_REG and i.reg_name(ops[0].reg) == f"r{rd}" and not i.mnemonic.startswith("str") and i.mnemonic not in ("cmp", "tst"):
                break
    return res
