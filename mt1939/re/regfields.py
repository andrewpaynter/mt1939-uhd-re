"""For a register, list every code site (load of its literal / base+off) followed by field ops
(bics/orrs/ands with shifted constants) - reports masks used, per image."""
import sys, struct, re, collections, pickle
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
def field_ops(img, sites):
    out = []
    for s in sorted(sites):
        regs = {}; ops = []
        for i in list(md.disasm(img[s - 16:s + 40], s - 16)):
            t = f"{i.mnemonic} {i.op_str}"
            m = re.match(r"movs (r\d), #(\w+)$", t)
            if m: regs[m.group(1)] = int(m.group(2), 0); continue
            m = re.match(r"lsls (r\d), (r\d), #(\w+)$", t)
            if m and m.group(2) in regs: regs[m.group(1)] = regs[m.group(2)] << int(m.group(3), 0); continue
            m = re.match(r"(bics|orrs|ands) (r\d), (r\d)$", t)
            if m and m.group(3) in regs and i.address >= s - 4: ops.append(f"{m.group(1)} {regs[m.group(3)]:#x}")
        out.append((s, ops))
    return out
if __name__ == "__main__":
    reg = int(sys.argv[1], 16)
    for lab, img, pk, key in (("MT1939", "/work/dumps/dumpA_0-2M.bin", "/work/scratch/mmio_census.pkl", 0), ("MT1959", "/work/mt1959/combined_1.01.bin", "/work/scratch/mmio_census.pkl", 1)):
        I = open(img, "rb").read(); c = pickle.load(open(pk, "rb"))[key]
        if lab == "MT1959": c = {**c, **{k: v for k, v in pickle.load(open("/work/scratch/mmio_overlay.pkl", "rb")).items() if k not in c}} if False else c
        sites = (c.get(reg, {}).get("w", set()) | c.get(reg, {}).get("r", set()))
        if lab == "MT1959":
            co = pickle.load(open("/work/scratch/mmio_overlay.pkl", "rb")).get(reg, {})
            sites = sites | co.get("w", set()) | co.get("r", set())
        masks = collections.Counter()
        print(f"== {lab} {reg:#x}: {len(sites)} sites")
        for s, ops in field_ops(I, sites):
            if ops: print(f"   {s:#x}: {ops}"); masks.update(ops)
        print("   summary:", dict(masks))
