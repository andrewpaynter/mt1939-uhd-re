"""Build a CANDIDATE patched WH16NS40 1.00 image: E8->C8 fix + AES-CMAC re-sign.

★ OFFLINE, REVIEW-ONLY. This assembles a patched 2 MB image and re-signs it so it
passes the drive's integrity check. It is NOT flashed and NOT behaviorally tested
(we can't test without flashing). Output goes to mt1939/out/, never over the dumps.

Patch strategy (cleaner than the doc's paper P1+P2 — leaves 0x134C9E untouched):
  Only the shortcut path (0x68F96) reaches the ID with a 3-layer provisional type
  (E8). Replace the `bl 0x10A10A` at 0x68FB2 with `bl NEWCODE` (free space 0x1A9C00).
  NEWCODE:
    1. bl 0x102B52            # populate reflectivity measurement  [ASSUMPTION, see below]
    2. type := 0xF4           # make the drive's own dual pressed-test run
    3. load reflectivity arg (0x01FFA2F4[0..1]) and bl 0x134C9E
         -> 0x134C9E sets type=C4 if PRESSED, leaves F4 if RECORDABLE (thresh 0.76)
    4. remap: C4 -> C8  (pressed 3-layer BD-ROM, our goal)
              F4 -> E8  (genuine BD-R/RE XL, restored -> no regression)
    5. bl 0x10A10A ; pop {pc}  # original decode call, return to 0x68FB6 with its r0

  This reuses the drive's real reflectivity test (correct measurement + threshold)
  instead of reimplementing it, and preserves recordable BDXL by construction.

OPEN ASSUMPTIONS:
  A. [LARGELY RESOLVED, static] 0x102B52 writes the reflectivity buffer 0x01FFA2F4
     (verified at 0x102C44-54) and natively measures 3-layer discs (per-layer slots
     at 0x102C5C+). It has two callers and takes no args, so the standalone call here
     is sound; calling it while type is still E8 measures triple reflectivity, then
     we remap to F4 for the pressed test. Minor residual: whether a specific layer
     must be pre-focused (untestable without a disc). CALL_102B52=True recommended.
  B. [untestable w/o disc] The dual threshold 0.76 (0x3F428F5C) suiting a 3-layer disc.
  C. [untestable w/o disc] The "long tail" of dual-only (C4) code paths after ID.

Run:  re/run re/buildpatch.py       (writes out/patched.bin, verifies CMAC, disasm)
"""
import sys, os, struct
_RE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, "/work/re"); sys.path.insert(0, _RE)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
import cmac

DUMP = "/work/dumps/dumpA_0-2M.bin"
if not os.path.exists(DUMP): DUMP = os.path.join(_RE, "..", "dumps", "dumpA_0-2M.bin")

HOOK_SITE   = 0x68FB2      # the `bl 0x10A10A` we replace
NEWCODE     = 0x1A9C00     # free space (FF-filled, inside rec2)
F_102B52    = 0x102B52
F_134C9E    = 0x134C9E
F_10A10A    = 0x10A10A
TYPE_ADDR   = 0x01FF9DD3
REFL_ADDR   = 0x01FFA2F4
CALL_102B52 = True         # assumption A; set False for the no-prep variant
# --- v2 (bit-18 servo experiment) — TESTED ON HARDWARE AND REFUTED ---
# Setting bit 18 of focus reg 0x04030020 for the C8 read (matching the recordable
# path) was flashed and tested: it did NOT make the UHD disc-info read complete.
# Kept as a documented experiment. Default off -> the default build is the
# classification fix (v1), which IS validated on hardware. See FINDINGS.md §5.
BIT18       = False        # True rebuilds the refuted bit-18 variant (patched-v2.bin)
# v3a experiment (2026-11-21, MT1959 comparison): type assigned to a PRESSED 3-layer disc.
#   0xC8 = v1/v2 behaviour (BDXL-TL / 33.4 GB-per-layer config everywhere, incl. the inner zone).
#   0xC4 = v3a: treat it as a standard dual-layer BD-ROM, which approximates MT1959's UHD
#          "inner-zone mode" (flag 0x02000B17=1: standard-BD config, 27 GB density row, DL-style
#          addressing) for the DI read. Diagnostic only: tests whether the DI read succeeds (log 11bb).
PRESSED_TL_TYPE = 0xC8
HOOK2_SITE  = 0xB9FF8      # `bl 0x46c0a` in the ROM read 0xB9FB0, after r0=0x30000
NEWCODE2    = 0x1A9C60     # second free-space routine (after NEWCODE's 64 B; still FF, in rec2)
F_46C0A     = 0x46C0A      # writes r0 -> servo reg 0x04030020

# ---- tiny Thumb assembler (only the ops this routine needs) -----------------
class Asm:
    def __init__(self, base):
        self.base = base; self.buf = bytearray(); self.labels = {}; self.fix = []
        self.pool = []; self.pool_refs = []
    def _emit16(self, h): self.buf += struct.pack("<H", h & 0xFFFF)
    def here(self): return self.base + len(self.buf)
    def label(self, name): self.labels[name] = self.here()
    # 16-bit encodings
    def push(self, lr=False, regs=0):  self._emit16(0xB400 | (0x100 if lr else 0) | regs)
    def pop_pc(self):                  self._emit16(0xBD00)
    def movs_imm(self, rd, imm):       self._emit16(0x2000 | (rd << 8) | (imm & 0xFF))
    def cmp_imm(self, rn, imm):        self._emit16(0x2800 | (rn << 8) | (imm & 0xFF))
    def ldrb_imm(self, rt, rn, imm=0): self._emit16(0x7800 | ((imm & 0x1F) << 6) | (rn << 3) | rt)
    def strb_imm(self, rt, rn, imm=0): self._emit16(0x7000 | ((imm & 0x1F) << 6) | (rn << 3) | rt)
    def lsls_imm(self, rd, rm, imm):   self._emit16(0x0000 | ((imm & 0x1F) << 6) | (rm << 3) | rd)
    def orrs(self, rd, rm):            self._emit16(0x4300 | (rm << 3) | rd)
    def ldr_lit(self, rt, value):      # ldr rt,=value  (pooled)
        idx = len(self.pool); self.pool.append(value)
        self.pool_refs.append((len(self.buf), rt, idx)); self._emit16(0x4800 | (rt << 8))
    def b(self, label):   self.fix.append((len(self.buf), "b", label));   self._emit16(0xE000)
    def bne(self, label): self.fix.append((len(self.buf), "bne", label)); self._emit16(0xD100)
    def bl(self, target): # 32-bit BL
        off = len(self.buf); self.fix.append((off, "bl", target)); self._emit16(0xF000); self._emit16(0xD000)
    def finish(self):
        # place literal pool, word-aligned, after code
        while (self.here() & 3): self._emit16(0xBF00)  # nop padding
        pool_addr = []
        for v in self.pool:
            pool_addr.append(self.here()); self.buf += struct.pack("<I", v)
        # resolve ldr-literal
        for pos, rt, idx in self.pool_refs:
            ins_addr = self.base + pos
            imm = (pool_addr[idx] - ((ins_addr + 4) & ~3)) >> 2
            assert 0 <= imm <= 0xFF, f"ldr lit out of range {imm}"
            struct.pack_into("<H", self.buf, pos, 0x4800 | (rt << 8) | imm)
        # resolve branches
        for pos, kind, tgt in self.fix:
            ins_addr = self.base + pos
            dest = self.labels[tgt] if isinstance(tgt, str) else tgt
            off = dest - (ins_addr + 4)
            if kind == "b":
                assert -0x800 <= off < 0x800, f"b range {off}"
                struct.pack_into("<H", self.buf, pos, 0xE000 | ((off >> 1) & 0x7FF))
            elif kind == "bne":
                assert -0x100 <= off < 0x100, f"bne range {off}"
                struct.pack_into("<H", self.buf, pos, 0xD100 | ((off >> 1) & 0xFF))
            elif kind == "bl":
                S = (off >> 24) & 1; i1 = (off >> 23) & 1; i2 = (off >> 22) & 1
                imm10 = (off >> 12) & 0x3FF; imm11 = (off >> 1) & 0x7FF
                j1 = (i1 ^ S) ^ 1; j2 = (i2 ^ S) ^ 1
                h1 = 0xF000 | (S << 10) | imm10
                h2 = 0xD000 | (j1 << 13) | (j2 << 11) | imm11
                struct.pack_into("<H", self.buf, pos, h1)
                struct.pack_into("<H", self.buf, pos + 2, h2)
        return bytes(self.buf)

def build_newcode():
    a = Asm(NEWCODE)
    a.push(lr=True)                       # push {lr}
    if CALL_102B52: a.bl(F_102B52)        # populate reflectivity measurement
    a.ldr_lit(1, TYPE_ADDR); a.movs_imm(0, 0xF4); a.strb_imm(0, 1)   # type := F4
    a.ldr_lit(1, REFL_ADDR)               # r1 = &0x01FFA2F4
    a.ldrb_imm(0, 1, 0); a.ldrb_imm(2, 1, 1); a.lsls_imm(2, 2, 8); a.orrs(0, 2)  # r0 = b1<<8|b0
    a.bl(F_134C9E)                        # run dual pressed-test
    a.ldr_lit(1, TYPE_ADDR); a.ldrb_imm(0, 1); a.cmp_imm(0, 0xC4); a.bne("rec")
    a.movs_imm(0, PRESSED_TL_TYPE); a.strb_imm(0, 1); a.b("done")   # pressed -> C8 (v3a: C4)
    a.label("rec"); a.movs_imm(0, 0xE8); a.strb_imm(0, 1)  # recordable -> restore E8
    a.label("done"); a.bl(F_10A10A); a.pop_pc()          # original decode + return
    return a.finish()

def build_newcode2():
    # v2: called in place of `bl 0x46c0a` at 0xB9FF8 (r0 already = 0x30000).
    # If type==C8, override r0=0x70000 (set bit 18 = recordable/BDXL multi-layer focus);
    # else leave r0 unchanged (0x30000) so C0/C4 2-layer BD-ROM reads are untouched.
    a = Asm(NEWCODE2)
    a.push(lr=True)
    a.ldr_lit(1, TYPE_ADDR); a.ldrb_imm(1, 1); a.cmp_imm(1, 0xC8); a.bne("skip")
    a.movs_imm(0, 7); a.lsls_imm(0, 0, 0x10)      # r0 = 0x70000
    a.label("skip")
    a.bl(F_46C0A); a.pop_pc()
    return a.finish()

def thumb_bl_bytes(site, target):
    off = target - (site + 4)
    S = (off >> 24) & 1; i1 = (off >> 23) & 1; i2 = (off >> 22) & 1
    imm10 = (off >> 12) & 0x3FF; imm11 = (off >> 1) & 0x7FF
    j1 = (i1 ^ S) ^ 1; j2 = (i2 ^ S) ^ 1
    return struct.pack("<HH", 0xF000 | (S << 10) | imm10, 0xD000 | (j1 << 13) | (j2 << 11) | imm11)

def main():
    img = bytearray(open(DUMP, "rb").read())
    assert len(img) == 0x200000
    # sanity: original hook must be `bl 0x10A10A`
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    orig = list(md.disasm(bytes(img[HOOK_SITE:HOOK_SITE+4]), HOOK_SITE))
    assert orig and orig[0].mnemonic == "bl" and orig[0].op_str.endswith(hex(F_10A10A)[2:]) or orig[0].op_str.endswith("0x10a10a"), \
        f"hook site not the expected bl: {orig[0].mnemonic} {orig[0].op_str}"
    # free space must be FF where we write
    code = build_newcode()
    assert img[NEWCODE:NEWCODE+len(code)] == b"\xFF"*len(code), "free space not FF"
    # apply
    img[HOOK_SITE:HOOK_SITE+4] = thumb_bl_bytes(HOOK_SITE, NEWCODE)
    img[NEWCODE:NEWCODE+len(code)] = code
    code2 = None
    if BIT18:
        orig2 = list(md.disasm(bytes(img[HOOK2_SITE:HOOK2_SITE+4]), HOOK2_SITE))
        assert orig2 and orig2[0].mnemonic == "bl" and orig2[0].op_str.endswith("0x46c0a"), \
            f"hook2 site not the expected bl 0x46c0a: {orig2[0].mnemonic} {orig2[0].op_str}"
        code2 = build_newcode2()
        assert img[NEWCODE2:NEWCODE2+len(code2)] == b"\xFF"*len(code2), "NEWCODE2 free space not FF"
        assert NEWCODE2 >= NEWCODE + len(code), "NEWCODE2 overlaps NEWCODE"
        img[HOOK2_SITE:HOOK2_SITE+4] = thumb_bl_bytes(HOOK2_SITE, NEWCODE2)
        img[NEWCODE2:NEWCODE2+len(code2)] = code2
    # re-sign
    signed = cmac.resign(bytes(img))
    # verify integrity
    print("=== CMAC verify of patched+signed image ===")
    ok = cmac.verify(signed)
    print("INTEGRITY:", "OK" if ok else "FAIL")
    # write out
    outdir = os.path.join(os.path.dirname(DUMP), "..", "out"); outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    outp = os.path.join(outdir, "patched-v3a.bin" if PRESSED_TL_TYPE == 0xC4 else ("patched-v2.bin" if BIT18 else "patched.bin"))
    open(outp, "wb").write(signed)
    print("wrote", outp, len(signed), "bytes; CALL_102B52 =", CALL_102B52, "BIT18 =", BIT18)
    # disassemble patched regions for review
    print(f"\n=== patched hook @0x{HOOK_SITE:06x} ===")
    for i in md.disasm(signed[HOOK_SITE:HOOK_SITE+4], HOOK_SITE):
        print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    print(f"\n=== NEWCODE @0x{NEWCODE:06x} ({len(code)} bytes) ===")
    for i in md.disasm(code, NEWCODE):
        print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    if BIT18:
        print(f"\n=== v2 hook @0x{HOOK2_SITE:06x} ===")
        for i in md.disasm(signed[HOOK2_SITE:HOOK2_SITE+4], HOOK2_SITE):
            print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
        print(f"\n=== NEWCODE2 @0x{NEWCODE2:06x} ({len(code2)} bytes) ===")
        for i in md.disasm(code2, NEWCODE2):
            print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    return ok

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
