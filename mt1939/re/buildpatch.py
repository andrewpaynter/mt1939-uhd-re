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
# v3b "lock probe" (2026-11-21): for type C8 only, point the first ROM DI read (0xBA01E in 0xB9FB0)
# at the DATA-ZONE start PSN 0x100000 instead of the DI (PSN 0xD3A00). Diagnostic: does read-ready
# (0x04206080 bit14, log 11bb) ever set on Dune's pressed 33 GB pits? (MT1959 locks in the data zone
# first, then trains, then reads the DI.) Use with PRESSED_TL_TYPE=0xC8. C0/C4 discs keep 0xD3A00.
DI_PROBE_DATAZONE = False
HOOK3_SITE  = 0xBA01E      # `ldr r0,=0xD3A00 ; ldr r5,=0x02000E1C` (2+2 bytes) -> `bl NEWCODE3`
NEWCODE3    = 0x1A9C80     # third free-space routine (FF, in rec2)
PROBE_PSN   = 0x100000
HOOK2_SITE  = 0xB9FF8      # `bl 0x46c0a` in the ROM read 0xB9FB0, after r0=0x30000
NEWCODE2    = 0x1A9C60     # second free-space routine (after NEWCODE's 64 B; still FF, in rec2)
F_46C0A     = 0x46C0A      # writes r0 -> servo reg 0x04030020
# v3c "UHD spindle speed" (2026-11-21, MT1959 0xDCCFC comparison): MT1959 spins UHD discs at ~0.75x
# (its own rpm row 0x14FF7C, ~= density ratio 25/33.4) so the channel bit rate matches a BD-25 at the
# same speed class; MT1939's speed-set 0x104284 has one row (0x1A6FAE) and no type test.
# Hook the `bl 0x681E6` (spindle rpm setter) at 0x104420: r0 = rpm, r4 = speed class 0-5, r6 = class*2.
# NEWCODE4: if type==C8 use UHD_RPM_ROW[class]; log marker 3E01 (4 bytes: class, type, rpm16);
# tail-call 0x681E6 with the original lr. Use together with DI_PROBE_DATAZONE (v3b) -> patched-v3c.bin.
UHD_SPEED   = False
HOOK4_SITE  = 0x104420
NEWCODE4    = 0x1A9CC0     # fourth free-space routine (FF, in rec2), after NEWCODE3 (ends 0x1A9CA4)
F_681E6     = 0x681E6
F_LOG       = 0xF59CC
LOG_3E01    = 0x3E0104EA   # event 0x3E01 (unused in stock fw), 4 data bytes
# classes 0-2: MT1959's UHD values (MT1959 and MT1939 std rows are identical there);
# classes 3-5: MT1939's own std row scaled by MT1959's UHD/std ratio for that class.
_STD39 = [0x834, 0xD48, 0x1388, 0x1964, 0x1F72, 0x2648]
_STD59 = [0x834, 0xD48, 0x1388, 0x198C, 0x2008, 0x2684]
_UHD59 = [0x625, 0xC1C, 0xE60, 0x1305, 0x17E2, 0x1C17]
# v3d "speed/clock trace" (diagnostic, no behaviour change): log every call of the spindle setter
# 0x681E6 (event 3E03: rpm, caller) and the read-clock multiplier setter 0x2FF06 (event 3E04: value,
# caller) so the Dune log shows what rpm/clock are in force at the DI reads and who set them.
# Hooks sit after each setter's push (lr already saved): 0x681EE (`ldr r0,=0x04205040; subs r0,#0x20`,
# r1-r3 dead) and 0x2FF08 (`cmp r0,#0; beq 0x2FF86`, emulated in the stub). Use with UHD_SPEED -> v3d.
TRACE       = False
HOOK5_SITE  = 0x681EE;  NEWCODE5 = 0x1A9D10;  LOG_3E03 = 0x3E0308FA
HOOK6_SITE  = 0x2FF08;  NEWCODE6 = 0x1A9D40;  LOG_3E04 = 0x3E0408FA
# v3e "class-1 density fix" (2026-11-21): MT1939's triple-layer rpm row 0x1A70B4 (used by the ID speed-set
# 0x105174 and the rpm getter at 0x104E2A for (type&0xCC)==0xC8) is density-compensated only at class 0
# (0x625/0x834 = 0.749 = 25/33.4). Class 1 (speed 4, which the disc-ID handler hard-codes for DI attempts)
# is 0xC1C/0xD48 = 0.91. Set class 1 to 0xD48*0.749 = 0x9F3 (2547 rpm) there and in NEWCODE4's row.
CLASS1_FIX  = False
TL_ROW      = 0x1A70B4
CLASS1_RPM  = 0x9F3
UHD_RPM_ROW = [u if a == b else round(a * u / b) for a, b, u in zip(_STD39, _STD59, _UHD59)]

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
    def bx_lr(self):                   self._emit16(0x4770)
    def push_r0_lr(self):              self._emit16(0xB501)
    def pop_r0_r3(self):               self._emit16(0xBC09)
    def mov_lr_r3(self):               self._emit16(0x469E)
    def bx_r3(self):                   self._emit16(0x4718)
    def ldrh_reg(self, rt, rn, rm):    self._emit16(0x5A00 | (rm << 6) | (rn << 3) | rt)
    def str_sp(self, rt, imm8w):       self._emit16(0x9000 | (rt << 8) | (imm8w & 0xFF))
    def ldr_sp(self, rt, imm8w):       self._emit16(0x9800 | (rt << 8) | (imm8w & 0xFF))
    def movs_rr(self, rd, rm):         self._emit16(0x1C00 | (rm << 3) | rd)
    def push_lr(self):                 self._emit16(0xB500)
    def pop_r0_r1(self):               self._emit16(0xBC03)
    def bx_r1(self):                   self._emit16(0x4708)
    def orrs_(self, rd, rm):           self._emit16(0x4300 | (rm << 3) | rd)
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

def build_newcode3():
    # r0 = (type==C8) ? PROBE_PSN : 0xD3A00 ; r5 = 0x02000E1C ; return (replaces the two ldr's at HOOK3_SITE)
    a = Asm(NEWCODE3)
    a.ldr_lit(0, TYPE_ADDR); a.ldrb_imm(0, 0); a.cmp_imm(0, 0xC8); a.bne("std")
    a.ldr_lit(0, PROBE_PSN); a.b("done")
    a.label("std"); a.ldr_lit(0, 0x000D3A00)
    a.label("done"); a.ldr_lit(5, 0x02000E1C); a.bx_lr()
    return a.finish()

def build_newcode4():
    row = list(UHD_RPM_ROW)
    if CLASS1_FIX: row[1] = CLASS1_RPM
    a = Asm(NEWCODE4)
    a.push_r0_lr()                                   # [sp]=rpm, [sp+4]=lr (return to 0x104424)
    a.ldr_lit(2, TYPE_ADDR); a.ldrb_imm(2, 2); a.cmp_imm(2, 0xC8); a.bne("log")
    a.ldr_lit(1, 0)  # placeholder -> &UHD_RPM_ROW (patched below)
    a.ldrh_reg(0, 1, 6); a.str_sp(0, 0)              # rpm := row[class]
    a.label("log")
    a.lsls_imm(1, 4, 24); a.lsls_imm(3, 2, 16); a.orrs_(1, 3)
    a.ldr_sp(3, 0); a.orrs_(1, 3)                    # r1 = class<<24 | type<<16 | rpm
    a.ldr_lit(0, LOG_3E01); a.bl(F_LOG)
    a.pop_r0_r3(); a.mov_lr_r3()                     # r0 = rpm, lr = original return
    a.ldr_lit(3, F_681E6 | 1); a.bx_r3()             # tail-call the rpm setter
    code = bytearray(a.finish())
    row_addr = NEWCODE4 + len(code)
    # fix the placeholder literal (first pool entry with value 0) to point at the row
    pool_start = len(code) - 4 * len(a.pool)
    idx = a.pool.index(0); struct.pack_into("<I", code, pool_start + 4 * idx, row_addr)
    code += struct.pack("<6H", *row)
    return bytes(code)

def build_newcode5():   # at 0x681EE: r4 = rpm (0 already fixed to 1), caller lr at [sp+20] before our push
    a = Asm(NEWCODE5)
    a.push_lr(); a.movs_rr(1, 4); a.ldr_sp(2, 24 // 4)
    a.ldr_lit(0, LOG_3E03); a.bl(F_LOG)
    a.ldr_lit(0, 0x04205020); a.pop_pc()            # displaced: r0 = 0x04205040 - 0x20
    return a.finish()

def build_newcode6():   # at 0x2FF08: r0 = clock value, caller lr at [sp+4] before our push
    a = Asm(NEWCODE6)
    a.push_r0_lr(); a.movs_rr(1, 0); a.ldr_sp(2, 12 // 4)
    a.ldr_lit(0, LOG_3E04); a.bl(F_LOG)
    a.pop_r0_r1()                                    # r0 = value, r1 = return addr (0x2FF0D)
    a.cmp_imm(0, 0); a.bne("ret")                    # displaced: cmp r0,#0 ; beq 0x2FF86
    a.ldr_lit(1, 0x2FF86 | 1)
    a.label("ret"); a.bx_r1()
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
    code3 = None
    if DI_PROBE_DATAZONE:
        assert PRESSED_TL_TYPE == 0xC8 and not BIT18, "v3b = v1 (C8) + probe only"
        h3 = bytes(img[HOOK3_SITE:HOOK3_SITE+4])
        assert struct.unpack_from("<I", img, ((HOOK3_SITE+4)&~3) + (h3[0])*4)[0] == 0x000D3A00 and h3[1] == 0x48, "hook3 ldr r0 mismatch"
        assert h3[3] == 0x4D and struct.unpack_from("<I", img, ((HOOK3_SITE+2+4)&~3) + (h3[2])*4)[0] == 0x02000E1C, "hook3 ldr r5 mismatch"
        code3 = build_newcode3()
        assert img[NEWCODE3:NEWCODE3+len(code3)] == b"\xFF"*len(code3), "NEWCODE3 free space not FF"
        assert NEWCODE3 >= NEWCODE + len(code), "NEWCODE3 overlaps NEWCODE"
        img[HOOK3_SITE:HOOK3_SITE+4] = thumb_bl_bytes(HOOK3_SITE, NEWCODE3)
        img[NEWCODE3:NEWCODE3+len(code3)] = code3
    if UHD_SPEED:
        o4 = list(md.disasm(bytes(img[HOOK4_SITE:HOOK4_SITE+4]), HOOK4_SITE))
        assert o4 and o4[0].mnemonic == "bl" and int(o4[0].op_str.lstrip("#"), 16) == F_681E6, "hook4 is not bl 0x681E6"
        assert struct.unpack_from("<H", img, 0x1042E2)[0] == 0x0066, "r6 != class*2 setup (lsls r6,r4,#1) not found"
        code4 = build_newcode4()
        assert img[NEWCODE4:NEWCODE4+len(code4)] == b"\xFF"*len(code4), "NEWCODE4 free space not FF"
        assert NEWCODE4 >= NEWCODE3 + 0x24, "NEWCODE4 overlaps NEWCODE3"
        img[HOOK4_SITE:HOOK4_SITE+4] = thumb_bl_bytes(HOOK4_SITE, NEWCODE4)
        img[NEWCODE4:NEWCODE4+len(code4)] = code4
    if CLASS1_FIX:
        assert struct.unpack_from("<6H", img, TL_ROW) == (0x625, 0xC1C, 0xE60, 0x1305, 0x1768, 0x1C17), "TL row changed"
        struct.pack_into("<H", img, TL_ROW + 2, CLASS1_RPM)
    if TRACE:
        assert bytes(img[HOOK5_SITE:HOOK5_SITE+4]) == bytes.fromhex("bc482038"), "hook5 bytes changed"
        assert bytes(img[HOOK6_SITE:HOOK6_SITE+4]) == bytes.fromhex("00283cd0"), "hook6 bytes changed"
        assert struct.unpack_from("<I", img, ((HOOK5_SITE+4)&~3) + 0xbc*4)[0] == 0x04205040, "hook5 literal"
        code5 = build_newcode5(); code6 = build_newcode6()
        assert NEWCODE5 >= NEWCODE4 + 0x44 and NEWCODE6 >= NEWCODE5 + len(code5), "trace stubs overlap"
        for at, c in ((NEWCODE5, code5), (NEWCODE6, code6)):
            assert img[at:at+len(c)] == b"\xFF"*len(c), f"free space at {at:#x} not FF"
            img[at:at+len(c)] = c
        img[HOOK5_SITE:HOOK5_SITE+4] = thumb_bl_bytes(HOOK5_SITE, NEWCODE5)
        img[HOOK6_SITE:HOOK6_SITE+4] = thumb_bl_bytes(HOOK6_SITE, NEWCODE6)
    # re-sign
    signed = cmac.resign(bytes(img))
    # verify integrity
    print("=== CMAC verify of patched+signed image ===")
    ok = cmac.verify(signed)
    print("INTEGRITY:", "OK" if ok else "FAIL")
    # write out
    outdir = os.path.join(os.path.dirname(DUMP), "..", "out"); outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    outp = os.path.join(outdir, "patched-v3e.bin" if CLASS1_FIX else "patched-v3d.bin" if TRACE else "patched-v3c.bin" if UHD_SPEED else "patched-v3b.bin" if DI_PROBE_DATAZONE else ("patched-v3a.bin" if PRESSED_TL_TYPE == 0xC4 else ("patched-v2.bin" if BIT18 else "patched.bin")))
    open(outp, "wb").write(signed)
    print("wrote", outp, len(signed), "bytes; CALL_102B52 =", CALL_102B52, "BIT18 =", BIT18)
    # disassemble patched regions for review
    print(f"\n=== patched hook @0x{HOOK_SITE:06x} ===")
    for i in md.disasm(signed[HOOK_SITE:HOOK_SITE+4], HOOK_SITE):
        print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    print(f"\n=== NEWCODE @0x{NEWCODE:06x} ({len(code)} bytes) ===")
    for i in md.disasm(code, NEWCODE):
        print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    if code3:
        print(f"\n=== hook3 @0x{HOOK3_SITE:06x} / NEWCODE3 @0x{NEWCODE3:06x} ({len(code3)} bytes) ===")
        for i in md.disasm(signed[HOOK3_SITE:HOOK3_SITE+4], HOOK3_SITE): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
        for i in md.disasm(code3, NEWCODE3): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    if UHD_SPEED:
        print(f"\n=== hook4 @0x{HOOK4_SITE:06x} / NEWCODE4 @0x{NEWCODE4:06x} ({len(code4)} bytes; row {[hex(x) for x in UHD_RPM_ROW]}) ===")
        for i in md.disasm(signed[HOOK4_SITE:HOOK4_SITE+4], HOOK4_SITE): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
        for i in md.disasm(code4, NEWCODE4): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
    if TRACE:
        for nm, hs, nc, c in (("hook5 rpm-trace", HOOK5_SITE, NEWCODE5, code5), ("hook6 clock-trace", HOOK6_SITE, NEWCODE6, code6)):
            print(f"\n=== {nm} @0x{hs:06x} -> 0x{nc:06x} ({len(c)} bytes) ===")
            for i in md.disasm(signed[hs:hs+4], hs): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
            for i in md.disasm(c, nc): print(f"  {i.address:06x}: {i.bytes.hex():<8} {i.mnemonic} {i.op_str}")
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
