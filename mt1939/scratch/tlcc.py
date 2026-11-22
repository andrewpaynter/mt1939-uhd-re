import sys,os; sys.path.insert(0,"/work/re"); from fw import *
REG=[(0x10000,0x1a0000)] if "dumpA" in FWIMG else [(0x10000,0x15c000),(0x01F78000,0x01F78000+0x727dc)]
cc=[];sh=[]
for lo,hi in REG:
    for a in range(lo,min(hi,len(FW)-8),2):
        h=u16(a)
        if (h&0xf8ff)==0x20cc:  # movs rX,#0xcc
            for y in range(a+2,a+8,2):
                if (u16(y)&0xf8ff)==0x28c8: cc.append(a);break
        if (h&0xf8ff)==0x2832 and (u16(a-2)&0xffc0)==0x0880: sh.append(a)
print("and0xCC==C8:",len(cc)," >>2==0x32:",len(sh))
