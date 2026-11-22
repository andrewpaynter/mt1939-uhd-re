import sys,os; sys.path.insert(0,"/work/re"); from fw import *
REG=[(0x10000,0x1a0000)] if "dumpA" in FWIMG else [(0x10000,0x15c000),(0x01F78000,0x01F78000+0x727dc)]
n=[]
for lo,hi in REG:
    for a in range(lo,min(hi,len(FW)-4),2):
        if (u16(a)&0xf8ff)==0x2832 and (u16(a-2)&0xffc0)==0x0880: n.append(a)
        elif (u16(a)&0xf8ff)==0x2832 and (u16(a-2)&0xffc0)==0x0880: pass
print(len(n)); print(" ".join(hex(x) for x in n))
