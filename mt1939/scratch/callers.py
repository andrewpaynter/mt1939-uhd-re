import sys; sys.path.insert(0,"/work/re"); from fw import *
def fstart(a):
    for x in range(a&~1, max(a-0x3000,0x10000), -2):
        h=u16(x)
        if (h&0xff00)==0xb500 or ((h&0xfe00)==0xb400 and h&0x100): return x
t=int(sys.argv[1],16)
cs=bl_callers(t)
print(len(cs),"callers:")
for c in cs: print(f"  call@{c:#x} fn {fstart(c):#x}")
