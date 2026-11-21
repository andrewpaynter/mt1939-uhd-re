import sys; sys.path.insert(0,"/work/re"); from fw import *
def fstart(a):
    a&=~1
    for x in range(a, max(a-0x1000,0x10000), -2):
        h=u16(x)
        if (h&0xff00)==0xb500 or (h&0xfe00)==0xb400 and (h&0x100): return x
    return None
def up(t, depth=0, maxd=4, seen=set()):
    if depth>maxd or t in seen: return
    seen.add(t)
    cs=bl_callers(t)
    for c in cs[:8]:
        f=fstart(c); print("  "*depth+f"{t:#x} <- call@{c:#x} in fn {f:#x}" if f else "  "*depth+f"{t:#x} <- call@{c:#x}")
        if f: up(f,depth+1,maxd,seen)
up(int(sys.argv[1],16), maxd=int(sys.argv[2]) if len(sys.argv)>2 else 3)
