"""Census of front-end param writes of the form FEwrite(swap16(CONST), PARAM) with simple constant tracking.
Usage: FWIMG=<img> re/run scratch/fewrites.py <swapfn> <fewritefn> [lo hi]"""
import sys; sys.path.insert(0,"/work/re"); from fw import *
import fw
_thumb=fw._thumb
def walk(lo,hi):
    a=lo
    while a<hi:
        last=a
        for i in _thumb.disasm(FW[a:hi],a):
            yield i; last=i.address+i.size
        a=max(last,a)+2
SW=int(sys.argv[1],16); FE=int(sys.argv[2],16)
lo=int(sys.argv[3],16) if len(sys.argv)>3 else 0; hi=int(sys.argv[4],16) if len(sys.argv)>4 else 0x1c0000
import re as _re
regs={}
out=[]
for i in walk(lo,hi):
    m=i.mnemonic; ops=i.op_str.replace(" ","").split(",")
    try:
        if m=="movs" and ops[1].startswith("#"): regs[ops[0]]=int(ops[1][1:],0)
        elif m=="movs" and ops[1] in regs: regs[ops[0]]=regs[ops[1]]
        elif m=="mov" and ops[1] in regs: regs[ops[0]]=regs[ops[1]]
        elif m=="lsls" and len(ops)==3 and ops[1] in regs: regs[ops[0]]=(regs[ops[1]]<<int(ops[2][1:],0))&0xffffffff
        elif m=="adds" and len(ops)==2 and ops[0] in regs: regs[ops[0]]=(regs[ops[0]]+int(ops[1][1:],0))&0xffffffff
        elif m=="adds" and len(ops)==3 and ops[2].startswith("#") and ops[1] in regs: regs[ops[0]]=(regs[ops[1]]+int(ops[2][1:],0))&0xffffffff
        elif m=="subs" and len(ops)==3 and ops[2].startswith("#") and ops[1] in regs: regs[ops[0]]=(regs[ops[1]]-int(ops[2][1:],0))&0xffffffff
        elif m=="ldr" and "pc" in i.op_str:
            h=i.bytes[0]|i.bytes[1]<<8; regs[ops[0]]=u32(((i.address+4)&~3)+(h&0xff)*4)
        elif m in("bl","blx"):
            t=int(i.op_str.lstrip("#"),16)
            if t==SW: regs={"r0s":regs.get("r0")}; continue
            if t==FE: out.append((i.address,regs.get("r0s"),regs.get("r1")))
            regs={}
        elif m.startswith("b") or m.startswith("pop") or m.startswith("push"): regs={k:v for k,v in regs.items() if k.startswith("r") and k[1:].isdigit() and int(k[1:])>=4 or k=="r0s"}
        elif ops and ops[0] in regs: regs.pop(ops[0])
    except Exception: regs.pop(ops[0],None)
for a,v,p in out:
    if v is not None and p is not None: print(f"{a:#08x} FE[{p:#04x}] = {v:#06x}")
