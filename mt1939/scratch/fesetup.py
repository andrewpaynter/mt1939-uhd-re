"""Map front-end setup code: function starts, disc-type loads/compares, log events, FE writes (const-tracked).
Usage: FWIMG=<img> re/run scratch/fesetup.py <typeaddr> <swapfn> <fewrite> <lo> <hi>"""
import sys,re; sys.path.insert(0,"/work/re"); from fw import *
import fw
_thumb=fw._thumb
TYPE,SW,FEW,lo,hi=(int(x,16) for x in sys.argv[1:6])
def walk(lo,hi):
    a=lo
    while a<hi:
        last=a
        for i in _thumb.disasm(FW[a:hi],a):
            yield i; last=i.address+i.size
        a=max(last,a)+2
r={}
for i in walk(lo,hi):
    m,op=i.mnemonic,i.op_str.replace(" ","").split(",")
    a=f"{i.address:06x}"
    try:
        if m=="push" and "lr" in i.op_str: print(a,"---- FUNC")
        if m=="movs" and op[1].startswith("#"): r[op[0]]=int(op[1][1:],0)
        elif m=="lsls" and len(op)==3 and op[0]==op[1] and op[0] in r: r[op[0]]<<=int(op[2][1:],0)
        elif m=="adds" and len(op)==2 and op[1].startswith("#") and op[0] in r: r[op[0]]+=int(op[1][1:],0)
        elif m=="ldr" and "[pc" in i.op_str:
            b=i.bytes; h=b[0]|b[1]<<8; lit=((i.address+4)&~3)+(h&0xff)*4; v=u32(lit); r[op[0]]=v
            if v==TYPE: print(a,"   type load ->",op[0])
            if (v&0xff) in (0xaa,0x2a,0x0a,0xea,0xfa) and 0x1000<(v>>16)<0x3000 and (v>>8&0xff)<0x10: print(a,f"   LOG {v>>16:04x}")
        elif m=="cmp" and op[1].startswith("#"): print(a,"   cmp",op[0],op[1])
        elif m=="lsrs" and len(op)==3 and op[2] in ("#2","#3","#4","#5"): print(a,"   lsrs",op[2])
        elif m=="bl":
            t=int(op[0][1:],0)
            if t==FEW: print(a,f"   FE[{r.get('r1','?') if not isinstance(r.get('r1'),int) else hex(r['r1'])}] = {hex(r['r0']) if isinstance(r.get('r0'),int) else '?'}")
            elif t!=SW: r.pop("r0",None)
        elif m in ("bx","pop") : pass
        if m not in ("movs","lsls","adds","ldr","bl") and op and op[0] in r and m not in ("cmp","str","strb","strh","push","pop","b","bne","beq"): r.pop(op[0],None)
    except Exception: pass
