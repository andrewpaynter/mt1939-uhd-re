import sys,struct; sys.path.insert(0,"/work/re"); from fw import *
import fw
lo,hi=int(sys.argv[1],16),int(sys.argv[2],16)
a=lo
while a<hi:
    last=a
    for i in fw._thumb.disasm(FW[a:hi],a):
        if i.mnemonic=="bl": print(f"{i.address:06x} {i.op_str}")
        last=i.address+i.size
    a=max(last,a)+2
