import struct, re
A=open("/work/dumps/dumpA_0-2M.bin","rb").read(); B=open("/work/mt1959/WH16NS60_1.01_stock.bin","rb").read()
def ev_sites(img, ev):
    out=[]
    for a in range(0x10000,0x1E0000,4):
        v=struct.unpack_from("<I",img,a)[0]
        if v>>16==ev: out.append((a,v))
    return out
for ev in (0x11b9,0x11bb,0x11be,0x12eb,0x12ee,0x12ef,0x12f4,0x23cf,0x23da,0x0e26,0x2e41,0x114f,0x1a74,0x1a76,0x0ddd,0x134e,0x1335):
    a=ev_sites(A,ev); b=ev_sites(B,ev)
    print(f"{ev:04x}: A {[(hex(x),hex(v)) for x,v in a][:4]}  B {[(hex(x),hex(v)) for x,v in b][:4]}")
