# Minimal pure-python AES-128 (encrypt only), for MAC experiments. Self-contained.
sbox=[]
def _init():
    p=1;q=1;s=[0]*256
    # generate sbox via GF(2^8)
    inv=[0]*256
    # compute multiplicative inverse table using exp/log
    exp=[0]*256; log=[0]*256
    x=1
    for i in range(255):
        exp[i]=x; log[x]=i
        x^= (x<<1)&0xFF
        if x& 0x00: pass
        # multiply by 3 (generator) properly:
    # redo exp/log with generator 3
    exp=[0]*256; log=[0]*256; x=1
    for i in range(255):
        exp[i]=x; log[x]=i
        # x = x*3 in GF(2^8)
        x ^= xtime(x)
        x&=0xFF
    def ginv(a):
        if a==0: return 0
        return exp[(255-log[a])%255]
    for i in range(256):
        a=ginv(i)
        # affine transform
        s_=a
        s_= a ^ rotl(a,1)^rotl(a,2)^rotl(a,3)^rotl(a,4)^0x63
        sbox.append(s_&0xFF)
def xtime(a):
    a<<=1
    if a&0x100: a^=0x11b
    return a&0xFF
def rotl(b,n): return ((b<<n)|(b>>(8-n)))&0xFF
_init()
Rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def key_expansion(key):
    assert len(key)==16
    w=[list(key[i:i+4]) for i in range(0,16,4)]
    for i in range(4,44):
        t=list(w[i-1])
        if i%4==0:
            t=t[1:]+t[:1]
            t=[sbox[b] for b in t]
            t[0]^=Rcon[i//4-1]
        w.append([w[i-4][j]^t[j] for j in range(4)])
    return w
def add_rk(s,w,r):
    for c in range(4):
        for row in range(4):
            s[row][c]^=w[r*4+c][row]
def sub_bytes(s):
    for r in range(4):
        for c in range(4):
            s[r][c]=sbox[s[r][c]]
def shift_rows(s):
    for r in range(1,4):
        s[r]=s[r][r:]+s[r][:r]
def mix_cols(s):
    for c in range(4):
        a=[s[r][c] for r in range(4)]
        s[0][c]=xtime(a[0])^(xtime(a[1])^a[1])^a[2]^a[3]
        s[1][c]=a[0]^xtime(a[1])^(xtime(a[2])^a[2])^a[3]
        s[2][c]=a[0]^a[1]^xtime(a[2])^(xtime(a[3])^a[3])
        s[3][c]=(xtime(a[0])^a[0])^a[1]^a[2]^xtime(a[3])
def encrypt_block(pt,w):
    s=[[pt[r+4*c] for c in range(4)] for r in range(4)]
    add_rk(s,w,0)
    for rnd in range(1,10):
        sub_bytes(s); shift_rows(s); mix_cols(s); add_rk(s,w,rnd)
    sub_bytes(s); shift_rows(s); add_rk(s,w,10)
    return bytes(s[r][c] for c in range(4) for r in range(4))
def _selftest():
    # FIPS-197 test vector
    key=bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt=bytes.fromhex("00112233445566778899aabbccddeeff")
    ct=encrypt_block(pt,key_expansion(key))
    assert ct.hex()=="69c4e0d86a7b0430d8cdb78070b4c55a", ct.hex()
    # zero key/zero pt
if __name__=="__main__":
    _selftest(); print("AES selftest OK")
