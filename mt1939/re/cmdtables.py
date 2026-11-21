from fw import *
NAMES={0x00:"TEST UNIT READY",0x03:"REQUEST SENSE",0x04:"FORMAT UNIT",0x12:"INQUIRY",0x1b:"START STOP",0x1e:"PREVENT ALLOW",0x23:"READ FMT CAP",0x25:"READ CAPACITY",0x28:"READ(10)",0x2a:"WRITE(10)",0x2b:"SEEK",0x2e:"WRITE+VERIFY",0x2f:"VERIFY",0x35:"SYNC CACHE",0x3b:"WRITE BUFFER",0x3c:"READ BUFFER",0x42:"READ SUBCHAN",0x43:"READ TOC",0x44:"READ HEADER",0x45:"PLAY AUDIO10",0x46:"GET CONFIG",0x47:"PLAY MSF",0x4a:"GET EVENT",0x4b:"PAUSE/RESUME",0x4e:"STOP PLAY",0x51:"READ DISC INFO",0x52:"READ TRACK INFO",0x53:"RESERVE TRACK",0x54:"SEND OPC",0x55:"MODE SELECT",0x5a:"MODE SENSE",0x5b:"CLOSE TRACK",0x5c:"READ BUF CAP",0x5d:"SEND CUE",0xa1:"BLANK",0xa2:"SEND EVENT",0xa3:"SEND KEY",0xa4:"REPORT KEY",0xa5:"PLAY AUDIO12",0xa7:"SET RD AHEAD",0xa8:"READ(12)",0xaa:"WRITE(12)",0xab:"READ MEDIA SN",0xac:"GET PERF",0xad:"READ DISC STRUCT",0xb6:"SET STREAMING",0xb9:"READ CD MSF",0xba:"SCAN",0xbb:"SET CD SPEED",0xbd:"MECH STATUS",0xbe:"READ CD",0xbf:"SEND DISC STRUCT"}
SENSE={0x052000:"05/20/00 invalid opcode",0x053002:"05/30/02 cannot read: incompatible format",0x053005:"05/30/05 cannot write: incompatible format",0x053006:"05/30/06 cannot format: incompatible medium",0x023a00:"02/3A/00 MEDIUM NOT PRESENT"}
def parse(start, end):
    a = start
    while a < end:
        k, v = u32(a), u32(a + 4)
        if k == 0x400: print(f"\n=== table @0x{a:06x}  parent/ptr=0x{v:06x}")
        elif k >> 8 == 2: print(f"  {k&0xff:02x} {NAMES.get(k&0xff,'?'):16s} -> code 0x{v:06x}")
        elif k >> 8 == 8: print(f"  {k&0xff:02x} {NAMES.get(k&0xff,'?'):16s} -> REFUSE {SENSE.get(v, hex(v))}")
        elif k >> 8 == 1: print(f"  {k&0xff:02x} {NAMES.get(k&0xff,'?'):16s} -> flag1 0x{v:06x}")
        elif k >> 8 == 9: print(f"  {k&0xff:02x} {NAMES.get(k&0xff,'?'):16s} -> flag9 0x{v:06x}")
        else: print(f"  ?? key=0x{k:08x} val=0x{v:08x}")
        a += 8
if __name__ == "__main__":
    import sys; parse(int(sys.argv[1],16), int(sys.argv[2],16))
