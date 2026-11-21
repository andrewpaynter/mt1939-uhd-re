#!/usr/bin/env python3
"""Parse an MT1939 log dump: records = [0xE3+n][code_hi][code_lo][desc][n arg bytes][~first]."""
import sys
def records(d):
    i, out = 0, []
    while i < len(d) - 5:
        b0 = d[i]
        if b0 >= 0xe3:
            n = b0 - 0xe3
            end = i + 4 + n
            if end < len(d) and d[end] == (~b0) & 0xff:
                code = (d[i+1] << 8 | d[i+2]) << 16 | d[i+3]
                out.append((i, code, d[i+4:end]))
                i = end + 1; continue
        i += 1
    return out
if __name__ == "__main__":
    d = open(sys.argv[1], "rb").read()
    recs = records(d)
    print(f"{len(recs)} records, covering {sum(5+len(a) for _,_,a in recs)} of {len(d)} bytes")
    for off, code, args in recs[-int(sys.argv[2]) if len(sys.argv) > 2 else 0:]:
        print(f"{off:05x}  {code >> 16:04x}.{code & 0xff:02x}  {args.hex(' ')}")
