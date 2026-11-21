#!/bin/bash
# Read-only: copy the drive's 128 KB internal log area (DRAM 0x1EB00-0x3EB00) via
# vendor READ BUFFER mode 1 with control byte 0x50 (2 KB per command).
# Usage: logdump.sh <outfile>
set -euo pipefail
out=$1; tmp=$(mktemp); : > "$out"
for ((a = 0x1eb00; a < 0x3eb00; a += 0x800)); do
  b=$(printf "%06x" $a)
  r=$(sg_raw -r 2048 -o "$tmp" /dev/sg5 3c 01 00 ${b:0:2} ${b:2:2} ${b:4:2} 00 08 00 50 2>&1)
  grep -q "Good" <<<"$r" || { echo "read failed at 0x$b: $r" >&2; exit 1; }
  head -c 2048 "$tmp" >> "$out"
done
rm -f "$tmp"; echo "wrote $(stat -c %s "$out") bytes to $out"
