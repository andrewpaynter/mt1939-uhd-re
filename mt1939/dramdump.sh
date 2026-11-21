#!/bin/bash
# Read-only: dump drive DRAM [start,end) via READ BUFFER mode 1 / control 0x50, 2 KB per command.
# Usage: dramdump.sh <out> <start_hex> <end_hex>
set -euo pipefail
out=$1; s=$(($2)); e=$(($3)); tmp=$(mktemp); : > "$out"
for ((a = s; a < e; a += 0x800)); do
  b=$(printf "%06x" $a)
  r=$(sg_raw -r 2048 -o "$tmp" /dev/sg5 3c 01 00 ${b:0:2} ${b:2:2} ${b:4:2} 00 08 00 50 2>&1)
  grep -q "Good" <<<"$r" || { echo "read failed at 0x$b: $r" >&2; exit 1; }
  head -c 2048 "$tmp" >> "$out"
done
rm -f "$tmp"; echo "wrote $(stat -c %s "$out") bytes to $out"
