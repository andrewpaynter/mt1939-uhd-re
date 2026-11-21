#!/bin/bash
# Read-only dump of the MT1939 drive's memory window via vendor READ BUFFER (3C mode 06).
# Usage: dump.sh <outfile> [start_hex] [end_hex]   (default 0x000000-0x200000)
set -euo pipefail
out=$1; start=$((${2:-0x0})); end=$((${3:-0x200000})); chunk=0x8000
tmp=$(mktemp -d); : > "$out"
for ((a = start; a < end; a += chunk)); do
  b=$(printf "%06x" $a)
  r=$(sg_raw -r $((chunk)) -o "$tmp/c" /dev/sg5 3c 06 00 ${b:0:2} ${b:2:2} ${b:4:2} 00 80 00 00 2>&1)
  grep -q "Good" <<<"$r" || { echo "read failed at 0x$b: $r" >&2; exit 1; }
  head -c $((chunk)) "$tmp/c" >> "$out"
done
rm -rf "$tmp"; echo "wrote $(stat -c %s "$out") bytes to $out"
