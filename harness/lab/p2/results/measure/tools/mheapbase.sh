#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mheapbase.sh - the heap baseline of iPXE's own users (risk R1): the instrumented BIOS build (DEBUG=malloc) brings the lab NIC up, runs the run script
# with NO image hooked, and exits; iPXE prints "HEAP maximum usage NkB" at shutdown. What the driver's hook adds is the difference to a run that hooks
# (campaign.sh heap: heap-probe-N).
#
#   mheapbase.sh LABEL [--oct N]
# Environment as mrun.sh. Evidence: $P2M_OUT/LABEL (serial.txt, result.txt, cmdline.txt, binaries.sha256, facts.json, verdict.txt).
set -euo pipefail
LC_ALL=C
export LC_ALL
M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_REPO:=$(cd "$M_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?}" "${P2Q_WORK:?}" "${P2M_WORK:?}"
: "${P2M_OUT:=$P2Q_WORK/../out/runs}"
export P2_LAB_DIR P2Q_WORK
QEMU_DIR=$P2M_REPO/harness/lab/p2/qemu
name=${1:?LABEL}
shift
oct=66
[ "${1:-}" != --oct ] || oct=$2
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || { echo "mheapbase.sh: bad name" >&2; exit 2; }
bin=$P2M_WORK/bin/inst/ipxe-stub.pxe
[ -f "$bin" ] || { echo "mheapbase.sh: no $bin" >&2; exit 2; }
dir=$P2M_OUT/$name
[ ! -e "$dir" ] || { echo "mheapbase.sh: $dir exists" >&2; exit 2; }
mkdir -p "$P2M_OUT"
mkdir -m 700 "$dir"
args=(--row B1 --ip "10.77.0.$oct" --no-key --action none --leave exit --expect marker --marker 'HEAP maximum usage' --timeout 240 --cpus 2 --mem 1024
    --bin "$bin" --ipxe-dir "$(dirname "$bin")" --delivery stub)
{ echo "# heap baseline: no image hooked"; printf 'bash %q' "$QEMU_DIR/run-bios-pxe.sh"; for a in "${args[@]}"; do printf ' %q' "$a"; done; echo; } > "$dir/cmdline.txt"
{ sha256sum "$bin" "$QEMU_DIR/run-bios-pxe.sh"; } > "$dir/binaries.sha256"
rc=0
bash "$QEMU_DIR/run-bios-pxe.sh" "${args[@]}" > "$dir/stdout.txt" 2>&1 || rc=$?
{ tail -n 1 "$dir/stdout.txt"; echo "exit=$rc"; } > "$dir/result.txt"
console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
: > "$dir/serial.txt"
[ -z "$console" ] || [ ! -f "$console" ] || cp -p "$console" "$dir/serial.txt"
python3 -I "$M_HERE/analyze.py" base "$dir" > /dev/null || true
echo "mheapbase.sh: $name: $(head -n 1 "$dir/verdict.txt") ($(grep -a -o 'HEAP maximum usage [0-9]*kB' "$dir/serial.txt" | tail -n 1))"
