#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# runwinpe.sh - rows W3 and W4: SeaBIOS boots a WinPE image (the owner's, imported by harness/lab/p2/winpe/import-winpe.sh) over rbd://.
#
#   runwinpe.sh LABEL w3|w4 VARIANT [--bin NAME] [--timeout S]
#
#   w3  PXE (run-undi.sh, one lab NIC, undionly.kpxe unless --bin), w4  the real bin/ipxe.usb on a USB stick (run-media.sh)
#   VARIANT  the iPXE build directory under $P2B_WORK/out (rel, i386-rel, ...)
#
# What it does: rolls the lab image back to its snapshot `pristine` (a boot manager may write to its disk: every row starts from the same bytes),
# starts the run (--action sanboot --expect none --stay: the run does not decide by itself, there is no serial marker with these images, see
# winpe/run-rows.md), and beside it evidence.sh of winpe/run-rows.md: the screen every 15 s (the WinPE shell is told by its colours), the
# guest memory dumped 8 s after the SAN opened and at the end and scanned for the rBFT table (the dumps hold the key of the run: they are
# deleted by the evidence script). Everything goes to $P2B_WORK/results/LABEL: cmdline.txt, serial.txt, console.ts, shots/*.png, evidence.txt,
# hashes.txt, result.txt. A WinPE image is the owner's: only logs and screenshots are kept, never an image or a dump.
#
# The verdict of a WinPE row is NOT decided here: S1 (the SAN opened) is read from the console, S2 to S4 from the screenshots by a person.
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=labenv.sh
. "$here/labenv.sh"

label=${1:?LABEL} row=${2:?ROW} variant=${3:?VARIANT}
shift 3
pxebin=undionly.kpxe timeout=420
while [ $# -gt 0 ]; do
    case $1 in
        --bin) pxebin=$2; shift 2;;
        --timeout) timeout=$2; shift 2;;
        *) echo "runwinpe.sh: unknown option $1" >&2; exit 2;;
    esac
done
bin=$P2B_WORK/out/$variant
res=$P2B_WORK/results/$label
[ -d "$bin" ] || { echo "runwinpe.sh: no iPXE build in $bin" >&2; exit 2; }
[ ! -e "$res" ] || { echo "runwinpe.sh: $res exists" >&2; exit 2; }
name=wrtest-p2-winpe-mbr
keyfile=$LAB_DIR/keys/client.$name.secret
[ -r "$keyfile" ] || { echo "runwinpe.sh: no key file for $name (import-winpe.sh import --layout bios --name winpe-mbr)" >&2; exit 2; }
case $row in
    w3) runner=(bash "$here/run-undi.sh") oct=76 rowid=W3 ipxebin=$bin/$pxebin
        extra=(--bin "$ipxebin" --delivery stub);;
    w4) runner=(bash "$here/run-media.sh" usb) oct=77 rowid=W4 ipxebin=$bin/ipxe.usb
        extra=(--media "$bin/ipxe.usb" --ipxe-dir "$bin" --delivery embed);;
    *) echo "runwinpe.sh: ROW must be w3 or w4" >&2; exit 2;;
esac
export WINPE_WORK=$P2B_WORK/winpe
tools=$WINPE_WORK/tools
mkdir -p -m 700 "$tools" "$res" "$res/shots"
rr=$here/../../../winpe/run-rows.md
awk '/^<!-- selftest:rbft-scan -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$rr" > "$tools/rbft-scan.py"
awk '/^<!-- selftest:qmp-tool -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$rr" > "$tools/qmp-shot.py"
awk '/^<!-- selftest:evidence -->$/ {f = 1; next} f && /^```bash/ {g = 1; next} g && /^```/ {exit} g {print}' "$rr" > "$tools/evidence.sh"
# the evidence script picks "the newest control socket"; with other guests on the box that may not be ours: it is told ours
sed -i 's|^sock=\$(ls -t "\$P2Q_WORK"/s/\*.sock \| head -1)|sock=${EV_SOCK:-$(ls -t "$P2Q_WORK"/s/*.sock \| head -1)}|' "$tools/evidence.sh"
grep -q 'EV_SOCK' "$tools/evidence.sh" || { echo "runwinpe.sh: the evidence script of run-rows.md has changed: cannot pin its socket" >&2; exit 2; }
[ -s "$tools/evidence.sh" ] && [ -s "$tools/qmp-shot.py" ] && [ -s "$tools/rbft-scan.py" ] || { echo "runwinpe.sh: cannot extract the evidence tools from $rr" >&2; exit 2; }

run_args=(--row "$rowid" --pool winrbd --image "$name" --user "$name" --key-file "$keyfile" --action sanboot --expect none --stay --mem 2048
    --timeout "$timeout" --ip "10.77.0.$oct" --on-fail hold --opt handoff=key "${extra[@]}")
{
    echo "# $label: row $row ($rowid), build $variant, started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "${runner[@]}" -n "${run_args[@]}" 2>&1 | grep -v '^\[qemu\] warning: undionly'
} > "$res/cmdline.txt"

echo "rolling back winrbd/$name@pristine" >&2
lab "sudo rbd snap rollback winrbd/$name@pristine" > "$res/rollback.txt" 2>&1 || { echo "runwinpe.sh: the rollback failed (see $res/rollback.txt)" >&2; exit 2; }
health_before=$(lab_health 2>&1 | tr '\n' ' ')
export P2B_DEBUGCON=0 P2B_PAUSE_ON="" P2B_PAUSE_SECS=60 P2B_PAUSE_HOOK=""
"${runner[@]}" "${run_args[@]}" > "$res/run.out" 2> "$res/stderr.txt" &
rpid=$!
# the evidence script needs the run directory and the control socket of THIS guest: wait for them (the run script may wait for the PXE lock first)
for _ in $(seq 1 300); do
    if [ -S "$P2Q_WORK/s/$rpid.sock" ] && ls -d "$P2Q_WORK"/runs/"$rowid"-* >/dev/null 2>&1; then break; fi
    kill -0 "$rpid" 2>/dev/null || break
    sleep 1
done
( cd "$tools" && EV_SOCK="$P2Q_WORK/s/$rpid.sock" P2Q_WORK=$P2Q_WORK WINPE_WORK=$WINPE_WORK EV_MEM_MB=2048 EV_DEADLINE=$((timeout - 40)) EV_POLL=15 bash evidence.sh "$rowid" ) > "$res/evidence.txt" 2>&1
wait "$rpid"
rc=$?
health_after=$(lab_health 2>&1 | tr '\n' ' ')
resultline=$(grep '^RESULT ' "$res/run.out" | tail -n 1)
runid=$(printf '%s\n' "$resultline" | sed -n 's/.* run=\([^ ]*\) .*/\1/p')
lb=$P2Q_WORK/logs/$runid
for s in console ts chunks dnsmasq; do
    [ -f "$lb.$s" ] || continue
    case $s in console) dst=serial.txt;; ts) dst=console.ts;; chunks) dst=console.chunks;; dnsmasq) dst=dnsmasq.txt;; esac
    cp -f "$lb.$s" "$res/$dst"
done
[ ! -d "$WINPE_WORK/evidence/$rowid" ] || { cp -f "$WINPE_WORK"/evidence/"$rowid"/*.png "$res/shots/" 2>/dev/null; rm -f "$WINPE_WORK"/evidence/"$rowid"/*.png; }
{
    echo "ipxe_variant   $variant"
    ( cd "$bin" && sha256sum "$(basename "$ipxebin")" )
    [ ! -f "$bin/BUILD-INFO.txt" ] || sed 's/^/build   /' "$bin/BUILD-INFO.txt"
    echo "winpe image (raw, sha256 of the file imported; the image is the owner's, not kept here):"
    sha256sum "$WINPE_WORK/winpe-mbr.raw" 2>/dev/null | cut -c1-64 | sed 's/^/  /'
    for f in runwinpe.sh run-undi.sh run-media.sh lib.sh; do ( cd "$here" && sha256sum "$f" ); done
} > "$res/hashes.txt" 2>&1
{
    printf '%s\n' "$resultline"
    echo "run_script_exit $rc"
    echo "lab_health_before $health_before"
    echo "lab_health_after  $health_after"
    echo "S1 (the SAN opened): $(grep -a -c 'WRRUN-SAN-START' "$res/serial.txt" 2>/dev/null) start line(s), $(grep -a -c 'WRRUN-SAN-FAILED' "$res/serial.txt" 2>/dev/null) failed line(s), $(grep -a -c 'Booting from SAN device' "$res/serial.txt" 2>/dev/null) 'Booting from SAN device' line(s)"
    echo "evidence:"
    sed 's/^/  /' "$res/evidence.txt"
    echo "screenshots: $(ls "$res/shots" | wc -l) (S2 to S4 are read from these by a person; see the README of the results)"
} > "$res/result.txt"
cat "$res/result.txt"
exit 0
