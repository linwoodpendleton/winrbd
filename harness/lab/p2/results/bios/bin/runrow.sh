#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# runrow.sh - one run of the BIOS matrix, with its evidence directory.
#
#   runrow.sh LABEL ROW VARIANT [options]
#
#   LABEL     the name of the evidence directory ($P2B_WORK/results/LABEL), for example B1-rel-1
#   ROW       b0 | b1 | b2 | b3 | neg (the wrong-key negative control of row B1)
#   VARIANT   rel | sm | trace | i386-rel | i386-sm | i386-trace : the iPXE build in $P2B_WORK/out/VARIANT (rel = release, sm = RBD_STACK_MONITOR, trace = sm +
#             DEBUG=rbd_block:2,rbd_session; no prefix = the bin/ targets, which this pinned iPXE builds as x86_64 BIOS images; i386- = bin-i386-pcbios/,
#             the 32-bit BIOS images of the design); dbg = a local diagnostic build (see the README)
#   options   --opt N=V      a driver option for the rbd:// URI (repeatable; handoff=key is always set unless --nokey)
#             --nokey        do not put the key into the table: it reaches the guest as a QEMU file (opt/winrbd/key) instead
#             --pause-on RE --pause-secs N [--pause-hook CMD] [--pause-src console|dbg]   stop the guest when a line matches RE (serial console, or the
#                            DBG output of a trace build), wait, continue it (see tailts.py)
#             --timeout S    (default 420)
#             --append FILE  iPXE commands to run after sanhook (row b0)
#             --bin NAME     the PXE binary of rows b0 b1 neg: undionly.kpxe (default) or ipxe.pxe (native drivers, same single NIC)
#             --oct N        the last octet of the guest's lab address (default: 71 b1, 72 b0, 73 b2, 74 b3, 75 neg; 20 to 99, not 50): two guests with
#                            the same address cannot run together
#             --dry          print the plan, run nothing
#
# What it does: writes the expected values of the row (mkparams.sh), prints the command line (key hidden) into cmdline.txt, runs the run script
# of the row (run-undi.sh for b0 b1 neg; run-media.sh for b2 b3), copies the logs of the run into the evidence directory, and writes
#   cmdline.txt   the command, the QEMU command line and the iPXE run script, the key hidden
#   serial.txt    the serial console (not .log: the repository's .gitignore skips *.log), console.ts the time-stamped lines, console.chunks the time-stamped pieces, debug.ts (trace builds: iPXE's DBG
#                 output from the debug console, time-stamped), dnsmasq.txt (PXE rows)
#   result.txt    the RESULT line of the run script, the exit status, the verdict lines (analyse.py --verdict), the lab health before and after
#   hashes.txt    sha256 of the iPXE binary, of the image (manifest), of the params file and of the scripts that ran; the iPXE source digest
#   metrics.json  analyse.py: stage times, the table checker's verdict, INT 13h commands, stack and heap marks, pause timing
# Exit status: 0 the verdict is PASS, 1 FAIL, 2 environment.
#
# The key: read from its mode-600 file by the run script only; every log is scanned for it by the run script before it is kept (exit 4 and
# the logs are discarded if it is found). Nothing here prints, copies or passes it.
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=labenv.sh
. "$here/labenv.sh"

label=${1:?LABEL} row=${2:?ROW} variant=${3:?VARIANT}
shift 3
opts=() nokey=0 pause_on="" pause_secs=60 pause_hook="" timeout=420 append="" dry=0 pxebin=undionly.kpxe pause_src=console oct_override=
while [ $# -gt 0 ]; do
    case $1 in
        --opt) opts+=(--opt "$2"); shift 2;;
        --nokey) nokey=1; shift;;
        --pause-on) pause_on=$2; shift 2;;
        --pause-secs) pause_secs=$2; shift 2;;
        --pause-hook) pause_hook=$2; shift 2;;
        --pause-src) pause_src=$2; shift 2;;
        --timeout) timeout=$2; shift 2;;
        --append) append=$2; shift 2;;
        --bin) pxebin=$2; shift 2;;
        --oct) oct_override=$2; shift 2;;
        --dry) dry=1; shift;;
        *) echo "runrow.sh: unknown option $1" >&2; exit 2;;
    esac
done
case $variant in rel|sm|trace|trace2|dbg|fix|i386-rel|i386-sm|i386-trace|i386-trace2) ;; *) echo "runrow.sh: VARIANT must be rel, sm, trace, dbg, i386-rel, i386-sm or i386-trace" >&2; exit 2;; esac
bin=$P2B_WORK/out/$variant
[ -d "$bin" ] || { echo "runrow.sh: no iPXE build in $bin" >&2; exit 2; }
res=$P2B_WORK/results/$label
[ ! -e "$res" ] || { echo "runrow.sh: $res exists" >&2; exit 2; }

# ---- the row
case $row in
    b0) name=wrtest-p2-b0 oct=72 runner=(bash "$here/run-undi.sh") ipxebin=$bin/$pxebin rowid=B0 action=sanhook expect=os
        extra_run=(--bin "$ipxebin" --drive 0x81 --disk "$P2B_WORK/img/b0-tiny.raw" --delivery stub --leave exit)
        [ -z "$append" ] || extra_run+=(--append "$append");;
    b1) name=wrtest-p2-b1 oct=71 runner=(bash "$here/run-undi.sh") ipxebin=$bin/$pxebin rowid=B1 action=sanboot expect=os
        extra_run=(--bin "$ipxebin" --delivery stub);;
    neg) name=wrtest-p2-b1 oct=75 runner=(bash "$here/run-undi.sh") ipxebin=$bin/$pxebin rowid=B1-NEG action=sanboot expect=marker
        extra_run=(--bin "$ipxebin" --delivery stub --fake-key --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+' --on-fail hold);;
    b2) name=wrtest-p2-b2 oct=73 runner=(bash "$here/run-media.sh" usb) ipxebin=$bin/ipxe.usb rowid=B2 action=sanboot expect=os
        extra_run=(--media "$bin/ipxe.usb" --ipxe-dir "$bin" --delivery embed);;
    b3) name=wrtest-p2-b3 oct=74 runner=(bash "$here/run-media.sh" iso) ipxebin=$bin/ipxe.iso rowid=B3 action=sanboot expect=os
        extra_run=(--media "$bin/ipxe.iso" --ipxe-dir "$bin" --delivery embed);;
    *) echo "runrow.sh: unknown ROW $row" >&2; exit 2;;
esac
[ -z "$oct_override" ] || oct=$oct_override
keyfile=$LAB_DIR/keys/client.$name.secret
[ -r "$keyfile" ] || { echo "runrow.sh: no key file for $name (users.sh create $name)" >&2; exit 2; }

# ---- expected values
mp=(--no-require)
[ "$row" = b0 ] || mp=()
kt=aes
[ "$nokey" = 0 ] || kt=none
params=$("$here/mkparams.sh" "$name" "$oct" --keytype "$kt" ${mp[@]+"${mp[@]}"}) || exit 2

run_args=(--row "$rowid" --pool winrbd --image "$name" --user "$name" --action "$action" --expect "$expect" --timeout "$timeout" --ip "10.77.0.$oct"
    "${extra_run[@]}" ${opts[@]+"${opts[@]}"} --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/params,file=$params")
[ "$row" = neg ] || run_args+=(--key-file "$keyfile")
[ "$nokey" = 1 ] || run_args+=(--opt handoff=key)
if [ "$nokey" = 1 ]; then run_args+=(--qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/key,file=$keyfile"); fi
[ -z "$append" ] || [ "$row" = b0 ] || run_args+=(--append "$append")

plan() {
    echo "# $label: row $row ($rowid), variant $variant, started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "# the run script's own plan, key hidden:"
    "${runner[@]}" -n "${run_args[@]}" 2>&1 | grep -v '^\[qemu\] warning: undionly'
}
# --dry creates nothing: an evidence directory left behind would make the real run of the same label refuse ("exists")
[ "$dry" = 0 ] || { plan; exit 0; }
mkdir -p -m 700 "$res"
plan > "$res/cmdline.txt"

health_before=$(lab_health 2>&1 | tr '\n' ' ')
case $variant in *trace|*trace2) export P2B_DEBUGCON=1;; *) export P2B_DEBUGCON=0;; esac
export P2B_PAUSE_ON=$pause_on P2B_PAUSE_SECS=$pause_secs P2B_PAUSE_HOOK=$pause_hook P2B_PAUSE_SRC=$pause_src
out=$("${runner[@]}" "${run_args[@]}" 2>"$res/stderr.txt"); rc=$?
health_after=$(lab_health 2>&1 | tr '\n' ' ')
resultline=$(printf '%s\n' "$out" | grep '^RESULT ' | tail -n 1)
runid=$(printf '%s\n' "$resultline" | sed -n 's/.* run=\([^ ]*\) .*/\1/p')
[ -n "$runid" ] || { echo "runrow.sh: no RESULT line (status $rc)" >&2; cat "$res/stderr.txt" >&2; exit 2; }
lb=$P2Q_WORK/logs/$runid
for s in console ts chunks dbg.ts dnsmasq qemu; do
    [ -f "$lb.$s" ] || continue
    case $s in console) dst=serial.txt;; ts) dst=console.ts;; chunks) dst=console.chunks;; dbg.ts) dst=debug.ts;; dnsmasq) dst=dnsmasq.txt;; qemu) dst=qemu.out;; esac
    cp -f "$lb.$s" "$res/$dst"
done
# the guest's screen, when the run missed its stage
[ ! -f "$lb.screen.ppm" ] || cp -f "$lb.screen.ppm" "$res/screen.ppm"

# ---- hashes
{
    echo "# sha256 of what ran (nothing secret)"
    echo "ipxe_variant   $variant"
    ( cd "$bin" && sha256sum "$(basename "$ipxebin")" )
    [ -z "$(ls "$bin"/BUILD-INFO.txt 2>/dev/null)" ] || sed 's/^/build   /' "$bin/BUILD-INFO.txt"
    case $row in
        b0) ( cd "$P2B_WORK/img" && sha256sum b0-tiny.raw; grep '^image_sha256' linux-bios.raw.manifest | sed 's/^/rbd image content (linux-bios.raw) /' );;
        *) grep '^image_sha256' "$P2B_WORK/img/linux-bios.raw.manifest" | sed 's/^/rbd image (linux-bios.raw) /';;
    esac
    sha256sum "$params" | sed "s|  .*|  params (expected values of the row)|"
    for f in run-undi.sh run-media.sh lib.sh tailts.py analyse.py mkparams.sh runrow.sh; do ( cd "$here" && sha256sum "$f" ); done
    qd=$here/../../../qemu
    for f in common.sh gen-script.sh; do ( cd "$qd" && sha256sum "$f" ); done
    cp "$params" "$res/params.txt"
    echo "image_id       $(image_id "winrbd/$name" 2>/dev/null)"
} > "$res/hashes.txt" 2>&1

python3 -I "$here/analyse.py" "$lb" --json "$res/metrics.json" || echo "analyse failed" >&2
verdict=$(python3 -I "$here/analyse.py" "$lb" --verdict "$row" --result "$resultline" --exit "$rc" 2>&1); vrc=$?
{
    printf '%s\n' "$resultline"
    echo "run_script_exit $rc"
    echo "lab_health_before $health_before"
    echo "lab_health_after  $health_after"
    printf '%s\n' "$verdict"
} > "$res/result.txt"
cat "$res/result.txt"
exit "$vrc"
