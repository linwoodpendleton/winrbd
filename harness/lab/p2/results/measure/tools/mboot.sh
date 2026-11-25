#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mboot.sh - ONE boot of a guest image from the lab through the iPXE rbd:// driver, timed to the login prompt (design 14.4: time to login per row), with
# the stock run scripts of harness/lab/p2/qemu and the stage timer of the UEFI rows (results/uefi/tools/stamp.py).
#
#   mboot.sh row LABEL --family uefi|bios --via pxe|usb|iso --image NAME [--bin FILE] [--ipxe-dir DIR] [--oct N] [--timeout S] [--opt N=V]... [--exit]
#                      [--expect-marker REGEX --stage NAME] [--mem MB] [--note TEXT] [--dry]
#   mboot.sh env
#
#   --family/--via    the row: uefi pxe = U1, uefi usb = U2, uefi iso = U3, bios pxe = B1, bios usb = B2, bios iso = B3 (the run scripts run-<family>-<via>.sh)
#   --image NAME      the RBD image and the throwaway user of the guest (wrtest-p2-ms-lin-uefi, wrtest-p2-ms-lin-bios, a WinPE image, ...)
#   --bin FILE        the iPXE binary (default: ipxe.efi for uefi, ipxe-stub.pxe for bios pxe, ipxe.lkrn for bios usb / iso, in --ipxe-dir)
#   --ipxe-dir DIR    where the iPXE builds are (default $P2M_WORK/bin/rel; the media rows need ipxe.efi and ipxe.lkrn without a script: $P2M_WORK/bin/media)
#   --expect-marker   instead of the Linux guest's login prompt: wait for this line (a WinPE image prints WINRBD-WINPE-OK on COM1); --stage names the result
#   --rollback        before the run, roll the image back to its snapshot "pristine" (a WinPE image: import-winpe.sh takes it, and the boot manager may write)
#   --no-params       no table-check parameters and no key file channel (a WinPE image has neither)
#   --exit            no effect on the run script; kept for symmetry with mrun.sh
# What a row needs: the Linux guest's table-check parameters (expected-table.sh, as rr.sh and matrix.sh do) go in as a fw_cfg file, the key as another (never an
# argument); a WinPE image has neither (--no-params).
# The evidence directory $P2M_OUT/LABEL: cmdline.txt binaries.sha256 serial.txt stdout.txt result.txt stamps.txt (stage seconds, the guest's CPU wait) load.txt
# lab-before/after/diff.txt facts.json verdict.txt.
# shellcheck disable=SC2015
set -euo pipefail
LC_ALL=C
export LC_ALL
M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_REPO:=$(cd "$M_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?}" "${P2Q_WORK:?}" "${P2M_WORK:?}"
: "${P2M_OUT:=$P2Q_WORK/../out/runs}"
export P2_LAB_DIR P2Q_WORK
QEMU_DIR=$P2M_REPO/harness/lab/p2/qemu
UEFI_TOOLS=$P2M_REPO/harness/lab/p2/results/uefi/tools
LABSTATE=$P2M_REPO/harness/lab/p2/results/robust/tools/labstate.sh
die() { echo "mboot.sh: $*" >&2; exit 2; }
lab_ssh() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}
sumfile() { if [ -f "$1" ]; then sha256sum "$1"; else echo "MISSING  $1"; fi; }
cpu() { awk '/^cpu /{print $2, $3, $4, $5, $6, $7, $8, $9}' /proc/stat; }

case ${1:-} in
    env) echo "P2M_REPO=$P2M_REPO P2M_OUT=$P2M_OUT P2Q_WORK=$P2Q_WORK P2M_WORK=$P2M_WORK P2_LAB_DIR=$P2_LAB_DIR"; exit 0;;
    row) shift;;
    *) sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
name=${1:-}
shift || true
family="" via="" image="" bin="" ipdir="" oct=65 timeout=900 note="" dry=0 mem="" params=1 rollback=0 marker='login: ?$' stage=login opts=()
while [ $# -gt 0 ]; do
    case $1 in
        --family) family=$2; shift 2;;
        --via) via=$2; shift 2;;
        --image) image=$2; shift 2;;
        --bin) bin=$2; shift 2;;
        --ipxe-dir) ipdir=$2; shift 2;;
        --oct) oct=$2; shift 2;;
        --timeout) timeout=$2; shift 2;;
        --opt) opts+=(--opt "$2"); shift 2;;
        --mem) mem=$2; shift 2;;
        --note) note=$2; shift 2;;
        --no-params) params=0; shift;;
        --rollback) rollback=1; shift;;
        --expect-marker) marker=$2; shift 2;;
        --stage) stage=$2; shift 2;;
        --exit) shift;;
        --dry) dry=1; shift;;
        *) die "row: unknown option $1";;
    esac
done
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || die "row: bad name '$name'"
case $family in uefi | bios) ;; *) die "row: --family uefi|bios";; esac
case $via in pxe | usb | iso) ;; *) die "row: --via pxe|usb|iso";; esac
[[ $image =~ ^wrtest-p2-[a-z0-9-]{1,40}$ ]] || die "row: --image wrtest-p2-<name>"
[[ $oct =~ ^[0-9]+$ ]] && [ "$oct" -ge 20 ] && [ "$oct" -le 99 ] && [ "$oct" -ne 50 ] || die "row: --oct 20..99 but 50"
[[ $timeout =~ ^[0-9]+$ ]] || die "row: --timeout seconds"
keyfile=$P2_LAB_DIR/keys/client.$image.secret
[ -s "$keyfile" ] || die "row: no key file $keyfile"
if [ -z "$ipdir" ]; then
    if [ "$via" = pxe ]; then ipdir=$P2M_WORK/bin/rel; else ipdir=$P2M_WORK/bin/media; fi
fi
if [ -z "$bin" ]; then
    case $family/$via in
        uefi/*) bin=$ipdir/ipxe.efi;;
        bios/pxe) bin=$ipdir/ipxe-stub.pxe;;
        bios/*) bin=$ipdir/ipxe.lkrn;;
    esac
fi
[ -f "$bin" ] || die "row: no iPXE binary $bin"
runscript=$QEMU_DIR/run-$family-$via.sh
[ -f "$runscript" ] || die "row: no $runscript"
dir=$P2M_OUT/$name
[ ! -e "$dir" ] || die "row: $dir exists (runs are never overwritten)"
mkdir -p "$P2M_OUT"
mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
rowid=$(printf '%s%s' "$([ "$family" = uefi ] && echo U || echo B)" "$({ [ "$via" = pxe ] && echo 1; } || { [ "$via" = usb ] && echo 2; } || echo 3)")
tmp=$P2M_OUT/.tmp.$$
mkdir -m 700 "$tmp"
trap 'rm -rf -- "$tmp"' EXIT

args=(--row "$rowid" --ip "10.77.0.$oct" --user "$image" --pool winrbd --image "$image" --key-file "$keyfile" --ipxe-dir "$ipdir" --bin "$bin"
    "${opts[@]}" --action sanboot --expect marker --marker "$marker" --timeout "$timeout")
# the default device path flavour of a PXE row, unless the row names one (--opt devpath=...: the parser refuses an option given twice)
case " ${opts[*]-} " in
    *" devpath="*) ;;
    *) { [ "$family" = uefi ] && [ "$via" = pxe ] && args+=(--opt devpath=vendor); } || true
       { [ "$family" = bios ] && [ "$via" = pxe ] && args+=(--opt devpath=vendor); } || true ;;
esac
[ -z "$mem" ] || args+=(--mem "$mem")
if [ "$params" = 1 ]; then
    id=$(lab_ssh "sudo rbd info --format json winrbd/$image" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
    bash "$P2M_REPO/harness/lab/p2/images/expected-table.sh" fwcfg --mons 10.77.0.10:3300 --entity "$image" --pool winrbd --image "$image" --image-id "$id" \
        --mode crc --mac "$mac" --ip "10.77.0.$oct/24" --static > "$tmp/params.txt"
    echo rbft.require=1 >> "$tmp/params.txt"
    args+=(--fail-marker 'WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF|error: failure reading sector|Failed to boot both default|rbd: .*(out of memory|closing the path)'
        --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/params,file=$tmp/params.txt")
    # the key a second time, by the file channel, for the guest's own kernel client (the table does not carry it: handoff=nokey, the default)
    args+=(--qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/key,file=$keyfile")
fi

if [ "$dry" = 1 ]; then
    bash "$runscript" -n "${args[@]}"
    exit 0
fi
if [ "$rollback" = 1 ]; then
    lab_ssh "sudo rbd snap rollback winrbd/$image@pristine" > /dev/null 2>&1 || die "row: could not roll $image back to its snapshot pristine"
fi
mkdir -m 700 "$dir"
{
    echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) boot $name ($rowid: $family, $via), image $image${note:+; $note}"
    echo "# the cephx key is only ever a --key-file path or a fw_cfg file name"
    echo "P2Q_WORK=$P2Q_WORK P2_LAB_DIR=$P2_LAB_DIR P2Q_BUDGET_ROOT=${P2Q_BUDGET_ROOT:-}"
    printf 'bash %q' "$runscript"
    for a in "${args[@]}"; do printf ' %q' "$a"; done
    echo
} > "$dir/cmdline.txt"
{
    sumfile "$bin"
    sumfile "$runscript"
    [ "$family" = bios ] || { sumfile "${P2Q_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"; sumfile "${P2Q_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"; }
    echo "# $(qemu-system-x86_64 --version | head -n 1)"
    echo "# image $image: $(lab_ssh "sudo rbd info --format json winrbd/$image" 2> /dev/null | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print("id", d["id"], "size", d["size"], "features", d["features"])' 2> /dev/null || echo unknown)"
} > "$dir/binaries.sha256"
bash "$LABSTATE" snapshot "$dir/lab-before.txt" > /dev/null
{
    echo "# health before: $(bash "$LABSTATE" health 2> /dev/null | tr '\n' ' ' || echo unknown)"
    echo "before t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)"
} > "$dir/load.txt"
rc=0
: > "$dir/stdout.txt"
bash "$runscript" "${args[@]}" > "$dir/stdout.txt" 2>&1 &
pid=$!
python3 -I "$UEFI_TOOLS/stamp.py" "$P2Q_WORK/runs" "$pid" "$dir/stamps.txt" "$P2_LAB_DIR/vm/qemu.pid" &
spid=$!
wait "$pid" || rc=$?
wait "$spid" || true
{ tail -n 1 "$dir/stdout.txt"; echo "exit=$rc"; } > "$dir/result.txt"
echo "after t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)" >> "$dir/load.txt"
bash "$LABSTATE" snapshot "$dir/lab-after.txt" > /dev/null
bash "$LABSTATE" diff "$dir/lab-before.txt" "$dir/lab-after.txt" > "$dir/lab-diff.txt" 2>&1 || true
console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
: > "$dir/serial.txt"
if [ -n "$console" ] && [ -f "$console" ]; then
    cp -p "$console" "$dir/serial.txt"
    base=${console%.console}
    [ ! -f "$base.screen.ppm" ] || cp -p "$base.screen.ppm" "$dir/screen.ppm"
fi
keyhit=0 krc=0
hits=$(python3 -I "$UEFI_TOOLS/keyscan.py" "$keyfile" "$dir") || krc=$?
if [ "$krc" = 1 ]; then
    keyhit=1
    while IFS= read -r f; do [ -z "$f" ] || rm -f -- "$dir/$f"; done <<< "$hits"
elif [ "$krc" != 0 ]; then keyhit=1; fi
python3 -I "$M_HERE/analyze.py" login "$dir" "$stage" > /dev/null || true
if [ "$keyhit" = 1 ]; then
    { echo FAIL; echo "FAIL secret scan: the run's own key was found in the run's files (deleted) or could not be scanned"; tail -n +2 "$dir/verdict.txt"; } > "$dir/verdict.new"
    mv -f "$dir/verdict.new" "$dir/verdict.txt"
fi
echo "mboot.sh: $name: $(head -n 1 "$dir/verdict.txt")  ($(tail -n 2 "$dir/result.txt" | tr '\n' ' ' | cut -c1-200))"
