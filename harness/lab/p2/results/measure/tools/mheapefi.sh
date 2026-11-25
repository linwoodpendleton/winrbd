#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mheapefi.sh - iPXE's heap maximum on UEFI with the driver in use (risk R1). On UEFI iPXE shuts down when the boot loader calls ExitBootServices, and its "HEAP maximum
# usage" line (DEBUG=malloc) never reaches the console then (rows heap-efi-N: no such line in a whole boot). So this run does not boot: the instrumented ipxe.efi hooks the
# Linux guest's image, reads the firmware's file system on it (the ESP: the boot loader, through the firmware's FAT driver and the SAN device), frees it and exits;
# iPXE unloads and prints the line (twice per character: on UEFI the serial line carries the firmware console and the debug console, analyze.py reads that).
#
#   mheapefi.sh LABEL [--oct N]
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
oct=67
[ "${1:-}" != --oct ] || oct=$2
[[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || { echo "mheapefi.sh: bad name" >&2; exit 2; }
image=wrtest-p2-ms-lin-uefi
keyfile=$P2_LAB_DIR/keys/client.$image.secret
bin=$P2M_WORK/bin/inst/ipxe.efi
[ -s "$keyfile" ] && [ -f "$bin" ] || { echo "mheapefi.sh: no key file or no $bin" >&2; exit 2; }
dir=$P2M_OUT/$name
[ ! -e "$dir" ] || { echo "mheapefi.sh: $dir exists" >&2; exit 2; }
mkdir -p "$P2M_OUT"
mkdir -m 700 "$dir"
tmp=$(mktemp -d "$P2M_OUT/.tmp.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
cat > "$tmp/append.ipxe" <<'EOS'
echo WRMS-INFO-BEGIN
rbd-info
echo WRMS-INFO-END
imgfetch --name wrg file://WRBESP/EFI/BOOT/BOOTX64.EFI || echo WRHEAP-READ-FAILED ${errno}
imgstat
imgfree wrg
echo WRMS-INFO-BEGIN
rbd-info
echo WRMS-INFO-END
exit
EOS
args=(--row U1 --ip "10.77.0.$oct" --user "$image" --pool winrbd --image "$image" --key-file "$keyfile" --ipxe-dir "$(dirname "$bin")" --bin "$bin"
    --action sanhook --leave none --append "$tmp/append.ipxe" --expect marker --marker 'HHEEAAPP|HEAP maximum usage' --timeout 300 --opt devpath=vendor)
{ echo "# heap on UEFI: hook, read the ESP's boot loader, exit"; printf 'bash %q' "$QEMU_DIR/run-uefi-pxe.sh"; for a in "${args[@]}"; do printf ' %q' "$a"; done; echo; sed 's/^/#   /' "$tmp/append.ipxe"; } > "$dir/cmdline.txt"
sha256sum "$bin" "$QEMU_DIR/run-uefi-pxe.sh" > "$dir/binaries.sha256"
rc=0
bash "$QEMU_DIR/run-uefi-pxe.sh" "${args[@]}" > "$dir/stdout.txt" 2>&1 || rc=$?
{ tail -n 1 "$dir/stdout.txt"; echo "exit=$rc"; } > "$dir/result.txt"
console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
: > "$dir/serial.txt"
[ -z "$console" ] || [ ! -f "$console" ] || cp -p "$console" "$dir/serial.txt"
python3 -I "$M_HERE/analyze.py" base "$dir" > /dev/null || true
echo "mheapefi.sh: $name: $(head -n 1 "$dir/verdict.txt") ($(sed 's/\x1b\[[0-9;]*m//g' "$dir/serial.txt" | grep -a -o 'HHEEAAPP  mmaaxxiimmuumm  uussaaggee  [0-9]*kB' | tail -n 1))"
