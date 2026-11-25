#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mkparams.sh - the expected values of one row's configuration, as the guest's rbft-check wants them (a file for QEMU's
#   -fw_cfg name=opt/winrbd/params,file=FILE), written to $P2B_WORK/params/NAME-IP.txt (mode 600, no secret: the key is only measured).
#
#   mkparams.sh NAME OCTET [--keytype none|aes] [--mode crc|...] [--no-require] [--extra "words"]
#
# NAME is the lab image and the cephx user (wrtest-p2-bX); OCTET the last octet of the guest's lab address (10.77.0.OCTET/24, MAC
# 52:54:00:77:12:(OCTET+128)). The image id is read from the cluster. Expected: crc mode, one monitor, no gateway, no DNS, static NIC,
# the key in the table (flags key,static) unless --keytype none. rbft.require=1 ends a failed run at once instead of at the timeout
# (--no-require: row B0, where nothing is mapped and the root stays the local disk).
set -euo pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=labenv.sh
. "$here/labenv.sh"
name=${1:?NAME} oct=${2:?OCTET}
shift 2
keytype=aes extra="" mode=crc require=1
while [ $# -gt 0 ]; do
    case $1 in
        --keytype) keytype=$2; shift 2;;
        --mode) mode=$2; shift 2;;
        --extra) extra=$2; shift 2;;
        --no-require) require=0; shift;;
        *) echo "mkparams.sh: unknown option $1" >&2; exit 2;;
    esac
done
id=$(image_id "winrbd/$name")
mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
mkdir -p -m 700 "$P2B_WORK/params"
out=$P2B_WORK/params/$name-$oct.txt
args=(--mons 10.77.0.10:3300 --entity "$name" --pool winrbd --image "$name" --image-id "$id" --mode "$mode" --mac "$mac" --ip "10.77.0.$oct/24" --static)
[ "$keytype" = none ] || args+=(--keytype "$keytype" --key-b64-file "$LAB_DIR/keys/client.$name.secret")
umask 077
"$here/../../../images/expected-table.sh" fwcfg "${args[@]}" > "$out"
[ "$require" = 0 ] || echo rbft.require=1 >> "$out"
for w in $extra; do echo "$w" >> "$out"; done
echo "$out"
