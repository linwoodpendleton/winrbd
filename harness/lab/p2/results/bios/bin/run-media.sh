#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# run-media.sh - rows B2 and B3 with the REAL build targets bin/ipxe.usb and bin/ipxe.iso, which carry the constant stub (no key inside).
#
#   run-media.sh usb|iso [the options of run-bios-usb.sh / run-bios-iso.sh] --media FILE ...
#
# The stock run scripts take a real image only with the run script embedded in it ("--media FILE --delivery embed"), which puts the cephx key
# into the binary. This script keeps the key out of the binary: the image has the constant stub of gen-script.sh --stub built in (it brings
# net0 up with DHCP and runs autoexec.ipxe from the DHCP next-server over TFTP), and the run script reaches it over QEMU's own TFTP server
# on the user-mode NIC 1 (tftp= the run directory). Only q_build_qargs and q_stage_files of the stock library (common.sh, sourced unchanged)
# are replaced; budget, key handling, markers, timeout, clean-up and the scan of the log for the key are the library's.
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
qdir=${P2B_QEMU_DIR:-$here/../../../qemu}
# shellcheck source-path=SCRIPTDIR/../../../qemu source=../../../qemu/common.sh
. "$qdir/common.sh"

kind=${1:-}
case "$kind" in usb) qkind=bios-usb ;; iso) qkind=bios-iso ;; *) echo "usage: run-media.sh usb|iso [options] --media FILE" >&2; exit 2 ;; esac
shift

q_orig=$(declare -f q_stage_files)
eval "${q_orig/q_stage_files/m_orig_stage_files}"
q_stage_files() {
    m_orig_stage_files
    # the run script on QEMU's TFTP server (the stub asks the DHCP next-server, 10.0.2.2, for autoexec.ipxe)
    mkdir -m 700 "$RUNDIR/tftp"
    cp "$SCRIPT_FILE" "$RUNDIR/tftp/autoexec.ipxe"
    chmod 600 "$RUNDIR/tftp/autoexec.ipxe"
}

q_build_qargs() {
    local model=$P2Q_NIC_MODEL cpu=host
    [ "$P2Q_ACCEL" = kvm ] || cpu=max
    QARGS=(-name "$Q_RUNID_Q" -machine "q35,accel=$P2Q_ACCEL" -cpu "$cpu" -smp "$P2Q_CPUS" -m "$P2Q_MEM_MB"
        -display none -vga std -no-reboot
        -serial "file:$Q_CONSOLE"
        -chardev "socket,id=qmp0,path=$Q_QMP,server=on,wait=off" -mon chardev=qmp0,mode=control
        -pidfile "$Q_PIDFILE" -boot menu=off
        -netdev "user,id=net0,restrict=on,tftp=$RUNDIR/tftp,hostname=wrp2q"
        -device "$model,netdev=net0,mac=$Q_MAC_USER,romfile="
        -netdev "socket,id=lab,mcast=$P2Q_MCAST,localaddr=$P2Q_MCAST_LOCALADDR"
        -device "$model,netdev=lab,mac=$Q_MAC_LAB,romfile=")
    case "$Q_MEDIA_KIND" in
        usb) QARGS+=(-drive "if=none,id=usb0,file=$Q_MEDIA_PATH,format=raw,readonly=on" -device qemu-xhci,id=xhci
                     -device usb-storage,bus=xhci.0,drive=usb0,bootindex=1);;
        iso) QARGS+=(-drive "if=none,id=cd0,file=$Q_MEDIA_PATH,media=cdrom,readonly=on,format=raw"
                     -device ide-cd,drive=cd0,bootindex=1);;
    esac
    if [ -n "$Q_DISK" ]; then
        QARGS+=(-drive "if=none,id=hd0,file=${DISK_PATH:-$Q_DISK},format=${DISK_FMT:-$Q_DISK_FMT}" -device ide-hd,drive=hd0,bootindex=2)
    fi
    local a
    for a in ${Q_QEXTRA[@]+"${Q_QEXTRA[@]}"}; do QARGS+=("$a"); done
    b_debugcon_args
    q_check_no_host_net
}

# shellcheck source=lib.sh
. "$here/lib.sh"

q_main "$qkind" "$@"
exit $?
