#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# run-undi.sh - rows B0 and B1 with the real undionly.kpxe: SeaBIOS, PXE, ONE guest NIC that sits on the lab's layer 2.
#
# Why this script exists. undionly.kpxe drives only the NIC that the PXE ROM booted from (UNDI). The stock run script run-bios-pxe.sh
# PXE-boots from a user-mode NIC 1 and keeps the lab NIC as NIC 2, which UNDI cannot see (WRRUN-NO-LAB-NIC): fine for ipxe.pxe with native
# drivers, useless for undionly.kpxe. Here the lab NIC is the ONLY NIC and the PXE ROM boots from it, so UNDI sees the NIC that reaches
# the cluster. Something on that layer 2 has to answer DHCP and TFTP: a dnsmasq that this script starts in the lab VM for the length of
# the run (package dnsmasq-base, no service; it listens on the lab NIC only, answers only this guest's MAC, and is stopped at the end).
#
# Everything else is the stock library, unchanged: harness/lab/p2/qemu/common.sh (budget, key handling, serial markers, timeout, clean-up,
# the scan of the log for the key). Only three functions are replaced after it is sourced: q_build_qargs (the NIC topology),
# q_stage_files (put the files where the lab VM's TFTP server reads them) and q_cleanup (undo that).
#
#   run-undi.sh [the options of run-bios-pxe.sh] --bin undionly.kpxe --ipxe-dir DIR ...
# Environment: LAB_DIR (the lab of harness/lab/p2/cluster on this machine: its ssh key and port), P2Q_WORK, P2Q_BUDGET_* as for the stock scripts.
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
qdir=${P2B_QEMU_DIR:-$here/../../../qemu}
# shellcheck source-path=SCRIPTDIR/../../../qemu source=../../../qemu/common.sh
. "$qdir/common.sh"

: "${LAB_DIR:?LAB_DIR must name the lab directory (its ssh key and port are used to reach the lab VM)}"
U_LABUSER=${LAB_SSH_USER:-lab}
U_LABPORT=${LAB_SSH_PORT:-22232}
U_TFTP=wrp2-tftp                    # in the lab user's home
U_LOCK=${P2Q_WORK:-$HOME/winrbd-p2-qemu}/.undi.lock

u_lab() {   # u_lab COMMAND...  (one string, run by the remote shell)
    ssh -p "$U_LABPORT" -i "$LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "$U_LABUSER@127.0.0.1" "$@" </dev/null
}
u_put() {   # u_put LOCAL REMOTE-NAME MODE
    ssh -p "$U_LABPORT" -i "$LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "$U_LABUSER@127.0.0.1" \
        "umask 077; cat > $U_TFTP/$2.part && chmod $3 $U_TFTP/$2.part && mv -f $U_TFTP/$2.part $U_TFTP/$2" <"$1"
}

# ---- the NIC topology: the lab NIC is the only NIC and the PXE ROM boots from it
q_build_qargs() {
    local model=$P2Q_NIC_MODEL cpu=host
    [ "$P2Q_ACCEL" = kvm ] || cpu=max
    QARGS=(-name "$Q_RUNID_Q" -machine "q35,accel=$P2Q_ACCEL" -cpu "$cpu" -smp "$P2Q_CPUS" -m "$P2Q_MEM_MB"
        -display none -vga std -no-reboot
        -serial "file:$Q_CONSOLE"
        -chardev "socket,id=qmp0,path=$Q_QMP,server=on,wait=off" -mon chardev=qmp0,mode=control
        -pidfile "$Q_PIDFILE" -boot menu=off
        -netdev "socket,id=lab,mcast=$P2Q_MCAST,localaddr=$P2Q_MCAST_LOCALADDR"
        -device "$model,netdev=lab,mac=$Q_MAC_LAB,bootindex=1")
    if [ -n "$Q_DISK" ]; then
        QARGS+=(-drive "if=none,id=hd0,file=${DISK_PATH:-$Q_DISK},format=${DISK_FMT:-$Q_DISK_FMT}" -device ide-hd,drive=hd0,bootindex=2)
    fi
    local a
    for a in ${Q_QEXTRA[@]+"${Q_QEXTRA[@]}"}; do QARGS+=("$a"); done
    b_debugcon_args
    q_check_no_host_net
}

# ---- the files and the dnsmasq in the lab VM
orig_stage=$(declare -f q_stage_files)
eval "${orig_stage/q_stage_files/u_orig_stage_files}"
U_STARTED=0
q_stage_files() {
    u_orig_stage_files
    [ "$Q_DRY" = 0 ] || return 0
    exec 8>"$U_LOCK"
    flock -w 600 8 || q_die "another undionly run holds $U_LOCK"
    U_STARTED=1     # from here on the clean-up also stops dnsmasq and removes the run script in the lab VM
    u_lab "mkdir -p -m 700 $U_TFTP && rm -f $U_TFTP/autoexec.ipxe $U_TFTP/*.part" || q_die "cannot reach the lab VM"
    u_put "$Q_BIN_PATH" "$Q_BIN_NAME" 644 || q_die "cannot copy $Q_BIN_NAME to the lab VM"
    u_put "$SCRIPT_FILE" autoexec.ipxe 600 || q_die "cannot copy the run script to the lab VM"
    local ip="$P2Q_NET.$Q_OCT"
    # one dnsmasq: DHCP only for this guest's MAC (every other client on the layer 2 is ignored), TFTP from $U_TFTP, no DNS, no router
    # option (the stock rows have no gateway on the lab network, and the handoff table records the NIC as iPXE configured it), no leases kept
    u_lab "sudo pkill -x dnsmasq; sleep 0.5; : > $U_TFTP.log; sudo dnsmasq --conf-file=/dev/null --port=0 --interface=lab0 --bind-interfaces \
        --dhcp-range=$ip,static,255.255.255.0 --dhcp-host=$Q_MAC_LAB,$ip --dhcp-ignore='tag:!known' --dhcp-broadcast --dhcp-option=3 \
        --dhcp-boot=$Q_BIN_NAME,winrbd-p2-ceph,10.77.0.10 --enable-tftp --tftp-root=/home/$U_LABUSER/$U_TFTP --tftp-no-fail \
        --user=$U_LABUSER --pid-file=/home/$U_LABUSER/$U_TFTP.pid --dhcp-leasefile=/home/$U_LABUSER/$U_TFTP.leases \
        --log-dhcp --log-facility=/home/$U_LABUSER/$U_TFTP.log && sleep 1 && test -s $U_TFTP.pid" || q_die "dnsmasq did not start in the lab VM"
    Q_BOOTFILE=$Q_BIN_NAME
}

orig_clean=$(declare -f q_cleanup)
eval "${orig_clean/q_cleanup/u_orig_cleanup}"
q_cleanup() {
    if [ "${U_STARTED:-0}" = 1 ]; then
        u_lab "sudo pkill -x dnsmasq; rm -f $U_TFTP/autoexec.ipxe $U_TFTP/$Q_BIN_NAME $U_TFTP.pid $U_TFTP.leases" >/dev/null 2>&1 || q_warn "could not stop dnsmasq / remove the run script in the lab VM: do it by hand (pkill dnsmasq; rm ~/$U_TFTP/autoexec.ipxe)"
        if [ -n "${LOGBASE:-}" ]; then u_lab "cat $U_TFTP.log" > "$LOGBASE.dnsmasq" 2>/dev/null || true; fi
        u_lab "rm -f $U_TFTP.log" >/dev/null 2>&1 || true
        U_STARTED=0
    fi
    u_orig_cleanup
}

# shellcheck source=lib.sh
. "$here/lib.sh"

q_main bios-pxe "$@"
exit $?
