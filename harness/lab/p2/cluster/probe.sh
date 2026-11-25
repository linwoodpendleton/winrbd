#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 lab cluster: prove that a QEMU guest on the lab's private layer 2 reaches the monitor
# (10.77.0.10:3300) and every OSD address the OSD map advertises.
#
#   probe.sh [-n] [--keep]
#
#   -n, --dry-run   print the commands and the QEMU command line, start nothing
#   --keep          keep LAB_DIR/probe (seed, overlay, console log) after the run, for debugging
#
# What it does: asks the lab VM for the msgr2 address of the monitor and of every OSD (ceph mon dump / ceph osd dump),
# builds a throw-away cloud-init seed with that list, boots a small guest (a copy-on-write overlay of the verified
# base image, 1 core, 768 MiB, under nice / choom) whose
#   NIC 1 is user-mode (slirp), and
#   NIC 2 is on the lab's multicast layer 2 with the static address P2_PROBE_IP (10.77.0.50),
# which then opens a TCP connection to each address and reads the first bytes: a Ceph daemon speaking msgr2 sends the
# banner "ceph v2". The guest also asks the kernel which interface it would use to reach the monitor, and tries one
# address nobody owns (a control: it must NOT answer). The guest powers itself off; the results come back on its serial
# console. Exit status 0 only when the monitor and every OSD answered with the banner and the control did not.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=up.sh
. "$here/up.sh"

keep=0
p2_init "$@"
for a in "${P2_ARGS[@]+"${P2_ARGS[@]}"}"; do
    case "$a" in
        --keep) keep=1;;
        *) die "unknown option $a";;
    esac
done

pdir=$LAB_DIR/probe
base=$LAB_IMGDIR/$LAB_IMAGE_NAME
control_ip=${LAB_PRIV_CIDR%.*}.99

if ! p2_dry; then
    [ -n "$(p2_vm_pid || true)" ] || die "the lab VM is not running; run up.sh"
    p2_ssh_ok || die "the lab VM does not answer on ssh"
    [ -f "$base" ] || die "the base image $base is missing (up.sh downloads it; it is removed by down.sh)"
    [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not usable"
    p2_lock
    if [ -f "$pdir/qemu.pid" ]; then
        pp=$(cat "$pdir/qemu.pid" 2>/dev/null || true)
        if [ -n "$pp" ] && [ -d "/proc/$pp" ] && grep -q "$pdir" "/proc/$pp/cmdline" 2>/dev/null; then
            die "a probe guest is already running (pid $pp)"
        fi
    fi
fi
p2_budget_check "$P2_PROBE_CPUS" "$P2_PROBE_MEM_MB" "@none@"

# 1. the addresses the clusters advertises
info "asking the lab VM for the monitor and OSD addresses"
if p2_dry; then
    addrs="mon.a ${LAB_PRIV_CIDR%/*}:3300
osd.0 ${LAB_PRIV_CIDR%/*}:6800"
    p2_cluster_addrs
else
    addrs=$(p2_cluster_addrs)
fi
[ -n "$addrs" ] || die "no daemon addresses from the lab VM"

# 2. the seed
if ! p2_dry; then
    mkdir -p "$pdir" "$LAB_DIR/logs"
fi
guest_script() {
    cat <<'EOS'
#!/bin/bash
# Runs once, at first boot, after the network is up. Results go to the serial console, one line each.
con=/dev/ttyS0
say() { printf '\nWRPROBE %s\n' "$*" > "$con"; }   # leading newline: the kernel may be mid-line
self=$(awk '$1 == "self" {print $2}' /etc/wr-probe.targets)
say BEGIN "self=$self"
for _ in $(seq 1 90); do
    ip -4 -o addr show dev lab0 2>/dev/null | grep -q " $self/" && break
    sleep 1
done
say LINK "$(ip -br link show dev lab0 2>/dev/null | tr -s ' ')"
say ADDR "$(ip -4 -br addr show dev lab0 2>/dev/null | tr -s ' ')"
mon_ip=$(awk '$1 == "mon" {split($3, a, ":"); print a[1]; exit}' /etc/wr-probe.targets)
say ROUTE "to $mon_ip: $(ip -4 route get "$mon_ip" 2>&1 | head -n 1 | tr -s ' ')"
ping -c 3 -W 1 "$mon_ip" > /dev/null 2>&1
say NEIGH "$(ip neigh show dev lab0 2>/dev/null | tr -s ' ' | tr '\n' ';')"
# try HOST PORT -> "connected <first 8 bytes>" or "unreachable" / "timeout"
try() {
    local out rc
    out=$(timeout 12 bash -c 'exec 3<>"/dev/tcp/$1/$2" || exit 3; IFS= read -r -t 4 -N 8 b <&3; printf "%s" "$b" | tr -d "\\n"; exit 0' _ "$1" "$2" 2>/dev/null)
    rc=$?
    case $rc in
        0) echo "connected ${out:-no-banner}";;
        3) echo "unreachable -";;
        *) echo "timeout -";;
    esac
}
while read -r kind name addr; do
    case "$kind" in
        mon|osd|ctl)
            r=$(try "${addr%:*}" "${addr##*:}")
            say TCP "$kind" "$name" "$addr" "$r";;
    esac
done < /etc/wr-probe.targets
say END
EOS
}

targets=$(
    echo "self $P2_PROBE_IP"
    while read -r name addr; do
        [ -n "$name" ] || continue
        case "$name" in mon.*) echo "mon $name $addr";; osd.*) echo "osd $name $addr";; esac
    done <<< "$addrs"
    echo "ctl nobody $control_ip:3300"
)

if p2_dry; then
    echo "would write $pdir/user-data (cloud-config with the probe script and these targets), meta-data, network-config:"
    printf '%s\n' "$targets" | sed 's/^/    /'
else
    {
        echo '#cloud-config'
        echo 'hostname: wr-p2-probe'
        echo 'ssh_pwauth: false'
        echo 'write_files:'
        echo '  - path: /etc/wr-probe.targets'
        echo '    content: |'
        printf '%s\n' "$targets" | sed 's/^/      /'
        echo '  - path: /usr/local/bin/wr-probe.sh'
        echo "    permissions: '0755'"
        echo '    content: |'
        guest_script | sed 's/^/      /'
        echo 'runcmd:'
        echo '  - [ /usr/local/bin/wr-probe.sh ]'
        echo 'power_state:'
        echo '  mode: poweroff'
        echo '  message: probe finished'
        echo '  timeout: 30'
        echo '  condition: true'
    } > "$pdir/user-data"
    printf 'instance-id: wr-p2-probe-%s\nlocal-hostname: wr-p2-probe\n' "$(date +%s)" > "$pdir/meta-data"
    cat > "$pdir/network-config" <<NET
version: 2
ethernets:
  inet:
    match: {macaddress: "$P2_PROBE_MAC_INET"}
    set-name: inet0
    dhcp4: true
    optional: true
  lab:
    match: {macaddress: "$P2_PROBE_MAC_PRIV"}
    set-name: lab0
    dhcp4: false
    dhcp6: false
    addresses: ["$P2_PROBE_IP/24"]
NET
    "$LAB_DIR/tools/bin/cloud-localds" -N "$pdir/network-config" "$pdir/seed.iso" "$pdir/user-data" "$pdir/meta-data"
fi
run qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$pdir/probe.qcow2"

# 3. the guest
# shellcheck disable=SC2054  # the commas are part of QEMU's option syntax
qargs=(
    -name wr-p2-probe
    -machine q35,accel=kvm -cpu host
    -smp "$P2_PROBE_CPUS" -m "$P2_PROBE_MEM_MB"
    -display none -no-reboot
    -serial "file:$pdir/console.log"
    -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0
    -drive "file=$pdir/probe.qcow2,if=none,id=root,format=qcow2,cache=none"
    -device virtio-blk-pci,drive=root,bootindex=1
    -drive "file=$pdir/seed.iso,if=none,id=seed,format=raw,readonly=on"
    -device virtio-blk-pci,drive=seed
    -netdev user,id=net0
    -device "virtio-net-pci,netdev=net0,mac=$P2_PROBE_MAC_INET"
    -netdev "socket,id=net1,mcast=$LAB_MCAST,localaddr=$LAB_MCAST_LOCALADDR"
    -device "virtio-net-pci,netdev=net1,mac=$P2_PROBE_MAC_PRIV"
    -pidfile "$pdir/qemu.pid"
)

# shellcheck disable=SC2329  # called by the EXIT trap
cleanup() {
    local pp
    pp=$(cat "$pdir/qemu.pid" 2>/dev/null || true)
    if [ -n "$pp" ] && [ -d "/proc/$pp" ] && grep -q "$pdir" "/proc/$pp/cmdline" 2>/dev/null; then
        kill "$pp" 2>/dev/null || true
    fi
    if [ "$keep" = 0 ] && [ -d "$pdir" ]; then
        find "$pdir" -maxdepth 1 -type f -delete
        rmdir "$pdir" 2>/dev/null || true
    fi
}
if p2_dry; then
    run "${P2_WRAP[@]}" timeout "$P2_PROBE_TIMEOUT_S" qemu-system-x86_64 "${qargs[@]}"
    echo "dry run: nothing was started"
    exit 0
fi
# (not before the dry-run exit: a dry run must not delete what an earlier --keep run left in $pdir)
trap cleanup EXIT

info "booting the probe guest on the layer 2 $LAB_MCAST (nice $LAB_NICE, choom 600; up to $P2_PROBE_TIMEOUT_S s)"
set +e
"${P2_WRAP[@]}" timeout "$P2_PROBE_TIMEOUT_S" qemu-system-x86_64 "${qargs[@]}" 9>&-
qrc=$?
set -e
[ "$qrc" != 124 ] || info "the guest did not power off in time; terminated"

# 4. the results
stamp=$(date -u +%Y%m%dT%H%M%SZ)
[ -f "$pdir/console.log" ] || die "the probe guest left no console log (qemu exit status $qrc): it did not start; run again with the same settings and look at the message above"
lines=$(tr -d '\r' < "$pdir/console.log" | grep -o 'WRPROBE .*' || true)
cp -f "$pdir/console.log" "$LAB_DIR/logs/probe-$stamp.console"
printf '%s\n' "$lines" > "$LAB_DIR/logs/probe-$stamp.txt"
if ! printf '%s\n' "$lines" | grep -q '^WRPROBE END'; then
    info "no result from the guest (qemu exit $qrc); console log: $LAB_DIR/logs/probe-$stamp.console"
    tail -n 15 "$pdir/console.log" | tr -d '\r' >&2 || true
    exit 1
fi
want_mon=$(printf '%s\n' "$addrs" | grep -c '^mon\.' || true)
want_osd=$(printf '%s\n' "$addrs" | grep -c '^osd\.' || true)
fail=0
p2_probe_verdict "$lines" "$want_mon" "$want_osd" || fail=1
if [ "$fail" = 0 ]; then
    info "PROBE OK: the monitor and $P2_PROBE_NOSD OSD address(es) answered with the msgr2 banner over the lab's layer 2; the control did not"
else
    info "PROBE FAILED (logs: $LAB_DIR/logs/probe-$stamp.txt, .console)"
fi
exit "$fail"
