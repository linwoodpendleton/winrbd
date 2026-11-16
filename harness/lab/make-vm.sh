#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Create and run the winrbd Ceph lab VM (one Ubuntu 24.04 cloud-image VM under
# QEMU/KVM). Runs on a Linux host with /dev/kvm. Touches no host networking:
# the VM gets a slirp NIC (SSH forwarded on host loopback only) and a private
# L2 NIC built from a QEMU multicast socket.
#
#   make-vm.sh prepare   download + verify base image, create disks and seed
#   make-vm.sh start     start the VM
#   make-vm.sh up        prepare (if needed) and start
#   make-vm.sh stop      ACPI power-off, then terminate if it does not stop
#   make-vm.sh status    show state
#   make-vm.sh cmdline   print the exact qemu command line
#   make-vm.sh ssh [..]  ssh into the guest from the host
#
# Configuration: see lab.conf.example. Safe by default: it refuses to touch a
# directory that already holds a running VM, and never overwrites existing disks.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_init

need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1"; }

free_gb() { df -Pk "$1" | awk 'NR==2{printf "%d", $4/1048576}'; }

build_cmdline() {
    QEMU_ARGS=(
        -name "$LAB_HOSTNAME"
        -machine q35,accel=kvm
        -cpu host
        -smp "$LAB_VCPUS"
        -m "$LAB_MEM_MB"
        -rtc base=utc
        -display none
        -chardev "socket,id=ser0,path=$LAB_VMDIR/console.sock,server=on,wait=off,logfile=$LAB_VMDIR/console.log"
        -serial chardev:ser0
        -qmp "unix:$LAB_VMDIR/qmp.sock,server=on,wait=off"
        -object rng-random,id=rng0,filename=/dev/urandom
        -device virtio-rng-pci,rng=rng0
        -drive "file=$LAB_VMDIR/root.qcow2,if=none,id=root,format=qcow2,cache=$LAB_DISK_CACHE,discard=unmap"
        -device virtio-blk-pci,drive=root,bootindex=1,serial=winrbd-root
        -drive "file=$LAB_VMDIR/seed.iso,if=none,id=seed,format=raw,readonly=on"
        -device virtio-blk-pci,drive=seed,serial=winrbd-seed
    )
    local i
    for ((i = 0; i < LAB_OSD_COUNT; i++)); do
        QEMU_ARGS+=(
            -drive "file=$LAB_VMDIR/osd$i.qcow2,if=none,id=osd$i,format=qcow2,cache=$LAB_DISK_CACHE,discard=unmap"
            -device "virtio-blk-pci,drive=osd$i,serial=winrbd-osd$i"
        )
    done
    QEMU_ARGS+=(
        # NIC1: internet (slirp NAT); only SSH is forwarded, on host loopback.
        -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$LAB_SSH_PORT-:22"
        -device "virtio-net-pci,netdev=net0,mac=$LAB_MAC_INET"
        # NIC2: private L2 shared by every VM that uses the same mcast group.
        -netdev "socket,id=net1,mcast=$LAB_MCAST,localaddr=$LAB_MCAST_LOCALADDR"
        -device "virtio-net-pci,netdev=net1,mac=$LAB_MAC_PRIV"
    )
}

cmd_prepare() {
    need qemu-img
    need curl
    need sha256sum
    lab_running && die "the lab VM is running ($LAB_DIR); stop or tear it down first"
    [ -n "${LAB_SSH_PUBKEY_FILE:-}" ] && [ -r "$LAB_SSH_PUBKEY_FILE" ] \
        || die "LAB_SSH_PUBKEY_FILE must point to a readable public key"
    mkdir -p "$LAB_DIR" "$LAB_VMDIR" "$LAB_IMGDIR" "$LAB_FACTS"
    : > "$LAB_DIR/.winrbd-lab"
    local free
    free=$(free_gb "$LAB_DIR")
    [ "$free" -ge "$LAB_MIN_FREE_GB" ] \
        || die "only ${free} GB free under $LAB_DIR (need at least $LAB_MIN_FREE_GB)"
    [ ! -e "$LAB_VMDIR/root.qcow2" ] \
        || die "$LAB_VMDIR/root.qcow2 already exists; run teardown.sh first (disks are never overwritten)"

    # Base image, verified against the SHA256SUMS published next to it.
    local base="$LAB_IMGDIR/$LAB_IMAGE_NAME"
    if [ ! -f "$base" ]; then
        info "downloading $LAB_IMAGE_BASE_URL/$LAB_IMAGE_NAME"
        curl -fSL --retry 3 -C - -o "$base.part" "$LAB_IMAGE_BASE_URL/$LAB_IMAGE_NAME"
        mv "$base.part" "$base"
    fi
    curl -fsSL --retry 3 -o "$LAB_IMGDIR/SHA256SUMS" "$LAB_IMAGE_BASE_URL/SHA256SUMS"
    local want got
    want=$(awk -v n="$LAB_IMAGE_NAME" '{f=$2; sub(/^\*/,"",f); if (f==n) print $1}' "$LAB_IMGDIR/SHA256SUMS")
    [ -n "$want" ] || die "$LAB_IMAGE_NAME not listed in SHA256SUMS"
    got=$(sha256sum "$base" | awk '{print $1}')
    [ "$got" = "$want" ] || die "sha256 mismatch for $base (got $got, want $want); delete it and retry"
    info "base image sha256 verified: $got"
    echo "$got  $LAB_IMAGE_NAME" > "$LAB_IMGDIR/$LAB_IMAGE_NAME.sha256"

    info "creating disks"
    qemu-img create -q -f qcow2 -F qcow2 -b "$base" "$LAB_VMDIR/root.qcow2" "${LAB_ROOT_GB}G"
    local i
    for ((i = 0; i < LAB_OSD_COUNT; i++)); do
        qemu-img create -q -f qcow2 "$LAB_VMDIR/osd$i.qcow2" "${LAB_OSD_GB}G"
    done

    info "creating cloud-init seed"
    local seed="$LAB_VMDIR/seed-src"
    mkdir -p "$seed"
    {
        echo "instance-id: $LAB_HOSTNAME-$(date +%s)"
        echo "local-hostname: $LAB_HOSTNAME"
    } > "$seed/meta-data"
    {
        echo "#cloud-config"
        echo "hostname: $LAB_HOSTNAME"
        echo "manage_etc_hosts: true"
        echo "ssh_pwauth: false"
        echo "disable_root: true"
        echo "users:"
        echo "  - name: $LAB_SSH_USER"
        echo "    shell: /bin/bash"
        echo "    sudo: ALL=(ALL) NOPASSWD:ALL"
        echo "    lock_passwd: true"
        echo "    ssh_authorized_keys:"
        sed -e 's/[[:space:]]*$//' -e '/^$/d' -e 's/^/      - "/' -e 's/$/"/' "$LAB_SSH_PUBKEY_FILE"
        if [ -n "${LAB_EXTRA_PUBKEY_FILE:-}" ] && [ -r "$LAB_EXTRA_PUBKEY_FILE" ]; then
            sed -e 's/[[:space:]]*$//' -e '/^$/d' -e 's/^/      - "/' -e 's/$/"/' "$LAB_EXTRA_PUBKEY_FILE"
        fi
        if [ -n "$LAB_APT_MIRROR" ]; then
            echo "apt:"
            echo "  primary:"
            echo "    - arches: [default]"
            echo "      uri: $LAB_APT_MIRROR"
            echo "  security:"
            echo "    - arches: [default]"
            echo "      uri: $LAB_APT_MIRROR"
        fi
    } > "$seed/user-data"
    cat > "$seed/network-config" <<NET
version: 2
ethernets:
  inet:
    match: {macaddress: "$LAB_MAC_INET"}
    set-name: inet0
    dhcp4: true
  lab:
    match: {macaddress: "$LAB_MAC_PRIV"}
    set-name: lab0
    dhcp4: false
    dhcp6: false
    addresses: ["$LAB_PRIV_CIDR"]
NET
    if command -v cloud-localds >/dev/null 2>&1; then
        cloud-localds -N "$seed/network-config" "$LAB_VMDIR/seed.iso" "$seed/user-data" "$seed/meta-data"
    elif command -v genisoimage >/dev/null 2>&1; then
        genisoimage -quiet -output "$LAB_VMDIR/seed.iso" -volid cidata -joliet -rock \
            "$seed/user-data" "$seed/meta-data" "$seed/network-config"
    else
        die "need cloud-localds (cloud-image-utils) or genisoimage"
    fi
    info "prepared under $LAB_VMDIR"
}

cmd_start() {
    need qemu-system-x86_64
    [ -e /dev/kvm ] || die "/dev/kvm not present"
    lab_running && die "the lab VM is already running"
    [ -f "$LAB_VMDIR/root.qcow2" ] && [ -f "$LAB_VMDIR/seed.iso" ] || die "not prepared; run: $0 prepare"
    rm -f "$LAB_VMDIR/qmp.sock" "$LAB_VMDIR/console.sock"
    build_cmdline
    printf '%q ' qemu-system-x86_64 "${QEMU_ARGS[@]}" > "$LAB_VMDIR/qemu.cmdline"
    echo >> "$LAB_VMDIR/qemu.cmdline"
    case "$LAB_RUNNER" in
        systemd)
            need systemd-run
            systemd-run --quiet --collect --unit="$LAB_UNIT" --description="winrbd lab VM" \
                --property=Nice="$LAB_NICE" --property=KillSignal=SIGTERM \
                --property=TimeoutStopSec=30 \
                "$(command -v qemu-system-x86_64)" "${QEMU_ARGS[@]}" -pidfile "$LAB_VMDIR/qemu.pid"
            ;;
        daemon)
            nice -n "$LAB_NICE" qemu-system-x86_64 "${QEMU_ARGS[@]}" \
                -daemonize -pidfile "$LAB_VMDIR/qemu.pid"
            ;;
        *) die "unknown LAB_RUNNER '$LAB_RUNNER'";;
    esac
    info "started; ssh via 127.0.0.1:$LAB_SSH_PORT (user $LAB_SSH_USER) once cloud-init finishes"
}

qmp() {
    python3 - "$LAB_VMDIR/qmp.sock" "$1" <<'PY'
import json, socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); f = s.makefile("rw")
f.readline()
for c in ({"execute": "qmp_capabilities"}, {"execute": sys.argv[2]}):
    f.write(json.dumps(c) + "\n"); f.flush(); f.readline()
PY
}

cmd_stop() {
    lab_running || { info "not running"; return 0; }
    qmp system_powerdown 2>/dev/null || info "ACPI request failed; falling back to terminate"
    local i
    for ((i = 0; i < 60; i++)); do lab_running || { info "stopped"; return 0; }; sleep 1; done
    info "guest did not power off in 60 s; terminating qemu"
    if systemctl is-active --quiet "$LAB_UNIT" 2>/dev/null; then
        systemctl stop "$LAB_UNIT"
    else
        local pid; pid=$(cat "$LAB_VMDIR/qemu.pid"); kill "$pid"
    fi
}

cmd_status() {
    if lab_running; then echo "running"; else echo "stopped"; fi
    echo "dir:    $LAB_DIR"
    echo "ssh:    ssh -p $LAB_SSH_PORT $LAB_SSH_USER@127.0.0.1   (from the VM host)"
    echo "priv:   $LAB_PRIV_CIDR on mcast $LAB_MCAST"
}

cmd_cmdline() {
    build_cmdline
    printf '%q ' qemu-system-x86_64 "${QEMU_ARGS[@]}"; echo
}

cmd_ssh() {
    # shellcheck disable=SC2046
    ssh $(lab_ssh_opts) -p "$LAB_SSH_PORT" "$LAB_SSH_USER@127.0.0.1" "$@"
}

case "${1:-}" in
    prepare) cmd_prepare;;
    start)   cmd_start;;
    up)      [ -f "$LAB_VMDIR/root.qcow2" ] || cmd_prepare; cmd_start;;
    stop)    cmd_stop;;
    status)  cmd_status;;
    cmdline) cmd_cmdline;;
    ssh)     shift; cmd_ssh "$@";;
    *) sed -n '4,17p' "$0"; exit 2;;
esac
