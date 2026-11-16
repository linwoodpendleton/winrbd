#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Run INSIDE the lab VM, as root. Installs podman, cephadm and ceph-common from
# the pinned Ceph release, plus capture and build tools for the harness.
# Idempotent. Copy this directory (and lab.conf, if you use one) into the VM
# first, then:   sudo ./guest-packages.sh
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_load_conf; lab_defaults
[ "$(id -u)" = 0 ] || die "run as root"
export DEBIAN_FRONTEND=noninteractive

command -v cloud-init >/dev/null 2>&1 && cloud-init status --wait >/dev/null 2>&1 || true

info "adding the Ceph $LAB_CEPH_RELEASE apt repository"
install -d -m 0755 /etc/apt/keyrings
if [ ! -s /etc/apt/keyrings/ceph.asc ]; then
    curl -fsSL --retry 3 -o /etc/apt/keyrings/ceph.asc "$LAB_CEPH_KEY_URL"
fi
codename=$(. /etc/os-release && echo "$VERSION_CODENAME")
echo "deb [signed-by=/etc/apt/keyrings/ceph.asc] $LAB_CEPH_APT_URL $codename main" \
    > /etc/apt/sources.list.d/ceph.list
# Prefer the pinned Ceph release over the distribution's own (older) ceph packages.
cat > /etc/apt/preferences.d/ceph-release <<PREF
Package: ceph* librados* librbd* libcephfs* librgw* python3-ceph* python3-rados python3-rbd python3-cephfs python3-rgw cephadm rbd-nbd
Pin: version ${LAB_CEPH_VERSION}-*
Pin-Priority: 1001
PREF

apt-get update -q
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections

info "installing packages"
apt-get install -y -q \
    podman lvm2 chrony curl jq python3 \
    "cephadm=${LAB_CEPH_VERSION}-*" "ceph-common=${LAB_CEPH_VERSION}-*" "rbd-nbd=${LAB_CEPH_VERSION}-*" \
    tcpdump tshark \
    build-essential clang cmake git pkg-config gdb

# krbd: the rbd kernel module must be loadable.
if ! modprobe rbd 2>/dev/null; then
    info "rbd module missing; installing linux-modules-extra for $(uname -r)"
    apt-get install -y -q "linux-modules-extra-$(uname -r)"
    modprobe rbd
fi
echo rbd > /etc/modules-load.d/rbd.conf
systemctl enable --now chrony >/dev/null 2>&1 || true

info "installed: $(ceph --version)"
info "cephadm:   $(cephadm version 2>/dev/null | head -1 || true)"
