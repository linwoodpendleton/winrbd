#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Run INSIDE the lab VM, as root. Writes version and configuration facts that
# the protocol work needs to the directory given as $1 (default $LAB_FACTS = $LAB_DIR/facts). Contains no keys.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_load_conf; lab_defaults
[ "$(id -u)" = 0 ] || die "run as root"
out="${1:-$LAB_FACTS}"
mkdir -p "$out"
c() { # <file> <cmd...>
    local f=$1; shift
    { echo "# $*"; "$@"; } > "$out/$f" 2>&1 || echo "# (exit $?)" >> "$out/$f"
}
kr="/etc/ceph/ceph.client.$LAB_CEPHX_ID.keyring"
c versions.txt        ceph versions
c ceph-version.txt    ceph --version
c features.txt        ceph features
c ms-modes.txt        bash -c "for k in ms_service_mode ms_client_mode ms_cluster_mode ms_mon_service_mode ms_mon_client_mode ms_mon_cluster_mode ms_osd_compress_mode; do printf '%s = ' \$k; ceph config get mon \$k; done; ceph config dump"
c mon-dump.txt        ceph mon dump
c osd-dump-header.txt bash -c "ceph osd dump | sed -n '1,/^pool /p' | sed '\$d'"
c osd-dump.txt        ceph osd dump
c crush-tunables.txt  ceph osd crush show-tunables
c crush-rule-dump.txt ceph osd crush rule dump
c crush-tree.txt      ceph osd tree
c pool-ls-detail.txt  ceph osd pool ls detail
c pool-get-all.txt    ceph osd pool get "$LAB_POOL" all
c health.txt          ceph status
c auth-ciphers.txt    bash -c "ceph mon dump | grep '^auth_'; printf 'mon_auth_allow_insecure_key = '; ceph config get mon mon_auth_allow_insecure_key"
c auth-caps.txt       bash -c "ceph auth get client.$LAB_CEPHX_ID | grep -v key"
c auth-key-types.txt  bash -c "for e in \$(ceph auth ls -f json | jq -r '.auth_dump[].entity'); do ceph auth get \$e -f json | jq -r --arg e \$e '.[0].key as \$k | \$e + \"  key_len_b64=\" + (\$k|length|tostring)'; done"
c rbd-info-v1.txt     rbd -n "client.$LAB_CEPHX_ID" --keyring "$kr" info "$LAB_POOL/img-v1"
c rbd-info-default.txt rbd -n "client.$LAB_CEPHX_ID" --keyring "$kr" info "$LAB_POOL/img-default"
c rbd-features-default.txt bash -c "ceph config get client rbd_default_features; ceph config get client rbd_default_order"
c guest-os.txt        bash -c "uname -a; . /etc/os-release; echo \$PRETTY_NAME; ip -br addr"
c image-digests.txt   podman images --digests
echo "facts written to $out"
