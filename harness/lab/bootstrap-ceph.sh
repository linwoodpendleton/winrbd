#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Run INSIDE the lab VM, as root, after guest-packages.sh. Creates a
# single-host Ceph cluster with cephadm, one OSD per lab data disk, a
# replicated test pool, a cephx user restricted to that pool, and two test
# images. Refuses to run when a cluster already exists on this host.
#
# Outputs (never printed): the cluster admin keyring in /etc/ceph (cephadm's
# own) and the pool-limited keyring in /etc/ceph/ceph.client.<id>.keyring.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_load_conf; lab_defaults
[ "$(id -u)" = 0 ] || die "run as root"
command -v cephadm >/dev/null || die "cephadm missing; run guest-packages.sh first"
if [ -e /etc/ceph/ceph.conf ] || [ -n "$(ls -A /var/lib/ceph 2>/dev/null || true)" ]; then
    die "a Ceph cluster or configuration already exists on this host; refusing to bootstrap"
fi
mkdir -p "$LAB_FACTS"

# --- container image: pull, and check the digest against the upstream registry
upstream_ref="quay.io/ceph/ceph:v${LAB_CEPH_VERSION}"
accept='Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
manifest_digest() { # <registry/repo:tag>
    local ref=$1 host repo tag
    host=${ref%%/*}; repo=${ref#*/}; tag=${repo##*:}; repo=${repo%:*}
    curl -fsSI -m 30 -H "$accept" "https://$host/v2/$repo/manifests/$tag" \
        | tr -d '\r' | awk 'tolower($1)=="docker-content-digest:"{print $2}'
}
info "pulling $LAB_CEPH_IMAGE"
podman pull -q "$LAB_CEPH_IMAGE" >/dev/null
want=$(manifest_digest "$LAB_CEPH_IMAGE" || true)
up=$(manifest_digest "$upstream_ref" || true)
{ echo "image:                               $LAB_CEPH_IMAGE"
  echo "index digest (configured registry): ${want:-unknown}"
  echo "index digest (upstream registry):   ${up:-unknown}"; } | tee "$LAB_FACTS/image-digest.txt"
if [ -n "$want" ] && [ -n "$up" ] && [ "$want" != "$up" ]; then
    die "image digest differs from the upstream registry; refusing"
fi

info "bootstrapping the cluster on $LAB_IP"
cephadm --image "$LAB_CEPH_IMAGE" bootstrap \
    --mon-ip "$LAB_IP" \
    --single-host-defaults \
    --skip-monitoring-stack --skip-dashboard
# ceph-common (installed by guest-packages.sh) now finds /etc/ceph/ceph.conf
# and the admin keyring that bootstrap wrote.

# One mon and one mgr on this single host.
ceph orch apply mon --placement=1
ceph orch apply mgr --placement=1

# --- OSDs, one per data disk (found by serial, not by device letter) -------
for ((i = 0; i < LAB_OSD_COUNT; i++)); do
    dev=$(readlink -f "/dev/disk/by-id/virtio-winrbd-osd$i")
    [ -b "$dev" ] || die "data disk winrbd-osd$i not found"
    info "adding OSD on $dev"
    ceph orch daemon add osd "$(hostname -s):$dev"
done
info "waiting for $LAB_OSD_COUNT OSDs up+in"
for ((t = 0; t < 120; t++)); do
    n=$(ceph osd stat -f json 2>/dev/null | jq -r '.num_up_osds // 0' || echo 0)
    [ "$n" -ge "$LAB_OSD_COUNT" ] && break
    sleep 5
done
[ "${n:-0}" -ge "$LAB_OSD_COUNT" ] || die "OSDs did not come up (have ${n:-0})"

# --- pool: failure domain = osd, fixed pg_num so placement is reproducible --
ceph osd crush rule create-replicated winrbd_osd default osd
ceph osd pool create "$LAB_POOL" 32 32 replicated winrbd_osd
ceph osd pool set "$LAB_POOL" pg_autoscale_mode off
ceph osd pool set "$LAB_POOL" size 3
ceph osd pool set "$LAB_POOL" min_size 2
ceph osd pool application enable "$LAB_POOL" rbd
rbd pool init "$LAB_POOL"

# --- cephx user limited to the pool ---------------------------------------
ceph auth get-or-create "client.$LAB_CEPHX_ID" \
    mon 'profile rbd' osd "profile rbd pool=$LAB_POOL" \
    -o "/etc/ceph/ceph.client.$LAB_CEPHX_ID.keyring"
chmod 600 "/etc/ceph/ceph.client.$LAB_CEPHX_ID.keyring"

# --- test images -----------------------------------------------------------
# img-v1: layering only (the narrow v1 profile candidate)
# img-default: whatever this cluster uses by default (for comparison)
rbdc() { rbd -n "client.$LAB_CEPHX_ID" --keyring "/etc/ceph/ceph.client.$LAB_CEPHX_ID.keyring" "$@"; }
rbdc create "$LAB_POOL/img-v1" --size 4G --image-feature layering
rbdc create "$LAB_POOL/img-default" --size 4G
rbdc info "$LAB_POOL/img-v1"
rbdc info "$LAB_POOL/img-default"
info "cluster ready"
