#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Run INSIDE the lab VM, as root, after bootstrap-ceph.sh.
#
# Why this exists: a fresh Ceph 20.x (Tentacle) cluster issues AES-256 "krb5"
# cephx keys (32-byte secret, monmap auth_allowed_ciphers = aes256k only) and
# refuses legacy 16-byte AES keys. The Linux kernel client (libceph) of the
# Ubuntu 24.04 kernel only accepts 16-byte secrets ("libceph: secret too big
# 32"), so krbd, our ground-truth oracle, cannot authenticate to such a cluster.
#
# This script makes the LAB cluster (only) accept legacy AES keys alongside the
# new ones, and creates client.<id>-aes with the same pool-limited caps. The
# default user client.<id> keeps its modern key. The cluster then reports
# AUTH_INSECURE_* health errors on purpose; they are muted here. Do not do this
# on a cluster you care about.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_load_conf; lab_defaults
[ "$(id -u)" = 0 ] || die "run as root"

ceph config set mon mon_auth_allow_insecure_key true
ceph mon set auth_allowed_ciphers "aes aes256k"
ceph mon set auth_service_cipher aes
ceph auth get-or-create "client.$LAB_CEPHX_KRBD_ID" \
    mon 'profile rbd' osd "profile rbd pool=$LAB_POOL" \
    -o "/etc/ceph/ceph.client.$LAB_CEPHX_KRBD_ID.keyring" -- --key_type aes
chmod 600 "/etc/ceph/ceph.client.$LAB_CEPHX_KRBD_ID.keyring"
for c in AUTH_INSECURE_CLIENT_KEY_TYPE AUTH_INSECURE_KEYS_ALLOWED AUTH_INSECURE_KEYS_CREATABLE AUTH_INSECURE_SERVICE_TICKETS; do
    ceph health mute "$c" >/dev/null 2>&1 || true
done
info "krbd-compatible user client.$LAB_CEPHX_KRBD_ID created"
