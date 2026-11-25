#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 lab cluster: throwaway cephx users, test images and test pools, for the live tests.
# Runs on the machine that hosts the lab VM; the Ceph commands run inside the VM over SSH.
#
#   users.sh [-n] create NAME [--pool POOL] [--size 2G] [--key-type aes|aes256k] [--features LIST]
#       one test image POOL/NAME (default pool: the lab pool, default size 2G, at most 4G) and one cephx
#       user client.NAME whose caps are `mon 'profile rbd'` and `osd 'profile rbd pool=POOL'` (one pool only).
#       The default key type is the legacy `aes` (16-byte secret): the Linux kernel client in a guest cannot use
#       the 32-byte `aes256k` keys of a fresh Ceph 20 cluster. The keyring and the bare secret are written to
#       LAB_DIR/keys/client.NAME.keyring and .secret, mode 600, and are never printed.
#   users.sh [-n] delete NAME        remove the user, the image (and its snapshots) and the key files
#   users.sh [-n] delete-all         the same for every wrtest-* user, image and pool, and every key file
#   users.sh [-n] list               users, images, pools and key files (names and modes only)
#   users.sh keyfile NAME            print the path of the keyring (not its content)
#   users.sh [-n] krbd-check NAME    map the image with krbd in the VM using ONLY that user's key, write and read
#                                    back a pattern, check that another pool is refused, unmap
#   users.sh [-n] pool-create NAME [PG]   an extra pool wrtest-NAME ... (replicated, size 3, rbd enabled)
#   users.sh [-n] pool-delete NAME        remove such a pool (pool deletion is allowed only for the moment)
#
# NAME is lower-case letters, digits and '-'; it gets the prefix wrtest-p2- unless it already starts with wrtest-.
# Everything this script creates starts with wrtest-, and delete / delete-all touch nothing else: the pool
# winrbd, the images and users of the bootstrap (img-v1, img-default, client.winrbd, client.winrbd-aes) are never
# touched.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=up.sh
. "$here/up.sh"

MAX_MB=4096

usage() { sed -n '4,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

norm_name() { # NAME -> wrtest-... ; dies on a bad name
    local n=$1
    case "$n" in wrtest-*) ;; *) n=wrtest-p2-$n;; esac
    [[ "$n" =~ ^wrtest-[a-z0-9][a-z0-9-]{0,39}$ ]] || die "bad name '$1': lower-case letters, digits and '-', at most 40 characters after wrtest-"
    printf '%s' "$n"
}

norm_pool() { # POOL -> the lab pool, or a wrtest-* pool
    local p=$1
    if [ "$p" = "$LAB_POOL" ]; then printf '%s' "$p"; return; fi
    case "$p" in wrtest-*) ;; *) die "pool '$p' is not the lab pool ($LAB_POOL) and not a wrtest-* pool";; esac
    [[ "$p" =~ ^wrtest-[a-z0-9][a-z0-9-]{0,39}$ ]] || die "bad pool name '$p'"
    printf '%s' "$p"
}

size_mb() { # 512M | 2G -> MiB
    local s=$1 n
    [[ "$s" =~ ^([0-9]+)([MG])$ ]] || die "bad size '$s': use e.g. 512M or 2G"
    n=${BASH_REMATCH[1]}
    [ "${BASH_REMATCH[2]}" = G ] && n=$((n * 1024))
    [ "$n" -ge 4 ] && [ "$n" -le "$MAX_MB" ] || die "size $s out of range: 4M to 4G (the lab VM's disks are small)"
    printf '%s' "$n"
}

need_vm() {
    p2_dry && return 0
    [ -n "$(p2_vm_pid || true)" ] || die "the lab VM is not running; run up.sh"
    p2_ssh_ok || die "the lab VM does not answer on ssh yet"
}

ceph_vm() { vm sudo ceph "$@"; }
rbd_vm() { vm sudo rbd "$@"; }

keys_dir() { printf '%s' "$LAB_DIR/keys"; }

# Fetch the keyring and the bare secret of client.$1 into the key directory, mode 600, without printing them.
fetch_keys() {
    local user=$1 kd kr ks
    kd=$(keys_dir); kr=$kd/client.$user.keyring; ks=$kd/client.$user.secret
    if p2_dry; then
        echo "would write $kr and $ks (mode 600) from 'ceph auth get' / 'ceph auth get-key' of client.$user"
        return 0
    fi
    mkdir -p "$kd"; chmod 700 "$kd"
    (
        umask 077
        if ! vm sudo ceph auth get "client.$user" > "$kr.tmp" 2>/dev/null; then rm -f "$kr.tmp"; exit 1; fi
        if ! vm sudo ceph auth get-key "client.$user" > "$ks.tmp" 2>/dev/null; then rm -f "$kr.tmp" "$ks.tmp"; exit 1; fi
        mv -f "$kr.tmp" "$kr"; mv -f "$ks.tmp" "$ks"
        chmod 600 "$kr" "$ks"
    ) || die "could not fetch the key of client.$user"
}

key_kind() { # the kind of key of client.$1 from the size of the decoded secret blob (never prints the key)
    local n
    n=$(vm sudo bash -c "ceph auth get-key client.$1 | base64 -d | wc -c")
    case "$n" in
        28) echo "aes (legacy, 16-byte secret)";;
        44) echo "aes256k (32-byte secret)";;
        *)  echo "unknown ($n bytes)";;
    esac
}

kind_matches() { # REQUESTED KIND (the text key_kind prints)
    case "$1:$2" in "aes:aes ("*|"aes256k:aes256k ("*) return 0;; *) return 1;; esac
}

cmd_create() {
    [ $# -ge 1 ] || usage
    local name pool=$LAB_POOL size=2G kt=aes feat="" mb
    name=$(norm_name "$1") || exit 1; shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --pool) pool=$(norm_pool "${2:?--pool needs a value}") || exit 1; shift 2;;
            --size) size=${2:?--size needs a value}; shift 2;;
            --key-type) kt=${2:?--key-type needs a value}; shift 2;;
            --features) feat=${2:?--features needs a value}; shift 2;;
            *) die "unknown option $1";;
        esac
    done
    case "$kt" in aes|aes256k) ;; *) die "--key-type must be aes or aes256k";; esac
    [[ "$feat" =~ ^[a-z0-9,-]*$ ]] || die "bad --features list"
    mb=$(size_mb "$size") || exit 1
    need_vm

    # a leftover user of an interrupted run is checked FIRST, before anything is created: it is used only when it is what
    # was asked for, else the test would run with other caps or another key type than it believes (the key itself is never
    # read here, only its caps and its size)
    local exists=0 kind have
    if ! p2_dry && vm sudo ceph auth get "client.$name" >/dev/null 2>&1; then
        exists=1
        have=$(vm sudo bash -c "ceph auth get client.$name -f json | jq -r '.[0].caps.osd // empty'") || have=""
        [ "$have" = "profile rbd pool=$pool" ] \
            || die "user client.$name exists with other caps ('${have:-none}'); run: users.sh delete ${name#wrtest-p2-}"
        kind=$(key_kind "$name")
        kind_matches "$kt" "$kind" \
            || die "client.$name has a key of type '$kind', not the requested $kt; run: users.sh delete ${name#wrtest-p2-}"
    fi

    # the image
    if ! p2_dry && vm sudo rbd info "$pool/$name" >/dev/null 2>&1; then
        info "image $pool/$name exists"
    else
        local args=(create "$pool/$name" --size "${mb}M")
        [ -z "$feat" ] || args+=(--image-feature "$feat")
        rbd_vm "${args[@]}"
        info "image $pool/$name created (${mb} MiB)"
    fi
    # the user: caps limited to one pool
    if [ "$exists" = 1 ]; then
        info "user client.$name exists with the requested caps and key type"
    else
        local cargs=(auth get-or-create "client.$name" mon 'profile rbd' osd "profile rbd pool=$pool")
        if [ "$kt" = aes ]; then cargs+=(-- --key_type aes); fi
        # the command prints the keyring: discard it, the key goes to a file with fetch_keys
        if p2_dry; then ceph_vm "${cargs[@]}"; else ceph_vm "${cargs[@]}" >/dev/null; fi
        info "user client.$name created"
    fi
    fetch_keys "$name"
    p2_mute_insecure
    if ! p2_dry; then
        # read back what the cluster really issued (a fresh Ceph may not honour the requested type)
        kind=$(key_kind "$name")
        kind_matches "$kt" "$kind" \
            || die "client.$name has a key of type '$kind', not the requested $kt (run: users.sh delete ${name#wrtest-p2-})"
        info "client.$name: key type $kind, caps mon 'profile rbd', osd 'profile rbd pool=$pool'"
        info "keyring: $(keys_dir)/client.$name.keyring (mode 600), secret: $(keys_dir)/client.$name.secret"
    fi
}

# Remove one image and its snapshots; refuse while it is mapped in the VM.
rm_image() { # POOL NAME
    local pool=$1 name=$2
    if p2_dry; then rbd_vm snap purge --no-progress "$pool/$name"; rbd_vm rm --no-progress "$pool/$name"; return 0; fi
    vm sudo rbd info "$pool/$name" >/dev/null 2>&1 || return 0
    if vm sudo rbd showmapped 2>/dev/null | awk -v p="$pool" -v n="$name" '$2 == p && $3 == n {f = 1} END {exit !f}'; then
        die "image $pool/$name is mapped in the VM; unmap it first"
    fi
    vm sudo rbd snap purge --no-progress "$pool/$name" >/dev/null 2>&1 || true
    rbd_vm rm --no-progress "$pool/$name" >/dev/null
    info "image $pool/$name removed"
}

rm_keyfiles() { # NAME
    local kd; kd=$(keys_dir)
    if p2_dry; then echo "would remove $kd/client.$1.keyring and $kd/client.$1.secret"; return 0; fi
    rm -f "$kd/client.$1.keyring" "$kd/client.$1.secret" "$kd/client.$1.keyring.tmp" "$kd/client.$1.secret.tmp"
}

cmd_delete() {
    [ $# -eq 1 ] || usage
    local name pool
    name=$(norm_name "$1") || exit 1
    need_vm
    # the image can be in the lab pool or in any wrtest-* pool
    if p2_dry; then
        rm_image "$LAB_POOL" "$name"
    else
        for pool in "$LAB_POOL" $(vm sudo ceph osd pool ls | grep '^wrtest-' || true); do
            rm_image "$pool" "$name"
        done
    fi
    if p2_dry || vm sudo ceph auth get "client.$name" >/dev/null 2>&1; then
        ceph_vm auth rm "client.$name" >/dev/null
        info "user client.$name removed"
    fi
    rm_keyfiles "$name"
    p2_mute_insecure
}

lab_wrtest_pools() { vm sudo ceph osd pool ls | grep '^wrtest-' || true; }
lab_wrtest_users() { vm sudo bash -c "ceph auth ls -f json 2>/dev/null | jq -r '.auth_dump[].entity' | grep '^client[.]wrtest-' || true"; }
lab_wrtest_images() { # POOL
    vm sudo bash -c "rbd ls $1 2>/dev/null | grep '^wrtest-' || true"
}

cmd_delete_all() {
    need_vm
    if p2_dry; then
        echo "would remove every client.wrtest-* user, every wrtest-* image in $LAB_POOL and in the wrtest-* pools, every wrtest-* pool and every key file"
        return 0
    fi
    local pool img user kf
    for pool in "$LAB_POOL" $(lab_wrtest_pools); do
        for img in $(lab_wrtest_images "$pool"); do rm_image "$pool" "$img"; done
    done
    for user in $(lab_wrtest_users); do
        ceph_vm auth rm "$user" >/dev/null
        info "user $user removed"
    done
    for pool in $(lab_wrtest_pools); do cmd_pool_delete "$pool"; done
    for kf in "$(keys_dir)"/client.wrtest-*; do [ -e "$kf" ] && rm -f "$kf"; done
    p2_mute_insecure
    info "all wrtest-* objects removed"
}

cmd_list() {
    need_vm
    echo "users:"
    if p2_dry; then lab_wrtest_users; else lab_wrtest_users | sed 's/^/  /'; fi
    echo "pools: $LAB_POOL (lab pool) and:"
    if p2_dry; then lab_wrtest_pools; else lab_wrtest_pools | sed 's/^/  /'; fi
    echo "images:"
    if p2_dry; then lab_wrtest_images "$LAB_POOL"; return 0; fi
    local pool
    for pool in "$LAB_POOL" $(lab_wrtest_pools); do
        lab_wrtest_images "$pool" | sed "s|^|  $pool/|"
    done
    echo "key files ($(keys_dir)):"
    local f
    for f in "$(keys_dir)"/client.wrtest-*; do
        [ -e "$f" ] && printf '  %s  mode %s\n' "$(basename "$f")" "$(stat -c %a "$f")"
    done
    return 0
}

cmd_keyfile() {
    [ $# -eq 1 ] || usage
    local name f
    name=$(norm_name "$1") || exit 1
    f=$(keys_dir)/client.$name.keyring
    [ -f "$f" ] || die "no key file for client.$name (run: users.sh create $1)"
    printf '%s\n' "$f"
}

cmd_pool_create() {
    [ $# -ge 1 ] || usage
    local pool pg=${2:-8}
    pool=$(norm_name "$1") || exit 1
    [[ "$pg" =~ ^[0-9]+$ ]] && [ "$pg" -ge 1 ] && [ "$pg" -le 32 ] || die "PG count must be 1 to 32"
    need_vm
    if ! p2_dry && vm sudo ceph osd pool ls | grep -qx "$pool"; then info "pool $pool exists"; return 0; fi
    ceph_vm osd pool create "$pool" "$pg" "$pg" replicated winrbd_osd
    ceph_vm osd pool set "$pool" pg_autoscale_mode off
    ceph_vm osd pool set "$pool" size 3
    ceph_vm osd pool set "$pool" min_size 2
    ceph_vm osd pool application enable "$pool" rbd
    rbd_vm pool init "$pool"
    info "pool $pool created"
}

cmd_pool_delete() {
    [ $# -eq 1 ] || usage
    local pool
    pool=$(norm_name "$1") || exit 1
    need_vm
    if ! p2_dry && ! vm sudo ceph osd pool ls | grep -qx "$pool"; then return 0; fi
    # deletion is allowed only for the instant of the delete, and the flag is put back even when the delete fails
    local rc=0
    ceph_vm config set mon mon_allow_pool_delete true
    ceph_vm osd pool delete "$pool" "$pool" --yes-i-really-really-mean-it || rc=$?
    ceph_vm config set mon mon_allow_pool_delete false
    [ "$rc" = 0 ] || die "could not delete pool $pool (ceph exit status $rc)"
    info "pool $pool removed"
}

cmd_krbd_check() {
    [ $# -eq 1 ] || usage
    local name
    name=$(norm_name "$1") || exit 1
    need_vm
    local pool=$LAB_POOL kd
    kd=$(keys_dir)
    if ! p2_dry; then
        [ -f "$kd/client.$name.keyring" ] || die "no key file for client.$name"
        # the image may be in a wrtest-* pool: find it
        local p
        for p in "$LAB_POOL" $(lab_wrtest_pools); do
            if vm sudo rbd info "$p/$name" >/dev/null 2>&1; then pool=$p; break; fi
        done
    fi
    vm_stdin sudo bash -s -- "$pool" "$name" <<'EOS'
set -euo pipefail
pool=$1 img=$2
tmp=$(mktemp -d /dev/shm/wr-krbd.XXXXXX)
chmod 700 "$tmp"
dev=""
cleanup() { [ -z "$dev" ] || rbd unmap "$dev" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
# the user's own key only (not the admin's): the keyring is written to a file in RAM and removed on exit
ceph auth get "client.$img" -o "$tmp/keyring" >/dev/null 2>&1
chmod 600 "$tmp/keyring"
kind=$(ceph auth get-key "client.$img" | base64 -d | wc -c)
if [ "$kind" = 28 ]; then
    echo "key type: aes (legacy, 16-byte secret)"
else
    echo "FAIL: the kernel client cannot use this key ($kind bytes decoded; 44 is aes256k, 28 is legacy aes); create the user with --key-type aes"
    exit 1
fi
dev=$(rbd map "$pool/$img" --id "$img" --keyring "$tmp/keyring")
echo "mapped $pool/$img as $dev with the user's own key"
size=$(blockdev --getsize64 "$dev")
dd if=/dev/urandom of="$tmp/p1" bs=1M count=1 status=none
dd if=/dev/urandom of="$tmp/p2" bs=1M count=1 status=none
last=$(( size / 1048576 - 1 ))
dd if="$tmp/p1" of="$dev" bs=1M count=1 seek=0 oflag=direct status=none
dd if="$tmp/p2" of="$dev" bs=1M count=1 seek="$last" oflag=direct conv=notrunc status=none
dd if="$dev" of="$tmp/r1" bs=1M count=1 skip=0 iflag=direct status=none
dd if="$dev" of="$tmp/r2" bs=1M count=1 skip="$last" iflag=direct status=none
if cmp "$tmp/p1" "$tmp/r1" && cmp "$tmp/p2" "$tmp/r2"; then
    echo "pattern written and read back through krbd: identical (first and last MiB)"
else
    echo "FAIL: the pattern read back through krbd differs"; exit 1
fi
# the same bytes through librbd (the admin tool reads the image, not the device)
# (a pipe returns short reads: iflag=fullblock; no pipefail because rbd export gets SIGPIPE when dd stops)
if ( set +o pipefail; rbd export "$pool/$img" - 2>/dev/null | dd bs=1M count=1 iflag=fullblock status=none | cmp - "$tmp/p1" ); then
    echo "rbd export (librbd) agrees with the device"
else
    echo "FAIL: rbd export differs from what krbd wrote"; exit 1
fi
rbd unmap "$dev"; dev=""
echo "unmapped"
# caps: the user must be refused in a pool it has no cap for
other=$(ceph osd pool ls | grep -v -x "$pool" | head -n 1 || true)
if [ -n "$other" ]; then
    # refused for the right reason: an error that is not a permission error (a timeout, a missing pool) proves nothing
    if err=$(rbd ls "$other" --id "$img" --keyring "$tmp/keyring" 2>&1 >/dev/null); then
        echo "FAIL: client.$img could list pool $other"; exit 1
    fi
    case "$err" in
        *"not permitted"*|*"Permission denied"*|*"EPERM"*|*"EACCES"*) echo "caps: pool $other refused for client.$img (as intended)";;
        *) echo "FAIL: listing pool $other failed, but not with a permission error: $(printf '%s' "$err" | head -n 1)"; exit 1;;
    esac
else
    echo "FAIL: no second pool to test the caps against"; exit 1
fi
EOS
}

main() {
    p2_init "$@"
    local cmd=${P2_ARGS[0]:-}
    [ -n "$cmd" ] || usage
    set -- "${P2_ARGS[@]:1}"
    p2_lock
    case "$cmd" in
        create)       cmd_create "$@";;
        delete)       cmd_delete "$@";;
        delete-all)   cmd_delete_all;;
        list)         cmd_list;;
        keyfile)      cmd_keyfile "$@";;
        krbd-check)   cmd_krbd_check "$@";;
        pool-create)  cmd_pool_create "$@";;
        pool-delete)  cmd_pool_delete "$@";;
        *) usage;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
