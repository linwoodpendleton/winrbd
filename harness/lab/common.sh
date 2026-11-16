# SPDX-License-Identifier: MIT
# Shared helpers for the winrbd lab scripts. Source it; do not execute it.

lab_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "[lab] $*" >&2; }

# Environment wins over the config file: remember what the caller exported.
lab_load_conf() {
    local conf="${LAB_CONF:-$lab_here/lab.conf}" k v saved=()
    while IFS='=' read -r k v; do
        case "$k" in LAB_*) saved+=("$k=$v");; esac
    done < <(env)
    if [ -f "$conf" ]; then
        # shellcheck disable=SC1090
        . "$conf"
    elif [ -n "${LAB_CONF:-}" ]; then
        die "LAB_CONF=$LAB_CONF does not exist"
    fi
    local kv
    for kv in "${saved[@]+"${saved[@]}"}"; do
        export "${kv%%=*}=${kv#*=}"
    done
}

lab_defaults() {
    : "${LAB_DIR:=${XDG_DATA_HOME:-$HOME/.local/share}/winrbd-lab}"
    : "${LAB_MIN_FREE_GB:=100}"
    : "${LAB_HOSTNAME:=winrbd-ceph1}"
    : "${LAB_SSH_USER:=lab}"
    : "${LAB_VCPUS:=8}"
    : "${LAB_MEM_MB:=16384}"
    : "${LAB_ROOT_GB:=60}"
    : "${LAB_OSD_COUNT:=3}"
    : "${LAB_OSD_GB:=25}"
    : "${LAB_DISK_CACHE:=none}"
    : "${LAB_NICE:=10}"
    : "${LAB_SSH_PORT:=22221}"
    : "${LAB_MCAST:=230.77.0.1:7701}"
    : "${LAB_MCAST_LOCALADDR:=127.0.0.1}"
    : "${LAB_PRIV_CIDR:=10.77.0.10/24}"
    : "${LAB_MAC_INET:=52:54:00:77:00:01}"
    : "${LAB_MAC_PRIV:=52:54:00:77:00:10}"
    : "${LAB_IMAGE_BASE_URL:=https://cloud-images.ubuntu.com/noble/current}"
    : "${LAB_IMAGE_NAME:=noble-server-cloudimg-amd64.img}"
    : "${LAB_APT_MIRROR:=}"
    : "${LAB_UNIT:=winrbd-lab-ceph}"
    : "${LAB_CEPH_RELEASE:=tentacle}"
    : "${LAB_CEPH_VERSION:=20.2.5}"
    : "${LAB_CEPH_IMAGE:=quay.io/ceph/ceph:v${LAB_CEPH_VERSION}}"
    : "${LAB_CEPH_APT_URL:=https://download.ceph.com/debian-${LAB_CEPH_RELEASE}}"
    : "${LAB_CEPH_KEY_URL:=https://download.ceph.com/keys/release.asc}"
    : "${LAB_POOL:=winrbd}"
    : "${LAB_CEPHX_ID:=winrbd}"
    : "${LAB_CEPHX_KRBD_ID:=${LAB_CEPHX_ID}-aes}"
    if [ -z "${LAB_RUNNER:-}" ]; then
        if [ "$(id -u)" = 0 ] && command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
            LAB_RUNNER=systemd
        else
            LAB_RUNNER=daemon
        fi
    fi
    LAB_IP=${LAB_PRIV_CIDR%/*}
    LAB_VMDIR="$LAB_DIR/vm"
    LAB_IMGDIR="$LAB_DIR/images"
    LAB_FACTS="$LAB_DIR/facts"
}

# Refuse obviously dangerous LAB_DIR values: it must be an absolute path with
# at least three components (so never / or /root or /home/x by accident).
lab_check_dir() {
    case "$LAB_DIR" in /*) ;; *) die "LAB_DIR must be an absolute path (got '$LAB_DIR')";; esac
    local n
    n=$(printf '%s' "$LAB_DIR" | tr -cd '/' | wc -c)
    [ "$n" -ge 2 ] || die "LAB_DIR '$LAB_DIR' is too shallow; use a dedicated directory"
    case "$LAB_DIR" in *' '*|*'*'*|*'?'*) die "LAB_DIR must not contain spaces or glob characters";; esac
}

# Is the lab VM running? Succeeds when it is.
lab_running() {
    if [ -f "$LAB_VMDIR/qemu.pid" ]; then
        local pid
        pid=$(cat "$LAB_VMDIR/qemu.pid" 2>/dev/null || true)
        if [ -n "$pid" ] && [ -d "/proc/$pid" ] && grep -q "$LAB_VMDIR" "/proc/$pid/cmdline" 2>/dev/null; then
            return 0
        fi
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$LAB_UNIT" 2>/dev/null; then
        return 0
    fi
    return 1
}

lab_init() {
    lab_load_conf
    lab_defaults
    lab_check_dir
}

# Remote-shell helper (used by the host-side convenience commands).
lab_ssh_opts() {
    echo "-o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$LAB_DIR/known_hosts -o BatchMode=yes"
}
