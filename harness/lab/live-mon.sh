#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# live-mon.sh: run the winrbd core against the REAL lab monitor, once per cephx key type, with the
# wr-monprobe tool, and (optionally) the "lab" ctest. Read-only: it authenticates, receives the monitor
# maps and disconnects; it changes nothing on the cluster.
#
# Run it on a machine that can reach the monitor. In the lab that is the lab VM itself (the monitor
# listens on the private network 10.77.0.10, which the host does not route to):
#
#   rsync the repository to the VM, build the harness there:
#       cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Debug && cmake --build build/harness -j
#   keep the keyrings OUTSIDE the repository, mode 600 (for example ~/keys/), then:
#       WR_LAB_KEYRING_DIR=~/keys harness/lab/live-mon.sh
#
# Environment (all optional except the keyrings):
#   WR_BUILD_DIR          harness build directory (default: <repo>/build/harness)
#   WR_LAB_MON            monitor ip[:port]                      (default 10.77.0.10:3300)
#   WR_LAB_KEYRING_DIR    directory holding client.<user>.keyring or ceph.client.<user>.keyring
#   WR_LAB_USER_K2        user with the aes256k key              (default winrbd)
#   WR_LAB_KEYRING_K2     its keyring file (overrides the directory lookup)
#   WR_LAB_USER_K1        user with the legacy aes key           (default winrbd-aes)
#   WR_LAB_KEYRING_K1     its keyring file (overrides the directory lookup)
#   WR_LAB_FSID           cluster id; when unset it is read from /etc/ceph/ceph.conf if that is readable
#   WR_LAB_TIMEOUT_MS     per probe timeout                      (default 10000)
#
# Options: --ctest also runs the "lab" ctest (test_lab_mon) with the same settings.
#
# Key material is never printed by this script or by the tools it starts. Exit status: 0 when every key
# type reached an active session and saw both maps, non-zero otherwise.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)

die()  { echo "live-mon: error: $*" >&2; exit 2; }
info() { echo "live-mon: $*" >&2; }

run_ctest=0
for a in "$@"; do
    case "$a" in
        --ctest) run_ctest=1 ;;
        -h|--help) sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $a (try --help)" ;;
    esac
done

build=${WR_BUILD_DIR:-$repo/build/harness}
mon=${WR_LAB_MON:-10.77.0.10:3300}
user2=${WR_LAB_USER_K2:-winrbd}
user1=${WR_LAB_USER_K1:-winrbd-aes}
tmo=${WR_LAB_TIMEOUT_MS:-10000}
probe=$build/wr-monprobe

[ -x "$probe" ] || die "$probe not found; build the harness first (see --help)"

# Find the keyring file of a user: explicit variable first, then the directory (two usual names).
find_keyring() { # <explicit> <user>
    local explicit=$1 user=$2 d=${WR_LAB_KEYRING_DIR:-} f
    if [ -n "$explicit" ]; then echo "$explicit"; return 0; fi
    [ -n "$d" ] || return 1
    for f in "$d/client.$user.keyring" "$d/ceph.client.$user.keyring"; do
        if [ -f "$f" ]; then echo "$f"; return 0; fi
    done
    return 1
}

kr2=$(find_keyring "${WR_LAB_KEYRING_K2:-}" "$user2") || kr2=""
kr1=$(find_keyring "${WR_LAB_KEYRING_K1:-}" "$user1") || kr1=""
[ -n "$kr2$kr1" ] || die "no keyring found: set WR_LAB_KEYRING_DIR (a directory outside the repository) or WR_LAB_KEYRING_K2 / WR_LAB_KEYRING_K1"

# Keyrings are secrets: refuse the repository, warn about loose permissions (only the mode is looked at).
for kr in "$kr2" "$kr1"; do
    [ -n "$kr" ] || continue
    [ -r "$kr" ] || die "keyring not readable: $kr"
    case "$(cd "$(dirname "$kr")" && pwd -P)/" in
        "$repo"/*) die "keyring $kr is inside the repository; keep keys outside it" ;;
    esac
    mode=$(stat -c %a "$kr" 2>/dev/null || stat -f %Lp "$kr" 2>/dev/null || echo "")
    case "$mode" in
        ""|600|400) ;;
        *) info "warning: $kr has mode $mode, 600 is expected" ;;
    esac
done

fsid=${WR_LAB_FSID:-}
if [ -z "$fsid" ] && [ -r /etc/ceph/ceph.conf ]; then
    fsid=$(sed -n 's/^[[:space:]]*fsid[[:space:]]*=[[:space:]]*//p' /etc/ceph/ceph.conf | head -n 1 | tr -d '[:space:]')
fi
if [ -n "$fsid" ]; then info "cluster id pinned ($fsid)"; else info "cluster id not pinned (set WR_LAB_FSID to pin it)"; fi

# Reachability first, so the usual mistake (running on the host, not in the VM) gets a clear message.
# (first address of a list only; a dropped SYN must not hang the script, hence the timeout)
first=${mon%%[, ;]*}
first=${first#\[}
first=${first#v2:}
mon_host=${first%:*}
mon_port=${first##*:}
[ "$mon_port" != "$first" ] || { mon_port=3300; mon_host=$first; }
if ! timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$mon_host" "$mon_port" 2>/dev/null; then
    die "cannot open a TCP connection to $mon_host:$mon_port; run this inside the lab VM (winrbd-ceph1), the monitor is on its private network"
fi

fail=0
probe_one() { # <label> <user> <keyring>
    local label=$1 user=$2 kr=$3 out rc
    info "--- $label: client.$user"
    out=$("$probe" --mon "$mon" --user "$user" --keyring "$kr" --timeout "$tmo" ${fsid:+--fsid "$fsid"} 2>&1)
    rc=$?
    printf '%s\n' "$out"
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q ' result active=1 .* maps=11'; then
        info "$label: PASS"
    else
        info "$label: FAIL (exit $rc)"
        fail=1
    fi
}

[ -z "$kr2" ] || probe_one "aes256k key" "$user2" "$kr2"
[ -z "$kr1" ] || probe_one "legacy aes key" "$user1" "$kr1"

if [ "$run_ctest" -eq 1 ]; then
    info "--- ctest lab.mon"
    export WR_LAB_MON="$mon" WR_LAB_FSID="$fsid"
    [ -z "$kr2" ] || export WR_LAB_USER_K2="$user2" WR_LAB_KEYRING_K2="$kr2"
    [ -z "$kr1" ] || export WR_LAB_USER_K1="$user1" WR_LAB_KEYRING_K1="$kr1"
    ctest --test-dir "$build" -R '^lab\.mon$' --output-on-failure || fail=1
fi

if [ "$fail" -eq 0 ]; then info "all key types passed"; else info "FAILED"; fi
exit "$fail"
