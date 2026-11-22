#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# secure-tamper.sh: milestone 11 on the live lab, the "frame damaged on the wire" half. The winrbd core runs in its own network namespace; every
# connection it makes to the lab's monitor and OSDs goes through harness/lab/secure_tamper_proxy.py, which flips ONE bit of ONE direction of ONE
# connection at a chosen byte of the stream. The run shows what the design (docs/design/core-architecture.md 39.2) promises, against the real daemons:
#
#   control        secure, nothing damaged: the data is right, every connection is secure
#   osd-s2c        secure, a bit of the OSD's read reply damaged: the core's tag check refuses the frame (sec_failures=1), no plaintext of that frame is
#                  used, the connection is redialled and the read gives the right data
#   osd-c2s        secure, a bit of the core's write damaged: the OSD refuses it and drops the connection, the core redials and resends, and a clean
#                  read-back of the whole range shows exactly the pattern
#   mon-s2c        secure, a bit of the monitor's stream (after the handshake) damaged: the core's session to the monitor is refused and redialled, the
#                  image I/O goes on
#   hs-s2c         secure, a bit of the OSD's handshake (the AUTH_DONE side) damaged: that connection fails, the next one goes through
#   crc-s2c        crc, a bit of the OSD's read reply damaged: the core's crc check refuses it, the same recovery (the contrast to osd-s2c)
#   wire           the same 2 MiB of the byte 0x2a written and read in crc and in secure mode: the pattern is seen on the wire of the crc run and not
#                  in the secure one (an independent look from the relay, next to the tcpdump check of secure-live.sh)
#
# What is guaranteed (the EXIT trap, also on a failing step, Ctrl-C and kill): the relay is stopped, the namespace and its veth pair are removed,
# the image and the throwaway cephx user (client.wrtest-st-*) are removed, the work files are deleted, and the cluster state (OSD tree and flags,
# upmaps, config database, pools, auth entities, health checks) is compared with the snapshot taken first. The cluster is never changed otherwise: no
# option is set, no daemon is restarted. Names are wrtest-st-*; nothing else is touched. Key material is never printed.
#
# Usage (inside the lab VM, as a user with passwordless sudo, with ip, iptables, python3, ceph, rbd):
#   harness/lab/secure-tamper.sh [--only a,b,..] [--keep] [--outdir DIR]
#   environment: WR_BUILD_DIR (default <repo>/build/harness: wr-rbd), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd), WR_LAB_WORK (~/w/tamper-run)
#
# Exit status: 0 every check passed and the lab is as it was; 1 a check failed or the state differs; 2 setup problem.

set -u
set -o pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
build=${WR_BUILD_DIR:-$repo/build/harness}
WR=${WR_RBD:-$build/wr-rbd}
PROXY=$here/secure_tamper_proxy.py
MON=${WR_LAB_MON:-10.77.0.10:3300}
MON_IP=${MON%%:*}
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/tamper-run}
TAG=$$
NSNAME=wrtamper$TAG
VETH_H=wrt${TAG: -5}h
VETH_C=wrt${TAG: -5}c
NET_H=192.0.2.211
NET_C=192.0.2.212
NS="sudo -n ip netns exec $NSNAME"
MARK=119
LPORT=7777
USER_ID=wrtest-st-$TAG
IMG=wrtest-st-$TAG
only=""; keep=0; outdir=""
fails=0

die()  { echo "secure-tamper: error: $*" >&2; exit 2; }
info() { echo "secure-tamper: $*" >&2; }
ok()   { echo "PASS  $*"; }
bad()  { echo "FAIL  $*"; fails=$((fails + 1)); }

while [ $# -gt 0 ]; do
    case "$1" in
        --only) only=${2:-}; shift ;;
        --keep) keep=1 ;;
        --outdir) outdir=${2:-}; shift ;;
        -h|--help) sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
want() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0 ;; esac; return 1; }

for t in ip iptables python3 ceph rbd; do command -v "$t" >/dev/null 2>&1 || die "$t is needed"; done
[ -x "$WR" ] || die "wr-rbd not found at $WR (set WR_BUILD_DIR)"
sudo -n true 2>/dev/null || die "passwordless sudo is needed"
CEPH() { sudo -n ceph "$@"; }
RBD()  { sudo -n rbd "$@"; }

state_snapshot() { # <file>: what must be the same before and after
    {
        CEPH osd dump | grep -E '^(flags|pg_upmap|osd\.)' | sed -E 's/ up_from [0-9]+ up_thru [0-9]+ down_at [0-9]+ last_clean_interval \[[0-9,]+\]//; s/\[v2:[^ ]* [^ ]*//' | sort
        CEPH osd pool ls detail | sed -E 's/last_change [0-9]+//'
        CEPH config dump | sort
        CEPH auth ls 2>/dev/null | grep -E '^(client|osd|mon|mgr)\.' | sort
        RBD ls "$POOL" | grep -v '^wrtest-' | sort
        CEPH health detail -f json | python3 -c 'import sys,json;d=json.load(sys.stdin);print(sorted(d["checks"]), sorted(m["code"] for m in d.get("mutes",[])))'
    } 2>&1
}

mkdir -p "$WORK" && chmod 700 "$WORK" || die "cannot make $WORK"
[ -n "$outdir" ] && { mkdir -p "$outdir" || die "cannot make $outdir"; }
KR=$WORK/client.$USER_ID.keyring
state_snapshot > "$WORK/state.before" || die "cannot take the cluster state"

cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    stop_proxy
    sudo -n ip netns del "$NSNAME" >/dev/null 2>&1
    sudo -n ip link del "$VETH_H" >/dev/null 2>&1
    [ "$keep" -eq 1 ] || RBD rm "$POOL/$IMG" >/dev/null 2>&1
    CEPH auth del "client.$USER_ID" >/dev/null 2>&1
    if CEPH auth get "client.$USER_ID" >/dev/null 2>&1; then echo "FAIL  the throwaway user client.$USER_ID is still there" >&2; rc=1; fi
    if [ "$keep" -eq 0 ] && RBD info "$POOL/$IMG" >/dev/null 2>&1; then echo "FAIL  the image $IMG is still there" >&2; rc=1; fi
    # the state may need a moment to settle (health checks of the removals)
    local i=0
    while [ $i -lt 30 ]; do
        state_snapshot > "$WORK/state.after" 2>&1
        diff -q "$WORK/state.before" "$WORK/state.after" >/dev/null && break
        sleep 5; i=$((i + 1))
    done
    if diff -q "$WORK/state.before" "$WORK/state.after" >/dev/null; then
        echo "state: the lab matches the snapshot taken before"
    else
        echo "FAIL  the lab differs from the snapshot taken before:" >&2
        diff "$WORK/state.before" "$WORK/state.after" | head -20 >&2
        rc=1
    fi
    [ "$keep" -eq 1 ] || rm -rf "$WORK"
    [ "$rc" -eq 0 ] && [ "$fails" -gt 0 ] && rc=1
    info "finished with exit status $rc"
    exit "$rc"
}
trap cleanup EXIT INT TERM

# ---- the namespace, the redirect and the relay ---------------------------------------------------------------------------------------------------
sudo -n ip netns add "$NSNAME" || die "cannot create the namespace"
sudo -n ip link add "$VETH_H" type veth peer name "$VETH_C" || die "cannot create the veth pair"
sudo -n ip link set "$VETH_C" netns "$NSNAME"
sudo -n ip addr add "$NET_H/24" dev "$VETH_H"
sudo -n ip link set "$VETH_H" up
$NS ip addr add "$NET_C/24" dev "$VETH_C"
$NS ip link set "$VETH_C" up
$NS ip link set lo up
$NS ip route add default via "$NET_H"
# every connection to the lab's public network (monitor 3300 / 6789, OSDs 6800 and up) goes to the relay, except the relay's own (marked)
$NS iptables -t nat -A OUTPUT -p tcp -d "${MON_IP%.*}.0/24" -m mark ! --mark "$MARK" -j REDIRECT --to-ports "$LPORT" || die "cannot set the redirect"

PROXY_PID=""
start_proxy() { # <log> [proxy options]
    local log=$1; shift
    : > "$log"
    $NS python3 -I "$PROXY" --listen-port "$LPORT" --mark "$MARK" --log "$log" "$@" > "$WORK/proxy.out" 2>&1 &
    PROXY_PID=$!
    local i=0
    while [ $i -lt 50 ]; do grep -q '^ready' "$WORK/proxy.out" 2>/dev/null && return 0; sleep 0.1; i=$((i + 1)); done
    die "the relay did not start: $(cat "$WORK/proxy.out")"
}
stop_proxy() {
    [ -n "$PROXY_PID" ] || return 0
    sudo -n pkill -f "secure_tamper_proxy.py --listen-port $LPORT" >/dev/null 2>&1
    wait "$PROXY_PID" 2>/dev/null
    PROXY_PID=""
}

# the throwaway user and the image
(umask 077; CEPH auth get-or-create "client.$USER_ID" mon 'profile rbd' osd "profile rbd pool=$POOL" > "$KR" 2>/dev/null) && [ -s "$KR" ] || die "cannot create the throwaway user"
sudo -n chown root: "$KR"; sudo -n chmod 600 "$KR"
RBD create "$POOL/$IMG" --size 10M --image-feature layering >/dev/null 2>&1 || die "cannot create the image $IMG"

WRNS() { # <mode args> -- wr-rbd arguments: runs the tool in the namespace as root (the keyring is root's)
    $NS timeout 120 "$WR" --mon "$MON" --user "$USER_ID" --keyring "$KR" --pool "$POOL" --image "$IMG" "$@"
}
field() { # <key> <line>
    echo "$2" | tr ' ' '\n' | sed -n "s/^$1=//p" | head -1
}
statline() { grep -h ' stats ' | tail -1; }

run_case() { # <name> <proxy options...> -- <wr-rbd arguments...>: runs it, keeps the output in $WORK/<name>.out and the relay's log in $WORK/<name>.proxy
    local name=$1; shift
    local popts=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do popts+=("$1"); shift; done
    shift
    start_proxy "$WORK/$name.proxy" "${popts[@]}"
    WRNS "$@" > "$WORK/$name.out" 2> "$WORK/$name.err"
    LAST_RC=$?
    stop_proxy
    if [ -n "$outdir" ]; then cp "$WORK/$name.out" "$outdir/$name.out"; cp "$WORK/$name.proxy" "$outdir/$name.proxy"; fi
    LAST_STATS=$(statline < "$WORK/$name.out")
}
tampers() { grep -c '^[0-9.]* TAMPER' "$WORK/$1.proxy"; }
tamper_dst() { grep -h 'TAMPER' "$WORK/$1.proxy" | head -1 | sed -n 's/.* dst=\([^ ]*\) .*/\1/p'; }

echo "== secure-tamper: image $IMG, user client.$USER_ID, namespace $NSNAME"

# ---- the cases ----------------------------------------------------------------------------------------------------------------------------------
if want control; then
    run_case control -- --rw --mode secure --require-mode secure fill --pattern rand:5
    [ "$LAST_RC" = 0 ] && ok "control: a secure fill through the relay, exit 0 (every connection secure, no tag failure)  [$LAST_STATS]" || bad "control: fill exit $LAST_RC [$LAST_STATS]"
    run_case control2 -- --mode secure --require-mode secure verify --pattern rand:5
    [ "$LAST_RC" = 0 ] && ok "control: the secure read-back verifies the pattern" || bad "control: verify exit $LAST_RC"
fi

if want osd-s2c; then
    # the read of the whole 10 MiB: the first OSD connection that carries 200,000 bytes of replies gets one bit of its stream flipped
    run_case osd-s2c --dir s2c --offset 200000 --count 1 -- --mode secure verify --pattern rand:5
    t=$(tampers osd-s2c); sf=$(field sec_failures "$LAST_STATS"); cs=$(field conns_secure "$LAST_STATS"); cc=$(field conns_crc "$LAST_STATS")
    if [ "$t" = 1 ] && [ "$LAST_RC" = 0 ] && [ "${sf:-0}" -ge 1 ] && [ "${cc:-1}" = 0 ]; then
        ok "osd-s2c: a bit flipped at byte 200000 of a reply stream ($(tamper_dst osd-s2c)): the core refused the frame (sec_failures=$sf), redialled (conns_secure=$cs) and the verify of the whole range is exit 0"
    else
        bad "osd-s2c: tampers=$t exit=$LAST_RC [$LAST_STATS]"
    fi
fi

if want osd-c2s; then
    run_case osd-c2s --dir c2s --offset 200000 --count 1 -- --rw --mode secure fill --pattern rand:6
    t=$(tampers osd-c2s); cs=$(field conns_secure "$LAST_STATS"); cc=$(field conns_crc "$LAST_STATS")
    if [ "$t" = 1 ] && [ "$LAST_RC" = 0 ] && [ "${cc:-1}" = 0 ] && [ "${cs:-0}" -ge 3 ]; then
        ok "osd-c2s: a bit flipped at byte 200000 of the core's stream ($(tamper_dst osd-c2s)): the OSD dropped the connection, the core redialled (conns_secure=$cs) and the fill finished with exit 0"
    else
        bad "osd-c2s: tampers=$t exit=$LAST_RC [$LAST_STATS]"
    fi
    run_case osd-c2s-back -- --mode secure --require-mode secure verify --pattern rand:6
    [ "$LAST_RC" = 0 ] && ok "osd-c2s: a clean read-back of the whole image holds exactly the pattern that was written through the damaged connection" || bad "osd-c2s: read-back exit $LAST_RC [$LAST_STATS]"
fi

if want mon-s2c; then
    run_case mon-s2c --dir s2c --offset 3000 --only-port "${MON##*:}" --count 1 -- --mode secure verify --pattern rand:6
    t=$(tampers mon-s2c); sf=$(field sec_failures "$LAST_STATS"); cc=$(field conns_crc "$LAST_STATS")
    if [ "$t" = 1 ] && [ "$LAST_RC" = 0 ] && [ "${sf:-0}" -ge 1 ] && [ "${cc:-1}" = 0 ]; then
        ok "mon-s2c: a bit flipped at byte 3000 of the monitor's stream: the core refused the frame (sec_failures=$sf), took a new monitor session and the verify is exit 0"
    else
        bad "mon-s2c: tampers=$t exit=$LAST_RC [$LAST_STATS]"
    fi
fi

if want hs-s2c; then
    run_case hs-s2c --dir s2c --offset 120 --only-port "${MON##*:}" --count 1 -- --mode secure --timeout 60000 verify --pattern rand:6
    t=$(tampers hs-s2c)
    if [ "$t" = 1 ] && [ "$LAST_RC" = 0 ]; then
        ok "hs-s2c: a bit flipped at byte 120 of the monitor's handshake: that connection failed (not accepted), the next one went through, verify exit 0  [$LAST_STATS]"
    else
        bad "hs-s2c: tampers=$t exit=$LAST_RC [$LAST_STATS] $(tail -2 "$WORK/hs-s2c.err" | tr '\n' ' ')"
    fi
fi

if want crc-s2c; then
    run_case crc-s2c --dir s2c --offset 200000 --count 1 -- --mode crc --require-mode crc verify --pattern rand:6
    t=$(tampers crc-s2c); cs=$(field conns_secure "$LAST_STATS"); cc=$(field conns_crc "$LAST_STATS")
    if [ "$t" = 1 ] && [ "$LAST_RC" = 0 ] && [ "${cs:-1}" = 0 ]; then
        ok "crc-s2c: the same bit flip in crc mode ($(tamper_dst crc-s2c)) is refused by the crc, the core redialled (conns_crc=$cc) and the verify is exit 0"
    else
        bad "crc-s2c: tampers=$t exit=$LAST_RC [$LAST_STATS]"
    fi
fi

if want wire; then
    pat=$(printf '2a%.0s' $(seq 1 16))
    for m in crc secure; do
        run_case wire-$m --grep "$pat" -- --rw --mode $m --require-mode $m fill 0 2M --pattern byte:42
        rc1=$LAST_RC
        run_case wire-$m-read --grep "$pat" -- --mode $m --require-mode $m verify 0 2M --pattern byte:42
        rc2=$LAST_RC
        w=$(grep -h '^[0-9.]* END' "$WORK/wire-$m.proxy" "$WORK/wire-$m-read.proxy" | sed -n 's/.*c2s_pattern=\([0-9]*\) s2c_pattern=\([0-9]*\).*/\1 \2/p' | awk '{a += $1; b += $2} END {print a + 0, b + 0}')
        eval "wire_$m=\"\$w\""; eval "wire_rc_$m=\"\$rc1\$rc2\""
    done
    set -- $wire_crc; cw=$1; cr=$2
    set -- $wire_secure; sw=$1; sr=$2
    if [ "$wire_rc_crc" = 00 ] && [ "$wire_rc_secure" = 00 ] && [ "$cw" -ge 1 ] && [ "$cr" -ge 1 ] && [ "$sw" = 0 ] && [ "$sr" = 0 ]; then
        ok "wire: a 2 MiB pattern of 0x2a is on the wire in crc mode (written: $cw hits, read back: $cr) and nowhere on the wire in secure mode (written: $sw, read back: $sr)"
    else
        bad "wire: exits crc=$wire_rc_crc secure=$wire_rc_secure; pattern hits crc written/read=$cw/$cr secure written/read=$sw/$sr"
    fi
fi

echo "== secure-tamper: $fails failed check(s)"
exit 0
