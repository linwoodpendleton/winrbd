#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# osd_fault_lab.sh: the fault run of Phase 1 milestones 6 to 8 against the REAL lab cluster (docs/design/core-architecture.md
# 30.2 and 31.3): the core, through the wr-rbd tool, does random unaligned cross-object I/O on an RBD image while the cluster
# is hurt under it, and at the end every byte is compared twice: with the tool's own model, and with what the stock `rbd export`
# reads back. The faults, each one a map change or a lost connection that the core must survive with the same tid and no lost,
# doubled or reordered write:
#
#   kill     an OSD is stopped (aes256k key) or killed with SIGKILL (legacy aes key) and started again: the connection is cut,
#            the map marks it down and up again, every request in flight is resent
#   outin    an OSD is marked out and in again: the placement changes twice (data moves), requests resend to the new acting set
#   upmap    a pg-upmap entry puts another OSD first in the up set of every PG of the pool, then the entries are removed: every
#            primary moves and moves back with no OSD going down (a pure map change)
#   both     the three at once on one run: out/in, a kill and an upmap overlapping, so a resend lands on a map that changed twice
#
# Everything the script makes is named wrtest-ofl-* (images) and is removed again; the only changes to the cluster are the faults
# above and each is undone (daemons running, every OSD in, the upmap entries it added removed), also after an interrupted run.
# It never touches an image or pool it did not create. At the end the state of the cluster is compared with the state at the start
# (every OSD up and in, the same number of upmap entries, the same health text).
#
# Run it inside the lab VM (the monitor listens on the private network), after building the harness there:
#     cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Release && cmake --build build/harness -j
#     WR_BUILD_DIR=build/harness harness/tools/osd_fault_lab.sh
# Keep the keyrings OUTSIDE the repository (default ~/keys, mode 600, client.<user>.keyring); they are read by wr-rbd, never printed.
#
# Options:
#   --keys k2|k1|both      cephx key types (default both: client.winrbd aes256k, client.winrbd-aes legacy aes)
#   --only a,b,...         scenarios: kill outin upmap both (default all)
#   --ops N                operations per run (default 12000; --quick 6000); the run must outlast the first fault, else it fails
#   --cycles N             repeat each fault up to N times while the run is going (default 3): only the requests in flight at the
#                          moment of a map change or a cut connection are resent, so one cycle proves little
#   --quick                shorter runs
#   --keep                 do not remove the images at the end
#
# Environment: WR_BUILD_DIR (default <repo>/build/harness), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd),
# WR_LAB_KEYRING_DIR (~/keys), WR_LAB_USER_K2 (winrbd), WR_LAB_USER_K1 (winrbd-aes), WR_LAB_WORK (~/w/ofl-run), WR_LAB_SUDO (sudo).
#
# Exit status: 0 when every check passed, 1 when any failed, 2 for a setup problem.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
build=${WR_BUILD_DIR:-$repo/build/harness}
WR=$build/wr-rbd
MON=${WR_LAB_MON:-10.77.0.10:3300}
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/ofl-run}
SUDO=${WR_LAB_SUDO:-sudo}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
USER_K2=${WR_LAB_USER_K2:-winrbd}
USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
PFX=wrtest-ofl-

die()  { echo "osd_fault_lab: error: $*" >&2; exit 2; }
info() { echo "osd_fault_lab: $*" >&2; }

keys=both; only=""; ops=""; quick=0; keep=0; cycles_max=3
while [ $# -gt 0 ]; do
    case "$1" in
        --keys) keys=${2:-}; shift ;;
        --only) only=${2:-}; shift ;;
        --ops) ops=${2:-}; shift ;;
        --cycles) cycles_max=${2:-}; shift ;;
        --quick) quick=1 ;;
        --keep) keep=1 ;;
        -h|--help) sed -n '3,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
case "$keys" in k2|k1|both) ;; *) die "--keys takes k2, k1 or both" ;; esac
if [ -z "$ops" ]; then if [ "$quick" -eq 1 ]; then ops=6000; else ops=12000; fi; fi
case "$ops" in ''|*[!0-9]*) die "--ops takes a number" ;; esac
case "$cycles_max" in ''|*[!0-9]*|0) die "--cycles takes a number above 0" ;; esac
case "$WORK" in /*) ;; *) die "WR_LAB_WORK must be an absolute path" ;; esac
case "$WORK" in *' '*|*'*'*|*'?'*) die "WR_LAB_WORK must not contain spaces or glob characters" ;; esac

if [ -n "$only" ]; then # a typo must not turn into a run of nothing that "passes"
    for w in $(echo "$only" | tr ',' ' '); do
        case "$w" in kill|outin|upmap|both) ;; *) die "--only takes kill, outin, upmap, both (got '$w')" ;; esac
    done
fi

want() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0 ;; esac; return 1; }

[ -x "$WR" ] || die "$WR not found: build the harness first (see --help)"
command -v python3 >/dev/null || die "python3 is needed"
$SUDO -n true 2>/dev/null || die "passwordless sudo is needed for the stock CLI"
RBD()  { $SUDO rbd "$@"; }
CEPH() { $SUDO ceph "$@"; }

find_keyring() { # <user>
    local f
    for f in "$KEYDIR/client.$1.keyring" "$KEYDIR/ceph.client.$1.keyring"; do
        if [ -f "$f" ]; then echo "$f"; return 0; fi
    done
    return 1
}
KR_K2=$(find_keyring "$USER_K2") || KR_K2=""
KR_K1=$(find_keyring "$USER_K1") || KR_K1=""
for kr in "$KR_K2" "$KR_K1"; do
    [ -n "$kr" ] || continue
    [ -r "$kr" ] || die "keyring not readable: $kr"
    case "$(cd "$(dirname "$kr")" && pwd -P)/" in "$repo"/*) die "keyring $kr is inside the repository; keep keys outside it" ;; esac
done
case "$keys" in k2) KR_K1="" ;; k1) KR_K2="" ;; esac
[ -n "$KR_K2$KR_K1" ] || die "no keyring found (WR_LAB_KEYRING_DIR)"

first=${MON%%[, ;]*}; first=${first#\[}; first=${first#v2:}
mon_host=${first%:*}; mon_port=${first##*:}
[ "$mon_port" != "$first" ] || { mon_port=3300; mon_host=$first; }
timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$mon_host" "$mon_port" 2>/dev/null || die "cannot reach $mon_host:$mon_port: run this inside the lab VM"

# ---- reporting ------------------------------------------------------------------------------------------------------------------
PASS=0; FAIL=0; FAILED=(); OUT=""; RC=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); echo "FAIL  $*"; if [ -n "$OUT" ]; then printf '%s\n' "$OUT" | tail -n 6 | cut -c1-300 | sed 's/^/      | /'; fi; }
note() { echo "NOTE  $*"; }
sect() { echo; echo "=== $* ==="; }

mkdir -p "$WORK" && chmod 700 "$WORK"

# ---- the baseline: what "restored" means -----------------------------------------------------------------------------------------
health_snapshot() { # one comparable line
    echo "osd: $(CEPH osd stat 2>/dev/null | sed -n 's/^\([0-9]*\) osds: \([0-9]*\) up.*, \([0-9]*\) in.*/\1 osds \2 up \3 in/p') | upmaps: $(CEPH osd dump 2>/dev/null | grep -c '^pg_upmap') | health: $(CEPH health 2>/dev/null | sed 's/ (muted.*//' | tr '\n' ' ')"
}
BASE_STATE=$(health_snapshot)
# every PG active+clean: a scrub or a snapshot trim running at the moment is not a degraded PG (the first line of `ceph pg stat` lists
# the states as "N pgs: 30 active+clean, 3 active+clean+scrubbing; ..." and a bare match of "N active+clean;" refused such a moment)
pgs_clean() { # [text of ceph pg stat]
    printf '%s\n' "${1:-$(CEPH pg stat 2>/dev/null)}" | awk -F'[:;]' '
        /^[0-9]+ pgs:/ { n = split($2, a, ","); ok = 1
                         for (i = 1; i <= n; i++) if (a[i] !~ /^ *[0-9]+ active\+clean(\+(deep|scrubbing|snaptrim|snaptrim_wait))*$/) ok = 0
                         found = 1; exit ok ? 0 : 1 }
        END { if (!found) exit 1 }'
}
BASE_PGS=$(CEPH pg stat 2>/dev/null | sed -n 's/^\([0-9]* pgs\):.*/\1/p')
BASE_OSDS=$(CEPH osd stat 2>/dev/null | sed -n 's/^\([0-9]*\) osds.*/\1/p')
FSID=$(CEPH fsid)
[ -n "$BASE_OSDS" ] && [ -n "$FSID" ] || die "cannot read the cluster state (ceph osd stat / fsid)"
[ "$BASE_OSDS" -ge 3 ] || die "the faults need at least 3 OSDs (found $BASE_OSDS)"
info "baseline: $BASE_STATE"
info "baseline pgs: ${BASE_PGS:-unknown}"
# "restored" means "as it was": the faults only make sense on a cluster that starts whole, and the restore below puts every OSD back
# up and in, which would be a change (not a restore) on a cluster where an operator had stopped or marked one out on purpose
CEPH osd stat 2>/dev/null | grep -Eq "^$BASE_OSDS osds: $BASE_OSDS up.*, $BASE_OSDS in" || die "not every OSD is up and in at the start ($BASE_STATE): nothing is changed"
[ -n "$BASE_PGS" ] && pgs_clean || die "the placement groups are not all active+clean at the start (${BASE_PGS:-unknown}): nothing is changed"
info "baseline: every OSD up and in, every placement group active+clean"
# upmap entries that exist already (a balancer's, an operator's) are not ours: act_upmap leaves those PGs alone
PRE_UPMAP=" $(CEPH osd dump 2>/dev/null | sed -n 's/^pg_upmap\(_[a-z]*\)\{0,1\} \([0-9a-f.]*\) .*/\2/p' | tr '\n' ' ')"

osd_unit() { echo "ceph-$FSID@osd.$1.service"; }

wait_clean() { # <seconds>: all PGs active+clean and every OSD up and in again
    local t=${1:-300} i s o
    for ((i = 0; i < t; i += 3)); do
        s=$(CEPH pg stat 2>/dev/null); o=$(CEPH osd stat 2>/dev/null)
        if pgs_clean "$s" && printf '%s\n' "$o" | grep -Eq "^$BASE_OSDS osds: $BASE_OSDS up.*, $BASE_OSDS in"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

ensure_osds_running() {
    local n
    for ((n = 0; n < BASE_OSDS; n++)); do
        $SUDO systemctl is-active --quiet "$(osd_unit $n)" && continue
        note "osd.$n is not running: starting it"
        $SUDO systemctl reset-failed "$(osd_unit $n)" 2>/dev/null
        $SUDO systemctl start "$(osd_unit $n)"
    done
}

UPMAPPED=() # PGs this script gave an entry
remove_upmaps() {
    local pg
    for pg in ${UPMAPPED[@]+"${UPMAPPED[@]}"}; do CEPH osd rm-pg-upmap "$pg" >/dev/null 2>&1; done
    UPMAPPED=()
}

restore_cluster() { # daemons running, every OSD in, our upmap entries gone (also the trap's job after an interrupted fault)
    local n
    ensure_osds_running
    for ((n = 0; n < BASE_OSDS; n++)); do
        CEPH osd dump 2>/dev/null | grep -Eq "^osd\.$n (up|down) +out " && { note "osd.$n is out: marking it in"; CEPH osd in "$n" >/dev/null 2>&1; }
    done
    remove_upmaps
}

IMAGES=()
remove_images() {
    local i
    [ "$keep" -eq 0 ] || return 0
    for i in ${IMAGES[@]+"${IMAGES[@]}"}; do
        case "$i" in "$PFX"*) RBD rm "$POOL/$i" >/dev/null 2>&1 ;; esac # only what this script made
    done
    IMAGES=()
}

RUN_PID=""
cleanup() {
    local rc=$?
    if [ -n "${RUN_PID:-}" ]; then kill "$RUN_PID" 2>/dev/null; fi
    restore_cluster
    remove_images
    return $rc
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# ---- the faults -----------------------------------------------------------------------------------------------------------------
FAULT_OSD=1
act_kill() { # k2: stop and start (a clean departure); k1: SIGKILL (the connection dies with no goodbye)
    local i
    if [ "$CUR_LABEL" = k2 ]; then
        note "stopping osd.$FAULT_OSD for 12 s"
        $SUDO systemctl stop "$(osd_unit $FAULT_OSD)"; sleep 12; $SUDO systemctl start "$(osd_unit $FAULT_OSD)"
    else
        note "killing osd.$FAULT_OSD with SIGKILL (systemd starts it again; the script does after 30 s if not)"
        $SUDO pkill -9 -f "/usr/bin/ceph-osd -n osd\\.${FAULT_OSD} " || note "no ceph-osd process found for osd.$FAULT_OSD"
        for ((i = 0; i < 15; i++)); do
            sleep 2
            [ "$i" -ge 3 ] && $SUDO systemctl is-active --quiet "$(osd_unit $FAULT_OSD)" && break
        done
        $SUDO systemctl is-active --quiet "$(osd_unit $FAULT_OSD)" || { $SUDO systemctl reset-failed "$(osd_unit $FAULT_OSD)" 2>/dev/null; $SUDO systemctl start "$(osd_unit $FAULT_OSD)"; }
    fi
    note "osd.$FAULT_OSD is back"
}
act_outin() {
    note "marking osd.$FAULT_OSD out for 14 s"
    CEPH osd out "$FAULT_OSD" >/dev/null 2>&1; sleep 14; CEPH osd in "$FAULT_OSD" >/dev/null 2>&1
    note "osd.$FAULT_OSD marked in again"
}
# pg-upmap: every PG of the pool gets an up set that is the current one rotated by one, so every primary changes and nothing goes down; the
# entries are removed again after a pause (a second map change that moves the primaries back). Only PGs whose up set has more than one member
# get an entry.
act_upmap() {
    local n=0 pg rot line
    while read -r line; do
        pg=${line%% *}; rot=${line#* }
        [ -n "$pg" ] && [ "$rot" != "$line" ] && [ -n "$rot" ] || continue
        case "$PRE_UPMAP" in *" $pg "*) continue ;; esac # not ours: never overwrite, never remove
        # shellcheck disable=SC2086
        if CEPH osd pg-upmap "$pg" $rot </dev/null >/dev/null 2>&1; then UPMAPPED+=("$pg"); n=$((n + 1)); fi
    done < <(CEPH pg ls-by-pool "$POOL" -f json 2>/dev/null | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
for s in (d.get("pg_stats", []) if isinstance(d, dict) else d):
    up = s.get("up", [])
    if len(up) > 1:
        print(s["pgid"], " ".join(str(x) for x in up[1:] + up[:1]))' 2>/dev/null)
    note "$n PGs have an upmap entry (every primary moved)"
    [ "$n" -gt 0 ] || note "no upmap entry could be made (nothing was changed)"
    sleep 8
    remove_upmaps
    sleep 4
}
act_both() { # overlapping: out/in on one OSD, a kill of another one, upmaps meanwhile
    local save=$FAULT_OSD
    (FAULT_OSD=$(( (save + 1) % BASE_OSDS )); act_outin) &
    local p1=$!
    sleep 5
    act_kill
    act_upmap
    wait "$p1"
}

# ---- one run ---------------------------------------------------------------------------------------------------------------------
CUR_LABEL=""; CUR_USER=""; CUR_KR=""; IMG=""
TOTAL_RUNS=0; TOTAL_DIFF=0

fault_run() { # <label> <seed> <action function> [args of the action]
    local lbl=$1 seed=$2 act=$3 log="$WORK/run.log" model="$WORK/model.bin" exp="$WORK/export.bin" n diff mism
    shift 3
    rm -f "$model" "$exp"
    timeout 1800 "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$IMG" --rw --depth 8 --overlap \
        --delay-ms 5 --op-timeout 8000 --model-bytes 64M random "$ops" "$seed" --save "$model" > "$log" 2>&1 &
    RUN_PID=$!
    local t0=$SECONDS t_fault t_end still=1 cycles=0
    sleep 6
    # the fault is repeated (up to $cycles_max times, with a pause between) for as long as the run is still going: a map change or a
    # cut connection only hurts the requests that are in flight at that moment, so one cycle on a fast run resends one or two
    while [ "$cycles" -lt "$cycles_max" ] && kill -0 "$RUN_PID" 2>/dev/null; do
        "$act" "$@"
        cycles=$((cycles + 1))
        if [ "$cycles" -eq 1 ]; then
            # the first cycle only counts when the run was still doing I/O after it: a run that ended first proved nothing
            kill -0 "$RUN_PID" 2>/dev/null || still=0
            t_fault=$((SECONDS - t0))
        fi
        sleep 3
    done
    wait "$RUN_PID"; RC=$?; RUN_PID=""
    OUT=$(cat "$log")
    t_end=$((SECONDS - t0))
    note "$lbl: $cycles fault cycle(s); the first ended ${t_fault:-0} s into the run, the run ended at $t_end s"
    if [ "$cycles" -ge 1 ] && [ "$still" -eq 1 ]; then ok "$lbl: the run was still doing I/O when the first fault ended"; else bad "$lbl: the run ended before the fault did (raise --ops)"; fi
    TOTAL_RUNS=$((TOTAL_RUNS + 1))
    if [ "$RC" -eq 0 ]; then ok "$lbl: the random run finished (exit code of wr-rbd)"; else bad "$lbl: wr-rbd exit code $RC"; fi
    if printf '%s\n' "$OUT" | grep -Eq 'result random ok=1 .* read_mismatches=0 final_diff_bytes=0 errors=0'; then
        ok "$lbl: zero differences against the model"
    else
        bad "$lbl: the model and the image differ"
    fi
    diff=$(printf '%s\n' "$OUT" | sed -n 's/.* final_diff_bytes=\([0-9]*\).*/\1/p' | tail -n 1)
    mism=$(printf '%s\n' "$OUT" | sed -n 's/.* read_mismatches=\([0-9]*\).*/\1/p' | tail -n 1)
    TOTAL_DIFF=$((TOTAL_DIFF + ${diff:-1} + ${mism:-1}))
    echo "      $(printf '%s\n' "$OUT" | grep ' stats ' | sed 's/.* stats //' | cut -c1-300)"
    n=$(stat -c %s "$model" 2>/dev/null || echo 0)
    RBD export "$POOL/$IMG" - > "$exp" 2>/dev/null
    if [ "$n" -gt 0 ] && cmp -s -n "$n" "$model" "$exp"; then ok "$lbl: the stock export equals the model ($n bytes)"; else bad "$lbl: the stock export differs from the model"; fi
    rm -f "$log" "$model" "$exp"
    ensure_osds_running
    remove_upmaps
    if wait_clean 420; then ok "$lbl: the cluster is back to $BASE_OSDS up, $BASE_OSDS in and active+clean"; else bad "$lbl: the cluster did not return to a clean state within 7 minutes: $(CEPH pg stat 2>/dev/null)"; fi
}

make_image() { # <name>: features 0x1 (the writer profile), 64 MiB, 256 KiB objects: many objects over the PGs
    IMG=$1
    case "$IMG" in "$PFX"*) ;; *) die "image name must start with $PFX" ;; esac
    RBD info "$POOL/$IMG" >/dev/null 2>&1 && die "$POOL/$IMG exists already (an earlier run: rbd rm it)"
    RBD create "$POOL/$IMG" --size 64M --object-size 256K --image-feature layering >/dev/null 2>&1 || die "cannot create $POOL/$IMG"
    IMAGES+=("$IMG")
}

run_key() { # <label> <user> <keyring> <seed base>
    CUR_LABEL=$1; CUR_USER=$2; CUR_KR=$3
    local base=$4 osd_a osd_b
    osd_a=$([ "$CUR_LABEL" = k2 ] && echo 1 || echo 2)
    osd_b=$([ "$CUR_LABEL" = k2 ] && echo 0 || echo 1)
    make_image "${PFX}${CUR_LABEL}"
    if want kill; then sect "an OSD stopped or killed under I/O ($CUR_LABEL)"; FAULT_OSD=$osd_a; fault_run "kill osd.$osd_a ($CUR_LABEL)" $((base + 1)) act_kill; fi
    if want outin; then sect "an OSD marked out and in under I/O ($CUR_LABEL)"; FAULT_OSD=$osd_b; fault_run "out/in osd.$osd_b ($CUR_LABEL)" $((base + 2)) act_outin; fi
    if want upmap; then sect "pg-upmap moves the primaries under I/O ($CUR_LABEL)"; fault_run "upmap ($CUR_LABEL)" $((base + 3)) act_upmap; fi
    if want both; then sect "out/in, a kill and upmaps overlapping ($CUR_LABEL)"; FAULT_OSD=$osd_a; fault_run "overlapping faults ($CUR_LABEL)" $((base + 4)) act_both; fi
    remove_images
}

if [ -n "$KR_K2" ]; then run_key k2 "$USER_K2" "$KR_K2" 700; fi
if [ -n "$KR_K1" ]; then run_key k1 "$USER_K1" "$KR_K1" 800; fi

# ---- the cluster is back where it started ----------------------------------------------------------------------------------------
sect "state of the cluster"
restore_cluster
wait_clean 300 >/dev/null
# cephadm keeps a killed daemon as "error" until its next refresh (the check "1 failed cephadm daemon(s)"): ask for one
for ((i = 0; i < 20; i++)); do
    END_STATE=$(health_snapshot)
    [ "$END_STATE" = "$BASE_STATE" ] && break
    CEPH orch ps --refresh >/dev/null 2>&1
    sleep 5
done
note "baseline: $BASE_STATE"
note "now:      $END_STATE"
if [ "$END_STATE" = "$BASE_STATE" ]; then ok "the cluster state equals the baseline (every OSD up and in, no upmaps added, the same health)"; else bad "the cluster state differs from the baseline"; fi
END_PGS=$(CEPH pg stat 2>/dev/null | sed -n 's/^\([0-9]* pgs\):.*/\1/p')
if [ "$END_PGS" = "$BASE_PGS" ] && pgs_clean; then ok "every placement group is active+clean ($END_PGS)"; else bad "pgs: was '$BASE_PGS' active+clean, now '$(CEPH pg stat 2>/dev/null)'"; fi
if [ "$keep" -eq 0 ]; then
    left=$(RBD ls "$POOL" 2>/dev/null | grep -c "^$PFX")
    if [ "${left:-0}" -eq 0 ]; then ok "no wrtest-ofl-* image is left"; else bad "$left wrtest-ofl-* image(s) left"; fi
fi

echo
[ "$TOTAL_RUNS" -gt 0 ] || bad "no run was made (nothing was checked)"
echo "osd_fault_lab: $TOTAL_RUNS runs, $PASS passed, $FAIL failed, differing bytes + read mismatches in total: $TOTAL_DIFF"
if [ "$FAIL" -ne 0 ]; then printf '  failed: %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
