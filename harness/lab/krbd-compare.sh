#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# krbd-compare.sh: the lab procedure of milestone 9 (docs/design/core-architecture.md 33.4). The winrbd core and the Linux kernel client (krbd) read
# and write the SAME image and are compared, byte for byte, against a model: harness/host/tools/wr-krbdcmp does the comparing, this script makes
# the images, maps them, runs the tool, checks the result with the stock tools and leaves the lab as it found it.
#
# Per case (one cephx key type of the core x one image order):
#   rbd create wrtest-kc-<pid>-<case> (features layering[,deep-flatten], object size 2^order, a size that is NOT a whole number of objects)
#   rbd map -n client.winrbd-aes --keyring <file> -o ms_mode=prefer-crc|secure,alloc_size=512 <pool>/<image>   (krbd only accepts the 16 byte "aes" key
#       of client.winrbd-aes, so it always authenticates as that user; the core uses either key; alloc_size=512 makes the kernel honour every
#       sector aligned discard, as --discard-gran 512 tells the tool)
#   wr-krbdcmp --phase all --dir all ... (edges, random, checkpoint scans, in every direction)
#   rbd export the image and `wr-rbd compare` it: the stock oracle, as in milestone 8 (with --mode secure it runs in secure mode too)
#   rbd unmap, rbd rm
# The cases of one key type run at the same time (--parallel, default 4: at most 8 images exist at once, the rule of the lab).
#
# What is guaranteed (the EXIT trap, also on a failing step, Ctrl-C and kill): every mapping this run made is unmapped, then every image it made is
# removed, the work files are deleted; dmesg is scanned for new libceph / rbd errors (a new one fails the run); the cluster state (health checks,
# the OSD tree, OSD flags, upmaps, the config database, the pools) is snapshotted before and compared after, and a difference fails the run.
# Names are wrtest-kc-*; nothing else is ever touched (never img-default, img-v1 or the pool itself). Key material is never printed.
#
# Usage (inside the lab VM, as a user with passwordless sudo):
#   harness/lab/krbd-compare.sh [--keys k2|k1|both] [--orders 12,16,22,25] [--mode crc|secure] [--hours H | --time SEC | --ops N]
#                               [--dir D] [--phase P] [--parallel N] [--checkpoint N] [--depth N] [--seed S] [--keep]
#   harness/lab/krbd-compare.sh --selftest [--live]      an injected failing step must still unmap, remove the images and match the snapshot
#
#   --keys      which cephx key types the CORE uses: k2 = client.winrbd (aes256k), k1 = client.winrbd-aes (legacy aes), both (default)
#   --orders    image orders (default 12,16,22,25; 18 and 20 are allowed too)
#   --hours H   time of the random phase of each case, per key type (default 1: edges, scans and the stock comparison come on top)
#   --time SEC  the same in seconds;  --ops N  an operation count instead of a time
#   --mode      crc (default) maps krbd with ms_mode=prefer-crc; secure maps it with ms_mode=secure and gives the core --mode secure --require-mode
#               secure, in the comparison tool AND in the final stock comparison (wr-rbd compare): a run in which any connection of the core fell back to
#               crc, in which none was made, or in which one secure connection ended on a tag / nonce / secret failure, fails (exit 5). The script also
#               reads conns_secure / conns_crc / sec_failures from the stats records of both runs itself (a tool that does not report them fails a secure
#               row) and prints them on the case's result line.
#   --small     16 MiB images (three objects at the big orders: order 25 gets 96 MiB) for the live selftest and quick looks
#   --keep      do not remove the images and the work directory at the end (the mappings are still undone)
#   --selftest  run this script against stand-in rbd / ceph / dmesg commands (no lab needed) with an injected failure at every step, and check that
#               the trap undid everything; with --live the same on the real lab with two tiny images (needs the lab and sudo)
#
# Environment: WR_BUILD_DIR (default <repo>/build/harness: wr-krbdcmp and wr-rbd are there), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd),
# WR_LAB_KEYRING_DIR (~/keys: client.<user>.keyring), WR_LAB_USER_K2 (winrbd), WR_LAB_USER_K1 (winrbd-aes), WR_LAB_WORK (~/w/krbdcmp-run),
# WR_LAB_SUDO (sudo), KC_HEALTH_IGNORE (health checks left out of the state comparison: slow-op alerts come and go with the load),
# KC_STATE_WAIT (seconds to wait for the state to settle before calling a difference, default 90), KC_COMPARE_RETRIES (default 2: the stock comparison is
# tried again when it only could not OPEN the image, wr-rbd exit 3, which happens when the lab stalls; a difference is never retried),
# KC_INJECT_FAIL=<step> and KC_NAME_TAG (selftest).
#
# Exit status: 0 every case passed and the lab is as it was; 1 a difference, a failed stock comparison, a new kernel error or a changed lab;
# 2 setup problem (usage, a missing tool or keyring); 3 a case could not run (create / map failed); 4 a request failed or hung in the tool;
# 5 (--mode secure) the data agreed but a connection of the core was not secure, or the counters that prove it were missing (a difference, 1, or a hang,
# 4, in another case outranks it).

set -u
set -o pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
SELF="$here/$(basename "${BASH_SOURCE[0]}")"

build=${WR_BUILD_DIR:-$repo/build/harness}
WRKC=${WR_KRBDCMP:-$build/wr-krbdcmp}
WRRBD=${WR_RBD:-$build/wr-rbd}
MON=${WR_LAB_MON:-10.77.0.10:3300}
POOL=${WR_LAB_POOL:-winrbd}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
USER_K2=${WR_LAB_USER_K2:-winrbd}
USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
KRBD_USER=$USER_K1
WORK=${WR_LAB_WORK:-$HOME/w/krbdcmp-run}
SUDO=${WR_LAB_SUDO:-sudo}
HEALTH_IGNORE=${KC_HEALTH_IGNORE:-BLUESTORE_SLOW_OP_ALERT,SLOW_OPS,PG_NOT_DEEP_SCRUBBED,PG_NOT_SCRUBBED,RECENT_CRASH}
STATE_WAIT=${KC_STATE_WAIT:-90}
INJECT=${KC_INJECT_FAIL:-}
CMP_RETRIES=${KC_COMPARE_RETRIES:-2}
CMP_RETRY_WAIT=${KC_COMPARE_RETRY_WAIT:-20}
NAME_TAG=${KC_NAME_TAG:-$$}   # images are named wrtest-kc-<tag>-<case>; the live selftest gives its runs a tag of their own

die()  { echo "krbd-compare: error: $*" >&2; exit 2; }
info() { echo "krbd-compare: $*" >&2; }
note() { echo "NOTE  $*"; }

keys=both; orders=12,16,22,25; mode=crc; hours=1; secs=""; ops=""; dir=all; phase=all; parallel=4; ckpt=5000; depth=8; seed=""
keep=0; selftest=0; live=0; small=0; stall_ms=180000
while [ $# -gt 0 ]; do
    case "$1" in
        --keys) keys=${2:-}; shift ;;
        --orders) orders=${2:-}; shift ;;
        --mode) mode=${2:-}; shift ;;
        --hours) hours=${2:-}; shift ;;
        --time) secs=${2:-}; shift ;;
        --ops) ops=${2:-}; shift ;;
        --dir) dir=${2:-}; shift ;;
        --phase) phase=${2:-}; shift ;;
        --parallel) parallel=${2:-}; shift ;;
        --checkpoint) ckpt=${2:-}; shift ;;
        --depth) depth=${2:-}; shift ;;
        --seed) seed=${2:-}; shift ;;
        --stall-ms) stall_ms=${2:-}; shift ;;
        --keep) keep=1 ;;
        --small) small=1 ;;
        --selftest) selftest=1 ;;
        --live) live=1 ;;
        --inject-fail) INJECT=${2:-}; shift ;;
        -h|--help) awk 'NR >= 3 { if ($0 !~ /^#/) exit; print }' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;   # the whole leading comment block (a fixed line count cut the exit statuses off)
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
case "$keys" in k2|k1|both) ;; *) die "--keys takes k2, k1 or both" ;; esac
case "$mode" in crc|secure) ;; *) die "--mode takes crc or secure" ;; esac
case "$dir" in core-to-krbd|krbd-to-core|interleave|all) ;; *) die "--dir takes core-to-krbd, krbd-to-core, interleave or all" ;; esac
case "$phase" in edges|random|scan|all) ;; *) die "--phase takes edges, random, scan or all" ;; esac
case "$parallel$ckpt$depth" in *[!0-9]*|'') die "--parallel, --checkpoint and --depth take numbers" ;; esac
[ "$parallel" -ge 1 ] && [ "$parallel" -le 8 ] || die "--parallel takes 1 to 8"
for o in ${orders//,/ }; do
    case "$o" in 12|16|18|20|22|25) ;; *) die "--orders takes 12, 16, 18, 20, 22 or 25 (got $o)" ;; esac
done
if [ -z "$secs" ] && [ -z "$ops" ]; then
    secs=$(awk -v h="$hours" 'BEGIN { if (h !~ /^[0-9]+(\.[0-9]+)?$/) exit 1; printf "%d", h * 3600 }') || die "--hours takes a number"
fi
[ -z "$secs" ] || case "$secs" in *[!0-9]*) die "--time takes seconds" ;; esac
[ -z "$ops" ] || case "$ops" in *[!0-9]*) die "--ops takes a number" ;; esac

# ---- the commands, as the rest of the script calls them (selftest puts stand-ins first in PATH) ----------------------------------------------
RBD()  { $SUDO rbd "$@"; }
CEPH() { $SUDO ceph "$@"; }
DMESG() { $SUDO dmesg 2>/dev/null; }

TRACK="$WORK/track"
FINAL_RC=0
CHILDREN=()

inject() { case ",$INJECT," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }   # KC_INJECT_FAIL is one step name or a comma separated list

# step <name> <command...>: run a command of a case; a step named by KC_INJECT_FAIL fails without running (what the selftest uses).
step() {
    local name=$1; shift
    if inject "$name"; then
        echo "krbd-compare: injected failure at step '$name'" >&2
        return 99
    fi
    "$@"
}

# ---- cluster state snapshot ------------------------------------------------------------------------------------------------------------------
state_snapshot() { # <outfile>
    local o=$1 t="$WORK/.state.$$"
    mkdir -p "$WORK"
    CEPH health detail -f json > "$t.health" 2>/dev/null || echo '{}' > "$t.health"
    CEPH osd tree -f json > "$t.tree" 2>/dev/null || echo '{}' > "$t.tree"
    CEPH osd dump -f json > "$t.dump" 2>/dev/null || echo '{}' > "$t.dump"
    CEPH config dump -f json > "$t.config" 2>/dev/null || echo '[]' > "$t.config"
    CEPH osd pool ls detail -f json > "$t.pools" 2>/dev/null || echo '[]' > "$t.pools"
    python3 - "$t" "$HEALTH_IGNORE" > "$o" <<'PY'
import json, sys
base, ignore = sys.argv[1], set(x for x in sys.argv[2].split(",") if x)
def load(name, default):
    try:
        with open(base + "." + name) as f:
            return json.load(f)
    except Exception:
        return default
out = []
h = load("health", {})
for code in sorted((h.get("checks") or {}).keys()):
    if code not in ignore:
        out.append("health.check %s" % code)
for n in sorted((load("tree", {}).get("nodes") or []), key=lambda n: n.get("id", 0)):
    if n.get("type") == "osd":
        out.append("osd %s status=%s reweight=%s primary_affinity=%s" % (n.get("name"), n.get("status"), n.get("reweight"), n.get("primary_affinity")))
d = load("dump", {})
out.append("osd.flags %s" % ",".join(sorted(d.get("flags_set") or [])))
for o in sorted((d.get("osds") or []), key=lambda o: o.get("osd", 0)):
    out.append("osd.%s up=%s in=%s weight=%s" % (o.get("osd"), o.get("up"), o.get("in"), o.get("weight")))
out.append("pg_upmap %s" % json.dumps(d.get("pg_upmap") or [], sort_keys=True))
out.append("pg_upmap_items %s" % json.dumps(d.get("pg_upmap_items") or [], sort_keys=True))
out.append("pg_upmap_primaries %s" % json.dumps(d.get("pg_upmap_primaries") or [], sort_keys=True))
for c in sorted(load("config", []), key=lambda c: (c.get("section", ""), c.get("mask", ""), c.get("name", ""))):
    out.append("config %s/%s/%s=%s" % (c.get("section"), c.get("mask"), c.get("name"), c.get("value")))
for p in sorted(load("pools", []), key=lambda p: p.get("pool_name", "")):
    out.append("pool %s size=%s min_size=%s rule=%s app=%s" % (p.get("pool_name"), p.get("size"), p.get("min_size"), p.get("crush_rule"),
               ",".join(sorted((p.get("application_metadata") or {}).keys()))))
print("\n".join(out))
PY
    rm -f "$t.health" "$t.tree" "$t.dump" "$t.config" "$t.pools"
}

# 0 = the lab is in the state of the snapshot (after waiting up to STATE_WAIT seconds for it to settle: health alerts clear with time)
state_compare() { # <before> <label>
    local before=$1 label=$2 waited=0 after="$WORK/state.$2"
    while :; do
        state_snapshot "$after"
        if diff -u "$before" "$after" > "$after.diff"; then
            echo "state: the lab matches the snapshot taken before ($label)"
            return 0
        fi
        [ "$waited" -ge "$STATE_WAIT" ] && break
        sleep 10
        waited=$((waited + 10))
    done
    echo "FAIL  the cluster state differs from the snapshot taken before the run:" >&2
    sed 's/^/      | /' "$after.diff" >&2
    return 1
}

# ---- dmesg ------------------------------------------------------------------------------------------------------------------------------------
DMESG_FAIL='(bad |corrupt|mismatch|signature|decrypt|error|fail|BUG|WARNING|Oops|hung|blocked for|timed out)'
dmesg_snapshot() { DMESG | grep -E 'libceph|rbd' | sed 's/^\[[ 0-9.]*\] //' | sort > "$1" || true; }
dmesg_check() { # <before-file> -> 0 when no new libceph / rbd error line appeared
    local after="$WORK/dmesg.after" new="$WORK/dmesg.new" bad=0
    dmesg_snapshot "$after"
    comm -13 "$1" "$after" > "$new" || true
    if [ -s "$new" ]; then
        if grep -Eiq "$DMESG_FAIL" "$new"; then
            echo "FAIL  new libceph / rbd errors in dmesg:" >&2
            grep -Ei "$DMESG_FAIL" "$new" | head -n 20 | sed 's/^/      | /' >&2
            bad=1
        fi
        grep -Eiv "$DMESG_FAIL" "$new" | head -n 10 | sed 's/^/NOTE  dmesg: /' || true
    fi
    return $bad
}

# ---- tracking: what this run made, so the trap can undo it ----------------------------------------------------------------------------------
track_image() { echo "$1" > "$TRACK/$2.image"; }
track_map()   { echo "$1" > "$TRACK/$2.map"; }
untrack()     { rm -f "$TRACK/$1.$2"; }

unmap_dev() { # <dev>: retry a few times; a device that is busy for a moment is common right after the tool ended
    local dev=$1 i
    for i in 1 2 3 4 5; do
        if RBD unmap "$dev" 2>/dev/null; then return 0; fi
        sleep 2
    done
    RBD unmap -o force "$dev" 2>/dev/null
}

cleanup_tracked() { # unmap every device first, then remove every image (the order matters: a mapped image cannot be removed)
    local f dev img rc=0
    shopt -s nullglob
    for f in "$TRACK"/*.map; do
        dev=$(cat "$f")
        if inject unmap-cleanup; then echo "FAIL  could not unmap $dev (injected failure)" >&2; rc=1; continue; fi
        if unmap_dev "$dev"; then rm -f "$f"; else echo "FAIL  could not unmap $dev" >&2; rc=1; fi
    done
    for f in "$TRACK"/*.image; do
        img=$(cat "$f")
        [ "$keep" = 1 ] && continue
        if RBD rm "$img" >/dev/null 2>&1 || ! RBD info "$img" >/dev/null 2>&1; then rm -f "$f"; else echo "FAIL  could not remove image $img" >&2; rc=1; fi
    done
    shopt -u nullglob
    return $rc
}

# ---- one case ----------------------------------------------------------------------------------------------------------------------------------
geometry() { # <order> -> IMG_BYTES FEATURES (sizes: a partial last object, a multiple of 512 except for the two odd-tail cases)
    local order=$1 obj base partial
    obj=$((1 << order))
    case "$order" in
        12) base=$((64 << 20)); FEATURES=layering ;;
        16) base=$((512 << 20)); FEATURES=layering,deep-flatten ;;
        18) base=$((1024 << 20)); FEATURES=layering ;;
        20) base=$((1024 << 20)); FEATURES=layering,deep-flatten ;;
        22) base=$((2048 << 20)); FEATURES=layering ;;
        *)  base=$((2048 << 20)); FEATURES=layering,deep-flatten ;;
    esac
    partial=$(( obj * 5 / 16 / 512 * 512 ))
    [ "$partial" -ge 512 ] || partial=512
    IMG_BYTES=$(( base - obj + partial ))
    if [ "$small" = 1 ]; then # 16 MiB, but never fewer than three objects (an order 25 object is 32 MiB: 16 MiB - obj would be negative)
        base=$((16 << 20)); [ "$base" -ge $((3 * obj)) ] || base=$((3 * obj))
        IMG_BYTES=$(( base - obj + partial ))
    fi
    case "$order" in 16|25) IMG_BYTES=$((IMG_BYTES + 100)) ;; esac   # an odd number of bytes past the last sector: krbd cannot show them, the core can
}

result_line() { # <label> <status> <text>
    printf 'CASE %s %s %s\n' "$1" "$2" "$3"
}

# conn_field <text> <key>: the value of key= on the last stats record of the text ("" when there is none)
conn_field() {
    printf '%s\n' "$1" | grep ' stats ' | tail -n 1 | sed -n "s/.* $2=\([0-9][0-9]*\).*/\1/p"
}

# mode_check <text>: the connection counters of the stats record of a run of the core, against the mode of this run. Sets MODE_SUM (what to print) and
# returns 0 when they are what the mode needs: secure = every connection secure, at least one, no secure-mode failure, and the counters reported at all.
# Of a crc run nothing is asked (the counters only show, when the tool has them).
MODE_SUM=""
mode_check() {
    local cs cc sf
    cs=$(conn_field "$1" conns_secure); cc=$(conn_field "$1" conns_crc); sf=$(conn_field "$1" sec_failures)
    if [ -z "$cs" ] || [ -z "$cc" ] || [ -z "$sf" ]; then
        MODE_SUM="conns not reported"
        [ "$mode" = secure ] && return 1
        MODE_SUM=""
        return 0
    fi
    MODE_SUM="conns_secure=$cs conns_crc=$cc sec_failures=$sf"
    if [ "$mode" = secure ]; then [ "$cc" -eq 0 ] && [ "$cs" -gt 0 ] && [ "$sf" -eq 0 ]; else return 0; fi
}

run_case() { # <label> <core-user> <core-keyring> <order> <index>
    local label=$1 user=$2 kr=$3 order=$4 idx=$5
    local img="wrtest-kc-$NAME_TAG-$label" dev="" log="$WORK/case-$label.log" rc=0 rc_cmp=0 map_opts tool_rc=0 res="" diff="" exp="$WORK/export-$label.img"
    local sums tmo maxlen cmp_try stock_bad=0 n0 n1 tool_txt cout="$WORK/compare-$label.out" tool_req=() cmp_mode=() mode_fail=0 tool_sum="" stock_sum=""
    # a secure row must PROVE it was secure: the tool and the stock comparison both get --require-mode secure (a crc row runs as it always did)
    if [ "$mode" = secure ]; then tool_req=(--require-mode secure); cmp_mode=(--mode secure --require-mode secure); fi
    exec 3>&2
    exec > "$log" 2>&1
    geometry "$order"
    echo "case $label: core key of $user, image $POOL/$img order $order size $IMG_BYTES bytes features $FEATURES mode $mode"
    track_image "$POOL/$img" "$label"
    if ! step create RBD create --size "${IMG_BYTES}B" --image-feature "$FEATURES" --object-size "$((1 << order))" "$POOL/$img"; then
        result_line "$label" FAIL "could not create the image"; echo 3 > "$WORK/case-$label.rc"; return 0
    fi
    map_opts="ms_mode=$([ "$mode" = crc ] && echo prefer-crc || echo secure),alloc_size=512"
    dev=$(step map RBD map -n "client.$KRBD_USER" --keyring "$KEYDIR/client.$KRBD_USER.keyring" -o "$map_opts" "$POOL/$img") || dev=""
    case "$dev" in /dev/*) ;; *) result_line "$label" FAIL "could not map the image (krbd: $KRBD_USER, -o $map_opts): $dev"; echo 3 > "$WORK/case-$label.rc"; return 0 ;; esac
    track_map "$dev" "$label"
    echo "mapped $dev"
    tmo=$(( ${secs:-3600} + 7200 ))
    if [ -n "$ops" ]; then tmo=7200; fi
    # operation lengths: 1.5 objects as the design says, but at least 256 KiB (an order 12 image should see operations across many objects too) and at most 8 MiB
    maxlen=$(( (1 << order) * 3 / 2 )); [ "$maxlen" -ge 262144 ] || maxlen=262144; [ "$maxlen" -le 8388608 ] || maxlen=8388608
    n0=$(wc -l < "$log")
    echo "tool: wr-krbdcmp --mon $MON --user $user --keyring <keyring of $user> --pool $POOL --image $img --dev $dev --dir $dir --phase $phase" \
         "${secs:+--time $secs} ${ops:+--ops $ops} --depth $depth --checkpoint $ckpt --max-len $maxlen --mem-max 512M --discard-gran 512 --stall-ms $stall_ms" \
         "--mode $mode${tool_req[*]:+ ${tool_req[*]}} --label $label --seed $((${seed:-$$} + idx))"
    if step tool $SUDO timeout --kill-after=60 "$tmo" "$WRKC" --mon "$MON" --user "$user" --keyring "$kr" --pool "$POOL" --image "$img" --dev "$dev" \
            --dir "$dir" --phase "$phase" ${secs:+--time "$secs"} ${ops:+--ops "$ops"} --depth "$depth" --checkpoint "$ckpt" --max-len "$maxlen" \
            --mem-max 512M --discard-gran 512 --stall-ms "$stall_ms" --mode "$mode" ${tool_req[@]+"${tool_req[@]}"} --label "$label" --seed "$((${seed:-$$} + idx))"; then tool_rc=0; else tool_rc=$?; fi
    n1=$(wc -l < "$log")
    tool_txt=$(sed -n "$((n0 + 1)),${n1}p" "$log")
    res=$(grep ' result ok=' "$log" | tail -n 1 || true)
    diff=$(grep ' diff dir=' "$log" | head -n 1 || true)
    # the connection counters of the tool's own stats record (--require-mode makes the tool itself fail; this reads them independently, so a tool that
    # does not report them cannot pass a secure row)
    mode_check "$tool_txt" || mode_fail=1
    tool_sum=$MODE_SUM
    if [ "$tool_rc" -ne 0 ]; then
        echo "tool exit status $tool_rc"
        $SUDO dmesg 2>/dev/null | grep -E 'libceph|rbd' | tail -n 30 | sed 's/^/dmesg: /'
        rc=$tool_rc
    elif [ "$mode_fail" -eq 1 ]; then
        echo "FAIL  secure row, but the tool's stats record does not show secure connections only ($tool_sum)"
        rc=5
    fi
    # the stock oracle, whatever the tool said: the image as the cluster holds it must equal the stock export read through the core (in secure mode
    # for a secure row: the same --mode, and --require-mode so that a silent fall back to crc cannot pass)
    if [ "$tool_rc" -eq 0 ] || [ "$tool_rc" -eq 1 ] || [ "$tool_rc" -eq 5 ]; then
        : > "$cout"
        if step export RBD export --no-progress "$POOL/$img" "$exp"; then
            cmp_try=0
            while :; do
                step compare "$WRRBD" --mon "$MON" --user "$user" --keyring "$kr" --pool "$POOL" --image "$img" ${cmp_mode[@]+"${cmp_mode[@]}"} compare "$exp" > "$cout" 2>&1
                rc_cmp=$?
                cat "$cout"
                [ "$rc_cmp" -ne 0 ] || break
                # --require-mode not met: wr-rbd says so with exit 3 and a record, which is not "could not open the image": no second try
                if [ "$rc_cmp" -eq 3 ] && grep -q ' result require_mode ok=0 ' "$cout"; then break; fi
                # exit 3 is "the image could not be opened" (the monitor was too slow to answer while the other cases were busy), not a data
                # difference: try again, twice at most. A difference (1) or any other status is final.
                if [ "$rc_cmp" -eq 3 ] && [ "$cmp_try" -lt "$CMP_RETRIES" ]; then
                    cmp_try=$((cmp_try + 1)); echo "stock comparison could not open the image (exit 3): trying again ($cmp_try of $CMP_RETRIES) in $CMP_RETRY_WAIT s"; sleep "$CMP_RETRY_WAIT"; continue
                fi
                break
            done
        else
            rc_cmp=$?; [ "$rc_cmp" -ne 0 ] || rc_cmp=1
        fi
        stock_bad=0
        if [ "$rc_cmp" -eq 0 ]; then
            mode_check "$(cat "$cout")" || stock_bad=1
            stock_sum=$MODE_SUM
        elif [ "$rc_cmp" -eq 3 ] && grep -q ' result require_mode ok=0 ' "$cout"; then
            stock_bad=1
            mode_check "$(cat "$cout")" || true
            stock_sum=$MODE_SUM
        fi
        if [ "$stock_bad" -eq 1 ]; then
            echo "FAIL  secure row, but the stock comparison's connections were not all secure ($stock_sum)"
            [ "$rc" -ne 0 ] || rc=5
        elif [ "$rc_cmp" -ne 0 ]; then
            echo "stock comparison failed (exit $rc_cmp)"
            # a difference found by the stock oracle outranks "a connection was not secure" (5): the data is the more serious finding
            if [ "$rc" -eq 0 ] || [ "$rc" -eq 5 ]; then rc=1; fi
        fi
    fi
    rm -f "$cout"
    rm -f "$exp"
    if [ -n "$dev" ]; then
        if step unmap unmap_dev "$dev"; then untrack "$label" map; else echo "could not unmap $dev: left to the trap"; [ "$rc" -ne 0 ] || rc=1; fi
    fi
    if [ ! -e "$TRACK/$label.map" ]; then
        if [ "$keep" = 1 ]; then :; elif step rm RBD rm "$POOL/$img"; then untrack "$label" image; else echo "could not remove the image: left to the trap"; [ "$rc" -ne 0 ] || rc=1; fi
    fi
    sums=""
    [ -z "$tool_sum" ] || sums=" [tool $tool_sum]"
    [ -z "$stock_sum" ] || sums="$sums [stock $stock_sum]"
    if [ "$rc" -eq 0 ]; then
        result_line "$label" PASS "${res#*result }$sums"
    else
        result_line "$label" FAIL "exit=$rc stock_compare=$rc_cmp ${res#*result }$sums"
        [ -z "$diff" ] || echo "DIFF $diff"
    fi
    echo "$rc" > "$WORK/case-$label.rc"
    echo "krbd-compare: case $label finished: exit $rc" >&3
    return 0
}

# ---- the run ----------------------------------------------------------------------------------------------------------------------------------
on_exit() {
    local rc=$? crc=0 sc=0 dc=0 f
    trap - EXIT INT TERM
    if [ "$FINAL_RC" -eq 0 ]; then FINAL_RC=$rc; fi
    for f in "${CHILDREN[@]+"${CHILDREN[@]}"}"; do kill "$f" 2>/dev/null; done
    wait 2>/dev/null
    # the tools of this run (they run as root and keep a device open: they must be gone before the unmap)
    $SUDO pkill -TERM -f -- "--image [w]rtest-kc-$NAME_TAG-" 2>/dev/null
    sleep 1
    $SUDO pkill -KILL -f -- "--image [w]rtest-kc-$NAME_TAG-" 2>/dev/null
    cleanup_tracked || crc=1
    if [ -e "$WORK/dmesg.before" ]; then dmesg_check "$WORK/dmesg.before" || dc=1; fi
    if [ -s "$WORK/state.before" ]; then state_compare "$WORK/state.before" after || sc=1; fi
    if [ "$crc" -ne 0 ] || [ "$sc" -ne 0 ] || [ "$dc" -ne 0 ]; then [ "$FINAL_RC" -ne 0 ] || FINAL_RC=1; fi
    if [ "$keep" != 1 ]; then rm -rf "$WORK/track" "$WORK"/export-*.img; fi
    echo "krbd-compare: finished with exit status $FINAL_RC (cleanup: $([ $crc = 0 ] && echo clean || echo FAILED); state: $([ $sc = 0 ] && echo as-before || echo CHANGED); dmesg: $([ $dc = 0 ] && echo quiet || echo ERRORS))"
    exit "$FINAL_RC"
}

main() {
    local k user kr order idx n=0 running=0 label j worst=0 f
    [ -x "$WRKC" ] || die "$WRKC not found: build the harness first (cmake --build, see harness/README.md) or set WR_BUILD_DIR"
    [ -x "$WRRBD" ] || die "$WRRBD not found: build the harness first or set WR_BUILD_DIR"
    command -v python3 >/dev/null || die "python3 is needed"
    command -v rbd >/dev/null || die "the rbd command is needed (run this inside the lab VM)"
    $SUDO -n true 2>/dev/null || die "passwordless sudo is needed (rbd map, dmesg, the tool on /dev/rbdN)"
    for k in "$USER_K1" "$USER_K2"; do :; done
    [ -r "$KEYDIR/client.$KRBD_USER.keyring" ] || die "no keyring for the krbd user: $KEYDIR/client.$KRBD_USER.keyring (keep keyrings outside the repository, mode 600)"
    case "$(cd "$KEYDIR" && pwd -P)/" in "$repo"/*) die "the keyring directory $KEYDIR is inside the repository; keep keys outside it" ;; esac
    mkdir -p "$WORK" "$TRACK" || die "cannot create $WORK"
    rm -f "$WORK"/case-*.rc "$WORK"/case-*.log
    trap on_exit EXIT
    trap 'FINAL_RC=2; exit 2' INT TERM
    info "snapshot of the cluster state and of dmesg"
    state_snapshot "$WORK/state.before"
    [ -s "$WORK/state.before" ] || die "cannot read the cluster state (ceph commands failed)"
    dmesg_snapshot "$WORK/dmesg.before"
    n=0
    for k in k2 k1; do
        case "$keys:$k" in both:*|k2:k2|k1:k1) ;; *) continue ;; esac
        if [ "$k" = k2 ]; then user=$USER_K2; else user=$USER_K1; fi
        kr="$KEYDIR/client.$user.keyring"
        [ -r "$kr" ] || { FINAL_RC=2; die "no keyring for $user: $kr"; }
        idx=0
        for order in ${orders//,/ }; do
            label="$k-o$order"; idx=$((idx + 1)); n=$((n + 1))
            info "case $label starting (core key $user)"
            run_case "$label" "$user" "$kr" "$order" "$n" &
            CHILDREN+=($!)
            running=$((running + 1))
            if [ "$running" -ge "$parallel" ]; then wait -n 2>/dev/null; running=$((running - 1)); fi
        done
        wait
        running=0
        CHILDREN=()
    done
    echo
    echo "==== summary ===="
    for f in "$WORK"/case-*.log; do
        [ -e "$f" ] || continue
        grep -h '^CASE ' "$f"
    done
    for f in "$WORK"/case-*.log; do
        [ -e "$f" ] || continue
        grep -h -E '^(DIFF |FAIL  secure row)' "$f"
    done
    for f in "$WORK"/case-*.rc; do
        [ -e "$f" ] || continue
        j=$(cat "$f")
        # the worst of the exit statuses: a difference (1) and a hang (4) outrank a case that could not run (3, or anything unexpected)
        # (5, a connection that was not secure, ranks below a difference and a hang and above a case that could not run)
        case "$j" in 0) ;; 1) [ "$worst" -eq 4 ] || worst=1 ;; 4) worst=4 ;; 5) [ "$worst" -eq 4 ] || [ "$worst" -eq 1 ] || worst=5 ;; *) [ "$worst" -ne 0 ] || worst=3 ;; esac
    done
    [ "$n" -gt 0 ] || worst=2
    FINAL_RC=$worst
    return 0
}

# ---- selftest ----------------------------------------------------------------------------------------------------------------------------------
# Stand-ins for rbd, ceph, dmesg, sudo, wr-krbdcmp and wr-rbd in a directory of their own. They keep their state in files: images/ (one file per
# image), maps/ (one per mapping), and the ceph JSON in ceph/. A test changes those files to make the lab "drift".
write_stubs() { # <dir>
    local d=$1
    mkdir -p "$d/bin" "$d/images" "$d/maps" "$d/ceph"
    cat > "$d/bin/sudo" <<'STUB'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in -n|-E|-S) shift ;; *) break ;; esac; done
exec "$@"
STUB
    cat > "$d/bin/rbd" <<'STUB'
#!/bin/bash
S=$KC_STUB
cmd=$1; shift
case "$cmd" in
    create) last=${@: -1}; img=${last#*/}; sz=""; prev=""; for a in "$@"; do [ "$prev" = --size ] && sz=$a; prev=$a; done
            case "$sz" in [1-9]*B) ;; *) echo "rbd: the argument for option '--size' is invalid" >&2; exit 22 ;; esac   # a size like the real rbd accepts
            [ -e "$S/images/$img" ] && { echo "exists" >&2; exit 17; }; echo "$last" > "$S/images/$img" ;;
    rm) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || { echo "no such image" >&2; exit 2; }
        for m in "$S"/maps/*; do [ -e "$m" ] && [ "$(cat "$m")" = "$img" ] && { echo "image is mapped" >&2; exit 16; }; done
        rm -f "$S/images/$img" ;;
    info) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || exit 2 ;;
    map) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || { echo "no such image" >&2; exit 2; }
         n=0; while ! ( set -o noclobber; echo "$img" > "$S/maps/rbd$n" ) 2>/dev/null; do n=$((n + 1)); done; echo "/dev/rbd$n" ;;
    unmap) while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; *) dev=$1; shift ;; esac; done
           n=${dev#/dev/rbd}; [ -e "$S/maps/rbd$n" ] || { echo "not mapped" >&2; exit 22; }; rm -f "$S/maps/rbd$n" ;;
    showmapped) for m in "$S"/maps/*; do [ -e "$m" ] && echo "$(basename "$m") $(cat "$m")"; done; exit 0 ;;
    ls) for i in "$S"/images/*; do [ -e "$i" ] && basename "$i"; done; exit 0 ;;
    export) src=${@: -2:1}; dst=${@: -1}; : > "$dst" ;;
    *) echo "stub rbd: unsupported: $cmd $*" >&2; exit 1 ;;
esac
STUB
    cat > "$d/bin/ceph" <<'STUB'
#!/bin/bash
S=$KC_STUB
case "$*" in
    "health detail -f json") cat "$S/ceph/health.json" ;;
    "osd tree -f json") cat "$S/ceph/tree.json" ;;
    "osd dump -f json") cat "$S/ceph/dump.json" ;;
    "config dump -f json") cat "$S/ceph/config.json" ;;
    "osd pool ls detail -f json") cat "$S/ceph/pools.json" ;;
    *) echo "stub ceph: unsupported: $*" >&2; exit 1 ;;
esac
STUB
    cat > "$d/bin/dmesg" <<'STUB'
#!/bin/bash
cat "$KC_STUB/dmesg.txt"
STUB
    cat > "$d/bin/wr-krbdcmp" <<'STUB'
#!/bin/bash
# a tool that does nothing: it prints a stats and a result line and exits with what the test asked for. Its connection counters are those of its --mode
# (secure: 3 secure; crc: 3 crc) unless tool.conns ("<secure> <crc> <sec_failures>") says otherwise; tool.nofields leaves them out; with --require-mode it exits 5
# when they do not fit, unless tool.ignore_require is there (a tool that does not check: the script must catch it by itself)
mode=crc; req=""; echo "$*" >> "$KC_STUB/tool.args"
while [ $# -gt 0 ]; do case "$1" in --mode) mode=$2; shift ;; --require-mode) req=$2; shift ;; esac; shift; done
if [ "$mode" = secure ]; then s=3; c=0; else s=0; c=3; fi
f=0; [ ! -e "$KC_STUB/tool.conns" ] || read -r s c f < "$KC_STUB/tool.conns"
echo "@1 plan label=stub"
if [ -e "$KC_STUB/tool.nofields" ]; then echo "@2 stats ops_done=1 ops_resent=0 ops_failed=0 session_resets=0 ops_hiwater=1 reqs_hiwater=1 io_stalls=0 io_resumes=0 max_gap_ms=1 barrier_violations=0 bad_completions=0 model_chunks=0"
else echo "@2 stats ops_done=1 ops_resent=0 ops_failed=0 session_resets=0 ops_hiwater=1 reqs_hiwater=1 io_stalls=0 io_resumes=0 max_gap_ms=1 barrier_violations=0 bad_completions=0 model_chunks=0 conns_secure=$s conns_crc=$c sec_failures=$f"; fi
echo "@2 result ok=1 exit=0 diffs=0 transients=0 errors=0 verdict=none ops=1"
: > "$KC_STUB/tool.started"
if [ -n "$req" ] && [ ! -e "$KC_STUB/tool.ignore_require" ]; then
    case "$req" in
        secure) { [ "$c" = 0 ] && [ "$s" != 0 ] && [ "$f" = 0 ]; } || { echo "stub tool: --require-mode secure not met" >&2; exit 5; } ;;
        crc) { [ "$s" = 0 ] && [ "$c" != 0 ] && [ "$f" = 0 ]; } || { echo "stub tool: --require-mode crc not met" >&2; exit 5; } ;;
    esac
fi
# tool.hook: a command the test wants run while the "lab" is in use (a drift of the cluster, a kernel message): it runs when the tool does, which is
# after the script took its snapshots, however slow the machine is
[ -e "$KC_STUB/tool.hook" ] && bash "$KC_STUB/tool.hook"
[ -e "$KC_STUB/tool.sleep" ] && sleep "$(cat "$KC_STUB/tool.sleep")"
[ -e "$KC_STUB/tool.rc" ] && exit "$(cat "$KC_STUB/tool.rc")"
exit 0
STUB
    cat > "$d/bin/wr-rbd" <<'STUB'
#!/bin/bash
# compare.rc: the exit status; compare.fail_first N: fail with 3 (cannot open) the first N calls of each image, then succeed. Its stats record has the connection
# counters of its --mode (like the tool stand-in; compare.conns "<secure> <crc> <sec_failures>" overrides them); with --require-mode it prints the result record and
# exits 3 when they do not fit (compare.ignore_require: it does not check)
echo x >> "$KC_STUB/compare.calls"
echo "$*" >> "$KC_STUB/compare.args"
mode=crc; req=""; prev=""
for a in "$@"; do case "$prev" in --mode) mode=$a ;; --require-mode) req=$a ;; esac; prev=$a; done
if [ "$mode" = secure ]; then s=3; c=0; else s=0; c=3; fi
f=0; [ ! -e "$KC_STUB/compare.conns" ] || read -r s c f < "$KC_STUB/compare.conns"
echo "@5 stats ops_inflight=0 ops_hiwater=1 conns_secure=$s conns_crc=$c sec_failures=$f accel=0 gcm=portable gcm_ops=0"
if [ -n "$req" ] && [ ! -e "$KC_STUB/compare.ignore_require" ]; then
    ok=0
    case "$req" in
        secure) { [ "$c" = 0 ] && [ "$s" != 0 ] && [ "$f" = 0 ]; } && ok=1 ;;
        crc) { [ "$s" = 0 ] && [ "$c" != 0 ] && [ "$f" = 0 ]; } && ok=1 ;;
    esac
    echo "@6 result require_mode ok=$ok wanted=$req conns_secure=$s conns_crc=$c sec_failures=$f"
    [ "$ok" = 1 ] || exit 3
fi
if [ -e "$KC_STUB/compare.fail_first" ]; then
    img=""; while [ $# -gt 0 ]; do [ "$1" = --image ] && img=$2; shift; done
    n=$(grep -c "^$img\$" "$KC_STUB/compare.seen" 2>/dev/null); echo "$img" >> "$KC_STUB/compare.seen"
    [ "${n:-0}" -lt "$(cat "$KC_STUB/compare.fail_first")" ] && exit 3
    exit 0
fi
[ -e "$KC_STUB/compare.rc" ] && exit "$(cat "$KC_STUB/compare.rc")"
exit 0
STUB
    cat > "$d/ceph/health.json" <<'STUB'
{"status":"HEALTH_WARN","checks":{"AUTH_INSECURE_KEYS_ALLOWED":{"severity":"HEALTH_WARN"},"BLUESTORE_SLOW_OP_ALERT":{"severity":"HEALTH_WARN"}}}
STUB
    cat > "$d/ceph/tree.json" <<'STUB'
{"nodes":[{"id":-1,"name":"default","type":"root"},{"id":0,"name":"osd.0","type":"osd","status":"up","reweight":1,"primary_affinity":1},{"id":1,"name":"osd.1","type":"osd","status":"up","reweight":1,"primary_affinity":1}]}
STUB
    cat > "$d/ceph/dump.json" <<'STUB'
{"flags_set":["sortbitwise","recovery_deletes"],"osds":[{"osd":0,"up":1,"in":1,"weight":1},{"osd":1,"up":1,"in":1,"weight":1}],"pg_upmap":[],"pg_upmap_items":[],"pg_upmap_primaries":[]}
STUB
    cat > "$d/ceph/config.json" <<'STUB'
[{"section":"global","name":"osd_pool_default_size","value":"2","mask":""},{"section":"mon","name":"auth_allow_insecure_global_id_reclaim","value":"false","mask":""}]
STUB
    cat > "$d/ceph/pools.json" <<'STUB'
[{"pool_name":"winrbd","size":3,"min_size":2,"crush_rule":0,"application_metadata":{"rbd":{}}}]
STUB
    : > "$d/dmesg.txt"
    chmod +x "$d"/bin/*
}

selftest_expect() { # <what> <command...>
    local what=$1; shift
    if "$@"; then echo "  ok   $what"; else echo "  FAIL $what"; ST_FAILED=$((ST_FAILED + 1)); fi
}

selftest_stub() {
    local d st="" step steps rc ST_FAILED=0 out
    if [ "${BASH_VERSINFO[0]}" -lt 4 ] || [ "$(uname -s)" != Linux ] || ! command -v timeout >/dev/null || ! command -v pkill >/dev/null; then
        echo "SKIP: the selftest needs bash 4+, Linux, timeout and pkill"; return 77
    fi
    d=$(mktemp -d "${TMPDIR:-/tmp}/krbdcmp-selftest.XXXXXX") || die "mktemp failed"
    write_stubs "$d"
    # a keyring the script can find, outside any repository; the stand-ins never read it
    mkdir -p "$d/keys"; echo "[client.x]" > "$d/keys/client.$USER_K1.keyring"; cp "$d/keys/client.$USER_K1.keyring" "$d/keys/client.$USER_K2.keyring"
    chmod 600 "$d"/keys/*
    local env=(env "KC_STUB=$d" "PATH=$d/bin:$PATH" "WR_BUILD_DIR=$d/bin" "WR_KRBDCMP=$d/bin/wr-krbdcmp" "WR_RBD=$d/bin/wr-rbd" "WR_LAB_KEYRING_DIR=$d/keys"
               "WR_LAB_WORK=$d/work" "WR_LAB_SUDO=sudo" "KC_STATE_WAIT=0")
    steps="create map tool export compare unmap rm"
    local base=(--keys both --orders 12,16 --time 1 --parallel 4)
    echo "selftest with stand-in rbd / ceph / dmesg in $d"
    # a clean run passes and leaves nothing behind
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "a clean run exits 0 ($rc)" test "$rc" -eq 0
    selftest_expect "a clean run: no image left" test -z "$(ls "$d/images")"
    selftest_expect "a clean run: no mapping left" test -z "$(ls "$d/maps")"
    selftest_expect "a clean run: four PASS lines" test "$(printf '%s\n' "$out" | grep -c '^CASE .* PASS ')" -eq 4
    # --help prints the whole header, down to the last exit status (a fixed line count once cut the exit 5 paragraph off)
    selftest_expect "--help shows the exit 5 paragraph" bash -c '"$1" --help | grep -q "^5 (--mode secure) the data agreed"' _ "$SELF"
    # a secure row: the tool AND the stock comparison are asked for --mode secure --require-mode secure (a crc row is asked for neither), and the case lines
    # carry the connection counters of both runs
    rm -f "$d/tool.args" "$d/compare.args"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure: a clean run exits 0 ($rc)" test "$rc" -eq 0
    selftest_expect "secure: every tool call has --mode secure --require-mode secure" test "$(grep -c -- '--mode secure --require-mode secure --label' "$d/tool.args")" -eq 4
    selftest_expect "secure: every stock comparison has --mode secure --require-mode secure" test "$(grep -c -- '--mode secure --require-mode secure compare' "$d/compare.args")" -eq 4
    selftest_expect "secure: the four PASS lines show the counters of the tool and of the stock comparison" \
        test "$(printf '%s\n' "$out" | grep -c '^CASE .* PASS .*\[tool conns_secure=3 conns_crc=0 sec_failures=0\] \[stock conns_secure=3 conns_crc=0 sec_failures=0\]')" -eq 4
    selftest_expect "secure: nothing left over" test -z "$(ls "$d/images"; ls "$d/maps")"
    rm -f "$d/tool.args" "$d/compare.args"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "crc: a clean run exits 0 ($rc)" test "$rc" -eq 0
    selftest_expect "crc: neither the tool nor the stock comparison is given --require-mode" bash -c '! grep -q -- "--require-mode" "$1/tool.args" "$1/compare.args"' _ "$d"
    selftest_expect "crc: the PASS lines show the counters, as crc" test "$(printf '%s\n' "$out" | grep -c '^CASE .* PASS .*\[tool conns_secure=0 conns_crc=3 sec_failures=0\]')" -eq 4
    # a secure row that was not secure: one connection fell back to crc (the tool checks: exit 5; a tool that does not check: the script reads the counters itself)
    echo "2 1 0" > "$d/tool.conns"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a tool that saw a crc connection and exits 5: the run exits 5 ($rc)" test "$rc" -eq 5
    selftest_expect "secure, exit 5: the cases say FAIL and the reason is in the summary" bash -c "printf '%s\n' \"\$1\" | grep -q '^CASE .* FAIL exit=5 '" _ "$out"
    selftest_expect "secure, exit 5: nothing left over" test -z "$(ls "$d/images"; ls "$d/maps")"
    : > "$d/tool.ignore_require"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a tool that does not check but reports a crc connection: the script's own check exits 5 ($rc)" test "$rc" -eq 5
    selftest_expect "secure, own check: the reason is printed" bash -c "printf '%s\n' \"\$1\" | grep -q 'FAIL  secure row, but the tool.s stats record'" _ "$out"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "crc row with the same counters: not judged by them, exit 0 ($rc)" test "$rc" -eq 0
    echo "3 0 1" > "$d/tool.conns"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a secure-mode failure counted (sec_failures=1): exit 5 ($rc)" test "$rc" -eq 5
    rm -f "$d/tool.conns" "$d/tool.ignore_require"
    : > "$d/tool.nofields"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a tool that does not report the counters: exit 5 ($rc)" test "$rc" -eq 5
    selftest_expect "secure, no counters: the line says so" bash -c "printf '%s\n' \"\$1\" | grep -q 'conns not reported'" _ "$out"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "crc, a tool that does not report the counters: exit 0 ($rc)" test "$rc" -eq 0
    rm -f "$d/tool.nofields"
    echo 5 > "$d/tool.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "the tool's exit 5 is the run's exit 5 ($rc)" test "$rc" -eq 5
    rm -f "$d/tool.rc"
    # exit 5 from the tool (or from the script's own check) and then a difference found by the stock comparison: the difference (1) wins
    echo "2 1 0" > "$d/tool.conns"; echo 1 > "$d/compare.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a crc connection AND a stock difference: exit 1, not 5 ($rc)" test "$rc" -eq 1
    : > "$d/tool.ignore_require"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, the script's own mode check AND a stock difference: exit 1, not 5 ($rc)" test "$rc" -eq 1
    rm -f "$d/tool.conns" "$d/tool.ignore_require" "$d/compare.rc"
    echo 1 > "$d/tool.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "a difference (1) outranks 5 ($rc)" test "$rc" -eq 1
    rm -f "$d/tool.rc"
    # the stock comparison fell back to crc: wr-rbd refuses (exit 3 + the record), which is NOT "could not open": no retry, exit 5; one that does not check is caught by the counters
    echo "1 2 0" > "$d/compare.conns"; rm -f "$d/compare.calls"
    out=$("${env[@]}" "KC_COMPARE_RETRIES=2" "KC_COMPARE_RETRY_WAIT=1" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a stock comparison that was not secure: exit 5 ($rc)" test "$rc" -eq 5
    selftest_expect "secure, that refusal is not retried (one call per case)" test "$(wc -l < "$d/compare.calls")" -eq 4
    selftest_expect "secure, the reason is printed" bash -c "printf '%s\n' \"\$1\" | grep -q 'FAIL  secure row, but the stock comparison'" _ "$out"
    : > "$d/compare.ignore_require"
    out=$("${env[@]}" "$SELF" "${base[@]}" --mode secure 2>&1); rc=$?
    selftest_expect "secure, a stock comparison that does not check and reports crc: the script's own check exits 5 ($rc)" test "$rc" -eq 5
    rm -f "$d/compare.conns" "$d/compare.ignore_require" "$d/compare.calls" "$d/compare.args" "$d/tool.args"
    # --small at every order (order 25 objects are bigger than 16 MiB): the sizes handed to rbd create are valid, whatever the order
    out=$("${env[@]}" "$SELF" --keys k1 --orders 12,16,18,20,22,25 --small --time 1 --parallel 4 2>&1); rc=$?
    selftest_expect "--small at all orders: exit 0 ($rc)" test "$rc" -eq 0
    selftest_expect "--small at all orders: six PASS lines" test "$(printf '%s\n' "$out" | grep -c '^CASE .* PASS ')" -eq 6
    # every step failing: the trap still unmaps, removes, and the state matches
    for step in $steps; do
        out=$("${env[@]}" "KC_INJECT_FAIL=$step" "$SELF" "${base[@]}" 2>&1); rc=$?
        selftest_expect "step '$step' injected: the run fails ($rc)" test "$rc" -ne 0
        selftest_expect "step '$step' injected: no mapping left" test -z "$(ls "$d/maps")"
        selftest_expect "step '$step' injected: no image left" test -z "$(ls "$d/images")"
        selftest_expect "step '$step' injected: the state matches the snapshot" bash -c "printf '%s\n' \"\$1\" | grep -q 'state: the lab matches'" _ "$out"
    done
    # a failure of the cleanup itself (the unmap in the trap) must not be hidden: still a non-zero exit, and what could be removed is
    # (the case's own unmap fails too, so that a mapping is left for the trap to undo; the trap's failure must show in the exit status and in the output)
    out=$("${env[@]}" "KC_INJECT_FAIL=unmap,unmap-cleanup" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "a failing unmap in the trap is not hidden: the run fails ($rc)" test "$rc" -ne 0
    selftest_expect "a failing unmap in the trap is reported" bash -c "printf '%s\n' \"\$1\" | grep -q 'FAIL  could not unmap'" _ "$out"
    selftest_expect "a failing unmap in the trap: the cleanup is marked FAILED" bash -c "printf '%s\n' \"\$1\" | grep -q 'cleanup: FAILED'" _ "$out"
    for f in "$d"/maps/*; do [ -e "$f" ] && rm -f "$f"; done; for f in "$d"/images/*; do [ -e "$f" ] && rm -f "$f"; done
    # the tool says 1 (a difference): the run says 1, the images are still removed
    echo 1 > "$d/tool.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "the tool's exit 1 is the run's exit 1 ($rc)" test "$rc" -eq 1
    selftest_expect "tool exit 1: nothing left over" test -z "$(ls "$d/images"; ls "$d/maps")"
    echo 4 > "$d/tool.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "the tool's exit 4 is the run's exit 4 ($rc)" test "$rc" -eq 4
    rm -f "$d/tool.rc"
    echo 1 > "$d/compare.rc"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "a failed stock comparison fails the run ($rc)" test "$rc" -eq 1
    rm -f "$d/compare.rc"
    # a comparison that cannot open the image once is tried again and passes; one that never can fails the run (after its retries)
    echo 1 > "$d/compare.fail_first"; rm -f "$d/compare.seen" "$d/compare.calls"
    out=$("${env[@]}" "KC_COMPARE_RETRIES=2" "KC_COMPARE_RETRY_WAIT=1" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "a stock comparison that could not open the image once is tried again ($rc)" test "$rc" -eq 0
    selftest_expect "the retry shows in the logs of the cases" bash -c 'grep -lq "trying again" "$1"/work/case-*.log' _ "$d"
    echo 9 > "$d/compare.fail_first"; rm -f "$d/compare.seen"
    out=$("${env[@]}" "KC_COMPARE_RETRIES=1" "KC_COMPARE_RETRY_WAIT=1" "$SELF" "${base[@]}" 2>&1); rc=$?
    selftest_expect "a stock comparison that never opens the image fails the run ($rc)" test "$rc" -eq 1
    rm -f "$d/compare.fail_first" "$d/compare.seen" "$d/compare.calls"
    # the lab drifts during the run (an OSD goes out): the run must notice
    echo "sed -i 's/\"osd\":1,\"up\":1,\"in\":1/\"osd\":1,\"up\":1,\"in\":0/' \"$d/ceph/dump.json\"" > "$d/tool.hook"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    rm -f "$d/tool.hook"
    selftest_expect "a drifted cluster state fails the run ($rc)" test "$rc" -ne 0
    selftest_expect "a drifted cluster state is reported" bash -c "printf '%s\n' \"\$1\" | grep -q 'cluster state differs'" _ "$out"
    sed -i 's/"osd":1,"up":1,"in":0/"osd":1,"up":1,"in":1/' "$d/ceph/dump.json"
    # a new kernel error appears in dmesg during the run
    echo "echo '[  100.0] libceph: osd1 bad crc/signature' >> \"$d/dmesg.txt\"" > "$d/tool.hook"
    out=$("${env[@]}" "$SELF" "${base[@]}" 2>&1); rc=$?
    rm -f "$d/tool.hook"
    selftest_expect "a new kernel error fails the run ($rc)" test "$rc" -ne 0
    selftest_expect "a new kernel error is reported" bash -c "printf '%s\n' \"\$1\" | grep -q 'new libceph / rbd errors'" _ "$out"
    : > "$d/dmesg.txt"
    # killed in the middle (TERM while the tool runs): the trap still undoes everything. The stand-in tool says when it has started (and sleeps long
    # enough to be killed); the kill waits for that, not for a number of seconds
    echo 30 > "$d/tool.sleep"; rm -f "$d/tool.started"
    "${env[@]}" "$SELF" "${base[@]}" > "$d/killed.out" 2>&1 &
    local pid=$! waited=0
    while [ ! -e "$d/tool.started" ] && [ "$waited" -lt 600 ]; do sleep 0.1; waited=$((waited + 1)); done
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    selftest_expect "killed with TERM: no mapping left" test -z "$(ls "$d/maps")"
    selftest_expect "killed with TERM: no image left" test -z "$(ls "$d/images")"
    rm -f "$d/tool.sleep"
    rm -rf "$d"
    if [ "$ST_FAILED" -ne 0 ]; then echo "selftest: $ST_FAILED check(s) FAILED"; return 1; fi
    echo "selftest: all checks passed"
    return 0
}

selftest_live() {
    local step steps="create map tool export compare unmap rm" rc out left mapped tag
    [ -x "$WRKC" ] && [ -x "$WRRBD" ] || die "build the harness first (or set WR_BUILD_DIR)"
    echo "live selftest: two tiny images, a failure injected at each step"
    for step in $steps; do
        tag="st$$$step"
        out=$(WR_LAB_WORK="$WORK.selftest-$tag" KC_NAME_TAG=$tag KC_INJECT_FAIL=$step "$SELF" --keys k1 --orders 12,16 --small --ops 200 --phase random --dir all --parallel 2 2>&1); rc=$?
        left=$(RBD ls "$POOL" 2>/dev/null | grep -c "^wrtest-kc-$tag-" || true)
        mapped=$(RBD showmapped 2>/dev/null | grep -c "wrtest-kc-$tag-" || true)
        rm -rf "$WORK.selftest-$tag"
        if [ "$rc" -ne 0 ] && [ "$left" -eq 0 ] && [ "$mapped" -eq 0 ] && printf '%s\n' "$out" | grep -q 'state: the lab matches'; then
            echo "  ok   injected '$step': exit $rc, no wrtest-kc image or mapping left, the state matches"
        else
            echo "  FAIL injected '$step': exit $rc, images left $left, mappings left $mapped"; printf '%s\n' "$out" | tail -n 15 | sed 's/^/      | /'
            return 1
        fi
    done
    echo "live selftest: all checks passed"
}

if [ "$selftest" = 1 ]; then
    if [ "$live" = 1 ]; then selftest_live; exit $?; fi
    selftest_stub; exit $?
fi
main
exit "$FINAL_RC"
