#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# live-rbd.sh: the live matrix of milestone 8 (docs/design/core-architecture.md 30.4): the winrbd core, through the wr-rbd tool,
# against the REAL lab cluster, with the stock rbd / rados / ceph tools as the oracle. It runs once per cephx key type and checks:
#
#   refusals    images of the writer profile P1 (features 0x1 and 0x21) open as writers; the default feature set (0x3d) is refused as
#               a writer and read fine as a reader; a clone, a striped image and a data-pool image are refused with their stable status
#   reads       images written by `rbd import` / `rados put` read through wr-rbd equal the stock export, byte for byte, at ragged
#               offsets, across objects, over holes and short objects; a flipped byte is found at the right offset
#   writes      fill / write / write-file / discard / zeroes through wr-rbd, then the stock export equals the expected content
#               (built independently in python from the same operations)
#   random      random unaligned cross-object I/O against the tool's own model, then the stock export equals the model; once with
#               --overlap (requests that overlap run in submission order: the fence of the core)
#   geometry    an image of 10000001 bytes with 16 KiB objects (not a whole number of objects): the last partial object, the last byte,
#               the first byte past the end refused, the whole image against the stock export
#   faults      the same with an OSD stopped (aes256k key) or killed with SIGKILL (legacy aes key) and started again mid-run, with an
#               OSD marked out and in mid-run (map changes, resends), and (aes256k key) with two OSDs down at once so the PGs go inactive and I/O stalls and resumes;
#               the cluster is brought back to its baseline and the health compared
#   snapshot    a snapshot taken between two refreshes of a writer: how long writes still go out with the old snapshot context
#               (the exposure window of 24.4, measured), with and without ORDERSNAP (EOLDSNAPC handling)
#   mtime       the object's mtime with the real wall clock and with no wall clock at all (mtime 0 is accepted)
#   users       a data-pool image with a user that has caps on both pools; users without class access, without OSD caps and with
#               read-only caps (open refused / authorizer refused / every write refused)
#
# Run it inside the lab VM (the monitor listens on the private network). The images, the extra pool and the throwaway cephx users are
# made by harness/lab/rbd-prepare.sh (names wrtest-lrt-*, client.wrtest-lrt-*) and removed again at the end.
#
#   rsync the repository to the VM, build the harness there:
#       cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Release && cmake --build build/harness -j
#   keep the keyrings OUTSIDE the repository, mode 600 (default ~/keys):
#       WR_BUILD_DIR=build/harness harness/lab/live-rbd.sh
#
# Options:
#   --keys k2|k1|both       which cephx key types (default both: client.winrbd aes256k, client.winrbd-aes legacy aes)
#   --only a,b,...          run only these sections: refusals reads writes random geometry kill outin stall snapshot mtime users
#   --skip-faults           leave out kill and outin (they stop and start OSDs of the lab cluster)
#   --no-prepare            use the images of an earlier `rbd-prepare.sh create` (manifest in the work directory) and keep them
#   --keep                  do not clean up at the end
#   --ctest                 also run the "lab" ctest lab.rbd on the writer image
#   --quick                 shorter random runs
#
# Environment: WR_BUILD_DIR (default <repo>/build/harness), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd),
# WR_LAB_KEYRING_DIR (~/keys: client.<user>.keyring or ceph.client.<user>.keyring), WR_LAB_USER_K2 (winrbd), WR_LAB_USER_K1
# (winrbd-aes), WR_LAB_KEYRING_K2 / WR_LAB_KEYRING_K1 (explicit files), WR_LAB_WORK (~/w/lrt-run), WR_LAB_SUDO (sudo).
#
# Key material is never printed. Exit status: 0 when every check passed, 1 when any failed, 2 for a setup problem.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
build=${WR_BUILD_DIR:-$repo/build/harness}
WR=$build/wr-rbd
MON=${WR_LAB_MON:-10.77.0.10:3300}
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/lrt-run}
SUDO=${WR_LAB_SUDO:-sudo}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
export WR_LAB_POOL=$POOL WR_LAB_WORK=$WORK WR_LAB_SUDO=$SUDO

die()  { echo "live-rbd: error: $*" >&2; exit 2; }
info() { echo "live-rbd: $*" >&2; }

keys=both; only=""; skip_faults=0; prepare=1; keep=0; run_ctest=0; quick=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keys) keys=${2:-}; shift ;;
        --only) only=${2:-}; shift ;;
        --skip-faults) skip_faults=1 ;;
        --no-prepare) prepare=0; keep=1 ;;
        --keep) keep=1 ;;
        --ctest) run_ctest=1 ;;
        --quick) quick=1 ;;
        -h|--help) sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
case "$keys" in k2|k1|both) ;; *) die "--keys takes k2, k1 or both" ;; esac

want() { # <section>: is it selected?
    [ -z "$only" ] && return 0
    case ",$only," in *",$1,"*) return 0 ;; esac
    return 1
}

[ -x "$WR" ] || die "$WR not found; build the harness first (see --help)"
command -v python3 >/dev/null || die "python3 is needed"
$SUDO -n true 2>/dev/null || die "passwordless sudo is needed for the stock CLI"

RBD()   { $SUDO rbd "$@"; }
RADOS() { $SUDO rados "$@"; }
CEPH()  { $SUDO ceph "$@"; }

# ---- keyrings (outside the repository, never printed) ---------------------------------------------------------------------------
find_keyring() { # <explicit> <user>
    local explicit=$1 user=$2 f
    if [ -n "$explicit" ]; then echo "$explicit"; return 0; fi
    for f in "$KEYDIR/client.$user.keyring" "$KEYDIR/ceph.client.$user.keyring"; do
        if [ -f "$f" ]; then echo "$f"; return 0; fi
    done
    return 1
}
USER_K2=${WR_LAB_USER_K2:-winrbd}; USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
KR_K2=$(find_keyring "${WR_LAB_KEYRING_K2:-}" "$USER_K2") || KR_K2=""
KR_K1=$(find_keyring "${WR_LAB_KEYRING_K1:-}" "$USER_K1") || KR_K1=""
for kr in "$KR_K2" "$KR_K1"; do
    [ -n "$kr" ] || continue
    [ -r "$kr" ] || die "keyring not readable: $kr"
    case "$(cd "$(dirname "$kr")" && pwd -P)/" in "$repo"/*) die "keyring $kr is inside the repository; keep keys outside it" ;; esac
done
case "$keys" in k2) KR_K1="" ;; k1) KR_K2="" ;; esac
[ -n "$KR_K2$KR_K1" ] || die "no keyring found (WR_LAB_KEYRING_DIR, or WR_LAB_KEYRING_K2 / WR_LAB_KEYRING_K1)"

first=${MON%%[, ;]*}; first=${first#\[}; first=${first#v2:}
mon_host=${first%:*}; mon_port=${first##*:}
[ "$mon_port" != "$first" ] || { mon_port=3300; mon_host=$first; }
timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$mon_host" "$mon_port" 2>/dev/null || die "cannot reach $mon_host:$mon_port: run this inside the lab VM"

# ---- reporting ----------------------------------------------------------------------------------------------------------------
PASS=0; FAIL=0; FAILED=(); OUT=""; RC=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); echo "FAIL  $*"; if [ -n "$OUT" ]; then printf '%s\n' "$OUT" | tail -n 6 | cut -c1-300 | sed 's/^/      | /'; fi; }
note() { echo "NOTE  $*"; }
sect() { echo; echo "=== $* ==="; }
expect_rc()  { if [ "$RC" -eq "$1" ]; then ok "$2"; else bad "$2 (exit $RC, wanted $1)"; fi; }
expect_out() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then ok "$2"; else bad "$2 (no match for: $1)"; fi; }
expect_no()  { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then bad "$2 (found: $1)"; else ok "$2"; fi; }
field() { printf '%s\n' "$OUT" | sed -n "s/.*[ @]$1=\([^ ]*\).*/\1/p" | tail -n 1; } # last value of key=value in the output

CUR_USER=""; CUR_KR=""; CUR_LABEL=""; SH_RC=""; KEY_SEED=0
wr() { # <image> <args...>: run the tool as the current user; sets OUT and RC
    local img=$1; shift
    OUT=$(timeout "${WR_TMO:-1200}" "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" "$@" 2>&1); RC=$?
}
wru() { # <user> <keyring> <image> <args...>
    local u=$1 k=$2 img=$3; shift 3
    OUT=$(timeout "${WR_TMO:-1200}" "$WR" --mon "$MON" --user "$u" --keyring "$k" --pool "$POOL" --image "$img" "$@" 2>&1); RC=$?
}

# ---- the work directory, the manifest, the baseline ------------------------------------------------------------------------------
mkdir -p "$WORK" && chmod 700 "$WORK"
PYLIB=$(bash "$here/rbd-prepare.sh" pylib) || die "cannot write the python helper"
py() { python3 -I "$PYLIB" "$@"; }

health_snapshot() { # prints a comparable one-line state
    echo "osd: $(CEPH osd stat 2>/dev/null | sed -n 's/^\([0-9]*\) osds: \([0-9]*\) up.*, \([0-9]*\) in.*/\1 osds \2 up \3 in/p') | upmaps: $(CEPH osd dump 2>/dev/null | grep -c '^pg_upmap') | health: $(CEPH health 2>/dev/null | sed 's/ (muted.*//' | tr '\n' ' ')"
}
BASE_STATE=$(health_snapshot)
BASE_PGS=$(CEPH pg stat 2>/dev/null | sed -n 's/^\([0-9]* pgs\): \([0-9]* active+clean\).*/\1 \2/p')
BASE_OSDS=$(CEPH osd stat 2>/dev/null | sed -n 's/^\([0-9]*\) osds.*/\1/p')
FSID=$(CEPH fsid)
info "baseline: $BASE_STATE"
info "baseline pgs: ${BASE_PGS:-unknown}"

wait_clean() { # <seconds>: all PGs active+clean and every OSD up and in again
    local t=${1:-300} i s o
    for ((i = 0; i < t; i += 3)); do
        s=$(CEPH pg stat 2>/dev/null); o=$(CEPH osd stat 2>/dev/null)
        if printf '%s\n' "$s" | grep -Eq '^[0-9]+ pgs: [0-9]+ active\+clean;' && printf '%s\n' "$o" | grep -Eq "^$BASE_OSDS osds: $BASE_OSDS up.*, $BASE_OSDS in"; then
            return 0
        fi
        sleep 3
    done
    return 1
}

CLEANED=0
do_cleanup() { # remove what rbd-prepare.sh create made (once)
    [ "$CLEANED" -eq 0 ] || return 0
    CLEANED=1
    if [ "$keep" -eq 0 ] && [ "$prepare" -eq 1 ]; then
        info "cleaning up"
        bash "$here/rbd-prepare.sh" cleanup >/dev/null 2>&1 || info "cleanup reported a problem: run rbd-prepare.sh status"
    fi
}
FAULT_PID=""
cleanup() {
    local rc=$?
    if [ -n "${SH_PID:-}" ]; then kill "$SH_PID" 2>/dev/null; fi
    if [ -n "${FAULT_PID:-}" ]; then kill "$FAULT_PID" 2>/dev/null; fi
    # an interrupted fault must not leave the cluster short of an OSD: start the daemons again, mark every OSD in
    restore_osds
    do_cleanup
    return $rc
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

if [ "$prepare" -eq 1 ]; then
    info "preparing images (rbd-prepare.sh create)"
    bash "$here/rbd-prepare.sh" create >/dev/null
    prep_rc=$?
    if [ "$prep_rc" -eq 3 ]; then
        CLEANED=1 # nothing of ours was made: what is in the way belongs to another run, and the exit cleanup must not remove it
        die "rbd-prepare.sh create: images, pool or manifest of an earlier run are in the way (see its message; rbd-prepare.sh cleanup removes them)"
    fi
    [ "$prep_rc" -eq 0 ] || die "rbd-prepare.sh create failed (the exit cleanup removes what it made)"
fi
[ -f "$WORK/manifest.env" ] || die "no manifest in $WORK: run rbd-prepare.sh create, or leave out --no-prepare"
# shellcheck disable=SC1090
. "$WORK/manifest.env"

stock_export() { # <image> <file> [snap]
    local spec="$POOL/$1"
    [ -n "${3:-}" ] && spec="$spec@$3"
    RBD export "$spec" - > "$2" 2>/dev/null
}
size_of() { stat -c %s "$1"; }

# ---- sections --------------------------------------------------------------------------------------------------------------------
sec_refusals() {
    sect "refusals and the profile ($CUR_LABEL)"
    wr "$LRT_IMG_p1a" --rw info;  expect_rc 0 "p1a (0x1) opens as a writer"; expect_out 'features=0x1 .*writable=1' "p1a reports features 0x1, writable"
    wr "$LRT_IMG_p1b" --rw info;  expect_rc 0 "p1b (0x21) opens as a writer"; expect_out 'features=0x21 .*writable=1' "p1b reports features 0x21, writable"
    wr "$LRT_IMG_dflt" --rw info; expect_rc 3 "default features (0x3d) refused as a writer"; expect_out 'WR_E_RBD_FEATURES' "... with WR_E_RBD_FEATURES"
    wr "$LRT_IMG_dflt" info;      expect_rc 0 "default features (0x3d) opens as a reader"; expect_out 'features=0x3d .*writable=0' "... read-only, features 0x3d"
    wr "$LRT_IMG_clone" info;     expect_rc 3 "a clone is refused (reader)"; expect_out 'WR_E_RBD_PARENT' "... with WR_E_RBD_PARENT"
    wr "$LRT_IMG_clone" --rw info; expect_rc 3 "a clone is refused (writer)"; expect_out 'WR_E_RBD_PARENT' "... with WR_E_RBD_PARENT"
    wr "$LRT_IMG_str" info;       expect_rc 3 "a striped image is refused (reader)"; expect_out 'WR_E_RBD_STRIPING' "... with WR_E_RBD_STRIPING"
    wr "$LRT_IMG_str" --rw info;  expect_rc 3 "a striped image is refused (writer)"; expect_out 'WR_E_RBD_STRIPING' "... with WR_E_RBD_STRIPING"
    wr "$LRT_IMG_dp" info;        expect_rc 3 "a data-pool image without --data-pool is refused"; expect_out 'WR_E_RBD_DATA_POOL' "... with WR_E_RBD_DATA_POOL"
    wr "$LRT_IMG_dp" --data-pool "$POOL" info; expect_rc 3 "a data-pool image with the wrong pool name is refused"; expect_out 'WR_E_RBD_DATA_POOL' "... with WR_E_RBD_DATA_POOL"
    wr "no-such-image-lrt" --timeout 15000 info; expect_rc 3 "a missing image fails the open"; expect_out 'WR_E_RBD_NOT_FOUND' "... with WR_E_RBD_NOT_FOUND"
    OUT=$(timeout 120 "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --id "$LRT_ID_p1a" --rw info 2>&1); RC=$?
    expect_rc 0 "an image opens by id"; expect_out "id=$LRT_ID_p1a " "... the id is the one the stock tool reports"
}

# compare the tool with the stock export of an image; <image> [ro-flag-free]
read_compare() { # <image> <label>
    local img=$1 lbl=$2 f="$WORK/exp-$2.bin"
    stock_export "$img" "$f"
    wr "$img" compare "$f"; expect_rc 0 "$lbl: wr-rbd compare equals the stock export"; expect_out 'result compare ok=1 .* diffs=0 errors=0' "$lbl: zero differences"
    CMP_FILE=$f
}

slice_check() { # <image> <export file> <off> <len> <label>: read through the tool into a file, compare with the same slice of the export
    local img=$1 f=$2 off=$3 len=$4 lbl=$5 out="$WORK/slice.bin"
    wr "$img" read "$off" "$len" "$out"
    if [ "$RC" -eq 0 ] && [ "$(size_of "$out")" -eq "$len" ] && cmp -s -i "0:$off" -n "$len" "$out" "$f"; then ok "$lbl: read $off+$len equals the export"; else bad "$lbl: read $off+$len differs from the export"; fi
    rm -f "$out"
}

# the oracle itself, once on the freshly prepared images: the stock export is the reference content the python helper made
sec_oracle() {
    sect "the oracle: stock export of the prepared images equals the reference files"
    local img
    for img in p1a p1b dflt; do
        eval "n=\$LRT_IMG_$img; r=\$LRT_REF_$img"
        stock_export "$n" "$WORK/oracle.bin"
        if cmp -s "$WORK/oracle.bin" "$r"; then ok "rbd export of $n equals its reference file"; else bad "rbd export of $n differs from its reference file: $(py cmp "$WORK/oracle.bin" "$r")"; fi
    done
    rm -f "$WORK/oracle.bin"
}

sec_reads() {
    sect "reads against the stock export ($CUR_LABEL)"
    local img f
    for img in p1a p1b dflt; do
        eval "n=\$LRT_IMG_$img"
        read_compare "$n" "$img-$CUR_LABEL"
        f=$CMP_FILE
        if [ "$img" = p1a ] || [ "$img" = p1b ]; then
            local sz; sz=$(size_of "$f")
            slice_check "$n" "$f" 4191304 8000 "$img" # across the first object boundary
            slice_check "$n" "$f" 4194303 2 "$img"    # one byte each side
            slice_check "$n" "$f" 1 4194305 "$img"    # two objects, unaligned both ends
            slice_check "$n" "$f" 5242880 1000 "$img" # a hole
            slice_check "$n" "$f" 20971520 4194304 "$img" # one whole object
            slice_check "$n" "$f" 12582912 5000 "$img"   # a short object and what follows it
            slice_check "$n" "$f" $((sz - 777)) 777 "$img" # the end of the image
        fi
        rm -f "$f"
    done
    # an object written by rados, read through the tool: the short object 3 of p1b and a whole one
    local obj out
    for i in 0 3 15; do
        obj=$(printf 'rbd_data.%s.%016x' "$LRT_ID_p1b" "$i")
        if ! out=$(RADOS -p "$POOL" get "$obj" "$WORK/obj.bin" 2>&1); then
            if printf '%s\n' "$out" | grep -q 'No such file'; then
                # an earlier run of the matrix (the other key's random I/O) removed the object: an absent object reads as zeros
                wr "$LRT_IMG_p1b" verify $((i * 4194304)) 4194304 --pattern zero
                expect_rc 0 "p1b object $i does not exist (rados get says so) and reads as zeros"
            else
                bad "rados get $obj failed: $out"
            fi
            continue
        fi
        local n; n=$(size_of "$WORK/obj.bin")
        wr "$LRT_IMG_p1b" read $((i * 4194304)) "$n" "$WORK/objread.bin"
        if [ "$RC" -eq 0 ] && cmp -s "$WORK/obj.bin" "$WORK/objread.bin"; then ok "p1b object $i ($n bytes) equals what rados get returns"; else bad "p1b object $i differs from rados get"; fi
        if [ "$n" -lt 4194304 ]; then
            wr "$LRT_IMG_p1b" verify $((i * 4194304 + n)) $((4194304 - n)) --pattern zero
            expect_rc 0 "p1b object $i: the bytes after its end read as zeros"
        fi
        rm -f "$WORK/obj.bin" "$WORK/objread.bin"
    done
    # a difference is found where it is
    stock_export "$LRT_IMG_p1a" "$WORK/mut.bin"
    python3 -I - "$WORK/mut.bin" <<'PYEOF'
import sys
p = sys.argv[1]; b = bytearray(open(p, 'rb').read()); b[5000001] ^= 0x40; b[-1] ^= 1; open(p, 'wb').write(b)
PYEOF
    wr "$LRT_IMG_p1a" compare "$WORK/mut.bin"; expect_rc 1 "compare finds a flipped byte"; expect_out 'first_diff=5000001 ' "... at its offset"; expect_out 'diffs=2 ' "... and counts both"
    rm -f "$WORK/mut.bin"
    # holes and unwritten space read as zeros
    wr "$LRT_IMG_snap" verify --pattern zero; expect_rc 0 "an empty image reads as zeros"
}

sec_writes() {
    sect "writes read back by the stock tools ($CUR_LABEL)"
    local img=$LRT_IMG_p1a before="$WORK/before.bin" after="$WORK/after.bin" expect="$WORK/expect.bin" payload="$WORK/payload.bin" sz
    stock_export "$img" "$before"
    sz=$(size_of "$before")
    py build "$payload" zero:100000 0:100000:rand:9001
    wr "$img" --rw fill 0 8M --pattern rand:7;                         expect_rc 0 "fill 0+8M rand:7"
    wr "$img" --rw write 4194000 20000 --pattern offset;               expect_rc 0 "write 4194000+20000 offset (crosses an object boundary)"
    wr "$img" --rw write 30000001 100000 --file "$payload";            expect_rc 0 "write 30000001+100000 from a file"
    wr "$img" --rw discard 4194304 4194304;                            expect_rc 0 "discard one whole object"
    wr "$img" --rw zeroes 1000 7000;                                   expect_rc 0 "write-zeroes 1000+7000"
    wr "$img" --rw discard 50000001 3000001;                           expect_rc 0 "discard 50000001+3000001 (ragged, several objects)"
    wr "$img" --rw write $((sz - 777)) 777 --pattern byte:0x5a;        expect_rc 0 "write the last 777 bytes"
    py build "$expect" "$before" 0:8388608:rand:7 4194000:20000:offset 30000001:-:file:"$payload" 4194304:4194304:zero 1000:7000:zero \
        50000001:3000001:zero $((sz - 777)):777:byte:0x5a || die "python helper failed"
    stock_export "$img" "$after"
    if cmp -s "$expect" "$after"; then ok "the stock export equals the expected content (all seven operations)"; else bad "the stock export differs from the expected content: $(py cmp "$expect" "$after")"; fi
    wr "$img" compare "$after"; expect_rc 0 "wr-rbd compare agrees with the stock export after the writes"
    local obj; obj=$(printf 'rbd_data.%s.%016x' "$LRT_ID_p1a" 7)
    RADOS -p "$POOL" get "$obj" "$WORK/obj.bin" >/dev/null 2>&1
    if cmp -s -n "$(size_of "$WORK/obj.bin")" -i "0:$((7 * 4194304))" "$WORK/obj.bin" "$expect"; then ok "rados get of object 7 equals the expected slice"; else bad "rados get of object 7 differs"; fi
    rm -f "$before" "$after" "$expect" "$payload" "$WORK/obj.bin"
}

random_case() { # <image> <label> <extra args> <ops> <seed>
    local img=$1 lbl=$2 extra=$3 ops=$4 seed=$5 model="$WORK/model.bin" exp="$WORK/rexport.bin" n
    # shellcheck disable=SC2086
    wr "$img" --rw $extra random "$ops" "$seed" --save "$model"
    expect_rc 0 "random $lbl: $ops ops, seed $seed"
    expect_out 'result random ok=1 .* read_mismatches=0 final_diff_bytes=0 errors=0' "random $lbl: zero differences against the model"
    echo "      $(printf '%s\n' "$OUT" | grep ' result random ' | sed 's/.*result random //' | cut -c1-230)"
    echo "      $(printf '%s\n' "$OUT" | grep ' stats ' | sed 's/.* stats //' | cut -c1-230)"
    n=$(size_of "$model")
    stock_export "$img" "$exp"
    if cmp -s -n "$n" "$model" "$exp"; then ok "random $lbl: the stock export equals the model ($n bytes)"; else bad "random $lbl: the stock export differs from the model"; fi
    rm -f "$model" "$exp"
}

sec_random() {
    sect "random I/O against the model ($CUR_LABEL)"
    local ops=600
    [ "$quick" -eq 1 ] && ops=200
    random_case "$LRT_IMG_p1b" "$CUR_LABEL depth 8" "--depth 8" "$ops" $((11 + ${KEY_SEED:-0}))
    random_case "$LRT_IMG_p1b" "$CUR_LABEL depth 1" "--depth 1" $((ops / 3)) $((12 + ${KEY_SEED:-0}))
    random_case "$LRT_IMG_p1a" "$CUR_LABEL big ops, small model" "--depth 16 --model-bytes 12M --max-len 6M" "$ops" $((13 + ${KEY_SEED:-0}))
    random_case "$LRT_IMG_p1b" "$CUR_LABEL overlapping requests in flight" "--depth 16 --overlap --model-bytes 16M --max-len 3M" "$ops" $((14 + ${KEY_SEED:-0}))
}

sec_geometry() {
    sect "an image that is not a whole number of objects ($CUR_LABEL)"
    local img=$LRT_IMG_geo size=10000001 obj=16384 last exp="$WORK/geo-exp.bin" after="$WORK/geo-after.bin"
    last=$((size / obj * obj)) # the start of the last, partial object (5761 bytes long)
    wr "$img" --rw info; expect_rc 0 "the odd-sized image opens as a writer"; expect_out "size=$size .*order=14 object_size=$obj " "... size $size, 16 KiB objects"
    wr "$img" --rw fill --pattern rand:3; expect_rc 0 "fill the whole image (the last partial object included)"
    wr "$img" verify --pattern rand:3; expect_rc 0 "verify the whole image"
    wr "$img" --rw discard "$last" $((size - last)); expect_rc 0 "discard the last partial object"
    wr "$img" --rw write $((size - 1)) 1 --pattern byte:0x77; expect_rc 0 "write the very last byte"
    wr "$img" read $((size - 1)) 1; expect_rc 0 "read the very last byte"; expect_out 'nonzero=1' "... it is not zero"
    wr "$img" read $((size - 1)) 2; expect_rc 2 "a read that ends one byte past the end is refused"; expect_out 'status=range' "... as a range error"
    wr "$img" --rw write "$size" 1 --pattern byte:1; expect_rc 2 "a write at the first byte past the end is refused"; expect_out 'status=range' "... as a range error"
    wr "$img" --rw write "$size" 0 --pattern byte:1; expect_rc 0 "a write of no bytes at the end is fine"
    wr "$img" --rw discard $((last - 1)) 2; expect_rc 0 "discard two bytes across the last object boundary"
    wr "$img" --rw zeroes 9990000 9000; expect_rc 0 "write-zeroes across the last two objects"
    py build "$exp" zero:$size 0:$size:rand:3 "$last:$((size - last)):zero" $((size - 1)):1:byte:0x77 $((last - 1)):2:zero 9990000:9000:zero || die "python helper failed"
    stock_export "$img" "$after"
    if cmp -s "$exp" "$after"; then ok "the stock export equals the expected content ($size bytes)"; else bad "the stock export differs from the expected content: $(py cmp "$exp" "$after")"; fi
    wr "$img" compare "$after"; expect_rc 0 "wr-rbd compare agrees with the stock export"
    rm -f "$exp" "$after"
    random_case "$img" "$CUR_LABEL whole odd-sized image, overlapping" "--depth 16 --overlap --model-bytes 10M --max-len 100000" 700 $((15 + ${KEY_SEED:-0}))
}

# ---- faults: an OSD stopped / killed / marked out while random I/O runs -----------------------------------------------------------
osd_unit() { echo "ceph-$FSID@osd.$1.service"; }

fault_run() { # <label> <image> <seed> <action-script-function>
    local lbl=$1 img=$2 seed=$3 act=$4 log="$WORK/fault.log" model="$WORK/fmodel.bin" exp="$WORK/fexport.bin" pid n ops=2500
    [ "$quick" -eq 1 ] && ops=1500
    rm -f "$model"
    timeout 1500 "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" --rw --depth 8 --overlap --delay-ms 5 --op-timeout "${FAULT_OPTMO:-8000}" \
        random "$ops" "$seed" --save "$model" > "$log" 2>&1 &
    pid=$!; FAULT_PID=$pid
    sleep 6
    $act
    wait "$pid"; RC=$?; FAULT_PID=""
    OUT=$(cat "$log")
    expect_rc 0 "$lbl: the random run finished (exit code of wr-rbd)"
    expect_out 'result random ok=1 .* read_mismatches=0 final_diff_bytes=0 errors=0' "$lbl: zero differences against the model"
    echo "      $(printf '%s\n' "$OUT" | grep ' stats ' | sed 's/.* stats //' | cut -c1-260)"
    n=$(size_of "$model" 2>/dev/null || echo 0)
    stock_export "$img" "$exp"
    if [ "$n" -gt 0 ] && cmp -s -n "$n" "$model" "$exp"; then ok "$lbl: the stock export equals the model"; else bad "$lbl: the stock export differs from the model"; fi
    rm -f "$log" "$model" "$exp"
}

FAULT_OSD=1
act_stop_start() {
    note "stopping osd.$FAULT_OSD for 12 s"
    $SUDO systemctl stop "$(osd_unit $FAULT_OSD)"
    sleep 12
    $SUDO systemctl start "$(osd_unit $FAULT_OSD)"
    note "osd.$FAULT_OSD started again"
}
act_kill() {
    local i
    note "killing osd.$FAULT_OSD (SIGKILL); systemd may start it again by itself, if not the script does after 30 s"
    $SUDO pkill -9 -f "/usr/bin/ceph-osd -n osd\\.${FAULT_OSD} " || note "no ceph-osd process found for osd.$FAULT_OSD"
    for ((i = 0; i < 15; i++)); do
        sleep 2
        [ "$i" -ge 3 ] && $SUDO systemctl is-active --quiet "$(osd_unit $FAULT_OSD)" && return 0
    done
    $SUDO systemctl reset-failed "$(osd_unit $FAULT_OSD)" 2>/dev/null
    $SUDO systemctl start "$(osd_unit $FAULT_OSD)"
    note "osd.$FAULT_OSD started by the script"
}
ensure_osds_running() { # a daemon a fault left stopped or failed is started again (the baseline has every OSD up)
    local n
    for ((n = 0; n < BASE_OSDS; n++)); do
        $SUDO systemctl is-active --quiet "$(osd_unit $n)" && continue
        note "osd.$n is not running: starting it"
        $SUDO systemctl reset-failed "$(osd_unit $n)" 2>/dev/null
        $SUDO systemctl start "$(osd_unit $n)"
    done
}
restore_osds() { # every daemon running and every OSD in, as at the baseline (also the trap's job after an interrupted fault)
    local n
    [ -n "${BASE_OSDS:-}" ] || return 0
    ensure_osds_running
    for ((n = 0; n < BASE_OSDS; n++)); do
        CEPH osd dump 2>/dev/null | grep -Eq "^osd\.$n (up|down) +out " && { note "osd.$n is out: marking it in"; CEPH osd in "$n" >/dev/null 2>&1; }
    done
}
act_two_down() {
    note "stopping osd.1 and osd.2 for 12 s (the pool's min_size is 2: its PGs go inactive, I/O must wait and then resume)"
    $SUDO systemctl stop "$(osd_unit 1)" "$(osd_unit 2)"
    sleep 12
    $SUDO systemctl start "$(osd_unit 1)" "$(osd_unit 2)"
    note "osd.1 and osd.2 started again"
}
act_out_in() {
    note "marking osd.$FAULT_OSD out for 14 s"
    CEPH osd out "$FAULT_OSD" >/dev/null
    sleep 14
    CEPH osd in "$FAULT_OSD" >/dev/null
    note "osd.$FAULT_OSD marked in again"
}

after_fault() { # <label>
    ensure_osds_running
    if wait_clean 420; then ok "$1: the cluster is back to $BASE_OSDS up, $BASE_OSDS in and active+clean"; else bad "$1: the cluster did not return to a clean state within 7 minutes: $(CEPH pg stat 2>/dev/null)"; fi
}

sec_kill() {
    sect "an OSD stopped or killed under I/O ($CUR_LABEL)"
    if [ "$CUR_LABEL" = k2 ]; then
        FAULT_OSD=1; fault_run "stop/start osd.1 ($CUR_LABEL)" "$LRT_IMG_p1b" $((21 + ${KEY_SEED:-0})) act_stop_start
    else
        FAULT_OSD=2; fault_run "kill -9 osd.2 ($CUR_LABEL)" "$LRT_IMG_p1b" $((22 + ${KEY_SEED:-0})) act_kill
    fi
    after_fault "after the OSD fault ($CUR_LABEL)"
}

sec_stall() {
    sect "two OSDs down at once: I/O stalls, then resumes ($CUR_LABEL)"
    FAULT_OPTMO=3000 fault_run "two OSDs down ($CUR_LABEL)" "$LRT_IMG_p1b" $((41 + ${KEY_SEED:-0})) act_two_down
    local st; st=$(printf '%s\n' "$OUT" | sed -n 's/.* io_stalls=\([0-9]*\) .*/\1/p' | tail -n 1)
    if [ "${st:-0}" -ge 1 ]; then ok "the tool saw WR_EV_IO_STALL ($st) and WR_EV_IO_RESUME while the PGs were inactive"; else note "no IO_STALL event was raised (io_stalls=${st:-?})"; fi
    after_fault "after two OSDs down ($CUR_LABEL)"
}

sec_outin() {
    sect "an OSD marked out and in under I/O ($CUR_LABEL)"
    FAULT_OSD=$([ "$CUR_LABEL" = k2 ] && echo 0 || echo 1)
    fault_run "out/in osd.$FAULT_OSD ($CUR_LABEL)" "$LRT_IMG_p1a" $((31 + ${KEY_SEED:-0})) act_out_in
    after_fault "after out/in ($CUR_LABEL)"
}

# ---- snapshot between two refreshes, ORDERSNAP ---------------------------------------------------------------------------------------
SH_FIFO=""; SH_FD=""; SH_N=0; SH_OUT=""; SH_PID=""
shell_start() { # <image> <outfile> <tool args...>
    local img=$1; SH_OUT=$2; shift 2
    SH_FIFO="$WORK/sh.in"; rm -f "$SH_FIFO"; mkfifo "$SH_FIFO"
    "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" "$@" shell < "$SH_FIFO" > "$SH_OUT" 2>&1 &
    SH_PID=$!
    exec {SH_FD}> "$SH_FIFO"
    SH_N=0
    local i
    for ((i = 0; i < 400; i++)); do grep -q 'shell ready' "$SH_OUT" 2>/dev/null && return 0; sleep 0.1; done
    return 1
}
shell_cmd() { # <command...>: send it and wait for its "done" line; the command's rc in SH_RC
    local i n
    echo "$*" >&"$SH_FD"; SH_N=$((SH_N + 1))
    for ((i = 0; i < 1200; i++)); do
        if grep -q " done $SH_N rc=" "$SH_OUT" 2>/dev/null; then
            SH_RC=$(sed -n "s/.* done $SH_N rc=//p" "$SH_OUT" | tail -n 1); return 0
        fi
        sleep 0.05
    done
    SH_RC=timeout; return 1
}
shell_end() {
    echo quit >&"$SH_FD"; exec {SH_FD}>&-
    wait "$SH_PID"; SH_EXIT=$?; SH_PID=""
    rm -f "$SH_FIFO"
}
now() { date +%s.%N; }
fsub() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", a - b }'; }
objbyte() { python3 -I - "$1" "$2" <<'PYEOF'
import sys
f = open(sys.argv[1], 'rb'); f.seek(int(sys.argv[2]) * 4194304); print(f.read(1)[0])
PYEOF
}

exposure_run() { # <label> <refresh ms> <extra tool args> : writes 20 objects 0.3 s apart after a snapshot
    local lbl=$1 refresh=$2 extra=$3 img=$LRT_IMG_snap out="$WORK/sh.out" k t_snap t_end n=20 leaked=0 first_ok="" last_leak=""
    local -a tk
    RBD snap purge "$POOL/$img" >/dev/null 2>&1
    # every object starts with A (170) in its first byte
    wr "$img" --rw discard 0 134217728 >/dev/null 2>&1
    # shellcheck disable=SC2086
    shell_start "$img" "$out" --rw --hdr-refresh "$refresh" $extra || { bad "$lbl: the shell did not start"; return; }
    for ((k = 0; k < n; k++)); do shell_cmd write $((k * 4194304)) 4096 --pattern byte:170; done
    shell_cmd sleep 300
    t_snap=$(now); RBD snap create "$POOL/$img@s1" >/dev/null 2>&1 || bad "$lbl: rbd snap create failed"; t_end=$(now)
    for ((k = 0; k < n; k++)); do
        tk[k]=$(now)
        shell_cmd write $((k * 4194304)) 4096 --pattern byte:187
        [ "$SH_RC" = 0 ] || bad "$lbl: write $k failed (rc $SH_RC)"
        sleep 0.3
    done
    shell_end
    stock_export "$img" "$WORK/head.bin"; stock_export "$img" "$WORK/snap.bin" s1
    local line=""
    for ((k = 0; k < n; k++)); do
        local h s lag
        h=$(objbyte "$WORK/head.bin" $k); s=$(objbyte "$WORK/snap.bin" $k); lag=$(fsub "${tk[k]}" "$t_end")
        [ "$h" = 187 ] || bad "$lbl: object $k: the head holds $h, not the written 187"
        if [ "$s" = 187 ]; then leaked=$((leaked + 1)); last_leak=$lag; else [ -n "$first_ok" ] || first_ok=$lag; fi
        line="$line $k:${lag}s=${s}"
    done
    note "$lbl: object:seconds-after-snapshot=first-byte-in-the-snapshot (170 = preserved, 187 = overwritten): $line"
    note "$lbl: writes that leaked into the snapshot: $leaked of $n; last leaked at ${last_leak:--} s, first preserved at ${first_ok:--} s after the snapshot (refresh interval $((refresh / 1000)) s)"
    EXPOSURE_FIRST_OK=${first_ok:--}; EXPOSURE_LEAKED=$leaked
    rm -f "$WORK/head.bin" "$WORK/snap.bin" "$out"
    RBD snap purge "$POOL/$img" >/dev/null 2>&1
}

sec_snapshot() {
    sect "a snapshot between two refreshes ($CUR_LABEL)"
    exposure_run "refresh 4 s" 4000 ""
    if [ "$EXPOSURE_FIRST_OK" != "-" ] && awk -v a="$EXPOSURE_FIRST_OK" 'BEGIN { exit !(a <= 4 + 2.5) }'; then ok "the exposure window is at most the refresh interval plus one round trip (first preserved write ${EXPOSURE_FIRST_OK} s after the snapshot)"; else bad "the exposure window exceeded the refresh interval (first preserved write at ${EXPOSURE_FIRST_OK} s)"; fi
    [ "$EXPOSURE_LEAKED" -ge 1 ] && note "as the design says (24.4), the writes inside the window overwrite the snapshot: the exposure is real and bounded by hdr_refresh_ms"
    exposure_run "refresh 1 s" 1000 ""
    if [ "$EXPOSURE_FIRST_OK" != "-" ] && awk -v a="$EXPOSURE_FIRST_OK" 'BEGIN { exit !(a <= 1 + 2.5) }'; then ok "a shorter refresh interval shrinks the window (first preserved write ${EXPOSURE_FIRST_OK} s after the snapshot)"; else bad "a 1 s refresh interval left a window of ${EXPOSURE_FIRST_OK} s"; fi
    exposure_run "refresh 0 (never)" 0 ""
    note "hdr_refresh_ms = 0 means the writer never learns of the snapshot: $EXPOSURE_LEAKED of 20 writes overwrote it (documented behaviour)"

    # ORDERSNAP: another client (a second tool process, opened after the snapshot) writes an object with the NEW snapshot context; then
    # the first client, which still has the OLD one, writes the same object. With ORDERSNAP the OSD answers -EOLDSNAPC, the client
    # refreshes its header and resends; the snapshot must keep the old bytes either way.
    local img=$LRT_IMG_snap out="$WORK/sh.out" mode done_ops failed_ops done_with=0 failed_with=0 done_without=0 failed_without=0
    for mode in "with ORDERSNAP:--ordersnap" "without ORDERSNAP:"; do
        local lbl=${mode%%:*} flag=${mode#*:}
        RBD snap purge "$POOL/$img" >/dev/null 2>&1
        wr "$img" --rw discard 0 134217728 >/dev/null 2>&1
        # shellcheck disable=SC2086
        shell_start "$img" "$out" --rw --hdr-refresh 600000 $flag || { bad "$lbl: the shell did not start"; continue; }
        shell_cmd write 100663296 4096 --pattern byte:170; shell_cmd write 104857600 4096 --pattern byte:170
        RBD snap create "$POOL/$img@s2" >/dev/null 2>&1
        wr "$img" --rw write 100663296 4096 --pattern byte:204;  expect_rc 0 "EOLDSNAPC ($lbl): the other client writes object 24 with the new snapshot context"
        shell_cmd write 100663296 4096 --pattern byte:221
        [ "$SH_RC" = 0 ] && ok "EOLDSNAPC ($lbl): the stale-context write to object 24 completed" || bad "EOLDSNAPC ($lbl): the stale-context write failed (rc $SH_RC)"
        shell_cmd verify 100663296 4096 --pattern byte:221
        [ "$SH_RC" = 0 ] && ok "EOLDSNAPC ($lbl): the head of object 24 holds the stale client's bytes" || bad "EOLDSNAPC ($lbl): the head of object 24 is wrong (rc $SH_RC)"
        shell_end
        done_ops=$(sed -n 's/.* ops_done=\([0-9]*\) .*/\1/p' "$out" | tail -n 1); failed_ops=$(sed -n 's/.* ops_failed=\([0-9]*\) .*/\1/p' "$out" | tail -n 1)
        note "EOLDSNAPC ($lbl): ops_done=${done_ops:-?} ops_failed=${failed_ops:-?} (an -EOLDSNAPC answer, the header refresh it triggers and the resent write add to these)"
        if [ -n "$flag" ]; then done_with=${done_ops:-0}; failed_with=${failed_ops:-0}; else done_without=${done_ops:-0}; failed_without=${failed_ops:-0}; fi
        stock_export "$img" "$WORK/snap.bin" s2
        if [ "$(objbyte "$WORK/snap.bin" 24)" = 170 ]; then ok "EOLDSNAPC ($lbl): the snapshot kept the old bytes of object 24"; else bad "EOLDSNAPC ($lbl): the snapshot of object 24 holds $(objbyte "$WORK/snap.bin" 24)"; fi
        rm -f "$WORK/snap.bin" "$out"
        RBD snap purge "$POOL/$img" >/dev/null 2>&1
    done
    if [ $((done_with - done_without)) -ge 2 ] && [ $((failed_with - failed_without)) -ge 1 ]; then
        ok "ORDERSNAP: the OSD answered -EOLDSNAPC for the stale write and the client refreshed and resent it (ops_done +$((done_with - done_without)), ops_failed +$((failed_with - failed_without)))"
    else
        note "ORDERSNAP: no -EOLDSNAPC round trip seen (ops_done +$((done_with - done_without)), ops_failed +$((failed_with - failed_without))): the OSD accepted the stale write (it uses the object's newer snapshot context), so ORDERSNAP buys nothing here (R-C8)"
    fi
}

# ---- mtime -------------------------------------------------------------------------------------------------------------------------
sec_mtime() {
    sect "mtime: the wall clock and no wall clock ($CUR_LABEL)"
    local img=$LRT_IMG_snap so="$WORK/noclock.so" obj now_s m_s mt
    cat > "$WORK/noclock.c" <<'CEOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
/* A preload that makes the realtime clock fail: the tool then has no wall clock (wr_clock.wall_ms = 0). */
int clock_gettime(clockid_t id, struct timespec *ts)
{
	static int (*real)(clockid_t, struct timespec *);

	if (real == NULL)
		real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
	if (id == CLOCK_REALTIME) {
		errno = EINVAL;
		return -1;
	}
	return real(id, ts);
}
CEOF
    cc -shared -fPIC -o "$so" "$WORK/noclock.c" -ldl 2>/dev/null || { bad "mtime: cannot build the clock preload"; return; }
    # with the real clock
    wr "$img" --rw write 125829120 4096 --pattern byte:1; expect_rc 0 "write with the real wall clock"
    obj=$(printf 'rbd_data.%s.%016x' "$LRT_ID_snap" 30); now_s=$(date +%s)
    mt=$(RADOS -p "$POOL" stat "$obj" 2>/dev/null | sed -n 's/.* mtime \([^,]*\),.*/\1/p'); m_s=$(date -d "$mt" +%s 2>/dev/null || echo 0)
    note "mtime with the wall clock: $mt (now $(date -u +%FT%T))"
    if [ "$m_s" -gt 0 ] && [ $((now_s - m_s)) -le 120 ] && [ $((m_s - now_s)) -le 120 ]; then ok "the object's mtime is the wall clock (within 120 s)"; else bad "the object's mtime is not the wall clock: $mt"; fi
    # without a wall clock
    OUT=$(LD_PRELOAD="$so" timeout 300 "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" --rw write 130023424 4096 --pattern byte:2 2>&1); RC=$?
    expect_rc 0 "write with no wall clock at all (mtime 0) completes"
    obj=$(printf 'rbd_data.%s.%016x' "$LRT_ID_snap" 31)
    mt=$(RADOS -p "$POOL" stat "$obj" 2>/dev/null | sed -n 's/.* mtime \([^,]*\),.*/\1/p')
    note "mtime with no wall clock: $mt (rados prints a plain 0.000000 for the epoch)"
    case "$mt" in
        0|0.0*|1970-01-01*) ok "the OSD accepted a write that carried mtime 0 and stored it (Q4, R-C3: no wall clock is not an error)" ;;
        *) note "the OSD stored a different mtime for a write that carried 0: $mt" ;;
    esac
    wr "$img" verify 130023424 4096 --pattern byte:2; expect_rc 0 "the bytes of the no-clock write read back"
    rm -f "$so" "$WORK/noclock.c"
}

# ---- users ---------------------------------------------------------------------------------------------------------------------------
sec_users() {
    sect "users with other capabilities and the data-pool image"
    local img=$LRT_IMG_dp dpkr=$LRT_KEYRING_dp dpuser=$LRT_USER_dp f dpid
    dpid=$(CEPH osd pool ls detail --format json | python3 -I -c 'import json,sys; n=sys.argv[1]; print([p["pool_id"] for p in json.load(sys.stdin) if p["pool_name"]==n][0])' "$LRT_DP_POOL")
    wru "$dpuser" "$dpkr" "$img" --data-pool "$LRT_DP_POOL" --rw info; expect_rc 0 "the data-pool image opens (user with caps on both pools)"
    expect_out 'features=0x81 ' "... features 0x81 (layering, data-pool)"
    expect_out "data_pool_id=$dpid " "... the data pool id is the extra pool's"
    wru "$dpuser" "$dpkr" "$img" --data-pool "$LRT_DP_POOL" --rw fill 0 8M --pattern rand:55; expect_rc 0 "fill the data-pool image"
    wru "$dpuser" "$dpkr" "$img" --data-pool "$LRT_DP_POOL" verify 0 8M --pattern rand:55; expect_rc 0 "verify it"
    f="$WORK/dpexp.bin"; stock_export "$img" "$f"
    py build "$WORK/dpexpect.bin" zero:33554432 0:8388608:rand:55
    if cmp -s "$f" "$WORK/dpexpect.bin"; then ok "the stock export of the data-pool image equals what was written"; else bad "the stock export of the data-pool image differs: $(py cmp "$f" "$WORK/dpexpect.bin")"; fi
    local n_dp n_md
    n_dp=$(RADOS -p "$LRT_DP_POOL" ls 2>/dev/null | grep -c "^rbd_data\."); n_md=$(RADOS -p "$POOL" ls 2>/dev/null | grep "^rbd_data\." | grep -c "$LRT_ID_dp")
    if [ "$n_dp" -ge 2 ] && [ "$n_md" -eq 0 ]; then ok "the data objects are in the data pool ($n_dp) and none in the image pool"; else bad "data objects: $n_dp in the data pool, $n_md in the image pool"; fi
    rm -f "$f" "$WORK/dpexpect.bin"
    # the ordinary lab user has no caps on the extra pool: the open works (metadata), the data I/O is refused
    wr "$img" --data-pool "$LRT_DP_POOL" --rw --run-timeout 40000 write 0 4096 --pattern byte:9
    note "the lab user writing to a pool it has no caps on: exit $RC, $(printf '%s\n' "$OUT" | grep -E ' error | result write' | head -n 2 | cut -c1-200 | tr '\n' ' ')"
    if [ "$RC" -ne 0 ]; then ok "a write to a pool outside the user's caps does not succeed"; else bad "a write succeeded on a pool the user has no caps for"; fi

    # a READ that the OSD refuses is an error, never zeros (only a missing object reads as zeros)
    wr "$img" --data-pool "$LRT_DP_POOL" --run-timeout 40000 verify 0 4096 --pattern zero
    if [ "$RC" -eq 4 ] && printf '%s\n' "$OUT" | grep -q 'WR_E_OSD_PERM' && ! printf '%s\n' "$OUT" | grep -q 'result verify ok=1'; then ok "a read of a pool outside the user's caps fails with WR_E_OSD_PERM (it does not read as zeros)"; else bad "a read of a pool the user has no caps for: exit $RC (wanted 4 with WR_E_OSD_PERM)"; fi

    wru "$LRT_USER_nocls" "$LRT_KEYRING_nocls" "$LRT_IMG_p1a" --timeout 20000 info
    note "a user without class access: exit $RC, $(printf '%s\n' "$OUT" | grep ' result open ' | cut -c1-240)"
    if [ "$RC" -eq 3 ]; then ok "a user without class access cannot open an image"; else bad "a user without class access: exit $RC"; fi
    wru "$LRT_USER_noosd" "$LRT_KEYRING_noosd" "$LRT_IMG_p1a" --timeout 8000 info
    note "a user without OSD caps: exit $RC, $(printf '%s\n' "$OUT" | grep -E ' result open |IO_STALL' | head -n 3 | cut -c1-240 | tr '\n' ' ')"
    if [ "$RC" -eq 3 ]; then ok "a user without OSD caps cannot open an image (the authorizer is refused)"; else bad "a user without OSD caps: exit $RC"; fi
    wru "$LRT_USER_ro" "$LRT_KEYRING_ro" "$LRT_IMG_p1a" --rw --run-timeout 40000 write 0 4096 --pattern byte:9
    note "a read-only user writing: exit $RC, $(printf '%s\n' "$OUT" | grep -E ' error | result write' | head -n 2 | cut -c1-240 | tr '\n' ' ')"
    if [ "$RC" -eq 4 ] && printf '%s\n' "$OUT" | grep -q 'WR_E_OSD_PERM'; then ok "a read-only user: the write is refused with WR_E_OSD_PERM, the image stays open"; else bad "a read-only user's write: exit $RC (wanted 4 with WR_E_OSD_PERM)"; fi
    wru "$LRT_USER_ro" "$LRT_KEYRING_ro" "$LRT_IMG_p1a" read 0 1000; expect_rc 0 "a read-only user reads"
}

# ---- run ----------------------------------------------------------------------------------------------------------------------------
run_key() { # <label> <user> <keyring> <seed offset>
    CUR_LABEL=$1; CUR_USER=$2; CUR_KR=$3; KEY_SEED=$4
    echo; echo "##### key type $CUR_LABEL: client.$CUR_USER"
    want refusals && sec_refusals
    want reads && sec_reads
    want writes && sec_writes
    want random && sec_random
    want geometry && sec_geometry
    if [ "$skip_faults" -eq 0 ]; then
        want kill && sec_kill
        want outin && sec_outin
        want stall && [ "$CUR_LABEL" = k2 ] && sec_stall
    fi
}

if [ "$prepare" -eq 1 ] && want reads; then CUR_LABEL=oracle; sec_oracle; fi
if [ -n "$KR_K2" ]; then run_key k2 "$USER_K2" "$KR_K2" 0; fi
if [ -n "$KR_K1" ]; then run_key k1 "$USER_K1" "$KR_K1" 100; fi
# once, with the first key available
if [ -n "$KR_K2" ]; then CUR_LABEL=k2 CUR_USER=$USER_K2 CUR_KR=$KR_K2; else CUR_LABEL=k1 CUR_USER=$USER_K1 CUR_KR=$KR_K1; fi
want snapshot && sec_snapshot
want mtime && sec_mtime
want users && sec_users

if [ "$run_ctest" -eq 1 ]; then
    sect "ctest lab.rbd"
    export WR_RBD=$WR WR_LAB_MON=$MON WR_LAB_RBD_IMAGE=$LRT_IMG_p1b
    [ -z "$KR_K2" ] || export WR_LAB_USER_K2=$USER_K2 WR_LAB_KEYRING_K2=$KR_K2
    [ -z "$KR_K1" ] || export WR_LAB_USER_K1=$USER_K1 WR_LAB_KEYRING_K1=$KR_K1
    if ctest --test-dir "$build" -R '^lab\.rbd$' --output-on-failure; then ok "ctest lab.rbd"; else bad "ctest lab.rbd"; fi
fi

# ---- the cluster is back where it started ----------------------------------------------------------------------------------------------
sect "state of the cluster"
ensure_osds_running
do_cleanup
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
if [ "$END_STATE" = "$BASE_STATE" ]; then ok "the cluster state equals the baseline (every OSD up and in, no upmaps, the same health)"; else bad "the cluster state differs from the baseline"; fi
END_PGS=$(CEPH pg stat 2>/dev/null | sed -n 's/^\([0-9]* pgs\): \([0-9]* active+clean\).*/\1 \2/p')
if [ "$END_PGS" = "$BASE_PGS" ]; then ok "every placement group is active+clean ($END_PGS)"; elif [ "$keep" -eq 1 ] || [ "$prepare" -eq 0 ]; then note "pgs: was '$BASE_PGS', now '$END_PGS' (the test pool is still there: --keep / --no-prepare)"; else bad "pgs: was '$BASE_PGS', now '$END_PGS'"; fi

echo
echo "live-rbd: $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then printf '  failed: %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
