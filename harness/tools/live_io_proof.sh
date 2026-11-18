#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# live_io_proof.sh: the image I/O proof of Phase 1 milestones 6 to 8 against the REAL lab cluster, the stock rbd / rados tools as the
# oracle (docs/design/core-architecture.md 30.4 and 31.3). It complements harness/lab/live-rbd.sh (one fixed set of images) and
# harness/tools/osd_fault_lab.sh (OSD and map faults): this script runs the same engine over a MATRIX of image geometries and adds the
# cut-connection run and a few more refusals and snapshot checks. Sections:
#
#   matrix    images of different sizes (none a multiple of the object size, one smaller than an object), object orders 12, 16, 18, 22
#             and 25 and the writer feature sets 0x1 and 0x21; for each: the empty image reads as zeros, `rbd bench` writes (the stock
#             tool writes, the core reads: the whole image sequentially in three request shapes, and through the `read` command into a
#             file, all byte for byte against `rbd export`), random unaligned cross-object I/O by the core against its model (many
#             requests in flight, overlapping ones too), edge writes (the last byte, a range across the boundary of the last partial
#             object, a range across three objects, discard of a whole object, write-zeroes across a boundary), then `rbd export` must
#             equal the expected content (built independently in python) byte for byte, the core reads the new export back, individual
#             objects read by `rados get` equal the core's slice, and a second round of stock writes is read back by the core
#   tcpcut    the core's OWN sockets (found by process id, destroyed one 4-tuple at a time with `ss -K`) are cut again and again while a
#             long random workload runs: monitor session only, OSD sessions only, both; every request must complete exactly once with
#             the right data (final comparison with the model and with `rbd export`), and the resends are counted
#   refusals  journaling image (writer refused with WR_E_RBD_FEATURES, reader reads it byte for byte), object-map / fast-diff image
#             (reader only), a clone (WR_E_RBD_PARENT, and after `rbd flatten` it opens and reads), an encrypted image (not detectable:
#             opens as raw bytes, as documented), a read-only open (the tool refuses a write without --rw), and the lab's own img-v1 and
#             img-default (4 GiB, only READ: the core's read equals the stock export)
#   snap      an image with snapshots: the core writes, every snapshot still exports its old content, the head equals the expected content
#
# Everything it creates is named wrtest-iop-* (images) and is removed again. It never touches another image, pool or user. The cluster
# is not changed otherwise (no OSD is stopped here). Run it inside the lab VM, after building the harness there:
#     cmake -S harness -B build/harness -DCMAKE_BUILD_TYPE=Release && cmake --build build/harness -j
#     WR_BUILD_DIR=build/harness harness/tools/live_io_proof.sh
# Keep the keyrings OUTSIDE the repository (default ~/keys, mode 600); wr-rbd reads them, nothing prints them.
#
# Options:
#   --keys k2|k1|both   cephx key types (default both: client.winrbd aes256k runs everything, client.winrbd-aes legacy aes a lighter matrix)
#   --only a,b,...      sections: matrix tcpcut refusals snap (default all)
#   --quick             fewer operations, no 2 GiB image
#   --keep              do not remove the images at the end
#
# Environment: WR_BUILD_DIR, WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd), WR_LAB_KEYRING_DIR (~/keys), WR_LAB_USER_K2 (winrbd),
# WR_LAB_USER_K1 (winrbd-aes), WR_LAB_WORK (~/w/iop-run), WR_LAB_SUDO (sudo).
#
# Exit status: 0 when every check passed, 1 when any failed, 2 for a setup problem.

set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
build=${WR_BUILD_DIR:-$repo/build/harness}
WR=$build/wr-rbd
MON=${WR_LAB_MON:-10.77.0.10:3300}
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/iop-run}
SUDO=${WR_LAB_SUDO:-sudo}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
USER_K2=${WR_LAB_USER_K2:-winrbd}
USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
PFX=wrtest-iop-

die()  { echo "live_io_proof: error: $*" >&2; exit 2; }
info() { echo "live_io_proof: $*" >&2; }

keys=both; only=""; quick=0; keep=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keys) keys=${2:-}; shift ;;
        --only) only=${2:-}; shift ;;
        --quick) quick=1 ;;
        --keep) keep=1 ;;
        -h|--help) sed -n '3,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
case "$keys" in k2|k1|both) ;; *) die "--keys takes k2, k1 or both" ;; esac
case "$WORK" in /*) ;; *) die "WR_LAB_WORK must be an absolute path" ;; esac
case "$WORK" in *' '*|*'*'*|*'?'*) die "WR_LAB_WORK must not contain spaces or glob characters" ;; esac
if [ -n "$only" ]; then
    for w in $(echo "$only" | tr ',' ' '); do
        case "$w" in matrix|tcpcut|refusals|snap) ;; *) die "--only takes matrix, tcpcut, refusals, snap (got '$w')" ;; esac
    done
fi
want() { [ -z "$only" ] && return 0; case ",$only," in *",$1,"*) return 0 ;; esac; return 1; }

[ -x "$WR" ] || die "$WR not found: build the harness first (see --help)"
command -v python3 >/dev/null || die "python3 is needed"
$SUDO -n true 2>/dev/null || die "passwordless sudo is needed for the stock CLI"
RBD()   { $SUDO rbd "$@"; }
RADOS() { $SUDO rados -p "$POOL" "$@"; }
CEPH()  { $SUDO ceph "$@"; }

find_keyring() { local f; for f in "$KEYDIR/client.$1.keyring" "$KEYDIR/ceph.client.$1.keyring"; do [ -f "$f" ] && { echo "$f"; return 0; }; done; return 1; }
KR_K2=$(find_keyring "$USER_K2") || KR_K2=""
KR_K1=$(find_keyring "$USER_K1") || KR_K1=""
for kr in "$KR_K2" "$KR_K1"; do
    [ -n "$kr" ] || continue
    case "$(cd "$(dirname "$kr")" && pwd -P)/" in "$repo"/*) die "keyring $kr is inside the repository; keep keys outside it" ;; esac
done
case "$keys" in k2) KR_K1="" ;; k1) KR_K2="" ;; esac
[ -n "$KR_K2$KR_K1" ] || die "no keyring found (WR_LAB_KEYRING_DIR)"

first=${MON%%[, ;]*}; first=${first#\[}; first=${first#v2:}
mon_host=${first%:*}; mon_port=${first##*:}
[ "$mon_port" != "$first" ] || { mon_port=3300; mon_host=$first; }
timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$mon_host" "$mon_port" 2>/dev/null || die "cannot reach $mon_host:$mon_port: run this inside the lab VM"

# ---- reporting --------------------------------------------------------------------------------------------------------------------
PASS=0; FAIL=0; FAILED=(); OUT=""; RC=0
BYTES_CORE=0      # bytes the core read and compared with a stock export / a model
BYTES_EXPORT=0    # bytes of stock exports compared with the expected content
N_WORKLOADS=0; N_OPS=0; RESENT=0; RESETS=0; OPS_DONE=0; OPS_FAILED=0; CUTS=0; MISMATCH=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); echo "FAIL  $*"; if [ -n "$OUT" ]; then printf '%s\n' "$OUT" | tail -n 6 | cut -c1-300 | sed 's/^/      | /'; fi; }
note() { echo "NOTE  $*"; }
sect() { echo; echo "=== $* ==="; }
expect_rc()  { if [ "$RC" -eq "$1" ]; then ok "$2"; else bad "$2 (exit $RC, wanted $1)"; fi; }
expect_out() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then ok "$2"; else bad "$2 (no match for: $1)"; fi; }
statf() { printf '%s\n' "$OUT" | sed -n "s/.* stats .*$1=\([0-9]*\).*/\1/p" | tail -n 1; }
add_stats() { # fold the stats line of $OUT into the totals
    local v
    v=$(statf ops_resent); RESENT=$((RESENT + ${v:-0}))
    v=$(statf session_resets); RESETS=$((RESETS + ${v:-0}))
    v=$(statf ops_done); OPS_DONE=$((OPS_DONE + ${v:-0}))
    v=$(statf ops_failed); OPS_FAILED=$((OPS_FAILED + ${v:-0}))
}

CUR_USER=""; CUR_KR=""; CUR_LABEL=""
wr() { # <image> <args...>: run the tool as the current user; sets OUT and RC
    local img=$1; shift
    OUT=$(timeout "${WR_TMO:-1500}" "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" "$@" 2>&1); RC=$?
    add_stats
}

mkdir -p "$WORK" && chmod 700 "$WORK"
cat > "$WORK/iopy.py" <<'PYEOF'
# SPDX-License-Identifier: MIT
# iopy.py: the expected side of live_io_proof.sh. The pattern functions are the ones wr-rbd documents (zero, byte:N, seq, offset,
# rand:SEED), written here independently of the C code.
#   iopy.py patch FILE SEG...   write segments into FILE in place;  SEG = OFF:LEN:KIND[:ARG]  KIND = zero | byte | rand | file (LEN - = all)
import struct, sys
M = (1 << 64) - 1
def mix64(x):
    x = (x + 0x9e3779b97f4a7c15) & M
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & M
    return x ^ (x >> 31)
def words(fn, off, n):
    out = bytearray()
    for w in range(off >> 3, (off + n + 7) >> 3):
        out += struct.pack('<Q', fn(w))
    s = off & 7
    return bytes(out[s:s + n])
def pat(kind, arg, off, n):
    if kind == 'zero': return bytes(n)
    if kind == 'byte': return bytes([arg & 255]) * n
    if kind == 'rand': return words(lambda w: mix64((arg * 0x2545f4914f6cdd1d + w) & M), off, n)
    raise SystemExit('bad pattern ' + kind)
def patch(fn, segs):
    f = open(fn, 'r+b')
    f.seek(0, 2); size = f.tell()
    for s in segs:
        p = s.split(':', 3); off, kind = int(p[0]), p[2]
        if kind == 'file':
            data = open(p[3], 'rb').read()
            if p[1] != '-': data = data[:int(p[1])]
            f.seek(off); f.write(data); end = off + len(data)
        else:
            n = int(p[1]); end = off + n; step = 1 << 22
            for o in range(off, off + n, step):
                m = min(step, off + n - o)
                if o + m > size: raise SystemExit('segment past the end: ' + s)
                f.seek(o); f.write(pat(kind, int(p[3], 0) if len(p) > 3 else 0, o, m))
        if end > size: raise SystemExit('segment past the end: ' + s)
    f.close()
if sys.argv[1] == 'patch': patch(sys.argv[2], sys.argv[3:])
else: raise SystemExit('unknown command')
PYEOF
py() { python3 -I "$WORK/iopy.py" "$@"; }

# ---- the baseline and the clean-up ------------------------------------------------------------------------------------------------
health_snapshot() {
    echo "osd: $(CEPH osd stat 2>/dev/null | sed -n 's/^\([0-9]*\) osds: \([0-9]*\) up.*, \([0-9]*\) in.*/\1 osds \2 up \3 in/p') | upmaps: $(CEPH osd dump 2>/dev/null | grep -c '^pg_upmap') | pgs: $(CEPH pg stat 2>/dev/null | sed -n 's/^\([0-9]* pgs\):.*/\1/p')"
}
BASE_STATE=$(health_snapshot)
BASE_IMAGES=$(RBD ls "$POOL" 2>/dev/null | sort | tr '\n' ' ')
info "baseline: $BASE_STATE; images: $BASE_IMAGES"

CLEANED=0
remove_images() { # every wrtest-iop-* image: snapshots purged, clones before parents
    local i s
    [ "$keep" -eq 0 ] || return 0
    for i in $(RBD ls "$POOL" 2>/dev/null | grep "^$PFX"); do
        for s in $(RBD children "$POOL/$i" 2>/dev/null | grep "/$PFX"); do RBD rm "$s" >/dev/null 2>&1; done
    done
    for i in $(RBD ls "$POOL" 2>/dev/null | grep "^$PFX"); do
        RBD snap ls "$POOL/$i" --format json 2>/dev/null | python3 -I -c 'import sys,json
for s in json.load(sys.stdin): print(s["name"])' | while read -r s; do
            RBD snap unprotect "$POOL/$i@$s" >/dev/null 2>&1; RBD snap rm "$POOL/$i@$s" >/dev/null 2>&1
        done
        RBD rm "$POOL/$i" >/dev/null 2>&1
    done
}
BG_PID=""
cleanup() {
    local rc=$?
    [ -n "$BG_PID" ] && kill "$BG_PID" 2>/dev/null
    [ "$CLEANED" -eq 1 ] && return $rc
    CLEANED=1
    remove_images
    [ "$keep" -eq 1 ] || rm -rf "${WORK:?}/"*.bin "${WORK:?}/"*.out 2>/dev/null
    return $rc
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
RBD ls "$POOL" 2>/dev/null | grep -q "^$PFX" && die "images named $PFX* exist already (an earlier run?): remove them first"

jf() { python3 -I -c 'import sys,json; print(json.load(sys.stdin)[sys.argv[1]])' "$1"; } # field of `rbd info --format json` on stdin
mk_image() { # <name> <bytes> <order> <features> -> creates it; prints nothing
    RBD create "$POOL/$PFX$1" --size "${2}B" --order "$3" --image-feature "$4" >/dev/null 2>&1
}
export_to() { # <image[@snap]> <file>: the stock export as a sparse file (the tool refuses an existing file)
    rm -f "$2"
    RBD export "$POOL/$1" "$2" >/dev/null 2>&1 || { echo "NOTE  rbd export of $1 failed"; return 1; }
}

# ---- section: matrix ----------------------------------------------------------------------------------------------------------------
edge_ops() { # <image> <size> <obj>: edge writes through the core; SEGS gets the expected content of each
    local img=$1 S=$2 O=$3 L off len
    SEGS=()
    put() { # off len kind arg
        wr "$img" --rw write "$1" "$2" --pattern "$3${4:+:$4}"
        if [ "$RC" -ne 0 ]; then bad "edge write $1+$2 ($3) failed (exit $RC)"; fi
        SEGS+=("$1:$2:$3${4:+:$4}")
    }
    zer() { # off len mode(discard|zeroes)
        wr "$img" --rw "$3" "$1" "$2"
        if [ "$RC" -ne 0 ]; then bad "edge $3 $1+$2 failed (exit $RC)"; fi
        SEGS+=("$1:$2:zero")
    }
    put $((S - 1)) 1 byte 90
    if [ "$S" -lt "$O" ]; then
        put 0 "$S" rand 43; zer 1000 200 discard
    else
        L=$((S / O * O))
        len=$((S - L + 3)); [ "$S" -gt "$L" ] && put $((L - 3)) "$len" rand 43
        if [ "$S" -ge $((O + 40)) ]; then put $((O - 7)) 33 rand 41; fi
        if [ "$S" -ge $((3 * O)) ]; then
            len=$((2 * O + 1001)); [ "$len" -gt 6291469 ] && len=6291469
            off=$((O + O / 2 + 3 - len / 2)); [ "$off" -lt 0 ] && off=3
            put "$off" "$len" rand 42
        fi
        if [ "$S" -ge $((4 * O + 200)) ]; then zer "$O" "$O" discard; zer $((2 * O + 5)) 100 zeroes; fi
        if [ "$S" -ge $((O + 40)) ]; then zer $((O - 9)) 18 zeroes; fi
        put $((S * 3 / 4 - 11)) 4099 rand 44
    fi
}

matrix_image() { # <name> <bytes> <order> <features> <ops> <seed> <depth> [rand-model-bytes]
    local name=$1 size=$2 order=$3 feat=$4 ops=$5 seed=$6 depth=$7 mb=${8:-} img="$PFX$1" obj real_size real_order real_feat info bench_io bench_tot n lbl
    local X0="$WORK/x0.bin" X1="$WORK/x1.bin" X2="$WORK/x2.bin" X3="$WORK/x3.bin" EXP="$WORK/exp.bin" MOD="$WORK/model.bin" RD="$WORK/rd.bin"
    obj=$((1 << order)); lbl="$CUR_LABEL $name"
    mk_image "$name" "$size" "$order" "$feat" || { bad "$lbl: rbd create failed"; return; }
    info=$(RBD info "$POOL/$img" --format json)
    real_size=$(printf '%s' "$info" | jf size); real_order=$(printf '%s' "$info" | jf order); real_feat=$(printf '%s' "$info" | jf features)
    size=$real_size
    [ -n "$mb" ] || mb=$size; [ "$mb" -gt "$size" ] && mb=$size; [ "$mb" -gt 100663296 ] && mb=100663296
    echo "---- $lbl: $size bytes, $((size / obj)) whole objects + $((size % obj)) bytes, order $real_order, $(printf '%s' "$info" | jf features) ----"
    wr "$img" --rw info; expect_rc 0 "$lbl: opens as a writer"
    expect_out "size=$size .*order=$real_order object_size=$obj " "$lbl: the core reads size $size and order $real_order like rbd info"

    # 1. an empty image: holes read as zeros, and the export is a sparse file of zeros
    export_to "$img" "$X0"
    wr "$img" compare "$X0"; expect_rc 0 "$lbl: the empty image equals the stock export (holes read as zeros)"; BYTES_CORE=$((BYTES_CORE + size)); N_WORKLOADS=$((N_WORKLOADS+1))
    # 2. the stock tool writes (rbd bench, random places), the core reads
    bench_io=65536; [ "$obj" -lt "$bench_io" ] && bench_io=$obj
    while [ "$bench_io" -gt "$size" ]; do bench_io=$((bench_io / 2)); done # the stock bench refuses an I/O larger than the image
    bench_tot=$((size / 3)); [ "$bench_tot" -gt 25165824 ] && bench_tot=25165824
    [ "$bench_tot" -lt "$bench_io" ] && bench_tot=$bench_io
    RBD bench --io-type write --io-size "$bench_io" --io-threads 4 --io-total "$bench_tot" --io-pattern rand "$POOL/$img" >/dev/null 2>&1 || bad "$lbl: rbd bench failed"
    export_to "$img" "$X1"
    wr "$img" compare "$X1"; expect_rc 0 "$lbl: after rbd bench writes, the core's whole-image read equals the stock export (128K x 8)"; BYTES_CORE=$((BYTES_CORE + size))
    if [ "$size" -le 400000000 ]; then wr "$img" --io-size 4096 --depth 1 compare "$X1" ; expect_rc 0 "$lbl: ... in 4 KiB requests, one at a time"; BYTES_CORE=$((BYTES_CORE + size)); fi
    wr "$img" --io-size 8M --depth 4 compare "$X1"; expect_rc 0 "$lbl: ... in 8 MiB requests, 4 in flight"; BYTES_CORE=$((BYTES_CORE + size)); N_WORKLOADS=$((N_WORKLOADS+2))
    if [ "$size" -le 400000000 ]; then
        rm -f "$RD"; wr "$img" read 0 "$size" "$RD"; expect_rc 0 "$lbl: read 0..end into a file"
        if cmp -s "$RD" "$X1"; then ok "$lbl: that file equals the stock export byte for byte"; else bad "$lbl: the file read through the core differs from the stock export: $(cmp "$RD" "$X1" 2>&1 | head -1)"; fi
        BYTES_CORE=$((BYTES_CORE + size)); rm -f "$RD"
    fi
    # 3. the core writes: random unaligned cross-object I/O against its model, then edge writes
    rm -f "$MOD"
    wr "$img" --rw --depth "$depth" --overlap --model-bytes "$mb" --op-timeout 20000 random "$ops" "$seed" --save "$MOD"
    expect_rc 0 "$lbl: random $ops ops, depth $depth, overlapping, model $mb bytes"
    expect_out 'result random ok=1 .* read_mismatches=0 final_diff_bytes=0 errors=0' "$lbl: zero differences against the model (every read and the final read-back)"
    echo "      $(printf '%s\n' "$OUT" | grep ' result random ' | sed 's/.*result random //' | cut -c1-200)"
    N_OPS=$((N_OPS + ops)); N_WORKLOADS=$((N_WORKLOADS+1)); BYTES_CORE=$((BYTES_CORE + 2 * mb))
    edge_ops "$img" "$size" "$obj"
    # 4. the stock export equals the expected content, built independently
    export_to "$img" "$X2"
    rm -f "$EXP"; cp --sparse=always "$X1" "$EXP"
    py patch "$EXP" "0:-:file:$MOD" "${SEGS[@]}" || { bad "$lbl: the expected content could not be built"; return; }
    if cmp -s "$EXP" "$X2"; then ok "$lbl: the stock export equals the expected content ($size bytes: stock writes + model + ${#SEGS[@]} edge writes)"; else bad "$lbl: the stock export differs from the expected content: $(cmp "$EXP" "$X2" 2>&1 | head -1)"; MISMATCH=$((MISMATCH+1)); fi
    BYTES_EXPORT=$((BYTES_EXPORT + size))
    wr "$img" compare "$X2"; expect_rc 0 "$lbl: the core reads the written image back equal to the stock export"; BYTES_CORE=$((BYTES_CORE + size)); N_WORKLOADS=$((N_WORKLOADS+1))
    # 5. single objects: `rados get` of the last object and of one in the middle against the core's slice of the export
    local pre id k off2 want
    pre=$(printf '%s' "$info" | jf block_name_prefix)
    for k in $(( (size - 1) / obj )) $(( size / obj / 2 )); do
        off2=$((k * obj)); want=$obj; [ $((off2 + want)) -gt "$size" ] && want=$((size - off2))
        rm -f "$WORK/obj.bin" "$WORK/slice.bin" "$WORK/slice2.bin"
        if RADOS get "$pre.$(printf '%016x' "$k")" "$WORK/obj.bin" >/dev/null 2>&1; then :; else : > "$WORK/obj.bin"; fi
        # an object may be shorter than its extent: the rest of the extent is zeros
        python3 -I - "$WORK/obj.bin" "$want" "$WORK/slice.bin" <<'PYEOF'
import sys
d = open(sys.argv[1], 'rb').read(); n = int(sys.argv[2])
open(sys.argv[3], 'wb').write(d[:n] + bytes(n - len(d[:n])))
PYEOF
        wr "$img" read "$off2" "$want" "$WORK/slice2.bin"
        if [ "$RC" -eq 0 ] && cmp -s "$WORK/slice.bin" "$WORK/slice2.bin"; then ok "$lbl: object $k: rados get (zero-extended) equals the core's read of its extent ($want bytes)"; else bad "$lbl: object $k: rados get differs from the core's read"; fi
        BYTES_CORE=$((BYTES_CORE + want))
    done
    rm -f "$WORK/obj.bin" "$WORK/slice.bin" "$WORK/slice2.bin"
    # 6. the stock tool writes again over the core's content; the core reads that
    RBD bench --io-type write --io-size "$bench_io" --io-threads 4 --io-total "$bench_tot" --io-pattern rand "$POOL/$img" >/dev/null 2>&1 || bad "$lbl: the second rbd bench failed"
    export_to "$img" "$X3"
    wr "$img" --depth 16 compare "$X3"; expect_rc 0 "$lbl: stock writes over the core's content: the core reads the stock export back (depth 16)"; BYTES_CORE=$((BYTES_CORE + size)); N_WORKLOADS=$((N_WORKLOADS+2))
    rm -f "$X0" "$X1" "$X2" "$X3" "$EXP" "$MOD"
    RBD rm "$POOL/$img" >/dev/null 2>&1
}

sec_matrix() {
    local full=$1 ops=900 ops_big=300
    [ "$quick" -eq 1 ] && { ops=300; ops_big=120; }
    sect "matrix of image geometries ($CUR_LABEL)"
    S=$((CUR_SEED))
    # name          size                order features             ops      seed       depth model-bytes
    matrix_image m64k  $((7 * 1048576 + 777))      16 layering,deep-flatten "$ops"     $((101 + S)) 16
    matrix_image tiny  3000                        22 layering,deep-flatten 120        $((102 + S)) 4
    matrix_image m4k   $((2 * 1048576 + 513))      12 layering              "$ops"     $((103 + S)) 32
    [ "$full" -eq 1 ] || return 0
    matrix_image m256k $((33 * 1048576 + 1))       18 layering              "$ops"     $((104 + S)) 16 $((33 * 1048576 + 1))
    matrix_image m4m   $((100 * 1048576 + 12345))  22 layering,deep-flatten "$ops"     $((105 + S)) 16 50331648
    matrix_image m32m  $((300 * 1048576 + 4097))   25 layering              "$ops_big" $((106 + S)) 8  100663296
    matrix_image big1g $((1024 * 1048576 + 4097))  22 layering,deep-flatten "$ops_big" $((107 + S)) 16 33554432
    [ "$quick" -eq 1 ] || matrix_image big2g $((2048 * 1048576)) 22 layering "$ops_big" $((108 + S)) 8 33554432
}

# ---- section: tcpcut ----------------------------------------------------------------------------------------------------------------
sockets_of() { # <pid>: "local remote" of every established socket of the process
    $SUDO ss -tnpH state established 2>/dev/null | awk -v p="pid=$1," 'index($0, p) { print $3, $4 }'
}
cut_own() { # <pid> <scope>
    local n=0 l r rp
    while read -r l r; do
        [ -n "$l" ] || continue
        rp=${r##*:}
        case "$2" in mon) [ "$rp" = "$mon_port" ] || continue ;; osd) [ "$rp" != "$mon_port" ] || continue ;; esac
        if $SUDO ss -K -tn src "$l" dst "$r" >/dev/null 2>&1; then n=$((n+1)); fi
    done < <(sockets_of "$1")
    echo "$n"
}

tcpcut_run() { # <label> <image> <seed> <scope> <cycles> <ops>
    local lbl=$1 img=$2 seed=$3 scope=$4 cycles=$5 ops=$6 w log="$WORK/cut.out" model="$WORK/cmodel.bin" exp="$WORK/cexp.bin" pid i c total=0 first=1 n v
    rm -f "$model" "$log"
    # no `timeout` in front: the process id must be the tool's own, it is how its sockets are found
    "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" --rw --depth 32 --overlap --op-timeout 20000 \
        random "$ops" "$seed" --save "$model" > "$log" 2>&1 &
    pid=$!; BG_PID=$pid
    sleep 3
    for ((i = 0; i < cycles; i++)); do
        kill -0 "$pid" 2>/dev/null || break
        # the core connects again on demand: wait (at most 10 s) until it has sockets of the kind to cut
        for ((w = 0; w < 50; w++)); do
            kill -0 "$pid" 2>/dev/null || break
            sockets_of "$pid" | awk -v m="$mon_port" -v s="$scope" '{ n = split($2, a, ":"); p = a[n]; if (s == "all" || (s == "mon" && p == m) || (s == "osd" && p != m)) f = 1 } END { exit !f }' && break
            sleep 0.2
        done
        c=$(cut_own "$pid" "$scope"); total=$((total + c))
        [ "$c" -gt 0 ] || note "$lbl: cut $((i+1)): no socket of the process matched ($scope)"
        sleep 1.5
    done
    wait "$pid"; RC=$?; BG_PID=""
    OUT=$(cat "$log"); add_stats; CUTS=$((CUTS + total))
    expect_rc 0 "$lbl: the random run finished (exit code of wr-rbd) after $total sockets of its own were destroyed in $cycles rounds"
    expect_out 'result random ok=1 .* read_mismatches=0 final_diff_bytes=0 errors=0' "$lbl: zero differences against the model"
    echo "      $(printf '%s\n' "$OUT" | grep ' stats ' | sed 's/.* stats //' | cut -c1-300)"
    v=$(statf ops_resent); n=$(statf session_resets)
    if [ "$total" -gt 0 ] && [ "${v:-0}" -ge 1 ]; then ok "$lbl: requests were resent (ops_resent=$v, session_resets=${n:-0})"
    elif [ "$scope" = mon ] && [ "$total" -gt 0 ]; then note "$lbl: a monitor-only cut resends nothing (ops_resent=${v:-0}): the OSD sessions were not touched"
    else bad "$lbl: no resend seen although $total sockets were cut (ops_resent=${v:-0})"; fi
    v=$(statf barrier_violations); n=$(statf bad_completions)
    if [ "${v:-1}" -eq 0 ] && [ "${n:-1}" -eq 0 ]; then ok "$lbl: no request completed twice, no flush ahead of a write (bad_completions=0, barrier_violations=0)"; else bad "$lbl: contract violations (barrier=${v:-?}, bad=${n:-?})"; fi
    N_OPS=$((N_OPS + ops)); N_WORKLOADS=$((N_WORKLOADS+1)); BYTES_CORE=$((BYTES_CORE + 2 * 33554432))
    export_to "$img" "$WORK/cexport.bin"
    n=$(stat -c %s "$model")
    head -c "$n" "$WORK/cexport.bin" > "$exp"
    if cmp -s "$model" "$exp"; then ok "$lbl: the stock export equals the model ($n bytes)"; else bad "$lbl: the stock export differs from the model: $(cmp "$model" "$exp" 2>&1 | head -1)"; MISMATCH=$((MISMATCH+1)); fi
    BYTES_EXPORT=$((BYTES_EXPORT + n))
    rm -f "$model" "$exp" "$WORK/cexport.bin" "$log"
}

sec_tcpcut() {
    sect "the client's own connections cut under I/O ($CUR_LABEL)"
    local img=${PFX}cut ops=5000 cyc=12
    [ "$quick" -eq 1 ] && { ops=2500; cyc=5; }
    mk_image cut $((64 * 1048576 + 321)) 22 layering,deep-flatten || { bad "tcpcut: rbd create failed"; return; }
    tcpcut_run "tcp cut, OSD sessions ($CUR_LABEL)" "$img" $((201 + CUR_SEED)) osd "$cyc" "$ops"
    tcpcut_run "tcp cut, monitor session ($CUR_LABEL)" "$img" $((202 + CUR_SEED)) mon "$cyc" "$ops"
    tcpcut_run "tcp cut, every socket ($CUR_LABEL)" "$img" $((203 + CUR_SEED)) all $((cyc * 2)) $((ops * 2))
    RBD rm "$POOL/$img" >/dev/null 2>&1
}

# ---- section: refusals --------------------------------------------------------------------------------------------------------------
sec_refusals() {
    sect "refusals and read-only behaviour ($CUR_LABEL)"
    local img X="$WORK/r.bin" pf="$WORK/pass.txt"
    # journaling: a reader reads it, a writer is refused
    img=${PFX}jrn
    if RBD create "$POOL/$img" --size 8M --image-feature layering,exclusive-lock,journaling >/dev/null 2>&1; then
        RBD bench --io-type write --io-size 4096 --io-threads 2 --io-total 1M --io-pattern rand "$POOL/$img" >/dev/null 2>&1
        wr "$img" --rw info; expect_rc 3 "journaling image: refused as a writer"; expect_out 'WR_E_RBD_FEATURES' "... with WR_E_RBD_FEATURES"
        wr "$img" info; expect_rc 0 "journaling image: opens as a reader"; expect_out 'writable=0' "... read-only"
        export_to "$img" "$X"; wr "$img" compare "$X"; expect_rc 0 "journaling image: the reader equals the stock export"; BYTES_CORE=$((BYTES_CORE + 8388608))
        wr "$img" write 0 4096 --pattern byte:1; expect_rc 2 "journaling image: a write on the read-only open is refused by the tool before it reaches the engine"; expect_out "need --rw" "... saying why (a write needs --rw)"
        RBD rm "$POOL/$img" >/dev/null 2>&1
    else bad "cannot create a journaling image"; fi
    # object map + fast diff: reader only
    img=${PFX}omap
    if RBD create "$POOL/$img" --size 16M --image-feature layering,exclusive-lock,object-map,fast-diff >/dev/null 2>&1; then
        RBD bench --io-type write --io-size 8192 --io-threads 2 --io-total 2M --io-pattern rand "$POOL/$img" >/dev/null 2>&1
        wr "$img" --rw info; expect_rc 3 "object-map image: refused as a writer"; expect_out 'WR_E_RBD_FEATURES' "... with WR_E_RBD_FEATURES"
        export_to "$img" "$X"; wr "$img" compare "$X"; expect_rc 0 "object-map image: the reader equals the stock export (object map ignored, holes are zeros)"; BYTES_CORE=$((BYTES_CORE + 16777216))
        RBD rm "$POOL/$img" >/dev/null 2>&1
    else bad "cannot create an object-map image"; fi
    # a clone: refused; flattened it opens
    local par=${PFX}par cln=${PFX}cln
    if RBD create "$POOL/$par" --size 12M --image-feature layering,deep-flatten >/dev/null 2>&1; then
        RBD bench --io-type write --io-size 4096 --io-threads 2 --io-total 3M --io-pattern rand "$POOL/$par" >/dev/null 2>&1
        RBD snap create "$POOL/$par@s" >/dev/null 2>&1; RBD snap protect "$POOL/$par@s" >/dev/null 2>&1
        RBD clone "$POOL/$par@s" "$POOL/$cln" >/dev/null 2>&1
        wr "$cln" info; expect_rc 3 "clone: refused as a reader"; expect_out 'WR_E_RBD_PARENT' "... with WR_E_RBD_PARENT"
        wr "$cln" --rw info; expect_rc 3 "clone: refused as a writer"; expect_out 'WR_E_RBD_PARENT' "... with WR_E_RBD_PARENT"
        RBD flatten "$POOL/$cln" >/dev/null 2>&1
        wr "$cln" --rw info; expect_rc 0 "clone after rbd flatten: opens as a writer"
        export_to "$cln" "$X"; wr "$cln" compare "$X"; expect_rc 0 "clone after rbd flatten: the core reads the stock export (data copied up)"; BYTES_CORE=$((BYTES_CORE + 12582912))
        RBD rm "$POOL/$cln" >/dev/null 2>&1; RBD snap unprotect "$POOL/$par@s" >/dev/null 2>&1; RBD snap rm "$POOL/$par@s" >/dev/null 2>&1; RBD rm "$POOL/$par" >/dev/null 2>&1
    else bad "cannot create the parent image"; fi
    # an encrypted image cannot be told from a raw one: the core exposes the raw bytes (documented), and they equal the stock raw export
    img=${PFX}enc
    if RBD create "$POOL/$img" --size 16M --image-feature layering >/dev/null 2>&1; then
        printf 'live-io-proof-throwaway' > "$pf"; chmod 600 "$pf"
        if RBD encryption format "$POOL/$img" luks2 "$pf" >/dev/null 2>&1; then
            export_to "$img" "$X"
            wr "$img" --rw info; expect_rc 0 "encrypted (LUKS2) image: opens (the format is not detectable from the header)"
            wr "$img" compare "$X"; expect_rc 0 "encrypted image: the core reads the raw (ciphertext and LUKS header) bytes the stock raw export holds"; BYTES_CORE=$((BYTES_CORE + 16777216))
            head -c 4 "$X" | grep -q 'LUKS' && ok "encrypted image: the raw bytes start with the LUKS header (the guest would see this, as documented)" || note "the raw bytes do not start with LUKS magic"
        else note "rbd encryption format is not available here: the encryption note is skipped"; fi
        rm -f "$pf"; RBD rm "$POOL/$img" >/dev/null 2>&1
    fi
    # the lab's own images are only READ (format 1 images cannot be made any more: `rbd create --image-format 1` is refused by this release;
    # a missing image is the not-found path, tested in harness/lab/live-rbd.sh)
    local li
    for li in img-v1 img-default; do
        if RBD ls "$POOL" 2>/dev/null | grep -qx "$li"; then
            export_to "$li" "$X" && { wr "$li" compare "$X"; expect_rc 0 "the lab's $li (4 GiB, read-only use): the core's read equals the stock export"; BYTES_CORE=$((BYTES_CORE + 4294967296)); }
        fi
    done
    rm -f "$X"
}

# ---- section: snap -------------------------------------------------------------------------------------------------------------------
sec_snap() {
    sect "snapshots: the snapshot context of the writer ($CUR_LABEL)"
    local img=${PFX}snp S=$((9 * 1048576 + 1001)) O=65536 s1="$WORK/s1.bin" s2="$WORK/s2.bin" h="$WORK/h.bin" e="$WORK/e.bin" m1="$WORK/m1.bin" ex
    if ! mk_image snp "$S" 16 layering,deep-flatten; then bad "snap: rbd create failed"; return; fi
    RBD bench --io-type write --io-size 4096 --io-threads 2 --io-total 4M --io-pattern rand "$POOL/$img" >/dev/null 2>&1
    RBD snap create "$POOL/$img@s1" >/dev/null 2>&1; export_to "$img@s1" "$s1"
    wr "$img" --rw info; expect_rc 0 "an image with a snapshot opens as a writer"; expect_out 'n_snaps=1|snaps=1|snap' "... and the open knows the snapshot context"
    wr "$img" --rw --depth 16 --overlap --model-bytes "$S" random 600 301 --save "$m1"; expect_rc 0 "random writes with the snapshot context of s1"
    expect_out 'result random ok=1 .* final_diff_bytes=0' "... zero differences against the model"; N_OPS=$((N_OPS + 600)); BYTES_CORE=$((BYTES_CORE + 2 * S))
    export_to "$img@s1" "$e"
    if cmp -s "$s1" "$e"; then ok "the snapshot s1 still exports the content it had before the core's writes ($S bytes)"; else bad "snapshot s1 changed under the core's writes: $(cmp "$s1" "$e" 2>&1 | head -1)"; MISMATCH=$((MISMATCH+1)); fi
    BYTES_EXPORT=$((BYTES_EXPORT + S))
    export_to "$img" "$h"
    if cmp -s "$m1" "$h"; then ok "the head equals the model"; else bad "the head differs from the model: $(cmp "$m1" "$h" 2>&1 | head -1)"; MISMATCH=$((MISMATCH+1)); fi
    # a second snapshot, a new open (the new context), more writes
    RBD snap create "$POOL/$img@s2" >/dev/null 2>&1; export_to "$img@s2" "$s2"
    wr "$img" --rw write 70000 200000 --pattern rand:9; expect_rc 0 "a write across 4 objects after the second snapshot"
    wr "$img" --rw discard 0 262144; expect_rc 0 "a discard of the first 4 objects after the second snapshot"
    export_to "$img@s1" "$e"; cmp -s "$s1" "$e" && ok "s1 unchanged after the second round" || { bad "s1 changed in the second round"; MISMATCH=$((MISMATCH+1)); }
    export_to "$img@s2" "$e"; cmp -s "$s2" "$e" && ok "s2 unchanged after writes and a discard made with its context" || { bad "s2 changed in the second round"; MISMATCH=$((MISMATCH+1)); }
    BYTES_EXPORT=$((BYTES_EXPORT + 2 * S))
    rm -f "$e"; cp --sparse=always "$h" "$e"; py patch "$e" "70000:200000:rand:9" "0:262144:zero"
    export_to "$img" "$h"
    if cmp -s "$e" "$h"; then ok "the head equals the expected content after the second round"; else bad "the head differs after the second round: $(cmp "$e" "$h" 2>&1 | head -1)"; MISMATCH=$((MISMATCH+1)); fi
    BYTES_EXPORT=$((BYTES_EXPORT + S))
    RBD snap rollback "$POOL/$img@s1" >/dev/null 2>&1
    export_to "$img" "$h"; cmp -s "$s1" "$h" && ok "rbd snap rollback to s1 restores the head to s1's content (the stock tool, over what the core wrote)" || bad "rollback to s1 did not restore the content"
    wr "$img" compare "$h"; expect_rc 0 "the core reads the rolled-back head equal to the stock export"; BYTES_CORE=$((BYTES_CORE + S))
    rm -f "$s1" "$s2" "$h" "$e" "$m1"
    RBD snap purge "$POOL/$img" >/dev/null 2>&1; RBD rm "$POOL/$img" >/dev/null 2>&1
}

# ---- run ------------------------------------------------------------------------------------------------------------------------------
CUR_SEED=0
run_key() { # <label> <user> <keyring> <seed offset> <full matrix 1|0>
    CUR_LABEL=$1; CUR_USER=$2; CUR_KR=$3; CUR_SEED=$4
    echo; echo "################ key type $1 (client.$2) ################"
    want matrix && sec_matrix "$5"
    want tcpcut && sec_tcpcut
    want refusals && sec_refusals
    want snap && sec_snap
}
[ -z "$KR_K2" ] || run_key k2 "$USER_K2" "$KR_K2" 0 1
[ -z "$KR_K1" ] || run_key k1 "$USER_K1" "$KR_K1" 1000 0

# ---- the end --------------------------------------------------------------------------------------------------------------------------
sect "clean-up and the state of the cluster"
CLEANED=1; remove_images
left=$(RBD ls "$POOL" 2>/dev/null | grep -c "^$PFX")
if [ "$keep" -eq 1 ] || [ "$left" -eq 0 ]; then ok "no $PFX* image is left"; else bad "$left $PFX* images are left"; fi
END_STATE=$(health_snapshot); END_IMAGES=$(RBD ls "$POOL" 2>/dev/null | sort | tr '\n' ' ')
if [ "$keep" -eq 1 ]; then note "kept the images (--keep)"
elif [ "$END_STATE" = "$BASE_STATE" ] && [ "$END_IMAGES" = "$BASE_IMAGES" ]; then ok "cluster state and image list equal the baseline ($END_STATE)"
else bad "state differs: start '$BASE_STATE' / '$BASE_IMAGES', end '$END_STATE' / '$END_IMAGES'"; fi

echo
echo "SUMMARY workloads=$N_WORKLOADS ops_random=$N_OPS bytes_core_compared=$BYTES_CORE bytes_export_compared=$BYTES_EXPORT mismatches=$MISMATCH sockets_cut=$CUTS ops_done=$OPS_DONE ops_resent=$RESENT ops_failed=$OPS_FAILED session_resets=$RESETS"
echo "RESULT pass=$PASS fail=$FAIL"
if [ "$FAIL" -ne 0 ]; then printf 'FAILED: %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
