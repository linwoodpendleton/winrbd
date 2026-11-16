#!/bin/sh
# SPDX-License-Identifier: MIT
#
# run-all.sh - run every checker in harness/tools/ against the public vector set and print one summary.
#
# Usage:   harness/tools/run-all.sh [-v] [--serial]
#   -v        also print the full output of every checker (default: only the output of failing ones)
#   --serial  run one checker at a time (default: all eight in parallel)
#
# What it does:
#   1. runs harness/tools/fetch-ceph-ref.sh (a no-op when harness/.ceph-ref is already complete);
#   2. runs the eight checkers (msgr2, secure, cephx, monclient, osdmap, crush, osdop, rbd) with their defaults:
#      capture set harness/vectors/public, keys harness/vectors/public/keys, Ceph run-time data from
#      $WINRBD_CEPH_SRC or harness/.ceph-ref;
#   3. prints a table with passed / failed / skipped per checker, then the list of skipped checks and why.
#
# Exit status: 0 only if no checker failed (a skipped check is not a failure), 1 otherwise.
# Needs:   python3 with the 'cryptography' package, curl (first run only), POSIX sh and awk.
# Env:     PYTHON  interpreter to use (default python3)

set -u

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
py=${PYTHON:-python3}
verbose=0
serial=0
for a in "$@"; do
    case $a in
        -v) verbose=1 ;;
        --serial) serial=1 ;;
        -h|--help) sed -n '3,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "run-all: unknown argument: $a" >&2; exit 2 ;;
    esac
done

cd "$repo" || exit 2
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE

if ! "$py" -c 'import cryptography' >/dev/null 2>&1; then
    echo "run-all: $py cannot import 'cryptography' (pip install cryptography)" >&2
    exit 2
fi
# isolated mode (no user site, no current directory on the path) when the package is visible in it
if "$py" -I -c 'import cryptography' >/dev/null 2>&1; then
    pyflags=-I
else
    pyflags=-s
fi

if [ ! -d harness/vectors/public/pcap ]; then
    echo "run-all: harness/vectors/public/pcap is missing; is this a complete checkout?" >&2
    exit 2
fi

fetch_ok=1
echo "== Ceph run-time data"
if ! sh "$here/fetch-ceph-ref.sh" --quiet; then
    fetch_ok=0
    echo "run-all: fetching the Ceph run-time data failed; osdmap_check / crush_check will skip or fail" >&2
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/winrbd-run-all.XXXXXX") || exit 2
trap 'rm -rf "$tmp"' EXIT INT TERM

tools="msgr2_check secure_check cephx_check monclient_check osdmap_check crush_check osdop_check rbd_check"

run_one() {
    t=$1
    start=$(date +%s)
    "$py" $pyflags "$here/$t.py" > "$tmp/$t.out" 2>&1
    echo $? > "$tmp/$t.rc"
    echo $(( $(date +%s) - start )) > "$tmp/$t.secs"
}

echo "== running: $tools"
pids=
for t in $tools; do
    if [ "$serial" -eq 1 ]; then
        run_one "$t"
        echo "   $t done"
    else
        run_one "$t" &
        pids="$pids $!"
    fi
done
for p in $pids; do wait "$p"; done

failed_any=0
total_p=0; total_f=0; total_s=0
echo
printf '%-18s %-6s %10s %8s %8s %6s\n' checker status passed failed skipped secs
printf '%-18s %-6s %10s %8s %8s %6s\n' ------------------ ------ ---------- -------- -------- ------
for t in $tools; do
    rc=$(cat "$tmp/$t.rc" 2>/dev/null || echo 99)
    secs=$(cat "$tmp/$t.secs" 2>/dev/null || echo "?")
    line=$(grep '^WINRBD-RESULT ' "$tmp/$t.out" | tail -n 1)
    p=0; f=0; s=0
    if [ -n "$line" ]; then
        p=$(echo "$line" | sed 's/.* passed=\([0-9]*\).*/\1/')
        f=$(echo "$line" | sed 's/.* failed=\([0-9]*\).*/\1/')
        s=$(echo "$line" | sed 's/.* skipped=\([0-9]*\).*/\1/')
    fi
    status=PASS
    if [ "$rc" -ne 0 ] || [ -z "$line" ] || [ "$f" -ne 0 ]; then
        status=FAIL
        failed_any=1
    fi
    total_p=$((total_p + p)); total_f=$((total_f + f)); total_s=$((total_s + s))
    printf '%-18s %-6s %10d %8d %8d %6s\n' "$t" "$status" "$p" "$f" "$s" "$secs"
done
printf '%-18s %-6s %10s %8s %8s %6s\n' ------------------ ------ ---------- -------- -------- ------
printf '%-18s %-6s %10d %8d %8d\n' TOTAL "" "$total_p" "$total_f" "$total_s"

echo
echo "== skipped checks ($total_s): input the public set does not have; a skip is not a failure"
for t in $tools; do
    grep '^WINRBD-SKIP ' "$tmp/$t.out" 2>/dev/null | while IFS= read -r l; do
        what=${l#*what=}; what=${what%% reason=*}
        reason=${l#*reason=}
        echo "  $t: $what"
        echo "      why: $reason"
    done
done
[ "$total_s" -eq 0 ] && echo "  (none)"

for t in $tools; do
    rc=$(cat "$tmp/$t.rc" 2>/dev/null || echo 99)
    line=$(grep '^WINRBD-RESULT ' "$tmp/$t.out" | tail -n 1)
    if [ "$verbose" -eq 1 ]; then
        echo
        echo "================ $t (exit $rc) ================"
        cat "$tmp/$t.out"
    elif [ "$rc" -ne 0 ] || [ -z "$line" ] || ! echo "$line" | grep -q ' failed=0 '; then
        echo
        echo "================ $t FAILED (exit $rc); last 60 lines ================"
        tail -n 60 "$tmp/$t.out"
    fi
done

echo
if [ "$fetch_ok" -eq 0 ]; then
    failed_any=1
    echo "RESULT: FAILED (the Ceph run-time data could not be fetched)"
elif [ "$failed_any" -eq 0 ]; then
    echo "RESULT: ALL CHECKERS PASSED ($total_p checks, $total_s skipped)"
else
    echo "RESULT: FAILED"
fi
exit "$failed_any"
