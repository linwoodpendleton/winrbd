#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# selftest.sh - the offline test of the scripts of the exit measurements (ctest measure.selftest). No cluster, no lab VM, no network.
#
#   selftest.sh [--quick]      --quick skips the QEMU smoke of the assembled bench program
#
# What is checked:
#   - every script parses (bash -n, python3 -m py_compile), and shellcheck is clean where it is installed
#   - analyze.py and captan.py: their own self-tests (synthetic consoles and captures, with negative controls)
#   - mkbench.py (needs GNU as and ld for i386, else this part is skipped): the assembled bench has the signature, the header and the records; the expected
#     sums are those of the bytes of the image; "verify" accepts a copy that was made and refuses one byte of difference and a missing destination
#   - the bench program itself, in QEMU with software emulation and a plain disk (SeaBIOS): the program runs, its calibration and its 127-sector reads are
#     right (the sums equal the plan's), a 1 MiB command (which SeaBIOS cannot do) is reported as an error line and not as success, and the analysis says
#     FAIL for it (so the self-test shows the analysis catching a failing step in a real console)
#   - the option refusals of mrun.sh, mimages.sh, krbd.sh and campaign.sh (bad names, missing files, out-of-range numbers: exit 2 and no side effect)
#   - summarize.py on synthetic runs: the medians, the spreads and the refusal to average over runs that did not pass
# Exit: 0 all passed, 1 a check failed, 77 skipped (no python3).
set -uo pipefail
LC_ALL=C
export LC_ALL
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
quick=0
[ "${1:-}" != --quick ] || quick=1
command -v python3 > /dev/null || { echo "selftest: no python3: skipped"; exit 77; }
fails=0
pass() { echo "ok   $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }
check() { # DESCRIPTION CMD... : the command must succeed
    local d=$1
    shift
    if "$@" > /dev/null 2>&1; then pass "$d"; else fail "$d"; fi
}
refuses() { # DESCRIPTION PATTERN CMD... : the command must exit with status 2 (a refused request) and its message must match PATTERN
    local d=$1 pat=$2 out rc=0
    shift 2
    out=$("$@" 2>&1) || rc=$?
    if [ "$rc" = 2 ] && printf '%s' "$out" | grep -q -- "$pat"; then pass "$d"; else fail "$d (exit $rc: $(printf '%s' "$out" | head -n 1))"; fi
}
T=$(mktemp -d "${TMPDIR:-/tmp}/measure-selftest.XXXXXX")
trap 'rm -rf -- "$T"' EXIT

# ---- parse
for f in "$HERE"/*.sh; do check "bash -n $(basename "$f")" bash -n "$f"; done
for f in "$HERE"/*.py; do check "py_compile $(basename "$f")" python3 -I -c 'import sys; compile(open(sys.argv[1]).read(), sys.argv[1], "exec")' "$f"; done
if command -v shellcheck > /dev/null; then
    for f in "$HERE"/*.sh; do check "shellcheck $(basename "$f")" shellcheck -x -S warning "$f"; done
else
    echo "note shellcheck is not installed: skipped"
fi

# ---- the analysers' own tests
check "analyze.py selftest" python3 -I "$HERE/analyze.py" selftest
check "captan.py selftest" python3 -I "$HERE/captan.py" selftest

# ---- mkbench.py and the assembled bench
AS=${AS:-as}
LD=${LD:-ld}
if echo ".code16" | "$AS" --32 -o "$T/probe.o" - > /dev/null 2>&1 && command -v "$LD" > /dev/null && "$LD" -m elf_i386 -o "$T/probe.bin" "$T/probe.o" > /dev/null 2>&1; then
    check "mkbench.py builds the probe disk" python3 -I "$HERE/mkbench.py" build "$T/probe.raw" --plan probe --data-mib 16 --scratch-mib 6 --json "$T/probe.json"
    python3 -I - "$T/probe.raw" "$T/probe.json" << 'PY' > "$T/probe.check" 2>&1 && pass "the probe disk: signature, header, records and sums are as the plan says" || { fail "the probe disk is not as the plan says"; cat "$T/probe.check"; }
import json, struct, sys
raw = open(sys.argv[1], "rb").read()
plan = json.load(open(sys.argv[2]))
assert raw[510:512] == b"\x55\xaa", "boot signature"
assert raw[512:516] == b"WRMB", "header magic"
n = struct.unpack("<I", raw[516:520])[0]
assert n == len(plan["records"]) == 4, "record count"
for i, r in enumerate(plan["records"]):
    t, cmd, total, lba, dst, gap, rid = struct.unpack("<B3xIIIIII4x", raw[0x220 + 32 * i:0x220 + 32 * (i + 1)])
    assert (chr(t), cmd, total, lba, dst, gap, rid) == (r["type"], r["cmd"], r["total"], r["lba"], r["dst"], r["gap"], r["id"]), "record %d" % i
assert len(raw) == plan["image_sectors"] * 512, "image size"
r2 = plan["records"][1]                      # R 127 x 2032 sectors: the last command is 127 sectors at lba + total - 127
last = r2["lba"] + r2["total"] - 127
words = struct.unpack("<%dI" % (127 * 128), raw[last * 512:(last + 127) * 512])
assert "%08x" % (sum(words) & 0xFFFFFFFF) == plan["expected"]["2"]["sumA"], "expected sum"
PY
    # a copy plan: do the copy in python and verify
    check "mkbench.py builds the write plan" python3 -I "$HERE/mkbench.py" build "$T/w.raw" --plan write --data-mib 16 --scratch-mib 24 --write-mib 2 --json "$T/w.json"
    python3 -I - "$T/w.raw" "$T/w.json" "$T/w.done" "$T/w.bad" << 'PY'
import json, sys
raw = bytearray(open(sys.argv[1], "rb").read())
plan = json.load(open(sys.argv[2]))
for v in plan["verify"]:
    raw[v["dst"] * 512:(v["dst"] + v["sectors"]) * 512] = raw[v["src"] * 512:(v["src"] + v["sectors"]) * 512]
open(sys.argv[3], "wb").write(raw)
raw[plan["verify"][1]["dst"] * 512 + 777] ^= 1
open(sys.argv[4], "wb").write(raw)
PY
    check "verify accepts a disk on which the copies were made" python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/w.done"
    if python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/w.bad" > "$T/w.badout" 2>&1; then fail "verify refuses a disk with one flipped bit"; else grep -q MISMATCH "$T/w.badout" && pass "verify refuses a disk with one flipped bit (names the range)" || fail "verify refused without naming the range"; fi
    if python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/w.raw" > /dev/null 2>&1; then fail "verify refuses a disk on which nothing was copied"; else pass "verify refuses a disk on which nothing was copied"; fi
    # --strict: nothing but the destination ranges may differ from the image as it was built (a write that landed in the wrong place is not found by the digests of the destinations)
    python3 -I - "$T/w.done" "$T/w.json" "$T" << 'PY'
import json, sys
raw = bytearray(open(sys.argv[1], "rb").read())
plan = json.load(open(sys.argv[2]))
t = sys.argv[3]
last_end = max(v["dst"] + v["sectors"] for v in plan["verify"]) * 512
def save(name, data):
    open("%s/%s" % (t, name), "wb").write(data)
x = bytearray(raw); x[100] ^= 1; save("s.code", x)                                               # the program
x = bytearray(raw); x[plan["data_first"] * 512 + 5 * 1048576 + 3] ^= 1; save("s.data", x)       # the data area
x = bytearray(raw); x[last_end + 4096 + 7] = 1; save("s.scratch", x)                             # scratch, outside every destination
x = bytearray(raw); x[plan["scratch_lba"] * 512 - 1] = 1; save("s.gap", x)                       # between the data area and the scratch area
save("s.short", raw[:-512])
PY
    check "verify --strict accepts a disk on which only the copies were made" python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/w.done" --strict
    for v in code:"sectors 0 to 15" data:"the data area changed" scratch:"non-zero byte" gap:"non-zero byte" short:"the export is"; do
        if python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/s.${v%%:*}" --strict > "$T/s.out" 2>&1; then fail "verify --strict refuses a change of ${v%%:*}"; else
            grep -q -- "${v#*:}" "$T/s.out" && pass "verify --strict refuses a change of ${v%%:*} (names it)" || fail "verify --strict refused a change of ${v%%:*} without naming it: $(head -n 3 "$T/s.out" | tr '\n' '|')"; fi
    done
    check "the plain verify still looks only at the destination ranges (it passes the stray-byte disk that --strict refuses)" python3 -I "$HERE/mkbench.py" verify "$T/w.json" "$T/s.scratch"
    refuses "mkbench.py refuses a plan it does not know" 'unknown plan' python3 -I "$HERE/mkbench.py" build "$T/x.raw" --plan nope

    if [ "$quick" = 0 ] && command -v qemu-system-x86_64 > /dev/null && qemu-system-x86_64 -accel help 2> /dev/null | grep -q tcg; then
        rm -f "$T/serial.txt"
        timeout 120 qemu-system-x86_64 -name measure-selftest -accel tcg -m 64 -smp 1 -drive "file=$T/probe.raw,format=raw,if=ide,snapshot=on" -serial "file:$T/serial.txt" \
            -display none -nic none -no-reboot -monitor none > /dev/null 2>&1 &
        qp=$!
        for _ in $(seq 1 110); do grep -aq 'WRMS-DONE' "$T/serial.txt" 2> /dev/null && break; sleep 1; done
        kill "$qp" 2> /dev/null
        wait "$qp" 2> /dev/null
        mkdir "$T/run"
        cp "$T/serial.txt" "$T/run/serial.txt" 2> /dev/null || : > "$T/run/serial.txt"
        cp "$T/probe.json" "$T/run/plan.json"
        python3 -I "$HERE/analyze.py" run "$T/run" > "$T/run/out.txt" 2>&1
        grep -aq 'WRMS-START' "$T/run/serial.txt" && pass "the bench program starts in SeaBIOS (software emulation)" || fail "the bench program did not start"
        grep -q '^ok   a TSC calibration was printed' "$T/run/verdict.txt" && pass "the calibration step prints" || fail "no calibration line"
        grep -q '^ok   step 2: the data check' "$T/run/verdict.txt" && pass "127-sector reads: the data check equals the plan's sums" || { fail "127-sector reads: the data check"; cat "$T/run/verdict.txt"; }
        grep -q '^ok   step 2: R of 2032 sectors in 16 commands of 127, as planned' "$T/run/verdict.txt" && pass "127-sector reads: the planned sectors in the planned number of commands (a real console against the plan's record)" || { fail "the plan check of step 2"; cat "$T/run/verdict.txt"; }
        grep -q '^ok   latency series 4: 4 reads after a gap of 0 s, as planned' "$T/run/verdict.txt" && pass "the latency series has the planned reads (a real console)" || fail "the plan check of the latency series"
        grep -aq 'WRMS-ERR id=3' "$T/run/serial.txt" && pass "a 1 MiB command SeaBIOS cannot do is an error line, not a success" || fail "the unsupported command was not reported"
        head -n 1 "$T/run/verdict.txt" | grep -q '^FAIL' && pass "the analysis says FAIL for a run with a failed step" || fail "the analysis passed a run with a failed step"
        grep -aq 'WRMS-LATR id=4 k=3' "$T/serial.txt" && pass "the latency series runs to its end" || fail "the latency series did not finish"
    else
        echo "note QEMU smoke skipped"
    fi
else
    echo "note GNU as/ld for i386 not available: the assembled-bench checks are skipped"
fi

# ---- option refusals (no side effect: the checks come before anything is touched)
export P2_LAB_DIR=$T/lab P2Q_WORK=$T/q P2M_OUT=$T/out P2M_WORK=$T/work
mkdir -p "$T/lab" "$T/q" "$T/work/img"
: > "$T/plan.json"
: > "$T/ipxe.pxe"
refuses "mrun.sh: a bad run name" 'bad name' bash "$HERE/mrun.sh" row 'bad name' --image wrtest-p2-ms-read --plan "$T/plan.json" --bin "$T/ipxe.pxe"
refuses "mrun.sh: an image that is not a wrtest-p2 image" '--image wrtest-p2' bash "$HERE/mrun.sh" row r1 --image img-default --plan "$T/plan.json" --bin "$T/ipxe.pxe"
refuses "mrun.sh: no plan" '--plan' bash "$HERE/mrun.sh" row r1 --image wrtest-p2-ms-read --plan "$T/none.json" --bin "$T/ipxe.pxe"
refuses "mrun.sh: no binary" '--bin' bash "$HERE/mrun.sh" row r1 --image wrtest-p2-ms-read --plan "$T/plan.json" --bin "$T/none.pxe"
refuses "mrun.sh: address 50 is the lab's probe guest" '--oct' bash "$HERE/mrun.sh" row r1 --image wrtest-p2-ms-read --plan "$T/plan.json" --bin "$T/ipxe.pxe" --oct 50
refuses "mrun.sh: netem with a unit" 'milliseconds' bash "$HERE/mrun.sh" row r1 --image wrtest-p2-ms-read --plan "$T/plan.json" --bin "$T/ipxe.pxe" --netem 5ms
refuses "mrun.sh: no key file" 'no key file' bash "$HERE/mrun.sh" row r1 --image wrtest-p2-ms-read --plan "$T/plan.json" --bin "$T/ipxe.pxe"
refuses "mrun.sh: an unknown option" 'unknown option' bash "$HERE/mrun.sh" row r1 --frobnicate
refuses "mimages.sh: an unknown plan" 'unknown plan' bash "$HERE/mimages.sh" create nope
refuses "mimages.sh: delete needs a plan" 'which plan' bash "$HERE/mimages.sh" delete
refuses "krbd.sh: an image that is not a wrtest-p2-ms image" '--image wrtest-p2-ms' bash "$HERE/krbd.sh" run k1 --image img-v1
refuses "krbd.sh: a non-numeric size" 'numbers only' bash "$HERE/krbd.sh" run k1 --image wrtest-p2-ms-read --mib abc
[ ! -e "$T/out/r1" ] && [ ! -e "$T/out/k1" ] && pass "a refused request leaves no evidence directory behind" || fail "a refused request left a directory"
refuses "campaign.sh: an unknown series" 'read' bash "$HERE/campaign.sh" nope

# ---- summarize.py
python3 -I "$HERE/summarize.py" selftest > "$T/sum.out" 2>&1 && pass "summarize.py selftest" || { fail "summarize.py selftest"; cat "$T/sum.out"; }

if [ "$fails" = 0 ]; then echo "selftest: PASS"; exit 0; fi
echo "selftest: FAIL ($fails)"
exit 1
