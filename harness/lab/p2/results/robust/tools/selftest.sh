#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Offline self-test of the scripts that ran the robustness rows (qemu-robust): harness/lab/p2/qemu/robust.sh (the fault driver), tools/rr.sh, matrix.sh,
# labstate.sh, analyze.py (the verdicts), mkreader.py and reader.S (the INT 13h reader). No KVM, no real QEMU, no cluster, no network, no root: QEMU is a stand-in
# that serves the control socket and records what it is told (stop, cont, set_link, send-key), and the lab VM is a stub that records the commands it is given and
# answers the few the fault driver asks. Every file is below one temporary directory, removed at the end.
#
#   selftest.sh            everything; exit status 0 only when every check passed (77 when python3 is missing)
#   selftest.sh --quick    the cases that start no process
#
# What it proves (each line is a promise of the README or a defect a review found):
#   * robust.sh refuses what it should (family, fault, numbers, shell operators in the lab command) and its dry run says what each fault would do
#   * every fault does what it says and its undo runs: mon-kill / mon-osd / osd-kill (kill + stop, later start, wait for quorum / OSDs), stall / outage (STOP, CONT),
#     pause (QMP stop, cont), link-down (set_link false, true), --press (send-key); a fault still waiting when the run ends is undone at once (and says so)
#   * a fault that cannot be prepared stops the run before the guest exists; a trigger that never appears is reported (exit 3, "NO FAULT WAS INJECTED")
#   * the time-stamped console and the fault log are written, and a key in the console is caught
#   * analyze.py: each profile passes on good evidence and fails on each defect (wrong digest, wrong prefix hash, a canary violation, a read error that reached the
#     loader, a fault that did not overlap the workload, a changed lab, a wrong errno, two driver lines, a key-shaped string, a missing expectation)
#   * mkreader.py: the hash, the progress points, and (with GNU as and ld) the assembled reader is exactly 4096 bytes with the signature and the patched count
# shellcheck disable=SC2329,SC2016,SC2015,SC2030,SC2031,SC2009,SC2012  # cases are called through their names; quotes are deliberate; the library is sourced in groups
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../../../../../.." && pwd)
robust=$repo/harness/lab/p2/qemu/robust.sh
quick=0
[ "${1:-}" != --quick ] || quick=1
command -v python3 >/dev/null 2>&1 || { echo "robust.selftest: python3 is needed" >&2; exit 77; }

pass=0 fail=0 skipped=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n' "$1" >&2; }
skip() { skipped=$((skipped + 1)); printf '  skip %s\n' "$1"; }
# check DESCRIPTION COMMAND [ARGS] [&& COMMAND [ARGS]]...: passes only when every command of the list succeeds (the && is a quoted word: written bare, the shell would
# end the check at the first command and run the rest outside it, where a failure counts for nothing)
check() {
    local d=$1 good=1; shift
    local seg=()
    while [ $# -gt 0 ]; do
        seg=()
        while [ $# -gt 0 ] && [ "$1" != '&&' ]; do seg+=("$1"); shift; done
        [ $# -eq 0 ] || shift
        if [ "${#seg[@]}" -gt 0 ] && ! "${seg[@]}"; then good=0; break; fi
    done
    if [ "$good" = 1 ]; then ok "$d"; else bad "$d"; fi
}
not() { ! "$@"; }
contains() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
not_contains() { ! contains "$1" "$2"; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-robust-selftest.XXXXXX")
case "$tmp" in /*/*) ;; *) echo "bad temporary directory $tmp" >&2; exit 2;; esac
cleanup() {
    find "$tmp" -type f -delete 2>/dev/null || true
    find "$tmp" -type s -delete 2>/dev/null || true
    find "$tmp" -depth -type d -exec rmdir {} + 2>/dev/null || true
}
trap cleanup EXIT
umask 077
KEY='AQDmYtZnAAAAABAAEXAMPLEKEYEXAMPLEKEYAA=='
mkdir -p "$tmp/keys" "$tmp/stubs" "$tmp/ipxe" "$tmp/out"
printf '%s\n' "$KEY" > "$tmp/keys/bare"
chmod 600 "$tmp/keys/bare"

echo "== the test's own helper"
# (every later command of a check's list must count: written with a bare && it once ran outside the check and nothing it said was seen)
out=$( (check "probe" true '&&' false) 2>&1 ); check "check: a failing later command of the list fails the check" contains "$out" "FAIL probe"
out=$( (check "probe" true '&&' true '&&' not false) 2>&1 ); check "check: a list in which every command succeeds passes" contains "$out" "ok   probe"
out=$( (check "probe" false '&&' true) 2>&1 ); check "check: a failing first command fails the check" contains "$out" "FAIL probe"

echo "== the scripts parse"
for f in qemu/robust.sh results/robust/tools/rr.sh results/robust/tools/matrix.sh results/robust/tools/labstate.sh results/robust/tools/selftest.sh; do
    check "bash -n $f" bash -n "$repo/harness/lab/p2/$f"
done
for f in analyze.py mkreader.py summarize.py; do
    check "$f compiles" python3 -I -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$here/$f"
done
if command -v shellcheck >/dev/null 2>&1; then
    check "shellcheck is clean on robust.sh rr.sh matrix.sh labstate.sh" shellcheck -x "$robust" "$here/rr.sh" "$here/matrix.sh" "$here/labstate.sh"
else
    skip "shellcheck is not installed"
fi
check "every script has its SPDX line" test "$(head -n 3 "$robust" "$here/rr.sh" "$here/matrix.sh" "$here/labstate.sh" "$here/analyze.py" "$here/mkreader.py" "$here/reader.S" "$here/summarize.py" | grep -c 'SPDX-License-Identifier: MIT')" = 8

echo "== matrix.sh"
out=$(bash "$here/matrix.sh" list)
check "the matrix lists rows of both families and all workloads" test "$(printf '%s\n' "$out" | grep -c -E '^(U1|B1)-(bytes|reader|boot|neg)-')" -ge 40
for f in mon mon-short mon-osd osd-short osd-long pause link stall20 stall40 outage; do
    check "U1 and B1 both have a $f row" test "$(printf '%s\n' "$out" | grep -c -E -- "^(U1-bytes|B1-reader)-$f ")" = 2
done
check "the four negative rows exist in both families" test "$(printf '%s\n' "$out" | grep -c -E -- '-neg-(key|pool|image|mon) ')" = 8
check "every row name is unique" test "$(printf '%s\n' "$out" | awk '{print $1}' | sort | uniq -d | wc -l | tr -d ' ')" = 0
out=$(bash "$here/matrix.sh" run nosuchrow 2>&1); rc=$?
check "an unknown row is refused" test "$rc" -eq 2

echo "== robust.sh: options and dry runs"
rb() { bash "$robust" "$@" 2>&1; }
out=$(rb --family dos --fault none); rc=$?; check "a bad --family is refused" test "$rc" -eq 2
out=$(rb --family bios --fault explode); rc=$?; check "a bad --fault is refused" test "$rc" -eq 2
out=$(rb --family bios --fault pause --down abc); rc=$?; check "--down must be a number" test "$rc" -eq 2
out=$(rb --family bios --fault pause --delay -1); rc=$?; check "--delay must not be negative" test "$rc" -eq 2
out=$(rb --family bios --fault osd-kill --osd 1x); rc=$?; check "--osd must be a number" test "$rc" -eq 2
out=$(rb --family bios --fault stall --lab-ssh 'ssh x; rm -rf y'); rc=$?; check "shell operators in --lab-ssh are refused" test "$rc" -eq 2
out=$(rb --family bios --fault pause --press 'ret; rm'); rc=$?; check "--press takes key names only" test "$rc" -eq 2
out=$(rb --family bios --fault pause --link-name 'a b'); rc=$?; check "--link-name must be a QEMU id" test "$rc" -eq 2
out=$(rb --family bios --fault mon-kill --on-nth 0); rc=$?; check "--on-nth starts at 1" test "$rc" -eq 2
out=$(rb --family bios --fault pause --on '(unclosed'); rc=$?; check "--on must be a regular expression (a bad one would never fire and the guest would run to the timeout)" test "$rc" -eq 2
out=$(rb --family bios --fault pause --idle-timeout 3); rc=$?; check "--idle-timeout must be 5 or more" test "$rc" -eq 2
out=$(rb --family bios --fault pause --idle-timeout x); rc=$?; check "--idle-timeout must be a number" test "$rc" -eq 2
out=$(rb --help); rc=$?; check "--help works" test "$rc" -eq 0 && check "--help names every fault" contains "$out" "outage"
for f in none mon-kill mon-osd osd-kill pause link-down stall outage; do
    out=$(P2Q_WORK=$tmp/work rb --family bios --fault $f -n --bin "$tmp/ipxe/ipxe-stub.pxe" --pool p --image i --fake-key --delivery stub --row B1); rc=$?
    check "dry run, fault $f: exit 0 and the plan says $f" test "$rc" -eq 0 '&&' contains "$out" "fault: $f on"
done
out=$(P2Q_WORK=$tmp/work rb --family bios --fault pause -n --down 7 --delay 2.5 --bin "$tmp/ipxe/ipxe-stub.pxe" --pool p --image i --fake-key --delivery stub)
check "the dry run shows the timing and the QMP command" contains "$out" "lasting 7 s" '&&' contains "$out" "QMP stop"
out=$(P2Q_WORK=$tmp/work rb --family bios --fault pause -n --qemu-arg tap --bin "$tmp/ipxe/ipxe-stub.pxe" --pool p --image i --fake-key --delivery stub); rc=$?
check "the stock refusals of --qemu-arg still hold" test "$rc" -eq 2
out=$(P2Q_WORK=$tmp/work rb --family bios --fault pause -n --bin "$tmp/ipxe/ipxe-stub.pxe" --pool p --image i --fake-key --delivery stub)
check "the dry run starts nothing and creates nothing" test ! -e "$tmp/work/runs/B1-DRYRUN"
check "the QEMU command line has the lab NIC under the id the fault driver uses (lab)" contains "$out" 'netdev socket\,id=lab\,'

echo "== mkreader.py and reader.S"
H=$(python3 -I -c "
import importlib.util
sp = importlib.util.spec_from_file_location('mkreader', '$here/mkreader.py'); m = importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
import struct
print('%08x' % m.hash_prefix(struct.pack('<4I', 1, 2, 3, 4)))
print(len(m.prog_points(262136)), m.prog_points(262136)[0], m.prog_points(262136)[-1])
print(m.prog_points(100))
")
check "the hash of four dwords is the pinned value" contains "$H" "bdd149cc"
check "the progress points of a 128 MiB disk: 63 of them, the first at lba 4157" contains "$H" "63 4157"
check "a disk of 100 sectors has no progress point" contains "$H" "[]"
if command -v as >/dev/null 2>&1 && command -v ld >/dev/null 2>&1 && as --version 2>/dev/null | head -n 1 | grep -q GNU && ld --version 2>/dev/null | head -n 1 | grep -q GNU && [ "$(uname -s)" = Linux ]; then
    out=$(python3 -I "$here/mkreader.py" "$tmp/out/reader.raw" --size-mib 2 2>&1); rc=$?
    check "the reader assembles into 8 sectors + data and the count is patched" test "$rc" -eq 0 '&&' contains "$out" "data sectors 4088"
    sz=$(stat -c %s "$tmp/out/reader.raw")
    check "the disk is 2 MiB" test "$sz" -eq 2097152
    sig=$(dd if="$tmp/out/reader.raw" bs=1 skip=510 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')
    check "the boot signature is there" test "$sig" = 55aa
    check "the second stage has its header" test "$(dd if="$tmp/out/reader.raw" bs=1 skip=512 count=4 2>/dev/null)" = WRRD
    a=$(python3 -I "$here/mkreader.py" --hash "$tmp/out/reader.raw")
    out=$(python3 -I "$here/mkreader.py" --prefix "$tmp/out/reader.raw" | tail -n 1)
    check "--prefix ends with the same hash as --hash" contains "$out" "final 4088 $a"
else
    skip "GNU as and ld on Linux are needed to assemble the reader"
fi

echo "== analyze.py"
mkrow() { # DIR PROFILE: an empty evidence directory
    mkdir -p "$1"
}
E=$tmp/expect
mkdir -p "$E"
cat > "$E/bytes.md5" <<'EOF'
11111111111111111111111111111111  f-0001
22222222222222222222222222222222  f-0002
33333333333333333333333333333333  f-0003
44444444444444444444444444444444  f-0004
55555555555555555555555555555555  f-0005
66666666666666666666666666666666  f-0006
77777777777777777777777777777777  f-0007
88888888888888888888888888888888  f-0008
99999999999999999999999999999999  f-0009
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  f-0010
EOF
python3 -I - "$E" <<'PY'
import sys
e = sys.argv[1]
pts = [4157 + 4100 * i for i in range(20)]
with open(e + "/reader.prefix", "w") as f:
    for i, p in enumerate(pts):
        f.write("%d %08x\n" % (p, 0x1000 + i))
    f.write("final 262136 00ff0001\n")
PY
cat > "$tmp/mkevid.py" <<'PY'
import sys, os
d, kind = sys.argv[1], sys.argv[2]
mods = set(sys.argv[3:])
os.makedirs(d, exist_ok=True)
T0 = 1000.0
def w(name, text):
    open(os.path.join(d, name), "w").write(text)
con, ts = [], []
def say(t, line):
    con.append(line)
    ts.append("%.3f %s" % (T0 + t, line))
fault = ["%.3f T+0 guest started (pid 1); fault x" % T0]
fkind = "mon-kill" if "nofault" not in mods else "none"
say(10, "WRRUN-SAN-OK")
if kind == "bytes":
    names = ["f-%04d" % i for i in range(1, 11)]
    md5 = {"f-0001": "1" * 32, "f-0002": "2" * 32, "f-0003": "3" * 32, "f-0004": "4" * 32, "f-0005": "5" * 32, "f-0006": "6" * 32, "f-0007": "7" * 32,
           "f-0008": "8" * 32, "f-0009": "9" * 32, "f-0010": "a" * 32}
    t = 11
    for n in names:
        say(t, "WRBYTES-FILE " + n)
        if "failfile" in mods and n == "f-0005":
            say(t + 1, "WRBYTES-FAIL " + n)
        else:
            say(t + 1, "file://WRBYTES/%s... ok" % n)
            h = md5[n]
            if "badmd5" in mods and n == "f-0007":
                h = "0" * 32
            say(t + 1, "%s  wrb" % h)
        t += 2
    say(t, "WRINFO-BEGIN")
    say(t, "rbd: image winrbd/x: open, 1 device(s), 100 blocks of 512 bytes")
    say(t, "rbd:   session: 100 pumps, 2 cancels (most rounds 1), 1 reopens, 1 stall closes")
    say(t, "rbd:   core: connections 4 (most 4), arena 1 bytes, bulk 1 bytes; modes: 4 crc, 0 secure, 0 secure failures")
    say(t, "rbd:   osd: 500 ops done, 3 resent, 0 failed; in flight 0 (most 8), requests 0 (most 8); 1 session resets, zombies 0 of 0 bytes")
    say(t, "WRINFO-END")
    if "nodone" not in mods:
        say(t, "WRBYTES-DONE")
    say(t, "WRRUN-END")
    wend = t
elif kind == "reader":
    say(11, "WRRB-START drive=80 first=8 sectors=262136 rtc=100000")
    t = 12
    for i in range(20):
        h = 0x1000 + i
        if "badprefix" in mods and i == 7:
            h = 0xDEAD
        say(t, "WRRB-PROG lba=%d h=%08X maxticks=1@8 rtc=1000%02d errs=0 stale=0" % (4157 + 4100 * i, h, 12 + i))
        t += 0.5
    errs = 1 if "readerr" in mods else 0
    stale = 1 if "stale" in mods else 0
    fh = "00FF0001" if "badfinal" not in mods else "00FF0002"
    if "stale" in mods:
        say(t, "WRRB-STALE slot=1 lba=100 what=canary")
    say(t + 1, "WRRB-DONE sectors=262136 h=%s errs=%d stale=%d maxticks=5@34702 rtc=100030 end=ok" % (fh, errs, stale))
    say(t + 1, "WRRUN-END")
    wend = t + 1
elif kind == "boot":
    say(11, "WRRUN-SAN-START sanboot")
    say(12, "Loading, please wait...")
    say(12, "RBFT-RESULT PASS pass=40 fail=0 skip=0" if "badtable" not in mods else "RBFT-RESULT FAIL pass=39 fail=1 skip=0")
    say(13, "WRBOOT-HOOK-DONE root=/dev/rbd0p2 table=PASS")
    if "grub_err" in mods:
        say(20, "error: failure reading sector 0x1234 from `hd0'.")
    if "noroot" not in mods and "grub_err" not in mods:
        say(30, "WRBOOT-ROOT-OK fw=uefi root=/dev/rbd0p2 table=PASS")
    if "panic" in mods:
        say(31, "Kernel panic - not syncing: x")
    wend = 12
else:  # neg-*
    errno, text = {"neg-key": ("0x02000000", "rbd: open failed: key refused (WR_E_AUTH_DENIED)"),
                   "neg-pool": ("0x2d000000", "rbd: open failed: pool not found (WR_E_POOL_NOT_FOUND)"),
                   "neg-image": ("0x2d000000", "rbd: open failed: image not found (WR_E_RBD_NOT_FOUND)"),
                   "neg-mon": ("0x28000000", "rbd: open failed: connect (WR_E_NET_CONNECT)")}[kind]
    con[:] = []; ts[:] = []
    say(10, "WRRUN-SAN-START sanhook")
    if "wrongerrno" in mods:
        errno = "0x43000000"
    say(11, text)
    if "twolines" in mods:
        say(11, text)
    say(12, "Could not open SAN device: Operation not supported (https://ipxe.org/x)")
    say(12, "WRRUN-SAN-FAILED " + errno)
    wend = 12
if kind != "neg" and not kind.startswith("neg"):
    pass
if "leak" in mods:
    say(5, "oops AQDmYtZnAAAAABAAEXAMPLEKEYEXAMPLEKEYAA==")
# the fault
if fkind != "none" and not kind.startswith("neg"):
    fb = T0 + wend - 5 if "late" not in mods else T0 + wend + 3
    fault.append("%.3f T+1 fault %s: begins (down 20 s)" % (fb, fkind))
    if "nofaultend" not in mods:
        fault.append("%.3f T+2 fault %s: ends (rc 0)" % (fb + 20, fkind))
    if "undofailed" in mods:
        fault.append("%.3f T+3 UNDO FAILED" % (fb + 21))
if "healthline" in mods:   # the lines robust.sh writes before the guest exists (the lab's health, the idle timeout being set)
    fault.insert(0, "%.3f T+2 health checks at the start: none" % (T0 - 3))
w("serial.txt", "\r\n".join(con) + "\r\n")
w("ts.txt", "\n".join(ts) + "\n")
w("fault.txt", "\n".join(fault) + "\n")
w("result.txt", "RESULT row=X expect=marker met=1 stop=expectation\nexit=%d\n" % (1 if "exit1" in mods else 0))
w("lab-diff.txt", "labstate: no difference\n" if "labdiff" not in mods else "--- a\n+++ b\n+auth client.x\n")
w("lab-health.txt", "health before: x\nhealth after: 3 osds: 3 up (since 5s), 3 in (since 1h); epoch: e9 33 pgs: 33 active+clean; 1 MiB\n" if "osddown" not in mods else
  "health before: x\nhealth after: 3 osds: 2 up (since 5s), 3 in (since 1h); epoch: e9\n")
w("stdout.txt", "x\n")
w("cmdline.txt", "bash robust.sh --fault %s\n" % fkind)
PY
judge() { # NAME KIND PROFILE FAULT [mods...] -> $v
    local n=$1 k=$2 p=$3 f=$4
    shift 4
    python3 -I "$tmp/mkevid.py" "$tmp/ev/$n" "$k" "$@"
    v=$(python3 -I "$here/analyze.py" --dir "$tmp/ev/$n" --profile "$p" --workload "$k" --fault "$f" --family uefi --expect-dir "$E" 2>&1)
}
first() { printf '%s\n' "$v" | head -n 1; }
judge b-ok bytes bytes mon-kill; check "bytes: good evidence passes" test "$(first)" = PASS
judge b-md5 bytes bytes mon-kill badmd5; check "bytes: a wrong digest fails" test "$(first)" = FAIL '&&' contains "$v" "wrong or missing: f-0007"
judge b-fail bytes bytes mon-kill failfile; check "bytes: a file that failed to read fails" test "$(first)" = FAIL
judge b-nodone bytes bytes mon-kill nodone; check "bytes: no WRBYTES-DONE fails" test "$(first)" = FAIL
judge b-late bytes bytes mon-kill late; check "bytes: a fault that began after the workload ended fails" test "$(first)" = FAIL '&&' contains "$v" "still working"
judge b-noend bytes bytes mon-kill nofaultend; check "bytes: a fault with no end line fails" test "$(first)" = FAIL
judge b-undo bytes bytes mon-kill undofailed; check "bytes: UNDO FAILED in fault.txt fails" test "$(first)" = FAIL
judge b-lab bytes bytes mon-kill labdiff; check "bytes: a changed lab fails" test "$(first)" = FAIL '&&' contains "$v" "equals the state before"
judge b-osd bytes bytes mon-kill osddown; check "bytes: an OSD down afterwards fails" test "$(first)" = FAIL
judge b-exit bytes bytes mon-kill exit1; check "bytes: a non-zero exit fails" test "$(first)" = FAIL
judge b-leak bytes bytes mon-kill leak; check "bytes: a key-shaped string fails" test "$(first)" = FAIL
judge b-none bytes bytes none nofault; check "bytes: the control (no fault) passes" test "$(first)" = PASS
check "bytes: facts.txt has the counters" grep -q 'rbd_info_cancels: 2' "$tmp/ev/b-ok/facts.txt"
judge b-hl bytes bytes mon-kill healthline
check "the start of the guest is the 'guest started' line, not the first line of fault.txt" grep -q '^guest_started_epoch: 1000.000$' "$tmp/ev/b-hl/facts.txt" '&&' test "$(grep '^fault_begin' "$tmp/ev/b-hl/facts.txt")" = "$(grep '^fault_begin' "$tmp/ev/b-ok/facts.txt")"
mv "$E/bytes.md5" "$E/bytes.md5.off"; judge b-noexp bytes bytes mon-kill; check "bytes: no md5 list is a FAIL, not a pass" test "$(first)" = FAIL; mv "$E/bytes.md5.off" "$E/bytes.md5"
judge b-out bytes bytes outage failfile; check "bytes, outage: a read that failed is what the row wants" test "$(first)" = PASS
judge b-out2 bytes bytes outage; check "bytes, outage: no failed read at all fails (the SAN layer never gave up)" test "$(first)" = FAIL
judge b-out3 bytes bytes outage failfile badmd5; check "bytes, outage: a wrong digest still fails" test "$(first)" = FAIL
judge r-out reader reader outage readerr; check "reader, outage: a read error that reached the loader is what the row wants" test "$(first)" = PASS
judge r-out2 reader reader outage; check "reader, outage: no read error at all fails" test "$(first)" = FAIL
judge r-ok reader reader mon-kill; check "reader: good evidence passes" test "$(first)" = PASS
judge r-pre reader reader mon-kill badprefix; check "reader: a wrong prefix hash fails" test "$(first)" = FAIL
judge r-fin reader reader mon-kill badfinal; check "reader: a wrong final hash fails" test "$(first)" = FAIL
judge r-stale reader reader mon-kill stale; check "reader: a canary violation fails" test "$(first)" = FAIL '&&' contains "$v" "canary"
judge r-err reader reader mon-kill readerr; check "reader: a read error that reached the loader fails" test "$(first)" = FAIL
judge o-ok boot boot mon-kill; check "boot: good evidence passes" test "$(first)" = PASS
judge o-no boot boot mon-kill noroot; check "boot: no WRBOOT-ROOT-OK fails" test "$(first)" = FAIL
judge o-tab boot boot mon-kill badtable; check "boot: a failed table check fails" test "$(first)" = FAIL
judge o-pan boot boot mon-kill panic; check "boot: a kernel panic fails" test "$(first)" = FAIL
judge g-ok boot bootgive outage; check "boot-outage: it booted after the cluster came back: pass" test "$(first)" = PASS
judge g-err boot bootgive outage grub_err; check "boot-outage: a loader read error and a stop is a pass" test "$(first)" = PASS
judge g-none boot bootgive outage noroot; check "boot-outage: no outcome at all fails" test "$(first)" = FAIL
judge g-pan boot bootgive outage panic; check "boot-outage: a kernel panic fails" test "$(first)" = FAIL
judge g-tab boot bootgive outage badtable; check "boot-outage: a booted system with a failed table check fails" test "$(first)" = FAIL
for k in neg-key neg-pool neg-image neg-mon; do
    judge n-$k $k negative none; check "negative $k: good evidence passes" test "$(first)" = PASS
    judge n-$k-e $k negative none wrongerrno; check "negative $k: the wrong errno fails" test "$(first)" = FAIL '&&' contains "$v" "errno"
done
judge n-two neg-key negative none twolines; check "negative: two driver lines fail" test "$(first)" = FAIL
mkdir -p "$tmp/ev/empty"; v=$(python3 -I "$here/analyze.py" --dir "$tmp/ev/empty" --profile bytes --workload bytes --fault none --family uefi --expect-dir "$E" 2>&1)
check "no console log is BLOCKED, not a pass" test "$(first)" = BLOCKED

echo "== matrix.sh rejudge"
mkdir -p "$tmp/rj"
python3 -I "$tmp/mkevid.py" "$tmp/rj/U1-neg-pool" neg-pool nofault
out=$(P2R_OUT=$tmp/rj bash "$here/matrix.sh" rejudge U1-neg-pool 2>&1)
check "rejudge: good evidence is judged again and passes" test "$(head -n 1 "$tmp/rj/U1-neg-pool/verdict.txt")" = PASS
printf 'FAIL\nFAIL secret scan: keyscan.py found the run'"'"'s own key in the row'"'"'s files\n' > "$tmp/rj/U1-neg-pool/verdict.txt"
out=$(P2R_OUT=$tmp/rj bash "$here/matrix.sh" rejudge U1-neg-pool 2>&1)
check "rejudge: a row that failed the secret scan still fails (its files are gone, the analysis cannot see the key)" test "$(head -n 1 "$tmp/rj/U1-neg-pool/verdict.txt")" = FAIL '&&' grep -q '^FAIL secret scan' "$tmp/rj/U1-neg-pool/verdict.txt"
out=$(P2R_OUT=$tmp/rj bash "$here/matrix.sh" rejudge U1-neg-key 2>&1); rc=$?
check "rejudge: a row with no evidence directory is refused" test "$rc" -eq 2

echo "== labstate.sh"
printf 'osd osd.0 status=up reweight=1\nblocklist 5\nquorum a\n' > "$tmp/out/s1"
printf 'osd osd.0 status=up reweight=1\nblocklist 6\nquorum a\n' > "$tmp/out/s2"
printf 'osd osd.0 status=down reweight=1\nblocklist 6\nquorum a\n' > "$tmp/out/s3"
out=$(bash "$here/labstate.sh" diff "$tmp/out/s1" "$tmp/out/s2" 2>&1); rc=$?
check "labstate diff: the blocklist count alone is not a difference" test "$rc" -eq 0 '&&' contains "$out" "no difference"
out=$(bash "$here/labstate.sh" diff "$tmp/out/s1" "$tmp/out/s3" 2>&1); rc=$?
check "labstate diff: an OSD that is down is a difference" test "$rc" -ne 0 '&&' contains "$out" "status=down"
out=$(bash "$here/labstate.sh" snapshot "$tmp/out/s4" 2>&1); rc=$?
check "labstate snapshot without a lab is refused" test "$rc" -eq 2

if [ "$quick" = 1 ]; then
    echo
    echo "robust.selftest: $pass passed, $fail failed, $skipped skipped (--quick)"
    [ "$fail" -eq 0 ]
    exit $?
fi

echo "== whole runs against a QEMU stand-in and a lab stub"
if [ "$(uname -s)" != Linux ] || ! command -v flock >/dev/null 2>&1; then
    skip "the whole-run cases need Linux and flock"
    echo
    echo "robust.selftest: $pass passed, $fail failed, $skipped skipped"
    [ "$fail" -eq 0 ]
    exit $?
fi
cat > "$tmp/stubs/qemu-system-x86_64" <<'EOS'
#!/usr/bin/env bash
exec -a "$0" python3 -I "$(dirname "$0")/fake_qemu.py" "$@"
EOS
cat > "$tmp/stubs/fake_qemu.py" <<'EOS'
import os, signal, socket, sys, threading, time, json
args = sys.argv[1:]
def opt(name):
    return args[args.index(name) + 1] if name in args else None
serial = opt("-serial")
con = open(serial[5:], "ab", buffering=0)
open(opt("-pidfile"), "w").write("%d\n" % os.getpid())
sock = [p.split("=", 1)[1] for p in opt("-chardev").split(",") if p.startswith("path=")][0]
qlog = os.environ["FAKE_QMPLOG"]
srv = socket.socket(socket.AF_UNIX)
srv.bind(sock)
srv.listen(4)
def serve(c):
    f = c.makefile("rw")
    f.write(json.dumps({"QMP": {"version": {}, "capabilities": []}}) + "\n"); f.flush()
    for line in f:
        m = json.loads(line)
        cmd = m.get("execute")
        if cmd != "qmp_capabilities":
            open(qlog, "a").write("%.2f %s %s\n" % (time.time(), cmd, json.dumps(m.get("arguments", {}), sort_keys=True)))
        f.write(json.dumps({"return": {}}) + "\n"); f.flush()
        if cmd == "quit":
            os._exit(0)
def acceptor():
    while True:
        c, _ = srv.accept()
        threading.Thread(target=serve, args=(c,), daemon=True).start()
threading.Thread(target=acceptor, daemon=True).start()
signal.signal(signal.SIGTERM, lambda *a: os._exit(0))
def say(s, delay=0.3):
    time.sleep(delay)
    con.write((s + "\r\n").encode())
scen = os.environ.get("FAKE_SCENARIO", "work")
say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T")
if scen == "netfail":
    say("WRRUN-NET-FAILED no link")
    while True:
        time.sleep(1)
say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanhook"); say("WRRUN-SAN-OK")
if scen == "work":     # a workload of about 5 s, then the end marker
    say("WRRB-START drive=80 first=8 sectors=1")
    for i in range(10):
        say("WRRB-PROG lba=%d h=00000000 maxticks=1@8 rtc=000000 errs=0 stale=0" % i, 0.5)
    say("WRRB-DONE sectors=1 h=00000000 errs=0 stale=0 maxticks=1@8 rtc=000000 end=ok"); say("WRRUN-END")
elif scen == "short":  # ends almost at once
    say("WRRB-START drive=80 first=8 sectors=1"); say("WRRB-DONE sectors=1 h=00000000 errs=0 stale=0 maxticks=1@8 rtc=000000 end=ok"); say("WRRUN-END")
elif scen == "partial":  # the last line has no newline (a prompt, or a line cut off by the end of the run)
    say("WRRB-START drive=80 first=8 sectors=1"); say("WRRB-DONE sectors=1 h=00000000 errs=0 stale=0 maxticks=1@8 rtc=000000 end=ok")
    time.sleep(0.3); con.write(b"WRRUN-END")
elif scen == "netfail":  # the lab NIC has no link: the script says so and holds
    pass
elif scen == "leak":
    say("WRRB-START drive=80 first=8 sectors=1"); say("oops " + os.environ.get("FAKE_KEY", "")); say("WRRB-DONE x"); say("WRRUN-END")
while True:
    time.sleep(1)
EOS
cat > "$tmp/stubs/labstub" <<'EOS'
#!/usr/bin/env bash
# the lab VM: records every command, answers the few the fault driver asks
echo "$(date +%s.%N | cut -c1-14) $1" >> "$LABLOG"
case "$1" in
    *"ceph fsid"*) [ "${LABSTUB_FAIL:-}" = fsid ] && exit 1; echo 3e2ea2d5-e750-11f1-a548-525400771201;;
    *"list-units"*"mon."*) echo "ceph-3e2ea2d5-e750-11f1-a548-525400771201@mon.a.service";;
    *"list-units"*"osd."*) echo "ceph-3e2ea2d5-e750-11f1-a548-525400771201@osd.1.service";;
    *"pgrep -c"*) echo 3;;
    *quorum_status*) echo '{"quorum_names":["a"]}';;
    *"osd stat"*) echo '{"num_up_osds":3,"num_in_osds":3,"num_osds":3}';;
    *"health detail"*)
        if [ "${LABSTUB_HEALTH:-}" = improve ] && [ -s "$LABLOG.health" ]; then echo '{"checks":{}}'; else echo x >> "$LABLOG.health"; echo '{"checks":{"RECENT_CRASH":{}}}'; fi;;
    *"config dump"*) [ "${LABSTUB_FAIL:-}" = config ] && { echo "Error ENOENT"; exit 1; }
        echo   # (the real one starts its JSON with an empty line)
        if [ -n "${LABSTUB_IDLE_EXISTS:-}" ]; then echo '[{"section":"global","name":"container_image","value":"x"},{"section":"osd","name":"ms_connection_idle_timeout","value":"60"}]'; else echo '[{"section":"global","name":"container_image","value":"x"}]'; fi;;
    *"command -v tcpdump"*) [ "${LABSTUB_FAIL:-}" = nocapture ] && exit 1;;
    *"systemctl reset-failed"*) [ "${LABSTUB_FAIL:-}" = undo ] && exit 1;;
    *"date +%s"*) date +%s.%N;;
    *"timeout "*"tcpdump -i any"*) { echo "1.000000 lab0  In  IP 10.77.0.21.4000 > 10.77.0.10.3300: tcp 0"; sleep 30; };;
esac
exit 0
EOS
chmod 755 "$tmp/stubs/qemu-system-x86_64" "$tmp/stubs/labstub"
command -v nice >/dev/null 2>&1 || printf '#!/bin/sh\nshift 2\nexec "$@"\n' > "$tmp/stubs/nice"
command -v choom >/dev/null 2>&1 || printf '#!/bin/sh\nshift 3\nexec "$@"\n' > "$tmp/stubs/choom"
chmod 755 "$tmp/stubs"/* 2>/dev/null
export PATH=$tmp/stubs:$PATH
export P2Q_QEMU=$tmp/stubs/qemu-system-x86_64 P2Q_WORK=$tmp/work P2Q_BUDGET_CORES=24 P2Q_BUDGET_MEM_MB=32768
export P2Q_ACCEL=tcg   # the stand-in needs no KVM (and a CI runner or the builder guest has none)
export LABLOG=$tmp/out/lab.log FAKE_QMPLOG=$tmp/out/qmp.log FAKE_KEY=$KEY
: > "$tmp/ipxe/ipxe-stub.pxe"; : > "$tmp/ipxe/ipxe.efi"
BASE=(--family bios --bin "$tmp/ipxe/ipxe-stub.pxe" --delivery stub --row B1 --pool p --image i --user u --key-file "$tmp/keys/bare" --expect marker --marker '^WRRUN-END' --timeout 40 --lab-ssh "$tmp/stubs/labstub")
newest() { ls -t "$P2Q_WORK/logs"/*."$1" 2>/dev/null | head -n 1; }
runr() {
    : > "$LABLOG"; : > "$FAKE_QMPLOG"; rm -f "$LABLOG.health"
    o=$(FAKE_SCENARIO=${SCEN:-work} bash "$robust" "${BASE[@]}" "$@" 2>&1); rc=$?
    res=$(printf '%s\n' "$o" | grep '^RESULT ' | tail -n 1); fl=$(newest fault)
    [ -z "${SELFTEST_DEBUG:-}" ] || printf '%s\n' "$o" | sed 's/^/      | /' >&2
}
lab() { cat "$LABLOG"; }
qmp() { cat "$FAKE_QMPLOG"; }

SCEN=work runr --fault none
check "no fault: exit 0, the marker was seen" test "$rc" -eq 0 '&&' contains "$res" "stop=expectation"
check "no fault: the lab was not asked for anything" test "$(grep -c . "$LABLOG")" = 0
check "no fault: fault.txt says so" grep -q "fault none: nothing will be injected" "$fl"
check "the time-stamped console is written and every line has an epoch" test "$(grep -c -E '^[0-9]+\.[0-9]+ ' "$(newest ts)")" -ge 8
check "the time-stamped console has the end marker" grep -q 'WRRUN-END' "$(newest ts)"

SCEN=work runr --fault mon-kill --on '^WRRB-START' --delay 0.5 --down 1.5
check "mon-kill: exit 0" test "$rc" -eq 0
check "mon-kill: kill + stop, then start, then waits for quorum" contains "$(lab)" "systemctl kill -s KILL 'ceph-3e2ea2d5-e750-11f1-a548-525400771201@mon.a.service'; sudo systemctl stop" '&&' contains "$(lab)" "systemctl start 'ceph-3e2ea2d5-e750-11f1-a548-525400771201@mon.a.service'" '&&' contains "$(lab)" "quorum_status"
check "mon-kill: the begin, the kill, the start and the return are in fault.txt in that order" test "$(sed -n -e 's/^[0-9.]* T+[0-9]* fault mon-kill: begins.*/begin/p' -e 's/^[0-9.]* T+[0-9]* monitor killed.*/killed/p' -e 's/^[0-9.]* T+[0-9]* monitor started.*/started/p' -e 's/^[0-9.]* T+[0-9]* monitor is back in quorum.*/quorum/p' -e 's/^[0-9.]* T+[0-9]* fault mon-kill: ends.*/end/p' "$fl" | tr '\n' '|')" = "begin|killed|started|quorum|end|"
check "mon-kill: after the restart it asks cephadm for a refresh and waits for its health checks to go" contains "$(lab)" "ceph orch ps --refresh" '&&' contains "$(lab)" "ceph health detail" '&&' grep -q "health checks are the ones the run started with again" "$fl"
check "mon-kill: the guest was not touched" test "$(qmp | grep -c .)" = 1   # only the stop at the end of the run (quit)

SCEN=short runr --fault mon-kill --on '^WRRB-START' --delay 0 --down 30
check "a fault still waiting when the run ends is undone at once" test "$rc" -eq 0
check "...and fault.txt says that the run ended first" grep -q "the run ended before the fault did" "$fl"
check "...and the monitor was started again" contains "$(lab)" "systemctl start 'ceph-3e2ea2d5-e750-11f1-a548-525400771201@mon.a.service'"
check "...within seconds, not after the 30 s" test "$(grep -c "monitor started" "$fl")" -le 1

SCEN=work runr --fault mon-osd --on '^WRRB-START' --delay 0.3 --down 1
check "mon-osd: the monitor is killed first, then the OSD, with the monitor down" test "$rc" -eq 0 '&&' grep -q "killed (rc 0), with the monitor down" "$fl"
check "mon-osd: starts the monitor, waits for quorum, starts the OSD" contains "$(lab)" "@osd.1.service'; sudo systemctl stop" '&&' contains "$(lab)" "quorum_status" '&&' contains "$(lab)" "osd stat"

SCEN=work runr --fault osd-kill --osd 1 --on '^WRRB-START' --delay 0.3 --down 1
check "osd-kill: kill + stop, start, wait for all OSDs up and in" test "$rc" -eq 0 '&&' contains "$(lab)" "systemctl kill -s KILL 'ceph-3e2ea2d5-e750-11f1-a548-525400771201@osd.1.service'" '&&' contains "$(lab)" "osd stat" '&&' grep -q "all OSDs up and in again" "$fl"

SCEN=work runr --fault stall --on '^WRRB-START' --delay 0.3 --down 1
check "stall: STOP, then CONT, then waits for the OSDs" test "$rc" -eq 0 '&&' contains "$(lab)" "pkill -STOP -x ceph-osd" '&&' contains "$(lab)" "pkill -CONT -x ceph-osd"
check "stall: STOP comes before CONT" test "$(grep -n -E 'pkill -(STOP|CONT)' "$LABLOG" | head -n 1 | grep -c STOP)" = 1

SCEN=work runr --fault pause --on '^WRRB-START' --delay 0.3 --down 1.5
check "pause: QMP stop, then cont" test "$rc" -eq 0 '&&' test "$(qmp | awk '{print $2}' | grep -E '^(stop|cont)$' | tr '\n' ' ')" = "stop cont "

SCEN=work runr --fault pause --on '^WRRB-START' --delay 0.3 --down 1 --idle-timeout 20
check "--idle-timeout: set for the monitor and the OSDs before the guest runs, removed afterwards" test "$rc" -eq 0 '&&' contains "$(lab)" "ceph config set osd ms_connection_idle_timeout 20" '&&' contains "$(lab)" "ceph config set mon ms_connection_idle_timeout 20" '&&' contains "$(lab)" "ceph config rm osd ms_connection_idle_timeout"
check "--idle-timeout: the setting comes first and the removal last" test "$(grep -n -E 'config (set|rm)' "$LABLOG" | head -n 1 | grep -c 'config set')" = 1 '&&' test "$(grep -n -E 'config (set|rm)' "$LABLOG" | tail -n 1 | grep -c 'config rm')" = 1
check "--idle-timeout: fault.txt says both" grep -q "ms_connection_idle_timeout set to 20" "$fl" '&&' grep -q "ms_connection_idle_timeout removed again" "$fl"

SCEN=work runr --fault link-down --on '^WRRB-START' --delay 0.3 --down 1.5
check "link-down: set_link false, then true, on the netdev named lab" test "$rc" -eq 0 '&&' test "$(qmp | grep set_link | grep -c '"name": "lab"')" = 2 '&&' test "$(qmp | grep set_link | head -n 1 | grep -c false)" = 1 '&&' test "$(qmp | grep set_link | tail -n 1 | grep -c true)" = 1

SCEN=work runr --fault none --on '^WRRB-START' --press "ret" --press-delay 0.2
check "--press: one send-key of Enter" test "$rc" -eq 0 '&&' test "$(qmp | grep -c send-key)" = 1 '&&' grep -q "keys 'ret' pressed" "$fl"

SCEN=work runr --fault pause --on '^NEVER-PRINTED' --delay 0 --down 1
check "a trigger that never appears: exit 3 and the fault log says nothing was injected" test "$rc" -eq 3 '&&' grep -q "NO FAULT WAS INJECTED" "$fl"

LABSTUB_FAIL=fsid SCEN=work runr --fault mon-kill --on '^WRRB-START'
check "a fault that cannot be prepared stops the run before the guest starts" test "$rc" -ne 0 '&&' not_contains "$o" "starting wrp2q" '&&' contains "$o" "fsid"
unset LABSTUB_FAIL

SCEN=work runr --fault stall --on '^WRRB-START' --delay 0.3 --down 1 --capture
check "--capture: a tcpdump is started in the lab VM, limited to the guest and the monitor ports" contains "$(lab)" "tcpdump -i any -nn -l -tt -q" '&&' contains "$(lab)" "port 3300 or port 6789"
check "--capture: its output is kept next to the other logs" test -s "$(newest syn)"

LABSTUB_FAIL=nocapture SCEN=work runr --fault none --capture
check "--capture: a lab without tcpdump stops the run before the guest starts" test "$rc" -ne 0 '&&' not_contains "$o" "starting wrp2q" '&&' contains "$o" "--capture needs"
unset LABSTUB_FAIL

LABSTUB_IDLE_EXISTS=1 SCEN=work runr --fault pause --on '^WRRB-START' --idle-timeout 20
check "--idle-timeout: a lab that already has the setting is refused, and nothing is set or removed" test "$rc" -ne 0 '&&' not_contains "$o" "starting wrp2q" '&&' contains "$o" "already has ms_connection_idle_timeout" '&&' not grep -q 'config set\|config rm' "$LABLOG"
unset LABSTUB_IDLE_EXISTS
LABSTUB_FAIL=config SCEN=work runr --fault pause --on '^WRRB-START' --idle-timeout 20
check "--idle-timeout: a lab whose configuration cannot be read is refused too (the undo could not be trusted)" test "$rc" -ne 0 '&&' not_contains "$o" "starting wrp2q" '&&' contains "$o" "cannot read the lab's configuration" '&&' not grep -q 'config set' "$LABLOG"
unset LABSTUB_FAIL

LABSTUB_HEALTH=improve SCEN=work runr --fault mon-kill --on '^WRRB-START' --delay 0.3 --down 1
check "a cluster with fewer health checks than at the start is not a failure (and the wait does not run out)" test "$rc" -eq 0 '&&' grep -q "the health checks are the ones the run started with again" "$fl"
unset LABSTUB_HEALTH

LABSTUB_FAIL=undo SCEN=work runr --fault mon-kill --on '^WRRB-START' --delay 0.3 --down 1
check "a fault whose undo fails: exit 3 and fault.txt says UNDO FAILED" test "$rc" -eq 3 '&&' grep -q "UNDO FAILED" "$fl"
unset LABSTUB_FAIL

SCEN=partial runr --fault none
check "a last console line without its newline is in the time-stamped console too" test "$rc" -eq 0 '&&' grep -q 'WRRUN-END' "$(newest ts)"

SCEN=netfail runr --fault none --expect san --timeout 30
check "no link on the lab NIC: the run ends at once, not at the timeout (net-failed)" contains "$res" "stop=net-failed"

# a signal in the middle of a fault: the lab must be put back before the script exits (the header promises it)
: > "$LABLOG"; : > "$FAKE_QMPLOG"; rm -f "$LABLOG.health"
pre=$(newest fault)
FAKE_SCENARIO=work bash "$robust" "${BASE[@]}" --fault mon-kill --on '^WRRB-START' --delay 0.3 --down 60 > "$tmp/out/sig.out" 2>&1 &
sigpid=$!
fl=$pre
for _ in $(seq 1 60); do fl=$(newest fault); [ "$fl" != "$pre" ] && grep -q "monitor killed" "$fl" 2>/dev/null && break; sleep 0.5; done
check "signal: the monitor was killed and the run is still going" grep -q "monitor killed" "$fl" '&&' kill -0 "$sigpid" 2>/dev/null
kill -TERM "$sigpid" 2>/dev/null
wait "$sigpid" 2>/dev/null; rc=$?
check "signal: SIGTERM ends the script with 143" test "$rc" -eq 143
check "signal: the monitor was started again before the script exited" grep -q "the run ended before the fault did" "$fl" '&&' contains "$(lab)" "systemctl start 'ceph-3e2ea2d5-e750-11f1-a548-525400771201@mon.a.service'"
check "signal: no guest and no run directory left" test -z "$(find "$P2Q_WORK/runs" -mindepth 1 2>/dev/null | head -n 1)" '&&' test -z "$(ps -eww -o args= | grep -F -- "-name wrp2q-" | grep -F "$tmp" | grep -v grep || true)"

SCEN=leak runr --fault none
runid=$(printf '%s' "$res" | sed -n 's/.* run=\([^ ]*\) .*/\1/p')
check "the key in the console: exit 4, and the console, the time-stamped console and the QEMU output of that run are discarded" test "$rc" -eq 4 '&&' contains "$res" "console=discarded-key-leak" '&&' test -n "$runid" '&&' not test -e "$P2Q_WORK/logs/$runid.console" '&&' not test -e "$P2Q_WORK/logs/$runid.ts" '&&' not test -e "$P2Q_WORK/logs/$runid.qemu"
check "nothing of any run is left behind" test -z "$(find "$P2Q_WORK/runs" -mindepth 1 2>/dev/null | head -n 1)"
check "no QEMU stand-in is left" test -z "$(ps -eww -o args= | grep -F -- "-name wrp2q-" | grep -F "$tmp" | grep -v grep || true)"
check "the key is nowhere under the work directory except where the stock library keeps it" test -z "$(grep -r -a -l -F "$KEY" "$P2Q_WORK" 2>/dev/null | head -n 1)"

echo
echo "robust.selftest: $pass passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]
