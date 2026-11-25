#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# selftest.sh - offline test of the scripts of the qemu-bios module: no QEMU, no KVM, no cluster, no network.
#
#   selftest.sh            (ctest: bios.selftest)
#
#   1. analyse.py's own self-test
#   2. the verdicts on synthetic logs: a good B1 / B0 / negative-control log is PASS, and each deliberate defect (a failed table field, no
#      marker, a drive that is not visible, a second console line, a boot that goes on after the failure) is FAIL: a verdict that cannot say
#      FAIL proves nothing
#   3. tailts.py against a growing file and a fake QMP socket: stamps, the chunk file, the pause (stop, hook, wait, cont), the end when the
#      process has gone, and a pause whose "stop" cannot be sent (no pause line, nothing resumed)
#   3b. lib.sh's key scan and clean-up: a log that holds the key is found and is never copied into the evidence; a clean one is
#   4. the two run scripts in dry-run mode over the stock library: the NIC topology of each (one lab NIC that boots PXE; the user NIC with
#      TFTP plus the lab NIC for the media), and that the key never shows
#   5. every script parses (bash -n, python compile)
set -u -o pipefail
LC_ALL=C
export LC_ALL
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/p2bios-selftest.XXXXXX") || exit 2
trap 'rm -f "$tmp"/* "$tmp"/*/* 2>/dev/null; rmdir "$tmp"/* 2>/dev/null; rmdir "$tmp" 2>/dev/null' EXIT
fail=0
ok() { echo "ok    $*"; }
bad() { echo "FAIL  $*"; fail=$((fail + 1)); }
PY="python3 -I"

# ---- 1
if $PY "$here/analyse.py" --selftest >/dev/null; then ok "analyse.py self-test"; else bad "analyse.py self-test"; fi

# ---- 2: synthetic logs
mk() { # NAME : lines on stdin ("SECONDS TEXT"), written to $tmp/NAME.ts and an empty chunk file
    { echo "# tailts start epoch=0"; cat; } > "$tmp/$1.ts"
    : > "$tmp/$1.chunks"
}
good_b1() {
    cat <<'EOF'
7.9 WRRUN-STUB
11.1 WRRUN-NET-OK
11.2 WRRUN-SAN-START sanboot
11.6 Booting from SAN device 0x80
33.0 RBFT INFO source: scan: found at physical address 0x9a840 (1 valid copy/copies)
33.4 RBFT-RESULT PASS pass=40 fail=0 skip=0
33.5 WRBOOT-TABLE PASS
68.1 WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1 fstype=ext4 mapped=rbd0 table=PASS src=scan image=wrtest-p2-b1 kernel=6.8.0-151-generic
EOF
}
# verdict_is WANT LOG ROW RESULT EXIT : does analyse.py --verdict print "VERDICT WANT"? (its exit status is 1 for FAIL, so it is read into a variable first)
verdict_is() {
    local o
    o=$($PY "$here/analyse.py" "$tmp/$2" --verdict "$3" --result "$4" --exit "$5") || true
    printf '%s\n' "$o" | grep -q "^VERDICT $1\$"
}
RES='RESULT row=B1 run=x expect=os met=1 stop=expectation secs=70'
good_b1 | mk b1good
if verdict_is PASS b1good b1 "$RES" 0; then ok "verdict: a good B1 log is PASS"; else bad "verdict: a good B1 log is PASS"; fi
good_b1 | sed 's/RBFT-RESULT PASS pass=40 fail=0 skip=0/RBFT-RESULT FAIL pass=39 fail=1 skip=0/' | mk b1fail
if verdict_is FAIL b1fail b1 "$RES" 0; then ok "verdict: a failed table field is FAIL"; else bad "verdict: a failed table field is FAIL"; fi
good_b1 | grep -v WRBOOT-ROOT-OK | mk b1nomark
if verdict_is FAIL b1nomark b1 "$RES" 0; then ok "verdict: no marker is FAIL"; else bad "verdict: no marker is FAIL"; fi
good_b1 | sed 's/root=\/dev\/rbd0p1/root=\/dev\/sda1/' | mk b1localroot
if verdict_is FAIL b1localroot b1 "$RES" 0; then ok "verdict: a root that is not on the image is FAIL"; else bad "verdict: a root that is not on the image is FAIL"; fi
if verdict_is FAIL b1good b1 "$RES" 4; then ok "verdict: run script exit 4 (key in a log) is FAIL"; else bad "verdict: run script exit 4 is FAIL"; fi
if verdict_is FAIL b1good b1 "${RES/met=1/met=0}" 0; then ok "verdict: met=0 is FAIL"; else bad "verdict: met=0 is FAIL"; fi

# the table must be the WHOLE table: "PASS" of fewer fields than the checker has is not a pass
good_b1 | sed 's/pass=40 fail=0 skip=0/pass=39 fail=0 skip=0/' | mk b1short
if verdict_is FAIL b1short b1 "$RES" 0; then ok "verdict: a PASS of 39 of 40 fields is FAIL"; else bad "verdict: a PASS of 39 of 40 fields is FAIL"; fi
# a row this script does not know must not read as PASS because its list of criteria is short
if verdict_is FAIL b1good B1 "$RES" 0; then ok "verdict: an unknown row name is FAIL"; else bad "verdict: an unknown row name is FAIL"; fi

cat <<'EOF' | mk b0good
11.1 WRRUN-NET-OK
11.3 WRRUN-SAN-OK
11.6 WRRUN-END
129.7 RBFT INFO source: scan: found at physical address 0x9e120 (1 valid copy/copies)
129.7 RBFT-RESULT PASS pass=40 fail=0 skip=0
129.7 WRBOOT-EDD int13_dev80 mbr_signature=0x7d1f0001
129.7 WRBOOT-EDD int13_dev81 mbr_signature=0x7d1f0002
129.7 WRBOOT-ROOT-OK fw=bios root=initramfs fstype=rootfs mapped=none table=PASS src=scan image=wrtest-p2-b0 kernel=6.8.0-151-generic
EOF
if verdict_is PASS b0good b0 "$RES" 0; then ok "verdict: a good B0 log is PASS"; else bad "verdict: a good B0 log is PASS"; fi
# the roadmap-visible case: B0's marker line exists but says the table failed (WRBOOT-ROOT-TABLE-FAIL is a marker too)
sed 's/WRBOOT-ROOT-OK fw=bios root=initramfs/WRBOOT-ROOT-TABLE-FAIL fw=bios root=initramfs/' "$tmp/b0good.ts" | grep -v '^#' | mk b0badmarker
if verdict_is FAIL b0badmarker b0 "$RES" 0; then ok "verdict: B0 with a WRBOOT-ROOT-TABLE-FAIL marker is FAIL"; else bad "verdict: B0 with a failure marker is FAIL"; fi
grep -v int13_dev81 "$tmp/b0good.ts" | mk b0novis
if verdict_is FAIL b0novis b0 "$RES" 0; then ok "verdict: a hooked drive the BIOS does not see is FAIL"; else bad "verdict: B0 without int13_dev81 is FAIL"; fi

cat <<'EOF' | mk neggood
7.9 WRRUN-STUB
11.1 WRRUN-NET-OK
11.2 WRRUN-SAN-START sanboot
11.9 rbd: open failed: the cluster refused the key (WR_E_AUTH_DENIED)
11.9 Could not open SAN device: Permission denied (https://ipxe.org/0x00000000)
12.0 WRRUN-SAN-FAILED 0x3c2d0539
12.0 WRRUN-END
EOF
NEG='RESULT row=B1-NEG run=x expect=marker met=1 stop=expectation secs=20'
if verdict_is PASS neggood neg "$NEG" 0; then ok "verdict: a wrong key that fails with one console line is PASS"; else bad "verdict: negative control PASS case"; fi
{ cat "$tmp/neggood.ts"; echo "13.0 rbd: a second line"; } | grep -v '^#' | mk negtwo
if verdict_is FAIL negtwo neg "$NEG" 0; then ok "verdict: a second driver line is FAIL"; else bad "verdict: negative control with two lines"; fi
{ grep -v '^#' "$tmp/neggood.ts"; echo "14.0 GNU GRUB  version 2.14"; } | mk negboot
if verdict_is FAIL negboot neg "$NEG" 0; then ok "verdict: a boot that goes on after the failure is FAIL"; else bad "verdict: negative control that boots"; fi

# ---- 3: tailts.py with a fake QMP server
cat > "$tmp/fakeqmp.py" <<'PY'
import json, os, socket, sys
path, log = sys.argv[1], sys.argv[2]
if os.path.exists(path):
    os.unlink(path)
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(4)
srv.settimeout(20)
n = 0
while n < 2:
    try:
        c, _ = srv.accept()
    except socket.timeout:
        break
    f = c.makefile("rw")
    f.write(json.dumps({"QMP": {"version": {}}}) + "\n"); f.flush()
    for line in f:
        m = json.loads(line)
        f.write(json.dumps({"return": {}}) + "\n"); f.flush()
        if m["execute"] in ("stop", "cont"):
            with open(log, "a") as o:
                o.write(m["execute"] + "\n")
            n += 1
            break
    c.close()
PY
: > "$tmp/console.log"
$PY "$tmp/fakeqmp.py" "$tmp/q.sock" "$tmp/qmp.log" &
qpid=$!
sleep 1 &
spid=$!
sleep 0.3
$PY "$here/tailts.py" "$tmp/console.log" "$tmp/out.ts" "$spid" --qmp "$tmp/q.sock" --pause-on 'PAUSE-HERE' --pause-secs 1 --pause-hook "echo hooked > $tmp/hook.txt" &
tpid=$!
{ printf 'first line\r\n'; sleep 0.2; printf 'GRUB-like text without newline'; sleep 0.2; printf '\nPAUSE-HERE now\nlast\n'; } >> "$tmp/console.log"
wait "$tpid"
wait "$qpid" 2>/dev/null
if grep -q 'first line' "$tmp/out.ts" && grep -q 'PAUSE-HERE now' "$tmp/out.ts"; then ok "tailts: lines are time-stamped"; else bad "tailts: lines are time-stamped"; fi
if [ "$(wc -l < "$tmp/out.ts.chunks")" -ge 2 ] && grep -q 'GRUB-like' "$tmp/out.ts.chunks"; then ok "tailts: chunks keep the pieces that have no newline"; else bad "tailts: chunk file"; fi
if grep -q 'PAUSE stop' "$tmp/out.ts" && grep -q 'PAUSE cont' "$tmp/out.ts" && grep -q 'hook rc=0' "$tmp/out.ts" && [ -f "$tmp/hook.txt" ]; then ok "tailts: pause = stop, hook, wait, cont"; else bad "tailts: the pause"; cat "$tmp/out.ts"; fi
if [ "$(tr '\n' ' ' < "$tmp/qmp.log")" = "stop cont " ]; then ok "tailts: QMP got stop then cont and nothing else"; else bad "tailts: QMP commands: $(tr '\n' ' ' < "$tmp/qmp.log")"; fi

# a pause whose "stop" cannot be sent (no QMP socket): the tool says so, writes no "PAUSE stop" line, sends nothing else and ends with the process
: > "$tmp/console2.log"
sleep 5 &
spid=$!
$PY "$here/tailts.py" "$tmp/console2.log" "$tmp/out2.ts" "$spid" --qmp "$tmp/no-such.sock" --pause-on 'PAUSE-HERE' --pause-secs 1 &
tpid=$!
sleep 0.3
printf 'PAUSE-HERE now\nafter\n' >> "$tmp/console2.log"
wait "$tpid"
if grep -q 'PAUSE error stop failed' "$tmp/out2.ts" && ! grep -q '# PAUSE stop' "$tmp/out2.ts" && ! grep -q '# PAUSE cont' "$tmp/out2.ts" && grep -q 'after' "$tmp/out2.ts"; then ok "tailts: a stop that cannot be sent is reported, the log goes on"; else bad "tailts: failing stop"; cat "$tmp/out2.ts"; fi

# ---- 3b: lib.sh (the key scan and the clean-up of the time-stamped logs), over stubs of the stock library's four functions
(
    q_start() { :; }; q_stop() { :; }; q_key_scan() { KEY_LEAK=0; }; q_cleanup() { :; }
    # shellcheck source=lib.sh
    . "$here/lib.sh"
    RUNDIR=$tmp/libsh LOGBASE=$tmp/libsh-log
    mkdir -p "$RUNDIR"
    KEYSCAN=$RUNDIR/key.txt
    echo 'SECRETSECRETSECRETSECRET==' > "$KEYSCAN"
    printf '# tailts start epoch=0\n7.000 a line with SECRETSECRETSECRETSECRET== inside\n' > "$RUNDIR/console.ts"
    q_key_scan
    [ "${KEY_LEAK:-0}" = 1 ] || exit 11
    q_cleanup
    [ ! -e "$LOGBASE.ts" ] || exit 12
    [ ! -e "$RUNDIR/console.ts" ] || exit 13
    printf '# tailts start epoch=0\n7.000 a clean line\n' > "$RUNDIR/console.ts"
    echo '[7.0, "a clean line"]' > "$RUNDIR/console.ts.chunks"
    KEY_LEAK=0
    q_key_scan
    [ "${KEY_LEAK:-0}" = 0 ] || exit 14
    q_cleanup
    [ -s "$LOGBASE.ts" ] && [ -s "$LOGBASE.chunks" ] && [ ! -e "$RUNDIR/console.ts" ] || exit 15
    exit 0
)
rc=$?
if [ "$rc" = 0 ]; then ok "lib.sh: a log with the key is found and never copied; a clean one is copied and the working copy removed"; else bad "lib.sh key scan / clean-up (exit $rc)"; fi

# ---- 4: the run scripts in dry-run mode
qdir=$here/../../../qemu
if [ -f "$qdir/common.sh" ]; then
    mkdir -p "$tmp/lab/ssh" "$tmp/work"
    : > "$tmp/ipxe.bin"
    echo 'AAAAAAAAAAAAAAAAAAAAAA==' > "$tmp/k.secret"
    chmod 600 "$tmp/k.secret"
    out=$(LAB_DIR="$tmp/lab" P2Q_WORK="$tmp/work" bash "$here/run-undi.sh" -n --row B1 --bin "$tmp/ipxe.bin" --delivery stub --pool winrbd --image x --user x \
        --key-file "$tmp/k.secret" --ip 10.77.0.71 2>&1 | tr -d '\\')
    if printf '%s\n' "$out" | grep -q 'would run' && printf '%s\n' "$out" | grep -q 'mac=52:54:00:77:12:c7,bootindex=1' &&
        ! printf '%s\n' "$out" | grep -q 'restrict=on'; then ok "run-undi.sh: one NIC, the lab NIC, boots PXE; no user-mode NIC"; else bad "run-undi.sh dry run"; printf '%s\n' "$out" | tail -5; fi
    if printf '%s\n' "$out" | grep -q 'AAAAAAAAAAAAAAAAAAAAAA'; then bad "run-undi.sh: the key is in the dry-run output"; else ok "run-undi.sh: the key is not in the dry-run output"; fi
    out=$(LAB_DIR="$tmp/lab" P2Q_WORK="$tmp/work" bash "$here/run-media.sh" usb -n --row B2 --media "$tmp/ipxe.bin" --ipxe-dir "$tmp" --bin "$tmp/ipxe.bin" --delivery embed --pool winrbd --image x --user x \
        --key-file "$tmp/k.secret" --ip 10.77.0.73 2>&1 | tr -d '\\')
    if printf '%s\n' "$out" | grep -q 'restrict=on,tftp=' && printf '%s\n' "$out" | grep -q 'mcast=' && printf '%s\n' "$out" | grep -q 'usb-storage'; then ok "run-media.sh usb: user NIC with TFTP, lab NIC, USB stick"; else bad "run-media.sh usb dry run"; printf '%s\n' "$out" | tail -5; fi
    out=$(LAB_DIR="$tmp/lab" P2Q_WORK="$tmp/work" bash "$here/run-media.sh" iso -n --row B3 --media "$tmp/ipxe.bin" --ipxe-dir "$tmp" --bin "$tmp/ipxe.bin" --delivery embed --pool winrbd --image x --user x \
        --key-file "$tmp/k.secret" --ip 10.77.0.74 2>&1 | tr -d '\\')
    if printf '%s\n' "$out" | grep -q 'ide-cd'; then ok "run-media.sh iso: CD-ROM"; else bad "run-media.sh iso dry run"; fi
    rm -rf "$tmp/lab" "$tmp/work" 2>/dev/null
    # (the dry run creates nothing: the directories above were ours)
else
    echo "skip  run scripts (the stock library $qdir/common.sh is not here)"
fi

# ---- 5: syntax
for f in "$here"/*.sh; do
    if bash -n "$f"; then :; else bad "bash -n $(basename "$f")"; fi
done
for f in "$here"/*.py; do
    if $PY -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f"; then :; else bad "python syntax $(basename "$f")"; fi
done
ok "every script parses"

if [ "$fail" = 0 ]; then echo "selftest: all passed"; exit 0; fi
echo "selftest: $fail FAILED"
exit 1
