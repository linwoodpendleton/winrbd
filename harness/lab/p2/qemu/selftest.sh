#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Offline self-test of the Phase 2 QEMU scripts (common.sh, gen-script.sh, the six run scripts, make-usb.sh's argument handling).
# No KVM, no real QEMU, no network, no root, no cluster: QEMU is replaced by a small stand-in that has the same command-line
# surface the scripts use (-name, -pidfile, -serial file:, the QMP control socket), prints what a scenario says, and obeys quit /
# SIGTERM. Every file the test makes is below one temporary directory, removed at the end.
#
#   selftest.sh            run everything; exit status 0 only when every check passed
#   selftest.sh --quick    the cases that start no process (generator, dry runs, option refusals, process-list parsing)
#
# What it proves (each line is a defect found by review, or a promise of the README):
#   * the generated iPXE script never carries the key anywhere but in its one "set rbd-key" line; --redact hides it; a key file
#     that is group- or world-readable is refused; a password in the URI is refused; octal-looking addresses ("020") are refused;
#     every goto has its label (all action / leave / on-fail combinations); sanboot never claims success; the error number is
#     printed in the form the run scripts' markers expect; the stub holds no secret
#   * the QEMU command line: nice 19 + choom 600, a name per run, restricted user-mode networking + the lab's multicast socket
#     only, no tap / bridge / forward / listening socket, the USB image read-only, pflash only for UEFI, the six rows differ
#     as the matrix says; --qemu-arg cannot add a host network, a VNC / gdb / TCP monitor, a shared directory
#   * the process-list parsing: the budget counts the QEMUs under the root (the ps column is the first word), the leftover check
#     finds this run's guest and nothing else (it once matched every QEMU of the machine), the address check
#   * a whole run against the stand-in: success, timeout, the SAN open failing (stops at once), the guest ending, QEMU not starting,
#     the key appearing in a console log (logs discarded, exit 4), a TERM to the run script (guest stopped, files removed), two
#     run scripts started at the same moment against a budget for one (exactly one starts), and after each run: no file of the
#     run is left, in particular nothing that held the key
# shellcheck disable=SC2329,SC2016,SC2015  # the cases are called through their names; the quotes are deliberate
# shellcheck disable=SC2030,SC2031  # the library is sourced inside ( ) groups on purpose: its settings must not leak into the later cases
# shellcheck disable=SC2009,SC2012  # `ps -o args=` is read for the exact command line (pgrep -f would also match its own); ls only counts files we named
set -u

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
quick=0
[ "${1:-}" != --quick ] || quick=1

pass=0 fail=0 skipped=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n' "$1" >&2; }
skip() { skipped=$((skipped + 1)); printf '  skip %s\n' "$1"; }
check() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
contains() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }
not_contains() { ! contains "$1" "$2"; }
rc_has() { [ "$1" -eq "$2" ] && contains "$3" "$4"; }   # RC WANT OUTPUT TEXT

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-p2q-selftest.XXXXXX")
case "$tmp" in /*/*) ;; *) echo "bad temporary directory $tmp" >&2; exit 2;; esac
cleanup() { # fixed layout: files first, then the directories (never a recursive delete of a variable)
    find "$tmp" -type f -delete 2>/dev/null || true
    find "$tmp" -type s -delete 2>/dev/null || true
    find "$tmp" -depth -type d -exec rmdir {} + 2>/dev/null || true
}
trap cleanup EXIT

gen=$here/gen-script.sh
KEY='AQDmYtZnAAAAABAAEXAMPLEKEYEXAMPLEKEYAA=='
umask 077
mkdir -p "$tmp/keys" "$tmp/stubs" "$tmp/ipxe" "$tmp/out"
printf '%s\n' "$KEY" > "$tmp/keys/bare"
chmod 600 "$tmp/keys/bare"
printf '[client.lab]\n\tkey = %s\n' "$KEY" > "$tmp/keys/keyring"
chmod 600 "$tmp/keys/keyring"
cp "$tmp/keys/bare" "$tmp/keys/open"
chmod 644 "$tmp/keys/open"

echo "== generator (gen-script.sh)"

URI_ARGS=(--pool rbd --image img1 --user lab --mon 10.77.0.10:3300)
rc=0; "$gen" -o "$tmp/out/s1.ipxe" --row U1 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" || rc=$?
check "the script is written" test "$rc" -eq 0
mode=$(stat -c %a "$tmp/out/s1.ipxe" 2>/dev/null || stat -f %Lp "$tmp/out/s1.ipxe")
check "the script file is mode 600" test "$mode" = 600
check "the key is in the script, once, in the rbd-key line" test "$(grep -c -F "$KEY" "$tmp/out/s1.ipxe")" = 1
check "that line is 'set rbd-key <key>'" grep -q -x "set rbd-key $KEY" "$tmp/out/s1.ipxe"
red=$("$gen" --redact --row U1 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare")
check "--redact hides the key" not_contains "$red" "$KEY"
check "--redact says where it was" contains "$red" "set rbd-key <redacted>"
out=$("$gen" -o "$tmp/out/s2.ipxe" "${URI_ARGS[@]}" --key-file "$tmp/keys/keyring" 2>&1); rc=$?
check "a keyring's 'key = ...' line is accepted" test "$rc" -eq 0 -a "$(grep -c -F "$KEY" "$tmp/out/s2.ipxe")" = 1
out=$("$gen" -o "$tmp/out/s3.ipxe" "${URI_ARGS[@]}" --key-file "$tmp/keys/open" 2>&1); rc=$?
check "a group/world readable key file is refused (exit 2)" test "$rc" -eq 2
check "...and the message does not show the key" not_contains "$out" "$KEY"
check "...and writes nothing" test ! -e "$tmp/out/s3.ipxe"
out=$("$gen" -o - "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" 2>&1); rc=$?
check "a script with a key is never written to stdout" test "$rc" -eq 2 -a "${out#*"$KEY"}" = "$out"
out=$("$gen" --redact --uri 'rbd://lab:SECRETPW@10.77.0.10:3300/rbd/img' --key-file "$tmp/keys/bare" 2>&1); rc=$?
check "a password in the URI is refused" test "$rc" -eq 2
check "...without printing it" not_contains "$out" SECRETPW
for badip in 10.77.0.020 10.77.0.256 10.77.0.1.5 10.77.0 08.1.1.1; do
    "$gen" --redact --ip "$badip" "${URI_ARGS[@]}" --no-key >/dev/null 2>&1; rc=$?
    check "address $badip is refused" test "$rc" -eq 2
done
"$gen" --redact --ip 10.77.0.99 --netmask 255.255.255.0 "${URI_ARGS[@]}" --no-key >/dev/null 2>&1; rc=$?
check "a plain address is accepted" test "$rc" -eq 0
out=$("$gen" --redact --ip 10.77.0.20 "${URI_ARGS[@]}" --no-key)
check "the lab MAC is derived (last octet + 128) in lower case" contains "$out" "set labmac 52:54:00:77:12:94"
check "the rbd:// URI is composed" contains "$out" "sanhook rbd://lab@10.77.0.10:3300/rbd/img1 || goto san-fail"
check "the error number is printed in the form the markers look for" contains "$out" 'WRRUN-SAN-FAILED 0x${errno:hexraw}'
check "...and the unreadable colon form is not used" not_contains "$out" '${errno:hex}'

# structure: every goto has a label, every label is unique
structure_ok() { # FILE
    local f=$1 l dup
    while read -r l; do
        grep -q -x ":$l" "$f" || { echo "goto $l has no label" >&2; return 1; }
    done < <(grep -E '(\|\| |^)goto ' "$f" | sed -E 's/.*goto ([A-Za-z0-9_-]+).*/\1/' | sort -u)
    dup=$(grep -E '^:' "$f" | sort | uniq -d)
    [ -z "$dup" ] || { echo "duplicate label $dup" >&2; return 1; }
}
n=0 badn=0
for action in sanhook sanboot none; do for leave in exit poweroff none; do for onfail in poweroff hold exit; do
    n=$((n + 1))
    "$gen" -o "$tmp/out/c.ipxe" --action "$action" --leave "$leave" --on-fail "$onfail" "${URI_ARGS[@]}" --fake-key >/dev/null 2>&1 || { badn=$((badn + 1)); continue; }
    structure_ok "$tmp/out/c.ipxe" 2>/dev/null || badn=$((badn + 1))
    rm -f "$tmp/out/c.ipxe"
done; done; done
check "every action/leave/on-fail combination ($n) is a well-formed script (gotos and labels)" test "$badn" -eq 0
sb=$("$gen" --redact --action sanboot "${URI_ARGS[@]}" --no-key)
check "sanboot never prints WRRUN-SAN-OK" not_contains "$sb" WRRUN-SAN-OK
check "sanboot that returns says so and fails" contains "$sb" WRRUN-BOOT-RETURNED
sh=$("$gen" --redact --action sanhook "${URI_ARGS[@]}" --no-key)
check "sanhook says WRRUN-SAN-OK when it worked" contains "$sh" WRRUN-SAN-OK
"$gen" -o "$tmp/out/f1" "${URI_ARGS[@]}" --fake-key; "$gen" -o "$tmp/out/f2" "${URI_ARGS[@]}" --fake-key
k1=$(sed -n 's/^set rbd-key //p' "$tmp/out/f1"); k2=$(sed -n 's/^set rbd-key //p' "$tmp/out/f2")
check "--fake-key: a random 28-byte key (40 base64 characters), a new one each time" test "${#k1}" -eq 40 -a "$k1" != "$k2"
rm -f "$tmp/out/f1" "$tmp/out/f2"
"$gen" --stub -o "$tmp/out/stub.ipxe"
check "the stub holds no key and no rbd setting or URI" test "$(grep -c -E 'rbd-key|rbd-user|rbd://' "$tmp/out/stub.ipxe")" = 0
check "the stub reports its error number readably" grep -q '0x${errno:hexraw}' "$tmp/out/stub.ipxe"
structure_ok "$tmp/out/stub.ipxe"; check "the stub's gotos have labels" test $? -eq 0
"$gen" --smoke -o "$tmp/out/smoke.ipxe"
structure_ok "$tmp/out/smoke.ipxe"; check "the smoke script's gotos have labels" test $? -eq 0
check "the smoke script holds no key setting and no real key" test "$(grep -c -E 'rbd-key|rbd-user|AQ[A-Za-z0-9+/]{20}' "$tmp/out/smoke.ipxe")" = 0
check "the smoke script has its three tests and ends with SMOKE-DONE" test "$(grep -c -E '^echo (test: password in URI must be refused|test: well formed URI must fail closed|test: unknown scheme control)$' "$tmp/out/smoke.ipxe")" = 3 -a "$(tail -n 2 "$tmp/out/smoke.ipxe" | head -n 1)" = "echo SMOKE-DONE"
check "the smoke script prints error numbers in the readable form" grep -q 'refused: 0x${errno:hexraw}' "$tmp/out/smoke.ipxe"
check "the smoke script's password URI really has a password component" grep -q -E '^sanhook rbd://[a-z]+:[a-z]+@' "$tmp/out/smoke.ipxe"
out=$("$gen" --smoke --stub -o "$tmp/out/both.ipxe" 2>&1); rc=$?
check "--smoke and --stub exclude each other" test "$rc" -eq 2
out=$("$gen" --redact --action sanhook --opt mode=crc --opt timeout=7 "${URI_ARGS[@]}" --no-key)
check "driver options are put in the query" contains "$out" "/rbd/img1?mode=crc&timeout=7 "
out=$("$gen" --redact --opt bogus=1 "${URI_ARGS[@]}" --no-key 2>&1); rc=$?
check "an unknown driver option is refused (use --raw-query to test the driver's refusal)" test "$rc" -eq 2
for baddrive in 256 999 0x100 010 08 0x 1e2; do
    "$gen" --redact --drive "$baddrive" "${URI_ARGS[@]}" --no-key >/dev/null 2>&1; rc=$?
    check "--drive $baddrive is refused (a BIOS drive number is one byte; no octal surprise)" test "$rc" -eq 2
done
for gooddrive in 0x80 0x81 0xff 129 255 0; do
    "$gen" --redact --drive "$gooddrive" "${URI_ARGS[@]}" --no-key >/dev/null 2>&1; rc=$?
    check "--drive $gooddrive is accepted" test "$rc" -eq 0
done
out=$("$gen" --redact --raw-query 'key=AQDSECRETSECRETSECRETSECRETSECRET==' "${URI_ARGS[@]}" --no-key 2>&1); rc=$?
check "a key in --raw-query is refused" test "$rc" -eq 2
check "...without printing it" not_contains "$out" AQDSECRET
out=$("$gen" --redact --uri 'rbd://lab@10.77.0.10:3300/rbd/img?mode=crc&secret=AQDSECRETSECRET' --no-key 2>&1); rc=$?
check "a secret in the query of --uri is refused" test "$rc" -eq 2
check "...without printing it" not_contains "$out" AQDSECRET
out=$("$gen" --redact --uri 'rbd://lab@10.77.0.10:3300/rbd/img?mode=crc&timeout=5' --no-key 2>&1); rc=$?
check "a plain query in --uri is still accepted" test "$rc" -eq 0

echo "== command lines (dry runs)"

export P2Q_WORK=$tmp/work
export P2Q_IPXE_DIR=$tmp/ipxe
export P2Q_QEMU=$tmp/stubs/qemu-system-x86_64
export P2Q_ACCEL=tcg
export P2Q_BUDGET_ROOT=$tmp
export P2Q_OVMF_CODE=$tmp/ipxe/OVMF_CODE_4M.fd P2Q_OVMF_VARS=$tmp/ipxe/OVMF_VARS_4M.fd
# a multicast group and addresses of its own: the stand-in opens no socket, but the scripts' "is this address free" check looks at the
# whole machine, and a real run of the same address (or a lab) must not collide with the test
export P2Q_MCAST=230.77.250.250:7799
unset P2_LAB_DIR P2_MCAST P2_MCAST_LOCALADDR P2_NET_CIDR P2_MON_ADDR P2_MON_PORT
: > "$tmp/ipxe/ipxe.efi"; : > "$tmp/ipxe/ipxe.lkrn"; : > "$tmp/ipxe/ipxe-stub.pxe"; : > "$tmp/ipxe/ipxe.pxe"; : > "$tmp/ipxe/undionly.kpxe"
: > "$tmp/ipxe/OVMF_CODE_4M.fd"; : > "$tmp/ipxe/OVMF_VARS_4M.fd"

dry() { # KIND args...
    local k=$1
    shift
    local o
    o=$("$here/run-$k.sh" -n "$@" 2>&1)
    printf '%s\n' "${o//\\/}"      # the plan prints the command with printf %q: commas and the like come out escaped
}
FORBID=(hostfwd guestfwd "tap," "tap=" bridge vde vhost "-vnc" "-spice" "-gdb" "tcp:" "-monitor stdio" "-net " "-nic ")
for k in uefi-pxe uefi-usb uefi-iso bios-pxe bios-usb bios-iso; do
    d=$(dry "$k" "${URI_ARGS[@]}" --fake-key)
    check "$k: the command is nice 19 choom 600 qemu" contains "$d" "would run: nice -n 19 choom -n 600 -- $tmp/stubs/qemu-system-x86_64"
    check "$k: the guest has a name of its own" contains "$d" "-name wrp2q-"
    check "$k: restricted user-mode NIC and the lab multicast NIC on the loopback" contains "$d" "restrict=on"
    check "$k: ...multicast socket on 127.0.0.1" contains "$d" "socket,id=lab,mcast=$P2Q_MCAST,localaddr=127.0.0.1"
    f=""; for w in "${FORBID[@]}"; do contains "$d" "$w" && f="$f [$w]"; done
    check "$k: nothing that touches the host network or opens a port${f}" test -z "$f"
    case "$k" in
        uefi-*) check "$k: OVMF pflash code (read-only) and variable store" contains "$d" "if=pflash,format=raw,unit=0,readonly=on";;
        bios-*) check "$k: no pflash (SeaBIOS)" not_contains "$d" pflash;;
    esac
    case "$k" in
        *-usb) check "$k: the stick is a USB mass-storage device on xHCI, first in the boot order" contains "$d" "usb-storage,bus=xhci.0,drive=usb0,bootindex=1"
               case "$d" in *"id=usb0,file="*"format=raw,readonly=on"*) ok "$k: the stick is read-only to the guest";; *) bad "$k: the stick is read-only to the guest";; esac;;
        *-iso) check "$k: a CD-ROM, read-only" contains "$d" "media=cdrom,readonly=on";;
        *-pxe) check "$k: PXE bootfile from QEMU's own TFTP root" contains "$d" "tftp=";;
    esac
done
d=$("$here/smoke.sh" -n --san --hold --rows "U1 B1" 2>&1); rc=$?
check "smoke.sh -n plans every pass of every row and starts nothing (exit 0)" test "$rc" -eq 0
for w in "U1 reaches-ipxe" "U1 driver" "U1 san-fails" "U1 no-cluster" "B1 reaches-ipxe" "B1 driver" "B1 san-fails" "B1 no-cluster"; do
    check "smoke.sh -n: pass '$w'" contains "$d" "== $w"
done
check "smoke.sh -n: the no-cluster pass's script holds after the failure (a hold loop)" contains "$d" ":hold"
"$here/smoke.sh" -n --rows "U1 B1" > /dev/null 2> "$tmp/smoke.err"
check "smoke.sh with stderr in a file keeps every progress line (no truncation by a second open of /dev/stderr)" test "$(grep -c '^== ' "$tmp/smoke.err")" -eq 4
d=$("$here/smoke.sh" -n --rows "U9" 2>&1); rc=$?
check "smoke.sh: an unknown row is refused (exit 2)" test "$rc" -eq 2
d=$("$here/smoke.sh" -n --no-driver --rows "U1" 2>&1)
check "smoke.sh --no-driver: no driver pass" not_contains "$d" "U1 driver"
check "smoke.sh leaves no temporary directory behind" test -z "$(ls "$tmp"/wr-p2q-smoke.* 2>/dev/null)"
d=$(env -u P2Q_MCAST "$here/run-uefi-pxe.sh" -n --no-key 2>&1)
check "the default lab layer 2 is the cluster scripts' group 230.77.12.1:7712 on the loopback" contains "$d" "mcast=230.77.12.1:7712"
d=$(dry uefi-pxe --pool p --image i --mon 10.77.0.10:3300 --fake-key)
check "U1: the default binary is ipxe.efi" contains "$d" "bootfile=ipxe.efi"
d=$(dry bios-pxe --pool p --image i --fake-key)
check "B1: the default binary is the stub build" contains "$d" "bootfile=ipxe-stub.pxe"
d=$(dry bios-pxe --pool p --image i --fake-key --bin "$tmp/ipxe/undionly.kpxe" --delivery embed)
check "B1 with undionly: a warning that the lab NIC is invisible to UNDI" contains "$d" "UNDI"
d=$(dry uefi-pxe --ip 10.77.0.21 --no-key)
check "a second guest address gives another lab MAC (.21 -> :95)" contains "$d" "mac=52:54:00:77:12:95"

refuse() { # DESC pattern args...: the dry run must exit 2 and say so
    local desc=$1 pat=$2 o rc
    shift 2
    o=$("$here/run-${RK:-uefi-pxe}.sh" -n "$@" 2>&1); rc=$?
    check "refused: $desc" test "$rc" -eq 2
    check "...with the reason ($pat)" contains "$o" "$pat"
}
refuse "--qemu-arg -netdev (a host forward)" "touch the host's network" --qemu-arg -netdev
refuse "--qemu-arg hostfwd" "touch the host's network" --qemu-arg "user,id=x,hostfwd=tcp::2222-:22"
refuse "--qemu-arg tap" "touch the host's network" --qemu-arg "tap,id=t0"
refuse "--qemu-arg -vnc" "listening socket" --qemu-arg -vnc
refuse "--qemu-arg -s (gdb stub)" "listening socket" --qemu-arg -s
refuse "--qemu-arg a TCP chardev" "listening socket" --qemu-arg "socket,id=c,host=0.0.0.0,port=4444,server=on"
refuse "--qemu-arg a TCP serial" "listening socket" --qemu-arg "tcp:127.0.0.1:5555,server"
refuse "--qemu-arg -virtfs" "listening socket" --qemu-arg -virtfs
refuse "--qemu-arg a chardev that connects out" "listening socket" --qemu-arg "socket,id=c,connect=192.0.2.1:99"
refuse "--qemu-arg a disk on nbd" "listening socket" --qemu-arg "if=none,id=d,file=nbd:192.0.2.1:10809"
refuse "--qemu-arg a disk on http" "listening socket" --qemu-arg "if=none,id=d,file=http://192.0.2.1/x.img"
refuse "--qemu-arg driver=nbd" "listening socket" --qemu-arg "driver=nbd,server.type=inet"
refuse "--qemu-arg a handed-in descriptor" "listening socket" --qemu-arg "socket,id=c,fd=5"
refuse "--cpus 5" "at most 4 cores" --cpus 5
P2Q_CONSOLE_MAX_MB=0 refuse "P2Q_CONSOLE_MAX_MB=0" "P2Q_CONSOLE_MAX_MB" --no-key

refuse "--mem 8192" "at most 4 GiB" --mem 8192
refuse "--ip outside the lab network" "not in the lab network" --ip 192.168.1.20
refuse "--ip .50 (the probe guest)" "not 50" --ip 10.77.0.50
refuse "--ip .10 (the monitor)" "20 to 99" --ip 10.77.0.10
refuse "--ip 10.77.0.020 (octal in iPXE)" "leading zeros" --ip 10.77.0.020
refuse "--timeout 1" "5 to 7200" --timeout 1
refuse "--nic-model ne2k" "--nic-model" --nic-model ne2k
refuse "an action without a target" "needs a target" --action sanhook
refuse "--no-key together with --fake-key" "excludes" --no-key --fake-key --pool p --image i
refuse "--key-file together with --fake-key" "excludes" --key-file "$tmp/keys/bare" --fake-key --pool p --image i
RK=uefi-usb refuse "--delivery stub on a USB row (it is for PXE)" "stub" --delivery stub --media "$tmp/ipxe/ipxe.efi" --no-key
o=$("$here/run-bios-pxe.sh" -n --delivery autoexec --no-key 2>&1); rc=$?
check "refused: BIOS PXE with --delivery autoexec (the binary cannot read it)" test "$rc" -eq 2
o=$(P2Q_CPUS=02 P2Q_MEM_MB=02048 "$here/run-uefi-pxe.sh" -n --no-key 2>&1); rc=$?
check "a number with a leading zero (02, 02048) is accepted and read as decimal, not an octal error" test "$rc" -eq 0
o=$(env -u P2Q_IPXE_DIR -u P2Q_BUDGET_ROOT "$here/run-uefi-pxe.sh" -n --no-key --work "$tmp/w2" 2>&1)
check "--work is applied before the defaults derived from it (the iPXE directory)" contains "$o" "iPXE binary $tmp/w2/ipxe/ipxe.efi"
# an iPXE binary that is not there (dry runs do not look; a real run says so)
o=$("$here/run-uefi-pxe.sh" -h 2>&1); rc=$?
check "--help works and mentions the row" rc_has "$rc" 0 "$o" "row U1"

echo "== make-usb.sh (arguments only; the images are built in the live run)"
o=$("$here/make-usb.sh" bogus "$tmp/out/x.img" 2>&1); rc=$?; check "an unknown kind is refused" test "$rc" -eq 2
: > "$tmp/out/exists.img"
o=$("$here/make-usb.sh" uefi-usb "$tmp/out/exists.img" --efi "$tmp/ipxe/ipxe.efi" 2>&1); rc=$?
check "an existing output is never overwritten" rc_has "$rc" 2 "$o" "never overwrites"
o=$("$here/make-usb.sh" uefi-usb "$tmp/out/n.img" 2>&1); rc=$?; check "uefi-usb without --efi is refused" test "$rc" -eq 2
o=$("$here/make-usb.sh" iso "$tmp/out/n.iso" --efi "$tmp/ipxe/ipxe.efi" 2>&1); rc=$?; check "iso needs both binaries" test "$rc" -eq 2
o=$("$here/make-usb.sh" uefi-usb "$tmp/out/n.img" --efi "$tmp/ipxe/ipxe.efi" --method syslinux 2>&1); rc=$?; check "--method is for bios-usb only" test "$rc" -eq 2
o=$("$here/make-usb.sh" bios-usb "$tmp/out/n.img" --lkrn "$tmp/ipxe/ipxe.lkrn" --method grub 2>&1); rc=$?; check "an unknown --method is refused" test "$rc" -eq 2
printf 'MZ' > "$tmp/ipxe/notpe.efi"
o=$("$here/make-usb.sh" uefi-usb "$tmp/out/n.img" --efi "$tmp/ipxe/notpe.efi" 2>&1); rc=$?
check "an EFI binary that is not a PE file is refused" test "$rc" -eq 2
if command -v mformat >/dev/null 2>&1; then check "...with the reason (the PE header)" contains "$o" "PE"; else skip "the PE check's reason (no mtools here)"; fi
check "...and no half-written image is left" test ! -e "$tmp/out/n.img"
leftwork=""; for f in "$tmp/out"/*.work.*; do [ -e "$f" ] && leftwork=$f; done
check "a refused call leaves no work directory behind" test -z "$leftwork"

echo "== process lists (the budget, the leftovers, the address check)"
# shellcheck disable=SC1091
( # a subshell: the library is sourced here and its functions called on a canned process list
    mkdir -p "$tmp/pstub"
    cat > "$tmp/pstub/ps" <<'EOS'
#!/bin/sh
case "$*" in
    *pid=*args=*) cat "$PS_CANNED";;
    *args=*) sed 's/^ *[0-9][0-9]* *//' "$PS_CANNED";;
    *) exit 1;;
esac
EOS
    chmod 755 "$tmp/pstub/ps"
    export PS_CANNED=$tmp/ps.txt
    cat > "$PS_CANNED" <<EOS
  101 qemu-system-x86_64 -name lab -smp 4 -m 8192 -drive file=$tmp/lab/disk.qcow2
  102 qemu-system-x86_64 -name wrp2q-U1-20260101T000000Z-12 -smp 2 -m 2048 -netdev socket,id=lab,mcast=230.77.12.1:7712 -device virtio-net-pci,mac=52:54:00:77:12:94 $tmp/work
  103 qemu-system-x86_64 -name wrp2q-U1-20260101T000000Z-123 -smp cpus=2,sockets=1 -m size=4G $tmp/work
  104 qemu-system-x86_64 -name other -smp 16 -m 65536 /somewhere/else/disk
  105 vim qemu-system-x86_64 $tmp/notes.txt
  106 /usr/bin/qemu-system-aarch64 -name wrp2q-B1-20260101T000000Z-7 -smp 2 -m 1G $tmp/work
EOS
    export PATH=$tmp/pstub:$PATH
    # shellcheck source-path=SCRIPTDIR source=common.sh
    . "$here/common.sh"
    P2Q_BUDGET_ROOT=$tmp
    r=$(q_qemu_usage)
    P2Q_BUDGET_ROOT=$tmp/                                         # a trailing slash in the setting must not switch the budget off
    r2=$(q_defaults; q_qemu_usage)
    [ "$r2" = "$r" ] && echo "ok budget-trailing-slash" || echo "FAIL budget-trailing-slash '$r2' vs '$r'"
    P2Q_BUDGET_ROOT=$tmp
    [ "$r" = "10 15360 4" ] && echo "ok budget" || echo "FAIL budget '$r' (want '10 15360 4': 4+2+2+2 cores; 8192+2048+4096+1024 MiB; processes under the root)"
    Q_RUNID_Q=wrp2q-U1-20260101T000000Z-12
    r=$(q_leftovers | tr '\n' ' ')
    [ "$r" = "102 " ] && echo "ok leftover-exact" || echo "FAIL leftover-exact '$r' (want '102 ': the run ...-12 is not the run ...-123)"
    Q_RUNID_Q=wrp2q-NONE-1
    r=$(q_leftovers | tr '\n' ' ')
    [ -z "$r" ] && echo "ok leftover-none" || echo "FAIL leftover-none '$r'"
    Q_RUNID_Q=wrp2q-B1-20260101T000000Z-7
    r=$(q_leftovers | tr '\n' ' ')
    [ "$r" = "106 " ] && echo "ok leftover-path" || echo "FAIL leftover-path '$r' (qemu-system-* given with a path)"
    Q_MAC_LAB=52:54:00:77:12:94 P2Q_MCAST=230.77.12.1:7712 Q_IP=10.77.0.20
    r=$( (q_unique_check) 2>&1 ); rc=$?
    [ "$rc" -eq 2 ] && echo "ok unique-refused" || echo "FAIL unique-refused rc=$rc '$r'"
    Q_MAC_LAB=52:54:00:77:12:95
    r=$( (q_unique_check) 2>&1 ); rc=$?
    [ "$rc" -eq 0 ] && echo "ok unique-free" || echo "FAIL unique-free rc=$rc '$r'"
) > "$tmp/pl.out" 2>&1
while read -r l; do
    case "$l" in ok*) ok "process list: ${l#ok }";; FAIL*) bad "process list: ${l#FAIL }";; *) printf '       %s\n' "$l";; esac
done < "$tmp/pl.out"

echo "== the console parser (what the markers and the shell prompt are made of)"
(
    # shellcheck source-path=SCRIPTDIR source=common.sh
    . "$here/common.sh"
    RUNDIR=$tmp/rd; mkdir -p "$RUNDIR"
    Q_CONSOLE=$RUNDIR/console.log
    Q_OK_MARK=WRBOOT-ROOT-OK Q_MARKER="" Q_FAIL_MARK="" Q_SHELL="map -r" T0=$SECONDS
    S_IPXE="" S_NET="" S_SAN="" S_END="" S_OS="" S_SHELL="" S_MARKER="" S_FAILMARK="" S_SHELL_TYPED="" S_SHELL_OK="" S_SHELL_MARK=0 SAN_STATE="" Q_SHELL_EXPECT='Mapping table'
    # OVMF's setup menu is drawn on the serial line too, in one long line that mentions the shell
    printf 'iPXE initialising devices...\r\nWRRUN-BEGIN row=U0\r\n >Boot Manager EFI Internal Shell> UEFI PXEv4\r\nMapping table\r\nPress ESC in 5 seconds to skip startup.nsh\r\n' > "$Q_CONSOLE"
    q_scan
    [ -z "$S_SHELL" ] && echo "ok the setup menu is not taken for the shell prompt" || echo "FAIL the setup menu is taken for the shell prompt"
    printf '\033[2J\033[1;1HShell> ' >> "$Q_CONSOLE"
    q_scan
    [ -n "$S_SHELL" ] && echo "ok the prompt at the start of a line is the shell" || echo "FAIL the prompt is not found"
    # "Mapping table" is in the banner: it counts only after the commands were typed
    S_SHELL_TYPED=1
    S_SHELL_MARK=$(wc -l < "$RUNDIR/console.txt")
    q_scan
    [ -z "$S_SHELL_OK" ] && echo "ok the banner's 'Mapping table' does not satisfy the shell expectation" || echo "FAIL the banner satisfied the expectation"
    printf 'map -r\r\nMapping table\r\n' >> "$Q_CONSOLE"
    q_scan
    [ -n "$S_SHELL_OK" ] && echo "ok the output of the typed command does" || echo "FAIL the output of the typed command was not seen"
    # the verdict of the booted system is a line that starts with the marker; a trace of the init script or a command line is not
    : > "$Q_CONSOLE"; S_OS=""
    printf '+ echo WRBOOT-ROOT-OK fw=bios\r\nKernel command line: root=/dev/vda1 WRBOOT-ROOT-OK\r\n' > "$Q_CONSOLE"
    Q_OK_MARK='^WRBOOT-ROOT-OK'
    q_scan
    [ -z "$S_OS" ] && echo "ok a trace line that merely contains WRBOOT-ROOT-OK is not the verdict" || echo "FAIL a trace line was taken for the verdict"
    printf '\033[0mWRBOOT-ROOT-OK fw=bios root=/dev/vda1 table=PASS\r\n' >> "$Q_CONSOLE"
    q_scan
    [ -n "$S_OS" ] && echo "ok the verdict line at the start of a line is" || echo "FAIL the verdict line was not found"
    printf 'WRRUN-NO-LAB-NIC\r\n' >> "$Q_CONSOLE"
    S_NETFAIL=""
    q_scan
    [ -n "$S_NETFAIL" ] && echo "ok a missing lab NIC is noticed" || echo "FAIL a missing lab NIC is not noticed"
    rm -f "$Q_CONSOLE" "$RUNDIR/console.txt"; rmdir "$RUNDIR"
) > "$tmp/cp.out" 2>&1
while read -r l; do
    case "$l" in ok*) ok "console: ${l#ok }";; FAIL*) bad "console: ${l#FAIL }";; *) printf '       %s\n' "$l";; esac
done < "$tmp/cp.out"
refuse "--menu-keys with a shell metacharacter" "menu-keys" --menu-keys 'down;ret'

if [ "$quick" = 1 ]; then
    echo
    echo "selftest (quick): $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
    exit $?
fi

echo "== whole runs against the QEMU stand-in"
if [ "$(uname -s)" != Linux ] || ! command -v flock >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    skip "the whole-run cases need Linux, flock and python3"
    echo
    echo "selftest: $pass passed, $fail failed, $skipped skipped"
    [ "$fail" -eq 0 ]
    exit $?
fi

# The stand-in: a shell shim named qemu-system-x86_64 that becomes a python process with the shim's own path as argv[0] (so that
# `ps` shows "<path>/qemu-system-x86_64 <script> -name ..." as it does for QEMU started by its path). It writes the pid file, serves the control socket (greeting, qmp_capabilities, quit, screendump, send-key, anything else: an empty return),
# and plays $FAKE_SCENARIO on the serial file.
cat > "$tmp/stubs/qemu-system-x86_64" <<'EOS'
#!/usr/bin/env bash
exec -a "$0" python3 -I "$(dirname "$0")/fake_qemu.py" "$@"
EOS
cat > "$tmp/stubs/fake_qemu.py" <<'EOS'
import os, signal, socket, sys, threading, time, json
args = sys.argv[1:]
def opt(name):
    return args[args.index(name) + 1] if name in args else None
scen = os.environ.get("FAKE_SCENARIO", "ok")
if scen == "nostart":
    sys.stderr.write("qemu-system-x86_64: could not open /dev/kvm: Permission denied\n")
    sys.exit(1)
serial = opt("-serial")
assert serial and serial.startswith("file:")
con = open(serial[5:], "ab", buffering=0)
pidfile = opt("-pidfile")
open(pidfile, "w").write("%d\n" % os.getpid())
chard = opt("-chardev")
sock = [p.split("=", 1)[1] for p in chard.split(",") if p.startswith("path=")][0]
srv = socket.socket(socket.AF_UNIX)
srv.bind(sock)
srv.listen(4)
stop = threading.Event()
def serve(c):
    f = c.makefile("rw")
    f.write(json.dumps({"QMP": {"version": {}, "capabilities": []}}) + "\n"); f.flush()
    for line in f:
        cmd = json.loads(line).get("execute")
        f.write(json.dumps({"return": {}}) + "\n"); f.flush()
        if cmd == "quit":
            stop.set()
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
key = os.environ.get("FAKE_KEY", "")
if scen == "silent":
    pass
elif scen == "ok":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanhook")
    say("WRRUN-SAN-OK"); say("WRRUN-LEAVE exit"); say("WRRUN-END")
elif scen == "san-failed":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanhook")
    say("WRRUN-SAN-FAILED 0x3c2d0539"); say("WRRUN-FAIL"); say("WRRUN-END")
elif scen == "leak":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("oops " + key); say("WRRUN-SAN-OK"); say("WRRUN-END")
elif scen in ("smoke-ok", "smoke-missing"):
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-LEAVE exit"); say("WRRUN-END")
    say("winrbd driver smoke test"); say("test: password in URI must be refused")
    if scen == "smoke-ok":
        say("rbd: key material must not be part of the URI (use the rbd-key setting)")
    say("Could not open SAN device: Invalid argument (https://ipxe.org/1c706082)"); say("refused: 0x1c706082")
    say("test: well formed URI must fail closed"); say("Could not open SAN device: Operation not supported (https://ipxe.org/3c716083)"); say("failed closed: 0x3c716083")
    say("test: unknown scheme control"); say("Could not open SAN device: Operation not supported (https://ipxe.org/3c092083)"); say("control: 0x3c092083")
    say("SMOKE-DONE")
elif scen == "netfail":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NO-LAB-NIC"); say("WRRUN-FAIL"); say("WRRUN-END")
elif scen == "flood":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T")
    for _ in range(4000):
        con.write(b"x" * 1023 + b"\n")
elif scen == "os-trace":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanboot")
    say("+ echo WRBOOT-ROOT-OK fw=bios"); say("Kernel command line: root=/dev/vda1 WRBOOT-ROOT-OK")
elif scen == "os-ok":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanboot")
    say("WRBOOT-ROOT-OK fw=bios root=/dev/vda1 table=PASS")
elif scen == "os-fail":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T"); say("WRRUN-NET-OK"); say("WRRUN-SAN-START sanboot")
    say("WRBOOT-ROOT-TABLE-FAIL fw=bios field=pool")
elif scen == "exit-early":
    say("iPXE initialising devices..."); say("WRRUN-BEGIN row=T")
    sys.exit(0)
while True:
    time.sleep(1)
EOS
chmod 755 "$tmp/stubs/qemu-system-x86_64"
command -v nice >/dev/null 2>&1 || printf '#!/bin/sh\nshift 2\nexec "$@"\n' > "$tmp/stubs/nice"
if ! command -v choom >/dev/null 2>&1; then printf '#!/bin/sh\nshift 3\nexec "$@"\n' > "$tmp/stubs/choom"; fi
chmod 755 "$tmp/stubs"/* 2>/dev/null
export PATH=$tmp/stubs:$PATH
export P2Q_QEMU=$tmp/stubs/qemu-system-x86_64
export P2Q_BUDGET_CORES=24 P2Q_BUDGET_MEM_MB=32768
: > "$tmp/ipxe/ipxe.efi"; printf 'x' > "$tmp/ipxe/ipxe-stub.pxe"

left_over_files() { find "$P2Q_WORK/runs" -mindepth 1 2>/dev/null | head -n 3 | tr '\n' ' '; }
key_anywhere() { grep -r -a -l -F "$KEY" "$P2Q_WORK" 2>/dev/null | head -n 3 | tr '\n' ' '; }

# run_case NAME SCENARIO KIND args...  -> $o (all output), $rc, $res (the RESULT line)
run_case() {
    local scen=$1 kind=$2
    shift 2
    o=$(FAKE_SCENARIO=$scen FAKE_KEY=$KEY "$here/run-$kind.sh" "$@" 2>&1); rc=$?
    res=$(printf '%s\n' "$o" | grep '^RESULT ' | tail -n 1)
    [ -z "${SELFTEST_DEBUG:-}" ] || printf '%s\n' "$o" | sed 's/^/      | /' >&2
}
T0=$SECONDS
run_case ok bios-pxe --row T --timeout 20 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "success: exit 0" test "$rc" -eq 0
check "success: RESULT says met=1 with the stage times" contains "$res" "met=1"
check "success: the SAN verdict is recorded" contains "$res" "san=ok@"
check "success: the run directory is gone" test -z "$(left_over_files)"
check "success: the key is nowhere under the work directory" test -z "$(key_anywhere)"
check "success: the console log is kept in logs/" test "$(ls "$P2Q_WORK/logs"/*.console 2>/dev/null | wc -l)" -ge 1
check "success: no qemu stand-in is left" test -z "$(ps -eww -o args= | grep -F -- "-name wrp2q-" | grep -F "$tmp" | grep -v grep || true)"
check "success: the control socket is gone" test -z "$(ls "$P2Q_WORK/s" 2>/dev/null)"
check "success: it stopped at the expectation, not at the timeout" contains "$res" "stop=expectation"

run_case silent bios-pxe --row T --timeout 5 --expect san "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "timeout: exit 1" test "$rc" -eq 1
check "timeout: RESULT says stop=timeout, met=0" contains "$res" "stop=timeout"
check "timeout: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"

t1=$SECONDS
run_case san-failed bios-pxe --row T --timeout 60 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" --on-fail hold
check "SAN open fails: exit 1" test "$rc" -eq 1
check "SAN open fails: it does not wait out the timeout (stop=san-failed)" contains "$res" "stop=san-failed"
check "SAN open fails: quickly" test $((SECONDS - t1)) -lt 30
check "SAN open fails: the verdict is in RESULT" contains "$res" "san=failed@"
check "SAN open fails: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"

run_case san-failed bios-pxe --row T --timeout 20 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+'
check "a negative test can expect the failure with --marker: met" rc_has "$rc" 0 "$res" "met=1"

run_case exit-early bios-pxe --row T --timeout 30 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "the guest ends before the expectation: exit 1, stop=guest-exited" rc_has "$rc" 1 "$res" "stop=guest-exited"

run_case leak bios-pxe --row T --timeout 20 --expect none "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" --stay
check "key in the console: exit 4" test "$rc" -eq 4
check "key in the console: the logs of the run are discarded" test -z "$(grep -r -a -l -F "$KEY" "$P2Q_WORK/logs" 2>/dev/null || true)"
check "key in the console: nothing about the key is printed by the run script" not_contains "$o" "$KEY"
check "key in the console: the verdict line says so" contains "$res" "discarded-key-leak"
check "key in the console: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"

printf '#!ipxe\nset rbd-key "%s"  \necho custom\n' "$KEY" > "$tmp/custom.ipxe"
run_case leak bios-pxe --row T --timeout 20 --expect none --script "$tmp/custom.ipxe" --stay
check "a script of your own with the key quoted: a leak into the console is still found (exit 4)" test "$rc" -eq 4
check "...and its copies are gone" test -z "$(left_over_files)$(key_anywhere)"

run_case nostart bios-pxe --row T --timeout 20 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "QEMU does not start: exit 2 and the message of QEMU is shown" rc_has "$rc" 2 "$o" "Permission denied"
check "QEMU does not start: RESULT says so" contains "$res" "qemu-did-not-start"
check "QEMU does not start: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"

# the lab NIC is missing and the guest holds: the run ends at once, not at the timeout
t1=$SECONDS
run_case netfail bios-pxe --row T --timeout 60 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" --on-fail hold
check "lab NIC missing: exit 1, stop=net-failed" rc_has "$rc" 1 "$res" "stop=net-failed"
check "lab NIC missing: it does not wait out the timeout" test $((SECONDS - t1)) -lt 30
check "lab NIC missing: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"
run_case netfail bios-pxe --row T --timeout 20 --expect ipxe --no-key --action none
check "lab NIC missing, but only 'reaches iPXE' was asked for (the UNDI row): met" rc_has "$rc" 0 "$res" "met=1"

# a guest that floods the serial line is stopped, and its log is kept (it holds no key)
o=$(P2Q_CONSOLE_MAX_MB=1 FAKE_SCENARIO=flood "$here/run-bios-pxe.sh" --row T --timeout 60 --expect none --stay --no-key 2>&1); rc=$?
res=$(printf '%s\n' "$o" | grep '^RESULT ' | tail -n 1)
check "console flood: exit 1, stop=console-flood" rc_has "$rc" 1 "$res" "stop=console-flood"
check "console flood: nothing left behind" test -z "$(left_over_files)"

# the verdict of a booted system: anchored; the image's failure lines end the run at once
run_case os-trace bios-pxe --row T --timeout 8 --action sanboot --expect os "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "os: a trace line / command line that merely mentions WRBOOT-ROOT-OK is not success" rc_has "$rc" 1 "$res" "met=0"
run_case os-ok bios-pxe --row T --timeout 20 --action sanboot --expect os "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "os: the verdict line is success" rc_has "$rc" 0 "$res" "met=1"
t1=$SECONDS
run_case os-fail bios-pxe --row T --timeout 60 --action sanboot --expect os "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
check "os: WRBOOT-ROOT-TABLE-FAIL ends the run at once (stop=fail-marker)" rc_has "$rc" 1 "$res" "stop=fail-marker"
check "os: ...quickly" test $((SECONDS - t1)) -lt 30
check "os: nothing left behind" test -z "$(left_over_files)$(key_anywhere)"

# a umask of 022 in the caller does not make the kept logs readable by others; a link as the work directory is refused
umask 022
run_case ok bios-pxe --row T --timeout 20 "${URI_ARGS[@]}" --key-file "$tmp/keys/bare"
umask 077
lm=$(stat -c %a "$P2Q_WORK"/logs/*.console 2>/dev/null | sort -u | tr '\n' ' ')
check "umask 022 in the caller: every kept log is still mode 600 ($lm)" test "$lm" = "600 "
ln -s "$P2Q_WORK" "$tmp/worklink"
o=$(FAKE_SCENARIO=silent "$here/run-bios-pxe.sh" --row T --timeout 8 --work "$tmp/worklink" --no-key 2>&1); rc=$?
check "a symbolic link as the work directory is refused (exit 2)" rc_has "$rc" 2 "$o" "symbolic link"
rm -f "$tmp/worklink"

# smoke.sh itself: a complete good run, a run whose console lacks a line of the driver test, and the negative control pass
o=$(FAKE_SCENARIO=smoke-ok "$here/smoke.sh" --rows B1 --timeout 30 2>&1); rc=$?
check "smoke.sh against a console with every driver line: exit 0, both passes met" rc_has "$rc" 0 "$o" "smoke: 2 of 2 runs met their expectation"
o=$(FAKE_SCENARIO=smoke-missing "$here/smoke.sh" --rows B1 --timeout 30 2>&1); rc=$?
check "smoke.sh: a missing driver line (the password refusal) fails the run (exit 1)" rc_has "$rc" 1 "$o" "key material must not be part of the URI"
check "smoke.sh: ...and the table says FAIL for the driver pass" contains "$o" "driver          FAIL"
o=$(FAKE_SCENARIO=san-failed "$here/smoke.sh" --rows B1 --no-driver --hold --hold-timeout 6 --timeout 30 2>&1); rc=$?
check "smoke.sh --hold: a guest that fails and holds ends at its timeout (exit 1 of the run) and that is the pass" rc_has "$rc" 0 "$o" "smoke: 2 of 2 runs met their expectation"
check "smoke.sh --hold: the table shows stop=timeout" contains "$o" "stop=timeout"
check "smoke.sh: nothing left behind" test -z "$(left_over_files)$(key_anywhere)$(ls "$tmp"/wr-p2q-smoke.* 2>/dev/null)"

# TERM to the run script: the guest is stopped and the files go
FAKE_SCENARIO=silent "$here/run-bios-pxe.sh" --row T --timeout 60 --expect none --stay "${URI_ARGS[@]}" --key-file "$tmp/keys/bare" > "$tmp/term.out" 2>&1 &
rp=$!
# (not `ps | grep -q`: the grep of the pipeline lists itself, with the pattern in its command line, and ends the wait at once)
for _ in $(seq 1 240); do pgrep -f -- "-name wrp2q-T-" >/dev/null && break; sleep 0.25; done   # a loaded machine can take many seconds to start
[ -z "${SELFTEST_DEBUG:-}" ] || tail -n 25 "$tmp/term.out" | sed 's/^/      | /' >&2
check "TERM test: the guest is running" test -n "$(ps -eww -o args= | grep -F -- "-name wrp2q-T-" | grep -v grep || true)"
kill -TERM "$rp"; wait "$rp"; rc=$?
check "TERM to the run script: it ends (143)" test "$rc" -eq 143
check "TERM: the guest is gone" test -z "$(ps -eww -o args= | grep -F -- "-name wrp2q-T-" | grep -v grep || true)"
check "TERM: the run directory and the key copies are gone" test -z "$(left_over_files)$(key_anywhere)"

# two run scripts at the same moment, a budget for one guest: exactly one starts
export P2Q_BUDGET_CORES=2 P2Q_BUDGET_MEM_MB=2048
FAKE_SCENARIO=silent "$here/run-bios-pxe.sh" --row T --timeout 8 --expect none --ip 10.77.0.21 --no-key > "$tmp/r1.out" 2>&1 &
p1=$!
FAKE_SCENARIO=silent "$here/run-bios-pxe.sh" --row T --timeout 8 --expect none --ip 10.77.0.22 --no-key > "$tmp/r2.out" 2>&1 &
p2=$!
wait "$p1"; r1=$?; wait "$p2"; r2=$?
started=0; refused=0
for f in "$tmp/r1.out" "$tmp/r2.out"; do
    if grep -q 'stop=timeout' "$f"; then started=$((started + 1)); fi
    if grep -q 'workflow budget would be exceeded' "$f"; then refused=$((refused + 1)); fi
done
check "two simultaneous starts, budget for one: exactly one guest ran (started=$started refused=$refused)" test "$started" -eq 1 -a "$refused" -eq 1
check "...the other exited 2 ($r1/$r2)" test $((r1 + r2)) -eq 3
export P2Q_BUDGET_CORES=24 P2Q_BUDGET_MEM_MB=32768
check "nothing left behind after all the runs" test -z "$(left_over_files)$(key_anywhere)"
check "no qemu stand-in left" test -z "$(ps -eww -o args= | grep -F -- "-name wrp2q-" | grep -F "$tmp" | grep -v grep || true)"
echo "   (whole-run cases: $((SECONDS - T0)) s)"

echo
echo "selftest: $pass passed, $fail failed, $skipped skipped"
[ "$fail" -eq 0 ]
