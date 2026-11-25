#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Offline self-test of the Phase 2 lab-cluster scripts (up.sh, down.sh, users.sh, probe.sh). No VM, no QEMU, no ssh, no
# network, no root: the machine's process list, the VM and the Ceph commands are replaced by stand-ins, and every file it
# creates is below one temporary directory that it removes at the end.
#
#   selftest.sh            run everything; exit status 0 only when every check passed
#
# What it proves (each is a regression of a defect found in review):
#   * the isolation check really looks at other QEMU processes (it once tested the pid column and could never fire),
#     compares whole option values and ignores this lab's own VM and anything that only mentions QEMU
#   * the budget arithmetic: -smp / -m forms, units, a command that merely mentions qemu, a process outside the work root
#   * the address check refuses an empty answer, an address outside the private network and too few OSDs
#   * the probe verdict is exact: a missing target, a missing banner, an answering control, a missing END line, a route
#     through the wrong NIC are each a failure
#   * users.sh: name / pool / size / feature validation; a key is never printed (create with the key-bearing commands
#     answering with a recognisable fake secret), key files are mode 600 in a mode 700 directory, a leftover user with
#     other caps or another key type is refused, a failed pool delete is reported
#   * down.sh: refuses a directory without the marker, deletes only the tool's own files, reports what it did not make
#   * a dry run changes nothing; the cloud-localds stand-in writes an ISO 9660 image that parses back
# shellcheck disable=SC2329,SC2016,SC2015  # the cases are called through their names; the quotes are deliberate
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

pass=0 fail=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n' "$1" >&2; }
check() { # DESCRIPTION COMMAND...   (the command is run in this shell; success = pass)
    local d=$1; shift
    if "$@"; then ok "$d"; else bad "$d"; fi
}
contains() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

# The cases run one per process (`selftest.sh --case NAME`): every case then has the errexit setting of a script of its
# own, which a subshell on the left of && or || would silently switch off.
if [ "${1:-}" = "--case" ]; then
    tmp=${SELFTEST_TMP:?}
else
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-p2-selftest.XXXXXX")
fi
case "$tmp" in /*/*) ;; *) echo "bad temporary directory $tmp" >&2; exit 2;; esac
cleanup() { # fixed layout, files only, then the directories (never a recursive delete of a variable)
    find "$tmp" -type f -delete 2>/dev/null || true
    find "$tmp" -depth -type d -exec rmdir {} + 2>/dev/null || true
}
[ "${1:-}" = "--case" ] || trap cleanup EXIT
export SELFTEST_TMP=$tmp

stubs=$tmp/stubs
mkdir -p "$stubs"
# the stand-in for ps: the canned process list in $PS_CANNED ("pid args" per line)
cat > "$stubs/ps" <<'EOS'
#!/bin/sh
case "$*" in
    *pid=*) cat "$PS_CANNED";;
    *args=*) sed 's/^ *[0-9][0-9]* *//' "$PS_CANNED";;
    *) exit 1;;
esac
EOS
chmod 755 "$stubs/ps"
export PS_CANNED=$tmp/ps.txt

# lib <dir> [script]: source the library (or users.sh) with LAB_DIR=<dir> and initialise.
lib() { # LAB_DIR [script-to-source]
    export LAB_DIR=$1
    export LAB_CONF=$here/lab.conf.example
    # shellcheck source=up.sh
    . "$here/${2:-up.sh}"
    p2_init
}





case_1() {
    lib /w/lab
    cat > "$PS_CANNED" <<'EOS'
      100 /usr/bin/qemu-system-x86_64 -name a -smp 4 -m 8192 -drive file=/w/lab/vm/root.qcow2,if=none
      101 /usr/bin/qemu-system-x86_64 -name b -smp cpus=8,sockets=1 -m 12G -drive file=/w/x/y.qcow2
      102 qemu-system-x86_64 -smp 2 -m size=2048M,slots=2 -drive file=/w/z.qcow2
      103 ssh host qemu-system-x86_64 -smp 64 -m 99999 /w/
      104 /usr/bin/qemu-system-x86_64 -smp 6 -m 4096 /other/dir/vm.qcow2
      105 /usr/bin/qemu-system-x86_64 -name d /w/d.qcow2
      106 nice -n 19 choom -n 600 -- /w/lab/make-vm.sh start
EOS
    got=$(PATH=$stubs:$PATH p2_qemu_usage)
    # 4+8+2+1 cores; 8192+12288+2048+128 MiB; four processes (the ssh line and the one outside /w do not count)
    [ "$got" = "15 22656 4" ] || { echo "usage: got '$got'"; exit 1; }
    got=$(PATH=$stubs:$PATH p2_qemu_usage "/w/lab/vm/")
    [ "$got" = "11 14464 3" ] || { echo "usage with skip: got '$got'"; exit 1; }
}

case_2() {
    lib /w/lab
    # budget: 16 cores and 24576 MiB in use; the limits are 24 cores and 32768 MiB
    cat > "$PS_CANNED" <<'EOS'
      101 /usr/bin/qemu-system-x86_64 -name b -smp 8 -m 12G -drive file=/w/x/y.qcow2
      102 /usr/bin/qemu-system-x86_64 -name c -smp 8 -m 12G -drive file=/w/x/z.qcow2
EOS
    export PATH=$stubs:$PATH
    out=$( (p2_budget_check 9 1024 "@none@") 2>&1) && { echo "9 cores on top of 16 must be refused"; exit 1; }
    contains "$out" "budget would be exceeded" || { echo "message: $out"; exit 1; }
    out=$( (p2_budget_check 8 9000 "@none@") 2>&1) && { echo "memory 24576+9000 must be refused"; exit 1; }
    (p2_budget_check 8 8192 "@none@") >/dev/null 2>&1 || { echo "8 cores / 8192 MiB fit exactly"; exit 1; }
}

case_3() {
    lib /w/lab
    export PATH=$stubs:$PATH
    # a foreign VM on our group: refused, and the message names the pid
    printf '%s\n' '   777 /usr/bin/qemu-system-x86_64 -name t -netdev socket,id=n1,mcast=230.77.12.1:7712,localaddr=127.0.0.1 -device virtio-net-pci,netdev=n1,mac=52:54:00:77:12:30' > "$PS_CANNED"
    out=$( (p2_check_isolation) 2>&1) && { echo "a VM on our multicast group must be refused"; exit 1; }
    contains "$out" "pid 777" && contains "$out" "multicast group" || { echo "message: $out"; exit 1; }
    # a foreign VM with one of our MACs (upper case value) on another group
    printf '%s\n' '   778 /usr/bin/qemu-system-x86_64 -netdev socket,id=n1,mcast=230.77.99.1:7799 -device e1000e,netdev=n1,mac=52:54:00:77:12:10' > "$PS_CANNED"
    out=$( (p2_check_isolation) 2>&1) && { echo "a VM with our MAC must be refused"; exit 1; }
    contains "$out" "MAC address" || { echo "message: $out"; exit 1; }
    # neighbours that must pass: a longer port, a similar MAC, our own VM and probe guest, a process that only mentions it
    cat > "$PS_CANNED" <<'EOS'
       801 /usr/bin/qemu-system-x86_64 -netdev socket,id=n1,mcast=230.77.12.1:77120 -device e1000e,mac=52:54:00:77:12:100
       802 /usr/bin/qemu-system-x86_64 -netdev socket,id=n1,mcast=230.77.12.1:7712 -drive file=/w/lab/vm/root.qcow2
       803 /usr/bin/qemu-system-x86_64 -netdev socket,id=n1,mcast=230.77.12.1:7712 -serial file:/w/lab/probe/console.log
       804 ssh -L 1:2 host qemu-system-x86_64 -netdev socket,mcast=230.77.12.1:7712
       805 /bin/sh -c grep mcast=230.77.12.1:7712 /var/log/x
EOS
    p2_check_isolation || { echo "neighbours that must pass were refused"; exit 1; }
}

case_4() {
    lib /w/lab
    good=$'mon.a 10.77.0.10:3300\nosd.0 10.77.0.10:6800\nosd.1 10.77.0.10:6801\nosd.2 10.77.0.10:6802'
    (p2_check_addr_list "$good" 3 "10.77.0.") >/dev/null 2>&1 || { echo "a good list was refused"; exit 1; }
    for case_ in "" $'mon.a 10.77.0.10:3300' $'osd.0 10.77.0.10:6800\nosd.1 10.77.0.10:6801\nosd.2 10.77.0.10:6802' \
        $'mon.a 10.77.0.10:3300\nosd.0 10.0.2.15:6800\nosd.1 10.77.0.10:6801\nosd.2 10.77.0.10:6802' \
        $'mon.a 10.77.0.10:3300\nosd.0 10.77.0.10:6800' $'mon.a 10.77.0.10:3300\nmgr.x 10.77.0.10:6800'; do
        if (p2_check_addr_list "$case_" 3 "10.77.0.") >/dev/null 2>&1; then echo "accepted: $case_"; exit 1; fi
    done
}

case_5() {
    lib /w/lab
    # a full console transcript for 1 monitor and 3 OSDs
    base=$'WRPROBE BEGIN self=10.77.0.50\nWRPROBE LINK lab0 UP 52:54:00:77:12:50\nWRPROBE ADDR lab0 UP 10.77.0.50/24\nWRPROBE ROUTE to 10.77.0.10: 10.77.0.10 dev lab0 src 10.77.0.50 uid 0\nWRPROBE NEIGH 10.77.0.10 lladdr 52:54:00:77:12:10 REACHABLE;'
    tcp() { printf 'WRPROBE TCP %s %s %s %s\n' "$1" "$2" "$3" "$4"; }
    good=$base$'\n'$(tcp mon mon.a 10.77.0.10:3300 "connected ceph v2")$'\n'$(tcp osd osd.0 10.77.0.10:6800 "connected ceph v2")$'\n'$(tcp osd osd.1 10.77.0.10:6801 "connected ceph v2")$'\n'$(tcp osd osd.2 10.77.0.10:6802 "connected ceph v2")$'\n'$(tcp ctl nobody 10.77.0.99:3300 "timeout -")$'\nWRPROBE END'
    v() { (p2_probe_verdict "$1" "$2" "$3") >"$tmp/verdict.out" 2>&1; }
    v "$good" 1 3 || { echo "the good transcript was refused"; cat "$tmp/verdict.out"; exit 1; }
    expect_fail() { # NAME TRANSCRIPT WANT_MON WANT_OSD
        if v "$2" "$3" "$4"; then echo "accepted: $1"; exit 1; fi
    }
    expect_fail "an OSD answered without the banner" "${good//osd.1 10.77.0.10:6801 connected ceph v2/osd.1 10.77.0.10:6801 connected -}" 1 3
    expect_fail "an OSD unreachable" "${good//osd.2 10.77.0.10:6802 connected ceph v2/osd.2 10.77.0.10:6802 unreachable -}" 1 3
    expect_fail "the control answered" "${good//nobody 10.77.0.99:3300 timeout -/nobody 10.77.0.99:3300 connected ceph v2}" 1 3
    expect_fail "a target was skipped (2 OSDs for 3)" "${good//$'WRPROBE TCP osd osd.2 10.77.0.10:6802 connected ceph v2\n'/}" 1 3
    expect_fail "no END line" "${good//$'\nWRPROBE END'/}" 1 3
    expect_fail "the route used the slirp NIC" "${good//dev lab0 src/dev inet0 src}" 1 3
    expect_fail "no control line" "${good//$'WRPROBE TCP ctl nobody 10.77.0.99:3300 timeout -\n'/}" 1 3
    expect_fail "more OSDs advertised than probed" "$good" 1 4
    expect_fail "nothing to prove (no targets)" "$base"$'\nWRPROBE END' 0 0
    # a passing run reports the counts the caller prints
    p2_probe_verdict "$good" 1 3 >/dev/null 2>&1
    [ "$P2_PROBE_NOSD" = 3 ] && [ "$P2_PROBE_NMON" = 1 ] || { echo "counts: $P2_PROBE_NMON / $P2_PROBE_NOSD"; exit 1; }
}

case_6() {
    lib /w/lab users.sh
    dies() { ( "$@" ) >/dev/null 2>&1 && return 1 || return 0; }
    [ "$(norm_name foo)" = wrtest-p2-foo ] || exit 1
    [ "$(norm_name wrtest-x)" = wrtest-x ] || exit 1
    # the bootstrap's own names are prefixed, so they can never be addressed
    [ "$(norm_name img-v1)" = wrtest-p2-img-v1 ] || exit 1
    [ "$(norm_name winrbd)" = wrtest-p2-winrbd ] || exit 1
    for n in Foo 'a b' 'a;b' 'a/b' '../x' 'wrtest--x' 'wrtest-' 'wrtest-Bad' "wrtest-$(printf 'a%.0s' $(seq 1 41))" '$(id)' 'a`id`'; do
        dies norm_name "$n" || { echo "accepted the name '$n'"; exit 1; }
    done
    [ "$(norm_pool winrbd)" = winrbd ] && [ "$(norm_pool wrtest-p)" = wrtest-p ] || exit 1
    for p in img .mgr rbd 'winrbd2' 'wrtest-A' 'wrtest-a;b'; do
        dies norm_pool "$p" || { echo "accepted the pool '$p'"; exit 1; }
    done
    [ "$(size_mb 2G)" = 2048 ] && [ "$(size_mb 512M)" = 512 ] && [ "$(size_mb 4G)" = 4096 ] && [ "$(size_mb 4M)" = 4 ] || exit 1
    for sz in 5G 4097M 3M 0M 0G 2g 2 -1G 1.5G '' 2GB '2G;x'; do
        dies size_mb "$sz" || { echo "accepted the size '$sz'"; exit 1; }
    done
    # option parsing in create is checked in the stub-driven test below
}

case_7() {
    lib "$tmp/ulab/lab" users.sh
    mkdir -p "$LAB_DIR/keys"
    : > "$LAB_DIR/.winrbd-lab"
    chmod 755 "$LAB_DIR/keys"      # a directory made loosely by something else: create must tighten it
    state=$tmp/ustate
    mkdir -p "$state"
    secret=AQBFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE==
    log=$state/calls.log
    : > "$log"
    # stand-ins: the VM exists; every ceph / rbd command is answered here
    p2_vm_pid() { echo 1; }
    p2_ssh_ok() { return 0; }
    vm_stdin() { cat > /dev/null; }
    vm() {
        printf '%s\n' "$*" >> "$log"
        case "$*" in
            "sudo rbd info "*) [ -e "$state/image" ];;
            "sudo rbd create "*) : > "$state/image";;
            "sudo ceph auth get client.wrtest-p2-t1")
                [ -e "$state/user" ] || return 2
                printf '[client.wrtest-p2-t1]\n\tkey = %s\n' "$secret";;
            "sudo ceph auth get-key client.wrtest-p2-t1")
                [ -e "$state/user" ] || return 2
                printf '%s' "$secret";;
            "sudo ceph auth get-or-create "*)
                : > "$state/user"
                printf '[client.wrtest-p2-t1]\n\tkey = %s\n' "$secret";;
            "sudo bash -c ceph auth get-key client.wrtest-p2-t1 | base64 -d | wc -c") echo "${KEYLEN:-28}";;
            "sudo bash -c ceph auth get client.wrtest-p2-t1 -f json | jq -r '.[0].caps.osd // empty'") echo "${HAVECAPS:-profile rbd pool=winrbd}";;
            "sudo ceph osd pool ls") ;;
            *) ;;
        esac
    }
    out=$(cmd_create t1 --size 64M 2>&1)
    contains "$out" "$secret" && { echo "the secret was printed"; exit 1; }
    contains "$out" "FAKEFAKE" && { echo "part of the secret was printed"; exit 1; }
    kr=$LAB_DIR/keys/client.wrtest-p2-t1.keyring ks=$LAB_DIR/keys/client.wrtest-p2-t1.secret
    [ -f "$kr" ] && [ -f "$ks" ] || { echo "key files missing"; exit 1; }
    [ "$(stat -c %a "$kr" 2>/dev/null || stat -f %Lp "$kr")" = 600 ] || { echo "keyring mode"; exit 1; }
    [ "$(stat -c %a "$ks" 2>/dev/null || stat -f %Lp "$ks")" = 600 ] || { echo "secret mode"; exit 1; }
    [ "$(stat -c %a "$LAB_DIR/keys" 2>/dev/null || stat -f %Lp "$LAB_DIR/keys")" = 700 ] || { echo "keys directory mode"; exit 1; }
    contains "$(cat "$ks")" "$secret" || { echo "secret file content"; exit 1; }
    contains "$(cat "$log")" "--key_type aes" || { echo "legacy key type not requested"; exit 1; }
    contains "$(cat "$log")" "osd profile rbd pool=winrbd" || { echo "caps not limited to the pool"; exit 1; }
    # the same name again: the leftover is reused only when it is what was asked for
    out=$(cmd_create t1 --size 64M 2>&1) || { echo "a matching leftover was refused: $out"; exit 1; }
    : > "$log"
    HAVECAPS="profile rbd pool=img-v1" out=$( (cmd_create t1 --size 64M) 2>&1) && { echo "a leftover with other caps was accepted"; exit 1; }
    contains "$out" "other caps" || { echo "message: $out"; exit 1; }
    # refused before anything was created
    contains "$(cat "$log")" "rbd create" && { echo "an image was created although the leftover user was refused"; exit 1; }
    contains "$(cat "$log")" "auth get-or-create" && { echo "a user was created although the leftover user was refused"; exit 1; }
    HAVECAPS="profile rbd pool=winrbd"
    KEYLEN=44 out=$( (cmd_create t1 --size 64M) 2>&1) && { echo "a leftover with a 32-byte key was accepted for --key-type aes"; exit 1; }
    contains "$out" "not the requested aes" || { echo "message: $out"; exit 1; }
    KEYLEN=28
    # a key of the wrong type is refused
    rm -f "$state/user" "$state/image"
    KEYLEN=44 out=$( (cmd_create t1 --size 64M) 2>&1) && { echo "a 32-byte key was accepted for --key-type aes"; exit 1; }
    contains "$out" "not the requested aes" || { echo "message: $out"; exit 1; }
    contains "$out" "FAKEFAKE" && { echo "the secret was printed on the failure path"; exit 1; }
    # bad options never reach the VM
    : > "$log"
    for bad_args in "--size 9G" "--key-type rsa" "--features a;b" "--pool img-v1" "--bogus 1"; do
        # shellcheck disable=SC2086
        ( cmd_create t2 $bad_args ) >/dev/null 2>&1 && { echo "accepted: $bad_args"; exit 1; }
    done
    [ ! -s "$log" ] || { echo "a bad option reached the VM: $(cat "$log")"; exit 1; }
    # delete removes the key files
    cmd_delete t1 >/dev/null 2>&1
    [ ! -e "$kr" ] && [ ! -e "$ks" ] || { echo "key files left after delete"; exit 1; }
}

case_8() {
    lib "$tmp/ulab2/lab" users.sh
    log=$tmp/ustate2.log
    : > "$log"
    p2_vm_pid() { echo 1; }
    p2_ssh_ok() { return 0; }
    vm() {
        printf '%s\n' "$*" >> "$log"
        case "$*" in
            "sudo ceph osd pool ls") echo wrtest-p2-x;;
            "sudo ceph osd pool delete "*) return 16;;
            *) ;;
        esac
    }
    out=$( (cmd_pool_delete x) 2>&1) && { echo "a failed pool delete was reported as success"; exit 1; }
    contains "$out" "could not delete pool" || { echo "message: $out"; exit 1; }
    # the flag that allows deletion is switched on and, even though the delete failed, off again
    on=$(grep -n 'mon_allow_pool_delete true' "$log" | cut -d: -f1 | head -n 1)
    off=$(grep -n 'mon_allow_pool_delete false' "$log" | cut -d: -f1 | head -n 1)
    [ -n "$on" ] && [ -n "$off" ] && [ "$off" -gt "$on" ] || { echo "the deletion flag was not restored"; exit 1; }
}

case_9() {
    export LAB_DIR=$tmp/dry/lab LAB_CONF=$here/lab.conf.example PATH=$stubs:$PATH
    # a real lab may be running on this machine: the dry run must not depend on its port
    LAB_SSH_PORT=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
    export LAB_SSH_PORT
    : > "$PS_CANNED"
    for c in "up.sh -n" "up.sh -n status" "users.sh -n create dry" "users.sh -n delete dry" "users.sh -n delete-all" "users.sh -n list" \
             "users.sh -n pool-create dry" "users.sh -n pool-delete dry" "users.sh -n krbd-check dry" "probe.sh -n" "down.sh -n"; do
        # shellcheck disable=SC2086
        "$here"/$c > "$tmp/dry.out" 2>&1 || { echo "$c failed:"; cat "$tmp/dry.out"; exit 1; }
    done
    [ ! -e "$tmp/dry" ] || { echo "a dry run created $tmp/dry"; exit 1; }
    envout=$("$here/up.sh" env)
    contains "$envout" "P2_MON_ADDR=10.77.0.10" || { echo "up.sh env: $envout"; exit 1; }
    # nothing that looks like a key or a keyring (the two paths are the only mention of keys)
    secretish=$(printf '%s\n' "$envout" | grep -E -i 'secret|keyring|BEGIN|AQ[A-Za-z0-9+/]{20}' | grep -v -E '^P2_(SSH_KEY|KEYS_DIR)=' || true)
    [ -z "$secretish" ] || { echo "up.sh env prints something that looks like a secret: $secretish"; exit 1; }
}

case_10() {
    lib "$tmp/shim/lab"
    mkdir -p "$LAB_DIR"
    p2_write_shim
    printf '#cloud-config\nhostname: x\n' > "$tmp/ud"
    printf 'instance-id: i-1\n' > "$tmp/md"
    printf 'version: 2\nethernets: {}\n' > "$tmp/nc"
    "$LAB_DIR/tools/bin/cloud-localds" -N "$tmp/nc" "$tmp/seed.iso" "$tmp/ud" "$tmp/md"
    python3 -I "$here/selftest_iso.py" "$tmp/seed.iso" "$tmp/ud" "$tmp/md" "$tmp/nc"
    if command -v bsdtar >/dev/null 2>&1; then
        names=$(bsdtar -tf "$tmp/seed.iso" 2>/dev/null | sort | tr '\n' ' ') || names=""
        contains "$names" "user-data" || { echo "bsdtar does not list the files: '$names'"; exit 1; }
    fi
}

case_11() {
    lib /w/lab
    p2_validate || exit 1
    # each of these must be refused (run in a subshell: die exits)
    for kv in "P2_OSD_MEMORY_TARGET=1;id" "P2_BUDGET_CORES=" "P2_BUDGET_MEM_MB=32G" "LAB_SSH_PORT=22 232" "LAB_MCAST=230.77.12.1" \
              "LAB_MCAST=230.77.12.1:7712,x" "LAB_PRIV_CIDR=10.77.0.10/16" "P2_PROBE_IP=10.77.1.50" "P2_PROBE_IP=10.77.0.10" \
              "P2_PROBE_IP=10.77.0.50;x" "LAB_MAC_PRIV=52:54:00:77:12" "P2_PROBE_MAC_PRIV=52:54:00:77:12:10"; do
        if ( export "${kv?}"; p2_validate ) >/dev/null 2>&1; then echo "accepted: $kv"; exit 1; fi
    done
}

CASES=(
    "case_1|p2_qemu_usage: -smp / -m forms, units, only real qemu commands below the work root, skip pattern"
    "case_2|p2_budget_check: refuses over the core limit and over the memory limit, accepts the exact fit"
    "case_3|p2_check_isolation: refuses a foreign VM on our group or MAC (names the pid), passes own VM, probe guest, near misses, non-qemu lines"
    "case_4|p2_check_addr_list: empty, no monitor, too few OSDs, an address outside the network, an unknown daemon are refused"
    "case_5|p2_probe_verdict: exact counts, banner, control, END line and route are each enforced"
    "case_6|users.sh: names always carry wrtest-, pools only winrbd or wrtest-*, sizes 4M..4G, no shell metacharacters"
    "case_7|users.sh create: key never printed (also on failure paths), key files 600 in 700, caps / key type of a leftover checked, bad options stop early, delete removes the files"
    "case_8|users.sh pool-delete: a failed delete is an error and the deletion flag is switched off again"
    "case_9|dry runs of every script and command succeed, create nothing, and 'up.sh env' carries no secret"
    "case_10|cloud-localds stand-in: a valid ISO 9660 + Joliet image, label cidata, three files with exact content"
    "case_11|settings validation: numbers, group, network, probe address and MAC addresses are checked before anything starts"
)
if [ "${1:-}" = "--case" ]; then
    "${2:?case name}"
    exit 0
fi

# ---------------------------------------------------------------------------------------------------------------------
for entry in "${CASES[@]}"; do
    name=${entry%%|*} desc=${entry#*|}
    if out=$(SELFTEST_TMP=$tmp "$here/selftest.sh" --case "$name" 2>&1); then
        ok "$desc"
    else
        bad "$desc"
        printf '%s\n' "$out" | sed 's/^/         /' >&2
    fi
done

echo "down.sh"
mk_lab() { # DIR: a lab directory the way up.sh / users.sh / probe.sh / make-vm.sh leave it
    local d=$1 f
    mkdir -p "$d/ssh" "$d/keys" "$d/logs" "$d/state" "$d/tools/bin" "$d/probe" "$d/vm" "$d/images" "$d/facts"
    : > "$d/.winrbd-lab"; : > "$d/.p2.lock"; : > "$d/known_hosts"
    for f in ssh/id_ed25519 ssh/id_ed25519.pub keys/client.wrtest-p2-a.keyring keys/client.wrtest-p2-a.secret logs/stage-x.log \
             state/up.done tools/bin/cloud-localds probe/console.log vm/root.qcow2 vm/osd0.qcow2 vm/osd1.qcow2 vm/osd2.qcow2 vm/seed.iso \
             vm/console.log images/noble-server-cloudimg-amd64.img images/SHA256SUMS facts/image-digest.txt; do
        : > "$d/$f"
    done
}
run_down() { # DIR args... -> output in $tmp/down.out, status returned
    local d=$1; shift
    ( export LAB_DIR=$d LAB_CONF=$here/lab.conf.example; "$here/down.sh" "$@" ) > "$tmp/down.out" 2>&1
}

mk_lab "$tmp/d1/lab"
before=$(find "$tmp/d1/lab" | wc -l)
if run_down "$tmp/d1/lab" -n && [ "$(find "$tmp/d1/lab" | wc -l)" = "$before" ]; then ok "down.sh -n: changes nothing"; else bad "down.sh -n changed something"; fi

if run_down "$tmp/d1/lab" && [ ! -e "$tmp/d1/lab" ]; then ok "down.sh: removes every file of the tool and the lab directory itself"; else bad "down.sh did not leave nothing behind: $(find "$tmp/d1" | tr '\n' ' ')"; fi

mk_lab "$tmp/d2/lab"
: > "$tmp/d2/lab/notes-by-someone.txt"
mkdir -p "$tmp/d2/lab/keys/sub"; : > "$tmp/d2/lab/keys/sub/precious"
if ! run_down "$tmp/d2/lab" && [ -e "$tmp/d2/lab/notes-by-someone.txt" ] && [ -e "$tmp/d2/lab/keys/sub/precious" ] \
   && [ ! -e "$tmp/d2/lab/ssh" ] && [ ! -e "$tmp/d2/lab/vm" ] && grep -q 'left behind' "$tmp/down.out"; then
    ok "down.sh: files it did not make are left alone and reported, exit status 1, its own files are gone"
else
    bad "down.sh with foreign files: $(cat "$tmp/down.out")"
fi

mkdir -p "$tmp/d3/lab/keys"; : > "$tmp/d3/lab/keys/mine"
if ! run_down "$tmp/d3/lab" && [ -e "$tmp/d3/lab/keys/mine" ] && grep -q 'marker' "$tmp/down.out"; then
    ok "down.sh: a directory without the marker file is refused and untouched"
else
    bad "down.sh without marker: $(cat "$tmp/down.out")"
fi

mk_lab "$tmp/d4/lab"
if run_down "$tmp/d4/lab" --keep-image && [ -f "$tmp/d4/lab/images/noble-server-cloudimg-amd64.img" ] && [ ! -e "$tmp/d4/lab/vm" ] \
   && [ ! -e "$tmp/d4/lab/keys" ] && [ ! -e "$tmp/d4/lab/ssh" ]; then
    ok "down.sh --keep-image: the base image stays, keys / disks / ssh keys go"
else
    bad "down.sh --keep-image: $(cat "$tmp/down.out"); $(find "$tmp/d4" | tr '\n' ' ')"
fi

echo
echo "selftest: $pass passed, $fail failed"
[ "$fail" = 0 ]
