#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 lab cluster: build (or bring back) the dedicated single-host Ceph v20.2.5 lab VM on a
# shared Linux build machine, using the repository's own harness/lab scripts (make-vm.sh,
# guest-packages.sh, bootstrap-ceph.sh, krbd-compat.sh). Needs no root and changes nothing on the
# host's network: the VM has a user-mode NIC (SSH on 127.0.0.1 only) and a QEMU multicast-socket
# NIC (the lab's private layer 2, 10.77.0.0/24, monitor 10.77.0.10).
#
#   up.sh [-n] [up]     create what is missing and start the VM; idempotent: a second run only checks
#   up.sh [-n] status   VM, health, OSDs, pools, address check and the CPU / RAM it uses
#   up.sh stop          power the VM off (ACPI, then terminate); disks and cluster stay, a later `up.sh` starts it again
#   up.sh env           shell assignments (no secrets) for scripts that start guests on the lab's layer 2:
#                         eval "$(harness/lab/p2/cluster/up.sh env)"
#   up.sh ssh [CMD...]  run a command in the VM (or log in)
#
#   -n, --dry-run       print what would be run, change nothing
#
# This file is also the function library of down.sh, users.sh and probe.sh: when it is sourced it
# defines functions only and does nothing else.
#
# Rules it enforces (shared machine): everything below one directory (LAB_DIR, marked by a file;
# a directory that exists and is not ours is refused); every process it starts is run as
# `nice -n 19 choom -n 600 --`; the sum of cores and RAM of all QEMU processes under the parent of
# LAB_DIR plus the new one stays within P2_BUDGET_CORES / P2_BUDGET_MEM_MB; the SSH port, the
# multicast group and the MAC addresses must not be in use by another VM; KVM is required.
#
# Configuration: lab.conf.example (this directory). Logs of the long steps go to LAB_DIR/logs.
set -euo pipefail

p2_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
p2_lab=$(cd "$p2_here/../.." && pwd)
# shellcheck source=../../common.sh
. "$p2_lab/common.sh"

# ---------------------------------------------------------------------------------------------
# configuration and small helpers
# ---------------------------------------------------------------------------------------------

p2_defaults() {
    : "${P2_BUDGET_CORES:=24}"
    : "${P2_BUDGET_MEM_MB:=32768}"
    : "${P2_OSD_MEMORY_TARGET:=1288490188}"
    : "${P2_WAIT_SSH_S:=900}"
    : "${P2_WAIT_STAGE_S:=3600}"
    : "${P2_WAIT_HEALTH_S:=900}"
    : "${P2_PROBE_IP:=10.77.0.50}"
    : "${P2_PROBE_CPUS:=1}"
    : "${P2_PROBE_MEM_MB:=768}"
    : "${P2_PROBE_MAC_INET:=52:54:00:77:12:51}"
    : "${P2_PROBE_MAC_PRIV:=52:54:00:77:12:50}"
    : "${P2_PROBE_TIMEOUT_S:=420}"
}

# The settings end up in arithmetic tests, in QEMU command lines and in commands run as root in the VM (the OSD memory
# target): refuse anything but the plain shape, so a typo in a configuration file fails here and not half way through a
# first boot.
p2_validate() {
    local v
    for v in LAB_VCPUS LAB_MEM_MB LAB_ROOT_GB LAB_OSD_COUNT LAB_OSD_GB LAB_NICE LAB_SSH_PORT LAB_MIN_FREE_GB P2_BUDGET_CORES \
             P2_BUDGET_MEM_MB P2_OSD_MEMORY_TARGET P2_WAIT_SSH_S P2_WAIT_STAGE_S P2_WAIT_HEALTH_S P2_PROBE_CPUS P2_PROBE_MEM_MB \
             P2_PROBE_TIMEOUT_S; do
        [[ "${!v}" =~ ^[0-9]+$ ]] || die "$v must be a plain number (got '${!v}')"
    done
    [[ "$LAB_MCAST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]] || die "LAB_MCAST must look like 230.77.12.1:7712 (got '$LAB_MCAST')"
    [[ "$LAB_PRIV_CIDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/24$ ]] || die "LAB_PRIV_CIDR must be an address in a /24 (got '$LAB_PRIV_CIDR')"
    [[ "$P2_PROBE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "P2_PROBE_IP must be an IPv4 address (got '$P2_PROBE_IP')"
    case "$P2_PROBE_IP" in "${LAB_PRIV_CIDR%.*}."*) ;; *) die "P2_PROBE_IP $P2_PROBE_IP is not inside ${LAB_PRIV_CIDR%.*}.0/24";; esac
    [ "$P2_PROBE_IP" != "${LAB_PRIV_CIDR%/*}" ] || die "P2_PROBE_IP is the monitor's own address"
    for v in LAB_MAC_INET LAB_MAC_PRIV P2_PROBE_MAC_INET P2_PROBE_MAC_PRIV; do
        [[ "${!v}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || die "$v is not a MAC address (got '${!v}')"
    done
    [ "$LAB_MAC_INET" != "$LAB_MAC_PRIV" ] && [ "$P2_PROBE_MAC_INET" != "$P2_PROBE_MAC_PRIV" ] \
        && [ "$LAB_MAC_PRIV" != "$P2_PROBE_MAC_PRIV" ] && [ "$LAB_MAC_INET" != "$P2_PROBE_MAC_INET" ] \
        || die "the MAC addresses of the lab VM and the probe guest must all differ"
    return 0
}

# Parse -n / --dry-run out of the arguments (the rest is left in P2_ARGS) and load the configuration.
p2_init() {
    P2_DRY_RUN=${P2_DRY_RUN:-0}
    P2_ARGS=()
    local a
    for a in "$@"; do
        case "$a" in
            -n|--dry-run) P2_DRY_RUN=1;;
            *) P2_ARGS+=("$a");;
        esac
    done
    if [ -z "${LAB_CONF:-}" ]; then
        if [ -f "$p2_here/lab.conf" ]; then LAB_CONF=$p2_here/lab.conf; else LAB_CONF=$p2_here/lab.conf.example; fi
    fi
    export LAB_CONF
    lab_load_conf
    lab_defaults
    lab_check_dir
    p2_defaults
    p2_validate
    P2_WORKROOT=$(dirname "$LAB_DIR")
    P2_WRAP=(nice -n "$LAB_NICE" choom -n 600 --)
    P2_SSH=(ssh -i "$LAB_DIR/ssh/id_ed25519" -p "$LAB_SSH_PORT"
        -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$LAB_DIR/known_hosts"
        -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 -o LogLevel=ERROR
        "$LAB_SSH_USER@127.0.0.1")
}

p2_dry() { [ "${P2_DRY_RUN:-0}" = 1 ]; }

# Run a command, or only print it in dry-run mode.
run() {
    if p2_dry; then
        printf 'would run:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

# Run a command in the VM. Every argument is quoted for the remote shell, so a command line can be
# passed as separate words. Never put a secret in an argument (dry-run prints them).
vm() {
    local cmd
    cmd=$(printf '%q ' "$@")
    if p2_dry; then
        echo "would run in the VM: $cmd"
        return 0
    fi
    "${P2_SSH[@]}" "$cmd"
}

# The same with stdin from the caller (a script on stdin: vm_stdin sudo bash -s -- args < file).
vm_stdin() {
    local cmd
    cmd=$(printf '%q ' "$@")
    if p2_dry; then
        echo "would run in the VM (script on stdin): $cmd"
        cat >/dev/null
        return 0
    fi
    "${P2_SSH[@]}" "$cmd"
}

p2_need() {
    local t
    for t in "$@"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            if p2_dry; then info "warning: missing tool $t (a real run would stop here)"; else die "missing tool: $t"; fi
        fi
    done
}

# Take the lab's lock (one up / down / users change at a time). Held until the process ends; the
# file descriptor is closed for everything the script starts (9>&- in the callers that start qemu).
p2_lock() {
    p2_dry && return 0
    [ -d "$LAB_DIR" ] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    exec 9>"$LAB_DIR/.p2.lock"
    flock -n 9 || die "another up.sh / down.sh is running on $LAB_DIR"
}

p2_is_lab_dir() { [ -f "$LAB_DIR/.winrbd-lab" ]; }

# ---------------------------------------------------------------------------------------------
# the machine: ports, multicast group, MACs, budget
# ---------------------------------------------------------------------------------------------

# "<cores> <mem_mb> <count>" of every qemu process (the command itself, not a shell or ssh line that mentions
# it) whose command line is below P2_WORKROOT, except those
# whose command line contains the pattern $1 (this lab's own VM, when it is being counted separately).
p2_qemu_usage() {
    ps -eww -o args= 2>/dev/null | awk -v root="$P2_WORKROOT/" -v skip="${1:-@none@}" '
        $1 ~ /(^|\/)qemu-system-[a-z0-9_]+$/ && index($0, root) && !index($0, skip) {
            c = 1; m = 128
            n = split($0, f, " ")
            for (i = 1; i < n; i++) {
                if (f[i] == "-smp") { v = f[i+1]; sub(/^cpus=/, "", v); sub(/[^0-9].*$/, "", v); if (v != "") c = v + 0 }
                if (f[i] == "-m")   { v = f[i+1]; sub(/^size=/, "", v); u = v; sub(/[^0-9].*$/, "", v); sub(/^[0-9]+/, "", u); u = substr(u, 1, 1); m = v + 0; if (u == "G" || u == "g") m *= 1024 }
            }
            cores += c; mem += m; cnt++
        }
        END { printf "%d %d %d\n", cores, mem, cnt }'
}

# Refuse to start a VM of $1 cores / $2 MiB when the workflow's total would exceed the budget.
# $3 = pattern of command lines not to count (default: none).
p2_budget_check() {
    local add_c=$1 add_m=$2 skip=${3:-@none@} c m n
    read -r c m n < <(p2_qemu_usage "$skip")
    info "budget: $n other VM(s) under $P2_WORKROOT use $c cores / $m MiB; adding $add_c cores / $add_m MiB; limit $P2_BUDGET_CORES cores / $P2_BUDGET_MEM_MB MiB"
    if [ $((c + add_c)) -gt "$P2_BUDGET_CORES" ] || [ $((m + add_m)) -gt "$P2_BUDGET_MEM_MB" ]; then
        die "the workflow budget would be exceeded ($((c + add_c)) cores / $((m + add_m)) MiB); stop another VM first"
    fi
}

p2_port_in_use() {
    if command -v ss >/dev/null 2>&1; then
        [ -n "$(ss -H -ltn "sport = :$1" 2>/dev/null)" ]
    else
        (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
    fi
}

# p2_has TEXT PATTERN: does TEXT contain PATTERN (fixed string, case-insensitive)? Counts instead of
# using grep -q, which can make an upstream printf die of SIGPIPE under pipefail.
p2_has() {
    local n
    n=$(printf '%s\n' "$1" | grep -c -i -F -- "$2" || true)
    [ "${n:-0}" -gt 0 ]
}

# Another VM that uses our multicast group or one of our MAC addresses would join our layer 2. The other
# QEMU processes are listed with their pid first, so the command is the second word. The comparison is by
# whole option value (the command line is split at commas and blanks), so 230.77.12.1:7712 never matches a
# longer group or port. A guest of the live tests that is still running while the lab VM is stopped is
# also such a VM: the message names the process.
p2_check_isolation() {
    local others
    others=$(ps -eww -o pid=,args= 2>/dev/null | awk -v own="$LAB_VMDIR/" -v probe="$LAB_DIR/probe/" \
        '$2 ~ /(^|\/)qemu-system-[a-z0-9_]+$/ && !index($0, own) && !index($0, probe) { print }' || true)
    p2_isolation_verdict "$others"
}

# p2_isolation_verdict PS_LINES: succeeds when none of the "pid command line" lines uses our group or MACs.
p2_isolation_verdict() {
    local line tok mac pid macs=() m mc
    mc=$(printf '%s' "$LAB_MCAST" | tr '[:upper:]' '[:lower:]')
    for m in "$LAB_MAC_INET" "$LAB_MAC_PRIV" "$P2_PROBE_MAC_INET" "$P2_PROBE_MAC_PRIV"; do
        macs+=("$(printf '%s' "$m" | tr '[:upper:]' '[:lower:]')")
    done
    while IFS= read -r line; do
        line=${line#"${line%%[![:space:]]*}"}      # ps pads the pid with blanks
        [ -n "$line" ] || continue
        pid=${line%% *}
        while IFS= read -r tok; do
            if [ "$tok" = "mcast=$mc" ]; then
                die "another QEMU process (pid $pid) already uses the multicast group $LAB_MCAST; stop it, or set LAB_MCAST to an unused group"
            fi
            for mac in "${macs[@]}"; do
                if [ "$tok" = "mac=$mac" ]; then
                    die "another QEMU process (pid $pid) already uses the MAC address $mac"
                fi
            done
        done < <(printf '%s\n' "$line" | tr ', ' '\n' | tr '[:upper:]' '[:lower:]')
    done <<< "$1"
    return 0
}

p2_free_gb() { df -Pk "$1" | awk 'NR==2{printf "%d", $4/1048576}'; }

# ---------------------------------------------------------------------------------------------
# the cloud-localds stand-in: the repository's make-vm.sh builds its cloud-init seed with
# cloud-localds or genisoimage, which a shared box without root does not have. This writes the same
# seed (an ISO 9660 image with a Joliet tree, volume label cidata) with the Python standard library.
# ---------------------------------------------------------------------------------------------

p2_write_shim() {
    local dir=$LAB_DIR/tools/bin
    if p2_dry; then
        echo "would write the cloud-localds stand-in to $dir/cloud-localds"
        return 0
    fi
    mkdir -p "$dir"
    cat > "$dir/cloud-localds" <<'PY'
#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
# cloud-localds stand-in:  cloud-localds [-N network-config] OUTPUT user-data [meta-data]
# Writes an ISO 9660 image (volume label "cidata", Joliet names) holding user-data, meta-data and
# network-config, as cloud-init's NoCloud datasource wants it. Standard library only.
import datetime
import struct
import sys

SECT = 2048


def pad(b, n, fill=b"\x00"):
    return (b + fill * n)[:n]


def both16(n):
    return struct.pack("<H", n) + struct.pack(">H", n)


def both32(n):
    return struct.pack("<I", n) + struct.pack(">I", n)


def rec_date(d):
    return bytes([d.year - 1900, d.month, d.day, d.hour, d.minute, d.second, 0])


def vd_date(d):
    return d.strftime("%Y%m%d%H%M%S").encode() + b"00" + b"\x00"


def dirrec(extent, size, flags, ident, d):
    n = len(ident)
    total = 33 + n + (1 if n % 2 == 0 else 0)
    r = struct.pack("<BB", total, 0) + both32(extent) + both32(size) + rec_date(d)
    r += struct.pack("<BBB", flags, 0, 0) + both16(1) + struct.pack("<B", n) + ident
    return pad(r, total)


def dirsector(extent, parent, entries, d):
    out = dirrec(extent, SECT, 2, b"\x00", d) + dirrec(parent, SECT, 2, b"\x01", d)
    for ident, ext, size in sorted(entries):
        out += dirrec(ext, size, 0, ident, d)
    if len(out) > SECT:
        raise SystemExit("too many entries for one directory sector")
    return pad(out, SECT)


def path_table(extent, big):
    e = struct.pack(">I" if big else "<I", extent)
    p = struct.pack("<BB", 1, 0) + e + struct.pack(">H" if big else "<H", 1) + b"\x00\x00"
    return p


def ucs(s):
    return s.encode("utf-16-be")


def vd(kind, joliet, d, total, root, ptsize, ptl, ptm, label):
    if joliet:
        enc = ucs
        escape = b"%/E"
        sysid = enc("")
        flag = 0
    else:
        enc = lambda s: s.encode("ascii")
        escape = b""
        sysid = b""
        flag = 0
    fill = b"\x00\x20" if joliet else b" "

    def field(s, n):
        return pad(enc(s), n, fill)

    v = struct.pack("<B5sBB", kind, b"CD001", 1, flag)
    v += pad(sysid, 32, fill) + field(label, 32) + b"\x00" * 8 + both32(total)
    v += pad(escape, 32) + both16(1) + both16(1) + both16(SECT) + both32(ptsize)
    v += struct.pack("<I", ptl) + struct.pack("<I", 0) + struct.pack(">I", ptm) + struct.pack(">I", 0)
    v += root
    v += field("", 128) * 4          # volume set, publisher, preparer, application
    v += field("", 37) * 3           # copyright, abstract, bibliographic file ids
    v += vd_date(d) + vd_date(d) + b"0000000000000000\x00" + b"0000000000000000\x00"
    v += struct.pack("<BB", 1, 0)
    return pad(v, SECT)


def main(argv):
    netcfg = None
    args = list(argv)
    if args[:1] == ["-N"]:
        netcfg = args[1]
        args = args[2:]
    elif args[:1] and args[0].startswith("--network-config="):
        netcfg = args[0].split("=", 1)[1]
        args = args[1:]
    if len(args) < 2:
        raise SystemExit("usage: cloud-localds [-N network-config] OUTPUT user-data [meta-data]")
    out, files = args[0], [("user-data", args[1])]
    files.append(("meta-data", args[2] if len(args) > 2 else None))
    if netcfg:
        files.append(("network-config", netcfg))
    blobs = []
    for name, path in files:
        data = open(path, "rb").read() if path else b""
        blobs.append((name, data))
    d = datetime.datetime(2026, 1, 1, 0, 0, 0)
    # layout: 16 PVD, 17 SVD (Joliet), 18 terminator, 19-22 path tables, 23 root, 24 Joliet root, 25.. data
    first = 25
    extents = []
    nxt = first
    for _, data in blobs:
        extents.append(nxt)
        nxt += max(1, (len(data) + SECT - 1) // SECT)
    total = nxt
    used = set()
    prim = []
    jol = []
    for (name, data), ext in zip(blobs, extents):
        base = name.upper().replace("-", "_")
        short = base[:8]
        while short in used:
            short = short[:-1] + "X"
        used.add(short)
        prim.append((short.encode() + b".;1", ext, len(data)))
        jol.append((ucs(name), ext, len(data)))
    img = bytearray(16 * SECT)
    proot = dirrec(23, SECT, 2, b"\x00", d)
    jroot = dirrec(24, SECT, 2, b"\x00", d)
    img += vd(1, False, d, total, proot, 10, 19, 20, "cidata")
    img += vd(2, True, d, total, jroot, 10, 21, 22, "cidata")
    img += pad(struct.pack("<B5sB", 255, b"CD001", 1), SECT)
    img += pad(path_table(23, False), SECT) + pad(path_table(23, True), SECT)
    img += pad(path_table(24, False), SECT) + pad(path_table(24, True), SECT)
    img += dirsector(23, 23, prim, d) + dirsector(24, 24, jol, d)
    for _, data in blobs:
        img += pad(data, max(1, (len(data) + SECT - 1) // SECT) * SECT)
    with open(out, "wb") as f:
        f.write(img)


main(sys.argv[1:])
PY
    chmod 755 "$dir/cloud-localds"
}

# ---------------------------------------------------------------------------------------------
# VM state
# ---------------------------------------------------------------------------------------------

p2_vm_pid() {
    local pid
    pid=$(cat "$LAB_VMDIR/qemu.pid" 2>/dev/null || true)
    if [ -n "$pid" ] && [ -d "/proc/$pid" ] && grep -q "$LAB_VMDIR" "/proc/$pid/cmdline" 2>/dev/null; then
        echo "$pid"
    fi
}

p2_ssh_ok() { "${P2_SSH[@]}" true >/dev/null 2>&1; }

p2_wait_ssh() {
    p2_dry && { echo "would wait for ssh on 127.0.0.1:$LAB_SSH_PORT (up to $P2_WAIT_SSH_S s)"; return 0; }
    local t=0
    until p2_ssh_ok; do
        [ "$t" -lt "$P2_WAIT_SSH_S" ] || die "the VM did not accept ssh within $P2_WAIT_SSH_S s (see $LAB_VMDIR/console.log)"
        sleep 5; t=$((t + 5))
    done
    # bounded: a cloud-init that never finishes must not hang the script (the stages need only ssh and apt)
    vm timeout 600 cloud-init status --wait >/dev/null 2>&1 || true
}

# Check that the VM runs under nice / choom as required; stop it and fail when not.
p2_check_wrap() {
    p2_dry && return 0
    local pid ni oom
    pid=$(p2_vm_pid)
    [ -n "$pid" ] || die "the VM is not running"
    ni=$(ps -o ni= -p "$pid" | tr -d ' ')
    oom=$(cat "/proc/$pid/oom_score_adj")
    if [ "$ni" != "$LAB_NICE" ] || [ "$oom" != 600 ]; then
        "$p2_lab/make-vm.sh" stop || true
        die "the VM (pid $pid) runs with nice $ni and oom_score_adj $oom, expected $LAB_NICE and 600; stopped it"
    fi
    info "VM pid $pid: nice $ni, oom_score_adj $oom"
}

# ---------------------------------------------------------------------------------------------
# guest stages (run detached in the VM, polled from here, so a dropped ssh connection loses nothing)
# ---------------------------------------------------------------------------------------------

p2_copy_scripts() {
    if p2_dry; then
        echo "would copy common.sh guest-packages.sh bootstrap-ceph.sh krbd-compat.sh and a generated lab.conf to ~/lab in the VM"
        return 0
    fi
    tar -C "$p2_lab" -cf - common.sh guest-packages.sh bootstrap-ceph.sh krbd-compat.sh \
        | "${P2_SSH[@]}" 'mkdir -p ~/lab && tar -C ~/lab -xf -'
    {
        local v
        for v in LAB_PRIV_CIDR LAB_OSD_COUNT LAB_POOL LAB_CEPHX_ID LAB_CEPH_RELEASE LAB_CEPH_VERSION \
                 LAB_CEPH_IMAGE LAB_CEPH_APT_URL LAB_CEPH_KEY_URL; do
            printf '%s=%q\n' "$v" "${!v}"
        done
    } | "${P2_SSH[@]}" 'cat > ~/lab/lab.conf'
    "${P2_SSH[@]}" 'cat > ~/lab/p2-stage.sh && chmod 755 ~/lab/p2-stage.sh' <<'EOS'
#!/bin/sh
# usage (as root): p2-stage.sh NAME COMMAND...   runs COMMAND, log in /var/log/winrbd-p2-NAME.log,
# result in /var/lib/winrbd-p2/NAME.rc, and NAME.done when it succeeded.
name=$1; shift
d=/var/lib/winrbd-p2
mkdir -p "$d"
rm -f "$d/$name.rc" "$d/$name.done"
"$@" > "/var/log/winrbd-p2-$name.log" 2>&1
rc=$?
echo $rc > "$d/$name.rc"
[ $rc = 0 ] && : > "$d/$name.done"
exit 0
EOS
    "${P2_SSH[@]}" 'cat > ~/lab/p2-tune.sh && chmod 755 ~/lab/p2-tune.sh' <<'EOS'
#!/bin/bash
# usage (as root): p2-tune.sh OSD_MEMORY_TARGET_BYTES
# Three OSDs, a mon and a mgr in 8 GiB: pin the OSD memory target instead of the 4 GiB default.
set -euo pipefail
tgt=${1:?osd_memory_target}
ceph config set osd osd_memory_target_autotune false
ceph config rm "osd/host:$(hostname -s)" osd_memory_target >/dev/null 2>&1 || true
ceph config set osd osd_memory_target "$tgt"
EOS
}

# p2_stage NAME COMMAND...  : run a command in the VM as root, once (a marker records success).
p2_stage() {
    local name=$1; shift
    if p2_dry; then
        echo "would run stage '$name' as root in the VM: $*"
        return 0
    fi
    if "${P2_SSH[@]}" "test -e /var/lib/winrbd-p2/$name.done" 2>/dev/null; then
        info "stage $name: already done"
        return 0
    fi
    info "stage $name: running (log in the VM: /var/log/winrbd-p2-$name.log)"
    if "${P2_SSH[@]}" "pgrep -f '[p]2-stage.sh $name ' >/dev/null" 2>/dev/null; then
        # an earlier up.sh was interrupted (Ctrl-C, a dropped terminal) while the stage kept running in the VM: wait for
        # that run, a second one next to it would fight over the package lock or try to bootstrap twice
        info "stage $name: already running in the VM (started by an earlier up.sh); waiting for it"
    else
        # a result left by an earlier failed run must not be read as the result of this one: the stage is started in
        # the background, so the first poll can come before the stage script has removed it itself
        "${P2_SSH[@]}" "sudo rm -f /var/lib/winrbd-p2/$name.rc /var/lib/winrbd-p2/$name.done"
        "${P2_SSH[@]}" "{ cd ~/lab && sudo setsid nohup ./p2-stage.sh $name $*; } </dev/null >/dev/null 2>&1 &"
    fi
    local t=0 rc=""
    while :; do
        rc=$("${P2_SSH[@]}" "sudo cat /var/lib/winrbd-p2/$name.rc 2>/dev/null" 2>/dev/null || true)
        [ -n "$rc" ] && break
        [ "$t" -lt "$P2_WAIT_STAGE_S" ] || die "stage $name did not finish within $P2_WAIT_STAGE_S s"
        sleep 10; t=$((t + 10))
    done
    mkdir -p "$LAB_DIR/logs"
    "${P2_SSH[@]}" "sudo cat /var/log/winrbd-p2-$name.log" > "$LAB_DIR/logs/stage-$name.log" 2>/dev/null || true
    if [ "$rc" != 0 ]; then
        info "stage $name failed (rc=$rc); last lines of its log:"
        tail -n 25 "$LAB_DIR/logs/stage-$name.log" >&2 || true
        die "stage $name failed; fix the cause, then run down.sh and up.sh again (bootstrap-ceph.sh is not restartable)"
    fi
    info "stage $name: ok ($t s)"
}

# Health checks that are expected in this lab and must not hide a real problem behind HEALTH_WARN:
#  - AUTH_INSECURE_*: the lab accepts legacy keys on purpose (krbd-compat.sh). krbd-compat.sh mutes them, but a
#    plain mute is dropped when the check clears (for instance when the last legacy-key user is deleted) and
#    the next legacy-key user would turn the lab to HEALTH_WARN. A sticky mute stays.
#  - BLUESTORE_SLOW_OP_ALERT: the VM runs at nice 19 on a machine that is busy with other work, so its sparse
#    disks are slow after every boot and Ceph keeps the warning for 24 hours. Slow disks are a property of
#    the shared box, not a fault of the cluster; operations that really hang still show as SLOW_OPS.
p2_mute_insecure() {
    p2_dry && { echo "would mute the expected health checks (AUTH_INSECURE_*, BLUESTORE_SLOW_OP_ALERT; sticky)"; return 0; }
    vm_stdin sudo bash -s <<'EOS'
for c in AUTH_INSECURE_CLIENT_KEY_TYPE AUTH_INSECURE_KEYS_ALLOWED AUTH_INSECURE_KEYS_CREATABLE AUTH_INSECURE_SERVICE_TICKETS BLUESTORE_SLOW_OP_ALERT; do
    ceph health mute "$c" --sticky >/dev/null 2>&1 || true
done
EOS
}

p2_wait_health() {
    p2_mute_insecure
    p2_dry && { echo "would wait for HEALTH_OK (up to $P2_WAIT_HEALTH_S s)"; return 0; }
    local t=0 h=""
    while :; do
        h=$(vm sudo ceph health 2>/dev/null || true)
        case "$h" in HEALTH_OK*) info "cluster: $h"; return 0;; esac
        [ "$t" -lt "$P2_WAIT_HEALTH_S" ] || { vm sudo ceph health detail >&2 || true; die "cluster is not HEALTH_OK after $P2_WAIT_HEALTH_S s (got: ${h:-nothing})"; }
        sleep 10; t=$((t + 10))
    done
}

# Every address the OSD map and the monitor map advertise must sit on the private layer 2: a guest
# on it has no other way in. Prints "<name> <addr>" for every msgr2 address. Fails (non-zero, nothing
# printed to stdout that could pass for a result) when the maps cannot be read: an empty answer is an
# error, never "no addresses outside the network".
p2_cluster_addrs() {
    vm_stdin sudo bash -s <<'EOS'
set -euo pipefail
ceph mon dump -f json 2>/dev/null | jq -r '.mons[] | .name as $n | .public_addrs.addrvec[] | select(.type=="v2") | "mon.\($n) \(.addr)"'
ceph osd dump -f json 2>/dev/null | jq -r '.osds[] | select(.up == 1) | .osd as $o | .public_addrs.addrvec[] | select(.type=="v2") | "osd.\($o) \(.addr)"'
EOS
}

# p2_check_addr_list LIST MIN_OSDS NET_PREFIX: every "<name> <addr>" line of LIST is inside the network, there is at
# least one monitor and at least MIN_OSDS OSDs. Dies otherwise.
p2_check_addr_list() {
    local all=$1 want=$2 net=$3 bad=0 name addr nmon=0 nosd=0
    while read -r name addr; do
        [ -n "$name" ] || continue
        case "$name" in mon.*) nmon=$((nmon + 1));; osd.*) nosd=$((nosd + 1));; *) die "unexpected daemon name '$name' in the address list";; esac
        case "$addr" in "$net"*:[0-9]*) ;; *) info "address of $name is $addr, outside ${net}0/24"; bad=1;; esac
    done <<< "$all"
    [ "$bad" = 0 ] || die "some Ceph daemons advertise addresses outside the private layer 2; a guest on it could not reach them"
    [ "$nmon" -ge 1 ] || die "the monitor map has no msgr2 address (is the cluster up?)"
    [ "$nosd" -ge "$want" ] || die "only $nosd of $want OSDs are up with a msgr2 address; the check would prove nothing about the rest"
}

p2_check_addrs() {
    p2_dry && { echo "would check that every mon / OSD address is inside the private network"; return 0; }
    local all
    all=$(p2_cluster_addrs) || die "could not read the monitor and OSD maps from the lab VM"
    p2_check_addr_list "$all" "$LAB_OSD_COUNT" "${LAB_PRIV_CIDR%.*}."
    info "daemon addresses (msgr2): $(printf '%s' "$all" | tr '\n' ' ')"
}

# p2_probe_verdict LINES WANT_MON WANT_OSD: judge the "WRPROBE ..." lines a probe guest wrote to its console. Prints the
# table; succeeds only when the guest finished (END), every monitor and OSD the maps advertise answered with the msgr2
# banner (the counts must match exactly: a guest that skipped a target is a failure), the control address did not
# answer, and the route to the monitor used the private NIC.
p2_probe_verdict() {
    local lines=$1 want_mon=$2 want_osd=$3 fail=0 nmon=0 nosd=0 nctl=0 kind name addr status banner verdict
    if ! printf '%s\n' "$lines" | grep -c '^WRPROBE END' | grep -qv '^0$'; then
        info "the guest did not finish (no END line)"
        return 1
    fi
    echo "guest (static $P2_PROBE_IP on NIC 2, multicast $LAB_MCAST):"
    printf '%s\n' "$lines" | grep -E '^WRPROBE (LINK|ADDR|ROUTE|NEIGH) ' | sed 's/^WRPROBE /  /' || true
    echo "TCP from the guest (first 8 bytes of a msgr2 peer are 'ceph v2'):"
    while read -r _ _ kind name addr status banner; do
        verdict=
        case "$kind" in
            mon|osd)
                if [ "$status" = connected ] && [ "$banner" = "ceph v2" ]; then verdict="OK"; else verdict="FAIL"; fail=1; fi
                if [ "$kind" = mon ]; then nmon=$((nmon + 1)); else nosd=$((nosd + 1)); fi;;
            ctl)
                nctl=$((nctl + 1))
                if [ "$status" = connected ]; then verdict="FAIL (an address nobody owns answered)"; fail=1; else verdict="OK (no answer, as intended)"; fi;;
            *) verdict="FAIL (unknown target kind '$kind')"; fail=1;;
        esac
        printf '  %-8s %-22s %-12s %-8s %s\n' "$name" "$addr" "$status" "${banner:--}" "$verdict"
    done < <(printf '%s\n' "$lines" | grep '^WRPROBE TCP ' || true)
    if [ "$nmon" != "$want_mon" ]; then info "the guest reported $nmon monitor(s), the maps advertise $want_mon"; fail=1; fi
    if [ "$nosd" != "$want_osd" ]; then info "the guest reported $nosd OSD(s), the maps advertise $want_osd"; fail=1; fi
    if [ "$nmon" -lt 1 ] || [ "$nosd" -lt 1 ]; then info "nothing to prove: no monitor or no OSD was probed"; fail=1; fi
    if [ "$nctl" != 1 ]; then info "the control address was probed $nctl time(s), expected once"; fail=1; fi
    if ! printf '%s\n' "$lines" | grep -c '^WRPROBE ROUTE .* dev lab0' | grep -qv '^0$'; then
        info "the route to the monitor does not use lab0 (the private layer 2)"
        fail=1
    fi
    # shellcheck disable=SC2034  # read by probe.sh, which sources this file
    P2_PROBE_NMON=$nmon P2_PROBE_NOSD=$nosd
    return "$fail"
}

p2_resources() {
    local pid
    pid=$(p2_vm_pid || true)
    if [ -z "$pid" ]; then echo "VM not running"; return 0; fi
    local c m n
    read -r c m n < <(p2_qemu_usage "@none@")
    echo "lab VM: pid $pid, $LAB_VCPUS vCPU, $LAB_MEM_MB MiB, nice $(ps -o ni= -p "$pid" | tr -d ' '), oom_score_adj $(cat "/proc/$pid/oom_score_adj")"
    ps -o pid=,pcpu=,rss=,nlwp= -p "$pid" | awk '{printf "  qemu: %s%% CPU (average since start), %d MiB resident, %d threads\n", $2, $3/1024, $4}'
    echo "  all QEMU processes under $P2_WORKROOT: $n VM(s), $c cores, $m MiB assigned (budget $P2_BUDGET_CORES cores / $P2_BUDGET_MEM_MB MiB)"
    if p2_ssh_ok; then
        vm_stdin sh -s <<'EOS'
free -m | awk 'NR==2{printf "  guest: %d MiB used of %d MiB, %d MiB available\n", $3, $2, $7}'
uptime | sed 's/^ */  guest load: /'
EOS
    fi
}

# ---------------------------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------------------------

p2_cmd_up() {
    p2_need qemu-system-x86_64 qemu-img curl sha256sum ssh ssh-keygen python3 tar awk ps choom nice
    if ! p2_dry; then
        [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not usable by $(id -un); a lab without KVM is too slow to be a test"
    fi

    if [ -d "$LAB_DIR" ] && ! p2_is_lab_dir; then
        [ -z "$(ls -A "$LAB_DIR" 2>/dev/null)" ] || die "$LAB_DIR exists, is not empty and is not a lab directory; refusing to use it"
    fi
    if ! p2_dry; then
        mkdir -p "$LAB_DIR"
        : > "$LAB_DIR/.winrbd-lab"
        mkdir -p "$LAB_DIR/ssh" "$LAB_DIR/keys" "$LAB_DIR/logs" "$LAB_DIR/state"
        chmod 700 "$LAB_DIR/ssh" "$LAB_DIR/keys" "$LAB_DIR/logs"
    else
        echo "would create $LAB_DIR (marker, ssh/, keys/ mode 700, logs/, state/)"
    fi
    p2_lock

    local free
    if [ -d "$LAB_DIR" ]; then
        free=$(p2_free_gb "$LAB_DIR")
        [ "$free" -ge "$LAB_MIN_FREE_GB" ] || die "only $free GB free under $LAB_DIR (need $LAB_MIN_FREE_GB)"
    fi

    local pid
    pid=$(p2_vm_pid || true)
    if [ -z "$pid" ]; then
        p2_check_isolation
        if p2_port_in_use "$LAB_SSH_PORT"; then die "TCP port $LAB_SSH_PORT on 127.0.0.1 is in use; set LAB_SSH_PORT to a free port"; fi
        p2_budget_check "$LAB_VCPUS" "$LAB_MEM_MB" "$LAB_VMDIR/"
    fi

    if [ ! -f "$LAB_DIR/ssh/id_ed25519" ]; then
        run ssh-keygen -q -t ed25519 -N '' -C winrbd-p2-lab -f "$LAB_DIR/ssh/id_ed25519"
    fi
    p2_write_shim

    if [ -z "$pid" ]; then
        if [ ! -f "$LAB_VMDIR/root.qcow2" ]; then
            info "preparing the VM (downloads and verifies the base image: a few minutes)"
            # the download resumes (curl -C -), so a reset connection costs only a retry; nothing else
            # in prepare can half-succeed before the download is complete
            local try=1
            until PATH="$LAB_DIR/tools/bin:$PATH" run "$p2_lab/make-vm.sh" prepare 9>&-; do
                [ "$try" -lt 8 ] || die "make-vm.sh prepare failed $try times; see above"
                info "prepare failed (attempt $try); retrying, the download resumes"
                try=$((try + 1)); sleep 5
            done
        fi
        info "starting the VM under: ${P2_WRAP[*]}"
        run "${P2_WRAP[@]}" "$p2_lab/make-vm.sh" start 9>&-
    else
        info "the VM is already running (pid $pid)"
    fi
    p2_check_wrap
    p2_wait_ssh
    p2_copy_scripts
    p2_stage guest-packages ./guest-packages.sh
    p2_stage bootstrap ./bootstrap-ceph.sh
    p2_stage krbd-compat ./krbd-compat.sh
    p2_stage tune ./p2-tune.sh "$P2_OSD_MEMORY_TARGET"
    p2_wait_health
    p2_check_addrs
    if ! p2_dry; then date -u +%Y-%m-%dT%H:%M:%SZ > "$LAB_DIR/state/up.done"; fi
    info "lab cluster is up"
    p2_cmd_status
}

p2_cmd_status() {
    if p2_dry; then echo "would show the VM state, ceph -s, pools, addresses and resources"; return 0; fi
    if [ -z "$(p2_vm_pid || true)" ]; then echo "lab VM: not running ($LAB_DIR)"; return 0; fi
    echo "lab dir: $LAB_DIR"
    echo "ssh:     ssh -i $LAB_DIR/ssh/id_ed25519 -p $LAB_SSH_PORT $LAB_SSH_USER@127.0.0.1   (from this machine)"
    echo "layer 2: multicast $LAB_MCAST on $LAB_MCAST_LOCALADDR, monitor ${LAB_PRIV_CIDR%/*}:3300"
    if p2_ssh_ok; then
        vm sudo ceph -s || true
        vm sudo ceph osd pool ls detail | cut -c1-160 || true
        p2_cluster_addrs | sed 's/^/  addr /' || true
    else
        echo "ssh to the VM does not answer (still booting, or stopped)"
    fi
    p2_resources
}

p2_cmd_env() {
    cat <<EOF
P2_LAB_DIR=$LAB_DIR
P2_SSH_PORT=$LAB_SSH_PORT
P2_SSH_KEY=$LAB_DIR/ssh/id_ed25519
P2_SSH_USER=$LAB_SSH_USER
P2_KNOWN_HOSTS=$LAB_DIR/known_hosts
P2_MCAST=$LAB_MCAST
P2_MCAST_LOCALADDR=$LAB_MCAST_LOCALADDR
P2_MON_ADDR=${LAB_PRIV_CIDR%/*}
P2_MON_PORT=3300
P2_NET_CIDR=${LAB_PRIV_CIDR%.*}.0/24
P2_POOL=$LAB_POOL
P2_KEYS_DIR=$LAB_DIR/keys
P2_BASE_IMAGE=$LAB_IMGDIR/$LAB_IMAGE_NAME
P2_BUDGET_CORES=$P2_BUDGET_CORES
P2_BUDGET_MEM_MB=$P2_BUDGET_MEM_MB
EOF
}

p2_up_main() {
    p2_init "$@"
    local cmd=${P2_ARGS[0]:-up}
    case "$cmd" in
        up)     p2_cmd_up;;
        status) p2_cmd_status;;
        stop)   run "$p2_lab/make-vm.sh" stop 9>&-;;
        env)    p2_cmd_env;;
        ssh)    P2_DRY_RUN=0; "${P2_SSH[@]}" "${P2_ARGS[@]:1}";;
        *) sed -n '10,18p' "${BASH_SOURCE[0]}"; exit 2;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    p2_up_main "$@"
fi
