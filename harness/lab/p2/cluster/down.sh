#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 lab cluster: stop the lab VM and delete exactly what up.sh, users.sh and probe.sh made.
#
#   down.sh [-n] [--keep-image]
#
#   -n, --dry-run   print what would be stopped and deleted, change nothing
#   --keep-image    keep the downloaded base image (LAB_DIR/images) for the next up.sh; LAB_DIR itself stays
#
# What it does, in order:
#   1. a probe guest that is still running (probe.sh crashed): terminated, only when its command line is ours
#   2. the lab VM: ACPI power-off, then terminate (harness/lab/make-vm.sh stop)
#   3. the files of this tool: the cloud-localds stand-in, the SSH key pair, the key files of the throwaway
#      cephx users, logs, state, probe leftovers, known_hosts, the lock
#   4. the files of the repository's lab scripts (harness/lab/teardown.sh --yes --purge-all): VM disks, seed,
#      console log, base image, facts
#   5. LAB_DIR itself, when it is empty; whatever is left is listed (and nothing outside LAB_DIR is ever touched)
# Only fixed, known names are removed (no recursive delete of a variable), and only when the marker file
# LAB_DIR/.winrbd-lab exists.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=up.sh
. "$here/up.sh"

keep_image=0
p2_init "$@"
for a in "${P2_ARGS[@]+"${P2_ARGS[@]}"}"; do
    case "$a" in
        --keep-image) keep_image=1;;
        *) die "unknown option $a";;
    esac
done

if [ ! -d "$LAB_DIR" ]; then
    info "nothing to do: $LAB_DIR does not exist"
    exit 0
fi
p2_is_lab_dir || die "$LAB_DIR is not a lab directory (marker file missing); refusing"
p2_lock

# 1. a stray probe guest
pidfile=$LAB_DIR/probe/qemu.pid
if [ -f "$pidfile" ]; then
    ppid=$(cat "$pidfile" 2>/dev/null || true)
    if [ -n "$ppid" ] && [ -d "/proc/$ppid" ] && grep -q "$LAB_DIR/probe" "/proc/$ppid/cmdline" 2>/dev/null; then
        info "terminating the probe guest (pid $ppid)"
        run kill "$ppid"
        if ! p2_dry; then
            for _ in 1 2 3 4 5 6 7 8 9 10; do [ -d "/proc/$ppid" ] || break; sleep 1; done
            [ ! -d "/proc/$ppid" ] || die "the probe guest (pid $ppid) did not stop"
        fi
    fi
fi

# 2. the lab VM
if [ -n "$(p2_vm_pid || true)" ]; then
    info "stopping the lab VM"
    run "$p2_lab/make-vm.sh" stop 9>&-
fi
if ! p2_dry && [ -n "$(p2_vm_pid || true)" ]; then
    die "the lab VM is still running; not deleting its disks"
fi

# 3. this tool's own files (fixed sub-directories of LAB_DIR, files only; a sub-directory with anything
#    unexpected in it is left alone and reported)
rmfiles() { # DIR: delete the regular files directly inside DIR, then the directory if it is empty
    local d=$1
    [ -d "$d" ] || return 0
    if p2_dry; then
        local f
        for f in "$d"/* "$d"/.[!.]*; do if [ -f "$f" ]; then echo "would remove $f"; fi; done
        echo "would remove directory $d"
        return 0
    fi
    find "$d" -maxdepth 1 -type f -delete
    rmdir "$d" 2>/dev/null || info "left in place (not empty): $d"
}
rmfiles "$LAB_DIR/keys"
rmfiles "$LAB_DIR/logs"
rmfiles "$LAB_DIR/state"
rmfiles "$LAB_DIR/probe"
rmfiles "$LAB_DIR/tools/bin"
rmfiles "$LAB_DIR/tools"
rmfiles "$LAB_DIR/ssh"
if [ -e "$LAB_DIR/known_hosts" ] || [ -e "$LAB_DIR/known_hosts.old" ]; then
    run rm -f "$LAB_DIR/known_hosts" "$LAB_DIR/known_hosts.old"
fi

# 4. the repository's own teardown (VM disks, seed, console log, images, facts, the marker, LAB_DIR)
if [ "$keep_image" = 1 ]; then
    run "$p2_lab/teardown.sh" --yes
else
    run rm -f "$LAB_DIR/.p2.lock"
    run "$p2_lab/teardown.sh" --yes --purge-all
fi

# 5. what is left
if p2_dry; then
    echo "dry run: nothing was changed"
    exit 0
fi
if [ -d "$LAB_DIR" ]; then
    if [ "$keep_image" = 1 ]; then
        info "kept (--keep-image): $(find "$LAB_DIR" -mindepth 1 | tr '\n' ' ')"
    else
        left=$(find "$LAB_DIR" -mindepth 1 2>/dev/null | tr '\n' ' ')
        info "WARNING: left behind in $LAB_DIR: $left"
        exit 1
    fi
else
    info "$LAB_DIR is gone; nothing of the lab is left"
fi
