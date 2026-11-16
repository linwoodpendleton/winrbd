#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Stop the lab VM and delete the files this lab created. Only well-known file
# names inside LAB_DIR are removed (never a recursive delete of a variable).
#
#   teardown.sh --yes                remove VM disks, seed, logs, sockets
#   teardown.sh --yes --purge-images also remove the downloaded base image
#   teardown.sh --yes --purge-all    also remove facts/ and the LAB_DIR itself
#                                    (only if nothing else is left in it)
#
# Without --yes it only prints what it would do.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_init

yes=0 purge_img=0 purge_all=0
for a in "$@"; do
    case "$a" in
        --yes) yes=1;;
        --purge-images) purge_img=1;;
        --purge-all) purge_all=1; purge_img=1;;
        *) die "unknown option $a";;
    esac
done
[ -f "$LAB_DIR/.winrbd-lab" ] || die "$LAB_DIR is not a winrbd lab directory (marker file missing); refusing"

run() { if [ "$yes" = 1 ]; then "$@"; else echo "would run: $*"; fi; }

if lab_running; then
    info "VM is running"
    if [ "$yes" = 1 ]; then "$lab_here/make-vm.sh" stop; else echo "would stop the VM"; fi
fi

files=(root.qcow2 seed.iso qemu.cmdline qemu.pid console.log console.sock qmp.sock)
for ((i = 0; i < LAB_OSD_COUNT; i++)); do files+=("osd$i.qcow2"); done
for f in "${files[@]}"; do
    [ -e "$LAB_VMDIR/$f" ] && run rm -f "$LAB_VMDIR/$f"
done
for f in user-data meta-data network-config; do
    [ -e "$LAB_VMDIR/seed-src/$f" ] && run rm -f "$LAB_VMDIR/seed-src/$f"
done
[ -d "$LAB_VMDIR/seed-src" ] && run rmdir "$LAB_VMDIR/seed-src"
[ -d "$LAB_VMDIR" ] && run rmdir "$LAB_VMDIR" 2>/dev/null || true

if [ "$purge_img" = 1 ]; then
    for f in "$LAB_IMAGE_NAME" "$LAB_IMAGE_NAME.part" "$LAB_IMAGE_NAME.sha256" SHA256SUMS; do
        [ -e "$LAB_IMGDIR/$f" ] && run rm -f "$LAB_IMGDIR/$f"
    done
    [ -d "$LAB_IMGDIR" ] && run rmdir "$LAB_IMGDIR" 2>/dev/null || true
fi
if [ "$purge_all" = 1 ]; then
    [ -e "$LAB_DIR/known_hosts" ] && run rm -f "$LAB_DIR/known_hosts"
    if [ -d "$LAB_FACTS" ]; then
        find "$LAB_FACTS" -maxdepth 1 -type f -print0 | while IFS= read -r -d '' f; do run rm -f "$f"; done
        run rmdir "$LAB_FACTS" 2>/dev/null || true
    fi
    run rm -f "$LAB_DIR/.winrbd-lab"
    run rmdir "$LAB_DIR" 2>/dev/null || info "$LAB_DIR not empty; left in place"
fi
[ "$yes" = 1 ] && info "done" || info "dry run; pass --yes to do it"
