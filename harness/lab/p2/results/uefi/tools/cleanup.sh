#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# cleanup.sh - leave the lab as it was: remove what the UEFI matrix made, and list what is left.
#
#   cleanup.sh [-n] [--keep-images]       delete the throwaway users client.wrtest-p2-* of this matrix and their key files, the RBD images
#                                         (wrtest-p2-lin-uefi, wrtest-p2-bytes, wrtest-p2-winpe-gpt), the media that hold a key (the embedded ISO),
#                                         the raw images under P2U_IMAGES (a copy of the owner's WinPE image among them),
#                                         the run directories of the QEMU work directory; then print the lab's listing (users.sh list)
#
# Needs P2_LAB_DIR and P2Q_WORK (box-env.sh). Only names that start with wrtest-p2- are touched (images.sh / users.sh refuse others).
# The evidence directories (P2U_OUT) and the iPXE binaries stay: they hold no key (the script copies of a run live in the run directory,
# which the run script deletes itself; this removes what an interrupted run might have left).
set -euo pipefail
LC_ALL=C
export LC_ALL
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=${P2U_REPO:-$(cd "$here/../../../../../.." && pwd)}
: "${P2_LAB_DIR:?}"
: "${P2Q_WORK:?}"
dry=""
keep=0
while [ $# -gt 0 ]; do
    case $1 in -n) dry=-n;; --keep-images) keep=1;; *) echo "usage: cleanup.sh [-n] [--keep-images]" >&2; exit 2;; esac
    shift
done
LAB_DIR=$P2_LAB_DIR
export LAB_DIR
if [ "$keep" = 0 ]; then
    for n in wrtest-p2-lin-uefi wrtest-p2-bytes wrtest-p2-winpe-gpt; do
        bash "$repo/harness/lab/p2/images/import.sh" ${dry:+$dry} delete "$n" || echo "cleanup.sh: $n: not there or not removable" >&2
        if [ -z "$dry" ]; then
            f=$P2_LAB_DIR/keys/client.$n.secret
            [ ! -f "$f" ] || rm -f -- "$f"
        fi
    done
fi
if [ -z "$dry" ]; then
    # key files of throwaway users of this matrix (a user that was created and never listed above leaves one too)
    for f in "$P2_LAB_DIR"/keys/client.wrtest-p2-*.secret; do [ -f "$f" ] && rm -f -- "$f"; done
    # a medium that holds a key
    [ ! -f "$P2Q_WORK/ipxe/efi-ipxe-embed.iso" ] || rm -f -- "$P2Q_WORK/ipxe/efi-ipxe-embed.iso"
    # the raw disk images made for the import (the owner's WinPE image must not stay around); the manifests and digests are kept
    if [ -n "${P2U_IMAGES:-}" ] && [ -d "$P2U_IMAGES" ]; then
        for f in "$P2U_IMAGES"/*/*.raw; do [ -f "$f" ] && rm -f -- "$f"; done
    fi
    # run directories left by an interrupted run (the run scripts delete theirs; every one of them holds a mode-600 script copy)
    for d in "$P2Q_WORK"/runs/*; do
        [ -d "$d" ] || continue
        rm -f -- "$d"/autoexec.ipxe "$d"/run.ipxe "$d"/tftp/* "$d"/*.img "$d"/*.iso 2>/dev/null || true
    done
fi
# the listing names the lab directory (the box's own path, which has no place in the repository): show it as <lab dir>
bash "$repo/harness/lab/p2/cluster/users.sh" list | sed "s#$P2_LAB_DIR#<lab dir>#g; s#$HOME#~#g"
