#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# embed-iso.sh - row U3: the REAL iPXE build target bin-x86_64-efi/ipxe.iso with the run script embedded (EMBED=), built in the builder guest.
#
#   embed-iso.sh [-n] OUT.iso --user U --pool P --image I --key-file F [--ip A] [--row ID]
#
# The run script (gen-script.sh: sets the lab NIC's address, the rbd-key setting, sanboot) holds the throwaway cephx key, so the ISO holds it
# too: it is one user per image, deleted at the end of the run, and the ISO is deleted with it (cleanup.sh). The script and the build tree in
# the guest are deleted as soon as the ISO has been copied out. Runs on the box that hosts the builder (BUILDER_DIR), from the repository copy
# whose builder/up.sh and qemu/gen-script.sh it uses. The pinned tree in the guest is ~/work/ipxe/src (what build-ipxe.sh left there).
set -euo pipefail
LC_ALL=C
export LC_ALL
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=${P2U_REPO:-$(cd "$here/../../../../../.." && pwd)}
: "${BUILDER_DIR:?}"
dry=0
[ "${1:-}" = -n ] && { dry=1; shift; }
out=${1:?usage: embed-iso.sh [-n] OUT.iso --user U --pool P --image I --key-file F}
shift
tmp=$(mktemp -d "${TMPDIR:-/tmp}/p2u-embed.XXXXXX")
trap 'rm -f -- "$tmp/run.ipxe"; rmdir "$tmp" 2>/dev/null || true' EXIT
chmod 700 "$tmp"
bash "$repo/harness/lab/p2/qemu/gen-script.sh" -o "$tmp/run.ipxe" --row U3 --action sanboot "$@"
[ "$dry" = 0 ] || { echo "embed-iso.sh: dry run: script made ($(wc -l < "$tmp/run.ipxe") lines), nothing built"; exit 0; }
up=$repo/harness/lab/p2/builder/up.sh
bash "$up" put "$tmp/run.ipxe" work/embed-run.ipxe
bash "$up" ssh 'set -e; cd ~/work/ipxe/src; rm -rf ~/work/ipxe/embed-build; nice -n 19 bash ipxe/tools/build.sh build -o ~/work/ipxe/embed-build -j 4 -e ~/work/embed-run.ipxe bin-x86_64-efi/ipxe.iso > ~/work/embed-build.log 2>&1; tail -n 3 ~/work/embed-build.log; ls -l ~/work/ipxe/embed-build/src/bin-x86_64-efi/ipxe.iso; if grep -ci warning ~/work/embed-build.log | grep -qx 0; then echo "build: zero warnings"; else echo "build: WARNINGS"; fi'
bash "$up" get work/ipxe/embed-build/src/bin-x86_64-efi/ipxe.iso "$out"
bash "$up" ssh 'rm -f ~/work/embed-run.ipxe; rm -rf ~/work/ipxe/embed-build'
sha256sum "$out"
