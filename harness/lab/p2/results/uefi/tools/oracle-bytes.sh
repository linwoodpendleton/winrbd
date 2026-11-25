#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# oracle-bytes.sh IMAGE OUT - the oracle of the SAN-level byte check: "rbd export" of the imported byte-check disk (read by the lab's own
# Ceph tools, not by the driver), the files read back out of its FAT file system with mtools, and their md5 in the format of
# build-bytes-image.sh's MD5SUMS. Runs on the box that hosts the lab VM; needs P2_LAB_DIR and P2Q_WORK (for the mtools prefix).
#
# It also checks the export against the image digest in bytes.manifest (P2U_IMAGES/bytes/bytes.manifest): the export must be the very file that was
# built. A missing manifest is an error (the oracle would not be tied to the image that was built); P2U_ORACLE_NO_MANIFEST=1 says so on purpose.
set -euo pipefail
: "${P2_LAB_DIR:?}"
: "${P2Q_WORK:?}"
img=${1:?usage: oracle-bytes.sh IMAGE OUT}
out=${2:?usage: oracle-bytes.sh IMAGE OUT}
case $img in wrtest-*) ;; *) echo "oracle-bytes.sh: only wrtest-* images" >&2; exit 2;; esac
tools=$P2Q_WORK/tools/usr
export LD_LIBRARY_PATH=$tools/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
mcopy=$tools/bin/mcopy
[ -x "$mcopy" ] || mcopy=$(command -v mcopy)
tmp=$(mktemp -d "$P2Q_WORK/oracle.XXXXXX")
trap 'rm -f -- "$tmp"/export.raw "$tmp"/f.* ; rmdir "$tmp" 2>/dev/null || true' EXIT
ssh -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
    -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" "${LAB_SSH_USER:-lab}@127.0.0.1" "sudo rbd export --no-progress winrbd/$img -" > "$tmp/export.raw"
sum=$(sha256sum "$tmp/export.raw" | cut -d' ' -f1)
man=${P2U_IMAGES:-$P2Q_WORK/../out/images}/bytes/bytes.manifest
if [ -r "$man" ]; then
    want=$(sed -n 's/^image_sha256[= ]//p' "$man")
    [ -n "$want" ] && [ "$want" = "$sum" ] || { echo "oracle-bytes.sh: rbd export ($sum) is not the image that was built (manifest says '${want:-nothing}')" >&2; exit 1; }
elif [ "${P2U_ORACLE_NO_MANIFEST:-0}" = 1 ]; then
    echo "oracle-bytes.sh: no manifest $man: the export is not compared with the image that was built (P2U_ORACLE_NO_MANIFEST=1)" >&2
else
    echo "oracle-bytes.sh: no manifest $man: the oracle would not be tied to the image that was built (set P2U_ORACLE_NO_MANIFEST=1 to go on)" >&2
    exit 1
fi
: > "$out.tmp"
# the names come from the disk's own directory listing, not from our list: a file that is on the disk and not in the list shows up here
for n in $("$tools/bin/mdir" -b -i "$tmp/export.raw@@1M" :: | sed 's#^::/##'); do
    case $n in *[!A-Za-z0-9.+-]*) echo "oracle-bytes.sh: odd file name $n" >&2; exit 1;; esac
    "$mcopy" -n -i "$tmp/export.raw@@1M" "::/$n" "$tmp/f.cur"
    printf '%s  %s\n' "$(md5sum "$tmp/f.cur" | cut -d' ' -f1)" "$n" >> "$out.tmp"
    rm -f -- "$tmp/f.cur"
done
mv "$out.tmp" "$out"
echo "oracle-bytes.sh: export of $img is sha256 $sum; $(wc -l < "$out") files digested into $out"
