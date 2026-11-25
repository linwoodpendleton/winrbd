#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Row U-bytes: the disk for the SAN-level byte check (docs/design/ipxe-driver.md, section 14.3, last sentence of the table's paragraph).
#
# iPXE has no command that reads raw sectors, so the byte check reads FILES through the SAN device: the firmware's FAT driver turns
# every file read into block reads at many offsets and lengths (FAT, directory and data sectors), and iPXE's own `imgfetch
# file://WRBYTES/<name>` + `md5sum` digest what came through. This script makes the disk those files live on: GPT, one FAT32 partition
# (label WRBYTES) holding files whose sizes straddle every boundary that matters (sector, 4 KiB, 64 KiB, 1 MiB, odd sizes) and one filler so
# that the high end of the disk is read too. The content is a deterministic pseudo-random stream (python3 random.Random(seed)), so the
# disk and its MD5SUMS list can be rebuilt byte for byte; the check compares THREE things: this list, the files read back out of
# `rbd export` of the imported image (the oracle) and what iPXE printed.
#
#   build-bytes-image.sh OUTDIR [SHELL.EFI]
#                                      writes OUTDIR/bytes.raw (192 MiB, sparse), OUTDIR/MD5SUMS ("<md5>  <name>", one per file) and
#                                      OUTDIR/bytes.manifest (name, size, md5, SHA-256 of the whole image)
#
# With SHELL.EFI (the UEFI Shell taken out of the firmware image by extract-shell.py) that file is put on the disk as Shell.efi, so that row U0
# can start the shell FROM iPXE out of this very disk (iPXE keeps its SAN devices only while it runs, so the shell must be its child). The file
# is a firmware build product: it is on the lab disk only, never in the repository.
#
# No root and no loop device: sfdisk (--no-reread --no-tell-kernel: it must not call sync(), which on a busy shared machine blocks for hours) writes the partition table into the file, mkfs.vfat --offset formats inside it, mtools (mcopy -i
# FILE@@OFFSET) fills it. Needs: python3, sfdisk, mkfs.vfat (dosfstools), mtools, md5sum, sha256sum.
set -euo pipefail
LC_ALL=C
export LC_ALL

die() { echo "build-bytes-image: $*" >&2; exit 2; }
[ $# -ge 1 ] && [ $# -le 2 ] || die "usage: build-bytes-image.sh OUTDIR [SHELL.EFI]"
out=$1
shell_efi=${2:-}
[ -z "$shell_efi" ] || [ -f "$shell_efi" ] || die "no such file: $shell_efi"
case $out in /*) ;; *) die "OUTDIR must be an absolute path";; esac
for t in python3 sfdisk mkfs.vfat mcopy mdir md5sum sha256sum truncate; do command -v "$t" >/dev/null 2>&1 || die "missing tool: $t"; done
mkdir -p "$out"
[ ! -e "$out/bytes.raw" ] || die "$out/bytes.raw exists (remove it yourself; this script deletes only its own scratch files)"

img=$out/bytes.raw
size_mib=192
part_start_sectors=2048                               # 1 MiB
total_sectors=$((size_mib * 2048))
part_sectors=$((total_sectors - part_start_sectors - 2048))    # leave 1 MiB for the backup GPT
truncate -s "${size_mib}M" "$img"
printf 'label: gpt\n%s\n' "start=$part_start_sectors, size=$part_sectors, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name=wrbytes" | sfdisk --quiet --no-reread --no-tell-kernel "$img"
# mkfs.vfat takes the size in 1 KiB blocks; 1 KiB clusters keep the cluster count above 65525 (firmware FAT drivers
# decide FAT12/16/32 by that count alone, so fewer clusters would be read as FAT16)
mkfs.vfat -F 32 -n WRBYTES -s 2 --offset "$part_start_sectors" "$img" $((part_sectors / 2)) >/dev/null

work=$(mktemp -d "$out/.files.XXXXXX")
# name:size. The sizes: around the 512-byte sector, the 4 KiB cluster, 64 KiB (one SAN command of the stock readahead), 1 MiB, and larger odd ones.
spec="
f-0001:1
f-0511:511
f-0512:512
f-0513:513
f-4095:4095
f-4096:4096
f-4097:4097
f-65535:65535
f-65536:65536
f-65537:65537
f-1m-1:1048575
f-1m:1048576
f-1m+1:1048577
f-3m:3000001
f-17m:17825793
f-33m:34603009
z-fill-80m:83886081
"
python3 -I - "$work" "$spec" <<'PY'
import random, sys
work, spec = sys.argv[1], sys.argv[2]
for line in spec.split():
    name, size = line.split(':')
    rnd = random.Random("winrbd-p2-bytes/" + name)        # the seed is the name: stable, different per file
    left, size = int(size), int(size)
    with open(work + "/" + name, "wb") as f:
        while left:
            n = min(left, 1 << 20)
            f.write(rnd.randbytes(n))
            left -= n
PY
: > "$out/bytes.manifest"
: > "$out/MD5SUMS"
if [ -n "$shell_efi" ]; then cp -- "$shell_efi" "$work/Shell.efi"; spec="$spec
Shell.efi:0
"; fi
for line in $spec; do
    n=${line%%:*}
    sz=$(stat -c %s "$work/$n")
    h=$(md5sum "$work/$n")
    h=${h%% *}
    printf '%s  %s\n' "$h" "$n" >> "$out/MD5SUMS"
    printf 'file %s %s %s\n' "$n" "$sz" "$h" >> "$out/bytes.manifest"
    # long names go through mtools' own name handling; every name here is a valid 8.3-free VFAT long name
    mcopy -i "$img@@1M" "$work/$n" "::/$n"
done
for line in $spec; do rm -f -- "$work/${line%%:*}"; done
rmdir "$work"
mdir -i "$img@@1M" :: >/dev/null
printf 'image_sha256=%s\n' "$(sha256sum "$img" | cut -d' ' -f1)" >> "$out/bytes.manifest"
echo "build-bytes-image: wrote $img ($size_mib MiB) with $(wc -l < "$out/MD5SUMS") files, list in $out/MD5SUMS"
