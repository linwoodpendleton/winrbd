#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 WinPE rows (W1 to W4): check the layout of a WinPE / Windows setup boot image BEFORE a run, and fail loudly
# when it is not what the rows need. Read-only: it never writes to the image, never needs root, and reads the file
# system with mtools (no mount).
#
#   check-layout.sh --layout uefi|bios [--max-size 2G] [--strict] [--quiet] IMAGE
#
#   --layout   uefi: GPT with a FAT32 EFI system partition (rows W1, W2).  bios: MBR with an active FAT32 partition
#              (rows W3, W4).  There is no automatic detection: the check must not pass an image for the wrong row.
#   --max-size the largest image accepted (K, M, G suffixes; default 2G, the size rule of the lab images)
#   --strict   a warning is a failure too
#   --quiet    print only warnings and failures
#   IMAGE      a raw disk image (file or block device). A fixed VHD (a raw disk followed by a 512-byte "conectix"
#              footer, what Windows' own disk tools write) is accepted: the footer is not part of the disk.
#
# Every line of output is `PASS`, `WARN` or `FAIL`, then a check id, then what was found and, for a failure, what to
# do about it. The last line is `RESULT: PASS` or `RESULT: FAIL (n failed, m warnings)`.
# Exit status: 0 = every check passed, 1 = at least one check failed, 2 = bad usage or a missing tool.
#
# What is checked (layout-uefi.md and layout-bios.md say why):
#   both:  image size (a multiple of 512, at least 64 MiB, at most --max-size); the partition table; the FAT32 boot
#          sector of the boot partition (512-byte sectors, and FAT32 by the cluster count, which is what firmware uses);
#          that mtools can read the file system; the files below; and that every \path.wim / \path.sdi that the BCD
#          names is really in the image.
#   uefi:  protective MBR, GPT header at the start and the BACKUP header in the last sector of the disk, an EFI system
#          partition (type GUID C12A7328-...), \EFI\BOOT\bootx64.efi (a PE32+ x86-64 EFI application),
#          \EFI\Microsoft\Boot\BCD, \sources\boot.wim, \boot\boot.sdi.
#   bios:  an MBR (not GPT) with exactly one active partition of type 0B or 0C, boot code in the MBR, the NT boot sector
#          in the partition (not the stub that mkfs.fat writes), the hidden-sector count equal to the partition start,
#          \bootmgr, \boot\BCD, \sources\boot.wim, \boot\boot.sdi; the NT 6 boot record's second part in sector 12.
# Needs: bash, od, dd, tr, grep, sed, awk, sort, stat (or blockdev), sfdisk (util-linux) and mtools (mdir, mcopy). sgdisk
# is used when present (it verifies the GPT CRCs).
set -euo pipefail
export LC_ALL=C
# mtools refuses an image that has no mtools.conf entry unless told not to; every call below names the offset itself.
export MTOOLS_SKIP_CHECK=1

die() { echo "error: $*" >&2; exit 2; }

usage() { sed -n '4,34p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

layout="" max_size_arg=2G strict=0 quiet=0 img=""
while [ $# -gt 0 ]; do
    case "$1" in
        --layout) layout=${2:?--layout needs uefi or bios}; shift 2;;
        --max-size) max_size_arg=${2:?--max-size needs a value}; shift 2;;
        --strict) strict=1; shift;;
        --quiet) quiet=1; shift;;
        -h|--help) usage;;
        -*) die "unknown option $1 (try --help)";;
        *) [ -z "$img" ] || die "one image only"; img=$1; shift;;
    esac
done
case "$layout" in uefi|bios) ;; *) die "--layout uefi or --layout bios is required";; esac
[ -n "$img" ] || die "no image given"
[ -e "$img" ] || die "$img does not exist"
[ -r "$img" ] || die "$img is not readable"

to_bytes() { # 512M | 2G | 1024 -> bytes (at most 1 TiB: a larger number would wrap around in 64-bit arithmetic and pass the limit)
    local s=$1 n mult=1
    [[ "$s" =~ ^([0-9]{1,15})([KMG]?)$ ]] || die "bad size '$s': use e.g. 512M or 2G"
    n=$((10#${BASH_REMATCH[1]}))
    case "${BASH_REMATCH[2]}" in K) mult=1024;; M) mult=1048576;; G) mult=1073741824;; *) ;; esac
    [ "$n" -le $((1099511627776 / mult)) ] || die "size '$s' is out of range (at most 1T)"
    printf '%s' "$((n * mult))"
}
max_size=$(to_bytes "$max_size_arg")

for t in od dd tr grep sed awk sort sfdisk mdir mcopy; do
    command -v "$t" >/dev/null 2>&1 || die "missing tool: $t (sfdisk is in util-linux; mdir and mcopy are in the package mtools)"
done

# ---------------------------------------------------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------------------------------------------------
nfail=0 nwarn=0
pass() { [ "$quiet" = 1 ] || printf 'PASS %-18s %s\n' "$1" "$2"; }
warn() { nwarn=$((nwarn + 1)); printf 'WARN %-18s %s\n' "$1" "$2"; }
fail() { nfail=$((nfail + 1)); printf 'FAIL %-18s %s\n' "$1" "$2"; }
finish() {
    local bad=$nfail
    [ "$strict" = 1 ] && bad=$((nfail + nwarn))
    if [ "$bad" -eq 0 ]; then
        echo "RESULT: PASS ($nwarn warnings)"
        exit 0
    fi
    echo "RESULT: FAIL ($nfail failed, $nwarn warnings)"
    exit 1
}

# ---------------------------------------------------------------------------------------------------------------------
# byte access (no mount, no root). Offsets are bytes from the start of FILE.
# ---------------------------------------------------------------------------------------------------------------------
hex_at() { # FILE OFFSET COUNT -> lower-case hex, no spaces
    od -An -v -tx1 -j "$2" -N "$3" "$1" 2>/dev/null | tr -d ' \n'
}
le_hex() { # little-endian hex string -> decimal
    local h=$1 out="" i
    for ((i = ${#h} - 2; i >= 0; i -= 2)); do out+=${h:i:2}; done
    printf '%s' "$((16#${out:-0}))"
}
u8()  { le_hex "$(hex_at "$1" "$2" 1)"; }
u16() { le_hex "$(hex_at "$1" "$2" 2)"; }
u32() { le_hex "$(hex_at "$1" "$2" 4)"; }
ascii_at() { # FILE OFFSET COUNT -> the bytes as text, NULs dropped
    dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | tr -d '\0'
}
all_zero() { # HEX
    [[ "$1" =~ ^0*$ ]]
}

file_size() { # FILE or block device -> bytes
    if [ -b "$1" ]; then
        blockdev --getsize64 "$1"
    elif stat -c %s "$1" >/dev/null 2>&1; then
        stat -c %s "$1"
    else
        stat -f %z "$1"
    fi
}

# ---------------------------------------------------------------------------------------------------------------------
# the image as a disk
# ---------------------------------------------------------------------------------------------------------------------
raw_size=$(file_size "$img")
disk_size=$raw_size
if [ "$raw_size" -ge 1048576 ] && [ "$(hex_at "$img" $((raw_size - 512)) 8)" = 636f6e6563746978 ]; then
    # "conectix": a VHD footer. Disk type 2 = fixed: the data is the raw disk and the footer follows it.
    if [ "$(hex_at "$img" $((raw_size - 512 + 60)) 4)" = 00000002 ]; then
        disk_size=$((raw_size - 512))
        pass vhd "fixed VHD: the trailing 512-byte footer is not part of the disk (import-winpe.sh convert strips it)"
    else
        fail vhd "this is a dynamic or differencing VHD, not a raw disk; convert it first: import-winpe.sh convert --disk IMAGE --out RAW"
        finish
    fi
fi

if [ $((disk_size % 512)) -ne 0 ]; then
    fail size "the disk size $disk_size is not a multiple of 512 bytes; the SAN device has 512-byte blocks"
    finish
fi
if [ "$disk_size" -lt 67108864 ]; then
    fail size "the disk is only $disk_size bytes; a boot image with boot.wim is at least 64 MiB"
elif [ "$disk_size" -gt "$max_size" ]; then
    fail size "the disk is $disk_size bytes, over the limit of $max_size ($max_size_arg); the lab images are at most 2 GiB: use a smaller image (import-winpe.sh build --size) or raise --max-size on purpose"
else
    pass size "$disk_size bytes ($((disk_size / 1048576)) MiB), limit $max_size_arg"
fi
total_sectors=$((disk_size / 512))

# the boot signature of the first sector (both layouts: the MBR or the protective MBR)
if [ "$(hex_at "$img" 510 2)" = 55aa ]; then
    pass boot-signature "0x55AA at offset 510 of sector 0"
else
    fail boot-signature "sector 0 has no 0x55AA signature: this is not a partitioned disk image (is it a partition image, or a file system image without a partition table?)"
    finish
fi

# ---------------------------------------------------------------------------------------------------------------------
# the partition table (sfdisk -d: one line per partition)
# ---------------------------------------------------------------------------------------------------------------------
tmp=$(mktemp -d "${TMPDIR:-/tmp}/winpe-check.XXXXXX")
trap 'rm -f -- "$tmp"/*; rmdir -- "$tmp"' EXIT

sf_status=0
sfdisk -d "$img" >"$tmp/pt" 2>"$tmp/pt.err" || sf_status=$?
label=$(sed -n 's/^label: *//p' "$tmp/pt" | head -n 1)
if [ "$sf_status" -ne 0 ] || [ -z "$label" ]; then
    fail partition-table "sfdisk cannot read a partition table from the image: $(tr '\n' ' ' <"$tmp/pt.err")"
    finish
fi
label_id=$(sed -n 's/^label-id: *//p' "$tmp/pt" | head -n 1)

pstart=() psize=() ptype=() pboot=()
while IFS= read -r line; do
    case "$line" in *"start="*) ;; *) continue;; esac
    s=$(sed -n 's/.*start= *\([0-9][0-9]*\),.*/\1/p' <<<"$line")
    z=$(sed -n 's/.*size= *\([0-9][0-9]*\),.*/\1/p' <<<"$line")
    t=$(sed -n 's/.*type=\([^,]*\).*/\1/p' <<<"$line")
    b=0
    case "$line" in *bootable*) b=1;; esac
    [ -n "$s" ] && [ -n "$z" ] || continue
    pstart+=("$s"); psize+=("$z"); ptype+=("$t"); pboot+=("$b")
done <"$tmp/pt"
nparts=${#pstart[@]}
if [ "$nparts" -eq 0 ]; then
    fail partition-table "the partition table is empty (label $label)"
    finish
fi

# the partition that holds the boot files
boot_idx=-1

check_gpt() {
    if [ "$label" != gpt ]; then
        fail partition-table "the image has a '$label' partition table, the UEFI rows need GPT: repartition (sgdisk) or import the GPT variant of the media"
        finish
    fi
    pass partition-table "GPT, $nparts partition(s), disk GUID $label_id"
    if all_zero "$(printf '%s' "$label_id" | tr -d '-')" || [ -z "$label_id" ]; then
        warn disk-guid "the disk GUID is zero; Windows names the disk by it: give it a random one (sgdisk -G)"
    fi
    # protective MBR: the first partition entry has type 0xEE
    if [ "$(hex_at "$img" 450 1)" = ee ]; then
        pass protective-mbr "protective MBR entry (type 0xEE)"
    else
        fail protective-mbr "sector 0 has no protective MBR entry (type 0xEE at offset 450); a GPT without it is refused by some firmware: sgdisk -g would rewrite it"
    fi
    # the primary header at LBA 1 and the BACKUP header in the last sector
    if [ "$(ascii_at "$img" 512 8)" = "EFI PART" ]; then
        pass gpt-primary "GPT header at LBA 1"
    else
        fail gpt-primary "no 'EFI PART' signature at LBA 1"
    fi
    if [ "$(ascii_at "$img" $((disk_size - 512)) 8)" = "EFI PART" ]; then
        pass gpt-backup "backup GPT header in the last sector of the disk (LBA $((total_sectors - 1)))"
    else
        fail gpt-backup "no backup GPT header in the last sector: the image is larger or smaller than the disk the table was made for (a firmware or Linux will warn and may refuse); fix with: sgdisk -e IMAGE"
    fi
    if command -v sgdisk >/dev/null 2>&1; then
        local sgv
        sgv=$(sgdisk -v "$img" 2>&1 || true) # captured, not piped into grep -q (an early close of the pipe fails the pipeline under pipefail)
        if grep -q 'No problems found' <<<"$sgv"; then
            pass gpt-verify "sgdisk -v: no problems found (header and table CRCs are good)"
        elif [ "$disk_size" -ne "$raw_size" ]; then
            warn gpt-verify "sgdisk -v skipped: the file has a VHD footer, so the end of the disk is not the end of the file"
        else
            fail gpt-verify "sgdisk -v reports problems: $(tr '\n' ' ' <<<"$sgv")"
        fi
    else
        warn gpt-verify "sgdisk is not installed: the GPT CRCs were not verified (sfdisk read the table, which already needs a good header)"
    fi
    local i esp="c12a7328-f81f-11d2-ba4b-00a0c93ec93b" found=0
    for ((i = 0; i < nparts; i++)); do
        if [ "$(tr 'A-F' 'a-f' <<<"${ptype[$i]}")" = "$esp" ]; then
            found=$((found + 1))
            [ "$boot_idx" -ge 0 ] || boot_idx=$i
        fi
    done
    if [ "$found" -eq 0 ]; then
        fail esp "no EFI system partition (type GUID C12A7328-F81F-11D2-BA4B-00A0C93EC93B) in the table: the firmware will not look for \\EFI\\BOOT\\bootx64.efi; set the type (sgdisk -t N:EF00)"
        finish
    fi
    pass esp "EFI system partition: number $((boot_idx + 1)), start sector ${pstart[$boot_idx]}, ${psize[$boot_idx]} sectors"
    [ "$found" -eq 1 ] || warn esp "$found EFI system partitions; the first one is checked, and firmware may pick another"
}

check_mbr() {
    if [ "$label" != dos ]; then
        fail partition-table "the image has a '$label' partition table, the BIOS rows need an MBR (dos): that is the layout the Windows media use for legacy boot, and the protective MBR of a GPT disk has no active partition"
        finish
    fi
    pass partition-table "MBR, $nparts partition(s), disk signature $label_id"
    case "$label_id" in 0x00000000|0x0|"") warn disk-signature "the MBR disk signature is zero; Windows names the disk by it: give it a random one (sfdisk --disk-id)";; *) ;; esac
    local i active=0 bad_type=""
    for ((i = 0; i < nparts; i++)); do
        if [ "${ptype[$i]}" = ee ]; then
            fail partition-table "partition $((i + 1)) is a GPT protective entry (type EE): this is a GPT disk, not an MBR disk"
        fi
        if [ "${pboot[$i]}" = 1 ]; then
            active=$((active + 1))
            boot_idx=$i
        fi
    done
    if [ "$active" -ne 1 ]; then
        fail active-flag "$active active (0x80) partitions; exactly one is needed, or the BIOS boot code finds none (or the wrong one): sfdisk --activate IMAGE N"
        finish
    fi
    pass active-flag "partition $((boot_idx + 1)) is the only active partition"
    case "${ptype[$boot_idx]}" in
        b|c|0b|0c) pass partition-type "type ${ptype[$boot_idx]} (FAT32)";;
        *) bad_type=${ptype[$boot_idx]}
           fail partition-type "the active partition has type '$bad_type', not 0B or 0C (FAT32): set it (sfdisk --part-type IMAGE $((boot_idx + 1)) c)";;
    esac
    # MBR boot code: the first 440 bytes
    local code
    code=$(hex_at "$img" 0 440)
    if all_zero "$code"; then
        fail mbr-code "the MBR has no boot code (440 zero bytes): SeaBIOS would jump into zeros. Write the Windows MBR: ms-sys --mbr7 IMAGE, or bootsect /nt60 X: /mbr on Windows"
    elif dd if="$img" bs=440 count=1 2>/dev/null | grep -aq 'Invalid partition table'; then
        pass mbr-code "boot code present, the 'Invalid partition table' messages of the Windows 7 and later MBR are there"
    else
        warn mbr-code "boot code present but it is not recognised as the Windows MBR (no 'Invalid partition table'): fine if it loads the boot sector of the active partition, which this script cannot know"
    fi
}

case "$layout" in uefi) check_gpt;; bios) check_mbr;; *) ;; esac

# the boot partition must lie inside the disk (the GPT backup occupies the last 33 sectors)
start=${pstart[$boot_idx]} size=${psize[$boot_idx]}
limit=$total_sectors
[ "$layout" = uefi ] && limit=$((total_sectors - 33))
if [ $((start + size)) -gt "$limit" ] || [ "$start" -lt 1 ] || [ "$size" -lt 1 ]; then
    fail partition-bounds "the boot partition (start $start, $size sectors) does not lie inside the disk ($total_sectors sectors): the table does not match the image size"
    finish
fi
pass partition-bounds "start $start, $size sectors ($((size / 2048)) MiB)"
poff=$((start * 512))

# ---------------------------------------------------------------------------------------------------------------------
# the FAT32 boot sector (BPB)
# ---------------------------------------------------------------------------------------------------------------------
oem=$(ascii_at "$img" $((poff + 3)) 8)
case "$oem" in
    "NTFS    ") fail fat32 "the boot partition is NTFS; firmware reads only FAT: format it FAT32 (the Windows boot media are FAT32)"; finish;;
    "EXFAT   ") fail fat32 "the boot partition is exFAT; firmware reads only FAT: format it FAT32"; finish;;
    *) ;;
esac
bps=$(u16 "$img" $((poff + 11)))
spc=$(u8 "$img" $((poff + 13)))
rsv=$(u16 "$img" $((poff + 14)))
nfat=$(u8 "$img" $((poff + 16)))
rootent=$(u16 "$img" $((poff + 17)))
tot16=$(u16 "$img" $((poff + 19)))
fat16=$(u16 "$img" $((poff + 22)))
hidden=$(u32 "$img" $((poff + 28)))
tot32=$(u32 "$img" $((poff + 32)))
fat32sz=$(u32 "$img" $((poff + 36)))
rootcl=$(u32 "$img" $((poff + 44)))
sig=$(hex_at "$img" $((poff + 510)) 2)
fstype=$(ascii_at "$img" $((poff + 82)) 8)
fatok=1
if [ "$sig" != 55aa ]; then
    fail fat32 "the boot sector of the partition has no 0x55AA signature at offset 510: nothing is formatted there (an empty or unformatted partition?)"
    fatok=0
fi
if [ "$fatok" = 1 ] && [ "$bps" -ne 512 ]; then
    fail fat32 "the file system has $bps bytes per sector; the SAN device has 512-byte blocks, firmware will not mount it: format it with mkfs.fat -S 512"
    fatok=0
fi
if [ "$fatok" = 1 ] && { [ "$rootent" -ne 0 ] || [ "$tot16" -ne 0 ] || [ "$fat16" -ne 0 ] || [ "$fat32sz" -eq 0 ] || [ "$spc" -eq 0 ] || [ $((spc & (spc - 1))) -ne 0 ] || [ "$rsv" -eq 0 ] || [ "$nfat" -eq 0 ] || [ "$rootcl" -lt 2 ]; }; then
    fail fat32 "the boot sector is not a FAT32 one (root entries $rootent, FAT16 sectors $fat16, FAT32 sectors $fat32sz, sectors/cluster $spc, root cluster $rootcl): format the partition FAT32 (mkfs.fat -F 32)"
    fatok=0
fi
if [ "$fatok" = 1 ]; then
    if [ "$tot32" -gt "$size" ]; then
        fail fat32 "the file system claims $tot32 sectors but the partition has only $size: the image was cut short or the table was changed after formatting"
        fatok=0
    else
        clusters=$(((tot32 - rsv - nfat * fat32sz) / spc))
        if [ "$clusters" -lt 65525 ]; then
            fail fat32 "only $clusters clusters: by the cluster count this is FAT16 or FAT12, and firmware decides the type by that count, not by the label. Use smaller clusters (mkfs.fat -s) or a larger partition"
            fatok=0
        else
            pass fat32 "FAT32: $bps-byte sectors, $spc sectors per cluster, $clusters clusters, $nfat FATs, boot sector label '${fstype%% *}'"
        fi
    fi
fi
[ "$fatok" = 1 ] || finish
[ "$fstype" = "FAT32   " ] || warn fat32-label "the informational file system type string at offset 82 is '$fstype', not 'FAT32   ' (harmless for firmware, odd for Windows tools)"

if [ "$layout" = bios ]; then
    # hidden sectors: the NT boot sector reads bootmgr relative to this number
    if [ "$hidden" -eq "$start" ]; then
        pass hidden-sectors "hidden sectors $hidden = partition start"
    else
        fail hidden-sectors "the boot sector says $hidden hidden sectors but the partition starts at sector $start: the NT boot sector would read bootmgr from the wrong place. Rewrite the BPB: mkfs.fat -h $start, or ms-sys -p"
    fi
    # the boot code: the sector, three sectors for FAT32
    pbr=$(dd if="$img" bs=512 skip="$start" count=3 2>/dev/null | tr -d '\0')
    if all_zero "$(hex_at "$img" $((poff + 90)) 420)"; then
        fail boot-sector "the boot sector of the partition has no boot code: write the NT boot sector (ms-sys --fat32pe, or bootsect /nt60 X: on Windows)"
    elif grep -aq 'This is not a bootable disk' <<<"$pbr"; then
        fail boot-sector "the boot sector is the stub mkfs.fat writes ('This is not a bootable disk'): it will never load bootmgr. Write the NT boot sector (ms-sys --fat32pe, or bootsect /nt60 X: on Windows)"
    elif grep -aq 'BOOTMGR' <<<"$pbr"; then
        pass boot-sector "boot code present and it names BOOTMGR"
    else
        warn boot-sector "boot code present but it does not name BOOTMGR in the first three sectors: not recognised as the NT 6 boot sector; the BIOS row will show whether it loads bootmgr"
    fi
    # The NT 6 FAT32 boot record keeps the rest of its code in sector 12 of the partition. An image whose sector 0 is right and
    # sector 12 is empty prints "Booting from Hard Disk..." and hangs (seen with SeaBIOS), which no other check would explain.
    if all_zero "$(hex_at "$img" $((poff + 12 * 512)) 512)"; then
        fail boot-sector-2 "sector 12 of the partition is empty: the NT 6 FAT32 boot record keeps the rest of its code there, and without it the machine hangs after 'Booting from Hard Disk...'. ms-sys --fat32pe and bootsect /nt60 write it (copy at least the first 16 sectors of the partition when you write the boot record to a scratch copy)"
    elif [ "$(hex_at "$img" $((poff + 12 * 512 + 510)) 2)" != 55aa ]; then
        fail boot-sector-2 "sector 12 of the partition has data but no 0x55AA signature: not the NT 6 boot record's second part"
    else
        pass boot-sector-2 "sector 12 of the partition holds the rest of the boot code"
    fi
fi

# ---------------------------------------------------------------------------------------------------------------------
# the files (mtools reads the file system inside the image at the partition's offset)
# ---------------------------------------------------------------------------------------------------------------------
spec="$img@@$poff"
if ! mdir -i "$spec" :: >/dev/null 2>"$tmp/mdir.err"; then
    fail files "mtools cannot read the file system: $(tr '\n' ' ' <"$tmp/mdir.err")"
    finish
fi

fat_size() { # PATH -> size in bytes of the one file, or fails (missing, or a directory)
    local out n
    out=$(mdir -i "$spec" "::$1" 2>/dev/null) || return 1
    case "$out" in *'<DIR>'*) return 1;; *) ;; esac
    n=$(grep -E ' [0-9]+ [0-9]{4}-[0-9]{2}-[0-9]{2} ' <<<"$out" | sed -n 's/.* \([0-9][0-9]*\) [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} .*/\1/p' || true)
    [ -n "$n" ] && [ "$(wc -l <<<"$n")" -eq 1 ] || return 1
    printf '%s' "$n"
}
fat_cat() { mcopy -n -i "$spec" "::$1" - 2>/dev/null; }
fat_head() { # PATH N -> the first N bytes, as a file on stdout
    { fat_cat "$1" || true; } | head -c "$2" || true # head closes the pipe early: SIGPIPE is expected
}
head_hex() { # PATH N -> hex of the first N bytes
    fat_head "$1" "$2" | od -An -v -tx1 | tr -d ' \n'
}

# NAME PATH MINSIZE MAGIC_HEX HINT: present, big enough, and starts with the magic. Always returns 0; need_ok says whether it passed.
need_ok=0
need_file() {
    local name=$1 path=$2 min=$3 magic=$4 hint=$5 size got
    need_ok=0
    if ! size=$(fat_size "$path"); then
        fail "$name" "\\${path//\//\\} is missing from the image. $hint"
        return 0
    fi
    if [ "$size" -lt "$min" ]; then
        fail "$name" "\\${path//\//\\} is only $size bytes (at least $min expected): truncated or a placeholder. $hint"
        return 0
    fi
    if [ -n "$magic" ]; then
        got=$(head_hex "$path" $((${#magic} / 2)))
        if [ "$got" != "$magic" ]; then
            fail "$name" "\\${path//\//\\} does not start with the expected bytes ($magic, found ${got:-nothing}): wrong kind of file. $hint"
            return 0
        fi
    fi
    pass "$name" "\\${path//\//\\} present, $size bytes"
    need_ok=1
    return 0
}

check_pe_x64_efi() { # PATH: MZ, PE00, machine x86-64, PE32+, subsystem EFI application
    local path=$1 h lfa machine magic subsys
    h=$tmp/pe.head
    fat_head "$path" 4096 >"$h"
    lfa=$(u32 "$h" 60)
    if [ "$(ascii_at "$h" 0 2)" != MZ ] || [ "$lfa" -lt 64 ] || [ "$lfa" -gt 3968 ] || [ "$(hex_at "$h" "$lfa" 4)" != 50450000 ]; then
        fail efi-binary "\\${path//\//\\} is not a PE file (no MZ / PE header): the firmware would not load it. Take it from the media's EFI\\BOOT directory"
        return
    fi
    machine=$(u16 "$h" $((lfa + 4)))
    magic=$(u16 "$h" $((lfa + 24)))
    subsys=$(u16 "$h" $((lfa + 24 + 68)))
    if [ "$machine" -ne $((0x8664)) ]; then
        fail efi-binary "\\${path//\//\\} is for machine $(printf '0x%04x' "$machine"), not x86-64 (0x8664): OVMF in these rows is x86-64"
    elif [ "$magic" -ne $((0x20b)) ] || [ "$subsys" -ne 10 ]; then
        fail efi-binary "\\${path//\//\\} is a PE file for x86-64 but not an EFI application (optional-header magic $(printf '0x%x' "$magic"), subsystem $subsys; wanted 0x20b and 10)"
    else
        pass efi-binary "\\${path//\//\\} is a PE32+ x86-64 EFI application"
    fi
}

# the files that the BCD names must exist: \sources\boot.wim and \boot\boot.sdi in every Windows boot media
check_bcd_references() { # PATH of the BCD
    local bcd=$1 refs ref p
    refs=$(fat_cat "$bcd" | tr -d '\0' | grep -a -o -i '\\[A-Za-z0-9_. \\-]*\.\(wim\|sdi\)' | sort -u || true)
    if [ -z "$refs" ]; then
        warn bcd-references "no .wim or .sdi path found in \\${bcd//\//\\} (an unusual BCD?): the check that it points at files that exist could not be made"
        return
    fi
    while IFS= read -r ref; do
        p=${ref//\\//}
        p=${p#/}
        if fat_size "$p" >/dev/null; then
            pass bcd-references "the BCD names $ref and it is in the image"
        else
            fail bcd-references "the BCD names $ref but the image has no such file: the boot manager would stop with 0xc000000f (or similar). Copy it from the media"
        fi
    done <<<"$refs"
    return 0
}

if [ "$layout" = uefi ]; then
    need_file efi-binary-file EFI/BOOT/bootx64.efi 65536 4d5a "Copy EFI\\BOOT\\bootx64.efi (the Windows boot manager) from the media."
    [ "$need_ok" = 0 ] || check_pe_x64_efi EFI/BOOT/bootx64.efi
    bcd=EFI/Microsoft/Boot/BCD
    need_file bcd "$bcd" 4096 72656766 "Copy EFI\\Microsoft\\Boot\\BCD from the media."
    [ "$need_ok" = 0 ] || check_bcd_references "$bcd"
else
    need_file bootmgr bootmgr 16384 "" "Copy bootmgr (no extension) from the media root."
    bcd=boot/BCD
    need_file bcd "$bcd" 4096 72656766 "Copy boot\\BCD from the media."
    [ "$need_ok" = 0 ] || check_bcd_references "$bcd"
fi
need_file boot-wim sources/boot.wim 1048576 4d5357494d000000 "Copy sources\\boot.wim (the WinPE image) from the media; install.wim / install.esd are not needed."
need_file boot-sdi boot/boot.sdi 65536 2453444930303031 "Copy boot\\boot.sdi from the media: the BCD loads boot.wim as a RAM disk with it."

finish
