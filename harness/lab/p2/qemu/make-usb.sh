#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 QEMU scripts: build the boot media of rows U2, U3, B2 and B3 (a USB stick image, a CD image) around an iPXE binary and,
# optionally, the iPXE run script (autoexec.ipxe). No root, no loop device, no network: mtools, syslinux and xorriso on files.
#
#   make-usb.sh uefi-usb OUT --efi ipxe.efi            [--script S] [--size-mb N]
#       GPT, one EFI System partition (FAT) at 1 MiB with EFI/BOOT/BOOTX64.EFI and, with --script, autoexec.ipxe at the root
#       (iPXE reads it from the file system it was started from).      Row U2.
#   make-usb.sh bios-usb OUT --lkrn ipxe.lkrn          [--script S] [--method hybrid|syslinux] [--size-mb N]
#       A stick the BIOS boots: isolinux starts ipxe.lkrn with the script as its initrd. iPXE does not look at the initrd's name: it
#       registers the initrd as an image and runs the first image it has. That is the script only because the kernel command line
#       (isolinux's BOOT_IMAGE=... and our initrd=...) is empty once iPXE has stripped those two words: any other word on the
#       APPEND line would become an image of its own, ahead of the script. Keep the APPEND line as it is.      Row B2.
#         hybrid (default)  an ISO 9660 image with an MBR in front (xorriso -isohybrid-mbr): the same bytes boot as a CD and as a
#                           disk (dd it to a stick). Needs no syslinux installer.
#         syslinux          MBR with the syslinux boot code, one active FAT partition at 1 MiB, syslinux installed in it. The
#                           installer ends with a global sync(), which on a shared machine with other heavy writers can stall for
#                           an hour or more (seen on the build box: 20+ minutes, uninterruptible): use it only on a quiet machine.
#   make-usb.sh iso OUT --lkrn ipxe.lkrn --efi ipxe.efi [--script S]
#       one El Torito CD: isolinux (BIOS, row B3) and an EFI System image (UEFI, row U3), both with the script.
#
#   --script S     the iPXE script to put on the medium (it may hold the cephx key: OUT is then as secret as S; both are mode 600)
#   --method M     bios-usb only: hybrid (default) or syslinux, see above
#   --size-mb N    size of the FAT partition of a USB image (default: the content plus 8 MiB, at least 16)
#
# Why not iPXE's own util/genfsimg (what "make bin/ipxe.usb" and "bin/ipxe.iso" use)? It makes the same kind of image, but it looks
# for the syslinux files only in system directories and needs root-free tools to be on the PATH; this script finds them under
# P2Q_TOOLS (default $P2Q_WORK/tools/usr, then the system) as well, checks the PE header of the EFI binary, builds GPT for the UEFI
# stick (genfsimg writes an MBR table there) and refuses to overwrite anything. A ready-made bin/ipxe.usb or bin/ipxe.iso (built
# with EMBED) can be used instead of this script through the run scripts' --media option.
#
# Files it needs: mformat mcopy mmd (mtools), python3, and for iso and bios-usb (hybrid) xorriso (or xorrisofs), isolinux.bin,
# ldlinux.c32 and isohdpfx.bin; for bios-usb --method syslinux: syslinux and mbr.bin. Every missing piece is named in the error.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

die() { echo "make-usb.sh: $*" >&2; exit 2; }

usage() { awk 'NR >= 3 && /^#/ { sub(/^# ?/, ""); print; next } NR >= 3 { exit }' "${BASH_SOURCE[0]}"; }

[ $# -ge 1 ] || { usage >&2; exit 2; }
case "$1" in -h|--help) usage; exit 0;; esac
kind=$1
shift
[ $# -ge 1 ] || die "give the output file after $kind"
out=$1
shift
efi="" lkrn="" script="" size_mb="" method=hybrid
while [ $# -gt 0 ]; do
    case "$1" in
        --efi) [ $# -ge 2 ] || die "--efi needs a file"; efi=$2; shift 2;;
        --lkrn) [ $# -ge 2 ] || die "--lkrn needs a file"; lkrn=$2; shift 2;;
        --script) [ $# -ge 2 ] || die "--script needs a file"; script=$2; shift 2;;
        --size-mb) [ $# -ge 2 ] || die "--size-mb needs a number"; size_mb=$2; shift 2;;
        --method) [ $# -ge 2 ] || die "--method needs hybrid or syslinux"; method=$2; shift 2;;
        *) die "unknown option $1 (see --help)";;
    esac
done

case "$kind" in uefi-usb|bios-usb|iso) ;; *) die "kind must be uefi-usb, bios-usb or iso (got '$kind')";; esac
case "$method" in hybrid|syslinux) ;; *) die "--method must be hybrid or syslinux";; esac
[ "$method" = hybrid ] || [ "$kind" = bios-usb ] || die "--method is for bios-usb"
case "$out" in
    */*) ;;
    *) out=./$out;;
esac
[ ! -e "$out" ] || die "$out exists: this script never overwrites (the run scripts give it a fresh name)"
[ -d "$(dirname "$out")" ] || die "no directory $(dirname "$out")"
case "$out" in *[[:space:],]*) die "no spaces or commas in the output path";; esac
if [ -n "$size_mb" ]; then
    [[ "$size_mb" =~ ^[0-9]{1,4}$ ]] || die "--size-mb must be a number"
    size_mb=$((10#$size_mb))
    [ "$size_mb" -ge 8 ] && [ "$size_mb" -le 2048 ] || die "--size-mb must be 8 to 2048"
fi
[ -z "$script" ] || [ -r "$script" ] || die "cannot read the script $script"
case "$kind" in
    uefi-usb) [ -n "$efi" ] || die "uefi-usb needs --efi"; [ -z "$lkrn" ] || die "uefi-usb takes no --lkrn";;
    bios-usb) [ -n "$lkrn" ] || die "bios-usb needs --lkrn"; [ -z "$efi" ] || die "bios-usb takes no --efi";;
    iso)      [ -n "$lkrn" ] && [ -n "$efi" ] || die "iso needs --lkrn and --efi";;
esac
[ -z "$efi" ] || [ -r "$efi" ] || die "cannot read $efi"
[ -z "$lkrn" ] || [ -r "$lkrn" ] || die "cannot read $lkrn"

# ---- tools -----------------------------------------------------------------------------------------------------------------
tools=${P2Q_TOOLS:-${P2Q_WORK:+$P2Q_WORK/tools/usr}}
if [ -n "$tools" ] && [ -d "$tools/bin" ]; then
    PATH=$tools/bin:$tools/sbin:$PATH
    # the libraries of an unpacked package (xorriso needs libisoburn and friends)
    LD_LIBRARY_PATH=$tools/lib/x86_64-linux-gnu:$tools/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
    export PATH LD_LIBRARY_PATH
    # mtools of an unpacked package finds its own configuration nowhere: it needs none, but it checks for one
    export MTOOLS_SKIP_CHECK=1
fi
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is not installed ($2)"; }
if [ "$kind" != bios-usb ] || [ "$method" = syslinux ]; then
    need mformat "package mtools"
    need mcopy "package mtools"
    need mmd "package mtools"
fi
need python3 "python3"
export MTOOLS_SKIP_CHECK=1

# Where a syslinux file lives: the tool prefix first, then the places genfsimg knows.
find_syslinux_file() {
    local f=$1 d
    for d in ${tools:+"$tools/lib/syslinux" "$tools/lib/syslinux/bios" "$tools/lib/syslinux/mbr" "$tools/lib/syslinux/modules/bios" \
              "$tools/lib/ISOLINUX" "$tools/share/syslinux"} \
             /usr/lib/syslinux /usr/lib/syslinux/bios /usr/lib/syslinux/mbr /usr/lib/syslinux/modules/bios /usr/lib/ISOLINUX \
             /usr/share/syslinux /usr/share/syslinux/bios /usr/share/syslinux/mbr /usr/share/syslinux/modules/bios; do
        if [ -r "$d/$f" ]; then printf '%s\n' "$d/$f"; return 0; fi
    done
    die "cannot find the syslinux file $f (packages syslinux-common and isolinux; P2Q_TOOLS=<prefix with lib/syslinux or lib/ISOLINUX>)"
}

# The machine field of the PE header of an EFI binary: refuse anything but x86-64 (the file name BOOTX64.EFI is a promise).
check_efi_x64() {
    python3 -I - "$1" <<'PY' || exit 2
import struct, sys
p = sys.argv[1]
d = open(p, "rb").read(4096)
if d[:2] != b"MZ" or len(d) < 0x40:
    sys.exit("make-usb.sh: %s is not a PE file (no MZ header)" % p)
off = struct.unpack_from("<I", d, 0x3c)[0]
if off + 6 > len(d) or d[off:off + 4] != b"PE\0\0":
    sys.exit("make-usb.sh: %s has no PE header" % p)
machine = struct.unpack_from("<H", d, off + 4)[0]
if machine != 0x8664:
    sys.exit("make-usb.sh: %s is not an x86-64 EFI binary (machine 0x%04x); the stick is for OVMF x86-64" % (p, machine))
PY
}

# The partition table, written by this script (sfdisk calls fsync, which on a busy shared disk can stall for many minutes, and it is
# one more dependency): "gpt" = protective MBR + primary and backup GPT with one EFI System partition; "mbr" = one active
# FAT32 (LBA) partition in the MBR, boot code untouched (bytes 0 to 439 stay as they are).
# args: KIND FILE FIRST_SECTOR SECTORS
write_table() {
    python3 -I - "$@" <<'PY'
import struct, sys, uuid, zlib
kind, path, first, count = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
with open(path, "r+b") as f:
    f.seek(0, 2)
    total = f.tell() // 512
    if first + count > total - (34 if kind == "gpt" else 0):
        sys.exit("make-usb.sh: the partition does not fit in the image")
    if kind == "mbr":
        # status, CHS (LBA addressing: the classic "use LBA" marker), type 0x0c, CHS, first LBA, sector count
        ent = struct.pack("<B3sB3sII", 0x80, b"\xfe\xff\xff", 0x0c, b"\xfe\xff\xff", first, count)
        f.seek(440)
        f.write(uuid.uuid4().bytes[:4] + b"\0\0")          # disk signature, reserved
        f.write(ent + b"\0" * 48 + b"\x55\xaa")
    else:
        pmbr = struct.pack("<B3sB3sII", 0, b"\x00\x02\x00", 0xee, b"\xff\xff\xff", 1, min(total - 1, 0xffffffff))
        f.seek(446)
        f.write(pmbr + b"\0" * 48 + b"\x55\xaa")
        esp = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").bytes_le
        ent = esp + uuid.uuid4().bytes_le + struct.pack("<QQQ", first, first + count - 1, 0) + "WRP2EFI".encode("utf-16-le").ljust(72, b"\0")
        table = ent + b"\0" * (128 * 128 - len(ent))
        tcrc = zlib.crc32(table) & 0xffffffff
        guid = uuid.uuid4().bytes_le
        def header(cur, bak, tlba):
            h = struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x00010000, 92, 0, 0, cur, bak, 34, total - 34, guid, tlba, 128, 128, tcrc)
            crc = zlib.crc32(h) & 0xffffffff
            h = h[:16] + struct.pack("<I", crc) + h[20:]
            return h + b"\0" * (512 - len(h))
        f.seek(512);  f.write(header(1, total - 1, 2))
        f.seek(1024); f.write(table)
        f.seek((total - 33) * 512); f.write(table)
        f.seek((total - 1) * 512);  f.write(header(total - 1, 1, total - 33))
PY
}

work=""
cleanup() { # fixed names, files first, then the directory: nothing is deleted through a variable path pattern
    [ -n "$work" ] && [ -d "$work" ] || return 0
    local f
    rm -f "$work/syslinux.cfg" "$work/xorriso.log"
    for f in isolinux.bin ldlinux.c32 ipxe.lkrn isolinux.cfg autoexec.ipxe esp.img; do rm -f "$work/iso/$f"; done
    rmdir "$work/iso" 2>/dev/null || true
    rmdir "$work" 2>/dev/null || true
}
partial=""
on_exit() {
    local s=$?
    cleanup
    # a half-written output is worse than none
    if [ "$s" -ne 0 ] && [ -n "$partial" ]; then rm -f "$partial"; fi
    exit "$s"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work=$(mktemp -d "$out.work.XXXXXX")
chmod 700 "$work"

file_size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }

# A FAT file system of at least $2 MiB in the file $1 ($3 = hidden sectors, 0 for none). mformat picks FAT12/16/32 by size.
make_fat() { # FILE MIB HIDDEN LABEL CREATE   (CREATE=1: FILE does not exist yet; a "file@@offset" is formatted in place)
    local f=$1 mib=$2 hidden=$3 label=$4 create=$5 c=()
    [ "$create" != 1 ] || c=(-C)
    mformat -i "$f" ${c[@]+"${c[@]}"} -T $((mib * 2048)) -H "$hidden" -v "$label" ::
}

# Total FAT size for the content (a few MiB of slack for the directories and cluster rounding).
fat_mib() { # bytes...
    local total=0 b
    for b in "$@"; do total=$((total + b)); done
    local mib=$(( (total + 1048575) / 1048576 + 8 ))
    [ "$mib" -ge 16 ] || mib=16
    printf '%d' "$mib"
}

script_size=0
[ -z "$script" ] || script_size=$(file_size "$script")

# The syslinux / isolinux configuration: start ipxe.lkrn at once; with a script, as its initrd.
write_isolinux_cfg() {
    echo "SAY iPXE (winrbd phase 2)"
    echo "PROMPT 0"
    echo "TIMEOUT 1"
    echo "DEFAULT ipxe"
    echo "LABEL ipxe"
    echo " KERNEL ipxe.lkrn"
    if [ -n "$script" ]; then echo " APPEND initrd=autoexec.ipxe"; fi
    return 0
}

# The isolinux tree (BIOS part of the CD and of the hybrid stick) in $work/iso.
stage_isolinux() {
    local isolinux ldlinux
    isolinux=$(find_syslinux_file isolinux.bin)
    ldlinux=$(find_syslinux_file ldlinux.c32)
    mkdir "$work/iso"
    cp "$isolinux" "$work/iso/isolinux.bin"
    cp "$ldlinux" "$work/iso/ldlinux.c32"
    cp "$lkrn" "$work/iso/ipxe.lkrn"
    write_isolinux_cfg > "$work/iso/isolinux.cfg"
    if [ -n "$script" ]; then cp "$script" "$work/iso/autoexec.ipxe"; fi
}

# write_iso OUT efi|hybrid: efi = BIOS isolinux + EFI System image (esp.img, El Torito alternative entry); hybrid = BIOS only, with
# the MBR of isohdpfx.bin in front so that the same bytes boot from a stick.
write_iso() {
    local o=$1 mode=$2 mk hdpfx
    if command -v xorriso >/dev/null 2>&1; then mk=(xorriso -as mkisofs); elif command -v xorrisofs >/dev/null 2>&1; then mk=(xorrisofs)
    else die "xorriso is not installed (package xorriso)"; fi
    local args=(-quiet -o "$o" -V WRP2 -J -R -l -b isolinux.bin -c boot.cat -no-emul-boot -boot-load-size 4 -boot-info-table)
    if [ "$mode" = efi ]; then
        args+=(-eltorito-alt-boot -e esp.img -no-emul-boot)
    else
        hdpfx=$(find_syslinux_file isohdpfx.bin)
        args+=(-isohybrid-mbr "$hdpfx")
    fi
    if ! "${mk[@]}" "${args[@]}" "$work/iso" > "$work/xorriso.log" 2>&1; then
        sed 's/^/    xorriso: /' "$work/xorriso.log" | tail -n 8 >&2
        die "xorriso could not write $o (its message is above)"
    fi
}

case "$kind" in
# ---------------------------------------------------------------------------------------------------------------------------
uefi-usb)
    check_efi_x64 "$efi"
    mib=${size_mb:-$(fat_mib "$(file_size "$efi")" "$script_size")}
    partial=$out
    # layout: 1 MiB gap, the partition, 1 MiB for the backup GPT
    sectors=$(( (mib + 2) * 2048 ))
    : > "$out"
    truncate -s $((sectors * 512)) "$out"
    write_table gpt "$out" 2048 $((mib * 2048))
    make_fat "$out@@1048576" "$mib" 2048 WRP2EFI 0
    mmd -i "$out@@1048576" ::/EFI ::/EFI/BOOT
    mcopy -i "$out@@1048576" "$efi" ::/EFI/BOOT/BOOTX64.EFI
    if [ -n "$script" ]; then mcopy -i "$out@@1048576" "$script" ::/autoexec.ipxe; fi
    ;;
# ---------------------------------------------------------------------------------------------------------------------------
bios-usb)
  if [ "$method" = syslinux ]; then
    need syslinux "package syslinux"
    mbr=$(find_syslinux_file mbr.bin)
    ldlinux=$(find_syslinux_file ldlinux.c32)
    mib=${size_mb:-$(fat_mib "$(file_size "$lkrn")" "$script_size")}
    partial=$out
    sectors=$(( (mib + 1) * 2048 ))
    : > "$out"
    truncate -s $((sectors * 512)) "$out"
    write_table mbr "$out" 2048 $((mib * 2048))
    # the boot code goes into the first 440 bytes only: the partition table stays
    dd if="$mbr" of="$out" bs=440 count=1 conv=notrunc status=none
    make_fat "$out@@1048576" "$mib" 2048 WRP2BIOS 0
    write_isolinux_cfg > "$work/syslinux.cfg"
    mcopy -i "$out@@1048576" "$lkrn" ::/ipxe.lkrn
    mcopy -i "$out@@1048576" "$ldlinux" ::/ldlinux.c32
    mcopy -i "$out@@1048576" "$work/syslinux.cfg" ::/syslinux.cfg
    if [ -n "$script" ]; then mcopy -i "$out@@1048576" "$script" ::/autoexec.ipxe; fi
    # the boot sector and ldlinux.sys of the partition at 1 MiB (ends in sync(): see the header)
    syslinux --offset 1048576 --install "$out" || die "syslinux could not be installed into $out"
  else
    partial=$out
    stage_isolinux
    write_iso "$out" hybrid
  fi
    ;;
# ---------------------------------------------------------------------------------------------------------------------------
iso)
    check_efi_x64 "$efi"
    partial=$out
    stage_isolinux
    # the EFI System image the second El Torito entry boots (an EFI binary on a FAT image; script at its root)
    mib=$(fat_mib "$(file_size "$efi")" "$script_size")
    make_fat "$work/iso/esp.img" "$mib" 0 WRP2ESP 1
    mmd -i "$work/iso/esp.img" ::/EFI ::/EFI/BOOT
    mcopy -i "$work/iso/esp.img" "$efi" ::/EFI/BOOT/BOOTX64.EFI
    if [ -n "$script" ]; then mcopy -i "$work/iso/esp.img" "$script" ::/autoexec.ipxe; fi
    write_iso "$out" efi
    ;;
esac
chmod 600 "$out"
partial=""
echo "make-usb.sh: wrote $out ($kind, $(file_size "$out") bytes)" >&2
