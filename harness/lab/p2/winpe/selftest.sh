#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Self-test of the WinPE preparation scripts (check-layout.sh, import-winpe.sh). No VM, no QEMU, no network, no root, no Windows
# file of any kind: the "media" are synthetic files made here (right names, right magic numbers, no real content), the disk
# images are built from them with the scripts under test, and every file lives below one temporary directory that is removed
# at the end. The cluster is replaced by stand-ins (the VM, rbd, users.sh).
#
#   selftest.sh            run everything; exit 0 when every check passed, 1 on a failure, 77 when this machine lacks a tool
#                          (the build-and-check cases need sfdisk, sgdisk, mkfs.fat with --offset, mtools, python3, gzip)
#
# What it proves:
#   * a correct layout passes, for UEFI (GPT + ESP) and for BIOS (MBR + active partition + NT boot sector), from a directory and
#     from an ISO, with and without a fixed-VHD footer
#   * each of these fails with a message that says what is wrong and what to do: missing bootmgr, missing BCD, missing boot.wim or
#     boot.sdi, a BCD that names a file that is not there, a boot.wim of the wrong kind, an arm64 bootloader, an ESP that is not
#     FAT32 (FAT16, NTFS, empty), no active flag, wrong partition type, no boot code, the stub boot sector of mkfs.fat, a wrong
#     hidden-sector count, a missing backup GPT, an image that is too big, a disk that is not partitioned, the wrong layout
#   * import-winpe.sh: the layout check runs first and stops the import; the stream that reaches the VM is the image; a read-back
#     that differs is refused; a leftover image is not replaced without --replace; names and pools are validated; a dry run
#     changes nothing; the git guard refuses a path git would track
#   * no Windows file lives in this directory, the .gitignore here covers every kind of file the scripts handle, and the code
#     block in run-rows.md that scans a memory dump for the rBFT table finds a valid table and refuses broken ones
#   * the scripts are shellcheck clean (when shellcheck is installed)
# shellcheck disable=SC2329,SC2016,SC2015  # the cases are called through their names; the quotes are deliberate
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
check_sh=$here/check-layout.sh
import_sh=$here/import-winpe.sh

pass=0 fail=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n' "$1" >&2; }
contains() { case "$1" in *"$2"*) return 0;; *) return 1;; esac; }

need_tools() {
    local t miss=""
    for t in sfdisk sgdisk mkfs.fat mdir mcopy mmd mdel truncate python3 gzip od dd git; do
        command -v "$t" >/dev/null 2>&1 || miss="$miss $t"
    done
    if [ -n "$miss" ]; then
        echo "skip: this machine lacks:$miss" >&2
        exit 77
    fi
    mkfs.fat --help 2>&1 | grep -q -- '--offset' || { echo "skip: mkfs.fat has no --offset (dosfstools 4.2 is needed)" >&2; exit 77; }
}

if [ "${1:-}" = "--case" ]; then
    tmp=${SELFTEST_TMP:?}
else
    need_tools
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-winpe-selftest.XXXXXX")
fi
case "$tmp" in /*/*) ;; *) echo "bad temporary directory $tmp" >&2; exit 2;; esac
cleanup() { # fixed layout, files only, then the directories (never a recursive delete of a variable)
    find "$tmp" \( -type f -o -type l \) -delete 2>/dev/null || true
    find "$tmp" -depth -type d -exec rmdir {} + 2>/dev/null || true
}
[ "${1:-}" = "--case" ] || trap cleanup EXIT
export SELFTEST_TMP=$tmp
export MTOOLS_SKIP_CHECK=1
export WINPE_WORK=$tmp/work

media=$tmp/media

# ---------------------------------------------------------------------------------------------------------------------
# the synthetic media: names and magic numbers of a boot media, no real content
# ---------------------------------------------------------------------------------------------------------------------
make_media() {
    [ -d "$media" ] && return 0
    mkdir -p "$tmp/gen"
    cat > "$tmp/gen/media.py" <<'EOF'
import os, struct, sys
root = sys.argv[1]
def w(rel, data):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'wb').write(data)
def filler(n, seed):
    return bytes((seed + i * 7) & 0xff for i in range(n))
def pe(machine):
    d = bytearray(filler(70000, 3))
    d[0:2] = b'MZ'
    struct.pack_into('<I', d, 60, 0x80)
    d[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', d, 0x84, machine)
    struct.pack_into('<H', d, 0x80 + 24, 0x20b)
    struct.pack_into('<H', d, 0x80 + 24 + 68, 10)
    return bytes(d)
def bcd(refs):
    d = bytearray(16384)
    d[0:4] = b'regf'
    off = 512
    for r in refs:
        d[off:off + 4 + 2 * len(r)] = b'\x2a\x00\x00\x00' + r.encode('utf-16le')
        off += 256
    return bytes(d)
good = ['\\sources\\boot.wim', '\\boot\\boot.sdi']
w('bootmgr', filler(40000, 1))
w('bootmgr.efi', filler(90000, 2))
w('boot/BCD', bcd(good))
w('boot/boot.sdi', b'$SDI0001' + filler(150000, 5))
w('boot/fonts/wgl4_boot.ttf', filler(20000, 9))
w('boot/en-us/bootmgr.exe.mui', filler(5000, 11))
w('efi/boot/bootx64.efi', pe(0x8664))
w('efi/microsoft/boot/BCD', bcd(good))
w('sources/boot.wim', b'MSWIM\0\0\0' + filler(3 * 1048576, 13))
w('sources/install.wim', b'MSWIM\0\0\0' + filler(1048576, 17))   # must NOT end up in the image
w('en-us/bootmgr.efi.mui', filler(3000, 19))
w('support/readme.txt', b'not needed')
open(os.path.join(root, 'pe-arm64.efi'), 'wb').write(pe(0xaa64))
open(os.path.join(root, 'bcd-orphan'), 'wb').write(bcd(['\\sources\\boot.wim', '\\boot\\gone.sdi']))
EOF
    mkdir -p "$media"
    python3 -I "$tmp/gen/media.py" "$media"
}

# a stand-in for ms-sys: same option names, and it writes what the check looks for (the strings of the Windows MBR and of the
# NT 6 FAT32 boot sector), so that the plumbing of build is tested. It is NOT the real ms-sys and proves nothing about real boot code.
make_stub_mssys() {
    mkdir -p "$tmp/stubs"
    cat > "$tmp/stubs/ms-sys" <<'EOS'
#!/bin/sh
case "$1" in
    --help) echo "ms-sys stand-in"; echo "  -7, --mbr7      Write a Windows 7 master boot record"; echo "  -3, --fat32pe   Write a FAT32 boot record for WinPE"; exit 0;;
    --mbr7) printf '\372\061\300Invalid partition table\0Error loading operating system\0Missing operating system\0' | dd of="$2" bs=1 seek=0 conv=notrunc 2>/dev/null; exit 0;;
    --fat32pe) head -c 420 /dev/zero | dd of="$2" bs=1 seek=90 conv=notrunc 2>/dev/null
               printf 'BOOTMGR    \0Disk error\0' | dd of="$2" bs=1 seek=400 conv=notrunc 2>/dev/null
               head -c 420 /dev/zero | tr '\0' 'x' | dd of="$2" bs=1 seek=6144 conv=notrunc 2>/dev/null
               printf '\125\252' | dd of="$2" bs=1 seek=6654 conv=notrunc 2>/dev/null; exit 0;;
    *) echo "unknown option $1" >&2; exit 1;;
esac
EOS
    chmod +x "$tmp/stubs/ms-sys"
}

# part_of IMAGE -> "START SIZE" of partition 1, in sectors
part_of() { sfdisk -d "$1" 2>/dev/null | sed -n 's/.*start= *\([0-9][0-9]*\), *size= *\([0-9][0-9]*\),.*/\1 \2/p' | head -n 1; }
start_of() { part_of "$1" | cut -d' ' -f1; }
spec_of() { printf '%s@@%s' "$1" "$(($(start_of "$1") * 512))"; }

good_uefi() { # builds once: $tmp/uefi.img
    [ -f "$tmp/uefi.img" ] && return 0
    make_media
    "$import_sh" build --layout uefi --media "$media" --out "$tmp/uefi.img" >"$tmp/uefi.build" 2>&1 || { cat "$tmp/uefi.build"; return 1; }
}
good_bios() { # builds once: $tmp/bios.img (with the stand-in ms-sys)
    [ -f "$tmp/bios.img" ] && return 0
    make_media
    make_stub_mssys
    PATH=$tmp/stubs:$PATH "$import_sh" build --layout bios --media "$media" --out "$tmp/bios.img" >"$tmp/bios.build" 2>&1 || { cat "$tmp/bios.build"; return 1; }
}
copy_of() { cp "$1" "$tmp/$2"; printf '%s' "$tmp/$2"; }

# expect_fail LAYOUT IMAGE ID TEXT: check-layout.sh must exit 1 with a FAIL line for ID that contains TEXT
expect_fail() {
    local out rc=0
    out=$("$check_sh" --layout "$1" "$2" 2>&1) || rc=$?
    [ "$rc" -eq 1 ] || { echo "exit status $rc, wanted 1; output:"; echo "$out"; return 1; }
    printf '%s\n' "$out" | grep -E "^FAIL +$3 " | grep -qF -- "$4" || { echo "no FAIL $3 line with '$4'; output:"; echo "$out"; return 1; }
}

# ---------------------------------------------------------------------------------------------------------------------
# cases
# ---------------------------------------------------------------------------------------------------------------------
case_uefi_good() {
    good_uefi
    out=$("$check_sh" --layout uefi "$tmp/uefi.img" 2>&1) || { echo "$out"; exit 1; }
    for id in gpt-primary gpt-backup esp fat32 efi-binary bcd-references boot-wim boot-sdi; do
        contains "$out" "PASS $id" || { echo "no PASS $id:"; echo "$out"; exit 1; }
    done
    contains "$out" "RESULT: PASS (0 warnings)" || { echo "$out"; exit 1; }
    # only the boot files are in the image: install.wim and support/ stay out, the language directory comes along
    spec=$(spec_of "$tmp/uefi.img")
    ls=$(mdir -/ -b -i "$spec" :: 2>/dev/null | tr '[:upper:]' '[:lower:]')
    contains "$ls" "install.wim" && { echo "install.wim was copied"; exit 1; }
    contains "$ls" "support" && { echo "support/ was copied"; exit 1; }
    contains "$ls" "en-us/bootmgr.efi.mui" || { echo "the language directory is missing: $ls"; exit 1; }
    contains "$ls" "boot/en-us/bootmgr.exe.mui" || { echo "boot/en-us is missing"; exit 1; }
    # BIOS layout asked of a GPT image
    expect_fail bios "$tmp/uefi.img" partition-table "need an MBR"
}

case_bios_good() {
    good_bios
    out=$("$check_sh" --layout bios "$tmp/bios.img" 2>&1) || { echo "$out"; exit 1; }
    for id in active-flag partition-type mbr-code fat32 hidden-sectors boot-sector bootmgr bcd bcd-references boot-wim boot-sdi; do
        contains "$out" "PASS $id" || { echo "no PASS $id:"; echo "$out"; exit 1; }
    done
    expect_fail uefi "$tmp/bios.img" partition-table "need GPT"
}

case_bios_no_bootcode() {
    # without ms-sys the build says so, and the check fails on the MBR and on the stub boot sector of mkfs.fat
    make_media
    rc=0
    out=$("$import_sh" build --layout bios --media "$media" --out "$tmp/nobc.img" --ms-sys no 2>&1) || rc=$?
    [ "$rc" -ne 0 ] || { echo "a BIOS image without boot code was accepted: $out"; exit 1; }
    contains "$out" "NO boot code yet" || { echo "message: $out"; exit 1; }
    expect_fail bios "$tmp/nobc.img" mbr-code "no boot code"
    expect_fail bios "$tmp/nobc.img" boot-sector "This is not a bootable disk"
    contains "$("$check_sh" --layout bios "$tmp/nobc.img" 2>&1 || true)" "RESULT: FAIL (3 failed" || { echo "wanted exactly three failures"; exit 1; }
    expect_fail bios "$tmp/nobc.img" boot-sector-2 "sector 12" || exit 1
}

case_missing_files() {
    good_uefi
    good_bios
    for f in EFI/BOOT/bootx64.efi:efi-binary-file:missing EFI/Microsoft/Boot/BCD:bcd:missing sources/boot.wim:boot-wim:missing boot/boot.sdi:boot-sdi:missing; do
        id=${f#*:}; id=${id%%:*}; path=${f%%:*}
        img=$(copy_of "$tmp/uefi.img" m.img)
        mdel -i "$(spec_of "$img")" "::$path"
        expect_fail uefi "$img" "$id" "missing from the image" || { echo "(uefi, $path)"; exit 1; }
    done
    # boot.sdi missing: the BCD names it, so the reference check fails too
    expect_fail uefi "$img" bcd-references "\\boot\\boot.sdi" || exit 1
    for f in bootmgr:bootmgr boot/BCD:bcd sources/boot.wim:boot-wim boot/boot.sdi:boot-sdi; do
        path=${f%%:*}; id=${f#*:}
        img=$(copy_of "$tmp/bios.img" m.img)
        mdel -i "$(spec_of "$img")" "::$path"
        expect_fail bios "$img" "$id" "missing from the image" || { echo "(bios, $path)"; exit 1; }
    done
}

case_bad_files() {
    good_uefi
    # boot.wim that is not a WIM
    img=$(copy_of "$tmp/uefi.img" m.img)
    spec=$(spec_of "$img")
    mdel -i "$spec" ::sources/boot.wim
    head -c 2000000 /dev/zero > "$tmp/notwim"
    mcopy -n -i "$spec" "$tmp/notwim" ::sources/boot.wim
    expect_fail uefi "$img" boot-wim "wrong kind of file" || exit 1
    # an arm64 boot loader
    img=$(copy_of "$tmp/uefi.img" m.img)
    spec=$(spec_of "$img")
    mdel -i "$spec" ::EFI/BOOT/bootx64.efi
    mcopy -n -i "$spec" "$media/pe-arm64.efi" ::EFI/BOOT/bootx64.efi
    expect_fail uefi "$img" efi-binary "not x86-64" || exit 1
    # a BCD that names a file that is not there
    img=$(copy_of "$tmp/uefi.img" m.img)
    spec=$(spec_of "$img")
    mdel -i "$spec" ::EFI/Microsoft/Boot/BCD
    mcopy -n -i "$spec" "$media/bcd-orphan" ::EFI/Microsoft/Boot/BCD
    expect_fail uefi "$img" bcd-references "\\boot\\gone.sdi" || exit 1
    # a BCD that is not a registry hive
    img=$(copy_of "$tmp/uefi.img" m.img)
    spec=$(spec_of "$img")
    mdel -i "$spec" ::EFI/Microsoft/Boot/BCD
    head -c 16384 /dev/zero > "$tmp/notbcd"
    mcopy -n -i "$spec" "$tmp/notbcd" ::EFI/Microsoft/Boot/BCD
    expect_fail uefi "$img" bcd "wrong kind of file" || exit 1
}

case_partition_table() {
    good_uefi
    good_bios
    # the ESP type changed to a Linux data partition
    img=$(copy_of "$tmp/uefi.img" m.img)
    sgdisk -t 1:8300 "$img" >/dev/null
    expect_fail uefi "$img" esp "no EFI system partition" || exit 1
    # a missing backup GPT: the image grew after the table was written
    img=$(copy_of "$tmp/uefi.img" m.img)
    truncate -s +64M "$img"
    expect_fail uefi "$img" gpt-backup "sgdisk -e" || exit 1
    # BIOS: no active flag, wrong type, no MBR boot code
    img=$(copy_of "$tmp/bios.img" m.img)
    printf '\000' | dd of="$img" bs=1 seek=446 conv=notrunc 2>/dev/null
    expect_fail bios "$img" active-flag "0 active" || exit 1
    img=$(copy_of "$tmp/bios.img" m.img)
    printf '\203' | dd of="$img" bs=1 seek=450 conv=notrunc 2>/dev/null
    expect_fail bios "$img" partition-type "not 0B or 0C" || exit 1
    img=$(copy_of "$tmp/bios.img" m.img)
    head -c 440 /dev/zero | dd of="$img" bs=1 seek=0 conv=notrunc 2>/dev/null
    expect_fail bios "$img" mbr-code "no boot code" || exit 1
    # BIOS: sector 0 of the boot record is right but sector 12 (the rest of its code) is empty: the hang the check exists for
    img=$(copy_of "$tmp/bios.img" m.img)
    st=$(start_of "$img")
    head -c 512 /dev/zero | dd of="$img" bs=512 seek=$((st + 12)) conv=notrunc 2>/dev/null
    expect_fail bios "$img" boot-sector-2 "hangs after" || exit 1
    # BIOS: a wrong hidden-sector count
    img=$(copy_of "$tmp/bios.img" m.img)
    st=$(start_of "$img")
    printf '\001\000\000\000' | dd of="$img" bs=1 seek=$((st * 512 + 28)) conv=notrunc 2>/dev/null
    expect_fail bios "$img" hidden-sectors "mkfs.fat -h $st" || exit 1
    # a disk that is not partitioned at all, and one that is too big or too small
    head -c 100000000 /dev/zero > "$tmp/odd.img"
    expect_fail uefi "$tmp/odd.img" size "not a multiple of 512" || exit 1
    head -c 100663296 /dev/zero > "$tmp/zero.img"
    expect_fail uefi "$tmp/zero.img" boot-signature "not a partitioned disk" || exit 1
    "$check_sh" --layout uefi --max-size 64M "$tmp/uefi.img" >"$tmp/big.out" 2>&1 && { echo "an image over --max-size passed"; exit 1; }
    expect_fail uefi "$tmp/uefi.img" size "over the limit" 2>/dev/null && true
    out=$("$check_sh" --layout uefi --max-size 64M "$tmp/uefi.img" 2>&1 || true)
    contains "$out" "FAIL size" || { echo "$out"; exit 1; }
}

case_not_fat32() {
    make_media
    # a GPT image whose ESP is FAT16, one whose ESP is empty, and one that claims to be NTFS
    for kind in fat16 empty ntfs; do
        img=$tmp/nf-$kind.img
        truncate -s 128M "$img"
        sgdisk -o -n 1:2048:0 -t 1:EF00 "$img" >/dev/null
        read -r st sz < <(part_of "$img")
        case "$kind" in
            fat16) mkfs.fat -F 16 -S 512 --offset "$st" "$img" "$((sz / 2))" >/dev/null;;
            empty) ;;
            ntfs) mkfs.fat -F 32 -S 512 --offset "$st" "$img" "$((sz / 2))" >/dev/null
                  printf 'NTFS    ' | dd of="$img" bs=1 seek=$((st * 512 + 3)) conv=notrunc 2>/dev/null;;
            *) ;;
        esac
    done
    expect_fail uefi "$tmp/nf-fat16.img" fat32 "not a FAT32 one" || exit 1
    expect_fail uefi "$tmp/nf-empty.img" fat32 "0x55AA" || exit 1
    expect_fail uefi "$tmp/nf-ntfs.img" fat32 "NTFS" || exit 1
    # 4096-byte sectors (a different disk geometry) are refused: the SAN device has 512-byte blocks
    img=$tmp/nf-4k.img
    truncate -s 128M "$img"
    sgdisk -o -n 1:2048:0 -t 1:EF00 "$img" >/dev/null
    read -r st sz < <(part_of "$img")
    mkfs.fat -F 32 -S 512 --offset "$st" "$img" "$((sz / 2))" >/dev/null
    printf '\000\020' | dd of="$img" bs=1 seek=$((st * 512 + 11)) conv=notrunc 2>/dev/null
    expect_fail uefi "$img" fat32 "4096 bytes per sector" || exit 1
}

case_vhd_footer() {
    good_uefi
    img=$(copy_of "$tmp/uefi.img" vhd.img)
    python3 -I - "$img" <<'EOF'
import struct, sys
f = open(sys.argv[1], 'ab')
foot = bytearray(512)
foot[0:8] = b'conectix'
struct.pack_into('>I', foot, 60, 2)
f.write(foot)
EOF
    out=$("$check_sh" --layout uefi "$img" 2>&1) || { echo "$out"; exit 1; }
    contains "$out" "PASS vhd" || { echo "$out"; exit 1; }
    contains "$out" "RESULT: PASS" || { echo "$out"; exit 1; }
    # convert strips the footer (with or without qemu-img) and the result is exactly the original disk
    "$import_sh" convert --layout uefi --disk "$img" --out "$tmp/vhd.raw" >/dev/null 2>&1 || { echo "convert failed"; exit 1; }
    cmp -s "$tmp/vhd.raw" "$tmp/uefi.img" || { echo "the converted image differs from the original disk"; exit 1; }
    # a dynamic VHD is refused with a pointer to convert
    img=$(copy_of "$tmp/uefi.img" dyn.img)
    python3 -I - "$img" <<'EOF'
import struct, sys
f = open(sys.argv[1], 'ab')
foot = bytearray(512)
foot[0:8] = b'conectix'
struct.pack_into('>I', foot, 60, 3)
f.write(foot)
EOF
    expect_fail uefi "$img" vhd "dynamic or differencing" || exit 1
    # real VHDs, made by qemu-img (a valid footer with its checksum): fixed passes the check as it is, dynamic is refused with a
    # pointer to convert, and convert gives back exactly the original disk for both
    if command -v qemu-img >/dev/null 2>&1; then
        for sub in fixed dynamic; do
            qemu-img convert -f raw -O vpc -o "subformat=$sub,force_size=on" "$tmp/uefi.img" "$tmp/q-$sub.vhd" >/dev/null 2>&1 \
                || { echo "qemu-img could not write a $sub VHD"; exit 1; }
            if [ "$sub" = fixed ]; then
                "$check_sh" --layout uefi "$tmp/q-$sub.vhd" >/dev/null 2>&1 || { echo "a fixed VHD from qemu-img failed the check"; exit 1; }
            else
                expect_fail uefi "$tmp/q-$sub.vhd" vhd "dynamic or differencing" || exit 1
            fi
            "$import_sh" convert --layout uefi --disk "$tmp/q-$sub.vhd" --out "$tmp/q-$sub.raw" >/dev/null 2>&1 || { echo "convert of the $sub VHD failed"; exit 1; }
            cmp -s "$tmp/q-$sub.raw" "$tmp/uefi.img" || { echo "convert of the $sub VHD differs from the original disk"; exit 1; }
        done
    fi
    # without qemu-img only a fixed VHD or a raw image can be converted, and the script says what is needed for the rest
    mkdir -p "$tmp/noq"
    for t in bash cp od dd tr truncate stat sfdisk sgdisk mdir mcopy mmd git grep sed awk sort head tail cat rm rmdir mkdir dirname basename find mktemp wc env ls date; do
        ln -sf "$(command -v "$t")" "$tmp/noq/$t"
    done
    PATH=$tmp/noq "$import_sh" convert --layout uefi --disk "$tmp/vhd.img" --out "$tmp/vhd2.raw" >/dev/null 2>&1 || { echo "convert of a fixed VHD without qemu-img failed"; exit 1; }
    cmp -s "$tmp/vhd2.raw" "$tmp/uefi.img" || { echo "convert without qemu-img differs from the original disk"; exit 1; }
    out=$(PATH=$tmp/noq "$import_sh" convert --layout uefi --disk "$tmp/dyn.img" --out "$tmp/dyn2.raw" 2>&1) && { echo "a dynamic VHD was converted without qemu-img"; exit 1; }
    contains "$out" "qemu-img is needed" || { echo "message: $out"; exit 1; }
}

case_usage() {
    rc=0; "$check_sh" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "no arguments: exit $rc"; exit 1; }
    rc=0; "$check_sh" --layout hybrid x >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "bad layout: exit $rc"; exit 1; }
    rc=0; "$check_sh" --layout uefi "$tmp/does-not-exist" >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "missing image: exit $rc"; exit 1; }
    rc=0; "$import_sh" bogus >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "bad command: exit $rc"; exit 1; }
    # build refuses an existing output, a bad label, a media root without the files
    make_media
    : > "$tmp/exists.img"
    "$import_sh" build --layout uefi --media "$media" --out "$tmp/exists.img" >/dev/null 2>&1 && { echo "overwrote an image"; exit 1; }
    "$import_sh" build --layout uefi --media "$media" --out "$tmp/l.img" --label 'bad label' >/dev/null 2>&1 && { echo "accepted a bad label"; exit 1; }
    mkdir -p "$tmp/emptymedia"
    out=$("$import_sh" build --layout uefi --media "$tmp/emptymedia" --out "$tmp/e.img" 2>&1) && { echo "built from an empty media directory"; exit 1; }
    contains "$out" "lacks" || { echo "message: $out"; exit 1; }
    [ ! -e "$tmp/e.img" ] || { echo "left an image behind"; exit 1; }
    "$import_sh" build --layout uefi --media "$media" --out "$tmp/big.img" --max-size 3G >/dev/null 2>&1 && { echo "accepted --max-size over 2G"; exit 1; }
    out=$("$import_sh" build --layout uefi --media "$media" --out "$tmp/big.img" --max-size 64M 2>&1) && { echo "built an image over --max-size"; exit 1; }
    contains "$out" "over the limit" || { echo "message: $out"; exit 1; }
    [ ! -e "$tmp/big.img" ] || { echo "left an image behind"; exit 1; }
    return 0
}

case_iso() {
    command -v xorriso >/dev/null 2>&1 || { echo "skip: no xorriso"; exit 77; }
    make_media
    xorriso -as mkisofs -quiet -R -J -o "$tmp/media.iso" "$media" >/dev/null 2>&1 || { echo "could not make the ISO"; exit 1; }
    out=$("$import_sh" build --layout uefi --media "$tmp/media.iso" --out "$tmp/iso.img" 2>&1) || { echo "$out"; exit 1; }
    contains "$out" "RESULT: PASS" || { echo "$out"; exit 1; }
    ls=$(mdir -/ -b -i "$(spec_of "$tmp/iso.img")" :: | tr '[:upper:]' '[:lower:]')
    contains "$ls" "install.wim" && { echo "install.wim was copied from the ISO"; exit 1; }
    return 0
}

case_git_guard() {
    make_media
    command -v git >/dev/null 2>&1 || { echo "skip: no git"; exit 77; }
    g=$tmp/repo
    mkdir -p "$g/ignored"
    git -C "$g" init -q
    printf 'ignored/\n' > "$g/.gitignore"
    out=$("$import_sh" -n build --layout uefi --media "$media" --out "$g/tracked.raw" 2>&1) && { echo "a path git would track was accepted"; exit 1; }
    contains "$out" "Windows files must never be committed" || { echo "message: $out"; exit 1; }
    "$import_sh" -n build --layout uefi --media "$media" --out "$g/ignored/ok.raw" >/dev/null 2>&1 || { echo "an ignored path was refused"; exit 1; }
    # convert and the work directory are guarded too
    out=$("$import_sh" -n convert --layout uefi --disk "$media/bootmgr" --out "$g/tracked2.raw" 2>&1) && { echo "convert accepted a tracked path"; exit 1; }
    contains "$out" "never be committed" || { echo "message: $out"; exit 1; }
    out=$(WINPE_WORK=$g/work "$import_sh" -n build --layout uefi --media "$media" --out "$tmp/elsewhere.raw" 2>&1) && { echo "a tracked work directory was accepted"; exit 1; }
    contains "$out" "never be committed" || { echo "message: $out"; exit 1; }
}

case_gitignore() {
    # the .gitignore of this directory covers every kind of file the scripts handle
    g=$tmp/gi
    mkdir -p "$g/harness/lab/p2/winpe"
    git -C "$g" init -q
    cp "$here/.gitignore" "$g/harness/lab/p2/winpe/.gitignore"
    for f in bootmgr bootmgr.efi BCD boot.wim boot.sdi bootx64.efi x.iso x.raw x.img x.vhd x.vhdx x.qcow2 media/boot/BCD work/a.raw out/a.raw stage.123/boot.wim shots/row.png; do
        mkdir -p "$g/harness/lab/p2/winpe/$(dirname "$f")"
        : > "$g/harness/lab/p2/winpe/$f"
        git -C "$g" check-ignore -q -- "harness/lab/p2/winpe/$f" || { echo "not ignored: $f"; exit 1; }
    done
    # and no such file is in the directory itself
    found=$(find "$here" -type f \( -iname '*.wim' -o -iname '*.sdi' -o -iname 'bcd' -o -iname 'bootmgr*' -o -iname '*.efi' -o -iname '*.vhd' -o -iname '*.vhdx' \
        -o -iname '*.iso' -o -iname '*.raw' -o -iname '*.img' -o -iname '*.qcow2' -o -iname '*.esd' \) | head -n 3)
    [ -z "$found" ] || { echo "a media file is in the source directory: $found"; exit 1; }
}

# the stand-ins for the cluster: sourced library, functions replaced
lib_import() {
    export LAB_DIR=$tmp/lab/lab LAB_CONF=$here/../cluster/lab.conf.example
    # shellcheck source=import-winpe.sh
    . "$import_sh"
    # shellcheck source=../cluster/up.sh
    . "$here/../cluster/up.sh"
    state=$tmp/vmstate
    mkdir -p "$state"
    : > "$state/calls.log"
    p2_vm_pid() { echo 1; }
    p2_ssh_ok() { return 0; }
    vm_stdin() { printf '%s\n' "STDIN $*" >> "$state/calls.log"; cat > "$state/stream.gz"; }
    vm() {
        printf '%s\n' "$*" >> "$state/calls.log"
        case "$*" in
            "sudo rbd info "*) [ -e "$state/exists" ];;
            "sudo bash -c rbd export "*) cat "$state/readback.sum";;
            *) ;;
        esac
    }
    mkdir -p "$tmp/stubs"
    cat > "$tmp/stubs/users.sh" <<EOS
#!/bin/sh
echo "users.sh \$*" >> "$state/calls.log"
exit 0
EOS
    chmod +x "$tmp/stubs/users.sh"
    export WINPE_USERS_SH=$tmp/stubs/users.sh
}

case_import() {
    good_uefi
    lib_import
    sum=$(wp_sha256 "$tmp/uefi.img")
    printf '%s  -\n' "$sum" > "$state/readback.sum"
    out=$(wp_import --layout uefi --image "$tmp/uefi.img" --name t1 2>&1) || { echo "$out"; exit 1; }
    gzip -dc "$state/stream.gz" | cmp -s - "$tmp/uefi.img" || { echo "the stream that reached the VM is not the image"; exit 1; }
    log=$(cat "$state/calls.log")
    contains "$log" "rbd import --image-format 2  - winrbd/wrtest-p2-t1" || { echo "import command: $log"; exit 1; }
    contains "$log" "users.sh create wrtest-p2-t1 --pool winrbd --size 128M" || { echo "users.sh: $log"; exit 1; }
    contains "$log" "rbd snap create winrbd/wrtest-p2-t1@pristine" || { echo "snapshot: $log"; exit 1; }
    contains "$out" "sha256 matches" || { echo "$out"; exit 1; }
    # the layout check comes first: a broken image reaches nothing
    : > "$state/calls.log"
    cp "$tmp/uefi.img" "$tmp/broken.img"
    mdel -i "$(spec_of "$tmp/broken.img")" ::sources/boot.wim
    out=$( (wp_import --layout uefi --image "$tmp/broken.img" --name t2) 2>&1) && { echo "a broken image was imported"; exit 1; }
    contains "$out" "nothing was imported" || { echo "message: $out"; exit 1; }
    [ ! -s "$state/calls.log" ] || { echo "the VM was contacted: $(cat "$state/calls.log")"; exit 1; }
    # a read-back that differs
    printf '%s  -\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$state/readback.sum"
    out=$( (wp_import --layout uefi --image "$tmp/uefi.img" --name t3) 2>&1) && { echo "a differing read-back was accepted"; exit 1; }
    contains "$out" "differs" || { echo "message: $out"; exit 1; }
    contains "$(cat "$state/calls.log")" "users.sh create" && { echo "a user was created for an image that failed verification"; exit 1; }
    printf '%s  -\n' "$sum" > "$state/readback.sum"
    # an existing image is not replaced without --replace
    : > "$state/exists"
    : > "$state/calls.log"
    out=$( (wp_import --layout uefi --image "$tmp/uefi.img" --name t4) 2>&1) && { echo "an existing image was overwritten"; exit 1; }
    contains "$out" "--replace" || { echo "message: $out"; exit 1; }
    contains "$(cat "$state/calls.log")" "rbd import" && { echo "rbd import ran over an existing image"; exit 1; }
    out=$( (wp_import --layout uefi --image "$tmp/uefi.img" --name t4 --replace) 2>&1) || { echo "$out"; exit 1; }
    contains "$(cat "$state/calls.log")" "users.sh delete wrtest-p2-t4" || { echo "no delete before the replace"; exit 1; }
    # names, pools, features
    for n in 'Bad' 'a b' 'a;b' '' 'x/y'; do
        (wp_import --layout uefi --image "$tmp/uefi.img" --name "$n") >/dev/null 2>&1 && { echo "accepted the name '$n'"; exit 1; }
    done
    for p in img-v1 'a;b' 'winrbd2'; do
        (wp_import --layout uefi --image "$tmp/uefi.img" --name t5 --pool "$p") >/dev/null 2>&1 && { echo "accepted the pool '$p'"; exit 1; }
    done
    (wp_import --layout uefi --image "$tmp/uefi.img" --name t5 --features 'a;b') >/dev/null 2>&1 && { echo "accepted bad features"; exit 1; }
    # no key or keyring file name appears in anything printed
    contains "$out" "keyring" && { echo "a keyring is mentioned: $out"; exit 1; }
    return 0
}

case_dry_run() {
    good_uefi
    export LAB_DIR=$tmp/dry/lab LAB_CONF=$here/../cluster/lab.conf.example
    out=$("$import_sh" -n import --layout uefi --image "$tmp/uefi.img" --name dry1 2>&1) || { echo "$out"; exit 1; }
    contains "$out" "would run" || { echo "$out"; exit 1; }
    contains "$out" "rbd import" || { echo "$out"; exit 1; }
    contains "$out" "users.sh" || { echo "$out"; exit 1; }
    [ ! -e "$tmp/dry" ] || { echo "a dry run created $tmp/dry"; exit 1; }
    # a dry run of build changes nothing either
    make_media
    out=$("$import_sh" -n build --layout bios --media "$media" --out "$tmp/dry.img" 2>&1) || { echo "$out"; exit 1; }
    [ ! -e "$tmp/dry.img" ] || { echo "a dry run made an image"; exit 1; }
    contains "$out" "sfdisk" || { echo "$out"; exit 1; }
    contains "$out" "mkfs.fat" || { echo "$out"; exit 1; }
}

case_shellcheck() {
    command -v shellcheck >/dev/null 2>&1 || { echo "skip: shellcheck is not installed"; exit 77; }
    (cd "$here" && shellcheck -x --source-path=SCRIPTDIR check-layout.sh import-winpe.sh selftest.sh) || exit 1
}

case_rbft_scan() {
    # the scanner in run-rows.md: extract the block, run it against synthetic dumps
    blk=$tmp/scan.py
    awk '/^<!-- selftest:rbft-scan -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$here/run-rows.md" > "$blk"
    [ -s "$blk" ] || { echo "no scanner block found in run-rows.md"; exit 1; }
    python3 -I - "$tmp" <<'EOF'
import struct, sys
tmp = sys.argv[1]
def table(length=200, magic=b'WRBT', fix=True, sig=b'rBFT'):
    t = bytearray(length)
    t[0:4] = sig
    struct.pack_into('<I', t, 4, length)
    t[8] = 1
    t[10:16] = b'FENSYS'; t[16:24] = b'iPXE    '
    t[36:40] = magic
    struct.pack_into('<H', t, 40, 1); struct.pack_into('<H', t, 42, 116)
    if fix:
        t[9] = (-sum(t)) & 0xff
    return bytes(t)
def dump(name, tab, at=0x7e000):
    d = bytearray(1 << 20)
    d[at:at + len(tab)] = tab
    open(f'{tmp}/{name}', 'wb').write(d)
dump('d_good.bin', table())
dump('d_badsum.bin', table(fix=False))
dump('d_badmagic.bin', table(magic=b'XXXX'))
dump('d_long.bin', table(length=4000))
dump('d_none.bin', b'')
dump('d_other.bin', table(sig=b'iBFT'))
EOF
    out=$(python3 -I "$blk" "$tmp/d_good.bin" 2>&1) || { echo "the good table was not found: $out"; exit 1; }
    contains "$out" "rBFT at 0x7e000" || { echo "output: $out"; exit 1; }
    for d in d_badsum d_badmagic d_long d_none d_other; do
        rc=0; out=$(python3 -I "$blk" "$tmp/$d.bin" 2>&1) || rc=$?
        [ "$rc" -eq 1 ] || { echo "$d: exit $rc ($out)"; exit 1; }
        contains "$out" "no valid rBFT table" || { echo "$d: $out"; exit 1; }
    done
}

wp_size_of_file() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }

make_fakeqmp() { # the stand-in QEMU: $tmp/fakeqmp.py SOCKET LOG. A screen is the WinPE shell when the name ends in shell.ppm or the file $FAKE_SHELL exists
    cat > "$tmp/fakeqmp.py" <<'FAKEQMP'
import json, os, socket, struct, sys
path, log = sys.argv[1], sys.argv[2]
srv = socket.socket(socket.AF_UNIX)
srv.bind(path)
srv.listen(4)
done = False
while not done:
    c, _ = srv.accept()
    f = c.makefile("rw")
    f.write(json.dumps({"QMP": {"version": {}, "capabilities": []}}) + "\n"); f.flush()
    for line in f:
        m = json.loads(line)
        cmd, a = m["execute"], m.get("arguments", {})
        open(log, "a").write(json.dumps(m, sort_keys=True) + "\n")
        if cmd == "query-status":
            r = {"return": {"status": "running", "running": True}}
        elif cmd == "screendump":
            if a["filename"].endswith("shell.ppm") or os.path.exists(os.environ.get("FAKE_SHELL", "")):   # a WinPE-like screen: blue desktop, dark console window
                w, h = 100, 100
                img = bytearray(bytes((18, 115, 170)) * (w * h))
                for y in range(20, 90):
                    for x in range(20, 90):
                        img[(y * w + x) * 3:(y * w + x) * 3 + 3] = bytes((12, 12, 12))
                open(a["filename"], "wb").write(b"P6\n%d %d\n255\n" % (w, h) + bytes(img))
            else:
                w, h = 3, 2
                open(a["filename"], "wb").write(b"P6\n%d %d\n255\n" % (w, h) + bytes(range(w * h * 3)))
            r = {"return": {}}
        elif cmd == "pmemsave":
            t = bytearray(200); t[0:4] = b"rBFT"; struct.pack_into("<I", t, 4, 200); t[8] = 1
            t[36:40] = b"WRBT"; struct.pack_into("<H", t, 40, 1); struct.pack_into("<H", t, 42, 116)
            t[9] = (-sum(t)) & 0xff
            d = bytearray(a["size"]); d[0x7e000:0x7e000 + 200] = t
            open(a["filename"], "wb").write(d)
            r = {"return": {}}
        elif cmd == "quit":
            r = {"return": {}}; done = True
        elif cmd == "qmp_capabilities":
            r = {"return": {}}
        else:
            r = {"error": {"class": "CommandNotFound", "desc": "no " + cmd}}
        f.write(json.dumps(r) + "\n"); f.flush()
        if done:
            break
    c.close()
os.unlink(path)
FAKEQMP
}

case_qmp_tool() {
    # the QMP tool of run-rows.md against a stand-in QEMU: the right JSON goes out, a PPM becomes a valid PNG, pmemsave output feeds the scanner
    blk=$tmp/qmp-shot.py
    awk '/^<!-- selftest:qmp-tool -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$here/run-rows.md" > "$blk"
    [ -s "$blk" ] || { echo "no QMP tool block found in run-rows.md"; exit 1; }
    scan=$tmp/scan2.py
    awk '/^<!-- selftest:rbft-scan -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$here/run-rows.md" > "$scan"
    make_fakeqmp
    sock=$tmp/q.sock
    python3 -I "$tmp/fakeqmp.py" "$sock" "$tmp/qmp.log" &
    pid=$!
    for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
    [ -S "$sock" ] || { echo "the stand-in QMP server did not start"; exit 1; }
    out=$(python3 -I "$blk" "$sock" status 2>&1) || { echo "status: $out"; exit 1; }
    contains "$out" running || { echo "status output: $out"; exit 1; }
    python3 -I "$blk" "$sock" screendump "$tmp/shot.png" >/dev/null || { echo "screendump failed"; exit 1; }
    python3 -I - "$tmp/shot.png" <<'PNGCHK' || { echo "the screendump is not a valid PNG"; exit 1; }
import struct, sys, zlib
d = open(sys.argv[1], "rb").read()
assert d[:8] == b"\x89PNG\r\n\x1a\n"
pos, idat, ihdr = 8, b"", None
while pos < len(d):
    n, t = struct.unpack(">I4s", d[pos:pos + 8])
    body = d[pos + 8:pos + 8 + n]
    assert struct.unpack(">I", d[pos + 8 + n:pos + 12 + n])[0] == zlib.crc32(t + body) & 0xffffffff
    if t == b"IHDR":
        ihdr = struct.unpack(">IIBBBBB", body)
    if t == b"IDAT":
        idat += body
    pos += 12 + n
assert ihdr == (3, 2, 8, 2, 0, 0, 0), ihdr
raw = zlib.decompress(idat)
assert raw == b"\0" + bytes(range(9)) + b"\0" + bytes(range(9, 18)), raw
PNGCHK
    [ ! -e "$tmp/shot.png.ppm" ] || { echo "the temporary PPM was left behind"; exit 1; }
    python3 -I "$blk" "$sock" screendump "$tmp/shot.ppm" >/dev/null || { echo "ppm screendump failed"; exit 1; }
    [ "$(head -c 2 "$tmp/shot.ppm")" = P6 ] || { echo "the .ppm output is not a PPM"; exit 1; }
    python3 -I "$blk" "$sock" pmemsave "$tmp/mem.bin" 1 >/dev/null || { echo "pmemsave failed"; exit 1; }
    [ "$(wp_size_of_file "$tmp/mem.bin")" -eq 1048576 ] || { echo "pmemsave size"; exit 1; }
    out=$(python3 -I "$scan" "$tmp/mem.bin") || { echo "$out"; exit 1; }
    contains "$out" "rBFT at 0x7e000" || { echo "scan of the dump: $out"; exit 1; }
    # probe: a WinPE-like screen is recognised (exit 0, temp file removed), another screen is not (exit 3)
    out=$(python3 -I "$blk" "$sock" probe "$tmp/shell.ppm") || { echo "probe of a shell screen: $out"; exit 1; }
    contains "$out" '"winpe_shell": true' || { echo "probe output: $out"; exit 1; }
    [ ! -e "$tmp/shell.ppm" ] || { echo "probe left its screendump"; exit 1; }
    rc=0; out=$(python3 -I "$blk" "$sock" probe "$tmp/other.ppm") || rc=$?
    [ "$rc" -eq 3 ] && contains "$out" '"winpe_shell": false' || { echo "probe of another screen: exit $rc: $out"; exit 1; }
    [ ! -e "$tmp/other.ppm" ] || { echo "probe left its screendump"; exit 1; }
    # a bad command line is exit 2
    rc=0; python3 -I "$blk" "$sock" bogus >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "bad command: exit $rc"; exit 1; }
    rc=0; python3 -I "$blk" "$sock" pmemsave "$tmp/x.bin" abc >/dev/null 2>&1 || rc=$?
    [ "$rc" -eq 2 ] || { echo "bad size: exit $rc"; exit 1; }
    python3 -I "$blk" "$sock" quit >/dev/null || { echo "quit failed"; exit 1; }
    wait "$pid" || true
    log=$(cat "$tmp/qmp.log")
    contains "$log" '"filename": "'"$tmp"'/shot.png.ppm"' || { echo "the screendump request: $log"; exit 1; }
    contains "$log" '"size": 1048576' || { echo "the pmemsave request: $log"; exit 1; }
    contains "$log" '"val": 0' || { echo "the pmemsave start: $log"; exit 1; }
    # a socket that is not there is a clean failure, not a traceback
    rc=0; out=$(python3 -I "$blk" "$tmp/none.sock" status 2>&1) || rc=$?
    [ "$rc" -eq 1 ] && contains "$out" "qmp-shot:" && ! contains "$out" Traceback || { echo "missing socket: exit $rc: $out"; exit 1; }
}

case_import_vhd() {
    # a fixed VHD passes check-layout.sh (it knows the footer) but must not be imported as it is: the footer would be the last sector of the disk
    good_uefi
    lib_import
    img=$(copy_of "$tmp/uefi.img" vhd-imp.img)
    python3 -I - "$img" <<'EOF2'
import struct, sys
f = open(sys.argv[1], 'ab')
foot = bytearray(512)
foot[0:8] = b'conectix'
struct.pack_into('>I', foot, 60, 2)
f.write(foot)
EOF2
    "$check_sh" --layout uefi "$img" >/dev/null 2>&1 || { echo "the fixed VHD should pass the check"; exit 1; }
    : > "$state/calls.log"
    out=$( (wp_import --layout uefi --image "$img" --name t6) 2>&1) && { echo "a fixed VHD was imported"; exit 1; }
    contains "$out" "VHD footer" && contains "$out" "convert" || { echo "message: $out"; exit 1; }
    [ ! -s "$state/calls.log" ] || { echo "the VM was contacted: $(cat "$state/calls.log")"; exit 1; }
    # the converted raw image is accepted
    "$import_sh" convert --layout uefi --disk "$img" --out "$tmp/vhd-imp.raw" >/dev/null 2>&1 || { echo "convert failed"; exit 1; }
    printf '%s  -\n' "$(wp_sha256 "$tmp/vhd-imp.raw")" > "$state/readback.sum"
    out=$( (wp_import --layout uefi --image "$tmp/vhd-imp.raw" --name t6 --replace) 2>&1) || { echo "$out"; exit 1; }   # --replace: case_import left its "image exists" flag
}

case_readonly() {
    # check-layout.sh says it never writes to the image: the bytes are the same after a passing and after a failing run
    good_uefi
    good_bios
    img=$(copy_of "$tmp/bios.img" ro-bad.img)
    mdel -i "$(spec_of "$img")" ::bootmgr
    for f in "$tmp/uefi.img:uefi" "$tmp/bios.img:bios" "$img:bios" "$tmp/uefi.img:bios"; do
        path=${f%:*}; lay=${f##*:}
        before=$(wp_sha256_file "$path")
        "$check_sh" --layout "$lay" "$path" >/dev/null 2>&1 || true
        [ "$(wp_sha256_file "$path")" = "$before" ] || { echo "check-layout.sh changed $path"; exit 1; }
    done
}
wp_sha256_file() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

case_sizes() {
    # sizes: no wrap-around in 64-bit shell arithmetic, no octal surprise, bounded
    export LAB_DIR=$tmp/lab/lab LAB_CONF=$here/../cluster/lab.conf.example
    # shellcheck source=import-winpe.sh
    . "$import_sh"
    [ "$(wp_to_bytes 2G)" = 2147483648 ] || { echo "2G"; exit 1; }
    [ "$(wp_to_bytes 08M)" = 8388608 ] || { echo "08M is not read as decimal"; exit 1; }
    for bad in 17179869185G 18446744073709551617 99999999999999999G 2000G 1x -1 ''; do
        out=$( (wp_to_bytes "$bad") 2>&1) && { echo "wp_to_bytes accepted '$bad' as $out"; exit 1; }
    done
    make_media
    out=$("$import_sh" -n build --layout uefi --media "$media" --out "$tmp/ovf.raw" --size 17179869185G 2>&1) && { echo "a wrapped size was accepted: $out"; exit 1; }
    contains "$out" "out of range" || { echo "message: $out"; exit 1; }
    good_uefi
    out=$("$check_sh" --layout uefi --max-size 17179869185G "$tmp/uefi.img" 2>&1) && { echo "check-layout accepted a wrapped --max-size"; exit 1; }
    contains "$out" "out of range" || { echo "message: $out"; exit 1; }
    "$check_sh" --layout uefi --max-size 08G "$tmp/uefi.img" >/dev/null 2>&1 || { echo "--max-size 08G refused"; exit 1; }
}

case_iso_install() {
    # install images are skipped whatever the case of their name, and the scratch tree of a failed build does not stay
    command -v xorriso >/dev/null 2>&1 || { echo "skip: no xorriso"; exit 77; }
    make_media
    m2=$tmp/media2
    mkdir -p "$m2"
    cp -R "$media/." "$m2/"
    mv "$m2/sources" "$m2/Sources"
    mv "$m2/Sources/install.wim" "$m2/Sources/Install.Wim"
    xorriso -as mkisofs -quiet -R -J -o "$tmp/media2.iso" "$m2" >/dev/null 2>&1 || { echo "could not make the ISO"; exit 1; }
    export LAB_DIR=$tmp/lab/lab LAB_CONF=$here/../cluster/lab.conf.example
    # shellcheck source=import-winpe.sh
    . "$import_sh"
    mkdir -p "$tmp/ex"
    wp_extract_iso "$tmp/media2.iso" "$tmp/ex" >/dev/null 2>&1 || { echo "extract failed"; exit 1; }
    found=$(find "$tmp/ex" -iname 'install.*' | head -n 1)
    [ -z "$found" ] || { echo "an install image was extracted: $found"; exit 1; }
    [ -n "$(find "$tmp/ex" -iname 'boot.wim' | head -n 1)" ] || { echo "boot.wim was not extracted"; exit 1; }
    # a build that dies after the extraction leaves no stage.* directory in the work directory
    out=$("$import_sh" build --layout uefi --media "$tmp/media2.iso" --out "$tmp/late.img" --size 100K 2>&1) && { echo "a --size of 100K was accepted"; exit 1; }
    contains "$out" "multiple of 1 MiB" || { echo "message: $out"; exit 1; }
    left=$(find "$tmp/work" -maxdepth 1 -name 'stage.*' 2>/dev/null | head -n 1)
    [ -z "$left" ] || { echo "the scratch tree was left behind: $left"; exit 1; }
    # and a build that succeeds removes it too
    "$import_sh" build --layout uefi --media "$tmp/media2.iso" --out "$tmp/ok2.img" >/dev/null 2>&1 || { echo "build from the ISO failed"; exit 1; }
    left=$(find "$tmp/work" -maxdepth 1 -name 'stage.*' 2>/dev/null | head -n 1)
    [ -z "$left" ] || { echo "the scratch tree was left behind after a good build: $left"; exit 1; }
}

case_convert_backing() {
    command -v qemu-img >/dev/null 2>&1 || { echo "skip: no qemu-img"; exit 77; }
    good_uefi
    qemu-img convert -f raw -O qcow2 "$tmp/uefi.img" "$tmp/base.qcow2" >/dev/null 2>&1 || { echo "no qcow2"; exit 1; }
    qemu-img create -q -f qcow2 -b "$tmp/base.qcow2" -F qcow2 "$tmp/overlay.qcow2" >/dev/null 2>&1 || { echo "no overlay"; exit 1; }
    out=$("$import_sh" convert --layout uefi --disk "$tmp/overlay.qcow2" --out "$tmp/ov.raw" 2>&1) && { echo "an overlay with a backing file was converted"; exit 1; }
    contains "$out" "backing file" || { echo "message: $out"; exit 1; }
    [ ! -e "$tmp/ov.raw" ] || { echo "left an output behind"; exit 1; }
    "$import_sh" convert --layout uefi --disk "$tmp/base.qcow2" --out "$tmp/base.raw" >/dev/null 2>&1 || { echo "a plain qcow2 failed"; exit 1; }
    cmp -s "$tmp/base.raw" "$tmp/uefi.img" || { echo "the converted qcow2 differs"; exit 1; }
}

case_git_guard_relative() {
    make_media
    command -v git >/dev/null 2>&1 || { echo "skip: no git"; exit 77; }
    g=$tmp/repo2
    mkdir -p "$g/ignored"
    git -C "$g" init -q
    # an anchored pattern: a relative path must be judged where it really is, not relative to its own directory
    printf '/ignored/*.raw\n' > "$g/.gitignore"
    (cd "$g" && "$import_sh" -n build --layout uefi --media "$media" --out ignored/ok.raw >/dev/null 2>&1) || { echo "a relative, ignored path was refused"; exit 1; }
    out=$(cd "$g" && "$import_sh" -n build --layout uefi --media "$media" --out ignored/ok.txt 2>&1) && { echo "a relative path git would track was accepted"; exit 1; }
    contains "$out" "never be committed" || { echo "message: $out"; exit 1; }
}

case_rbft_scan_edges() {
    blk=$tmp/scan3.py
    awk '/^<!-- selftest:rbft-scan -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' "$here/run-rows.md" > "$blk"
    python3 -I - "$tmp" <<'EOF2'
import struct, sys
tmp = sys.argv[1]
def table(off_pool=None, length=200):
    t = bytearray(length)
    t[0:4] = b'rBFT'
    struct.pack_into('<I', t, 4, length)
    t[8] = 1
    t[36:40] = b'WRBT'
    struct.pack_into('<H', t, 40, 1); struct.pack_into('<H', t, 42, 116)
    if off_pool is not None:
        struct.pack_into('<H', t, 36 + 98, off_pool)
    t[9] = (-sum(t)) & 0xff
    return bytes(t)
CH = 64 << 20
# tables across the 64 MiB read boundary, right after it, and in the last bytes of the file
with open(tmp + '/d_edges.bin', 'wb') as f:
    f.truncate(2 * CH + 5000)
    for at in (CH - 100, CH, 2 * CH - 1, 2 * CH + 5000 - 200):
        f.seek(at); f.write(table())
# the strings of a table are read inside the table: an offset past its end must not show what follows it
with open(tmp + '/d_oob.bin', 'wb') as f:
    f.truncate(4096)
    f.seek(0x1000 - 4096); f.write(table(off_pool=100))      # ends at 200; var area starts at 152; 152 + 100 = 252 is outside
    f.seek(252); f.write(b'EVIL\0')
EOF2
    out=$(python3 -I "$blk" "$tmp/d_edges.bin" 2>&1) || { echo "$out"; exit 1; }
    for at in $((64 * 1048576 - 100)) $((64 * 1048576)) $((128 * 1048576 - 1)) $((128 * 1048576 + 5000 - 200)); do
        contains "$out" "rBFT at $(printf '0x%x' "$at") " || { echo "missing the table at $at: $out"; exit 1; }
    done
    [ "$(printf '%s\n' "$out" | grep -c '^rBFT at')" -eq 4 ] || { echo "wrong number of tables (a duplicate or a miss): $out"; exit 1; }
    out=$(python3 -I "$blk" "$tmp/d_oob.bin" 2>&1) || { echo "$out"; exit 1; }
    contains "$out" EVIL && { echo "the scanner read a string from outside the table: $out"; exit 1; }
    contains "$out" "image=?/" || { echo "output: $out"; exit 1; }
    return 0
}

case_evidence() {
    # the evidence script of run-rows.md against the stand-in QEMU: a shell is recognised, a run without one ends at its deadline, a dead run does not spin;
    # the dumps never stay, and the guest is told to quit
    blk=$tmp/ev; mkdir -p "$blk"
    for n in rbft-scan:python:rbft-scan.py qmp-tool:python:qmp-shot.py evidence:bash:evidence.sh; do
        mark=${n%%:*}; rest=${n#*:}; lang=${rest%%:*}; file=${rest#*:}
        awk -v m="<!-- selftest:$mark -->" -v l="\`\`\`$lang" '$0 == m {f = 1; next} f && $0 == l {g = 1; next} g && /^```/ {exit} g {print}' "$here/run-rows.md" > "$blk/$file"
        [ -s "$blk/$file" ] || { echo "no $mark block in run-rows.md"; exit 1; }
    done
    make_fakeqmp
    export EV_SETTLE=0 EV_POLL=1 EV_MEM_MB=1
    for scenario in shell noshell dead; do
        export P2Q_WORK=$tmp/p2q-$scenario WINPE_WORK=$tmp/evwork-$scenario     # a fresh pair per scenario
        mkdir -p "$P2Q_WORK/runs/W9-vendor-20260101T000000Z-1" "$P2Q_WORK/s"
        : > "$P2Q_WORK/runs/W9-vendor-20260101T000000Z-1/console.log"
        pid=""
        if [ "$scenario" != dead ]; then
            echo "WRRUN-SAN-START sanboot" > "$P2Q_WORK/runs/W9-vendor-20260101T000000Z-1/console.log"
            : > "$tmp/qmp-ev.log"
            [ "$scenario" = shell ] && : > "$tmp/fake-shell" || rm -f "$tmp/fake-shell"
            FAKE_SHELL=$tmp/fake-shell python3 -I "$tmp/fakeqmp.py" "$P2Q_WORK/s/1.sock" "$tmp/qmp-ev.log" &
            pid=$!
            for _ in $(seq 1 50); do [ -S "$P2Q_WORK/s/1.sock" ] && break; sleep 0.1; done
        fi
        rc=0
        out=$(cd "$blk" && EV_DEADLINE=6 timeout 60 bash evidence.sh W9-vendor 2>&1) || rc=$?
        [ -z "$pid" ] || { wait "$pid" 2>/dev/null || true; }
        d=$WINPE_WORK/evidence/W9-vendor
        case "$scenario" in
            shell)
                [ "$rc" -eq 0 ] || { echo "shell: exit $rc: $out"; exit 1; }
                contains "$out" "WinPE shell recognised" || { echo "shell: $out"; exit 1; }
                contains "$out" "rBFT at 0x7e000" || { echo "shell: no table in the scan: $out"; exit 1; }
                [ -s "$d/final.png" ] || { echo "shell: no final screenshot"; exit 1; }
                contains "$(cat "$tmp/qmp-ev.log")" '"execute": "quit"' || { echo "shell: the guest was not told to quit"; exit 1; };;
            noshell)
                [ "$rc" -eq 0 ] || { echo "noshell: exit $rc: $out"; exit 1; }
                contains "$out" "no shell by the deadline" || { echo "noshell: $out"; exit 1; }
                [ -s "$d/001.png" ] && [ -s "$d/final.png" ] || { echo "noshell: no screenshots"; exit 1; }
                contains "$(cat "$tmp/qmp-ev.log")" '"execute": "quit"' || { echo "noshell: the guest was not told to quit"; exit 1; };;
            dead)
                [ "$rc" -eq 1 ] || { echo "dead: exit $rc (124 = it spun until the timeout): $out"; exit 1; }
                contains "$out" "no WRRUN-SAN-START" || { echo "dead: $out"; exit 1; };;
            *) ;;
        esac
        # the dumps (they can hold the run's key) are gone on every path, and the directory is private
        [ -z "$(find "$WINPE_WORK" -name '*.bin' -o -name '*.ppm' 2>/dev/null | head -n 1)" ] || { echo "$scenario: a dump or screen file was left behind"; exit 1; }
        [ "$(stat -c %a "$d" 2>/dev/null || stat -f %Lp "$d")" = 700 ] || { echo "$scenario: the evidence directory is not mode 700"; exit 1; }
    done
}

cases=(
    "uefi_good|a UEFI image built from a media directory passes, carries only the boot files, and is refused for the BIOS rows"
    "bios_good|a BIOS image built with a boot-code writer passes, and is refused for the UEFI rows"
    "bios_no_bootcode|a BIOS image with no boot code fails on the MBR and on the mkfs.fat stub boot sector, and build says so"
    "missing_files|a missing bootx64.efi, BCD, boot.wim, boot.sdi, bootmgr each fail with a clear message (both layouts)"
    "bad_files|a boot.wim that is no WIM, an arm64 loader, a BCD naming a missing file, a BCD that is no hive each fail"
    "partition_table|wrong ESP type, missing backup GPT, no active flag, wrong type, no MBR code, wrong hidden sectors, not partitioned, too big"
    "not_fat32|an ESP that is FAT16, NTFS, empty, or has 4096-byte sectors fails"
    "vhd_footer|a fixed VHD footer is accepted and stripped by convert, a dynamic VHD is refused"
    "usage|bad arguments exit 2; build refuses an existing output, a bad label, an empty media tree, a size over the limit"
    "iso|an ISO of the media builds a passing image without install.wim"
    "git_guard|a path inside a git work tree that git does not ignore is refused (build, convert, work directory)"
    "gitignore|the .gitignore here covers every kind of media file, and none is in the directory"
    "import|import: layout check first, the stream is the image, read-back compared, no overwrite, names and pools validated"
    "dry_run|dry runs print and change nothing"
    "rbft_scan|the rBFT scanner of run-rows.md accepts a valid table and refuses a bad checksum, bad magic, bad length"
    "qmp_tool|the QMP tool of run-rows.md: status, a screendump that is a valid PNG, pmemsave output the scanner reads, errors are clean"
    "import_vhd|a fixed VHD is not imported as it is (the footer would become the last sector); the converted raw image is"
    "readonly|check-layout.sh leaves the image byte for byte as it was, on a pass and on a failure"
    "sizes|sizes do not wrap around, 08M is decimal, --size and --max-size are bounded"
    "iso_install|install images are skipped whatever the case of their name; no scratch tree stays after a failed or a good build"
    "convert_backing|a qcow2 overlay with a backing file is refused; a plain qcow2 converts exactly"
    "git_guard_relative|a relative path is judged where it really is (anchored ignore pattern)"
    "rbft_scan_edges|the scanner finds tables across a read boundary and at the end of a file, and reads strings only inside the table"
    "evidence|the evidence script: shell recognised, deadline when there is none, no spinning on a dead run, dumps removed, directory private"
    "shellcheck|shellcheck clean"
)

run_case() { # NAME DESCRIPTION: its own process, so errexit is on as in a script of its own
    local name=$1 desc=$2 rc=0 log
    log=$tmp/case-$name.log
    bash "${BASH_SOURCE[0]}" --case "$name" >"$log" 2>&1 || rc=$?
    case "$rc" in
        0) ok "$desc";;
        77) printf '  skip %s (%s)\n' "$desc" "$(head -n 1 "$log")";;
        *) bad "$desc"; sed 's/^/       /' "$log" >&2;;
    esac
}

if [ "${1:-}" = "--case" ]; then
    "case_${2:?}"
    exit 0
fi

for c in "${cases[@]}"; do
    run_case "${c%%|*}" "${c#*|}"
done
echo "winpe selftest: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
