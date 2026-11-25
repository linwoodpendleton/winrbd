#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 WinPE rows (W1 to W4): turn the OWNER's WinPE or Windows setup boot media into a raw disk image, check its layout,
# and import it into a lab RBD image with its own throwaway cephx user. This script downloads NOTHING: WinPE and Windows
# media are not redistributable and are never fetched from anywhere; you bring them (README.md, "What you must supply").
#
#   import-winpe.sh [-n] build   --layout uefi|bios --media DIR|ISO --out IMAGE [--size 1G] [--label WINPE]
#                                [--max-size 2G] [--ms-sys auto|yes|no] [--ms-sys-bin PATH]
#       a new raw image (GPT + FAT32 ESP for uefi, MBR + active FAT32 partition for bios) holding only what a boot needs:
#       bootmgr, bootmgr.efi, boot\, EFI\, the language directories with bootmgr's messages, and sources\boot.wim (never
#       install.wim or install.esd). --media is a directory (a copied or mounted media tree) or an .iso. Needs: sgdisk
#       (uefi) or sfdisk (bios), mkfs.fat, mtools, truncate; for an ISO also 7z, bsdtar or xorriso. No root.
#       Then it runs check-layout.sh on the result and fails when that fails.
#   import-winpe.sh [-n] convert --layout uefi|bios --disk FILE --out IMAGE
#       a disk image you made yourself (a fixed or dynamic VHD, VHDX, qcow2 or raw) to a raw image, then check-layout.sh.
#   import-winpe.sh [-n] import  --layout uefi|bios --image IMAGE --name NAME [--pool POOL] [--features LIST]
#                                [--replace] [--no-snapshot] [--no-verify]
#       check-layout.sh (always; a failing layout stops here), then import into the lab VM: the raw image is streamed
#       (gzip) into `rbd import`, read back and compared by sha256, a cephx user client.wrtest-p2-NAME limited to that pool
#       is created (users.sh create), and a snapshot `pristine` is taken so that every row can start from the same bytes
#       (rbd snap rollback). The key goes to the lab's keys directory and is never printed.
#   import-winpe.sh [-n] all     --layout L (--media M | --disk D) --name NAME [--size S] [--pool POOL] [--replace]
#       build or convert into $WINPE_WORK/NAME.raw, then import.
#
#   -n, --dry-run   print what would be done and change nothing
#
# Where files go: WINPE_WORK (default ~/.local/share/winrbd-winpe, or $XDG_DATA_HOME/winrbd-winpe). It must be OUTSIDE the
# repository, or git-ignored: this script refuses a path inside a git work tree that git would not ignore, so that no Windows
# file can ever be committed. The lab settings (LAB_DIR, LAB_CONF, ...) are those of harness/lab/p2/cluster.
# Image names: NAME gets the prefix wrtest-p2- unless it starts with wrtest- (the rule of users.sh).
#
# This file is also a function library for selftest.sh: when it is sourced it defines functions only.
set -euo pipefail

wp_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../../common.sh
. "$wp_here/../../common.sh"

WP_MAX_BYTES=2147483648

wp_dry=0
act() { # run a command, or only print it in dry-run mode
    if [ "$wp_dry" = 1 ]; then
        printf 'would run:'
        printf ' %q' "$@"
        printf '\n'
        return 0
    fi
    "$@"
}

wp_to_bytes() { # 512M | 2G | 4096 -> bytes (at most 1 TiB: a bigger number would wrap around in 64-bit shell arithmetic and could pass a limit check)
    local s=$1 n mult=1
    [[ "$s" =~ ^([0-9]{1,15})([KMG]?)$ ]] || die "bad size '$s': use e.g. 512M or 2G"
    n=$((10#${BASH_REMATCH[1]})) # base 10: a leading zero is not octal
    case "${BASH_REMATCH[2]}" in K) mult=1024;; M) mult=1048576;; G) mult=1073741824;; *) ;; esac
    [ "$n" -le $((1099511627776 / mult)) ] || die "size '$s' is out of range (at most 1T)"
    printf '%s' "$((n * mult))"
}

wp_need() { # TOOL... : every tool must exist (in dry-run mode a missing tool is only reported)
    local t
    for t in "$@"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            if [ "$wp_dry" = 1 ]; then info "warning: missing tool $t (a real run would stop here)"; else die "missing tool: $t"; fi
        fi
    done
}

wp_work() {
    printf '%s' "${WINPE_WORK:-${XDG_DATA_HOME:-$HOME/.local/share}/winrbd-winpe}"
}

# No Windows file may reach a commit: a path inside a git work tree must be ignored by git.
wp_check_untracked() { # PATH (need not exist)
    local p=$1 d top
    # git -C DIR reads a relative path against DIR, not against the current directory: make it absolute first
    case "$p" in /*) ;; *) p=$PWD/$p;; esac
    d=$(dirname "$p")
    while [ ! -d "$d" ] && [ "$d" != / ]; do d=$(dirname "$d"); done
    if top=$(git -C "$d" rev-parse --show-toplevel 2>/dev/null); then
        if ! git -C "$d" check-ignore -q -- "$p" 2>/dev/null; then
            die "$p is inside the git work tree $top and git does not ignore it: Windows files must never be committed. Use a path outside the repository (WINPE_WORK) or an ignored one."
        fi
    fi
}

wp_sha256() { # FILE or stdin
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@" | awk '{print $1}'; else shasum -a 256 "$@" | awk '{print $1}'; fi
}

wp_size_of() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }

# the first partition of a raw image: "START SIZE" in sectors (from sfdisk -d)
wp_part_of() {
    sfdisk -d "$1" 2>/dev/null | sed -n 's/.*start= *\([0-9][0-9]*\), *size= *\([0-9][0-9]*\),.*/\1 \2/p' | head -n 1
}

wp_find_ci() { # DIR NAME : the entry of DIR called NAME in any letter case
    local e
    while IFS= read -r e; do printf '%s' "$e"; return 0; done < <(find "$1" -maxdepth 1 -mindepth 1 -iname "$2" 2>/dev/null | sort)
    return 1
}

# ---------------------------------------------------------------------------------------------------------------------
# media -> a directory that holds the tree (an ISO is extracted, without the install images)
# ---------------------------------------------------------------------------------------------------------------------
wp_extract_iso() { # ISO DEST
    local iso=$1 dest=$2 t n
    for t in 7zz 7z 7za; do
        if command -v "$t" >/dev/null 2>&1; then
            info "extracting with $t (reads UDF and ISO 9660; the install images are skipped)"
            # -ssc- makes the exclusion case-insensitive (media spell it Sources/Install.wim as often as sources/install.wim); a
            # 7-Zip that does not know the switch gets the three common spellings instead
            if ! "$t" x -y -bd -ssc- -o"$dest" "$iso" '-x!sources/install.*' >/dev/null 2>&1; then
                "$t" x -y -bd -o"$dest" "$iso" '-x!sources/install.*' '-x!SOURCES/install.*' '-x!Sources/install.*' >/dev/null \
                    || die "$t could not read $iso"
            fi
            wp_drop_install_images "$dest"
            return 0
        fi
    done
    if command -v bsdtar >/dev/null 2>&1; then
        info "extracting with bsdtar (ISO 9660 only; the install images are skipped)"
        bsdtar -xf "$iso" -C "$dest" --exclude 'sources/install.*' --exclude 'SOURCES/install.*' --exclude 'Sources/install.*'
        wp_drop_install_images "$dest"
        return 0
    fi
    if command -v xorriso >/dev/null 2>&1; then
        info "extracting with xorriso (ISO 9660 only; the fixed list of boot files, no language directories)"
        for n in bootmgr bootmgr.efi boot efi BOOTMGR BOOTMGR.EFI BOOT EFI; do
            xorriso -osirrox on -indev "$iso" -extract "/$n" "$dest/$n" >/dev/null 2>&1 || true
        done
        mkdir -p "$dest/sources"
        for n in sources/boot.wim SOURCES/BOOT.WIM SOURCES/boot.wim Sources/boot.wim; do
            if xorriso -osirrox on -indev "$iso" -extract "/$n" "$dest/sources/boot.wim" >/dev/null 2>&1; then break; fi
        done
        return 0
    fi
    die "no tool to read an ISO: install 7-Zip (7z or 7zz; it reads UDF, which Windows media use), bsdtar or xorriso, or extract the ISO yourself and pass the directory"
}

wp_drop_install_images() { # DEST : whatever spelling the media used, install.wim / install.esd / install.swm do not stay in the scratch tree
    find "$1" -mindepth 2 -maxdepth 2 -type f -ipath '*/sources/install.*' -delete
}

# ---------------------------------------------------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------------------------------------------------
wp_have_bootwim() { # SRCDIR : does it hold sources/boot.wim (any letter case)?
    local n
    n=$(wp_find_ci "$1" sources) || return 1
    [ -d "$n" ] || return 1
    wp_find_ci "$n" boot.wim >/dev/null
}

wp_payload_bytes() { # SRCDIR -> bytes of what will be copied (files only)
    local d=$1 total=0 e n
    for e in bootmgr bootmgr.efi; do
        if n=$(wp_find_ci "$d" "$e") && [ -f "$n" ]; then total=$((total + $(wp_size_of "$n"))); fi
    done
    for e in boot efi; do
        if n=$(wp_find_ci "$d" "$e") && [ -d "$n" ]; then total=$((total + $(du -sk "$n" | awk '{print $1 * 1024}'))); fi
    done
    if n=$(wp_find_ci "$d" sources) && [ -d "$n" ] && n=$(wp_find_ci "$n" boot.wim); then total=$((total + $(wp_size_of "$n"))); fi
    while IFS= read -r e; do
        total=$((total + $(du -sk "$e" | awk '{print $1 * 1024}')))
    done < <(wp_lang_dirs "$d")
    printf '%s' "$total"
}

wp_lang_dirs() { # SRCDIR : top-level language directories (bootmgr's .mui messages), one per line
    find "$1" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | while IFS= read -r e; do
        case "$(basename "$e")" in
            [A-Za-z][A-Za-z]-*|[A-Za-z][A-Za-z][A-Za-z]-*|[a-z][a-z]-[a-z][a-z][a-z][a-z]-*) printf '%s\n' "$e";;
            *) ;;
        esac
    done | sort
}

wp_copy_media() { # SRCDIR IMAGE OFFSET_BYTES
    local d=$1 img=$2 off=$3 spec n e c target
    spec="$img@@$off"
    export MTOOLS_SKIP_CHECK=1
    for e in bootmgr bootmgr.efi; do
        if n=$(wp_find_ci "$d" "$e") && [ -f "$n" ]; then act mcopy -n -m -i "$spec" "$n" "::$e"; fi
    done
    for e in boot efi; do
        if n=$(wp_find_ci "$d" "$e") && [ -d "$n" ]; then
            target=$e
            if [ "$e" = efi ]; then target=EFI; fi
            act mmd -i "$spec" "::$target"
            for c in "$n"/*; do
                if [ -e "$c" ]; then act mcopy -s -n -m -i "$spec" "$c" "::$target/"; fi
            done
        fi
    done
    if n=$(wp_find_ci "$d" sources) && [ -d "$n" ] && n=$(wp_find_ci "$n" boot.wim); then
        act mmd -i "$spec" ::sources
        act mcopy -n -m -i "$spec" "$n" ::sources/boot.wim
    fi
    while IFS= read -r e; do
        [ -n "$e" ] || continue
        act mmd -i "$spec" "::$(basename "$e")"
        for c in "$e"/*; do
            if [ -e "$c" ]; then act mcopy -s -n -m -i "$spec" "$c" "::$(basename "$e")/"; fi
        done
    done < <(wp_lang_dirs "$d")
}

wp_write_boot_code() { # IMAGE START_SECTOR ms-sys-binary : the Windows MBR and the NT boot sector
    local img=$1 start=$2 bin=$3 help pbr
    help=$("$bin" --help 2>&1 || true)
    case "$help" in *--mbr7*) ;; *) die "$bin has no --mbr7 option (the Windows 7 MBR); see layout-bios.md for the Windows-side alternative (bootsect /nt60 X: /mbr)";; esac
    case "$help" in *--fat32pe*) ;; *) die "$bin has no --fat32pe option (the FAT32 boot record that loads bootmgr); see layout-bios.md (bootsect /nt60 X:)";; esac
    act "$bin" --mbr7 "$img"
    # ms-sys writes a boot record onto a partition: give it the first 16 sectors of ours as a small file and put them back
    pbr=$(mktemp "${TMPDIR:-/tmp}/winpe-pbr.XXXXXX")
    if [ "$wp_dry" = 1 ]; then
        echo "would run: dd of the first 16 sectors of the partition into a scratch file, $bin --fat32pe on it, dd back at sector $start"
        rm -f -- "$pbr"
        return 0
    fi
    dd if="$img" of="$pbr" bs=512 skip="$start" count=16 status=none
    "$bin" --fat32pe "$pbr"
    dd if="$pbr" of="$img" bs=512 seek="$start" count=16 conv=notrunc status=none
    rm -f -- "$pbr"
}

wp_build() {
    local layout="" media="" out="" size="" label=WINPE maxs=2G mssys=auto mssys_bin=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --layout) layout=${2:?}; shift 2;;
            --media) media=${2:?}; shift 2;;
            --out) out=${2:?}; shift 2;;
            --size) size=${2:?}; shift 2;;
            --label) label=${2:?}; shift 2;;
            --max-size) maxs=${2:?}; shift 2;;
            --ms-sys) mssys=${2:?}; shift 2;;
            --ms-sys-bin) mssys_bin=${2:?}; shift 2;;
            *) die "build: unknown option $1";;
        esac
    done
    case "$layout" in uefi|bios) ;; *) die "build: --layout uefi or bios is required";; esac
    [ -n "$media" ] && [ -n "$out" ] || die "build: --media and --out are required"
    [ -e "$media" ] || die "build: $media does not exist"
    case "$mssys" in auto|yes|no) ;; *) die "build: --ms-sys must be auto, yes or no";; esac
    [[ "$label" =~ ^[A-Za-z0-9_-]{1,11}$ ]] || die "build: the volume label is 1 to 11 of letters, digits, '_' and '-'"
    local maxb
    maxb=$(wp_to_bytes "$maxs")
    [ "$maxb" -le "$WP_MAX_BYTES" ] || die "build: --max-size over 2G: the lab images are at most 2 GiB"
    wp_check_untracked "$out"
    wp_check_untracked "$(wp_work)"
    [ ! -e "$out" ] || die "build: $out already exists; remove it yourself first (this script never overwrites an image)"

    wp_need truncate mkfs.fat mcopy mmd sfdisk
    [ "$layout" = uefi ] && wp_need sgdisk
    if [ "$wp_dry" = 0 ] && ! mkfs.fat --help 2>&1 | grep -q -- '--offset'; then
        die "build: this mkfs.fat has no --offset option (dosfstools 4.2 or newer is needed)"
    fi

    local src stage=""
    if [ -d "$media" ]; then
        src=$media
    else
        case "$media" in *.iso|*.ISO) ;; *) die "build: $media is neither a directory nor an .iso";; esac
        if [ "$wp_dry" = 1 ]; then
            src=""
            info "dry run: would extract $media into a scratch directory under $(wp_work)"
        else
            mkdir -p "$(wp_work)"
            stage=$(mktemp -d "$(wp_work)/stage.XXXXXX")
            # the scratch tree holds the media's files: it goes away on every way out (a failed check, a failed mkfs.fat, Ctrl-C)
            wp_stage=$stage
            trap wp_cleanup_stage EXIT
            wp_extract_iso "$media" "$stage"
            src=$stage
        fi
    fi

    # what must be there (the same list check-layout.sh insists on)
    if [ -n "$src" ]; then
        local miss=""
        wp_have_bootwim "$src" || miss="$miss sources/boot.wim"
        wp_find_ci "$src" boot >/dev/null || miss="$miss boot/"
        if [ "$layout" = uefi ]; then
            wp_find_ci "$src" efi >/dev/null || miss="$miss efi/"
        else
            wp_find_ci "$src" bootmgr >/dev/null || miss="$miss bootmgr"
        fi
        if [ -n "$miss" ]; then
            die "build: the media lacks:$miss. Pass the media root (the directory that holds bootmgr, boot, efi and sources), or an ISO of WinPE / Windows setup."
        fi
    fi

    # the size
    local payload=0 bytes
    if [ -n "$src" ]; then payload=$(wp_payload_bytes "$src"); fi
    if [ -n "$size" ]; then
        bytes=$(wp_to_bytes "$size")
    elif [ "$payload" -gt 0 ]; then
        bytes=$(((payload * 11 / 10 + 80 * 1048576 + 67108863) / 67108864 * 67108864))
        [ "$bytes" -ge 134217728 ] || bytes=134217728
    else
        bytes=1073741824
    fi
    if [ "$bytes" -gt "$maxb" ]; then
        die "build: the image would be $bytes bytes, over the limit $maxs (the payload is $payload bytes). Use a smaller boot.wim, or raise --max-size on purpose (the lab images are at most 2 GiB)"
    fi
    [ $((bytes % 1048576)) -eq 0 ] || die "build: --size must be a multiple of 1 MiB"
    [ "$bytes" -ge 67108864 ] || die "build: --size under 64 MiB"
    [ "$payload" -lt "$bytes" ] || die "build: the payload ($payload bytes) does not fit in $bytes bytes"
    info "layout $layout, image $((bytes / 1048576)) MiB, payload $((payload / 1048576)) MiB"

    # the disk
    mkdir -p "$(dirname "$out")"
    act truncate -s "$bytes" "$out"
    local sectors=$((bytes / 512)) start=2048 psize pstart
    if [ "$layout" = uefi ]; then
        act sgdisk -o -n "1:$start:0" -t 1:EF00 -c "1:EFI system partition" "$out"
    else
        if [ "$wp_dry" = 1 ]; then
            echo "would run: sfdisk $out <<< 'label: dos / start=2048, type=c, bootable' (with a random disk id)"
        else
            printf 'label: dos\nlabel-id: 0x%s\nunit: sectors\n\nstart=%s, type=c, bootable\n' \
                "$(od -An -N4 -tx4 /dev/urandom | tr -d ' \n')" "$start" | sfdisk --quiet "$out" >/dev/null
        fi
    fi
    if [ "$wp_dry" = 1 ]; then
        pstart=$start psize=$((sectors - start - 2048))
    else
        read -r pstart psize < <(wp_part_of "$out")
        [ -n "${pstart:-}" ] || die "build: cannot read the partition table back"
    fi
    # FAT32 inside it: 512-byte sectors, the hidden-sector count = the partition start, drive number 0x80 (BIOS)
    act mkfs.fat -F 32 -S 512 -h "$pstart" -D 0x80 -n "$label" --offset "$pstart" "$out" "$((psize / 2))"
    wp_copy_media "${src:-/nonexistent-dry-run}" "$out" "$((pstart * 512))"
    wp_cleanup_stage
    trap - EXIT

    # the BIOS boot code
    if [ "$layout" = bios ]; then
        local bin=""
        if [ "$mssys" != no ]; then bin=${mssys_bin:-$(command -v ms-sys || true)}; fi
        if [ -n "$bin" ]; then
            wp_write_boot_code "$out" "$pstart" "$bin"
        elif [ "$mssys" = yes ]; then
            die "build: --ms-sys yes but no ms-sys found"
        else
            info "no ms-sys: the image has NO boot code yet (check-layout.sh will say so). Write the Windows MBR and the NT 6 FAT32 boot sector with ms-sys, or on Windows with: bootsect /nt60 X: /mbr  (layout-bios.md)"
        fi
    fi
    wp_run_check "$layout" "$out"
}

wp_stage=""
wp_rm_stage() { # only a directory this script made, under the work directory
    local s=$1
    case "$s" in "$(wp_work)"/stage.*) ;; *) die "internal error: refusing to delete $s";; esac
    chmod -R u+rwX -- "$s" 2>/dev/null || true # media from a UDF image can come out read-only
    rm -rf -- "$s"
}
wp_cleanup_stage() { # idempotent; runs as the EXIT trap of build
    local s=$wp_stage
    wp_stage=""
    [ -z "$s" ] || wp_rm_stage "$s"
}

wp_run_check() { # LAYOUT IMAGE
    if [ "$wp_dry" = 1 ]; then echo "would run: $wp_here/check-layout.sh --layout $1 $2"; return 0; fi
    "$wp_here/check-layout.sh" --layout "$1" "$2" || die "the layout check failed (see FAIL lines above); the image is left at $2 for inspection"
}

# ---------------------------------------------------------------------------------------------------------------------
# convert
# ---------------------------------------------------------------------------------------------------------------------
wp_convert() {
    local layout="" disk="" out=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --layout) layout=${2:?}; shift 2;;
            --disk) disk=${2:?}; shift 2;;
            --out) out=${2:?}; shift 2;;
            *) die "convert: unknown option $1";;
        esac
    done
    case "$layout" in uefi|bios) ;; *) die "convert: --layout uefi or bios is required";; esac
    [ -n "$disk" ] && [ -n "$out" ] || die "convert: --disk and --out are required"
    [ -f "$disk" ] || die "convert: $disk is not a file"
    wp_check_untracked "$out"
    [ ! -e "$out" ] || die "convert: $out already exists; remove it yourself first"
    mkdir -p "$(dirname "$out")"
    # A fixed VHD is the raw disk followed by a 512-byte "conectix" footer: strip it here, the same way for every host. (qemu-img
    # decides by a probe that also checks the footer's checksum, and gives up on a footer it does not like, which would leave the
    # footer inside the "disk".) Any other format needs qemu-img.
    local sz head8 foot8 vtype
    sz=$(wp_size_of "$disk")
    foot8="" vtype=""
    if [ "$sz" -ge 1048576 ]; then
        foot8=$(dd if="$disk" bs=1 skip=$((sz - 512)) count=8 status=none | od -An -tx1 | tr -d ' \n')
        vtype=$(dd if="$disk" bs=1 skip=$((sz - 512 + 60)) count=4 status=none | od -An -tx1 | tr -d ' \n')
    fi
    head8=$(dd if="$disk" bs=1 count=8 status=none | od -An -tx1 | tr -d ' \n')
    if [ "$foot8" = 636f6e6563746978 ] && [ "$vtype" = 00000002 ]; then
        info "fixed VHD: the 512-byte footer is dropped"
        act cp --sparse=always -- "$disk" "$out"
        act truncate -s "$((sz - 512))" "$out"
    elif [ "$foot8" = 636f6e6563746978 ] || [ "$head8" = 636f6e6563746978 ] || [ "${head8:0:6}" = 514649 ] || [ "$head8" = 7668647866696c65 ]; then
        # a dynamic or differencing VHD (the footer is also copied to the start), a qcow2 ("QFI"), a VHDX ("vhdxfile")
        command -v qemu-img >/dev/null 2>&1 || die "convert: $disk is a dynamic VHD, a VHDX or a qcow2: qemu-img is needed to read it"
        # the format is named, never probed (a probe on file contents can be steered by the contents), and an image that reads other
        # files through a backing chain (a qcow2 overlay, a differencing VHD) is refused: its bytes are not all in this file
        local fmt=vpc qinfo=""
        if [ "${head8:0:6}" = 514649 ]; then fmt=qcow2; elif [ "$head8" = 7668647866696c65 ]; then fmt=vhdx; fi
        if [ "$foot8" = 636f6e6563746978 ] && [ "$vtype" = 00000004 ]; then
            die "convert: $disk is a differencing VHD (it has a parent disk): it is not a complete disk. Merge it on Windows first (Merge-VHD), or export the whole disk"
        fi
        qinfo=$(qemu-img info -f "$fmt" "$disk" 2>/dev/null || true) # captured, not piped: grep -q would close the pipe early
        case "$qinfo" in
            *$'\n'"backing file:"*|"backing file:"*) die "convert: $disk has a backing file: it is not a complete disk. Flatten it first (qemu-img convert -O $fmt) on a machine that has the whole chain";; *) ;; esac
        act qemu-img convert -f "$fmt" -O raw -S 4k "$disk" "$out"
    else
        info "no VHD, VHDX or qcow2 signature: taking $disk as a raw image"
        act cp --sparse=always -- "$disk" "$out"
    fi
    wp_run_check "$layout" "$out"
}

# ---------------------------------------------------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------------------------------------------------
wp_norm_name() { # NAME -> wrtest-...  (the rule of users.sh)
    local n=$1
    case "$n" in wrtest-*) ;; *) n=wrtest-p2-$n;; esac
    [[ "$n" =~ ^wrtest-[a-z0-9][a-z0-9-]{0,39}$ ]] || die "bad name '$1': lower-case letters, digits and '-', at most 40 characters after wrtest-"
    printf '%s' "$n"
}

wp_load_cluster() { # the lab library; honours the dry-run flag
    # selftest.sh sources the library first and replaces the functions that talk to the VM: do not load it again over them
    if ! declare -F p2_init >/dev/null; then
        # shellcheck source=../cluster/up.sh
        . "$wp_here/../cluster/up.sh"
    fi
    if [ "$wp_dry" = 1 ]; then P2_DRY_RUN=1; export P2_DRY_RUN; fi
    p2_init
}

wp_import() {
    local layout="" image="" name="" pool="" features="" replace=0 snap=1 verify=1
    while [ $# -gt 0 ]; do
        case "$1" in
            --layout) layout=${2:?}; shift 2;;
            --image) image=${2:?}; shift 2;;
            --name) name=${2:?}; shift 2;;
            --pool) pool=${2:?}; shift 2;;
            --features) features=${2:?}; shift 2;;
            --replace) replace=1; shift;;
            --no-snapshot) snap=0; shift;;
            --no-verify) verify=0; shift;;
            *) die "import: unknown option $1";;
        esac
    done
    case "$layout" in uefi|bios) ;; *) die "import: --layout uefi or bios is required";; esac
    [ -n "$image" ] && [ -n "$name" ] || die "import: --image and --name are required"
    [ -f "$image" ] || die "import: $image is not a file"
    [[ "$features" =~ ^[a-z0-9,-]*$ ]] || die "import: bad --features list"
    local img
    img=$(wp_norm_name "$name")

    # A fixed VHD is a multiple of 512 bytes too, and check-layout.sh accepts it (it knows the footer): imported as it is, the footer would
    # become the last sector of the RBD disk and push the backup GPT one sector off the end. Only a raw image goes into the cluster.
    local fsz
    fsz=$(wp_size_of "$image")
    if [ "$fsz" -ge 1048576 ] && [ "$(dd if="$image" bs=1 skip=$((fsz - 512)) count=8 status=none | od -An -tx1 | tr -d ' \n')" = 636f6e6563746978 ]; then
        die "import: $image ends in a VHD footer ('conectix'): run 'import-winpe.sh convert' first and import its raw output"
    fi

    # the layout check comes first and is not optional
    if [ "$wp_dry" = 1 ]; then
        echo "would run: $wp_here/check-layout.sh --layout $layout $image"
    else
        "$wp_here/check-layout.sh" --layout "$layout" "$image" || die "the layout check failed: nothing was imported"
    fi
    local bytes mb
    bytes=$(wp_size_of "$image")
    [ "$bytes" -le "$WP_MAX_BYTES" ] || die "import: $image is over 2 GiB"
    [ $((bytes % 512)) -eq 0 ] || die "import: the image size is not a multiple of 512 (a fixed VHD? run convert first)"
    mb=$(((bytes + 1048575) / 1048576))

    wp_load_cluster
    [ -n "$pool" ] || pool=$LAB_POOL
    if [ "$pool" != "$LAB_POOL" ]; then
        case "$pool" in wrtest-*) ;; *) die "import: pool '$pool' is not the lab pool ($LAB_POOL) and not a wrtest-* pool";; esac
    fi
    [[ "$pool" =~ ^[A-Za-z0-9_-]{1,64}$ ]] || die "import: bad pool name '$pool'"
    if [ "$wp_dry" = 0 ]; then
        [ -n "$(p2_vm_pid || true)" ] || die "the lab VM is not running; run harness/lab/p2/cluster/up.sh"
        p2_ssh_ok || die "the lab VM does not answer on ssh yet"
    fi

    local users="${WINPE_USERS_SH:-$wp_here/../cluster/users.sh}"
    if [ "$wp_dry" = 0 ] && vm sudo rbd info "$pool/$img" >/dev/null 2>&1; then
        if [ "$replace" = 1 ]; then
            info "replacing the existing image $pool/$img (and its user): users.sh delete"
            "$users" delete "$img" || die "could not delete the old image"
        else
            die "image $pool/$img exists; use --replace to delete it and its user first (wrtest-* objects only)"
        fi
    fi

    local sum="" got
    local gz=(gzip -1 -c)
    sum=$(wp_sha256 "$image")
    info "importing $image ($((bytes / 1048576)) MiB, sha256 ${sum:0:12}...) into $pool/$img"
    local feat_args=""
    [ -z "$features" ] || feat_args="--image-feature $features"
    if [ "$wp_dry" = 1 ]; then
        echo "would run: ${gz[*]} $image | ssh VM: gzip -dc | sudo rbd import --image-format 2 $feat_args - $pool/$img"
        vm sudo rbd info "$pool/$img"
    else
        "${gz[@]}" -- "$image" | vm_stdin sudo bash -c "set -o pipefail; gzip -dc | rbd import --image-format 2 $feat_args - $pool/$img" \
            || die "rbd import failed; the partial image $pool/$img may exist: users.sh delete ${img#wrtest-p2-}"
    fi
    if [ "$verify" = 1 ]; then
        if [ "$wp_dry" = 1 ]; then
            echo "would run in the VM: rbd export $pool/$img - | sha256sum, and compare with $sum"
        else
            got=$(vm sudo bash -c "rbd export $pool/$img - | sha256sum" | awk '{print $1}')
            if [ "$got" != "$sum" ]; then
                die "the image read back from the cluster differs (sha256 ${got:0:12}... instead of ${sum:0:12}...): do not use it; users.sh delete ${img#wrtest-p2-}"
            fi
            info "read back from the cluster: sha256 matches"
        fi
    fi
    # the per-image cephx user (limited to this pool) and the key files; the image exists, so only the user is made
    local uargs=(create "$img" --pool "$pool" --size "${mb}M")
    [ -z "$features" ] || uargs+=(--features "$features")
    if [ "$wp_dry" = 1 ]; then
        echo "would run: $users -n ${uargs[*]}"
    else
        "$users" "${uargs[@]}" || die "users.sh create failed"
    fi
    if [ "$snap" = 1 ]; then
        vm sudo rbd snap create "$pool/$img@pristine"
        info "snapshot $pool/$img@pristine taken; before a row: rbd snap rollback $pool/$img@pristine"
    fi
    info "done: image $pool/$img, user client.$img (key files in the lab keys directory, mode 600, not printed)"
    info "next: boot it with   rbd://$img@${LAB_PRIV_CIDR%/*}/$pool/$img   (run-rows.md)"
}

wp_all() {
    local layout="" media="" disk="" name="" size="" pool="" replace=0 features=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --layout) layout=${2:?}; shift 2;;
            --media) media=${2:?}; shift 2;;
            --disk) disk=${2:?}; shift 2;;
            --name) name=${2:?}; shift 2;;
            --size) size=${2:?}; shift 2;;
            --pool) pool=${2:?}; shift 2;;
            --features) features=${2:?}; shift 2;;
            --replace) replace=1; shift;;
            *) die "all: unknown option $1";;
        esac
    done
    [ -n "$name" ] || die "all: --name is required"
    [ -n "$media" ] || [ -n "$disk" ] || die "all: --media or --disk is required"
    [ -z "$media" ] || [ -z "$disk" ] || die "all: --media or --disk, not both"
    local out
    out=$(wp_work)/$(wp_norm_name "$name").raw
    mkdir -p "$(wp_work)"
    if [ -n "$media" ]; then
        local a=(--layout "$layout" --media "$media" --out "$out")
        [ -z "$size" ] || a+=(--size "$size")
        wp_build "${a[@]}"
    else
        wp_convert --layout "$layout" --disk "$disk" --out "$out"
    fi
    local b=(--layout "$layout" --image "$out" --name "$name")
    [ -z "$pool" ] || b+=(--pool "$pool")
    [ -z "$features" ] || b+=(--features "$features")
    [ "$replace" = 0 ] || b+=(--replace)
    wp_import "${b[@]}"
}

wp_usage() { sed -n '4,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }

wp_main() {
    local args=() a
    for a in "$@"; do
        case "$a" in
            -n|--dry-run) wp_dry=1;;
            -h|--help) wp_usage;;
            *) args+=("$a");;
        esac
    done
    [ "${#args[@]}" -ge 1 ] || wp_usage
    local cmd=${args[0]}
    case "$cmd" in
        build)   wp_build "${args[@]:1}";;
        convert) wp_convert "${args[@]:1}";;
        import)  wp_import "${args[@]:1}";;
        all)     wp_all "${args[@]:1}";;
        *) wp_usage;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    wp_main "$@"
fi
