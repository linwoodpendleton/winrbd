#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-uefi.sh - the UEFI Linux guest image of the live test matrix (docs/design/ipxe-driver.md, 14.3): a raw disk of 2 GiB with
#
#   GPT   p1 "WRBESP"  128 MiB FAT32, EFI/BOOT/BOOTX64.EFI (grub, the removable path: no NVRAM entry needed, firmware and iPXE find it)
#         p2 "wrbroot" ext4 root: Ubuntu minbase + kernel, grub.cfg, an initramfs with the kernel client (rbd, libceph) and the
#         boot hook that reads and checks the rBFT table, brings the NIC up from it and maps the image
#
# Run it as root where loop devices, debootstrap, sgdisk, mkfs.ext4, mkfs.vfat, grub-install (x86_64-efi) and gcc with static glibc
# exist: the builder guest (harness/lab/p2/builder, "up.sh put" / "up.sh ssh"), never on a workstation. It re-runs itself with sudo.
#
#   build-uefi.sh [-n] [--out FILE] [--force] [--size MIB] [--mirror URL] [--release NAME] [--base-only]
#
#   -n, --dry-run   check the options and the tools and print the plan; change nothing
#   --out FILE      the image (default $IMG_WORK/out/linux-uefi.raw); FILE.manifest is written next to it
#   --force         replace an existing image
#   --size MIB      1024 to 2048 (default 2048)
#   --mirror URL    the Ubuntu archive (default $IMG_MIRROR, http://archive.ubuntu.com/ubuntu)
#   --release NAME  the Ubuntu release (default noble, the 6.8 kernel that the lab's krbd oracle runs)
#   --base-only     only make (and cache) the base system
# Environment: IMG_WORK (default /var/tmp/winrbd-p2-images: cache/ out/ tmp/), IMG_MIRROR, IMG_RELEASE, IMG_SIZE_MB, IMG_PACKAGES.
# The image holds no key and no address of a real machine; it is never committed (the output path is checked against .gitignore).
# shellcheck disable=SC2031  # IMG_CLEAN is changed in subshells on purpose (the base is built in one)
set -euo pipefail

IMG_PROG=build-uefi.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=initramfs/lib/image-common.sh
. "$here/initramfs/lib/image-common.sh"

orig_args=("$@") # for the re-run as root: the option loop below shifts "$@" away
out=
force=0
base_only=0
usage() { sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
	case $1 in
	-n | --dry-run) IMG_DRY=1; shift ;;
	--out) [ $# -ge 2 ] || img_die "--out needs a value"; out=$2; shift 2 ;;
	--force) force=1; shift ;;
	--size) [ $# -ge 2 ] || img_die "--size needs a value"; IMG_SIZE_MB=$2; shift 2 ;;
	--mirror) [ $# -ge 2 ] || img_die "--mirror needs a value"; IMG_MIRROR=$2; shift 2 ;;
	--release) [ $# -ge 2 ] || img_die "--release needs a value"; IMG_RELEASE=$2; shift 2 ;;
	--base-only) base_only=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; img_die "unknown option '$1'" ;;
	esac
done
case $IMG_RELEASE in *[!a-z]* | '') img_die "--release must be a release name such as noble" ;; esac
case $IMG_MIRROR in http://* | https://*) ;; *) img_die "--mirror must be an http(s) URL" ;; esac
img_size_check
[ -n "$out" ] || out=$IMG_WORK/out/linux-uefi.raw
case $out in /*) ;; *) out=$PWD/$out ;; esac
img_check_untracked "$out"

img_need_tools debootstrap sgdisk losetup mkfs.ext4 mkfs.vfat grub-install gcc tar zstd e2fsck fallocate truncate sha256sum mount umount chroot
if [ -e "$out" ] && [ "$force" != 1 ] && [ "$base_only" != 1 ]; then img_die "$out exists (--force replaces it)"; fi
[ -d "${IMG_GRUB_DIR:-/usr/lib/grub}/x86_64-efi" ] || [ "$IMG_DRY" = 1 ] || img_die "grub for x86_64-efi is missing (package grub-efi-amd64-bin)"

if [ "$IMG_DRY" = 1 ]; then
	cat <<PLAN
build-uefi.sh: plan (nothing is changed)
  1. base system: debootstrap $IMG_RELEASE (minbase) from $IMG_MIRROR + packages, cached under $IMG_WORK/cache/
  2. build the static table checker (gcc -static) from initramfs/rbft-check/rbft-check.c
  3. $out: ${IMG_SIZE_MB} MiB raw, GPT: p1 WRBESP 128 MiB FAT32 (ef00), p2 $IMG_ROOT_LABEL ext4 (UUID $IMG_ROOT_UUID)
  4. unpack the base into p2, install the hook / checker / marker / initramfs (MODULES=list, zstd), fstab, grub.cfg
  5. grub-install --target=x86_64-efi --removable into p1 (EFI/BOOT/BOOTX64.EFI), boot files in p2:/boot
  6. unmount, e2fsck -fn, dig holes (sparse file), write $out.manifest (sha256 of the kernel, initramfs, grub.cfg, checker)
PLAN
	exit 0
fi

img_need_root ${orig_args[@]+"${orig_args[@]}"}
img_traps
mkdir -p "$IMG_WORK/out" "$IMG_WORK/tmp" "$IMG_WORK/cache"
base=$(img_base)
[ "$base_only" != 1 ] || { img_info "base system: $base"; exit 0; }
[ -s "$base" ] || img_die "no base system tarball"

checker=$IMG_WORK/tmp/rbft-check.$$
img_defer "rm -f $(printf '%q' "$checker")"
img_build_checker "$checker"

part=$out.part
img_defer "rm -f $(printf '%q' "$part") $(printf '%q' "$part.manifest")"
rm -f "$part"
truncate -s "${IMG_SIZE_MB}M" "$part"
# 1 MiB aligned; p1 = ESP, p2 = the rest
sgdisk -o -U "$IMG_DISK_GUID" \
	-n 1:2048:+128M -t 1:ef00 -c 1:wrbesp \
	-n 2:0:0 -t 2:8300 -c 2:wrbroot "$part" > /dev/null
lmark=${#IMG_CLEAN[@]}
img_losetup "$part"
img_wait_part 1
img_wait_part 2
mkfs.vfat -F 32 -n "$IMG_ESP_LABEL" "${IMG_LOOP}p1" > /dev/null
if ! mkfs.ext4 -F -q -L "$IMG_ROOT_LABEL" -U "$IMG_ROOT_UUID" -O ^orphan_file "${IMG_LOOP}p2" 2> /dev/null; then
	mkfs.ext4 -F -q -L "$IMG_ROOT_LABEL" -U "$IMG_ROOT_UUID" "${IMG_LOOP}p2"
fi

mark=${#IMG_CLEAN[@]}
mnt=''
img_mktemp_dir root mnt
img_mount "${IMG_LOOP}p2" "$mnt"
install -d "$mnt/boot/efi"
img_mount "${IMG_LOOP}p1" "$mnt/boot/efi"
tar --numeric-owner --xattrs --acls -C "$mnt" -I zstd -xpf "$base"
# the tar has /boot/efi as an (empty) directory: the ESP is mounted over it
install -d "$mnt/proc" "$mnt/sys" "$mnt/dev" "$mnt/run"
img_chroot_mounts "$mnt"
img_install_guest "$mnt" "$checker"
img_write_fstab "$mnt" "LABEL=$IMG_ESP_LABEL /boot/efi vfat umask=0077,nofail 0 0"
install -d "$mnt/boot/grub"
img_write_grub_cfg "$mnt/boot/grub/grub.cfg" 2 "$IMG_KVER" ""
# the host's grub: no probing of the guest's disks, the removable path, no NVRAM write (there is none in a loop device)
grub-install --target=x86_64-efi --efi-directory="$mnt/boot/efi" --boot-directory="$mnt/boot" --removable --no-nvram \
	--no-uefi-secure-boot --modules="part_gpt part_msdos ext2 fat search search_label configfile normal linux serial terminal echo test" \
	> "$IMG_WORK/tmp/grub-install.$$.log" 2>&1 || { cat "$IMG_WORK/tmp/grub-install.$$.log" >&2; rm -f "$IMG_WORK/tmp/grub-install.$$.log"; img_die "grub-install failed"; }
rm -f "$IMG_WORK/tmp/grub-install.$$.log"
[ -s "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI" ] || img_die "grub-install made no EFI/BOOT/BOOTX64.EFI"
img_info "ESP: $(stat -c %s "$mnt/boot/efi/EFI/BOOT/BOOTX64.EFI") bytes in EFI/BOOT/BOOTX64.EFI"
img_write_manifest "$part" "$mnt" uefi
sync
img_cleanup_to "$mark"
e2fsck -fn "${IMG_LOOP}p2" > /dev/null || img_die "e2fsck found problems in the finished root file system"
fsck.vfat -n "${IMG_LOOP}p1" > /dev/null || img_die "fsck.vfat found problems in the ESP"
img_info "file systems are clean"
sync
# detach the loop device; then dig holes
img_cleanup_to "$lmark"
fallocate --dig-holes "$part"
mv "$part" "$out"
mv "$part.manifest" "$out.manifest"
{ printf 'image_sha256=%s\n' "$(img_sha256 "$out")"; } >> "$out.manifest"
img_info "done: $out ($(du -h --apparent-size "$out" | cut -f1) apparent, $(du -h "$out" | cut -f1) on disk)"
img_info "manifest: $out.manifest"
