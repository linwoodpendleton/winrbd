#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-bios.sh - the BIOS Linux guest images of the live test matrix (docs/design/ipxe-driver.md, 14.3). Two kinds:
#
#   (default)  linux-bios.raw   a raw disk of 2 GiB, MBR, one ext4 partition "wrbroot" (active): Ubuntu minbase + kernel, grub-pc in the
#              MBR gap, an initramfs with the kernel client (rbd, libceph) and the boot hook that finds the rBFT table by a scan of low
#              memory (/dev/mem with iomem=relaxed; the table is in iPXE's resident area, not in an RSDT), checks every field, brings the
#              NIC up from it and maps the image. Rows B1, B2, B3.
#   --tiny     b0-tiny.raw      a disk of 96 MiB for row B0 ("sanhook --drive 0x81" and boot a small local disk): grub-pc, the same kernel
#              and an initramfs that is the whole system (busybox, the checker, the same hook and marker; edd.ko for the BIOS drive list).
#              It prints the BIOS drives (/sys/firmware/edd), checks the table, prints the marker and powers off. No cluster needed.
#
# Run it as root where loop devices, debootstrap, sfdisk, mkfs.ext4, grub-install (i386-pc), cpio and gcc with static glibc exist: the
# builder guest (harness/lab/p2/builder). It re-runs itself with sudo.
#
#   build-bios.sh [-n] [--tiny] [--out FILE] [--force] [--size MIB] [--mirror URL] [--release NAME]
#
#   -n, --dry-run   check the options and the tools and print the plan; change nothing
#   --out FILE      the image (default $IMG_WORK/out/linux-bios.raw or b0-tiny.raw); FILE.manifest is written next to it
#   --force         replace an existing image
#   --size MIB      1024 to 2048 for the full image (default 2048); the tiny image is always 96 MiB
#   --mirror URL / --release NAME   as in build-uefi.sh
# Environment: IMG_WORK (default /var/tmp/winrbd-p2-images), IMG_MIRROR, IMG_RELEASE, IMG_SIZE_MB, IMG_PACKAGES. Both kinds share the
# base system cache of build-uefi.sh. Never committed (the output path is checked against .gitignore); no key inside.
# shellcheck disable=SC2031  # IMG_CLEAN is changed in subshells on purpose (the base is built in one)
set -euo pipefail

IMG_PROG=build-bios.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=initramfs/lib/image-common.sh
. "$here/initramfs/lib/image-common.sh"

orig_args=("$@") # for the re-run as root: the option loop below shifts "$@" away
out=
force=0
tiny=0
usage() { sed -n '3,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
	case $1 in
	-n | --dry-run) IMG_DRY=1; shift ;;
	--tiny) tiny=1; shift ;;
	--out) [ $# -ge 2 ] || img_die "--out needs a value"; out=$2; shift 2 ;;
	--force) force=1; shift ;;
	--size) [ $# -ge 2 ] || img_die "--size needs a value"; IMG_SIZE_MB=$2; shift 2 ;;
	--mirror) [ $# -ge 2 ] || img_die "--mirror needs a value"; IMG_MIRROR=$2; shift 2 ;;
	--release) [ $# -ge 2 ] || img_die "--release needs a value"; IMG_RELEASE=$2; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; img_die "unknown option '$1'" ;;
	esac
done
case $IMG_RELEASE in *[!a-z]* | '') img_die "--release must be a release name such as noble" ;; esac
case $IMG_MIRROR in http://* | https://*) ;; *) img_die "--mirror must be an http(s) URL" ;; esac
if [ "$tiny" = 1 ]; then
	IMG_SIZE_MB=96
	[ -n "$out" ] || out=$IMG_WORK/out/b0-tiny.raw
else
	img_size_check
	[ -n "$out" ] || out=$IMG_WORK/out/linux-bios.raw
fi
case $out in /*) ;; *) out=$PWD/$out ;; esac
img_check_untracked "$out"

img_need_tools debootstrap sfdisk losetup mkfs.ext4 mkfs.ext2 grub-install gcc tar zstd e2fsck fallocate truncate sha256sum mount umount chroot cpio gzip
if [ -e "$out" ] && [ "$force" != 1 ]; then img_die "$out exists (--force replaces it)"; fi
[ -d "${IMG_GRUB_DIR:-/usr/lib/grub}/i386-pc" ] || [ "$IMG_DRY" = 1 ] || img_die "grub for i386-pc is missing (package grub-pc-bin)"

if [ "$IMG_DRY" = 1 ]; then
	if [ "$tiny" = 1 ]; then
		cat <<PLAN
build-bios.sh: plan for the tiny image of row B0 (nothing is changed)
  1. the base system of build-uefi.sh (cached under $IMG_WORK/cache/): only its kernel, busybox and edd / qemu_fw_cfg modules are used
  2. build the static table checker; an initramfs (cpio, gzip) with busybox, init, the checker, local-top/rbft, wrboot-marker, edd.ko
  3. $out: 96 MiB raw, MBR, p1 ext2 "wrbtiny" (active); grub-install --target=i386-pc; kernel + initramfs in /boot
  4. e2fsck -fn, dig holes, write $out.manifest
PLAN
	else
		cat <<PLAN
build-bios.sh: plan (nothing is changed)
  1. base system: debootstrap $IMG_RELEASE (minbase) from $IMG_MIRROR + packages, cached under $IMG_WORK/cache/ (shared with build-uefi.sh)
  2. build the static table checker (gcc -static) from initramfs/rbft-check/rbft-check.c
  3. $out: ${IMG_SIZE_MB} MiB raw, MBR: p1 $IMG_ROOT_LABEL ext4 (UUID $IMG_ROOT_UUID, active) from 1 MiB
  4. unpack the base into p1, install the hook / checker / marker / initramfs (MODULES=list, zstd), fstab, grub.cfg (rbft.rootpart=1)
  5. grub-install --target=i386-pc (core image in the MBR gap), boot files in p1:/boot
  6. unmount, e2fsck -fn, dig holes, write $out.manifest
PLAN
	fi
	exit 0
fi

img_need_root ${orig_args[@]+"${orig_args[@]}"}
img_traps
mkdir -p "$IMG_WORK/out" "$IMG_WORK/tmp" "$IMG_WORK/cache"
base=$(img_base)
[ -s "$base" ] || img_die "no base system tarball"

checker=$IMG_WORK/tmp/rbft-check.$$
img_defer "rm -f $(printf '%q' "$checker")"
img_build_checker "$checker"

part=$out.part
img_defer "rm -f $(printf '%q' "$part") $(printf '%q' "$part.manifest")"
rm -f "$part"
truncate -s "${IMG_SIZE_MB}M" "$part"

GRUB_MODULES="part_msdos ext2 search_label configfile normal linux linux16 serial terminal echo test biosdisk"
gilog=$IMG_WORK/tmp/grub-install.$$.log
img_defer "rm -f $(printf '%q' "$gilog")"
run_grub_install() { # MOUNTPOINT
	grub-install --target=i386-pc --boot-directory="$1/boot" --modules="$GRUB_MODULES" --no-floppy "$IMG_LOOP" > "$gilog" 2>&1 \
		|| { cat "$gilog" >&2; img_die "grub-install failed"; }
}

if [ "$tiny" = 1 ]; then
	# ---- B0: an initramfs that is the whole system -------------------------------------------------------------------------
	scratch=$IMG_WORK/tmp/tiny-$$.ext4
	img_defer "rm -f $(printf '%q' "$scratch")"
	truncate -s 400M "$scratch"
	mkfs.ext4 -F -q -m 0 -O ^has_journal "$scratch"
	smark=${#IMG_CLEAN[@]}
	img_losetup "$scratch"
	w=''
	img_mktemp_dir tinywork w
	img_mount "$IMG_LOOP" "$w"
	# what the tiny system takes from the base: the kernel, busybox, two modules
	tar -I zstd -tf "$base" > "$w/.list"
	bb=$(grep -E '^\./(usr/)?bin/busybox$' "$w/.list" | head -n 1 || true)
	kv=$(grep -E '^\./boot/vmlinuz-[0-9]' "$w/.list" | sed 's|^\./boot/vmlinuz-||' | sort -V | tail -n 1)
	[ -n "$bb" ] || img_die "no busybox in the base system (package busybox-static)"
	[ -n "$kv" ] || img_die "no kernel in the base system"
	edd=$(grep -E "^\./(usr/)?lib/modules/$kv/kernel/drivers/firmware/edd\.ko" "$w/.list" | head -n 1 || true)
	fwc=$(grep -E "^\./(usr/)?lib/modules/$kv/kernel/drivers/firmware/qemu_fw_cfg\.ko" "$w/.list" | head -n 1 || true)
	if [ -z "$edd" ] && ! tar -I zstd -xOf "$base" "./usr/lib/modules/$kv/modules.builtin" 2> /dev/null | grep -q '/edd\.ko$'; then
		img_info "warning: this kernel has no edd, neither as a module nor built in: the BIOS drive list will be missing"
	fi
	sel=("./boot/vmlinuz-$kv" "$bb")
	[ -z "$edd" ] || sel+=("$edd")
	[ -z "$fwc" ] || sel+=("$fwc")
	tar -I zstd -C "$w" -xpf "$base" "${sel[@]}"
	IMG_KVER=$kv
	t=$w/tree
	install -d "$t/bin" "$t/dev" "$t/proc" "$t/sys" "$t/lib/modules" "$t/scripts/local-top" "$t/usr/local/sbin" "$t/run" "$t/tmp" "$t/etc"
	install -m 0755 "$w/$bb" "$t/bin/busybox"
	install -m 0755 "$IMG_SRC_DIR/tiny/init" "$t/init"
	install -m 0755 "$IMG_SRC_DIR/scripts/local-top/rbft" "$t/scripts/local-top/rbft"
	install -m 0755 "$IMG_SRC_DIR/system/wrboot-marker" "$t/usr/local/sbin/wrboot-marker"
	install -m 0755 "$checker" "$t/usr/local/sbin/rbft-check"
	if [ -n "$edd" ]; then zstd -d -q -c "$w/$edd" > "$t/lib/modules/edd.ko" 2> /dev/null || cp "$w/$edd" "$t/lib/modules/edd.ko"; fi
	if [ -n "$fwc" ]; then zstd -d -q -c "$w/$fwc" > "$t/lib/modules/qemu_fw_cfg.ko" 2> /dev/null || cp "$w/$fwc" "$t/lib/modules/qemu_fw_cfg.ko"; fi
	(cd "$t" && find . | cpio -o -H newc --quiet | gzip -9 > "$w/tiny.initrd")
	img_info "tiny initramfs: $(stat -c %s "$w/tiny.initrd") bytes"

	sfdisk -q "$part" <<SFD
label: dos
label-id: 0x7d1f0001
start=2048, type=83, bootable
SFD
	lmark=${#IMG_CLEAN[@]}
	img_losetup "$part"
	img_wait_part 1
	mkfs.ext2 -F -q -L wrbtiny "${IMG_LOOP}p1"
	mnt=''
	tmark=${#IMG_CLEAN[@]}
	img_mktemp_dir tiny mnt
	img_mount "${IMG_LOOP}p1" "$mnt"
	install -d "$mnt/boot/grub"
	install -m 0644 "$w/boot/vmlinuz-$kv" "$mnt/boot/vmlinuz-$kv"
	install -m 0644 "$w/tiny.initrd" "$mnt/boot/tiny.initrd"
	cat > "$mnt/boot/grub/grub.cfg" <<GRUBCFG
# generated by build-bios.sh --tiny (harness/lab/p2/images)
set default=0
set timeout=1
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console
search --no-floppy --label wrbtiny --set=root
set rbft_extra=""
if [ -f /boot/grub/rbft-extra.cfg ]; then source /boot/grub/rbft-extra.cfg; fi
menuentry 'winrbd tiny (row B0)' {
    linux16 /boot/vmlinuz-$kv console=tty0 console=ttyS0,115200n8 iomem=relaxed edd=on loglevel=4 rbft.hook=1 rbft.map=0 rbft.src=scan rbft.waitnic=0 \$rbft_extra
    initrd16 /boot/tiny.initrd
}
GRUBCFG
	run_grub_install "$mnt"
	{
		echo "# winrbd p2 image manifest (not secret)"
		echo "kind=bios-tiny"
		echo "release=$IMG_RELEASE"
		echo "kernel=$kv"
		echo "size_bytes=$(stat -c %s "$part")"
		echo "root_label=wrbtiny"
		printf 'file=boot/vmlinuz-%s %s\n' "$kv" "$(img_sha256 "$mnt/boot/vmlinuz-$kv")"
		printf 'file=boot/tiny.initrd %s\n' "$(img_sha256 "$mnt/boot/tiny.initrd")"
		printf 'file=boot/grub/grub.cfg %s\n' "$(img_sha256 "$mnt/boot/grub/grub.cfg")"
	} > "$part.manifest"
	sync
	img_cleanup_to "$tmark" # unmounts (and removes the mount point): the deferred umount must not run a second time
	e2fsck -fn "${IMG_LOOP}p1" > /dev/null || img_die "e2fsck found problems in the tiny disk"
	img_info "file system is clean"
	img_cleanup_to "$lmark"
	img_cleanup_to "$smark"
else
	# ---- the full image -------------------------------------------------------------------------------------------------
	sfdisk -q "$part" <<SFD
label: dos
label-id: 0x7d1f0002
start=2048, type=83, bootable
SFD
	lmark=${#IMG_CLEAN[@]}
	img_losetup "$part"
	img_wait_part 1
	if ! mkfs.ext4 -F -q -L "$IMG_ROOT_LABEL" -U "$IMG_ROOT_UUID" -O ^orphan_file "${IMG_LOOP}p1" 2> /dev/null; then
		mkfs.ext4 -F -q -L "$IMG_ROOT_LABEL" -U "$IMG_ROOT_UUID" "${IMG_LOOP}p1"
	fi
	mark=${#IMG_CLEAN[@]}
	mnt=''
	img_mktemp_dir root mnt
	img_mount "${IMG_LOOP}p1" "$mnt"
	tar --numeric-owner --xattrs --acls -C "$mnt" -I zstd -xpf "$base"
	install -d "$mnt/proc" "$mnt/sys" "$mnt/dev" "$mnt/run"
	img_chroot_mounts "$mnt"
	img_install_guest "$mnt" "$checker"
	img_write_fstab "$mnt" ""
	install -d "$mnt/boot/grub"
	img_write_grub_cfg "$mnt/boot/grub/grub.cfg" 1 "$IMG_KVER" "" 16
	run_grub_install "$mnt"
	img_write_manifest "$part" "$mnt" bios
	sync
	img_cleanup_to "$mark"
	e2fsck -fn "${IMG_LOOP}p1" > /dev/null || img_die "e2fsck found problems in the finished root file system"
	img_info "file system is clean"
	sync
	img_cleanup_to "$lmark"
fi
fallocate --dig-holes "$part"
mv "$part" "$out"
mv "$part.manifest" "$out.manifest"
printf 'image_sha256=%s\n' "$(img_sha256 "$out")" >> "$out.manifest"
img_info "done: $out ($(du -h --apparent-size "$out" | cut -f1) apparent, $(du -h "$out" | cut -f1) on disk)"
img_info "manifest: $out.manifest"
