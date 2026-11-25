# SPDX-License-Identifier: MIT
# shellcheck shell=bash
# shellcheck disable=SC2034  # the variables are used by the scripts that source this file
#
# image-common.sh - what build-uefi.sh and build-bios.sh share (sourced, not run).
#
# They run as root on a Linux machine with loop devices, debootstrap, sgdisk / sfdisk, mkfs.ext4 / mkfs.vfat, grub (the host's:
# grub-install from grub-pc-bin and grub-efi-amd64-bin) and gcc with static glibc: the builder guest of harness/lab/p2/builder. They
# make raw disk images of an Ubuntu minbase system with the kernel client in the initramfs and the table-checking boot hook.
#
# Nothing here removes a directory tree: the system is built inside an ext4 image file that is deleted as a file, and every mount point
# is an empty directory made by mktemp that is removed with rmdir after the unmount.

IMG_LIB_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMG_SRC_DIR=$(cd "$IMG_LIB_DIR/.." && pwd) # harness/lab/p2/images/initramfs

: "${IMG_RELEASE:=noble}"
: "${IMG_MIRROR:=http://archive.ubuntu.com/ubuntu}"
: "${IMG_WORK:=/var/tmp/winrbd-p2-images}"
: "${IMG_SIZE_MB:=2048}"
: "${IMG_DEBOOTSTRAP_TIMEOUT:=3600}"
# what goes into the base system. Order does not matter; it is part of the cache key.
: "${IMG_PACKAGES:=systemd-sysv udev kmod iproute2 initramfs-tools e2fsprogs util-linux busybox-static zstd login linux-image-virtual}"
# bump when the way the base is made changes (it is part of the cache key)
IMG_BASE_REV=2
# fixed identities: the image is found by label, and the UUIDs make two builds comparable
IMG_ROOT_LABEL=wrbroot
IMG_ESP_LABEL=WRBESP
IMG_ROOT_UUID=7d1f8a52-3b0e-4c6a-9a0e-5b1e0c0de001
IMG_DISK_GUID=7d1f8a52-3b0e-4c6a-9a0e-5b1e0c0de0aa

IMG_PROG=${IMG_PROG:-image}
IMG_DRY=0
IMG_CLEAN=()
IMG_LOOP=
IMG_KVER=

img_die() {
	printf '%s: %s\n' "$IMG_PROG" "$*" >&2
	exit 1
}
img_info() { printf '%s: %s\n' "$IMG_PROG" "$*"; }

# run a command, or only show it in a dry run
img_run() {
	if [ "$IMG_DRY" = 1 ]; then
		printf '%s: would run:' "$IMG_PROG"
		printf ' %q' "$@"
		printf '\n'
		return 0
	fi
	"$@"
}

img_on_exit() {
	local rc=$? i
	set +e
	for ((i = ${#IMG_CLEAN[@]} - 1; i >= 0; i--)); do
		eval "${IMG_CLEAN[i]}" > /dev/null 2>&1
	done
	exit "$rc"
}
img_defer() { IMG_CLEAN+=("$1"); } # a command line (already quoted) to run at exit, last registered first
# run the deferred commands registered after position $1 (the value of ${#IMG_CLEAN[@]} taken earlier), newest first, and forget them
img_cleanup_to() {
	local i keep=$1
	for ((i = ${#IMG_CLEAN[@]} - 1; i >= keep; i--)); do
		eval "${IMG_CLEAN[i]}" > /dev/null 2>&1 || img_info "warning: cleanup step failed: ${IMG_CLEAN[i]}" >&2
		unset 'IMG_CLEAN[i]'
	done
	IMG_CLEAN=("${IMG_CLEAN[@]}")
}

img_traps() {
	trap img_on_exit EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	trap 'exit 129' HUP
}

img_need_tools() { # TOOL...
	local t missing=()
	for t in "$@"; do command -v "$t" > /dev/null 2>&1 || missing+=("$t"); done
	if [ "${#missing[@]}" -gt 0 ]; then
		if [ "$IMG_DRY" = 1 ]; then
			img_info "warning: missing tools (a real run would stop here): ${missing[*]}"
		else
			img_die "missing tools: ${missing[*]} (the builder guest of harness/lab/p2/builder has them)"
		fi
	fi
}

# re-run this script as root (sudo) when it is not. The arguments are the script's OWN, as the user typed them (the callers save them before
# their option loop shifts them away: a re-run without them is a different command, "--tiny" or "--out" or "--force" silently gone), and
# the settings travel as arguments of env: "sudo -E" is refused or ignored by some sudo (sudo-rs of Ubuntu 26.04 says "-E is ignored"),
# which dropped IMG_WORK, IMG_MIRROR ... on the way to root. IMG_TEST_UID lets the self-test play a user that is not root.
img_need_root() {
	if [ "$IMG_DRY" = 1 ]; then return 0; fi
	if [ "${IMG_TEST_UID:-$(id -u)}" != 0 ]; then
		command -v sudo > /dev/null 2>&1 || img_die "run this as root (loop devices, mount, chroot)"
		exec sudo env "IMG_WORK=$IMG_WORK" "IMG_MIRROR=$IMG_MIRROR" "IMG_RELEASE=$IMG_RELEASE" "IMG_SIZE_MB=$IMG_SIZE_MB" \
			"IMG_PACKAGES=$IMG_PACKAGES" "IMG_DEBOOTSTRAP_TIMEOUT=$IMG_DEBOOTSTRAP_TIMEOUT" bash "$0" "$@"
	fi
}

# an image is a disk: it must never end up in a git commit
img_check_untracked() { # PATH
	local p=$1 d top
	d=$(dirname "$p")
	while [ ! -d "$d" ] && [ "$d" != / ]; do d=$(dirname "$d"); done
	if top=$(git -C "$d" rev-parse --show-toplevel 2> /dev/null); then
		if ! git -C "$d" check-ignore -q -- "$p" 2> /dev/null; then
			img_die "$p is inside the git work tree $top and git does not ignore it: disk images must never be committed. Use IMG_WORK outside the repository."
		fi
	fi
}

img_sha256() { sha256sum "$1" | cut -d' ' -f1; }

img_size_check() {
	case $IMG_SIZE_MB in '' | *[!0-9]*) img_die "IMG_SIZE_MB must be a number (MiB)" ;; esac
	[ "$IMG_SIZE_MB" -le 2048 ] || img_die "IMG_SIZE_MB=$IMG_SIZE_MB: the test images are 2 GiB at most (the lab allows 2 GiB per image)"
	[ "$IMG_SIZE_MB" -ge 1024 ] || img_die "IMG_SIZE_MB=$IMG_SIZE_MB: 1024 MiB is the least that holds the system and the kernel"
}

# ----------------------------------------------------------------------------------------------------------------------------
# loop devices and mounts, each undone at exit
# ----------------------------------------------------------------------------------------------------------------------------
# a call in a $(...) would register the clean-up in a subshell and lose it: the directory name goes into the variable named by $2
img_mktemp_dir() { # NAME VARIABLE : an empty directory below $IMG_WORK/tmp, removed (rmdir) at exit
	local d
	mkdir -p "$IMG_WORK/tmp"
	d=$(mktemp -d "$IMG_WORK/tmp/$1.XXXXXX")
	img_defer "rmdir $(printf '%q' "$d")"
	printf -v "$2" '%s' "$d"
}

img_losetup() { # FILE : attach with partition scan, sets IMG_LOOP, detaches at exit
	IMG_LOOP=$(losetup --find --show --partscan "$1") || img_die "losetup failed for $1"
	img_defer "losetup -d $(printf '%q' "$IMG_LOOP")"
	udevadm settle 2> /dev/null || true
}

img_wait_part() { # N : the partition node of the loop device
	local n=$1 t=0
	while [ ! -b "${IMG_LOOP}p$n" ]; do
		[ "$t" -ge 100 ] && img_die "partition ${IMG_LOOP}p$n did not appear"
		sleep 0.1
		t=$((t + 1))
	done
}

img_mount() { # DEV DIR [OPTIONS]
	mount ${3:+-o "$3"} "$1" "$2" || img_die "mount $1 on $2 failed"
	img_defer "umount $(printf '%q' "$2")"
}

# the pseudo file systems a chroot needs (update-initramfs, apt, dpkg triggers)
img_chroot_mounts() { # ROOT
	local r=$1
	mount -t proc proc "$r/proc"
	img_defer "umount $(printf '%q' "$r/proc")"
	mount -t sysfs sysfs "$r/sys"
	img_defer "umount $(printf '%q' "$r/sys")"
	mount --bind /dev "$r/dev"
	img_defer "umount $(printf '%q' "$r/dev")"
	mount -t tmpfs tmpfs "$r/run"
	img_defer "umount $(printf '%q' "$r/run")"
}

# ----------------------------------------------------------------------------------------------------------------------------
# the base system, built once and cached as a tar
# ----------------------------------------------------------------------------------------------------------------------------
img_base_key() {
	printf '%s\n' "$IMG_RELEASE" "$IMG_PACKAGES" "$IMG_BASE_REV" | sha256sum | cut -c1-12
}

# print the path of the base tarball; build it when there is none
img_base() {
	local tarball tmp ext4 mnt rc=0
	mkdir -p "$IMG_WORK/cache"
	tarball=$IMG_WORK/cache/base-$IMG_RELEASE-$(img_base_key).tar.zst
	if [ -s "$tarball" ]; then
		printf '%s' "$tarball"
		return 0
	fi
	if [ "$IMG_DRY" = 1 ]; then
		img_info "would build the base system $IMG_RELEASE from $IMG_MIRROR into $tarball" >&2
		printf '%s' "$tarball"
		return 0
	fi
	img_info "building the base system ($IMG_RELEASE from $IMG_MIRROR; packages: $IMG_PACKAGES)" >&2
	# a subshell of its own, run as a plain statement (not in an || or if), so that its set -e works
	set +e
	(
		set -euo pipefail
		IMG_CLEAN=()
		trap img_on_exit EXIT
		img_mktemp_dir base tmp
		ext4=$IMG_WORK/tmp/base-$$.ext4
		img_defer "rm -f $(printf '%q' "$ext4")"
		truncate -s 5G "$ext4"
		mkfs.ext4 -F -q -m 0 -O ^has_journal "$ext4"
		img_losetup "$ext4"
		mnt=$tmp
		img_mount "$IMG_LOOP" "$mnt"
		timeout "$IMG_DEBOOTSTRAP_TIMEOUT" debootstrap --variant=minbase --arch=amd64 --components=main "$IMG_RELEASE" "$mnt" "$IMG_MIRROR" >&2
		cat > "$mnt/etc/apt/sources.list" <<EOF
deb $IMG_MIRROR $IMG_RELEASE main
deb $IMG_MIRROR $IMG_RELEASE-updates main
deb $IMG_MIRROR $IMG_RELEASE-security main
EOF
		img_chroot_mounts "$mnt"
		# no initramfs while the kernel is installed: it is made per image, with the hook in place
		# The generic kernel packs qemu_fw_cfg (the QEMU file channel: expected values and a key from outside the guest) in the
		# modules-extra package, which holds a gigabyte of drivers nobody needs here: take that one file out of it.
		# shellcheck disable=SC2016
		timeout "$IMG_DEBOOTSTRAP_TIMEOUT" chroot "$mnt" env INITRD=No DEBIAN_FRONTEND=noninteractive LC_ALL=C PKGS="$IMG_PACKAGES" \
			sh -c 'set -e
apt-get update -q
apt-get install -y -q --no-install-recommends $PKGS
kver=$(ls /boot | sed -n "s/^vmlinuz-//p" | sort -V | tail -n 1)
mkdir -p /tmp/extra
cd /tmp/extra
apt-get download -q "linux-modules-extra-$kver"
dpkg-deb --fsys-tarfile linux-modules-extra-*.deb | tar -x -C / --wildcards "./lib/modules/$kver/kernel/drivers/firmware/qemu_fw_cfg.ko*"
cd /
rm -f /tmp/extra/*.deb
rmdir /tmp/extra
depmod "$kver"
ls /usr/lib/modules/$kver/kernel/drivers/firmware/qemu_fw_cfg.ko* > /dev/null
apt-get clean
rm -rf /var/lib/apt/lists/*' >&2
		# fixed paths only: the system's own caches
		chroot "$mnt" sh -c 'rm -f /var/cache/ldconfig/aux-cache /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log' || true
		ls "$mnt"/boot/vmlinuz-* > /dev/null 2>&1 || { echo "no kernel was installed" >&2; exit 1; }
		umount "$mnt/run" "$mnt/dev" "$mnt/sys" "$mnt/proc"
		tar --numeric-owner --xattrs --acls -C "$mnt" -I 'zstd -T0 -3' -cf "$tarball.part" .
		mv "$tarball.part" "$tarball"
	)
	rc=$?
	set -e
	[ "$rc" = 0 ] || { rm -f "$tarball.part"; img_die "building the base system failed (status $rc)"; }
	printf '%s' "$tarball"
}

# ----------------------------------------------------------------------------------------------------------------------------
# the guest-side files
# ----------------------------------------------------------------------------------------------------------------------------

# the static table checker, built on this machine
img_build_checker() { # OUTFILE
	local src=$IMG_SRC_DIR/rbft-check/rbft-check.c
	[ -r "$src" ] || img_die "cannot read $src"
	gcc -std=c99 -O2 -Wall -Wextra -Werror -static -o "$1" "$src" || img_die "cannot build rbft-check (static glibc missing? libc6-dev has it)"
	strip "$1" 2> /dev/null || true
}

# the kernel version installed in a root: the newest vmlinuz-*
img_kver() { # ROOT
	local f best=
	for f in "$1"/boot/vmlinuz-*; do
		[ -e "$f" ] || continue
		best=${f##*/vmlinuz-}
	done
	[ -n "$best" ] || img_die "no kernel in $1/boot"
	printf '%s' "$best"
}

# put the hook, the checker, the marker and the service into a root that is mounted, and make the initramfs
img_install_guest() { # ROOT CHECKER
	local r=$1 checker=$2 d kver
	install -d -m 0755 "$r/etc/initramfs-tools/hooks" "$r/etc/initramfs-tools/scripts/local-top" "$r/usr/local/sbin" "$r/etc/systemd/system/multi-user.target.wants"
	install -m 0755 "$IMG_SRC_DIR/hooks/rbft" "$r/etc/initramfs-tools/hooks/rbft"
	install -m 0755 "$IMG_SRC_DIR/scripts/local-top/rbft" "$r/etc/initramfs-tools/scripts/local-top/rbft"
	install -m 0644 "$IMG_SRC_DIR/modules" "$r/etc/initramfs-tools/rbft-modules"
	install -m 0755 "$checker" "$r/usr/local/sbin/rbft-check"
	install -m 0755 "$IMG_SRC_DIR/system/wrboot-marker" "$r/usr/local/sbin/wrboot-marker"
	install -m 0644 "$IMG_SRC_DIR/system/wrboot-marker.service" "$r/etc/systemd/system/wrboot-marker.service"
	ln -sf ../wrboot-marker.service "$r/etc/systemd/system/multi-user.target.wants/wrboot-marker.service"
	# a login prompt on the serial console
	install -d -m 0755 "$r/etc/systemd/system/getty.target.wants"
	ln -sf /usr/lib/systemd/system/serial-getty@.service "$r/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service"
	# initramfs: only the modules of the list, compressed with zstd
	sed -i -e 's/^MODULES=.*/MODULES=list/' -e 's/^COMPRESS=.*/COMPRESS=zstd/' "$r/etc/initramfs-tools/initramfs.conf"
	grep -q '^MODULES=list' "$r/etc/initramfs-tools/initramfs.conf" || img_die "initramfs.conf has no MODULES line to set"
	: > "$r/etc/initramfs-tools/modules"
	# identity
	echo winrbd-guest > "$r/etc/hostname"
	printf '127.0.0.1 localhost\n127.0.1.1 winrbd-guest\n' > "$r/etc/hosts"
	chroot "$r" sh -c 'systemd-id128 new > /etc/machine-id' || true
	# the root account has no password: the login prompt is for show, the marker is the evidence
	chroot "$r" sh -c 'passwd -l root' > /dev/null 2>&1 || true
	kver=$(img_kver "$r")
	img_info "kernel $kver: making the initramfs"
	chroot "$r" env LC_ALL=C update-initramfs -c -k "$kver" 2>&1 | sed 's/^/    /'
	[ -s "$r/boot/initrd.img-$kver" ] || img_die "no initramfs was made"
	# the finished initramfs must hold what the hook needs
	local list
	list=$(chroot "$r" lsinitramfs "/boot/initrd.img-$kver") || img_die "cannot list the initramfs"
	local need m missing=() builtin
	# a module built into the kernel needs no file (Ubuntu builds in the crypto, virtio and ata drivers used here)
	builtin=$(cat "$r/usr/lib/modules/$kver/modules.builtin" 2> /dev/null || true)
	need=$(awk '$1 == "required" { print $2 }' "$IMG_SRC_DIR/modules")
	for m in $need; do
		# a module may be spelled with - or _ in the file name
		if printf '%s\n' "$list" | grep -Eq "/(${m}|${m//_/-})\\.ko(\\.[a-z]+)?\$"; then continue; fi
		if printf '%s\n' "$builtin" | grep -Eq "/(${m}|${m//_/-})\\.ko\$"; then continue; fi
		missing+=("$m")
	done
	for m in usr/local/sbin/rbft-check scripts/local-top/rbft; do
		printf '%s\n' "$list" | grep -q "$m\$" || missing+=("$m")
	done
	printf '%s\n' "$list" | grep -Eq '(^|/)ip$' || missing+=("ip")
	if [ "${#missing[@]}" -gt 0 ]; then img_die "the initramfs lacks: ${missing[*]}"; fi
	img_info "the initramfs holds the checker, ip, the hook and every required module"
	IMG_KVER=$kver
	d=$r/boot
	ln -sf "vmlinuz-$kver" "$d/vmlinuz"
	ln -sf "initrd.img-$kver" "$d/initrd.img"
}

# /etc/fstab; the argument is the ESP line or empty
img_write_fstab() { # ROOT [ESPLINE]
	{
		echo "LABEL=$IMG_ROOT_LABEL / ext4 ro,noatime 0 0"
		[ -n "${2:-}" ] && echo "$2"
		echo "tmpfs /tmp tmpfs defaults,nosuid,nodev 0 0"
		echo "tmpfs /var/tmp tmpfs defaults,nosuid,nodev 0 0"
		echo "tmpfs /var/log tmpfs defaults,nosuid,nodev 0 0"
		echo "tmpfs /var/cache tmpfs defaults,nosuid,nodev 0 0"
	} > "$1/etc/fstab"
}

# the grub.cfg both images use. $1 = path of the file, $2 = rbft.rootpart, $3 = kernel version, $4 = extra kernel words,
# $5 = "16" for grub-pc: the linux16 / initrd16 commands run the kernel's real-mode setup code, which is what collects the BIOS drive
# information (EDD, edd=on). The plain linux command of grub-pc enters the kernel in protected mode and skips it.
img_write_grub_cfg() {
	local cfg=$1 part=$2 kver=$3 extra=${4:-} sfx=${5:-}
	cat > "$cfg" <<EOF
# generated by build-*.sh (harness/lab/p2/images); static on purpose: no probing of disks
set default=0
set timeout=2
serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console
search --no-floppy --label $IMG_ROOT_LABEL --set=root
set rbft_extra=""
# import.sh --expect-opts writes this file: the expected values of one test configuration as kernel command line words
if [ -f /boot/grub/rbft-extra.cfg ]; then source /boot/grub/rbft-extra.cfg; fi

menuentry 'winrbd Linux: check the table, root from the image if there is one' {
    linux$sfx /boot/vmlinuz-$kver root=LABEL=$IMG_ROOT_LABEL ro console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 iomem=relaxed edd=on noresume loglevel=4 rbft.hook=1 rbft.rootpart=$part $extra \$rbft_extra
    initrd$sfx /boot/initrd.img-$kver
}
menuentry 'winrbd Linux: local root only (no hook)' {
    linux$sfx /boot/vmlinuz-$kver root=LABEL=$IMG_ROOT_LABEL ro console=tty0 console=ttyS0,115200n8 net.ifnames=0 biosdevname=0 iomem=relaxed edd=on noresume loglevel=4 rbft.hook=0 $extra
    initrd$sfx /boot/initrd.img-$kver
}
EOF
}

# a manifest of the image: what krbd-check of import.sh compares after the import
img_write_manifest() { # IMAGE ROOT KIND
	local img=$1 r=$2 kind=$3 out="$1.manifest" kver
	kver=$IMG_KVER
	{
		echo "# winrbd p2 image manifest (not secret)"
		echo "kind=$kind"
		echo "release=$IMG_RELEASE"
		echo "kernel=$kver"
		echo "size_bytes=$(stat -c %s "$img")"
		echo "root_label=$IMG_ROOT_LABEL"
		echo "root_uuid=$IMG_ROOT_UUID"
		for f in "boot/vmlinuz-$kver" "boot/initrd.img-$kver" boot/grub/grub.cfg usr/local/sbin/rbft-check usr/local/sbin/wrboot-marker; do
			printf 'file=%s %s\n' "$f" "$(img_sha256 "$r/$f")"
		done
	} > "$out"
}
