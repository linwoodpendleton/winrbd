#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# import.sh - put a raw guest image of build-uefi.sh / build-bios.sh into a lab RBD image and prove it arrived intact.
#
#   import.sh [-n] import     --image FILE|- --name NAME [--pool POOL] [--compressed] [--force]
#   import.sh [-n] user-create NAME [--pool POOL]
#   import.sh [-n] check      --name NAME [--pool POOL] [--manifest FILE] [--sha256 HEX | --image FILE] [--rootpart N]
#   import.sh [-n] expect     --image FILE (--opts "OPTIONS OF expected-table.sh" | --words "rbft.a=b rbft.c=d")
#   import.sh [-n] delete     NAME [--pool POOL]          the image and the user of that name
#   import.sh [-n] list
#
#   import      write the raw image into the RBD image NAME (default pool winrbd), format 2, feature layering only (the writer profile
#               of the driver: no exclusive-lock, object-map or fast-diff; krbd takes it too). FILE - reads standard input, which is
#               zstd-compressed with --compressed (a stream from another machine). Refuses an existing image unless --force (which
#               removes only a wrtest-* image of that name). The image is compared to the size of the file.
#   user-create a throwaway cephx user client.NAME with legacy "aes" key (the Linux kernel client cannot use the 32-byte aes256k keys),
#               caps  mon 'profile rbd'  osd 'profile rbd pool=POOL'. The key stays in the cluster: it is never printed, never copied
#               here, and never in an argument list. check reads it with the lab's own ceph tool when it needs it.
#   check       the proof that the import is intact: (1) the SHA-256 of "rbd export" equals the image's (from --image, --sha256 or the
#               image_sha256 line of --manifest); (2) with the user's own key, krbd maps the image, e2fsck -fn is clean, the root
#               partition mounts read-only, the files named in --manifest have the recorded SHA-256, and for a UEFI image the ESP holds
#               EFI/BOOT/BOOTX64.EFI. Everything is unmapped and unmounted at the end, also on failure.
#   expect      write the expected values of one test configuration into a (local, raw) image as /boot/grub/rbft-extra.cfg, which grub
#               puts on the kernel command line (rbft.mons=... rbft.pool=...): the table hook of the guest then checks the table
#               against them. OPTIONS are those of expected-table.sh (--mons, --entity, --pool, --image, --mode, --ip ...). Needs
#               debugfs and sfdisk; run it before "import". (QEMU runs can use -fw_cfg instead; see the README.)
#   delete      remove the RBD image and the user (only names that start with wrtest-)
#
# Where the lab is: the lab VM is reached with the ssh command in P2_LAB_SSH (words, e.g.  ssh -J user@jump -p 22221 lab@127.0.0.1 ),
# or, when LAB_DIR is the directory of harness/lab/p2/cluster's lab on this machine, with its key and port. The lab user needs sudo
# without a password in the VM (ceph, rbd, mount, e2fsck run through it).
# Rules: only names that start with wrtest- are created, imported over or deleted; pools: winrbd or wrtest-*; images of at most 2 GiB.
# -n shows what would be done and runs nothing (the remote commands are printed, they contain no key).
# shellcheck disable=SC2016  # the scripts for the lab VM are in single quotes on purpose: they expand there, not here
set -euo pipefail

prog=import.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
dry=0
die() { printf '%s: %s\n' "$prog" "$*" >&2; exit 1; }
info() { printf '%s: %s\n' "$prog" "$*"; }
usage() { sed -n '3,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

LAB_SSH=()
lab_setup() {
	if [ -n "${P2_LAB_SSH:-}" ]; then
		read -r -a LAB_SSH <<< "$P2_LAB_SSH"
	elif [ -n "${LAB_DIR:-}" ] && [ -r "$LAB_DIR/ssh/id_ed25519" ]; then
		LAB_SSH=(ssh -p "${LAB_SSH_PORT:-22232}" -i "$LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes
			-o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$LAB_DIR/ssh/known_hosts" "${LAB_SSH_USER:-lab}@127.0.0.1")
	else
		[ "$dry" = 1 ] && { LAB_SSH=(ssh LAB); return 0; }
		die "no lab: set P2_LAB_SSH to the ssh command that reaches the lab VM (see the usage), or LAB_DIR"
	fi
}
# run a command line in the lab VM; the arguments are quoted for the remote shell
lab() {
	local cmd
	cmd=$(printf '%q ' "$@")
	if [ "$dry" = 1 ]; then printf '%s: would run in the lab VM: %s\n' "$prog" "$cmd"; return 0; fi
	# never the caller's standard input: "import --image -" has the image on it, and an ssh that reads it eats a piece of the image
	"${LAB_SSH[@]}" "$cmd" < /dev/null
}
# the same, with a script text for bash -c (arguments follow)
lab_script() { # SCRIPT ARGS...
	local s=$1
	shift
	lab sudo bash -c "$s" bash "$@"
}

norm_name() { # NAME -> NAME, only wrtest-* names
	case $1 in
	wrtest-*) ;;
	*) die "the name '$1' must start with wrtest- (this tool never touches another image or user)" ;;
	esac
	case $1 in *[!a-z0-9-]* | -* | *-) die "the name '$1' may hold only a-z, 0-9 and '-'" ;; esac
	[ "${#1}" -le 48 ] || die "the name '$1' is longer than 48 characters"
	printf '%s' "$1"
}
norm_pool() { # POOL
	case $1 in
	winrbd) ;;
	wrtest-*) case $1 in *[!a-z0-9-]*) die "the pool '$1' may hold only a-z, 0-9 and '-'" ;; esac ;;
	*) die "the pool '$1' is not winrbd or a wrtest-* pool" ;;
	esac
	printf '%s' "$1"
}

need_value() { [ $# -ge 2 ] || die "$1 needs a value"; }

# ------------------------------------------------------------------------------------------------------------------------------
cmd_user_create() {
	local name pool=winrbd
	[ $# -ge 1 ] || usage
	name=$(norm_name "$1")
	shift
	while [ $# -gt 0 ]; do
		case $1 in
		--pool) need_value "$@"; pool=$(norm_pool "$2"); shift 2 ;;
		*) die "user-create: unknown option '$1'" ;;
		esac
	done
	lab_setup
	local script='set -euo pipefail
name=$1 pool=$2
caps_osd="profile rbd pool=$pool"
if ceph auth get "client.$name" >/dev/null 2>&1; then
	have=$(ceph auth get "client.$name" 2>/dev/null | sed -n "s/^[[:space:]]*caps osd = \"\(.*\)\"/\1/p")
	[ "$have" = "$caps_osd" ] || { echo "client.$name exists with other osd caps ($have): delete it first" >&2; exit 1; }
	echo "client.$name exists with the right caps: reused"
else
	ceph auth get-or-create "client.$name" mon "profile rbd" osd "$caps_osd" -- --key_type aes >/dev/null
	echo "client.$name created (legacy aes key, caps: mon profile rbd, osd $caps_osd)"
fi
n=$(ceph auth get-key "client.$name" | base64 -d | wc -c)
if [ "$n" != 28 ]; then echo "client.$name has a key of $n bytes decoded; the kernel client needs the legacy type (28): delete the user and create it again" >&2; exit 1; fi
echo "key type: legacy aes (checked, not shown)"'
	lab_script "$script" "$name" "$pool"
}

cmd_import() {
	local image="" name="" pool=winrbd compressed=0 force=0
	while [ $# -gt 0 ]; do
		case $1 in
		--image) need_value "$@"; image=$2; shift 2 ;;
		--name) need_value "$@"; name=$(norm_name "$2"); shift 2 ;;
		--pool) need_value "$@"; pool=$(norm_pool "$2"); shift 2 ;;
		--compressed) compressed=1; shift ;;
		--force) force=1; shift ;;
		*) die "import: unknown option '$1'" ;;
		esac
	done
	[ -n "$image" ] || die "import: --image FILE (or -) is needed"
	[ -n "$name" ] || die "import: --name NAME is needed"
	local size=0
	if [ "$image" != - ]; then
		[ -r "$image" ] || die "cannot read $image"
		size=$(stat -c %s "$image" 2> /dev/null || stat -f %z "$image")
		[ "$size" -le 2147483648 ] || die "$image is $size bytes: the lab images are 2 GiB at most"
		[ "$size" -ge 33554432 ] || die "$image is only $size bytes: not a disk image"
	else
		[ "$dry" = 1 ] || [ ! -t 0 ] || die "--image - reads a stream on standard input"
	fi
	lab_setup
	local exists
	exists='set -eu
if rbd info "$1/$2" >/dev/null 2>&1; then echo yes; else echo no; fi'
	if [ "$dry" = 1 ]; then
		lab_script "$exists" "$pool" "$name"
	else
		local have
		have=$(lab_script "$exists" "$pool" "$name")
		if [ "$have" = yes ]; then
			[ "$force" = 1 ] || die "the image $pool/$name exists (--force replaces it)"
			info "removing the old $pool/$name"
			lab sudo rbd rm --no-progress "$pool/$name"
		fi
	fi
	info "importing ${image} into $pool/$name (format 2, feature layering only)"
	local remote
	# pipefail: a stream that does not decompress must fail the import, not leave an empty image
	remote="set -o pipefail; "$(printf '%q ' sudo rbd import --no-progress --image-format 2 --image-feature layering --dest-pool "$pool" - "$name")
	if [ "$dry" = 1 ]; then
		printf '%s: would stream %s%s to the lab VM and run: %s\n' "$prog" "$image" "$([ "$image" = - ] || echo ' through zstd')" "$remote"
		return 0
	fi
	# a transfer that fails (ssh dropped, a stream that does not decompress) can leave a half image under the final name, which a later
	# run would take for an old one: it is removed here, and said
	if ! {
		if [ "$image" = - ]; then
			if [ "$compressed" = 1 ]; then "${LAB_SSH[@]}" "set -o pipefail; zstd -d -c | ${remote#set -o pipefail; }"; else "${LAB_SSH[@]}" "$remote"; fi
		else
			if ! command -v zstd > /dev/null 2>&1; then
				"${LAB_SSH[@]}" "$remote" < "$image"
			else
				zstd -q -c -T0 -3 "$image" | "${LAB_SSH[@]}" "set -o pipefail; zstd -d -c | ${remote#set -o pipefail; }"
			fi
		fi
	}; then
		lab sudo rbd rm --no-progress "$pool/$name" > /dev/null 2>&1 || true
		die "the transfer into $pool/$name failed: the partial image was removed"
	fi
	local got
	got=$(lab sudo rbd info --format json "$pool/$name" | sed -n 's/.*"size": *\([0-9][0-9]*\).*/\1/p')
	[ -n "$got" ] || die "cannot read the size of $pool/$name after the import"
	if [ "$size" != 0 ] && [ "$got" != "$size" ]; then die "the image has $got bytes, the file $size"; fi
	if [ "$got" -lt 33554432 ]; then
		lab sudo rbd rm --no-progress "$pool/$name" > /dev/null 2>&1 || true
		die "the import left an image of only $got bytes (the stream was empty or damaged): removed it"
	fi
	info "imported: $pool/$name is $got bytes"
}

cmd_expect() {
	local image="" opts="" words="" haveopts=0 havewords=0
	while [ $# -gt 0 ]; do
		case $1 in
		--image) need_value "$@"; image=$2; shift 2 ;;
		--opts) need_value "$@"; opts=$2; haveopts=1; shift 2 ;;
		--words) need_value "$@"; words=$2; havewords=1; shift 2 ;;
		*) die "expect: unknown option '$1'" ;;
		esac
	done
	[ -n "$image" ] || die "expect: --image FILE is needed"
	[ "$haveopts$havewords" != 00 ] || die "expect: --opts or --words is needed"
	[ "$haveopts$havewords" != 11 ] || die "expect: --opts and --words are exclusive"
	[ -w "$image" ] || die "cannot write $image"
	if [ "$haveopts" = 1 ]; then
		local a=()
		read -r -a a <<< "$opts"
		words=$("$here/expected-table.sh" params "${a[@]}")
	fi
	# only characters that belong on a kernel command line and inside a grub string
	case $words in *[!A-Za-z0-9._:@/+=\ \[\]-]*) die "the words hold a character that does not belong on a kernel command line" ;; esac
	case $words in *rbft.key=*) die "the key does not go into an image (use the QEMU fw_cfg file or the table)" ;; esac
	command -v debugfs > /dev/null 2>&1 || die "debugfs is needed (e2fsprogs)"
	command -v sfdisk > /dev/null 2>&1 || die "sfdisk is needed (util-linux)"
	local start
	# the last partition: the root of every image of this directory (p2 of the UEFI one, p1 of the BIOS ones)
	start=$(sfdisk -d "$image" 2> /dev/null | sed -n 's/^[^ ]* *: *start= *\([0-9][0-9]*\),.*/\1/p' | tail -n 1)
	[ -n "$start" ] || die "no partition table in $image"
	# a global: the exit trap runs after the function has returned
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr-expect.XXXXXX")
	trap 'rm -f "$tmp/cfg" "$tmp/cmds" "$tmp/out"; rmdir "$tmp" 2>/dev/null || true' EXIT
	printf 'set rbft_extra="%s"\n' "$words" > "$tmp/cfg"
	if [ "$dry" = 1 ]; then
		info "would write /boot/grub/rbft-extra.cfg into the file system at offset $((start * 512)) of $image: $(cat "$tmp/cfg")"
		return 0
	fi
	{
		echo "rm /boot/grub/rbft-extra.cfg"
		echo "write $tmp/cfg /boot/grub/rbft-extra.cfg"
	} > "$tmp/cmds"
	debugfs -w -f "$tmp/cmds" "$image?offset=$((start * 512))" > "$tmp/out" 2>&1 || { cat "$tmp/out" >&2; rm -f "$tmp/out"; die "debugfs failed"; }
	local back
	back=$(debugfs -R "cat /boot/grub/rbft-extra.cfg" "$image?offset=$((start * 512))" 2> /dev/null)
	rm -f "$tmp/out"
	[ "$back" = "$(cat "$tmp/cfg")" ] || die "the file written into the image does not read back"
	# the image changed, so the digest in its manifest (what "check --manifest" compares the export with) must follow, or the next
	# check of this very image fails on a digest that was right for the image before
	if [ -f "$image.manifest" ] && grep -q '^image_sha256=' "$image.manifest"; then
		local newsum
		newsum=$(sha256sum "$image" | cut -d' ' -f1)
		if sed "s/^image_sha256=.*/image_sha256=$newsum/" "$image.manifest" > "$image.manifest.new"; then
			mv "$image.manifest.new" "$image.manifest"
		else
			rm -f "$image.manifest.new"
			die "cannot update the digest in $image.manifest"
		fi
		info "updated image_sha256 in $image.manifest"
	fi
	info "the expected values are in $image (/boot/grub/rbft-extra.cfg): $words"
}

cmd_check() {
	local name="" pool=winrbd manifest="" sha="" image="" rootpart=""
	while [ $# -gt 0 ]; do
		case $1 in
		--name) need_value "$@"; name=$(norm_name "$2"); shift 2 ;;
		--pool) need_value "$@"; pool=$(norm_pool "$2"); shift 2 ;;
		--manifest) need_value "$@"; manifest=$2; shift 2 ;;
		--sha256) need_value "$@"; sha=$2; shift 2 ;;
		--image) need_value "$@"; image=$2; shift 2 ;;
		--rootpart) need_value "$@"; rootpart=$2; shift 2 ;;
		*) die "check: unknown option '$1'" ;;
		esac
	done
	[ -n "$name" ] || die "check: --name NAME is needed"
	local kind="" files=""
	if [ -n "$manifest" ]; then
		[ -r "$manifest" ] || die "cannot read $manifest"
		kind=$(sed -n 's/^kind=//p' "$manifest" | head -n 1)
		files=$(sed -n 's/^file=//p' "$manifest")
		[ -n "$sha" ] || sha=$(sed -n 's/^image_sha256=//p' "$manifest" | head -n 1)
	fi
	if [ -z "$sha" ] && [ -n "$image" ]; then
		[ -r "$image" ] || die "cannot read $image"
		sha=$(sha256sum "$image" | cut -d' ' -f1)
	fi
	case $sha in '' | *[!0-9a-f]*) [ -z "$sha" ] || die "--sha256 is a lowercase hex digest" ;; esac
	if [ -z "$rootpart" ]; then
		case $kind in uefi) rootpart=2 ;; *) rootpart=1 ;; esac
	fi
	case $rootpart in *[!0-9]* | '') die "--rootpart is a number" ;; esac
	lab_setup
	local script='set -uo pipefail
pool=$1 name=$2 rootpart=$3 kind=$4 want=$5 files=$6
fail=0 skipped=0
say() { printf "%s\n" "$*"; }
finish() { # the verdict: FAIL beats PARTIAL beats PASS; only PASS exits 0 (a skipped part is not a pass)
	if [ "$fail" != 0 ]; then say "CHECK-RESULT FAIL"; exit 1; fi
	if [ "$skipped" != 0 ]; then say "CHECK-RESULT PARTIAL (a part was skipped, see the CHECK SKIP lines)"; exit 3; fi
	say "CHECK-RESULT PASS"; exit 0
}
bad() { say "CHECK FAIL $*"; fail=1; }
ok() { say "CHECK PASS $*"; }
tmp=$(mktemp -d /dev/shm/wr-check.XXXXXX); chmod 700 "$tmp"
dev=""; mnt=""; esp=""
cleanup() {
	[ -z "$esp" ] || umount "$esp" 2>/dev/null
	[ -z "$mnt" ] || umount "$mnt" 2>/dev/null
	[ -z "$dev" ] || rbd unmap "$dev" >/dev/null 2>&1
	rm -f "$tmp/keyring" "$tmp/export"; rmdir "$tmp/mnt" "$tmp/esp" 2>/dev/null; rmdir "$tmp" 2>/dev/null
}
trap cleanup EXIT
rbd info "$pool/$name" >/dev/null 2>&1 || { bad "image $pool/$name does not exist"; exit 1; }
if [ -n "$want" ]; then
	got=$(rbd export "$pool/$name" - 2>/dev/null | sha256sum | cut -d" " -f1)
	if [ "$got" = "$want" ]; then ok "rbd export has the SHA-256 of the image ($want)"; else bad "rbd export SHA-256 is $got, wanted $want"; fi
else
	say "CHECK SKIP no digest to compare the export with (give --image, --sha256 or --manifest)"; skipped=1
fi
if ! ceph auth get "client.$name" -o "$tmp/keyring" >/dev/null 2>&1; then
	say "CHECK SKIP no user client.$name: the krbd part needs it (user-create)"; skipped=1
	finish
fi
chmod 600 "$tmp/keyring"
kb=$(ceph auth get-key "client.$name" | base64 -d | wc -c)
if [ "$kb" != 28 ]; then bad "the key of client.$name is not a legacy aes key ($kb bytes decoded)"; exit 1; fi
dev=$(rbd map "$pool/$name" --id "$name" --keyring "$tmp/keyring" -o ms_mode=prefer-crc 2>"$tmp/maperr") || { bad "rbd map failed: $(head -n 1 "$tmp/maperr")"; rm -f "$tmp/maperr"; dev=""; exit 1; }
rm -f "$tmp/maperr"
ok "krbd mapped $pool/$name as $dev with the user own key"
t=0; while [ ! -b "${dev}p$rootpart" ] && [ $t -lt 60 ]; do sleep 0.5; t=$((t+1)); done
if [ ! -b "${dev}p$rootpart" ]; then bad "no partition ${dev}p$rootpart (is --rootpart right?)"; exit 1; fi
if e2fsck -fn "${dev}p$rootpart" >"$tmp/fsck" 2>&1; then ok "e2fsck -fn ${dev}p$rootpart: clean"; else bad "e2fsck -fn found problems: $(tail -n 3 "$tmp/fsck" | tr "\n" " ")"; fi
rm -f "$tmp/fsck"
mkdir "$tmp/mnt"; mnt="$tmp/mnt"
if mount -o ro,noload "${dev}p$rootpart" "$mnt" 2>/dev/null || mount -o ro "${dev}p$rootpart" "$mnt"; then ok "root partition mounts read-only"; else bad "mount failed"; mnt=""; exit 1; fi
say "CHECK INFO /boot: $(ls "$mnt/boot" 2>/dev/null | tr "\n" " ")"
printf "%s\n" "$files" | while read -r f sum; do
	[ -n "$f" ] || continue
	if [ ! -f "$mnt/$f" ]; then bad "$f is missing"; continue; fi
	g=$(sha256sum "$mnt/$f" | cut -d" " -f1)
	if [ "$g" = "$sum" ]; then ok "$f has the recorded SHA-256"; else bad "$f differs from the manifest"; fi
done > "$tmp/files.out"
cat "$tmp/files.out"; if grep -q "^CHECK FAIL" "$tmp/files.out"; then fail=1; fi; rm -f "$tmp/files.out"
umount "$mnt" && mnt=""
if [ "$kind" = uefi ]; then
	mkdir "$tmp/esp"; esp="$tmp/esp"
	if mount -o ro "${dev}p1" "$esp" 2>/dev/null; then
		if [ -s "$esp/EFI/BOOT/BOOTX64.EFI" ]; then ok "ESP has EFI/BOOT/BOOTX64.EFI ($(stat -c %s "$esp/EFI/BOOT/BOOTX64.EFI") bytes)"; else bad "ESP has no EFI/BOOT/BOOTX64.EFI"; fi
		umount "$esp" && esp=""
	else bad "the ESP does not mount"; esp=""; fi
fi
rbd unmap "$dev" && dev="" && ok "unmapped"
finish'
	lab_script "$script" "$pool" "$name" "$rootpart" "$kind" "$sha" "$files"
}

cmd_delete() {
	local name pool=winrbd
	[ $# -ge 1 ] || usage
	name=$(norm_name "$1")
	shift
	while [ $# -gt 0 ]; do
		case $1 in
		--pool) need_value "$@"; pool=$(norm_pool "$2"); shift 2 ;;
		*) die "delete: unknown option '$1'" ;;
		esac
	done
	lab_setup
	lab_script 'set -u
pool=$1 name=$2
if rbd info "$pool/$name" >/dev/null 2>&1; then
	# nothing may have it mapped
	if rbd showmapped 2>/dev/null | grep -q " $name "; then echo "image $pool/$name is mapped here: unmap it first" >&2; exit 1; fi
	rbd rm --no-progress "$pool/$name" 2>&1 | tail -n 1; echo "image $pool/$name removed"
else echo "no image $pool/$name"; fi
if ceph auth get "client.$name" >/dev/null 2>&1; then ceph auth rm "client.$name" >/dev/null && echo "user client.$name removed"; else echo "no user client.$name"; fi' "$pool" "$name"
}

cmd_list() {
	lab_setup
	lab_script 'set -u
echo "images (pool winrbd, wrtest-*):"; rbd ls winrbd 2>/dev/null | grep "^wrtest-" || echo "  none"
echo "users (client.wrtest-*):"; ceph auth ls 2>/dev/null | grep "^client.wrtest-" || echo "  none"'
}

# ------------------------------------------------------------------------------------------------------------------------------
if [ "${1:-}" = -n ] || [ "${1:-}" = --dry-run ]; then
	dry=1
	shift
fi
[ $# -ge 1 ] || { usage >&2; exit 2; }
cmd=$1
shift
case $cmd in
import) cmd_import "$@" ;;
user-create) cmd_user_create "$@" ;;
check) cmd_check "$@" ;;
expect) cmd_expect "$@" ;;
delete) cmd_delete "$@" ;;
list) cmd_list "$@" ;;
-h | --help | help) usage ;;
*) usage >&2; die "unknown command '$cmd'" ;;
esac
