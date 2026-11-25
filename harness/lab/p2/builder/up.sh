#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# up.sh - the Phase 2 builder: an Ubuntu 26.04 guest with the CI toolchain (gcc 15.2, clang 21.1.8), the iPXE build dependencies and
# the tools to build disk images (loop devices, qemu-img, parted, grub), on a shared Linux box, without root on the box.
#
#   up.sh [up]            create the guest if it does not exist (cached cloud image, ci26_vm.sh create), boot it, install the extra
#                         packages, check the toolchain; idempotent
#   up.sh provision       install the extra packages again (a newer extras list)
#   up.sh status          state directory, guest, versions
#   up.sh ssh CMD...      run CMD in the guest (the user "ci", passwordless sudo inside the guest only)
#   up.sh put SRC DEST    rsync SRC (on the box) into the guest (DEST relative to /home/ci, or absolute)      (on the box only)
#   up.sh get SRC DEST    rsync SRC from the guest to DEST on the box                                          (on the box only)
#   up.sh start | stop    boot / power off the guest (the state is kept)
#   up.sh env             print the settings as they resolve (state directory, cores, RAM, disk, jobs) and check them; no guest needed
#
# It is a thin wrapper around harness/tools/ci26_vm.sh (every rule of that script applies: nice -n 19 choom -n 600, memory check before a
# start, user-mode networking only, KVM, one state directory with a marker file). What this wrapper adds: its own state directory, the
# caps of this module (8 cores, 12 GiB), the iPXE and image-building packages, and the two ways to run it:
#
#   on the box          run the scripts of this directory on the box, from a copy of the repository (BUILDER_HOST unset);
#   from your machine   BUILDER_HOST=user@box [BUILDER_SSH_OPTS="-J user@jump -o HostKeyAlias=box"] BUILDER_DIR=/abs/dir/on/box
#                       up.sh ...  copies the repository (and a clean shallow clone of the pinned iPXE, made from your own
#                       third_party/ipxe) to the box and runs the same script there. Nothing is compiled on your machine.
#
# Environment (all optional unless said):
#   BUILDER_HOST        user@box; empty = run on this machine
#   BUILDER_SSH_OPTS    extra ssh options for the connection to the box (jump host, host key alias)
#   BUILDER_DIR         state directory on the box (absolute). Default $HOME/winrbd-builder26; REQUIRED with BUILDER_HOST.
#                       Holds ci26/ (the ci26_vm.sh state: guest disk, key, cached image), stage/ (the repository copy), out/ (results),
#                       logs/. A directory that is not empty and has no marker file is refused, so down.sh can never reach foreign files.
#   BUILDER_CPUS        guest cores (default 8, at most 8)       BUILDER_RAM_MB   guest RAM in MiB (default 12288, at most 12288)
#   BUILDER_DISK_GB     guest disk, sparse (default 60)          BUILDER_JOBS     build jobs in the guest (default = cores)
#   BUILDER_IMAGE_CACHE directory with the cloud image and its SHA256SUMS to copy instead of downloading (the download is slow on the
#                       lab box); default: the first of $BUILDER_DIR/../ci26/dl and $HOME/winrbd-ci26/dl that has the image
#   BUILDER_APT_MIRROR  apt mirror for the guest (passed to ci26_vm.sh as CI26_APT_MIRROR)
#   BUILDER_LOCAL_LOGS  (from your machine) where the logs of a run are copied (default ${TMPDIR:-/tmp}/winrbd-builder-logs)
#   BUILDER_LOCAL_OUT   (from your machine) where the build results are copied (default: not copied; they stay on the box in out/)
#   BUILDER_DETACH      (from your machine) 1 = start the job on the box detached from the ssh session and return at once; its output
#                       goes to BUILDER_DIR/logs/detached-<script>-<time>.log, whose last line is "BUILDER-EXIT <status>" when it is done
#   BUILDER_TREE        (from your machine) ship this directory instead of the repository the script lives in: a snapshot of a tree
#                       (git archive of a commit plus files from the working tree, say) that has harness/lab/p2/builder in it. The
#                       pinned iPXE clone is still made from this repository's third_party/ipxe, at the revision of TREE/ipxe/PINNED.
#
# Other scripts of this directory source this file for the shared functions (they never run its main).
#
# Written for bash 3.2 (macOS, the driving side) and bash 5 (Ubuntu, the box).

set -eu
set -o pipefail
LC_ALL=C
export LC_ALL

B_SELF=${BASH_SOURCE[0]}
B_HERE=$(cd "$(dirname "$B_SELF")" && pwd)
B_REPO=$(cd "$B_HERE/../../../.." && pwd)
B_CI26=$B_REPO/harness/tools/ci26_vm.sh
B_MARKER=.winrbd-builder-dir
B_CI26_MARKER=.ci26-vm-dir
B_IMAGE_NAME=ubuntu-26.04-server-cloudimg-amd64.img
B_EXTRAS_REV=extras-2       # bump when the package lists below change: provision runs again

b_die() { echo "builder: $*" >&2; exit 2; }
b_note() { echo "builder: $*" >&2; }
b_is_uint() { case $1 in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# ---- environment ------------------------------------------------------------------------------------------------------------------

b_remote() { [ -n "${BUILDER_HOST:-}" ] && [ "${BUILDER_ON_BOX:-0}" != 1 ]; }

b_init_env() {
	local D
	if b_remote; then
		[ -n "${BUILDER_DIR:-}" ] || b_die "BUILDER_DIR (an absolute path on $BUILDER_HOST) is required with BUILDER_HOST"
		D=$BUILDER_DIR
	else
		D=${BUILDER_DIR:-$HOME/winrbd-builder26}
	fi
	case $D in /*) ;; *) b_die "BUILDER_DIR must be an absolute path, got '$D'" ;; esac
	while case $D in *//*) true ;; *) false ;; esac; do D=${D//\/\//\/}; done
	while [ "${#D}" -gt 1 ] && [ "${D%/}" != "$D" ]; do D=${D%/}; done
	case /$D/ in */../* | */./*) b_die "BUILDER_DIR must be a plain absolute path (no '.' or '..' components), got '$D'" ;; esac
	case $D in *[!A-Za-z0-9_.+/-]*) b_die "BUILDER_DIR may only contain letters, digits and _ . + - /, got '$D'" ;; esac
	case $D in / | /home | /root | /tmp | /usr | /var | /etc | /opt | /srv | /mnt | /bin | /lib | /boot | /dev | /proc | /sys | /run | "${HOME:-/nonexistent}")
		b_die "refusing to use $D as the state directory" ;;
	esac
	BUILDER_DIR=$D
	BUILDER_CPUS=${BUILDER_CPUS:-8}
	BUILDER_RAM_MB=${BUILDER_RAM_MB:-12288}
	BUILDER_DISK_GB=${BUILDER_DISK_GB:-60}
	b_is_uint "$BUILDER_CPUS" && [ "$BUILDER_CPUS" -ge 1 ] && [ "$BUILDER_CPUS" -le 8 ] || b_die "BUILDER_CPUS must be 1..8 (the cap of this guest), got '$BUILDER_CPUS'"
	b_is_uint "$BUILDER_RAM_MB" && [ "$BUILDER_RAM_MB" -ge 4096 ] && [ "$BUILDER_RAM_MB" -le 12288 ] ||
		b_die "BUILDER_RAM_MB must be 4096..12288 (the cap of this guest is 12 GiB), got '$BUILDER_RAM_MB'"
	b_is_uint "$BUILDER_DISK_GB" && [ "$BUILDER_DISK_GB" -ge 20 ] && [ "$BUILDER_DISK_GB" -le 200 ] || b_die "BUILDER_DISK_GB must be 20..200, got '$BUILDER_DISK_GB'"
	BUILDER_JOBS=${BUILDER_JOBS:-$BUILDER_CPUS}
	b_is_uint "$BUILDER_JOBS" && [ "$BUILDER_JOBS" -ge 1 ] && [ "$BUILDER_JOBS" -le 64 ] || b_die "BUILDER_JOBS must be 1..64, got '$BUILDER_JOBS'"
	case ${BUILDER_APT_MIRROR:-} in *[!A-Za-z0-9_.:/~+-]*) b_die "BUILDER_APT_MIRROR may only contain letters, digits and _ . : / ~ + -" ;; esac
	B_STAGE=$BUILDER_DIR/stage
	B_OUT=$BUILDER_DIR/out
	B_LOGS=$BUILDER_DIR/logs
	B_V=$BUILDER_DIR/ci26/vm
	B_NICE="nice -n 19 choom -n 600 --"
	# what ci26_vm.sh reads (it is never given CI26_HOST here: on the box it works locally)
	unset CI26_HOST CI26_SSH_OPTS
	export CI26_DIR=$BUILDER_DIR/ci26 CI26_CPUS=$BUILDER_CPUS CI26_RAM_MB=$BUILDER_RAM_MB CI26_DISK_GB=$BUILDER_DISK_GB CI26_JOBS=$BUILDER_JOBS
	if [ -n "${BUILDER_APT_MIRROR:-}" ]; then export CI26_APT_MIRROR=$BUILDER_APT_MIRROR; fi
}

ci26() { bash "$B_CI26" "$@"; }

# b_guest_exec [-s] NAME [ARG...]: the script text on stdin is put into the guest as a FILE (~/.builder/NAME.sh) and run from there with
# its own stdin on /dev/null; -s runs it as root. Never "bash -s" with the script on the ssh pipe: bash reads such a script as it goes, so
# any program in it that reads stdin (apt, a package prompt, make, sudo) would swallow the next lines of the script and the run would
# end half-done with a status of 0. ARGs must be plain words (numbers, labels).
b_guest_exec() {
	local sudo="" name a args=""
	if [ "${1:-}" = -s ]; then sudo=sudo; shift; fi
	name=$1
	shift
	case $name in '' | *[!A-Za-z0-9_-]*) b_die "bad guest script name '$name'" ;; esac
	for a in "$@"; do
		case $a in '' | *[!A-Za-z0-9_.+-]*) b_die "bad guest script argument '$a'" ;; esac
		args="$args $a"
	done
	ci26 ssh "mkdir -p .builder && cat >.builder/$name.sh" || return 2
	ci26 ssh "${sudo:+$sudo }bash .builder/$name.sh$args" </dev/null
}

# the files that never go into the guest or onto the box: git metadata of the top level, build trees, the unrelated submodule, junk, the
# hidden files and directories of the top level (editor and tool state of whoever ships the tree; .github and the .git* files of the
# repository are let through, the checks read them), and everything that looks like a secret (a local lab.conf, key files, keyrings: .gitignore keeps them out of commits, this keeps them out of
# a working-tree copy that is shipped to a shared box). rsync takes the first rule that matches, so the order matters: the pinned iPXE tree
# is never filtered (it is not ours), and the six keyrings of the PUBLIC test vectors (throwaway cephx users, committed on purpose, the
# ctest vector tests read them) are let through before the keyring pattern.
# b_excludes [noipxe]: with "noipxe" the pinned iPXE tree is excluded altogether (it is shipped separately)
b_excludes() {
	local ipxe='--include=/third_party/ipxe/***'
	[ "${1:-}" != noipxe ] || ipxe=--exclude=/third_party/ipxe
	printf '%s\n' --exclude=/.git '--exclude=/build*' --exclude=/third_party/wnbd --exclude=/ci26-logs --exclude=.DS_Store '--exclude=._*' \
		--exclude=__pycache__ '--exclude=*.pyc' --exclude=/harness/.ceph-ref \
		--include=/.github/'***' --include=/.gitignore --include=/.gitmodules --include=/.gitattributes '--exclude=/.[!.]*' \
		"$ipxe" \
		'--include=/harness/vectors/public/keys/*.keyring' '--include=/harness/vectors/public/secure/keys/*.keyring' \
		--exclude=lab.conf '--exclude=*.keyring' --exclude=keyring '--exclude=*.secret' '--exclude=*.key' '--exclude=*.pem' '--exclude=*.p12' \
		'--exclude=id_ed25519*' '--exclude=id_rsa*' '--exclude=id_ecdsa*' --exclude=lab-secrets --exclude=ceph.conf.local
}

# ---- the state directory (on the box) ------------------------------------------------------------------------------------------------

# make BUILDER_DIR ours: new, empty or already marked. The ci26 sub-directory gets the ci26_vm.sh marker beforehand (so that the cached
# image can be put into ci26/dl before create, which would otherwise refuse a directory with files in it).
b_prepare_dirs() {
	local e
	if [ ! -f "$BUILDER_DIR/$B_MARKER" ] && [ -e "$BUILDER_DIR" ]; then
		[ -d "$BUILDER_DIR" ] || b_die "$BUILDER_DIR exists and is not a directory"
		for e in "$BUILDER_DIR"/* "$BUILDER_DIR"/.[!.]* "$BUILDER_DIR"/..?*; do
			if [ -e "$e" ] || [ -L "$e" ]; then
				b_die "$BUILDER_DIR is not empty and has no $B_MARKER file: it is not a builder state directory, refusing to take it over (choose a new BUILDER_DIR)"
			fi
		done
	fi
	mkdir -p "$BUILDER_DIR"
	[ -f "$BUILDER_DIR/$B_MARKER" ] || echo "winrbd builder state directory; down.sh deletes the known sub-directories of it" >"$BUILDER_DIR/$B_MARKER"
	mkdir -p "$B_STAGE" "$B_OUT" "$B_LOGS"
}

b_need_marker() { [ -f "$BUILDER_DIR/$B_MARKER" ] || b_die "$BUILDER_DIR has no $B_MARKER file: not a builder state directory (run up.sh first)"; }

b_vm_pid() {
	local p cl
	[ -f "$B_V/qemu.pid" ] || return 1
	p=$(cat "$B_V/qemu.pid" 2>/dev/null || true)
	b_is_uint "$p" || return 1
	[ -r "/proc/$p/cmdline" ] || return 1
	cl=$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true)
	case $cl in *"$B_V/disk.qcow2"*) ;; *) return 1 ;; esac
	echo "$p"
}
b_vm_running() { b_vm_pid >/dev/null 2>&1; }

# the guest must exist (up.sh made it); boot it if it is off
b_ensure_guest() {
	b_need_marker
	[ -f "$B_V/disk.qcow2" ] || b_die "no guest in $B_V: run up.sh first"
	b_vm_running || ci26 start
}

# ssh options for rsync into / out of the guest (the key and the forwarded port are in the ci26 state directory)
b_guest_ssh() {
	local port
	port=$(cat "$B_V/port" 2>/dev/null || true)
	b_is_uint "$port" || b_die "no guest port recorded: is the guest started?"
	printf 'ssh -i %s -p %s -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=%s -o HostKeyAlias=ci26 -o LogLevel=ERROR' \
		"$B_V/id_ci26" "$port" "$B_V/known_hosts"
}

# rsync the repository (as staged on the box) into the guest: DEST is relative to /home/ci
b_sync_repo_to_guest() { # DEST
	local ex=() l
	while IFS= read -r l; do ex+=("$l"); done < <(b_excludes)
	# the guest copy keeps third_party/ipxe/.git: the build script needs the pinned revision from git. A submodule checkout has a .git FILE
	# that points to the top repository's .git/modules, which is not copied: the guest could not read the revision. The "from your machine"
	# mode always stages a real clone; on the box a plain clone is needed.
	[ -d "$B_REPO/third_party/ipxe/.git" ] ||
		b_die "$B_REPO/third_party/ipxe/.git is not a directory (a submodule checkout has a .git file that points outside this copy): use BUILDER_HOST from a machine that has the submodule, or put a plain git clone of the pinned iPXE there"
	ci26 ssh "mkdir -p '$1'" </dev/null
	$B_NICE rsync -a --delete --delete-excluded "${ex[@]}" -e "$(b_guest_ssh)" "$B_REPO/" "ci@127.0.0.1:$1/"
}

# ---- the cached image -----------------------------------------------------------------------------------------------------------------

b_stage_image() {
	local c have want got
	[ ! -f "$BUILDER_DIR/ci26/vm/disk.qcow2" ] || return 0
	mkdir -p "$BUILDER_DIR/ci26/dl"
	[ -f "$BUILDER_DIR/ci26/$B_CI26_MARKER" ] || echo "ci26_vm state directory; destroy deletes the known sub-directories of it" >"$BUILDER_DIR/ci26/$B_CI26_MARKER"
	have=""
	for c in "${BUILDER_IMAGE_CACHE:-}" "$BUILDER_DIR/../ci26/dl" "$HOME/winrbd-ci26/dl"; do
		if [ -n "$c" ] && [ -f "$c/$B_IMAGE_NAME" ] && [ -f "$c/SHA256SUMS" ]; then have=$c; break; fi
	done
	if [ -z "$have" ]; then b_note "no cached cloud image: ci26_vm.sh will download it (slow on a lab box)"; return 0; fi
	if [ -f "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME" ]; then b_note "the image is already in $BUILDER_DIR/ci26/dl"; return 0; fi
	want=$(awk -v n="$B_IMAGE_NAME" '$2 == "*" n || $2 == n { print $1; exit }' "$have/SHA256SUMS")
	if [ -z "$want" ]; then b_note "the cache $have has no checksum for the image: not using it"; return 0; fi
	b_note "copying the cached image from $have"
	$B_NICE cp "$have/$B_IMAGE_NAME" "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME.part"
	got=$(sha256sum "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME.part" | awk '{print $1}')
	if [ "$got" != "$want" ]; then
		rm -f "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME.part"
		b_note "the cached image does not match its SHA256SUMS: not using it"
		return 0
	fi
	mv "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME.part" "$BUILDER_DIR/ci26/dl/$B_IMAGE_NAME"
	cp "$have/SHA256SUMS" "$BUILDER_DIR/ci26/dl/SHA256SUMS"
}

# ---- driving from another machine ------------------------------------------------------------------------------------------------------

# b_remote_run SCRIPT [ARGS...]: copy the repository and the pinned iPXE clone to the box, run SCRIPT there (same arguments, same
# environment), copy the logs (and, if asked, the results) back. Returns the exit status of the script on the box.
# B_FETCH=none (down.sh, ssh): nothing is copied back.
b_remote_run() {
	local script=$1 rc=0 k v l tmp rev envs="" args="" a rsh tree=${BUILDER_TREE:-$B_REPO}
	local -a ex sshw
	shift
	command -v rsync >/dev/null 2>&1 && command -v ssh >/dev/null 2>&1 && command -v git >/dev/null 2>&1 || b_die "ssh, rsync and git are needed on this machine"
	# BUILDER_SSH_OPTS is deliberately split into words
	# shellcheck disable=SC2206
	sshw=(ssh -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=20 ${BUILDER_SSH_OPTS:-})
	rsh="ssh -o BatchMode=yes -o ServerAliveInterval=30 ${BUILDER_SSH_OPTS:-}"
	[ -f "$tree/harness/lab/p2/builder/up.sh" ] || b_die "BUILDER_TREE=$tree is not a winrbd tree with harness/lab/p2/builder"
	rev=$(sed -n '1{s/[[:space:]].*//;p;}' "$tree/ipxe/PINNED")
	[ -n "$rev" ] || b_die "$tree/ipxe/PINNED is empty"
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/winrbd-builder.XXXXXX")
	trap 'rm -rf "$tmp"' EXIT
	# a clean, shallow clone of the pinned iPXE revision (committed files only, 11 MB of history): what the box needs to run
	# ipxe/tools/build.sh; the working tree of your submodule is not used, so a dirty file cannot leak into a build
	[ -e "$B_REPO/third_party/ipxe/.git" ] || b_die "$B_REPO/third_party/ipxe is not a git checkout (git submodule update --init third_party/ipxe)"
	( cd "$tmp" && git init -q ipxe && cd ipxe && git fetch -q --depth 1 "$B_REPO/third_party/ipxe" "$rev" && git checkout -q FETCH_HEAD ) ||
		b_die "cannot clone iPXE $rev from $B_REPO/third_party/ipxe (git submodule update --init third_party/ipxe)"
	[ "$(git -C "$tmp/ipxe" rev-parse HEAD)" = "$rev" ] || b_die "the clone is not at $rev"
	b_note "staging the repository on $BUILDER_HOST:$BUILDER_DIR/stage"
	"${sshw[@]}" "$BUILDER_HOST" "d=$(printf %q "$BUILDER_DIR"); if [ -e \"\$d\" ] && [ ! -f \"\$d/$B_MARKER\" ] && [ -n \"\$(ls -A \"\$d\")\" ]; then echo \"builder: \$d is not empty and has no $B_MARKER file: refusing to take it over\" >&2; exit 3; fi; mkdir -p \"\$d/stage/repo\" && { [ -f \"\$d/$B_MARKER\" ] || echo 'winrbd builder state directory; down.sh deletes the known sub-directories of it' >\"\$d/$B_MARKER\"; }" ||
		b_die "cannot prepare $BUILDER_DIR on $BUILDER_HOST (see above)"
	ex=()
	while IFS= read -r l; do ex+=("$l"); done < <(b_excludes noipxe)
	# third_party/ipxe is shipped separately (below): excluded here, and without --delete-excluded the clone on the box is not deleted
	rsync -a --delete "${ex[@]}" -e "$rsh" "$tree/" "$BUILDER_HOST:$BUILDER_DIR/stage/repo/"
	# -c: the clone is made afresh every time (new mtimes), only content decides
	rsync -ac --delete -e "$rsh" "$tmp/ipxe/" "$BUILDER_HOST:$BUILDER_DIR/stage/repo/third_party/ipxe/"
	# the BUILDER_* variables the script on the box must see, as an env(1) argument list
	for k in $(compgen -v BUILDER_); do
		case $k in BUILDER_HOST | BUILDER_SSH_OPTS | BUILDER_LOCAL_LOGS | BUILDER_LOCAL_OUT | BUILDER_TREE | BUILDER_ON_BOX) continue ;; esac
		v=${!k:-}
		[ -z "$v" ] || envs="$envs $(printf %q "$k=$v")"
	done
	for a in "$@"; do args="$args $(printf %q "$a")"; done
	local inner
	inner="env BUILDER_ON_BOX=1$envs bash $(printf %q "$BUILDER_DIR/stage/repo/harness/lab/p2/builder/$script")$args"
	if [ "${BUILDER_DETACH:-0}" = 1 ]; then
		# the job runs on the box, detached from this ssh session (an hours-long matrix must not die with a dropped connection or a
		# tool timeout): its output goes to a log on the box, the last line of which is "BUILDER-EXIT <status>"
		local dlog
		dlog="$BUILDER_DIR/logs/detached-${script%.sh}-$(date +%Y%m%d-%H%M%S).log"
		"${sshw[@]}" "$BUILDER_HOST" "mkdir -p $(printf %q "$BUILDER_DIR/logs"); nohup bash -c $(printf %q "$inner; echo \"BUILDER-EXIT \$?\"") >$(printf %q "$dlog") 2>&1 </dev/null 9>&- & sleep 1" </dev/null ||
			b_die "could not start the job on $BUILDER_HOST"
		b_note "detached: the job runs on the box; follow it with: ssh <box> tail -f $dlog   (done when the last line is BUILDER-EXIT <status>)"
		echo "BUILDER_DETACHED_LOG=$dlog"
		rm -rf "$tmp"
		trap - EXIT
		return 0
	fi
	set +e
	"${sshw[@]}" "$BUILDER_HOST" "$inner" </dev/null
	rc=$?
	set -e
	if [ "${B_FETCH:-logs}" = logs ]; then
		local ld=${BUILDER_LOCAL_LOGS:-${TMPDIR:-/tmp}/winrbd-builder-logs}
		mkdir -p "$ld"
		if rsync -a -e "$rsh" "$BUILDER_HOST:$BUILDER_DIR/logs/" "$ld/" >/dev/null 2>&1; then b_note "logs copied to $ld"; else b_note "could not copy the logs back"; fi
		if [ -n "${BUILDER_LOCAL_OUT:-}" ]; then
			mkdir -p "$BUILDER_LOCAL_OUT"
			if rsync -a -e "$rsh" "$BUILDER_HOST:$BUILDER_DIR/out/" "$BUILDER_LOCAL_OUT/" >/dev/null 2>&1; then
				b_note "results copied to $BUILDER_LOCAL_OUT"
			else
				b_note "could not copy the results back"
			fi
		fi
	fi
	rm -rf "$tmp"
	trap - EXIT
	return "$rc"
}

# ---- the guest: the extra packages -----------------------------------------------------------------------------------------------------

# runs in the guest as root. The CI packages (build-essential, gcc, clang, cmake, ninja, libssl-dev, gcc-multilib, ...) came with ci26_vm.sh
# create; these are the iPXE ones (liblzma-dev: zbin; mtools, xorriso, syslinux-common, isolinux: util/genfsimg for bin/ipxe.iso; patch, git:
# ipxe/tools/build.sh; perl) and the image-building ones for the linux-images module (loop devices, qemu-img, partitioning, FAT and ext4 tools,
# debootstrap, the two grub flavours) and libclang-rt-N-dev (the sanitizer runtimes of clang). Optional ones may be missing from a release: they are reported, not fatal.
extras_script() {
	cat <<EOF
set -eu
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -o DPkg::Lock::Timeout=600 -y -q"
\$APT update
\$APT install --no-install-recommends liblzma-dev gcc-multilib mtools xorriso syslinux syslinux-common isolinux patch git perl make binutils \\
	qemu-utils parted gdisk dosfstools e2fsprogs kpartx xz-utils zstd cpio rsync util-linux fdisk
# the sanitizer runtimes of clang (compiler-rt): without them every -fsanitize=address,undefined link of the clang matrix fails
cv=\$(clang --version | sed -n 's/.*clang version \\([0-9][0-9]*\\)\\..*/\\1/p;q')
\$APT install --no-install-recommends "libclang-rt-\$cv-dev"
for p in debootstrap grub-pc-bin grub-efi-amd64-bin grub-common mmdebstrap squashfs-tools; do
	if apt-cache show "\$p" >/dev/null 2>&1; then \$APT install --no-install-recommends "\$p" || echo "OPTIONAL-FAILED \$p"; else echo "OPTIONAL-MISSING \$p"; fi
done
modprobe loop 2>/dev/null || true
echo "$B_EXTRAS_REV" >/etc/winrbd-builder-extras
EOF
}

# runs in the guest (not as root): every tool and file the scripts of this module rely on, so that a missing one is found by up.sh and
# not in the middle of a build. Prints "ok name" / "MISSING name"; the exit status is the number of missing required items.
verify_script() {
	cat <<'EOF'
miss=0
need() { if command -v "$1" >/dev/null 2>&1; then echo "ok      $1"; else echo "MISSING $1"; miss=$((miss + 1)); fi; }
needf() { if [ -e "$1" ]; then echo "ok      $1"; else echo "MISSING $1"; miss=$((miss + 1)); fi; }
for t in gcc clang cmake ninja make perl patch git rsync xorriso mformat mcopy qemu-img losetup parted sgdisk mkfs.vfat mkfs.ext4 kpartx xz zstd cpio strings; do need "$t"; done
needf /usr/lib/ISOLINUX/isolinux.bin
needf /usr/lib/syslinux/modules/bios/ldlinux.c32
needf /usr/include/lzma.h
# a 32-bit object builds (the BIOS targets of iPXE) and a loop device can be attached (the image builds)
t=$(mktemp -d)
printf 'int main(void){return 0;}\n' >"$t/a.c"
if gcc -m32 -c "$t/a.c" -o "$t/a.o" 2>/dev/null; then echo "ok      gcc -m32"; else echo "MISSING gcc -m32 (gcc-multilib)"; miss=$((miss + 1)); fi
truncate -s 8M "$t/loop.img"
if dev=$(sudo losetup -f --show "$t/loop.img" 2>/dev/null); then sudo losetup -d "$dev"; echo "ok      loop device ($dev)"; else echo "MISSING loop device (sudo losetup)"; miss=$((miss + 1)); fi
if qemu-img create -q -f qcow2 "$t/q.qcow2" 8M 2>/dev/null; then echo "ok      qemu-img create"; else echo "MISSING qemu-img create"; miss=$((miss + 1)); fi
# the sanitizers link and run with both compilers (the ASan/UBSan flavours of build-harness.sh)
printf '#include <stdio.h>\nint main(void){puts("san");return 0;}\n' >"$t/s.c"
for cc in gcc clang; do
	if "$cc" -fsanitize=address,undefined "$t/s.c" -o "$t/s.$cc" 2>/dev/null && [ "$("$t/s.$cc")" = san ]; then echo "ok      $cc -fsanitize=address,undefined"; else echo "MISSING $cc -fsanitize=address,undefined (clang: libclang-rt-N-dev)"; miss=$((miss + 1)); fi
done
rm -rf "$t"
for p in debootstrap grub-pc-bin grub-efi-amd64-bin; do if dpkg -s "$p" >/dev/null 2>&1; then echo "ok      $p"; else echo "absent  $p (optional)"; fi; done
echo "gcc     $(gcc -dumpfullversion)"
echo "clang   $(clang --version | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p;q')"
echo "kernel  $(uname -r)"
exit "$miss"
EOF
}

b_provision() {
	local out
	extras_script | b_guest_exec -s extras || b_die "installing the extra packages failed"
	b_note "checking the guest"
	if ! out=$(verify_script | b_guest_exec verify); then
		echo "$out" >&2
		b_die "the guest is missing required tools (above)"
	fi
	mkdir -p "$B_LOGS"
	echo "$out" | tee "$B_LOGS/builder-versions.txt"
	echo "$B_EXTRAS_REV" >"$BUILDER_DIR/ready"
}

# ---- commands ----------------------------------------------------------------------------------------------------------------------------

cmd_up() {
	b_prepare_dirs
	if [ ! -f "$B_V/disk.qcow2" ]; then
		b_stage_image
		# a new disk has none of the extra packages, whatever an old "ready" file says (a guest destroyed by hand)
		rm -f "$BUILDER_DIR/ready"
		ci26 create
	elif [ ! -f "$B_V/versions.txt" ]; then
		# ci26_vm.sh create writes versions.txt as its last step before it powers the guest off: a disk without it is a create that did not
		# finish (no packages, maybe no user); booting it would fail in confusing ways
		b_die "$B_V/disk.qcow2 is there but the create never finished (no versions.txt): run down.sh and then up.sh again"
	fi
	b_vm_running || ci26 start
	if [ "$(cat "$BUILDER_DIR/ready" 2>/dev/null || true)" != "$B_EXTRAS_REV" ]; then b_provision; else b_note "extra packages already installed ($B_EXTRAS_REV)"; fi
	b_note "the builder is up: $(ci26 ssh 'gcc -dumpfullversion; clang --version | head -n 1' </dev/null | tr '\n' ' ')"
}

cmd_status() {
	b_need_marker
	ci26 status
	echo "builder dir $BUILDER_DIR ($(cat "$BUILDER_DIR/ready" 2>/dev/null || echo 'extras not installed'))"
	if [ -d "$B_OUT" ]; then ls -1 "$B_OUT" 2>/dev/null | sed 's/^/out         /' || true; fi
}

cmd_put() {
	[ $# -eq 2 ] || b_die "usage: put SRC DEST"
	b_ensure_guest
	$B_NICE rsync -a -e "$(b_guest_ssh)" "$1" "ci@127.0.0.1:$2"
}

cmd_get() {
	[ $# -eq 2 ] || b_die "usage: get SRC DEST"
	b_ensure_guest
	$B_NICE rsync -a -e "$(b_guest_ssh)" "ci@127.0.0.1:$1" "$2"
}

b_main() {
	local sub=${1:-up}
	[ $# -eq 0 ] || shift
	case $sub in
	-h | --help | help) sed -n '4,45p' "$B_SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
	up | provision | status | ssh | start | stop | put | get | env) ;;
	*) b_die "unknown command '$sub' (up, provision, status, ssh, put, get, start, stop, env)" ;;
	esac
	if [ "$sub" = env ]; then
		# the settings as they resolve on this machine (the checks of b_init_env are the point of it)
		BUILDER_ON_BOX=1
		b_init_env
		echo "dir=$BUILDER_DIR cpus=$BUILDER_CPUS ram_mb=$BUILDER_RAM_MB disk_gb=$BUILDER_DISK_GB jobs=$BUILDER_JOBS"
		exit 0
	fi
	if b_remote; then
		case $sub in put | get) b_die "$sub works on the box only: run it there (ssh to the box and run up.sh $sub)" ;; esac
		b_init_env
		B_FETCH=logs
		[ "$sub" != ssh ] || B_FETCH=none
		b_remote_run up.sh "$sub" "$@"
		exit $?
	fi
	b_init_env
	case $sub in
	up) cmd_up ;;
	provision) b_ensure_guest; b_provision ;;
	status) cmd_status ;;
	ssh) b_need_marker; b_vm_running || b_die "the guest is not running (up.sh start)"; ci26 ssh "$@" ;;
	start) b_need_marker; b_vm_running || ci26 start ;;
	stop) b_need_marker; ci26 stop ;;
	put) cmd_put "$@" ;;
	get) cmd_get "$@" ;;
	esac
}

# run main only when this file is executed, not when another script of the directory sources it
if [ "${BASH_SOURCE[0]}" = "$0" ]; then b_main "$@"; exit $?; fi
