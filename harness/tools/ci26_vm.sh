#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# ci26_vm.sh - a disposable Ubuntu 26.04 build machine for the harness: the toolchain of the CI runner (gcc 15.2, clang 21.1.8),
# on a big shared Linux box, without root and without touching anything of the box that is not ours.
#
#   ci26_vm.sh create              download the official 26.04 cloud image, boot it once, install the CI packages, power off
#   ci26_vm.sh start               boot it (waits for ssh)
#   ci26_vm.sh run [opts] TREE     copy TREE in, configure, build with -Werror and run ctest in every flavour, print a short log
#   ci26_vm.sh stop                power it off
#   ci26_vm.sh destroy [--purge]   stop it and delete the disk, the key and the staged trees (--purge: the image and the logs too)
#   ci26_vm.sh provision           install the CI packages again in the running guest (apt is idempotent: picks up packages added since create)
#   ci26_vm.sh status | ssh CMD... | log | selftest
#
# Where it runs. Without CI26_HOST everything happens on the machine you run it on (you are on the box). With CI26_HOST=user@box the
# script copies itself to the box and does the work there; your own machine only needs ssh and rsync, and TREE is a directory on
# your own machine (it is rsynced to the box first). The guest is only ever reached from the box (127.0.0.1 forward), never from outside.
#
# The rules it enforces (a shared machine that also runs other people's work):
#   - everything lives under one directory ($CI26_DIR, default ~/winrbd-ci26), marked by a file; create only marks a directory that
#     does not exist yet or is empty (a directory with someone else's files is refused, so destroy can never reach them); destroy
#     deletes only known sub-directories of it, and only when the marker is there, and not while a run is going on;
#   - every process the script starts is run as `nice -n 19 choom -n 600 --`;
#   - the guest has at most 24 cores and 32 GiB of RAM (CI26_CPUS / CI26_RAM_MB are checked against that; they are the caps for
#     the whole job, so the defaults (8 cores, 12 GiB) leave room for other users of the same budget);
#   - before every start the box must have at least 64 GiB of MemAvailable (CI26_MIN_AVAIL_GB), or nothing is started;
#   - networking is qemu user-mode (slirp) only: the only way in is one ssh port forwarded on 127.0.0.1. No bridge, no tap, no
#     change to the host's network or firewall. KVM is used when /dev/kvm is usable by the calling user (it is a hard requirement:
#     a build in TCG emulation would be too slow to be a test);
#   - only one `run` at a time (flock): ctest timing checks do not see each other's load;
#   - ssh to the guest is only done from the box, the key lives in the state directory, never in the repository.
#
# What `run` does, per compiler in CI26_CCS (default "gcc clang"), mirroring the CI jobs of .github/workflows:
#   matrix   core.yml / harness.yml build-test: Debug, Debug + ASan/UBSan, Release, MinSizeRel; cmake -G Ninja, -Werror
#            (WR_WERROR=ON is passed explicitly), `ctest -j 4 --timeout 600 -LE lab --no-tests=error`; a build that prints any
#            "warning:" counts as failed even if the compiler was not told to fail on it
#   gates    harness.yml compile-matrix (the 32-bit core, the iPXE-flag core, every header on its own, the object gates on those
#            objects) and object-gates (Release and MinSizeRel core: sources in sync, no libc, no globals)
# The list of flavours (-f) and stages (-s) can be changed; "-f all" adds Release and MinSizeRel with the sanitizers.
# Not replayed here (they stay CI-only or run with fuzz_long.sh): the libFuzzer smoke run and the call-graph budgets.
#
# If the cloud image cannot be fetched (no route to cloud-images.ubuntu.com, wrong checksum) create stops with a message. The
# fallback for a box that cannot reach the image is to build gcc 15.2.0 (ftp.gnu.org/gnu/gcc/gcc-15.2.0) and LLVM 21.1.8 (the
# llvm-project-21.1.8.src.tar.xz release tarball) under $CI26_DIR/toolchain with a prefix install and put them first in PATH
# for a native (no VM) run of the same cmake commands; it is not automated here because the image is reachable on the lab box
# (it would be hours of compiling, and a script nobody has run is worse than none).
#
# Environment (all optional):
#   CI26_HOST          user@box of the build box; empty = run here
#   CI26_SSH_OPTS      extra ssh options for the connection to the box, e.g. "-J user@jump -o HostKeyAlias=box"
#   CI26_DIR           state directory on the box (default $HOME/winrbd-ci26)
#   CI26_CPUS          guest cores (default 8, at most 24)         CI26_RAM_MB      guest RAM in MiB (default 12288, at most 32768)
#   CI26_DISK_GB       guest disk, sparse (default 40)             CI26_MIN_AVAIL_GB  MemAvailable the box must have (default 64)
#   CI26_JOBS          build jobs in the guest (default = cores)   CI26_CTEST_JOBS  ctest -j (default 4, as in CI)
#   CI26_CCS           compilers (default "gcc clang")             CI26_LABEL       name of the tree on the guest (default "default")
#   CI26_IMAGE_URL     directory of the cloud image (default https://cloud-images.ubuntu.com/releases/26.04/release)
#   CI26_IMAGE_NAME    file name of the image (default ubuntu-26.04-server-cloudimg-amd64.img)
#   CI26_APT_MIRROR    apt mirror to use inside the guest instead of the image's default (e.g. a nearby http://host/ubuntu)
#   CI26_EXPECT_GCC / CI26_EXPECT_CLANG   versions the CI runner has (default 15.2 / 21.1.8); a different one is a loud warning
#   CI26_LOGDIR        where `run` puts the short log on YOUR machine (default ${TMPDIR:-/tmp}/ci26-logs)
#
# Exit status of run: 0 all flavours passed, 1 something failed, 2 usage / environment problem (nothing was tested; an ssh or rsync
# failure, a signal and any other status of the machinery also end up as 2, so that 1 always means "the tree failed a check").
#
# Written for bash 3.2 (macOS) and 5 (Ubuntu): no associative arrays, no mapfile, no ${x,,}.

set -eu
set -o pipefail
# [A-Za-z] in the word checks below must mean ASCII letters whatever locale the caller has
LC_ALL=C
export LC_ALL

SELF=$0
case $SELF in /*) ;; *) SELF=$(pwd)/$SELF ;; esac

# ---- defaults -------------------------------------------------------------------------------------------------------------------
CPUS=${CI26_CPUS:-8}
RAM_MB=${CI26_RAM_MB:-12288}
DISK_GB=${CI26_DISK_GB:-40}
MIN_AVAIL_GB=${CI26_MIN_AVAIL_GB:-64}
MAX_CPUS=24
MAX_RAM_MB=32768
IMAGE_URL=${CI26_IMAGE_URL:-https://cloud-images.ubuntu.com/releases/26.04/release}
IMAGE_NAME=${CI26_IMAGE_NAME:-ubuntu-26.04-server-cloudimg-amd64.img}
EXPECT_GCC=${CI26_EXPECT_GCC:-15.2}
EXPECT_CLANG=${CI26_EXPECT_CLANG:-21.1.8}
GUEST_USER=ci
MARKER=.ci26-vm-dir

die() { echo "ci26_vm: $*" >&2; exit 2; }
note() { echo "ci26_vm: $*" >&2; }

usage() {
	sed -n '4,14p' "$SELF" | sed 's/^# \{0,1\}//' >&2
	cat >&2 <<'EOF'

run options:
  -l LABEL     name of the tree on the guest (default $CI26_LABEL or "default"); a second label keeps a second tree
  -c "CCS"     compilers, default "gcc clang"
  -f "FLAV"    flavours of the matrix stage: debug san release minsizerel relsan minsan; "all" = all six;
               default: debug san release minsizerel
  -s "STAGES"  matrix gates (default both)
  -S           power the guest off when the run is over (default: leave it up for the next run)
  TREE         the directory to test: on your machine when CI26_HOST is set, otherwise on this machine
EOF
	exit 2
}

# ---- small helpers --------------------------------------------------------------------------------------------------------------

is_uint() { case $1 in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# a space separated list of simple words (letters, digits, dash, underscore, dot, plus) and nothing else: these end up in a shell
# command line on the box and in a directory name, so nothing else gets through
check_words() {
	case $2 in *[!A-Za-z0-9_.+\ -]*) die "$1: only letters, digits and - _ . + are allowed, got '$2'" ;; esac
}

check_limits() {
	is_uint "$CPUS" && [ "$CPUS" -ge 1 ] || die "CI26_CPUS must be a number from 1 to $MAX_CPUS, got '$CPUS'"
	[ "$CPUS" -le "$MAX_CPUS" ] || die "CI26_CPUS=$CPUS is above the cap of $MAX_CPUS cores"
	is_uint "$RAM_MB" && [ "$RAM_MB" -ge 2048 ] || die "CI26_RAM_MB must be a number of at least 2048, got '$RAM_MB'"
	[ "$RAM_MB" -le "$MAX_RAM_MB" ] || die "CI26_RAM_MB=$RAM_MB is above the cap of $MAX_RAM_MB MiB"
	is_uint "$DISK_GB" && [ "$DISK_GB" -ge 10 ] && [ "$DISK_GB" -le 200 ] || die "CI26_DISK_GB must be 10..200, got '$DISK_GB'"
	is_uint "$MIN_AVAIL_GB" || die "CI26_MIN_AVAIL_GB must be a number, got '$MIN_AVAIL_GB'"
	check_words CI26_EXPECT_GCC "$EXPECT_GCC"
	check_words CI26_EXPECT_CLANG "$EXPECT_CLANG"
	# the mirror ends up inside a sed command that runs as root in the guest: URL characters only (nothing sed or the shell treats specially)
	case ${CI26_APT_MIRROR:-} in *[!A-Za-z0-9_.:/~+-]*) die "CI26_APT_MIRROR may only contain letters, digits and _ . : / ~ + -, got '${CI26_APT_MIRROR:-}'" ;; esac
	if [ -n "${CI26_JOBS:-}" ]; then is_uint "$CI26_JOBS" && [ "$CI26_JOBS" -ge 1 ] || die "CI26_JOBS must be a number, got '$CI26_JOBS'"; fi
	if [ -n "${CI26_CTEST_JOBS:-}" ]; then is_uint "$CI26_CTEST_JOBS" && [ "$CI26_CTEST_JOBS" -ge 1 ] || die "CI26_CTEST_JOBS must be a number"; fi
}

# MemAvailable in kB from /proc/meminfo (CI26_MEMINFO replaces the file for the self test)
mem_available_kb() {
	awk '/^MemAvailable:/ { print $2; found = 1 } END { if (!found) exit 1 }' "${CI26_MEMINFO:-/proc/meminfo}"
}

# refuse to start anything when the box is short of memory: the box has other work, which comes first
check_mem() {
	local kb need
	kb=$(mem_available_kb) || die "cannot read MemAvailable"
	is_uint "$kb" || die "cannot read MemAvailable"
	need=$((MIN_AVAIL_GB * 1024 * 1024))
	if [ "$kb" -lt "$need" ]; then
		die "MemAvailable is $((kb / 1024 / 1024)) GiB, less than the $MIN_AVAIL_GB GiB this script needs before it starts a guest: not starting"
	fi
	note "MemAvailable $((kb / 1024 / 1024)) GiB (>= $MIN_AVAIL_GB): ok"
}

# ---- the host side (this runs on the box) ----------------------------------------------------------------------------------------

host_init() {
	check_limits
	D=${CI26_DIR:-$HOME/winrbd-ci26}
	case $D in /*) ;; *) die "CI26_DIR must be an absolute path, got '$D'" ;; esac
	# doubled and trailing slashes off (so "$HOME/" is $HOME for the guard below); no "." or ".." component, no space or glob character
	while case $D in *//*) true ;; *) false ;; esac; do D=${D//\/\//\/}; done
	while [ "${#D}" -gt 1 ] && [ "${D%/}" != "$D" ]; do D=${D%/}; done
	case /$D/ in */../* | */./*) die "CI26_DIR must be a plain absolute path (no '.' or '..' components), got '$D'" ;; esac
	case $D in *[!A-Za-z0-9_.+/~-]*) die "CI26_DIR may only contain letters, digits and _ . + ~ - /, got '$D'" ;; esac
	# the shortest absolute paths, and the home directory itself, would be a disaster: refuse them whatever else is true
	case $D in / | /home | /root | /tmp | /usr | /var | /etc | /opt | /srv | /mnt | /bin | /lib | /boot | /dev | /proc | /sys | /run | "$HOME") die "refusing to use $D as the state directory" ;; esac
	V=$D/vm
	NICE="nice -n 19 choom -n 600 --"
}

need_tools() {
	local t
	for t in "$@"; do
		command -v "$t" >/dev/null 2>&1 || die "'$t' is needed on the box and was not found"
	done
}

need_kvm() {
	[ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not usable by $(id -un): the guest needs KVM (a build under emulation is too slow to be a test)"
}

# the state directory must be ours before anything is deleted in it
need_marker() {
	[ -f "$D/$MARKER" ] || die "$D has no $MARKER file: not a ci26 state directory (run create first)"
}

# create may mark a directory as its own only when it is new, empty, or holds nothing but bin/ (what the remote entry point put there):
# a directory with anything else in it belongs to somebody else, and the marker would make destroy delete its vm/ and stage/
need_new_or_ours() {
	local e
	[ ! -f "$D/$MARKER" ] || return 0
	[ -e "$D" ] || return 0
	[ -d "$D" ] || die "$D exists and is not a directory"
	for e in "$D"/* "$D"/.[!.]* "$D"/..?*; do
		[ -e "$e" ] || [ -L "$e" ] || continue
		[ "$e" = "$D/bin" ] || die "$D is not empty and has no $MARKER file: it is not a ci26 state directory, refusing to take it over (choose a new CI26_DIR)"
	done
}

vm_pid() {
	local p cl
	[ -f "$V/qemu.pid" ] || return 1
	p=$(cat "$V/qemu.pid" 2>/dev/null || true)
	is_uint "$p" || return 1
	# the pid must be the qemu of THIS state directory (the pid file may be stale and the number reused)
	[ -r "/proc/$p/cmdline" ] || return 1
	cl=$(tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null || true)
	case $cl in *"$V/disk.qcow2"*) ;; *) return 1 ;; esac
	echo "$p"
}

vm_running() { vm_pid >/dev/null 2>&1; }

guest_port() { cat "$V/port" 2>/dev/null || true; }

# ssh to the guest from the box. stdin is passed through: callers that must not read it say </dev/null.
G() {
	local port
	port=$(guest_port)
	is_uint "$port" || die "no guest port recorded: is the guest created and started?"
	ssh -i "$V/id_ci26" -p "$port" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10 -o ServerAliveInterval=30 \
		-o ServerAliveCountMax=20 -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$V/known_hosts" -o HostKeyAlias=ci26 \
		-o LogLevel=ERROR "$GUEST_USER@127.0.0.1" "$@"
}

free_port() {
	python3 - <<'EOF'
import random, socket
for _ in range(200):
    p = random.randint(20000, 39999)
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
    except OSError:
        s.close()
        continue
    s.close()
    print(p)
    break
else:
    raise SystemExit(1)
EOF
}

wait_ssh() {
	local limit=$1 i=0
	while [ "$i" -lt "$limit" ]; do
		vm_running || { note "the guest process is gone; last lines of the console:"; tail -n 15 "$V/console.log" >&2 || true; return 1; }
		if G true </dev/null 2>/dev/null; then return 0; fi
		sleep 2
		i=$((i + 2))
	done
	note "no ssh answer from the guest after ${limit}s; last lines of the console:"
	tail -n 15 "$V/console.log" >&2 || true
	return 1
}

# start_vm [seed_port]: boot the disk; with a seed port the first-boot configuration is read from http://10.0.2.2:PORT/ (cloud-init)
start_vm() {
	local seed=${1:-} port try smbios=""
	need_tools qemu-system-x86_64 python3 ssh nice choom
	need_kvm
	[ -f "$V/disk.qcow2" ] || die "no guest disk in $V: run create first"
	check_mem
	if [ -n "$seed" ]; then smbios="-smbios type=1,serial=ds=nocloud;s=http://10.0.2.2:$seed/"; fi
	: >"$V/console.log"
	try=0
	while [ "$try" -lt 3 ]; do
		port=$(free_port) || die "no free local port"
		echo "$port" >"$V/port"
		rm -f "$V/qemu.pid" "$V/mon.sock"
		# shellcheck disable=SC2086
		if $NICE qemu-system-x86_64 -name ci26 -enable-kvm -machine q35 -cpu host -smp "$CPUS" -m "${RAM_MB}M" \
			-display none -serial "file:$V/console.log" \
			-object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
			-drive "file=$V/disk.qcow2,if=none,id=d0,format=qcow2,cache=unsafe,discard=unmap" -device virtio-blk-pci,drive=d0 \
			-netdev "user,id=n0,hostfwd=tcp:127.0.0.1:$port-:22" -device virtio-net-pci,netdev=n0 \
			-monitor "unix:$V/mon.sock,server,nowait" -pidfile "$V/qemu.pid" -daemonize $smbios </dev/null >"$V/qemu.log" 2>&1 9>&-; then
			note "guest started (pid $(cat "$V/qemu.pid"), ssh forward 127.0.0.1:$port on this machine, $CPUS cores, ${RAM_MB} MiB)"
			return 0
		fi
		try=$((try + 1))
		note "qemu did not start (attempt $try): $(tail -n 2 "$V/qemu.log" | tr '\n' ' ')"
		sleep 1
	done
	die "qemu did not start"
}

stop_vm() {
	local p i=0
	p=$(vm_pid) || { note "the guest is not running"; return 0; }
	G 'sudo systemctl poweroff' </dev/null >/dev/null 2>&1 || true
	while [ "$i" -lt 90 ] && [ -d "/proc/$p" ]; do sleep 1; i=$((i + 1)); done
	if [ -d "/proc/$p" ] && [ -S "$V/mon.sock" ]; then
		note "guest did not power off in 90 s, asking qemu to quit"
		python3 - "$V/mon.sock" <<'EOF' || true
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(5)
s.connect(sys.argv[1])
s.sendall(b"quit\n")
EOF
		i=0
		while [ "$i" -lt 15 ] && [ -d "/proc/$p" ]; do sleep 1; i=$((i + 1)); done
	fi
	if [ -d "/proc/$p" ] && vm_running; then
		note "killing qemu pid $p (ours: its command line names $V/disk.qcow2)"
		kill "$p" 2>/dev/null || true
		sleep 2
	fi
	rm -f "$V/qemu.pid" "$V/mon.sock"
	note "guest stopped"
}

# ---- create -------------------------------------------------------------------------------------------------------------------

fetch_image() {
	local want got
	mkdir -p "$D/dl"
	if ! $NICE curl -fsS -I -m 30 "$IMAGE_URL/$IMAGE_NAME" >/dev/null 2>&1; then
		die "the Ubuntu 26.04 cloud image is not reachable at $IMAGE_URL/$IMAGE_NAME (see the fallback in the header of this script)"
	fi
	$NICE curl -fsS -m 60 -L "$IMAGE_URL/SHA256SUMS" -o "$D/dl/SHA256SUMS" || die "cannot fetch $IMAGE_URL/SHA256SUMS"
	want=$(awk -v n="$IMAGE_NAME" '$2 == "*" n || $2 == n { print $1; exit }' "$D/dl/SHA256SUMS")
	[ -n "$want" ] || die "$IMAGE_NAME is not in $IMAGE_URL/SHA256SUMS"
	if [ -f "$D/dl/$IMAGE_NAME" ] && [ "$(sha256sum "$D/dl/$IMAGE_NAME" | awk '{print $1}')" = "$want" ]; then
		note "image already downloaded and its sha256 matches"
	else
		note "downloading $IMAGE_NAME"
		$NICE curl -fL -sS --retry 5 --retry-delay 5 -C - -o "$D/dl/$IMAGE_NAME.part" "$IMAGE_URL/$IMAGE_NAME" || die "download failed"
		got=$(sha256sum "$D/dl/$IMAGE_NAME.part" | awk '{print $1}')
		[ "$got" = "$want" ] || { rm -f "$D/dl/$IMAGE_NAME.part"; die "sha256 of the download is $got, expected $want"; }
		mv "$D/dl/$IMAGE_NAME.part" "$D/dl/$IMAGE_NAME"
	fi
	note "image ok: sha256 $want"
}

# the first-boot configuration: one user with our public key, passwordless sudo INSIDE the guest, no ssh passwords
write_seed() {
	local pub
	pub=$(cat "$V/id_ci26.pub")
	mkdir -p "$V/seed"
	cat >"$V/seed/user-data" <<EOF
#cloud-config
hostname: ci26
users:
  - name: $GUEST_USER
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    lock_passwd: true
    ssh_authorized_keys:
      - $pub
ssh_pwauth: false
EOF
	printf 'instance-id: ci26-%s\nlocal-hostname: ci26\n' "$(date +%s)" >"$V/seed/meta-data"
	: >"$V/seed/vendor-data"
}

# runs in the guest as root: install exactly what the CI jobs install (plus the usual runner basics), quiet the machine, record versions
provision_script() {
	cat <<EOF
set -eu
export DEBIAN_FRONTEND=noninteractive
APT="apt-get -o DPkg::Lock::Timeout=600 -y -q"
if [ -n "${CI26_APT_MIRROR:-}" ]; then
	sed -i "s|http://[A-Za-z0-9.-]*/ubuntu|${CI26_APT_MIRROR:-}|g" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
fi
# nothing else may hold the apt lock or burn CPU while a build is timed
systemctl mask --now apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service unattended-upgrades.service \
	motd-news.timer esm-cache.service ua-timer.timer 2>/dev/null || true
\$APT update
# the packages of core.yml / harness.yml, valgrind (the hardening module's CI step), plus what a hosted runner image ships anyway
# (make, git, curl, rsync)
\$APT install --no-install-recommends build-essential gcc cmake ninja-build libssl-dev python3 gcc-multilib clang valgrind \
	git curl ca-certificates rsync file xz-utils
# the CI sanitizer jobs lower the mmap randomisation first; do it for good here
printf 'vm.mmap_rnd_bits = 28\n' >/etc/sysctl.d/60-ci26.conf
echo 28 >/proc/sys/vm/mmap_rnd_bits 2>/dev/null || true
# the box has no use for cloud-init after the first boot (it would look for a datasource that is not there)
touch /etc/cloud/cloud-init.disabled
EOF
}

versions_text() {
	cat <<'EOF'
echo "os      $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r)"
echo "gcc     $(gcc -dumpfullversion 2>/dev/null || echo missing)"
echo "clang   $(clang --version 2>/dev/null | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p;q')"
echo "cmake   $(cmake --version 2>/dev/null | sed -n '1s/.* //p')"
echo "ninja   $(ninja --version 2>/dev/null || echo missing)"
echo "python3 $(python3 --version 2>&1 | sed 's/Python //')"
echo "openssl $(openssl version 2>/dev/null | awk '{print $2}')"
echo "cores   $(nproc)   mem $(awk '/MemTotal/ {printf "%d MiB", $2/1024}' /proc/meminfo)   mmap_rnd_bits $(sudo cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo ?)"
EOF
}

# warn loudly when the compilers are not the ones of the CI runner
check_versions() {
	local out gcc clang
	out=$(versions_text | G bash -s) || return 0
	echo "$out"
	gcc=$(echo "$out" | awk '$1 == "gcc" { print $2 }')
	clang=$(echo "$out" | awk '$1 == "clang" { print $2 }')
	case $gcc in "$EXPECT_GCC"*) ;; *) note "WARNING: gcc is $gcc, the CI runner has $EXPECT_GCC (CI26_EXPECT_GCC)" ;; esac
	case $clang in "$EXPECT_CLANG"*) ;; *) note "WARNING: clang is $clang, the CI runner has $EXPECT_CLANG (CI26_EXPECT_CLANG)" ;; esac
}

# on any exit of create before it is finished: stop the seed server and the half-installed guest (it is not useful and it costs RAM)
CREATE_SEEDPID=""
CREATE_DONE=0
create_cleanup() {
	[ -z "$CREATE_SEEDPID" ] || kill "$CREATE_SEEDPID" 2>/dev/null || true
	if [ "$CREATE_DONE" != 1 ] && vm_running; then
		note "create did not finish: stopping the guest (run destroy before trying again, the disk is incomplete)"
		stop_vm || true
	fi
}

cmd_create() {
	local seedport
	need_new_or_ours
	need_tools qemu-img qemu-system-x86_64 curl python3 ssh ssh-keygen sha256sum nice choom
	need_kvm
	[ ! -e "$V/disk.qcow2" ] || die "a guest already exists in $V (use start, or destroy first)"
	mkdir -p "$D"
	[ -f "$D/$MARKER" ] || echo "ci26_vm state directory; destroy deletes the known sub-directories of it" >"$D/$MARKER"
	mkdir -p "$D/dl" "$D/logs" "$D/stage" "$D/bin" "$V"
	local freekb
	freekb=$(df -Pk "$D" | awk 'NR == 2 { print $4 }')
	[ "$freekb" -gt $(((DISK_GB + 5) * 1024 * 1024)) ] || die "less than $((DISK_GB + 5)) GiB free under $D"
	check_mem
	fetch_image
	# an overlay on the pristine download: destroy only has to delete the overlay
	# (the cloud image is qcow2 although it is named .img)
	$NICE qemu-img create -q -f qcow2 -F qcow2 -b "$D/dl/$IMAGE_NAME" "$V/disk.qcow2" "${DISK_GB}G" || die "qemu-img failed"
	rm -f "$V/id_ci26" "$V/id_ci26.pub" "$V/known_hosts"
	ssh-keygen -q -t ed25519 -N '' -C ci26 -f "$V/id_ci26"
	write_seed
	seedport=$(free_port) || die "no free local port"
	# the seed is served from the box's loopback for the first boot only (the guest sees it as 10.0.2.2)
	# -I: python ignores the current directory and the environment (it only serves the seed directory, which holds no code)
	$NICE python3 -I -m http.server "$seedport" --bind 127.0.0.1 --directory "$V/seed" >"$V/seed.log" 2>&1 </dev/null 9>&- &
	CREATE_SEEDPID=$!
	trap create_cleanup EXIT
	start_vm "$seedport"
	wait_ssh 420 || die "the guest did not come up for the first time"
	kill "$CREATE_SEEDPID" 2>/dev/null || true
	CREATE_SEEDPID=""
	note "first boot done, installing the CI packages (apt inside the guest)"
	provision_script | G 'sudo bash -s' || die "provisioning failed"
	note "installed:"
	check_versions | sed 's/^/  /' | tee "$V/versions.txt" >&2
	CREATE_DONE=1
	trap - EXIT
	stop_vm
	note "create finished: $D (disk $(du -sh "$V/disk.qcow2" | awk '{print $1}'))"
}

cmd_start() {
	check_limits
	[ -f "$V/disk.qcow2" ] || die "no guest in $V: run create first"
	if vm_running; then note "the guest is already running"; return 0; fi
	start_vm
	wait_ssh 240 || die "the guest did not come up"
	note "up: $(G 'uname -sr; nproc' </dev/null | tr '\n' ' ')"
}

cmd_stop() { need_marker; stop_vm; }

# the CI packages again, in a guest that exists already (apt-get install is idempotent): picks up what a newer create installs, e.g. valgrind
cmd_provision() {
	need_marker
	vm_running || cmd_start
	provision_script | G 'sudo bash -s' || die "provisioning failed"
	check_versions | sed 's/^/  /' | tee "$V/versions.txt" >&2
}

cmd_status() {
	[ -f "$D/$MARKER" ] || { echo "no state directory at $D"; return 0; }
	echo "state dir   $D"
	if vm_running; then echo "guest       running, pid $(vm_pid), ssh 127.0.0.1:$(guest_port) (on the box)"; else echo "guest       not running"; fi
	[ -f "$V/disk.qcow2" ] && echo "disk        $(du -sh "$V/disk.qcow2" | awk '{print $1}') used" || echo "disk        none"
	[ -f "$V/versions.txt" ] && sed 's/^/  /' "$V/versions.txt"
	local kb
	if kb=$(mem_available_kb 2>/dev/null) && is_uint "$kb"; then echo "MemAvailable $((kb / 1024 / 1024)) GiB"; else echo "MemAvailable unknown"; fi
	ls -1t "$D/logs" 2>/dev/null | head -n 3 | sed 's/^/log         /' || true
}

cmd_ssh() {
	need_marker
	vm_running || die "the guest is not running (start it)"
	G "$@"
}

cmd_log() {
	local f
	f=$(ls -1t "$D/logs"/*.log 2>/dev/null | head -n 1 || true)
	[ -n "$f" ] || die "no log yet"
	cat "$f"
}

# destroy [--purge]
cmd_destroy() {
	local purge=0
	case ${1:-} in '') ;; --purge) purge=1 ;; *) die "destroy: unknown argument '$1' (only --purge)" ;; esac
	if [ ! -d "$D" ]; then note "nothing to destroy at $D"; return 0; fi
	need_marker
	# a run in progress owns the guest: do not pull the disk from under it (flock is not on every machine; the selftest runs on a Mac)
	if command -v flock >/dev/null 2>&1; then
		exec 9>>"$D/run.lock"
		flock -n 9 || die "a run is in progress (it holds $D/run.lock): wait for it, or stop it, before destroy"
	fi
	vm_running && stop_vm
	# fixed sub-directories of the state directory, nothing computed from outside input
	rm -rf -- "${D:?}/vm" "${D:?}/stage" "${D:?}/bin"
	if [ "$purge" = 1 ]; then
		rm -rf -- "$D/dl" "$D/logs"
		rm -f -- "$D/run.lock" "$D/$MARKER"
		rmdir "$D" 2>/dev/null || note "$D still holds other files, left in place"
	fi
	if [ "$purge" = 1 ]; then note "destroyed and purged: $D"; else note "destroyed (image and logs kept): $D"; fi
}

# the exit status of run from the status the guest script reported: 0 and 1 are the verdict on the tree, 2 is "nothing was tested"; anything
# else (ssh's 255, a signal, no status line at all) is a failure of the machinery and also becomes 2; returns 1 for those
verdict_rc() {
	case $1 in 0 | 1 | 2) echo "$1" ;; *) echo 2; return 1 ;; esac
}

# ---- run (host side) -----------------------------------------------------------------------------------------------------------

cmd_run() {
	local label=${CI26_LABEL:-default} ccs=${CI26_CCS:-gcc clang} flav="" stages="matrix gates" stopafter=0 tree o
	OPTIND=1
	while getopts "l:c:f:s:S" o; do
		case $o in
		l) label=$OPTARG ;;
		c) ccs=$OPTARG ;;
		f) flav=$OPTARG ;;
		s) stages=$OPTARG ;;
		S) stopafter=1 ;;
		*) usage ;;
		esac
	done
	shift $((OPTIND - 1))
	[ $# -eq 1 ] || usage
	tree=$1
	check_words label "$label"
	case $label in '' | .* | *' '*) die "label must be one word and not start with a dot" ;; esac
	check_words compilers "$ccs"
	check_words flavours "$flav"
	check_words stages "$stages"
	[ "$flav" != all ] || flav="debug san release minsizerel relsan minsan"
	[ -n "$flav" ] || flav="debug san release minsizerel"
	[ -d "$tree/harness" ] && [ -d "$tree/core" ] || die "$tree is not a winrbd tree (no harness/ and core/)"
	need_marker
	need_tools rsync flock ssh

	# one run at a time: the timing checks of ctest must not see another job's load
	mkdir -p "$D/logs"
	exec 9>"$D/run.lock"
	if ! flock -n 9; then note "another run holds the lock, waiting"; flock 9; fi

	vm_running || cmd_start
	vm_running || die "the guest is not running"

	local port ts logf rc gdir
	port=$(guest_port)
	ts=$(date +%Y%m%d-%H%M%S)
	logf=$D/logs/$label-$ts.log
	gdir=work/$label
	G "mkdir -p '$gdir/src'" </dev/null
	note "copying $tree into the guest ($gdir/src)"
	$NICE rsync -a --delete --delete-excluded \
		--exclude=/.git --exclude='/build*' --exclude=/ci26-logs --exclude=.DS_Store --exclude='._*' --exclude=__pycache__ \
		--exclude='*.pyc' --exclude=/harness/.ceph-ref \
		-e "ssh -i $V/id_ci26 -p $port -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$V/known_hosts -o HostKeyAlias=ci26 -o LogLevel=ERROR" \
		"$tree/" "$GUEST_USER@127.0.0.1:$gdir/src/"
	G 'cat > ci26_guest.sh' <"$SELF"
	{
		echo "ci26_vm log $ts label=$label tree=$tree"
		echo "guest limits: $CPUS cores, ${RAM_MB} MiB"
		# no `exec`/stdin trick: the guest script reads nothing from stdin
		set +e
		G "env CI26_LABEL='$label' CI26_CCS='$ccs' CI26_FLAVOURS='$flav' CI26_STAGES='$stages' CI26_JOBS='${CI26_JOBS:-$CPUS}' CI26_CTEST_JOBS='${CI26_CTEST_JOBS:-4}' CI26_EXPECT_GCC='$EXPECT_GCC' CI26_EXPECT_CLANG='$EXPECT_CLANG' bash ci26_guest.sh --in-guest run-guest" </dev/null
		rc=$?
		set -e
		echo "ci26_vm exit status $rc"
	} 2>&1 | tee "$logf" || true
	rc=$(tail -n 1 "$logf" | sed -n 's/^ci26_vm exit status \([0-9]*\)$/\1/p')
	# 0 and 1 are the guest script's verdict on the tree, 2 is its "nothing was tested"; anything else (ssh 255, a signal, no status line)
	# is a problem of the machinery, not a failed check, and is reported as 2
	rc=$(verdict_rc "$rc") || note "the run did not end with a verdict: see $logf"
	echo "CI26_LOG=$logf"
	if [ "$stopafter" = 1 ]; then stop_vm; fi
	return "$rc"
}

# ---- the guest side (this runs inside the VM) -----------------------------------------------------------------------------------

RESULTS=""   # lines of the summary
NFAIL=0

# result STATUS NAME DETAIL
result() {
	RESULTS="$RESULTS$(printf '%-6s %-28s %s' "$1" "$2" "$3")
"
	case $1 in PASS | SKIP) ;; *) NFAIL=$((NFAIL + 1)) ;; esac
}

# the status word ctest printed for one test ("Passed", "Failed", "Timeout", "Skipped", ...), "-" when the test is not in the log
ctest_status() { # FILE NAME
	local st
	st=$(grep -E "Test +#[0-9]+: $2 " "$1" | head -n 1 | sed -E 's/.*\.\.+ *//; s/\*//g; s/ +[0-9.]+ sec.*//; s/ +$//' || true)
	if [ -n "$st" ]; then echo "$st"; else echo -; fi
}

# an excerpt of a failed step, for the short log
excerpt() { # FILE LINES
	echo "  --- last lines of $1:"
	tail -n "$2" "$1" | sed 's/^/  | /'
}

# the part of a ctest log that says what failed
ctest_failures() { # FILE
	local f=$1
	echo "  --- failed tests:"
	sed -n '/The following tests FAILED:/,$p' "$f" | head -n 30 | sed 's/^/  | /' || true
	grep -E '^\s*[0-9]+/[0-9]+ Test +#[0-9]+: .*(Failed|Timeout|Exception|SEGFAULT)' "$f" | head -n 10 | sed 's/^/  | /' || true
}

flavour_vars() { # NAME -> BT SAN
	case $1 in
	debug) BT=Debug; SAN="" ;;
	san) BT=Debug; SAN="address,undefined" ;;
	release) BT=Release; SAN="" ;;
	minsizerel) BT=MinSizeRel; SAN="" ;;
	relsan) BT=Release; SAN="address,undefined" ;;
	minsan) BT=MinSizeRel; SAN="address,undefined" ;;
	*) return 1 ;;
	esac
}

now() { date +%s; }

# matrix_one CC FLAVOUR
matrix_one() {
	local cc=$1 fl=$2 b log t0 t1 t2 st="" n_total n_fail n_skip ev name s need miss
	flavour_vars "$fl" || { result FAIL "$cc/$fl" "unknown flavour"; return 0; }
	b=$OUT/build/$cc-$fl
	log=$OUT/logs/$cc-$fl
	t0=$(now)
	if ! cmake -S "$SRC/harness" -B "$b" -G Ninja -DCMAKE_BUILD_TYPE="$BT" -DCMAKE_C_COMPILER="$cc" -DWR_WERROR=ON \
		${SAN:+-DWR_SANITIZE="$SAN"} >"$log.configure.log" 2>&1; then
		result FAIL "$cc/$fl" "configure failed"
		excerpt "$log.configure.log" 25
		return 0
	fi
	if ! timeout 3000 cmake --build "$b" -j "$JOBS" >"$log.build.log" 2>&1; then
		result FAIL "$cc/$fl" "build failed (-Werror)"
		grep -E 'error:|warning:' "$log.build.log" | head -n 15 | cut -c1-300 | sed 's/^/  | /' || true
		return 0
	fi
	t1=$(now)
	s=$(grep -c 'warning:' "$log.build.log" || true)
	if [ "$s" -gt 0 ]; then
		result FAIL "$cc/$fl" "build printed $s warning line(s)"
		grep 'warning:' "$log.build.log" | head -n 10 | sed 's/^/  | /' || true
		return 0
	fi
	if [ -n "$SAN" ]; then
		export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:detect_leaks=1
		export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
	fi
	set +e
	timeout 3000 ctest --test-dir "$b" --output-on-failure -j "$CTEST_JOBS" --timeout 600 -LE lab --no-tests=error >"$log.ctest.log" 2>&1
	st=$?
	set -e
	unset ASAN_OPTIONS UBSAN_OPTIONS
	t2=$(now)
	n_total=$(sed -n 's/.*tests passed, [0-9]* tests failed out of \([0-9]*\).*/\1/p' "$log.ctest.log" | tail -n 1)
	n_fail=$(sed -n 's/.*tests passed, \([0-9]*\) tests failed out of.*/\1/p' "$log.ctest.log" | tail -n 1)
	n_skip=$(grep -c '\*\*\*Skipped' "$log.ctest.log" || true)
	[ -n "$n_total" ] || n_total="?"
	[ -n "$n_fail" ] || n_fail="?"
	# the status of the named checks, so the log is the evidence that they ran (and did not just skip). The ones in $need must have
	# PASSED: a skip (no tool in the guest) or a missing registration would otherwise read as green. core_no_libc and core_no_globals
	# look at object code and are registered in the plain builds only (the sanitizer runtime adds symbols); secure.skel is informational
	# (a module may retire it)
	ev=""
	miss=""
	need="core.docs core_sources_in_sync core_freestanding core_freestanding_m32"
	[ -n "$SAN" ] || need="$need core_no_libc core_no_globals"
	for name in secure.skel core.docs core_sources_in_sync core_no_libc core_no_globals core_freestanding core_freestanding_os core_freestanding_m32; do
		s=$(ctest_status "$log.ctest.log" "$name")
		ev="$ev $name=$s"
		case " $need " in *" $name "*) [ "$s" = Passed ] || miss="$miss $name=$s" ;; esac
	done
	if [ "$st" -eq 0 ] && [ -n "$miss" ]; then
		result FAIL "$cc/$fl" "ctest passed but required checks did not pass:$miss"
	elif [ "$st" -eq 0 ]; then
		result PASS "$cc/$fl" "build $((t1 - t0))s, ctest $n_total tests, $n_fail failed, $n_skip skipped, $((t2 - t1))s"
	else
		result FAIL "$cc/$fl" "ctest exit $st: $n_fail failed of $n_total, $n_skip skipped"
		ctest_failures "$log.ctest.log"
	fi
	RESULTS="$RESULTS       checks:$ev
"
	# which tests skipped, so that a skip is a visible line and not just a count
	if [ "$n_skip" -gt 0 ]; then
		RESULTS="$RESULTS       skipped:$(grep '\*\*\*Skipped' "$log.ctest.log" | sed -E 's/.*Test +#[0-9]+: ([^ ]+) .*/ \1/' | tr -d '\n')
"
	fi
}

# the gates of harness.yml: the 32-bit core, the iPXE-flag core, every header on its own
gates_compile_matrix() { # CC
	local cc=$1 b flags log t0 target
	b=$OUT/build/cm-$cc
	log=$OUT/logs/cm-$cc
	flags="-fno-pie"
	[ "$cc" != clang ] || flags="$flags -fno-builtin-memcmp"
	t0=$(now)
	if ! cmake -S "$SRC/harness" -B "$b" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$flags" \
		-DWR_WITH_OPENSSL=OFF -DWR_WERROR=ON >"$log.configure.log" 2>&1; then
		result FAIL "$cc/compile-matrix" "configure failed"
		excerpt "$log.configure.log" 25
		return 0
	fi
	for target in wr_core_m32 wr_core_ipxe_flags wr_header_check; do
		# wr_core_ipxe_flags exists for gcc only (as in CI); the others for both, so a missing one (no gcc-multilib in the guest, a tree
		# without the target) is a failure and not a skip
		# (through a file: `ninja | grep -q` under pipefail fails when grep leaves early and the writer gets SIGPIPE)
		if ! ninja -C "$b" -t targets all >"$log.targets" 2>/dev/null; then
			result FAIL "$cc/$target" "ninja could not list the targets"
			continue
		fi
		if ! grep -q "^$target:" "$log.targets"; then
			if [ "$target" = wr_core_ipxe_flags ] && [ "$cc" != gcc ]; then
				result SKIP "$cc/$target" "gcc only, as in CI"
			else
				result FAIL "$cc/$target" "target not defined (no 32-bit toolchain in the guest, or the tree lacks it)"
			fi
			continue
		fi
		if ! timeout 1800 cmake --build "$b" --target "$target" -j "$JOBS" >"$log.$target.log" 2>&1; then
			result FAIL "$cc/$target" "build failed"
			grep -E 'error:|warning:' "$log.$target.log" | head -n 10 | cut -c1-300 | sed 's/^/  | /' || true
			continue
		fi
		if grep -q 'warning:' "$log.$target.log"; then
			result FAIL "$cc/$target" "build printed warnings"
			continue
		fi
		case $target in
		wr_core_m32 | wr_core_ipxe_flags)
			local objs lib
			lib=$b/core_$target.a
			objs=$(find "$b/CMakeFiles/$target.dir" -name '*.o' | sort)
			rm -f "$lib"
			# shellcheck disable=SC2086
			ar rcs "$lib" $objs
			if sh "$SRC/harness/tools/check_no_libc.sh" "$lib" >"$log.$target.gates.log" 2>&1 &&
				sh "$SRC/harness/tools/check_no_globals.sh" "$lib" >>"$log.$target.gates.log" 2>&1; then
				result PASS "$cc/$target" "built, no libc, no globals ($(echo "$objs" | wc -l) objects)"
			else
				result FAIL "$cc/$target" "object gates failed"
				excerpt "$log.$target.gates.log" 20
			fi
			;;
		*) result PASS "$cc/$target" "built" ;;
		esac
	done
	note_time "$cc compile-matrix" "$t0"
}

# the object gates on the optimised core
gates_object() { # CC BT
	local cc=$1 bt=$2 b log flags="" st
	b=$OUT/build/og-$cc-$bt
	log=$OUT/logs/og-$cc-$bt
	[ "$cc" != clang ] || flags="-fno-builtin-memcmp"
	if ! cmake -S "$SRC/harness" -B "$b" -G Ninja -DCMAKE_BUILD_TYPE="$bt" -DCMAKE_C_COMPILER="$cc" -DCMAKE_C_FLAGS="$flags" \
		-DWR_WITH_OPENSSL=OFF -DWR_BUILD_HOST=OFF -DWR_WERROR=ON >"$log.configure.log" 2>&1; then
		result FAIL "$cc/gates-$bt" "configure failed"
		excerpt "$log.configure.log" 25
		return 0
	fi
	if ! timeout 1800 cmake --build "$b" --target wr_core -j "$JOBS" >"$log.build.log" 2>&1 || grep -q 'warning:' "$log.build.log"; then
		result FAIL "$cc/gates-$bt" "core build failed or printed warnings"
		grep -E 'error:|warning:' "$log.build.log" | head -n 10 | cut -c1-300 | sed 's/^/  | /' || true
		return 0
	fi
	set +e
	ctest --test-dir "$b" --output-on-failure -R '^core_' --no-tests=error >"$log.ctest.log" 2>&1
	st=$?
	set -e
	if [ "$st" -eq 0 ]; then
		result PASS "$cc/gates-$bt" "$(sed -n 's/.*tests passed, [0-9]* tests failed out of \([0-9]*\).*/\1 core_ checks/p' "$log.ctest.log" | tail -n 1)"
	else
		result FAIL "$cc/gates-$bt" "core_ checks failed"
		ctest_failures "$log.ctest.log"
	fi
}

note_time() { echo "  ($1: $(($(now) - $2))s)" >&2; }

guest_run() {
	local cc fl st t0 vers
	LABEL=${CI26_LABEL:-default}
	CCS=${CI26_CCS:-"gcc clang"}
	FLAVOURS=${CI26_FLAVOURS:-"debug san release minsizerel"}
	STAGES=${CI26_STAGES:-"matrix gates"}
	JOBS=${CI26_JOBS:-$(nproc)}
	CTEST_JOBS=${CI26_CTEST_JOBS:-4}
	# the host side checked the label; this script deletes $OUT/build, so it checks again
	case $LABEL in '' | .* | */* | *[!A-Za-z0-9_.+-]*) echo "bad label '$LABEL'"; exit 2 ;; esac
	OUT=$HOME/work/$LABEL
	SRC=$OUT/src
	[ -d "$SRC/harness" ] || { echo "no tree at $SRC"; exit 2; }
	rm -rf "$OUT/build" "$OUT/logs"
	mkdir -p "$OUT/build" "$OUT/logs"
	t0=$(now)

	# the CI sanitizer jobs lower the mmap randomisation first (a no-op here after provisioning, kept in case the box was changed)
	echo 28 | sudo tee /proc/sys/vm/mmap_rnd_bits >/dev/null 2>&1 || true

	echo "== toolchain"
	vers=$(
		echo "os      $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r)"
		echo "gcc     $(gcc -dumpfullversion 2>/dev/null || echo missing)"
		echo "clang   $(clang --version 2>/dev/null | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p;q')"
		echo "cmake   $(cmake --version 2>/dev/null | sed -n '1s/.* //p')   ninja $(ninja --version 2>/dev/null || echo missing)"
		echo "openssl $(openssl version 2>/dev/null | awk '{print $2}')   python3 $(python3 --version 2>&1 | sed 's/Python //')"
		echo "cores   $(nproc), build jobs $JOBS, ctest -j $CTEST_JOBS   mem $(awk '/MemTotal/ {printf "%d MiB", $2/1024}' /proc/meminfo)   mmap_rnd_bits $(sudo cat /proc/sys/vm/mmap_rnd_bits 2>/dev/null || echo ?)"
	)
	echo "$vers"
	case $(echo "$vers" | awk '$1 == "gcc" { print $2 }') in
	"$CI26_EXPECT_GCC"*) ;; *) echo "WARNING: gcc differs from the CI runner's $CI26_EXPECT_GCC" ;;
	esac
	case $(echo "$vers" | awk '$1 == "clang" { print $2 }') in
	"$CI26_EXPECT_CLANG"*) ;; *) echo "WARNING: clang differs from the CI runner's $CI26_EXPECT_CLANG" ;;
	esac
	# which tree this was: a digest over every file name and content (no .git in the copy)
	echo "tree    $(cd "$SRC" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -c1-16) ($(cd "$SRC" && find . -type f | wc -l) files)"

	for st in $STAGES; do
		case $st in
		matrix)
			for cc in $CCS; do
				command -v "$cc" >/dev/null 2>&1 || { result FAIL "$cc" "compiler not found"; continue; }
				for fl in $FLAVOURS; do
					echo "== matrix $cc/$fl" >&2
					matrix_one "$cc" "$fl"
				done
			done
			;;
		gates)
			for cc in $CCS; do
				command -v "$cc" >/dev/null 2>&1 || { result FAIL "$cc" "compiler not found"; continue; }
				echo "== gates $cc" >&2
				gates_compile_matrix "$cc"
				gates_object "$cc" Release
				gates_object "$cc" MinSizeRel
			done
			;;
		*) result FAIL "$st" "unknown stage" ;;
		esac
	done

	echo
	echo "== result ($(($(now) - t0))s)"
	printf '%s' "$RESULTS"
	if [ "$NFAIL" -eq 0 ]; then echo "ALL PASSED"; else echo "FAILED: $NFAIL"; fi
	echo "full logs on the guest: $OUT/logs (reach them with: ci26_vm.sh ssh 'ls $OUT/logs')"
	[ "$NFAIL" -eq 0 ]
}

# ---- self test (no VM, no network: the guards and the parsing) --------------------------------------------------------------------

selftest() {
	local fails=0 t out me=$SELF
	ok() { echo "ok   $1"; }
	bad() { echo "FAIL $1"; fails=$((fails + 1)); }
	expect_rc() { # NAME WANT_RC CMD...
		local name=$1 want=$2 rc
		shift 2
		set +e
		"$@" >/dev/null 2>&1
		rc=$?
		set -e
		if [ "$rc" = "$want" ]; then ok "$name"; else bad "$name (exit $rc, wanted $want)"; fi
	}
	unset CI26_HOST CI26_CPUS CI26_RAM_MB CI26_DISK_GB CI26_MIN_AVAIL_GB CI26_MEMINFO CI26_DIR CI26_LABEL CI26_CCS CI26_JOBS CI26_CTEST_JOBS \
		CI26_APT_MIRROR CI26_EXPECT_GCC CI26_EXPECT_CLANG CI26_IMAGE_URL CI26_IMAGE_NAME CI26_LOGDIR
	t=$(mktemp -d "${TMPDIR:-/tmp}/ci26_selftest.XXXXXX")
	t=$(cd "$t" && pwd -P)
	# the script parses under bash
	expect_rc "syntax" 0 bash -n "$me"
	# the SPDX tag (core.docs wants it in the first three lines of every script)
	if head -n 3 "$me" | grep -q 'SPDX-License-Identifier: MIT'; then ok "spdx tag"; else bad "spdx tag"; fi
	# memory guard: 10 GiB available is refused, 100 GiB accepted
	printf 'MemTotal: 1\nMemAvailable:   10485760 kB\n' >"$t/low"
	printf 'MemTotal: 1\nMemAvailable:  104857600 kB\n' >"$t/high"
	printf 'MemTotal: 1\n' >"$t/none"
	expect_rc "memory guard refuses 10 GiB" 2 env CI26_MEMINFO="$t/low" CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "memory guard accepts 100 GiB" 0 env CI26_MEMINFO="$t/high" CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "memory guard: no MemAvailable line" 2 env CI26_MEMINFO="$t/none" CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "memory threshold is configurable" 0 env CI26_MIN_AVAIL_GB=8 CI26_MEMINFO="$t/low" CI26_DIR="$t/d" bash "$me" selftest-mem
	# caps
	expect_rc "25 cores refused" 2 env CI26_CPUS=25 CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "24 cores accepted" 0 env CI26_CPUS=24 CI26_MEMINFO="$t/high" CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "33 GiB RAM refused" 2 env CI26_RAM_MB=33792 CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "32 GiB RAM accepted" 0 env CI26_RAM_MB=32768 CI26_MEMINFO="$t/high" CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "cores must be a number" 2 env CI26_CPUS=eight CI26_DIR="$t/d" bash "$me" selftest-mem
	expect_rc "relative state directory refused" 2 env CI26_DIR=relative/dir bash "$me" status
	# destroy deletes nothing in a directory that is not ours
	mkdir -p "$t/foreign/vm" "$t/foreign/stage"
	echo keep >"$t/foreign/vm/precious"
	expect_rc "destroy refuses an unmarked directory" 2 env CI26_DIR="$t/foreign" bash "$me" destroy
	if [ -f "$t/foreign/vm/precious" ]; then ok "unmarked directory untouched"; else bad "unmarked directory was modified"; fi
	# destroy of a marked directory removes the known sub-directories only
	mkdir -p "$t/ours/vm" "$t/ours/stage" "$t/ours/dl" "$t/ours/logs" "$t/ours/other"
	echo "x" >"$t/ours/$MARKER"
	echo l >"$t/ours/logs/a.log"
	echo o >"$t/ours/other/file"
	expect_rc "destroy of a marked directory" 0 env CI26_DIR="$t/ours" bash "$me" destroy
	if [ ! -d "$t/ours/vm" ] && [ ! -d "$t/ours/stage" ] && [ -f "$t/ours/logs/a.log" ] && [ -d "$t/ours/dl" ] && [ -f "$t/ours/other/file" ]; then
		ok "destroy removed vm and stage, kept logs, image and foreign files"
	else
		bad "destroy removed the wrong things"
	fi
	expect_rc "destroy --purge" 0 env CI26_DIR="$t/ours" bash "$me" destroy --purge
	if [ ! -d "$t/ours/dl" ] && [ ! -d "$t/ours/logs" ] && [ -f "$t/ours/other/file" ]; then ok "purge removed image and logs, kept foreign files"; else bad "purge result"; fi
	# input checks of run
	expect_rc "run without a tree" 2 env CI26_DIR="$t/d" bash "$me" run
	expect_rc "run with a non-tree" 2 env CI26_DIR="$t/d" bash "$me" run "$t"
	expect_rc "run with a hostile label" 2 env CI26_DIR="$t/d" bash "$me" run -l 'x;y' "$t"
	expect_rc "unknown subcommand" 2 bash "$me" frobnicate
	# the flavour table
	out=$(bash "$me" selftest-flavours 2>&1) || true
	if [ "$out" = "debug=Debug: san=Debug:address,undefined release=Release: minsizerel=MinSizeRel: relsan=Release:address,undefined minsan=MinSizeRel:address,undefined bogus=ERR" ]; then
		ok "flavour table"
	else
		bad "flavour table: $out"
	fi
	# more input checks of run: compilers, flavours and stages end up in shell command lines and directory names
	expect_rc "run with hostile compilers" 2 env CI26_DIR="$t/d" bash "$me" run -c 'gcc;id' "$t"
	expect_rc "run with hostile flavours" 2 env CI26_DIR="$t/d" bash "$me" run -f 'debug$(id)' "$t"
	expect_rc "run with hostile stages" 2 env CI26_DIR="$t/d" bash "$me" run -s 'gates|id' "$t"
	expect_rc "run with a label that starts with a dot" 2 env CI26_DIR="$t/d" bash "$me" run -l .hidden "$t"
	expect_rc "run with a label with a slash" 2 env CI26_DIR="$t/d" bash "$me" run -l ../x "$t"
	# the state directory: no way to point it at a system directory or at the home directory, with or without a trailing slash
	expect_rc "state directory /" 2 env CI26_DIR=/ bash "$me" status
	expect_rc "state directory /etc/" 2 env CI26_DIR=/etc/ bash "$me" status
	expect_rc "state directory is HOME" 2 env HOME="$t" CI26_DIR="$t" bash "$me" status
	expect_rc "state directory is HOME with a slash" 2 env HOME="$t" CI26_DIR="$t/" bash "$me" status
	expect_rc "state directory with .." 2 env CI26_DIR="$t/a/../b" bash "$me" status
	expect_rc "state directory with a space" 2 env CI26_DIR="$t/a b" bash "$me" status
	expect_rc "state directory with doubled slashes is accepted" 0 env CI26_DIR="$t//d" bash "$me" status
	expect_rc "hostile apt mirror" 2 env CI26_APT_MIRROR='http://m/ubuntu|;id' CI26_DIR="$t/d" bash "$me" status
	expect_rc "ordinary apt mirror" 0 env CI26_APT_MIRROR='http://mirror.example.org/ubuntu' CI26_DIR="$t/d" bash "$me" status
	expect_rc "destroy with an unknown argument" 2 env CI26_DIR="$t/d" bash "$me" destroy --pruge
	# create does not take over a directory that holds someone else's files (the marker it writes would let destroy delete in it)
	mkdir -p "$t/other/vm"
	echo precious >"$t/other/vm/disk"
	out=$(env CI26_DIR="$t/other" bash "$me" create 2>&1) || true
	case $out in *"refusing to take it over"*) ok "create refuses a directory with foreign files" ;; *) bad "create did not refuse a foreign directory: $out" ;; esac
	if [ ! -e "$t/other/$MARKER" ] && [ -f "$t/other/vm/disk" ]; then ok "foreign directory got no marker and is untouched"; else bad "foreign directory was marked or changed"; fi
	# destroy stays out of the way of a running guest of someone else: a pid file that names a process which is not our qemu is not trusted
	mkdir -p "$t/live/vm"
	echo x >"$t/live/$MARKER"
	sleep 30 >/dev/null 2>&1 &
	local sp=$!
	echo "$sp" >"$t/live/vm/qemu.pid"
	out=$(env CI26_DIR="$t/live" bash "$me" status 2>&1) || true
	case $out in *"not running"*) ok "a pid that is not our qemu is not the guest" ;; *) bad "foreign pid taken for the guest: $out" ;; esac
	expect_rc "stop leaves a foreign process alone" 0 env CI26_DIR="$t/live" bash "$me" stop
	if kill -0 "$sp" 2>/dev/null; then ok "the foreign process is still alive"; else bad "stop killed a process that is not ours"; fi
	kill "$sp" 2>/dev/null || true
	wait "$sp" 2>/dev/null || true
	# a process whose command line names our disk is the guest
	if [ -r /proc/self/cmdline ]; then
		# a process whose argv[0] is the disk path (one process, so the kill below leaves nothing behind that holds ctest's pipes open)
		bash -c 'exec -a "$0" sleep 30' "$t/live/vm/disk.qcow2" >/dev/null 2>&1 &
		sp=$!
		echo "$sp" >"$t/live/vm/qemu.pid"
		out=$(env CI26_DIR="$t/live" bash "$me" status 2>&1) || true
		case $out in *"running, pid $sp"*) ok "a process that names our disk is the guest" ;; *) bad "our qemu not recognised: $out" ;; esac
		kill "$sp" 2>/dev/null || true
		wait "$sp" 2>/dev/null || true
	else
		echo "skip a process that names our disk is the guest (no /proc on this machine)"
	fi
	# destroy waits for a run: the lock is held, destroy refuses (needs flock)
	if command -v flock >/dev/null 2>&1; then
		mkdir -p "$t/busy/vm"
		echo x >"$t/busy/$MARKER"
		( flock -w 10 8 && exec sleep 20 ) 8>>"$t/busy/run.lock" >/dev/null 2>&1 &
		sp=$!
		local w=0
		while [ "$w" -lt 50 ] && flock -n "$t/busy/run.lock" true 2>/dev/null; do sleep 0.1; w=$((w + 1)); done
		expect_rc "destroy refuses while a run holds the lock" 2 env CI26_DIR="$t/busy" bash "$me" destroy
		if [ -d "$t/busy/vm" ]; then ok "nothing deleted under a running run"; else bad "destroy deleted under a running run"; fi
		kill "$sp" 2>/dev/null || true
		wait "$sp" 2>/dev/null || true
	fi
	# the variables handed to the box survive the shell quoting of the remote command line
	out=$(env CI26_LABEL="a b'c\$(echo X)" CI26_CPUS=4 bash "$me" selftest-exports) || true
	if [ "$(bash -c "$out"' printf "%s|%s" "$CI26_LABEL" "$CI26_CPUS"')" = "a b'c\$(echo X)|4" ]; then ok "remote exports are quoted"; else bad "remote exports: $out"; fi
	# the exit status the caller of run sees
	if [ "$(verdict_rc 0)" = 0 ] && [ "$(verdict_rc 1)" = 1 ] && [ "$(verdict_rc 2)" = 2 ] && [ "$(verdict_rc 255)" = 2 ] && [ "$(verdict_rc '')" = 2 ]; then
		ok "exit status: 0/1/2 pass through, everything else is 2"
	else
		bad "verdict_rc"
	fi
	# reading the ctest log: a failure, a timeout, a skip and a pass are told apart, and a test that is not there is "-"
	cat >"$t/ctest.log" <<'EOF'
 1/5 Test  #1: core.docs ....................   Passed    0.31 sec
 2/5 Test  #2: core_no_libc .................***Failed    0.02 sec
 3/5 Test  #3: core_freestanding_m32 ........***Skipped   0.00 sec
 4/5 Test  #4: core_no_globals ..............***Timeout 600.01 sec
 5/5 Test  #5: core_freestanding_os .........   Passed  100.00 sec
EOF
	if [ "$(ctest_status "$t/ctest.log" core.docs)" = Passed ] && [ "$(ctest_status "$t/ctest.log" core_no_libc)" = Failed ] &&
		[ "$(ctest_status "$t/ctest.log" core_freestanding_m32)" = Skipped ] && [ "$(ctest_status "$t/ctest.log" core_no_globals)" = Timeout ] &&
		[ "$(ctest_status "$t/ctest.log" core_freestanding)" = - ] && [ "$(ctest_status "$t/ctest.log" core_freestanding_os)" = Passed ]; then
		ok "ctest status parsing"
	else
		bad "ctest status parsing"
	fi
	# usage names every subcommand
	out=$(bash "$me" help 2>&1) || true
	case $out in *create*start*run*stop*destroy*provision*) ok "usage lists the subcommands" ;; *) bad "usage: $out" ;; esac
	rm -rf "$t"
	if [ "$fails" -eq 0 ]; then echo "selftest: all passed"; else echo "selftest: $fails failed"; exit 1; fi
}

# ---- dispatch -----------------------------------------------------------------------------------------------------------------------

# the CI26_* variables the box side must see, as `export` statements for the remote shell
remote_exports() {
	local v val out=""
	for v in CI26_DIR CI26_CPUS CI26_RAM_MB CI26_DISK_GB CI26_MIN_AVAIL_GB CI26_JOBS CI26_CTEST_JOBS CI26_CCS CI26_LABEL CI26_IMAGE_URL \
		CI26_IMAGE_NAME CI26_APT_MIRROR CI26_EXPECT_GCC CI26_EXPECT_CLANG; do
		val=${!v:-}
		if [ -n "$val" ]; then out="$out export $v=$(printf %q "$val");"; fi
	done
	printf '%s' "$out"
}

main_remote() {
	# CI26_SSH_OPTS is deliberately split into words
	local -a SSH
	# shellcheck disable=SC2206
	SSH=(ssh -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=20 ${CI26_SSH_OPTS:-} "$CI26_HOST")
	local ex hdir sub=$1 args="" a tree="" rc=0 tmp logpath
	shift
	ex=$(remote_exports)
	# put this very script on the box (no repository checkout needed there) and learn the state directory. Written beside and renamed over
	# (atomic): another run on the box may be executing the old file, and bash reads a script as it goes, so rewriting it in place would
	# make that run execute pieces of the new text
	hdir=$("${SSH[@]}" "$ex"'d=${CI26_DIR:-$HOME/winrbd-ci26}; mkdir -p "$d/bin" && cat >"$d/bin/.ci26_vm.sh.new.$$" && chmod 700 "$d/bin/.ci26_vm.sh.new.$$" && mv -f "$d/bin/.ci26_vm.sh.new.$$" "$d/bin/ci26_vm.sh" && printf %s "$d"' <"$SELF") ||
		die "cannot reach $CI26_HOST (set CI26_SSH_OPTS for jump hosts and host-key aliases)"
	if [ "$sub" = run ]; then
		# the tree is the last argument; it is copied to the box first and replaced by the staged path
		local n=$#
		local -a av
		av=("$@")
		[ "$n" -ge 1 ] || usage
		tree=${av[$((n - 1))]}
		[ -d "$tree/harness" ] && [ -d "$tree/core" ] || die "$tree is not a winrbd tree (no harness/ and core/)"
		local label=${CI26_LABEL:-default} i
		for ((i = 0; i < n - 1; i++)); do [ "${av[$i]}" != -l ] || label=${av[$((i + 1))]}; done
		check_words label "$label"
		case $label in '' | .* | *' '*) die "label must be one word and not start with a dot" ;; esac
		note "staging $tree on $CI26_HOST"
		"${SSH[@]}" "mkdir -p '$hdir/stage/$label'"
		rsync -a --delete --delete-excluded \
			--exclude=/.git --exclude='/build*' --exclude=/ci26-logs --exclude=.DS_Store --exclude='._*' --exclude=__pycache__ \
			--exclude='*.pyc' --exclude=/harness/.ceph-ref \
			-e "ssh -o BatchMode=yes ${CI26_SSH_OPTS:-}" "$tree/" "$CI26_HOST:$hdir/stage/$label/"
		for ((i = 0; i < n - 1; i++)); do args="$args $(printf %q "${av[$i]}")"; done
		args="$args $(printf %q "$hdir/stage/$label")"
	else
		for a in "$@"; do args="$args $(printf %q "$a")"; done
	fi
	tmp=$(mktemp "${TMPDIR:-/tmp}/ci26_out.XXXXXX")
	set +e
	"${SSH[@]}" "$ex $(printf %q "$hdir/bin/ci26_vm.sh") $sub $args" </dev/null 2>&1 | tee "$tmp"
	rc=${PIPESTATUS[0]}
	set -e
	logpath=$(sed -n 's/^CI26_LOG=//p' "$tmp" | tail -n 1)
	if [ -n "$logpath" ]; then
		local ld=${CI26_LOGDIR:-${TMPDIR:-/tmp}/ci26-logs}
		mkdir -p "$ld"
		if rsync -a -e "ssh -o BatchMode=yes ${CI26_SSH_OPTS:-}" "$CI26_HOST:$logpath" "$ld/" >/dev/null 2>&1; then
			note "short log copied to $ld/$(basename "$logpath")"
		else
			note "could not copy $logpath back"
		fi
	fi
	rm -f "$tmp"
	exit "$rc"
}

main() {
	[ $# -ge 1 ] || usage
	case $1 in
	-h | --help | help) usage ;;
	selftest) shift; selftest; exit 0 ;;
	esac

	# internal entry points
	if [ "$1" = --in-guest ]; then
		shift
		case ${1:-} in run-guest) guest_run ;; *) die "bad guest command" ;; esac
		exit $?
	fi
	if [ "$1" = selftest-exports ]; then remote_exports; exit 0; fi
	if [ "$1" = selftest-flavours ]; then
		for f in debug san release minsizerel relsan minsan bogus; do
			if flavour_vars "$f"; then printf '%s=%s:%s ' "$f" "$BT" "$SAN"; else printf '%s=ERR\n' "$f"; fi
		done
		exit 0
	fi

	local sub=$1
	case $sub in
	create | start | stop | destroy | provision | status | run | ssh | log | selftest-mem) ;;
	*) echo "ci26_vm: unknown subcommand '$sub'" >&2; usage ;;
	esac

	if [ -n "${CI26_HOST:-}" ] && [ "${CI26_ON_HOST:-0}" != 1 ]; then
		check_limits
		main_remote "$@"
	fi

	shift
	host_init
	case $sub in
	selftest-mem) check_mem ;;
	create) cmd_create ;;
	start) cmd_start ;;
	stop) cmd_stop ;;
	provision) cmd_provision ;;
	destroy) cmd_destroy "$@" ;;
	status) cmd_status ;;
	run) cmd_run "$@" ;;
	ssh) cmd_ssh "$@" ;;
	log) cmd_log ;;
	esac
}

# one line: bash has parsed all of it before main runs, so a rewrite of this file while it runs can never be read as the next command
main "$@"; exit $?
