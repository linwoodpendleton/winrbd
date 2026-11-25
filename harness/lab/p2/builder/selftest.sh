#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Offline self-test of the Phase 2 builder scripts (up.sh, down.sh, build-ipxe.sh, build-harness.sh). No VM, no QEMU, no ssh to anywhere,
# no network, no root: ssh, rsync and the ci26_vm.sh wrapper are replaced by stand-ins, the iPXE build by a fake build.sh, and every file it
# makes is below one temporary directory that it removes at the end.
#
#   selftest.sh            run everything; exit status 0 only when every check passed (a check that needs something this machine
#                          does not have, such as /proc or GNU stat, says "skip" and does not count as a pass)
#
# What it proves (each is a defect found in review of the module, or a guard that must never go away):
#   * the settings: the caps of this guest (8 cores, 12 GiB), the state-directory rules (absolute, plain, no system directory, no HOME)
#   * up.sh never takes over a directory that is not its own; down.sh deletes only what it made, keeps what it was told to keep
#     (--keep-logs also keeps the ci26_vm.sh logs), and reports what is left
#   * the copy that goes to the shared box and into the guest carries no secret: lab.conf, key and keyring files, private keys never
#     travel; the six public test-vector keyrings and the pinned iPXE tree do; with "noipxe" the iPXE tree is left out
#   * a script is put into the guest as a file and run with stdin on /dev/null (never "bash -s" on the ssh pipe), and its arguments are words
#   * the command line the box runs: BUILDER_* values with spaces or $(...) in them arrive as plain text
#   * build-harness.sh refuses a run that tests nothing (empty stage list, unknown flavour or compiler, a hostile label) and finds the
#     PASS lines by exact name
#   * the verdict logic of build-ipxe.sh (the guest script, run against a stand-in build.sh): all-good passes; every one of these fails:
#     a warning, a missing image, a driver not in a link map, a self-test object in an image, a licence verdict that is not exactly
#     GPL 2 or later although the lines above it say so, a Secure Boot build that succeeds, a driver object that is not FORBIDDEN, a
#     pristine control that does not build, a failing self-test run
# shellcheck disable=SC2329,SC2016,SC2015  # the cases are called through their names; the quotes are deliberate
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

pass=0 fail=0 skips=0
ok()   { pass=$((pass + 1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf '  FAIL %s\n' "$1" >&2; }
skip() { skips=$((skips + 1)); printf '  skip %s\n' "$1"; }
check() { # DESCRIPTION COMMAND...   (run in this shell; success = pass)
	local d=$1
	shift
	if "$@"; then ok "$d"; else bad "$d"; fi
}
# expect_rc NAME WANT_RC CMD...: the command's exit status; its output goes to $out (for the checks that read the message)
out=""
expect_rc() {
	local name=$1 want=$2 rc
	shift 2
	set +e
	out=$("$@" 2>&1)
	rc=$?
	set -e
	if [ "$rc" = "$want" ]; then ok "$name"; else bad "$name (exit $rc, wanted $want): $(printf '%s' "$out" | head -n 3 | tr '\n' '|')"; fi
}
contains() { case $out in *"$1"*) return 0 ;; *) return 1 ;; esac; }

t=$(mktemp -d "${TMPDIR:-/tmp}/builder_selftest.XXXXXX")
t=$(cd "$t" && pwd -P)
trap 'rm -rf "$t"' EXIT
# nothing the caller has set may leak into the cases
unset BUILDER_HOST BUILDER_SSH_OPTS BUILDER_DIR BUILDER_CPUS BUILDER_RAM_MB BUILDER_DISK_GB BUILDER_JOBS BUILDER_IMAGE_CACHE BUILDER_APT_MIRROR \
	BUILDER_LOCAL_LOGS BUILDER_LOCAL_OUT BUILDER_DETACH BUILDER_TREE BUILDER_ON_BOX BUILDER_ALLOW_OTHER_TOOLCHAIN CI26_HOST CI26_SSH_OPTS CI26_DIR
HOME=$t/home
mkdir -p "$HOME"
export HOME
is_linux=0
[ "$(uname -s)" = Linux ] && [ -r /proc/self/status ] && is_linux=1

echo "== syntax and tags"
for f in up.sh down.sh build-ipxe.sh build-harness.sh selftest.sh; do
	check "$f parses" bash -n "$here/$f"
	check "$f has the SPDX tag in its first three lines" bash -c "head -n 3 '$here/$f' | grep -q 'SPDX-License-Identifier: MIT'"
done

echo "== settings"
up="$here/up.sh"
expect_rc "defaults resolve" 0 env BUILDER_DIR="$t/b1" bash "$up" env
contains "cpus=8 ram_mb=12288 disk_gb=60 jobs=8" && ok "default caps: 8 cores, 12 GiB, 60 GiB disk" || bad "defaults: $out"
expect_rc "9 cores refused (the cap of this guest is 8)" 2 env BUILDER_DIR="$t/b1" BUILDER_CPUS=9 bash "$up" env
expect_rc "8 cores accepted" 0 env BUILDER_DIR="$t/b1" BUILDER_CPUS=8 bash "$up" env
expect_rc "0 cores refused" 2 env BUILDER_DIR="$t/b1" BUILDER_CPUS=0 bash "$up" env
expect_rc "cores must be a number" 2 env BUILDER_DIR="$t/b1" BUILDER_CPUS=eight bash "$up" env
expect_rc "12289 MiB refused (the cap is 12 GiB)" 2 env BUILDER_DIR="$t/b1" BUILDER_RAM_MB=12289 bash "$up" env
expect_rc "12288 MiB accepted" 0 env BUILDER_DIR="$t/b1" BUILDER_RAM_MB=12288 bash "$up" env
expect_rc "disk 19 GiB refused" 2 env BUILDER_DIR="$t/b1" BUILDER_DISK_GB=19 bash "$up" env
expect_rc "jobs 65 refused" 2 env BUILDER_DIR="$t/b1" BUILDER_JOBS=65 bash "$up" env
expect_rc "hostile apt mirror refused" 2 env BUILDER_DIR="$t/b1" BUILDER_APT_MIRROR='http://m/ubuntu|;id' bash "$up" env
expect_rc "relative state directory refused" 2 env BUILDER_DIR=relative/dir bash "$up" env
expect_rc "state directory /" 2 env BUILDER_DIR=/ bash "$up" env
expect_rc "state directory /etc/" 2 env BUILDER_DIR=/etc/ bash "$up" env
expect_rc "state directory is HOME" 2 env BUILDER_DIR="$HOME" bash "$up" env
expect_rc "state directory is HOME with a slash" 2 env BUILDER_DIR="$HOME/" bash "$up" env
expect_rc "state directory with .." 2 env BUILDER_DIR="$t/a/../b" bash "$up" env
expect_rc "state directory with a space" 2 env BUILDER_DIR="$t/a b" bash "$up" env
expect_rc "doubled slashes are normalised" 0 env BUILDER_DIR="$t//b2//" bash "$up" env
contains "dir=$t/b2 " && ok "normalised to $t/b2" || bad "normalised dir: $out"
expect_rc "BUILDER_HOST without BUILDER_DIR refused" 2 env BUILDER_HOST=nobody@nowhere bash "$up" status
expect_rc "unknown subcommand" 2 bash "$up" frobnicate

echo "== state directory ownership"
mkdir -p "$t/foreign"
echo precious >"$t/foreign/file"
expect_rc "up.sh refuses a directory with foreign files" 2 env BUILDER_DIR="$t/foreign" bash "$up" up
contains "refusing to take it over" && ok "...and says why" || bad "message: $out"
[ ! -e "$t/foreign/.winrbd-builder-dir" ] && [ -f "$t/foreign/file" ] && ok "foreign directory got no marker and is untouched" || bad "foreign directory was marked or changed"
mkdir -p "$t/foreign2/.hidden"
expect_rc "up.sh refuses a directory with only a hidden entry" 2 env BUILDER_DIR="$t/foreign2" bash "$up" up
expect_rc "down.sh refuses an unmarked directory" 2 env BUILDER_DIR="$t/foreign" bash "$here/down.sh"
[ -f "$t/foreign/file" ] && ok "down.sh left the foreign file alone" || bad "down.sh deleted a foreign file"
expect_rc "down.sh on a directory that does not exist" 0 env BUILDER_DIR="$t/nothing" bash "$here/down.sh"

echo "== down.sh"
mk_marked() { # DIR: a marked state directory with every known part, one foreign file
	local d=$1
	mkdir -p "$d/stage/repo" "$d/out/ipxe" "$d/logs" "$d/ci26/vm" "$d/ci26/dl" "$d/ci26/logs"
	echo m >"$d/.winrbd-builder-dir"
	echo m >"$d/ci26/.ci26-vm-dir"
	echo r >"$d/ready"
	echo o >"$d/out/ipxe/ipxe.efi"
	echo l >"$d/logs/a.log"
	echo c >"$d/ci26/logs/c.log"
	echo i >"$d/ci26/dl/image.img"
}
if [ "$is_linux" = 1 ]; then
	mk_marked "$t/d1"
	expect_rc "down.sh destroys a marked directory" 0 env BUILDER_DIR="$t/d1" bash "$here/down.sh"
	[ ! -e "$t/d1" ] && ok "everything is gone, the directory too" || bad "left: $(ls -A "$t/d1" | tr '\n' ' ')"
	mk_marked "$t/d2"
	echo mine >"$t/d2/foreign-file"
	expect_rc "a foreign file in a marked directory: exit 1, file kept" 1 env BUILDER_DIR="$t/d2" bash "$here/down.sh"
	[ -f "$t/d2/foreign-file" ] && [ ! -e "$t/d2/stage" ] && [ ! -e "$t/d2/out" ] && ok "only the known parts were deleted" || bad "down.sh result in d2"
	mk_marked "$t/d3"
	expect_rc "down.sh --keep-out" 0 env BUILDER_DIR="$t/d3" bash "$here/down.sh" --keep-out
	[ -f "$t/d3/out/ipxe/ipxe.efi" ] && [ ! -e "$t/d3/logs" ] && [ ! -e "$t/d3/stage" ] && [ ! -e "$t/d3/ci26/dl" ] && [ ! -e "$t/d3/ci26/logs" ] && ok "out kept, everything else gone" || bad "keep-out: $(find "$t/d3" -type f | tr '\n' ' ')"
	mk_marked "$t/d4"
	expect_rc "down.sh --keep-logs" 0 env BUILDER_DIR="$t/d4" bash "$here/down.sh" --keep-logs
	[ -f "$t/d4/logs/a.log" ] && [ -f "$t/d4/ci26/logs/c.log" ] && [ ! -e "$t/d4/ci26/dl" ] && [ ! -e "$t/d4/out" ] && ok "both log directories kept (the ci26_vm.sh logs too), image and results gone" || bad "keep-logs: $(find "$t/d4" -type f | tr '\n' ' ')"
	mk_marked "$t/d5"
	expect_rc "down.sh --keep-image" 0 env BUILDER_DIR="$t/d5" bash "$here/down.sh" --keep-image
	[ -f "$t/d5/ci26/dl/image.img" ] && [ ! -e "$t/d5/ci26/logs" ] && [ ! -e "$t/d5/logs" ] && [ ! -e "$t/d5/out" ] && ok "image kept, logs and results gone" || bad "keep-image: $(find "$t/d5" -type f | tr '\n' ' ')"
	expect_rc "down.sh on the kept remains finishes the job" 0 env BUILDER_DIR="$t/d5" bash "$here/down.sh"
	[ ! -e "$t/d5" ] && ok "second down.sh removed the rest" || bad "remains: $(find "$t/d5" | tr '\n' ' ')"
	mk_marked "$t/d6"
	# a process that names the directory is reported (and its presence is exit 1), one that does not is not
	bash -c 'exec -a "$0" sleep 30' "$t/d6/ci26/vm/disk.qcow2" >/dev/null 2>&1 &
	sp=$!
	expect_rc "down.sh reports a process that still names the directory" 1 env BUILDER_DIR="$t/d6" bash "$here/down.sh"
	contains "still name" && ok "...and says which" || bad "message: $out"
	kill "$sp" 2>/dev/null || true
	wait "$sp" 2>/dev/null || true
else
	skip "down.sh cases (need /proc)"
fi

echo "== what travels to the box and into the guest"
if command -v rsync >/dev/null 2>&1; then
	# a tree with secrets of every kind, the public vector keyrings and a fake iPXE tree that has a .pem of its own
	s=$t/tree
	mkdir -p "$s/harness/lab" "$s/harness/vectors/public/keys" "$s/harness/vectors/public/secure/keys" "$s/harness/vectors/public/other" "$s/third_party/ipxe/src" "$s/third_party/wnbd" "$s/core" "$s/build/x" "$s/.git" "$s/sub/lab-secrets" "$s/.ssh-ish" "$s/.github/workflows" "$s/.toolstate"
	for f in harness/lab/lab.conf harness/lab/lab.conf.example sub/x.keyring sub/keyring sub/a.secret sub/b.key sub/c.pem sub/d.p12 sub/id_ed25519 sub/id_ed25519.pub sub/id_rsa \
		sub/lab-secrets/k sub/ceph.conf.local harness/vectors/public/keys/client.vec-k1.keyring harness/vectors/public/secure/keys/client.vec-sec-k1.keyring \
		harness/vectors/public/other/leak.keyring third_party/ipxe/src/Makefile third_party/ipxe/src/test.pem third_party/wnbd/w core/c.c build/x/o .git/config ordinary.txt sub/__pycache__x .github/workflows/w.yml .gitignore .toolstate/s .localfile; do
		echo "$f" >"$s/$f"
	done
	copy_with() { # DEST [noipxe]
		local ex=() l
		while IFS= read -r l; do ex+=("$l"); done < <(
			# shellcheck source=up.sh
			. "$up"
			BUILDER_ON_BOX=1
			b_excludes "${2:-}"
		)
		rsync -a --delete --delete-excluded "${ex[@]}" "$s/" "$1/"
	}
	copy_with "$t/c1"
	for f in ordinary.txt core/c.c harness/lab/lab.conf.example harness/vectors/public/keys/client.vec-k1.keyring \
		harness/vectors/public/secure/keys/client.vec-sec-k1.keyring third_party/ipxe/src/Makefile third_party/ipxe/src/test.pem .github/workflows/w.yml .gitignore; do
		[ -f "$t/c1/$f" ] && ok "travels: $f" || bad "does not travel (it must): $f"
	done
	for f in harness/lab/lab.conf sub/x.keyring sub/keyring sub/a.secret sub/b.key sub/c.pem sub/d.p12 sub/id_ed25519 sub/id_ed25519.pub sub/id_rsa sub/lab-secrets/k sub/ceph.conf.local \
		harness/vectors/public/other/leak.keyring third_party/wnbd/w build/x/o .git/config .toolstate/s .localfile; do
		[ ! -e "$t/c1/$f" ] && ok "stays home: $f" || bad "travels (it must not): $f"
	done
	copy_with "$t/c2" noipxe
	[ ! -e "$t/c2/third_party/ipxe" ] && [ -f "$t/c2/ordinary.txt" ] && ok "noipxe leaves the iPXE tree out" || bad "noipxe: $(find "$t/c2/third_party" | tr '\n' ' ')"
else
	skip "copy filter cases (no rsync)"
fi

echo "== guest scripts are files, with stdin on /dev/null"
(
	# shellcheck source=up.sh
	. "$up"
	BUILDER_ON_BOX=1
	b_die() { echo "builder: $*" >&2; exit 2; }
	calls=$t/guest-calls
	: >"$calls"
	# stand-in for the ci26_vm.sh wrapper: records the command and what is on stdin
	ci26() {
		local stdin
		stdin=$(cat | tr '\n' '~')
		printf 'ci26 %s <<%s>>\n' "$*" "$stdin" >>"$calls"
	}
	printf 'echo line1\necho line2\n' | b_guest_exec -s extras 12 0
	printf 'x\n' | b_guest_exec verify
	for bad_arg in 'a b' 'x;id' '$(id)' ''; do
		if (printf 'x\n' | b_guest_exec verify "$bad_arg") >/dev/null 2>&1; then echo "ACCEPTED-ARG $bad_arg" >>"$calls"; fi
	done
	if (printf 'x\n' | b_guest_exec 'a/b') >/dev/null 2>&1; then echo "ACCEPTED-NAME" >>"$calls"; fi
) >/dev/null 2>&1 || true
calls=$t/guest-calls
[ "$(sed -n 1p "$calls")" = "ci26 ssh mkdir -p .builder && cat >.builder/extras.sh <<echo line1~echo line2~>>" ] && ok "the script text is written to ~/.builder/extras.sh" || bad "write call: $(sed -n 1p "$calls")"
[ "$(sed -n 2p "$calls")" = "ci26 ssh sudo bash .builder/extras.sh 12 0 <<>>" ] && ok "it runs as root from the file, arguments as words, stdin empty" || bad "run call: $(sed -n 2p "$calls")"
[ "$(sed -n 4p "$calls")" = "ci26 ssh bash .builder/verify.sh <<>>" ] && ok "a non-root script runs without sudo" || bad "verify call: $(sed -n 4p "$calls")"
! grep -q 'ACCEPTED' "$calls" && ok "hostile arguments and names are refused" || bad "accepted: $(grep ACCEPTED "$calls" | tr '\n' ' ')"
! grep -q 'bash -s' "$calls" && ok "no \"bash -s\" anywhere" || bad "bash -s used"

echo "== the command line the box runs"
if command -v git >/dev/null 2>&1 && [ -e "$here/../../../../third_party/ipxe/.git" ] && command -v rsync >/dev/null 2>&1; then
	mkdir -p "$t/bin"
	log=$t/ssh-log
	: >"$log"
	cat >"$t/bin/ssh" <<EOF
#!/bin/sh
# stand-in: records the last argument (the remote command) and does nothing
for a; do last=\$a; done
printf '%s\n' "\$last" >>"$log"
exit 0
EOF
	cat >"$t/bin/rsync" <<'EOF'
#!/bin/sh
exit 0
EOF
	chmod +x "$t/bin/ssh" "$t/bin/rsync"
	expect_rc "a remote run with awkward values" 0 env PATH="$t/bin:$PATH" TMPDIR="$t" BUILDER_HOST=nobody@nowhere BUILDER_DIR="$t/remote-dir" \
		BUILDER_IMAGE_CACHE="/x y/\$(touch $t/PWNED)/z" BUILDER_LOCAL_LOGS="$t/ll" bash "$up" status
	last=$(tail -n 1 "$log")
	got=$(bash -c 'env() { printf "[%s]\n" "$@"; }; bash() { printf "[%s]\n" "$@"; }; '"$last") || got="EVAL-FAILED"
	case $got in *"[BUILDER_ON_BOX=1]"*) ok "the box side is told it is on the box" ;; *) bad "no BUILDER_ON_BOX: $got" ;; esac
	case $got in *"[BUILDER_IMAGE_CACHE=/x y/\$(touch $t/PWNED)/z]"*) ok "a value with a space and \$(...) arrives as plain text" ;; *) bad "value mangled: $got" ;; esac
	[ ! -e "$t/PWNED" ] && ok "...and nothing was executed" || bad "the value was executed"
	case $got in *"[status]"*) ok "the subcommand is passed" ;; *) bad "no subcommand: $got" ;; esac
	case $got in *"$t/remote-dir/stage/repo/harness/lab/p2/builder/up.sh"*) ok "it runs the staged copy" ;; *) bad "wrong script: $got" ;; esac
	case $got in *BUILDER_HOST* | *BUILDER_SSH_OPTS*) bad "BUILDER_HOST leaked to the box" ;; *) ok "BUILDER_HOST and BUILDER_SSH_OPTS stay home" ;; esac
	# a directory on the box that is not ours is refused by the staging command itself (the stand-in prints it; evaluate it here)
	first=$(sed -n 1p "$log")
	mkdir -p "$t/theirs"
	echo x >"$t/theirs/f"
	set +e
	bash -c "$first" >/dev/null 2>&1
	rc=$?
	set -e
	# $first is the staging command for $t/remote-dir (not marked, does not exist yet): it creates it; run the same text against a foreign directory
	[ "$rc" = 0 ] && ok "staging into a new directory works" || bad "staging command rc $rc"
	foreign_cmd=$(printf '%s' "$first" | sed "s|$t/remote-dir|$t/theirs|g")
	set +e
	bash -c "$foreign_cmd" >/dev/null 2>&1
	rc=$?
	set -e
	[ "$rc" = 3 ] && [ ! -d "$t/theirs/stage" ] && ok "staging refuses a foreign directory on the box (exit 3, nothing made)" || bad "staging into a foreign directory: rc $rc"
else
	skip "remote command cases (need git, rsync and the third_party/ipxe checkout)"
fi

echo "== build-harness.sh arguments"
bh="$here/build-harness.sh"
expect_rc "an empty stage list is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -s ""
contains "tests nothing" && ok "...with the reason" || bad "message: $out"
expect_rc "an unknown stage is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -s "matrix gate"
expect_rc "an unknown flavour is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -f "debug fast"
expect_rc "an unknown compiler is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -c "gcc tcc"
expect_rc "a hostile compiler list is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -c 'gcc;id'
expect_rc "a label with .. is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -l '../x'
expect_rc "a label with a leading dot is refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -l '.x'
expect_rc "ctest jobs 17 refused" 2 env BUILDER_DIR="$t/b1" bash "$bh" -j 17
expect_rc "a valid request without a guest stops at the guest (exit 2)" 2 env BUILDER_DIR="$t/b1" bash "$bh" -f all
contains "not a builder state directory" && ok "...saying there is no builder" || bad "message: $out"

# PASS lines are found by exact name
(
	# shellcheck source=build-harness.sh
	. "$bh"
	printf 'PASS   gcc/debug              build 1s\nFAIL   gcc/san                incl. PASS gcc/san\nPASS   gcc/release-x          x\nSKIP   clang/debug            x\n' >"$t/res.log"
	bh_has_pass "$t/res.log" gcc/debug || exit 1
	bh_has_pass "$t/res.log" gcc/san && exit 2
	bh_has_pass "$t/res.log" gcc/release && exit 3
	bh_has_pass "$t/res.log" clang/debug && exit 4
	bh_has_pass "$t/res.log" 'gcc/d.bug' && exit 5
	exit 0
) && ok "bh_has_pass: exact names, only PASS counts (not FAIL, SKIP, a prefix or a regex)" || bad "bh_has_pass (exit $?)"

echo "== build-ipxe.sh: the verdict logic against a stand-in build.sh"
if [ "$is_linux" = 1 ] && command -v git >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1 && command -v make >/dev/null 2>&1 && command -v nm >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
	W=$t/gh/work/ipxe/src
	mkdir -p "$W/ipxe/tools" "$W/ipxe/src" "$W/third_party/ipxe/src"
	# the "pinned iPXE": a real git repository whose src/Makefile can build the pristine -sb target
	cat >"$W/third_party/ipxe/src/Makefile" <<'EOF'
bin-x86_64-efi-sb/snponly.efi:
	mkdir -p bin-x86_64-efi-sb
	echo pristine > $@
EOF
	(
		cd "$W/third_party/ipxe"
		git init -q .
		git -c user.name=t -c user.email=t@example.org -c commit.gpgsign=false add -A
		git -c user.name=t -c user.email=t@example.org -c commit.gpgsign=false commit -q -m pin
		git rev-parse HEAD >"$W/ipxe/PINNED"
	)
	echo 'printf ( "rbd: key material must not be part of the URI" );' >"$W/ipxe/src/rbd_uri.c"
	# the stand-in build.sh: FAKE is the scenario ("good" or one thing that is wrong)
	cat >"$W/ipxe/tools/build.sh" <<'EOF'
#!/usr/bin/env bash
# stand-in for ipxe/tools/build.sh: acts out the scenario in $FAKE
set -u
sub=$1
shift
out=""
targets=()
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift 2 ;;
	-j) shift 2 ;;
	-n | -u) shift ;;
	*) targets+=("$1"); shift ;;
	esac
done
case $sub in
check) [ "$FAKE" != check-fails ] ;;
build)
	t=${targets[0]}
	if [ "$t" = bin-x86_64-efi-sb/snponly.efi ]; then
		mkdir -p "$out/src/bin-x86_64-efi-sb" "$out/src/winrbd"
		for i in $(seq 1 60); do
			[ -f "$out/src/winrbd/f$i.c" ] || echo "int x;" >"$out/src/winrbd/f$i.c"
			if [ "$FAKE" = not-forbidden ] && [ "$i" = 7 ]; then echo "int y;" | gcc -c -x c - -o "$out/src/bin-x86_64-efi-sb/f$i.o"
			else echo "int __secboot__forbidden__f$i;" | gcc -c -x c - -o "$out/src/bin-x86_64-efi-sb/f$i.o"; fi
		done
		if [ "$FAKE" = sb-succeeds ]; then echo ok >"$out/src/$t"; exit 0; fi
		echo "This build includes files that are not permitted to be signed for UEFI Secure Boot"
		exit 2
	fi
	for t in "${targets[@]}"; do
		[ "$FAKE" = missing-image ] && [ "$t" = bin/ipxe.usb ] && continue
		mkdir -p "$out/src/$(dirname "$t")"
		echo "image $t" >"$out/src/$t"
		if [ "$t" = bin-x86_64-efi/ipxe.efi ]; then
			echo "key material must not be part of the URI" >>"$out/src/$t"
			[ "$FAKE" != selftest-in-image ] || echo "rbd_selftest" >>"$out/src/$t"
		fi
	done
	for m in bin-x86_64-efi/ipxe.efi bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.lkrn bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.lkrn; do
		mkdir -p "$out/src/$(dirname "$m")"
		case $FAKE in
		no-link-map) [ "$m" != bin/ipxe.pxe ] || continue ;;
		no-driver) echo "blib.a(other.o)" >"$out/src/$m.tmp.map"; continue ;;
		esac
		echo "blib.a(rbd_uri.o)" >"$out/src/$m.tmp.map"
		[ "$FAKE" != selftest-linked ] || [ "$m" != bin/undionly.kpxe ] || echo "blib.a(tests.o)" >>"$out/src/$m.tmp.map"
	done
	[ "$FAKE" != warning ] || echo "foo.c:1:2: warning: something"
	[ "$FAKE" != build-fails ] || exit 2
	exit 0
	;;
licence)
	cat <<'LIC'
GPL version 2 (or, at your option, any later version) subsumes GPL version 2 (or, at your option, any later version) or Unmodified Binary Distribution Licence
MIT/X11/Xorg Licence subsumes Public Domain
The overall licence for this file is:
LIC
	case $FAKE in
	licence-gpl2-only) echo "  GPL version 2 only" ;;
	licence-ubdl) echo "  GPL version 2 (or, at your option, any later version) or Unmodified Binary Distribution Licence" ;;
	licence-none) ;;
	*) echo "  GPL version 2 (or, at your option, any later version)" ;;
	esac
	[ "$FAKE" != licence-fails ] || exit 1
	;;
test)
	[ "$FAKE" != selftest-fails ] || { echo "FAILURE: broken"; exit 1; }
	echo 'OK: all 305 tests passed'
	;;
esac
EOF
	# the guest script text, as it is shipped
	( . "$here/build-ipxe.sh"; guest_script ) >"$t/guest-ipxe.sh"
	run_guest() { # SCENARIO [control tests]: runs the guest script in the fixture; $out has its output, status in $?
		local sc=$1 control=${2:-1} tests=${3:-1}
		rm -rf "$t/gh/work/ipxe/build" "$t/gh/work/ipxe/build-ubsan" "$t/gh/work/ipxe/build-negctl" "$t/gh/work/ipxe/pristine" "$t/gh/work/ipxe/results"
		env HOME="$t/gh" FAKE="$sc" bash "$t/guest-ipxe.sh" 2 0 "$control" "$tests"
	}
	expect_rc "scenario good: every check passes" 0 run_guest good
	contains "RESULT 0 check(s) failed" && ok "...and says so" || bad "result line: $(printf '%s' "$out" | tail -n 3)"
	contains "licence bin-x86_64-efi/snponly.efi" && contains "every driver object is FORBIDDEN" && contains "self-tests negative-control" && contains "control: pristine tree" && ok "...with the licence, FORBIDDEN, self-test and control lines present" || bad "missing check lines: $out"
	# results.txt has the verdict lines too (the README says it does), not only the header
	[ "$(grep -c '^PASS ' "$t/gh/work/ipxe/results/results.txt")" -ge 20 ] && grep -q '^RESULT 0 check' "$t/gh/work/ipxe/results/results.txt" && ok "results.txt carries the check lines and the RESULT line" || bad "results.txt: $(wc -l <"$t/gh/work/ipxe/results/results.txt") lines"
	for sc in check-fails build-fails warning missing-image no-link-map no-driver selftest-linked selftest-in-image licence-gpl2-only licence-ubdl licence-none licence-fails sb-succeeds not-forbidden selftest-fails; do
		expect_rc "scenario $sc fails the run" 1 run_guest "$sc"
	done
	# the pristine control: the pinned tree is committed with a src/Makefile whose -sb target fails, and the control must then fail the run
	set_pristine() { # good | broken: commit the stand-in tree's Makefile and pin the new revision
		if [ "$1" = good ]; then printf 'bin-x86_64-efi-sb/snponly.efi:\n\tmkdir -p bin-x86_64-efi-sb\n\techo pristine > $@\n' >"$W/third_party/ipxe/src/Makefile"
		else printf 'bin-x86_64-efi-sb/snponly.efi:\n\tfalse\n' >"$W/third_party/ipxe/src/Makefile"; fi
		git -C "$W/third_party/ipxe" -c user.name=t -c user.email=t@example.org -c commit.gpgsign=false commit -q -am "pristine $1 $RANDOM"
		git -C "$W/third_party/ipxe" rev-parse HEAD >"$W/ipxe/PINNED"
	}
	set_pristine broken
	expect_rc "a pristine tree that does not build fails the run (the control)" 1 run_guest good
	contains "control: pristine tree builds the -sb target" && contains "FAIL" && ok "...naming the control" || bad "control message: $(printf '%s' "$out" | grep -i control)"
	set_pristine good
	# -C and -T skip their checks, and nothing else
	expect_rc "-C -T: control and self-tests skipped, the rest passes" 0 run_guest good 0 0
	{ ! contains "control: pristine" && ! contains "self-tests"; } && ok "...and neither is run" || bad "skipped checks ran: $out"
	expect_rc "the wrong pinned revision fails the run" 1 bash -c "echo 0000000000000000000000000000000000000000 >'$W/ipxe/PINNED'; env HOME='$t/gh' FAKE=good bash '$t/guest-ipxe.sh' 2 0 1 1"
	contains "pinned iPXE revision" && ok "...at the pin check" || bad "message: $out"
else
	skip "build-ipxe.sh verdict cases (need Linux, git, gcc, make, nm, timeout)"
fi

echo
echo "builder selftest: $pass passed, $fail failed, $skips skipped"
[ "$fail" -eq 0 ]
