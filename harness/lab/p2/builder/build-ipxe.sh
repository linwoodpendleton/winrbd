#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-ipxe.sh - build iPXE with the winrbd rbd:// driver in the builder guest (Ubuntu 26.04, gcc 15.2) and check the result the way the CI
# job `ipxe` and docs/design/ipxe-driver.md (section 3, 14.2) say:
#
#   build-ipxe.sh [-j N] [-k] [-C] [-T] [-S]
#
#   -j N   build jobs in the guest (default BUILDER_JOBS, = the cores)
#   -k     keep the build trees in the guest (default: deleted after the results are copied out)
#   -C     skip the control build of the pristine tree (see 5 below)
#   -T     skip the self-tests (see 6 below)
#   -S     power the guest off afterwards
#
# What it does: copies the repository and a clone of the pinned iPXE (third_party/ipxe at the revision of ipxe/PINNED, .git included: the
# build script reads the revision from git and exports committed files only) into the guest, then in the guest runs
#
#   0. ipxe/tools/build.sh check
#   1. ipxe/tools/build.sh build  bin-x86_64-efi/ipxe.efi  bin/undionly.kpxe  bin/ipxe.pxe  bin/ipxe.usb  bin/ipxe.iso
#                                 bin-x86_64-efi/snponly.efi  bin-x86_64-efi/ipxe.iso
#      from a clean prepared tree (pinned export + patches + glue + core), with iPXE's own -Werror; the log must have ZERO "warning" lines
#   2. the driver is linked into the four images (iPXE's link maps name rbd_uri.o) and its console line is a string of
#      bin-x86_64-efi/ipxe.efi; no self-test object is in any image (the link maps and the bytes of the EFI image)
#   3. ipxe/tools/build.sh licence  bin/undionly.kpxe  bin-x86_64-efi/snponly.efi
#      the line after "The overall licence for this file is:" must be exactly "GPL version 2 (or, at your option, any later version)"
#      (the "subsumes" lines above it also contain that text, so a search over the whole output would pass a GPL-2-only or a mixed result)
#   4. ipxe/tools/build.sh build bin-x86_64-efi-sb/snponly.efi must FAIL with "not permitted to be signed for UEFI Secure Boot" and leave no
#      binary: every file of the driver is FILE_SECBOOT ( FORBIDDEN ) by design. The refusal is one verdict for the whole image, so the
#      compiled objects are looked at one by one: each glue and core object must carry the symbol __secboot__forbidden__<object>
#   5. control: the same Secure Boot target built from the PRISTINE pinned tree (no patch, no driver) must SUCCEED, so that 4 fails because
#      of the driver and not for some other reason
#   6. the self-tests of ipxe/tests, as in the CI job "self-tests", with gcc 15: build.sh test (64-bit program, 32-bit program, both with
#      UBSan in trap mode) and the negative control (build.sh test -n: a deliberate failure must be seen)
#
# and prints one PASS / FAIL line per check, the sizes against the skeleton's table (informational: the box that measured them had gcc 11.4),
# and sha256 sums. Results (the binaries, the logs, results.txt) are copied to BUILDER_DIR/out/ipxe/ on the box (and to BUILDER_LOCAL_OUT
# from your machine). One build at a time per guest (the lock of ci26_vm.sh run), so that the timing checks of build-harness.sh never see a
# build. The guest must exist (up.sh). Environment and the two ways to run it: see up.sh.
#
# Exit status: 0 every check passed; 1 a check failed; 2 environment problem (nothing was tested: ssh or rsync failed, no verdict came back).

set -eu
set -o pipefail
LC_ALL=C
export LC_ALL

BI_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=up.sh
. "$BI_HERE/up.sh"

# runs in the guest. $1 = jobs, $2 = keep (0/1), $3 = control (0/1)
guest_script() {
	cat <<'GUEST'
set -u
set -o pipefail
LC_ALL=C
export LC_ALL
JOBS=$1
KEEP=$2
CONTROL=$3
TESTS=$4
W=$HOME/work/ipxe
SRC=$W/src
OUT=$W/build
PRIS=$W/pristine
RES=$W/results
rm -rf "$OUT" "$OUT-ubsan" "$OUT-negctl" "$PRIS" "$RES"
mkdir -p "$RES"
cd "$SRC" || exit 2
FAIL=0
# every verdict line goes to the screen and to results.txt (the README says results.txt has the check lines)
ok() { local l; l=$(printf 'PASS  %-44s %s' "$1" "$2"); echo "$l"; echo "$l" >>"$RES/results.txt"; }
bad() { local l; l=$(printf 'FAIL  %-44s %s' "$1" "$2"); echo "$l"; echo "$l" >>"$RES/results.txt"; FAIL=$((FAIL + 1)); }
# a hung build must not hold the guest (and the lock of ci26_vm.sh) for ever
B() { timeout 3000 bash ipxe/tools/build.sh "$@"; }
now() { date +%s; }

# bin/ is the DEFAULT_ARCH of the pinned iPXE (x86_64): 64-bit BIOS images. The 32-bit images, with iPXE's 4 KiB stack and the core on its own
# 16 KiB stack (what most BIOS machines run), are bin-i386-pcbios/: both are built and checked
TARGETS="bin-x86_64-efi/ipxe.efi bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso bin-x86_64-efi/snponly.efi bin-x86_64-efi/ipxe.iso bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso"
{
	echo "iPXE build check $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "os      $(. /etc/os-release; echo "$PRETTY_NAME") kernel $(uname -r)"
	echo "gcc     $(gcc -dumpfullversion)"
	echo "clang   $(clang --version | sed -n 's/.*clang version \([0-9][0-9.]*\).*/\1/p;q')"
	echo "make    $(make --version | sed -n 1p)"
	echo "ld      $(ld --version | sed -n 1p)"
	echo "perl    $(perl -e 'print $^V')"
	echo "jobs    $JOBS"
	# which tree this was (the box copy can be replaced by another driver between two runs): a digest over every file name and content
	echo "tree    $(cd "$SRC" && find . -type f -not -path './third_party/ipxe/.git/*' | LC_ALL=C sort | xargs -d '\n' sha256sum | sha256sum | cut -c1-16)"
} | tee "$RES/results.txt"

# 0. pinned revision and static checks
want=$(sed -n '1{s/[[:space:]].*//;p;}' ipxe/PINNED)
have=$(git -C third_party/ipxe rev-parse HEAD 2>/dev/null || echo none)
if [ "$have" = "$want" ]; then ok "pinned iPXE revision" "$have"; else bad "pinned iPXE revision" "have $have, want $want"; fi
if B check >"$RES/check.log" 2>&1; then ok "build.sh check" "glue files tagged, no name collisions"; else bad "build.sh check" "see check.log"; cat "$RES/check.log"; fi

# 1. the targets
t0=$(now)
B build -o "$OUT" -j "$JOBS" $TARGETS >"$RES/build.log" 2>&1
rc=$?
t1=$(now)
nw=$(grep -ci 'warning' "$RES/build.log" || true)
ne=$(grep -ciE 'error:|\*\*\*|fatal' "$RES/build.log" || true)
if [ "$rc" = 0 ] && [ "$nw" = 0 ] && [ "$ne" = 0 ]; then
	ok "build, zero warnings (-Werror)" "$((t1 - t0)) s, $(wc -l <"$RES/build.log") log lines"
else
	bad "build, zero warnings (-Werror)" "exit $rc, $nw warning line(s), $ne error line(s)"
	grep -i -m 15 -E 'warning|error' "$RES/build.log" | cut -c1-300 | sed 's/^/        | /'
fi
sizes() { # NAME TARGET DOCSIZE
	local f=$OUT/src/$2 sz
	if [ -s "$f" ]; then
		sz=$(stat -c %s "$f")
		cp "$f" "$RES/$1"
		ok "target $2" "$sz bytes (skeleton table: ${3:-n/a})"
	else
		bad "target $2" "not built"
	fi
}
sizes ipxe.efi bin-x86_64-efi/ipxe.efi 1288704
sizes undionly.kpxe bin/undionly.kpxe 133909
sizes ipxe.pxe bin/ipxe.pxe 480617
sizes ipxe.usb bin/ipxe.usb 507904
sizes ipxe.iso bin/ipxe.iso
sizes snponly.efi bin-x86_64-efi/snponly.efi
sizes efi-ipxe.iso bin-x86_64-efi/ipxe.iso
sizes i386-undionly.kpxe bin-i386-pcbios/undionly.kpxe
sizes i386-ipxe.pxe bin-i386-pcbios/ipxe.pxe
sizes i386-ipxe.usb bin-i386-pcbios/ipxe.usb
sizes i386-ipxe.iso bin-i386-pcbios/ipxe.iso

# 2. the driver is in the images, the self-tests are not. Two looks: the link maps iPXE leaves next to every image (which object files went
# in; the BIOS images are compressed, so their bytes cannot be searched) and, for the EFI image, which is not compressed, its bytes. Each
# look has a positive control (the driver IS in the image), so that an empty search means something.
msg='key material must not be part of the URI'
for m in bin-x86_64-efi/ipxe.efi bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.lkrn bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.lkrn; do
	map=$OUT/src/$m.tmp.map
	if [ ! -f "$map" ]; then bad "link map of $m" "no $map (iPXE changed its file names?)"; continue; fi
	if ! grep -q 'blib\.a(rbd_uri\.o)' "$map"; then bad "driver linked into $m" "rbd_uri.o is not in the link map"
	elif grep -Eq 'rbd_selftest|\(tests\.o\)' "$map"; then bad "no self-test in $m" "a self-test object is in the link map"
	else ok "driver in $m, no self-test" "link map"; fi
done
if grep -q "$msg" ipxe/src/rbd_uri.c 2>/dev/null; then
	if [ -s "$RES/ipxe.efi" ] && [ "$(LC_ALL=C grep -a -c "$msg" "$RES/ipxe.efi")" -ge 1 ]; then ok "driver text in ipxe.efi" "console line present"; else bad "driver text in ipxe.efi" "console line not found"; fi
	if [ -s "$RES/ipxe.efi" ] && [ "$(LC_ALL=C grep -a -c rbd_selftest "$RES/ipxe.efi")" = 0 ]; then ok "no self-test text in ipxe.efi" "no rbd_selftest string"; else bad "no self-test text in ipxe.efi" "rbd_selftest found (or the image is missing)"; fi
else
	bad "driver text in ipxe.efi" "the marker string is not in ipxe/src/rbd_uri.c any more: update this check"
fi

# 3. the licence check on a real build (the two targets without NIC drivers; the all-driver images fail it on the pristine tree too).
# The verdict is the line right after "The overall licence for this file is:", compared whole. A search for the text anywhere in the output
# is not enough: the "... subsumes ..." lines above the verdict contain it too, so a result of "GPL version 2 only" would still match.
licence_verdict() { # LOGFILE -> prints the verdict line(s), one per "overall licence" header
	awk '/The overall licence for this file is:/ { want = 1; next } want { sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, ""); print; want = 0 }' "$1"
}
for t in bin/undionly.kpxe bin-i386-pcbios/undionly.kpxe bin-x86_64-efi/snponly.efi; do
	n=licence-$(basename "$t").log
	B licence -o "$OUT" "$t" >"$RES/$n" 2>&1
	rc=$?
	v=$(licence_verdict "$RES/$n")
	if [ "$rc" = 0 ] && [ "$v" = "GPL version 2 (or, at your option, any later version)" ]; then
		ok "licence $t" "$v"
	else
		bad "licence $t" "exit $rc, verdict '$v' (see $n)"
		tail -n 12 "$RES/$n" | sed 's/^/        | /'
	fi
done

# 4. the Secure Boot build is refused, and every object of the driver is FORBIDDEN
B build -o "$OUT" -j "$JOBS" bin-x86_64-efi-sb/snponly.efi >"$RES/sb.log" 2>&1
rc=$?
if [ "$rc" != 0 ] && grep -q 'not permitted to be signed for UEFI Secure Boot' "$RES/sb.log" && [ ! -e "$OUT/src/bin-x86_64-efi-sb/snponly.efi" ]; then
	ok "Secure Boot build refused" "$(grep -m1 -o 'not permitted to be signed for UEFI Secure Boot' "$RES/sb.log")"
else
	bad "Secure Boot build refused" "exit $rc (wanted non-zero with the refusal message and no binary); tail of sb.log:"
	tail -n 12 "$RES/sb.log" | sed 's/^/        | /'
fi
# the refusal is one verdict for the whole image: a single file marked PERMITTED would not change it. Each glue and core object must carry
# the symbol __secboot__forbidden__<object> (compiler.h gives every file "permitted" by default; only an explicit FILE_SECBOOT ( FORBIDDEN )
# adds the other one)
nobj=0
nbad=0
for c in "$OUT"/src/winrbd/*.c; do
	o=$OUT/src/bin-x86_64-efi-sb/$(basename "$c" .c).o
	[ -f "$o" ] || continue
	nobj=$((nobj + 1))
	# (grep -c, not -q: with pipefail, grep -q closing the pipe early can kill nm with SIGPIPE and make the pipeline look false)
	if [ "$(nm "$o" | grep -c ' __secboot__forbidden__' || true)" -lt 1 ]; then nbad=$((nbad + 1)); echo "        | not FORBIDDEN: $c"; fi
done
if [ "$nobj" -gt 50 ] && [ "$nbad" = 0 ]; then ok "every driver object is FORBIDDEN" "$nobj objects"; else bad "every driver object is FORBIDDEN" "$nobj objects found (want > 50), $nbad not forbidden"; fi

# 5. control: the pristine pinned tree builds the same Secure Boot target
if [ "$CONTROL" = 1 ]; then
	mkdir -p "$PRIS"
	git -C third_party/ipxe archive --format=tar HEAD | tar -x -C "$PRIS"
	( cd "$PRIS/src" && make -j "$JOBS" bin-x86_64-efi-sb/snponly.efi ) >"$RES/pristine-sb.log" 2>&1
	rc=$?
	if [ "$rc" = 0 ] && [ -s "$PRIS/src/bin-x86_64-efi-sb/snponly.efi" ]; then
		ok "control: pristine tree builds the -sb target" "$(stat -c %s "$PRIS/src/bin-x86_64-efi-sb/snponly.efi") bytes"
	else
		bad "control: pristine tree builds the -sb target" "exit $rc; see pristine-sb.log"
		tail -n 12 "$RES/pristine-sb.log" | sed 's/^/        | /'
	fi
fi

# 6. the self-tests (CI job "self-tests"), with this guest's compiler. Each run is accepted by build.sh test only when the program exits 0,
# prints "OK: all N tests passed", has no FAILURE line and every ipxe/tests file has its own OK line; -n is the negative control
if [ "$TESTS" = 1 ]; then
	runtest() { # NAME ARGS...
		local name=$1 log
		shift
		log=$RES/selftest-$name.log
		t0=$(now)
		if B test -o "$OUT" -j "$JOBS" "$@" >"$log" 2>&1; then
			ok "self-tests $name" "$((($(now)) - t0)) s, $(grep -m1 '^OK: all' "$log" | tr -d '\r' || true)"
		else
			bad "self-tests $name" "see selftest-$name.log"
			tail -n 12 "$log" | sed 's/^/        | /'
		fi
	}
	runtest 64bit
	runtest 32bit bin-i386-linux/tests.linux
	runtest 64bit-ubsan -u
	runtest 32bit-ubsan -u bin-i386-linux/tests.linux
	runtest negative-control -n
fi

# sums of what was built
( cd "$RES" && sha256sum ipxe.efi undionly.kpxe ipxe.pxe ipxe.usb ipxe.iso snponly.efi efi-ipxe.iso i386-undionly.kpxe i386-ipxe.pxe i386-ipxe.usb i386-ipxe.iso 2>/dev/null ) | tee "$RES/SHA256SUMS" >/dev/null
echo "RESULT $FAIL check(s) failed" | tee -a "$RES/results.txt" >/dev/null
echo "RESULT $FAIL check(s) failed"
if [ "$KEEP" != 1 ]; then rm -rf "$OUT" "$OUT-ubsan" "$OUT-negctl" "$PRIS"; fi
[ "$FAIL" = 0 ]
GUEST
}

bi_main() {
	local jobs="" keep=0 control=1 tests=1 stop=0 o rc=0 ts log rev have
	OPTIND=1
	while getopts "j:kCTSh" o; do
		case $o in
		j) jobs=$OPTARG ;;
		k) keep=1 ;;
		C) control=0 ;;
		T) tests=0 ;;
		S) stop=1 ;;
		*) sed -n '4,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; [ "$o" = h ] && exit 0; exit 2 ;;
		esac
	done
	shift $((OPTIND - 1))
	[ $# -eq 0 ] || b_die "no arguments expected, got '$*'"
	if [ -n "$jobs" ]; then b_is_uint "$jobs" && [ "$jobs" -ge 1 ] && [ "$jobs" -le 64 ] || b_die "-j must be a number from 1 to 64"; BUILDER_JOBS=$jobs; export BUILDER_JOBS; fi
	if b_remote; then
		local -a a=()
		[ -z "$jobs" ] || a+=(-j "$jobs")
		[ "$keep" = 0 ] || a+=(-k)
		[ "$control" = 1 ] || a+=(-C)
		[ "$tests" = 1 ] || a+=(-T)
		[ "$stop" = 0 ] || a+=(-S)
		b_init_env
		B_FETCH=logs
		b_remote_run build-ipxe.sh ${a[@]+"${a[@]}"}
		exit $?
	fi
	b_init_env
	b_ensure_guest
	mkdir -p "$B_LOGS" "$B_OUT/ipxe"

	# the pinned revision must be what the box has (a clone made by b_remote_run, or a real checkout)
	rev=$(sed -n '1{s/[[:space:]].*//;p;}' "$B_REPO/ipxe/PINNED")
	have=$(git -C "$B_REPO/third_party/ipxe" rev-parse HEAD 2>/dev/null || echo none)
	[ "$have" = "$rev" ] || b_die "$B_REPO/third_party/ipxe is at $have, the driver is pinned to $rev (run this from a machine that has the submodule with BUILDER_HOST, or git submodule update --init third_party/ipxe)"

	# one job at a time in the guest: the same lock as ci26_vm.sh run / destroy (fd 9 is not inherited by the guest's qemu: it was started above)
	exec 9>"$CI26_DIR/run.lock"
	if ! flock -n 9; then b_note "another job holds the guest, waiting"; flock 9; fi

	b_note "copying the repository into the guest"
	b_sync_repo_to_guest work/ipxe/src
	ts=$(date +%Y%m%d-%H%M%S)
	log=$B_LOGS/ipxe-$ts.log
	set +e
	# the script goes into the guest as a file and runs with stdin on /dev/null (see b_guest_exec)
	guest_script | b_guest_exec ipxe "$BUILDER_JOBS" "$keep" "$control" "$tests" 2>&1 | tee "$log"
	rc=${PIPESTATUS[1]}
	set -e
	# the guest script ends with 0 (every check passed), 1 (a check failed) or 2 (no tree); anything else is the machinery (ssh 255, a
	# signal, a timeout kill) and is not a verdict on the build
	case $rc in 0 | 1) ;; *) b_note "no verdict from the guest (status $rc): the build was not judged"; rc=2 ;; esac
	# the results (binaries, logs, results.txt) to the box
	rm -rf "${B_OUT:?}/ipxe"
	mkdir -p "$B_OUT/ipxe"
	if $B_NICE rsync -a -e "$(b_guest_ssh)" "ci@127.0.0.1:work/ipxe/results/" "$B_OUT/ipxe/"; then
		cp "$log" "$B_OUT/ipxe/run.log"
		b_note "results in $B_OUT/ipxe"
	else
		b_note "could not copy the results out of the guest"
		[ "$rc" != 0 ] || rc=2
	fi
	echo "BUILDER_LOG=$log"
	[ "$stop" != 1 ] || { flock -u 9; ci26 stop; }
	return "$rc"
}

# run main only when this file is executed (the self-test sources it to run the guest script against a stand-in build.sh)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then bi_main "$@"; exit $?; fi
