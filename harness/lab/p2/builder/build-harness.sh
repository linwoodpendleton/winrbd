#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-harness.sh - the CI ctest matrix of the harness, in the builder guest (Ubuntu 26.04, gcc 15.2, clang 21.1.8 like the CI runner).
#
#   build-harness.sh [-c "CCS"] [-f "FLAVOURS"] [-s "STAGES"] [-l LABEL] [-S]
#
#   -c   compilers (default "gcc clang")
#   -f   flavours: debug san release minsizerel relsan minsan; "all" = all six
#        (default "debug san release minsizerel": Debug, Debug + ASan/UBSan, Release, MinSizeRel, as the CI matrix)
#   -s   gate stages of ci26_vm.sh (default "matrix gates": the matrix, then the 32-bit / iPXE-flag / header / object gates)
#   -l   name of the tree in the guest (default "harness")
#   -j N ctest parallelism in the guest (default 4, as in CI; a lower number is kinder to the timing checks on a loaded box)
#   -S   power the guest off afterwards
#
# It copies this repository into the guest, then runs `ci26_vm.sh run`: for every compiler and flavour a cmake -G Ninja configure with
# -DWR_WERROR=ON, a build (a "warning:" line anywhere fails the flavour even if the compiler was not told to), `ctest -j 4 --timeout 600
# -LE lab --no-tests=error` and the named checks (core.docs, core_sources_in_sync, core_freestanding*, core_no_libc, core_no_globals)
# which must have PASSED, not skipped. On top of that this script
#   - refuses to call a run good when the guest's compilers are not the CI runner's (gcc 15.2, clang 21.1.8; override with
#     BUILDER_ALLOW_OTHER_TOOLCHAIN=1, the result is then marked as such);
#   - checks that the log has a PASS line for every requested compiler/flavour (an empty or skipped matrix is not green).
# The guest must exist (up.sh). Environment and the two ways to run it (on the box, or from your machine with BUILDER_HOST) are those of
# up.sh. The short log is kept in BUILDER_DIR/logs (copied to BUILDER_LOCAL_LOGS from your machine).
#
# Exit status: 0 every requested flavour passed with the CI toolchain; 1 something failed; 2 nothing was tested (environment problem).

set -eu
set -o pipefail
LC_ALL=C
export LC_ALL

BH_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=up.sh
. "$BH_HERE/up.sh"

# stop the load sampler: its sleep first (a child), then the loop itself
bh_stop_sampler() {
	[ -z "${1:-}" ] || pkill -P "$1" 2>/dev/null || true
	[ -z "${1:-}" ] || kill "$1" 2>/dev/null || true
	[ -z "${1:-}" ] || wait "$1" 2>/dev/null || true
}

# bh_has_pass LOG NAME: the log has a result line "PASS <name> ..." (ci26_vm.sh prints them as "%-6s %-28s detail"); a fixed-string compare,
# not a regular expression
bh_has_pass() {
	awk -v n="$2" '$1 == "PASS" && $2 == n { found = 1 } END { exit found ? 0 : 1 }' "$1"
}

bh_main() {
	local ccs="gcc clang" flav="debug san release minsizerel" stages="matrix gates" label=harness stop=0 o rc=0 log ts gccv clangv cc fl st miss="" line
	local cjobs="" sampler=""
	OPTIND=1
	while getopts "c:f:s:l:j:Sh" o; do
		case $o in
		c) ccs=$OPTARG ;;
		f) flav=$OPTARG ;;
		s) stages=$OPTARG ;;
		l) label=$OPTARG ;;
		j) cjobs=$OPTARG ;;
		S) stop=1 ;;
		*) sed -n '4,26p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; [ "$o" = h ] && exit 0; exit 2 ;;
		esac
	done
	shift $((OPTIND - 1))
	[ $# -eq 0 ] || b_die "no arguments expected, got '$*'"
	if [ -n "$cjobs" ]; then b_is_uint "$cjobs" && [ "$cjobs" -ge 1 ] && [ "$cjobs" -le 16 ] || b_die "-j must be 1..16"; fi
	# these words end up in file names, a shell command line in the guest and a pattern in the check below: simple words only, and each
	# of them must mean something (an empty stage list or an unknown flavour would be a run that tests nothing and reads as green)
	case $label in '' | .* | *[!A-Za-z0-9_.+-]*) b_die "-l: a label is letters, digits and _ . + - and does not start with a dot, got '$label'" ;; esac
	case $ccs$flav$stages in *[!A-Za-z0-9_.+\ -]*) b_die "-c, -f, -s: simple words only (letters, digits and _ . + -)" ;; esac
	[ -n "${ccs// /}" ] || b_die "-c: no compiler given"
	[ -n "${flav// /}" ] || b_die "-f: no flavour given"
	[ -n "${stages// /}" ] || b_die "-s: no stage given (that would be a run that tests nothing)"
	for cc in $ccs; do case $cc in gcc | clang) ;; *) b_die "-c: '$cc' is not a compiler of the CI matrix (gcc, clang)" ;; esac; done
	if [ "$flav" != all ]; then for fl in $flav; do case $fl in debug | san | release | minsizerel | relsan | minsan) ;; *) b_die "-f: unknown flavour '$fl' (debug san release minsizerel relsan minsan, or all)" ;; esac; done; fi
	for st in $stages; do case $st in matrix | gates) ;; *) b_die "-s: unknown stage '$st' (matrix, gates)" ;; esac; done
	if b_remote; then
		local -a a
		a=(-c "$ccs" -f "$flav" -s "$stages" -l "$label")
		[ -z "$cjobs" ] || a+=(-j "$cjobs")
		[ "$stop" = 0 ] || a+=(-S)
		b_init_env
		B_FETCH=logs
		b_remote_run build-harness.sh "${a[@]}"
		exit $?
	fi
	[ -z "$cjobs" ] || export CI26_CTEST_JOBS=$cjobs
	b_init_env
	b_ensure_guest
	mkdir -p "$B_LOGS"
	[ "$flav" != all ] || flav="debug san release minsizerel relsan minsan"

	# the toolchain first: a run with other compilers than the CI runner's proves nothing about CI
	gccv=$(ci26 ssh 'gcc -dumpfullversion' </dev/null)
	clangv=$(ci26 ssh "clang --version | sed -n 's/.*clang version \\([0-9][0-9.]*\\).*/\\1/p;q'" </dev/null)
	b_note "guest toolchain: gcc $gccv, clang $clangv"
	case $gccv in 15.2*) ;; *) [ "${BUILDER_ALLOW_OTHER_TOOLCHAIN:-0}" = 1 ] || b_die "gcc in the guest is $gccv, the CI runner has 15.2 (BUILDER_ALLOW_OTHER_TOOLCHAIN=1 to run anyway)" ;; esac
	case $clangv in 21.1.8*) ;; *) [ "${BUILDER_ALLOW_OTHER_TOOLCHAIN:-0}" = 1 ] || b_die "clang in the guest is $clangv, the CI runner has 21.1.8 (BUILDER_ALLOW_OTHER_TOOLCHAIN=1 to run anyway)" ;; esac

	ts=$(date +%Y%m%d-%H%M%S)
	log=$B_LOGS/harness-$label-$ts.log
	# a load log, so that a timing flake can be judged against what the box and the guest were doing (the box is shared): one line every
	# 30 s, "time box <1/5/15 min load> guest <1/5/15 min load>"
	: >"$log.load"
	(
		while sleep 30; do
			echo "$(date +%T) box $(cut -d' ' -f1-3 /proc/loadavg) guest $(ci26 ssh 'cut -d" " -f1-3 /proc/loadavg' </dev/null 2>/dev/null || echo '?')"
		done
	) >>"$log.load" 2>&1 9>&- &
	sampler=$!
	# the sampler must not outlive this script (a Ctrl-C or a failed step would leave it asking the guest every 30 s for ever)
	# shellcheck disable=SC2064  # the pid is expanded now on purpose: the trap runs after this function has returned
	trap "bh_stop_sampler $sampler" EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	# the repository as it is on the box (the staged copy, or the checkout the script was started from); ci26_vm.sh copies it into the guest
	set +e
	ci26 run -l "$label" -c "$ccs" -f "$flav" -s "$stages" "$B_REPO" 2>&1 | tee "$log"
	rc=${PIPESTATUS[0]}
	set -e
	bh_stop_sampler "$sampler"
	trap - EXIT
	awk '$3 ~ /^[0-9.]+$/ { n++; s += $3; if ($3 > m) m = $3 } END { if (n) printf "builder: box load (1 min) over the run: avg %.1f, max %.1f, %d samples (%s)\n", s / n, m, n, FILENAME }' "$log.load" | tee -a "$log"
	{
		echo "builder: toolchain gcc $gccv clang $clangv (CI runner: gcc 15.2, clang 21.1.8)"
		echo "builder: ci26_vm.sh run exit status $rc"
	} | tee -a "$log"

	# a PASS line for every requested compiler/flavour of the matrix stage, and for every gate of the gates stage (ci26_vm.sh names them
	# <cc>/<name>); a missing line is a skipped or an empty stage, which is not green. wr_core_ipxe_flags is gcc only, as in CI.
	if [ "$rc" = 0 ]; then
		for cc in $ccs; do
			case " $stages " in
			*" matrix "*) for fl in $flav; do bh_has_pass "$log" "$cc/$fl" || miss="$miss $cc/$fl"; done ;;
			esac
			case " $stages " in
			*" gates "*)
				for line in wr_core_m32 wr_header_check gates-Release gates-MinSizeRel; do bh_has_pass "$log" "$cc/$line" || miss="$miss $cc/$line"; done
				[ "$cc" != gcc ] || bh_has_pass "$log" "$cc/wr_core_ipxe_flags" || miss="$miss $cc/wr_core_ipxe_flags"
				;;
			esac
		done
		if [ -n "$miss" ]; then
			echo "builder: no PASS line for:$miss -> not green" | tee -a "$log"
			rc=1
		fi
	fi
	case $gccv$clangv in 15.2*21.1.8*) ;; *) echo "builder: NOTE: not the CI toolchain (BUILDER_ALLOW_OTHER_TOOLCHAIN=1)" | tee -a "$log" ;; esac
	echo "BUILDER_LOG=$log"
	[ "$stop" != 1 ] || ci26 stop
	return "$rc"
}

# run main only when this file is executed (the self-test sources it)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then bh_main "$@"; exit $?; fi
