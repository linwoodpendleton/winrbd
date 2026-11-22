#!/bin/sh
# SPDX-License-Identifier: MIT
#
# ct_trace_check.sh - constant time by trace equivalence (design 41.4; a third check next to Valgrind's undefined-value tracking and the
# read-only-data scan of design 35.6).
#
# The idea. Code that is constant time in the sense of core/src/crypto/wri_aesct.h executes the same instructions and touches the same
# addresses whatever the key, the IV and the data are. So: build the crypto of the core into a small program (ct_trace_drv.c) that takes
# all its secrets from a file, run it under Valgrind's `lackey --trace-mem=yes` with several files (random ones, all zero bits, all one
# bits), cut each trace at the start of main (the dynamic loader and the C library's start-up read the environment and the random bytes
# of the kernel: not ours) and require that the traces are IDENTICAL, line for line. A secret-dependent branch changes which instructions
# are listed; a secret-dependent table index or shift changes an address. The method has its own control: the same driver with the table
# AES of the cephx code (wri_aes.c, which is NOT constant time) must give traces that all differ, or the check proves nothing and fails.
#
# What it shows and what it does not. It covers the paths the driver runs (both key sizes, 1 to 9 blocks, counter mode at 5 lengths and a
# wrapping counter, GHASH, GCM in odd pieces with additional data, seal and open, the dispatcher), for the compilers and optimisation levels
# it is run with: it is evidence about the object code, like Valgrind's check, and independent of it (no undefined-value tracking, so it also
# sees what the tracking cannot, a secret that reaches an address through a clean intermediate). Timing itself is not measured.
#
# Usage: ct_trace_check.sh [--cc "gcc clang"] [--opt "O0 O1 O2 O3 Os"] [--secrets N] [--keep DIR] [TREE]
#   TREE defaults to the repository this script is in. Needs valgrind, a C compiler that can link statically (so that the loader's
#   own behaviour stays out of the trace) and nm. Exit: 0 every row identical and every control different, 1 not, 77 no valgrind or
#   no static C library here (the reason on stderr; WRT_CT_REQUIRE=1 turns that into a failure, as for check_ct_rodata.sh), 2 usage.
set -u

ccs="gcc clang"
opts="O0 O1 O2 O3 Os"
nsec=8
keep=""
tree=""
while [ $# -gt 0 ]; do
	case "$1" in
	--cc) ccs="$2"; shift 2 ;;
	--opt) opts="$2"; shift 2 ;;
	--secrets) nsec="$2"; shift 2 ;;
	--keep) keep="$2"; shift 2 ;;
	-h | --help) sed -n '3,25p' "$0"; exit 0 ;;
	-*) echo "ct_trace_check: unknown option $1" >&2; exit 2 ;;
	*) tree="$1"; shift ;;
	esac
done
case "$nsec" in '' | *[!0-9]*) echo "ct_trace_check: --secrets wants a number" >&2; exit 2 ;; esac
[ "$nsec" -ge 3 ] || { echo "ct_trace_check: --secrets must be at least 3 (random, all zero, all one)" >&2; exit 2; }

skip_exit() {
	if [ -n "${WRT_CT_REQUIRE:-}" ] && [ "${WRT_CT_REQUIRE}" != "0" ]; then
		echo "FAIL: $1 (WRT_CT_REQUIRE is set, a skip is not allowed)" >&2
		exit 1
	fi
	echo "SKIP: $1" >&2
	exit 77
}
command -v valgrind >/dev/null 2>&1 || skip_exit "valgrind not found"
command -v nm >/dev/null 2>&1 || skip_exit "nm not found"

here=$(cd "$(dirname "$0")" && pwd)
[ -n "$tree" ] || tree=$(cd "$here/../.." && pwd)
[ -f "$tree/core/src/crypto/wri_aesct.c" ] || { echo "ct_trace_check: $tree is not a winrbd tree" >&2; exit 2; }

work=$(mktemp -d "${TMPDIR:-/tmp}/wr_ct_trace.XXXXXX") || { echo "ct_trace_check: mktemp failed" >&2; exit 2; }
trap 'if [ -n "$keep" ]; then mkdir -p "$keep" && cp -R "$work"/. "$keep"/ 2>/dev/null; fi; rm -rf "$work"' EXIT INT TERM

inc="-I$tree/core/include -I$tree/core/include/winrbd -I$tree/core/src/util -I$tree/core/src/crypto -I$tree/core/src/auth"
src="$tree/core/src/crypto/wri_aesct.c $tree/core/src/crypto/wri_ghash.c $tree/core/src/crypto/wri_gcm.c $tree/core/src/crypto/wri_pgcm.c $tree/core/src/crypto/wri_aes.c $tree/core/src/util/wri_misc.c"

# the secrets: random files, then one of zero bits and one of one bits; every file is exactly 512 bytes
i=1
while [ "$i" -le "$nsec" ]; do
	case "$i" in
	"$((nsec - 1))") head -c 512 /dev/zero >"$work/in$i.bin" ;;
	"$nsec") head -c 512 /dev/zero | tr '\0' '\377' >"$work/in$i.bin" ;;
	*) head -c 512 /dev/urandom >"$work/in$i.bin" ;;
	esac
	i=$((i + 1))
done

# one trace, cut at the entry of main; the lines of Valgrind's own report (they carry the process id) are dropped
trace_hash() { # exe file [control]
	valgrind -q --tool=lackey --trace-mem=yes "$1" "$2" ${3:+"$3"} 2>"$work/tr" >/dev/null
	grep -v '^==' "$work/tr" | sed -n "/^I  0*$mainaddr,/,\$p" | sha256sum | cut -c1-16
}

status=0
rows=0
for cc in $ccs; do
	command -v "$cc" >/dev/null 2>&1 || { echo "ct_trace_check: $cc not found, skipped" >&2; continue; }
	for opt in $opts; do
		exe="$work/drv-$cc-$opt"
		# shellcheck disable=SC2086
		if ! "$cc" -std=gnu99 "-$opt" -g0 -static $inc "$here/ct_trace_drv.c" $src -o "$exe" 2>"$work/cc.err"; then
			if grep -q -i "cannot find -lc\|crt1.o\|static" "$work/cc.err"; then skip_exit "no static C library for $cc here"; fi
			echo "FAIL: $cc -$opt did not build:" >&2; head -5 "$work/cc.err" >&2; status=1; continue
		fi
		mainaddr=$(nm "$exe" | awk '$3 == "main" { print $1 }' | sed 's/^0*//')
		[ -n "$mainaddr" ] || { echo "FAIL: no main in $exe" >&2; status=1; continue; }
		hs=""
		i=1
		while [ "$i" -le "$nsec" ]; do
			h=$(trace_hash "$exe" "$work/in$i.bin")
			valgrind -q --tool=none "$exe" "$work/in$i.bin" >/dev/null 2>&1
			rc=$?
			[ "$rc" -eq 0 ] || { echo "FAIL: $cc -$opt: the driver exited $rc on secret $i" >&2; status=1; }
			hs="$hs $h"
			i=$((i + 1))
		done
		distinct=$(echo $hs | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')
		hc=""
		i=1
		while [ "$i" -le 6 ] && [ "$i" -le "$nsec" ]; do
			hc="$hc $(trace_hash "$exe" "$work/in$i.bin" control)"
			i=$((i + 1))
		done
		cdistinct=$(echo $hc | tr ' ' '\n' | sort -u | wc -l | tr -d ' ')
		cn=$(echo $hc | wc -w | tr -d ' ')
		verdict=ok
		[ "$distinct" -eq 1 ] || verdict=DIFFERENT
		[ "$cdistinct" -eq "$cn" ] || verdict="$verdict,control-not-seen"
		printf '%s -%s: %s secrets, %s distinct trace(s) of the constant-time path; control (table AES) %s distinct of %s: %s\n' \
			"$cc" "$opt" "$nsec" "$distinct" "$cdistinct" "$cn" "$verdict"
		[ "$verdict" = ok ] || status=1
		rows=$((rows + 1))
	done
done
[ "$rows" -gt 0 ] || skip_exit "no compiler could be used"
[ "$status" -eq 0 ] && echo "ct_trace_check: $rows rows, all identical, all controls different"
exit "$status"
