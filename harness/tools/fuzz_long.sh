#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Long libFuzzer run of the committed fuzz targets (clang). Builds the targets with ASan + UBSan and coverage
# instrumentation of the core as well as the target, copies each target's committed seeds into a work corpus (the
# checkout is not modified), runs the targets in parallel groups, and prints one line of statistics per target.
#
#   sh harness/tools/fuzz_long.sh [-s SECONDS] [-j JOBS] [-w WORKERS] [-o WORKDIR] [-t "target target" | -p PRESET] [-m]
#
#   -s SECONDS   run time per target (default 600)
#   -j JOBS      targets running at the same time (default 4)
#   -w WORKERS   libFuzzer worker processes per target (default 1: one process, no fork mode; above 1 the target runs with
#                -fork=WORKERS, one parent that hands the corpus to WORKERS children and merges what they find). The cores in use at
#                any moment are JOBS x WORKERS: keep that number at or below the idle cores of the machine (the 100-core box of
#                design 40.4 is shared: 24 at most, so e.g. "-j 3 -w 8"), and -rss_limit_mb=2048 applies to each worker
#   -o WORKDIR   where the build, the corpora, the logs and the crash files go (default build/fuzz-long)
#   -t LIST      only these targets, e.g. "fuzz_m2_rx fuzz_cx_reply" (default: every harness/fuzz/fuzz_*.c)
#   -p PRESET    a named group instead of -t: "partb" = the five targets of Phase 1 part B (OSD map, CRUSH, placement):
#                fuzz_crush_dec fuzz_crush_map fuzz_osdmap_full fuzz_osdmap_inc fuzz_mapstore
#                "partc" = the seven targets of Phase 1 part C (OSD messages, RBD calls and open, OSD sessions, the request engine and
#                the whole client with an image): fuzz_osd_reply fuzz_osd_backoff fuzz_rbd_cls fuzz_osd_sess fuzz_osd_req
#                fuzz_rbd_open fuzz_client_osd
#                "partd" = the five new targets of Phase 1 part D (secure mode): fuzz_gcm fuzz_m2_sec_tx fuzz_m2_sec_rx
#                fuzz_m2_conn_sec fuzz_client_secure (fuzz_cx_reply, which gained secret-carrying seeds, is an older target and is
#                in the full run, not in this preset)
#   -m           afterwards minimise each corpus against the committed seeds and print the new inputs worth committing
#                (copy them into harness/fuzz/seeds/<target>/ by hand after reading them: they are fuzzer output)
#
# A crash leaves crash-* / oom-* / timeout-* in WORKDIR/artifacts and the script exits 1. Fix it, minimise the file
# (`target -minimize_crash=1 file`), add it to harness/fuzz/seeds/<target>/ as a regression input and run again.
# Never put key material in a corpus: the committed seeds are scrubbed vectors and public captures only.
set -eu

secs=600
jobs=4
workers=1
work=build/fuzz-long
only=""
merge=0
chosen=0
partb="fuzz_crush_dec fuzz_crush_map fuzz_osdmap_full fuzz_osdmap_inc fuzz_mapstore"
partc="fuzz_osd_reply fuzz_osd_backoff fuzz_rbd_cls fuzz_osd_sess fuzz_osd_req fuzz_rbd_open fuzz_client_osd"
partd="fuzz_gcm fuzz_m2_sec_tx fuzz_m2_sec_rx fuzz_m2_conn_sec fuzz_client_secure"
while getopts "s:j:w:o:t:p:m" o; do
	case $o in
	s) secs=$OPTARG ;;
	j) jobs=$OPTARG ;;
	w) workers=$OPTARG ;;
	o) work=$OPTARG ;;
	t) only=$OPTARG; chosen=$((chosen + 1)) ;;
	p) chosen=$((chosen + 1)); case $OPTARG in
	   partb) only=$partb ;;
	   partc) only=$partc ;;
	   partd) only=$partd ;;
	   *) echo "fuzz_long: unknown preset '$OPTARG' (partb, partc, partd)" >&2; exit 2 ;;
	   esac ;;
	m) merge=1 ;;
	*) echo "usage: fuzz_long.sh [-s SECONDS] [-j JOBS] [-w WORKERS] [-o WORKDIR] [-t TARGETS | -p PRESET] [-m]" >&2; exit 2 ;;
	esac
done

# a typo in a number must not become a run of zero seconds that "finds nothing" (libFuzzer takes -max_total_time=0 as "no limit",
# and a shell arithmetic error would only show up after the build)
case $secs in '' | *[!0-9]* | 0) echo "fuzz_long: -s takes a number of seconds above 0" >&2; exit 2 ;; esac
case $jobs in '' | *[!0-9]* | 0) echo "fuzz_long: -j takes a number above 0" >&2; exit 2 ;; esac
case $workers in '' | *[!0-9]* | 0) echo "fuzz_long: -w takes a number above 0" >&2; exit 2 ;; esac
# one process per target is a plain run; -fork=1 would still start a child, so it is not used
if [ "$workers" -gt 256 ]; then echo "fuzz_long: -w above 256 workers is not a plan, it is a typo" >&2; exit 2; fi
fork_opt=""
if [ "$workers" -gt 1 ]; then fork_opt="-fork=$workers"; fi

# -t and -p both choose the target list: giving both is a mistake, not "the last one wins"
if [ "$chosen" -gt 1 ]; then
	echo "fuzz_long: use either -t or -p, not both" >&2
	exit 2
fi

here=$(cd "$(dirname "$0")/.." && pwd) # harness/
mkdir -p "$work"
work=$(cd "$work" && pwd)

command -v clang >/dev/null 2>&1 || { echo "fuzz_long: clang is needed (libFuzzer)" >&2; exit 2; }
CC=clang cmake -S "$here" -B "$work/build" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo \
	-DCMAKE_C_FLAGS="-fsanitize=fuzzer-no-link -fno-omit-frame-pointer" -DWR_FUZZ=ON \
	-DWR_SANITIZE=address,undefined -DWR_WITH_OPENSSL=OFF -DWR_BUILD_HOST=OFF > "$work/configure.log" 2>&1 ||
	{ echo "fuzz_long: cmake failed, see $work/configure.log" >&2; exit 2; }
cmake --build "$work/build" > "$work/build.log" 2>&1 || { echo "fuzz_long: the build failed, see $work/build.log" >&2; exit 2; }

if [ -z "$only" ]; then
	only=$(cd "$work/build" && ls fuzz_* 2>/dev/null | grep -v '\.' | tr '\n' ' ')
fi
if [ -z "$only" ]; then
	echo "fuzz_long: no fuzz target was built (see $work/configure.log and $work/build.log)" >&2
	exit 2
fi
mkdir -p "$work/artifacts" "$work/log"

# A named target that was not built is an error (a typo or a renamed file must not shrink the run unnoticed), and a target
# without committed seeds would start from nothing, which the core.docs test forbids for the repository anyway.
for t in $only; do
	case $t in # a target is a file name in the build directory, nothing else
	*/* | .*) echo "fuzz_long: bad target name '$t'" >&2; exit 2 ;;
	esac
	if [ ! -x "$work/build/$t" ]; then
		echo "fuzz_long: no such target '$t' (built: $(cd "$work/build" && ls fuzz_* 2>/dev/null | grep -v '\.' | tr '\n' ' '))" >&2
		exit 2
	fi
	[ -d "$here/fuzz/seeds/$t" ] || echo "fuzz_long: warning: $t has no committed seeds" >&2
done

run_one() {
	t=$1
	c="$work/corpus/$t"
	mkdir -p "$c"
	cp "$here/fuzz/seeds/$t"/* "$c"/ 2>/dev/null || true
	# the children of a fork-mode run write their own fuzz-<n>.log files into the working directory: that is a directory of the
	# target's own under the log directory, not the checkout
	mkdir -p "$work/log/$t.d"
	(cd "$work/log/$t.d" && "$work/build/$t" $fork_opt -max_total_time="$secs" -max_len=65536 -rss_limit_mb=2048 -timeout=60 \
		-print_final_stats=1 -artifact_prefix="$work/artifacts/$t-" "$c" > "$work/log/$t.log" 2>&1) ||
		echo "CRASH $t" >> "$work/crashes"
}

rm -f "$work/crashes"
running=0
for t in $only; do
	run_one "$t" &
	running=$((running + 1))
	if [ "$running" -ge "$jobs" ]; then
		wait
		running=0
	fi
done
wait

for t in $only; do
	printf '%s: ' "$t"
	grep -E '^Done|stat::number_of_executed_units' "$work/log/$t.log" | tr '\n' ' ' | sed 's/  */ /g'
	grep -E '^#[0-9]+[[:space:]]+DONE' "$work/log/$t.log" | sed 's/.*DONE[[:space:]]*//' | cut -c1-80 || true
	# a fork-mode parent prints no final statistics: its last progress line (executions, coverage, corpus, time) is the summary
	if [ "$workers" -gt 1 ]; then grep -E '^#[0-9]+: cov:.*job:' "$work/log/$t.log" | tail -n 1 | cut -c1-140 || true; fi
done

if [ "$merge" = 1 ]; then
	for t in $only; do
		m="$work/merged/$t"
		rm -rf "$m"
		mkdir -p "$m"
		cp "$here/fuzz/seeds/$t"/* "$m"/ 2>/dev/null || true
		"$work/build/$t" -merge=1 -max_len=65536 -rss_limit_mb=2048 -timeout=60 "$m" "$work/corpus/$t" \
			> "$work/log/$t.merge.log" 2>&1 || true
		new=0
		for f in "$m"/*; do
			[ -e "$here/fuzz/seeds/$t/$(basename "$f")" ] || new=$((new + 1))
		done
		echo "$t: $new new inputs in $m (not in the committed seeds)"
	done
fi

if [ -s "$work/crashes" ]; then
	cat "$work/crashes" >&2
	echo "fuzz_long: crashes, see $work/artifacts" >&2
	exit 1
fi
echo "fuzz_long: no crash in $secs s per target ($workers worker(s) each)"
