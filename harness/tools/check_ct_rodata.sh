#!/bin/sh
# SPDX-License-Identifier: MIT
#
# check_ct_rodata.sh - the object-code scan of design 35.6 (module ct-check).
#
# A constant-time AES or GHASH has no lookup table. A table (an S-box of 256 bytes, the round tables of 1 to 4 KiB, a multiplication
# table of 4 KiB) has to live in a read-only data section of the object file, so an object whose read-only data is small cannot contain
# one: the bitsliced code keeps only a few 16-byte mask constants (0 to 144 bytes in all, measured with gcc 13 and clang 18, -O0 to -O3
# and -Os). This script fails when any named object has a read-only data section of the limit (default 256 bytes) or more, or when all of
# its read-only data together is twice the limit or more (a table split over several sections). Initialised writable data
# (.data*, a table that is not const) counts the same way: a table is a table whether or not the compiler could put it in ROM.
#
# The limit is the SMALLEST size that fails: a section of limit bytes or more is flagged (default 256, the size of one AES S-box: a lone
# S-box passes a "larger than 256" test). The self test (--selftest CC) proves it by compiling real tables.
#
# Usage:
#   check_ct_rodata.sh [--limit N] [--control NAME] <libwr_core.a | directory of objects> NAME...
#   check_ct_rodata.sh [--limit N] --selftest CC      compile a 256-byte const table, a 4 KiB one, a writable 256-byte one and a small
#                                                     one with CC and check that the scan flags the first three and passes the last
#     NAME is the base name of a core source (wri_aesct, wri_ghash, wri_gcm): the member wri_aesct.c.o / wri_aesct.o of the archive, or
#     the object of that name found under the directory. Every NAME must be found (a rename must not turn the check into a no-op).
#     --control NAME: the table-driven object (wri_aes) that the scan MUST flag; it is scanned the same way and the run fails when it
#     is not flagged, so a scan that cannot see a table cannot pass.
#
# Data sections counted: ELF .rodata, .rodata.* (all mergeable constant and string sections too), .lrodata*, .data, .data.* (.data.rel.ro*
# among them), .ldata*, COFF .rdata*, .data, Mach-O __const, __literal*, __cstring, __data. Exit codes: 0 pass, 1 fail, 2 usage or missing object, 77 skipped (no ar / readelf / objdump /
# size on this machine), the reason on stderr.

limit=256
control=""
selftest=""
while [ $# -gt 0 ]; do
	case "$1" in
	--limit) limit="$2"; shift 2 ;;
	--control) control="$2"; shift 2 ;;
	--selftest) selftest="$2"; shift 2 ;;
	--) shift; break ;;
	-*) echo "check_ct_rodata: unknown option $1" >&2; exit 2 ;;
	*) break ;;
	esac
done
# A skip (77) that CI can turn into a failure: with WRT_CT_REQUIRE set in the environment a missing tool is an error (exit 1), so the
# scan cannot vanish unnoticed from a runner image. $1 = the reason.
skip_exit() {
	if [ -n "${WRT_CT_REQUIRE:-}" ] && [ "${WRT_CT_REQUIRE}" != "0" ]; then
		echo "FAIL: $1 (WRT_CT_REQUIRE is set, a skip is not allowed)" >&2
		exit 1
	fi
	echo "SKIP: $1" >&2
	exit 77
}

if [ -n "$selftest" ]; then
	case "$limit" in '' | *[!0-9]*) echo "check_ct_rodata: --limit wants a number" >&2; exit 2 ;; esac
	st_dir=$(mktemp -d "${TMPDIR:-/tmp}/wr_ct_selftest.XXXXXX") || { echo "check_ct_rodata: mktemp failed" >&2; exit 2; }
	trap 'rm -rf "$st_dir"' EXIT INT TERM
	# name, size, qualifier ("const" = read-only, "" = writable initialised data), expected verdict (flag / pass)
	status=0
	for spec in "selft256 256 const flag" "selft4k 4096 const flag" "seltdata 256 '' flag" "seltsmall 64 const pass"; do
		eval "set -- $spec"
		name=$1 size=$2 qual=$3 want=$4
		awk -v n="$size" -v q="$qual" -v name="$name" 'BEGIN {
			printf "static %sunsigned char t[%d] = {", (q == "" ? "" : q " "), n
			for (i = 0; i < n; i++) printf "%s%d", (i ? "," : ""), ((i * 167 + 13) * (i + 1)) % 251
			printf "};\nunsigned char %s_look(unsigned x) { return t[x %% %d]; }\n", name, n
			if (q == "") printf "void %s_poke(void) { t[0]++; }\n", name
		}' >"$st_dir/$name.c"
		if ! "$selftest" -O2 -c "$st_dir/$name.c" -o "$st_dir/$name.o" 2>"$st_dir/cc.err"; then
			skip_exit "$selftest cannot compile the self test sources: $(head -n 1 "$st_dir/cc.err")"
		fi
		sh "$0" --limit "$limit" "$st_dir" "$name" >"$st_dir/out.txt" 2>&1
		rc=$?
		if [ "$want" = flag ] && [ "$rc" -eq 1 ]; then
			echo "ok   selftest $name flagged ($(head -n 1 "$st_dir/out.txt" | tr -s ' '))"
		elif [ "$want" = pass ] && [ "$rc" -eq 0 ]; then
			echo "ok   selftest $name passed ($(head -n 1 "$st_dir/out.txt" | tr -s ' '))"
		elif [ "$rc" -eq 77 ]; then
			cat "$st_dir/out.txt" >&2
			exit 77
		else
			echo "FAIL selftest $name: expected the scan to ${want}, exit code $rc: $(cat "$st_dir/out.txt")" >&2
			status=1
		fi
	done
	exit $status
fi
if [ $# -lt 2 ]; then
	echo "usage: check_ct_rodata.sh [--limit N] [--control NAME] <archive|directory> NAME..." >&2
	echo "       check_ct_rodata.sh [--limit N] --selftest CC" >&2
	exit 2
fi
src="$1"
shift
case "$src" in /*) ;; *) src="$(pwd)/$src" ;; esac # the archive is opened from another directory
case "$limit" in
'' | *[!0-9]*) echo "check_ct_rodata: --limit wants a number" >&2; exit 2 ;;
esac
total_limit=$((limit * 2))

have() { command -v "$1" >/dev/null 2>&1; }

# ---- which tool reads the sections -----------------------------------------------------------------------------

tool=""
probe_obj=""
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_ct_rodata.XXXXXX") || { echo "check_ct_rodata: mktemp failed" >&2; exit 2; }
cleanup() { [ -n "$tmp" ] && [ -d "$tmp" ] && rm -rf "$tmp"; }
trap cleanup EXIT INT TERM

# ---- find the objects -------------------------------------------------------------------------------------------

# $1 = NAME -> prints the path of its object (extracting from the archive), or nothing
find_obj() {
	name="$1"
	if [ -d "$src" ]; then
		find "$src" -type f \( -name "$name.c.o" -o -name "$name.o" -o -name "$name.c.obj" -o -name "$name.obj" \) | head -n 1
		return
	fi
	if ! have ar; then
		return
	fi
	if [ ! -d "$tmp/ar" ]; then
		mkdir -p "$tmp/ar"
		(cd "$tmp/ar" && ar x "$src") 2>/dev/null || true
	fi
	for cand in "$name.c.o" "$name.o" "$name.c.obj" "$name.obj"; do
		if [ -f "$tmp/ar/$cand" ]; then
			echo "$tmp/ar/$cand"
			return
		fi
	done
}

if [ ! -e "$src" ]; then
	echo "check_ct_rodata: $src does not exist (build the core first)" >&2
	exit 2
fi
if [ ! -d "$src" ] && ! have ar; then
	skip_exit "no 'ar' on this machine, the archive cannot be opened"
fi

first=$(find_obj "$1")
if [ -z "$first" ]; then
	echo "check_ct_rodata: no object named $1 in $src" >&2
	exit 2
fi
probe_obj="$first"

if have readelf && readelf -S -W "$probe_obj" >/dev/null 2>&1; then
	tool=readelf
elif have objdump && objdump -h "$probe_obj" >/dev/null 2>&1; then
	tool=objdump
elif have size && size -m "$probe_obj" >/dev/null 2>&1; then
	tool=size
else
	skip_exit "none of readelf, objdump (binutils) or size -m (Mach-O) can read $probe_obj"
fi

# ---- the read-only sections of one object: "name size" lines (decimal) ------------------------------------------------

is_ro_name() {
	case "$1" in
	.rodata | .rodata.* | .lrodata | .lrodata.* | .data | .data.* | .ldata | .ldata.* | .rdata | .rdata\$* | .data\$* | __const | __literal* | __cstring | __data) return 0 ;;
	esac
	return 1
}

list_sections() {
	obj="$1"
	case "$tool" in
	readelf)
		readelf -S -W "$obj" | sed -e 's/^ *\[ *[0-9]*\] *//' | awk '$2 ~ /^[A-Z_]+$/ && NF >= 5 { print $1, $5 }' |
			while read -r n hex; do
				case "$hex" in *[!0-9a-fA-F]* | '') continue ;; esac
				echo "$n $((0x$hex))"
			done
		;;
	objdump)
		objdump -h "$obj" | awk '$1 ~ /^[0-9]+$/ && NF >= 3 { print $2, $3 }' |
			while read -r n hex; do
				case "$hex" in *[!0-9a-fA-F]* | '') continue ;; esac
				echo "$n $((0x$hex))"
			done
		;;
	size)
		# "Section (__TEXT, __const): 48" -> "__const 48"
		size -m "$obj" | sed -n -e 's/^[[:space:]]*Section (\([A-Za-z_]*\), \([A-Za-z_0-9.]*\)): \([0-9][0-9]*\).*$/\2 \3/p'
		;;
	esac
}

# scan one object. Prints one line; sets scan_flagged to 1 when a section or the sum is over the limit.
scan_flagged=0
scan() {
	name="$1"
	obj=$(find_obj "$name")
	if [ -z "$obj" ]; then
		echo "check_ct_rodata: no object named $name in $src" >&2
		exit 2
	fi
	scan_flagged=0
	sum=0
	desc=""
	over=""
	secs=$(list_sections "$obj")
	while read -r n sz; do
		[ -n "$n" ] || continue
		if is_ro_name "$n"; then
			sum=$((sum + sz))
			desc="$desc $n=$sz"
			if [ "$sz" -ge "$limit" ]; then
				over="$over $n($sz>=$limit)"
				scan_flagged=1
			fi
		fi
	done <<EOF
$secs
EOF
	if [ "$sum" -ge "$total_limit" ]; then
		over="$over total($sum>=$total_limit)"
		scan_flagged=1
	fi
	[ -n "$desc" ] || desc=" (no read-only data)"
	scan_line="$name:$desc total=$sum"
	scan_over="$over"
}

# ---- run ----------------------------------------------------------------------------------------------------------

status=0
for name in "$@"; do
	scan "$name"
	if [ "$scan_flagged" -eq 1 ]; then
		echo "FAIL $scan_line  -> too much constant data:$scan_over (a lookup table?)" >&2
		status=1
	else
		echo "ok   $scan_line (a section of $limit bytes or more fails)"
	fi
done

if [ -n "$control" ]; then
	scan "$control"
	if [ "$scan_flagged" -eq 1 ]; then
		echo "ok   control $scan_line  -> flagged as it must be:$scan_over"
	else
		echo "FAIL control $control: the table-driven object was NOT flagged ($scan_line): the scan cannot see a lookup table" >&2
		status=1
	fi
fi
exit $status
