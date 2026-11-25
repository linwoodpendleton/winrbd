#!/bin/sh
# SPDX-License-Identifier: MIT
#
# The call-depth and stack budgets of the core as iPXE builds it: check_callgraph.py run with the flags of the hosts that matter for the glue
# (-Os, and -m32 for the BIOS images), and the budgets of the entry points the glue calls.
#
# Why a second measurement next to the one in the `static-limits` job. That job measures with -O2 on x86_64, which is neither of the builds the
# driver ends up in. iPXE compiles with -Os (less inlining: the deepest chain is 19 frames, against 17 with -O2) and its BIOS images are i386
# (pointers and size_t are 32 bits; the frames are smaller; -mregparm=3, which iPXE adds, would make them smaller still, so this is the
# conservative number). The stack of the iPXE process is small and fixed (design: docs/design/core-architecture.md, the iPXE profile), and
# what counts is what each call from the glue costs on top of the caller's own frames.
#
# Measured (bytes of static stack along the worst chain, gcc 11.4 / 13.4 / 14.3 / 15.2 on the 26.04 guest and the 22.04 box; the worst
# static chain of the whole core is wr_client_run, down through the map store's incremental apply and the CRUSH rule audit):
#   i386 -m32 -Os   2,632 (gcc 11, 15)   2,648 (gcc 13)   2,664 (gcc 14)
#   x86_64 -Os      2,944 (gcc 11)       2,960 (gcc 13)   2,976 (gcc 14)   2,928 (gcc 15)
# A budget is the largest of the four measurements plus 8 %, rounded up to 8 bytes, and never less than 16 bytes above it (the entry points
# of a few bytes would otherwise fail on a compiler's rounding). The calls through the msgr2 upper-layer table (the OSD session's and the
# monitor client's message handler) are linked in, as in the static-limits job, so that the reply path counts for wr_client_run. Calls through
# the host's function pointers (the I/O hooks, the GCM hook) end a chain in this measurement; the host's own frames are the host's to bound.
# An entry that is renamed away is an error, not a pass, and so is one that the core only calls and never defines (it would measure 0).
#
# The table is also checked for completeness against the glue: every core function that a C file of ipxe/src calls must be in it
# (check_callgraph.py --glue; the failure lists the ones that are missing). The first version of the table came from the design
# document's list of entry points and left out 17 small ones that the glue also calls (the getters, the configuration setters,
# wr_key_wipe, the text functions). They are measured with gcc 11.4 and gcc 15.2 only (the other two compilers were not at hand), which
# the 8 % and the 16-byte floor cover for frames this small.
#
# Adding an entry point: measure it (check_callgraph.py --entry NAME with the flags below, once per architecture and compiler), put the larger
# number plus the margin into the table below. Lowering a budget when the code gets shallower is welcome; raising one needs a reason in review.
#
#   callgraph_ipxe.sh [--cc gcc] [--core DIR] [--glue DIR] [--chains] [--keep DIR] i386|x86_64|both
#
# Run by the `ipxe-gates` job of .github/workflows/harness.yml (gcc 13 and gcc 15) and by ctest (`core_callgraph_i386`, `core_callgraph_x86_64`,
# label `checks`). Exit 0 = within the budgets, 1 = not, 2 = tool error (a missing entry point, a compile error), 77 = skipped: python3 or
# gcc 10 or newer is missing, or (i386 only) the compiler cannot build a hosted 32-bit file (no gcc-multilib: the call graph is read from
# an ordinary compile, which includes the system's <stdint.h>). WRT_IPXE_REQUIRE=1 turns that last skip into a failure, as in
# check_ipxe_headers.sh: the CI job that exists for the gates sets it, a plain ctest run on a box without 32-bit headers does not.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
cc=${CC:-gcc}
extra=""
core_arg=""
glue_arg=""
glue_given=0
while [ $# -gt 0 ]; do
	case $1 in
	--cc) cc=$2; shift 2 ;;
	--core) core_arg="--core $2"; shift 2 ;;
	--glue) glue_arg="$glue_arg --glue $2"; glue_given=1; shift 2 ;;
	--chains) extra="$extra --chains"; shift ;;
	--keep) extra="$extra --keep $2"; shift 2 ;;
	-*) echo "callgraph_ipxe.sh: unknown option $1" >&2; exit 2 ;;
	*) break ;;
	esac
done
which=${1:?usage: callgraph_ipxe.sh [--cc gcc] [--core DIR] [--glue DIR] [--chains] [--keep DIR] i386|x86_64|both}
case $which in i386 | x86_64 | both) ;; *) echo "callgraph_ipxe.sh: i386, x86_64 or both" >&2; exit 2 ;; esac

command -v python3 > /dev/null 2>&1 || { echo "callgraph_ipxe.sh: python3 not found (skipped)" >&2; exit 77; }
command -v "$cc" > /dev/null 2>&1 || { echo "callgraph_ipxe.sh: $cc not found (skipped)" >&2; exit 77; }
# the glue whose calls into the core must all have a budget: the repository's own, unless --glue names another (the self-test does)
if [ "$glue_given" = 0 ] && [ -d "$here/../../../ipxe/src" ]; then
	glue_arg="--glue $here/../../../ipxe/src"
fi

# the call graph comes from gcc's -fcallgraph-info (gcc 10 and newer); clang has no such option
if "$cc" --version 2> /dev/null | grep -qi clang; then echo "callgraph_ipxe.sh: $cc is clang; the call graph needs gcc 10 or newer (skipped)" >&2; exit 77; fi

# name  i386-budget  x86_64-budget
table='
wr_client_run          2880 3216
wr_client_get_state      40   32
wr_client_last_error     40   32
wr_client_get_stats     128   88
wr_client_osd_stats     112   48
wr_client_create       1112 1360
wr_client_destroy       368  232
wr_client_next_action   544  352
wr_client_next_event     56   32
wr_client_next_done     136   56
wr_client_pool_track    320  200
wr_client_osd_addr       72   56
wr_client_mem_required  608  688
wr_config_profile_ipxe   48   32
wr_config_enable_maps    40   24
wr_config_enable_osd     80   72
wr_config_enable_secure  32   24
wr_conn_connected       632  400
wr_conn_closed          456  280
wr_conn_rx_window       264  128
wr_conn_rx_commit       248  128
wr_conn_rx_push         320  192
wr_conn_tx_peek         160   56
wr_conn_tx_consume      848  648
wr_image_open           208  248
wr_image_submit         376  256
wr_image_cancel         832  616
wr_image_close          816  648
wr_image_get_info        88   48
wr_image_get_state       72   48
wr_image_error           72   48
wr_handoff_encode       296  272
wr_handoff_encode_table 296  256
wr_handoff_fix_checksum  32   24
wr_handoff_decode       600  584
wr_handoff_decode_table 672  616
wr_rburl_parse          552  568
wr_rburl_spec_wipe      104   48
wr_rburl_strerror        64   32
wr_rburl_status_name     64   32
wr_ra_cfg_from_kib       48   24
wr_ra_mem_required       80   48
wr_ra_init              104   56
wr_ra_read              144   72
wr_ra_prefetch_next      96   64
wr_ra_line_done          72   56
wr_ra_line_failed        72   56
wr_ra_line_unissued      72   56
wr_ra_write              88   40
wr_ra_reset              88   40
wr_ra_span               88   40
wr_ra_get_stats          56   32
wr_key_wipe              56   32
wr_key_from_raw         200  176
wr_key_parse_base64     376  352
wr_key_parse_keyring    448  384
wr_mon_parse_hosts      448  464
wr_strerror              32   24
wr_status_name           32   24
'

# a skip of one architecture is returned (77, or 1 with WRT_IPXE_REQUIRE=1), not exited, so that "both" still measures the other one
skip() {
	echo "callgraph_ipxe.sh: $* (skipped)" >&2
	if [ "${WRT_IPXE_REQUIRE:-0}" = 1 ]; then
		echo "callgraph_ipxe.sh: WRT_IPXE_REQUIRE=1: a skip is a failure here" >&2
		return 1
	fi
	return 77
}

run_one() {
	arch=$1
	if [ "$arch" = i386 ]; then
		# the 32-bit graph is read from an ordinary (hosted) compile: it needs the system's 32-bit headers (gcc-multilib). Without them
		# the first core file fails with "bits/libc-header-start.h: No such file", which is not a finding about the core.
		probe=$(mktemp "${TMPDIR:-/tmp}/wr_cg_probe.XXXXXX")
		printf '#include <stdint.h>\n#include <stddef.h>\nint main(void){return (int)sizeof(size_t) - 4;}\n' > "$probe"
		if ! "$cc" -m32 -x c -c -o /dev/null "$probe" 2> /dev/null; then
			rm -f "$probe"
			skip "$cc cannot compile a hosted 32-bit file (install gcc-multilib)"
			return $?
		fi
		rm -f "$probe"
		flags="--cflag=-m32 --cflag=-Os"
		col=2
		global=2880
	else
		flags="--cflag=-Os"
		col=3
		global=3216
	fi
	entries=$(printf '%s\n' "$table" | awk -v c="$col" 'NF == 3 { printf " --entry %s=%s", $1, $c }')
	echo "callgraph_ipxe: $arch ($cc $(echo "$flags" | sed 's/--cflag=//g'))"
	# --depth 19: the deepest chain of the core with -Os (the AUTH_SIGNATURE frame going out in secure mode, down to the GHASH multiplication);
	# --stack: the worst static chain of the core, measured as above
	# shellcheck disable=SC2086
	python3 "$here/check_callgraph.py" --cc "$cc" --depth 19 --stack "$global" $flags $core_arg $glue_arg $extra \
		--link wri_m2c_ready_frame=core/src/osd/wri_osd_sess_up.c:up_message \
		--link wri_m2c_ready_frame=core/src/mon/wri_mon.c:up_message \
		$entries
}

# 1 (over a budget) and 2 (tool error) outrank 77 (skipped): a skipped i386 must not hide a failed x86_64
rc=0
case $which in
i386) run_one i386 || rc=$? ;;
x86_64) run_one x86_64 || rc=$? ;;
both)
	r1=0
	r2=0
	run_one i386 || r1=$?
	run_one x86_64 || r2=$?
	# the first failure wins; a skip only if nothing else happened
	rc=0
	for r in "$r1" "$r2"; do
		if [ "$r" -ne 0 ] && [ "$r" -ne 77 ] && { [ "$rc" -eq 0 ] || [ "$rc" -eq 77 ]; }; then rc=$r; fi
		if [ "$r" -eq 77 ] && [ "$rc" -eq 0 ]; then rc=77; fi
	done
	;;
esac
exit "$rc"
