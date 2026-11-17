#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Regenerate (or check) core/sources.txt: the list of C files of the portable core, one path per
# line relative to core/, sorted. That list is what the iPXE make glue and the msbuild project read;
# the harness CMake build globs core/src/ and core/crush_ln/ directly and a ctest check keeps the two in sync.
# core/crush_ln/ is the LGPL-2.1 directory (the CRUSH log tables, see LICENSE): its one .c file is listed like any
# other, and the glue recognises it by the crush_ln/ prefix.
#
#   core/tools/gen_sources.sh           rewrite core/sources.txt
#   core/tools/gen_sources.sh --check   exit 1 if core/sources.txt is stale
#
# Rule: C file basenames are unique across core/ (iPXE derives object names from basenames).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
core=$(cd "$here/.." && pwd)
tmp=$(mktemp "${TMPDIR:-/tmp}/wr_sources.XXXXXX")
trap 'rm -f "$tmp" "$tmp.names"' EXIT

(cd "$core" && LC_ALL=C find src crush_ln -name '*.c' | LC_ALL=C sort) > "$tmp"

# basenames must be unique
sed 's|.*/||' "$tmp" | LC_ALL=C sort > "$tmp.names"
dup=$(uniq -d "$tmp.names")
if [ -n "$dup" ]; then
	echo "gen_sources: duplicate C file basenames in core/ (iPXE needs unique object names):" >&2
	echo "$dup" >&2
	exit 1
fi

if [ "${1:-}" = "--check" ]; then
	if [ -f "$core/sources.txt" ] && cmp -s "$tmp" "$core/sources.txt"; then
		exit 0
	fi
	echo "gen_sources: core/sources.txt is stale; run core/tools/gen_sources.sh" >&2
	exit 1
fi

cp "$tmp" "$core/sources.txt"
echo "wrote $core/sources.txt ($(wc -l < "$core/sources.txt" | tr -d ' ') files)"
