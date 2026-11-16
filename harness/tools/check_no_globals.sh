#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Fails if any object of the core static library has writable global state: non-empty .data,
# .bss, COMMON, or thread-local sections. Read-only data is fine, including .data.rel.ro* (const
# tables holding pointers, which a PIE build places there).
#
# usage: check_no_globals.sh libwr_core.a
set -eu

lib=${1:?usage: check_no_globals.sh libwr_core.a}
lib=$(cd "$(dirname "$lib")" && pwd)/$(basename "$lib")
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_noglob.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

(cd "$tmp" && ar x "$lib")
bad=0
for o in "$tmp"/*.o; do
	[ -f "$o" ] || continue
	# columns of objdump -h: Idx Name Size ...
	objdump -h "$o" | awk -v obj="$(basename "$o")" '
		$2 ~ /^\.(data|bss|tdata|tbss|sdata|sbss)(\.|$)/ || $2 == "COMMON" {
			if ($2 ~ /^\.data\.rel\.ro/) next
			if ($3 !~ /^0+$/) { printf "%s: writable section %s (size 0x%s)\n", obj, $2, $3; found = 1 }
		}
		END { exit found ? 1 : 0 }' || bad=1
done
if [ "$bad" -ne 0 ]; then
	echo "check_no_globals: the core must not contain writable global state" >&2
	exit 1
fi
echo "check_no_globals: ok"
