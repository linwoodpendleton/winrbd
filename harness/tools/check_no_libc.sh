#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Fails if the core static library needs anything from libc beyond memcpy/memmove/memset
# (and compiler arithmetic helpers). Symbols that are defined by another member of the same
# archive are not undefined. Sanitizer runtime symbols are ignored (sanitizer builds only).
#
# usage: check_no_libc.sh libwr_core.a
set -eu

lib=${1:?usage: check_no_libc.sh libwr_core.a}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_nolibc.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

nm -g --defined-only "$lib" 2>/dev/null | awk 'NF==3 {print $3}' | LC_ALL=C sort -u > "$tmp/defined"
nm -u "$lib" 2>/dev/null | awk 'NF==2 && $1=="U" {print $2}' | LC_ALL=C sort -u > "$tmp/undef"

LC_ALL=C comm -23 "$tmp/undef" "$tmp/defined" \
	| grep -v -E '^(memcpy|memmove|memset)$' \
	| grep -v -E '^__(u?div|u?mod|ashl|lshr|ashr|mul)(di|ti|si)3$' \
	| grep -v -E '^__(asan|ubsan|sanitizer|msan|tsan|gcov|llvm_gcov|stack_chk|cyg_profile)' \
	> "$tmp/bad" || true

if [ -s "$tmp/bad" ]; then
	echo "check_no_libc: core references libc symbols it must not use:" >&2
	cat "$tmp/bad" >&2
	exit 1
fi
echo "check_no_libc: ok ($(wc -l < "$tmp/undef" | tr -d ' ') undefined symbols, all allowed)"
