#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Compiles every file of the core in another C dialect than the one the harness builds in: the language standard that iPXE ends up with.
#
# iPXE sets no -std. It gets the compiler's default: gnu17 up to gcc 14, gnu23 with gcc 15 (the compiler of the CI image
# ubuntu-26.04, and of the build guest). The harness builds the core as strict C99 (-std=c99 -pedantic-errors), which says nothing about
# what a C23 compiler thinks of it: bool, true, false, nullptr, constexpr, static_assert, thread_local, typeof and alignas become keywords
# (a field or a variable of that name stops compiling), and an empty parameter list now means (void). This check compiles each file with
# -std=gnu2x (the spelling every gcc from 9 and clang from 9 knows; gcc 15 takes it as gnu23) and -std=gnu17, with the warning set of the
# iPXE build, freestanding, and the compiler's own headers only. It writes no object (-o /dev/null): a syntax and warning check.
#
# It is independent of the iPXE tree and of the shim (check_ipxe_headers.sh is the one that reads those), so it runs everywhere the harness
# does. An old compiler that has no C23 mode (the keywords are the compiler's business: gcc 11 and clang 14 accept gnu2x but do not make
# bool a keyword) still checks what it can; that gcc 15 is the one that judges is why the 26.04 jobs exist.
#
#   check_core_std.sh [-c CC] [-k CORE_DIR] [-s "gnu17 gnu2x"] [-m "-m32"]
#     -c CC     compiler (default $CC, else gcc)
#     -k DIR    the core/ directory (default: the one of this repository)
#     -s LIST   standards to compile with (default "gnu17 gnu2x"; any -std= value of the compiler)
#     -m FLAGS  extra flags, one word list (for example -m32)
#
# Exit status: 0 ok, 1 a file does not compile, 77 skipped (the compiler does not know a requested standard).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
cc=${CC:-gcc}
core=$repo/core
stds="gnu17 gnu2x"
extra=""
while getopts c:k:s:m: opt; do
	case $opt in
	c) cc=$OPTARG ;;
	k) core=$OPTARG ;;
	s) stds=$OPTARG ;;
	m) extra=$OPTARG ;;
	*) echo "usage: check_core_std.sh [-c CC] [-k CORE_DIR] [-s \"gnu17 gnu2x\"] [-m FLAGS]" >&2; exit 2 ;;
	esac
done

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_std.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

is_clang=0
if "$cc" --version 2>/dev/null | grep -qi clang; then is_clang=1; fi
# shellcheck disable=SC2086
fsinc=$("$cc" $extra -print-file-name=include 2>/dev/null || true)
if [ ! -f "$fsinc/stddef.h" ]; then
	# shellcheck disable=SC2086
	fsinc=$("$cc" $extra -print-resource-dir 2>/dev/null || true)/include
fi
if [ ! -f "$fsinc/stddef.h" ] || [ ! -f "$fsinc/stdint.h" ]; then
	echo "check_core_std: no freestanding <stddef.h>/<stdint.h> for $cc (skipped)" >&2
	exit 77
fi

incs="-I$core/include -I$core/include/winrbd"
for d in "$core"/src/*; do
	[ -d "$d" ] && incs="$incs -I$d"
done
incs="$incs -I$core/crush_ln"

wflags="-Wall -W -Wformat-nonliteral -Wno-array-bounds"
[ "$is_clang" = 1 ] || wflags="$wflags -Wshift-overflow=2 -Wno-dangling-pointer"

printf 'int main(void){return 0;}\n' > "$tmp/probe.c"
sed -e '/^[[:space:]]*$/d' "$core/sources.txt" > "$tmp/files"
nfiles=$(wc -l < "$tmp/files" | tr -d ' ')
[ "$nfiles" -gt 0 ] || { echo "check_core_std: $core/sources.txt is empty" >&2; exit 1; }
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
[ "$jobs" -le 8 ] || jobs=8
n=0
for std in $stds; do
	# shellcheck disable=SC2086
	"$cc" $extra -std="$std" -c -o /dev/null "$tmp/probe.c" 2>/dev/null || { echo "check_core_std: $cc does not know -std=$std (skipped)" >&2; exit 77; }
	cat > "$tmp/one.sh" <<EOF
#!/bin/sh
f=\$1
out=\$("$cc" $extra -std=$std -Os -ffreestanding -fno-common -fno-stack-protector $wflags -Werror \\
	-nostdinc -isystem "$fsinc" $incs -c -o /dev/null "$core/\$f" 2>&1) || {
	printf 'check_core_std: %s does not compile with -std=$std:\n%s\n' "\$f" "\$out" >&2
	exit 1
}
EOF
	chmod +x "$tmp/one.sh"
	if ! xargs -n 1 -P "$jobs" "$tmp/one.sh" < "$tmp/files" 2> "$tmp/err"; then
		cat "$tmp/err" >&2
		exit 1
	fi
	n=$((n + nfiles))
done
echo "check_core_std: ok ($n compiles, -std={$(echo "$stds" | tr ' ' ',')}, freestanding, iPXE warning set, $cc $extra)"
