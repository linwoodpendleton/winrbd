#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Freestanding smoke test: what an iPXE or a Windows kernel build sees of the core.
#
# Compiles every core/src/**/*.c as ISO C99 with -ffreestanding and NO system include path (only the compiler's own
# freestanding headers: <stddef.h>, <stdint.h>), then links all the objects into an executable with -nostdlib and no
# libc, next to a stub that defines exactly the three memory functions the core is allowed to call (memcpy, memmove, memset;
# equality is wri_ct_memeq, so no memcmp or bcmp is needed). The link fails if
# the core needs anything else. Nothing is run (the stub entry point never executes the core); this is a compile and
# link check only.
#
# usage: check_freestanding.sh CC CORE_DIR [EXTRA_FLAGS]
#   CC           gcc or clang (a path or a name)
#   CORE_DIR     the core/ directory of the tree
#   EXTRA_FLAGS  e.g. "-m32" (one word list, split on spaces) or "-O0"; default flags are -Os
# Exit 0 ok, 1 failure, 77 skipped (the toolchain cannot do a freestanding no-libc link here).
set -eu

cc=${1:?usage: check_freestanding.sh CC CORE_DIR [EXTRA_FLAGS]}
core=${2:?usage: check_freestanding.sh CC CORE_DIR [EXTRA_FLAGS]}
extra=${3:-}

# The link line below is the ELF / GNU ld one (static, -nostdlib, own entry symbol); other hosts get no verdict from it.
if [ "$(uname -s)" != Linux ]; then
	echo "check_freestanding: only run on Linux (ELF linker), skipped" >&2
	exit 77
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_freestanding.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

fsinc=$("$cc" $extra -print-file-name=include 2>/dev/null || true)
if [ -z "$fsinc" ] || [ ! -f "$fsinc/stddef.h" ]; then
	# clang keeps its freestanding headers in its resource dir
	fsinc=$("$cc" $extra -print-resource-dir 2>/dev/null || true)/include
fi
if [ ! -f "$fsinc/stddef.h" ] || [ ! -f "$fsinc/stdint.h" ]; then
	echo "check_freestanding: no freestanding <stddef.h>/<stdint.h> for $cc, skipped" >&2
	exit 77
fi

incs="-I$core/include -I$core/include/winrbd"
for d in "$core"/src/*; do
	[ -d "$d" ] && incs="$incs -I$d"
done

# The stub: the three functions of the core's whole libc surface, written byte-wise (not the optimiser's business to
# turn them into calls to themselves), and an entry point that does not call the core.
cat > "$tmp/stub.c" <<'EOF'
#include <stddef.h>
void *memcpy(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;

	while (n-- > 0)
		*a++ = *b++;
	return d;
}
void *memmove(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;

	if (a < b) {
		while (n-- > 0)
			*a++ = *b++;
	} else {
		a += n;
		b += n;
		while (n-- > 0)
			*--a = *--b;
	}
	return d;
}
void *memset(void *d, int c, size_t n)
{
	unsigned char *a = d;

	while (n-- > 0)
		*a++ = (unsigned char)c;
	return d;
}
void _start(void)
{
	for (;;)
		;
}
EOF

# One line per file so a failure names it. -fno-builtin-memcpy and friends (on the stub only) keep the stub from being
# replaced by a call to itself.
flags="-std=c99 -pedantic-errors -Wall -Wextra -Werror -ffreestanding -nostdinc -isystem $fsinc -Os
 -fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables $extra"
n=0
objs=""
for f in $(find "$core/src" -name '*.c' | LC_ALL=C sort); do
	o="$tmp/o$n.o"
	# shellcheck disable=SC2086
	"$cc" $flags $incs -c "$f" -o "$o" || { echo "check_freestanding: $f does not compile freestanding" >&2; exit 1; }
	objs="$objs $o"
	n=$((n + 1))
done
# shellcheck disable=SC2086
"$cc" $flags -fno-builtin-memcpy -fno-builtin-memmove -fno-builtin-memset -c "$tmp/stub.c" -o "$tmp/stub.o" \
	|| { echo "check_freestanding: the stub does not compile" >&2; exit 1; }

# shellcheck disable=SC2086
if ! "$cc" $extra -nostdlib -nostartfiles -static -no-pie -Wl,-e,_start $objs "$tmp/stub.o" -o "$tmp/image" 2> "$tmp/link.err"; then
	if grep -qiE "cannot find|unrecognized option|unsupported|not supported|linker command failed with exit code 1 \(use -v" "$tmp/link.err" \
	   && ! grep -qi "undefined" "$tmp/link.err"; then
		echo "check_freestanding: this toolchain cannot do the no-libc link ($(head -n 1 "$tmp/link.err")), skipped" >&2
		exit 77
	fi
	echo "check_freestanding: the core needs more than memcpy/memmove/memset:" >&2
	cat "$tmp/link.err" >&2
	exit 1
fi
echo "check_freestanding: ok ($n core files, ISO C99, no system headers, no libc, $cc $extra)"
