#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Compiles the portable core against iPXE's own headers, with the flags the iPXE build uses, so that a core change that the iPXE
# build would refuse is seen in ctest (and in CI) first. Nothing is linked or run, and nothing is built in the iPXE tree.
#
# Why it exists. iPXE's <stdint.h> is not the C99 one: it has the fixed-width types and nothing else (no uintptr_t, none of the limit
# macros UINT32_MAX, INT64_MIN, SIZE_MAX ...), and its string functions are inline wrappers, there is no out-of-line memmove(). The
# core uses the macros and the type, and takes its memory primitives from a host configuration header. For iPXE that header is
# ipxe/src/rbd_core_cfg.h, the "shim": it supplies uintptr_t and the macros from the compiler's predefined macros and maps WR_MEM*
# to iPXE's own functions. This script is the proof that the core and the shim still fit: a core file that starts using a macro the
# shim does not define (INT16_MAX, UINTPTR_MAX ...) fails here, and so does a shim that loses a definition the core needs.
#
# What it reproduces of the iPXE build (third_party/ipxe/src/Makefile.housekeeping and arch/*/Makefile; the pinned tree is read, not
# built or modified): the include path (arch/<arch>/include, arch/x86/include, include, the source directory), "-include
# include/compiler.h" (FILE_LICENCE, FILE_SECBOOT, __nonnull ...), -DARCH / -DPLATFORM / -DOBJECT, -ffreestanding -Os, the warning set
# (-Wall -W -Wformat-nonliteral -Wshift-overflow=2 -Wno-array-bounds -Wno-dangling-pointer) with -Werror, no -std (so the compiler's own
# default: gnu17 up to gcc 14, gnu23 with gcc 15, which is why the warning-free result matters on the 26.04 guest), the architecture flags
# (i386: -m32 -march=i386 -mregparm=3 -mrtd -fno-pie ...; x86_64, the EFI image: -m64 -mno-mmx -mno-sse -mno-red-zone -fpie, -fshort-wchar;
# an earlier version of this script compiled x86_64 with -fno-pie and a red zone, which is not what bin-x86_64-efi uses). Not reproduced: the platform's own
# headers beyond what the include path gives (the core includes none), the embedded configuration (config/*.h), the link.
# The compiler's own freestanding headers are added after the iPXE ones (-nostdinc -isystem), so the core cannot reach for a hosted
# header (<stdio.h>, <limits.h> from the host) that the iPXE build would not give it either.
#
# The objects are kept and their undefined symbols are read (nm): the iPXE link has no libc, so everything a core object needs that no other
# core object defines has to be something iPXE itself defines out of line. On x86 that is __memcpy, __memcpy_reverse and __memmove (the
# memcpy() and memmove() of <string.h> are inline wrappers around them; a plain "memcpy" or "memmove" in an object is therefore an undefined
# reference at the iPXE link: the failure docs/design/ipxe-driver.md records for memmove), memcmp (core/string.c) and the 64-bit division helpers of
# src/libgcc. A compile-only check cannot see any of this: it passes a core file that ends in a call to memmove() (a __builtin_memmove with a variable length, say). The
# allow-list is the NM_ALLOWED variable below; a symbol outside it names the file that needs it.
# The same objects are checked for writable global state (the core has none), which the harness's own objects pass but which the shim could break.
#
# The core is compiled exactly as the harness has it, with two things the import step of ipxe/tools/build.sh does for the real build done
# on the command line instead: WR_HOST_CONFIG_HEADER is set to "rbd_core_cfg.h" (the import appends that define to wr_port.h), and the
# licence placeholders are left empty (the import turns them into FILE_LICENCE and FILE_SECBOOT lines, which do not change a type).
#
#   check_ipxe_headers.sh [-c CC] [-k CORE_DIR] [-i IPXE_DIR] [-s SHIM_DIR] [-a "i386 x86_64"] [-j JOBS] [-q]
#     -c CC        compiler (default $CC, else gcc). gcc and clang both work; the flags only gcc knows are left out for clang
#     -k DIR       the core/ directory (default: the one of this repository)
#     -i DIR       the iPXE tree (default: third_party/ipxe of this repository; the src/ directory is the one used)
#     -s DIR       the directory with rbd_core_cfg.h (default: ipxe/src of this repository); the self-test points it at a damaged copy
#     -a LIST      architectures to compile for (default "i386 x86_64"; i386 needs a compiler that can do -m32, without libc headers)
#     -j N         parallel compiles (default: number of CPUs)
#     -q           quiet on success
#
# Exit status: 0 ok, 1 a file does not compile or needs a symbol iPXE does not define, 77 skipped (no iPXE tree, a clang compiler, or no -m32 on this compiler). With WRT_IPXE_REQUIRE=1 a
# skip is a failure (1): the CI job that exists for this check sets it, so the check cannot vanish from it unnoticed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
cc=${CC:-gcc}
core=$repo/core
ipxe=$repo/third_party/ipxe
shim=$repo/ipxe/src
archs="i386 x86_64"
jobs=""
quiet=0
while getopts c:k:i:s:a:j:q opt; do
	case $opt in
	c) cc=$OPTARG ;;
	k) core=$OPTARG ;;
	i) ipxe=$OPTARG ;;
	s) shim=$OPTARG ;;
	a) archs=$OPTARG ;;
	j) jobs=$OPTARG ;;
	q) quiet=1 ;;
	*) echo "usage: check_ipxe_headers.sh [-c CC] [-k CORE_DIR] [-i IPXE_DIR] [-s SHIM_DIR] [-a \"i386 x86_64\"] [-j JOBS] [-q]" >&2; exit 2 ;;
	esac
done

skip() {
	echo "check_ipxe_headers: $* (skipped)" >&2
	if [ "${WRT_IPXE_REQUIRE:-0}" = 1 ]; then
		echo "check_ipxe_headers: WRT_IPXE_REQUIRE=1: a skip is a failure here" >&2
		exit 1
	fi
	exit 77
}

src=$ipxe/src
[ -f "$src/include/compiler.h" ] && [ -f "$src/include/stdint.h" ] || skip "no iPXE tree at $ipxe (git submodule update --init third_party/ipxe)"
[ -f "$shim/rbd_core_cfg.h" ] || { echo "check_ipxe_headers: no rbd_core_cfg.h in $shim" >&2; exit 1; }
[ -f "$core/sources.txt" ] || { echo "check_ipxe_headers: $core has no sources.txt" >&2; exit 1; }
if [ -z "$jobs" ]; then
	# as check_core_std.sh: at most 8 at a time by default (a 100-core box under ctest -j would otherwise start a hundred compilers per test)
	jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
	[ "$jobs" -le 8 ] || jobs=8
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/wr_ipxe_hdr.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# what iPXE defines out of line and a core object may therefore leave undefined (see the header comment)
NM_ALLOWED=" __memcpy __memcpy_reverse __memmove memcmp __udivdi3 __umoddi3 __divdi3 __moddi3 __udivmoddi4 __divmoddi4 "
nmtool=$(command -v "${NM:-nm}" 2>/dev/null || true)
if [ -z "$nmtool" ]; then
	echo "check_ipxe_headers: no nm: the undefined-symbol check is not done (only the compile)" >&2
	if [ "${WRT_IPXE_REQUIRE:-0}" = 1 ]; then
		echo "check_ipxe_headers: WRT_IPXE_REQUIRE=1: that is a failure here" >&2
		exit 1
	fi
fi

objdumptool=$(command -v "${OBJDUMP:-objdump}" 2>/dev/null || true)
if [ -z "$objdumptool" ]; then
	echo "check_ipxe_headers: no objdump: the no-globals check of the iPXE objects is not done" >&2
	if [ "${WRT_IPXE_REQUIRE:-0}" = 1 ]; then
		echo "check_ipxe_headers: WRT_IPXE_REQUIRE=1: that is a failure here" >&2
		exit 1
	fi
fi

# iPXE is built with gcc, and its headers are not clang-clean (clang -Werror stops at "attribute declaration must precede definition" in
# <string.h>, before any core file is read), so a clang verdict would be about iPXE and not about the core. Only gcc is a judge here.
if "$cc" --version 2>/dev/null | grep -qi clang; then skip "$cc is clang; iPXE is built with gcc and its own headers do not compile warning-free with clang"; fi

fsinc=$("$cc" -print-file-name=include 2>/dev/null || true)
if [ ! -f "$fsinc/stddef.h" ]; then
	fsinc=$("$cc" -print-resource-dir 2>/dev/null || true)/include
fi
[ -f "$fsinc/stddef.h" ] || skip "no freestanding compiler headers for $cc"

# the files: the list the iPXE import uses (core/sources.txt), so a file missing from it is not compiled here either; the harness
# checks that the list is in sync (core_sources_in_sync)
sed -e '/^[[:space:]]*$/d' "$core/sources.txt" > "$tmp/files"
nfiles=$(wc -l < "$tmp/files" | tr -d ' ')
[ "$nfiles" -gt 0 ] || { echo "check_ipxe_headers: $core/sources.txt is empty" >&2; exit 1; }

# the core's include directories (the import copies every header flat into one directory; here they are where they are)
incs="-I$core/include -I$core/include/winrbd"
for d in "$core"/src/*; do
	[ -d "$d" ] && incs="$incs -I$d"
done
incs="$incs -I$core/crush_ln"

total=0
for arch in $archs; do
	case $arch in
	i386)
		# a compiler that cannot do -m32 at all (no 32-bit support in this build of it) is a skip, not a pass
		printf 'int main(void){return 0;}\n' > "$tmp/probe.c"
		"$cc" -m32 -c -nostdinc -o "$tmp/probe.o" "$tmp/probe.c" 2>/dev/null || skip "$cc cannot compile for -m32"
		plat=pcbios
		aflags="-m32 -march=i386 -fomit-frame-pointer -mregparm=3 -freg-struct-return -fshort-wchar -fno-pie"
		aflags="$aflags -fstrength-reduce -falign-jumps=1 -falign-loops=1 -falign-functions=1 -mpreferred-stack-boundary=2 -mrtd"
		;;
	x86_64)
		plat=efi
		# bin-x86_64-efi: arch/x86_64/Makefile.efi adds -fpie and -mno-red-zone (the red zone is unusable in firmware)
		aflags="-m64 -mno-mmx -mno-sse -mno-red-zone -fpie -fomit-frame-pointer -fshort-wchar"
		aflags="$aflags -fstrength-reduce -falign-jumps=1 -falign-loops=1 -falign-functions=1"
		;;
	*) echo "check_ipxe_headers: unknown architecture '$arch' (i386, x86_64)" >&2; exit 2 ;;
	esac
	wflags="-Wall -W -Wformat-nonliteral -Wshift-overflow=2 -Wno-array-bounds -Wno-dangling-pointer"
	# one self-contained command per file; a failure names the file and prints the compiler's words
	mkdir -p "$tmp/obj.$arch"
	cat > "$tmp/one.sh" <<EOF
#!/bin/sh
f=\$1
base=\$(basename "\$f" .c)
out=\$("$cc" $aflags -Os -ffreestanding -fno-common -fno-stack-protector $wflags -Werror \\
	-nostdinc -I"$src/arch/$arch/include" -I"$src/arch/x86/include" -I"$src/include" -I"$src" -isystem "$fsinc" \\
	-I"$shim" $incs \\
	-DARCH=$arch -DPLATFORM=$plat -DPLATFORM_$plat -DNVALGRIND -Ulinux -Ui386 -DOBJECT=\$base \\
	-DWR_HOST_CONFIG_HEADER='"rbd_core_cfg.h"' \\
	-include "$src/include/compiler.h" -c -o "$tmp/obj.$arch/\$base.o" "$core/\$f" 2>&1) || {
	printf '%s\n%s\n' "check_ipxe_headers: $arch: \$f does not compile against iPXE's headers:" "\$out" >&2
	exit 1
}
EOF
	chmod +x "$tmp/one.sh"
	if ! xargs -n 1 -P "$jobs" "$tmp/one.sh" < "$tmp/files" 2> "$tmp/err.$arch"; then
		# every failing file's message, once
		cat "$tmp/err.$arch" >&2
		echo "check_ipxe_headers: the core does not build against iPXE's headers ($arch, $cc). If a core file started using a standard header macro or" >&2
		echo "  type iPXE's <stdint.h> lacks, add it to ipxe/src/rbd_core_cfg.h (from the compiler's predefined macros) or stop using it in the core." >&2
		exit 1
	fi
	if [ -n "$nmtool" ]; then
		# one object name per core file (iPXE derives them from the file name, and the core keeps them unique), so the directory holds nfiles
		nobj=$(ls "$tmp/obj.$arch" | wc -l | tr -d ' ')
		[ "$nobj" = "$nfiles" ] || { echo "check_ipxe_headers: $arch: $nobj objects for $nfiles files (two core files with one basename?)" >&2; exit 1; }
		# POSIX format: "name type [value size]"; undefined = U, defined = anything else but a lowercase-only local (only globals count)
		"$nmtool" -P "$tmp"/obj."$arch"/*.o 2> /dev/null | awk 'NF >= 2 && $1 !~ /:$/ { if ($2 == "U") u[$1] = 1; else d[$1] = 1 } END { for (n in u) if (!(n in d)) print n }' | sort > "$tmp/undef.$arch"
		bad=""
		for sym in $(cat "$tmp/undef.$arch"); do
			case "$NM_ALLOWED" in *" $sym "*) ;; *) bad="$bad $sym" ;; esac
		done
		if [ -n "$bad" ]; then
			for sym in $bad; do
				for o in "$tmp"/obj."$arch"/*.o; do
					if "$nmtool" -P -u "$o" 2> /dev/null | awk -v s="$sym" '$1 == s { f = 1 } END { exit f ? 0 : 1 }'; then
						echo "check_ipxe_headers: $arch: $(basename "$o" .o).c needs the symbol '$sym', which neither the core nor iPXE's string and libgcc code define out of line" >&2
					fi
				done
			done
			echo "check_ipxe_headers: the core would not link into iPXE ($arch, $cc): undefined:$bad. On x86 a call that the compiler makes to memcpy / memmove / memset" >&2
			echo "  has no target there (iPXE's own are inline wrappers around __memcpy and __memmove): route it through WR_MEMCPY / WR_MEMMOVE / WR_MEMSET, or avoid the construct." >&2
			exit 1
		fi
	fi
	# the same objects must hold no writable global state either (the core's own rule, checked by check_no_globals.sh on the harness's
	# objects: the shim and iPXE's inline string functions must not bring a variable into a core file). Read-only data is fine, including
	# .data.rel.ro* (the tables of pointers that -fpie puts there), as in check_no_globals.sh. The one exception is the byte
	# "__debug_disable_<object>" that iPXE's compiler.h puts into every object it is included in (the DBG level of the object; it is
	# there in every iPXE file, written only by iPXE's debug machinery and by nothing in the core).
	if [ -n "$objdumptool" ]; then
		bad_glob=0
		for o in "$tmp"/obj."$arch"/*.o; do
			"$objdumptool" -t "$o" 2> /dev/null | awk -v f="$(basename "$o" .o).c" -v arch="$arch" '
				$3 == "O" && ($4 ~ /^\.(data|bss|tdata|tbss|sdata|sbss)(\.|$)/ || $4 == "*COM*") && $4 !~ /^\.data\.rel\.ro/ &&
				$NF !~ /^__debug_disable_/ && $5 !~ /^0+$/ {
					printf "check_ipxe_headers: %s: %s has writable global state: %s (section %s, size 0x%s)\n", arch, f, $NF, $4, $5; found = 1 }
				END { exit found ? 1 : 0 }' >> "$tmp/noglob.$arch" || bad_glob=1
		done
		if [ "$bad_glob" = 1 ]; then
			cat "$tmp/noglob.$arch" >&2
			echo "check_ipxe_headers: $arch: the core built the iPXE way holds writable global state (the core has none: it keeps its state in the arena)" >&2
			exit 1
		fi
	fi
	total=$((total + nfiles))
done
checked=""
[ -n "$nmtool" ] && checked="$checked, no undefined symbol outside iPXE's string and libgcc code"
[ -n "$objdumptool" ] && checked="$checked, no writable global"
[ "$quiet" = 1 ] || echo "check_ipxe_headers: ok ($total compiles: $nfiles core files, $archs, against iPXE's headers, iPXE's flags, $cc$checked)"
