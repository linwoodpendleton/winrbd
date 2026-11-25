#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build.sh - build iPXE with the winrbd "rbd://" SAN driver, from a clean copy of the pinned submodule.
#
#   ipxe/tools/build.sh prepare [-s SRC] [-o OUT]       export the pinned iPXE tree to OUT, apply ipxe/patches, import the
#                                                       glue files, the self-tests and the core
#   ipxe/tools/build.sh build   [-o OUT] [-j N] [-e SCRIPT] [-d DEBUG] [-- make-args] TARGET...
#                                                       prepare (if OUT is not prepared, or not from the current sources) and
#                                                       make TARGET... in OUT/src
#   ipxe/tools/build.sh licence [-o OUT] TARGET...      make TARGET.licence: the iPXE licence check on a real build, and fail
#                                                       unless the overall licence is exactly the expected one (below)
#   ipxe/tools/build.sh verify  [-o OUT] TARGET...      after "build": the driver is linked into each image and no self-test
#                                                       object is (link maps, and strings of the EFI image)
#   ipxe/tools/build.sh secboot [-o OUT] [-j N] [-n | -p]
#                                                       the Secure Boot build (bin-x86_64-efi-sb/snponly.efi) must be refused
#                                                       and every driver object must be FILE_SECBOOT ( FORBIDDEN ).
#                                                       -p: control, the pristine pinned tree must build the same target.
#                                                       -n: control, a glue file that is not FORBIDDEN must be seen
#   ipxe/tools/build.sh test    [-o OUT] [-j N] [-n | -u] [TARGET] [-- make-args]
#                                                       build the self-test program (default bin-x86_64-linux/tests.linux),
#                                                       run it, and fail unless every test set passed and every winrbd test
#                                                       set (ipxe/tests/*.c) really ran. -n: the negative control,
#                                                       -u: with UBSan in the driver's objects (both: see below)
#   ipxe/tools/build.sh check   [-n]                    static checks of ipxe/, ipxe/tests/ and the licence tags of core/
#                                                       (no iPXE tree needed). -n: the negative controls, seeded mistakes in
#                                                       a scratch copy (a core file without its licence placeholder, a glue
#                                                       file marked PERMITTED, ...) must each be refused with their message
#   ipxe/tools/build.sh clean   [-o OUT]                delete OUT (only a directory this script prepared)
#
# TARGETs are iPXE make targets relative to OUT/src, for example
#   bin-x86_64-efi/ipxe.efi   bin/undionly.kpxe   bin/ipxe.pxe   bin/ipxe.usb   bin/ipxe.iso
# and, for the 32-bit BIOS images (bin/ is x86_64: DEFAULT_ARCH of the pinned iPXE), bin-i386-pcbios/undionly.kpxe and so on
#
# What "prepare" does (and why nothing inside third_party/ipxe is ever modified):
#   1. SRC (default third_party/ipxe) must be at the revision in ipxe/PINNED. The tree is EXPORTED with `git archive` (committed
#      files only, so a dirty or untracked file in the submodule cannot leak into a build) into OUT. A SRC that is not a git
#      checkout (a release tarball) is copied as is, with a warning.
#   2. ipxe/patches/*.patch are applied in name order (patch -p1). They are the whole change to iPXE's own files.
#   3. The glue files ipxe/src/* and the portable core are copied FLAT into OUT/src/winrbd/. The core is imported with a
#      mechanical transform: the one placeholder line WR_FILE_LICENCE_MIT (or ..._LGPL21) of every .c file becomes
#      "FILE_LICENCE ( MIT );" ("... ( GPL2_OR_LATER );" for core/crush_ln/) plus "FILE_SECBOOT ( FORBIDDEN );", and every header
#      gets the same two lines after its include guard. iPXE's licence check (make bin/<target>.licence) greps the sources for
#      FILE_LICENCE, so the tags have to be in the text; the core in the repository stays free of iPXE macros.
#   4. The self-test files ipxe/tests/*.c (named rbd_<module>_test.c by convention) are copied FLAT into OUT/src/tests/, next to
#      iPXE's own tests. Patch 0003 makes src/tests/tests.c require them; "check" keeps the two lists equal.
#
# "test": iPXE's self-tests (src/tests/*_test.c, struct self_test) are linked into a test program that runs as a Linux process,
# bin-x86_64-linux/tests.linux (bin-i386-linux/tests.linux: the 32-bit build, the word size of the BIOS images). The script builds
# it, runs it, and accepts only: exit status 0, the line "OK: all N tests passed", no FAILURE line, and an "OK: "<name>" N tests
# passed" line for every ipxe/tests/<name>.c (a test file that was not wired in would otherwise pass by not running).
# "test -n" (negative control) prepares a second copy, OUT-negctl, with the deliberate failure of rbd_selftest.c compiled in
# (RBD_SELFTEST_NEGATIVE_CONTROL through iPXE's per-object CFLAGS_<object>), runs the same check, and succeeds only if the check
# FAILED because of that assertion (exactly its three FAILURE lines: a dead build, a crash or a timeout is an error, not a proof):
# it proves that a failing self-test is seen. The copy is deleted afterwards.
# "test -u" (UBSan): a third copy, OUT-ubsan, with the glue, the core and the test objects compiled with -fsanitize=undefined in
# trap mode (no runtime library needed; the alignment check is off, see UBSAN_FLAGS); undefined behaviour in them, under iPXE's own
# flags, ends the run.
# The run is only accepted if the objects really contain UBSan traps (iPXE's make does not say whether a flag was used).
#
# Secrets: an EMBED script (-e) may hold the cephx key (design: one key per image). The script never prints it, but the image holds
# it in clear, and so does the build directory (bin*/ objects): keep both private, never put them in a CI artifact, a log or the
# repository (build/ is git-ignored). Tests and CI never embed a key.
#
# Environment (all optional):
#   IPXE_HOST_LZMA_PREFIX   directory with include/lzma.h and lib/liblzma.so, for a host without liblzma-dev (iPXE's zbin tool)
#   IPXE_JOBS               make -j (default: number of CPUs)
#   IPXE_NICE               command prefix for make (default: empty), for example "nice -n 19"
#   IPXE_TEST_TIMEOUT       seconds before the test program is killed (default 900; needs the timeout command, else none)
#
# Written for bash 3.2 and 5; needs git, patch, awk, make and the iPXE build dependencies (gcc, perl, liblzma-dev, and for
# bin/ipxe.iso: mtools, xorriso, syslinux).
set -eu
set -o pipefail
LC_ALL=C
export LC_ALL

HERE=$(cd "$(dirname "$0")" && pwd)
IPXE_DIR=$(cd "$HERE/.." && pwd)
REPO=$(cd "$IPXE_DIR/.." && pwd)
MARK=.winrbd-ipxe-build

die() { echo "ipxe/tools/build.sh: $*" >&2; exit 1; }
note() { echo "ipxe/tools/build.sh: $*" >&2; }

pinned_rev() { sed -n '1{s/[[:space:]].*//;p;}' "$IPXE_DIR/PINNED"; }

# ---- static checks -------------------------------------------------------------------------------------------------------

TESTS_PATCH=0003-winrbd-self-tests.patch

# The licence and Secure Boot declarations of a glue or test file (iPXE greps the sources for them, so they must be the text it
# expects): an "SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL" comment in the first five lines (CONTRIBUTING.md, rule 2),
# exactly one line "FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );" and exactly one "FILE_SECBOOT ( FORBIDDEN );", and NO other
# FILE_LICENCE / FILE_SECBOOT in the code. Comment lines (first text is "*", "/*" or "//") are not looked at: the files explain the
# tags in their header comments. Any other spelling ("FILE_SECBOOT (PERMITTED)", "FILE_SECBOOT(PERMITTED)", FILE_SECBOOT_PERMITTED
# used directly, a second licence line) is refused: a check for the one spelling that exists today would pass the next one.
# FILE_SECBOOT ( PERMITTED ) needs the security review the rule asks for. $1 = file. Prints what is wrong; non-zero if anything is.
check_tags() {
	awk -v f="$1" '
		{ sub(/[ \t\r]+$/, "") }
		NR <= 5 && index($0, "SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL") { spdx = 1 }
		/^[ \t]*(\/\*|\*|\/\/)/ { next }
		/(^|[^A-Za-z0-9_])FILE_LICENCE/ {
			if ($0 == "FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );") lic++
			else { printf "%s: a FILE_LICENCE line other than the one declaration (FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );): %s\n", f, $0; bad = 1 }
		}
		/(^|[^A-Za-z0-9_])FILE_SECBOOT/ {
			if ($0 == "FILE_SECBOOT ( FORBIDDEN );") sec++
			else { printf "%s: FILE_SECBOOT other than ( FORBIDDEN ) needs the security review the rule asks for: %s\n", f, $0; bad = 1 }
		}
		END {
			if (!spdx) { printf "missing SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL in the first five lines: %s (CONTRIBUTING.md, rule 2)\n", f; bad = 1 }
			if (lic != 1) { printf "missing FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL ): %s (found %d such lines, need exactly one)\n", f, lic; bad = 1 }
			if (sec != 1) { printf "missing FILE_SECBOOT ( FORBIDDEN ): %s (found %d such lines, need exactly one)\n", f, sec; bad = 1 }
			exit bad
		}' "$1"
}

# The self-test files: each declares licence and Secure Boot status, is named rbd_*.c (iPXE derives the object name from the base
# name, and all test objects of the series share one directory), registers a test set whose .name is its object name (the
# "test" command looks for that name in the run), and is wired in by patch 0003 (REQUIRE_OBJECT): a file that is not wired would
# never run, a wired object without a file would not link. Prints a line per problem; returns non-zero if there was one.
check_tests() {
	local f base bad=0 patch="$IPXE_DIR/patches/$TESTS_PATCH" o wired n=0
	for f in "$IPXE_DIR"/tests/*; do
		[ -f "$f" ] || continue
		case "$(basename "$f")" in
		README.md) continue ;;
		*.c) ;;
		*) echo "ipxe/tests holds only rbd_*.c files and README.md (a header is not imported): $f"; bad=1; continue ;;
		esac
		n=$((n + 1))
		base=$(basename "$f" .c)
		check_tags "$f" || bad=1
		case "$base" in rbd_*) ;; *) echo "test file name must start with rbd_: $f"; bad=1 ;; esac
		if [ -e "$IPXE_DIR/src/$base.c" ] || [ -e "$IPXE_DIR/src/$base.h" ] || [ "$(find "$REPO/core" -name "$base.*" -print | grep -c .)" != 0 ]; then
			echo "test file name collides with a glue or core file: $f"; bad=1
		fi
		grep -Eq '^struct self_test[[:space:]]+[A-Za-z0-9_]+[[:space:]]+__self_test' "$f" || { echo "no 'struct self_test <name> __self_test' in $f"; bad=1; }
		grep -Eq "^[[:space:]]*\\.name[[:space:]]*=[[:space:]]*\"$base\"," "$f" || { echo "the test set's .name must be \"$base\" (the name of the object): $f"; bad=1; }
		if [ -f "$patch" ]; then
			grep -q "^+REQUIRE_OBJECT ( $base );" "$patch" || { echo "not wired in: add '+REQUIRE_OBJECT ( $base );' to patches/$TESTS_PATCH (and one to the hunk's new line count): $f"; bad=1; }
		fi
	done
	if [ -f "$patch" ]; then
		for o in $(sed -n 's/^+REQUIRE_OBJECT ( \(rbd_[A-Za-z0-9_]*\) );.*/\1/p' "$patch"); do
			[ -f "$IPXE_DIR/tests/$o.c" ] || { echo "patches/$TESTS_PATCH requires $o but ipxe/tests/$o.c does not exist"; bad=1; }
		done
		# a REQUIRE_OBJECT line the pattern above would not see (another prefix, a different spelling) is a mistake too
		wired=$(grep -c '^+REQUIRE_OBJECT' "$patch" || true)
		[ "$wired" = "$(grep -c '^+REQUIRE_OBJECT ( rbd_[A-Za-z0-9_]* );' "$patch" || true)" ] || { echo "patches/$TESTS_PATCH adds a REQUIRE_OBJECT line that is not '+REQUIRE_OBJECT ( rbd_<name> );'"; bad=1; }
		[ "$wired" = "$n" ] || { echo "patches/$TESTS_PATCH wires $wired objects, ipxe/tests has $n files"; bad=1; }
	elif [ "$n" -gt 0 ]; then
		echo "ipxe/tests has $n files but patches/$TESTS_PATCH does not exist"; bad=1
	fi
	return $bad
}

# The line counts in the hunk headers of a patch ("@@ -97,3 +97,6 @@") must match the hunks: "patch" refuses a hunk whose counts are
# wrong ("malformed patch") or, worse, applies a short one, and the error only shows when the tree is prepared. $1 = patch file.
# Prints what is wrong; non-zero if anything is.
patch_counts_ok() {
	awk '
		function finish() { if (inh) { printf "%s: hunk at line %d is short (old %d of %d, new %d of %d)\n", FILENAME, hl, o, ob, n, nb; bad = 1 } inh = 0 }
		/^@@ -[0-9]+(,[0-9]+)? \+[0-9]+(,[0-9]+)? @@/ {
			finish(); hl = FNR; h = $0; sub(/^@@ -/, "", h); split(h, a, " ")
			split(a[1], b, ","); ob = (b[2] == "" ? 1 : b[2]) + 0
			x = a[2]; sub(/^\+/, "", x); split(x, c, ","); nb = (c[2] == "" ? 1 : c[2]) + 0
			o = 0; n = 0; inh = (ob + nb > 0); after = !inh; next
		}
		/^(--- |\+\+\+ |diff |index )/ && ! inh { after = 0; next }
		after && /^[-+ ]/ { printf "%s:%d: a line after the end of its hunk (the header counts are too small): %s\n", FILENAME, FNR, $0; bad = 1; after = 0; next }
		inh {
			t = substr($0, 1, 1)
			if (t == " " || t == "") { o++; n++ } else if (t == "-") o++; else if (t == "+") n++; else if (t != "\\") { printf "%s:%d: not a hunk line: %s\n", FILENAME, FNR, $0; bad = 1; inh = 0 }
			if (inh && o == ob && n == nb) { inh = 0; after = 1 }
			if (inh && (o > ob || n > nb)) { printf "%s: hunk at line %d is longer than its header says\n", FILENAME, hl; bad = 1; inh = 0 }
		}
		END { finish(); exit bad }' "$1"
}

# The core stays free of iPXE macros: each of its C files carries ONE placeholder line, which "prepare" turns into FILE_LICENCE and
# FILE_SECBOOT (import_core_file). A file without it would be refused only when somebody prepares a tree; the same is checked here,
# so that it is the first step of the job that fails, and the message names the file. core/ is MIT, except core/crush_ln/ (LGPL-2.1,
# imported as "GPL2_OR_LATER"). Every header needs an include guard (#ifndef X / #define X), where the import puts its two lines.
check_core() {
	local f want n bad=0 core="$REPO/core"
	for f in $(cd "$core" && find src crush_ln -name '*.c' | sort); do
		case $f in crush_ln/*) want=LGPL21 ;; *) want=MIT ;; esac
		n=$(grep -Ec '^WR_FILE_LICENCE_(MIT|LGPL21)[[:space:]]*$' "$core/$f" || true)
		if [ "$n" != 1 ]; then
			echo "core/$f: needs exactly one WR_FILE_LICENCE_$want line (it has $n): without it the iPXE licence check sees no FILE_LICENCE for the file"
			bad=1
		elif ! grep -Eq "^WR_FILE_LICENCE_${want}[[:space:]]*\$" "$core/$f"; then
			echo "core/$f: the placeholder must be WR_FILE_LICENCE_$want (core/crush_ln is LGPL21, the rest of core/ is MIT)"
			bad=1
		fi
	done
	# the core stays free of iPXE macros: the import ADDS the one licence and the one Secure Boot line; a core file with an own
	# FILE_LICENCE / FILE_SECBOOT would give the object two (the licence check would combine both, and a PERMITTED could hide
	# beside the imported FORBIDDEN). Comment lines are not looked at.
	for f in $(cd "$core" && find include src crush_ln \( -name '*.c' -o -name '*.h' -o -name '*.inc' \) | sort); do
		n=$(awk '/^[ \t]*(\/\*|\*|\/\/)/ { next } /(^|[^A-Za-z0-9_])FILE_(LICENCE|SECBOOT)/ { n++ } END { print n + 0 }' "$core/$f")
		[ "$n" = 0 ] || { echo "core/$f: has $n FILE_LICENCE / FILE_SECBOOT line(s) of its own: the core stays free of iPXE macros (the import adds them)"; bad=1; }
	done
	for f in $(cd "$core" && find include src crush_ln -name '*.h' | sort); do
		awk '
			state == 0 && /^#ifndef[ \t]+[A-Za-z0-9_]+[ \t]*$/ { guard = $2; state = 1; next }
			state == 1 && $1 == "#define" && $2 == guard { state = 2 }
			END { exit state == 2 ? 0 : 1 }' "$core/$f" || { echo "core/$f: no include guard (#ifndef X / #define X): the import cannot tag it"; bad=1; }
	done
	return $bad
}

# The subcommands the CI workflow calls must exist (a renamed one would fail only in CI), and the steps must not bypass this script
# with a make of their own.
check_workflow() {
	local wf="$REPO/.github/workflows/ipxe.yml" sub bad=0
	[ -f "$wf" ] || return 0
	# (comment lines are not calls)
	for sub in $(sed -n '/^[[:space:]]*#/d; s|.*ipxe/tools/build\.sh[[:space:]][[:space:]]*\([A-Za-z][A-Za-z-]*\).*|\1|p' "$wf" | sort -u); do
		case $sub in
		prepare|build|licence|verify|secboot|test|check|clean) ;;
		*) echo ".github/workflows/ipxe.yml calls 'build.sh $sub', which is not a subcommand"; bad=1 ;;
		esac
	done
	# The non-comment text of the workflow, read once. Every look below counts matches (grep -c, which reads all its input): a
	# "grep -q" at the end of a pipe exits at the first match, the writer then dies of SIGPIPE, and under "set -o pipefail" a
	# match is reported as a failure, depending on timing (it made the first version of the gate check fail on one run in three).
	local body
	body=$(grep -v '^[[:space:]]*#' "$wf" || true)
	if [ "$(printf '%s\n' "$body" | grep -Ec '^[[:space:]]*(-[[:space:]]+)?(run:[[:space:]]*)?(cd [^;]*&&[[:space:]]*)?make[[:space:]]' || true)" != 0 ]; then
		echo ".github/workflows/ipxe.yml runs make by hand: build.sh is the only supported interface"; bad=1
	fi
	# The gates the roadmap and the design (section 14.3) ask CI to run. A workflow that quietly drops one stays green, so the
	# check names them: each text must be on a line that is not a comment (the steps above only prove that what IS called exists).
	local want
	while IFS= read -r want; do
		[ -n "$want" ] || continue
		[ "$(printf '%s\n' "$body" | grep -c -F -- "$want" || true)" != 0 ] || { echo ".github/workflows/ipxe.yml no longer runs '$want' (a gate of the driver's CI: docs/design/ipxe-driver.md section 14.3)"; bad=1; }
	done <<'LIST'
build.sh check -n
build.sh verify
build.sh licence
build.sh secboot -j
build.sh secboot -p
build.sh secboot -n
build.sh test -n
build.sh test -j
bin-x86_64-efi/ipxe.efi
bin/undionly.kpxe
bin/ipxe.pxe
bin/ipxe.usb
bin/ipxe.iso
bin-i386-pcbios/undionly.kpxe
bin-i386-pcbios/ipxe.usb
bin-x86_64-efi/snponly.efi
bin-x86_64-linux/tests.linux
bin-i386-linux/tests.linux
flags: "-u"
LIST
	[ "$(printf '%s\n' "$body" | grep -Ec 'build\.sh check[[:space:]]*$' || true)" != 0 ] || { echo ".github/workflows/ipxe.yml no longer runs 'build.sh check' (the static checks)"; bad=1; }
	return $bad
}

# Every glue file declares its licence and its Secure Boot status (iPXE's checks grep for these lines), and no glue file
# has the basename of a core file (they all land in one directory, and iPXE derives object names from basenames).
check_all() {
	local f bad=0 base
	for f in "$IPXE_DIR"/src/*.c "$IPXE_DIR"/src/*.h; do
		[ -f "$f" ] || continue
		check_tags "$f" || bad=1
		case "$(basename "$f")" in rbd_*) ;; *) echo "glue file name must start with rbd_: $f"; bad=1 ;; esac
		base=$(basename "$f")
		if [ -n "$(find "$REPO/core" -name "$base" -print)" ]; then echo "glue file name collides with a core file: $f"; bad=1; fi
	done
	for f in "$IPXE_DIR"/patches/*.patch; do
		[ -f "$f" ] || continue
		grep -q '^--- a/' "$f" || { echo "not a unified diff: $f"; bad=1; }
		patch_counts_ok "$f" || bad=1
	done
	[ -s "$IPXE_DIR/PINNED" ] || { echo "ipxe/PINNED is missing or empty"; bad=1; }
	check_tests || bad=1
	check_core || bad=1
	check_workflow || bad=1
	# this script runs under "set -o pipefail": "cmd | grep -q X" ends the pipe at the first match, cmd can die of SIGPIPE, and the
	# match then reads as a failure, depending on timing (a gate of this script failed that way on one run in three). grep -c reads
	# all its input. (The pattern is written so that this line does not match itself.)
	if [ "$(sed '/^[[:space:]]*#/d' "$IPXE_DIR/tools/build.sh" | grep -Ec '\|[[:space:]]*grep[[:space:]]+-[A-Za-z]*q' || true)" != 0 ]; then
		echo "ipxe/tools/build.sh: a pipeline that ends in 'grep -q' (timing-dependent under pipefail): count with 'grep -c' instead"; bad=1
	fi
	# the core's header basenames must be unique (they are imported into one directory)
	local dups
	dups=$(find "$REPO/core/include" "$REPO/core/src" "$REPO/core/crush_ln" \( -name '*.h' -o -name '*.inc' \) -exec basename {} \; | sort | uniq -d)
	[ -z "$dups" ] || { echo "duplicate core header basenames: $dups"; bad=1; }
	return $bad
}

# check -n: the negative controls of the static checks. Each seeded mistake goes into a scratch copy of ipxe/ and core/ (the copy
# runs ITS OWN build.sh, so it checks itself) and the check must refuse it, with the message that names the mistake: a check that
# passes a mistake, or that fails for another reason, proves nothing and fails this control. The unmodified copy must pass first
# (the positive control: otherwise every refusal below could be a broken copy).
cmd_check_negative() {
	local tmp work n=0 name want out rc f g
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/winrbd-check-n.XXXXXX") || die "check -n: no scratch directory"
	trap 'rm -rf "${tmp:?}"' EXIT
	work="$tmp/repo"
	fresh() {
		rm -rf "${work:?}"
		mkdir -p "$work"
		cp -R "$IPXE_DIR" "$work/ipxe"
		cp -R "$REPO/core" "$work/core"
		rm -rf "$work/ipxe/build"
		# the real workflow too (the positive control must pass with it, the controls below seed mistakes into it)
		if [ -f "$REPO/.github/workflows/ipxe.yml" ]; then
			mkdir -p "$work/.github/workflows"
			cp "$REPO/.github/workflows/ipxe.yml" "$work/.github/workflows/ipxe.yml"
		fi
	}
	run_copy() { rc=0; out=$(bash "$work/ipxe/tools/build.sh" check 2>&1) || rc=$?; }
	# $1 = what is seeded, $2 = a substring the refusal must contain; the seeding is done by the caller before the call
	expect_refused() {
		name=$1; want=$2
		run_copy
		if [ "$rc" = 0 ]; then
			die "check -n: the check ACCEPTED a seeded mistake ($name): it does not see it"
		fi
		case $out in
		*"$want"*) n=$((n + 1)); note "check -n: refused, as it must: $name" ;;
		*) echo "$out" >&2; die "check -n: the seeded mistake ($name) was refused, but not with '$want': the check failed for another reason" ;;
		esac
	}
	fresh
	run_copy
	[ "$rc" = 0 ] || { echo "$out" >&2; die "check -n: the unmodified scratch copy fails the check (positive control): nothing can be concluded"; }

	fresh
	f=$(cd "$work/core" && find src -name '*.c' | sort | sed -n 1p)
	[ -n "$f" ] || die "check -n: no core C file"
	grep -v '^WR_FILE_LICENCE_' "$work/core/$f" > "$work/x" && mv "$work/x" "$work/core/$f"
	expect_refused "a core file without its WR_FILE_LICENCE_ placeholder ($f)" "WR_FILE_LICENCE_MIT"

	fresh
	f=$(cd "$work/core" && find src -name '*.c' | sort | sed -n 1p)
	{ cat "$work/core/$f"; grep '^WR_FILE_LICENCE_' "$work/core/$f"; } > "$work/x"
	mv "$work/x" "$work/core/$f"
	expect_refused "a core file with the placeholder twice ($f)" "exactly one WR_FILE_LICENCE_MIT"

	fresh
	f=$(cd "$work/core" && find crush_ln -name '*.c' | sort | sed -n 1p)
	[ -z "$f" ] || { sed 's/^WR_FILE_LICENCE_LGPL21/WR_FILE_LICENCE_MIT/' "$work/core/$f" > "$work/x" && mv "$work/x" "$work/core/$f"
		expect_refused "the LGPL directory's file relabelled MIT ($f)" "must be WR_FILE_LICENCE_LGPL21"; }

	fresh
	f=$(cd "$work/core" && find include -name '*.h' | sort | sed -n 1p)
	sed '/^#ifndef/d' "$work/core/$f" > "$work/x" && mv "$work/x" "$work/core/$f"
	expect_refused "a core header without an include guard ($f)" "no include guard"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	sed 's/^FILE_SECBOOT ( FORBIDDEN );/FILE_SECBOOT ( PERMITTED );/' "$work/ipxe/src/$g" > "$work/x" && mv "$work/x" "$work/ipxe/src/$g"
	expect_refused "a glue file marked PERMITTED ($g)" "needs the security review"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	grep -v '^FILE_SECBOOT' "$work/ipxe/src/$g" > "$work/x" && mv "$work/x" "$work/ipxe/src/$g"
	expect_refused "a glue file with no FILE_SECBOOT declaration ($g)" "missing FILE_SECBOOT ( FORBIDDEN )"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	grep -v '^FILE_LICENCE' "$work/ipxe/src/$g" > "$work/x" && mv "$work/x" "$work/ipxe/src/$g"
	expect_refused "a glue file with no FILE_LICENCE declaration ($g)" "missing FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	grep -v 'SPDX-License-Identifier' "$work/ipxe/src/$g" > "$work/x" && mv "$work/x" "$work/ipxe/src/$g"
	expect_refused "a glue file with no SPDX-License-Identifier line ($g)" "missing SPDX-License-Identifier: GPL-2.0-or-later OR LicenseRef-UBDL"

	fresh
	g=$(cd "$work/ipxe/tests" && ls rbd_*.c | sort | sed -n 1p)
	sed 's/rbd_[a-z0-9]*_test/rbd_seeded_test/g' "$work/ipxe/tests/$g" > "$work/ipxe/tests/rbd_seeded_test.c"
	expect_refused "a test file that patch 0003 does not wire in" "not wired in"

	fresh
	g=$(cd "$work/ipxe/patches" && ls ./*.patch | sort | tail -1 | sed 's|^\./||')
	awk '!d && /^@@ / && $3 ~ /^\+[0-9]+,[0-9]+$/ { split($3, q, ","); $3 = q[1] "," (q[2] - 1); d = 1 } { print }' "$work/ipxe/patches/$g" > "$work/x" && mv "$work/x" "$work/ipxe/patches/$g"
	expect_refused "a patch whose hunk header counts are too small ($g)" "hunk"

	fresh
	mkdir -p "$work/.github/workflows"
	printf 'jobs:\n  a:\n    steps:\n      - run: ipxe/tools/build.sh frobnicate x\n' > "$work/.github/workflows/ipxe.yml"
	expect_refused "a workflow step that calls a subcommand build.sh does not have" "not a subcommand"

	fresh
	mkdir -p "$work/.github/workflows"
	printf 'jobs:\n  a:\n    steps:\n      - run: |\n          make -C build/ipxe/src bin/x\n' > "$work/.github/workflows/ipxe.yml"
	expect_refused "a workflow step that runs make by hand" "runs make by hand"

	fresh
	: > "$work/ipxe/PINNED"
	expect_refused "an empty ipxe/PINNED" "PINNED"

	# the other spellings of the same mistakes (a check for the one spelling that exists today passes the next one)
	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	sed 's/^FILE_SECBOOT ( FORBIDDEN );/FILE_SECBOOT(PERMITTED);/' "$work/ipxe/src/$g" > "$work/x" && mv "$work/x" "$work/ipxe/src/$g"
	expect_refused "a glue file with FILE_SECBOOT(PERMITTED); (no spaces) ($g)" "needs the security review"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	printf 'FILE_SECBOOT ( PERMITTED );\n' >> "$work/ipxe/src/$g"
	expect_refused "a glue file with a second FILE_SECBOOT line, PERMITTED, beside the FORBIDDEN one ($g)" "needs the security review"

	fresh
	g=$(cd "$work/ipxe/src" && ls ./*.c | sort | sed -n 1p | sed 's|^\./||')
	printf 'FILE_LICENCE ( PUBLIC_DOMAIN );\n' >> "$work/ipxe/src/$g"
	expect_refused "a glue file with a second, other FILE_LICENCE line ($g)" "a FILE_LICENCE line other than"

	fresh
	g=$(cd "$work/ipxe/tests" && ls rbd_*.c | sort | sed -n 1p)
	sed 's/^FILE_SECBOOT ( FORBIDDEN );/FILE_SECBOOT ( PERMITTED );/' "$work/ipxe/tests/$g" > "$work/x" && mv "$work/x" "$work/ipxe/tests/$g"
	expect_refused "a test file marked PERMITTED ($g)" "needs the security review"

	fresh
	f=$(cd "$work/core" && find src -name '*.c' | sort | sed -n 1p)
	printf 'FILE_SECBOOT ( PERMITTED );\n' >> "$work/core/$f"
	expect_refused "a core file with an iPXE FILE_SECBOOT of its own ($f)" "free of iPXE macros"

	fresh
	printf '%s %s\n' 'x=$(printf a |' 'grep -q a)' >> "$work/ipxe/tools/build.sh"
	expect_refused "a pipeline ending in grep -q in this script" "grep -q"

	# the workflow must keep calling every gate
	fresh
	if [ -f "$work/.github/workflows/ipxe.yml" ]; then
		grep -v 'bin/ipxe\.iso' "$work/.github/workflows/ipxe.yml" > "$work/x" && mv "$work/x" "$work/.github/workflows/ipxe.yml"
		expect_refused "a workflow that no longer builds bin/ipxe.iso" "no longer runs 'bin/ipxe.iso'"
		fresh
		grep -v 'build\.sh secboot -n' "$work/.github/workflows/ipxe.yml" > "$work/x" && mv "$work/x" "$work/.github/workflows/ipxe.yml"
		expect_refused "a workflow that no longer runs the Secure Boot scan control" "no longer runs 'build.sh secboot -n'"
		fresh
		sed 's/^\([[:space:]]*\)#\(.*\)build\.sh check -n/\1#\2build.sh check -n/; s/run: ipxe\/tools\/build\.sh check -n/run: echo skipped check -n/' "$work/.github/workflows/ipxe.yml" > "$work/x" && mv "$work/x" "$work/.github/workflows/ipxe.yml"
		expect_refused "a workflow whose only call of check -n became an echo" "no longer runs 'build.sh check -n'"
	fi

	# ---- the checks that run after a build, end to end on stand-in inputs -------------------------------------------------
	# "licence", "verify" and the test-log check are only reached after a long build, so a fault in them would show on the first
	# bad image, not before. Each runs here on canned inputs (no iPXE tree, no compiler, no make of iPXE), a good one that must be
	# accepted and bad ones that must be refused with the message that names the fault.
	local me="$HERE/build.sh" fake="$tmp/fake" log
	rm -rf "${work:?}"
	mkdir -p "$fake/src"
	printf '%s\n%s\n%s\n' "ipxe 0" "fake" "" > "$fake/$MARK"

	# licence: make is replaced by a Makefile whose <target>.licence prints a canned verdict (a tab starts the recipe line)
	printf '%%.licence:\n\t@cat "%s"\n' "$tmp/canned" > "$fake/src/Makefile"
	ctl_licence() { # $1 = name, $2 = canned output, $3 = "ok" or the substring of the refusal
		printf '%b' "$2" > "$tmp/canned"
		rc=0; out=$(bash "$me" licence -o "$fake" t 2>&1) || rc=$?
		if [ "$3" = ok ]; then
			[ "$rc" = 0 ] || { echo "$out" >&2; die "check -n: the licence check refused a good verdict ($1)"; }
		else
			[ "$rc" != 0 ] || die "check -n: the licence check ACCEPTED a bad verdict ($1)"
			case $out in *"$3"*) ;; *) echo "$out" >&2; die "check -n: the licence check refused ($1), but not with '$3'" ;; esac
		fi
		n=$((n + 1)); note "check -n: licence verdict as it must be: $1"
	}
	ctl_licence "the expected verdict" "GPL version 2 (or, at your option, any later version) subsumes MIT/X11/Xorg Licence\nThe overall licence for this file is:\n  $EXPECTED_LICENCE\n" ok
	ctl_licence "GPL version 2 only, after a header whose line above says 'subsumes ... later version'" "GPL version 2 (or, at your option, any later version) subsumes MIT/X11/Xorg Licence\nThe overall licence for this file is:\n  GPL version 2 only\n" "the overall licence is now"
	ctl_licence "UBDL" "The overall licence for this file is:\n  GPL version 2 (or, at your option, any later version) or Unmodified Binary Distribution Licence\n" "the overall licence is now"
	ctl_licence "no verdict at all" "nothing to see\n" "expected one 'overall licence' verdict"
	ctl_licence "two verdicts" "The overall licence for this file is:\n  $EXPECTED_LICENCE\nThe overall licence for this file is:\n  $EXPECTED_LICENCE\n" "expected one 'overall licence' verdict"

	# verify: a fake image and link map
	mkdir -p "$fake/src/bin"
	{ printf 'MZ\000\000rbd\000\000rbd: %s (stand-in)\000' "$VERIFY_CONSOLE_LINE"; } > "$fake/src/bin/t.efi"
	map_good() { for o in $VERIFY_OBJECTS; do printf ' .text  0x1  0x2 bin/blib.a(%s.o)\n' "$o"; done; }
	ctl_verify() { # $1 = name, $2 = "ok" or the substring of the refusal
		rc=0; out=$(bash "$me" verify -o "$fake" bin/t.efi 2>&1) || rc=$?
		if [ "$2" = ok ]; then
			[ "$rc" = 0 ] || { echo "$out" >&2; die "check -n: verify refused a good image ($1)"; }
		else
			[ "$rc" != 0 ] || die "check -n: verify ACCEPTED a bad image ($1)"
			case $out in *"$2"*) ;; *) echo "$out" >&2; die "check -n: verify refused ($1), but not with '$2'" ;; esac
		fi
		n=$((n + 1)); note "check -n: verify as it must be: $1"
	}
	map_good > "$fake/src/bin/t.efi.tmp.map"
	ctl_verify "driver in the map, console line and scheme in the image" ok
	map_good | sed '$d' > "$fake/src/bin/t.efi.tmp.map"
	ctl_verify "an object of the driver missing from the link map" "the driver is not linked"
	{ map_good; printf ' .text  0x1  0x2 bin/blib.a(rbd_selftest.o)\n'; } > "$fake/src/bin/t.efi.tmp.map"
	ctl_verify "a self-test object in the link map" "a self-test object is linked in"
	map_good > "$fake/src/bin/t.efi.tmp.map"
	printf 'MZ\000\000rbd\000\000' > "$fake/src/bin/t.efi"
	ctl_verify "the console line missing from the image" "the console line"
	printf 'MZ\000\000rbd: %s\000' "$VERIFY_CONSOLE_LINE" > "$fake/src/bin/t.efi"
	ctl_verify "the scheme string missing from the image" "the URI scheme string"
	printf 'MZ\000\000rbd\000\000rbd: %s\000rbd_selftest\000' "$VERIFY_CONSOLE_LINE" > "$fake/src/bin/t.efi"
	ctl_verify "the text of a self-test in the image" "the text of a self-test is in the image"
	rm -f "$fake/src/bin/t.efi.tmp.map"
	printf 'MZ\000\000rbd\000\000rbd: %s\000' "$VERIFY_CONSOLE_LINE" > "$fake/src/bin/t.efi"
	ctl_verify "no link map at all" "no link map"

	# the verification of a self-test run: a good log, then one fault at a time
	log="$tmp/test.log"
	tests_ok() { # prints a good log (every set of ipxe/tests passed)
		local t
		for t in "$IPXE_DIR"/tests/*.c; do [ -f "$t" ] || continue; printf 'OK: "%s" 12 tests passed\r\n' "$(basename "$t" .c)"; done
		printf 'OK: all 12345 tests passed\r\n'
	}
	ctl_testlog() { # $1 = name, $2 = exit status, $3 = "ok" or the substring of the refusal; the log is $log
		rc=0; out=$(verify_test_log "$log" "$2" 2>&1) || rc=$?
		if [ "$3" = ok ]; then
			[ "$rc" = 0 ] || { echo "$out" >&2; die "check -n: the test-log check refused a good run ($1)"; }
		else
			[ "$rc" != 0 ] || die "check -n: the test-log check ACCEPTED a bad run ($1)"
			case $out in *"$3"*) ;; *) echo "$out" >&2; die "check -n: the test-log check refused ($1), but not with '$3'" ;; esac
		fi
		n=$((n + 1)); note "check -n: self-test log as it must be: $1"
	}
	tests_ok > "$log"
	ctl_testlog "a good run" 0 ok
	ctl_testlog "a good log, exit status 3" 3 "exited with status 3"
	tests_ok | grep -v 'all 12345' > "$log"
	ctl_testlog "no 'all N tests passed' line" 0 "no 'OK: all N tests passed' line"
	{ tests_ok; printf 'FAILURE: "x" test failed at y.c line 1\r\n'; } > "$log"
	ctl_testlog "a FAILURE line" 0 "failures reported"
	tests_ok | sed '1d' > "$log"
	ctl_testlog "the first test set did not run" 0 "did not run and pass"
	tests_ok | sed '1s/12 tests/0 tests/' > "$log"
	ctl_testlog "a test set with no tests" 0 "did not run and pass"

	trap - EXIT
	rm -rf "${tmp:?}"
	note "check -n: all $n seeded mistakes and stand-in inputs were judged as they must be"
}

cmd_check() {
	local neg=0
	while [ $# -gt 0 ]; do
		case $1 in
		-n|--negative-control) neg=1; shift ;;
		*) die "check: unknown argument $1" ;;
		esac
	done
	if [ "$neg" = 1 ]; then cmd_check_negative; return; fi
	check_all || exit 1
	note "check: ok"
}

# ---- prepare -------------------------------------------------------------------------------------------------------------

# Tag one imported core file. $1 = source, $2 = destination, $3 = licence tag.
import_core_file() {
	local src=$1 dst=$2 tag=$3
	case "$src" in
	*.c)
		awk -v tag="$tag" '
			/^WR_FILE_LICENCE_(MIT|LGPL21)[ \t]*$/ { print tag; print "FILE_SECBOOT ( FORBIDDEN );"; n++; next }
			{ print }
			END { if (n != 1) exit 3 }' "$src" > "$dst" || die "core file without exactly one WR_FILE_LICENCE_* placeholder line: $src"
		;;
	*.h)
		awk -v tag="$tag" -v cfg="$([ "$(basename "$src")" = wr_port.h ] && echo 1 || echo 0)" '
			state == 0 && /^#ifndef[ \t]+[A-Za-z0-9_]+[ \t]*$/ { guard = $2; state = 1; print; next }
			state == 1 && $1 == "#define" && $2 == guard { print; print tag; print "FILE_SECBOOT ( FORBIDDEN );"; if (cfg == 1) print "#define WR_HOST_CONFIG_HEADER \"rbd_core_cfg.h\""; state = 2; next }
			{ print }
			END { if (state != 2) exit 3 }' "$src" > "$dst" || die "core header without an include guard (#ifndef X / #define X): $src"
		;;
	*.inc)
		# a data file included inside an initialiser (the CRC tables): no macro can go in, but iPXE's check only greps for
		# the line, so it goes into a comment at the top
		{ printf '/*\n%s\nFILE_SECBOOT ( FORBIDDEN );\n*/\n' "$tag"; cat "$src"; } > "$dst"
		;;
	esac
}

# Export the pinned iPXE tree to OUT (empty or new). $1 = SRC, $2 = OUT, $3 = the pinned revision. "a git checkout" means SRC is the
# top of its own work tree: a plain directory inside some other repository (an unpacked tarball under this one) would otherwise
# answer with that repository's HEAD. A git checkout must be AT the pinned revision and is exported with git archive (committed
# files only); anything else is copied as is, with a warning.
export_pinned() {
	local src=$1 out=$2 rev=$3 top have
	top=$(git -C "$src" rev-parse --show-toplevel 2>/dev/null || true)
	if [ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$(cd "$src" && pwd -P)" ]; then
		have=$(git -C "$src" rev-parse HEAD)
		[ "$have" = "$rev" ] || die "iPXE at $src is $have, the driver is pinned to $rev (ipxe/PINNED)"
		git -C "$src" archive --format=tar HEAD | tar -x -C "$out"
	else
		note "warning: $src is not a git checkout; copying it as is (revision $rev not verifiable)"
		cp -R "$src"/. "$out"/
	fi
}

cmd_prepare() {
	local src="$REPO/third_party/ipxe" out="$REPO/build/ipxe" rev f base tag dst stamp dup
	while [ $# -gt 0 ]; do
		case $1 in
		-s) src=$2; shift 2 ;;
		-o) out=$2; shift 2 ;;
		*) die "prepare: unknown argument $1" ;;
		esac
	done
	check_all || exit 1
	rev=$(pinned_rev)
	[ -e "$src/src/Makefile" ] || die "no iPXE tree at $src (git submodule update --init third_party/ipxe)"
	if [ -e "$out" ]; then
		[ -f "$out/$MARK" ] || die "$out exists and was not prepared by this script; refusing to touch it"
		rm -rf "${out:?}"
	fi
	# the stamp describes the sources as they are NOW (taken before anything is copied: a file edited while this runs makes the
	# copy look stale next time, never fresh), and the marker goes in first, as "incomplete": a prepare that is interrupted
	# (a full disk, a failed patch, Ctrl-C) leaves a directory this script still recognises as its own, so the next run
	# prepares it again and "clean" can delete it, instead of "refusing to touch it" for ever
	stamp=$(source_stamp)
	mkdir -p "$out"
	printf '%s\n%s\n%s\n' "ipxe $rev" "incomplete" "$src" > "$out/$MARK"
	export_pinned "$src" "$out" "$rev"
	for f in "$IPXE_DIR"/patches/*.patch; do
		[ -f "$f" ] || continue
		note "applying $(basename "$f")"
		# -F0: no fuzz. The tree is pinned, so a hunk either applies exactly or the pin and the patch have drifted apart
		patch -p1 -F0 --no-backup-if-mismatch -s -d "$out" < "$f" || die "patch failed: $f"
	done
	mkdir -p "$out/src/winrbd"
	for f in "$IPXE_DIR"/src/*; do
		[ -f "$f" ] || continue
		cp "$f" "$out/src/winrbd/$(basename "$f")"
	done
	# the core: sources from core/sources.txt (generated list), every header and include file, imported flat
	( cd "$REPO/core" && sh tools/gen_sources.sh --check ) || die "core/sources.txt is stale (core/tools/gen_sources.sh)"
	for f in $(cat "$REPO/core/sources.txt") $(cd "$REPO/core" && find include src crush_ln \( -name '*.h' -o -name '*.inc' \) | sort); do
		base=$(basename "$f")
		dst="$out/src/winrbd/$base"
		[ ! -e "$dst" ] || die "core file name collides with an existing imported file: $f"
		case "$f" in
		crush_ln/*) tag='FILE_LICENCE ( GPL2_OR_LATER );' ;;
		*) tag='FILE_LICENCE ( MIT );' ;;
		esac
		import_core_file "$REPO/core/$f" "$dst" "$tag"
	done
	# the self-tests, flat next to iPXE's own (patch 0003 requires them from src/tests/tests.c)
	for f in "$IPXE_DIR"/tests/*.c; do
		[ -f "$f" ] || continue
		dst="$out/src/tests/$(basename "$f")"
		[ ! -e "$dst" ] || die "test file name collides with an iPXE test: $f"
		cp "$f" "$dst"
	done
	# iPXE names an object after the BASENAME of its source and puts every object of every directory into one bin/: a glue, core or
	# test file with the name of a source of iPXE would be two sources for one object (one of them silently not built, or a
	# duplicate-symbol link error far from the cause). The lists are compared here, on the real tree.
	dup=$(comm -12 \
		<( { ls "$out"/src/winrbd/*.c "$out"/src/tests/rbd_*.c; } | sed 's|.*/||; s|\.c$||' | sort -u ) \
		<( find "$out/src" \( -name '*.c' -o -name '*.S' \) ! -path "$out/src/winrbd/*" ! -path "$out/src/tests/rbd_*" | sed 's|.*/||; s|\.[cS]$||' | sort -u ))
	[ -z "$dup" ] || die "an imported file has the object name of a source of iPXE itself: $(echo $dup)"
	# line 1: the revision; line 2: a checksum of everything that went in (ensure_prepared re-prepares a copy that does not match
	# the tree any more); line 3: where the iPXE tree came from
	printf '%s\n%s\n%s\n' "ipxe $rev" "$stamp" "$src" > "$out/$MARK"
	note "prepared $out (iPXE $rev, $(ls "$out/src/winrbd" | wc -l | tr -d ' ') files in src/winrbd, $(ls "$IPXE_DIR"/tests/*.c 2>/dev/null | wc -l | tr -d ' ') test files)"
}

# A checksum of everything that goes into a prepared copy besides the iPXE tree: the revision, the patches, the glue, the
# self-tests and the core (the files, not the names or times).
source_stamp() {
	local f
	{
		# names and contents (a line moved from one file to another changes the stamp), and this script: the import
		# transform in it decides what the imported core and glue look like
		for f in $( cd "$IPXE_DIR" && find PINNED patches src tests tools -type f \( -name PINNED -o -name '*.patch' -o -name '*.c' -o -name '*.h' -o -name 'build.sh' \) | sort ); do
			printf '%s\n' "ipxe/$f"
			cat "$IPXE_DIR/$f"
		done
		for f in sources.txt $( cd "$REPO/core" && find include src crush_ln -type f | sort ); do
			printf '%s\n' "core/$f"
			cat "$REPO/core/$f"
		done
	} | cksum
}

# Prepare OUT unless it is already prepared from the current sources (a copy that is stale is prepared again, which also
# rebuilds it from scratch: iPXE's make would not notice a file that was replaced behind its back).
ensure_prepared() {
	local out=$1 src
	if [ -f "$out/$MARK" ] && [ "$(sed -n 2p "$out/$MARK")" = "$(source_stamp)" ]; then
		return 0
	fi
	if [ -f "$out/$MARK" ]; then
		note "$out is not prepared from the current sources: preparing it again"
		src=$(sed -n 3p "$out/$MARK")
		[ -z "$src" ] || { cmd_prepare -s "$src" -o "$out"; return; }
	fi
	cmd_prepare -o "$out"
}

# ---- build ---------------------------------------------------------------------------------------------------------------

run_make() {
	local out=$1 jobs=${IPXE_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
	shift
	if [ -n "${IPXE_HOST_LZMA_PREFIX:-}" ]; then
		export CPATH="$IPXE_HOST_LZMA_PREFIX/include${CPATH:+:$CPATH}"
		export LIBRARY_PATH="$IPXE_HOST_LZMA_PREFIX/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
		export LD_LIBRARY_PATH="$IPXE_HOST_LZMA_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
	fi
	# shellcheck disable=SC2086
	( cd "$out/src" && ${IPXE_NICE:-} make -j"$jobs" "$@" )
}

cmd_build() {
	local out="$REPO/build/ipxe" embed="" debug="" extra=() targets=()
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		-j) IPXE_JOBS=$2; export IPXE_JOBS; shift 2 ;;
		-e) embed=$2; shift 2 ;;
		-d) debug=$2; shift 2 ;;
		--) shift; extra=("$@"); break ;;
		-*) die "build: unknown option $1" ;;
		*) targets+=("$1"); shift ;;
		esac
	done
	[ ${#targets[@]} -gt 0 ] || die "build: no TARGET given (for example bin-x86_64-efi/ipxe.efi)"
	ensure_prepared "$out"
	if [ -n "$embed" ]; then
		[ -f "$embed" ] || die "build: no such script: $embed"
		# the objects and the image of this copy hold the script in clear: no other user of a shared build box reads them
		chmod 700 "$out" || die "build: cannot restrict $out to its owner"
		note "the script $embed is embedded in the image as it is (a key in it is readable from the image): $out is now private to its owner; keep the image private, and delete $out (build.sh clean) when done"
		extra+=("EMBED=$(cd "$(dirname "$embed")" && pwd)/$(basename "$embed")")
	fi
	[ -z "$debug" ] || extra+=("DEBUG=$debug")
	run_make "$out" ${extra[@]+"${extra[@]}"} "${targets[@]}"
}

# What iPXE's own licence check must conclude for a build of the driver (the line after "The overall licence for this file is:").
# The binary links the CRUSH log tables (core/crush_ln, LGPL-2.1, tagged GPL2_OR_LATER on import), everything else is MIT or
# GPL-2-or-later-or-UBDL, and the reduction ends at "GPL version 2 (or, at your option, any later version)" (design section 13).
# A different verdict is a visible event: a new file under another licence, a changed tag, a different iPXE. It is not "fixed" by
# editing this line; the design's section 13 and LICENSE are updated in the same change, deliberately.
EXPECTED_LICENCE="GPL version 2 (or, at your option, any later version)"

# The verdict line(s) of an output of "make <target>.licence", one per "overall licence" header. The line right after the header is
# compared whole: the "... subsumes ..." lines above it contain the same words, so a search over the whole output would pass a
# result of "GPL version 2 only" too.
licence_verdict() {
	awk '/The overall licence for this file is:/ { want = 1; next } want { sub(/^[ \t]+/, ""); sub(/[ \t\r]+$/, ""); print; want = 0 }' "$1"
}

cmd_licence() {
	local out="$REPO/build/ipxe" t targets=() log v n rc bad=0
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		-*) die "licence: unknown option $1" ;;
		*) targets+=("$1"); shift ;;
		esac
	done
	[ ${#targets[@]} -gt 0 ] || die "licence: no TARGET given"
	[ -f "$out/$MARK" ] || die "licence: $out is not prepared (run build first: the licence check needs the intermediate objects)"
	log="$out/licence.log"
	for t in "${targets[@]}"; do
		rc=0
		run_make "$out" "$t.licence" > "$log" 2>&1 || rc=$?
		cat "$log"
		if [ "$rc" != 0 ]; then
			echo "licence: iPXE's licence check of $t failed (exit $rc)" >&2; bad=1; continue
		fi
		v=$(licence_verdict "$log")
		n=$(printf '%s\n' "$v" | grep -c . || true)
		if [ "$n" != 1 ]; then
			echo "licence: $t: expected one 'overall licence' verdict, found $n" >&2; bad=1
		elif [ "$v" != "$EXPECTED_LICENCE" ]; then
			echo "licence: $t: the overall licence is now '$v', expected '$EXPECTED_LICENCE'. A change of the result's licence must be deliberate: update EXPECTED_LICENCE together with docs/design/ipxe-driver.md section 13 and LICENSE" >&2; bad=1
		else
			note "licence: $t: $v"
		fi
	done
	[ "$bad" = 0 ] || die "licence: FAILED"
}

# ---- verify: the driver is in the images, the self-tests are not -----------------------------------------------------------

# The glue and core objects that must appear in the link map of every image (one of each side; the rest follows from them, and
# the console line below is the look at the bytes) and the text of the console line the EFI image must carry. Both are looked up
# in the sources first: a rename there fails here with a message that says what to update, instead of a silent miss.
VERIFY_OBJECTS="rbd_uri rbd_block wri_rbd"
VERIFY_CONSOLE_LINE="key material must not be part of the URI"

# $1 = out, $2 = target. Prints what is wrong; non-zero if anything is.
verify_image() {
	local out=$1 t=$2 f m maps o bad=0 nobj=0 nmaps=0 dir
	f="$out/src/$t"
	[ -s "$f" ] || { echo "$t: not built ($f)"; return 1; }
	dir=$(dirname "$f")
	# an image iPXE links itself leaves its link map next to it (<image>.tmp.map); bin/ipxe.usb and bin/ipxe.iso are made from
	# other images (ipxe.hd, ipxe.lkrn), so for those every map in the directory is looked at: all of them must hold the driver
	if [ -f "$f.tmp.map" ]; then maps="$f.tmp.map"; else maps=$(ls "$dir"/*.tmp.map 2>/dev/null || true); fi
	[ -n "$maps" ] || { echo "$t: no link map (*.tmp.map) next to it: iPXE changed its file names?"; return 1; }
	for m in $maps; do
		nmaps=$((nmaps + 1))
		for o in $VERIFY_OBJECTS; do
			grep -Fq "blib.a($o.o)" "$m" || { echo "$t: the driver is not linked: $o.o is not in $(basename "$m")"; bad=1; }
		done
		if grep -Eq 'blib\.a\((rbd_[A-Za-z0-9_]*_test|rbd_selftest|tests)\.o\)' "$m"; then
			echo "$t: a self-test object is linked in ($(basename "$m"))"; bad=1
		fi
		nobj=$(grep -Eo 'blib\.a\((rbd_|wr_|wri_)[A-Za-z0-9_]*\.o\)' "$m" | sort -u | wc -l | tr -d ' ')
	done
	case $t in
	*.efi)
		# not compressed: the bytes can be searched. Each look has its positive control (the driver's text IS there), so that an
		# empty search for the self-tests means something. The scheme is the NUL-terminated string "rbd" of the URI opener.
		grep -Fq "$VERIFY_CONSOLE_LINE" "$IPXE_DIR/src/rbd_uri.c" || { echo "build.sh: VERIFY_CONSOLE_LINE '$VERIFY_CONSOLE_LINE' is not in ipxe/src/rbd_uri.c any more: update the check"; bad=1; }
		[ "$(LC_ALL=C grep -a -c -F "rbd: $VERIFY_CONSOLE_LINE" "$f" || true)" -ge 1 ] || { echo "$t: the console line 'rbd: $VERIFY_CONSOLE_LINE' is not in the image"; bad=1; }
		[ "$(LC_ALL=C tr '\000' '\n' < "$f" | grep -c -x rbd || true)" -ge 1 ] || { echo "$t: the URI scheme string \"rbd\" is not in the image"; bad=1; }
		[ "$(LC_ALL=C grep -a -c 'rbd_selftest' "$f" || true)" = 0 ] || { echo "$t: the text of a self-test is in the image"; bad=1; }
		;;
	esac
	[ "$bad" != 0 ] || note "verify: $t: driver linked ($nobj driver objects in $nmaps link map(s)), no self-test$(case $t in *.efi) echo ', scheme and console line in the image' ;; esac)"
	return $bad
}

cmd_verify() {
	local out="$REPO/build/ipxe" t targets=() bad=0
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		-*) die "verify: unknown option $1" ;;
		*) targets+=("$1"); shift ;;
		esac
	done
	[ ${#targets[@]} -gt 0 ] || die "verify: no TARGET given"
	[ -f "$out/$MARK" ] || die "verify: $out is not prepared (run build first)"
	for t in "${targets[@]}"; do verify_image "$out" "$t" || bad=1; done
	[ "$bad" = 0 ] || die "verify: FAILED"
}

# ---- secboot ---------------------------------------------------------------------------------------------------------------

SB_TARGET=bin-x86_64-efi-sb/snponly.efi
SB_REFUSAL="not permitted to be signed for UEFI Secure Boot"

# Which of the glue and core objects compiled for the Secure Boot platform are not FORBIDDEN. iPXE's verdict is one for the whole
# image: it is refused as soon as ONE object is forbidden, so one file marked PERMITTED (or with no declaration: compiler.h gives
# every file "permitted" by default, and only an explicit FILE_SECBOOT ( FORBIDDEN ) adds the symbol __secboot__forbidden__<object>)
# would not change the refusal. So the objects are looked at one by one. (The symbol is named after the object that INCLUDES the
# declaration, so a .c file that includes a FORBIDDEN header, which every imported header is, is FORBIDDEN whatever its own lines say:
# the scan reads what the Secure Boot build sees; the declaration of the .c file itself is what "check" enforces.) $1 = out, $2... = base names (default: every .c of
# src/winrbd). Prints "not FORBIDDEN: <file>" per object that is not, "no object: <file>" for one that was not compiled; sets
# SB_SEEN to the number of objects looked at; non-zero if anything is wrong.
secboot_scan() {
	local out=$1 c b o bad=0 names=()
	shift
	if [ $# -gt 0 ]; then names=("$@"); else for c in "$out"/src/winrbd/*.c; do names+=("$(basename "$c" .c)"); done; fi
	SB_SEEN=0
	for b in ${names[@]+"${names[@]}"}; do
		o="$out/src/$(dirname "$SB_TARGET")/$b.o"
		if [ ! -f "$o" ]; then echo "no object: $b.c (its Secure Boot object $o was not compiled)"; bad=1; continue; fi
		SB_SEEN=$((SB_SEEN + 1))
		# (grep -c, not -q: with pipefail, grep -q closing the pipe early can make nm fail with SIGPIPE and the pipeline look false)
		[ "$(nm "$o" | grep -c ' __secboot__forbidden__' || true)" -ge 1 ] || { echo "not FORBIDDEN: $b.c"; bad=1; }
	done
	[ "$SB_SEEN" -gt 0 ] || { echo "no object looked at: the scan proves nothing"; bad=1; }
	return $bad
}

cmd_secboot() {
	local out="$REPO/build/ipxe" mode=main log rc=0 res o b f
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		-j) IPXE_JOBS=$2; export IPXE_JOBS; shift 2 ;;
		-n|--negative-control) mode=neg; shift ;;
		-p|--pristine-control) mode=pristine; shift ;;
		*) die "secboot: unknown argument $1" ;;
		esac
	done
	case $mode in
	main)
		ensure_prepared "$out"
		log="$out/secboot.log"
		run_make "$out" "$SB_TARGET" > "$log" 2>&1 || rc=$?
		[ "$rc" != 0 ] || die "secboot: the Secure Boot build $SB_TARGET SUCCEEDED: nothing of the driver is marked FILE_SECBOOT ( FORBIDDEN )"
		if ! grep -q "$SB_REFUSAL" "$log"; then
			tail -n 20 "$log" >&2
			die "secboot: the Secure Boot build failed (exit $rc), but not with '$SB_REFUSAL': for another reason (see above)"
		fi
		[ ! -e "$out/src/$SB_TARGET" ] || die "secboot: the refused build left a binary behind: $out/src/$SB_TARGET"
		note "secboot: $SB_TARGET refused: $SB_REFUSAL"
		res=0
		secboot_scan "$out" || res=1
		[ "$res" = 0 ] || die "secboot: the driver's objects are not all FORBIDDEN (see above)"
		note "secboot: all $SB_SEEN driver objects are FORBIDDEN"
		;;
	pristine)
		# control: the pinned tree as it is, no patch and no driver. If it were refused too, the refusal of the main check would not
		# be about the driver. Its own directory (a pristine export), deleted afterwards.
		o="$out-pristine"
		if [ -e "$o" ] && [ ! -f "$o/$MARK" ]; then die "$o exists and was not prepared by this script; refusing to touch it"; fi
		rm -rf "${o:?}"
		mkdir -p "$o"
		printf '%s\n%s\n%s\n' "ipxe $(pinned_rev)" "pristine" "" > "$o/$MARK"
		export_pinned "$REPO/third_party/ipxe" "$o" "$(pinned_rev)"
		log="$o/secboot.log"
		run_make "$o" "$SB_TARGET" > "$log" 2>&1 || rc=$?
		if [ "$rc" != 0 ] || [ ! -s "$o/src/$SB_TARGET" ]; then
			tail -n 20 "$log" >&2
			rm -rf "${o:?}"
			die "secboot -p: the PRISTINE iPXE tree does not build $SB_TARGET (exit $rc): the refusal of the main check proves nothing about the driver"
		fi
		rm -rf "${o:?}"
		note "secboot -p: the pristine tree builds $SB_TARGET: the refusal of the main check is the driver's"
		;;
	neg)
		# control for the object scan. An object is FORBIDDEN when the .c file OR any header it includes says so (the symbol carries the
		# name of the object that includes the declaration), and every imported header says so; so the copy loses the declaration in
		# the headers and in one glue file (it becomes PERMITTED, the default), while one other object is compiled BEFORE that from the
		# unchanged copy. Only these two objects are compiled (a full Secure Boot build is not needed: the scan reads objects). The
		# scan must pass the first and flag the second. Its own directory, deleted afterwards.
		o="$out-permitted"
		if [ -e "$o" ] && [ ! -f "$o/$MARK" ]; then die "$o exists and was not prepared by this script; refusing to touch it"; fi
		rm -rf "${o:?}"
		ensure_prepared "$o"
		b=rbd_uri
		grep -q '^FILE_SECBOOT ( FORBIDDEN );' "$o/src/winrbd/$b.c" || die "secboot -n: $b.c has no FILE_SECBOOT ( FORBIDDEN ) line to turn into PERMITTED"
		run_make "$o" "$(dirname "$SB_TARGET")/rbd_block.o" > "$o/secboot.log" 2>&1 ||
			{ tail -n 20 "$o/secboot.log" >&2; rm -rf "${o:?}"; die "secboot -n: the control object rbd_block.o did not compile"; }
		for f in "$o/src/winrbd/$b.c" "$o"/src/winrbd/*.h; do
			sed 's/^FILE_SECBOOT ( FORBIDDEN );/FILE_SECBOOT ( PERMITTED );/' "$f" > "$o/x" && mv "$o/x" "$f"
		done
		run_make "$o" "$(dirname "$SB_TARGET")/$b.o" > "$o/secboot.log" 2>&1 ||
			{ tail -n 20 "$o/secboot.log" >&2; rm -rf "${o:?}"; die "secboot -n: the seeded object $b.o did not compile"; }
		res=0
		secboot_scan "$o" rbd_block > "$o/scan-ok.txt" 2>&1 || res=1
		[ "$res" = 0 ] || { cat "$o/scan-ok.txt" >&2; rm -rf "${o:?}"; die "secboot -n: the scan flagged an untouched, FORBIDDEN object (rbd_block): it flags everything"; }
		secboot_scan "$o" "$b" > "$o/scan-bad.txt" 2>&1 || res=2
		if [ "$res" != 2 ] || ! grep -q "^not FORBIDDEN: $b\.c\$" "$o/scan-bad.txt"; then
			cat "$o/scan-bad.txt" >&2
			rm -rf "${o:?}"
			die "secboot -n: the scan did NOT flag $b.c, which is PERMITTED in the control copy: it does not see an object that is not FORBIDDEN"
		fi
		rm -rf "${o:?}"
		note "secboot -n: an object that is PERMITTED ($b.c) is flagged, an untouched one is not"
		;;
	esac
}

# Verify the output of a self-test run. $1 = log file, $2 = exit status of the program. Prints what is wrong; non-zero if anything is.
verify_test_log() {
	local log=$1 rc=$2 f base bad=0
	[ "$rc" = 0 ] || { echo "the test program exited with status $rc"; bad=1; }
	grep -q '^OK: all [1-9][0-9]* tests passed' "$log" || { echo "no 'OK: all N tests passed' line"; bad=1; }
	if grep -q 'FAILURE' "$log"; then echo "failures reported:"; grep 'FAILURE' "$log" | sed 's/^/    /'; bad=1; fi
	for f in "$IPXE_DIR"/tests/*.c; do
		[ -f "$f" ] || continue
		base=$(basename "$f" .c)
		grep -q "^OK: \"$base\" [1-9][0-9]* tests passed" "$log" || { echo "the test set \"$base\" did not run and pass (not wired in, or no tests)"; bad=1; }
	done
	return $bad
}

# Build the self-test program TARGET in OUT, run it from OUT/src, verify the run. $3...: extra make arguments.
run_selftests() {
	local out=$1 target=$2 log rc timeout_cmd=""
	shift 2
	ensure_prepared "$out"
	# (this function runs in "if" / "||" context, where set -e is off: check the build explicitly, never run a stale program)
	run_make "$out" "$@" "$target" || die "test: the build of $target failed (see above)"
	[ -x "$out/src/$target" ] || die "test: $out/src/$target was not built (is it a self-test program target, such as bin-x86_64-linux/tests.linux?)"
	command -v timeout >/dev/null 2>&1 && timeout_cmd="timeout ${IPXE_TEST_TIMEOUT:-900}"
	log="$out/test.log"
	rc=0
	# shellcheck disable=SC2086
	( cd "$out/src" && $timeout_cmd "./$target" ) > "$log" 2>&1 || rc=$?
	cat "$log"
	verify_test_log "$log" "$rc"
}

# After a "test -u" run: the UBSan flags must really have reached the compiler. iPXE's make does not tell, and a flag that
# silently did nothing would leave the "UBSan run" a plain run. In trap mode the checks are ud2 instructions; the glue and core
# objects of the test program must hold some (the plain build has none: checked by hand on the pinned tree). $1 = OUT of the
# UBSan copy, $2 = the test program target (its directory holds the objects).
check_ubsan_applied() {
	local out=$1 dir o n=0 c
	if ! command -v objdump >/dev/null 2>&1; then
		note "test -u: no objdump here, cannot confirm that the UBSan flags took effect"
		return 0
	fi
	dir="$out/src/$(dirname "$2")"
	for o in "$out"/src/winrbd/*.c; do
		[ -f "$dir/$(basename "$o" .c).o" ] || continue
		c=$(objdump -d "$dir/$(basename "$o" .c).o" | grep -c 'ud2' || true)
		n=$((n + c))
	done
	[ "$n" -gt 0 ] || die "test -u: no UBSan trap in any glue or core object of $dir: the flags did not take effect"
	note "test -u: $n UBSan traps in the glue and core objects (the flags took effect)"
}

# The UBSan flags of "test -u": every check of -fsanitize=undefined, in trap mode, EXCEPT the alignment check. iPXE's own inline
# memset() (arch/x86/include/bits/string.h) clears a constant-size region with a store of the widest type through a union pointer,
# which x86 allows at any address and which iPXE relies on everywhere. A core function that clears a uint8_t[4] with WR_MEMSET
# (wri_m2_tx_frame) therefore traps, although nothing is wrong: it was the first thing the first -u run found, and it ends the whole
# program. The alignment of the core's own accesses is checked where there is no iPXE inline in the way: the harness builds the core
# against libc under the full UBSan (ctest, every compiler and build type).
UBSAN_FLAGS="-fsanitize=undefined -fno-sanitize=alignment -fsanitize-undefined-trap-on-error"

cmd_test() {
	local out="$REPO/build/ipxe" target=bin-x86_64-linux/tests.linux neg=0 ubsan=0 extra=() f
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		-j) IPXE_JOBS=$2; export IPXE_JOBS; shift 2 ;;
		-n|--negative-control) neg=1; shift ;;
		-u|--ubsan) ubsan=1; shift ;;
		--) shift; extra=("$@"); break ;;
		-*) die "test: unknown option $1" ;;
		*) target=$1; shift ;;
		esac
	done
	if [ "$ubsan" = 1 ]; then
		# every glue, core and test object compiled with UBSan in trap mode (no runtime library: the iPXE link has no room for
		# one); a finding kills the program with SIGILL, which the verification reports. Its own copy: iPXE's make does not see a
		# changed CFLAGS_<object>, so an already built copy would keep its old objects.
		[ "$neg" = 0 ] || die "test: -u and -n do not combine"
		out="$out-ubsan"
		ensure_prepared "$out"
		for f in "$out"/src/winrbd/*.c "$out"/src/tests/rbd_*.c; do
			extra+=("CFLAGS_$(basename "$f" .c)=$UBSAN_FLAGS")
		done
	fi
	if [ "$neg" = 0 ]; then
		# prepared HERE, as a plain statement: inside the "||" below "set -e" is off for everything the function calls, and a
		# failed copy or extraction would go unnoticed
		ensure_prepared "$out"
		run_selftests "$out" "$target" ${extra[@]+"${extra[@]}"} || die "test: the self-tests FAILED (see above)"
		[ "$ubsan" = 0 ] || check_ubsan_applied "$out" "$target"
		note "test: ok"
		return 0
	fi
	# negative control: a copy with a deliberate failure; the check must fail on it, and for that reason, and the copy is removed
	local nout="$out-negctl" res=0
	[ -f "$IPXE_DIR/tests/rbd_selftest.c" ] || die "test -n: ipxe/tests/rbd_selftest.c (which holds the deliberate failure) is missing"
	grep -q RBD_SELFTEST_NEGATIVE_CONTROL "$IPXE_DIR/tests/rbd_selftest.c" || die "test -n: rbd_selftest.c has no RBD_SELFTEST_NEGATIVE_CONTROL"
	if [ -e "$nout" ] && [ ! -f "$nout/$MARK" ]; then die "$nout exists and was not prepared by this script; refusing to touch it"; fi
	rm -rf "${nout:?}"
	ensure_prepared "$nout"
	if run_selftests "$nout" "$target" CFLAGS_rbd_selftest=-DRBD_SELFTEST_NEGATIVE_CONTROL; then
		res=1
	fi
	# The check failed. That is only the proof if it failed BECAUSE of the deliberate assertion: a build that dies, a program that
	# crashes or a missing summary line would "fail the check" too and prove nothing. The run must report exactly one failed
	# assertion, in rbd_selftest.c, and one failed test in the set "rbd_selftest" (and no other set).
	if [ "$res" = 0 ]; then
		# (iPXE's Linux console writes CR LF: the CRs are dropped before the patterns, which end in $)
		if [ "$(tr -d '\r' < "$nout/test.log" | grep -c '^FAILURE: "rbd_selftest" test failed at .*rbd_selftest\.c line ' || true)" != 1 ] ||
		   [ "$(tr -d '\r' < "$nout/test.log" | grep -c '^FAILURE: "rbd_selftest" 1 of [1-9][0-9]* tests failed$' || true)" != 1 ] ||
		   [ "$(tr -d '\r' < "$nout/test.log" | grep -c '^FAILURE: ' || true)" != 3 ]; then
			res=2
		fi
	fi
	rm -rf "${nout:?}"
	[ "$res" != 1 ] || die "test -n: the check PASSED a run with a deliberate failure: the self-test machinery does not see failures"
	[ "$res" != 2 ] || die "test -n: the check failed, but not with exactly the deliberate failure of rbd_selftest.c (one assertion, one set, one summary line): it proves nothing"
	note "test -n: the deliberate failure was detected (the check failed, as it must)"
}

cmd_clean() {
	local out="$REPO/build/ipxe"
	while [ $# -gt 0 ]; do
		case $1 in
		-o) out=$2; shift 2 ;;
		*) die "clean: unknown argument $1" ;;
		esac
	done
	[ -f "$out/$MARK" ] || die "$out was not prepared by this script; refusing to delete it"
	rm -rf "${out:?}"
}

[ $# -gt 0 ] || { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2; }
sub=$1
shift
case $sub in
prepare) cmd_prepare "$@" ;;
build) cmd_build "$@" ;;
licence) cmd_licence "$@" ;;
verify) cmd_verify "$@" ;;
secboot) cmd_secboot "$@" ;;
test) cmd_test "$@" ;;
check) cmd_check "$@" ;;
clean) cmd_clean "$@" ;;
*) die "unknown command $sub (prepare, build, licence, verify, secboot, test, check, clean)" ;;
esac
