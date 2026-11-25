#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# build-variants.sh - the iPXE builds of the exit measurements (design section 14.4), made in the builder guest (Ubuntu 26.04, gcc 15.2).
#
#   build-variants.sh REPO OUTDIR sizes | rel | inst | all
#
#   sizes   the five documented targets (and their 32-bit BIOS twins) WITH the driver (ipxe/tools/build.sh, release flags, no script) and from the
#           pristine pinned iPXE tree (git archive, no patch, no glue), same compiler, same flags: the image sizes of the exit table.
#           OUTDIR/sizes/{drv,pristine}/{x86_64-efi,x86_64-pcbios,i386-pcbios}/<file>, and OUTDIR/sizes/sizes.txt (name, bytes, sha256)
#   rel     the release builds that the throughput and idle runs use: the BIOS 32-bit ipxe.pxe with the constant PXE stub (it fetches
#           autoexec.ipxe over TFTP) and a serial console (-DCONSOLE_SERIAL, the run scripts read the serial line), and bin-x86_64-efi/ipxe.efi.
#           OUTDIR/rel/ (ipxe-stub.pxe, ipxe.efi)
#   media   the 32-bit BIOS ipxe.lkrn with a serial console and NO embedded script (isolinux starts it with the run script as its initrd: rows B2, B3 and the BIOS
#           half of the CD of row U3) and bin-x86_64-efi/ipxe.efi. OUTDIR/media/ (ipxe.lkrn, ipxe.efi)
#   inst    the instrumented builds for the watermarks: the same with -DRBD_STACK_MONITOR (stack high-water mark on BIOS) and DEBUG=malloc
#           (iPXE's own heap maximum, "HEAP maximum usage NkB", printed at shutdown), the serial console taking debug output too.
#           OUTDIR/inst/ (ipxe-stub.pxe, ipxe.efi)
#
# Every build is iPXE's own -Werror (never NO_WERROR); the number of warning lines of each log is written next to the result
# (OUTDIR/<group>/warnings.txt) and a non-zero count fails the script. One tree per variant: iPXE's make does not notice a change of
# EXTRA_CFLAGS, so a tree is never reused for another set of flags.
set -euo pipefail
LC_ALL=C
export LC_ALL

REPO=$(cd "${1:?REPO}" && pwd)
OUT=${2:?OUTDIR}
WHAT=${3:?sizes|rel|media|inst|all}
JOBS=${IPXE_JOBS:-$(nproc)}
BUILD=$REPO/ipxe/tools/build.sh
export IPXE_JOBS=$JOBS IPXE_NICE="${IPXE_NICE:-nice -n 19}"
mkdir -p "$OUT"

die() { echo "build-variants.sh: $*" >&2; exit 1; }

warnings() { # LOG... -> count of warning lines (iPXE prints "warning:" for the compiler's)
	local n
	n=$(cat "$@" | grep -ci 'warning' || true)
	printf '%s' "$n"
}

stub() { # the constant PXE stub of the QEMU run scripts
	[ -s "$OUT/stub.ipxe" ] || bash "$REPO/harness/lab/p2/qemu/gen-script.sh" --stub -o "$OUT/stub.ipxe"
}

# sizes ---------------------------------------------------------------------------------------------------------------------------
TARGETS_X64="bin-x86_64-efi/ipxe.efi bin/undionly.kpxe bin/ipxe.pxe bin/ipxe.usb bin/ipxe.iso"
TARGETS_I386="bin-i386-pcbios/undionly.kpxe bin-i386-pcbios/ipxe.pxe bin-i386-pcbios/ipxe.usb bin-i386-pcbios/ipxe.iso"

collect() { # TREE GROUPDIR : copy the targets that exist and record sizes
	local tree=$1 dest=$2 t f arch
	mkdir -p "$dest"
	: > "$dest/sizes.part"
	for t in $TARGETS_X64 $TARGETS_I386; do
		f=$tree/src/$t
		[ -f "$f" ] || die "missing $f"
		case $t in bin-x86_64-efi/*) arch=x86_64-efi;; bin-i386-pcbios/*) arch=i386-pcbios;; *) arch=x86_64-pcbios;; esac
		mkdir -p "$dest/$arch"
		cp -p "$f" "$dest/$arch/"
		printf '%s %s %s\n' "$arch/$(basename "$t")" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)" >> "$dest/sizes.part"
	done
}

do_sizes() {
	local d=$OUT/sizes
	rm -rf "$d"
	mkdir -p "$d"
	# with the driver: the tool's own prepare + build (patches, glue, core), release flags, no embedded script
	bash "$BUILD" build -o "$d/tree-drv" -j "$JOBS" $TARGETS_X64 $TARGETS_I386 > "$d/build-drv.log" 2>&1 || { tail -n 30 "$d/build-drv.log" >&2; die "driver build failed"; }
	# the pristine pinned tree: the same revision, the same make, no patch and no glue
	rev=$(sed -n '1{s/[[:space:]].*//;p;}' "$REPO/ipxe/PINNED")
	mkdir -p "$d/tree-pri"
	git -C "$REPO/third_party/ipxe" archive "$rev" | tar -x -C "$d/tree-pri"
	( cd "$d/tree-pri/src" && $IPXE_NICE make -j "$JOBS" $TARGETS_X64 $TARGETS_I386 ) > "$d/build-pri.log" 2>&1 || { tail -n 30 "$d/build-pri.log" >&2; die "pristine build failed"; }
	collect "$d/tree-drv" "$d/drv"
	mv "$d/drv/sizes.part" "$d/drv/sizes.txt"
	collect "$d/tree-pri" "$d/pristine"
	mv "$d/pristine/sizes.part" "$d/pristine/sizes.txt"
	echo "warnings drv=$(warnings "$d/build-drv.log") pristine=$(warnings "$d/build-pri.log")" > "$d/warnings.txt"
	cat "$d/warnings.txt"
	[ "$(warnings "$d/build-drv.log" "$d/build-pri.log")" = 0 ] || die "warning lines in the sizes builds"
	rm -rf "$d/tree-drv" "$d/tree-pri"
}

# rel / inst ------------------------------------------------------------------------------------------------------------------------
do_flavour() { # NAME EXTRA_CFLAGS DEBUGWORDS
	local name=$1 cflags=$2 dbg=$3 d=$OUT/$1 args=()
	rm -rf "$d"
	mkdir -p "$d"
	stub
	[ -z "$dbg" ] || args+=(-d "$dbg")
	bash "$BUILD" build -o "$d/tree-bios" -j "$JOBS" -e "$OUT/stub.ipxe" "${args[@]}" bin-i386-pcbios/ipxe.pxe -- EXTRA_CFLAGS="$cflags" > "$d/build-bios.log" 2>&1 || { tail -n 30 "$d/build-bios.log" >&2; die "$name BIOS build failed"; }
	bash "$BUILD" build -o "$d/tree-efi" -j "$JOBS" "${args[@]}" bin-x86_64-efi/ipxe.efi -- EXTRA_CFLAGS="$cflags" > "$d/build-efi.log" 2>&1 || { tail -n 30 "$d/build-efi.log" >&2; die "$name EFI build failed"; }
	cp -p "$d/tree-bios/src/bin-i386-pcbios/ipxe.pxe" "$d/ipxe-stub.pxe"
	cp -p "$d/tree-efi/src/bin-x86_64-efi/ipxe.efi" "$d/ipxe.efi"
	cp -p "$d/tree-bios/src/bin-i386-pcbios/ipxe.lkrn" "$d/ipxe.lkrn" 2>/dev/null || true
	( cd "$d" && sha256sum ipxe-stub.pxe ipxe.efi > SHA256SUMS; stat -c '%n %s' ipxe-stub.pxe ipxe.efi > sizes.txt )
	echo "warnings $name=$(warnings "$d/build-bios.log" "$d/build-efi.log")" > "$d/warnings.txt"
	cat "$d/warnings.txt"
	[ "$(warnings "$d/build-bios.log" "$d/build-efi.log")" = 0 ] || die "warning lines in the $name builds"
	rm -rf "$d/tree-bios" "$d/tree-efi"
}

do_media() {
	local d=$OUT/media
	rm -rf "$d"
	mkdir -p "$d"
	bash "$BUILD" build -o "$d/tree-bios" -j "$JOBS" bin-i386-pcbios/ipxe.lkrn -- EXTRA_CFLAGS="-DCONSOLE_SERIAL" > "$d/build-bios.log" 2>&1 || { tail -n 30 "$d/build-bios.log" >&2; die "media BIOS build failed"; }
	bash "$BUILD" build -o "$d/tree-efi" -j "$JOBS" bin-x86_64-efi/ipxe.efi -- EXTRA_CFLAGS="-DCONSOLE_SERIAL" > "$d/build-efi.log" 2>&1 || { tail -n 30 "$d/build-efi.log" >&2; die "media EFI build failed"; }
	cp -p "$d/tree-bios/src/bin-i386-pcbios/ipxe.lkrn" "$d/ipxe.lkrn"
	cp -p "$d/tree-efi/src/bin-x86_64-efi/ipxe.efi" "$d/ipxe.efi"
	( cd "$d" && sha256sum ipxe.lkrn ipxe.efi > SHA256SUMS; stat -c '%n %s' ipxe.lkrn ipxe.efi > sizes.txt )
	echo "warnings media=$(warnings "$d/build-bios.log" "$d/build-efi.log")" > "$d/warnings.txt"
	cat "$d/warnings.txt"
	[ "$(warnings "$d/build-bios.log" "$d/build-efi.log")" = 0 ] || die "warning lines in the media builds"
	rm -rf "$d/tree-bios" "$d/tree-efi"
}

case $WHAT in
	media) do_media;;
	sizes) do_sizes;;
	rel) do_flavour rel "-DCONSOLE_SERIAL" "";;
	inst) do_flavour inst "-DCONSOLE_SERIAL= -DRBD_STACK_MONITOR" "malloc";;
	all) do_sizes; do_media; do_flavour rel "-DCONSOLE_SERIAL" ""; do_flavour inst "-DCONSOLE_SERIAL= -DRBD_STACK_MONITOR" "malloc";;
	*) die "usage: build-variants.sh REPO OUTDIR sizes|rel|media|inst|all";;
esac
echo "build-variants.sh: $WHAT done"
