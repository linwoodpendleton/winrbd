#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# boot-test.sh - boot the guest images in plain QEMU from their own disks (no iPXE, no network boot) and check what the guest says on
# its serial console. This proves the images boot, and that the table hook prints the right PASS / FAIL lines for a hand-built table.
# A table is handed to the guest the way a loader would leave it: as an ACPI table of the firmware (QEMU -acpitable: UEFI and BIOS),
# in low memory (QEMU -device loader: the BIOS scan), or as a fw_cfg file read by the hook's test source (rbft.src=fwcfg: lets a bad
# checksum through, which -acpitable repairs). The expected values travel in the fw_cfg file opt/winrbd/params.
# The low-memory table needs a boot that leaves low memory alone. iPXE keeps its tables in memory it reserves (INT 15h e820 and the
# BIOS memory size); nothing reserves a table that QEMU puts there, and grub (pc) overwrites it. So the scan cases boot the kernel and
# initramfs of the image directly (QEMU -kernel / -initrd, read out of the image with debugfs), with the command line of the image's
# grub.cfg plus memmap=4K$0x9e000, which reserves the page in the kernel's memory map the way iPXE's INT 15h hook does (the kernel would
# zero it otherwise); the cases that boot through grub (bios-good, tiny-boot, the UEFI ones) use the firmware tables instead.
#
#   boot-test.sh [options] CASE...      CASE is one of the names below, or "all"
#
#   uefi-good      OVMF, linux-uefi.raw, good table in the firmware tables: every field PASS, root on the local disk, NIC up from the table
#   uefi-field     the same with one wrong field (pool): exactly that FAIL line, WRBOOT-TABLE FAIL, no WRBOOT-ROOT-OK
#   uefi-badsum    a table with a bad checksum through fw_cfg: FAIL checksum, WRBOOT-TABLE UNUSABLE
#   uefi-none      no table at all: WRBOOT-TABLE NONE, the boot goes on
#   bios-good      SeaBIOS, linux-bios.raw, good table in the firmware tables (the hook scans low memory first, then falls back to sysfs)
#   bios-scan      SeaBIOS, kernel and initramfs of linux-bios.raw booted directly, the table only in low memory: found by the scan
#   bios-field     the same, a wrong field found by the scan
#   bios-badsum    the same, bad checksum in low memory: the scan ignores it (no valid table), WRBOOT-TABLE NONE
#   tiny-boot      SeaBIOS + grub-pc boot b0-tiny.raw (row B0's disk) from its own disk: the BIOS drives (EDD) are listed, no table
#   tiny-good      the tiny kernel and initramfs booted directly, table in low memory: scan finds it, every field PASS
#   tiny-field     the same with a wrong field
#   uefi-map       OVMF, the table names a real cluster: the hook maps the image with krbd and mounts the root from /dev/rbd<N>p2
#   bios-map       SeaBIOS, the same
#                  Both need a cluster the guest can reach and --map-image NAME (an imported image and its user client.NAME, see
#                  import.sh). Run as root IN THE LAB VM: the script maps the image there (read-only, with the user's own key) as the guest's
#                  boot disk, hands the key to the guest as an fw_cfg file (it stays in a mode 600 file of the work directory, deleted at the
#                  end) and boots with a table that names the lab's monitor; the guest is on QEMU's user-mode network (10.0.2.15, gateway
#                  10.0.2.2), whose NAT reaches the monitor and the OSDs from the VM itself. With --map-key-file FILE (and an image file) it
#                  boots a local copy instead and takes the key from that file.
#   uefi-map-badkey   the same with a key the cluster does not know, and rbft.require=1: the kernel refuses, the hook says so (its own line
#   bios-map-badkey   and the kernel's libceph lines), powers the guest off (WRBOOT-HOOK-POWEROFF) and prints no WRBOOT-ROOT-OK
#   uefi-map-noimage  the same with a valid key and an image that does not exist (the kernel answers ENOENT)
#   bios-map-noimage
#
# Options: --uefi FILE --bios FILE --tiny FILE (images; default $IMG_WORK/out/linux-uefi.raw, linux-bios.raw, b0-tiny.raw), --qemu BIN
#   --ovmf-code FILE --ovmf-vars FILE, --accel kvm|tcg|auto (default auto), --cpus N (2), --mem MB (1024), --timeout S (240),
#   --work DIR (default a temporary directory, removed), --keep (keep it), --map-image NAME --map-key-file FILE --map-mons A:P
#   --map-entity USER (default the image name) --map-pool POOL (winrbd)
# The images are opened with snapshot=on: they are never modified. QEMU runs as `nice -n 19` with user-mode networking only.
# Exit status: 0 every case passed; 1 a case failed; 2 usage or a missing prerequisite.
# shellcheck disable=SC2015  # "A && ok || bad": ok and bad cannot fail
set -u

prog=boot-test.sh
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${IMG_WORK:=/var/tmp/winrbd-p2-images}"
uefi_img=$IMG_WORK/out/linux-uefi.raw
bios_img=$IMG_WORK/out/linux-bios.raw
tiny_img=$IMG_WORK/out/b0-tiny.raw
qemu=
ovmf_code=
ovmf_vars=
accel=auto
cpus=2
mem=1024
timeout_s=240
work=
keep=0
map_image=
map_key=
map_mons=10.77.0.10:3300
map_entity=
map_pool=winrbd
cases=()
et=$here/expected-table.sh

die() { printf '%s: %s\n' "$prog" "$*" >&2; exit 2; }
usage() { sed -n '3,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }
need_val() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
	case $1 in
	--uefi) need_val "$@"; uefi_img=$2; shift 2 ;;
	--bios) need_val "$@"; bios_img=$2; shift 2 ;;
	--tiny) need_val "$@"; tiny_img=$2; shift 2 ;;
	--qemu) need_val "$@"; qemu=$2; shift 2 ;;
	--ovmf-code) need_val "$@"; ovmf_code=$2; shift 2 ;;
	--ovmf-vars) need_val "$@"; ovmf_vars=$2; shift 2 ;;
	--accel) need_val "$@"; accel=$2; shift 2 ;;
	--cpus) need_val "$@"; cpus=$2; shift 2 ;;
	--mem) need_val "$@"; mem=$2; shift 2 ;;
	--timeout) need_val "$@"; timeout_s=$2; shift 2 ;;
	--work) need_val "$@"; work=$2; shift 2 ;;
	--keep) keep=1; shift ;;
	--map-image) need_val "$@"; map_image=$2; shift 2 ;;
	--map-key-file) need_val "$@"; map_key=$2; shift 2 ;;
	--map-mons) need_val "$@"; map_mons=$2; shift 2 ;;
	--map-entity) need_val "$@"; map_entity=$2; shift 2 ;;
	--map-pool) need_val "$@"; map_pool=$2; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	-*) usage >&2; die "unknown option '$1'" ;;
	*) cases+=("$1"); shift ;;
	esac
done
[ "${#cases[@]}" -gt 0 ] || { usage >&2; exit 2; }
ALL="uefi-good uefi-field uefi-badsum uefi-none bios-good bios-scan bios-field bios-badsum tiny-boot tiny-good tiny-field"
MAPCASES="uefi-map bios-map uefi-map-badkey bios-map-badkey uefi-map-noimage bios-map-noimage"
if [ "${cases[0]}" = all ]; then read -r -a cases <<< "$ALL"; fi
for c in "${cases[@]}"; do
	case " $ALL $MAPCASES " in *" $c "*) ;; *) die "unknown case '$c'" ;; esac
done
case $cpus$mem$timeout_s in *[!0-9]*) die "--cpus, --mem and --timeout are numbers" ;; esac
[ "$cpus" -le 4 ] || die "--cpus: at most 4"
[ "$mem" -le 4096 ] || die "--mem: at most 4096"
case $accel in kvm | tcg | auto) ;; *) die "--accel is kvm, tcg or auto" ;; esac

[ -n "$qemu" ] || qemu=$(command -v qemu-system-x86_64 || true)
[ -n "$qemu" ] && [ -x "$qemu" ] || die "no qemu-system-x86_64 (--qemu BIN)"
command -v python3 > /dev/null 2>&1 || die "python3 is needed (expected-table.sh)"
if [ "$accel" = auto ]; then
	if [ -w /dev/kvm ]; then accel=kvm; else accel=tcg; fi
fi

want_uefi=0
for c in "${cases[@]}"; do case $c in uefi-*) want_uefi=1 ;; esac; done
if [ "$want_uefi" = 1 ]; then
	if [ -z "$ovmf_code" ]; then
		for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/qemu/OVMF_CODE.fd; do
			[ -r "$f" ] && { ovmf_code=$f; break; }
		done
	fi
	[ -r "$ovmf_code" ] || die "no OVMF firmware (--ovmf-code FILE, package ovmf)"
	if [ -z "$ovmf_vars" ]; then
		for f in "${ovmf_code/CODE/VARS}" /usr/share/OVMF/OVMF_VARS_4M.fd /usr/share/OVMF/OVMF_VARS.fd; do
			[ -r "$f" ] && { ovmf_vars=$f; break; }
		done
	fi
	[ -r "$ovmf_vars" ] || die "no OVMF variable store (--ovmf-vars FILE)"
fi

own_work=0
if [ -z "$work" ]; then
	work=$(mktemp -d "${TMPDIR:-/tmp}/wr-boot-test.XXXXXX") || die "cannot make a work directory"
	own_work=1
else
	[ -d "$work" ] || mkdir -p "$work" || die "cannot make $work"
fi
qpid=
MAPPED_DEV=''
cleanup() {
	[ -z "$qpid" ] || kill "$qpid" 2> /dev/null
	[ -z "$MAPPED_DEV" ] || rbd unmap "$MAPPED_DEV" > /dev/null 2>&1
	# every file that can hold a key, also in a --work directory that stays (a failed "rbd map" leaves its keyring behind otherwise)
	rm -f "$work"/*-map.key "$work"/*-map-badkey.key "$work"/*-map-badkey.badkey "$work"/*-map-noimage.key "$work"/*.keyring
	if [ "$keep" = 1 ]; then echo "$prog: kept $work"; return; fi
	if [ "$own_work" = 1 ]; then
		case $work in "${TMPDIR:-/tmp}"/wr-boot-test.*) rm -rf "$work" ;; esac
	fi
}
trap cleanup EXIT

npass=0 nfail=0
ok() { npass=$((npass + 1)); printf '  ok      %s\n' "$*"; }
bad() { nfail=$((nfail + 1)); printf '  FAILED  %s\n' "$*"; }

# the serial log without carriage returns and escape sequences
# (cursor movement and screen clears, which grub uses, become line breaks: grub's text and the kernel's lines are not glued together)
clean_log() { tr -d '\r' < "$1" | sed -E 's/\x1b\[[0-9;?]*[HJ]/\n/g; s/\x1b\[[0-9;?]*[A-Za-z]//g'; }
has() { grep -Eq -- "$2" "$1"; }

# the kernel and the initramfs of an image, read out with debugfs from its last partition (its root) into $work: sets QDIRECT_KERNEL and QDIRECT_INITRD
extract_boot() { # IMAGE TAG
	local img=$1 tag=$2 start off k i names
	command -v debugfs > /dev/null 2>&1 && command -v sfdisk > /dev/null 2>&1 || die "debugfs and sfdisk are needed to boot an image's kernel directly (e2fsprogs, util-linux)"
	start=$(sfdisk -d "$img" 2> /dev/null | sed -n 's/^[^ ]* *: *start= *\([0-9][0-9]*\),.*/\1/p' | tail -n 1)
	[ -n "$start" ] || die "no partition table in $img"
	off=$((start * 512))
	names=$(debugfs -R "ls -p /boot" "$img?offset=$off" 2> /dev/null | awk -F/ '{print $6}')
	k=$(printf '%s\n' "$names" | grep -E '^vmlinuz-[0-9]' | sort -V | tail -n 1)
	i=$(printf '%s\n' "$names" | grep -E '^(initrd\.img-[0-9]|tiny\.initrd)' | sort -V | tail -n 1)
	[ -n "$k" ] && [ -n "$i" ] || die "no kernel and initramfs in /boot of $img"
	rm -f "$work/kernel-$tag" "$work/initrd-$tag"
	debugfs -R "dump /boot/$k $work/kernel-$tag" "$img?offset=$off" > /dev/null 2>&1 || die "cannot read /boot/$k from $img"
	debugfs -R "dump /boot/$i $work/initrd-$tag" "$img?offset=$off" > /dev/null 2>&1 || die "cannot read /boot/$i from $img"
	QDIRECT_KERNEL=$work/kernel-$tag
	QDIRECT_INITRD=$work/initrd-$tag
}

# run_case NAME FW IMAGE ...: the table and the options come from the globals set by the case function
run_case() {
	local name=$1 fw=$2 image=$3 log vars
	log=$work/serial-$name.log
	vars=$work/vars-$name.fd
	local args=() st=0 t=0
	[ -r "$image" ] || { bad "$name: no image $image"; return 1; }
	rm -f "$log"
	args+=(-name "wrbt-$name" -nodefaults -display none -no-reboot -smp "$cpus" -m "$mem" -serial "file:$log" -monitor none)
	if [ "$accel" = kvm ]; then args+=(-machine "$QMACHINE,accel=kvm" -cpu host); else args+=(-machine "$QMACHINE,accel=tcg" -cpu max); fi
	if [ "$fw" = uefi ]; then
		cp "$ovmf_vars" "$vars"
		args+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" -drive "if=pflash,format=raw,unit=1,file=$vars")
	fi
	args+=(-drive "file=$image,format=raw,if=virtio,snapshot=on")
	args+=(-netdev "user,id=n0" -device "virtio-net-pci,netdev=n0,mac=$QMAC")
	args+=(-fw_cfg "name=opt/winrbd/params,file=$work/$name.params")
	[ -z "$QKEY" ] || args+=(-fw_cfg "name=opt/winrbd/key,file=$QKEY")
	if [ -n "$QDIRECT" ]; then args+=(-kernel "$QDIRECT_KERNEL" -initrd "$QDIRECT_INITRD" -append "$QDIRECT"); fi
	case $QTABLE in
	acpi) args+=(-acpitable "sig=rBFT,rev=1,data=$work/$name.body") ;;
	low) args+=(-device "loader,file=$work/$name.table,addr=$QLOWADDR,force-raw=on") ;;
	fwcfg) args+=(-fw_cfg "name=opt/winrbd/table,file=$work/$name.table") ;;
	none) ;;
	esac
	nice -n 19 "$qemu" "${args[@]}" > "$work/$name.qemu.out" 2>&1 &
	qpid=$!
	# wait for the verdict line, the end of QEMU, or the timeout
	while [ "$t" -lt "$timeout_s" ]; do
		kill -0 "$qpid" 2> /dev/null || break
		if [ -s "$log" ] && clean_log "$log" | grep -Eq "$QDONE"; then sleep 3; break; fi
		sleep 2
		t=$((t + 2))
	done
	kill "$qpid" 2> /dev/null
	wait "$qpid" 2> /dev/null
	qpid=
	clean_log "$log" > "$work/$name.txt" 2> /dev/null
	if [ ! -s "$work/$name.txt" ]; then bad "$name: the guest printed nothing on the serial console (QEMU: $(head -n 2 "$work/$name.qemu.out" | tr '\n' ' '))"; return 1; fi
	st=0
	return $st
}

# prepare the table, expectations and options of a case
prep() { # NAME TABLE-MODE [expected-table options...]
	local n=$1 mode=$2
	shift 2
	QTABLE=$mode
	"$et" fwcfg "$@" > "$work/$n.params" 2> /dev/null || die "expected-table.sh params failed ($*)"
	{ printf '%s\n' "rbft.poweroff=$QPOWEROFF"; printf '%s\n' "$QEXTRA"; } >> "$work/$n.params"
	case $mode in
	acpi) "$et" body "$@" -o "$work/$n.body" 2> /dev/null || die "expected-table.sh body failed" ;;
	low | fwcfg) "$et" table "$@" -o "$work/$n.table" 2> /dev/null || die "expected-table.sh table failed" ;;
	esac
}

QMACHINE=q35
QMAC=52:54:00:77:12:20
QKEY=
QEXTRA=
QLOWADDR=0x9e000
QDONE='WRBOOT-(ROOT-[A-Z-]+|TINY staying)|Kernel panic|WRBOOT-HOOK-POWEROFF'
QDIRECT='' QDIRECT_KERNEL='' QDIRECT_INITRD=''
QPOWEROFF=1 # the guest powers itself off after the marker (so that a run ends by itself); the cases that look for the login prompt keep it up

line_count() { grep -Ec -- "$2" "$1" || true; }

check_common_pass() { # NAME FW
	local n=$1 t=$work/$1.txt
	has "$t" '^WRBOOT-TABLE PASS' && ok "$n: WRBOOT-TABLE PASS" || bad "$n: no WRBOOT-TABLE PASS"
	has "$t" '^RBFT-RESULT PASS pass=[0-9]+ fail=0 skip=0' && ok "$n: every field of the table checked and PASS (RBFT-RESULT PASS ... fail=0 skip=0)" || bad "$n: RBFT-RESULT: $(grep '^RBFT-RESULT' "$t" | head -n 1)"
	[ "$(line_count "$t" '^RBFT FAIL')" = 0 ] && ok "$n: no FAIL line" || bad "$n: FAIL lines: $(grep '^RBFT FAIL' "$t" | head -n 3 | tr '\n' ' ')"
}

case_uefi_good() {
	local n=uefi-good
	QEXTRA="rbft.map=0"
	QPOWEROFF=0
	prep $n acpi
	QDONE='[a-z-]+ login: '
	run_case $n uefi "$uefi_img" || return
	local t=$work/$n.txt
	check_common_pass $n
	has "$t" '^RBFT-HOOK table found by source sysfs' && ok "$n: the table came from the firmware tables (sysfs)" || bad "$n: source"
	has "$t" '^RBFT-HOOK nic: eth0 has MAC 52:54:00:77:12:20' && has "$t" '^RBFT-HOOK nic: eth0 address 10.77.0.20/24' && ok "$n: the NIC was found by the table's MAC and got the table's address" || bad "$n: NIC lines: $(grep 'RBFT-HOOK nic' "$t" | head -n 3 | tr '\n' ' ')"
	has "$t" '^WRBOOT-NET eth0 mac=52:54:00:77:12:20 .*10\.77\.0\.20/24' && ok "$n: the booted system has the address on eth0" || bad "$n: WRBOOT-NET"
	has "$t" '^RBFT DUMP 0000: 72 42 46 54' && ok "$n: the table is dumped (acpidump-style) in the log" || bad "$n: no dump"
	has "$t" '^WRBOOT-ROOT-OK fw=uefi root=/dev/(vda2|sda2) .*table=PASS src=sysfs' && ok "$n: WRBOOT-ROOT-OK fw=uefi, root on the local disk (no cluster), table=PASS" || bad "$n: marker: $(grep '^WRBOOT-ROOT' "$t" | head -n 1)"
	has "$t" '^[a-z-]+ login:' && ok "$n: a login prompt on the serial console" || bad "$n: no login prompt"
}
case_uefi_field() {
	local n=uefi-field
	QEXTRA="rbft.map=0"
	prep $n acpi --set pool=other
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n uefi "$uefi_img" || return
	local t=$work/$n.txt
	has "$t" "^RBFT FAIL pool: expected 'winrbd', got 'other'" && ok "$n: RBFT FAIL pool: expected 'winrbd', got 'other'" || bad "$n: no FAIL pool line"
	[ "$(line_count "$t" '^RBFT FAIL')" = 1 ] && ok "$n: it is the only FAIL line" || bad "$n: FAIL lines: $(grep '^RBFT FAIL' "$t" | tr '\n' ' ')"
	has "$t" '^WRBOOT-TABLE FAIL' && has "$t" '^WRBOOT-ROOT-TABLE-FAIL ' && ! has "$t" '^WRBOOT-ROOT-OK' && ok "$n: WRBOOT-TABLE FAIL, WRBOOT-ROOT-TABLE-FAIL, no WRBOOT-ROOT-OK" || bad "$n: verdict lines"
}
case_uefi_badsum() {
	local n=uefi-badsum
	QEXTRA=$(printf 'rbft.map=0\nrbft.src=fwcfg')
	prep $n fwcfg --defect checksum
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n uefi "$uefi_img" || return
	local t=$work/$n.txt
	has "$t" '^RBFT FAIL checksum: ' && has "$t" '^WRBOOT-TABLE UNUSABLE' && has "$t" '^WRBOOT-ROOT-TABLE-FAIL ' && ok "$n: FAIL checksum, WRBOOT-TABLE UNUSABLE, WRBOOT-ROOT-TABLE-FAIL" || bad "$n: $(grep -E 'WRBOOT-TABLE|FAIL' "$t" | head -n 3 | tr '\n' ' ')"
	has "$t" '^RBFT-HOOK table found by source fwcfg' && ok "$n: through the fw_cfg test source" || bad "$n: source"
}
case_uefi_none() {
	local n=uefi-none
	QEXTRA="rbft.map=0"
	prep $n none
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n uefi "$uefi_img" || return
	local t=$work/$n.txt
	has "$t" '^WRBOOT-TABLE NONE' && has "$t" '^WRBOOT-ROOT-OK fw=uefi .*table=NONE' && ok "$n: WRBOOT-TABLE NONE and the boot goes on (WRBOOT-ROOT-OK table=NONE)" || bad "$n: $(grep -E '^WRBOOT' "$t" | head -n 3 | tr '\n' ' ')"
}
case_bios_good() {
	local n=bios-good
	QMACHINE=pc
	QEXTRA="rbft.map=0"
	QPOWEROFF=0
	prep $n acpi
	QDONE='[a-z-]+ login: '
	run_case $n bios "$bios_img" || return
	local t=$work/$n.txt
	check_common_pass $n
	has "$t" '^RBFT-HOOK source scan: no table' && has "$t" '^RBFT-HOOK table found by source sysfs' && ok "$n: the scan of low memory finds none, then the firmware tables do" || bad "$n: sources: $(grep 'source' "$t" | head -n 3 | tr '\n' ' ')"
	has "$t" '^WRBOOT-ROOT-OK fw=bios root=/dev/(vda1|sda1) .*table=PASS' && ok "$n: WRBOOT-ROOT-OK fw=bios, local root, table=PASS" || bad "$n: marker: $(grep '^WRBOOT-ROOT' "$t" | head -n 1)"
	has "$t" '^WRBOOT-EDD int13_dev80 ' && ok "$n: the BIOS drive (EDD int13_dev80) is listed" || bad "$n: no EDD line"
	has "$t" '^[a-z-]+ login:' && ok "$n: a login prompt on the serial console" || bad "$n: no login prompt"
}
case_bios_scan() {
	local n=bios-scan
	QMACHINE=pc
	QEXTRA=$(printf 'rbft.map=0\nrbft.src=scan')
	prep $n low
	extract_boot "$bios_img" bios
	QDIRECT="root=LABEL=wrbroot ro console=ttyS0,115200n8 net.ifnames=0 iomem=relaxed edd=on memmap=4K\$$QLOWADDR rbft.hook=1 rbft.rootpart=1"
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n bios "$bios_img" || return
	local t=$work/$n.txt
	check_common_pass $n
	has "$t" '^RBFT INFO source: scan: found at physical address 0x9e000' && ok "$n: found by the scan of low memory at 0x9e000" || bad "$n: source: $(grep -E 'source|scan' "$t" | head -n 3 | tr '\n' ' ')"
	has "$t" '^WRBOOT-ROOT-OK fw=bios .*table=PASS src=scan' && ok "$n: WRBOOT-ROOT-OK table=PASS src=scan" || bad "$n: marker: $(grep '^WRBOOT-ROOT' "$t" | head -n 1)"
}
case_bios_field() {
	local n=bios-field
	QMACHINE=pc
	QEXTRA=$(printf 'rbft.map=0\nrbft.src=scan')
	prep $n low --set image=other
	extract_boot "$bios_img" bios
	QDIRECT="root=LABEL=wrbroot ro console=ttyS0,115200n8 net.ifnames=0 iomem=relaxed edd=on memmap=4K\$$QLOWADDR rbft.hook=1 rbft.rootpart=1"
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n bios "$bios_img" || return
	local t=$work/$n.txt
	has "$t" "^RBFT FAIL image: expected 'wrtest-p2-lin-uefi', got 'other'" && [ "$(line_count "$t" '^RBFT FAIL')" = 1 ] && has "$t" '^WRBOOT-ROOT-TABLE-FAIL ' && ok "$n: exactly the FAIL image line, WRBOOT-ROOT-TABLE-FAIL" || bad "$n: $(grep -E '^RBFT FAIL|WRBOOT-ROOT' "$t" | head -n 3 | tr '\n' ' ')"
}
case_bios_badsum() {
	local n=bios-badsum
	QMACHINE=pc
	QEXTRA=$(printf 'rbft.map=0\nrbft.src=scan')
	prep $n low --defect checksum
	extract_boot "$bios_img" bios
	QDIRECT="root=LABEL=wrbroot ro console=ttyS0,115200n8 net.ifnames=0 iomem=relaxed edd=on memmap=4K\$$QLOWADDR rbft.hook=1 rbft.rootpart=1"
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n bios "$bios_img" || return
	local t=$work/$n.txt
	has "$t" 'signature at 0x9e000 but no valid length and checksum: ignored' && has "$t" '^WRBOOT-TABLE NONE' && ok "$n: the scan ignores a table with a bad checksum (names it), WRBOOT-TABLE NONE" || bad "$n: $(grep -E 'scan|WRBOOT-TABLE' "$t" | head -n 3 | tr '\n' ' ')"
}
case_tiny() { # NAME [expected-table options]
	local n=$1
	shift
	QMACHINE=pc
	QEXTRA=$(printf 'rbft.src=scan')
	prep "$n" low "$@"
	extract_boot "$tiny_img" tiny
	QDIRECT="console=ttyS0,115200n8 iomem=relaxed edd=on memmap=4K\$$QLOWADDR rbft.hook=1 rbft.map=0 rbft.src=scan rbft.waitnic=0"
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case "$n" bios "$tiny_img" || return
}
case_tiny_boot() {
	local n=tiny-boot t
	QMACHINE=pc
	QEXTRA=$(printf 'rbft.src=scan')
	prep $n none
	QDONE='WRBOOT-ROOT-[A-Z-]+'
	run_case $n bios "$tiny_img" || return
	t=$work/$n.txt
	has "$t" '^WRBOOT-TINY start kernel=' && ok "$n: grub-pc booted the tiny disk from its own disk and its init ran" || bad "$n: no WRBOOT-TINY line"
	has "$t" '^WRBOOT-EDD int13_dev80 ' && ok "$n: the BIOS drive (EDD int13_dev80) is listed (edd=on)" || bad "$n: no EDD line"
	has "$t" '^WRBOOT-TABLE NONE' && has "$t" '^WRBOOT-ROOT-OK fw=bios root=initramfs .*table=NONE' && ok "$n: no table: WRBOOT-TABLE NONE, marker root=initramfs" || bad "$n: marker: $(grep '^WRBOOT' "$t" | head -n 4 | tr '\n' ' ')"
}
case_tiny_good() {
	local n=tiny-good t
	case_tiny $n || return
	t=$work/$n.txt
	check_common_pass $n
	has "$t" '^WRBOOT-EDD int13_dev80 ' && ok "$n: the BIOS drive list (EDD) is printed" || bad "$n: no EDD line (is edd built in or loaded?)"
	has "$t" '^WRBOOT-ROOT-OK fw=bios root=initramfs .*table=PASS src=scan' && ok "$n: WRBOOT-ROOT-OK fw=bios root=initramfs table=PASS src=scan" || bad "$n: marker: $(grep '^WRBOOT-ROOT' "$t" | head -n 1)"
}
case_tiny_field() {
	local n=tiny-field t
	case_tiny $n --set mtu=9000 || return
	t=$work/$n.txt
	has "$t" "^RBFT FAIL nic_mtu: expected 1500, got 9000" && [ "$(line_count "$t" '^RBFT FAIL')" = 1 ] && has "$t" '^WRBOOT-ROOT-TABLE-FAIL ' && ok "$n: exactly the FAIL nic_mtu line" || bad "$n: $(grep -E '^RBFT FAIL|WRBOOT-ROOT' "$t" | head -n 3 | tr '\n' ' ')"
}
case_map() { # FW [badkey|noimage]
	local fw=$1 variant=${2:-} n=$1-map img part dev='' kr rootdev t want_image why key=$map_key
	[ -z "$variant" ] || n=$1-map-$variant
	[ -n "$map_image" ] || { bad "$n: needs --map-image NAME"; return; }
	[ -n "$map_entity" ] || map_entity=$map_image
	if [ "$fw" = uefi ]; then img=$uefi_img part=2; else img=$bios_img part=1; QMACHINE=pc; fi
	if [ -z "$key" ]; then
		# lab mode: the image on the cluster is the guest's boot disk (read-only), the user's own key goes to the guest as a file
		[ "$(id -u)" = 0 ] || { bad "$n: lab mode needs root (rbd map, ceph auth) in the lab VM"; return; }
		command -v rbd > /dev/null 2>&1 && command -v ceph > /dev/null 2>&1 || { bad "$n: no rbd / ceph commands here: run this in the lab VM, or give --map-key-file"; return; }
		key=$work/$n.key
		kr=$work/$n.keyring
		(umask 077; ceph auth get-key "client.$map_entity" > "$key" 2> /dev/null && ceph auth get "client.$map_entity" -o "$kr" > /dev/null 2>&1) || { bad "$n: no user client.$map_entity (import.sh user-create)"; return; }
		dev=$(rbd map "$map_pool/$map_image" --id "$map_entity" --keyring "$kr" -o ro,ms_mode=prefer-crc 2> "$work/$n.maperr") || { bad "$n: rbd map failed: $(head -n 1 "$work/$n.maperr")"; return; }
		MAPPED_DEV=$dev
		img=$dev
		rm -f "$kr"
		printf '  boot disk: %s (the image %s/%s on the cluster, mapped read-only with the user key)\n' "$dev" "$map_pool" "$map_image"
	fi
	[ -r "$key" ] || { bad "$n: cannot read $key"; return; }
	want_image=$map_image
	QEXTRA=$(printf 'rbft.map=1')
	case $variant in
	badkey)
		# a well-formed legacy key (type 1, 16 random bytes) that no user of the cluster has
		python3 -I -c 'import base64, os, struct, sys; open(sys.argv[1], "w").write(base64.b64encode(struct.pack("<HIIH", 1, 0, 0, 16) + os.urandom(16)).decode())' "$work/$n.badkey" || { bad "$n: cannot make a key"; return; }
		chmod 600 "$work/$n.badkey"
		key=$work/$n.badkey
		QEXTRA=$(printf 'rbft.map=1\nrbft.require=1')
		;;
	noimage)
		want_image=wrtest-p2-no-such-image
		QEXTRA=$(printf 'rbft.map=1\nrbft.require=1')
		;;
	esac
	QKEY=$key
	QPOWEROFF=0
	QMAC=52:54:00:77:12:20
	# the guest is on QEMU's user-mode network (10.0.2.0/24), whose gateway reaches the monitor and the OSDs of the lab
	prep "$n" acpi --mons "$map_mons" --entity "$map_entity" --pool "$map_pool" --image "$want_image" --ip 10.0.2.15/24 --gw 10.0.2.2
	QDONE='[a-z-]+ login: |WRBOOT-ROOT-[A-Z-]*FAIL|WRBOOT-HOOK-POWEROFF|WRBOOT-ROOT-WRONG|WRBOOT-ROOT-NOT-RBD'
	run_case "$n" "$fw" "$img" || return
	t=$work/$n.txt
	check_common_pass "$n"
	if [ -n "$variant" ]; then
		has "$t" '^RBFT-HOOK map: the kernel refused the mapping' && ok "$n: the hook says the kernel refused the mapping" || bad "$n: no refusal line: $(grep -E 'RBFT-HOOK' "$t" | tail -n 3 | tr '\n' ' ')"
		why=$(grep -a '^RBFT-HOOK dmesg: ' "$t" | grep -v 'loaded' | head -n 1 | cut -c1-140)
		[ -n "$why" ] && ok "$n: and shows the kernel's reason: ${why#RBFT-HOOK dmesg: }" || bad "$n: no reason from the kernel in the dmesg lines"
		has "$t" '^WRBOOT-HOOK-POWEROFF: ' && ok "$n: rbft.require=1: WRBOOT-HOOK-POWEROFF" || bad "$n: no WRBOOT-HOOK-POWEROFF"
		! has "$t" '^WRBOOT-ROOT-OK' && ok "$n: no WRBOOT-ROOT-OK" || bad "$n: WRBOOT-ROOT-OK after a failed mapping"
		if grep -qF "$(tr -d '\n' < "$key")" "$t"; then bad "$n: THE KEY IS IN THE SERIAL LOG"; else ok "$n: the key is not in the serial log"; fi
		return
	fi
	rootdev=/dev/rbd0p$part
	has "$t" "^RBFT-HOOK map: image $map_pool/$map_image is /dev/rbd[0-9]+, root device /dev/rbd[0-9]+p$part" && ok "$n: the kernel client in the guest mapped $map_pool/$map_image" || bad "$n: map lines: $(grep -E 'RBFT-HOOK (map|FAIL)' "$t" | tail -n 3 | tr '\n' ' ')"
	has "$t" "^WRBOOT-ROOT-OK fw=$fw root=/dev/rbd[0-9]+p$part fstype=ext4 mapped=rbd[0-9]+ table=PASS" && ok "$n: WRBOOT-ROOT-OK with / on $rootdev (mapped=rbd0, table=PASS)" || bad "$n: marker: $(grep '^WRBOOT-ROOT' "$t" | head -n 1)"
	has "$t" '^[a-z-]+ login:' && ok "$n: a login prompt with the root on the cluster" || bad "$n: no login prompt"
	if grep -qF "$(tr -d '\n' < "$key")" "$t"; then bad "$n: THE KEY IS IN THE SERIAL LOG"; else ok "$n: the key is not in the serial log"; fi
}

for c in "${cases[@]}"; do
	printf '\n== %s\n' "$c"
	before=$nfail
	QMACHINE=q35 QMAC=52:54:00:77:12:20 QKEY='' QEXTRA='' QLOWADDR=0x9e000 QPOWEROFF=1 QDIRECT='' QDIRECT_KERNEL='' QDIRECT_INITRD=''
	case $c in
	uefi-good) case_uefi_good ;;
	uefi-field) case_uefi_field ;;
	uefi-badsum) case_uefi_badsum ;;
	uefi-none) case_uefi_none ;;
	bios-good) case_bios_good ;;
	bios-scan) case_bios_scan ;;
	bios-field) case_bios_field ;;
	bios-badsum) case_bios_badsum ;;
	tiny-boot) case_tiny_boot ;;
	tiny-good) case_tiny_good ;;
	tiny-field) case_tiny_field ;;
	uefi-map) case_map uefi ;;
	bios-map) case_map bios ;;
	uefi-map-badkey) case_map uefi badkey ;;
	bios-map-badkey) case_map bios badkey ;;
	uefi-map-noimage) case_map uefi noimage ;;
	bios-map-noimage) case_map bios noimage ;;
	esac
	# a case that mapped the image on this machine lets it go before the next one
	if [ -n "$MAPPED_DEV" ]; then rbd unmap "$MAPPED_DEV" > /dev/null 2>&1; MAPPED_DEV=''; fi
	if [ "$nfail" != "$before" ] && [ -s "$work/$c.txt" ]; then
		printf '  --- the last lines of the serial console of %s:\n' "$c"
		tail -n 25 "$work/$c.txt" | sed 's/^/  | /'
	fi
done

printf '\n%s: %d passed, %d failed\n' "$prog" "$npass" "$nfail"
[ "$nfail" = 0 ]
