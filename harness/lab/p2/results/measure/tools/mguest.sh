#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mguest.sh - the kernel client on the SAME PATH as the iPXE guests (design 14.4): a Linux guest with the same virtual hardware (q35, KVM, 2 vCPUs, the
# lab NIC of the same model on the same multicast layer 2) maps the same image with the same throwaway user's key and reads it with rdbench.
#
#   mguest.sh prepare                  build the guest's kernel and initramfs in the lab VM (guest/mkguest.sh) and copy them to $P2M_WORK/guest/
#   mguest.sh row LABEL --image NAME [--oct N] [--mib 128] [--runs 3] [--skip-bytes 8192] [--timeout S]
#
# The run is the stock QEMU library (harness/lab/p2/qemu/common.sh, sourced unchanged: budget, limits, key handling, clean-up, the scan of the log for the key)
# with one function wrapped: the QEMU arguments get -kernel / -initrd / -append and the key as the first sector of a read-only virtio disk (a file in the
# run directory, mode 600, deleted with it; this kernel has no fw_cfg module). The guest reads the key from that disk and writes it to sysfs (guest/init); it is
# never an argument of a program. The evidence directory $P2M_OUT/LABEL has serial.txt (the console), krbd.txt (the KRBD
# lines), load.txt, lab-before/after/diff.txt, cmdline.txt, binaries.sha256.
# The guest maps with ms_mode=crc (msgr2 in crc mode, the iPXE driver's wire protocol) to the monitor's v2 port.
set -uo pipefail
LC_ALL=C
export LC_ALL
M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_REPO:=$(cd "$M_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?}" "${P2Q_WORK:?}" "${P2M_WORK:?}"
: "${P2M_OUT:=$P2Q_WORK/../out/runs}"
QEMU_DIR=$P2M_REPO/harness/lab/p2/qemu
UEFI_TOOLS=$P2M_REPO/harness/lab/p2/results/uefi/tools
LABSTATE=$P2M_REPO/harness/lab/p2/results/robust/tools/labstate.sh
G=$M_HERE/../guest
die() { echo "mguest.sh: $*" >&2; exit 2; }
lab_ssh() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}
cpu() { awk '/^cpu /{print $2, $3, $4, $5, $6, $7, $8, $9}' /proc/stat; }

do_prepare() {
    mkdir -p "$P2M_WORK/guest"
    tar -C "$G" -c init rdbench.c mkguest.sh | ssh -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" "${LAB_SSH_USER:-lab}@127.0.0.1" 'rm -rf /var/tmp/ms-guest-src && mkdir -p /var/tmp/ms-guest-src && tar -C /var/tmp/ms-guest-src -x' || die "prepare: copy to the lab VM failed"
    lab_ssh "sudo bash /var/tmp/ms-guest-src/mkguest.sh /var/tmp/ms-guest-src /var/tmp/ms-guest-out" | tee "$P2M_WORK/guest/mkguest.txt" || die "prepare: mkguest.sh failed"
    local f
    for f in vmlinuz initrd.img; do
        lab_ssh "cat /var/tmp/ms-guest-out/$f" > "$P2M_WORK/guest/$f" || die "prepare: copy of $f failed"
    done
    lab_ssh "sudo rm -rf /var/tmp/ms-guest-src /var/tmp/ms-guest-out"
    (cd "$P2M_WORK/guest" && sha256sum vmlinuz initrd.img > SHA256SUMS && cat SHA256SUMS)
}

do_row() {
    local name=$1 image="" oct=64 mib=128 runs=3 skip=8192 timeout=600
    shift
    while [ $# -gt 0 ]; do
        case $1 in
            --image) image=$2; shift 2;;
            --oct) oct=$2; shift 2;;
            --mib) mib=$2; shift 2;;
            --runs) runs=$2; shift 2;;
            --skip-bytes) skip=$2; shift 2;;
            --timeout) timeout=$2; shift 2;;
            *) die "row: unknown option $1";;
        esac
    done
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || die "row: bad name $name"
    [[ $image =~ ^wrtest-p2-ms-[a-z0-9-]{1,30}$ ]] || die "row: --image wrtest-p2-ms-<name>"
    [[ $oct =~ ^[0-9]+$ ]] && [ "$oct" -ge 20 ] && [ "$oct" -le 99 ] && [ "$oct" -ne 50 ] || die "row: --oct 20..99 but 50"
    [[ $mib =~ ^[0-9]+$ ]] && [[ $runs =~ ^[0-9]+$ ]] && [[ $skip =~ ^[0-9]+$ ]] && [[ $timeout =~ ^[0-9]+$ ]] || die "row: numbers only"
    local keyfile=$P2_LAB_DIR/keys/client.$image.secret
    [ -s "$keyfile" ] || die "row: no key file $keyfile"
    [ -f "$P2M_WORK/guest/vmlinuz" ] && [ -f "$P2M_WORK/guest/initrd.img" ] || die "row: no guest kernel (mguest.sh prepare)"
    local dir=$P2M_OUT/$name
    [ ! -e "$dir" ] || die "row: $dir exists"
    mkdir -p "$P2M_OUT"
    local mac
    mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
    export P2M_G_KERNEL=$P2M_WORK/guest/vmlinuz P2M_G_INITRD=$P2M_WORK/guest/initrd.img
    export P2M_G_APPEND="console=ttyS0,115200n8 net.ifnames=0 panic=-1 quiet loglevel=3 wrkg.mac=$mac wrkg.ip=10.77.0.$oct wrkg.user=$image wrkg.image=$image wrkg.mib=$mib wrkg.skip=$skip wrkg.runs=$runs"
    mkdir -m 700 "$dir"
    {
        echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) kernel-client guest $name, image $image, $mib MiB from byte $skip, $runs runs per figure"
        echo "# the cephx key is only ever a file name (the key disk is made in the run directory)"
        echo "bash $0 row $name --image $image --oct $oct --mib $mib --runs $runs --skip-bytes $skip"
        echo "# kernel command line: $P2M_G_APPEND"
    } > "$dir/cmdline.txt"
    { sha256sum "$P2M_WORK/guest/vmlinuz" "$P2M_WORK/guest/initrd.img" "$G/init" "$G/rdbench.c" "$G/mkguest.sh" "$0"; echo "# $(qemu-system-x86_64 --version | head -n 1)"; } > "$dir/binaries.sha256"
    bash "$LABSTATE" snapshot "$dir/lab-before.txt" > /dev/null
    { echo "before t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)"
      echo "before $(lab_ssh "echo lab_load=\$(cut -d' ' -f1-3 /proc/loadavg) lab_cpu=\$(awk '/^cpu /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat)")"; } > "$dir/load.txt"
    local rc=0
    P2M_G_RUN=1 bash "$0" qemu --ipxe-dir "$P2M_WORK/bin/rel" --bin "$P2M_WORK/bin/rel/ipxe-stub.pxe" --row B1 --ip "10.77.0.$oct" --user "$image" --pool winrbd --image "$image" --key-file "$keyfile" \
        --action none --expect marker --marker '^WRKG-END' --fail-marker 'WRKG-FAIL' --cpus 2 --mem 1024 --timeout "$timeout" > "$dir/stdout.txt" 2>&1 || rc=$?
    { tail -n 1 "$dir/stdout.txt"; echo "exit=$rc"; } > "$dir/result.txt"
    { echo "after t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)"
      echo "after $(lab_ssh "echo lab_load=\$(cut -d' ' -f1-3 /proc/loadavg) lab_cpu=\$(awk '/^cpu /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat)")"; } >> "$dir/load.txt"
    bash "$LABSTATE" snapshot "$dir/lab-after.txt" > /dev/null
    bash "$LABSTATE" diff "$dir/lab-before.txt" "$dir/lab-after.txt" > "$dir/lab-diff.txt" 2>&1 || true
    local console
    console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
    : > "$dir/serial.txt"
    [ -z "$console" ] || [ ! -f "$console" ] || cp -p "$console" "$dir/serial.txt"
    grep -a '^KRBD ' "$dir/serial.txt" | tr -d '\r' > "$dir/krbd.txt"
    local keyhit=0 krc=0 hits f
    hits=$(python3 -I "$UEFI_TOOLS/keyscan.py" "$keyfile" "$dir") || krc=$?
    if [ "$krc" = 1 ]; then
        keyhit=1
        while IFS= read -r f; do [ -z "$f" ] || rm -f -- "$dir/$f"; done <<< "$hits"
    elif [ "$krc" != 0 ]; then keyhit=1; fi
    local n
    n=$(grep -c '^KRBD ' "$dir/krbd.txt" 2> /dev/null || true)
    if [ "$rc" = 0 ] && [ "$keyhit" = 0 ] && [ "${n:-0}" -ge $((runs * 9)) ]; then echo PASS > "$dir/verdict.txt"; else echo FAIL > "$dir/verdict.txt"; fi
    echo "krbd passes: $n (want $((runs * 9))), run exit $rc, key found in the evidence: $keyhit" >> "$dir/verdict.txt"
    echo "mguest.sh: $name: $(head -n 1 "$dir/verdict.txt") ($(tail -n 2 "$dir/result.txt" | tr '\n' ' ' | cut -c1-160))"
}

case ${1:-} in
    prepare) do_prepare;;
    row) shift; do_row "$@";;
    qemu)
        # the stock library with the QEMU arguments of the Linux guest added
        shift
        # shellcheck source=/dev/null
        . "$QEMU_DIR/common.sh"
        q_orig=$(declare -f q_build_qargs)
        eval "${q_orig/q_build_qargs/g_orig_build_qargs}"
        q_build_qargs() {
            g_orig_build_qargs
            # the key reaches the guest as the first sector of a read-only virtio disk (a file in the run directory, mode 600, deleted with it): the
            # kernel client's secret cannot be a command-line word (the QEMU process list shows those), and this kernel has no fw_cfg module
            ( umask 077; { cat "$Q_KEYFILE"; head -c 512 /dev/zero; } | head -c 512 > "$RUNDIR/key.blk" )
            QARGS+=(-kernel "$P2M_G_KERNEL" -initrd "$P2M_G_INITRD" -append "$P2M_G_APPEND"
                -drive "if=none,id=keydisk,file=$RUNDIR/key.blk,format=raw,readonly=on" -device "virtio-blk-pci,drive=keydisk,serial=wrkey")
            q_check_no_host_net
        }
        q_main bios-pxe "$@"
        exit $?;;
    *) sed -n '3,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
