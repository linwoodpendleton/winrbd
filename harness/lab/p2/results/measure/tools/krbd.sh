#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# krbd.sh - the kernel client's sequential read throughput on the SAME image and cluster as the bench runs (design 14.4, the comparison).
#
#   krbd.sh run LABEL --image NAME [--mib 128] [--runs 3] [--skip-bytes 8192]
#
# In the lab VM (the cluster's own host: the kernel client talks to the monitor and the OSDs over the VM's loopback path, not over a NIC, so this is the
# upper bound of what a kernel client gets from this cluster, not the same network path as the guest's; the Linux-guest variant, krbd.sh guest, is the
# same path: see the README). The image is mapped with the throwaway user's own key (a keyring in /dev/shm, removed on exit), read only. For
# every combination of
#   mode   direct (O_DIRECT, no client cache or readahead: the counterpart of readahead=0), ra128k (buffered, the kernel's default readahead of 128 KiB),
#          ra2048k (buffered, readahead set to 2 MiB: the counterpart of the driver's default window)
#   block  64 KiB, 1 MiB, 4 MiB
# it reads --mib MiB from --skip-bytes (the data area of the bench disk starts at sector 16 = byte 8192) to /dev/null, after one untimed warm pass over the
# same range, --runs times; for the buffered modes the client's page cache is dropped before every timed pass. One line per pass:
#   KRBD mode=direct bs=65536 run=1 bytes=134217728 secs=1.2345 mibs=103.7
# The evidence goes to $P2M_OUT/LABEL: krbd.txt, load.txt (host and lab VM load and CPU steal before and after), lab-before/after/diff.txt.
set -euo pipefail
LC_ALL=C
export LC_ALL
M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2_LAB_DIR:?}" "${P2M_OUT:?}"
LABSTATE=$M_HERE/../../robust/tools/labstate.sh
die() { echo "krbd.sh: $*" >&2; exit 2; }
lab_ssh() {
    ssh -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}

[ "${1:-}" = run ] || { sed -n '3,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
shift
label=${1:?LABEL}
shift
image="" mib=128 runs=3 skip=8192
while [ $# -gt 0 ]; do
    case $1 in
        --image) image=$2; shift 2;;
        --mib) mib=$2; shift 2;;
        --runs) runs=$2; shift 2;;
        --skip-bytes) skip=$2; shift 2;;
        *) die "unknown option $1";;
    esac
done
[[ $image =~ ^wrtest-p2-ms-[a-z0-9-]{1,30}$ ]] || die "--image wrtest-p2-ms-<name>"
[[ $mib =~ ^[0-9]+$ ]] && [[ $runs =~ ^[0-9]+$ ]] && [[ $skip =~ ^[0-9]+$ ]] || die "numbers only"
dir=$P2M_OUT/$label
[ ! -e "$dir" ] || die "$dir exists"
mkdir -p "$dir"
bash "$LABSTATE" snapshot "$dir/lab-before.txt" > /dev/null
cpu() { awk '/^cpu /{print $2, $3, $4, $5, $6, $7, $8, $9}' /proc/stat; }
{
    echo "# krbd.sh run $label, image $image, $mib MiB from byte $skip, $runs runs per figure"
    echo "before t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)"
    echo "before $(lab_ssh "echo lab_load=\$(cut -d' ' -f1-3 /proc/loadavg) lab_cpu=\$(awk '/^cpu /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat) kernel=\$(uname -r)")"
} > "$dir/load.txt"

rc=0
lab_ssh "sudo bash -s -- $image $mib $runs $skip" > "$dir/krbd.txt" 2> "$dir/stderr.txt" << 'EOS' || rc=$?
set -euo pipefail
img=$1 mib=$2 runs=$3 skip=$4
tmp=$(mktemp -d /dev/shm/wr-krbd-bench.XXXXXX)
chmod 700 "$tmp"
dev=""
cleanup() { [ -z "$dev" ] || rbd unmap "$dev" > /dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
ceph auth get "client.$img" -o "$tmp/keyring" > /dev/null 2>&1
chmod 600 "$tmp/keyring"
dev=$(rbd map "winrbd/$img" --id "$img" --keyring "$tmp/keyring")
echo "# mapped winrbd/$img as $dev with the user's own key; kernel $(uname -r); read_ahead_kb at start $(cat /sys/block/$(basename "$dev")/queue/read_ahead_kb)"
bytes=$((mib * 1048576))
pass() { # mode bs run : one timed pass over the range
    local mode=$1 bs=$2 run=$3 flags=skip_bytes,count_bytes t0 t1
    [ "$mode" != direct ] || flags=direct,skip_bytes,count_bytes
    [ "$mode" = direct ] || echo 1 > /proc/sys/vm/drop_caches
    t0=$EPOCHREALTIME
    dd if="$dev" of=/dev/null bs="$bs" iflag="$flags" skip="$skip" count="$bytes" status=none
    t1=$EPOCHREALTIME
    awk -v a="$t0" -v b="$t1" -v m="$mode" -v bs="$bs" -v r="$run" -v n="$bytes" 'BEGIN { s = b - a; printf "KRBD mode=%s bs=%d run=%d bytes=%d secs=%.4f mibs=%.2f\n", m, bs, r, n, s, n / 1048576 / s }'
}
dd if="$dev" of=/dev/null bs=1M iflag=direct,skip_bytes,count_bytes skip="$skip" count="$bytes" status=none   # the warm pass
for mode in direct ra128k ra2048k; do
    case $mode in
        ra128k) blockdev --setra 256 "$dev";;
        ra2048k) blockdev --setra 4096 "$dev";;
    esac
    echo "# mode $mode: readahead $(blockdev --getra "$dev") sectors"
    for bs in 65536 1048576 4194304; do
        dd if="$dev" of=/dev/null bs="$bs" iflag=direct,skip_bytes,count_bytes skip="$skip" count="$bytes" status=none   # warm for this block size
        for run in $(seq 1 "$runs"); do pass "$mode" "$bs" "$run"; done
    done
done
rbd unmap "$dev"
dev=""
echo "# unmapped"
EOS
{
    echo "after t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu)"
    echo "after $(lab_ssh "echo lab_load=\$(cut -d' ' -f1-3 /proc/loadavg) lab_cpu=\$(awk '/^cpu /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat)")"
} >> "$dir/load.txt"
bash "$LABSTATE" snapshot "$dir/lab-after.txt" > /dev/null
bash "$LABSTATE" diff "$dir/lab-before.txt" "$dir/lab-after.txt" > "$dir/lab-diff.txt" 2>&1 || true
n=$(grep -c '^KRBD ' "$dir/krbd.txt" || true)
echo "krbd.sh: $label: rc=$rc, $n passes recorded ($(tail -n 1 "$dir/lab-diff.txt"))"
exit "$rc"
