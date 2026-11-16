#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Run INSIDE the lab VM, as root. Oracle check: map the v1 test image with
# krbd under both msgr2 modes, write a pattern, read it back, unmap.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
lab_load_conf; lab_defaults
[ "$(id -u)" = 0 ] || die "run as root"
img="$LAB_POOL/${1:-img-v1}"
kr="/etc/ceph/ceph.client.$LAB_CEPHX_KRBD_ID.keyring"
fail=0
for mode in crc secure; do
    info "krbd map $img ms_mode=$mode"
    dev=$(rbd map -n "client.$LAB_CEPHX_KRBD_ID" --keyring "$kr" -o "ms_mode=$mode" "$img")
    # Pattern: 1 MiB of a repeating counter at offset 0 and at 1 GiB.
    if python3 - "$dev" <<'PY'
import hashlib, os, sys
dev = sys.argv[1]
blk = bytes((i * 7 + 3) & 0xFF for i in range(1 << 20))
fd = os.open(dev, os.O_RDWR | os.O_SYNC)
for off in (0, 1 << 30):
    os.pwrite(fd, blk, off)
os.fsync(fd); os.close(fd)
os.system("echo 3 > /proc/sys/vm/drop_caches")
fd = os.open(dev, os.O_RDONLY)
ok = all(os.pread(fd, len(blk), off) == blk for off in (0, 1 << 30))
os.close(fd)
print("pattern readback:", "OK" if ok else "MISMATCH", hashlib.sha256(blk).hexdigest()[:16])
sys.exit(0 if ok else 1)
PY
    then rc=0; else rc=1; fi
    cat /sys/kernel/debug/ceph/*/client_options 2>/dev/null || true
    rbd unmap "$dev" || fail=1
    [ "$rc" = 0 ] || fail=1
    echo "ms_mode=$mode: $([ "$rc" = 0 ] && echo PASS || echo FAIL)"
done
exit "$fail"
