#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mimages.sh - the bench disks of the exit measurements: make them, put them into the lab, take them out again.
#
#   mimages.sh make [PLAN...]        build $P2M_WORK/img/wrtest-p2-ms-PLAN.raw and .json with mkbench.py (plans: probe read write idle; default all of those);
#                                    lin-uefi and lin-bios are the Linux guests of harness/lab/p2/images built in the builder guest ($P2M_WORK/img-linux/linux-*.raw):
#                                    make hard-links them
#   mimages.sh create PLAN...        import the raw disk into the lab as RBD image wrtest-p2-ms-PLAN (feature layering only), create its throwaway
#                                    cephx user (legacy aes key, caps limited to the pool) and write the key file (mode 600, never printed)
#   mimages.sh reset PLAN...         import the disk again over the same image (--force): the scratch area is zero again (before a copy run)
#   mimages.sh delete PLAN...        remove the image and the user, and the key file
#   mimages.sh delete-all            the same for every wrtest-p2-ms-* image and user (nothing else is touched)
#   mimages.sh list
#
# Environment: P2_LAB_DIR (lab directory), P2M_WORK (work directory; img/ below it), P2M_REPO (a copy of the repository). The names always start with
# wrtest-p2-ms-: images/import.sh refuses anything else, and so does this script.
set -euo pipefail
LC_ALL=C
export LC_ALL

M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_REPO:=$(cd "$M_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?set P2_LAB_DIR}"
: "${P2M_WORK:?set P2M_WORK}"
export LAB_DIR=$P2_LAB_DIR
IMPORT=$P2M_REPO/harness/lab/p2/images/import.sh
P2U=$P2M_REPO/harness/lab/p2/results/uefi/tools/p2u.sh
IMG=$P2M_WORK/img
PLANS="probe read write idle lin-uefi lin-bios"

die() { echo "mimages.sh: $*" >&2; exit 2; }
valid() { case " $PLANS " in *" $1 "*) ;; *) die "unknown plan '$1' (probe read write idle)";; esac; }
nm() { echo "wrtest-p2-ms-$1"; }

lab_ssh() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}

do_make() {
	local p plans
	mkdir -p "$IMG"
	plans=${*:-probe read write idle}
	for p in $plans; do
		valid "$p"
		case $p in
			probe) python3 -I "$M_HERE/mkbench.py" build "$IMG/$(nm probe).raw" --plan probe --data-mib 32 --scratch-mib 6 --json "$IMG/$(nm probe).json";;
			read) python3 -I "$M_HERE/mkbench.py" build "$IMG/$(nm read).raw" --plan read --data-mib 256 --scratch-mib 4 --json "$IMG/$(nm read).json";;
			write) python3 -I "$M_HERE/mkbench.py" build "$IMG/$(nm write).raw" --plan write --data-mib 64 --scratch-mib 64 --write-mib "${P2M_WRITE_MIB:-8}" --json "$IMG/$(nm write).json";;
			idle) python3 -I "$M_HERE/mkbench.py" build "$IMG/$(nm idle).raw" --plan idle --data-mib 256 --scratch-mib 4 --gaps "${P2M_GAPS:-5,40,120,960}" --json "$IMG/$(nm idle).json";;
			lin-uefi | lin-bios) [ -f "$P2M_WORK/img-linux/linux-${p#lin-}.raw" ] && ln -f "$P2M_WORK/img-linux/linux-${p#lin-}.raw" "$IMG/$(nm "$p").raw" || echo "mimages.sh: no $P2M_WORK/img-linux/linux-${p#lin-}.raw" >&2;;
		esac
	done
}

do_create() {
    local p n
    for p in "$@"; do
        valid "$p"
        n=$(nm "$p")
        [ -f "$IMG/$n.raw" ] || die "no disk $IMG/$n.raw (mimages.sh make $p)"
        bash "$IMPORT" import --image "$IMG/$n.raw" --name "$n" --force
        bash "$IMPORT" user-create "$n"
        bash "$P2U" key "$n"
    done
}

do_reset() {
    local p n
    for p in "$@"; do
        valid "$p"
        n=$(nm "$p")
        [ -f "$IMG/$n.raw" ] || die "no disk $IMG/$n.raw"
        bash "$IMPORT" import --image "$IMG/$n.raw" --name "$n" --force
    done
}

do_delete() {
    local p n
    for p in "$@"; do
        valid "$p"
        n=$(nm "$p")
        bash "$IMPORT" delete "$n" || true
        rm -f -- "$P2_LAB_DIR/keys/client.$n.secret"
    done
}

do_list() {
    lab_ssh "sudo rbd ls winrbd | grep '^wrtest-p2-ms-' || true; sudo ceph auth ls 2>/dev/null | grep '^client.wrtest-p2-ms-' || true"
}

cmd=${1:-}
shift || true
case $cmd in
    make) do_make "$@";;
    create) [ $# -ge 1 ] || die "create: which plan?"; do_create "$@";;
    reset) [ $# -ge 1 ] || die "reset: which plan?"; do_reset "$@";;
    delete) [ $# -ge 1 ] || die "delete: which plan?"; do_delete "$@";;
    delete-all) do_delete $PLANS;;
    list) do_list;;
    *) sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
