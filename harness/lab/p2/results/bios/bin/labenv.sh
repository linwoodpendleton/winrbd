# SPDX-License-Identifier: MIT
# labenv.sh - the environment of the qemu-bios scripts (source it). Everything is a variable with a default; nothing here is secret.
#   P2B_WORK    work directory on the build machine (iPXE binaries in $P2B_WORK/out/<variant>/, images in img/, the params files in params/)
#   LAB_DIR     the dedicated lab (harness/lab/p2/cluster): its ssh key and port reach the lab VM, its keys/ hold the throwaway users' keys
#   P2Q_WORK    work directory of the QEMU run scripts (run directories, logs)
# shellcheck shell=bash
b_bin=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
b_p2=$(cd "$b_bin/../../.." && pwd)
: "${P2B_WORK:=$HOME/winrbd-p2-bios}"
: "${LAB_DIR:?LAB_DIR must name the lab directory}"
: "${P2Q_WORK:=$P2B_WORK/work}"
export P2B_WORK LAB_DIR P2Q_WORK P2_LAB_DIR=${P2_LAB_DIR:-$LAB_DIR}
: "${LAB_SSH_PORT:=22232}" "${LAB_SSH_USER:=lab}"

# lab COMMAND... : run a command line in the lab VM (one string)
lab() {
    ssh -p "$LAB_SSH_PORT" -i "$LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new \
        -o "UserKnownHostsFile=$LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "$LAB_SSH_USER@127.0.0.1" "$@" </dev/null
}
# image_id POOL/IMAGE : the id of the RBD image (the handoff table carries it)
image_id() { lab "sudo rbd info $1 --format json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
# lab_health : one word per line: HEALTH, osds up, osds in
lab_health() {
    lab "sudo ceph health | cut -d' ' -f1; sudo ceph osd stat --format json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[\"num_up_osds\"], d[\"num_in_osds\"], d[\"num_osds\"])'"
}
