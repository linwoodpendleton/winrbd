#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# campaign.sh - the series of runs of the exit measurements, in the order they were made (each is one mrun.sh row; a failed run is kept and counted).
#
#   campaign.sh read [N]       N (default 3) runs of the read plan with the default readahead and with readahead=0, interleaved (default, 0, default, 0, ...)
#   campaign.sh inst [N]       N runs of the read plan with the instrumented build (stack monitor, DEBUG=malloc), default readahead
#   campaign.sh write [N]      N runs of the write plan (a copy: read a command's worth, write it), the image put back before each, with a capture
#   campaign.sh netem MS... [N]   the write plan with MS milliseconds of added delay for each MS, N runs each
#   campaign.sh krbd [N]       N runs of the kernel client in a Linux guest on the guests' own layer 2 (mguest.sh: the same path as the iPXE guests), and N
#                              runs of the kernel client inside the lab VM (krbd.sh: the cluster's own host, loopback path), alternating
#   campaign.sh redo           the replacements of the two runs that the machine spoiled: rd-def-4 (the lab's daemons were restarted by an unattended upgrade
#                              inside rd-def-3: session resets in its rbd-info) and inst-4 (inst-1 never got a cluster: the lab VM was stalled)
#   campaign.sh ra [N]         N runs of the read plan for each readahead size of 256, 512, 1024 and 4096 KiB (the default, 2,048, and 0 are the "read" series)
#   campaign.sh idle [N]       N runs of the idle plan with the daemons' default idle timeout, and N with ms_connection_idle_timeout 10 s
#   campaign.sh heap [N]       N runs of the instrumented BIOS build that never hooks an image (the heap baseline of iPXE's own users), and of the same build with
#                              the probe image hooked (what the driver adds)
#   campaign.sh r10 [HOOKS]    the R10 tests: HOOKS (default 150) hooks in one iPXE session and three hooks after the session cache's grace, in a guest with 64 MiB;
#                              then a hook in guests with less and less memory (24, 16, 12, 10, 8, 6 MiB)
#   campaign.sh efi [N]        N boots of the Linux guest (row U1) with the instrumented ipxe.efi (DEBUG=malloc): iPXE's heap maximum on UEFI, printed when the
#                              boot loader calls ExitBootServices
#   campaign.sh winpe [N]      N boots of the owner's WinPE image per row W1 (UEFI PXE), W2 (UEFI USB), W3 (BIOS PXE), W4 (BIOS USB), to the line WINRBD-WINPE-OK on COM1
#   campaign.sh r10mem [MB...] a hook in guests of the given memory (default 8 6); r10leak [MB]: 5 sessions created and destroyed in a guest of MB (default 20) MiB
#   campaign.sh efiheap [N]    N runs that hook the Linux guest's image with the instrumented ipxe.efi, read the ESP's boot loader and exit (iPXE then prints its heap maximum)
#   campaign.sh login [N]      N boots of the Linux guest of each row U1, U2, U3, B1, B2, B3 (time to login), interleaved, in the order U1 B1 U2 B2 U3 B3
#
# Environment: as mrun.sh (source box-env). Output: $P2M_OUT/<name>-<n>. The runs of one series run one after the other, so the cluster is never shared
# between two guests of this campaign, except in "idle", where the guests are asleep for most of their time (they run side by side, see below).
set -uo pipefail
M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_WORK:?}" "${P2M_OUT:?}"
BIN=$P2M_WORK/bin
IMG=$P2M_WORK/img
ssh_lab() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}
log() { echo "campaign: $(date -u +%H:%M:%S) $*"; }
row() { bash "$M_HERE/mrun.sh" row "$@" || log "row $1 returned $?"; }
gate() { # wait (up to 20 minutes) until the lab answers quickly, its load is low and the cluster is clean: a run started into a stalled lab measures the stall
    local i h l t0 t1
    for i in $(seq 1 40); do
        t0=$(date +%s%N)
        l=$(ssh_lab "cut -d' ' -f1 /proc/loadavg" 2> /dev/null) || l=""
        t1=$(date +%s%N)
        h=$(bash "$M_HERE/../../robust/tools/labstate.sh" health 2> /dev/null | head -n 1)
        if [ -n "$l" ] && [ $(((t1 - t0) / 1000000)) -lt 3000 ] && awk -v l="$l" 'BEGIN { exit !(l < 4.0) }' && case $h in *"3 osds: 3 up"*"3 in"*"active+clean"*) true;; *) false;; esac; then
            return 0
        fi
        [ "$i" != 1 ] || log "waiting for the lab (load ${l:-?}, ssh $(((t1 - t0) / 1000000)) ms): ${h:-no health}"
        sleep 30
    done
    log "WARNING: the lab was not quiet after 20 minutes; going on"
}

what=${1:-}
shift || true
case $what in
    read)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate; row "rd-def-$i" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 900 --oct 61
            gate; row "rd-ra0-$i" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 1500 --oct 61 --opt readahead=0
        done;;
    inst)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate; row "inst-$i" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 900 --oct 62 --exit --note "instrumented build: stack monitor, DEBUG=malloc"
        done;;
    write)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            bash "$M_HERE/mimages.sh" reset write > /dev/null
            gate; row "wr-d0-$i" --image wrtest-p2-ms-write --plan "$IMG/wrtest-p2-ms-write.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 1800 --oct 63 --capture
        done;;
    netem)
        ms=()
        while [ $# -gt 1 ]; do ms+=("$1"); shift; done
        n=${1:-3}
        for d in "${ms[@]}"; do
            for i in $(seq 1 "$n"); do
                bash "$M_HERE/mimages.sh" reset write > /dev/null
                gate; row "wr-d$d-$i" --image wrtest-p2-ms-write --plan "$IMG/wrtest-p2-ms-write.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 2400 --oct 63 --capture --netem "$d"
            done
        done;;
    krbd)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate; bash "$M_HERE/mguest.sh" row "kg-$i" --image wrtest-p2-ms-read --oct 64 --runs 3 || log "kg-$i returned $?"
            gate; bash "$M_HERE/krbd.sh" run "krbd-$i" --image wrtest-p2-ms-read || log "krbd-$i returned $?"
        done;;
    redo)
        gate; row "inst-4" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 900 --oct 62 --exit --note "replaces inst-1 (the lab VM was stalled)"
        gate; row "rd-def-4" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 900 --oct 61 --note "replaces rd-def-3 (daemon restart inside the run)";;
    ra)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            for ra in 256 512 1024 4096; do
                gate; row "rd-ra$ra-$i" --image wrtest-p2-ms-read --plan "$IMG/wrtest-p2-ms-read.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 1500 --oct 61 --opt "readahead=$ra"
            done
        done;;
    heap)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate
            log "heap baseline $i"
            bash "$M_HERE/mheapbase.sh" "heap-base-$i" || log "heap-base-$i returned $?"
            gate; row "heap-probe-$i" --image wrtest-p2-ms-probe --plan "$IMG/wrtest-p2-ms-probe.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 600 --oct 62 --exit --note "heap: the probe image hooked and read a little"
        done;;
    r10)
        h=${1:-150}
        bash "$M_HERE/mkloop.sh" wrtest-p2-ms-probe "$h" 3 > "$P2M_WORK/loop.ipxe"
        gate; row "r10-loop-1" --image wrtest-p2-ms-probe --plan "$IMG/wrtest-p2-ms-probe.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 1800 --oct 62 --qemu-mem 64 --append "$P2M_WORK/loop.ipxe" --exit \
            --note "$h hooks in one session, then 3 hooks after the 125 s grace (new sessions), 64 MiB guest"
        bash "$M_HERE/mkloop.sh" wrtest-p2-ms-probe 1 0 > "$P2M_WORK/loop1.ipxe"
        for mb in 24 16 12 10 8 6; do
            gate; row "r10-mem$mb-1" --image wrtest-p2-ms-probe --plan "$IMG/wrtest-p2-ms-probe.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 240 --oct 62 --qemu-mem "$mb" --append "$P2M_WORK/loop1.ipxe" --exit \
                --note "one hook in a guest with $mb MiB"
        done;;
    efi)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate; bash "$M_HERE/mboot.sh" row "heap-efi-$i" --family uefi --via pxe --image wrtest-p2-ms-lin-uefi --oct 65 --bin "$BIN/inst/ipxe.efi" --ipxe-dir "$BIN/inst" \
                --note "instrumented build: DEBUG=malloc" || log "heap-efi-$i returned $?"
        done;;
    winpe)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            for r in uefi/pxe/gpt uefi/usb/gpt bios/pxe/mbr bios/usb/mbr; do
                fam=${r%%/*}
                rest=${r#*/}
                via=${rest%/*}
                lay=${rest#*/}
                w=$([ "$fam" = uefi ] && echo 1 || echo 3)
                [ "$via" = pxe ] || w=$((w + 1))
                gate; bash "$M_HERE/mboot.sh" row "winpe-W$w-$i" --family "$fam" --via "$via" --image "wrtest-p2-ms-winpe-$lay" --oct 66 --no-params --rollback --mem 2048 \
                    --expect-marker 'WINRBD-WINPE-OK' --stage marker --timeout 900 || log "winpe-W$w-$i returned $?"
            done
        done;;
    r10mem)
        # a hook in guests with the given memory (MiB), default 8 and 6 (the rows 24 to 10 are in the r10 series)
        bash "$M_HERE/mkloop.sh" wrtest-p2-ms-probe 1 0 > "$P2M_WORK/loop1.ipxe"
        for mb in "${@:-8 6}"; do
            for m in $mb; do
                gate; row "r10-mem$m-1" --image wrtest-p2-ms-probe --plan "$IMG/wrtest-p2-ms-probe.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 240 --oct 62 --qemu-mem "$m" --append "$P2M_WORK/loop1.ipxe" --exit \
                    --note "one hook in a guest with $m MiB"
            done
        done;;
    r10leak)
        # sessions created and destroyed in a guest too small to hold more than one or two leaked blocks of 4.78 MiB: 20 hooks, 4 grace rounds, in a 20 MiB guest
        bash "$M_HERE/mkloop.sh" wrtest-p2-ms-probe 20 4 > "$P2M_WORK/loopleak.ipxe"
        gate; row "r10-leak-1" --image wrtest-p2-ms-probe --plan "$IMG/wrtest-p2-ms-probe.json" --bin "$BIN/inst/ipxe-stub.pxe" --timeout 1800 --oct 62 --qemu-mem "${1:-20}" --append "$P2M_WORK/loopleak.ipxe" --exit \
            --note "5 sessions created and destroyed in a ${1:-20} MiB guest";;
    efiheap)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            gate; bash "$M_HERE/mheapefi.sh" "heap-efix-$i" || log "heap-efix-$i returned $?"
        done;;
    login)
        n=${1:-3}
        for i in $(seq 1 "$n"); do
            for r in uefi/pxe bios/pxe uefi/usb bios/usb uefi/iso bios/iso; do
                fam=${r%/*}
                via=${r#*/}
                gate; bash "$M_HERE/mboot.sh" row "login-$fam-$via-$i" --family "$fam" --via "$via" --image "wrtest-p2-ms-lin-$fam" --oct 65 || log "login-$fam-$via-$i returned $?"
            done
        done;;
    idle)
        n=${1:-3}
        # the guests of one configuration run side by side: each spends 1,100 s of its 1,150 s asleep, and what is measured is one 64 KiB read after the sleep
        pids=()
        for i in $(seq 1 "$n"); do
            row "idle-def-$i" --image wrtest-p2-ms-idle --plan "$IMG/wrtest-p2-ms-idle.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 1700 --oct $((70 + i)) &
            pids+=($!)
            sleep 20
        done
        wait "${pids[@]}"
        log "default-timeout idle runs done"
        # the daemons close connections that have been idle for 10 s (set once, here; the rows do not touch it, they run side by side)
        ssh_lab "for w in mon osd; do sudo ceph config set \$w ms_connection_idle_timeout 10; done" || { log "could not set the idle timeout"; exit 1; }
        # shellcheck disable=SC2016,SC2154  # the loop variable belongs to the remote shell
        trap 'ssh_lab "for w in mon osd; do sudo ceph config rm \$w ms_connection_idle_timeout; done"' EXIT
        pids=()
        for i in $(seq 1 "$n"); do
            row "idle-t10-$i" --image wrtest-p2-ms-idle --plan "$IMG/wrtest-p2-ms-idle.json" --bin "$BIN/rel/ipxe-stub.pxe" --timeout 1700 --oct $((70 + i)) --note "ms_connection_idle_timeout 10 s on mon and osd" &
            pids+=($!)
            sleep 20
        done
        wait "${pids[@]}"
        ssh_lab "for w in mon osd; do sudo ceph config rm \$w ms_connection_idle_timeout; done" && trap - EXIT
        log "10 s idle-timeout runs done"
        ;;
    *) sed -n '3,38p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
