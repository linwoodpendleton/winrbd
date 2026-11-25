#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# matrix.sh - the rows of milestone 7 (design section 14.3, "robustness rows", run on U1 and B1) and what each proves. Runs rr.sh for each.
#
#   matrix.sh list                        the rows, one line each, with what they do
#   matrix.sh [-n] run NAME|GROUP...      run rows (groups: ctl mon osd pause link stall outage neg boot-all bytes reader boot all)
#   matrix.sh rejudge [NAME...]          judge existing evidence directories again (the analysis rules changed, the run did not); all rows when none is named
#   matrix.sh oracle WHEN                 hash `rbd export` of every image of the rows and compare with what was imported (WHEN: start | end); writes
#                                         $P2R_OUT/../oracle-WHEN.txt. The images are read only for the guests: the two files must be equal.
#   matrix.sh cleanup                     delete the four throwaway images and users of the rows (and their key files), then snapshot the lab and compare it with the
#                                         snapshot taken before they were made ($P2R_OUT/../lab-base.txt): the difference must be empty
#   matrix.sh summarize                   MATRIX.md from the verdicts under $P2R_OUT
#
# Row names: <family>-<workload>-<fault>, family U1 (OVMF + PXE, ipxe.efi) or B1 (SeaBIOS + PXE, ipxe.pxe); workload bytes (U1: the byte-check disk through the
# firmware's file system driver), reader (B1: the INT 13h reader of tools/reader.S) or boot (the Linux guest). Environment as rr.sh.
set -euo pipefail
LC_ALL=C
export LC_ALL
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RR=$HERE/rr.sh

# name | family | workload | options of rr.sh | what it shows
read -r -d '' ROWS <<'TABLE' || true
U1-bytes-ctl|uefi|bytes|--fault none|control: the byte check with no fault (the baseline of every U1 bytes row)
U1-bytes-mon|uefi|bytes|--fault mon-kill --on '^WRBYTES-FILE f-17m' --delay 0 --down 20|a: the monitor is killed during the read and started 20 s later
U1-bytes-mon-short|uefi|bytes|--fault mon-kill --on '^WRBYTES-FILE f-17m' --delay 0 --down 2|a: the monitor is killed and started again 2 s later, inside the read
U1-bytes-mon-osd|uefi|bytes|--fault mon-osd --on '^WRBYTES-FILE f-17m' --delay 0 --down 15|a+b: the monitor is killed, then osd.1: with no monitor nobody can mark the OSD down or publish a map; the monitor is back after 15 s, the OSD 10 s later
U1-bytes-osd-short|uefi|bytes|--fault osd-kill --on '^WRBYTES-FILE f-17m' --delay 0 --down 8|b: osd.1 killed during the read, back after 8 s (before the cluster marks it down)
U1-bytes-osd-long|uefi|bytes|--fault osd-kill --on '^WRBYTES-FILE f-17m' --delay 0 --down 45|b: osd.1 killed, down 45 s (marked down, PGs re-peer, the client changes primaries and back)
U1-bytes-pause|uefi|bytes|--fault pause --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 60|c: the guest is stopped for 60 s in the middle of the read (the idle gap: nothing in the guest runs, the cluster goes on)
U1-bytes-idle|uefi|bytes|--fault pause --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 60 --idle-timeout 20|c: the same pause, with the daemons told to close connections idle for 20 s: the first command after the gap must reconnect and authenticate again
U1-bytes-link|uefi|bytes|--fault link-down --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 40|d: the guest's lab NIC is cut for 40 s
U1-bytes-stall20|uefi|bytes|--fault stall --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 20|f: every OSD stopped for 20 s: the SAN layer's 15 s command timeout fires, the driver's 30 s watchdog does not
U1-bytes-stall40|uefi|bytes|--fault stall --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 40|f: every OSD stopped for 40 s: command timeout and watchdog (path closed, reopened against the cached session)
U1-bytes-outage|uefi|bytes|--fault outage --on '^WRBYTES-FILE f-17m' --delay 0.5 --down 420 --timeout 1500|e: the cluster is gone for 7 minutes: the SAN layer retries and gives up, then the cluster comes back
B1-reader-ctl|bios|reader|--fault none|control: the INT 13h read with no fault
B1-reader-mon|bios|reader|--fault mon-kill --on '^WRRB-START' --delay 1 --down 20|a
B1-reader-mon-short|bios|reader|--fault mon-kill --on '^WRRB-START' --delay 1 --down 2|a
B1-reader-mon-osd|bios|reader|--fault mon-osd --on '^WRRB-START' --delay 1 --down 15|a+b
B1-reader-osd-short|bios|reader|--fault osd-kill --on '^WRRB-START' --delay 1 --down 8|b
B1-reader-osd-long|bios|reader|--fault osd-kill --on '^WRRB-START' --delay 1 --down 45|b
B1-reader-pause|bios|reader|--fault pause --on '^WRRB-START' --delay 1 --down 60|c
B1-reader-idle|bios|reader|--fault pause --on '^WRRB-START' --delay 1 --down 60 --idle-timeout 20|c
B1-reader-link|bios|reader|--fault link-down --on '^WRRB-START' --delay 1 --down 40|d
B1-reader-stall20|bios|reader|--fault stall --on '^WRRB-START' --delay 1 --down 20|f
B1-reader-stall40|bios|reader|--fault stall --on '^WRRB-START' --delay 1 --down 40|f
B1-reader-outage|bios|reader|--fault outage --on '^WRRB-START' --delay 1 --down 420 --timeout 1500|e
U1-boot-ctl|uefi|boot|--fault none --on 'before booting or' --press ret --press-delay 1|control: the Linux guest boots (Enter at GRUB's menu so that the kernel load starts at a known moment)
U1-boot-mon|uefi|boot|--fault mon-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 20|a: the monitor is killed during the kernel load
U1-boot-mon-short|uefi|boot|--fault mon-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 2|a: the monitor is killed and restarted 2 s later, inside the kernel load
U1-boot-mon-osd|uefi|boot|--fault mon-osd --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 15|a+b: no monitor, then no OSD, during the kernel load
U1-boot-osd-esp|uefi|boot|--fault osd-kill --on '^Booting from SAN device' --delay 0.3 --down 45|b: osd.1 killed while the firmware reads the ESP and GRUB
U1-boot-osd-kernel|uefi|boot|--fault osd-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 45|b: osd.1 killed during the kernel load
U1-boot-pause|uefi|boot|--fault pause --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 60|c: the guest is stopped for 60 s during the kernel load
U1-boot-idle|uefi|boot|--fault pause --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 60 --idle-timeout 20|c: pause during the kernel load with the idle timeout lowered
U1-boot-link|uefi|boot|--fault link-down --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 40|d: the lab NIC is cut for 40 s during the kernel load
U1-boot-stall20|uefi|boot|--fault stall --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 20|f: every OSD stopped for 20 s during the kernel load
U1-boot-outage|uefi|boot-outage|--fault outage --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 330 --timeout 900|e: the cluster is gone for 5.5 minutes while the kernel loads: the real loader's reaction when the SAN layer gives up
B1-boot-ctl|bios|boot|--fault none --on 'before booting or' --press ret --press-delay 1|control
B1-boot-mon|bios|boot|--fault mon-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 20|a
B1-boot-mon-short|bios|boot|--fault mon-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 2|a
B1-boot-mon-osd|bios|boot|--fault mon-osd --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 15|a+b
B1-boot-osd-esp|bios|boot|--fault osd-kill --on '^Booting from SAN device' --delay 0.3 --down 45|b
B1-boot-osd-kernel|bios|boot|--fault osd-kill --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 45|b
B1-boot-pause|bios|boot|--fault pause --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 60|c
B1-boot-idle|bios|boot|--fault pause --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 60 --idle-timeout 20|c
B1-boot-link|bios|boot|--fault link-down --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 40|d
B1-boot-stall20|bios|boot|--fault stall --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 20|f
B1-boot-outage|bios|boot-outage|--fault outage --on 'before booting or' --press ret --press-delay 1 --delay 1.2 --down 330 --timeout 900|e
U1-neg-key|uefi|neg-key||e: a key the cluster does not accept
U1-neg-pool|uefi|neg-pool||e: a pool that does not exist
U1-neg-image|uefi|neg-image||e: an image that does not exist
U1-neg-mon|uefi|neg-mon||e: a monitor address nobody answers on
B1-neg-key|bios|neg-key||e
B1-neg-pool|bios|neg-pool||e
B1-neg-image|bios|neg-image||e
B1-neg-mon|bios|neg-mon||e
TABLE

die() { echo "matrix.sh: $*" >&2; exit 2; }

names_of() { printf '%s\n' "$ROWS" | cut -d'|' -f1; }

group() {
    case $1 in
        all) names_of;;
        bytes) names_of | grep -E '^U1-bytes-';;
        reader) names_of | grep -E '^B1-reader-';;
        boot) names_of | grep -E -- '-boot-' | grep -v -- '-outage$';;
        neg) names_of | grep -E -- '-neg-';;
        ctl) names_of | grep -E -- '-ctl$';;
        mon | osd | pause | idle | link | stall | outage) names_of | grep -E -- "-$1(-|\$)";;
        *) if names_of | grep -q -x -- "$1"; then echo "$1"; else die "no row or group '$1' (matrix.sh list)"; fi;;
    esac
}

cmd_list() {
    printf '%s\n' "$ROWS" | awk -F'|' '{ printf "%-22s %-5s %-7s %s\n", $1, $2, $3, $5 }'
}

cmd_run() {
    local dry=0 n sel=() line name fam wl opts desc
    if [ "${1:-}" = -n ]; then dry=1; shift; fi
    [ $# -ge 1 ] || die "run what? (a row name or a group; matrix.sh list)"
    for n in "$@"; do
        # (die inside the process substitution below would not stop this shell: look the name up first)
        case $n in all | bytes | reader | boot | neg | ctl | mon | osd | pause | idle | link | stall | outage) ;; *) names_of | grep -q -x -- "$n" || die "no row or group '$n' (matrix.sh list)";; esac
        while IFS= read -r line; do sel+=("$line"); done < <(group "$n")
    done
    for name in "${sel[@]}"; do
        line=$(printf '%s\n' "$ROWS" | grep -E "^$name\|")
        IFS='|' read -r name fam wl opts desc <<< "$line"
        local words=()
        eval "words=($opts)"
        if [ "$dry" = 1 ]; then echo "== $name"; bash "$RR" row "$name" --family "$fam" --workload "$wl" --capture --note "$desc" --dry "${words[@]}"; continue; fi
        bash "$RR" row "$name" --family "$fam" --workload "$wl" --capture --note "$desc" "${words[@]}" || true
    done
}

# the images of the rows and what they were imported from
cmd_oracle() {
    local when=${1:?usage: matrix.sh oracle start|end} out img want got
    : "${P2R_OUT:?}" "${P2_LAB_DIR:?}" "${P2R_IMAGES:?}"
    out=$P2R_OUT/../oracle-$when.txt
    : > "$out"
    for img in rb-bytes rb-reader rb-lin-uefi rb-lin-bios; do
        case $img in
            rb-bytes) want=$(sed -n 's/^image_sha256=//p' "$P2R_IMAGES/bytes/bytes.manifest");;
            rb-reader) want=$(cut -d' ' -f1 "$P2R_IMAGES/reader.raw.sha256");;
            rb-lin-uefi) want=$(sed -n 's/^image_sha256[= ]//p' "$P2R_IMAGES/lin/linux-uefi.raw.manifest");;
            rb-lin-bios) want=$(sed -n 's/^image_sha256[= ]//p' "$P2R_IMAGES/lin/linux-bios.raw.manifest");;
        esac
        got=$(ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" \
            "${LAB_SSH_USER:-lab}@127.0.0.1" "sudo rbd export --no-progress winrbd/wrtest-p2-$img -" | sha256sum | cut -d' ' -f1)
        printf '%s export_sha256=%s imported_sha256=%s %s\n' "wrtest-p2-$img" "$got" "${want:-unknown}" "$([ "$got" = "$want" ] && echo EQUAL || echo DIFFERENT)" | tee -a "$out"
    done
}

cmd_cleanup() {
    : "${P2R_OUT:?}" "${P2_LAB_DIR:?}" "${P2R_REPO:?}"
    local img base=$P2R_OUT/../lab-base.txt
    [ -s "$base" ] || die "no $base: the state of the lab before the rows (labstate.sh snapshot) is the reference"
    for img in rb-bytes rb-reader rb-lin-uefi rb-lin-bios; do
        bash "$P2R_REPO/harness/lab/p2/images/import.sh" delete "wrtest-p2-$img" || echo "matrix.sh: could not delete wrtest-p2-$img" >&2
        rm -f -- "$P2_LAB_DIR/keys/client.wrtest-p2-$img.secret"
    done
    bash "$HERE/labstate.sh" snapshot "$P2R_OUT/../lab-final.txt"
    bash "$HERE/labstate.sh" diff "$base" "$P2R_OUT/../lab-final.txt" | tee "$P2R_OUT/../lab-restore-diff.txt"
}

cmd_rejudge() {
    : "${P2R_OUT:?}"
    local n line name fam wl opts desc fault prof sel=()
    if [ $# -eq 0 ]; then while IFS= read -r n; do [ ! -d "$P2R_OUT/$n" ] || sel+=("$n"); done < <(names_of); else sel=("$@"); fi
    for n in "${sel[@]}"; do
        line=$(printf '%s\n' "$ROWS" | grep -E "^$n\|") || die "no row $n"
        IFS='|' read -r name fam wl opts desc <<< "$line"
        fault=none
        case $opts in *"--fault "*) fault=${opts#*--fault }; fault=${fault%% *};; esac
        case $wl in bytes) prof=bytes;; reader) prof=reader;; boot) prof=boot;; boot-outage) prof=bootgive;; *) prof=negative;; esac
        [ -d "$P2R_OUT/$n" ] || die "no evidence directory $P2R_OUT/$n"
        python3 -I "$HERE/analyze.py" --profile "$prof" --workload "$wl" --fault "$fault" --family "$fam" --expect-dir "$HERE/../expect" --dir "$P2R_OUT/$n" > "$P2R_OUT/$n/verdict.txt.new"
        # a row whose files were deleted because they held the run's own key keeps that failure: the analysis cannot see a key that is no longer there
        if grep -q '^FAIL secret scan' "$P2R_OUT/$n/verdict.txt" 2>/dev/null && ! grep -q '^FAIL secret scan' "$P2R_OUT/$n/verdict.txt.new"; then
            { echo FAIL; grep '^FAIL secret scan' "$P2R_OUT/$n/verdict.txt"; tail -n +2 "$P2R_OUT/$n/verdict.txt.new"; } > "$P2R_OUT/$n/verdict.txt.new2"
            mv -f "$P2R_OUT/$n/verdict.txt.new2" "$P2R_OUT/$n/verdict.txt.new"
        fi
        mv -f "$P2R_OUT/$n/verdict.txt.new" "$P2R_OUT/$n/verdict.txt"
        echo "matrix.sh: $n: $(head -n 1 "$P2R_OUT/$n/verdict.txt") (judged again)"
    done
}

cmd_summarize() {
    : "${P2R_OUT:?}"
    python3 -I "$HERE/summarize.py" "$P2R_OUT"
}

case ${1:-} in
    list) cmd_list;;
    run) shift; cmd_run "$@";;
    oracle) shift; cmd_oracle "$@";;
    cleanup) cmd_cleanup;;
    rejudge) shift; cmd_rejudge "$@";;
    summarize) cmd_summarize;;
    *) sed -n '3,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
