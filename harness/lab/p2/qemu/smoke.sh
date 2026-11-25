#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 QEMU scripts: the smoke test. It needs no cluster and no key. Per row (firmware + way of delivery) it proves, in this order,
#
#   reaches-ipxe   the firmware starts the iPXE binary  ->  iPXE finds and runs the run script (autoexec.ipxe / stub / initrd)  ->  the
#                  lab NIC (the one with the lab MAC) is there, opens and has link  ->  iPXE leaves (WRRUN-END)
#   driver         the skeleton's firmware test (gen-script.sh --smoke), as it was run by hand before this module existed:
#                    a URI with a password is refused with the driver's own console line "rbd: key material must not be part of the
#                    URI" and "Invalid argument";  a well-formed URI to a monitor that cannot answer fails closed (a SAN device is
#                    never created: "Operation not supported" while opening is not implemented, a connection error once it is);
#                    an unknown scheme is the control and shows iPXE's stock "Operation not supported";  the script ends with SMOKE-DONE
#   san-fails      (--san)  the same failing target through the run script and the lab NIC: WRRUN-SAN-FAILED 0x<number>
#   no-cluster     (--hold) the negative control of the run scripts: nothing answers, the guest is told to hold after the failure, and the
#                  run must end by itself at its timeout (exit 1, stop=timeout) with no process and no file left behind
#
# It does not prove a boot from RBD (that needs the lab cluster: run-*.sh with --pool / --image / --key-file).
#
#   smoke.sh [options] [-- extra run-script options]
#     --rows "U1 U2 U3 B1 B2 B3"   which rows (default: these six, plus B1U when undionly-stub.kpxe is in the iPXE directory).
#                                  B1U is B1 with undionly-stub.kpxe: UNDI drives only the NIC PXE booted from, so the lab NIC must be
#                                  invisible (WRRUN-NO-LAB-NIC): the run proves that, and that the script still runs
#     --ipxe-dir DIR               the built iPXE files (default $P2Q_IPXE_DIR, else $P2Q_WORK/ipxe)
#     --no-driver                  skip the driver pass
#     --san                        also run the san-fails pass of every row
#     --hold                       also run the no-cluster pass of every row (takes --hold-timeout seconds per row)
#     --hold-timeout S             the timeout of the no-cluster pass (default 40)
#     --timeout S                  per run (default 150)
#     -n                           print what would run, start nothing
#   Environment: the P2Q_* variables of common.sh (P2Q_WORK, P2Q_BUDGET_ROOT, P2Q_OVMF_CODE, ...).
#
# Exit status: 0 every run met its expectation; 1 some did not; 2 usage / environment.
# The table at the end lists, per run, the seconds to each stage (iPXE up / lab link / SAN verdict / script end).
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

die() { echo "smoke.sh: $*" >&2; exit 2; }

rows="" ipxe_dir="" san=0 driver=1 hold=0 hold_timeout=40 timeout_s=150 dry=0
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) awk 'NR >= 3 && /^#/ { sub(/^# ?/, ""); print; next } NR >= 3 { exit }' "${BASH_SOURCE[0]}"; exit 0;;
        --rows) [ $# -ge 2 ] || die "--rows needs a list"; rows=$2; shift 2;;
        --ipxe-dir) [ $# -ge 2 ] || die "--ipxe-dir needs a directory"; ipxe_dir=$2; shift 2;;
        --san) san=1; shift;;
        --no-driver) driver=0; shift;;
        --hold) hold=1; shift;;
        --hold-timeout) [ $# -ge 2 ] || die "--hold-timeout needs seconds"; hold_timeout=$2; shift 2;;
        --timeout) [ $# -ge 2 ] || die "--timeout needs seconds"; timeout_s=$2; shift 2;;
        -n|--dry-run) dry=1; shift;;
        --) shift; break;;
        *) die "unknown option $1 (see --help)";;
    esac
done
[[ "$timeout_s" =~ ^[0-9]{1,4}$ ]] || die "--timeout must be a number of seconds"
[[ "$hold_timeout" =~ ^[0-9]{1,4}$ ]] || die "--hold-timeout must be a number of seconds"
extra=("$@")

ipxe_dir_eff=${ipxe_dir:-${P2Q_IPXE_DIR:-${P2Q_WORK:-${HOME:-/tmp}/winrbd-p2-qemu}/ipxe}}
if [ -z "$rows" ]; then
    rows="U1 U2 U3 B1 B2 B3"
    if [ -r "$ipxe_dir_eff/undionly-stub.kpxe" ]; then rows="$rows B1U"; fi
fi

script_of() {
    case "$1" in
        U1) echo run-uefi-pxe.sh;; U2) echo run-uefi-usb.sh;; U3) echo run-uefi-iso.sh;;
        B1|B1U) echo run-bios-pxe.sh;; B2) echo run-bios-usb.sh;; B3) echo run-bios-iso.sh;;
        *) return 1;;
    esac
}

common=()
[ -z "$ipxe_dir" ] || common+=(--ipxe-dir "$ipxe_dir")
[ "$dry" = 0 ] || common+=(-n)

work=""
cleanup() { # fixed names only
    [ -n "$work" ] && [ -d "$work" ] || return 0
    rm -f "$work/smoke.ipxe"
    rmdir "$work" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
smoke_script=""
if [ "$driver" = 1 ]; then
    work=$(mktemp -d "${TMPDIR:-/tmp}/wr-p2q-smoke.XXXXXX") || die "cannot make a temporary directory"
    chmod 700 "$work"
    "$here/gen-script.sh" --smoke -o "$work/smoke.ipxe" || exit 2
    smoke_script=$work/smoke.ipxe
fi

total=0 failed=0
table=()
want_rc=0 want_stop="" want_check=""

# The console text of a run (carriage returns and escape sequences removed), from the RESULT line's console=
console_text() { # RESULT-LINE
    local f
    f=$(printf '%s\n' "$1" | sed -n 's/.* console=\([^ ]*\)$/\1/p')
    [ -n "$f" ] && [ -r "$f" ] || return 1
    tr -d '\r\000' < "$f" | LC_ALL=C sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b[()][A-Z0-9]//g'
}

# check_driver CONSOLE: every line of the skeleton's smoke test, and nothing that says a SAN device was created
check_driver() {
    local txt=$1 miss="" pat
    for pat in 'rbd: key material must not be part of the URI' 'refused: 0x[0-9a-f]+' 'Invalid argument' \
               'failed closed: 0x[0-9a-f]+' 'control: 0x[0-9a-f]+' 'Operation not supported' '^SMOKE-DONE'; do
        printf '%s\n' "$txt" | grep -a -q -E -- "$pat" || miss="$miss [$pat]"
    done
    if printf '%s\n' "$txt" | grep -a -q 'WRSMOKE-FAIL'; then
        miss="$miss [$(printf '%s\n' "$txt" | grep -a -o 'WRSMOKE-FAIL [a-z-]*' | head -n 1)]"
    fi
    [ -z "$miss" ] || { echo "smoke: the console is missing / has:$miss" >&2; return 1; }
}

# check_nolab CONSOLE: the UNDI row: the lab NIC must be invisible
check_nolab() { printf '%s\n' "$1" | grep -a -q 'WRRUN-NO-LAB-NIC' || { echo "smoke: B1U: WRRUN-NO-LAB-NIC is missing (UNDI should not see the lab NIC)" >&2; return 1; }; }

run_one() { # ROW LABEL args...      (want_rc / want_stop / want_check are read and reset)
    local row=$1 label=$2 s out res rc ok=1 txt wrc=$want_rc wstop=$want_stop wcheck=$want_check
    shift 2
    want_rc=0 want_stop="" want_check=""
    s=$(script_of "$row") || die "unknown row '$row' (U1 U2 U3 B1 B1U B2 B3)"
    total=$((total + 1))
    echo "== $row $label" >&2
    local rowargs=()
    if [ "$row" = B1U ]; then rowargs=(--bin "$ipxe_dir_eff/undionly-stub.kpxe" --delivery stub); fi
    # (stdout of a run script is its RESULT line, or the plan with -n; the progress lines go to stderr as they come. Not `tee /dev/stderr`:
    # opening /dev/stderr anew truncates a log file that stderr was redirected to.)
    out=$("$here/$s" --row "$row" --timeout "$timeout_s" ${common[@]+"${common[@]}"} ${rowargs[@]+"${rowargs[@]}"} "$@" ${extra[@]+"${extra[@]}"}) && rc=0 || rc=$?
    printf '%s\n' "$out" >&2
    res=$(printf '%s\n' "$out" | tail -n 1)
    if [ "$dry" = 1 ]; then
        [ "$rc" -eq 0 ] || failed=$((failed + 1))
        return 0
    fi
    case "$res" in
        RESULT*) ;;
        *) res="RESULT row=$row met=0 stop=no-result-line (exit $rc)"; ok=0;;
    esac
    [ "$rc" -eq "$wrc" ] || ok=0
    if [ -n "$wstop" ]; then case "$res" in *" stop=$wstop "*) ;; *) ok=0; echo "smoke: wanted stop=$wstop" >&2;; esac; fi
    if [ "$ok" = 1 ] && [ -n "$wcheck" ]; then
        if txt=$(console_text "$res"); then "$wcheck" "$txt" || ok=0; else echo "smoke: no console log to check" >&2; ok=0; fi
    fi
    [ "$ok" = 1 ] || failed=$((failed + 1))
    table+=("$(printf '%-3s %-15s %-4s rc=%s %s' "$row" "$label" "$([ "$ok" = 1 ] && echo ok || echo FAIL)" "$rc" "$res")")
}

for r in $rows; do
    if [ "$r" = B1U ]; then
        want_check=check_nolab run_one "$r" lab-nic-hidden --expect ipxe --no-key --action none
    else
        run_one "$r" reaches-ipxe --expect ipxe --no-key --action none
    fi
    if [ "$driver" = 1 ]; then
        want_check=check_driver run_one "$r" driver --script "$smoke_script" --expect marker --marker '^SMOKE-DONE' --no-key
    fi
    if [ "$san" = 1 ] && [ "$r" != B1U ]; then
        # nothing answers at .253: the open must fail by itself (timeout=3 seconds), with the error number in the console
        run_one "$r" san-fails --pool smoke --image none --mon 10.77.0.253:3300 --fake-key --opt timeout=3 \
            --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+'
    fi
    if [ "$hold" = 1 ] && [ "$r" != B1U ]; then
        # the negative control: no cluster, the guest holds after the failure and never reaches the expected stage; the run must
        # end by itself at its timeout, with exit status 1 (not 4: nothing left behind)
        want_rc=1 want_stop=timeout run_one "$r" no-cluster --pool smoke --image none --mon 10.77.0.253:3300 --fake-key --opt timeout=3 \
            --on-fail hold --expect os --stay --timeout "$hold_timeout"
    fi
done

if [ "$dry" = 1 ]; then exit 0; fi

# nothing of ours may still run (the run scripts check their own guest; this looks at the whole work directory)
left=""
if command -v pgrep >/dev/null 2>&1; then
    left=$(pgrep -f -- '-name wrp2q-' 2>/dev/null | tr '\n' ' ' || true)
    if [ -n "$left" ]; then
        # other runs of other people may exist: only a guest whose command line names our work directory counts
        mine=""
        for pid in $left; do
            if ps -ww -o args= -p "$pid" 2>/dev/null | grep -F -q -- "${P2Q_WORK:-${HOME:-/tmp}/winrbd-p2-qemu}/runs/"; then mine="$mine $pid"; fi
        done
        left=$mine
    fi
fi
if [ -n "${left// /}" ]; then
    echo "smoke: guest process(es) still alive:$left" >&2
    failed=$((failed + 1))
    total=$((total + 1))
fi
echo
echo "smoke: $((total - failed)) of $total runs met their expectation"
for line in ${table[@]+"${table[@]}"}; do echo "  $line"; done
[ "$failed" -eq 0 ]
