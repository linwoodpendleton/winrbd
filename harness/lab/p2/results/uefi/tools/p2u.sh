#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# p2u.sh - run ONE row of the UEFI live matrix (docs/design/ipxe-driver.md, section 14.3) and leave an evidence directory behind.
#
#   p2u.sh row NAME KIND [--profile P] [--expect-file F] [--no-retry] -- RUN-SCRIPT-ARGS...
#
#     NAME      the row's directory name, e.g. U1-vendor (a directory of that name is made below $P2U_OUT; an existing one is refused)
#     KIND      uefi-pxe | uefi-usb | uefi-iso      (which of harness/lab/p2/qemu/run-<KIND>.sh to run)
#     --profile what the analysis requires (analyze.py): shell | boot | san | bytes | negative | smoke
#     --expect-file F   a file of "key=value" lines for the analysis (analyze.py documents them: errno, console line, ...)
#     RUN-SCRIPT-ARGS   everything after "--" goes to the run script unchanged (the key is a --key-file path, never a key)
#
#   p2u.sh rejudge NAME PROFILE [EXPECT-FILE]   judge one existing evidence directory again (the rules changed, the run did not)
#   p2u.sh rejudge-all ROWSDIR EXPECTDIR        the same for every row below ROWSDIR: the profile is the one cmdline.txt names (the HTTP-* control rows were
#                                               first judged as "smoke" and are judged as "control"), the expect file is EXPECTDIR/NAME.expect when there is one
#   p2u.sh env        print the settings as they resolve
#   p2u.sh lab CMD    run CMD in the lab VM (ssh with the lab's own key; sudo works there)
#   p2u.sh key NAME   write the key of the throwaway user client.NAME into $P2_LAB_DIR/keys/client.NAME.secret (mode 600; never printed)
#
# The evidence directory $P2U_OUT/NAME holds:
#   cmdline.txt     the exact command line (the key is a file name, never a value), the environment that matters, the start time
#   binaries.sha256 SHA-256 of every binary the row used: the iPXE file, the OVMF code and variable store, the media made from it, the
#                   guest image's manifest (P2U_MANIFEST), the SHA256SUMS of the iPXE build, and the QEMU version
#   serial.log      the guest's serial console, as the run script kept it (the run script discards a log with the key in it)
#   stamps.txt      seconds since the start of the run script at which each stage was first seen (poll interval 0.5 s)
#   result.txt      the run script's RESULT line and its exit status
#   facts.txt       what analyze.py extracted: the rbd lines, rbd-info counters, the table check summary, the markers
#   verdict.txt     first line PASS, FAIL or BLOCKED, then one line per check (what was required, what was seen)
#   screen.ppm      only when the guest missed its stage: what its screen showed
#   shots/          with P2U_SHOTS="20 60 ...": a PNG of the guest's screen at each of those seconds (shot.py)
#
# The scripts of harness/lab/p2/qemu do the QEMU work (limits, budget, user-mode networking, key scan); this one adds the
# bookkeeping. Environment (see "p2u.sh env"): P2U_REPO (the repository copy), P2U_OUT, P2Q_WORK, P2_LAB_DIR, P2U_MANIFEST.
set -euo pipefail
LC_ALL=C
export LC_ALL

P2U_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2U_REPO:=$(cd "$P2U_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?set P2_LAB_DIR to the lab directory (the one of harness/lab/p2/cluster)}"
: "${P2Q_WORK:?set P2Q_WORK to the QEMU work directory (it holds ipxe/ and tools/)}"
: "${P2U_OUT:=$P2Q_WORK/../out/rows}"
: "${P2U_RETRY_WAIT:=60}"
: "${P2U_RETRIES:=40}"
export P2_LAB_DIR P2Q_WORK
QEMU_DIR=$P2U_REPO/harness/lab/p2/qemu
if [ -d "$P2Q_WORK/tools/usr" ]; then
    export P2Q_TOOLS=${P2Q_TOOLS:-$P2Q_WORK/tools/usr}
    export LD_LIBRARY_PATH=$P2Q_TOOLS/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
fi

die() { echo "p2u: $*" >&2; exit 2; }

lab_ssh() {
    ssh -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}

cmd_env() {
    cat <<EOF
P2U_REPO=$P2U_REPO
P2U_OUT=$P2U_OUT
P2Q_WORK=$P2Q_WORK
P2Q_TOOLS=${P2Q_TOOLS:-}
P2_LAB_DIR=$P2_LAB_DIR
P2U_MANIFEST=${P2U_MANIFEST:-}
EOF
}

cmd_key() {
    local name=$1 f
    # the name goes into a command that runs in the lab VM: a closed character set, and only this matrix's own prefix
    [[ $name =~ ^wrtest-p2-[A-Za-z0-9-]{1,40}$ ]] || die "key: only wrtest-p2-<letters, digits, dash> users"
    f=$P2_LAB_DIR/keys/client.$name.secret
    ( umask 077; lab_ssh "sudo ceph auth get-key client.$name" > "$f.tmp" ) || { rm -f "$f.tmp"; die "key: no such user client.$name"; }
    chmod 600 "$f.tmp"
    mv -f "$f.tmp" "$f"
    echo "p2u: key of client.$name written to $f ($(wc -c < "$f") bytes, not shown)"
}

# sha256 of a file, or a "missing" line
sumfile() {
    if [ -f "$1" ]; then sha256sum "$1"; else echo "MISSING  $1"; fi
}

# Find the run script's evidence by its pid (the run id ends in the pid of the run script).
cmd_row() {
    local name=$1 kind=$2 profile=boot expect_file="" retry=1
    shift 2
    while [ $# -gt 0 ]; do
        case $1 in
            --profile) profile=$2; shift 2;;
            --expect-file) expect_file=$2; shift 2;;
            --no-retry) retry=0; shift;;
            --) shift; break;;
            *) die "row: unknown option $1";;
        esac
    done
    case $kind in uefi-pxe | uefi-usb | uefi-iso) ;; *) die "row: bad kind $kind";; esac
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || die "row: bad name $name"
    local dir=$P2U_OUT/$name
    [ ! -e "$dir" ] || die "row: $dir exists (rows are never overwritten; move it away first)"
    mkdir -p -m 700 "$dir"
    local runscript=$QEMU_DIR/run-$kind.sh
    [ -f "$runscript" ] || die "row: no $runscript"

    # the binary of the row, for the checksums: --bin / --media win over the default of the kind
    local bin="" media="" a prev=""
    for a in "$@"; do
        [ "$prev" = --bin ] && bin=$a
        [ "$prev" = --media ] && media=$a
        prev=$a
    done
    [ -n "$bin" ] || bin=$P2Q_WORK/ipxe/ipxe.efi
    case $bin in /*) ;; *) bin=$P2Q_WORK/ipxe/$bin;; esac

    {
        echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) row $name ($kind), profile $profile"
        echo "# run from $P2U_REPO; the cephx key is only ever a --key-file path"
        echo "P2Q_WORK=$P2Q_WORK P2_LAB_DIR=$P2_LAB_DIR"
        printf 'bash %q' "$runscript"
        for a in "$@"; do printf ' %q' "$a"; done
        echo
    } > "$dir/cmdline.txt"
    {
        sumfile "$bin"
        [ -z "$media" ] || sumfile "$media"
        sumfile "${P2Q_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
        sumfile "${P2Q_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
        [ -z "${P2U_MANIFEST:-}" ] || sumfile "$P2U_MANIFEST"
        echo "# iPXE build (SHA256SUMS of the build directory):"
        sed 's/^/#   /' "$P2Q_WORK/ipxe/SHA256SUMS" 2>/dev/null || true
        echo "# $(qemu-system-x86_64 --version | head -n 1)"
        echo "# repository HEAD of the scripts: $(git -C "$P2U_REPO" rev-parse HEAD 2>/dev/null || cat "$P2U_REPO/.p2u-head" 2>/dev/null || echo unknown)"
        # the scripts themselves, so a row can be tied to the version that ran it even when the copy has no git metadata
        echo "# digest of the scripts (tools/ and harness/lab/p2/qemu/): $( (cd "$P2U_REPO/harness/lab/p2" && find results/uefi/tools qemu -type f | LC_ALL=C sort | xargs sha256sum) 2>/dev/null | sha256sum | cut -d' ' -f1)"
    } > "$dir/binaries.sha256"

    # run, with a retry while the machine's budget has no room (another module's guest)
    local try=0 rc pid rundir
    while :; do
        : > "$dir/stdout.txt"
        bash "$runscript" "$@" > "$dir/stdout.txt" 2>&1 &
        pid=$!
        local t0=$SECONDS
        python3 -I "$P2U_HERE/stamp.py" "$P2Q_WORK/runs" "$pid" "$dir/stamps.txt" "$P2_LAB_DIR/vm/qemu.pid" &
        local spid=$! shpid=""
        if [ -n "${P2U_SHOTS:-}" ]; then
            # screenshots at the given seconds: the run script's own QMP socket is P2Q_WORK/s/<its pid>.sock
            mkdir -p "$dir/shots"
            # shellcheck disable=SC2086
            python3 -I "$P2U_HERE/shot.py" "$P2Q_WORK/s/$pid.sock" "$dir/shots" $P2U_SHOTS &
            shpid=$!
        fi
        rc=0
        wait "$pid" || rc=$?
        wait "$spid" || true
        if [ -n "$shpid" ]; then wait "$shpid" || true; fi
        if [ "$rc" = 2 ] && [ "$retry" = 1 ] && grep -qiE 'budget would be exceeded|address .*(in use|taken)|already (in use|used|uses the lab)' "$dir/stdout.txt" && [ "$try" -lt "$P2U_RETRIES" ]; then
            try=$((try + 1))
            echo "p2u: $name: no room yet (try $try): $(grep -iE 'budget would be exceeded|in use|taken|already (used|uses)' "$dir/stdout.txt" | head -n 1)" >&2
            sleep "$P2U_RETRY_WAIT"
            continue
        fi
        break
    done
    {
        tail -n 1 "$dir/stdout.txt"
        echo "exit=$rc wall=$((SECONDS - t0))s retries=$try"
    } > "$dir/result.txt"

    local console
    console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
    if [ -n "$console" ] && [ -f "$console" ]; then
        cp -p "$console" "$dir/serial.log"
        local base=${console%.console}
        [ ! -f "$base.screen.ppm" ] || cp -p "$base.screen.ppm" "$dir/screen.ppm"
        [ ! -f "$base.qemu" ] || { [ -s "$base.qemu" ] && cp -p "$base.qemu" "$dir/qemu.out" || true; }
    else
        : > "$dir/serial.log"
    fi
    # defence in depth: the exact key of this run (base64 and hex forms) must not be in anything the row kept; a file that holds it is deleted
    local keyhit=0 kf="" hits krc
    for a in "$@"; do
        if [ "$kf" = --key-file ] && [ -s "$a" ]; then
            krc=0
            hits=$(python3 -I "$P2U_HERE/keyscan.py" "$a" "$dir") || krc=$?
            if [ "$krc" = 1 ]; then
                keyhit=1
                while IFS= read -r f; do [ -z "$f" ] || rm -f -- "$dir/$f"; done <<< "$hits"
            elif [ "$krc" != 0 ]; then
                echo "p2u: $name: the key file could not be scanned (keyscan.py exit $krc)" >&2
                keyhit=1
            fi
        fi
        kf=$a
    done
    python3 -I "$P2U_HERE/analyze.py" --profile "$profile" ${expect_file:+--expect-file "$expect_file"} \
        --dir "$dir" > "$dir/verdict.txt" || true
    if [ "$keyhit" = 1 ]; then
        { echo FAIL; echo "FAIL secret scan: keyscan.py found the run's own key in the row's files (deleted, names not kept) or could not scan"; tail -n +2 "$dir/verdict.txt"; } > "$dir/verdict.new"
        mv -f "$dir/verdict.new" "$dir/verdict.txt"
    fi
    echo "p2u: $name: $(head -n 1 "$dir/verdict.txt")  ($(tail -n 1 "$dir/result.txt"))"
}

# judge an existing evidence directory again (the analysis rules changed, the run did not): p2u.sh rejudge NAME PROFILE [EXPECT-FILE]
cmd_rejudge() {
    local dir=$P2U_OUT/$1 prof=$2 ef=${3:-}
    [ -d "$dir" ] || die "rejudge: no $dir"
    python3 -I "$P2U_HERE/analyze.py" --profile "$prof" ${ef:+--expect-file "$ef"} --dir "$dir" > "$dir/verdict.txt"
    echo "p2u: $1: $(head -n 1 "$dir/verdict.txt") (judged again)"
}

cmd_rejudge_all() {
    local rows=${1:?usage: rejudge-all ROWSDIR EXPECTDIR} exp=${2:?usage: rejudge-all ROWSDIR EXPECTDIR} d n prof ef
    for d in "$rows"/*/; do
        n=$(basename "$d")
        prof=$(sed -n '1s/.*profile \([a-z]*\).*/\1/p' "$d/cmdline.txt")
        case $n in HTTP-*) prof=control;; esac
        [ -n "$prof" ] || { echo "p2u: $n: no profile in cmdline.txt" >&2; continue; }
        ef=""
        [ ! -f "$exp/$n.expect" ] || ef=$exp/$n.expect
        python3 -I "$P2U_HERE/analyze.py" --profile "$prof" ${ef:+--expect-file "$ef"} --dir "$d" > "$d/verdict.txt.new"
        mv -f "$d/verdict.txt.new" "$d/verdict.txt"
        echo "p2u: $n: $(head -n 1 "$d/verdict.txt") (judged again as $prof)"
    done
}

case ${1:-} in
    row) shift; cmd_row "$@";;
    rejudge-all) shift; cmd_rejudge_all "$@";;
    rejudge) shift; cmd_rejudge "$@";;
    env) cmd_env;;
    lab) shift; lab_ssh "$@";;
    key) shift; cmd_key "$@";;
    *) sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
