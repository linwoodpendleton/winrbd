#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# mrun.sh - ONE run of the exit measurements (design section 14.4): a SeaBIOS guest boots the bench program (bench.S) from an RBD image through the
# iPXE rbd:// driver, and the evidence of the run is left in one directory.
#
#   mrun.sh row LABEL --image NAME --plan PLAN.json --bin FILE [--opt N=V]... [--oct N] [--timeout S] [--netem MS] [--idle-timeout S] [--capture]
#                      [--marker REGEX] [--exit] [--note TEXT] [--dry]
#   mrun.sh env                       print the settings as they resolve
#
#   --image NAME      the RBD image and the throwaway cephx user (the same name, client.NAME); its key file is $P2_LAB_DIR/keys/client.NAME.secret
#   --plan PLAN.json  the plan mkbench.py wrote with the image (the analysis checks the data against it)
#   --bin FILE        the iPXE PXE binary with the constant stub (ipxe-stub.pxe of build-variants.sh rel | inst)
#   --opt N=V         a driver option of the rbd:// URI (readahead=0, ...); repeatable
#   --netem MS        add MS milliseconds of delay on the lab VM's lab NIC (tc netem, egress: the replies and ACKs to the guest) for the run; removed afterwards
#   --idle-timeout S  set ms_connection_idle_timeout of the monitor and the OSDs to S seconds for the run (ceph config set, removed afterwards)
#   --capture         tcpdump (headers only) of the guest's TCP traffic on the lab VM during the run; captan.py's numbers are capture.json, a sample is capture-head.txt
#   --append FILE     iPXE commands to run after the sanhook INSTEAD of the bench boot (the loop of the R10 test); the analysis then looks for WRLOOP lines
#   --qemu-mem MB     the guest's memory in MiB below the library's minimum of 512 (a later -m on the QEMU command line; the budget counts 512)
#   --exit            end the iPXE script with "exit", so that iPXE shuts down and prints its heap maximum (a DEBUG=malloc build); the run then waits for
#                     that line ("HEAP maximum usage") instead of the script's end
#
# The evidence directory $P2M_OUT/LABEL:
#   cmdline.txt (the command; the key is only a file name)   binaries.sha256   plan.json   serial.txt (the guest's console)   ts.txt (the same, each line with
#   the time it was first seen)   result.txt (RESULT line, exit status)   load.txt (the host's and the lab VM's load and CPU steal before / during / after)
#   lab-before.txt lab-after.txt lab-diff.txt (the lab's state before and after: the diff must be empty)   facts.json verdict.txt (analyze.py)
#   verify.txt (a copy run: the destination ranges against their sources)   capture.txt (--capture)
#
# Environment: P2_LAB_DIR (the lab directory: ssh/, keys/), P2Q_WORK (the QEMU work directory), P2M_REPO (a copy of the repository), P2M_OUT (the evidence).
# P2Q_BUDGET_ROOT should be the directory above every VM of the workflow, so that the budget of the QEMU scripts counts all of them.
# shellcheck disable=SC2015  # "A && B || die" is a guard here, not an if-then-else
set -euo pipefail
LC_ALL=C
export LC_ALL

M_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2M_REPO:=$(cd "$M_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?set P2_LAB_DIR to the lab directory (the one of harness/lab/p2/cluster)}"
: "${P2Q_WORK:?set P2Q_WORK to the QEMU work directory}"
: "${P2M_OUT:=$P2Q_WORK/../out/runs}"
export P2_LAB_DIR P2Q_WORK
QEMU_DIR=$P2M_REPO/harness/lab/p2/qemu
UEFI_TOOLS=$P2M_REPO/harness/lab/p2/results/uefi/tools
LABSTATE=$P2M_REPO/harness/lab/p2/results/robust/tools/labstate.sh

die() { echo "mrun.sh: $*" >&2; exit 2; }

lab_ssh() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}

sumfile() { if [ -f "$1" ]; then sha256sum "$1"; else echo "MISSING  $1"; fi; }

# one line of the CPU counters (user nice system idle iowait irq softirq steal) of this machine, or of the lab VM
cpu_here() { awk '/^cpu /{print $2, $3, $4, $5, $6, $7, $8, $9}' /proc/stat; }
sample_here() { echo "t=$(date +%s.%N) host_load=$(cut -d' ' -f1-3 /proc/loadavg) host_cpu=$(cpu_here)"; }
# the CPU wait of a process, summed over its threads (ns), or -1
waitns() {
    local pid=$1 t total=0 w
    [ -n "$pid" ] && [ -d "/proc/$pid/task" ] || { echo -1; return; }
    for t in /proc/"$pid"/task/*; do
        w=$(awk '{print $2}' "$t/schedstat" 2> /dev/null || echo 0)
        total=$((total + ${w:-0}))
    done
    echo "$total"
}
sample_lab() { lab_ssh "echo lab_t=\$(date +%s.%N) lab_load=\$(cut -d' ' -f1-3 /proc/loadavg) lab_cpu=\$(awk '/^cpu /{print \$2, \$3, \$4, \$5, \$6, \$7, \$8, \$9}' /proc/stat)" 2> /dev/null || echo "lab_sample=failed"; }

cmd_env() {
    cat <<EOF
P2M_REPO=$P2M_REPO
P2M_OUT=$P2M_OUT
P2Q_WORK=$P2Q_WORK
P2_LAB_DIR=$P2_LAB_DIR
P2Q_BUDGET_ROOT=${P2Q_BUDGET_ROOT:-(default: the parent of P2Q_WORK)}
EOF
}

cmd_row() {
    local name=$1 image="" plan="" bin="" oct=61 timeout=900 netem="" idle="" capture=0 marker="" doexit=0 note="" dry=0 opts=() mem=1024 append="" qmem=""
    shift
    while [ $# -gt 0 ]; do
        case $1 in
            --image) image=$2; shift 2;;
            --plan) plan=$2; shift 2;;
            --bin) bin=$2; shift 2;;
            --opt) opts+=(--opt "$2"); shift 2;;
            --oct) oct=$2; shift 2;;
            --timeout) timeout=$2; shift 2;;
            --netem) netem=$2; shift 2;;
            --idle-timeout) idle=$2; shift 2;;
            --capture) capture=1; shift;;
            --marker) marker=$2; shift 2;;
            --exit) doexit=1; shift;;
            --note) note=$2; shift 2;;
            --mem) mem=$2; shift 2;;
            --append) append=$2; shift 2;;
            --qemu-mem) qmem=$2; shift 2;;
            --dry) dry=1; shift;;
            *) die "row: unknown option $1";;
        esac
    done
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || die "row: bad name $name"
    [[ $image =~ ^wrtest-p2-[a-z0-9-]{1,40}$ ]] || die "row: --image wrtest-p2-<name>"
    [ -f "$plan" ] || die "row: --plan PLAN.json"
    [ -f "$bin" ] || die "row: --bin FILE (the iPXE binary)"
    [[ $oct =~ ^[0-9]+$ ]] && [ "$oct" -ge 20 ] && [ "$oct" -le 99 ] && [ "$oct" -ne 50 ] || die "row: --oct 20..99 but 50"
    [[ $timeout =~ ^[0-9]+$ ]] || die "row: --timeout seconds"
    [ -z "$qmem" ] || [[ $qmem =~ ^[0-9]+$ ]] || die "row: --qemu-mem MiB"
    [ -z "$netem" ] || [[ $netem =~ ^[0-9]+(\.[0-9]+)?$ ]] || die "row: --netem milliseconds"
    [ -z "$idle" ] || [[ $idle =~ ^[0-9]+$ ]] || die "row: --idle-timeout seconds"
    local keyfile=$P2_LAB_DIR/keys/client.$image.secret
    [ -s "$keyfile" ] || die "row: no key file $keyfile (p2u.sh key $image)"
    local dir=$P2M_OUT/$name
    [ ! -e "$dir" ] || die "row: $dir exists (runs are never overwritten; move it away first)"
    # (globals, not locals: the EXIT trap runs after this function has returned)
    tmp=$P2M_OUT/.tmp.$$
    mkdir -p "$P2M_OUT"
    mkdir -m 700 "$tmp"
    sampler="" undo_netem=0 undo_idle=0
    cleanup() {
        [ -z "$sampler" ] || kill "$sampler" 2> /dev/null || true
        if [ "$undo_netem" = 1 ]; then lab_ssh "sudo tc qdisc del dev lab0 root 2>/dev/null; true" > /dev/null 2>&1 || echo "mrun.sh: WARNING: could not remove the netem qdisc" >&2; fi
        if [ "$undo_idle" = 1 ]; then
            lab_ssh "for w in mon osd; do sudo ceph config rm \$w ms_connection_idle_timeout; done" > /dev/null 2>&1 || echo "mrun.sh: WARNING: could not remove ms_connection_idle_timeout" >&2
        fi
        rm -rf -- "$tmp"
    }
    trap cleanup EXIT
    trap 'exit 130' INT TERM HUP

    local mac ip
    ip=10.77.0.$oct
    mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
    if [ -n "$append" ]; then
        [ -f "$append" ] || die "row: --append FILE"
        cp "$append" "$tmp/append.ipxe"
        [ "$doexit" = 0 ] || echo "exit" >> "$tmp/append.ipxe"
    else
        {
            echo "echo WRMS-INFO-BEGIN"
            echo "rbd-info"
            echo "echo WRMS-INFO-END"
            echo "echo WRMS-BOOT"
            echo "sanboot --drive 0x80 || echo WRMS-BOOT-RETURNED \${errno}"
            echo "echo WRMS-INFO-BEGIN"
            echo "rbd-info"
            echo "echo WRMS-INFO-END"
            echo "echo WRMS-END"
            [ "$doexit" = 0 ] || echo "exit"
        } > "$tmp/append.ipxe"
    fi
    [ -n "$marker" ] || { [ "$doexit" = 1 ] && marker='HEAP maximum usage' || marker='^WRRUN-END'; }
    local args=(--row B1 --ip "$ip" --user "$image" --pool winrbd --image "$image" --key-file "$keyfile" --timeout "$timeout" --cpus 2 --mem "$mem"
        --action sanhook --drive 0x80 --leave none --append "$tmp/append.ipxe" --expect marker --marker "$marker" --bin "$bin" --delivery stub "${opts[@]}")

    # the library takes 512 MiB or more; a smaller guest (the R10 test) gets a later -m on the QEMU command line, which QEMU takes in place of the first
    [ -z "$qmem" ] || args+=(--qemu-arg -m --qemu-arg "${qmem}M")
    if [ "$dry" = 1 ]; then
        bash "$QEMU_DIR/run-bios-pxe.sh" -n "${args[@]}"
        return 0
    fi
    mkdir -m 700 "$dir"
    cp "$plan" "$dir/plan.json"
    {
        echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) run $name, image $image${netem:+, netem ${netem} ms}${idle:+, idle timeout ${idle} s}${note:+; $note}"
        echo "# the cephx key is only ever a --key-file path"
        echo "P2Q_WORK=$P2Q_WORK P2_LAB_DIR=$P2_LAB_DIR P2Q_BUDGET_ROOT=${P2Q_BUDGET_ROOT:-}"
        printf 'bash %q' "$QEMU_DIR/run-bios-pxe.sh"
        local a
        for a in "${args[@]}"; do printf ' %q' "$a"; done
        echo
        echo "# the iPXE script after sanhook:"
        sed 's/^/#   /' "$tmp/append.ipxe"
    } > "$dir/cmdline.txt"
    {
        sumfile "$bin"
        sumfile "$QEMU_DIR/run-bios-pxe.sh"
        sumfile "$M_HERE/bench.S"
        sumfile "$plan"
        echo "# $(qemu-system-x86_64 --version | head -n 1)"
        echo "# $(grep -c . /proc/cpuinfo > /dev/null && awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //'), $(nproc) CPUs"
        echo "# image $image: $(lab_ssh "sudo rbd info --format json winrbd/$image" 2> /dev/null | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print("id", d["id"], "size", d["size"], "order", d["order"], "features", d["features"])' 2> /dev/null || echo unknown)"
    } > "$dir/binaries.sha256"

    bash "$LABSTATE" snapshot "$dir/lab-before.txt" > /dev/null
    {
        echo "# health before: $(bash "$LABSTATE" health 2> /dev/null | tr '\n' ' ' || echo unknown)"
        echo "before $(sample_here)"
        echo "before $(sample_lab)"
    } > "$dir/load.txt"
    if [ -n "$netem" ]; then
        undo_netem=1
        lab_ssh "sudo tc qdisc replace dev lab0 root netem delay ${netem}ms && sudo tc qdisc show dev lab0" >> "$dir/load.txt" 2>&1 || die "row: could not set netem on the lab VM"
    fi
    if [ -n "$idle" ]; then
        undo_idle=1
        lab_ssh "for w in mon osd; do sudo ceph config set \$w ms_connection_idle_timeout $idle; done" > /dev/null 2>&1 || die "row: could not set ms_connection_idle_timeout"
        echo "idle timeout set to $idle s (mon, osd)" >> "$dir/load.txt"
    fi
    # every 5 s: the load, and how long the threads of this run's guest and of the lab VM have waited for a CPU (runnable but not running, from
    # /proc/<pid>/task/*/schedstat): a slow stretch that goes with a large wait is the machine's, not the driver's
    ( while :; do
        gp=$(pgrep -f "wrp2q.*mac=$mac" | head -n 1 || true)
        echo "during $(sample_here) guest_wait_ns=$(waitns "${gp:-}") lab_wait_ns=$(waitns "$(cat "$P2_LAB_DIR/vm/qemu.pid" 2> /dev/null || true)")"
        sleep 5
    done >> "$dir/load.txt" ) &
    sampler=$!
    if [ "$capture" = 1 ]; then
        lab_ssh "sudo timeout $((timeout + 30)) tcpdump -i lab0 -nn -tt -S -s 96 'tcp and host $ip' > /var/tmp/ms-capture.txt 2>/dev/null &" > /dev/null 2>&1 || true
        sleep 1
    fi

    local rc=0
    bash "$QEMU_DIR/run-bios-pxe.sh" "${args[@]}" > "$dir/stdout.txt" 2>&1 || rc=$?
    { tail -n 1 "$dir/stdout.txt"; echo "exit=$rc"; } > "$dir/result.txt"
    kill "$sampler" 2> /dev/null || true
    sampler=""
    {
        echo "after $(sample_here)"
        echo "after $(sample_lab)"
        echo "# health after: $(bash "$LABSTATE" health 2> /dev/null | tr '\n' ' ' || echo unknown)"
    } >> "$dir/load.txt"
    if [ "$capture" = 1 ]; then
        lab_ssh "sudo pkill -x tcpdump; sleep 1; sudo chmod 644 /var/tmp/ms-capture.txt; cat /var/tmp/ms-capture.txt; sudo rm -f /var/tmp/ms-capture.txt" > "$dir/capture.txt" 2> /dev/null || true
    fi
    if [ "$capture" = 1 ] && [ -s "$dir/capture.txt" ]; then
        # what the guest's TCP did (risk R6): the numbers go into capture.json; of the capture itself only a sample is kept (it is tens of MB)
        python3 -I "$M_HERE/captan.py" "$dir/capture.txt" --guest "$ip" --json "$dir/capture.json" > "$dir/capture-summary.txt" 2>&1 || true
        head -n 400 "$dir/capture.txt" > "$dir/capture-head.txt"
        wc -l < "$dir/capture.txt" | sed 's/^ *//; s/$/ lines in the full capture/' >> "$dir/capture-summary.txt"
        rm -f "$dir/capture.txt"
    fi
    # put the lab back before the diff
    if [ "$undo_netem" = 1 ]; then lab_ssh "sudo tc qdisc del dev lab0 root" > /dev/null 2>&1 && undo_netem=0 || true; fi
    if [ "$undo_idle" = 1 ]; then lab_ssh "for w in mon osd; do sudo ceph config rm \$w ms_connection_idle_timeout; done" > /dev/null 2>&1 && undo_idle=0 || true; fi
    bash "$LABSTATE" snapshot "$dir/lab-after.txt" > /dev/null
    bash "$LABSTATE" diff "$dir/lab-before.txt" "$dir/lab-after.txt" > "$dir/lab-diff.txt" 2>&1 || true

    local console base
    console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
    : > "$dir/serial.txt"
    if [ -n "$console" ] && [ -f "$console" ]; then
        cp -p "$console" "$dir/serial.txt"
        base=${console%.console}
        [ ! -f "$base.ts" ] || cp -p "$base.ts" "$dir/ts.txt"
    fi
    local keyhit=0 krc=0 hits f
    hits=$(python3 -I "$UEFI_TOOLS/keyscan.py" "$keyfile" "$dir") || krc=$?
    if [ "$krc" = 1 ]; then
        keyhit=1
        while IFS= read -r f; do [ -z "$f" ] || rm -f -- "$dir/$f"; done <<< "$hits"
    elif [ "$krc" != 0 ]; then
        echo "mrun.sh: $name: the key file could not be scanned (keyscan.py exit $krc)" >&2
        keyhit=1
    fi
    python3 -I "$M_HERE/analyze.py" run "$dir" > /dev/null || true
    if python3 -I -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["verify"] else 1)' "$plan"; then
        # a copy run: the destination ranges of the image, as the cluster holds them now, against the digests of their sources, and (--strict) everything else of the
        # image against the plan (the data area, the program, the rest of the scratch area): a write in the wrong place is found too
        lab_ssh "sudo rbd export winrbd/$image -" 2> /dev/null | python3 -I "$M_HERE/mkbench.py" verify "$plan" - --strict > "$dir/verify.txt" 2>&1 || true
        if ! grep -q '^VERIFY-RESULT PASS' "$dir/verify.txt"; then
            { echo FAIL; echo "FAIL the copy was not found intact in the image (verify.txt)"; tail -n +2 "$dir/verdict.txt"; } > "$dir/verdict.new"
            mv -f "$dir/verdict.new" "$dir/verdict.txt"
        fi
    fi
    if [ "$keyhit" = 1 ]; then
        { echo FAIL; echo "FAIL secret scan: the run's own key was found in the run's files (deleted) or could not be scanned"; tail -n +2 "$dir/verdict.txt"; } > "$dir/verdict.new"
        mv -f "$dir/verdict.new" "$dir/verdict.txt"
    fi
    echo "mrun.sh: $name: $(head -n 1 "$dir/verdict.txt")  ($(tail -n 2 "$dir/result.txt" | tr '\n' ' ' | cut -c1-200))"
}

case ${1:-} in
    row) shift; cmd_row "$@";;
    env) cmd_env;;
    *) sed -n '3,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
