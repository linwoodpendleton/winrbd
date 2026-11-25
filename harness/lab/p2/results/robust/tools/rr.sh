#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# rr.sh - run ONE robustness row (milestone 7, design section 14.3) and leave an evidence directory behind.
#
#   rr.sh row NAME --family uefi|bios --workload W [--fault KIND] [--on REGEX] [--on-nth N] [--delay S] [--down S] [--osd N] [--press KEYS] [--press-delay S]
#                  [--oct N] [--timeout S] [--capture] [--no-lab-diff] [--profile P] [--note TEXT] [--dry]
#   rr.sh env                      print the settings as they resolve
#
# Workloads (what the guest does while the fault happens):
#   bytes    (uefi) hook the byte-check disk, read its 17 files through the firmware's FAT driver, digest each in iPXE; the digests are compared with the list the
#            disk was built from and with `rbd export` of the same image (oracle)
#   reader   (bios) hook the reader disk (tools/reader.S), boot it: it reads 128 MiB through INT 13h and hashes it; compared with `rbd export` (oracle)
#   boot-outage  the same boot with the cluster gone for minutes while the kernel loads: what the real loader does when the SAN layer gives up (it may boot after
#            the cluster is back, or report a read error and stop; it must never boot damaged data)
#   boot     boot the Linux guest image of the family (GRUB, kernel, initramfs read through the SAN device; the kernel client takes over); must reach
#            WRBOOT-ROOT-OK with the table check passing
#   neg-key | neg-pool | neg-image | neg-mon     the negative rows (wrong key, no such pool, no such image, a monitor that does not exist): no fault; each must fail
#            with ONE driver console line and the right errno, and nothing may boot
#
# Faults and their options are those of harness/lab/p2/qemu/robust.sh (which this runs). The evidence directory $P2R_OUT/NAME:
#   cmdline.txt   the command (the key only as a file name)         binaries.sha256   hashes of everything that ran
#   serial.txt    the guest's serial console                         ts.txt   the same, each line with the time it was first seen
#   fault.txt     what the fault driver did, with times             syn.txt  (--capture) the guest's TCP connection attempts and its traffic with the monitor, as the lab VM saw it
#   stdout.txt    the run script's messages and RESULT line         result.txt   the RESULT line and the exit status
#   lab-before.txt lab-after.txt lab-diff.txt   the lab's state before and after (labstate.sh): the diff must be empty
#   facts.txt verdict.txt   what analyze.py extracted and its verdict (PASS / FAIL / BLOCKED, then one line per check)
#
# Environment (tools/box-env.example): P2Q_WORK (ipxe/ with ipxe.efi and ipxe-stub.pxe), P2_LAB_DIR (ssh/, keys/), P2R_REPO (a copy of the repository),
# P2R_OUT (the evidence), P2R_IMAGES (bytes/MD5SUMS, reader.raw: what the images were built from).
# shellcheck disable=SC2015  # "A && B || die" is a guard here, not an if-then-else
set -euo pipefail
LC_ALL=C
export LC_ALL

R_HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2R_REPO:=$(cd "$R_HERE/../../../../../.." && pwd)}"
: "${P2_LAB_DIR:?set P2_LAB_DIR to the lab directory (the one of harness/lab/p2/cluster)}"
: "${P2Q_WORK:?set P2Q_WORK to the QEMU work directory (it holds ipxe/)}"
: "${P2R_OUT:=$P2Q_WORK/../out/rows}"
: "${P2R_IMAGES:=$P2Q_WORK/../work}"
export P2_LAB_DIR P2Q_WORK
QEMU_DIR=$P2R_REPO/harness/lab/p2/qemu
UEFI_TOOLS=$P2R_REPO/harness/lab/p2/results/uefi/tools

die() { echo "rr.sh: $*" >&2; exit 2; }

lab_ssh() {
    ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$P2_LAB_DIR/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes \
        -o "UserKnownHostsFile=$P2_LAB_DIR/ssh/known_hosts" -o ConnectTimeout=15 "${LAB_SSH_USER:-lab}@127.0.0.1" "$@"
}

# the image (and user) of each workload and family
img_of() {
    case "$1/$2" in
        uefi/bytes | */neg-*) echo wrtest-p2-rb-bytes;;
        bios/reader) echo wrtest-p2-rb-reader;;
        uefi/boot | uefi/boot-outage) echo wrtest-p2-rb-lin-uefi;;
        bios/boot | bios/boot-outage) echo wrtest-p2-rb-lin-bios;;
        *) return 1;;
    esac
}

sumfile() { if [ -f "$1" ]; then sha256sum "$1"; else echo "MISSING  $1"; fi; }

image_id() { lab_ssh "sudo rbd info --format json winrbd/$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }

cmd_env() {
    cat <<EOF
P2R_REPO=$P2R_REPO
P2R_OUT=$P2R_OUT
P2R_IMAGES=$P2R_IMAGES
P2Q_WORK=$P2Q_WORK
P2_LAB_DIR=$P2_LAB_DIR
EOF
}

cmd_row() {
    local name=$1 family="" workload="" fault=none oct="" timeout="" capture=0 lab_diff=1 profile="" note="" dry=0
    local on="" nth="" delay="" down="" osd="" press="" press_delay="" idle="" extra=()
    shift
    while [ $# -gt 0 ]; do
        case $1 in
            --family) family=$2; shift 2;;
            --workload) workload=$2; shift 2;;
            --fault) fault=$2; shift 2;;
            --on) on=$2; shift 2;;
            --on-nth) nth=$2; shift 2;;
            --delay) delay=$2; shift 2;;
            --down) down=$2; shift 2;;
            --osd) osd=$2; shift 2;;
            --idle-timeout) idle=$2; shift 2;;
            --press) press=$2; shift 2;;
            --press-delay) press_delay=$2; shift 2;;
            --oct) oct=$2; shift 2;;
            --timeout) timeout=$2; shift 2;;
            --capture) capture=1; shift;;
            --no-lab-diff) lab_diff=0; shift;;
            --profile) profile=$2; shift 2;;
            --note) note=$2; shift 2;;
            --opt) extra+=(--opt "$2"); shift 2;;
            --dry) dry=1; shift;;
            *) die "row: unknown option $1";;
        esac
    done
    [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,60}$ ]] || die "row: bad name $name"
    case $family in uefi | bios) ;; *) die "row: --family uefi|bios";; esac
    case $workload in bytes | reader | boot | boot-outage | neg-key | neg-pool | neg-image | neg-mon) ;; *) die "row: bad --workload $workload";; esac
    case "$family/$workload" in uefi/reader | bios/bytes) die "row: the $workload workload is for the other family";; esac
    local img user keyfile
    img=$(img_of "$family" "$workload") || die "row: no image for $family/$workload"
    user=$img
    keyfile=$P2_LAB_DIR/keys/client.$user.secret
    [ -s "$keyfile" ] || die "row: no key file $keyfile (p2u.sh key $user)"
    [ -n "$oct" ] || oct=$([ "$family" = uefi ] && echo 21 || echo 22)
    [ -n "$profile" ] || case $workload in bytes) profile=bytes;; reader) profile=reader;; boot) profile=boot;; boot-outage) profile=bootgive;; neg-*) profile=negative;; esac
    [ -n "$timeout" ] || case $workload in bytes) timeout=420;; reader) timeout=420;; boot) timeout=600;; boot-outage) timeout=900;; neg-*) timeout=300;; esac

    local dir=$P2R_OUT/$name
    [ ! -e "$dir" ] || die "row: $dir exists (rows are never overwritten; move it away first)"
    local tmp=$P2R_OUT/.tmp.$$
    mkdir -p "$P2R_OUT"
    mkdir -m 700 "$tmp"
    # (the scratch directory holds the iPXE append script and the fw_cfg parameters: it goes away however the row ends)
    # shellcheck disable=SC2064  # $tmp is this row's directory, fixed now
    trap "rm -rf -- '$tmp'" EXIT
    local ipxe bin
    case $family in uefi) bin=ipxe.efi;; *) bin='ipxe-stub.pxe';; esac
    ipxe=$P2Q_WORK/ipxe/$bin

    # ---- what the guest runs
    local args=() mac id ip
    mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
    ip=10.77.0.$oct
    args+=(--row "$([ "$family" = uefi ] && echo U1 || echo B1)" --ip "$ip" --user "$user" --pool winrbd --image "$img" --key-file "$keyfile" --timeout "$timeout")
    case $workload in
        bytes)
            bash "$UEFI_TOOLS/gen-bytes-append.sh" "$P2R_IMAGES/bytes/MD5SUMS" > "$tmp/append.ipxe"
            args+=(--action sanhook --leave none --append "$tmp/append.ipxe" --expect marker --marker '^WRRUN-END');;
        reader)
            cat > "$tmp/append.ipxe" <<'EOS'
echo WRROB-INFO-BEGIN
rbd-info
echo WRROB-INFO-END
echo WRROB-BOOT
sanboot --drive 0x80 || echo WRROB-BOOT-RETURNED ${errno}
echo WRROB-INFO-BEGIN
rbd-info
echo WRROB-INFO-END
echo WRROB-END
EOS
            args+=(--action sanhook --drive 0x80 --leave none --append "$tmp/append.ipxe" --expect marker --marker '^WRRUN-END');;
        boot | boot-outage)
            id=$(image_id "$img")
            bash "$P2R_REPO/harness/lab/p2/images/expected-table.sh" fwcfg --mons 10.77.0.10:3300 --entity "$user" --pool winrbd --image "$img" --image-id "$id" \
                --mode crc --mac "$mac" --ip "$ip/24" --static > "$tmp/params.txt"
            echo rbft.require=1 >> "$tmp/params.txt"
            if [ "$workload" = boot ]; then args+=(--expect os); else args+=(--expect marker --marker 'WRBOOT-ROOT-OK|error: failure reading sector|Failed to boot|Boot from SAN device .* failed'); fi
            args+=(--action sanboot --opt devpath=vendor
                --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/params,file=$tmp/params.txt"
                --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/key,file=$keyfile");;
        neg-key)
            args=(--row "$([ "$family" = uefi ] && echo U1 || echo B1)" --ip "$ip" --user "$user" --pool winrbd --image "$img" --fake-key --timeout "$timeout"
                --action sanhook --leave none --on-fail hold --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+');;
        neg-pool)
            args=(--row "$([ "$family" = uefi ] && echo U1 || echo B1)" --ip "$ip" --user "$user" --pool wrtest-p2-nosuchpool --image "$img" --key-file "$keyfile" --timeout "$timeout"
                --action sanhook --leave none --on-fail hold --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+');;
        neg-image)
            args=(--row "$([ "$family" = uefi ] && echo U1 || echo B1)" --ip "$ip" --user "$user" --pool winrbd --image wrtest-p2-nosuchimage --key-file "$keyfile" --timeout "$timeout"
                --action sanhook --leave none --on-fail hold --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+');;
        neg-mon)
            args=(--row "$([ "$family" = uefi ] && echo U1 || echo B1)" --ip "$ip" --user "$user" --pool winrbd --image "$img" --key-file "$keyfile" --mon 10.77.0.97:3300 --timeout "$timeout"
                --action sanhook --leave none --on-fail hold --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+');;
    esac
    local rargs=(--family "$family" --fault "$fault")
    [ -z "$on" ] || rargs+=(--on "$on")
    [ -z "$nth" ] || rargs+=(--on-nth "$nth")
    [ -z "$delay" ] || rargs+=(--delay "$delay")
    [ -z "$down" ] || rargs+=(--down "$down")
    [ -z "$osd" ] || rargs+=(--osd "$osd")
    [ -z "$idle" ] || rargs+=(--idle-timeout "$idle")
    [ -z "$press" ] || rargs+=(--press "$press")
    [ -z "$press_delay" ] || rargs+=(--press-delay "$press_delay")
    [ "$capture" = 0 ] || rargs+=(--capture)
    rargs+=(--bin "$ipxe" "${args[@]}" "${extra[@]}")
    [ "$family" = uefi ] || rargs+=(--delivery stub)

    if [ "$dry" = 1 ]; then
        bash "$QEMU_DIR/robust.sh" -n "${rargs[@]}"
        rm -rf -- "$tmp"
        return 0
    fi

    mkdir -m 700 "$dir"
    {
        echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) row $name ($family, $workload, fault $fault), profile $profile${note:+; $note}"
        echo "# run from $P2R_REPO; the cephx key is only ever a --key-file path"
        echo "P2Q_WORK=$P2Q_WORK P2_LAB_DIR=$P2_LAB_DIR"
        printf 'bash %q' "$QEMU_DIR/robust.sh"
        local a
        for a in "${rargs[@]}"; do printf ' %q' "$a"; done
        echo
    } > "$dir/cmdline.txt"
    {
        sumfile "$ipxe"
        [ "$family" = bios ] || { sumfile "${P2Q_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"; sumfile "${P2Q_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"; }
        sumfile "$P2R_IMAGES/bytes/bytes.manifest"
        sumfile "$P2R_IMAGES/reader.raw.sha256"
        sumfile "$QEMU_DIR/robust.sh"
        echo "# $(qemu-system-x86_64 --version | head -n 1)"
        echo "# the image $img on the cluster: id $(image_id "$img" 2>/dev/null || echo unknown)"
    } > "$dir/binaries.sha256"

    local P2R_LABSTATE="$R_HERE/labstate.sh"
    if [ "$lab_diff" = 1 ]; then bash "$P2R_LABSTATE" snapshot "$dir/lab-before.txt" > /dev/null; fi
    echo "health before: $(bash "$P2R_LABSTATE" health 2>/dev/null || echo unknown)" > "$dir/lab-health.txt"

    # ---- the run
    local rc=0
    bash "$QEMU_DIR/robust.sh" "${rargs[@]}" > "$dir/stdout.txt" 2>&1 || rc=$?
    {
        tail -n 1 "$dir/stdout.txt"
        echo "exit=$rc"
    } > "$dir/result.txt"
    echo "health after: $(bash "$P2R_LABSTATE" health 2>/dev/null || echo unknown)" >> "$dir/lab-health.txt"
    if [ "$lab_diff" = 1 ]; then
        bash "$P2R_LABSTATE" snapshot "$dir/lab-after.txt" > /dev/null
        bash "$P2R_LABSTATE" diff "$dir/lab-before.txt" "$dir/lab-after.txt" > "$dir/lab-diff.txt" 2>&1 || true
    fi

    local console base
    console=$(sed -n 's/.* console=\([^ ]*\)$/\1/p' "$dir/stdout.txt" | tail -n 1)
    : > "$dir/serial.txt"
    if [ -n "$console" ] && [ -f "$console" ]; then
        cp -p "$console" "$dir/serial.txt"
        base=${console%.console}
        [ ! -f "$base.ts" ] || cp -p "$base.ts" "$dir/ts.txt"
        [ ! -f "$base.fault" ] || cp -p "$base.fault" "$dir/fault.txt"
        [ ! -f "$base.syn" ] || cp -p "$base.syn" "$dir/syn.txt"
        [ ! -f "$base.screen.ppm" ] || cp -p "$base.screen.ppm" "$dir/screen.ppm"
        [ ! -f "$base.qemu" ] || { [ -s "$base.qemu" ] && cp -p "$base.qemu" "$dir/qemu.out" || true; }
    fi
    # the key must not be in anything the row kept (a file that holds it is deleted and the row fails)
    local keyhit=0 krc=0 hits f
    hits=$(python3 -I "$UEFI_TOOLS/keyscan.py" "$keyfile" "$dir") || krc=$?
    if [ "$krc" = 1 ]; then
        keyhit=1
        while IFS= read -r f; do [ -z "$f" ] || rm -f -- "$dir/$f"; done <<< "$hits"
    elif [ "$krc" != 0 ]; then
        echo "rr.sh: $name: the key file could not be scanned (keyscan.py exit $krc)" >&2
        keyhit=1
    fi
    python3 -I "$R_HERE/analyze.py" --profile "$profile" --workload "$workload" --fault "$fault" --family "$family" \
        --expect-dir "$R_HERE/../expect" --dir "$dir" > "$dir/verdict.txt" || true
    if [ "$keyhit" = 1 ]; then
        { echo FAIL; echo "FAIL secret scan: keyscan.py found the run's own key in the row's files (deleted, names not kept) or could not scan"; tail -n +2 "$dir/verdict.txt"; } > "$dir/verdict.new"
        mv -f "$dir/verdict.new" "$dir/verdict.txt"
    fi
    rm -rf -- "$tmp"
    echo "rr.sh: $name: $(head -n 1 "$dir/verdict.txt")  ($(tail -n 2 "$dir/result.txt" | tr '\n' ' ' | cut -c1-220))"
}

case ${1:-} in
    row) shift; cmd_row "$@";;
    env) cmd_env;;
    *) sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2;;
esac
