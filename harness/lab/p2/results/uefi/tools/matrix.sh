#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# matrix.sh - the UEFI rows of docs/design/ipxe-driver.md section 14.3, repeatable. Runs on the machine that hosts the lab VM and the
# QEMU guests (the "box"); every row is one p2u.sh call and leaves one evidence directory (see p2u.sh).
#
#   matrix.sh [-n] ROW...         run the named rows (or a group: u0 u1 u2 u3 bytes neg all), in the order given
#   matrix.sh list                the rows and what each one proves
#
# Environment (all required unless a default is shown; see p2u.sh env):
#   P2_LAB_DIR   the lab directory of harness/lab/p2/cluster (keys/, ssh/)
#   P2Q_WORK     the QEMU work directory: ipxe/ (the iPXE build results and SHA256SUMS), tools/ (mtools, xorriso, syslinux)
#   P2U_OUT      where the evidence goes (default $P2Q_WORK/../out/rows)
#   P2U_IMAGES   directory with the guest images' manifests: bytes/ (bytes.manifest, MD5SUMS), lin-uefi/ (linux-uefi.raw.manifest)
#                (default $P2Q_WORK/../out/images)
#   P2U_LIN      the RBD image / user name of the Linux guest (default wrtest-p2-lin-uefi)
#   P2U_BYTES    the RBD image / user name of the byte-check disk (default wrtest-p2-bytes)
#   P2U_IP       the guest's lab address (default 10.77.0.31; the lab NIC's MAC follows from it, see gen-script.sh)
#   P2U_BIN      an iPXE binary other than ipxe.efi for the U1 rows (a debug build, for finding the cause of a failure)
#   P2U_EXTRA_OPT  one more driver option for the U1 rows (readahead=0, mode=secure, ...): the finding's discriminating experiments
#   P2U_EMBED_ISO  the real bin-x86_64-efi/ipxe.iso built with the run script embedded (row U3; made by embed-iso.sh)
#
# The rows (name: what it proves)
#   U0-vendor U0-uri U0-sata   OVMF + ipxe.efi by PXE, sanhook, then the UEFI shell: map -r shows the block device and its partitions,
#                              ls reads the ESP, the device path has the node of the flavour (devpath=vendor|uri|sata)
#   U1-vendor U1-uri U1-sata   OVMF + ipxe.efi by PXE, sanboot of the Linux GPT image to the login prompt: the table check (every field
#                              PASS), / on /dev/rbd0p2; the three device path flavours; the key comes from QEMU's file channel (handoff=nokey)
#   U1-vendor-r1 r2 ...        repeats of U1-vendor (how often does the boot fail?)
#   U1-handoff-key             the same with handoff=key: the table carries the key and the hook uses it
#   U2-usb                     ipxe.efi as EFI/BOOT/BOOTX64.EFI on a USB stick image (GPT + FAT), sanboot of the Linux image
#   W1-vendor W1-sata W1-uri   the owner's WinPE (GPT) image on RBD, ipxe.efi by PXE, sanboot: boot manager, boot.wim through the SAN, WinPE desktop (screenshots)
#   W2-vendor                  the same from a USB stick
#   U3-iso                     bin-x86_64-efi/ipxe.iso (the real build target, script embedded), sanboot of the Linux image
#   UB-bytes UB-bytes-ra0      SAN-level byte check: every file of the byte-check disk read through the SAN layer in iPXE and digested
#                              there, compared with the list the disk was built from and with the files read out of rbd export
#                              (UB-bytes-ra0: readahead=0, the baseline without the cache)
#   N-password N-nokey N-wrongkey N-wrongpool N-wrongimage N-nomon   the negative rows: each fails the way the design says
set -euo pipefail
LC_ALL=C
export LC_ALL

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${P2_LAB_DIR:?}"
: "${P2Q_WORK:?}"
: "${P2U_OUT:=$P2Q_WORK/../out/rows}"
: "${P2U_IMAGES:=$P2Q_WORK/../out/images}"
: "${P2U_LIN:=wrtest-p2-lin-uefi}"
: "${P2U_BYTES:=wrtest-p2-bytes}"
: "${P2U_IP:=10.77.0.31}"
: "${P2U_POOL:=winrbd}"
: "${P2U_WINPE:=wrtest-p2-winpe-gpt}"
: "${P2U_NAME_SUFFIX:=}"       # appended to the row's directory name: a second attempt of a row is P2U_NAME_SUFFIX=-a2
export P2_LAB_DIR P2Q_WORK P2U_OUT
P2U=$HERE/p2u.sh
EXP=$P2U_OUT/.expect
DRY=0
KEY_LIN=$P2_LAB_DIR/keys/client.$P2U_LIN.secret
KEY_BYTES=$P2_LAB_DIR/keys/client.$P2U_BYTES.secret

die() { echo "matrix: $*" >&2; exit 2; }

mac_of() { printf '52:54:00:77:12:%02x' $(($(echo "$1" | awk -F. '{print $4}') + 128)); }   # gen-script.sh / common.sh's rule

# the image's id (the table carries it; it is new with every import, so it is asked of the cluster, not written down)
image_id() { # IMAGE
    "$P2U" lab "sudo rbd info --format json $P2U_POOL/$1" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])'
}

# the guest's hook gets the expectations of the row as a file on QEMU's file channel (never a key in it)
params_file() { # NAME [expected-table.sh options...]
    local name=$1
    shift
    mkdir -p -m 700 "$EXP"
    bash "$P2U_REPO_DIR/harness/lab/p2/images/expected-table.sh" fwcfg --entity "$P2U_LIN" --pool "$P2U_POOL" --image "$P2U_LIN" --image-id "$(image_id "$P2U_LIN")" \
        --mac "$(mac_of "$P2U_IP")" --ip "$P2U_IP/24" --static "$@" > "$EXP/$name.params"
    echo rbft.require=1 >> "$EXP/$name.params"
    echo "$EXP/$name.params"
}
P2U_REPO_DIR=${P2U_REPO:-$(cd "$HERE/../../../../../.." && pwd)}

run() { # NAME KIND PROFILE EXPECT-LINES... -- run-script args
    local name=$1$P2U_NAME_SUFFIX kind=$2 prof=$3 ef
    shift 3
    mkdir -p -m 700 "$EXP"
    ef=$EXP/$name.expect
    : > "$ef"
    while [ $# -gt 0 ] && [ "$1" != -- ]; do echo "$1" >> "$ef"; shift; done
    [ "${1:-}" = -- ] && shift
    if [ "$DRY" = 1 ]; then echo "DRY: $name ($kind, $prof): $*"; return 0; fi
    "$P2U" row "$name" "$kind" --profile "$prof" --expect-file "$ef" -- "$@" || true
}

common_args() { printf '%s\n' --ip "$P2U_IP" --pool "$P2U_POOL"; }

# ---------------------------------------------------------------------------------------------------------------------------------

row_u0() { # flavour
    local f=$1 a=$EXP/u0-$1.ipxe
    # iPXE keeps its SAN devices only while it runs: when an EFI application returns, iPXE unloads and takes them with it. So the shell is
    # started FROM iPXE (imgexec), out of the second image (the byte-check disk, which carries the firmware's own Shell.efi, see
    # build-bytes-image.sh): both devices are then visible to the shell, which is also a test of two sessions in one iPXE.
    {
        printf 'echo WRINFO-BEGIN\nrbd-info\necho WRINFO-END\n'
        printf 'echo WRU0-HELPER-HOOK\n'
        printf 'sanhook --drive 0x81 rbd://%s@10.77.0.10:3300/%s/%s?devpath=%s || goto helper-failed\n' "$P2U_LIN" "$P2U_POOL" "$P2U_BYTES" "$f"
        printf 'imgfetch --name wrshell file://WRBYTES/Shell.efi || goto helper-failed\n'
        printf 'imgargs wrshell -nostartup\n'
        printf 'echo WRU0-SHELL-START\nimgexec wrshell\necho WRU0-SHELL-RETURNED\nexit\n'
        printf ':helper-failed\necho WRU0-HELPER-FAILED 0x${errno:hexraw}\nexit\n'
    } > "$a"
    run "U0-$f" uefi-pxe shell "devpath=$f" "devpath_image=$P2U_POOL/$P2U_LIN" "devpath_image=$P2U_POOL/$P2U_BYTES" -- --row U0 --ip "$P2U_IP" --user "$P2U_LIN" --pool "$P2U_POOL" --image "$P2U_LIN" \
        --key-file "$KEY_LIN" --opt "devpath=$f" --action sanhook --expect shell --timeout 420 \
        --append "$a" --menu-keys '' --shell-cmds 'map -r;fs1:;ls;fs2:;ls;ls EFI\BOOT'
}

boot_extra() { # the arguments every boot row shares: the table expectations and the key by file channel
    local params=$1 key=${2:-}
    printf '%s\n' --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/params,file=$params"
    if [ -n "$key" ]; then printf '%s\n' --qemu-arg -fw_cfg --qemu-arg "name=opt/winrbd/key,file=$key"; fi
}

row_u1() { # name flavour [handoff]
    local name=$1 f=$2 h=${3:-nokey} params key opt=() extra=()
    if [ "$h" = key ]; then
        params=$(params_file "$name" --keytype aes --key-b64-file "$KEY_LIN")
        opt=(--opt handoff=key)
    else
        params=$(params_file "$name")
        key=$KEY_LIN
    fi
    mapfile -t extra < <(boot_extra "$params" "${key:-}")
    run "$name" uefi-pxe boot "devpath=$f" -- --row U1 --ip "$P2U_IP" --user "$P2U_LIN" --pool "$P2U_POOL" --image "$P2U_LIN" \
        --key-file "$KEY_LIN" ${P2U_BIN:+--bin "$P2U_BIN"} --opt "devpath=$f" ${P2U_EXTRA_OPT:+--opt "$P2U_EXTRA_OPT"} "${opt[@]}" --action sanboot --expect marker --marker 'login: ?$' \
        --fail-marker 'WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF|error: failure reading sector|Failed to boot both default|rbd: .*(out of memory|closing the path)' --timeout 900 "${extra[@]}"
}

row_w() { # name kind flavour: the owner's WinPE image (UEFI/GPT) from the SAN, shell by screenshots
    local name=$1 kind=$2 f=$3 key=$P2_LAB_DIR/keys/client.$P2U_WINPE.secret
    P2U_SHOTS="${P2U_SHOTS:-60 120 180 240 300 360}" run "$name" "$kind" winpe -- --row "${name%%-*}" --ip "$P2U_IP" --user "$P2U_WINPE" --pool "$P2U_POOL" \
        --image "$P2U_WINPE" --key-file "$key" ${P2U_EXTRA_OPT:+--opt "$P2U_EXTRA_OPT"} --opt "devpath=$f" --action sanboot --expect none --stay --mem 2048 --timeout 400
}

row_u2() {
    local params key=$KEY_LIN extra=()
    params=$(params_file U2-usb)
    mapfile -t extra < <(boot_extra "$params" "$key")
    run U2-usb uefi-usb boot -- --row U2 --ip "$P2U_IP" --user "$P2U_LIN" --pool "$P2U_POOL" --image "$P2U_LIN" --key-file "$KEY_LIN" \
        --action sanboot --expect marker --marker 'login: ?$' \
        --fail-marker 'WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF|error: failure reading sector|Failed to boot both default|rbd: .*(out of memory|closing the path)' --timeout 900 "${extra[@]}"
}

row_u3() {
    local iso=${P2U_EMBED_ISO:-$P2Q_WORK/ipxe/efi-ipxe-embed.iso} params key=$KEY_LIN extra=()
    [ -f "$iso" ] || [ "$DRY" = 1 ] || die "U3: no $iso (embed-iso.sh makes it)"
    params=$(params_file U3-iso)
    mapfile -t extra < <(boot_extra "$params" "$key")
    run U3-iso uefi-iso boot -- --row U3 --ip "$P2U_IP" --media "$iso" --delivery embed --user "$P2U_LIN" --pool "$P2U_POOL" \
        --image "$P2U_LIN" --no-key --expect marker --marker 'login: ?$' \
        --fail-marker 'WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF|error: failure reading sector|Failed to boot both default|rbd: .*(out of memory|closing the path)' --timeout 900 "${extra[@]}"
}

row_bytes() { # name [extra --opt]
    local name=$1 opt=${2:-}
    local optargs=()
    [ -z "$opt" ] || optargs=(--opt "$opt")
    bash "$HERE/gen-bytes-append.sh" "$P2U_IMAGES/bytes/MD5SUMS" > "$EXP/bytes.ipxe"
    # the oracle: the files read out of rbd export of the very image that was imported
    [ -s "$EXP/oracle.md5" ] || [ "$DRY" = 1 ] || bash "$HERE/oracle-bytes.sh" "$P2U_BYTES" "$EXP/oracle.md5"
    run "$name" uefi-pxe bytes "md5sums=$P2U_IMAGES/bytes/MD5SUMS" "oracle=$EXP/oracle.md5" -- --row UB --ip "$P2U_IP" --user "$P2U_BYTES" \
        --pool "$P2U_POOL" --image "$P2U_BYTES" --key-file "$KEY_BYTES" "${optargs[@]}" --action sanhook --append "$EXP/bytes.ipxe" \
        --leave poweroff --expect marker --marker '^WRBYTES-DONE' --timeout 1500
}

row_neg() { # name  errno  console-regex  run-args...
    local name=$1 errno=$2 con=$3
    shift 3
    run "$name" uefi-pxe negative "errno=$errno" "console=$con" -- --row N --ip "$P2U_IP" --action sanhook \
        --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+' --timeout 300 "$@"
}

rows() {
    local r
    for r in "$@"; do
        case $r in
            u0) rows U0-vendor U0-uri U0-sata;;
            u1) rows U1-vendor U1-uri U1-sata U1-handoff-key;;
            u2) rows U2-usb;;
            u3) rows U3-iso;;
            bytes) rows UB-bytes UB-bytes-ra0;;
            neg) rows N-password N-nokey N-wrongkey N-wrongpool N-wrongimage N-nomon;;
            all) rows u0 bytes neg u1 u2 u3;;
            U0-vendor) row_u0 vendor;;
            U0-uri) row_u0 uri;;
            U0-sata) row_u0 sata;;
            U1-vendor) row_u1 U1-vendor vendor;;
            U1-vendor-*r[0-9]*) row_u1 "$r" vendor;;            # repeats of the same row (flakiness check)
            U1-uri) row_u1 U1-uri uri;;
            U1-sata) row_u1 U1-sata sata;;
            U1-handoff-key) row_u1 U1-handoff-key vendor key;;
            U2-usb) row_u2;;
            W1-vendor) row_w W1-vendor uefi-pxe vendor;;
            W1-sata) row_w W1-sata uefi-pxe sata;;
            W1-uri) row_w W1-uri uefi-pxe uri;;
            W2-vendor) row_w W2-vendor uefi-usb vendor;;
            w) rows W1-vendor W1-sata W1-uri W2-vendor;;
            U3-iso) row_u3;;
            UB-bytes) row_bytes UB-bytes;;
            UB-bytes-ra0) row_bytes UB-bytes-ra0 readahead=0;;
            N-password)
                # gen-script.sh refuses to write a URI with a password, so this row's script is written by hand: it asks the driver for exactly
                # that URI (the password is not a key) and must see the driver's own refusal
                mkdir -p -m 700 "$EXP"
                printf '#!ipxe\necho WRRUN-BEGIN row=N\necho WRRUN-SAN-START sanhook\nsanhook rbd://%s:notakey@10.77.0.10:3300/%s/%s || goto san-fail\necho WRRUN-SAN-OK\nexit\n:san-fail\necho WRRUN-SAN-FAILED 0x${errno:hexraw}\necho WRRUN-END\nexit\n' \
                    "$P2U_BYTES" "$P2U_POOL" "$P2U_BYTES" > "$EXP/N-password.ipxe"
                run N-password uefi-pxe negative errno=EINVAL 'console=key material must not be part of the URI' -- --row N --ip "$P2U_IP" \
                    --script "$EXP/N-password.ipxe" --expect marker --marker 'WRRUN-SAN-FAILED 0x[0-9a-f]+' --timeout 300;;
            N-nokey)
                row_neg N-nokey EINVAL 'no cephx key: set rbd-key' --user "$P2U_BYTES" --pool "$P2U_POOL" --image "$P2U_BYTES" --no-key \
                    --opt timeout=15;;
            N-wrongkey)
                row_neg N-wrongkey EACCES 'rbd: .*failed: .*\((WR_E_AUTH_[A-Z_]+|WR_E_M2_BAD_METHOD; the cluster answered -[0-9]+)\)' --user "$P2U_BYTES" --pool "$P2U_POOL" --image "$P2U_BYTES" --fake-key \
                    --opt timeout=15;;
            N-wrongpool)
                row_neg N-wrongpool ENOENT 'rbd: .*failed: pool not found .*\(WR_E_POOL_NOT_FOUND\)' --user "$P2U_BYTES" --pool wrtest-p2-nosuchpool --image "$P2U_BYTES" \
                    --key-file "$KEY_BYTES" --opt timeout=20;;
            N-wrongimage)
                row_neg N-wrongimage ENOENT 'rbd: .*failed: image not found .*\(WR_E_RBD_NOT_FOUND\)' --user "$P2U_BYTES" --pool "$P2U_POOL" --image wrtest-p2-nosuchimage \
                    --key-file "$KEY_BYTES" --opt timeout=20;;
            N-nomon)
                row_neg N-nomon "ETIMEDOUT ENETUNREACH" 'rbd: .*failed: .*\(WR_E_(MON_UNREACHABLE|TIMEOUT|NET_CONNECT)\)' --user "$P2U_BYTES" --mon 10.77.0.99:3300 --pool "$P2U_POOL" \
                    --image "$P2U_BYTES" --key-file "$KEY_BYTES" --opt timeout=15;;
            *) die "unknown row $r (matrix.sh list)";;
        esac
    done
}

case ${1:-} in
    list) sed -n '/^# The rows/,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d; s/^# \{0,1\}//'; exit 0;;
    -n) DRY=1; shift;;
esac
[ $# -ge 1 ] || { sed -n '3,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2; }
mkdir -p -m 700 "$P2U_OUT" "$EXP"
printf 'echo WRINFO-BEGIN\nrbd-info\necho WRINFO-END\n' > "$EXP/info.ipxe"
rows "$@"
