#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 QEMU scripts: the function library of run-*.sh and smoke.sh. Source it; do not execute it.
#
# One run = one QEMU guest, one directory (RUNDIR) of its own, one result. The library does everything the six run scripts have in
# common: the options, the limits, the firmware, the two NICs, the media, the iPXE script, the serial log with its markers, the timeout,
# and the clean-up. A run script only says which row of the matrix (design section 14.3) it is.
#
# Rules it enforces (shared build machine):
#   * every QEMU runs as `nice -n 19 choom -n 600 --`, with at most 4 cores and 4 GiB (defaults 2 and 2 GiB);
#   * the workflow's budget (24 cores / 32 GiB over every QEMU below the budget root) is checked before a guest starts;
#   * networking is user-mode (slirp, restricted: no route to the host's network) plus one QEMU multicast-socket NIC on 127.0.0.1;
#     no bridge, no tap, no host port forward, no listening socket other than the guest-facing TFTP server inside QEMU's own slirp;
#   * the guest is found again by its own name (-name wrp2q-<runid>) and a pid file inside RUNDIR; only a process whose command line
#     carries that name is ever signalled;
#   * everything that holds the cephx key (the run script, the TFTP copy of it, a medium with the script on it) lives in RUNDIR
#     (mode 700) and is deleted at the end; the console log is scanned for the key and discarded if it is there.
#
# Exit status of a run script: 0 the expected stage was reached; 1 it was not (timeout, the guest ended first, a failure marker);
# 2 usage or environment (nothing was started, or QEMU would not start); 4 something was left behind or the key was found in a log.
# The last line on stdout is always "RESULT row=... ipxe=... san=... os=... end=... secs=... console=...".

# shellcheck disable=SC2054  # the commas in the QEMU option strings are QEMU's syntax, not array separators
q_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

q_info() { echo "[qemu] $*" >&2; }
q_warn() { echo "[qemu] warning: $*" >&2; }
q_die()  { echo "error: $*" >&2; exit 2; }

# ---------------------------------------------------------------------------------------------------------------------
# defaults
# ---------------------------------------------------------------------------------------------------------------------

q_defaults() {
    : "${P2Q_WORK:=${HOME:-/tmp}/winrbd-p2-qemu}"
    : "${P2Q_QEMU:=qemu-system-x86_64}"
    : "${P2Q_ACCEL:=kvm}"
    : "${P2Q_CPUS:=2}"
    : "${P2Q_MEM_MB:=2048}"
    : "${P2Q_NICE:=19}"
    : "${P2Q_TIMEOUT_S:=300}"
    : "${P2Q_NIC_MODEL:=virtio-net-pci}"
    : "${P2Q_MCAST:=${P2_MCAST:-230.77.12.1:7712}}"
    : "${P2Q_MCAST_LOCALADDR:=${P2_MCAST_LOCALADDR:-127.0.0.1}}"
    local cidr=${P2_NET_CIDR:-10.77.0.0/24}
    : "${P2Q_NET:=${cidr%.*}}"
    : "${P2Q_MON:=${P2_MON_ADDR:-10.77.0.10}:${P2_MON_PORT:-3300}}"
    : "${P2Q_BUDGET_CORES:=${P2_BUDGET_CORES:-24}}"
    : "${P2Q_BUDGET_MEM_MB:=${P2_BUDGET_MEM_MB:-32768}}"
    : "${P2Q_IPXE_DIR:=$P2Q_WORK/ipxe}"
    : "${P2Q_SCREENDUMP:=1}"
    : "${P2Q_CONSOLE_MAX_MB:=64}"
    P2Q_BUDGET_ROOT=${P2Q_BUDGET_ROOT:-}
    while [ "${#P2Q_BUDGET_ROOT}" -gt 1 ] && [ "${P2Q_BUDGET_ROOT%/}" != "$P2Q_BUDGET_ROOT" ]; do P2Q_BUDGET_ROOT=${P2Q_BUDGET_ROOT%/}; done
    if [ -z "$P2Q_BUDGET_ROOT" ]; then
        if [ -n "${P2_LAB_DIR:-}" ]; then P2Q_BUDGET_ROOT=$(dirname "$P2_LAB_DIR"); else P2Q_BUDGET_ROOT=$(dirname "$P2Q_WORK"); fi
    fi
}

q_validate_env() {
    local v
    for v in P2Q_CPUS P2Q_MEM_MB P2Q_NICE P2Q_TIMEOUT_S P2Q_BUDGET_CORES P2Q_BUDGET_MEM_MB P2Q_CONSOLE_MAX_MB; do
        [[ "${!v}" =~ ^[0-9]{1,9}$ ]] || q_die "$v must be a plain number (got '${!v}')"
    done
    for v in P2Q_CPUS P2Q_MEM_MB P2Q_NICE P2Q_TIMEOUT_S P2Q_BUDGET_CORES P2Q_BUDGET_MEM_MB P2Q_CONSOLE_MAX_MB; do
        # "08" is an octal error inside $(( )): store every number in its plain decimal form
        printf -v "$v" '%d' "$((10#${!v}))"
    done
    [ "$P2Q_CPUS" -ge 1 ] && [ "$P2Q_CPUS" -le 4 ] || q_die "P2Q_CPUS (--cpus) must be 1 to 4: a test guest gets at most 4 cores"
    [ "$P2Q_MEM_MB" -ge 512 ] && [ "$P2Q_MEM_MB" -le 4096 ] || q_die "P2Q_MEM_MB (--mem) must be 512 to 4096: a test guest gets at most 4 GiB"
    [ "$P2Q_NICE" -ge 10 ] && [ "$P2Q_NICE" -le 19 ] || q_die "P2Q_NICE must be 10 to 19 (the shared machine's rule is 19)"
    [ "$P2Q_TIMEOUT_S" -ge 5 ] && [ "$P2Q_TIMEOUT_S" -le 7200 ] || q_die "--timeout must be 5 to 7200 seconds"
    [ "$P2Q_CONSOLE_MAX_MB" -ge 1 ] && [ "$P2Q_CONSOLE_MAX_MB" -le 1024 ] || q_die "P2Q_CONSOLE_MAX_MB must be 1 to 1024 (the serial log of one run is cut off there)"
    [[ "$P2Q_MCAST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]] || q_die "P2Q_MCAST must look like 230.77.12.1:7712"
    [[ "$P2Q_MCAST_LOCALADDR" =~ ^127\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || q_die "P2Q_MCAST_LOCALADDR must be a loopback address (the lab's layer 2 lives on the machine's loopback only)"
    [[ "$P2Q_NET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || q_die "P2Q_NET must be the first three octets of the lab network (10.77.0)"
    [[ "$P2Q_MON" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]] || q_die "P2Q_MON must look like 10.77.0.10:3300"
    [[ "$P2Q_NIC_MODEL" =~ ^(virtio-net-pci|e1000|e1000e|rtl8139)$ ]] || q_die "P2Q_NIC_MODEL (--nic-model) must be virtio-net-pci, e1000, e1000e or rtl8139"
    [[ "$P2Q_ACCEL" =~ ^(kvm|tcg)$ ]] || q_die "P2Q_ACCEL must be kvm or tcg"
    case "$P2Q_WORK" in /*) ;; *) q_die "P2Q_WORK must be an absolute path";; esac
    case "$P2Q_WORK" in *[[:space:],]*) q_die "P2Q_WORK must not contain spaces or commas (it ends up in QEMU option strings)";; esac
}

# The row, and what its kind of run script implies.
q_kind_setup() {
    Q_KIND=$1
    Q_MENU_DEFAULT=""
    case "$Q_KIND" in
        uefi-pxe) Q_FW=uefi; Q_MEDIA_KIND=pxe; Q_ROW_DEFAULT=U1; Q_BIN_DEFAULT=ipxe.efi;       Q_DELIVERY_DEFAULT=autoexec
                  Q_MENU_DEFAULT='down down ret down down down down ret';;
        uefi-usb) Q_FW=uefi; Q_MEDIA_KIND=usb; Q_ROW_DEFAULT=U2; Q_BIN_DEFAULT=ipxe.efi;       Q_DELIVERY_DEFAULT=autoexec
                  Q_MENU_DEFAULT='down down ret down ret';;
        uefi-iso) Q_FW=uefi; Q_MEDIA_KIND=iso; Q_ROW_DEFAULT=U3; Q_BIN_DEFAULT=ipxe.efi;       Q_DELIVERY_DEFAULT=autoexec
                  Q_MENU_DEFAULT='down down ret down ret';;
        bios-pxe) Q_FW=bios; Q_MEDIA_KIND=pxe; Q_ROW_DEFAULT=B1; Q_BIN_DEFAULT=ipxe-stub.pxe;  Q_DELIVERY_DEFAULT=stub;;
        bios-usb) Q_FW=bios; Q_MEDIA_KIND=usb; Q_ROW_DEFAULT=B2; Q_BIN_DEFAULT=ipxe.lkrn;      Q_DELIVERY_DEFAULT=autoexec;;
        bios-iso) Q_FW=bios; Q_MEDIA_KIND=iso; Q_ROW_DEFAULT=B3; Q_BIN_DEFAULT=ipxe.lkrn;      Q_DELIVERY_DEFAULT=autoexec;;
        *) q_die "internal: unknown kind $Q_KIND";;
    esac
}

# ---------------------------------------------------------------------------------------------------------------------
# options
# ---------------------------------------------------------------------------------------------------------------------

q_usage() {
    cat <<EOF
usage: $Q_PROG [options]        (row $Q_ROW_DEFAULT by default; kind $Q_KIND: $Q_FW firmware, boot from $Q_MEDIA_KIND)

  -n, --dry-run          print what would run (the QEMU command line and the script with the key hidden); start nothing
  --row ID               row label (U0 U1 U2 U3 B0 B1 B2 B3 ...); U0 / B0 change the defaults, see the README
  --ipxe-dir DIR         directory with the built iPXE files (ipxe.efi ipxe.pxe ipxe-stub.pxe undionly.kpxe ipxe.lkrn ...)
                         default \$P2Q_IPXE_DIR = $P2Q_IPXE_DIR
  --bin FILE             the iPXE binary to boot (default: $Q_BIN_DEFAULT in the iPXE directory)
  --delivery D           how the run script reaches iPXE: autoexec (autoexec.ipxe on the TFTP server or on the medium), stub (the binary has
                         the constant stub from gen-script.sh --stub built in, which fetches autoexec.ipxe over TFTP), embed (the script is
                         inside the binary; nothing is generated). Default for this kind: $Q_DELIVERY_DEFAULT
  --media FILE           a ready-made USB image / ISO (instead of building one with make-usb.sh)
  --ip A.B.C.D           the guest's lab address (default ${P2Q_NET}.20; .21 to .99 except .50 for parallel guests)
  --uri URI | --user U --mon HOSTS --pool P --image I [--opt N=V ...]   what to hook (see gen-script.sh); default mon $P2Q_MON
  --key-file F | --fake-key | --no-key       the cephx key (mode 600 file), a random one for a negative control, or none
  --action A  --drive N  --no-describe  --leave L  --on-fail F  --append FILE        passed to gen-script.sh
  --script FILE          use this iPXE script as it is (it may hold a key: it is copied into RUNDIR and deleted afterwards)
  --disk FILE [--disk-format F] [--disk-write]    a local disk (rows B0 and the like); a qcow2 overlay is used unless --disk-write
  --expect S             stage that makes the run a success: ipxe, san, os, shell, marker, none (default: san if a target is given, else ipxe)
  --marker REGEX         with --expect marker, and an extra line to wait for: the run succeeds when it appears
  --ok-marker REGEX      the line the booted OS prints on the serial console (default ^WRBOOT-ROOT-OK); --expect os waits for it
  --fail-marker REGEX    a line that ends the run as a failure at once (default: none; with --expect os: the image's other WRBOOT-ROOT-*
                         verdicts and a kernel panic)
  --shell-cmds "a;b"     UEFI shell commands to type once the shell prompt appears (row U0: default "map -r;fs0:;ls"); --shell-expect REGEX
  --menu-keys "k k ..."  QEMU key names that take OVMF from its setup menu to the UEFI shell (see the README; default for this kind:
                         $Q_MENU_DEFAULT)
  --stay                 do not stop the guest when the expectation is met; wait for the guest or the timeout
  --cpus N --mem MB      guest size (limits 4 / 4096; defaults $P2Q_CPUS / $P2Q_MEM_MB)       --nic-model M (default $P2Q_NIC_MODEL)
  --timeout S            seconds before the guest is stopped (default $P2Q_TIMEOUT_S)
  --keep                 keep RUNDIR (it holds the key if one was used): for debugging only
  --qemu-arg ARG         one extra QEMU argument, repeatable (anything that would touch the host's network is refused)
  -h, --help
EOF
}

# A dotted quad with each octet 0 to 255 and no leading zeros (iPXE would read 010 as octal).
q_ipv4_ok() {
    local o='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    [[ "$1" =~ ^$o\.$o\.$o\.$o$ ]]
}

q_need() { [ "$#" -ge 2 ] || q_die "option $1 needs a value"; }

q_parse() {
    Q_DRY=0 Q_ROW="" Q_BIN="" Q_DELIVERY="" Q_MEDIA_FILE="" Q_IP="" Q_URI="" Q_USER="" Q_MON="" Q_POOL="" Q_IMAGE=""
    Q_OPTS=() Q_KEYFILE="" Q_FAKE=0 Q_NOKEY=0 Q_ACTION="" Q_DRIVE="" Q_NODESC=0 Q_LEAVE="" Q_ONFAIL="" Q_APPEND=""
    Q_SCRIPT="" Q_DISK="" Q_DISK_FMT="" Q_DISK_WRITE=0 Q_EXPECT="" Q_MARKER="" Q_OK_MARK="" Q_FAIL_MARK=""
    Q_SHELL="" Q_SHELL_EXPECT="" Q_MENU="" Q_STAY=0 Q_KEEP=0 Q_QEXTRA=() Q_SNAP="" Q_USERSET=0 Q_RAWQ=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help) q_usage; exit 0;;
            -n|--dry-run) Q_DRY=1; shift;;
            --row) q_need "$@"; Q_ROW=$2; shift 2;;
            --ipxe-dir) q_need "$@"; P2Q_IPXE_DIR=$2; shift 2;;
            --bin) q_need "$@"; Q_BIN=$2; shift 2;;
            --delivery) q_need "$@"; Q_DELIVERY=$2; shift 2;;
            --media) q_need "$@"; Q_MEDIA_FILE=$2; shift 2;;
            --ip) q_need "$@"; Q_IP=$2; shift 2;;
            --uri) q_need "$@"; Q_URI=$2; shift 2;;
            --user) q_need "$@"; Q_USER=$2; shift 2;;
            --mon) q_need "$@"; Q_MON=$2; shift 2;;
            --pool) q_need "$@"; Q_POOL=$2; shift 2;;
            --image) q_need "$@"; Q_IMAGE=$2; shift 2;;
            --snap) q_need "$@"; Q_SNAP=$2; shift 2;;
            --opt) q_need "$@"; Q_OPTS+=("$2"); shift 2;;
            --raw-query) q_need "$@"; Q_RAWQ=$2; shift 2;;
            --user-setting) Q_USERSET=1; shift;;
            --key-file) q_need "$@"; Q_KEYFILE=$2; shift 2;;
            --fake-key) Q_FAKE=1; shift;;
            --no-key) Q_NOKEY=1; shift;;
            --action) q_need "$@"; Q_ACTION=$2; shift 2;;
            --drive) q_need "$@"; Q_DRIVE=$2; shift 2;;
            --no-describe) Q_NODESC=1; shift;;
            --leave) q_need "$@"; Q_LEAVE=$2; shift 2;;
            --on-fail) q_need "$@"; Q_ONFAIL=$2; shift 2;;
            --append) q_need "$@"; Q_APPEND=$2; shift 2;;
            --script) q_need "$@"; Q_SCRIPT=$2; shift 2;;
            --disk) q_need "$@"; Q_DISK=$2; shift 2;;
            --disk-format) q_need "$@"; Q_DISK_FMT=$2; shift 2;;
            --disk-write) Q_DISK_WRITE=1; shift;;
            --expect) q_need "$@"; Q_EXPECT=$2; shift 2;;
            --marker) q_need "$@"; Q_MARKER=$2; shift 2;;
            --ok-marker) q_need "$@"; Q_OK_MARK=$2; shift 2;;
            --fail-marker) q_need "$@"; Q_FAIL_MARK=$2; shift 2;;
            --shell-cmds) q_need "$@"; Q_SHELL=$2; shift 2;;
            --shell-expect) q_need "$@"; Q_SHELL_EXPECT=$2; shift 2;;
            --menu-keys) q_need "$@"; Q_MENU=$2; shift 2;;
            --stay) Q_STAY=1; shift;;
            --cpus) q_need "$@"; P2Q_CPUS=$2; shift 2;;
            --mem) q_need "$@"; P2Q_MEM_MB=$2; shift 2;;
            --nic-model) q_need "$@"; P2Q_NIC_MODEL=$2; shift 2;;
            --timeout) q_need "$@"; P2Q_TIMEOUT_S=$2; shift 2;;
            --work) q_need "$@"; P2Q_WORK=$2; shift 2;;
            --keep) Q_KEEP=1; shift;;
            --qemu-arg) q_need "$@"; Q_QEXTRA+=("$2"); shift 2;;
            *) q_die "unknown option $1 (see --help)";;
        esac
    done
}

# Fill in what the row and the options imply, and check it.
q_resolve() {
    [ -n "$Q_ROW" ] || Q_ROW=$Q_ROW_DEFAULT
    [[ "$Q_ROW" =~ ^[A-Za-z0-9_-]{1,16}$ ]] || q_die "--row must be 1 to 16 letters, digits, - or _"
    [ -n "$Q_IP" ] || Q_IP=$P2Q_NET.20
    q_ipv4_ok "$Q_IP" || q_die "--ip must be an IPv4 address written without leading zeros (iPXE reads 010 as octal 8)"
    case "$Q_IP" in "$P2Q_NET".*) ;; *) q_die "--ip $Q_IP is not in the lab network $P2Q_NET.0/24";; esac
    Q_OCT=${Q_IP##*.}
    [ "$Q_OCT" -ge 20 ] && [ "$Q_OCT" -le 99 ] && [ "$Q_OCT" -ne 50 ] || q_die "--ip: the last octet must be 20 to 99 and not 50 (.10 is the monitor, .50 the probe guest)"
    Q_MAC_LAB=$(printf '52:54:00:77:12:%02x' $((Q_OCT + 128)))
    Q_MAC_USER=$(printf '52:54:00:77:11:%02x' "$Q_OCT")
    [ -n "$Q_DELIVERY" ] || Q_DELIVERY=$Q_DELIVERY_DEFAULT
    case "$Q_DELIVERY" in autoexec|stub|embed) ;; *) q_die "--delivery must be autoexec, stub or embed";; esac
    if [ "$Q_DELIVERY" = stub ] && [ "$Q_MEDIA_KIND" != pxe ]; then q_die "--delivery stub is for PXE runs (the stub fetches the script over TFTP)"; fi
    if [ "$Q_DELIVERY" = autoexec ] && [ "$Q_FW" = bios ] && [ "$Q_MEDIA_KIND" = pxe ]; then
        q_die "a BIOS iPXE started by PXE cannot read autoexec.ipxe by itself: use --delivery stub (a binary with the stub built in) or --delivery embed"
    fi
    if [ "$Q_NOKEY" = 1 ] && { [ -n "$Q_KEYFILE" ] || [ "$Q_FAKE" = 1 ]; }; then q_die "--no-key excludes --key-file and --fake-key"; fi
    if [ -n "$Q_KEYFILE" ] && [ "$Q_FAKE" = 1 ]; then q_die "--fake-key excludes --key-file"; fi
    # (anchored at the start of a line, as the images' own tests do: a kernel command line, a `set -x` trace or an echo of the
    # script that merely mentions the word is not the verdict of the booted system)
    [ -n "$Q_OK_MARK" ] || Q_OK_MARK='^WRBOOT-ROOT-OK'
    # the target: a URI, or pool + image
    Q_HAVE_TARGET=0
    if [ -n "$Q_URI" ] || [ -n "$Q_POOL$Q_IMAGE" ]; then Q_HAVE_TARGET=1; fi
    if [ -z "$Q_ACTION" ]; then if [ "$Q_HAVE_TARGET" = 1 ]; then Q_ACTION=sanhook; else Q_ACTION=none; fi; fi
    case "$Q_ACTION" in sanhook|sanboot|none) ;; *) q_die "--action must be sanhook, sanboot or none";; esac
    if [ "$Q_ACTION" != none ] && [ "$Q_HAVE_TARGET" = 0 ] && [ -z "$Q_SCRIPT" ] && [ "$Q_DELIVERY" != embed ]; then
        q_die "--action $Q_ACTION needs a target (--uri, or --pool and --image)"
    fi
    # row defaults
    case "$Q_ROW" in
        U0)
            [ -n "$Q_SHELL" ] || Q_SHELL='map -r;fs0:;ls'
            [ -n "$Q_SHELL_EXPECT" ] || Q_SHELL_EXPECT='Mapping table'
            [ -n "$Q_EXPECT" ] || Q_EXPECT=shell
            [ -n "$Q_LEAVE" ] || Q_LEAVE='exit';;
        B0)
            [ -n "$Q_DRIVE" ] || Q_DRIVE=0x81
            [ -n "$Q_LEAVE" ] || Q_LEAVE='exit';;
    esac
    [ -n "$Q_LEAVE" ] || Q_LEAVE='exit'
    [ -n "$Q_MENU" ] || Q_MENU=$Q_MENU_DEFAULT
    [[ "$Q_MENU" =~ ^[a-z0-9_\ -]*$ ]] || q_die "--menu-keys: QEMU key names (down ret esc ...) separated by spaces"
    [ -n "$Q_ONFAIL" ] || Q_ONFAIL=poweroff
    if [ -z "$Q_EXPECT" ]; then
        if [ "$Q_ACTION" = sanboot ]; then Q_EXPECT=os
        elif [ "$Q_ACTION" = sanhook ]; then Q_EXPECT=san
        else Q_EXPECT=ipxe; fi
    fi
    case "$Q_EXPECT" in ipxe|san|os|shell|marker|none) ;; *) q_die "--expect must be ipxe, san, os, shell, marker or none";; esac
    # the other verdicts the Linux images print (initramfs: not on RBD, wrong root, handoff table wrong) and a kernel that gave up end
    # an --expect os run at once instead of at the timeout
    if [ "$Q_EXPECT" = os ] && [ -z "$Q_FAIL_MARK" ]; then Q_FAIL_MARK='^WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|^Kernel panic - not syncing'; fi
    if [ "$Q_EXPECT" = marker ] && [ -z "$Q_MARKER" ]; then q_die "--expect marker needs --marker REGEX"; fi
    if [ "$Q_EXPECT" = shell ] && [ "$Q_FW" != uefi ]; then q_die "--expect shell is for the UEFI rows (the UEFI shell)"; fi
    [ -z "$Q_SHELL" ] || [ "$Q_FW" = uefi ] || q_die "--shell-cmds is for the UEFI rows"
    if [ -n "$Q_SHELL" ]; then
        [[ "$Q_SHELL" =~ ^[A-Za-z0-9\ ._:/\\\;-]+$ ]] || q_die "--shell-cmds: plain characters only (letters, digits, space . _ : / \\ ; -)"
    fi
    if [ -n "$Q_DISK" ]; then
        if [ -z "$Q_DISK_FMT" ]; then case "$Q_DISK" in *.qcow2) Q_DISK_FMT=qcow2;; *) Q_DISK_FMT=raw;; esac; fi
        case "$Q_DISK_FMT" in raw|qcow2) ;; *) q_die "--disk-format must be raw or qcow2";; esac
        case "$Q_DISK" in *[[:space:],]*) q_die "--disk: no spaces or commas in the path";; esac
    fi
    if [ -n "$Q_MEDIA_FILE" ]; then case "$Q_MEDIA_FILE" in *[[:space:],]*) q_die "--media: no spaces or commas in the path";; esac; fi
    local a
    for a in ${Q_QEXTRA[@]+"${Q_QEXTRA[@]}"}; do
        q_refuse_host_net "$a"
    done
    if [ "$Q_HAVE_TARGET" = 1 ] && [ -z "$Q_SCRIPT" ] && [ -z "$Q_KEYFILE" ] && [ "$Q_FAKE" = 0 ]; then
        q_warn "a target without --key-file: the script sets no rbd-key, and the cluster will refuse the session (use --fake-key for a negative control on purpose)"
    fi
    q_validate_env
    Q_BIN_NAME=$Q_BIN_DEFAULT
    if [ -n "$Q_BIN" ]; then Q_BIN_PATH=$Q_BIN; Q_BIN_NAME=$(basename "$Q_BIN"); else Q_BIN_PATH=$P2Q_IPXE_DIR/$Q_BIN_DEFAULT; fi
    case "$Q_BIN_PATH$Q_MEDIA_FILE" in *[[:space:],]*) q_die "paths must not contain spaces or commas";; esac
    if [ "$Q_FW" = bios ] && [ "$Q_MEDIA_KIND" = pxe ]; then
        case "$Q_BIN_NAME" in
            undionly*) q_warn "$Q_BIN_NAME drives only the NIC that PXE booted from (UNDI): the lab NIC (NIC 2) is invisible to it and every row that needs the cluster will report WRRUN-NO-LAB-NIC. Use ipxe.pxe (native drivers) for those; undionly.kpxe is fine for 'reaches iPXE' checks.";;
        esac
    fi
}

# Nothing the guest is given may touch the host's network. The run scripts never build such an argument; this stops --qemu-arg.
q_refuse_host_net() {
    local a=$1
    if [[ "$a" =~ (^|[,=:[:space:]])(tap|bridge|vde|vhost-user|hostfwd|guestfwd|smb|ifname|script=|downscript=|-nic|-net) ]]; then
        q_die "refusing the QEMU argument '$a': it would touch the host's network (user-mode networking and the lab's multicast socket only)"
    fi
    # nor may it open a listening socket or reach into the host (VNC / SPICE / gdb stub / TCP monitor or serial / chardev on a host
    # address / migration / shared host directories / USB pass-through)
    # (a chardev that connects out, a descriptor handed in, and a disk that is a network resource count too: all reach beyond the run
    # directory)
    if [[ "$a" =~ (^|[,=:[:space:]])(tcp:|telnet:|udp:|websocket=|host=|port=|connect=|listen=|addr=|to=|fd=|fds=|usb-host|vnc|spice|gdb|incoming|virtfs|fsdev) ]] ||
       [[ "$a" =~ (^|[,=:[:space:]])(nbd|iscsi|ssh|https?|ftps?|tftp|nfs|gluster|rbd)[:+] ]] ||
       [[ "$a" =~ (^|[,=:[:space:]])(file\.)?driver=(nbd|iscsi|ssh|http|https|ftp|ftps|nfs|gluster|rbd|curl)(,|$) ]] ||
       [[ "$a" =~ ^-(s|vnc|spice|gdb|incoming|virtfs|fsdev|monitor|qmp|qmp-pretty)$ ]]; then
        q_die "refusing the QEMU argument '$a': it would open a listening socket or reach into the host (the guest gets its serial log and the control socket inside the run directory, nothing else)"
    fi
}

# ---------------------------------------------------------------------------------------------------------------------
# the machine: budget, duplicates, firmware
# ---------------------------------------------------------------------------------------------------------------------

q_wrap() {
    Q_WRAP=(nice -n "$P2Q_NICE" choom -n 600 --)
}

# "<cores> <mem_mb> <count>" of every qemu process whose command line is below the budget root (as lab/p2/cluster/up.sh counts)
q_qemu_usage() {
    ps -eww -o args= 2>/dev/null | awk -v root="${P2Q_BUDGET_ROOT%/}/" '
        $1 ~ /(^|\/)qemu-system-[a-z0-9_]+$/ && index($0, root) {
            c = 1; m = 128
            n = split($0, f, " ")
            for (i = 1; i < n; i++) {
                if (f[i] == "-smp") { v = f[i+1]; sub(/^cpus=/, "", v); sub(/[^0-9].*$/, "", v); if (v != "") c = v + 0 }
                if (f[i] == "-m")   { v = f[i+1]; sub(/^size=/, "", v); u = v; sub(/[^0-9].*$/, "", v); sub(/^[0-9]+/, "", u); u = substr(u, 1, 1); m = v + 0; if (u == "G" || u == "g") m *= 1024 }
            }
            cores += c; mem += m; cnt++
        }
        END { printf "%d %d %d\n", cores, mem, cnt }'
}

q_budget_check() {
    local c m n
    read -r c m n < <(q_qemu_usage)
    q_info "budget: $n other VM(s) under $P2Q_BUDGET_ROOT use $c cores / $m MiB; adding $P2Q_CPUS cores / $P2Q_MEM_MB MiB; limit $P2Q_BUDGET_CORES cores / $P2Q_BUDGET_MEM_MB MiB"
    if [ $((c + P2Q_CPUS)) -gt "$P2Q_BUDGET_CORES" ] || [ $((m + P2Q_MEM_MB)) -gt "$P2Q_BUDGET_MEM_MB" ]; then
        q_die "the workflow budget would be exceeded ($((c + P2Q_CPUS)) cores / $((m + P2Q_MEM_MB)) MiB); stop another VM first (or raise P2Q_BUDGET_* by exactly the share of a VM that is not part of this workflow, and say so)"
    fi
}

# Two guests with the same lab MAC (= the same address) would corrupt each other's traffic on the layer 2.
q_unique_check() {
    local hit
    hit=$(ps -eww -o pid=,args= 2>/dev/null | awk -v mac="mac=$Q_MAC_LAB" -v mc="mcast=$P2Q_MCAST" '
        $2 ~ /(^|\/)qemu-system-[a-z0-9_]+$/ && index($0, mac) && index($0, mc) { print $1 }' | head -n 1)
    [ -z "$hit" ] || q_die "another guest (pid $hit) already uses the lab address $Q_IP (MAC $Q_MAC_LAB) on $P2Q_MCAST; give --ip another address"
}

q_find_ovmf() {
    local c
    if [ -z "${P2Q_OVMF_CODE:-}" ]; then
        for c in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/edk2/ovmf/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd /usr/share/edk2/ovmf/OVMF_CODE.fd; do
            if [ -r "$c" ]; then P2Q_OVMF_CODE=$c; break; fi
        done
    fi
    if [ -z "${P2Q_OVMF_VARS:-}" ] && [ -n "${P2Q_OVMF_CODE:-}" ]; then
        # the matching variable store, Secure Boot off (no keys enrolled): OVMF_VARS_4M.fd next to OVMF_CODE_4M.fd, else OVMF_VARS.fd
        c=$(dirname "$P2Q_OVMF_CODE")/$(basename "$P2Q_OVMF_CODE" | sed 's/CODE/VARS/')
        if [ -r "$c" ]; then P2Q_OVMF_VARS=$c; fi
    fi
    if [ "$Q_DRY" = 1 ]; then
        : "${P2Q_OVMF_CODE:=/usr/share/OVMF/OVMF_CODE_4M.fd}"
        : "${P2Q_OVMF_VARS:=/usr/share/OVMF/OVMF_VARS_4M.fd}"
    fi
    [ -n "${P2Q_OVMF_CODE:-}" ] && [ -r "$P2Q_OVMF_CODE" ] || q_die "no OVMF firmware found (P2Q_OVMF_CODE; install the ovmf package: OVMF_CODE_4M.fd)"
    [ -n "${P2Q_OVMF_VARS:-}" ] && [ -r "$P2Q_OVMF_VARS" ] || q_die "no OVMF variable store found (P2Q_OVMF_VARS; the Secure Boot off OVMF_VARS_4M.fd)"
    case "$(basename "$P2Q_OVMF_VARS")" in *ms*|*secboot*|*snakeoil*) q_die "P2Q_OVMF_VARS ($P2Q_OVMF_VARS) is a Secure Boot variable store; the matrix runs with Secure Boot off";; esac
    case "$(basename "$P2Q_OVMF_CODE")" in *secboot*|*.ms.*|*snakeoil*) q_die "P2Q_OVMF_CODE ($P2Q_OVMF_CODE) is a Secure Boot build; the matrix runs with Secure Boot off";; esac
    case "$P2Q_OVMF_CODE$P2Q_OVMF_VARS" in *[[:space:],]*) q_die "the OVMF paths must not contain spaces or commas";; esac
}

# ---------------------------------------------------------------------------------------------------------------------
# the run directory
# ---------------------------------------------------------------------------------------------------------------------

q_prepare_work() {
    local marker=$P2Q_WORK/.winrbd-p2-qemu
    if [ -e "$P2Q_WORK" ] && [ ! -d "$P2Q_WORK" ]; then q_die "$P2Q_WORK exists and is not a directory"; fi
    # the run directories below it hold the cephx key: it must be the caller's own directory, not a link into someone else's and not
    # another user's (the default under /tmp, when HOME is not set, is a name anybody can pre-create)
    if [ -L "$P2Q_WORK" ]; then q_die "$P2Q_WORK is a symbolic link: refusing to put run directories (they hold the key) behind it"; fi
    if [ -d "$P2Q_WORK" ] && [ ! -O "$P2Q_WORK" ]; then q_die "$P2Q_WORK is owned by another user: refusing to use it (the run directories hold the key)"; fi
    if [ -d "$P2Q_WORK" ] && [ ! -f "$marker" ]; then
        # an existing directory is ours only if it is empty, or holds nothing but what an operator put there before the first run
        # (the iPXE build results in ipxe/, the tools in tools/)
        local other
        other=$(find "$P2Q_WORK" -mindepth 1 -maxdepth 1 ! -name ipxe ! -name tools ! -name media 2>/dev/null | head -n 1)
        [ -z "$other" ] || q_die "$P2Q_WORK is not empty and has no marker file: refusing to use a directory that is not ours (set P2Q_WORK to an empty or new one)"
    fi
    # shellcheck disable=SC2174  # -m applies to the deepest directory on purpose: that is the one that matters (and the only new one)
    mkdir -p -m 700 "$P2Q_WORK"
    : > "$marker"
    # shellcheck disable=SC2174
    mkdir -p -m 700 "$P2Q_WORK/runs" "$P2Q_WORK/logs" "$P2Q_WORK/s"
}

# The start lock: one file in the work directory, flock on fd 9 (released by q_unlock, by exit, and not inherited by QEMU).
q_lock() {
    if ! command -v flock >/dev/null 2>&1; then
        q_warn "flock is not installed: two runs started at the same moment can both pass the budget check"
        return 0
    fi
    exec 9>"$P2Q_WORK/.start.lock"
    flock -w 120 9 || q_die "another run script holds the start lock of $P2Q_WORK for more than 120 s"
}
q_unlock() { exec 9>&-; }

q_new_run() {
    Q_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
    Q_RUNID=$Q_ROW-$Q_STAMP-$$
    Q_RUNID_Q=wrp2q-$Q_RUNID
    RUNDIR=$P2Q_WORK/runs/$Q_RUNID
    LOGBASE=$P2Q_WORK/logs/$Q_RUNID
    mkdir -m 700 "$RUNDIR"
    Q_CONSOLE=$RUNDIR/console.log
    Q_PIDFILE=$RUNDIR/qemu.pid
    Q_QMP=$P2Q_WORK/s/$$.sock
    [ "${#Q_QMP}" -le 100 ] || q_die "the QMP socket path $Q_QMP is too long for a unix socket (108 bytes): use a shorter P2Q_WORK"
}

# ---------------------------------------------------------------------------------------------------------------------
# the iPXE script, the files the guest boots from
# ---------------------------------------------------------------------------------------------------------------------

q_gen_args() {
    GEN_ARGS=(--row "$Q_ROW" --ip "$Q_IP" --lab-mac "$Q_MAC_LAB" --action "$Q_ACTION" --leave "$Q_LEAVE" --on-fail "$Q_ONFAIL")
    local o
    if [ "$Q_HAVE_TARGET" = 1 ]; then
        if [ -n "$Q_URI" ]; then
            GEN_ARGS+=(--uri "$Q_URI")
        else
            GEN_ARGS+=(--pool "$Q_POOL" --image "$Q_IMAGE" --mon "${Q_MON:-$P2Q_MON}")
            [ -z "$Q_USER" ] || GEN_ARGS+=(--user "$Q_USER")
            [ -z "$Q_SNAP" ] || GEN_ARGS+=(--snap "$Q_SNAP")
            [ "$Q_USERSET" = 0 ] || GEN_ARGS+=(--user-setting)
            for o in ${Q_OPTS[@]+"${Q_OPTS[@]}"}; do GEN_ARGS+=(--opt "$o"); done
            [ -z "$Q_RAWQ" ] || GEN_ARGS+=(--raw-query "$Q_RAWQ")
        fi
    fi
    [ -z "$Q_DRIVE" ] || GEN_ARGS+=(--drive "$Q_DRIVE")
    [ "$Q_NODESC" = 0 ] || GEN_ARGS+=(--no-describe)
    [ -z "$Q_APPEND" ] || GEN_ARGS+=(--append "$Q_APPEND")
    if [ -n "$Q_KEYFILE" ]; then GEN_ARGS+=(--key-file "$Q_KEYFILE")
    elif [ "$Q_FAKE" = 1 ]; then GEN_ARGS+=(--fake-key)
    else GEN_ARGS+=(--no-key); fi
}

# Does the run script come from us (markers WRRUN-*) or from the caller?
q_custom_script() { [ -n "$Q_SCRIPT" ]; }

q_make_script() {
    SCRIPT_FILE=$RUNDIR/autoexec.ipxe
    if q_custom_script; then
        [ -r "$Q_SCRIPT" ] || q_die "--script: cannot read $Q_SCRIPT"
        cp "$Q_SCRIPT" "$SCRIPT_FILE"
        chmod 600 "$SCRIPT_FILE"
    else
        q_gen_args
        "$q_here/gen-script.sh" -o "$SCRIPT_FILE" "${GEN_ARGS[@]}" || exit 2
    fi
    # a copy of the key alone, for the scan of the console log afterwards (never printed, never an argument)
    KEYSCAN=$RUNDIR/key.txt
    : > "$KEYSCAN"
    chmod 600 "$KEYSCAN"
    # (the form gen-script.sh writes, and the same with quotes or trailing blanks as a script of your own may have it)
    sed -n 's/^set rbd-key[[:space:]]\{1,\}//p' "$SCRIPT_FILE" | tr -d "\"' \t\r" | grep -E '^[A-Za-z0-9+/=]{16,}$' > "$KEYSCAN" || true
}

# Put a file where the guest can read it: a hard link when the file system allows, else a copy.
q_place() { ln -f "$1" "$2" 2>/dev/null || cp -f "$1" "$2"; }

q_stage_files() {
    # the iPXE binary
    if [ "$Q_DELIVERY" = embed ] || [ "$Q_MEDIA_KIND" = pxe ] || [ -z "$Q_MEDIA_FILE" ]; then
        [ -r "$Q_BIN_PATH" ] || q_die "the iPXE binary $Q_BIN_PATH does not exist (build it: ipxe/tools/build.sh; --ipxe-dir / --bin)"
    fi
    case "$Q_MEDIA_KIND" in
        pxe)
            mkdir -m 700 "$RUNDIR/tftp"
            q_place "$Q_BIN_PATH" "$RUNDIR/tftp/$Q_BIN_NAME"
            if [ "$Q_DELIVERY" != embed ]; then
                cp "$SCRIPT_FILE" "$RUNDIR/tftp/autoexec.ipxe"
                chmod 600 "$RUNDIR/tftp/autoexec.ipxe"
            fi
            Q_BOOTFILE=$Q_BIN_NAME;;
        usb|iso)
            if [ -n "$Q_MEDIA_FILE" ]; then
                [ -r "$Q_MEDIA_FILE" ] || q_die "--media: cannot read $Q_MEDIA_FILE"
                Q_MEDIA_PATH=$Q_MEDIA_FILE
            else
                q_build_media
            fi;;
    esac
}

# The USB stick / CD with the script on it (make-usb.sh), in RUNDIR.
q_build_media() {
    local out efi lkrn script_args=()
    if [ "$Q_DELIVERY" != embed ]; then script_args=(--script "$SCRIPT_FILE"); fi
    case "$Q_FW/$Q_MEDIA_KIND" in
        uefi/usb)
            out=$RUNDIR/medium.img
            "$q_here/make-usb.sh" uefi-usb "$out" --efi "$Q_BIN_PATH" "${script_args[@]}" || q_die "cannot build the USB image (make-usb.sh above)";;
        bios/usb)
            out=$RUNDIR/medium.usb
            "$q_here/make-usb.sh" bios-usb "$out" --lkrn "$Q_BIN_PATH" "${script_args[@]}" || q_die "cannot build the USB image (make-usb.sh above)";;
        uefi/iso|bios/iso)
            out=$RUNDIR/medium.iso
            if [ "$Q_FW" = uefi ]; then efi=$Q_BIN_PATH; lkrn=${P2Q_LKRN:-$P2Q_IPXE_DIR/ipxe.lkrn}; else lkrn=$Q_BIN_PATH; efi=${P2Q_EFI:-$P2Q_IPXE_DIR/ipxe.efi}; fi
            [ -r "$lkrn" ] && [ -r "$efi" ] || q_die "the ISO holds the BIOS kernel (ipxe.lkrn) and the EFI binary (ipxe.efi): $lkrn and $efi must both exist (P2Q_LKRN / P2Q_EFI)"
            "$q_here/make-usb.sh" iso "$out" --lkrn "$lkrn" --efi "$efi" "${script_args[@]}" || q_die "cannot build the ISO (make-usb.sh above)";;
        *) q_die "internal: no medium for $Q_FW/$Q_MEDIA_KIND";;
    esac
    Q_MEDIA_PATH=$out
}

# ---------------------------------------------------------------------------------------------------------------------
# the QEMU command line
# ---------------------------------------------------------------------------------------------------------------------

q_build_qargs() {
    local model=$P2Q_NIC_MODEL rom1="" bi1="" cpu=host
    [ "$P2Q_ACCEL" = kvm ] || cpu=max
    QARGS=(-name "$Q_RUNID_Q" -machine "q35,accel=$P2Q_ACCEL" -cpu "$cpu" -smp "$P2Q_CPUS" -m "$P2Q_MEM_MB"
        -display none -vga std -no-reboot
        -serial "file:$Q_CONSOLE"
        -chardev "socket,id=qmp0,path=$Q_QMP,server=on,wait=off" -mon chardev=qmp0,mode=control
        -pidfile "$Q_PIDFILE")
    if [ "$Q_FW" = uefi ]; then
        QARGS+=(-drive "if=pflash,format=raw,unit=0,readonly=on,file=$P2Q_OVMF_CODE"
                -drive "if=pflash,format=raw,unit=1,file=$RUNDIR/OVMF_VARS.fd")
    else
        QARGS+=(-boot menu=off)
    fi
    # NIC 1: user-mode, restricted (no way out to the host's network; DHCP and TFTP are QEMU's own); it carries the PXE bootfile
    if [ "$Q_MEDIA_KIND" = pxe ]; then
        QARGS+=(-netdev "user,id=net0,restrict=on,tftp=$RUNDIR/tftp,bootfile=${Q_BOOTFILE:-$Q_BIN_NAME},hostname=wrp2q")
        bi1=",bootindex=1"
        # UEFI: OVMF's own driver; BIOS: QEMU's PXE option ROM (the one that downloads the bootfile)
        if [ "$Q_FW" = uefi ]; then rom1=",romfile="; fi
    else
        QARGS+=(-netdev "user,id=net0,restrict=on,hostname=wrp2q")
        rom1=",romfile="
    fi
    QARGS+=(-device "$model,netdev=net0,mac=$Q_MAC_USER$rom1$bi1")
    # NIC 2: the lab's layer 2 (QEMU's multicast socket on the loopback address), no option ROM
    QARGS+=(-netdev "socket,id=lab,mcast=$P2Q_MCAST,localaddr=$P2Q_MCAST_LOCALADDR"
            -device "$model,netdev=lab,mac=$Q_MAC_LAB,romfile=")
    case "$Q_MEDIA_KIND" in
        usb) QARGS+=(-drive "if=none,id=usb0,file=$Q_MEDIA_PATH,format=raw,readonly=on" -device qemu-xhci,id=xhci
                     -device usb-storage,bus=xhci.0,drive=usb0,bootindex=1);;
        iso) QARGS+=(-drive "if=none,id=cd0,file=$Q_MEDIA_PATH,media=cdrom,readonly=on,format=raw"
                     -device ide-cd,drive=cd0,bootindex=1);;
    esac
    if [ -n "$Q_DISK" ]; then
        QARGS+=(-drive "if=none,id=hd0,file=${DISK_PATH:-$Q_DISK},format=${DISK_FMT:-$Q_DISK_FMT}" -device ide-hd,drive=hd0,bootindex=2)
    fi
    local a
    for a in ${Q_QEXTRA[@]+"${Q_QEXTRA[@]}"}; do QARGS+=("$a"); done
    q_check_no_host_net
}

# The last line of defence: whatever was assembled, it has no tap, bridge, forward or other way to the host's network.
q_check_no_host_net() {
    local a
    for a in "${QARGS[@]}"; do
        case "$a" in
            -net|-nic) q_die "internal: '$a' in the command line";;
            tap*|*,ifname=*|*bridge*|*hostfwd*|*guestfwd*|*vde*|*vhost*) q_die "internal: '$a' would touch the host's network";;
            *tcp:*|*telnet:*|*udp:*|*,host=*|*,port=*|*,connect=*|*,listen=*|*,addr=*|-vnc|-spice|-gdb|-s|-incoming|-virtfs|-fsdev|-monitor) q_die "internal: '$a' would open a socket on the host";;
            *file=nbd:*|*file=nbd+*|*file=iscsi:*|*file=ssh:*|*file=http:*|*file=https:*|*file=ftp:*|*file=nfs:*|*file=gluster*|*file=rbd:*) q_die "internal: '$a' reaches a network resource";;
        esac
    done
}

# ---------------------------------------------------------------------------------------------------------------------
# QMP (control socket) and keystrokes
# ---------------------------------------------------------------------------------------------------------------------

# q_qmp COMMAND [JSON-ARGUMENTS]: run one QMP command; prints the result; non-zero when QEMU answered with an error or not at all.
q_qmp() {
    python3 -I - "$Q_QMP" "$@" <<'PY'
import json, socket, sys
path, cmd = sys.argv[1], sys.argv[2]
args = json.loads(sys.argv[3]) if len(sys.argv) > 3 else None
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(5)
    s.connect(path)
    f = s.makefile("rw")
    f.readline()
    def call(c, a=None):
        m = {"execute": c}
        if a is not None:
            m["arguments"] = a
        f.write(json.dumps(m) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if not line:
                return {"return": {}} if c == "quit" else {"error": "connection closed"}
            r = json.loads(line)
            if "return" in r or "error" in r:
                return r
    call("qmp_capabilities")
    r = call(cmd, args)
    print(json.dumps(r.get("return", r)))
    sys.exit(1 if "error" in r else 0)
except (OSError, ValueError) as e:
    print("qmp: %s" % e, file=sys.stderr)
    sys.exit(1)
PY
}

# q_type TEXT: type TEXT and Enter at the guest's keyboard (QMP send-key). ';' is not typed: it separates lines in the caller.
q_type() {
    python3 -I - "$Q_QMP" "$1" <<'PY'
import json, socket, sys, time
path, text = sys.argv[1], sys.argv[2]
plain = {" ": ["spc"], "-": ["minus"], ".": ["dot"], "/": ["slash"], "\\": ["backslash"], ";": ["semicolon"],
         ":": ["shift", "semicolon"], "_": ["shift", "minus"]}
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(path)
f = s.makefile("rw")
f.readline()
def call(c, a=None):
    m = {"execute": c}
    if a is not None:
        m["arguments"] = a
    f.write(json.dumps(m) + "\n")
    f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
call("qmp_capabilities")
def press(keys):
    r = call("send-key", {"keys": [{"type": "qcode", "data": k} for k in keys], "hold-time": 40})
    if "error" in r:
        sys.exit("send-key failed: %s" % r["error"])
    time.sleep(0.08)
for ch in text + "\n":
    if ch == "\n":
        press(["ret"])
    elif ch in plain:
        press(plain[ch])
    elif ch.isalpha() and ch.isupper():
        press(["shift", ch.lower()])
    elif ch.isalnum():
        press([ch])
    else:
        sys.exit("cannot type %r" % ch)
PY
}

# q_keys "k1 k2 ...": press these keys (QEMU key names) one after the other.
q_keys() {
    python3 -I - "$Q_QMP" "$1" <<'PY'
import json, socket, sys, time
path, keys = sys.argv[1], sys.argv[2].split()
s = socket.socket(socket.AF_UNIX)
s.settimeout(10)
s.connect(path)
f = s.makefile("rw")
f.readline()
def call(c, a=None):
    m = {"execute": c}
    if a is not None:
        m["arguments"] = a
    f.write(json.dumps(m) + "\n")
    f.flush()
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            return r
call("qmp_capabilities")
for k in keys:
    r = call("send-key", {"keys": [{"type": "qcode", "data": k}], "hold-time": 60})
    if "error" in r:
        sys.exit("send-key %s failed: %s" % (k, r["error"]))
    time.sleep(0.6)
PY
}

# ---------------------------------------------------------------------------------------------------------------------
# the guest: start, watch, stop
# ---------------------------------------------------------------------------------------------------------------------

# The state letter of a pid ("" when there is no such process).
q_pstate() { ps -o stat= -p "$1" 2>/dev/null | tr -d ' ' | cut -c1 || true; }

q_alive() {
    local s
    [ -n "${QPID:-}" ] || return 1
    s=$(q_pstate "$QPID")
    [ -n "$s" ] && [ "$s" != Z ]
}

# Is $QPID really this run's QEMU? (the command line carries the run's name)
q_is_ours() {
    local args
    [ -n "${QPID:-}" ] || return 1
    args=$(ps -ww -o args= -p "$QPID" 2>/dev/null || true)
    case "$args " in *"-name $Q_RUNID_Q "*) return 0;; esac
    return 1
}

q_start() {
    local logq=$RUNDIR/qemu.out
    q_info "starting $Q_RUNID_Q ($Q_FW, $Q_MEDIA_KIND, ${P2Q_CPUS} cores, ${P2Q_MEM_MB} MiB, nice $P2Q_NICE choom 600, up to ${P2Q_TIMEOUT_S} s)"
    "${Q_WRAP[@]}" "$P2Q_QEMU" "${QARGS[@]}" >"$logq" 2>&1 9>&- &
    QPID=$!
    T0=$SECONDS
    # QEMU that cannot start (a bad option, no KVM) exits within a moment
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! q_alive; then
            q_info "QEMU ended right after the start; its message:"
            sed 's/^/    /' "$logq" >&2 || true
            QPID=""
            return 1
        fi
        if [ -S "$Q_QMP" ] && [ -s "$Q_PIDFILE" ]; then break; fi
        sleep 0.3
    done
    q_is_ours || { q_warn "pid $QPID is not the guest ($(ps -ww -o args= -p "$QPID" 2>/dev/null | cut -c1-80))"; return 1; }
    return 0
}

q_stop() {
    [ -n "${QPID:-}" ] || return 0
    if q_alive && q_is_ours; then
        q_qmp quit >/dev/null 2>&1 || kill -TERM "$QPID" 2>/dev/null || true
        for _ in $(seq 1 40); do q_alive || break; sleep 0.25; done
        if q_alive && q_is_ours; then
            kill -TERM "$QPID" 2>/dev/null || true
            for _ in $(seq 1 20); do q_alive || break; sleep 0.25; done
        fi
        if q_alive && q_is_ours; then kill -KILL "$QPID" 2>/dev/null || true; fi
    fi
    wait "$QPID" 2>/dev/null || true
    QPID=""
}

# Any qemu process whose command line carries this run's directory or name?
q_leftovers() {
    # the name is matched with its option and a trailing space, so that run "...-12" is not taken for run "...-123"
    ps -eww -o pid=,args= 2>/dev/null | awk -v pat="-name $Q_RUNID_Q " '$2 ~ /(^|\/)qemu-system-[a-z0-9_]+$/ && index($0 " ", pat) { print $1 }'
}

# Size of a file in bytes (0 when there is none); GNU and BSD stat.
q_file_size() { { stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null; } || echo 0; }

# Console text without carriage returns and terminal escape sequences, for the markers.
q_clean_console() {
    [ -f "$Q_CONSOLE" ] || { : > "$RUNDIR/console.txt"; return 0; }
    tr -d '\r\000' < "$Q_CONSOLE" | LC_ALL=C sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\x1b[()][A-Z0-9]//g' > "$RUNDIR/console.txt"
}

q_has() { grep -a -q -E -- "$1" "$RUNDIR/console.txt" 2>/dev/null; }
# q_has_after N REGEX: only in the lines after the first N (what appeared after the shell commands were typed)
q_has_after() { tail -n +$(($1 + 1)) "$RUNDIR/console.txt" 2>/dev/null | grep -a -q -E -- "$2"; }

# Look at the console and note what stage the guest is in (seconds since the start of the first sight).
q_scan() {
    q_clean_console
    if [ -z "$S_IPXE" ] && q_has 'WRRUN-BEGIN|WRRUN-STUB|iPXE initialising devices|Open Source Network Boot Firmware'; then S_IPXE=$((SECONDS - T0)); fi
    if [ -z "$S_NET" ] && q_has 'WRRUN-NET-OK'; then S_NET=$((SECONDS - T0)); fi
    if [ -z "$S_SAN" ]; then
        if q_has 'WRRUN-SAN-OK'; then S_SAN=$((SECONDS - T0)); SAN_STATE=ok
        elif q_has 'WRRUN-SAN-FAILED'; then S_SAN=$((SECONDS - T0)); SAN_STATE=failed; fi
    fi
    if [ -z "$S_END" ] && q_has 'WRRUN-END'; then S_END=$((SECONDS - T0)); fi
    if [ -z "${S_NETFAIL:-}" ] && q_has 'WRRUN-(NO-LAB-NIC|NET-FAILED)'; then S_NETFAIL=$((SECONDS - T0)); fi
    if [ -z "$S_OS" ] && q_has "$Q_OK_MARK"; then S_OS=$((SECONDS - T0)); fi
    # the shell's own prompt at the start of a line (OVMF's setup menu is drawn on the serial line too, and it mentions the shell)
    if [ -z "$S_SHELL" ] && q_has '^(Shell> |Shell>$|FS[0-9]+:\\> |BLK[0-9]+:\\> )'; then S_SHELL=$((SECONDS - T0)); fi
    if [ -z "$S_MARKER" ] && [ -n "$Q_MARKER" ] && q_has "$Q_MARKER"; then S_MARKER=$((SECONDS - T0)); fi
    if [ -z "$S_FAILMARK" ] && [ -n "$Q_FAIL_MARK" ] && q_has "$Q_FAIL_MARK"; then S_FAILMARK=$((SECONDS - T0)); fi
    if [ -n "$Q_SHELL" ] && [ -n "$S_SHELL_TYPED" ] && [ -z "$S_SHELL_OK" ] && q_has_after "$S_SHELL_MARK" "$Q_SHELL_EXPECT"; then S_SHELL_OK=$((SECONDS - T0)); fi
}

# The expectation of the run, as reached so far.
q_met() {
    case "$Q_EXPECT" in
        ipxe) if q_custom_script || [ "$Q_DELIVERY" = embed ]; then [ -n "$S_IPXE" ]; else [ -n "$S_IPXE" ] && [ -n "$S_END" ]; fi;;
        san) [ "$SAN_STATE" = ok ];;
        os) [ -n "$S_OS" ];;
        shell) [ -n "$S_SHELL" ] && { [ -z "$Q_SHELL" ] || [ -n "$S_SHELL_OK" ]; };;
        marker) [ -n "$S_MARKER" ];;
        none) return 1;;
    esac
}

# OVMF does not start its shell by itself: when everything else has returned, it stops in its setup menu, which is drawn on the
# screen only (nothing of it reaches the serial line). The run script has said WRRUN-END; some seconds later the keys of --menu-keys
# take the menu to Boot Manager and "EFI Internal Shell" (blind: the number of boot entries in front of the shell is known from the
# NICs and the media this script made; a different machine needs other keys: a screenshot of a run that did not get to the shell is
# kept for that).
q_menu_step() {
    [ "$Q_EXPECT" = shell ] && [ -n "$Q_MENU" ] && [ -n "$S_END" ] && [ -z "$S_SHELL" ] && [ -z "$S_MENU" ] || return 0
    [ $((SECONDS - T0)) -ge $((S_END + 10)) ] || return 0
    q_info "OVMF is in its setup menu: keys to the EFI Internal Shell: $Q_MENU"
    q_keys "$Q_MENU" || q_warn "could not press the keys of --menu-keys"
    S_MENU=1
}

# Type the shell commands once the UEFI shell prompt is up (row U0).
q_shell_step() {
    [ -n "$Q_SHELL" ] && [ -n "$S_SHELL" ] && [ -z "$S_SHELL_TYPED" ] || return 0
    [ $((SECONDS - T0)) -ge $((S_SHELL + 3)) ] || return 0   # let the prompt settle
    local cmd IFS=';'
    q_clean_console
    S_SHELL_MARK=$(wc -l < "$RUNDIR/console.txt")      # "Mapping table" is in the shell's banner too: only what comes after counts
    for cmd in $Q_SHELL; do
        IFS=$' \t\n'
        q_info "typing into the UEFI shell: $cmd"
        q_type "$cmd" || { q_warn "could not type into the guest"; break; }
        sleep 3
        IFS=';'
    done
    IFS=$' \t\n'
    S_SHELL_TYPED=1
}

q_wait() {
    local deadline=$((SECONDS + P2Q_TIMEOUT_S))
    END_REASON=""
    while :; do
        if ! q_alive; then END_REASON=guest-exited; break; fi
        q_scan
        if [ -n "$S_FAILMARK" ]; then END_REASON=fail-marker; break; fi
        if [ "$SAN_STATE" = failed ] && { [ "$Q_EXPECT" = san ] || [ "$Q_EXPECT" = os ]; } && [ "$Q_STAY" = 0 ] && ! q_custom_script; then
            # the target could not be opened: the rest of the timeout would only wait for something that cannot come
            sleep 1
            END_REASON=san-failed
            break
        fi
        if [ -n "${S_NETFAIL:-}" ] && [ -z "$S_SAN" ] && { [ "$Q_EXPECT" = san ] || [ "$Q_EXPECT" = os ]; } && [ "$Q_STAY" = 0 ] && ! q_custom_script; then
            # the lab NIC is missing or has no link (with --on-fail hold the guest would sit there until the timeout)
            sleep 1
            END_REASON=net-failed
            break
        fi
        # a guest that floods the serial line (a kernel in a panic loop, a script in a tight echo loop) must not fill the disk
        if [ "$(q_file_size "$Q_CONSOLE")" -gt $((P2Q_CONSOLE_MAX_MB * 1048576)) ]; then
            q_warn "the serial log passed $P2Q_CONSOLE_MAX_MB MiB: stopping the guest (P2Q_CONSOLE_MAX_MB)"
            END_REASON=console-flood
            break
        fi
        if q_met && [ "$Q_STAY" = 0 ]; then END_REASON=expectation; break; fi
        if [ "$SECONDS" -ge "$deadline" ]; then END_REASON=timeout; break; fi
        q_menu_step
        q_shell_step
        sleep 1
    done
    q_scan   # the last lines of a guest that has just powered itself off
}

# ---------------------------------------------------------------------------------------------------------------------
# the verdict and the clean-up
# ---------------------------------------------------------------------------------------------------------------------

# Never leave the key in a log: look for it in the console and the QEMU output.
q_key_scan() {
    KEY_LEAK=0
    [ -s "$KEYSCAN" ] || return 0
    local f
    for f in "$Q_CONSOLE" "$RUNDIR/console.txt" "$RUNDIR/qemu.out"; do
        [ -f "$f" ] || continue
        if grep -a -q -F -f "$KEYSCAN" "$f" 2>/dev/null; then KEY_LEAK=1; fi
    done
}

q_finish() {
    local met=1 rc stamp_secs
    q_met && met=0
    # a picture of the screen of a guest that did not get where it should (BIOS runs have no other trace)
    if [ "$met" != 0 ] && [ "$P2Q_SCREENDUMP" = 1 ] && q_alive && q_is_ours; then
        q_qmp screendump "{\"filename\":\"$RUNDIR/screen.ppm\"}" >/dev/null 2>&1 || true
    fi
    q_stop
    q_key_scan
    stamp_secs=$((SECONDS - T0))
    if [ "$KEY_LEAK" = 1 ]; then
        q_warn "the cephx key appears in the guest's console output: the logs of this run are discarded (this is a bug in whatever printed it)"
    else
        [ ! -f "$Q_CONSOLE" ] || cp -f "$Q_CONSOLE" "$LOGBASE.console"
        [ ! -f "$RUNDIR/qemu.out" ] || cp -f "$RUNDIR/qemu.out" "$LOGBASE.qemu"
        if [ -f "$RUNDIR/screen.ppm" ] && [ "$met" != 0 ]; then cp -f "$RUNDIR/screen.ppm" "$LOGBASE.screen.ppm"; fi
    fi
    RESULT="RESULT row=$Q_ROW run=$Q_RUNID expect=$Q_EXPECT met=$([ "$met" = 0 ] && echo 1 || echo 0) ipxe=${S_IPXE:--} net=${S_NET:--} san=${SAN_STATE:-none}@${S_SAN:--} end=${S_END:--} os=${S_OS:--} stop=$END_REASON secs=$stamp_secs console=$LOGBASE.console"
    echo "$RESULT" > "$LOGBASE.result"
    LEFT=$(q_leftovers | tr '\n' ' ')
    q_cleanup
    if [ "$KEY_LEAK" = 1 ]; then rm -f "$LOGBASE.console" "$LOGBASE.qemu" "$LOGBASE.screen.ppm"; echo "${RESULT%% console=*} console=discarded-key-leak"; return 4; fi
    if [ -n "$LEFT" ]; then q_warn "a QEMU process of this run is still alive (pid $LEFT)"; echo "$RESULT"; return 4; fi
    echo "$RESULT"
    rc=$met
    return "$rc"
}

# Remove what this run made. Only the files it created, by name (nothing is deleted with a variable path).
q_cleanup() {
    [ -n "${RUNDIR:-}" ] && [ -d "$RUNDIR" ] || return 0
    if [ "${Q_KEEP:-0}" = 1 ]; then
        q_warn "--keep: $RUNDIR stays; it holds the iPXE script (with the key, if one was used): delete it when you are done"
        return 0
    fi
    local f
    for f in autoexec.ipxe key.txt OVMF_VARS.fd console.log console.txt qemu.out qemu.pid screen.ppm medium.img medium.usb medium.iso disk-overlay.qcow2; do
        rm -f "$RUNDIR/$f"
    done
    if [ -d "$RUNDIR/tftp" ]; then
        for f in "$RUNDIR/tftp/"*; do [ -e "$f" ] && rm -f "$f"; done
        rmdir "$RUNDIR/tftp" 2>/dev/null || true
    fi
    rm -f "$Q_QMP"
    rmdir "$RUNDIR" 2>/dev/null || q_warn "$RUNDIR holds files this script did not make; left alone"
}

# ---------------------------------------------------------------------------------------------------------------------
# a whole run
# ---------------------------------------------------------------------------------------------------------------------

q_print_plan() {
    q_info "dry run: nothing is started, nothing is created"
    q_info "row $Q_ROW ($Q_KIND): $Q_FW firmware, boot from $Q_MEDIA_KIND, iPXE binary $Q_BIN_PATH, delivery $Q_DELIVERY, expect $Q_EXPECT"
    q_info "lab NIC: $Q_MAC_LAB, address $Q_IP/24 on $P2Q_MCAST; user NIC: $Q_MAC_USER"
    if [ "$Q_DELIVERY" != embed ] || q_custom_script; then
        if q_custom_script; then
            q_info "the iPXE script is $Q_SCRIPT (not shown)"
        else
            q_gen_args
            q_info "the iPXE script (key hidden):"
            "$q_here/gen-script.sh" --redact "${GEN_ARGS[@]}" | sed 's/^/    | /' || exit 2
        fi
    fi
    local RUNDIR=$P2Q_WORK/runs/$Q_ROW-DRYRUN Q_QMP=$P2Q_WORK/s/DRYRUN.sock Q_CONSOLE
    Q_CONSOLE=$RUNDIR/console.log
    Q_PIDFILE=$RUNDIR/qemu.pid
    Q_RUNID_Q=wrp2q-$Q_ROW-DRYRUN
    [ "$Q_MEDIA_KIND" = pxe ] || Q_MEDIA_PATH=${Q_MEDIA_FILE:-$RUNDIR/medium.$([ "$Q_MEDIA_KIND" = iso ] && echo iso || echo img)}
    Q_BOOTFILE=$Q_BIN_NAME
    q_build_qargs
    printf 'would run:'
    printf ' %q' "${Q_WRAP[@]}" "$P2Q_QEMU" "${QARGS[@]}"
    printf '\n'
}

q_run() {
    q_resolve
    q_wrap
    if [ "$Q_FW" = uefi ]; then q_find_ovmf; fi
    if [ "$Q_DRY" = 1 ]; then q_print_plan; return 0; fi
    command -v "$P2Q_QEMU" >/dev/null 2>&1 || q_die "$P2Q_QEMU not found (P2Q_QEMU)"
    command -v python3 >/dev/null 2>&1 || q_die "python3 is needed (QMP: stop the guest, type into the UEFI shell, screendump)"
    if [ "$P2Q_ACCEL" = kvm ]; then
        [ -r /dev/kvm ] && [ -w /dev/kvm ] || q_die "/dev/kvm is not usable (a test guest on TCG would be too slow to mean anything; P2Q_ACCEL=tcg to try anyway)"
    fi
    umask 077     # everything a run makes (script, console, copies) is private to the caller, whatever the shell's umask
    q_prepare_work
    # The address, budget and "is the name free" checks, and the start of the guest, are one step: two run scripts started at the
    # same moment would otherwise both pass the budget check. The lock (fd 9, never inherited by QEMU) is held until QEMU runs.
    q_lock
    q_unique_check
    q_budget_check
    q_new_run
    # whatever happens from here on: stop our guest, remove our files
    S_IPXE="" S_NET="" S_SAN="" S_END="" S_OS="" S_SHELL="" S_MARKER="" S_FAILMARK="" S_SHELL_TYPED="" S_SHELL_OK="" S_SHELL_MARK=0 S_MENU="" S_NETFAIL="" SAN_STATE="" END_REASON="" KEY_LEAK=0
    QPID="" T0=$SECONDS LEFT="" RESULT=""
    # shellcheck disable=SC2329  # called by the traps
    q_abort() { local s=$1; trap - EXIT INT TERM HUP; q_stop; q_cleanup; q_unlock; exit "$s"; }
    trap 'q_abort 130' INT
    trap 'q_abort 143' TERM
    trap 'q_abort 129' HUP
    trap 'q_abort 2' EXIT
    q_make_script
    q_stage_files
    if [ "$Q_FW" = uefi ]; then cp -f "$P2Q_OVMF_VARS" "$RUNDIR/OVMF_VARS.fd"; chmod 600 "$RUNDIR/OVMF_VARS.fd"; fi
    if [ -n "$Q_DISK" ]; then
        [ -r "$Q_DISK" ] || q_die "--disk: cannot read $Q_DISK"
        if [ "$Q_DISK_WRITE" = 1 ]; then
            DISK_PATH=$Q_DISK; DISK_FMT=$Q_DISK_FMT
        else
            qemu-img create -q -f qcow2 -F "$Q_DISK_FMT" -b "$(cd "$(dirname "$Q_DISK")" && pwd)/$(basename "$Q_DISK")" "$RUNDIR/disk-overlay.qcow2" >/dev/null || q_die "cannot create the disk overlay"
            DISK_PATH=$RUNDIR/disk-overlay.qcow2; DISK_FMT=qcow2
        fi
    fi
    Q_BOOTFILE=${Q_BOOTFILE:-$Q_BIN_NAME}
    q_build_qargs
    if ! q_start; then
        trap - EXIT INT TERM HUP
        q_stop
        q_cleanup
        q_unlock
        echo "RESULT row=$Q_ROW run=$Q_RUNID expect=$Q_EXPECT met=0 stop=qemu-did-not-start"
        return 2
    fi
    q_unlock
    q_wait
    # the traps stay armed through q_finish: a signal while the guest is being stopped and the files removed must still end in the
    # clean-up (the run directory holds the key); q_finish has done its own clean-up when it returns
    local rc=0
    q_finish || rc=$?
    trap - EXIT INT TERM HUP
    return "$rc"
}

# The entry point of a run script: q_main KIND "$@".
q_main() {
    local kind=$1 a
    shift
    Q_PROG=$(basename "$0")
    # --work decides the defaults derived from it (the iPXE directory, the budget root): read it before they are made
    local prev=""
    for a in "$@"; do
        if [ "$prev" = --work ]; then P2Q_WORK=$a; fi
        prev=$a
    done
    q_defaults
    q_kind_setup "$kind"
    q_parse "$@"
    q_run
}
