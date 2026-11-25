#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 QEMU scripts: generate the iPXE script of one test run (or the constant stub of a PXE-only build).
#
#   gen-script.sh -o OUT [options]            write the run script to OUT (mode 600)
#   gen-script.sh --redact [options]          print the script with the key replaced by <redacted> (nothing is written)
#   gen-script.sh --stub -o OUT               the constant stub for iPXE binaries that have no media to carry a script (see below)
#   gen-script.sh --smoke -o OUT              the constant driver smoke script of smoke.sh (see below)
#
# What the run script does (everything it prints starts with WRRUN-, which is what the run scripts wait for):
#   1. finds the NIC on the lab's layer 2 by its MAC address (net0 .. net7), gives it the static address, opens it and waits for link
#   2. sets the rbd-key setting from a key file (never from the command line, never printed) and runs sanhook / sanboot on the rbd:// URI
#   3. prints WRRUN-SAN-OK (sanhook) or WRRUN-SAN-FAILED 0x<iPXE error number>, then leaves (exit to the firmware, power off) or,
#      after a failure, powers off / holds / exits, and always prints WRRUN-END first. sanboot does not print WRRUN-SAN-OK: if it
#      comes back at all nothing booted, and the script says WRRUN-BOOT-RETURNED and fails.
#
#   -o FILE             where to write the script (mode 600; the directory should be 700). "-" is refused unless --redact is given.
#   --row ID            label that appears in WRRUN-BEGIN (default X)
#   --ip A.B.C.D        the guest's address on the lab network (default 10.77.0.20)        --netmask M (default 255.255.255.0)
#   --lab-mac MAC       MAC of the guest's lab NIC (default: derived from the address, as the run scripts do)
#   --uri URI           the whole rbd:// URI (no password in it: a user:password@ is refused)
#   --user U --mon HOSTS --pool P --image I [--snap S]   compose the URI (HOSTS: ip[:port][,ip[:port]...], default 10.77.0.10:3300)
#   --opt NAME=VALUE    a driver option of design section 8 (mode ro timeout readahead fsid devpath handoff mapmem monmsg); repeatable
#   --raw-query STR     append ?STR verbatim (for negative tests: an unknown option, a bad value)
#   --user-setting      give the user through the rbd-user setting instead of user@ in the URI
#   --key-file F        file with the cephx key: the bare base64 as printed by `ceph auth get-key`, or a keyring with a "key = " line.
#                       It must be mode 600 (no group or other access). The key goes into the script and nowhere else.
#   --fake-key          a random syntactically valid legacy key (negative controls: it opens nothing); --no-key: no key at all
#   --action A          sanhook (default), sanboot or none
#   --drive N           drive number for sanhook / sanboot (BIOS: 0x81 for a hooked disk next to a local one)
#   --no-describe       sanhook / sanboot --no-describe (EFI without the ACPI table protocol)
#   --leave L           after a successful sanhook: exit (default; back to the firmware, which then boots the next device or the UEFI shell),
#                       poweroff, or none (fall off the end of the script)
#   --on-fail F         poweroff (default), hold (loop forever: for the timeout path of the run scripts) or exit
#   --append FILE       iPXE commands to insert after WRRUN-SAN-OK (measurement steps)
#   --link-timeout MS   how long to wait for the lab NIC's link (default 10000)
#
# The stub (--stub): iPXE has no media to read a script from when it is started by PXE on a BIOS machine (the UEFI build reads
# autoexec.ipxe from the TFTP server by itself). The stub is built into the binary once (build.sh build -e stub.ipxe ...), brings up
# the NIC that PXE used, and runs autoexec.ipxe from the same TFTP server: the run script then needs no build. It holds no secret.
#
# The smoke script (--smoke): the skeleton's firmware test, kept as a constant. It needs no network and no key (the URIs below carry
# no real key and point at nothing): a URI with a password component must be refused by the driver with its one console line, a
# well-formed URI to a monitor that cannot answer must fail closed (whatever the driver does today: "Operation not supported" while
# opening is not implemented, a connection error later), and a URI of a scheme nobody knows is the control that shows the stock
# error of iPXE. It prints "SMOKE-DONE" last; smoke.sh checks every line.
#
# The key: read from the file, kept in a shell variable, written to the output file, never printed, never in an argument of any
# program, never in an error message.
set -euo pipefail
umask 077
LC_ALL=C
export LC_ALL

die() { echo "gen-script.sh: $*" >&2; exit 2; }

usage() { awk 'NR >= 3 && /^#/ { sub(/^# ?/, ""); print; next } NR >= 3 { exit }' "${BASH_SOURCE[0]}"; }

out="" row=X ip=10.77.0.20 mask=255.255.255.0 mac="" uri="" user="" mon=10.77.0.10:3300 pool="" image="" snap=""
opts=() rawq="" usersetting=0 keyfile="" fake=0 nokey=0 action=sanhook drive="" nodescribe=0 leave=exit onfail=poweroff
append="" linkto=10000 redact=0 stub=0 smoke=0

need() { [ "$#" -ge 2 ] || die "option $1 needs a value"; }

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0;;
        -o) need "$@"; out=$2; shift 2;;
        --redact) redact=1; shift;;
        --stub) stub=1; shift;;
        --smoke) smoke=1; shift;;
        --row) need "$@"; row=$2; shift 2;;
        --ip) need "$@"; ip=$2; shift 2;;
        --netmask) need "$@"; mask=$2; shift 2;;
        --lab-mac) need "$@"; mac=$2; shift 2;;
        --uri) need "$@"; uri=$2; shift 2;;
        --user) need "$@"; user=$2; shift 2;;
        --mon) need "$@"; mon=$2; shift 2;;
        --pool) need "$@"; pool=$2; shift 2;;
        --image) need "$@"; image=$2; shift 2;;
        --snap) need "$@"; snap=$2; shift 2;;
        --opt) need "$@"; opts+=("$2"); shift 2;;
        --raw-query) need "$@"; rawq=$2; shift 2;;
        --user-setting) usersetting=1; shift;;
        --key-file) need "$@"; keyfile=$2; shift 2;;
        --fake-key) fake=1; shift;;
        --no-key) nokey=1; shift;;
        --action) need "$@"; action=$2; shift 2;;
        --drive) need "$@"; drive=$2; shift 2;;
        --no-describe) nodescribe=1; shift;;
        --leave) need "$@"; leave=$2; shift 2;;
        --on-fail) need "$@"; onfail=$2; shift 2;;
        --append) need "$@"; append=$2; shift 2;;
        --link-timeout) need "$@"; linkto=$2; shift 2;;
        *) die "unknown option $1 (see --help)";;
    esac
done

# ---------------------------------------------------------------------------------------------------------------------
# the stub
# ---------------------------------------------------------------------------------------------------------------------
emit_stub() {
    cat <<'EOF'
#!ipxe
# winrbd Phase 2 stub: bring up the NIC that PXE used and run autoexec.ipxe from the same TFTP server. No secret in here.
echo WRRUN-STUB
dhcp net0 || goto stub-fail
chain tftp://${next-server}/autoexec.ipxe || chain tftp://10.0.2.2/autoexec.ipxe || goto stub-fail
exit
:stub-fail
echo WRRUN-STUB-FAILED 0x${errno:hexraw}
sleep 2
exit
EOF
}

emit_smoke() {
    cat <<'EOF'
#!ipxe
# winrbd Phase 2 smoke script (gen-script.sh --smoke). No secret in here: the "password" is a placeholder, the monitor does not exist.
echo winrbd driver smoke test
echo test: password in URI must be refused
sanhook rbd://smoke:placeholder@10.77.0.253:3300/smoke/none || goto refused
echo WRSMOKE-FAIL password-accepted
goto done
:refused
echo refused: 0x${errno:hexraw}
echo test: well formed URI must fail closed
sanhook rbd://smoke@10.77.0.253:3300/smoke/none?timeout=3 || goto closed
echo WRSMOKE-FAIL wellformed-opened
goto done
:closed
echo failed closed: 0x${errno:hexraw}
echo test: unknown scheme control
sanhook nosuchscheme://smoke/none || goto control
echo WRSMOKE-FAIL control-opened
goto done
:control
echo control: 0x${errno:hexraw}
:done
echo SMOKE-DONE
exit
EOF
}

if [ "$stub" = 1 ] || [ "$smoke" = 1 ]; then
    [ "$stub$smoke" != 11 ] || die "--stub and --smoke exclude each other"
    [ -n "$out" ] || die "--stub / --smoke need -o FILE"
    [ "$out" != - ] || die "--stub / --smoke need a file, not stdout"
    if [ "$stub" = 1 ]; then emit_stub > "$out"; else emit_smoke > "$out"; fi
    exit 0
fi

# ---------------------------------------------------------------------------------------------------------------------
# validation (every value ends up inside an iPXE script line: allow only plain shapes)
# ---------------------------------------------------------------------------------------------------------------------
# each octet 0 to 255 without a leading zero (iPXE reads 010 as octal 8)
re_oct='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
re_ip="^$re_oct\\.$re_oct\\.$re_oct\\.$re_oct\$"
re_name='^[A-Za-z0-9._-]+$'
[[ "$row" =~ ^[A-Za-z0-9_-]{1,16}$ ]] || die "--row must be 1 to 16 letters, digits, - or _"
[[ "$ip" =~ $re_ip ]] || die "--ip must be an IPv4 address"
[[ "$mask" =~ $re_ip ]] || die "--netmask must be an IPv4 netmask"
[[ "$linkto" =~ ^[0-9]{1,6}$ ]] || die "--link-timeout must be a number of milliseconds"
case "$action" in sanhook|sanboot|none) ;; *) die "--action must be sanhook, sanboot or none";; esac
case "$leave" in exit|poweroff|none) ;; *) die "--leave must be exit, poweroff or none";; esac
case "$onfail" in poweroff|hold|exit) ;; *) die "--on-fail must be poweroff, hold or exit";; esac
if [ -n "$drive" ]; then
    [[ "$drive" =~ ^(0x[0-9A-Fa-f]{1,2}|[1-9][0-9]{0,2}|0)$ ]] || die "--drive must be a drive number such as 0x81 (decimal without a leading zero: iPXE would read 010 as octal)"
    # a BIOS drive number is one byte (a larger one would be cut off by the INT 13h hook, and hook some other drive)
    if [ $((drive)) -gt 255 ]; then die "--drive must be 0 to 255 (0x00 to 0xff)"; fi
fi
if [ -z "$mac" ]; then
    oct=${ip##*.}
    [ "$oct" -ge 0 ] && [ "$oct" -le 127 ] || die "--ip: cannot derive a MAC from the last octet $oct (give --lab-mac)"
    mac=$(printf '52:54:00:77:12:%02x' $((oct + 128)))
fi
[[ "$mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]] || die "--lab-mac is not a MAC address"
mac=$(printf '%s' "$mac" | tr 'A-F' 'a-f')   # iPXE prints MAC addresses in lower case; iseq is case sensitive
if [ -n "$append" ]; then [ -r "$append" ] || die "--append: cannot read $append"; fi

# A key, a secret or a password never goes in a URI (the driver refuses it as well; and the plan printed by -n / --redact shows the URI).
re_secretq='(^|[?&,])(key|rbd-key|secret|password|passwd|pass|pw|token|auth)='
# The URI.
known_opts=" mode ro timeout readahead fsid devpath handoff mapmem monmsg "
query=""
for o in ${opts[@]+"${opts[@]}"}; do
    [[ "$o" =~ ^([a-z]+)=([A-Za-z0-9._-]+)$ ]] || die "--opt must look like name=value (letters, digits . _ -): '$o'"
    case "$known_opts" in *" ${BASH_REMATCH[1]} "*) ;; *) die "--opt: unknown option '${BASH_REMATCH[1]}' (a driver option of design section 8; use --raw-query to test the refusal)";; esac
    query="$query${query:+&}$o"
done
if [ -n "$rawq" ]; then
    re_rawq='^[A-Za-z0-9._=&,-]*$'
    [[ "$rawq" =~ $re_rawq ]] || die "--raw-query may hold only letters, digits and . _ = & , -"
    ! [[ "$rawq" =~ $re_secretq ]] || die "--raw-query: a key / secret / password does not go in the URI (use --key-file)"
    query="$query${query:+&}$rawq"
fi
if [ "$action" != none ]; then
    if [ -n "$uri" ]; then
        re_uri='^rbd://[]A-Za-z0-9._@:,/?=&[-]+$'
        [[ "$uri" =~ $re_uri ]] || die "--uri: not a plain rbd:// URI"
        case "$uri" in *\?*) ! [[ "?${uri#*\?}" =~ $re_secretq ]] || die "--uri: a key / secret / password in the query is refused (use --key-file)";; esac
        # userinfo is everything before the last @ of the authority; a colon in it is a password
        auth=${uri#rbd://}
        auth=${auth%%/*}
        case "$auth" in
            *@*) userinfo=${auth%@*}; case "$userinfo" in *:*) die "--uri: a password in the URI is refused (the key goes in a key file; the driver refuses it too)";; esac;;
        esac
        [ -z "$query" ] || die "--opt / --raw-query cannot be combined with --uri (put the query in the URI)"
    else
        [ -n "$pool" ] && [ -n "$image" ] || die "give --uri, or --pool and --image (and --user, --mon)"
        [[ "$pool" =~ $re_name ]] || die "--pool: plain name please"
        [[ "$image" =~ $re_name ]] || die "--image: plain name please"
        re_mon='^[]0-9A-Za-z.:,[-]+$'
        [[ "$mon" =~ $re_mon ]] || die "--mon: ip[:port][,ip[:port]...]"
        if [ -n "$user" ]; then [[ "$user" =~ $re_name ]] || die "--user: plain name please"; fi
        if [ -n "$snap" ]; then [[ "$snap" =~ $re_name ]] || die "--snap: plain name please"; fi
        uri="rbd://"
        if [ -n "$user" ] && [ "$usersetting" = 0 ]; then uri="$uri$user@"; fi
        uri="$uri$mon/$pool/$image"
        [ -z "$snap" ] || uri="$uri@$snap"
        [ -z "$query" ] || uri="$uri?$query"
    fi
fi

# ---------------------------------------------------------------------------------------------------------------------
# the key
# ---------------------------------------------------------------------------------------------------------------------
keytxt=""
file_mode() {
    local m
    m=$(stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1" 2>/dev/null || true)
    [ -n "$m" ] || die "cannot read the mode of $1"
    printf '%s' "$m"
}
if [ "$fake" = 1 ]; then
    [ -z "$keyfile" ] && [ "$nokey" = 0 ] || die "--fake-key excludes --key-file and --no-key"
    # type 1 (legacy aes), created (8 bytes), length 16, 16 random bytes: 28 bytes, the shape of `ceph auth get-key`
    keytxt=$( { printf '\001\000'; head -c 8 /dev/urandom; printf '\020\000'; head -c 16 /dev/urandom; } | base64 | tr -d '\n')
elif [ -n "$keyfile" ]; then
    [ "$nokey" = 0 ] || die "--key-file excludes --no-key"
    [ -f "$keyfile" ] && [ -r "$keyfile" ] || die "--key-file: cannot read $keyfile"
    m=$(file_mode "$keyfile")
    if [ $((8#$m & 8#077)) -ne 0 ]; then die "--key-file: $keyfile is mode $m; it must be 600 (no group or other access)"; fi
    keytxt=$(awk '
        /^[[:space:]]*key[[:space:]]*=[[:space:]]*[A-Za-z0-9+\/]+=*[[:space:]]*$/ { v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*$/, "", v); print v; found = 1; exit }
        /^[A-Za-z0-9+\/]+=*[[:space:]]*$/ { if (!bare) { b = $0; sub(/[[:space:]]*$/, "", b); bare = b } else multi = 1 }
        END { if (!found && bare != "" && !multi) print bare }' "$keyfile")
    [ -n "$keytxt" ] || die "--key-file: $keyfile holds no cephx key (expected the bare base64 key, or a keyring with a 'key = ...' line)"
    [ "${#keytxt}" -ge 20 ] && [ "${#keytxt}" -le 120 ] || die "--key-file: the key in $keyfile has an implausible length"
elif [ "$nokey" = 0 ] && [ "$action" != none ]; then
    die "give --key-file F, --fake-key or --no-key"
fi

# ---------------------------------------------------------------------------------------------------------------------
# the script
# ---------------------------------------------------------------------------------------------------------------------
emit() {
    local shown_key=$1 i san_args=""
    cat <<EOF
#!ipxe
# winrbd Phase 2 run script for row $row, generated by gen-script.sh.
# It holds the cephx key unless it was made with --redact: keep it private (mode 600, directory 700), never commit it.
echo WRRUN-BEGIN row=$row
set labmac $mac
EOF
    for i in 0 1 2 3 4 5 6 7; do
        cat <<EOF
iseq \${net$i/mac} \${labmac} || goto not$i
set wr-if net$i
goto have-if
:not$i
EOF
    done
    cat <<EOF
echo WRRUN-NO-LAB-NIC
goto fail
:have-if
set \${wr-if}/ip $ip
set \${wr-if}/netmask $mask
ifopen \${wr-if} || goto fail-net
iflinkwait -t $linkto \${wr-if} || goto fail-net
echo WRRUN-NET-OK
EOF
    if [ -n "$shown_key" ]; then
        echo "set rbd-key $shown_key"
    fi
    if [ "$usersetting" = 1 ] && [ -n "$user" ]; then
        echo "set rbd-user $user"
    fi
    if [ "$action" != none ]; then
        [ -z "$drive" ] || san_args="$san_args --drive $drive"
        [ "$nodescribe" = 0 ] || san_args="$san_args --no-describe"
        echo "echo WRRUN-SAN-START $action"
        echo "$action$san_args $uri || goto san-fail"
        if [ "$action" = sanboot ]; then
            # sanboot only returns when the boot code came back (a boot sector that returns, a failed EFI start): nothing booted
            echo "echo WRRUN-BOOT-RETURNED"
            echo "goto fail"
        else
            echo "echo WRRUN-SAN-OK"
        fi
    fi
    if [ -n "$append" ]; then
        echo "# ---- appended from a file ----"
        cat "$append"
        echo "# ---- end of the appended part ----"
    fi
    echo "echo WRRUN-LEAVE $leave"
    echo "echo WRRUN-END"
    case "$leave" in
        exit) echo "exit";;
        poweroff) echo "poweroff";;
        none) echo "goto finished";;
    esac
    cat <<'EOF'
:san-fail
echo WRRUN-SAN-FAILED 0x${errno:hexraw}
goto fail
:fail-net
echo WRRUN-NET-FAILED 0x${errno:hexraw}
:fail
echo WRRUN-FAIL
echo WRRUN-END
EOF
    case "$onfail" in
        poweroff) echo "poweroff";;
        exit) echo "exit";;
        hold) printf ':hold\nsleep 5\ngoto hold\n';;
    esac
    echo ":finished"
}

if [ "$redact" = 1 ]; then
    shown=""
    [ -z "$keytxt" ] || shown='<redacted>'
    emit "$shown"
    exit 0
fi
[ -n "$out" ] || die "give -o FILE (or --redact to look at it)"
[ "$out" != - ] || die "refusing to print a script with a key on stdout (use --redact)"
tmp="$out.tmp.$$"
trap 'rm -f "$tmp"' EXIT
emit "$keytxt" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$out"
trap - EXIT
