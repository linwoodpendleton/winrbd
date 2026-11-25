#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Phase 2 QEMU scripts, milestone 7 (design section 14.3, "robustness rows"): one run of row U1 (OVMF, ipxe.efi over PXE) or row B1 (SeaBIOS, ipxe.pxe over
# PXE) with ONE fault injected while the guest runs, and the lab put back afterwards.
#
#   robust.sh --family uefi|bios --fault KIND [fault options] [run-script options]
#
# It is run-uefi-pxe.sh / run-bios-pxe.sh (the same library, the same options, the same limits and clean-up: common.sh) with a different waiting loop. The loop
# does what the stock one does and in addition
#   * stamps every console line with the time it was first seen (poll interval 0.25 s): LOGBASE.ts, "<epoch seconds> <line>"
#   * waits for a trigger (a console line), then starts the fault in the background, so that the loop goes on judging the run
#   * writes what it did, with times, to LOGBASE.fault
#   * puts everything back before it returns, however the run ended (the guest exited, the timeout, a signal): the library's q_stop is wrapped
#
# Faults (KIND), all of them undone at the end of --down seconds or when the run ends, whichever comes first:
#   none        nothing (the control: the same run without a fault)
#   mon-kill    SIGKILL the monitor, keep it down, start it again          (design 14.3 a)
#   mon-osd     SIGKILL the monitor, then one OSD a second later; start the monitor after --down seconds and the OSD 10 s after that: while the monitor is
#               gone nobody can mark the OSD down or publish a map, so the client can neither learn that its primary is dead nor be told where to go
#   osd-kill    SIGKILL one OSD (--osd N, default 1), keep it down, start it again   (b)
#   pause       QMP stop of the guest, QMP cont                              (c: the idle-gap case: nothing in the guest runs, the cluster goes on)
#   link-down   QMP set_link of the guest's lab NIC down, then up           (d)
#   stall       SIGSTOP of every OSD, then SIGCONT: commands wait, the cluster does not answer, nothing is lost   (f: with --down 15 to 29 the SAN layer's
#               15 s command timeout fires and the 30 s watchdog of the driver does not; longer, both do)
#   outage      the same as stall, meant to last for minutes: the cluster is gone for good as far as the guest can tell (the "SAN retries, then gives up" case)
#
# Fault options:
#   --fault KIND         one of the above (required)
#   --on REGEX           the console line that starts the fault (an extended regular expression, matched against the console as the run script sees it: no CR,
#                        no escape sequences); default ^WRRUN-SAN-(OK|START)
#   --on-nth N           the Nth line that matches (default 1)
#   --delay S            seconds after that line (default 0; decimals allowed)
#   --down S             how long the fault lasts (default: mon-kill 20, mon-osd 20, osd-kill 45, pause 60, link-down 40, stall 20, outage 600)
#   --osd N              which OSD for osd-kill (default 1)
#   --press "KEYS"       press these QEMU keys (names as for q_keys: ret down ...) in the guest, once, at the trigger line + --press-delay seconds (default 0): row
#                        U1/B1 boot rows press Enter at GRUB's menu so that the kernel load starts at a known moment instead of at the menu's timeout
#   --press-delay S      seconds after the trigger line at which --press happens (default 0)
#   --idle-timeout S     before the guest starts, set the lab daemons' ms_connection_idle_timeout (monitor and OSDs) to S seconds, and remove the setting at the end
#                        (labstate.sh sees the configuration database: the row's lab diff must be empty). The Ceph default is 900 s, so a 60 s gap leaves every
#                        connection standing; with 20 s the daemons close the connections a paused guest leaves idle, and the first command after the gap
#                        must reconnect and authenticate again, which is the case design section 11 describes ("Idle gaps")
#   --capture            also record the guest's TCP connection attempts (every SYN) and everything it exchanges with the monitor's ports (3300, 6789) as the lab
#                        VM sees them, one line per packet with its length: LOGBASE.syn (tcpdump in the lab VM; the headers only, no payload is kept)
#   --lab-ssh "WORDS"    the ssh command that reaches the lab VM (default: $P2_LAB_SSH, else the key and port of the lab directory $P2_LAB_DIR / $LAB_DIR);
#                        the lab user needs sudo without a password in the VM
#   --link-name NAME     the QEMU netdev id of the lab NIC for set_link (default lab: the id common.sh gives it)
# Everything else is the option list of run-uefi-pxe.sh / run-bios-pxe.sh (see --help of those); --family decides which.
#
# Outputs next to the stock ones ($P2Q_WORK/logs/<run id>.*): .console (the serial log), .result, .ts, .fault, .syn (with --capture).
# Exit status as the stock scripts (0 the expected stage was reached, 1 not, 2 usage, 4 something left behind / the key in a log), with one addition: a fault that could
# not be injected or not be undone makes it 3 (and says so on stderr: the lab must be looked at).
#
# Safety: the fault commands name only the lab VM's own ceph daemons, the processes called ceph-osd there and (with --capture) the process called tcpdump there, which
# the run starts itself under a time limit; nothing here touches the host's network or any process of this machine except the guest of the run (by its own name and
# pid file, as the library does). --idle-timeout refuses a lab that already has that setting (its undo is "config rm").
# shellcheck disable=SC2015  # "A && B || die" is a guard here, not an if-then-else
set -u -o pipefail
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$here/common.sh"

R_FAMILY="" R_FAULT="" R_ON='^WRRUN-SAN-(OK|START)' R_NTH=1 R_DELAY=0 R_DOWN="" R_OSD=1 R_CAPTURE=0 R_LABSSH="" R_LINK=lab R_PRESS="" R_PRESS_DELAY=0 R_IDLE=""
R_ARGS=()

r_die() { echo "robust.sh: $*" >&2; exit 2; }
r_num() { [[ "$2" =~ ^[0-9]+(\.[0-9]+)?$ ]] || r_die "$1 must be a number of seconds (got '$2')"; }

r_parse() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --family) [ $# -ge 2 ] || r_die "--family needs a value"; R_FAMILY=$2; shift 2;;
            --fault) [ $# -ge 2 ] || r_die "--fault needs a value"; R_FAULT=$2; shift 2;;
            --on) [ $# -ge 2 ] || r_die "--on needs a value"; R_ON=$2; shift 2;;
            --on-nth) [ $# -ge 2 ] || r_die "--on-nth needs a value"; R_NTH=$2; shift 2;;
            --delay) [ $# -ge 2 ] || r_die "--delay needs a value"; R_DELAY=$2; shift 2;;
            --down) [ $# -ge 2 ] || r_die "--down needs a value"; R_DOWN=$2; shift 2;;
            --osd) [ $# -ge 2 ] || r_die "--osd needs a value"; R_OSD=$2; shift 2;;
            --press) [ $# -ge 2 ] || r_die "--press needs a value"; R_PRESS=$2; shift 2;;
            --press-delay) [ $# -ge 2 ] || r_die "--press-delay needs a value"; R_PRESS_DELAY=$2; shift 2;;
            --idle-timeout) [ $# -ge 2 ] || r_die "--idle-timeout needs a value"; R_IDLE=$2; shift 2;;
            --capture) R_CAPTURE=1; shift;;
            --lab-ssh) [ $# -ge 2 ] || r_die "--lab-ssh needs a value"; R_LABSSH=$2; shift 2;;
            --link-name) [ $# -ge 2 ] || r_die "--link-name needs a value"; R_LINK=$2; shift 2;;
            -h|--help) awk 'NR >= 3 && /^#/ { sub(/^# ?/, ""); print; next } NR >= 3 { exit }' "${BASH_SOURCE[0]}"; exit 0;;
            *) R_ARGS+=("$1"); shift;;
        esac
    done
    case "$R_FAMILY" in uefi|bios) ;; *) r_die "--family must be uefi or bios";; esac
    case "$R_FAULT" in none|mon-kill|mon-osd|osd-kill|pause|link-down|stall|outage) ;; *) r_die "--fault must be none, mon-kill, mon-osd, osd-kill, pause, link-down, stall or outage";; esac
    # a trigger that is not a regular expression would never match: the guest would run to the timeout with no fault (grep says 2 for a bad one, 1 for no match)
    printf '' | grep -E -- "$R_ON" >/dev/null 2>&1; [ $? -le 1 ] || r_die "--on is not an extended regular expression: $R_ON"
    [[ "$R_NTH" =~ ^[0-9]{1,4}$ ]] && [ "$R_NTH" -ge 1 ] || r_die "--on-nth must be a number from 1"
    [[ "$R_OSD" =~ ^[0-9]{1,3}$ ]] || r_die "--osd must be an OSD number"
    [[ "$R_LINK" =~ ^[A-Za-z0-9_-]{1,32}$ ]] || r_die "--link-name must be a QEMU id (letters, digits, - _)"
    r_num --delay "$R_DELAY"
    r_num --press-delay "$R_PRESS_DELAY"
    [ -z "$R_IDLE" ] || { [[ "$R_IDLE" =~ ^[0-9]{1,4}$ ]] && [ "$R_IDLE" -ge 5 ] || r_die "--idle-timeout must be 5 to 9999 seconds"; }
    [[ "$R_PRESS" =~ ^[a-z0-9_\ -]*$ ]] || r_die "--press: QEMU key names (ret down ...) separated by spaces"
    if [ -z "$R_DOWN" ]; then
        case "$R_FAULT" in mon-kill) R_DOWN=20;; mon-osd) R_DOWN=20;; osd-kill) R_DOWN=45;; pause) R_DOWN=60;; link-down) R_DOWN=40;; stall) R_DOWN=20;; outage) R_DOWN=600;; none) R_DOWN=0;; esac
    fi
    r_num --down "$R_DOWN"
    # nothing of the lab ssh words reaches a shell as anything but words: a command line of your own is yours, but keep out the obvious accidents
    # shellcheck disable=SC2016  # the '$(' is a pattern, not an expansion
    case "$R_LABSSH" in *';'*|*'|'*|*'&'*|*'`'*|*'$('*) r_die "--lab-ssh: the words of one ssh command, no shell operators";; esac
}

# ---------------------------------------------------------------------------------------------------------------------
# the lab
# ---------------------------------------------------------------------------------------------------------------------

# labx 'COMMAND LINE': run it in the lab VM (the remote shell reads it)
labx() {
    if [ -n "$R_LABSSH" ]; then
        # shellcheck disable=SC2086  # the words of a command
        $R_LABSSH "$1" </dev/null
    elif [ -n "${P2_LAB_SSH:-}" ]; then
        # shellcheck disable=SC2086
        $P2_LAB_SSH "$1" </dev/null
    else
        local d=${P2_LAB_DIR:-${LAB_DIR:-}}
        [ -n "$d" ] && [ -r "$d/ssh/id_ed25519" ] || { echo "robust.sh: no lab: set P2_LAB_SSH, --lab-ssh or P2_LAB_DIR" >&2; return 255; }
        ssh -n -p "${LAB_SSH_PORT:-22232}" -i "$d/ssh/id_ed25519" -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=15 \
            -o "UserKnownHostsFile=$d/ssh/known_hosts" "${LAB_SSH_USER:-lab}@127.0.0.1" "$1"
    fi
}

R_MONUNIT="" R_OSDUNIT=""

# Find the units of the monitor and the OSD (before the guest starts: a fault that cannot be injected must stop the run before it begins).
r_discover() {
    local fsid out
    case "$R_FAULT" in
        mon-kill|osd-kill|mon-osd)
            fsid=$(labx "sudo ceph fsid" 2>/dev/null | tr -d '\r\n ') || fsid=""
            [[ "$fsid" =~ ^[0-9a-f-]{36}$ ]] || { echo "robust.sh: cannot read the cluster's fsid from the lab VM" >&2; return 1; }
            if [ "$R_FAULT" = mon-kill ] || [ "$R_FAULT" = mon-osd ]; then
                out=$(labx "systemctl list-units --no-legend --plain 'ceph-$fsid@mon.*.service' | awk '{print \$1}'" 2>/dev/null | tr -d '\r') || out=""
                [ "$(printf '%s\n' "$out" | grep -c .)" = 1 ] || { echo "robust.sh: expected exactly one monitor unit, found: ${out:-none}" >&2; return 1; }
                R_MONUNIT=$out
            fi
            if [ "$R_FAULT" = osd-kill ] || [ "$R_FAULT" = mon-osd ]; then
                out=$(labx "systemctl list-units --no-legend --plain 'ceph-$fsid@osd.$R_OSD.service' | awk '{print \$1}'" 2>/dev/null | tr -d '\r') || out=""
                [ "$(printf '%s\n' "$out" | grep -c .)" = 1 ] || { echo "robust.sh: no unit for osd.$R_OSD, found: ${out:-none}" >&2; return 1; }
                R_OSDUNIT=$out
            fi;;
        stall|outage)
            out=$(labx "pgrep -c -x ceph-osd" 2>/dev/null | tr -d '\r\n ') || out=0
            [ "${out:-0}" -ge 1 ] || { echo "robust.sh: no ceph-osd process in the lab VM" >&2; return 1; }
            ;;
    esac
    if [ "$R_CAPTURE" = 1 ]; then
        # (a capture that cannot start would leave an empty LOGBASE.syn that looks like "the guest made no connection")
        labx "sudo -n true && command -v tcpdump >/dev/null && command -v timeout >/dev/null" >/dev/null 2>&1 || { echo "robust.sh: --capture needs sudo without a password, tcpdump and timeout in the lab VM" >&2; return 1; }
    fi
    return 0
}

# ---------------------------------------------------------------------------------------------------------------------
# the record
# ---------------------------------------------------------------------------------------------------------------------

R_FEV=""
r_now() { date +%s.%N | cut -c1-14; }
# fev TEXT: one line in LOGBASE.fault (epoch seconds, seconds since the guest started, text)
fev() {
    [ -n "$R_FEV" ] || return 0
    printf '%s T+%s %s\n' "$(r_now)" "$((SECONDS - T0))" "$*" >> "$R_FEV"
}

R_TS_OFF=0 R_TS_BUF="" R_TS=""
# r_ts [flush]: append what the console has printed since the last call to LOGBASE.ts, every complete line stamped with now. A last line without its newline waits for
# the next call; with "flush" (the end of the run) it is written too. One pass over the new text (read, not a cut of the whole buffer per line: a burst of kernel
# messages must not stall the loop that decides when the fault starts and when the run times out).
r_ts() {
    [ -n "$R_TS" ] && [ -f "$Q_CONSOLE" ] || return 0
    local sz now chunk line
    sz=$(q_file_size "$Q_CONSOLE")
    if [ "$sz" -gt "$R_TS_OFF" ]; then
        now=$(r_now)
        chunk=$(tail -c +$((R_TS_OFF + 1)) "$Q_CONSOLE" | head -c $((sz - R_TS_OFF)) | tr -d '\r\000'; printf x)
        chunk=${chunk%x}
        R_TS_OFF=$sz
        R_TS_BUF+=$chunk
        if [[ "$R_TS_BUF" == *$'\n'* ]]; then
            {
                while IFS= read -r line; do printf '%s %s\n' "$now" "$line"; done <<< "${R_TS_BUF%$'\n'*}"
            } >> "$R_TS"
            R_TS_BUF=${R_TS_BUF##*$'\n'}
        fi
    fi
    if [ "${1:-}" = flush ] && [ -n "$R_TS_BUF" ]; then
        printf '%s %s\n' "$(r_now)" "$R_TS_BUF" >> "$R_TS"
        R_TS_BUF=""
    fi
    return 0
}

# ---------------------------------------------------------------------------------------------------------------------
# the faults. Each runs in the background (a subshell) and always ends with its undo; r_undo does the undo again, idempotently, at the end of the run.
# ---------------------------------------------------------------------------------------------------------------------

R_IDLE_SET=0
# the idle timeout back to what it was (the rows start from a lab that has no such setting)
r_idle_undo() {
    [ "$R_IDLE_SET" = 1 ] || return 0
    # the flag stays up until the removal worked: a later call (the end of the run after a failed start) tries again
    labx "sudo ceph config rm osd ms_connection_idle_timeout; sudo ceph config rm mon ms_connection_idle_timeout" >/dev/null 2>&1 || return 1
    R_IDLE_SET=0
    return 0
}

R_FPID="" R_KPID="" R_FDONE=0 R_UNDONE=0 R_FAIL=0 R_CAPPID="" R_STARTED=0

r_wait_quorum() {
    local i
    for i in $(seq 1 60); do
        if labx "sudo ceph quorum_status --format json" 2>/dev/null | grep -q '"quorum_names":\["'; then fev "monitor is back in quorum (poll $i)"; return 0; fi
        sleep 1
    done
    fev "monitor did NOT come back in quorum within 60 s"; return 1
}

r_wait_osds() {
    local i n
    for i in $(seq 1 90); do
        n=$(labx "sudo ceph osd stat --format json" 2>/dev/null | python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d["num_up_osds"], d["num_in_osds"], d["num_osds"])' 2>/dev/null) || n=""
        if [ -n "$n" ] && [ "${n%% *}" = "${n##* }" ] && [ "$(echo "$n" | awk '{print ($1==$2 && $2==$3)}')" = 1 ]; then fev "all OSDs up and in again: $n (poll $i)"; return 0; fi
        sleep 1
    done
    fev "OSDs did NOT all come back within 90 s: ${n:-no answer}"; return 1
}

# What the cluster reports as health checks (names only), once, as one sorted line
r_health_names() {
    labx "sudo ceph health detail --format json" 2>/dev/null | python3 -I -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin).get("checks", {}))))' 2>/dev/null
}

# After a fault the cluster may report health checks that were not there before the run (cephadm's CEPHADM_FAILED_DAEMON after a killed daemon stays until its next
# refresh; SLOW_OPS / OSD_SLOW_PING_TIME after a stop of every OSD fade out by themselves): ask cephadm for its refresh and wait until the set of checks is again
# the one the run started with, so that the lab's state after the row is the state before it.
R_HEALTH0=""
r_wait_health() {
    local i now extra="" n
    labx "sudo ceph orch ps --refresh" >/dev/null 2>&1 || true
    for i in $(seq 1 60); do
        # (r_health_names fails when the lab does not answer: that is not "no health checks", and a cluster that has fewer checks than at the start is fine)
        if now=$(r_health_names); then
            extra=""
            for n in $now; do case " $R_HEALTH0 " in *" $n "*) ;; *) extra="$extra $n";; esac; done
            if [ -z "$extra" ]; then fev "the health checks are the ones the run started with again (poll $i)"; return 0; fi
        else
            extra=" (no answer)"
        fi
        sleep 2
    done
    fev "health checks that were not there before the run are still raised after 120 s:$extra"
    return 1
}

# the faults themselves (the undo of each is idempotent: starting a started unit, CONT of a running process, cont of a running guest, link up on an up link)
f_undo() {
    case "$R_FAULT" in
        mon-kill) labx "sudo systemctl reset-failed '$R_MONUNIT' 2>/dev/null; sudo systemctl start '$R_MONUNIT'" >/dev/null 2>&1 || return 1;;
        osd-kill) labx "sudo systemctl reset-failed '$R_OSDUNIT' 2>/dev/null; sudo systemctl start '$R_OSDUNIT'" >/dev/null 2>&1 || return 1;;
        mon-osd) labx "sudo systemctl reset-failed '$R_MONUNIT' '$R_OSDUNIT' 2>/dev/null; sudo systemctl start '$R_MONUNIT'; sudo systemctl start '$R_OSDUNIT'" >/dev/null 2>&1 || return 1;;
        stall|outage) labx "sudo pkill -CONT -x ceph-osd; true" >/dev/null 2>&1 || return 1;;
        pause) if [ -n "${QPID:-}" ] && q_alive && q_is_ours; then q_qmp cont >/dev/null 2>&1 || return 1; fi;;
        link-down) if [ -n "${QPID:-}" ] && q_alive && q_is_ours; then q_qmp set_link "{\"name\":\"$R_LINK\",\"up\":true}" >/dev/null 2>&1 || return 1; fi;;
    esac
    return 0
}

f_run() {
    local rc=0
    fev "fault $R_FAULT: begins (down $R_DOWN s)"
    case "$R_FAULT" in
        mon-kill)
            # kill, then stop: the stop keeps systemd from restarting it by itself after 10 s, so the time down is the time asked for
            # (the SIGKILL is sent at the start of the command; the stop takes a few seconds more, and the line below is written after it)
            fev "monitor: SIGKILL sent now"
            labx "sudo systemctl kill -s KILL '$R_MONUNIT'; sudo systemctl stop '$R_MONUNIT'" >/dev/null 2>&1 || rc=1
            fev "monitor killed (rc $rc)"
            sleep "$R_DOWN"
            labx "sudo systemctl reset-failed '$R_MONUNIT' 2>/dev/null; sudo systemctl start '$R_MONUNIT'" >/dev/null 2>&1 || rc=1
            fev "monitor started (rc $rc)"
            r_wait_quorum || rc=1;;
        mon-osd)
            fev "monitor: SIGKILL sent now"
            labx "sudo systemctl kill -s KILL '$R_MONUNIT'; sudo systemctl stop '$R_MONUNIT'" >/dev/null 2>&1 || rc=1
            fev "monitor killed (rc $rc)"
            sleep 1
            fev "osd.$R_OSD: SIGKILL sent now"
            labx "sudo systemctl kill -s KILL '$R_OSDUNIT'; sudo systemctl stop '$R_OSDUNIT'" >/dev/null 2>&1 || rc=1
            fev "osd.$R_OSD killed (rc $rc), with the monitor down"
            sleep "$R_DOWN"
            labx "sudo systemctl reset-failed '$R_MONUNIT' 2>/dev/null; sudo systemctl start '$R_MONUNIT'" >/dev/null 2>&1 || rc=1
            fev "monitor started (rc $rc)"
            r_wait_quorum || rc=1
            sleep 10
            labx "sudo systemctl reset-failed '$R_OSDUNIT' 2>/dev/null; sudo systemctl start '$R_OSDUNIT'" >/dev/null 2>&1 || rc=1
            fev "osd.$R_OSD started (rc $rc)"
            r_wait_osds || rc=1;;
        osd-kill)
            fev "osd.$R_OSD: SIGKILL sent now"
            labx "sudo systemctl kill -s KILL '$R_OSDUNIT'; sudo systemctl stop '$R_OSDUNIT'" >/dev/null 2>&1 || rc=1
            fev "osd.$R_OSD killed (rc $rc)"
            sleep "$R_DOWN"
            labx "sudo systemctl reset-failed '$R_OSDUNIT' 2>/dev/null; sudo systemctl start '$R_OSDUNIT'" >/dev/null 2>&1 || rc=1
            fev "osd.$R_OSD started (rc $rc)"
            r_wait_osds || rc=1;;
        pause)
            q_qmp stop >/dev/null 2>&1 || rc=1
            fev "guest stopped (rc $rc)"
            sleep "$R_DOWN"
            q_qmp cont >/dev/null 2>&1 || rc=1
            fev "guest continued (rc $rc)";;
        link-down)
            q_qmp set_link "{\"name\":\"$R_LINK\",\"up\":false}" >/dev/null 2>&1 || rc=1
            fev "lab NIC link set down (rc $rc)"
            sleep "$R_DOWN"
            q_qmp set_link "{\"name\":\"$R_LINK\",\"up\":true}" >/dev/null 2>&1 || rc=1
            fev "lab NIC link set up (rc $rc)";;
        stall|outage)
            fev "all ceph-osd processes: SIGSTOP sent now"
            labx "sudo pkill -STOP -x ceph-osd; true" >/dev/null 2>&1 || rc=1
            fev "all ceph-osd processes stopped (SIGSTOP) (rc $rc)"
            sleep "$R_DOWN"
            labx "sudo pkill -CONT -x ceph-osd; true" >/dev/null 2>&1 || rc=1
            fev "all ceph-osd processes continued (SIGCONT) (rc $rc)"
            r_wait_osds || rc=1;;
    esac
    fev "fault $R_FAULT: ends (rc $rc)"
    return $rc
}

r_start_fault() {
    fev "trigger seen ($R_ON, #$R_NTH)"
    if [ -n "$R_PRESS" ]; then
        fev "keys '$R_PRESS' will be pressed after $R_PRESS_DELAY s"
        (
            trap - EXIT INT TERM HUP
            sleep "$R_PRESS_DELAY"
            if q_keys "$R_PRESS"; then fev "keys '$R_PRESS' pressed"; else fev "KEYS NOT PRESSED"; fi
        ) 9>&- &
        R_KPID=$!
    fi
    [ "$R_FAULT" != none ] || { fev "fault none: nothing to do"; R_FDONE=1; return 0; }
    fev "fault $R_FAULT after $R_DELAY s"
    (
        trap - EXIT INT TERM HUP
        sleep "$R_DELAY"
        f_run
        echo "$?" > "$LOGBASE.fault.rc"
    ) 9>&- &
    R_FPID=$!
    R_FDONE=1
}

# at the end of the run, whatever the state: stop a fault that is still waiting, undo it, stop the capture, scan the records for the key
r_end() {
    [ "$R_UNDONE" = 0 ] || return 0
    R_UNDONE=1
    local rc=0 left=""
    r_ts flush
    if [ -n "$R_FPID" ] && kill -0 "$R_FPID" 2>/dev/null; then
        # the fault was still in its sleep (the guest ended first): stop its timer and undo it now
        pkill -TERM -P "$R_FPID" 2>/dev/null || true
        kill -TERM "$R_FPID" 2>/dev/null || true
        left=1
        fev "the run ended before the fault did: undoing it now"
    fi
    [ -z "$R_FPID" ] || wait "$R_FPID" 2>/dev/null || true
    if [ -n "$R_KPID" ]; then kill -TERM "$R_KPID" 2>/dev/null || true; wait "$R_KPID" 2>/dev/null || true; fi
    if [ "$R_FAULT" != none ] && [ "$R_FDONE" = 1 ]; then
        f_undo || { rc=1; fev "UNDO FAILED"; }
        case "$R_FAULT" in
            mon-kill) [ -z "$left" ] || r_wait_quorum || rc=1;;
            mon-osd) [ -z "$left" ] || { r_wait_quorum && r_wait_osds; } || rc=1;;
            osd-kill|stall|outage) [ -z "$left" ] || r_wait_osds || rc=1;;
        esac
    fi
    case "$R_FAULT" in mon-kill|osd-kill|mon-osd|stall|outage) if [ "$R_FDONE" = 1 ]; then r_wait_health || rc=1; fi;; esac
    if [ -n "$R_PRESS" ] && grep -q 'KEYS NOT PRESSED' "$R_FEV" 2>/dev/null; then rc=1; fi
    if [ "$R_FAULT" != none ] && [ "$R_FDONE" = 0 ] && [ "$R_STARTED" = 1 ]; then fev "the trigger never appeared: NO FAULT WAS INJECTED"; rc=1; fi
    if [ -f "$LOGBASE.fault.rc" ]; then
        [ "$(cat "$LOGBASE.fault.rc")" = 0 ] || { rc=1; fev "the fault routine reported a failure"; }
        rm -f "$LOGBASE.fault.rc"
    fi
    if [ "$R_IDLE_SET" = 1 ]; then
        if r_idle_undo; then fev "lab: ms_connection_idle_timeout removed again"; else fev "UNDO FAILED: ms_connection_idle_timeout is still set"; rc=1; fi
    fi
    if [ -n "$R_CAPPID" ]; then
        kill -TERM "$R_CAPPID" 2>/dev/null || true
        labx "sudo pkill -x tcpdump; true" >/dev/null 2>&1 || true
        wait "$R_CAPPID" 2>/dev/null || true
        R_CAPPID=""
    fi
    # the records hold what the guest printed: the key must not be in them either
    if [ -s "${KEYSCAN:-/nonexistent}" ] && [ -n "$R_TS" ] && [ -f "$R_TS" ] && grep -a -q -F -f "$KEYSCAN" "$R_TS"; then
        q_warn "the cephx key is in the time-stamped console: $R_TS discarded"
        rm -f "$R_TS"; rc=1
    fi
    [ "$rc" = 0 ] || { R_FAIL=1; q_warn "a fault could not be injected or undone: look at the lab (LOGBASE.fault says what happened)"; }
    return 0
}

# ---------------------------------------------------------------------------------------------------------------------
# the library's hooks
# ---------------------------------------------------------------------------------------------------------------------

# q_stop of the library, wrapped: after the guest is gone (or on the way out of a signal) the lab is put back
eval "$(declare -f q_stop | sed '1s/^q_stop /q_stop_lib /')"
q_stop() { q_stop_lib; r_end; }

# q_start of the library, wrapped: find what the fault needs before the guest exists; start the capture
eval "$(declare -f q_start | sed '1s/^q_start /q_start_lib /')"
q_start() {
    R_FEV=$LOGBASE.fault R_TS=$LOGBASE.ts
    : > "$R_FEV"; : > "$R_TS"
    if ! r_discover; then return 1; fi
    if [ "$R_FAULT" != none ]; then
        R_HEALTH0=$(r_health_names) || R_HEALTH0=""
        fev "health checks at the start: ${R_HEALTH0:-none}"
    fi
    if [ -n "$R_IDLE" ]; then
        # the undo is "config rm": a setting that was there before the row would be thrown away with it, so a lab that has one is refused
        local has
        has=$(labx "sudo ceph config dump --format json" 2>/dev/null | python3 -I -c 'import json,sys; print("yes" if any(c.get("name") == "ms_connection_idle_timeout" for c in json.load(sys.stdin)) else "no")' 2>/dev/null) || has=""
        case "$has" in
            no) ;;
            yes) echo "robust.sh: the lab already has ms_connection_idle_timeout in its configuration database: --idle-timeout would remove it afterwards" >&2; return 1;;
            *) echo "robust.sh: cannot read the lab's configuration database" >&2; return 1;;
        esac
        R_IDLE_SET=1
        if ! labx "sudo ceph config set osd ms_connection_idle_timeout $R_IDLE && sudo ceph config set mon ms_connection_idle_timeout $R_IDLE" >/dev/null 2>&1; then
            echo "robust.sh: could not set ms_connection_idle_timeout in the lab" >&2; r_idle_undo; return 1
        fi
        fev "lab: ms_connection_idle_timeout set to $R_IDLE s for the monitor and the OSDs"
    fi
    q_start_lib || { r_idle_undo || echo "robust.sh: could not remove ms_connection_idle_timeout again: look at the lab" >&2; return 1; }
    R_STARTED=1
    fev "guest started (pid $QPID); fault $R_FAULT on '$R_ON' #$R_NTH + $R_DELAY s, down $R_DOWN s"
    [ "$R_FAULT" != none ] || fev "fault none: nothing will be injected"
    if [ "$R_CAPTURE" = 1 ]; then
        # the lab VM's view of the guest's connections: every TCP SYN of the guest's lab address, and its traffic with the monitor
        labx "date +%s.%N" 2>/dev/null | sed 's/^/lab-clock /' | while read -r l; do fev "$l"; done
        ( labx "sudo timeout $((P2Q_TIMEOUT_S + 120)) tcpdump -i any -nn -l -tt -q 'host $Q_IP and (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn or port 3300 or port 6789)' 2>/dev/null" > "$LOGBASE.syn" ) 9>&- &
        R_CAPPID=$!
    fi
    return 0
}

# the waiting loop of the library, with the trigger and the stamps
q_wait() {
    local deadline=$((SECONDS + P2Q_TIMEOUT_S)) n
    END_REASON=""
    while :; do
        if ! q_alive; then END_REASON=guest-exited; break; fi
        q_scan
        r_ts
        if [ "$R_FDONE" = 0 ] && { [ "$R_FAULT" != none ] || [ -n "$R_PRESS" ]; }; then
            n=$(grep -a -c -E -- "$R_ON" "$RUNDIR/console.txt" 2>/dev/null || true)
            if [ "${n:-0}" -ge "$R_NTH" ]; then r_start_fault; fi
        fi
        if [ -n "$S_FAILMARK" ]; then END_REASON=fail-marker; break; fi
        if [ "$SAN_STATE" = failed ] && { [ "$Q_EXPECT" = san ] || [ "$Q_EXPECT" = os ]; } && [ "$Q_STAY" = 0 ] && ! q_custom_script; then
            sleep 1; END_REASON=san-failed; break
        fi
        if [ -n "${S_NETFAIL:-}" ] && [ -z "$S_SAN" ] && { [ "$Q_EXPECT" = san ] || [ "$Q_EXPECT" = os ]; } && [ "$Q_STAY" = 0 ] && ! q_custom_script; then
            # as the stock loop: the lab NIC is missing or has no link, and nothing can come of waiting out the timeout
            sleep 1; END_REASON=net-failed; break
        fi
        if [ "$(q_file_size "$Q_CONSOLE")" -gt $((P2Q_CONSOLE_MAX_MB * 1048576)) ]; then
            q_warn "the serial log passed $P2Q_CONSOLE_MAX_MB MiB: stopping the guest (P2Q_CONSOLE_MAX_MB)"
            END_REASON=console-flood; break
        fi
        if q_met && [ "$Q_STAY" = 0 ]; then END_REASON=expectation; break; fi
        if [ "$SECONDS" -ge "$deadline" ]; then END_REASON=timeout; break; fi
        sleep 0.25
    done
    q_scan
    r_ts
}

# the plan of a dry run says what would be injected
eval "$(declare -f q_print_plan | sed '1s/^q_print_plan /q_print_plan_lib /')"
q_print_plan() {
    q_print_plan_lib
    [ -z "$R_IDLE" ] || q_info "lab: ms_connection_idle_timeout $R_IDLE s for the monitor and the OSDs while the run lasts (ceph config set, removed afterwards)"
    q_info "fault: $R_FAULT on '$R_ON' (#$R_NTH) + $R_DELAY s, lasting $R_DOWN s$({ [ "$R_FAULT" = osd-kill ] || [ "$R_FAULT" = mon-osd ]; } && echo ", osd.$R_OSD")$([ "$R_CAPTURE" = 1 ] && echo ", with the SYN capture in the lab VM")"
    case "$R_FAULT" in
        mon-kill) q_info "  would run in the lab VM: systemctl kill -s KILL + stop of the monitor's unit; after $R_DOWN s: start it, wait for quorum";;
        mon-osd) q_info "  would run in the lab VM: kill the monitor, 1 s later osd.$R_OSD; after $R_DOWN s start the monitor, 10 s later the OSD";;
        osd-kill) q_info "  would run in the lab VM: systemctl kill -s KILL + stop of osd.$R_OSD's unit; after $R_DOWN s: start it, wait for all OSDs up and in";;
        stall|outage) q_info "  would run in the lab VM: pkill -STOP -x ceph-osd; after $R_DOWN s: pkill -CONT -x ceph-osd";;
        pause) q_info "  would send QMP stop to the guest, then cont after $R_DOWN s";;
        link-down) q_info "  would send QMP set_link $R_LINK up=false, then up=true after $R_DOWN s";;
    esac
}

r_parse "$@"
case "$R_FAMILY" in
    uefi) kind=uefi-pxe;;
    bios) kind=bios-pxe;;
esac
Q_PROG=robust.sh
q_main_robust() {
    local a prev=""
    for a in "${R_ARGS[@]+"${R_ARGS[@]}"}"; do
        if [ "$prev" = --work ]; then P2Q_WORK=$a; fi
        prev=$a
    done
    q_defaults
    q_kind_setup "$kind"
    q_parse "${R_ARGS[@]+"${R_ARGS[@]}"}"
    q_run
}
q_main_robust
rc=$?
if [ "$R_FAIL" = 1 ] && [ "$rc" -lt 3 ]; then rc=3; fi
exit "$rc"
