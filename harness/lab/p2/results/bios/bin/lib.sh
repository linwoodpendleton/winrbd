# SPDX-License-Identifier: MIT
# lib.sh - what run-undi.sh and run-media.sh add to the stock library common.sh (source it AFTER common.sh and after their own overrides):
#   * a time-stamped copy of the serial log, made while the guest runs (tailts.py), kept as <run>.ts next to the other logs;
#     it is scanned for the key like the console log, and removed with the rest of the run directory
#   * with P2B_DEBUGCON=1: QEMU's debug console (I/O port 0xe9) into a file, time-stamped the same way (<run>.dbg.ts). iPXE's DBG output goes to
#     the VGA console only unless it is built with -DCONSOLE_DEBUGCON; the "trace" builds are, and that is where the INT 13h commands are read
#   * an optional pause of the guest at a chosen console line (P2B_PAUSE_ON / P2B_PAUSE_SECS / P2B_PAUSE_HOOK; P2B_PAUSE_SRC=dbg looks for the
#     line in the DBG output of a trace build instead of the serial console), see tailts.py
# shellcheck shell=bash
# shellcheck disable=SC2034

b_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

b_orig=$(declare -f q_start);    eval "${b_orig/q_start/b_orig_q_start}"
b_orig=$(declare -f q_stop);     eval "${b_orig/q_stop/b_orig_q_stop}"
b_orig=$(declare -f q_key_scan); eval "${b_orig/q_key_scan/b_orig_q_key_scan}"
b_orig=$(declare -f q_cleanup);  eval "${b_orig/q_cleanup/b_orig_q_cleanup}"

B_TS_PID=""
B_DBG_PID=""
# b_debugcon_args : add the QEMU debug console to QARGS (the run scripts call it at the end of q_build_qargs)
b_debugcon_args() {
    if [ "${P2B_DEBUGCON:-0}" = 1 ]; then QARGS+=(-debugcon "file:$RUNDIR/debugcon.log"); fi
}
q_start() {
    b_orig_q_start || return $?
    local args=("$Q_CONSOLE" "$RUNDIR/console.ts" "$QPID") dargs=("$RUNDIR/debugcon.log" "$RUNDIR/debugcon.ts" "$QPID") pa=()
    if [ -n "${P2B_PAUSE_ON:-}" ]; then
        pa=(--qmp "$Q_QMP" --pause-on "$P2B_PAUSE_ON" --pause-secs "${P2B_PAUSE_SECS:-60}")
        [ -z "${P2B_PAUSE_HOOK:-}" ] || pa+=(--pause-hook "$P2B_PAUSE_HOOK")
        # the line that triggers the pause is looked for on the serial console, or (P2B_PAUSE_SRC=dbg) in iPXE's DBG output on the debug console
        if [ "${P2B_PAUSE_SRC:-console}" = dbg ]; then dargs+=("${pa[@]}"); else args+=("${pa[@]}"); fi
    fi
    python3 -I "$b_here/tailts.py" "${args[@]}" 9>&- &
    B_TS_PID=$!
    if [ "${P2B_DEBUGCON:-0}" = 1 ]; then
        python3 -I "$b_here/tailts.py" "${dargs[@]}" 9>&- &
        B_DBG_PID=$!
    fi
    return 0
}

q_stop() {
    b_orig_q_stop
    if [ -n "$B_TS_PID" ]; then
        # the watcher ends by itself when QEMU has gone; give it a moment for its last read
        local i
        for i in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$B_TS_PID" 2>/dev/null || break; sleep 0.2; done
        if kill -0 "$B_TS_PID" 2>/dev/null; then kill "$B_TS_PID" 2>/dev/null; fi
        wait "$B_TS_PID" 2>/dev/null
        B_TS_PID=""
    fi
    if [ -n "$B_DBG_PID" ]; then
        local j
        for j in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$B_DBG_PID" 2>/dev/null || break; sleep 0.2; done
        if kill -0 "$B_DBG_PID" 2>/dev/null; then kill "$B_DBG_PID" 2>/dev/null; fi
        wait "$B_DBG_PID" 2>/dev/null
        B_DBG_PID=""
    fi
}

q_key_scan() {
    b_orig_q_key_scan
    local f
    for f in "$RUNDIR/console.ts" "$RUNDIR/console.ts.chunks" "$RUNDIR/debugcon.ts" "$RUNDIR/debugcon.log"; do
        if [ -s "${KEYSCAN:-}" ] && [ -f "$f" ] && grep -a -q -F -f "$KEYSCAN" "$f" 2>/dev/null; then KEY_LEAK=1; fi
    done
}

# q_finish stops the guest, scans for the key, copies the console, prints RESULT and then calls q_cleanup: the time-stamped log is copied
# there (the key scan has run by then), and only if the key was not found
q_cleanup() {
    if [ -n "${LOGBASE:-}" ] && [ -f "${RUNDIR:-/nonexistent}/console.ts" ] && [ "${KEY_LEAK:-0}" != 1 ]; then
        cp -f "$RUNDIR/console.ts" "$LOGBASE.ts" 2>/dev/null || true
        cp -f "$RUNDIR/console.ts.chunks" "$LOGBASE.chunks" 2>/dev/null || true
        cp -f "$RUNDIR/debugcon.ts" "$LOGBASE.dbg.ts" 2>/dev/null || true
    fi
    rm -f "${RUNDIR:-/nonexistent}/console.ts" "${RUNDIR:-/nonexistent}/console.ts.chunks" "${RUNDIR:-/nonexistent}/debugcon.ts" "${RUNDIR:-/nonexistent}/debugcon.ts.chunks" "${RUNDIR:-/nonexistent}/debugcon.log"
    b_orig_q_cleanup
}
