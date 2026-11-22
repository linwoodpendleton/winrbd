#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# exit-run.sh: the long randomized run of the Phase 1 exit criteria (docs/design/core-architecture.md 40.1 to 40.3) against the lab cluster: the winrbd
# core and the Linux kernel client (krbd) read and write the SAME images and are compared, byte for byte, with a model (harness/host/tools/wr-krbdcmp),
# for hours, while a fault injector (harness/tools/fault_inject.sh) kills and restarts OSDs and the monitor, marks an OSD out and in and moves a primary
# with pg-upmap. Zero differences, no hang, no lost write, and the lab back as it was, is the evidence.
#
# Five runs (a run = one connection mode x one cephx key type of the core, three fresh images at once):
#   1  crc                              core key aes256k (client.winrbd)          krbd ms_mode=prefer-crc
#   2  crc                              core key legacy aes (client.winrbd-aes)   krbd ms_mode=prefer-crc
#   3  secure                           core key aes256k                          krbd ms_mode=secure
#   4  secure                           core key legacy aes                       krbd ms_mode=secure
#   5  secure, the CLUSTER forced to secure (ms_mon_service_mode and ms_service_mode secure, the monitor and every OSD restarted under them), core key
#      aes256k (--forced-key k1 for the other): the cluster would refuse a crc connection, so a connection at all is a secure one
# krbd always authenticates as client.winrbd-aes (the kernel client of the lab VM accepts no other key, design 33.2).
#
# The three images of a run (names wrtest-ex-<pid>-r<N><c, a1, a2...>-o<order>: the calibration and every attempt have images of their own; feature layering, one wr-krbdcmp and one /dev/rbdN each; at most 8 images exist):
#   order 12   64 MiB                      (16,384 objects of 4 KiB)
#   order 18   1 GiB - 192 KiB             (4,095 objects of 256 KiB and a partial last object of 64 KiB)
#   order 22   2 GiB - 1.5 MiB             (511 objects of 4 MiB and a partial last object of 2.5 MiB)
# Each tool runs `--phase all --dir all`: the edges once, then the random phase for the run's time (the three directions in turn: core to krbd, krbd to
# core, interleaved; the tool splits the time and the operations in equal thirds), a scan of the whole image by both clients every --checkpoint (5,000)
# operations and at the end of every phase; afterwards `rbd export` of each image against `wr-rbd compare` with the run's mode as an assertion
# (--require-mode: every core connection of that comparison was of the mode, none ended on a tag, nonce or secret failure).
#
# Length: at least --hours (default 2) AND at least --min-ops (500,000) operations on every image AND long enough for the injector's deck (below). The
# time is worked out per run from a short calibration (--calibrate SEC, default 150, on throw-away images without faults: ops/s of the slowest image,
# with a margin of two fifths for what the faults and the scans cost); a run that still comes up short (fewer operations, or fewer faults, than the minimum) is
# repeated on fresh images with a longer time (--attempts, default 2): a slow day extends the run, it never shrinks the evidence.
#
# Faults (fault_inject.sh, one at a time, a fault every 90 to 300 s on a printed seed): at least 20 OSD SIGKILL + start, 10 monitor restarts (half SIGKILL),
# 10 mark out / in, 5 pg-upmap, per run. The watchdog is the tool's --stall-ms 180000: a request without a completion for that long is exit 4.
#
# The lab is left as it was found (the EXIT trap, also after a failing step, Ctrl-C and kill): the injector is stopped and restores, the tools end, every
# mapping is unmapped, every image removed, the four ms_*_mode options are put back and, if the cluster was forced, the monitor and the OSDs restarted
# under the original options; then the cluster state (health checks, OSD tree and flags, upmaps, config database, effective mode options, pools,
# daemons) is compared with the snapshot taken first, and dmesg is scanned for new libceph / rbd errors. A difference fails the run, with ONE exception: the
# config database lines osd_mclock_max_capacity_iops_hdd / osd_mclock_max_capacity_iops_ssd (that exact option name, section osd.N, osd or global, any mask) that were
# added or changed during the run. Ceph writes those itself (the mclock scheduler benchmarks a disk after an OSD restart), they are reported as NOTE lines
# and are left alone: the cleanup does not restore or remove them (a `ceph config rm` would be this script changing a Ceph-owned value, and the next OSD
# restart writes it again). Every other difference, and a vanished mclock line, still fails. Only images named
# wrtest-ex-<pid>-* are ever created or removed; never img-default, img-v1 or the pool. Key material is never printed. The first INT / TERM / HUP starts the
# restore; further ones while it runs are ignored (only SIGKILL stops it, and then the next start's state check finds what was left).
#
# Usage (inside the lab VM, a user with passwordless sudo; wr-krbdcmp, wr-rbd built, keyrings in ~/keys):
#   exit-run.sh [--runs 1,2,3,4,5] [--hours 2] [--min-ops 500000] [--max-hours 8] [--attempts 2] [--calibrate 150 | --rate OPS_PER_S | --time-sec SEC]
#               [--ops-short-ok | --short-ok] [--checkpoint 5000] [--depth 8] [--stall-ms 180000] [--seed S] [--forced-key k2|k1] [--min-gap 90] [--max-gap 300]
#               [--osd-kills 20] [--mon-restarts 10] [--outins 10] [--upmaps 5] [--initial-delay 60] [--pause-cap SEC] [--no-faults] [--quick] [--keep]
#   exit-run.sh --dry-run        print the plan (images, times, the injector's deck, the commands); nothing is run, no lab needed
#   exit-run.sh --selftest       the whole script against stand-in cluster tools, with a failure injected at every step: the restore must still run
#   exit-run.sh --report DIR     print the report table of the results kept in DIR (a $WR_LAB_WORK/results of an earlier run)
#
#   --runs LIST      which of the five runs (default all; a run is self-contained: it forces and restores its own cluster state)
#   --hours H        the least random-phase time per run (default 2); --max-hours caps the time the calibration may ask for (default 8)
#   --time-sec SEC   a fixed random-phase time (skips the calibration and the planning; for short trial runs)
#   --quick          small images (16 MiB / 16 MiB - 192 KiB / 10.5 MiB), a 9 minute random phase, the deck cut to 2 OSD kills, 2 monitor restarts, 1 out/in,
#                    1 upmap with gaps of 15 to 40 s, 2,000 operations: the live check of the script itself (a quick run proves nothing about the exit criteria)
#   --no-faults      no injector (a control run)
#   --ops-short-ok   a run whose slowest image ends below --min-ops operations after the time the plan allowed is not repeated and not failed: it passes
#                    with a note that names the images and their counts (the faults and every other check still have to be met). Meant for the long
#                    campaign: on the lab VM the order 22 image does about 15 operations a second in secure mode (the portable GCM, up to 6 MiB per
#                    operation), so 500,000 operations on it would take most of a day per run. Without the flag a short run is repeated and then fails
#   --short-ok       --ops-short-ok, and the same for the faults: a run that ends with fewer OSD kills, monitor restarts, out/in or upmap changes than the
#                    deck asked for (the cluster's recovery after an OSD kill under load takes minutes on the lab VM, so a deck of 45 faults needs
#                    far more than the 2 hours) passes with the counts in the notes. The counts reached are in the report either way
#   --keep           keep the images and the work files
#   --inject-fail S  (selftest) make the step S fail; a comma separated list is allowed
#
# Environment: WR_BUILD_DIR (default <repo>/build/harness), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd), WR_LAB_KEYRING_DIR (~/keys),
# WR_LAB_USER_K2 (winrbd), WR_LAB_USER_K1 (winrbd-aes), WR_LAB_WORK (~/w/exit-run-work; logs and results stay there), WR_LAB_SUDO (sudo),
# EX_HEALTH_IGNORE (health checks left out of the state comparison), EX_STATE_WAIT (seconds to let the final state settle, default 180),
# EX_RESTART_WAIT (seconds a daemon restart may take to become clean again, default 600), EX_HEARTBEAT (seconds between progress lines, default 300).
#
# What fails and what only warns: a byte difference, a failed stock comparison, a tool error, a stall past the watchdog (--stall-ms), an injector fault that
# FAILED (its summary says failed>0), a recovery that never healed (the injector's exit 3), a lab that is not restored (the state compare above) or new
# kernel errors fail the run. Late recoveries (the injector's late>0: a recovery took longer than EX_RECOVERY_MAX, default 600 s, but the cluster healed
# within three times that) only give a WARN line in the report with the count and the slowest one's lateness; the run goes on and passes. So a run 1
# that ends with only those two classes (late recoveries, mclock lines) passes and run 2 is started.
#
# Exit status: 0 every run passed and the lab is as it was; 1 a difference, a failed stock comparison, too little evidence (fewer operations or faults
# than the minimum after the last attempt), a new kernel error, a mode that was not the one asked for or a changed lab; 2 setup problem (usage, a missing
# tool or keyring, a lab that is not whole at the start); 3 a run could not start (create / map failed) or the injector reports a lab that does not
# heal; 4 a request failed or hung in a tool (the watchdog).

set -u
set -o pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
SELF="$here/$(basename "${BASH_SOURCE[0]}")"
INJECTOR="$here/../tools/fault_inject.sh"
# the injector's library (its commands, the state snapshot, the restore); sourcing it runs nothing
# shellcheck disable=SC1090
. "$INJECTOR"

build=${WR_BUILD_DIR:-$repo/build/harness}
WRKC=${WR_KRBDCMP:-$build/wr-krbdcmp}
WRRBD=${WR_RBD:-$build/wr-rbd}
MON=${WR_LAB_MON:-10.77.0.10:3300}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
USER_K2=${WR_LAB_USER_K2:-winrbd}
USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
KRBD_USER=$USER_K1
HEALTH_IGNORE=${EX_HEALTH_IGNORE:-$HEALTH_IGNORE}
MY_UPMAPS="$WORK/injector/my-upmaps"   # the upmap entries the injector child gives itself (its work directory is $WORK/injector): the restore above removes those
STATE_WAIT=${EX_STATE_WAIT:-180}
RESTART_WAIT=${EX_RESTART_WAIT:-600}
HEARTBEAT=${EX_HEARTBEAT:-300}
NAME_TAG=${EX_NAME_TAG:-$$}
ORDERS="12 18 22"

die()  { echo "exit-run: error: $*" >&2; exit 2; }
info() { echo "exit-run: $*" >&2; }

all_args=" $* "
runs="1,2,3,4,5"; hours=2; min_ops=500000; max_hours=8; attempts=2; calib=150; rate=""; time_sec=""; ckpt=5000; depth=8; stall_ms=180000
ops_short_ok=0; faults_short_ok=0; seed=""; forced_key=k2; min_gap=90; max_gap=300; ko=20; km=10; kio=10; ku=5; nofaults=0; quick=0; keep=0; report_arg=""; dry=0; selftest=0
initial=60; pause_cap=0
while [ $# -gt 0 ]; do
    case "$1" in
        --runs) runs=${2:-}; shift ;;
        --hours) hours=${2:-}; shift ;;
        --min-ops) min_ops=${2:-}; shift ;;
        --max-hours) max_hours=${2:-}; shift ;;
        --attempts) attempts=${2:-}; shift ;;
        --calibrate) calib=${2:-}; shift ;;
        --rate) rate=${2:-}; shift ;;
        --time-sec) time_sec=${2:-}; shift ;;
        --checkpoint) ckpt=${2:-}; shift ;;
        --depth) depth=${2:-}; shift ;;
        --stall-ms) stall_ms=${2:-}; shift ;;
        --seed) seed=${2:-}; shift ;;
        --forced-key) forced_key=${2:-}; shift ;;
        --min-gap) min_gap=${2:-}; shift ;;
        --max-gap) max_gap=${2:-}; shift ;;
        --osd-kills) ko=${2:-}; shift ;;
        --mon-restarts) km=${2:-}; shift ;;
        --outins) kio=${2:-}; shift ;;
        --upmaps) ku=${2:-}; shift ;;
        --initial-delay) initial=${2:-}; shift ;;
        --pause-cap) pause_cap=${2:-}; shift ;;
        --no-faults) nofaults=1 ;;
        --quick) quick=1 ;;
        --keep) keep=1 ;;
        --ops-short-ok) ops_short_ok=1 ;;
        --short-ok) ops_short_ok=1; faults_short_ok=1 ;;
        --report) report_arg=${2:-}; shift ;;
        --dry-run) dry=1 ;;
        --selftest) selftest=1 ;;
        --inject-fail) INJECT=${2:-}; shift ;;
        -h|--help) sed -n '3,/^set -u$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# ---- the small python program: the tool's summary, the table --------------------------------------------------------------------------------------
PYX=""
write_pyx() {
    PYX="$WORK/ex.py"
    cat > "$PYX" <<'PY'
import glob, os, re, sys

def kv(line):
    return dict(re.findall(r"([A-Za-z_0-9]+)=(\S+)", line))

cmd = sys.argv[1]
if cmd == "toolsum":    # toolsum LOG -> key=value lines: the last result and stats records, the counts of diff / stall / error records, the last progress
    res, stats, prog, ndiff, nstall, nerr, nretry = {}, {}, {}, 0, 0, 0, 0
    try:
        with open(sys.argv[2], errors="replace") as f:
            for line in f:
                m = re.match(r"@\d+ (\w+) (.*)", line)
                if not m:
                    continue
                k, rest = m.group(1), m.group(2)
                if k == "result" and rest.startswith("ok="):
                    res = kv(rest)
                elif k == "stats":
                    stats = kv(rest)
                elif k == "progress":
                    prog = kv(rest)
                elif k == "diff":
                    ndiff += 1
                elif k == "stall":
                    nstall += 1
                elif k == "error":
                    nerr += 1
                elif k == "retry":
                    nretry += 1
    except OSError:
        pass
    out = {}
    for k in ("ok", "exit", "diffs", "transients", "errors", "verdict", "ops", "reads", "writes", "discards", "zeroes", "flushes", "core_bytes_written",
              "krbd_bytes_written", "core_bytes_read", "krbd_bytes_read", "checkpoints", "scans", "edges", "seed"):
        out["r_" + k] = res.get(k, "")
    for k in ("max_gap_ms", "session_resets", "ops_resent", "ops_failed", "io_stalls", "barrier_violations", "bad_completions", "conns_secure", "conns_crc", "sec_failures"):
        out["s_" + k] = stats.get(k, "")
    out["prog_ops"] = prog.get("ops", "")
    out["prog_phase"] = prog.get("phase", "")
    out["n_diff"], out["n_stall"], out["n_error"], out["n_retry"] = ndiff, nstall, nerr, nretry
    out["have_result"] = 1 if res else 0
    for k in sorted(out):
        print("%s=%s" % (k, out[k]))
elif cmd == "stockstats":   # stockstats LOG -> conns_secure conns_crc sec_failures of the stats line of a wr-rbd run
    cs = cc = sf = ""
    try:
        with open(sys.argv[2], errors="replace") as f:
            for line in f:
                if re.match(r"@\d+ stats ", line):
                    d = kv(line)
                    cs, cc, sf = d.get("conns_secure", ""), d.get("conns_crc", ""), d.get("sec_failures", "")
    except OSError:
        pass
    print("conns_secure=%s\nconns_crc=%s\nsec_failures=%s" % (cs, cc, sf))
elif cmd == "render":   # render RESULTS_DIR -> the report
    root = sys.argv[2]
    def load(p):
        d = {}
        try:
            with open(p) as f:
                for line in f:
                    if "=" in line:
                        k, v = line.rstrip("\n").split("=", 1)
                        d[k] = v
        except OSError:
            pass
        return d
    def human(n):
        try:
            n = float(n)
        except ValueError:
            return "-"
        for u in ("B", "KiB", "MiB", "GiB", "TiB"):
            if n < 1024 or u == "TiB":
                return ("%d %s" % (n, u)) if u == "B" else ("%.1f %s" % (n, u))
            n /= 1024.0
    def dur(s):
        try:
            s = int(float(s))
        except ValueError:
            return "-"
        return "%dh%02dm%02ds" % (s // 3600, s % 3600 // 60, s % 60)
    runs = sorted(glob.glob(os.path.join(root, "run-*")), key=lambda p: int(re.sub(r"\D", "", os.path.basename(p)) or 0))
    out = []
    total_diffs = 0
    for rd in runs:
        m = load(os.path.join(rd, "meta.txt"))
        if not m:
            continue
        out.append("")
        out.append("RUN %s  %s  core key %s  %s  status %s" % (m.get("run"), m.get("mode"), m.get("key"), "cluster forced to secure" if m.get("forced") == "1" else "cluster as found", m.get("status", "?").upper()))
        out.append("  time: random phase %ss planned, %s elapsed, %s attempt(s), seed %s" % (m.get("t_plan", "?"), dur(m.get("elapsed_s", "")), m.get("attempts", "?"), m.get("seed", "?")))
        hdr = "  %-6s %-10s %-9s %9s %8s %8s %7s %6s %7s %10s %10s %10s %10s %5s %5s %5s %5s %7s %9s %6s  %s"
        out.append(hdr % ("order", "size", "tool exit", "ops", "reads", "writes", "discard", "zeroes", "flushes", "core wr", "krbd wr", "core rd", "krbd rd", "ckpts", "scans",
                          "diffs", "trans", "stalls", "max gap", "resets", "stock compare"))
        for ip in sorted(glob.glob(os.path.join(rd, "img-o*.txt")), key=lambda p: int(re.sub(r"\D", "", os.path.basename(p)) or 0)):
            d = load(ip)
            try:
                total_diffs += int(d.get("r_diffs") or 0)
            except ValueError:
                pass
            mg = d.get("s_max_gap_ms", "")
            out.append(hdr % ("o" + d.get("order", "?"), human(d.get("bytes", "")), d.get("tool_rc", "?"), d.get("r_ops", "-"), d.get("r_reads", "-"), d.get("r_writes", "-"),
                              d.get("r_discards", "-"), d.get("r_zeroes", "-"), d.get("r_flushes", "-"), human(d.get("r_core_bytes_written", "")),
                              human(d.get("r_krbd_bytes_written", "")), human(d.get("r_core_bytes_read", "")), human(d.get("r_krbd_bytes_read", "")), d.get("r_checkpoints", "-"),
                              d.get("r_scans", "-"), d.get("r_diffs", "-"), d.get("r_transients", "-"), d.get("n_stall", "-"), (mg + " ms") if mg else "-",
                              d.get("s_session_resets", "-"), "exit " + d.get("stock_rc", "?") if d.get("stock_rc") != "0" else "equal"))
        out.append("  injector: %s" % (m.get("injector") or "none (no faults)"))
        if m.get("warn"):
            out.append("  WARN: %s" % m["warn"])
        if m.get("state_notes"):
            out.append("  NOTE: %s" % m["state_notes"])
        out.append("  largest stall: %s ms (watchdog limit %s ms), injector exit %s" % (m.get("max_gap_ms", "?"), m.get("stall_ms", "?"), m.get("injector_rc", "-")))
        out.append("  connections of the stock comparison (the core, every OSD and the monitor): conns_secure=%s conns_crc=%s sec_failures=%s; of the tools: %s" %
                   (m.get("conns_secure", "?"), m.get("conns_crc", "?"), m.get("sec_failures", "?"), m.get("tool_conns", "not reported by the tool")))
        out.append("  lab restored: %s; dmesg: %s" % (m.get("restored", "?"), m.get("dmesg", "?")))
        if m.get("notes"):
            out.append("  notes: %s" % m["notes"])
    out.append("")
    out.append("differences in all tools: %d" % total_diffs)
    print("\n".join(out))
PY
}
pyx() { python3 -I "$PYX" "$@"; }

if [ -n "$report_arg" ]; then
    [ -d "$report_arg" ] || die "--report takes the results directory (a \$WR_LAB_WORK/results of an earlier run): '$report_arg' is not one"
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/exit-run-report.XXXXXX") || die "no temporary directory"
    write_pyx
    pyx render "$report_arg"
    rm -rf "$WORK"
    exit 0
fi

# ---- the arguments -----------------------------------------------------------------------------------------------------------------------------
case "$forced_key" in k2|k1) ;; *) die "--forced-key takes k2 or k1" ;; esac
for r in ${runs//,/ }; do case "$r" in 1|2|3|4|5) ;; *) die "--runs takes numbers 1 to 5 (got '$r')" ;; esac; done
[ -n "${runs//,/}" ] || die "--runs is empty"
[[ "$hours" =~ ^([0-9]+(\.[0-9]*)?|\.[0-9]+)$ ]] || die "--hours takes a number (like 2 or 0.5)"
# every numeric option on its own: an empty one or one with a letter is refused (a concatenated check let '--osd-kills ""' through, and the test
# `[ x -lt "" ]` then fails quietly, which read as "enough faults"); at most nine digits (the arithmetic below multiplies them); read as decimal ("08" is
# not an octal error)
for v in min_ops max_hours attempts calib ckpt depth stall_ms min_gap max_gap ko km kio ku initial pause_cap rate time_sec seed; do
    eval "val=\${$v}"
    case "$v:$val" in rate:|time_sec:|seed:) continue ;; esac
    case "$val" in ''|*[!0-9]*) die "the numeric options take whole numbers (got '$val' for $v)" ;; esac
    [ "${#val}" -le 9 ] || die "the numeric options take at most nine digits (got '$val' for $v)"
    eval "$v=\$((10#$val))"
done
[ "$max_hours" -ge 1 ] && [ "$calib" -ge 1 ] && [ "$ckpt" -ge 1 ] && [ "$stall_ms" -ge 1 ] || die "--max-hours, --calibrate, --checkpoint and --stall-ms take at least 1"
[ -z "$rate" ] || [ "$rate" -ge 1 ] || die "--rate takes at least 1 operation per second"
[ -z "$time_sec" ] || [ "$time_sec" -ge 1 ] || die "--time-sec takes at least 1 second"
[ "$attempts" -ge 1 ] && [ "$attempts" -le 5 ] || die "--attempts takes 1 to 5"
[ "$min_gap" -ge 1 ] && [ "$max_gap" -ge "$min_gap" ] || die "--min-gap / --max-gap: 1 <= min <= max"
[ "$depth" -ge 1 ] && [ "$depth" -le 64 ] || die "--depth takes 1 to 64"
case "$WORK" in /*) ;; *) die "WR_LAB_WORK must be an absolute path" ;; esac
case "$WORK" in *' '*|*'*'*|*'?'*) die "WR_LAB_WORK must not contain spaces or glob characters" ;; esac
if [ "$quick" -eq 1 ]; then
    # the live check of the script itself: the deck cut down, the gaps short, the images small, the time short (explicit options still win)
    case "$all_args" in *" --calibrate "*|*" --rate "*) ;; *) [ -n "$time_sec" ] || time_sec=540 ;; esac
    case "$all_args" in *" --min-ops "*) ;; *) min_ops=2000 ;; esac
    case "$all_args" in *" --osd-kills "*) ;; *) ko=2 ;; esac
    case "$all_args" in *" --mon-restarts "*) ;; *) km=2 ;; esac
    case "$all_args" in *" --outins "*) ;; *) kio=1 ;; esac
    case "$all_args" in *" --upmaps "*) ;; *) ku=1 ;; esac
    case "$all_args" in *" --min-gap "*) ;; *) min_gap=15 ;; esac
    case "$all_args" in *" --max-gap "*) ;; *) max_gap=40 ;; esac
    case "$all_args" in *" --initial-delay "*) ;; *) initial=10 ;; esac
    case "$all_args" in *" --pause-cap "*) ;; *) pause_cap=20 ;; esac
    case "$all_args" in *" --checkpoint "*) ;; *) ckpt=1000 ;; esac
fi

# ---- sizes and the plan ---------------------------------------------------------------------------------------------------------------------------
KIB=1024; MIB=$((1024 * 1024)); GIB=$((1024 * 1024 * 1024))
geom() { # <order> -> IMG_BYTES
    case "$quick:$1" in
        1:12) IMG_BYTES=$((16 * MIB)) ;;
        1:18) IMG_BYTES=$((16 * MIB - 192 * KIB)) ;;
        1:22) IMG_BYTES=$((12 * MIB - 3 * MIB / 2)) ;;
        0:12) IMG_BYTES=$((64 * MIB)) ;;
        0:18) IMG_BYTES=$((GIB - 192 * KIB)) ;;
        0:22) IMG_BYTES=$((2 * GIB - 3 * MIB / 2)) ;;
        *) die "no geometry for order $1" ;;
    esac
}
maxlen_of() { # <order> -> operation length bound: 1.5 objects, at least 256 KiB, at most 8 MiB
    local m=$(( (1 << $1) * 3 / 2 ))
    [ "$m" -ge 262144 ] || m=262144
    [ "$m" -le 8388608 ] || m=8388608
    echo "$m"
}
run_spec() { # <n> -> R_MODE R_KEY R_FORCED R_USER
    case "$1" in
        1) R_MODE=crc; R_KEY=k2; R_FORCED=0 ;;
        2) R_MODE=crc; R_KEY=k1; R_FORCED=0 ;;
        3) R_MODE=secure; R_KEY=k2; R_FORCED=0 ;;
        4) R_MODE=secure; R_KEY=k1; R_FORCED=0 ;;
        5) R_MODE=secure; R_KEY=$forced_key; R_FORCED=1 ;;
    esac
    if [ "$R_KEY" = k2 ]; then R_USER=$USER_K2; else R_USER=$USER_K1; fi
}
# the deck's time at the mean gap, with a fifth on top for the recoveries, plus the first fault's delay
# a fault never starts before the last one has recovered (about a minute and a half on the lab), so a gap shorter than that counts as that
deck_secs() { local per=$(( (min_gap + max_gap) / 2 )); [ "$per" -ge 90 ] || per=90; echo $(( (ko + km + kio + ku) * per * 6 / 5 + initial + 60 )); }
secs_of_hours() { awk -v h="$hours" 'BEGIN { printf "%d", h * 3600 }'; }

if [ "$dry" -eq 1 ]; then
    echo "exit-run plan (nothing is run, nothing is changed):"
    echo "  tools: $WRKC, $WRRBD, injector $INJECTOR"
    echo "  length per run: at least $(secs_of_hours) s ($hours h) and $min_ops operations per image and the injector's deck (about $(deck_secs) s); the least random-phase time of a run is the largest of the three${time_sec:+; FIXED at $time_sec s}"
    echo "  calibration: ${rate:+skipped, assuming $rate ops/s}${rate:-$([ -n "$time_sec" ] && echo skipped || echo "$calib s on throw-away images without faults")}; attempts $attempts; checkpoint every $ckpt operations; depth $depth; watchdog $stall_ms ms"
    for r in ${runs//,/ }; do
        run_spec "$r"
        echo "  run $r: mode $R_MODE, core key $R_KEY (client.$R_USER), krbd ms_mode=$([ "$R_MODE" = crc ] && echo prefer-crc || echo secure) as client.$KRBD_USER$([ "$R_FORCED" = 1 ] && echo ", cluster forced to secure (ms_mon_service_mode, ms_service_mode)")"
        for o in $ORDERS; do
            geom "$o"
            echo "    image wrtest-ex-<pid>-r$r-o$o: $IMG_BYTES bytes, object size $((1 << o)), operation length up to $(maxlen_of "$o"); wr-krbdcmp --phase all --dir all --mode $R_MODE --checkpoint $ckpt --stall-ms $stall_ms"
        done
        if [ "$nofaults" -eq 1 ]; then echo "    faults: none"; else
            echo "    faults: fault_inject.sh --osd-kills $ko --mon-restarts $km --outins $kio --upmaps $ku --min-gap $min_gap --max-gap $max_gap (a printed seed)"; fi
        echo "    end: stop the injector (it restores), rbd export + wr-rbd compare --mode $R_MODE --require-mode $R_MODE, unmap, rm$([ "$R_FORCED" = 1 ] && echo ", put the options back and restart the daemons under them"), compare the state"
    done
    exit 0
fi

# ---- the work directory, the keyrings, the tools -----------------------------------------------------------------------------------------------
TRACK="$WORK/track"
RESULTS="$WORK/results"
FINAL_RC=0
STOPFILE="$WORK/injector.stop"
INJ_PID=""
TOOL_PIDS=()
CUR_RUN=0

keyring_of() { echo "$KEYDIR/client.$1.keyring"; }

# ---- dmesg -----------------------------------------------------------------------------------------------------------------------------------------
DMESG() { $SUDO dmesg 2>/dev/null; }
# What the kernel client says when a daemon is killed under it is not an error of the client: the connection is gone and it reconnects ("socket error on
# write", "socket closed", "session lost, hunting for new mon", the OSD map's "osdN down" / "osdN up" and "weight ... (out)" / "(in)"). Those lines are
# counted and shown as notes; any other new libceph / rbd line that names a corruption, a bad signature or tag, a failed decrypt, a hung task or a kernel
# warning fails the run (the data itself is judged by the byte comparison, this is the second witness: what the kernel complained about).
DMESG_EXPECTED='(socket (error on (read|write)|closed)|session (lost|established)|hunting for new mon|osd[0-9]+ (down|up)$|weight 0x[0-9a-f]+ \((in|out)\))'
DMESG_FAIL='(bad |corrupt|mismatch|signature|decrypt|integrity|invalid|protocol error|error|fail|BUG|WARNING|Oops|hung|blocked for|timed out|Call Trace)'
dmesg_snapshot() { DMESG | grep -E 'libceph|rbd' | sed 's/^\[[ 0-9.]*\] //' | sort > "$1" || true; }
dmesg_check() { # <before-file> -> 0 when no new libceph / rbd line of a kind that is not the expected churn of a killed daemon appeared
    local after="$WORK/dmesg.after" new="$WORK/dmesg.new" other="$WORK/dmesg.other" bad=0
    dmesg_snapshot "$after"
    comm -13 "$1" "$after" > "$new" || true
    grep -Eiv "$DMESG_EXPECTED" "$new" > "$other" || true
    if [ -s "$other" ]; then
        if grep -Eiq "$DMESG_FAIL" "$other"; then
            echo "FAIL  new libceph / rbd errors in dmesg:" >&2
            grep -Ei "$DMESG_FAIL" "$other" | head -n 20 | sed 's/^/      | /' >&2
            bad=1
        fi
        grep -Eiv "$DMESG_FAIL" "$other" | head -n 10 | sed 's/^/NOTE  dmesg: /' || true
    fi
    if grep -Eiq "$DMESG_EXPECTED" "$new"; then
        echo "NOTE  dmesg: $(grep -Eic "$DMESG_EXPECTED" "$new") expected lines of the kernel client reconnecting after a killed or restarted daemon (e.g. $(grep -Ei "$DMESG_EXPECTED" "$new" | head -n 1 | cut -c1-100))"
    fi
    return $bad
}

# ---- the four options and the daemons that read them at startup ------------------------------------------------------------------------------------
# A flag file says that the daemons may run with options other than the original ones (set before the first `config set`, cleared after a restart of
# every daemon under the original options): the EXIT trap restarts them in that case.
mark_stale() { : > "$WORK/stale"; }

modes_snapshot() { # <outfile>: the four options as the config database holds them ("name<TAB>who<TAB>value", sorted); 1 when the cluster cannot say
    local o=$1 j
    j=$(CEPH config dump -f json 2>/dev/null) || return 1
    [ -n "$j" ] || return 1
    printf '%s' "$j" | py modes "$MODE_OPTS" > "$o.tmp" || { rm -f "$o.tmp"; return 1; }
    mv "$o.tmp" "$o"
}
modes_match_baseline() { local cur="$WORK/modes.cur"; modes_snapshot "$cur" || return 2; cmp -s "$WORK/modes.before" "$cur"; }

set_mode_opt() { # <who: mon|osd> <name> <value>: only the four options of the lab rules, only to the values they allow
    local who=$1 name=$2 value=$3 n ok=0
    for n in $MODE_OPTS; do [ "$n" = "$name" ] && ok=1; done
    [ "$ok" -eq 1 ] || die "refusing to set $name: only $MODE_OPTS may be changed"
    case "$who" in mon|osd) ;; *) die "refusing to set $name for '$who'" ;; esac
    case "$value" in secure|crc|"crc secure"|"secure crc") ;; *) die "refusing to set $name to '$value'" ;; esac
    mark_stale
    fi_step "set-$who" CEPH config set "$who" "$name" "$value"
}

revert_modes() { # every option set (or removed) that differs from the snapshot taken first is put back; 0 when the database matches afterwards
    local cur="$WORK/modes.cur" name who value rc=0
    modes_snapshot "$cur" || { echo "FAIL  cannot read the config database to put the four options back" >&2; return 1; }
    while IFS=$'\t' read -r name who value; do   # set now but not in the original: remove
        [ -n "$name" ] || continue
        echo "exit-run: restore: removing $name of $who (was: $value)" >&2
        CEPH config rm "$who" "$name" >/dev/null 2>&1 || rc=1
    done < <(LC_ALL=C comm -13 "$WORK/modes.before" "$cur")
    while IFS=$'\t' read -r name who value; do   # in the original but not (or not the same) now: set back
        [ -n "$name" ] || continue
        echo "exit-run: restore: setting $name of $who back to '$value'" >&2
        CEPH config set "$who" "$name" "$value" >/dev/null 2>&1 || rc=1
    done < <(LC_ALL=C comm -23 "$WORK/modes.before" "$cur")
    modes_match_baseline || rc=1
    return $rc
}

# restart_all: the monitor, then every OSD one at a time, each waited for until the cluster is clean again (the options are read at startup).
restart_all() {
    local u kind rc=0 n=0
    for u in "${MON_UNITS[@]}" "${OSD_UNITS[@]}"; do
        n=$((n + 1))
        case "$u" in *@mon.*) kind=mon ;; *) kind=osd ;; esac
        info "restarting ${u#*@}"
        SYSCTL reset-failed "$u" >/dev/null 2>&1
        if ! fi_step "restart-$kind" SYSCTL restart "$u"; then
            echo "FAIL  could not restart $u" >&2
            rc=1
            continue
        fi
        if ! fi_wait_clean "$RESTART_WAIT"; then
            echo "FAIL  after restarting $u the cluster did not become clean within $RESTART_WAIT s: $(CEPH pg stat 2>&1 | head -n 1)" >&2
            rc=1
        fi
    done
    [ "$n" -gt 0 ] || { echo "FAIL  found no ceph mon / osd unit to restart" >&2; return 1; }
    return $rc
}

force_secure() { # the cluster refuses crc from here on: the monitor and every OSD read the options at startup
    set_mode_opt mon ms_mon_service_mode secure || return 1
    set_mode_opt osd ms_service_mode secure || return 1
    case "$(CEPH config get mon ms_mon_service_mode 2>&1) $(CEPH config get osd ms_service_mode 2>&1)" in
        "secure secure") ;; *) echo "FAIL  the config database does not say secure after setting it" >&2; return 1 ;;
    esac
    restart_all
}

# restore_modes: idempotent; options back, daemons restarted when they ran with other options; 0 when the options match and the restart worked
restore_modes() {
    local rc=0
    if ! modes_match_baseline; then revert_modes || rc=1; fi
    if [ -e "$WORK/stale" ]; then
        info "restoring: restarting the monitor and the OSDs under the original options"
        if restart_all; then rm -f "$WORK/stale"; else rc=1; fi
    fi
    return $rc
}

# ---- images and mappings (what this script made, so the trap can undo it) -------------------------------------------------------------------------
track_image() { echo "$1" > "$TRACK/$2.image"; }
track_map()   { echo "$1" > "$TRACK/$2.map"; }
untrack()     { rm -f "$TRACK/$1.$2"; }

unmap_dev() { # <dev>: retry a few times; a device that is busy for a moment is common right after the tool ended
    local dev=$1 i
    for i in 1 2 3 4 5; do
        if RBD unmap "$dev" 2>/dev/null; then return 0; fi
        sleep 2
    done
    RBD unmap -o force "$dev" 2>/dev/null
}

cleanup_tracked() { # every device first, then every image (a mapped image cannot be removed)
    local f dev img rc=0
    shopt -s nullglob
    for f in "$TRACK"/*.map; do
        dev=$(cat "$f")
        if fi_inject unmap-cleanup; then echo "FAIL  could not unmap $dev (injected failure)" >&2; rc=1; continue; fi
        if unmap_dev "$dev"; then rm -f "$f"; else echo "FAIL  could not unmap $dev" >&2; rc=1; fi
    done
    for f in "$TRACK"/*.image; do
        img=$(cat "$f")
        [ "$keep" = 1 ] && continue
        case "$img" in "$POOL/wrtest-ex-$NAME_TAG-"*) ;; *) echo "FAIL  refusing to remove '$img': not an image of this run" >&2; rc=1; continue ;; esac
        if RBD rm "$img" >/dev/null 2>&1 || ! RBD info "$img" >/dev/null 2>&1; then rm -f "$f"; else echo "FAIL  could not remove image $img" >&2; rc=1; fi
    done
    shopt -u nullglob
    return $rc
}

# ---- the injector ------------------------------------------------------------------------------------------------------------------------------------
start_injector() { # <run dir> <seed>
    local rdir=$1 iseed=$2
    rm -f "$STOPFILE" "$rdir/injector.summary"   # a summary of an earlier attempt must never be read as this one's (an injector that is killed writes none)
    mkdir -p "$WORK/injector"
    : > "$rdir/fault-events.log"
    WR_LAB_WORK="$WORK/injector" FI_INJECT_FAIL="$INJECT" FI_STATE_WAIT="$STATE_WAIT" FI_POLL="$POLL" \
        bash "$INJECTOR" --seed "$iseed" --stop-file "$STOPFILE" --events "$rdir/fault-events.log" --summary "$rdir/injector.summary" \
        --min-gap "$min_gap" --max-gap "$max_gap" --osd-kills "$ko" --mon-restarts "$km" --outins "$kio" --upmaps "$ku" --initial-delay "$initial" \
        --pause-cap "$pause_cap" --recovery-max "${EX_RECOVERY_MAX:-600}" > "$rdir/injector.log" 2>&1 &
    INJ_PID=$!
}
injector_alive() { [ -n "$INJ_PID" ] && kill -0 "$INJ_PID" 2>/dev/null; }
# stop the injector: it finishes the fault in progress (the daemon is started again, the OSD marked in), restores and compares the state, then exits
stop_injector() { # -> sets INJ_RC
    local i
    INJ_RC=""
    [ -n "$INJ_PID" ] || return 0
    : > "$STOPFILE"
    for ((i = 0; i < ${EX_INJ_STOP_WAIT:-1800}; i++)); do
        injector_alive || break
        sleep 1
    done
    if injector_alive; then
        echo "exit-run: the injector did not stop within ${EX_INJ_STOP_WAIT:-1800} s: sending SIGTERM" >&2
        kill -TERM "$INJ_PID" 2>/dev/null
        for ((i = 0; i < 600; i++)); do injector_alive || break; sleep 1; done
        injector_alive && kill -KILL "$INJ_PID" 2>/dev/null
    fi
    wait "$INJ_PID" 2>/dev/null
    INJ_RC=$?
    INJ_PID=""
    rm -f "$STOPFILE"
    # an injector that was killed (or died) in the middle of a fault leaves a daemon down, an OSD out or an upmap entry behind: the same idempotent restore
    # the injector's own trap runs, from here, with the units and the entries it knows (a restore that was already done finds nothing to do)
    if ! fi_restore_cluster; then
        echo "FAIL  the injector's restore (every daemon running, every OSD in, the upmap entries removed) could not be completed" >&2
        [ "${INJ_RC:-0}" -ne 0 ] || INJ_RC=3
    fi
}

# ---- the tools ---------------------------------------------------------------------------------------------------------------------------------------
tools_kill() {
    local p i alive
    $SUDO pkill -TERM -f -- "--image [w]rtest-ex-$NAME_TAG-" 2>/dev/null
    sleep 1
    $SUDO pkill -KILL -f -- "--image [w]rtest-ex-$NAME_TAG-" 2>/dev/null
    # the subshell of each tool writes its status file as soon as the tool is gone: a subshell killed before that leaves no file (read as 255, a
    # "could not run" that would hide the tool's own status); only one that is still there after ten seconds is told to go
    for ((i = 0; i < 10; i++)); do
        alive=0
        for p in "${TOOL_PIDS[@]+"${TOOL_PIDS[@]}"}"; do kill -0 "$p" 2>/dev/null && alive=1; done
        [ "$alive" -eq 1 ] || return 0
        sleep 1
    done
    for p in "${TOOL_PIDS[@]+"${TOOL_PIDS[@]}"}"; do kill "$p" 2>/dev/null; done
}

# ---- one run -----------------------------------------------------------------------------------------------------------------------------------------
IMG_NAMES=(); IMG_DEVS=(); IMG_SUFFIX=""
img_of() { echo "wrtest-ex-$NAME_TAG-r$1$IMG_SUFFIX-o$2"; }   # <run> <order>: the calibration ("c") and every attempt ("a1", "a2") have images of their own
tkey()   { echo "r$1$IMG_SUFFIX-o$2"; }
make_images() { # <run> <rdir> -> 0, or 3 when an image could not be made or mapped
    local n=$1 o img dev opts i=0
    IMG_NAMES=(); IMG_DEVS=()
    opts="ms_mode=$([ "$R_MODE" = crc ] && echo prefer-crc || echo secure),alloc_size=512"
    for o in $ORDERS; do
        geom "$o"
        img=$(img_of "$n" "$o")
        track_image "$POOL/$img" "$(tkey "$n" "$o")"
        if ! fi_step "create-o$o" RBD create --size "${IMG_BYTES}B" --image-feature layering --object-size "$((1 << o))" "$POOL/$img" >/dev/null; then
            echo "FAIL  could not create the image $POOL/$img" >&2
            return 3
        fi
        dev=$(fi_step "map-o$o" RBD map -n "client.$KRBD_USER" --keyring "$(keyring_of "$KRBD_USER")" -o "$opts" "$POOL/$img") || dev=""
        case "$dev" in /dev/*) ;; *) echo "FAIL  could not map $POOL/$img (krbd: $KRBD_USER, -o $opts): $dev" >&2; return 3 ;; esac
        track_map "$dev" "$(tkey "$n" "$o")"
        IMG_NAMES+=("$img"); IMG_DEVS+=("$dev")
        i=$((i + 1))
    done
    return 0
}

drop_images() { # <run>: unmap and remove what make_images made (the calibration's, and each attempt's)
    local n=$1 o dev img rc=0 k
    for o in $ORDERS; do
        k=$(tkey "$n" "$o")
        if [ -e "$TRACK/$k.map" ]; then
            dev=$(cat "$TRACK/$k.map")
            if fi_step unmap unmap_dev "$dev"; then untrack "$k" map; else echo "FAIL  could not unmap $dev: left to the trap" >&2; rc=1; fi
        fi
        if [ ! -e "$TRACK/$k.map" ] && [ -e "$TRACK/$k.image" ]; then
            img=$(cat "$TRACK/$k.image")
            if [ "$keep" = 1 ]; then :; elif fi_step rm RBD rm "$img" >/dev/null 2>&1; then untrack "$k" image; else echo "FAIL  could not remove $img: left to the trap" >&2; rc=1; fi
        fi
    done
    return $rc
}

# does the tool take --require-mode (the run's own connections counted and asserted)? A tool built before that option still works, without the assertion
tool_has_require_mode() { [ "$("$WRKC" --help 2>&1 | grep -c -- '--require-mode')" -gt 0 ]; }   # grep -c, not -q: under pipefail a -q that quits early reads as a failure

start_tools() { # <run> <rdir> <tag> <phase> <dir> <time s> <seed base>
    local n=$1 rdir=$2 tag=$3 phase=$4 dir=$5 tsec=$6 sbase=$7 i=0 o kr req=()
    kr=$(keyring_of "$R_USER")
    if tool_has_require_mode; then req=(--require-mode "$R_MODE"); fi
    TOOL_PIDS=()
    for o in $ORDERS; do
        local img=${IMG_NAMES[$i]} dev=${IMG_DEVS[$i]} log="$rdir/$tag-o$o.log" ml tmo
        ml=$(maxlen_of "$o")
        tmo=$((tsec + 7200 + ${EX_TOOL_SLACK:-0}))
        rm -f "$rdir/$tag-o$o.rc"
        {
            echo "tool: wr-krbdcmp --mon $MON --user $R_USER --keyring <keyring of $R_USER> --pool $POOL --image $img --dev $dev --dir $dir --phase $phase --time $tsec" \
                 "--depth $depth --checkpoint $ckpt --max-len $ml --mem-max 512M --discard-gran 512 --stall-ms $stall_ms --mode $R_MODE ${req[*]+"${req[*]}"} --label r$n-o$o --seed $((sbase + i))"
        } > "$log"
        (
            fi_step tool $SUDO timeout --kill-after=60 "$tmo" "$WRKC" --mon "$MON" --user "$R_USER" --keyring "$kr" --pool "$POOL" --image "$img" --dev "$dev" \
                --dir "$dir" --phase "$phase" --time "$tsec" --depth "$depth" --checkpoint "$ckpt" --max-len "$ml" --mem-max 512M --discard-gran 512 \
                --stall-ms "$stall_ms" --mode "$R_MODE" ${req[@]+"${req[@]}"} --label "r$n-o$o" --seed "$((sbase + i))" >> "$log" 2>&1
            echo $? > "$rdir/$tag-o$o.rc"
        ) &
        TOOL_PIDS+=($!)
        i=$((i + 1))
    done
}

# wait_tools <rdir> <tag> <t0>: until every tool has ended; the first tool that ends badly (or an injector that stopped) ends the run, the others are
# told to stop. Prints a progress line every EX_HEARTBEAT seconds. 0 = all ended, 1 = one failed (the others were stopped)
wait_tools() {
    local rdir=$1 tag=$2 t0=$3 last=$SECONDS o alldone bad=0 rc i
    while :; do
        alldone=1; bad=0
        for o in $ORDERS; do
            if [ -e "$rdir/$tag-o$o.rc" ]; then
                rc=$(cat "$rdir/$tag-o$o.rc")
                [ "$rc" = 0 ] || bad=1
            else
                alldone=0
            fi
        done
        if [ "$bad" -eq 0 ] && [ -n "$INJ_PID" ] && ! injector_alive; then
            echo "exit-run: the injector ended on its own (see $rdir/injector.log): the run cannot go on" >&2
            bad=1
        fi
        if [ "$bad" -eq 1 ]; then
            echo "exit-run: a tool or the injector failed: stopping the others" >&2
            tools_kill
            for ((i = 0; i < 90; i++)); do
                alldone=1
                for o in $ORDERS; do [ -e "$rdir/$tag-o$o.rc" ] || alldone=0; done
                [ "$alldone" -eq 1 ] && break
                sleep 1
            done
            return 1
        fi
        [ "$alldone" -eq 1 ] && return 0
        if [ $((SECONDS - last)) -ge "$HEARTBEAT" ]; then
            last=$SECONDS
            progress_line "$rdir" "$tag" "$((SECONDS - t0))"
        fi
        sleep "${EX_WAIT_POLL:-5}"
    done
}

progress_line() { # <rdir> <tag> <elapsed>
    local o s line=""
    for o in $ORDERS; do
        s=$(pyx toolsum "$1/$2-o$o.log" | sed -n 's/^prog_ops=//p;s/^prog_phase=/ phase /p' | tr '\n' ' ')
        line="$line o$o: ops ${s:-?};"
    done
    echo "exit-run: [$(date +%H:%M:%S)] run $CUR_RUN $(printf '%dh%02dm' $(($3 / 3600)) $(($3 % 3600 / 60)))$line faults so far: $(grep -c ' fault n=' "$1/fault-events.log" 2>/dev/null || echo 0)" >&2
}

# the stock oracle: the image as the cluster holds it must equal the stock export read through the core, in the run's mode
stock_compare() { # <run> <rdir> <order> <user> <keyring> -> sets SC_RC; the stats of the comparison in $rdir/stock-o<order>.log
    local n=$1 rdir=$2 o=$3 user=$4 kr=$5 try=0 rc img exp log
    img=$(img_of "$n" "$o"); exp="$WORK/export-r$n$IMG_SUFFIX-o$o.img"; log="$rdir/stock-o$o.log"
    SC_RC=1
    : > "$log"
    if ! fi_step export RBD export --no-progress "$POOL/$img" "$exp" >> "$log" 2>&1; then
        echo "stock export failed" >> "$log"; rm -f "$exp"; return 0
    fi
    while :; do
        fi_step compare "$WRRBD" --mon "$MON" --user "$user" --keyring "$kr" --pool "$POOL" --image "$img" --mode "$R_MODE" --require-mode "$R_MODE" compare "$exp" > "$log.try" 2>&1
        rc=$?
        cat "$log.try" >> "$log"; rm -f "$log.try"
        [ "$rc" -ne 0 ] || break
        # exit 3 is "the image could not be opened" (the monitor was slow to answer after the faults), not a data difference: try again, twice at most
        if [ "$rc" -eq 3 ] && [ "$try" -lt 2 ]; then try=$((try + 1)); echo "stock comparison could not open the image (exit 3): trying again ($try of 2)" >> "$log"; sleep "${EX_RETRY_WAIT:-20}"; continue; fi
        break
    done
    rm -f "$exp"
    SC_RC=$rc
}

sum_of() { # <file> <key>: the value of key= in a key=value file
    sed -n "s/^$2=//p" "$1" | tail -n 1
}

# one attempt of a run: 0 = a complete pass, 5 = too little evidence (the caller may repeat it with more time), anything else = a failure (final)
ATT_OPS_MIN=0; ATT_FAULTS_OK=1; ATT_STATUS=""; ATT_NOTE=""; ATT_FAULTS_TEXT=""; ATT_WARN=""

# inj_judge <rdir> <the injector's summary line>: what the injector's own counts say about the run. A fault that FAILED (a step of it did not work: failed>0)
# is a failure, returned as 1 with a FAIL line. Late recoveries (late>0: a recovery took longer than the injector's limit, EX_RECOVERY_MAX, but the cluster
# DID heal, within three times the limit; a recovery that does not heal is the injector's exit 3) are a WARN: ATT_WARN carries the count and how far past the
# limit the slowest one went, the report shows it, and the run is not failed by it. No summary (an injector that was killed writes none) judges nothing here:
# its exit status already did.
inj_judge() {
    local rdir=$1 sm=$2 f l o m lim
    ATT_WARN=""
    f=$(echo "$sm" | sed -n 's/.* failed=\([0-9]*\).*/\1/p'); l=$(echo "$sm" | sed -n 's/.* late=\([0-9]*\).*/\1/p')
    o=$(echo "$sm" | sed -n 's/.* late_max_over_s=\([0-9]*\).*/\1/p'); m=$(echo "$sm" | sed -n 's/.* max_recovery_s=\([0-9]*\).*/\1/p')
    lim=$(echo "$sm" | sed -n 's/.* recovery_limit_s=\([0-9]*\).*/\1/p')
    # fail closed: a summary that does not say how many faults failed (cut short, garbled, or no file although the injector exited 0) proves nothing
    if [ -z "$f" ] || [ -z "$l" ]; then
        echo "FAIL  the injector's summary line has no failed= / late= count (injector.summary: '${sm:-empty}'): nothing shows that every fault worked" >&2
        return 1
    fi
    if [ "${f:-0}" -gt 0 ]; then
        echo "FAIL  the injector counted $f failed fault(s): a step of a fault did not work (see $rdir/injector.log and $rdir/fault-events.log)" >&2
        return 1
    fi
    if [ "${l:-0}" -gt 0 ]; then
        ATT_WARN="$l late recoveries (each took longer than the ${lim:-${EX_RECOVERY_MAX:-600}} s limit but the cluster healed), the slowest ${o:-?} s past the limit (longest recovery ${m:-?} s)"
        echo "exit-run: WARN: $ATT_WARN" >&2
    fi
    return 0
}
run_attempt() { # <run> <rdir> <time s> <attempt> <seed base>
    local n=$1 rdir=$2 tsec=$3 att=$4 sbase=$5 o i rc=0 worst=0 tag="att$4" t0 rcs ops_min="" conns_s=0 conns_c=0 secf=0 maxgap=0 r_rc
    local imgdir="$rdir/attempt-$att" aseed=$((sbase + (att - 1) * 1000))   # a repeated attempt draws other operations and other faults
    mkdir -p "$imgdir"
    IMG_SUFFIX="a$att"
    ATT_STATUS=""; ATT_NOTE=""; ATT_WARN=""
    # a failed start gives its images back at once: with EX_STOP_ON_FAIL=0 the next run must not find three more mapped images (the lab rule is
    # eight at a time)
    make_images "$n" || { ATT_STATUS="could not create or map an image"; drop_images "$n" || true; return 3; }
    if ! fi_wait_clean "$RESTART_WAIT"; then ATT_STATUS="the cluster is not clean before the start: $(CEPH pg stat 2>&1 | head -n 1)"; drop_images "$n" || true; return 3; fi
    t0=$SECONDS
    if [ "$nofaults" -eq 0 ]; then
        start_injector "$rdir" "$((aseed + 7777))"
        info "run $n attempt $att: injector started (seed $((aseed + 7777)), log $rdir/injector.log)"
        sleep 2
        if ! injector_alive; then ATT_STATUS="the injector did not start: $(tail -n 3 "$rdir/injector.log" | tr '\n' ' ')"; stop_injector; drop_images "$n" || true; return 3; fi
    fi
    info "run $n attempt $att: three wr-krbdcmp for $tsec s of random phase (mode $R_MODE, core key $R_KEY), logs in $rdir"
    start_tools "$n" "$rdir" "$tag" all all "$tsec" "$aseed"
    wait_tools "$rdir" "$tag" "$t0" || rc=1
    # the tools are done: the injector stops, restores, and the lab is clean again before the stock comparison
    stop_injector
    if [ "$nofaults" -eq 0 ]; then
        INJ_SUMMARY=$(cat "$rdir/injector.summary" 2>/dev/null || true)
        [ "${INJ_RC:-0}" -eq 0 ] || { rc=1; [ "${INJ_RC:-0}" -ne 3 ] || worst=3; }
        inj_judge "$rdir" "$INJ_SUMMARY" || { rc=1; [ "$worst" -ne 0 ] || worst=1; }
    fi
    if ! fi_wait_clean "$RESTART_WAIT"; then echo "FAIL  the cluster is not clean after the injector stopped: $(CEPH pg stat 2>&1 | head -n 1)" >&2; rc=1; fi
    i=0
    for o in $ORDERS; do
        rcs=$(cat "$rdir/$tag-o$o.rc" 2>/dev/null || echo 255)
        cp "$rdir/$tag-o$o.log" "$imgdir/tool-o$o.log" 2>/dev/null
        {
            pyx toolsum "$rdir/$tag-o$o.log"
            echo "order=$o"
            geom "$o"; echo "bytes=$IMG_BYTES"
            echo "tool_rc=$rcs"
        } > "$rdir/img-o$o.txt"
        case "$rcs" in 0) ;; 1|5) [ "$worst" -eq 4 ] || worst=1; rc=1 ;; 4) worst=4; rc=1 ;; *) [ "$worst" -ne 0 ] || worst=3; rc=1 ;; esac
        i=$((i + 1))
    done
    # the stock comparison: whatever the tools said, as long as they ended (0 or 1)
    for o in $ORDERS; do
        rcs=$(sum_of "$rdir/img-o$o.txt" tool_rc)
        if [ "$rcs" = 0 ] || [ "$rcs" = 1 ] || [ "$rcs" = 5 ]; then
            stock_compare "$n" "$rdir" "$o" "$R_USER" "$(keyring_of "$R_USER")"
            r_rc=$SC_RC
        else
            r_rc=skipped
        fi
        echo "stock_rc=$r_rc" >> "$rdir/img-o$o.txt"
        pyx stockstats "$rdir/stock-o$o.log" | sed 's/^/stock_/' >> "$rdir/img-o$o.txt" 2>/dev/null
        if [ "$r_rc" != 0 ]; then rc=1; [ "$worst" -ne 0 ] || worst=1; fi
        cp "$rdir/stock-o$o.log" "$imgdir/stock-o$o.log" 2>/dev/null
    done
    drop_images "$n" || rc=1
    # what the run proved
    local t_s=0 t_c=0 t_f=0 t_rep=0
    for o in $ORDERS; do
        local f="$rdir/img-o$o.txt" ops d s c sf g ts tc tf
        ops=$(sum_of "$f" r_ops); d=$(sum_of "$f" r_diffs); g=$(sum_of "$f" s_max_gap_ms)
        s=$(sum_of "$f" stock_conns_secure); c=$(sum_of "$f" stock_conns_crc); sf=$(sum_of "$f" stock_sec_failures)
        ts=$(sum_of "$f" s_conns_secure); tc=$(sum_of "$f" s_conns_crc); tf=$(sum_of "$f" s_sec_failures)
        [ -n "$ops" ] && { [ -z "$ops_min" ] || [ "$ops" -lt "$ops_min" ]; } && ops_min=$ops
        [ -n "$ops" ] || ops_min=0
        [ "${d:-0}" = 0 ] || { rc=1; [ "$worst" -ne 0 ] || worst=1; }
        # a tool that ended with status 0 has printed its result record: without one the counts above are empty and "zero differences" means nothing
        if [ "$(sum_of "$f" tool_rc)" = 0 ] && [ "$(sum_of "$f" have_result)" != 1 ]; then
            echo "FAIL  the order $o tool ended with status 0 but printed no result record" >&2; rc=1; [ "$worst" -ne 0 ] || worst=1
        fi
        # the tool's own connections over the whole random phase (the stock comparison below counts only its own)
        if [ -n "$ts" ] && [ -n "$tc" ]; then t_rep=$((t_rep + 1)); t_s=$((t_s + ts)); t_c=$((t_c + tc)); fi
        [ -z "$tf" ] || t_f=$((t_f + tf))
        [ -z "$g" ] || [ "$g" -le "$maxgap" ] || maxgap=$g
        [ -z "$s" ] || conns_s=$((conns_s + s)); [ -z "$c" ] || conns_c=$((conns_c + c)); [ -z "$sf" ] || secf=$((secf + sf))
    done
    ATT_OPS_MIN=${ops_min:-0}; ATT_MAXGAP=$maxgap; ATT_CONNS_S=$conns_s; ATT_CONNS_C=$conns_c; ATT_SECF=$secf
    # a run that was cut short by a failure is a failure, whatever else
    if [ "$rc" -ne 0 ]; then ATT_STATUS="failed"; [ "$worst" -ne 0 ] || worst=1; return "$worst"; fi
    # the mode that was asked for, counted on the connections of the three tools first: the whole random phase, every redial after a killed daemon
    # included (a downgrade or a failed tag would show there), and a tool that does not report its counters is not evidence for a mode
    if [ "$t_rep" -ne 3 ]; then
        ATT_STATUS="failed"; echo "FAIL  only $t_rep of 3 tools reported conns_secure / conns_crc: the mode of the random phase is not shown" >&2; return 1
    fi
    if [ "$R_MODE" = secure ]; then
        if [ "$t_c" -ne 0 ] || [ "$t_s" -eq 0 ] || [ "$t_f" -ne 0 ]; then ATT_STATUS="failed"; echo "FAIL  secure run, but the tools counted conns_secure=$t_s conns_crc=$t_c sec_failures=$t_f" >&2; return 1; fi
    else
        if [ "$t_s" -ne 0 ] || [ "$t_c" -eq 0 ] || [ "$t_f" -ne 0 ]; then ATT_STATUS="failed"; echo "FAIL  crc run, but the tools counted conns_secure=$t_s conns_crc=$t_c sec_failures=$t_f" >&2; return 1; fi
    fi
    # and on the stock comparison's connections
    if [ "$R_MODE" = secure ]; then
        if [ "$conns_c" -ne 0 ] || [ "$conns_s" -eq 0 ] || [ "$secf" -ne 0 ]; then ATT_STATUS="failed"; echo "FAIL  secure run, but conns_secure=$conns_s conns_crc=$conns_c sec_failures=$secf" >&2; return 1; fi
    else
        if [ "$conns_s" -ne 0 ] || [ "$conns_c" -eq 0 ]; then ATT_STATUS="failed"; echo "FAIL  crc run, but conns_secure=$conns_s conns_crc=$conns_c" >&2; return 1; fi
    fi
    # enough evidence?
    ATT_FAULTS_OK=1
    if [ "$nofaults" -eq 0 ]; then
        local sm c_ko c_km c_io c_up
        sm=$INJ_SUMMARY
        c_ko=$(echo "$sm" | sed -n 's/.* osdkill=\([0-9]*\).*/\1/p'); c_km=$(echo "$sm" | sed -n 's/.* mon_restarts=\([0-9]*\).*/\1/p')
        c_io=$(echo "$sm" | sed -n 's/.* outin=\([0-9]*\).*/\1/p'); c_up=$(echo "$sm" | sed -n 's/.* upmap=\([0-9]*\).*/\1/p')
        if [ "${c_ko:-0}" -lt "$ko" ] || [ "${c_km:-0}" -lt "$km" ] || [ "${c_io:-0}" -lt "$kio" ] || [ "${c_up:-0}" -lt "$ku" ]; then
            ATT_FAULTS_OK=0
            echo "exit-run: too few faults: osdkill ${c_ko:-0}/$ko monitor restarts ${c_km:-0}/$km out-in ${c_io:-0}/$kio upmap ${c_up:-0}/$ku" >&2
            ATT_FAULTS_TEXT="${c_ko:-0} OSD kills, ${c_km:-0} monitor restarts, ${c_io:-0} out-in, ${c_up:-0} upmap"
        fi
    fi
    if [ "$ATT_OPS_MIN" -lt "$min_ops" ]; then echo "exit-run: too few operations: the least image did $ATT_OPS_MIN of $min_ops" >&2; fi
    local ops_ok=1 faults_ok=1
    [ "$ATT_OPS_MIN" -ge "$min_ops" ] || [ "$ops_short_ok" -eq 1 ] || ops_ok=0
    [ "$ATT_FAULTS_OK" -eq 1 ] || [ "$faults_short_ok" -eq 1 ] || faults_ok=0
    if [ "$ops_ok" -eq 1 ] && [ "$faults_ok" -eq 1 ] && { [ "$ATT_OPS_MIN" -lt "$min_ops" ] || [ "$ATT_FAULTS_OK" -eq 0 ]; }; then
        # accepted by the flags: what was short is named in the report
        ATT_NOTE=""
        if [ "$ATT_OPS_MIN" -lt "$min_ops" ]; then
            ATT_NOTE="operations below the minimum of $min_ops (accepted):"
            for o in $ORDERS; do
                local oo; oo=$(sum_of "$rdir/img-o$o.txt" r_ops)
                [ "${oo:-0}" -ge "$min_ops" ] || ATT_NOTE="$ATT_NOTE o$o ${oo:-0};"
            done
        fi
        [ "$ATT_FAULTS_OK" -eq 1 ] || ATT_NOTE="${ATT_NOTE:+$ATT_NOTE }faults below the deck of $ko OSD kills / $km monitor restarts / $kio out-in / $ku upmap (accepted): reached ${ATT_FAULTS_TEXT}"
        ATT_STATUS="pass"; return 0
    fi
    if [ "$ATT_OPS_MIN" -lt "$min_ops" ] || [ "$ATT_FAULTS_OK" -eq 0 ]; then ATT_STATUS="short"; return 5; fi
    ATT_STATUS="pass"
    return 0
}

# a short run of the same three tools on throw-away images, no faults: the ops/s of the slowest image decides the length
calibrate() { # <run> <rdir> <seed base> -> sets CAL_RATE (ops per second, integer, at least 1)
    local n=$1 rdir=$2 sbase=$3 o rcs ops min="" cdir
    cdir="$rdir/calibration"
    mkdir -p "$cdir"
    CAL_RATE=0
    IMG_SUFFIX="c"
    make_images "$n" || { drop_images "$n" || true; return 3; }
    start_tools "$n" "$cdir" cal random interleave "$calib" "$sbase"
    wait_tools "$cdir" cal "$SECONDS" || { drop_images "$n"; return 3; }
    for o in $ORDERS; do
        rcs=$(cat "$cdir/cal-o$o.rc" 2>/dev/null || echo 255)
        ops=$(pyx toolsum "$cdir/cal-o$o.log" | sed -n 's/^r_ops=//p')
        echo "calibration o$o: exit $rcs, ${ops:-?} operations in $calib s"
        [ "$rcs" = 0 ] && [ -n "$ops" ] || { drop_images "$n"; return 3; }
        [ -n "$min" ] && [ "$ops" -ge "$min" ] || min=$ops
    done
    drop_images "$n" || return 3
    CAL_RATE=$(( min / calib ))
    [ "$CAL_RATE" -ge 1 ] || CAL_RATE=1
    return 0
}

# plan_time <rate>: the random-phase time of a run, seconds: the largest of --hours, the operations at a rate cut by two fifths, and the injector's deck
plan_time() {
    local r=$1 t_h t_ops t_deck t
    t_h=$(secs_of_hours); t_deck=$(deck_secs)
    t_ops=$(( (min_ops * 5 + r * 3 - 1) / (r * 3) ))   # the rate cut by two fifths: what the faults and the scans of a long run cost
    t=$t_h; [ "$t_ops" -le "$t" ] || t=$t_ops; [ "$nofaults" -eq 1 ] || [ "$t_deck" -le "$t" ] || t=$t_deck
    PLAN_NOTE="hours ${t_h}s, operations at $r ops/s -40% ${t_ops}s, deck ${t_deck}s"
    local cap=$((max_hours * 3600))
    if [ "$t" -gt "$cap" ]; then PLAN_NOTE="$PLAN_NOTE; capped at ${cap}s (--max-hours)"; t=$cap; fi
    PLAN_T=$t
}

write_meta() { # <rdir> <key=value>...
    local f=$1/meta.txt k; shift
    for k in "$@"; do echo "$k" >> "$f"; done
}

# one run of the five; sets RUN_RC (the worst exit status of its attempts)
do_run() { # <n>
    local n=$1 rdir att tsec t_start sbase notes="" rc=0 status final_status="fail"
    CUR_RUN=$n
    run_spec "$n"
    # nothing of the run before may show in this run's report or growth arithmetic (a run that fails before its first attempt reports what it has)
    ATT_OPS_MIN=0; ATT_FAULTS_OK=1; ATT_STATUS=""; ATT_NOTE=""; ATT_FAULTS_TEXT=""; ATT_MAXGAP=""; ATT_CONNS_S=""; ATT_CONNS_C=""; ATT_SECF=""; ATT_WARN=""
    INJ_RC=""; INJ_SUMMARY=""
    rdir="$WORK/run-$n"; rm -rf "$rdir"; mkdir -p "$rdir"
    : > "$rdir/meta.txt"
    sbase=$(( ${seed:-$$} + n * 100 ))
    info "==== run $n: mode $R_MODE, core key $R_KEY (client.$R_USER)$([ "$R_FORCED" = 1 ] && echo ", the cluster forced to secure"), seed $sbase ===="
    t_start=$SECONDS
    RUN_RC=0
    if [ "$R_FORCED" = 1 ]; then
        info "run $n: forcing the cluster to secure (ms_mon_service_mode, ms_service_mode), restarting the monitor and the OSDs"
        if ! force_secure; then
            echo "FAIL  could not force the cluster to secure" >&2
            RUN_RC=3; notes="could not force the cluster to secure"
        fi
    fi
    if [ "$RUN_RC" -eq 0 ]; then
        if [ -n "$time_sec" ]; then
            tsec=$time_sec; PLAN_NOTE="fixed by --time-sec"
        else
            if [ -n "$rate" ]; then CAL_RATE=$rate
            else
                info "run $n: calibration, $calib s on throw-away images"
                if ! calibrate "$n" "$rdir" "$sbase"; then
                    echo "FAIL  the calibration run failed (see $rdir/calibration)" >&2
                    RUN_RC=3; notes="the calibration failed"
                fi
            fi
            [ "$RUN_RC" -ne 0 ] || { plan_time "$CAL_RATE"; tsec=$PLAN_T; }
        fi
        [ "$RUN_RC" -ne 0 ] || info "run $n: random phase $tsec s (${PLAN_NOTE})"
    fi
    att=0
    final_status="fail"
    if [ "$RUN_RC" -eq 0 ]; then
        while :; do
            att=$((att + 1))
            if [ "$att" -gt 1 ]; then
                # fresh images, a longer time: the larger of a quarter more and what the operations (or the faults) that were missing need
                local grow=$(( tsec * 5 / 4 ))
                if [ "$ATT_OPS_MIN" -gt 0 ] && [ "$ATT_OPS_MIN" -lt "$min_ops" ]; then
                    local g2=$(( tsec * min_ops * 5 / 4 / ATT_OPS_MIN )); [ "$g2" -le "$grow" ] || grow=$g2
                fi
                [ "$ATT_FAULTS_OK" -eq 1 ] || { local g3=$(( tsec * 3 / 2 )); [ "$g3" -le "$grow" ] || grow=$g3; }
                [ "$grow" -le $((max_hours * 3600 * 2)) ] || grow=$((max_hours * 3600 * 2))
                info "run $n: attempt $((att - 1)) was short ($ATT_OPS_MIN operations on the least image, faults complete: $ATT_FAULTS_OK): attempt $att with ${grow}s instead of ${tsec}s"
                tsec=$grow
            fi
            run_attempt "$n" "$rdir" "$tsec" "$att" "$sbase"
            RUN_RC=$?
            [ "$RUN_RC" -eq 5 ] && [ "$att" -lt "$attempts" ] || break
        done
    fi
    # the verdict of the run
    case "$RUN_RC" in
        0) final_status="pass"; [ -z "$ATT_NOTE" ] || notes="${notes:+$notes; }$ATT_NOTE" ;;
        5) final_status="fail"; notes="${notes:+$notes; }too little evidence after $att attempt(s): $ATT_OPS_MIN operations on the least image, faults complete: $ATT_FAULTS_OK"; RUN_RC=1 ;;
        *) final_status="fail"; notes="${notes:+$notes; }${ATT_STATUS:-failed}" ;;
    esac
    # the run's lab: put back and compared (a forced cluster is restored here, before the next run)
    local rest="yes" dmc="quiet" rr=0
    if [ "$R_FORCED" = 1 ] || [ -e "$WORK/stale" ]; then
        restore_modes || { rest="NO (the options or the daemons could not be restored)"; rr=1; }
    fi
    if ! fi_state_compare "$WORK/state.before" "run$n" >> "$rdir/state-compare.log" 2>&1; then
        rest="NO (the state differs from the snapshot: $rdir/state-compare.log)"; rr=1
    fi
    # Ceph's own mclock capacity lines (a restarted OSD benchmarks its disk and stores the result) are not a difference; the compare names them as NOTE lines
    local snotes
    snotes=$(sed -n 's/^NOTE  *//p' "$rdir/state-compare.log" 2>/dev/null | sort -u | tr '\n' ';' | sed 's/;$//; s/;/; /g')
    [ "$rr" -eq 0 ] || { final_status="fail"; [ "$RUN_RC" -ne 0 ] || RUN_RC=1; }
    if ! dmesg_check "$WORK/dmesg.before" >> "$rdir/dmesg.log" 2>&1; then dmc="NEW ERRORS (see $rdir/dmesg.log)"; final_status="fail"; [ "$RUN_RC" -ne 0 ] || RUN_RC=1; fi
    # the tools' own counters, when they report them
    local tc="" o
    for o in $ORDERS; do
        local s c
        s=$(sum_of "$rdir/img-o$o.txt" s_conns_secure); c=$(sum_of "$rdir/img-o$o.txt" s_conns_crc)
        [ -z "$s$c" ] || tc="$tc o$o:conns_secure=${s:-?} conns_crc=${c:-?}"
    done
    tc=${tc# }
    local fsum=""
    fsum=$(cat "$rdir/injector.summary" 2>/dev/null | sed 's/^summary //')
    write_meta "$rdir" "run=$n" "mode=$R_MODE" "key=$R_KEY" "forced=$R_FORCED" "status=$final_status" "t_plan=${tsec:-0}" "elapsed_s=$((SECONDS - t_start))" "attempts=$att" \
        "seed=$sbase" "injector=$fsum" "injector_rc=${INJ_RC:--}" "max_gap_ms=${ATT_MAXGAP:-0}" "stall_ms=$stall_ms" "conns_secure=${ATT_CONNS_S:-?}" "conns_crc=${ATT_CONNS_C:-?}" \
        "sec_failures=${ATT_SECF:-?}" "tool_conns=${tc:-not reported by the tool}" "restored=$rest" "dmesg=$dmc" "notes=$notes" "warn=${ATT_WARN:-}" "state_notes=${snotes:-}"
    mkdir -p "$RESULTS"
    rm -rf "$RESULTS/run-$n"; mkdir -p "$RESULTS/run-$n"
    cp "$rdir"/meta.txt "$rdir"/img-o*.txt "$rdir"/injector.summary "$RESULTS/run-$n/" 2>/dev/null
    cp "$rdir"/fault-events.log "$RESULTS/run-$n/" 2>/dev/null
    info "==== run $n finished: $final_status (exit $RUN_RC) ===="
    return 0
}

# ---- the trap and the main program ----------------------------------------------------------------------------------------------------------------------
on_exit() {
    local rc=$? crc=0 sc=0 dc=0 mc=0
    # a second Ctrl-C, or the SIGTERM that a test harness sends after the SIGINT that reached both of us, must not cut the restore short: from here
    # on the signals are ignored (SIGKILL is the only way out, and the lab is then left for the state comparison of the next start to find)
    trap - EXIT
    trap '' INT TERM HUP
    if [ "$FINAL_RC" -eq 0 ]; then FINAL_RC=$rc; fi
    info "cleaning up: the tools, the injector, the mappings and images, the mode options, the cluster state"
    tools_kill
    for p in "${TOOL_PIDS[@]+"${TOOL_PIDS[@]}"}"; do wait "$p" 2>/dev/null; done
    stop_injector
    cleanup_tracked || crc=1
    if [ -s "$WORK/modes.before" ] || [ -e "$WORK/stale" ]; then restore_modes || mc=1; fi
    if [ -e "$WORK/dmesg.before" ]; then dmesg_check "$WORK/dmesg.before" || dc=1; fi
    if [ -s "$WORK/state.before" ]; then fi_state_compare "$WORK/state.before" after || sc=1; fi
    if [ "$crc" -ne 0 ] || [ "$sc" -ne 0 ] || [ "$dc" -ne 0 ] || [ "$mc" -ne 0 ]; then [ "$FINAL_RC" -ne 0 ] || FINAL_RC=1; fi
    if [ -d "$RESULTS" ]; then
        echo
        echo "==== report ===="
        pyx render "$RESULTS" | tee "$WORK/report.txt"
        [ -z "$report_file" ] || cp "$WORK/report.txt" "$report_file" 2>/dev/null
    fi
    if [ "$keep" != 1 ]; then rm -rf "$TRACK" "$WORK"/export-*.img "$WORK/injector"; fi
    echo "exit-run: finished with exit status $FINAL_RC (cleanup: $([ $crc = 0 ] && echo clean || echo FAILED); modes: $([ $mc = 0 ] && echo original || echo NOT-RESTORED); state: $([ $sc = 0 ] && echo as-before || echo CHANGED); dmesg: $([ $dc = 0 ] && echo quiet || echo ERRORS))"
    exit "$FINAL_RC"
}

report_file=""
main() {
    local r worst=0
    [ -x "$WRKC" ] || die "$WRKC not found: build the harness first (cmake --build, see harness/README.md) or set WR_BUILD_DIR"
    [ -x "$WRRBD" ] || die "$WRRBD not found: build the harness first or set WR_BUILD_DIR"
    [ -r "$INJECTOR" ] || die "$INJECTOR not found"
    command -v python3 >/dev/null || die "python3 is needed"
    command -v rbd >/dev/null || die "the rbd command is needed (run this inside the lab VM)"
    command -v ceph >/dev/null || die "the ceph command is needed (run this inside the lab VM)"
    $SUDO -n true 2>/dev/null || die "passwordless sudo is needed (rbd map, dmesg, systemctl, the tools on /dev/rbdN)"
    for r in $USER_K1 $USER_K2; do
        [ -r "$(keyring_of "$r")" ] || die "no keyring for $r: $(keyring_of "$r") (keep keyrings outside the repository, mode 600)"
    done
    case "$(cd "$KEYDIR" && pwd -P)/" in "$repo"/*) die "the keyring directory $KEYDIR is inside the repository; keep keys outside it" ;; esac
    mkdir -p "$WORK" "$TRACK" || die "cannot create $WORK"
    # The flag of a run that was cut off (SIGKILL, a power cut) while the four options were changed or the daemons were being restarted under them. Deleting
    # it and snapshotting the lab as it is now would make the changed options "the original": the lab would stay forced for good. So: stop, and say how.
    [ ! -e "$WORK/stale" ] || die "$WORK/stale exists: an earlier run was cut off while the cluster ran with changed mode options (or its daemons were being restarted). Check 'ceph config dump | grep ms_' and the daemons, put them back as they were (the original options are in $WORK/modes.before), then delete $WORK/stale. Nothing was changed now."
    fi_write_pylib || die "cannot write to $WORK"
    write_pyx
    report_file=${EX_REPORT:-}
    rm -rf "$RESULTS"; rm -f "$STOPFILE"
    fi_discover || die "cannot read the cluster (ceph fsid, the mon and OSD units; need one monitor and at least 3 OSDs)"
    CEPH osd stat -f json 2>/dev/null | py osdup "$BASE_OSDS" || die "not every OSD is up and in at the start: nothing is changed"
    CEPH pg stat -f json 2>/dev/null | py pgclean >/dev/null || die "the placement groups are not all active+clean at the start: nothing is changed"
    # a leftover of an earlier run would make the "at most 8 images" rule a guess
    if [ -n "$(RBD ls "$POOL" 2>/dev/null | grep -E '^wrtest-' | head -n 1)" ]; then
        info "NOTE: other wrtest-* images exist in the pool: $(RBD ls "$POOL" 2>/dev/null | grep -E '^wrtest-' | head -n 8 | tr '\n' ' ')"
        [ "$(RBD ls "$POOL" 2>/dev/null | grep -Ec '^wrtest-')" -le 4 ] || die "more than 4 wrtest-* images exist already: the lab rule allows 8 at a time and a run needs 3"
    fi
    trap on_exit EXIT
    trap 'FINAL_RC=2; exit 2' INT TERM HUP
    info "snapshot of the cluster state, of the four mode options and of dmesg"
    fi_state_snapshot "$WORK/state.before"
    [ -s "$WORK/state.before" ] || die "cannot read the cluster state (ceph commands failed)"
    modes_snapshot "$WORK/modes.before" || die "cannot read the config database"
    dmesg_snapshot "$WORK/dmesg.before"
    info "runs $runs; per run at least ${hours} h, $min_ops operations per image, the deck $ko OSD kills / $km monitor restarts / $kio out-in / $ku upmap$([ "$nofaults" = 1 ] && echo " (NO faults)")"
    for r in ${runs//,/ }; do
        do_run "$r"
        case "$RUN_RC" in 0) ;; 1) [ "$worst" -eq 4 ] || [ "$worst" -eq 3 ] || worst=1 ;; 3) [ "$worst" -eq 4 ] || worst=3 ;; 4) worst=4 ;; *) [ "$worst" -ne 0 ] || worst=1 ;; esac
        if [ "$RUN_RC" -ne 0 ] && [ "${EX_STOP_ON_FAIL:-1}" = 1 ]; then
            info "run $r failed: the remaining runs are not started (a failure is looked at before more hours are spent)"
            break
        fi
    done
    FINAL_RC=$worst
    return 0
}

# ---- selftest ------------------------------------------------------------------------------------------------------------------------------------
# The whole script against stand-ins for sudo, ceph, systemctl, pkill, pgrep (the injector's python stand-in: a three OSD cluster with a config
# database, daemons that read ms_*_service_mode when they start, and an unclean spell after every change), rbd, dmesg, wr-krbdcmp and wr-rbd, with a
# failure injected at every step of the run that forces the cluster. After each run, a good or a failed one: no image, no mapping, the config database as
# it was, every daemon that was restarted running with the original mode, every OSD up and in, no upmap entry, no tool left running.
er_write_stubs() { # <dir>
    local d=$1
    fi_write_stubs "$d"
    mkdir -p "$d/st/images" "$d/st/maps" "$d/keys"
    echo dummy > "$d/keys/client.winrbd.keyring"; echo dummy > "$d/keys/client.winrbd-aes.keyring"; chmod 600 "$d/keys/"*
    cat > "$d/bin/rbd" <<'STUB'
#!/bin/bash
S=$FI_STUB
cmd=$1; shift
case "$cmd" in
    create) last=${@: -1}; img=${last#*/}; sz=""; prev=""; for a in "$@"; do [ "$prev" = --size ] && sz=$a; prev=$a; done
            case "$sz" in [1-9]*B) ;; *) echo "rbd: the argument for option '--size' is invalid" >&2; exit 22 ;; esac
            [ -e "$S/images/$img" ] && { echo "exists" >&2; exit 17; }; echo "$last" > "$S/images/$img" ;;
    rm) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || { echo "no such image" >&2; exit 2; }
        for m in "$S"/maps/*; do [ -e "$m" ] && [ "$(cat "$m")" = "$img" ] && { echo "image is mapped" >&2; exit 16; }; done
        rm -f "$S/images/$img" ;;
    info) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || exit 2 ;;
    map) last=${@: -1}; img=${last#*/}; [ -e "$S/images/$img" ] || { echo "no such image" >&2; exit 2; }
         n=0; while ! ( set -o noclobber; echo "$img" > "$S/maps/rbd$n" ) 2>/dev/null; do n=$((n + 1)); done; echo "/dev/rbd$n" ;;
    unmap) while [ $# -gt 0 ]; do case "$1" in -o) shift 2 ;; *) dev=$1; shift ;; esac; done
           n=${dev#/dev/rbd}; [ -e "$S/maps/rbd$n" ] || { echo "not mapped" >&2; exit 22; }; rm -f "$S/maps/rbd$n" ;;
    ls) for i in "$S"/images/*; do [ -e "$i" ] && basename "$i"; done; exit 0 ;;
    export) dst=${@: -1}; : > "$dst" ;;
    *) echo "stub rbd: unsupported: $cmd $*" >&2; exit 1 ;;
esac
STUB
    printf '#!/bin/bash\ncat "$FI_STUB/dmesg.txt" 2>/dev/null\nexit 0\n' > "$d/bin/dmesg"
    cat > "$d/bin/wr-krbdcmp" <<'STUB'
#!/bin/bash
# a stand-in for the comparison tool: needs its image mapped, runs for min(--time, ER_STUB_SLEEP) seconds, then reports ER_STUB_OPS_PER_S operations per second
[ "${1:-}" != --help ] || { echo "usage: wr-krbdcmp --mon M [--mode crc|secure] [--require-mode secure|crc]"; exit 2; }
img=""; label=""; t=1; mode=""; phase=all
while [ $# -gt 0 ]; do case "$1" in --image) img=$2; shift ;; --label) label=$2; shift ;; --time) t=$2; shift ;; --mode) mode=$2; shift ;; --phase) phase=$2; shift ;; esac; shift; done
grep -qx "$img" "$FI_STUB"/maps/* 2>/dev/null || { echo "@1 error the device of $img is not mapped"; exit 3; }
[ -z "${ER_STUB_DMESG:-}" ] || printf '[ 1.0] %s\n' "$ER_STUB_DMESG" >> "$FI_STUB/dmesg.txt"
echo "@10 plan label=$label seed=1"
slp=$t; [ "$slp" -le "${ER_STUB_SLEEP:-8}" ] || slp=${ER_STUB_SLEEP:-8}
for ((i = 0; i < slp; i++)); do echo "@$((1000 * i)) progress phase=random ops=$((i * ${ER_STUB_OPS_PER_S:-1000})) reads=1 writes=1 discards=0 zeroes=0 flushes=0 core_written=1 krbd_written=1 model_chunks=1 inflight=1"; sleep 1; done
case ",${ER_STUB_TOOL_RC:-}," in *",$label:"*)
    rc=$(echo ",$ER_STUB_TOOL_RC," | sed -n "s/.*,$label:\([0-9]*\),.*/\1/p")
    [ "$rc" != 1 ] || echo "@2000 diff dir=interleave op=7 off=0 len=4096 verdict=core"
    [ "$rc" != 4 ] || echo "@2000 stall a request has had no answer for 190000 ms (limit 180000): hang"
    exit "$rc" ;;
esac
ops=$((t * ${ER_STUB_OPS_PER_S:-1000}))
if [ "$mode" = secure ]; then cs=3; cc=0; else cs=0; cc=3; fi
[ -z "${ER_STUB_TOOL_CONN_WRONG:-}" ] || { cs=2; cc=1; }     # a connection of the other mode among them
conns=" conns_secure=$cs conns_crc=$cc sec_failures=${ER_STUB_TOOL_SECFAIL:-0}"
[ -z "${ER_STUB_TOOL_NOCONNS:-}" ] || conns=""                # a tool that does not report them
echo "@$((slp * 1000)) stats ops_done=$ops ops_resent=3 ops_failed=0 session_resets=2 max_gap_ms=${ER_STUB_GAP_MS:-4321} barrier_violations=0 bad_completions=0 model_chunks=1$conns"
[ -z "${ER_STUB_TOOL_NORESULT:-}" ] || exit 0                # a tool that ends with status 0 and no result record
echo "@$((slp * 1000)) result ok=1 exit=0 diffs=0 transients=0 errors=0 verdict=none ops=$ops reads=$((ops / 2)) writes=$((ops / 4)) discards=$((ops / 8)) zeroes=$((ops / 16)) flushes=$((ops / 16)) refusals=0 edges=100 core_writes=1 krbd_writes=1 core_bytes_written=1048576 krbd_bytes_written=2097152 core_bytes_read=3145728 krbd_bytes_read=4194304 checkpoints=3 scans=4 seed=1 label=$label"
exit 0
STUB
    cat > "$d/bin/wr-rbd" <<'STUB'
#!/bin/bash
mode=crc; req=""
while [ $# -gt 0 ]; do case "$1" in --mode) mode=$2; shift ;; --require-mode) req=$2; shift ;; esac; shift; done
[ -z "${ER_STUB_STOCK_FAIL:-}" ] || { echo "@1 mismatch off=0"; exit 1; }
if [ "$mode" = secure ]; then s=3; c=0; else s=0; c=3; fi
[ -z "${ER_STUB_CONN_WRONG:-}" ] || { s=1; c=2; }
echo "@5 stats conns_secure=$s conns_crc=$c sec_failures=0 accel=0 gcm=portable gcm_ops=0"
case "$req" in
    secure) { [ "$c" = 0 ] && [ "$s" != 0 ]; } || exit 3 ;;
    crc) { [ "$s" = 0 ] && [ "$c" != 0 ]; } || exit 3 ;;
esac
exit 0
STUB
    chmod +x "$d/bin/rbd" "$d/bin/dmesg" "$d/bin/wr-krbdcmp" "$d/bin/wr-rbd"
}

# The scenarios are independent (each has a directory of its own for the stand-in cluster's state and for the work files, and a name tag of its own for
# its images), so they run at the same time, a few at once, and are judged afterwards in order. er_go <dir> <name> [ENV=VALUE ...] -- <args...> launches
# one, er_judge <dir> <name> <label> <expected status: 0 | nonzero | a number> reports it.
er_go() {
    local d=$1 name=$2 envs=() sigs="" killinj=0 e k; shift 2
    # two settings of the scenario are not for the script: SIGS="ready secs:SIG secs:SIG ..." (signals sent to it, each after the given pause; "ready" waits
    # for the script's snapshots) and KILLINJ=1
    # (SIGKILL for the injector as soon as an OSD of the stand-in cluster is down: a fault is then left half done)
    while [ $# -gt 0 ] && [ "$1" != -- ]; do
        case "$1" in SIGS=*) sigs=${1#SIGS=} ;; KILLINJ=1) killinj=1 ;; *) envs+=("$1") ;; esac
        shift
    done
    shift
    local sd="$d/sc-$name"
    mkdir -p "$sd/st/images" "$sd/st/maps" "$sd/work"
    ( env "${envs[@]+"${envs[@]}"}" PATH="$d/bin:$PATH" FI_STUB="$sd/st" WR_LAB_WORK="$sd/work" WR_BUILD_DIR="$d/bin" WR_LAB_KEYRING_DIR="$d/keys" FI_POLL=0 FI_MON_WAIT=3 EX_STATE_WAIT=0 \
          EX_HEARTBEAT=3 EX_WAIT_POLL=1 EX_RETRY_WAIT=0 EX_RESTART_WAIT=30 EX_RECOVERY_MAX=5 EX_INJ_STOP_WAIT=120 EX_NAME_TAG="s$$$(echo "$name" | tr -cd 'a-z0-9')" WR_LAB_SUDO=sudo \
          bash "$SELF" "$@" > "$sd/out" 2>&1 &
      p=$!
      for e in $sigs; do
          if [ "$e" = ready ]; then   # the script has taken its snapshots (so its traps are in place): not before, a signal then is a plain kill
              for ((k = 0; k < 600; k++)); do [ -s "$sd/work/modes.before" ] && break; sleep 0.1; done
              continue
          fi
          sleep "${e%%:*}"; kill -"${e##*:}" "$p" 2>/dev/null
      done
      if [ "$killinj" -eq 1 ]; then
          for ((e = 0; e < 600; e++)); do
              if grep -qx inactive "$sd"/st/osd.*.state 2>/dev/null; then pkill -KILL -f -- "$sd/work/injector.stop"; break; fi
              sleep 0.1
          done
      fi
      wait "$p"; echo $? > "$sd/rc" ) &
    while [ "$(jobs -rp | wc -l)" -ge "${EX_SELFTEST_JOBS:-6}" ]; do wait -n 2>/dev/null || break; done
}

ER_RC=0
er_judge() {
    local d=$1 name=$2 label=$3 want=$4 sd rc why
    sd="$d/sc-$name"
    rc=$(cat "$sd/rc" 2>/dev/null || echo none); ER_RC=$rc
    case "$want" in
        0) [ "$rc" = 0 ] || { st_bad "$label: exit status $rc, expected 0"; sed 's/^/      | /' "$sd/out" | tail -n 25; return 1; } ;;
        nonzero) { [ "$rc" != 0 ] && [ "$rc" != none ]; } || { st_bad "$label: exit status $rc, expected a failure"; sed 's/^/      | /' "$sd/out" | tail -n 25; return 1; } ;;
        *) [ "$rc" = "$want" ] || { st_bad "$label: exit status $rc, expected $want"; sed 's/^/      | /' "$sd/out" | tail -n 25; return 1; } ;;
    esac
    if why=$(st_lab_whole "$sd"); then st_ok "$label: the lab is whole again (exit $rc)"; else st_bad "$label: the lab is NOT restored: $why"; sed 's/^/      | /' "$sd/out" | tail -n 25; fi
    if [ -z "$(ls -A "$sd/st/images" "$sd/st/maps" 2>/dev/null | grep -v ':$')" ]; then st_ok "$label: no image and no mapping left"; else st_bad "$label: left behind: $(ls -A "$sd/st/images" "$sd/st/maps" | tr '\n' ' ')"; fi
    return 0
}

er_has() { # <dir> <name> <text> <description>
    if grep -qF -- "$3" "$1/sc-$2/out"; then st_ok "$4"; else st_bad "$4 (no '$3' in the output)"; fi
}

exit_selftest() {
    local d step k fast good out rc
    command -v python3 >/dev/null || { echo "python3 is needed"; return 77; }
    d=$(mktemp -d "${TMPDIR:-/tmp}/exit-run-selftest.XXXXXX") || { echo "cannot make a temporary directory" >&2; return 2; }
    case "$d" in /*/exit-run-selftest.??????) ;; *) echo "unexpected temporary directory '$d'" >&2; return 2 ;; esac
    echo "selftest with stand-in cluster tools in $d"
    er_write_stubs "$d"
    WORK="$d/lib"; mkdir -p "$WORK"; fi_write_pylib; write_pyx
    # fast: short tools (the faults of the deck will not all fit: such a run ends "short", which the failure scenarios do not mind);
    # good: a run that must pass, its tools long enough for its small deck
    fast="--quick --time-sec 6 --min-ops 100 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 1 --osd-kills 1 --mon-restarts 0 --outins 0 --upmaps 0 --depth 2"
    good="--quick --time-sec 24 --min-ops 100 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 1 --osd-kills 1 --mon-restarts 2 --outins 1 --upmaps 1 --depth 2"

    # launch every scenario that needs the stand-in cluster; the checks that need none are made while they run
    er_go "$d" good ER_STUB_SLEEP=24 -- $good --runs 1,3,5
    er_go "$d" k1 ER_STUB_SLEEP=14 -- $good --time-sec 14 --mon-restarts 0 --upmaps 0 --runs 5 --forced-key k1
    for step in set-mon set-osd restart-mon restart-osd create-o18 map-o22 tool export compare unmap rm; do
        er_go "$d" "step-$step" -- $fast --runs 5 --inject-fail "$step" --attempts 1
    done
    er_go "$d" waitclean -- $fast --runs 5 --inject-fail wait-clean --attempts 1
    er_go "$d" diff ER_STUB_TOOL_RC=r3-o18:1 -- $fast --runs 3 --attempts 1
    er_go "$d" hang ER_STUB_TOOL_RC=r1-o22:4 -- $fast --runs 1 --attempts 1
    er_go "$d" stockfail ER_STUB_STOCK_FAIL=1 -- $fast --runs 1 --attempts 1
    er_go "$d" wrongconn ER_STUB_CONN_WRONG=1 -- $fast --runs 3 --attempts 1
    er_go "$d" req5 ER_STUB_TOOL_RC=r3-o12:5 -- $fast --runs 3 --attempts 1
    er_go "$d" shortok ER_STUB_OPS_PER_S=10 ER_STUB_SLEEP=8 -- $fast --time-sec 8 --runs 1 --attempts 1 --ops-short-ok
    er_go "$d" fshort ER_STUB_SLEEP=3 -- $fast --time-sec 3 --runs 1 --attempts 1 --short-ok --osd-kills 6 --mon-restarts 0 --outins 0 --upmaps 0
    er_go "$d" fshortno ER_STUB_SLEEP=3 -- $fast --time-sec 3 --runs 1 --attempts 1 --ops-short-ok --osd-kills 6 --mon-restarts 0 --outins 0 --upmaps 0
    er_go "$d" short1 ER_STUB_OPS_PER_S=10 -- $fast --runs 1 --attempts 1
    er_go "$d" short2 ER_STUB_OPS_PER_S=15 ER_STUB_SLEEP=12 -- $fast --time-sec 5 --runs 1 --attempts 2
    er_go "$d" dmesgok "ER_STUB_DMESG=libceph: osd0 (2)10.77.0.10:6808 socket error on write" ER_STUB_SLEEP=3 -- $fast --runs 1 --attempts 1 --time-sec 3 --osd-kills 0 --mon-restarts 0 --outins 0 --upmaps 0 --no-faults --min-ops 100
    er_go "$d" dmesgbad "ER_STUB_DMESG=libceph: bad authentication tag from osd1" ER_STUB_SLEEP=3 -- $fast --runs 1 --attempts 1 --time-sec 3 --no-faults --min-ops 100
    er_go "$d" calib ER_STUB_SLEEP=4 -- --quick --calibrate 3 --hours 0.0005 --min-ops 100 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 1 --osd-kills 1 --mon-restarts 0 \
          --outins 0 --upmaps 0 --runs 1 --depth 2
    # the two classes that are no failure: Ceph's own mclock capacity lines written when OSDs restart (a NOTE), and a recovery that is late but heals (a WARN);
    # and the two that are: the same line plus somebody else's config change, and a fault of the injector that failed
    er_go "$d" mclockok FI_STUB_MCLOCK=1 ER_STUB_SLEEP=12 -- $fast --time-sec 12 --runs 1 --attempts 1
    er_go "$d" mclockbad FI_STUB_MCLOCK=other ER_STUB_SLEEP=12 -- $fast --time-sec 12 --runs 1 --attempts 1
    er_go "$d" lateok FI_STUB_UNCLEAN_SECS=7 ER_STUB_SLEEP=14 -- $fast --time-sec 14 --runs 1 --attempts 1
    er_go "$d" failedfault ER_STUB_SLEEP=8 -- $fast --time-sec 8 --runs 1 --attempts 1 --short-ok --inject-fail kill-osd
    mkdir -p "$d/sc-notwhole/st/images" "$d/sc-notwhole/st/maps" "$d/sc-notwhole/work"; echo 0 > "$d/sc-notwhole/st/osd.2.in"
    er_go "$d" notwhole -- $fast --runs 1
    mkdir -p "$d/sc-stale/st/images" "$d/sc-stale/st/maps" "$d/sc-stale/work"; : > "$d/sc-stale/work/stale"
    er_go "$d" stale -- $fast --runs 5
    er_go "$d" toolconn ER_STUB_TOOL_CONN_WRONG=1 -- $fast --runs 3 --attempts 1
    er_go "$d" toolconncrc ER_STUB_TOOL_CONN_WRONG=1 -- $fast --runs 1 --attempts 1
    er_go "$d" toolsecfail ER_STUB_TOOL_SECFAIL=2 -- $fast --runs 3 --attempts 1
    er_go "$d" noconns ER_STUB_TOOL_NOCONNS=1 -- $fast --runs 3 --attempts 1
    er_go "$d" noresult ER_STUB_TOOL_NORESULT=1 -- $fast --runs 1 --attempts 1
    # signals: the first stops the run, the ones after it (a second Ctrl-C, the SIGTERM a test harness sends after the SIGINT) arrive while the lab is being put back
    er_go "$d" sigs ER_STUB_SLEEP=40 "SIGS=ready 4:TERM 1:TERM 1:INT 1:HUP" -- --quick --time-sec 40 --min-ops 100 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 3 --osd-kills 3 --mon-restarts 2 --outins 2 \
          --upmaps 1 --depth 2 --runs 5 --attempts 1
    # the injector is killed in the middle of a fault (an OSD stopped): the script puts it back itself
    er_go "$d" killinj ER_STUB_SLEEP=40 KILLINJ=1 -- --quick --time-sec 40 --min-ops 100 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 30 --osd-kills 3 --mon-restarts 0 --outins 0 \
          --upmaps 0 --depth 2 --runs 1 --attempts 1

    # 1. arithmetic: the time of a run is the largest of three, capped
    hours=2; min_ops=500000; max_hours=8; nofaults=0; ko=20; km=10; kio=10; ku=5; min_gap=90; max_gap=300; initial=60
    plan_time 100
    [ "$PLAN_T" -eq "$(deck_secs)" ] && [ "$PLAN_T" -gt 7200 ] && st_ok "plan: the injector's deck lengthens a 2 hour run to $PLAN_T s" || st_bad "plan: at 100 ops/s the deck (about 3 h) should set the length, got $PLAN_T"
    plan_time 30
    [ "$PLAN_T" -eq 27778 ] && st_ok "plan: 30 ops/s needs 500,000 operations at 18 ops/s: 27778 s" || st_bad "plan: 30 ops/s gave $PLAN_T s, expected 27778"
    plan_time 10
    [ "$PLAN_T" -eq 28800 ] && st_ok "plan: a slow day is capped at --max-hours (28800 s)" || st_bad "plan: 10 ops/s gave $PLAN_T s, expected the cap 28800"
    hours=2; min_ops=1000; nofaults=1; plan_time 1000
    [ "$PLAN_T" -eq 7200 ] && st_ok "plan: with enough ops/s and no faults the 2 hours stand" || st_bad "plan: gave $PLAN_T s, expected 7200"

    # 2. the plan printed, no cluster
    out=$(PATH="$d/empty:/usr/bin:/bin" bash "$SELF" --dry-run --runs 3,5 2>&1); rc=$?
    case "$out" in
        *"run 3: mode secure"*"wrtest-ex-<pid>-r3-o12: 67108864 bytes"*"run 5: mode secure"*"cluster forced to secure"*"wrtest-ex-<pid>-r5-o22: 2145910784 bytes"*)
            [ "$rc" -eq 0 ] && st_ok "dry run: prints the three images of each run and the forced cluster of run 5" || st_bad "dry run: exit $rc" ;;
        *) st_bad "dry run: unexpected output: $out" ;;
    esac
    out=$(PATH="$d/empty:/usr/bin:/bin" bash "$SELF" --dry-run --runs 1 2>&1)
    case "$out" in *"1073545216 bytes"*) st_ok "dry run: order 18 is 1 GiB - 192 KiB (a partial last object of 64 KiB)" ;; *) st_bad "dry run: order 18 size: $out" ;; esac
    # argument checks (the script stops before it reaches a cluster)
    for k in "--runs 6" "--runs 0" "--hours x" "--min-gap 0" "--forced-key k3" "--attempts 0" "--depth 0" "--seed x" "--bogus" "--time-sec x" "--calibrate 0" "--rate 0" "--max-hours 0" "--time-sec 0" "--hours 1.2.3" "--hours ." "--stall-ms 0" "--checkpoint 0" "--min-ops 1234567890"; do
        # shellcheck disable=SC2086
        PATH="$d/bin:$PATH" FI_STUB="$d/sc-good/st" WR_LAB_WORK="$d/argwork" WR_BUILD_DIR="$d/bin" WR_LAB_KEYRING_DIR="$d/keys" bash "$SELF" $k > "$d/args.out" 2>&1; rc=$?
        [ "$rc" -eq 2 ] && st_ok "argument check: '$k' is refused with status 2" || st_bad "argument check: '$k' gave status $rc"
    done

    # an option with an empty value is refused (it used to read as zero faults wanted); leading zeros are decimal numbers
    PATH="$d/bin:$PATH" FI_STUB="$d/sc-good/st" WR_LAB_WORK="$d/argwork" WR_BUILD_DIR="$d/bin" WR_LAB_KEYRING_DIR="$d/keys" bash "$SELF" --osd-kills "" > "$d/args.out" 2>&1; rc=$?
    [ "$rc" -eq 2 ] && st_ok "argument check: '--osd-kills' with an empty value is refused with status 2" || st_bad "argument check: an empty --osd-kills gave status $rc"
    out=$(PATH="$d/empty:/usr/bin:/bin" bash "$SELF" --dry-run --runs 1 --min-gap 08 --max-gap 09 --osd-kills 08 --initial-delay 08 2>&1); rc=$?
    [ "$rc" -eq 0 ] && st_ok "argument check: 08 and 09 are decimal numbers" || st_bad "argument check: 08 / 09 gave status $rc: $out"

    # 3. the scenarios, in order
    wait
    er_judge "$d" good "runs 1, 3 and 5" 0
    for k in "RUN 1  crc  core key k2" "RUN 3  secure  core key k2" "RUN 5  secure  core key k2  cluster forced to secure" "status PASS" "differences in all tools: 0" "conns_secure=9 conns_crc=0" \
             "conns_secure=0 conns_crc=9" "of the tools: o12:conns_secure=3 conns_crc=0" "osdkill=" "largest stall: 4321 ms" "lab restored: yes; dmesg: quiet"; do
        er_has "$d" good "$k" "report: has '$k'"
    done
    # --report on the kept results prints the same table
    out=$(bash "$SELF" --report "$d/sc-good/work/results" 2>&1)
    case "$out" in *"RUN 5  secure"*) st_ok "--report: renders the kept results" ;; *) st_bad "--report: $out" ;; esac
    er_judge "$d" k1 "run 5 with --forced-key k1" 0
    er_has "$d" k1 "RUN 5  secure  core key k1" "run 5 --forced-key k1: the report says core key k1"
    for step in set-mon set-osd restart-mon restart-osd create-o18 map-o22 tool export compare unmap rm; do er_judge "$d" "step-$step" "failing step $step (run 5)" nonzero; done
    er_judge "$d" waitclean "failing step wait-clean (the lab does not heal)" nonzero
    er_judge "$d" diff "a difference in the order 18 tool" 1
    er_has "$d" diff "status FAIL" "difference: the run is FAIL in the report"
    er_judge "$d" hang "a hang in the order 22 tool" 4
    er_judge "$d" stockfail "a stock comparison that fails" 1
    er_judge "$d" wrongconn "a secure run with a crc connection" 1
    er_judge "$d" req5 "a tool whose --require-mode was not met (exit 5)" 1
    er_has "$d" req5 "status FAIL" "tool exit 5: the run is FAIL in the report"
    [ -s "$d/sc-req5/work/run-3/stock-o12.log" ] && st_ok "tool exit 5: the stock comparison still ran (the data agreed)" || st_bad "tool exit 5: no stock comparison log"
    er_judge "$d" shortok "too few operations with --ops-short-ok" 0
    er_has "$d" shortok "operations below the minimum of 100 (accepted): o" "--ops-short-ok: the shortfall is named in the report"
    er_judge "$d" fshort "too few faults with --short-ok" 0
    er_has "$d" fshort "faults below the deck of 6 OSD kills" "--short-ok: the fault shortfall and what was reached are in the report"
    er_judge "$d" fshortno "too few faults with only --ops-short-ok" 1
    er_judge "$d" short1 "too few operations, one attempt" 1
    er_has "$d" short1 "too little evidence after 1 attempt" "short run: the notes say too little evidence"
    er_judge "$d" short2 "too few operations, a second attempt with more time" 0
    er_has "$d" short2 "attempt 2 with" "short run: attempt 2 was made with a longer time"
    er_judge "$d" dmesgok "expected kernel client churn (socket error on write) is a note, not a failure" 0
    er_has "$d" dmesgok "expected lines of the kernel client reconnecting" "dmesg: the expected lines are counted and shown"
    er_judge "$d" dmesgbad "a libceph line about a bad authentication tag" 1
    er_has "$d" dmesgbad "FAIL  new libceph / rbd errors in dmesg" "dmesg: the unexpected line fails the run"
    er_judge "$d" mclockok "Ceph's mclock capacity lines written after OSD restarts (the run passes)" 0
    er_has "$d" mclockok "status PASS" "mclock: the run is PASS in the report"
    er_has "$d" mclockok "  NOTE: Ceph wrote osd." "mclock: the report names the lines as a NOTE"
    er_has "$d" mclockok "state: the lab matches the snapshot taken before (after)" "mclock: the final state compare matches"
    er_has "$d" mclockok "  lab restored: yes; dmesg: quiet" "mclock: the lab counts as restored"
    grep -q "^FAIL" "$d/sc-mclockok/out" && st_bad "mclock: a FAIL line in the output" || st_ok "mclock: no FAIL line in the output"
    [ "$(cat "$d/sc-mclockok/rc" 2>/dev/null)" = 0 ] && grep -q osd_mclock_max_capacity "$d/sc-mclockok/st/config.json" 2>/dev/null && st_ok "mclock: the Ceph-written lines are still there (not restored, not removed)" || st_bad "mclock: the lines were touched"
    rc=$(cat "$d/sc-mclockbad/rc" 2>/dev/null)
    if [ "$rc" != 0 ] && [ -n "$rc" ] && grep -q "status FAIL" "$d/sc-mclockbad/out" && grep -q "lab restored: NO" "$d/sc-mclockbad/out" && grep -q "osd_memory_target=1" "$d/sc-mclockbad/out"; then
        st_ok "an mclock line plus another config change: the run FAILS (exit $rc), the other line is shown"
    else st_bad "an mclock line plus another config change: exit $rc"; sed 's/^/      | /' "$d/sc-mclockbad/out" | tail -n 25; fi
    er_judge "$d" lateok "late recoveries that heal (a WARN, no failure)" 0
    er_has "$d" lateok "status PASS" "late: the run is PASS in the report"
    er_has "$d" lateok "  WARN: " "late: the report has a WARN line"
    er_has "$d" lateok "late recoveries (each took longer than the 5 s limit but the cluster healed)" "late: the WARN names the count and the limit"
    grep -qE "WARN: [1-9][0-9]* late recoveries.*the slowest [1-9][0-9]* s past the limit" "$d/sc-lateok/out" && st_ok "late: the WARN names how late the slowest was" || st_bad "late: no lateness in the WARN"
    grep -q "^FAIL" "$d/sc-lateok/out" && st_bad "late: a FAIL line in the output" || st_ok "late: no FAIL line in the output"
    er_judge "$d" failedfault "a fault of the injector that failed" nonzero
    er_has "$d" failedfault "FAIL  the injector counted" "failed fault: the run is failed for it"
    er_has "$d" failedfault "status FAIL" "failed fault: the run is FAIL in the report"
    rc=$(cat "$d/sc-stale/rc" 2>/dev/null)
    if [ "$rc" = 2 ] && grep -qF "stale exists: an earlier run was cut off" "$d/sc-stale/out" && [ ! -e "$d/sc-stale/st/config.json" ]; then st_ok "a leftover stale flag: refused (status 2), nothing changed"; else st_bad "a leftover stale flag: status $rc"; fi
    er_judge "$d" toolconn "a secure run whose tools counted a crc connection" 1
    er_has "$d" toolconn "secure run, but the tools counted" "tool counters: the crc connection of a secure run is a failure"
    er_judge "$d" toolconncrc "a crc run whose tools counted a secure connection" 1
    er_has "$d" toolconncrc "crc run, but the tools counted" "tool counters: the secure connection of a crc run is a failure"
    er_judge "$d" toolsecfail "a secure run whose tools counted secure-mode failures" 1
    er_has "$d" toolsecfail "sec_failures=6" "tool counters: the failures are named"
    er_judge "$d" noconns "tools that do not report their connection counters" 1
    er_has "$d" noconns "tools reported conns_secure" "tool counters: missing counters are a failure, not a pass"
    er_judge "$d" noresult "a tool that ends with status 0 and no result record" 1
    er_has "$d" noresult "printed no result record" "no result record: a failure"
    er_judge "$d" sigs "SIGTERM, then SIGTERM, SIGINT and SIGHUP while the lab is put back" 2
    er_has "$d" sigs "finished with exit status 2 (cleanup: clean; modes: original; state: as-before" "signals: the restore ran to its end (cleanup clean, modes original, state as before)"
    er_judge "$d" killinj "an injector killed in the middle of a fault" nonzero
    er_has "$d" killinj "the injector ended on its own" "killed injector: the run noticed"
    er_judge "$d" calib "calibration" 0
    er_has "$d" calib "calibration o12: exit 0" "calibration: the three tools ran on throw-away images"
    rc=$(cat "$d/sc-notwhole/rc" 2>/dev/null)
    [ "$rc" = 2 ] && [ "$(cat "$d/sc-notwhole/st/osd.2.in")" = 0 ] && [ -z "$(ls -A "$d/sc-notwhole/st/images")" ] && st_ok "a lab with an OSD out: refused (status 2), nothing created or changed" || st_bad "a lab with an OSD out: status $rc"
    case "$d" in /*/exit-run-selftest.??????) rm -rf "$d" ;; esac
    echo
    echo "exit-run selftest: $ST_PASS passed, $ST_FAIL failed"
    [ "$ST_FAIL" -eq 0 ]
}

if [ "$selftest" -eq 1 ]; then
    exit_selftest
    exit $?
fi
main "$@"
