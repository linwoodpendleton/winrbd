#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# fault_inject.sh: the fault injector of the Phase 1 exit run (docs/design/core-architecture.md 40.3). It runs BESIDE a long run (harness/lab/exit-run.sh
# starts it) and hurts the lab cluster, one fault at a time, on a schedule drawn from its own printed seed, then puts the cluster back:
#
#   osdkill    SIGKILL of one OSD daemon (the process the unit runs), the unit held down for a pause of 5 to 60 seconds, then started again
#   monkill    SIGKILL of the monitor daemon, systemd (or this script after 60 s) starts it again
#   monclean   a clean restart of the monitor unit (monkill and monclean are the two halves of "the monitor restarted", half with SIGKILL)
#   outin      `ceph osd out N`, a pause of 10 to 60 seconds, `ceph osd in N` (the placement changes twice)
#   upmap      `ceph osd pg-upmap` of ONE placement group of the pool to its up set rotated by one (its primary moves), a pause, then removed again
#
# The schedule is a deck (at least --osd-kills OSD kills, --mon-restarts monitor restarts (half SIGKILL), --outins out/in pairs and --upmaps upmap
# changes, shuffled by the seed) followed by more faults drawn the same way, so the run never goes quiet while it is still going. A fault starts
# --min-gap to --max-gap seconds (seed drawn) after the START of the previous one, and never before the previous one has recovered (every OSD up and in,
# every PG active+clean, the monitor answering). A recovery that is not complete after --recovery-max seconds is logged as "late" and waited for up to
# three times as long, after which the injector restores what it can and stops with status 3 (the lab is not healing: a person must look). A late
# recovery that DID complete within the three times is a WARN, not a failure: the summary line carries late=<count> and late_max_over_s=<seconds past the
# limit of the slowest> and the exit run's report shows them as a WARN. A fault that failed (failed=<count>, its step did not work) is a failure.
#
# The ceph CLI is not reliable while the lab is being hurt (a monitor that was just restarted, a VM whose disks stall for 20 s), so no injection is failed
# for a command that merely could not reach the cluster. Every ceph call goes through one wrapper (CEPH): a TRANSIENT failure (the rc of `timeout`, "RADOS
# timed out", "error connecting to the cluster", monclient, "no quorum", connection refused / reset, EAGAIN / ETIMEDOUT and the like) is retried with a pause that
# doubles (FI_CLI_BACKOFF 2 s up to FI_CLI_BACKOFF_MAX 15 s) for up to FI_CLI_RETRY_S seconds (default 120) and only then fails the call; an error that waiting does
# not cure (EINVAL, ENOENT, EPERM / EACCES, an unknown command, any text the injector does not know) fails at once. After a monitor restart, and before an
# `osd out` or an upmap, the injector waits (up to FI_QUORUM_WAIT seconds, default 120) until `ceph quorum_status` answers. Every failed attempt is a line in the
# log and in the events file (cli attempt=N rc=R class=... during=<fault number> cmd="ceph ..." stderr: ...), every poll of the wait too; the note of a fault that
# failed carries the last rc, the number of attempts and the stderr. The summary line gains cli_retries (re-runs in all), cli_retry_max_s (the most seconds one call
# spent retrying), cli_recovered (calls that worked after a retry), cli_gave_up (calls that failed after the window or at once), quorum_waits (waits that needed
# more than one poll), quorum_wait_max_s and quorum_gave_up. The polling loops (fi_wait_clean) and the messages of a diagnostic make ONE attempt per call (they are
# their own retry), logged all the same.
#
# NEVER done here: removing or destroying an OSD or the monitor, touching keys or caps, any image, the pool, more than one daemon down at once,
# anything outside the lab VM this script runs in. The only commands that change the cluster are: kill / stop / start / restart of the ceph-<fsid>@mon.*
# and @osd.* units, `ceph osd out|in N`, `ceph osd pg-upmap PG ...` and `ceph osd rm-pg-upmap PG` (only for a PG this script gave an entry).
#
# EXIT trap (also after an interrupt or a failing step): every daemon unit running, every OSD in, the upmap entries this script added removed, the
# cluster clean again, and the state compared with the snapshot taken before the first fault (health checks, OSD tree and flags, upmaps, config
# database, pools, daemons). Exit status 3 when the restore is incomplete or the state differs. The state compare ignores ONE thing: config lines
# osd_mclock_max_capacity_iops_hdd / _ssd that Ceph itself added or changed (its own disk benchmark after an OSD restart); they are noted ("NOTE ...") and
# left in place, never restored or removed (see fi_state_compare).
#
# Usage (inside the lab VM, a user with passwordless sudo):
#   fault_inject.sh [--seed S] [--stop-file F] [--run-for SEC] [--events FILE] [--summary FILE]
#                   [--min-gap 90] [--max-gap 300] [--osd-kills 20] [--mon-restarts 10] [--outins 10] [--upmaps 5]
#                   [--initial-delay SEC] [--recovery-max 600] [--pause-cap SEC] [--only osdkill,monkill,monclean,outin,upmap]
#   fault_inject.sh --dry-run          print the schedule and what each fault would run; no cluster needed, nothing is changed
#   fault_inject.sh --selftest         run the injector against stand-in ceph / systemctl / pkill commands, with a failure injected at every step:
#                                      the restore must still run (no lab needed; the ctest faultinject.selftest)
#
#   --seed S         the schedule's seed (default: random, printed first; the same seed on the same counts gives the same plan)
#   --stop-file F    stop (after the fault in progress has been undone) when this file exists; SIGTERM / SIGINT do the same
#   --run-for SEC    stop after this many seconds (default: until the stop file or a signal)
#   --events FILE    one "fault ..." line per fault, appended (default $WORK/fault-events.log); --summary FILE the totals line at the end
#   --pause-cap SEC  never pause longer than this (quick runs and the selftest)
#   --inject-fail S  (selftest) make the step S fail: kill-osd, stop-osd, start-osd, kill-mon, restart-mon, start-mon, osd-out, osd-in, upmap-set,
#                    upmap-rm, wait-clean; a comma separated list is allowed
#
# Environment: WR_LAB_POOL (winrbd), WR_LAB_WORK (~/w/exit-run-work), WR_LAB_SUDO (sudo), FI_HEALTH_IGNORE (health checks left out of the state
# comparison: slow-op alerts come and go with the load), FI_STATE_WAIT (seconds to wait for the final state to settle, default 180), FI_POLL (3),
# FI_MON_WAIT (seconds systemd gets to start a SIGKILLed monitor again before this script does, default 60), FI_CLI_RETRY_S (120), FI_CLI_BACKOFF (2),
# FI_CLI_BACKOFF_MAX (15), FI_QUORUM_WAIT (120): the retry window of a ceph call, its first and its longest pause, the wait for the monitor (whole seconds).
#
# Exit status: 0 the injector ran and the lab is as it was; 2 usage or setup problem (nothing was changed); 3 the restore is incomplete, the state
# differs from the snapshot, or the cluster would not recover.

set -u
set -o pipefail

fi_here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
fi_sourced=0
if [ "${BASH_SOURCE[0]}" != "$0" ]; then fi_sourced=1; fi

SUDO=${WR_LAB_SUDO:-sudo}
POOL=${WR_LAB_POOL:-winrbd}
WORK=${WR_LAB_WORK:-$HOME/w/exit-run-work}
HEALTH_IGNORE=${FI_HEALTH_IGNORE:-BLUESTORE_SLOW_OP_ALERT,SLOW_OPS,PG_NOT_DEEP_SCRUBBED,PG_NOT_SCRUBBED,RECENT_CRASH}
STATE_WAIT=${FI_STATE_WAIT:-180}
POLL=${FI_POLL:-3}
MON_WAIT=${FI_MON_WAIT:-60}   # seconds to give systemd to start a SIGKILLed monitor again before this script does
INJECT=${FI_INJECT_FAIL:-}
MODE_OPTS="ms_mon_service_mode ms_service_mode ms_mon_client_mode ms_client_mode"

fi_die()  { echo "fault_inject: error: $*" >&2; exit 2; }
fi_info() { echo "fault_inject: $*" >&2; }

# ---- the commands, as the rest of the script calls them (the selftest puts stand-ins first in PATH) -------------------------------------------
RBD()    { $SUDO rbd "$@"; }
SYSCTL() { $SUDO systemctl "$@"; }

# ---- the ONE way the injector (and exit-run.sh, which sources this file) runs the ceph CLI --------------------------------------------------------
# CEPH1 is one attempt. CEPH is the wrapper everything calls: a transient failure (the CLI cannot reach a monitor or has no quorum: a monitor that was
# just restarted, or a lab VM whose disks stalled for 20 s) is retried with a growing pause for up to CLI_RETRY_S seconds (default 120), and only then is
# the call a failure; an error that will not go away by waiting (EINVAL, ENOENT, a permission error, an unknown command, any text this file does not know)
# fails at once. Every failed attempt is logged with its rc and stderr (injector.log and the events file); a call that was retried is counted in the
# stats file, which the summary line reads (cli_retries=, cli_retry_max_s=, ...). A polling loop that is its own retry (fi_wait_clean) and the
# diagnostics (CEPHQ) run with CLI_CAP=0: one attempt, still logged.
CLI_TIMEOUT_S=60                                  # one attempt, `timeout`
fi_uint() { case "$1" in ''|*[!0-9]*) echo "$2" ;; *) echo $((10#${1:0:9})) ;; esac; }   # a whole number from the environment, or the default
CLI_RETRY_S=$(fi_uint "${FI_CLI_RETRY_S:-}" 120)  # the window in which a transient failure is retried (a new attempt starts only inside it)
CLI_BACKOFF_S=$(fi_uint "${FI_CLI_BACKOFF:-}" 2)  # the first pause; doubled after every failed attempt
CLI_BACKOFF_MAX_S=$(fi_uint "${FI_CLI_BACKOFF_MAX:-}" 15)
QUORUM_WAIT_S=$(fi_uint "${FI_QUORUM_WAIT:-}" 120)   # how long to wait for the monitor to answer again after it was restarted
CLI_STATS=""        # file of one line per retried (or finally failed) call and per quorum wait; set by fi_main; the summary line adds it up
CLI_LAST_ERR=""; CLI_LAST_RC=0; CLI_LAST_TRIES=0   # of the last call that failed (main shell only: the faults put it into their note)
FI_CUR=""           # the number of the fault in progress (for the log lines)

# one text per class, case-insensitive extended regexes. The fatal list is read first: "Error EINVAL: ... timed out" is a wrong command, not a slow cluster.
FI_CLI_FATAL_RE='Error E(INVAL|NOENT|PERM|ACCES|EXIST|NOTSUP|OPNOTSUPP|RANGE|NODEV|NOSYS|DOM|NOTEMPTY|NOSPC)|permission denied|access denied|unrecognized (command|option|arguments)|unknown command|command not found|permission error|\[errno (1|2|13|22)\]|no such file or directory|^usage:'
FI_CLI_TRANSIENT_RE='timed out|timeout|no quorum|quorum|error connecting to the cluster|monclient|connection (refused|reset|closed|lost|aborted)|connect(ion)? (failed|error)|(unable|could not|cannot|can.t) (to )?(get|connect|reach)|broken pipe|temporarily unavailable|try again|try later|hunting|service unavailable|ECONN(REFUSED|RESET|ABORTED)|ETIMEDOUT|EAGAIN|EINTR|ENOTCONN|EHOSTUNREACH|ENETUNREACH|Error E(AGAIN|TIMEDOUT|NOTCONN|CONNREFUSED|CONNRESET|HOSTUNREACH|INTR)|\[errno (4|11|32|104|110|111|113)\]'

# fi_cli_class <rc> <stderr file>: "transient" or "non-transient". The rc of `timeout` (124) is always transient; an error text that is in neither list is non-transient
# (it fails at once with its text in the log, so the list can learn it; a silent retry loop on a real bug would hide it for two minutes per call).
fi_cli_class() {
    local rc=$1 f=$2
    if grep -Eiq "$FI_CLI_FATAL_RE" "$f" 2>/dev/null; then echo non-transient; return 0; fi
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then echo transient; return 0; fi
    if grep -Eiq "$FI_CLI_TRANSIENT_RE" "$f" 2>/dev/null; then echo transient; return 0; fi
    echo non-transient
}

# fi_cli_log <text>: one line to the injector's stderr (fd 8 is the stderr of fi_main: a caller's 2>/dev/null on the ceph call must not swallow it) and to
# the events file. No ' fault n=' in it: exit-run.sh counts those lines as faults.
fi_cli_log() {
    local line
    line="$(date +%s) +$((SECONDS - T0))s $*"
    { echo "fault_inject: $*" >&8; } 2>/dev/null || echo "fault_inject: $*" >&2
    [ -z "$EVENTS" ] || echo "$line" >> "$EVENTS"
}

# fi_oneline <file> [max chars]: the first 300 characters of a file as one line of printable text
fi_redact() { sed -E 's/AQ[A-Za-z0-9+\/]{30,}={0,2}/<key removed>/g'; }   # a cephx key (base64, starts with AQ) must never reach a log, whatever the CLI printed
fi_oneline() { head -c 4096 "$1" 2>/dev/null | fi_redact | head -c "${2:-300}" | tr '\n\t' '  ' | tr -cd '[:print:]'; }   # redact first: a cut key would be a partial key

fi_cli_stat() { [ -z "$CLI_STATS" ] || echo "$*" >> "$CLI_STATS" 2>/dev/null; return 0; }   # a line of the stats file; a failing write is no reason to stop

CEPH1() { $SUDO timeout -k 10 "$CLI_TIMEOUT_S" ceph --connect-timeout 10 "$@"; }   # one attempt

CEPH() {
    local d="$WORK"
    [ -d "$d" ] || d=${TMPDIR:-/tmp}
    local out="$d/.fi-cli.${BASHPID:-$$}.out" err="$d/.fi-cli.${BASHPID:-$$}.err"
    local win=${CLI_CAP:-$CLI_RETRY_S} back=$CLI_BACKOFF_S start=$SECONDS tries=0 rc cls el sl last_err
    local cmd="ceph $*"
    cmd=${cmd:0:160}
    : > "$out"; : > "$err"
    while :; do
        tries=$((tries + 1))
        CEPH1 "$@" > "$out" 2> "$err" < /dev/null; rc=$?
        [ "$rc" -ne 0 ] || break
        cls=$(fi_cli_class "$rc" "$err")
        fi_cli_log "cli attempt=$tries rc=$rc class=$cls${FI_CUR:+ during=$FI_CUR} cmd=\"$cmd\" stderr: $(fi_oneline "$err")"
        [ "$cls" = transient ] || break
        el=$((SECONDS - start))
        [ "$el" -lt "$win" ] || break
        sl=$back
        [ $((el + sl)) -le "$win" ] || sl=$((win - el))
        [ "$sl" -ge 1 ] || sl=1
        sleep "$sl"
        back=$((back * 2))
        [ "$back" -le "$CLI_BACKOFF_MAX_S" ] || back=$CLI_BACKOFF_MAX_S
        [ "$back" -ge 1 ] || back=1
    done
    el=$((SECONDS - start))
    cat "$out"
    cat "$err" >&2
    last_err=$(cat "$err" 2>/dev/null)
    rm -f "$out" "$err"
    if [ "$rc" -eq 0 ]; then
        if [ "$tries" -gt 1 ]; then
            fi_cli_log "cli recovered after $((tries - 1)) retries in ${el}s${FI_CUR:+ during=$FI_CUR} cmd=\"$cmd\""
            fi_cli_stat "cli $((tries - 1)) $el ok"
        fi
    else
        if [ "$tries" -gt 1 ] || [ "$win" -gt 0 ]; then
            fi_cli_log "cli gave up after $tries attempts in ${el}s rc=$rc${FI_CUR:+ during=$FI_CUR} cmd=\"$cmd\""
            fi_cli_stat "cli $((tries - 1)) $el fail"
        fi
        CLI_LAST_RC=$rc; CLI_LAST_TRIES=$tries; CLI_LAST_ERR=$last_err
    fi
    return "$rc"
}
CEPHQ() { local CLI_CAP=0; CEPH "$@"; }   # one attempt: for the diagnostics of a message and for the polls

# fi_cli_note <text>: text plus what the last failed ceph call said (rc, attempts, stderr), one line, for the note of a failed fault
fi_cli_note() {
    local t=$1 e
    if [ -n "$CLI_LAST_ERR" ] || [ "$CLI_LAST_RC" -ne 0 ]; then
        e=$(printf '%s' "$CLI_LAST_ERR" | head -c 4096 | fi_redact | head -c 160 | tr '\n\t' '  ' | tr -cd '[:print:]')
        t="$t (rc=$CLI_LAST_RC after $CLI_LAST_TRIES attempts: ${e:-no stderr})"
    fi
    printf '%s' "$t"
}

fi_inject() { case ",$INJECT," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }   # INJECT is one step name or a comma separated list

# fi_step <name> <command...>: run a command of a fault; a step named by --inject-fail fails without running (what the selftest uses).
fi_step() {
    local name=$1; shift
    CLI_LAST_ERR=""; CLI_LAST_RC=0; CLI_LAST_TRIES=0
    if fi_inject "$name"; then
        echo "fault_inject: injected failure at step '$name'" >&2
        return 99
    fi
    "$@"
}

# ---- one python program for the parts that are better as code than as shell (JSON, the plan) ---------------------------------------------------
PYLIB=""
fi_write_pylib() { # needs $WORK
    mkdir -p "$WORK" || return 1
    PYLIB="$WORK/fi.py"
    cat > "$PYLIB" <<'PY'
import json, random, re, sys

MODE_OPTS = (sys.argv[2].split() if len(sys.argv) > 2 else [])

def load(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default

def who(c):
    return c.get("section", "") + (("/" + c["mask"]) if c.get("mask") else "")

cmd = sys.argv[1]
if cmd == "modes":      # stdin: config dump -> "name<TAB>who<TAB>value" of the four options, sorted
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    if not isinstance(d, list):
        sys.exit(3)
    rows = sorted("%s\t%s\t%s" % (c.get("name"), who(c), c.get("value")) for c in d if c.get("name") in MODE_OPTS)
    print("\n".join(rows))
elif cmd == "state":    # state <base> <ignore-csv> <eff-file>
    base, ignore, eff = sys.argv[2], set(x for x in sys.argv[3].split(",") if x), sys.argv[4]
    out = []
    h = load(base + ".health", {})
    for code in sorted((h.get("checks") or {}).keys()):
        if code not in ignore:
            out.append("health.check %s" % code)
    for n in sorted((load(base + ".tree", {}).get("nodes") or []), key=lambda n: n.get("id", 0)):
        if n.get("type") == "osd":
            out.append("osd %s status=%s reweight=%s primary_affinity=%s" % (n.get("name"), n.get("status"), n.get("reweight"), n.get("primary_affinity")))
    d = load(base + ".dump", {})
    out.append("osd.flags %s" % ",".join(sorted(d.get("flags_set") or [])))
    for o in sorted((d.get("osds") or []), key=lambda o: o.get("osd", 0)):
        out.append("osd.%s up=%s in=%s weight=%s" % (o.get("osd"), o.get("up"), o.get("in"), o.get("weight")))
    for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries"):
        out.append("%s %s" % (k, json.dumps(d.get(k) or [], sort_keys=True)))
    for c in sorted(load(base + ".config", []), key=lambda c: (c.get("section", ""), c.get("mask", ""), c.get("name", ""))):
        out.append("config %s/%s/%s=%s" % (c.get("section"), c.get("mask"), c.get("name"), c.get("value")))
    try:
        with open(eff) as f:
            for line in sorted(l.rstrip("\n") for l in f if l.strip()):
                out.append("mode.effective " + line)
    except OSError:
        pass
    for p in sorted(load(base + ".pools", []), key=lambda p: p.get("pool_name", "")):
        out.append("pool %s size=%s min_size=%s rule=%s app=%s" % (p.get("pool_name"), p.get("size"), p.get("min_size"), p.get("crush_rule"),
                   ",".join(sorted((p.get("application_metadata") or {}).keys()))))
    for p in sorted(load(base + ".orch", []), key=lambda p: p.get("daemon_name", "")):
        if p.get("daemon_type") in ("mon", "osd", "mgr"):
            out.append("daemon %s status=%s" % (p.get("daemon_name"), p.get("status_desc")))
    print("\n".join(out))
elif cmd == "statediff":    # statediff <before> <after>: classify the differences of two state files. Exit 0 when there is no difference or every one is ignorable.
    # The ONE class that is ignored: a config line whose option name is exactly osd_mclock_max_capacity_iops_hdd or osd_mclock_max_capacity_iops_ssd (section
    # global, osd or osd.<n>; any mask) that is in the "after" file and is new or has another value. Ceph writes those itself (the mclock scheduler's own benchmark of a
    # disk, run after an OSD restarts); they are not a difference the run made. Reported as "NOTE ...". Everything else is a "DIFF ..." line and exit 1,
    # a removed or vanished mclock line included (Ceph never removes them: that would be somebody else's change).
    IGNORE = ("osd_mclock_max_capacity_iops_hdd", "osd_mclock_max_capacity_iops_ssd")
    def rd(path):
        with open(path) as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    def mclock(line):   # -> (key, value) of an ignorable config line, else None; the line is "config <section>/<mask>/<name>=<value>"
        if not line.startswith("config "):
            return None
        key, eq, val = line[len("config "):].partition("=")
        parts = key.split("/")
        if not eq or len(parts) != 3 or parts[2] not in IGNORE:
            return None
        # only the sections Ceph's OSDs write these into (an OSD's own, the osd type, global): the same name under mon / client / mgr is somebody's change
        if not re.fullmatch(r"global|osd|osd\.[0-9]+", parts[0]):
            return None
        return (key, val)
    b, a = rd(sys.argv[2]), rd(sys.argv[3])
    gone = [l for l in b if l not in a]
    came = [l for l in a if l not in b]
    before_mc = dict(x for x in (mclock(l) for l in b) if x)
    after_mc = dict(x for x in (mclock(l) for l in a) if x)
    bad = 0
    for l in came:
        m = mclock(l)
        if m:
            old = before_mc.get(m[0])
            print("NOTE  Ceph wrote %s: %s" % (m[0], ("added, value %s" % m[1]) if old is None else ("changed from %s to %s" % (old, m[1]))))
        else:
            print("DIFF  + " + l)
            bad = 1
    for l in gone:
        m = mclock(l)
        if m and m[0] in after_mc:
            continue    # the other half of a changed value, reported above
        print("DIFF  - " + l)
        bad = 1
    sys.exit(bad)
elif cmd == "pgclean":  # stdin: pg stat json -> exit 0 when there is at least one PG and every one is active+clean (scrubbing is fine)
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    d = d.get("pg_summary", d)
    states = d.get("num_pg_by_state") or []
    bad = re.compile(r"degraded|undersized|peering|stale|down|incomplete|remapped|backfill|recover|unknown|inactive|wait|activating|creating|unfound|inconsistent|snaptrim_error|repair")
    print(" ".join("%s:%s" % (s.get("name"), s.get("num")) for s in states) or "no pgs")
    sys.exit(0 if states and all("active" in s["name"] and "clean" in s["name"] and not bad.search(s["name"]) for s in states) else 1)
elif cmd == "osdup":    # osdup <n>; stdin: osd stat json -> exit 0 when n OSDs exist and all are up and in
    n = int(sys.argv[2])
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    d = d.get("osdmap", d)
    sys.exit(0 if d.get("num_osds") == n and d.get("num_up_osds") == n and d.get("num_in_osds") == n else 1)
elif cmd == "units":    # stdin: systemctl list-units -> mon units first, then OSD units by id
    mons, osds = [], []
    for line in sys.stdin:
        w = line.split()
        if not w:
            continue
        m = re.match(r"^ceph-[0-9a-f-]+@(mon|osd)\.([^.]+(?:\.[^.]+)*?)\.service$", w[0])
        if m and m.group(1) == "mon":
            mons.append(w[0])
        elif m and m.group(2).isdigit():
            osds.append((int(m.group(2)), w[0]))
    print("\n".join(mons + [u for _, u in sorted(osds)]))
elif cmd == "upmaps":   # stdin: osd dump json -> the pgids that have a pg_upmap, pg_upmap_items or pg_upmap_primaries entry, one per line
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    ids = set()
    for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries"):
        for e in d.get(k) or []:
            if isinstance(e, dict) and "pgid" in e:
                ids.add(e["pgid"])
    print("\n".join(sorted(ids)))
elif cmd == "pgrot":    # pgrot <arg>; stdin: pg ls-by-pool json -> "pgid a b c": one PG picked by arg, its up set rotated by one (its primary moves)
    arg = int(sys.argv[2])
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    rows = []
    for s in (d.get("pg_stats", []) if isinstance(d, dict) else d):
        up = s.get("up", [])
        if len(up) > 1:
            rows.append((s["pgid"], up[1:] + up[:1]))
    rows.sort()
    if not rows:
        sys.exit(1)
    pg, rot = rows[arg % len(rows)]
    print(pg, " ".join(str(x) for x in rot))
elif cmd == "plan":     # plan seed osd_kills mon_restarts outins upmaps min_gap max_gap pause_cap extra -> "idx kind gap pause arg", the deck then extras
    seed, ko, km, kio, ku, g0, g1, cap, extra = [int(x) for x in sys.argv[2:11]]
    r = random.Random(seed)
    deck = ["osdkill"] * ko + ["monkill"] * (km // 2) + ["monclean"] * (km - km // 2) + ["outin"] * kio + ["upmap"] * ku
    r.shuffle(deck)
    pool = list(deck) or ["osdkill"]
    items = deck + [r.choice(pool) for _ in range(extra)]
    for i, k in enumerate(items):
        gap = r.randint(g0, g1)
        pause = {"osdkill": (5, 60), "outin": (10, 60), "upmap": (10, 40)}.get(k)
        p = r.randint(*pause) if pause else 0
        if cap and p > cap:
            p = cap
        print(i + 1, k, gap, p, r.randint(0, 2 ** 31 - 1))
PY
}
py() { python3 -I "$PYLIB" "$@"; }

# ---- the cluster: what exists, what state it is in ---------------------------------------------------------------------------------------------
FSID=""; BASE_OSDS=0; OSD_IDS=(); MON_UNITS=(); OSD_UNITS=()
PRE_UPMAP=""

fi_discover() { # sets FSID, OSD_IDS, MON_UNITS, OSD_UNITS, BASE_OSDS, PRE_UPMAP; 1 when the cluster cannot say
    local u n units
    FSID=$(CEPH fsid 2>/dev/null) || FSID=""
    [ -n "$FSID" ] || return 1
    units=$(SYSCTL list-units --type=service --all --no-legend --plain 'ceph-*@mon.*.service' 'ceph-*@osd.*.service' 2>/dev/null | py units) || return 1
    MON_UNITS=(); OSD_UNITS=(); OSD_IDS=()
    for u in $units; do
        case "$u" in
            ceph-"$FSID"@mon.*) MON_UNITS+=("$u") ;;
            ceph-"$FSID"@osd.*) OSD_UNITS+=("$u"); n=${u#*@osd.}; OSD_IDS+=("${n%.service}") ;;
        esac
    done
    BASE_OSDS=${#OSD_IDS[@]}
    [ "${#MON_UNITS[@]}" -ge 1 ] && [ "$BASE_OSDS" -ge 3 ] || return 1
    PRE_UPMAP=" $(CEPH osd dump -f json 2>/dev/null | py upmaps 2>/dev/null | tr '\n' ' ')"
    return 0
}

fi_osd_unit() { echo "ceph-$FSID@osd.$1.service"; }

# wait_clean <seconds>: every OSD up and in, every PG active+clean, on two polls in a row (the manager's PG statistics lag the monitor's OSD map by a
# few seconds: one clean report right after a restart can still be the one from before it)
fi_wait_clean() { # <seconds> [stoppable]: with a second argument a stop request ends the wait early (status 2); the restore never passes it
    local t=${1:-300} stoppable=${2:-} end good=0 CLI_CAP=0   # CLI_CAP=0: this loop is its own retry, one attempt per poll
    if fi_inject wait-clean; then echo "fault_inject: injected failure at step 'wait-clean'" >&2; return 99; fi
    end=$((SECONDS + t))
    while :; do
        if CEPH osd stat -f json 2>/dev/null | py osdup "$BASE_OSDS" && CEPH pg stat -f json 2>/dev/null | py pgclean >/dev/null; then
            good=$((good + 1))
            [ "$good" -lt 2 ] || return 0
        else
            good=0
        fi
        [ "$SECONDS" -lt "$end" ] || return 1
        if [ -n "$stoppable" ] && fi_stopping; then return 2; fi
        sleep "$POLL"
    done
}

fi_state_snapshot() { # <outfile>
    local o=$1 t="$WORK/.state.$$" who name v
    mkdir -p "$WORK"
    CEPH health detail -f json > "$t.health" 2>/dev/null || echo '{}' > "$t.health"
    CEPH osd tree -f json > "$t.tree" 2>/dev/null || echo '{}' > "$t.tree"
    CEPH osd dump -f json > "$t.dump" 2>/dev/null || echo '{}' > "$t.dump"
    CEPH config dump -f json > "$t.config" 2>/dev/null || echo '[]' > "$t.config"
    CEPH osd pool ls detail -f json > "$t.pools" 2>/dev/null || echo '[]' > "$t.pools"
    CEPH orch ps -f json > "$t.orch" 2>/dev/null || echo '[]' > "$t.orch"
    : > "$t.eff"
    for who in mon osd client; do   # what each kind of daemon or client would use, defaults included: the four options one by one
        for name in $MODE_OPTS; do
            v=$(CEPH config get "$who" "$name" 2>/dev/null | head -n 1) || v="?"
            echo "$who $name=$v" >> "$t.eff"
        done
    done
    py state "$t" "$HEALTH_IGNORE" "$t.eff" > "$o"
    rm -f "$t.health" "$t.tree" "$t.dump" "$t.config" "$t.pools" "$t.orch" "$t.eff"
}

# 0 = the lab is in the state of the snapshot (after waiting up to STATE_WAIT seconds for it to settle: health alerts clear with time, cephadm
# refreshes its daemon list now and then)
#
# The one kind of difference that is NOT a failure: the config database lines osd_mclock_max_capacity_iops_hdd / osd_mclock_max_capacity_iops_ssd (option name
# exactly, section osd.N, osd or global, any mask) that were added or changed since the snapshot. Ceph owns them: its mclock scheduler benchmarks a disk by itself after
# an OSD restarts and stores the result, so a run that restarts OSDs always leaves new ones. They are printed as "NOTE ..." lines and the state still
# "matches". They are NOT removed or restored here (a `ceph config rm` would be this script changing a Ceph-written value; the next OSD restart writes it
# again anyway). Every other difference, and a vanished mclock line, still fails.
fi_state_compare() { # <before> <label>
    local before=$1 label=$2 waited=0 after="$WORK/state.$2" sd
    while :; do
        fi_state_snapshot "$after"
        if diff -u "$before" "$after" > "$after.diff"; then
            echo "state: the lab matches the snapshot taken before ($label)"
            return 0
        fi
        # a difference that is only Ceph's own mclock capacity lines counts as a match (with notes); the second pass may then show the rest settling
        if sd=$(py statediff "$before" "$after" 2>&1); then
            printf '%s\n' "$sd"
            echo "state: the lab matches the snapshot taken before ($label)"
            return 0
        fi
        [ "$waited" -ge "$STATE_WAIT" ] && break
        CEPH orch ps --refresh >/dev/null 2>&1
        sleep 10
        waited=$((waited + 10))
    done
    echo "FAIL  the cluster state differs from the snapshot taken before ($label):" >&2
    sed 's/^/      | /' "$after.diff" >&2
    return 1
}

fi_unit_active() { SYSCTL is-active --quiet "$1" 2>/dev/null; }

fi_unit_start() { # <unit>: the cephadm units refuse a start after five in a short time ("start-limit-hit"): reset the counter first
    SYSCTL reset-failed "$1" >/dev/null 2>&1
    SYSCTL start "$1"
}

# ---- restore ---------------------------------------------------------------------------------------------------------------------------------------
MY_UPMAPS="$WORK/my-upmaps"   # the PGs this script gave an entry (one per line), so the restore removes those and only those

fi_remove_upmaps() {
    local pg rc=0 keep="$WORK/my-upmaps.keep"
    : > "$keep"
    [ -s "$MY_UPMAPS" ] || return 0
    while read -r pg; do
        [ -n "$pg" ] || continue
        case "$PRE_UPMAP" in *" $pg "*) continue ;; esac   # not ours: never remove
        if ! CEPH osd rm-pg-upmap "$pg" >/dev/null 2>&1; then
            # `ceph osd rm-pg-upmap` of an entry that is not there answers 0 as well; a failure is a real failure: keep the PG for the next try
            echo "$pg" >> "$keep"
            rc=1
        fi
    done < "$MY_UPMAPS"
    mv -f "$keep" "$MY_UPMAPS"
    return $rc
}

# restore_cluster: every daemon unit running, every OSD in, our upmap entries gone. 0 when all of that is true afterwards (the state comparison is the
# caller's: it takes longer). Idempotent; the trap calls it after an interrupted fault as well.
fi_restore_cluster() {
    local u n rc=0 dump
    for u in "${MON_UNITS[@]+"${MON_UNITS[@]}"}" "${OSD_UNITS[@]+"${OSD_UNITS[@]}"}"; do
        if ! fi_unit_active "$u"; then
            echo "fault_inject: restore: $u is not running: starting it" >&2
            fi_unit_start "$u" || rc=1
        fi
    done
    # one read of the OSD map for all OSDs (a monitor that does not answer would otherwise cost one whole retry window per OSD)
    if [ "${#OSD_IDS[@]}" -gt 0 ]; then
        dump=$(CEPH osd dump 2>/dev/null) || { echo "fault_inject: restore: cannot read the OSD map (no OSD checked; the cli lines above have rc and stderr)" >&2; rc=1; dump=""; }
    fi
    for n in "${OSD_IDS[@]+"${OSD_IDS[@]}"}"; do
        [ -n "$dump" ] || break
        # grep -c, not -q: under pipefail a -q that stops reading early can make the writer die of SIGPIPE and the whole test read as "not out"
        if [ "$(printf '%s\n' "$dump" | grep -Ec "^osd\.$n (up|down) +out ")" -gt 0 ]; then
            echo "fault_inject: restore: osd.$n is out: marking it in" >&2
            CEPH osd in "$n" >/dev/null 2>&1 || { echo "fault_inject: restore: osd in $n failed" >&2; rc=1; }
        fi
    done
    fi_remove_upmaps || rc=1
    return $rc
}

# ---- the faults ----------------------------------------------------------------------------------------------------------------------------------
STOP=0
EVENTS=""; STOPFILE=""; SUMMARY=""; RECOVERY_MAX=600
CNT_osdkill=0; CNT_monkill=0; CNT_monclean=0; CNT_outin=0; CNT_upmap=0; CNT_failed=0; CNT_late=0; MAX_RECOVERY=0; MAX_LATE_OVER=0
T0=0

fi_stopping() { [ "$STOP" -eq 1 ] || { [ -n "$STOPFILE" ] && [ -e "$STOPFILE" ]; }; }
fi_sleep() { # <seconds>: 0 when the whole time passed, 1 when a stop request cut it short
    local i
    for ((i = 0; i < $1; i++)); do
        fi_stopping && return 1
        sleep 1
    done
    return 0
}

fi_event() { # <text>: one line of the events file and of the log
    local line
    line="$(date +%s) +$((SECONDS - T0))s $*"
    echo "fault_inject: $*" >&2
    [ -z "$EVENTS" ] || echo "$line" >> "$EVENTS"
}

# fi_wait_quorum [seconds]: until `ceph quorum_status` answers (the monitor is back and has a quorum), at most QUORUM_WAIT_S seconds. A restarted monitor needs
# some seconds to be back (SIGKILLed: its store is replayed), and a command fired at it in that time fails for nothing the injector did. Every failed poll is a
# line in the log (rc, stderr); the first answer after one is a line too; the stats file gets "quorum <polls> <seconds> ok|fail". 0 = answers, 1 = still not.
fi_wait_quorum() {
    local t=${1:-$QUORUM_WAIT_S} start=$SECONDS end n=0 rc cls o e el pause=$POLL
    o="$WORK/.fi-q.${BASHPID:-$$}.out"; e="$WORK/.fi-q.${BASHPID:-$$}.err"
    [ "$pause" -ge 1 ] || pause=1
    end=$((SECONDS + t))
    while :; do
        n=$((n + 1))
        CEPH1 quorum_status -f json > "$o" 2> "$e" < /dev/null; rc=$?
        if [ "$rc" -eq 0 ]; then
            el=$((SECONDS - start))
            if [ "$n" -gt 1 ]; then
                fi_cli_log "quorum: the monitor answers again after $n polls in ${el}s${FI_CUR:+ during=$FI_CUR}"
                fi_cli_stat "quorum $n $el ok"
            fi
            rm -f "$o" "$e"
            return 0
        fi
        cls=$(fi_cli_class "$rc" "$e")
        fi_cli_log "quorum: poll=$n rc=$rc class=$cls${FI_CUR:+ during=$FI_CUR} stderr: $(fi_oneline "$e")"
        CLI_LAST_RC=$rc; CLI_LAST_TRIES=$n; CLI_LAST_ERR=$(cat "$e" 2>/dev/null)
        # an error that waiting does not cure (a permission error, a wrong command) ends the wait at once
        if [ "$cls" != transient ]; then break; fi
        [ "$SECONDS" -lt "$end" ] || break
        sleep "$pause"
    done
    el=$((SECONDS - start))
    fi_cli_log "quorum: no answer after $n polls in ${el}s${FI_CUR:+ during=$FI_CUR}"
    fi_cli_stat "quorum $n $el fail"
    rm -f "$o" "$e"
    return 1
}

fault_osdkill() { # <pause> <arg>
    local pause=$1 arg=$2 n unit pid_n
    n=${OSD_IDS[$((arg % BASE_OSDS))]}
    unit=$(fi_osd_unit "$n")
    FAULT_TARGET="osd.$n"
    pid_n=$($SUDO pgrep -f "/usr/bin/ceph-osd -n osd\\.${n} " 2>/dev/null | wc -l)
    [ "$pid_n" -ge 1 ] || { FAULT_NOTE="no ceph-osd process for osd.$n"; return 1; }
    # SIGKILL: the process dies with no goodbye (the connections are cut). Then the unit is stopped, which cancels systemd's own restart, so the
    # daemon stays down for the whole pause and comes back when this script starts it.
    fi_step kill-osd $SUDO pkill -KILL -f "/usr/bin/ceph-osd -n osd\\.${n} " || { FAULT_NOTE="kill failed"; return 1; }
    sleep 1
    fi_step stop-osd SYSCTL stop "$unit" >/dev/null 2>&1 || { FAULT_NOTE="stop failed"; return 1; }
    fi_sleep "$pause" || true
    fi_step start-osd fi_unit_start "$unit" || { FAULT_NOTE="start failed"; return 1; }
    return 0
}

fault_mon() { # <kill|clean> <arg>
    local how=$1 mu i
    mu=${MON_UNITS[0]}
    FAULT_TARGET=${mu#*@}; FAULT_TARGET=${FAULT_TARGET%.service}
    if [ "$how" = kill ]; then
        local mon=${FAULT_TARGET#mon.}
        fi_step kill-mon $SUDO pkill -KILL -f "/usr/bin/ceph-mon -n mon\\.${mon} " || { FAULT_NOTE="kill failed"; return 1; }
        # systemd starts it again after its restart delay (10 s); if it has not within 60 s this script does
        for ((i = 0; i < MON_WAIT; i++)); do
            sleep 1
            [ "$i" -ge 2 ] && fi_unit_active "$mu" && break
        done
        fi_unit_active "$mu" || { fi_step start-mon fi_unit_start "$mu" || { FAULT_NOTE="start failed"; return 1; }; }
    else
        SYSCTL reset-failed "$mu" >/dev/null 2>&1
        fi_step restart-mon SYSCTL restart "$mu" || { FAULT_NOTE="restart failed"; return 1; }
    fi
    # the monitor is a process again; it is a monitor with a quorum when `ceph` answers. The next thing that needs it (the recovery wait, an `osd out`)
    # starts only then
    fi_wait_quorum || { FAULT_NOTE=$(fi_cli_note "the monitor did not answer within $QUORUM_WAIT_S s after its restart"); return 1; }
    return 0
}

fault_outin() { # <pause> <arg>
    local pause=$1 arg=$2 n
    n=${OSD_IDS[$((arg % BASE_OSDS))]}
    FAULT_TARGET="osd.$n"
    fi_wait_quorum || { FAULT_NOTE=$(fi_cli_note "no monitor answer within $QUORUM_WAIT_S s before osd out"); return 1; }
    fi_step osd-out CEPH osd out "$n" >/dev/null 2>&1 || { FAULT_NOTE=$(fi_cli_note "osd out failed"); return 1; }
    fi_sleep "$pause" || true
    fi_step osd-in CEPH osd in "$n" >/dev/null 2>&1 || { FAULT_NOTE=$(fi_cli_note "osd in failed"); return 1; }
    return 0
}

fault_upmap() { # <pause> <arg>
    local pause=$1 arg=$2 line pg rot
    FAULT_TARGET="-"
    fi_wait_quorum || { FAULT_NOTE=$(fi_cli_note "no monitor answer within $QUORUM_WAIT_S s before the upmap"); return 1; }
    line=$(CEPH pg ls-by-pool "$POOL" -f json 2>/dev/null | py pgrot "$arg") || { FAULT_NOTE="no PG with more than one OSD in its up set (or ceph pg ls-by-pool failed: the cli lines have rc and stderr)"; return 1; }
    pg=${line%% *}; rot=${line#* }
    FAULT_TARGET="pg.$pg"
    case "$PRE_UPMAP" in *" $pg "*) FAULT_NOTE="pg $pg has an upmap entry that is not ours"; return 1 ;; esac
    echo "$pg" >> "$MY_UPMAPS"   # first: the restore must know of it even if the command is cut half way
    # shellcheck disable=SC2086
    fi_step upmap-set CEPH osd pg-upmap "$pg" $rot </dev/null >/dev/null 2>&1 || { FAULT_NOTE=$(fi_cli_note "pg-upmap failed"); return 1; }
    fi_sleep "$pause" || true
    fi_step upmap-rm CEPH osd rm-pg-upmap "$pg" >/dev/null 2>&1 || { FAULT_NOTE=$(fi_cli_note "rm-pg-upmap failed"); return 1; }
    sed -i "\\|^$pg\$|d" "$MY_UPMAPS" 2>/dev/null
    return 0
}

# one fault of the plan; 0 = it ran to its end and the cluster recovered, 1 = failed (counted, the restore has run), 3 = the cluster would not heal
FAULT_TARGET=""; FAULT_NOTE=""
fi_run_fault() { # <idx> <kind> <pause> <arg>
    local idx=$1 kind=$2 pause=$3 arg=$4 t1 rc=0 rec
    FAULT_TARGET="-"; FAULT_NOTE=""; FI_CUR=$idx
    t1=$SECONDS
    case "$kind" in
        osdkill) fault_osdkill "$pause" "$arg" || rc=1 ;;
        monkill) fault_mon kill "$arg" || rc=1 ;;
        monclean) fault_mon clean "$arg" || rc=1 ;;
        outin) fault_outin "$pause" "$arg" || rc=1 ;;
        upmap) fault_upmap "$pause" "$arg" || rc=1 ;;
        *) FAULT_NOTE="unknown kind"; rc=1 ;;
    esac
    local t_acted=$((SECONDS - t1))
    if [ "$rc" -ne 0 ]; then
        # whatever was half done is undone now, before anything else happens
        fi_restore_cluster || FAULT_NOTE="$FAULT_NOTE; restore incomplete"
    fi
    # the recovery wait: a late recovery is logged and waited for, up to three times the limit
    local t2=$SECONDS late=0 waited_rc=0
    fi_wait_clean "$RECOVERY_MAX" stoppable; local wrc=$?
    if [ "$wrc" -eq 2 ]; then
        :   # a stop was asked for: the recovery is finished by the restore at the end, which waits for it
    elif [ "$wrc" -ne 0 ]; then
        late=1; CNT_late=$((CNT_late + 1))
        fi_event "fault n=$idx kind=$kind target=$FAULT_TARGET: the recovery is late (more than $RECOVERY_MAX s): $(CEPHQ pg stat 2>&1 | head -n 1)"
        fi_restore_cluster || true
        fi_wait_clean $((RECOVERY_MAX * 2)) stoppable; wrc=$?
        [ "$wrc" -eq 0 ] || [ "$wrc" -eq 2 ] || waited_rc=3
    fi
    rec=$((SECONDS - t2))
    [ "$rec" -le "$MAX_RECOVERY" ] || MAX_RECOVERY=$rec
    # how far past the limit the slowest late recovery went (a WARN for the caller, not a failure: the cluster did heal, within three times the limit)
    if [ "$late" -eq 1 ] && [ $((rec - RECOVERY_MAX)) -gt "$MAX_LATE_OVER" ]; then MAX_LATE_OVER=$((rec - RECOVERY_MAX)); fi
    if [ "$waited_rc" -ne 0 ]; then
        fi_event "fault n=$idx kind=$kind target=$FAULT_TARGET acted=${t_acted}s recovery=${rec}s rc=3 note=the cluster did not heal"
        return 3
    fi
    if [ "$rc" -eq 0 ]; then
        eval "CNT_$kind=\$((CNT_$kind + 1))"
    else
        CNT_failed=$((CNT_failed + 1))
    fi
    fi_event "fault n=$idx kind=$kind target=$FAULT_TARGET pause=$pause acted=${t_acted}s recovery=${rec}s late=$late rc=$rc${FAULT_NOTE:+ note=$FAULT_NOTE}"
    FI_CUR=""
    return "$rc"
}

# ---- the trap and the main loop ----------------------------------------------------------------------------------------------------------------
FI_FINAL_RC=0
# the totals of the stats file (one line per retried or finally failed ceph call: "cli <retries> <seconds> ok|fail"; per quorum wait: "quorum <polls> <seconds> ok|fail")
fi_cli_totals() {
    if [ -n "$CLI_STATS" ] && [ -s "$CLI_STATS" ]; then
        awk '$1 == "cli" { r += $2; if ($3 + 0 > m) m = $3 + 0; if ($4 == "ok") k++; else g++ }
             $1 == "quorum" { q++; if ($3 + 0 > qm) qm = $3 + 0; if ($4 != "ok") qf++ }
             END { printf "cli_retries=%d cli_retry_max_s=%d cli_recovered=%d cli_gave_up=%d quorum_waits=%d quorum_wait_max_s=%d quorum_gave_up=%d", r, m, k, g, q, qm, qf }' "$CLI_STATS"
    else
        printf 'cli_retries=0 cli_retry_max_s=0 cli_recovered=0 cli_gave_up=0 quorum_waits=0 quorum_wait_max_s=0 quorum_gave_up=0'
    fi
}
fi_summary_line() {
    echo "summary seed=$SEED osdkill=$CNT_osdkill monkill=$CNT_monkill monclean=$CNT_monclean mon_restarts=$((CNT_monkill + CNT_monclean)) outin=$CNT_outin upmap=$CNT_upmap failed=$CNT_failed late=$CNT_late max_recovery_s=$MAX_RECOVERY late_max_over_s=$MAX_LATE_OVER recovery_limit_s=$RECOVERY_MAX $(fi_cli_totals)"
}

fi_on_exit() {
    local rc=$? crc=0 sc=0
    # from here on the signals are ignored: a second Ctrl-C (or the TERM of a caller that is in a hurry) must not cut the restore short and leave a
    # daemon down; SIGKILL is the only way out, and whoever called us (exit-run.sh) puts back what it knows of
    trap - EXIT
    trap '' INT TERM HUP
    [ "$FI_FINAL_RC" -ne 0 ] || FI_FINAL_RC=$rc
    if [ -s "$WORK/fi.state.before" ] || [ "${#OSD_IDS[@]}" -gt 0 ]; then
        fi_restore_cluster || crc=1
        if ! fi_wait_clean $((RECOVERY_MAX * 2 > 300 ? RECOVERY_MAX * 2 : 300)); then
            echo "FAIL  the cluster is not clean again after the restore: $(CEPHQ pg stat 2>&1 | head -n 1)" >&2
            crc=1
        fi
        if [ -s "$WORK/fi.state.before" ]; then fi_state_compare "$WORK/fi.state.before" fi-after || sc=1; fi
        if [ "$crc" -ne 0 ] || [ "$sc" -ne 0 ]; then FI_FINAL_RC=3; fi
    fi
    fi_info "$(fi_summary_line)"
    [ -z "$SUMMARY" ] || fi_summary_line > "$SUMMARY"
    fi_info "finished with exit status $FI_FINAL_RC (restore: $([ $crc = 0 ] && echo complete || echo INCOMPLETE); state: $([ $sc = 0 ] && echo as-before || echo CHANGED))"
    exit "$FI_FINAL_RC"
}

SEED=""
fi_main() {
    local min_gap=90 max_gap=300 ko=20 km=10 kio=10 ku=5 initial="" cap=0 only="" runfor=0 dry=0 selftest=0 plan i n=0 v val
    local idx kind gap pause arg next_start prev_start
    exec 8>&2   # the log of the ceph wrapper goes here, whatever a caller does with the stderr of one call (fi_cli_log)
    while [ $# -gt 0 ]; do
        case "$1" in
            --seed) SEED=${2:-}; shift ;;
            --stop-file) STOPFILE=${2:-}; shift ;;
            --run-for) runfor=${2:-}; shift ;;
            --events) EVENTS=${2:-}; shift ;;
            --summary) SUMMARY=${2:-}; shift ;;
            --min-gap) min_gap=${2:-}; shift ;;
            --max-gap) max_gap=${2:-}; shift ;;
            --osd-kills) ko=${2:-}; shift ;;
            --mon-restarts) km=${2:-}; shift ;;
            --outins) kio=${2:-}; shift ;;
            --upmaps) ku=${2:-}; shift ;;
            --initial-delay) initial=${2:-}; shift ;;
            --recovery-max) RECOVERY_MAX=${2:-}; shift ;;
            --pause-cap) cap=${2:-}; shift ;;
            --only) only=${2:-}; shift ;;
            --dry-run) dry=1 ;;
            --selftest) selftest=1 ;;
            --inject-fail) INJECT=${2:-}; shift ;;
            -h|--help) sed -n '3,/^set -u$/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
            *) fi_die "unknown argument: $1 (try --help)" ;;
        esac
        shift
    done
    if [ "$selftest" -eq 1 ]; then fi_selftest; exit $?; fi
    # every numeric option on its own (a concatenated check let an empty one through, and `[ x -lt "" ]` then fails quietly); at most nine digits; read as
    # decimal ("08" is not an octal error)
    for v in min_gap max_gap ko km kio ku cap runfor RECOVERY_MAX STATE_WAIT POLL; do
        eval "val=\${$v}"
        case "$val" in ''|*[!0-9]*) fi_die "the numeric options take whole numbers (got '$val' for $v)" ;; esac
        [ "${#val}" -le 9 ] || fi_die "the numeric options take at most nine digits (got '$val' for $v)"
        eval "$v=\$((10#$val))"
    done
    # the retry window of the ceph calls and the quorum wait: the environment is read by fi_uint with a default; a mistyped value is refused here
    for v in FI_CLI_RETRY_S FI_CLI_BACKOFF FI_CLI_BACKOFF_MAX FI_QUORUM_WAIT; do
        eval "val=\${$v:-0}"
        case "$val" in *[!0-9]*) fi_die "$v takes whole seconds (got '$val')" ;; esac
    done
    [ "$min_gap" -ge 1 ] && [ "$max_gap" -ge "$min_gap" ] || fi_die "--min-gap / --max-gap: 1 <= min <= max"
    [ "$RECOVERY_MAX" -ge 1 ] || fi_die "--recovery-max takes seconds"
    if [ -n "$only" ]; then
        for i in ${only//,/ }; do
            case "$i" in osdkill|monkill|monclean|outin|upmap) ;; *) fi_die "--only takes osdkill, monkill, monclean, outin, upmap (got '$i')" ;; esac
        done
        # a restricted run keeps only the deck entries of the kinds asked for
        case ",$only," in *,osdkill,*) ;; *) ko=0 ;; esac
        case ",$only," in *,monkill,*|*,monclean,*) ;; *) km=0 ;; esac
        case ",$only," in *,outin,*) ;; *) kio=0 ;; esac
        case ",$only," in *,upmap,*) ;; *) ku=0 ;; esac
        [ $((ko + km + kio + ku)) -gt 0 ] || fi_die "--only leaves nothing to inject"
    fi
    case "$SEED" in '') SEED=$(( $(od -An -N4 -tu4 /dev/urandom | tr -d ' ') % 2147483647 + 1 )) ;; *[!0-9]*) fi_die "--seed takes a number" ;; esac
    [ -n "$initial" ] || initial=
    case "$initial" in *[!0-9]*) fi_die "--initial-delay takes seconds" ;; esac
    [ -z "$initial" ] || [ "${#initial}" -le 9 ] || fi_die "--initial-delay takes at most nine digits"
    [ -z "$initial" ] || initial=$((10#$initial))
    case "$WORK" in /*) ;; *) fi_die "WR_LAB_WORK must be an absolute path" ;; esac
    case "$WORK" in *' '*|*'*'*|*'?'*) fi_die "WR_LAB_WORK must not contain spaces or glob characters" ;; esac
    command -v python3 >/dev/null || fi_die "python3 is needed"
    fi_write_pylib || fi_die "cannot write to $WORK"
    [ -n "$EVENTS" ] || EVENTS="$WORK/fault-events.log"
    MY_UPMAPS="$WORK/my-upmaps"
    # the plan: the deck, then enough extras to run for a long time (the loop ends on the stop file, the time limit or a signal)
    plan=$(py plan "$SEED" "$ko" "$km" "$kio" "$ku" "$min_gap" "$max_gap" "$cap" 2000) || fi_die "cannot make the plan"
    fi_info "seed $SEED, deck: osdkill=$ko monkill=$((km / 2)) monclean=$((km - km / 2)) outin=$kio upmap=$ku, gaps $min_gap-$max_gap s (reproduce with --seed $SEED)"
    if [ "$dry" -eq 1 ]; then
        echo "plan (the first 60 of the deck and the extras; nothing is run, nothing is changed):"
        printf '%s\n' "$plan" | head -n 60 | while read -r idx kind gap pause arg; do
            case "$kind" in
                osdkill) echo "  $idx +${gap}s osdkill: SIGKILL osd.<#$arg>, held down ${pause}s, started again, then wait for active+clean" ;;
                monkill) echo "  $idx +${gap}s monkill: SIGKILL the monitor, systemd (or this script after 60 s) starts it, then wait for active+clean" ;;
                monclean) echo "  $idx +${gap}s monclean: clean restart of the monitor unit, then wait for active+clean" ;;
                outin) echo "  $idx +${gap}s outin: ceph osd out osd.<#$arg>, ${pause}s, ceph osd in, then wait for active+clean" ;;
                upmap) echo "  $idx +${gap}s upmap: pg-upmap of PG <#$arg> of pool $POOL to its up set rotated by one, ${pause}s, rm-pg-upmap, then wait" ;;
            esac
        done
        echo "restore (EXIT trap): units running, OSDs in, own upmap entries removed, active+clean, state equal to the snapshot"
        return 0
    fi
    command -v ceph >/dev/null || fi_die "the ceph command is needed (run this inside the lab VM)"
    $SUDO -n true 2>/dev/null || fi_die "passwordless sudo is needed (the stock CLI, systemctl, pkill)"
    mkdir -p "$WORK" || fi_die "cannot create $WORK"
    : > "$MY_UPMAPS"
    CLI_STATS="$WORK/fi.cli.stats"; : > "$CLI_STATS"
    fi_discover || fi_die "cannot read the cluster (ceph fsid, the mon and OSD units; need one monitor and at least 3 OSDs)"
    # the faults only make sense on a cluster that starts whole; the restore puts every OSD back up and in, which on a cluster where an operator
    # had stopped or marked one out on purpose would be a change, not a restore
    CEPH osd stat -f json 2>/dev/null | py osdup "$BASE_OSDS" || fi_die "not every OSD is up and in at the start: nothing is changed"
    CEPH pg stat -f json 2>/dev/null | py pgclean >/dev/null || fi_die "the placement groups are not all active+clean at the start: nothing is changed"
    fi_state_snapshot "$WORK/fi.state.before"
    [ -s "$WORK/fi.state.before" ] || fi_die "cannot read the cluster state (ceph commands failed)"
    trap fi_on_exit EXIT
    trap 'STOP=1' INT TERM HUP
    T0=$SECONDS
    fi_event "start seed=$SEED osds=$BASE_OSDS mon_units=${#MON_UNITS[@]} fsid=$FSID"
    prev_start=$SECONDS
    first=1
    while read -r idx kind gap pause arg <&3; do   # fd 3: the commands inside the loop must not read the plan from stdin
        fi_stopping && break
        [ "$runfor" -eq 0 ] || [ $((SECONDS - T0)) -lt "$runfor" ] || break
        if [ "$first" -eq 1 ]; then
            first=0
            [ -z "$initial" ] || gap=$initial
        fi
        next_start=$((prev_start + gap))
        while [ "$SECONDS" -lt "$next_start" ]; do
            fi_stopping && break
            [ "$runfor" -eq 0 ] || [ $((SECONDS - T0)) -lt "$runfor" ] || break
            sleep 1
        done
        fi_stopping && break
        [ "$runfor" -eq 0 ] || [ $((SECONDS - T0)) -lt "$runfor" ] || break
        prev_start=$SECONDS
        fi_run_fault "$idx" "$kind" "$pause" "$arg"
        n=$?
        if [ "$n" -eq 3 ]; then FI_FINAL_RC=3; break; fi
    done 3<<< "$plan"
    return 0
}

# ---- selftest ----------------------------------------------------------------------------------------------------------------------------------------
# Stand-ins for sudo, ceph, systemctl, pkill and pgrep (one python program) in a directory of their own, first in PATH: a cluster of three OSDs and one
# monitor that keeps its state in files (daemon up / down / failed, in / out, the upmap table) and reports PGs as unclean for a few polls after any
# change. A failure is injected at every step the injector has; the restore must put everything back each time.
fi_write_stubs() { # <dir>
    local d=$1
    mkdir -p "$d/bin" "$d/st"
    cat > "$d/bin/sudo" <<'STUB'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in -n|-E|-S) shift ;; *) break ;; esac; done
exec "$@"
STUB
    cat > "$d/stub.py" <<'PY'
import json, os, sys, time
S = os.environ["FI_STUB"]
FSID = "11111111-2222-3333-4444-555555555555"

def rd(name, default=""):
    try:
        with open(os.path.join(S, name)) as f:
            return f.read().strip()
    except OSError:
        return default

def wr(name, v):
    with open(os.path.join(S, name), "w") as f:
        f.write(str(v))

DEFAULTS = {"ms_mon_service_mode": "secure crc", "ms_service_mode": "crc secure", "ms_mon_client_mode": "secure crc", "ms_client_mode": "crc secure"}

def cfg():
    try:
        return json.loads(rd("config.json", "[]"))
    except ValueError:
        return []

def eff(who, name):    # the value a daemon of kind `who` would read at startup
    for c in cfg():
        if c["name"] == name and c["section"] in (who, "global"):
            return c["value"]
    return DEFAULTS.get(name, "")

def started(kind, name):    # a daemon that starts reads its mode option now
    os.makedirs(os.path.join(S, "modes"), exist_ok=True)
    wr("modes/%s" % ("mon" if kind == "mon" else "osd." + name), eff(kind, "ms_mon_service_mode" if kind == "mon" else "ms_service_mode"))
    mc = os.environ.get("FI_STUB_MCLOCK", "")
    if mc and kind != "mon":    # an OSD that starts runs the mclock benchmark and stores the result itself, as Ceph does (FI_STUB_MCLOCK=other: and somebody else's change too)
        who, nm = "osd.%s" % name, "osd_mclock_max_capacity_iops_hdd"
        c = [x for x in cfg() if not (x["section"] == who and x["name"] == nm)]
        c.append({"section": who, "name": nm, "value": "208.634136", "mask": "", "level": "basic"})
        if mc == "other":
            c = [x for x in c if x["name"] != "osd_memory_target"] + [{"section": "osd", "name": "osd_memory_target", "value": "1", "mask": "", "level": "basic"}]
        wr("config.json", json.dumps(c))

def unclean(n=2):
    wr("unclean", n)
    if os.environ.get("FI_STUB_UNCLEAN_SECS"):    # a recovery that takes this many seconds of wall time, whatever the number of polls
        wr("unclean_until", time.time() + float(os.environ["FI_STUB_UNCLEAN_SECS"]))

def osd_state(i):
    return rd("osd.%d.state" % i, "active")      # active | failed | inactive

def osd_in(i):
    return rd("osd.%d.in" % i, "1") == "1"

prog = os.environ["FI_PROG"]
args = sys.argv[1:]

def upmaps():
    return [l for l in rd("upmaps").split() if l]

if prog == "ceph":
    a = [x for x in args if x not in ("--connect-timeout", "10")]
    if a[:1] == ["--connect-timeout"]:
        a = a[2:]
    cmd = " ".join(a)
    # FI_STUB_QUORUM_DOWN=N: after the monitor was started or restarted, the next N invocations of ceph (any command) fail the way the CLI does while the
    # monitor is not back (N < 0: always). FI_STUB_CLI_FAIL="osd out" makes the commands that start with that text fail FI_STUB_CLI_N times (< 0: always)
    # with FI_STUB_CLI_ERR on stderr and FI_STUB_CLI_RC as the status (FI_STUB_CLI_AFTER_SET=1: only after the first `config set`; FI_STUB_CLI_AFTER_APPLY=1: the command is carried out first and then reported as failed, as when the answer of the monitor is lost).
    qd = int(rd("quorum.down", "0") or 0)
    if qd != 0:
        if qd > 0:
            wr("quorum.down", qd - 1)
        sys.stderr.write("monclient(hunting): authenticate timed out after 10\n[errno 110] RADOS timed out (error connecting to the cluster)\n")
        sys.exit(1)
    fspec = os.environ.get("FI_STUB_CLI_FAIL", "")
    late_fail = False
    if fspec and cmd.startswith(fspec) and (os.environ.get("FI_STUB_CLI_AFTER_SET", "") != "1" or rd("cfgset.seen", "0") == "1"):
        fn = int(os.environ.get("FI_STUB_CLI_N", "1"))
        done = int(rd("clifail.count", "0") or 0)
        if fn < 0 or done < fn:
            wr("clifail.count", done + 1)
            if os.environ.get("FI_STUB_CLI_AFTER_APPLY", "") == "1":
                late_fail = True    # the monitor does what was asked and the CLI still times out (the answer is lost): the command ran, the caller is told it failed
            else:
                sys.stderr.write(os.environ.get("FI_STUB_CLI_ERR", "[errno 110] RADOS timed out (error connecting to the cluster)") + "\n")
                sys.exit(int(os.environ.get("FI_STUB_CLI_RC", "1")))
    if cmd == "fsid":
        print(FSID)
    elif cmd.startswith("quorum_status"):
        if rd("mon.state", "active") != "active":
            sys.stderr.write("[errno 111] error connecting to the cluster: Connection refused\n")
            sys.exit(1)
        sys.exit(0)
    elif cmd.startswith("osd stat"):
        up = sum(1 for i in range(3) if osd_state(i) == "active")
        inn = sum(1 for i in range(3) if osd_in(i))
        print(json.dumps({"num_osds": 3, "num_up_osds": up, "num_in_osds": inn}))
    elif cmd.startswith("pg stat"):
        n = int(rd("unclean", "0"))
        if n > 0 or time.time() < float(rd("unclean_until", "0") or 0):
            if n > 0:
                wr("unclean", n - 1)
            print(json.dumps({"num_pg_by_state": [{"name": "active+undersized+degraded", "num": 5}, {"name": "active+clean", "num": 28}]}))
        else:
            print(json.dumps({"num_pg_by_state": [{"name": "active+clean", "num": 33}]}))
    elif cmd == "osd out 0" or cmd == "osd out 1" or cmd == "osd out 2":
        wr("osd.%s.in" % a[2], "0"); unclean()
    elif cmd == "osd in 0" or cmd == "osd in 1" or cmd == "osd in 2":
        wr("osd.%s.in" % a[2], "1"); unclean()
    elif cmd.startswith("pg ls-by-pool"):
        print(json.dumps({"pg_stats": [{"pgid": "1.%x" % k, "up": [(k + j) % 3 for j in range(3)]} for k in range(8)]}))
    elif cmd.startswith("osd pg-upmap "):
        u = upmaps()
        if a[2] not in u:
            u.append(a[2])
        wr("upmaps", " ".join(u)); unclean()
    elif cmd.startswith("osd rm-pg-upmap "):
        wr("upmaps", " ".join(x for x in upmaps() if x != a[2])); unclean()
    elif cmd.startswith("osd dump") and "-f" in a:
        print(json.dumps({"flags_set": ["sortbitwise"], "osds": [{"osd": i, "up": 1 if osd_state(i) == "active" else 0, "in": 1 if osd_in(i) else 0, "weight": 1.0 if osd_in(i) else 0.0} for i in range(3)],
                          "pg_upmap_items": [{"pgid": p, "mappings": []} for p in upmaps()]}))
    elif cmd == "osd dump":
        for i in range(3):
            print("osd.%d %s %s weight 1 up_from 1" % (i, "up" if osd_state(i) == "active" else "down", "in" if osd_in(i) else "out"))
    elif cmd.startswith("osd tree"):
        print(json.dumps({"nodes": [{"id": i, "name": "osd.%d" % i, "type": "osd", "status": "up" if osd_state(i) == "active" else "down", "reweight": 1.0 if osd_in(i) else 0.0} for i in range(3)]}))
    elif cmd.startswith("health detail"):
        print(json.dumps({"checks": {}}))
    elif cmd.startswith("config dump"):
        print(json.dumps(cfg()))
    elif cmd.startswith("config get "):
        print(eff(a[2], a[3]))
    elif cmd.startswith("config set "):
        wr("cfgset.seen", "1")    # FI_STUB_CLI_AFTER_SET=1: the failures of FI_STUB_CLI_FAIL start after the first `config set`
        c = [x for x in cfg() if not (x["section"] == a[2] and x["name"] == a[3])]
        c.append({"section": a[2], "name": a[3], "value": " ".join(a[4:]), "mask": "", "level": "advanced"})
        wr("config.json", json.dumps(c))
    elif cmd.startswith("config rm "):
        wr("config.json", json.dumps([x for x in cfg() if not (x["section"] == a[2] and x["name"] == a[3])]))
    elif cmd.startswith("osd pool ls detail"):
        print(json.dumps([{"pool_name": "winrbd", "size": 3, "min_size": 2, "crush_rule": 1, "application_metadata": {"rbd": {}}}]))
    elif cmd.startswith("orch ps --refresh"):
        pass
    elif cmd.startswith("orch ps"):
        out = [{"daemon_type": "osd", "daemon_name": "osd.%d" % i, "status_desc": "running" if osd_state(i) == "active" else "error"} for i in range(3)]
        out.append({"daemon_type": "mon", "daemon_name": "mon.lab", "status_desc": "running" if rd("mon.state", "active") == "active" else "error"})
        print(json.dumps(out))
    else:
        sys.stderr.write("stub ceph: unsupported: %s\n" % cmd)
        sys.exit(1)
    if late_fail:
        sys.stderr.write(os.environ.get("FI_STUB_CLI_ERR", "[errno 110] RADOS timed out (error connecting to the cluster)") + "\n")
        sys.exit(int(os.environ.get("FI_STUB_CLI_RC", "1")))
elif prog == "systemctl":
    cmd = args[0]
    if cmd == "list-units":
        for i in range(3):
            print("ceph-%s@osd.%d.service loaded active running Ceph osd.%d" % (FSID, i, i))
        print("ceph-%s@mon.lab.service loaded active running Ceph mon.lab" % FSID)
        sys.exit(0)
    unit = args[-1]
    kind, _, rest = unit.partition("@")[2].partition(".")
    name = rest[:-len(".service")]
    key = "mon.state" if kind == "mon" else "osd.%s.state" % name
    if cmd == "is-active":
        sys.exit(0 if rd(key, "active") == "active" else 3)
    elif cmd == "reset-failed":
        if rd(key, "active") == "failed":
            wr(key, "inactive")
    elif cmd in ("start", "restart"):
        wr(key, "active"); started(kind, name); unclean()
        if kind == "mon":
            wr("quorum.down", os.environ.get("FI_STUB_QUORUM_DOWN", "0"))
    elif cmd == "stop":
        wr(key, "inactive"); unclean()
elif prog == "pkill" or prog == "pgrep":
    pat = args[-1]
    kind = "mon" if "ceph-mon" in pat else "osd"
    if kind == "osd" and "osd\\." not in pat:
        os.execv("/usr/bin/" + prog, [prog] + args)     # a pattern of another program (the exit run's tools): the real command
    if kind == "osd":
        i = pat.split("osd\\.")[1].split(" ")[0]
        key = "osd.%s.state" % i
    else:
        key = "mon.state"
    if prog == "pgrep":
        if rd(key, "active") == "active":
            print(1)
            sys.exit(0)
        sys.exit(1)
    if rd(key, "active") != "active":
        sys.exit(1)
    wr(key, "failed"); unclean()
else:
    sys.exit(1)
PY
    local p
    for p in ceph systemctl pkill pgrep; do
        printf '#!/bin/bash\nFI_PROG=%s exec python3 -I "%s/stub.py" "$@"\n' "$p" "$d" > "$d/bin/$p"
        chmod +x "$d/bin/$p"
    done
    chmod +x "$d/bin/sudo"
}

# st_check <name> <description> <rc>: PASS / FAIL line and the counters
ST_PASS=0; ST_FAIL=0
st_ok()  { ST_PASS=$((ST_PASS + 1)); echo "PASS  $*"; }
st_bad() { ST_FAIL=$((ST_FAIL + 1)); echo "FAIL  $*"; }

# the lab of the stand-ins as a person would read it: 0 when every OSD and the monitor run, every OSD is in, no upmap entry is left, the config database
# is as it was and every daemon that was restarted runs with the original mode
st_lab_whole() { # <scenario dir>
    local d=$1 i s extra
    for i in 0 1 2; do
        s=$(cat "$d/st/osd.$i.state" 2>/dev/null || echo active)
        [ "$s" = active ] || { echo "osd.$i is $s"; return 1; }
        [ "$(cat "$d/st/osd.$i.in" 2>/dev/null || echo 1)" = 1 ] || { echo "osd.$i is out"; return 1; }
    done
    [ "$(cat "$d/st/mon.state" 2>/dev/null || echo active)" = active ] || { echo "the monitor is not running"; return 1; }
    [ -z "$(cat "$d/st/upmaps" 2>/dev/null | tr -d ' \n')" ] || { echo "upmap entries are left: $(cat "$d/st/upmaps")"; return 1; }
    # the config database is as it was, but for the mclock capacity lines the stand-in OSDs write when they start (Ceph's own benchmark: not restored by design)
    extra=$(python3 -I -c 'import json, sys
try:
    c = json.load(open(sys.argv[1]))
except Exception:
    c = []
print(",".join(x["section"] + "/" + x["name"] for x in c if x["name"] not in ("osd_mclock_max_capacity_iops_hdd", "osd_mclock_max_capacity_iops_ssd")))' "$d/st/config.json" 2>/dev/null)
    [ -z "$extra" ] || { echo "the config database is not as it was: $extra"; return 1; }
    for i in "$d"/st/modes/*; do   # a daemon that was restarted read the mode option then: it must be the original one
        [ -e "$i" ] || continue
        case "$(basename "$i"):$(cat "$i")" in mon:"secure crc"|osd.*:"crc secure") ;; *) echo "$(basename "$i") runs with '$(cat "$i")'"; return 1 ;; esac
    done
    return 0
}

# The scenarios are independent (each has a directory of its own for the stand-in cluster's state and for the work files), so they run at the same time,
# a few at once, and are judged afterwards in order: st_go launches one, st_judge reports it.
ST_JOBS=${FI_SELFTEST_JOBS:-6}
st_throttle() { while [ "$(jobs -rp | wc -l)" -ge "$ST_JOBS" ]; do wait -n 2>/dev/null || break; done; }

# st_go <dir> <name> [ENV=VALUE ...] -- <args...>: the injector in a clean stand-in lab of its own; rc and output in <dir>/sc-<name>/
st_go() {
    local d=$1 name=$2 envs=(); shift 2
    while [ $# -gt 0 ] && [ "$1" != -- ]; do envs+=("$1"); shift; done
    shift
    local sd="$d/sc-$name"
    mkdir -p "$sd/st" "$sd/work"
    ( env FI_CLI_RETRY_S=6 FI_CLI_BACKOFF=1 FI_CLI_BACKOFF_MAX=1 FI_QUORUM_WAIT=20 "${envs[@]+"${envs[@]}"}" PATH="$d/bin:$PATH" FI_STUB="$sd/st" WR_LAB_WORK="$sd/work" FI_POLL=0 FI_STATE_WAIT=0 FI_MON_WAIT=3 WR_LAB_SUDO=sudo bash "$SELF" "$@" > "$sd/out" 2>&1
      echo $? > "$sd/rc" ) &
    st_throttle
}
st_wait() { wait; }   # every launched scenario is done
st_num() { sed -n "s/.* $2=\([0-9]*\).*/\1/p" "$1/sc-$3/out" 2>/dev/null | tail -n 1; }   # st_num <dir> <key> <scenario>: a number of the summary line (empty when none)
# st_once <dir> <scenario> <kind> <label>: PASS when the summary count of <kind> equals the number of <kind> faults that ended with rc=0 in the
# events file, at least one did, and the first fault of the run (the one whose answer was lost) is among them. A re-run of a command whose answer was lost must not count the fault twice; the run may still have room
# for a further fault of the same kind after the deck (--run-for), so the number itself depends on the runner's speed and is not fixed.
st_once() {
    local v n; v=$(st_num "$1" "$3" "$2")
    n=$(grep -cE "fault n=[0-9]+ kind=$3 .* rc=0( |\$)" "$1/sc-$2/work/fault-events.log" 2>/dev/null)
    # the first fault of the run is the one whose answer was lost (the stand-in fails only the first calls): it must have ended with rc=0
    if [ -n "$v" ] && [ "${n:-0}" -ge 1 ] && [ "$v" -eq "$n" ] && grep -qE "fault n=1 kind=$3 .* rc=0( |\$)" "$1/sc-$2/work/fault-events.log" 2>/dev/null; then
        st_ok "$4: $3=$v, $n fault(s) of that kind, the first one done"
    else st_bad "$4: $3='${v:-none}', faults of that kind that ended with rc=0: ${n:-0}"; sed 's/^/      | /' "$1/sc-$2/out" | grep -E "summary|cli |fault n=" | tail -n 8; fi
}

st_cmp() { # <dir> <scenario> <key> <op> <n> <label>: PASS when the summary number of <key> satisfies <op> <n> (-eq, -ge)
    local v; v=$(st_num "$1" "$3" "$2")
    if [ -n "$v" ] && [ "$v" "$4" "$5" ]; then st_ok "$6: $3=$v"; else st_bad "$6: $3='${v:-none}', expected $4 $5"; sed 's/^/      | /' "$1/sc-$2/out" | grep -E "summary|cli |quorum" | tail -n 6; fi
}

# st_judge <dir> <name> <label> <expected status: a number or any>: PASS / FAIL for the status and for the lab being whole again
ST_RC=0
st_judge() {
    local d=$1 name=$2 label=$3 want=$4 sd rc why
    sd="$d/sc-$name"
    rc=$(cat "$sd/rc" 2>/dev/null || echo none); ST_RC=$rc
    if [ "$want" != any ] && [ "$rc" != "$want" ]; then st_bad "$label: exit status $rc, expected $want"; sed 's/^/      | /' "$sd/out" | tail -n 12; return 1; fi
    if why=$(st_lab_whole "$sd"); then st_ok "$label: the lab is whole again (exit $rc)"; else st_bad "$label: the lab is NOT restored: $why"; sed 's/^/      | /' "$sd/out" | tail -n 12; fi
    return 0
}

fi_selftest() {
    local d step plan1 plan2 c k out rc only name p
    SELF="$fi_here/$(basename "${BASH_SOURCE[0]}")"
    d=$(mktemp -d "${TMPDIR:-/tmp}/fault-inject-selftest.XXXXXX") || { echo "cannot make a temporary directory" >&2; return 2; }
    case "$d" in /*/fault-inject-selftest.??????) ;; *) echo "unexpected temporary directory '$d'" >&2; return 2 ;; esac
    command -v python3 >/dev/null || { echo "python3 is needed"; return 77; }
    echo "selftest with stand-in ceph / systemctl / pkill in $d"
    fi_write_stubs "$d"
    WORK="$d/work"; mkdir -p "$WORK"; fi_write_pylib

    # launch everything that needs a cluster first: they run while the pure checks below are made
    local common="--seed 11 --min-gap 1 --max-gap 2 --initial-delay 1 --pause-cap 1 --osd-kills 3 --mon-restarts 2 --outins 2 --upmaps 2 --recovery-max 5 --run-for 25"
    st_go "$d" full -- $common
    local steps="kill-osd:osdkill stop-osd:osdkill start-osd:osdkill kill-mon:monkill restart-mon:monclean osd-out:outin osd-in:outin upmap-set:upmap upmap-rm:upmap"
    for k in $steps; do
        step=${k%%:*}; only=${k##*:}
        # a failing step: the fault is counted as failed, the restore runs at once, and the injector goes on and ends restored
        st_go "$d" "step-$step" -- --seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only "$only" --osd-kills 2 --mon-restarts 2 --outins 2 --upmaps 2 \
              --recovery-max 5 --run-for 6 --inject-fail "$step"
    done
    # Ceph's own mclock capacity line appears while OSDs restart: a NOTE, the run passes, the line is left alone; the same plus somebody else's change fails
    st_go "$d" mclock FI_STUB_MCLOCK=1 -- $common
    st_go "$d" mclockother FI_STUB_MCLOCK=other -- --seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only osdkill --osd-kills 2 --recovery-max 5 --run-for 6
    # a recovery that takes longer than --recovery-max but heals within three times it: late=1, a WARN number in the summary, the injector still exits 0
    st_go "$d" late FI_STUB_UNCLEAN_SECS=7 -- --seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only osdkill --osd-kills 1 --recovery-max 5 --run-for 4
    # the ceph CLI that fails for a while (docs 40.3): the injector retries it and the injection counts as done; fails beyond the window; fails at once on a
    # wrong command; a monitor that is not back yet is waited for. Short windows (st_go sets 6 s and a 1 s pause): the stand-ins answer in no time
    local clic="--seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only outin --outins 1 --recovery-max 5 --run-for 4"
    local quor="--seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only monclean --mon-restarts 2 --recovery-max 5 --run-for 8"
    st_go "$d" cliretry "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=3 -- $clic
    st_go "$d" clirc124 "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=2 FI_STUB_CLI_RC=124 FI_STUB_CLI_ERR= -- $clic
    st_go "$d" clibeyond "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=-1 FI_CLI_RETRY_S=3 -- $clic
    st_go "$d" clieinval "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=-1 "FI_STUB_CLI_ERR=Error EINVAL: invalid osd id" -- $clic
    local upm="--seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only upmap --upmaps 1 --recovery-max 5 --run-for 4"
    st_go "$d" cliapply "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=2 FI_STUB_CLI_AFTER_APPLY=1 -- $clic
    st_go "$d" cliapplyin "FI_STUB_CLI_FAIL=osd in" FI_STUB_CLI_N=1 FI_STUB_CLI_AFTER_APPLY=1 -- $clic
    st_go "$d" cliapplyup "FI_STUB_CLI_FAIL=osd pg-upmap" FI_STUB_CLI_N=1 FI_STUB_CLI_AFTER_APPLY=1 -- $upm
    st_go "$d" cliapplyrm "FI_STUB_CLI_FAIL=osd rm-pg-upmap" FI_STUB_CLI_N=2 FI_STUB_CLI_AFTER_APPLY=1 -- $upm
    st_go "$d" clikey "FI_STUB_CLI_FAIL=osd out" FI_STUB_CLI_N=-1 FI_CLI_RETRY_S=2 "FI_STUB_CLI_ERR=[errno 110] RADOS timed out; key = AQBhZ2xhbmQgaXMgbm90IGEga2V5IGF0IGFsbCE9PQ==" -- $clic
    st_go "$d" cliquorum FI_STUB_QUORUM_DOWN=4 -- $quor
    st_go "$d" cliquorumout FI_STUB_QUORUM_DOWN=12 FI_QUORUM_WAIT=3 -- $quor
    st_go "$d" cliquorum2 FI_STUB_QUORUM_DOWN=3 -- --seed 5 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only monclean,outin --mon-restarts 2 --outins 2 --recovery-max 5 --run-for 14
    # a cluster that does not recover: exit 3, and what could be restored is
    st_go "$d" nowait -- --seed 3 --min-gap 1 --max-gap 1 --initial-delay 1 --pause-cap 1 --only outin --outins 1 --recovery-max 3 --run-for 5 --inject-fail wait-clean
    # a stop request in the middle of a fault
    mkdir -p "$d/sc-term/st" "$d/sc-term/work"
    ( PATH="$d/bin:$PATH" FI_STUB="$d/sc-term/st" WR_LAB_WORK="$d/sc-term/work" FI_POLL=0 FI_STATE_WAIT=0 FI_MON_WAIT=3 bash "$SELF" --seed 9 --min-gap 1 --max-gap 1 --initial-delay 1 --only outin --outins 3 --recovery-max 5 \
          > "$d/sc-term/out" 2>&1 &
      p=$!; for ((k = 0; k < 600; k++)); do grep -q "fault_inject: start seed" "$d/sc-term/out" 2>/dev/null && break; sleep 0.1; done   # the traps are in place from here
      sleep 2; kill -TERM "$p"; wait "$p"; echo $? > "$d/sc-term/rc" ) &
    # more signals while the restore runs (a second Ctrl-C, a TERM after the INT): they must not cut it short. The poll of one second makes the restore take
    # a few seconds, so the signals land inside it
    mkdir -p "$d/sc-term2/st" "$d/sc-term2/work"
    ( PATH="$d/bin:$PATH" FI_STUB="$d/sc-term2/st" WR_LAB_WORK="$d/sc-term2/work" FI_POLL=1 FI_STATE_WAIT=0 FI_MON_WAIT=3 bash "$SELF" --seed 9 --min-gap 1 --max-gap 1 --initial-delay 1 --only outin --outins 3 \
          --recovery-max 8 > "$d/sc-term2/out" 2>&1 &
      p=$!; for ((k = 0; k < 600; k++)); do grep -q "fault_inject: start seed" "$d/sc-term2/out" 2>/dev/null && break; sleep 0.1; done
      sleep 2; kill -TERM "$p"; sleep 1; kill -TERM "$p"; kill -INT "$p"; sleep 1; kill -HUP "$p"; wait "$p"; echo $? > "$d/sc-term2/rc" ) &
    # a baseline that is not whole: nothing is changed, status 2
    mkdir -p "$d/sc-notwhole/st" "$d/sc-notwhole/work"; echo 0 > "$d/sc-notwhole/st/osd.1.in"
    st_go "$d" notwhole -- --seed 1 --run-for 3

    # 1. the plan: a pure function of the seed, and the deck has the counts asked for
    plan1=$(py plan 4242 20 10 10 5 90 300 0 50); plan2=$(py plan 4242 20 10 10 5 90 300 0 50)
    [ "$plan1" = "$plan2" ] && st_ok "plan: the same seed gives the same plan" || st_bad "plan: the same seed gave two plans"
    [ "$plan1" != "$(py plan 4243 20 10 10 5 90 300 0 50)" ] && st_ok "plan: another seed gives another plan" || st_bad "plan: two seeds gave one plan"
    for k in "osdkill 20" "monkill 5" "monclean 5" "outin 10" "upmap 5"; do
        set -- $k
        c=$(printf '%s\n' "$plan1" | head -n 45 | awk -v k="$1" '$2 == k' | wc -l)
        [ "$c" -eq "$2" ] && st_ok "plan: the first 45 faults hold exactly $2 of $1" || st_bad "plan: $c of $1 in the first 45 faults, expected $2"
    done
    printf '%s\n' "$plan1" | awk '$3 < 90 || $3 > 300 { bad++ } $2 == "osdkill" && ($4 < 5 || $4 > 60) { bad++ } $2 == "outin" && ($4 < 10 || $4 > 60) { bad++ } END { exit bad != 0 }' \
        && st_ok "plan: gaps are 90 to 300 s, OSD pauses 5 to 60 s, out pauses 10 to 60 s" || st_bad "plan: a gap or a pause is out of its range"
    [ "$(printf '%s\n' "$(py plan 7 20 10 10 5 1 2 3 0)" | awk '$4 > 3' | wc -l)" -eq 0 ] && st_ok "plan: --pause-cap clamps every pause" || st_bad "plan: a pause is above the cap"

    # 1b. the state compare: only Ceph's own mclock capacity lines (option name exactly osd_mclock_max_capacity_iops_hdd / _ssd, added or changed) are noted, never a failure
    local sb="$d/sd.before" sa="$d/sd.after" sdo
    printf '%s\n' "osd osd.0 status=up" "config osd.1//osd_mclock_max_capacity_iops_hdd=466.054370" "config osd//osd_memory_target_autotune=true" > "$sb"
    sd_case() { # <name> <expected rc> <expected text or ""> <lines of the after file...>
        local name=$1 want=$2 text=$3; shift 3
        { cat "$sb"; printf '%s\n' "$@"; } | sort > "$sa"
        sort -o "$sb.sorted" "$sb"
        sdo=$(py statediff "$sb.sorted" "$sa" 2>&1); local rc=$?
        { [ "$rc" = "$want" ] && { [ -z "$text" ] || printf '%s' "$sdo" | grep -qF -- "$text"; }; } && st_ok "state compare: $name" || { st_bad "state compare: $name (rc $rc, wanted $want; output: $sdo)"; }
    }
    sd_case "no difference" 0 "" 
    sd_case "an added osd.2 hdd capacity line is a NOTE" 0 "NOTE  Ceph wrote osd.2//osd_mclock_max_capacity_iops_hdd: added, value 208.6" "config osd.2//osd_mclock_max_capacity_iops_hdd=208.6"
    sd_case "an added ssd capacity line is a NOTE" 0 "NOTE  Ceph wrote osd.0//osd_mclock_max_capacity_iops_ssd: added" "config osd.0//osd_mclock_max_capacity_iops_ssd=5000"
    sd_case "a global-scope capacity line is a NOTE" 0 "NOTE" "config global//osd_mclock_max_capacity_iops_hdd=100"
    sd_case "a masked capacity line is a NOTE" 0 "NOTE" "config osd/host:h1/osd_mclock_max_capacity_iops_hdd=100"
    sd_case "a changed capacity value is a NOTE (not a failure)" 0 "changed from 466.054370 to 500" "config osd.1//osd_mclock_max_capacity_iops_hdd=500"
    sd_case "a capacity line plus another added line fails" 1 "DIFF  + config osd//osd_memory_target=5" "config osd.2//osd_mclock_max_capacity_iops_hdd=208.6" "config osd//osd_memory_target=5"
    sd_case "a capacity line plus an OSD that is down fails" 1 "DIFF  + osd osd.1 status=down" "config osd.2//osd_mclock_max_capacity_iops_hdd=208.6" "osd osd.1 status=down"
    sd_case "a similar option name is not ignored" 1 "DIFF  + config osd.2//osd_mclock_max_capacity_iops_hdd_x=1" "config osd.2//osd_mclock_max_capacity_iops_hdd_x=1"
    sd_case "the capacity option under a client section is not ignored" 1 "DIFF  + config client.x//osd_mclock_max_capacity_iops_hdd=1" "config client.x//osd_mclock_max_capacity_iops_hdd=1"
    sd_case "the capacity option under a mon section is not ignored" 1 "DIFF  + config mon//osd_mclock_max_capacity_iops_ssd=1" "config mon//osd_mclock_max_capacity_iops_ssd=1"
    sd_case "the capacity option under osd.x (not a number) is not ignored" 1 "DIFF" "config osd.x//osd_mclock_max_capacity_iops_hdd=1"
    sd_case "another mclock option is not ignored" 1 "DIFF" "config osd.2//osd_mclock_scheduler_client_wgt=2"
    sd_case "a changed value of another option fails" 1 "DIFF  + config osd//osd_memory_target_autotune=false" "config osd//osd_memory_target_autotune=false"
    # a line that was there before and is gone: the capacity line may not vanish either (only added / changed ones are ignored)
    grep -v "osd_mclock_max_capacity_iops_hdd" "$sb" | sort > "$sa"; sort -o "$sb.sorted" "$sb"
    sdo=$(py statediff "$sb.sorted" "$sa" 2>&1); rc=$?
    [ "$rc" = 1 ] && printf '%s' "$sdo" | grep -qF "DIFF  - config osd.1//osd_mclock_max_capacity_iops_hdd=466.054370" && st_ok "state compare: a vanished capacity line fails" || st_bad "state compare: a vanished capacity line (rc $rc: $sdo)"

    # 2. the dry run: no cluster, nothing changed
    out=$(PATH="$d/empty:/usr/bin:/bin" bash "$SELF" --dry-run --seed 5 --osd-kills 2 --mon-restarts 2 --outins 1 --upmaps 1 2>&1); rc=$?
    case "$out" in *"seed 5"*"osdkill"*) [ "$rc" -eq 0 ] && st_ok "dry run: prints the plan and exits 0 without a cluster" || st_bad "dry run: exit $rc" ;; *) st_bad "dry run: no plan in the output: $out" ;; esac
    # an empty or a mistyped number is refused, not read as zero; leading zeros are decimal
    for k in "--osd-kills" "--recovery-max" "--min-gap"; do
        PATH="$d/bin:$PATH" FI_STUB="$d/sc-full/st" WR_LAB_WORK="$d/argwork" bash "$SELF" "$k" "" > "$d/args.out" 2>&1; rc=$?
        [ "$rc" -eq 2 ] && st_ok "argument check: '$k' with an empty value is refused with status 2" || st_bad "argument check: '$k' with an empty value gave status $rc"
    done
    out=$(PATH="$d/empty:/usr/bin:/bin" bash "$SELF" --dry-run --seed 5 --min-gap 08 --max-gap 09 --initial-delay 08 --osd-kills 08 2>&1); rc=$?
    [ "$rc" -eq 0 ] && st_ok "argument check: 08 and 09 are decimal numbers" || st_bad "argument check: 08 / 09 gave status $rc: $out"
    # bad arguments (no cluster is reached)
    for k in "--min-gap 0" "--min-gap 5 --max-gap 2" "--seed x" "--only bogus" "--bogus"; do
        # shellcheck disable=SC2086
        PATH="$d/bin:$PATH" FI_STUB="$d/sc-full/st" WR_LAB_WORK="$d/argwork" bash "$SELF" $k > "$d/args.out" 2>&1; rc=$?
        [ "$rc" -eq 2 ] && st_ok "argument check: '$k' is refused with status 2" || st_bad "argument check: '$k' gave status $rc"
    done

    # 3. the scenarios, in order
    st_wait
    st_judge "$d" full "a full run" 0
    if grep -q "osdkill=[1-9]" "$d/sc-full/out" && grep -q "outin=[1-9]" "$d/sc-full/out" && grep -q "upmap=[1-9]" "$d/sc-full/out"; then st_ok "a full run: osd kills, out/in and upmap faults all ran"; else st_bad "a full run: a kind of fault did not run"; sed 's/^/      | /' "$d/sc-full/out" | tail -n 8; fi
    grep -q "mon_restarts=[1-9]" "$d/sc-full/out" && st_ok "a full run: the monitor was restarted" || st_bad "a full run: no monitor restart"
    grep -q "state: the lab matches the snapshot" "$d/sc-full/out" && st_ok "a full run: the state matches the snapshot at the end" || st_bad "a full run: no state match line"
    for k in $steps; do
        step=${k%%:*}
        st_judge "$d" "step-$step" "failing step $step" any
        if grep -q "failed=[1-9]" "$d/sc-step-$step/out"; then st_ok "failing step $step: counted as a failed fault"
        elif [ "$step" = start-mon ]; then st_ok "failing step $step: not reached (systemd restarted the stand-in monitor)"
        else st_bad "failing step $step: not counted as failed"; sed 's/^/      | /' "$d/sc-step-$step/out" | tail -n 6; fi
    done
    st_judge "$d" mclock "mclock capacity lines written by the OSDs that restarted" 0
    grep -q "^NOTE  Ceph wrote osd.*osd_mclock_max_capacity_iops_hdd" "$d/sc-mclock/out" && st_ok "mclock: the lines are reported as NOTE" || st_bad "mclock: no NOTE line"
    grep -q "state: the lab matches the snapshot taken before (fi-after)" "$d/sc-mclock/out" && st_ok "mclock: the state still matches the snapshot" || st_bad "mclock: no state match line"
    grep -q "^FAIL" "$d/sc-mclock/out" && st_bad "mclock: a FAIL line" || st_ok "mclock: no FAIL line"
    [ -s "$d/sc-mclock/st/config.json" ] && grep -q osd_mclock_max_capacity "$d/sc-mclock/st/config.json" && st_ok "mclock: the Ceph-written lines were left in place (not restored or removed)" || st_bad "mclock: the lines are gone"
    rc=$(cat "$d/sc-mclockother/rc" 2>/dev/null)
    if [ "$rc" = 3 ] && grep -q "^FAIL  the cluster state differs" "$d/sc-mclockother/out" && grep -qF "osd_memory_target=1" "$d/sc-mclockother/out" && ! grep -q "state: the lab matches" "$d/sc-mclockother/out"; then
        st_ok "mclock plus another config change: exit 3, the state differs"
    else st_bad "mclock plus another config change: exit $rc"; sed 's/^/      | /' "$d/sc-mclockother/out" | tail -n 12; fi
    st_judge "$d" late "a recovery that is late but heals" 0
    if grep -q " late=1 " "$d/sc-late/out" && grep -qE "late_max_over_s=[1-9][0-9]* recovery_limit_s=5" "$d/sc-late/out" && ! grep -q "^FAIL" "$d/sc-late/out"; then
        st_ok "late recovery: counted (late=1, seconds past the limit in the summary), exit 0, no FAIL"
    else st_bad "late recovery: the summary does not show it"; sed 's/^/      | /' "$d/sc-late/out" | tail -n 8; fi
    # the ceph CLI retry (the selftest of 40.3): the classifier first, then the scenarios above
    fi_cli_class_check() { # <expected> <rc> <stderr text> <label>
        local f="$d/class.err" got; printf '%s\n' "$3" > "$f"; got=$(fi_cli_class "$2" "$f")
        [ "$got" = "$1" ] && st_ok "cli class: $4 is $1" || st_bad "cli class: $4 is $got, expected $1"
    }
    fi_cli_class_check transient 124 "" "rc 124 (the timeout of one attempt)"
    fi_cli_class_check transient 1 "[errno 110] RADOS timed out (error connecting to the cluster)" "RADOS timed out"
    fi_cli_class_check transient 1 "2026-01-01 monclient(hunting): authenticate timed out after 300" "monclient hunting"
    fi_cli_class_check transient 1 "Error ETIMEDOUT: no quorum" "no quorum"
    fi_cli_class_check transient 1 "unable to get monitor info from DNS SRV" "no monitor info"
    fi_cli_class_check transient 1 "[errno 111] error connecting to the cluster: Connection refused" "connection refused"
    fi_cli_class_check transient 1 "read error: Connection reset by peer" "connection reset"
    fi_cli_class_check transient 11 "Error EAGAIN: try again" "EAGAIN"
    fi_cli_class_check non-transient 1 "[errno 2] RADOS object not found (error connecting to the cluster)" "errno 2 (no ceph.conf or keyring: waiting does not create one)"
    fi_cli_class_check non-transient 1 "[errno 1] RADOS permission error (error connecting to the cluster)" "errno 1"
    fi_cli_class_check non-transient 22 "Error EINVAL: invalid command" "EINVAL"
    fi_cli_class_check non-transient 2 "Error ENOENT: osd.9 does not exist" "ENOENT"
    fi_cli_class_check non-transient 1 "Error EPERM: access denied" "EPERM"
    fi_cli_class_check non-transient 13 "Error EACCES: permission denied" "EACCES"
    fi_cli_class_check non-transient 22 "Error EINVAL: bad pg id (the operation timed out in the parser)" "EINVAL that mentions a timeout (the fatal text is read first)"
    fi_cli_class_check non-transient 124 "Error EINVAL: invalid osd id" "EINVAL even with rc 124"
    fi_cli_class_check non-transient 1 "something nobody has seen" "an unknown text"
    fi_cli_class_check non-transient 1 "" "rc 1 with no text"
    st_judge "$d" cliretry "ceph osd out fails 3 times with a connect timeout, then works" 0
    st_cmp "$d" cliretry failed -eq 0 "cli retry: the injection is not failed"
    st_cmp "$d" cliretry outin -ge 1 "cli retry: the out/in fault completed"
    st_cmp "$d" cliretry cli_retries -eq 3 "cli retry: the three retries are counted"
    st_cmp "$d" cliretry cli_recovered -eq 1 "cli retry: one call recovered"
    st_cmp "$d" cliretry cli_gave_up -eq 0 "cli retry: no call gave up"
    st_cmp "$d" cliretry cli_retry_max_s -ge 2 "cli retry: the retry time is measured"
    if [ "$(grep -c "cli attempt=[123] rc=1 class=transient during=1 cmd=\"ceph osd out" "$d/sc-cliretry/work/fault-events.log" 2>/dev/null)" = 3 ] \
       && grep -q "RADOS timed out" "$d/sc-cliretry/work/fault-events.log" && grep -q "cli recovered after 3 retries" "$d/sc-cliretry/work/fault-events.log" \
       && grep -q "cli attempt=3 rc=1" "$d/sc-cliretry/out"; then
        st_ok "cli retry: every attempt is in the events file and in the log with its rc, class, fault number and stderr"
    else st_bad "cli retry: the attempts are not logged as expected"; grep "cli " "$d/sc-cliretry/work/fault-events.log" | tail -n 6 | sed 's/^/      | /'; fi
    st_judge "$d" clirc124 "ceph osd out hit by the timeout of its attempt (rc 124, no text) twice" 0
    st_cmp "$d" clirc124 failed -eq 0 "rc 124: the injection is not failed"
    st_cmp "$d" clirc124 cli_retries -eq 2 "rc 124: two retries"
    grep -q "rc=124 class=transient" "$d/sc-clirc124/out" && st_ok "rc 124: logged as a transient attempt" || st_bad "rc 124: no transient line"
    st_judge "$d" clibeyond "ceph osd out fails for longer than the retry window" any
    st_cmp "$d" clibeyond failed -ge 1 "beyond the window: the injection is counted as failed"
    st_cmp "$d" clibeyond cli_gave_up -ge 1 "beyond the window: the call gave up"
    st_cmp "$d" clibeyond cli_retries -ge 2 "beyond the window: it was retried first"
    if grep -q "cli gave up after [0-9]* attempts" "$d/sc-clibeyond/out" && grep -qE "note=osd out failed \(rc=1 after [0-9]+ attempts: .*RADOS timed out" "$d/sc-clibeyond/out" \
       && grep -q "RADOS timed out" "$d/sc-clibeyond/work/fault-events.log"; then
        st_ok "beyond the window: the failure note of the fault carries rc, attempts and stderr; the events file has the attempts"
    else st_bad "beyond the window: no stderr in the failure note"; grep -E "note=|cli " "$d/sc-clibeyond/out" | tail -n 5 | sed 's/^/      | /'; fi
    st_judge "$d" clieinval "ceph osd out answers EINVAL" any
    st_cmp "$d" clieinval failed -ge 1 "EINVAL: the injection is failed at once"
    st_cmp "$d" clieinval cli_retries -eq 0 "EINVAL: no retry"
    if grep -q "class=non-transient" "$d/sc-clieinval/out" && ! grep -q "class=transient" "$d/sc-clieinval/out" && grep -q "Error EINVAL: invalid osd id" "$d/sc-clieinval/work/fault-events.log"; then
        st_ok "EINVAL: one attempt per call, classed non-transient, stderr in the events file"
    else st_bad "EINVAL: the log does not show a single non-transient attempt"; grep -E "cli " "$d/sc-clieinval/out" | tail -n 4 | sed 's/^/      | /'; fi
    # a command that was carried out but whose answer was lost is run again: out, in, pg-upmap and rm-pg-upmap give the same result twice (the lab says "already out" with status 0)
    st_judge "$d" cliapply "ceph osd out carried out, its answer lost, twice" 0
    st_cmp "$d" cliapply failed -eq 0 "answer lost (osd out): the injection is not failed"
    st_once "$d" cliapply outin "answer lost (osd out): counted once per fault, not once per run"
    st_cmp "$d" cliapply cli_retries -eq 2 "answer lost (osd out): two re-runs"
    st_judge "$d" cliapplyin "ceph osd in carried out, its answer lost" 0
    st_cmp "$d" cliapplyin failed -eq 0 "answer lost (osd in): the injection is not failed"
    st_judge "$d" cliapplyup "ceph osd pg-upmap carried out, its answer lost" 0
    st_cmp "$d" cliapplyup failed -eq 0 "answer lost (pg-upmap): the injection is not failed"
    st_once "$d" cliapplyup upmap "answer lost (pg-upmap): counted once per fault"
    st_judge "$d" cliapplyrm "ceph osd rm-pg-upmap carried out, its answer lost, twice" 0
    st_cmp "$d" cliapplyrm failed -eq 0 "answer lost (rm-pg-upmap): the injection is not failed"
    st_once "$d" cliapplyrm upmap "answer lost (rm-pg-upmap): counted once per fault"
    st_judge "$d" clikey "a CLI that prints something shaped like a cephx key" any
    if ! grep -rq "AQBhZ2xhbmQgaXMgbm90" "$d/sc-clikey/out" "$d/sc-clikey/work" 2>/dev/null && grep -q "<key removed>" "$d/sc-clikey/work/fault-events.log"; then
        st_ok "key-shaped text: removed from the log, the events file and the note"
    else st_bad "key-shaped text: it is in a log, or was not removed"; grep -rl "AQBhZ2xhbmQgaXMgbm90" "$d/sc-clikey" | head -n 3 | sed 's/^/      | /'; fi
    st_judge "$d" cliquorum "the monitor restarted, ceph silent for 4 invocations" 0
    st_cmp "$d" cliquorum failed -eq 0 "quorum wait: no failed injection"
    st_cmp "$d" cliquorum mon_restarts -ge 1 "quorum wait: the monitor was restarted"
    st_cmp "$d" cliquorum quorum_waits -ge 1 "quorum wait: a wait was needed and counted"
    st_cmp "$d" cliquorum quorum_wait_max_s -ge 3 "quorum wait: its length is measured"
    grep -q "quorum: the monitor answers again after 5 polls" "$d/sc-cliquorum/out" && grep -q "quorum: poll=1 rc=1 class=transient" "$d/sc-cliquorum/out" && grep -q "RADOS timed out" "$d/sc-cliquorum/work/fault-events.log" \
        && st_ok "quorum wait: every poll is logged with rc and stderr, then the first answer" || st_bad "quorum wait: the polls are not logged as expected"
    st_judge "$d" cliquorumout "the monitor does not answer within the quorum wait" any
    st_cmp "$d" cliquorumout failed -ge 1 "no quorum in time: the fault is counted as failed"
    st_cmp "$d" cliquorumout quorum_gave_up -ge 1 "no quorum in time: the wait is counted as given up"
    grep -qE "note=the monitor did not answer within 3 s after its restart \(rc=1 after [0-9]+ attempts: .*RADOS timed out" "$d/sc-cliquorumout/out" \
        && st_ok "no quorum in time: the note names the wait and the last stderr" || { st_bad "no quorum in time: no note"; grep -E "note=|quorum" "$d/sc-cliquorumout/out" | tail -n 4 | sed 's/^/      | /'; }
    st_judge "$d" cliquorum2 "a monitor restart and out/in faults mixed" 0
    st_cmp "$d" cliquorum2 failed -eq 0 "mixed: no failed injection"
    st_cmp "$d" cliquorum2 cli_retries -eq 0 "mixed: the commands after a restart needed no retry (the wait came first)"
    st_cmp "$d" cliquorum2 quorum_waits -ge 1 "mixed: the quorum wait ran"
    st_judge "$d" nowait "recovery never completes" 3
    if why=$(st_lab_whole "$d/sc-term"); then st_ok "SIGTERM mid-run: the lab is whole again"; else st_bad "SIGTERM mid-run: $why"; fi
    [ "$(cat "$d/sc-term/rc" 2>/dev/null)" = 0 ] && st_ok "SIGTERM mid-run: exit 0 after the restore" || st_bad "SIGTERM mid-run: exit $(cat "$d/sc-term/rc" 2>/dev/null)"
    if why=$(st_lab_whole "$d/sc-term2"); then st_ok "SIGTERM, then SIGTERM, SIGINT and SIGHUP during the restore: the lab is whole again"; else st_bad "repeated signals: $why"; sed 's/^/      | /' "$d/sc-term2/out" | tail -n 8; fi
    [ "$(cat "$d/sc-term2/rc" 2>/dev/null)" = 0 ] && grep -q "state: the lab matches the snapshot" "$d/sc-term2/out" && st_ok "repeated signals: the restore ran to its end (exit 0, state compared)" \
        || { st_bad "repeated signals: exit $(cat "$d/sc-term2/rc" 2>/dev/null), the restore did not finish"; sed 's/^/      | /' "$d/sc-term2/out" | tail -n 8; }
    rc=$(cat "$d/sc-notwhole/rc" 2>/dev/null)
    [ "$rc" = 2 ] && [ "$(cat "$d/sc-notwhole/st/osd.1.in")" = 0 ] && st_ok "a start with an OSD out: refused (status 2), nothing changed" || st_bad "a start with an OSD out: status $rc"
    case "$d" in /*/fault-inject-selftest.??????) rm -rf "$d" ;; esac
    echo
    echo "fault_inject selftest: $ST_PASS passed, $ST_FAIL failed"
    [ "$ST_FAIL" -eq 0 ]
}

if [ "$fi_sourced" -eq 0 ]; then
    fi_main "$@"
fi
