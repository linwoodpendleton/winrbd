#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# secure-live.sh: the live matrix of milestone 11 (docs/design/core-architecture.md 39.2, module secure-live): the winrbd core in msgr2 SECURE mode
# against the REAL lab cluster, with the stock tools (rbd, ceph) as the oracle, and the lab put back exactly as it was whatever happens.
#
#   client        (1) client-side secure against the default cluster, both cephx key types: wr-rbd info / fill / verify / random / compare with
#                 --mode secure --require-mode secure (every connection secure, no tag / nonce / secret failure), the data checked against the
#                 stock `rbd export` (what the core wrote is what the stock tool reads, what the stock tool wrote is what the core reads), the
#                 AES-NI hook (--accel) when this CPU has it, wr-monprobe, the wire (tcpdump: the pattern of a crc run is seen on the client's own
#                 connections, not one run of it in a secure run of the same size; the OSDs' replication among themselves is not the client's
#                 traffic and is left out), a wrong secret refused; then (section krbd) wr-krbdcmp with krbd mapped ms_mode=secure
#                 (harness/lab/krbd-compare.sh --mode secure)
#   policy        (2) the five offer policies (crc, crc-first, secure-first, secure, stock) against the default cluster: which mode the monitor
#                 connection and the OSD connections of each ended in (conns_secure / conns_crc of the stats line), next to what the stock client
#                 gets with the same options (rbd --debug_ms=1)
#   forced-secure (3) the cluster forced to secure (ms_mon_service_mode and ms_service_mode secure, the monitor restarted, then every OSD one at a
#                 time: the options are startup-only): a crc-only client is refused with WR_E_M2_BAD_METHOD and allowed modes {secure} (the
#                 result code of the refusal captured), an OSD-only refusal too, a secure-first / crc-first / stock / secure client works
#   forced-crc    the reverse: the service modes set to crc, a secure-only client refused with {crc}, a secure-first client works (in crc)
#   (4) always: the lab is restored (options removed or set back to their original values, the monitor and the OSDs restarted one at a time,
#               HEALTH, the OSD tree, the upmaps, the config database and the daemon list compared with the snapshot taken first), then
#               checked behaviourally: a crc-only and a secure-only client both work again
#
# What is guaranteed (the EXIT trap, also on a failing step, Ctrl-C and kill): the four mode options are put back, the daemons are restarted one
# at a time when they ran with other settings, the images, the throwaway cephx user and the work files are removed, and the cluster state (health
# checks, OSD tree and flags, upmaps, config database, the four options one by one, pools, daemon list) is compared with the snapshot taken before.
# The only cluster options this script ever sets are the four of the lab rules: ms_mon_service_mode, ms_service_mode, ms_mon_client_mode,
# ms_client_mode (it sets the first two, and reverts all four, but only in a run that set one: a run that set none, such as --skip-forced, never
# writes them, and when they change under it, another run forcing the cluster, it reports that and leaves them). Names are wrtest-sl-*; nothing
# else is touched (never img-default, img-v1, the pool winrbd, the keys or caps of the existing users, OSDs or mons: they are only restarted). Key
# material is never printed.
#
# Usage (inside the lab VM, as a user with passwordless sudo):
#   harness/lab/secure-live.sh [--keys k2|k1|both] [--only a,b,..] [--skip-forced] [--skip-krbd] [--quick] [--capture-dir DIR] [--keep]
#   harness/lab/secure-live.sh --selftest [--inject-fail STEP]   the whole script against stand-in cluster tools (no lab needed)
#
#   --keys         which cephx key types the core uses: k2 = client.winrbd (aes256k), k1 = client.winrbd-aes (legacy aes), both (default)
#   --only         sections to run: client, krbd, policy, forced-secure, forced-crc (default all; "forced" = both forced sections)
#   --skip-forced  leave out the two sections that restart the monitor and the OSDs (the run then changes nothing on the cluster)
#   --skip-krbd    leave out the krbd comparison (it needs `rbd map` and runs for minutes)
#   --quick        shorter random runs, one image order for krbd, fewer krbd operations
#   --capture-dir  keep the refusal captures here: one text file per refusal (the tool's own lines with the result code and the allowed modes)
#                  and, when tcpdump exists, a pcap of each refusal made with a throwaway cephx user (client.wrtest-sl-*, removed at the end)
#   --keep         do not remove the images and the work directory at the end (the cluster is still restored)
#   --selftest     run the script against stand-ins for ceph / rbd / systemctl / wr-rbd / wr-monprobe that model a cluster whose daemons read the
#                  four options at restart; a full run must pass, and with a failure injected at every step the restore must still run
#                  (--inject-fail STEP: the script fails that step once; the step names are the ones the selftest uses)
#
# Environment: WR_BUILD_DIR (default <repo>/build/harness: wr-rbd and wr-monprobe are there), WR_LAB_MON (10.77.0.10:3300), WR_LAB_POOL (winrbd),
# WR_LAB_KEYRING_DIR (~/keys: client.<user>.keyring), WR_LAB_KEYRING_K2 / WR_LAB_KEYRING_K1 (explicit keyring files, as the lab ctests name them),
# WR_LAB_USER_K2 (winrbd), WR_LAB_USER_K1 (winrbd-aes), WR_LAB_WORK (~/w/secure-live-run),
# WR_LAB_SUDO (sudo), SL_KRBD_COMPARE (the krbd comparison script), SL_HEALTH_IGNORE (health checks left out of the state comparison),
# SL_STATE_WAIT (seconds to wait for the state to settle, default 180), SL_RESTART_WAIT (seconds each daemon gets to come back and the PGs to be
# clean again, default 300), SL_WIRE_MIN_BYTES (the payload the wire check's secure capture must hold on the client's own connections to count as
# seeing the data, default 4194304), SL_NAME_TAG, SL_INJECT_FAIL=<step> (as --inject-fail).
#
# Exit status: 0 every check passed and the lab is as it was; 1 a check failed, the restore failed or the state differs; 2 setup problem (usage, a
# missing tool or keyring, the lab unreachable). The last lines name the failed checks.

set -u
set -o pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
repo=$(cd "$here/../.." && pwd -P)
SELF="$here/$(basename "${BASH_SOURCE[0]}")"

build=${WR_BUILD_DIR:-$repo/build/harness}
WR=${WR_RBD:-$build/wr-rbd}
WRMP=${WR_MONPROBE:-$build/wr-monprobe}
KRBDCMP_SH=${SL_KRBD_COMPARE:-$here/krbd-compare.sh}
MON=${WR_LAB_MON:-10.77.0.10:3300}
POOL=${WR_LAB_POOL:-winrbd}
KEYDIR=${WR_LAB_KEYRING_DIR:-$HOME/keys}
KEYRING_K2=${WR_LAB_KEYRING_K2:-}   # explicit keyring files (the lab ctest names them); else $KEYDIR/client.<user>.keyring
KEYRING_K1=${WR_LAB_KEYRING_K1:-}
USER_K2=${WR_LAB_USER_K2:-winrbd}
USER_K1=${WR_LAB_USER_K1:-winrbd-aes}
WORK=${WR_LAB_WORK:-$HOME/w/secure-live-run}
SUDO=${WR_LAB_SUDO:-sudo}
HEALTH_IGNORE=${SL_HEALTH_IGNORE:-BLUESTORE_SLOW_OP_ALERT,SLOW_OPS,PG_NOT_DEEP_SCRUBBED,PG_NOT_SCRUBBED,RECENT_CRASH}
STATE_WAIT=${SL_STATE_WAIT:-180}
RESTART_WAIT=${SL_RESTART_WAIT:-300}
NAME_TAG=${SL_NAME_TAG:-$$}
INJECT=${SL_INJECT_FAIL:-}
TOOL_TMO=${SL_TOOL_TIMEOUT:-900}
WIRE_MIN_BYTES=${SL_WIRE_MIN_BYTES:-4194304}

# the four options this script may ever touch (the lab rules name exactly these)
MODE_OPTS="ms_mon_service_mode ms_service_mode ms_mon_client_mode ms_client_mode"

die()  { echo "secure-live: error: $*" >&2; exit 2; }
info() { echo "secure-live: $*" >&2; }

keys=both; only=""; skip_forced=0; skip_krbd=0; quick=0; capdir=""; keep=0; selftest=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keys) keys=${2:-}; shift ;;
        --only) only=${2:-}; shift ;;
        --skip-forced) skip_forced=1 ;;
        --skip-krbd) skip_krbd=1 ;;
        --quick) quick=1 ;;
        --capture-dir) capdir=${2:-}; shift ;;
        --keep) keep=1 ;;
        --selftest) selftest=1 ;;
        --inject-fail) INJECT=${2:-}; shift ;;
        -h|--help) sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done
case "$keys" in k2|k1|both) ;; *) die "--keys takes k2, k1 or both" ;; esac
if [ -n "$only" ]; then
    only_x=""
    for s in ${only//,/ }; do
        case "$s" in
            client|krbd|policy|forced-secure|forced-crc) only_x="$only_x,$s" ;;
            forced) only_x="$only_x,forced-secure,forced-crc" ;;
            *) die "--only takes client, krbd, policy, forced-secure, forced-crc or forced (got $s)" ;;
        esac
    done
    only=${only_x#,}
fi
case "$STATE_WAIT$RESTART_WAIT" in *[!0-9]*|'') die "SL_STATE_WAIT and SL_RESTART_WAIT take seconds" ;; esac
case "$WIRE_MIN_BYTES" in *[!0-9]*|'') die "SL_WIRE_MIN_BYTES takes a byte count" ;; esac

want() { # <section>: is it selected?
    case "$1" in forced-*) [ "$skip_forced" -eq 0 ] || return 1 ;; krbd) [ "$skip_krbd" -eq 0 ] || return 1 ;; esac
    [ -z "$only" ] && return 0
    case ",$only," in *",$1,"*) return 0 ;; esac
    return 1
}

kr_of() { # <cephx user id> -> its keyring file
    if [ "$1" = "$USER_K2" ] && [ -n "$KEYRING_K2" ]; then echo "$KEYRING_K2"
    elif [ "$1" = "$USER_K1" ] && [ -n "$KEYRING_K1" ]; then echo "$KEYRING_K1"
    else echo "$KEYDIR/client.$1.keyring"; fi
}

# ---- the commands, as the rest of the script calls them (the selftest puts stand-ins first in PATH) -----------------------------------------
RBD()    { $SUDO rbd "$@"; }
CEPH()   { $SUDO timeout 60 ceph --connect-timeout 10 "$@"; }
SYSCTL() { $SUDO systemctl "$@"; }

TRACK="$WORK/track"
FINAL_RC=0
CHILD=""
TCPDUMP_FILE=""

# SL_INJECT_FAIL is one step name or a comma separated list. An injected step fails ONCE (its first call): the selftest proves that the restore runs
# after a failing step, so the restore's own calls of the same step must be able to work.
inject() {
    case ",$INJECT," in *",$1,"*) ;; *) return 1 ;; esac
    [ ! -e "$WORK/injected.$1" ] || return 1
    : > "$WORK/injected.$1"
    return 0
}

# step <name> <command...>: run a command; a step named by SL_INJECT_FAIL fails without running (what the selftest uses).
step() {
    local name=$1; shift
    if inject "$name"; then
        echo "secure-live: injected failure at step '$name'" >&2
        return 99
    fi
    "$@"
}

# ---- reporting ---------------------------------------------------------------------------------------------------------------------------------
PASS=0; FAIL=0; FAILED=(); OUT=""; RC=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("$*"); echo "FAIL  $*"; if [ -n "$OUT" ]; then printf '%s\n' "$OUT" | tail -n 6 | cut -c1-300 | sed 's/^/      | /'; fi; }
note() { echo "NOTE  $*"; }
sect() { echo; echo "=== $* ==="; }
expect_rc()  { if [ "$RC" -eq "$1" ]; then ok "$2"; else bad "$2 (exit $RC, wanted $1)"; fi; }
expect_out() { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then ok "$2"; else bad "$2 (no match for: $1)"; fi; }
expect_no()  { if printf '%s\n' "$OUT" | grep -Eq -- "$1"; then bad "$2 (found: $1)"; else ok "$2"; fi; }
field() { printf '%s\n' "$OUT" | sed -n "s/.*[ @]$1=\([^ ]*\).*/\1/p" | tail -n 1; } # last value of key=value in the output

# runc <command...>: run a command in the background and wait for it (a trapped signal ends the wait at once, so the EXIT trap is not held up by
# a long command); sets OUT (stdout + stderr) and RC
runc() {
    local f="$WORK/.out.$$"
    "$@" > "$f" 2>&1 &
    CHILD=$!
    wait "$CHILD"; RC=$?
    CHILD=""
    OUT=$(cat "$f" 2>/dev/null); rm -f "$f"
}

CUR_USER=""; CUR_KR=""
WR_EVENTS=0   # 1: keep the tool's event lines (the refusals are in them)
wr() { # <image> <args...>: run wr-rbd as the current user; sets OUT and RC
    local img=$1 so=(--stats-only); shift
    [ "$WR_EVENTS" -eq 0 ] || so=()
    runc timeout --kill-after=15 "$TOOL_TMO" "$WR" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" --pool "$POOL" --image "$img" ${so[@]+"${so[@]}"} "$@"
}
wrmp() { # <args...>: wr-monprobe as the current user
    runc timeout --kill-after=15 120 "$WRMP" --mon "$MON" --user "$CUR_USER" --keyring "$CUR_KR" "$@"
}

# ---- the python helper (JSON of the stock tools -> one comparable text) ---------------------------------------------------------------------------
PYLIB=""
write_pylib() {
    PYLIB="$WORK/sl.py"
    cat > "$PYLIB" <<'PY'
import json, re, sys

MODE_OPTS = sys.argv[2].split() if len(sys.argv) > 2 else []

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
elif cmd == "osdports":  # stdin: osd dump json -> the v2 ports of the OSDs, space separated
    try:
        d = json.load(sys.stdin)
    except Exception:
        sys.exit(3)
    ports = set()
    for o in d.get("osds") or []:
        for a in ((o.get("public_addrs") or {}).get("addrvec") or []):
            if a.get("type") == "v2":
                ports.add(a["addr"].rsplit(":", 1)[1])
    print(" ".join(sorted(ports)))
elif cmd == "stockmodes":  # stockmodes <osd ports...>; stdin: a `rbd --debug_ms=1` log -> "mon=<modes> osd=<modes>" of the established connections
    # (the manager listens on a port of the same range as the OSDs: only the ports named here are OSDs; everything else that is not a monitor is ignored)
    osd_ports = set(sys.argv[2:])
    seen = {"mon": set(), "osd": set()}
    rx = re.compile(r">> \[v2:[0-9a-fA-F.:]+?:(\d+)/\d+[^\]]*\].*?msgr2=0x[0-9a-f]+ (crc|secure) ")
    for line in sys.stdin:
        m = rx.search(line)
        if m:
            if m.group(1) in ("3300", "6789"):
                seen["mon"].add(m.group(2))
            elif m.group(1) in osd_ports:
                seen["osd"].add(m.group(2))
    print(" ".join("%s=%s" % (k, "+".join(sorted(v)) if v else "none") for k, v in sorted(seen.items())))
elif cmd == "wire":     # wire <pcap> <port...> -> "<runs> <bytes>": runs of the pattern and TCP payload bytes on the connections that have one of
    # the ports at one end (the client's own connections: the monitor and the OSDs' public ports). The OSDs replicate a write to each other over the
    # cluster network, whose mode is not the client's: on the stock cluster that is crc, so the written data IS on the wire there in the clear
    import struct
    ports = set(int(x) for x in sys.argv[3:] if x.isdigit())
    try:
        with open(sys.argv[2], "rb") as f:
            d = f.read()
    except OSError:
        sys.exit(3)
    if len(d) < 24 or not ports:
        sys.exit(3)
    if d[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        e = "<"
    elif d[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        e = ">"
    else:
        sys.exit(3)
    hl = {1: 14, 12: 0, 101: 0, 113: 16, 276: 20}.get(struct.unpack_from(e + "I", d, 20)[0] & 0xffff)  # Ethernet, raw IP, Linux cooked v1 / v2
    if hl is None:
        sys.exit(3)
    pa, pb = bytes(range(64)), bytes(range(64, 128))
    runs = nbytes = 0
    off = 24
    while off + 16 <= len(d):
        incl = struct.unpack_from(e + "I", d, off + 8)[0]
        pkt = d[off + 16:off + 16 + incl]
        off += 16 + incl
        ip = pkt[hl:]
        if len(ip) >= 20 and ip[0] >> 4 == 4 and ip[9] == 6:
            t = ip[(ip[0] & 15) * 4:]
        elif len(ip) >= 40 and ip[0] >> 4 == 6 and ip[6] == 6:
            t = ip[40:]
        else:
            continue
        if len(t) < 20:
            continue
        sp, dp = struct.unpack_from(">HH", t, 0)
        if sp not in ports and dp not in ports:
            continue
        pl = t[(t[12] >> 4) * 4:]
        nbytes += len(pl)
        runs += pl.count(pa) + pl.count(pb)
    print("%d %d" % (runs, nbytes))
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
PY
}
py() { python3 -I "$PYLIB" "$@"; }

# ---- cluster state -----------------------------------------------------------------------------------------------------------------------------
# modes_snapshot <outfile>: the four options as the config database holds them ("name<TAB>who<TAB>value", sorted); 1 when the cluster cannot say
modes_snapshot() {
    local o=$1 j
    j=$(CEPH config dump -f json 2>/dev/null) || return 1
    [ -n "$j" ] || return 1
    printf '%s' "$j" | py modes "$MODE_OPTS" > "$o.tmp" || { rm -f "$o.tmp"; return 1; }
    mv "$o.tmp" "$o"
}

state_snapshot() { # <outfile>
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
state_compare() { # <before> <label>
    local before=$1 label=$2 waited=0 after="$WORK/state.$2"
    while :; do
        state_snapshot "$after"
        if diff -u "$before" "$after" > "$after.diff"; then
            echo "state: the lab matches the snapshot taken before ($label)"
            return 0
        fi
        [ "$waited" -ge "$STATE_WAIT" ] && break
        CEPH orch ps --refresh >/dev/null 2>&1
        sleep 10
        waited=$((waited + 10))
    done
    echo "FAIL  the cluster state differs from the snapshot taken before the run:" >&2
    sed 's/^/      | /' "$after.diff" >&2
    return 1
}

BASE_OSDS=0
POLL=${SL_POLL:-3}
wait_clean() { # <seconds>: every OSD up and in, every PG active+clean, on two polls in a row (the manager's PG statistics lag the monitor's
    # OSD map by a few seconds: one clean report right after a restart can still be the one from before it, and the next daemon must not go down
    # while the PGs of the last one are still peering: with three replicas and min_size 2 that would stop the I/O)
    local t=${1:-300} end good=0
    end=$((SECONDS + t))
    while :; do
        if CEPH osd stat -f json 2>/dev/null | py osdup "$BASE_OSDS" && CEPH pg stat -f json 2>/dev/null | py pgclean >/dev/null; then
            good=$((good + 1))
            [ "$good" -lt 2 ] || return 0
        else
            good=0
        fi
        [ "$SECONDS" -lt "$end" ] || return 1
        sleep "$POLL"
    done
}

# ---- the four options, and the daemons that read them at startup -------------------------------------------------------------------------------
# A flag file says that the daemons may run with options other than the original ones (set before the first `config set`, cleared after a restart
# of every daemon under the original options): the EXIT trap restarts them in that case.
mark_stale() { : > "$WORK/stale"; rm -f "$WORK/restarted"; }

# 1 once this run has set (or tried to set) one of the four options. A run that never did must not revert them: another run (the exit run, a second
# copy of this script with another work directory) may have forced the cluster in the meantime, and putting the options back under it, then leaving
# its daemons on settings it did not choose, would break that run. Such a change is reported (and the state comparison fails), never undone.
TOUCHED=0

modes_match_baseline() { # 0 when the config database holds exactly the original four options
    local cur="$WORK/modes.cur"
    modes_snapshot "$cur" || return 2
    cmp -s "$WORK/modes.before" "$cur"
}

set_mode_opt() { # <who: mon|osd> <name> <value>
    local who=$1 name=$2 value=$3 n ok=0
    for n in $MODE_OPTS; do [ "$n" = "$name" ] && ok=1; done
    [ "$ok" -eq 1 ] || die "refusing to set $name: only $MODE_OPTS may be changed"
    case "$who" in mon|osd) ;; *) die "refusing to set $name for '$who'" ;; esac
    case "$value" in secure|crc|"crc secure"|"secure crc") ;; *) die "refusing to set $name to '$value'" ;; esac
    TOUCHED=1
    mark_stale
    if ! step "set-$who-$name-$value" CEPH config set "$who" "$name" "$value"; then
        # nothing changed and nothing restarted since: the daemons still run with the original options
        if modes_match_baseline && [ ! -e "$WORK/restarted" ]; then rm -f "$WORK/stale"; fi
        return 1
    fi
}

# every option set (or removed) that differs from the snapshot taken first is put back; 0 when the database matches afterwards
revert_modes() {
    local cur="$WORK/modes.cur" name who value rc=0
    modes_snapshot "$cur" || { echo "FAIL  cannot read the config database to put the four options back" >&2; return 1; }
    while IFS=$'\t' read -r name who value; do   # set now but not in the original: remove
        [ -n "$name" ] || continue
        echo "secure-live: restore: removing $name of $who (was: $value)" >&2
        CEPH config rm "$who" "$name" >/dev/null 2>&1 || rc=1
    done < <(LC_ALL=C comm -13 "$WORK/modes.before" "$cur")
    while IFS=$'\t' read -r name who value; do   # in the original but not (or not the same) now: set back
        [ -n "$name" ] || continue
        echo "secure-live: restore: setting $name of $who back to '$value'" >&2
        CEPH config set "$who" "$name" "$value" >/dev/null 2>&1 || rc=1
    done < <(LC_ALL=C comm -23 "$WORK/modes.before" "$cur")
    modes_match_baseline || rc=1
    return $rc
}

daemon_units() { # mon units first, then the OSDs by id
    SYSCTL list-units --type=service --all --no-legend --plain 'ceph-*@mon.*.service' 'ceph-*@osd.*.service' 2>/dev/null | py units
}

# restart_all: the monitor, then every OSD one at a time, each waited for until the cluster is clean again (the options are read at startup).
# 0 when every daemon came back and the cluster is clean.
restart_all() {
    local u kind rc=0 n=0 units=()
    # the list is read first: a command of the loop body that reads its standard input must not eat the rest of it
    mapfile -t units < <(daemon_units)
    for u in ${units[@]+"${units[@]}"}; do
        [ -n "$u" ] || continue
        n=$((n + 1))
        case "$u" in *@mon.*) kind=mon ;; *) kind=osd ;; esac
        info "restarting ${u#*@}"
        # the cephadm units refuse a restart after five starts in a short time ("start-limit-hit"): reset the counter first, as osd_fault_lab.sh does
        SYSCTL reset-failed "$u" >/dev/null 2>&1
        if ! step "restart-$kind" SYSCTL restart "$u"; then
            echo "FAIL  could not restart $u" >&2
            rc=1
            continue
        fi
        if ! wait_clean "$RESTART_WAIT"; then
            echo "FAIL  after restarting $u the cluster did not become clean within $RESTART_WAIT s: $(CEPH pg stat 2>&1 | head -n 1)" >&2
            rc=1
        fi
    done
    [ "$n" -gt 0 ] || { echo "FAIL  found no ceph mon / osd unit to restart" >&2; return 1; }
    : > "$WORK/restarted"
    return $rc
}

# restore_cluster: idempotent; options back, daemons restarted when they ran with other options, 0 when the options match and the restart worked
restore_cluster() {
    local rc=0 m=0
    modes_match_baseline || m=$?
    if [ "$m" -ne 0 ] && [ "$TOUCHED" -eq 1 ]; then
        revert_modes || rc=1
    elif [ "$m" -eq 1 ]; then
        echo "FAIL  the four mode options changed during the run although this run set none of them (another run may be forcing the cluster): left as they are" >&2
        rc=1
    fi
    if [ -e "$WORK/stale" ]; then
        info "restoring: restarting the monitor and the OSDs under the original options"
        if restart_all; then rm -f "$WORK/stale"; else rc=1; fi
    fi
    return $rc
}

# ---- images and the throwaway cephx user (what this run made, so the trap can remove it) -----------------------------------------------------------
track_image() { echo "$1" > "$TRACK/$2.image"; }
THROW_USER=""; THROW_KR=""

cleanup_tracked() {
    local f img rc=0
    shopt -s nullglob
    for f in "$TRACK"/*.image; do
        img=$(cat "$f")
        [ "$keep" = 1 ] && continue
        if RBD rm "$img" >/dev/null 2>&1 || ! RBD info "$img" >/dev/null 2>&1; then rm -f "$f"; else echo "FAIL  could not remove image $img" >&2; rc=1; fi
    done
    shopt -u nullglob
    if [ -n "$THROW_USER" ]; then
        if CEPH auth del "client.$THROW_USER" >/dev/null 2>&1 || ! CEPH auth get "client.$THROW_USER" >/dev/null 2>&1; then THROW_USER=""; else echo "FAIL  could not delete client.$THROW_USER" >&2; rc=1; fi
    fi
    return $rc
}

quiet() { "$@" >/dev/null 2>&1; }   # a command whose output is of no interest, as a step's command (a redirect on `step` would hide its own messages)

make_image() { # <suffix> <size> -> sets IMG (name); the image has the layering feature only (the writer profile)
    IMG="wrtest-sl-$NAME_TAG-$1"
    track_image "$POOL/$IMG" "$1"
    step "create-$1" RBD create --size "$2" --image-feature layering "$POOL/$IMG"
}

# ---- tcpdump of a refusal (best effort) --------------------------------------------------------------------------------------------------------
mon_host=${MON%%[, ;]*}; mon_host=${mon_host#v2:}
case "$mon_host" in
    \[*) mon_host=${mon_host#\[}; mon_host=${mon_host%%\]*} ;;   # [v6addr]:port
    *) mon_host=${mon_host%:*} ;;                                  # v4addr:port
esac
mon_port=${MON%%[, ;]*}; mon_port=${mon_port#v2:}
case "$mon_port" in
    *\]:*) mon_port=${mon_port##*\]:} ;;
    *.*:*) mon_port=${mon_port##*:} ;;
    *) mon_port=3300 ;;
esac
case "$mon_port" in *[!0-9]*|'') mon_port=3300 ;; esac

# client_ports: the ports of the client's own connections, the monitor's and the OSDs' public v2 ports as the OSD map says now (they change when an
# OSD restarts). A capture is limited to them: the daemons of the lab talk to each other on the same host, and what an OSD replicates over the
# cluster network (in the clear on the stock cluster) or what the manager sends is neither the client's traffic nor anything a capture should keep.
client_ports() { echo "$mon_port $(CEPH osd dump -f json 2>/dev/null | py osdports)"; }
client_bpf() { # <ports...> -> the capture filter
    local p f=""
    for p in "$@"; do f="$f${f:+ or }port $p"; done
    echo "tcp and host $mon_host${f:+ and ($f)}"
}
# tcpdump_start <file>: the file must end in .pcap (the distribution's AppArmor profile of tcpdump only lets it write those). The lock descriptor is
# closed for the background process: a capture that outlived the script must not hold the lock of the run.
tcpdump_start() { # <file> [<ports...>]: without ports, the ports of the client's connections now
    local f=$1; shift
    command -v tcpdump >/dev/null 2>&1 || return 1
    [ $# -gt 0 ] || set -- $(client_ports)
    TCPDUMP_FILE=$f
    $SUDO tcpdump -i any -U -s 0 -w "$TCPDUMP_FILE" "$(client_bpf "$@")" >/dev/null 2>&1 9>&- &
    sleep 1
}
tcpdump_stop() {
    [ -n "$TCPDUMP_FILE" ] || return 0
    sleep 1
    $SUDO pkill -TERM -f -- "tcpdump -i any -U -s 0 -w $TCPDUMP_FILE" 2>/dev/null
    sleep 1
    $SUDO chown "$(id -u):$(id -g)" "$TCPDUMP_FILE" 2>/dev/null
    chmod 600 "$TCPDUMP_FILE" 2>/dev/null
    TCPDUMP_FILE=""
}
capture_start() { # <file>: only with --capture-dir, and only for the throwaway user: a capture keeps the handshake bytes of the connection, and the
    # winrbd / winrbd-aes users (whose keys never leave the lab) must not be in a file that is meant to be kept and may be published
    [ -n "$capdir" ] || return 0
    [ -n "$THROW_USER" ] && [ "$CUR_USER" = "$THROW_USER" ] || return 0
    tcpdump_start "$1" || true
}
capture_stop() { tcpdump_stop; }

# ---- one refusal: the tool's lines with the result code and the allowed modes --------------------------------------------------------------------
# refusal_check <label> <allowed-bits> <monprobe|rbd> <args...>: run the tool as the current user and check that the offer was refused with
# WR_E_M2_BAD_METHOD, that the allowed modes are the wanted ones (the tools print bit v for connection mode v, crc = 1 and secure = 2: {crc} is
# 0x2 and {secure} is 0x4), that the tool names the setting to change, and print / keep the result code the server sent (the numeric result of the
# refusal is captured here, not assumed: -95, EOPNOTSUPP, on a Linux server)
refusal_check() {
    local label=$1 want=$2 tool=$3; shift 3
    local lines allowed pr amode rmode side setting ca cr
    if [ "$want" = 0x4 ]; then amode=secure; rmode=crc; else amode=crc; rmode=secure; fi
    case "$label" in *-osd-*) side=OSD; setting=mode_policy_osd ;; *) side=monitor; setting=mode_policy ;; esac
    capture_start "${capdir:+$capdir/refusal-$label.pcap}"
    WR_EVENTS=1
    if [ "$tool" = rbd ]; then wr "$IMG_A" "$@"; else wrmp "$@"; fi
    WR_EVENTS=0
    capture_stop
    lines=$(printf '%s\n' "$OUT" | grep 'status=WR_E_M2_BAD_METHOD' | head -n 4)
    allowed=$(printf '%s\n' "$lines" | sed -n 's/.*allowed_modes=\(0x[0-9a-f]*\).*/\1/p' | head -n 1)
    pr=$(printf '%s\n' "$lines" | sed -n 's/.*peer_result=\(-\{0,1\}[0-9]*\).*/\1/p' | head -n 1)
    if [ -n "$lines" ]; then ok "$label: refused with WR_E_M2_BAD_METHOD"; else bad "$label: no M2_BAD_METHOD in the tool output"; fi
    if [ "$allowed" = "$want" ]; then ok "$label: allowed modes $allowed ($([ "$want" = 0x4 ] && echo '{secure}' || echo '{crc}'))"; else bad "$label: allowed modes '${allowed:-none}', wanted $want"; fi
    if [ "$pr" = -95 ]; then ok "$label: the server's result is -95 (EOPNOTSUPP)"; else bad "$label: the server's result is '${pr:-none}', wanted -95"; fi
    if printf '%s\n' "$OUT" | grep -Eq "$side allows only $amode mode: set $setting to a policy"; then ok "$label: the tool says that the $side allows only $amode and names $setting"; else bad "$label: no '$side allows only $amode mode: set $setting' hint in the tool output"; fi
    if [ "$RC" -ne 0 ]; then ok "$label: the run did not succeed (exit $RC)"; else bad "$label: the run exited 0 although the offer was refused"; fi
    # no connection fell back to the refused mode, and for an OSD refusal the monitor connection (offered the allowed mode) did come up: it is the OSD's
    ca=$(field "conns_$amode"); cr=$(field "conns_$rmode")
    if [ "${cr:-x}" = 0 ]; then ok "$label: no $rmode connection reached READY"; else bad "$label: conns_$rmode=${cr:-none} (wanted 0)"; fi
    if [ "$side" = OSD ]; then
        if [ "${ca:-0}" -ge 1 ]; then ok "$label: the monitor connection reached READY in $amode: the refusal is the OSD's"; else bad "$label: no $amode monitor connection (conns_$amode=${ca:-none}): the refusal may not be the OSD's"; fi
    fi
    note "CAPTURE $label: peer_result=${pr:-none} allowed_modes=${allowed:-none} exit=$RC"
    if [ -n "$capdir" ]; then
        { echo "# secure-live refusal capture: $label"; echo "# tool: $tool, user client.$CUR_USER, exit $RC"; printf '%s\n' "$OUT" | grep -E 'M2_BAD_METHOD|event|result|stats|allows only' | head -n 40; } > "$capdir/refusal-$label.txt"
    fi
}

# stock cross-check of a refusal: the stock client, offering only the refused mode, must fail too (it is the oracle for "the cluster refuses")
stock_refusal() { # <label> <mode>
    local label=$1 m=$2
    runc timeout --kill-after=5 40 $SUDO rbd --ms_mon_client_mode "$m" --ms_client_mode "$m" info "$POOL/$IMG_A"
    if [ "$RC" -ne 0 ]; then ok "$label: the stock client offering only $m fails too (exit $RC)"; else bad "$label: the stock client offering only $m was NOT refused"; fi
}

# ---- the scratch images -------------------------------------------------------------------------------------------------------------------------
# IMG_A holds the pristine content rand:SEED_A over its first 16 MiB (written once, under the stock policy, before anything is changed); the
# policy and forced sections only read it there and write beyond 16 MiB. IMG_R takes the random runs (their model covers its first 8 MiB).
IMG_A=""; IMG_R=""
SEED_A=77
ensure_images() {
    [ -z "$IMG_A" ] || return 0
    if ! make_image a 64M; then bad "could not create the scratch image"; return 1; fi
    IMG_A=$IMG
    if ! make_image r 64M; then bad "could not create the scratch image for the random runs"; return 1; fi
    IMG_R=$IMG
    CUR_USER=$USER_K2; CUR_KR=$(kr_of "$USER_K2")
    [ "$keys" != k1 ] || { CUR_USER=$USER_K1; CUR_KR=$(kr_of "$USER_K1"); }
    wr "$IMG_A" --rw --mode stock fill 0 16M --pattern "rand:$SEED_A"
    if [ "$RC" -ne 0 ]; then bad "the first fill of the scratch image failed (exit $RC)"; return 1; fi
    return 0
}

KLABEL=""; KSEED=0
for_each_key() { # <function>: run it with CUR_USER / CUR_KR / KLABEL / KSEED set for every selected key type
    local fn=$1 k
    for k in k2 k1; do
        case "$keys:$k" in both:*|k2:k2|k1:k1) ;; *) continue ;; esac
        if [ "$k" = k2 ]; then CUR_USER=$USER_K2; KSEED=10; else CUR_USER=$USER_K1; KSEED=20; fi
        CUR_KR=$(kr_of "$CUR_USER")
        KLABEL=$k
        "$fn"
    done
}

# ---- two checks the cluster's answers cannot give: the wire itself, and a key the cluster does not know -------------------------------------------
# The wire check counts the ascending runs of 64 bytes in the TCP payload of the client's own connections (py wire: the pattern `seq` is the offset
# modulo 256: 00 01 .. 3f, 40 41 .. 7f in every 256 bytes of data). Nothing else puts such a run on the wire: not a header, not a ticket, not a
# random-looking encrypted stream (2^-512).

# wire_check <image>: an INDEPENDENT proof that secure mode encrypts. The same 4 MiB of a recognisable pattern is written and read back in crc mode and in
# secure mode while tcpdump records the traffic to the lab's daemons (the lab's monitor and OSDs share one host): the crc capture must show the pattern
# (that is the control: a capture that cannot see the data proves nothing) and the secure capture must not show a single run of it. The stock cluster's
# answers (the stats counters, the stock client) are not evidence for this: a core that counted a connection as secure but sent the frames in the clear
# would pass every other check of this script.
wire_check() {
    local img=$1 m f r hits nb ports L=$KLABEL
    if ! command -v tcpdump >/dev/null 2>&1; then note "$L wire: tcpdump is not installed: the check that the data is not on the wire in secure mode is skipped"; return 0; fi
    ports=$(client_ports)
    case "$ports" in *" "[0-9]*) ;; *) bad "$L wire: could not read the OSDs' public ports from the OSD map"; return 0 ;; esac
    for m in crc secure; do
        f="$WORK/wire-$L-$m.pcap"
        rm -f "$f"
        # shellcheck disable=SC2086
        tcpdump_start "$f" $ports
        wr "$img" --rw --mode "$m" --require-mode "$m" fill 0 4M --pattern seq
        [ "$RC" -eq 0 ] || bad "$L wire: the $m fill of the pattern failed (exit $RC)"
        wr "$img" --mode "$m" --require-mode "$m" verify 0 4M --pattern seq
        [ "$RC" -eq 0 ] || bad "$L wire: the $m read of the pattern failed (exit $RC)"
        tcpdump_stop
        # shellcheck disable=SC2086
        r=$(py wire "$f" $ports 2>/dev/null) || r=""
        hits=${r% *}; nb=${r#* }
        case "$hits:$nb" in *[!0-9:]*|:*|*:) bad "$L wire: could not read the $m capture"; rm -f "$f"; continue ;; esac
        if [ "$m" = crc ]; then
            if [ "$hits" -ge 500 ]; then ok "$L wire: the crc capture shows the pattern ($hits runs in $nb bytes of the client's connections): the capture can see the data"; else bad "$L wire: the crc capture shows the pattern only $hits times in $nb bytes: the capture is blind, the secure result below proves nothing"; fi
        else
            # a capture that saw little of the client's traffic (tcpdump late or dropping) would hold no run either: it must have seen the data's volume
            if [ "$nb" -lt "$WIRE_MIN_BYTES" ]; then bad "$L wire: the secure capture holds only $nb bytes of the client's connections (wanted at least $WIRE_MIN_BYTES): it did not see the data"
            elif [ "$hits" -eq 0 ]; then ok "$L wire: not one run of the pattern in the secure capture: the data is encrypted on the wire ($nb bytes of the client's connections)"
            else bad "$L wire: the secure capture holds $hits runs of the pattern on the client's connections: the data went out in the clear"; fi
        fi
        rm -f "$f"
    done
}

# wrongkey_check <image>: the same user with a secret the cluster does not know (made from the real keyring's header with random bytes: the real secret
# is neither read nor printed) is refused in secure mode and in crc mode, quickly, without a single connection reaching READY and without data. The
# peer answers AUTH_BAD_METHOD with -EACCES here, which is not a mode refusal; only the outcome is checked, not the words of the log.
wrongkey_check() {
    local img=$1 wk="$WORK/keys/wrong.$CUR_USER.keyring" saved=$CUR_KR L=$KLABEL m cs cc t0
    mkdir -p "$WORK/keys"; chmod 700 "$WORK/keys"
    (umask 077; python3 -I -c 'import base64, os, struct, sys
b64 = None
for line in open(sys.argv[1]):
    if line.strip().startswith("key"):
        b64 = line.split("=", 1)[1].strip()
raw = base64.b64decode(b64)
typ, = struct.unpack_from("<H", raw, 0)
ln, = struct.unpack_from("<H", raw, 10)
new = struct.pack("<HIIH", typ, 0, 0, ln) + os.urandom(ln)
with open(sys.argv[2], "w") as f:
    f.write("[client.%s]\n\tkey = %s\n" % (sys.argv[3], base64.b64encode(new).decode()))' "$CUR_KR" "$wk" "$CUR_USER" 2>/dev/null)
    if [ ! -s "$wk" ]; then note "$L wrong key: could not make a keyring with a wrong secret from $CUR_KR: the check is skipped"; return 0; fi
    CUR_KR=$wk
    for m in secure crc; do
        t0=$SECONDS
        wrmp --mode "$m" --require-mode "$m" --timeout 8000
        if [ "$RC" -ne 0 ] && [ "$RC" -lt 100 ]; then ok "$L wrong key, $m: wr-monprobe fails (exit $RC), it does not hang"; else bad "$L wrong key, $m: wr-monprobe exit $RC (wanted a plain failure)"; fi
        expect_no 'result active=1' "$L wrong key, $m: the monitor session never became ACTIVE"
        cs=$(field conns_secure); cc=$(field conns_crc)
        if [ "${cs:-x}:${cc:-x}" = 0:0 ]; then ok "$L wrong key, $m: no connection reached READY"; else bad "$L wrong key, $m: conns_secure=${cs:-none} conns_crc=${cc:-none} with a wrong key (wanted 0 and 0)"; fi
        wr "$img" --mode "$m" --require-mode "$m" --timeout 8000 info
        if [ "$RC" -ne 0 ] && [ "$RC" -lt 100 ]; then ok "$L wrong key, $m: wr-rbd does not open the image (exit $RC)"; else bad "$L wrong key, $m: wr-rbd exit $RC (wanted a plain failure)"; fi
        expect_no 'state=OPEN' "$L wrong key, $m: the image did not open"
        [ $((SECONDS - t0)) -le 60 ] && ok "$L wrong key, $m: refused within $((SECONDS - t0)) s" || bad "$L wrong key, $m: took $((SECONDS - t0)) s to give up"
    done
    CUR_KR=$saved
    rm -f "$wk"
}

# ---- section client ----------------------------------------------------------------------------------------------------------------------------
sec_one_key() {
    local m="--mode secure --require-mode secure" exp="$WORK/export-$KLABEL.img" nops=300 s=$KSEED L=$KLABEL cs img imgb
    [ "$quick" -eq 0 ] || nops=120
    # an image of its own for this key: written and rewritten freely
    if ! make_image "c-$L" 64M; then bad "$L: could not create the image"; return 1; fi
    img=$IMG
    # shellcheck disable=SC2086
    wr "$img" --rw $m info
    expect_rc 0 "$L secure: info (writer)"
    expect_out 'state=OPEN' "$L secure: the image is OPEN"
    expect_out 'result require_mode ok=1' "$L secure: every connection secure ($(field conns_secure) secure, $(field conns_crc) crc, $(field sec_failures) failures)"
    cs=$(field conns_secure); if [ "${cs:-0}" -ge 2 ]; then ok "$L secure: a monitor and an OSD connection reached READY in secure mode"; else bad "$L secure: only ${cs:-0} secure connection(s)"; fi

    # shellcheck disable=SC2086
    wr "$img" --rw $m fill 0 16M --pattern "rand:$((s + 1))"
    expect_rc 0 "$L secure: fill 16 MiB (4 MiB objects: data frames of up to 4 MiB sealed)"
    # shellcheck disable=SC2086
    wr "$img" $m verify 0 16M --pattern "rand:$((s + 1))"
    expect_rc 0 "$L secure: verify the 16 MiB read back through secure frames"
    # shellcheck disable=SC2086
    wr "$img" $m verify 0 16M --pattern "rand:$((s + 2))"
    expect_rc 1 "$L secure: a wrong pattern is a difference, not a success"
    expect_out 'result require_mode ok=1' "$L secure: and every connection of that run was secure too (exit 1 keeps its code over a mode failure)"
    expect_out 'first_diff=' "$L secure: the difference names its offset"

    # shellcheck disable=SC2086
    wr "$img" --rw $m write 4189304 20000 --pattern seq
    expect_rc 0 "$L secure: a 20000 byte write at an unaligned offset across an object boundary"
    # shellcheck disable=SC2086
    wr "$img" --rw $m zeroes 100000 50000
    expect_rc 0 "$L secure: zeroes"
    # shellcheck disable=SC2086
    wr "$img" --rw $m discard 8M 1M
    expect_rc 0 "$L secure: discard"
    # shellcheck disable=SC2086
    wr "$img" $m verify 100000 50000 --pattern zero
    expect_rc 0 "$L secure: the zeroed range reads back as zeroes"
    # shellcheck disable=SC2086
    wr "$img" $m verify 8M 1M --pattern zero
    expect_rc 0 "$L secure: the discarded range reads back as zeroes"
    # shellcheck disable=SC2086
    wr "$img" $m verify 4189304 20000 --pattern seq
    expect_rc 0 "$L secure: the unaligned write reads back"

    # shellcheck disable=SC2086
    wr "$img" --rw $m --depth 6 random "$nops" "$((s + 3))" --model-bytes 8M
    expect_rc 0 "$L secure: $nops random unaligned cross-object operations against the model"
    expect_out 'result random ok=1 ' "$L secure: the random run reports ok"
    expect_out 'read_mismatches=0 final_diff_bytes=0 errors=0' "$L secure: no mismatch, no difference, no error"
    # shellcheck disable=SC2086
    wr "$img" --rw $m --depth 12 --overlap --model-bytes 8M --max-len 1M random "$nops" "$((s + 4))"
    expect_rc 0 "$L secure: random with overlapping requests in flight"
    expect_out 'barrier_violations=0 bad_completions=0' "$L secure: the fence of the core held in secure mode"

    # the stock oracle: the bytes the cluster holds are the bytes the secure core reads
    rm -f "$exp"
    if step "export-$L" quiet RBD export --no-progress "$POOL/$img" "$exp"; then
        # shellcheck disable=SC2086
        wr "$img" $m compare "$exp"
        expect_rc 0 "$L secure: the whole image read through the secure core equals the stock rbd export"
    else
        bad "$L: rbd export failed"
    fi
    rm -f "$exp"

    # what the stock tool writes, the secure core reads
    imgb="wrtest-sl-$NAME_TAG-b-$L"; track_image "$POOL/$imgb" "b-$L"
    python3 -I -c 'import os,sys; sys.stdout.buffer.write(os.urandom(6291456 + 777))' > "$WORK/stock-$L.bin"
    if step "import-$L" quiet RBD import --image-format 2 --image-feature layering "$WORK/stock-$L.bin" "$POOL/$imgb"; then
        # shellcheck disable=SC2086
        wr "$imgb" $m compare "$WORK/stock-$L.bin"
        expect_rc 0 "$L secure: an image written by the stock rbd import reads back byte for byte through the secure core"
    else
        bad "$L: rbd import failed"
    fi
    rm -f "$WORK/stock-$L.bin"

    wrmp --mode secure --require-mode secure
    expect_rc 0 "$L secure: wr-monprobe --require-mode secure"
    expect_out 'result active=1' "$L secure: the monitor session is ACTIVE with the maps"

    wr "$IMG_A" --mode secure --accel --require-mode secure verify 0 8M --pattern "rand:$SEED_A"
    if [ "$RC" -eq 2 ] && printf '%s\n' "$OUT" | grep -q 'no AES-NI'; then
        note "$L secure: this CPU has no AES-NI / PCLMULQDQ hook: --accel refused, the portable GCM was used above"
    else
        expect_rc 0 "$L secure: the same read with the host's AES-NI hook (--accel)"
        expect_out 'gcm=host' "$L secure: the hook's key objects were really used"
        expect_out 'gcm_ops=[1-9]' "$L secure: and the hook really ran the frames (gcm_ops=$(field gcm_ops))"
    fi
    wire_check "$img"
    wrongkey_check "$img"
    # the images of this key are not needed any more (the trap removes what is left)
    RBD rm "$POOL/$img" >/dev/null 2>&1 && rm -f "$TRACK/c-$L.image"
    RBD rm "$POOL/$imgb" >/dev/null 2>&1 && rm -f "$TRACK/b-$L.image"
    return 0
}

section_client() {
    sect "client side secure against the default cluster"
    ensure_images || return 1
    for_each_key sec_one_key
}

section_krbd() {
    local orders=12,22 ops=2500 kd="$WORK/krbd-keys" u
    sect "wr-krbdcmp with krbd mapped ms_mode=secure"
    [ "$quick" -eq 0 ] || { orders=12; ops=1200; }
    [ -f "$KRBDCMP_SH" ] || { bad "krbd-compare.sh not found: $KRBDCMP_SH"; return 1; }
    # the tools are the ones this run was given (WR_RBD, as lab.secure names them: the build directory of `cmake -S harness -B build` is not the
    # default <repo>/build/harness): wr-krbdcmp is looked for next to wr-rbd unless WR_KRBDCMP says otherwise (passed below)
    # krbd-compare.sh finds keyrings only as <dir>/client.<user>.keyring (and always maps krbd as the legacy-key user): the keyrings this run was
    # given (explicit files, as lab.secure names them) are linked under those names in a directory of the run's own (links only, no key bytes)
    rm -rf "$kd"; mkdir -p "$kd"; chmod 700 "$kd"
    for u in "$USER_K2" "$USER_K1"; do
        if [ -r "$(kr_of "$u")" ]; then ln -s "$(cd "$(dirname "$(kr_of "$u")")" && pwd -P)/$(basename "$(kr_of "$u")")" "$kd/client.$u.keyring"; fi
    done
    OUT=""; RC=0
    step krbd-compare runc env WR_LAB_WORK="$WORK/krbd" WR_BUILD_DIR="$build" WR_RBD="$WR" WR_KRBDCMP="${WR_KRBDCMP:-$(dirname "$WR")/wr-krbdcmp}" WR_LAB_MON="$MON" WR_LAB_POOL="$POOL" WR_LAB_KEYRING_DIR="$kd" \
        WR_LAB_USER_K2="$USER_K2" WR_LAB_USER_K1="$USER_K1" WR_LAB_SUDO="$SUDO" KC_NAME_TAG="sl$NAME_TAG" \
        timeout --kill-after=60 7200 bash "$KRBDCMP_SH" --mode secure --keys "$keys" --orders "$orders" --small --ops "$ops" --parallel 2 || RC=$?
    printf '%s\n' "$OUT" | grep -E '^(CASE |state:|krbd-compare: finished)' | sed 's/^/      | /'
    if [ "$RC" -eq 0 ]; then ok "krbd mapped with ms_mode=secure and the core with --mode secure: every case passed, no new kernel error, the lab as before"; else bad "krbd-compare --mode secure failed (exit $RC)"; fi
    expect_no '^CASE .* FAIL ' "no krbd case failed"
    if printf '%s\n' "$OUT" | grep -q '^CASE .* PASS '; then ok "at least one krbd case ran and passed ($(printf '%s\n' "$OUT" | grep -c '^CASE .* PASS ') cases)"; else bad "no krbd case passed"; fi
}

# ---- section policy ----------------------------------------------------------------------------------------------------------------------------
# what each offer policy gets from the default cluster: the monitor from wr-monprobe, the OSDs from two runs of wr-rbd (the monitor offer is
# pinned to the one mode the other way round, so a connection of the other mode can only be an OSD one)
policy_expect() { # <policy> -> "<mon mode> <osd mode>" the design table 34.2 against the default cluster (mon: secure crc, osd: crc secure)
    case "$1" in
        crc) echo "crc crc" ;; crc-first) echo "crc crc" ;; secure-first) echo "secure secure" ;; secure) echo "secure secure" ;; stock) echo "secure crc" ;;
    esac
}
stock_args() { # <policy> -> the stock client's options that mean the same
    case "$1" in
        crc) echo "--ms_mon_client_mode crc --ms_client_mode crc" ;;
        crc-first) echo "--ms_mon_client_mode crc,secure --ms_client_mode crc,secure" ;;
        secure-first) echo "--ms_mon_client_mode secure,crc --ms_client_mode secure,crc" ;;
        secure) echo "--ms_mon_client_mode secure --ms_client_mode secure" ;;
        stock) echo "" ;;
    esac
}

mode_of_counts() { # reads conns_secure / conns_crc of OUT -> secure | crc | both | none
    local s c
    s=$(field conns_secure); c=$(field conns_crc)
    if [ "${s:-0}" -gt 0 ] && [ "${c:-0}" -gt 0 ]; then echo both; elif [ "${s:-0}" -gt 0 ]; then echo secure; elif [ "${c:-0}" -gt 0 ]; then echo crc; else echo none; fi
}

policy_one_key() {
    local p exp expmon exposd gotmon gotosd a b stock sm so
    OSD_PORTS=$(CEPH osd dump -f json 2>/dev/null | py osdports) || OSD_PORTS=""
    for p in crc crc-first secure-first secure stock; do
        exp=$(policy_expect "$p"); expmon=${exp% *}; exposd=${exp#* }
        wrmp --mode "$p"
        [ "$RC" -eq 0 ] || bad "$KLABEL $p: wr-monprobe failed (exit $RC)"
        gotmon=$(mode_of_counts)
        # the OSD: pin the monitor offer to crc and give the OSD the policy: a secure connection is an OSD one; then the other way round
        wr "$IMG_A" --mode crc --mode-osd "$p" verify 0 4M --pattern "rand:$SEED_A"; a=$(mode_of_counts); [ "$RC" -eq 0 ] || bad "$KLABEL $p: a read with the OSD policy $p failed (exit $RC)"
        wr "$IMG_A" --mode secure --mode-osd "$p" verify 0 4M --pattern "rand:$SEED_A"; b=$(mode_of_counts); [ "$RC" -eq 0 ] || bad "$KLABEL $p: a read with the OSD policy $p failed (exit $RC)"
        # a: crc monitor + OSD(p): "crc" = OSD crc, "both" = OSD secure;  b: secure monitor + OSD(p): "secure" = OSD secure, "both" = OSD crc
        case "$a:$b" in crc:both) gotosd=crc ;; both:secure) gotosd=secure ;; *) gotosd="unclear($a/$b)" ;; esac
        if [ "$gotmon" = "$expmon" ] && [ "$gotosd" = "$exposd" ]; then ok "$KLABEL policy $p: monitor $gotmon, OSD $gotosd (as the design table 34.2 says for the default cluster)"; else bad "$KLABEL policy $p: monitor $gotmon / OSD $gotosd, wanted $expmon / $exposd"; fi
        # the stock client with the same options is the oracle
        # shellcheck disable=SC2046
        runc timeout --kill-after=5 60 $SUDO rbd --debug_ms=1 $(stock_args "$p") info "$POOL/$IMG_A"
        stock=$(printf '%s\n' "$OUT" | py stockmodes $OSD_PORTS)
        sm=$(printf '%s' "$stock" | sed -n 's/.*mon=\([a-z+]*\).*/\1/p'); so=$(printf '%s' "$stock" | sed -n 's/.*osd=\([a-z+]*\).*/\1/p')
        if [ "$sm" = "$gotmon" ] && [ "$so" = "$gotosd" ]; then ok "$KLABEL policy $p: the stock client with the same options got the same modes ($stock)"; else bad "$KLABEL policy $p: the stock client got '$stock', the core monitor $gotmon / OSD $gotosd"; fi
        note "TABLE policy=$p key=$KLABEL core_monitor=$gotmon core_osd=$gotosd stock=\"$stock\""
    done
    # whole runs with the stats of the design (conns_secure / conns_crc): the stock policy ends in both modes, crc-first in crc only
    wr "$IMG_A" --mode stock verify 0 8M --pattern "rand:$SEED_A"
    expect_rc 0 "$KLABEL policy stock: a read of 8 MiB"
    [ "$(mode_of_counts)" = both ] && ok "$KLABEL policy stock: conns_secure=$(field conns_secure) conns_crc=$(field conns_crc): monitor secure, OSDs crc, as the stock client" || bad "$KLABEL policy stock: modes $(mode_of_counts)"
    wr "$IMG_A" --mode crc-first --require-mode crc verify 0 8M --pattern "rand:$SEED_A"
    expect_rc 0 "$KLABEL policy crc-first: --require-mode crc holds (conns_secure=$(field conns_secure) conns_crc=$(field conns_crc))"
    wr "$IMG_A" --mode crc-first --require-mode secure verify 0 4M --pattern "rand:$SEED_A"
    expect_rc 3 "$KLABEL policy crc-first: --require-mode secure is refused (exit 3): the assertion cannot pass on a crc connection"
}

section_policy() {
    sect "offer policies against the default cluster"
    ensure_images || return 1
    for_each_key policy_one_key
}

# ---- sections forced-secure and forced-crc --------------------------------------------------------------------------------------------------------
FORCED_REGION=16777216
FORCED_M=""; FORCED_SEED=0
forced_one_key() { # every client that must work against a cluster that only allows FORCED_M
    local m=$FORCED_M L=$KLABEL seed=$((FORCED_SEED + KSEED)) p exp="$WORK/export-forced-$KLABEL.img"
    for p in crc-first secure-first stock "$m"; do
        wr "$IMG_A" --mode "$p" --require-mode "$m" verify 0 16M --pattern "rand:$SEED_A"
        expect_rc 0 "$L forced $m: a $p client reads the known content and every connection is $m (conns_secure=$(field conns_secure) conns_crc=$(field conns_crc))"
    done
    wr "$IMG_A" --rw --mode secure-first --require-mode "$m" fill "$FORCED_REGION" 8M --pattern "rand:$seed"
    expect_rc 0 "$L forced $m: a secure-first client writes 8 MiB"
    wr "$IMG_A" --mode crc-first --require-mode "$m" verify "$FORCED_REGION" 8M --pattern "rand:$seed"
    expect_rc 0 "$L forced $m: and a crc-first client reads it back"
    wr "$IMG_R" --rw --mode secure-first --require-mode "$m" --depth 6 random 150 "$((seed + 1))" --model-bytes 8M
    expect_rc 0 "$L forced $m: 150 random operations against the model"
    expect_out 'read_mismatches=0 final_diff_bytes=0 errors=0' "$L forced $m: no mismatch"
    if [ "$m" = secure ]; then
        wr "$IMG_A" --mode secure --accel --require-mode secure verify "$FORCED_REGION" 8M --pattern "rand:$seed"
        if [ "$RC" -eq 2 ] && printf '%s\n' "$OUT" | grep -q 'no AES-NI'; then note "$L forced secure: no AES-NI hook on this CPU"; else expect_rc 0 "$L forced secure: the AES-NI hook against the forced cluster"; fi
    fi
    rm -f "$exp"
    if step "export-forced-$L" quiet RBD export --no-progress "$POOL/$IMG_A" "$exp"; then
        wr "$IMG_A" --mode secure-first --require-mode "$m" compare "$exp"
        expect_rc 0 "$L forced $m: the image as the stock tool exports it equals what the core reads"
    else
        bad "$L forced $m: rbd export failed"
    fi
    rm -f "$exp"
    FORCED_REGION=$((FORCED_REGION + 8388608))
}

forced_phase() { # <secure|crc>
    local m=$1 refused hex hexname rk
    if [ "$m" = secure ]; then refused=crc; hex=0x4; hexname='{secure}'; FORCED_SEED=300; else refused=secure; hex=0x2; hexname='{crc}'; FORCED_SEED=400; fi
    FORCED_M=$m
    sect "the cluster forced to $m (ms_mon_service_mode and ms_service_mode $m)"
    ensure_images || return 1
    if ! set_mode_opt mon ms_mon_service_mode "$m" || ! set_mode_opt osd ms_service_mode "$m"; then
        bad "forced $m: could not set the service modes"; return 1
    fi
    ok "forced $m: ms_mon_service_mode and ms_service_mode set to $m"
    if restart_all; then ok "forced $m: the monitor and every OSD restarted one at a time, every OSD up and in, every PG active+clean"; else bad "forced $m: restarting the daemons did not end clean"; return 1; fi
    OUT="$(CEPH config get mon ms_mon_service_mode 2>&1) $(CEPH config get osd ms_service_mode 2>&1)"
    case "$OUT" in "$m $m") ok "forced $m: the config database says ms_mon_service_mode=$m ms_service_mode=$m" ;; *) bad "forced $m: the config database says '$OUT'" ;; esac

    CUR_USER=$USER_K2; [ "$keys" != k1 ] || CUR_USER=$USER_K1
    rk=$CUR_USER
    CUR_KR=$(kr_of "$CUR_USER")
    if [ -n "$capdir" ] && command -v tcpdump >/dev/null 2>&1; then
        if make_throwaway_user; then CUR_USER=$THROW_USER; CUR_KR=$THROW_KR; fi
    fi
    # a client offering only the other mode is refused, by the monitor and (the monitor offer pinned to the allowed mode) by the OSDs
    refusal_check "forced-$m-monitor-$refused-only" "$hex" monprobe --mode "$refused" --timeout 15000
    refusal_check "forced-$m-whole-$refused-only" "$hex" rbd --mode "$refused" --timeout 15000 info
    refusal_check "forced-$m-osd-$refused-only" "$hex" rbd --mode "$m" --mode-osd "$refused" --timeout 15000 info
    CUR_USER=$rk; CUR_KR=$(kr_of "$rk")
    stock_refusal "forced $m" "$refused"
    note "forced $m: a $refused-only client is told the cluster allows $hexname"
    # every client that offers the allowed mode works, with the data checked
    for_each_key forced_one_key
    return 0
}

make_throwaway_user() {
    THROW_USER="wrtest-sl-$NAME_TAG"
    THROW_KR="$WORK/keys/client.$THROW_USER.keyring"
    mkdir -p "$WORK/keys"; chmod 700 "$WORK/keys"
    # the keyring comes on stdout and is written by this shell (a file made by `sudo ceph -o` would belong to root)
    if (umask 077; CEPH auth get-or-create "client.$THROW_USER" mon 'profile rbd' osd "profile rbd pool=$POOL" > "$THROW_KR" 2>/dev/null) && [ -s "$THROW_KR" ]; then
        return 0
    fi
    CEPH auth del "client.$THROW_USER" >/dev/null 2>&1
    note "could not create the throwaway cephx user: the refusals are captured with the regular user"
    THROW_USER=""; return 1
}

section_forced_secure() { forced_phase secure; }
section_forced_crc()    { forced_phase crc; }

# ---- the run ----------------------------------------------------------------------------------------------------------------------------------
on_exit() {
    local rc=$? crc=0 sc=0 xc=0 f
    trap '' INT TERM HUP    # the restore must finish
    trap - EXIT
    if [ "$FINAL_RC" -eq 0 ]; then FINAL_RC=$rc; fi
    [ -z "$CHILD" ] || kill -TERM "$CHILD" 2>/dev/null
    wait 2>/dev/null
    capture_stop
    if [ -s "$WORK/modes.before" ]; then
        echo
        echo "=== restore ==="
        restore_cluster || xc=1
    fi
    cleanup_tracked || crc=1
    if [ -s "$WORK/state.before" ]; then state_compare "$WORK/state.before" after || sc=1; fi
    if [ "$xc" -ne 0 ] || [ "$crc" -ne 0 ] || [ "$sc" -ne 0 ]; then [ "$FINAL_RC" -ne 0 ] || FINAL_RC=1; fi
    if [ "$FAIL" -ne 0 ]; then [ "$FINAL_RC" -ne 0 ] || FINAL_RC=1; fi
    # (an interrupted wire check leaves its captures, which hold the pattern of the crc run, and the stock comparison its random file)
    rm -f "$WORK"/wire-*.pcap "$WORK"/stock-*.bin
    rm -rf "$WORK/krbd-keys"
    if [ "$keep" != 1 ]; then rm -rf "$WORK/track" "$WORK/keys" "$WORK"/export-*.img "$WORK"/model-*.bin "$WORK/krbd" "$WORK/.state."* "$WORK/.out."*; fi
    echo
    echo "secure-live: $PASS passed, $FAIL failed"
    if [ "$FAIL" -ne 0 ]; then printf '  failed: %s\n' "${FAILED[@]}"; fi
    echo "secure-live: finished with exit status $FINAL_RC (restore: $([ $xc = 0 ] && echo done || echo FAILED); cleanup: $([ $crc = 0 ] && echo clean || echo FAILED); state: $([ $sc = 0 ] && echo as-before || echo CHANGED))"
    exit "$FINAL_RC"
}

main() {
    local s
    [ -x "$WR" ] || die "$WR not found: build the harness first (cmake --build, see harness/README.md) or set WR_BUILD_DIR"
    [ -x "$WRMP" ] || die "$WRMP not found: build the harness first or set WR_BUILD_DIR"
    command -v python3 >/dev/null || die "python3 is needed"
    command -v ceph >/dev/null || die "the ceph command is needed (run this inside the lab VM)"
    command -v rbd >/dev/null || die "the rbd command is needed (run this inside the lab VM)"
    $SUDO -n true 2>/dev/null || die "passwordless sudo is needed (the stock CLI, systemctl)"
    local k user kf
    for k in k2 k1; do
        case "$keys:$k" in both:*|k2:k2|k1:k1) ;; *) continue ;; esac
        if [ "$k" = k2 ]; then user=$USER_K2; else user=$USER_K1; fi
        kf=$(kr_of "$user")
        [ -r "$kf" ] || die "no keyring for $user: $kf (keep keyrings outside the repository, mode 600)"
        case "$(cd "$(dirname "$kf")" && pwd -P)/" in "$repo"/*) die "the keyring $kf is inside the repository; keep keys outside it" ;; esac
    done
    if [ -n "$capdir" ]; then mkdir -p "$capdir" || die "cannot create $capdir"; capdir=$(cd "$capdir" && pwd -P); fi
    local first=${MON%%[, ;]*}
    if [ -z "${SL_NO_MON_CHECK:-}" ]; then
        timeout 5 bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$mon_host" "$mon_port" 2>/dev/null || die "cannot reach the monitor $first: run this inside the lab VM"
    fi
    mkdir -p "$WORK" "$TRACK" || die "cannot create $WORK"
    chmod 700 "$WORK"
    # one run at a time per work directory: two runs would share the snapshot, the images list and the restore flag (flock is part of util-linux)
    if command -v flock >/dev/null 2>&1; then
        exec 9> "$WORK/lock" || die "cannot create $WORK/lock"
        flock -n 9 || die "another secure-live run is using $WORK (its lock is held)"
    fi
    if [ -e "$WORK/stale" ]; then
        die "an earlier run did not finish restoring the cluster ($WORK/stale exists): check 'ceph config dump | grep ms_' against $WORK/modes.before, restart the monitor and the OSDs one at a time if the four options were changed, then delete $WORK/stale"
    fi
    rm -f "$WORK/restarted" "$WORK"/injected.* "$WORK/modes.before" "$WORK/state.before"   # (a snapshot of an earlier run is not this run's baseline)
    write_pylib
    trap on_exit EXIT
    trap 'FINAL_RC=2; exit 2' INT TERM HUP
    info "snapshot of the cluster state (config database, the four mode options, health, OSD tree, upmaps, daemons)"
    modes_snapshot "$WORK/modes.before" || { FINAL_RC=2; die "cannot read the config database (ceph config dump failed)"; }
    if grep -q . "$WORK/modes.before" && [ -z "${SL_ALLOW_BASELINE_OPTIONS:-}" ]; then
        FINAL_RC=2
        die "the config database already holds one of the four mode options ($(grep -v '^$' "$WORK/modes.before" | tr '\t\n' ' =' | cut -c1-200)): another run may have the cluster forced right now, and its settings would become this run's baseline. Not starting (SL_ALLOW_BASELINE_OPTIONS=1 overrides when that is really the state to restore)"
    fi
    state_snapshot "$WORK/state.before"
    [ -s "$WORK/state.before" ] || { FINAL_RC=2; die "cannot read the cluster state (ceph commands failed)"; }
    BASE_OSDS=$(CEPH osd stat -f json 2>/dev/null | python3 -I -c 'import json,sys; d=json.load(sys.stdin); d=d.get("osdmap",d); print(d["num_osds"])' 2>/dev/null) || BASE_OSDS=0
    [ "${BASE_OSDS:-0}" -gt 0 ] || { FINAL_RC=2; die "cannot count the OSDs"; }
    wait_clean 60 || { FINAL_RC=2; die "the cluster is not clean now (every OSD up and in, every PG active+clean): not starting"; }
    local bo
    bo=$(grep -v '^$' "$WORK/modes.before" | awk -F'\t' '{ printf "%s of %s = %s; ", $1, $2, $3 }')
    note "baseline options: ${bo:-none set} ($BASE_OSDS OSDs, all up and in, PGs clean)"
    for s in client krbd policy forced-secure forced-crc; do
        want "$s" || continue
        case "$s" in
            client) section_client ;; krbd) section_krbd ;; policy) section_policy ;;
            forced-secure) section_forced_secure ;; forced-crc) section_forced_crc ;;
        esac
    done
    if want forced-secure || want forced-crc; then
        sect "restore and check"
        if restore_cluster; then ok "the four options are back to their original values and the daemons restarted under them"; else bad "the restore did not complete"; fi
        post_restore_probe
    fi
    return 0
}

# the daemons really run with the original options again: both offers are accepted by the monitor and by the OSDs
post_restore_probe() {
    CUR_USER=$USER_K2; CUR_KR=$(kr_of "$USER_K2")
    [ "$keys" != k1 ] || { CUR_USER=$USER_K1; CUR_KR=$(kr_of "$USER_K1"); }
    [ -n "$IMG_A" ] || return 0
    wr "$IMG_A" --mode crc --require-mode crc verify 0 16M --pattern "rand:$SEED_A"
    expect_rc 0 "restored: a crc-only client works again (monitor and OSDs)"
    wr "$IMG_A" --mode secure --require-mode secure verify 0 16M --pattern "rand:$SEED_A"
    expect_rc 0 "restored: a secure-only client works again (monitor and OSDs)"
    wr "$IMG_A" --mode stock verify 0 16M --pattern "rand:$SEED_A"
    expect_rc 0 "restored: the stock policy works"
    [ "$(mode_of_counts)" = both ] && ok "restored: stock policy ends monitor secure, OSD crc, as on the default cluster" || bad "restored: stock policy modes $(mode_of_counts)"
}

# ---- selftest ----------------------------------------------------------------------------------------------------------------------------------
# Stand-ins for sudo, ceph, rbd, systemctl, wr-rbd, wr-monprobe, krbd-compare.sh and tcpdump in a directory of their own, the first five in one
# python program (stub.py). They model a cluster whose monitor and OSDs read ms_mon_service_mode / ms_service_mode when they are RESTARTED (a
# daemon's file in daemon_modes/ is rewritten by `systemctl restart`), the config database, a few polls of unclean PGs after each restart, and a
# store of images made of pattern ranges. The refusals, the require-mode results and the stats lines of the tools have the shape of the real ones.
write_stubs() { # <dir>
    local d=$1 t
    mkdir -p "$d/bin" "$d/keys"
    cat > "$d/stub.py" <<'PYSTUB'
import hashlib, json, os, re, struct, subprocess, sys, time

S = os.environ["KC_STUB"]
DEFAULTS = {"ms_mon_service_mode": "secure crc", "ms_service_mode": "crc secure", "ms_mon_client_mode": "secure crc", "ms_client_mode": "crc secure"}
BIT = {"crc": 2, "secure": 4}   # bit v for connection mode v (crc 1, secure 2), as the tools print it

def P(*a):
    return os.path.join(S, *a)

def rd(path, default=""):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return default

def wr(path, text):
    with open(path, "w") as f:
        f.write(text)

def cfg():
    return json.loads(rd(P("config.json"), "[]"))

def save_cfg(c):
    # config.json is the database; config.txt is the same in a form the shell fast paths of the stand-ins read
    wr(P("config.json"), json.dumps(c))
    wr(P("config.txt"), "".join("%s\t%s\t%s\n" % (e["section"], e["name"], e["value"]) for e in c))

def eff(who, name):
    v = DEFAULTS[name]
    for c in cfg():
        if c["name"] == name and c["section"] in (who, "global"):
            v = c["value"]
    return v

def toks(s):
    return [t for t in re.split(r"[ ,]+", s.strip()) if t]

def units():
    return [l.strip() for l in rd(P("units")).splitlines() if l.strip()]

def daemon_modes(kind):
    # the modes the daemons run with (read at their last start); the first daemon of the kind speaks for all of them
    for u in units():
        if u.startswith(kind + "."):
            return toks(rd(P("daemon_modes", u), eff(kind, "ms_mon_service_mode" if kind == "mon" else "ms_service_mode")))
    return ["crc", "secure"]

def pick(offer, allowed):
    for m in offer:
        if m in allowed:
            return m
    return None

def bits(allowed):
    return sum(BIT[m] for m in allowed)

# ---- ceph ------------------------------------------------------------------------------------------------------------------------------------------
def ceph(a):
    out = []
    i = 0
    while i < len(a):
        if a[i] == "--connect-timeout":
            i += 2
            continue
        out.append(a[i])
        i += 1
    a = out
    cmd = " ".join(a)
    if cmd == "config dump -f json":
        print(json.dumps(cfg()))
    elif a[:2] == ["config", "set"]:
        who, name, value = a[2], a[3], " ".join(a[4:])
        if name not in DEFAULTS:
            print("unknown option", file=sys.stderr)
            return 22
        c = [e for e in cfg() if not (e["section"] == who and e["name"] == name)]
        c.append({"section": who, "name": name, "value": value, "mask": "", "level": "advanced"})
        save_cfg(c)
    elif a[:2] == ["config", "rm"]:
        save_cfg([e for e in cfg() if not (e["section"] == a[2] and e["name"] == a[3])])
    elif cmd == "orch ps -f json":
        print(json.dumps([{"daemon_type": u.split(".")[0], "daemon_name": u, "status_desc": "running"} for u in units()]))
    elif cmd == "orch ps --refresh":
        pass
    elif a[:2] == ["auth", "get-or-create"]:
        user = a[2]
        print("[%s]\n\tkey = AQBthrowawaythrowawaythrowawaythrowaway00==" % user)
        with open(P("users"), "a") as u:
            u.write(user + "\n")
    elif a[:2] == ["auth", "get"]:
        return 0 if a[2] in rd(P("users")).split() else 2
    elif a[:2] == ["auth", "del"]:
        wr(P("users"), "".join(x + "\n" for x in rd(P("users")).split() if x != a[2]))
    else:
        print("stub ceph: unsupported: " + cmd, file=sys.stderr)
        return 1
    return 0

# ---- the image store -------------------------------------------------------------------------------------------------------------------------------
def size_of(s):
    m = re.match(r"^(\d+)([KMG]?)$", s)
    return int(m.group(1)) * {"": 1, "K": 1024, "M": 1 << 20, "G": 1 << 30}[m.group(2)]

def img_path(name):
    return P("images", name + ".json")

def load_img(name):
    t = rd(img_path(name), "")
    return json.loads(t) if t else None

def save_img(name, d):
    os.makedirs(P("images"), exist_ok=True)
    wr(img_path(name), json.dumps(d))

def apply(segs, s, e, pat):
    out = []
    for (a, b, p) in segs:
        if b <= s or a >= e:
            out.append([a, b, p])
        else:
            if a < s:
                out.append([a, s, p])
            if b > e:
                out.append([e, b, p])
    if pat != "zero":
        out.append([s, e, pat])
    out.sort()
    merged = []
    for x in out:
        if merged and merged[-1][1] == x[0] and merged[-1][2] == x[2]:
            merged[-1][1] = x[1]
        else:
            merged.append(x)
    return merged

def covered_by(segs, s, e, pat):
    if pat == "zero":
        return not any(a < e and b > s for (a, b, p) in segs)
    pos = s
    for (a, b, p) in sorted(segs):
        if b <= pos:
            continue
        if a > pos or p != pat:
            return False
        pos = b
        if pos >= e:
            return True
    return pos >= e

def rbd(a):
    opts = {}
    rest = []
    i = 0
    while i < len(a):
        x = a[i]
        if x.startswith("--debug_ms"):
            opts["debug"] = True
        elif x in ("--ms_mon_client_mode", "--ms_client_mode", "--image-format", "--image-feature", "--size"):
            opts[x] = a[i + 1]
            i += 1
        elif x.startswith("--"):
            pass
        else:
            rest.append(x)
        i += 1
    cmd, args = rest[0], rest[1:]
    if cmd == "create":
        name = args[-1].split("/")[-1]
        if load_img(name):
            print("exists", file=sys.stderr)
            return 17
        save_img(name, {"size": size_of(opts.get("--size", "64M")), "segs": []})
    elif cmd == "rm":
        name = args[-1].split("/")[-1]
        if not load_img(name):
            print("no such image", file=sys.stderr)
            return 2
        os.unlink(img_path(name))
    elif cmd == "info":
        name = args[-1].split("/")[-1]
        if not load_img(name):
            return 2
        for kind, port, optname, deflt in (("mon", 3300, "--ms_mon_client_mode", "secure crc"), ("osd", 6800, "--ms_client_mode", "crc secure")):
            m = pick(toks(opts.get(optname, deflt)), daemon_modes(kind))
            if m is None:
                print("unable to connect: (95) Operation not supported", file=sys.stderr)
                return 1
            if opts.get("debug"):
                print("2026-01-01 7f 1 -- 10.77.0.10:0/1 >> [v2:10.77.0.10:%d/0,v1:10.77.0.10:%d/0] conn(0x1 msgr2=0x2 %s :-1 s=STATE_CONNECTION_ESTABLISHED l=0).read" % (port, port + 1, m))
    elif cmd == "export":
        d = load_img(args[-2].split("/")[-1])
        if not d:
            return 2
        wr(args[-1], json.dumps(d, sort_keys=True))
    elif cmd == "import":
        with open(args[-2], "rb") as f:
            data = f.read()
        save_img(args[-1].split("/")[-1], {"size": len(data), "segs": [[0, len(data), "file:" + hashlib.sha256(data).hexdigest()]]})
    elif cmd == "ls":
        for f in sorted(os.listdir(P("images"))) if os.path.isdir(P("images")) else []:
            print(f[:-5])
    else:
        print("stub rbd: unsupported: " + cmd, file=sys.stderr)
        return 1
    return 0

# ---- wr-rbd and wr-monprobe ---------------------------------------------------------------------------------------------------------------------------
def offers(mode, mode_osd):
    def one(m, osd):
        return {"crc": ["crc"], "crc-first": ["crc", "secure"], "secure-first": ["secure", "crc"], "secure": ["secure"],
                "stock": ["crc", "secure"] if osd else ["secure", "crc"]}[m]
    return one(mode, False), one(mode_osd or mode, True)

def refusal(allowed):
    return 'status=WR_E_M2_BAD_METHOD peer_result=-95 what="server refused the authentication method or mode" allowed_modes=0x%x allowed_methods=0x4 offered_method=2' % bits(allowed)

def hint(who, allowed):
    # the words of the core's log record (wri_client_modes.c): the OSD's names mode_policy_osd, the monitor's mode_policy
    setting = "mode_policy_osd" if who == "OSD" else "mode_policy"
    print("winrbd WARN client WR_E_M2_BAD_METHOD conn=0x00000001 %s allows only %s mode: set %s to a policy that offers %s a0=0x4 a1=0x%x a2=0x0 a3=0x0"
          % (who, allowed[0], setting, allowed[0], bits(allowed)), file=sys.stderr)

# ---- tcpdump -----------------------------------------------------------------------------------------------------------------------------------------
def pcap_write(path):
    # A Linux cooked v2 capture of what the stand-in tools "sent" since the capture started (wire.log: one line per fill / verify of the pattern `seq`,
    # with the mode of the OSD connection): on the client's connection to the first OSD's public port, the pattern when it was crc (or always, with
    # leak_secure: a core that sends its secure frames in the clear) and noise when it was secure; nothing of it with blind_capture. On top, as on the
    # stock cluster, the OSDs replicate the write to each other over the cluster network in crc mode: the pattern in the clear on a cluster port, which
    # the wire check must not count against the client.
    log = rd(P("wire.log")).split()
    pat = bytes(range(256)) * 128
    pk = []
    if not os.path.exists(P("blind_capture")):
        for m in log:
            clear = m == "crc" or os.path.exists(P("leak_secure"))
            pk += [(40000, 6800, pat if clear else os.urandom(len(pat)))] * 4
    if log:
        pk += [(6802, 41000, pat)] * 4
    out = [struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 276)]
    for sp, dp, pl in pk:
        ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 40 + len(pl), 0, 0, 64, 6, 0, bytes([10, 77, 0, 10]), bytes([10, 77, 0, 10]))
        tcp = struct.pack(">HHIIBBHHH", sp, dp, 0, 0, 5 << 4, 0x18, 65535, 0, 0)
        frame = bytes(20) + ip + tcp + pl
        out.append(struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame)
    with open(path, "wb") as f:
        f.write(b"".join(out))

def tool(name, a):
    o = {"mode": "crc", "mode_osd": None, "require": None, "accel": False, "rw": False, "image": None}
    pos = []
    i = 0
    valued = ("--mon", "--user", "--keyring", "--pool", "--image", "--mode", "--mode-osd", "--require-mode", "--depth", "--model-bytes", "--max-len",
              "--save", "--timeout", "--pattern", "--file", "--io-size")
    while i < len(a):
        x = a[i]
        if x in valued:
            v = a[i + 1]
            i += 1
            if x == "--mode":
                o["mode"] = v
            elif x == "--mode-osd":
                o["mode_osd"] = v
            elif x == "--require-mode":
                o["require"] = v
            elif x == "--image":
                o["image"] = v
            elif x == "--keyring":
                o["keyring"] = v
            elif x == "--pattern":
                o["pattern"] = v
            elif x == "--model-bytes":
                o["model"] = size_of(v)
        elif x == "--accel":
            o["accel"] = True
        elif x == "--rw":
            o["rw"] = True
        elif x.startswith("--"):
            pass
        else:
            pos.append(x)
        i += 1
    if o["accel"] and os.path.exists(P("no_aesni")):
        print("%s: --accel: this build or CPU has no AES-NI / PCLMULQDQ GCM hook: refused" % name, file=sys.stderr)
        return 2
    if "wrong." in o.get("keyring", ""):   # a secret the cluster does not know: the peer answers AUTH_BAD_METHOD with -EACCES (13), nothing connects
        print("@5 event AUTH_FAILED status=WR_E_M2_BAD_METHOD module=3 peer_result=-13 what=\"server refused the authentication method or mode\" allowed_modes=0x6 allowed_methods=0x4 offered_method=2")
        if name == "wr-monprobe":
            print("@8000 result active=0 timeout last_error=WR_E_M2_BAD_METHOD")
        else:
            print("@8000 result open ok=0 state=FAILED status=WR_E_TIMEOUT peer_result=0")
        print("@8001 stats conns_secure=0 conns_crc=0 sec_failures=0 accel=0 gcm=portable gcm_ops=0")
        return 1 if name == "wr-monprobe" else 3
    mon_offer, osd_offer = offers(o["mode"], o["mode_osd"])
    if os.path.exists(P("tool.hook.run")):
        subprocess.call(["bash", P("tool.hook.run")])
        os.unlink(P("tool.hook.run"))
    if os.path.exists(P("hang_forced")) and daemon_modes("mon") == ["secure"] and name == "wr-rbd":
        wr(P("hung"), "1")
        time.sleep(120)
    secure = crc = 0
    mm = pick(mon_offer, daemon_modes("mon"))
    if mm is None:
        r = refusal(daemon_modes("mon"))
        hint("monitor", daemon_modes("mon"))
        if name == "wr-monprobe":
            print("@2 event AUTH_FAILED %s" % r)
            print("@15000 result active=0 timeout last_error=M2_BAD_METHOD")
            print("@15000 stats conns_secure=0 conns_crc=0 sec_failures=0 accel=0 gcm=portable gcm_ops=0")
            return 1
        print("@5 event AUTH_FAILED %s" % r)
        print("@5 result open ok=0 state=FAILED status=WR_E_TIMEOUT peer_result=0")
        print("@6 stats conns_secure=0 conns_crc=0 sec_failures=0 accel=0 gcm=portable gcm_ops=0")
        return 3
    secure += mm == "secure"
    crc += mm == "crc"
    rc = 0
    if name == "wr-rbd":
        om = pick(osd_offer, daemon_modes("osd"))
        if om is None:
            hint("OSD", daemon_modes("osd"))
            print("@5 event IO_STALL %s" % refusal(daemon_modes("osd")))
            print("@5 result open ok=0 state=FAILED status=WR_E_TIMEOUT peer_result=0")
            print("@6 stats conns_secure=%d conns_crc=%d sec_failures=0 accel=0 gcm=portable gcm_ops=0" % (secure, crc))
            return 3
        secure += 2 * (om == "secure")
        crc += 2 * (om == "crc")
        img = load_img(o["image"])
        if img is None:
            print("@5 result open ok=0 state=FREE status=RBD_NOT_FOUND WR_E_RBD_NOT_FOUND")
            return 3
        cmd = pos[0] if pos else ""
        segs = img["segs"]
        if cmd in ("fill", "verify") and o.get("pattern") == "seq":   # what a capture of the wire would see: the pattern in the clear on a crc connection
            with open(P("wire.log"), "a") as wl:
                wl.write(("secure" if om == "secure" else "crc") + "\n")
        if cmd == "info":
            print("@5 image id=1 size=%d features=0x1 writable=%d" % (img["size"], 1 if o["rw"] else 0))
            print("@5 result info ok=1 state=OPEN")
        elif cmd in ("fill", "write", "zeroes", "discard"):
            if not o["rw"]:
                print("wr-rbd: need --rw", file=sys.stderr)
                return 2
            off, ln = size_of(pos[1]), size_of(pos[2])
            pat = "zero" if cmd in ("zeroes", "discard") else o.get("pattern", "rand:1")
            img["segs"] = apply(segs, off, off + ln, pat)
            save_img(o["image"], img)
            print("@6 result %s ok=1 off=%d len=%d diffs=0 errors=0" % (cmd, off, ln))
        elif cmd == "verify":
            off, ln = size_of(pos[1]), size_of(pos[2])
            if covered_by(segs, off, off + ln, o.get("pattern", "zero")):
                print("@6 result verify ok=1 off=%d len=%d diffs=0" % (off, ln))
            else:
                print("@6 result verify ok=0 first_diff=%d" % off)
                rc = 1
        elif cmd == "random":
            if not o["rw"]:
                return 2
            img["segs"] = apply(segs, 0, o.get("model", 33554432), "run:" + pos[2])
            save_img(o["image"], img)
            print("@9 result random ok=1 ops=%s read_mismatches=0 final_diff_bytes=0 errors=0 barrier_violations=0 bad_completions=0" % pos[1])
        elif cmd == "compare":
            with open(pos[1], "rb") as f:
                txt = f.read()
            try:
                same = json.loads(txt) == json.loads(json.dumps(img, sort_keys=True))
            except ValueError:
                same = img["segs"] == [[0, len(txt), "file:" + hashlib.sha256(txt).hexdigest()]] and img["size"] == len(txt)
            print("@6 result compare ok=%d" % (1 if same else 0))
            rc = 0 if same else 1
        else:
            print("stub wr-rbd: unsupported: " + cmd, file=sys.stderr)
            return 2
    else:
        print("@2 event MON_SESSION_UP")
        print("@3 result active=1 monmap_epoch=3 maps=11")
    gcm = "host" if o["accel"] and secure else "portable"
    print("@7 stats ops_done=1 conns_secure=%d conns_crc=%d sec_failures=0 accel=%d gcm=%s gcm_ops=%d" % (secure, crc, 1 if o["accel"] else 0, gcm, 5 if gcm == "host" else 0))
    if o["require"]:
        ok = (crc == 0 and secure != 0) if o["require"] == "secure" else (secure == 0 and crc != 0)
        print("@7 result require_mode ok=%d wanted=%s conns_secure=%d conns_crc=%d sec_failures=0" % (1 if ok else 0, o["require"], secure, crc))
        if not ok and rc not in (1, 4):
            rc = 3
    return rc

def main():
    t = sys.argv[1]
    a = sys.argv[2:]
    if t == "tcpdump-write":
        pcap_write(a[0])
        return 0
    if t == "ceph":
        return ceph(a)
    if t == "rbd":
        return rbd(a)
    return tool(t, a)

sys.exit(main())
PYSTUB
    for t in rbd wr-rbd wr-monprobe; do
        printf '#!/bin/bash\nexec python3 -I -S "%s/stub.py" %s "$@"\n' "$d" "$t" > "$d/bin/$t"
    done
    # ceph and systemctl: the calls a run makes most often (state, config get, pg stat, restart) are shell, the rest goes to python
    cat > "$d/bin/ceph" <<'STUB'
#!/bin/bash
S=$KC_STUB
args=(); skip=0
for a in "$@"; do
    if [ "$skip" = 1 ]; then skip=0; continue; fi
    if [ "$a" = --connect-timeout ]; then skip=1; continue; fi
    args+=("$a")
done
case "${args[*]}" in
    "osd stat -f json") echo '{"epoch":7,"num_osds":3,"num_up_osds":3,"num_in_osds":3}'; exit 0 ;;
    "pg stat -f json")
        n=$(cat "$S/unclean" 2>/dev/null); n=${n:-0}
        if [ "$n" -gt 0 ]; then echo $((n - 1)) > "$S/unclean"; echo '{"pg_summary":{"num_pg_by_state":[{"name":"active+undersized+degraded","num":5},{"name":"active+clean","num":28}]}}'
        else echo '{"pg_summary":{"num_pg_by_state":[{"name":"active+clean","num":33}]}}'; fi
        exit 0 ;;
    "health detail -f json") cat "$S/ceph/health.json"; exit 0 ;;
    "osd tree -f json") cat "$S/ceph/tree.json"; exit 0 ;;
    "osd dump -f json") cat "$S/ceph/dump.json"; exit 0 ;;
    "osd pool ls detail -f json") cat "$S/ceph/pools.json"; exit 0 ;;
    "config get "*)
        who=${args[2]}; name=${args[3]}
        case "$name" in ms_mon_service_mode|ms_mon_client_mode) v='secure crc' ;; ms_service_mode|ms_client_mode) v='crc secure' ;; *) exit 22 ;; esac
        while IFS=$'\t' read -r sec n val; do
            if [ "$n" = "$name" ] && { [ "$sec" = "$who" ] || [ "$sec" = global ]; }; then v=$val; fi
        done < "$S/config.txt"
        echo "$v"; exit 0 ;;
esac
exec python3 -I -S "$S/stub.py" ceph "$@"
STUB
    cat > "$d/bin/systemctl" <<'STUB'
#!/bin/bash
S=$KC_STUB
FSID=52762725-e19a-11f1-886d-525400770001
case "$1" in
    list-units) while read -r u; do [ -n "$u" ] && echo "ceph-$FSID@$u.service loaded active running Ceph $u"; done < "$S/units"; exit 0 ;;
    restart)
        name=${2#ceph-*@}; name=${name%.service}
        [ ! -e "$S/restart.fail" ] || { echo "Job for $2 failed" >&2; exit 1; }
        kind=${name%%.*}
        if [ "$kind" = mon ]; then opt=ms_mon_service_mode; v='secure crc'; else opt=ms_service_mode; v='crc secure'; fi
        while IFS=$'\t' read -r sec n val; do
            if [ "$n" = "$opt" ] && { [ "$sec" = "$kind" ] || [ "$sec" = global ]; }; then v=$val; fi
        done < "$S/config.txt"
        mkdir -p "$S/daemon_modes"
        echo "$v" > "$S/daemon_modes/$name"
        echo "$name $v" >> "$S/restart.log"
        echo 2 > "$S/unclean"
        exit 0 ;;
    is-active|reset-failed) exit 0 ;;
esac
exit 1
STUB
    cat > "$d/bin/sudo" <<'STUB'
#!/bin/bash
while [ $# -gt 0 ]; do case "$1" in -n|-E|-S) shift ;; *) break ;; esac; done
exec "$@"
STUB
    cat > "$d/bin/krbd-compare.sh" <<'STUB'
#!/bin/bash
echo "CASE k2-o12 PASS ok=1 stub"
echo "CASE k1-o12 PASS ok=1 stub"
echo "state: the lab matches the snapshot taken before (after)"
exit "$(cat "$KC_STUB/krbd.rc" 2>/dev/null || echo 0)"
STUB
    cat > "$d/bin/tcpdump" <<'STUB'
#!/bin/bash
# a capture of what the stand-in tools "sent": the recognisable pattern when a crc connection carried it, noise when only secure ones did
f=""; while [ $# -gt 0 ]; do case "$1" in -w) f=$2; shift ;; esac; shift; done
: > "$KC_STUB/wire.log"
echo pcap > "$f"
finish() {
    python3 -I -S "$KC_STUB/stub.py" tcpdump-write "$f"
    exit 0
}
trap finish TERM
sleep 60 >/dev/null 2>&1 & wait
STUB
    chmod +x "$d"/bin/*
    for t in "$USER_K2" "$USER_K1"; do   # a keyring of the real shape (a key of a made-up value: type, created time, length, secret)
        python3 -I -c 'import base64, struct, sys
raw = struct.pack("<HIIH", 4, 0, 0, 32) + bytes(range(32))
open(sys.argv[2], "w").write("[client.%s]\n\tkey = %s\n" % (sys.argv[1], base64.b64encode(raw).decode()))' "$t" "$d/keys/client.$t.keyring"
    done
    chmod 600 "$d"/keys/*
}

# the cluster as the lab starts: no option set, every daemon on the defaults, nothing left from an earlier run
reset_stub_cluster() { # <dir>
    local d=$1 u
    rm -rf "$d/images" "$d/daemon_modes" "$d/ceph" "$d/cap"
    rm -f "$d/restart.log" "$d/unclean" "$d/users" "$d/hung" "$d/restart.fail" "$d/tool.hook.run" "$d/hang_forced" "$d/no_aesni" "$d/krbd.rc" "$d/leak_secure" "$d/blind_capture"
    mkdir -p "$d/ceph" "$d/images" "$d/daemon_modes"
    echo '[]' > "$d/config.json"; : > "$d/config.txt"
    printf 'mon.winrbd-ceph1\nosd.0\nosd.1\nosd.2\n' > "$d/units"
    echo 'secure crc' > "$d/daemon_modes/mon.winrbd-ceph1"
    for u in osd.0 osd.1 osd.2; do echo 'crc secure' > "$d/daemon_modes/$u"; done
    echo '{"checks":{"AUTH_INSECURE_KEYS_ALLOWED":{"severity":"HEALTH_WARN"},"BLUESTORE_SLOW_OP_ALERT":{"severity":"HEALTH_WARN"}}}' > "$d/ceph/health.json"
    echo '{"nodes":[{"id":-1,"name":"default","type":"root"},{"id":0,"name":"osd.0","type":"osd","status":"up","reweight":1,"primary_affinity":1},{"id":1,"name":"osd.1","type":"osd","status":"up","reweight":1,"primary_affinity":1}]}' > "$d/ceph/tree.json"
    echo '{"flags_set":["sortbitwise"],"osds":[{"osd":0,"up":1,"in":1,"weight":1,"public_addrs":{"addrvec":[{"type":"v2","addr":"10.77.0.10:6800"}]}},{"osd":1,"up":1,"in":1,"weight":1,"public_addrs":{"addrvec":[{"type":"v2","addr":"10.77.0.10:6808"}]}}],"pg_upmap":[],"pg_upmap_items":[],"pg_upmap_primaries":[]}' > "$d/ceph/dump.json"
    echo '[{"pool_name":"winrbd","size":3,"min_size":2,"crush_rule":0,"application_metadata":{"rbd":{}}}]' > "$d/ceph/pools.json"
}

ST_FAILED=0; ST_N=0; ST_RC=0; ST_OUT=""
st_expect() { # <what> <command...>
    local what=$1; shift
    if "$@"; then echo "  ok   $what"; else echo "  FAIL $what"; ST_FAILED=$((ST_FAILED + 1)); fi
}
st_has()   { printf '%s\n' "$ST_OUT" | grep -Eq -- "$1"; }
st_hasnt() { ! printf '%s\n' "$ST_OUT" | grep -Eq -- "$1"; }
st_restored() { # the stub cluster is as it started: no option set, every daemon running with the original options, no image or user left
    local d=$1 u
    [ "$(cat "$d/config.json")" = '[]' ] || return 1
    [ "$(cat "$d/daemon_modes/mon.winrbd-ceph1")" = 'secure crc' ] || return 1
    for u in osd.0 osd.1 osd.2; do [ "$(cat "$d/daemon_modes/$u")" = 'crc secure' ] || return 1; done
    [ -z "$(ls "$d/images")" ] || return 1
    [ ! -s "$d/users" ] || return 1
}
st_restarts() { wc -l < "$1/restart.log" 2>/dev/null || echo 0; }

# st_env <dir> <work-name>: the environment of a run on the stand-ins
st_env() {
    echo "KC_STUB=$1" "PATH=$1/bin:$PATH" "WR_BUILD_DIR=$1/bin" "WR_RBD=$1/bin/wr-rbd" "WR_MONPROBE=$1/bin/wr-monprobe" "SL_KRBD_COMPARE=$1/bin/krbd-compare.sh" \
         "WR_LAB_KEYRING_DIR=$1/keys" "WR_LAB_WORK=$1/$2" "WR_LAB_SUDO=sudo" "SL_STATE_WAIT=0" "SL_RESTART_WAIT=20" "SL_POLL=0.1" "SL_NO_MON_CHECK=1" \
         "SL_WIRE_MIN_BYTES=131072"
}
st_run() { # <dir> <args...>: a run in a work directory of its own; sets ST_OUT and ST_RC
    local d=$1; shift
    ST_N=$((ST_N + 1))
    # shellcheck disable=SC2046
    ST_OUT=$(env $(st_env "$d" "work-$ST_N") "SL_NAME_TAG=st$ST_N" "$SELF" "$@" 2>&1)
    ST_RC=$?
    # SL_SELFTEST_VERBOSE=1: what a run that did not exit 0 printed (the injected failures and the refusals of the matrix are expected ones)
    if [ "$ST_RC" -ne 0 ] && [ -n "${SL_SELFTEST_VERBOSE:-}" ]; then printf '%s\n' "$ST_OUT" | grep -E '^(FAIL|secure-live: error)' -A6 | head -n 40 | sed 's/^/    | /'; fi
}

selftest_main() {
    local d step steps pid waited
    if [ "${BASH_VERSINFO[0]}" -lt 4 ] || [ "$(uname -s)" != Linux ] || ! command -v python3 >/dev/null || ! command -v timeout >/dev/null || ! command -v mktemp >/dev/null; then
        echo "SKIP: the selftest needs bash 4+, Linux, python3, timeout and mktemp"; return 77
    fi
    d=$(mktemp -d "${TMPDIR:-/tmp}/secure-live-selftest.XXXXXX") || die "mktemp failed"
    case "$d" in */secure-live-selftest.??????) ;; *) die "unexpected selftest directory $d" ;; esac
    # a self test that is stopped (Ctrl-C, ctest's timeout sends TERM first) removes its stand-in cluster too
    trap 'rm -rf -- "$d"' EXIT
    trap 'exit 1' INT TERM HUP
    write_stubs "$d"
    echo "selftest with stand-in ceph / rbd / systemctl / wr-rbd / wr-monprobe in $d"

    # a full run on the stand-in cluster: every check passes, the forced sections restart the daemons, the restore puts everything back
    reset_stub_cluster "$d"
    st_run "$d" --keys both --quick
    st_expect "a full run exits 0 ($ST_RC)" test "$ST_RC" -eq 0
    st_expect "a full run: no failed check" st_hasnt '^FAIL '
    st_expect "a full run: the monitor refusal was captured with its result code" st_has 'CAPTURE forced-secure-monitor-crc-only: peer_result=-95 allowed_modes=0x4'
    st_expect "a full run: the reverse refusal names {crc}" st_has 'CAPTURE forced-crc-osd-secure-only: peer_result=-95 allowed_modes=0x2'
    st_expect "a full run: the policy table was printed" st_has 'TABLE policy=stock key=k2 core_monitor=secure core_osd=crc stock="mon=secure osd=crc"'
    st_expect "a full run: the state matches" st_has 'state: the lab matches the snapshot'
    st_expect "a full run: restore done, cleanup clean" st_has 'restore: done; cleanup: clean; state: as-before'
    st_expect "a full run: 12 daemon restarts (4 for each forced section and 4 for the restore)" test "$(st_restarts "$d")" -eq 12
    st_expect "a full run: the monitor is restarted first in every round" test "$(awk 'NR % 4 == 1 { print $1 }' "$d/restart.log" | sort -u)" = mon.winrbd-ceph1
    st_expect "a full run: the cluster is as it started" st_restored "$d"

    # a run that leaves the daemons alone changes nothing
    reset_stub_cluster "$d"
    st_run "$d" --keys k2 --quick --skip-forced
    st_expect "--skip-forced exits 0 ($ST_RC)" test "$ST_RC" -eq 0
    st_expect "--skip-forced restarts nothing" test ! -e "$d/restart.log"
    # the refusal captures and the throwaway user of --capture-dir
    reset_stub_cluster "$d"
    st_run "$d" --keys k2 --quick --skip-krbd --only forced-secure --capture-dir "$d/cap"
    st_expect "--capture-dir exits 0 ($ST_RC)" test "$ST_RC" -eq 0
    st_expect "--capture-dir: one text capture and one pcap per refusal" test "$(ls "$d"/cap/*.txt | wc -l)" -eq 3 -a "$(ls "$d"/cap/*.pcap | wc -l)" -eq 3
    st_expect "--capture-dir: the capture holds the result code and the allowed modes" grep -q 'peer_result=-95 .*allowed_modes=0x4' "$d/cap/refusal-forced-secure-whole-crc-only.txt"
    st_expect "--capture-dir: the refusals used the throwaway user" grep -q 'user client.wrtest-sl-st' "$d/cap/refusal-forced-secure-monitor-crc-only.txt"
    st_expect "--capture-dir: the throwaway user is deleted again" st_restored "$d"
    # no AES-NI: the accel check is a note, not a failure
    reset_stub_cluster "$d"; : > "$d/no_aesni"
    st_run "$d" --keys k2 --quick --skip-krbd --only client
    st_expect "a CPU without the hook passes (the accel check is a note) ($ST_RC)" test "$ST_RC" -eq 0
    st_expect "a CPU without the hook: the note is there" st_has 'no AES-NI'
    # the wire check: the full run above saw the OSDs' replication in the clear (the stub writes it into every capture) and passed; a client connection
    # that carries the pattern in secure mode fails it, and so does a capture that did not see the client's traffic
    st_expect "the wire check passed although the replication between the OSDs carried the pattern" st_has '^PASS  k2 wire: not one run of the pattern in the secure capture'
    reset_stub_cluster "$d"; : > "$d/leak_secure"
    st_run "$d" --keys k2 --quick --skip-krbd --only client
    st_expect "the pattern in the clear on a secure client connection fails the run ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "the pattern in the clear on a secure client connection is named" st_has '^FAIL  k2 wire: the secure capture holds [0-9]+ runs of the pattern on the client'
    reset_stub_cluster "$d"; : > "$d/blind_capture"
    st_run "$d" --keys k2 --quick --skip-krbd --only client
    st_expect "a capture blind to the client's connections fails the run ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "a blind secure capture is not taken for proof" st_has '^FAIL  k2 wire: the secure capture holds only 0 bytes'
    st_expect "a blind crc capture is named as blind" st_has '^FAIL  k2 wire: the crc capture shows the pattern only 0 times'
    # another run forces the cluster while this one only reads: the option is reported, NOT removed, and nothing is restarted
    reset_stub_cluster "$d"
    cat > "$d/tool.hook.run" <<HOOK
echo '[{"section":"osd","name":"ms_service_mode","value":"secure","mask":"","level":"advanced"}]' > "$d/config.json"
printf 'osd\tms_service_mode\tsecure\n' > "$d/config.txt"
HOOK
    st_run "$d" --keys k2 --quick --skip-krbd --skip-forced --only client
    st_expect "an option set by someone else during a run that set none fails the run ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "the foreign option is reported" st_has 'changed during the run although this run set none'
    st_expect "the foreign option is left as it is" grep -q '"name":"ms_service_mode","value":"secure"' "$d/config.json"
    st_expect "nothing was restarted under the foreign option" test ! -e "$d/restart.log"
    # a cluster that is not at its defaults: the policy table must notice
    reset_stub_cluster "$d"
    echo '[{"section":"mon","name":"ms_mon_service_mode","value":"crc","mask":"","level":"advanced"}]' > "$d/config.json"; echo crc > "$d/daemon_modes/mon.winrbd-ceph1"
    st_run "$d" --keys k2 --quick --skip-krbd --skip-forced --only policy
    st_expect "a lab that already has a mode option set is not taken as the baseline (exit $ST_RC)" test "$ST_RC" -eq 2
    st_expect "the refusal says that another run may have the cluster forced" st_has 'another run may have the cluster forced'
    SL_ALLOW_BASELINE_OPTIONS=1 st_run "$d" --keys k2 --quick --skip-krbd --skip-forced --only policy
    st_expect "with the override, a cluster that differs from the default fails the policy table ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "the failed check is named" st_has '^FAIL .*policy'
    # the krbd comparison failing fails the run
    reset_stub_cluster "$d"; echo 1 > "$d/krbd.rc"
    st_run "$d" --keys k2 --quick --only krbd
    st_expect "a failing krbd comparison fails the run ($ST_RC)" test "$ST_RC" -ne 0

    # a failure injected at every step: the run fails, and the restore still ran (options back, daemons restarted under them, images gone). Each
    # run is limited to the section the step belongs to, to keep the self test short.
    steps="create-a:client create-r:client create-c-k2:client export-k2:client import-k2:client krbd-compare:krbd
           set-mon-ms_mon_service_mode-secure:forced-secure set-osd-ms_service_mode-secure:forced-secure restart-mon:forced-secure restart-osd:forced-secure
           export-forced-k2:forced-secure set-mon-ms_mon_service_mode-crc:forced-crc set-osd-ms_service_mode-crc:forced-crc"
    for step in $steps; do
        reset_stub_cluster "$d"
        st_run "$d" --keys k2 --quick --only "${step#*:}" --inject-fail "${step%%:*}"
        st_expect "step '${step%%:*}' injected: the run fails ($ST_RC)" test "$ST_RC" -ne 0
        st_expect "step '${step%%:*}' injected: the injection was reached" st_has "injected failure at step '${step%%:*}'"
        st_expect "step '${step%%:*}' injected: the options and daemons are back, no image left" st_restored "$d"
        st_expect "step '${step%%:*}' injected: the state matches the snapshot" st_has 'state: the lab matches'
    done
    # the second set failing leaves the monitor on the forced option: the restore restarts the daemons (the forced round's own restarts are skipped)
    reset_stub_cluster "$d"
    st_run "$d" --keys k2 --quick --skip-krbd --only forced-secure --inject-fail set-osd-ms_service_mode-secure
    st_expect "a failed second set: the restore restarted the daemons ($(st_restarts "$d") restarts)" test "$(st_restarts "$d")" -eq 4
    st_expect "a failed second set: the cluster is as it started" st_restored "$d"
    # a failed first set changes nothing: no restart at all
    reset_stub_cluster "$d"
    st_run "$d" --keys k2 --quick --skip-krbd --only forced-secure --inject-fail set-mon-ms_mon_service_mode-secure
    st_expect "a failed first set: nothing was restarted" test ! -e "$d/restart.log"

    # the restore itself failing is not hidden, and the next run refuses to start over a lab that may still have the forced options
    reset_stub_cluster "$d"; : > "$d/restart.fail"
    st_run "$d" --keys k2 --quick --skip-krbd --only forced-secure
    st_expect "a restore that cannot restart the daemons fails the run ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "a restore that cannot restart the daemons says so" st_has 'restore: FAILED'
    st_expect "the options were put back even so" test "$(cat "$d/config.json")" = '[]'
    rm -f "$d/restart.fail"
    # shellcheck disable=SC2046
    ST_OUT=$(env $(st_env "$d" "work-$ST_N") "$SELF" --keys k2 --quick --skip-forced 2>&1); ST_RC=$?
    st_expect "the next run over an unfinished restore refuses to start (exit $ST_RC)" test "$ST_RC" -eq 2
    st_expect "the refusal says what to check" st_has 'earlier run did not finish restoring'

    # the lab drifts during the run (an upmap appears): the run notices
    reset_stub_cluster "$d"
    printf '%s\n' "sed -i 's/\"pg_upmap\":\[\]/\"pg_upmap\":[{\"pgid\":\"2.1\"}]/' \"$d/ceph/dump.json\"" > "$d/tool.hook.run"
    st_run "$d" --keys k2 --quick --skip-krbd --skip-forced
    st_expect "a drifted cluster state fails the run ($ST_RC)" test "$ST_RC" -ne 0
    st_expect "a drifted cluster state is reported" st_has 'cluster state differs'

    # killed with TERM while a client runs against the forced cluster: the trap restores
    reset_stub_cluster "$d"; : > "$d/hang_forced"
    ST_N=$((ST_N + 1))
    # shellcheck disable=SC2046
    env $(st_env "$d" "work-$ST_N") "SL_NAME_TAG=stk" "$SELF" --keys k2 --quick --skip-krbd --only forced-secure > "$d/killed.out" 2>&1 &
    pid=$!; waited=0
    while [ ! -e "$d/hung" ] && [ "$waited" -lt 600 ]; do sleep 0.1; waited=$((waited + 1)); done
    kill -TERM "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    ST_OUT=$(cat "$d/killed.out")
    st_expect "killed with TERM while the cluster is forced: the options and daemons are back, no image left" st_restored "$d"
    st_expect "killed with TERM: the restore says so" st_has 'restore: done'
    st_expect "killed with TERM: the daemons were restarted under the original options" test "$(st_restarts "$d")" -eq 8

    rm -rf -- "$d"
    if [ "$ST_FAILED" -ne 0 ]; then echo "selftest: $ST_FAILED check(s) FAILED"; return 1; fi
    echo "selftest: all checks passed"
    return 0
}

if [ "$selftest" = 1 ]; then
    selftest_main
    exit $?
fi
main
exit "$FINAL_RC"
