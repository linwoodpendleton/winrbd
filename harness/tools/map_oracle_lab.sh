#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# map_oracle_lab.sh - the live comparison of the core's OSD map, placement and CRUSH code (through harness/oracle/wr-maporacle)
# with Ceph's own tools on the lab cluster (docs/design/core-architecture.md 18.3 and 18.4).
#
#   map_oracle_lab.sh --selftest        no cluster: every committed vector through the built tool and the comparison code, plus
#                                       negative tests (python3 only). ctest runs it as oracle.selftest.
#   map_oracle_lab.sh run [options]     on the lab VM (passwordless sudo, cephadm; the admin CLI is used through `sudo ceph` and
#                                       `sudo cephadm shell` for osdmaptool / crushtool / the rados python module): drives each state
#                                       of 18.3 with the admin CLI, saves the map after each change, asks `ceph osd map -f json` for the
#                                       large name set once per pool geometry and osdmaptool for every PG of every pool in every state,
#                                       runs wr-maporacle on the same maps, diffs (map_oracle_diff.py), restores the cluster and verifies
#                                       the restore. Prints the number of comparisons and the first mismatches. Exit 0 only when nothing
#                                       differs, every state was reached, the restore verified and the chain step ran.
#   map_oracle_lab.sh cleanup           removes whatever a failed run left (pools wrtest-or-*, their rule / profile / weight sets, the
#                                       overrides it set) and puts the cluster back as `run` found it (needs the saved baseline).
#
# Options of `run`:   --tool PATH   the wr-maporacle binary (default $WR_MAPORACLE, else build/harness/wr-maporacle under the repository)
#                     --work DIR    work directory, at least two levels below $HOME (default ~/w/oracle-lab/work); maps, tables, logs
#                     --names N     names per pool for the name oracle (default 700; 8 pools: 5,600 names; --quick uses 60)
#                     --states LIST comma separated state labels or prefixes to run (default all: s01 .. s15, crush)
#                     --quick       a short run for development: 60 names per pool, no split / merge polling, shorter waits
#                     --no-chain    skip the incremental chain step (it copies the monitor store, read-only, and deletes the copy)
#
# What the run may touch (CONTRIBUTING.md, lab rules): pools named wrtest-or-* (its own prefix: other users' wrtest-* pools are never
# touched), one extra crush rule, one erasure-code profile, a weight set of a test pool, OSD-wide upmap / temp / affinity / reweight /
# out / noup entries for a few seconds each, require_min_compat_client (raised to reef for upmap-primary, then put back) and
# mon_allow_pool_delete. All of it is restored at the end and checked against a baseline taken first. It never touches the pool
# 'winrbd', removes or destroys no OSD or monitor, and does not touch any key (the keyrings are not read; the monitor store copy of the
# chain step is read with a tool inside the cephadm container, holds the monitor's own auth database, and is deleted right after).
# Nothing in the output is secret; the maps it saves stay in the work directory (they carry the lab fsid and OSD uuids).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIFF="$HERE/map_oracle_diff.py"

die() { echo "map_oracle_lab.sh: $*" >&2; exit 2; }

find_tool() {
  local t="${TOOL_ARG:-${WR_MAPORACLE:-}}"
  if [ -z "$t" ]; then
    for c in "$REPO/build/harness/wr-maporacle" "$REPO/build/wr-maporacle" "$REPO/harness/build/wr-maporacle"; do
      [ -x "$c" ] && { t="$c"; break; }
    done
  fi
  [ -n "$t" ] && [ -x "$t" ] || die "wr-maporacle not found: build it (cmake --build ... --target wr-maporacle) and pass --tool or set WR_MAPORACLE"
  echo "$t"
}

CMD="${1:-}"
TOOL_ARG=""
case "$CMD" in
  --selftest)
    shift
    while [ $# -gt 0 ]; do case "$1" in --tool) TOOL_ARG="$2"; shift 2;; *) die "unknown option $1";; esac; done
    command -v python3 >/dev/null || die "python3 is needed"
    TOOL="$(find_tool)"
    exec python3 -I "$DIFF" selftest --tool "$TOOL" --vectors "$REPO/harness/vectors"
    ;;
  run|cleanup|--run|--cleanup)
    CMD="${CMD#--}"
    shift
    ;;
  ""|-h|--help)
    sed -n '3,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
  *)
    die "unknown command '$CMD' (--selftest, run, cleanup; --help)"
    ;;
esac

NAMES=700; STATES=""; QUICK=0; CHAIN=1; WORK_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tool) TOOL_ARG="$2"; shift 2;;
    --work) WORK_ARG="$2"; shift 2;;
    --names) NAMES="$2"; shift 2;;
    --states) STATES="$2"; shift 2;;
    --quick) QUICK=1; NAMES=60; shift;;
    --no-chain) CHAIN=0; shift;;
    *) die "unknown option $1";;
  esac
done
command -v python3 >/dev/null || die "python3 is needed"
command -v sudo >/dev/null || die "sudo is needed (the admin CLI runs through it)"
TOOL="$(find_tool)"
export ORACLE_TOOL="$TOOL" ORACLE_TOOLS_DIR="$HERE" ORACLE_CMD="$CMD" ORACLE_NAMES="$NAMES" ORACLE_STATES="$STATES" \
       ORACLE_QUICK="$QUICK" ORACLE_CHAIN="$CHAIN" ORACLE_WORK="${WORK_ARG:-${HOME:-/nonexistent}/w/oracle-lab/work}"
exec python3 -I - <<'PYEOF'
import collections, json, os, random, re, shutil, string, subprocess, sys, time, traceback

sys.path.insert(0, os.environ["ORACLE_TOOLS_DIR"])
import map_oracle_diff as D

TOOL = D.Tool(os.environ["ORACLE_TOOL"])
CMD = os.environ["ORACLE_CMD"]
NAMES_PER_POOL = int(os.environ["ORACLE_NAMES"])
ONLY = [s for s in os.environ["ORACLE_STATES"].split(",") if s]
QUICK = os.environ["ORACLE_QUICK"] == "1"
CHAIN = os.environ["ORACLE_CHAIN"] == "1"
PFX = "wrtest-or-"          # every pool, rule and profile this script creates starts with it; nothing else is ever removed
ME = "%d:%d" % (os.getuid(), os.getgid())


def safe_work(w):
    """the work directory is written and partly deleted: it must be at least two levels below the home directory"""
    w = os.path.realpath(w)
    h = os.path.realpath(os.path.expanduser("~"))
    if not w.startswith(h + os.sep) or len(os.path.relpath(w, h).split(os.sep)) < 2:
        raise SystemExit("refusing %s as the work directory: it must be at least two levels below %s" % (w, h))
    return w


WORK = safe_work(os.environ["ORACLE_WORK"])
for d in ("maps", "pgs", "crush", "crushout", "names", "inc", "dumps", "off"):
    os.makedirs(os.path.join(WORK, d), exist_ok=True)
LOG = open(os.path.join(WORK, "run.log"), "a")


def log(s):
    LOG.write(s + "\n")
    LOG.flush()
    print(s, flush=True)


# ---- running things -------------------------------------------------------------------------------------------------

def sh(cmd, check=True, timeout=1800, inp=None):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, input=inp)
    out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError("%s -> rc %d: %s %s" % (" ".join(cmd)[:200], p.returncode, out.strip()[:300], err.strip()[:300]))
    return p.returncode, out, err


def cc(*a, check=True, quiet=False):
    t0 = time.time()
    rc, out, err = sh(["sudo", "ceph"] + [str(x) for x in a], check=False)
    msg = (err.strip() or out.strip())[:140].replace("\n", " | ")
    if not quiet:
        log("[%5.1fs] rc=%d ceph %s%s" % (time.time() - t0, rc, " ".join(str(x) for x in a), ("   => " + msg) if msg else ""))
    if check and rc != 0:
        raise RuntimeError("ceph %s -> rc %d: %s" % (" ".join(str(x) for x in a), rc, msg))
    return rc, out, err


def cj(*a):
    return json.loads(cc(*a, "-f", "json", quiet=True)[1])


def cur_epoch():
    return cj("osd", "stat")["epoch"]


def dump(epoch=None):
    return cj("osd", "dump", *([epoch] if epoch else []))


def pool_by_name(d, name):
    for p in d["pools"]:
        if p["pool_name"] == name:
            return p
    return None


def settled(timeout=180, stable=5):
    """no PG creating / peering / unknown and the map epoch unchanged for `stable` seconds"""
    if QUICK:
        stable = 3
    t0, last, since, states = time.time(), None, None, []
    while time.time() - t0 < timeout:
        st = cj("status")
        states = [s["state_name"] for s in st["pgmap"].get("pgs_by_state", [])]
        busy = [s for s in states if any(w in s for w in ("creating", "peering", "unknown", "activating", "backfill_wait", "backfilling", "remapped+peering", "stale"))]
        e = st["osdmap"]["epoch"] if "epoch" in st["osdmap"] else cur_epoch()
        if busy or e != last:
            last, since = e, time.time()
        elif time.time() - since >= stable:
            return e
        time.sleep(1)
    log("warning: the cluster did not settle within %ds (states %r)" % (timeout, states))
    return cur_epoch()


# ---- baseline and restore ---------------------------------------------------------------------------------------------

BASE_FILE = os.path.join(WORK, "baseline.json")


def table_rows(d, key):
    out = []
    for r in d.get(key, []):
        if isinstance(r, dict):
            out.append(json.dumps(r, sort_keys=True))
    if key == "primary_temp":
        pt = d.get(key, [])
        out = [json.dumps([pt[i], pt[i + 1]]) for i in range(0, len(pt), 2)] if pt and not isinstance(pt[0], dict) else out
    return sorted(out)


def snapshot():
    d = dump()
    base_ids = [p["pool"] for p in d["pools"] if not p["pool_name"].startswith(PFX)]
    snap = {
        "epoch": d["epoch"],
        "pools": sorted((p["pool"], p["pool_name"], p["pg_num"], p["pg_placement_num"], p["size"], p["min_size"], p["crush_rule"], p["flags"]) for p in d["pools"] if p["pool"] in base_ids),
        "osds": [(o["osd"], o["up"], o["in"], o["weight"], o["primary_affinity"]) for o in d["osds"]],
        "flags": d["flags"], "require_min_compat_client": d["require_min_compat_client"], "crush_version": d["crush_version"],
        "tables": {k: [r for r in table_rows(d, k) if int(json.loads(r)["pgid"].split(".")[0] if r.startswith("{") else json.loads(r)[0].split(".")[0]) in base_ids]
                   for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "primary_temp")},
        "mon_allow_pool_delete": cc("config", "get", "mon", "mon_allow_pool_delete", quiet=True)[1].strip(),
        "mon_allow_pool_delete_in_db": any(c.get("name") == "mon_allow_pool_delete" for c in cj("config", "dump")),
        "rules": sorted(r["rule_name"] for r in cj("osd", "crush", "rule", "dump")),
        "profiles": sorted(json.loads(cc("osd", "erasure-code-profile", "ls", "-f", "json", quiet=True)[1] or "[]")),
        "weight_sets": json.loads(cc("osd", "crush", "weight-set", "ls", "-f", "json", quiet=True)[1] or "[]"),
    }
    return snap


def own_pools(d=None):
    d = d or dump()
    return [p["pool_name"] for p in d["pools"] if p["pool_name"].startswith(PFX)]


def cleanup(base):
    """put the cluster back: overrides, own pools (removal needs mon_allow_pool_delete), rule, profile, weight sets, OSD settings"""
    log("clean-up")
    d = dump()
    ids = {p["pool"]: p["pool_name"] for p in d["pools"] if p["pool_name"].startswith(PFX)}
    for pid in ids:
        for pg in [r["pgid"] for k in ("pg_upmap_items", "pg_upmap") for r in d.get(k, []) if isinstance(r, dict) and int(r["pgid"].split(".")[0]) == pid]:
            cc("osd", "rm-pg-upmap-items", pg, check=False)
            cc("osd", "rm-pg-upmap", pg, check=False)
        for r in d.get("pg_upmap_primaries", []):
            if int(r["pgid"].split(".")[0]) == pid:
                cc("osd", "rm-pg-upmap-primary", r["pgid"], check=False)
    pt = d.get("primary_temp", [])
    pairs = [(pt[i], pt[i + 1]) for i in range(0, len(pt), 2)] if pt and not isinstance(pt[0], dict) else [(r["pgid"], r.get("osd")) for r in pt]
    for pg, _ in pairs:
        if int(pg.split(".")[0]) in ids:
            cc("osd", "rm-primary-temp", pg, check=False)
    cc("osd", "unset", "noup", check=False)
    now = {o["osd"]: o for o in d["osds"]}
    for o, up, inn, w, aff in base["osds"]:      # only what differs from the baseline is touched
        if o in now and abs(now[o]["weight"] - w) > 1e-9:
            cc("osd", "reweight", o, w, check=False)
        if o in now and abs(now[o]["primary_affinity"] - aff) > 1e-9:
            cc("osd", "primary-affinity", o, aff, check=False)
        if inn and o in now and not now[o]["in"]:
            cc("osd", "in", o, check=False)
    # tiers before pools
    for p in d["pools"]:
        if p["pool_name"].startswith(PFX) and p.get("tier_of", -1) >= 0:
            base_name = next((q["pool_name"] for q in d["pools"] if q["pool"] == p["tier_of"]), None)
            if base_name:
                cc("osd", "tier", "remove-overlay", base_name, check=False)
                cc("osd", "tier", "remove", base_name, p["pool_name"], check=False)
    for ws in json.loads(cc("osd", "crush", "weight-set", "ls", "-f", "json", quiet=True)[1] or "[]"):
        if ws.startswith(PFX):
            cc("osd", "crush", "weight-set", "rm", ws, check=False)
    if not base["weight_sets"] or "(compat)" not in base["weight_sets"]:
        cc("osd", "crush", "weight-set", "rm-compat", check=False)
    cc("config", "set", "mon", "mon_allow_pool_delete", "true", check=False)
    for name in ids.values():
        assert name.startswith(PFX)
        cc("osd", "pool", "rm", name, name, "--yes-i-really-really-mean-it", check=False)
    if base["mon_allow_pool_delete_in_db"]:
        cc("config", "set", "mon", "mon_allow_pool_delete", base["mon_allow_pool_delete"], check=False)
    else:
        cc("config", "rm", "mon", "mon_allow_pool_delete", check=False)
    for r in cj("osd", "crush", "rule", "dump"):
        if r["rule_name"].startswith(PFX):
            cc("osd", "crush", "rule", "rm", r["rule_name"], check=False)
    for pr in json.loads(cc("osd", "erasure-code-profile", "ls", "-f", "json", quiet=True)[1] or "[]"):
        if pr.startswith(PFX):
            cc("osd", "erasure-code-profile", "rm", pr, check=False)
    if dump()["require_min_compat_client"] != base["require_min_compat_client"]:
        cc("osd", "set-require-min-compat-client", base["require_min_compat_client"], "--yes-i-really-mean-it", check=False)
    settled(120)


def verify_restore(base):
    now = snapshot()
    problems = []
    for k in ("pools", "osds", "flags", "require_min_compat_client", "tables", "mon_allow_pool_delete", "mon_allow_pool_delete_in_db", "rules", "profiles", "weight_sets"):
        a, b = now[k], base[k]
        if json.loads(json.dumps(a)) != json.loads(json.dumps(b)):
            problems.append("%s: now %s, was %s" % (k, json.dumps(a)[:160], json.dumps(b)[:160]))
    if own_pools():
        problems.append("own pools left: %s" % own_pools())
    return problems


if CMD == "cleanup":
    if not os.path.exists(BASE_FILE):
        raise SystemExit("no baseline at %s: nothing to restore to (is --work the directory of the run?)" % BASE_FILE)
    base = json.load(open(BASE_FILE))
    cleanup(base)
    probs = verify_restore(base)
    log("restore check: %s" % ("OK" if not probs else probs))
    sys.exit(0 if not probs else 1)


# ---- saving maps ----------------------------------------------------------------------------------------------------------

STATES = []     # (label, epoch, description, reached)


def save_map(label, epoch=None, desc="", reached=True):
    """settle, then save the map of the current epoch (ceph osd getmap) and its ceph osd dump; both are the ground truth of this state"""
    e = epoch or settled()
    p = os.path.join(WORK, "maps", "%s.bin" % label)
    sh(["sudo", "ceph", "osd", "getmap", str(e), "-o", p])
    sh(["sudo", "chown", ME, p])
    json.dump(dump(e), open(os.path.join(WORK, "dumps", "%s.json" % label), "w"))
    STATES.append({"label": label, "epoch": e, "desc": desc, "reached": reached})
    log("state %s: epoch %d%s  %s" % (label, e, "" if reached else "  [PREDICATE NOT MET]", desc))
    return e


def want(label):
    return not ONLY or any(label.startswith(o) or o.startswith(label[:3]) for o in ONLY)


def pg_up(pg):
    return cj("pg", "map", pg)["up"]


def third_osd(up):
    return next(o for o in (0, 1, 2) if o not in up)


# ---- pools ------------------------------------------------------------------------------------------------------------------

POOLS = [  # name, pg_num, pgp_num, size
    (PFX + "a", 16, 16, 3), (PFX + "b", 12, 12, 2), (PFX + "c", 7, 4, 2), (PFX + "d", 12, 8, 3), (PFX + "e", 8, 8, 2), (PFX + "f", 8, 8, 4),
]


def mkpool(name, pg, pgp, size, *extra):
    assert name.startswith(PFX)
    cc("osd", "pool", "create", name, pg, pgp, *extra)
    cc("osd", "pool", "set", name, "pg_autoscale_mode", "off", check=False)
    if size and not extra:
        cc("osd", "pool", "set", name, "size", size)
        cc("osd", "pool", "set", name, "min_size", 1, check=False)


def wait_geometry(name, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        p = pool_by_name(dump(), name)
        if p and p["pg_num"] == p["pg_num_target"] and p["pg_placement_num"] == p["pg_placement_num_target"] and p["pg_num_pending"] == p["pg_num"]:
            return p
        time.sleep(2)
    log("warning: %s did not reach its target geometry" % name)
    return pool_by_name(dump(), name)


# ---- the name oracle ----------------------------------------------------------------------------------------------------------

def monbytes(s):
    """the bytes the monitor hashes for a JSON string: UTF-8, but a code point above U+FFFF arrives as two 3-byte surrogate halves"""
    out = b""
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            out += chr(0xD800 + (cp >> 10)).encode("utf-8", "surrogatepass") + chr(0xDC00 + (cp & 0x3FF)).encode("utf-8", "surrogatepass")
        else:
            out += ch.encode("utf-8")
    return out


def make_names(n, seed):
    """distinct names: every length 0..25 and 255, rbd-style names, non-ASCII (2, 3 and 4 byte characters), odd ASCII, random fill"""
    rnd = random.Random(seed)
    al = string.ascii_letters + string.digits + "._-"
    names = ["".join(rnd.choice(al) for _ in range(L)) for L in list(range(0, 26)) + [31, 32, 33, 47, 48, 49, 63, 64, 65, 100, 127, 128, 129, 254, 255]]
    names += ["rbd_directory", "rbd_info", "rbd_header.37841afbd1d7", "rbd_id.img-v1"] + ["rbd_data.37841afbd1d7.%016x" % i for i in range(30)]
    names += ["\u00e9", "ma\u00f1ana", "\u00dcn\u00efc\u00f6d\u00e9", "\u65e5\u672c\u8a9e", "\ud55c\uad6d\uc5b4", "\U0001F600", "a\U0001F600b", "\U0001D4B3\U0001D4B4", "\u00e9" * 127, "\u20ac" * 85,
              "\uffff", "\ud7ff", "\ue000", "\u0080", "\u07ff", "\u0800", "\U0010FFFF", "\U00010000", "caf\u00e9-\u2603-\U0001F680"]
    names += ["/", "//a", "a/b/c", " ", "  lead", "trail  ", "\t", "a\nb", "\x01\x02\x03", "\x7f", ".", "..", "_", "%", "\"", "\\", "a\"b'c", "{}", "z" * 1000]
    alpha = list(al) + [chr(c) for c in (0xe0, 0xe9, 0xf1, 0x3b1, 0x416, 0x4e2d, 0xac00, 0x20ac, 0x1F600, 0x1F680)]
    seen, out = set(), []
    for x in names:
        if x not in seen:
            seen.add(x)
            out.append(x)
    while len(out) < n:
        x = "".join(rnd.choice(alpha) for _ in range(rnd.randint(1, 40)))
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


ORACLE_PY = r'''
import json, sys, rados
items = json.load(open(sys.argv[1])); out = open(sys.argv[2], "w")
c = rados.Rados(conffile="/etc/ceph/ceph.conf"); c.connect()
for it in items:
    cmd = {"prefix": "osd map", "pool": it["pool"], "object": it["obj"], "format": "json"}
    if it["ns"]: cmd["nspace"] = it["ns"]
    rc, outb, outs = c.mon_command(json.dumps(cmd), b"")
    rec = {"pool": it["pool"], "obj_hex": it["obj_hex"], "ns_hex": it["ns_hex"], "rc": rc}
    if rc == 0: rec["reply"] = json.loads(outb)
    else: rec["err"] = outs
    out.write(json.dumps(rec, sort_keys=True) + "\n")
out.close(); c.shutdown()
'''


def run_in_cephadm(script_name, script_text, token="", timeout=3600):
    """run a script inside the cephadm container with the work directory mounted at /work; the script must print `token` last"""
    open(os.path.join(WORK, script_name), "w").write(script_text)
    r = sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % WORK, "--", "bash", "/work/" + script_name], timeout=timeout, check=False)
    sh(["sudo", "chown", "-R", ME, WORK])
    if r[0] != 0 or (token and token not in r[1]):
        raise RuntimeError("%s in the cephadm container failed (rc %d): %s %s" % (script_name, r[0], r[1][-400:], r[2][-400:]))
    for ln in r[1].splitlines():
        if re.match(r"^(osdmaptool|crushtool) failed|^build failed|^no inc ", ln):
            log("  container: " + ln)
    return r


def name_oracle(label, pools, count, results):
    """`ceph osd map -f json` for count names per pool (once per pool geometry), against the core's answers on the map of that epoch"""
    master = make_names(count, 20261117 + len(pools))
    nslist = ["ns1", "a-longer-namespace", "\u00fcn\u00ef", "\u540d\u524d", "x" * 40, "\U0001F600ns"]
    items = []
    for pi, pool in enumerate(pools):
        rnd = random.Random(pi)
        sel = master[:]
        rnd.shuffle(sel)
        for i, n in enumerate(sel):
            ns = nslist[(i + pi * 5) % len(nslist)] if (i * 7 + pi) % 6 == 0 else None
            items.append({"pool": pool, "obj": n, "ns": ns, "obj_hex": monbytes(n).hex(), "ns_hex": monbytes(ns).hex() if ns else ""})
    nin, nout = os.path.join(WORK, "names", label + ".in.json"), os.path.join(WORK, "names", label + ".out.jsonl")
    json.dump(items, open(nin, "w"))
    open(os.path.join(WORK, "names_oracle.py"), "w").write(ORACLE_PY)
    eps = {}
    for attempt in range(3):
        settled()
        if os.path.exists(nout):
            os.remove(nout)
        run_in_cephadm("names_run.sh", "python3 /work/names_oracle.py /work/names/%s.in.json /work/names/%s.out.jsonl && echo NAMES-DONE\n" % (label, label), "NAMES-DONE")
        eps = collections.Counter()
        for ln in open(nout):
            r = json.loads(ln)
            if r["rc"] == 0:
                eps[r["reply"]["epoch"]] += 1
        log("name oracle %s: answers per epoch %s" % (label, dict(eps)))
        if len(eps) == 1:
            break
    if len(eps) != 1:
        results.append(D.Result("names %s" % label))
        results[-1].bad("the cluster changed epoch during every attempt: %s" % dict(eps))
        return
    e = next(iter(eps))
    mp = os.path.join(WORK, "maps", "names-%s.bin" % label)
    sh(["sudo", "ceph", "osd", "getmap", str(e), "-o", mp])
    sh(["sudo", "chown", ME, mp])
    names = D.names_from_jsonl(nout)
    nf = os.path.join(WORK, "names", label + ".txt")
    open(nf, "w").write(D.names_batch(names, {}))
    out = TOOL.run(["--map", mp, "--names", nf] + [a for p in pools for a in ("--pool", p)])
    res = D.compare_names("names %s at epoch %d (%d pools)" % (label, e, len(pools)), names, out)
    results.append(res)
    log(res.line())


# ---- main ---------------------------------------------------------------------------------------------------------------------

def compare_states(results):
    """osdmaptool for every PG of every pool of every saved map (one cephadm shell for all), against the tool"""
    lines = ["set -u", "cd /work"]
    for s in STATES:
        lines.append("osdmaptool maps/%s.bin --test-map-pgs-dump-all > pgs/%s.txt 2> pgs/%s.err || echo 'osdmaptool failed %s'" % ((s["label"],) * 4))
    run_in_cephadm("pgs_run.sh", "\n".join(lines) + "\necho PGS-DONE\n", "PGS-DONE")
    res_pg = D.Result("pg tables of %d states against osdmaptool" % len(STATES))
    res_st = D.Result("compact state against ceph osd dump")
    for s in STATES:
        label = s["label"]
        mp = os.path.join(WORK, "maps", label + ".bin")
        txt = open(os.path.join(WORK, "pgs", label + ".txt")).read()
        d = json.load(open(os.path.join(WORK, "dumps", label + ".json")))
        for p in d["pools"]:
            truth = D.truth_from_text(txt, p["pool"])
            out = TOOL.run(["--map", mp, "--pool", p["pool_name"], "--dump-pgs"], expect=(0, 3))
            res_pg.merge(D.compare_pgs("%s pool %d (%s)" % (label, p["pool"], p["pool_name"]), truth, out, pools={p["pool"]}))
        names8 = [p["pool_name"] for p in d["pools"]][:8]
        out = TOOL.run(["--map", mp, "--dump-state"] + [a for n in names8 for a in ("--pool", n)])
        blk = D.state_blocks(out).get(d["epoch"])
        if blk is None:
            res_st.bad("%s: no state block for epoch %d" % (label, d["epoch"]))
        else:
            res_st.merge(D.compare_state_json(label, blk, d))
    for r in (res_pg, res_st):
        results.append(r)
        r.report()


def compare_crush(results):
    """crushtool --test --show-mappings on the lab's own crush maps (saved after each crush change) and on offline --build maps"""
    maps = sorted(f for f in os.listdir(os.path.join(WORK, "crush")) if f.endswith(".bin"))
    runs = []   # (map path, out name, rule, num_rep, weights)
    wsets = ([], [("0", "0")], [("1", "0.5"), ("2", "0.25")])
    for f in maps:
        rules = [r["rule_id"] for r in json.load(open(os.path.join(WORK, "crush", f[:-4] + ".rules.json")))]
        for rule in rules:
            for rep in (2, 3):
                for wi, w in enumerate(wsets):
                    runs.append((os.path.join(WORK, "crush", f), "%s.r%d.n%d.w%d" % (f[:-4], rule, rep, wi), rule, rep, w))
    lines = ["set -u", "cd /work"]
    builds = [("cm1", "host straw 4 rack list 3 root uniform 0"), ("cm2", "host tree 4 rack tree 3 root straw2 0"), ("cm3", "host list 4 rack straw 3 root tree 0"),
              ("cm4", "host uniform 4 rack straw2 3 root list 0"), ("cm5", "host straw2 4 rack straw2 3 root straw2 0")]
    for nm, lay in builds:
        lines.append("crushtool --build --num_osds 24 %s -o off/%s.bin >/dev/null 2>&1 || echo 'build failed %s'" % (lay, nm, nm))
        for wi, w in enumerate(([], [("3", "0"), ("7", "0.5"), ("20", "0")])):
            runs.append((os.path.join(WORK, "off", nm + ".bin"), "off.%s.r0.n3.w%d" % (nm, wi), 0, 3, w))
    for path, name, rule, rep, w in runs:
        rel = os.path.relpath(path, WORK)
        wa = " ".join("--weight %s %s" % x for x in w)
        lines.append("crushtool -i %s --test --show-mappings --rule %d --num-rep %d --min-x 0 --max-x %d %s > crushout/%s.txt 2> crushout/%s.err || echo 'crushtool failed %s'" %
                     (rel, rule, rep, 399 if QUICK else 1999, wa, name, name, name))
    run_in_cephadm("crush_run.sh", "\n".join(lines) + "\necho CRUSH-DONE\n", "CRUSH-DONE")
    res = D.Result("crushtool --test --show-mappings (%d runs)" % len(runs))
    for path, name, rule, rep, w in runs:
        args = ["--crush", path, "--rule", rule, "--num-rep", rep, "--min-x", 0, "--max-x", 399 if QUICK else 1999]
        for dev, wt in w:
            args += ["--weight", dev, wt]
        tp = os.path.join(WORK, "crushout", name + ".txt")
        if not os.path.exists(tp):
            res.bad("%s: crushtool produced no output" % name)
            continue
        res.merge(D.compare_crush(name, open(tp).read(), TOOL.run(args)))
    results.append(res)
    res.report()


def save_crush(label):
    p = os.path.join(WORK, "crush", label + ".bin")
    sh(["sudo", "ceph", "osd", "getcrushmap", "-o", p])
    sh(["sudo", "chown", ME, p])
    json.dump(cj("osd", "crush", "rule", "dump"), open(os.path.join(WORK, "crush", label + ".rules.json"), "w"))


def chain_step(base_label, base_epoch, results):
    """incrementals from a read-only copy of the monitor store, applied by the tool to the saved base map, against the full map of every saved state"""
    last = max(s["epoch"] for s in STATES)
    store = os.path.join(WORK, "store")
    sh(["sudo", "rm", "-rf", store], check=False)
    os.makedirs(store, mode=0o700)   # the copy holds the monitor's auth database: nobody else on the machine may walk into it
    try:
        sh(["sudo", "bash", "-c", "cp -a /var/lib/ceph/*/mon.*/store.db %s/" % store])
        script = "set -u\ncd /work\nfor e in $(seq %d %d); do ceph-kvstore-tool rocksdb /work/store/store.db get osdmap $e out inc/$e.bin >/dev/null 2>&1 || echo \"no inc $e\"; done\necho INC-DONE\n" % (base_epoch + 1, last)
        run_in_cephadm("inc_run.sh", script, "INC-DONE")
    finally:
        sh(["sudo", "rm", "-rf", store], check=False)   # it holds the monitor's own auth database
    lst = []
    for e in range(base_epoch + 1, last + 1):
        p = os.path.join(WORK, "inc", "%d.bin" % e)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            lst.append("%d %s\n" % (e, open(p, "rb").read().hex()))
    res = D.Result("incremental chain from epoch %d to %d (%d of %d incrementals found)" % (base_epoch, last, len(lst), last - base_epoch))
    if len(lst) != last - base_epoch:
        res.bad("the monitor store holds %d of the %d incrementals" % (len(lst), last - base_epoch))
        results.append(res)
        return
    incf = os.path.join(WORK, "inc", "chain.hex")
    open(incf, "w").write("".join(lst))
    d0 = json.load(open(os.path.join(WORK, "dumps", base_label + ".json")))
    tracked = [n for n in (["winrbd"] + [p[0] for p in POOLS[:5]] + [PFX + "n", PFX + "ren"])][:8]
    pool_args = [a for n in tracked for a in ("--pool", n)]
    base_map = os.path.join(WORK, "maps", base_label + ".bin")
    chain = TOOL.run(["--map", base_map, "--apply-inc", incf, "--dump-state"] + pool_args)
    for s in STATES:
        if s["epoch"] < base_epoch:
            continue
        full = TOOL.run(["--map", os.path.join(WORK, "maps", s["label"] + ".bin"), "--dump-state"] + pool_args)
        res.merge(D.compare_state("chain vs full map %s" % s["label"], chain, full))
    results.append(res)
    res.report()


def pid(name):
    return pool_by_name(dump(), name)["pool"]


def rows(d, key):
    """the rows of an override table of a ceph osd dump as (pgid, value) pairs: dict rows or the flat primary_temp list"""
    out = []
    for r in d.get(key, []):
        if isinstance(r, dict):
            out.append((r["pgid"], r))
    pt = d.get(key, [])
    if key == "primary_temp" and pt and not isinstance(pt[0], dict):
        out = [(pt[i], pt[i + 1]) for i in range(0, len(pt), 2)]
    return out


def has_pg(key, *pgs):
    """predicate: the table `key` holds an entry for every pgid in pgs"""
    return lambda d: all(any(g == pg for g, _ in rows(d, key)) for pg in pgs)


def step(label, desc, need, *cmds, wait=1.5):
    """run the commands, then save the FIRST epoch after them that satisfies `need` (the monitor cleans some entries in a later epoch, so
    the epoch the state exists in can be a short one); without a match the current epoch is saved and the state is marked not reached"""
    e0 = cur_epoch()
    for c in cmds:
        cc(*c, check=False)
    time.sleep(wait)
    if need is None:
        return save_map(label, desc=desc)
    last = cur_epoch()
    for e in range(e0 + 1, last + 1):
        if need(dump(e)):
            return save_map(label, e, desc)
    return save_map(label, last, desc, reached=False)


def run_states(results):
    # ---- S1 / S10: pool geometries, a legacy pool ----
    for name, pg, pgp, size in POOLS:
        mkpool(name, pg, pgp, size)
    cc("osd", "pool", "set", PFX + "e", "hashpspool", "false", "--yes-i-really-mean-it", check=False)
    for name, pg, pgp, size in POOLS:
        wait_geometry(name)
    settled()
    d = dump()
    ok = all((pool_by_name(d, n) or {}).get("pg_num") == pg and (pool_by_name(d, n) or {}).get("pg_placement_num") == pgp for n, pg, pgp, _ in POOLS)
    legacy = not ((pool_by_name(d, PFX + "e") or {}).get("flags", 1) & 1)
    save_map("s01-pools", desc="S1/S10: pg_num 16, 12 (not a power of two), 7 with pgp_num 4, 12 with pgp_num 8, a legacy pool (no HASHPSPOOL), size 4 on three OSDs",
             reached=ok and legacy)
    save_crush("c0")
    if want("s01"):
        name_oracle("geom1", [p[0] for p in POOLS] + ["winrbd", ".mgr"], NAMES_PER_POOL, results)     # the name oracle, once per pool geometry
    A, B = POOLS[0][0], POOLS[1][0]
    pa, pb = pid(A), pid(B)

    # ---- S2 / S15: a split, then a merge, in progress; every epoch of it ----
    if want("s02") and not QUICK:
        cc("osd", "pool", "set", B, "pg_num", 14)
        seen, t0 = set(), time.time()
        while time.time() - t0 < 120:
            e = cur_epoch()
            if e not in seen:
                seen.add(e)
                p = pool_by_name(dump(e), B)
                save_map("s02-split-e%d" % e, e, "S2: %s pg_num 12 -> 14 (now pg_num %d, pgp_num %d)" % (B, p["pg_num"], p["pg_placement_num"]),
                         reached=p["pg_num_target"] == 14)
                if p["pg_num"] == 14 and p["pg_placement_num"] == 14:
                    break
            time.sleep(1.2)
        settled()
        name_oracle("geom2", [B, "winrbd"], max(60, NAMES_PER_POOL // 4), results)     # a new geometry: pg_num 14
    if want("s15") and not QUICK:
        cc("osd", "pool", "set", B, "pg_num", 9)
        seen, t0 = set(), time.time()
        while time.time() - t0 < 120:
            e = cur_epoch()
            if e not in seen:
                seen.add(e)
                p = pool_by_name(dump(e), B)
                save_map("s15-merge-e%d" % e, e, "S15: %s pg_num lowered to 9 (now pg_num %d, pgp_num %d, pending %d)" % (B, p["pg_num"], p["pg_placement_num"], p["pg_num_pending"]),
                         reached=p["pg_num_target"] == 9)
                if p["pg_num"] == 9 and p["pg_placement_num"] == 9:
                    break
            time.sleep(1.2)
        settled()
        name_oracle("geom3", [B, "winrbd"], max(60, NAMES_PER_POOL // 4), results)     # pg_num 9

    # ---- S3 pg_upmap_items ----
    if want("s03"):
        up = pg_up("%d.0" % pb)
        step("s03a", "S3: one pg_upmap_items pair on %d.0" % pb, has_pg("pg_upmap_items", "%d.0" % pb),
             ("osd", "pg-upmap-items", "%d.0" % pb, up[-1], third_osd(up)))
        up2 = pg_up("%d.2" % pb)
        step("s03b", "S3: two pairs on %d.2" % pb, has_pg("pg_upmap_items", "%d.2" % pb),
             ("osd", "pg-upmap-items", "%d.2" % pb, up2[0], third_osd(up2), up2[1], up2[0]))
        upa, upb3 = pg_up("%d.1" % pa), pg_up("%d.3" % pb)
        step("s03c", "S3: a pair whose `to` is already in the set, a pair whose `from` is not", has_pg("pg_upmap_items", "%d.1" % pa),
             ("osd", "pg-upmap-items", "%d.1" % pa, upa[0], upa[1]),
             ("osd", "pg-upmap-items", "%d.3" % pb, third_osd(upb3), upb3[0]))
        step("s03z", "S3: removed again", lambda d: not rows(d, "pg_upmap_items"),
             *[("osd", "rm-pg-upmap-items", pg) for pg in ("%d.0" % pb, "%d.2" % pb, "%d.1" % pa, "%d.3" % pb)])

    # ---- S4 pg_upmap ----
    if want("s04"):
        up = pg_up("%d.3" % pa)
        step("s04a", "S4: pg_upmap reorders %d.3" % pa, has_pg("pg_upmap", "%d.3" % pa), ("osd", "pg-upmap", "%d.3" % pa, up[1], up[0], up[2]))
        upb = pg_up("%d.4" % pb)
        step("s04b", "S4: pg_upmap replaces a member of %d.4" % pb, has_pg("pg_upmap", "%d.4" % pb), ("osd", "pg-upmap", "%d.4" % pb, third_osd(upb), upb[0]))
        cc("osd", "reweight", 1, 0)
        step("s04c", "S4: a pg_upmap naming osd.1 whose weight is 0", has_pg("pg_upmap", "%d.5" % pb), ("osd", "pg-upmap", "%d.5" % pb, 1, 0))
        cc("osd", "reweight", 1, 1)
        step("s04z", "S4: removed, weight restored", lambda d: not rows(d, "pg_upmap"),
             *[("osd", "rm-pg-upmap", pg) for pg in ("%d.3" % pa, "%d.4" % pb, "%d.5" % pb)])

    # ---- S5 pg_upmap_primary ----
    if want("s05"):
        cc("osd", "set-require-min-compat-client", "reef", "--yes-i-really-mean-it")
        up = pg_up("%d.2" % pa)
        step("s05b", "S5: pg_upmap_primary on %d.2" % pa, has_pg("pg_upmap_primaries", "%d.2" % pa), ("osd", "pg-upmap-primary", "%d.2" % pa, up[-1]))
        up5 = pg_up("%d.5" % pa)
        step("s05c", "S5: two pg_upmap_primary entries", has_pg("pg_upmap_primaries", "%d.2" % pa, "%d.5" % pa), ("osd", "pg-upmap-primary", "%d.5" % pa, up5[1]))
        step("s05z", "S5: removed", lambda d: not rows(d, "pg_upmap_primaries"),
             ("osd", "rm-pg-upmap-primary", "%d.2" % pa), ("osd", "rm-pg-upmap-primary", "%d.5" % pa))
        cc("osd", "set-require-min-compat-client", base_snapshot["require_min_compat_client"], "--yes-i-really-mean-it", check=False)

    # ---- S6 pg_temp / primary_temp (primary_temp only names a member of the acting set: any other OSD crashes that OSD) ----
    if want("s06"):
        up = pg_up("%d.4" % pa)
        step("s06a", "S6: pg_temp alone on %d.4" % pa, has_pg("pg_temp", "%d.4" % pa), ("osd", "pg-temp", "%d.4" % pa, up[1], up[0], up[2]), wait=0.5)
        upb = pg_up("%d.6" % pb)
        step("s06b", "S6: primary_temp alone on %d.6" % pb, has_pg("primary_temp", "%d.6" % pb), ("osd", "primary-temp", "%d.6" % pb, upb[1]), wait=0.5)
        step("s06c", "S6: pg_temp and primary_temp on one PG", lambda d: has_pg("primary_temp", "%d.4" % pa)(d), ("osd", "pg-temp", "%d.4" % pa, up[1], up[0], up[2]),
             ("osd", "primary-temp", "%d.4" % pa, up[1]), wait=0.5)
        step("s06z", "S6: temps cleared", lambda d: not rows(d, "primary_temp"),
             ("osd", "rm-primary-temp", "%d.4" % pa), ("osd", "rm-primary-temp", "%d.6" % pb), ("osd", "pg-temp", "%d.4" % pa))

    # ---- S7 primary affinity ----
    if want("s07"):
        def aff(*want_):
            return lambda d: [o["primary_affinity"] for o in d["osds"]] == list(want_)
        step("s07a", "S7: osd.0 affinity 0", aff(0, 1, 1), ("osd", "primary-affinity", 0, 0))
        step("s07b", "S7: osd.1 affinity 0.25", aff(0, 0.25, 1), ("osd", "primary-affinity", 1, 0.25))
        step("s07c", "S7: osd.2 affinity 0.5", aff(0, 0.25, 0.5), ("osd", "primary-affinity", 2, 0.5))
        step("s07z", "S7: affinity restored", aff(1, 1, 1), *[("osd", "primary-affinity", o, 1) for o in (0, 1, 2)])

    # ---- S8 reweight, out, in ----
    if want("s08"):
        for w, lab in ((0.5, "a"), (0.1, "b"), (0, "c")):
            step("s08" + lab, "S8: osd.2 reweight %s" % w, lambda d, w=w: abs([o for o in d["osds"] if o["osd"] == 2][0]["weight"] - w) < 1e-3, ("osd", "reweight", 2, w))
        step("s08d", "S8: reweight restored", lambda d: [o for o in d["osds"] if o["osd"] == 2][0]["weight"] == 1, ("osd", "reweight", 2, 1))
        step("s08e", "S8: osd.2 out", lambda d: [o for o in d["osds"] if o["osd"] == 2][0]["in"] == 0, ("osd", "out", 2))
        step("s08f", "S8: osd.2 in", lambda d: [o for o in d["osds"] if o["osd"] == 2][0]["in"] == 1, ("osd", "in", 2))

    # ---- S9 down but not out ----
    if want("s09"):
        cc("osd", "set", "noup")
        step("s09a", "S9: noup set, osd.2 marked down and kept down", lambda d: [o for o in d["osds"] if o["osd"] == 2][0]["up"] == 0, ("osd", "down", 2), wait=3)
        cc("osd", "unset", "noup")
        t0 = time.time()
        while time.time() - t0 < 90 and not [o for o in dump()["osds"] if o["osd"] == 2 and o["up"]]:
            time.sleep(2)
        save_map("s09b", desc="S9: osd.2 up again", reached=bool([o for o in dump()["osds"] if o["osd"] == 2 and o["up"]]))

    # ---- S11 pool created, renamed, deleted ----
    if want("s11"):
        N, R = PFX + "n", PFX + "ren"
        mkpool(N, 16, 16, 2)
        save_map("s11b", desc="S11: pool %s created" % N, reached=pool_by_name(dump(), N) is not None)
        step("s11d", "S11: renamed to %s" % R, lambda d: pool_by_name(d, R) is not None, ("osd", "pool", "rename", N, R))
        cc("config", "set", "mon", "mon_allow_pool_delete", "true")
        step("s11e", "S11: pool deleted", lambda d: pool_by_name(d, R) is None, ("osd", "pool", "rm", R, R, "--yes-i-really-really-mean-it"))

    # ---- S12 erasure pool, cache tier: refused by the core with a clear status (an ERROR line, counted as skipped) ----
    if want("s12"):
        cc("osd", "erasure-code-profile", "set", PFX + "prof", "k=2", "m=1", "crush-failure-domain=osd", "--force", check=False)
        step("s12b", "S12: an erasure pool", lambda d: (pool_by_name(d, PFX + "ec") or {}).get("type") == 3, ("osd", "pool", "create", PFX + "ec", 8, 8, "erasure", PFX + "prof"))
        cc("osd", "pool", "set", PFX + "ec", "pg_autoscale_mode", "off", check=False)
        mkpool(PFX + "base", 8, 8, 2)
        mkpool(PFX + "cache", 8, 8, 2)
        step("s12e", "S12: a cache tier with an overlay", lambda d: (pool_by_name(d, PFX + "cache") or {}).get("tier_of", -1) >= 0,
             ("osd", "tier", "add", PFX + "base", PFX + "cache"), ("osd", "tier", "cache-mode", PFX + "cache", "writeback", "--yes-i-really-mean-it"),
             ("osd", "tier", "set-overlay", PFX + "base", PFX + "cache"))
        step("s12z", "S12: tier removed", lambda d: (pool_by_name(d, PFX + "cache") or {}).get("tier_of", 0) < 0,
             ("osd", "tier", "remove-overlay", PFX + "base"), ("osd", "tier", "remove", PFX + "base", PFX + "cache"))

    # ---- S13 / S14 choose_args and crush changes ----
    if want("s13") or want("s14") or want("crush"):
        v0 = dump()["crush_version"]
        step("s13a", "S13: a positional weight set for %s (choose_args key = pool id)" % A, lambda d: d["crush_version"] > v0, ("osd", "crush", "weight-set", "create", A, "positional"))
        for o, w in ((0, ("0.002", "0.01", "0.05")), (1, ("0.05", "0.01", "0.002")), (2, ("0.02", "0.02", "0.02"))):     # one value per position (pool size 3)
            cc("osd", "crush", "weight-set", "reweight", A, "osd.%d" % o, *w)
        step("s13b", "S13: positional weights changed", lambda d: d["crush_version"] > v0 + 1, wait=1.5)
        save_crush("c1")
        v1 = dump()["crush_version"]
        step("s13c", "S13: a compat weight set (key -1)", lambda d: d["crush_version"] > v1, ("osd", "crush", "weight-set", "create-compat"))
        save_crush("c2")
        cc("osd", "crush", "weight-set", "rm-compat")
        cc("osd", "crush", "weight-set", "rm", A)
        v2 = dump()["crush_version"]
        step("s14a", "S14: a crush rule added through the monitor", lambda d: d["crush_version"] > v2, ("osd", "crush", "rule", "create-replicated", PFX + "rule", "default", "osd"))
        save_crush("c3")
        step("s14z", "S14: the rule removed", lambda d: d["crush_version"] > v2 + 1, ("osd", "crush", "rule", "rm", PFX + "rule"))


base_snapshot = None


def main():
    global base_snapshot
    if os.path.exists(BASE_FILE) and CMD == "run":
        raise SystemExit("%s exists: a previous run did not finish. Run `map_oracle_lab.sh cleanup --work %s` first (or delete the work directory)." % (BASE_FILE, WORK))
    for k in ("ceph", "cephadm"):
        if shutil.which(k) is None:
            raise SystemExit("%s is not installed: this runs on the lab VM" % k)
    leftovers = own_pools()
    if leftovers:
        raise SystemExit("pools %s exist already (another run, or a failed one): `map_oracle_lab.sh cleanup` removes them" % leftovers)
    others = [p["pool_name"] for p in dump()["pools"] if p["pool_name"].startswith("wrtest-")]
    if others:
        log("warning: other wrtest-* pools exist (%s): another test may be running; epochs move under us, comparisons are retried per saved map" % others)
    base_snapshot = snapshot()
    json.dump(base_snapshot, open(BASE_FILE, "w"), indent=1, default=list)
    log("baseline: epoch %d, pools %s" % (base_snapshot["epoch"], [p[1] for p in base_snapshot["pools"]]))
    results, failed = [], []

    def phase(name, fn, *args):
        try:
            fn(*args)
        except BaseException:
            failed.append(name)
            log("!!! %s FAILED: %s" % (name, traceback.format_exc()))

    try:
        phase("driving the states", run_states, results)
        # what was saved is compared even when a later state could not be driven
        phase("per-PG comparison", compare_states, results)
        phase("crushtool comparison", compare_crush, results)
        if CHAIN and STATES:
            first = next((s for s in STATES if s["label"] == "s01-pools"), STATES[0])
            phase("incremental chain", chain_step, first["label"], first["epoch"], results)
    finally:
        try:
            cleanup(base_snapshot)
        except BaseException:
            failed.append("clean-up")
            log("!!! the clean-up failed: " + traceback.format_exc())
    probs = verify_restore(base_snapshot)
    log("restore check: %s" % ("OK" if not probs else probs))
    # ---- the summary ----
    total = D.Result("TOTAL")
    for r in results:
        total.merge(r)
    unreached = [s["label"] for s in STATES if not s["reached"]]
    log("")
    log("states saved: %d (%s)" % (len(STATES), ", ".join(s["label"] for s in STATES)))
    log("comparisons: %d compared, %d mismatches, %d skipped (pools or rules this client does not serve, names above the core's limit)" % (total.compared, len(total.mismatches), total.skipped))
    for r in results:
        log("  " + r.line())
    for m in total.mismatches[:20]:
        log("  MISMATCH " + m)
    rc = 0
    if total.mismatches:
        rc = 1
    # a run that skipped as much as it compared (or compared nothing) did not test the core: skipping is for the odd pool, never the rule
    if total.compared == 0 or total.skipped > total.compared:
        rc = 1
        log("too little compared: %d compared, %d skipped" % (total.compared, total.skipped))
    if failed or probs:
        rc = 1
        log("failed phases: %s" % failed)
    if unreached:
        log("states whose predicate was not met: %s" % unreached)
        rc = 1
    if not CHAIN:
        log("note: the incremental chain step was skipped (--no-chain)")
    if not probs:
        os.remove(BASE_FILE)    # the baseline is only needed to repair a restore that did not verify
    sys.exit(rc)


main()
PYEOF
