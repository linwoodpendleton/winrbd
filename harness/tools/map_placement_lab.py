#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
map_placement_lab.py - the live proof of the core's placement: the whole client (harness/src/winrbd-mapwatch) follows the lab
cluster over a real monitor session while this script changes the cluster, and every answer of the core is compared with Ceph's own.

    map_placement_lab.py run     [--tool PATH] [--work DIR] [--names N] [--keyring FILE --user ID] [--mon ADDR]
    map_placement_lab.py export  [--work DIR] [--out DIR]       build harness/vectors/public/placement/ from a finished run
    map_placement_lab.py cleanup [--work DIR]                   remove what a failed run left (pools wrtest-pl-*, rules, overrides)
    map_placement_lab.py reanalyze [--work DIR]                 redo the exact-epoch comparison of a finished run (no cluster changes)

Runs on the lab VM (passwordless sudo, cephadm; python3 with the `rados` module under sudo). It touches only: pools named
wrtest-pl-* (its own prefix), two crush rules named wrtest-pl-*, pg_upmap / pg_upmap_items / pg_upmap_primary / pg_temp /
primary_temp entries, primary affinity and reweight of the OSDs for a few seconds each, one OSD marked out and in,
require_min_compat_client (raised to reef for upmap-primary, then put back) and mon_allow_pool_delete (to delete its own pools).
All of it is put back at the end and checked against a snapshot taken first. It never touches the pool 'winrbd', never removes or
destroys an OSD or a monitor and never reads or writes a key (the winrbd-mapwatch client reads its own keyring file).

Method. winrbd-mapwatch (the core's monitor client + map store, no model in between) tracks the pools, takes the monitor's full map
and every later incremental, and writes (a) the placement of every PG of every tracked pool at EVERY epoch it adopts (--trace), (b) the
raw map messages it was handed (--save-maps) and (c) on command the placement of 2,000 synthetic object names per pool. Ground truth:
  * names:   `ceph osd map -f json` for every name of every pool (python rados mon_command, one session), accepted only when the
             monitor's reply names the same epoch as the core's row (the cluster is settled before each look; skewed rows are
             asked again, never counted as matches);
  * epochs:  `ceph osd getmap <epoch>` + `osdmaptool --test-map-pgs-dump-all` for every epoch the core traced, compared PG by PG
             (up, up primary, acting, acting primary), plus `ceph osd dump <epoch>` to count which overrides each epoch carried.
Fault cases: a message of the live link swallowed before the store (the next incremental has a gap: the store must ask for a full map)
and a monitor connection killed from the outside while maps change.
"""
import argparse
import collections
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import map_oracle_diff as D  # noqa: E402

PFX = "wrtest-pl-"
POOLS = [("a", 8, 3, "replicated_rule"), ("b", 13, 2, "replicated_rule"), ("c", 32, 3, PFX + "hdd"), ("d", 64, 2, PFX + "host")]
POOL_NAMES = {k: PFX + k for k, _, _, _ in POOLS}
TRACKED = ["winrbd"] + [PFX + k for k, _, _, _ in POOLS]
ME = "%d:%d" % (os.getuid(), os.getgid())
POOL_KEEP = ["pool", "pool_name", "flags", "flags_names", "type", "size", "min_size", "crush_rule", "object_hash", "pg_num", "pg_placement_num",
             "pg_num_target", "pg_placement_num_target", "pg_num_pending", "last_change", "tiers", "tier_of", "read_tier", "write_tier", "cache_mode",
             "erasure_code_profile", "stripe_width"]
DUMP_KEEP = ["epoch", "flags", "crush_version", "pool_max", "max_osd", "require_min_compat_client", "min_compat_client", "require_osd_release",
             "pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp", "erasure_code_profiles"]
FEATURES = ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp")


def obj_name(i):
    """the synthetic object names: half RBD data objects, half plain names"""
    return "rbd_data.5ae8a7c3d6e4.%016x" % i if i % 2 == 0 else "wrtest-pl-obj-%d" % i


def fnv64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def csv(v):
    return ",".join(str(x) for x in v)


# ---- tiny infrastructure ------------------------------------------------------------------------------------------

WORK = None
LOG = None


def log(s):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), s)
    print(line, flush=True)
    if LOG:
        LOG.write(line + "\n")
        LOG.flush()


def sh(cmd, check=True, timeout=1800, inp=None):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, input=inp)
    out, err = p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError("%s -> rc %d: %s %s" % (" ".join(cmd)[:200], p.returncode, out.strip()[:300], err.strip()[:300]))
    return p.returncode, out, err


OPS = []  # every cluster-changing command of the run, with its result


def cc(*a, check=True, quiet=False, record=True):
    t0 = time.time()
    rc, out, err = sh(["sudo", "ceph"] + [str(x) for x in a], check=False)
    msg = (err.strip() or out.strip())[:160].replace("\n", " | ")
    if not quiet:
        log("[%5.1fs] rc=%d ceph %s%s" % (time.time() - t0, rc, " ".join(str(x) for x in a), ("   => " + msg) if msg else ""))
    if record:
        OPS.append({"cmd": "ceph " + " ".join(str(x) for x in a), "rc": rc, "msg": msg})
    if check and rc != 0:
        raise RuntimeError("ceph %s -> rc %d: %s" % (" ".join(str(x) for x in a), rc, msg))
    return rc, out, err


def cj(*a):
    return json.loads(cc(*a, "-f", "json", quiet=True, record=False)[1])


def cur_epoch():
    return cj("osd", "stat")["epoch"]


def dump_now():
    return cj("osd", "dump")


def settled(timeout=240, stable=4):
    """no PG creating / peering / unknown / backfilling and the epoch unchanged for `stable` seconds; returns the epoch"""
    t0, last, since = time.time(), None, None
    while time.time() - t0 < timeout:
        st = cj("status")
        states = [s["state_name"] for s in st["pgmap"].get("pgs_by_state", [])]
        busy = [s for s in states if any(w in s for w in ("creating", "peering", "unknown", "activating", "backfill_wait", "backfilling", "stale", "recovering", "recovery_wait"))]
        e = st["osdmap"]["epoch"] if "epoch" in st["osdmap"] else cur_epoch()
        if busy or e != last:
            last, since = e, time.time()
        elif time.time() - since >= stable:
            return e
        time.sleep(1)
    log("warning: the cluster did not settle within %ds" % timeout)
    return cur_epoch()


def prune(d):
    o = {k: d[k] for k in DUMP_KEEP if k in d}
    o["pools"] = [{k: p[k] for k in POOL_KEEP if k in p} for p in d["pools"]]
    o["osds"] = [{k: x[k] for k in ("osd", "up", "in", "weight", "primary_affinity", "up_from", "up_thru", "down_at") if k in x} for x in d["osds"]]
    return o


def snapshot():
    d = dump_now()
    rules = json.loads(cc("osd", "crush", "rule", "dump", "-f", "json", quiet=True, record=False)[1])
    return {
        "pools": {p["pool_name"]: {k: p.get(k) for k in ("pool", "size", "min_size", "pg_num", "pg_placement_num", "crush_rule", "flags")} for p in d["pools"]},
        "osds": [(o["osd"], o["up"], o["in"], o["weight"], o["primary_affinity"]) for o in d["osds"]],
        "flags": d["flags"], "require_min_compat_client": d["require_min_compat_client"],
        "tables": {k: len(d.get(k, [])) for k in FEATURES},
        "rules": sorted((r["rule_id"], r["rule_name"]) for r in rules),
        "mon_allow_pool_delete": cc("config", "get", "mon", "mon_allow_pool_delete", quiet=True, record=False)[1].strip(),
        "mon_allow_pool_delete_in_db": any(c.get("name") == "mon_allow_pool_delete" for c in cj("config", "dump")),
        "tree": cc("osd", "tree", quiet=True, record=False)[1],
    }


def restore_cluster(base, why):
    """remove every override and every pool / rule of this tool, put the OSD settings and the two options back"""
    log("restoring the cluster (%s)" % why)
    d = dump_now()
    for e in d.get("pg_upmap_items", []):
        cc("osd", "rm-pg-upmap-items", e["pgid"], check=False)
    for e in d.get("pg_upmap", []):
        cc("osd", "rm-pg-upmap", e["pgid"], check=False)
    for e in d.get("pg_upmap_primaries", []):
        cc("osd", "rm-pg-upmap-primary", e["pgid"], check=False)
    pt = d.get("primary_temp", [])
    for i in range(0, len(pt), 2):
        if isinstance(pt[i], str):
            cc("osd", "rm-primary-temp", pt[i], check=False)
    for o in d["osds"]:
        cc("osd", "primary-affinity", "osd.%d" % o["osd"], "1", check=False)
        cc("osd", "reweight", o["osd"], "1", check=False)
        cc("osd", "in", o["osd"], check=False)
    cc("config", "set", "mon", "mon_allow_pool_delete", "true", check=False)
    for p in d["pools"]:
        if p["pool_name"].startswith(PFX):
            cc("osd", "pool", "rm", p["pool_name"], p["pool_name"], "--yes-i-really-really-mean-it", check=False)
    rules = json.loads(cc("osd", "crush", "rule", "dump", "-f", "json", quiet=True, record=False)[1])
    for r in rules:
        if r["rule_name"].startswith(PFX):
            cc("osd", "crush", "rule", "rm", r["rule_name"], check=False)
    if base is not None:
        if base["mon_allow_pool_delete_in_db"]:
            cc("config", "set", "mon", "mon_allow_pool_delete", base["mon_allow_pool_delete"], check=False)
        else:
            cc("config", "rm", "mon", "mon_allow_pool_delete", check=False)
        cc("osd", "set-require-min-compat-client", base["require_min_compat_client"], "--yes-i-really-mean-it", check=False)
    time.sleep(3)
    settled(timeout=120)


def verify_restore(base):
    now = snapshot()
    bad = []
    for k in ("pools", "osds", "flags", "require_min_compat_client", "tables", "mon_allow_pool_delete", "mon_allow_pool_delete_in_db", "rules"):
        if now[k] != base[k]:
            bad.append("%s: before %r, now %r" % (k, base[k], now[k]))
    if now["tree"] != base["tree"]:
        bad.append("osd tree differs")
    return bad, now


# ---- the client ---------------------------------------------------------------------------------------------------

class MW:
    """winrbd-mapwatch as a child process driven over its stdin"""

    def __init__(self, tool, mon, user, keyring, pools, wd, tag):
        self.wd = wd
        os.makedirs(os.path.join(wd, "saved-" + tag), exist_ok=True)
        self.trace = os.path.join(wd, "trace-%s.txt" % tag)
        self.logf = os.path.join(wd, "mapwatch-%s.log" % tag)
        self.saved = os.path.join(wd, "saved-" + tag)
        cmd = [tool, "--mon", mon, "--user", user, "--keyring", keyring, "--stdin", "--trace", self.trace, "--trace-pgs", "4096",
               "--save-maps", self.saved, "--log", self.logf, "--timeout", "30000"]
        for p in pools:
            cmd += ["--pool", p]
        self.err = open(os.path.join(wd, "mapwatch-%s.stderr" % tag), "w")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err, text=True, bufsize=1)

    def cmd(self, line, timeout=180):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        t0 = time.time()
        import select
        while True:
            r, _, _ = select.select([self.p.stdout], [], [], 1.0)
            if r:
                ln = self.p.stdout.readline()
                if ln == "":
                    raise RuntimeError("winrbd-mapwatch ended (see %s)" % self.logf)
                return ln.strip()
            if self.p.poll() is not None:
                raise RuntimeError("winrbd-mapwatch exited with %s" % self.p.returncode)
            if time.time() - t0 > timeout:
                raise RuntimeError("winrbd-mapwatch did not answer %r" % line)

    def ok(self, line, timeout=180):
        r = self.cmd(line, timeout)
        if not r.startswith("ok"):
            raise RuntimeError("winrbd-mapwatch: %r -> %s" % (line, r))
        return r

    def info(self):
        r = self.ok("info")
        return {k: v for k, v in (kv.split("=", 1) for kv in r.split()[1:] if "=" in kv)}

    def close(self):
        rc = None
        try:
            self.cmd("quit", 10)
            rc = self.p.wait(30)
        except Exception:
            self.p.kill()
            rc = self.p.wait()
        self.err.close()
        return rc


RE_ROW = re.compile(r"^(\d+) (\S+) (\S+) ps=([0-9a-f]+) pg=(\d+)\.([0-9a-f]+) (?:up=\[([^\]]*)\] upp=(-?\d+) acting=\[([^\]]*)\] actp=(-?\d+)|(UNMAPPABLE))$")


def ints(s):
    return [int(x) for x in s.split(",")] if s.strip() else []


def read_rows(path):
    """{(pool, name): (epoch, ps, pgid, up, upp, acting, actp)}; an UNMAPPABLE answer (no OSD serves the PG) has up = None"""
    rows = {}
    for ln in open(path):
        m = RE_ROW.match(ln.strip())
        if not m:
            if ln.strip():
                raise RuntimeError("an answer of the core that is not a row: %s" % ln.strip()[:200])
            continue
        e, pool, name, ps, pid, pg, up, upp, act, actp, unm = m.groups()
        if unm:
            rows[(pool, name)] = (int(e), int(ps, 16), "%s.%s" % (pid, pg), None, -1, [], -1)
        else:
            rows[(pool, name)] = (int(e), int(ps, 16), "%s.%s" % (pid, pg), ints(up), int(upp), ints(act), int(actp))
    return rows


# ---- ground truth helpers (run as root: they need the admin keyring) ----------------------------------------------------

TRUTH_PY = r'''
import json, sys, rados
names = [l.rstrip("\n") for l in open(sys.argv[1])]
pools = sys.argv[3].split(",")
out = open(sys.argv[2], "w")
c = rados.Rados(conffile="/etc/ceph/ceph.conf"); c.connect()
for p in pools:
    for i, n in enumerate(names):
        rc, outb, outs = c.mon_command(json.dumps({"prefix": "osd map", "pool": p, "object": n, "format": "json"}), b"")
        out.write(json.dumps({"pool": p, "i": i, "name": n, "rc": rc, "reply": json.loads(outb) if rc == 0 else outs}) + "\n")
out.close(); c.shutdown()
'''

EPOCH_PY = r'''
import json, sys, os, rados
c = rados.Rados(conffile="/etc/ceph/ceph.conf"); c.connect()
wd = sys.argv[1]
for e in [int(x) for x in sys.argv[2].split(",")]:
    mp = os.path.join(wd, "maps", "e%d.bin" % e)
    if not os.path.exists(mp):
        rc, outb, outs = c.mon_command(json.dumps({"prefix": "osd getmap", "epoch": e}), b"")
        if rc != 0:
            open(mp + ".err", "w").write(outs); continue
        open(mp, "wb").write(outb)
    dp = os.path.join(wd, "dumps", "e%d.json" % e)
    if not os.path.exists(dp):
        rc, outb, outs = c.mon_command(json.dumps({"prefix": "osd dump", "epoch": e, "format": "json"}), b"")
        if rc != 0:
            open(dp + ".err", "w").write(outs); continue
        open(dp, "wb").write(outb)
c.shutdown()
'''


def run_helper(name, text, args, timeout=3600):
    p = os.path.join(WORK, name)
    open(p, "w").write(text)
    sh(["sudo", "python3", "-I", p] + args, timeout=timeout)
    sh(["sudo", "chown", "-R", ME, WORK])


def run_in_cephadm(script_name, script_text, token, timeout=3600):
    open(os.path.join(WORK, script_name), "w").write(script_text)
    r = sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % WORK, "--", "bash", "/work/" + script_name], timeout=timeout, check=False)
    sh(["sudo", "chown", "-R", ME, WORK])
    if r[0] != 0 or token not in r[1]:
        raise RuntimeError("%s in the cephadm container failed (rc %d): %s %s" % (script_name, r[0], r[1][-400:], r[2][-400:]))


# ---- the comparison of names --------------------------------------------------------------------------------------------

class Tally:
    def __init__(self):
        self.names_compared = 0
        self.names_skewed = 0
        self.unmappable = 0
        self.names_mismatch = []
        self.by_pool = collections.Counter()
        self.state_rows = {}

    def bad(self, s):
        self.names_mismatch.append(s)
        log("MISMATCH " + s)


def compare_names(label, ours, truth_path, tally, pools_expected):
    """ours: {(pool, name): row}; truth jsonl. Returns (compared, skewed, rows compared by pool, truth rows {pool: [row by index]})"""
    compared = skewed = 0
    seen = collections.Counter()
    trows = collections.defaultdict(dict)
    for ln in open(truth_path):
        t = json.loads(ln)
        if t["rc"] != 0:
            tally.bad("%s: ceph osd map %s %s failed: %s" % (label, t["pool"], t["name"], t["reply"]))
            continue
        r = t["reply"]
        o = ours.get((t["pool"], t["name"]))
        if o is None:
            tally.bad("%s: no row of the core for %s %s" % (label, t["pool"], t["name"]))
            continue
        if o[0] != r["epoch"]:
            skewed += 1
            continue
        want = (int(r["raw_pgid"].split(".")[1], 16), r["pgid"], r["up"], r["up_primary"], r["acting"], r["acting_primary"])
        if o[3] is None:  # the core says nobody serves this PG: the monitor's acting set must be empty and have no primary
            got = (o[1], o[2], r["up"], r["up_primary"], [], -1)
            if r["acting"] == [] and r["acting_primary"] == -1:
                tally.unmappable += 1
        else:
            got = (o[1], o[2], o[3], o[4], o[5], o[6])
        compared += 1
        seen[t["pool"]] += 1
        trows[t["pool"]][t["i"]] = (r["epoch"], want[0], want[1], want[2], want[3], want[4], want[5])
        if want != got:
            tally.bad("%s: epoch %d pool %s object %s: monitor ps=%08x pg=%s up=%s/%s acting=%s/%s; core ps=%08x pg=%s up=%s/%s acting=%s/%s" %
                      (label, r["epoch"], t["pool"], t["name"], want[0], want[1], want[2], want[3], want[4], want[5], got[0], got[1], got[2], got[3], got[4], got[5]))
    return compared, skewed, seen, {p: [d[i] for i in sorted(d)] for p, d in trows.items()}


def names_digest(rows_by_pool, pool_ids):
    """FNV-1a 64 over `pool_id index up upp acting actp` lines, pools in ascending id (the C test does the same)"""
    h = bytearray()
    for pool in sorted(rows_by_pool, key=lambda p: pool_ids[p]):
        for i in range(len(rows_by_pool[pool])):
            o = rows_by_pool[pool][i]
            h += ("%d %d %s %d %s %d\n" % (pool_ids[pool], i, csv(o[3]), o[4], csv(o[5]), o[6])).encode()
    return "%016x" % fnv64(bytes(h))


# ---- the run -------------------------------------------------------------------------------------------------------------

class Run:
    def __init__(self, a):
        self.a = a
        self.tally = Tally()
        self.states = []  # {"label","epoch","description","ops","names_digest","sample"}
        self.nnames = a.names
        self.mw = None
        self.mw2 = None
        self.mw_tag = "m1"
        self.pool_ids = {}
        self.fault = {}

    def start_client(self):
        self.mw = MW(self.a.tool, self.a.mon, self.a.user, self.a.keyring, TRACKED, WORK, self.mw_tag)
        e = cur_epoch()
        self.mw.ok("wait-epoch %d 60" % e, 90)
        # a second client with the other key type (legacy aes) follows the whole run undisturbed: it must reach the same tables
        self.mw2 = MW(self.a.tool, self.a.mon, self.a.user2, self.a.keyring2, TRACKED, WORK, "m2")
        self.mw2.ok("wait-epoch %d 60" % e, 90)

    def place_and_compare(self, label, pools, quick=False):
        """place every name in every pool of `pools` with the client and compare with the monitor; retried until nothing is skewed.
        quick: do not wait for the cluster to settle (a state that does not last: temps), three attempts, skewed rows are only noted"""
        names_file = os.path.join(WORK, "names.txt")
        verdict = None
        for attempt in range(3 if quick else 8):
            e = cur_epoch() if quick else settled(timeout=180)
            self.mw.ok("wait-epoch %d 60" % e, 90)
            ours = {}
            for p in pools:
                out = os.path.join(WORK, "ours", "%s.%s.txt" % (label, p))
                self.mw.ok("placef %s %s %s" % (p, out, names_file), 300)
                ours.update(read_rows(out))
            tp = os.path.join(WORK, "truth", "%s.jsonl" % label)
            run_helper("truth_names.py", TRUTH_PY, [names_file, tp, ",".join(pools)])
            compared, skewed, seen, trows = compare_names(label, ours, tp, self.tally, pools)
            log("%s: names compared %d (%s), skewed by an epoch change %d, attempt %d" % (label, compared, dict(seen), skewed, attempt + 1))
            if skewed == 0 and compared == self.nnames * len(pools):
                verdict = (e, ours, trows, compared)
                break
        if verdict is None:
            if quick:
                log("%s: the state did not last long enough for a full pass (not counted, covered by the epoch trace)" % label)
                return None
            self.tally.bad("%s: the cluster never held one epoch for a full pass" % label)
            return None
        self.tally.names_compared += verdict[3]
        self.tally.names_skewed += skewed
        for p, n in seen.items():
            self.tally.by_pool[p] += n
        return verdict

    def state(self, label, desc, cmds, expect=None, pools=None, wait_s=0.0, quick=False):
        """run the cluster commands, settle, place all names, compare with the monitor, record the state"""
        t0 = len(OPS)
        for c in cmds:
            if c[0] == "?":  # a command the monitor may refuse (it is part of what the state tries)
                cc(*c[1:], check=False)
            else:
                cc(*c)
        if wait_s:
            time.sleep(wait_s)
        d = dump_now()
        present = [p["pool_name"] for p in d["pools"] if p["pool_name"] in TRACKED]
        pools = [p for p in (pools or present) if p in present]
        res = self.place_and_compare(label, pools, quick)
        if res is None:
            return
        e, ours, rows_by_pool, compared = res
        dd = json.loads(sh(["sudo", "ceph", "osd", "dump", str(e), "-f", "json"])[1])
        ids = {p["pool_name"]: p["pool"] for p in dd["pools"]}
        witness = {k: len(dd.get(k, [])) for k in FEATURES}
        ok = True
        if expect is not None:
            ok = expect(dd)
            if not ok:
                self.tally.bad("%s: the state the step is about was not in epoch %d (%s)" % (label, e, witness))
        sample = []
        for p in pools:
            idx = sorted(random.Random(label + p).sample(range(self.nnames), min(40, self.nnames)))
            for i in idx:
                o = rows_by_pool[p][i]
                sample.append([ids[p], i, o[0], "%08x" % o[1], o[2], o[3], o[4], o[5], o[6]])
        self.states.append({"label": label, "epoch": e, "description": desc, "pools": pools, "witness": witness, "names": compared,
                            "names_digest": names_digest(rows_by_pool, ids), "sample": sample, "ops": OPS[t0:], "witnessed": ok})
        log("state %s epoch %d: %d names compared, witness %s" % (label, e, compared, witness))

    # ---- the scenario --------------------------------------------------------------------------------------------------

    def create_pools(self):
        cc("osd", "crush", "rule", "create-replicated", PFX + "hdd", "default", "osd", "hdd")
        cc("osd", "crush", "rule", "create-replicated", PFX + "host", "default", "host")
        for k, pg, size, rule in POOLS:
            name = PFX + k
            cc("osd", "pool", "create", name, str(pg), str(pg), "replicated", rule)
            cc("osd", "pool", "set", name, "pg_autoscale_mode", "off")
            cc("osd", "pool", "set", name, "size", str(size))
            if size == 2:
                cc("osd", "pool", "set", name, "min_size", "1")
        settled(timeout=240)

    def pg_of(self, pool, seed):
        return "%d.%x" % (self.pool_ids[pool], seed)

    def up_of(self, pool, seed):
        r = cj("pg", "map", self.pg_of(pool, seed))
        return r["up"]

    def scenario(self):
        self.mw = None
        self.start_client()
        self.mw.ok("info")
        self.create_pools()
        self.pool_ids = {p["pool_name"]: p["pool"] for p in dump_now()["pools"]}
        A, B, C, Dp = (PFX + x for x in "abcd")
        self.state("s00-base", "the four test pools created (pg_num 8 / 13 / 32 / 64, size 3 / 2 / 3 / 2, rules choose-osd / choose-osd / device class hdd / chooseleaf host) and winrbd", [])
        # ---- upmap
        ub = self.up_of(B, 0)
        spare = [o for o in range(3) if o not in ub][0]
        ub5 = self.up_of(B, 5)
        spare5 = [o for o in range(3) if o not in ub5][0]
        ua = self.up_of(A, 1)
        self.state("s01-upmap-items", "pg_upmap_items on pool b (two PGs, one pair each; one more pair names an OSD already in the set) and pool a (a pair whose to is in the set)",
                   [("osd", "pg-upmap-items", self.pg_of(B, 0), ub[0], spare), ("osd", "pg-upmap-items", self.pg_of(B, 5), ub5[1], spare5),
                    ("?", "osd", "pg-upmap-items", self.pg_of(A, 1), ua[0], ua[1])],
                   expect=lambda d: len(d.get("pg_upmap_items", [])) >= 2)
        self.state("s02-upmap-full", "pg_upmap on pool a (a reordered full set) and on pool c (a different order), the earlier items still set",
                   [("osd", "pg-upmap", self.pg_of(A, 2), *reversed(self.up_of(A, 2))), ("osd", "pg-upmap", self.pg_of(C, 7), *(lambda u: u[1:] + u[:1])(self.up_of(C, 7)))],
                   expect=lambda d: len(d.get("pg_upmap", [])) >= 1)
        self.state("s03-upmap-cleared", "every upmap removed again",
                   [("osd", "rm-pg-upmap-items", self.pg_of(B, 0)), ("osd", "rm-pg-upmap-items", self.pg_of(B, 5)), ("?", "osd", "rm-pg-upmap-items", self.pg_of(A, 1)),
                    ("osd", "rm-pg-upmap", self.pg_of(A, 2)), ("osd", "rm-pg-upmap", self.pg_of(C, 7))])
        # ---- upmap primary (needs reef)
        cc("osd", "set-require-min-compat-client", "reef", "--yes-i-really-mean-it")
        ua3, uc4 = self.up_of(A, 3), self.up_of(C, 4)
        self.state("s04-upmap-primary", "pg_upmap_primary on pool a and pool c (the last OSD of the set becomes the primary); require_min_compat_client reef",
                   [("osd", "pg-upmap-primary", self.pg_of(A, 3), ua3[-1]), ("osd", "pg-upmap-primary", self.pg_of(C, 4), uc4[-1])],
                   expect=lambda d: len(d.get("pg_upmap_primaries", [])) >= 2)
        self.state("s04z-upmap-primary-cleared", "pg_upmap_primary removed again",
                   [("osd", "rm-pg-upmap-primary", self.pg_of(A, 3)), ("osd", "rm-pg-upmap-primary", self.pg_of(C, 4))])
        cc("osd", "set-require-min-compat-client", "luminous", "--yes-i-really-mean-it")
        # ---- primary affinity
        self.state("s05-affinity", "primary affinity 0 on osd.0, 0.5 on osd.1",
                   [("osd", "primary-affinity", "osd.0", "0"), ("osd", "primary-affinity", "osd.1", "0.5")],
                   expect=lambda d: any(o["primary_affinity"] < 1 for o in d["osds"]))
        self.state("s05z-affinity-reset", "primary affinity back to 1", [("osd", "primary-affinity", "osd.0", "1"), ("osd", "primary-affinity", "osd.1", "1")])
        # ---- reweight
        self.state("s06-reweight", "reweight osd.0 0.6 and osd.2 0.2", [("osd", "reweight", "0", "0.6"), ("osd", "reweight", "2", "0.2")],
                   expect=lambda d: any(0 < o["weight"] < 1 for o in d["osds"]))
        self.state("s06b-reweight-zero", "reweight osd.1 0 (a member that CRUSH must now skip)", [("osd", "reweight", "1", "0")])
        self.state("s06c-reweight-low", "reweight osd.0 0.3, osd.2 0.1 (osd.1 stays 0): CRUSH rejects most picks, some PGs of the one-host pool get no OSD at all",
                   [("osd", "reweight", "0", "0.3"), ("osd", "reweight", "2", "0.1")])
        self.state("s06z-reweight-reset", "reweights back to 1", [("osd", "reweight", "0", "1"), ("osd", "reweight", "1", "1"), ("osd", "reweight", "2", "1")])
        # ---- out / in (pg_temp while PGs move)
        self.state("s07-osd-out", "osd.2 marked out", [("osd", "out", "2")], expect=lambda d: any(o["in"] == 0 for o in d["osds"]))
        self.state("s07z-osd-in", "osd.2 marked in again", [("osd", "in", "2")])
        # ---- pg_temp and primary_temp (the primary_temp OSD is a member of both the up and the temp set, so it is in the acting set either way)
        ub1 = self.up_of(B, 1)
        uc2 = self.up_of(C, 2)
        cmds = [("osd", "pg-temp", self.pg_of(B, 1), ub1[1], ub1[0]), ("osd", "primary-temp", self.pg_of(B, 1), ub1[0]),
                ("osd", "pg-temp", self.pg_of(C, 2), uc2[2], uc2[0], uc2[1]), ("osd", "primary-temp", self.pg_of(C, 2), uc2[1])]
        self.state("s08-temps", "pg_temp (a reordered set) and primary_temp on one PG each of pools b and c", cmds, pools=[PFX + "b"], quick=True)
        cur = dump_now()
        pt = cur.get("primary_temp", [])
        rm = [("osd", "rm-primary-temp", pt[i]) for i in range(0, len(pt), 2) if isinstance(pt[i], str)]
        rm += [("?", "osd", "pg-temp", self.pg_of(B, 1)), ("?", "osd", "pg-temp", self.pg_of(C, 2))]  # an empty list removes the entry
        self.state("s08z-temps-cleared", "primary_temp (and any pg_temp left) removed", rm)
        # ---- sizes
        self.state("s09-resize", "pool b size 2 -> 3, pool a size 3 -> 2", [("osd", "pool", "set", B, "size", "3"), ("osd", "pool", "set", A, "size", "2"),
                                                                              ("osd", "pool", "set", A, "min_size", "1")])
        self.state("s09z-resize-back", "pool b size 3 -> 2, pool a size 2 -> 3", [("osd", "pool", "set", B, "size", "2"), ("osd", "pool", "set", A, "size", "3")])
        # ---- splits: pg_num rises, pgp_num follows (mgr)
        self.state("s10-split", "pool a pg_num 8 -> 16 and pool b pg_num 13 -> 20 (pgp_num follows in steps); looked at once the cluster settles",
                   [("osd", "pool", "set", A, "pg_num", "16"), ("osd", "pool", "set", B, "pg_num", "20")], wait_s=1)
        self.state("s10z-split-done", "same pools after pgp_num caught up", [])

    def gap_and_cut(self):
        A = PFX + "a"
        before = self.mw.info()
        self.mw.ok("drop 1")
        t = time.time()
        cc("osd", "reweight", "1", "0.9")
        time.sleep(2)
        cc("osd", "reweight", "1", "1")
        for _ in range(60):
            inf = self.mw.info()
            if int(inf["resync"]) > int(before["resync"]):
                break
            time.sleep(1)
        self.mw.ok("wait-epoch %d 60" % cur_epoch(), 90)
        after = self.mw.info()
        self.fault["gap"] = {"before": before, "after": after, "seconds": round(time.time() - t, 1)}
        log("gap: %s" % self.fault["gap"])
        if int(after["dropped_by_hook"]) < 1 or int(after["resync"]) <= int(before["resync"]) or int(after["full"]) <= int(before["full"]):
            self.tally.bad("gap: the swallowed message did not lead to a full-map request and a full map (%s -> %s)" % (before, after))
        self.state("s11-after-gap", "the core missed one incremental (swallowed before the store), asked the monitor for a full map and adopted it; reweight osd.1 0.9 and back",
                   [], pools=[PFX + "a", PFX + "b", "winrbd"])
        # the connection is killed from outside while maps change
        before = self.mw.info()
        killed = 0
        for val in ("0.7", "1", "0.5", "1"):  # four times: kill the connection, change the maps, let the core reconnect
            killed += kill_mon_connection(self.mw.p.pid)
            cc("osd", "reweight", "2", val)
            time.sleep(0.7)
        self.mw.ok("wait-epoch %d 60" % cur_epoch(), 90)
        after = self.mw.info()
        self.fault["cut"] = {"killed_sockets": killed, "before": before, "after": after}
        log("cut: %s" % self.fault["cut"])
        self.state("s12-after-cut", "the monitor connection was killed from outside while osd.2 was reweighted 0.7 and back; the core reconnected and caught up",
                   [], pools=[PFX + "a", PFX + "b", "winrbd"])

    def finish(self, base):
        # delete one pool (the tracked pool disappears from the map), then the rest
        cc("config", "set", "mon", "mon_allow_pool_delete", "true")
        self.state("s13-pool-deleted", "pool d deleted (a tracked pool disappears from the map)",
                   [("osd", "pool", "rm", PFX + "d", PFX + "d", "--yes-i-really-really-mean-it")],
                   expect=lambda d: all(p["pool_name"] != PFX + "d" for p in d["pools"]))


def kill_mon_connection(pid):
    """kill the TCP connection of ONE process (the client under test) to the monitor, by its local port (ss -K); returns the number of
    sockets of that process that were found. Other daemons' connections are never selected."""
    rc, out, _ = sh(["sudo", "ss", "-tnp", "dst", "10.77.0.10", "dport", "=", ":3300"], check=False)
    ports = []
    for ln in out.splitlines()[1:]:
        m = re.search(r"10\.77\.0\.10:(\d+)\s+10\.77\.0\.10:3300.*pid=%d," % pid, ln)
        if m:
            ports.append(m.group(1))
    for port in ports:
        sh(["sudo", "ss", "-K", "dst", "10.77.0.10", "dport", "=", ":3300", "sport", "=", ":" + port], check=False)
    return len(ports)


# ---- after the run: the exact-epoch comparison of every epoch the core adopted --------------------------------------------

def parse_trace(path):
    ep = collections.OrderedDict()
    cur = None
    for ln in open(path):
        ln = ln.rstrip("\n")
        if ln.startswith("== epoch "):
            cur = int(ln.split()[2])
            ep[cur] = {"pools": {}, "pgs": {}}
        elif ln.startswith("pool "):
            m = re.match(r"^pool (\S+) (ABSENT|id=(\d+) size=(\d+) min_size=(\d+) pg_num=(\d+) pgp_num=(\d+) flags=([0-9a-f]+))$", ln)
            if m.group(2) == "ABSENT":
                ep[cur]["pools"][m.group(1)] = None
            else:
                ep[cur]["pools"][m.group(1)] = {"id": int(m.group(3)), "size": int(m.group(4)), "pg_num": int(m.group(6)), "pgp_num": int(m.group(7))}
        else:
            m = re.match(r"^(\d+) (\S+) pg=(\d+)\.([0-9a-f]+) (?:up=\[([^\]]*)\] upp=(-?\d+) acting=\[([^\]]*)\] actp=(-?\d+)|(\S+.*))$", ln)
            if not m:
                raise RuntimeError("trace line not understood: %s" % ln)
            if m.group(9):
                ep[cur]["pgs"][(int(m.group(3)), int(m.group(4), 16))] = m.group(9)
            else:
                ep[cur]["pgs"][(int(m.group(3)), int(m.group(4), 16))] = (ints(m.group(5)), int(m.group(6)), ints(m.group(7)), int(m.group(8)))
    return ep


def check_epochs(runs, state_epochs, results, span=None):
    """osdmaptool on the monitor's own full map of every traced epoch against the core's table of that epoch, for every client trace;
    returns the epochs.tsv rows (every epoch of the span, also those no client held)"""
    for d in ("maps", "dumps", "pgs"):
        os.makedirs(os.path.join(WORK, d), exist_ok=True)
    traces = [(tag, parse_trace(path)) for tag, path in runs]
    traced = set()
    for _, tr in traces:
        traced |= set(tr)
    eps = sorted(traced | set(state_epochs) | (set(range(span[0], span[1] + 1)) if span else set()))
    log("epochs to check: %d (first %d, last %d), %d client trace(s); asking the monitor for its map and dump of each" % (len(eps), eps[0], eps[-1], len(traces)))
    run_helper("epoch_fetch.py", EPOCH_PY, [WORK, ",".join(str(e) for e in eps)])
    missing = [e for e in eps if not os.path.exists(os.path.join(WORK, "maps", "e%d.bin" % e))]
    lines = ["cd /work/maps"]
    for e in eps:
        if e in missing:
            continue
        lines.append("osdmaptool e%d.bin --test-map-pgs-dump-all > ../pgs/e%d.txt 2> ../pgs/e%d.err || echo 'osdmaptool failed e%d'" % (e, e, e, e))
    run_in_cephadm("pgs_run.sh", "\n".join(lines) + "\necho PGS-DONE\n", "PGS-DONE")
    rows = []
    feat_epochs = collections.Counter()
    pgs_compared = 0
    mism = 0
    unmappable = 0
    for e in eps:
        if e in missing:
            if any(e in tr for _, tr in traces):
                results.append("epoch %d: the monitor no longer has its map" % e)
                mism += 1
            continue
        dump = json.load(open(os.path.join(WORK, "dumps", "e%d.json" % e)))
        ids = {p["pool_name"]: p["pool"] for p in dump["pools"]}
        for k in FEATURES:
            if dump.get(k):
                feat_epochs[k] += 1
        if any(o["weight"] < 1 for o in dump["osds"]):
            feat_epochs["reweighted"] += 1
        if any(o["primary_affinity"] < 1 for o in dump["osds"]):
            feat_epochs["primary_affinity"] += 1
        if any(o["in"] == 0 for o in dump["osds"]):
            feat_epochs["osd_out"] += 1
        if any(p["pg_num"] != p["pg_placement_num"] for p in dump["pools"] if p["pool_name"] in TRACKED):
            feat_epochs["pgp_lagging"] += 1
        truth, errs, _ = D.parse_pg_text(open(os.path.join(WORK, "pgs", "e%d.txt" % e)).read())
        tracked_ids = sorted(ids[n] for n in TRACKED if n in ids)
        digest_rows = []
        for pid in tracked_ids:
            for (p, s) in sorted(k for k in truth if k[0] == pid):
                t = truth[(p, s)]
                digest_rows.append("%d.%x %s %d %s %d\n" % (p, s, csv(t[2]), t[3], csv(t[4]), t[5]))
        rows.append((e, len(digest_rows), "%016x" % fnv64("".join(digest_rows).encode())))
        for tag, tr in traces:
            rec = tr.get(e)
            if rec is None:
                continue
            for name in TRACKED:
                ours_pool = rec["pools"].get(name, "missing")
                if ours_pool == "missing":
                    continue
                if name not in ids:
                    if ours_pool is not None:
                        results.append("%s epoch %d: the core has pool %s, the monitor's map does not" % (tag, e, name))
                        mism += 1
                    continue
                if ours_pool is None:
                    results.append("%s epoch %d: the monitor's map has pool %s, the core says it is absent" % (tag, e, name))
                    mism += 1
                    continue
                pid = ids[name]
                tp = [p for p in dump["pools"] if p["pool"] == pid][0]
                if (ours_pool["id"], ours_pool["size"], ours_pool["pg_num"], ours_pool["pgp_num"]) != (pid, tp["size"], tp["pg_num"], tp["pg_placement_num"]):
                    results.append("%s epoch %d pool %s: geometry %r, monitor id %d size %d pg_num %d pgp_num %d" % (tag, e, name, ours_pool, pid, tp["size"], tp["pg_num"], tp["pg_placement_num"]))
                    mism += 1
                for s in range(tp["pg_num"]):
                    o = rec["pgs"].get((pid, s))
                    t = truth.get((pid, s))
                    pgs_compared += 1
                    if isinstance(o, str) and t is not None:  # UNMAPPABLE: nobody serves the PG, so osdmaptool's acting set must be empty
                        if t[4] == [] and t[5] == -1:
                            unmappable += 1
                            continue
                    if t is None or o is None or isinstance(o, str) or (o[0], o[1], o[2], o[3]) != (t[2], t[3], t[4], t[5]):
                        mism += 1
                        if mism <= 10:
                            results.append("%s epoch %d pg %d.%x: core %r, osdmaptool %r" % (tag, e, pid, s, o, t and (t[2], t[3], t[4], t[5])))
    feat_epochs["unmappable_pg_rows"] = unmappable
    return rows, pgs_compared, mism, feat_epochs, eps


# ---- commands --------------------------------------------------------------------------------------------------------------

def default_work():
    return os.path.join(os.path.expanduser("~"), "w", "placement-live", "work")


def safe_work(w):
    w = os.path.realpath(w)
    h = os.path.realpath(os.path.expanduser("~"))
    if not w.startswith(h + os.sep) or len(os.path.relpath(w, h).split(os.sep)) < 2:
        raise SystemExit("refusing %s as the work directory: it must be at least two levels below %s" % (w, h))
    return w


def cmd_run(a):
    global WORK, LOG
    WORK = safe_work(a.work)
    for d in ("ours", "truth", "maps", "dumps", "pgs"):
        os.makedirs(os.path.join(WORK, d), exist_ok=True)
    LOG = open(os.path.join(WORK, "run.log"), "a")
    names_file = os.path.join(WORK, "names.txt")
    open(names_file, "w").write("".join(obj_name(i) + "\n" for i in range(a.names)))
    base = snapshot()
    json.dump(base, open(os.path.join(WORK, "baseline.json"), "w"), indent=1, sort_keys=True)
    e0 = base_epoch = cur_epoch()
    log("baseline epoch %d, pools %s" % (e0, sorted(base["pools"])))
    leftovers = [p for p in base["pools"] if p.startswith(PFX)] + [r for _, r in base["rules"] if r.startswith(PFX)]
    if leftovers:
        raise SystemExit("leftovers of an earlier run (%s): run `cleanup` first" % leftovers)
    run = Run(a)
    failure = None
    try:
        run.scenario()
        run.gap_and_cut()
        run.finish(base)
    except Exception as ex:  # noqa: BLE001
        import traceback
        failure = traceback.format_exc()
        log("FAILED: " + failure)
    finally:
        info = None
        rc = None
        info2 = rc2 = None
        if run.mw2 is not None:
            try:
                run.mw2.ok("wait-epoch %d 60" % cur_epoch(), 90)
                info2 = run.mw2.info()
            except Exception:
                pass
            rc2 = run.mw2.close()
        if run.mw is not None:
            try:
                info = run.mw.info()
            except Exception:
                pass
            rc = run.mw.close()
        restore_cluster(base, "end of run")
    bad, now = verify_restore(base)
    log("restore verified: %s" % ("identical to the baseline" if not bad else bad))
    results = []
    runs = ([(run.mw_tag, run.mw.trace)] if run.mw is not None else []) + ([("m2", run.mw2.trace)] if run.mw2 is not None else [])
    last_traced = max(parse_trace(runs[0][1])) if runs else e0
    rows, pgs_compared, mism, feats, eps = check_epochs(runs, [s["epoch"] for s in run.states], results, (e0, last_traced))
    json.dump({"states": run.states, "epochs": rows, "tally": {"names_compared": run.tally.names_compared, "by_pool": dict(run.tally.by_pool), "name_mismatches": run.tally.names_mismatch[:50]},
               "pg_rows_compared": pgs_compared, "pg_mismatches": mism, "feature_epochs": dict(feats), "fault": run.fault, "client_info": info, "client_rc": rc, "client2_info": info2, "client2_rc": rc2, "first_epoch": e0,
               "epoch_list": eps, "pool_ids": run.pool_ids, "ops": OPS, "restore_problems": bad, "failure": failure, "pg_mismatch_samples": results[:20]},
              open(os.path.join(WORK, "result.json"), "w"), indent=1, sort_keys=True)
    log("RESULT names compared %d (mismatches %d, skewed rows asked again %d) | traced epochs %d, PG rows compared %d, mismatches %d | feature epochs %s | client %s rc %s | second client %s rc %s | restore %s" %
        (run.tally.names_compared, len(run.tally.names_mismatch), run.tally.names_skewed, len(eps), pgs_compared, mism, dict(feats), info, rc, info2, rc2, "ok" if not bad else "PROBLEMS"))
    for r in results[:10]:
        log("  " + r)
    if info2 is not None and (int(info2["bad"]) or int(info2["resync"]) or int(info2["full"]) != 1 or rc2 != 0):
        log("the undisturbed second client was not clean: %s rc %s" % (info2, rc2))
        mism += 1
    ok = not failure and not run.tally.names_mismatch and mism == 0 and not bad and rc == 0 and run.tally.names_compared > 0
    return 0 if ok else 1


def cmd_reanalyze(a):
    """redo the exact-epoch comparison of a finished run (every epoch from the first to the last, also those the core never held)"""
    global WORK, LOG
    WORK = safe_work(a.work)
    LOG = open(os.path.join(WORK, "run.log"), "a")
    rp = os.path.join(WORK, "result.json")
    res = json.load(open(rp))
    results = []
    runs = [("m1", os.path.join(WORK, "trace-m1.txt"))] + ([("m2", os.path.join(WORK, "trace-m2.txt"))] if os.path.exists(os.path.join(WORK, "trace-m2.txt")) else [])
    last = max(parse_trace(runs[0][1]))
    rows, pgs_compared, mism, feats, eps = check_epochs(runs, [s["epoch"] for s in res["states"]], results, (res["first_epoch"], last))
    res.update({"epochs": rows, "pg_rows_compared": pgs_compared, "pg_mismatches": mism, "feature_epochs": dict(feats), "epoch_list": eps, "pg_mismatch_samples": results[:20]})
    json.dump(res, open(rp, "w"), indent=1, sort_keys=True)
    log("REANALYZED traced epochs + gaps filled: %d epochs, PG rows compared %d, mismatches %d, feature epochs %s" % (len(eps), pgs_compared, mism, dict(feats)))
    return 0 if mism == 0 else 1


def cmd_cleanup(a):
    global WORK, LOG
    WORK = safe_work(a.work)
    os.makedirs(WORK, exist_ok=True)
    LOG = open(os.path.join(WORK, "run.log"), "a")
    bp = os.path.join(WORK, "baseline.json")
    base = json.load(open(bp)) if os.path.exists(bp) else None
    restore_cluster(base, "cleanup")
    if base:
        bad, _ = verify_restore(base)
        log("restore verified: %s" % ("identical to the baseline" if not bad else bad))
        return 0 if not bad else 1
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("run", "cleanup", "export", "reanalyze"):
        s = sub.add_parser(n)
        s.add_argument("--work", default=default_work())
        s.add_argument("--tool", default=os.path.join(os.path.expanduser("~"), "w", "placement-live", "b-gcc", "winrbd-mapwatch"))
        s.add_argument("--names", type=int, default=2000)
        s.add_argument("--mon", default="10.77.0.10:3300")
        s.add_argument("--user", default="winrbd")
        s.add_argument("--keyring", default=os.path.join(os.path.expanduser("~"), "keys", "client.winrbd.keyring"))
        s.add_argument("--user2", default="winrbd-aes")
        s.add_argument("--keyring2", default=os.path.join(os.path.expanduser("~"), "keys", "client.winrbd-aes.keyring"))
        s.add_argument("--out", default=None)
    a = ap.parse_args()
    if a.cmd == "run":
        return cmd_run(a)
    if a.cmd == "cleanup":
        return cmd_cleanup(a)
    if a.cmd == "reanalyze":
        return cmd_reanalyze(a)
    import map_placement_export as X
    return X.export(a)


if __name__ == "__main__":
    sys.exit(main())
