#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# capture_mapb.sh - capture, build and check the "map-b" public vectors (harness/vectors/public/mapb/):
# placement states the first vector set lacks (non power-of-two pg_num, split / merge, upmap, upmap primary,
# pg_temp / primary_temp, primary affinity, reweight / out, noup + down, legacy pools, pool create / rename /
# delete, erasure pool and cache tier, choose_args, bucket algorithms, legacy tunables, device classes).
#
#   capture_mapb.sh capture   on the lab VM (passwordless sudo, cephadm): drives the cluster, restores it, writes the raw
#                             outputs to $MAPB_RAW (default ~/w/vectors-b/work/raw)
#   capture_mapb.sh export    on the lab VM: copies the monitor store, exports every incremental and full map from the base
#                             epoch on, runs osdmaptool over every saved map (the store copy holds the cluster's keys: delete it)
#   capture_mapb.sh offline   on the lab VM: builds the offline CRUSH maps / OSDMaps and runs the Ceph tools on them
#   capture_mapb.sh build     scrubs the raw outputs and writes harness/vectors/public/mapb/ (python3 + the raw directory)
#   capture_mapb.sh --check   verifies the committed vectors: sizes, hashes, scrub, CRCs, every name hash, the name oracle and
#                             the targeted answers against the rebuilt maps, and (default) every tabulated PG result, every
#                             offline map and every crushtool mapping against the independent python mapper (python3 only; the
#                             CRUSH log tables come from core/crush_ln/, else WINRBD_CEPH_SRC / harness/.ceph-ref;
#                             MAPB_DEEP=0 turns the mapper cross-checks off)
#   capture_mapb.sh --selftest  damages copies of the vectors in 16 ways and wants --check to fail on each (python3 only)
#   capture_mapb.sh cleanup   removes whatever a failed `capture` left on the lab (pools wrtest-mb-*, rule, profile, overrides)
#   capture_mapb.sh all       capture, export, offline, build, --check
#
# What the lab run may touch (CONTRIBUTING.md, lab rules): pools named wrtest-mb-* (the prefix is the script's own, so
# another test user's wrtest-* pools are never touched), one extra crush rule, one erasure profile, a weight set of a
# test pool, OSD-wide upmap / temp / affinity / reweight / out / noup entries for a few seconds each, and
# require_min_compat_client (raised to reef for upmap-primary, then lowered again) and mon_allow_pool_delete. Everything
# is restored at the end and the restore is verified (raw/restore.json). It never touches pool 'winrbd', OSD / mon
# objects, or any key. Nothing secret is written: the build step replaces the cluster fsid and the OSD uuids exactly like
# harness/vectors/osdmap/README.md describes, and recomputes the CRCs.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
MAPB="${MAPB_OUT:-$REPO/harness/vectors/public/mapb}"
WORK="${MAPB_WORK:-${HOME:-/nonexistent}/w/vectors-b/work}"
RAW="${MAPB_RAW:-$WORK/raw}"

read -r -d '' PY_COMMON <<'PYEOF' || true
import json, os, sys, struct, hashlib, re, collections
TOOLS = os.path.join(os.environ["MAPB_REPO"], "harness", "tools")
sys.path.insert(0, TOOLS)
import osdmap_check as oc
PLACEHOLDER_FSID = bytes.fromhex("00112233445566778899aabbccddeeff")
def uuid_bytes(s): return bytes.fromhex(s.replace("-", ""))
def wrap_hex(b, width=96):
    h = b.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))
def cdump(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
def hash_name(pool, name, ns):
    """raw ps of an object: the pool's hash over [ns 0x1f] name"""
    return oc.object_ps(pool, name, ns)
def pgids(d, key):
    """pgids of an override table of `ceph osd dump -f json`: dict rows (pg_temp, pg_upmap, ...) or a flat [pgid, osd, ...] list (primary_temp)"""
    out = []
    for r in d.get(key, []):
        if isinstance(r, dict): out.append(r.get("pgid"))
        elif isinstance(r, str): out.append(r)
    return out
def norm_map(m):
    """plain dicts: the checker's tables are OrderedDicts, which compare insertion order too (an applied incremental appends)"""
    m2 = dict(m)
    for k in ("pg_temp", "primary_temp", "pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pool_name", "pools"):
        if k in m2: m2[k] = dict(m2[k])
    return m2
def same_state(a, b, where):
    """no differences between two decoded maps (crush compared structurally: an incremental's crush blob has two more tunables)"""
    errs = oc.state_diff_nocrush(norm_map(a), norm_map(b), where)
    if oc.crush_struct(oc.dec_crush(a["crush"])) != oc.crush_struct(oc.dec_crush(b["crush"])): errs.append(where + ": crush differs")
    return errs
def safe_work(w):
    """the work directory is deleted from (the monitor store copy): it must be a directory at least two levels below the home directory"""
    w = os.path.realpath(w); h = os.path.realpath(os.path.expanduser("~"))
    if not w.startswith(h + os.sep) or len(os.path.relpath(w, h).split(os.sep)) < 2:
        raise SystemExit("refusing to use %s as the work directory: it must be at least two levels below %s" % (w, h))
    return w
def pg_of_ps(pg_num, ps):
    return oc.stable_mod(ps, pg_num, (1 << (pg_num - 1).bit_length()) - 1)
PYEOF

# ---------------------------------------------------------------------------------------------------------
# lab capture driver (runs on the lab VM; every ceph call goes through sudo)
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_CAPTURE <<'PYEOF' || true
import subprocess, time, random, shutil, traceback, copy
RAW = os.environ["MAPB_RAW"]; WORK = os.environ["MAPB_WORK"]
for d in ("maps", "dumps", "names", "pgs", "objs_in", "objs", "inc", "full", "crush"):
    os.makedirs(os.path.join(RAW, d), exist_ok=True)
LOGF = open(os.path.join(RAW, "ops.log"), "a")
OPS = []          # commands since the last mark
FAILS = []

def log(s):
    LOGF.write(s + "\n"); LOGF.flush(); print(s, flush=True)

def sh(cmd, check=True, timeout=900, inp=None):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, input=inp)
    out = p.stdout.decode("utf-8", "replace"); err = p.stderr.decode("utf-8", "replace")
    if check and p.returncode != 0:
        raise RuntimeError("%s -> rc %d: %s %s" % (" ".join(cmd), p.returncode, out.strip()[:300], err.strip()[:300]))
    return p.returncode, out, err

def cc(*a, check=True, note=True):
    """one ceph command; logged; returns (rc, out, err)"""
    t0 = time.time()
    rc, out, err = sh(["sudo", "ceph"] + list(a), check=False)
    line = "ceph " + " ".join(a)
    msg = (err.strip() or out.strip())[:160].replace("\n", " | ")
    log("[%6.1fs] rc=%d %s%s" % (time.time() - t0, rc, line, ("   => " + msg) if msg else ""))
    if note:
        OPS.append({"cmd": line, "rc": rc, "msg": msg})
    if check and rc != 0:
        raise RuntimeError("%s -> rc %d: %s" % (line, rc, msg))
    return rc, out, err

def cj(*a):
    rc, out, err = cc(*a, "-f", "json", note=False)
    return json.loads(out)

def cur_epoch():
    return cj("osd", "stat")["epoch"]

DUMPS = {}
def dump(e):
    if e not in DUMPS:
        p = os.path.join(RAW, "dumps", "e%d.json" % e)
        if os.path.exists(p):
            DUMPS[e] = json.load(open(p))
        else:
            rc, out, err = sh(["sudo", "ceph", "osd", "dump", str(e), "-f", "json"])
            open(p, "w").write(out)
            DUMPS[e] = json.loads(out)
    return DUMPS[e]

def save_map(e):
    p = os.path.join(RAW, "maps", "e%d.bin" % e)
    if not os.path.exists(p):
        sh(["sudo", "ceph", "osd", "getmap", str(e), "-o", p])
        sh(["sudo", "chown", "%d:%d" % (os.getuid(), os.getgid()), p])
    dump(e)

def pool_by_name(d, name):
    for p in d["pools"]:
        if p["pool_name"] == name:
            return p
    return None

def pool_id(name):
    p = pool_by_name(dump(cur_epoch()), name)
    return p["pool"] if p else None

STATES = []
def mark(label, desc, find=None, since=None, pools=None, notes="", full=False, wait=45):
    """record the map state that holds the effect of the ops since the last mark.  `find(dump)` selects the first
    epoch after `since` whose dump satisfies it (the monitor may clean a pg_temp / upmap one epoch later);
    without it the current epoch is used.  pools: names whose PG tables are kept (None = all pools)."""
    cur = cur_epoch()
    ep = None
    if find is not None:
        lo = (since if since is not None else cur) + 1
        t_end = time.time() + wait
        while True:
            for e in range(lo, cur + 1):
                try:
                    if find(dump(e)):
                        ep = e; break
                except Exception as ex:
                    log("find error at e%d: %r" % (e, ex))
            if ep is not None or time.time() > t_end:
                break
            lo = max(lo, cur + 1); time.sleep(2); cur = cur_epoch()
        if ep is None:
            FAILS.append(label)
            log("!! state %s: predicate never true in epochs %d..%d; recording the current epoch %d" % (label, lo, cur, cur))
            notes = (notes + " " if notes else "") + "PREDICATE-NOT-MET: the monitor did not keep the requested state in any epoch"
            ep = cur
    else:
        ep = cur
    save_map(ep)
    STATES.append({"label": label, "epoch": ep, "desc": desc, "pools": pools, "notes": notes, "full": full, "ops": list(OPS)})
    del OPS[:]
    json.dump(STATES, open(os.path.join(RAW, "states.json"), "w"), indent=1)
    log("== state %s -> epoch %d" % (label, ep))
    return ep

def mark_range(prefix, desc, e_from, e_to, pools=None, maxn=14):
    es = list(range(e_from, e_to + 1))
    if len(es) > maxn:
        es = es[:maxn - 1] + [es[-1]]
    for e in es:
        save_map(e)
        STATES.append({"label": "%s-e%d" % (prefix, e), "epoch": e, "desc": desc, "pools": pools, "notes": "", "full": False, "ops": []})
    json.dump(STATES, open(os.path.join(RAW, "states.json"), "w"), indent=1)

def wait_clean(timeout=240, quiet=4):
    t0 = time.time(); last = None; since = time.time()
    while time.time() - t0 < timeout:
        s = cj("pg", "stat")["pg_summary"]
        # pools of size 4 on 3 OSDs and the one-host rule stay undersized (and keep a monitor-made pg_temp) for good:
        # "settled" means every PG is active and the epoch stopped moving
        ok = all(x["name"].startswith("active") for x in s["num_pg_by_state"]) and s["num_pgs"] > 0
        e = cur_epoch()
        if ok and e == last:
            if time.time() - since >= quiet:
                return e
        else:
            since = time.time()
        last = e if ok else None
        time.sleep(1.5)
    log("!! wait_clean timed out")
    return cur_epoch()

def wait_osds_up(n=3, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if cj("osd", "stat")["num_up_osds"] >= n:
            return True
        time.sleep(2)
    return False

PG_NUM_MASK = lambda n: (1 << (n - 1).bit_length()) - 1
def names_hitting(pool, pgseed, k, tag):
    """k object names hashing to PG `pgseed` of `pool` (a dump pool row)"""
    out = []; i = 0
    while len(out) < k and i < 100000:
        nm = ("wrmapb-%s-%d" % (tag, i)).encode()
        ps = oc.str_hash_rjenkins(nm)
        if oc.stable_mod(ps, pool["pg_num"], PG_NUM_MASK(pool["pg_num"])) == pgseed:
            out.append(nm.decode())
        i += 1
    return out

ANS = open(os.path.join(RAW, "answers.jsonl"), "a")
def answers(label, poolname, pgids, k=2):
    """`ceph osd map` for names that hash into the given PGs (online oracle for override states)"""
    d = dump(cur_epoch())
    p = pool_by_name(d, poolname)
    for pg in pgids:
        seed = int(pg.split(".")[1], 16)
        for nm in names_hitting(p, seed, k, "%s" % label):
            rc, out, err = sh(["sudo", "ceph", "osd", "map", poolname, nm, "-f", "json"], check=False)
            if rc != 0:
                log("osd map failed %s %s: %s" % (poolname, nm, err.strip()[:120])); continue
            r = json.loads(out)
            save_map(r["epoch"])
            ANS.write(json.dumps({"label": label, "pool": poolname, "obj_hex": nm.encode().hex(), "ns_hex": "", "reply": r}, sort_keys=True) + "\n")
    ANS.flush()

def up_of(pgid):
    r = cj("pg", "map", pgid)
    return r["up"]

# ---- the run -------------------------------------------------------------------------------------------
BASE = {}
def baseline():
    e = cur_epoch()
    d = dump(e)
    BASE["epoch"] = e
    BASE["require_min_compat_client"] = d["require_min_compat_client"]
    BASE["flags"] = d["flags"]
    BASE["osds"] = [(o["osd"], o["up"], o["in"], o["weight"], o["primary_affinity"]) for o in d["osds"]]
    BASE["pools"] = sorted((p["pool_name"] for p in d["pools"] if not p["pool_name"].startswith("wrtest-")))
    BASE["crush_version"] = d["crush_version"]
    for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp"):
        assert not [r for r in pgids(d, k) if int(r.split(".")[0]) in (1, 2)], "baseline has %s entries on .mgr / winrbd, refusing to run: %r" % (k, d[k])
    rc, out, err = cc("config", "get", "mon", "mon_allow_pool_delete", note=False)
    BASE["mon_allow_pool_delete"] = out.strip()
    rc, out, err = cc("config", "dump", "-f", "json", note=False)
    BASE["mon_allow_pool_delete_in_db"] = any(c.get("name") == "mon_allow_pool_delete" for c in json.loads(out))
    # the clean-up removes what this run sets (noup, a compat weight set, the mon_allow_pool_delete value): never run where the lab already has any of them,
    # or the clean-up would take away the lab's own setting
    assert "noup" not in d["flags"], "baseline has the noup flag set, refusing to run: the clean-up would unset it"
    assert not BASE["mon_allow_pool_delete_in_db"] and BASE["mon_allow_pool_delete"] == "false", \
        "baseline has mon_allow_pool_delete set (%s), refusing to run: the clean-up would remove it" % BASE["mon_allow_pool_delete"]
    rc, out, err = cc("osd", "crush", "weight-set", "ls", "-f", "json", note=False)
    assert "(compat)" not in json.loads(out or "[]"), "baseline has a compat weight set, refusing to run: the clean-up would remove it"
    sh(["sudo", "ceph", "osd", "getcrushmap", "-o", os.path.join(RAW, "crush", "before.bin")])
    sh(["sudo", "chown", "%d:%d" % (os.getuid(), os.getgid()), os.path.join(RAW, "crush", "before.bin")])
    json.dump(BASE, open(os.path.join(RAW, "baseline.json"), "w"), indent=1)
    log("baseline epoch %d, %r" % (e, BASE))

def test_pools():
    return [p["pool_name"] for p in dump(cur_epoch())["pools"] if p["pool_name"].startswith("wrtest-mb-")]

def cleanup(final=False):
    log("---- cleanup ----")
    d = dump_now()
    # tiers first
    for p in d["pools"]:
        if p["pool_name"].startswith("wrtest-mb-") and p.get("tier_of", -1) >= 0:
            base = [q["pool_name"] for q in d["pools"] if q["pool"] == p["tier_of"]][0]
            cc("osd", "tier", "remove-overlay", base, check=False)
            cc("osd", "tier", "remove", base, p["pool_name"], check=False)
    d = dump_now()
    # overrides on test pools
    test_ids = {p["pool"] for p in d["pools"] if p["pool_name"].startswith("wrtest-mb-")}
    for key, cmd in (("pg_upmap_items", "rm-pg-upmap-items"), ("pg_upmap", "rm-pg-upmap"), ("pg_upmap_primaries", "rm-pg-upmap-primary")):
        for pg in pgids(d, key):
            if int(pg.split(".")[0]) in test_ids:
                cc("osd", cmd, pg, check=False)
    # a primary_temp is never cleared by the OSDs and the monitor keeps it while the OSD is only "out": clear it first
    for pg in pgids(d, "primary_temp"):
        if int(pg.split(".")[0]) in test_ids:
            cc("osd", "rm-primary-temp", pg, check=False)
    for pg in pgids(d, "pg_temp"):
        if int(pg.split(".")[0]) in test_ids:
            cc("osd", "pg-temp", pg, check=False)
    cc("osd", "unset", "noup", check=False)
    for (o, up, inn, w, aff) in BASE["osds"]:
        cc("osd", "reweight", str(o), str(w), check=False)
        cc("osd", "primary-affinity", "osd.%d" % o, str(aff), check=False)
        if inn:
            cc("osd", "in", str(o), check=False)
    wait_osds_up(len(BASE["osds"]), 90)
    # weight sets
    for nm in [p["pool_name"] for p in d["pools"] if p["pool_name"].startswith("wrtest-mb-")]:
        cc("osd", "crush", "weight-set", "rm", nm, check=False)
    cc("osd", "crush", "weight-set", "rm-compat", check=False)
    # pools
    cc("config", "set", "mon", "mon_allow_pool_delete", "true", check=False)
    for nm in [p["pool_name"] for p in d["pools"] if p["pool_name"].startswith("wrtest-mb-")]:
        cc("osd", "pool", "delete", nm, nm, "--yes-i-really-really-mean-it", check=False)
    # crush rules / profiles made here
    rc, out, err = cc("osd", "crush", "rule", "ls", note=False, check=False)
    for r in out.split():
        if r.startswith("wrtest-mb-"):
            cc("osd", "crush", "rule", "rm", r, check=False)
    rc, out, err = cc("osd", "erasure-code-profile", "ls", note=False, check=False)
    for r in out.split():
        if r.startswith("wrtest-mb-"):
            cc("osd", "erasure-code-profile", "rm", r, check=False)
    if dump_now()["require_min_compat_client"] != BASE["require_min_compat_client"]:
        cc("osd", "set-require-min-compat-client", BASE["require_min_compat_client"], check=False)
    if final:
        # the lab keeps the built-in default (false); this script is the only one that sets the option
        cc("config", "rm", "mon", "mon_allow_pool_delete", check=False)

def dump_now():
    rc, out, err = sh(["sudo", "ceph", "osd", "dump", "-f", "json"])
    return json.loads(out)

def mkpool(name, pg, pgp=None, size=None, rule=None, kind="replicated", profile=None):
    a = ["osd", "pool", "create", name, str(pg)]
    a += [str(pgp if pgp is not None else pg)]
    a += [kind]
    if kind == "erasure":
        a += [profile]
    cc(*a)
    cc("osd", "pool", "set", name, "pg_autoscale_mode", "off")
    if rule:
        cc("osd", "pool", "set", name, "crush_rule", rule)
    if size:
        cc("osd", "pool", "set", name, "size", str(size))

def quiet_gate(maxwait=1500):
    """the lab is shared: wait until nobody else's test pools or OSD-wide changes are in the map"""
    t0 = time.time()
    while True:
        d = dump_now()
        foreign = [p["pool_name"] for p in d["pools"] if p["pool_name"].startswith("wrtest-") and not p["pool_name"].startswith("wrtest-mb-")]
        anom = [o["osd"] for o in d["osds"] if o["weight"] != 1 or o["primary_affinity"] != 1 or not o["up"] or not o["in"]]
        other = [k for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp") if d[k]]
        if not foreign and not anom and not other and "noup" not in d["flags"]:
            return
        log("lab busy (foreign pools %r, odd osds %r, overrides %r); waiting" % (foreign, anom, other))
        if time.time() - t0 > maxwait:
            log("!! lab still busy after %d s; continuing anyway" % maxwait); return
        time.sleep(20)

def run():
    quiet_gate()
    baseline()
    e_start = cur_epoch()
    # ---- housekeeping: allow deletes, remove leftovers of an earlier probe --------------------------------------
    cc("config", "set", "mon", "mon_allow_pool_delete", "true")
    left = test_pools()
    if left:
        e0 = cur_epoch()
        for nm in left:
            cc("osd", "pool", "delete", nm, nm, "--yes-i-really-really-mean-it")
        mark("s11a-pools-deleted-early", "S11: test pools deleted (old_pools in the incremental); pool ids are not reused (pool_max stays)",
             find=lambda d: not any(p["pool_name"].startswith("wrtest-mb-") for p in d["pools"]), since=e0, pools=["winrbd"])
        wait_clean()

    # ---- pools -------------------------------------------------------------------------------------------------
    e0 = cur_epoch(); mkpool("wrtest-mb-p16", 16, 16, size=3)
    mark("s11b-pool-created", "S11: a pool created (pg_num 16, size 3, power of two); new_pools in the incremental",
         find=lambda d: pool_by_name(d, "wrtest-mb-p16") is not None, since=e0, pools=["wrtest-mb-p16"], full=True)
    mkpool("wrtest-mb-p12", 12, 12, size=2)
    e0 = cur_epoch(); mkpool("wrtest-mb-p7", 7, 4, size=2)
    mark("s01a-p7-created", "S1/S2: pg_num 7, pgp_num 7 with pgp_num_target 4 (the first epoch of the pool)",
         find=lambda d: (pool_by_name(d, "wrtest-mb-p7") or {}).get("pg_num") == 7, since=e0 - 1, pools=["wrtest-mb-p7"])
    mark("s01b-p7-pgp4", "S1: pg_num 7, pgp_num 4 (not a power of two, pgp_num below pg_num)",
         find=lambda d: (pool_by_name(d, "wrtest-mb-p7") or {}).get("pg_placement_num") == 4, since=e0, pools=["wrtest-mb-p7"], full=True)
    e0 = cur_epoch(); mkpool("wrtest-mb-np", 12, 8, size=3)
    mark("s01c-np-pgp8", "S1: pg_num 12, pgp_num 8, size 3",
         find=lambda d: (pool_by_name(d, "wrtest-mb-np") or {}).get("pg_placement_num") == 8, since=e0, pools=["wrtest-mb-np"], full=True)
    e0 = cur_epoch(); mkpool("wrtest-mb-leg", 8, 8, size=2)
    cc("osd", "pool", "set", "wrtest-mb-leg", "hashpspool", "false", "--yes-i-really-mean-it")
    mark("s10-legacy-pool", "S10: a pool without the HASHPSPOOL flag (pps = ps + pool id)",
         find=lambda d: (pool_by_name(d, "wrtest-mb-leg") or {}).get("flags_names", "x").find("hashpspool") < 0 and pool_by_name(d, "wrtest-mb-leg") is not None, since=e0,
         pools=["wrtest-mb-leg"], full=True)
    mkpool("wrtest-mb-s4", 8, 8, size=4)
    e0 = cur_epoch()
    cc("osd", "crush", "rule", "create-replicated", "wrtest-mb-host", "default", "host")
    mark("s14a-crush-rule-added", "S14: a crush rule added through the monitor (crush field of the incremental, crush_version +1)",
         find=lambda d: d["crush_version"] > BASE["crush_version"], since=e0, pools=[])
    mkpool("wrtest-mb-host", 8, 8, size=3, rule="wrtest-mb-host")
    e_clean = wait_clean()
    mark("s00-base-pools", "all test pools present and every PG active, no override set by hand (the undersized pools keep monitor-made pg_temp entries): the epoch of the name oracle (names/)",
         pools=None, full=True)
    NAMES_EPOCH = STATES[-1]["epoch"]
    run_name_oracle(NAMES_EPOCH)

    P12 = pool_id("wrtest-mb-p12"); P16 = pool_id("wrtest-mb-p16"); NP = pool_id("wrtest-mb-np")
    PGW = lambda p, i: "%d.%x" % (p, i)

    # ---- S3 upmap items ---------------------------------------------------------------------------------------
    def three(pg):
        s = up_of(pg); other = [o for o in (0, 1, 2) if o not in s]
        return s, other
    pgs3 = [PGW(P12, 1), PGW(P12, 2), PGW(P12, 3), PGW(P12, 4)]
    s1, o1 = three(pgs3[0]); e0 = cur_epoch()
    cc("osd", "pg-upmap-items", pgs3[0], str(s1[0]), str(o1[0]))
    mark("s03a-upmap-items-one", "S3: pg_upmap_items with one pair on %s (up %s, %d -> %d)" % (pgs3[0], s1, s1[0], o1[0]),
         find=lambda d: any(r["pgid"] == pgs3[0] for r in d["pg_upmap_items"]), since=e0, pools=["wrtest-mb-p12"], full=True)
    answers("s03a", "wrtest-mb-p12", [pgs3[0]])
    s2, o2 = three(pgs3[1]); e0 = cur_epoch()
    rc, out, err = cc("osd", "pg-upmap-items", pgs3[1], str(s2[0]), str(o2[0]), str(s2[1]), str(s2[0]), check=False)
    mark("s03b-upmap-items-two", "S3: pg_upmap_items with two pairs on %s (up %s: %d -> %d, %d -> %d; the second pair uses the OSD the first one freed)" % (pgs3[1], s2, s2[0], o2[0], s2[1], s2[0]),
         find=lambda d: any(r["pgid"] == pgs3[1] and len(r["mappings"]) == 2 for r in d["pg_upmap_items"]), since=e0, pools=["wrtest-mb-p12"],
         notes="" if rc == 0 else "monitor refused the command: " + err.strip()[:100])
    answers("s03b", "wrtest-mb-p12", [pgs3[1]])
    s3, o3 = three(pgs3[2]); e0 = cur_epoch()
    cc("osd", "pg-upmap-items", pgs3[2], str(s3[0]), str(s3[1]), check=False)
    mark("s03c-upmap-items-invalid-to", "S3: an invalid pair, 'to' already in the up set (%s: %d -> %d); the monitor accepts it, the mapping must ignore it" % (pgs3[2], s3[0], s3[1]),
         find=lambda d: any(r["pgid"] == pgs3[2] for r in d["pg_upmap_items"]), since=e0, pools=["wrtest-mb-p12"])
    answers("s03c", "wrtest-mb-p12", [pgs3[2]])
    s4, o4 = three(pgs3[3]); e0 = cur_epoch()
    cc("osd", "pg-upmap-items", pgs3[3], str(o4[0]), str(s4[0]), check=False)
    mark("s03d-upmap-items-invalid-from", "S3: an invalid pair, 'from' not in the up set (%s up %s: %d -> %d)" % (pgs3[3], s4, o4[0], s4[0]),
         find=lambda d: any(r["pgid"] == pgs3[3] for r in d["pg_upmap_items"]), since=e0, pools=["wrtest-mb-p12"], wait=6,
         notes="the monitor accepts the command but cleans an invalid pair in the epoch that would have carried it, so normally no epoch holds it")
    answers("s03d", "wrtest-mb-p12", [pgs3[3]])
    e0 = cur_epoch()
    for pg in pgs3:
        cc("osd", "rm-pg-upmap-items", pg, check=False)
    mark("s03z-upmap-items-removed", "S3: the four pg_upmap_items removed again (old_pg_upmap_items)",
         find=lambda d: not d["pg_upmap_items"], since=e0, pools=["wrtest-mb-p12"])

    # ---- S4 pg_upmap -----------------------------------------------------------------------------------------
    pg5, pg6, pg7, pg8 = [PGW(P12, i) for i in (5, 6, 7, 8)]
    s, o = three(pg5); e0 = cur_epoch()
    cc("osd", "pg-upmap", pg5, str(s[1]), str(s[0]))
    mark("s04a-upmap-reorder", "S4: pg_upmap on %s that reorders the up set %s" % (pg5, s),
         find=lambda d: any(r["pgid"] == pg5 for r in d["pg_upmap"]), since=e0, pools=["wrtest-mb-p12"], full=True)
    answers("s04a", "wrtest-mb-p12", [pg5])
    s, o = three(pg6); e0 = cur_epoch()
    cc("osd", "pg-upmap", pg6, str(o[0]), str(s[0]))
    mark("s04b-upmap-replace", "S4: pg_upmap on %s with an OSD outside the CRUSH result %s" % (pg6, s),
         find=lambda d: any(r["pgid"] == pg6 for r in d["pg_upmap"]), since=e0, pools=["wrtest-mb-p12"])
    answers("s04b", "wrtest-mb-p12", [pg6])
    s, o = three(pg7); e0 = cur_epoch()
    cc("osd", "pg-upmap", pg7, str(s[0]), str(o[0]))
    victim = o[0]
    cc("osd", "reweight", str(victim), "0")
    mark("s04c-upmap-member-weight0", "S4: pg_upmap on %s that holds osd.%d, then osd.%d reweighted to 0 (a member with weight 0)" % (pg7, victim, victim),
         find=lambda d: any(r["pgid"] == pg7 for r in d["pg_upmap"]) and [x for x in d["osds"] if x["osd"] == victim][0]["weight"] == 0, since=e0, pools=["wrtest-mb-p12"],
         notes="the monitor cleans such an entry in the same or a later epoch if it considers it invalid")
    answers("s04c", "wrtest-mb-p12", [pg7])
    cc("osd", "reweight", str(victim), "1")
    e0 = cur_epoch()
    cc("osd", "reweight", str(victim), "0")
    rc, out, err = cc("osd", "pg-upmap", pg8, str(victim), str(up_of(pg8)[0]), check=False)
    mark("s04d-upmap-set-after-weight0", "S4: pg_upmap naming osd.%d, set while osd.%d already has weight 0 (rc %d)" % (victim, victim, rc),
         find=lambda d: any(r["pgid"] == pg8 for r in d["pg_upmap"]), since=e0, pools=["wrtest-mb-p12"],
         notes="" if rc == 0 else "monitor refused: " + err.strip()[:100])
    cc("osd", "reweight", str(victim), "1")
    e0 = cur_epoch()
    for pg in (pg5, pg6, pg7, pg8):
        cc("osd", "rm-pg-upmap", pg, check=False)
    mark("s04z-upmap-removed", "S4: pg_upmap entries removed, weights back to 1", find=lambda d: not d["pg_upmap"] and all(x["weight"] == 1 for x in d["osds"]), since=e0, pools=["wrtest-mb-p12"])

    # ---- S5 pg_upmap_primary ---------------------------------------------------------------------------------
    e0 = cur_epoch()
    cc("osd", "set-require-min-compat-client", "reef")
    mark("s05a-require-reef", "S5: require_min_compat_client raised to reef (needed for pg-upmap-primary); restored in s05z",
         find=lambda d: d["require_min_compat_client"] == "reef", since=e0, pools=[])
    pp1, pp2 = PGW(NP, 1), PGW(NP, 2)
    s = up_of(pp1); e0 = cur_epoch()
    cc("osd", "pg-upmap-primary", pp1, str(s[-1]))
    mark("s05b-upmap-primary-one", "S5: pg_upmap_primary on %s (up %s, primary %d)" % (pp1, s, s[-1]),
         find=lambda d: pp1 in pgids(d, "pg_upmap_primaries"), since=e0, pools=["wrtest-mb-np"], full=True)
    answers("s05b", "wrtest-mb-np", [pp1])
    s = up_of(pp2); e0 = cur_epoch()
    cc("osd", "pg-upmap-primary", pp2, str(s[1]))
    mark("s05c-upmap-primary-two", "S5: a second pg_upmap_primary on %s (up %s, primary %d)" % (pp2, s, s[1]),
         find=lambda d: len(pgids(d, "pg_upmap_primaries")) >= 2, since=e0, pools=["wrtest-mb-np"])
    answers("s05c", "wrtest-mb-np", [pp2])
    e0 = cur_epoch()
    cc("osd", "rm-pg-upmap-primary", pp1, check=False); cc("osd", "rm-pg-upmap-primary", pp2, check=False)
    cc("osd", "set-require-min-compat-client", BASE["require_min_compat_client"])
    mark("s05z-upmap-primary-removed", "S5: both entries removed and require_min_compat_client back to %s" % BASE["require_min_compat_client"],
         find=lambda d: not pgids(d, "pg_upmap_primaries") and d["require_min_compat_client"] == BASE["require_min_compat_client"], since=e0, pools=["wrtest-mb-np"])

    # ---- S6 pg_temp / primary_temp ---------------------------------------------------------------------------
    t1, t2, t3 = PGW(P12, 9), PGW(P12, 10), PGW(NP, 3)
    s = up_of(t1); e0 = cur_epoch()
    cc("osd", "pg-temp", t1, str(s[1]), str(s[0]))
    mark("s06a-pg-temp", "S6: pg_temp without primary_temp on %s (up %s, temp [%d, %d])" % (t1, s, s[1], s[0]),
         find=lambda d: any(r["pgid"] == t1 for r in d["pg_temp"]), since=e0, pools=["wrtest-mb-p12"], full=True)
    s = up_of(t2); e0 = cur_epoch()
    cc("osd", "primary-temp", t2, str(s[1]))
    mark("s06b-primary-temp", "S6: primary_temp without pg_temp on %s (up %s, primary_temp %d)" % (t2, s, s[1]),
         find=lambda d: t2 in pgids(d, "primary_temp"), since=e0, pools=["wrtest-mb-p12"])
    s = up_of(t3); e0 = cur_epoch()
    cc("osd", "primary-temp", t3, str(s[1]))     # primary_temp first: it stays, the pg_temp of the next command is what the OSDs clear quickly
    cc("osd", "pg-temp", t3, str(s[2]), str(s[0]), str(s[1]))
    mark("s06c-pg-temp-and-primary-temp", "S6: both on %s (up %s, temp [%d, %d, %d], primary_temp %d)" % (t3, s, s[2], s[0], s[1], s[1]),
         find=lambda d: t3 in pgids(d, "pg_temp") and t3 in pgids(d, "primary_temp"), since=e0, pools=["wrtest-mb-np"])
    e0 = cur_epoch()
    for pg in (t2, t3):
        cc("osd", "rm-primary-temp", pg)           # primary_temp entries stay until an admin clears them
    for pg in (t1, t3):
        cc("osd", "pg-temp", pg)                   # pg_temp is normally cleared by the OSDs; make sure
    mark("s06z-temps-cleared", "S6: pg_temp / primary_temp cleared again (an empty new_pg_temp entry and a primary_temp of -1 in the incremental)",
         find=lambda d: not any(x in pgids(d, "primary_temp") + pgids(d, "pg_temp") for x in (t1, t2, t3)), since=e0, pools=["wrtest-mb-p12", "wrtest-mb-np"])

    # ---- S7 primary affinity ---------------------------------------------------------------------------------
    for (lab, ops, dd) in (("s07a", [(0, "0")], "osd.0 affinity 0"), ("s07b", [(1, "0.25")], "osd.0 0, osd.1 0.25"), ("s07c", [(2, "0.5")], "osd.0 0, osd.1 0.25, osd.2 0.5")):
        e0 = cur_epoch()
        for o, v in ops:
            cc("osd", "primary-affinity", "osd.%d" % o, v)
        mark(lab + "-primary-affinity", "S7: primary affinity: " + dd, since=e0, find=lambda d: True, full=(lab == "s07c"))
    e0 = cur_epoch()
    for o in (0, 1, 2):
        cc("osd", "primary-affinity", "osd.%d" % o, "1")
    mark("s07z-affinity-restored", "S7: affinity back to 1 on all OSDs", find=lambda d: all(x["primary_affinity"] == 1 for x in d["osds"]), since=e0)

    # ---- S8 reweight / out / in ------------------------------------------------------------------------------
    for (lab, v) in (("s08a", "0.5"), ("s08b", "0.1"), ("s08c", "0")):
        e0 = cur_epoch(); cc("osd", "reweight", "0", v)
        mark(lab + "-reweight-" + v.replace(".", "p"), "S8: osd.0 reweight %s" % v,
             find=lambda d, v=v: abs([x for x in d["osds"] if x["osd"] == 0][0]["weight"] - float(v)) < 0.001, since=e0, full=(lab == "s08b"))
    e0 = cur_epoch(); cc("osd", "reweight", "0", "1")
    mark("s08d-reweight-restored", "S8: osd.0 reweight back to 1", find=lambda d: [x for x in d["osds"] if x["osd"] == 0][0]["weight"] == 1, since=e0)
    e0 = cur_epoch(); cc("osd", "out", "1")
    mark("s08e-osd-out", "S8: osd.1 marked out (weight 0, still up)", find=lambda d: [x for x in d["osds"] if x["osd"] == 1][0]["in"] == 0, since=e0, full=True)
    e0 = cur_epoch(); cc("osd", "in", "1")
    mark("s08f-osd-in", "S8: osd.1 marked in again", find=lambda d: [x for x in d["osds"] if x["osd"] == 1][0]["in"] == 1, since=e0)
    wait_clean(90)

    # ---- S9 down but not out ---------------------------------------------------------------------------------
    e0 = cur_epoch()
    cc("osd", "set", "noup")
    cc("osd", "down", "2")
    mark("s09a-osd-down-noup", "S9: noup set and osd.2 marked down (still in)",
         find=lambda d: [x for x in d["osds"] if x["osd"] == 2][0]["up"] == 0, since=e0, full=True)
    e0 = cur_epoch(); cc("osd", "unset", "noup")
    wait_osds_up(3, 120)
    mark("s09b-osd-up-again", "S9: noup cleared, osd.2 up again (new up_from)", pools=None)
    wait_clean(150)

    # ---- S2 split in progress, S15 merge in progress ---------------------------------------------------------
    mkpool("wrtest-mb-sp", 12, 12, size=2); wait_clean(120)
    e0 = cur_epoch(); cc("osd", "pool", "set", "wrtest-mb-sp", "pg_num", "14")
    wait_clean(120); e1 = cur_epoch()
    mark_range("s02-split", "S2: wrtest-mb-sp pg_num 12 -> 14 (pgp_num follows), every epoch", e0 + 1, e1, pools=["wrtest-mb-sp"])
    mkpool("wrtest-mb-mg", 16, 16, size=2); wait_clean(120)
    e0 = cur_epoch(); cc("osd", "pool", "set", "wrtest-mb-mg", "pg_num", "8")
    wait_clean(180); e1 = cur_epoch()
    mark_range("s15-merge", "S15: wrtest-mb-mg pg_num 16 -> 8 (merge, pg_num_pending), every epoch", e0 + 1, e1, pools=["wrtest-mb-mg"])

    # ---- S11 rename / delete ---------------------------------------------------------------------------------
    e0 = cur_epoch(); mkpool("wrtest-mb-del", 4, 4, size=2)
    mark("s11c-pool-created-small", "S11: wrtest-mb-del created", find=lambda d: pool_by_name(d, "wrtest-mb-del") is not None, since=e0, pools=["wrtest-mb-del"])
    e0 = cur_epoch(); cc("osd", "pool", "rename", "wrtest-mb-del", "wrtest-mb-ren")
    mark("s11d-pool-renamed", "S11: the pool renamed to wrtest-mb-ren (new_pool_names)", find=lambda d: pool_by_name(d, "wrtest-mb-ren") is not None, since=e0, pools=["wrtest-mb-ren"], full=True)
    wait_clean(60)
    e0 = cur_epoch(); cc("osd", "pool", "delete", "wrtest-mb-ren", "wrtest-mb-ren", "--yes-i-really-really-mean-it")
    mark("s11e-pool-deleted", "S11: the pool deleted (old_pools)", find=lambda d: pool_by_name(d, "wrtest-mb-ren") is None, since=e0, pools=["wrtest-mb-p12"], full=True)

    # ---- S12 erasure pool, cache tier ------------------------------------------------------------------------
    e0 = cur_epoch(); cc("osd", "erasure-code-profile", "set", "wrtest-mb-ec21", "k=2", "m=1", "crush-failure-domain=osd")
    mark("s12a-ec-profile", "S12: an erasure-code profile (k=2, m=1) in erasure_code_profiles", find=lambda d: "wrtest-mb-ec21" in d["erasure_code_profiles"], since=e0, pools=[])
    e0 = cur_epoch(); mkpool("wrtest-mb-ec", 4, 4, kind="erasure", profile="wrtest-mb-ec21")
    mark("s12b-ec-pool", "S12: an erasure pool (type 3, size 3, indep rule created by the monitor)", find=lambda d: pool_by_name(d, "wrtest-mb-ec") is not None, since=e0, pools=["wrtest-mb-ec"], full=True)
    wait_clean(90)
    mkpool("wrtest-mb-base", 4, 4, size=2); mkpool("wrtest-mb-cache", 4, 4, size=2); wait_clean(90)
    e0 = cur_epoch(); cc("osd", "tier", "add", "wrtest-mb-base", "wrtest-mb-cache")
    mark("s12c-tier-added", "S12: wrtest-mb-cache added as a tier of wrtest-mb-base (tiers / tier_of)", find=lambda d: (pool_by_name(d, "wrtest-mb-cache") or {}).get("tier_of", -1) >= 0, since=e0, pools=["wrtest-mb-base", "wrtest-mb-cache"], full=True)
    cc("osd", "pool", "set", "wrtest-mb-cache", "hit_set_type", "bloom"); cc("osd", "pool", "set", "wrtest-mb-cache", "hit_set_count", "1"); cc("osd", "pool", "set", "wrtest-mb-cache", "hit_set_period", "3600")
    e0 = cur_epoch(); cc("osd", "tier", "cache-mode", "wrtest-mb-cache", "writeback", "--yes-i-really-mean-it")
    mark("s12d-cache-writeback", "S12: cache_mode writeback", find=lambda d: (pool_by_name(d, "wrtest-mb-cache") or {}).get("cache_mode") == "writeback", since=e0, pools=["wrtest-mb-base", "wrtest-mb-cache"])
    e0 = cur_epoch(); cc("osd", "tier", "set-overlay", "wrtest-mb-base", "wrtest-mb-cache")
    mark("s12e-tier-overlay", "S12: overlay set (read_tier / write_tier on the base pool)", find=lambda d: (pool_by_name(d, "wrtest-mb-base") or {}).get("read_tier", -1) >= 0, since=e0, pools=["wrtest-mb-base", "wrtest-mb-cache"], full=True)
    wait_clean(60)
    e0 = cur_epoch(); cc("osd", "tier", "remove-overlay", "wrtest-mb-base"); cc("osd", "tier", "remove", "wrtest-mb-base", "wrtest-mb-cache")
    mark("s12z-tier-removed", "S12: overlay and tier removed", find=lambda d: (pool_by_name(d, "wrtest-mb-cache") or {}).get("tier_of", 0) < 0 and (pool_by_name(d, "wrtest-mb-base") or {}).get("read_tier", 0) < 0, since=e0, pools=["wrtest-mb-base", "wrtest-mb-cache"])

    # ---- S13 choose_args on a test pool ----------------------------------------------------------------------
    mkpool("wrtest-mb-ws", 16, 16, size=2); wait_clean(120)
    WS = pool_id("wrtest-mb-ws")
    e0 = cur_epoch(); cc("osd", "crush", "weight-set", "create", "wrtest-mb-ws", "positional")
    mark("s13a-weight-set-created", "S13: a positional weight set for wrtest-mb-ws (choose_args key = pool id %d), values equal to the crush weights" % WS,
         find=lambda d: d["crush_version"] > BASE["crush_version"], since=e0, pools=["wrtest-mb-ws"], full=True)
    answers("s13a", "wrtest-mb-ws", [PGW(WS, i) for i in range(0, 16, 5)])
    e0 = cur_epoch()
    for o, w in ((0, ("0.002", "0.05")), (1, ("0.05", "0.002")), (2, ("0.02", "0.02"))):
        cc("osd", "crush", "weight-set", "reweight", "wrtest-mb-ws", "osd.%d" % o, *w)
    mark("s13b-weight-set-changed", "S13: positional weights changed: osd.0 [0.002, 0.05], osd.1 [0.05, 0.002], osd.2 [0.02, 0.02]", since=e0, pools=["wrtest-mb-ws"], full=True)
    answers("s13b", "wrtest-mb-ws", [PGW(WS, i) for i in range(16)], k=2)
    e0 = cur_epoch(); cc("osd", "crush", "weight-set", "create-compat")
    mark("s13c-compat-set-created", "S13: a compat weight set (choose_args key -1; values equal to the crush weights, so no pool moves)",
         find=lambda d: d["crush_version"] > BASE["crush_version"], since=e0, pools=["wrtest-mb-ws", "winrbd"])
    cc("osd", "crush", "weight-set", "rm-compat"); cc("osd", "crush", "weight-set", "rm", "wrtest-mb-ws")
    mark("s13z-weight-sets-removed", "S13: both removed again", pools=["wrtest-mb-ws"])

    # ---- restore ---------------------------------------------------------------------------------------------
    cleanup(final=True)
    e_end = wait_clean(240)
    mark("s99-restored", "the cluster after the clean-up (only .mgr and winrbd, no overrides)", pools=None, full=True)
    verify_restore()

def verify_restore():
    d = dump_now(); res = {"ok": True, "problems": []}
    def bad(m): res["ok"] = False; res["problems"].append(m)
    if sorted(p["pool_name"] for p in d["pools"] if not p["pool_name"].startswith("wrtest-")) != BASE["pools"]: bad("pools differ: %r vs %r" % ([p["pool_name"] for p in d["pools"]], BASE["pools"]))
    if [p["pool_name"] for p in d["pools"] if p["pool_name"].startswith("wrtest-mb-")]: bad("own pools left")
    if [(o["osd"], o["up"], o["in"], o["weight"], o["primary_affinity"]) for o in d["osds"]] != [tuple(x) for x in BASE["osds"]]: bad("osd rows differ")
    if d["require_min_compat_client"] != BASE["require_min_compat_client"]: bad("require_min_compat_client")
    if d["flags"] != BASE["flags"]: bad("flags %s != %s" % (d["flags"], BASE["flags"]))
    for k in ("pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp"):
        if [r for r in pgids(d, k) if int(r.split(".")[0]) in (1, 2)]: bad("%s not empty on .mgr / winrbd" % k)
    rc, out, err = cc("config", "get", "mon", "mon_allow_pool_delete", note=False)
    if out.strip() != BASE["mon_allow_pool_delete"]: bad("mon_allow_pool_delete is %s, was %s" % (out.strip(), BASE["mon_allow_pool_delete"]))
    rc, out, err = cc("config", "dump", "-f", "json", note=False)
    if any(c.get("name") == "mon_allow_pool_delete" for c in json.loads(out)) != BASE["mon_allow_pool_delete_in_db"]: bad("mon_allow_pool_delete is stored in the config database now")
    rc, out, err = cc("osd", "crush", "weight-set", "ls", "-f", "json", note=False)
    if json.loads(out or "[]"): bad("weight sets left: %s" % out.strip()[:100])
    sh(["sudo", "ceph", "osd", "getcrushmap", "-o", os.path.join(RAW, "crush", "after.bin")])
    sh(["sudo", "chown", "%d:%d" % (os.getuid(), os.getgid()), os.path.join(RAW, "crush", "after.bin")])
    res["epoch_end"] = d["epoch"]; res["crush_version"] = d["crush_version"]; res["crush_version_before"] = BASE["crush_version"]
    json.dump(res, open(os.path.join(RAW, "restore.json"), "w"), indent=1)
    log("restore check: %r" % res)

# ---- the big name oracle --------------------------------------------------------------------------------------
def make_names():
    rnd = random.Random(20261116)
    al = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    names = []
    for L in list(range(0, 26)) + [31, 32, 33, 36, 37, 47, 48, 49, 63, 64, 65, 100, 127, 128, 129, 254, 255]:
        names.append("".join(rnd.choice(al) for _ in range(L)))
    names += ["rbd_directory", "rbd_info", "rbd_children", "rbd_trash", "rbd_mirroring", "rbd_id.img-v1", "rbd_header.37841afbd1d7", "rbd_object_map.37841afbd1d7"]
    names += ["rbd_data.37841afbd1d7.%016x" % i for i in range(60)]
    names += ["rbd_data.37863d7ada59.%016x" % (i * 977) for i in range(40)]
    names += ["pg_%d" % i for i in range(30)]
    uni = ["\u00e9", "ma\u00f1ana", "\u00dcn\u00efc\u00f6d\u00e9", "\u65e5\u672c\u8a9e", "\u540d\u524d", "\ud55c\uad6d\uc5b4", "\U0001F600", "a\U0001F600b", "\U0001D4B3\U0001D4B4\U0001D4B5",
           "\u00e9" * 10, "\u00e9" * 127, "\uffff", "\ud7ff", "\ue000", "\u0080", "\u07ff", "\u0800", "x\u00ff", "\u20ac" * 5, "\u20ac" * 85,
           "\U0001F600" * 3, "\U0001F600" * 21, "\U0010FFFF", "\U00010000", "caf\u00e9-\u2603-\U0001F680"]
    names += uni
    names += ["/", "//a", "a/b/c", " ", "  lead", "trail  ", "\t", "a\nb", "\x01\x02\x03", "\x7f", ".", "..", "_", "-", "%", "\"", "\\", "a\"b'c", "{}", "[]", "\u2028",
              "z" * 1000, "ab" * 2048]
    # random mixed strings (ASCII, 2-byte, 3-byte and 4-byte characters)
    alpha = list(al) + [chr(c) for c in (0xe0, 0xe9, 0xf1, 0x3b1, 0x416, 0x4e2d, 0x65e5, 0xac00, 0x20ac, 0x1F600, 0x1F680, 0x1D4B3)]
    for _ in range(190):
        names.append("".join(rnd.choice(alpha) for _ in range(rnd.randint(1, 40))))
    seen = set(); out = []
    for n in names:
        if n not in seen:
            seen.add(n); out.append(n)
    return out

def run_name_oracle(epoch):
    pools = ["winrbd", "wrtest-mb-p16", "wrtest-mb-p12", "wrtest-mb-p7", "wrtest-mb-np", "wrtest-mb-leg", "wrtest-mb-s4", "wrtest-mb-host"]
    nslist = ["ns1", "a-longer-namespace", "\u00fcn\u00ef", "\u540d\u524d\u7a7a\u9593", "x" * 40, "\U0001F600ns"]
    master = make_names()
    items = []
    for pi, pool in enumerate(pools):
        for i, n in enumerate(master):
            ns = nslist[(i + pi * 5) % len(nslist)] if (i * 7 + pi) % 6 == 0 else None
            items.append({"pool": pool, "obj": n, "ns": ns})
    json.dump(items, open(os.path.join(WORK, "names_in.json"), "w"))
    open(os.path.join(WORK, "names_oracle.py"), "w").write(ORACLE_PY)
    for attempt in range(3):
        if os.path.exists(os.path.join(WORK, "names_out.jsonl")): os.remove(os.path.join(WORK, "names_out.jsonl"))
        e_before = wait_clean(120, 4)
        sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % WORK, "--", "python3", "/work/names_oracle.py", "/work/names_in.json", "/work/names_out.jsonl"], timeout=3000)
        sh(["sudo", "chown", "-R", "%d:%d" % (os.getuid(), os.getgid()), WORK])
        eps = collections.Counter()
        for line in open(os.path.join(WORK, "names_out.jsonl")):
            r = json.loads(line)
            if r["rc"] == 0: eps[r["reply"]["epoch"]] += 1
        log("name oracle epochs: %r (base epoch %d)" % (dict(eps), epoch))
        if len(eps) == 1:
            break
    for e in eps:
        save_map(e)
    shutil.copy(os.path.join(WORK, "names_out.jsonl"), os.path.join(RAW, "names", "names_out.jsonl"))
    json.dump({"epoch_state": epoch, "epochs": {str(k): v for k, v in eps.items()}, "pools": pools}, open(os.path.join(RAW, "names", "meta.json"), "w"))

ORACLE_PY = r'''
import json, sys, rados
items = json.load(open(sys.argv[1])); out = open(sys.argv[2], "w")
c = rados.Rados(conffile="/etc/ceph/ceph.conf")
c.connect()
for it in items:
    cmd = {"prefix": "osd map", "pool": it["pool"], "object": it["obj"], "format": "json"}
    if it["ns"] is not None: cmd["nspace"] = it["ns"]
    rc, outb, outs = c.mon_command(json.dumps(cmd), b"")
    rec = {"pool": it["pool"], "obj": it["obj"], "ns": it["ns"], "rc": rc}
    if rc == 0: rec["reply"] = json.loads(outb)
    else: rec["err"] = outs
    out.write(json.dumps(rec, ensure_ascii=True, sort_keys=True) + "\n")
out.close(); c.shutdown()
'''

if __name__ == "__main__":
    if os.environ.get("MAPB_ONLY_CLEANUP"):
        BASE.update(json.load(open(os.path.join(RAW, "baseline.json"))))
        cleanup(final=True); sys.exit(0)
    try:
        run()
    except BaseException:
        log("!!! FAILED: " + traceback.format_exc())
        try:
            cleanup(final=True)
        finally:
            sys.exit(1)
    log("capture done: %d states, %d failed predicates: %r" % (len(STATES), len(FAILS), FAILS))
PYEOF

# ---------------------------------------------------------------------------------------------------------
# lab export: monitor store -> incrementals and full maps; per-state osdmaptool tables (runs on the lab VM)
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_EXPORT <<'PYEOF' || true
import subprocess, random
RAW = os.environ["MAPB_RAW"]; WORK = safe_work(os.environ["MAPB_WORK"])
ME = "%d:%d" % (os.getuid(), os.getgid())
def sh(cmd, check=True):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode: raise RuntimeError("%s: %s" % (cmd, p.stdout.decode()[-400:]))
    return p.stdout.decode()
states = json.load(open(os.path.join(RAW, "states.json")))
base = json.load(open(os.path.join(RAW, "baseline.json")))
BASE_EPOCH = base["epoch"]       # the lab map right before the capture; the monitor trims epochs older than mon_min_osdmap_epochs (500)
maps = sorted(int(f[1:-4]) for f in os.listdir(os.path.join(RAW, "maps")) if f.endswith(".bin"))
last = int(sh(["sudo", "ceph", "osd", "stat", "-f", "json"]).split('"epoch":')[1].split(",")[0])
# 1. a copy of the monitor store (a plain copy of a live RocksDB is read-only used below)
shutil_rm = ["sudo", "rm", "-rf", os.path.join(WORK, "store")]
sh(shutil_rm); os.makedirs(os.path.join(WORK, "store"))
sh(["sudo", "bash", "-c", "cp -a /var/lib/ceph/*/mon.*/store.db %s/store/" % WORK])
# 2. per-map object names: PGs with overrides get names that hash into them
def pool_rows(d): return {p["pool"]: p for p in d["pools"]}
for e in maps:
    d = json.load(open(os.path.join(RAW, "dumps", "e%d.json" % e)))
    pools = pool_rows(d)
    want = collections.OrderedDict()
    for key in ("pg_upmap_items", "pg_upmap", "pg_upmap_primaries", "pg_temp", "primary_temp"):
        for pg in pgids(d, key):
            pid, ps = pg.split("."); want[(int(pid), int(ps, 16))] = 1
    lines = []
    rnd = random.Random(e)
    for pid, p in sorted(pools.items()):
        n = p["pg_num"]; mask = (1 << (n - 1).bit_length()) - 1
        seeds = [ps for (q, ps) in want if q == pid] + [rnd.randrange(n) for _ in range(2)]
        for si, seed in enumerate(seeds):
            k = 0; i = 0
            while k < 2 and i < 20000:
                nm = "wrmapb-o%d-%d-%d" % (e, si, i); i += 1
                if oc.stable_mod(oc.str_hash_rjenkins(nm.encode()), n, mask) == seed:
                    lines.append("%d %s" % (pid, nm)); k += 1
    open(os.path.join(RAW, "objs_in", "e%d.txt" % e), "w").write("\n".join(lines) + "\n")
open(os.path.join(WORK, "export_range"), "w").write("%d %d\n" % (BASE_EPOCH, last))
SCRIPT = r'''
set -u
cd /work/raw
read FROM TO < /work/export_range
for f in maps/e*.bin; do b=$(basename $f .bin); osdmaptool $f --test-map-pgs-dump-all > pgs/$b.txt 2> pgs/$b.err || echo "pgs failed $b"; done
for f in objs_in/e*.txt; do b=$(basename $f .txt); : > objs/$b.txt
  while read -r pool name; do osdmaptool maps/$b.bin --test-map-object "$name" --pool $pool 2>&1 | grep "^ object" | sed "s/^/$pool /" >> objs/$b.txt; done < $f
done
for e in $(seq $FROM $TO); do
  ceph-kvstore-tool rocksdb /work/store/store.db get osdmap $e out inc/$e.bin >/dev/null 2>&1 || echo "no inc $e"
  ceph-kvstore-tool rocksdb /work/store/store.db get osdmap full_$e out full/$e.bin >/dev/null 2>&1 || echo "no full $e"
done
crushtool -d crush/before.bin -o crush/before.txt; crushtool -d crush/after.bin -o crush/after.txt
echo EXPORT-DONE
'''
open(os.path.join(WORK, "export.sh"), "w").write(SCRIPT)
try:
    out = sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % WORK, "--", "bash", "/work/export.sh"])
    print(out[-1500:])
finally:
    # the store copy holds the cluster's keys (the monitor's auth database): it is only needed by the line above, remove it whatever happened
    sh(["sudo", "rm", "-rf", os.path.join(WORK, "store")], check=False)
sh(["sudo", "chown", "-R", ME, WORK])
print("exported incrementals / full maps for epochs %d..%d, %d state maps" % (BASE_EPOCH, last, len(maps)))
PYEOF

# ---------------------------------------------------------------------------------------------------------
# offline CRUSH maps (S13, S14) and OSDMaps built with crushtool / osdmaptool (runs on the lab VM, nothing is
# sent to the cluster)
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_OFFLINE <<'PYEOF' || true
import subprocess
RAW = os.environ["MAPB_RAW"]; WORK = os.environ["MAPB_WORK"]
OFF = os.path.join(RAW, "offline"); os.makedirs(OFF, exist_ok=True)
ME = "%d:%d" % (os.getuid(), os.getgid())
def sh(cmd, check=True):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if check and p.returncode: raise RuntimeError("%s: %s" % (cmd, p.stdout.decode()[-600:]))
    return p.stdout.decode()
def container(script_name, text):
    open(os.path.join(WORK, script_name), "w").write(text)
    out = sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % WORK, "--", "bash", "/work/" + script_name])
    sh(["sudo", "chown", "-R", ME, WORK])
    return out

TUN = {
 "jewel":    [("choose_local_tries", 0), ("choose_local_fallback_tries", 0), ("choose_total_tries", 50), ("chooseleaf_descend_once", 1), ("chooseleaf_vary_r", 1), ("chooseleaf_stable", 1), ("straw_calc_version", 1), ("allowed_bucket_algs", 54)],
    "hammer":   [("choose_local_tries", 0), ("choose_local_fallback_tries", 0), ("choose_total_tries", 50), ("chooseleaf_descend_once", 1), ("chooseleaf_vary_r", 1), ("chooseleaf_stable", 0), ("straw_calc_version", 1), ("allowed_bucket_algs", 54)],
    "firefly":  [("choose_local_tries", 0), ("choose_local_fallback_tries", 0), ("choose_total_tries", 50), ("chooseleaf_descend_once", 1), ("chooseleaf_vary_r", 1), ("chooseleaf_stable", 0), ("straw_calc_version", 0), ("allowed_bucket_algs", 22)],
    "bobtail":  [("choose_local_tries", 0), ("choose_local_fallback_tries", 0), ("choose_total_tries", 50), ("chooseleaf_descend_once", 1), ("chooseleaf_vary_r", 0), ("chooseleaf_stable", 0), ("straw_calc_version", 0), ("allowed_bucket_algs", 22)],
    "argonaut": [("choose_local_tries", 2), ("choose_local_fallback_tries", 5), ("choose_total_tries", 19), ("chooseleaf_descend_once", 0), ("chooseleaf_vary_r", 0), ("chooseleaf_stable", 0), ("straw_calc_version", 0), ("allowed_bucket_algs", 22)],
}
NH, PER, NR = 6, 4, 2   # hosts, osds per host, racks (3 hosts each)

def fw(x): return "%.5f" % x

def rules_std(root="root"):
    return """
# rules
rule r0_host {
	id 0
	type replicated
	step take %(r)s
	step chooseleaf firstn 0 type host
	step emit
}
rule r1_rack {
	id 1
	type replicated
	step take %(r)s
	step chooseleaf firstn 0 type rack
	step emit
}
rule r2_flat {
	id 2
	type replicated
	step take %(r)s
	step choose firstn 0 type osd
	step emit
}
rule r3_two_steps {
	id 3
	type replicated
	step take %(r)s
	step choose firstn 2 type rack
	step chooseleaf firstn 2 type host
	step emit
}
rule r4_indep_host {
	id 4
	type erasure
	step set_chooseleaf_tries 5
	step set_choose_tries 100
	step take %(r)s
	step chooseleaf indep 0 type host
	step emit
}
rule r5_indep_flat {
	id 5
	type erasure
	step take %(r)s
	step choose indep 0 type osd
	step emit
}
rule r6_take_rack {
	id 6
	type replicated
	step take rack0
	step chooseleaf firstn 0 type host
	step emit
}
rule r7_two_emits {
	id 7
	type replicated
	step take rack0
	step chooseleaf firstn 1 type host
	step emit
	step take rack1
	step chooseleaf firstn 2 type host
	step emit
}

# end crush map
""" % {"r": root}

def crush_text(host_alg, rack_alg, root_alg, tun, weights=None, classes=None, rules=None, root_name="root", cargs=""):
    w = weights or [1.0] * (NH * PER)
    L = ["# begin crush map"]
    for k, v in TUN[tun]: L.append("tunable %s %d" % (k, v))
    L += ["", "# devices"]
    for i in range(NH * PER):
        L.append("device %d osd.%d%s" % (i, i, (" class " + classes[i]) if classes else ""))
    L += ["", "# types", "type 0 osd", "type 1 host", "type 2 rack", "type 3 root", "", "# buckets"]
    hw = []
    for h in range(NH):
        items = ["\titem osd.%d weight %s" % (o, fw(w[o])) for o in range(h * PER, (h + 1) * PER)]
        hw.append(sum(w[h * PER:(h + 1) * PER]))
        L += ["host host%d {" % h, "\tid %d" % (-(h + 1)), "\t# weight %s" % fw(hw[-1]), "\talg %s" % host_alg, "\thash 0\t# rjenkins1"] + items + ["}"]
    rw = []
    for r in range(NR):
        hs = range(r * 3, r * 3 + 3); rw.append(sum(hw[h] for h in hs))
        L += ["rack rack%d {" % r, "\tid %d" % (-(NH + 1 + r)), "\t# weight %s" % fw(rw[-1]), "\talg %s" % rack_alg, "\thash 0\t# rjenkins1"] + ["\titem host%d weight %s" % (h, fw(hw[h])) for h in hs] + ["}"]
    L += ["root %s {" % root_name, "\tid %d" % (-(NH + NR + 1)), "\t# weight %s" % fw(sum(rw)), "\talg %s" % root_alg, "\thash 0\t# rjenkins1"] + ["\titem rack%d weight %s" % (r, fw(rw[r])) for r in range(NR)] + ["}"]
    return "\n".join(L) + "\n" + (rules if rules is not None else rules_std(root_name)) + cargs

def cargs_text(sets):
    """sets: {key: kind} with kind 'pos' (3 positions + ids) | 'flat' | 'zero' ; per bucket of the std layout"""
    out = []
    for key, kind in sets:
        out.append("\nchoose_args %d {" % key)
        for bid, items in [(-(h + 1), PER) for h in range(NH)] + [(-(NH + 1 + r), 3) for r in range(NR)] + [(-(NH + NR + 1), NR)]:
            pos = 3 if kind == "pos" else 1
            rows = []
            for p in range(pos):
                vals = []
                for i in range(items):
                    base = 1.0 if bid > -(NH + 1) else (4.0 if bid > -(NH + NR + 1) else 12.0)
                    f = [1.0, 0.5, 2.0, 0.25, 1.5][(abs(bid) + i + p + (key % 3)) % 5]
                    if kind == "zero" and i == 1: f = 0.0
                    vals.append(fw(base * f))
                rows.append("\t\t\t[ %s ]" % " ".join(vals))
            out.append("\t{\n\t\tbucket_id %d\n\t\tweight_set [\n%s\n\t\t]" % (bid, "\n".join(rows)))
            if kind == "pos":
                out.append("\t\tids [ %s ]" % " ".join(str(-3000 - abs(bid) * 10 - i) for i in range(items)))
            out.append("\t}")
        out.append("}")
    return "\n".join(out) + "\n"

STD_RUNS = [("r0n3", 0, 3), ("r1n2", 1, 2), ("r1n3", 1, 3), ("r2n3", 2, 3), ("r2n5", 2, 5), ("r3n4", 3, 4), ("r4n4", 4, 4), ("r4n6", 4, 6), ("r5n4", 5, 4), ("r6n3", 6, 3), ("r7n3", 7, 3)]
SML_RUNS = [("r0n3", 0, 3), ("r1n3", 1, 3), ("r2n3", 2, 3), ("r4n4", 4, 4), ("r7n3", 7, 3)]
def runs_of(lst, x1=63, extra=None):
    out = [{"name": n, "rule": r, "num_rep": k, "args": []} for (n, r, k) in lst]
    return out + (extra or [])
def wargs(d): return [a for dev, w in sorted(d.items()) for a in ("--weight", str(dev), str(w))]
OUT_A = dict([(d, 0) for d in range(0, 12)] + [(14, 0), (17, 0), (20, 0)])
OUT_B = dict([(d, 0.5) for d in range(0, 24, 2)] + [(1, 0), (2, 0), (9, 0), (10, 0), (21, 0)])
WOUT = [{"name": "outA-r0n3", "rule": 0, "num_rep": 3, "args": wargs(OUT_A), "weights": OUT_A},
        {"name": "outA-r2n5", "rule": 2, "num_rep": 5, "args": wargs(OUT_A), "weights": OUT_A},
        {"name": "outA-r4n4", "rule": 4, "num_rep": 4, "args": wargs(OUT_A), "weights": OUT_A},
        {"name": "outB-r0n3", "rule": 0, "num_rep": 3, "args": wargs(OUT_B), "weights": OUT_B},
        {"name": "outB-r5n4", "rule": 5, "num_rep": 4, "args": wargs(OUT_B), "weights": OUT_B}]
UNEQ = [1.0, 2.0, 0.5, 1.5, 3.0, 0.25, 1.0, 1.0, 0.75, 2.5, 1.0, 0.1] * 2

MAPS = collections.OrderedDict()   # name -> {"desc", "build": cmd or None, "text": str, "runs": [...]}
# cm01..cm04: made with crushtool --build (algorithm mixes); rules are replaced by the standard rule set
BUILDS = [("cm01-host-straw-rack-list-root-uniform", "host straw 4 rack list 3 root uniform 0", "jewel"),
          ("cm02-host-tree-rack-tree-root-straw2", "host tree 4 rack tree 3 root straw2 0", "jewel"),
          ("cm03-host-list-rack-straw-root-tree", "host list 4 rack straw 3 root tree 0", "jewel"),
          ("cm04-host-uniform-rack-straw2-root-list", "host uniform 4 rack straw2 3 root list 0", "jewel")]
for nm, lay, tun in BUILDS:
    MAPS[nm] = {"desc": "crushtool --build --num_osds 24 %s (6 hosts of 4 OSDs, 2 racks of 3 hosts); the standard rule set r0..r7 replaces the rule --build makes" % lay, "build": lay, "text": None,
                "runs": runs_of(STD_RUNS if nm.startswith("cm01") else SML_RUNS, extra=WOUT if nm.startswith("cm01") else None)}
MAPS["cm05-all-straw2-unequal"] = {"desc": "straw2 at every level, unequal OSD weights (0.1 to 3.0)", "build": None, "runs": runs_of(STD_RUNS),
                                   "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ)}
MAPS["cm06-all-straw-unequal-calc1"] = {"desc": "straw at every level, unequal weights, straw_calc_version 1", "build": None, "runs": runs_of(SML_RUNS),
                                        "text": crush_text("straw", "straw", "straw", "jewel", weights=UNEQ)}
MAPS["cm07-all-straw-unequal-calc0"] = {"desc": "the same buckets with straw_calc_version 0 (the original, wrong-for-changed-weights straw lengths)", "build": None, "runs": runs_of(SML_RUNS),
                                        "text": crush_text("straw", "straw", "straw", "bobtail", weights=UNEQ)}
MAPS["cm08-argonaut-uniform-list-tree"] = {"desc": "argonaut tunables (local tries 2, local fallback tries 5, total tries 19, descend_once 0, vary_r 0, stable 0, straw_calc 0): uniform hosts, list racks, tree root; permutation fallback + local retries",
                                           "build": None, "runs": runs_of(STD_RUNS, extra=WOUT), "text": crush_text("uniform", "list", "tree", "argonaut")}
MAPS["cm09-bobtail-list-straw-tree"] = {"desc": "bobtail tunables (descend_once 1, vary_r 0, stable 0), list hosts, straw racks, tree root, unequal weights", "build": None, "runs": runs_of(SML_RUNS, extra=WOUT[:3]),
                                        "text": crush_text("list", "straw", "tree", "bobtail", weights=UNEQ)}
MAPS["cm10-firefly-tree-tree-straw2"] = {"desc": "firefly tunables (vary_r 1, stable 0), tree hosts and racks, straw2 root", "build": None, "runs": runs_of(SML_RUNS),
                                         "text": crush_text("tree", "tree", "straw2", "firefly", weights=UNEQ)}
MAPS["cm11-hammer-straw2"] = {"desc": "hammer tunables (vary_r 1, stable 0), straw2 everywhere, unequal weights", "build": None, "runs": runs_of(SML_RUNS, extra=WOUT[:2]),
                              "text": crush_text("straw2", "straw2", "straw2", "hammer", weights=UNEQ)}
MAPS["cm12-argonaut-fallback-stress"] = {"desc": "argonaut tunables with straw hosts, uniform racks, list root, unequal weights: with many devices out the retry, local-retry and fallback paths run constantly",
                                         "build": None, "runs": runs_of(SML_RUNS, extra=WOUT), "text": crush_text("straw", "uniform", "list", "argonaut")}
CLS = ["ssd" if i % 4 == 0 else ("nvme" if i % 7 == 3 else "hdd") for i in range(24)]
RULES_CLS = """
# rules
rule r0_all {
	id 0
	type replicated
	step take default
	step chooseleaf firstn 0 type host
	step emit
}
rule r1_hdd {
	id 1
	type replicated
	step take default class hdd
	step chooseleaf firstn 0 type host
	step emit
}
rule r2_ssd {
	id 2
	type replicated
	step take default class ssd
	step chooseleaf firstn 0 type host
	step emit
}
rule r3_nvme_flat {
	id 3
	type replicated
	step take default class nvme
	step choose firstn 0 type osd
	step emit
}
rule r4_hdd_rack_indep {
	id 4
	type erasure
	step take default class hdd
	step chooseleaf indep 0 type rack
	step emit
}
rule r5_ssd_two_steps {
	id 5
	type replicated
	step take default class ssd
	step choose firstn 2 type rack
	step chooseleaf firstn 2 type host
	step emit
}

# end crush map
"""
MAPS["cm13-device-classes"] = {"desc": "device classes (ssd on OSD 0,4,8,...; nvme where i%7==3; the rest hdd): rules over the shadow roots default~hdd, default~ssd, default~nvme", "build": None,
                               "runs": runs_of([("r0n3", 0, 3), ("r1n3", 1, 3), ("r2n2", 2, 2), ("r3n3", 3, 3), ("r4n3", 4, 3), ("r5n4", 5, 4)]),
                               "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ, classes=CLS, rules=RULES_CLS, root_name="default")}
MAPS["cm13b-device-classes-hdd-rule0"] = {"desc": "the same map with the hdd rule as rule 0 (the pool of osdmap om05 uses it)", "build": None, "runs": runs_of([("r0n3", 0, 3), ("r0n2", 0, 2)]),
                                          "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ, classes=CLS,
                                                             rules=RULES_CLS.replace("rule r0_all {\n\tid 0", "rule r0_all {\n\tid 9").replace("rule r1_hdd {\n\tid 1", "rule r1_hdd {\n\tid 0").replace("rule r0_all {\n\tid 9", "rule r0_all {\n\tid 1"),
                                                             root_name="default")}
def cruns(pools):
    out = [{"name": "r0n3", "rule": 0, "num_rep": 3, "args": []}, {"name": "r2n3", "rule": 2, "num_rep": 3, "args": []}, {"name": "r4n4", "rule": 4, "num_rep": 4, "args": []}]
    for p in pools:
        out += [{"name": "pool%d-%s" % (p, n), "rule": r, "num_rep": k, "args": ["--pool-id", str(p)], "pool_id": p} for (n, r, k) in [("r0n3", 0, 3), ("r2n3", 2, 3)]]
    return out
CA_NOTE = " (crushtool --test always asks for choose_args key 0 and falls back to the compat key -1; --pool-id only changes the hash of x)"
MAPS["cm14a-choose-args-key0-positional"] = {"desc": "choose_args key 0: a positional weight set (3 positions) with replaced ids, straw2 everywhere; the only set crushtool --test can select by itself" + CA_NOTE, "build": None,
                                             "runs": cruns([1, 7]), "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ, cargs=cargs_text([(0, "pos")]))}
MAPS["cm14b-choose-args-key0-flat"] = {"desc": "choose_args key 0: a flat weight set (one position, no ids)" + CA_NOTE, "build": None, "runs": cruns([7]),
                                       "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ, cargs=cargs_text([(0, "flat")]))}
MAPS["cm14c-choose-args-pool1-and-compat"] = {"desc": "choose_args keys 1 (positional, ids) and -1 (compat, flat): for crushtool only the compat set can apply (key 0 absent); an OSDMap pool with id 1 uses key 1, every other pool the compat set" + CA_NOTE, "build": None,
                                              "runs": cruns([1, 7]), "text": crush_text("straw2", "straw2", "straw2", "jewel", weights=UNEQ, cargs=cargs_text([(1, "pos"), (3, "flat")]))}
MAPS["cm15-choose-args-zero"] = {"desc": "choose_args with only the compat set (key -1) holding a zero weight for one item of every bucket" + CA_NOTE, "build": None, "runs": cruns([1]),
                                 "text": crush_text("straw2", "straw2", "straw2", "jewel", cargs=cargs_text([(3, "zero")]))}

# OSDMaps: (name, crush map, pg-bits, size, patch) -- the pool is pool 1 'rbd', rule 0
OMS = [("om01-straw-list-uniform", "cm01-host-straw-rack-list-root-uniform", 1, 3, {}),
       ("om02-argonaut-uniform-list-tree", "cm08-argonaut-uniform-list-tree", 0, 3, {}),
       ("om03-straw-unequal-calc1", "cm06-all-straw-unequal-calc1", 2, 3, {}),
       ("om04-straw2-unequal-out-down", "cm05-all-straw2-unequal", 1, 3, {"out": [2, 3, 17], "down": [5], "reweight": {7: 0x8000, 11: 0x2000}}),
       ("om05-classes-hdd-rule", "cm13b-device-classes-hdd-rule0", 0, 3, {}),
       ("om06-choose-args-pool1", "cm14c-choose-args-pool1-and-compat", 1, 3, {}),
       ("om07-choose-args-compat", "cm15-choose-args-zero", 1, 3, {}),
       ("om08-choose-args-key0-not-special", "cm14a-choose-args-key0-positional", 1, 3, {})]
# the pool of om05 / om06 / om07 must use the rule named below as rule 0; for om05 that is the hdd rule, made by swapping ids in the text
def with_rule0(text, name):
    return text

def locate_vectors(buf):
    r = oc.Reader(buf); wrap = oc.Env(r, 8, legacy_at=7); cb = oc.Env(r, 10)
    r.raw(16); r.u32(); r.utime(); r.utime()
    oc.dec_map(r, lambda x: x.s64(), oc.dec_pool); oc.dec_map(r, lambda x: x.s64(), lambda x: x.string())
    r.s32(); r.u32(); mx = r.s32()
    st = r.p; n = r.u32(); r.raw(4 * n)
    wt = r.p; n2 = r.u32()
    return mx, st + 4, wt + 4, n, n2

def patch_map(buf, out=(), down=(), reweight=None):
    mx, st, wt, n, n2 = locate_vectors(buf)
    assert n == mx == n2, (n, mx, n2)
    b = bytearray(buf)
    for i in range(mx):
        struct.pack_into("<I", b, st + 4 * i, 1 if i in down else 3)
        struct.pack_into("<I", b, wt + 4 * i, 0 if i in out else (reweight or {}).get(i, 0x10000))
    b[12:28] = PLACEHOLDER_FSID            # the fsid osdmaptool wrote (all zero) -> the public placeholder
    return oc.refresh_full_crc(bytes(b))

# ---- step 1: compile / build / test the CRUSH maps -------------------------------------------------------
def gen_build_text(name, lay):
    return None
S1 = ["set -u", "cd /work/raw/offline"]
for nm, m in MAPS.items():
    if m["build"]:
        S1.append("crushtool --build --num_osds 24 %s -o %s.build.bin >/dev/null 2>&1 && crushtool -d %s.build.bin -o %s.build.txt || echo BUILD-FAILED %s" % (m["build"], nm, nm, nm, nm))
open(os.path.join(WORK, "off1.sh"), "w").write("\n".join(S1) + "\n")
container("off1.sh", "\n".join(S1) + "\n")
for nm, m in MAPS.items():
    if m["build"]:
        t = open(os.path.join(OFF, nm + ".build.txt")).read()
        head = t.split("# rules")[0]
        # the --build text has the default tunables; keep them and only swap the rule set
        m["text"] = head.rstrip("\n") + "\n" + rules_std("root")
    open(os.path.join(OFF, nm + ".txt"), "w").write(m["text"])
S2a = ["set -u", "cd /work/raw/offline"]
for nm, m in MAPS.items():
    S2a.append("crushtool -c %s.txt -o %s.bin || echo COMPILE-FAILED %s" % (nm, nm, nm))
print(container("off2a.sh", "\n".join(S2a) + "\necho OFF2A-DONE\n")[-500:])

def put_crush_key(blob, old, new):
    """the text grammar cannot spell the compat key -1: compile it as `old`, then rename the key in the binary and re-sort"""
    cm = oc.dec_crush(blob)
    ca = cm["choose_args"]
    ser = struct.pack("<I", len(ca))
    sec_len = 4
    def one(key, args):
        b = struct.pack("<qI", key, len(args))
        for bi, a in args.items():
            b += struct.pack("<II", bi, len(a["weight_set"]))
            for row in a["weight_set"]:
                b += struct.pack("<I", len(row)) + b"".join(struct.pack("<I", v) for v in row)
            b += struct.pack("<I", len(a["ids"])) + b"".join(struct.pack("<i", v) for v in a["ids"])
        return b
    total = 4 + sum(len(one(k, a)) for k, a in ca.items())
    msr = 8 if cm["tail_present"].get("msr") else 0
    start = len(blob) - total - msr
    assert blob[start:start + 4] == struct.pack("<I", len(ca)), "choose_args section not located"
    new_ca = {(new if k == old else k): a for k, a in ca.items()}
    sec = struct.pack("<I", len(new_ca)) + b"".join(one(k, new_ca[k]) for k in sorted(new_ca))
    return blob[:start] + sec + blob[len(blob) - msr:]
for nm in ("cm14c-choose-args-pool1-and-compat", "cm15-choose-args-zero"):
    fp = os.path.join(OFF, nm + ".bin")
    nb = put_crush_key(open(fp, "rb").read(), 3, -1)
    open(fp, "wb").write(nb)
    assert oc.dec_crush(nb)["choose_args"].keys() >= {-1}

S2 = ["set -u", "cd /work/raw/offline"]
for nm, m in MAPS.items():
    S2.append("crushtool -d %s.bin -o %s.dec.txt" % (nm, nm))
    for r in m["runs"]:
        S2.append("crushtool -i %s.bin --test --show-mappings --rule %d --num-rep %d --min-x 0 --max-x 47 %s > run.%s.%s.txt 2>run.%s.%s.err || echo TEST-FAILED %s %s" % (nm, r["rule"], r["num_rep"], " ".join(r["args"]), nm, r["name"], nm, r["name"], nm, r["name"]))
# ---- step 2: osdmaps ---
for (on, cm, bits, size, patch) in OMS:
    S2.append("osdmaptool --createsimple 24 --clobber --with-default-pool --pg-bits %d --osd_pool_default_size %d %s.raw.bin >/dev/null 2>&1" % (bits, size, on))
    S2.append("osdmaptool %s.raw.bin --import-crush %s.bin >/dev/null 2>&1" % (on, cm))
    S2.append("osdmaptool %s.raw.bin --mark-up-in --test-map-pgs-dump-all > %s.allupin.txt 2>&1" % (on, on))
print(container("off2.sh", "\n".join(S2) + "\necho OFF2-DONE\n")[-800:])
# patch: all up and in (+ the out / down / reweight of the case), CRC recomputed
S3 = ["set -u", "cd /work/raw/offline"]
for (on, cm, bits, size, patch) in OMS:
    raw = open(os.path.join(OFF, on + ".raw.bin"), "rb").read()
    allup = patch_map(raw)
    open(os.path.join(OFF, on + ".allup.bin"), "wb").write(allup)
    full = patch_map(raw, out=patch.get("out", ()), down=patch.get("down", ()), reweight=patch.get("reweight"))
    open(os.path.join(OFF, on + ".bin"), "wb").write(full)
    S3.append("osdmaptool %s.allup.bin --test-map-pgs-dump-all > %s.allup.txt 2>&1" % (on, on))
    S3.append("osdmaptool %s.bin --test-map-pgs-dump-all > %s.pgs.txt 2>&1" % (on, on))
    S3.append("ceph-dencoder type OSDMap import %s.bin decode dump_json > %s.dencoder.json 2>%s.dencoder.err || echo DENCODER-FAILED %s" % (on, on, on, on))
print(container("off3.sh", "\n".join(S3) + "\necho OFF3-DONE\n")[-600:])
json.dump({"maps": {k: {"desc": v["desc"], "build": v["build"], "runs": v["runs"]} for k, v in MAPS.items()},
           "osdmaps": [{"name": a, "crush": b, "pg_bits": c, "size": d, "patch": {k: (list(v) if isinstance(v, (list, tuple)) else {str(i): j for i, j in v.items()}) for k, v in e.items()}} for (a, b, c, d, e) in OMS]},
          open(os.path.join(OFF, "plan.json"), "w"), indent=1)
print("offline done")
PYEOF

# ---------------------------------------------------------------------------------------------------------
# build: raw captures -> scrubbed vectors under harness/vectors/public/mapb/
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_BUILD <<'PYEOF' || true
import shutil, subprocess, tempfile, glob
RAW = os.environ["MAPB_RAW"]; OUT = os.environ["MAPB_OUT"]
def rj(*p): return json.load(open(os.path.join(RAW, *p)))
def rb(*p): return open(os.path.join(RAW, *p), "rb").read()
def rt(*p): return open(os.path.join(RAW, *p)).read()
files = {}      # relpath -> bytes (written at the end)
def put(rel, data):
    if isinstance(data, str): data = data.encode()
    files[rel] = data
def hexfile(rel, b, comment):
    put(rel, "# SPDX-License-Identifier: MIT\n# " + comment + "\n" + wrap_hex(b) + "\n")

states_raw = rj("states.json")
baseline = rj("baseline.json"); restore = rj("restore.json")
BASE_EPOCH = baseline["epoch"]
last_epoch = max(int(f[:-4]) for f in os.listdir(os.path.join(RAW, "full")) if f.endswith(".bin") and os.path.getsize(os.path.join(RAW, "full", f)) > 0)
dumps = {}
def dump(e):
    if e not in dumps: dumps[e] = rj("dumps", "e%d.json" % e)
    return dumps[e]

# ---- scrub -----------------------------------------------------------------------------------------------
d0 = dump(states_raw[-1]["epoch"])
FSID = d0["fsid"]
repl = [(uuid_bytes(FSID), PLACEHOLDER_FSID)]
UUIDS = {}
for o in d0["osds"]:
    repl.append((uuid_bytes(o["uuid"]), bytes([0xA0 + o["osd"]]) * 16)); UUIDS[o["osd"]] = o["uuid"]
def scrub_bytes(b):
    for old, new in repl: b = b.replace(old, new)
    return b
def scrub_text(t):
    t = t.replace(FSID, "00112233-4455-6677-8899-aabbccddeeff")
    for o, u in UUIDS.items():
        t = t.replace(u, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % ((0xA0 + o,) * 16))
    return t

FULL = {}; INC = {}
for e in range(BASE_EPOCH, last_epoch + 1):
    f = oc.refresh_full_crc(scrub_bytes(rb("full", "%d.bin" % e)))
    m = oc.dec_osdmap(f)
    assert m["crc_ok"] and m["epoch"] == e and m["fsid"] == PLACEHOLDER_FSID, e
    FULL[e] = f
    if e > BASE_EPOCH:
        i = oc.refresh_inc_crc(scrub_bytes(rb("inc", "%d.bin" % e)), m["crc"])
        di = oc.dec_incremental(i)
        assert di["inc_crc_ok"] and di["full_crc"] == m["crc"] and di["epoch"] == e and di["fsid"] == PLACEHOLDER_FSID, e
        INC[e] = i
same = 0
for f in os.listdir(os.path.join(RAW, "maps")):
    if f.endswith(".bin"):
        e = int(f[1:-4])
        assert rb("maps", f) == rb("full", "%d.bin" % e), "ceph osd getmap %d differs from the monitor store" % e
        same += 1
print("`ceph osd getmap` == the monitor store's full map for all %d saved epochs" % same)
print("scrubbed %d full maps and %d incrementals (epochs %d..%d)" % (len(FULL), len(INC), BASE_EPOCH, last_epoch))

# ---- the chain: applying the incrementals to the base reproduces every stored map ---------------------------
m = oc.dec_osdmap(FULL[BASE_EPOCH])
for e in range(BASE_EPOCH + 1, last_epoch + 1):
    m = oc.apply_incremental_checked(m, oc.dec_incremental(INC[e]))
    errs = same_state(m, oc.dec_osdmap(FULL[e]), "e%d" % e)
    assert not errs, errs[:3]
print("chain check: base + incrementals == stored full map at every epoch")

BASE_FILE = "base-e%d.hex" % BASE_EPOCH
hexfile(BASE_FILE, FULL[BASE_EPOCH], "OSDMap at epoch %d of the lab cluster, taken right before the capture (pools .mgr and winrbd, 3 OSDs up and in, no overrides): the base of incrementals.hex. fsid and OSD uuids replaced, crc recomputed." % BASE_EPOCH)
put("incrementals.hex", "# SPDX-License-Identifier: MIT\n# one `OSDMap::Incremental` per line, `<epoch> <hex>`, epochs %d to %d, applied in order to %s. fsid and OSD uuids replaced, inc_crc and full_crc recomputed.\n" % (BASE_EPOCH + 1, last_epoch, BASE_FILE)
    + "".join("%d %s\n" % (e, INC[e].hex()) for e in sorted(INC)))

# ---- states -----------------------------------------------------------------------------------------------
POOL_KEEP = ["pool", "pool_name", "flags", "flags_names", "type", "size", "min_size", "crush_rule", "object_hash", "pg_num", "pg_placement_num",
             "pg_num_target", "pg_placement_num_target", "pg_num_pending", "last_change", "tiers", "tier_of", "read_tier", "write_tier", "cache_mode",
             "erasure_code_profile", "stripe_width"]
def prune(d):
    o = {k: d[k] for k in ("epoch", "flags", "crush_version", "pool_max", "max_osd", "require_min_compat_client", "min_compat_client", "require_osd_release",
                           "pg_upmap", "pg_upmap_items", "pg_upmap_primaries", "pg_temp", "primary_temp", "erasure_code_profiles") if k in d}
    o["pools"] = [{k: p[k] for k in POOL_KEEP if k in p} for p in d["pools"]]
    o["osds"] = [{k: x[k] for k in ("osd", "up", "in", "weight", "primary_affinity", "up_from", "up_thru", "down_at") if k in x} for x in d["osds"]]
    return json.loads(scrub_text(json.dumps(o)))
PGRE = re.compile(r"^(\d+)\.([0-9a-f]+) raw \(\[([^\]]*)\], p(-?\d+)\) up \(\[([^\]]*)\], p(-?\d+)\) acting \(\[([^\]]*)\], p(-?\d+)\)")
OBRE = re.compile(r"^(\d+)\s+object '(.*)' -> (\d+)\.([0-9a-f]+) -> \[([^\]]*)\]")
def ints(s): return [int(x) for x in s.split(",")] if s.strip() else []
def pg_table(e):
    t = {}
    for line in rt("pgs", "e%d.txt" % e).splitlines():
        mm = PGRE.match(line)
        if mm:
            t[(int(mm.group(1)), mm.group(2))] = [ints(mm.group(3)), ints(mm.group(5)), int(mm.group(6)), ints(mm.group(7)), int(mm.group(8))]
    return t
def obj_table(e):
    out = []
    p = os.path.join(RAW, "objs", "e%d.txt" % e)
    if os.path.exists(p):
        for line in open(p):
            mm = OBRE.match(line.strip())
            if mm: out.append([int(mm.group(1)), mm.group(2).encode().hex(), "%s.%s" % (mm.group(3), mm.group(4)), ints(mm.group(5))])
    return out
KEEP_FULL = set()
idx_states = []; seen_labels = set()
for st in states_raw:
    if st["label"] in seen_labels: continue
    seen_labels.add(st["label"])
    e = st["epoch"]; d = dump(e)
    byname = {p["pool_name"]: p["pool"] for p in d["pools"]}
    keep = None if st["pools"] is None else [byname[n] for n in st["pools"] if n in byname]
    tab = pg_table(e)
    pgs = {"%d.%s" % k: v for k, v in sorted(tab.items()) if keep is None or k[0] in keep}
    for k, v in pgs.items():
        pid = int(k.split(".")[0]); pool = [p for p in d["pools"] if p["pool"] == pid][0]
        assert len([1 for kk in tab if kk[0] == pid]) == pool["pg_num"], (st["label"], pid)
    rec = {"label": st["label"], "epoch": e, "description": st["desc"], "notes": st["notes"], "full_map": None,
           "ops": [{"cmd": o["cmd"], "rc": o["rc"], "msg": scrub_text(o["msg"])} for o in st["ops"]],
           "pools_in_tables": keep, "dump": prune(d), "pgs": pgs, "objects": [x for x in obj_table(e) if keep is None or x[0] in keep]}
    rec["pg_columns"] = "[raw, up, up_primary, acting, acting_primary] as printed by `osdmaptool --test-map-pgs-dump-all` over `ceph osd getmap <epoch>`"
    if st["full"]:
        rec["full_map"] = "maps/e%d.hex" % e; KEEP_FULL.add(e)
    put("states/%s.json" % st["label"], cdump(rec) + "\n")
    idx_states.append({"label": st["label"], "epoch": e, "file": "states/%s.json" % st["label"], "full_map": rec["full_map"], "description": st["desc"], "notes": st["notes"]})
KEEP_FULL.add(BASE_EPOCH)
for e in sorted(KEEP_FULL):
    if e != BASE_EPOCH:
        hexfile("maps/e%d.hex" % e, FULL[e], "OSDMap at epoch %d (`ceph osd getmap %d`), fsid and OSD uuids replaced, crc recomputed." % (e, e))

# ---- the name oracle -------------------------------------------------------------------------------------
meta = rj("names", "meta.json"); (NE,) = [int(k) for k in meta["epochs"]]
nd = dump(NE); pools = {p["pool_name"]: p for p in nd["pools"]}
def cands(s):
    if s is None: return [b""]
    out = [s.encode("utf-8")]
    ce = oc.cesu8(s)
    if ce not in out: out.append(ce)
    return out
rows = []; bad = []
for line in rt("names", "names_out.jsonl").splitlines():
    r = json.loads(line)
    if r["rc"] != 0: bad.append((r["pool"], r["obj"], r.get("err"))); continue
    rep = r["reply"]; pool = pools[r["pool"]]; want_ps = int(rep["raw_pgid"].split(".")[1], 16)
    found = None
    for ob in cands(r["obj"]):
        for nb in cands(r["ns"]):
            if oc.object_ps(pool, ob, nb) == want_ps: found = (ob, nb); break
        if found: break
    if not found: bad.append((r["pool"], r["obj"], "hash mismatch")); continue
    ob, nb = found
    pg = rep["pgid"].split(".")[1]
    assert int(pg, 16) == oc.stable_mod(want_ps, pool["pg_num"], (1 << (pool["pg_num"] - 1).bit_length()) - 1), (r["pool"], r["obj"])
    rows.append([rep["pool_id"], ob.hex(), nb.hex(), want_ps, rep["pgid"], rep["up"], rep["up_primary"], rep["acting"], rep["acting_primary"]])
assert not bad, bad[:5]
npools = {str(p["pool"]): {"name": p["pool_name"], "pg_num": p["pg_num"], "pgp_num": p["pg_placement_num"], "size": p["size"], "crush_rule": p["crush_rule"],
                           "hashpspool": "hashpspool" in p["flags_names"], "object_hash": p["object_hash"]} for p in nd["pools"] if p["pool_name"] in meta["pools"]}
put("names/names-e%d.json" % NE, cdump({
    "comment": "[pool_id, object_bytes_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary]; oracle = `ceph osd map -f json` on the lab cluster at epoch %d (every answer carries that epoch). "
               "The bytes are what the monitor hashed: characters above U+FFFF are two 3-byte surrogates (CESU-8), the namespace is hashed as ns + 0x1f + name. The map of that epoch is states/s00-base-pools.json's full_map (or base + incrementals)." % NE,
    "epoch": NE, "pools": npools, "entries": rows}) + "\n")
print("names: %d rows over %d pools" % (len(rows), len(npools)))

# ---- targeted online answers (ceph osd map for the names that hit an override) ---------------------------
arows = []
for line in open(os.path.join(RAW, "answers.jsonl")):
    a = json.loads(line); rep = a["reply"]
    arows.append([a["label"], rep["epoch"], rep["pool_id"], a["obj_hex"], a["ns_hex"], int(rep["raw_pgid"].split(".")[1], 16), rep["pgid"], rep["up"], rep["up_primary"], rep["acting"], rep["acting_primary"]])
put("answers.json", cdump({"comment": "[label, epoch, pool_id, object_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary]: `ceph osd map -f json` run right after an override was set; the epoch is the one in the answer (build the map by applying incrementals.hex to the base map up to it)",
                           "entries": arows}) + "\n")

# ---- offline CRUSH maps -----------------------------------------------------------------------------------
OFF = os.path.join(RAW, "offline")
plan = json.load(open(os.path.join(OFF, "plan.json")))
LINE = re.compile(r"^CRUSH rule (\d+) x (\d+) \[([^\]]*)\]")
idx_crush = []
for nm, mp in plan["maps"].items():
    blob = open(os.path.join(OFF, nm + ".bin"), "rb").read()
    cm = oc.dec_crush(blob)
    hexfile("crush/%s.crush.hex" % nm, blob, "CRUSH map %s (compiled by crushtool -c%s): %s" % (nm, " from `crushtool --build` output" if mp["build"] else "", mp["desc"]))
    put("crush/%s.txt" % nm, rt("offline", nm + ".dec.txt"))
    runs = {}
    for r in mp["runs"]:
        xs = []
        for line in rt("offline", "run.%s.%s.txt" % (nm, r["name"])).splitlines():
            mm = LINE.match(line)
            if mm:
                assert int(mm.group(2)) == len(xs), (nm, r["name"])
                xs.append(ints(mm.group(3)))
        assert len(xs) == 48, (nm, r["name"], len(xs))
        run = {"rule": r["rule"], "num_rep": r["num_rep"], "min_x": 0, "x_to_result": xs}
        if "pool_id" in r: run["pool_id"] = r["pool_id"]
        if r.get("weights"): run["weights"] = {str(k): v for k, v in r["weights"].items()}
        runs[r["name"]] = run
    put("crush/%s.mappings.json" % nm, cdump({"map": nm, "description": mp["desc"], "crushtool": "crushtool -i <map> --test --show-mappings --rule R --num-rep N --min-x 0 --max-x 47 [--pool-id P] [--weight DEV W ...]; "
                                                "with --pool-id the tool maps x through hash2(x, pool_id) first; `weights` are the --weight overrides (0..1)",
                                               "runs": runs}) + "\n")
    idx_crush.append({"name": nm, "crush": "crush/%s.crush.hex" % nm, "text": "crush/%s.txt" % nm, "mappings": "crush/%s.mappings.json" % nm,
                      "algs": sorted({{1: "uniform", 2: "list", 3: "tree", 4: "straw", 5: "straw2"}[b["alg"]] for b in cm["buckets"] if b}),
                      "choose_args_keys": sorted(cm["choose_args"]), "device_classes": len(cm["class_name"]), "tunables": cm["tunables"], "rules": len([x for x in cm["rules"] if x]),
                      "description": mp["desc"]})
# ---- offline OSDMaps --------------------------------------------------------------------------------------
idx_om = []
for om in plan["osdmaps"]:
    nm = om["name"]
    full = rb("offline", nm + ".bin")
    mo = oc.dec_osdmap(full); assert mo["crc_ok"] and mo["fsid"] == PLACEHOLDER_FSID
    tab = {}
    for line in rt("offline", nm + ".pgs.txt").splitlines():
        mm = PGRE.match(line)
        if mm: tab["%s.%s" % (mm.group(1), mm.group(2))] = [ints(mm.group(3)), ints(mm.group(5)), int(mm.group(6)), ints(mm.group(7)), int(mm.group(8))]
    # the all-up patch must equal osdmaptool --mark-up-in on the untouched map
    def tbl(t): return [PGRE.match(l).groups() for l in t.splitlines() if PGRE.match(l)]
    assert tbl(rt("offline", nm + ".allup.txt")) == tbl(rt("offline", nm + ".allupin.txt")), nm
    assert oc.crush_struct(oc.dec_crush(mo["crush"])) == oc.crush_struct(oc.dec_crush(open(os.path.join(OFF, om["crush"] + ".bin"), "rb").read())), "%s: the imported crush map is not %s" % (nm, om["crush"])
    dj = json.load(open(os.path.join(OFF, nm + ".dencoder.json")))
    hexfile("offline/%s.osdmap.hex" % nm, full, "offline OSDMap %s: `osdmaptool --createsimple 24 --pg-bits %d --osd_pool_default_size %d`, crush map %s imported, OSDs set up and in%s; fsid placeholder, crc recomputed" %
            (nm, om["pg_bits"], om["size"], om["crush"], (", then patched: " + json.dumps(om["patch"], sort_keys=True)) if om["patch"] else ""))
    put("offline/%s.pgs.json" % nm, cdump({"osdmap": nm, "crush": om["crush"], "patch": om["patch"], "pg_num": dj["pools"][0]["pg_num"], "pool_size": dj["pools"][0]["size"],
                                           "columns": "[raw, up, up_primary, acting, acting_primary] from `osdmaptool <map> --test-map-pgs-dump-all`", "pgs": tab}) + "\n")
    idx_om.append({"name": nm, "osdmap": "offline/%s.osdmap.hex" % nm, "pgs": "offline/%s.pgs.json" % nm, "crush": om["crush"], "pg_num": dj["pools"][0]["pg_num"], "patch": om["patch"]})

# ---- crush maps in the monitor's own history -------------------------------------------------------------
# (before / after the whole run: identical content, so the restore is visible in the vectors)
put("crush/lab-before.txt", rt("crush", "before.txt")); put("crush/lab-after.txt", rt("crush", "after.txt"))

# ---- provenance and index -------------------------------------------------------------------------------
ops_total = sum(len(st["ops"]) for st in states_raw)
oplog = [l for l in rt("ops.log").splitlines()]
idx = {"format": 1, "ceph": "v20.2.5 (ed27c686770872022f4c1de04f6b0ac5d5384ded)", "base_epoch": BASE_EPOCH, "base_map": BASE_FILE, "last_epoch": last_epoch, "names_epoch": NE,
       "scrub": {"fsid": "00112233-4455-6677-8899-aabbccddeeff", "osd_uuids": "16 bytes of 0xA0 + osd id", "crc": "recomputed (full map crc, incremental inc_crc and full_crc)"},
       "states": idx_states, "crush": idx_crush, "osdmaps": idx_om, "restore": restore, "baseline": {"epoch_at_start": baseline["epoch"], "crush_version": baseline["crush_version"]},
       "names": {"file": "names/names-e%d.json" % NE, "rows": len(rows), "pools": npools}, "answers": {"file": "answers.json", "rows": len(arows)}}
POLL = (" ceph pg stat", " ceph osd stat", " ceph pg map", " ceph osd getmap", " ceph osd dump", " ceph config get", " ceph config dump", " ceph osd crush rule ls", " ceph osd erasure-code-profile ls")
put("ops.log.txt", scrub_text("\n".join(re.sub(r"^\[ *[0-9.]+s\] ", "", l)[:170] for l in oplog if (("rc=" in l and not any(x in l for x in POLL)) or l.startswith("==") or l.startswith("!!"))) + "\n"))
idx["files"] = {}
for rel in sorted(files):
    idx["files"][rel] = {"bytes": len(files[rel]), "sha256": hashlib.sha256(files[rel]).hexdigest()}
idx["total_bytes"] = sum(v["bytes"] for v in idx["files"].values())
# write
for sub in ("states", "maps", "names", "crush", "offline"):
    shutil.rmtree(os.path.join(OUT, sub), ignore_errors=True)
for rel, data in files.items():
    p = os.path.join(OUT, rel); os.makedirs(os.path.dirname(p) or OUT, exist_ok=True); open(p, "wb").write(data)
open(os.path.join(OUT, "INDEX.json"), "w").write(json.dumps(idx, indent=1, sort_keys=True) + "\n")
print("wrote %d files, %d bytes (+ INDEX.json)" % (len(files), idx["total_bytes"]))
# ---- Ceph's own decoder on every scrubbed map and incremental (verifies the CRCs) ----------------------------
dec = shutil.which("ceph-dencoder")
if dec:
    tmp = tempfile.mkdtemp(); badl = []
    def try_dec(typ, data, what):
        fp = os.path.join(tmp, "x"); open(fp, "wb").write(data)
        r = subprocess.run([dec, "type", typ, "import", fp, "decode"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)   # decode verifies the CRC; `dump_json` of a map with primary affinity segfaults in this ceph-dencoder
        if r.returncode != 0: badl.append((what, r.stderr.decode()[:200]))
    for e in sorted(KEEP_FULL): try_dec("OSDMap", FULL[e], "full e%d" % e)
    for e in sorted(INC): try_dec("OSDMap::Incremental", INC[e], "inc e%d" % e)
    for om in plan["osdmaps"]: try_dec("OSDMap", open(os.path.join(OFF, om["name"] + ".bin"), "rb").read(), "offline " + om["name"])
    shutil.rmtree(tmp)
    print("ceph-dencoder on %d maps, %d incrementals and %d offline maps: %d failures %r" % (len(KEEP_FULL), len(INC), len(plan["osdmaps"]), len(badl), badl[:3]))
    assert not badl
else:
    print("ceph-dencoder not found: Ceph's decoder was not run on the scrubbed files")
PYEOF

# ---------------------------------------------------------------------------------------------------------
# --check: sizes, hashes, scrub, CRCs, name hashes, coverage of the committed vectors (python3 only)
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_CHECK <<'PYEOF' || true
import copy
OUT = os.environ["MAPB_OUT"]
DEEP = os.environ.get("MAPB_DEEP", "1") != "0"     # the independent python mapper cross-checks run by default; MAPB_DEEP=0 turns them off
MAX_TOTAL = 2_600_000
# sha256 of the real lab fsid and OSD uuids (16 raw bytes each): they must not occur anywhere in the vectors
FORBIDDEN = {"9eb4728e6c2ecbc3349538312585c3627f21bd83ac7cf9c8dec9d577fbaffada": "lab fsid",
             "ff6466179d0a9c431eb53cacbf25c290e6169274828cc55fc383935b0e49fbd5": "osd uuid", "d842693ce09444205dd7becfa15a252947ac8d9d44736e36575b3230ee1cd395": "osd uuid",
             "a43a3be2ef83c07a79e13571bccfcaadb5e267506396883b59ec99c42b65cde7": "osd uuid"}
passed = failed = 0
def check(ok, what, detail=""):
    global passed, failed
    if ok: passed += 1
    else:
        failed += 1; print("FAIL: %s %s" % (what, detail))
def rd(rel, mode="rb"): return open(os.path.join(OUT, rel), mode).read()
def hexload(rel):
    lines = [l.strip() for l in rd(rel, "r").splitlines() if l.strip() and not l.startswith("#")]
    return bytes.fromhex("".join(lines))

idx = json.loads(rd("INDEX.json", "r"))
# 1. files, sizes, hashes
on_disk = set()
for root, dirs, fs in os.walk(OUT):
    for f in fs + dirs:
        if os.path.islink(os.path.join(root, f)): check(False, "no symbolic link", os.path.join(root, f))
    for f in fs:
        on_disk.add(os.path.relpath(os.path.join(root, f), OUT))
listed = set(idx["files"])
check(on_disk - listed - {"INDEX.json", "README.md"} == set(), "no unlisted file", str(sorted(on_disk - listed - {"INDEX.json", "README.md"})[:5]))
check(listed - on_disk == set(), "no missing file", str(sorted(listed - on_disk)[:5]))
for rel, meta in idx["files"].items():
    if rel in on_disk:
        b = rd(rel)
        check(len(b) == meta["bytes"] and hashlib.sha256(b).hexdigest() == meta["sha256"], "size + sha256 of " + rel)
total = sum(os.path.getsize(os.path.join(OUT, r)) for r in on_disk)
check(total <= MAX_TOTAL, "total size within budget", "%d > %d" % (total, MAX_TOTAL))
print("files: %d, %d bytes on disk (budget %d)" % (len(on_disk), total, MAX_TOTAL))

# 2. scrub: no real fsid / uuid in any byte of any file or hex-decoded blob, no key-looking text, no foreign address
def scan_windows(b, rel):
    for i in range(0, max(0, len(b) - 15)):
        h = hashlib.sha256(b[i:i + 16]).hexdigest()
        if h in FORBIDDEN:
            check(False, "scrub: %s at offset %d of %s" % (FORBIDDEN[h], i, rel)); return
    check(True, "scrub " + rel)
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
OKUU = {"00112233-4455-6677-8899-aabbccddeeff", "00000000-0000-0000-0000-000000000000"} | {"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x" % ((0xA0 + i,) * 16) for i in range(24)}
for rel in sorted(on_disk):
    b = rd(rel)
    if rel == "incrementals.hex":
        scan_windows(b"".join(bytes.fromhex(l.split(" ")[1]) for l in b.decode().splitlines() if l and not l.startswith("#")), rel)
    elif rel.endswith(".hex"):
        scan_windows(hexload(rel), rel)
    else:
        t = b.decode("utf-8", "replace")
        for u in UUID.findall(t): check(u in OKUU, "scrub: uuid %s in %s" % (u, rel))
        check(not re.search(r"AQ[A-Za-z0-9+/]{30,}==?", t), "no key-looking string in " + rel)
        if rel != "README.md": check(not re.search(r"keyring|\bkey\s*=\s*[A-Za-z0-9+/]{20,}", t, re.I), "no key text in " + rel)
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", t):
            check(ip.startswith("10.77.") or ip == "0.0.0.0", "address %s in %s" % (ip, rel))
        # the real fsid / OSD uuids written without dashes (also inside a longer run of hex digits), and private names (home directories, user names, the ssh hop)
        check(not any(hashlib.sha256(bytes.fromhex(run[i:i + 32])).hexdigest() in FORBIDDEN
                      for run in re.findall(r"[0-9a-fA-F]{32,}", t) for i in range(len(run) - 31)), "scrub: compact fsid / uuid in " + rel)
        check(not re.search(r"/home/|/Users/|/root/|\b[a-z][a-z0-9_-]*@\d{1,3}\.", t), "no private path or user name in " + rel)

# 3. maps and incrementals: CRC, scrub placeholders, the chain
base = hexload(idx["base_map"])
m = oc.dec_osdmap(base)
check(m["crc_ok"] and m["epoch"] == idx["base_epoch"] and m["fsid"] == PLACEHOLDER_FSID, "base map decodes, crc ok, placeholder fsid")
incs = {}
for line in rd("incrementals.hex", "r").splitlines():
    if line and not line.startswith("#"):
        e, h = line.split(" "); incs[int(e)] = bytes.fromhex(h)
check(sorted(incs) == list(range(idx["base_epoch"] + 1, idx["last_epoch"] + 1)), "incrementals are contiguous", "%d..%d" % (min(incs), max(incs)))
fulls = {}
for s in idx["states"]:
    if s["full_map"]:
        fulls[s["epoch"]] = hexload(s["full_map"])
at = {}
ans = json.loads(rd(idx["answers"]["file"], "r"))
state_epochs = sorted({s["epoch"] for s in idx["states"]} | {a[1] for a in ans["entries"]})
cur = m
for e in sorted(incs):
    di = oc.dec_incremental(incs[e])
    check(di["inc_crc_ok"] and di["epoch"] == e and di["fsid"] == PLACEHOLDER_FSID, "incremental %d crc ok" % e)
    cur = oc.apply_incremental_checked(cur, di)
    if e in fulls:
        fm = oc.dec_osdmap(fulls[e])
        check(fm["crc_ok"] and di["full_crc"] == fm["crc"], "e%d: full map crc == incremental full_crc" % e)
        check(not same_state(cur, fm, "e%d" % e), "e%d: base + incrementals == stored full map" % e)
    if e in state_epochs:
        at[e] = copy.deepcopy(cur)
for e, fb in fulls.items():
    fm = oc.dec_osdmap(fb); check(fm["crc_ok"] and fm["fsid"] == PLACEHOLDER_FSID and fm["epoch"] == e, "full map e%d decodes" % e)

# 4. the name oracle: every row hashes to its pgid
nm = json.loads(rd(idx["names"]["file"], "r"))
ne = nm["epoch"]; pools = nm["pools"]
check(len(nm["entries"]) >= 3000 and len(pools) >= 4, "names: >= 3000 rows over >= 4 pools", "%d rows, %d pools" % (len(nm["entries"]), len(pools)))
badrow = 0; cesu = 0
for (pid, oh, nsh, ps, pgid, up, upp, act, actp) in nm["entries"]:
    P = pools[str(pid)]
    h = oc.object_ps({"object_hash": P["object_hash"]}, bytes.fromhex(oh), bytes.fromhex(nsh))
    mask = (1 << (P["pg_num"] - 1).bit_length()) - 1
    if h != ps or "%d.%x" % (pid, oc.stable_mod(h, P["pg_num"], mask)) != pgid: badrow += 1
    if b"\xed" in bytes.fromhex(oh): cesu += 1
check(badrow == 0, "names: raw ps and pgid of every row recomputed", "%d bad" % badrow)
check(cesu >= 5, "names: CESU-8 (surrogate pair) rows present", str(cesu))
lens = {len(bytes.fromhex(r[1])) for r in nm["entries"]}
check(set(range(0, 26)) <= lens and 255 in lens, "names: every length 0..25 and 255 present")
check(any(r[2] for r in nm["entries"]) and any(any(c > 127 for c in bytes.fromhex(r[1])) for r in nm["entries"]), "names: namespaces and non-ASCII names present")
geom = sorted((P["pg_num"], P["pgp_num"], P["hashpspool"]) for P in pools.values())
check(any(g[0] & (g[0] - 1) == 0 and g[0] == g[1] for g in geom), "names: a power-of-two pool")
check(any(g[0] == 12 for g in geom) and any(g[0] == 7 and g[1] < 7 for g in geom) and any(g[0] == 12 and g[1] < 12 for g in geom), "names: pg_num 12, pg_num 7 / pgp_num below pg_num")
check(any(not g[2] for g in geom), "names: a legacy pool without HASHPSPOOL")
check(any(P["name"] == "winrbd" for P in pools.values()), "names: winrbd")
check(ne in at, "names: the map of the oracle epoch is a state")
check(len(nm["entries"]) == idx["names"]["rows"], "names: the row count of INDEX.json")
# the monitor's up / acting answers against the PG table of `osdmaptool --test-map-pgs-dump-all` over the full map of that epoch (a state that carries a full map)
st_ne = [json.loads(rd(s["file"], "r")) for s in idx["states"] if s["epoch"] == ne and s["full_map"] and s["label"].startswith("s00-")]
check(len(st_ne) == 1 and st_ne[0]["pools_in_tables"] is None, "names: the oracle epoch has a full table of every pool")
if st_ne:
    badpl = 0
    for (pid, oh, nsh, ps, pgid, up, upp, act, actp) in nm["entries"]:
        t = st_ne[0]["pgs"].get(pgid)
        if t is None or t[1] != up or t[2] != upp or t[3] != act or t[4] != actp: badpl += 1
    check(badpl == 0, "names: up / acting of every row equals the osdmaptool table of that epoch", "%d bad" % badpl)
if ne in at:
    for pid, P in pools.items():
        q = at[ne]["pools"].get(int(pid))
        check(q is not None and q["pg_num"] == P["pg_num"] and q["pgp_num"] == P["pgp_num"] and q["size"] == P["size"] and q["crush_rule"] == P["crush_rule"]
              and bool(q["flags"] & oc.FLAG_HASHPSPOOL) == P["hashpspool"] and q["object_hash"] == P["object_hash"], "names: header geometry of pool %s equals the map" % pid)
# the targeted answers: each carries its own epoch; hash, PG and (where the map of that epoch has a table or the mapper can) up / acting
check(len(ans["entries"]) == idx["answers"]["rows"] and len(ans["entries"]) >= 50, "answers: the row count of INDEX.json, at least 50 rows")
st_by_epoch = {s["epoch"]: json.loads(rd(s["file"], "r")) for s in idx["states"]}
ans_ok = ans_tab = 0
for (label, e, pid, oh, nsh, ps, pgid, up, upp, act, actp) in ans["entries"]:
    mm = at[e]; q = mm["pools"][pid]
    h = oc.object_ps(q, bytes.fromhex(oh), bytes.fromhex(nsh))
    check(h == ps and pgid == "%d.%x" % (pid, oc.stable_mod(h, q["pg_num"], q["pg_num_mask"])), "answers: %s e%d %s hashes to its raw ps and pgid" % (label, e, pgid))
    t = st_by_epoch.get(e, {}).get("pgs", {}).get(pgid)
    if t is not None:
        check(t[1] == up and t[2] == upp and t[3] == act and t[4] == actp, "answers: %s e%d %s equals the PG table of that epoch" % (label, e, pgid)); ans_tab += 1
check(ans_tab >= 10, "answers: at least 10 rows are tied to a PG table", str(ans_tab))

# 5. states: coverage and table shape
need = ["s00-", "s01a", "s01b", "s01c", "s02-split", "s03a", "s03b", "s03c", "s03d", "s04a", "s04b", "s04c", "s05b", "s06a", "s06b", "s06c", "s07a", "s07b", "s07c",
        "s08a", "s08b", "s08c", "s08e", "s09a", "s10-", "s11b", "s11d", "s11e", "s12b", "s12c", "s12e", "s13a", "s13b", "s14a", "s15-merge", "s99-"]
labels = [s["label"] for s in idx["states"]]
for n in need:
    check(any(l.startswith(n) for l in labels), "state present: " + n)
for s in idx["states"]:
    st = json.loads(rd(s["file"], "r"))
    check(st["epoch"] == s["epoch"] == st["dump"]["epoch"], "state %s: epoch" % s["label"])
    pg_n = {p["pool"]: p["pg_num"] for p in st["dump"]["pools"]}
    for (pid, nmh, pgid, act) in st["objects"]:
        h = oc.str_hash_rjenkins(bytes.fromhex(nmh)); mask = (1 << (pg_n[pid] - 1).bit_length()) - 1
        check(pgid == "%d.%x" % (pid, oc.stable_mod(h, pg_n[pid], mask)), "state %s: object %s hashes to %s" % (s["label"], bytes.fromhex(nmh).decode(), pgid))
        if pgid in st["pgs"]: check(st["pgs"][pgid][3] == act, "state %s: object %s acting == PG table" % (s["label"], pgid))
    if s["epoch"] in at:
        mm = at[s["epoch"]]
        for pgs, row in st["pgs"].items():
            pid = int(pgs.split(".")[0])
            if pid not in mm["pools"]:
                check(False, "state %s: pool of %s exists in the rebuilt map" % (s["label"], pgs)); break
        # the dump's pool rows agree with the rebuilt map
        for p in st["dump"]["pools"]:
            q = mm["pools"].get(p["pool"])
            check(q is not None and q["pg_num"] == p["pg_num"] and q["pgp_num"] == p["pg_placement_num"] and q["size"] == p["size"], "state %s: pool %d geometry" % (s["label"], p["pool"]))
        for o in st["dump"]["osds"]:
            check(mm["osd_weight"][o["osd"]] == round(o["weight"] * 0x10000) or abs(mm["osd_weight"][o["osd"]] - o["weight"] * 0x10000) <= 1, "state %s: weight osd.%d" % (s["label"], o["osd"]))
        for key, tkey in (("pg_upmap_items", "pg_upmap_items"), ("pg_upmap", "pg_upmap"), ("pg_temp", "pg_temp"), ("primary_temp", "primary_temp"), ("pg_upmap_primaries", "pg_upmap_primaries")):
            want = {tuple(int(x, 16) if i else int(x) for i, x in enumerate(r.split("."))) for r in pgids(st["dump"], key)}
            check(want == set(mm[tkey]), "state %s: %s keys equal the rebuilt map" % (s["label"], key), "%r vs %r" % (sorted(want), sorted(mm[tkey])))

# 6. CRUSH maps: coverage
algs = set(); tun = set(); has_cargs = set(); has_classes = False; has_cat = False
ALG = {1: "uniform", 2: "list", 3: "tree", 4: "straw", 5: "straw2"}
for c in idx["crush"]:
    blob = hexload(c["crush"]); cm = oc.dec_crush(blob)
    check(cm["_trailing"] == 0, "crush %s decodes to the end" % c["name"])
    algs |= {ALG[b["alg"]] for b in cm["buckets"] if b}
    t = cm["tunables"]; tun.add((t["choose_local_tries"], t["choose_local_fallback_tries"], t["choose_total_tries"], t["chooseleaf_descend_once"], t["chooseleaf_vary_r"], t["chooseleaf_stable"], t["straw_calc_version"]))
    has_cargs |= set(cm["choose_args"]); has_classes |= bool(cm["class_bucket"])
    mp = json.loads(rd(c["mappings"], "r"))
    for rn, run in mp["runs"].items():
        check(len(run["x_to_result"]) == 48 and all(len(r) <= run["num_rep"] for r in run["x_to_result"]), "crush %s run %s shape" % (c["name"], rn))
check(algs == {"uniform", "list", "tree", "straw", "straw2"}, "crush: every bucket algorithm", str(algs))
check(len(tun) >= 4, "crush: several tunable profiles", str(len(tun)))
check({-1, 0, 1} <= has_cargs, "crush: choose_args keys 0, 1 and -1", str(has_cargs)); check(has_classes, "crush: shadow roots of device classes")
for o in idx["osdmaps"]:
    mo = oc.dec_osdmap(hexload(o["osdmap"])); check(mo["crc_ok"] and mo["fsid"] == PLACEHOLDER_FSID, "offline osdmap %s crc" % o["name"])
    check(oc.crush_struct(oc.dec_crush(mo["crush"])) == oc.crush_struct(oc.dec_crush(hexload("crush/%s.crush.hex" % o["crush"]))), "offline osdmap %s carries crush map %s" % (o["name"], o["crush"]))
    pj = json.loads(rd(o["pgs"], "r")); check(len(pj["pgs"]) == pj["pg_num"], "offline osdmap %s: one row per PG" % o["name"])
check(idx["restore"]["ok"], "the lab restore check of the capture passed", str(idx["restore"].get("problems")))

# 7. optional cross-check with the independent python mapper (replicated firstn pools only; needs the Ceph run-time data)
def load_ln_from_core():
    """the two CRUSH log tables from core/crush_ln/ (read as data; the repository's own copy), parsed like osdmap_check.load_ln_tables does"""
    txt = open(os.path.join(os.environ["MAPB_REPO"], "core", "crush_ln", "crush_ln_table.h")).read()
    tabs = {}
    for name, n in (("__RH_LH_tbl", 258), ("__LL_tbl", 256)):
        mt = re.search(name + r"\s*\[[^\]]*\]\s*=\s*\{(.*?)\};", txt, re.S)
        tabs[name] = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", mt.group(1))] if mt else []
        if len(tabs[name]) != n: raise ValueError("%s has %d entries, want %d" % (name, len(tabs[name]), n))
    oc.LN_TABLES["RH_LH"] = tabs["__RH_LH_tbl"]; oc.LN_TABLES["LL"] = tabs["__LL_tbl"]
if DEEP:
    try:
        load_ln_from_core()
    except Exception as ex1:
        try:
            import pubset
            oc.load_ln_tables(pubset.ceph_src(None))
        except Exception as ex2:
            print("deep: crush_ln tables not available (%s; %s); the mapper cross-checks are skipped" % (ex1, ex2)); DEEP = False
# the placement results the python mapper cannot produce (erasure pools; indep rules; list / uniform / tree buckets; the argonaut tunables of om02) are
# skipped, never silently more of them: the counts below are the committed set's
MAX_SKIP_PG = 4; MAX_SKIP_RUNS = 55; MAX_SKIP_OM = {"om02-argonaut-uniform-list-tree": 24}
MIN_OK_PG = 2000; MIN_OK_MAPPINGS = 3500; MIN_OK_OM = 350
if DEEP:
    ok = bad = skip = 0
    for s in idx["states"]:
        if s["epoch"] not in at: continue
        mm = at[s["epoch"]]; st = json.loads(rd(s["file"], "r")); cm = oc.dec_crush(mm["crush"])
        for pgs, row in st["pgs"].items():
            pid, ps = pgs.split("."); pid = int(pid); ps = int(ps, 16)
            try:
                r = oc.pg_placement(mm, cm, pid, ps)
            except Exception:
                skip += 1; continue
            got = [r["raw"], r["up"], r["up_primary"], r["acting"], r["acting_primary"]]
            if got == row: ok += 1
            else:
                bad += 1
                if bad <= 8: print("deep mismatch %s %s: python %r, osdmaptool %r" % (s["label"], pgs, got, row))
    print("deep: %d PG results agree with the independent python mapper, %d differ, %d skipped (not replicated / unsupported)" % (ok, bad, skip))
    check(bad == 0, "deep cross-check")
    check(ok >= MIN_OK_PG and skip <= MAX_SKIP_PG, "deep: the mapper covered the tabulated PGs", "%d agree, %d skipped" % (ok, skip))
    # the monitor's own answers (answers.json) against the mapper over the map of the answer's epoch (base + incrementals)
    aok = abad = askip = 0
    for (label, e, pid, oh, nsh, ps, pgid, up, upp, act, actp) in ans["entries"]:
        mm = at[e]
        try: r = oc.pg_placement(mm, oc.dec_crush(mm["crush"]), pid, ps)
        except Exception: askip += 1; continue
        if [r["up"], r["up_primary"], r["acting"], r["acting_primary"]] == [up, upp, act, actp]: aok += 1
        else:
            abad += 1; print("deep answer mismatch %s e%d %s: python %r, monitor %r" % (label, e, pgid, [r["up"], r["up_primary"], r["acting"], r["acting_primary"]], [up, upp, act, actp]))
    print("deep: %d monitor answers agree with the independent python mapper, %d differ, %d skipped" % (aok, abad, askip))
    check(abad == 0 and aok >= 50 and askip == 0, "deep answers cross-check", "%d agree, %d differ, %d skipped" % (aok, abad, askip))
if DEEP:
    ok = bad = skip = 0; om_ok = 0
    for c in idx["crush"]:
        cm = oc.dec_crush(hexload(c["crush"])); mp = json.loads(rd(c["mappings"], "r"))
        for rn, run in mp["runs"].items():
            w = [0x10000] * cm["max_devices"]
            for dev, wf in run.get("weights", {}).items(): w[int(dev)] = int(wf * 0x10000)
            for x, want in enumerate(run["x_to_result"]):
                xx = oc.hash2(x, run["pool_id"]) if "pool_id" in run else x
                try:
                    got = oc.crush_do_rule(cm, run["rule"], xx, run["num_rep"], w, cargs_key=0)   # crushtool --test asks for choose_args key 0, falling back to -1, whatever --pool-id says
                except Exception:
                    skip += 1; break
                if got == want: ok += 1
                else:
                    bad += 1
                    if bad <= 8: print("deep crush mismatch %s %s x=%d: python %r, crushtool %r" % (c["name"], rn, x, got, want))
    for o in idx["osdmaps"]:
        mo = oc.dec_osdmap(hexload(o["osdmap"])); cm = oc.dec_crush(mo["crush"]); pj = json.loads(rd(o["pgs"], "r"))
        okk = badd = skp = 0
        for pgs, row in pj["pgs"].items():
            pid, ps = pgs.split("."); pid = int(pid); ps = int(ps, 16)
            try: r = oc.pg_placement(mo, cm, pid, ps)
            except Exception: skp += 1; continue
            if [r["raw"], r["up"], r["up_primary"], r["acting"], r["acting_primary"]] == row: okk += 1
            else:
                badd += 1
                if badd <= 4: print("deep osdmap mismatch %s %s: python %r, osdmaptool %r" % (o["name"], pgs, [r["raw"], r["up"], r["up_primary"], r["acting"], r["acting_primary"]], row))
        print("deep: offline osdmap %s: %d PGs agree, %d differ, %d skipped" % (o["name"], okk, badd, skp))
        check(badd == 0, "deep offline osdmap " + o["name"])
        check(skp <= MAX_SKIP_OM.get(o["name"], 0), "deep: no unexpected skipped PG in offline osdmap " + o["name"], str(skp)); om_ok += okk
    print("deep: %d crushtool mappings agree with the python mapper, %d differ, %d runs skipped (indep / unsupported)" % (ok, bad, skip))
    check(bad == 0, "deep crush cross-check")
    check(ok >= MIN_OK_MAPPINGS and skip <= MAX_SKIP_RUNS, "deep: the mapper covered the crushtool runs", "%d agree, %d runs skipped" % (ok, skip))
    check(om_ok >= MIN_OK_OM, "deep: the mapper covered the offline osdmaps", str(om_ok))
print("capture_mapb --check: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PYEOF

# ---------------------------------------------------------------------------------------------------------
# --selftest: the checker must fail on damaged copies of the vectors (python3 only)
# ---------------------------------------------------------------------------------------------------------
read -r -d '' PY_SELFTEST <<'PYEOF' || true
import shutil, subprocess, tempfile
SCRIPT = os.environ["MAPB_SCRIPT"]; SRC = os.environ["MAPB_OUT"]
tmp = tempfile.mkdtemp(prefix="mapb-selftest-")
passed = failed = 0
def run_check(env_extra):
    env = dict(os.environ, MAPB_OUT=os.path.join(tmp, "w"), **env_extra)
    p = subprocess.run(["bash", SCRIPT, "--check"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout
def case(name, mutate, expect, deep=False):
    """damage a fresh copy of the vectors (INDEX.json is kept consistent with the damaged file, so only the content checks can notice) and want the check to fail with `expect`"""
    global passed, failed
    w = os.path.join(tmp, "w"); shutil.rmtree(w, ignore_errors=True); shutil.copytree(SRC, w)
    idx = json.load(open(os.path.join(w, "INDEX.json")))
    rel = mutate(w, idx)
    if rel in idx["files"]:
        b = open(os.path.join(w, rel), "rb").read(); idx["files"][rel] = {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    json.dump(idx, open(os.path.join(w, "INDEX.json"), "w"), indent=1)
    rc, out = run_check({} if deep else {"MAPB_DEEP": "0"})
    ok = rc != 0 and expect in out
    if ok: passed += 1
    else:
        failed += 1; print("SELFTEST FAIL: %s: rc=%d, wanted %r in the output: %s" % (name, rc, expect, out[-300:]))
def edit(rel, fn):
    def m(w, idx):
        j = json.load(open(os.path.join(w, rel))); fn(j)
        open(os.path.join(w, rel), "w").write(json.dumps(j, sort_keys=True, separators=(",", ":")) + "\n"); return rel
    return m
def append(rel, text):
    def m(w, idx):
        open(os.path.join(w, rel), "a").write(text); return rel
    return m
def hexflip(rel, line_no, pos):
    """flip one hex digit on a data line of a hex file (a damaged byte)"""
    def m(w, idx):
        ls = open(os.path.join(w, rel)).read().split("\n"); l = ls[line_no]
        ls[line_no] = l[:pos] + ("0" if l[pos] != "0" else "1") + l[pos + 1:]
        open(os.path.join(w, rel), "w").write("\n".join(ls)); return rel
    return m
try:
    shutil.copytree(SRC, os.path.join(tmp, "w"))
    rc, out = run_check({"MAPB_DEEP": "0"})
    if rc == 0: passed += 1
    else: failed += 1; print("SELFTEST FAIL: the undamaged copy does not pass: " + out[-300:])
    def stray(w, i): open(os.path.join(w, "names", "stray.hex"), "w").write("00"); return None
    def link(w, i): os.symlink("/etc/hosts", os.path.join(w, "link.txt")); return None
    def restore(w, i): i["restore"]["ok"] = False; return "INDEX.json"
    def pgrow(j): j["pgs"][sorted(j["pgs"])[0]][1] = [9, 9, 9]
    def nmrow(j): j["entries"][5][5] = [7, 7, 7]
    def nmhash(j): j["entries"][5][3] ^= 1
    def anpg(j): j["entries"][3][6] = "43.9"
    def anup(j): j["entries"][3][7] = [7, 7]
    def crun(j): j["runs"]["r0n3"]["x_to_result"][4] = [1, 2, 3]
    def ofpg(j): j["pgs"][sorted(j["pgs"])[0]][0] = [5, 5, 5]
    def desc(t):
        def f(j): j["description"] = t
        return f
    case("a stray file", stray, "no unlisted file")
    case("a symbolic link", link, "no symbolic link")
    case("the capture's restore check failed", restore, "the lab restore check")
    case("a damaged byte in an incremental", hexflip("incrementals.hex", 40, 60), "incremental")
    case("a damaged byte in the base map", hexflip("base-e666.hex", 10, 20), "base map")
    case("a name row whose raw ps does not match its name", edit("names/names-e709.json", nmhash), "names: raw ps and pgid")
    case("a name row with a wrong up set", edit("names/names-e709.json", nmrow), "up / acting of every row")
    case("an answer with a wrong pgid", edit("answers.json", anpg), "answers:")
    case("the real fsid without dashes in a state", edit("states/s00-base-pools.json", desc("52762725e19a11f1886d525400770001")), "compact fsid")
    case("a private path in a state", edit("states/s00-base-pools.json", desc("see /home/someone/x")), "no private path")
    case("a foreign address", append("ops.log.txt", "\nmon 192.0.2.7\n"), "address 192.0.2.7")
    case("a key in a text file", append("crush/lab-before.txt", "\nkey = AQDabcdefghijklmnopqrstuvwxyz0123456789==\n"), "key-looking")
    case("a PG row changed in a state table", edit("states/s03a-upmap-items-one.json", pgrow), "deep cross-check", True)
    case("an answer with a wrong up set", edit("answers.json", anup), "deep answers cross-check", True)
    case("a crushtool mapping changed", edit("crush/cm01-host-straw-rack-list-root-uniform.mappings.json", crun), "deep crush cross-check", True)
    case("an offline PG row changed", edit("offline/om01-straw-list-uniform.pgs.json", ofpg), "deep offline osdmap om01", True)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print("capture_mapb --selftest: %d passed, %d failed" % (passed, failed))
sys.exit(1 if failed else 0)
PYEOF

# ---------------------------------------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------------------------------------
cmd="${1:-}"
export MAPB_REPO="$REPO" MAPB_RAW="$RAW" MAPB_WORK="$WORK" MAPB_OUT="$MAPB"
run_py() { python3 -I -c "$PY_COMMON
$1"; }
case "$cmd" in
  capture) mkdir -p "$RAW"; run_py "$PY_CAPTURE" ;;
  cleanup) mkdir -p "$RAW"; MAPB_ONLY_CLEANUP=1 run_py "$PY_CAPTURE" ;;
  export)  mkdir -p "$RAW"; run_py "$PY_EXPORT" ;;
  offline) mkdir -p "$RAW"; run_py "$PY_OFFLINE" ;;
  build)   mkdir -p "$MAPB"; run_py "$PY_BUILD" ;;
  --check|check) run_py "$PY_CHECK" ;;
  --selftest) MAPB_SCRIPT="$HERE/$(basename "${BASH_SOURCE[0]}")" run_py "$PY_SELFTEST" ;;
  all)     "$0" capture && "$0" export && "$0" offline && "$0" build && "$0" --check ;;
  *) echo "usage: $0 capture|export|offline|build|--check|--selftest|cleanup|all" >&2; exit 2 ;;
esac
