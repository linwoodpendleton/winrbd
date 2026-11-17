# SPDX-License-Identifier: MIT
"""
map_placement_export.py - builds harness/vectors/public/placement/ from a finished `map_placement_lab.py run` (called by its `export`
command; python3 standard library only, no cluster needed, the work directory is the only input).

Files written (all text, hex for binary; nothing but maps, tables and counts):

    base-e<E0>.hex          the full OSD map the core started from (what the monitor sent as the first map message)
    incrementals.hex        every incremental of E0+1 .. the last epoch the core adopted, one per line `<epoch> <hex>`, exactly the bytes the
                            monitor sent to the client (the client saved them as it received them, also the one it was made to drop)
    maps/e<E>.hex           the monitor's own full map (`ceph osd getmap <E>`) of a few state epochs, and the full map the core fetched after
                            the incremental it missed (resync-e<E>.hex)
    epochs.tsv              for EVERY epoch of the chain: epoch, number of PG rows, FNV-1a 64 digest of the PG rows of the tracked pools as
                            `osdmaptool --test-map-pgs-dump-all` printed them at that epoch (up, up primary, acting, acting primary)
    names.json              the synthetic object names (recipe) and the object hash (`raw_pgid`) the monitor gave each
    states/<label>.json     one state: epoch, what was done, the pruned `ceph osd dump`, the full PG table of the tracked pools (osdmaptool),
                            the digest of the monitor's `ceph osd map` answers for all names of all tracked pools (`names_digest`) and 120 of
                            those answers in clear
    ops.log.txt             the cluster commands of the run with their exit codes
    RESULT.json             the counts of the live run (what was compared, mismatches, the fault cases, the restore check)
    INDEX.json              size and SHA-256 of every file above
"""
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import map_oracle_diff as D  # noqa: E402
import map_placement_lab as L  # noqa: E402

MAPS_KEEP = ("s00-base", "s01-upmap-items", "s02-upmap-full", "s04-upmap-primary", "s06-reweight", "s07-osd-out", "s10z-split-done", "s13-pool-deleted")


def wrap_hex(b, width=64):
    h = b.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width)) + "\n"


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def export(a):
    work = L.safe_work(a.work)
    out = os.path.abspath(a.out or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "public", "placement"))
    res = json.load(open(os.path.join(work, "result.json")))
    if res.get("failure") or res["pg_mismatches"] or res["tally"]["name_mismatches"] or res["restore_problems"]:
        raise SystemExit("refusing to export a run that failed or did not restore: see %s/result.json" % work)
    saved = os.path.join(work, "saved-m1")
    e0 = res["first_epoch"]
    last = max(res["epoch_list"])
    os.makedirs(out, exist_ok=True)
    for d in ("states", "maps"):
        os.makedirs(os.path.join(out, d), exist_ok=True)

    # the chain: the full map the core started from, then every incremental
    base = None
    for name in sorted(os.listdir(saved)):
        m = re.match(r"^full-(\d+)\.bin$", name)
        if m and int(m.group(1)) <= e0 + 1 and base is None:
            base = (int(m.group(1)), open(os.path.join(saved, name), "rb").read())
    if base is None:
        raise SystemExit("no first full map was saved")
    e_base = base[0]
    incs = {}
    for name in os.listdir(saved):
        m = re.match(r"^inc-(\d+)\.bin$", name)
        if m:
            incs[int(m.group(1))] = open(os.path.join(saved, name), "rb").read()
    miss = [e for e in range(e_base + 1, last + 1) if e not in incs]
    if miss:
        raise SystemExit("the client did not receive these incrementals (the monitor sent a full map instead): %s" % miss[:20])
    write(os.path.join(out, "base-e%d.hex" % e_base),
          "# full OSD map of epoch %d, as the monitor sent it to winrbd-mapwatch (lab cluster, Ceph v20.2.5); the start of incrementals.hex\n" % e_base + wrap_hex(base[1]))
    write(os.path.join(out, "incrementals.hex"),
          "# <epoch> <hex> : every OSDMap::Incremental of epochs %d to %d, as the monitor sent them to winrbd-mapwatch\n" % (e_base + 1, last) +
          "".join("%d %s\n" % (e, incs[e].hex()) for e in range(e_base + 1, last + 1)))
    # the full maps the core was handed later (resync after the swallowed incremental): the monitor's answer to start 0
    resync = []
    for name in sorted(os.listdir(saved)):
        m = re.match(r"^full-(\d+)\.bin$", name)
        if m and int(m.group(1)) > e_base + 1:
            resync.append(int(m.group(1)))
            write(os.path.join(out, "maps", "resync-e%s.hex" % m.group(1)),
                  "# full OSD map of epoch %s that the monitor sent to winrbd-mapwatch after it missed an incremental (answer to a start-0 subscription)\n" % m.group(1) +
                  wrap_hex(open(os.path.join(saved, name), "rb").read()))

    # epochs.tsv
    write(os.path.join(out, "epochs.tsv"),
          "# epoch  pg_rows  fnv1a64  : the PG rows of the tracked pools (winrbd, wrtest-pl-a .. d) at that epoch, `osdmaptool --test-map-pgs-dump-all` over the monitor's map\n"
          "# row text: \"<pool>.<seed hex> <up csv> <up primary> <acting csv> <acting primary>\\n\", pools by id, seeds ascending\n" +
          "".join("%d %d %s\n" % (e, n, d) for e, n, d in res["epochs"] if e >= e_base))

    # names.json (hash of every name, from the monitor's answers of the first state)
    truth = os.path.join(work, "truth", "s00-base.jsonl")
    ps = {}
    for ln in open(truth):
        t = json.loads(ln)
        if t["rc"] == 0 and t["i"] not in ps:
            ps[t["i"]] = t["reply"]["raw_pgid"].split(".")[1]
    n = max(ps) + 1
    write(os.path.join(out, "names.json"), json.dumps({
        "recipe": "i even: rbd_data.5ae8a7c3d6e4.<i as 16 hex digits>; i odd: wrtest-pl-obj-<i as decimal>",
        "count": n, "tracked_pools": L.TRACKED, "hash": "ps = the object hash ceph osd map prints after the pool id in raw_pgid, hex",
        "digest": "fnv1a64 over \"<pool id> <i> <up csv> <up primary> <acting csv> <acting primary>\\n\" for pools by ascending id, i ascending",
        "ps": [ps[i] for i in range(n)]}, separators=(",", ":")) + "\n")

    # states
    index_states = []
    for st in res["states"]:
        e = st["epoch"]
        dump = json.load(open(os.path.join(work, "dumps", "e%d.json" % e)))
        ids = {p["pool_name"]: p["pool"] for p in dump["pools"]}
        truth_pgs, errs, _ = D.parse_pg_text(open(os.path.join(work, "pgs", "e%d.txt" % e)).read())
        keep = sorted(ids[nm] for nm in L.TRACKED if nm in ids)
        pgs = {"%d.%x" % k: [v[0], v[2], v[3], v[4], v[5]] for k, v in sorted(truth_pgs.items()) if k[0] in keep}
        rec = {"label": st["label"], "epoch": e, "description": st["description"], "witness": st["witness"], "pools_in_tables": keep,
               "names_compared": st["names"], "names_pools": st["pools"], "names_pool_ids": sorted(ids[nm] for nm in st["pools"]), "names_digest": st["names_digest"],
               "ops": [{"cmd": o["cmd"], "rc": o["rc"], "msg": o["msg"]} for o in st["ops"]],
               "dump": L.prune(dump), "pg_columns": "[raw, up, up_primary, acting, acting_primary] as printed by `osdmaptool --test-map-pgs-dump-all` over `ceph osd getmap <epoch>`",
               "pgs": pgs, "answers_columns": "[pool_id, name index, epoch, object hash hex, pgid, up, up_primary, acting, acting_primary] from `ceph osd map -f json`, equal to the core's row",
               "answers": st["sample"]}
        write(os.path.join(out, "states", st["label"] + ".json"), json.dumps(rec, separators=(",", ":"), sort_keys=True) + "\n")
        index_states.append(st["label"])
        if st["label"] in MAPS_KEEP:
            write(os.path.join(out, "maps", "e%d.hex" % e), "# full OSD map of epoch %d (`ceph osd getmap %d`), state %s\n" % (e, e, st["label"]) +
                  wrap_hex(open(os.path.join(work, "maps", "e%d.bin" % e), "rb").read()))

    write(os.path.join(out, "ops.log.txt"), "".join("rc=%d %s\n" % (o["rc"], o["cmd"]) for o in res["ops"]))
    summary = {k: res[k] for k in ("tally", "pg_rows_compared", "pg_mismatches", "feature_epochs", "fault", "client_info", "client_rc", "client2_info", "client2_rc", "first_epoch", "pool_ids", "restore_problems")}
    summary["tally"] = {k: v for k, v in summary["tally"].items() if k != "name_mismatches"}
    summary["states"] = index_states
    summary["epochs"] = len(res["epochs"])
    summary["resync_full_maps"] = resync
    write(os.path.join(out, "RESULT.json"), json.dumps(summary, indent=1, sort_keys=True) + "\n")
    files = {}
    for root, _, names in os.walk(out):
        for nm in sorted(names):
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, out)
            if rel == "INDEX.json" or rel == "README.md":
                continue
            b = open(p, "rb").read()
            files[rel] = {"bytes": len(b), "sha256": hashlib.sha256(b).hexdigest()}
    write(os.path.join(out, "INDEX.json"), json.dumps({"base_epoch": e_base, "last_epoch": last, "states": index_states, "resync_maps": resync, "files": files}, indent=1, sort_keys=True) + "\n")
    print("exported %d files (%d bytes) to %s" % (len(files), sum(f["bytes"] for f in files.values()), out))
    return 0
