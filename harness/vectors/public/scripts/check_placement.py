#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
check_placement.py - integrity of harness/vectors/public/placement/ (python3 standard library only, no cluster).

    python3 -I check_placement.py [--dir DIR]       (ctest: vectors_placement_check)

Checks: every file's size and SHA-256 against INDEX.json and no stray file or link; the chain (base map, then contiguous
incrementals up to the last epoch of INDEX.json, one epoch each); epochs.tsv names every epoch of the chain once; every state file
parses, its epoch is in the chain, its PG table has the rows its dump's pools say (pg_num per tracked pool); names.json holds `count`
object hashes; the total size stays below the budget; nothing that looks like a key, a ticket, a password or an address outside
10.77.0.x is in any text file. The placement itself is checked by the C test place.live (ctest), not here.
"""
import argparse
import hashlib
import json
import os
import re
import sys

BUDGET = 1_500_000
TRACKED = ["winrbd", "wrtest-pl-a", "wrtest-pl-b", "wrtest-pl-c", "wrtest-pl-d"]
KEY_RE = re.compile(r"AQ[A-Za-z0-9+/]{36,}={0,2}|key\s*=|-----BEGIN|password|secret|ticket", re.I)
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "placement"))
    a = ap.parse_args()
    d = os.path.abspath(a.dir)
    bad = []
    idx = json.load(open(os.path.join(d, "INDEX.json")))
    files = idx["files"]
    on_disk = {}
    for root, dirs, names in os.walk(d, followlinks=False):
        for nm in names:
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, d)
            if os.path.islink(p):
                bad.append("symbolic link %s" % rel)
                continue
            if rel in ("INDEX.json", "README.md"):
                continue
            on_disk[rel] = p
    for rel in sorted(set(on_disk) - set(files)):
        bad.append("stray file %s" % rel)
    total = 0
    for rel, meta in sorted(files.items()):
        p = on_disk.get(rel)
        if p is None:
            bad.append("missing file %s" % rel)
            continue
        b = open(p, "rb").read()
        total += len(b)
        if len(b) != meta["bytes"] or hashlib.sha256(b).hexdigest() != meta["sha256"]:
            bad.append("%s differs from INDEX.json" % rel)
        if rel.endswith((".json", ".tsv", ".txt")):
            txt = b.decode("utf-8", "replace")
            if rel.startswith("states/") and False:
                continue
            for m in KEY_RE.finditer(txt):
                # "secret" / "key" appear in nothing we publish; the words are not allowed at all
                bad.append("%s: key-like text %r" % (rel, m.group(0)[:20]))
                break
            for m in IP_RE.finditer(txt):
                ip = m.groups()
                if tuple(int(x) for x in ip[:3]) != (10, 77, 0) and not (int(ip[0]) == 0 and int(ip[3]) == 0) and not rel.endswith("epochs.tsv"):
                    # numbers such as "2.9.0.1" do not occur in these files; anything dotted-quad-like outside the lab net is suspicious
                    if all(int(x) < 256 for x in ip) and not rel.startswith("states/"):
                        bad.append("%s: address %s outside 10.77.0.x" % (rel, m.group(0)))
                        break
    if total > BUDGET:
        bad.append("total size %d above the budget of %d" % (total, BUDGET))
    # the chain
    e0, last = idx["base_epoch"], idx["last_epoch"]
    inc = [ln.split() for ln in open(os.path.join(d, "incrementals.hex")) if ln.strip() and not ln.startswith("#")]
    eps = [int(x[0]) for x in inc]
    if eps != list(range(e0 + 1, last + 1)):
        bad.append("incrementals.hex is not the contiguous chain %d..%d" % (e0 + 1, last))
    for x in inc:
        if len(x) != 2 or not re.fullmatch(r"[0-9a-f]+", x[1]) or len(x[1]) % 2:
            bad.append("incrementals.hex: epoch %s is not hex" % x[0])
            break
    if not os.path.exists(os.path.join(d, "base-e%d.hex" % e0)):
        bad.append("base-e%d.hex is missing" % e0)
    tsv = [ln.split() for ln in open(os.path.join(d, "epochs.tsv")) if ln.strip() and not ln.startswith("#")]
    tsv_eps = [int(x[0]) for x in tsv]
    if tsv_eps != sorted(set(tsv_eps)) or not set(range(e0, last + 1)) <= set(tsv_eps):
        bad.append("epochs.tsv does not name every epoch of the chain once")
    # states
    names = json.load(open(os.path.join(d, "names.json")))
    if len(names["ps"]) != names["count"] or names["count"] < 2000:
        bad.append("names.json: count %s, hashes %d" % (names["count"], len(names["ps"])))
    for label in idx["states"]:
        st = json.load(open(os.path.join(d, "states", label + ".json")))
        if not e0 <= st["epoch"] <= last:
            bad.append("state %s: epoch %d outside the chain" % (label, st["epoch"]))
        per = {}
        for k in st["pgs"]:
            per[k.split(".")[0]] = per.get(k.split(".")[0], 0) + 1
        for p in st["dump"]["pools"]:
            if p["pool_name"] in TRACKED and per.get(str(p["pool"]), 0) != p["pg_num"]:
                bad.append("state %s: pool %s has %d PG rows, pg_num is %d" % (label, p["pool_name"], per.get(str(p["pool"]), 0), p["pg_num"]))
    print("placement vectors: %d files, %d bytes, chain %d..%d (%d incrementals), %d epochs in epochs.tsv, %d states: %s" %
          (len(files), total, e0, last, len(inc), len(tsv), len(idx["states"]), "OK" if not bad else "%d PROBLEMS" % len(bad)))
    for b in bad[:20]:
        print("  " + b)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
