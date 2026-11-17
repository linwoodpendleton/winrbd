#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
map_oracle_diff.py - compares what wr-maporacle (harness/oracle/) prints with what Ceph's own tools printed.

Used by harness/tools/map_oracle_lab.sh (the live comparison on the lab cluster and its --selftest). Python 3 standard
library only, so `python3 -I map_oracle_diff.py ...` works anywhere. Every comparison prints one line

    RESULT <label> compared=<n> mismatches=<m> skipped=<s>

followed by the first mismatches, and exits 0 only when there were no mismatches. "skipped" counts answers of a pool or rule this
client does not serve (erasure pools, tiers, indep rules, tree buckets: the tool prints ERROR WR_E_POOL_UNSUPPORTED /
WR_E_CRUSH_UNSUPPORTED / WR_E_CRUSH_NO_RULE) and names above the core's 4,096-byte limit (ERROR WR_E_TOOBIG); a run that
skips everything is reported as such, never as a pass of what was skipped.

Sub-commands (see the functions for the formats):

  names    --truth-jsonl F | --truth-names-json F   --ours F        object lines against `ceph osd map -f json` / a names oracle
  pgs      --truth-text F | --truth-json F [--pool-id N]   --ours F   PG lines against osdmaptool --test-map-pgs-dump-all / a table
  crush    --truth F --ours F                                         crushtool --test --show-mappings lines
  state    --chain F --full F [--epoch N]                             --dump-state of an applied chain against the monitor's full map
  selftest --tool PATH --vectors DIR                                  every committed vector through the tool, plus negative tests
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

NONE_ITEM = 0x7FFFFFFF
UNSUPPORTED = ("WR_E_POOL_UNSUPPORTED", "WR_E_CRUSH_UNSUPPORTED", "WR_E_CRUSH_NO_RULE")
CORE_LIMIT = ("WR_E_TOOBIG",)
CORE_NAME_MAX = 4096  # WRI_PLACE_NAME_MAX: name + namespace + key
MAX_SHOW = 10

RE_LIST = r"(\[[^\]]*\])"
RE_PG = re.compile(r"^(\d+)\.([0-9a-f]+) raw \(" + RE_LIST + r", p(-?\d+)\) up \(" + RE_LIST + r", p(-?\d+)\) acting \(" + RE_LIST + r", p(-?\d+)\)$")
RE_PG_ERR = re.compile(r"^(\d+)\.([0-9a-f]+) ERROR (\S+)")
RE_POOL_ERR = re.compile(r"^pool (\d+) ERROR (\S+)")
RE_OBJ = re.compile(
    r"^osdmap e(\d+) pool '(.*)' \((-?\d+)\) object '(.*)' -> pg (\d+)\.([0-9a-f]+) \((\d+)\.([0-9a-f]+)\) -> up \(" + RE_LIST + r", p(-?\d+)\) acting \(" + RE_LIST + r", p(-?\d+)\)$"
)
RE_OBJ_ERR = re.compile(r"^osdmap e(\d+) pool '(.*)' \((-?\d+)\) object '.*' -> ERROR (\S+)")
RE_CRUSH = re.compile(r"^CRUSH rule (\d+) x (\d+) (\[[^\]]*\])$")
RE_CRUSH_ERR = re.compile(r"^CRUSH rule (\d+) x (\d+) ERROR (\S+)")


class Result:
    """Counts of one comparison and the first things that differed."""

    def __init__(self, label):
        self.label = label
        self.compared = 0
        self.skipped = 0
        self.mismatches = []
        self.notes = []

    def bad(self, msg):
        self.mismatches.append(msg)

    def merge(self, other):
        self.compared += other.compared
        self.skipped += other.skipped
        self.mismatches += other.mismatches
        self.notes += other.notes

    def line(self):
        return "RESULT %s compared=%d mismatches=%d skipped=%d" % (self.label, self.compared, len(self.mismatches), self.skipped)

    def report(self, out=sys.stdout):
        out.write(self.line() + "\n")
        for m in self.mismatches[:MAX_SHOW]:
            out.write("  MISMATCH %s\n" % m)
        if len(self.mismatches) > MAX_SHOW:
            out.write("  ... and %d more\n" % (len(self.mismatches) - MAX_SHOW))
        seen = {}
        for n in self.notes:
            seen[n] = seen.get(n, 0) + 1
        for n in list(seen)[:MAX_SHOW]:
            out.write("  note: %s%s\n" % (n, " (x%d)" % seen[n] if seen[n] > 1 else ""))


def plist(s):
    """'[1,0,NONE]' -> [1, 0, 2147483647]"""
    body = s.strip()[1:-1]
    return [NONE_ITEM if x == "NONE" else int(x) for x in body.split(",") if x != ""]


def first_primary(osds):
    for o in osds:
        if o != NONE_ITEM:
            return o
    return -1


def fmt_list(v):
    return "[" + ",".join(str(x) for x in v) + "]"


# ---------------------------------------------------------------------------------------------------------------------
# PG tables (osdmaptool --test-map-pgs-dump-all)
# ---------------------------------------------------------------------------------------------------------------------

def parse_pg_text(text):
    """-> (pgs {(pool, seed): (raw, rawp, up, upp, acting, actp)}, errors [(where, status)], other lines)"""
    pgs, errs, other = {}, [], []
    for ln in text.splitlines():
        m = RE_PG.match(ln)
        if m:
            pgs[(int(m.group(1)), int(m.group(2), 16))] = (plist(m.group(3)), int(m.group(4)), plist(m.group(5)), int(m.group(6)), plist(m.group(7)), int(m.group(8)))
            continue
        m = RE_PG_ERR.match(ln)
        if m:
            errs.append(("%s.%s" % (m.group(1), m.group(2)), m.group(3), int(m.group(1))))
            continue
        m = RE_POOL_ERR.match(ln)
        if m:
            errs.append(("pool %s" % m.group(1), m.group(2), int(m.group(1))))
            continue
        if ln.strip():
            other.append(ln)
    return pgs, errs, other


def truth_from_table(table):
    """{"<pool>.<hex>": [raw, up, up_primary, acting, acting_primary]} -> the tuple form (the raw primary is the first member)"""
    out = {}
    for k, v in table.items():
        pool, seed = k.split(".")
        out[(int(pool), int(seed, 16))] = (v[0], first_primary(v[0]), v[1], v[2], v[3], v[4])
    return out


def compare_pgs(label, truth, ours_text, pools=None):
    """truth: {(pool, seed): tuple}; every PG of the chosen pools must be printed, equal, and nothing else."""
    r = Result(label)
    ours, errs, other = parse_pg_text(ours_text)
    skipped_pools = set()
    for where, status, pool in errs:
        if status in UNSUPPORTED:
            skipped_pools.add(pool)
        else:
            r.bad("%s: the tool printed ERROR %s" % (where, status))
    for ln in other:
        r.bad("unrecognised output line: %r" % ln[:200])
    for key in sorted(truth):
        if pools is not None and key[0] not in pools:
            continue
        if key[0] in skipped_pools:
            r.skipped += 1
            continue
        got = ours.get(key)
        if got is None:
            r.bad("%d.%x missing from the tool's output" % key)
            continue
        r.compared += 1
        if got != truth[key]:
            r.bad("%d.%x: tool raw %s p%d up %s p%d acting %s p%d; truth raw %s p%d up %s p%d acting %s p%d" % ((key[0], key[1]) + _cols(got) + _cols(truth[key])))
    for key in ours:
        if key not in truth or (pools is not None and key[0] not in pools):
            r.bad("%d.%x printed by the tool but not in the truth" % key)
    return r


def _cols(t):
    return (fmt_list(t[0]), t[1], fmt_list(t[2]), t[3], fmt_list(t[4]), t[5])


def truth_from_text(text, pool=None):
    pgs, _, _ = parse_pg_text(text)
    if pool is not None:
        pgs = {k: v for k, v in pgs.items() if k[0] == pool}
    return pgs


# ---------------------------------------------------------------------------------------------------------------------
# object lines (ceph osd map)
# ---------------------------------------------------------------------------------------------------------------------

def esc_name(b):
    """the escaping the tool applies to object names (printable ASCII as is, backslash doubled, other bytes \\xHH)"""
    out = []
    for c in b:
        if c == 0x5C:
            out.append("\\\\")
        elif 0x20 <= c <= 0x7E:
            out.append(chr(c))
        else:
            out.append("\\x%02x" % c)
    return "".join(out)


class Name:
    """one object of the oracle: the bytes the monitor hashed and its answer"""

    def __init__(self, pool_id, obj, ns, raw_ps, pgid, up, upp, acting, actp, epoch=None, pool_name=None):
        self.pool_id, self.obj, self.ns = pool_id, obj, ns
        self.raw_ps, self.pgid = raw_ps, pgid
        self.up, self.upp, self.acting, self.actp = up, upp, acting, actp
        self.epoch = epoch
        self.pool_name = pool_name


def names_from_json(path):
    """the committed layout: entries [pool_id, object_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary]"""
    d = json.load(open(path))
    epoch = d.get("epoch")
    return [Name(e[0], bytes.fromhex(e[1]), bytes.fromhex(e[2]), e[3], e[4], e[5], e[6], e[7], e[8], epoch) for e in d["entries"]]


def names_from_jsonl(path):
    """the lab driver's file: one JSON object per line {"pool", "obj_hex", "ns_hex", "rc", "reply": <ceph osd map -f json>}"""
    out = []
    for ln in open(path):
        ln = ln.strip()
        if not ln:
            continue
        r = json.loads(ln)
        if r.get("rc") != 0:
            out.append(Name(None, bytes.fromhex(r["obj_hex"]), bytes.fromhex(r["ns_hex"]), None, None, None, None, None, None, None, r.get("pool")))
            out[-1].err = r.get("err", "rc %s" % r.get("rc"))
            continue
        p = r["reply"]
        raw_ps = int(p["raw_pgid"].split(".")[1], 16)
        out.append(Name(p["pool_id"], bytes.fromhex(r["obj_hex"]), bytes.fromhex(r["ns_hex"]), raw_ps, p["pgid"], p["up"], p["up_primary"], p["acting"], p["acting_primary"], p["epoch"], r.get("pool")))
    return out


def names_batch(names, pool_name_of):
    """the file for --names: '<pool> <object hex|-> <ns hex|->' per name, the same order as `names`"""
    lines = []
    for n in names:
        pool = n.pool_name if n.pool_name is not None else pool_name_of[n.pool_id]
        lines.append("%s %s %s\n" % (pool, n.obj.hex() or "-", n.ns.hex() or "-"))
    return "".join(lines)


def compare_names(label, names, ours_text):
    r = Result(label)
    lines = ours_text.splitlines()
    if len(lines) != len(names):
        r.bad("the tool printed %d lines for %d names" % (len(lines), len(names)))
        return r
    for i, (n, ln) in enumerate(zip(names, lines)):
        if getattr(n, "err", None) is not None:
            r.skipped += 1
            r.notes.append("name #%d: the monitor refused it (%s)" % (i, n.err))
            continue
        m = RE_OBJ.match(ln)
        if not m:
            m2 = RE_OBJ_ERR.match(ln)
            if m2 and (m2.group(4) in UNSUPPORTED or (m2.group(4) in CORE_LIMIT and len(n.obj) + len(n.ns) > CORE_NAME_MAX)):
                r.skipped += 1  # TOOBIG only counts as skipped when the name really is above the core's limit
                continue
            r.bad("#%d pool %s %s: unparsable or error line: %s" % (i, n.pool_id, n.obj.hex()[:40], ln[:200]))
            continue
        epoch, pname, pid, oname, rpool, rps, mpool, mseed, up, upp, act, actp = m.groups()
        want_seed = int(n.pgid.split(".")[1], 16)
        r.compared += 1
        got = (int(pid), int(rpool), int(rps, 16), int(mpool), int(mseed, 16), plist(up), int(upp), plist(act), int(actp))
        want = (n.pool_id, n.pool_id, n.raw_ps, n.pool_id, want_seed, n.up, n.upp, n.acting, n.actp)
        # the line must also name the object (and the pool) that was asked for, not only carry the right placement
        shown = (esc_name(n.ns) + "/" if n.ns else "") + esc_name(n.obj)
        if oname != shown or (n.pool_name is not None and pname != esc_name(n.pool_name.encode("utf-8"))):
            r.bad("#%d pool %s: the line names object '%s' in pool '%s', asked for '%s' in '%s'" % (i, n.pool_id, oname[:80], pname[:40], shown[:80], n.pool_name))
            continue
        if got != want or (n.epoch is not None and int(epoch) != n.epoch):
            r.bad("#%d pool %s name %s ns %s: tool %s; truth ps %x pg %s up %s p%d acting %s p%d (epoch %s)" % (
                i, n.pool_id, n.obj.hex()[:60] or "-", n.ns.hex() or "-", ln[ln.index(" -> pg "):][:200], n.raw_ps, n.pgid, fmt_list(n.up), n.upp, fmt_list(n.acting), n.actp, n.epoch))
    return r


# ---------------------------------------------------------------------------------------------------------------------
# crushtool --test --show-mappings
# ---------------------------------------------------------------------------------------------------------------------

def compare_crush(label, truth_text, ours_text):
    r = Result(label)
    truth = [l for l in truth_text.splitlines() if l.startswith("CRUSH rule ")]
    ours = ours_text.splitlines()
    if len(truth) != len(ours):
        r.bad("the tool printed %d lines, crushtool %d" % (len(ours), len(truth)))
        return r
    skipped_run = False
    for t, o in zip(truth, ours):
        m = RE_CRUSH_ERR.match(o)
        if m and m.group(3) in UNSUPPORTED:
            skipped_run = True
            r.skipped += 1
            continue
        r.compared += 1
        if t != o:
            r.bad("tool %r, crushtool %r" % (o[:200], t[:200]))
    if skipped_run:
        r.notes.append("some mappings use a bucket algorithm or rule this client does not serve")
    return r


def crush_truth_text(rule, mappings):
    """[(x, [osds])] -> crushtool's lines"""
    return "".join("CRUSH rule %d x %d %s\n" % (rule, x, fmt_list(v)) for x, v in mappings)


# ---------------------------------------------------------------------------------------------------------------------
# --dump-state
# ---------------------------------------------------------------------------------------------------------------------

def state_blocks(text):
    """{epoch: [lines]} of a --dump-state output; the flags line keeps only the bits a client reads (0xe)"""
    blocks, cur = {}, None
    for ln in text.splitlines():
        m = re.match(r"^== epoch (\d+)$", ln)
        if m:
            cur = blocks.setdefault(int(m.group(1)), [])
            continue
        if cur is None:
            continue
        if ln.startswith("flags 0x"):
            ln = "flags(client bits) 0x%x" % (int(ln.split()[1], 16) & 0xE)
        cur.append(ln)
    return blocks


def compare_state(label, chain_text, full_text, epoch=None):
    """the block of `epoch` (default: every epoch the full-map dump has) of an applied chain equals the monitor's full map"""
    r = Result(label)
    chain, full = state_blocks(chain_text), state_blocks(full_text)
    for e in sorted(full if epoch is None else [epoch]):
        if e not in chain or e not in full:
            r.bad("epoch %d: not in both dumps" % e)
            continue
        r.compared += 1
        if chain[e] != full[e]:
            diff = [(a, b) for a, b in zip(chain[e], full[e]) if a != b]
            r.bad("epoch %d: %d lines differ (chain %d lines, full %d); first: chain %r vs full %r" % (
                e, len(diff) + abs(len(chain[e]) - len(full[e])), len(chain[e]), len(full[e]), diff[0][0][:150] if diff else "", diff[0][1][:150] if diff else ""))
    return r


def _pool_ids_of(block):
    ids = {}
    for ln in block:
        m = re.match(r"^pool (-?\d+) '(.*)' present type (\d+) size (\d+) min_size (\d+) rule (\d+) hash (\d+) flags 0x([0-9a-f]+) pg_num (\d+) pgp_num (\d+) pg_num_pending (\d+) status (\S+)$", ln)
        if m:
            ids[int(m.group(1))] = dict(name=m.group(2), type=int(m.group(3)), size=int(m.group(4)), min_size=int(m.group(5)), rule=int(m.group(6)), hash=int(m.group(7)),
                                        flags=int(m.group(8), 16), pg_num=int(m.group(9)), pgp_num=int(m.group(10)), pending=int(m.group(11)), status=m.group(12))
    return ids


def compare_state_json(label, block, dump):
    """one state block against `ceph osd dump -f json` of the same epoch: the OSD rows, the tracked pools and the five tables"""
    r = Result(label)
    pools = _pool_ids_of(block)
    tracked = set(pools)
    absent = [m.group(1) for m in (re.match(r"^pool '(.*)' absent$", l) for l in block) if m]
    osd_rows = {}
    for ln in block:
        m = re.match(r"^osd\.(\d+) state (\d+) weight (\d+) affinity (\d+) addr ", ln)
        if m:
            osd_rows[int(m.group(1))] = (int(m.group(2)), int(m.group(3)), int(m.group(4)))
    r.compared += 1
    if dump["max_osd"] != len(osd_rows):
        r.bad("max_osd %d vs %d OSD lines" % (dump["max_osd"], len(osd_rows)))
    dump_osds = {o["osd"]: o for o in dump["osds"]}
    for i, (st, w, a) in osd_rows.items():
        r.compared += 1
        d = dump_osds.get(i)
        if d is None:
            if st & 1:
                r.bad("osd.%d exists in the tool's state but not in the dump" % i)
            continue
        if not (st & 1) or bool(st & 2) != bool(d["up"]) or abs(w / 65536.0 - d["weight"]) > 2e-5 or abs(a / 65536.0 - d["primary_affinity"]) > 2e-5:
            r.bad("osd.%d: tool state %d weight %d affinity %d; dump up %s weight %s affinity %s" % (i, st, w, a, d["up"], d["weight"], d["primary_affinity"]))
    by_id = {p["pool"]: p for p in dump["pools"]}
    for pid, p in pools.items():
        r.compared += 1
        d = by_id.get(pid)
        if d is None or d["pool_name"] != p["name"]:
            r.bad("pool %d '%s': not in the dump under that name" % (pid, p["name"]))
            continue
        want = dict(type=d["type"], size=d["size"], min_size=d["min_size"], rule=d["crush_rule"], hash=d["object_hash"], flags=d["flags"], pg_num=d["pg_num"],
                    pgp_num=d["pg_placement_num"], pending=d["pg_num_pending"])
        got = {k: p[k] for k in want}
        if got != want:
            r.bad("pool %d: tool %s, dump %s" % (pid, got, want))
    for nm in absent:
        r.compared += 1
        if any(p["pool_name"] == nm for p in dump["pools"]):
            r.bad("pool '%s' is absent in the tool's state but in the dump" % nm)

    def tab(kind):
        out = {}
        for ln in block:
            m = re.match(r"^" + kind + r" (\d+)\.([0-9a-f]+) (\[[^\]]*\])$", ln)
            if m:
                out[(int(m.group(1)), int(m.group(2), 16))] = plist(m.group(3))
        return out

    def dump_tab(rows, val):
        out = {}
        for row in rows:
            pool, seed = row["pgid"].split(".")
            if int(pool) in tracked:
                out[(int(pool), int(seed, 16))] = val(row)
        return out

    pt = dump.get("primary_temp", [])
    if pt and not isinstance(pt[0], dict):  # a flat [pgid, osd, pgid, osd, ...] list
        pt = [{"pgid": pt[i], "osd": pt[i + 1]} for i in range(0, len(pt), 2)]
    want_tabs = {
        "pg_temp": dump_tab(dump.get("pg_temp", []), lambda x: x["osds"]),
        "primary_temp": dump_tab(pt, lambda x: [x["osd"]]),
        "pg_upmap": dump_tab(dump.get("pg_upmap", []), lambda x: x["osds"]),
        "pg_upmap_items": dump_tab(dump.get("pg_upmap_items", []), lambda x: [v for m in x["mappings"] for v in (m["from"], m["to"])]),
        "pg_upmap_primary": dump_tab(dump.get("pg_upmap_primaries", []), lambda x: [x["primary_osd"]]),
    }
    for kind, want in want_tabs.items():
        got = tab(kind)
        r.compared += 1
        if got != want:
            r.bad("%s: tool %s; dump %s" % (kind, sorted(got.items())[:6], sorted(want.items())[:6]))
    return r


# ---------------------------------------------------------------------------------------------------------------------
# running the tool
# ---------------------------------------------------------------------------------------------------------------------

class Tool:
    def __init__(self, path):
        self.path = path
        self.runs = 0

    def run(self, args, expect=(0, 3)):
        self.runs += 1
        p = subprocess.run([self.path] + [str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode not in expect:
            raise SystemExit("wr-maporacle %s -> exit %d: %s" % (" ".join(str(a) for a in args)[:300], p.returncode, p.stderr.decode("utf-8", "replace")[:600]))
        return p.stdout.decode("utf-8", "replace")

    def run_full(self, args):
        """(exit status, stdout, stderr) without judging the status"""
        self.runs += 1
        p = subprocess.run([self.path] + [str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------------------------------------------------------------
# the self test: every committed vector through the tool
# ---------------------------------------------------------------------------------------------------------------------

def selftest(tool_path, vec):
    tool = Tool(tool_path)
    total = Result("selftest")
    parts = []

    def add(res):
        parts.append(res)
        total.merge(res)
        res.report()

    # ---- the first lab set: epoch 42 and the 89 incrementals --------------------------------------------------------
    e42, incs = os.path.join(vec, "osdmap/full-e42.hex"), os.path.join(vec, "osdmap/incrementals.hex")
    names42 = names_from_json(os.path.join(vec, "osdmap/placement-names-e42.json"))
    pool_name = {1: ".mgr", 2: "winrbd"}
    with tempfile.TemporaryDirectory() as td:
        nf = os.path.join(td, "names.txt")
        open(nf, "w").write(names_batch(names42, pool_name))
        out = tool.run(["--map", e42, "--names", nf, "--pool", ".mgr", "--pool", "winrbd"])
        add(compare_names("names e42 (osdmap/placement-names-e42.json)", names42, out))
    states = json.load(open(os.path.join(vec, "osdmap/placement-states.json")))["states"]
    res = Result("pg tables of the 24 states of osdmap/placement-states.json")
    for label, st in sorted(states.items()):
        for pid, pname in pool_name.items():
            out = tool.run(["--map", e42, "--apply-inc", incs, "--epoch", st["epoch"], "--pool", pname, "--dump-pgs"])
            res.merge(compare_pgs("%s pool %d" % (label, pid), truth_from_table(st["pgs"]), out, pools={pid}))
    add(res)
    # crush maps of the first set
    crush_hex = os.path.join(vec, "osdmap/crush-embedded.hex")
    sets = json.load(open(os.path.join(vec, "osdmap/crush-mappings.json")))["sets"]
    res = Result("crushtool mappings of osdmap/crush-mappings.json")
    for name, s in sorted(sets.items()):
        xs = [x for x, _ in s["mappings"]]
        args = ["--crush", crush_hex, "--rule", s["rule"], "--num-rep", s["num_rep"], "--min-x", min(xs), "--max-x", max(xs)]
        if s.get("pool_id_hash") is not None:
            args += ["--pool-id", s["pool_id_hash"]]
        res.merge(compare_crush(name, crush_truth_text(s["rule"], s["mappings"]), tool.run(args)))
    add(res)
    runs = json.load(open(os.path.join(vec, "crush/crushtool-mappings.json")))["runs"]
    res = Result("crushtool runs of crush/crushtool-mappings.json")
    for name, s in sorted(runs.items()):
        args = ["--crush", os.path.join(vec, "crush/crush-getcrushmap.hex"), "--rule", s["rule"], "--num-rep", s["num_rep"], "--min-x", 0, "--max-x", len(s["x_to_result"]) - 1]
        if s.get("pool_id_hash2_applied_by_tool") is not None:
            args += ["--pool-id", s["pool_id_hash2_applied_by_tool"]]
        res.merge(compare_crush(name, crush_truth_text(s["rule"], list(enumerate(s["x_to_result"]))), tool.run(args)))
    add(res)

    # ---- the committed text of the Ceph tools (public/gt) --------------------------------------------------------------
    gt = os.path.join(vec, "public/gt")
    res = Result("crushtool text of public/gt")
    for f in sorted(os.listdir(os.path.join(gt, "crushtool-tests"))):
        m = re.match(r"^rule(\d+)\.rep(\d+)\.x0-9999(?:\.pool(\d+))?\.txt$", f)
        if not m:
            continue
        args = ["--crush", os.path.join(gt, "crush.bin"), "--rule", m.group(1), "--num-rep", m.group(2), "--min-x", 0, "--max-x", 9999]
        if m.group(3):
            args += ["--pool-id", m.group(3)]
        res.merge(compare_crush(f, open(os.path.join(gt, "crushtool-tests", f)).read(), tool.run(args)))
    add(res)
    res = Result("osdmaptool text of public/gt")
    for pid, pname in ((1, ".mgr"), (2, "winrbd")):
        truth = truth_from_text(open(os.path.join(gt, "osdmaptool-test-map-pgs-dump-all.pool%d.txt" % pid)).read(), pid)
        res.merge(compare_pgs("pool %d" % pid, truth, tool.run(["--map", os.path.join(gt, "osdmap.bin"), "--pool", pname, "--dump-pgs"]), pools={pid}))
    add(res)

    # ---- map-b: the name oracle, every state, the offline maps and CRUSH maps -----------------------------------------------
    mb = os.path.join(vec, "public/mapb")
    index = json.load(open(os.path.join(mb, "INDEX.json")))
    base, mincs = os.path.join(mb, "base-e666.hex"), os.path.join(mb, "incrementals.hex")
    nj = json.load(open(os.path.join(mb, "names/names-e709.json")))
    pool_name_b = {int(k): v["name"] for k, v in nj["pools"].items()}
    names709 = names_from_json(os.path.join(mb, "names/names-e709.json"))
    tracked8 = [pool_name_b[k] for k in sorted(pool_name_b)]
    pool_args = [a for n in tracked8 for a in ("--pool", n)]
    with tempfile.TemporaryDirectory() as td:
        nf = os.path.join(td, "names.txt")
        open(nf, "w").write(names_batch(names709, pool_name_b))
        add(compare_names("names e709 (full map)", names709, tool.run(["--map", os.path.join(mb, "maps/e709.hex"), "--names", nf] + pool_args)))
        add(compare_names("names e709 (chain)", names709, tool.run(["--map", base, "--apply-inc", mincs, "--epoch", 709, "--names", nf] + pool_args)))
    res = Result("pg tables of the states of public/mapb")
    resj = Result("state dump against ceph osd dump of public/mapb")
    resc = Result("state dump chain against full map of public/mapb")
    for st in index["states"]:
        sj = json.load(open(os.path.join(mb, st["file"])))
        ep = st["epoch"]
        pools_in = sorted({int(k.split(".")[0]) for k in sj["pgs"]})
        dump_pools = {p["pool"]: p["pool_name"] for p in sj["dump"]["pools"]}
        truth = truth_from_table(sj["pgs"])
        for pid in pools_in:
            pname = dump_pools[pid]
            rc, out, err = tool.run_full(["--map", base, "--apply-inc", mincs, "--epoch", ep, "--pool", pname, "--dump-pgs"])
            if rc == 1 and "WR_E_MAP_RESYNC" in err and st.get("full_map"):
                # the chain cannot follow a rename into a name it never tracked (a client takes a full map); use the full map
                out = tool.run(["--map", os.path.join(mb, st["full_map"]), "--pool", pname, "--dump-pgs"], expect=(0, 3))
                res.notes.append("%s pool %s: the chain asks for a full map (renamed pool); compared from the full map" % (st["label"], pname))
            elif rc not in (0, 3):
                raise SystemExit("%s pool %s: wr-maporacle exit %d: %s" % (st["label"], pname, rc, err[:400]))
            res.merge(compare_pgs("%s pool %d" % (st["label"], pid), truth, out, pools={pid}))
            if st.get("full_map"):
                out = tool.run(["--map", os.path.join(mb, st["full_map"]), "--pool", pname, "--dump-pgs"], expect=(0, 3))
                res.merge(compare_pgs("%s pool %d (full map)" % (st["label"], pid), truth, out, pools={pid}))
        # the compact state against the monitor's own ceph osd dump (tracked pools = the eight of the name oracle that exist)
        if st.get("full_map"):
            out = tool.run(["--map", os.path.join(mb, st["full_map"]), "--dump-state"] + pool_args)
        else:
            rc, out, err = tool.run_full(["--map", base, "--apply-inc", mincs, "--epoch", ep, "--dump-state"] + pool_args)
            if rc != 0 and "WR_E_MAP_RESYNC" not in err:
                raise SystemExit("%s: wr-maporacle exit %d: %s" % (st["label"], rc, err[:400]))
        blk = state_blocks(out).get(ep)
        if blk is None:
            resj.notes.append("%s: no block for epoch %d (the chain stops at a renamed pool)" % (st["label"], ep))
            continue
        resj.merge(compare_state_json(st["label"], blk, sj["dump"]))
    add(res)
    add(resj)
    # chain against full maps: one chain run, every full map of the vectors
    # the chain stops at epoch 848, where a tracked name moves to a pool the chain never tracked (a client takes a full map there);
    # every full map before it is compared with the chain, the later ones with a chain that tracks the renamed pool from the start
    rc, chain, err = tool.run_full(["--map", base, "--apply-inc", mincs, "--dump-state"] + pool_args)
    if rc != 0 and "WR_E_MAP_RESYNC" not in err:
        raise SystemExit("chain dump: wr-maporacle exit %d: %s" % (rc, err[:400]))
    for f in sorted(os.listdir(os.path.join(mb, "maps"))):
        out = tool.run(["--map", os.path.join(mb, "maps", f), "--dump-state"] + pool_args)
        resc.merge(compare_state("chain vs %s" % f, chain, out))
    add(resc)
    res = Result("offline osdmaps of public/mapb")
    for om in index["osdmaps"]:
        pj = json.load(open(os.path.join(mb, om["pgs"])))
        out = tool.run(["--map", os.path.join(mb, om["osdmap"]), "--pool", "rbd", "--dump-pgs"], expect=(0, 3))
        res.merge(compare_pgs(om["name"], truth_from_table(pj["pgs"]), out, pools={1}))
    add(res)
    res = Result("crushtool runs of the 18 offline CRUSH maps")
    for cm in index["crush"]:
        mj = json.load(open(os.path.join(mb, cm["mappings"])))
        for rn, run in sorted(mj["runs"].items()):
            res.merge(_crush_run(tool, os.path.join(mb, cm["crush"]), "%s %s" % (cm["name"], rn), run, run["x_to_result"]))
    add(res)
    res = Result("crushtool runs of public/crushleg")
    cl = os.path.join(vec, "public/crushleg")
    for f in sorted(os.listdir(cl)):
        if f.endswith(".mappings.json"):
            mj = json.load(open(os.path.join(cl, f)))
            for rn, run in sorted(mj["runs"].items()):
                res.merge(_crush_run(tool, os.path.join(cl, f.replace(".mappings.json", ".crush.hex")), "%s %s" % (f, rn), run, run["x_to_result"]))
    add(res)

    negative_tests(tool, vec, total, add)

    # ---- the verdict -----------------------------------------------------------------------------------------------------
    total.label = "selftest TOTAL (%d tool runs)" % tool.runs
    sys.stdout.write(total.line() + "\n")
    if total.compared < 15000:
        sys.stdout.write("  too few comparisons (%d): a data set was skipped\n" % total.compared)
        return 1
    return 1 if total.mismatches else 0


def _crush_run(tool, crush_file, label, run, results):
    args = ["--crush", crush_file, "--rule", run["rule"], "--num-rep", run["num_rep"], "--min-x", run["min_x"], "--max-x", run["min_x"] + len(results) - 1]
    if run.get("pool_id") not in (None, -1):
        args += ["--pool-id", run["pool_id"]]
    for dev, w in sorted(run.get("weights", {}).items(), key=lambda kv: int(kv[0])):
        args += ["--weight", dev, w]
    truth = crush_truth_text(run["rule"], [(run["min_x"] + i, v) for i, v in enumerate(results)])
    return compare_crush(label, truth, tool.run(args))


def negative_tests(tool, vec, total, add):
    """the comparators must notice damage: a pass with nothing compared or with changed output would hide a broken tool"""
    r = Result("negative tests (every one must be detected)")
    gt = os.path.join(vec, "public/gt")
    good = tool.run(["--map", os.path.join(gt, "osdmap.bin"), "--pool", "winrbd", "--dump-pgs"])
    truth = truth_from_text(open(os.path.join(gt, "osdmaptool-test-map-pgs-dump-all.pool2.txt")).read(), 2)
    lines = good.splitlines()

    def expect_detected(what, res):
        r.compared += 1
        if not res.mismatches:
            r.bad("%s was NOT detected" % what)

    expect_detected("a PG line with its up set reversed", compare_pgs("neg", truth, "\n".join([lines[0].replace("up ([", "up ([99,", 1)] + lines[1:]) + "\n", {2}))
    expect_detected("a missing PG line", compare_pgs("neg", truth, "\n".join(lines[1:]) + "\n", {2}))
    expect_detected("an extra PG line", compare_pgs("neg", truth, good + "2.ff raw ([0], p0) up ([0], p0) acting ([0], p0)\n", {2}))
    expect_detected("a changed acting primary", compare_pgs("neg", truth, good.replace(") acting ([", ") acting ([", 1).replace("p0)\n", "p1)\n", 1), {2}))
    expect_detected("a garbage line", compare_pgs("neg", truth, good + "hello\n", {2}))
    crush_txt = open(os.path.join(gt, "crushtool-tests/rule1.rep3.x0-9999.txt")).read()
    crush_out = tool.run(["--crush", os.path.join(gt, "crush.bin"), "--rule", 1, "--num-rep", 3, "--min-x", 0, "--max-x", 9999])
    expect_detected("a changed CRUSH line", compare_crush("neg", crush_txt, crush_out.replace("x 17 ", "x 17 [0,0] ", 1)))
    expect_detected("a short CRUSH output", compare_crush("neg", crush_txt, "\n".join(crush_out.splitlines()[:-1]) + "\n"))
    names = names_from_json(os.path.join(vec, "osdmap/placement-names-e42.json"))
    with tempfile.TemporaryDirectory() as td:
        nf = os.path.join(td, "n.txt")
        open(nf, "w").write(names_batch(names, {1: ".mgr", 2: "winrbd"}))
        out = tool.run(["--map", os.path.join(vec, "osdmap/full-e42.hex"), "--names", nf, "--pool", ".mgr", "--pool", "winrbd"])
        ol = out.splitlines()
        ol[5] = ol[5].replace("-> pg ", "-> pg 9", 1)
        expect_detected("a changed raw pgid of an object line", compare_names("neg", names, "\n".join(ol) + "\n"))
        expect_detected("a missing object line", compare_names("neg", names, "\n".join(ol[:-1]) + "\n"))
    chain = tool.run(["--map", os.path.join(vec, "osdmap/full-e42.hex"), "--apply-inc", os.path.join(vec, "osdmap/incrementals.hex"), "--dump-state", "--pool", "winrbd"])
    expect_detected("a changed OSD weight in a state block", compare_state("neg", chain, chain.replace("weight 65536", "weight 65535", 1)))
    add(r)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("names")
    p.add_argument("--truth-jsonl")
    p.add_argument("--truth-names-json")
    p.add_argument("--ours", required=True)
    p.add_argument("--label", default="names")
    p = sub.add_parser("pgs")
    p.add_argument("--truth-text")
    p.add_argument("--truth-json")
    p.add_argument("--pool-id", type=int)
    p.add_argument("--ours", required=True)
    p.add_argument("--label", default="pgs")
    p = sub.add_parser("crush")
    p.add_argument("--truth", required=True)
    p.add_argument("--ours", required=True)
    p.add_argument("--label", default="crush")
    p = sub.add_parser("state")
    p.add_argument("--chain", required=True)
    p.add_argument("--full", required=True)
    p.add_argument("--epoch", type=int)
    p.add_argument("--label", default="state")
    p = sub.add_parser("selftest")
    p.add_argument("--tool", required=True)
    p.add_argument("--vectors", required=True)
    a = ap.parse_args()

    if a.cmd == "selftest":
        return selftest(a.tool, a.vectors)
    if a.cmd == "names":
        names = names_from_jsonl(a.truth_jsonl) if a.truth_jsonl else names_from_json(a.truth_names_json)
        res = compare_names(a.label, names, open(a.ours).read())
    elif a.cmd == "pgs":
        if a.truth_json:
            d = json.load(open(a.truth_json))
            truth = truth_from_table(d["pgs"])
        else:
            truth = truth_from_text(open(a.truth_text).read(), a.pool_id)
        res = compare_pgs(a.label, truth, open(a.ours).read(), None if a.pool_id is None else {a.pool_id})
    elif a.cmd == "crush":
        res = compare_crush(a.label, open(a.truth).read(), open(a.ours).read())
    else:
        res = compare_state(a.label, open(a.chain).read(), open(a.full).read(), a.epoch)
    res.report()
    return 1 if res.mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
