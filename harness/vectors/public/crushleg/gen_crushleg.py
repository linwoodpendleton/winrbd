#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Generates the CRUSH maps and the crushtool ground truth of this directory (test crush.legacy).

  python3 gen_crushleg.py OUTDIR            # needs `sudo cephadm shell` (the cluster's own tool image); touches no cluster state

For each map it writes OUTDIR/<name>.txt (the text map this script produces), <name>.crush.hex (the same map compiled by
`crushtool -c`) and <name>.mappings.json (the results of `crushtool -i <map> --test --show-mappings`, one entry per run).
The offline tools run in the container only; the cluster, its pools, keys and OSD map are never read or changed.

The maps are about the legacy bucket algorithms (list, uniform) and the permutation fallback of the local-retry tunables:
  cl01  flat buckets of every size class, legacy tunables (2 / 5 / 19): the chooser answer itself (one replica, all devices in),
        retries through out devices (the draw number r grows), and the fallback (90 % of the devices out)
  cl02  the same with jewel tunables and buckets of 256, 257 and 300 items (the permutation chooser stops at 256)
  cl03  a mixed hierarchy (straw2 root, list racks, uniform hosts, unequal host weights), legacy tunables
  cl04  the same hierarchy, firefly-like tunables (no local retries, no fallback, vary_r 1, descend_once 1)
  cl05  the same hierarchy, odd tunables: local 3, fallback 2, total 30, vary_r 2, stable 1
"""
import json
import os
import subprocess
import sys
import tempfile

TUN = {
    "legacy": {"choose_local_tries": 2, "choose_local_fallback_tries": 5, "choose_total_tries": 19,
               "chooseleaf_descend_once": 0, "chooseleaf_vary_r": 0, "chooseleaf_stable": 0},
    "jewel": {"choose_local_tries": 0, "choose_local_fallback_tries": 0, "choose_total_tries": 50,
              "chooseleaf_descend_once": 1, "chooseleaf_vary_r": 1, "chooseleaf_stable": 1},
    "firefly": {"choose_local_tries": 0, "choose_local_fallback_tries": 0, "choose_total_tries": 50,
                "chooseleaf_descend_once": 1, "chooseleaf_vary_r": 1, "chooseleaf_stable": 0},
    "odd": {"choose_local_tries": 3, "choose_local_fallback_tries": 2, "choose_total_tries": 30,
            "chooseleaf_descend_once": 0, "chooseleaf_vary_r": 2, "chooseleaf_stable": 1},
}


class Lcg:
    def __init__(self, seed):
        self.s = seed & 0xffffffff

    def next(self, n):
        self.s = (self.s * 1664525 + 1013904223) & 0xffffffff
        return (self.s >> 8) % n


def w16(units):  # weights are multiples of 1/16, so the text value is exact
    return "%.5f" % (units / 16.0)


def header(tun, nd):
    t = TUN[tun]
    out = ["# begin crush map"]
    for k in ("choose_local_tries", "choose_local_fallback_tries", "choose_total_tries", "chooseleaf_descend_once",
              "chooseleaf_vary_r", "chooseleaf_stable"):
        out.append("tunable %s %d" % (k, t[k]))
    out.append("tunable straw_calc_version 1")
    out.append("tunable allowed_bucket_algs 54")
    out.append("")
    out.append("# devices")
    for d in range(nd):
        out.append("device %d osd.%d" % (d, d))
    out.append("")
    out.append("# types")
    for i, n in enumerate(("osd", "host", "rack", "root")):
        out.append("type %d %s" % (i, n))
    out.append("")
    return out


def bucket(kind, name, bid, alg, items, rng, equal):
    """items: list of (item name, weight in 1/16 units or None to draw one)."""
    out = ["%s %s {" % (kind, name), "\tid %d" % bid, "\talg %s" % alg, "\thash 0"]
    for it, w in items:
        if w is None:
            w = 16 if equal else 4 + rng.next(45)
        out.append("\titem %s weight %s" % (it, w16(w)))
    out.append("}")
    return out


def rule(rid, name, steps):
    out = ["rule %s {" % name, "\tid %d" % rid, "\ttype replicated"]
    out += ["\tstep " + s for s in steps]
    out.append("}")
    return out


def flat_map(name, tun, specs, nd, seed):
    """specs: (bucket name, alg, number of items); every bucket is a root over devices 0..n-1."""
    rng = Lcg(seed)
    txt = header(tun, nd)
    txt.append("# buckets")
    rules = []
    for i, (bn, alg, n) in enumerate(specs):
        items = [("osd.%d" % ((j + i * 3) % nd), None) for j in range(n)]
        txt += bucket("root", bn, -1 - i, alg, items, rng, alg in ("uniform",))
        rules.append((i, bn))
    txt.append("")
    txt.append("# rules")
    for i, bn in rules:
        txt += rule(i, "r%d_%s" % (i, bn), ["take " + bn, "choose firstn 0 type osd", "emit"])
    txt.append("")
    txt.append("# end crush map")
    return txt, [(i, bn) for i, bn in rules]


def mixed_map(name, tun, seed):
    rng = Lcg(seed)
    nd = 36
    txt = header(tun, nd)
    txt.append("# buckets")
    host_w = [16, 24, 12, 16, 32, 16, 20, 16, 8]  # per-device weight of each host (units of 1/16)
    hosts = []
    for h in range(9):
        items = [("osd.%d" % (h * 4 + k), host_w[h]) for k in range(4)]
        txt += bucket("host", "host%d" % h, -1 - h, "uniform", items, rng, True)
        hosts.append(("host%d" % h, 4 * host_w[h]))
    racks = []
    for r in range(3):
        items = hosts[r * 3:(r + 1) * 3]
        txt += bucket("rack", "rack%d" % r, -10 - r, "list", items, rng, False)
        racks.append(("rack%d" % r, sum(w for _, w in items)))
    txt += bucket("root", "root", -20, "straw2", racks, rng, False)
    txt.append("")
    txt.append("# rules")
    txt += rule(0, "r0_host", ["take root", "chooseleaf firstn 0 type host", "emit"])
    txt += rule(1, "r1_rack", ["take root", "chooseleaf firstn 0 type rack", "emit"])
    txt += rule(2, "r2_flat", ["take root", "choose firstn 0 type osd", "emit"])
    txt += rule(3, "r3_rack0", ["take rack0", "choose firstn 0 type osd", "emit"])
    txt += rule(4, "r4_two", ["take root", "choose firstn 2 type rack", "chooseleaf firstn 2 type host", "emit"])
    txt += rule(5, "r5_listrack", ["take rack1", "chooseleaf firstn 0 type host", "emit"])
    txt.append("")
    txt.append("# end crush map")
    return txt, nd


def out_set(nd, pct, salt):
    """devices that are out (weight 0) and some at half weight, as a dict dev -> weight."""
    w = {}
    for d in range(nd):
        v = ((d * 2654435761 + salt * 40503) >> 7) % 100
        if v < pct:
            w[d] = 0
        elif v < pct + 10 and pct < 90:
            w[d] = 0.5
    return w


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, **kw)


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    maps = {}  # name -> (text lines, runs, description)

    # cl01: flat buckets, legacy tunables
    sizes_l = [5, 16, 40]
    sizes_u = [1, 2, 3, 8, 16, 64, 256]
    specs = [("list%d" % n, "list", n) for n in sizes_l] + [("uni%d" % n, "uniform", n) for n in sizes_u]
    specs += [("list12", "list", 12), ("straw12", "straw", 12), ("straw2_12", "straw2", 12)]
    nd = 256
    txt, rules = flat_map("cl01", "legacy", specs, nd, 11)
    runs = {}
    for rid, bn in rules:
        runs["%s-in-n3" % bn] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": {}}
        runs["%s-in-n1" % bn] = {"rule": rid, "num_rep": 1, "min_x": 100, "weights": {}}
        runs["%s-half-n3" % bn] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": out_set(nd, 50, rid)}
        runs["%s-most-out-n2" % bn] = {"rule": rid, "num_rep": 2, "min_x": 0, "weights": out_set(nd, 90, rid + 3)}
    maps["cl01-flat-legacy-choosers"] = (txt, runs, "flat list, uniform, straw and straw2 buckets of 1 to 256 items, legacy tunables (local 2, fallback 5, total 19)", 96)

    # cl02: jewel tunables, large buckets
    specs = [("list256", "list", 256), ("list300", "list", 300), ("uni256", "uniform", 256), ("uni257", "uniform", 257),
             ("uni300", "uniform", 300), ("straw2_300", "straw2", 300)]
    nd = 300
    txt, rules = flat_map("cl02", "jewel", specs, nd, 23)
    runs = {}
    for rid, bn in rules:
        runs["%s-in-n3" % bn] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": {}}
        runs["%s-half-n3" % bn] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": out_set(nd, 50, rid + 9)}
    maps["cl02-jewel-large-buckets"] = (txt, runs, "list and uniform buckets of 256, 257 and 300 items, jewel tunables (no fallback)", 64)

    # cl03..cl05: the mixed hierarchy under three tunable profiles
    for nm, tun, dsc in (("cl03-mixed-legacy", "legacy", "straw2 root, list racks, uniform hosts of unequal weight; legacy tunables (local 2, fallback 5, total 19)"),
                         ("cl04-mixed-firefly", "firefly", "the same hierarchy; no local retries, no fallback, vary_r 1, descend_once 1"),
                         ("cl05-mixed-odd", "odd", "the same hierarchy; local 3, fallback 2, total 30, vary_r 2, stable 1")):
        txt, nd = mixed_map(nm, tun, 5)
        runs = {}
        for rid, rn in ((0, "host"), (1, "rack"), (2, "flat"), (3, "rack0"), (4, "two"), (5, "listrack")):
            runs["r%d_%s-in-n3" % (rid, rn)] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": {}}
            runs["r%d_%s-in-n1" % (rid, rn)] = {"rule": rid, "num_rep": 1, "min_x": 200, "weights": {}}
            runs["r%d_%s-40out-n3" % (rid, rn)] = {"rule": rid, "num_rep": 3, "min_x": 0, "weights": out_set(nd, 40, rid + 21)}
            runs["r%d_%s-75out-n4" % (rid, rn)] = {"rule": rid, "num_rep": 4, "min_x": 0, "weights": out_set(nd, 75, rid + 33)}
        maps[nm] = (txt, runs, dsc, 64)

    work = tempfile.mkdtemp(prefix="crushleg-")
    os.chmod(work, 0o755)
    script = ["set -e", "cd /work"]
    for nm, (txt, runs, dsc, nx) in maps.items():
        with open(os.path.join(work, nm + ".txt"), "w") as f:
            f.write("\n".join(txt) + "\n")
        script.append("crushtool -c %s.txt -o %s.bin" % (nm, nm))
        for rn, r in runs.items():
            wargs = " ".join("--weight %d %s" % (d, ("%g" % w)) for d, w in sorted(r["weights"].items()))
            script.append("crushtool -i %s.bin --test --show-mappings --rule %d --num-rep %d --min-x %d --max-x %d %s > run.%s.%s.txt"
                          % (nm, r["rule"], r["num_rep"], r["min_x"], r["min_x"] + nx - 1, wargs, nm, rn))
    with open(os.path.join(work, "run.sh"), "w") as f:
        f.write("\n".join(script) + "\n")
    sh(["sudo", "cephadm", "shell", "--mount", "%s:/work" % work, "--", "bash", "/work/run.sh"])

    for nm, (txt, runs, dsc, nx) in maps.items():
        blob = open(os.path.join(work, nm + ".bin"), "rb").read()
        res = {}
        for rn, r in runs.items():
            rows = []
            for line in open(os.path.join(work, "run.%s.%s.txt" % (nm, rn))):
                if not line.startswith("CRUSH rule"):
                    continue
                lst = line[line.index("[") + 1:line.index("]")]
                rows.append([int(v) for v in lst.split(",") if v.strip() != ""])
            assert len(rows) == nx, (nm, rn, len(rows))
            res[rn] = {"rule": r["rule"], "num_rep": r["num_rep"], "min_x": r["min_x"],
                       "weights": {str(d): w for d, w in sorted(r["weights"].items())}, "x_to_result": rows}
        hexs = blob.hex()
        with open(os.path.join(outdir, nm + ".crush.hex"), "w") as f:
            f.write("# SPDX-License-Identifier: MIT\n# CRUSH map %s (compiled by crushtool -c from %s.txt): %s\n" % (nm, nm, dsc))
            for i in range(0, len(hexs), 64):
                f.write(hexs[i:i + 64] + "\n")
        if len("\n".join(txt)) < 8192:  # the two large flat maps are reproducible from this script; their text is not kept
            with open(os.path.join(outdir, nm + ".txt"), "w") as f:
                f.write("\n".join(txt) + "\n")
        with open(os.path.join(outdir, nm + ".mappings.json"), "w") as f:
            json.dump({"map": nm, "description": dsc,
                       "crushtool": "crushtool -i <map> --test --show-mappings --rule R --num-rep N --min-x X --max-x X+n-1 [--weight DEV W ...]; "
                                    "`weights` are the --weight overrides (0 = out, 0.5 = half)",
                       "runs": res}, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        print("%s: %d runs, %d bytes of map" % (nm, len(res), len(blob)))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
