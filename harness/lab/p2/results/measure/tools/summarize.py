#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""summarize.py - the tables of the exit measurements, computed from the evidence directories (never typed by hand).

  summarize.py runs RUNSDIR                 one line per run directory: verdict, what it was
  summarize.py read RUNSDIR [GROUP...]      sequential read throughput by command size, per group (default: every group that ran the read plan)
  summarize.py lat RUNSDIR [GROUP...]       single-command latency (the latency series with no gap), per group
  summarize.py write RUNSDIR [GROUP...]     copy runs: write throughput by command size, per group (with the capture's numbers when there is one)
  summarize.py writecap RUNSDIR [GROUP...]  copy runs with a capture (risk R6): the segment the guest sent, the time between its segments, the time to the acknowledgement, the
                                            rate that stop-and-wait gives (MSS / gap), the rate measured, and how many commands of each size failed
  summarize.py login RUNSDIR [GROUP...]     boot runs (mboot.sh): seconds from the start of the run script to GRUB, the kernel, the table check, the root marker and the login
                                            prompt (a WinPE run: to its marker), per group
  summarize.py heap RUNSDIR                 iPXE's heap maximum (DEBUG=malloc) and the stack marks of the instrumented runs, per group
  summarize.py idle RUNSDIR [GROUP...]      the first command after an idle gap, per group and gap, against the control series
  summarize.py krbd RUNSDIR [LABEL...]      the kernel client's passes (krbd.sh runs), by mode and block size
  summarize.py sizes SIZESDIR               image sizes with and without the driver (SIZESDIR has drv/sizes.txt and pristine/sizes.txt of build-variants.sh sizes)
  summarize.py all RUNSDIR                  everything above, as markdown on standard output
  summarize.py selftest

A GROUP is a run label without its trailing "-N" (rd-def-1, rd-def-2, rd-def-3 are the group rd-def). Only runs whose verdict is PASS are summed up; the
others are listed with the reason, and a figure that rests on fewer than three passing runs says so ("n=2"). A figure is the median of its passes with the
smallest and the largest in brackets; the number of passes is n.
"""
import glob, json, os, re, statistics, sys


def load_runs(runs):
    out = []
    for d in sorted(glob.glob(os.path.join(runs, "*"))):
        fp = os.path.join(d, "facts.json")
        vp = os.path.join(d, "verdict.txt")
        if not (os.path.isfile(fp) and os.path.isfile(vp)):
            continue
        verdict = open(vp).read().split("\n")
        facts = json.load(open(fp))
        plan = {}
        pp = os.path.join(d, "plan.json")
        if os.path.isfile(pp):
            plan = json.load(open(pp))
        name = os.path.basename(d)
        out.append(dict(name=name, group=re.sub(r"-\d+$", "", name), ok=verdict[0] == "PASS", verdict=verdict, facts=facts, plan=plan, dir=d))
    return out


def stat(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None
    return dict(n=len(xs), median=statistics.median(xs), min=min(xs), max=max(xs))


def fmt(s, digits=1, unit=""):
    if s is None:
        return "-"
    return "%.*f%s (%.*f - %.*f), n=%d" % (digits, s["median"], unit, digits, s["min"], digits, s["max"], s["n"])


def groups_of(runs, plan_kind=None, wanted=None):
    g = {}
    for r in runs:
        if plan_kind and r["plan"].get("plan") != plan_kind:
            continue
        if wanted and r["group"] not in wanted:
            continue
        g.setdefault(r["group"], []).append(r)
    return g


def warm_ids(r):
    return {str(x["id"]) for x in r["plan"].get("records", []) if x["note"].startswith("warm")}


def read_stats(runs, wanted=None):
    res = {}
    for gname, rs in groups_of(runs, "read", wanted).items():
        good = [r for r in rs if r["ok"]]
        cell = {}
        for cmd in (127, 2048, 8192):
            xs = []
            ms = []
            for r in good:
                skip = warm_ids(r)
                for sid, st in r["facts"]["steps"].items():
                    if sid in skip or st["type"] != "R" or st["cmd"] != cmd:
                        continue
                    xs.append(st.get("wall_mibs"))
                    ms.append(st.get("read_cmd_ms"))
            cell[cmd] = dict(mibs=stat(xs), cmd_ms=stat(ms))
        res[gname] = dict(runs=len(rs), passed=len(good), failed=[(r["name"], [x for x in r["verdict"] if x.startswith("FAIL ")][:2]) for r in rs if not r["ok"]], cells=cell)
    return res


def lat_stats(runs, wanted=None):
    res = {}
    for gname, rs in groups_of(runs, None, wanted).items():
        good = [r for r in rs if r["ok"] and r["plan"].get("plan") in ("read", "idle")]
        xs = []
        for r in good:
            for sid, l in r["facts"]["lat"].items():
                if l["gap"] == 0:
                    xs += [x * 1000 for x in l["secs"]]
        if xs:
            xs.sort()
            res[gname] = dict(runs=len(good), n=len(xs), median=statistics.median(xs), p90=xs[int(0.9 * (len(xs) - 1))], min=xs[0], max=xs[-1])
    return res


def write_stats(runs, wanted=None):
    res = {}
    for gname, rs in groups_of(runs, "write", wanted).items():
        good = [r for r in rs if r["ok"]]
        cell = {}
        for cmd in (127, 2048, 8192):
            w, wm, rd = [], [], []
            for r in good:
                for sid, st in r["facts"]["steps"].items():
                    if st["type"] == "C" and st["cmd"] == cmd:
                        w.append(st.get("write_mibs"))
                        wm.append(st.get("write_cmd_ms"))
                        rd.append(st.get("read_mibs"))
            cell[cmd] = dict(write_mibs=stat(w), write_cmd_ms=stat(wm), read_mibs=stat(rd))
        cap = []
        for r in good:
            cp = os.path.join(r["dir"], "capture.json")
            if os.path.isfile(cp):
                cap.append(json.load(open(cp)))
        res[gname] = dict(runs=len(rs), passed=len(good), failed=[(r["name"], [x for x in r["verdict"] if x.startswith("FAIL ")][:2]) for r in rs if not r["ok"]], cells=cell, captures=cap,
                          good_runs=good)
    return res


def idle_stats(runs, wanted=None):
    res = {}
    for gname, rs in groups_of(runs, "idle", wanted).items():
        good = [r for r in rs if r["ok"]]
        gaps = {}
        ctl = []
        for r in good:
            for sid, l in sorted(r["facts"]["lat"].items(), key=lambda kv: int(kv[0])):
                secs = [x * 1000 for x in l["secs"]]
                if l["gap"] == 0:
                    ctl += secs
                else:
                    g = gaps.setdefault(l["gap"], dict(first=[], later=[]))
                    g["first"].append(secs[0])
                    g["later"] += secs[1:]
        res[gname] = dict(runs=len(rs), passed=len(good), failed=[(r["name"], [x for x in r["verdict"] if x.startswith("FAIL ")][:2]) for r in rs if not r["ok"]], control=stat(ctl),
                          gaps={g: dict(first=stat(v["first"]), later=stat(v["later"])) for g, v in sorted(gaps.items())})
    return res


KRBD_SERIES = (("krbd", "kernel client in the lab VM (loopback)"), ("kg", "kernel client in a guest on the layer 2 (same path as the iPXE guest)"))


def krbd_stats(runs_dir, labels=None):
    """KRBD lines of krbd.sh runs (series 'krbd') and mguest.sh runs (series 'kg') -> {series: {mode: {bs: stat}}}; only runs whose verdict is PASS (kg) count."""
    rows = {}
    for series, _ in KRBD_SERIES:
        for d in sorted(glob.glob(os.path.join(runs_dir, series + "-[0-9]*"))):
            lab = os.path.basename(d)
            if labels and lab not in labels and series not in labels:
                continue
            p = os.path.join(d, "krbd.txt")
            vp = os.path.join(d, "verdict.txt")
            if not os.path.isfile(p):
                continue
            if os.path.isfile(vp) and not open(vp).read().startswith("PASS"):
                continue
            for ln in open(p):
                m = re.match(r"KRBD mode=(\S+) bs=(\d+) run=(\d+) bytes=(\d+) secs=([\d.]+) mibs=([\d.]+)", ln)
                if m:
                    mode = m.group(1)
                    rows.setdefault((series, mode, int(m.group(2))), []).append(float(m.group(6)))
    out = {}
    for (series, mode, bs), xs in rows.items():
        out.setdefault(series, {}).setdefault(mode, {})[bs] = stat(xs)
    return out


def md_sizes(sizes_dir):
    def load(g):
        d = {}
        for ln in open(os.path.join(sizes_dir, g, "sizes.txt")):
            f = ln.split()
            if len(f) >= 2 and f[1].isdigit():
                d[f[0]] = int(f[1])
        return d
    drv, pri = load("drv"), load("pristine")
    order = ["x86_64-efi/ipxe.efi", "x86_64-pcbios/undionly.kpxe", "x86_64-pcbios/ipxe.pxe", "x86_64-pcbios/ipxe.usb", "x86_64-pcbios/ipxe.iso",
             "i386-pcbios/undionly.kpxe", "i386-pcbios/ipxe.pxe", "i386-pcbios/ipxe.usb", "i386-pcbios/ipxe.iso"]
    lines = ["| image | without the driver (bytes) | with the driver (bytes) | added (bytes) | added |", "|---|---|---|---|---|"]
    for k in order:
        if k in drv and k in pri:
            lines.append("| `%s` | %s | %s | %s | %.1f %% |" % (k, format(pri[k], ","), format(drv[k], ","), format(drv[k] - pri[k], ","), 100.0 * (drv[k] - pri[k]) / pri[k]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# text

def md_read(runs, wanted=None):
    rs = read_stats(runs, wanted)
    lines = ["| group | runs (passed) | 127 sectors (63.5 KiB) MiB/s | 2,048 sectors (1 MiB) MiB/s | 8,192 sectors (4 MiB) MiB/s |", "|---|---|---|---|---|"]
    for g, v in sorted(rs.items()):
        lines.append("| %s | %d (%d) | %s | %s | %s |" % (g, v["runs"], v["passed"], fmt(v["cells"][127]["mibs"]), fmt(v["cells"][2048]["mibs"]), fmt(v["cells"][8192]["mibs"])))
        for name, why in v["failed"]:
            lines.append("| %s: NOT counted | | %s | | |" % (name, why[0][5:] if why else ""))
    return "\n".join(lines)


def md_lat(runs, wanted=None):
    ls = lat_stats(runs, wanted)
    lines = ["| group | runs | reads | median ms | p90 ms | min - max ms |", "|---|---|---|---|---|---|"]
    for g, v in sorted(ls.items()):
        lines.append("| %s | %d | %d | %.1f | %.1f | %.1f - %.1f |" % (g, v["runs"], v["n"], v["median"], v["p90"], v["min"], v["max"]))
    return "\n".join(lines)


def md_write(runs, wanted=None):
    ws = write_stats(runs, wanted)
    lines = ["| group | runs (passed) | 127 sectors MiB/s | 1 MiB MiB/s | 4 MiB MiB/s | time per 127-sector write ms | operations resent / session resets (per run) |", "|---|---|---|---|---|---|---|"]
    for g, v in sorted(ws.items()):
        rs = [(r["facts"].get("info") or {}) for r in v.get("good_runs", [])]
        resent = "/".join(str(i.get("ops_resent", "?")) for i in rs)
        resets = "/".join(str(i.get("session_resets", "?")) for i in rs)
        lines.append("| %s | %d (%d) | %s | %s | %s | %s | %s ; %s |" % (g, v["runs"], v["passed"], fmt(v["cells"][127]["write_mibs"], 3), fmt(v["cells"][2048]["write_mibs"], 3),
                                                                      fmt(v["cells"][8192]["write_mibs"], 3), fmt(v["cells"][127]["write_cmd_ms"], 1), resent, resets))
    return "\n".join(lines)


def writecap_stats(runs, wanted=None):
    res = {}
    for gname, rs in groups_of(runs, "write", wanted).items():
        gap, ack, model, mss, infl, ge30 = [], [], [], [], [], []
        flows = 0                             # the OSD connections that carried the writes; "infl" only has those whose bytes in flight were measured
        fails = {127: 0, 2048: 0, 8192: 0}
        total = {127: 0, 2048: 0, 8192: 0}
        for r in rs:                          # a failed command is a result of a write run, so every run counts here
            for st in r["facts"]["steps"].values():
                if st["type"] == "C" and st["cmd"] in fails:
                    total[st["cmd"]] += 1
                    fails[st["cmd"]] += 1 if st["errs"] else 0
            cp = os.path.join(r["dir"], "capture.json")
            if os.path.isfile(cp):
                for c in json.load(open(cp)).values():
                    if c["segments"] >= 5000:         # the OSD connections that carried the writes
                        flows += 1
                        gap.append(c["gap_median_ms"])
                        ack.append(c.get("ack_delay_median_ms"))
                        model.append(c["model_mibs"])
                        mss.append(c["mss"])
                        # a flow that sent data has at least that segment in flight: 0 (or null) is a capture that began in the middle of the connection (captan.py), not a result
                        if c.get("inflight_max_bytes"):
                            infl.append(c["inflight_max_bytes"])
                        if c.get("ack_delay_ge_30ms_pct") is not None:
                            ge30.append(c["ack_delay_ge_30ms_pct"])
        res[gname] = dict(runs=len(rs), gap=stat(gap), ack=stat(ack), model=stat(model), mss=max(mss) if mss else None, inflight=max(infl) if infl else None,
                          ge30=max(ge30) if ge30 else None, fails=fails, total=total, flows=flows, flows_inflight=len(infl))
    return res


def md_writecap(runs, wanted=None):
    ws = writecap_stats(runs, wanted)
    lines = ["| group | runs | MSS seen (bytes) | most bytes in flight (flows measured) | median time between segments ms | median time to the ACK ms | ACKs at 30 ms or more (worst flow) % | MSS / gap MiB/s | commands that failed (127 / 1 MiB / 4 MiB sectors) |",
             "|---|---|---|---|---|---|---|---|---|"]
    for g, v in sorted(ws.items(), key=lambda kv: (len(kv[0]), kv[0])):
        f = v["fails"]
        t = v["total"]
        lines.append("| %s | %d | %s | %s (%d of %d) | %s | %s | %s | %s | %d of %d / %d of %d / %d of %d |" % (g, v["runs"], v["mss"], v["inflight"], v["flows_inflight"], v["flows"], fmt(v["gap"], 2), fmt(v["ack"], 2),
                                                                                         "%.1f" % v["ge30"] if v["ge30"] is not None else "-", fmt(v["model"], 2), f[127], t[127], f[2048], t[2048], f[8192], t[8192]))
    return "\n".join(lines)


def login_stats(runs, wanted=None):
    res = {}
    for r in runs:
        if r["facts"].get("kind") != "boot":
            continue
        if wanted and r["group"] not in wanted:
            continue
        g = res.setdefault(r["group"], dict(runs=[], failed=[]))
        if r["ok"]:
            g["runs"].append(r)
        else:
            g["failed"].append((r["name"], [x for x in r["verdict"] if x.startswith("FAIL ")][:2]))
    out = {}
    for name, g in res.items():
        d = {}
        for st in ("ipxe-script", "grub", "kernel-up", "table-check-done", "root-ok", "login", "marker"):
            d[st] = stat([r["facts"]["stages"].get(st) for r in g["runs"]])
        d["runs"] = len(g["runs"]) + len(g["failed"])
        d["passed"] = len(g["runs"])
        d["failed"] = g["failed"]
        d["heap_kb"] = [h for r in g["runs"] for h in r["facts"].get("heap_kb", [])]
        out[name] = d
    return out


def md_login(runs, wanted=None):
    ls = login_stats(runs, wanted)
    lines = ["| group | runs (passed) | GRUB s | kernel s | table checked s | root on the image s | login prompt / WinPE marker s |", "|---|---|---|---|---|---|---|"]
    for g, d in sorted(ls.items()):
        last = d["marker"] if d["marker"] else d["login"]
        lines.append("| %s | %d (%d) | %s | %s | %s | %s | %s |" % (g, d["runs"], d["passed"], fmt(d["grub"]), fmt(d["kernel-up"]), fmt(d["table-check-done"]), fmt(d["root-ok"]), fmt(last)))
        for name, why in d["failed"]:
            lines.append("| %s: NOT counted | | %s | | | | |" % (name, why[0][5:] if why else ""))
    return "\n".join(lines)


HEAP_GROUPS = (("heap-base", "BIOS, nothing hooked (iPXE alone)"), ("heap-probe", "BIOS, the probe image hooked, a few small reads"),
               ("inst", "BIOS, 128 MiB read in 127-sector, 1 MiB and 4 MiB commands, twice (the read plan)"), ("r10-loop", "BIOS, 153 hooks, 4 sessions created (the R10 loop)"),
               ("heap-efix", "UEFI, hook and one file read from the ESP"), ("heap-efi", "UEFI, a whole boot to the hand-over to GRUB's kernel"))


def md_heap(runs):
    by = {}
    for r in runs:
        by.setdefault(r["group"], []).append(r)
    lines = ["| group | what | runs (passed) | heap maximum kB, per run | stack high-water (iPXE / core) bytes |", "|---|---|---|---|---|"]
    for g, what in HEAP_GROUPS:
        rs = by.get(g, [])
        good = [r for r in rs if r["ok"]]
        if not rs:
            continue
        hv = ["/".join(str(h) for h in r["facts"].get("heap_kb", [])) or "-" for r in good]
        st = set()
        for r in good:
            for a in r["facts"].get("stack", [])[-1:]:
                st.add("%d of %d" % (a[0], a[1]))
            for a in r["facts"].get("core_stack", [])[-1:]:
                st.add("%d of %d" % (a[0], a[1]))
        lines.append("| %s | %s | %d (%d) | %s | %s |" % (g, what, len(rs), len(good), ", ".join(hv), "; ".join(sorted(st)) or "-"))
    return "\n".join(lines)


def md_idle(runs, wanted=None):
    ids = idle_stats(runs, wanted)
    lines = ["| group | runs (passed) | control (no gap) ms | gap s | first read after the gap ms | the reads after it ms |", "|---|---|---|---|---|---|"]
    for g, v in sorted(ids.items()):
        first = True
        for gap, x in v["gaps"].items():
            lines.append("| %s | %s | %s | %s | %s | %s |" % (g if first else "", "%d (%d)" % (v["runs"], v["passed"]) if first else "", fmt(v["control"], 1) if first else "", gap,
                                                            fmt(x["first"], 1), fmt(x["later"], 1)))
            first = False
    return "\n".join(lines)


def md_krbd(runs_dir, labels=None):
    ks = krbd_stats(runs_dir, labels)
    names = dict(KRBD_SERIES)
    lines = ["| series | mode | 64 KiB MiB/s | 1 MiB MiB/s | 4 MiB MiB/s |", "|---|---|---|---|---|"]
    for series, _ in KRBD_SERIES:
        for mode in ("direct", "ra128k", "ra2048k"):
            if series in ks and mode in ks[series]:
                m = ks[series][mode]
                lines.append("| %s | %s | %s | %s | %s |" % (names[series], mode, fmt(m.get(65536)), fmt(m.get(1048576)), fmt(m.get(4194304))))
    return "\n".join(lines)


def md_runs(runs):
    lines = ["| run | verdict | plan | TSC GHz | calibration spread % |", "|---|---|---|---|---|"]
    for r in runs:
        f = r["facts"]
        kind = r["plan"].get("plan") or f.get("kind") or "-"
        lines.append("| %s | %s | %s | %s | %s |" % (r["name"], r["verdict"][0], kind, "%.3f" % (f["tsc_hz"] / 1e9) if f.get("tsc_hz") else "-",
                                                  "%.3f" % f["cal_spread_pct"] if f.get("cal_spread_pct") is not None else "-"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------------------------------------------------------------------------
# self-test

def _mk(tmp, name, plan, steps, lats=(), ok=True, plan_records=None):
    d = os.path.join(tmp, name)
    os.makedirs(d)
    facts = dict(tsc_hz=2.0e9, cal_spread_pct=0.01, steps=steps, lat={str(i): dict(gap=g, cmd=127, n=len(s), secs=s, ah=["00"] * len(s)) for i, g, s in lats}, info=None,
                 heap_kb=[], stack=[], core_stack=[])
    json.dump(facts, open(os.path.join(d, "facts.json"), "w"))
    open(os.path.join(d, "verdict.txt"), "w").write(("PASS\n" if ok else "FAIL\nFAIL step 4: the data check\n"))
    json.dump(dict(plan=plan, records=plan_records or []), open(os.path.join(d, "plan.json"), "w"))
    return d


def selftest():
    import tempfile
    fails = []

    def check(ok, what):
        if not ok:
            fails.append(what)
        print(("ok   " if ok else "FAIL ") + what)

    with tempfile.TemporaryDirectory() as t:
        recs = [dict(id=2, note="warm pass"), dict(id=4, note="x")]
        for i, v in enumerate((10.0, 12.0, 11.0), 1):
            steps = {"2": dict(type="R", cmd=2048, wall_mibs=99.0, read_cmd_ms=1.0), "4": dict(type="R", cmd=127, wall_mibs=v, read_cmd_ms=5.0 + i)}
            _mk(t, "rd-a-%d" % i, "read", steps, plan_records=recs)
        _mk(t, "rd-a-4", "read", {"4": dict(type="R", cmd=127, wall_mibs=500.0, read_cmd_ms=0.1)}, ok=False, plan_records=recs)
        _mk(t, "rd-b-1", "read", {"4": dict(type="R", cmd=127, wall_mibs=20.0, read_cmd_ms=3.0)}, plan_records=recs)
        runs = load_runs(t)
        rs = read_stats(runs)
        c = rs["rd-a"]["cells"][127]["mibs"]
        check(c["n"] == 3 and c["median"] == 11.0 and c["min"] == 10.0 and c["max"] == 12.0, "median, min, max over the three passing runs (%s)" % c)
        check(rs["rd-a"]["runs"] == 4 and rs["rd-a"]["passed"] == 3 and rs["rd-a"]["failed"][0][0] == "rd-a-4", "a failed run is listed, not summed")
        check(rs["rd-a"]["cells"][2048]["mibs"] is None, "the warm pass is not a result (and an absent cell is None)")
        check("NOT counted" in md_read(runs) and "the data check" in md_read(runs) and "n=3" in md_read(runs) and "n=1" in md_read(runs), "the markdown says n and names the run that did not count")
    with tempfile.TemporaryDirectory() as t:
        _mk(t, "idle-x-1", "idle", {}, lats=[(3, 0, [0.004, 0.005]), (4, 40, [0.5, 0.01, 0.02]), (5, 120, [0.7, 0.01, 0.01]), (6, 0, [0.004])])
        _mk(t, "idle-x-2", "idle", {}, lats=[(3, 0, [0.006]), (4, 40, [0.3, 0.01]), (5, 120, [0.9, 0.02]), (6, 0, [0.004])])
        _mk(t, "idle-x-3", "idle", {}, lats=[(3, 0, [0.005]), (4, 40, [0.4, 0.01]), (5, 120, [0.8, 0.02])])
        ids = idle_stats(load_runs(t))
        g = ids["idle-x"]
        check(g["control"]["n"] == 6 and abs(g["control"]["median"] - 4.5) < 1e-9, "the control series pools the reads with no gap (%s)" % g["control"])
        check(g["gaps"][40]["first"]["n"] == 3 and abs(g["gaps"][40]["first"]["median"] - 400.0) < 1e-6, "first read after the 40 s gap: median of the three first reads (ms)")
        check(g["gaps"][120]["later"]["n"] == 4, "the reads after the first one are kept apart")
    with tempfile.TemporaryDirectory() as t:
        steps = {"2": dict(type="C", cmd=127, errs=0, write_mibs=0.5, write_cmd_ms=120.0, read_mibs=9.0)}
        _mk(t, "wr-d0-1", "write", steps)
        _mk(t, "wr-d0-2", "write", steps)
        ws = write_stats(load_runs(t))
        check(ws["wr-d0"]["cells"][127]["write_mibs"]["median"] == 0.5 and ws["wr-d0"]["passed"] == 2, "write throughput is taken from the write-time sum")
        flow = lambda infl: dict(segments=6000, gap_median_ms=0.5, ack_delay_median_ms=0.1, model_mibs=2.0, mss=1208, inflight_max_bytes=infl, ack_delay_ge_30ms_pct=1.0)
        json.dump({"a:1": flow(0), "b:2": flow(1208), "c:3": flow(None)}, open(os.path.join(t, "wr-d0-1", "capture.json"), "w"))
        wc = writecap_stats(load_runs(t))["wr-d0"]
        check(wc["inflight"] == 1208 and wc["flows"] == 3 and wc["flows_inflight"] == 1, "negative control: a flow whose bytes in flight are 0 or null (a capture that began mid-connection) is not a measurement and is counted as such")
        check("1208 (1 of 3)" in md_writecap(load_runs(t)), "writecap markdown names how many flows the bytes in flight rest on")
        os.makedirs(os.path.join(t, "krbd-1"))
        os.makedirs(os.path.join(t, "kg-1"))
        open(os.path.join(t, "kg-1", "krbd.txt"), "w").write("KRBD mode=direct bs=65536 run=1 bytes=1 secs=1 mibs=8.00\n")
        open(os.path.join(t, "kg-1", "verdict.txt"), "w").write("FAIL\n")
        open(os.path.join(t, "krbd-1", "krbd.txt"), "w").write("# x\nKRBD mode=direct bs=65536 run=1 bytes=1 secs=1 mibs=50.00\nKRBD mode=direct bs=65536 run=2 bytes=1 secs=1 mibs=60.00\nKRBD mode=ra128k bs=1048576 run=1 bytes=1 secs=1 mibs=70.00\n")
        ks = krbd_stats(t)
        check(ks["krbd"]["direct"][65536]["median"] == 55.0 and ks["krbd"]["ra128k"][1048576]["n"] == 1, "krbd passes are grouped by mode and block size")
        check("kg" not in ks, "negative control: the passes of a guest run whose verdict is FAIL are not counted")
        check("direct" in md_krbd(t) and "n=2" in md_krbd(t), "krbd markdown")
    with tempfile.TemporaryDirectory() as t:
        for i, v in enumerate((60.0, 62.0, 61.0), 1):
            d = os.path.join(t, "login-uefi-pxe-%d" % i)
            os.makedirs(d)
            json.dump(dict(kind="boot", stages={"grub": 13.0, "kernel-up": 20.0, "root-ok": v - 5, "login": v}, heap_kb=[100 * i], result={}), open(os.path.join(d, "facts.json"), "w"))
            open(os.path.join(d, "verdict.txt"), "w").write("PASS\n")
            json.dump(dict(), open(os.path.join(d, "plan.json"), "w"))
        d = os.path.join(t, "login-uefi-pxe-4")
        os.makedirs(d)
        json.dump(dict(kind="boot", stages={"login": 1.0}, result={}), open(os.path.join(d, "facts.json"), "w"))
        open(os.path.join(d, "verdict.txt"), "w").write("FAIL\nFAIL the stage 'login' was seen (None)\n")
        json.dump(dict(), open(os.path.join(d, "plan.json"), "w"))
        lg = login_stats(load_runs(t))["login-uefi-pxe"]
        check(lg["passed"] == 3 and lg["runs"] == 4 and lg["login"]["median"] == 61.0 and lg["login"]["max"] == 62.0, "boot runs: the median and spread of the login time over the passing runs only")
        check("NOT counted" in md_login(load_runs(t)), "boot runs: the run that failed is named, not summed")
    with tempfile.TemporaryDirectory() as t:
        for g, base in (("drv", 1500), ("pristine", 1000)):
            os.makedirs(os.path.join(t, g))
            open(os.path.join(t, g, "sizes.txt"), "w").write("x86_64-efi/ipxe.efi %d abc\ni386-pcbios/ipxe.pxe %d def\n" % (base, base // 2))
        md = md_sizes(t)
        check("| `x86_64-efi/ipxe.efi` | 1,000 | 1,500 | 500 | 50.0 % |" in md and "i386-pcbios/ipxe.pxe" in md, "the sizes table: bytes with and without the driver, the difference and its share")
    print("selftest: %s" % ("PASS" if not fails else "FAIL (%d)" % len(fails)))
    return 0 if not fails else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) < 3:
        print(__doc__)
        return 2
    cmd, runs_dir = argv[1], argv[2]
    rest = argv[3:] or None
    runs = load_runs(runs_dir)
    if cmd == "runs":
        print(md_runs(runs))
    elif cmd == "read":
        print(md_read(runs, rest))
    elif cmd == "lat":
        print(md_lat(runs, rest))
    elif cmd == "write":
        print(md_write(runs, rest))
    elif cmd == "idle":
        print(md_idle(runs, rest))
    elif cmd == "heap":
        print(md_heap(runs))
    elif cmd == "login":
        print(md_login(runs, rest))
    elif cmd == "writecap":
        print(md_writecap(runs, rest))
    elif cmd == "krbd":
        print(md_krbd(runs_dir, rest))
    elif cmd == "sizes":
        print(md_sizes(runs_dir))
    elif cmd == "all":
        for title, text in (("Runs", md_runs(runs)), ("Sequential reads", md_read(runs)), ("Single-command latency", md_lat(runs)), ("Writes (copy runs)", md_write(runs)), ("The writes' TCP (capture)", md_writecap(runs)),
                            ("After an idle gap", md_idle(runs)), ("Time to login (boot runs)", md_login(runs)), ("Heap and stack marks", md_heap(runs)), ("Kernel client", md_krbd(runs_dir))):
            print("### %s\n\n%s\n" % (title, text))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
