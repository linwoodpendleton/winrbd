#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""analyze.py - turn the serial console of one bench run (bench.S) into numbers.

  analyze.py run DIR [--plan PLAN.json]      DIR/serial.txt (+ DIR/plan.json) -> DIR/facts.json and DIR/verdict.txt (PASS / FAIL, then one line per check)
  analyze.py selftest                        run the built-in tests on synthetic consoles (what ctest measure.selftest does)

What a run's facts are:
  tsc_hz        the guest's TSC rate, from the calibration steps (Z): TSC delta over 91 BIOS ticks of 1,193,181.818 / 65,536 Hz. The two calibrations (before,
                after) are both kept; the rate used is their mean and their difference is a fact ("cal_spread_pct")
  steps[id]     per step: type, cmd, sectors, errs, seconds (wall, read, write), MiB/s, mean command time, the data check (sumA / sumB against the plan)
  lat[id]       per latency series: the per-read times in seconds, in order
  info          what "rbd-info" printed (counters, readahead, stack and arena marks), as numbers
  heap_kb       iPXE's "HEAP maximum usage NkB" (a DEBUG=malloc build)
  stack         the stack high-water marks the driver printed (iPXE's stack, the core's own stack)
  stalls        count of "the cluster has not answered" lines; errors: WRMS-ERR lines

The checks (verdict): the program started and finished, no WRMS-ERR line, every read step's sums equal the plan's, the calibration is stable (the two
rates within 2 %). A run without a plan has no sum check.
"""
import json, os, re, statistics, sys

TICK_HZ = 1193181.8181818182 / 65536.0
CAL_TICKS = 91


def kv(line):
    """'WRMS-STEP id=2 type=R ...' -> ('WRMS-STEP', {'id': '2', ...})"""
    parts = line.split()
    d = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            d[k] = v
    return parts[0], d


def h64(s):
    return int(s, 16)


ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def undouble(line):
    """On UEFI a build whose serial console also takes debug output prints every character twice (OVMF mirrors the firmware console to the same serial line):
    'HHEEAAPP  mmaaxxiimmuumm' -> 'HEAP maximum'. A line that is not made of doubled characters is returned as it is."""
    line = ANSI.sub("", line)
    if len(line) >= 4 and len(line) % 2 == 0 and all(line[i] == line[i + 1] for i in range(0, len(line), 2)):
        return line[::2]
    return line


def parse_console(text):
    cal, steps, lats, errs = [], {}, {}, []
    lat_meta = {}
    info_blocks = []
    cur = None
    heap = []
    stack = []
    core_stack = []
    stalls = 0
    other = []
    grows = []
    loop = []
    started = done = False
    for raw in text.replace("\r", "").split("\n"):
        line = undouble(raw.strip()).strip()
        if not line:
            continue
        if line.startswith("WRMS-START"):
            started = True
        elif line.startswith("WRMS-DONE"):
            done = True
            _, d = kv(line)
            if d.get("errs", "0") != "0":
                errs.append(line)
        elif line.startswith("WRMS-CAL"):
            _, d = kv(line)
            cal.append(dict(id=int(d["id"]), tsc0=h64(d["tsc0"]), tsc1=h64(d["tsc1"]), ticks=int(d["ticks"])))
        elif line.startswith("WRMS-STEP"):
            _, d = kv(line)
            steps[int(d["id"])] = d
        elif line.startswith("WRMS-LATR"):
            _, d = kv(line)
            lats.setdefault(int(d["id"]), []).append(dict(k=int(d["k"]), lba=int(d["lba"]), tsc=h64(d["tsc"]), ah=d["ah"]))
        elif line.startswith("WRMS-LAT"):
            _, d = kv(line)
            lat_meta[int(d["id"])] = dict(gap=int(d["gap"]), cmd=int(d["cmd"]), n=int(d["n"]))
        elif line.startswith("WRMS-ERR"):
            errs.append(line)
        elif line.startswith("WRLOOP-"):
            loop.append(line)
        elif line.startswith("WRMS-INFO-BEGIN"):
            cur = []
        elif line.startswith("WRMS-INFO-END"):
            if cur is not None:
                info_blocks.append(cur)
            cur = None
        else:
            m = re.search(r"HEAP maximum usage (\d+)kB", line)
            if m:
                heap.append(int(m.group(1)))
            m = re.search(r"rbd: stack high-water (\d+) of (\d+) bytes", line)
            if m:
                stack.append((int(m.group(1)), int(m.group(2))))
            m = re.search(r"rbd: core stack high-water (\d+) of (\d+) bytes", line)
            if m:
                core_stack.append((int(m.group(1)), int(m.group(2))))
            if "has not answered" in line:
                stalls += 1
            m = re.search(r"HEAP attempting to grow for (0x[0-9a-f]+) .*used (\d+)kB", line)
            if m:
                grows.append((int(m.group(1), 16), int(m.group(2))))
            if "HEAP failed to allocate" in line:
                other.append(line)
            if cur is not None and line.startswith("rbd:"):
                cur.append(line)
    if not heap:
        # a doubled console (see undouble) with the line not on a line of its own
        for m in re.finditer(r"HHEEAAPP\s+mmaaxxiimmuumm\s+uussaaggee\s+((?:\d\d)+)kkBB", ANSI.sub("", text)):
            heap.append(int(m.group(1)[::2]))
    return dict(cal=cal, steps=steps, lats=lats, lat_meta=lat_meta, errs=errs, info_blocks=info_blocks, heap=heap, stack=stack, core_stack=core_stack,
                stalls=stalls, other=other, grows=grows, started=started, done=done, loop=loop)


def parse_info(lines):
    """The numbers of one rbd-info block."""
    out = {}
    for ln in lines:
        m = re.search(r"session: (\d+) pumps, (\d+) cancels \(most rounds (\d+)\), (\d+) reopens, (\d+) stall closes", ln)
        if m:
            out.update(pumps=int(m.group(1)), cancels=int(m.group(2)), reopens=int(m.group(4)), stall_closes=int(m.group(5)))
        m = re.search(r"core stack: (\d+) of (\d+) bytes used", ln)
        if m:
            out["core_stack_used"] = int(m.group(1))
            out["core_stack_total"] = int(m.group(2))
        m = re.search(r"core: connections (\d+) \(most (\d+)\), arena (\d+) bytes, bulk (\d+) bytes", ln)
        if m:
            out.update(conns=int(m.group(1)), conns_most=int(m.group(2)), arena_used=int(m.group(3)), bulk_used=int(m.group(4)))
        m = re.search(r"osd: (\d+) ops done, (\d+) resent, (\d+) failed; in flight (\d+) \(most (\d+)\), requests (\d+) \(most (\d+)\); (\d+) session resets, zombies (\d+) of (\d+) bytes", ln)
        if m:
            g = [int(x) for x in m.groups()]
            out.update(ops_done=g[0], ops_resent=g[1], ops_failed=g[2], ops_inflight_most=g[4], reqs_most=g[6], session_resets=g[7], zombie_used=g[8], zombie_max=g[9])
        m = re.search(r"readahead: (\d+) reads: (\d+) hits, (\d+) waits, (\d+) misses; (\d+) windows, (\d+) prefetches \((\d+) landed, (\d+) failed, (\d+) dropped\), (\d+) lines valid", ln)
        if m:
            g = [int(x) for x in m.groups()]
            out["ra"] = dict(reads=g[0], hits=g[1], waits=g[2], misses=g[3], windows=g[4], prefetches=g[5], landed=g[6], failed=g[7], dropped=g[8], valid=g[9])
        if "readahead: off" in ln:
            out["ra"] = None
    return out


def tsc_hz(cal):
    rates = []
    for c in cal:
        d = (c["tsc1"] - c["tsc0"]) % (1 << 64)
        rates.append(d / (c["ticks"] / TICK_HZ))
    if not rates:
        return None, None
    spread = (max(rates) - min(rates)) / (sum(rates) / len(rates)) * 100.0 if len(rates) > 1 else None
    return sum(rates) / len(rates), spread


def analyse(text, plan=None):
    p = parse_console(text)
    hz, spread = tsc_hz(p["cal"])
    facts = dict(tsc_hz=hz, cal_spread_pct=spread, steps={}, lat={}, info=None, info_all=[], heap_kb=p["heap"], stack=p["stack"], core_stack=p["core_stack"],
                 stalls=p["stalls"], errors=p["errs"], heap_trouble=p["other"], heap_grow_requests=p["grows"], started=p["started"], done=p["done"])
    checks = []

    def chk(ok, what):
        checks.append((bool(ok), what))

    if p["loop"]:
        # a script run (the R10 loop), not the bench program: WRLOOP-HOOK i ok|fail ..., WRLOOP-END n=N ok=K fail=F
        end = [ln for ln in p["loop"] if ln.startswith("WRLOOP-END")]
        hooks = [ln for ln in p["loop"] if ln.startswith("WRLOOP-HOOK")]
        kvs = kv(end[-1])[1] if end else {}
        num = lambda k: int(kvs[k]) if kvs.get(k, "").isdigit() else 0
        facts["loop"] = dict(n=num("n"), ok=num("ok"), fail=num("fail"), hooks=len(hooks),
                             failed=[ln for ln in hooks if " fail" in ln][:10])
        chk(bool(end), "the loop ran to its end (WRLOOP-END)")
        chk(bool(end) and facts["loop"]["fail"] == 0 and facts["loop"]["ok"] == facts["loop"]["n"] > 0, "every hook succeeded (%s)" % facts["loop"])
        infos = [parse_info(b) for b in p["info_blocks"]]
        facts["info_all"] = infos
        facts["info"] = infos[-1] if infos else None
        return facts, checks
    chk(p["started"], "the bench program started (WRMS-START)")
    chk(p["done"], "the bench program finished (WRMS-DONE)")
    chk(not p["errs"], "no WRMS-ERR line (%d seen)" % len(p["errs"]))
    chk(not p["other"], "iPXE's heap never failed an allocation (%d lines)" % len(p["other"]))
    if len(p["cal"]) >= 2:
        chk(spread is not None and spread < 2.0, "the two TSC calibrations agree within 2 %% (%.3f %%)" % (spread or 0))
    chk(hz is not None, "a TSC calibration was printed")
    zs = [r for r in (plan or {}).get("records", []) if r["type"] == "Z"]
    if zs:
        chk(len(p["cal"]) == len(zs), "every calibration step of the plan printed its line (%d of %d)" % (len(p["cal"]), len(zs)))
    expected = (plan or {}).get("expected", {})
    for sid, d in sorted(p["steps"].items()):
        cmd = int(d["cmd"])
        sectors = int(d["sectors"])
        wall = h64(d["walltsc"]) / hz if hz else None
        rd = h64(d["rdtsc"]) / hz if hz else None
        wr = h64(d["wrtsc"]) / hz if hz else None
        mib = sectors * 512 / 1048576.0
        st = dict(type=d["type"], cmd=cmd, sectors=sectors, mib=mib, errs=int(d["errs"]), rdn=int(d["rdn"]), wrn=int(d["wrn"]), wall_s=wall, read_s=rd, write_s=wr,
                  ticks=int(d["ticks"]), sumA=d["sumA"], sumB=d["sumB"], lastcnt=int(d["lastcnt"]))
        if wall:
            st["wall_mibs"] = mib / wall
        if rd and st["rdn"]:
            st["read_mibs"] = mib / rd
            st["read_cmd_ms"] = rd / st["rdn"] * 1000.0
        if wr and st["wrn"]:
            st["write_mibs"] = mib / wr
            st["write_cmd_ms"] = wr / st["wrn"] * 1000.0
        e = expected.get(str(sid))
        if e is not None and st["errs"] == 0:
            ok = (e["sumA"] == d["sumA"] and e["sumB"] == d["sumB"] and e["lastcnt"] == st["lastcnt"])
            st["sums_ok"] = ok
            chk(ok, "step %d: the data check (sumA %s / sumB %s against the plan's %s / %s)" % (sid, d["sumA"], d["sumB"], e["sumA"], e["sumB"]))
        facts["steps"][str(sid)] = st
    # the plan's own records against what the console says was done (a step that read fewer sectors than the plan's total, with no error line, or that issued
    # another number of commands, is not a measurement of the plan; the sums only look at the last command of a step, so this is what covers the rest)
    for rec in (plan or {}).get("records", []):
        rid = int(rec["id"])
        if rec["type"] in ("R", "C"):
            d = p["steps"].get(rid)
            if d is None:
                chk(False, "step %d of the plan (%s) was not run" % (rid, rec["type"]))
                continue
            if int(d["errs"]) != 0:
                continue                       # the error line has failed the run already
            ncmd = -(-rec["total"] // rec["cmd"])
            ok = (d["type"] == rec["type"] and int(d["cmd"]) == rec["cmd"] and int(d["sectors"]) == rec["total"] and int(d["rdn"]) == ncmd
                  and (rec["type"] == "R" or int(d["wrn"]) == ncmd) and (rec["type"] == "C" or int(d["wrn"]) == 0))
            chk(ok, "step %d: %s of %d sectors in %d commands of %d, as planned (console: %s of %s sectors, %s reads, %s writes, command %s)" %
                (rid, rec["type"], rec["total"], ncmd, rec["cmd"], d["type"], d["sectors"], d["rdn"], d["wrn"], d["cmd"]))
        elif rec["type"] == "L":
            rows = p["lats"].get(rid)
            chk(rows is not None and len(rows) == rec["total"] and p["lat_meta"].get(rid, {}).get("gap") == rec["gap"],
                "latency series %d: %d reads after a gap of %d s, as planned (console: %s reads, gap %s)" %
                (rid, rec["total"], rec["gap"], len(rows) if rows is not None else "no", p["lat_meta"].get(rid, {}).get("gap")))
    for sid, rows in sorted(p["lats"].items()):
        meta = p["lat_meta"].get(sid, {})
        secs = [r["tsc"] / hz if hz else None for r in rows]
        facts["lat"][str(sid)] = dict(gap=meta.get("gap"), cmd=meta.get("cmd"), n=meta.get("n"), secs=secs, ah=[r["ah"] for r in rows])
        chk(all(r["ah"] == "00" for r in rows), "latency series %d: every read succeeded" % sid)
    infos = [parse_info(b) for b in p["info_blocks"]]
    facts["info_all"] = infos
    if infos:
        facts["info"] = infos[-1]
        if (plan or {}).get("plan") in ("read", "probe"):
            # a read run on a healthy cluster has nothing resent, no session reset, no cancelled command and no closed path: a daemon that restarted
            # (or a stall of the lab) during the run shows here, and the run is not a measurement. (A write run is not judged this way: with a slow
            # path the driver's own operation timeout can resend a write, and that is a result of the run, which the tables show)
            i = infos[-1]
            quiet = (i.get("ops_resent", 0) == 0 and i.get("session_resets", 0) == 0 and i.get("cancels", 0) == 0 and i.get("stall_closes", 0) == 0
                     and i.get("ops_failed", 0) == 0)
            chk(quiet, "the cluster did not disturb the run (resent %s, session resets %s, cancels %s, stall closes %s, failed %s)" %
                (i.get("ops_resent"), i.get("session_resets"), i.get("cancels"), i.get("stall_closes"), i.get("ops_failed")))
    return facts, checks


def verdict(checks):
    ok = all(c[0] for c in checks)
    out = ["PASS" if ok else "FAIL"]
    for good, what in checks:
        out.append(("ok   " if good else "FAIL ") + what)
    return "\n".join(out) + "\n"


def parse_load(text):
    """load.txt of mrun.sh: the host's load average at the start, the end and the highest sample, and how much of the run the guest's and the lab VM's threads
    waited for a CPU (runnable, not running) according to the 5 s samples."""
    rows = []
    for ln in text.splitlines():
        m = re.match(r"(during|before|after) t=([\d.]+) host_load=([\d.]+) ", ln)
        if m:
            gw = re.search(r" guest_wait_ns=(-?\d+)", ln)
            lw = re.search(r" lab_wait_ns=(-?\d+)", ln)
            rows.append(dict(kind=m.group(1), t=float(m.group(2)), load1=float(m.group(3)), gw=int(gw.group(1)) if gw else None, lw=int(lw.group(1)) if lw else None))
    out = {}
    if rows:
        out["host_load1_start"] = rows[0]["load1"]
        out["host_load1_end"] = rows[-1]["load1"]
        out["host_load1_max"] = max(r["load1"] for r in rows)
    ds = [r for r in rows if r["kind"] == "during" and r["gw"] is not None and r["gw"] >= 0]
    if len(ds) >= 2:
        dur = ds[-1]["t"] - ds[0]["t"]
        out["sample_seconds"] = dur
        out["guest_cpu_wait_s"] = (ds[-1]["gw"] - ds[0]["gw"]) / 1e9
        if dur > 0:
            out["guest_cpu_wait_pct"] = 100.0 * out["guest_cpu_wait_s"] / dur
        lw = [r for r in ds if r["lw"] is not None and r["lw"] >= 0]
        if len(lw) >= 2 and dur > 0:
            out["lab_cpu_wait_pct"] = 100.0 * (lw[-1]["lw"] - lw[0]["lw"]) / 1e9 / dur
    return out


LOGIN_STAGES = ("ipxe-script", "net-ok", "san-start", "san-ok", "grub", "kernel-up", "table-check-done", "root-ok", "login", "winpe-ok")


def parse_stamps(text):
    """stamps.txt of stamp.py: '<seconds> <stage> <the line>' per stage (first sighting) -> {stage: seconds}, plus the CPU wait it noted."""
    st = {}
    wait = {}
    for ln in text.splitlines():
        m = re.match(r"^\s*(\d+(?:\.\d+)?) (\S+)", ln)
        if m and m.group(2) not in st:
            st[m.group(2)] = float(m.group(1))
        if ln.startswith("#"):
            wait[len(wait)] = ln
    return st, list(wait.values())


def parse_result(text):
    """the run script's RESULT line: ipxe=8 net=12 san=ok@13 end=18 os=- ... (seconds since the guest started)"""
    out = {}
    for ln in text.splitlines():
        if ln.startswith("RESULT"):
            for w in ln.split():
                if "=" in w:
                    k, v = w.split("=", 1)
                    out[k] = v
    return out


def login_run(d, marker_stage="login"):
    """A boot run (mboot.sh): the stage times, and a verdict that needs the run script's success and the marker stage (the login prompt, or the WinPE marker)."""
    sp = os.path.join(d, "stamps.txt")
    rp = os.path.join(d, "result.txt")
    st, notes = parse_stamps(open(sp, errors="replace").read()) if os.path.exists(sp) else ({}, [])
    res = parse_result(open(rp, errors="replace").read()) if os.path.exists(rp) else {}
    if marker_stage == "marker" and res.get("met") == "1" and res.get("secs", "").isdigit():
        st["marker"] = float(res["secs"])      # a run that waited for one console line (a WinPE image's marker): the second the run ended at
    facts = dict(stages=st, notes=notes, result=res, kind="boot", marker_stage=marker_stage)
    sp2 = os.path.join(d, "serial.txt")
    if os.path.exists(sp2):
        pc = parse_console(open(sp2, errors="replace").read())
        facts["heap_kb"] = pc["heap"]
        facts["stack"] = pc["stack"]
        facts["core_stack"] = pc["core_stack"]
    checks = [(res.get("met") == "1", "the run script reached its expectation (met=%s, stop=%s)" % (res.get("met"), res.get("stop"))),
              (marker_stage in st, "the stage '%s' was seen (%s)" % (marker_stage, st.get(marker_stage))),
              ("kernel-panic" not in st, "no kernel panic")]
    if marker_stage == "login":
        checks.append(("root-ok" in st, "the booted system's root marker (WRBOOT-ROOT-OK) was seen"))
    lp = os.path.join(d, "load.txt")
    if os.path.exists(lp):
        facts["load"] = parse_load(open(lp, errors="replace").read())
    with open(os.path.join(d, "facts.json"), "w") as f:
        json.dump(facts, f, indent=1, sort_keys=True)
        f.write("\n")
    v = verdict(checks)
    with open(os.path.join(d, "verdict.txt"), "w") as f:
        f.write(v)
    return v


def base_run(d):
    """The heap baseline run (mheapbase.sh): iPXE's heap maximum with nothing hooked."""
    text = open(os.path.join(d, "serial.txt"), errors="replace").read()
    p = parse_console(text)
    facts = dict(kind="heap-baseline", heap_kb=p["heap"], trouble=p["other"], heap_grow_requests=p["grows"])
    checks = [(bool(p["heap"]), "iPXE printed its heap maximum (%s kB)" % (p["heap"][-1] if p["heap"] else "-")), (not p["other"], "no allocation failure line")]
    with open(os.path.join(d, "facts.json"), "w") as f:
        json.dump(facts, f, indent=1, sort_keys=True)
        f.write("\n")
    v = verdict(checks)
    with open(os.path.join(d, "verdict.txt"), "w") as f:
        f.write(v)
    return v


def run(d, plan_path=None):
    text = open(os.path.join(d, "serial.txt"), errors="replace").read()
    plan = None
    pp = plan_path or os.path.join(d, "plan.json")
    if os.path.exists(pp):
        plan = json.load(open(pp))
    facts, checks = analyse(text, plan)
    lp = os.path.join(d, "load.txt")
    if os.path.exists(lp):
        facts["load"] = parse_load(open(lp, errors="replace").read())
    with open(os.path.join(d, "facts.json"), "w") as f:
        json.dump(facts, f, indent=1, sort_keys=True)
        f.write("\n")
    v = verdict(checks)
    with open(os.path.join(d, "verdict.txt"), "w") as f:
        f.write(v)
    return v


# ---------------------------------------------------------------------------------------------------------------------------------------------
# self-test

def _synthetic(hz=2.0e9, bad_sum=False, errors=False):
    t0 = 1000
    cal = lambda i, hz=hz: "WRMS-CAL id=%d tsc0=%016x tsc1=%016x ticks=91" % (i, t0, t0 + int(hz * 91 / TICK_HZ))
    lines = ["iPXE noise", "WRMS-START drive=80 steps=5", cal(1)]
    # 64 MiB in 1 s of wall time, 1,000 reads of 100 us... rdtsc: 0.9 s
    lines.append("WRMS-STEP id=2 type=R cmd=127 sectors=131072 errs=%d rdn=1032 rdtsc=%016x wrn=0 wrtsc=%016x walltsc=%016x ticks=18 sumA=%s sumB=%s lastcnt=8" %
                 (1 if errors else 0, int(0.9e9 * 2), 0, int(2e9), "deadbeef" if bad_sum else "01020304", "05060708"))
    lines.append("WRMS-STEP id=3 type=C cmd=2048 sectors=16384 errs=0 rdn=8 rdtsc=%016x wrn=8 wrtsc=%016x walltsc=%016x ticks=36 sumA=11111111 sumB=22222222 lastcnt=2048" %
                 (int(0.1 * hz), int(1.9 * hz), int(2.0 * hz)))
    lines += ["WRMS-LAT id=4 gap=40 cmd=127 n=2", "WRMS-LATR id=4 k=0 lba=100 tsc=%016x ah=00" % int(0.5 * hz), "WRMS-LATR id=4 k=1 lba=200 tsc=%016x ah=00" % int(0.01 * hz)]
    if errors:
        lines.append("WRMS-ERR id=2 ah=09 lba=16 op=42")
    lines += [cal(5), "WRMS-DONE errs=%d" % (1 if errors else 0),
              "WRMS-INFO-BEGIN",
              "rbd: image winrbd/x: open, 1 device(s), 100 blocks of 512 bytes",
              "rbd:   session: 5 pumps, 1 cancels (most rounds 2), 3 reopens, 4 stall closes",
              "rbd:   core stack: 1696 of 16384 bytes used",
              "rbd:   core: connections 4 (most 5), arena 260128 bytes, bulk 2627584 bytes; modes: 4 crc, 0 secure, 0 secure failures",
              "rbd:   osd: 900 ops done, 7 resent, 0 failed; in flight 0 (most 12), requests 0 (most 3); 2 session resets, zombies 0 of 1048576 bytes",
              "rbd:   readahead: 2000 reads: 1900 hits, 20 waits, 80 misses; 30 windows, 500 prefetches (490 landed, 1 failed, 9 dropped), 8 lines valid",
              "rbd: stack high-water 2784 of 4096 bytes (1312 left)",
              "WRMS-INFO-END", "HEAP maximum usage 1234kB"]
    return "\r\n".join(lines) + "\r\n"


def selftest():
    fails = []

    def check(ok, what):
        if not ok:
            fails.append(what)
        print(("ok   " if ok else "FAIL ") + what)

    plan = dict(expected={"2": dict(sumA="01020304", sumB="05060708", lastcnt=8), "3": dict(sumA="11111111", sumB="22222222", lastcnt=2048)})
    facts, checks = analyse(_synthetic(), plan)
    check(all(c[0] for c in checks), "a good synthetic console passes every check: %s" % [c[1] for c in checks if not c[0]])
    check(abs(facts["tsc_hz"] - 2.0e9) / 2.0e9 < 1e-6, "the TSC rate is recovered from the calibration (%.0f)" % facts["tsc_hz"])
    s2 = facts["steps"]["2"]
    check(abs(s2["wall_mibs"] - 64.0) < 0.01, "64 MiB in 1 s of wall time is 64 MiB/s (got %.3f)" % s2["wall_mibs"])
    check(abs(s2["read_cmd_ms"] - 0.9 / 1032 * 1000) < 1e-6, "mean command time from the read-time sum")
    s3 = facts["steps"]["3"]
    check(abs(s3["write_mibs"] - 8 / 1.9) < 1e-6, "copy step: write MiB/s from the write-time sum only (%.4f)" % s3["write_mibs"])
    check(abs(facts["lat"]["4"]["secs"][0] - 0.5) < 1e-9 and facts["lat"]["4"]["gap"] == 40, "latency series: seconds per read, gap kept")
    inf = facts["info"]
    check(inf["ra"]["hits"] == 1900 and inf["ops_resent"] == 7 and inf["core_stack_used"] == 1696 and inf["arena_used"] == 260128, "rbd-info numbers parsed")
    check(facts["stack"] == [(2784, 4096)] and facts["heap_kb"] == [1234], "stack and heap marks parsed")
    plan_read = dict(plan, plan="read")
    f1, c1 = analyse(_synthetic(), plan_read)
    check(any((not c[0]) and "did not disturb" in c[1] for c in c1), "negative control: a throughput run with resent operations and session resets is refused")
    quiet = _synthetic().replace("7 resent", "0 resent").replace("2 session resets", "0 session resets").replace("1 cancels", "0 cancels").replace("4 stall closes", "0 stall closes")
    f1, c1 = analyse(quiet, plan_read)
    check(all(c[0] for c in c1), "a throughput run with nothing resent, no reset, no cancel passes (%s)" % [c[1] for c in c1 if not c[0]])
    f2, c2 = analyse(_synthetic(bad_sum=True), plan)
    check(any((not c[0]) and "step 2" in c[1] for c in c2), "negative control: a wrong sum fails the check of its step")
    f3, c3 = analyse(_synthetic(errors=True), plan)
    check(any((not c[0]) and "WRMS-ERR" in c[1] for c in c3), "negative control: a WRMS-ERR line fails the run")
    f4, c4 = analyse("nothing at all\n", plan)
    check(not all(c[0] for c in c4) and verdict(c4).startswith("FAIL"), "negative control: an empty console fails")
    lines = _synthetic().split("\r\n")
    ci = [i for i, ln in enumerate(lines) if ln.startswith("WRMS-CAL id=5")][0]
    lines[ci] = "WRMS-CAL id=5 tsc0=%016x tsc1=%016x ticks=91" % (1000, 1000 + int(2.2e9 * 91 / TICK_HZ))
    f5, c5 = analyse("\r\n".join(lines), plan)
    check(any((not c[0]) and "calibrations" in c[1] for c in c5), "negative control: two calibrations 10 % apart fail")
    f6, _ = analyse(_synthetic().replace("\r\n", "\n"), plan)
    check(f6["steps"].keys() == facts["steps"].keys(), "LF-only consoles parse the same")
    lt = ("before t=100.0 host_load=10.00 9.00 8.00 host_cpu=1 2 3 4 5 6 7 8\nbefore lab_t=100.0 lab_load=1 1 1\n"
          "during t=105.0 host_load=12.00 9.00 8.00 host_cpu=1 2 3 4 5 6 7 8 guest_wait_ns=1000000000 lab_wait_ns=500000000\n"
          "during t=205.0 host_load=40.00 9.00 8.00 host_cpu=1 2 3 4 5 6 7 8 guest_wait_ns=11000000000 lab_wait_ns=2500000000\n"
          "after t=206.0 host_load=39.00 9.00 8.00 host_cpu=1 2 3 4 5 6 7 8\n")
    pl = parse_load(lt)
    check(pl["host_load1_max"] == 40.0 and abs(pl["guest_cpu_wait_pct"] - 10.0) < 1e-6 and abs(pl["lab_cpu_wait_pct"] - 2.0) < 1e-6, "load.txt: load average and the CPU wait of the guest and the lab VM (%s)" % pl)
    check(parse_load("garbage\n") == {}, "load.txt: garbage gives nothing")
    import tempfile
    with tempfile.TemporaryDirectory() as t:
        open(os.path.join(t, "stamps.txt"), "w").write("  0.0 ipxe-script WRRUN-BEGIN\n8.5 san-ok WRRUN-SAN-OK\n20.0 grub GNU GRUB\n40.5 root-ok WRBOOT-ROOT-OK\n44.0 login host login:\n# guest cpu wait 1.0 s\n")
        open(os.path.join(t, "result.txt"), "w").write("RESULT row=U1 expect=marker met=1 ipxe=8 net=12 san=ok@13 end=- os=44 stop=expectation secs=44\nexit=0\n")
        v = login_run(t)
        ff = json.load(open(os.path.join(t, "facts.json")))
        check(v.startswith("PASS") and ff["stages"]["login"] == 44.0 and ff["result"]["san"] == "ok@13", "a boot run: stage seconds from stamps.txt and the RESULT line, verdict PASS")
        open(os.path.join(t, "stamps.txt"), "w").write("0.0 ipxe-script WRRUN-BEGIN\n")
        check(login_run(t).startswith("FAIL"), "negative control: a boot run without the login stage fails")
    f9, _ = analyse("".join(c + c for c in "HEAP maximum usage 248kB") + "\n", plan)
    check(f9["heap_kb"] == [248], "a UEFI console that prints every character twice is read (HEAP maximum usage 248 kB)")
    loop = "WRLOOP-HOOK 1 ok\nWRLOOP-HOOK 2 ok\nWRLOOP-END n=2 ok=2 fail=0\nHEAP maximum usage 900kB\n"
    f7, c7 = analyse(loop, plan)
    check(all(c[0] for c in c7) and f7["loop"]["ok"] == 2 and f7["heap_kb"] == [900], "a script run (loop) is judged on its own lines")
    f8, c8 = analyse(loop.replace("WRLOOP-HOOK 2 ok", "WRLOOP-HOOK 2 fail 0x1234").replace("ok=2 fail=0", "ok=1 fail=1"), plan)
    check(any(not c[0] for c in c8), "negative control: a failed hook fails the loop run")
    check(any(not c[0] for c in analyse("WRLOOP-HOOK 1 ok\n", plan)[1]), "negative control: a loop that never ended fails")
    # the plan's records against the console (the review's finding: a step that read less than planned, or in other commands, must not pass)
    recs = [dict(type="Z", id=1, cmd=0, total=0, lba=0, dst=0, gap=0), dict(type="R", id=2, cmd=127, total=131072, lba=16, dst=0, gap=0),
            dict(type="C", id=3, cmd=2048, total=16384, lba=16, dst=0, gap=0), dict(type="L", id=4, cmd=127, total=2, lba=0, dst=0, gap=40),
            dict(type="Z", id=5, cmd=0, total=0, lba=0, dst=0, gap=0)]
    rplan = dict(plan, records=recs)
    good = _synthetic().replace("rdn=1032", "rdn=1033")      # 131072 sectors in commands of 127: 1,033 commands, the last one short
    fr, cr = analyse(good, rplan)
    check(all(c[0] for c in cr), "records: a console that did what the plan says passes (%s)" % [c[1] for c in cr if not c[0]])
    short = good.replace("sectors=131072", "sectors=130945")
    check(any((not c[0]) and "step 2" in c[1] for c in analyse(short, rplan)[1]), "negative control: a read step that did fewer sectors than planned, with no error line, fails")
    check(any((not c[0]) and "step 2" in c[1] for c in analyse(good.replace("rdn=1033", "rdn=1032"), rplan)[1]), "negative control: a step with another number of commands than planned fails")
    check(any((not c[0]) and "step 3" in c[1] for c in analyse(good.replace("wrn=8 ", "wrn=7 "), rplan)[1]), "negative control: a copy step with fewer writes than reads fails")
    nostep = "\r\n".join(ln for ln in good.split("\r\n") if not ln.startswith("WRMS-STEP id=3"))
    check(any((not c[0]) and "step 3" in c[1] for c in analyse(nostep, rplan)[1]), "negative control: a step of the plan that never ran fails")
    nolat = "\r\n".join(ln for ln in good.split("\r\n") if not ln.startswith("WRMS-LATR id=4 k=1"))
    check(any((not c[0]) and "latency series 4" in c[1] for c in analyse(nolat, rplan)[1]), "negative control: a latency series with a read missing fails")
    nocal = "\r\n".join(ln for ln in good.split("\r\n") if not ln.startswith("WRMS-CAL id=5"))
    check(any((not c[0]) and "calibration step" in c[1] for c in analyse(nocal, rplan)[1]), "negative control: a missing calibration line fails")
    print("selftest: %s" % ("PASS" if not fails else "FAIL (%d)" % len(fails)))
    return 0 if not fails else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 3 and argv[1] == "base":
        v = base_run(argv[2])
        sys.stdout.write(v)
        return 0 if v.startswith("PASS") else 1
    if len(argv) >= 3 and argv[1] == "login":
        v = login_run(argv[2], argv[3] if len(argv) > 3 else "login")
        sys.stdout.write(v)
        return 0 if v.startswith("PASS") else 1
    if len(argv) >= 3 and argv[1] == "run":
        plan = argv[argv.index("--plan") + 1] if "--plan" in argv else None
        v = run(argv[2], plan)
        sys.stdout.write(v)
        return 0 if v.startswith("PASS") else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
