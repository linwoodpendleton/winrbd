#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""analyse.py - what one run of the BIOS matrix measured, from its serial log.

  analyse.py LOGBASE [--json OUT]       LOGBASE is the path of a run's logs without the suffix (LOGBASE.console, .ts, .chunks ...), or an evidence directory of rows/
  analyse.py --selftest

Reads LOGBASE.ts (time-stamped lines) and LOGBASE.chunks (time-stamped pieces; GRUB draws its screen without newlines) and prints one
JSON object (or writes it to OUT):

  stages        seconds since the start of the guest at which each stage was first seen
  rbft          the guest checker's verdict (RBFT-RESULT line, counts, the FAIL lines), the table's length, where the scan found it,
                the marker line the booted system printed
  int13         (build with DEBUG=rbd_block:2) every read command the driver was handed: count, sectors, histogram of the sizes, how many
                were 127 sectors, how many continued the previous one, the largest, and the span between the first and the last
  stack         the last "stack high-water" the driver printed (build with RBD_STACK_MONITOR) and the core's own stack mark
  heap          the core's arena and bulk use as "rbd-info" prints it, and the memory the session asked for
  pause         the guest was stopped at a chosen line (tailts.py --pause-on): the commands around the pause and the time to the first
                one that finished after it

Times are as exact as the 20 ms polling of tailts.py. Nothing here reads the key: the logs are scanned for it before they are kept.
"""
import json
import os
import re
import sys

STAGE_RES = [
    ("ipxe", r"iPXE initialising devices|Open Source Network Boot Firmware"),
    ("stub", r"WRRUN-STUB"),
    ("script", r"WRRUN-BEGIN"),
    ("net", r"WRRUN-NET-OK"),
    ("san_start", r"WRRUN-SAN-START"),
    ("san_ok", r"WRRUN-SAN-OK"),
    ("san_failed", r"WRRUN-SAN-FAILED"),
    ("registered", r"Registered SAN device"),
    ("booting", r"Booting from SAN device"),
    ("grub", r"GNU GRUB"),
    ("grub_countdown_end", r"executed automatically in 0s"),
    ("grub_loading", r"Loading, please wait"),
    ("hook", r"RBFT-HOOK start"),
    ("table_found", r"RBFT-HOOK table found"),
    ("table_result", r"RBFT-RESULT"),
    ("hook_done", r"WRBOOT-HOOK-DONE"),
    ("root_ok", r"WRBOOT-ROOT-OK"),
    ("end", r"WRRUN-END"),
]

# the number of fields of the handoff table the guest's checker compares (rbft-check): a "PASS" of fewer fields is not the whole table
EXPECTED_FIELDS = 40

CMD_RE = re.compile(r"RBD (\S+) cmd (\S+) kind (\d+) lba (0x[0-9a-f]+) count (\d+) state (\d+)")
DONE_RE = re.compile(r"RBD (\S+) cmd (\S+) done \(kind (\d+)\): (.*)")
STACK_RE = re.compile(r"rbd: stack high-water (\d+) of (\d+) bytes \((\d+) left\)")
CORE_STACK_RE = re.compile(r"rbd: core stack high-water (\d+) of (\d+) bytes")
CORE_STACK_INFO_RE = re.compile(r"rbd:\s+core stack: (\d+) of (\d+) bytes used")
ARENA_RE = re.compile(r"rbd:\s+core: connections (\d+) \(most (\d+)\), arena (\d+) bytes, bulk (\d+) bytes")
NEEDS_RE = re.compile(r"RBD \S+ needs (\d+) \+ (\d+) \+ (\d+) \+ (\d+) bytes")
RA_RE = re.compile(r"rbd:\s+readahead: (.*)")
OSD_RE = re.compile(r"rbd:\s+osd: (.*)")


def read_ts(path):
    """[(seconds, text)] and the [(seconds, '# PAUSE ...')] markers."""
    rows = []
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or line.startswith("# tailts"):
                    continue
                m = re.match(r"^(\d+\.\d+) (.*)$", line)
                if m:
                    rows.append((float(m.group(1)), m.group(2)))
    except OSError:
        pass
    return rows


def paths_of(base):
    """(serial log, debug console log, chunk file) of a run: LOGBASE.ts / .dbg.ts / .chunks, or, when BASE is an evidence directory, console.ts / debug.ts / console.chunks."""
    if os.path.isdir(base):
        return (os.path.join(base, "console.ts"), os.path.join(base, "debug.ts"), os.path.join(base, "console.chunks"))
    return (base + ".ts", base + ".dbg.ts", base + ".chunks")


def read_all(base):
    """The serial log and, when the run had one, the debug console (iPXE's DBG output), merged by time."""
    ts, dbg, _ = paths_of(base)
    rows = read_ts(ts) + read_ts(dbg)
    rows.sort(key=lambda r: r[0])
    return rows


def read_chunks(path):
    out = []
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                try:
                    t, text = json.loads(line)
                except ValueError:
                    continue
                out.append((float(t), text))
    except OSError:
        pass
    return out


def first_time(chunks, regex):
    """Earliest time at which the cumulative text of the chunks matches regex (the match may span chunks)."""
    rx = re.compile(regex)
    text = ""
    for t, c in chunks:
        text += c
        if rx.search(text):
            return t
        if len(text) > 4096:
            text = text[-1024:]
    return None


def analyse(lines, chunks):
    res = {}
    stages = {}
    for name, rx in STAGE_RES:
        t = first_time(chunks, rx) if chunks else None
        if t is None:
            for ts, text in lines:
                if re.search(rx, text):
                    t = ts
                    break
        if t is not None:
            stages[name] = t
    # the first kernel message (printk time stamp column)
    for ts, text in lines:
        if re.match(r"^\[\s*0\.\d+\]", text):
            stages["kernel"] = ts
            break
    res["stages"] = stages

    # the guest's table checker
    rb = {"result": None, "pass": None, "fail": None, "skip": None, "fail_lines": [], "length": None, "source": None, "marker": None,
          "edd": [], "table": None}
    for ts, text in lines:
        m = re.search(r"RBFT-RESULT (PASS|FAIL) pass=(\d+) fail=(\d+) skip=(\d+)", text)
        if m:
            rb["result"], rb["pass"], rb["fail"], rb["skip"] = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))
        m = re.search(r"RBFT FAIL (\S+): (.*)", text)
        if m:
            rb["fail_lines"].append("%s: %s" % (m.group(1), m.group(2)))
        m = re.search(r"RBFT PASS length: (\d+) bytes", text)
        if m:
            rb["length"] = int(m.group(1))
        m = re.search(r"RBFT INFO source: (.*)", text)
        if m:
            rb["source"] = m.group(1)
        m = re.search(r"^(WRBOOT-ROOT-\S+.*)$", text)
        if m:
            rb["marker"] = m.group(1)
        m = re.search(r"^(WRBOOT-EDD .*)$", text)
        if m:
            rb["edd"].append(m.group(1))
        m = re.search(r"^(WRBOOT-TABLE \S+)", text)
        if m:
            rb["table"] = m.group(1)
    res["rbft"] = rb

    # INT 13h commands as the driver saw them (DEBUG=rbd_block:2).
    # One logical command can print its "cmd" line more than once: when the SAN layer's own timeout cancels a command that has not finished
    # it issues the same read again (the same kind, lba and count), under the same address or, after the driver closed and re-opened the
    # path, under a new one. Such a repeat is a RETRY of the open command, not a new read: counting it as a read would inflate the
    # sector totals, and matching its "done" line by address alone would pair it with a LATER command that reuses the address (the
    # allocator hands the same address out again), which gave a 71 s "read" that was really 61 s. A "done" line closes the open
    # command that last carried its address.
    cmds = []
    open_cmds = []
    pause = []
    retries = 0
    for ts, text in lines:
        m = CMD_RE.search(text)
        if m:
            key = (int(m.group(3)), int(m.group(4), 16), int(m.group(5)))
            again = next((c for c in open_cmds if (c["kind"], c["lba"], c["count"]) == key), None)
            if again is not None:
                again["cmd"] = m.group(2)
                again["retries"] += 1
                retries += 1
                continue
            c = {"t": ts, "cmd": m.group(2), "kind": key[0], "lba": key[1], "count": key[2], "retries": 0, "done_t": None, "result": None}
            cmds.append(c)
            open_cmds.append(c)
            continue
        m = DONE_RE.search(text)
        if m:
            for c in reversed(open_cmds):
                if c["cmd"] == m.group(2):
                    c["done_t"], c["result"] = ts, m.group(4)
                    open_cmds.remove(c)
                    break
            continue
        if "# PAUSE" in text:
            pause.append((ts, text))

    def brief(c):
        return {"t": c["t"], "cmd": c["cmd"], "kind": c["kind"], "lba": c["lba"], "count": c["count"]}

    reads = [c for c in cmds if c["kind"] == 0]
    if cmds:
        hist = {}
        seq = 0
        prev_end = None
        for c in reads:
            hist[c["count"]] = hist.get(c["count"], 0) + 1
            if prev_end is not None and c["lba"] == prev_end:
                seq += 1
            prev_end = c["lba"] + c["count"]
        sectors = sum(c["count"] for c in reads)
        res["int13"] = {
            "commands": len(cmds), "reads": len(reads), "capacity": sum(1 for c in cmds if c["kind"] == 2),
            "writes": sum(1 for c in cmds if c["kind"] == 1), "sectors": sectors, "mib": round(sectors * 512 / 1048576, 2),
            "largest": max((c["count"] for c in reads), default=0), "sectors_127": hist.get(127, 0),
            "sequential": seq, "histogram": {str(k): hist[k] for k in sorted(hist)},
            "first_t": reads[0]["t"] if reads else None, "last_t": reads[-1]["t"] if reads else None,
            "retries": retries, "unfinished": len(open_cmds),
        }
        # latency: the first issue to the "done" line of the same logical command (20 ms resolution)
        lat = sorted(c["done_t"] - c["t"] for c in reads if c["done_t"] is not None and c["done_t"] >= c["t"])
        if lat:
            res["int13"]["latency_ms"] = {"n": len(lat), "median": round(lat[len(lat) // 2] * 1000), "p90": round(lat[int(len(lat) * 0.9)] * 1000),
                                          "max": round(lat[-1] * 1000)}
    # the stack
    st = None
    core = None
    for ts, text in lines:
        m = STACK_RE.search(text)
        if m:
            st = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        m = CORE_STACK_RE.search(text)
        if m:
            core = (int(m.group(1)), int(m.group(2)))
        m = CORE_STACK_INFO_RE.search(text)
        if m:
            core = (int(m.group(1)), int(m.group(2)))
    if st or core:
        res["stack"] = {}
        if st:
            res["stack"].update({"ipxe_used": st[0], "ipxe_total": st[1], "ipxe_left": st[2]})
        if core:
            res["stack"].update({"core_used": core[0], "core_total": core[1]})
    # the heap (rbd-info, session open)
    heap = {}
    for ts, text in lines:
        m = ARENA_RE.search(text)
        if m:
            heap["conns"], heap["conns_most"], heap["arena_bytes"], heap["bulk_bytes"] = (int(m.group(i)) for i in (1, 2, 3, 4))
        m = NEEDS_RE.search(text)
        if m:
            heap["session_needs"] = [int(m.group(i)) for i in (1, 2, 3, 4)]
        m = RA_RE.search(text)
        if m:
            heap["readahead"] = m.group(1)
        m = OSD_RE.search(text)
        if m:
            heap["osd"] = m.group(1)
    if heap:
        res["heap"] = heap
    # the pause
    if pause:
        p = {"markers": [{"t": t, "what": w.strip()} for t, w in pause]}
        stop = next((t for t, w in pause if "PAUSE stop" in w), None)
        cont = next((t for t, w in pause if "PAUSE cont" in w), None)
        if stop is not None and cont is not None:
            before = [c for c in cmds if c["t"] <= stop]
            after = [c for c in cmds if c["t"] >= cont]
            p["last_command_before"] = brief(before[-1]) if before else None
            # a command that was in flight when the guest was stopped: how long after the resume did it finish?
            if before:
                b = before[-1]
                if b["done_t"] is not None and b["done_t"] >= cont:
                    p["in_flight_done_after_cont_ms"] = round((b["done_t"] - cont) * 1000)
                    p["in_flight_result"] = b["result"]
            # the first command issued after the resume, and how long it took
            if after:
                a = after[0]
                p["first_command_after"] = brief(a)
                if a["done_t"] is not None and a["done_t"] >= a["t"]:
                    p["first_command_after_latency_ms"] = round((a["done_t"] - a["t"]) * 1000)
                    p["first_command_after_result"] = a["result"]
            p["pause_s"] = round(cont - stop, 3)
            late = [t for ts, t in lines if ts >= cont and "the cluster has not answered" in t]
            p["complaints"] = "; ".join(late[:3]) if late else "none"
            # the first line of any kind after the resume
            nxt = next((ts for ts, text in lines if ts >= cont and "# PAUSE" not in text), None)
            if nxt is not None:
                p["first_output_after_cont_ms"] = round((nxt - cont) * 1000)
        res["pause"] = p
    return res


def verdict(row, base, result_line, exit_status):
    """The criteria of a row, one line each (CRITERION PASS|FAIL name: detail) and a last line VERDICT PASS|FAIL."""
    lines = read_all(base)
    res = analyse(lines, read_chunks(paths_of(base)[2]))
    rb = res["rbft"]
    texts = [t for _, t in lines]
    crit = []

    def add(name, ok, detail=""):
        crit.append((name, bool(ok), detail))

    def table_ok():
        return rb["result"] == "PASS" and rb["fail"] == 0 and rb["skip"] == 0 and rb["pass"] == EXPECTED_FIELDS

    def table_detail():
        return "%s pass=%s fail=%s skip=%s (expected pass=%d) %s" % (rb["result"], rb["pass"], rb["fail"], rb["skip"], EXPECTED_FIELDS, rb["fail_lines"])

    kv = dict(re.findall(r"(\w+)=(\S+)", result_line or ""))
    add("run script reached the expected stage", kv.get("met") == "1", "met=%s stop=%s" % (kv.get("met"), kv.get("stop")))
    add("run script exit status 0 (no leftover, no key in a log)", str(exit_status) == "0", "exit %s" % exit_status)
    if row in ("b1", "b2", "b3"):
        marker = rb["marker"] or ""
        add("booted system printed WRBOOT-ROOT-OK", marker.startswith("WRBOOT-ROOT-OK"), marker[:120] or "no marker")
        add("root is on the mapped image", "root=/dev/rbd" in marker and "mapped=rbd" in marker, marker[:120])
        add("table found by the low-memory scan", (rb["source"] or "").startswith("scan: found"), rb["source"] or "no source line")
        add("every field of the table matches (RBFT-RESULT PASS, all %d fields, no FAIL, no SKIP)" % EXPECTED_FIELDS, table_ok(), table_detail())
        add("hook verdict WRBOOT-TABLE PASS", rb["table"] == "WRBOOT-TABLE PASS", rb["table"] or "none")
        add("SAN device registered and booted from", "booting" in res["stages"], "Booting from SAN device")
    elif row == "b0":
        add("hooked drive visible to the BIOS (int13_dev81)", any("int13_dev81" in e for e in rb["edd"]), "; ".join(rb["edd"]) or "no EDD line")
        add("table found by the low-memory scan", (rb["source"] or "").startswith("scan: found"), rb["source"] or "no source line")
        add("every field of the table matches (RBFT-RESULT PASS, all %d fields, no FAIL, no SKIP)" % EXPECTED_FIELDS, table_ok(), table_detail())
        # the marker must be the OK one: WRBOOT-ROOT-TABLE-FAIL, -WRONG and -NOT-RBD are markers too
        marker = rb["marker"] or ""
        add("local disk booted (the tiny system printed WRBOOT-ROOT-OK)", marker.startswith("WRBOOT-ROOT-OK"), marker[:120] or "no marker")
        add("SAN hook reported OK", "san_ok" in res["stages"], "WRRUN-SAN-OK")
    elif row == "neg":
        errs = [t for t in texts if t.startswith("rbd: ")]
        add("SAN open failed (WRRUN-SAN-FAILED)", "san_failed" in res["stages"], "")
        add("exactly one driver console line", len(errs) == 1, "; ".join(errs[:3]))
        add("iPXE's own line follows (Could not open SAN device)", any(t.startswith("Could not open SAN device") for t in texts), "")
        add("nothing booted (no GRUB, no kernel, no table)", "grub" not in res["stages"] and "kernel" not in res["stages"] and rb["result"] is None, "")
    else:
        # a row this function does not know decides nothing: it must not read as PASS because the list of criteria is short
        add("known row (b0 b1 b2 b3 neg)", False, "row %r" % row)
    ok = all(c[1] for c in crit)
    notes = []
    if row == "b0":
        sig = next((re.search(r"mbr_signature=(\S+)", e).group(1) for e in rb["edd"] if "int13_dev81" in e and "mbr_signature=" in e), None)
        stalls = sum(1 for t in texts if "the cluster has not answered for" in t)
        notes.append("NOTE hooked drive readable by the guest's EDD probe (MBR signature of 0x81): %s" % ("yes, %s" % sig if sig and sig != "-" else "NO (the first sector could not be read)"))
        notes.append("NOTE driver stall lines while the local disk booted (each is a 30 s wait of one INT 13h command): %d" % stalls)
    out = []
    for name, good, detail in crit:
        out.append("CRITERION %s %s%s" % ("PASS" if good else "FAIL", name, (": " + detail) if detail else ""))
    out.extend(notes)
    out.append("VERDICT %s" % ("PASS" if ok else "FAIL"))
    return ok, "\n".join(out)


def selftest():
    lines = [
        (1.0, "iPXE initialising devices..."), (2.0, "WRRUN-STUB"), (3.0, "WRRUN-NET-OK"), (3.1, "WRRUN-SAN-START sanboot"),
        (3.5, "RBD 0x1000 cmd 0x2000 kind 2 lba 0x0 count 0 state 0"),
        (4.0, "RBD 0x1000 cmd 0x2001 kind 0 lba 0x0 count 1 state 0"), (4.1, "RBD 0x1000 cmd 0x2001 done (kind 0): Success"),
        (4.2, "RBD 0x1000 cmd 0x2002 kind 0 lba 0x1 count 127 state 0"), (4.3, "RBD 0x1000 cmd 0x2002 done (kind 0): Success"),
        (4.4, "RBD 0x1000 cmd 0x2003 kind 0 lba 0x80 count 127 state 0"), (4.5, "RBD 0x1000 cmd 0x2003 done (kind 0): Success"),
        (4.6, "RBD 0x1000 cmd 0x2004 kind 0 lba 0x900 count 8 state 0"),
        (5.0, "# PAUSE stop {}"), (65.0, "# PAUSE cont {}"), (65.5, "RBD 0x1000 cmd 0x2004 done (kind 0): Success"),
        (65.6, "RBD 0x1000 cmd 0x2005 kind 0 lba 0x908 count 127 state 0"), (66.1, "RBD 0x1000 cmd 0x2005 done (kind 0): Success"),
        (70.0, "rbd: stack high-water 2816 of 4096 bytes (1280 left)"), (70.1, "rbd: core stack high-water 2400 of 16384 bytes"),
        (71.0, "rbd:   core: connections 2 (most 3), arena 90000 bytes, bulk 4096 bytes; modes: 2 crc, 0 secure, 0 secure failures"),
        (80.0, "RBFT PASS length: 234 bytes"), (80.1, "RBFT FAIL nic_gateway: expected none, got 10.77.0.10"),
        (80.2, "RBFT-RESULT FAIL pass=38 fail=1 skip=0"), (81.0, "WRBOOT-ROOT-OK fw=bios root=/dev/rbd0p1"),
    ]
    chunks = [(30.0, "GNU GR"), (30.2, "UB  version"), (40.0, "in 0s"), (40.1, ".  Loading, please wait")]
    r = analyse(lines, chunks)
    assert r["stages"]["san_start"] == 3.1, r["stages"]
    assert r["stages"]["grub"] == 30.2, r["stages"]
    assert r["int13"]["reads"] == 5 and r["int13"]["capacity"] == 1, r["int13"]
    assert r["int13"]["sectors"] == 1 + 127 + 127 + 8 + 127, r["int13"]
    assert r["int13"]["sectors_127"] == 3 and r["int13"]["largest"] == 127
    assert r["int13"]["sequential"] == 3, r["int13"]
    assert r["stack"]["ipxe_used"] == 2816 and r["stack"]["core_total"] == 16384
    assert r["heap"]["arena_bytes"] == 90000
    assert r["rbft"]["result"] == "FAIL" and r["rbft"]["fail_lines"] == ["nic_gateway: expected none, got 10.77.0.10"]
    assert r["rbft"]["length"] == 234 and r["rbft"]["marker"].startswith("WRBOOT-ROOT-OK")
    assert r["pause"]["last_command_before"]["cmd"] == "0x2004", r["pause"]
    assert r["pause"]["in_flight_done_after_cont_ms"] == 500, r["pause"]
    assert r["pause"]["first_command_after"]["cmd"] == "0x2005", r["pause"]
    assert r["pause"]["first_command_after_latency_ms"] == 500, r["pause"]
    assert r["pause"]["pause_s"] == 60.0
    # a read that the SAN layer cancels and issues again: twice under the same address, then (the path was re-opened) under a new one, and
    # the old address is handed out again to a later command: ONE read of 61 s, two retries... three, and a later 0.1 s read
    lines = [
        (10.0, "RBD 0x1000 cmd 0x2000 kind 0 lba 0x100 count 8 state 2"),
        (25.0, "RBD 0x1000 cmd 0x2000 kind 0 lba 0x100 count 8 state 2"),
        (40.0, "RBD 0x1000 cmd 0x2000 kind 0 lba 0x100 count 8 state 2"),
        (47.0, "RBD 0x1000 cmd 0x3000 kind 0 lba 0x100 count 8 state 2"),
        (71.0, "RBD 0x1000 cmd 0x3000 done (kind 0): Operation completed successfully"),
        (71.1, "RBD 0x1000 cmd 0x2000 kind 0 lba 0x108 count 8 state 2"),
        (71.2, "RBD 0x1000 cmd 0x2000 done (kind 0): Operation completed successfully"),
        (71.3, "RBD 0x1000 cmd 0x2000 kind 0 lba 0x110 count 8 state 2"),
    ]
    r = analyse(lines, [])
    i = r["int13"]
    assert i["reads"] == 3 and i["sectors"] == 24 and i["retries"] == 3 and i["unfinished"] == 1, i
    assert i["sequential"] == 2, i
    assert i["latency_ms"]["n"] == 2 and i["latency_ms"]["max"] == 61000, i["latency_ms"]
    # a log without anything of the driver is an empty analysis, not an error
    e = analyse([], [])
    assert e["stages"] == {} and "int13" not in e and "stack" not in e
    print("analyse.py selftest: ok")
    return 0


def main(argv):
    if argv and argv[0] == "--selftest":
        return selftest()
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    base = argv[0]
    out = None
    if len(argv) >= 3 and argv[1] == "--json":
        out = argv[2]
    if len(argv) >= 3 and argv[1] == "--verdict":
        row = argv[2]
        result_line, status = "", ""
        i = 3
        while i + 1 < len(argv):
            if argv[i] == "--result":
                result_line = argv[i + 1]
            elif argv[i] == "--exit":
                status = argv[i + 1]
            i += 2
        ok, text = verdict(row, base, result_line, status)
        print(text)
        return 0 if ok else 1
    r = analyse(read_all(base), read_chunks(paths_of(base)[2]))
    text = json.dumps(r, indent=1, sort_keys=True)
    if out:
        with open(out, "w") as f:
            f.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
