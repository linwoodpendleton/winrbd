#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Make the table of the robustness rows from the evidence directories.

    summarize.py ROWSDIR > MATRIX.md

One line per row directory: the verdict (first line of verdict.txt), the fault and when it ran, how long the workload took, what the driver counted (rbd-info of the
end of the run: cancels by the SAN layer, reopens, stall closes, resent operations, session resets) and the first FAIL line. Then a count per family. Reads only
what the rows kept (no key is in any of it). Standard library only."""
import os
import re
import sys


def read(p):
    try:
        with open(p, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def facts(d):
    out = {}
    for ln in read(os.path.join(d, "facts.txt")).splitlines():
        k, _, v = ln.partition(": ")
        out.setdefault(k, v)
    return out


def late_conns(f):
    """'3 osd, 1 mon' from connections_started_after_the_fault_began"""
    v = f.get("connections_started_after_the_fault_began", "")
    if not v or v == "none":
        return "0"
    n_m = len(re.findall(r"monitor:", v))
    n_o = len(re.findall(r"osd:", v))
    more = re.search(r"\.\.\.", v)
    return "%d mon, %d osd%s" % (n_m, n_o, "+" if more else "")


def main():
    root = sys.argv[1]
    rows = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)) and not d.startswith("."))
    fam = {}
    print("| Row | Verdict | Fault (begin / end after guest start) | Workload s | cancels | reopens | stall closes | resent | session resets | New connections after the fault began | Reader: errors / slowest read | First FAIL |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        d = os.path.join(root, r)
        v = read(os.path.join(d, "verdict.txt")).splitlines()
        verdict = v[0] if v else "(none)"
        f = facts(d)
        cmd = read(os.path.join(d, "cmdline.txt"))
        m = re.search(r"--fault (\S+)", cmd)
        kind = m.group(1) if m else "-"
        fb, fe = f.get("fault_begin", "-"), f.get("fault_end", "-")
        fe = re.sub(r" \(.*", "", fe)
        took = re.search(r"took ([0-9.]+) s", f.get("workload_end", ""))
        first = next((ln[5:] for ln in v[1:] if ln.startswith("FAIL")), "")
        first = first.replace("|", "/")[:150]
        rd = "-"
        if "reader_errs" in f:
            mt = re.match(r"(\d+) ticks \(([0-9.]+) s\)", f.get("reader_maxticks", ""))
            rd = "%s / %s s" % (f["reader_errs"], mt.group(2) if mt else "?")
        print("| %s | %s | %s %s / %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r, verdict, kind, fb, fe, took.group(1) if took else "-", f.get("rbd_info_cancels", "-"), f.get("rbd_info_reopens", "-"),
            f.get("rbd_info_stall_closes", "-"), f.get("rbd_info_ops_resent", "-"), f.get("rbd_info_session_resets", "-"), late_conns(f), rd, first))
        fk = r.split("-")[0] + "-" + r.split("-")[1]
        c = fam.setdefault(fk, {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "(none)": 0})
        c[verdict if verdict in c else "(none)"] += 1
    print()
    print("| Family and workload | PASS | FAIL | BLOCKED |")
    print("|---|---|---|---|")
    for k in sorted(fam):
        print("| %s | %d | %d | %d |" % (k, fam[k]["PASS"], fam[k]["FAIL"], fam[k]["BLOCKED"]))


if __name__ == "__main__":
    main()
