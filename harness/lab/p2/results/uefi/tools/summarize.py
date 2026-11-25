#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Make the table of the UEFI matrix from the evidence directories.

    summarize.py ROWSDIR > MATRIX.md

One line per row directory, then a count per family of repeats (every run counts, the failed and the debug-build ones too) (names sort in matrix order): the verdict (first line of verdict.txt), the numbers of the run (RESULT line:
seconds to iPXE, to the SAN device, to the OS marker; stamps.txt: grub, table check, root, login), what the analysis counted, and the first
FAIL line if there is one. Reads only what the rows kept (no key is in any of it). Standard library only."""
import os
import re
import sys


def read(p):
    try:
        with open(p, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def stage(stamps, name):
    m = re.search(r"^\s*([0-9.]+) %s\b" % re.escape(name), stamps, re.M)
    return m.group(1) if m else "-"


def main():
    root = sys.argv[1]
    rows = sorted(d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d)) and not d.startswith("."))
    fam = {}
    print("| Row | Verdict | iPXE s | SAN ok s | grub s | table s | root s | login s | Notes |")
    print("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        d = os.path.join(root, r)
        v = read(os.path.join(d, "verdict.txt")).splitlines()
        verdict = v[0] if v else "(none)"
        res = read(os.path.join(d, "result.txt"))
        stamps = read(os.path.join(d, "stamps.txt"))
        m = re.search(r"\bipxe=(\S+)", res)
        ipxe = m.group(1) if m else "-"
        m = re.search(r"\bsan=(\w+)@(\S+)", res)
        san = (m.group(2) if m and m.group(1) == "ok" else ("failed@" + m.group(2) if m and m.group(1) == "failed" else "-"))
        fails = [l[5:] for l in v if l.startswith("FAIL ")]
        notes = ""
        if verdict != "PASS" and fails:
            notes = fails[0][:110]
        elif verdict == "PASS":
            ex = [l for l in v if l.startswith("PASS ") and ("device path flavour" in l or "every file" in l or "errno is" in l or "table: RBFT" in l)]
            notes = "; ".join(re.sub(r"^PASS ", "", l)[:80] for l in ex[:2])
        notes = notes.replace("|", "/")
        first = read(os.path.join(d, "binaries.sha256")).splitlines()[:1]
        binary = os.path.basename(first[0].split(None, 1)[1].strip()) if first and len(first[0].split(None, 1)) == 2 else ""
        key = re.sub(r"-r\d+$", "", r)
        if binary and binary != "ipxe.efi" and not binary.endswith(".iso") and not r.startswith(("U2", "U3", "W", "UB", "N-")):
            key += " [" + binary + "]"
        c = fam.setdefault(key, {"PASS": 0, "FAIL": 0, "BLOCKED": 0, "other": 0})
        c[verdict if verdict in c else "other"] += 1
        print("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            r, verdict, ipxe, san, stage(stamps, "grub"), stage(stamps, "table-check-done"), stage(stamps, "root-ok"), stage(stamps, "login"), notes))
    print()
    print("| Family (runs of the same row; [binary] when it is not ipxe.efi) | Runs | PASS | FAIL | BLOCKED |")
    print("|---|---|---|---|---|")
    for k in sorted(fam):
        c = fam[k]
        print("| %s | %d | %d | %d | %d |" % (k, sum(c.values()), c["PASS"], c["FAIL"], c["BLOCKED"] + c["other"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
