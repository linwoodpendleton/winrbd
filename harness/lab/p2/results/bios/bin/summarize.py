#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""summarize.py - one table over the evidence directories of the qemu-bios module.

  summarize.py RESULTS_DIR [--md]

Reads RESULTS_DIR/<label>/{result.txt,metrics.json,hashes.txt} for every label and prints one line each: the verdict, the seconds of the stages,
the read phase (GRUB's countdown ended -> the initramfs started: the time the firmware spent serving the kernel and the initramfs through
INT 13h), the table length and where the scan found it, the stack and heap marks. With --md the same as a Markdown table.
"""
import json
import os
import re
import sys


def load(d):
    r = {"label": os.path.basename(d.rstrip("/"))}
    try:
        with open(os.path.join(d, "metrics.json")) as f:
            m = json.load(f)
    except (OSError, ValueError):
        m = {}
    try:
        with open(os.path.join(d, "result.txt")) as f:
            res = f.read()
    except OSError:
        res = ""
    try:
        with open(os.path.join(d, "hashes.txt")) as f:
            h = f.read()
    except OSError:
        h = ""
    v = re.search(r"^VERDICT (\w+)", res, re.M)
    r["verdict"] = v.group(1) if v else "-"
    if r["verdict"] == "PASS" and re.search(r"^NOTE hooked drive readable .*: NO\b", res, re.M):
        # the criteria of row B0 are "visible to the BIOS + the table + the local disk boots" and held; the drive could not be READ (finding F3):
        # a bare PASS in the table would hide that
        r["verdict"] = "PASS (drive unreadable)"
    if "WinPE shell recognised" in res:       # the WinPE rows have no automatic verdict: the evidence script's probe of the screen
        r["verdict"] = "WinPE shell"
    elif "no shell by the deadline" in res:
        r["verdict"] = "NO SHELL"
    if r["label"].startswith("DIAG"):
        r["verdict"] = "diagnostic"
    st = m.get("stages", {})
    r["net"] = st.get("net")
    r["san"] = st.get("san_start")
    r["grub"] = st.get("grub")
    r["countdown"] = st.get("grub_countdown_end")
    r["initramfs"] = st.get("grub_loading")
    r["root_ok"] = st.get("root_ok")
    r["read_s"] = (st["grub_loading"] - st["grub_countdown_end"]) if "grub_loading" in st and "grub_countdown_end" in st else None
    rb = m.get("rbft", {})
    r["table_len"] = rb.get("length")
    src = rb.get("source") or ""
    a = re.search(r"physical address (0x[0-9a-f]+)", src)
    r["table_at"] = a.group(1) if a else None
    r["fields"] = "%s/%s/%s" % (rb.get("pass"), rb.get("fail"), rb.get("skip")) if rb.get("result") else None
    s = m.get("stack", {})
    r["stack"] = ("%s/%s" % (s.get("ipxe_used"), s.get("ipxe_total"))) if "ipxe_used" in s else None
    r["core_stack"] = ("%s/%s" % (s.get("core_used"), s.get("core_total"))) if "core_used" in s else None
    hp = m.get("heap", {})
    r["arena"] = hp.get("arena_bytes")
    r["bulk"] = hp.get("bulk_bytes")
    i = m.get("int13", {})
    r["reads"] = i.get("reads")
    r["sectors"] = i.get("sectors")
    r["n127"] = i.get("sectors_127")
    r["variant"] = (re.search(r"^ipxe_variant\s+(\S+)", h, re.M) or [None, "-"])[1]
    return r


def fmt(x, nd=1):
    if x is None:
        return "-"
    if isinstance(x, float):
        return ("%." + str(nd) + "f") % x
    return str(x)


COLS = [("label", "label"), ("variant", "build"), ("verdict", "verdict"), ("net", "net s"), ("san", "SAN s"), ("grub", "GRUB s"), ("read_s", "read s"),
        ("initramfs", "initramfs s"), ("root_ok", "root OK s"), ("table_len", "table B"), ("fields", "pass/fail/skip"), ("stack", "stack used/total"),
        ("core_stack", "core stack"), ("arena", "arena B"), ("bulk", "bulk B"), ("reads", "reads"), ("sectors", "sectors"), ("n127", "of 127")]


def main(argv):
    if not argv:
        sys.stderr.write(__doc__)
        return 2
    root = argv[0]
    md = "--md" in argv
    rows = []
    for name in sorted(os.listdir(root)):
        d = os.path.join(root, name)
        if os.path.isdir(d) and os.path.exists(os.path.join(d, "result.txt")):
            rows.append(load(d))
    if md:
        print("| " + " | ".join(c[1] for c in COLS) + " |")
        print("|" + "|".join("---" for _ in COLS) + "|")
        for r in rows:
            print("| " + " | ".join(fmt(r[c[0]]) for c in COLS) + " |")
    else:
        for r in rows:
            print("  ".join("%s=%s" % (c[0], fmt(r[c[0]])) for c in COLS))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
