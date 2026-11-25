#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""report.py - the numbers the README quotes, computed from the evidence directories (so that no number in it is typed by hand).

  report.py RESULTS_DIR

Prints Markdown: the readahead comparison (labels *-ra0-N against *-rad-N: the read phase = GRUB's countdown ended -> the initramfs started),
the stack and heap marks of every build that has them, the INT 13h command statistics of the trace runs, and the pause measurement.
"""
import json
import os
import re
import statistics
import sys


def load(d):
    try:
        with open(os.path.join(d, "metrics.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def read_phase(m):
    st = m.get("stages", {})
    if "grub_loading" in st and "grub_countdown_end" in st:
        return st["grub_loading"] - st["grub_countdown_end"]
    return None


def variant_of(d):
    try:
        with open(os.path.join(d, "hashes.txt")) as f:
            m = re.search(r"^ipxe_variant\s+(\S+)", f.read(), re.M)
            return m.group(1) if m else "-"
    except OSError:
        return "-"


def main(argv):
    root = argv[0]
    only = None
    if len(argv) >= 3 and argv[1] == "--section":
        only = argv[2]
    runs = {}
    for name in sorted(os.listdir(root)):
        m = load(os.path.join(root, name))
        if m is not None:
            runs[name] = m
    out_all = sys.stdout
    import io
    sections = {}
    buf = io.StringIO()
    sys.stdout = buf
    print("## Readahead: time the firmware spent serving GRUB's reads of the kernel and the initramfs\n")
    print("| path | readahead | runs | read phase s (min / median / max) |")
    print("|---|---|---|---|")
    for prefix, what in (("B1-i386", "PXE, undionly.kpxe (UNDI NIC)"), ("B3-i386", "CD, ipxe.iso (native NIC)")):
        for tag, ra in (("ra0", "0 (off)"), ("rad", "2048 KiB (default)")):
            vals = [read_phase(m) for n, m in runs.items() if re.match(r"^%s-%s-\d+$" % (prefix, tag), n)]
            vals = [v for v in vals if v is not None]
            if vals:
                print("| %s | %s | %d | %.1f / %.1f / %.1f |" % (what, ra, len(vals), min(vals), statistics.median(vals), max(vals)))
    sections["readahead"] = buf.getvalue()
    buf.seek(0); buf.truncate()
    print("## Stack and heap marks\n")
    print("| run | build | iPXE stack used / total (left) | core's own stack | arena B | bulk B |")
    print("|---|---|---|---|---|---|")
    for n, m in runs.items():
        s = m.get("stack")
        h = m.get("heap", {})
        if s or h.get("arena_bytes"):
            i = ("%s / %s (%s)" % (s.get("ipxe_used"), s.get("ipxe_total"), s.get("ipxe_left"))) if s and "ipxe_used" in s else "-"
            c = ("%s / %s" % (s.get("core_used"), s.get("core_total"))) if s and "core_used" in s else "-"
            print("| %s | %s | %s | %s | %s | %s |" % (n, variant_of(os.path.join(root, n)), i, c, h.get("arena_bytes", "-"), h.get("bulk_bytes", "-")))
    sections["stack"] = buf.getvalue()
    buf.seek(0); buf.truncate()
    print("## INT 13h commands (trace builds)\n")
    for n, m in runs.items():
        i = m.get("int13")
        if not i or "pause" in n:   # the pause runs are in the next table; their "max" is the time the guest was stopped
            continue
        print("### %s\n" % n)
        print("- commands %s (reads %s, capacity %s, writes %s), %s sectors = %s MiB, largest %s sectors, %s reads of 127 sectors, %s reads continue the previous one" %
              (i["commands"], i["reads"], i["capacity"], i["writes"], i["sectors"], i["mib"], i["largest"], i["sectors_127"], i["sequential"]))
        if i.get("retries"):
            print("- %d re-issue(s) of a command that had not finished (the SAN layer's own timeout; counted once, not as new reads)" % i["retries"])
        if "latency_ms" in i:
            print("- first issue to done (20 ms resolution): median %s ms, p90 %s ms, max %s ms over %s reads" %
                  (i["latency_ms"]["median"], i["latency_ms"]["p90"], i["latency_ms"]["max"], i["latency_ms"]["n"]))
        h = i["histogram"]
        top = sorted(h.items(), key=lambda kv: -kv[1])[:8]
        print("- most frequent sizes (sectors: count): " + ", ".join("%s: %s" % kv for kv in top))
        big = [int(k) for k in h if int(k) > 64]
        print("- reads over 64 sectors: %d" % sum(h[str(k)] for k in big))
        print()
    sections["trace"] = buf.getvalue()
    buf.seek(0); buf.truncate()
    print("## Pause (guest stopped, then continued)\n")
    print("| run | guest stopped for | stopped at | the command in flight finished | the first command issued after | driver complaints after the resume |")
    print("|---|---|---|---|---|---|")
    for n, m in runs.items():
        p = m.get("pause")
        if not p or "pause_s" not in p:
            continue
        lb = p.get("last_command_before") or {}
        fa = p.get("first_command_after") or {}
        print("| %s | %.0f s | an INT 13h read at LBA %#x (%d sectors) | %s ms after the resume | %s ms (LBA %#x, %s sectors) | %s |" % (
            n, p["pause_s"], lb.get("lba", 0), lb.get("count", 0), p.get("in_flight_done_after_cont_ms", "-"),
            p.get("first_command_after_latency_ms", "-"), fa.get("lba", 0), fa.get("count", "-"), p.get("complaints", "none")))
    sections["pause"] = buf.getvalue()
    sys.stdout = out_all
    if only:
        sys.stdout.write(sections.get(only, ""))
    else:
        for k in ("readahead", "stack", "trace", "pause"):
            sys.stdout.write(sections[k] + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
