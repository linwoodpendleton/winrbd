#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""analyze.py - judge one robustness row (qemu-robust) from the files rr.sh kept, and write facts.txt.

    analyze.py --dir ROWDIR --profile bytes|reader|boot|negative --workload W --fault KIND --family uefi|bios --expect-dir EXPECTDIR

stdout: the verdict. First line PASS, FAIL or BLOCKED, then one line per check:  PASS|FAIL|NOTE|INFO  <what>: <what was seen>.
  PASS    = every check of the row's profile held (NOTE and INFO lines never change the first line);
  FAIL    = at least one check did not hold: the row is a finding;
  BLOCKED = the guest did not run at all (no console log): nothing is said about the driver.
facts.txt in the row directory: what was extracted (times, counters), one "key: value" per line, so a rerun of this script can be compared.

What a row has to show (the checks differ by profile; every one is a line of the verdict):
  all     the fault was injected and undone (fault.txt), it overlapped the workload, the lab's state after equals the state before (lab-diff.txt), every OSD up and in,
          no key shape in any file, the run script's exit status
  bytes   the 17 files read through the SAN device have the md5 of the list the disk was built from (and the list was checked against `rbd export`)
  reader  the reader's hash of everything it read (and of every prefix it printed) equals the oracle's, no canary violation (stale = 0), no read error
          that reached the loader
  boot    the Linux guest reached WRBOOT-ROOT-OK with its table check passing, the root on the image
  negative  one driver console line with the right text, the right errno, nothing booted, and no allocation failure

Standard library only. The expectations (md5 list, hash prefixes) are files in EXPECTDIR; a missing one is a FAIL of the check, not a pass.
"""
import argparse
import os
import re
import sys

ERRNO_TOP = {  # the top byte of an iPXE error number: the generic errno (include/errno.h of the pinned tree)
    0x02: "EACCES", 0x0A: "EBUSY", 0x0B: "ECANCELED", 0x0F: "ECONNRESET", 0x1C: "EINVAL", 0x1D: "EIO",
    0x28: "ENETUNREACH", 0x2C: "ENODEV", 0x2D: "ENOENT", 0x31: "ENOMEM", 0x34: "ENOSPC", 0x3C: "ENOTSUP",
    0x43: "EPROTO", 0x47: "EROFS", 0x4C: "ETIMEDOUT",
}
NEG = {  # workload -> (errno names accepted, console regex of the one driver line)
    "neg-key": (("EACCES",), r"^rbd: .*failed: .*\((WR_E_AUTH_[A-Z_]+|WR_E_M2_BAD_METHOD; the cluster answered -[0-9]+)\)"),
    "neg-pool": (("ENOENT",), r"^rbd: .*failed: pool not found .*\(WR_E_POOL_NOT_FOUND\)"),
    "neg-image": (("ENOENT",), r"^rbd: .*failed: image not found .*\(WR_E_RBD_NOT_FOUND\)"),
    "neg-mon": (("ETIMEDOUT", "ENETUNREACH"), r"^rbd: .*failed: .*\(WR_E_(MON_UNREACHABLE|TIMEOUT|NET_CONNECT|M2_HANDSHAKE_TIMEOUT)\)"),
}
ANSI = re.compile(r"\x1b\[[0-9;?=]*[A-Za-z]|\x1b[()][A-Z0-9]")
KEYSHAPE = re.compile(r"(?<![A-Za-z0-9+/])A[Qg][A-Za-z0-9+/]{30,}={0,2}")


class V:
    """The verdict: lines, and the first word."""

    def __init__(self):
        self.lines = []
        self.bad = 0

    def ok(self, what, seen=""):
        self.lines.append("PASS %s%s" % (what, ": " + seen if seen else ""))

    def fail(self, what, seen=""):
        self.bad += 1
        self.lines.append("FAIL %s%s" % (what, ": " + seen if seen else ""))

    def check(self, cond, what, seen=""):
        (self.ok if cond else self.fail)(what, seen)

    def note(self, what):
        self.lines.append("NOTE " + what)

    def info(self, what):
        self.lines.append("INFO " + what)


def read(path):
    try:
        with open(path, "rb") as f:
            return f.read().decode("latin-1")
    except OSError:
        return None


def clean(text):
    return ANSI.sub("", text.replace("\r", "").replace("\x00", ""))


def parse_ts(text):
    """[(epoch, line)] from ts.txt"""
    out = []
    for ln in (text or "").split("\n"):
        m = re.match(r"^(\d+\.\d+) (.*)$", ln)
        if m:
            out.append((float(m.group(1)), clean(m.group(2))))
    return out


def parse_fault(text):
    """[(epoch, text)] from fault.txt (the leading 'T+n' is dropped)"""
    out = []
    for ln in (text or "").split("\n"):
        m = re.match(r"^(\d+\.\d+) T\+\d+ (.*)$", ln)
        if m:
            out.append((float(m.group(1)), m.group(2)))
    return out


def info_blocks(lines, begin, end):
    """The text lines of every rbd-info report (between the begin and end marker lines)"""
    blocks, cur = [], None
    for t, ln in lines:
        if ln.startswith(begin):
            cur = []
        elif ln.startswith(end):
            if cur is not None:
                blocks.append(cur)
            cur = None
        elif cur is not None:
            cur.append(ln)
    return blocks


def counters(block):
    """The numbers of an rbd-info report"""
    d = {}
    txt = "\n".join(block)
    pats = {
        "pumps": r"session: (\d+) pumps", "cancels": r"pumps, (\d+) cancels", "reopens": r"cancels \(most rounds \d+\), (\d+) reopens",
        "stall_closes": r"reopens, (\d+) stall closes", "conns": r"connections (\d+) \(most (\d+)\)", "ops_done": r"osd: (\d+) ops done",
        "ops_resent": r"ops done, (\d+) resent", "ops_failed": r"resent, (\d+) failed", "session_resets": r"(\d+) session resets",
        "ra_reads": r"readahead: (\d+) reads", "devices": r"(\d+) device\(s\)",
    }
    for k, p in pats.items():
        m = re.search(p, txt)
        if m:
            d[k] = int(m.group(1)) if k != "conns" else (int(m.group(1)), int(m.group(2)))
    m = re.search(r"rbd: image \S+: (\w+),", txt)
    if m:
        d["state"] = m.group(1)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--workload", default="")
    ap.add_argument("--fault", default="none")
    ap.add_argument("--family", default="")
    ap.add_argument("--expect-dir", default="")
    a = ap.parse_args()
    d = a.dir
    v = V()
    facts = []

    def fact(k, val):
        facts.append("%s: %s" % (k, val))

    serial_raw = read(os.path.join(d, "serial.txt"))
    if not serial_raw:
        print("BLOCKED\nno console log: the guest did not run (or the run script discarded it)")
        return
    serial = clean(serial_raw)
    slines = serial.split("\n")
    ts = parse_ts(read(os.path.join(d, "ts.txt")))
    fl = parse_fault(read(os.path.join(d, "fault.txt")))
    result = read(os.path.join(d, "result.txt")) or ""
    stdout = read(os.path.join(d, "stdout.txt")) or ""

    def t_of(rx, nth=0, last=False):
        hits = [t for t, ln in ts if re.search(rx, ln)]
        if not hits:
            return None
        return hits[-1] if last else hits[nth]

    # the start of the guest is the "guest started" line; fault.txt has lines before it (the lab's health at the start, the idle timeout being set)
    t_start = next((t for t, txt in fl if txt.startswith("guest started")), fl[0][0] if fl else (ts[0][0] if ts else 0.0))
    fact("guest_started_epoch", "%.3f" % t_start)

    # ---- the fault
    f_begin = f_end = None
    cut = None
    for t, txt in fl:
        if re.match(r"fault \S+: begins", txt) and f_begin is None:
            f_begin = t
        if re.match(r"fault \S+: ends", txt):
            f_end = t
        if "the run ended before the fault did" in txt:
            cut = t
    problems = [txt for t, txt in fl if re.search(r"UNDO FAILED|NO FAULT WAS INJECTED|KEYS NOT PRESSED|did NOT|failure|NOT come back|still raised", txt)]
    if a.fault != "none":
        if f_end is None and cut is not None:
            f_end = cut
        done = f_begin is not None and f_end is not None
        v.check(done and not problems, "the fault was injected and undone",
                ("begins +%.1f s, %s +%.1f s after the start of the guest%s" % (f_begin - t_start, "cut short at" if cut else "ends", (f_end or f_begin) - t_start,
                                                                                   ("; " + "; ".join(problems)) if problems else ""))
                if f_begin else "fault.txt has no begin line")
        if cut is not None and f_begin is not None:
            v.note("the guest finished %.1f s after the fault began, before the fault's own %s s were up: the fault was undone at the end of the run (the lab was put back)"
                   % (cut - f_begin, next((m.group(1) for t, txt in fl for m in [re.search(r"begins \(down ([0-9.]+) s\)", txt)] if m), "?")))
        if f_begin:
            fact("fault_begin", "+%.1f s" % (f_begin - t_start))
            fact("fault_end", "+%.1f s (%s %.1f s)" % ((f_end or f_begin) - t_start, "cut short after" if cut else "lasted", (f_end or f_begin) - f_begin))
        for t, txt in fl:
            if re.search(r"back in quorum|up and in again|stopped|killed|started|continued|link set|SIGSTOP|SIGCONT", txt) and not txt.startswith("guest started"):
                fact("fault_event", "+%.1f s %s" % (t - t_start, txt))
    else:
        v.check(not problems, "no fault, and nothing in fault.txt that says otherwise", "; ".join(problems))
    if any("KEYS NOT PRESSED" in txt for t, txt in fl):
        v.fail("the keys of --press were pressed", "KEYS NOT PRESSED")
    pressed = [t for t, txt in fl if re.search(r"^keys '.*' pressed$", txt)]
    if pressed:
        fact("keys_pressed", "+%.1f s" % (pressed[0] - t_start))

    # ---- the workload: its interval on the clock
    w0 = w1 = None
    if a.workload == "bytes":
        w0, w1 = t_of(r"^WRBYTES-FILE "), t_of(r"^WRBYTES-DONE")
    elif a.workload == "reader":
        w0, w1 = t_of(r"^WRRB-START"), t_of(r"^WRRB-DONE")
    elif a.workload == "boot":
        # the firmware's part of the boot (what the iPXE driver serves): from the SAN open to the first line the Linux initramfs prints; what comes after is the guest's
        # own kernel client (it maps the image itself, through the monitor)
        w0 = t_of(r"^WRRUN-SAN-START")
        w1 = t_of(r"^(Loading, please wait|Starting systemd-udevd|Begin: Loading essential drivers)")
        if w1 is None:
            w1 = t_of(r"^WRBOOT-HOOK-DONE")
    if w0:
        fact("workload_start", "+%.1f s" % (w0 - t_start))
    if w1:
        fact("workload_end", "+%.1f s (took %.1f s)" % (w1 - t_start, w1 - (w0 or w1)))
    if a.fault != "none" and f_begin is not None and a.profile != "negative":
        if w1 is None:
            v.note("the workload has no end marker, so whether the fault began before it ended is judged from the verdict of the workload alone")
        else:
            lead = w1 - f_begin
            v.check(lead > 0.3, "the fault began while the guest was still working",
                    "fault began %.1f s %s the workload's end marker" % (abs(lead), "before" if lead > 0 else "after"))
            if w0 and f_begin < w0:
                v.note("the fault began %.1f s before the workload's first marker (the firmware was still starting it)" % (w0 - f_begin))

    # ---- driver console lines
    trouble = []
    for ln in slines:
        if re.search(r"parse URI failed|out of memory|Not enough space|could not \(re\)open|SAN \S+ could not", ln, re.I):
            trouble.append(ln.strip())
    # (the line can follow iPXE's progress text on the same console line: "file://x... rbd: the cluster ...")
    closes = [m.group(0) for ln in slines for m in [re.search(r"rbd: the cluster has not answered for \d+ seconds, closing the path.*$", ln)] if m]
    fact("stall_close_lines", len(closes))
    for ln in closes[:6]:
        fact("stall_close", ln)
    fact("trouble_lines", len(trouble))
    for ln in trouble[:6]:
        fact("trouble", ln)
    sanfail = [ln for ln in slines if re.search(r"Could not open SAN device|Boot from SAN device .* failed|SAN device .* failed", ln)]
    for ln in sanfail[:4]:
        fact("san_failure_line", ln.strip())
    # rbd-info
    blocks = info_blocks(ts, "WRINFO-BEGIN", "WRINFO-END") + info_blocks(ts, "WRROB-INFO-BEGIN", "WRROB-INFO-END")
    cnt = counters(blocks[-1]) if blocks else {}
    for k, val in cnt.items():
        fact("rbd_info_" + k, val)
    if len(blocks) >= 2:
        c0 = counters(blocks[0])
        fact("rbd_info_before", "; ".join("%s=%s" % (k, c0[k]) for k in sorted(c0)))

    # ---- profile checks
    if a.profile == "bytes":
        want = {}
        txt = read(os.path.join(a.expect_dir, "bytes.md5")) if a.expect_dir else None
        if txt:
            for ln in txt.strip().split("\n"):
                m = re.match(r"^([0-9a-f]{32})  (\S+)$", ln)
                if m and m.group(2) != "Shell.efi":
                    want[m.group(2)] = m.group(1)
        v.check(len(want) >= 10, "the md5 list of the disk is known", "%d files" % len(want))
        v.check(any(ln.startswith("WRRUN-SAN-OK") for ln in slines), "the SAN device was opened")
        got, failed, cur = {}, [], None
        for ln in slines:
            m = re.match(r"^WRBYTES-FILE (\S+)$", ln)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^WRBYTES-FAIL (\S+)$", ln)
            if m:
                failed.append(m.group(1))
                cur = None
                continue
            m = re.match(r"^([0-9a-f]{32})  wrb$", ln)
            if m and cur:
                got[cur] = m.group(1)
        if a.fault == "outage":
            # the cluster is gone for minutes: the SAN layer retries and gives up, so some reads must FAIL; what must never happen is a wrong digest
            wrong = sorted(n for n in got if got[n] != want.get(n))
            v.check(bool(failed), "the SAN layer gave up: at least one read failed and said so", ", ".join(failed) or "no read failed (the outage did not make the SAN layer give up)")
            v.check(not wrong, "no digest that was printed is wrong", ", ".join(wrong))
            v.check(len(got) >= 1, "files were read correctly before or after the outage", "%d of %d digests printed" % (len(got), len(want)))
            fact("files_failed", ", ".join(failed))
            bad = []
        else:
            bad = sorted(n for n in want if got.get(n) != want[n])
            v.check(not failed, "no file failed to read", ", ".join(failed))
            v.check(not bad and len(got) == len(want), "every file has the md5 of the list",
                    "%d of %d equal%s" % (len(want) - len(bad), len(want), ("; wrong or missing: " + ", ".join(bad)) if bad else ""))
        v.check(any(ln.startswith("WRBYTES-DONE") for ln in slines), "the script ran to its end (WRBYTES-DONE)")
        fact("files_read", "%d of %d" % (len(got), len(want)))
        if a.fault == "outage":
            pass
    elif a.profile == "reader":
        prefix, final = {}, None
        txt = read(os.path.join(a.expect_dir, "reader.prefix")) if a.expect_dir else None
        for ln in (txt or "").strip().split("\n"):
            m = re.match(r"^(\d+) ([0-9a-f]{8})$", ln)
            if m:
                prefix[int(m.group(1))] = m.group(2).upper()
            m = re.match(r"^final (\d+) ([0-9a-f]{8})$", ln)
            if m:
                final = (int(m.group(1)), m.group(2).upper())
        v.check(final is not None and len(prefix) > 10, "the oracle of the reader is known", "final hash %s, %d prefixes" % (final[1] if final else "-", len(prefix)))
        v.check(any(ln.startswith("WRRUN-SAN-OK") for ln in slines), "the SAN device was opened")
        progs = [(int(m.group(1)), m.group(2)) for ln in slines for m in [re.match(r"^WRRB-PROG lba=(\d+) h=([0-9A-F]{8}) ", ln)] if m]
        wrong = [(l, h) for l, h in progs if prefix.get(l) != h]
        v.check(progs and not wrong, "every progress hash equals the oracle's prefix hash", "%d lines, %d wrong%s" % (len(progs), len(wrong), (" (first at lba %d)" % wrong[0][0]) if wrong else ""))
        done = [m for ln in slines for m in [re.match(r"^WRRB-DONE sectors=(\d+) h=([0-9A-F]{8}) errs=(\d+) stale=(\d+) maxticks=(\d+)@(\d+) rtc=(\d+) end=(\w+)$", ln)] if m]
        v.check(bool(done), "the reader finished (WRRB-DONE)")
        if done:
            sec, h, errs, stale, mt, mlba, rtc, end = done[-1].groups()
            v.check(end == "ok" and final is not None and (int(sec), h) == final, "the whole read has the oracle's hash",
                    "%s sectors, hash %s, want %s" % (sec, h, ("%d %s" % final) if final else "-"))
            v.check(int(stale) == 0, "no write landed in a buffer the loader had moved on from (canary)", "stale=%s" % stale)
            if a.fault == "outage":
                v.check(int(errs) >= 1, "the SAN layer gave up: a read error reached the loader", "errs=%s" % errs)
            else:
                v.check(int(errs) == 0, "no read error reached the loader", "errs=%s" % errs)
            fact("reader_errs", errs)
            fact("reader_stale", stale)
            fact("reader_maxticks", "%s ticks (%.1f s) at lba %s" % (mt, int(mt) / 18.2, mlba))
        st = [ln for ln in slines if ln.startswith("WRRB-STALE")]
        v.check(not st, "no WRRB-STALE line", "; ".join(st[:3]))
        errlines = [ln for ln in slines if ln.startswith("WRRB-ERR")]
        for ln in errlines[:6]:
            fact("reader_err_line", ln)
        # the clock the guest kept (the CMOS clock follows the host's; the BIOS ticks stop with the guest)
        rtcs = [m.group(1) for ln in slines for m in [re.match(r"^WRRB-(?:START|PROG|DONE).* rtc=(\d{6})", ln)] if m]
        if rtcs:
            def secs(s):
                h, m_, s_ = (int(s[i:i + 2]) for i in (0, 2, 4))
                return h * 3600 + m_ * 60 + s_
            gaps = []
            for (x, y) in zip(rtcs, rtcs[1:]):
                dlt = (secs(y) - secs(x)) % 86400
                gaps.append(dlt)
            if gaps:
                fact("reader_rtc_largest_step_seconds", max(gaps))
    elif a.profile == "boot":
        v.check(any(re.search(r"WRBOOT-ROOT-OK", ln) for ln in slines), "the system booted with its root on the image (WRBOOT-ROOT-OK)")
        m = [ln for ln in slines if re.search(r"WRBOOT-ROOT-OK", ln)]
        for ln in m[:1]:
            fact("root_ok_line", ln.strip())
        res = [ln for ln in slines if ln.startswith("RBFT-RESULT")]
        v.check(bool(res) and all(re.match(r"^RBFT-RESULT PASS pass=40 fail=0 skip=0", ln) for ln in res), "the table check passed in the guest", res[-1] if res else "no RBFT-RESULT line")
        bad = [ln for ln in slines if re.search(r"WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF|error: failure reading sector|Failed to boot", ln)]
        v.check(not bad, "no failure marker (not on RBD, table failure, kernel panic, GRUB read error)", "; ".join(x.strip() for x in bad[:3]))
        if w1 and w0:
            fact("boot_phase_seconds", "%.1f (SAN start to the first line of the Linux initramfs: the firmware's part)" % (w1 - w0))
        t_hook = t_of(r"^WRBOOT-HOOK-DONE")
        if t_hook and w1:
            fact("kernel_client_seconds", "%.1f (first initramfs line to the end of the image mapping by the guest's own kernel client)" % (t_hook - w1))
        t_ok = t_of(r"WRBOOT-ROOT-OK")
        if t_ok:
            fact("root_ok_at", "+%.1f s" % (t_ok - t_start))
        t_grub = t_of(r"before booting or")
        if t_grub:
            fact("grub_menu_at", "+%.1f s" % (t_grub - t_start))
    elif a.profile == "bootgive":
        ok = [ln for ln in slines if re.search(r"WRBOOT-ROOT-OK", ln)]
        err = [ln.strip() for ln in slines if re.search(r"error: failure reading sector|Failed to boot|Boot from SAN device .* failed|Could not (boot|open)", ln)]
        bad = [ln for ln in slines if re.search(r"WRBOOT-ROOT-(NOT-RBD|TABLE-FAIL|WRONG)|Kernel panic|WRBOOT-HOOK-POWEROFF", ln)]
        v.check(bool(ok) or bool(err), "the loader reached an outcome: it booted after the cluster came back, or it reported a read error", "booted" if ok else (err[0] if err else "neither: the run ended with no outcome"))
        v.check(not bad, "no damaged boot (not on RBD, table failure, kernel panic)", "; ".join(x.strip() for x in bad[:3]))
        if ok:
            res = [ln for ln in slines if ln.startswith("RBFT-RESULT")]
            v.check(bool(res) and all(re.match(r"^RBFT-RESULT PASS pass=40 fail=0 skip=0", ln) for ln in res), "when it booted, the table check passed", res[-1] if res else "no RBFT-RESULT line")
            t_ok = t_of(r"WRBOOT-ROOT-OK")
            if t_ok:
                fact("booted_at", "+%.1f s" % (t_ok - t_start))
        fact("outcome", "booted after the outage" if ok else ("loader error: " + err[0] if err else "none"))
        for ln in err[:4]:
            fact("loader_error_line", ln)
        t_err = t_of(r"error: failure reading sector|Failed to boot|Boot from SAN device .* failed")
        if t_err:
            fact("loader_error_at", "+%.1f s" % (t_err - t_start))
        v.check(not trouble, "no allocation failure and no reopen loop on the console", "; ".join(trouble[:3]))
    elif a.profile == "negative":
        want = NEG.get(a.workload)
        v.check(want is not None, "the negative row has an expectation", a.workload)
        if want:
            names, rx = want
            m = [re.match(r"^WRRUN-SAN-FAILED 0x([0-9a-f]+)$", ln) for ln in slines]
            m = [x for x in m if x]
            v.check(bool(m), "the SAN open failed (WRRUN-SAN-FAILED)")
            if m:
                code = int(m[-1].group(1), 16)
                name = ERRNO_TOP.get(code >> 24, "errno 0x%02x" % (code >> 24))
                v.check(name in names, "the errno is the right one", "%s (0x%08x), want %s" % (name, code, " or ".join(names)))
                fact("errno", "%s 0x%08x" % (name, code))
            driver = [ln.strip() for ln in slines if re.match(r"^rbd: .*(failed|error)", ln) and "high-water" not in ln]
            fact("driver_lines", len(driver))
            for ln in driver[:4]:
                fact("driver_line", ln)
            v.check(len(driver) == 1 and re.match(rx, driver[0]) is not None, "one driver console line, with the right text", "%d line(s): %s" % (len(driver), "; ".join(driver[:3])))
            v.check(any("Could not open SAN device" in ln for ln in slines), "iPXE's own line (Could not open SAN device) is there")
            v.check(not any(re.search(r"Registered SAN device|Booting from SAN device", ln) for ln in slines), "no SAN device was registered and nothing booted")
            v.check(not trouble, "no allocation failure or reopen loop", "; ".join(trouble[:3]))
            t_fail = t_of(r"^WRRUN-SAN-FAILED")
            t_try = t_of(r"^WRRUN-SAN-START")
            if t_fail and t_try:
                fact("seconds_to_fail", "%.1f" % (t_fail - t_try))
    else:
        v.fail("known profile", a.profile)

    # robustness verdicts that every workload shares
    if a.profile in ("bytes", "reader", "boot"):
        v.check(not trouble, "no allocation failure and no reopen loop on the console", "; ".join(trouble[:3]))
    if a.profile in ("bytes", "reader") and a.fault in ("stall", "link-down", "osd-kill", "outage"):
        pass
    if blocks:
        fact("rbd_info_reports", len(blocks))

    # ---- the lab
    ld = read(os.path.join(d, "lab-diff.txt"))
    if ld is None:
        v.note("no lab state diff was taken for this row")
    else:
        v.check("labstate: no difference" in ld, "the lab's state after equals the state before", "no difference" if "no difference" in ld else ld.strip().replace("\n", " | ")[:300])
    hl = read(os.path.join(d, "lab-health.txt")) or ""
    after = [ln for ln in hl.split("\n") if ln.startswith("health after")]
    if after:
        v.check(bool(re.search(r"3 osds: 3 up .*3 in", after[-1])), "every OSD is up and in after the row", after[-1][:160])
        m = re.search(r"(\d+) pgs: ([^;]+)", after[-1])
        if m:
            fact("pgs_after", m.group(2))
    # the exit status of the run
    m = re.search(r"exit=(\d+)", result)
    code = int(m.group(1)) if m else -1
    fact("exit", code)
    m = re.search(r"stop=(\S+)", result)
    fact("stop", m.group(1) if m else "-")
    if a.profile != "negative":
        v.check(code == 0, "the run script's exit status is 0", "exit=%d%s" % (code, (" stop=" + m.group(1)) if m else ""))
    else:
        v.check(code in (0,), "the run script's exit status is 0 (the marker was seen)", "exit=%d" % code)
    # the capture
    syn = read(os.path.join(d, "syn.txt"))
    if syn:
        summarise_syn(syn, t_start, f_begin, f_end, facts, fl, v)
    # the key
    shape = []
    for name in ("serial.txt", "ts.txt", "stdout.txt", "fault.txt", "cmdline.txt"):
        txt = read(os.path.join(d, name)) or ""
        if KEYSHAPE.search(clean(txt)):
            shape.append(name)
    v.check(not shape, "no key-shaped string in the row's files", ", ".join(shape))

    first = "PASS" if v.bad == 0 else "FAIL"
    with open(os.path.join(d, "facts.txt"), "w") as f:
        f.write("\n".join(facts) + "\n")
    print(first)
    print("\n".join(v.lines))


def summarise_syn(syn, t_start, f_begin, f_end, facts, fl, v):
    """Counts from the lab VM's capture (tcpdump -q on the lab VM: one line per packet; every SYN of the guest's address, and every packet to or from a monitor
    port). The lab VM's clock is compared with ours through the 'lab-clock' line of fault.txt (the ssh round trip is in it: about a second at most)."""
    off = 0.0
    for t, txt in fl:
        m = re.match(r"^lab-clock (\d+\.\d+)$", txt)
        if m:
            off = float(m.group(1)) - t
            break
    facts.append("lab_clock_offset_seconds: %.2f (the lab VM's clock minus ours, the ssh round trip included)" % off)
    first = {}      # (guest port, server port) -> time of the first packet seen: the start of a connection (the capture starts before the guest does)
    mon_in = []     # (t, bytes) monitor -> guest
    for ln in syn.split("\n"):
        m = re.match(r"^(\d+\.\d+) \S+\s+(In|Out)\s+IP (\S+)\.(\d+) > (\S+)\.(\d+): tcp (\d+)", ln)
        if not m:
            continue
        t = float(m.group(1)) - off
        sport, dport, nb = int(m.group(4)), int(m.group(6)), int(m.group(7))
        if m.group(2) == "In":
            first.setdefault((sport, dport), t)
        elif sport in (3300, 6789):
            mon_in.append((t, nb))

    def role(p):
        return "monitor" if p in (3300, 6789) else "osd"
    conns = sorted((t, dp) for (sp, dp), t in first.items())
    tot = {}
    for t, p in conns:
        tot[role(p)] = tot.get(role(p), 0) + 1
    facts.append("connections_started_in_the_run: %s" % (", ".join("%s %d" % kv for kv in sorted(tot.items())) or "none seen"))
    if f_begin is not None:
        end = f_end if f_end is not None else f_begin
        late = [(t, p) for t, p in conns if t >= f_begin]
        facts.append("connections_started_after_the_fault_began: %s" % (", ".join("+%.1f s %s:%d" % (t - t_start, role(p), p) for t, p in late[:16]) or "none"))
        before = [nb for t, nb in mon_in if t < f_begin]
        during = [nb for t, nb in mon_in if f_begin <= t <= end]
        after = [nb for t, nb in mon_in if t > end]
        facts.append("monitor_to_guest_bytes: %d before the fault (%d packets), %d while it lasted (%d), %d after it ended (%d)"
                     % (sum(before), len(before), sum(during), len(during), sum(after), len(after)))


if __name__ == "__main__":
    main()
