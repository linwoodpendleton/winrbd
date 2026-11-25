#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Follow the serial console of one run and write the second at which each stage was first seen.

    stamp.py RUNS_DIR PID OUTFILE [LAB_PIDFILE]

RUNS_DIR is the QEMU scripts' P2Q_WORK/runs; the run directory of the run script with process id PID is the one whose name ends in "-PID".
The log is read every 0.5 s until the run script has ended (PID gone) and the log has been read once more. Times are seconds since this
program started, which is within a second or two of the start of the run script; the run script's own RESULT line has the exact
guest-relative times of its stages (ipxe, net, san, end, os), these are the ones it does not record (grub, kernel, login ...).
With LAB_PIDFILE (the lab VM's QEMU pid file) the CPU wait of the cluster's own threads is measured too: a guest that waits for nothing while the
cluster it reads from is starved looks like a driver stall in the guest's numbers alone.
Needs nothing but the standard library. The file holds "<seconds> <stage> <the line>" per stage (the line cut to 160 characters)."""
import glob
import os
import re
import sys
import time

STAGES = [
    ("ipxe-script", re.compile(rb"WRRUN-BEGIN")),
    ("net-ok", re.compile(rb"WRRUN-NET-OK")),
    ("san-start", re.compile(rb"WRRUN-SAN-START")),
    ("san-ok", re.compile(rb"WRRUN-SAN-OK")),
    ("san-failed", re.compile(rb"WRRUN-SAN-FAILED")),
    ("script-end", re.compile(rb"WRRUN-END")),
    ("uefi-shell", re.compile(rb"Shell> ")),
    ("grub", re.compile(rb"GNU GRUB")),
    ("kernel-up", re.compile(rb"^Begin: (Loading essential drivers|Running /scripts/init-top)|^\[ *\d+\.\d+\] ")),   # initramfs running = kernel booted
    ("table-check-done", re.compile(rb"RBFT-RESULT")),
    ("root-ok", re.compile(rb"^WRBOOT-ROOT-OK")),
    ("login", re.compile(rb"login: ?\r?$")),
    ("kernel-panic", re.compile(rb"Kernel panic")),
]


def alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def run_delay_ns(pid: int) -> int:
    """Total time the guest's threads spent runnable but not running (the host's scheduler kept them waiting), in ns."""
    total = 0
    try:
        for t in os.listdir("/proc/%d/task" % pid):
            try:
                with open("/proc/%d/task/%s/schedstat" % (pid, t)) as f:
                    total += int(f.read().split()[1])
            except (OSError, ValueError, IndexError):
                pass
    except OSError:
        return -1
    return total


class Wait:
    """The CPU wait of one QEMU process, summed over its threads, as the difference between two polls."""

    def __init__(self):
        self.last = None
        self.total = 0
        self.worst = (0.0, 0.0)        # (seconds waited within one polling interval, at second)

    def poll(self, pid: int, now: float) -> None:
        rd = run_delay_ns(pid)
        if rd < 0:
            return
        if self.last is not None and rd >= self.last:
            self.total += rd - self.last
            if (rd - self.last) / 1e9 > self.worst[0]:
                self.worst = ((rd - self.last) / 1e9, now)
        self.last = rd


def read_pid(path: str) -> int:
    try:
        return int(open(path).read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0


def main() -> int:
    if len(sys.argv) not in (4, 5):
        print(__doc__, file=sys.stderr)
        return 2
    runs, pid, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    labfile = sys.argv[4] if len(sys.argv) == 5 else ""
    lab = Wait()
    t0 = time.monotonic()
    seen = {}
    done = False
    final = False
    qpid = 0
    guest = Wait()
    load0 = "%.2f" % os.getloadavg()[0]
    while not final:
        if not alive(pid):
            final = True  # one more read, then stop
        found = glob.glob(os.path.join(runs, "*-%d" % pid, "console.log"))
        if found:
            try:
                with open(found[0], "rb") as f:
                    data = f.read()
            except OSError:
                data = b""
            now = time.monotonic() - t0
            if not qpid:
                try:
                    qpid = int(open(os.path.join(os.path.dirname(found[0]), "qemu.pid")).read().split()[0])
                except (OSError, ValueError, IndexError):
                    qpid = 0
            if qpid:
                guest.poll(qpid, now)
            if labfile:
                lpid = read_pid(labfile)
                if lpid:
                    lab.poll(lpid, now)
            for line in data.split(b"\n"):
                for name, rx in STAGES:
                    if name not in seen and rx.search(line):
                        seen[name] = (now, line.strip()[:160].decode("ascii", "replace"))
        if not final:
            time.sleep(0.5)
    with open(out, "w") as w:
        for name, (t, line) in sorted(seen.items(), key=lambda kv: kv[1][0]):
            w.write("%7.1f %-17s %s\n" % (t, name, line))
        w.write("# host: load average at start %s, at end %s\n" % (load0, "%.2f" % os.getloadavg()[0]))
        w.write("# guest threads waited for a host CPU: %.1f s in total; the worst 0.5 s polling interval %.1f s (at %.0f s)\n" %
                (guest.total / 1e9, guest.worst[0], guest.worst[1]))
        if labfile:
            w.write("# lab VM (cluster) threads waited for a host CPU: %.1f s in total; the worst 0.5 s polling interval %.1f s (at %.0f s)\n" %
                    (lab.total / 1e9, lab.worst[0], lab.worst[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
