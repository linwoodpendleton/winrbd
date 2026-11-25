#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tailts.py - timestamp the lines of a QEMU serial log while the guest runs, and (optionally) pause the guest at a chosen line.

  tailts.py CONSOLE OUT PID [--qmp SOCK --pause-on REGEX --pause-secs N [--pause-hook COMMAND]]

Writes OUT as  "<seconds since the start of this tool, 3 decimals> <line>"  (carriage returns and terminal escape sequences removed), and
OUT.chunks as one JSON array [seconds, text] per read of the file (a program that draws its screen with cursor movements, as GRUB does, makes
very long "lines" that carry one time stamp: the chunks keep the time at which each piece arrived). The
serial log is a file that QEMU appends to as the guest writes, so a line is stamped within about 20 ms of its appearing. The tool ends when the
process PID has gone (after a last read of the file).

With --pause-on: the first time a line matches REGEX the tool sends QMP "stop" to SOCK, writes "# PAUSE stop" to OUT, waits N seconds
(running COMMAND through the shell once, right after the stop, if --pause-hook is given: for example a restart of a cluster daemon), sends
"cont", and writes "# PAUSE cont". Nothing else is ever sent to QMP. The log may contain console text only; it never sees a key (the run
scripts scan it for the key like every other log of the run).
"""
import json, os, re, socket, subprocess, sys, time

ESC = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]")


def qmp(sock_path, cmd):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(sock_path)
    f = s.makefile("rw")
    f.readline()

    def call(c):
        f.write(json.dumps({"execute": c}) + "\n")
        f.flush()
        while True:
            r = json.loads(f.readline())
            if "return" in r or "error" in r:
                return r

    call("qmp_capabilities")
    r = call(cmd)
    s.close()
    return r


def qmp_retry(sock_path, cmd, tries):
    """qmp(), tried again (once a second) while the socket is not there or the answer is an error; the last answer, or {"error": ...}."""
    last = {"error": "not tried"}
    for i in range(tries):
        try:
            last = qmp(sock_path, cmd)
            if "return" in last:
                return last
        except (OSError, ValueError) as e:
            last = {"error": str(e)}
        time.sleep(1)
    return last


def alive(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().split(") ")[-1][0] != "Z"
    except OSError:
        return True


def main(argv):
    if len(argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    console, out, pid = argv[0], argv[1], int(argv[2])
    opts = {}
    i = 3
    while i < len(argv):
        if argv[i] in ("--qmp", "--pause-on", "--pause-secs", "--pause-hook"):
            opts[argv[i]] = argv[i + 1]
            i += 2
        else:
            sys.stderr.write("tailts.py: unknown option %s\n" % argv[i])
            return 2
    pause_re = re.compile(opts["--pause-on"]) if "--pause-on" in opts else None
    pause_secs = float(opts.get("--pause-secs", "0"))
    paused = False
    t0 = time.monotonic()
    pos = 0
    buf = b""
    with open(out, "w", buffering=1) as o, open(out + ".chunks", "w", buffering=1) as ck:
        o.write("# tailts start epoch=%.3f\n" % time.time())
        last = False
        while True:
            try:
                with open(console, "rb") as f:
                    f.seek(pos)
                    data = f.read()
            except FileNotFoundError:
                data = b""
            if data:
                pos += len(data)
                buf += data.replace(b"\r", b"").replace(b"\x00", b"")
                now = time.monotonic() - t0
                ck.write(json.dumps([round(now, 3), ESC.sub(b"", data.replace(b"\r", b"").replace(b"\x00", b"")).decode("latin-1")]) + "\n")
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    text = ESC.sub(b"", line).decode("latin-1")
                    o.write("%.3f %s\n" % (now, text))
                    if pause_re and not paused and pause_re.search(text):
                        paused = True
                        r = qmp_retry(opts["--qmp"], "stop", 3)
                        if "return" not in r:
                            # not stopped: nothing to resume, and no "PAUSE stop" line (the analysis would take the run for a paused one)
                            o.write("%.3f # PAUSE error stop failed %s\n" % (time.monotonic() - t0, json.dumps(r)))
                            continue
                        o.write("%.3f # PAUSE stop %s\n" % (time.monotonic() - t0, json.dumps(r)))
                        try:
                            if "--pause-hook" in opts:
                                o.write("%.3f # PAUSE hook start\n" % (time.monotonic() - t0))
                                h = subprocess.run(opts["--pause-hook"], shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                                o.write("%.3f # PAUSE hook rc=%d\n" % (time.monotonic() - t0, h.returncode))
                            time.sleep(max(0.0, pause_secs))
                        finally:
                            # a guest that is left stopped is a run that hangs until its timeout: whatever happened above, resume it
                            r = qmp_retry(opts["--qmp"], "cont", 30)
                            o.write("%.3f # PAUSE cont %s\n" % (time.monotonic() - t0, json.dumps(r)))
            if last:
                if buf:
                    o.write("%.3f %s\n" % (time.monotonic() - t0, ESC.sub(b"", buf).decode("latin-1")))
                break
            if not alive(pid):
                last = True
                continue
            time.sleep(0.02)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
