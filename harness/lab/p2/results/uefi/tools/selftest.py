#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline test of the scripts that ran the UEFI rows of the live matrix: verdicts on synthetic logs, each with its negative controls (a run
that must be judged FAIL is judged FAIL), the Shell extractor on a made-up firmware volume, the table maker, the generator of the byte-check
script, and that every script parses. No QEMU, no KVM, no cluster, no network, no key. Standard library only.

    selftest.py          exit 0 when everything holds, 1 otherwise (each failure is named)
"""
import hashlib
import lzma
import shutil
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []
COUNT = 0


def check(cond, name):
    global COUNT
    COUNT += 1
    if not cond:
        FAILS.append(name)
        print("FAIL", name)


def run(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def analyze(profile, serial, result, expect="", stamps=""):
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "serial.log"), "w").write(serial)
        open(os.path.join(d, "result.txt"), "w").write(result)
        open(os.path.join(d, "stamps.txt"), "w").write(stamps)
        args = [sys.executable, "-I", os.path.join(HERE, "analyze.py"), "--profile", profile, "--dir", d]
        if expect:
            ef = os.path.join(d, "expect")
            open(ef, "w").write(expect)
            args += ["--expect-file", ef]
        r = run(args)
        facts = open(os.path.join(d, "facts.txt")).read() if os.path.exists(os.path.join(d, "facts.txt")) else ""
        return r.stdout.splitlines()[0] if r.stdout else "(no output)", r.stdout, facts


def result(met=1, stop="expectation", exit_=0, san="none@-"):
    return ("RESULT row=U1 run=U1-x expect=marker met=%d ipxe=11 net=11 san=%s end=- os=54 stop=%s secs=61 console=/x\n"
            "exit=%d wall=61s retries=0\n" % (met, san, stop, exit_))


# ---- a good boot -------------------------------------------------------------------------------------------------------------
GOOD_BOOT = "WRRUN-BEGIN row=U1\nWRRUN-NET-OK\nWRRUN-SAN-START sanboot\nGNU GRUB  version 2.14\n" + \
    "".join("RBFT PASS field%d: ok\n" % i for i in range(40)) + "RBFT-RESULT PASS pass=40 fail=0 skip=0\n" + \
    "WRBOOT-ROOT-OK fw=uefi root=/dev/rbd0p2 fstype=ext4 mapped=rbd0 table=PASS src=sysfs image=x kernel=6\nwinrbd-guest login: \n"


def boot_cases():
    v, _, _ = analyze("boot", GOOD_BOOT, result())
    check(v == "PASS", "boot: a good boot is PASS (%s)" % v)
    v, _, _ = analyze("boot", GOOD_BOOT.replace("RBFT-RESULT PASS pass=40 fail=0 skip=0\n", ""), result())
    check(v == "FAIL", "boot: no RBFT-RESULT is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("RBFT PASS field3: ok", "RBFT FAIL field3: wrong"), result())
    check(v == "FAIL", "boot: one RBFT FAIL line is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("RBFT PASS field4: ok", "RBFT SKIP field4: no expectation"), result())
    check(v == "FAIL", "boot: a SKIP line is FAIL unless allowed")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("RBFT PASS field4: ok", "RBFT SKIP field4: no expectation").replace("pass=40 fail=0 skip=0", "pass=39 fail=0 skip=1"), result(), expect="allow_skip=1\n")
    check(v == "PASS", "boot: allow_skip lets one SKIP line through (%s)" % v)
    v, _, _ = analyze("boot", GOOD_BOOT.replace("root=/dev/rbd0p2", "root=/dev/vda2"), result())
    check(v == "FAIL", "boot: a root that is not on rbd is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("winrbd-guest login: \n", ""), result())
    check(v == "FAIL", "boot: no login prompt is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT, result(met=0, stop="timeout"))
    check(v == "FAIL", "boot: a run that missed its expectation is FAIL")
    v, _, _ = analyze("boot", "", result(exit_=2, stop="qemu-did-not-start", met=0))
    check(v == "BLOCKED", "a run that did not start is BLOCKED, not FAIL")
    v, out, _ = analyze("boot", GOOD_BOOT + "key = AQ" + "A" * 36 + "==\n", result())
    check(v == "FAIL" and "secret scan" in out, "a key-looking line in the log is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("WRRUN-SAN-START sanboot", "WRRUN-SAN-START sanhook"), result())
    check(v == "FAIL", "boot: a script that did not use sanboot is FAIL")
    # forty PASS lines of one field are not forty fields
    same = "".join("RBFT PASS signature: rBFT\n" for _ in range(40))
    v, _, _ = analyze("boot", GOOD_BOOT.replace("".join("RBFT PASS field%d: ok\n" % i for i in range(40)), same), result())
    check(v == "FAIL", "boot: forty PASS lines of the same field are FAIL (distinct fields are counted)")
    v, _, _ = analyze("boot", GOOD_BOOT.replace("pass=40 fail=0 skip=0", "pass=41 fail=0 skip=0"), result())
    check(v == "FAIL", "boot: an RBFT-RESULT that disagrees with the lines is FAIL")
    for line in ("rbd: the cluster has not answered for 30 seconds, closing the path: operation timed out (WR_E_TIMEOUT)",
                 "rbd: parse URI failed: out of memory", "error: failure reading sector 0x40802 from `hd0'."):
        v, out, _ = analyze("boot", GOOD_BOOT.replace("GNU GRUB  version 2.14\n", "GNU GRUB  version 2.14\n" + line + "\n"), result())
        check(v == "FAIL" and "driver or GRUB trouble" in out, "boot: a passing boot that printed '%s...' is FAIL" % line[:30])
    info = "WRINFO-BEGIN\nrbd:   session: 5 pumps, 0 cancels (most rounds 0), %d reopens, %d stall closes\nWRINFO-END\n"
    v, _, _ = analyze("boot", GOOD_BOOT + info % (0, 0), result())
    check(v == "PASS", "boot: rbd-info with no reopen and no stall close is PASS (%s)" % v)
    v, out, _ = analyze("boot", GOOD_BOOT + info % (1, 0), result())
    check(v == "FAIL" and "path closure" in out, "boot: a reopen in rbd-info is FAIL")
    v, _, _ = analyze("boot", GOOD_BOOT, result(exit_=4))
    check(v == "FAIL", "boot: the run script's exit 4 (a leftover or a key in the log) is FAIL")
    v, out, _ = analyze("boot", GOOD_BOOT, result(), expect="errnoo=EACCES\n")
    check(v == "FAIL" and "expect file" in out, "an unknown key in the expect file is FAIL (a check that never ran)")
    v, _, _ = analyze("boot", GOOD_BOOT, result(), expect="forbid=Kernel panic\n")
    check(v == "PASS", "boot: forbid= that does not match is PASS")
    v, _, _ = analyze("boot", GOOD_BOOT + "Kernel panic - not syncing\n", result(), expect="forbid=Kernel panic\n")
    check(v == "FAIL", "boot: forbid= that matches is FAIL")


def secret_cases():
    legacy = "AQ" + "B" * 38 + "=="          # ceph's legacy aes key blob in base64 begins AQ (type 1)
    modern = "Ag" + "C" * 58 + "="          # aes256k (type 2) begins Ag
    for name, key in (("aes", legacy), ("aes256k", modern)):
        v, out, _ = analyze("boot", GOOD_BOOT + "leaked %s\n" % key, result())
        check(v == "FAIL" and "secret scan" in out and key[:12] not in out, "secret scan: a %s key in the log is FAIL and nothing of it is printed" % name)
    # a key wrapped over two lines by a terminal
    half = len(legacy) // 2
    v, out, _ = analyze("boot", GOOD_BOOT + "leaked %s\n%s\n" % (legacy[:half], legacy[half:]), result())
    check(v == "FAIL" and "secret scan" in out, "secret scan: a key wrapped over two lines is FAIL")
    # in another file of the row
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "serial.log"), "w").write(GOOD_BOOT)
        open(os.path.join(d, "result.txt"), "w").write(result())
        open(os.path.join(d, "stdout.txt"), "w").write("[qemu] oops %s\n" % legacy)
        r = run([sys.executable, "-I", os.path.join(HERE, "analyze.py"), "--profile", "boot", "--dir", d])
        check(r.stdout.startswith("FAIL") and "stdout.txt" in r.stdout and legacy[:12] not in r.stdout, "secret scan: a key in stdout.txt is FAIL, by file name only")
    # a run that did not take place is still scanned
    with tempfile.TemporaryDirectory() as d:
        open(os.path.join(d, "serial.log"), "w").write("x %s\n" % legacy)
        open(os.path.join(d, "result.txt"), "w").write(result(exit_=2, stop="qemu-did-not-start", met=0))
        r = run([sys.executable, "-I", os.path.join(HERE, "analyze.py"), "--profile", "boot", "--dir", d])
        check(r.stdout.startswith("FAIL"), "secret scan: a BLOCKED run with a key in its log is FAIL, not BLOCKED")
    # ordinary text that is long and base64-like must not trip it
    v, _, _ = analyze("boot", GOOD_BOOT + "Agent-" + "x" * 5 + " " + "AQ short\n" + "/usr/lib/x86_64-linux-gnu/" + "a" * 50 + "\n", result())
    check(v == "PASS", "secret scan: long ordinary words are not keys (%s)" % v)


def keyscan_cases():
    import base64
    secret = bytes(range(0x10, 0x20))
    blob = struct.pack("<H", 1) + b"\0" * 8 + struct.pack("<H", 16) + secret
    b64 = base64.b64encode(blob).decode()
    ks = os.path.join(HERE, "keyscan.py")
    with tempfile.TemporaryDirectory() as d:
        kf = os.path.join(d, "key")
        open(kf, "w").write(b64 + "\n")
        rows = os.path.join(d, "rows")
        os.mkdir(rows)
        forms = {
            "b64.txt": "key %s\n" % b64,
            "hexdump.txt": "RBFT DUMP 0040: " + " ".join("%02x" % c for c in secret) + "\n",
            "hexflat.txt": "key=" + secret.hex().upper() + "\n",
            "wrapped.txt": "key %s\n%s\n" % (b64[:20], b64[20:]),
            "oxform.txt": ", ".join("0x%02x" % c for c in secret) + "\n",
        }
        for n, t in forms.items():
            open(os.path.join(rows, n), "w").write(t)
        open(os.path.join(rows, "clean.txt"), "w").write("nothing here, 10 20 30 40 and 0x10\n")
        open(os.path.join(rows, "shot.png"), "wb").write(b64.encode())          # screenshots are skipped
        r = run([sys.executable, "-I", ks, kf, rows])
        got = set(r.stdout.split())
        check(r.returncode == 1 and got == set(forms), "keyscan.py: every form of the key is found, a clean file and a PNG are not (%s)" % sorted(got ^ set(forms)))
        check(b64 not in r.stdout and b64 not in r.stderr and secret.hex() not in r.stdout, "keyscan.py: prints file names only")
        os.mkdir(os.path.join(d, "empty"))
        r = run([sys.executable, "-I", ks, kf, os.path.join(d, "empty")])
        check(r.returncode == 0 and r.stdout == "", "keyscan.py: a directory without the key is exit 0")
        open(os.path.join(d, "short"), "w").write(base64.b64encode(b"abc").decode())
        r = run([sys.executable, "-I", ks, os.path.join(d, "short"), rows])
        check(r.returncode == 2, "keyscan.py: a key file that is not a key blob is exit 2 (a short pattern would match by chance)")
        open(os.path.join(d, "blank"), "w").write("")
        r = run([sys.executable, "-I", ks, os.path.join(d, "blank"), rows])
        check(r.returncode == 2, "keyscan.py: an empty key file is exit 2 (an empty pattern would match everything)")
        r = run([sys.executable, "-I", ks, os.path.join(d, "nokeyfile"), rows])
        check(r.returncode == 2, "keyscan.py: a missing key file is exit 2")


# ---- the shell row -------------------------------------------------------------------------------------------------------
def shell_log(node, with_esp=True, parts=3, esp_fs=2, listing_fs=2):
    """A shell session of row U0. esp_fs: the number of the file system that really is the ESP; listing_fs: which one the script's commands name
    in the header of the root listing that holds EFI (they differ when a log is made up to be wrong)."""
    lines = ["WRRUN-BEGIN row=U0", "WRRUN-SAN-OK", "WRU0-SHELL-START", "Mapping table"]
    for i in range(parts):
        lines.append("      FS%d: Alias(s):HD0b:;BLK%d:" % (i, i * 2))
        lines.append("          PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400771295,0x1)/%s/HD(%d,GPT,4C3D637D-9991-41D5-81C0-A2EB3D770C3)" % (node, i + 1))
    lines.append("     BLK9: Alias(s):")
    lines.append("          PciRoot(0x0)/Pci(0x3,0x0)/MAC(525400771295,0x1)/%s" % node)
    lines.append("Shell> map -r")
    lines.append("FS1:\\> ls")
    lines.append("Directory of: FS1:\\")
    lines.append("11/23/2026  20:00                   1  f-0001")
    lines.append("         1 File(s)           1 bytes")
    lines.append("FS1:\\> fs2:")
    lines.append("FS2:\\> ls")
    lines.append("Directory of: FS%d:\\" % listing_fs)
    if with_esp:
        lines.append("11/23/2026  20:00 <DIR>          4,096  EFI")
    lines.append("         0 File(s)           0 bytes")
    lines.append("FS2:\\> ls EFI\\BOOT")
    lines.append("Directory of: FS%d:\\EFI\\BOOT\\" % listing_fs)
    lines.append("11/23/2026  20:00 <DIR>          4,096  .")
    if with_esp:
        lines.append("11/23/2026  20:00             724,992  BOOTX64.EFI")
    lines.append("FS2:\\> ")
    return "\n".join(lines) + "\n"


def ven(image=b"winrbd/wrtest-p2-lin-uefi", version=1, fsid=b"\0" * 16):
    return "VenMsg(9041FCE5-0402-4EAE-B3C1-BD75ADF50455,%s)" % (bytes([version, 0]) + fsid + image + b"\0").hex().upper()


VEN = ven()
SHELL_R = result().replace("expect=marker", "expect=shell")
def shell_cases():
    v, _, _ = analyze("shell", shell_log(VEN), SHELL_R, expect="devpath=vendor\n")
    check(v == "PASS", "shell: vendor node, three partitions, ESP listed is PASS (%s)" % v)
    v, _, _ = analyze("shell", shell_log("Sata(0x76BF,0xFFFF,0x0)"), SHELL_R, expect="devpath=sata\n")
    check(v == "PASS", "shell: the sata flavour is PASS")
    v, _, _ = analyze("shell", shell_log("Uri(rbd://x@10.0.0.1:3300/p/i)"), SHELL_R, expect="devpath=uri\n")
    check(v == "PASS", "shell: the uri flavour is PASS")
    v, _, _ = analyze("shell", shell_log(VEN), SHELL_R, expect="devpath=uri\n")
    check(v == "FAIL", "shell: the vendor node is FAIL when the uri flavour was asked for")
    v, _, _ = analyze("shell", shell_log(VEN, with_esp=False), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: an ESP listing without EFI is FAIL")
    v, _, _ = analyze("shell", shell_log(VEN, parts=1), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: fewer than three partitions is FAIL")
    v, _, _ = analyze("shell", shell_log(VEN).replace("WRU0-SHELL-START\n", "WRU0-HELPER-FAILED 0x1\n"), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: a shell that was not started from iPXE is FAIL")
    want = "devpath=vendor\ndevpath_image=winrbd/wrtest-p2-lin-uefi\n"
    v, _, _ = analyze("shell", shell_log(VEN), SHELL_R, expect=want)
    check(v == "PASS", "shell: the vendor node names the expected pool/image (%s)" % v)
    v, _, _ = analyze("shell", shell_log(ven(image=b"winrbd/other-image")), SHELL_R, expect=want)
    check(v == "FAIL", "shell: a vendor node that names another image is FAIL")
    v, _, _ = analyze("shell", shell_log(ven(version=2)), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: a vendor node of version 2 is FAIL")
    v, _, _ = analyze("shell", shell_log(ven(fsid=b"\0" * 15)), SHELL_R, expect=want)
    check(v == "FAIL", "shell: a vendor node whose fsid is 15 bytes (name shifted by one) is FAIL when the expected name is given")
    v, _, _ = analyze("shell", shell_log(VEN).replace("PciRoot(0x0)/Pci(0x3,0x0)/", ""), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: a vendor node that does not follow PciRoot/Pci/MAC is FAIL")
    v, out, _ = analyze("shell", shell_log(VEN), SHELL_R, expect="devpath=vendor\n")
    check("no devpath_image" in out, "shell: without devpath_image the decoded name is shown, not compared")
    v, _, _ = analyze("shell", shell_log(VEN, esp_fs=1, listing_fs=1), SHELL_R, expect="devpath=vendor\n")
    check(v == "PASS", "shell: the ESP is found on whichever file system holds EFI (FS1 here)")
    v, out, _ = analyze("shell", shell_log(VEN).replace("Directory of: FS2:\\EFI\\BOOT\\\n", "").replace("BOOTX64.EFI", "x"), SHELL_R, expect="devpath=vendor\n")
    check(v == "PASS" and "did not list EFI" in out, "shell: an EFI\\BOOT that was not listed is said, not failed")
    v, _, _ = analyze("shell", shell_log(VEN).replace("BOOTX64.EFI", "other.bin"), SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: an EFI\\BOOT listing without BOOTX64.EFI is FAIL")
    info = "WRINFO-BEGIN\nrbd:   session: 5 pumps, 0 cancels (most rounds 0), 1 reopens, 0 stall closes\nWRINFO-END\n"
    v, _, _ = analyze("shell", shell_log(VEN) + info, SHELL_R, expect="devpath=vendor\n")
    check(v == "FAIL", "shell: a reopen during the row is FAIL")


# ---- the bytes row -------------------------------------------------------------------------------------------------------
def bytes_cases():
    with tempfile.TemporaryDirectory() as d:
        names = ["f-0001", "f-4096", "z-fill-80m"]
        sums = {n: hashlib.md5(n.encode()).hexdigest() for n in names}
        ms = os.path.join(d, "MD5SUMS")
        oc = os.path.join(d, "oracle")
        open(ms, "w").write("".join("%s  %s\n" % (h, n) for n, h in sums.items()))
        open(oc, "w").write("".join("%s  %s\n" % (h, n) for n, h in sums.items()))
        log = "WRRUN-SAN-OK\n" + "".join("WRBYTES-FILE %s\n%s  wrb\n" % (n, h) for n, h in sums.items()) + "WRBYTES-DONE\n"
        ex = "md5sums=%s\noracle=%s\n" % (ms, oc)
        r = result().replace("expect=marker", "expect=marker")
        v, _, _ = analyze("bytes", log, r, expect=ex)
        check(v == "PASS", "bytes: three equal digests are PASS (%s)" % v)
        bad = log.replace(sums["f-4096"], "0" * 32)
        v, _, _ = analyze("bytes", bad, r, expect=ex)
        check(v == "FAIL", "bytes: one wrong digest is FAIL")
        v, _, _ = analyze("bytes", log.replace("WRBYTES-DONE\n", ""), r, expect=ex)
        check(v == "FAIL", "bytes: a script that did not finish is FAIL")
        open(oc, "w").write("".join("%s  %s\n" % ("1" * 32 if n == "f-0001" else h, n) for n, h in sums.items()))
        v, _, _ = analyze("bytes", log, r, expect=ex)
        check(v == "FAIL", "bytes: a digest that differs from rbd export is FAIL even if iPXE and the build list agree")
        open(oc, "w").write("")
        v, _, _ = analyze("bytes", log, r, expect=ex)
        check(v == "FAIL", "bytes: an empty oracle is FAIL (an empty list must not read as all green)")
        v, _, _ = analyze("bytes", log, r, expect="")
        check(v == "FAIL", "bytes: no list at all is FAIL")
        open(oc, "w").write("".join("%s  %s\n" % (h, n) for n, h in sums.items()) + "%s  stray-file\n" % ("2" * 32))
        v, out, _ = analyze("bytes", log, r, expect=ex)
        check(v == "FAIL" and "stray-file" in out, "bytes: a file on the disk that is not in the list is FAIL")
        open(oc, "w").write("".join("%s  %s\n" % (h, n) for n, h in sums.items()))
        # the files named in the expect file may be given by a path that no longer exists: the copy next to the expect file is used
        gone = "md5sums=/nonexistent/dir/MD5SUMS\noracle=/nonexistent/dir/oracle\n"
        shutil.copy(ms, os.path.join(d, "MD5SUMS.copy"))
        v, _, _ = analyze("bytes", log, r, expect=gone)
        check(v == "FAIL", "bytes: lists that cannot be found at all are FAIL")
        # the generator of the iPXE commands
        g = run(["bash", os.path.join(HERE, "gen-bytes-append.sh"), ms])
        check(g.returncode == 0 and g.stdout.count("md5sum wrb") == 3 and "WRBYTES-DONE" in g.stdout and "file://WRBYTES/f-4096" in g.stdout,
              "gen-bytes-append.sh: one fetch and one digest per file, a final marker")
        open(os.path.join(d, "bad"), "w").write("%s  evil name;rm\n" % ("0" * 32))
        g = run(["bash", os.path.join(HERE, "gen-bytes-append.sh"), os.path.join(d, "bad")])
        check(g.returncode != 0, "gen-bytes-append.sh: a file name with odd characters is refused")


# ---- the negative rows -------------------------------------------------------------------------------------------------
def neg_cases():
    def log(code, line):
        return "WRRUN-SAN-START sanhook\n%s\nCould not open SAN device\nWRRUN-SAN-FAILED 0x%08x\nWRRUN-END\n" % (line, code)
    r = result(met=1).replace("san=none@-", "san=failed@13")
    v, _, _ = analyze("negative", log(0x2D76608E, "rbd: open failed: pool not found in the OSD map (WR_E_POOL_NOT_FOUND)"), r,
                      expect="errno=ENOENT\nconsole=rbd: .*failed\n")
    check(v == "PASS", "negative: ENOENT with its console line is PASS (%s)" % v)
    v, _, _ = analyze("negative", log(0x43766098, "rbd: open failed: server refused (WR_E_M2_BAD_METHOD)"), r, expect="errno=EACCES\n")
    check(v == "FAIL", "negative: EPROTO where EACCES is expected is FAIL")
    v, _, _ = analyze("negative", log(0x28766090, "rbd: open failed: no monitor could be reached"), r, expect="errno=ETIMEDOUT ENETUNREACH\nconsole=no monitor\n")
    check(v == "PASS", "negative: one of two accepted errnos is PASS")
    v, _, _ = analyze("negative", log(0x2D76608E, "nothing"), r, expect="errno=ENOENT\nconsole=rbd: .*failed\n")
    check(v == "FAIL", "negative: the expected console line missing is FAIL")
    v, _, _ = analyze("negative", "WRRUN-SAN-START sanhook\nWRRUN-SAN-OK\n", r.replace("failed", "ok"), expect="errno=ENOENT\n")
    check(v == "FAIL", "negative: a SAN open that worked is FAIL")
    v, _, _ = analyze("negative", log(0x2D76608E, "rbd: open failed: pool not found in the OSD map (WR_E_POOL_NOT_FOUND)"), r)
    check(v == "FAIL", "negative: a negative row without an errno and a console expectation is FAIL")
    v, _, _ = analyze("negative", log(0x2D76608E, "rbd: open failed: pool not found in the OSD map (WR_E_POOL_NOT_FOUND)"), r, expect="errno=ENOENT\n")
    check(v == "FAIL", "negative: an errno without a console expectation is FAIL")
    # the console expectation of the matrix names the status, so the generic out-of-memory line cannot stand in for it
    con = "console=rbd: .*failed: pool not found .*\\(WR_E_POOL_NOT_FOUND\\)\n"
    v, _, _ = analyze("negative", log(0x2D76608E, "rbd: open failed: pool not found in the OSD map (WR_E_POOL_NOT_FOUND)"), r, expect="errno=ENOENT\n" + con)
    check(v == "PASS", "negative: the specific console line is PASS (%s)" % v)
    v, _, _ = analyze("negative", log(0x2D76608E, "rbd: parse URI failed: out of memory"), r, expect="errno=ENOENT\n" + con)
    check(v == "FAIL", "negative: the right errno with the wrong console line is FAIL")


# ---- the WinPE rows, the control rows and the small profiles --------------------------------------------------------------------------
def winpe_dir(serial, probe, d):
    open(os.path.join(d, "serial.log"), "w").write(serial)
    open(os.path.join(d, "result.txt"), "w").write(result(met=0, stop="timeout").replace("expect=marker", "expect=none"))
    os.makedirs(os.path.join(d, "shots"))
    open(os.path.join(d, "shots", "probe.txt"), "w").write(probe)
    r = run([sys.executable, "-I", os.path.join(HERE, "analyze.py"), "--profile", "winpe", "--dir", d])
    return r.stdout.splitlines()[0], r.stdout


def winpe_cases():
    boot = "WRRUN-BEGIN row=W1\nWRRUN-SAN-START sanboot\nRegistered SAN device 0x80\nBooting from SAN device 0x80\n"
    good = "".join("%d winpe-blue-corners=%d\n" % (t, c) for t, c in ((60, 0), (120, 4), (180, 4), (240, 4)))
    for name, serial, probe, want in (
            ("a WinPE colour that stays", boot, good, "PASS"),
            ("no screenshot with the colour", boot, "60 winpe-blue-corners=0\n120 winpe-blue-corners=0\n", "FAIL"),
            ("a colour seen once and gone (a transient screen)", boot, "60 winpe-blue-corners=0\n120 winpe-blue-corners=4\n180 winpe-blue-corners=0\n", "FAIL"),
            ("a colour in one screenshot only, the last one", boot, "60 winpe-blue-corners=0\n120 winpe-blue-corners=4\n", "FAIL"),
            ("no 'Registered SAN device' line", boot.replace("Registered SAN device 0x80\n", ""), good, "FAIL"),
            ("a SAN that failed", boot + "WRRUN-SAN-FAILED 0x2c222087\n", good, "FAIL"),
            ("the boot manager that returned", boot + "WRRUN-BOOT-RETURNED\n", good, "FAIL"),
            ("two corners are enough", boot, "120 winpe-blue-corners=2\n180 winpe-blue-corners=2\n", "PASS")):
        with tempfile.TemporaryDirectory() as d:
            v, _ = winpe_dir(serial, probe, d)
        check(v == want, "winpe: %s is %s (%s)" % (name, want, v))
    # the screenshot probe itself, on a made-up PPM
    import importlib.util
    spec = importlib.util.spec_from_file_location("shot", os.path.join(HERE, "shot.py"))
    shot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shot)
    with tempfile.TemporaryDirectory() as d:
        w, h = 64, 48
        for name, colour, want in (("blue", shot.WINPE_BLUE, 4), ("black", (0, 0, 0), 0), ("near blue", (0x12 + 20, 0x73 - 20, 0xAA + 20), 4), ("too far", (0x12 + 40, 0x73, 0xAA), 0),
                                   ("a brighter blue", (0, 0x78, 0xD7), 0)):
            ppm = os.path.join(d, name + ".ppm")
            open(ppm, "wb").write(b"P6\n%d %d\n255\n" % (w, h) + bytes(colour) * (w * h))
            check(shot.probe(ppm) == want, "shot.py: the probe counts %d corners for a %s screen (%d)" % (want, name, shot.probe(ppm)))
        # only the corners count: a blue middle on a black screen is not the WinPE desktop
        pix = bytearray(b"\0" * (w * h * 3))
        for y in range(10, 38):
            for x in range(10, 54):
                pix[(y * w + x) * 3:(y * w + x) * 3 + 3] = bytes(shot.WINPE_BLUE)
        ppm = os.path.join(d, "mid.ppm")
        open(ppm, "wb").write(b"P6\n%d %d\n255\n" % (w, h) + bytes(pix))
        check(shot.probe(ppm) == 0, "shot.py: a blue window on a black screen counts no corner")
        png = os.path.join(d, "x.png")
        shot.ppm_to_png(ppm, png)
        data = open(png, "rb").read()
        check(data[:8] == b"\x89PNG\r\n\x1a\n" and data[-12:-8] == struct.pack(">I", 0) and data[-8:-4] == b"IEND", "shot.py: the PNG has its signature and its end chunk")


def small_profile_cases():
    v, _, _ = analyze("smoke", "WRRUN-BEGIN\nWRRUN-END\n", result())
    check(v == "PASS", "smoke: a script that ran to its end is PASS")
    v, _, _ = analyze("smoke", "WRRUN-BEGIN\n", result())
    check(v == "FAIL", "smoke: a script that did not reach its end is FAIL")
    v, _, _ = analyze("san", "WRRUN-SAN-OK\nWRINFO-BEGIN\nrbd: image a/b: open, 1 device(s)\nWRINFO-END\n", result())
    check(v == "PASS", "san: sanhook ok with rbd-info is PASS")
    v, _, _ = analyze("san", "WRRUN-SAN-OK\n", result())
    check(v == "FAIL", "san: no rbd-info output is FAIL")
    v, _, _ = analyze("control", "WRRUN-SAN-START sanboot\nGNU GRUB\n", result())
    check(v == "PASS", "control: the expectation met, a GRUB without a read error is PASS")
    v, _, _ = analyze("control", "WRRUN-SAN-START sanboot\nerror: failure reading sector 0x1 from `hd0'.\n", result())
    check(v == "FAIL", "control: a GRUB read error is FAIL")
    v, _, _ = analyze("control", "WRRUN-SAN-START sanboot\n", result(met=0, stop="timeout"))
    check(v == "FAIL", "control: a run that missed its expectation is FAIL")
    v, _, _ = analyze("nonsense", "", result())
    check(v == "FAIL", "an unknown profile is FAIL")


# ---- the Shell extractor on a made-up firmware volume ------------------------------------------------------------------
def section(typ, payload):
    n = 4 + len(payload)
    return struct.pack("<I", n | typ << 24) + payload


def ffs_file(name, ftype, body):
    size = 24 + len(body)
    hdr = name.bytes_le + b"\x00\x00" + bytes([ftype, 0]) + bytes([size & 255, size >> 8 & 255, size >> 16 & 255]) + b"\xf8"
    return hdr + body


def fv(files):
    body = b""
    for f in files:
        body += f + b"\x00" * ((-len(f)) % 8)
    hlen = 72
    total = hlen + len(body)
    hdr = b"\x00" * 16 + uuid.UUID("8C8CE578-8A3D-4F1C-9935-896185C32DD3").bytes_le + struct.pack("<Q", total) + b"_FVH" + struct.pack("<I", 0x4FEFF) + \
        struct.pack("<HHHBB", hlen, 0, 0, 0, 2) + struct.pack("<II", 1, total) + b"\x00" * 8
    hdr = hdr.ljust(hlen, b"\x00")
    return hdr + body


def extractor_cases():
    shell = uuid.UUID("7C04A583-9E3E-4F1C-AD65-E05268D0B4D1")
    pe = b"MZ" + bytes(random.Random(1).randrange(256) for _ in range(300))
    inner = fv([ffs_file(uuid.uuid4(), 0x07, section(0x10, b"MZ-other")), ffs_file(shell, 0x09, section(0x10, pe) + section(0x15, b"U\x00i\x00"))])
    lz = lzma.compress(section(0x17, inner), format=lzma.FORMAT_ALONE)
    guid_sec = section(0x02, uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF").bytes_le + struct.pack("<HH", 24, 1) + lz)
    outer = fv([ffs_file(uuid.uuid4(), 0xF0, b"\xff" * 20), ffs_file(uuid.uuid4(), 0x0B, guid_sec)])
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, "fw.fd"), os.path.join(d, "Shell.efi")
        open(src, "wb").write(b"\xff" * 64 + outer + b"\xff" * 64)
        r = run([sys.executable, "-I", os.path.join(HERE, "extract-shell.py"), src, dst])
        check(r.returncode == 0 and os.path.exists(dst) and open(dst, "rb").read() == pe,
              "extract-shell.py: the Shell is found inside an LZMA section inside a firmware volume, behind a padding file (%s)" % r.stderr.strip()[:80])
        open(src, "wb").write(b"\xff" * 4096)
        r = run([sys.executable, "-I", os.path.join(HERE, "extract-shell.py"), src, os.path.join(d, "none.efi")])
        check(r.returncode != 0 and not os.path.exists(os.path.join(d, "none.efi")), "extract-shell.py: a firmware without a Shell is refused, nothing written")


# ---- the table of the rows ---------------------------------------------------------------------------------------------
def summarize_cases():
    with tempfile.TemporaryDirectory() as d:
        r1 = os.path.join(d, "U1-a")
        os.mkdir(r1)
        open(os.path.join(r1, "verdict.txt"), "w").write("PASS\nPASS table: RBFT-RESULT PASS: x\n")
        open(os.path.join(r1, "result.txt"), "w").write(result())
        open(os.path.join(r1, "stamps.txt"), "w").write("   12.5 grub    GNU\n   20.0 table-check-done RBFT-RESULT\n   54.1 root-ok WRBOOT\n   59.6 login x\n")
        r2 = os.path.join(d, "U1-b")
        os.mkdir(r2)
        open(os.path.join(r2, "verdict.txt"), "w").write("FAIL\nFAIL run met its expectation: RESULT met=0 | stop=timeout\n")
        open(os.path.join(r2, "result.txt"), "w").write(result(met=0, stop="timeout"))
        r = run([sys.executable, "-I", os.path.join(HERE, "summarize.py"), d])
        rows = [l for l in r.stdout.split("| Family")[0].splitlines() if l.startswith("| U1-")]
        fam = r.stdout.split("| Family")[-1]
        check("| U1-a | 1 | 1 | 0 | 0 |" in fam and "| U1-b | 1 | 0 | 1 | 0 |" in fam, "summarize.py: the table of families counts every run, the failed ones too")
        check(len(rows) == 2 and "| PASS |" in rows[0] and "| 59.6 |" in rows[0] and "| FAIL |" in rows[1] and "RESULT met=0 / stop=timeout" in rows[1],
              "summarize.py: one line per row with its verdict, stages and the first FAIL line (a | in a line cannot break the table)")


# ---- stamp.py: the stages of a console log, and the CPU wait of the guest and of the lab VM ---------------------------------------------------------
def stamp_cases():
    import time

    def follow(runs, pid_proc, out, labfile=None):
        """Run stamp.py next to a process that plays the run script, and let the process end (and be reaped, as p2u.sh's wait does)."""
        args = [sys.executable, "-I", os.path.join(HERE, "stamp.py"), runs, str(pid_proc.pid), out] + ([labfile] if labfile else [])
        st = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1.5)
        pid_proc.wait()
        try:
            st.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            st.kill()
            st.communicate()
            return None
        return st.returncode

    with tempfile.TemporaryDirectory() as d:
        sleeper = subprocess.Popen(["sleep", "3"])
        rd = os.path.join(d, "runs", "U1-x-%d" % sleeper.pid)
        os.makedirs(rd)
        open(os.path.join(rd, "console.log"), "w").write("WRRUN-BEGIN row=U1\nWRRUN-NET-OK\nWRRUN-SAN-START sanboot\nGNU GRUB  version 2.14\n"
                                                       "RBFT-RESULT PASS pass=40 fail=0 skip=0\nWRBOOT-ROOT-OK fw=uefi root=/dev/rbd0p2\nwinrbd-guest login: \n")
        open(os.path.join(d, "lab.pid"), "w").write("%d\n" % os.getpid())
        out = os.path.join(d, "stamps.txt")
        rc = follow(os.path.join(d, "runs"), sleeper, out, os.path.join(d, "lab.pid"))
        text = open(out).read() if os.path.exists(out) else ""
        names = [l.split()[1] for l in text.splitlines() if l and not l.startswith("#")]
        check(rc == 0 and names == ["ipxe-script", "net-ok", "san-start", "grub", "table-check-done", "root-ok", "login"],
              "stamp.py: the stages of a console log, in the order they were seen, and it ends with the run script (%s, rc %s)" % (names, rc))
        check("# lab VM (cluster) threads waited" in text and "# guest threads waited" in text and "# host: load average" in text,
              "stamp.py: with a lab pid file it also records the lab VM's CPU wait")
        sleeper2 = subprocess.Popen(["sleep", "2"])
        rd2 = os.path.join(d, "runs", "U1-y-%d" % sleeper2.pid)
        os.makedirs(rd2)
        open(os.path.join(rd2, "console.log"), "w").write("Kernel panic - not syncing\n")
        out2 = os.path.join(d, "stamps2.txt")
        rc = follow(os.path.join(d, "runs"), sleeper2, out2)
        t2 = open(out2).read() if os.path.exists(out2) else ""
        check(rc == 0 and "kernel-panic" in t2 and "lab VM" not in t2, "stamp.py: a kernel panic is a stage; without a lab pid file the lab line is absent")


# ---- p2u.sh: what it refuses before it touches anything --------------------------------------------------------------------------------------------
def p2u_cases():
    env = dict(os.environ, P2_LAB_DIR="/nonexistent/lab", P2Q_WORK="/nonexistent/work", P2U_OUT="/nonexistent/out")
    for name in ("wrtest-p2-x;id", "wrtest-p2-x y", "wrtest-p2-$(id)", "wrtest-p2-", "wrtest-other", "client.admin", "wrtest-p2-" + "a" * 60):
        r = subprocess.run(["bash", os.path.join(HERE, "p2u.sh"), "key", name], capture_output=True, text=True, env=env)
        check(r.returncode == 2 and "only wrtest-p2-" in r.stderr, "p2u.sh key: the name '%s' is refused before any ssh is run" % name[:24])
    r = subprocess.run(["bash", os.path.join(HERE, "p2u.sh"), "row", "bad/name", "uefi-pxe"], capture_output=True, text=True, env=env)
    check(r.returncode == 2 and "bad name" in r.stderr, "p2u.sh row: a row name with a slash is refused")
    r = subprocess.run(["bash", os.path.join(HERE, "p2u.sh"), "row", "ok-name", "nonsense-kind"], capture_output=True, text=True, env=env)
    check(r.returncode == 2 and "bad kind" in r.stderr, "p2u.sh row: an unknown kind is refused")
    # the keyscan hook of p2u.sh: a fake run script that leaks the key must make the row FAIL and the file disappear
    if run(["sh", "-c", "command -v sha256sum"]).returncode:
        print("SKIP the p2u.sh key hook: sha256sum is missing")
        return
    with tempfile.TemporaryDirectory() as d:
        import base64
        blob = struct.pack("<H", 1) + b"\0" * 8 + struct.pack("<H", 16) + bytes(range(1, 17))
        b64 = base64.b64encode(blob).decode()
        os.makedirs(os.path.join(d, "repo/harness/lab/p2/qemu"))
        os.makedirs(os.path.join(d, "work/runs"))
        os.makedirs(os.path.join(d, "work/ipxe"))
        os.makedirs(os.path.join(d, "lab"))
        kf = os.path.join(d, "key.secret")
        open(kf, "w").write(b64)
        con = os.path.join(d, "work", "leaky.console")
        open(con, "w").write("WRRUN-BEGIN row=U1\nkey is %s\n" % b64)
        fake = os.path.join(d, "repo/harness/lab/p2/qemu/run-uefi-pxe.sh")
        open(fake, "w").write("#!/bin/bash\necho \"RESULT row=U1 run=U1-x met=1 ipxe=1 net=1 san=none@- end=- os=1 stop=expectation secs=1 console=%s\"\n" % con)
        env2 = dict(env, P2_LAB_DIR=os.path.join(d, "lab"), P2Q_WORK=os.path.join(d, "work"), P2U_OUT=os.path.join(d, "out"), P2U_REPO=os.path.join(d, "repo"),
                    PATH=os.path.join(d, "bin") + ":" + os.environ["PATH"])
        os.makedirs(os.path.join(d, "bin"))
        open(os.path.join(d, "bin", "qemu-system-x86_64"), "w").write("#!/bin/sh\necho QEMU emulator version 0.0 (fake)\n")
        os.chmod(os.path.join(d, "bin", "qemu-system-x86_64"), 0o755)
        r = subprocess.run(["bash", os.path.join(HERE, "p2u.sh"), "row", "leaky", "uefi-pxe", "--profile", "boot", "--no-retry", "--", "--key-file", kf],
                           capture_output=True, text=True, env=env2)
        row = os.path.join(d, "out", "leaky")
        verdict = open(os.path.join(row, "verdict.txt")).read() if os.path.exists(os.path.join(row, "verdict.txt")) else ""
        check(verdict.startswith("FAIL") and "secret scan" in verdict and not os.path.exists(os.path.join(row, "serial.log")) and b64 not in verdict and b64 not in r.stdout,
              "p2u.sh row: a row whose log holds the run's own key is FAIL and the log is deleted, by name only (%s)" % (r.stderr.strip()[-120:] or verdict[:60]))


# ---- every script parses -------------------------------------------------------------------------------------------------
def parse_cases():
    for f in sorted(os.listdir(HERE)):
        p = os.path.join(HERE, f)
        if f.endswith(".sh"):
            check(run(["bash", "-n", p]).returncode == 0, "%s: bash -n" % f)
        elif f.endswith(".py"):
            try:
                compile(open(p).read(), p, "exec")
                check(True, f)
            except SyntaxError as e:
                check(False, "%s: python syntax: %s" % (f, e))
    # every script carries its licence tag
    for f in sorted(os.listdir(HERE)):
        if f.endswith((".sh", ".py")):
            head = open(os.path.join(HERE, f)).read(300)
            check("SPDX-License-Identifier: MIT" in head, "%s: SPDX tag" % f)


def bytes_image_cases():
    if os.environ.get("P2U_SELFTEST_NO_DISK"):
        print("SKIP the byte-check disk: P2U_SELFTEST_NO_DISK is set")
        return
    need = ["python3", "sfdisk", "mkfs.vfat", "mcopy", "mdir", "md5sum", "sha256sum", "truncate"]
    if any(run(["sh", "-c", "command -v %s" % t]).returncode for t in need):
        print("SKIP the byte-check disk: a tool is missing (%s)" % " ".join(need))
        return
    with tempfile.TemporaryDirectory() as d:
        r = run(["bash", os.path.join(HERE, "build-bytes-image.sh"), d])
        if r.returncode != 0:
            check(False, "build-bytes-image.sh: %s" % (r.stderr.strip()[-120:]))
            return
        sums = open(os.path.join(d, "MD5SUMS")).read().split("\n")
        check(len([s for s in sums if s]) == 17, "build-bytes-image.sh: 17 files in the list")
        # a second build gives the same list (the content is a function of the names)
        with tempfile.TemporaryDirectory() as d2:
            r = run(["bash", os.path.join(HERE, "build-bytes-image.sh"), d2])
            check(r.returncode == 0 and open(os.path.join(d2, "MD5SUMS")).read() == open(os.path.join(d, "MD5SUMS")).read(),
                  "build-bytes-image.sh: rebuilt, the same list (repeatable)")
        # what the disk holds is what the list says
        mdir = run(["mdir", "-b", "-i", os.path.join(d, "bytes.raw") + "@@1M", "::"]).stdout.split()
        check(len(mdir) == 17, "build-bytes-image.sh: the file system holds the 17 files (%d)" % len(mdir))
        r = run(["bash", os.path.join(HERE, "build-bytes-image.sh"), d])
        check(r.returncode != 0, "build-bytes-image.sh: an existing image is never overwritten")


def main():
    for fn in (boot_cases, secret_cases, keyscan_cases, shell_cases, bytes_cases, neg_cases, winpe_cases, small_profile_cases, extractor_cases, summarize_cases,
               stamp_cases, p2u_cases, parse_cases, bytes_image_cases):
        fn()
    print("uefi selftest: %d checks, %d failed" % (COUNT, len(FAILS)))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
