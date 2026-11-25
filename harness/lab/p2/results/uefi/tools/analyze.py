#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Judge one row of the UEFI matrix from what it left in its evidence directory.

    analyze.py --profile P --dir ROWDIR [--expect-file F]

Reads ROWDIR/serial.log, result.txt and stamps.txt, writes ROWDIR/facts.txt and prints the verdict on standard output:
the first line is PASS, FAIL or BLOCKED, then one line per check ("PASS|FAIL|INFO <check>: <detail>"). BLOCKED is only for a run that did
not take place (the machine had no room, QEMU did not start, no medium): nothing is said about the driver. Everything else that is not
met is FAIL. The key is never in any input (the run script discards a log with it), and nothing here prints more than
a line of the log.

Profiles
  shell     row U0: the run reached the UEFI shell; "map -r" shows the block device and its partitions; "ls" reads the ESP;
            the device path shows the node of the expected flavour (expect: devpath=vendor|uri|sata)
  boot      rows U1 to U3: the whole boot: every field of the handoff table PASS (no FAIL, no SKIP unless allowed), the marker
            WRBOOT-ROOT-OK with the root on /dev/rbd<N>p<P>, a login prompt
  bytes     the SAN-level byte check: every file's md5 as iPXE printed it equals the list the image was built from AND the file read
            out of "rbd export" (expect: md5sums=FILE oracle=FILE)
  negative  a run that must FAIL the way the design says: WRRUN-SAN-FAILED with the expected errno and the expected console line
            (expect: errno=NAME console=REGEX), and no SAN device
  san       the sanhook worked (WRRUN-SAN-OK) and rbd-info printed its counters
  winpe     rows W1/W2: SAN opened, boot manager started (iPXE lines), WinPE desktop on the screen (screenshot heuristic; WinPE prints nothing on the serial line)
  smoke     iPXE ran the script
  control   the http-control rows (stock iPXE HTTP SAN): the run met its expectation (the initramfs' hook ran) and GRUB had no read error

Expect-file lines (key=value, # comments): devpath devpath_image errno console no_console require forbid md5sums oracle allow_skip
(require, forbid, console, no_console and devpath_image may repeat; require, forbid, console and no_console are regular expressions matched
against single log lines; devpath_image is a "pool/image" the vendor node of the device path must name). A key that is not in this list is
a FAIL (a misspelt key would otherwise be a check that silently never ran), and a negative row without an errno and a console expectation is a FAIL.

Every profile also scans the row's own files (serial.log, stdout.txt, qemu.out, stamps.txt, cmdline.txt, result.txt) for the shape of a cephx
key (legacy aes "AQ..." and aes256k "Ag..."), per line and across wrapped lines, and never prints any part of what it found.
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
KNOWN_EXPECT = {"devpath", "devpath_image", "errno", "console", "no_console", "require", "forbid", "md5sums", "oracle", "allow_skip"}
KEY_RX = re.compile(r"A[Qg][A-Za-z0-9+/]{30,}={0,2}")      # a cephx key blob: u16 type (1 = aes, 2 = aes256k), then 8 + 2 + len bytes, base64
SECRET_FILES = ("serial.log", "stdout.txt", "qemu.out", "stamps.txt", "cmdline.txt", "result.txt")
VEN_GUID = "9041FCE5-0402-4EAE-B3C1-BD75ADF50455"
VEN_RX = re.compile(r"/VenMsg\(" + VEN_GUID + r",([0-9A-Fa-f]*)\)", re.I)
NET_PREFIX_RX = re.compile(r"^PciRoot\(0x[0-9A-Fa-f]+\)/Pci\(0x[0-9A-Fa-f]+,0x[0-9A-Fa-f]+\)/MAC\([0-9A-Fa-f]{12},0x[0-9A-Fa-f]+\)/")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][0-9A-B]|\x1b[=>]")


def clean(text: str) -> list:
    """The serial log as lines, terminal escapes removed, carriage returns folded."""
    text = ANSI.sub("", text)
    out = []
    for line in text.split("\n"):
        line = line.rstrip("\r")
        if "\r" in line:
            line = line.split("\r")[-1] or line
        out.append(line)
    return out


def read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read().decode("ascii", "replace")
    except OSError:
        return ""


def parse_expect(path: str) -> dict:
    exp = {}
    for raw in read(path).splitlines() if path else []:
        raw = raw.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        k, v = raw.split("=", 1)
        exp.setdefault(k.strip(), []).append(v.strip())
    return exp


def resolve(path: str, expect_file: str) -> str:
    """A file named in the expect file: as given when it exists, else next to the expect file (the evidence keeps its own copies)."""
    if os.path.exists(path) or os.path.isabs(path) and not expect_file:
        return path
    alt = os.path.join(os.path.dirname(os.path.abspath(expect_file)), os.path.basename(path)) if expect_file else path
    return alt if os.path.exists(alt) else path


def result_fields(txt: str) -> dict:
    f = {}
    for line in txt.splitlines():
        if line.startswith("RESULT "):
            for tok in line.split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    f[k] = v
        m = re.match(r"exit=(\d+) wall=(\d+)s retries=(\d+)", line)
        if m:
            f["exit"], f["wall"], f["retries"] = m.group(1), m.group(2), m.group(3)
    return f


class Verdict:
    def __init__(self):
        self.lines = []
        self.failed = False
        self.blocked = False

    def ok(self, name, detail=""):
        self.lines.append("PASS %s: %s" % (name, detail))

    def bad(self, name, detail=""):
        self.failed = True
        self.lines.append("FAIL %s: %s" % (name, detail))

    def info(self, name, detail=""):
        self.lines.append("INFO %s: %s" % (name, detail))

    def check(self, cond, name, ok_detail, bad_detail):
        (self.ok if cond else self.bad)(name, ok_detail if cond else bad_detail)

    def text(self):
        head = "BLOCKED" if self.blocked else ("FAIL" if self.failed else "PASS")
        return head + "\n" + "\n".join(self.lines) + "\n"


def find(lines, rx, flags=0):
    r = re.compile(rx, flags)
    return [l for l in lines if r.search(l)]


def decode_vendor(path: str):
    """The vendor-defined messaging node of a device path as the shell prints it: (problem, "pool/image" or None).

    Layout (docs/design/ipxe-driver.md section 6): u8 version = 1, u8 reserved = 0, u8 fsid[16] (zero when unknown), "pool/image[@snap]", NUL.
    The node must follow the network prefix PciRoot/Pci/MAC (iPXE's efi_netdev_path)."""
    m = VEN_RX.search(path)
    if not m:
        return "no vendor node", None
    if not NET_PREFIX_RX.match(path):
        return "the vendor node does not follow PciRoot()/Pci()/MAC()", None
    hx = m.group(1)
    if len(hx) % 2 or len(hx) < 2 * 20:
        return "vendor node data has %d bytes (at least 20 expected)" % (len(hx) // 2), None
    data = bytes.fromhex(hx)
    if data[0] != 1 or data[1] != 0:
        return "vendor node version/reserved are %d/%d (expected 1/0)" % (data[0], data[1]), None
    if data[-1] != 0 or 0 in data[18:-1]:
        return "vendor node name is not one NUL-terminated string", None
    name = data[18:-1]
    if not re.fullmatch(rb"[A-Za-z0-9._-]+/[A-Za-z0-9._@-]+", name):
        return "vendor node name %r is not pool/image" % name[:40], None
    return "", name.decode("ascii")


def secret_scan(d: str) -> list:
    """Names of the row's files that look like they hold a cephx key (never the content)."""
    hits = []
    for n in SECRET_FILES:
        t = ANSI.sub("", read(os.path.join(d, n)))
        if KEY_RX.search(t) or KEY_RX.search(t.replace("\n", "").replace("\r", "")):
            hits.append(n)
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--expect-file", default="")
    a = ap.parse_args()
    d = a.dir
    v = Verdict()
    exp = parse_expect(a.expect_file)
    unknown = sorted(set(exp) - KNOWN_EXPECT)
    log = clean(read(os.path.join(d, "serial.log")))
    res = result_fields(read(os.path.join(d, "result.txt")))
    stamps = read(os.path.join(d, "stamps.txt"))
    facts = []

    # ---- the run itself ----------------------------------------------------------------------------------------------
    stop = res.get("stop", "?")
    if res.get("exit") == "2" or stop in ("qemu-did-not-start", "?") or not res:
        v.blocked = True
        v.info("run", "the run did not take place (exit=%s stop=%s): see stdout.txt" % (res.get("exit"), stop))
        if secret_scan(d):      # even a run that did not take place must not leave a key behind
            v.blocked = False
            v.bad("secret scan", "the shape of a cephx key is in the row's files (content not shown)")
        open(os.path.join(d, "facts.txt"), "w").write("no run\n")
        sys.stdout.write(v.text())
        return 0
    if res.get("exit") == "4":
        v.bad("run", "the run script reported a leftover or a key in the log (exit 4)")
    v.info("run", "stop=%s secs=%s ipxe=%s net=%s san=%s os=%s" %
           (stop, res.get("secs"), res.get("ipxe"), res.get("net"), res.get("san"), res.get("os")))

    # ---- facts ---------------------------------------------------------------------------------------------------------
    banner = find(log, r"^iPXE \d|iPXE initialising|^iPXE\b.*\(g")
    facts.append("ipxe banner: %s" % (banner[0].strip()[:120] if banner else "(none seen)"))
    rbd = find(log, r"^rbd:")
    facts.append("rbd console lines (%d):" % len(rbd))
    facts += ["  " + l.strip()[:200] for l in rbd]
    run = find(log, r"^WRRUN-")
    facts.append("run script lines (%d):" % len(run))
    facts += ["  " + l.strip()[:200] for l in run]
    rf = find(log, r"^RBFT (PASS|FAIL|SKIP|INFO) ")
    npass = len([l for l in rf if l.startswith("RBFT PASS")])
    nfail = len([l for l in rf if l.startswith("RBFT FAIL")])
    nskip = len([l for l in rf if l.startswith("RBFT SKIP")])
    rr = find(log, r"^RBFT-RESULT ")
    facts.append("table check: %d PASS, %d FAIL, %d SKIP; %s" % (npass, nfail, nskip, rr[-1].strip() if rr else "no RBFT-RESULT line"))
    facts += ["  " + l.strip()[:200] for l in rf if not l.startswith("RBFT PASS")]
    wb = find(log, r"^WRBOOT-")
    facts.append("guest markers (%d):" % len(wb))
    facts += ["  " + l.strip()[:200] for l in wb]
    facts.append("stages (seconds since the run script started):")
    facts += ["  " + l for l in stamps.splitlines()]
    # rbd-info block
    info_lines = []
    on = False
    for l in log:
        if l.startswith("WRINFO-BEGIN"):
            on = True
            info_lines.append(l.strip())
            continue
        if l.startswith("WRINFO-END"):
            on = False
            info_lines.append(l.strip())
            continue
        if on:
            info_lines.append(l.strip()[:200])
    facts.append("rbd-info (%d lines):" % len(info_lines))
    facts += ["  " + l for l in info_lines]

    info_txt = "\n".join(info_lines)
    reopens = sum(int(x) for x in re.findall(r"(\d+) reopens", info_txt))
    stall_closes = sum(int(x) for x in re.findall(r"(\d+) stall closes", info_txt))
    osd_failed = sum(int(x) for x in re.findall(r"(\d+) failed; in flight", info_txt))

    def clean_counters():
        """A row that reads through the SAN device must not have needed a reopen or a stall close; a failed OSD operation is shown, not judged
        (a read whose data are right can still have had one: finding F7)."""
        if info_lines:
            v.check(reopens == 0 and stall_closes == 0, "no path closure during the row", "0 reopens, 0 stall closes",
                    "%d reopens, %d stall closes: the cluster stopped answering during the row" % (reopens, stall_closes))
            if osd_failed:
                v.info("osd ops", "%d failed operation(s) in rbd-info although the row went on (finding F7)" % osd_failed)

    prof = a.profile
    for k in unknown:
        v.bad("expect file", "key '%s' is not one of: %s (a misspelt key would be a check that never ran)" % (k, " ".join(sorted(KNOWN_EXPECT))))

    # ---- every profile: generic expectations ------------------------------------------------------------------------
    for rx in exp.get("require", []):
        v.check(bool(find(log, rx)), "require /%s/" % rx, "seen", "not in the log")
    for rx in exp.get("forbid", []):
        hits = find(log, rx)
        v.check(not hits, "forbid /%s/" % rx, "not seen", "seen: %s" % (hits[0].strip()[:120] if hits else ""))
    for rx in exp.get("console", []):
        v.check(bool(find(log, rx)), "console line /%s/" % rx, "seen", "not in the log")
    for rx in exp.get("no_console", []):
        hits = find(log, rx)
        v.check(not hits, "no console line /%s/" % rx, "not seen", "seen: %s" % hits[0].strip()[:120])

    failed_lines = find(log, r"^WRRUN-SAN-FAILED 0x[0-9a-f]+")
    code = None
    if failed_lines:
        code = int(failed_lines[-1].split()[1], 16)

    # ---- profiles --------------------------------------------------------------------------------------------------------
    if prof == "control":
        v.check(res.get("met") == "1", "run met its expectation", "RESULT met=1 (%s)" % stop, "RESULT met=%s stop=%s" % (res.get("met"), stop))
        v.check(bool(find(log, r"^WRRUN-SAN-START sanboot")), "script used sanboot", "yes", "no sanboot")
        v.check(not find(log, r"error: failure reading sector|Failed to boot both default"), "GRUB read everything", "no GRUB read error", "GRUB read error")

    elif prof == "smoke":
        v.check(bool(find(log, r"^WRRUN-END")), "script ran", "WRRUN-END seen", "no WRRUN-END")

    elif prof == "san":
        v.check(bool(find(log, r"^WRRUN-SAN-OK")), "sanhook", "WRRUN-SAN-OK", "no WRRUN-SAN-OK (SAN open failed: %s)" % (failed_lines[-1] if failed_lines else "no failure line"))
        v.check(bool(info_lines), "rbd-info", "%d lines" % len(info_lines), "no rbd-info output")
        clean_counters()

    elif prof == "shell":
        v.check(res.get("met") == "1", "reached the UEFI shell", "RESULT met=1", "RESULT met=%s stop=%s" % (res.get("met"), stop))
        v.check(bool(find(log, r"^WRRUN-SAN-OK")), "sanhook of the image", "WRRUN-SAN-OK", "no WRRUN-SAN-OK")
        v.check(bool(find(log, r"^WRU0-SHELL-START")) and not find(log, r"^WRU0-HELPER-FAILED"), "the shell was started from iPXE",
                "WRU0-SHELL-START", "no WRU0-SHELL-START (%s)" % ("; ".join(l.strip() for l in find(log, r"^WRU0-")) or "no WRU0 line"))
        txt = "\n".join(log)
        fsl = [l for l in log if re.search(r"\bFS\d+:", l) and "Alias" in l]
        blk = [l for l in log if re.search(r"\bBLK\d+:", l) and "Alias" in l]
        v.check(bool(fsl) and bool(blk), "map -r lists the block devices and file systems", "%d FS and %d BLK lines" % (len(fsl), len(blk)),
                "no FSn / BLKn line in the shell output")
        # a map entry is two lines: the names, then the device path on the next line
        paths = []
        for i, l in enumerate(log):
            if re.search(r"\b(FS|BLK)\d+:", l) and "Alias" in l and i + 1 < len(log):
                paths.append(log[i + 1].strip())
        flav = (exp.get("devpath") or ["vendor"])[0]
        rx = {"vendor": r"/VenMsg\(9041FCE5-0402-4EAE-B3C1-BD75ADF50455,", "uri": r"/Uri\(rbd:", "sata": r"/Sata\("}[flav]
        hit = [p for p in paths if re.search(rx, p, re.I)]
        v.check(bool(hit), "device path flavour %s" % flav, "%d map entries carry the node, e.g. %s" % (len(hit), re.sub(r"HD\(.*", "HD(...", hit[0])[:170] if hit else ""),
                "no map entry carries the %s node (device paths seen: %s)" % (flav, " | ".join(p[:90] for p in paths[:3]) or "none"))
        if flav == "vendor":
            bad_nodes, names = [], set()
            for p in paths:
                if VEN_RX.search(p):
                    why, nm = decode_vendor(p)
                    if why:
                        bad_nodes.append("%s: %s" % (re.sub(r"HD\(.*", "HD(...", p)[:60], why))
                    else:
                        names.add(nm)
            v.check(bool(names) and not bad_nodes, "vendor node payload (version 1, fsid, pool/image) and network prefix",
                    "names %s" % ", ".join(sorted(names)), "; ".join(bad_nodes[:2]) or "no vendor node could be decoded")
            for want in exp.get("devpath_image", []):
                v.check(want in names, "vendor node names %s" % want, "yes", "names seen: %s" % (", ".join(sorted(names)) or "none"))
            if not exp.get("devpath_image"):
                v.info("vendor node name", "no devpath_image in the expect file: the decoded name was not compared with an expectation")
        parts = [p for p in paths if "/HD(" in p]
        v.check(len(parts) >= 3, "partitions are published (HD nodes)", "%d partition entries" % len(parts), "%d partition entries (expected 3: the ESP and root of the Linux image, the FAT of the byte-check disk)" % len(parts))
        # every "ls" the shell ran: header ("FS2:\\EFI\\BOOT") -> the lines printed under it, up to the next header or prompt. The firmware numbers the
        # file systems itself (the ESP is FS2 with the vendor node and FS1 with the SATA node), so the ESP is the one whose root holds EFI.
        listings, cur = {}, None
        for l in log:
            m = re.match(r"^Directory of: (FS\d+:\\.*?)\\?\s*$", l)
            if m:
                cur = m.group(1).rstrip("\\")
                listings[cur] = []
            elif re.match(r"^(FS\d+:\\.*>|Shell>)", l):
                cur = None
            elif cur is not None:
                listings[cur].append(l)
        esp_fs = [re.match(r"FS\d+", h).group(0) for h, ls_ in listings.items()
                  if re.fullmatch(r"FS\d+:", h) and any(re.search(r"<DIR>\s+.*\bEFI\s*$", x) for x in ls_)]
        v.check(bool(esp_fs), "ls of a file system root lists EFI (the ESP of the Linux image)", "the ESP is %s" % ", ".join(esp_fs),
                "no listing of a file system root has a <DIR> EFI line (listings: %s)" % (", ".join(sorted(listings)) or "none"))
        for fs in esp_fs[:1]:
            deep = listings.get(fs + ":\\EFI\\BOOT")
            if deep is None:
                v.info("ls EFI\\BOOT", "the run's shell commands did not list EFI\\BOOT on %s (they list it on FS2 only): the ESP's second level was not read in this row" % fs)
            else:
                v.check(any(re.search(r"\bBOOTX64\.EFI\s*$", x) for x in deep), "ls of %s:\\EFI\\BOOT reads a directory two levels down" % fs,
                        "BOOTX64.EFI listed", "no BOOTX64.EFI under %s:\\EFI\\BOOT" % fs)
        clean_counters()
    elif prof == "winpe":
        # WinPE has no serial marker with these images: the stages are told apart by iPXE's lines and by screenshots (shots/probe.txt: corners in the
        # WinPE desktop colour). S1 the SAN opened and the boot manager was started; S4 the WinPE desktop is on the screen.
        v.check(bool(find(log, r"^WRRUN-SAN-START sanboot")), "S1 sanboot started", "yes", "no sanboot")
        v.check(bool(find(log, r"Registered SAN device")) and bool(find(log, r"Booting from SAN device")), "S1 iPXE registered the SAN device and booted from it",
                "Registered / Booting from SAN device lines", "no 'Registered SAN device' and 'Booting from SAN device' lines")
        v.check(not find(log, r"^WRRUN-SAN-FAILED") and not find(log, r"^WRRUN-BOOT-RETURNED"), "S1 the SAN opened and the boot manager was started",
                "no WRRUN-SAN-FAILED, no WRRUN-BOOT-RETURNED", "; ".join(l.strip() for l in find(log, r"^WRRUN-(SAN-FAILED|BOOT-RETURNED)")))
        pr = read(os.path.join(d, "shots", "probe.txt")).splitlines()
        best = max([int(m.group(2)) for m in (re.match(r"(\d+) winpe-blue-corners=(\d+)", l) for l in pr) if m] or [0])
        first = [l.split()[0] for l in pr if re.match(r"\d+ winpe-blue-corners=([234])$", l)]
        counts = [int(m.group(2)) for m in (re.match(r"(\d+) winpe-blue-corners=(\d+)", l) for l in pr) if m]
        v.check(best >= 2, "S4 the WinPE desktop is on the screen (heuristic, see the screenshots)",
                "%d of 4 corners in the WinPE colour from second %s on" % (best, first[0] if first else "?"),
                "no screenshot has the WinPE colour in two corners (%d screenshots)" % len(pr))
        # a colour seen once could be a transient screen of the boot manager: it must be there in the last screenshot and in at least two
        v.check(len(counts) >= 2 and counts[-1] >= 2 and len([c for c in counts if c >= 2]) >= 2, "S4 the colour is stable (last screenshot, at least two screenshots)",
                "last screenshot %d of 4 corners, %d screenshots in the colour" % (counts[-1] if counts else 0, len([c for c in counts if c >= 2])),
                "colour counts per screenshot: %s" % (counts or "none"))
        v.info("serial", "WinPE prints nothing on the serial line with these images (startnet.cmd's COM1 echo does not reach it): the screenshots are the evidence")

    elif prof == "boot":
        v.check(res.get("met") == "1", "run met its expectation", "RESULT met=1 (%s)" % stop, "RESULT met=%s stop=%s" % (res.get("met"), stop))
        v.check(bool(find(log, r"^WRRUN-SAN-START sanboot")), "script used sanboot", "yes", "no WRRUN-SAN-START sanboot")
        v.check(bool(find(log, r"^RBFT-RESULT PASS")), "table: RBFT-RESULT PASS", rr[-1].strip() if rr else "", rr[-1].strip() if rr else "no RBFT-RESULT line")
        v.check(nfail == 0, "table: no FAIL line", "0 FAIL, %d PASS" % npass, "%d FAIL lines" % nfail)
        if "allow_skip" not in exp:
            v.check(nskip == 0, "table: no SKIP line (every field has an expectation)", "0 SKIP", "%d SKIP lines" % nskip)
        names_pass = {re.match(r"RBFT PASS ([^:\s]+)", l).group(1) for l in rf if re.match(r"RBFT PASS ([^:\s]+)", l)}
        names_skip = {re.match(r"RBFT SKIP ([^:\s]+)", l).group(1) for l in rf if re.match(r"RBFT SKIP ([^:\s]+)", l)}
        counted = len(names_pass) + (len(names_skip) if "allow_skip" in exp else 0)
        v.check(counted >= 40, "table: fields checked", "%d distinct fields PASS" % len(names_pass),
                "only %d distinct fields PASS (expected at least 40; %d PASS lines)" % (len(names_pass), npass))
        m = re.search(r"pass=(\d+) fail=(\d+) skip=(\d+)", rr[-1]) if rr else None
        v.check(bool(m) and int(m.group(1)) == npass and int(m.group(2)) == nfail and int(m.group(3)) == nskip, "table: RBFT-RESULT counts agree with the lines",
                "pass=%d fail=%d skip=%d" % (npass, nfail, nskip), "RBFT-RESULT says %s, the lines say pass=%d fail=%d skip=%d" % (m.group(0) if m else "(no counts)", npass, nfail, nskip))
        trouble = find(log, r"^rbd: .*(out of memory|closing the path|open failed)|error: failure reading sector|Failed to boot both default")
        v.check(not trouble, "no driver or GRUB trouble on the way to the login prompt", "none", "seen: %s" % (trouble[0].strip()[:120] if trouble else ""))
        clean_counters()
        ok = find(log, r"^WRBOOT-ROOT-OK")
        v.check(bool(ok), "marker WRBOOT-ROOT-OK", ok[0].strip()[:200] if ok else "", "no WRBOOT-ROOT-OK (%s)" % ("; ".join(l.strip()[:100] for l in find(log, r"^WRBOOT-ROOT-")) or "no WRBOOT-ROOT-* line"))
        if ok:
            v.check(bool(re.search(r"root=/dev/rbd\d+p\d+", ok[0])), "root is on /dev/rbd<N>p<P>", re.search(r"root=\S+", ok[0]).group(0) if re.search(r"root=\S+", ok[0]) else "", "root: %s" % ok[0][:120])
            v.check("table=PASS" in ok[0], "marker says table=PASS", "yes", ok[0][:160])
        v.check(bool(find(log, r"login: ?$")), "login prompt", "seen", "no login prompt")

    elif prof == "bytes":
        sums = {}
        for l in read(resolve(exp["md5sums"][0], a.expect_file)).splitlines() if "md5sums" in exp else []:
            h, _, n = l.partition("  ")
            if h and n:
                sums[n.strip()] = h.strip()
        oracle = {}
        for l in read(resolve(exp["oracle"][0], a.expect_file)).splitlines() if "oracle" in exp else []:
            h, _, n = l.partition("  ")
            if h and n:
                oracle[n.strip()] = h.strip()
        got = {}
        cur = None
        for l in log:
            m = re.match(r"^WRBYTES-FILE (\S+)", l)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r"^([0-9a-f]{32})\s+\S*", l)
            if m and cur and cur not in got:
                got[cur] = m.group(1)
            if l.startswith("WRBYTES-FAIL"):
                v.bad("fetch", l.strip()[:160])
        v.check(bool(sums), "list of the image's files", "%d files" % len(sums), "no md5sums list")
        nok = 0
        for n, h in sums.items():
            g = got.get(n)
            o = oracle.get(n)
            if g is None:
                v.bad("file %s" % n, "iPXE printed no digest")
            elif g == h == o:
                nok += 1
            else:
                v.bad("file %s" % n, "iPXE %s, built %s, rbd export %s" % (g, h, o))
        extra = sorted(set(oracle) - set(sums))
        v.check(not extra, "the disk holds no file that is not in the list", "oracle and list name the same files", "files on the disk but not in the list: %s" % " ".join(extra[:5]))
        clean_counters()
        v.check(nok == len(sums) and sums, "every file: iPXE digest == build list == rbd export", "%d of %d files" % (nok, len(sums)), "%d of %d files match" % (nok, len(sums)))
        v.check(bool(find(log, r"^WRBYTES-DONE")), "script finished", "WRBYTES-DONE", "no WRBYTES-DONE")

    elif prof == "negative":
        v.check(bool(exp.get("errno")) and bool(exp.get("console")), "the row says what it expects", "errno and console line given",
                "a negative row needs both an errno and a console expectation (errno: %s, console: %s)" % (exp.get("errno", "none"), exp.get("console", "none")))
        v.check(code is not None, "the SAN open failed", "WRRUN-SAN-FAILED 0x%08x" % (code or 0), "no WRRUN-SAN-FAILED line (stop=%s)" % stop)
        v.check(not find(log, r"^WRRUN-SAN-OK"), "no SAN device was made", "no WRRUN-SAN-OK", "WRRUN-SAN-OK seen")
        if code is not None:
            top = code >> 24
            name = ERRNO_TOP.get(top, "errno 0x%02x" % top)
            v.info("errno", "0x%08x = %s" % (code, name))
            want = " ".join(exp.get("errno", [])).split()
            if want:
                v.check(name in want, "errno is %s" % "/".join(want), name, "got %s" % name)
        v.check(not find(log, r"^WRRUN-BOOT-RETURNED"), "nothing booted", "yes", "WRRUN-BOOT-RETURNED")

    else:
        v.bad("profile", "unknown profile %s" % prof)

    # ---- every profile: the key is not in anything we keep (the run script already scans; this is the second look; it never prints what it found)
    hits = secret_scan(d)
    if hits:
        v.bad("secret scan", "the shape of a cephx key is in: %s (content not shown; delete the row's files and the user)" % ", ".join(hits))

    open(os.path.join(d, "facts.txt"), "w").write("\n".join(facts) + "\n")
    sys.stdout.write(v.text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
