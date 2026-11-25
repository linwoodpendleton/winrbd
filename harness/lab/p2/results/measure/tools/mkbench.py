#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""mkbench.py - make the disk of the exit measurements' bench program (bench.S) and the plan that goes with it.

  mkbench.py build OUT.raw --plan read|write|idle|probe [--data-mib 256] [--scratch-mib 64] [--seed S] [--gaps 5,40,120,960] [--write-mib 8] [--json PLAN.json] [--as AS] [--ld LD]
        assemble bench.S next to this file, patch the plan into it, append the data (a deterministic pseudo-random stream) and a zeroed scratch area, write
        OUT.raw, and write PLAN.json: the records, the layout, the expected sums of every read step and the digest of every copy's source range
  mkbench.py verify PLAN.json EXPORT|- [--strict]
        EXPORT (or standard input) is "rbd export" of the image after a copy run: every destination range must have the digest of its source range.
        --strict reads the whole export and also requires that nothing else changed: the boot sector and the program (when the plan has code_sha256), the
        data area (regenerated from the plan's seed) and every byte of the scratch area outside the destination ranges (zero). A write that landed in the wrong
        place, or too far, is found by that and not by the destination digests
  mkbench.py show PLAN.json
        the plan, one record per line

The disk (512-byte sectors): sector 0 is stage 1, sectors 1 to 15 are stage 2 (header, up to 64 records, code), data from sector 16 (DATA_FIRST) for
data-mib MiB, then the scratch area (starting at a multiple of 8,192 sectors, so a copy's destination starts on an object boundary of a 4 MiB object
image) of scratch-mib MiB. The bench reads the data area and writes only the scratch area, and only in the "write" plan.

A record is 32 bytes, little endian:  +0 type letter (Z R C L), +4 cmd (sectors per command), +8 total (R, C: sectors; L: number of reads), +12 lba (R, C:
source; L: first read), +16 dst (C: destination lba; L: stride in sectors), +20 gap (L: seconds to wait first), +24 id (printed on the lines).

The expected sums: bench.S sums, as little-endian dwords, the first ("sumA") and the last ("sumB") min(bytes of the LAST command, 64 KiB) of the buffer after
a read step. The last command of a step with total T and command size C reads T mod C sectors (or C when that is 0) at lba + T - that.
"""
import argparse, hashlib, json, os, random, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_FIRST = 16
HDR_OFF = 512
REC_OFF = 512 + 0x20
MAX_REC = 64
M32 = 0xFFFFFFFF


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(2)


def records(plan, data_first=DATA_FIRST, scratch_lba=0, args=None):
    """The plan as a list of dicts (type, id, cmd, total, lba, dst, gap)."""
    a = args
    df = data_first
    r = []

    def add(t, i, cmd=0, total=0, lba=0, dst=0, gap=0, note=""):
        r.append(dict(type=t, id=i, cmd=cmd, total=total, lba=lba, dst=dst, gap=gap, note=note))

    sec = lambda mib: mib * 2048
    if plan == "probe":                      # a short plan to see that the program and the analysis work
        add("Z", 1, note="calibration")
        add("R", 2, 127, 2032, df, note="64K style, 1 MiB")
        add("R", 3, 2048, 4096, df, note="1 MiB commands, 2 MiB")
        add("L", 4, 127, 4, df + 8192, 8192, 0, "latency series")
    elif plan == "read":
        n = sec(a.read_mib)
        add("Z", 1, note="calibration before")
        add("R", 2, 2048, n, df, note="warm pass (1 MiB commands), not a result")
        add("L", 3, 127, 8, df + 4096, 49152, 0, "single 127-sector reads far apart: the latency of one command, no readahead window")
        i = 4
        for rep in (1, 2):
            for cmd in (127, 2048, 8192):
                add("R", i, cmd, n, df, note="sequential read, %d sectors per command, pass %d" % (cmd, rep))
                i += 1
        add("L", i, 127, 8, df + 4096, 49152, 0, "single reads again")
        add("Z", i + 1, note="calibration after")
    elif plan == "write":
        n = sec(a.write_mib)
        add("Z", 1, note="calibration before")
        add("C", 2, 127, n, df, scratch_lba, note="copy with 127-sector commands")
        add("C", 3, 2048, n, df, scratch_lba + n, note="copy with 1 MiB commands")
        add("C", 4, 8192, n, df, scratch_lba + 2 * n, note="copy with 4 MiB commands")
        add("Z", 5, note="calibration after")
    elif plan == "idle":
        gaps = [int(x) for x in a.gaps.split(",") if x != ""]
        add("Z", 1, note="calibration before")
        add("R", 2, 2048, sec(64), df, note="warm pass: 64 MiB, so that every OSD has been talked to")
        add("L", 3, 127, 8, df + 4096, 49152, 0, "control: reads far apart, no gap")
        i = 4
        for g in gaps:
            add("L", i, 127, 6, df + 4096, 49152, g, "after %d s of idle" % g)
            i += 1
        add("L", i, 127, 8, df + 4096, 49152, 0, "control again, no gap")
        add("Z", i + 1, note="calibration after")
    else:
        die("mkbench: unknown plan %r" % plan)
    if len(r) > MAX_REC:
        die("mkbench: %d records, at most %d" % (len(r), MAX_REC))
    return r


def pack(rec):
    return struct.pack("<B3xIIIIII4x", ord(rec["type"]), rec["cmd"], rec["total"], rec["lba"], rec["dst"], rec["gap"], rec["id"])


def dsum(buf):
    n = len(buf) // 4
    return sum(struct.unpack("<%dI" % n, buf[:n * 4])) & M32


def last_cmd(rec):
    c = rec["cmd"]
    t = rec["total"]
    k = t % c or c
    return k, rec["lba"] + t - k


def build(a):
    rnd = random.Random("winrbd-p2-measure/%s" % a.seed)
    data_sectors = a.data_mib * 2048
    scratch_lba = ((DATA_FIRST + data_sectors + 8191) // 8192) * 8192
    scratch_sectors = a.scratch_mib * 2048
    if a.plan == "write":
        a.write_mib = min(a.write_mib, a.scratch_mib // 3)
    recs = records(a.plan, DATA_FIRST, scratch_lba, a)
    src = os.path.join(HERE, "bench.S")
    with tempfile.TemporaryDirectory(prefix="mkbench.") as t:
        o = os.path.join(t, "bench.o")
        b = os.path.join(t, "bench.bin")
        subprocess.run([a.as_, "--32", "-o", o, src], check=True)
        subprocess.run([a.ld, "-m", "elf_i386", "-Ttext", "0x7c00", "--oformat", "binary", "-o", b, o], check=True)
        code = bytearray(open(b, "rb").read())
    if len(code) != DATA_FIRST * 512:
        die("mkbench: the assembled bench is %d bytes, want %d" % (len(code), DATA_FIRST * 512))
    if code[510:512] != b"\x55\xaa" or code[HDR_OFF:HDR_OFF + 4] != b"WRMB":
        die("mkbench: the assembled bench has no boot signature or no WRMB header")
    code[HDR_OFF + 4:HDR_OFF + 8] = struct.pack("<I", len(recs))
    for i, rec in enumerate(recs):
        code[REC_OFF + 32 * i:REC_OFF + 32 * (i + 1)] = pack(rec)
    total_sectors = scratch_lba + scratch_sectors
    h = hashlib.sha256()
    with open(a.out, "wb") as f:
        f.write(code)
        h.update(code)
        left = data_sectors * 512
        while left:
            k = min(left, 1 << 20)
            chunk = rnd.randbytes(k)
            f.write(chunk)
            h.update(chunk)
            left -= k
        gap = (scratch_lba - DATA_FIRST - data_sectors) * 512 + scratch_sectors * 512
        while gap:
            k = min(gap, 1 << 20)
            f.write(b"\0" * k)
            h.update(b"\0" * k)
            gap -= k
    # the expected sums and digests, from the file just written
    expected = {}
    verify = []
    with open(a.out, "rb") as f:
        for rec in recs:
            if rec["type"] in "RC":
                k, lba = last_cmd(rec)
                nbytes = k * 512
                m = min(nbytes, 65536)
                f.seek(lba * 512)
                head = f.read(m)
                f.seek(lba * 512 + nbytes - m)
                tail = f.read(m)
                expected[str(rec["id"])] = dict(sumA="%08x" % dsum(head), sumB="%08x" % dsum(tail), lastcnt=k)
            if rec["type"] == "C":
                d = hashlib.sha256()
                f.seek(rec["lba"] * 512)
                left = rec["total"] * 512
                while left:
                    chunk = f.read(min(left, 1 << 20))
                    d.update(chunk)
                    left -= len(chunk)
                verify.append(dict(id=rec["id"], dst=rec["dst"], src=rec["lba"], sectors=rec["total"], sha256=d.hexdigest()))
    plan = dict(plan=a.plan, seed=a.seed, code_sha256=hashlib.sha256(bytes(code)).hexdigest(), data_first=DATA_FIRST, data_sectors=data_sectors, scratch_lba=scratch_lba, scratch_sectors=scratch_sectors,
                image_sectors=total_sectors, image_sha256=h.hexdigest(), records=recs, expected=expected, verify=verify)
    if a.json:
        with open(a.json, "w") as f:
            json.dump(plan, f, indent=1)
            f.write("\n")
    print("mkbench: %s: %d records, %d MiB data, scratch at sector %d, image sha256 %s" % (a.out, len(recs), a.data_mib, scratch_lba, h.hexdigest()))


def verify_strict(plan, data):
    """Everything outside the copies' destination ranges is as the plan built it. Returns a list of problems (empty: nothing else changed)."""
    problems = []
    want = plan["image_sectors"] * 512
    if len(data) != want:
        return ["the export is %d bytes, the image is %d" % (len(data), want)]
    if plan.get("code_sha256") and hashlib.sha256(bytes(data[:DATA_FIRST * 512])).hexdigest() != plan["code_sha256"]:
        problems.append("sectors 0 to %d (the boot sector and the program) changed" % (DATA_FIRST - 1))
    rnd = random.Random("winrbd-p2-measure/%s" % plan["seed"])
    pos = DATA_FIRST * 512
    left = plan["data_sectors"] * 512
    while left:
        k = min(left, 1 << 20)
        if bytes(data[pos:pos + k]) != rnd.randbytes(k):
            problems.append("the data area changed in the 1 MiB at byte %d (sector %d)" % (pos, pos // 512))
            break
        pos += k
        left -= k
    # the rest: zero, except the destination ranges (their content is the other check)
    rest = pos if not problems else DATA_FIRST * 512 + plan["data_sectors"] * 512
    spans = sorted((v["dst"] * 512, (v["dst"] + v["sectors"]) * 512) for v in plan["verify"])
    cur = rest
    for a, b in spans + [(want, want)]:
        if a > cur and data.count(0, cur, a) != a - cur:
            problems.append("a non-zero byte between byte %d and %d (sectors %d to %d) outside every destination range" % (cur, a, cur // 512, a // 512 - 1))
        cur = max(cur, b)
    return problems


def verify(plan_path, export, strict=False):
    plan = json.load(open(plan_path))
    f = sys.stdin.buffer if export == "-" else open(export, "rb")
    need = max([v["dst"] + v["sectors"] for v in plan["verify"]] or [0]) * 512
    if strict:
        need = plan["image_sectors"] * 512
    data = bytearray()
    while len(data) < need:
        chunk = f.read(min(need - len(data), 1 << 24))
        if not chunk:
            break
        data += chunk
    bad = 0
    for v in plan["verify"]:
        part = bytes(data[v["dst"] * 512:(v["dst"] + v["sectors"]) * 512])
        ok = len(part) == v["sectors"] * 512 and hashlib.sha256(part).hexdigest() == v["sha256"]
        print("VERIFY id=%d dst=%d sectors=%d %s" % (v["id"], v["dst"], v["sectors"], "OK" if ok else "MISMATCH"))
        bad += 0 if ok else 1
    if strict:
        problems = verify_strict(plan, data)
        for pr in problems:
            print("VERIFY-STRICT %s" % pr)
        if not problems:
            print("VERIFY-STRICT nothing outside the destination ranges changed (%d bytes checked)" % len(data))
        bad += len(problems)
    ok = bad == 0 and bool(plan["verify"] or strict)
    print("VERIFY-RESULT %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def show(plan_path):
    plan = json.load(open(plan_path))
    for r in plan["records"]:
        print("%2d %s cmd=%5d total=%7d lba=%8d dst=%8d gap=%4d  %s" % (r["id"], r["type"], r["cmd"], r["total"], r["lba"], r["dst"], r["gap"], r.get("note", "")))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("out")
    b.add_argument("--plan", required=True)
    b.add_argument("--data-mib", type=int, default=256)
    b.add_argument("--scratch-mib", type=int, default=64)
    b.add_argument("--read-mib", type=int, default=128)
    b.add_argument("--write-mib", type=int, default=8)
    b.add_argument("--gaps", default="5,40,120,960")
    b.add_argument("--seed", default="bench-1")
    b.add_argument("--json")
    b.add_argument("--as", dest="as_", default="as")
    b.add_argument("--ld", default="ld")
    v = sub.add_parser("verify")
    v.add_argument("plan")
    v.add_argument("export")
    v.add_argument("--strict", action="store_true")
    s = sub.add_parser("show")
    s.add_argument("plan")
    a = ap.parse_args()
    if a.cmd == "build":
        if not 8 <= a.data_mib <= 1024 or not 3 <= a.scratch_mib <= 512:
            die("mkbench: --data-mib 8..1024, --scratch-mib 3..512")
        build(a)
    elif a.cmd == "verify":
        sys.exit(verify(a.plan, a.export, a.strict))
    else:
        show(a.plan)


if __name__ == "__main__":
    main()
