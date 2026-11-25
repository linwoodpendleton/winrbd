#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""mkreader.py - make the disk of the BIOS rows' reader (reader.S): a boot sector and its second stage, then data.

  mkreader.py OUT.raw [--size-mib N] [--seed S] [--as AS] [--ld LD]     assemble reader.S next to this file, append the data, write OUT.raw
  mkreader.py --hash FILE [--first 8] [--sectors N]                  print the reader's hash of FILE's sectors (the oracle's side)

The data is a deterministic pseudo-random stream (python's random.Random(seed)), so the disk can be rebuilt byte for byte. The number of sectors the
reader reads is patched into the second stage (offset 512 + 4); the data starts at sector 8 (4 KiB).
"""
import argparse, os, random, struct, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIRST = 8
MUL = 0x9E3779B1
M32 = 0xFFFFFFFF


def hash_prefix(data, h=0):
    """The reader's hash (see reader.S) of data (a multiple of 4 bytes), continuing from h."""
    for (w,) in struct.iter_unpack("<I", data):
        h = (((h << 5) | (h >> 27)) & M32) ^ w
        h = (h * MUL) & M32
    return h


def hash_file(path, first=FIRST, sectors=None, marks=()):
    """Hash of sectors first .. first+sectors-1 of the file; with marks (sorted lba list) also {lba: hash of everything before that lba}."""
    out = {}
    h = 0
    size = os.path.getsize(path) // 512
    if sectors is None:
        sectors = size - first
    end = first + sectors
    marks = sorted(m for m in marks if first <= m <= end)
    pos = first
    with open(path, "rb") as f:
        f.seek(first * 512)
        for m in marks + [end]:
            n = m - pos
            while n > 0:
                k = min(n, 2048)
                h = hash_prefix(f.read(k * 512), h)
                n -= k
            pos = m
            out[m] = h
    return h, out


CHUNKS = (127, 64, 33, 8, 1, 100, 17, 127)
PROG_STEP = 4096


def prog_points(n, first=FIRST):
    """The lbas at which the reader prints a WRRB-PROG line (the next lba to read at that moment) for n data sectors: it sums commands of the sizes in
    CHUNKS and prints once at least PROG_STEP more sectors have been done."""
    pts, lba, left, done, nextp, i = [], first, n, 0, PROG_STEP, 0
    while left:
        c = min(CHUNKS[i & 7], left)
        i += 1
        lba += c
        left -= c
        done += c
        if done >= nextp:
            nextp += PROG_STEP
            pts.append(lba)
    return pts


def build(out, size_mib, seed, as_, ld):
    src = os.path.join(HERE, "reader.S")
    with tempfile.TemporaryDirectory(prefix="mkreader.") as t:
        o = os.path.join(t, "reader.o")
        b = os.path.join(t, "reader.bin")
        subprocess.run([as_, "--32", "-o", o, src], check=True)
        subprocess.run([ld, "-m", "elf_i386", "-Ttext", "0x7c00", "--oformat", "binary", "-o", b, o], check=True)
        code = bytearray(open(b, "rb").read())
    if len(code) != FIRST * 512:
        sys.exit("mkreader: the assembled reader is %d bytes, want %d" % (len(code), FIRST * 512))
    if code[510:512] != b"\x55\xaa" or code[512:516] != b"WRRD":
        sys.exit("mkreader: the assembled reader has no boot signature or no WRRD header")
    total = size_mib * 2048
    n = total - FIRST
    code[516:520] = struct.pack("<I", n)
    rnd = random.Random("winrbd-p2-robust/%s" % seed)
    with open(out, "wb") as f:
        f.write(code)
        left = n * 512
        while left:
            k = min(left, 1 << 20)
            f.write(rnd.randbytes(k))
            left -= k
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?")
    ap.add_argument("--size-mib", type=int, default=128)
    ap.add_argument("--seed", default="reader-1")
    ap.add_argument("--as", dest="as_", default="as")
    ap.add_argument("--ld", default="ld")
    ap.add_argument("--hash", metavar="FILE")
    ap.add_argument("--prefix", metavar="FILE", help="print 'lba hash' for every WRRB-PROG point and the final line, from FILE's data")
    ap.add_argument("--first", type=int, default=FIRST)
    ap.add_argument("--sectors", type=int)
    a = ap.parse_args()
    if a.prefix:
        n = a.sectors or (os.path.getsize(a.prefix) // 512 - a.first)
        pts = prog_points(n, a.first)
        h, marks = hash_file(a.prefix, a.first, n, pts)
        for p in pts:
            print("%d %08x" % (p, marks[p]))
        print("final %d %08x" % (n, h))
        return
    if a.hash:
        h, _ = hash_file(a.hash, a.first, a.sectors)
        print("%08x" % h)
        return
    if not a.out or not 1 <= a.size_mib <= 2048:
        ap.error("OUT.raw and --size-mib 1..2048")
    if os.path.exists(a.out):
        sys.exit("mkreader: %s exists" % a.out)
    n = build(a.out, a.size_mib, a.seed, a.as_, a.ld)
    h, _ = hash_file(a.out, FIRST, n)
    print("mkreader: wrote %s: %d MiB, data sectors %d (from %d), reader hash %08x" % (a.out, a.size_mib, n, FIRST, h))


if __name__ == "__main__":
    main()
