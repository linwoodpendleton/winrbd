#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Take screenshots of a running QEMU guest through its QMP socket, at given seconds, as PNG files (standard library only).

    shot.py SOCKET OUTDIR SECONDS...

SOCKET is the QMP unix socket of the run (P2Q_WORK/s/<pid of the run script>.sock); the program waits for it to appear, takes one screenshot
at each SECONDS after it started (QEMU's screendump writes a PPM, converted here) and stops when the socket goes away. A screenshot is
evidence of what a guest showed when it printed nothing on the serial line (OVMF's menus, the Windows boot screens). Used by p2u.sh with
P2U_SHOTS="20 60 120"."""
import json
import os
import socket
import struct
import sys
import time
import zlib


def qmp(path, cmd, args=None):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(20)
    s.connect(path)
    f = s.makefile("rwb", buffering=0)
    json.loads(f.readline())
    f.write(b'{"execute":"qmp_capabilities"}\n')
    json.loads(f.readline())
    req = {"execute": cmd}
    if args:
        req["arguments"] = args
    f.write(json.dumps(req).encode() + b"\n")
    while True:
        r = json.loads(f.readline())
        if "return" in r or "error" in r:
            s.close()
            return r


def ppm_to_png(ppm, png):
    with open(ppm, "rb") as f:
        data = f.read()
    # P6\nW H\n255\n
    parts = data.split(b"\n", 3)
    w, h = (int(x) for x in parts[1].split())
    pix = parts[3]
    raw = b"".join(b"\x00" + pix[y * w * 3:(y + 1) * w * 3] for y in range(h))

    def chunk(t, d):
        c = struct.pack(">I", len(d)) + t + d
        return c + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    with open(png, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
                chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


WINPE_BLUE = (0x12, 0x73, 0xAA)     # the desktop colour of the WinPE theme (the winpe module's qmp-shot.py uses the same constant)


def probe(ppm):
    """How many of four corner pixels have the WinPE desktop colour (a heuristic: the screenshot is always kept next to it)."""
    with open(ppm, "rb") as f:
        data = f.read()
    parts = data.split(b"\n", 3)
    w, h = (int(x) for x in parts[1].split())
    pix = parts[3]
    hit = 0
    for x, y in ((8, 8), (w - 9, 8), (8, h - 9), (w - 9, h - 9)):
        o = (y * w + x) * 3
        r, g, b = pix[o], pix[o + 1], pix[o + 2]
        if all(abs(c - t) <= 24 for c, t in zip((r, g, b), WINPE_BLUE)):
            hit += 1
    return hit


def main():
    sock, out, times = sys.argv[1], sys.argv[2], [float(x) for x in sys.argv[3:]]
    for _ in range(600):
        if os.path.exists(sock):
            break
        time.sleep(0.5)
    else:
        return 0
    t0 = time.monotonic()
    for t in times:
        while time.monotonic() - t0 < t:
            time.sleep(0.25)
            if not os.path.exists(sock):
                return 0
        ppm = os.path.join(out, "shot-%03d.ppm" % int(t))
        try:
            r = qmp(sock, "screendump", {"filename": ppm})
            if "error" in r:
                continue
            for _ in range(20):
                if os.path.exists(ppm) and os.path.getsize(ppm) > 100:
                    break
                time.sleep(0.25)
            time.sleep(0.3)
            ppm_to_png(ppm, ppm[:-4] + ".png")
            with open(os.path.join(out, "probe.txt"), "a") as pf:
                pf.write("%d winpe-blue-corners=%d\n" % (int(t), probe(ppm)))
            os.unlink(ppm)
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return 0


if __name__ == "__main__":
    sys.exit(main())
