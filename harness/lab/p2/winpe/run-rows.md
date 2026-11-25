<!-- SPDX-License-Identifier: MIT -->
# Rows W1 to W4: boot WinPE over `rbd://`, and what to record

The four WinPE rows of `docs/design/ipxe-driver.md` section 14.3, with the exact command lines, the evidence to collect, and a
results template. They are the QEMU scripts of `harness/lab/p2/qemu` with a WinPE image on the RBD image and `--action sanboot`.

**Status of the rows in this repository: prepared, and each one needs *a WinPE image from the owner*.** WinPE is not
redistributable and this project downloads nothing: you bring the media (README.md). The owner has put WinPE images (an ISO and a UEFI/GPT and a
BIOS/MBR VHD, built with the Windows ADK) on the lab machine, outside the repository; they pass `check-layout.sh`, and they and the images
`import-winpe.sh` builds from that ISO boot to the WinPE shell from a **local** disk (row W0 below, observed 2026-11-23). **Close-out (Phase 2, 2026-11-24): W1 to W4 have
since been run**, on the owner's current images, by the Phase 2 matrix: UEFI over PXE and from a USB stick image, BIOS over PXE and from a USB stick image, two or three runs
each, all reached `WINRBD-WINPE-OK` on the serial port; the evidence is `harness/lab/p2/results/final/` (`MATRIX.md`, `rows/runs-winpe-*`, `rows/rows-W1-*`) and the
summary is in `docs/design/ipxe-driver.md` section 18.3. The results template at the end of this file is the blank form that was given to this module and is kept as it was;
it is not the record. The rest of this file is the module's own text and is as written before those runs.

| Row | Firmware | iPXE binary | Delivered by | Run script | Image | Runs |
|---|---|---|---|---|---|---|
| W0 | OVMF (Secure Boot off) / SeaBIOS | none | the image as a **local** disk (baseline, no iPXE, no cluster) | plain `qemu-system-x86_64` (below) | UEFI image / BIOS image | 1 + 1 |
| W1 | OVMF (Secure Boot off) | `ipxe.efi` | PXE | `run-uefi-pxe.sh` | UEFI image (layout-uefi.md) | 3: `devpath` vendor, uri, sata |
| W2 | OVMF (Secure Boot off) | `ipxe.efi` as `BOOTX64.EFI` | USB stick | `run-uefi-usb.sh` | UEFI image | 3: vendor, uri, sata |
| W3 | SeaBIOS | native-NIC `ipxe.pxe` with the stub (see the qemu README) | PXE | `run-bios-pxe.sh` | BIOS image (layout-bios.md) | 1 |
| W4 | SeaBIOS | `ipxe.lkrn` / `ipxe.usb` | USB stick | `run-bios-usb.sh` | BIOS image | 1 |

The **devpath flavours** (`devpath=vendor|uri|sata`, design section 6) are the three shapes of the EFI device path the driver can put
on the block device. Windows' boot manager is the first consumer that may care which one it gets, which is why every UEFI row is run
with all three. The BIOS build has no EFI device path: it accepts the option and ignores it, so a BIOS row is run once.

**Row W0 is not optional.** A WinPE row that fails means something only if the same image boots from a plain disk in the same QEMU. Run W0 first, with the
image you are about to import; if W0 does not reach the shell, the image is the problem and W1 to W4 would say nothing about the driver.

## Row W0: the baseline, a local disk

```
IMG=$WINPE_WORK/uefi.raw                       # or bios.raw
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd     # UEFI only: a private copy of the (Secure Boot off) variable store
FW=(-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=vars.fd)   # BIOS image: FW=()
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 2048 -display none -serial file:w0.log -nic none -snapshot \
    -qmp unix:w0.sock,server=on,wait=off "${FW[@]}" \
    -drive file="$IMG",format=raw,if=none,id=d0 -device ich9-ahci,id=ahci -device ide-hd,drive=d0,bus=ahci.0,bootindex=1
```

(Run it under `nice -n 19 choom -n 600 --` on the lab machine; `-snapshot` throws the guest's writes away; the paths of the OVMF files are those of Debian and
Ubuntu.) Then
`python3 -I qmp-shot.py w0.sock probe w0.ppm` every 10 seconds until it exits 0 (the screen is the WinPE shell), and `qmp-shot.py w0.sock screendump w0.png`
for the record. A fixed VHD is given as `format=vpc`.

Observed on 2026-11-23 (QEMU 6.2.0, KVM, OVMF 4M build, SeaBIOS 1.15.0-1, the owner's images): the owner's UEFI VHD and BIOS VHD both reach the WinPE shell
(a `cmd.exe` window on a blue desktop) in under 100 seconds; the UEFI image and the BIOS image that `import-winpe.sh build` made from the owner's ISO reach it too
(the BIOS one with the boot code of the owner's image written by a throw-away script, because `ms-sys` is not available there: the point was to test the
layout the script builds, and it found the sector-12 rule of layout-bios.md).

**A finding that decides how a row is judged: the serial marker does not work with these images in this QEMU.** Their `startnet.cmd` runs
`echo WINRBD-WINPE-OK 1>COM1` and the shell shows `The system cannot find the file specified.` The guest has the serial device (ACPI `PNP0501` is in
`HKLM\SYSTEM\CurrentControlSet\Enum\ACPI`) but Windows PE gives it no `COM1` (`HKLM\HARDWARE\DEVICEMAP\SERIALCOMM` is empty; `drvload` of `msports.inf` answers
`0x80070103`). So `--expect os` cannot be met and a run would only end by timeout. **The shell is recognised by the screen** (`probe`, below), and the serial
marker is used only for an image whose W0 run printed it.
(Close-out: the owner's **current** images do print the marker on COM1 in the matrix, so the W1 to W4 rows of `results/final` are judged by it
(`the stage 'marker' was seen`); the finding above is about the earlier images this module was tested with, and it is why the scripts do not depend on a marker.)

## Before a run

1. **The image passes the layout check, and boots in W0**, and is imported as a lab image with its own throwaway user:
   ```
   harness/lab/p2/winpe/check-layout.sh --layout uefi "$WINPE_WORK/uefi.raw"          # or bios; fails loudly
   harness/lab/p2/winpe/import-winpe.sh import --layout uefi --image "$WINPE_WORK/uefi.raw" --name winpe-gpt
   harness/lab/p2/winpe/import-winpe.sh import --layout bios --image "$WINPE_WORK/bios.raw" --name winpe-mbr
   ```
   `import` reads the image back from the cluster and compares sha256, and takes the snapshot `pristine`. **Before every run, roll the
   image back** (a boot manager can write to its disk, and a row must start from the same bytes):
   `harness/lab/p2/cluster/up.sh ssh sudo rbd snap rollback winrbd/wrtest-p2-winpe-gpt@pristine`.
2. **The iPXE binaries** of the current tree, built with `ipxe/tools/build.sh` (qemu README, "What a run needs"; a BIOS build needs a serial
   console or the run scripts see nothing). Record the iPXE build id and the git revision of this tree in the results.
3. **The key file** of the image's user: `users.sh keyfile NAME` prints its path (mode 600). The key is never printed by anything here, and
   the run scripts scan their logs for it.
4. **Budget and place.** A guest is 2 vCPU and `--mem 2048` (the RAM disk takes the size of `boot.wim`, 300 to 500 MB, plus WinPE itself: under
   1 GiB the boot manager stops with a memory error), on the machine of the lab, under the workflow's 24-core / 32 GiB budget; the run scripts
   enforce it.

## The command lines

`-n` prints the QEMU command line and the iPXE script (key hidden) and starts nothing: do that first. Common part:

```
export P2Q_WORK=$HOME/winrbd-p2-qemu
Q=harness/lab/p2/qemu
common() {   # NAME of an imported image (winpe-gpt, winpe-mbr): the options every row shares
    COMMON=(--pool winrbd --image "wrtest-p2-$1" --user "wrtest-p2-$1" --key-file "$(harness/lab/p2/cluster/users.sh keyfile "$1")"
            --action sanboot --expect none --mem 2048 --timeout 600 --stay)
}
```

`--expect none --stay`: the run does not decide by itself (there is no serial marker, above); it keeps the guest until the timeout, or until you stop it with
`qmp-shot.py SOCK quit`, so that the evidence below can be taken. For an image that **does** print a marker in W0, use `--expect os --ok-marker <the line>` instead,
and the run ends by itself with exit status 0.

```
common winpe-gpt                                  # the UEFI image: W1 and W2, three flavours each
for dp in vendor uri sata; do $Q/run-uefi-pxe.sh --row W1-$dp "${COMMON[@]}" --opt devpath=$dp; done      # W1: OVMF, PXE
for dp in vendor uri sata; do $Q/run-uefi-usb.sh --row W2-$dp "${COMMON[@]}" --opt devpath=$dp; done      # W2: OVMF, USB stick
common winpe-mbr                                  # the BIOS image: W3 and W4, one run each
$Q/run-bios-pxe.sh --row W3 "${COMMON[@]}" --delivery stub                                                 # W3: SeaBIOS, PXE
$Q/run-bios-usb.sh --row W4 "${COMMON[@]}"                                                                 # W4: SeaBIOS, USB stick
```

(`--row` is a label of up to 16 characters. The loops are written as a list of commands: **run them one at a time, each in its own shell, with the evidence
script below running beside it, and roll the image back before each.**) The last line of a run on stdout is
`RESULT row=... run=... expect=none met=0 ipxe=<s> net=<s> san=...@<s> end=<s> os=- stop=... secs=... console=<log>`: paste it into the results (with `--expect none`
`met=0` always; the verdict is the evidence).

## The evidence, stage by stage

A WinPE boot has four places where it can stop, and none has a serial line with these images. The stages are told apart by **screenshots** (taken during the run
with the QMP tool below) and by the iPXE console lines.

| Stage | Meaning | Evidence |
|---|---|---|
| S1 firmware reached iPXE and the SAN opened | the driver opened the image (net, session, image open) | `WRRUN-NET-OK`, `WRRUN-SAN-START sanboot` in the console; no `WRRUN-SAN-FAILED` |
| S2 **the boot manager started** | `bootx64.efi` (UEFI) / `bootmgr` (BIOS) ran from the SAN device | a screenshot that shows the Windows boot manager (its menu or its error screen with a status code and a file name), or the Windows logo with a progress bar; **or** `WRRUN-BOOT-RETURNED` with no screen: then iPXE got control back (on EFI the loader returned an error status; record it) |
| S3 **the boot manager read `boot.wim` and handed over** | the RAM disk was loaded through the SAN device, and `winload` started *from the RAM disk* | the screen after S2 moves on to the WinPE start-up (the blue desktop, "Starting Windows", or the WinPE console); a bootmgr error such as `0xc000000f` (file not found) after the logo means S3 failed and names the file |
| S4 **the WinPE shell** | `wpeinit` finished and `startnet.cmd` ran | `qmp-shot.py SOCK probe` exits 0 (the screen has the WinPE desktop colour in two corners and a dark console window), and the screenshot shows the `cmd.exe` window; or the serial marker for an image that prints one |

What a pass proves and does not: **`winload` and everything after it come from the RAM disk** (`boot.wim` is loaded entirely into memory by the
boot manager), so S4 proves that the boot manager read the *whole* of `boot.wim` (hundreds of MB) correctly through the SAN device, and nothing about
the disk after `ExitBootServices` / after the BIOS is left: WinPE has **no `rbd` driver in this phase**, so the RBD disk is not visible in
WinPE and **that is the expected result**, not a failure. Whether Windows can *use* the disk is Phase 3 (`docs/design/ipxe-winpe.md`).

`probe` is a heuristic and says so: it compares two corner pixels with the WinPE theme's desktop colour (`#1273AA`, constant `WINPE_BLUE` in the tool) and one pixel
inside the console window with black. It cannot tell a healthy shell from another screen of the same colours, so the screenshot is always filed with it.

### The rBFT table

Two separate questions, recorded in two columns:

* **in guest memory** (the iPXE side, host-checked): dump the guest's physical memory through QMP and scan it. Take **two dumps**, 8 seconds
  after `WRRUN-SAN-START` (the table was installed when `sanboot` hooked the device; the boot manager has only just started) and when the
  marker appears. On UEFI the table lives in memory the OS may reuse after it has read the tables, so the second dump can come up empty while the
  first does not; that is a finding, not an error.
* **seen by Windows** (the OS side): `not tested` unless the WinPE image carries a program that calls `GetSystemFirmwareTable('ACPI', ...)`
  for the `rBFT` signature. Whether a Windows driver can read an unknown signature this early is exactly what is **unverified**
  (`docs/design/ipxe-winpe.md`); a row records `not tested` rather than guess.

### The tools (extract them, then run them)

```
awk '/^<!-- selftest:rbft-scan -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' run-rows.md > rbft-scan.py
awk '/^<!-- selftest:qmp-tool -->$/ {f = 1; next} f && /^```python/ {g = 1; next} g && /^```/ {exit} g {print}' run-rows.md > qmp-shot.py
awk '/^<!-- selftest:evidence -->$/ {f = 1; next} f && /^```bash/ {g = 1; next} g && /^```/ {exit} g {print}' run-rows.md > evidence.sh      # see "Taking the evidence"
```

The scanner reads a memory dump whose file offset is the guest-physical address (what `pmemsave` writes) and prints every `rBFT` table that
passes the checks of `docs/design/handoff-table.md`: the signature, a length of 152 to 1,024 bytes, revision 1, the checksum, the `WRBT` magic,
version 1 and header length 116. It prints the key as `present (N bytes)` or `absent`, never the bytes.

<!-- selftest:rbft-scan -->
```python
#!/usr/bin/env python3
# rbft-scan.py DUMP...: find rBFT handoff tables in a guest-physical memory dump (file offset = physical address).
# Exit 0 when at least one valid table was found, 1 when none, 2 on a usage or read error. Never prints key bytes.
import os
import struct
import sys

CHUNK = 64 << 20
MAXLEN = 1024
HDR = 36
FIXED = 116


def cstr(t, off):
    if off >= len(t):
        return "?"
    end = t.find(b"\0", off)
    return t[off:end].decode("utf-8", "replace") if end >= 0 else "?"


def parse(t):
    """t starts at a candidate signature; returns a dict for a valid table, else None."""
    if len(t) < HDR + FIXED or t[0:4] != b"rBFT":
        return None
    length = struct.unpack_from("<I", t, 4)[0]
    if length < HDR + FIXED or length > MAXLEN or length > len(t):
        return None
    if t[8] != 1 or sum(t[:length]) & 0xFF != 0:
        return None
    if t[HDR:HDR + 4] != b"WRBT":
        return None
    t = t[:length]                      # the strings below are read inside the table only, never from the memory that follows it
    version, header_len = struct.unpack_from("<HH", t, HDR + 4)
    if version != 1 or header_len != FIXED:
        return None
    flags = struct.unpack_from("<I", t, HDR + 8)[0]
    var = HDR + header_len

    def off(field):
        return struct.unpack_from("<H", t, HDR + field)[0]

    return {
        "length": length, "flags": flags, "mode": t[HDR + 13], "key": (flags & 2) != 0, "key_len": t[HDR + 15],
        "mons": t[HDR + 16], "pool": cstr(t, var + off(98)), "image": cstr(t, var + off(102)),
        "entity": cstr(t, var + off(96)),
    }


def scan(path):
    size = os.path.getsize(path)
    pos = 0
    carry = b""
    with open(path, "rb") as f:
        while pos < size:
            blk = f.read(CHUNK)
            if not blk:
                break
            end = pos + len(blk)
            buf = carry + blk
            base = pos - len(carry)
            last = end >= size
            limit = len(buf) if last else max(0, len(buf) - MAXLEN)
            i = buf.find(b"rBFT")
            while i != -1 and i < limit:
                r = parse(buf[i:i + MAXLEN])
                if r:
                    yield base + i, r
                i = buf.find(b"rBFT", i + 1)
            carry = b"" if last else buf[limit:]
            pos = end


def main(argv):
    if not argv:
        print("usage: rbft-scan.py DUMP...", file=sys.stderr)
        return 2
    status = 1
    for path in argv:
        try:
            found = list(scan(path))
        except OSError as e:
            print("rbft-scan: %s" % e, file=sys.stderr)
            return 2
        for at, r in found:
            print("rBFT at 0x%x length=%d flags=0x%x mode=%d mons=%d key=%s user=%s image=%s/%s" % (
                at, r["length"], r["flags"], r["mode"], r["mons"],
                "present (%d bytes)" % r["key_len"] if r["key"] else "absent", r["entity"], r["pool"], r["image"]))
        if found:
            status = 0
        else:
            print("%s: no valid rBFT table" % path)
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

The QMP tool talks to the control socket the run script creates (`$P2Q_WORK/s/<pid of the run script>.sock`; it exists while the guest runs). It does what the
evidence needs and nothing else:

<!-- selftest:qmp-tool -->
```python
#!/usr/bin/env python3
# qmp-shot.py SOCKET COMMAND [ARGS...]
#   status               print the run state of the guest
#   screendump OUT       the guest's screen: OUT ending in .png is written as PNG, anything else as PPM
#   probe TMP.ppm        take a screendump into TMP.ppm (deleted afterwards) and say whether it looks like the WinPE shell: the desktop
#                        colour of the default WinPE theme in two corners and a dark console window; exit 0 if so, 3 if not
#   pmemsave OUT MIB     guest-physical memory from 0 up to MIB MiB, written by QEMU to OUT (use the guest's --mem)
#   quit                 stop the guest
import json
import os
import socket
import struct
import sys
import zlib


def qmp(path, cmd, args=None):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(600)
    s.connect(path)
    f = s.makefile("rw")
    f.readline()

    def call(c, a=None):
        m = {"execute": c}
        if a is not None:
            m["arguments"] = a
        f.write(json.dumps(m) + "\n")
        f.flush()
        while True:
            line = f.readline()
            if not line:
                return {"return": {}} if c == "quit" else {"error": {"desc": "connection closed"}}
            r = json.loads(line)
            if "return" in r or "error" in r:
                return r

    call("qmp_capabilities")
    return call(cmd, args)


def read_ppm(src):
    d = open(src, "rb").read()
    parts, i = [], 0
    while len(parts) < 4:               # magic, width, height, maxval (comments are not expected from QEMU)
        while i < len(d) and d[i:i + 1].isspace():
            i += 1
        j = i
        while j < len(d) and not d[j:j + 1].isspace():
            j += 1
        parts.append(d[i:j])
        i = j
    i += 1
    if parts[0] != b"P6" or parts[3] != b"255":
        raise ValueError("not an 8-bit P6 PPM")
    w, h = int(parts[1]), int(parts[2])
    if len(d) < i + w * h * 3:
        raise ValueError("truncated PPM")
    return w, h, d, i


def ppm_to_png(src, dst):
    w, h, d, i = read_ppm(src)
    raw = b"".join(b"\0" + d[i + y * w * 3:i + (y + 1) * w * 3] for y in range(h))

    def chunk(t, c):
        return struct.pack(">I", len(c)) + t + c + struct.pack(">I", zlib.crc32(t + c) & 0xFFFFFFFF)

    with open(dst, "wb") as o:
        o.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) +
                chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


WINPE_BLUE = (18, 115, 170)             # the desktop colour of the default WinPE theme (seen in the owner's images); change it for another theme


def probe_ppm(src):
    """(desktop_blue, console_dark): sampled at relative positions, so it does not depend on the resolution."""
    w, h, d, i = read_ppm(src)

    def px(fx, fy):
        o = i + (int(h * fy) * w + int(w * fx)) * 3
        return tuple(d[o:o + 3])

    near = all(abs(a - b) <= 12 for c in (px(0.01, 0.01), px(0.99, 0.99)) for a, b in zip(c, WINPE_BLUE))
    return near, sum(px(0.3, 0.65)) < 90


def main(argv):
    if len(argv) < 2:
        print(__doc__ or "usage: qmp-shot.py SOCKET COMMAND [ARGS...]", file=sys.stderr)
        return 2
    sock, cmd, rest = argv[0], argv[1], argv[2:]
    try:
        if cmd == "status" and not rest:
            r = qmp(sock, "query-status")
        elif cmd == "screendump" and len(rest) == 1:
            png = rest[0].endswith(".png")
            r = qmp(sock, "screendump", {"filename": rest[0] + ".ppm" if png else rest[0]})
            if "error" not in r and png:
                ppm_to_png(rest[0] + ".ppm", rest[0])
                os.unlink(rest[0] + ".ppm")
        elif cmd == "probe" and len(rest) == 1:
            r = qmp(sock, "screendump", {"filename": rest[0]})
            if "error" not in r:
                try:
                    blue, dark = probe_ppm(rest[0])
                finally:
                    os.unlink(rest[0])
                print(json.dumps({"desktop_blue": blue, "console_dark": dark, "winpe_shell": blue and dark}))
                return 0 if blue and dark else 3
        elif cmd == "pmemsave" and len(rest) == 2 and rest[1].isdigit():
            r = qmp(sock, "pmemsave", {"val": 0, "size": int(rest[1]) << 20, "filename": rest[0]})
        elif cmd == "quit" and not rest:
            r = qmp(sock, "quit")
        else:
            print("qmp-shot: bad command line", file=sys.stderr)
            return 2
    except (OSError, ValueError) as e:
        print("qmp-shot: %s" % e, file=sys.stderr)
        return 1
    if "error" in r:
        print("qmp-shot: %s" % json.dumps(r["error"]), file=sys.stderr)
        return 1
    print(json.dumps(r.get("return", {})))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
```

### Taking the evidence of one run

Save this as `evidence.sh` and start it with `bash evidence.sh W1-vendor` in a second shell while the run of that row is going (the first shell is waiting in the run
script); the `qmp-shot.py` and `rbft-scan.py` of the previous section must be in the current directory. Every wait has a deadline and ends when the guest's control
socket is gone, so a run that fails early (iPXE never reaches the SAN, the guest powers off) cannot leave it spinning. The memory dumps of a guest hold whatever the guest
held, the cephx key of the run included (it is in the boot script iPXE read): they are written into a directory of mode 700 and removed on every way out of the script, even when it is
interrupted. `EV_MEM_MB` is the guest's `--mem` (2048 here), `EV_DEADLINE` the seconds to wait for the shell (the run's `--timeout`).

<!-- selftest:evidence -->
```bash
#!/usr/bin/env bash
set -u
row=${1:?usage: evidence.sh ROW   (for example W1-vendor)}
umask 077
run=$(ls -td "$P2Q_WORK"/runs/"$row"-* | head -1)              # the run directory of that row
sock=$(ls -t "$P2Q_WORK"/s/*.sock | head -1)                   # its control socket
out=$WINPE_WORK/evidence/$row; mkdir -p "$out"                 # outside the repository (it holds screens of Windows)
trap 'rm -f "$out/early.bin" "$out/late.bin" "$out/probe.ppm"' EXIT
qs() { python3 -I qmp-shot.py "$sock" "$@"; }
alive() { [ -S "$sock" ] && qs status >/dev/null 2>&1; }       # the guest is still there
deadline=$((SECONDS + ${EV_DEADLINE:-600}))
until grep -a -q 'WRRUN-SAN-START' "$run/console.log"; do
    alive && [ "$SECONDS" -lt "$deadline" ] || { echo "no WRRUN-SAN-START: the run ended or stalled before the SAN opened"; exit 1; }
    sleep 1
done
sleep "${EV_SETTLE:-8}"; qs pmemsave "$out/early.bin" "${EV_MEM_MB:-2048}"; python3 -I rbft-scan.py "$out/early.bin"
n=0; shell=1
while alive && [ "$SECONDS" -lt "$deadline" ]; do
    if qs probe "$out/probe.ppm" >/dev/null 2>&1; then shell=0; break; fi    # exit 0 = the WinPE shell
    n=$((n + 1)); qs screendump "$out/$(printf %03d $n).png" >/dev/null 2>&1 || true; sleep "${EV_POLL:-15}"
done
if alive; then
    qs screendump "$out/final.png" >/dev/null                  # the shell, or the last screen before the deadline
    qs pmemsave "$out/late.bin" "${EV_MEM_MB:-2048}"; python3 -I rbft-scan.py "$out/late.bin"
    qs quit                                                    # ends the run (it was started with --stay)
fi
echo "probe: $([ "$shell" = 0 ] && echo 'WinPE shell recognised' || echo 'no shell by the deadline')"
```

A row that never reaches the shell ends at the deadline with its screenshots (`001.png`, `002.png`, ... and `final.png`); file the last one. The dumps are `EV_MEM_MB` MiB
and written by QEMU into `$out`: put it where there is room. The trap deletes them; keep the scan's output in the results, not the dump. `rbft-scan.py` exits 1 when a dump
holds no table, which is a finding (the early dump) or expected (the late one, on UEFI), not a failure of the script.

## Results template

Copy this per session into a file **outside the repository** (`$WINPE_WORK/results-<date>.md`) or into the module's report; the screenshots and
dumps stay with it. `not run` is the starting value of every cell. `yes` / `no` are facts read from the console, the screenshots or the scan;
anything else is written out in words, with the error text exactly as shown (`0xc000000f`, `File: \EFI\Microsoft\Boot\BCD`, ...).

Session: date ______  iPXE build id ______  repository revision ______  image (name, sha256 first 12) ______  QEMU / OVMF / SeaBIOS versions ______

| Row | devpath | S1 SAN open | S2 boot manager started | S3 `boot.wim` read, `winload` started | S4 WinPE shell | RESULT line | rBFT in memory, early | rBFT in memory, late | rBFT seen by Windows |
|---|---|---|---|---|---|---|---|---|---|
| W0 | UEFI image, local disk | n/a | n/a | n/a | not run | n/a | n/a | n/a | not tested |
| W0 | BIOS image, local disk | n/a | n/a | n/a | not run | n/a | n/a | n/a | not tested |
| W1 | vendor | not run | not run | not run | not run | not run | not run | not run | not tested |
| W1 | uri | not run | not run | not run | not run | not run | not run | not run | not tested |
| W1 | sata | not run | not run | not run | not run | not run | not run | not run | not tested |
| W2 | vendor | not run | not run | not run | not run | not run | not run | not run | not tested |
| W2 | uri | not run | not run | not run | not run | not run | not run | not run | not tested |
| W2 | sata | not run | not run | not run | not run | not run | not run | not run | not tested |
| W3 | n/a (BIOS) | not run | not run | not run | not run | not run | not run | not run | not tested |
| W4 | n/a (BIOS) | not run | not run | not run | not run | not run | not run | not run | not tested |

What to write in the cells:

* **S1**: `yes` (and the seconds from RESULT: `san=ok@<s>` or the `WRRUN-SAN-START` time) or the `WRRUN-SAN-FAILED 0x...` line.
* **S2, S3**: `yes`, `no`, or `unclear`, with the number of the screenshot that shows it and, for a boot manager error screen, its status code and file name.
* **S4**: `yes` with the screenshot's number and the `probe` result (and `os=<s>` from RESULT if the image prints a marker), or `no` with the last screenshot's number.
* **rBFT in memory**: the line the scanner printed (`rBFT at 0x... length=... flags=... mons=... key=absent user=... image=...`) or `none`; compare `flags`,
  `mons`, `user` and `image` with what the run was started with; if the scanner found two tables at different addresses, say so (iPXE keeps its
  own copy while it builds).
* **rBFT seen by Windows**: `not tested`, or `yes` / `no` with the tool and its output.

A row is **passed** when W0 for the same image was `yes`, S4 is `yes` and the early scan found a table whose fields match the run. A row where S2 is `yes` and S3 is `no` is a **finding**
about the device path or the SAN device (put the status code in the notes), not a harness failure. If the three flavours of W1 differ, that difference is
the answer to design question Q1 (`devpath` default).

Notes (one line per surprise): ______
