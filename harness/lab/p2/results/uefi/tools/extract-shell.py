#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Take the UEFI Shell application out of an OVMF firmware image (standard library only).

    extract-shell.py OVMF_CODE.fd OUT/Shell.efi

Why: row U0 needs the firmware's shell to look at the block device iPXE publishes, and iPXE can only keep that device alive while it is
itself running (when an EFI application returns, iPXE unloads and takes its SAN devices with it). So the run script chains the shell FROM
iPXE (chain tftp://.../Shell.efi), and the shell is the very one OVMF has built in, taken from the firmware image on the machine that
runs the guests. The file is never committed or published (it is a build product of the firmware's package).

OVMF's flash image holds firmware volumes (FV) of firmware file system (FFS) files made of sections; the big volume is LZMA-compressed
inside a GUID-defined section. This walks all of it and writes the PE32 section of the FFS file whose name is the Shell's (7C04A583-9E3E-4F1C-
AD65-E05268D0B4D1)."""
import lzma
import struct
import sys
import uuid

SHELL = uuid.UUID("7C04A583-9E3E-4F1C-AD65-E05268D0B4D1")
LZMA_GUID = uuid.UUID("EE4E5898-3914-4259-9D6E-DC7BD79403CF")
found = []


def sections(buf, ctx):
    """Yield (type, payload) of every section in buf, descending into compressed and GUID-defined ones."""
    off = 0
    while off + 4 <= len(buf):
        size = buf[off] | buf[off + 1] << 8 | buf[off + 2] << 16
        typ = buf[off + 3]
        hdr = 4
        if size == 0xFFFFFF:
            size = struct.unpack_from("<I", buf, off + 4)[0]
            hdr = 8
        if size < hdr or off + size > len(buf):
            break
        body = buf[off + hdr:off + size]
        if typ == 0x02:      # GUID defined
            g = uuid.UUID(bytes_le=bytes(body[:16]))
            data_off = struct.unpack_from("<H", body, 16)[0]
            data = body[data_off - hdr:]
            if g == LZMA_GUID:
                try:
                    out = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(bytes(data))
                except lzma.LZMAError:
                    out = b""
                yield from sections(out, ctx)
            else:
                yield from sections(bytes(data), ctx)
        elif typ == 0x01:    # compression
            ctype = body[4]
            if ctype == 0:
                yield from sections(bytes(body[5:]), ctx)
        elif typ == 0x17:    # firmware volume image
            walk_fv(bytes(body), ctx)
        else:
            yield typ, bytes(body)
        off += (size + 3) & ~3


def walk_fv(buf, ctx):
    """Walk the FFS files of every firmware volume found in buf."""
    pos = 0
    while True:
        i = buf.find(b"_FVH", pos)
        if i < 0:
            return
        pos = i + 4
        start = i - 40
        if start < 0:
            continue
        fvlen = struct.unpack_from("<Q", buf, start + 32)[0]
        hlen = struct.unpack_from("<H", buf, start + 48)[0]
        if fvlen == 0 or hlen < 56 or start + fvlen > len(buf):
            continue
        f = start + hlen
        end = start + fvlen
        f = (f + 7) & ~7
        while f + 24 <= end:
            name = uuid.UUID(bytes_le=bytes(buf[f:f + 16]))
            ftype = buf[f + 18]
            attrs = buf[f + 19]
            size = buf[f + 20] | buf[f + 21] << 8 | buf[f + 22] << 16
            hdr = 24
            if attrs & 0x01:
                size = struct.unpack_from("<Q", buf, f + 24)[0]
                hdr = 32
            if ftype == 0xFF or size < hdr or f + size > end:   # 0xFF: erased flash, the end of the files
                break
            body = buf[f + hdr:f + size]
            if ftype != 0xF0:
                for typ, payload in sections(bytes(body), ctx):
                    if name == SHELL and typ == 0x10:
                        found.append(payload)
            f = (f + size + 7) & ~7


def main():
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as fh:
        data = fh.read()
    walk_fv(data, None)
    if not found:
        print("extract-shell.py: no UEFI Shell in %s" % sys.argv[1], file=sys.stderr)
        return 1
    best = max(found, key=len)
    if best[:2] != b"MZ":
        print("extract-shell.py: the Shell section is not a PE file", file=sys.stderr)
        return 1
    with open(sys.argv[2], "wb") as fh:
        fh.write(best)
    print("extract-shell.py: wrote %s (%d bytes, from %d candidate(s))" % (sys.argv[2], len(best), len(found)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
