#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Check the seed image written by the cloud-localds stand-in of up.sh.

usage: selftest_iso.py SEED.ISO USER-DATA META-DATA NETWORK-CONFIG

The image must be an ISO 9660 image with a Joliet tree and the volume label "cidata" (what cloud-init's NoCloud
datasource looks for), holding the three files with exactly the bytes that were given. Standard library only.
"""
import struct
import sys

SECT = 2048


def main(argv):
    iso, ud, md, nc = argv
    d = open(iso, "rb").read()
    assert len(d) % SECT == 0, "image size is not a multiple of a sector"

    def sect(n):
        return d[n * SECT:(n + 1) * SECT]

    pvd, svd, term = sect(16), sect(17), sect(18)
    assert pvd[:7] == b"\x01CD001\x01", "primary volume descriptor"
    assert svd[:7] == b"\x02CD001\x01", "supplementary (Joliet) volume descriptor"
    assert term[:7] == b"\xffCD001\x01", "terminator"
    assert pvd[40:72].rstrip(b" ") == b"cidata", "volume label (primary)"
    assert svd[40:72].decode("utf-16-be").rstrip(" \x00") == "cidata", "volume label (Joliet)"
    assert svd[88:91] == b"%/E", "Joliet escape sequence"
    total = struct.unpack("<I", pvd[80:84])[0]
    assert total * SECT == len(d), "volume size field"

    def entries(vd, joliet):
        rec = vd[156:190]
        ext, size = struct.unpack("<I", rec[2:6])[0], struct.unpack("<I", rec[10:14])[0]
        out, off, block = {}, 0, sect(ext)
        while off < size and block[off] != 0:
            n = block[off]
            r = block[off:off + n]
            ident = r[33:33 + r[32]]
            if ident not in (b"\x00", b"\x01"):
                name = ident.decode("utf-16-be") if joliet else ident.decode("ascii")
                out[name] = (struct.unpack("<I", r[2:6])[0], struct.unpack("<I", r[10:14])[0])
            off += n
        return out

    j = entries(svd, True)
    assert sorted(j) == ["meta-data", "network-config", "user-data"], j
    for name, path in (("user-data", ud), ("meta-data", md), ("network-config", nc)):
        ext, size = j[name]
        want = open(path, "rb").read()
        assert size == len(want) and d[ext * SECT:ext * SECT + size] == want, "content of " + name
    p = entries(pvd, False)
    assert len(p) == 3 and all(k.endswith(";1") for k in p), p
    print("iso ok")


if __name__ == "__main__":
    main(sys.argv[1:])
