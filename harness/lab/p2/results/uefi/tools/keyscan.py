#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Look for one specific cephx key in every file below a directory and print the NAMES of the files that hold it (never the key, never a match).

    keyscan.py KEYFILE DIR

KEYFILE holds the key as ceph prints it (base64 text of the blob: u16 type, 8 bytes created, u16 length, the secret). The forms that are
searched: the base64 text; the whole blob and the secret itself as contiguous hex (either case) and as hex bytes separated by a space, a colon,
a comma or a dash (a hex dump of the handoff table would show the key that way); the secret as "0x"-prefixed bytes. PNG and PPM files (screenshots)
are skipped: a key cannot be read out of them by a text search.

Exit status: 0 nothing found, 1 something found (the names are printed, one per line), 2 the key file is unusable (missing, empty, not base64, a
secret shorter than 8 bytes: such a pattern would match by chance) or DIR is missing. Standard library only; the key is read from a file, never
from an argument, and nothing here writes it anywhere."""
import base64
import binascii
import os
import sys


def patterns(text: str) -> list:
    text = text.strip()
    pats = [text.encode("ascii", "replace")]
    try:
        blob = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return []
    secret = blob[12:] if len(blob) > 12 else b""
    for raw in (blob, secret):
        if len(raw) < 8:
            continue
        h = raw.hex()
        for form in (h, h.upper()):
            pats.append(form.encode())
            for sep in (" ", ":", ",", "-"):
                pats.append(sep.join(form[i:i + 2] for i in range(0, len(form), 2)).encode())
        if raw is secret:
            pats.append(" ".join("0x" + h[i:i + 2] for i in range(0, len(h), 2)).encode())
            pats.append(", ".join("0x" + h[i:i + 2] for i in range(0, len(h), 2)).encode())
    return pats


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    keyfile, root = sys.argv[1], sys.argv[2]
    try:
        with open(keyfile, "r", encoding="ascii", errors="replace") as f:
            text = f.read()
    except OSError as e:
        print("keyscan.py: cannot read the key file: %s" % e.strerror, file=sys.stderr)
        return 2
    if not os.path.isdir(root):
        print("keyscan.py: no directory %s" % root, file=sys.stderr)
        return 2
    pats = patterns(text)
    try:
        blob_len = len(base64.b64decode(text.strip(), validate=True))
    except (binascii.Error, ValueError):
        blob_len = 0
    if not pats or blob_len < 20:
        print("keyscan.py: the key file does not hold a cephx key (base64 blob of at least 20 bytes)", file=sys.stderr)
        return 2
    hits = []
    for dirpath, _dirs, files in os.walk(root):
        for n in sorted(files):
            if n.endswith((".png", ".ppm")):
                continue
            p = os.path.join(dirpath, n)
            try:
                with open(p, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            flat = data.replace(b"\r", b"").replace(b"\n", b"")       # a line that the terminal wrapped
            if any(q in data or q in flat for q in pats):
                hits.append(os.path.relpath(p, root))
    for h in hits:
        print(h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
