#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# expected-table.sh - the expected values of a test configuration, as the guest's rbft-check wants them, and a hand-built
# rBFT table for the same configuration.
#
#   expected-table.sh params [OPTIONS]            one line: the expectations as kernel command-line words (rbft.pool=winrbd ...)
#   expected-table.sh fwcfg  [OPTIONS]            the same, one word per line (a file for QEMU:  -fw_cfg name=opt/winrbd/params,file=FILE)
#   expected-table.sh table  [OPTIONS] -o FILE    the whole ACPI table (OEM fields zero, checksum right unless a defect says otherwise)
#   expected-table.sh body   [OPTIONS] -o FILE    the body only (QEMU:  -acpitable sig=rBFT,rev=1,data=FILE  builds the header and the checksum)
#
# The expectations are taken from the options; the table is built from the same options, so a table built without --set / --defect
# must pass every check and a table built with one deliberate difference must fail exactly the line of that field. That is how the
# initramfs hook is exercised without a cluster (see README.md, "Tests").
#
# OPTIONS (defaults are the dedicated lab of harness/lab/p2/cluster)
#   --mons LIST        monitors, ip:port or [v6]:port, comma separated    (10.77.0.10:3300)
#   --entity ID        cephx user id, no "client."; "-" = none, auth none (winrbd-aes)
#   --pool NAME        (winrbd)       --image NAME (wrtest-p2-lin-uefi)     --image-id ID|-     --snap NAME|-
#   --mode M           crc | crc-first | secure-first | secure              (crc)
#   --keytype T        none | aes | aes256k: the key travels in the table   (none)
#   --key-b64-file F   the armoured key (as "ceph auth get-key" prints it); required with --keytype aes / aes256k. Never printed.
#   --fsid UUID|-      (-)            --mac AA:BB:..   (52:54:00:77:12:20)   --vlan N (0)   --mtu N (1500)
#   --ip ADDR/PREFIX|- (10.77.0.20/24)   --gw ADDR|-    --dns ADDR|-          (both -)
#   --static           the NIC was configured statically (flag)      --ro   the image was opened read-only (flag)
#   --secure-required  flag "secure required" (needs --mode secure)
# Table-only differences (the expectations stay as the options say):
#   --set NAME=VALUE   change one field of the table: mons entity pool image snap mode mac vlan mtu ip gw dns fsid flags auth keytype
#   --defect KIND      checksum | length | signature | magic | version | revision | reserved | trailing | truncate | oem
#                      (oem puts iPXE's own OEM fields in and fixes the checksum: it must still pass; truncate cuts the file short)
#
# Needs python3. Reads the independent layout implementation of harness/vectors/handoff/gen_handoff_vectors.py.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
gen_dir="$here/../../../vectors/handoff"

die() { printf 'expected-table.sh: %s\n' "$*" >&2; exit 2; }

usage() { sed -n '3,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

[ $# -ge 1 ] || { usage >&2; exit 2; }
cmd=$1
shift
case $cmd in
params | fwcfg | table | body) ;;
-h | --help | help) usage; exit 0 ;;
*) die "unknown command '$cmd' (params, fwcfg, table, body)" ;;
esac

[ -f "$gen_dir/gen_handoff_vectors.py" ] || die "cannot find $gen_dir/gen_handoff_vectors.py (run this from a full checkout of the repository)"
command -v python3 >/dev/null 2>&1 || die "python3 is needed"

# python -I: no user site, no PYTHONPATH, no cwd on the path; the generator's directory is added by hand below
exec python3 -I - "$gen_dir" "$cmd" "$@" <<'PY'
import base64, ipaddress, os, re, struct, sys

gen_dir, cmd, args = sys.argv[1], sys.argv[2], sys.argv[3:]
sys.dont_write_bytecode = True   # importing the generator must not leave a __pycache__ in the vectors directory
sys.path.insert(0, gen_dir)
import gen_handoff_vectors as g   # noqa: E402  (the independent second implementation of the layout)

def die(msg):
    sys.stderr.write("expected-table.sh: %s\n" % msg)
    sys.exit(2)

opt = dict(mons="10.77.0.10:3300", entity="winrbd-aes", pool="winrbd", image="wrtest-p2-lin-uefi", image_id="-", snap="-",
           mode="crc", keytype="none", key_b64_file=None, fsid="-", mac="52:54:00:77:12:20", vlan="0", mtu="1500",
           ip="10.77.0.20/24", gw="-", dns="-", static=False, ro=False, secreq=False)
sets, defects, out = [], [], None
valued = {"--mons": "mons", "--entity": "entity", "--pool": "pool", "--image": "image", "--image-id": "image_id", "--snap": "snap",
          "--mode": "mode", "--keytype": "keytype", "--key-b64-file": "key_b64_file", "--fsid": "fsid", "--mac": "mac",
          "--vlan": "vlan", "--mtu": "mtu", "--ip": "ip", "--gw": "gw", "--dns": "dns"}
i = 0
while i < len(args):
    a = args[i]
    if a in valued:
        if i + 1 >= len(args): die("%s needs a value" % a)
        opt[valued[a]] = args[i + 1]; i += 2
    elif a == "--static": opt["static"] = True; i += 1
    elif a == "--ro": opt["ro"] = True; i += 1
    elif a == "--secure-required": opt["secreq"] = True; i += 1
    elif a == "--set":
        if i + 1 >= len(args) or "=" not in args[i + 1]: die("--set needs NAME=VALUE")
        sets.append(args[i + 1].split("=", 1)); i += 2
    elif a == "--defect":
        if i + 1 >= len(args): die("--defect needs a kind")
        defects.append(args[i + 1]); i += 2
    elif a == "-o":
        if i + 1 >= len(args): die("-o needs a file")
        out = args[i + 1]; i += 2
    else:
        die("unknown option '%s'" % a)

for _k in ("vlan", "mtu"):
    if not opt[_k].isdigit(): die("--%s: a number" % _k)

MODES = {"crc": 1, "crc-first": 2, "secure-first": 3, "secure": 4}
KEYS = {"none": 0, "aes": 1, "aes256k": 2}

def key_raw(o):
    """the raw secret from the armoured file: u16 type, u32 sec, u32 nsec, u16 len, secret (never printed)"""
    if o["keytype"] == "none":
        return b""
    if not o["key_b64_file"]:
        die("--keytype %s needs --key-b64-file" % o["keytype"])
    try:
        blob = base64.b64decode(open(o["key_b64_file"]).read().strip(), validate=False)
    except OSError as e:
        die("cannot read the key file: %s" % e.strerror)
    if len(blob) < 12 or 12 + struct.unpack_from("<H", blob, 10)[0] != len(blob):
        die("the key file does not hold an armoured cephx secret")
    return blob[12:]

def ipv(text):
    try: a = ipaddress.ip_address(text)
    except ValueError: die("%r is not an address" % text)
    return (4 if a.version == 4 else 6), g.ip16(text).hex()

def monlist(text):
    res = []
    for m in text.split(","):
        mm = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d+)|([0-9.]+):(\d+)", m)
        if not mm: die("bad monitor '%s'" % m)
        host, port = (mm.group(1), mm.group(2)) if mm.group(1) else (mm.group(3), mm.group(4))
        res.append(g.mon(host, int(port)))
    return res

def flags_of(o):
    f = 0
    if o["ro"]: f |= g.F_RO
    if o["keytype"] != "none": f |= g.F_KEY
    if o["static"]: f |= g.F_STATIC
    if int(o["vlan"]) > 0: f |= g.F_VLAN
    if o["fsid"] != "-": f |= g.F_FSID
    if o["secreq"]: f |= g.F_SECREQ
    return f

def flag_names(f):
    n = [nm for bit, nm in ((g.F_RO, "ro"), (g.F_KEY, "key"), (g.F_STATIC, "static"), (g.F_VLAN, "vlan"), (g.F_FSID, "fsid"),
                            (g.F_SECREQ, "secure")) if f & bit]
    return ",".join(n) or "none"

def expectations(o):
    """the rbft.* words, in a fixed order"""
    keylen = len(key_raw(o)) if o["keytype"] != "none" else 0
    w = [("mons", o["mons"]), ("entity", o["entity"]), ("pool", o["pool"]), ("image", o["image"]), ("imageid", o["image_id"]),
         ("snap", o["snap"]), ("auth", "none" if o["entity"] == "-" else "cephx"), ("mode", o["mode"]),
         ("flags", flag_names(flags_of(o))), ("keytype", o["keytype"]), ("keylen", str(keylen)), ("fsid", o["fsid"]),
         ("mac", o["mac"].lower()), ("vlan", o["vlan"]), ("mtu", o["mtu"]), ("ip", o["ip"]), ("gw", o["gw"]), ("dns", o["dns"])]
    for k, v in w:
        if not re.fullmatch(r"[A-Za-z0-9._:@/+=,\[\]-]+", v):
            die("the value of %s has a character that does not belong on a kernel command line: %r" % (k, v))
    return w

def info_of(o):
    """the table description for the generator"""
    for k in ("vlan", "mtu"):
        if not o[k].isdigit(): die("%s: a number, not %r" % (k, o[k]))
    flags = flags_of(o)
    kt = KEYS.get(o["keytype"])
    if kt is None: die("--keytype: none, aes or aes256k")
    mode = MODES.get(o["mode"])
    if mode is None: die("--mode: crc, crc-first, secure-first or secure")
    key = key_raw(o)
    nf, nip, ngw, ndns, pre = 0, "00" * 16, "00" * 16, "00" * 16, 0
    if o["ip"] != "-":
        addr, _, p = o["ip"].partition("/")
        if not p.isdigit(): die("--ip: ADDR/PREFIX or -")
        nf, nip = ipv(addr)
        pre = int(p)
        if o["gw"] != "-": ngw = ipv(o["gw"])[1]
        if o["dns"] != "-": ndns = ipv(o["dns"])[1]
    fsid = "00" * 16
    if o["fsid"] != "-":
        fsid = o["fsid"].replace("-", "").lower()
        if not re.fullmatch(r"[0-9a-f]{32}", fsid): die("--fsid: a UUID or -")
    mac = o["mac"].replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{12}", mac): die("--mac: aa:bb:cc:dd:ee:ff")
    return {"flags": flags, "auth": 0 if o["entity"] == "-" else 1, "msgr_mode": mode,
            "key_type": kt, "key": key.hex(), "key_len": len(key), "fsid": fsid, "nic_mac": mac, "nic_vlan": int(o["vlan"]),
            "nic_mtu": int(o["mtu"]), "nic_family": nf, "nic_prefix": pre, "nic_ip": nip, "nic_gateway": ngw, "nic_dns": ndns,
            "entity": "" if o["entity"] == "-" else o["entity"], "pool": o["pool"], "rbd_namespace": "", "image": o["image"],
            "image_id": "" if o["image_id"] == "-" else o["image_id"], "snapshot": "" if o["snap"] == "-" else o["snap"],
            "mons": monlist(o["mons"])}

words = expectations(opt)
if cmd == "params":
    print(" ".join("rbft.%s=%s" % kv for kv in words)); sys.exit(0)
if cmd == "fwcfg":
    print("\n".join("rbft.%s=%s" % kv for kv in words)); sys.exit(0)

# a table: first the description of the options, then the deliberate differences
topt = dict(opt)
allowed = {"mons", "entity", "pool", "image", "snap", "mode", "mac", "vlan", "mtu", "ip", "gw", "dns", "fsid", "flags", "auth", "keytype"}
for k, v in sets:
    if k not in allowed: die("--set: unknown field '%s'" % k)
    if k == "auth":
        if v == "none": topt["entity"] = "-"
        elif v != "cephx": die("--set auth=none|cephx")
    elif k != "flags": topt[k] = v
info = info_of(topt)
if "flags" in dict(sets):
    info["flags"] = int(dict(sets)["flags"], 0)
body = g.build_body(info)
oem = False
table = g.wrap_table(body)
# a defect lives in the ACPI header or in the framing of the whole table; a "body" (QEMU builds the header itself) has neither, and
# with several defects the later one would silently replace the earlier: both would hand a test a table that is not the one it asked for
if defects and cmd == "body": die("--defect needs the whole table (use 'table'): QEMU makes the header and the checksum of a body")
if len(defects) > 1: die("one --defect at a time")
for d in defects:
    t = bytearray(table)
    if d == "checksum": t[9] ^= 0x5A
    elif d == "length": table = g.wrap_table(body, length=len(t) + 8); continue
    elif d == "signature": t[0:4] = b"rBFt"; table = g.set_checksum(bytes(t)); continue
    elif d == "revision": table = g.wrap_table(body, rev=2); continue
    elif d == "magic": b = bytearray(body); b[0:4] = b"WRBU"; table = g.wrap_table(bytes(b)); continue
    elif d == "version": b = bytearray(body); b[4] = 2; table = g.wrap_table(bytes(b)); continue
    elif d == "reserved": b = bytearray(body); b[19] = 1; table = g.wrap_table(bytes(b)); continue
    elif d == "trailing": table = g.wrap_table(body + b"\x00\x00\x00\x00"); continue
    elif d == "truncate": t = t[:-8]
    elif d == "oem":
        t[10:16] = b"FENSYS"; t[16:24] = b"iPXE    "; t[24:28] = struct.pack("<I", 1); t[28:32] = b"iPXE"
        t[9] = 0; t[9] = (-sum(t)) & 0xFF
    else: die("--defect: unknown kind '%s'" % d)
    table = bytes(t)

if out is None: die("-o FILE is needed for '%s'" % cmd)
data = body if cmd == "body" else table
fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(data)
sys.stderr.write("expected-table.sh: %s: %d bytes\n" % (out, len(data)))
PY
