#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
check_osdc.py - the OSD / RBD capture set of module vectors-c (harness/vectors/public/osdc/): an independent decoder written from
docs/spec/osd-ops.md, docs/spec/rbd-format2.md and docs/spec/msgr2.md (python3 standard library only, no cluster, no Ceph code).

    python3 -I check_osdc.py [check] [--dir DIR]        verify the committed vectors      (ctest: vectors_osdc_check)
    python3 -I check_osdc.py selftest [--dir DIR]       feed `check` 23 damaged copies of them (ctest: vectors_osdc_selftest)
    python3 -I check_osdc.py extract --work W --out DIR build the vectors from a capture  (capture_osdc.sh, inside the lab VM)

check: every file's size and SHA-256 against INDEX.json, no stray file or link, a size budget, no text that looks like a key, a
ticket, a password or an address outside the lab nets; every message of every session is decoded again from its recorded
bytes with the layouts of the notes (the msgr2 header, MOSDOp v9, MOSDOpReply v8, MOSDBackoff, the rbd and lock class outputs) and
must equal the recorded summary; requests and replies pair by transaction id; the data segment of every reply is cut by its operation
lengths and agrees with what the client library reported at capture time; the header reads of every image agree with `rbd info`
and with the refusal table of the note; every exported data object agrees with the recipe of its pattern; backoffs are well formed
(an ack equals its block, an unblock names a block) and the coverage the module promises is there (every operation kind, a missing
object, a short object, a write with a snapshot context, BLOCK / ACK_BLOCK / UNBLOCK, every feature word of the refusal table).
The C replays (ctest osd.vec_replay and rbd.vec_replay) run the same files through the real decoders of core/.

extract: reads the work directory of capture_osdc.sh (pcap per session, the probe's log, the commands, the ground truth taken with
the stock tools) and writes the vector tree. The pcaps themselves are not published: only the OSD messages cut out of them.
"""
import argparse
import hashlib
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DIR = os.path.normpath(os.path.join(HERE, "..", "osdc"))
BUDGET = 3_000_000
DATA_HEX_MAX = 20000          # data segments up to this many bytes are stored in full, longer ones as length + sha256 + head
NOSNAP = 0xFFFFFFFFFFFFFFFE


class DecodeError(Exception):
    pass


# ---- CRC-32C ---------------------------------------------------------------------------------------------------------

def _tab():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t.append(c)
    return t


_T = _tab()


def crc32c(data, crc=0):
    for b in data:
        crc = (crc >> 8) ^ _T[(crc ^ b) & 255]
    return crc


# ---- reader ----------------------------------------------------------------------------------------------------------

class Rd:
    def __init__(self, b):
        self.b = bytes(b)
        self.o = 0

    def left(self):
        return len(self.b) - self.o

    def take(self, n):
        if n < 0 or self.o + n > len(self.b):
            raise DecodeError("need %d bytes at %d, have %d" % (n, self.o, self.left()))
        r = self.b[self.o:self.o + n]
        self.o += n
        return r

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def string(self):
        return self.take(self.u32())

    def boolean(self):
        v = self.u8()
        if v > 1:
            raise DecodeError("bool %d" % v)
        return v == 1

    def sub(self, max_compat):
        """struct header: u8 version, u8 compat, u32 length; returns (version, compat, reader over the body)."""
        v, c, n = self.u8(), self.u8(), self.u32()
        if c > max_compat:
            raise DecodeError("struct compat %d above %d" % (c, max_compat))
        return v, c, Rd(self.take(n))


def hx(b):
    return bytes(b).hex()


def ulong(v):
    """u64 values that may pass 2^53 travel as hex strings in the JSON files."""
    return "0x%x" % v


# ---- pcap, TCP streams, msgr2 frames (crc mode) ----------------------------------------------------------------------

class Stream:
    def __init__(self):
        self.isn = None
        self.segs = []
        self.data = b""
        self.chunks = []
        self.gaps = 0

    def finish(self):
        buf = bytearray()
        for off, d, ts in sorted(self.segs, key=lambda s: s[0]):
            if off > len(buf):
                self.gaps += 1
                break
            if off < len(buf):
                d = d[len(buf) - off:]
                off = len(buf)
                if not d:
                    continue
            self.chunks.append((off, ts))
            buf += d
        self.data = bytes(buf)
        self.segs = []

    def ts_at(self, off):
        best = self.chunks[0][1] if self.chunks else 0.0
        for o, ts in self.chunks:
            if o <= off:
                best = ts
            else:
                break
        return best


class Flow:
    def __init__(self, client, server):
        self.client, self.server = client, server
        self.c2s, self.s2c = Stream(), Stream()


def tcp_flows(path):
    data = open(path, "rb").read()
    if data[:4] == b"\xd4\xc3\xb2\xa1":
        nano = False
    elif data[:4] == b"\x4d\x3c\xb2\xa1":
        nano = True
    else:
        raise DecodeError("not a little-endian classic pcap")
    if struct.unpack("<I", data[20:24])[0] != 1:
        raise DecodeError("link type is not Ethernet")
    p = 24
    flows, order = {}, []
    while p + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack("<IIII", data[p:p + 16])
        p += 16
        fr = data[p:p + incl]
        p += incl
        ts = sec + frac / (1e9 if nano else 1e6)
        if len(fr) < 54 or fr[12:14] != b"\x08\x00" or fr[23] != 6:
            continue
        ihl = (fr[14] & 15) * 4
        tot = struct.unpack(">H", fr[16:18])[0]
        src = ".".join(str(x) for x in fr[26:30])
        dst = ".".join(str(x) for x in fr[30:34])
        t = 14 + ihl
        sport, dport, seq, _ack = struct.unpack(">HHII", fr[t:t + 12])
        doff = (fr[t + 12] >> 4) * 4
        fl = fr[t + 13]
        payload = fr[t + doff:14 + tot]
        a, b = (src, sport), (dst, dport)
        k = (a, b) if (a, b) in flows else ((b, a) if (b, a) in flows else None)
        if k is None:
            k = (a, b)
            flows[k] = Flow(a, b)
            order.append(k)
        f = flows[k]
        st = f.c2s if a == f.client else f.s2c
        if fl & 2:
            st.isn = (seq + 1) & 0xFFFFFFFF
        if payload:
            if st.isn is None:
                st.isn = seq
            st.segs.append(((seq - st.isn) & 0xFFFFFFFF, payload, ts))
    out = []
    for k in order:
        f = flows[k]
        f.c2s.finish()
        f.s2c.finish()
        out.append(f)
    return out


def walk_frames(buf):
    """Yield (tag, segments, stream offset) for every msgr2 crc-mode frame after the banner (msgr2.md 2.2 to 2.6)."""
    if buf[:8] != b"ceph v2\n":
        return
    # banner: 8 bytes prefix, u16 payload length, payload (two u64 feature words = 16 bytes)
    pos = 10 + struct.unpack("<H", buf[8:10])[0]
    while pos + 32 <= len(buf):
        pre = buf[pos:pos + 32]
        tag, n = pre[0], pre[1]
        if not 1 <= n <= 4 or crc32c(pre[:28], 0) != struct.unpack("<I", pre[28:32])[0]:
            return
        lens = [struct.unpack("<IH", pre[2 + 6 * i:8 + 6 * i])[0] for i in range(4)]
        p = pos + 32
        need = (lens[0] + 4 if lens[0] else 0) + sum(lens[1:n]) + (13 if n > 1 else 0)
        if p + need > len(buf):
            return
        segs = []
        if lens[0]:
            s0 = buf[p:p + lens[0]]
            if crc32c(s0, 0xFFFFFFFF) != struct.unpack("<I", buf[p + lens[0]:p + lens[0] + 4])[0]:
                return
            p += lens[0] + 4
        else:
            s0 = b""
        segs.append(s0)
        for i in range(1, n):
            segs.append(buf[p:p + lens[i]])
            p += lens[i]
        if n > 1:
            for i in range(1, n):
                c = struct.unpack("<I", buf[p + 1 + 4 * (i - 1):p + 5 + 4 * (i - 1)])[0]
                if crc32c(segs[i], 0xFFFFFFFF) != c:
                    return
            p += 13
        yield tag, segs, pos
        pos = p


def dec_header2(h):
    if len(h) != 41:
        raise DecodeError("message header is %d bytes, not 41" % len(h))
    (seq, tid, typ, prio, ver, dpp, doff, ackseq, flags, compat, resv) = struct.unpack("<QQHHHIHQBHH", h)
    return dict(seq=seq, tid=tid, type=typ, priority=prio, version=ver, compat_version=compat, data_pre_padding=dpp,
                data_off=doff, ack_seq=ackseq, flags=flags, reserved=resv)


MSG_TYPES = {41: "MOSDMap", 42: "MOSDOp", 43: "MOSDOpReply", 61: "MOSDBackoff"}


def capture_messages(path):
    """Every OSD message (types 41, 42, 43, 61) of a capture, in time order, with its connection index."""
    msgs = []
    for ci, f in enumerate(tcp_flows(path)):
        for dname, st in (("c2s", f.c2s), ("s2c", f.s2c)):
            for tag, segs, off in walk_frames(st.data):
                if tag != 17 or len(segs[0]) != 41:
                    continue
                h = dec_header2(segs[0])
                if h["type"] not in MSG_TYPES:
                    continue
                segs = segs + [b""] * (4 - len(segs))
                msgs.append(dict(conn=ci, dir=dname, ts=st.ts_at(off), off=off, hdr=segs[0], h=h, front=segs[1], middle=segs[2],
                                 data=segs[3], server=f.server))
    msgs.sort(key=lambda m: (m["ts"], m["conn"], m["dir"] != "c2s", m["off"]))
    return msgs


# ---- message layouts -------------------------------------------------------------------------------------------------

OPS = {0x1201: "READ", 0x1202: "STAT", 0x1205: "SPARSE_READ", 0x2201: "WRITE", 0x2202: "WRITEFULL", 0x2203: "TRUNCATE",
       0x2204: "ZERO", 0x2205: "DELETE", 0x220D: "CREATE", 0x2223: "SETALLOCHINT", 0x1301: "GETXATTR", 0x1401: "CALL",
       0x1212: "OMAPGETVALS", 0x1214: "OMAPGETVALSBYKEYS"}
EXTENT_OPS = ("READ", "SPARSE_READ", "WRITE", "WRITEFULL", "TRUNCATE", "ZERO")
MUTATING = (0x2201, 0x2202, 0x2203, 0x2204, 0x2205, 0x220D, 0x2223)


def dec_op_record(b):
    if len(b) != 38:
        raise DecodeError("op record of %d bytes" % len(b))
    code, flags = struct.unpack_from("<HI", b, 0)
    payload = struct.unpack_from("<I", b, 34)[0]
    d = dict(code=code, name=OPS.get(code, "0x%04x" % code), flags=flags, payload_len=payload)
    nm = d["name"]
    if nm in EXTENT_OPS:
        d["off"], d["len"], d["truncate_size"], d["truncate_seq"] = struct.unpack_from("<QQQI", b, 6)
    elif nm == "CALL":
        d["class_len"], d["method_len"], d["argc"], d["indata_len"] = struct.unpack_from("<BBBI", b, 6)
    elif nm == "SETALLOCHINT":
        d["off"], d["len"], d["hint_flags"] = struct.unpack_from("<QQI", b, 6)     # expected object size, expected write size
    elif nm == "GETXATTR":
        d["name_len"], d["value_len"] = struct.unpack_from("<II", b, 6)
    elif nm in ("OMAPGETVALS", "OMAPGETVALSBYKEYS"):
        d["off"], d["len"] = struct.unpack_from("<QQ", b, 6)
    return d


def dec_spg(r):
    v, c, s = r.sub(1)
    if s.u8() != 1:
        raise DecodeError("pg_t leading byte")
    pool, seed, pref = s.u64(), s.u32(), s.i32()
    shard = s.u8()
    if s.left() or pref != -1:
        raise DecodeError("spg_t body")
    return pool, seed, shard


def dec_mosdop(front, version):
    """osd-ops.md 2.3."""
    r = Rd(front)
    pool, seed, shard = dec_spg(r)
    m = dict(pool=pool, seed=seed, shard=shard, hash=r.u32(), epoch=r.u32(), flags=r.u32())
    v, c, s = r.sub(2)                                           # reqid
    m["reqid"] = [s.u8(), s.i64(), s.u64(), s.i32()]
    if s.left():
        raise DecodeError("reqid body")
    r.take(24)                                                   # blkin
    if version >= 9:
        if r.take(7) != bytes.fromhex("01010100000000"):
            raise DecodeError("otel field is not the empty one")
    m["client_inc"] = r.u32()
    m["mtime"] = [r.u32(), r.u32()]
    v, c, s = r.sub(6)                                           # object_locator_t
    lpool, lpref, key, nspace, lhash = s.i64(), s.i32(), s.string(), s.string(), s.i64()
    m["oloc"] = dict(pool=lpool, key=key.decode("latin1"), nspace=nspace.decode("latin1"), hash=lhash)
    m["oid"] = r.string().decode("latin1")
    n = r.u16()
    m["ops"] = [dec_op_record(r.take(38)) for _ in range(n)]
    m["snapid"] = r.u64()
    m["snap_seq"] = r.u64()
    m["snaps"] = [r.u64() for _ in range(r.u32())]
    m["retry_attempt"] = r.i32()
    m["features"] = r.u64()
    if r.left():
        raise DecodeError("%d bytes after the request" % r.left())
    return m


def dec_mosdopreply(front):
    """osd-ops.md 2.9 (version 8)."""
    r = Rd(front)
    m = dict(oid=r.string().decode("latin1"))
    if r.u8() != 1:
        raise DecodeError("pg_t leading byte")
    m["pool"], m["seed"], pref = r.u64(), r.u32(), r.i32()
    m["flags"], m["result"] = r.i64(), r.i32()
    r.take(12)                                                   # legacy replay version
    m["epoch"] = r.u32()
    n = r.u32()
    if n > 64:
        raise DecodeError("op count")
    m["ops"] = [dec_op_record(r.take(38)) for _ in range(n)]
    m["retry_attempt"] = r.i32()
    m["rvals"] = [r.i32() for _ in range(n)]
    m["replay_version"] = [r.u64(), r.u32()]
    m["user_version"] = r.u64()
    m["do_redirect"] = r.boolean()
    if m["do_redirect"]:
        raise DecodeError("redirect reply")
    r.take(24)
    if r.left():
        raise DecodeError("%d bytes after the reply" % r.left())
    return m


def dec_hobject(r):
    v, c, s = r.sub(4)
    key, oid, snap, h, mx, ns, pool = s.string(), s.string(), s.u64(), s.u32(), s.boolean(), s.string(), s.i64()
    if s.left() and v < 5:
        raise DecodeError("hobject body")
    return dict(key=key.decode("latin1"), oid=oid.decode("latin1"), snap=ulong(snap), hash=h, max=int(mx),
                nspace=ns.decode("latin1"), pool=pool)


def dec_backoff(front):
    """osd-ops.md 2.10."""
    r = Rd(front)
    pool, seed, shard = dec_spg(r)
    m = dict(pool=pool, seed=seed, epoch=r.u32(), op=r.u8(), id=r.u64())
    m["begin"] = dec_hobject(r)
    m["end"] = dec_hobject(r)
    if r.left():
        raise DecodeError("%d bytes after the backoff" % r.left())
    return m


def summarize(msg):
    """The decoded fields of one message (what the C replays rebuild it from)."""
    t = msg["h"]["type"]
    if t == 42:
        m = dec_mosdop(msg["front"], msg["h"]["version"])
        ops = []
        for o in m["ops"]:
            d = dict(o)
            for k in ("truncate_size", "truncate_seq", "argc"):
                d.pop(k, None)
            ops.append(d)
        return dict(pool=m["pool"], seed=m["seed"], hash=m["hash"], epoch=m["epoch"], flags=m["flags"], oid=m["oid"],
                    nspace=m["oloc"]["nspace"], oloc_key=m["oloc"]["key"], mtime=m["mtime"], ops=ops, snapid=ulong(m["snapid"]),
                    snap_seq=ulong(m["snap_seq"]), snaps=[ulong(s) for s in m["snaps"]], retry_attempt=m["retry_attempt"],
                    features=ulong(m["features"]), client_inc=m["client_inc"], reqid=m["reqid"],
                    trunc=[[o.get("truncate_size", 0), o.get("truncate_seq", 0)] for o in m["ops"] if "truncate_size" in o])
    if t == 43:
        m = dec_mosdopreply(msg["front"])
        return dict(oid=m["oid"], pool=m["pool"], seed=m["seed"], flags=m["flags"], result=m["result"], epoch=m["epoch"],
                    ops=[dict(code=o["code"], name=o["name"], out_len=o["payload_len"]) for o in m["ops"]], rvals=m["rvals"],
                    retry_attempt=m["retry_attempt"], user_version=m["user_version"], replay_version=m["replay_version"],
                    do_redirect=0)
    if t == 61:
        return dec_backoff(msg["front"])
    return {}


def msg_json(msg):
    d = msg["data"]
    data = dict(length=len(d), sha256=hashlib.sha256(d).hexdigest())
    if len(d) <= DATA_HEX_MAX:
        data["hex"] = hx(d)
    else:
        data["head_hex"] = hx(d[:32])
    h = msg["h"]
    return dict(type=h["type"], version=h["version"], compat_version=h["compat_version"], priority=h["priority"], tid=h["tid"],
                seq=h["seq"], header2_hex=hx(msg["hdr"]), segment_lengths=[41, len(msg["front"]), len(msg["middle"]), len(d)],
                front_hex=hx(msg["front"]), data=data, summary=summarize(msg))


# ---- rbd class outputs and the refusal table (rbd-format2.md 2.3, 2.5, 2.7, 2.8, 3.3, 4.2) -----------------------------

def dec_call_out(method, out):
    r = Rd(out)
    if method == "get_id":
        v = dict(id=r.string().decode("latin1"))
    elif method == "get_size":
        v = dict(order=r.u8(), size=r.u64())
    elif method == "get_object_prefix":
        v = dict(prefix=r.string().decode("latin1"))
    elif method == "get_features":
        v = dict(features=r.u64(), incompatible=r.u64())
    elif method in ("get_flags", "op_features_get"):
        v = {"flags" if method == "get_flags" else "op_features": r.u64()}
    elif method == "get_snapcontext":
        seq, n = r.u64(), r.u32()
        if n * 8 > r.left():
            raise DecodeError("snapshot count")
        v = dict(seq=seq, snaps=[r.u64() for _ in range(n)])
    elif method == "get_data_pool":
        v = dict(data_pool=r.i64())
    elif method == "parent_get":
        _v, _c, s = r.sub(1)
        pool, ns, iid, snap = s.i64(), s.string(), s.string(), s.u64()
        v = dict(parent=int(pool >= 0 and len(iid) > 0 and snap != NOSNAP), pool=pool, image_id=iid.decode("latin1"),
                 snap=ulong(snap))
    elif method == "parent_overlap_get":
        pres = r.u8()
        if pres > 1:
            raise DecodeError("optional marker")
        v = dict(present=pres, overlap=r.u64() if pres else 0)
    elif method == "get_stripe_unit_count":
        v = dict(unit=r.u64(), count=r.u64())
    elif method == "get_info":
        _v, _c, s = r.sub(1)
        n = s.u32()
        if n > 64:
            raise DecodeError("lockers")
        lockers = []
        for _ in range(n):
            _a, _b, idr = s.sub(1)
            ent = (idr.u8(), idr.i64())
            cookie = idr.string()
            _a, _b, info = s.sub(1)
            exp = [info.u32(), info.u32()]
            lockers.append(dict(entity=list(ent), cookie=cookie.decode("latin1"), expiration=exp, rest_len=info.left()))
        v = dict(lockers=lockers, type=s.u8(), tag=s.string().decode("latin1"))
        if s.left():
            raise DecodeError("lock info trailing")
    else:
        raise DecodeError("no layout for " + method)
    if r.left():
        raise DecodeError("%s: %d bytes left" % (method, r.left()))
    return v


def header_from_calls(calls):
    """Everything the open decides on, from the decoded call outputs of one image ({method: decoded})."""
    h = dict(order=calls["get_size"]["order"], size=calls["get_size"]["size"], prefix=calls["get_object_prefix"]["prefix"],
             features=calls["get_features"]["features"], flags=calls["get_flags"]["flags"], snapc=calls["get_snapcontext"],
             data_pool=calls["get_data_pool"]["data_pool"], has_parent=calls["parent_get"]["parent"],
             has_overlap=calls["parent_overlap_get"]["present"], overlap=calls["parent_overlap_get"]["overlap"],
             op_features=calls.get("op_features_get", {}).get("op_features", 0), stripe_unit=0, stripe_count=0)
    if "get_stripe_unit_count" in calls:
        h["stripe_unit"] = calls["get_stripe_unit_count"]["unit"]
        h["stripe_count"] = calls["get_stripe_unit_count"]["count"]
    return h


def snapc_valid(seq, snaps):
    if seq > 0xFFFFFFFFFFFFFFFD:
        return False
    for i, s in enumerate(snaps):
        if i == 0 and s > seq:
            return False
        if i > 0 and (s >= snaps[i - 1] or snaps[i - 1] == 0):
            return False
    return True


def refusal(h, writer):
    """The first refusal of rbd-format2.md 3.3 for the profiles of 4.2 (reader R1 = 0x1ff, writer P1 = 0xa1; the striping bit is
    judged by its layout for both). Returns ("OK", {}) or ("RBD_E_*", numbers)."""
    f = h["features"]
    mask = (0xA1 if writer else 0x1FF) | 0x2
    if f & ~mask:
        return "RBD_E_FEATURES", dict(a0=f & ~mask, a1=f, a2=int(writer))
    if not snapc_valid(h["snapc"]["seq"], h["snapc"]["snaps"]):
        return "RBD_E_SNAPC", {}
    if not 12 <= h["order"] <= 25:
        return "RBD_E_ORDER", dict(a0=h["order"])
    obj = 1 << h["order"]
    if f & 2 and h["stripe_unit"] and h["stripe_count"] and (h["stripe_count"] != 1 or h["stripe_unit"] != obj):
        return "RBD_E_STRIPING", dict(a0=h["stripe_unit"], a1=h["stripe_count"], a2=obj)
    parent = h["has_parent"] or h["has_overlap"] or (f & 0x100 and h["op_features"] & 2)
    if parent:
        return "RBD_E_PARENT", dict(parent_get=h["has_parent"], overlap=h["has_overlap"],
                                    clone_child=int(bool(f & 0x100 and h["op_features"] & 2)))
    if f & 0x80 and h["data_pool"] < 0:
        return "RBD_E_DATA_POOL", {}
    if writer and h["flags"]:
        return "RBD_E_FLAGS", dict(a0=h["flags"])
    return "OK", {}


# ---- patterned images (the recipe of capture_osdc.sh) ----------------------------------------------------------------

def recipe_byte(segments, o):
    for off, ln, mul, add in segments:
        if off <= o < off + ln:
            return (o * mul + add) % 251
    return 0


def recipe_range(segments):
    """(first, last+1) image offsets that carry data"""
    return min(s[0] for s in segments), max(s[0] + s[1] for s in segments)


def check_object(img, objno, blob, errs):
    """The exported object of a patterned image against its recipe: every byte, and the size (it holds every written byte, ends
    inside the data of its last written 4 KiB sparse block)."""
    order, segs = img["order"], img["segments"]
    osz = 1 << order
    base = objno * osz
    last = -1
    for o in range(base, base + osz):
        if recipe_byte(segs, o):
            last = o - base
    if last < 0:
        errs.append("%s object %d: has no data in the recipe, but exists" % (img["name"], objno))
        return
    if len(blob) < last + 1 or len(blob) > min(osz, ((last + 4096) // 4096) * 4096):
        errs.append("%s object %d: size %d does not match the recipe (last data byte at %d)" % (img["name"], objno, len(blob), last))
    for i, b in enumerate(blob):
        if b != recipe_byte(segs, base + i):
            errs.append("%s object %d: byte %d is %d, the recipe says %d" % (img["name"], objno, i, b, recipe_byte(segs, base + i)))
            return


# ---- extract ---------------------------------------------------------------------------------------------------------

def jdump(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")


def read_probe(path):
    rows = []
    if os.path.exists(path):
        for ln in open(path):
            ln = ln.strip()
            if ln.startswith("{"):
                rows.append(json.loads(ln))
    return rows


def probe_summary(p):
    """What the client library reported, in the form the checker compares with the wire."""
    d = dict(label=p["label"], rc=p["rc"], kind=p["kind"])
    if p["kind"] == "calls":
        d["calls"] = [dict(cls=c["cls"], method=c["method"], inp=c["in"], out=c["out"], rval=c["rval"]) for c in p["calls"]]
    else:
        d["rval"] = p.get("rval")
        if "data" in p:
            d["data_len"] = p["data_len"]
            d["data_sha256"] = hashlib.sha256(bytes.fromhex(p["data"])).hexdigest()
        for k in ("extents", "size", "mtime", "what", "off", "len"):
            if k in p:
                d[k] = p[k]
    return d


def pair_messages(msgs, single_client):
    """Requests (first transmission and resends) with their reply, by transaction id (and connection when several client processes
    ran in one capture). Returns exchanges in order of the first request."""
    ex, order = {}, []
    for m in msgs:
        t = m["h"]["type"]
        if t not in (42, 43):
            continue
        key = m["h"]["tid"] if single_client else (m["conn"] if t == 43 else None, m["h"]["tid"])
        if not single_client and t == 42:
            key = (m["conn"], m["h"]["tid"])
        e = ex.get(key)
        if e is None:
            e = dict(req=[], rep=None, conn=m["conn"])
            ex[key] = e
            order.append(key)
        if t == 42:
            e["req"].append(m)
        else:
            e["rep"] = m
    return [ex[k] for k in order if ex[k]["req"]]


def exchange_json(e, n):
    d = dict(n=n, conn=e["conn"], request=msg_json(e["req"][0]))
    if len(e["req"]) > 1:
        d["resends"] = [dict(msg_json(m), conn=m["conn"]) for m in e["req"][1:]]
    d["reply"] = msg_json(e["rep"]) if e["rep"] is not None else None
    d["t_ms"] = round((e["req"][0]["ts"] - e["t0"]) * 1000, 1)
    return d


def scrub_paths(cmds, work):
    """The commands are published as the record of what the stock tools were asked: the lab's own directories (the work directory
    and the home it lives in) are not part of that record."""
    home = os.path.expanduser("~")
    out = []
    for c in cmds:
        c = c.replace(work, "<work>")
        if len(home) > 1:
            c = c.replace(home, "<home>")
        out.append(c)
    return out


def extract_session(work, name, meta):
    pcap = os.path.join(work, "pcap", name + ".pcap")
    msgs = capture_messages(pcap)
    if not msgs:
        raise DecodeError("%s: no OSD message in the capture" % name)
    t0 = msgs[0]["ts"]
    kind = meta.get("kind", "probe")
    probe = read_probe(os.path.join(work, "probe", name + ".jsonl"))
    sess = dict(session=name, about=meta.get("about", ""), mode="crc", commands=scrub_paths(meta.get("commands", []), work),
                osdmap_epoch=[meta.get("epoch0"), meta.get("epoch1")], pcap_bytes=os.path.getsize(pcap),
                pcap_sha256=hashlib.sha256(open(pcap, "rb").read()).hexdigest(), start=meta.get("start"), end=meta.get("end"),
                tcpdump_dropped=meta.get("dropped", 0))
    if kind == "backoff":
        return extract_backoff(sess, msgs, t0)
    exs = pair_messages(msgs, single_client=(kind == "probe"))
    for e in exs:
        e["t0"] = t0
    if kind == "probe":
        steps = [p for p in probe if p.get("kind") != "loop"]
        if len(steps) != len(exs):
            raise DecodeError("%s: the probe reported %d steps, the capture has %d requests" % (name, len(steps), len(exs)))
        out = []
        for i, (e, p) in enumerate(zip(exs, steps)):
            j = exchange_json(e, i + 1)
            if j["request"]["summary"]["oid"] != p["oid"]:
                raise DecodeError("%s step %d: probe object %s, wire object %s" % (name, i + 1, p["oid"], j["request"]["summary"]["oid"]))
            j["label"] = p["label"]
            j["probe"] = probe_summary(p)
            out.append(j)
    else:
        out = [exchange_json(e, i + 1) for i, e in enumerate(exs)]
    sess["exchanges"] = out
    sess["other_messages"] = sum(1 for m in msgs if m["h"]["type"] == 41)
    return sess


def extract_backoff(sess, msgs, t0):
    """A load under an OSD restart or an `osd out`: keep every backoff message and, for each PG that was blocked, the requests that
    were in flight to it (first transmission, resends) with their replies; the thousands of other exchanges are counted only."""
    bo = [m for m in msgs if m["h"]["type"] == 61]
    pgs = set()
    for m in bo:
        b = dec_backoff(m["front"])
        pgs.add((b["pool"], b["seed"]))
    exs = pair_messages(msgs, single_client=True)
    for e in exs:
        e["t0"] = t0
    keep = []
    total = len(exs)
    for e in exs:
        s = summarize(e["req"][0])
        if (s["pool"], s["seed"]) in pgs and (len(e["req"]) > 1 or e["rep"] is None or e["req"][0]["conn"] != (e["rep"] or e["req"][0])["conn"]):
            keep.append(e)
    # at most 16 blocked exchanges, the first ones
    keep = keep[:16]
    sess["exchanges"] = [exchange_json(e, i + 1) for i, e in enumerate(keep)]
    sess["exchanges_in_capture"] = total
    sess["backoffs"] = []
    for m in bo:
        d = msg_json(m)
        d["dir"] = m["dir"]
        d["conn"] = m["conn"]
        d["t_ms"] = round((m["ts"] - t0) * 1000, 1)
        sess["backoffs"].append(d)
    return sess


def cmd_extract(a):
    work, out = os.path.abspath(a.work), os.path.abspath(a.out)
    plan = json.load(open(os.path.join(work, "plan.json")))
    files = {}
    os.makedirs(out, exist_ok=True)
    sessions = []
    for name in plan["sessions"]:
        meta = json.load(open(os.path.join(work, "meta", name + ".json")))
        s = extract_session(work, name, meta)
        jdump(os.path.join(out, "sessions", name + ".json"), s)
        sessions.append(name)
        print("session %-22s %3d exchanges, %d backoff messages" % (name, len(s["exchanges"]), len(s.get("backoffs", []))))
    # images: ground truth from the stock tools + what the header reads said
    images = []
    for im in plan["images"]:
        d = dict(im)
        d["gt"] = json.load(open(os.path.join(work, "gt", im["name"] + ".json")))
        errs = []
        h, calls = decode_image(json.load(open(os.path.join(out, "sessions", "hdr-" + im["name"] + ".json"))), errs)
        if h is None:
            raise DecodeError("%s: %s" % (im["name"], errs))
        d["header"] = image_header_json(h, calls)
        d["expect"] = image_expect(h)
        images.append(d)
    jdump(os.path.join(out, "images.json"), dict(images=images))
    # data objects exported with `rados get`
    objs = dict(images=plan["patterns"], objects=[])
    for pat in plan["patterns"]:
        d = os.path.join(work, "objects", pat["name"])
        for fn in sorted(os.listdir(d)):
            blob = open(os.path.join(d, fn), "rb").read()
            objno = int(fn.split(".")[-1], 16)
            rel = "objects/%s/%s.bin" % (pat["name"], fn.split(".")[-1])
            os.makedirs(os.path.join(out, "objects", pat["name"]), exist_ok=True)
            open(os.path.join(out, rel), "wb").write(blob)
            objs["objects"].append(dict(image=pat["name"], objno=objno, file=rel, size=len(blob),
                                        sha256=hashlib.sha256(blob).hexdigest()))
    jdump(os.path.join(out, "objects.json"), objs)
    index = dict(plan["index"], sessions=sessions)
    index["files"] = {}
    for root, _d, names in os.walk(out):
        for nm in names:
            rel = os.path.relpath(os.path.join(root, nm), out)
            if rel in ("INDEX.json", "README.md"):
                continue
            b = open(os.path.join(root, nm), "rb").read()
            index["files"][rel] = dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    jdump(os.path.join(out, "INDEX.json"), index)
    print("wrote %d files, %d bytes" % (len(index["files"]), sum(f["bytes"] for f in index["files"].values())))
    return 0


# ---- check -----------------------------------------------------------------------------------------------------------

KEY_RE = re.compile(r"AQ[A-Za-z0-9+/]{36,}={0,2}|key\s*=|-----BEGIN|password|secret|ticket", re.I)
KEY_RE_LOG = re.compile(r"AQ[A-Za-z0-9+/]{36,}={0,2}|key\s*=|-----BEGIN|password")   # revert-proof.txt names health checks (..._TICKETS)
PATH_RE = re.compile(r"(?<![A-Za-z0-9_.])/(?:home|Users|root|tmp|var/tmp)/[A-Za-z0-9_.-]")   # a lab or developer directory in a published file
IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
REQUIRED_FEATURES = {0x1, 0x5, 0x21, 0x3D, 0x45, 0x81, 0x3}      # feature words of the refusal table the images must cover


def op_method(ex, op):
    """The method name of a CALL of a request, read from its data segment."""
    data = bytes.fromhex(ex["request"]["data"]["hex"])
    off = 0
    for o in ex["request"]["summary"]["ops"]:
        if o is op:
            if o["name"] != "CALL":
                return o["name"]
            return data[off + o["class_len"]:off + o["class_len"] + o["method_len"]].decode("latin1")
        off += o["payload_len"]
    raise DecodeError("op not found")


def decode_image(sess, errs):
    """The header reads of one image (a `hdr-*` session): the decoded outputs of the reader form, the writer form checked against
    them, and everything the open decides on. Returns (header, calls) or (None, None) with the reasons in errs."""
    calls, writer = {}, {}
    for ex in sess["exchanges"]:
        lab = ex.get("label")
        if lab not in ("get_id", "header8-reader", "header8-writer", "stripe-unit-count", "op-features", "lock-get-info"):
            continue
        rp = ex["reply"]
        if rp is None or rp["summary"]["result"] != 0 or any(r != 0 for r in rp["summary"]["rvals"]):
            errs.append("%s did not succeed" % lab)
            return None, None
        data = bytes.fromhex(rp["data"]["hex"])
        off = 0
        for op, po in zip(ex["request"]["summary"]["ops"], rp["summary"]["ops"]):
            out = data[off:off + po["out_len"]]
            off += po["out_len"]
            meth = op_method(ex, op)
            try:
                dec = dec_call_out(meth, out)
            except DecodeError as e:
                errs.append("%s %s: %s" % (lab, meth, e))
                return None, None
            if lab == "header8-writer":
                writer[meth] = dec
            else:
                calls[meth] = dec
    need = ("get_size", "get_object_prefix", "get_features", "get_flags", "get_snapcontext", "get_data_pool", "parent_get",
            "parent_overlap_get", "get_id", "get_info")
    if any(k not in calls for k in need) or "get_features" not in writer:
        errs.append("header calls missing")
        return None, None
    for k, v in writer.items():
        if k != "get_features" and calls.get(k) != v:
            errs.append("the writer form of %s differs from the reader form" % k)
    if writer["get_features"]["features"] != calls["get_features"]["features"]:
        errs.append("the writer form reports other features")
    calls["writer_incompatible"] = writer["get_features"]["incompatible"]
    return header_from_calls(calls), calls


def image_expect(h):
    return {k: [v[0], v[1]] for k, v in (("reader", refusal(h, False)), ("writer", refusal(h, True)))}


def image_header_json(h, calls):
    return dict(order=h["order"], size=h["size"], prefix=h["prefix"], features=h["features"], flags=h["flags"],
                snap_seq=ulong(h["snapc"]["seq"]), snaps=[ulong(s) for s in h["snapc"]["snaps"]], data_pool=h["data_pool"],
                has_parent=h["has_parent"], has_overlap=h["has_overlap"], overlap=h["overlap"], op_features=h["op_features"],
                stripe_unit=h["stripe_unit"], stripe_count=h["stripe_count"], lockers=len(calls["get_info"]["lockers"]),
                lock_type=calls["get_info"]["type"], lock_tag=calls["get_info"]["tag"], id=calls["get_id"]["id"],
                incompatible_reader=calls["get_features"]["incompatible"], incompatible_writer=calls["writer_incompatible"])


def rev32(x):
    return int("{:032b}".format(x)[::-1], 2)


def hkey(h):
    """The total order of osd-ops.md 2.10: max flag, pool, bit-reversed hash, namespace, effective key, name, snapshot id."""
    return (h["max"], h["pool"], rev32(h["hash"]), h["nspace"], h["key"] or h["oid"], h["oid"], int(h["snap"], 16))


def request_pos(rs):
    return dict(key="", oid=rs["oid"], snap=ulong(NOSNAP), hash=rs["hash"], max=0, nspace=rs["nspace"], pool=rs["pool"])


def covers(bsum, pos):
    lo, hi, p = hkey(bsum["begin"]), hkey(bsum["end"]), hkey(pos)
    return p == lo if lo == hi else lo <= p < hi


class Checker:
    def __init__(self, d):
        self.d = d
        self.bad = []
        self.stats = dict(messages=0, exchanges=0, sessions=0, backoffs=0)
        self.orders = set()
        self.cover = {}

    def err(self, s):
        self.bad.append(s)

    def need(self, what, cond):
        if cond:
            self.cover[what] = True
        else:
            self.cover.setdefault(what, False)

    # -- one message
    def check_msg(self, where, m, want_type):
        self.stats["messages"] += 1
        try:
            hdr, front = bytes.fromhex(m["header2_hex"]), bytes.fromhex(m["front_hex"])
            h = dec_header2(hdr)
            if h["type"] != want_type or h["type"] != m["type"] or h["tid"] != m["tid"] or h["seq"] != m["seq"] or \
               h["version"] != m["version"] or h["compat_version"] != m["compat_version"] or h["priority"] != m["priority"]:
                self.err("%s: header fields differ from the recorded ones" % where)
            data = m["data"]
            if m["segment_lengths"] != [41, len(front), 0, data["length"]]:
                self.err("%s: segment lengths" % where)
            if "hex" in data:
                raw = bytes.fromhex(data["hex"])
                if len(raw) != data["length"] or hashlib.sha256(raw).hexdigest() != data["sha256"]:
                    self.err("%s: data hex does not match its length / hash" % where)
            elif "head_hex" not in data or data["length"] <= DATA_HEX_MAX:
                self.err("%s: data neither in full nor as a head" % where)
            if h["flags"] not in (3, 1) and h["flags"] != 0:
                self.err("%s: header flags %d" % (where, h["flags"]))
            msg = dict(h=h, hdr=hdr, front=front, data=b"")
            if summarize(msg) != m["summary"]:
                self.err("%s: summary differs from the decoded front" % where)
        except (DecodeError, ValueError, KeyError, struct.error) as e:
            self.err("%s: %s" % (where, e))

    # -- one request / reply pair
    def check_pair(self, where, req, rep):
        rs, ps = req["summary"], rep["summary"]
        self.stats["exchanges"] += 1
        if req["tid"] != rep["tid"]:
            self.err("%s: tids differ" % where)
        if req["priority"] != 63 or rs["client_inc"] != 0 or rs["reqid"] != [0, 0, 0, 0]:
            self.err("%s: priority / client_inc / reqid of the request" % where)
        if (req["version"], req["compat_version"], rep["version"], rep["compat_version"]) not in ((9, 3, 8, 2),):
            self.err("%s: message versions %s" % (where, (req["version"], req["compat_version"], rep["version"], rep["compat_version"])))
        if rs["oid"] != ps["oid"] or rs["pool"] != ps["pool"] or rs["seed"] != ps["seed"] or rs["oloc_key"] != "":
            self.err("%s: reply names another object / PG" % where)
        if ps["retry_attempt"] != rs["retry_attempt"]:
            self.err("%s: retry attempt not echoed" % where)
        if rs["flags"] & 4 == 0 or rs["flags"] & 0x400000 == 0 or rs["flags"] & 0x8000000 == 0 or (rs["flags"] & 0x30) not in (0x10, 0x20):
            self.err("%s: request flags %#x" % (where, rs["flags"]))
        if bool(rs["flags"] & 8) != bool(rs["retry_attempt"]):
            self.err("%s: RETRY flag does not follow retry_attempt" % where)
        mutating = any(o["code"] in MUTATING for o in rs["ops"])
        if mutating and (rs["flags"] & 0x20 == 0 or rs["snapid"] != ulong(NOSNAP)):
            self.err("%s: a message with a mutating op must carry WRITE and snapid NOSNAP" % where)
        if (rs["mtime"] != [0, 0]) != bool(rs["flags"] & 0x20):
            self.err("%s: mtime is set exactly for write messages" % where)
        want_in = sum(o["payload_len"] for o in rs["ops"])
        if want_in != req["data"]["length"]:
            self.err("%s: request data %d, ops say %d" % (where, req["data"]["length"], want_in))
        for o in rs["ops"]:
            if o["name"] in ("WRITE", "WRITEFULL") and o["len"] != o["payload_len"]:
                self.err("%s: WRITE length differs from its payload" % where)
            if o["name"] == "CALL" and o["payload_len"] != o["class_len"] + o["method_len"] + o["indata_len"]:
                self.err("%s: CALL lengths" % where)
        # the reply: one echoed record per request op, unless the message failed before any op ran
        n_out = sum(o["out_len"] for o in ps["ops"])
        if n_out != rep["data"]["length"]:
            self.err("%s: reply data %d, ops say %d" % (where, rep["data"]["length"], n_out))
        if len(ps["ops"]) != len(rs["ops"]):
            self.err("%s: %d ops sent, %d echoed" % (where, len(rs["ops"]), len(ps["ops"])))
        else:
            for a, b in zip(rs["ops"], ps["ops"]):
                if a["code"] != b["code"] and not (a["name"] == "ZERO" and b["name"] == "TRUNCATE"):
                    self.err("%s: op %s echoed as %s" % (where, a["name"], b["name"]))
        if ps["result"] < 0 and rep["data"]["length"] and ps["result"] != 0 and not all(r == 0 for r in ps["rvals"][:0]):
            pass
        # a reply carries ONDISK; one that executed also carries ACK (osd-ops.md 2.9: the pre-execution errors lack it). Captured, beyond
        # the note: the answer to a RESENT WRITE (the OSD found the tid in its PG log and returned the stored result) has ONDISK and
        # no ACK, so a client must not wait for the ACK bit.
        resent_write = rs["retry_attempt"] > 0 and mutating
        if ps["flags"] & 4 == 0 or (ps["result"] >= 0 and ps["flags"] & 1 == 0 and not resent_write):
            self.err("%s: reply flags %#x" % (where, ps["flags"]))
        # what a reply may hold: nothing for a failed message, never more than was asked for a READ, 16 bytes for a STAT, nothing for a write
        for a, b in zip(rs["ops"], ps["ops"]):
            if ps["result"] < 0 and all(r == 0 for r in ps["rvals"]) and b["out_len"]:
                self.err("%s: a message that failed as a whole has output" % where)
            if a["name"] == "READ" and a["len"] and b["out_len"] > a["len"]:
                self.err("%s: a READ of %d bytes returned %d" % (where, a["len"], b["out_len"]))
            if a["name"] == "STAT" and ps["result"] >= 0 and b["out_len"] != 16:
                self.err("%s: STAT output of %d bytes" % (where, b["out_len"]))
            if a["name"] in ("WRITE", "WRITEFULL", "ZERO", "TRUNCATE", "DELETE", "SETALLOCHINT") and b["out_len"]:
                self.err("%s: %s has output" % (where, a["name"]))
        if ps["epoch"] == 0 or ps["replay_version"] is None:
            self.err("%s: reply epoch" % where)
        # coverage
        for o in rs["ops"]:
            self.cover[o["name"]] = True
        if ps["result"] == -2 and not any(o["rval"] for o in [dict(rval=r) for r in ps["rvals"]]):
            self.cover["ENOENT whole message"] = True
        if rs["snaps"] and mutating:
            self.cover["write with snapshot context"] = True
        if rs["snapid"] != ulong(NOSNAP):
            self.cover["read of a snapshot"] = True
        if len(rs["ops"]) == 8 and all(o["name"] == "CALL" for o in rs["ops"]):
            self.cover["eight-call header read"] = True
        if any(o["name"] == "ZERO" for o in rs["ops"]) and any(o["name"] == "TRUNCATE" for o in ps["ops"]) and \
           any(a["name"] == "ZERO" and b["name"] == "TRUNCATE" for a, b in zip(rs["ops"], ps["ops"])):
            self.cover["ZERO rewritten to TRUNCATE"] = True

    # -- outputs of one reply against what the library reported
    def check_probe(self, where, ex):
        pr, rs, ps = ex.get("probe"), ex["request"]["summary"], ex["reply"]["summary"]
        if pr is None:
            return
        data = bytes.fromhex(ex["reply"]["data"].get("hex", "")) if "hex" in ex["reply"]["data"] else None
        if pr["kind"] == "calls":
            if len(pr["calls"]) != len(rs["ops"]):
                self.err("%s: the probe made %d calls, the wire has %d ops" % (where, len(pr["calls"]), len(rs["ops"])))
                return
            if ps["result"] != pr["rc"] and not (ps["result"] == 0 and pr["rc"] >= 0):
                self.err("%s: result %d on the wire, %d reported" % (where, ps["result"], pr["rc"]))
            if data is None:
                self.err("%s: the reply data is not stored in full" % where)
                return
            off = 0
            for i, (c, op, po) in enumerate(zip(pr["calls"], rs["ops"], ps["ops"])):
                out = data[off:off + po["out_len"]]
                off += po["out_len"]
                if out.hex() != c["out"] or ps["rvals"][i] != c["rval"]:
                    self.err("%s: call %d (%s) output or rval differs from the library's" % (where, i, c["method"]))
        else:
            if pr["kind"] in ("read", "sparse") and pr.get("data_sha256") is not None:
                if ex["reply"]["data"]["length"] != pr["data_len"] and pr["kind"] == "read":
                    self.err("%s: read returned %d bytes on the wire, %d reported" % (where, ex["reply"]["data"]["length"], pr["data_len"]))
                if pr["kind"] == "read" and ex["reply"]["data"]["sha256"] != pr["data_sha256"]:
                    self.err("%s: read data differs from the library's" % where)
            if ps["result"] != pr["rc"] and not (ps["result"] >= 0 and pr["rc"] >= 0):
                self.err("%s: result %d on the wire, %d reported" % (where, ps["result"], pr["rc"]))
            if pr["kind"] == "stat" and "hex" in ex["reply"]["data"]:
                d = bytes.fromhex(ex["reply"]["data"]["hex"])
                if len(d) == 16:
                    size, sec = struct.unpack("<QI", d[:12])
                    if size != pr["size"] or sec != pr["mtime"]:
                        self.err("%s: stat differs from the library's" % where)
            if pr["kind"] == "sparse" and "hex" in ex["reply"]["data"]:
                try:
                    r = Rd(bytes.fromhex(ex["reply"]["data"]["hex"]))
                    n = r.u32()
                    ext = [[r.u64(), r.u64()] for _ in range(n)]
                    dl = r.u32()
                    if r.left() != dl or sum(e[1] for e in ext) != dl or ext != pr["extents"]:
                        self.err("%s: sparse-read output does not decode to the library's extents" % where)
                    if n >= 2:
                        self.cover["sparse read with a hole"] = True
                    prev = 0
                    for e in ext:
                        if e[0] < prev:
                            self.err("%s: sparse extents not ascending" % where)
                        prev = e[0] + e[1]
                except DecodeError as e:
                    self.err("%s: sparse output: %s" % (where, e))
            if pr["kind"] == "read":
                if ps["result"] >= 0 and pr["data_len"] == 0:
                    self.cover["read past the end"] = True
                if ps["result"] >= 0 and 0 < pr["data_len"] < rs["ops"][0]["len"]:
                    self.cover["short read"] = True

    # -- one session
    def check_session(self, name):
        p = os.path.join(self.d, "sessions", name + ".json")
        s = json.load(open(p))
        self.stats["sessions"] += 1
        if s["session"] != name or s["mode"] != "crc":
            self.err("%s: name / mode" % name)
        if s.get("tcpdump_dropped", 0) != 0:
            self.err("%s: tcpdump dropped packets" % name)
        tids = set()
        for ex in s["exchanges"]:
            where = "%s #%d" % (name, ex["n"])
            self.check_msg(where + " request", ex["request"], 42)
            for k, rq in enumerate(ex.get("resends", [])):
                self.check_msg(where + " resend %d" % (k + 1), rq, 42)
                rs, r0 = rq["summary"], ex["request"]["summary"]
                # every transmission is on the wire in the capture: the attempts are exactly 0, 1, 2 ... (a gap would be a transmission the set lost)
                if rq["tid"] != ex["request"]["tid"] or rs["retry_attempt"] != r0["retry_attempt"] + k + 1 or not rs["flags"] & 8:
                    self.err("%s: a resend must keep the tid and raise retry_attempt by one with RETRY set" % where)
                for key in ("pool", "oid", "hash", "ops", "snaps", "snap_seq", "snapid"):
                    if rs[key] != r0[key]:
                        self.err("%s: a resend changes %s" % (where, key))
                self.cover["resend with the same tid and retry_attempt + 1"] = True
            # one client process numbers its operations once: a transaction id is used by one exchange (`rados get` makes one client per
            # object, so there the id is only unique per connection)
            tid_key = (ex["conn"], ex["request"]["tid"]) if name.startswith("objects-") else ex["request"]["tid"]
            if tid_key in tids:
                self.err("%s: transaction id %d is used by two exchanges of one connection" % (where, ex["request"]["tid"]))
            tids.add(tid_key)
            if ex["reply"] is None:
                # a request the OSD never answered is not a vector of this set: it would be replayed against nothing
                self.err("%s: no reply" % where)
                continue
            self.check_msg(where + " reply", ex["reply"], 43)
            self.check_pair(where, (ex.get("resends") or [ex["request"]])[-1], ex["reply"])
            self.check_probe(where, ex)
        for b in s.get("backoffs", []):
            self.stats["backoffs"] += 1
            self.check_msg("%s backoff %s" % (name, b["t_ms"]), b, 61)
        if s.get("backoffs"):
            self.check_backoffs(name, s)
        return s

    def check_backoffs(self, name, s):
        blocks = {}
        allblocks = []
        for b in s["backoffs"]:
            sm = b["summary"]
            if b["version"] != 1 or b["compat_version"] != 1 or b["priority"] != 63 and b["dir"] == "c2s":
                self.err("%s: backoff header version / priority" % name)
            key = (b["conn"], sm["id"])
            if sm["op"] == 1:
                if b["dir"] != "s2c":
                    self.err("%s: BLOCK must come from the OSD" % name)
                blocks[key] = (b, False)
                allblocks.append(sm)
                if hkey(sm["begin"]) > hkey(sm["end"]):
                    self.err("%s: a BLOCK whose begin is above its end" % name)
                self.cover["BLOCK"] = True
                if sm["begin"] == sm["end"]:
                    self.cover["BLOCK of one object"] = True
                else:
                    self.cover["BLOCK of a PG range"] = True
            elif sm["op"] == 2:
                self.cover["ACK_BLOCK"] = True
                if b["dir"] != "c2s" or key not in blocks:
                    self.err("%s: ACK_BLOCK without its BLOCK" % name)
                    continue
                blk = blocks[key][0]["summary"]
                for f in ("pool", "seed", "epoch", "begin", "end", "id"):
                    if blk[f] != sm[f]:
                        self.err("%s: ACK_BLOCK differs from its BLOCK in %s" % (name, f))
                blocks[key] = (blocks[key][0], True)
            elif sm["op"] == 3:
                self.cover["UNBLOCK"] = True
                if b["dir"] != "s2c" or key not in blocks:
                    self.err("%s: UNBLOCK for a backoff that was never blocked" % name)
            else:
                self.err("%s: backoff op %d" % (name, sm["op"]))
            for side in ("begin", "end"):
                p = sm[side]
                if p["max"] == 1 and side == "end":
                    # the end of the last PG of a pool is the "maximum" object: max flag, pool = the smallest i64, hash 0, no names
                    if p["pool"] != -(1 << 63) or p["hash"] != 0 or p["oid"] or p["key"] or p["nspace"] or p["snap"] != "0x0":
                        self.err("%s: backoff end position (max object)" % name)
                    self.cover["BLOCK up to the maximum object"] = True
                elif p["pool"] != sm["pool"] or p["snap"] not in (ulong(NOSNAP), "0x0", ulong(0xFFFFFFFFFFFFFFFF)):
                    self.err("%s: backoff %s position" % (name, side))
        # a request that was held (it was sent again after the unblock) lies inside the BLOCK of its PG; one object is not its neighbour
        for ex in s["exchanges"]:
            if not ex.get("resends"):
                continue
            rs = ex["request"]["summary"]
            pos = request_pos(rs)
            hit = [b for b in allblocks if b["pool"] == rs["pool"] and b["seed"] == rs["seed"] and covers(b, pos)]
            if not hit:
                self.err("%s #%d: a held request is in no BLOCK of its PG" % (name, ex["n"]))
            for b in allblocks:
                if b["pool"] == rs["pool"] and b["seed"] == rs["seed"] and hkey(b["begin"]) == hkey(b["end"]):
                    if covers(b, dict(pos, oid=rs["oid"] + "X")):
                        self.err("%s: a one-object BLOCK covers another object" % name)
                    self.cover["held request inside a one-object BLOCK"] = True
        for b in allblocks:
            if hkey(b["begin"]) != hkey(b["end"]):
                self.cover["held request inside a PG-range BLOCK"] = self.cover.get("held request inside a PG-range BLOCK") or any(
                    ex.get("resends") and covers(b, request_pos(ex["request"]["summary"])) for ex in s["exchanges"])

    # -- images
    def check_images(self):
        doc = json.load(open(os.path.join(self.d, "images.json")))
        for im in doc["images"]:
            nm = im["name"]
            try:
                s = json.load(open(os.path.join(self.d, "sessions", "hdr-" + nm + ".json")))
            except (OSError, ValueError):
                self.err("%s: no header session" % nm)
                continue
            errs = []
            h, calls = decode_image(s, errs)
            self.bad += ["%s: %s" % (nm, e) for e in errs]
            if h is None:
                continue
            self.check_gt(nm, h, calls, im["gt"], im)
            exp = image_expect(h)
            if im.get("expect") != exp:
                self.err("%s: expected refusals %s differ from the stored %s" % (nm, exp, im.get("expect")))
            if im.get("header") != image_header_json(h, calls):
                self.err("%s: the stored header values differ from the decoded replies" % nm)
            if im.get("lock") == "foreign" and not calls["get_info"]["lockers"]:
                self.err("%s: the foreign lock is not there" % nm)
            self.cover["header of %#x" % h["features"]] = True
            if h["has_parent"]:
                self.cover["header of a clone"] = True
            if h["features"] & 2:
                self.cover["header of a striped image"] = True
            if h["features"] & 0x80:
                self.cover["header of a data-pool image"] = True
            if h["snapc"]["snaps"]:
                self.cover["header with snapshots"] = True
            if calls["get_info"]["lockers"]:
                self.cover["header with a foreign lock"] = True
            if exp["writer"][0] != "OK":
                self.cover["refusal " + exp["writer"][0]] = True
            self.orders.add(h["order"])

    def check_gt(self, nm, h, calls, gt, im):
        if calls["get_id"]["id"] != gt["id"] or h["size"] != gt["size"] or h["order"] != gt["order"]:
            self.err("%s: id / size / order differ from `rbd info`" % nm)
        osz = 1 << h["order"]
        if gt.get("objects") != (h["size"] + osz - 1) // osz or gt.get("object_size") != osz:
            self.err("%s: object count / object size differ from `rbd info`" % nm)
        if h["prefix"] != gt["block_name_prefix"]:
            self.err("%s: object prefix differs from `rbd info`" % nm)
        gf = gt["features_mask"] if "features_mask" in gt else None
        if gf is not None and gf != h["features"]:
            self.err("%s: features %#x differ from `rbd info` %#x" % (nm, h["features"], gf))
        if bool(gt.get("parent")) != bool(h["has_parent"]):
            self.err("%s: parent differs from `rbd info`" % nm)
        if gt.get("stripe_count", 1) != (h["stripe_count"] if h["features"] & 2 else 1) and h["features"] & 2:
            self.err("%s: striping differs from `rbd info`" % nm)
        gids = sorted((s["id"] for s in gt.get("snaps", [])), reverse=True)
        if [x for x in h["snapc"]["snaps"]] != gids or h["snapc"]["seq"] < (gids[0] if gids else 0):
            self.err("%s: snapshot context %s differs from the snapshots %s" % (nm, h["snapc"], gids))
        if (h["data_pool"] >= 0) != bool(h["features"] & 0x80):
            self.err("%s: data pool id and feature bit disagree" % nm)
        if h["features"] & 0x80 and gt.get("data_pool_id") is not None and gt["data_pool_id"] != h["data_pool"]:
            self.err("%s: data pool id differs from the pool list" % nm)
        # the server's `incompatible` is logged, never trusted: for the reader it is features & the read-incompatible mask
        ro = calls["get_features"]["incompatible"]
        if ro & ~h["features"]:
            self.err("%s: incompatible bits that are not features" % nm)

    # -- objects
    def check_objects(self):
        doc = json.load(open(os.path.join(self.d, "objects.json")))
        pats = {p["name"]: p for p in doc["images"]}
        by_img = {}
        for o in doc["objects"]:
            blob = open(os.path.join(self.d, o["file"]), "rb").read()
            if len(blob) != o["size"] or hashlib.sha256(blob).hexdigest() != o["sha256"]:
                self.err("%s: size / hash" % o["file"])
            by_img.setdefault(o["image"], {})[o["objno"]] = blob
            if o["image"] not in pats:
                self.err("%s: unknown image" % o["file"])
                continue
            e = []
            check_object(pats[o["image"]], o["objno"], blob, e)
            self.bad += e
        for nm, p in pats.items():
            osz = 1 << p["order"]
            want = set()
            for off, ln, mul, add in p["segments"]:
                for o in range(off // osz, (off + ln - 1) // osz + 1):
                    want.add(o)
            got = set(by_img.get(nm, {}))
            if want != got:
                self.err("%s: objects %s exist, the recipe says %s" % (nm, sorted(got), sorted(want)))
            if p["size"] % osz and False:
                pass
            if set(range((p["size"] + osz - 1) // osz)) - got:
                self.cover["data objects with holes"] = True
            self.cover["pattern image of order %d" % p["order"]] = True
        return doc


def check_dir(d):
    """All the checks on a vector tree. Returns (problems, one summary line)."""
    c = Checker(d)
    try:
        idx = json.load(open(os.path.join(d, "INDEX.json")))
    except (OSError, ValueError) as e:
        return ["no usable INDEX.json: %s" % e], "osdc vectors: unusable"
    files = idx["files"]
    on_disk, total = {}, 0
    for root, _dirs, names in os.walk(d, followlinks=False):
        for nm in names:
            p = os.path.join(root, nm)
            rel = os.path.relpath(p, d)
            if os.path.islink(p):
                c.err("symbolic link %s" % rel)
                continue
            if rel in ("INDEX.json", "README.md"):
                continue
            on_disk[rel] = p
    for rel in sorted(set(on_disk) - set(files)):
        c.err("stray file %s" % rel)
    for rel, meta in sorted(files.items()):
        p = on_disk.get(rel)
        if p is None:
            c.err("missing file %s" % rel)
            continue
        b = open(p, "rb").read()
        total += len(b)
        if len(b) != meta["bytes"] or hashlib.sha256(b).hexdigest() != meta["sha256"]:
            c.err("%s differs from INDEX.json" % rel)
        if rel.endswith((".json", ".txt", ".md", ".tsv")):
            txt = b.decode("utf-8", "replace")
            m = (KEY_RE_LOG if rel == "revert-proof.txt" else KEY_RE).search(txt)
            if m:
                c.err("%s: key-like text %r" % (rel, m.group(0)[:20]))
            m = PATH_RE.search(txt)
            if m:
                c.err("%s: a directory of the lab or of a developer machine (%r)" % (rel, txt[m.start():m.start() + 24]))
            for m in IP_RE.finditer(txt):
                q = tuple(int(x) for x in m.groups())
                if all(x < 256 for x in q) and q[:3] not in ((10, 77, 0), (192, 0, 2)) and not (q[0] == 127):
                    c.err("%s: address %s outside 10.77.0.x / 192.0.2.x" % (rel, m.group(0)))
                    break
    if total > BUDGET:
        c.err("total size %d above the budget of %d" % (total, BUDGET))
    if not isinstance(idx.get("user"), dict) or idx["user"].get("deleted") is not True or not idx["user"].get("verified_gone"):
        c.err("INDEX.json does not record the removal of the throwaway user")
    for need in ("sessions", "images", "files"):
        if need not in idx and need != "images":
            c.err("INDEX.json lacks %s" % need)
    for name in idx.get("sessions", []):
        if "sessions/%s.json" % name not in files:
            c.err("session %s is not in the file list" % name)
            continue
        c.check_session(name)
    try:
        c.check_images()
        c.check_objects()
    except (OSError, ValueError, KeyError) as e:
        c.err("images / objects: %r" % e)
    required = ["READ", "WRITE", "ZERO", "TRUNCATE", "DELETE", "STAT", "SPARSE_READ", "CALL", "SETALLOCHINT", "ENOENT whole message",
                "short read", "read past the end", "write with snapshot context", "read of a snapshot", "eight-call header read",
                "ZERO rewritten to TRUNCATE", "sparse read with a hole", "BLOCK", "ACK_BLOCK", "UNBLOCK",
                "resend with the same tid and retry_attempt + 1", "BLOCK of one object", "BLOCK of a PG range",
                "held request inside a one-object BLOCK", "held request inside a PG-range BLOCK", "header of a clone", "header of a striped image",
                "header of a data-pool image", "header with snapshots", "header with a foreign lock", "refusal RBD_E_FEATURES",
                "refusal RBD_E_PARENT", "refusal RBD_E_STRIPING", "data objects with holes"]
    for r in required:
        if not c.cover.get(r):
            c.err("coverage: nothing in the set shows `%s`" % r)
    for w in sorted(REQUIRED_FEATURES):
        if not c.cover.get("header of %#x" % w):
            c.err("coverage: no image with the feature word %#x" % w)
    orders = c.orders
    if len(orders) < 4 or min(orders) > 13 or max(orders) < 16:
        c.err("coverage: image orders %s (want at least four, from 12 or 13 up to 16)" % sorted(orders))
    st = c.stats
    line = "osdc vectors: %d files, %d bytes, %d sessions, %d exchanges, %d messages decoded, %d backoff messages: %s" % (
        len(files), total, st["sessions"], st["exchanges"], st["messages"], st["backoffs"], "OK" if not c.bad else "%d PROBLEMS" % len(c.bad))
    return c.bad, line


def cmd_check(a):
    d = os.path.abspath(a.dir)
    if not os.path.exists(os.path.join(d, "INDEX.json")):
        print("SKIP: %s has no INDEX.json (the lab captures of module vectors-c are not in this tree)" % d)
        return 77
    bad, line = check_dir(d)
    print(line)
    for b in bad[:25]:
        print("  " + b)
    return 0 if not bad else 1


# ---- the checker's own error paths: damaged copies of the vectors, each of which `check` must reject -------------------------------

def _reindex(d):
    idx = json.load(open(os.path.join(d, "INDEX.json")))
    idx["files"] = {}
    for root, _dn, names in os.walk(d):
        for nm in names:
            rel = os.path.relpath(os.path.join(root, nm), d)
            if rel in ("INDEX.json", "README.md"):
                continue
            b = open(os.path.join(root, nm), "rb").read()
            idx["files"][rel] = dict(bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
    jdump(os.path.join(d, "INDEX.json"), idx)


def _edit(d, rel, fn):
    p = os.path.join(d, rel)
    doc = json.load(open(p))
    fn(doc)
    with open(p, "w") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")


def _first(doc, label):
    return next(e for e in doc["exchanges"] if e.get("label") == label)


def cmd_selftest(a):
    import shutil
    import tempfile
    src = os.path.abspath(a.dir)
    if not os.path.exists(os.path.join(src, "INDEX.json")):
        print("SKIP: no vectors")
        return 77
    bad, _line = check_dir(src)
    if bad:
        print("the vectors themselves fail: %s" % bad[:3])
        return 1
    hdr = "sessions/hdr-wrtest-osdc-f3d.json"
    snap = "sessions/hdr-wrtest-osdc-snap.json"

    def flip_front(doc):
        e = doc["exchanges"][1]["request"]
        e["front_hex"] = e["front_hex"][:40] + ("0" if e["front_hex"][40] != "0" else "1") + e["front_hex"][41:]

    def change_result(doc):
        doc["exchanges"][1]["reply"]["summary"]["result"] = -5

    def change_output(doc):
        r = doc["exchanges"][1]["reply"]["data"]
        r["hex"] = ("ff" if r["hex"][:2] != "ff" else "00") + r["hex"][2:]
        r["sha256"] = hashlib.sha256(bytes.fromhex(r["hex"])).hexdigest()

    def swap_tid(doc):
        doc["exchanges"][1]["reply"]["tid"] += 1

    def drop_block(doc):
        doc["backoffs"] = [b for b in doc["backoffs"] if b["summary"]["op"] != 1][:] or doc["backoffs"]

    def ack_other_id(doc):
        for b in doc["backoffs"]:
            if b["summary"]["op"] == 2:
                b["summary"]["id"] += 7
                return

    def expect_ok(doc):
        for im in doc["images"]:
            if im["name"].endswith("f3d"):
                im["expect"]["writer"] = ["OK", {}]

    def gt_features(doc):
        doc["images"][0]["gt"]["features_mask"] = 3

    def no_user(doc):
        doc["user"]["deleted"] = False

    def keylike(doc):
        doc["about"] = "key = AQBjP6ZmvVbxHBAA0NiCdp2g0OD6TKMVXrkSdQ=="

    def foreign_ip(doc):
        doc["about"] = "client at 203.0.113.9"

    def lab_path(doc):
        doc["commands"][0] += " /home/someone/w/cap/out"

    def no_reply(doc):
        doc["exchanges"][2]["reply"] = None

    def dup_tid(doc):
        # the request of exchange 4 carries the tid of exchange 3 everywhere (header words, summary, reply), so only the rule
        # "a transaction id belongs to one exchange" can object
        want = doc["exchanges"][2]["request"]["tid"]
        e = doc["exchanges"][3]
        for m in (e["request"], e["reply"]):
            h = bytearray.fromhex(m["header2_hex"])
            h[8:16] = struct.pack("<Q", want)
            m["header2_hex"] = hx(h)
            m["tid"] = want

    def reply_flags_zero(doc):
        # the reply flags rewritten in the front, the summary and the segment bookkeeping alike: only the flags rule can object
        m = doc["exchanges"][2]["reply"]
        f = bytearray.fromhex(m["front_hex"])
        at = 4 + struct.unpack_from("<I", f, 0)[0] + 1 + 8 + 4 + 4
        f[at:at + 8] = struct.pack("<q", 0)
        m["front_hex"] = hx(f)
        m["summary"]["flags"] = 0

    def bad_objects(doc):
        doc["images"][0]["gt"]["objects"] += 1

    def mutate_object(d):
        p = os.path.join(d, "objects", "pat14")
        fn = sorted(os.listdir(p))[1]
        b = bytearray(open(os.path.join(p, fn), "rb").read())
        b[5] ^= 0x55
        open(os.path.join(p, fn), "wb").write(bytes(b))

    def drop_session(d):
        os.remove(os.path.join(d, "sessions", "io-snap.json"))
        _edit(d, "INDEX.json", lambda x: x["sessions"].remove("io-snap"))

    muts = [
        ("front byte flipped (hash only)", False, lambda d: _edit(d, hdr, flip_front)),
        ("front byte flipped", True, lambda d: _edit(d, hdr, flip_front)),
        ("summary result changed", True, lambda d: _edit(d, hdr, change_result)),
        ("reply output changed", True, lambda d: _edit(d, hdr, change_output)),
        ("reply tid changed", True, lambda d: _edit(d, hdr, swap_tid)),
        ("BLOCK removed", True, lambda d: _edit(d, "sessions/backoff-restart.json", drop_block)),
        ("ACK_BLOCK with another id", True, lambda d: _edit(d, "sessions/backoff-restart.json", ack_other_id)),
        ("expected verdict changed", True, lambda d: _edit(d, "images.json", expect_ok)),
        ("ground truth changed", True, lambda d: _edit(d, "images.json", gt_features)),
        ("snapshot session changed", True, lambda d: _edit(d, snap, change_output)),
        ("user removal not recorded", True, lambda d: _edit(d, "INDEX.json", no_user)),
        ("key-like text", True, lambda d: _edit(d, "images.json", keylike)),
        ("foreign address", True, lambda d: _edit(d, "images.json", foreign_ip)),
        ("a lab directory in a command", True, lambda d: _edit(d, "sessions/objects-pat12.json", lab_path), "directory"),
        ("an exchange without a reply", True, lambda d: _edit(d, "sessions/io-plain.json", no_reply), "no reply"),
        ("two exchanges with one tid", True, lambda d: _edit(d, "sessions/io-plain.json", dup_tid), "transaction id"),
        ("object count of `rbd info` changed", True, lambda d: _edit(d, "images.json", bad_objects), "object count"),
        ("reply flags without ONDISK", True, lambda d: _edit(d, "sessions/io-plain.json", reply_flags_zero), "reply flags"),
        ("data object byte changed", True, mutate_object),
        ("a session removed (coverage)", True, drop_session),
        ("stray file", False, lambda d: open(os.path.join(d, "stray.txt"), "w").write("x")),
        ("file removed", False, lambda d: os.remove(os.path.join(d, "images.json"))),
        ("symbolic link", False, lambda d: os.symlink("images.json", os.path.join(d, "link.json"))),
    ]
    fails = 0
    for mut in muts:
        name, reindex, fn = mut[:3]
        why = mut[3] if len(mut) > 3 else None     # when given, the rejection must be for this reason (a substring of a message)
        tmp = tempfile.mkdtemp(prefix="osdc-selftest-")
        try:
            d = os.path.join(tmp, "osdc")
            shutil.copytree(src, d, symlinks=True)
            fn(d)
            if reindex:
                _reindex(d)
            bad, _l = check_dir(d)
            ok = bool(bad) and (why is None or any(why in b for b in bad))
            print("  %-36s %s" % (name, "rejected: " + bad[0][:70] if ok else ("rejected for another reason: " + bad[0][:60] if bad else "NOT REJECTED")))
            fails += 0 if ok else 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    print("osdc selftest: %d damaged copies, %d accepted" % (len(muts), fails))
    return 0 if not fails else 1


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd")
    pc = sub.add_parser("check")
    pc.add_argument("--dir", default=DEFAULT_DIR)
    ps = sub.add_parser("selftest")
    ps.add_argument("--dir", default=DEFAULT_DIR)
    pe = sub.add_parser("extract")
    pe.add_argument("--work", required=True)
    pe.add_argument("--out", required=True)
    a = ap.parse_args()
    if a.cmd == "extract":
        return cmd_extract(a)
    if a.cmd == "selftest":
        return cmd_selftest(a)
    if a.cmd is None:
        a = ap.parse_args(["check"] + sys.argv[1:])
    return cmd_check(a)


if __name__ == "__main__":
    sys.exit(main())
