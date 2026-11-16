#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Independent checker for docs/spec/rbd-format2.md.

Written from the NOTES only (rbd-format2.md, plus msgr2.md and osd-ops.md for
the envelope that carries the class calls). Never from Ceph source and never
through Ceph's own decoders: every byte is decoded here. The output of the
stock tools (rbd info, rados, ceph-dencoder-free dumps from the lab) is used
only as the expected answer.

What it checks
  A. msgr2 (crc mode, revision 1): every TCP stream of every crc-mode pcap is
     reassembled and cut into frames; the banner, preamble CRC, segment CRCs,
     epilogue late_status, tag values and segment counts are verified for every
     frame. Streams that turn out to be secure mode are counted, not decoded
     (the secure-mode and cephx checks belong to their own notes).
  B. MOSDOp v9 / MOSDOpReply v8 from those frames (osd-ops.md 2.3, 2.5, 2.9),
     fully decoded: the front segment must be consumed to the last byte, op
     payload lengths must add up to the data segment.
  C. The rbd / lock class calls inside those messages and in the lab ground
     truth (gt4): the input and output bytes of every method in note 2.3 and
     2.7, the op vectors of 2.6, the omap keys of 2.4, the snapshot context of
     2.5, the feature table of 2.8, object names of 2.1 (data object names and
     the striping math of 2.9 / 2.10 against the sha256 of the real objects).
  D. Behaviour claims of the note that the captures can settle (reply framing
     of multi-op requests, read of a missing object, lock record, ...).

Secrets: nothing here reads a keyring. Captures carry no key material in the
frames used (crc mode, after authentication only MOSDOp / MOSDOpReply and
their payloads are looked at; the auth frames are only length/CRC checked).

Usage
    python3 harness/tools/rbd_check.py --captures <dir> [--vectors <dir>]
                                       [--write-vectors] [--skip-pcap] [-v]
    python3 harness/tools/rbd_check.py --vectors-only [--vectors <dir>]
Exit status 0 when every check passes, 1 otherwise.

Standard library only.
"""

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pubset  # noqa: E402

# ---------------------------------------------------------------------------
# tiny test framework
# ---------------------------------------------------------------------------


class Results:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.passed = 0
        self.failed = 0
        self.groups = collections.OrderedDict()
        self.failures = []
        self.cur = None

    def group(self, name):
        self.cur = name
        self.groups.setdefault(name, [0, 0])
        if self.verbose:
            print("== %s" % name)

    def check(self, cond, what, detail=""):
        g = self.groups.setdefault(self.cur, [0, 0])
        if cond:
            self.passed += 1
            g[0] += 1
            if self.verbose:
                print("  ok   %s" % what)
        else:
            self.failed += 1
            g[1] += 1
            self.failures.append((self.cur, what, detail))
            print("  FAIL [%s] %s %s" % (self.cur, what, detail))
        return bool(cond)

    def eq(self, got, want, what):
        ok = got == want
        return self.check(ok, what, "" if ok else "got %r want %r" % (got, want))

    def note(self, text):
        if self.verbose:
            print("  info %s" % text)

    def skip(self, what, reason):
        """A check whose input is not in this capture set: reported, counted as skipped, never a failure."""
        pubset.skip("rbd_check", "[%s] %s" % (self.cur, what), reason)

    def summary(self):
        print("")
        print("%-46s %7s %7s" % ("group", "pass", "fail"))
        for g, (p, f) in self.groups.items():
            print("%-46s %7d %7d" % (g, p, f))
        print("%-46s %7d %7d" % ("TOTAL", self.passed, self.failed))


R = None  # global Results, set in main()


# ---------------------------------------------------------------------------
# byte reader (little endian, as in the note 1.4)
# ---------------------------------------------------------------------------


class DecodeError(Exception):
    pass


class Rd:
    def __init__(self, b, off=0, end=None):
        self.b = b
        self.o = off
        self.end = len(b) if end is None else end

    def left(self):
        return self.end - self.o

    def take(self, n):
        if n < 0 or self.o + n > self.end:
            raise DecodeError("need %d bytes, %d left" % (n, self.left()))
        v = self.b[self.o:self.o + n]
        self.o += n
        return bytes(v)

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def i32(self):
        return struct.unpack("<i", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def i64(self):
        return struct.unpack("<q", self.take(8))[0]

    def boolean(self):
        v = self.u8()
        if v > 1:
            raise DecodeError("bool byte %d" % v)
        return bool(v)

    def string(self):
        n = self.u32()
        return self.take(n)

    def text(self):
        return self.string().decode("utf-8")

    def vec_u64(self):
        n = self.u32()
        return [self.u64() for _ in range(n)]

    def optional_u64(self):
        p = self.u8()
        if p > 1:
            raise DecodeError("optional marker %d" % p)
        return self.u64() if p else None

    def utime(self):
        return (self.u32(), self.u32())

    def struct_hdr(self, max_compat=None):
        """versioned struct header (note 1.4): returns (v, compat, Rd over body)"""
        v = self.u8()
        compat = self.u8()
        ln = self.u32()
        if max_compat is not None and compat > max_compat:
            raise DecodeError("struct_compat %d > %d" % (compat, max_compat))
        if ln > self.left():
            raise DecodeError("struct_len %d > %d left" % (ln, self.left()))
        body = Rd(self.b, self.o, self.o + ln)
        self.o += ln
        return v, compat, body

    def done(self, what="struct"):
        if self.left() != 0:
            raise DecodeError("%s: %d trailing bytes" % (what, self.left()))


def enc_string(s):
    if isinstance(s, str):
        s = s.encode()
    return struct.pack("<I", len(s)) + s


def enc_u64(v):
    return struct.pack("<Q", v)


CEPH_NOSNAP = 0xFFFFFFFFFFFFFFFE
CEPH_SNAPDIR = 0xFFFFFFFFFFFFFFFF
CEPH_MAXSNAP = 0xFFFFFFFFFFFFFFFD

# ---------------------------------------------------------------------------
# CRC-32C (msgr2.md 2.5): reflected 0x82F63B78, caller seed, no final xor.
# Table generated, slice-by-8 for speed.
# ---------------------------------------------------------------------------


def _mk_tables():
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t0.append(c)
    tt = [t0]
    for _ in range(1, 8):
        prev = tt[-1]
        tt.append([(prev[i] >> 8) ^ t0[prev[i] & 0xFF] for i in range(256)])
    return tt


_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = _mk_tables()
_unpackQ = struct.Struct("<Q").unpack_from


def crc32c(data, seed=0):
    c = seed
    n = len(data)
    mv = memoryview(data)
    end = n - (n % 8)
    i = 0
    while i < end:
        x = _unpackQ(mv, i)[0] ^ c
        c = (_T7[x & 255] ^ _T6[(x >> 8) & 255] ^ _T5[(x >> 16) & 255] ^
             _T4[(x >> 24) & 255] ^ _T3[(x >> 32) & 255] ^ _T2[(x >> 40) & 255] ^
             _T1[(x >> 48) & 255] ^ _T0[x >> 56])
        i += 8
    while i < n:
        c = (c >> 8) ^ _T0[(c ^ mv[i]) & 255]
        i += 1
    return c


# ---------------------------------------------------------------------------
# pcap + TCP reassembly
# ---------------------------------------------------------------------------


def read_pcap(path):
    f = open(path, "rb").read()
    m = f[:4]
    if m == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif m == b"\xa1\xb2\xc3\xd4":
        e = ">"
    else:
        raise DecodeError("%s: not a classic pcap file" % path)
    linktype = struct.unpack_from(e + "I", f, 20)[0]
    off = 24
    pk = []
    while off + 16 <= len(f):
        ts, tu, cl, ol = struct.unpack_from(e + "IIII", f, off)
        off += 16
        pk.append((ts + tu / 1e6, f[off:off + cl]))
        off += cl
    return linktype, pk


class Flow:
    """one direction of a TCP connection"""

    def __init__(self, key):
        self.key = key
        self.isn = None
        self.segs = []  # (seq, payload)
        self.syn_seq = None
        self.retrans = 0
        self.data = b""
        self.gaps = 0
        self.is_client = None  # True when this direction started with SYN (no ACK)
        self.first_gap = None

    def finish(self):
        if self.syn_seq is not None:
            isn = (self.syn_seq + 1) & 0xFFFFFFFF
        elif self.segs:
            isn = min(s for s, _ in self.segs)
        else:
            self.data = b""
            return
        buf = bytearray()
        cover = []  # (start, end)
        for seq, p in self.segs:
            rel = (seq - isn) & 0xFFFFFFFF
            if rel > 0x7FFFFFFF:
                continue
            end = rel + len(p)
            if end <= len(buf) and any(a <= rel and end <= b for a, b in cover):
                self.retrans += 1
                continue
            if len(buf) < end:
                buf.extend(b"\0" * (end - len(buf)))
            # partially covered segments count as retransmission, the bytes are identical
            if any(a < end and rel < b for a, b in cover):
                self.retrans += 1
            buf[rel:end] = p
            cover.append((rel, end))
        cover.sort()
        pos = 0
        first_gap = None
        for a, b in cover:
            if a > pos:
                self.gaps += 1
                if first_gap is None:
                    first_gap = pos
            pos = max(pos, b)
        # bytes after a hole cannot be trusted (the hole is zero filled): cut the stream there
        self.data = bytes(buf[:first_gap]) if first_gap is not None else bytes(buf)
        self.first_gap = first_gap


def tcp_flows(linktype, pk):
    flows = collections.OrderedDict()
    for ts, d in pk:
        if linktype == 1:
            if len(d) < 14 or d[12:14] != b"\x08\x00":
                continue
            ip = d[14:]
        elif linktype == 113:
            if len(d) < 16 or d[14:16] != b"\x08\x00":
                continue
            ip = d[16:]
        elif linktype == 101:
            ip = d
        else:
            raise DecodeError("unsupported pcap link type %d" % linktype)
        if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tl = struct.unpack_from(">H", ip, 2)[0]
        tcp = ip[ihl:tl]
        if len(tcp) < 20:
            continue
        sp, dp, seq, ack = struct.unpack_from(">HHII", tcp, 0)
        doff = (tcp[12] >> 4) * 4
        fl = tcp[13]
        pay = tcp[doff:]
        key = (".".join(str(x) for x in ip[12:16]), sp, ".".join(str(x) for x in ip[16:20]), dp)
        fo = flows.get(key)
        if fo is None:
            fo = flows[key] = Flow(key)
        if fl & 2:
            fo.syn_seq = seq
            fo.is_client = not (fl & 16)
        if pay:
            fo.segs.append((seq, pay))
    for fo in flows.values():
        fo.finish()
    return flows


# ---------------------------------------------------------------------------
# msgr2 frames, crc mode, revision 1 (msgr2.md 2.2 - 2.9)
# ---------------------------------------------------------------------------

TAGS = {1: "HELLO", 2: "AUTH_REQUEST", 3: "AUTH_BAD_METHOD", 4: "AUTH_REPLY_MORE",
        5: "AUTH_REQUEST_MORE", 6: "AUTH_DONE", 7: "AUTH_SIGNATURE", 8: "CLIENT_IDENT",
        9: "SERVER_IDENT", 10: "IDENT_MISSING_FEATURES", 11: "SESSION_RECONNECT",
        12: "SESSION_RESET", 13: "SESSION_RETRY", 14: "SESSION_RETRY_GLOBAL",
        15: "SESSION_RECONNECT_OK", 16: "WAIT", 17: "MESSAGE", 18: "KEEPALIVE2",
        19: "KEEPALIVE2_ACK", 20: "ACK", 21: "COMPRESSION_REQUEST", 22: "COMPRESSION_DONE"}
T_AUTH_DONE = 6
T_MESSAGE = 17
BANNER_PREFIX = b"ceph v2\n"


class Frame:
    __slots__ = ("tag", "segs", "crc_ok", "problems", "offset", "total")


class StreamInfo:
    def __init__(self):
        self.banner = None  # (supported, required)
        self.frames = []
        self.problems = []
        self.secure_from = None  # byte offset where plain parsing stopped
        self.trailing = 0  # unparsed bytes at the end (partial frame)
        self.auth_mode = None


def parse_stream(data, count_crc=True):
    """Cut one direction of one connection into frames. Stops (without a
    problem) at the first preamble whose CRC does not match when `maybe_secure`
    is possible: that is reported through secure_from."""
    si = StreamInfo()
    if len(data) < 26:
        si.problems.append("stream shorter than banner (%d)" % len(data))
        return si
    if data[:8] != BANNER_PREFIX:
        si.problems.append("banner prefix %r" % data[:8])
        return si
    plen = struct.unpack_from("<H", data, 8)[0]
    if plen != 16:
        si.problems.append("banner payload length %d" % plen)
        return si
    sup, req = struct.unpack_from("<QQ", data, 10)
    si.banner = (sup, req)
    pos = 26
    n = len(data)
    while pos < n:
        if n - pos < 32:
            si.trailing = n - pos
            break
        pre = data[pos:pos + 32]
        tag = pre[0]
        nseg = pre[1]
        pcrc = struct.unpack_from("<I", pre, 28)[0]
        if crc32c(pre[:28], 0) != pcrc:
            si.secure_from = pos
            break
        fr = Frame()
        fr.problems = []
        fr.offset = pos
        fr.tag = tag
        if tag not in TAGS:
            fr.problems.append("unknown tag %d" % tag)
        if not 1 <= nseg <= 4:
            fr.problems.append("num segments %d" % nseg)
            si.frames.append(fr)
            fr.segs = []
            break
        lens = []
        for i in range(4):
            l, al = struct.unpack_from("<IH", pre, 2 + 6 * i)
            lens.append((l, al))
        for i in range(nseg, 4):
            if lens[i] != (0, 0):
                fr.problems.append("unused segment %d not zero" % i)
        if nseg > 1 and lens[nseg - 1][0] == 0:
            fr.problems.append("last segment empty")
        flags = pre[26]
        if flags != 0 or pre[27] != 0:
            fr.problems.append("preamble flags/reserved %d/%d" % (flags, pre[27]))
        p = pos + 32
        segs = []
        L0 = lens[0][0]
        need = (L0 + 4 if L0 else 0) + sum(lens[i][0] for i in range(1, nseg)) + (13 if nseg > 1 else 0)
        if p + need > n:
            si.trailing = n - pos
            break
        seg0 = b""
        if L0:
            seg0 = data[p:p + L0]
            c = struct.unpack_from("<I", data, p + L0)[0]
            if count_crc and crc32c(seg0, 0xFFFFFFFF) != c:
                fr.problems.append("segment 0 crc mismatch")
            p += L0 + 4
        segs.append(seg0)
        for i in range(1, nseg):
            L = lens[i][0]
            segs.append(data[p:p + L])
            p += L
        if nseg > 1:
            ep = data[p:p + 13]
            p += 13
            if ep[0] & 0x0F != 0x0E:
                fr.problems.append("late_status 0x%02x" % ep[0])
            if ep[0] != 0x0E:
                fr.problems.append("late_status not exactly 0x0e (0x%02x)" % ep[0])
            for i in range(1, 4):
                c = struct.unpack_from("<I", ep, 1 + 4 * (i - 1))[0]
                if i < nseg:
                    if count_crc:
                        want = crc32c(segs[i], 0xFFFFFFFF)
                        if want != c:
                            fr.problems.append("segment %d crc mismatch" % i)
                else:
                    if c != 0:
                        fr.problems.append("unused crc slot %d not zero" % i)
        fr.segs = segs
        fr.total = 32 + need
        si.frames.append(fr)
        pos = p
        if tag == T_AUTH_DONE and len(seg0) >= 12:
            si.auth_mode = struct.unpack_from("<I", seg0, 8)[0]
    return si


# ---------------------------------------------------------------------------
# MESSAGE frame, MOSDOp v9, MOSDOpReply v8 (msgr2.md 2.9, osd-ops.md 2.2-2.9)
# ---------------------------------------------------------------------------

MSG_OSD_OP = 42
MSG_OSD_OPREPLY = 43

OPNAMES = {
    0x1201: "READ", 0x1202: "STAT", 0x1205: "SPARSE_READ", 0x2201: "WRITE",
    0x2202: "WRITEFULL", 0x2203: "TRUNCATE", 0x2204: "ZERO", 0x2205: "DELETE",
    0x220D: "CREATE", 0x2223: "SETALLOCHINT", 0x1301: "GETXATTR", 0x1401: "CALL",
    0x220F: "WATCH", 0x1211: "OMAPGETKEYS", 0x1212: "OMAPGETVALS",
    0x1214: "OMAPGETVALSBYKEYS", 0x1213: "OMAPGETHEADER", 0x1220: "CMPEXT",
    0x2226: "WRITESAME", 0x1208: "ASSERT_VER",
}
OP_CALL = 0x1401

ENOENT, EIO, EOPNOTSUPP, EINVAL, ENOEXEC = 2, 5, 95, 22, 8


def parse_msg_header(seg0):
    if len(seg0) != 41:
        raise DecodeError("ceph_msg_header2 is %d bytes, not 41" % len(seg0))
    (seq, tid, mtype, prio, ver, pre_pad, data_off, ack_seq, flags, compat, rsv) = \
        struct.unpack("<QQHHHIHQBHH", seg0)
    return dict(seq=seq, tid=tid, type=mtype, prio=prio, version=ver, pre_pad=pre_pad,
                data_off=data_off, ack_seq=ack_seq, flags=flags, compat=compat, rsv=rsv)


class Op:
    __slots__ = ("code", "flags", "union", "payload_len", "raw")

    def name(self):
        return OPNAMES.get(self.code, "0x%04x" % self.code)

    def extent(self):
        off, ln, tsz, tseq = struct.unpack_from("<QQQI", self.union, 0)
        return off, ln, tsz, tseq

    def cls(self):
        cl, ml, argc, il = struct.unpack_from("<BBBI", self.union, 0)
        return cl, ml, argc, il


def parse_op(raw):
    if len(raw) != 38:
        raise DecodeError("op record is %d bytes" % len(raw))
    o = Op()
    o.raw = bytes(raw)
    o.code, o.flags = struct.unpack_from("<HI", raw, 0)
    o.union = raw[6:34]
    o.payload_len = struct.unpack_from("<I", raw, 34)[0]
    return o


def dec_spg(r):
    v, c, body = r.struct_hdr()
    pg_ver = body.u8()
    pool = body.u64()
    seed = body.u32()
    pref = body.i32()
    shard = struct.unpack("<b", body.take(1))[0]
    body.done("spg_t")
    return dict(v=v, compat=c, pg_ver=pg_ver, pool=pool, seed=seed, pref=pref, shard=shard)


def dec_oloc(r):
    v, c, body = r.struct_hdr()
    pool = body.i64()
    pref = body.i32()
    key = body.string()
    nspace = body.string()
    h = body.i64()
    body.done("object_locator_t")
    return dict(v=v, compat=c, pool=pool, pref=pref, key=key, nspace=nspace, hash=h)


def dec_mosdop(front, data):
    """osd-ops.md 2.3, version 9"""
    r = Rd(front)
    m = {}
    m["pgid"] = dec_spg(r)
    m["hash"] = r.u32()
    m["epoch"] = r.u32()
    m["flags"] = r.u32()
    # osd_reqid_t: struct header v2/2 len 21 + entity_name_t(9) + u64 tid + i32 inc
    v, c, b = r.struct_hdr()
    nt = b.u8()
    nn = b.i64()
    tid = b.u64()
    inc = b.i32()
    b.done("osd_reqid_t")
    m["reqid"] = dict(v=v, compat=c, name_type=nt, name_num=nn, tid=tid, inc=inc)
    m["blkin"] = r.take(24)
    m["otel"] = r.take(7)
    m["client_inc"] = r.u32()
    m["mtime"] = r.utime()
    m["oloc"] = dec_oloc(r)
    m["oid"] = r.string()
    n = r.u16()
    ops = [parse_op(r.take(38)) for _ in range(n)]
    m["snapid"] = r.u64()
    m["snap_seq"] = r.u64()
    m["snaps"] = r.vec_u64()
    m["retry"] = r.i32()
    m["features"] = r.u64()
    r.done("MOSDOp front")
    m["raw_front"] = bytes(front)
    m["raw_data"] = bytes(data)
    tot = sum(o.payload_len for o in ops)
    if tot != len(data):
        raise DecodeError("sum(payload_len)=%d != data segment %d" % (tot, len(data)))
    m["ops"] = ops
    ins = []
    p = 0
    for o in ops:
        ins.append(bytes(data[p:p + o.payload_len]))
        p += o.payload_len
    m["op_in"] = ins
    return m


def dec_mosdopreply(front, data):
    """osd-ops.md 2.9, version 8"""
    r = Rd(front)
    m = {}
    m["oid"] = r.string()
    pg_ver = r.u8()
    pool = r.u64()
    seed = r.u32()
    pref = r.i32()
    m["pgid"] = dict(ver=pg_ver, pool=pool, seed=seed, pref=pref)
    m["flags"] = r.i64()
    m["result"] = r.i32()
    m["bad_replay"] = (r.u64(), r.u32())
    m["epoch"] = r.u32()
    n = r.u32()
    ops = [parse_op(r.take(38)) for _ in range(n)]
    m["retry"] = r.i32()
    m["rvals"] = [r.i32() for _ in range(n)]
    m["replay_version"] = (r.u64(), r.u32())
    m["user_version"] = r.u64()
    m["do_redirect"] = r.boolean()
    if m["do_redirect"]:
        raise DecodeError("redirect reply not handled")
    m["blkin"] = r.take(24)
    r.done("MOSDOpReply front")
    m["raw_front"] = bytes(front)
    m["raw_data"] = bytes(data)
    tot = sum(o.payload_len for o in ops)
    if tot != len(data):
        raise DecodeError("reply: sum(payload_len)=%d != data segment %d" % (tot, len(data)))
    outs = []
    p = 0
    for o in ops:
        outs.append(bytes(data[p:p + o.payload_len]))
        p += o.payload_len
    m["ops"] = ops
    m["op_out"] = outs
    return m


class Exchange:
    """one request with its (optional) reply, with decoded op vectors"""

    def __init__(self, conn, req_hdr, req, rep_hdr, rep):
        self.conn = conn
        self.req_hdr = req_hdr
        self.req = req
        self.rep_hdr = rep_hdr
        self.rep = rep


def exchanges_of(session, c_si, s_si, problems):
    """pair MOSDOp (client stream) with MOSDOpReply (server stream) by tid"""
    reqs = []
    reps = {}
    for fr in c_si.frames:
        if fr.tag != T_MESSAGE:
            continue
        h = parse_msg_header(fr.segs[0])
        if h["type"] != MSG_OSD_OP:
            continue
        front = fr.segs[1] if len(fr.segs) > 1 else b""
        mid = fr.segs[2] if len(fr.segs) > 2 else b""
        data = fr.segs[3] if len(fr.segs) > 3 else b""
        if mid:
            problems.append("MOSDOp with non-empty middle segment")
        try:
            reqs.append((h, dec_mosdop(front, data), len(fr.segs)))
        except DecodeError as e:
            problems.append("MOSDOp tid %d: %s" % (h["tid"], e))
    for fr in s_si.frames:
        if fr.tag != T_MESSAGE:
            continue
        h = parse_msg_header(fr.segs[0])
        if h["type"] != MSG_OSD_OPREPLY:
            continue
        front = fr.segs[1] if len(fr.segs) > 1 else b""
        mid = fr.segs[2] if len(fr.segs) > 2 else b""
        data = fr.segs[3] if len(fr.segs) > 3 else b""
        if mid:
            problems.append("MOSDOpReply with non-empty middle segment")
        try:
            reps[h["tid"]] = (h, dec_mosdopreply(front, data), len(fr.segs))
        except DecodeError as e:
            problems.append("MOSDOpReply tid %d: %s" % (h["tid"], e))
    out = []
    for h, m, ns in reqs:
        rp = reps.pop(h["tid"], None)
        out.append(Exchange(session, (h, ns), m, rp[0:1] + (rp[2],) if rp else None, rp[1] if rp else None))
    if reps:
        problems.append("%d replies without request" % len(reps))
    return out


# ---------------------------------------------------------------------------
# rbd / lock class payloads (rbd-format2.md 2.3, 2.5, 2.7, 2.8)
# ---------------------------------------------------------------------------

FEATURES = collections.OrderedDict([
    (0x1, "layering"), (0x2, "striping"), (0x4, "exclusive-lock"), (0x8, "object-map"),
    (0x10, "fast-diff"), (0x20, "deep-flatten"), (0x40, "journaling"), (0x80, "data-pool"),
    (0x100, "operations"), (0x200, "migrating"), (0x400, "non-primary"), (0x800, "dirty-cache")])
FEATURES_ALL = 0xFFF
# note 2.8 table, column "RO-incompat" = yes: layering, striping, data-pool, dirty-cache
FEATURES_INCOMPATIBLE = 0x1 | 0x2 | 0x80 | 0x800
FEATURES_RW_INCOMPATIBLE = 0xFFF
FEATURES_DEFAULT = 0x3D
OPFEAT = collections.OrderedDict([(0x1, "clone-parent"), (0x2, "clone-child"),
                                  (0x4, "group"), (0x8, "snap-trash")])
LOCK_NONE, LOCK_EXCLUSIVE, LOCK_SHARED, LOCK_EPHEMERAL = 0, 1, 2, 3


def feature_names(bits):
    return [n for b, n in FEATURES.items() if bits & b]


def dec_get_size_out(b):
    r = Rd(b)
    order = r.u8()
    size = r.u64()
    r.done("get_size")
    return order, size


def dec_get_features_out(b):
    r = Rd(b)
    f = r.u64()
    inc = r.u64()
    r.done("get_features")
    return f, inc


def dec_string_out(b):
    r = Rd(b)
    s = r.string()
    r.done("string")
    return s


def dec_snapcontext(b):
    r = Rd(b)
    seq = r.u64()
    snaps = r.vec_u64()
    r.done("snapcontext")
    return seq, snaps


def snapcontext_valid(seq, snaps):
    """note 2.5, validity rules"""
    if seq > CEPH_MAXSNAP:
        return False
    if snaps:
        if snaps[0] > seq:
            return False
        for i in range(1, len(snaps)):
            if snaps[i] >= snaps[i - 1] or snaps[i - 1] == 0:
                return False
    return True


def dec_u64_out(b):
    r = Rd(b)
    v = r.u64()
    r.done("u64")
    return v


def dec_i64_out(b):
    r = Rd(b)
    v = r.i64()
    r.done("i64")
    return v


def dec_parent_get_out(b):
    r = Rd(b)
    v, c, body = r.struct_hdr()
    pool = body.i64()
    ns = body.string()
    iid = body.string()
    snap = body.u64()
    body.done("ParentImageSpec")
    r.done("parent_get")
    return dict(v=v, compat=c, pool=pool, ns=ns, image_id=iid, snap=snap)


def dec_get_parent_out(b):
    r = Rd(b)
    pool = r.i64()
    iid = r.string()
    snap = r.u64()
    overlap = r.u64()
    r.done("get_parent")
    return dict(pool=pool, image_id=iid, snap=snap, overlap=overlap)


def dec_entity_addr(r):
    """returns dict; both forms of note 2.7 / msgr2.md 2.8"""
    marker = r.u8()
    if marker == 1:
        v, c, body = r.struct_hdr()
        typ = body.u32()
        nonce = body.u32()
        elen = body.u32()
        sa = body.take(elen)
        body.done("entity_addr_t")
        fam = struct.unpack_from("<H", sa, 0)[0] if elen >= 2 else None
        port = ip = None
        if fam == 2 and elen >= 8:
            port = struct.unpack_from(">H", sa, 2)[0]
            ip = ".".join(str(x) for x in sa[4:8])
        return dict(form="v2", v=v, compat=c, type=typ, nonce=nonce, elen=elen, family=fam, port=port, ip=ip,
                    tail_zero=all(x == 0 for x in sa[8:]) if elen > 8 else True)
    if marker == 0:
        # legacy: the marker byte is the first byte of u32 type
        rest = r.take(3)
        typ = marker | (rest[0] << 8) | (rest[1] << 16) | (rest[2] << 24)
        nonce = r.u32()
        ss = r.take(128)
        fam = struct.unpack_from(">H", ss, 0)[0]
        fam_le = struct.unpack_from("<H", ss, 0)[0]
        return dict(form="legacy", type=typ, nonce=nonce, family_be=fam, family_le=fam_le,
                    port=struct.unpack_from(">H", ss, 2)[0],
                    ip=".".join(str(x) for x in ss[4:8]))
    raise DecodeError("entity_addr_t marker %d" % marker)


def dec_lock_info_out(b):
    """lock get_info reply (note 2.7)"""
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    n = body.u32()
    lockers = []
    for _ in range(n):
        v1, c1, idb = body.struct_hdr(max_compat=1)
        etype = idb.u8()
        enum = idb.i64()
        cookie = idb.string()
        idb.done("locker_id_t")
        v2, c2, ib = body.struct_hdr(max_compat=1)
        exp = ib.utime()
        addr = dec_entity_addr(ib)
        desc = ib.string()
        ib.done("locker_info_t")
        lockers.append(dict(etype=etype, num=enum, cookie=cookie, expiration=exp, addr=addr, desc=desc))
    ltype = body.u8()
    tag = body.string()
    body.done("cls_lock_get_info_reply")
    r.done("lock get_info reply")
    return dict(v=v, compat=c, lockers=lockers, type=ltype, tag=tag)


def enc_lock_get_info_in(name="rbd_lock"):
    body = enc_string(name)
    return b"\x01\x01" + struct.pack("<I", len(body)) + body


def dec_lock_in(b):
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    d = dict(v=v, compat=c)
    d["name"] = body.text()
    d["type"] = body.u8()
    d["cookie"] = body.text()
    d["tag"] = body.text()
    d["desc"] = body.text()
    d["duration"] = body.utime()
    d["flags"] = body.u8()
    body.done("lock input")
    r.done("lock input")
    return d


def dec_unlock_in(b):
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    d = dict(v=v, compat=c, name=body.text(), cookie=body.text())
    body.done("unlock input")
    r.done("unlock input")
    return d


def dec_assert_locked_in(b):
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    d = dict(v=v, compat=c, name=body.text(), type=body.u8(), cookie=body.text(), tag=body.text())
    body.done("assert_locked input")
    r.done("assert_locked input")
    return d


def dec_set_cookie_in(b):
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    d = dict(v=v, compat=c, name=body.text(), type=body.u8(), cookie=body.text(),
             tag=body.text(), new_cookie=body.text())
    body.done("set_cookie input")
    r.done("set_cookie input")
    return d


def dec_break_lock_in(b):
    r = Rd(b)
    v, c, body = r.struct_hdr(max_compat=1)
    d = dict(v=v, compat=c, name=body.text(), etype=body.u8(), num=body.i64(), cookie=body.text())
    body.done("break_lock input")
    r.done("break_lock input")
    return d


def enc_lock_in(name, ltype, cookie, tag, desc="", duration=(0, 0), flags=0):
    body = (enc_string(name) + bytes([ltype]) + enc_string(cookie) + enc_string(tag) +
            enc_string(desc) + struct.pack("<II", *duration) + bytes([flags]))
    return b"\x01\x01" + struct.pack("<I", len(body)) + body


# methods of note 2.3 that the open sequence uses; value = (decode input, decode output)
def classify_call(cls, method):
    return "%s.%s" % (cls, method)


def decode_call(cls, method, inb, outb):
    """Decode (input, output) of a call named in the note; returns a dict or
    raises DecodeError. Methods the note does not describe return None."""
    k = classify_call(cls, method)
    d = {"call": k}
    if k == "rbd.get_size":
        r = Rd(inb)
        d["snap"] = r.u64()
        r.done("get_size input")
        if outb is not None:
            d["order"], d["size"] = dec_get_size_out(outb)
    elif k == "rbd.get_features":
        r = Rd(inb)
        d["snap"] = r.u64()
        d["read_only"] = None
        if r.left():
            d["read_only"] = r.boolean()
        r.done("get_features input")
        if outb is not None:
            d["features"], d["incompatible"] = dec_get_features_out(outb)
    elif k in ("rbd.get_object_prefix", "rbd.get_id"):
        Rd(inb).done("%s input" % k)
        if outb is not None:
            d["value"] = dec_string_out(outb)
    elif k == "rbd.get_snapcontext":
        Rd(inb).done("get_snapcontext input")
        if outb is not None:
            d["seq"], d["snaps"] = dec_snapcontext(outb)
    elif k == "rbd.get_data_pool":
        Rd(inb).done("get_data_pool input")
        if outb is not None:
            d["pool"] = dec_i64_out(outb)
    elif k == "rbd.get_stripe_unit_count":
        Rd(inb).done("input")
        if outb is not None:
            r = Rd(outb)
            d["stripe_unit"] = r.u64()
            d["stripe_count"] = r.u64()
            r.done("get_stripe_unit_count")
    elif k == "rbd.get_flags":
        r = Rd(inb)
        d["snap"] = r.u64()
        r.done("get_flags input")
        if outb is not None:
            d["flags"] = dec_u64_out(outb)
    elif k == "rbd.op_features_get":
        Rd(inb).done("input")
        if outb is not None:
            d["op_features"] = dec_u64_out(outb)
    elif k == "rbd.parent_get":
        Rd(inb).done("input")
        if outb is not None:
            d["parent"] = dec_parent_get_out(outb)
    elif k == "rbd.parent_overlap_get":
        r = Rd(inb)
        d["snap"] = r.u64()
        r.done("input")
        if outb is not None:
            rr = Rd(outb)
            d["overlap"] = rr.optional_u64()
            rr.done("parent_overlap_get")
    elif k == "rbd.get_parent":
        r = Rd(inb)
        d["snap"] = r.u64()
        r.done("input")
        if outb is not None:
            d["parent"] = dec_get_parent_out(outb)
    elif k == "rbd.dir_get_id":
        r = Rd(inb)
        d["name"] = r.string()
        r.done("dir_get_id input")
        if outb is not None:
            d["id"] = dec_string_out(outb)
    elif k == "rbd.dir_get_name":
        r = Rd(inb)
        d["id"] = r.string()
        r.done("dir_get_name input")
        if outb is not None:
            d["name"] = dec_string_out(outb)
    elif k == "lock.get_info":
        r = Rd(inb)
        v, c, body = r.struct_hdr(max_compat=1)
        d["name"] = body.text()
        body.done("get_info input")
        r.done("get_info input")
        d["input_raw_ok"] = (inb == enc_lock_get_info_in(d["name"]))
        if outb is not None:
            d["info"] = dec_lock_info_out(outb)
    elif k == "lock.lock":
        d["in"] = dec_lock_in(inb)
    elif k == "lock.unlock":
        d["in"] = dec_unlock_in(inb)
    elif k == "lock.assert_locked":
        d["in"] = dec_assert_locked_in(inb)
    elif k == "lock.set_cookie":
        d["in"] = dec_set_cookie_in(inb)
    elif k == "lock.break_lock":
        d["in"] = dec_break_lock_in(inb)
    else:
        return None
    return d


# ---------------------------------------------------------------------------
# Striping (note 2.9, 2.10)
# ---------------------------------------------------------------------------


def stripe_extents(offset, length, object_size, su=None, sc=1):
    """note 2.10: image byte range -> [(objectno, in_obj_off, run)]"""
    if su is None or sc == 1:
        su = object_size if sc == 1 else su
    spo = object_size // su
    out = []
    cur = offset
    rem = length
    while rem > 0:
        block = cur // su
        stripe = block // sc
        pos = block % sc
        objectset = stripe // spo
        objectno = objectset * sc + pos
        in_off = (stripe % spo) * su + (cur % su)
        run = min(rem, su - (cur % su))
        if out and out[-1][0] == objectno and out[-1][1] + out[-1][2] == in_off:
            out[-1] = (objectno, out[-1][1], out[-1][2] + run)
        else:
            out.append((objectno, in_off, run))
        cur += run
        rem -= run
    return out


def object_count(size, object_size, su=None, sc=1):
    """note 2.9"""
    if su is None:
        su = object_size
    period = sc * object_size
    num_periods = -(-size // period)
    rem = size % period
    sub = 0
    if 0 < rem < sc * su:
        sub = sc - (-(-rem // su))
    return num_periods * sc - sub


def data_object_name(prefix, objno):
    return "%s.%016x" % (prefix, objno)


# ---------------------------------------------------------------------------
# ground truth loaders (lab output of the stock tools)
# ---------------------------------------------------------------------------


def jload(path):
    with open(path) as f:
        return json.load(f)


def parse_hexdump_values(text):
    """`rados listomapvals` text: sections '== label', then per key:
    key line, 'value (N bytes) :', hexdump lines, offset line, blank.
    Returns {label: {key: bytes}} (label = text after '== ')."""
    out = collections.OrderedDict()
    cur = None
    key = None
    buf = None
    want = None
    for line in text.splitlines():
        if line.startswith("== "):
            cur = out.setdefault(line[3:], collections.OrderedDict())
            key = None
            continue
        if cur is None:
            continue
        m = re.match(r"value \((\d+) bytes\) :", line)
        if m:
            want = int(m.group(1))
            buf = bytearray()
            continue
        if buf is not None:
            m = re.match(r"^[0-9a-f]{8}  ([0-9a-f ]*?)\s*\|", line)
            if m:
                buf.extend(bytes.fromhex(m.group(1).replace(" ", "")))
                continue
            if re.match(r"^[0-9a-f]{8}$", line):
                cur[key] = bytes(buf)
                if len(buf) != want:
                    raise DecodeError("hexdump of %r: %d bytes, header said %d" % (key, len(buf), want))
                buf = None
                key = None
                continue
        if line.strip() and buf is None:
            key = line.strip()
    return out


def calendar_timegm(text):
    import calendar
    return calendar.timegm(time.strptime(text, "%a %b %d %H:%M:%S %Y"))


def fmt_ctime_utc(sec):
    return time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(sec))


# ---------------------------------------------------------------------------
# checks on the ground truth (gt4), independent of any pcap
# ---------------------------------------------------------------------------


def expected_incompat(features, read_only):
    return features & (FEATURES_INCOMPATIBLE if read_only else FEATURES_RW_INCOMPATIBLE)


def check_gt4(cap, ctx):
    gt4 = os.path.join(cap, "gt4")
    if not os.path.isdir(gt4):
        R.group("gt4 (missing)")
        R.check(False, "gt4 directory present")
        return
    images = ["img-v1", "img-default", "t0-copy-v1", "t0-copy-def", "t0-copy-v1.with-snap"]
    hdr_omaps = parse_hexdump_values(open(os.path.join(gt4, "header-omapvals.txt")).read())
    pool_omaps = parse_hexdump_values(open(os.path.join(gt4, "pool-omapvals.txt")).read())
    dirmap = pool_omaps.get("rbd_directory", {})
    ctx["gt4_images"] = {}
    for img in images:
        mpath = os.path.join(gt4, img + ".meta.json")
        if not os.path.exists(mpath):
            continue
        meta = jload(mpath)
        base = img.split(".")[0]
        info = jload(os.path.join(gt4, (base if img != "t0-copy-v1.with-snap" else "t0-copy-v1.after-snap")
                                  + ".rbd-info.json"))
        iid = meta["id"]
        R.group("rbd metadata vs rbd info (gt4)")
        # ---- id object, directory (2.1, 2.3)
        rid = bytes.fromhex(meta["rbd_id_object_hex"])
        try:
            got = dec_string_out(rid)
        except DecodeError as e:
            got = None
            R.check(False, "%s rbd_id object decodes as one string: %s" % (img, e))
        R.eq(got, iid.encode(), "%s rbd_id.<name> raw bytes are `u32 len + id`" % img)
        R.check(re.fullmatch(r"[0-9a-zA-Z]+", iid) is not None and len(iid) <= 14,
                "%s id is alphanumeric, non-empty, <= 14 (librbd generated)" % img)
        R.eq(info["id"], iid, "%s rbd info id == rbd_id object" % img)
        R.eq(dirmap.get("name_" + base), rid, "%s directory key name_<name> -> encoded id" % img)
        R.eq(dirmap.get("id_" + iid), enc_string(base), "%s directory key id_<id> -> encoded name" % img)
        # ---- header omap (2.4)
        omap = collections.OrderedDict((k, bytes.fromhex(v)) for k, v in meta["header_omap"])
        for k in ("size", "order", "features", "object_prefix", "snap_seq",
                  "create_timestamp", "access_timestamp", "modify_timestamp"):
            R.check(k in omap, "%s header omap has key %s" % (img, k))
        size = struct.unpack("<Q", omap["size"])[0]
        order = omap["order"][0]
        R.eq(len(omap["order"]), 1, "%s omap order is u8" % img)
        feats = struct.unpack("<Q", omap["features"])[0]
        prefix = dec_string_out(omap["object_prefix"]).decode()
        snap_seq = struct.unpack("<Q", omap["snap_seq"])[0]
        R.eq(size, info["size"], "%s omap size == rbd info size" % img)
        R.eq(order, info["order"], "%s omap order == rbd info order" % img)
        R.eq(1 << order, info["object_size"], "%s object_size == 1 << order (2.9)" % img)
        R.eq(feature_names(feats), info["features"], "%s feature bits -> names (2.8)" % img)
        R.eq(prefix, info["block_name_prefix"], "%s omap object_prefix == block_name_prefix" % img)
        R.eq(prefix, "rbd_data." + iid, "%s prefix is rbd_data.<id> for same-pool data (2.1.1)" % img)
        extra = [k for k in omap if k not in ("size", "order", "features", "object_prefix", "snap_seq",
                                              "create_timestamp", "access_timestamp", "modify_timestamp")
                 and not k.startswith("snapshot_")]
        R.eq(extra, [], "%s no data_pool_id/stripe_*/flags/op_features/parent keys on a plain image (2.4)" % img)
        for k, label in (("create_timestamp", "create_timestamp"), ("access_timestamp", "access_timestamp"),
                         ("modify_timestamp", "modify_timestamp")):
            r = Rd(omap[k])
            sec, nsec = r.utime()
            r.done("utime")
            if k == "access_timestamp":
                # librbd bumps the access time on later opens; the omap was dumped after `rbd info`
                R.check(sec >= calendar_timegm(info[label]),
                        "%s %s = utime_t, not older than the one `rbd info` printed" % (img, k))
            else:
                R.eq(fmt_ctime_utc(sec), info[label], "%s %s = utime_t(u32 sec,u32 nsec), rbd info agrees" % (img, k))
            R.check(nsec < 10 ** 9, "%s %s nsec < 1e9" % (img, k))
        R.eq(object_count(size, 1 << order), info["objects"], "%s object count formula (2.9) == rbd info objects" % img)
        # ---- snapshot keys
        snap_keys = [k for k in omap if k.startswith("snapshot_")]
        # ---- the call table of the lab (rados Ioctx.execute)
        calls = meta["cls_calls"]
        hdr = meta["header_object"]
        R.eq(hdr, "rbd_header." + iid, "%s header object name rbd_header.<id> (2.1)" % img)
        for c in calls:
            if "err" in c:
                continue
            cls_, meth = c["call"].split(".")
            inb = bytes.fromhex(c["in"])
            outb = bytes.fromhex(c["out"])
            R.eq(c["rc"], len(outb), "%s %s rc is output length" % (img, c["call"]))
            try:
                d = decode_call(cls_, meth, inb, outb)
            except DecodeError as e:
                R.check(False, "%s %s decodes per note: %s" % (img, c["call"], e))
                continue
            if d is None:
                continue
            tag = "%s %s" % (img, c["call"])
            if c["call"] == "rbd.get_size":
                snap = d["snap"]
                if snap == CEPH_NOSNAP:
                    R.eq((d["order"], d["size"]), (order, size), tag + " (head) = (order, size), order first (2.3)")
            elif c["call"] == "rbd.get_features":
                snap = d["snap"]
                if snap in (CEPH_NOSNAP, CEPH_SNAPDIR):
                    R.eq(d["features"], feats, tag + " features")
                    R.eq(d["incompatible"], expected_incompat(feats, bool(d["read_only"])),
                         tag + " incompatible = features & mask(read_only=%s) (2.8)" % bool(d["read_only"]))
            elif c["call"] == "rbd.get_object_prefix":
                R.eq(d["value"].decode(), prefix, tag)
            elif c["call"] == "rbd.get_flags":
                R.eq(d["flags"], 0, tag + " absent key reads as 0 (2.3)")
            elif c["call"] == "rbd.get_snapcontext":
                R.eq(d["seq"], snap_seq, tag + " seq == omap snap_seq")
                R.check(snapcontext_valid(d["seq"], d["snaps"]), tag + " valid per 2.5")
                want = sorted((int(k[len("snapshot_"):], 16) for k in snap_keys), reverse=True)
                R.eq(d["snaps"], want, tag + " ids == snapshot_* keys, descending (2.5)")
                if d["snaps"]:
                    ctx["gt_snapctx_bytes"] = (outb, d["seq"], d["snaps"])
            elif c["call"] == "rbd.get_data_pool":
                R.eq(d["pool"], -1, tag + " = -1 when key absent (2.3)")
            elif c["call"] == "rbd.parent_get":
                p = d["parent"]
                R.eq((p["v"], p["compat"], p["pool"], p["ns"], p["image_id"], p["snap"]),
                     (1, 1, -1, b"", b"", CEPH_NOSNAP), tag + " default ParentImageSpec (2.3)")
                R.eq(outb[:6], b"\x01\x01\x18\x00\x00\x00", tag + " struct header v1/compat1/len 24")
            elif c["call"] == "rbd.get_parent":
                p = d["parent"]
                R.eq((p["pool"], p["image_id"], p["snap"], p["overlap"]), (-1, b"", CEPH_NOSNAP, 0),
                     tag + " legacy form: i64 pool,string id,u64 snap,u64 overlap")
            elif c["call"] == "rbd.op_features_get":
                R.eq(d["op_features"], 0, tag + " absent key reads as 0")
            elif c["call"] == "rbd.get_all_features":
                pass
            elif c["call"] == "lock.get_info":
                R.check(d["input_raw_ok"], tag + " input = 01 01 <len> string name (2.7)")
                R.eq(inb.hex(), "01010c000000080000007262645f6c6f636b", tag + " input bytes equal the note's example")
                inf = d["info"]
                x = meta["xattrs"][hdr].get("lock.rbd_lock")
                if x is None:
                    R.eq((inf["lockers"], inf["type"], inf["tag"]), ([], LOCK_NONE, b""),
                         tag + " no xattr -> empty map, type 0, empty tag (2.7)")
                else:
                    # xattr lock.rbd_lock is the same struct as the reply
                    R.eq(x, c["out"], tag + " reply == stored xattr lock.rbd_lock (empty lockers)")
                    ctx.setdefault("released_lock_form", []).append((img, inf["type"], inf["tag"], inf["lockers"]))
            elif c["call"] == "rbd.get_id":
                R.eq(d["value"], iid.encode(), tag)
            elif c["call"] == "rbd.dir_get_id":
                R.eq(d["id"], iid.encode(), tag)
            elif c["call"] == "rbd.dir_get_name":
                R.eq(d["name"], base.encode(), tag)
        # features arithmetic (2.8)
        R.eq(expected_incompat(feats, True), expected_incompat(feats, True), "tautology guard")
        ctx["gt4_images"][img] = dict(id=iid, prefix=prefix, size=size, order=order, features=feats,
                                       snaps=[int(k[len("snapshot_"):], 16) for k in snap_keys], info=info, meta=meta)
        # get_stripe_unit_count: the lab script lost the errno; handled by the probe if present
    ga = [c for c in jload(os.path.join(gt4, "img-default.meta.json"))["cls_calls"] if c["call"] == "rbd.get_all_features"][0]
    R.group("feature table (2.8)")
    R.eq(struct.unpack("<Q", bytes.fromhex(ga["out"]))[0], FEATURES_ALL, "server's RBD_FEATURES_ALL == 0xFFF (bits 0-11)")
    R.eq(FEATURES_DEFAULT, 1 | 4 | 8 | 0x10 | 0x20, "0x3D = layering|exclusive-lock|object-map|fast-diff|deep-flatten")
    R.eq(feature_names(0x3D), jload(os.path.join(gt4, "img-default.rbd-info.json"))["features"],
         "names of 0x3D equal `rbd info` (default image)")
    R.eq(feature_names(0x1), ["layering"], "names of 0x01")


def check_gt4_objects(cap, ctx):
    """2.1.1 data object names + 2.9/2.10 striping math against the real objects"""
    gt4 = os.path.join(cap, "gt4")
    R.group("data objects vs striping math (gt4)")

    def pat(n, mul, add):
        return bytes(((i * mul + add) % 251) for i in range(n))

    blk = bytes((i * 7 + 3) & 0xFF for i in range(1 << 20))
    for img in ("t0-copy-v1", "t0-copy-def", "img-v1", "img-default"):
        info = ctx["gt4_images"].get(img)
        p = os.path.join(gt4, img + ".data-objects.json")
        if not info or not os.path.exists(p):
            continue
        rows = jload(p)
        prefix = info["prefix"]
        object_size = 1 << info["order"]
        objs = collections.OrderedDict()  # objno -> bytearray (sparse model)
        # base content: the krbd pattern written to img-v1 (1 MiB at 0 and at 1 GiB), copied by `rbd cp`
        writes = []
        if img in ("img-v1", "img-default", "t0-copy-v1", "t0-copy-def"):
            writes.append((0, blk))
            writes.append((1 << 30, blk))
        if img.startswith("t0-copy"):
            for ln in open(os.path.join(gt4, "pattern-writes.%s.txt" % img)).read().splitlines():
                _, off, n, k = ln.split()
                writes.append((int(off), pat(int(n), 13, int(k))))
        if img == "t0-copy-v1":
            # gt4.sh: after `rbd snap create`, 512 bytes of 0xEE at offset 0 (snapshot copy-on-write test)
            writes.append((0, b"\xee" * 512))
        for off, data in writes:
            for objno, ioff, run in stripe_extents(off, len(data), object_size):
                o = objs.setdefault(objno, bytearray())
                if len(o) < ioff + run:
                    o.extend(b"\0" * (ioff + run - len(o)))
                src = off  # position of this run inside the write
                # recompute data offset of the run
                # (default striping: image offset = objno*object_size + ioff)
                img_off = objno * object_size + ioff
                o[ioff:ioff + run] = data[img_off - off:img_off - off + run]
        want_names = [data_object_name(prefix, n) for n in sorted(objs)]
        R.eq([r["object"] for r in rows], want_names, "%s object names rbd_data.<id>.<16 hex> for written ranges" % img)
        for r in rows:
            n = int(r["object"].rsplit(".", 1)[1], 16)
            o = bytes(objs.get(n, b""))
            R.eq((r["size"], hashlib.sha256(o).hexdigest()), (len(o), r["sha256"]),
                 "%s %s size and sha256 equal our extent mapping" % (img, r["object"].rsplit(".", 1)[1]))
    # worked examples of 2.10
    R.group("striping worked examples (2.9, 2.10)")
    R.eq(stripe_extents(10 << 20, 8 << 20, 4 << 20), [(2, 2 << 20, 2 << 20), (3, 0, 4 << 20), (4, 0, 2 << 20)],
         "default 4 MiB: offset 10 MiB len 8 MiB")
    R.eq(stripe_extents(327680, 4096, 4 << 20, 65536, 4), [(1, 65536, 4096)], "su 64 KiB sc 4: offset 327680")
    R.eq(stripe_extents(16 << 20, 1, 4 << 20, 65536, 4), [(4, 0, 1)], "su 64 KiB sc 4: offset 16 MiB -> object 4")
    R.eq(object_count(4 << 30, 4 << 20), 1024, "object count 4 GiB / 4 MiB")
    R.eq(object_count(10, 4 << 20, 65536, 4), 1, "object count tiny image, striped (rem 10 < sc*su)")
    # general formula against a brute-force model of the documented stripe layout
    ok = True
    for su, sc, osz in ((65536, 4, 1 << 20), (4096, 3, 16384), (8192, 2, 1 << 16)):
        total = 5 * sc * osz + 3 * su
        model = {}
        for b in range(0, total, su):
            # documented rule: block b -> stripe b // sc, position b % sc, object set stripe // (osz/su)
            objno = (b // su // sc // (osz // su)) * sc + (b // su) % sc
            ioff = ((b // su // sc) % (osz // su)) * su
            model[b] = (objno, ioff)
        for b in range(0, total, su):
            ex = stripe_extents(b, su, osz, su, sc)
            if ex != [(model[b][0], model[b][1], su)]:
                ok = False
    R.check(ok, "stripe_extents agrees with an independent per-block model (3 layouts)")


# ---------------------------------------------------------------------------
# pcap analysis
# ---------------------------------------------------------------------------

CLIENT_PORT_MIN = 32768


class Conn:
    def __init__(self, pcap, key, cflow, sflow):
        self.pcap = pcap
        self.key = key
        self.c = cflow
        self.s = sflow
        self.csi = parse_stream(cflow.data)
        self.ssi = parse_stream(sflow.data) if sflow is not None else StreamInfo()
        self.secure = (self.ssi.auth_mode == 2) or self.csi.secure_from is not None or self.ssi.secure_from is not None
        self.exch = []
        self.problems = []


# `rbd bench --io-type write ... --io-pattern seq` on a fresh image: every thread writes its own run, starting at
# an equal share of the image.  The shape of a session comes from its command line (cmd/<session>.cmd) when the
# capture set has one; the large private set had a 64 MiB image, 64 KiB IOs, 4 threads, 8 MiB in total.
BENCH_DEFAULT = (64 << 20, 4, 65536, 8 << 20)

# Least number of CALL ops the all-CALL-ops checks must have seen to count (the checks themselves are over all of them).
MIN_CALL_OPS = 100


def _size(txt):
    m = re.fullmatch(r"(\d+)([KMGkmg]?)(?:i?[Bb])?", txt)
    return int(m.group(1)) << {"": 0, "k": 10, "m": 20, "g": 30}[m.group(2).lower()]


def bench_shape(cap, session):
    """(image size, threads, io size, io total) of the `rbd bench` write in a session; BENCH_DEFAULT if unknown."""
    try:
        lines = open(os.path.join(cap, "cmd", session + ".cmd")).read().splitlines()
        size = thr = iosz = tot = None
        for ln in lines:
            ln = ln.strip()
            m = re.search(r"rbd create .*--size (\S+)", ln)
            if m:
                size = _size(m.group(1))
            if "rbd bench" in ln and "--io-type write" in ln:
                thr = int(re.search(r"--io-threads (\d+)", ln).group(1))
                iosz = _size(re.search(r"--io-size (\S+)", ln).group(1))
                tot = _size(re.search(r"--io-total (\S+)", ln).group(1))
        if None not in (size, thr, iosz, tot):
            return size, thr, iosz, tot
    except (OSError, AttributeError, ValueError, KeyError):
        pass
    return BENCH_DEFAULT


def load_sessions(cap):
    out = {}
    p = os.path.join(cap, "sessions.tsv")
    if not os.path.exists(p):
        return out
    for ln in open(p):
        f = ln.rstrip("\n").split("\t")
        if len(f) >= 4:
            out[f[0]] = dict(keytype=f[1], user=f[2], mode=f[3])
    return out


def load_drops(cap):
    """tcpdump's own statistics: `N packets dropped by kernel` per pcap (stdout/<session>.tcpdump.err)"""
    out = {}
    for f in glob.glob(os.path.join(cap, "stdout", "*.tcpdump.err")):
        name = os.path.basename(f)[:-len(".tcpdump.err")]
        m = re.search(r"(\d+) packets dropped by kernel", open(f).read())
        out[name] = int(m.group(1)) if m else None
    return out


def load_conns(pcap_path):
    lt, pk = read_pcap(pcap_path)
    flows = tcp_flows(lt, pk)
    conns = []
    name = os.path.basename(pcap_path)[:-5]
    for key, fo in flows.items():
        rk = (key[2], key[3], key[0], key[1])
        client = fo.is_client
        if client is None:
            client = key[1] >= CLIENT_PORT_MIN and key[3] < CLIENT_PORT_MIN
        if not client:
            continue
        sfo = flows.get(rk)
        if not fo.data and not (sfo and sfo.data):
            continue
        c = Conn(name, key, fo, sfo)
        if not c.secure and key[3] >= 6800:
            c.exch = exchanges_of(key, c.csi, c.ssi, c.problems)
        conns.append(c)
    return conns


HS_C = ["HELLO", "AUTH_REQUEST", "AUTH_REQUEST_MORE", "AUTH_SIGNATURE", "COMPRESSION_REQUEST", "CLIENT_IDENT"]
HS_S = ["HELLO", "AUTH_REPLY_MORE", "AUTH_DONE", "AUTH_SIGNATURE", "COMPRESSION_DONE", "SERVER_IDENT"]


def check_msgr2(cap, ctx, conns_by_pcap, sessions, drops):
    R.group("msgr2 frames (crc mode)")
    tot_frames = tot_conn = tot_secure = tot_msgs = 0
    for pname, conns in conns_by_pcap.items():
        sess = sessions.get(pname, {})
        for c in conns:
            tot_conn += 1
            port = c.key[3]
            ok_stream = True
            if c.csi.banner != (3, 0) or (c.ssi.banner is not None and c.ssi.banner != (3, 0)):
                ok_stream = False
                R.check(False, "%s %d banner features" % (pname, port), "%r %r" % (c.csi.banner, c.ssi.banner))
            lossy = bool(drops.get(pname))
            if (c.c.gaps or c.s is not None and c.s.gaps):
                R.check(lossy, "%s %d TCP stream has a hole only where tcpdump reports dropped packets" % (pname, port),
                        "drops=%r" % drops.get(pname))
                ctx.setdefault("capture_holes", []).append((pname, port))
            if c.secure:
                tot_secure += 1
                # secure connections: only the plain prefix (up to AUTH_DONE) was cut
                want = {"crc": 0, "sec": 2, "def": 2}.get(sess.get("mode"))
                continue
            for who, si in (("client", c.csi), ("server", c.ssi)):
                bad = [(TAGS.get(fr.tag, fr.tag), fr.problems) for fr in si.frames if fr.problems]
                tot_frames += len(si.frames)
                if bad or si.problems:
                    ok_stream = False
                    R.check(False, "%s %d %s frames: crc/length/tag problems" % (pname, port, who),
                            "%r %r" % (bad[:2], si.problems[:2]))
                if si.trailing and who == "client" and False:
                    pass
            hs_c = [TAGS.get(fr.tag) for fr in c.csi.frames[:6]]
            hs_s = [TAGS.get(fr.tag) for fr in c.ssi.frames[:6]]
            if len(hs_c) == 6 and len(hs_s) == 6:
                if hs_c != HS_C or hs_s != HS_S:
                    ok_stream = False
                    R.check(False, "%s %d handshake frame order" % (pname, port), "%r %r" % (hs_c, hs_s))
            if c.ssi.auth_mode is not None:
                want = {"crc": 1, "sec": 2}.get(sess.get("mode"))
                if want is not None:
                    R.eq(c.ssi.auth_mode, want, "%s %d AUTH_DONE connection mode matches session mode" % (pname, port))
            tot_msgs += sum(1 for fr in c.csi.frames + c.ssi.frames if fr.tag == T_MESSAGE)
            if ok_stream:
                pass
    R.check(tot_frames > 0 and tot_conn > 0, "parsed %d connections, %d frames, %d MESSAGE frames; %d secure connections not decoded"
            % (tot_conn, tot_frames, tot_msgs, tot_secure))
    ctx["msgr2_counts"] = (tot_conn, tot_frames, tot_msgs, tot_secure)


def check_envelope(cap, ctx, conns_by_pcap, drops):
    R.group("MOSDOp / MOSDOpReply envelope")
    n_req = n_rep = 0
    flags_seen = collections.Counter()
    for pname, conns in conns_by_pcap.items():
        for c in conns:
            if c.secure or c.key[3] < 6800:
                continue
            if c.problems:
                unmatched = [p for p in c.problems if p.endswith("replies without request")]
                other = [p for p in c.problems if p not in unmatched]
                R.check(not other, "%s %d messages decode (front consumed exactly, payload lengths add up)" % (pname, c.key[3]),
                        repr(other[:2]))
                if unmatched:
                    # tcpdump dropped packets of the client->server direction (its own statistics say so): replies whose
                    # request is not in the file. Only tolerated in pcaps with a non-zero drop count.
                    R.check(bool(drops.get(pname)),
                            "%s %d replies without request only in a pcap where tcpdump reports drops" % (pname, c.key[3]),
                            "drops=%r" % drops.get(pname))
                    ctx.setdefault("tail_loss", []).append((pname, c.key[3], len(unmatched)))
            else:
                R.check(True, "%s %d messages decode" % (pname, c.key[3]))
            for e in c.exch:
                n_req += 1
                m = e.req
                h, nseg = e.req_hdr
                R.check(h["version"] == 9 and h["compat"] == 3 and h["flags"] == 3,
                        "MOSDOp header version/compat 9/3 (osd-ops 2.1)",
                        "%r" % ((h["version"], h["compat"], h["flags"]),))
                bad = []
                if m["pgid"]["shard"] != -1 or m["pgid"]["pool"] != m["oloc"]["pool"]:
                    bad.append("spg")
                if (m["oloc"]["v"], m["oloc"]["compat"]) != (6, 3) or m["oloc"]["hash"] != -1 or m["oloc"]["pref"] != -1:
                    bad.append("oloc")
                if m["oloc"]["key"] != b"" or m["oloc"]["nspace"] != b"":
                    bad.append("oloc key/nspace non-empty")
                r = m["reqid"]
                if (r["v"], r["compat"], r["name_type"], r["name_num"], r["tid"]) != (2, 2, 0, 0, 0):
                    bad.append("reqid")
                if r["inc"] != m["client_inc"]:
                    bad.append("reqid.inc != client_inc")
                if m["blkin"] != b"\0" * 24 or m["otel"] != bytes.fromhex("01010100000000"):
                    bad.append("trace blocks")
                if m["snapid"] != CEPH_NOSNAP:
                    bad.append("snapid")
                if bad:
                    R.check(False, "MOSDOp fixed fields (osd-ops 2.2/2.3) tid %d %s" % (h["tid"], pname), repr(bad))
                flags_seen[m["flags"]] += 1
                if e.rep is not None:
                    n_rep += 1
                    rp = e.rep
                    if len(rp["ops"]) != len(m["ops"]):
                        R.check(False, "reply num_ops == request num_ops tid %d %s" % (h["tid"], pname))
                    if rp["oid"] != m["oid"]:
                        R.check(False, "reply echoes oid", pname)
    R.check(n_req > 0 and n_rep > 0, "decoded %d MOSDOp, %d with a reply" % (n_req, n_rep))
    base = 0x4 | 0x400000 | 0x8000000  # ONDISK | KNOWN_REDIR | SUPPORTSPOOLEIO, on every request
    extra_ok = 0x800000 | 0x1000000  # FULL_TRY, FULL_FORCE (removal paths)
    bad = [hex(f) for f in flags_seen
           if (f & base) != base or (f & ~(base | extra_ok | 0x10 | 0x20)) or ((f & 0x30) not in (0x10, 0x20))]
    R.check(not bad, "every request word = ONDISK|KNOWN_REDIR|SUPPORTSPOOLEIO + exactly one of READ(0x10)/WRITE(0x20) (+FULL_TRY/FULL_FORCE) (osd-ops 2.4)",
            repr(bad))
    R.check(0x08400014 in flags_seen and 0x08400024 in flags_seen, "plain read word 0x08400014 and plain write word 0x08400024 both seen")
    ctx["flags_seen"] = flags_seen


def call_ops(e):
    """[(class, method, input, output|None, rval|None)] for the CALL ops of an exchange"""
    out = []
    m = e.req
    for i, o in enumerate(m["ops"]):
        if o.code != OP_CALL:
            continue
        cl, ml, argc, il = o.cls()
        d = m["op_in"][i]
        cls_, meth, inb = d[:cl].decode(), d[cl:cl + ml].decode(), d[cl + ml:]
        if len(inb) != il:
            raise DecodeError("call indata_len %d != %d" % (il, len(inb)))
        rv = None
        outb = None
        if e.rep is not None and e.rep["result"] >= 0 and i < len(e.rep["rvals"]):
            rv = e.rep["rvals"][i]
            outb = e.rep["op_out"][i]
        out.append((cls_, meth, inb, outb, rv))
    return out


def hdr_id(oid):
    m = re.fullmatch(rb"rbd_header\.([0-9a-zA-Z]+)", oid)
    return m.group(1).decode() if m else None


VEC_A = ("get_size", "get_object_prefix", "get_features")
VEC_B = ("get_size", "get_features", "get_flags", "get_snapcontext", "lock.get_info")
VEC_C = ("parent_get", "parent_overlap_get")
NOSNAP_B = enc_u64(CEPH_NOSNAP)


def check_wire_rbd(cap, ctx, conns_by_pcap, sessions, drops):
    R.group("rbd/lock calls on the wire (crc pcaps)")
    truth = {}
    for img, t in ctx.get("gt4_images", {}).items():
        truth["rbd_header." + t["id"]] = t
    learned = {}  # (pcap, header oid) -> dict
    counts = collections.Counter()
    undescribed = collections.Counter()
    open_kinds = collections.defaultdict(list)  # pcap -> request kinds on header objects
    eperm = []
    enoent = []
    locks = collections.defaultdict(list)
    watches = collections.defaultdict(list)
    data_w = collections.defaultdict(list)
    data_r = collections.defaultdict(list)
    opcodes_seen = set()
    call_fr = []
    call_echo = []
    for pname, conns in conns_by_pcap.items():
        for c in conns:
            if c.secure:
                continue
            for e in c.exch:
                m = e.req
                oid = m["oid"]
                rp = e.rep
                h = hdr_id(oid)
                # ---- whole-request failures of the note 2.2 (ENOENT before any op runs)
                if rp is not None and rp["result"] < 0:
                    names_ = [o.name() for o in m["ops"]]
                    if rp["result"] == -2:
                        enoent.append((pname, oid, names_, list(rp["rvals"]), [len(x) for x in rp["op_out"]], m["flags"]))
                    elif rp["result"] == -1 and any(o.code == OP_CALL for o in m["ops"]):
                        eperm.append((pname, oid, rp["rvals"]))
                    continue
                kinds = []
                try:
                    cops = call_ops(e)
                except DecodeError as ex:
                    R.check(False, "call op framing %s %r" % (pname, oid), str(ex))
                    continue
                for (cls_, meth, inb, outb, rv) in cops:
                    kinds.append("%s.%s" % (cls_, meth) if cls_ != "rbd" else meth)
                    if outb is None:
                        continue
                    try:
                        d = decode_call(cls_, meth, inb, outb)
                    except DecodeError as ex:
                        R.check(False, "decode %s.%s on %r (%s)" % (cls_, meth, oid, pname), str(ex))
                        continue
                    if d is None:
                        undescribed["%s.%s" % (cls_, meth)] += 1
                        continue
                    counts[d["call"]] += 1
                    L = learned.setdefault((pname, h), {}) if h else {}
                    t = truth.get("rbd_header." + h) if h else None
                    if d["call"] == "rbd.get_size" and d["snap"] == CEPH_NOSNAP:
                        L.setdefault("sizes", set()).add((d["order"], d["size"]))
                        if t:
                            R.eq((d["order"], d["size"]), (t["order"], t["size"]), "wire get_size(head) == ground truth %s" % h)
                    elif d["call"] == "rbd.get_features":
                        L.setdefault("features", set()).add(d["features"])
                        ro = bool(d["read_only"])
                        R.eq(d["incompatible"], expected_incompat(d["features"], ro),
                             "wire get_features incompatible = features & mask(read_only=%s)" % ro)
                        R.check(d["features"] & ~FEATURES_ALL == 0, "wire features within bits 0-11")
                        if t:
                            R.eq(d["features"], t["features"], "wire get_features == ground truth %s" % h)
                    elif d["call"] == "rbd.get_object_prefix":
                        R.eq(d["value"], b"rbd_data." + h.encode(), "wire get_object_prefix == rbd_data.<id>")
                        L["prefix"] = d["value"].decode()
                    elif d["call"] == "rbd.get_snapcontext":
                        R.check(snapcontext_valid(d["seq"], d["snaps"]), "wire snapcontext valid (2.5)")
                        if t:
                            R.eq((d["seq"], d["snaps"]), (0, t["snaps"]), "wire snapcontext == ground truth %s" % h)
                    elif d["call"] == "rbd.get_flags":
                        R.eq(d["flags"], 0, "wire get_flags == 0")
                    elif d["call"] == "rbd.get_data_pool":
                        R.eq(d["pool"], -1, "wire get_data_pool == -1")
                    elif d["call"] == "rbd.parent_get":
                        p = d["parent"]
                        R.eq((p["pool"], p["ns"], p["image_id"], p["snap"]), (-1, b"", b"", CEPH_NOSNAP),
                             "wire parent_get default spec")
                    elif d["call"] == "rbd.parent_overlap_get":
                        R.eq(d["overlap"], None, "wire parent_overlap_get not set (u8 0)")
                        R.eq(outb, b"\x00", "wire parent_overlap_get bytes are a single 00")
                    elif d["call"] == "lock.get_info":
                        R.eq(inb, enc_lock_get_info_in("rbd_lock"), "wire lock get_info input = note 2.7 example bytes")
                    elif d["call"] == "rbd.get_id":
                        m2 = re.fullmatch(rb"rbd_id\.(.+)", oid)
                        R.check(m2 is not None, "get_id sent to rbd_id.<name>")
                        R.check(re.fullmatch(rb"[0-9a-zA-Z]+", d["value"]) is not None and len(d["value"]) > 0,
                                "wire id is non-empty alphanumeric")
                        if m2:
                            for img, tt in ctx.get("gt4_images", {}).items():
                                if img == m2.group(1).decode():
                                    R.eq(d["value"], tt["id"].encode(), "wire get_id(%s) == ground truth" % img)
                    elif d["call"] == "lock.lock":
                        locks[(pname, c.key, oid)].append(("lock", d["in"], e))
                    elif d["call"] == "lock.unlock":
                        locks[(pname, c.key, oid)].append(("unlock", d["in"], e))
                    elif d["call"] == "lock.assert_locked":
                        locks[(pname, c.key, oid)].append(("assert", d["in"], e))
                for i, o in enumerate(m["ops"]):
                    opcodes_seen.add(o.code)
                    if o.code == OP_CALL:
                        cl, ml, argc, il = o.cls()
                        call_fr.append((argc == 0 and o.union[7:] == b"\0" * 21 and o.payload_len == cl + ml + il))
                        if rp is not None and rp["result"] >= 0:
                            ro = rp["ops"][i]
                            call_echo.append((ro.code == OP_CALL and ro.union[:7] == o.union[:7] and
                                              struct.unpack_from("<Q", ro.union, 8)[0] == ro.payload_len))
                    if o.code == 0x220F:
                        watches[(pname, c.key, oid)].append(struct.unpack_from("<Q", o.union, 0)[0])
                if h and kinds:
                    open_kinds[pname].append((h, tuple(kinds), e))
                    names = tuple(kinds)
                    ins = [x[2] for x in cops]
                    if names == VEC_A:
                        R.eq(ins, [NOSNAP_B, b"", NOSNAP_B + b"\x01"], "vector A inputs (2.6)")
                    elif names == VEC_B:
                        R.check(ins[0] == NOSNAP_B and ins[1] in (NOSNAP_B + b"\x00", NOSNAP_B + b"\x01") and
                                ins[2] == NOSNAP_B and ins[3] == b"" and ins[4] == enc_lock_get_info_in("rbd_lock"),
                                "vector B inputs (2.6)", repr([x.hex() for x in ins]))
                    elif names == VEC_C:
                        R.eq(ins, [b"", NOSNAP_B], "vector C inputs (2.6 step C)")
                    counts["vec:" + "+".join(names)] += 1
                # ---- data path
                mo = re.fullmatch(rb"(rbd_data\.[0-9a-zA-Z]+)\.([0-9a-f]{16})", oid)
                if mo:
                    names = [o.name() for o in m["ops"]]
                    objno = int(mo.group(2), 16)
                    prefix = mo.group(1).decode()
                    for i, o in enumerate(m["ops"]):
                        if o.name() == "WRITE":
                            off, ln, tsz, tseq = o.extent()
                            R.eq((ln, tsz, tseq), (o.payload_len, 0, 0), "WRITE extent length == payload_len, truncate fields 0/0 (2.11)")
                            R.check(names in (["SETALLOCHINT", "WRITE"], ["WRITE"]), "write op vector [SETALLOCHINT] WRITE (3.6)", repr(names))
                            data_w[(pname, prefix)].append((objno, off, m["op_in"][i], m["snap_seq"], m["snaps"]))
                        elif o.name() == "SETALLOCHINT":
                            eos, ews, fl = struct.unpack_from("<QQI", o.union, 0)
                            R.eq((o.flags, eos, ews, fl), (0x2, 4 << 20, 4 << 20, 0),
                                 "SETALLOCHINT FAILOK, object size twice, flags 0 (2.11)")
                        elif o.name() == "SPARSE_READ" and rp is not None:
                            off, ln, tsz, tseq = o.extent()
                            outb = rp["op_out"][i]
                            rr = Rd(outb)
                            n = rr.u32()
                            ext = [(rr.u64(), rr.u64()) for _ in range(n)]
                            dl = rr.u32()
                            dat = rr.take(dl)
                            rr.done("sparse read reply")
                            R.eq(sum(x[1] for x in ext), dl, "SPARSE_READ reply: sum(extent lengths) == data length (2.11)")
                            if ext:
                                R.check(ext[0][0] >= off and ext[-1][0] + ext[-1][1] <= off + ln,
                                        "SPARSE_READ extents lie inside the request range, offsets object-relative")
                            data_r[(pname, prefix)].append((objno, off, ln, ext, dat))
                        elif o.name() == "READ":
                            pass
    # ---- aggregate checks
    R.group("op vectors of 2.6 / 3.1 (rbd info sessions)")
    for pname in sorted(open_kinds):
        if "rbd-info-v1" not in pname and "def-rbd-info" not in pname:
            continue
        seq = [k for (_, k, _) in open_kinds[pname]]
        want = [VEC_A, ("get_create_timestamp",), ("get_access_timestamp", "get_modify_timestamp"),
                ("get_data_pool",), VEC_B, VEC_C]
        R.eq(seq[:6], want, "%s: open sequence A, timestamps, data pool, B, C (2.6)" % pname)
        # STAT then get_id on rbd_id.<name>, as two requests (3.1)
    for pname in sorted(conns_by_pcap):
        if "rbd-info-v1" not in pname and "def-rbd-info" not in pname:
            continue
        ids = []
        for c in conns_by_pcap[pname]:
            for e in c.exch:
                if e.req["oid"].startswith(b"rbd_id."):
                    ids.append((e.req_hdr[0]["tid"], [o.name() for o in e.req["ops"]]))
        R.eq([x[1] for x in sorted(ids)], [["STAT"], ["CALL"]], "%s: STAT rbd_id.<name> then get_id as separate requests (3.1)" % pname)
    R.group("ENOENT / EPERM on the wire (2.2, 2.11)")
    whole = [x for x in enoent if x[1] == b"rbd_mirroring" or x[1].endswith(b".rbd") or x[1].startswith(b"journal.")
             or (x[1].startswith(b"rbd_id.") and x[2] == ["STAT"])]
    meth = [x for x in enoent if x[1] == b"rbd_directory"]
    dele = [x for x in enoent if x[2] == ["DELETE"]]
    R.check(len(whole) > 0, "saw read requests on objects that do not exist (%d)" % len(whole))
    for (pname, oid, names_, rvals, outl, fl) in whole:
        if fl & 0x20:
            continue  # a mutating request on a missing object: the op itself reports it, see DELETE below
        R.check(all(v == 0 for v in rvals) and all(x == 0 for x in outl),
                "read-only request on a missing object: result -2, every rval 0, no output: %s %r %r" % (pname, oid, names_))
    R.check(len(meth) > 0, "saw a method-level ENOENT (dir_get_name on an existing rbd_directory) (%d)" % len(meth))
    for (pname, oid, names_, rvals, outl, fl) in meth:
        R.eq(rvals, [-2], "method returned -ENOENT: the op's rval is -2 as well (%s)" % pname)
    R.check(len(dele) > 0, "saw DELETE of a missing object (%d)" % len(dele))
    for (pname, oid, names_, rvals, outl, fl) in dele:
        R.eq(rvals, [-2], "DELETE on a missing object: result -2 and rval -2 (%s %r)" % (pname, oid))
    if eperm:
        R.check(True, "saw -1 (EPERM) for CALLs by a client with only `osd r` (%d)" % len(eperm))
    else:
        R.skip("saw -1 (EPERM) for CALLs by a client with only `osd r`",
               "needs a session by a read-only cephx user (x-t0-ro); not in the public set (it has no such user)")
    for (pname, oid, rvals) in eperm:
        R.check(all(v == 0 for v in rvals), "EPERM fails the whole request, rvals 0 (%s)" % pname)
    R.group("call op record and op codes (2.2, 2.11)")
    R.check(len(call_fr) >= MIN_CALL_OPS and all(call_fr), "all %d CALL ops: argc 0, bytes 7..27 of the union zero, payload_len = class_len + method_len + indata_len (2.2)" % len(call_fr))
    R.check(len(call_echo) >= MIN_CALL_OPS and all(call_echo), "all %d CALL replies: op record echoed, union bytes 8..15 (extent length) = output length (2.2)" % len(call_echo))
    for code, name in ((0x1201, "READ"), (0x1202, "STAT"), (0x1205, "SPARSE_READ"), (0x2201, "WRITE"), (0x2202, "WRITEFULL"),
                       (0x220D, "CREATE"), (0x2205, "DELETE"), (0x2223, "SETALLOCHINT"), (0x1401, "CALL"), (0x220F, "WATCH")):
        R.check(code in opcodes_seen, "op code 0x%04x (%s) seen on the wire in a request that behaved as that op" % (code, name))
    ctx["opcodes_seen"] = opcodes_seen
    ctx["wire_counts"] = counts
    ctx["undescribed"] = undescribed
    # ---- locks and watches of the librbd writer
    R.group("exclusive lock as librbd does it (3.9)")
    nlock = 0
    for (pname, ckey, oid), ev in sorted(locks.items(), key=lambda kv: str(kv[0])):
        if not oid.startswith(b"rbd_header."):
            continue
        lk = [x for x in ev if x[0] == "lock"]
        ul = [x for x in ev if x[0] == "unlock"]
        for kind, d, e in lk:
            nlock += 1
            R.check(d["name"] == "rbd_lock" and d["type"] == LOCK_EXCLUSIVE and re.fullmatch(r"auto \d+", d["cookie"]) is not None
                    and d["tag"] == "internal" and d["desc"] == "" and d["duration"] == (0, 0) and d["flags"] == 0,
                    "lock input: rbd_lock, EXCLUSIVE, cookie `auto <n>`, tag internal, no desc/duration/flags", repr(d))
            R.eq(e.rep["result"] if e.rep else None, 0, "lock call succeeded")
            handle = int(d["cookie"].split()[1])
            w = watches.get((pname, ckey, oid), [])
            R.check(handle in w, "lock cookie handle == cookie field of the header WATCH op (T7)", "%d in %r" % (handle, w))
        for kind, d, e in ul:
            R.check(re.fullmatch(r"auto \d+", d["cookie"]) is not None and d["name"] == "rbd_lock",
                    "unlock input: rbd_lock + same cookie", repr(d))
            R.check(any(x[1]["cookie"] == d["cookie"] for x in lk), "unlock cookie equals the cookie that was locked")
    if nlock > 0:
        R.check(True, "saw the librbd exclusive-lock acquire (%d)" % nlock)
    else:
        R.skip("saw the librbd exclusive-lock acquire",
               "needs a write session on a default-feature image (exclusive-lock enabled); the public set writes only to "
               "layering-only images")
    # ---- data path from the bench sessions
    R.group("data path: object names, extent mapping, write context (2.1.1, 2.10, 3.5, 3.6)")
    for (pname, prefix), ws in sorted(data_w.items()):
        if "bench" not in pname:
            continue
        lossy = bool(drops.get(pname))
        offs = sorted(o * (4 << 20) + off for (o, off, _, _, _) in ws)
        img_size, nthr, iosz, iotot = bench_shape(cap, pname)
        R.check(all(x % 65536 == 0 for x in offs) and len(set(offs)) == len(offs) and offs[-1] < img_size,
                "%s %s: writes are distinct 64 KiB-aligned image offsets inside the image (objno*4MiB+off)" % (pname, prefix))
        # rbd bench seq with N threads: N sequential runs of io_total / N bytes, one per N-th of the image
        want = sorted(t * (img_size // nthr) + j * iosz for t in range(nthr) for j in range(iotot // iosz // nthr))
        shape = "4 runs of 32 x 64 KiB at 0,16,32,48 MiB" if (img_size, nthr, iosz, iotot) == BENCH_DEFAULT else (
            "%d runs of %d x %d KiB at multiples of %d MiB (command line in cmd/%s.cmd)" % (
                nthr, iotot // iosz // nthr, iosz >> 10, (img_size // nthr) >> 20, pname))
        if lossy:
            R.check(set(offs) <= set(want), "%s: captured writes are a subset of the 4x2 MiB bench pattern (lossy capture)" % pname)
        else:
            R.eq(offs, want, "%s: bench writes = %s; names rbd_data.<id>.%%016x of objno" % (pname, shape))
        R.check(all(sq == 0 and sn == [] for (_, _, _, sq, sn) in ws), "%s writes carry (seq 0, no snaps) when the image has no snapshot" % pname)
        rs = data_r.get((pname, prefix), [])
        if rs:
            wmap = {}
            for (o, off, payload, _, _) in ws:
                wmap[(o, off)] = payload
            hit = 0
            ok = True
            for (o, off, ln, ext, dat) in rs:
                if (o, off) in wmap:
                    hit += 1
                    if ext != [(off, ln)] or dat != wmap[(o, off)]:
                        ok = False
            R.check(ok and (hit == len(rs) or lossy), "%s: SPARSE_READ data equals what was written at the same (object, offset)" % pname,
                    "hit %d of %d" % (hit, len(rs)))
    ctx["data_w"] = data_w
    ctx["data_r"] = data_r
    ctx["locks"] = locks
    ctx["watches"] = watches


# ---------------------------------------------------------------------------
# extra experiments (captures/rbd-extra): requests the stock tools never send.
# The lab probe (kept outside the repository, it links Ceph's librados) wrote a
# list of steps; the wire is the evidence, the list only labels it.
# ---------------------------------------------------------------------------

NOTE_LOCK_EXAMPLE = bytes.fromhex(
    "010124000000" "080000007262645F6C6F636B" "01" "0100000063" "0100000074" "00000000" "0000000000000000" "00")
NOTE_GET_INFO_EXAMPLE = bytes.fromhex("01010C000000080000007262645F6C6F636B")


def op_key(e, i):
    o = e.req["ops"][i]
    d = e.req["op_in"][i]
    if o.code == OP_CALL:
        cl, ml, argc, il = o.cls()
        return ("call", d[:cl].decode(), d[cl:cl + ml].decode(), d[cl + ml:])
    off, ln, tsz, tseq = o.extent()
    n = o.name()
    if n == "READ":
        return ("read", off, ln)
    if n == "STAT":
        return ("stat",)
    if n == "ZERO":
        return ("zero", off, ln)
    if n == "TRUNCATE":
        return ("trunc", off)
    if n == "DELETE":
        return ("del",)
    if n == "CREATE":
        return ("create", bool(o.flags & 1))
    if n == "WRITE":
        return ("write", off, ln)
    return (n,)


def exch_sig(e):
    return [op_key(e, i) for i in range(len(e.req["ops"]))]


def step_sig(s):
    k = s["kind"]
    if k == "exec":
        return [("call", s["cls"], s["method"], bytes.fromhex(s["input"]))]
    out = []
    for o in s["ops"]:
        t = o[0]
        if t == "call":
            out.append(("call", o[1], o[2], bytes.fromhex(o[3])))
        elif t == "read":
            out.append(("read", o[1], o[2]))
        elif t == "stat":
            out.append(("stat",))
        elif t == "zero":
            out.append(("zero", o[1], o[2]))
        elif t == "truncate":
            out.append(("trunc", o[1]))
        elif t == "remove":
            out.append(("del",))
        elif t == "create":
            out.append(("create", bool(o[1])))
        elif t == "write":
            ln = o[1] if isinstance(o[1], int) else len(o[1]) // 2
            out.append(("write", o[2], ln))
        else:
            out.append((t,))
    return out


def conn_gid(c):
    for fr in c.ssi.frames:
        if fr.tag == T_AUTH_DONE and len(fr.segs[0]) >= 8:
            return struct.unpack_from("<Q", fr.segs[0], 0)[0]
    return None


def match_steps(steps, conns):
    """pair every labelled step with the wire exchange that carries it (same oid, same op vector, in order)"""
    pool = []
    for ci, c in enumerate(conns):
        # a connection that performs librbd's open sequence belongs to a CLI command, not to the probe client
        if any(exch_sig(e) and exch_sig(e)[0][:3] == ("call", "rbd", "get_create_timestamp") for e in c.exch):
            continue
        for e in c.exch:
            pool.append((ci, e.req_hdr[0]["tid"], e, c))
    used = set()
    out = {}
    for s in steps:
        if s.get("kind") not in ("exec", "rop", "wop"):
            continue
        sig = step_sig(s)
        oid = s["oid"].encode()
        for idx, (ci, tid, e, c) in enumerate(pool):
            if idx in used or e.req["oid"] != oid:
                continue
            if exch_sig(e) == sig:
                used.add(idx)
                out[s["step"]] = (s, e, c)
                break
    return out


def wire_outs(e):
    return e.rep["op_out"] if e.rep else None


def check_extra(cap, ctx, conns_by_pcap, sessions, drops):
    d = os.path.join(cap, "rbd-extra")
    if not os.path.isdir(d):
        R.group("rbd-extra (not present)")
        R.check(True, "no rbd-extra directory: lab probe checks skipped")
        return
    steps = jload(os.path.join(d, "probe1.json")) + jload(os.path.join(d, "probe2.json"))
    ids = jload(os.path.join(d, "setup.json"))
    cliidx = {}
    for ln in open(os.path.join(d, "cli", "index.tsv")):
        f = ln.rstrip("\n").split("\t")
        cliidx[f[0]] = (int(f[1]), float(f[2]), f[3])

    def cli_out(name):
        return open(os.path.join(d, "cli", name + ".out"), errors="replace").read()

    conns = []
    for pn in ("probe-a", "probe-b"):
        p = os.path.join(d, "pcap", pn + ".pcap")
        cs = load_conns(p)
        conns += cs
        ctx.setdefault("probe_conns", {})[pn] = cs
    bad = [(c.key, c.problems[:1]) for c in conns if c.problems]
    R.group("probe pcaps: frames and messages")
    R.check(not bad, "every message of the probe captures decodes", repr(bad[:2]))
    R.check(all(not (fr.problems) for c in conns if not c.secure for fr in c.csi.frames + c.ssi.frames),
            "every frame of the probe captures passes its CRC / length checks")
    mdrop = re.search(r"(\d+) packets dropped by kernel", open(os.path.join(d, "tcpdump.err")).read())
    R.check(mdrop is not None and int(mdrop.group(1)) == 0, "tcpdump dropped no packet during the probe")
    m = match_steps(steps, conns)
    R.group("probe: steps found on the wire")
    wire_steps = [s for s in steps if s.get("kind") in ("exec", "rop", "wop")]
    missing = [s["step"] for s in wire_steps if s["step"] not in m]
    R.check(not missing, "all %d labelled steps are present on the wire with the same op vector" % len(wire_steps), repr(missing[:6]))
    for label, (s, e, c) in m.items():
        if s["kind"] == "exec":
            want = s["rc"] if s["rc"] is not None and s["rc"] < 0 else (s["errno"] and -s["errno"]) or 0
            got = e.rep["result"]
            if s["errno"]:
                R.eq(got, -s["errno"], "%s: wire result == API errno" % label)
            else:
                R.check(got >= 0 and e.rep["op_out"][0].hex() == s["out"], "%s: wire output == API output" % label)
        elif s["kind"] in ("rop", "wop"):
            R.eq(e.rep["result"], s["rc"], "%s: wire result == API result" % label)

    def W(label):
        t = m.get(label)
        return t[1] if t else None

    # -------------------------------------------------------------- T17 / T18
    R.group("multi-op class calls and failing ops (2.2, 3.2, T17, T18)")
    for img, feats in (("t0-feat-3d", 0x3D), ("t0-feat-05", 0x05)):
        e = W("t17.six_op." + img)
        if e is None:
            continue
        rp = e.rep
        R.check(rp["result"] == 0 and rp["rvals"] == [0] * 6 and len(rp["op_out"]) == 6 and all(rp["op_out"]),
                "%s: six `call` ops in one request: result 0, six rvals 0, six outputs (3.2 request 1)" % img)
        try:
            ds = [decode_call(cl, me, inb, out) for (cl, me, inb, out, rv) in call_ops(e)]
            R.eq((ds[0]["order"], ds[0]["size"]), (22, 16 << 20), "%s six-op: get_size" % img)
            R.eq(ds[1]["value"], b"rbd_data." + ids[img].encode(), "%s six-op: get_object_prefix" % img)
            R.eq((ds[2]["features"], ds[2]["incompatible"]), (feats, 1), "%s six-op: get_features(read_only)" % img)
            R.eq(ds[3]["flags"], 0, "%s six-op: get_flags" % img)
            R.eq((ds[4]["seq"], ds[4]["snaps"]), (0, []), "%s six-op: get_snapcontext" % img)
            R.eq((ds[5]["info"]["lockers"], ds[5]["info"]["type"]), ([], 0), "%s six-op: lock get_info (no lock ever taken)" % img)
        except DecodeError as ex:
            R.check(False, "%s six-op outputs decode: %s" % (img, ex))
    e = W("t18.fail_middle")
    if e:
        rp = e.rep
        R.eq((rp["result"], rp["rvals"]), (-ENOEXEC, [0, -ENOEXEC, 0]), "failing middle op: result and rval are -ENOEXEC (8), other rvals 0")
        R.check(len(rp["op_out"][0]) == 9 and rp["op_out"][1] == b"" and rp["op_out"][2] == b"",
                "outputs of the ops BEFORE the failing one are delivered; the failing op and the one after have none (2.2, Q4)")
        R.check(rp["ops"][0].payload_len == 9 and rp["ops"][1].payload_len == 0 and rp["ops"][2].payload_len == 0,
                "per-op payload_len echoes the output length (2.2)")
    e = W("t18.fail_middle_failok")
    if e:
        rp = e.rep
        R.check(e.req["ops"][1].flags == 0x2 and e.req["ops"][0].flags == 0 and e.req["ops"][2].flags == 0,
                "FAILOK is the per-op flag 0x2 on the failing op only (2.2)")
        R.eq((rp["result"], rp["rvals"]), (0, [0, -ENOEXEC, 0]), "FAILOK: request result 0, the op keeps rval -8, later ops still run")
        R.check(len(rp["op_out"][0]) == 9 and rp["op_out"][1] == b"" and len(rp["op_out"][2]) > 0, "FAILOK: outputs of ops 1 and 3 present, 2 empty")
    e = W("t18.fail_first")
    if e:
        R.eq((e.rep["result"], e.rep["rvals"], [len(x) for x in e.rep["op_out"]]), (-ENOEXEC, [-ENOEXEC, 0], [0, 0]),
             "first op fails: later op not executed (rval 0, no output)")
    e = W("t18.fail_last")
    if e:
        R.eq((e.rep["result"], e.rep["rvals"], [len(x) for x in e.rep["op_out"]]), (-ENOEXEC, [0, -ENOEXEC], [9, 0]),
             "last op fails: first output delivered")
    for lab in ("t18.missing_object_two_ops", "t18.missing_object_stat_call"):
        e = W(lab)
        if e:
            R.eq((e.rep["result"], e.rep["rvals"], [len(x) for x in e.rep["op_out"]]), (-ENOENT, [0, 0], [0, 0]),
                 "%s: object missing -> whole request -ENOENT, all rval 0, no output (2.2)" % lab)
    # -------------------------------------------------------------- errno table
    R.group("method error numbers on the wire (2.3, 3.1, errno values of 1.4)")
    table = [("t4.get_features.empty_input", -22), ("t4.get_features.short_input", -22), ("t4.get_size.empty_input", -22),
             ("t4.get_size.unknown_snap", -2), ("t4.get_flags.unknown_snap", -2),
             ("t4.get_stripe_unit_count.nostriping", -8), ("t4.get_id.missing", -2), ("t4.get_id.empty_object", -2),
             ("t4.get_id.garbage_object", -5), ("t4.dir_get_id.missing", -2), ("t4.dir_get_name.missing", -2),
             ("t4.unknown_method", -95), ("t4.unknown_class", -1), ("t4.lock.get_info.garbage_input", -22),
             ("t4.lock.get_info.missing_object", -2)]
    for lab, want in table:
        e = W(lab)
        if e:
            R.eq(e.rep["result"], want, "%s -> %d on the wire (negative Linux errno)" % (lab, want))
    e = W("t4.get_features.ro_false")
    for lab in ("t4.get_features.ro_false", "t4.get_features.ro_true", "t4.get_features.ro_2", "t4.get_features.trailing"):
        e = W(lab)
        if e:
            R.check(e.rep["result"] >= 0 and len(e.rep["op_out"][0]) == 16, "%s accepted (extra / odd trailing bytes are tolerated)" % lab)
    e = W("t4.get_stripe_unit_count.striped")
    if e:
        R.eq(decode_call("rbd", "get_stripe_unit_count", b"", e.rep["op_out"][0]), {"call": "rbd.get_stripe_unit_count",
             "stripe_unit": 65536, "stripe_count": 4}, "get_stripe_unit_count: u64 stripe_unit then u64 stripe_count (2.3)")
    e = W("t4.lock.get_info.other_name")
    if e:
        R.eq(e.rep["op_out"][0], bytes.fromhex("010109000000000000000000000000"), "lock get_info for a lock name that was never taken: empty map, type 0, empty tag")
    # -------------------------------------------------------------- feature matrix
    R.group("feature matrix, parent, data pool, snapshots (2.3 - 2.8, T14)")
    want_feats = {"t0-feat-01": 0x1, "t0-feat-05": 0x5, "t0-feat-21": 0x21, "t0-feat-25": 0x25, "t0-feat-45": 0x45,
                  "t0-feat-3d": 0x3D, "t0-feat-str": 0x3, "t0-feat-snap": 0x1, "t0-feat-clone": 0x1, "t0-feat-dp": 0x81}
    omaps = {s["step"][len("t3.omap."):]: s for s in steps if s["step"].startswith("t3.omap.")}
    matrix = {}
    for img, f in want_feats.items():
        e = W("t14.matrix." + img)
        if not e:
            continue
        try:
            ds = [decode_call(cl, me, inb, out) for (cl, me, inb, out, rv) in call_ops(e)]
        except DecodeError as ex:
            R.check(False, "%s matrix decodes: %s" % (img, ex))
            continue
        matrix[img] = ds
        R.eq(ds[2]["features"], f, "%s features == %#x (%s)" % (img, f, ",".join(feature_names(f))))
        R.eq(ds[2]["incompatible"], expected_incompat(f, True), "%s incompatible(read_only) = features & RO mask" % img)
        R.eq(ds[3]["incompatible"], expected_incompat(f, False), "%s incompatible(read-write) = features & RW mask" % img)
        pool_prefix = "rbd_data.2." if img == "t0-feat-dp" else "rbd_data."
        R.eq(ds[1]["value"].decode(), pool_prefix + ids[img], "%s object prefix" % img)
        R.eq(ds[6]["pool"], ids["t0-data-pool-id"] if img == "t0-feat-dp" else -1, "%s data pool id" % img)
        R.eq(ds[4]["flags"], 0, "%s flags" % img)
        R.eq(ds[9]["op_features"], 0, "%s op_features" % img)
        R.check(snapcontext_valid(ds[5]["seq"], ds[5]["snaps"]), "%s snapshot context valid (2.5)" % img)
        om = omaps.get(img)
        if om and "vals" in om:
            keys = set(om["vals"])
            base = {"access_timestamp", "create_timestamp", "features", "modify_timestamp", "object_prefix", "order", "size", "snap_seq"}
            extra = set()
            if img == "t0-feat-str":
                extra |= {"stripe_unit", "stripe_count"}
            if img == "t0-feat-dp":
                extra |= {"data_pool_id"}
            if img == "t0-feat-clone":
                extra |= {"parent"}
            if img in ("t0-feat-snap", "t0-feat-01"):
                extra |= {k for k in keys if k.startswith("snapshot_")}
            R.eq(keys, base | extra, "%s header omap key set (2.4)" % img)
            R.eq(struct.unpack("<Q", bytes.fromhex(om["vals"]["features"]))[0], f, "%s omap features" % img)
            if img == "t0-feat-str":
                R.eq((struct.unpack("<Q", bytes.fromhex(om["vals"]["stripe_unit"]))[0],
                      struct.unpack("<Q", bytes.fromhex(om["vals"]["stripe_count"]))[0]), (65536, 4), "striped: omap stripe_unit / stripe_count are u64 each")
            if img == "t0-feat-dp":
                R.eq(struct.unpack("<q", bytes.fromhex(om["vals"]["data_pool_id"]))[0], ids["t0-data-pool-id"], "data pool: omap data_pool_id is an i64")
            if img == "t0-feat-clone":
                pv = bytes.fromhex(om["vals"]["parent"])
                R.check(pv[0] >= 2 and pv[1] <= pv[0], "clone: omap `parent` is a versioned struct, v%d/compat%d (2.12 says v2 from Nautilus on)" % (pv[0], pv[1]))
                ctx["parent_omap_hdr"] = (pv[0], pv[1])
            if img in ("t0-feat-snap",):
                sk = sorted((int(k[9:], 16) for k in keys if k.startswith("snapshot_")), reverse=True)
                R.eq(ds[5]["snaps"], sk, "snapshots: get_snapcontext ids == snapshot_<16 hex> keys, strictly descending, gap kept (2.5)")
                R.eq(ds[5]["seq"], max(sk), "snapshots: seq == newest id")
    if "t0-feat-clone" in matrix:
        ds = matrix["t0-feat-clone"]
        p = ds[7]["parent"]
        R.eq((p["v"], p["compat"], p["pool"], p["image_id"].decode()), (1, 1, 2, ids["t0-feat-01"]), "clone: parent_get = (pool 2, parent image id)")
        R.check(p["snap"] not in (CEPH_NOSNAP, CEPH_SNAPDIR) and p["ns"] == b"", "clone: parent snap id is a real snapshot id, namespace empty")
        R.eq(ds[8]["overlap"], 16 << 20, "clone: parent_overlap_get = Some(image size)")
        R.check(ds[2]["features"] & 0x100 == 0 and ds[9]["op_features"] == 0,
                "clone: the `operations` feature bit and op_features are NOT set, so a clone is only detectable through parent_get")
        e = W("t4.get_parent.clone")
        if e:
            gp = decode_call("rbd", "get_parent", NOSNAP_B, e.rep["op_out"][0])["parent"]
            R.eq((gp["pool"], gp["image_id"].decode(), gp["snap"], gp["overlap"]), (2, ids["t0-feat-01"], p["snap"], 16 << 20),
                 "clone: legacy get_parent agrees with parent_get")
    # -------------------------------------------------------------- object semantics
    R.group("OSD object semantics seen on the wire (2.11, 3.5, T10, T19)")
    e = W("t10.read_whole_len0")
    iid = ids["t0-feat-01"]
    want_obj = enc_string(iid.encode())
    for lab, wantb in (("t10.read_whole_len0", want_obj), ("t10.read_len_0_off_4", want_obj[4:]), ("t10.read_crossing_end", want_obj[4:]),
                       ("t10.read_at_end", b""), ("t10.read_past_end", b"")):
        e = W(lab)
        if e:
            R.check(e.rep["result"] == 0 and e.rep["op_out"][0] == wantb, "%s -> %d bytes, success" % (lab, len(wantb)))
    e = W("t10.read_whole_len0")
    if e:
        R.eq(e.rep["op_out"][0], want_obj, "READ offset 0 length 0 returns the `u32 len + id` bytes of rbd_id.<name> (3.1 alternative, 2.11)")
    for lab in ("t19.read_missing", "t19.stat_missing"):
        e = W(lab)
        if e:
            R.eq((e.rep["result"], e.rep["rvals"]), (-ENOENT, [0]), "%s: read-only request on a missing object -> -ENOENT, rval 0" % lab)
    for lab, res in (("t19.zero_missing", 0), ("t19.truncate_missing", 0), ("t19.write0_missing", 0), ("t19.create_excl", 0),
                     ("t19.create_nonexcl_again", 0), ("t19.delete_missing", -2), ("t19.create_excl_again", -17)):
        e = W(lab)
        if e:
            R.eq(e.rep["result"], res, "%s -> %d" % (lab, res))
    e = W("t19.delete_missing")
    if e:
        R.eq(e.rep["rvals"], [-2], "DELETE of a missing object in a mutating request: the op's own rval is -2")
    stats = {s["step"]: s for s in steps if s.get("kind") == "stat"}
    R.check(stats["t19.zero_missing.exists_after"]["stat"] is None and stats["t19.truncate_missing.exists_after"]["stat"] is None,
            "ZERO and TRUNCATE on a missing object succeed and do NOT create it")
    R.eq(stats["t19.write0_missing.exists_after"]["stat"][0], "0", "WRITE of length 0 on a missing object creates it with size 0 (Q5)")
    e = W("t10.read_hole_range")
    if e:
        o = e.rep["op_out"][0]
        R.check(len(o) == (1 << 20) + 4096 and o[:4096] == b"A" * 4096 and o[4096:1 << 20] == b"\0" * ((1 << 20) - 4096) and o[1 << 20:] == b"B" * 4096,
                "READ over a hole: bytes between the two writes are zero, length shortened to the object size (3.5)")
    e = W("t10.read_inside_hole")
    if e:
        R.eq(e.rep["op_out"][0], b"\0" * 4096, "READ entirely inside a hole returns zeros (T10)")
    e = W("t19.zero_to_end")
    if e:
        R.eq(e.rep["ops"][0].name(), "TRUNCATE", "ZERO reaching the object end is echoed back as TRUNCATE (osd-ops 2.7)")
    e = W("t19.zero_inner")
    if e:
        R.eq(e.rep["ops"][0].name(), "ZERO", "ZERO inside the object stays ZERO")
    R.eq(stats["t19.zero_to_end.stat"]["stat"][0], str((1 << 20) + 100), "ZERO to the end leaves size = offset (never grows)")
    R.eq(stats["t19.truncate_extend.stat"]["stat"][0], str(3 << 20), "TRUNCATE beyond the end extends the object")
    R.eq(stats["t19.write0_past_end.stat"]["stat"][0], str(5 << 20), "WRITE of 0 bytes at an offset past the end extends the object")
    # -------------------------------------------------------------- lock class
    R.group("lock class on the wire (2.7, T6, T20)")
    e = W("t20.lock.note_example")
    if e:
        got = op_key(e, 0)[3]
        R.eq(got, NOTE_LOCK_EXAMPLE, "the 42-byte lock example of the note is exactly what was sent (and accepted)")
        R.eq(e.rep["result"], 0, "hand-built lock input from the note is accepted")
        R.eq(len(NOTE_LOCK_EXAMPLE), 42, "example length 42")
        R.eq(enc_lock_in("rbd_lock", 1, "c", "t"), NOTE_LOCK_EXAMPLE, "own encoder reproduces the note's example")
    e = W("t20.get_info.live")
    gid_of = {}
    if e:
        info = dec_lock_info_out(e.rep["op_out"][0])
        R.eq((info["type"], info["tag"], len(info["lockers"])), (LOCK_EXCLUSIVE, b"t", 1), "live lock: type EXCLUSIVE, tag, one locker")
        lk = info["lockers"][0]
        R.eq((lk["etype"], lk["cookie"], lk["desc"], lk["expiration"]), (8, b"c", b"", (0, 0)), "locker: client entity type 8, cookie, empty description, no expiry")
        cn = [c for c in conns if any(x is e for x in c.exch)][0]
        R.eq(lk["num"], conn_gid(cn), "locker entity number == the global id of the connection that sent `lock` (the identity is not supplied by the client)")
        a = lk["addr"]
        R.check(a["form"] == "v2" and (a["v"], a["compat"]) == (1, 1) and a["type"] == 1 and a["elen"] == 16 and a["family"] == 2 and a["ip"] == cn.key[0],
                "locker address (client advertises MSG_ADDR2): marker 1, struct v1/1, type forced to legacy (1), elen 16, AF_INET, client IP", repr(a))
        R.check(a["port"] == 0 and a["tail_zero"], "locker address port is 0 (client messenger does not listen), rest of sa_data zero")
        # the nonce equals the nonce of the client's own address in CLIENT_IDENT
        cid = [fr for fr in cn.csi.frames if TAGS.get(fr.tag) == "CLIENT_IDENT"][0].segs[0]
        r = Rd(cid)
        mk = r.u8()
        cnt = r.u32()
        ad = dec_entity_addr(r)
        R.eq(a["nonce"], ad["nonce"], "locker address nonce == the nonce in the client's CLIENT_IDENT address")
        gid_of["c"] = lk["num"]
    for lab, res in (("t20.lock.same_again", -17), ("t20.lock.same_again_may_renew", 0), ("t20.lock.other_cookie_excl", -16),
                     ("t20.lock.other_tag", -16), ("t20.lock.shared_vs_excl", -16), ("t20.lock.type0", -22), ("t20.lock.empty_name", -22),
                     ("t20.lock.both_renew_flags", -22), ("t20.lock.garbage_input", -22), ("t20.assert_locked.ok", 0),
                     ("t20.assert_locked.wrong_cookie", -16), ("t20.assert_locked.wrong_tag", -16), ("t20.unlock.wrong_cookie", -2),
                     ("t20.unlock.ok", 0), ("t20.unlock.again", -2), ("t20.lock.shared", 0), ("t20.lock.shared_2nd_cookie", 0),
                     ("t20.set_cookie", 0), ("t20.break_lock.s1new", 0), ("t20.break_lock.s2", 0), ("t20.break_lock.again", -2),
                     ("t20.lock.expiring", 0)):
        e = W(lab)
        if e:
            R.eq(e.rep["result"], res, "%s -> %d (2.7 semantics)" % (lab, res))
    # input decoders against what was really sent
    e = W("t20.assert_locked.ok")
    if e:
        R.eq(dec_assert_locked_in(op_key(e, 0)[3]), dict(v=1, compat=1, name="rbd_lock", type=1, cookie="c", tag="t"), "assert_locked input layout (2.7)")
    e = W("t20.set_cookie")
    if e:
        R.eq(dec_set_cookie_in(op_key(e, 0)[3]), dict(v=1, compat=1, name="rbd_lock", type=2, cookie="s1", tag="t", new_cookie="s1new"), "set_cookie input layout (2.7)")
    e = W("t20.break_lock.s2")
    if e:
        bl = dec_break_lock_in(op_key(e, 0)[3])
        R.eq((bl["name"], bl["etype"], bl["cookie"]), ("rbd_lock", 8, "s2"), "break_lock input: name, entity_name_t (u8 type, i64 num), cookie (2.7)")
    e = W("t20.unlock.ok")
    if e:
        R.eq(dec_unlock_in(op_key(e, 0)[3]), dict(v=1, compat=1, name="rbd_lock", cookie="c"), "unlock input layout (2.7)")
    for lab, (ty, tg, n) in (("t20.get_info.after_unlock", (LOCK_EXCLUSIVE, b"t", 0)), ("t20.get_info.end", (LOCK_SHARED, b"t", 0)),
                             ("t20.get_info.expired", (LOCK_EXCLUSIVE, b"t", 0))):
        e = W(lab)
        if e:
            i2 = dec_lock_info_out(e.rep["op_out"][0])
            R.eq((i2["type"], i2["tag"], len(i2["lockers"])), (ty, tg, n),
                 "%s: no locker left, but the lock type and tag of the last holder remain in the record" % lab)
    e = W("t20.get_info.two_shared")
    if e:
        i2 = dec_lock_info_out(e.rep["op_out"][0])
        R.eq([(x["cookie"], x["etype"]) for x in i2["lockers"]], [(b"s1", 8), (b"s2", 8)], "two shared lockers, ordered by (type, num, cookie)")
        R.eq(i2["type"], LOCK_SHARED, "shared lock record type 2")
    e = W("t20.get_info.after_set_cookie")
    if e:
        i2 = dec_lock_info_out(e.rep["op_out"][0])
        R.eq(sorted(x["cookie"] for x in i2["lockers"]), [b"s1new", b"s2"], "set_cookie renamed the cookie of the caller's lock")
    e = W("t20.get_info.expiring")
    if e:
        i2 = dec_lock_info_out(e.rep["op_out"][0])
        R.check(len(i2["lockers"]) == 1 and i2["lockers"][0]["expiration"][0] > 0 and i2["lockers"][0]["expiration"][1] < 10 ** 9,
                "lock with duration 2 s: expiration is an absolute utime (u32 sec, u32 nsec), non-zero")
    e = W("t20.get_info.expired")
    if e:
        R.eq(len(dec_lock_info_out(e.rep["op_out"][0])["lockers"]), 0, "expired locker is dropped from the reply on read (2.7)")
    # -------------------------------------------------------------- foreign lock, capabilities
    R.group("foreign-tag lock and capabilities (3.9 L2, T15, T16)")
    e = W("t15.get_info.foreign")
    if e:
        i2 = dec_lock_info_out(e.rep["op_out"][0])
        lk = i2["lockers"][0]
        R.eq((i2["type"], i2["tag"], lk["cookie"], lk["desc"]), (LOCK_EXCLUSIVE, b"winrbd", b"winrbd probe cookie", b"winrbd probe"), "foreign lock record as sent")
    for lab, res in (("t15.data_write_by_nonholder", 0), ("t15.data_read_by_nonholder", 0), ("t15.data_remove_by_nonholder", 0)):
        e = W(lab)
        if e:
            R.eq(e.rep["result"], res, "%s -> success: the OSD does not check the exclusive lock on data objects (2.7)" % lab)
    e = W("t15.data_read_by_nonholder")
    if e:
        R.eq(e.rep["op_out"][0], b"Z" * 512, "a different cephx identity reads back what it wrote while another identity holds the lock")
    e = W("t16.rbro.read_calls")
    if e:
        R.eq((e.rep["result"], e.rep["rvals"]), (0, [0, 0, 0]), "profile rbd-read-only: get_size / get_features / lock get_info succeed (class-read)")
    e = W("t16.rbro.stat")
    if e:
        R.eq(e.rep["result"], 0, "profile rbd-read-only: STAT succeeds")
    for lab in ("t16.rbro.lock_lock", "t16.rbro.set_id", "t16.rbro.write"):
        e = W(lab)
        if e:
            R.eq(e.rep["result"], -1, "profile rbd-read-only: %s refused with -EPERM (class-write / write needed)" % lab)
    bl = open(os.path.join(d, "blocklist-after.txt")).read()
    client_ips = set(c.key[0] for cs in ctx["probe_conns"].values() for c in cs)
    R.check(client_ips and not any(ip in bl for ip in client_ips),
            "no blocklist entry for the probe client address after the foreign-lock experiment (peers never blocklist an external lock holder)")
    R.check("(30) Read-only file system" in cli_out("t15.snap-create") and "(30) Read-only file system" in cli_out("t15.resize"),
            "librbd `snap create` and `resize` on an image whose lock is held with a foreign tag fail at once with (30) EROFS")
    rc, secs, _ = cliidx["t15.bench"]
    R.check(rc in (137, 124) and secs >= 30, "librbd `bench` (a writer) with a foreign-tag lock never completes (killed after %.0f s, rc %d)" % (secs, rc))
    R.eq(cliidx["t15.bench-after-break"][0], 0, "after break_lock the same `rbd bench` completes (rc 0)")
    a_conns = ctx["probe_conns"]["probe-a"]
    polls = notifies = 0
    for c in a_conns:
        for ex_ in c.exch:
            if ex_.req["oid"] == b"rbd_header." + ids["t0-probe-el"].encode():
                for o in ex_.req["ops"]:
                    if o.code == 0x1206:
                        notifies += 1
                    if o.code == OP_CALL:
                        polls += 1
    R.check(notifies >= 100 and polls >= 100,
            "the stalled writer polls `lock get_info` + a 0x1206/0x1207 op pair in a tight loop: %d polls, %d 0x1206 ops in the first 0.2 s slice" % (polls, notifies))
    ctx["flood"] = (polls, notifies)
    R.check("(22) Invalid argument" in cli_out("q14.create-in-snappool") and "self-managed" in cli_out("q14.create-in-snappool"),
            "rbd create in a pool in pool-snapshot mode is refused by librbd: (22) pool not configured for self-managed snapshot support (Q14)")
    inf = json.loads(cli_out("t14.info-mig-dst"))
    R.eq(inf["features"], ["layering", "migrating"], "image under migration: feature list layering + migrating (0x201)")
    # -------------------------------------------------------------- open sequences incl. conditional calls
    R.group("conditional metadata calls follow the feature bits (3.2, 2.6)")
    allc = []
    for pname, cs in conns_by_pcap.items():
        allc += [(pname, c) for c in cs]
    for pn, cs in ctx["probe_conns"].items():
        allc += [(pn, c) for c in cs]
    n_str = n_nostr = n_op = 0
    for pname, c in allc:
        feats = {}
        calls_by_hdr = collections.defaultdict(list)
        for ex_ in c.exch:
            h = hdr_id(ex_.req["oid"])
            if not h or ex_.rep is None or ex_.rep["result"] < 0:
                continue
            try:
                for (cl, me, inb, out, rv) in call_ops(ex_):
                    calls_by_hdr[h].append(me if cl == "rbd" else cl + "." + me)
                    if me == "get_features" and out is not None and len(out) == 16:
                        feats[h] = struct.unpack("<Q", out[:8])[0]
            except DecodeError:
                pass
        for h, f in feats.items():
            seen = calls_by_hdr[h]
            if not all(x in seen for x in ("get_features", "get_size", "get_data_pool", "get_create_timestamp")):
                continue  # not a librbd open on this connection (the probe client calls methods one by one)
            if f & 0x2:
                n_str += 1
            else:
                n_nostr += 1
            R.eq("get_stripe_unit_count" in seen, bool(f & 0x2), "%s %s: get_stripe_unit_count issued iff STRIPINGV2 (features %#x)" % (pname, h, f))
            R.eq("op_features_get" in seen, bool(f & 0x100), "%s %s: op_features_get issued iff OPERATIONS (features %#x)" % (pname, h, f))
            if f & 0x2 and "get_stripe_unit_count" in seen and "get_object_prefix" in seen:
                R.check(seen.index("get_stripe_unit_count") > seen.index("get_features") and seen.index("get_stripe_unit_count") < seen.index("get_data_pool"),
                        "%s %s: get_stripe_unit_count comes after step A and before get_data_pool (2.6)" % (pname, h))
    R.check(n_str >= 1 and n_nostr >= 10, "open sequences examined: %d striped, %d non-striped" % (n_str, n_nostr))
    # -------------------------------------------------------------- data pool, striping, snapshot context by librbd
    R.group("librbd data path with striping, data pool and snapshots (2.1.1, 2.9, 2.10, 3.6, T9, T12, T13)")
    pa = ctx["probe_conns"]["probe-a"]
    allex = [ex_ for c in pa for ex_ in c.exch]

    def writes_to(prefix):
        out = []
        for ex_ in allex:
            mo = re.fullmatch(re.escape(prefix.encode()) + rb"\.([0-9a-f]{16})", ex_.req["oid"])
            if not mo:
                continue
            for i, o in enumerate(ex_.req["ops"]):
                if o.name() == "WRITE":
                    off, ln, _, _ = o.extent()
                    out.append((ex_.req_hdr[0]["tid"], int(mo.group(1), 16), off, ln, ex_.req["oloc"]["pool"], ex_.req["snap_seq"], ex_.req["snaps"], ex_))
        return sorted(out, key=lambda x: x[0])
    ws = writes_to("rbd_data." + ids["t0-feat-str"])
    want = []
    for b in range(16):
        want += stripe_extents(b * 65536, 65536, 4 << 20, 65536, 4)
    R.eq([(o, off, ln) for (_, o, off, ln, _, _, _, _) in ws], want,
         "striped image (su 64 KiB, sc 4): 16 sequential 64 KiB writes land on objects 0,1,2,3,0,1,... at in-object offsets 0,0,0,0,64K,... (2.10)")
    sizes = {}
    for ln in open(os.path.join(d, "object-sizes.txt")):
        n, sz = ln.split()
        sizes[n] = int(sz)
    R.eq({n.rsplit(".", 1)[1]: v for n, v in sizes.items() if ids["t0-feat-str"] in n}, {"%016x" % i: 262144 for i in range(4)},
         "striped image: the four objects hold 256 KiB each after 1 MiB of writes (stat of the real objects)")
    R.eq(object_count(16 << 20, 4 << 20, 65536, 4), 4, "object count of the striped 16 MiB image (2.9) == `rbd info` objects")
    ws = writes_to("rbd_data.2." + ids["t0-feat-dp"])
    R.check(len(ws) == 2 and all(w[4] == ids["t0-data-pool-id"] for w in ws),
            "data pool image: data object writes go to pool %d (the data pool), names rbd_data.<metadata pool id>.<id>.<16 hex>" % ids["t0-data-pool-id"])
    hp = [ex_ for ex_ in allex if ex_.req["oid"] == b"rbd_header." + ids["t0-feat-dp"].encode()]
    R.check(hp and all(ex_.req["oloc"]["pool"] == 2 for ex_ in hp), "data pool image: header / metadata requests stay in the metadata pool (2)")
    dl = [x.strip() for x in open(os.path.join(d, "t0-data.ls")) if x.strip()]
    R.check("rbd_data.2.%s.0000000000000000" % ids["t0-feat-dp"] in dl, "`rados ls` of the data pool shows rbd_data.2.<id>.0000000000000000 (T13)")
    ws = writes_to("rbd_data." + ids["t0-feat-snap"])
    R.check(len(ws) == 1 and ws[0][5] == 11 and ws[0][6] == [11, 9], "write to an image with snapshots carries the context (seq 11, snaps [11, 9]) from get_snapcontext (3.6, T12)",
            repr([(w[5], w[6]) for w in ws]))
    # -------------------------------------------------------------- migrating
    pb = ctx["probe_conns"]["probe-b"]
    mig_f = None
    for c in pb:
        for ex_ in c.exch:
            if ex_.req["oid"].startswith(b"rbd_header.") and ex_.rep and ex_.rep["result"] >= 0:
                for (cl, me, inb, out, rv) in call_ops(ex_):
                    if me == "get_features" and out and struct.unpack("<Q", out[:8])[0] & 0x200:
                        mig_f = (struct.unpack("<Q", out[:8])[0], struct.unpack("<Q", out[8:])[0], len(inb))
    R.group("migrating image (2.8, T14)")
    R.check(mig_f is not None and mig_f[0] == 0x201 and mig_f[1] == 0x1, "wire get_features of the migration target: 0x201 (layering|migrating), incompatible(read_only) 0x1", repr(mig_f))
    ctx["probe_matched"] = len(m)


# ---------------------------------------------------------------------------
# scrubbed test vectors (harness/vectors/rbd) and their self-check
# ---------------------------------------------------------------------------

DOC_IP = bytes([192, 0, 2, 7])  # TEST-NET-1: replaces the lab client address inside lock records


def jsonable(x):
    if isinstance(x, bytes):
        try:
            t = x.decode("ascii")
            if t.isprintable():
                return t
        except UnicodeDecodeError:
            pass
        return "hex:" + x.hex()
    if isinstance(x, dict):
        return {str(k): jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [jsonable(v) for v in x]
    return x


LAB_CLIENT_IPS = set()  # filled from the probe captures: the client address of every connection


def scrub_addr(b):
    """lab client address -> 192.0.2.7 inside a lock reply (see README: scrubbing)"""
    for ip in LAB_CLIENT_IPS:
        b = b.replace(bytes(int(x) for x in ip.split(".")), DOC_IP)
    return b


def vec_call(vid, source, oid_kind, cls_, meth, inb, outb, result, note=""):
    d = {"id": vid, "source": source, "object": oid_kind, "class": cls_, "method": meth, "input_hex": inb.hex(),
         "output_hex": outb.hex(), "result": result}
    if note:
        d["note"] = note
    if result >= 0:
        dd = decode_call(cls_, meth, inb, outb)
        if dd is not None:
            d["decoded"] = jsonable({k: v for k, v in dd.items() if k not in ("call", "input_raw_ok")})
    return d


def write_vectors(cap, ctx, conns_by_pcap, vec_dir):
    os.makedirs(vec_dir, exist_ok=True)
    gt4 = os.path.join(cap, "gt4")
    calls = []
    for cs in ctx.get("probe_conns", {}).values():
        LAB_CLIENT_IPS.update(c.key[0] for c in cs)
    # 1. rados exec ground truth (stock python binding on the lab cluster)
    for img, label in (("img-v1", "layering-only image"), ("img-default", "default-feature image, lock released"),
                       ("t0-copy-v1.with-snap", "layering image with snapshots 3 (head state at the time of the dump)")):
        meta = jload(os.path.join(gt4, img + ".meta.json"))
        for c in meta["cls_calls"]:
            if "err" in c or c["call"] in ("rbd.metadata_list", "rbd.dir_list", "rbd.get_all_features"):
                continue
            cls_, meth = c["call"].split(".")
            oid = "rbd_header" if "rbd_header" in c["oid"] else c["oid"].split(".")[0]
            calls.append(vec_call("%s/%s/%d" % (img, c["call"], len(calls)), "rados exec, %s" % label, oid, cls_, meth,
                                  bytes.fromhex(c["in"]), scrub_addr(bytes.fromhex(c["out"])), c["rc"]))
    # 2. probe results as seen on the wire
    d = os.path.join(cap, "rbd-extra")
    if os.path.isdir(d):
        steps = jload(os.path.join(d, "probe1.json"))
        mm = match_steps(steps, ctx["probe_conns"]["probe-a"])
        pick = ["t4.get_features.empty_input", "t4.get_size.unknown_snap", "t4.get_stripe_unit_count.nostriping",
                "t4.get_stripe_unit_count.striped", "t4.get_id.empty_object", "t4.get_id.garbage_object", "t4.unknown_method",
                "t4.unknown_class", "t4.get_snapcontext", "t4.parent_get.clone", "t4.parent_overlap_get.clone", "t4.get_parent.clone",
                "t4.get_data_pool.dp", "t20.lock.note_example", "t20.get_info.live", "t20.lock.same_again", "t20.lock.other_cookie_excl",
                "t20.lock.shared_vs_excl", "t20.lock.type0", "t20.lock.both_renew_flags", "t20.assert_locked.wrong_cookie",
                "t20.unlock.wrong_cookie", "t20.get_info.after_unlock", "t20.get_info.two_shared", "t20.set_cookie",
                "t20.break_lock.s2", "t20.get_info.expired", "t15.get_info.foreign"]
        for lab in pick:
            if lab not in mm:
                continue
            s, e, c = mm[lab]
            cl, me, inb = op_key(e, 0)[1:4]
            outb = e.rep["op_out"][0] if e.rep["result"] >= 0 else b""
            note = {"t4.get_features.empty_input": "input missing: -EINVAL (22)",
                    "t4.get_stripe_unit_count.nostriping": "STRIPINGV2 bit clear: -ENOEXEC (8)",
                    "t4.unknown_class": "class name not in the OSD class lists: -EPERM (1), not -EOPNOTSUPP",
                    "t20.get_info.after_unlock": "locker gone, lock type and tag of the last holder remain",
                    "t20.get_info.live": "client address scrubbed to 192.0.2.7 (lab address replaced)"}.get(lab, "")
            calls.append(vec_call(lab, "wire (probe capture)", e.req["oid"].decode().split(".")[0] if e.req["oid"].startswith(b"rbd_") else "scratch object",
                                  cl, me, inb, scrub_addr(outb), e.rep["result"], note))
    json.dump({"_about": "Class-method vectors. input_hex / output_hex are the raw bytes of one `call` op and its reply; result is the "
                         "request result (negative errno on failure). decoded = what the note's layout gives. See README.md.",
               "vectors": calls}, open(os.path.join(vec_dir, "rbd-class-calls.json"), "w"), indent=1)
    # 3. header omap dumps
    omap = {}
    for img in ("img-v1", "img-default", "t0-copy-v1.with-snap"):
        meta = jload(os.path.join(gt4, img + ".meta.json"))
        omap[img] = {"object": "rbd_header.<id>", "omap_hex": {k: v for k, v in meta["header_omap"]},
                     "rbd_id_object_hex": meta["rbd_id_object_hex"], "lock_xattr_hex": meta["xattrs"]["rbd_header." + meta["id"]].get("lock.rbd_lock")}
    if os.path.isdir(d):
        for s in jload(os.path.join(d, "probe1.json")):
            if s["step"].startswith("t3.omap.") and "vals" in s:
                n = s["step"][len("t3.omap."):]
                if n in ("t0-feat-str", "t0-feat-dp", "t0-feat-clone", "t0-feat-snap", "t0-feat-45", "t0-feat-05"):
                    omap[n] = {"object": "rbd_header.<id>", "omap_hex": s["vals"]}
    pool = parse_hexdump_values(open(os.path.join(gt4, "pool-omapvals.txt")).read())
    omap["rbd_directory"] = {"object": "rbd_directory", "omap_hex": {k: v.hex() for k, v in pool["rbd_directory"].items()}}
    json.dump({"_about": "Header and directory omap values (rados listomapvals). Image ids and names are lab values. Timestamps are utime_t "
                         "(u32 sec, u32 nsec). Keys that are absent in a dump are absent on the cluster (2.4).", "images": omap},
              open(os.path.join(vec_dir, "header-omap.json"), "w"), indent=1)
    # 4. whole OSD messages (MOSDOp v9 / MOSDOpReply v8 bodies, crc mode) from the captures
    msgs = []

    def add(label, e, c):
        m, rp = e.req, e.rep
        ent = {"id": label, "oid": m["oid"].decode(), "request": {"front_hex": m["raw_front"].hex(),
                                                                 "ops": [{"op": o.name(), "code": "0x%04x" % o.code, "flags": o.flags,
                                                                          "payload_len": o.payload_len} for o in m["ops"]]},
               "reply": {"front_hex": rp["raw_front"].hex(), "result": rp["result"], "rvals": rp["rvals"],
                         "out_len": [len(x) for x in rp["op_out"]]}}
        if len(m["raw_data"]) <= 600:
            ent["request"]["data_hex"] = m["raw_data"].hex()
        else:
            ent["request"]["data_len"] = len(m["raw_data"])
            ent["request"]["data_note"] = "payload omitted (length only)"
        if len(rp["raw_data"]) <= 600:
            ent["reply"]["data_hex"] = scrub_addr(rp["raw_data"]).hex()
        else:
            ent["reply"]["data_len"] = len(rp["raw_data"])
        msgs.append(ent)

    sel = []
    for pname in ("k2-rbd-info-v1", "k2-rbd-bench-v1", "k2-rbd-bench-default", "k2-rados-small"):
        for c in conns_by_pcap.get(pname, []):
            for e in c.exch:
                sig = tuple(k[1] + "." + k[2] if k[0] == "call" else k[0] for k in exch_sig(e))
                oid = e.req["oid"].decode()
                key = (pname, oid.split(".")[0], sig)
                if key in sel or e.rep is None:
                    continue
                if pname == "k2-rbd-info-v1" and not oid.startswith(("rbd_id", "rbd_header")):
                    continue
                if pname == "k2-rbd-bench-v1" and sig not in (("SETALLOCHINT", "write"), ("read",)):
                    continue
                if pname == "k2-rbd-bench-default" and sig not in (("lock.lock",), ("lock.assert_locked", "rbd.object_map_update")):
                    continue
                if pname == "k2-rados-small" and oid not in ("t0-small", "t0-missing-k2"):
                    continue
                sel.append(key)
                add("%s/%s/%s" % (pname, oid, "+".join(sig)), e, c)
    if os.path.isdir(d):
        for lab in ("t17.six_op.t0-feat-3d", "t18.fail_middle", "t18.fail_middle_failok", "t18.missing_object_two_ops", "t10.read_whole_len0",
                    "t19.zero_to_end", "t19.delete_missing", "t20.get_info.live"):
            if lab in mm:
                add("probe/" + lab, mm[lab][1], mm[lab][2])
    json.dump({"_about": "Whole OSD messages. front_hex is the msgr2 front segment (MOSDOp version 9 / MOSDOpReply version 8); data_hex is the data "
                         "segment when it is small. Everything is plain: no key material is involved at this layer (crc mode). See README.md.",
               "messages": msgs}, open(os.path.join(vec_dir, "osd-messages.json"), "w"), indent=1)
    # 5. striping, names, real object digests
    st = {"_about": "Image byte range -> object extents (default and striped layout), data object names, and the sha256 of real objects "
                    "written through the mapping. Write recipe in README.md.",
          "worked_examples": [
              {"layout": {"object_size": 4194304, "stripe_unit": 4194304, "stripe_count": 1}, "offset": 10485760, "length": 8388608,
               "extents": [list(x) for x in stripe_extents(10 << 20, 8 << 20, 4 << 20)]},
              {"layout": {"object_size": 4194304, "stripe_unit": 65536, "stripe_count": 4}, "offset": 327680, "length": 4096,
               "extents": [list(x) for x in stripe_extents(327680, 4096, 4 << 20, 65536, 4)]},
              {"layout": {"object_size": 4194304, "stripe_unit": 65536, "stripe_count": 4}, "offset": 16777216, "length": 1,
               "extents": [list(x) for x in stripe_extents(16 << 20, 1, 4 << 20, 65536, 4)]}],
          "object_names": [{"prefix": "rbd_data.37863d7ada59", "objno": n, "name": data_object_name("rbd_data.37863d7ada59", n)} for n in (0, 2, 255, 0x3ff)]
                          + [{"prefix": "rbd_data.2.600ecac4b85c", "objno": 255, "name": data_object_name("rbd_data.2.600ecac4b85c", 255)}],
          "object_counts": [{"size": 4 << 30, "object_size": 4 << 20, "stripe_unit": 4 << 20, "stripe_count": 1, "count": 1024},
                            {"size": 16 << 20, "object_size": 4 << 20, "stripe_unit": 65536, "stripe_count": 4, "count": 4},
                            {"size": 10, "object_size": 4 << 20, "stripe_unit": 65536, "stripe_count": 4, "count": object_count(10, 4 << 20, 65536, 4)}],
          "written_objects": []}
    for r in jload(os.path.join(gt4, "t0-copy-def.data-objects.json")):
        st["written_objects"].append({"object_suffix": r["object"].rsplit(".", 1)[1], "size": r["size"], "sha256": r["sha256"]})
    st["write_recipe"] = {"base": "bytes((i*7+3)&0xFF for i in range(1<<20)) written at image offsets 0 and 1073741824 (then copied with `rbd cp`)",
                          "patterns": "pat(n,k) = bytes((i*13+k)%251 for i in range(n))",
                          "writes": [[0, 4096, 1], [12388, 777, 2], [4193792, 1024, 3], [12582913, 5000, 4], [1073741824, 8192, 5], [4294963200, 4096, 6]],
                          "image": {"size": 4294967296, "order": 22, "stripe": "default"}}
    json.dump(st, open(os.path.join(vec_dir, "striping-and-objects.json"), "w"), indent=1)
    print("vectors written to %s" % vec_dir)


def check_vectors(vec_dir):
    R.group("vectors in harness/vectors/rbd decode with the note's layouts")
    p = os.path.join(vec_dir, "rbd-class-calls.json")
    if not os.path.exists(p):
        R.check(True, "no vector files yet (run with --write-vectors)")
        return
    for v in jload(p)["vectors"]:
        try:
            if v["result"] >= 0:
                dd = decode_call(v["class"], v["method"], bytes.fromhex(v["input_hex"]), bytes.fromhex(v["output_hex"]))
                R.eq(jsonable({k: x for k, x in dd.items() if k not in ("call", "input_raw_ok")}), v.get("decoded", jsonable({k: x for k, x in dd.items() if k not in ("call", "input_raw_ok")})),
                     "vector %s decodes to the recorded fields" % v["id"])
            else:
                R.check(v["output_hex"] == "", "vector %s: failed call has no output" % v["id"])
        except DecodeError as ex:
            R.check(False, "vector %s decodes: %s" % (v["id"], ex))
    om = jload(os.path.join(vec_dir, "header-omap.json"))["images"]
    for name, rec in om.items():
        if name == "rbd_directory":
            for k, h in rec["omap_hex"].items():
                R.check(k.startswith(("name_", "id_")) and Rd(bytes.fromhex(h)).string() is not None, "directory omap %s is `u32 len + string`" % k)
            continue
        vals = {k: bytes.fromhex(h) for k, h in rec["omap_hex"].items()}
        R.check(len(vals["size"]) == 8 and len(vals["order"]) == 1 and len(vals["features"]) == 8 and len(vals["snap_seq"]) == 8,
                "%s omap: size u64, order u8, features u64, snap_seq u64" % name)
        R.eq(dec_string_out(vals["object_prefix"]).decode().startswith("rbd_data."), True, "%s omap object_prefix is a string rbd_data.*" % name)
    for m in jload(os.path.join(vec_dir, "osd-messages.json"))["messages"]:
        rq = m["request"]
        data = bytes.fromhex(rq["data_hex"]) if "data_hex" in rq else b"\0" * rq["data_len"]
        try:
            dm = dec_mosdop(bytes.fromhex(rq["front_hex"]), data)
            R.eq([o.name() for o in dm["ops"]], [o["op"] for o in rq["ops"]], "message %s: MOSDOp v9 front decodes, op list matches" % m["id"])
            rp = m["reply"]
            rdata = bytes.fromhex(rp["data_hex"]) if "data_hex" in rp else b"\0" * rp["data_len"]
            dr = dec_mosdopreply(bytes.fromhex(rp["front_hex"]), rdata)
            R.eq((dr["result"], dr["rvals"], [len(x) for x in dr["op_out"]]), (rp["result"], rp["rvals"], rp["out_len"]), "message %s: MOSDOpReply v8 decodes, result/rvals/lengths match" % m["id"])
        except DecodeError as ex:
            R.check(False, "message %s decodes: %s" % (m["id"], ex))
    st = jload(os.path.join(vec_dir, "striping-and-objects.json"))
    for w in st["worked_examples"]:
        L = w["layout"]
        R.eq([list(x) for x in stripe_extents(w["offset"], w["length"], L["object_size"], L["stripe_unit"], L["stripe_count"])], w["extents"],
             "striping example offset %d length %d" % (w["offset"], w["length"]))
    for o in st["object_names"]:
        R.eq(data_object_name(o["prefix"], o["objno"]), o["name"], "object name %s" % o["name"])
    for o in st["object_counts"]:
        R.eq(object_count(o["size"], o["object_size"], o["stripe_unit"], o["stripe_count"]), o["count"], "object count %r" % (o,))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main(argv=None):
    global R
    ap = argparse.ArgumentParser(description="independent checker for docs/spec/rbd-format2.md")
    ap.add_argument("--captures", default=None, help="capture directory (default: harness/vectors/public)")
    ap.add_argument("--vectors-only", action="store_true", help="only decode the committed vectors (no capture set needed)")
    ap.add_argument("--vectors", default=None, help="vector directory (default: harness/vectors/rbd next to this tool)")
    ap.add_argument("--write-vectors", action="store_true", help="(re)write the scrubbed test vectors")
    ap.add_argument("--skip-pcap", action="store_true", help="only check the ground-truth files (fast)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    R = Results(args.verbose)
    here = os.path.dirname(os.path.abspath(__file__))
    vec_dir = os.path.normpath(args.vectors or os.path.join(here, "..", "vectors", "rbd"))
    if args.vectors_only:
        check_vectors(vec_dir)
        R.summary()
        pubset.emit_result("rbd_check", R.passed, R.failed)
        return 0 if R.failed == 0 else 1
    cap = pubset.captures_dir(args.captures)
    if not os.path.isdir(cap):
        print("capture directory not found: %s (use --captures, or --vectors-only)" % cap)
        return 2
    ctx = {}
    t0 = time.time()
    check_gt4(cap, ctx)
    check_gt4_objects(cap, ctx)
    conns_by_pcap = collections.OrderedDict()
    if not args.skip_pcap:
        sessions = load_sessions(cap)
        drops = load_drops(cap)
        for p in sorted(glob.glob(os.path.join(cap, "pcap", "*.pcap"))):
            conns_by_pcap[os.path.basename(p)[:-5]] = load_conns(p)
        check_msgr2(cap, ctx, conns_by_pcap, sessions, drops)
        check_envelope(cap, ctx, conns_by_pcap, drops)
        check_wire_rbd(cap, ctx, conns_by_pcap, sessions, drops)
        extra = globals().get("check_extra")
        if extra:
            extra(cap, ctx, conns_by_pcap, sessions, drops)
    if args.write_vectors:
        if args.skip_pcap:
            print("--write-vectors needs the pcaps")
            return 2
        write_vectors(cap, ctx, conns_by_pcap, vec_dir)
    if os.path.isdir(vec_dir):
        check_vectors(vec_dir)
    R.summary()
    c = ctx.get("msgr2_counts")
    if c:
        print("pcaps: %d connections, %d frames, %d MESSAGE frames; %d secure-mode connections not decoded here"
              % (len(conns_by_pcap) and c[0], c[1], c[2], c[3]))
    if ctx.get("tail_loss") or ctx.get("capture_holes"):
        print("capture loss (tcpdump reported drops): %r" % sorted(set(x[0] for x in (ctx.get("tail_loss") or []) + (ctx.get("capture_holes") or []))))
    print("elapsed %.1f s" % (time.time() - t0))
    pubset.emit_result("rbd_check", R.passed, R.failed)
    return 0 if R.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
