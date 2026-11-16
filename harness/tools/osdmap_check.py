#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Independent checker for docs/spec/osdmap.md (and the placement part of
docs/spec/crush-and-placement.md that section 3.7 of the osdmap note relies on).

Written from the NOTES only, never from Ceph source and never through Ceph's
own decoders.  Real bytes come from the Phase 0 capture set; the Ceph tools'
output (ceph-dencoder JSON, `ceph osd map`, crushtool, osdmaptool) is used
purely as the expected answer to compare with.

What it covers: msgr2.1 frame parsing of the pcaps (crc mode; every preamble,
segment and late_status check), MMonSubscribe / MOSDMap messages, the OSDMap and
OSDMap::Incremental decoders, the pg_pool_t table, envelope skipping and
rejection, the CRC of the notes, applying incrementals, CRUSH blob decoding,
the placement pipeline (object -> pg -> up/acting) and the committed vectors.
It does not cover cephx, secure mode, OSD ops or RBD metadata: those belong to
the checkers of their own notes (no keyring is read here).

Standard library only.

Usage:
    python3 -I harness/tools/osdmap_check.py --captures <winrbd-ref/captures> [--ref <ceph tree>]
    python3 -I harness/tools/osdmap_check.py                  # committed vectors only

Exit status 0 when every check passes, 1 otherwise.

Run time data (never embedded here, see CONTRIBUTING and licensing question 1 of
the crush note): the two CRUSH log tables are parsed at run time from
<ref>/src/crush/crush_ln_table.h; without --ref (default: ../winrbd-ref/ceph-v20.2.5
next to the repository) the checks that need them are skipped and reported as such.
"""

import argparse
import binascii
import collections
import glob
import json
import os
import re
import struct
import sys

# --------------------------------------------------------------------------
# tiny test framework
# --------------------------------------------------------------------------


class Results:
    def __init__(self, verbose=False):
        self.passed = 0
        self.failed = 0
        self.failures = []
        self.verbose = verbose
        self.sections = collections.OrderedDict()
        self.cur = None

    def section(self, name):
        self.cur = name
        self.sections.setdefault(name, [0, 0])
        print("== %s" % name)

    def ok(self, what, detail=""):
        self.passed += 1
        self.sections[self.cur][0] += 1
        if self.verbose:
            print("  ok   %s %s" % (what, detail))

    def bad(self, what, detail=""):
        self.failed += 1
        self.sections[self.cur][1] += 1
        self.failures.append("%s: %s %s" % (self.cur, what, detail))
        print("  FAIL %s %s" % (what, detail))

    def check(self, cond, what, detail=""):
        if cond:
            self.ok(what, detail)
        else:
            self.bad(what, detail)
        return cond

    def info(self, msg):
        print("  info %s" % msg)


R = None  # global Results, set in main()


class DecodeError(Exception):
    pass


# --------------------------------------------------------------------------
# CRC-32C (raw register update, note 2.4.5 / msgr2 2.5): table generated
# from the reflected polynomial, never copied.
# --------------------------------------------------------------------------


def _make_crc_table():
    tab = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if (c & 1) else (c >> 1)
        tab.append(c)
    return tab


_CRC_TAB = _make_crc_table()


def _make_slices():
    t = [_CRC_TAB]
    for k in range(1, 8):
        prev = t[-1]
        t.append([(prev[i] >> 8) ^ _CRC_TAB[prev[i] & 0xFF] for i in range(256)])
    # 16-bit tables: U[j][x] covers bytes 2j and 2j+1 of an 8-byte little-endian word
    u = []
    for j in range(4):
        ta, tb = t[7 - 2 * j], t[6 - 2 * j]
        u.append([ta[x & 0xFF] ^ tb[x >> 8] for x in range(65536)])
    return u


_U0, _U1, _U2, _U3 = _make_slices()


def crc32c_raw(seed, data):
    """raw update, no final inversion (the start value is the caller's).  The byte-at-a-time
    definition handles the tail; the bulk uses the same table extended to 8 bytes per step."""
    c = seed & 0xFFFFFFFF
    n = len(data)
    nb = n - (n % 8)
    if nb:
        u0, u1, u2, u3 = _U0, _U1, _U2, _U3
        if sys.byteorder == "little":
            it = memoryview(data)[:nb].cast("Q")
        else:
            it = (w for (w,) in struct.iter_unpack("<Q", memoryview(data)[:nb]))
        for w in it:
            w ^= c
            c = u0[w & 0xFFFF] ^ u1[(w >> 16) & 0xFFFF] ^ u2[(w >> 32) & 0xFFFF] ^ u3[w >> 48]
    t = _CRC_TAB
    for b in data[nb:]:
        c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    return c


# --------------------------------------------------------------------------
# byte reader with the note's envelope rules (2.2)
# --------------------------------------------------------------------------


class Reader:
    def __init__(self, buf, pos=0, end=None):
        self.b = buf
        self.p = pos
        self.end = len(buf) if end is None else end

    def need(self, n):
        if n < 0 or self.p + n > self.end:
            raise DecodeError("read of %d bytes at %d overruns end %d" % (n, self.p, self.end))

    def u8(self):
        self.need(1)
        v = self.b[self.p]
        self.p += 1
        return v

    def u16(self):
        self.need(2)
        v = struct.unpack_from("<H", self.b, self.p)[0]
        self.p += 2
        return v

    def u32(self):
        self.need(4)
        v = struct.unpack_from("<I", self.b, self.p)[0]
        self.p += 4
        return v

    def s32(self):
        self.need(4)
        v = struct.unpack_from("<i", self.b, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        self.need(8)
        v = struct.unpack_from("<Q", self.b, self.p)[0]
        self.p += 8
        return v

    def s64(self):
        self.need(8)
        v = struct.unpack_from("<q", self.b, self.p)[0]
        self.p += 8
        return v

    def raw(self, n):
        self.need(n)
        v = bytes(self.b[self.p:self.p + n])
        self.p += n
        return v

    def blob(self):
        n = self.u32()
        return self.raw(n)

    def string(self):
        return self.blob().decode("utf-8", "replace")

    def utime(self):
        s = self.u32()
        ns = self.u32()
        return (s, ns)

    def left(self):
        return self.end - self.p

    def skip_to(self, pos):
        if pos < self.p:
            raise DecodeError("consumed past envelope end (%d > %d)" % (self.p, pos))
        self.p = pos


class Env:
    """Versioned envelope, note 2.2.  While open, the reader is confined to the
    envelope (the stricter rule the note recommends: inner end must lie within
    the outer end).  Call finish() to jump to the end and leave the envelope."""

    def __init__(self, r, max_compat, legacy_at=None):
        self.r = r
        self.start = r.p
        self.v = r.u8()
        if legacy_at is not None and self.v < legacy_at:
            raise DecodeError("legacy envelope: struct_v %d < %d" % (self.v, legacy_at))
        self.compat = r.u8()
        self.length = r.u32()
        if self.compat > max_compat:
            raise DecodeError("struct_compat %d > supported %d" % (self.compat, max_compat))
        if self.length > r.left():
            raise DecodeError("struct_len %d > bytes left %d" % (self.length, r.left()))
        self.end = r.p + self.length
        self.prev_end = r.end
        r.end = self.end

    def finish(self):
        if self.r.p > self.end:
            raise DecodeError("consumed %d bytes past envelope end" % (self.r.p - self.end))
        self.r.p = self.end
        self.r.end = self.prev_end


# --------------------------------------------------------------------------
# generic containers (note 2.1)
# --------------------------------------------------------------------------


def dec_map(r, kf, vf):
    n = r.u32()
    if n * 1 > r.left():
        raise DecodeError("map count %d too large" % n)
    out = collections.OrderedDict()
    prev = None
    sorted_ok = True
    for _ in range(n):
        k = kf(r)
        v = vf(r)
        if prev is not None and not (_key_lt(prev, k)):
            sorted_ok = False
        prev = k
        out[k] = v
    if not sorted_ok:
        SORT_VIOLATIONS.append(1)
    return out


SORT_VIOLATIONS = []
SORT_CHECKED = [0]


def _key_lt(a, b):
    SORT_CHECKED[0] += 1
    return a < b


def dec_vec(r, ef):
    n = r.u32()
    if n > r.left():
        raise DecodeError("vector count %d too large" % n)
    return [ef(r) for _ in range(n)]


def dec_pgt(r):
    """pg_t: 17 bytes (2.1.1) -> (pool, seed); also returns checked fields."""
    ver = r.u8()
    pool = r.u64()
    seed = r.u32()
    pref = r.s32()
    PGT_SEEN.append((ver, pref))
    return (pool, seed)


PGT_SEEN = []


def dec_interval_set(r):
    n = r.u32()
    if n * 16 > r.left():
        raise DecodeError("interval_set count too large")
    return [(r.u64(), r.u64()) for _ in range(n)]


# --------------------------------------------------------------------------
# entity_addr_t / addrvec (2.1.2, 2.1.3)
# --------------------------------------------------------------------------

ADDR_OBS = {"elen": collections.Counter(), "type": collections.Counter(),
            "family": collections.Counter(), "marker": collections.Counter(),
            "veclen": collections.Counter(), "vecmarker": collections.Counter(),
            "nonzero_pad": 0, "flow_scope": 0, "struct_len": collections.Counter(),
            "struct_v": collections.Counter(), "compat": collections.Counter()}


def dec_addr(r):
    a0 = r.p
    marker = r.u8()
    ADDR_OBS["marker"][marker] += 1
    if marker != 1:
        raise DecodeError("entity_addr_t marker %d (legacy form not handled)" % marker)
    v = r.u8()
    c = r.u8()
    ADDR_OBS["struct_v"][v] += 1
    ADDR_OBS["compat"][c] += 1
    if c > 1:
        raise DecodeError("entity_addr_t compat %d" % c)
    ln = r.u32()
    ADDR_OBS["struct_len"][ln] += 1
    end = r.p + ln
    if ln > r.left():
        raise DecodeError("entity_addr_t struct_len overruns")
    typ = r.u32()
    nonce = r.u32()
    elen = r.u32()
    ADDR_OBS["type"][typ] += 1
    ADDR_OBS["elen"][elen] += 1
    ip = None
    port = None
    fam = None
    if elen:
        fam = r.u16()
        ADDR_OBS["family"][fam] += 1
        body = r.raw(elen - 2)
        if fam == 2:
            if elen != 16:
                raise DecodeError("IPv4 elen %d" % elen)
            port = struct.unpack(">H", body[0:2])[0]
            ip = ".".join(str(x) for x in body[2:6])
            if any(body[6:]):
                ADDR_OBS["nonzero_pad"] += 1
        elif fam == 10:
            if elen != 28:
                raise DecodeError("IPv6 elen %d" % elen)
            port = struct.unpack(">H", body[0:2])[0]
            flow = struct.unpack("<I", body[2:6])[0]
            scope = struct.unpack("<I", body[22:26])[0]
            if flow or scope:
                ADDR_OBS["flow_scope"] += 1
            ip = body[6:22].hex()
        else:
            if any(body):
                ADDR_OBS["nonzero_pad"] += 1
    r.skip_to(end)
    return {"type": typ, "nonce": nonce, "elen": elen, "family": fam, "ip": ip, "port": port,
            "raw": bytes(r.b[a0:r.p])}


def dec_addrvec(r):
    m = r.u8()
    ADDR_OBS["vecmarker"][m] += 1
    if m != 2:
        raise DecodeError("addrvec marker %d" % m)
    n = r.u32()
    ADDR_OBS["veclen"][n] += 1
    if n * 11 > r.left():
        raise DecodeError("addrvec count too large")
    return [dec_addr(r) for _ in range(n)]


# --------------------------------------------------------------------------
# pcap -> TCP streams -> msgr2 frames  (msgr2 note 2.2-2.9)
# --------------------------------------------------------------------------


def read_pcap(path):
    """yield (ts, src_ip, sport, dst_ip, dport, seq, flags, payload) for IPv4/TCP."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise DecodeError("not a classic pcap: %r" % magic)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise DecodeError("linktype %d" % linktype)
    pos = 24
    n = len(data)
    while pos + 16 <= n:
        ts_s, ts_us, caplen, wirelen = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        pkt = data[pos:pos + caplen]
        pos += caplen
        if len(pkt) < 14 or pkt[12:14] != b"\x08\x00":
            continue
        ihl = (pkt[14] & 0xF) * 4
        if pkt[14] >> 4 != 4 or pkt[23] != 6:
            continue
        tot = struct.unpack(">H", pkt[16:18])[0]
        src = ".".join(str(x) for x in pkt[26:30])
        dst = ".".join(str(x) for x in pkt[30:34])
        ip_end = 14 + tot
        t = 14 + ihl
        sport, dport, seq, ack = struct.unpack(">HHII", pkt[t:t + 12])
        doff = (pkt[t + 12] >> 4) * 4
        flags = pkt[t + 13]
        payload = pkt[t + doff:ip_end]
        yield (ts_s + ts_us / 1e6, src, sport, dst, dport, seq, flags, payload)


class Stream:
    """One direction of a TCP connection, reassembled by sequence number."""

    def __init__(self):
        self.isn = None
        self.segs = {}      # rel seq -> payload
        self.retrans = 0

    def add(self, seq, flags, payload):
        if flags & 0x02:  # SYN
            self.isn = seq
            return
        if not payload:
            return
        if self.isn is None:
            self.isn = seq - 1
        rel = (seq - self.isn - 1) & 0xFFFFFFFF
        if rel in self.segs:
            if len(self.segs[rel]) >= len(payload):
                self.retrans += 1
                return
            self.retrans += 1
        self.segs[rel] = payload

    def assemble(self):
        """contiguous bytes from the start; a missing segment (capture loss) ends the stream there"""
        out = bytearray()
        self.hole = None
        for rel in sorted(self.segs):
            p = self.segs[rel]
            if rel > len(out):
                self.hole = (len(out), rel)
                break
            if rel + len(p) <= len(out):
                continue
            out += p[len(out) - rel:]
        return bytes(out)


def pcap_connections(path):
    """-> {(cport, sip, sport): {'c2s': bytes, 's2c': bytes, 'retrans': n, 'order': first_ts}}"""
    conns = {}
    # the capture is one client talking to daemons; the client is whoever sends the first bare SYN
    client_ip = None
    for ts, src, sp, dst, dp, seq, flags, payload in read_pcap(path):
        if (flags & 0x12) == 0x02:
            client_ip = src
            break
    for ts, src, sp, dst, dp, seq, flags, payload in read_pcap(path):
        if src == client_ip:
            key = (sp, dst, dp)
            d = "c2s"
        else:
            key = (dp, src, sp)
            d = "s2c"
        c = conns.setdefault(key, {"c2s": Stream(), "s2c": Stream(), "ts": ts})
        c[d].add(seq, flags, payload)
    out = {}
    for k, c in conns.items():
        a, b = c["c2s"].assemble(), c["s2c"].assemble()
        out[k] = {"c2s": a, "s2c": b, "retrans": c["c2s"].retrans + c["s2c"].retrans, "ts": c["ts"],
                  "holes": [h for h in (c["c2s"].hole, c["s2c"].hole) if h]}
    return out


TAG_NAMES = {1: "HELLO", 2: "AUTH_REQUEST", 3: "AUTH_BAD_METHOD", 4: "AUTH_REPLY_MORE",
             5: "AUTH_REQUEST_MORE", 6: "AUTH_DONE", 7: "AUTH_SIGNATURE", 8: "CLIENT_IDENT",
             9: "SERVER_IDENT", 10: "IDENT_MISSING_FEATURES", 11: "SESSION_RECONNECT",
             12: "SESSION_RESET", 13: "SESSION_RETRY", 14: "SESSION_RETRY_GLOBAL",
             15: "SESSION_RECONNECT_OK", 16: "WAIT", 17: "MESSAGE", 18: "KEEPALIVE2",
             19: "KEEPALIVE2_ACK", 20: "ACK", 21: "COMPRESSION_REQUEST", 22: "COMPRESSION_DONE"}

FRAME_STATS = collections.Counter()


def parse_frames(stream, who, stop_after=None):
    """Parse one direction of a msgr2.1 crc-mode stream.

    Returns (frames, mode, note).  frames = list of dicts with tag, segs.
    Stops (without error) at AUTH_DONE with connection_mode 2 (secure): the
    rest of that stream is encrypted and belongs to the secure-mode note.
    """
    frames = []
    if stream[:8] != b"ceph v2\n":
        raise DecodeError("%s: bad banner prefix %r" % (who, stream[:8]))
    plen = struct.unpack("<H", stream[8:10])[0]
    sup, req = struct.unpack("<QQ", stream[10:26])
    FRAME_STATS["banner"] += 1
    if plen != 16:
        FRAME_STATS["banner_len_" + str(plen)] += 1
    pos = 10 + plen
    mode = "crc"
    while pos < len(stream):
        if len(stream) - pos < 32:
            return frames, mode, "truncated preamble at %d" % pos
        pre = stream[pos:pos + 32]
        pcrc = struct.unpack("<I", pre[28:32])[0]
        if crc32c_raw(0, pre[:28]) != pcrc:
            raise DecodeError("%s: preamble CRC mismatch at %d" % (who, pos))
        FRAME_STATS["preamble_crc_ok"] += 1
        tag = pre[0]
        nseg = pre[1]
        if not (1 <= nseg <= 4):
            raise DecodeError("%s: nseg %d" % (who, nseg))
        lens = []
        aligns = []
        for i in range(4):
            l, a = struct.unpack_from("<IH", pre, 2 + 6 * i)
            lens.append(l)
            aligns.append(a)
        if any(lens[nseg:]) :
            raise DecodeError("%s: unused segment has length" % who)
        if nseg > 1 and lens[nseg - 1] == 0:
            raise DecodeError("%s: last segment empty with nseg>1" % who)
        flags = pre[26]
        if flags != 0 or pre[27] != 0:
            FRAME_STATS["preamble_flags_nonzero"] += 1
        p = pos + 32
        segs = []
        need = (lens[0] + 4 if lens[0] else 0) + sum(lens[1:nseg]) + (13 if nseg > 1 else 0)
        if p + need > len(stream):
            return frames, mode, "truncated frame at %d (need %d have %d)" % (pos, need, len(stream) - p)
        if lens[0]:
            s0 = stream[p:p + lens[0]]
            c0 = struct.unpack_from("<I", stream, p + lens[0])[0]
            if crc32c_raw(0xFFFFFFFF, s0) != c0:
                raise DecodeError("%s: seg0 CRC mismatch (tag %d)" % (who, tag))
            FRAME_STATS["seg0_crc_ok"] += 1
            p += lens[0] + 4
        else:
            s0 = b""
        segs.append(s0)
        for i in range(1, nseg):
            segs.append(stream[p:p + lens[i]])
            p += lens[i]
        if nseg > 1:
            ep = stream[p:p + 13]
            p += 13
            if ep[0] != 0x0E:
                raise DecodeError("%s: late_status %#x" % (who, ep[0]))
            FRAME_STATS["late_status_0e"] += 1
            for i in range(1, nseg):
                c = struct.unpack_from("<I", ep, 1 + 4 * (i - 1))[0]
                want = crc32c_raw(0xFFFFFFFF, segs[i])
                if c != want:
                    raise DecodeError("%s: seg%d CRC mismatch" % (who, i))
                FRAME_STATS["segN_crc_ok"] += 1
            for i in range(nseg, 4):
                c = struct.unpack_from("<I", ep, 1 + 4 * (i - 1))[0]
                if c != 0:
                    FRAME_STATS["epilogue_unused_slot_nonzero"] += 1
        pos = p
        fr = {"tag": tag, "segs": segs, "aligns": aligns[:nseg], "lens": lens[:nseg]}
        frames.append(fr)
        if stop_after is not None and len(frames) >= stop_after:
            return frames, mode, "stopped (secure client side)"
        FRAME_STATS["frames"] += 1
        FRAME_STATS["tag_" + TAG_NAMES.get(tag, str(tag))] += 1
        if tag == 6:   # AUTH_DONE: global_id u64, mode u32, payload
            gid, cm = struct.unpack_from("<QI", segs[0], 0)
            mode = {1: "crc", 2: "secure"}.get(cm, "?%d" % cm)
            fr["gid"] = gid
            if mode == "secure":
                return frames, mode, "secure after AUTH_DONE"
    return frames, mode, ""


def hdr2(seg0):
    if len(seg0) < 41:
        raise DecodeError("header2 too short")
    seq, tid, typ, prio, ver, pad, doff, ack, flags, compat, rsv = struct.unpack_from(
        "<QQHHHIHQBHH", seg0, 0)
    return {"seq": seq, "tid": tid, "type": typ, "prio": prio, "version": ver,
            "pre_pad": pad, "data_off": doff, "ack_seq": ack, "flags": flags,
            "compat": compat, "rsv": rsv}


def messages_of(frames):
    for fr in frames:
        if fr["tag"] == 17:
            h = hdr2(fr["segs"][0])
            segs = fr["segs"]
            h["front"] = segs[1] if len(segs) > 1 else b""
            h["middle"] = segs[2] if len(segs) > 2 else b""
            h["data"] = segs[3] if len(segs) > 3 else b""
            yield h


# --------------------------------------------------------------------------
# pg_pool_t  (note 2.5)
# --------------------------------------------------------------------------

POOL_VERSIONS = collections.Counter()


def dec_varint(r):
    v = 0
    shift = 0
    while True:
        b = r.u8()
        v |= (b & 0x7F) << shift
        if not (b & 0x80):
            return v
        shift += 7
        if shift > 70:
            raise DecodeError("varint too long")


def dec_str_map(r):
    return dec_map(r, lambda x: x.string(), lambda x: x.string())


def dec_pool(r):
    """pg_pool_t with the legacy envelope (thresholds 5,5, max compat 32)."""
    env = Env(r, 32, legacy_at=5)
    v = env.v
    POOL_VERSIONS[v] += 1
    p = {"struct_v": v, "struct_compat": env.compat}
    p["type"] = r.u8()
    p["size"] = r.u8()
    p["crush_rule"] = r.u8()
    p["object_hash"] = r.u8()
    p["pg_num"] = r.u32()
    p["pgp_num"] = r.u32()
    p["lpg_num"] = r.u32()
    p["lpgp_num"] = r.u32()
    p["last_change"] = r.u32()
    p["snap_seq"] = r.u64()
    p["snap_epoch"] = r.u32()
    if v >= 3:
        def snapinfo(rr):
            e = Env(rr, 2)
            d = {"snapid": rr.u64(), "stamp": rr.utime(), "name": rr.string()}
            e.finish()
            return d
        p["snaps"] = dec_map(r, lambda x: x.u64(), snapinfo)
        p["removed_snaps"] = dec_interval_set(r)
        p["auid"] = r.u64()
    if v >= 4:
        p["flags"] = r.u64()
        p["crash_replay_interval"] = r.u32()
    if v >= 7:
        p["min_size"] = r.u8()
    if v >= 8:
        p["quota_max_bytes"] = r.u64()
        p["quota_max_objects"] = r.u64()
    if v >= 9:
        p["tiers"] = dec_vec(r, lambda x: x.u64())
        p["tier_of"] = r.s64()
        p["cache_mode"] = r.u8()
        p["read_tier"] = r.s64()
        p["write_tier"] = r.s64()
    if v >= 10:
        p["properties"] = dec_str_map(r)
    if v >= 11:
        e = Env(r, 1)
        e.finish()                 # hit_set_params: skipped by length
        p["hit_set_period"] = r.u32()
        p["hit_set_count"] = r.u32()
    if v >= 12:
        p["stripe_width"] = r.u32()
    if v >= 13:
        p["target_max_bytes"] = r.u64()
        p["target_max_objects"] = r.u64()
        p["cache_target_dirty_ratio_micro"] = r.u32()
        p["cache_target_full_ratio_micro"] = r.u32()
        p["cache_min_flush_age"] = r.u32()
        p["cache_min_evict_age"] = r.u32()
    if v >= 14:
        p["erasure_code_profile"] = r.string()
    if v >= 15:
        p["last_force_op_resend_preluminous"] = r.u32()
    if v >= 16:
        p["min_read_recency_for_promote"] = r.u32()
    if v >= 17:
        p["expected_num_objects"] = r.u64()
    if v >= 19:
        p["cache_target_dirty_high_ratio_micro"] = r.u32()
    if v >= 20:
        p["min_write_recency_for_promote"] = r.u32()
    if v >= 21:
        p["use_gmt_hitset"] = bool(r.u8())
    if v >= 22:
        p["fast_read"] = bool(r.u8())
    if v >= 23:
        p["hit_set_grade_decay_rate"] = r.u32()
        p["hit_set_search_last_n"] = r.u32()
    if v >= 24:
        e = Env(r, 1)
        n = r.u32()
        p["opts_count"] = n
        e.finish()
    if v >= 25:
        p["last_force_op_resend_prenautilus"] = r.u32()
    if v >= 26:
        p["application_metadata"] = dec_map(r, lambda x: x.string(), dec_str_map)
    if v >= 27:
        p["create_time"] = r.utime()
    if v >= 28:
        p["pg_num_target"] = r.u32()
        p["pgp_num_target"] = r.u32()
        p["pg_num_pending"] = r.u32()
        p["ignored_merge_epochs"] = (r.u32(), r.u32())
        p["last_force_op_resend"] = r.u32()
        p["pg_autoscale_mode"] = r.u8()
    if v >= 29:
        e = Env(r, 1)
        e.finish()                 # last_pg_merge_meta
    if v == 30:
        p["peering_crush_bucket_count"] = r.u32()
        p["peering_crush_bucket_target"] = r.u32()
        p["peering_crush_bucket_barrier"] = r.u32()
        p["peering_crush_bucket_mandatory_member"] = r.s32()
    if v >= 31:
        present = r.u8()
        if present:
            p["peering_crush_bucket_count"] = r.u32()
            p["peering_crush_bucket_target"] = r.u32()
            p["peering_crush_bucket_barrier"] = r.u32()
            p["peering_crush_bucket_mandatory_member"] = r.u32()
        else:
            p["peering_crush_bucket_count"] = 0
        p["_row52_present"] = present
    if v >= 32:
        p["nonprimary_shards"] = (dec_varint(r), dec_varint(r))
    p["_consumed_to_end"] = (r.p == env.end)
    p["_trailing"] = env.end - r.p
    p["_env_start"] = env.start
    env.finish()
    p["pg_num_mask"] = _mask(p["pg_num"])
    p["pgp_num_mask"] = _mask(p["pgp_num"])
    return p


def _bits(x):
    return x.bit_length()


def _mask(n):
    if n == 0:
        raise DecodeError("pg_num 0")
    return (1 << _bits(n - 1)) - 1


# --------------------------------------------------------------------------
# full OSDMap (note 2.4)
# --------------------------------------------------------------------------


def dec_s32_vec(r):
    return dec_vec(r, lambda x: x.s32())


def dec_pg_temp(r):
    return dec_map(r, dec_pgt, dec_s32_vec)


def dec_osdmap(buf, verify_crc=True, want_crc_info=None):
    """Decode a full OSDMap.  Returns dict (state) per the note."""
    r = Reader(buf)
    wrap = Env(r, 8, legacy_at=7)
    if wrap.end != len(buf):
        raise DecodeError("wrapper end %d != buffer %d" % (wrap.end, len(buf)))
    m = {"wrapper_v": wrap.v, "wrapper_compat": wrap.compat}
    cb = Env(r, 10)
    m["client_v"] = cb.v
    m["client_compat"] = cb.compat
    v = cb.v
    m["fsid"] = r.raw(16)
    m["epoch"] = r.u32()
    m["created"] = r.utime()
    m["modified"] = r.utime()
    m["pools"] = dec_map(r, lambda x: x.s64(), dec_pool)
    m["pool_name"] = dec_map(r, lambda x: x.s64(), lambda x: x.string())
    m["pool_max"] = r.s32()
    m["flags"] = r.u32()
    m["max_osd"] = r.s32()
    if m["max_osd"] < 0:
        raise DecodeError("negative max_osd")
    if v >= 5:
        m["osd_state"] = dec_vec(r, lambda x: x.u32())
    else:
        m["osd_state"] = dec_vec(r, lambda x: x.u8())
    m["osd_weight"] = dec_vec(r, lambda x: x.u32())
    if v >= 8:
        m["client_addrs"] = dec_vec(r, dec_addrvec)
    else:
        raise DecodeError("client block < 8 not supported by this checker")
    m["pg_temp"] = dec_pg_temp(r)
    m["primary_temp"] = dec_map(r, dec_pgt, lambda x: x.s32())
    m["osd_primary_affinity"] = dec_vec(r, lambda x: x.u32()) if v >= 2 else []
    m["crush"] = r.blob()
    if v >= 3:
        m["erasure_code_profiles"] = dec_map(r, lambda x: x.string(), dec_str_map)
    if v >= 4:
        m["pg_upmap"] = dec_map(r, dec_pgt, dec_s32_vec)
        m["pg_upmap_items"] = dec_map(r, dec_pgt, lambda x: dec_vec(x, lambda y: (y.s32(), y.s32())))
    if v >= 6:
        m["crush_version"] = r.u32()
    if v >= 7:
        m["new_removed_snaps"] = dec_map(r, lambda x: x.s64(), dec_interval_set)
        m["new_purged_snaps"] = dec_map(r, lambda x: x.s64(), dec_interval_set)
    if v >= 9:
        m["last_up_change"] = r.utime()
        m["last_in_change"] = r.utime()
    if v >= 10:
        m["pg_upmap_primaries"] = dec_map(r, dec_pgt, lambda x: x.s32())
    m["_client_block_consumed_exactly"] = (r.p == cb.end)
    m["_client_block_trailing"] = cb.end - r.p
    cb.finish()
    ob_start = r.p
    ob = Env(r, 255)
    m["osd_block_v"] = ob.v
    m["osd_block_compat"] = ob.compat
    m["osd_block_len"] = ob.length
    ob.finish()
    if wrap.v >= 8:
        crc_pos = r.p
        m["crc"] = r.u32()
        # coverage per 2.4.5: first byte of wrapper up to the crc field, then bytes after it
        c = crc32c_raw(0xFFFFFFFF, buf[:crc_pos])
        c = crc32c_raw(c, buf[crc_pos + 4:wrap.end])
        m["crc_computed"] = c
        m["crc_ok"] = (c == m["crc"])
        m["crc_tail_len"] = wrap.end - (crc_pos + 4)
        # also keep the textbook (inverted) variant for the report
        m["crc_textbook"] = c ^ 0xFFFFFFFF
    m["_wrapper_trailing"] = wrap.end - r.p
    wrap.finish()
    return m


# --------------------------------------------------------------------------
# Incremental (note 2.6)
# --------------------------------------------------------------------------


def dec_incremental(buf):
    r = Reader(buf)
    wrap = Env(r, 8, legacy_at=7)
    if wrap.end != len(buf):
        raise DecodeError("incremental wrapper end %d != buffer %d" % (wrap.end, len(buf)))
    inc = {"wrapper_v": wrap.v, "wrapper_compat": wrap.compat}
    cb = Env(r, 9)
    v = cb.v
    inc["client_v"] = v
    inc["client_compat"] = cb.compat
    inc["fsid"] = r.raw(16)
    inc["epoch"] = r.u32()
    inc["modified"] = r.utime()
    inc["new_pool_max"] = r.s64()
    inc["new_flags"] = r.s32()
    inc["fullmap"] = r.blob()
    inc["crush"] = r.blob()
    inc["new_max_osd"] = r.s32()
    inc["new_pools"] = dec_map(r, lambda x: x.s64(), dec_pool)
    inc["new_pool_names"] = dec_map(r, lambda x: x.s64(), lambda x: x.string())
    inc["old_pools"] = dec_vec(r, lambda x: x.s64())
    inc["new_up_client"] = dec_map(r, lambda x: x.s32(), dec_addrvec)
    inc["new_state"] = dec_map(r, lambda x: x.s32(), lambda x: x.u32())
    inc["new_weight"] = dec_map(r, lambda x: x.s32(), lambda x: x.u32())
    inc["new_pg_temp"] = dec_map(r, dec_pgt, dec_s32_vec)
    inc["new_primary_temp"] = dec_map(r, dec_pgt, lambda x: x.s32())
    inc["new_primary_affinity"] = dec_map(r, lambda x: x.s32(), lambda x: x.u32()) if v >= 2 else {}
    if v >= 3:
        inc["new_erasure_code_profiles"] = dec_map(r, lambda x: x.string(), dec_str_map)
        inc["old_erasure_code_profiles"] = dec_vec(r, lambda x: x.string())
    if v >= 4:
        inc["new_pg_upmap"] = dec_map(r, dec_pgt, dec_s32_vec)
        inc["old_pg_upmap"] = dec_vec(r, dec_pgt)
        inc["new_pg_upmap_items"] = dec_map(r, dec_pgt, lambda x: dec_vec(x, lambda y: (y.s32(), y.s32())))
        inc["old_pg_upmap_items"] = dec_vec(r, dec_pgt)
    if v >= 6:
        inc["new_removed_snaps"] = dec_map(r, lambda x: x.s64(), dec_interval_set)
        inc["new_purged_snaps"] = dec_map(r, lambda x: x.s64(), dec_interval_set)
    if v >= 8:
        inc["new_last_up_change"] = r.utime()
        inc["new_last_in_change"] = r.utime()
    if v >= 9:
        inc["new_pg_upmap_primary"] = dec_map(r, dec_pgt, lambda x: x.s32())
        inc["old_pg_upmap_primary"] = dec_vec(r, dec_pgt)
    inc["_client_block_consumed_exactly"] = (r.p == cb.end)
    inc["_client_block_trailing"] = cb.end - r.p
    cb.finish()
    ob = Env(r, 255)
    inc["osd_block_v"] = ob.v
    inc["osd_block_len"] = ob.length
    ob.finish()
    if wrap.v >= 8:
        crc_pos = r.p
        inc["inc_crc"] = r.u32()
        inc["full_crc"] = r.u32()
        c = crc32c_raw(0xFFFFFFFF, buf[:crc_pos])
        c = crc32c_raw(c, buf[crc_pos + 4:wrap.end])
        inc["inc_crc_computed"] = c
        inc["inc_crc_ok"] = (c == inc["inc_crc"])
    inc["_wrapper_trailing"] = wrap.end - r.p
    wrap.finish()
    return inc


# --------------------------------------------------------------------------
# MOSDMap message payload (note 2.3)
# --------------------------------------------------------------------------


def dec_mosdmap(front, version):
    r = Reader(front)
    d = {"fsid": r.raw(16)}
    d["incremental_maps"] = dec_map(r, lambda x: x.u32(), lambda x: x.blob())
    d["maps"] = dec_map(r, lambda x: x.u32(), lambda x: x.blob())
    if version >= 2:
        d["oldest_map"] = r.u32()
        d["newest_map"] = r.u32()
    if version >= 4:
        n = r.u32()
        d["gap_count"] = n
        for _ in range(n):
            r.s64()
            dec_interval_set(r)
    d["_trailing"] = r.left()
    return d


# --------------------------------------------------------------------------
# CRUSH blob decode + mapper (docs/spec/crush-and-placement.md 2, 3).
# Tables RH_LH / LL_tbl are parsed at run time from the reference tree.
# --------------------------------------------------------------------------

M32 = 0xFFFFFFFF
CRUSH_ITEM_NONE = 0x7FFFFFFF
LN_TABLES = {}


def load_ln_tables(ref):
    path = os.path.join(ref, "src", "crush", "crush_ln_table.h")
    txt = open(path).read()

    def grab(name):
        m = re.search(name + r"\s*\[[^\]]*\]\s*=\s*\{(.*?)\};", txt, re.S)
        if not m:
            raise DecodeError("table %s not found in %s" % (name, path))
        return [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1))]
    rh = grab("__RH_LH_tbl")
    ll = grab("__LL_tbl")
    if len(rh) != 258 or len(ll) != 256:
        raise DecodeError("unexpected table sizes %d %d" % (len(rh), len(ll)))
    LN_TABLES["RH_LH"] = rh
    LN_TABLES["LL"] = ll


def crush_ln(u):
    """3.4.2"""
    x = u + 1
    iexpon = 15
    if not (x & 0x18000):
        bits = 16 - x.bit_length()
        x <<= bits
        iexpon = 15 - bits
    idx1 = (x >> 8) << 1
    rh = LN_TABLES["RH_LH"][idx1 - 256]
    lh = LN_TABLES["RH_LH"][idx1 + 1 - 256]
    xl = (x * rh) >> 48
    ll = LN_TABLES["LL"][xl & 0xFF]
    return ((iexpon << 44) + ((lh + ll) >> 4)) & 0xFFFFFFFFFFFFFFFF


def _mix(a, b, c):
    a = (a - b - c) & M32; a ^= c >> 13
    b = (b - c - a) & M32; b ^= (a << 8) & M32
    c = (c - a - b) & M32; c ^= b >> 13
    a = (a - b - c) & M32; a ^= c >> 12
    b = (b - c - a) & M32; b ^= (a << 16) & M32
    c = (c - a - b) & M32; c ^= b >> 5
    a = (a - b - c) & M32; a ^= c >> 3
    b = (b - c - a) & M32; b ^= (a << 10) & M32
    c = (c - a - b) & M32; c ^= b >> 15
    return a, b, c


CRUSH_SEED = 1315423911


def hash2(a, b):
    a &= M32; b &= M32
    h = CRUSH_SEED ^ a ^ b
    x, y = 231232, 1232
    a, b, h = _mix(a, b, h)
    x, a, h = _mix(x, a, h)
    b, y, h = _mix(b, y, h)
    return h


def hash3(a, b, c):
    a &= M32; b &= M32; c &= M32
    h = CRUSH_SEED ^ a ^ b ^ c
    x, y = 231232, 1232
    a, b, h = _mix(a, b, h)
    c, x, h = _mix(c, x, h)
    y, a, h = _mix(y, a, h)
    b, x, h = _mix(b, x, h)
    y, c, h = _mix(y, c, h)
    return h


def hash4(a, b, c, d):
    a &= M32; b &= M32; c &= M32; d &= M32
    h = CRUSH_SEED ^ a ^ b ^ c ^ d
    x, y = 231232, 1232
    a, b, h = _mix(a, b, h)
    c, d, h = _mix(c, d, h)
    a, x, h = _mix(a, x, h)
    y, b, h = _mix(y, b, h)
    c, x, h = _mix(c, x, h)
    y, d, h = _mix(y, d, h)
    return h


def str_hash_rjenkins(data):
    """3.1.1"""
    n = len(data)
    a = b = 0x9E3779B9
    c = 0
    k = data
    pos = 0
    ln = n
    while ln >= 12:
        a = (a + struct.unpack_from("<I", k, pos)[0]) & M32
        b = (b + struct.unpack_from("<I", k, pos + 4)[0]) & M32
        c = (c + struct.unpack_from("<I", k, pos + 8)[0]) & M32
        a, b, c = _mix(a, b, c)
        pos += 12
        ln -= 12
    c = (c + n) & M32
    t = k[pos:]
    for i in range(min(ln, 4)):
        a = (a + (t[i] << (8 * i))) & M32
    for i in range(4, min(ln, 8)):
        b = (b + (t[i] << (8 * (i - 4)))) & M32
    for i in range(8, min(ln, 11)):
        c = (c + (t[i] << (8 * (i - 8 + 1)))) & M32
    a, b, c = _mix(a, b, c)
    return c


def str_hash_linux(data):
    h = 0
    for c in data:
        h = ((h + (c << 4) + (c >> 4)) * 11) & M32
    return h


def stable_mod(x, b, bmask):
    if (x & bmask) < b:
        return x & bmask
    return x & (bmask >> 1)


# ---- decode -------------------------------------------------------------


def _dec_named(r):
    """name maps with the empty-name quirk of 2.2 rows 7-9"""
    n = r.u32()
    out = {}
    for _ in range(n):
        k = r.s32()
        ln = r.u32()
        if ln == 0:
            ln = r.u32()
        out[k] = r.raw(ln).decode("utf-8", "replace")
    return out


def dec_crush(blob):
    r = Reader(blob)
    cm = {"raw_len": len(blob)}
    magic = r.u32()
    if magic != 0x00010000:
        raise DecodeError("crush magic %#x" % magic)
    max_buckets = r.s32()
    max_rules = r.u32()
    cm["wire_max_devices"] = r.s32()
    cm["max_buckets"] = max_buckets
    cm["max_rules"] = max_rules
    buckets = [None] * max_buckets
    for slot in range(max_buckets):
        alg = r.u32()
        if alg == 0:
            continue
        if not (1 <= alg <= 5):
            raise DecodeError("bucket alg marker %d" % alg)
        b = {"slot": slot}
        b["id"] = r.s32()
        b["type"] = r.u16()
        b["alg"] = r.u8()
        b["hash"] = r.u8()
        b["weight"] = r.u32()
        size = r.u32()
        if size * 4 > r.left():
            raise DecodeError("bucket size too large")
        b["items"] = [r.s32() for _ in range(size)]
        if b["alg"] != alg:
            raise DecodeError("alg marker != alg byte")
        if b["id"] != -1 - slot:
            raise DecodeError("bucket id %d != -1-slot %d" % (b["id"], slot))
        if b["hash"] != 0:
            raise DecodeError("bucket hash %d" % b["hash"])
        if alg == 1:
            b["item_weight"] = r.u32()
            b["weights"] = [b["item_weight"]] * size
        elif alg == 2:
            b["weights"] = []
            b["sums"] = []
            for _ in range(size):
                b["weights"].append(r.u32())
                b["sums"].append(r.u32())
        elif alg == 3:
            nn = r.u8()
            b["node_weights"] = [r.u32() for _ in range(nn)]
            b["weights"] = []
        elif alg == 4:
            b["weights"] = []
            b["straws"] = []
            for _ in range(size):
                b["weights"].append(r.u32())
                b["straws"].append(r.u32())
        elif alg == 5:
            b["weights"] = [r.u32() for _ in range(size)]
        buckets[slot] = b
    cm["buckets"] = buckets
    rules = [None] * max_rules
    for i in range(max_rules):
        present = r.u32()
        if not present:
            continue
        ln = r.u32()
        rl = {"id": i}
        rl["ruleset"] = r.u8()
        rl["type"] = r.u8()
        rl["min_size"] = r.u8()
        rl["max_size"] = r.u8()
        if rl["ruleset"] != i:
            raise DecodeError("rule ruleset %d != slot %d" % (rl["ruleset"], i))
        if ln * 12 > r.left():
            raise DecodeError("rule steps too many")
        rl["steps"] = [(r.u32(), r.s32(), r.s32()) for _ in range(ln)]
        rules[i] = rl
    cm["rules"] = rules
    cm["type_map"] = _dec_named(r)
    cm["name_map"] = _dec_named(r)
    cm["rule_name_map"] = _dec_named(r)
    # tunables with legacy defaults (2.5)
    t = {"choose_local_tries": 2, "choose_local_fallback_tries": 5, "choose_total_tries": 19,
         "chooseleaf_descend_once": 0, "chooseleaf_vary_r": 0, "straw_calc_version": 0,
         "allowed_bucket_algs": 0x16, "chooseleaf_stable": 0,
         "msr_descents": 100, "msr_collision_tries": 100}
    cm["tail_present"] = {}
    if r.left():
        t["choose_local_tries"] = r.u32()
        t["choose_local_fallback_tries"] = r.u32()
        t["choose_total_tries"] = r.u32()
        cm["tail_present"]["A"] = True
    if r.left():
        t["chooseleaf_descend_once"] = r.u32()
        cm["tail_present"]["B"] = True
    if r.left():
        t["chooseleaf_vary_r"] = r.u8()
        cm["tail_present"]["C"] = True
    if r.left():
        t["straw_calc_version"] = r.u8()
        cm["tail_present"]["D"] = True
    if r.left():
        t["allowed_bucket_algs"] = r.u32()
        cm["tail_present"]["E"] = True
    if r.left():
        t["chooseleaf_stable"] = r.u8()
        cm["tail_present"]["F"] = True
    cm["class_map"] = {}
    cm["class_name"] = {}
    cm["class_bucket"] = {}
    if r.left():
        n = r.u32()
        for _ in range(n):
            k = r.s32()
            cm["class_map"][k] = r.s32()
        n = r.u32()
        for _ in range(n):
            k = r.s32()
            cm["class_name"][k] = r.string()
        n = r.u32()
        for _ in range(n):
            k = r.s32()
            m = r.u32()
            cm["class_bucket"][k] = [(r.s32(), r.s32()) for _ in range(m)]
        cm["tail_present"]["classes"] = True
    cm["choose_args"] = {}
    if r.left():
        n = r.u32()
        for _ in range(n):
            key = r.s64()
            nb = r.u32()
            args = {}
            for _ in range(nb):
                bi = r.u32()
                if bi >= max_buckets:
                    raise DecodeError("choose_args bucket index")
                npos = r.u32()
                rows = []
                for _ in range(npos):
                    sz = r.u32()
                    rows.append([r.u32() for _ in range(sz)])
                ids_size = r.u32()
                ids = [r.s32() for _ in range(ids_size)]
                args[bi] = {"weight_set": rows, "ids": ids}
            cm["choose_args"][key] = args
        cm["tail_present"]["choose_args"] = True
    if r.left():
        t["msr_descents"] = r.u32()
        t["msr_collision_tries"] = r.u32()
        cm["tail_present"]["msr"] = True
    cm["_trailing"] = r.left()
    cm["tunables"] = t
    # 2.4: max_devices recomputed
    md = 0
    for b in buckets:
        if b:
            for it in b["items"]:
                if it >= 0 and it + 1 > md:
                    md = it + 1
    for k in cm["name_map"]:
        if k >= 0 and k + 1 > md:
            md = k + 1
    cm["max_devices"] = md
    return cm


# ---- mapper ---------------------------------------------------------------


class CrushError(Exception):
    pass


def _perm_choose(b, x, r):
    size = len(b["items"])
    pr = r % size
    perm = list(range(size))
    for p in range(pr + 1):
        if p < size - 1:
            j = hash3(x, b["id"], p) % (size - p)
            if j:
                perm[p], perm[p + j] = perm[p + j], perm[p]
    return b["items"][perm[pr]]


def _straw2(b, x, r, position, cargs):
    ids = b["items"]
    weights = b["weights"]
    if cargs is not None:
        ca = cargs.get(b["slot"])
        if ca:
            if ca["weight_set"]:
                pos = min(position, len(ca["weight_set"]) - 1)
                weights = ca["weight_set"][pos]
            if ca["ids"]:
                ids = ca["ids"]
    best = None
    bi = 0
    for i in range(len(b["items"])):
        w = weights[i]
        if w:
            u = hash3(x, ids[i], r) & 0xFFFF
            ln = crush_ln(u) - 0x1000000000000
            if w >= 0x80000000:
                w -= 1 << 32
            # exact signed 64-bit truncating division
            q = abs(ln) // abs(w)
            draw = q if (ln >= 0) == (w > 0) else -q
        else:
            draw = -(1 << 63)
        if best is None or draw > best:
            best = draw
            bi = i
    return b["items"][bi]


def _bucket_choose(b, x, r, position, cargs):
    alg = b["alg"]
    if alg == 5:
        return _straw2(b, x, r, position, cargs)
    if alg == 4:
        best = -1
        bi = 0
        for i, it in enumerate(b["items"]):
            d = (hash3(x, it, r) & 0xFFFF) * b["straws"][i]
            if best < 0 or d > best:
                best = d
                bi = i
        return b["items"][bi]
    if alg == 2:
        for i in range(len(b["items"]) - 1, -1, -1):
            w = hash4(x, b["items"][i], r, b["id"]) & 0xFFFF
            w = (w * b["sums"][i]) >> 16
            if w < b["weights"][i]:
                return b["items"][i]
        return b["items"][0]
    if alg == 1:
        return _perm_choose(b, x, r)
    raise CrushError("bucket alg %d unsupported" % alg)


def _is_out(weight, item, x):
    if item >= len(weight):
        return True
    w = weight[item]
    if w >= 0x10000:
        return False
    if w == 0:
        return True
    return not ((hash2(x, item) & 0xFFFF) < w)


def _choose_firstn(cm, B, x, numrep, T, out, outpos, budget, tries, recurse_tries,
                   local_retries, local_fb, leaf, vary_r, stable, out2, parent_r,
                   weight, cargs):
    buckets = cm["buckets"]
    maxb = cm["max_buckets"]
    rep = 0 if stable else outpos
    while rep < numrep and budget > 0:
        fails_all = 0
        cur = B
        fails_here = 0
        slot_done = False
        while True:
            r = rep + parent_r + fails_all
            reject = False
            collision = False
            if not cur["items"]:
                reject = True
            else:
                if local_fb > 0 and fails_here >= len(cur["items"]) // 2 and fails_here > local_fb:
                    item = _perm_choose(cur, x, r)
                else:
                    item = _bucket_choose(cur, x, r, outpos, cargs)
                if item >= cm["max_devices"]:
                    break
                if item < 0:
                    bs = -1 - item
                    if bs >= maxb or buckets[bs] is None:
                        break
                    itype = buckets[bs]["type"]
                else:
                    itype = 0
                if itype != T:
                    if item >= 0:
                        break
                    cur = buckets[-1 - item]
                    continue
                collision = item in out[:outpos]
                if not collision and leaf:
                    if item < 0:
                        sub = buckets[-1 - item]
                        n = _choose_firstn(cm, sub, x, 1 if stable else outpos + 1, 0, out2, outpos,
                                           budget, recurse_tries, 0, local_retries, local_fb,
                                           False, vary_r, stable, None,
                                           (r >> (vary_r - 1)) if vary_r else 0, weight, cargs)
                        if n <= outpos:
                            reject = True
                    else:
                        out2[outpos] = item
                if not reject and not collision and itype == 0:
                    if _is_out(weight, item, x):
                        reject = True
            if not (reject or collision):
                while len(out) <= outpos:
                    out.append(None)
                out[outpos] = item
                outpos += 1
                budget -= 1
                break
            fails_all += 1
            fails_here += 1
            if collision and fails_here <= local_retries:
                continue
            if local_fb > 0 and fails_here <= len(cur["items"]) + local_fb:
                continue
            if fails_all < tries:
                cur = B
                fails_here = 0
                continue
            break
        rep += 1
    return outpos


def crush_do_rule(cm, rule_id, x, result_max, weight, cargs_key=None):
    """3.3.  returns list of osd ids (replicated firstn rules only)."""
    if rule_id >= cm["max_rules"] or cm["rules"][rule_id] is None:
        raise CrushError("rule %d missing" % rule_id)
    rule = cm["rules"][rule_id]
    if rule["type"] != 1:
        raise CrushError("rule type %d" % rule["type"])
    t = cm["tunables"]
    cargs = None
    if cargs_key is not None:
        if cargs_key in cm["choose_args"]:
            cargs = cm["choose_args"][cargs_key]
        elif -1 in cm["choose_args"]:
            cargs = cm["choose_args"][-1]
    choose_tries = t["choose_total_tries"] + 1
    choose_leaf_tries = 0
    local_retries = t["choose_local_tries"]
    local_fb = t["choose_local_fallback_tries"]
    vary_r = t["chooseleaf_vary_r"]
    stable = t["chooseleaf_stable"]
    result = []
    w = []
    for op, a1, a2 in rule["steps"]:
        if op == 1:
            if (0 <= a1 < cm["max_devices"]) or (a1 < 0 and -1 - a1 < cm["max_buckets"]
                                                 and cm["buckets"][-1 - a1] is not None):
                w = [a1]
        elif op == 8:
            if a1 > 0:
                choose_tries = a1
        elif op == 9:
            if a1 > 0:
                choose_leaf_tries = a1
        elif op == 10:
            if a1 >= 0:
                local_retries = a1
        elif op == 11:
            if a1 >= 0:
                local_fb = a1
        elif op == 12:
            if a1 >= 0:
                vary_r = a1
        elif op == 13:
            if a1 >= 0:
                stable = a1
        elif op in (2, 6):
            if not w:
                continue
            leaf = (op == 6)
            o = []
            c = []
            osize = 0
            for wi in w:
                numrep = a1
                if numrep <= 0:
                    numrep += result_max
                    if numrep <= 0:
                        continue
                bno = -1 - wi
                if bno < 0 or bno >= cm["max_buckets"] or cm["buckets"][bno] is None:
                    continue
                if choose_leaf_tries:
                    rt = choose_leaf_tries
                elif t["chooseleaf_descend_once"]:
                    rt = 1
                else:
                    rt = choose_tries
                oo = []
                cc = [None] * (result_max + 2)
                n = _choose_firstn(cm, cm["buckets"][bno], x, numrep, a2, oo, 0, result_max - osize,
                                   choose_tries, rt, local_retries, local_fb, leaf, vary_r, stable,
                                   cc, 0, weight, cargs)
                o.extend(oo[:n])
                c.extend(cc[:n])
                osize += n
            if leaf:
                o = c[:osize]
            w = o
        elif op == 4:
            for v in w:
                if len(result) < result_max:
                    result.append(v)
            w = []
        elif op in (3, 7, 14, 15, 16):
            raise CrushError("opcode %d out of scope" % op)
    return result


# --------------------------------------------------------------------------
# placement pipeline over a decoded OSDMap (osdmap.md 3.7 / crush note 3.7)
# --------------------------------------------------------------------------

STATE_EXISTS = 0x1
STATE_UP = 0x2
FLAG_HASHPSPOOL = 1


def osd_exists(m, o):
    return 0 <= o < m["max_osd"] and bool(m["osd_state"][o] & STATE_EXISTS)


def osd_up(m, o):
    return osd_exists(m, o) and bool(m["osd_state"][o] & STATE_UP)


def object_ps(pool, name, nspace=b"", key=b""):
    subject = key if key else name
    if nspace:
        subject = nspace + b"\x1f" + subject
    h = pool["object_hash"]
    if h == 2:
        return str_hash_rjenkins(subject)
    if h == 1:
        return str_hash_linux(subject)
    raise CrushError("object_hash %d" % h)


def pg_placement(m, cm, pool_id, ps):
    """full pipeline for (pool, raw seed ps).  returns dict."""
    pool = m["pools"][pool_id]
    if pool["type"] != 1:
        raise CrushError("not a replicated pool")
    pg_seed = stable_mod(ps, pool["pg_num"], pool["pg_num_mask"])
    pg = (pool_id, pg_seed)
    pgp = stable_mod(ps, pool["pgp_num"], pool["pgp_num_mask"])
    if pool["flags"] & FLAG_HASHPSPOOL:
        pps = hash2(pgp, pool_id & M32)
    else:
        pps = (pgp + pool_id) & M32
    weight = m["osd_weight"]
    raw = crush_do_rule(cm, pool["crush_rule"], pps, pool["size"], weight, cargs_key=pool_id)
    raw = [o for o in raw if o == CRUSH_ITEM_NONE or osd_exists(m, o)]
    raw = [o for o in raw if o != CRUSH_ITEM_NONE]
    raw_for_report = list(raw)
    # --- upmap (3.7 step 3) -------------------------------------------------
    def valid(o):
        return o != CRUSH_ITEM_NONE and 0 <= o < m["max_osd"]
    skip = False
    up_m = m.get("pg_upmap", {})
    if pg in up_m:
        lst = up_m[pg]
        for o in lst:
            if valid(o) and weight[o] == 0:
                skip = True
                break
        if not skip:
            raw = list(lst)
    if not skip:
        items = m.get("pg_upmap_items", {}).get(pg)
        if items:
            for frm, to in items:
                if to in raw:
                    continue
                pos = -1
                for i, o in enumerate(raw):
                    if o == frm:
                        pos = i
                        break
                if valid(to) and weight[to] == 0:
                    continue
                if pos >= 0:
                    raw[pos] = to
        prim = m.get("pg_upmap_primaries", {}).get(pg)
        if prim is not None and valid(prim) and weight[prim] != 0:
            for k in range(1, len(raw)):
                if raw[k] == prim:
                    raw[0], raw[k] = raw[k], raw[0]
                    break
    # --- up set -------------------------------------------------------------
    up = [o for o in raw if osd_up(m, o)]
    up_primary = up[0] if up else -1
    up_primary_pre_affinity = up_primary
    # --- primary affinity ---------------------------------------------------
    aff = m.get("osd_primary_affinity") or []
    if aff and up and any(aff[o] != 0x10000 for o in up if 0 <= o < len(aff)):
        pos = -1
        for i, o in enumerate(up):
            a = aff[o]
            if a < 0x10000 and (hash2(pps, o) >> 16) >= a:
                if pos < 0:
                    pos = i
            else:
                pos = i
                break
        if pos >= 0:
            up_primary = up[pos]
            if pos > 0:
                up = [up[pos]] + up[:pos] + up[pos + 1:]
    # --- temp ---------------------------------------------------------------
    temp = [o for o in m["pg_temp"].get(pg, []) if osd_up(m, o)]
    if pg in m["primary_temp"]:
        temp_primary = m["primary_temp"][pg]
    elif temp:
        temp_primary = temp[0]
    else:
        temp_primary = -1
    if temp:
        acting, acting_primary = temp, temp_primary
    else:
        acting = list(up)
        acting_primary = temp_primary if temp_primary != -1 else up_primary
    return {"pg": pg, "pps": pps, "raw": raw_for_report, "up": up, "up_primary": up_primary,
            "acting": acting, "acting_primary": acting_primary,
            "up_primary_pre_affinity": up_primary_pre_affinity, "after_upmap": list(raw)}


# --------------------------------------------------------------------------
# JSON comparison helpers
# --------------------------------------------------------------------------


def iso_to_utime(s):
    # "2026-11-16T08:47:23.599179+0000"
    import calendar
    m = re.match(r"(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)\.(\d+)\+0000$", s)
    if not m:
        if s in ("0.000000", "0"):
            return (0, 0)
        raise ValueError(s)
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    us = int(m.group(7))
    return (calendar.timegm((y, mo, d, h, mi, se)), us)


def utime_eq(ut, s):
    try:
        sec, us = iso_to_utime(s)
    except ValueError:
        return False
    return ut[0] == sec and ut[1] // 1000 == us


def fsid_str(b):
    h = b.hex()
    return "%s-%s-%s-%s-%s" % (h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def pg_str(pg):
    return "%d.%x" % pg


ADDR_TYPE_NAME = {1: "v1", 2: "v2", 3: "any"}


def addrvec_eq(vec, js):
    exp = js.get("addrvec", [])
    if len(exp) != len(vec):
        return False
    for a, e in zip(vec, exp):
        if ADDR_TYPE_NAME.get(a["type"]) != e["type"]:
            return False
        if a["family"] == 2:
            s = "%s:%d" % (a["ip"], a["port"])
        else:
            return False
        if s != e["addr"] or a["nonce"] != e["nonce"]:
            return False
    return True


STATE_NAMES = ["exists", "up", "autoout", "new", "full", "nearfull", "backfillfull",
               "destroyed", "noup", "nodown", "noin", "noout", "stop"]
CACHE_MODES = ["none", "writeback", "forward", "readonly", "readforward", "readproxy", "proxy"]


def state_names(v):
    return [n for i, n in enumerate(STATE_NAMES) if v & (1 << i)]


def pool_vs_json(p, pj, errs, where):
    def eq(a, b, what):
        if a != b:
            errs.append("%s pool %s: %s decoded %r != json %r" % (where, pj.get("pool"), what, a, b))
    eq(p["type"], pj["type"], "type")
    eq(p["size"], pj["size"], "size")
    eq(p["min_size"], pj["min_size"], "min_size")
    eq(p["crush_rule"], pj["crush_rule"], "crush_rule")
    eq(p["object_hash"], pj["object_hash"], "object_hash")
    eq(p["pg_num"], pj["pg_num"], "pg_num")
    eq(p["pgp_num"], pj["pg_placement_num"], "pgp_num")
    eq(p["pg_num_target"], pj["pg_num_target"], "pg_num_target")
    eq(p["pgp_num_target"], pj["pg_placement_num_target"], "pgp_num_target")
    eq(p["pg_num_pending"], pj["pg_num_pending"], "pg_num_pending")
    eq(p["flags"], pj["flags"], "flags")
    eq(str(p["last_change"]), pj["last_change"], "last_change")
    eq(str(p["last_force_op_resend"]), pj["last_force_op_resend"], "last_force_op_resend")
    eq(str(p["last_force_op_resend_prenautilus"]), pj["last_force_op_resend_prenautilus"], "lfor_prenautilus")
    eq(str(p["last_force_op_resend_preluminous"]), pj["last_force_op_resend_preluminous"], "lfor_preluminous")
    eq(p["snap_seq"], pj["snap_seq"], "snap_seq")
    eq(p["snap_epoch"], pj["snap_epoch"], "snap_epoch")
    eq(p["auid"], pj["auid"], "auid")
    eq(p["quota_max_bytes"], pj["quota_max_bytes"], "quota_max_bytes")
    eq(p["quota_max_objects"], pj["quota_max_objects"], "quota_max_objects")
    eq(p["tiers"], pj["tiers"], "tiers")
    eq(p["tier_of"], pj["tier_of"], "tier_of")
    eq(p["read_tier"], pj["read_tier"], "read_tier")
    eq(p["write_tier"], pj["write_tier"], "write_tier")
    eq(CACHE_MODES[p["cache_mode"]], pj["cache_mode"], "cache_mode")
    eq(p["target_max_bytes"], pj["target_max_bytes"], "target_max_bytes")
    eq(p["target_max_objects"], pj["target_max_objects"], "target_max_objects")
    eq(p["cache_target_dirty_ratio_micro"], pj["cache_target_dirty_ratio_micro"], "dirty_ratio")
    eq(p["cache_target_dirty_high_ratio_micro"], pj["cache_target_dirty_high_ratio_micro"], "dirty_high")
    eq(p["cache_target_full_ratio_micro"], pj["cache_target_full_ratio_micro"], "full_ratio")
    eq(p["cache_min_flush_age"], pj["cache_min_flush_age"], "flush_age")
    eq(p["cache_min_evict_age"], pj["cache_min_evict_age"], "evict_age")
    eq(p["erasure_code_profile"], pj["erasure_code_profile"], "ec_profile")
    eq(p["hit_set_period"], pj["hit_set_period"], "hit_set_period")
    eq(p["hit_set_count"], pj["hit_set_count"], "hit_set_count")
    eq(p["use_gmt_hitset"], pj["use_gmt_hitset"], "use_gmt_hitset")
    eq(p["min_read_recency_for_promote"], pj["min_read_recency_for_promote"], "min_read_recency")
    eq(p["min_write_recency_for_promote"], pj["min_write_recency_for_promote"], "min_write_recency")
    eq(p["hit_set_grade_decay_rate"], pj["hit_set_grade_decay_rate"], "decay")
    eq(p["hit_set_search_last_n"], pj["hit_set_search_last_n"], "search_last_n")
    eq(p["stripe_width"], pj["stripe_width"], "stripe_width")
    eq(p["expected_num_objects"], pj["expected_num_objects"], "expected_num_objects")
    eq(p["fast_read"], pj["fast_read"], "fast_read")
    eq(p.get("peering_crush_bucket_count", 0), pj["peering_crush_bucket_count"], "stretch count")
    eq(p["opts_count"], len(pj["options"]), "opts count")
    eq(sorted(p["application_metadata"].keys()), sorted(pj["application_metadata"].keys()), "app keys")
    if not utime_eq(p["create_time"], pj["create_time"]):
        errs.append("%s pool %s: create_time mismatch" % (where, pj.get("pool")))
    eq(len(p["snaps"]), len(pj["pool_snaps"]), "pool_snaps count")
    # removed_snaps JSON is a string like "[2~1]" (hex start~len) in the pool dump
    rs = "[" + ",".join("%x~%x" % (a, b) for a, b in p["removed_snaps"]) + "]"
    eq(rs, pj["removed_snaps"], "removed_snaps")


def osdmap_vs_json(m, j, where):
    errs = []

    def eq(a, b, what):
        if a != b:
            errs.append("%s: %s decoded %r != json %r" % (where, what, a, b))
    eq(m["epoch"], j["epoch"], "epoch")
    eq(fsid_str(m["fsid"]), j["fsid"], "fsid")
    if not utime_eq(m["created"], j["created"]):
        errs.append("%s: created" % where)
    if not utime_eq(m["modified"], j["modified"]):
        errs.append("%s: modified" % where)
    if not utime_eq(m["last_up_change"], j["last_up_change"]):
        errs.append("%s: last_up_change" % where)
    if not utime_eq(m["last_in_change"], j["last_in_change"]):
        errs.append("%s: last_in_change" % where)
    eq(m["flags"], j["flags_num"], "flags")
    eq(m["crush_version"], j["crush_version"], "crush_version")
    eq(m["pool_max"], j["pool_max"], "pool_max")
    eq(m["max_osd"], j["max_osd"], "max_osd")
    eq(len(m["osd_state"]), m["max_osd"], "len(osd_state)")
    eq(len(m["osd_weight"]), m["max_osd"], "len(osd_weight)")
    eq(len(m["client_addrs"]), m["max_osd"], "len(client_addrs)")
    if m["osd_primary_affinity"]:
        eq(len(m["osd_primary_affinity"]), m["max_osd"], "len(osd_primary_affinity)")
    # pools
    jp = {p["pool"]: p for p in j["pools"]}
    eq(sorted(m["pools"].keys()), sorted(jp.keys()), "pool ids")
    for pid, p in m["pools"].items():
        if pid in jp:
            pool_vs_json(p, jp[pid], errs, where)
            eq(m["pool_name"].get(pid), jp[pid]["pool_name"], "pool_name %d" % pid)
    eq(sorted(m["pool_name"].keys()), sorted(m["pools"].keys()), "pool_name keys == pool keys")
    # osds
    jo = {o["osd"]: o for o in j["osds"]}
    exist = [i for i in range(m["max_osd"]) if m["osd_state"][i] & 1]
    eq(sorted(jo.keys()), exist, "existing osd ids")
    for i in exist:
        o = jo.get(i)
        if not o:
            continue
        st = m["osd_state"][i]
        eq(int(bool(st & 2)), o["up"], "osd.%d up" % i)
        eq(int(m["osd_weight"][i] != 0), o["in"], "osd.%d in" % i)
        eq(abs(m["osd_weight"][i] / 65536.0 - o["weight"]) < 1e-5, True, "osd.%d weight" % i)
        pa = m["osd_primary_affinity"][i] if m["osd_primary_affinity"] else 0x10000
        eq(abs(pa / 65536.0 - o["primary_affinity"]) < 1e-5, True, "osd.%d primary_affinity" % i)
        eq(state_names(st), o["state"], "osd.%d state names" % i)
        if not addrvec_eq(m["client_addrs"][i], o["public_addrs"]):
            errs.append("%s: osd.%d public_addrs differ %r vs %r" % (where, i, m["client_addrs"][i], o["public_addrs"]))
    # temp / upmap
    def pgl(js, key="osds"):
        return {e["pgid"]: e[key] for e in js}
    eq({pg_str(k): v for k, v in m["pg_temp"].items()}, pgl(j["pg_temp"]), "pg_temp")
    eq({pg_str(k): v for k, v in m["pg_upmap"].items()}, pgl(j["pg_upmap"]), "pg_upmap")
    eq({pg_str(k): [(a, b) for a, b in v] for k, v in m["pg_upmap_items"].items()},
       {e["pgid"]: [(x["from"], x["to"]) for x in e["mappings"]] for e in j["pg_upmap_items"]},
       "pg_upmap_items")
    jpt = j["primary_temp"]
    if jpt and isinstance(jpt[0], str):
        jpt = [jpt]
    eq({pg_str(k): v for k, v in m["primary_temp"].items()}, {e[0]: e[1] for e in jpt}, "primary_temp")
    jpp = j.get("pg_upmap_primaries", [])
    if jpp and isinstance(jpp[0], str):
        jpp = [jpp]
    if jpp and isinstance(jpp[0], dict):
        eq({pg_str(k): v for k, v in m["pg_upmap_primaries"].items()}, {e["pgid"]: e["primary"] for e in jpp},
           "pg_upmap_primaries")
    else:
        eq({pg_str(k): v for k, v in m["pg_upmap_primaries"].items()}, {e[0]: e[1] for e in jpp}, "pg_upmap_primaries")
    eq({k: dict(v) for k, v in m["erasure_code_profiles"].items()},
       {k: dict(v) for k, v in j["erasure_code_profiles"].items()}, "erasure_code_profiles")
    return errs


# --------------------------------------------------------------------------
# applying an incremental (note 3.5)
# --------------------------------------------------------------------------

import copy

STATE_AUTOOUT = 0x4
STATE_NEW = 0x8
STATE_STOP = 0x1000


def set_max_osd(m, n):
    old = m["max_osd"]
    m["max_osd"] = n
    for key, fill in (("osd_state", 0), ("osd_weight", 0)):
        a = m[key]
        if n > len(a):
            a.extend([fill] * (n - len(a)))
        else:
            del a[n:]
    a = m["client_addrs"]
    if n > len(a):
        a.extend([[] for _ in range(n - len(a))])
    else:
        del a[n:]
    if m["osd_primary_affinity"]:
        a = m["osd_primary_affinity"]
        if n > len(a):
            a.extend([0x10000] * (n - len(a)))
        else:
            del a[n:]


def apply_incremental(m, inc):
    """returns the new state (a fresh dict when an embedded full map is used)."""
    if inc["epoch"] == 1:
        m["fsid"] = inc["fsid"]
    elif inc["fsid"] != m["fsid"]:
        raise DecodeError("incremental fsid mismatch")
    if inc["epoch"] != m["epoch"] + 1:
        raise DecodeError("non-contiguous incremental %d after %d" % (inc["epoch"], m["epoch"]))
    m["epoch"] = inc["epoch"]
    m["modified"] = inc["modified"]
    if inc["fullmap"]:
        return dec_osdmap(inc["fullmap"])
    if inc["new_flags"] >= 0:
        m["flags"] = inc["new_flags"]
    if inc["new_max_osd"] >= 0:
        set_max_osd(m, inc["new_max_osd"])
    if inc["new_pool_max"] != -1:
        m["pool_max"] = inc["new_pool_max"]
    for pid, p in inc["new_pools"].items():
        p = copy.deepcopy(p)
        p["last_change"] = inc["epoch"]
        m["pools"][pid] = p
    for pid, name in inc["new_pool_names"].items():
        m["pool_name"][pid] = name
    for pid in inc["old_pools"]:
        m["pools"].pop(pid, None)
        m["pool_name"].pop(pid, None)
    for o, w in inc["new_weight"].items():
        m["osd_weight"][o] = w
        if w:
            m["osd_state"][o] |= STATE_EXISTS
            m["osd_state"][o] &= ~(STATE_AUTOOUT | STATE_NEW)
    for o, a in inc["new_primary_affinity"].items():
        if not m["osd_primary_affinity"]:
            m["osd_primary_affinity"] = [0x10000] * m["max_osd"]
        m["osd_primary_affinity"][o] = a
    for o, mask in inc["new_state"].items():
        s = mask if mask else STATE_UP
        if (m["osd_state"][o] & STATE_EXISTS) and (s & STATE_EXISTS):
            m["osd_state"][o] = 0
            m["client_addrs"][o] = []
            if m["osd_primary_affinity"]:
                m["osd_primary_affinity"][o] = 0x10000
        else:
            m["osd_state"][o] ^= s
    for o, av in inc["new_up_client"].items():
        m["osd_state"][o] |= STATE_EXISTS | STATE_UP
        m["osd_state"][o] &= ~STATE_STOP
        m["client_addrs"][o] = av
    for pg, v in inc["new_pg_temp"].items():
        if not v:
            m["pg_temp"].pop(pg, None)
        else:
            m["pg_temp"][pg] = v
    for pg, o in inc["new_primary_temp"].items():
        if o == -1:
            m["primary_temp"].pop(pg, None)
        else:
            m["primary_temp"][pg] = o
    for pg, v in inc.get("new_pg_upmap", {}).items():
        m["pg_upmap"][pg] = v
    for pg in inc.get("old_pg_upmap", []):
        m["pg_upmap"].pop(pg, None)
    for pg, v in inc.get("new_pg_upmap_items", {}).items():
        m["pg_upmap_items"][pg] = v
    for pg in inc.get("old_pg_upmap_items", []):
        m["pg_upmap_items"].pop(pg, None)
    for pg, v in inc.get("new_pg_upmap_primary", {}).items():
        m["pg_upmap_primaries"][pg] = v
    for pg in inc.get("old_pg_upmap_primary", []):
        m["pg_upmap_primaries"].pop(pg, None)
    if inc["crush"]:
        m["crush"] = inc["crush"]
    return m


def state_diff(a, b, where):
    """compare the client-visible state of two decoded maps; returns list of diffs"""
    errs = []
    for k in ("epoch", "flags", "max_osd", "osd_state", "osd_weight", "pool_max"):
        if a[k] != b[k]:
            errs.append("%s: %s differs (%r vs %r)" % (where, k, a[k], b[k]))
    if a["modified"] != b["modified"]:
        errs.append("%s: modified differs" % where)
    for k in ("client_addrs", "pg_temp", "primary_temp", "pg_upmap", "pg_upmap_items", "pg_upmap_primaries",
              "pool_name"):
        if a[k] != b[k]:
            errs.append("%s: %s differs" % (where, k))
    pa = a["osd_primary_affinity"] or [0x10000] * a["max_osd"]
    pb = b["osd_primary_affinity"] or [0x10000] * b["max_osd"]
    if pa != pb:
        errs.append("%s: osd_primary_affinity differs %r vs %r" % (where, pa, pb))
    if sorted(a["pools"]) != sorted(b["pools"]):
        errs.append("%s: pool ids differ" % where)
    else:
        for pid in a["pools"]:
            x = {k: v for k, v in a["pools"][pid].items() if not k.startswith("_")}
            y = {k: v for k, v in b["pools"][pid].items() if not k.startswith("_")}
            if x != y:
                d = [k for k in x if x[k] != y.get(k)]
                errs.append("%s: pool %d differs in %s" % (where, pid, d))
    if a["crush"] != b["crush"]:
        errs.append("%s: crush blob differs (%d vs %d bytes)" % (where, len(a["crush"]), len(b["crush"])))
    return errs


def inc_vs_json(inc, j, where):
    errs = []

    def eq(a, b, what):
        if a != b:
            errs.append("%s: %s decoded %r != json %r" % (where, what, a, b))
    eq(inc["epoch"], j["epoch"], "epoch")
    eq(fsid_str(inc["fsid"]), j["fsid"], "fsid")
    if not utime_eq(inc["modified"], j["modified"]):
        errs.append("%s: modified" % where)
    if not utime_eq(inc["new_last_up_change"], j["new_last_up_change"]):
        errs.append("%s: new_last_up_change" % where)
    if not utime_eq(inc["new_last_in_change"], j["new_last_in_change"]):
        errs.append("%s: new_last_in_change" % where)
    eq(inc["new_pool_max"], j["new_pool_max"], "new_pool_max")
    eq(inc["new_flags"], j["new_flags"], "new_flags")
    eq(inc["new_max_osd"], j["new_max_osd"], "new_max_osd")
    eq(bool(inc["fullmap"]), "full_map" in j, "fullmap presence")
    eq(bool(inc["crush"]), "crush" in j, "crush presence")
    eq(sorted(inc["new_pools"]), sorted(p["pool"] for p in j["new_pools"]), "new_pools ids")
    jp = {p["pool"]: p for p in j["new_pools"]}
    for pid, p in inc["new_pools"].items():
        if pid in jp:
            pool_vs_json(p, jp[pid], errs, where)
    eq({k: v for k, v in inc["new_pool_names"].items()}, {e["pool"]: e["name"] for e in j["new_pool_names"]},
       "new_pool_names")
    eq(sorted(inc["old_pools"]), sorted(j["old_pools"]), "old_pools")
    jup = {e["osd"]: e for e in j["new_up_osds"]}
    eq(sorted(inc["new_up_client"]), sorted(jup), "new_up_osds ids")
    for o, av in inc["new_up_client"].items():
        if o in jup and not addrvec_eq(av, jup[o]["public_addrs"]):
            errs.append("%s: new_up addrs osd.%d" % (where, o))
    eq({o: w for o, w in inc["new_weight"].items()}, {e["osd"]: e["weight"] for e in j["new_weight"]}, "new_weight")
    jst = {}
    for e in j["osd_state_xor"]:
        jst[e["osd"]] = e["state_xor"]
    got = {o: state_names(v) if v else None for o, v in inc["new_state"].items()}
    # a zero mask is shown by the dumper as the UP toggle or as an empty list; accept either
    ok = True
    if sorted(got) != sorted(jst):
        ok = False
    else:
        for o in got:
            if got[o] is None:
                if jst[o] not in ([], ["up"]):
                    ok = False
            elif got[o] != jst[o]:
                ok = False
    if not ok:
        errs.append("%s: osd_state_xor decoded %r != json %r" % (where, got, jst))
    eq({pg_str(k): v for k, v in inc["new_pg_temp"].items()}, {e["pgid"]: e["osds"] for e in j["new_pg_temp"]},
       "new_pg_temp")
    jpt = j["primary_temp"]
    if jpt and isinstance(jpt[0], str):
        jpt = [jpt]
    eq({pg_str(k): v for k, v in inc["new_primary_temp"].items()}, {e[0]: e[1] for e in jpt}, "new_primary_temp")
    eq({pg_str(k): v for k, v in inc["new_pg_upmap"].items()}, {e["pgid"]: e["osds"] for e in j["new_pg_upmap"]},
       "new_pg_upmap")
    eq(sorted(pg_str(k) for k in inc["old_pg_upmap"]), sorted(j["old_pg_upmap"]), "old_pg_upmap")
    eq({pg_str(k): [(a, b) for a, b in v] for k, v in inc["new_pg_upmap_items"].items()},
       {e["pgid"]: [(x["from"], x["to"]) for x in e["mappings"]] for e in j["new_pg_upmap_items"]},
       "new_pg_upmap_items")
    eq(sorted(pg_str(k) for k in inc["old_pg_upmap_items"]), sorted(j["old_pg_upmap_items"]), "old_pg_upmap_items")
    eq(len(inc["new_pg_upmap_primary"]), len(j["new_pg_upmap_primaries"]), "new_pg_upmap_primary count")
    eq(len(inc["old_pg_upmap_primary"]), len(j["old_pg_upmap_primaries"]), "old_pg_upmap_primary count")
    eq(inc["new_erasure_code_profiles"] and {k: dict(v) for k, v in inc["new_erasure_code_profiles"].items()} or {},
       j["erasure_code_profiles"], "new_erasure_code_profiles")
    eq(inc["old_erasure_code_profiles"], j["old_erasure_code_profiles"], "old_erasure_code_profiles")
    jrs = {e["pool"]: [(s["begin"], s["length"]) for s in e["snaps"]] for e in j["new_removed_snaps"]}
    eq({k: [tuple(x) for x in v] for k, v in inc["new_removed_snaps"].items()}, jrs, "new_removed_snaps")
    # note 2.6.3 says new_primary_affinity is on the wire; the dumper omits it, so it is checked by
    # apply_incremental against the next full map instead.
    return errs


def crush_struct(cm):
    """structure of a decoded crush map minus the two places that differ by feature set"""
    s = copy.deepcopy(cm)
    for r in s["rules"]:
        if r:
            r["min_size"] = r["max_size"] = None
    s["tail_present"].pop("msr", None)
    for k in ("msr_descents", "msr_collision_tries"):
        s["tunables"].pop(k, None)
    s.pop("raw_len", None)
    return s


# --------------------------------------------------------------------------
# validation (note 3.6) and bounds-checked apply
# --------------------------------------------------------------------------

MAX_OSD_LIMIT = 1 << 20


def validate_map(m):
    """returns a list of problems (empty = ok); the checks of note 3.6"""
    bad = []
    n = m["max_osd"]
    if n < 0 or n > MAX_OSD_LIMIT:
        bad.append("max_osd %d out of range" % n)
        return bad
    for k in ("osd_state", "osd_weight", "client_addrs"):
        if len(m[k]) != n:
            bad.append("%s has %d entries, max_osd is %d" % (k, len(m[k]), n))
    if m["osd_primary_affinity"] and len(m["osd_primary_affinity"]) != n:
        bad.append("osd_primary_affinity has %d entries" % len(m["osd_primary_affinity"]))
    for pid, p in m["pools"].items():
        if p["pg_num"] == 0 or p["pgp_num"] == 0 or p["size"] < 1:
            bad.append("pool %d has pg_num/pgp_num/size zero" % pid)
    return bad


def check_inc_osd_ids(m, inc):
    n = m["max_osd"]
    for key in ("new_state", "new_weight", "new_up_client", "new_primary_affinity"):
        for o in inc[key]:
            if not (0 <= o < n):
                raise DecodeError("incremental %s names osd %d outside [0,%d)" % (key, o, n))


_apply_unchecked = apply_incremental


def apply_incremental_checked(m, inc):
    """apply_incremental plus the id bound check of 3.6 (after the resize of step 6)."""
    if inc["fullmap"]:
        return _apply_unchecked(m, inc)
    # emulate "after step 6": a trial max_osd
    trial = dict(max_osd=inc["new_max_osd"] if inc["new_max_osd"] >= 0 else m["max_osd"])
    check_inc_osd_ids(trial, inc)
    return _apply_unchecked(m, inc)


# --------------------------------------------------------------------------
# byte surgery helpers for the negative / robustness tests (T7, T9)
# --------------------------------------------------------------------------


def refresh_full_crc(buf):
    b = bytearray(buf)
    wrap_len = struct.unpack_from("<I", b, 2)[0]
    end = 6 + wrap_len
    crc_pos = end - 4
    c = crc32c_raw(0xFFFFFFFF, bytes(b[:crc_pos]))
    struct.pack_into("<I", b, crc_pos, c)
    return bytes(b)


def insert_into_envelope(buf, env_offsets, at, extra):
    """insert `extra` bytes at absolute offset `at`; every envelope whose header
    offset is in env_offsets gets its u32 length (at +2) increased."""
    b = bytearray(buf)
    b[at:at] = extra
    for off in env_offsets:
        ln = struct.unpack_from("<I", b, off + 2)[0]
        struct.pack_into("<I", b, off + 2, ln + len(extra))
    return bytes(b)


def robustness_tests(full_bytes, inc_bytes):
    """returns list of (name, ok, detail)"""
    out = []
    m0 = dec_osdmap(full_bytes)
    # T7a: client block struct_v raised to 11 + 5 extra bytes, compat unchanged: must decode
    cb_off = 6
    cb_len = struct.unpack_from("<I", full_bytes, cb_off + 2)[0]
    cb_end = cb_off + 6 + cb_len
    b = bytearray(full_bytes)
    b[cb_off] = 11
    b2 = insert_into_envelope(bytes(b), [0, cb_off], cb_end, b"\xde\xad\xbe\xef\x01")
    b2 = refresh_full_crc(b2)
    try:
        m = dec_osdmap(b2)
        same = all(m[k] == m0[k] for k in ("epoch", "pools", "osd_state", "osd_weight", "client_addrs", "crush"))
        out.append(("T7 raised client struct_v + tail accepted", same and m["crc_ok"] and m["client_v"] == 11,
                    "client_v=%s crc_ok=%s" % (m["client_v"], m["crc_ok"])))
    except DecodeError as e:
        out.append(("T7 raised client struct_v + tail accepted", False, str(e)))
    # T7b: compat raised to 11: must be rejected
    b = bytearray(full_bytes)
    b[cb_off + 1] = 11
    try:
        dec_osdmap(refresh_full_crc(bytes(b)))
        out.append(("T7 raised client struct_compat rejected", False, "accepted"))
    except DecodeError:
        out.append(("T7 raised client struct_compat rejected", True, ""))
    # T7c: pool struct_v raised to 33 with 7 extra bytes inside the pool envelope: accepted
    pool_off = [p["_env_start"] for p in m0["pools"].values()][1]
    plen = struct.unpack_from("<I", full_bytes, pool_off + 2)[0]
    pend = pool_off + 6 + plen
    b = bytearray(full_bytes)
    b[pool_off] = 33
    b2 = insert_into_envelope(bytes(b), [0, cb_off, pool_off], pend, b"\x01\x02\x03\x04\x05\x06\x07")
    b2 = refresh_full_crc(b2)
    try:
        m = dec_osdmap(b2)
        ok = m["pools"][2]["struct_v"] == 33 and m["pools"][2]["pg_num"] == 32 and m["pools"][2]["size"] == 3
        out.append(("T7 raised pool struct_v + tail accepted", ok, "pool v=%d" % m["pools"][2]["struct_v"]))
    except DecodeError as e:
        out.append(("T7 raised pool struct_v + tail accepted", False, str(e)))
    # T7d: pool compat raised above 32: rejected
    b = bytearray(full_bytes)
    b[pool_off + 1] = 33
    try:
        dec_osdmap(refresh_full_crc(bytes(b)))
        out.append(("T7 pool struct_compat 33 rejected", False, "accepted"))
    except DecodeError:
        out.append(("T7 pool struct_compat 33 rejected", True, ""))
    # T9a: every truncation fails cleanly
    bad_exc = 0
    for n in list(range(0, 80)) + list(range(80, len(full_bytes), 7)):
        try:
            dec_osdmap(full_bytes[:n])
            bad_exc += 1000   # a truncated map must never decode
        except DecodeError:
            pass
        except Exception:
            bad_exc += 1
    out.append(("T9 truncated maps rejected with a clean error", bad_exc == 0, "unexpected=%d" % bad_exc))
    # T9b: oversize struct_len of the client block / wrapper
    for name, off in (("wrapper", 0), ("client block", cb_off)):
        b = bytearray(full_bytes)
        struct.pack_into("<I", b, off + 2, len(full_bytes) + 1000)
        try:
            dec_osdmap(bytes(b))
            out.append(("T9 oversize %s struct_len rejected" % name, False, "accepted"))
        except DecodeError:
            out.append(("T9 oversize %s struct_len rejected" % name, True, ""))
    # T9c: giant pool count: rejected without allocating
    b = bytearray(full_bytes)
    struct.pack_into("<I", b, cb_off + 6 + 16 + 4 + 8 + 8, 0xFFFFFFFF)
    try:
        dec_osdmap(bytes(b))
        out.append(("T9 hostile map count rejected", False, "accepted"))
    except DecodeError:
        out.append(("T9 hostile map count rejected", True, ""))
    # T9d: max_osd vs vector length mismatch is caught by validate_map
    m = copy.deepcopy(m0)
    m["max_osd"] = 5
    out.append(("T9 max_osd/vector mismatch flagged by validation", bool(validate_map(m)), str(validate_map(m))))
    m = copy.deepcopy(m0)
    m["max_osd"] = -1
    out.append(("T9 negative max_osd flagged", bool(validate_map(m)), ""))
    m = copy.deepcopy(m0)
    m["pools"][2]["pg_num"] = 0
    out.append(("T9 pg_num 0 flagged", bool(validate_map(m)), ""))
    out.append(("pg_num 0 mask refused", _raises(lambda: _mask(0)), ""))
    # T9e: incremental naming an osd outside [0, max_osd)
    inc = dec_incremental(inc_bytes)
    m = copy.deepcopy(m0)
    m["epoch"] = inc["epoch"] - 1
    m["fsid"] = inc["fsid"]
    inc2 = copy.deepcopy(inc)
    inc2["new_weight"] = {7: 0x10000}
    out.append(("T9 incremental osd id out of range rejected",
                _raises(lambda: apply_incremental_checked(copy.deepcopy(m), inc2)), ""))
    inc3 = copy.deepcopy(inc)
    inc3["epoch"] = inc["epoch"] + 5
    out.append(("incremental across an epoch gap rejected",
                _raises(lambda: apply_incremental_checked(copy.deepcopy(m), inc3)), ""))
    inc4 = copy.deepcopy(inc)
    inc4["fsid"] = b"\x00" * 16
    out.append(("incremental with other fsid rejected",
                _raises(lambda: apply_incremental_checked(copy.deepcopy(m), inc4)), ""))
    # T9f: seeded bit-flip fuzz of both decoders: only DecodeError may escape
    import random
    rnd = random.Random(20261116)
    bad = 0
    n_ok = 0
    for _ in range(1500):
        for src, fn in ((full_bytes, dec_osdmap), (inc_bytes, dec_incremental)):
            b = bytearray(src)
            for _ in range(rnd.choice((1, 1, 2, 4))):
                i = rnd.randrange(len(b))
                b[i] ^= 1 << rnd.randrange(8)
            try:
                fn(bytes(b))
                n_ok += 1
            except DecodeError:
                pass
            except Exception as e:   # anything else is a bug in the decoder
                bad += 1
                if bad < 4:
                    out.append(("fuzz unexpected exception", False, repr(e)))
    out.append(("T9 fuzz: 3000 flipped inputs, only clean errors", bad == 0, "decoded-ok=%d unexpected=%d" % (n_ok, bad)))
    return out


def _raises(fn):
    try:
        fn()
    except DecodeError:
        return True
    return False


# --------------------------------------------------------------------------
# summaries, scrubbing and vectors
# --------------------------------------------------------------------------

import hashlib

PLACEHOLDER_FSID = bytes.fromhex("00112233445566778899aabbccddeeff")


def addr_summary(vec):
    out = []
    for a in vec:
        out.append([a["type"], "%s:%d" % (a["ip"], a["port"]) if a["ip"] else "", a["nonce"]])
    return out


def crush_digest(cm):
    s = crush_struct(cm)
    txt = json.dumps(s, sort_keys=True, default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
    return hashlib.sha256(txt.encode()).hexdigest()[:16]


def state_summary(m):
    pools = {}
    for pid, p in sorted(m["pools"].items()):
        pools[str(pid)] = {k: p[k] for k in ("type", "size", "min_size", "crush_rule", "object_hash", "pg_num",
                                               "pgp_num", "flags", "last_change", "struct_v")}
        pools[str(pid)]["name"] = m["pool_name"].get(pid)
    return {
        "epoch": m["epoch"], "flags": m["flags"], "max_osd": m["max_osd"],
        "osd_state": list(m["osd_state"]), "osd_weight": list(m["osd_weight"]),
        "osd_primary_affinity": list(m["osd_primary_affinity"]) or [0x10000] * m["max_osd"],
        "client_addrs": [addr_summary(v) for v in m["client_addrs"]],
        "pg_temp": {pg_str(k): v for k, v in m["pg_temp"].items()},
        "primary_temp": {pg_str(k): v for k, v in m["primary_temp"].items()},
        "pg_upmap": {pg_str(k): v for k, v in m["pg_upmap"].items()},
        "pg_upmap_items": {pg_str(k): [list(x) for x in v] for k, v in m["pg_upmap_items"].items()},
        "pg_upmap_primaries": {pg_str(k): v for k, v in m["pg_upmap_primaries"].items()},
        "pools": pools,
        "crush": crush_digest(dec_crush(m["crush"])) if m["crush"] else "",
    }


def parse_hex_file(path):
    """hex text with optional '#' comment lines; a line may start with a label word then hex"""
    out = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def hexline_to_bytes(s):
    return bytes.fromhex("".join(s.split()))


def wrap_hex(b, width=96):
    h = b.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


def scrub_ids(buf, repl):
    for old, new in repl:
        buf = buf.replace(old, new)
    return buf


def refresh_inc_crc(buf, full_crc):
    b = bytearray(buf)
    wrap_len = struct.unpack_from("<I", b, 2)[0]
    end = 6 + wrap_len
    struct.pack_into("<I", b, end - 4, full_crc)
    c = crc32c_raw(0xFFFFFFFF, bytes(b[:end - 8]))
    c = crc32c_raw(c, bytes(b[end - 4:end]))
    struct.pack_into("<I", b, end - 8, c)
    return bytes(b)


def vec_name_bytes(o):
    return o if isinstance(o, bytes) else o.encode("utf-8")


def cesu8(s):
    """UTF-8 where non-BMP characters are written as two 3-byte surrogates (what the monitor's
    JSON command parser produced for `ceph osd map` in the oracle run)"""
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp > 0xFFFF:
            cp -= 0x10000
            for sur in (0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF)):
                out += chr(sur).encode("utf-8", "surrogatepass")
        else:
            out += ch.encode("utf-8")
    return bytes(out)


# --------------------------------------------------------------------------
# claims registry (what the run settles about the note)
# --------------------------------------------------------------------------

CLAIMS = collections.OrderedDict()
ITEMS = collections.Counter()
SKIPPED = []


def claim(cid, ok, text):
    prev = CLAIMS.get(cid)
    if prev is not None and prev[0] is False:
        return
    CLAIMS[cid] = (ok, text)


def captures_path(ctx, *parts):
    return os.path.join(ctx["cap"], *parts)


def have(ctx, *parts):
    return ctx["cap"] is not None and os.path.exists(captures_path(ctx, *parts))


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


# --------------------------------------------------------------------------
# section: arithmetic vectors given in the notes
# --------------------------------------------------------------------------


def sec_selftest(ctx):
    R.section("A. arithmetic known answers quoted in the notes (crc, hashes, stable_mod, pps)")
    # msgr2 note 2.5: crc of "123456789"
    d = b"123456789"
    R.check(crc32c_raw(0xFFFFFFFF, d) == 0x1CF96D7C, "raw crc32c(seed ffffffff) of 123456789 = 1cf96d7c")
    R.check(crc32c_raw(0xFFFFFFFF, d) ^ 0xFFFFFFFF == 0xE3069283, "textbook crc32c of 123456789 = e3069283")
    R.check(crc32c_raw(0, d) == 0x58E3FA20, "raw crc32c(seed 0) of 123456789 = 58e3fa20")
    R.check(_CRC_TAB[1] == 0xF26B8303 and _CRC_TAB[2] == 0xE13B70F7, "generated table starts 0, f26b8303, e13b70f7")
    sh = [(b"", 0xbd49d10d, 0), (b"a", 0x29eec818, 0x42f2), (b"foo", 0x7fc1f406, 0x24db2a),
          (b"abcdefghijkl", 0x0b1b3ea5, 0xf281eff0), (b"abcdefghijklm", 0x3122b031, 0x6b959a82),
          (b"rbd_directory", 0x30a98c1c, 0x9569da2c), (b"rbd_id.myimage", 0xf8d9dc15, 0xca6e1713),
          (b"rbd_header.1234abcd5678", 0xdb3ea4d9, 0xc6227fd9),
          (b"rbd_data.1234abcd5678.0000000000000000", 0x89a0b515, 0xe9caf84f),
          (b"ns\x1ffoo", 0xac17f0b6, 0xccc913ee)]
    ok = all(str_hash_rjenkins(i) == a and str_hash_linux(i) == b for i, a, b in sh)
    R.check(ok, "string hashes of crush note 5.1 (rjenkins and linux dcache, 10 inputs)")
    h = [(hash2(0, 0), 0x19ad4ce9), (hash2(1, 2), 0xb78dee9c), (hash2(0x7fc1f406, 1), 0x8ddb71b1),
         (hash2(0xffffffff, 0xffffffff), 0x9f3c11cc), (hash3(0, 0, 0), 0x7a3bf3b2), (hash3(1, 2, 3), 0x735ad42b),
         (hash3(0x12345678, 0xffffffff, 7), 0x03097224), (hash3(5, 0xffffffff, 0), 0x3e502f1c),
         (hash4(0, 0, 0, 0), 0x3fafb04d), (hash4(1, 2, 3, 4), 0x696d1f16),
         (hash2(6, 1), 0xd77484f9), (hash2(6, 2), 0x37f72ca0), (hash2(14, 1), 0xadee4b52)]
    R.check(all(a == b for a, b in h), "crush hash2/3/4 vectors of crush note 5.1 (13 values)")
    sm = [(stable_mod(0x7fc1f406, 12, 15), 6), (stable_mod(0x7fc1f40e, 12, 15), 6), (stable_mod(0x7fc1f40e, 16, 15), 14),
          (stable_mod(0xffffffff, 100, 127), 63), (stable_mod(100, 100, 127), 36), (stable_mod(0x1234, 1, 0), 0)]
    R.check(all(a == b for a, b in sm), "stable_mod vectors of crush note 5.1")
    R.check([_mask(n) for n in (1, 2, 32, 100, 12)] == [0, 1, 31, 127, 15], "pg_num_mask examples of osdmap note 2.5 (1,2,32,100,12)")
    if ctx["ref"]:
        lnv = {0: 0, 1: 0x100000000000, 2: 0x195c01a39fbd, 255: 0x800000000000, 256: 0x80171e3b6d7a,
               0x1234: 0xc2fb9e09ec18, 0x7fff: 0xf00000000000, 0x8000: 0xf0002e2a60a0, 0xfffe: 0xfffffd61ad10,
               0xffff: 0xfffff0000000}
        R.check(all(crush_ln(k) == v for k, v in lnv.items()), "crush_ln vectors of crush note 5.1 (tables loaded at run time)")
    ITEMS["selftest"] += 60


# --------------------------------------------------------------------------
# section: stored maps (gt3 = every epoch 1..89 as the monitor stores them)
# --------------------------------------------------------------------------


def sec_stored(ctx):
    R.section("B. every stored OSDMap and Incremental, epochs 1..89 (gt3) against ceph-dencoder JSON")
    if not have(ctx, "gt3", "full"):
        SKIPPED.append("B (gt3 missing)")
        return None
    fulls, incs, fb, ib = {}, {}, {}, {}
    n_err = []
    for e in range(1, 90):
        fb[e] = read_file(captures_path(ctx, "gt3", "full", "full.%05d.bin" % e))
        ib[e] = read_file(captures_path(ctx, "gt3", "inc", "inc.%05d.bin" % e))
        fulls[e] = dec_osdmap(fb[e])
        incs[e] = dec_incremental(ib[e])
    R.ok("decoded 89 full maps and 89 incrementals without error")
    ctx["fulls"], ctx["incs"], ctx["fb"], ctx["ib"] = fulls, incs, fb, ib
    # versions
    vs = collections.Counter((m["wrapper_v"], m["wrapper_compat"], m["client_v"], m["client_compat"],
                              m["osd_block_v"], m["osd_block_compat"]) for m in fulls.values())
    R.check(list(vs) == [(8, 7, 10, 1, 9, 1)], "full map versions: wrapper 8/compat 7, client block 10/compat 1, OSD block 9/compat 1",
            str(dict(vs)))
    claim("2.4.2 tentacle row", list(vs) == [(8, 7, 10, 1, 9, 1)] and set(POOL_VERSIONS) == {32},
          "full map wrapper 8/7, client block 10 (compat 1), OSD-only block 9; pg_pool_t struct_v 32 (compat 5), all 89 epochs")
    ivs = collections.Counter((i["wrapper_v"], i["wrapper_compat"], i["client_v"], i["client_compat"], i["osd_block_v"])
                              for i in incs.values())
    R.check(list(ivs) == [(8, 7, 9, 1, 9)], "incremental versions: wrapper 8/7, client block 9/compat 1, OSD block 9", str(dict(ivs)))
    R.check(set(POOL_VERSIONS) == {32}, "every decoded pg_pool_t has struct_v 32", str(dict(POOL_VERSIONS)))
    pcompat = {p["struct_compat"] for m in fulls.values() for p in m["pools"].values()}
    R.check(pcompat == {5}, "every pg_pool_t has struct_compat 5", str(pcompat))
    R.check(all(p["_consumed_to_end"] for m in fulls.values() for p in m["pools"].values()),
            "pool fields of table 2.5 (rows 1-53) end exactly at the pool envelope end in all %d pool records" %
            sum(len(m["pools"]) for m in fulls.values()))
    R.check(all(p["_trailing"] == 0 for i in incs.values() for p in i["new_pools"].values()),
            "same for pool records inside incrementals")
    R.check(all(m["_client_block_consumed_exactly"] for m in fulls.values()) and
            all(i["_client_block_consumed_exactly"] for i in incs.values()),
            "client block tables 2.4.3 / 2.6.3 consume the block exactly (no unknown tail) in all 178 blobs")
    R.check(all(m["_wrapper_trailing"] == 0 for m in fulls.values()) and
            all(i["_wrapper_trailing"] == 0 for i in incs.values()), "nothing between the last field and the wrapper end")
    # JSON compare
    bad = []
    for e in range(1, 90):
        if not have(ctx, "gt3", "full-json", "full.%05d.json" % e):
            continue
        jf = json.load(open(captures_path(ctx, "gt3", "full-json", "full.%05d.json" % e)))
        bad += osdmap_vs_json(fulls[e], jf, "full e%d" % e)
        ji = json.load(open(captures_path(ctx, "gt3", "inc-json", "inc.%05d.json" % e)))
        bad += inc_vs_json(incs[e], ji, "inc e%d" % e)
        ITEMS["json field-groups"] += 2
    R.check(not bad, "all 89 full maps and 89 incrementals equal the ceph-dencoder JSON field by field", "; ".join(bad[:3]))
    # the comparison itself must be able to fail: alter one field at a time and expect a report
    probe = copy.deepcopy(fulls[42])
    jf42 = json.load(open(captures_path(ctx, "gt3", "full-json", "full.00042.json")))
    detect = []
    for name, mut in (("pool size", lambda x: x["pools"][2].__setitem__("size", 2)),
                      ("osd weight", lambda x: x["osd_weight"].__setitem__(1, 0x8000)),
                      ("address port", lambda x: x["client_addrs"][0][0].__setitem__("port", 1)),
                      ("pg_temp", lambda x: x["pg_temp"].__setitem__((2, 3), [0, 1]))):
        q = copy.deepcopy(probe)
        mut(q)
        detect.append(bool(osdmap_vs_json(q, jf42, "probe")))
    ji = json.load(open(captures_path(ctx, "gt3", "inc-json", "inc.00043.json")))
    q = copy.deepcopy(incs[43])
    q["new_weight"][0] = 1
    detect.append(bool(inc_vs_json(q, ji, "probe")))
    R.check(all(detect), "self-test: the JSON comparison reports every one of 5 deliberately altered fields")
    # crc
    R.check(all(m["crc_ok"] for m in fulls.values()), "full map crc = raw CRC-32C, seed 0xFFFFFFFF, no final inversion, over wrapper minus crc field (89/89)")
    R.check(all(m["crc_tail_len"] == 0 for m in fulls.values()), "no bytes after the crc field inside the wrapper (89/89)")
    R.check(all(i["inc_crc_ok"] for i in incs.values()), "incremental inc_crc = same CRC over wrapper minus inc_crc field, covering full_crc (89/89)")
    R.check(all(incs[e]["full_crc"] == fulls[e]["crc"] for e in fulls), "incremental full_crc equals the crc of the stored full map of that epoch (89/89)")
    R.check(all(m["crc_computed"] ^ 0xFFFFFFFF == m["crc_textbook"] and m["crc_textbook"] != m["crc"] for m in fulls.values()),
            "the textbook (inverted) CRC-32C never equals the stored value, so the inversion statement matters")
    claim("2.4.5 crc", all(m["crc_ok"] for m in fulls.values()) and all(i["inc_crc_ok"] for i in incs.values()),
          "89 maps + 89 incrementals: start 0xFFFFFFFF, no final inversion, range = wrapper minus the crc field, empty tail")
    # sorted
    R.check(not SORT_VIOLATIONS, "map / set keys arrive in ascending order (%d adjacent key pairs seen)" % SORT_CHECKED[0])
    claim("2.1 sorted", not SORT_VIOLATIONS and SORT_CHECKED[0] > 100,
          "%d adjacent key pairs in maps decoded from the capture, 0 out of order (pg_temp up to 32 entries, pools, names)" % SORT_CHECKED[0])
    # pg_t
    R.check(set(PGT_SEEN) == {(1, -1)}, "every pg_t is 17 bytes: version 1, preferred -1 (%d seen)" % len(PGT_SEEN))
    # addresses
    ao = ADDR_OBS
    R.check(set(ao["elen"]) == {16} and set(ao["family"]) == {2} and set(ao["struct_len"]) == {28} and
            ao["nonzero_pad"] == 0 and set(ao["marker"]) == {1} and set(ao["struct_v"]) == {1} and set(ao["compat"]) == {1},
            "every entity_addr_t is the 35-byte IPv4 form: marker 1, v1/compat 1, struct_len 28, elen 16, family 2, pad zero",
            str({k: dict(v) if hasattr(v, "items") else v for k, v in ao.items()}))
    rebuilt = 0
    for m in fulls.values():
        for vec in m["client_addrs"]:
            for a in vec:
                exp = bytes([1, 1, 1]) + struct.pack("<I", 28) + struct.pack("<III", a["type"], a["nonce"], 16) + \
                    struct.pack("<H", 2) + struct.pack(">H", a["port"]) + bytes(int(x) for x in a["ip"].split(".")) + b"\x00" * 8
                if exp != a["raw"]:
                    R.bad("address re-encode mismatch")
                    break
                rebuilt += 1
    R.ok("%d addresses re-encoded from their decoded fields reproduce the captured bytes (port big-endian)" % rebuilt)
    R.check(ao["veclen"][0] > 0 and ao["veclen"][2] > 0 and set(ao["veclen"]) <= {0, 2}, "address vectors: count 0 (never-up OSD) and count 2 occur, nothing else",
            str(dict(ao["veclen"])))
    types_per_vec = collections.Counter()
    for m in fulls.values():
        for vec in m["client_addrs"]:
            if vec:
                types_per_vec[tuple(a["type"] for a in vec)] += 1
    R.check(list(types_per_vec) == [(2, 1)], "every non-empty client address vector is [v2 entry, v1 entry] (v2 first)", str(dict(types_per_vec)))
    claim("2.1.2 ipv4 layout", rebuilt > 100 and ao["nonzero_pad"] == 0,
          "IPv4 sockaddr body = port (big-endian), address, 8 zero bytes; struct_len 28, elen 16: %d entries re-encoded byte for byte" % rebuilt)
    claim("2.1.3 empty vector", ao["veclen"][0] > 0 and 28 not in ao["elen"],
          "never-up OSDs carry the 5-byte empty vector (%d seen); no blank elen-28 entry anywhere" % ao["veclen"][0])
    claim("Q12 v2 first", list(types_per_vec) == [(2, 1)], "all %d dual-stack OSD vectors list v2 before v1" % sum(types_per_vec.values()))
    claim("Q11 elen", set(ao["elen"]) == {16}, "no address with an elen other than 16 (IPv4 only; no IPv6 in the lab)")
    # pool tail rows 50-53 and a few single statements of the note
    R.check(all(p["_row52_present"] == 0 and p["nonprimary_shards"] == (0, 0) and p["peering_crush_bucket_count"] == 0
                for m_ in fulls.values() for p in m_["pools"].values()),
            "pool rows 52-53: non-stretch pools carry the single byte 0 (row 52) and two varints 00 00 (row 53)")
    aff_first = min(e for e in fulls if fulls[e]["osd_primary_affinity"])
    inc_first = min(e for e in incs if incs[e]["new_primary_affinity"])
    R.check(aff_first == inc_first and all(len(fulls[e]["osd_primary_affinity"]) in (0, fulls[e]["max_osd"]) for e in fulls) and
            all(not fulls[e]["osd_primary_affinity"] for e in fulls if e < aff_first),
            "osd_primary_affinity is an empty vector until the first new_primary_affinity (epoch %d), then max_osd entries" % aff_first)
    claim("2.6.3 affinity on wire", aff_first == inc_first and incs[inc_first]["new_primary_affinity"] != {},
          "new_primary_affinity (map<s32,u32>, omitted by the dencoder dump) decodes from the raw bytes at epochs 55 and 57 and the applied state equals the full maps")
    down = [e for e in fulls if fulls[e]["osd_state"] and any((fulls[e]["osd_state"][o] & 3) == 1 and fulls[e]["client_addrs"][o]
                                                             for o in range(fulls[e]["max_osd"]))]
    R.check(len(down) > 0, "an existing but down OSD keeps its last client address vector (%d epochs, e.g. %s)" % (len(down), down[:3]))
    claim("3.5 step 14 down keeps addr", len(down) > 0, "a down OSD keeps its last address (osd.2, epochs %s...)" % down[:3])
    if have(ctx, "gt3", "meta.first_committed.bin"):
        fc = struct.unpack("<Q", read_file(captures_path(ctx, "gt3", "meta.first_committed.bin"))[:8])[0]
        ctx["first_committed"] = fc
        R.check(fc == 1, "the monitor store's first_committed is 1, the value MOSDMap reports as trim lower bound")
    # apply chain
    st = None
    errs = []
    for e in range(1, 90):
        inc = incs[e]
        if st is None:
            st = dec_osdmap(inc["fullmap"])
            if inc["epoch"] != 1 or fsid_str(inc["fsid"]) is None:
                errs.append("first")
        else:
            st = apply_incremental_checked(st, inc)
        d = state_diff_nocrush(st, fulls[e], "e%d" % e)
        if dec_crush(st["crush"]) and crush_struct(dec_crush(st["crush"])) != crush_struct(dec_crush(fulls[e]["crush"])):
            d.append("e%d crush structure differs" % e)
        errs += d
        ITEMS["apply steps"] += 1
    R.check(not errs, "applying incrementals 1..89 in the order of 3.5 reproduces the stored full map of every epoch (state, pools, pg_temp, upmap, affinity, addresses, crush structure)",
            "; ".join(errs[:3]))
    claim("3.5 order", not errs, "incrementals 1..89 applied in the note's order reproduce the monitor's full map at every epoch")
    # coverage and Q5
    cov = collections.Counter()
    q5 = []
    for e, inc in incs.items():
        for key in ("new_pools", "new_pool_names", "old_pools", "new_up_client", "new_state", "new_weight", "new_pg_temp",
                    "new_primary_temp", "new_primary_affinity", "new_pg_upmap", "old_pg_upmap", "new_pg_upmap_items",
                    "old_pg_upmap_items", "new_pg_upmap_primary", "old_pg_upmap_primary", "new_removed_snaps",
                    "new_erasure_code_profiles"):
            if inc[key]:
                cov[key] += 1
        if inc["fullmap"]:
            cov["fullmap"] += 1
        if inc["crush"]:
            cov["crush"] += 1
        if inc["new_flags"] >= 0:
            cov["new_flags"] += 1
        if inc["new_max_osd"] >= 0:
            cov["new_max_osd"] += 1
        if inc["new_pool_max"] != -1:
            cov["new_pool_max"] += 1
        for o, mask in inc["new_state"].items():
            if mask == 0:
                cov["new_state mask 0"] += 1
            if mask & 1:
                cov["new_state with EXISTS bit"] += 1
            if inc["new_weight"].get(o):
                q5.append((e, o, mask))
        for pg, v in inc["new_pg_temp"].items():
            cov["pg_temp clear" if not v else "pg_temp set"] += 1
        for pg, v in inc["new_primary_temp"].items():
            cov["primary_temp clear (-1)" if v == -1 else "primary_temp set"] += 1
        for o in inc["new_weight"]:
            if o >= 0 and inc["new_weight"][o] == 0:
                cov["new_weight 0 (out)"] += 1
    ctx["coverage"] = cov
    R.info("incremental fields exercised by the 89 stored epochs: %s" % dict(cov))
    both = [x for x in q5 if x[2] & 1]
    R.check(not both, "no incremental gives a non-zero weight and toggles EXISTS for the same OSD (Q5, create path only)",
            str(both))
    created = [e for e, i in incs.items() if any(mask & STATE_NEW for mask in i["new_state"].values())]
    claim("Q5 create path", not both and bool(created),
          "OSD creation (epochs %s): the non-zero weight comes with state NEW only, never the EXISTS bit; destroy / purge were not exercised" % created)
    return True


def state_diff_nocrush(a, b, where):
    a2 = dict(a)
    b2 = dict(b)
    a2["crush"] = b2["crush"] = b""
    return state_diff(a2, b2, where)


# --------------------------------------------------------------------------
# section: ground-truth maps outside the store (gt, gt2, baseline)
# --------------------------------------------------------------------------


def sec_gt_maps(ctx):
    R.section("C. maps fetched with `ceph osd getmap` (gt, gt2 steps, baseline-after)")
    if not have(ctx, "gt", "osdmap.bin"):
        SKIPPED.append("C (gt missing)")
        return
    b42 = read_file(captures_path(ctx, "gt", "osdmap.bin"))
    m42 = dec_osdmap(b42)
    ctx["m42"], ctx["b42"] = m42, b42
    j = json.load(open(captures_path(ctx, "gt", "dencoder-OSDMap.json")))
    errs = osdmap_vs_json(m42, j, "gt/osdmap.bin")
    R.check(not errs, "gt/osdmap.bin (epoch 42) equals dencoder-OSDMap.json field by field", "; ".join(errs[:3]))
    R.check(m42["crc_ok"] and m42["wrapper_v"] == 8, "gt/osdmap.bin crc ok")
    if "fb" in ctx:
        R.check(ctx["fb"][42] == b42, "the map returned by `osd getmap` is byte-identical to the stored epoch 42 map")
    # gt2 steps
    steps = {}
    for f in sorted(glob.glob(captures_path(ctx, "gt2", "osdmap.s*.bin"))):
        b = read_file(f)
        m = dec_osdmap(b)
        steps[os.path.basename(f)] = (m, b)
    R.check(all(m["crc_ok"] and m["_client_block_consumed_exactly"] for m, b in steps.values()) and len(steps) == 24,
            "24 intermediate maps of gt2 decode, crc ok, consumed exactly")
    same = 0
    if "fb" in ctx:
        for name, (m, b) in steps.items():
            if m["epoch"] in ctx["fb"] and ctx["fb"][m["epoch"]] == b:
                same += 1
    R.check(same == len(steps), "each gt2 map is byte-identical to the stored map of its epoch (%d/%d)" % (same, len(steps)))
    ctx["steps"] = steps
    # baseline-after (epoch 92) against the text dump
    if have(ctx, "baseline", "baseline-after", "osdmap.bin"):
        b92 = read_file(captures_path(ctx, "baseline", "baseline-after", "osdmap.bin"))
        m92 = dec_osdmap(b92)
        ctx["m92"], ctx["b92"] = m92, b92
        txt = open(captures_path(ctx, "baseline", "baseline-after", "osd-dump.txt")).read()
        errs = []
        if "epoch %d\n" % m92["epoch"] not in txt:
            errs.append("epoch")
        if "fsid " + fsid_str(m92["fsid"]) not in txt:
            errs.append("fsid")
        for line in txt.splitlines():
            g = re.match(r"pool (\d+) '(.*?)' replicated size (\d+) min_size (\d+) crush_rule (\d+) object_hash rjenkins "
                         r"pg_num (\d+) pgp_num (\d+) .*?last_change (\d+) flags (\S+)", line)
            if g:
                pid = int(g.group(1))
                p = m92["pools"].get(pid)
                names = [n for n, bit in (("hashpspool", 0), ("selfmanaged_snaps", 13)) if p and p["flags"] >> bit & 1]
                if not p or (m92["pool_name"][pid], p["size"], p["min_size"], p["crush_rule"], p["pg_num"], p["pgp_num"],
                             p["last_change"], ",".join(names)) != (g.group(2), int(g.group(3)), int(g.group(4)),
                                                                    int(g.group(5)), int(g.group(6)), int(g.group(7)),
                                                                    int(g.group(8)), g.group(9)):
                    errs.append("pool %d" % pid)
            g = re.match(r"osd\.(\d+) (up|down)\s+(in|out)\s+weight ([0-9.]+) up_from \d+ up_thru \d+ down_at \d+ "
                         r"last_clean_interval \[\d+,\d+\) \[v2:([\d.]+):(\d+)/(\d+),v1:([\d.]+):(\d+)/(\d+)\]", line)
            if g:
                o = int(g.group(1))
                v = m92["client_addrs"][o]
                if bool(m92["osd_state"][o] & 2) != (g.group(2) == "up") or \
                        [(a["type"], a["ip"], a["port"], a["nonce"]) for a in v] != \
                        [(2, g.group(5), int(g.group(6)), int(g.group(7))), (1, g.group(8), int(g.group(9)), int(g.group(10)))]:
                    errs.append("osd.%d" % o)
        R.check(not errs, "epoch 92 map (baseline-after) agrees with `ceph osd dump` text: epoch, fsid, pools, osd up/addresses", str(errs))
        R.check(m92["crc_ok"], "epoch 92 map crc ok")


# --------------------------------------------------------------------------
# section: crush blob decode vs the monitor's JSON
# --------------------------------------------------------------------------

ALG_NAMES = {1: "uniform", 2: "list", 3: "tree", 4: "straw", 5: "straw2"}
OP_NAMES = {1: "take", 2: "choose_firstn", 3: "choose_indep", 4: "emit", 6: "chooseleaf_firstn",
            7: "chooseleaf_indep", 8: "set_choose_tries", 9: "set_chooseleaf_tries", 10: "set_choose_local_tries",
            11: "set_choose_local_fallback_tries", 12: "set_chooseleaf_vary_r", 13: "set_chooseleaf_stable"}


def crush_vs_json(cm, j, where):
    errs = []
    dev = {d["id"]: d["name"] for d in j["devices"]}
    for did, nm in dev.items():
        if cm["name_map"].get(did) != nm:
            errs.append("%s device %d name" % (where, did))
    types = {t["type_id"]: t["name"] for t in j["types"]}
    if cm["type_map"] != types:
        errs.append("%s type_map" % where)
    jb = {b["id"]: b for b in j["buckets"]}
    mb = {b["id"]: b for b in cm["buckets"] if b}
    if sorted(jb) != sorted(mb):
        errs.append("%s bucket ids %r vs %r" % (where, sorted(mb), sorted(jb)))
    for bid, b in mb.items():
        e = jb.get(bid)
        if not e:
            continue
        if (cm["name_map"].get(bid), b["type"], b["weight"], ALG_NAMES[b["alg"]]) != (e["name"], e["type_id"], e["weight"], e["alg"]):
            errs.append("%s bucket %d header" % (where, bid))
        if [(i, w) for i, w in zip(b["items"], b["weights"])] != [(x["id"], x["weight"]) for x in e["items"]]:
            errs.append("%s bucket %d items" % (where, bid))
    jr = {r["rule_id"]: r for r in j["rules"]}
    mr = {r["id"]: r for r in cm["rules"] if r}
    if sorted(jr) != sorted(mr):
        errs.append("%s rule ids" % where)
    for rid, r in mr.items():
        e = jr.get(rid)
        if not e:
            continue
        if cm["rule_name_map"].get(rid) != e["rule_name"] or r["type"] != e["type"]:
            errs.append("%s rule %d header" % (where, rid))
        steps = []
        for op, a1, a2 in r["steps"]:
            steps.append((OP_NAMES.get(op, op), a1, a2))
        js = []
        for s in e["steps"]:
            op = s["op"]
            if op == "take":
                js.append(("take", s["item"], 0))
            elif op in ("choose_firstn", "chooseleaf_firstn"):
                tid = next((k for k, v in types.items() if v == s["type"]), None)
                js.append((op, s["num"], tid))
            elif op == "emit":
                js.append(("emit", 0, 0))
            else:
                js.append((op, s.get("num", s.get("item")), 0))
        if steps != js:
            errs.append("%s rule %d steps %r vs %r" % (where, rid, steps, js))
    t = cm["tunables"]
    for k in ("choose_local_tries", "choose_local_fallback_tries", "choose_total_tries", "chooseleaf_descend_once",
              "chooseleaf_vary_r", "chooseleaf_stable", "straw_calc_version", "allowed_bucket_algs"):
        if t[k] != j["tunables"][k]:
            errs.append("%s tunable %s %r vs %r" % (where, k, t[k], j["tunables"][k]))
    return errs


def sec_crush(ctx):
    R.section("D. CRUSH blob decoding (crush note 2.2, 2.4)")
    if not have(ctx, "gt", "crush.bin"):
        SKIPPED.append("D (gt/crush.bin missing)")
        return
    j = json.load(open(captures_path(ctx, "gt", "crush-dump.json")))
    gcm = dec_crush(read_file(captures_path(ctx, "gt", "crush.bin")))
    errs = crush_vs_json(gcm, j, "getcrushmap")
    R.check(not errs, "`ceph osd getcrushmap` blob decodes to the monitor's crush dump (devices, types, buckets, items, rules, tunables)", "; ".join(errs[:3]))
    R.check(gcm["_trailing"] == 0 and gcm["max_devices"] == len(j["devices"]) == gcm["wire_max_devices"],
            "no bytes left after the last group; recomputed max_devices (3) = devices in the dump = wire value")
    if "m42" in ctx:
        ecm = dec_crush(ctx["m42"]["crush"])
        errs = crush_vs_json(ecm, j, "embedded e42")
        R.check(not errs, "the blob embedded in the epoch 42 OSDMap decodes to the same crush dump", "; ".join(errs[:3]))
        R.check("msr" not in ecm["tail_present"] and "msr" in gcm["tail_present"],
                "embedded blob has no MSR tunable pair; getcrushmap blob has it (crush note 2.1 (a))",
                "embedded tails %s; getcrushmap tails %s" % (sorted(ecm["tail_present"]), sorted(gcm["tail_present"])))
        R.check(crush_struct(ecm) == crush_struct(gcm), "embedded and getcrushmap blobs differ only by the MSR pair")
        R.check(ctx["m42"]["crush"] != read_file(captures_path(ctx, "gt", "crush.bin")) and
                len(read_file(captures_path(ctx, "gt", "crush.bin"))) - len(ctx["m42"]["crush"]) == 8,
                "the two forms differ by exactly 8 bytes (two u32)")
    claims_msr = None
    if "incs" in ctx:
        with_crush = [e for e, i in ctx["incs"].items() if i["crush"]]
        inc_msr = all("msr" in dec_crush(ctx["incs"][e]["crush"])["tail_present"] for e in with_crush)
        full_nomsr = all("msr" not in dec_crush(ctx["fulls"][e]["crush"])["tail_present"] for e in ctx["fulls"] if ctx["fulls"][e]["crush"])
        errs = []
        for e in with_crush:
            a = crush_struct(dec_crush(ctx["incs"][e]["crush"]))
            b = crush_struct(dec_crush(ctx["fulls"][e]["crush"]))
            if a != b:
                errs.append(e)
        R.check(inc_msr and full_nomsr and not errs,
                "in %d incrementals that carry a crush map the blob has the MSR pair, in all 89 full maps it has not; structures equal" % len(with_crush), str(errs))
        claim("crush 2.1 (a) msr pair", inc_msr and full_nomsr and not errs and len(with_crush) > 5,
              "full-map blob has no MSR pair (89/89), crush field of %d incrementals and getcrushmap have it" % len(with_crush))
        sizes = {(r["min_size"], r["max_size"]) for e in ctx["fulls"] for r in dec_crush(ctx["fulls"][e]["crush"])["rules"] if r}
        sizes_inc = {(r["min_size"], r["max_size"]) for e in with_crush for r in dec_crush(ctx["incs"][e]["crush"])["rules"] if r}
        R.info("rule min/max bytes seen: full maps %s, incrementals %s (both 1/100: the stored value equals the constant, so this does not distinguish the two cases)" % (sorted(sizes), sorted(sizes_inc)))
        claim("crush 2.1 (b) rule sizes", None, "all rules store 1/100 themselves, so 'stored value vs constant 1/100' cannot be told apart in this lab")
    ITEMS["crush blobs"] += 180


# --------------------------------------------------------------------------
# section: placement
# --------------------------------------------------------------------------


def parse_pg_dump(path):
    rx = re.compile(r"^(\d+)\.([0-9a-f]+)\s+raw \(\[([^\]]*)\], p(-?\d+)\) up \(\[([^\]]*)\], p(-?\d+)\) acting \(\[([^\]]*)\], p(-?\d+)\)")

    def lst(s):
        return [int(x) for x in s.split(",") if x != ""]
    out = {}
    for line in open(path):
        g = rx.match(line)
        if g:
            out[(int(g.group(1)), int(g.group(2), 16))] = (lst(g.group(3)), int(g.group(4)), lst(g.group(5)), int(g.group(6)),
                                                          lst(g.group(7)), int(g.group(8)))
    return out


def sec_placement(ctx):
    R.section("E. placement pipeline (osdmap note 3.7 + crush note 3) against the monitor, crushtool and osdmaptool")
    if not ctx["ref"]:
        SKIPPED.append("E (no reference tree for the crush_ln tables)")
        return
    if "m42" not in ctx:
        SKIPPED.append("E (no gt map)")
        return
    m = ctx["m42"]
    cm = dec_crush(m["crush"])
    weight16 = [0x10000] * cm["max_devices"]
    # crushtool
    tot = bad = 0
    files = sorted(glob.glob(captures_path(ctx, "gt", "crushtool-tests", "rule*.txt")))
    for f in files:
        if "stats" in f:
            continue
        g = re.match(r".*rule(\d)\.rep(\d)\.x0-9999(\.pool(\d))?\.txt", f)
        rule, rep, pool = int(g.group(1)), int(g.group(2)), g.group(4)
        nb = 0
        for line in open(f):
            h = re.match(r"CRUSH rule (\d+) x (\d+) \[(.*)\]", line)
            if not h:
                continue
            x = int(h.group(2))
            exp = [int(v) for v in h.group(3).split(",") if v != ""]
            got = crush_do_rule(cm, rule, hash2(x, int(pool)) if pool else x, rep, weight16)
            tot += 1
            if got != exp:
                nb += 1
        bad += nb
        R.check(nb == 0, "crushtool %s: 10000 mappings" % os.path.basename(f), "%d mismatches" % nb)
    ITEMS["crushtool mappings"] += tot
    R.info("crushtool mappings: %d compared, %d mismatches (match rate %.4f%%)" % (tot, bad, 100.0 * (tot - bad) / max(tot, 1)))
    claim("crush firstn (lab)", bad == 0 and tot >= 80000, "crush note 3.3-3.6 reproduces %d crushtool mappings (rules 0,1; 1-3 replicas; x 0..9999; pool-id hash)" % tot)
    # ceph osd map
    tot = bad = 0
    kinds = collections.Counter()
    cesu = 0
    bad_list = []
    for line in open(captures_path(ctx, "gt", "osd-map-all.jsonl")):
        j = json.loads(line)
        if j["rc"] != 0:
            continue
        res = j["result"]
        pid = res["pool_id"]
        pool = m["pools"][pid]
        ns = (j["nspace"] or "")
        obj = j["object"]
        name_b = cesu8(obj)
        if name_b != obj.encode("utf-8"):
            cesu += 1
        ps = object_ps(pool, name_b, ns.encode())
        pl = pg_placement(m, cm, pid, ps)
        ok = (ps == int(res["raw_pgid"].split(".")[1], 16) and pg_str(pl["pg"]) == res["pgid"] and
              pl["up"] == res["up"] and pl["up_primary"] == res["up_primary"] and
              pl["acting"] == res["acting"] and pl["acting_primary"] == res["acting_primary"])
        tot += 1
        kinds[("ns" if ns else "plain", pool["pg_num"])] += 1
        if not ok:
            bad += 1
            bad_list.append(obj)
    ITEMS["ceph osd map names"] += tot
    R.check(bad == 0, "`ceph osd map`: %d object names (2 pools, plain and namespaced) give the same raw pg, pg, up, acting and both primaries" % tot,
            "%d mismatches: %s" % (bad, bad_list[:3]))
    R.info("osd map match rate %d/%d; non-BMP names (%d) only match when hashed as two 3-byte surrogates, an artefact of how the oracle's JSON command parser handled them" % (tot - bad, tot, cesu))
    claim("3.7 object->pg (lab)", bad == 0 and tot > 2000, "object name -> ps -> pg -> up/acting: %d `ceph osd map` answers reproduced, incl. 0x1f namespace rule (80 namespaced names)" % tot)
    # osdmaptool at epoch 42
    tot = bad = 0
    for P in (1, 2):
        pgs = parse_pg_dump(captures_path(ctx, "gt", "osdmaptool-test-map-pgs-dump-all.pool%d.txt" % P))
        for (pool, seed), (raw, rawp, up, upp, act, actp) in pgs.items():
            pl = pg_placement(m, cm, pool, seed)
            tot += 1
            if (pl["up"], pl["up_primary"], pl["acting"], pl["acting_primary"], pl["raw"]) != (up, upp, act, actp, raw):
                bad += 1
    R.check(bad == 0 and tot == 33, "osdmaptool --test-map-pgs-dump-all, epoch 42: all %d PGs of both pools (raw, up, acting, primaries)" % tot, "%d mismatches" % bad)
    # --test-map-object
    txt = open(captures_path(ctx, "gt", "osdmaptool-test-map-object.txt")).read()
    nobj = badobj = 0
    for g in re.finditer(r"--test-map-object (\S+) --pool (\d+)\n.*?\n object '.*?' -> (\d+)\.([0-9a-f]+) -> \[([\d,]*)\]", txt):
        name, pid = g.group(1), int(g.group(2))
        pool = m["pools"][pid]
        ps = object_ps(pool, name.encode())
        pl = pg_placement(m, cm, pid, ps)
        nobj += 1
        if "%x" % pl["pg"][1] != g.group(4) or pl["acting"] != [int(x) for x in g.group(5).split(",") if x]:
            badobj += 1
    R.check(badobj == 0 and nobj >= 5, "osdmaptool --test-map-object: %d objects" % nobj, "%d mismatches" % badobj)
    # gt2 states
    if "steps" in ctx and have(ctx, "gt5", "out"):
        tot = bad = 0
        base = parse_pg_dump(captures_path(ctx, "gt5", "out", "osdmap.s01.baseline.e42.pool2.txt"))
        base.update(parse_pg_dump(captures_path(ctx, "gt5", "out", "osdmap.s01.baseline.e42.pool1.txt")))
        changed = collections.Counter()
        paff_changed = 0
        per_state = []
        for name, (sm, b) in sorted(ctx["steps"].items()):
            scm = dec_crush(sm["crush"])
            stem = name[:-4]
            nb = 0
            n = 0
            for P in (1, 2):
                pgs = parse_pg_dump(captures_path(ctx, "gt5", "out", "%s.pool%d.txt" % (stem, P)))
                for (pool, seed), (raw, rawp, up, upp, act, actp) in pgs.items():
                    pl = pg_placement(sm, scm, pool, seed)
                    n += 1
                    if (pl["up"], pl["up_primary"], pl["acting"], pl["acting_primary"], pl["raw"]) != (up, upp, act, actp, raw):
                        nb += 1
                    if (up, upp, act, actp) != base[(pool, seed)][2:6]:
                        changed[stem.split(".")[1]] += 1   # key = step id "sNN"
                    if pl["up_primary"] != pl["up_primary_pre_affinity"]:
                        paff_changed += 1
            tot += n
            bad += nb
            per_state.append((stem, n, nb))
        ITEMS["osdmaptool pgs over 24 states"] += tot
        R.check(bad == 0, "osdmaptool oracle over the 24 gt2 states (reweight, affinity, upmap-items, upmap, primary-temp, pg-temp, out/in, noup+down): %d PG results" % tot,
                "%d mismatches %s" % (bad, [s for s in per_state if s[2]][:3]))
        R.info("non-vacuity: PG results that differ from the epoch-42 baseline per state: %s; PGs whose primary was changed by primary affinity: %d" %
               (dict(changed), paff_changed))
        R.check(paff_changed > 0, "primary affinity actually changed a primary in at least one oracle PG (%d cases)" % paff_changed)
        for cid, key, text in (("upmap_items", "s10", "pg_upmap_items (step 10)"), ("upmap", "s12", "pg_upmap (step 12)"),
                               ("primary_temp", "s14", "primary_temp (step 14)"), ("pg_temp", "s16", "pg_temp (step 16)"),
                               ("out", "s18", "osd out (step 18)"), ("down", "s21", "noup + osd down (step 21)"),
                               ("reweight", "s04", "reweight 0.5 (step 04)")):
            claim("3.7 " + cid, bad == 0 and changed.get(key, 0) > 0,
                  "%s: oracle results differ from the epoch-42 baseline in %d PGs and my pipeline reproduces all of them" % (text, changed.get(key, 0)))
        claim("3.7 affinity", bad == 0 and paff_changed > 0, "primary affinity (osd.1 = 0.5) changed %d primaries and all oracle answers are reproduced" % paff_changed)
    else:
        SKIPPED.append("E gt2 states (gt5 oracle output missing)")


# --------------------------------------------------------------------------
# section: what the monitor puts on the wire (pcaps)
# --------------------------------------------------------------------------

FEATURE_ALL_V20 = 0x3F07FFFFFFFDFFFF


def note_feature_masks(note_path):
    """rows of the table in 2.7.4: NAME | bit | mask"""
    out = []
    if not os.path.exists(note_path):
        return out
    for line in open(note_path):
        g = re.match(r"^\| ([A-Z_0-9]+)[^|]*\| (\d+) \| 0x([0-9a-fA-F]+) \|", line)
        if g:
            out.append((g.group(1), int(g.group(2)), int(g.group(3), 16)))
    return out


def dec_ident(seg0, server):
    r = Reader(seg0)
    d = {"addrs": dec_addrvec(r)}
    if not server:
        d["target"] = dec_addr(r)
    d["gid"] = r.s64()
    d["global_seq"] = r.u64()
    d["supported"] = r.u64()
    d["required"] = r.u64()
    d["flags"] = r.u64()
    d["cookie"] = r.u64()
    return d


def sec_pcap(ctx):
    R.section("F. msgr2 frames and MOSDMap messages in the 39 pcaps")
    if not have(ctx, "pcap"):
        SKIPPED.append("F (pcap missing)")
        return
    pcs = sorted(glob.glob(captures_path(ctx, "pcap", "*.pcap")))
    maxmb = ctx.get("max_pcap_mb")
    conns_total = fail = unread = empty = secure_conns = retrans = 0
    mos = []            # (pcap, version, compat, decoded dict, header)
    subs = []           # (pcap, items)
    cidents = []
    sidents = []
    trunc = []
    gaps = []
    per_pcap_fail = []
    for p in pcs:
        name = os.path.basename(p)[:-5]
        if maxmb and os.path.getsize(p) > maxmb * 1024 * 1024:
            SKIPPED.append("F %s (larger than --max-pcap-mb)" % name)
            continue
        try:
            conns = pcap_connections(p)
        except DecodeError as e:
            R.bad("pcap %s reassembly" % name, str(e))
            continue
        for key, c in sorted(conns.items(), key=lambda kv: kv[1]["ts"]):
            conns_total += 1
            retrans += c["retrans"]
            if c["holes"]:
                gaps.append((name, key, c["holes"]))
            if not c["s2c"]:
                empty += 1
                continue
            try:
                fs, mode, note = parse_frames(c["s2c"], "s2c")
                stop = None
                if mode == "secure":
                    stop = 2 + sum(1 for f in fs if f["tag"] == 4)
                    secure_conns += 1
                fc, _, note2 = parse_frames(c["c2s"], "c2s", stop)
            except DecodeError as e:
                fail += 1
                per_pcap_fail.append("%s %s: %s" % (name, key, e))
                continue
            if note.startswith("truncated") or note2.startswith("truncated"):
                trunc.append((name, key, note or note2))
            if mode == "secure":
                unread += 1
            for f in fs:
                if f["tag"] == 9:
                    sidents.append(dec_ident(f["segs"][0], True))
            for f in fc:
                if f["tag"] == 8:
                    cidents.append(dec_ident(f["segs"][0], False))
            for h in messages_of(fs):
                if h["type"] == 41:
                    mos.append((name, key, h, dec_mosdmap(h["front"], h["version"])))
            for h in messages_of(fc):
                if h["type"] == 15:
                    r = Reader(h["front"])
                    n = r.u32()
                    items = [(r.string(), r.u64(), r.u8()) for _ in range(n)]
                    host = r.string()
                    subs.append((name, key, h, items, r.left()))
    R.check(fail == 0, "all %d TCP connections in %d pcaps parse as msgr2.1 frame streams with valid preamble CRC, segment CRCs and late_status 0x0E" %
            (conns_total - empty, len(pcs)), "; ".join(per_pcap_fail[:3]))
    R.info("frame statistics: %s" % dict(FRAME_STATS))
    if gaps:
        R.info("capture gaps (missing TCP segments in the pcap itself, stream used up to the gap): %s" %
               ["%s %s:%d" % (g[0], g[1][1], g[1][2]) for g in gaps])
    R.info("connections: %d total, %d without server bytes, %d secure-mode (frames after AUTH_DONE not readable here), %d TCP retransmissions reassembled, %d cut by the capture end" %
           (conns_total, empty, secure_conns, retrans, len(trunc)))
    ITEMS["msgr2 frames"] += FRAME_STATS["frames"]
    # idents
    R.check(len(cidents) > 100 and all(c["supported"] == FEATURE_ALL_V20 for c in cidents),
            "CLIENT_IDENT: the stock client advertises 0x3f07fffffffdffff in all %d connections (Q1 recommendation)" % len(cidents),
            str({hex(c["supported"]) for c in cidents}))
    ssup = collections.Counter(s["supported"] for s in sidents)
    R.info("SERVER_IDENT supported masks: %s" % {hex(k): v for k, v in ssup.items()})
    masks = note_feature_masks(ctx["note"])
    if masks:
        bad = []
        for name, bit, mask in masks:
            if not (mask >> bit) & 1:
                bad.append("%s mask lacks its own bit" % name)
            if name == "RESERVED":
                if any(c["supported"] & mask for c in cidents) or any(s["supported"] & mask for s in sidents):
                    bad.append("RESERVED bit set")
                continue
            if any((c["supported"] & mask) != mask for c in cidents):
                bad.append("%s not fully in client mask" % name)
            if any((s["supported"] & mask) != mask for s in sidents):
                bad.append("%s not fully in server mask" % name)
        R.check(not bad and len(masks) >= 15, "the %d feature masks tabulated in 2.7.4 are all present in the client's and in every server's advertised set; RESERVED bit 62 is not" % len(masks), str(bad))
        claim("2.7.4 masks", not bad and len(masks) >= 15, "all %d masks of the 2.7.4 table are set in the stock client's and in the mon/OSD/mgr `supported` masks; bit 62 clear" % len(masks))
    claim("Q1 full mask", len(cidents) > 100 and all(c["supported"] == FEATURE_ALL_V20 for c in cidents) and
          all(m[2]["version"] == 4 and m[2]["compat"] == 3 for m in mos),
          "stock client advertises 0x3f07fffffffdffff; with it the monitor sends MOSDMap v4/compat 3, full map block v10, pool v32. Reduced masks were NOT tried (needs our own client)")
    # MOSDMap
    R.check(len(mos) > 40, "MOSDMap messages found in crc-mode connections: %d" % len(mos))
    stored = ctx.get("fb", {})
    ok_hdr = all(m[2]["version"] == 4 and m[2]["compat"] == 3 and not m[2]["middle"] and not m[2]["data"] and
                 m[2]["flags"] == 3 and m[2]["data_off"] == 0 and m[2]["pre_pad"] == 0 for m in mos)
    R.check(ok_hdr, "every MOSDMap: type 41, header version 4 / compat 3, front only (no middle, no data), header flags 3 (COMPLETE|NOCRC), data_off 0",
            str(collections.Counter((m[2]["version"], m[2]["compat"], len(m[2]["middle"]), len(m[2]["data"]), m[2]["flags"],
                                     m[2]["data_off"], m[2]["pre_pad"]) for m in mos)))
    R.check(all(m[3]["_trailing"] == 0 and m[3]["gap_count"] == 0 for m in mos),
            "MOSDMap payload = fsid, incrementals, maps, trim lower bound, newest, u32 0 gap count with nothing left over (%d messages)" % len(mos))
    kinds = collections.Counter((tuple(m[3]["incremental_maps"]), tuple(m[3]["maps"]), m[3]["oldest_map"], m[3]["newest_map"]) for m in mos)
    R.info("MOSDMap shapes (incremental epochs, full epochs, trim lower bound, newest): %s" % dict(kinds))
    R.check(all(len(m[3]["maps"]) == 1 and not m[3]["incremental_maps"] and list(m[3]["maps"])[0] == m[3]["newest_map"] and
                m[3]["oldest_map"] == 1 for m in mos),
            "a subscription with start 0 is answered by exactly one message with one full map of the newest epoch; trim lower bound = 1")
    claim("3.1 start 0", all(len(m[3]["maps"]) == 1 and not m[3]["incremental_maps"] for m in mos) and len(mos) > 40,
          "start 0 -> one MOSDMap with one full map of the newest epoch (%d messages). Re-subscribing with start 0 after already receiving maps was not exercised" % len(mos))
    # content checks
    nbytes_eq = nbytes = 0
    bad = []
    for name, key, h, d in mos:
        for e, blob in d["maps"].items():
            mm = dec_osdmap(blob)
            if fsid_str(mm["fsid"]) != fsid_str(d["fsid"]) or mm["epoch"] != e or not mm["crc_ok"]:
                bad.append((name, e))
            if e in stored:
                nbytes += 1
                if stored[e] == blob:
                    nbytes_eq += 1
            elif "b92" in ctx and e == ctx["m92"]["epoch"]:
                nbytes += 1
                if blob == ctx["b92"]:
                    nbytes_eq += 1
    R.check(not bad, "embedded map: fsid equals the message fsid, epoch equals the map key, crc ok in every message", str(bad[:3]))
    R.check(nbytes > 0 and nbytes == nbytes_eq,
            "the full map on the wire is byte-identical to the monitor's stored map / `osd getmap` output (%d/%d)" % (nbytes_eq, nbytes))
    claim("2.8 canonical bytes", nbytes > 0 and nbytes == nbytes_eq,
          "with the full feature mask the monitor sends the stored canonical bytes unchanged (%d wire maps byte-identical to stored/getmap)" % nbytes_eq)
    # subscriptions
    names = collections.Counter()
    for name, key, h, items, left in subs:
        for it in items:
            names[(it[0], it[2])] += 1
    R.check(all(s[2]["version"] == 3 and s[2]["compat"] == 1 and s[4] == 0 and all(len(i) == 3 for i in s[3]) for s in subs),
            "MMonSubscribe: header version 3 / compat 1; body = map<string,(start u64, flags u8)> + hostname string, nothing left (%d messages)" % len(subs))
    osd_subs = [i for s in subs for i in s[3] if i[0] == "osdmap"]
    R.check(all(i[2] == 1 for i in osd_subs) and any(i[1] == 0 for i in osd_subs) and any(i[1] > 0 for i in osd_subs),
            "the stock client subscribes to 'osdmap' with ONETIME (flag 1): start 0 first, later start = epoch + 1 (starts seen: %s)" %
            sorted({i[1] for i in osd_subs}))
    # start = epoch+1 on a connection that already received that epoch: is anything else sent?
    per_conn_mos = collections.Counter((m[0], m[1]) for m in mos)
    resub = [(s[0], s[1]) for s in subs if any(i[0] == "osdmap" and i[1] > 0 for i in s[3])]
    both = [k for k in resub if any(s[0] == k[0] and s[1] == k[1] and any(i[0] == "osdmap" and i[1] == 0 for i in s[3]) for s in subs)]
    quiet = [k for k in both if per_conn_mos[k] == 1]
    R.check(len(both) > 0 and len(both) == len(quiet),
            "on connections that subscribed with start 0 and later with start = epoch+1, no second MOSDMap followed (%d/%d connections)" % (len(quiet), len(both)))
    claim("3.1 start N+1", len(both) > 0 and len(both) == len(quiet),
          "subscribing with start = newest+1 draws no further MOSDMap (%d connections)" % len(both))
    ctx["wire_mos"] = mos
    return mos


# --------------------------------------------------------------------------
# negative / robustness section
# --------------------------------------------------------------------------


def sec_negative(ctx):
    R.section("G. envelope skipping, rejection and robustness (vectors T7, T9)")
    if "fb" in ctx:
        full, inc = ctx["fb"][42], ctx["ib"][43]
    elif ctx.get("vec_full") is not None:
        full, inc = ctx["vec_full"], ctx["vec_inc43"]
    else:
        SKIPPED.append("G (no map bytes)")
        return
    res = robustness_tests(full, inc)
    for name, ok, detail in res:
        R.check(ok, name, detail)
    if "fb" in ctx:
        claim("Q13 nested lengths", R.failed == 0, "decoding with the strict rule (inner end must lie inside the outer end) never rejected any of the 178 stored blobs, the 24 gt2 maps or the wire maps")
    claim("T7 skipping", all(ok for n, ok, d in res if n.startswith("T7")),
          "a client block with raised struct_v and extra tail, and a pool with struct_v 33 and extra tail, decode; raised compat is rejected (synthetic mutation of a real map)")


# --------------------------------------------------------------------------
# vectors: write (from the capture set) and verify (stand-alone)
# --------------------------------------------------------------------------

VEC_FILES = ["full-e42.hex", "incrementals.hex", "crush-embedded.hex", "crush-incremental-form.hex",
             "mosdmap-front-e42.hex", "expected.json", "placement-names-e42.json", "placement-states.json",
             "crush-mappings.json"]


def _scrub_maker(ctx):
    j = json.load(open(captures_path(ctx, "gt", "dencoder-OSDMap.json")))
    lab_fsid = bytes.fromhex(j["fsid"].replace("-", ""))
    repl = [(lab_fsid, PLACEHOLDER_FSID)]
    for o in j["osds"]:
        u = bytes.fromhex(o["uuid"].replace("-", ""))
        repl.append((u, bytes([0xA0 + o["osd"]]) * 16))
    return repl, lab_fsid


def scrub_full(buf, repl):
    return refresh_full_crc(scrub_ids(buf, repl))


def write_vectors(ctx, outdir):
    os.makedirs(outdir, exist_ok=True)
    repl, lab_fsid = _scrub_maker(ctx)
    fb, ib = ctx["fb"], ctx["ib"]
    sfull = {e: scrub_full(fb[e], repl) for e in fb}
    smaps = {e: dec_osdmap(sfull[e]) for e in sfull}
    sinc = {}
    for e in ib:
        b = ib[e]
        inc = ctx["incs"][e]
        if inc["fullmap"]:
            emb = inc["fullmap"]
            b = b.replace(emb, scrub_full(emb, repl))
        b = scrub_ids(b, repl)
        sinc[e] = refresh_inc_crc(b, smaps[e]["crc"])
    # self-check of the scrub
    for e in sfull:
        assert lab_fsid not in sfull[e] and lab_fsid not in sinc[e], "fsid survived scrub"
        assert smaps[e]["crc_ok"]
        di = dec_incremental(sinc[e])
        assert di["inc_crc_ok"] and di["fsid"] == PLACEHOLDER_FSID and di["full_crc"] == smaps[e]["crc"]
    for u, _ in repl[1:]:
        assert all(u not in sfull[e] and u not in sinc[e] for e in sfull)

    def wr(name, text):
        with open(os.path.join(outdir, name), "w") as f:
            f.write(text)
    hdr = ("# Scrubbed vector derived from a real capture (see README.md). Hex, whitespace ignored.\n")
    wr("full-e42.hex", hdr + "# OSDMap at epoch 42, wrapper v8 / client block v10 / OSD block v9, pool v32. fsid and OSD uuids replaced, crc recomputed.\n" +
       wrap_hex(sfull[42]) + "\n")
    lines = [hdr + "# One OSDMap::Incremental per line: `<epoch> <hex>`; epochs 1..89, consecutive. Epoch 1 carries an embedded full map.\n"]
    for e in range(1, 90):
        lines.append("%d %s\n" % (e, sinc[e].hex()))
    wr("incrementals.hex", "".join(lines))
    ecm = smaps[42]["crush"]
    icm = ctx["incs"][40]["crush"]
    wr("crush-embedded.hex", hdr + "# CRUSH blob embedded in the epoch-42 OSDMap (no MSR tunable pair).\n" + wrap_hex(ecm) + "\n")
    wr("crush-incremental-form.hex", hdr + "# CRUSH blob as carried in the `crush` field of an incremental (epoch 40), same map plus the 8-byte MSR pair.\n" + wrap_hex(icm) + "\n")
    front = PLACEHOLDER_FSID + struct.pack("<I", 0) + struct.pack("<II", 1, 42) + struct.pack("<I", len(sfull[42])) + sfull[42] + \
        struct.pack("<II", 1, 42) + struct.pack("<I", 0)
    wr("mosdmap-front-e42.hex", hdr + "# MOSDMap payload (header version 4): fsid, 0 incrementals, 1 full map (epoch 42), trim lower bound 1, newest 42, gap count 0.\n" + wrap_hex(front) + "\n")
    # expected
    exp = {"scrub": {"fsid": PLACEHOLDER_FSID.hex(), "osd_uuids": {str(i): (bytes([0xA0 + i]) * 16).hex() for i in range(3)},
                     "crc": "recomputed over the scrubbed bytes with the rule of osdmap.md 2.4.5; full_crc of each incremental = crc of the scrubbed full map of that epoch"},
           "full_e42": {"wrapper": [8, 7], "client_block": [10, 1], "osd_block": [9, 1], "pool_struct_v": 32, "pool_struct_compat": 5,
                        "crc": smaps[42]["crc"], "state": state_summary(smaps[42]), "bytes": len(sfull[42])}}
    exp["incrementals"] = {}
    for e in range(1, 90):
        di = dec_incremental(sinc[e])
        keys = [k for k in ("fullmap", "crush", "new_pools", "new_pool_names", "old_pools", "new_up_client", "new_state",
                            "new_weight", "new_pg_temp", "new_primary_temp", "new_primary_affinity", "new_pg_upmap",
                            "old_pg_upmap", "new_pg_upmap_items", "old_pg_upmap_items", "new_removed_snaps") if di[k]]
        if di["new_flags"] >= 0:
            keys.append("new_flags")
        if di["new_max_osd"] >= 0:
            keys.append("new_max_osd")
        if di["new_pool_max"] != -1:
            keys.append("new_pool_max")
        exp["incrementals"][str(e)] = {"bytes": len(sinc[e]), "inc_crc": di["inc_crc"], "full_crc": di["full_crc"], "fields": sorted(keys)}
    exp["chain"] = {str(e): state_summary(smaps[e]) for e in range(1, 90)}
    ecmd = dec_crush(ecm)
    exp["crush"] = {"embedded_tails": sorted(ecmd["tail_present"]), "incremental_form_tails": sorted(dec_crush(icm)["tail_present"]),
                    "digest": crush_digest(ecmd), "tunables": ecmd["tunables"], "max_devices": ecmd["max_devices"],
                    "buckets": {str(b["id"]): [b["type"], b["alg"], b["items"], b["weights"]] for b in ecmd["buckets"] if b},
                    "rules": {str(r["id"]): [r["type"], r["steps"]] for r in ecmd["rules"] if r},
                    "names": {str(k): v for k, v in ecmd["name_map"].items()}}
    wr("expected.json", json.dumps(exp, sort_keys=True, separators=(",", ":")) + "\n")
    # placement by name, epoch 42 (oracle: `ceph osd map`)
    names = []
    seq = collections.Counter()
    for line in open(captures_path(ctx, "gt", "osd-map-all.jsonl")):
        j = json.loads(line)
        res = j["result"]
        key = (res["pool_id"], bool(j["nspace"]))
        seq[key] += 1
        step = {(2, False): 12, (1, False): 10, (2, True): 2}[key]
        if seq[key] % step:
            continue
        names.append([res["pool_id"], cesu8(j["object"]).hex(), (j["nspace"] or "").encode().hex(),
                      int(res["raw_pgid"].split(".")[1], 16), res["pgid"], res["up"], res["up_primary"], res["acting"], res["acting_primary"]])
    wr("placement-names-e42.json", json.dumps({"comment": "[pool_id, object_bytes_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary]; oracle = `ceph osd map` on the lab cluster at epoch 42 (names with non-BMP characters are given as the surrogate-pair bytes the oracle hashed)",
                                                "entries": names}, separators=(",", ":")) + "\n")
    # placement by state (oracle: osdmaptool over the saved map of that epoch)
    states = {}
    for name in sorted(ctx["steps"]):
        stem = name[:-4]
        ent = {}
        for P in (1, 2):
            pgs = parse_pg_dump(captures_path(ctx, "gt5", "out", "%s.pool%d.txt" % (stem, P)))
            for (pool, seed), (raw, rawp, up, upp, act, actp) in sorted(pgs.items()):
                ent["%d.%x" % (pool, seed)] = [raw, up, upp, act, actp]
        states[stem] = {"epoch": ctx["steps"][name][0]["epoch"], "pgs": ent}
    wr("placement-states.json", json.dumps({"comment": "per saved state: epoch and, for every PG, [raw, up, up_primary, acting, acting_primary] as printed by `osdmaptool --test-map-pgs-dump-all` over the map saved at that epoch; the state itself is rebuilt by applying incrementals.hex",
                                            "states": states}, separators=(",", ":")) + "\n")
    # crush mappings
    cmj = {}
    for fn, rule, rep, pool in (("rule1.rep3.x0-9999.pool2.txt", 1, 3, 2), ("rule0.rep2.x0-9999.pool1.txt", 0, 2, 1),
                                ("rule1.rep3.x0-9999.txt", 1, 3, None), ("rule0.rep1.x0-9999.txt", 0, 1, None)):
        ent = []
        for line in open(captures_path(ctx, "gt", "crushtool-tests", fn)):
            g = re.match(r"CRUSH rule (\d+) x (\d+) \[(.*)\]", line)
            if g and int(g.group(2)) < 300:
                ent.append([int(g.group(2)), [int(v) for v in g.group(3).split(",") if v]])
        cmj[fn[:-4]] = {"rule": rule, "num_rep": rep, "pool_id_hash": pool, "mappings": ent}
    wr("crush-mappings.json", json.dumps({"comment": "crushtool --test --show-mappings over the epoch-42 crush map, all devices weight 1.0; when pool_id_hash is set the CRUSH input is hash2(x, pool_id) (crushtool --pool-id)",
                                          "sets": cmj}, separators=(",", ":")) + "\n")
    return outdir


def load_hex_single(path):
    lines = [l for l in parse_hex_file(path)]
    return hexline_to_bytes("".join(lines))


def verify_vectors(ctx, vdir):
    R.section("H. committed vectors (%s)" % vdir)
    missing = [f for f in VEC_FILES if not os.path.exists(os.path.join(vdir, f))]
    if missing:
        R.bad("vector files missing", str(missing))
        return
    full = load_hex_single(os.path.join(vdir, "full-e42.hex"))
    exp = json.load(open(os.path.join(vdir, "expected.json")))
    m = dec_osdmap(full)
    R.check(m["crc_ok"] and m["fsid"] == PLACEHOLDER_FSID and m["epoch"] == 42, "full-e42.hex decodes, crc ok, placeholder fsid")
    R.check((m["wrapper_v"], m["wrapper_compat"], m["client_v"], m["client_compat"], m["osd_block_v"], m["osd_block_compat"]) == (8, 7, 10, 1, 9, 1) and
            all(p["struct_v"] == 32 and p["struct_compat"] == 5 for p in m["pools"].values()) and len(full) == exp["full_e42"]["bytes"],
            "full-e42.hex has the versions the note's 2.4.2 table gives for tentacle")
    R.check(state_summary(m) == exp["full_e42"]["state"] and m["crc"] == exp["full_e42"]["crc"], "full-e42.hex state equals expected.json")
    ctx["vec_full"] = full
    # incrementals
    incb = {}
    for line in parse_hex_file(os.path.join(vdir, "incrementals.hex")):
        e, h = line.split(None, 1)
        incb[int(e)] = hexline_to_bytes(h)
    R.check(sorted(incb) == list(range(1, 90)), "incrementals.hex holds epochs 1..89")
    ctx["vec_inc43"] = incb[43]
    st = None
    errs = []
    for e in range(1, 90):
        inc = dec_incremental(incb[e])
        ei = exp["incrementals"][str(e)]
        if not inc["inc_crc_ok"] or inc["inc_crc"] != ei["inc_crc"] or inc["full_crc"] != ei["full_crc"] or len(incb[e]) != ei["bytes"]:
            errs.append("e%d crc/size" % e)
        if st is None:
            st = dec_osdmap(inc["fullmap"])
        else:
            st = apply_incremental_checked(st, inc)
        if state_summary(st) != exp["chain"][str(e)]:
            errs.append("e%d state" % e)
        if e == 42 and state_summary(st) != exp["full_e42"]["state"]:
            errs.append("e42 vs full")
        ctx.setdefault("vec_states", {})[e] = copy.deepcopy(st)
    R.check(not errs, "applying the 89 vector incrementals reproduces the expected state at every epoch and the stored crc values", "; ".join(errs[:4]))
    # front
    front = load_hex_single(os.path.join(vdir, "mosdmap-front-e42.hex"))
    d = dec_mosdmap(front, 4)
    R.check(d["fsid"] == PLACEHOLDER_FSID and list(d["maps"]) == [42] and d["maps"][42] == full and d["oldest_map"] == 1 and
            d["newest_map"] == 42 and d["gap_count"] == 0 and d["_trailing"] == 0, "mosdmap-front-e42.hex decodes (v4 layout) and embeds full-e42.hex")
    # crush
    e1 = dec_crush(load_hex_single(os.path.join(vdir, "crush-embedded.hex")))
    e2 = dec_crush(load_hex_single(os.path.join(vdir, "crush-incremental-form.hex")))
    R.check(sorted(e1["tail_present"]) == exp["crush"]["embedded_tails"] and sorted(e2["tail_present"]) == exp["crush"]["incremental_form_tails"] and
            crush_struct(e1) == crush_struct(e2) and crush_digest(e1) == exp["crush"]["digest"] and e1["max_devices"] == exp["crush"]["max_devices"],
            "both CRUSH blob forms decode; differ only by the MSR pair; digest equals expected")
    R.check(e1["tunables"] == exp["crush"]["tunables"] and e1["name_map"] == {int(k): v for k, v in exp["crush"]["names"].items()},
            "CRUSH tunables and names equal expected")
    # robustness on the vector bytes
    for name, ok, detail in robustness_tests(full, incb[43]):
        R.check(ok, "vector " + name, detail)
    # placement
    if not ctx["ref"]:
        SKIPPED.append("H placement vectors (no --ref tree for the crush_ln tables)")
        return
    cm = dec_crush(m["crush"])
    pn = json.load(open(os.path.join(vdir, "placement-names-e42.json")))["entries"]
    nb = 0
    for pool, nhex, nshex, rawps, pgid, up, upp, act, actp in pn:
        p = m["pools"][pool]
        ps = object_ps(p, bytes.fromhex(nhex), bytes.fromhex(nshex))
        pl = pg_placement(m, cm, pool, ps)
        if (ps, pg_str(pl["pg"]), pl["up"], pl["up_primary"], pl["acting"], pl["acting_primary"]) != (rawps, pgid, up, upp, act, actp):
            nb += 1
    R.check(nb == 0, "placement-names-e42.json: %d object names reproduce the oracle" % len(pn), "%d mismatches" % nb)
    ps_ = json.load(open(os.path.join(vdir, "placement-states.json")))["states"]
    nb = n = 0
    for stem, s in ps_.items():
        sm = ctx["vec_states"][s["epoch"]]
        scm = dec_crush(sm["crush"])
        for pgs, (raw, up, upp, act, actp) in s["pgs"].items():
            pool, seed = pgs.split(".")
            pl = pg_placement(sm, scm, int(pool), int(seed, 16))
            n += 1
            if (pl["raw"], pl["up"], pl["up_primary"], pl["acting"], pl["acting_primary"]) != (raw, up, upp, act, actp):
                nb += 1
    R.check(nb == 0, "placement-states.json: %d PG results over %d states (state rebuilt from incrementals.hex)" % (n, len(ps_)), "%d mismatches" % nb)
    cmj = json.load(open(os.path.join(vdir, "crush-mappings.json")))["sets"]
    nb = n = 0
    w = [0x10000] * cm["max_devices"]
    for k, s in cmj.items():
        for x, res in s["mappings"]:
            xx = hash2(x, s["pool_id_hash"]) if s["pool_id_hash"] is not None else x
            n += 1
            if crush_do_rule(cm, s["rule"], xx, s["num_rep"], w) != res:
                nb += 1
    R.check(nb == 0, "crush-mappings.json: %d mappings reproduce crushtool" % n, "%d mismatches" % nb)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def find_default_paths(args):
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.normpath(os.path.join(here, "..", ".."))
    if args.vectors is None:
        args.vectors = os.path.join(repo, "harness", "vectors", "osdmap")
    if args.ref is None:
        cand = os.path.normpath(os.path.join(repo, "..", "winrbd-ref", "ceph-v20.2.5"))
        if os.path.isdir(cand):
            args.ref = cand
    note = os.path.join(repo, "docs", "spec", "osdmap.md")
    return note


def main(argv=None):
    global R
    ap = argparse.ArgumentParser(description="independent checker for docs/spec/osdmap.md")
    ap.add_argument("--captures", help="capture directory (winrbd-ref/captures); without it only the committed vectors are checked")
    ap.add_argument("--ref", help="Ceph reference tree, only to read crush_ln_table.h at run time (default: ../winrbd-ref/ceph-v20.2.5)")
    ap.add_argument("--vectors", help="vector directory (default harness/vectors/osdmap)")
    ap.add_argument("--write-vectors", action="store_true", help="regenerate the scrubbed vectors from the captures into --vectors")
    ap.add_argument("--max-pcap-mb", type=int, default=0, help="skip pcaps larger than this (speed); 0 = all")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)
    R = Results(args.verbose)
    note = find_default_paths(args)
    ctx = {"cap": args.captures, "ref": args.ref, "note": note, "max_pcap_mb": args.max_pcap_mb}
    if args.captures and not os.path.isdir(args.captures):
        print("no such capture directory: %s" % args.captures)
        return 2
    if args.ref:
        try:
            load_ln_tables(args.ref)
        except (OSError, DecodeError) as e:
            print("cannot load crush_ln tables from %s: %s" % (args.ref, e))
            ctx["ref"] = None
    sec_selftest(ctx)
    if args.captures:
        sec_stored(ctx)
        sec_gt_maps(ctx)
        sec_crush(ctx)
        sec_placement(ctx)
        sec_pcap(ctx)
        if args.write_vectors:
            if "fb" not in ctx or "steps" not in ctx:
                print("cannot write vectors without gt3/gt2/gt5")
                return 2
            write_vectors(ctx, args.vectors)
            print("== vectors written to %s" % args.vectors)
    if os.path.isdir(args.vectors):
        verify_vectors(ctx, args.vectors)
    else:
        SKIPPED.append("H (no vector directory %s)" % args.vectors)
    sec_negative(ctx)
    print()
    print("== claims about docs/spec/osdmap.md settled by this run")
    for cid, (ok, text) in CLAIMS.items():
        print("  %-8s %-24s %s" % ({True: "CONFIRMED", False: "FAILED", None: "OPEN"}[ok], cid, text))
    print()
    print("== summary")
    for name, (p, f) in R.sections.items():
        print("  %-110s pass %-3d fail %d" % (name[:110], p, f))
    if SKIPPED:
        print("  skipped: %s" % "; ".join(SKIPPED))
    print("  item-level comparisons: %s" % dict(ITEMS))
    print("  checks: %d passed, %d failed" % (R.passed, R.failed))
    for f in R.failures:
        print("  FAILED: %s" % f)
    return 0 if R.failed == 0 and not any(v[0] is False for v in CLAIMS.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
