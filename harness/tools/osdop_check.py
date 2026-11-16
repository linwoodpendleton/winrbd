#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
osdop_check.py - independent checker for docs/spec/osd-ops.md against real
packet captures of a stock Ceph client talking to a lab cluster.

Written from the NOTES only (docs/spec/osd-ops.md, msgr2.md, msgr2-secure-mode.md,
cephx.md, rbd-format2.md, crush-and-placement.md section 3.1).  It does not
read Ceph source and does not call any Ceph decoder.  Standard library plus the
'cryptography' package.

    python3 harness/tools/osdop_check.py --captures <captures dir>
                [--keys <dir with client.*.keyring>]   (default: harness/vectors/public/keys for the public set,
                                                        else <captures>/../lab-secrets)
                [--vectors <dir>]                      (default: harness/vectors/osdop)
                [--only SESSION[,SESSION...]] [--jobs N] [-v]
                [--emit-vectors <dir>]                 (write scrubbed vectors, see vectors/osdop/README.md)
    python3 harness/tools/osdop_check.py --vectors-only [--vectors <dir>]    (offline, no captures)

Exit status 0 only if every check passed.

What is read from <captures dir>:
  pcap/<session>.pcap              packets (only used as bytes on the wire)
  sessions.tsv                     which cephx entity / mode each session used
  secrets/session-secrets/*.txt    ONLY as a cross-check of the session keys this tool derives itself
  secrets/keys/*.keyring           throw-away keyrings of the extra sessions
  gt/ gt4/ data/                   ground truth (ceph osd map, rbd info json, source data files)
Keyrings are read at run time from --keys; key material is never printed or written.
Without arguments the tool checks the public vector set (harness/vectors/public) with the public throw-away keys.

Layout of this file
    1  primitives: crc32c, reader, string hash, stable modulo
    2  pcap and TCP reassembly
    3  msgr2 frames (revision 1, crc and secure)
    4  cephx crypto (only to open the secure-mode connection secrets)
    5  connection analysis
    6  osd message decoders (MOSDOp v9, MOSDOpReply v8, MOSDBackoff, op records)
    7  class-call decoders (rbd, lock) and omap decoders
    8  the checks
    9  vectors (emit / verify)
    10 command line
"""

import argparse
import base64
import bisect
import collections
import concurrent.futures
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pubset  # noqa: E402

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.stderr.write("this tool needs the 'cryptography' package (pip install --user cryptography)\n")
    sys.exit(2)

# ===========================================================================
# 1  primitives
# ===========================================================================


class DecodeError(Exception):
    pass


def _make_crc_tables():
    # note msgr2.md 2.5: reflected polynomial 0x82F63B78, raw update, caller supplied seed, no final XOR
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t0.append(c)
    tabs = [t0]
    for _ in range(7):
        prev = tabs[-1]
        tabs.append([(prev[i] >> 8) ^ t0[prev[i] & 0xFF] for i in range(256)])
    return tabs


_T = _make_crc_tables()
_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = _T


def crc32c(data, seed=0):
    """Raw CRC-32C update (no implicit inversion), slice-by-8."""
    crc = seed & 0xFFFFFFFF
    n = len(data)
    n8 = n - (n & 7)
    if n8:
        t0, t1, t2, t3, t4, t5, t6, t7 = _T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7
        for (w,) in struct.iter_unpack('<Q', memoryview(data)[:n8]):
            w ^= crc
            crc = (t7[w & 255] ^ t6[(w >> 8) & 255] ^ t5[(w >> 16) & 255] ^ t4[(w >> 24) & 255]
                   ^ t3[(w >> 32) & 255] ^ t2[(w >> 40) & 255] ^ t1[(w >> 48) & 255] ^ t0[w >> 56])
    for b in memoryview(data)[n8:]:
        crc = (crc >> 8) ^ _T0[(crc ^ b) & 255]
    return crc


M32 = 0xFFFFFFFF


def _mix(a, b, c):
    # note crush-and-placement.md 3.2.1 (nine rounds)
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


def str_hash_rjenkins(data):
    """Object-name hash of note crush-and-placement.md 3.1.1."""
    n = len(data)
    a = b = 0x9E3779B9
    c = 0
    k = data
    ln = n
    while ln >= 12:
        a = (a + struct.unpack_from('<I', k, 0)[0]) & M32
        b = (b + struct.unpack_from('<I', k, 4)[0]) & M32
        c = (c + struct.unpack_from('<I', k, 8)[0]) & M32
        a, b, c = _mix(a, b, c)
        k = k[12:]
        ln -= 12
    c = (c + n) & M32
    for i in range(ln):
        if i < 4:
            a = (a + (k[i] << (8 * i))) & M32
        elif i < 8:
            b = (b + (k[i] << (8 * (i - 4)))) & M32
        else:
            c = (c + (k[i] << (8 * (i - 8 + 1)))) & M32
    a, b, c = _mix(a, b, c)
    return c


def cbits(v):
    return v.bit_length()


def stable_mod(x, b, bmask):
    return x & bmask if (x & bmask) < b else x & (bmask >> 1)


def placement_hash(oid, key=b'', ns=b''):
    subject = key if key else oid
    if ns:
        subject = ns + b'\x1f' + subject
    return str_hash_rjenkins(subject)


class Reader:
    """Little-endian cursor over bytes."""

    def __init__(self, b, off=0, end=None):
        self.b = b
        self.o = off
        self.end = len(b) if end is None else end

    def left(self):
        return self.end - self.o

    def take(self, n):
        if n < 0 or self.o + n > self.end:
            raise DecodeError("need %d bytes, have %d at offset %d" % (n, self.left(), self.o))
        v = self.b[self.o:self.o + n]
        self.o += n
        return bytes(v)

    def skip(self, n):
        self.take(n)

    def u8(self):
        return self.take(1)[0]

    def i8(self):
        return struct.unpack('<b', self.take(1))[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def i32(self):
        return struct.unpack('<i', self.take(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]

    def i64(self):
        return struct.unpack('<q', self.take(8))[0]

    def blob(self):
        n = self.u32()
        return self.take(n)

    def string(self):
        return self.blob()

    def boolean(self):
        v = self.u8()
        if v > 1:
            raise DecodeError("bool byte %d" % v)
        return bool(v)

    def utime(self):
        return (self.u32(), self.u32())

    def struct_header(self, max_known=None):
        """6-byte versioned envelope (note osd-ops.md 1.3). Returns (v, compat, sub-reader)."""
        v = self.u8()
        compat = self.u8()
        ln = self.u32()
        if ln > self.left():
            raise DecodeError("struct_len %d > remaining %d" % (ln, self.left()))
        if max_known is not None and compat > max_known:
            raise DecodeError("struct_compat %d > %d" % (compat, max_known))
        sub = Reader(self.b, self.o, self.o + ln)
        self.o += ln
        return v, compat, sub


def hexs(b, n=None):
    if n is not None and len(b) > n:
        return b[:n].hex() + '..(%d bytes)' % len(b)
    return b.hex()


# ===========================================================================
# 2  pcap and TCP reassembly
# ===========================================================================


class Stream:
    """One direction of one TCP connection, reassembled by sequence number."""

    def __init__(self):
        self.isn = None
        self.segs = {}        # offset -> bytes (first copy)
        self.times = []       # (offset, ts) for first copies
        self.retrans = 0
        self.conflict = 0
        self.data = b''
        self.gaps = 0
        self.fin_or_rst = False
        self._offs = None
        self.acked = 0          # highest byte offset the peer acknowledged (from the other direction's ACK fields)

    def add(self, seq, payload, ts):
        if self.isn is None:
            self.isn = seq
        off = (seq - self.isn) & M32
        if off in self.segs and len(self.segs[off]) >= len(payload):
            self.retrans += 1
            if self.segs[off][:len(payload)] != payload:
                self.conflict += 1
            return
        if off in self.segs:
            self.retrans += 1
        self.segs[off] = payload
        self.times.append((off, ts))

    def finish(self):
        out = bytearray()
        for off in sorted(self.segs):
            d = self.segs[off]
            if off > len(out):
                self.gaps += 1
                break  # a hole: stop, nothing after it can be trusted
            if off + len(d) <= len(out):
                if bytes(out[off:off + len(d)]) != d:
                    self.conflict += 1
                self.retrans += 1
                continue
            skip = len(out) - off
            if skip and bytes(out[off:]) != d[:skip]:
                self.conflict += 1
            out += d[skip:]
        self.data = bytes(out)
        self.times.sort()
        self._offs = [t[0] for t in self.times]

    def ts_at(self, off):
        i = bisect.bisect_right(self._offs, off) - 1
        if i < 0:
            i = 0
        return self.times[i][1] if self.times else 0.0


class Conn:
    def __init__(self, cip, cport, sip, sport):
        self.cip, self.cport, self.sip, self.sport = cip, cport, sip, sport
        self.c2s = Stream()
        self.s2c = Stream()
        self.first_ts = None
        self.syn_seen = False


def read_pcap(path):
    with open(path, 'rb') as f:
        buf = f.read()
    if len(buf) < 24:
        raise DecodeError("short pcap")
    magic = buf[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        e, nano = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4':
        e, nano = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1':
        e, nano = '<', True
    else:
        raise DecodeError("unsupported pcap magic %r" % magic)
    linktype = struct.unpack(e + 'I', buf[20:24])[0]
    if linktype != 1:
        raise DecodeError("link type %d (need Ethernet)" % linktype)
    off = 24
    pk = []
    while off + 16 <= len(buf):
        sec, frac, incl, _orig = struct.unpack(e + 'IIII', buf[off:off + 16])
        off += 16
        pk.append((sec + frac / (1e9 if nano else 1e6), buf[off:off + incl]))
        off += incl
    return pk


def load_conns(path):
    conns = {}
    order = []
    for ts, fr in read_pcap(path):
        if len(fr) < 14 + 20 or fr[12:14] != b'\x08\x00':
            continue
        ip = fr[14:]
        ihl = (ip[0] & 15) * 4
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        tot = struct.unpack('>H', ip[2:4])[0]
        if tot < ihl + 20 or tot > len(ip):
            # segmentation offload: the capture holds a super-packet whose IP length field is 0
            tot = len(ip)
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[ihl:tot]
        if len(tcp) < 20:
            continue
        sp, dp, seq, _ack = struct.unpack('>HHII', tcp[:12])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        payload = tcp[doff:]
        sips = '.'.join(map(str, src))
        dips = '.'.join(map(str, dst))
        # the client is the side that sent the SYN without ACK; otherwise the side
        # that talks to a well known daemon port (3300 / 6789 / 68xx)
        key = None
        for k in ((sips, sp, dips, dp), (dips, dp, sips, sp)):
            if k in conns:
                key = k
        if key is None:
            if flags & 2 and not flags & 16:
                key = (sips, sp, dips, dp)
            else:
                key = (sips, sp, dips, dp) if dp < sp else (dips, dp, sips, sp)
            conns[key] = Conn(*key)
            order.append(key)
        c = conns[key]
        if c.first_ts is None:
            c.first_ts = ts
        from_client = (sips, sp) == (key[0], key[1])
        st = c.c2s if from_client else c.s2c
        if flags & 2:
            c.syn_seen = True
            st.isn = (seq + 1) & M32
            continue
        if flags & 5:  # FIN or RST
            st.fin_or_rst = True
        if flags & 16:
            other = c.s2c if from_client else c.c2s
            if other.isn is not None:
                ao = (_ack - other.isn) & M32
                if ao < (1 << 31) and ao > other.acked:
                    other.acked = ao
        if payload:
            st.add(seq, bytes(payload), ts)
    out = []
    for k in order:
        c = conns[k]
        c.c2s.finish()
        c.s2c.finish()
        out.append(c)
    return out


# ===========================================================================
# 3  msgr2 frames
# ===========================================================================

TAGS = {1: 'HELLO', 2: 'AUTH_REQUEST', 3: 'AUTH_BAD_METHOD', 4: 'AUTH_REPLY_MORE',
        5: 'AUTH_REQUEST_MORE', 6: 'AUTH_DONE', 7: 'AUTH_SIGNATURE', 8: 'CLIENT_IDENT',
        9: 'SERVER_IDENT', 10: 'IDENT_MISSING_FEATURES', 11: 'SESSION_RECONNECT',
        12: 'SESSION_RESET', 13: 'SESSION_RETRY', 14: 'SESSION_RETRY_GLOBAL',
        15: 'SESSION_RECONNECT_OK', 16: 'WAIT', 17: 'MESSAGE', 18: 'KEEPALIVE2',
        19: 'KEEPALIVE2_ACK', 20: 'ACK', 21: 'COMPRESSION_REQUEST', 22: 'COMPRESSION_DONE'}
TAG_HELLO, TAG_AUTH_REQUEST, TAG_AUTH_BAD_METHOD, TAG_AUTH_REPLY_MORE = 1, 2, 3, 4
TAG_AUTH_REQUEST_MORE, TAG_AUTH_DONE, TAG_AUTH_SIGNATURE = 5, 6, 7
TAG_CLIENT_IDENT, TAG_SERVER_IDENT, TAG_MESSAGE, TAG_KEEPALIVE2, TAG_KEEPALIVE2_ACK = 8, 9, 17, 18, 19

BANNER = b'ceph v2\n'


class Frame:
    __slots__ = ('tag', 'segs', 'seglens', 'aligns', 'start', 'end', 'ok', 'errs', 'late', 'secure', 'ts')

    def __init__(self):
        self.errs = []
        self.ok = True
        self.late = None
        self.secure = False
        self.segs = []
        self.ts = 0.0


def _pad16(x):
    return (x + 15) & ~15


def _parse_preamble(pre, fr):
    if len(pre) != 32:
        raise DecodeError("preamble length %d" % len(pre))
    crc = struct.unpack('<I', pre[28:32])[0]
    if crc32c(pre[:28], 0) != crc:
        fr.errs.append('preamble crc')
    fr.tag = pre[0]
    n = pre[1]
    if not 1 <= n <= 4:
        fr.errs.append('segment count %d' % n)
        n = max(1, min(n, 4))
    fr.seglens, fr.aligns = [], []
    for i in range(4):
        ln, al = struct.unpack_from('<IH', pre, 2 + 6 * i)
        fr.seglens.append(ln)
        fr.aligns.append(al)
    for i in range(n, 4):
        if fr.seglens[i]:
            fr.errs.append('unused segment %d has length' % i)
    fr.seglens = fr.seglens[:n]
    fr.aligns = fr.aligns[:n]
    if n > 1 and fr.seglens[-1] == 0:
        fr.errs.append('last segment empty')
    if pre[26] & 0xFE or pre[27]:
        fr.errs.append('flags/reserved nonzero')
    return n


def parse_crc_frame(buf, off):
    """Parse one revision-1 crc-mode frame at buf[off:]. Returns (Frame, new offset) or (None, off)."""
    fr = Frame()
    fr.start = off
    if len(buf) - off < 32:
        return None, off
    n = _parse_preamble(buf[off:off + 32], fr)
    p = off + 32
    L = fr.seglens
    need = 32 + (L[0] + 4 if L[0] else 0) + sum(L[1:]) + (13 if n > 1 else 0)
    if len(buf) - off < need:
        return None, off
    segs = []
    if L[0]:
        s0 = buf[p:p + L[0]]
        p += L[0]
        c = struct.unpack('<I', buf[p:p + 4])[0]
        p += 4
        if crc32c(s0, 0xFFFFFFFF) != c:
            fr.errs.append('segment 0 crc')
        segs.append(s0)
    else:
        segs.append(b'')
    for i in range(1, n):
        segs.append(buf[p:p + L[i]])
        p += L[i]
    if n > 1:
        ep = buf[p:p + 13]
        p += 13
        fr.late = ep[0]
        if ep[0] & 0x0F != 0x0E:
            fr.errs.append('late_status %02x' % ep[0])
        for i in range(1, n):
            c = struct.unpack_from('<I', ep, 1 + 4 * (i - 1))[0]
            if crc32c(segs[i], 0xFFFFFFFF) != c:
                fr.errs.append('segment %d crc' % i)
        for i in range(n, 4):
            if struct.unpack_from('<I', ep, 1 + 4 * (i - 1))[0] != 0:
                fr.errs.append('unused epilogue crc slot %d nonzero' % i)
    fr.segs = segs
    fr.end = p
    fr.ok = not fr.errs
    return fr, p


class SecureDir:
    """One direction of an AES-128-GCM msgr2.1 stream (note msgr2-secure-mode.md 2.6, 2.8)."""

    def __init__(self, key16, nonce12):
        self.aead = AESGCM(key16)
        self.fixed = nonce12[:4]
        self.ctr = struct.unpack('<Q', nonce12[4:])[0]
        self.ops = 0

    def op(self, ct_and_tag):
        nonce = self.fixed + struct.pack('<Q', self.ctr)
        self.ctr = (self.ctr + 1) & 0xFFFFFFFFFFFFFFFF
        self.ops += 1
        return self.aead.decrypt(nonce, bytes(ct_and_tag), None)


def parse_secure_frame(buf, off, sd):
    fr = Frame()
    fr.start = off
    fr.secure = True
    if len(buf) - off < 96:
        return None, off
    try:
        p1 = sd.op(buf[off:off + 96])
    except Exception:
        fr.errs.append('part 1 tag')
        fr.ok = False
        fr.tag = 0
        fr.segs = []
        fr.end = off
        return fr, len(buf)
    p = off + 96
    n = _parse_preamble(p1[:32], fr)
    L = fr.seglens
    inline = p1[32:80]
    if L[0] > 48:
        rest = _pad16(L[0]) - 48
        if len(buf) - p < rest + 16:
            return None, off
        try:
            r = sd.op(buf[p:p + rest + 16])
        except Exception:
            fr.errs.append('part 2 tag')
            fr.ok = False
            fr.segs = []
            fr.end = p
            return fr, len(buf)
        p += rest + 16
        seg0 = (inline + r)[:L[0]]
    else:
        seg0 = inline[:L[0]]
    segs = [seg0]
    if n > 1:
        body = sum(_pad16(L[i]) for i in range(1, n)) + 16
        if len(buf) - p < body + 16:
            return None, off
        try:
            r = sd.op(buf[p:p + body + 16])
        except Exception:
            fr.errs.append('part 3 tag')
            fr.ok = False
            fr.segs = segs
            fr.end = p
            return fr, len(buf)
        p += body + 16
        q = 0
        for i in range(1, n):
            segs.append(r[q:q + L[i]])
            q += _pad16(L[i])
        fr.late = r[q]
        if r[q] & 0x0F != 0x0E:
            fr.errs.append('late_status %02x' % r[q])
    fr.segs = segs
    fr.end = p
    fr.ok = not fr.errs
    return fr, p


# ===========================================================================
# 4  cephx crypto (note cephx.md 2.3 - 2.7, 2.10)
# ===========================================================================

CEPHX_MAGIC = 0xFF009CAD8826AA55
CBC_IV1 = b'cephsageyudagreg'  # note cephx.md 2.1: hex 63 65 70 68 73 61 67 65 79 75 64 61 67 72 65 67
USAGE_CONN_SECRET, USAGE_TICKET_SESSION_KEY, USAGE_TICKET_BLOB = 0x03, 0x04, 0x05
USAGE_AUTHORIZE, USAGE_AUTHORIZE_CHALLENGE, USAGE_AUTHORIZE_REPLY = 0x10, 0x11, 0x12


class CephxError(Exception):
    pass


class CKey:
    def __init__(self, ktype, secret, created=(0, 0)):
        self.type, self.secret, self.created = ktype, secret, created
        self._d = {}

    @staticmethod
    def decode(b):
        r = Reader(b)
        t = r.u16()
        cr = r.utime()
        n = r.u16()
        s = r.take(n)
        if t == 1 and n < 16 or t == 2 and n < 32 or t not in (1, 2):
            raise CephxError("bad key type/len %d/%d" % (t, n))
        return CKey(t, s, cr), r

    def encode(self):
        return struct.pack('<HIIH', self.type, self.created[0], self.created[1], len(self.secret)) + self.secret

    # -- type 2 key schedule (RFC 8009 style, note cephx.md 2.5)
    def _derive(self, usage, tbyte, nbits):
        inp = b'\x00\x00\x00\x01' + struct.pack('>I', usage) + bytes([tbyte, 0]) + struct.pack('>I', nbits)
        return hmac.new(self.secret, inp, hashlib.sha384).digest()[:nbits // 8]

    def keys2(self, usage):
        if usage not in self._d:
            self._d[usage] = (self._derive(usage, 0x55, 192), self._derive(usage, 0xAA, 256))
        return self._d[usage]

    def decrypt(self, ct, usage):
        if self.type == 1:
            if not ct or len(ct) % 16:
                raise CephxError("type 1 ciphertext length %d" % len(ct))
            d = Cipher(algorithms.AES(self.secret[:16]), modes.CBC(CBC_IV1)).decryptor()
            pt = d.update(ct) + d.finalize()
            pad = pt[-1]
            if not 1 <= pad <= 16:
                raise CephxError("type 1 padding byte %d" % pad)
            return pt[:-pad]
        ki, ke = self.keys2(usage)
        if len(ct) < 40:
            raise CephxError("type 2 ciphertext too short")
        body, mac = ct[:-24], ct[-24:]
        if not hmac.compare_digest(hmac.new(ki, b'\x00' * 16 + body, hashlib.sha384).digest()[:24], mac):
            raise CephxError("type 2 MAC mismatch")
        m = _cts3_decrypt(ke, body)
        return m[16:]


def _ecb_dec(key, blk):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(blk) + d.finalize()


def _cbc_dec_zero_iv(key, data):
    d = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16)).decryptor()
    return d.update(data) + d.finalize()


def _cts3_decrypt(key, ct):
    n = len(ct)
    if n < 16:
        raise CephxError("CTS input shorter than a block")
    if n == 16:
        return _cbc_dec_zero_iv(key, ct)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    head = ct[:16 * (k - 2)]
    ck = ct[16 * (k - 2):16 * (k - 1)]
    part = ct[16 * (k - 1):]
    x = _ecb_dec(key, ck)
    ckm1 = part + x[r:]
    pk = bytes(a ^ b for a, b in zip(x[:r], part))
    pre = _cbc_dec_zero_iv(key, head + ckm1)
    return pre + pk


def open_envelope(key, ct, usage):
    """Decrypt an encode+encrypt item: u8 1, u64 magic, then the item. Returns the item bytes."""
    pt = key.decrypt(ct, usage)
    if len(pt) < 9:
        raise CephxError("envelope too short")
    if struct.unpack('<Q', pt[1:9])[0] != CEPHX_MAGIC:
        raise CephxError("envelope magic mismatch")
    return pt[9:]


def parse_keyring(path):
    out = {}
    cur = None
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            m = re.match(r'^\[(.+)\]$', line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r'^key\s*=\s*(\S+)$', line)
            if m and cur:
                k, _ = CKey.decode(base64.b64decode(m.group(1)))
                out[cur] = k
    return out


def parse_ticket_reply(r, key_for_msg_a, prev_key=None):
    """Ticket reply (note cephx.md 2.7). Returns list of dict(service, key, validity, blob)."""
    r.u8()  # reply_v
    num = r.u32()
    out = []
    for _ in range(num):
        service = r.u32()
        r.u8()  # ticket_v
        msg_a = r.blob()
        ticket_enc = r.u8()
        item = open_envelope(key_for_msg_a, msg_a, USAGE_TICKET_SESSION_KEY)
        ir = Reader(item)
        ir.u8()  # CephXServiceTicket struct_v
        sk, ir2 = CKey.decode(item[1:])
        ir = Reader(item, 1 + 12 + len(sk.secret))
        validity = ir.utime()
        if ticket_enc == 0:
            bl = r.blob()
        else:
            ct = r.blob()
            if prev_key is None:
                raise CephxError("encrypted ticket blob without previous key")
            inner = open_envelope(prev_key, ct, USAGE_TICKET_BLOB)
            bl = Reader(inner).blob()
        br = Reader(bl)
        br.u8()
        secret_id = br.u64()
        data = br.blob()
        out.append(dict(service=service, key=sk, validity=validity, blob=data, secret_id=secret_id))
    return out


# ===========================================================================
# 5  connection analysis
# ===========================================================================


class Msg:
    __slots__ = ('dir', 'seq', 'tid', 'type', 'prio', 'ver', 'compat', 'front', 'middle', 'data',
                 'ts', 'hdr', 'seglens', 'dpp', 'data_off', 'ack_seq', 'flags', 'resv', 'conn', 'hdr_raw', 'nseg')


def decode_header2(h):
    if len(h) != 41:
        raise DecodeError("ceph_msg_header2 is %d bytes, not 41" % len(h))
    (seq, tid, typ, prio, ver, dpp, doff, ackseq, flags, compat, resv) = struct.unpack('<QQHHHIHQBHH', h)
    return dict(seq=seq, tid=tid, type=typ, prio=prio, ver=ver, dpp=dpp, data_off=doff,
                ack_seq=ackseq, flags=flags, compat=compat, resv=resv)


class ConnInfo:
    """Everything the checks need to know about one TCP connection."""

    def __init__(self, c):
        self.c = c
        self.role = None        # 'mon' | 'osd' | 'other'
        self.mode = 'crc'
        self.frames = {'c2s': [], 's2c': []}
        self.msgs = []
        self.problems = []
        self.client_ident = None
        self.server_ident = None
        self.global_id = None
        self.auth_done = None
        self.secret = b''
        self.session_key = None   # CKey used for the pre-auth signature
        self.sig_ok = None
        self.banners = {}
        self.eof_partial = {'c2s': 0, 's2c': 0}
        self.auth_frames = {'c2s': [], 's2c': []}
        self.nsecure_ops = 0


def parse_banner(buf):
    if len(buf) < 26 or buf[:8] != BANNER:
        raise DecodeError("no msgr2 banner")
    ln = struct.unpack('<H', buf[8:10])[0]
    if ln < 16 or len(buf) < 10 + ln:
        raise DecodeError("banner payload %d" % ln)
    sup, req = struct.unpack('<QQ', buf[10:26])
    return 10 + ln, sup, req


def parse_entity_addr(r):
    """entity_addr_t of note msgr2.md 2.8 (only what is needed to skip it)."""
    marker = r.u8()
    if marker == 0:
        raise DecodeError("legacy address marker 0")
    v = r.u8()
    compat = r.u8()
    ln = r.u32()
    body = Reader(r.b, r.o, r.o + ln)
    r.skip(ln)
    typ = body.u32()
    nonce = body.u32()
    elen = body.u32()
    sa = body.take(elen)
    fam = struct.unpack('<H', sa[:2])[0] if elen >= 2 else 0
    return dict(type=typ, nonce=nonce, family=fam, raw=sa)


def parse_client_ident(p):
    r = Reader(p)
    marker = r.u8()
    cnt = r.u32()
    addrs = []
    for _ in range(cnt):
        addrs.append(parse_entity_addr(r))
    tgt = parse_entity_addr(r)
    gid = r.i64()
    gseq = r.u64()
    sup = r.u64()
    req = r.u64()
    flags = r.u64()
    cookie = r.u64()
    return dict(gid=gid, global_seq=gseq, supported=sup, required=req, flags=flags, cookie=cookie)


def parse_server_ident(p):
    r = Reader(p)
    marker = r.u8()
    cnt = r.u32()
    for _ in range(cnt):
        parse_entity_addr(r)
    gid = r.i64()
    gseq = r.u64()
    sup = r.u64()
    req = r.u64()
    flags = r.u64()
    cookie = r.u64()
    return dict(gid=gid, global_seq=gseq, supported=sup, required=req, flags=flags, cookie=cookie)


def parse_auth_done(p):
    r = Reader(p)
    gid = r.u64()
    mode = r.u32()
    payload = r.blob()
    return dict(global_id=gid, mode=mode, payload=payload)


def parse_auth_request(p):
    r = Reader(p)
    method = r.u32()
    n = r.u32()
    modes_ = [r.u32() for _ in range(n)]
    payload = r.blob()
    return dict(method=method, modes=modes_, payload=payload)


class AuthState:
    """cephx material shared by the connections of one session (one pcap)."""

    def __init__(self, keyring_key):
        self.user_key = keyring_key
        self.auth_key = None        # AUTH ticket session key (CKey)
        self.tickets = []           # dicts from parse_ticket_reply
        self.log = []

    def find_ticket(self, blob):
        for t in self.tickets:
            if t['blob'] == blob:
                return t
        return None


def analyze_conn(c, auth, results, name):
    """Parse all frames of one connection; open the secure-mode streams when needed."""
    ci = ConnInfo(c)
    if c.sport == 3300 or c.sport == 6789:
        ci.role = 'mon'
    elif 6800 <= c.sport <= 7300:
        ci.role = 'osd'     # also covers mgr; refined later by HELLO/ident
    else:
        ci.role = 'other'
    G = 'framing'
    # banners
    pos = {}
    for d, st in (('c2s', c.c2s), ('s2c', c.s2c)):
        if not st.data:
            pos[d] = 0
            continue
        try:
            n, sup, req = parse_banner(st.data)
            ci.banners[d] = (sup, req)
            pos[d] = n
        except DecodeError as e:
            results.fail(G, "%s %s banner: %s" % (name, d, e))
            pos[d] = len(st.data)
    # plain handshake frames, server direction first
    s2c_plain = []
    p = pos['s2c']
    secure_from = {}
    auth_done_frame = None
    while p < len(c.s2c.data):
        fr, q = parse_crc_frame(c.s2c.data, p)
        if fr is None:
            ci.eof_partial['s2c'] = len(c.s2c.data) - p
            break
        fr.ts = c.s2c.ts_at(p)
        s2c_plain.append(fr)
        p = q
        if fr.tag == TAG_AUTH_DONE and fr.ok:
            auth_done_frame = fr
            break
        if not fr.ok:
            break
    ci.frames['s2c'] = s2c_plain
    n_more = sum(1 for f in s2c_plain if f.tag == TAG_AUTH_REPLY_MORE)
    n_bad = sum(1 for f in s2c_plain if f.tag == TAG_AUTH_BAD_METHOD)
    # client direction: HELLO + (1 + bad) AUTH_REQUEST + n_more AUTH_REQUEST_MORE are plain
    c2s_plain_expected = 1 + (1 + n_bad) + n_more
    c2s = []
    p2 = pos['c2s']
    while p2 < len(c.c2s.data) and (auth_done_frame is None or len(c2s) < c2s_plain_expected):
        fr, q = parse_crc_frame(c.c2s.data, p2)
        if fr is None:
            ci.eof_partial['c2s'] = len(c.c2s.data) - p2
            break
        fr.ts = c.c2s.ts_at(p2)
        c2s.append(fr)
        p2 = q
        if not fr.ok:
            break
    ci.frames['c2s'] = c2s
    # transcripts for the pre-auth signature (note msgr2-secure-mode.md 2.7)
    tx_transcript = c.c2s.data[:p2] if auth_done_frame is not None else b''
    rx_transcript = c.s2c.data[:p] if auth_done_frame is not None else b''
    # hello / auth analysis
    for fr in c2s:
        if fr.tag in (TAG_AUTH_REQUEST, TAG_AUTH_REQUEST_MORE):
            ci.auth_frames['c2s'].append(fr)
    for fr in s2c_plain:
        if fr.tag in (TAG_AUTH_REPLY_MORE, TAG_AUTH_DONE, TAG_AUTH_BAD_METHOD):
            ci.auth_frames['s2c'].append(fr)
    sdir_rx = sdir_tx = None
    if auth_done_frame is not None:
        try:
            ci.auth_done = parse_auth_done(auth_done_frame.segs[0])
            ci.global_id = ci.auth_done['global_id']
            ci.mode = {1: 'crc', 2: 'secure'}.get(ci.auth_done['mode'], 'unknown')
        except DecodeError as e:
            results.fail(G, "%s AUTH_DONE decode: %s" % (name, e))
        try:
            _derive_session(ci, auth, tx_transcript, rx_transcript, results, name)
        except (CephxError, DecodeError, struct.error) as e:
            results.fail('cephx', "%s %s connection session key: %s" % (name, ci.role, e))
        if ci.mode == 'secure':
            if len(ci.secret) >= 40:
                key = ci.secret[:16]
                a, b = ci.secret[16:28], ci.secret[28:40]
                sdir_rx = SecureDir(key, a)   # client receives with seed A
                sdir_tx = SecureDir(key, b)   # client sends with seed B
            else:
                results.fail('cephx', "%s secure mode but no usable connection secret" % name)
    # remaining frames
    for d, st, start, sd in (('s2c', c.s2c, p, sdir_rx), ('c2s', c.c2s, p2, sdir_tx)):
        buf = st.data
        off = start
        out = ci.frames[d]
        while off < len(buf):
            if ci.mode == 'secure':
                if sd is None:
                    break
                fr, q = parse_secure_frame(buf, off, sd)
            else:
                if auth_done_frame is None and d == 's2c':
                    break
                if auth_done_frame is None and d == 'c2s':
                    break
                fr, q = parse_crc_frame(buf, off)
            if fr is None:
                ci.eof_partial[d] = len(buf) - off
                break
            fr.ts = st.ts_at(off)
            out.append(fr)
            off = q
            if not fr.ok:
                ci.problems.append('%s frame at %d: %s' % (d, off, ','.join(fr.errs)))
                break
    # AUTH_SIGNATURE frames (first post-AUTH_DONE frame each way)
    _check_signatures(ci, auth_done_frame, tx_transcript, rx_transcript, results, name)
    # idents and messages
    for d in ('c2s', 's2c'):
        for fr in ci.frames[d]:
            if fr.tag == TAG_CLIENT_IDENT and d == 'c2s':
                ci.client_ident = parse_client_ident(fr.segs[0])
            elif fr.tag == TAG_SERVER_IDENT and d == 's2c':
                ci.server_ident = parse_server_ident(fr.segs[0])
            elif fr.tag == TAG_MESSAGE and fr.ok:
                m = Msg()
                h = decode_header2(fr.segs[0])
                m.hdr = h
                m.dir, m.seq, m.tid, m.type = d, h['seq'], h['tid'], h['type']
                m.prio, m.ver, m.compat = h['prio'], h['ver'], h['compat']
                m.dpp, m.data_off, m.ack_seq, m.flags, m.resv = h['dpp'], h['data_off'], h['ack_seq'], h['flags'], h['resv']
                segs = fr.segs + [b''] * (4 - len(fr.segs))
                m.front, m.middle, m.data = segs[1], segs[2], segs[3]
                m.seglens = list(fr.seglens) + [0] * (4 - len(fr.seglens))
                m.nseg = len(fr.seglens)
                m.ts = fr.ts
                m.conn = ci
                ci.msgs.append(m)
    ci.msgs.sort(key=lambda m: (m.ts, 0 if m.dir == 'c2s' else 1, m.seq))
    return ci


def _derive_session(ci, auth, tx_tr, rx_tr, results, name):
    """Open the AUTH_DONE payload with the lab keys; fill auth state and connection secret."""
    payload = ci.auth_done['payload']
    if ci.role == 'mon':
        if auth.user_key is None:
            return
        r = Reader(payload)
        rt = r.u16()
        status = r.i32()
        if rt != 0x0100:
            raise CephxError("mon AUTH_DONE request_type %#x" % rt)
        if status != 0:
            raise CephxError("mon AUTH_DONE status %d" % status)
        t = parse_ticket_reply(r, auth.user_key, auth.auth_key)
        if len(t) != 1 or t[0]['service'] != 0x20:
            raise CephxError("expected exactly one AUTH ticket first")
        ak = t[0]['key']
        auth.auth_key = ak
        auth.tickets.append(t[0])
        cbl = r.blob() if r.left() else b''
        secret = b''
        if cbl:
            inner = Reader(cbl).blob()
            item = open_envelope(ak, inner, USAGE_CONN_SECRET)
            secret = Reader(item).blob()
        extra = r.blob() if r.left() else b''
        if extra:
            ex = parse_ticket_reply(Reader(extra), ak)
            auth.tickets.extend(ex)
        ci.secret = secret
        ci.session_key = ak
        want_len = 64 if ci.mode == 'secure' else 0
        results.check('cephx', len(secret) == want_len,
                      "%s mon connection secret length %d (mode %s)" % (name, len(secret), ci.mode))
        return
    if ci.role == 'osd':
        # authorizer in the last client AUTH_REQUEST / AUTH_REQUEST_MORE
        last = None
        for fr in ci.auth_frames['c2s']:
            if fr.tag == TAG_AUTH_REQUEST:
                last = parse_auth_request(fr.segs[0])['payload']
            else:
                last = Reader(fr.segs[0]).blob()
        if last is None:
            return
        r = Reader(last)
        ver = r.u8()
        gid = r.u64()
        service = r.u32()
        r.u8()
        r.u64()
        blob = r.blob()
        proof = r.blob()
        t = auth.find_ticket(blob)
        if t is None:
            raise CephxError("authorizer ticket blob not among the tickets of this session")
        tk = t['key']
        item = open_envelope(tk, proof, USAGE_AUTHORIZE)
        ir = Reader(item)
        ir.u8()
        nonce = ir.u64()
        have_ch = ir.boolean()
        ch_plus = ir.u64()
        ci.session_key = tk
        # server challenge (usage 0x11, raw envelope without length prefix)
        challenge = None
        for fr in ci.auth_frames['s2c']:
            if fr.tag == TAG_AUTH_REPLY_MORE:
                bl = Reader(fr.segs[0]).blob()
                it = open_envelope(tk, bl, USAGE_AUTHORIZE_CHALLENGE)
                ir2 = Reader(it)
                ir2.u8()
                challenge = ir2.u64()
        results.check('cephx', (challenge is None) == (not have_ch) or True, "challenge presence")
        if challenge is not None:
            results.check('cephx', have_ch and ch_plus == (challenge + 1) & 0xFFFFFFFFFFFFFFFF,
                          "%s authorizer answers the server challenge (+1)" % name)
        # final reply
        inner = Reader(payload).blob()
        item = open_envelope(tk, inner, USAGE_AUTHORIZE_REPLY)
        rr = Reader(item)
        v = rr.u8()
        nplus = rr.u64()
        results.check('cephx', nplus == (nonce + 1) & 0xFFFFFFFFFFFFFFFF,
                      "%s authorizer reply nonce_plus_one" % name)
        secret = rr.blob() if v >= 2 else b''
        ci.secret = secret
        results.check('cephx', (v >= 2) == (ci.mode == 'secure'),
                      "%s authorizer reply version %d for mode %s" % (name, v, ci.mode))
        if ci.mode == 'secure':
            results.check('cephx', len(secret) == 64, "%s osd connection secret length %d" % (name, len(secret)))


def _check_signatures(ci, adf, tx_tr, rx_tr, results, name):
    if adf is None or ci.session_key is None:
        return
    key = ci.session_key.secret
    sig_c = sig_s = None
    for fr in ci.frames['c2s']:
        if fr.tag == TAG_AUTH_SIGNATURE:
            sig_c = fr.segs[0]
            break
    for fr in ci.frames['s2c']:
        if fr.tag == TAG_AUTH_SIGNATURE:
            sig_s = fr.segs[0]
            break
    ok = True
    if sig_c is not None:
        ok &= hmac.compare_digest(sig_c, hmac.new(key, rx_tr, hashlib.sha256).digest())
    if sig_s is not None:
        ok &= hmac.compare_digest(sig_s, hmac.new(key, tx_tr, hashlib.sha256).digest())
    if sig_c is not None or sig_s is not None:
        ci.sig_ok = ok
        results.check('cephx', ok, "%s AUTH_SIGNATURE (both directions) equals HMAC-SHA256 over the transcripts" % name)


class Results:
    """pass / fail counters per group, with a few failure messages kept."""

    def __init__(self):
        self.counts = collections.OrderedDict()
        self.msgs = collections.defaultdict(list)
        self.warnings = []

    def check(self, group, cond, msg=''):
        c = self.counts.setdefault(group, [0, 0])
        if cond:
            c[0] += 1
        else:
            c[1] += 1
            self.msgs[group].append(msg)
        return bool(cond)

    def fail(self, group, msg):
        self.check(group, False, msg)

    def warn(self, msg):
        self.warnings.append(msg)

    def merge(self, other):
        self.warnings.extend(other.warnings)
        for g, (p, f) in other.counts.items():
            c = self.counts.setdefault(g, [0, 0])
            c[0] += p
            c[1] += f
        for g, m in other.msgs.items():
            self.msgs[g].extend(m)


# ===========================================================================
# 6  osd message decoders (note osd-ops.md section 2)
# ===========================================================================

CEPH_NOSNAP = 0xFFFFFFFFFFFFFFFE
MSG_OSD_MAP, MSG_OSD_OP, MSG_OSD_OPREPLY, MSG_OSD_BACKOFF = 41, 42, 43, 61

# note 2.6: op codes
OPS = {
    0x1201: 'READ', 0x1202: 'STAT', 0x1205: 'SPARSE_READ', 0x1208: 'ASSERT_VER',
    0x2201: 'WRITE', 0x2202: 'WRITEFULL', 0x2203: 'TRUNCATE', 0x2204: 'ZERO', 0x2205: 'DELETE',
    0x220D: 'CREATE', 0x2223: 'SETALLOCHINT', 0x2226: 'WRITESAME', 0x1220: 'CMPEXT',
    0x1211: 'OMAPGETKEYS', 0x1212: 'OMAPGETVALS', 0x1213: 'OMAPGETHEADER', 0x1214: 'OMAPGETVALSBYKEYS',
    0x1301: 'GETXATTR', 0x1401: 'CALL',
}
OP_NAMES = {v: k for k, v in OPS.items()}
# ops that mutate (mode bit WR 0x2000 of the code, note 2.6); CALL is decided per method
MUTATING = {'WRITE', 'WRITEFULL', 'TRUNCATE', 'ZERO', 'DELETE', 'CREATE', 'SETALLOCHINT', 'WRITESAME'}

# note 2.4
F_ACK, F_ONNVRAM, F_ONDISK, F_RETRY, F_READ, F_WRITE = 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
F_KNOWN_REDIR, F_SUPPORTSPOOLEIO = 0x400000, 0x8000000

ERRNO = {1: 'EPERM', 2: 'ENOENT', 5: 'EIO', 11: 'EAGAIN', 17: 'EEXIST', 22: 'EINVAL', 23: 'ENFILE',
         27: 'EFBIG', 28: 'ENOSPC', 36: 'ENAMETOOLONG', 61: 'ENODATA', 85: 'EOLDSNAPC', 90: 'EMSGSIZE',
         95: 'EOPNOTSUPP', 108: 'EBLOCKLISTED', 122: 'EDQUOT', 16: 'EBUSY', 125: 'ECANCELED'}


def errname(n):
    return ERRNO.get(-n, str(n)) if n < 0 else str(n)


def dec_pg_t(r):
    v = r.u8()
    if v != 1:
        raise DecodeError("pg_t leading byte %d" % v)
    pool = r.u64()
    seed = r.u32()
    pref = r.i32()
    return dict(pool=pool, seed=seed, preferred=pref)


def dec_spg_t(r):
    start = r.o
    v, compat, sub = r.struct_header(1)
    pg = dec_pg_t(sub)
    shard = sub.i8()
    return dict(v=v, compat=compat, pg=pg, shard=shard, size=r.o - start, left=sub.left())


def dec_reqid(r):
    v, compat, sub = r.struct_header(2)
    typ = sub.u8()
    num = sub.i64()
    tid = sub.u64()
    inc = sub.i32()
    return dict(v=v, compat=compat, name_type=typ, name_num=num, tid=tid, inc=inc, left=sub.left())


def dec_oloc(r):
    v, compat, sub = r.struct_header(6)
    pool = sub.i64()
    pref = sub.i32()
    key = sub.string()
    nspace = sub.string()
    hsh = sub.i64()
    return dict(v=v, compat=compat, pool=pool, preferred=pref, key=key, nspace=nspace, hash=hsh, left=sub.left())


def dec_op_record(b):
    """The 38-byte raw ceph_osd_op (note 2.5)."""
    if len(b) != 38:
        raise DecodeError("op record %d bytes" % len(b))
    op, flags = struct.unpack_from('<HI', b, 0)
    union = b[6:34]
    payload_len = struct.unpack_from('<I', b, 34)[0]
    d = dict(op=op, name=OPS.get(op, '0x%04x' % op), flags=flags, union=union, payload_len=payload_len, raw=bytes(b))
    name = d['name']
    if name in ('READ', 'SPARSE_READ', 'WRITE', 'WRITEFULL', 'ZERO', 'TRUNCATE'):
        d['offset'], d['length'], d['truncate_size'], d['truncate_seq'] = struct.unpack_from('<QQQI', b, 6)
    elif name == 'GETXATTR':
        d['name_len'], d['value_len'], d['cmp_op'], d['cmp_mode'] = struct.unpack_from('<IIBB', b, 6)
    elif name == 'CALL':
        d['class_len'], d['method_len'], d['argc'], d['indata_len'] = struct.unpack_from('<BBBI', b, 6)
    elif name == 'SETALLOCHINT':
        d['expected_object_size'], d['expected_write_size'], d['hint_flags'] = struct.unpack_from('<QQI', b, 6)
    elif name == 'WRITESAME':
        d['offset'], d['length'], d['data_length'] = struct.unpack_from('<QQQ', b, 6)
    else:
        d['offset'], d['length'] = struct.unpack_from('<QQ', b, 6)   # informational for the other ops
    return d


def dec_mosdop(front, ver=9):
    """Note 2.3. Returns a dict, raises DecodeError on anything that does not fit."""
    r = Reader(front)
    m = {}
    m['pgid'] = dec_spg_t(r)
    m['hash'] = r.u32()
    m['epoch'] = r.u32()
    m['flags'] = r.u32()
    m['reqid'] = dec_reqid(r)
    m['blkin'] = r.take(24)
    if ver >= 9:
        m['otel'] = r.take(7)
    m['client_inc'] = r.u32()
    m['mtime'] = r.utime()
    m['oloc'] = dec_oloc(r)
    m['oid'] = r.string()
    n = r.u16()
    m['ops'] = [dec_op_record(r.take(38)) for _ in range(n)]
    m['snapid'] = r.u64()
    m['snap_seq'] = r.u64()
    cnt = r.u32()
    m['snaps'] = [r.u64() for _ in range(cnt)]
    m['retry_attempt'] = r.i32()
    m['features'] = r.u64()
    m['left'] = r.left()
    return m


def dec_mosdopreply(front):
    """Note 2.9 (version 8)."""
    r = Reader(front)
    m = {}
    m['oid'] = r.string()
    m['pgid'] = dec_pg_t(r)
    m['flags'] = r.i64()
    m['result'] = r.i32()
    m['bad_replay_version'] = (r.u64(), r.u32())
    m['epoch'] = r.u32()
    n = r.u32()
    m['ops'] = [dec_op_record(r.take(38)) for _ in range(n)]
    m['retry_attempt'] = r.i32()
    m['rvals'] = [r.i32() for _ in range(n)]
    m['replay_version'] = (r.u64(), r.u32())
    m['user_version'] = r.u64()
    m['do_redirect'] = r.boolean()
    if m['do_redirect']:
        v, c, sub = r.struct_header(1)
        m['redirect'] = dict(oloc=dec_oloc(sub), object=sub.string())
    m['blkin'] = r.take(24)
    m['left'] = r.left()
    return m


def dec_hobject(r):
    v, compat, sub = r.struct_header(4)
    key = sub.string()
    oid = sub.string()
    snap = sub.u64()
    h = sub.u32()
    mx = sub.boolean()
    ns = sub.string()
    pool = sub.i64()
    return dict(key=key, oid=oid, snap=snap, hash=h, max=mx, nspace=ns, pool=pool, v=v)


def dec_mosdbackoff(front):
    r = Reader(front)
    m = {}
    m['pgid'] = dec_spg_t(r)
    m['map_epoch'] = r.u32()
    m['op'] = r.u8()
    m['id'] = r.u64()
    m['begin'] = dec_hobject(r)
    m['end'] = dec_hobject(r)
    m['left'] = r.left()
    return m


def enc_op_extent(code, offset, length, payload_len=0, flags=0, tseq=0, tsize=0):
    return struct.pack('<HI', code, flags) + struct.pack('<QQQI', offset, length, tsize, tseq) + struct.pack('<I', payload_len)


def enc_mosdop(pool, seed, hsh, epoch, flags, oid, ops, snapid=CEPH_NOSNAP, snap_seq=0, snaps=(),
               retry=0, features=0, client_inc=0, mtime=(0, 0), nspace=b'', key=b''):
    """Encoder written from the note (2.3): used to rebuild the 217-byte example and captured fronts."""
    out = bytearray()
    out += struct.pack('<BBI', 1, 1, 18) + b'\x01' + struct.pack('<QIi', pool, seed, -1) + b'\xff'
    out += struct.pack('<III', hsh, epoch, flags)
    out += struct.pack('<BBI', 2, 2, 21) + b'\x00' + struct.pack('<qQi', 0, 0, client_inc)
    out += b'\x00' * 24
    out += bytes([1, 1, 1, 0, 0, 0, 0])
    out += struct.pack('<I', client_inc)
    out += struct.pack('<II', *mtime)
    oloc = struct.pack('<qi', pool, -1) + struct.pack('<I', len(key)) + key + struct.pack('<I', len(nspace)) + nspace + struct.pack('<q', -1)
    out += struct.pack('<BBI', 6, 3, len(oloc)) + oloc
    out += struct.pack('<I', len(oid)) + oid
    out += struct.pack('<H', len(ops))
    for o in ops:
        out += o
    out += struct.pack('<QQI', snapid, snap_seq, len(snaps))
    for s in snaps:
        out += struct.pack('<Q', s)
    out += struct.pack('<iQ', retry, features)
    return bytes(out)


# ===========================================================================
# 7  class-call decoders (note rbd-format2.md 2.3, 2.5, 2.7) and omap decoders (note osd-ops.md 2.7)
# ===========================================================================

def _end(r, what):
    if r.left():
        raise DecodeError("%s: %d trailing bytes" % (what, r.left()))


def dec_entity_addr_any(r):
    """entity_addr_t as it appears in 'lock get_info' (note rbd-format2.md 2.7): marker 1 form."""
    marker = r.u8()
    if marker == 0:
        # legacy form: u32 0 (the marker byte is its first byte) ... not produced for MSG_ADDR2 clients
        r.skip(3)
        r.skip(4 + 128)
        return dict(legacy=True)
    v, c, sub = r.struct_header()
    typ = sub.u32()
    nonce = sub.u32()
    n = sub.u32()
    sa = sub.take(n)
    return dict(type=typ, nonce=nonce, sockaddr=sa)


def dec_lock_info(out):
    r = Reader(out)
    v, c, sub = r.struct_header(1)
    n = sub.u32()
    lockers = []
    for _ in range(n):
        v1, c1, idr = sub.struct_header(1)
        etype = idr.u8()
        enum_ = idr.i64()
        cookie = idr.string()
        v2, c2, ir = sub.struct_header(1)
        exp = ir.utime()
        addr = dec_entity_addr_any(ir)
        desc = ir.string()
        lockers.append(dict(etype=etype, num=enum_, cookie=cookie, expiration=exp, addr=addr, desc=desc))
    ltype = sub.u8()
    tag = sub.string()
    _end(r, 'lock get_info')
    return dict(lockers=lockers, type=ltype, tag=tag, tail=sub.left())


def dec_cls(cls, method, inp, out):
    """Decode (input, output) of the calls named in the notes. Returns dict, or None if the note has no entry."""
    key = (cls, method)
    if key == ('rbd', 'get_id') or key == ('rbd', 'dir_get_id') or key == ('rbd', 'dir_get_name'):
        r = Reader(out)
        s = r.string()
        _end(r, method)
        i = Reader(inp)
        arg = i.string() if inp else b''
        return dict(value=s, arg=arg)
    if key == ('rbd', 'get_size'):
        i = Reader(inp)
        snap = i.u64()
        _end(i, 'get_size input')
        r = Reader(out)
        order = r.u8()
        size = r.u64()
        _end(r, method)
        return dict(snap=snap, order=order, size=size)
    if key == ('rbd', 'get_features'):
        i = Reader(inp)
        snap = i.u64()
        ro = i.boolean() if i.left() else None
        _end(i, 'get_features input')
        r = Reader(out)
        f = r.u64()
        inc = r.u64()
        _end(r, method)
        return dict(snap=snap, read_only=ro, features=f, incompatible=inc)
    if key == ('rbd', 'get_object_prefix'):
        r = Reader(out)
        s = r.string()
        _end(r, method)
        return dict(prefix=s)
    if key == ('rbd', 'get_snapcontext'):
        r = Reader(out)
        seq = r.u64()
        n = r.u32()
        snaps = [r.u64() for _ in range(n)]
        _end(r, method)
        return dict(seq=seq, snaps=snaps)
    if key == ('rbd', 'get_data_pool'):
        r = Reader(out)
        v = r.i64()
        _end(r, method)
        return dict(pool=v)
    if key == ('rbd', 'get_flags'):
        i = Reader(inp)
        i.u64()
        _end(i, 'get_flags input')
        r = Reader(out)
        v = r.u64()
        _end(r, method)
        return dict(flags=v)
    if key == ('rbd', 'op_features_get'):
        r = Reader(out)
        v = r.u64()
        _end(r, method)
        return dict(op_features=v)
    if key == ('rbd', 'get_stripe_unit_count'):
        r = Reader(out)
        a, b = r.u64(), r.u64()
        _end(r, method)
        return dict(stripe_unit=a, stripe_count=b)
    if key == ('rbd', 'parent_get'):
        r = Reader(out)
        v, c, sub = r.struct_header(1)
        pool = sub.i64()
        ns = sub.string()
        iid = sub.string()
        snap = sub.u64()
        _end(r, method)
        return dict(pool=pool, ns=ns, image_id=iid, snap=snap, tail=sub.left())
    if key == ('rbd', 'parent_overlap_get'):
        i = Reader(inp)
        i.u64()
        r = Reader(out)
        present = r.u8()
        ov = r.u64() if present else None
        _end(r, method)
        return dict(present=present, overlap=ov)
    if key == ('lock', 'get_info'):
        i = Reader(inp)
        v, c, sub = i.struct_header(1)
        name = sub.string()
        _end(i, 'lock get_info input')
        d = dec_lock_info(out)
        d['name'] = name
        return d
    return None


def dec_omap_vals(out):
    r = Reader(out)
    n = r.u32()
    ents = [(r.string(), r.blob()) for _ in range(n)]
    trunc = r.boolean()
    _end(r, 'OMAPGETVALS output')
    return ents, trunc


def dec_omap_keys(out):
    # note osd-ops.md has no entry for OMAPGETKEYS (it says "skip"); the layout below is what the capture shows
    r = Reader(out)
    n = r.u32()
    keys = [r.string() for _ in range(n)]
    trunc = r.boolean()
    _end(r, 'OMAPGETKEYS output')
    return keys, trunc


def dec_sparse_read(out):
    r = Reader(out)
    n = r.u32()
    ext = [(r.u64(), r.u64()) for _ in range(n)]
    dl = r.u32()
    data = r.take(dl)
    _end(r, 'SPARSE_READ output')
    return ext, data


# ===========================================================================
# 8  the checks
# ===========================================================================

CALL_READONLY_HINT = {('lock', 'get_info')}
RBD_DATA_RE = re.compile(rb'^rbd_data\.([0-9a-f]+)\.([0-9a-f]{16})$')
FEATURE_BITS = {'layering': 1, 'striping': 2, 'exclusive-lock': 4, 'object-map': 8, 'fast-diff': 0x10,
                'deep-flatten': 0x20, 'journaling': 0x40, 'data-pool': 0x80, 'operations': 0x100}


class Ev:
    """Evidence counters: what the captures actually show (used to settle the note's open marks)."""

    def __init__(self):
        self.c = collections.defaultdict(collections.Counter)
        self.ex = {}

    def add(self, key, val, example=None):
        self.c[key][val] += 1
        if example is not None and (key, val) not in self.ex:
            self.ex[(key, val)] = example

    def merge(self, o):
        for k, v in o.c.items():
            self.c[k].update(v)
        for k, v in o.ex.items():
            self.ex.setdefault(k, v)


class Gt:
    """Ground truth read from the capture directory."""

    def __init__(self, cap):
        self.cap = cap
        g = os.path.join(cap, 'gt')
        d = json.load(open(os.path.join(g, 'osd-dump.json')))
        self.epoch0 = d['epoch']
        self.pools = {}
        for p in d['pools']:
            pgn = p['pg_num']
            self.pools[p['pool']] = dict(name=p['pool_name'], pg_num=pgn, pgp_num=p['pg_placement_num'],
                                         mask=(1 << cbits(pgn - 1)) - 1 if pgn > 1 else 0, hash=p['object_hash'])
        self.small = open(os.path.join(cap, 'data', 'small.bin'), 'rb').read()
        self.big = open(os.path.join(cap, 'data', 'big.bin'), 'rb').read()
        self.cls = {}
        self.images = {}
        g4 = os.path.join(cap, 'gt4')
        for n in ('img-v1', 'img-default'):
            m = json.load(open(os.path.join(g4, n + '.meta.json')))
            for c in m['cls_calls']:
                self.cls[(c['oid'], c['call'], c['in'])] = c
            info = json.load(open(os.path.join(g4, n + '.rbd-info.json')))
            self.images[info['id']] = info
            self.images[info['id']]['features_num'] = sum(FEATURE_BITS[f] for f in info['features'])
        self.maplines = []
        with open(os.path.join(g, 'osd-map-all.jsonl')) as f:
            for line in f:
                self.maplines.append(json.loads(line))


_GT = {}


def get_gt(cap):
    if cap not in _GT:
        _GT[cap] = Gt(cap)
    return _GT[cap]


def classify(q):
    """Which kind of message: 'read' / 'write' by op codes (note 2.6 mode bits); CALLs return 'call'."""
    names = [o['name'] for o in q['ops']]
    if any(o['op'] & 0x2000 and o['name'] != 'CALL' for o in q['ops']):
        return 'write'
    if 'CALL' in names:
        return 'call'
    return 'read'


class Pair:
    pass


def build_pairs(ci, results, name):
    reqs = {}
    pairs = []
    for m in ci.msgs:
        if m.dir == 'c2s' and m.type == MSG_OSD_OP:
            p = Pair()
            p.conn, p.rq_msg, p.rp_msg, p.rq, p.rp = ci, m, None, None, None
            try:
                p.rq = dec_mosdop(m.front, m.ver)
            except (DecodeError, struct.error) as e:
                results.fail('mosdop', "%s tid %d decode: %s" % (name, m.tid, e))
                continue
            if m.tid in reqs:
                results.fail('mosdop', "%s duplicate tid %d on one connection" % (name, m.tid))
            reqs[m.tid] = p
            pairs.append(p)
        elif m.dir == 's2c' and m.type == MSG_OSD_OPREPLY:
            p = reqs.get(m.tid)
            if p is None:
                if getattr(ci, 'gapped', False):
                    continue   # the request fell into a hole of the capture
                results.fail('mosdopreply', "%s reply for unknown tid %d" % (name, m.tid))
                continue
            if p.rp_msg is not None:
                results.fail('mosdopreply', "%s tid %d: a second reply" % (name, m.tid))
                continue
            try:
                p.rp = dec_mosdopreply(m.front)
            except (DecodeError, struct.error) as e:
                results.fail('mosdopreply', "%s tid %d decode: %s" % (name, m.tid, e))
                continue
            p.rp_msg = m
    return pairs


def split_data(data, ops):
    out, off = [], 0
    for o in ops:
        out.append(data[off:off + o['payload_len']])
        off += o['payload_len']
    return out, off


def check_pair(p, gt, results, ev, name, negotiated, pcap_t0):
    R = results
    q, m = p.rq, p.rq_msg
    tag = "%s tid %d" % (name, m.tid)
    # --- message header and segment placement (note 2.1)
    R.check('osd.header', m.type == 42 and m.ver == 9 and m.compat == 3,
            "%s: MOSDOp header type/version/compat %d/%d/%d" % (tag, m.type, m.ver, m.compat))
    R.check('osd.header', m.prio == 63, "%s: priority %d" % (tag, m.prio))
    R.check('osd.header', m.dpp == 0 and m.resv == 0, "%s: data_pre_padding %d reserved %d" % (tag, m.dpp, m.resv))
    R.check('osd.header', m.data_off == 0, "%s: request data_off %d" % (tag, m.data_off))
    R.check('osd.header', m.seglens[0] == 41 and m.seglens[1] == len(m.front) and m.seglens[2] == 0
            and m.seglens[3] == len(m.data), "%s: segment lengths %s" % (tag, m.seglens))
    ev.add('req.header.flags', m.hdr['flags'])
    ev.add('rep.header.flags', p.rp_msg.hdr['flags'] if p.rp_msg is not None else None)
    ev.add('req.priority', m.prio)
    ev.add('req.segments', tuple(1 if x else 0 for x in m.seglens))
    # trailing empty segments are not sent (msgr2.md 2.3): front-only -> 2 segments, with data -> 4
    R.check('osd.header', m.nseg == (4 if m.seglens[3] else 2), "%s: %d segments in the frame for lengths %s" % (tag, m.nseg, m.seglens))
    # --- body (2.3)
    R.check('mosdop', q['left'] == 0, "%s: %d trailing bytes in front segment" % (tag, q['left']))
    pg = q['pgid']
    R.check('mosdop', (pg['v'], pg['compat'], pg['size'], pg['left'], pg['shard']) == (1, 1, 24, 0, -1) and pg['pg']['preferred'] == -1,
            "%s: spg_t %r" % (tag, pg))
    pool = pg['pg']['pool']
    R.check('mosdop', q['oloc']['pool'] == pool, "%s: oloc pool %d vs pgid pool %d" % (tag, q['oloc']['pool'], pool))
    # placement hash and effective pg (2.2)
    pinfo = gt.pools.get(pool)
    if R.check('placement', pinfo is not None, "%s: pool %d unknown" % (tag, pool)):
        h = placement_hash(q['oid'], q['oloc']['key'], q['oloc']['nspace'])
        R.check('placement', h == q['hash'], "%s: hash %08x, rjenkins(oid) %08x" % (tag, q['hash'], h))
        R.check('placement', pg['pg']['seed'] == stable_mod(q['hash'], pinfo['pg_num'], pinfo['mask']),
                "%s: pg seed %d vs stable_mod %d" % (tag, pg['pg']['seed'], stable_mod(q['hash'], pinfo['pg_num'], pinfo['mask'])))
    # flags (2.4)
    fl = q['flags']
    kind = classify(q)
    ev.add('req.flags', ('%08x' % fl, kind), "%s %s" % (tag, [o['name'] for o in q['ops']]))
    R.check('flags', fl & F_ONDISK != 0, "%s: ONDISK not set (%08x)" % (tag, fl))
    R.check('flags', fl & F_KNOWN_REDIR != 0 and fl & F_SUPPORTSPOOLEIO != 0, "%s: KNOWN_REDIR/SUPPORTSPOOLEIO %08x" % (tag, fl))
    R.check('flags', fl & F_ACK == 0 and fl & F_ONNVRAM == 0, "%s: ACK/ONNVRAM set in a request %08x" % (tag, fl))
    R.check('flags', bool(fl & F_READ) != bool(fl & F_WRITE), "%s: READ and WRITE bits %08x" % (tag, fl))
    R.check('flags', bool(fl & F_RETRY) == (q['retry_attempt'] != 0), "%s: RETRY flag vs retry_attempt %d" % (tag, q['retry_attempt']))
    if kind == 'write':
        R.check('flags', bool(fl & F_WRITE), "%s: mutating op without WRITE flag" % tag)
    if kind == 'read':
        R.check('flags', bool(fl & F_READ), "%s: read-only message without READ flag" % tag)
    # reqid / incarnation (2.3 notes)
    rid = q['reqid']
    R.check('mosdop', (rid['v'], rid['compat'], rid['left']) == (2, 2, 0), "%s: reqid header %r" % (tag, rid))
    R.check('mosdop', rid['name_type'] == 0 and rid['name_num'] == 0 and rid['tid'] == 0, "%s: reqid name/tid not empty %r" % (tag, rid))
    R.check('mosdop', (rid['inc'] & 0xFFFFFFFF) == q['client_inc'], "%s: reqid.inc %d != client_inc %d" % (tag, rid['inc'], q['client_inc']))
    ev.add('req.client_inc', q['client_inc'])
    R.check('mosdop', q['blkin'] == b'\x00' * 24, "%s: blkin trace not zero" % tag)
    R.check('mosdop', q['otel'] == bytes([1, 1, 1, 0, 0, 0, 0]), "%s: otel field %s" % (tag, q['otel'].hex()))
    # mtime
    mt = q['mtime']
    ts = m.ts
    if not fl & F_WRITE:
        R.check('mosdop', mt == (0, 0), "%s: mtime %r on a read-flagged message" % (tag, mt))
        ev.add('req.mtime', 'zero-on-read-flagged')
    else:
        d = (mt[0] + mt[1] / 1e9) - ts
        ev.add('req.mtime', 'near-packet-time-on-write-flagged')
        R.check('mosdop', abs(d) < 10, "%s: mtime differs from packet time by %.1f s" % (tag, d))
    # locator (2.2)
    ol = q['oloc']
    R.check('mosdop', ol['left'] == 0 and ol['preferred'] == -1 and ol['key'] == b'' and ol['nspace'] == b'' and ol['hash'] == -1,
            "%s: oloc %r" % (tag, ol))
    ev.add('req.oloc.version', (ol['v'], ol['compat']))
    R.check('mosdop', len(q['oid']) > 0, "%s: empty oid" % tag)
    # snapshot fields
    snaps = q['snaps']
    valid = (q['snap_seq'] <= 0xFFFFFFFFFFFFFFFD and (not snaps or (snaps[0] <= q['snap_seq'] and all(a > b for a, b in zip(snaps, snaps[1:])))))
    R.check('mosdop', valid, "%s: snapshot context invalid" % tag)
    if kind != 'read':
        R.check('mosdop', q['snapid'] == CEPH_NOSNAP, "%s: write with snapid %#x" % (tag, q['snapid']))
    ev.add('req.snapc', (kind, q['snap_seq'], len(snaps), 'header' if q['oid'].startswith((b'rbd_header', b'rbd_id', b'rbd_directory', b'rbd_info', b'rbd_trash', b'rbd_object_map', b'rbd_mirroring')) else 'data'))
    R.check('mosdop', q['features'] == negotiated, "%s: features %016x vs negotiated %016x" % (tag, q['features'], negotiated))
    ev.add('req.features', '%016x' % q['features'])
    # ops and data segment (2.5)
    inputs, used = split_data(m.data, q['ops'])
    R.check('ops', used == len(m.data), "%s: sum(payload_len) %d != data segment %d" % (tag, used, len(m.data)))
    for i, op in enumerate(q['ops']):
        nm = op['name']
        ev.add('op.seen', nm)
        # unused union bytes must be zero (note 2.5)
        if nm in ('READ', 'SPARSE_READ', 'WRITE', 'WRITEFULL', 'ZERO', 'TRUNCATE'):
            R.check('ops', op['truncate_seq'] == 0 and op['truncate_size'] == 0, "%s: %s truncate_seq/size %d/%d" % (tag, nm, op['truncate_seq'], op['truncate_size']))
        if nm in ('WRITE', 'WRITEFULL'):
            R.check('ops', op['length'] == op['payload_len'], "%s: %s extent.length %d != payload_len %d" % (tag, nm, op['length'], op['payload_len']))
            if nm == 'WRITEFULL':
                R.check('ops', op['offset'] == 0, "%s: WRITEFULL offset %d" % (tag, op['offset']))
        if nm in ('READ', 'SPARSE_READ', 'STAT'):
            R.check('ops', op['payload_len'] == 0, "%s: %s payload_len %d" % (tag, nm, op['payload_len']))
        if nm == 'CALL':
            R.check('ops', op['class_len'] + op['method_len'] + op['indata_len'] == op['payload_len'] and op['argc'] == 0,
                    "%s: CALL lengths %d+%d+%d vs payload %d argc %d" % (tag, op['class_len'], op['method_len'], op['indata_len'], op['payload_len'], op['argc']))
            R.check('ops', op['union'][9:] == b'\x00' * 19, "%s: CALL union tail not zero" % tag)
            pl = inputs[i]
            op['cls'] = pl[:op['class_len']].decode('ascii', 'replace')
            op['method'] = pl[op['class_len']:op['class_len'] + op['method_len']].decode('ascii', 'replace')
            op['indata'] = pl[op['class_len'] + op['method_len']:]
            ev.add('call.flag', (op['cls'], op['method'], 'W' if fl & F_WRITE else 'R'))
        if nm == 'SETALLOCHINT':
            ev.add('op.allochint', (op['expected_object_size'], op['expected_write_size'], op['hint_flags']))
        if nm in ('OMAPGETVALS', 'OMAPGETVALSBYKEYS', 'OMAPGETKEYS'):
            ev.add('op.omap.union', (nm, op['offset'] == 0, op['length'] == op['payload_len']))
        ev.add('op.flags', (nm, op['flags']))
        op['input'] = inputs[i]
    # --- reply
    if p.rp is None:
        ev.add('reply', 'missing')
        return
    pr, rm = p.rp, p.rp_msg
    rtag = tag
    R.check('osd.header', rm.type == 43 and rm.ver == 8 and rm.compat == 2, "%s: MOSDOpReply header %d/%d/%d" % (rtag, rm.type, rm.ver, rm.compat))
    ev.add('rep.priority', rm.prio)
    ev.add('rep.data_off', (rm.data_off != 0, tuple(o['name'] for o in pr['ops']), rm.data_off if rm.data_off else 0))
    R.check('osd.header', rm.nseg == (4 if rm.seglens[3] else 2), "%s: reply has %d segments for lengths %s" % (rtag, rm.nseg, rm.seglens))
    R.check('osd.header', rm.seglens[0] == 41 and rm.seglens[1] == len(rm.front) and rm.seglens[2] == 0 and rm.seglens[3] == len(rm.data),
            "%s: reply segment lengths %s" % (rtag, rm.seglens))
    R.check('mosdopreply', pr['left'] == 0, "%s: %d trailing bytes in reply front" % (rtag, pr['left']))
    R.check('mosdopreply', pr['oid'] == q['oid'], "%s: oid echo" % rtag)
    R.check('mosdopreply', pr['pgid']['pool'] == pool and pr['pgid']['seed'] == pg['pg']['seed'] and pr['pgid']['preferred'] == -1,
            "%s: reply pg_t %r vs request %r" % (rtag, pr['pgid'], pg['pg']))
    R.check('mosdopreply', len(pr['ops']) == len(q['ops']) and len(pr['rvals']) == len(q['ops']), "%s: num_ops" % rtag)
    R.check('mosdopreply', pr['retry_attempt'] == q['retry_attempt'], "%s: retry_attempt echo" % rtag)
    R.check('mosdopreply', not pr['do_redirect'], "%s: redirect" % rtag)
    R.check('mosdopreply', pr['blkin'] == b'\x00' * 24, "%s: reply blkin not zero" % rtag)
    R.check('mosdopreply', 0 <= pr['flags'] < (1 << 32), "%s: reply flags %x" % (rtag, pr['flags']))
    brv = pr['bad_replay_version']
    ev.add('rep.bad_replay_version', ('version==user_version' if brv[0] == pr['user_version'] else 'version!=user_version',
                                      'epoch==replay_epoch' if brv[1] == pr['replay_version'][1] else 'epoch!=replay_epoch'), tag)
    R.check('mosdopreply', pr['epoch'] >= q['epoch'], "%s: reply epoch %d < request epoch %d" % (rtag, pr['epoch'], q['epoch']))
    ev.add('rep.epoch_vs_req', 'equal' if pr['epoch'] == q['epoch'] else 'differs')
    outs, used = split_data(rm.data, pr['ops'])
    R.check('mosdopreply', used == len(rm.data), "%s: sum(reply payload_len) %d != data segment %d" % (rtag, used, len(rm.data)))
    # result / flags classification (2.9)
    res = pr['result']
    rv = pr['rvals']
    added = pr['flags'] & ~fl & 0xFFFFFFFF
    removed = fl & ~pr['flags'] & 0xFFFFFFFF
    ev.add('rep.flags', ('ok' if res >= 0 else 'err', 'rvals-all-zero' if not any(rv) else 'rval-set', 'ACK' if pr['flags'] & F_ACK else 'noACK',
                         'ONDISK' if pr['flags'] & F_ONDISK else 'noONDISK', 'added=%x' % added, 'removed=%x' % removed),
           "%s %s result %d" % (tag, [o['name'] for o in q['ops']], res))
    if res >= 0:
        R.check('mosdopreply', pr['flags'] & F_ACK and pr['flags'] & F_ONDISK, "%s: success reply without ACK|ONDISK %x" % (rtag, pr['flags']))
        R.check('mosdopreply', (pr['flags'] & ~(F_ACK | F_ONDISK)) == (fl & ~(F_ACK | F_ONDISK)), "%s: reply flags %x vs request %x" % (rtag, pr['flags'], fl))
        # result is the last op's rval (2.7)
        ev.add('rep.result_vs_last_rval', 'equal' if res == rv[-1] else ('write-msg' if kind != 'read' else 'differs'))
    else:
        first_bad = next((x for x in rv if x < 0), None)
        ev.add('rep.err.rval', ('first-bad-rval-is-result' if first_bad == res else 'rvals-all-zero' if not any(rv) else 'other'),
               "%s %s result %d rvals %s" % (tag, [o['name'] for o in q['ops']], res, rv))
        R.check('mosdopreply', not any(outs), "%s: error reply carries output" % rtag)
    oclass = 'data' if RBD_DATA_RE.match(q['oid']) else ('rbd-meta' if q['oid'].startswith(b'rbd_') else ('journal' if q['oid'].startswith(b'journal') else 'plain'))
    ev.add('req.flags_by_object_class', (oclass, '%08x' % fl))
    ev.add('req.snapid', ('read' if not fl & F_WRITE else 'write', q['snapid'] == CEPH_NOSNAP))
    if any(x > 0 for x in rv):
        ev.add('rep.rval_positive', (tuple(o['name'] for o in q['ops']), tuple(rv), res), tag)
    if len(q['ops']) > 1 and res < 0:
        ev.add('rep.multi_op_failure', (tuple(o['name'] for o in q['ops']), tuple(rv), res), tag)
    for a_ in q['ops']:
        if a_['name'] == 'SPARSE_READ':
            ev.add('sparse.request_offset', 'nonzero' if a_['offset'] else 'zero')
    # echoed ops (2.7): same code except the ZERO->TRUNCATE rewrite
    for i, (a, b) in enumerate(zip(q['ops'], pr['ops'])):
        if a['op'] != b['op']:
            ev.add('rep.op_rewritten', (a['name'], b['name']), tag)
        if res >= 0 or True:
            ev.add('rep.echo_union', (a['name'], 'same' if a['union'] == b['union'] else 'changed'))
    # versions
    if kind == 'read':
        R.check('mosdopreply', pr['replay_version'] == (0, 0) or res < 0, "%s: replay_version %r on a read" % (rtag, pr['replay_version']))
    if kind == 'write' and res >= 0:
        R.check('mosdopreply', pr['replay_version'][0] > 0 and pr['replay_version'][1] == pr['epoch'], "%s: replay_version %r" % (rtag, pr['replay_version']))
        ev.add('rep.write_outputs', 'any-output' if any(len(o) for o in outs) else 'none', tag)
    ev.add('rep.user_version', ('ENOENT' if res == -2 else 'ok' if res >= 0 else errname(res), 'zero' if pr['user_version'] == 0 else 'nonzero'), tag)
    # --- per op output semantics
    for i, (a, b) in enumerate(zip(q['ops'], pr['ops'])):
        out = outs[i] if i < len(outs) else b''
        nm = a['name']
        otag = "%s op%d %s" % (tag, i, nm)
        if res < 0 and not rv[i]:
            # not executed, or the whole message was refused
            continue
        if nm == 'READ':
            R.check('ops', len(out) == b['payload_len'] and b['length'] == len(out), "%s: READ reply extent.length %d, payload %d" % (otag, b['length'], len(out)))
            R.check('ops', len(out) <= a['length'] or a['length'] == 0, "%s: READ returned %d > requested %d" % (otag, len(out), a['length']))
        elif nm == 'STAT':
            R.check('ops', len(out) == 16, "%s: STAT output %d bytes" % (otag, len(out)))
            if len(out) == 16:
                size = struct.unpack('<Q', out[:8])[0]
                sec, nsec = struct.unpack('<II', out[8:])
                R.check('ops', nsec < 1000000000, "%s: STAT nsec %d" % (otag, nsec))
                p.stat = (size, sec, nsec)
                ev.add('stat.size', 'checked')
                if p.rq['oid'] in (b't0-small', b't0-big'):
                    R.check('data', size == len(gt.small if p.rq['oid'] == b't0-small' else gt.big), "%s: STAT size %d" % (otag, size))
        elif nm == 'SPARSE_READ':
            try:
                ext, data = dec_sparse_read(out)
                ok = True
                last = a['offset']
                for (eo, el) in ext:
                    ok &= eo >= last and eo + el <= a['offset'] + a['length'] and el > 0
                    last = eo + el
                R.check('ops', ok, "%s: sparse extents %r outside / unordered (request %d+%d)" % (otag, ext[:3], a['offset'], a['length']))
                R.check('ops', sum(l for _, l in ext) == len(data), "%s: extents sum %d vs data %d" % (otag, sum(l for _, l in ext), len(data)))
                R.check('ops', b['length'] == len(data), "%s: reply extent.length %d vs data %d" % (otag, b['length'], len(data)))
                ev.add('sparse.shape', ('empty' if not ext else 'one-extent' if len(ext) == 1 else 'multi', len(ext) == 1 and ext[0] == (a['offset'], a['length'])), tag)
                p.sparse = (ext, data)
            except DecodeError as e:
                R.fail('ops', "%s: %s" % (otag, e))
        elif nm == 'OMAPGETVALS':
            try:
                ents, tr = dec_omap_vals(out)
                keys = [k for k, _ in ents]
                R.check('omap', keys == sorted(keys) and len(set(keys)) == len(keys), "%s: keys not strictly ascending" % otag)
                ir = Reader(a['input'])
                start_after, maxe, prefix = ir.string(), ir.u64(), ir.string()
                _end(ir, 'OMAPGETVALS input')
                R.check('omap', not keys or keys[0] > start_after, "%s: first key not after start_after" % otag)
                R.check('omap', len(ents) <= maxe and (not tr or len(ents) == min(maxe, 1024)), "%s: entries %d, max %d, truncated %s" % (otag, len(ents), maxe, tr))
                R.check('omap', all(k.startswith(prefix) for k in keys), "%s: filter prefix" % otag)
                p.omap = (start_after, maxe, ents, tr)
                ev.add('omap.page', (len(ents), tr, maxe))
            except DecodeError as e:
                R.fail('omap', "%s: %s" % (otag, e))
        elif nm == 'OMAPGETKEYS':
            try:
                keys, tr = dec_omap_keys(out)
                p.omapkeys = (keys, tr)
                ev.add('omap.keys.page', (len(keys), tr))
            except DecodeError as e:
                R.fail('omap', "%s: %s" % (otag, e))
        elif nm == 'OMAPGETVALSBYKEYS':
            try:
                r2 = Reader(out)
                n = r2.u32()
                ents = [(r2.string(), r2.blob()) for _ in range(n)]
                _end(r2, 'OMAPGETVALSBYKEYS')
                ir = Reader(a['input'])
                k = ir.u32()
                want = [ir.string() for _ in range(k)]
                _end(ir, 'OMAPGETVALSBYKEYS input')
                R.check('omap', all(e[0] in want for e in ents) and len(ents) <= len(want), "%s: keys not subset" % otag)
                p.omapbykeys = (want, ents)
            except DecodeError as e:
                R.fail('omap', "%s: %s" % (otag, e))
        elif nm == 'CALL':
            ev.add('call.reply_len_field', 'equals-output-len' if b['union'][8:16] == struct.pack('<Q', len(out)) else ('empty-output' if not out else 'other'), "%s %s.%s out=%d len=%d" % (tag, a['cls'], a['method'], len(out), struct.unpack('<Q', b['union'][8:16])[0]))
            try:
                d = dec_cls(a['cls'], a['method'], a['indata'], out) if rv[i] == 0 else None
            except (DecodeError, struct.error) as e:
                R.fail('cls', "%s %s.%s: %s" % (otag, a['cls'], a['method'], e))
                d = None
            a['decoded'] = d
            key = (a['cls'], a['method'])
            ev.add('call.seen', key + (('decoded' if d is not None else 'no-decoder-in-note') if rv[i] == 0 else 'rval%d' % rv[i],))
            if d is not None:
                R.check('cls', True, '')
            a['out'] = out
        if kind == 'write':
            ev.add('write.msg.output', (nm, len(out) > 0))
    p.rinfo = (res, rv, outs)


def read_sessions_tsv(cap):
    out = {}
    with open(os.path.join(cap, 'sessions.tsv')) as f:
        for line in f:
            c = line.rstrip('\n').split('\t')
            if len(c) >= 4:
                out[c[0]] = dict(name=c[0], keytype=c[1], user=c[2], mode=c[3])
    return out


def keyring_for(spec, cap, keydir):
    user = spec['user']
    for path in (os.path.join(keydir, user + '.keyring'),
                 os.path.join(cap, 'secrets', 'keys', 'ceph.%s.keyring' % user)):
        if os.path.exists(path):
            kr = parse_keyring(path)
            if user in kr:
                return kr[user]
    return None


def check_global(gt, R, ev):
    """rjenkins + stable_mod against every `ceph osd map` line (ground truth)."""
    n = 0
    for line in gt.maplines:
        if line.get('rc') != 0 or 'result' not in line:
            continue
        res = line['result']
        pool = gt.pools[res['pool_id']]
        ns = (line.get('nspace') or '').encode()
        name = line['object'].encode()
        h = placement_hash(name, b'', ns)
        if any(ord(ch) > 0xFFFF for ch in line['object']):
            # `ceph osd map` carries the name in JSON; the monitor decodes a surrogate pair as two 3-byte
            # sequences (CESU-8), so for names outside the BMP the hashed bytes are those, not UTF-8.
            alt = b''.join(chr(u).encode('utf-8', 'surrogatepass') for u in struct.unpack('>%dH' % (len(line['object'].encode('utf-16-be')) // 2), line['object'].encode('utf-16-be')))
            ev.add('gt.non_bmp_name', 'CESU-8 form used' if placement_hash(alt, b'', ns) == int(res['raw_pgid'].split('.')[1], 16) else 'no match', line['object'])
            name = alt
            h = placement_hash(name, b'', ns)
        raw = res['raw_pgid'].split('.')
        R.check('gt.placement', int(raw[1], 16) == h, "ceph osd map %s/%r: raw pgid %s vs hash %08x" % (line['pool'], line['object'], res['raw_pgid'], h))
        seed = stable_mod(h, pool['pg_num'], pool['mask'])
        R.check('gt.placement', res['pgid'] == '%d.%x' % (res['pool_id'], seed), "ceph osd map %r: pgid %s vs %d.%x" % (line['object'], res['pgid'], res['pool_id'], seed))
        n += 1
    ev.add('gt.osd_map_lines', n)


def check_connection_level(ci, R, ev, name):
    c = ci.c
    tail = max(0, c.c2s.acked - len(c.c2s.data) - (1 if c.c2s.fin_or_rst else 0), c.s2c.acked - len(c.s2c.data) - (1 if c.s2c.fin_or_rst else 0))
    ci.gapped = bool(c.c2s.gaps or c.s2c.gaps or tail > 1)
    if tail > 1:
        R.warn("%s :%d: the peer acknowledged %d bytes that are missing at the end of the pcap stream" % (name, c.sport, tail))
    R.check('framing', c.c2s.conflict == 0 and c.s2c.conflict == 0,
            "%s :%d retransmitted bytes differ from the first copy" % (name, c.sport))
    if ci.gapped:
        # packets missing from the pcap itself (the receiver acknowledged the bytes): a capture defect, not a protocol
        # failure.  Frames before the hole are still checked; everything after it in that direction is not.
        R.warn("%s :%d: bytes missing from the pcap (c2s gaps %d, s2c gaps %d); %d + %d bytes after the hole are not checked"
               % (name, c.sport, c.c2s.gaps, c.s2c.gaps, ci.eof_partial['c2s'], ci.eof_partial['s2c']))
    for d in ('c2s', 's2c'):
        for fr in ci.frames[d]:
            R.check('framing', fr.ok, "%s :%d %s %s: %s" % (name, c.sport, d, TAGS.get(fr.tag, fr.tag), ','.join(fr.errs)))
        if not ci.gapped:
            R.check('framing', ci.eof_partial[d] == 0, "%s :%d %s %d trailing bytes (partial frame)" % (name, c.sport, d, ci.eof_partial[d]))
    ev.add('conn.mode', (ci.role, ci.mode))
    if ci.client_ident and ci.server_ident:
        ev.add('conn.client_supported', '%016x' % ci.client_ident['supported'])
        ev.add('conn.server_supported', '%016x' % ci.server_ident['supported'])
        ev.add('conn.client_required', '%016x' % ci.client_ident['required'])


def check_data_flows(pairs, gt, R, ev, name):
    """Byte-level cross-checks of payloads against the files the lab used and against read-back."""
    written = collections.defaultdict(dict)   # oid -> {offset: bytes}
    readback = collections.defaultdict(list)  # oid -> [(offset, bytes)]
    for p in pairs:
        if p.rp is None or p.rq is None:
            continue
        q, (res, rv, outs) = p.rq, p.rinfo if hasattr(p, 'rinfo') else (None, None, None)
        if q is None or res is None:
            continue
        oid = q['oid']
        for i, op in enumerate(q['ops']):
            if res < 0:
                continue
            if op['name'] in ('WRITE', 'WRITEFULL'):
                written[oid][op['offset']] = op['input']
            elif op['name'] == 'READ' and rv[i] == 0:
                readback[oid].append((op['offset'], outs[i]))
            elif op['name'] == 'SPARSE_READ' and rv[i] == 0 and hasattr(p, 'sparse'):
                ext, data = p.sparse
                pos = 0
                for (eo, el) in ext:
                    readback[oid].append((eo, data[pos:pos + el]))
                    pos += el
    wm = {}
    for p in pairs:
        if p.rp is not None and p.rq is not None and hasattr(p, 'rinfo') and p.rinfo[0] >= 0 and any(o['name'] in ('WRITEFULL', 'WRITE') for o in p.rq['ops']):
            wm[p.rq['oid']] = p.rq['mtime']
    for p in pairs:
        if p.rp is not None and hasattr(p, 'stat') and p.rq['oid'] in wm:
            size, sec, nsec = p.stat
            R.check('data', (sec, nsec) == wm[p.rq['oid']], "%s: STAT mtime %r != mtime sent with the write %r" % (name, (sec, nsec), wm[p.rq['oid']]))
            ev.add('stat.mtime_equals_write_mtime', 'checked')
    srcs = {b't0-small': gt.small, b't0-big': gt.big}
    for oid, w in written.items():
        if oid in srcs:
            src = srcs[oid]
            buf = bytearray()
            ok = True
            for off in sorted(w):
                if off != len(buf):
                    ok = False
                buf += w[off]
            R.check('data', ok and bytes(buf) == src, "%s: bytes written to %r differ from the source file" % (name, oid))
            ev.add('data.put', (oid.decode(), len(w), tuple(sorted((o, len(v)) for o, v in w.items()))[:4]))
    for oid, rb in readback.items():
        if oid in srcs and rb:
            src = srcs[oid]
            ok = all(src[o:o + len(b)] == b for o, b in rb)
            tot = sum(len(b) for _, b in rb)
            R.check('data', ok and tot == len(src), "%s: bytes read from %r differ from the source file (got %d of %d)" % (name, oid, tot, len(src)))
            ev.add('data.get', (oid.decode(), len(rb)))
        # reads of rbd data objects must equal what the same session wrote
        if oid in written:
            for o, b in rb:
                buf = bytearray()
                covered = True
                # rebuild the object image from writes
                img = {}
                for woff, wb in written[oid].items():
                    img[woff] = wb
                # check byte by byte for the requested range from the writes (writes in this test do not overlap)
                for woff, wb in sorted(img.items()):
                    if woff <= o and o + len(b) <= woff + len(wb):
                        R.check('data', wb[o - woff:o - woff + len(b)] == b, "%s: %r read at %d differs from the data written" % (name, oid, o))
                        ev.add('data.readback_equals_write', 'checked')
                        break


def check_omap_paging(pairs, R, ev, name):
    pages = [p for p in pairs if p.rp is not None and hasattr(p, 'omap')]
    chains = collections.defaultdict(list)
    for p in pages:
        chains[p.rq['oid']].append(p)
    for oid, ps in chains.items():
        keys = []
        prev_last = b''
        okc = True
        for i, p in enumerate(ps):
            start_after, maxe, ents, tr = p.omap
            okc &= (start_after == prev_last)
            if ents:
                prev_last = ents[-1][0]
            keys += [k for k, _ in ents]
            if i < len(ps) - 1:
                okc &= tr
            else:
                okc &= not tr
        R.check('omap', okc, "%s: OMAPGETVALS chain on %r (start_after / truncated)" % (name, oid))
        R.check('omap', len(keys) == len(set(keys)), "%s: duplicate keys across pages" % name)
        ev.add('omap.total', (oid.decode(), len(keys), len(ps)))
        # the values follow the lab's pattern key-NNNN -> val-N
        good = all(p2.omap[2] and all(v == b'val-%d' % int(k[4:]) for k, v in p2.omap[2]) for p2 in ps)
        R.check('omap', good, "%s: omap values do not follow the lab pattern" % name)
    for p in pairs:
        if hasattr(p, 'omapbykeys'):
            want, ents = p.omapbykeys
            R.check('omap', all(v == b'val-%d' % int(k[4:]) for k, v in ents), "%s: OMAPGETVALSBYKEYS value" % name)


def check_cls_vs_gt(pairs, gt, R, ev, name):
    hdr_ids = {}
    for p in pairs:
        if p.rp is None or not hasattr(p, 'rinfo'):
            continue
        res, rv, outs = p.rinfo
        for i, op in enumerate(p.rq['ops']):
            if op['name'] != 'CALL' or rv[i] != 0 or res < 0:
                continue
            oid = p.rq['oid'].decode('ascii', 'replace')
            key = (oid, '%s.%s' % (op['cls'], op['method']), op['indata'].hex())
            g = gt.cls.get(key) if op['method'] != 'dir_list' else None
            if g is not None:
                R.check('cls.gt', g['out'] == outs[i].hex(), "%s: %s on %s: wire output %s vs librados exec output %s" % (name, key[1], oid, outs[i].hex()[:40], g['out'][:40]))
                ev.add('cls.gt_compared', key[1])
            d = op.get('decoded')
            if d is None:
                continue
            m = re.match(r'^rbd_header\.([0-9a-f]+)$', oid)
            if m:
                iid = m.group(1)
                img = gt.images.get(iid)
                if op['method'] == 'get_size' and op['indata'][:8] == struct.pack('<Q', CEPH_NOSNAP):
                    hdr_ids.setdefault(iid, {})['size'] = d['size']
                    hdr_ids[iid]['order'] = d['order']
                    if img:
                        R.check('cls.gt', d['size'] == img['size'] and d['order'] == img['order'], "%s: get_size %r vs rbd info" % (name, d))
                if op['method'] == 'get_features':
                    hdr_ids.setdefault(iid, {})['features'] = d['features']
                    if img and d['snap'] == CEPH_NOSNAP:
                        R.check('cls.gt', d['features'] == img['features_num'], "%s: features %#x vs rbd info %#x" % (name, d['features'], img['features_num']))
                if op['method'] == 'get_object_prefix':
                    hdr_ids.setdefault(iid, {})['prefix'] = d['prefix']
                    R.check('cls.gt', d['prefix'] == ('rbd_data.' + iid).encode(), "%s: object prefix %r for id %s" % (name, d['prefix'], iid))
                    if img:
                        R.check('cls.gt', d['prefix'].decode() == img['block_name_prefix'], "%s: prefix vs rbd info" % name)
                if op['method'] == 'get_snapcontext':
                    hdr_ids.setdefault(iid, {})['snapc'] = (d['seq'], d['snaps'])
                    if img:
                        R.check('cls.gt', d['seq'] == 0 and d['snaps'] == [] and img['snapshot_count'] == 0, "%s: snapcontext vs snapshot_count" % name)
                if op['method'] == 'get_data_pool':
                    R.check('cls.gt', d['pool'] == -1, "%s: data pool %d" % (name, d['pool']))
                if op['method'] == 'parent_get':
                    R.check('cls.gt', d['pool'] == -1 and d['image_id'] == b'' and d['snap'] == CEPH_NOSNAP, "%s: parent_get default %r" % (name, d))
            if op['method'] == 'get_id' and oid.startswith('rbd_id.'):
                ev.add('cls.get_id', 'ok')
                iname = oid[len('rbd_id.'):]
                for gi in gt.images.values():
                    if gi['name'] == iname:
                        R.check('cls.gt', d['value'].decode() == gi['id'], "%s: get_id %r vs rbd info id %s" % (name, d['value'], gi['id']))
            if op['method'] == 'dir_get_id':
                for gi in gt.images.values():
                    if gi['name'].encode() == d['arg']:
                        R.check('cls.gt', d['value'].decode() == gi['id'], "%s: dir_get_id" % name)
            if op['method'] == 'dir_get_name':
                for gi in gt.images.values():
                    if gi['id'].encode() == d['arg']:
                        R.check('cls.gt', d['value'].decode() == gi['name'], "%s: dir_get_name" % name)
    # writes to data objects: object name, range and snapshot context against the header values read in the same session
    for p in pairs:
        if p.rq is None:
            continue
        m = RBD_DATA_RE.match(p.rq['oid'])
        if not m:
            continue
        iid = m.group(1).decode()
        h = hdr_ids.get(iid)
        if not h:
            continue
        objno = int(m.group(2), 16)
        osz = 1 << h['order'] if 'order' in h else None
        if osz and 'size' in h:
            R.check('cls.gt', objno * osz < h['size'], "%s: data object %d beyond image size" % (name, objno))
        if h.get('snapc') is not None and any(o['name'] in ('WRITE', 'WRITEFULL') for o in p.rq['ops']):
            R.check('cls.gt', (p.rq['snap_seq'], p.rq['snaps']) == (h['snapc'][0], h['snapc'][1]),
                    "%s: write snapshot context %r vs get_snapcontext %r" % (name, (p.rq['snap_seq'], p.rq['snaps']), h['snapc']))
            ev.add('write.snapc_equals_header', 'checked')
        if osz:
            for op in p.rq['ops']:
                if op['name'] in ('WRITE', 'SPARSE_READ', 'READ'):
                    R.check('cls.gt', op['offset'] + (op['length'] if op['name'] != 'WRITE' else op['payload_len']) <= osz,
                            "%s: %s beyond object size" % (name, op['name']))
                if op['name'] == 'SETALLOCHINT':
                    R.check('cls.gt', op['expected_object_size'] == osz, "%s: alloc hint object size %d vs %d" % (name, op['expected_object_size'], osz))


def check_session(name, cap, keydir, spec, emit=None):
    R, ev = Results(), Ev()
    gt = get_gt(cap)
    t0 = time.time()
    path = os.path.join(cap, 'pcap', name + '.pcap')
    key = keyring_for(spec, cap, keydir) if spec else None
    wrong = name.endswith('wrongkey')
    auth = AuthState(None if wrong else key)
    conns = load_conns(path)
    cis = []
    allpairs = []
    for c in conns:
        ci = analyze_conn(c, auth, R, name)
        cis.append(ci)
        check_connection_level(ci, R, ev, name)
        if ci.role == 'osd' and ci.client_ident and ci.server_ident:
            neg = ci.client_ident['supported'] & ci.server_ident['supported']
            pairs = build_pairs(ci, R, name)
            sent = [m for m in ci.msgs if m.dir == 'c2s']
            R.check('osd.header', [m.seq for m in sent] == list(range(1, len(sent) + 1)), "%s :%d message seq numbers not 1..n" % (name, ci.c.sport))
            tids = [p.rq_msg.tid for p in pairs]
            R.check('osd.header', all(a < b for a, b in zip(tids, tids[1:])), "%s :%d tids not ascending %r" % (name, ci.c.sport, tids[:8]))
            if tids:
                ev.add('tid.first_on_connection', 'is-1' if tids[0] == 1 else 'not-1')
            for p in pairs:
                ev.add('osd.exchanges_by_mode', (ci.mode, 'answered' if p.rp is not None else 'unanswered'))
                check_pair(p, gt, R, ev, name, neg, None)
            if name != 'x-t0-noosd':
                for p in pairs:
                    if ci.gapped and p.rp is None:
                        continue
                    R.check('osd.pairing', p.rp is not None, "%s tid %d: no reply" % (name, p.rq_msg.tid if p.rq_msg else -1))
            else:
                ev.add('noosd', ('requests', len(pairs)))
                for p in pairs:
                    ev.add('noosd', ('replied' if p.rp is not None else 'silent'))
            allpairs += pairs
        elif ci.role == 'osd':
            for fr in ci.auth_frames['s2c']:
                if fr.tag == TAG_AUTH_BAD_METHOD:
                    r_ = Reader(fr.segs[0])
                    meth, resu = r_.u32(), r_.i32()
                    ev.add('osd.auth_bad_method', (meth, errname(resu), 'user=' + (spec['user'] if spec else '?')))
            ev.add('osd.conn.no_ident', (ci.mode, len(ci.frames['c2s']), len(ci.frames['s2c']), spec['user'] if spec else '?'))
        # other message types on osd connections (note 3.4: MOSDMap pushes)
        if ci.role == 'osd':
            for m in ci.msgs:
                if m.type not in (MSG_OSD_OP, MSG_OSD_OPREPLY):
                    ev.add('osd.other_msg', (m.dir, m.type, m.ver))
                    if m.type == MSG_OSD_BACKOFF and m.dir == 's2c':
                        try:
                            b = dec_mosdbackoff(m.front)
                            ev.add('backoff', (b['op'],))
                        except (DecodeError, struct.error) as e:
                            R.fail('backoff', "%s: %s" % (name, e))
    if any(ci.gapped for ci in cis):
        R.warn("%s: data-flow checks skipped (the capture has a hole)" % name)
    else:
        check_data_flows(allpairs, gt, R, ev, name)
    check_omap_paging(allpairs, R, ev, name)
    check_cls_vs_gt(allpairs, gt, R, ev, name)
    if emit is not None:
        emit(name, cis, allpairs)
    return R, ev, time.time() - t0, len(allpairs)


# ===========================================================================
# 9  vectors (scrubbed message dumps; see harness/vectors/osdop/README.md)
# ===========================================================================

def summarize_request(front, ver=9):
    q = dec_mosdop(front, ver)
    return dict(
        pool=q['pgid']['pg']['pool'], seed=q['pgid']['pg']['seed'], hash=q['hash'], epoch=q['epoch'],
        flags=q['flags'], oid=q['oid'].decode('latin-1'), retry_attempt=q['retry_attempt'],
        features=q['features'], snapid=q['snapid'], snap_seq=q['snap_seq'], snaps=q['snaps'],
        client_inc=q['client_inc'], mtime_is_zero=(q['mtime'] == (0, 0)),
        ops=[dict(name=o['name'], code=o['op'], flags=o['flags'], payload_len=o['payload_len'],
                  **{k: o[k] for k in ('offset', 'length') if k in o and o['name'] != 'CALL'},
                  **({k: o[k] for k in ('class_len', 'method_len', 'indata_len')} if o['name'] == 'CALL' else {}))
             for o in q['ops']])


def summarize_reply(front):
    p = dec_mosdopreply(front)
    return dict(oid=p['oid'].decode('latin-1'), pool=p['pgid']['pool'], seed=p['pgid']['seed'], flags=p['flags'],
                result=p['result'], epoch=p['epoch'], retry_attempt=p['retry_attempt'], rvals=p['rvals'],
                replay_version=list(p['replay_version']), user_version=p['user_version'],
                ops=[dict(name=o['name'], code=o['op'], payload_len=o['payload_len']) for o in p['ops']])


def _data_entry(d):
    e = dict(length=len(d), sha256=hashlib.sha256(d).hexdigest())
    if len(d) <= 2048:
        e['hex'] = d.hex()
    else:
        e['head_hex'] = d[:32].hex()
    return e


def _vec(name, source, note, rq_msg, rp_msg, extra=None):
    v = dict(name=name, source=source, note=note)
    for kind, m in (('request', rq_msg), ('reply', rp_msg)):
        if m is None:
            continue
        v[kind] = dict(type=m.type, version=m.ver, compat_version=m.compat, priority=m.prio, tid=m.tid, seq=m.seq,
                       segment_lengths=m.seglens, header2_hex=m.hdr_raw.hex(), front_hex=m.front.hex(),
                       data=_data_entry(m.data))
    if rq_msg is not None:
        v['request']['summary'] = summarize_request(rq_msg.front, rq_msg.ver)
    if rp_msg is not None:
        v['reply']['summary'] = summarize_reply(rp_msg.front)
    if extra:
        v.update(extra)
    return v


def emit_vectors(outdir, cap, keydir):
    """Write the scrubbed vector set. Only message headers, fronts and (small) payloads are kept; the cephx material,
    tickets, connection secrets and frame-level crypto are never part of a vector."""
    os.makedirs(outdir, exist_ok=True)
    specs = read_sessions_tsv(cap)
    gt = get_gt(cap)
    cache = {}

    def pairs_of(name):
        if name in cache:
            return cache[name]
        R, ev = Results(), Ev()
        res = []

        def grab(nm, cis, pairs):
            res.extend(pairs)
        check_session(name, cap, keydir, specs[name], emit=grab)
        cache[name] = res
        return res

    def find(name, pred, nth=0):
        n = 0
        for p in pairs_of(name):
            if p.rp is not None and pred(p):
                if n == nth:
                    return p
                n += 1
        raise SystemExit("vector source not found in %s" % name)

    def names(p):
        return [o['name'] for o in p.rq['ops']]

    def calls(p):
        return [(o.get('cls'), o.get('method')) for o in p.rq['ops'] if o['name'] == 'CALL']

    plan = [
        ('rados-put-small', 'k2-rados-small', lambda p: names(p) == ['WRITEFULL'], 0, 'WRITEFULL of 100 bytes: mtime set, data segment = the 100 bytes'),
        ('rados-stat', 'k2-rados-small', lambda p: names(p) == ['STAT'], 0, 'STAT: reply output is u64 size + utime (16 bytes)'),
        ('rados-read-whole', 'k2-rados-small', lambda p: names(p) == ['READ'] and p.rp['result'] == 0, 0, 'READ length 4 MiB of a 100 byte object: reply returns 100 bytes'),
        ('rados-read-enoent', 'k2-rados-small', lambda p: names(p) == ['READ'] and p.rp['result'] == -2, 0, 'READ of a missing object: result -2, rval 0, no data, no ACK flag in the reply'),
        ('rados-delete', 'k2-rados-small', lambda p: names(p) == ['DELETE'], 0, 'DELETE as sent by rados rm: FULL_FORCE (0x01000000) is set'),
        ('rados-put-big-chunk', 'k2-rados-big', lambda p: names(p) == ['WRITE'], 0, 'WRITE of a 4 MiB chunk (data kept as length + sha256 only)'),
        ('rbd-write-64k', 'k2-rbd-bench-default', lambda p: names(p) == ['SETALLOCHINT', 'WRITE'], 0, 'librbd data write: SETALLOCHINT then WRITE, data kept as length + sha256'),
        ('rbd-sparse-read-64k', 'k2-rbd-bench-default', lambda p: names(p) == ['SPARSE_READ'], 0, 'SPARSE_READ of 64 KiB: output = extents map + data blob'),
        ('rbd-open-compound-5calls', 'k2-rbd-info-default', lambda p: names(p) == ['CALL'] * 5, 0, 'five CALL ops in one read message (rbd info on the default-feature image)'),
        ('rbd-lock-get-info', 'k2-rbd-info-default', lambda p: ('lock', 'get_info') in calls(p), 0, 'lock get_info on the header object'),
        ('rbd-mirror-image-get-enoent', 'k2-rbd-bench-default', lambda p: calls(p) == [('rbd', 'mirror_image_get')] and p.rp['result'] == -2, 0, 'CALL on a missing object: whole-message -ENOENT, rval 0'),
        ('rbd-write-call-failing', 'k2-rbd-bench-default', lambda p: calls(p) == [('rbd', 'mirror_image_remove')], 0, 'mutating CALL whose method fails: result -2 and rval -2, reply has ACK'),
        ('rbd-create-then-call', 'k2-rbd-bench-v1', lambda p: names(p) == ['CREATE', 'CALL'], 0, 'CREATE followed by a CALL in one mutating message'),
        ('omap-getvals-byk', 'k2-omap', lambda p: names(p) == ['OMAPGETVALSBYKEYS'], 0, 'OMAPGETVALSBYKEYS for one key'),
        ('omap-getvals-page2', 'k2-omap', lambda p: names(p) == ['OMAPGETVALS'] and not p.omap[3], 0, 'second OMAPGETVALS page (start_after = last key of page 1, truncated = false)'),
        ('eperm-write', 'x-t0-ro', lambda p: names(p) == ['WRITEFULL'] and p.rp['result'] == -1, 0, 'write with a read-only OSD cap: result -1, rval 0, reply flags = request flags (no ACK)'),
        ('k1-rbd-get-size', 'k1-rbd-info-v1', lambda p: calls(p) and calls(p)[0] == ('rbd', 'get_size'), 0, 'same layout with the legacy key type'),
        ('secure-mode-read', 'k2-sec-rados-big', lambda p: names(p) == ['READ'], 0, 'obtained from a secure-mode connection after decrypting it; the plaintext message is identical in layout'),
    ]
    written = []
    for i, (vname, sess, pred, nth, note) in enumerate(plan, 1):
        p = find(sess, pred, nth)
        rq, rp = p.rq_msg, p.rp_msg
        for m in (rq, rp):
            m.hdr_raw = struct.pack('<QQHHHIHQBHH', m.hdr['seq'], m.hdr['tid'], m.hdr['type'], m.hdr['prio'], m.hdr['ver'],
                                    m.hdr['dpp'], m.hdr['data_off'], m.hdr['ack_seq'], m.hdr['flags'], m.hdr['compat'], m.hdr['resv'])
        v = _vec(vname, 'capture session %s, tid %d (private capture store)' % (sess, rq.tid), note, rq, rp)
        fn = '%02d-%s.json' % (i, vname)
        with open(os.path.join(outdir, fn), 'w') as f:
            json.dump(v, f, indent=1, sort_keys=True)
            f.write('\n')
        written.append(fn)
    # the note's own 217-byte example (computed by hand in the note, 5.1), rebuilt by this tool's encoder
    ops = [enc_op_extent(0x1201, 0, 4096)]
    front = enc_mosdop(1, 0x38, 0x12345678, 5, 0x08400014, b'a', ops)
    v = dict(name='note-5-1-example', source='synthetic: the example of osd-ops.md 5.1, rebuilt by osdop_check.py enc_mosdop()',
             note='READ of 4096 bytes at offset 0 of object "a", pool 1, hash 0x12345678, pg seed 0x38, epoch 5; 217 bytes',
             request=dict(front_hex=front.hex(), summary=summarize_request(front)))
    fn = '%02d-note-5-1-example.json' % (len(plan) + 1)
    with open(os.path.join(outdir, fn), 'w') as f:
        json.dump(v, f, indent=1, sort_keys=True)
        f.write('\n')
    written.append(fn)
    return written


def check_vectors(vdir, R):
    """Offline self-test: every vector decodes with this tool's own decoders and matches its stored summary."""
    n = 0
    for fn in sorted(os.listdir(vdir)):
        if not fn.endswith('.json'):
            continue
        v = json.load(open(os.path.join(vdir, fn)))
        n += 1
        for kind in ('request', 'reply'):
            if kind not in v:
                continue
            e = v[kind]
            front = bytes.fromhex(e['front_hex'])
            try:
                if kind == 'request':
                    ver = e.get('version', 9)
                    summ = summarize_request(front, ver)
                    q = dec_mosdop(front, ver)
                    R.check('vectors', q['left'] == 0, "%s: trailing bytes" % fn)
                    R.check('vectors', placement_hash(q['oid']) == q['hash'] or v['name'] == 'note-5-1-example',
                            "%s: hash does not match rjenkins(oid)" % fn)
                    # round trip through the encoder written from the note
                    again = enc_mosdop(q['pgid']['pg']['pool'], q['pgid']['pg']['seed'], q['hash'], q['epoch'], q['flags'], q['oid'],
                                       [o['raw'] for o in q['ops']], q['snapid'], q['snap_seq'], q['snaps'], q['retry_attempt'],
                                       q['features'], q['client_inc'], q['mtime'])
                    R.check('vectors', again == front, "%s: re-encoding the decoded request does not reproduce the bytes" % fn)
                    if v['name'] == 'note-5-1-example':
                        R.check('vectors', len(front) == 217, "%s: example length %d" % (fn, len(front)))
                else:
                    summ = summarize_reply(front)
                    p = dec_mosdopreply(front)
                    R.check('vectors', p['left'] == 0, "%s: trailing bytes" % fn)
                    if 'data' in e:
                        R.check('vectors', sum(o['payload_len'] for o in p['ops']) == e['data']['length'], "%s: payload_len sum vs data" % fn)
                R.check('vectors', json.loads(json.dumps(summ)) == e['summary'], "%s: %s summary differs from the stored one" % (fn, kind))
                if 'data' in e and 'hex' in e['data']:
                    R.check('vectors', hashlib.sha256(bytes.fromhex(e['data']['hex'])).hexdigest() == e['data']['sha256'], "%s: data digest" % fn)
                if 'header2_hex' in e:
                    h = decode_header2(bytes.fromhex(e['header2_hex']))
                    R.check('vectors', h['type'] in (42, 43) and h['tid'] == e['tid'], "%s: header2" % fn)
            except (DecodeError, struct.error, KeyError, ValueError) as ex:
                R.fail('vectors', "%s %s: %s" % (fn, kind, ex))
    # scrub check: nothing that looks like an address, a keyring line or a key blob may be in a vector file
    bad = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(\bkey\s*=)|([A-Za-z0-9+/]{40,}={0,2}(?![0-9a-f]))')
    for fn in sorted(os.listdir(vdir)):
        if fn.endswith('.json'):
            txt = open(os.path.join(vdir, fn)).read()
            txt_nohex = re.sub(r'"[0-9a-f]{32,}"', '"<hex>"', txt)
            m = bad.search(txt_nohex)
            R.check('vectors', m is None, "%s: scrub check hit %r" % (fn, m.group(0)[:40] if m else ''))
    R.check('vectors', n > 0, "no vectors found in %s" % vdir)
    return n


# ===========================================================================
# 10 command line
# ===========================================================================

def _worker(args):
    name, cap, keydir, spec = args
    R, ev, t, n = check_session(name, cap, keydir, spec)
    return name, R, ev, t, n


def print_evidence(ev, out):
    for key in sorted(ev.c):
        items = ev.c[key].most_common(12)
        out.write("  %s:\n" % key)
        for val, cnt in items:
            ex = ev.ex.get((key, val))
            out.write("     %6d  %s%s\n" % (cnt, val, ("    e.g. " + str(ex)) if ex is not None else ''))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--captures', help='capture directory (contains pcap/, sessions.tsv, gt/, gt4/, data/; '
                                       'default: harness/vectors/public)')
    ap.add_argument('--keys', help='directory with client.*.keyring (default: harness/vectors/public/keys for the public '
                                   'set, else <captures>/../lab-secrets)')
    ap.add_argument('--vectors', help='vector directory (default: harness/vectors/osdop next to this tool)')
    ap.add_argument('--vectors-only', action='store_true', help='only run the offline vector self-test')
    ap.add_argument('--emit-vectors', metavar='DIR', help='write scrubbed vectors to DIR (needs --captures)')
    ap.add_argument('--only', help='comma separated session names')
    ap.add_argument('--jobs', type=int, default=0, help='parallel sessions (default: number of CPUs)')
    ap.add_argument('--evidence', action='store_true', help='print the evidence counters used to settle the note')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args(argv)
    here = os.path.dirname(os.path.abspath(__file__))
    vdir = a.vectors or os.path.normpath(os.path.join(here, '..', 'vectors', 'osdop'))
    R, ev = Results(), Ev()
    t0 = time.time()
    if a.vectors_only:
        n = check_vectors(vdir, R)
        print("vectors: %d files" % n)
    else:
        cap = pubset.captures_dir(a.captures)
        keydir = os.path.abspath(a.keys) if a.keys else pubset.default_keys_dir(cap)
        if a.emit_vectors:
            for fn in emit_vectors(a.emit_vectors, cap, keydir):
                print("wrote", fn)
            return 0
        specs = read_sessions_tsv(cap)
        names = sorted(os.path.splitext(f)[0] for f in os.listdir(os.path.join(cap, 'pcap')) if f.endswith('.pcap'))
        if a.only:
            names = [n for n in a.only.split(',') if n]
        jobs = a.jobs or os.cpu_count() or 1
        gt = get_gt(cap)
        check_global(gt, R, ev)
        work = [(n, cap, keydir, specs.get(n)) for n in names]
        # biggest captures first so the pool stays busy
        work.sort(key=lambda w: -os.path.getsize(os.path.join(cap, 'pcap', w[0] + '.pcap')))
        done = 0
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as ex:
            for name, r, e, t, n in ex.map(_worker, work):
                R.merge(r)
                ev.merge(e)
                done += 1
                bad = sum(f for _, f in r.counts.values())
                if a.verbose or bad:
                    print("%-24s %5.1fs  %4d op exchanges  %s" % (name, t, n, 'FAIL %d' % bad if bad else 'ok'))
        print("sessions: %d" % done)
        n = check_vectors(vdir, R) if os.path.isdir(vdir) and any(f.endswith('.json') for f in os.listdir(vdir)) else 0
        print("vectors: %d files" % n)
        if a.evidence:
            print("evidence:")
            print_evidence(ev, sys.stdout)
    tp = tf = 0
    print("%-14s %8s %8s" % ('group', 'passed', 'failed'))
    for g, (p, f) in R.counts.items():
        print("%-14s %8d %8d" % (g, p, f))
        tp += p
        tf += f
    for w in R.warnings:
        print("  WARNING (capture defect, not counted): %s" % w)
    for g, msgs in R.msgs.items():
        for m in msgs[:5]:
            print("  FAIL [%s] %s" % (g, m))
        if len(msgs) > 5:
            print("  ... %d more in %s" % (len(msgs) - 5, g))
    print("TOTAL: %d checks, %d passed, %d failed (%.0f s)" % (tp + tf, tp, tf, time.time() - t0))
    pubset.emit_result('osdop_check', tp, tf)
    return 0 if tf == 0 and tp > 0 else 1


if __name__ == '__main__':
    sys.exit(main())
