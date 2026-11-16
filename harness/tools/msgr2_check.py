#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
msgr2_check.py - independent checker for docs/spec/msgr2.md (and the msgr2-facing
parts of docs/spec/cephx.md) against real packet captures.

Written from the NOTES only (not from Ceph source, not using any Ceph decoder).
Standard library plus the 'cryptography' package.

Usage:
    python3 harness/tools/msgr2_check.py --captures <captures dir> [--keys <keyring dir>]
                                         [--only SESSION[,SESSION...]] [-v]
                                         [--emit-vectors <dir>]

<captures dir> contains pcap/<session>.pcap and (for the cephx / secure-mode
checks) the session-secret notes in secrets/session-secrets/<session>.txt, which
are used ONLY as a cross-check of the keys this tool derives by itself.  The lab
keyrings are read at run time from --keys (default: sibling directory
../lab-secrets of the captures dir); key material is never printed.

Exit status 0 only if every check passed.

Layout of this file
    1. primitives (crc32c, reader, cephx crypto)
    2. pcap / TCP reassembly
    3. msgr2 frame parsing (rev 1, crc and secure)
    4. per-connection analysis and the checks
    5. command line
"""

import argparse
import base64
import collections
import hashlib
import hmac
import os
import re
import struct
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    sys.stderr.write("this tool needs the 'cryptography' package (pip install --user cryptography)\n")
    sys.exit(2)

# ---------------------------------------------------------------------------
# 1. primitives
# ---------------------------------------------------------------------------

# CRC-32C, raw update (no implicit inversion), table generated from the
# reflected polynomial exactly as the note (2.5) describes.
_POLY_REFLECTED = 0x82F63B78


def _make_table():
    t = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ _POLY_REFLECTED if c & 1 else c >> 1
        t.append(c)
    return t


_CRC_T = _make_table()


def _make_slices():
    t = [_CRC_T]
    for _ in range(7):
        prev = t[-1]
        t.append([(prev[i] >> 8) ^ _CRC_T[prev[i] & 0xFF] for i in range(256)])
    return t


_S = _make_slices()


def crc32c_slow(data, seed=0):
    """Byte-at-a-time reference form of the note's per-byte step (2.5)."""
    c = seed & 0xFFFFFFFF
    t = _CRC_T
    for b in data:
        c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    return c


def crc32c(data, seed=0):
    """Same function as crc32c_slow, 8 bytes per step (slice-by-8) so 19 MB captures finish quickly."""
    c = seed & 0xFFFFFFFF
    n = len(data)
    nw = n // 8
    if nw:
        t0, t1, t2, t3, t4, t5, t6, t7 = _S
        for x in struct.unpack('<%dQ' % nw, data[:nw * 8]):
            lo = (x & 0xFFFFFFFF) ^ c
            hi = x >> 32
            c = (t7[lo & 0xFF] ^ t6[(lo >> 8) & 0xFF] ^ t5[(lo >> 16) & 0xFF] ^ t4[lo >> 24]
                 ^ t3[hi & 0xFF] ^ t2[(hi >> 8) & 0xFF] ^ t1[(hi >> 16) & 0xFF] ^ t0[hi >> 24])
    t = _CRC_T
    for b in data[nw * 8:]:
        c = (c >> 8) ^ t[(c ^ b) & 0xFF]
    return c


def u8(b, o=0):
    return b[o]


def u16(b, o=0):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o=0):
    return struct.unpack_from('<I', b, o)[0]


def u64(b, o=0):
    return struct.unpack_from('<Q', b, o)[0]


def s32(b, o=0):
    return struct.unpack_from('<i', b, o)[0]


def s64(b, o=0):
    return struct.unpack_from('<q', b, o)[0]


class DecodeError(Exception):
    pass


class Reader:
    """Bounds-checked little-endian reader over bytes."""

    def __init__(self, data, off=0):
        self.d = bytes(data)
        self.o = off

    def left(self):
        return len(self.d) - self.o

    def take(self, n):
        if n < 0 or self.o + n > len(self.d):
            raise DecodeError("short read: need %d have %d" % (n, self.left()))
        r = self.d[self.o:self.o + n]
        self.o += n
        return r

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack('<H', self.take(2))[0]

    def u32(self):
        return struct.unpack('<I', self.take(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.take(8))[0]

    def s32(self):
        return struct.unpack('<i', self.take(4))[0]

    def s64(self):
        return struct.unpack('<q', self.take(8))[0]

    def blob(self):
        n = self.u32()
        return self.take(n)

    def string(self):
        return self.blob()

    def vec_u32(self):
        n = self.u32()
        if n > 4096:
            raise DecodeError("vector too long")
        return [self.u32() for _ in range(n)]

    def rest(self):
        return self.take(self.left())


# ---- cephx crypto (cephx note 2.3 - 2.6) -----------------------------------

CEPH_AES_IV = bytes.fromhex("63657068736167657975646167726567")  # "cephsageyudagreg"
CEPHX_MAGIC = 0xff009cad8826aa55


class CryptoKey:
    """A cephx CryptoKey: type 1 (aes) or type 2 (aes256k)."""

    def __init__(self, ktype, secret, created=(0, 0)):
        self.type = ktype
        self.secret = bytes(secret)
        self.created = created
        self._derived = {}

    @staticmethod
    def decode(b):
        r = Reader(b)
        t = r.u16()
        sec = r.u32(), r.u32()
        ln = r.u16()
        s = r.take(ln)
        return CryptoKey(t, s, sec)

    @staticmethod
    def from_base64(text):
        return CryptoKey.decode(base64.b64decode(text))

    def encode(self):
        return struct.pack('<HIIH', self.type, self.created[0], self.created[1], len(self.secret)) + self.secret

    # -- type 2 key derivation (RFC 8009 profile, empty context) --
    def _kdf(self, usage, typebyte, outlen):
        key = self._derived.get((usage, typebyte))
        if key is None:
            msg = b'\x00\x00\x00\x01' + struct.pack('>I', usage) + bytes([typebyte]) + b'\x00' + struct.pack('>I', outlen * 8)
            key = hmac.new(self.secret, msg, hashlib.sha384).digest()[:outlen]
            self._derived[(usage, typebyte)] = key
        return key

    def decrypt(self, ct, usage):
        """Raw decrypt (no envelope). Raises DecodeError on failure."""
        if self.type == 1:
            if len(ct) == 0 or len(ct) % 16:
                raise DecodeError("type1: bad ciphertext length %d" % len(ct))
            dec = Cipher(algorithms.AES(self.secret[:16]), modes.CBC(CEPH_AES_IV)).decryptor()
            pt = dec.update(ct) + dec.finalize()
            pad = pt[-1]
            if pad < 1 or pad > 16:
                raise DecodeError("type1: bad padding byte")
            return pt[:-pad]
        if self.type == 2:
            if len(ct) < 40:
                raise DecodeError("type2: too short")
            body, mac = ct[:-24], ct[-24:]
            ki = self._kdf(usage, 0x55, 24)
            ke = self._kdf(usage, 0xAA, 32)
            exp = hmac.new(ki, b'\x00' * 16 + body, hashlib.sha384).digest()[:24]
            if not hmac.compare_digest(exp, mac):
                raise DecodeError("type2: MAC mismatch")
            m = _cts3_decrypt(ke, body)
            return m[16:]
        raise DecodeError("unknown key type %d" % self.type)

    def encrypt(self, pt, usage, confounder=None):
        if self.type == 1:
            padn = 16 - len(pt) % 16
            pt = pt + bytes([padn]) * padn
            enc = Cipher(algorithms.AES(self.secret[:16]), modes.CBC(CEPH_AES_IV)).encryptor()
            return enc.update(pt) + enc.finalize()
        if self.type == 2:
            conf = confounder if confounder is not None else os.urandom(16)
            ki = self._kdf(usage, 0x55, 24)
            ke = self._kdf(usage, 0xAA, 32)
            ct = _cts3_encrypt(ke, conf + pt)
            mac = hmac.new(ki, b'\x00' * 16 + ct, hashlib.sha384).digest()[:24]
            return ct + mac
        raise DecodeError("unknown key type")


def _cbc_raw(key, data, encrypt):
    c = Cipher(algorithms.AES(key), modes.CBC(b'\x00' * 16))
    op = c.encryptor() if encrypt else c.decryptor()
    return op.update(data) + op.finalize()


def _cts3_encrypt(key, m):
    n = len(m)
    if n < 16:
        raise DecodeError("cts: input < 16")
    if n == 16:
        return _cbc_raw(key, m, True)
    k = (n + 15) // 16
    padded = m + b'\x00' * (k * 16 - n)
    c = _cbc_raw(key, padded, True)
    blocks = [c[i * 16:(i + 1) * 16] for i in range(k)]
    r = n - 16 * (k - 1)
    return b''.join(blocks[:k - 2]) + blocks[k - 1] + blocks[k - 2][:r]


def _cts3_decrypt(key, ct):
    n = len(ct)
    if n < 16:
        raise DecodeError("cts: input < 16")
    if n == 16:
        return _cbc_raw(key, ct, False)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    head = ct[:(k - 2) * 16]
    ck = ct[(k - 2) * 16:(k - 1) * 16]       # this is C_k (full block, swapped position)
    tail = ct[(k - 1) * 16:]                  # first r bytes of C_(k-1)
    # D(C_k) = P_k(padded) xor C_(k-1); C_(k-1) = tail || last (16-r) bytes of D(C_k)
    ecb = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    dk = ecb.update(ck) + ecb.finalize()
    cprev = tail + dk[r:]
    # P_k = D(C_k) xor C_(k-1), keep r bytes
    pk = bytes(a ^ b for a, b in zip(dk, cprev))[:r]
    # P_(k-1) = D(C_(k-1)) xor C_(k-2)
    ecb = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    dprev = ecb.update(cprev) + ecb.finalize()
    cprev2 = ct[(k - 3) * 16:(k - 2) * 16] if k >= 3 else b'\x00' * 16
    pprev = bytes(a ^ b for a, b in zip(dprev, cprev2))
    plain_head = b''
    if k > 2:
        # blocks C1..C(k-2) are ordinary CBC blocks
        plain_head = _cbc_raw(key, head, False)
    return plain_head + pprev + pk


def open_envelope(key, ct, usage):
    """Decrypt + check the u8 version / u64 magic envelope (cephx 2.6); return the item bytes."""
    pt = key.decrypt(ct, usage)
    if len(pt) < 9:
        raise DecodeError("envelope too short")
    if u64(pt, 1) != CEPHX_MAGIC:
        raise DecodeError("envelope magic mismatch")
    return pt[9:]


def seal_envelope(key, item, usage):
    return key.encrypt(b'\x01' + struct.pack('<Q', CEPHX_MAGIC) + item, usage)


def parse_keyring(path):
    """Return {entity: CryptoKey} from a keyring file. Never prints the secrets."""
    out = {}
    cur = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            m = re.match(r'^\[(.+)\]$', line)
            if m:
                cur = m.group(1)
                continue
            m = re.match(r'^key\s*=\s*(\S+)$', line)
            if m and cur:
                out[cur] = CryptoKey.from_base64(m.group(1))
    return out


# ---------------------------------------------------------------------------
# 2. pcap / TCP reassembly
# ---------------------------------------------------------------------------

class TcpDir:
    """One direction of one TCP connection, reassembled by sequence number."""

    def __init__(self):
        self.isn = None
        self.segs = {}       # relative offset -> bytes
        self.retrans = 0
        self.conflicts = 0
        self.first_ts = None
        self.acked = 0       # highest byte offset the peer acknowledged
        self.pkts = []       # (ts, rel_off, len)

    def add(self, seq, payload, syn, ts):
        if syn:
            self.isn = seq
            return
        if not payload:
            return
        if self.isn is None:
            raise DecodeError("data before SYN (capture does not start at connection setup)")
        off = (seq - self.isn - 1) & 0xFFFFFFFF
        if off in self.segs:
            self.retrans += 1
            if self.segs[off][:len(payload)] != payload[:len(self.segs[off])]:
                self.conflicts += 1
            if len(payload) > len(self.segs[off]):
                self.segs[off] = payload
            return
        self.segs[off] = payload
        if self.first_ts is None:
            self.first_ts = ts
        self.pkts.append((ts, off, len(payload)))

    def assemble(self):
        """Return (bytes up to the first hole, number of holes). A hole means the capture lost packets."""
        buf = bytearray()
        gaps = 0
        for off in sorted(self.segs):
            data = self.segs[off]
            if off > len(buf):
                gaps += 1
                self.first_gap = len(buf) if not hasattr(self, 'first_gap') else self.first_gap
                break
            if off + len(data) > len(buf):
                if off < len(buf):
                    self.retrans += 1
                    data = data[len(buf) - off:]
                buf.extend(data)
            else:
                self.retrans += 1
        if gaps == 0 and self.acked - len(buf) > 1:      # peer acked bytes the capture never saw (FIN may add 1)
            gaps = 1
        return bytes(buf), gaps


class Conn:
    def __init__(self, key):
        self.key = key            # (client_ip, client_port, server_ip, server_port)
        self.c2s = TcpDir()
        self.s2c = TcpDir()
        self.first_ts = None
        self.last_ts = None


def read_pcap(path):
    """Yield (ts, ip_src, sport, ip_dst, dport, seq, flags, payload) for every TCP/IPv4 packet."""
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        e = '<'
        nano = False
    elif magic == b'\xa1\xb2\xc3\xd4':
        e = '>'
        nano = False
    elif magic == b'\x4d\x3c\xb2\xa1':
        e = '<'
        nano = True
    else:
        raise DecodeError("not a classic pcap file: " + path)
    linktype = struct.unpack(e + 'I', data[20:24])[0]
    if linktype != 1:
        raise DecodeError("only Ethernet captures are supported (linktype %d)" % linktype)
    o = 24
    while o + 16 <= len(data):
        ts_s, ts_f, incl, orig = struct.unpack(e + 'IIII', data[o:o + 16])
        o += 16
        pkt = data[o:o + incl]
        o += incl
        ts = ts_s + ts_f / (1e9 if nano else 1e6)
        if len(pkt) < 14:
            continue
        et = struct.unpack('>H', pkt[12:14])[0]
        p = 14
        if et == 0x8100:
            et = struct.unpack('>H', pkt[16:18])[0]
            p = 18
        if et != 0x0800:
            continue
        ihl = (pkt[p] & 0x0F) * 4
        if pkt[p + 9] != 6:
            continue
        tot = struct.unpack('>H', pkt[p + 2:p + 4])[0]
        src = '.'.join(str(x) for x in pkt[p + 12:p + 16])
        dst = '.'.join(str(x) for x in pkt[p + 16:p + 20])
        t = p + ihl
        sport, dport, seq, ack = struct.unpack('>HHII', pkt[t:t + 12])
        doff = (pkt[t + 12] >> 4) * 4
        flags = pkt[t + 13]
        payload = pkt[t + doff:p + tot]
        yield ts, src, sport, dst, dport, seq, flags, payload, ack


def load_conns(path):
    """Group the packets of a pcap into Conn objects; the client is the SYN sender."""
    conns = collections.OrderedDict()
    for ts, src, sport, dst, dport, seq, flags, payload, ack in read_pcap(path):
        syn = bool(flags & 0x02)
        ack_f = bool(flags & 0x10)
        ack_only = ack_f
        k1 = (src, sport, dst, dport)
        k2 = (dst, dport, src, sport)
        if k1 in conns:
            c, d = conns[k1], 'c2s'
        elif k2 in conns:
            c, d = conns[k2], 's2c'
        elif syn and not ack_f:
            c = Conn(k1)
            conns[k1] = c
            d = 'c2s'
        else:
            continue                      # connection set up before the capture started
        if c.first_ts is None:
            c.first_ts = ts
        c.last_ts = ts
        (c.c2s if d == 'c2s' else c.s2c).add(seq, payload, syn, ts)
        if ack_f:
            # the ACK number tells how much of the OTHER direction the receiver saw: exposes tail loss in the capture
            other = c.s2c if d == 'c2s' else c.c2s
            if other.isn is not None:
                rel = (ack - other.isn - 1) & 0xFFFFFFFF
                if rel < (1 << 31) and rel > other.acked:
                    other.acked = rel
    return list(conns.values())


# ---------------------------------------------------------------------------
# 3. msgr2 frame parsing (revision 1)
# ---------------------------------------------------------------------------

TAGS = {1: 'HELLO', 2: 'AUTH_REQUEST', 3: 'AUTH_BAD_METHOD', 4: 'AUTH_REPLY_MORE', 5: 'AUTH_REQUEST_MORE',
        6: 'AUTH_DONE', 7: 'AUTH_SIGNATURE', 8: 'CLIENT_IDENT', 9: 'SERVER_IDENT',
        10: 'IDENT_MISSING_FEATURES', 11: 'SESSION_RECONNECT', 12: 'SESSION_RESET', 13: 'SESSION_RETRY',
        14: 'SESSION_RETRY_GLOBAL', 15: 'SESSION_RECONNECT_OK', 16: 'WAIT', 17: 'MESSAGE',
        18: 'KEEPALIVE2', 19: 'KEEPALIVE2_ACK', 20: 'ACK', 21: 'COMPRESSION_REQUEST', 22: 'COMPRESSION_DONE'}
T_HELLO, T_AUTH_REQUEST, T_AUTH_BAD_METHOD, T_AUTH_REPLY_MORE, T_AUTH_REQUEST_MORE, T_AUTH_DONE, T_AUTH_SIGNATURE = 1, 2, 3, 4, 5, 6, 7
T_CLIENT_IDENT, T_SERVER_IDENT, T_IDENT_MISSING = 8, 9, 10
T_WAIT, T_MESSAGE, T_KEEPALIVE2, T_KEEPALIVE2_ACK, T_ACK, T_COMPRESSION_REQUEST, T_COMPRESSION_DONE = 16, 17, 18, 19, 20, 21, 22

ENTITY_TYPES = {0x01: 'MON', 0x02: 'MDS', 0x04: 'OSD', 0x08: 'CLIENT', 0x10: 'MGR', 0x20: 'AUTH', 0xFF: 'ANY'}
PREAMBLE_LEN = 32
EPILOGUE_LEN = 13
LATE_COMPLETE = 0x0E


class Frame:
    def __init__(self):
        self.tag = 0
        self.nseg = 0
        self.lens = [0, 0, 0, 0]
        self.aligns = [0, 0, 0, 0]
        self.flags = 0
        self.reserved = 0
        self.segs = []
        self.seg0_crc = None
        self.late_status = None
        self.epi_crcs = None
        self.off = 0
        self.end = 0
        self.raw = b''
        self.secure = False
        self.problems = []      # list of (code, text) found while parsing this frame
        self.direction = ''
        self.ts = None

    @property
    def name(self):
        return TAGS.get(self.tag, 'TAG%d' % self.tag)


class Truncated(Exception):
    pass


def parse_preamble(pre, fr):
    """Fill the structural fields of fr from a 32-byte preamble; record problems."""
    fr.tag = pre[0]
    fr.nseg = pre[1]
    for i in range(4):
        fr.lens[i] = u32(pre, 2 + 6 * i)
        fr.aligns[i] = u16(pre, 6 + 6 * i)
    fr.flags = pre[26]
    fr.reserved = pre[27]
    if crc32c(pre[:28], 0) != u32(pre, 28):
        fr.problems.append(('P-CRC', 'preamble crc mismatch'))
    if not 1 <= fr.nseg <= 4:
        fr.problems.append(('P-NSEG', 'num_segments %d outside 1..4' % fr.nseg))
    elif fr.nseg > 1 and fr.lens[fr.nseg - 1] == 0:
        fr.problems.append(('P-LAST', 'last segment empty with n>1'))
    for i in range(fr.nseg, 4):
        if fr.lens[i] != 0 or fr.aligns[i] != 0:
            fr.problems.append(('P-UNUSED', 'unused segment %d has nonzero length/alignment' % i))


def parse_plain_frame(buf, off):
    """Parse one rev-1 crc frame at buf[off:]. Returns Frame. Raises Truncated at end of data."""
    if off + PREAMBLE_LEN > len(buf):
        raise Truncated()
    fr = Frame()
    fr.off = off
    pre = buf[off:off + PREAMBLE_LEN]
    parse_preamble(pre, fr)
    if any(c in ('P-CRC', 'P-NSEG') for c, _ in fr.problems):
        fr.end = off + PREAMBLE_LEN
        fr.raw = pre
        return fr
    p = off + PREAMBLE_LEN
    segs = []
    n = fr.nseg
    lens = fr.lens
    need = 0
    if lens[0] > 0:
        need += lens[0] + 4
    need += sum(lens[1:n])
    if n > 1:
        need += EPILOGUE_LEN
    if p + need > len(buf):
        raise Truncated()
    if lens[0] > 0:
        s0 = buf[p:p + lens[0]]
        c = u32(buf, p + lens[0])
        fr.seg0_crc = c
        if crc32c(s0, 0xFFFFFFFF) != c:
            fr.problems.append(('S0-CRC', 'segment 0 crc mismatch'))
        p += lens[0] + 4
    else:
        s0 = b''
    segs.append(s0)
    for i in range(1, n):
        segs.append(buf[p:p + lens[i]])
        p += lens[i]
    if n > 1:
        epi = buf[p:p + EPILOGUE_LEN]
        p += EPILOGUE_LEN
        fr.late_status = epi[0]
        fr.epi_crcs = [u32(epi, 1), u32(epi, 5), u32(epi, 9)]
        check_epilogue(fr, segs)
    fr.segs = segs
    fr.end = p
    fr.raw = buf[off:p]
    return fr


def check_epilogue(fr, segs):
    n = fr.nseg
    if fr.late_status != LATE_COMPLETE:
        fr.problems.append(('E-LATE', 'late_status 0x%02x (expected 0x0e)' % fr.late_status))
    for i in range(1, 4):
        slot = fr.epi_crcs[i - 1]
        if i < n:
            exp = crc32c(segs[i], 0xFFFFFFFF)
            if slot != exp:
                fr.problems.append(('E-CRC', 'segment %d crc slot 0x%08x != 0x%08x' % (i, slot, exp)))
        elif slot != 0:
            fr.problems.append(('E-UNUSED', 'unused crc slot %d not zero' % (i - 1)))


def _round16(n):
    return (n + 15) & ~15


class Aead:
    """AES-128-GCM with a 12-byte nonce whose 64-bit counter is bumped after every operation (note 2.6.3)."""

    def __init__(self, key, nonce):
        self.g = AESGCM(key)
        self.nonce = bytearray(nonce)
        self.ops = 0

    def _bump(self):
        c = (struct.unpack_from('<Q', self.nonce, 4)[0] + 1) & 0xFFFFFFFFFFFFFFFF
        struct.pack_into('<Q', self.nonce, 4, c)
        self.ops += 1

    def open(self, ct_and_tag):
        try:
            pt = self.g.decrypt(bytes(self.nonce), ct_and_tag, None)
        except Exception:
            raise DecodeError("AEAD tag mismatch at op %d" % self.ops)
        self._bump()
        return pt


def parse_secure_frame(buf, off, aead):
    """Parse one rev-1 secure frame (note 2.6.3). Raises Truncated / DecodeError."""
    if off + 96 > len(buf):
        raise Truncated()
    fr = Frame()
    fr.off = off
    fr.secure = True
    first = aead.open(buf[off:off + 96])
    pre = first[:PREAMBLE_LEN]
    inline = first[PREAMBLE_LEN:]
    parse_preamble(pre, fr)
    if any(c in ('P-CRC', 'P-NSEG') for c, _ in fr.problems):
        fr.end = off + 96
        fr.raw = buf[off:off + 96]
        return fr
    p = off + 96
    n = fr.nseg
    lens = fr.lens
    seg0_pad = _round16(lens[0])
    seg0 = bytearray(inline[:min(seg0_pad, 48)])
    if seg0_pad > 48:
        rest = seg0_pad - 48
        if p + rest + 16 > len(buf):
            raise Truncated()
        seg0 += aead.open(buf[p:p + rest + 16])
        p += rest + 16
    s0 = bytes(seg0[:lens[0]])
    if any(seg0[lens[0]:]):
        fr.problems.append(('SEC-PAD', 'segment 0 padding not zero'))
    if seg0_pad < 48 and any(inline[seg0_pad:]):
        fr.problems.append(('SEC-PAD', 'unused part of the 48-byte inline buffer not zero'))
    segs = [s0]
    if n > 1:
        body = sum(_round16(lens[i]) for i in range(1, n)) + 16
        if p + body + 16 > len(buf):
            raise Truncated()
        plain = aead.open(buf[p:p + body + 16])
        p += body + 16
        q = 0
        for i in range(1, n):
            segs.append(plain[q:q + lens[i]])
            if any(plain[q + lens[i]:q + _round16(lens[i])]):
                fr.problems.append(('SEC-PAD', 'segment %d padding not zero' % i))
            q += _round16(lens[i])
        epi = plain[q:q + 16]
        fr.late_status = epi[0]
        if any(epi[1:]):
            fr.problems.append(('SEC-EPI', 'epilogue padding not zero'))
        if (fr.late_status & 0x0F) != 0x0E:
            fr.problems.append(('E-LATE', 'late_status 0x%02x' % fr.late_status))
    fr.segs = segs
    fr.end = p
    fr.raw = buf[off:p]
    return fr


# ---- control-frame payload decoding (note 2.7, 2.8) ------------------------

class Addr:
    """entity_addr_t, current format (note 2.8)."""

    def __init__(self):
        self.marker = self.struct_v = self.struct_compat = self.struct_len = 0
        self.type = self.nonce = self.elen = self.family = 0
        self.sa = b''
        self.raw = b''

    @property
    def port(self):
        return struct.unpack('>H', self.sa[0:2])[0] if len(self.sa) >= 2 else None

    @property
    def ip4(self):
        return '.'.join(str(x) for x in self.sa[2:6]) if self.family == 2 and len(self.sa) >= 6 else None

    def __repr__(self):
        return 'Addr(type=%d nonce=%d fam=%d %s:%s)' % (self.type, self.nonce, self.family, self.ip4, self.port)


def decode_addr(r):
    a = Addr()
    start = r.o
    a.marker = r.u8()
    if a.marker != 1:
        raise DecodeError("entity_addr_t marker %d" % a.marker)
    a.struct_v = r.u8()
    a.struct_compat = r.u8()
    a.struct_len = r.u32()
    body = Reader(r.take(a.struct_len))
    a.type = body.u32()
    a.nonce = body.u32()
    a.elen = body.u32()
    if a.elen:
        a.family = body.u16()
        a.sa = body.take(a.elen - 2)
    if body.left():
        raise DecodeError("entity_addr_t: %d trailing bytes inside struct_len" % body.left())
    a.raw = r.d[start:r.o]
    return a


def decode_addrvec(r):
    marker = r.u8()
    if marker != 2:
        raise DecodeError("entity_addrvec_t marker %d (expected 2)" % marker)
    n = r.u32()
    if n > 16:
        raise DecodeError("addrvec count %d" % n)
    return [decode_addr(r) for _ in range(n)]


def encode_addr_v4(ip, port, nonce=0, atype=2):
    sa = struct.pack('>H', port) + bytes(int(x) for x in ip.split('.')) + b'\x00' * 8
    body = struct.pack('<IIIH', atype, nonce, 16, 2) + sa
    return b'\x01\x01\x01' + struct.pack('<I', len(body)) + body


def decode_control(fr):
    """Decode the payload of a control frame into a dict. Raises DecodeError."""
    t = fr.tag
    if not fr.segs:
        raise DecodeError("frame has no decoded segments (structure problem)")
    r = Reader(fr.segs[0])
    d = {}
    if t == T_HELLO:
        d['entity_type'] = r.u8()
        d['peer_addr'] = decode_addr(r)
    elif t == T_AUTH_REQUEST:
        d['method'] = r.u32()
        d['modes'] = r.vec_u32()
        d['payload'] = r.blob()
    elif t == T_AUTH_BAD_METHOD:
        d['method'] = r.u32()
        d['result'] = r.s32()
        d['methods'] = r.vec_u32()
        d['modes'] = r.vec_u32()
    elif t in (T_AUTH_REPLY_MORE, T_AUTH_REQUEST_MORE):
        d['payload'] = r.blob()
    elif t == T_AUTH_DONE:
        d['global_id'] = r.u64()
        d['mode'] = r.u32()
        d['payload'] = r.blob()
    elif t == T_AUTH_SIGNATURE:
        d['sig'] = r.take(32)
    elif t == T_CLIENT_IDENT:
        d['addrs'] = decode_addrvec(r)
        d['target'] = decode_addr(r)
        d['gid'] = r.s64()
        d['global_seq'] = r.u64()
        d['supported'] = r.u64()
        d['required'] = r.u64()
        d['flags'] = r.u64()
        d['cookie'] = r.u64()
    elif t == T_SERVER_IDENT:
        d['addrs'] = decode_addrvec(r)
        d['gid'] = r.s64()
        d['global_seq'] = r.u64()
        d['supported'] = r.u64()
        d['required'] = r.u64()
        d['flags'] = r.u64()
        d['cookie'] = r.u64()
    elif t == T_IDENT_MISSING:
        d['features'] = r.u64()
    elif t == 11:
        d['addrs'] = decode_addrvec(r)
        for k in ('client_cookie', 'server_cookie', 'global_seq', 'connect_seq', 'msg_seq'):
            d[k] = r.u64()
    elif t == 12:
        d['full'] = r.u8()
    elif t in (13, 14, 15, T_ACK):
        d['seq'] = r.u64()
    elif t == T_WAIT:
        pass
    elif t in (T_KEEPALIVE2, T_KEEPALIVE2_ACK):
        d['sec'] = r.u32()
        d['nsec'] = r.u32()
    elif t == T_COMPRESSION_REQUEST:
        d['is_compress'] = r.u8()
        d['methods'] = r.vec_u32()
    elif t == T_COMPRESSION_DONE:
        d['is_compress'] = r.u8()
        d['method'] = r.u32()
    else:
        raise DecodeError("no decoder for tag %d" % t)
    if r.left():
        raise DecodeError("%s: %d trailing bytes" % (TAGS.get(t, t), r.left()))
    return d


class MsgHeader2:
    SIZE = 41

    def __init__(self, b):
        if len(b) < 41:
            raise DecodeError("segment 0 shorter than 41 bytes")
        (self.seq, self.tid, self.type, self.priority, self.version, self.pre_padding,
         self.data_off, self.ack_seq, self.flags, self.compat, self.reserved) = struct.unpack('<QQHHHIHQBHH', b[:41])
        self.extra = len(b) - 41


# ---------------------------------------------------------------------------
# 4. checks registry
# ---------------------------------------------------------------------------

class Results:
    def __init__(self):
        self.order = []
        self.info = {}       # id -> dict(desc, ok, fail, examples)
        self.observed = collections.defaultdict(collections.Counter)

    def declare(self, cid, desc):
        if cid not in self.info:
            self.order.append(cid)
            self.info[cid] = {'desc': desc, 'ok': 0, 'fail': 0, 'examples': []}

    def check(self, cid, cond, ctx=''):
        e = self.info[cid]
        if cond:
            e['ok'] += 1
        else:
            e['fail'] += 1
            if len(e['examples']) < 5:
                e['examples'].append(ctx)
        return cond

    def obs(self, cid, value):
        self.observed[cid][value] += 1

    def total(self):
        return (sum(e['ok'] for e in self.info.values()), sum(e['fail'] for e in self.info.values()))


R = Results()


def declare_all():
    D = R.declare
    D('TCP-1', 'TCP streams reassemble: retransmitted segments carry identical bytes (streams with capture holes are analysed up to the hole and listed as warnings)')
    D('BAN-1', 'banner: 8-byte prefix "ceph v2\\n", u16 payload length 16, two u64 masks (26 bytes)')
    D('BAN-2', 'server banner advertises supported = 3 (REVISION_1 | COMPRESSION), required = 0')
    D('BAN-3', 'stock client banner supported/required masks (observed)')
    D('BAN-4', 'client sends HELLO only after the server banner has been received (note 3.1 step 3)')
    D('AUT-12', 'server picks the first mode in the client\'s preferred list (lab allows both); stock defaults: mon list secure,crc ; OSD/mgr list crc,secure')
    D('KAL-4', 'stock client pings the monitor with KEEPALIVE2 every 10 s (9.5 - 10.5 s apart) and the monitor answers each with KEEPALIVE2_ACK')
    D('KAL-3', 'idle OSD connections: no KEEPALIVE2 in either direction during the idle window (observed)')
    D('FRM-1', 'every frame preamble CRC-32C (seed 0, bytes 0..27) matches')
    D('FRM-2', 'num_segments in 1..4 and last segment non-empty when n > 1; unused segments have length 0 and alignment 0')
    D('FRM-3', 'preamble flags byte == 0 and reserved byte == 0')
    D('FRM-4', 'control frames carry exactly one segment with alignment 8 (64-bit build)')
    D('FRM-5', 'MESSAGE segment alignments: header 8, front 8, middle 8, data 4096 (also for a present-but-empty segment)')
    D('FRM-6', 'rev-1 crc: segment 0 crc inline after segment 0 (seed 0xFFFFFFFF), present iff L0 > 0')
    D('FRM-7', 'rev-1 crc: epilogue (13 bytes) present iff n > 1; late_status == 0x0E')
    D('FRM-8', 'epilogue crc slot i-1 == crc32c(seg i, 0xFFFFFFFF); used-but-empty segment slot == 0xFFFFFFFF')
    D('FRM-9', 'epilogue crc slots of unused trailing segments are 0')
    D('FRM-10', 'frame chain: every stream parses to an exact frame boundary at its end (sizes follow the 2.6.1 formula)')
    D('FRM-11', 'frame size == 32 + (L0>0 ? L0+4 : 0) + L1+L2+L3 + (n>1 ? 13 : 0) (2.6.1)')
    D('TAG-1', 'every tag is in 1..22 and appears only in its documented direction')
    D('TAG-2', 'tag numbers: names of tags seen match the 2.4 table (decoded payload parses with no trailing bytes)')
    D('HEL-1', 'HELLO from client: entity type CLIENT (0x08); from server: MON 0x01 on mon ports, OSD 0x04 on OSD ports')
    D('HEL-2', 'HELLO peer_addr from client equals the dialled address (ip, port); from server equals the client socket address')
    D('ADR-1', 'entity_addr_t layout: marker 1, struct_v 1, struct_compat 1, struct_len 28, elen 16, family 2, port big-endian, 8 zero pad bytes')
    D('ADR-2', 'address type is never rewritten to LEGACY (1): the client\'s own address in CLIENT_IDENT is ANY (3); peer addresses (HELLO, target_addr, SERVER_IDENT) keep their map type MSGR2 (2)')
    D('ADR-3', 'addrvec: marker 2, count, entity_addr_t each (CLIENT_IDENT / SERVER_IDENT)')
    D('AUT-1', 'AUTH_REQUEST: method 2 (CEPHX), preferred modes vector, auth payload is a u32-length-prefixed blob')
    D('AUT-2', 'mon AUTH_REQUEST payload: 0x0a, EntityName (u32 8 + string), u64 global_id')
    D('AUT-3', 'mon AUTH_REPLY_MORE payload: CephXServerChallenge (u8 1, u64 challenge)')
    D('AUT-4', 'AUTH_REQUEST_MORE payload: header 0x0100 + CephXAuthenticate v3 {client_challenge, proof, old_ticket, other_keys}')
    D('AUT-5', 'cephx challenge proof (cephx 2.8) recomputed from the keyring equals the proof on the wire')
    D('AUT-6', 'AUTH_DONE: global_id u64, connection_mode u32 (1 crc / 2 secure), blob; mode is one the client offered')
    D('AUT-7', 'mon AUTH_DONE payload decrypts with the keyring (type 1 and type 2) and parses (cephx 2.7)')
    D('AUT-8', 'OSD/MGR AUTH_REQUEST authorizer layout and AUTH_REPLY_MORE challenge / AUTH_DONE reply decrypt with the ticket session key')
    D('AUT-9', 'AUTH_DONE global_id equals the one assigned by the mon and is used in later CLIENT_IDENT gid')
    D('AUT-10', 'AUTH_BAD_METHOD fields: method, result (negative errno), allowed methods, allowed modes')
    D('SIG-1', 'client AUTH_SIGNATURE == HMAC-SHA256(session key, every byte received from the server up to and including AUTH_DONE, banner and HELLO included)')
    D('SIG-2', 'server AUTH_SIGNATURE == HMAC-SHA256(session key, every byte the client sent before its own AUTH_SIGNATURE)')
    D('SIG-3', 'coverage is exactly that: the variants without the banner, or including the signature frame, do NOT verify')
    D('SIG-4', 'AUTH_SIGNATURE key is the raw session-key secret (mon: AUTH key; OSD: OSD ticket key)')
    D('CMP-1', 'stock client (banner supports COMPRESSION) sends COMPRESSION_REQUEST after AUTH_SIGNATURE; server answers COMPRESSION_DONE (is_compress=false)')
    D('IDN-1', 'CLIENT_IDENT: addrvec(1 addr, type 3, port 0, nonce per process), target_addr == dialled address bytewise, flags 1 + cookie 0 (lossy) or flags 0 + cookie != 0 (lossless)')
    D('IDN-2', 'CLIENT_IDENT gid: -1 on the first mon connection, the mon-assigned global_id afterwards')
    D('IDN-3', 'CLIENT_IDENT supported_features == 0x3f07fffffffdffff (CEPH_FEATURES_ALL, note 2.10)')
    D('IDN-4', 'CLIENT_IDENT required_features (observed; note says stock sends 0x0800000000001000)')
    D('IDN-5', 'CLIENT_IDENT global_seq starts at 1 per client messenger and increases with each new connection attempt (failed attempts consume values)')
    D('IDN-6', 'SERVER_IDENT: addrs contain target_addr, flags/cookie agree with the client (lossy 1/0, lossless 0/non-zero), masks observed')
    D('IDN-8', 'SERVER_IDENT.required: the client supported mask covers every bit the server reports as required (values observed per peer type)')
    D('IDN-7', 'the same client nonce is used on all connections of one process (nonce per process)')
    D('MSG-1', 'MESSAGE segment 0 is a 41-byte ceph_msg_header2; flags has COMPLETE (bit 0) set (value observed); data_pre_padding_len == 0; reserved == 0')
    D('MSG-2', 'MESSAGE seq starts at 1 and increases by 1 per direction per connection')
    D('MSG-3', 'MESSAGE data_off (observed), compat_version <= version, compat_version != 0')
    D('MSG-4', 'MESSAGE ack_seq never exceeds the highest seq received from the peer so far (lossy: ignored but sent)')
    D('MSG-5', 'MESSAGE segment lengths in the preamble equal front/middle/data lengths; a 4-segment frame has empty segments 2 (and 3) with length 0 in the middle')
    D('KAL-1', 'KEEPALIVE2 frame is 44 bytes (32 + 8 + 4); KEEPALIVE2_ACK echoes the stamp exactly')
    D('ACK-1', 'no ACK frames on lossy sessions (mon, OSD) (note 2.9)')
    D('SEC-1', 'secure mode: AUTH_DONE mode == 2, the connection secret is recovered from the auth payload and is >= 40 bytes (64)')
    D('SEC-2', 'secure mode: every frame after AUTH_DONE decrypts with AES-128-GCM (key = secret[0:16], nonces secret[16:28] for server->client, [28:40] for client->server)')
    D('SEC-3', 'secure mode: the first part of each frame is 96 bytes (32 preamble + 48 inline + 16 tag); preamble CRC verifies inside')
    D('SEC-4', 'secure mode: segment padding to 16 is zero; epilogue is late_status + 15 zero bytes; rev-1 has no inline seg-0 crc')
    D('SEC-5', 'secure mode: nonce counter is the last 8 bytes, incremented after every AEAD operation (64-bit, LE)')
    D('SEC-6', 'secure mode: total on-wire size of each frame follows the note (2.6.3) exactly, stream ends on a frame boundary')
    D('SEC-7', 'secure mode: AUTH_SIGNATURE frames (both directions) are inside the encrypted stream and verify as SIG-1/SIG-2')
    D('NEG-1', 'wrong key: server answers the first AUTH_REQUEST_MORE with AUTH_BAD_METHOD (-EACCES) or closes')
    D('NEG-2', 'caps tests (read-only / no OSD caps): the OSD op layer is reached (frames parse); see observations')
    D('VEC-1', 'note 5.1 computed vectors (CRC values, banners, entity_addr_t, HELLO, WAIT, KEEPALIVE2, ACK, MESSAGE) reproduced by this tool')
    
    D('ENC-1', 're-encoding every captured control frame (HELLO, AUTH_*, IDENT, COMPRESSION_*) from its decoded fields reproduces the captured bytes')


# ---- encoders (used for the re-encode check and for the vectors) -----------

def p_u8(v):
    return struct.pack('<B', v)


def p_u32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def p_u64(v):
    return struct.pack('<Q', v & 0xFFFFFFFFFFFFFFFF)


def p_blob(b):
    return p_u32(len(b)) + b


def p_vec_u32(v):
    return p_u32(len(v)) + b''.join(p_u32(x) for x in v)


def encode_addrvec(addrs):
    return b'\x02' + p_u32(len(addrs)) + b''.join(a.raw if isinstance(a, Addr) else a for a in addrs)


def encode_control(tag, d):
    if tag == T_HELLO:
        return p_u8(d['entity_type']) + d['peer_addr'].raw
    if tag == T_AUTH_REQUEST:
        return p_u32(d['method']) + p_vec_u32(d['modes']) + p_blob(d['payload'])
    if tag == T_AUTH_BAD_METHOD:
        return p_u32(d['method']) + struct.pack('<i', d['result']) + p_vec_u32(d['methods']) + p_vec_u32(d['modes'])
    if tag in (T_AUTH_REPLY_MORE, T_AUTH_REQUEST_MORE):
        return p_blob(d['payload'])
    if tag == T_AUTH_DONE:
        return p_u64(d['global_id']) + p_u32(d['mode']) + p_blob(d['payload'])
    if tag == T_AUTH_SIGNATURE:
        return d['sig']
    if tag == T_CLIENT_IDENT:
        return (encode_addrvec(d['addrs']) + d['target'].raw + struct.pack('<q', d['gid']) + p_u64(d['global_seq'])
                + p_u64(d['supported']) + p_u64(d['required']) + p_u64(d['flags']) + p_u64(d['cookie']))
    if tag == T_SERVER_IDENT:
        return (encode_addrvec(d['addrs']) + struct.pack('<q', d['gid']) + p_u64(d['global_seq'])
                + p_u64(d['supported']) + p_u64(d['required']) + p_u64(d['flags']) + p_u64(d['cookie']))
    if tag == T_IDENT_MISSING:
        return p_u64(d['features'])
    if tag in (T_KEEPALIVE2, T_KEEPALIVE2_ACK):
        return p_u32(d['sec']) + p_u32(d['nsec'])
    if tag == T_ACK:
        return p_u64(d['seq'])
    if tag == T_WAIT:
        return b''
    if tag == T_COMPRESSION_REQUEST:
        return p_u8(d['is_compress']) + p_vec_u32(d['methods'])
    if tag == T_COMPRESSION_DONE:
        return p_u8(d['is_compress']) + p_u32(d['method'])
    raise DecodeError("no encoder for tag %d" % tag)


def build_frame(tag, segs, aligns=None):
    """Build a rev-1 crc frame (note 2.6.1). Trailing empty segments are dropped, at least one is kept."""
    segs = list(segs)
    while len(segs) > 1 and len(segs[-1]) == 0:
        segs.pop()
    n = len(segs)
    if aligns is None:
        aligns = [8] * n
    pre = bytearray(32)
    pre[0] = tag
    pre[1] = n
    for i in range(n):
        struct.pack_into('<IH', pre, 2 + 6 * i, len(segs[i]), aligns[i])
    struct.pack_into('<I', pre, 28, crc32c(bytes(pre[:28]), 0))
    out = bytes(pre)
    if segs[0]:
        out += segs[0] + p_u32(crc32c(segs[0], 0xFFFFFFFF))
    for s in segs[1:]:
        out += s
    if n > 1:
        slots = [crc32c(segs[i], 0xFFFFFFFF) if i < n else 0 for i in (1, 2, 3)]
        out += b'\x0e' + b''.join(p_u32(x) for x in slots)
    return out


# ---- cephx structures (cephx note 2.7) -------------------------------------

def decode_ticket_blob(r):
    """CephXTicketBlob -> (secret_id, data, raw bytes)"""
    start = r.o
    v = r.u8()
    sid = r.u64()
    data = r.blob()
    return sid, data, r.d[start:r.o]


def decode_service_ticket(plain):
    r = Reader(plain)
    r.u8()
    kt = r.u16()
    c = (r.u32(), r.u32())
    ln = r.u16()
    sec = r.take(ln)
    validity = (r.u32(), r.u32())
    return CryptoKey(kt, sec, c), validity


def parse_ticket_reply(r, key, prev_key=None):
    """Parse a ticket reply (cephx 2.7). Returns list of dict(service_id, key, validity, blob_raw, secret_id)."""
    out = []
    r.u8()
    num = r.u32()
    for _ in range(num):
        sid = r.u32()
        r.u8()
        msg_a = r.blob()
        sk, validity = decode_service_ticket(open_envelope(key, msg_a, 4))
        enc = r.u8()
        if enc == 0:
            bl = r.blob()
        else:
            ct = r.blob()
            if prev_key is None:
                raise DecodeError("ticket_enc=1 without previous key")
            inner = Reader(open_envelope(prev_key, ct, 5))
            bl = inner.blob()
        sec_id, data, raw = decode_ticket_blob(Reader(bl))
        out.append({'service_id': sid, 'key': sk, 'validity': validity, 'blob_raw': raw, 'secret_id': sec_id})
    return out


def proof_v2(secret, server_ch, client_ch):
    d = hmac.new(secret, struct.pack('<QQ', server_ch, client_ch), hashlib.sha256).digest()
    x = 0
    for i in range(4):
        x ^= u64(d, 8 * i)
    return x


def proof_v1(key, server_ch, client_ch):
    blob = struct.pack('<QQ', server_ch, client_ch)
    ct = key.encrypt(b'\x01' + struct.pack('<Q', CEPHX_MAGIC) + blob, 0)
    enc = p_u32(len(ct)) + ct
    x = 0
    for i in range(len(enc) // 8):
        x ^= u64(enc, 8 * i)
    return x


def proof_for(key, server_ch, client_ch):
    return proof_v1(key, server_ch, client_ch) if key.type == 1 else proof_v2(key.secret, server_ch, client_ch)


# ---------------------------------------------------------------------------
# 5. per-connection analysis
# ---------------------------------------------------------------------------

C2S_TAGS = {1, 2, 5, 7, 8, 11, 17, 18, 19, 20, 21}
S2C_TAGS = {1, 3, 4, 6, 7, 9, 10, 12, 13, 14, 15, 16, 17, 18, 19, 20, 22}
PLAIN_C2S_AUTH = {T_HELLO, T_AUTH_REQUEST, T_AUTH_REQUEST_MORE}

EXPECTED_FEATURES_ALL = 0x3f07fffffffdffff
LOSSY = 1


class Keystore:
    def __init__(self):
        self.tickets = {}        # raw CephXTicketBlob bytes -> (service_id, CryptoKey)
        self.auth_key = None
        self.global_id = None
        self.unknown_tickets = 0

    def add(self, replies):
        for t in replies:
            self.tickets[t['blob_raw']] = (t['service_id'], t['key'])


def ts_of(td, endoff):
    """capture time of the packet that carried stream byte endoff-1 (first transmission)."""
    best = None
    for ts, off, ln in td.pkts:
        if off <= endoff - 1 < off + ln:
            return ts
        if off <= endoff - 1:
            best = ts
    return best


class ConnInfo:
    def __init__(self, conn, idx, session):
        self.conn = conn
        self.idx = idx
        self.session = session
        self.c2s = []
        self.s2c = []
        self.peer_type = None
        self.mode = None
        self.session_key = None
        self.secret = None
        self.client_ident = None
        self.server_ident = None
        self.hello_c = None
        self.hello_s = None
        self.global_id = None
        self.auth_kind = None      # 'mon' | 'authorizer' | None
        self.bad_method = None
        self.msgs = {'c2s': [], 's2c': []}
        self.ctx = '%s#%d:%d' % (session, idx, conn.key[3])


def walk_plain(buf, off, direction, stop=None, allow_tags=None):
    """Parse plain frames from buf[off:]; return (frames, offset_after, status). status in
    'end' (exact end), 'trunc' (partial frame at end), 'stop', 'bad' (frame with a structural problem)."""
    frames = []
    while True:
        if off == len(buf):
            return frames, off, 'end'
        try:
            fr = parse_plain_frame(buf, off)
        except Truncated:
            return frames, off, 'trunc'
        fr.direction = direction
        if stop is not None and not stop(fr):
            return frames, off, 'stop'
        frames.append(fr)
        if any(c in ('P-CRC', 'P-NSEG') for c, _ in fr.problems):
            return frames, fr.end, 'bad'
        off = fr.end


def walk_secure(buf, off, direction, aead):
    frames = []
    while True:
        if off == len(buf):
            return frames, off, 'end'
        try:
            fr = parse_secure_frame(buf, off, aead)
        except Truncated:
            return frames, off, 'trunc'
        except DecodeError as e:
            return frames, off, 'bad:' + str(e)
        fr.direction = direction
        frames.append(fr)
        if any(c in ('P-CRC', 'P-NSEG') for c, _ in fr.problems):
            return frames, fr.end, 'bad'
        off = fr.end


def check_frame_structure(ci, fr, plain=True):
    ctx = '%s %s %s@%d' % (ci.ctx, fr.direction, fr.name, fr.off)
    probs = {c for c, _ in fr.problems}
    R.check('FRM-1', 'P-CRC' not in probs, ctx)
    R.check('FRM-2', not ({'P-NSEG', 'P-LAST', 'P-UNUSED'} & probs), ctx + ' ' + str(fr.problems))
    R.check('FRM-3', fr.flags == 0 and fr.reserved == 0, ctx + ' flags=%d rsv=%d' % (fr.flags, fr.reserved))
    n = fr.nseg if 1 <= fr.nseg <= 4 else 0
    if n == 0:
        return
    if fr.tag == T_MESSAGE:
        want = [8, 8, 8, 4096]
        R.check('FRM-5', fr.aligns[:n] == want[:n], ctx + ' aligns %s' % fr.aligns[:n])
        R.obs('FRM-5', tuple(fr.aligns[:n]))
    else:
        R.check('FRM-4', n == 1 and fr.aligns[0] == 8, ctx + ' n=%d aligns %s' % (n, fr.aligns[:n]))
        R.obs('FRM-4', (n, fr.aligns[0]))
    if plain:
        if fr.lens[0] > 0:
            R.check('FRM-6', 'S0-CRC' not in probs and fr.seg0_crc is not None, ctx)
        else:
            R.check('FRM-6', fr.seg0_crc is None, ctx)
        size = 32 + (fr.lens[0] + 4 if fr.lens[0] > 0 else 0) + sum(fr.lens[1:n]) + (EPILOGUE_LEN if n > 1 else 0)
        R.check('FRM-11', fr.end - fr.off == size, ctx + ' size %d vs %d' % (fr.end - fr.off, size))
        if n > 1:
            R.check('FRM-7', fr.late_status == LATE_COMPLETE, ctx + ' late=0x%x' % (fr.late_status or 0))
            for i in range(1, 4):
                slot = fr.epi_crcs[i - 1]
                if i < n:
                    if fr.lens[i] == 0:
                        R.check('FRM-8', slot == 0xFFFFFFFF, ctx + ' empty seg %d slot 0x%08x' % (i, slot))
                    else:
                        R.check('FRM-8', slot == crc32c(fr.segs[i], 0xFFFFFFFF), ctx + ' seg %d' % i)
                else:
                    R.check('FRM-9', slot == 0, ctx + ' slot %d' % (i - 1))
        else:
            R.check('FRM-7', fr.late_status is None, ctx)
    # tag / direction table
    allowed = C2S_TAGS if fr.direction == 'c2s' else S2C_TAGS
    R.check('TAG-1', 1 <= fr.tag <= 22 and fr.tag in allowed, ctx)


def hmac256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def load_keyrings(dirs):
    """{entity: [CryptoKey,...]} from every *.keyring found in dirs."""
    out = collections.defaultdict(list)
    for d in dirs:
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if fn.endswith('.keyring') or fn.endswith('.keyring.txt'):
                try:
                    for ent, k in parse_keyring(os.path.join(d, fn)).items():
                        out[ent].append(k)
                except Exception:
                    pass
    return out


def addr_checks(ci, a, what, ctx, expect_type=None):
    ok = (a.marker == 1 and a.struct_v == 1 and a.struct_compat == 1 and a.struct_len == 28 and a.elen == 16
          and a.family == 2 and len(a.sa) == 14 and a.sa[6:] == b'\x00' * 8 and len(a.raw) == 35)
    R.check('ADR-1', ok, '%s %s %r raw=%s' % (ctx, what, a, a.raw.hex()))
    want = 3 if what == 'ident-addr' else 2
    R.obs('ADR-2:' + what + '(type)', a.type)
    R.check('ADR-2', a.type == want, '%s %s type=%d (expected %d)' % (ctx, what, a.type, want))


def analyze_conn(ci, keystore, keyrings, res_extra):
    conn = ci.conn
    ctx = ci.ctx
    c2s, gc = conn.c2s.assemble()
    s2c, gs = conn.s2c.assemble()
    R.check('TCP-1', conn.c2s.conflicts == 0 and conn.s2c.conflicts == 0,
            '%s conflicts %d/%d' % (ctx, conn.c2s.conflicts, conn.s2c.conflicts))
    ci.gap = bool(gc or gs)
    if ci.gap:
        res_extra['gaps'].append('%s: packet loss in the capture (c2s holes %d, s2c holes %d); analysed up to the first hole (%d / %d bytes)'
                                 % (ctx, gc, gs, len(c2s), len(s2c)))
    if not c2s and not s2c:
        R.obs('TCP-1:connections with no payload (refused / reset)', True)
        return
    res_extra['retrans'] += conn.c2s.retrans + conn.s2c.retrans
    # --- banners ---
    for name, buf in (('client', c2s), ('server', s2c)):
        ok = (len(buf) >= 26 and buf[:8] == b'ceph v2\n' and u16(buf, 8) == 16)
        R.check('BAN-1', ok, '%s %s %s' % (ctx, name, buf[:26].hex()))
        if not ok:
            return
    sup_s, req_s = u64(s2c, 10), u64(s2c, 18)
    R.check('BAN-2', (sup_s, req_s) == (3, 0), '%s server %x/%x' % (ctx, sup_s, req_s))
    sup_c, req_c = u64(c2s, 10), u64(c2s, 18)
    t_ban_s = ts_of(conn.s2c, 26)
    R.obs('BAN-3', (hex(sup_c), hex(req_c)))
    R.check('BAN-3', req_c == 0 and (sup_c & 1) == 1, ctx)
    # --- unauthenticated phase frames ---
    s_frames, s_off, s_status = walk_plain(s2c, 26, 's2c', stop=None)
    # server frames up to and including AUTH_DONE / BAD_METHOD are always plain
    cut = len(s_frames)
    for i, f in enumerate(s_frames):
        if f.tag in (T_AUTH_DONE, T_AUTH_BAD_METHOD):
            cut = i + 1
            break
    pre_s = s_frames[:cut]
    c_frames, c_off, c_status = walk_plain(
        c2s, 26, 'c2s', stop=lambda f: f.tag in PLAIN_C2S_AUTH and not any(c == 'P-CRC' for c, _ in f.problems))
    ci.c2s = list(c_frames)
    ci.s2c = list(pre_s)
    auth_done = next((f for f in pre_s if f.tag == T_AUTH_DONE), None)
    bad = next((f for f in pre_s if f.tag == T_AUTH_BAD_METHOD), None)
    for f in ci.c2s + ci.s2c:
        check_frame_structure(ci, f)
    # --- HELLO ---
    hc = next((f for f in ci.c2s if f.tag == T_HELLO), None)
    hs = next((f for f in ci.s2c if f.tag == T_HELLO), None)
    srv_ip, srv_port = conn.key[2], conn.key[3]
    cli_ip, cli_port = conn.key[0], conn.key[1]
    if hc is not None and t_ban_s is not None:
        t_h = ts_of(conn.c2s, hc.off + 1)
        R.check('BAN-4', t_h is not None and t_h >= t_ban_s, '%s hello %.6f banner %.6f' % (ctx, t_h or -1, t_ban_s))
        R.obs('BAN-4:client_banner_before_server_banner', (ts_of(conn.c2s, 26) or 0) <= t_ban_s)
    if hc and hs:
        dc, ds = decode_control(hc), decode_control(hs)
        ci.hello_c, ci.hello_s = dc, ds
        ci.peer_type = ds['entity_type']
        R.check('HEL-1', dc['entity_type'] == 0x08 and ds['entity_type'] in ((0x01,) if srv_port == 3300 else (0x04, 0x10)),
                '%s c=%x s=%x' % (ctx, dc['entity_type'], ds['entity_type']))
        R.obs('HEL-1', (ENTITY_TYPES.get(dc['entity_type']), ENTITY_TYPES.get(ds['entity_type']), srv_port if srv_port == 3300 else 'osd-port'))
        addr_checks(ci, dc['peer_addr'], 'client-hello', ctx)
        addr_checks(ci, ds['peer_addr'], 'server-hello', ctx)
        R.check('HEL-2', (dc['peer_addr'].ip4, dc['peer_addr'].port) == (srv_ip, srv_port)
                and (ds['peer_addr'].ip4, ds['peer_addr'].port) == (cli_ip, cli_port),
                '%s %r %r' % (ctx, dc['peer_addr'], ds['peer_addr']))
        R.obs('HEL-2:client-hello(type,nonce)', (dc['peer_addr'].type, dc['peer_addr'].nonce))
        R.obs('HEL-2:server-hello(type,nonce)', (ds['peer_addr'].type, ds['peer_addr'].nonce))
    # --- AUTH_REQUEST etc. decode ---
    reqs = [f for f in ci.c2s if f.tag in (T_AUTH_REQUEST, T_AUTH_REQUEST_MORE)]
    for f in ci.c2s + ci.s2c:
        try:
            f.d = decode_control(f)
            R.check('TAG-2', True)
        except DecodeError as e:
            f.d = None
            R.check('TAG-2', False, '%s %s: %s' % (ctx, f.name, e))
    areq = next((f for f in ci.c2s if f.tag == T_AUTH_REQUEST), None)
    if areq and areq.d:
        R.check('AUT-1', areq.d['method'] == 2 and areq.d['modes'] in ([1], [2], [1, 2], [2, 1]),
                '%s method=%d modes=%s' % (ctx, areq.d['method'], areq.d['modes']))
        R.obs('AUT-1:modes', tuple(areq.d['modes']))
    if bad and bad.d:
        R.obs('AUT-10', (bad.d['method'], bad.d['result'], tuple(bad.d['methods']), tuple(bad.d['modes'])))
        R.check('AUT-10', bad.d['result'] in (-13, -95) and bad.d['methods'] == [2] and sorted(bad.d['modes']) == [1, 2]
                and (bad.d['method'] == 2 or bad.d['result'] == -95), ctx + str(bad.d))
        ci.bad_method = bad.d
    if not auth_done:
        # failed authentication: whatever else is on the wire is still plain
        s_rest, s_off, s_status = walk_plain(s2c, pre_s[-1].end if pre_s else 26, 's2c')
        c_rest, c_off, c_status = walk_plain(c2s, c_off, 'c2s')
        for f in s_rest + c_rest:
            check_frame_structure(ci, f)
            try:
                f.d = decode_control(f) if f.tag != T_MESSAGE else None
            except DecodeError:
                f.d = None
        ci.s2c += s_rest
        ci.c2s += c_rest
        return finish_conn(ci, c2s, s2c, c_off, s_off, c_status, s_status, early=True)
    ci.global_id = auth_done.d['global_id'] if auth_done.d else None
    mode = auth_done.d['mode']
    ci.mode = mode
    if areq is not None and areq.d:
        R.check('AUT-12', mode == areq.d['modes'][0], '%s offered=%s chosen=%d' % (ctx, areq.d['modes'], mode))
        R.obs('AUT-12:(peer, offered, chosen)', (ENTITY_TYPES.get(ci.peer_type), tuple(areq.d['modes']), mode))
    R.check('AUT-6', mode in (1, 2) and (areq is None or mode in areq.d['modes']),
            '%s mode=%d offered=%s' % (ctx, mode, areq.d['modes'] if areq else None))
    # --- cephx ---
    secret, sess_key = derive_session(ci, keystore, keyrings, areq, auth_done)
    ci.session_key = sess_key
    ci.secret = secret
    # --- continue frame walk ---
    if mode == 1:
        s_rest, s_off, s_status = walk_plain(s2c, pre_s[-1].end, 's2c')
        c_rest, c_off, c_status = walk_plain(c2s, c_off, 'c2s')
        for f in s_rest + c_rest:
            check_frame_structure(ci, f)
            try:
                f.d = decode_control(f) if f.tag != T_MESSAGE else None
                R.check('TAG-2', True)
            except DecodeError as e:
                f.d = None
                R.check('TAG-2', False, '%s %s: %s' % (ctx, f.name, e))
        ci.s2c += s_rest
        ci.c2s += c_rest
    elif mode == 2:
        if secret is None or len(secret) < 40:
            R.check('SEC-1', False, ctx + ' no connection secret')
            return finish_conn(ci, c2s, s2c, c_off, s_off, c_status, s_status, early=True)
        R.check('SEC-1', True, ctx)
        key = secret[:16]
        a_s2c = Aead(key, secret[16:28])
        a_c2s = Aead(key, secret[28:40])
        # client frames: plain until the first frame that is not HELLO/AUTH_REQUEST(_MORE) under the plain parse
        s_rest, s_off, s_status = walk_secure(s2c, pre_s[-1].end, 's2c', a_s2c)
        c_rest, c_off2, c_status = walk_secure(c2s, c_off, 'c2s', a_c2s)
        R.check('SEC-2', not str(s_status).startswith('bad') and not str(c_status).startswith('bad'),
                '%s s2c=%s c2s=%s' % (ctx, s_status, c_status))
        R.check('SEC-6', s_status in ('end', 'trunc') and c_status in ('end', 'trunc'),
                '%s s2c=%s c2s=%s' % (ctx, s_status, c_status))
        c_status_sec, s_status_sec = c_status, s_status
        c_status, s_status = c_status, s_status
        c_off, s_off = c_off2, s_off
        for f in s_rest + c_rest:
            check_frame_structure(ci, f, plain=False)
            R.check('SEC-3', len(f.raw) >= 96 and not [p for p in f.problems if p[0] in ('P-CRC',)], '%s %s' % (ctx, f.name))
            R.check('SEC-4', not [p for p in f.problems if p[0] in ('SEC-PAD', 'SEC-EPI')], '%s %s %s' % (ctx, f.name, f.problems))
            try:
                f.d = decode_control(f) if f.tag != T_MESSAGE else None
                R.check('TAG-2', True)
            except DecodeError as e:
                f.d = None
                R.check('TAG-2', False, '%s %s: %s' % (ctx, f.name, e))
        # nonce counter bookkeeping: one op per AEAD run
        R.check('SEC-5', a_s2c.ops > 0 and a_c2s.ops > 0, ctx)
        ci.s2c += s_rest
        ci.c2s += c_rest
    # --- AUTH_SIGNATURE ---
    check_signatures(ci, c2s, s2c, sess_key, auth_done)
    return finish_conn(ci, c2s, s2c, c_off, s_off, c_status, s_status)


def derive_session(ci, ks, keyrings, areq, auth_done):
    """cephx hand-shake decode for this connection (cephx note 2.7, 3.2, 3.3).
    Returns (connection_secret or None, session_key CryptoKey or None)."""
    ctx = ci.ctx
    if areq is None or areq.d is None or auth_done.d is None:
        return None, None
    payload = areq.d['payload']
    c2s_more = [f for f in ci.c2s if f.tag == T_AUTH_REQUEST_MORE and f.d]
    s2c_more = [f for f in ci.s2c if f.tag == T_AUTH_REPLY_MORE and f.d]
    done = auth_done.d
    try:
        if payload and payload[0] == 10:
            ci.auth_kind = 'mon'
            r = Reader(payload)
            r.u8()
            etype = r.u32()
            eid = r.string().decode()
            gid = r.u64()
            R.check('AUT-2', etype == 8 and r.left() == 0, '%s etype=%d left=%d' % (ctx, etype, r.left()))
            R.obs('AUT-2:global_id_in_request', 'zero' if gid == 0 else 'nonzero')
            if len(s2c_more) != 1 or len(c2s_more) != 1:
                R.check('AUT-3', False, '%s reply_more=%d request_more=%d' % (ctx, len(s2c_more), len(c2s_more)))
                return None, None
            rc = Reader(s2c_more[0].d['payload'])
            v, chal = rc.u8(), rc.u64()
            R.check('AUT-3', v == 1 and rc.left() == 0 and chal != 0, ctx)
            rm = Reader(c2s_more[0].d['payload'])
            rtype = rm.u16()
            av = rm.u8()
            cch = rm.u64()
            proof = rm.u64()
            old = decode_ticket_blob(rm)
            other = rm.u32()
            R.check('AUT-4', rtype == 0x0100 and av == 3 and rm.left() == 0, '%s rt=%x v=%d left=%d' % (ctx, rtype, av, rm.left()))
            R.obs('AUT-4:old_ticket_len', len(old[1]))
            R.obs('AUT-4:other_keys', hex(other))
            cands = keyrings.get('client.' + eid, [])
            user_key = None
            for k in cands:
                if proof_for(k, chal, cch) == proof:
                    user_key = k
                    break
            if user_key is None:
                if cands:
                    R.check('AUT-5', False, '%s no keyring candidate reproduces the proof for client.%s' % (ctx, eid))
                return None, None
            R.check('AUT-5', True, ctx)
            R.obs('AUT-5:key_type', user_key.type)
            pr = Reader(done['payload'])
            rt = pr.u16()
            status = pr.s32()
            tick = parse_ticket_reply(pr, user_key, ks.auth_key)
            auth_key = tick[0]['key']
            secret = None
            if pr.left():
                cbl = pr.blob()
                if cbl:
                    inner = Reader(cbl).blob()
                    sr = Reader(open_envelope(auth_key, inner, 3))
                    secret = sr.string()
                    R.obs('AUT-7:connection_secret_len', len(secret))
                extra = pr.blob()
                if extra:
                    ks.add(parse_ticket_reply(Reader(extra), auth_key))
            R.check('AUT-7', rt == 0x0100 and status == 0 and tick[0]['service_id'] == 0x20 and len(tick) == 1 and pr.left() == 0,
                    '%s rt=%x status=%d n=%d left=%d' % (ctx, rt, status, len(tick), pr.left()))
            R.obs('AUT-7:auth_key_type', auth_key.type)
            R.obs('AUT-7:auth_ticket_validity_s', tick[0]['validity'][0])
            ks.auth_key = auth_key
            ks.global_id = done['global_id']
            R.check('AUT-9', done['global_id'] != 0, ctx)
            return (secret if secret else None), auth_key
        elif payload and 1 <= payload[0] <= 9:
            ci.auth_kind = 'authorizer'
            r = Reader(payload)
            av = r.u8()
            gid = r.u64()
            svc = r.u32()
            sid, data, raw = decode_ticket_blob(r)
            proof = r.blob()
            R.check('AUT-8', av == 1 and r.left() == 0 and svc in (4, 0x10), '%s v=%d svc=%d left=%d' % (ctx, av, svc, r.left()))
            ent = ks.tickets.get(raw)
            if ent is None:
                ks.unknown_tickets += 1
                R.check('AUT-8', False, '%s ticket blob (secret_id %d) not delivered by any mon reply in this capture' % (ctx, sid))
                return None, None
            tkey = ent[1]
            a1 = Reader(open_envelope(tkey, proof, 0x10))
            av1, nonce, have, plus = a1.u8(), a1.u64(), a1.u8(), a1.u64()
            R.check('AUT-8', av1 == 2 and have == 0 and plus == 0 and a1.left() == 0, '%s authorize1 v=%d have=%d' % (ctx, av1, have))
            if len(s2c_more) != 1 or len(c2s_more) != 1:
                R.check('AUT-8', False, '%s reply_more=%d request_more=%d' % (ctx, len(s2c_more), len(c2s_more)))
                return None, tkey
            ch = Reader(open_envelope(tkey, s2c_more[0].d['payload'], 0x11))
            cv, cchal = ch.u8(), ch.u64()
            R.check('AUT-8', cv == 1 and ch.left() == 0, ctx + ' challenge')
            r2 = Reader(c2s_more[0].d['payload'])
            av2 = r2.u8()
            gid2 = r2.u64()
            svc2 = r2.u32()
            sid2, data2, raw2 = decode_ticket_blob(r2)
            proof2 = r2.blob()
            a2 = Reader(open_envelope(tkey, proof2, 0x10))
            av2b, nonce2, have2, plus2 = a2.u8(), a2.u64(), a2.u8(), a2.u64()
            R.check('AUT-8', (av2, gid2, svc2, raw2) == (av, gid, svc, raw) and nonce2 == nonce and have2 == 1
                    and plus2 == (cchal + 1) & 0xFFFFFFFFFFFFFFFF, '%s authorize2' % ctx)
            fr = Reader(done['payload'])
            ct = fr.blob()
            R.check('AUT-8', fr.left() == 0, ctx + ' done framing')
            rp = Reader(open_envelope(tkey, ct, 0x12))
            rv, nplus = rp.u8(), rp.u64()
            secret = None
            if rv >= 2:
                secret = rp.string()
            R.check('AUT-8', nplus == (nonce + 1) & 0xFFFFFFFFFFFFFFFF and rp.left() == 0, '%s reply v=%d' % (ctx, rv))
            R.obs('AUT-8:reply_v', rv)
            R.obs('AUT-8:service_key_type', tkey.type)
            R.check('AUT-9', gid == ks.global_id and done['global_id'] != 0, '%s gid=%d mon gid=%s done gid=%d' % (ctx, gid, ks.global_id, done['global_id']))
            R.obs('AUT-9:done_global_id_equals_authorizer_gid', done['global_id'] == gid)
            return (secret if secret else None), tkey
        else:
            R.check('AUT-1', False, '%s unknown auth payload prefix' % ctx)
    except DecodeError as e:
        if ci.auth_kind == 'mon':
            R.check('AUT-7', False, '%s %s' % (ctx, e))
        else:
            R.check('AUT-8', False, '%s %s' % (ctx, e))
    return None, None


def check_signatures(ci, c2s, s2c, sk, auth_done):
    ctx = ci.ctx
    sig_c = next((f for f in ci.c2s if f.tag == T_AUTH_SIGNATURE and f.d), None)
    sig_s = next((f for f in ci.s2c if f.tag == T_AUTH_SIGNATURE and f.d), None)
    if sk is None or sig_c is None or sig_s is None:
        if sk is not None:
            R.check('SIG-1', False, ctx + ' missing AUTH_SIGNATURE frame')
        return
    key = sk.secret
    exp_c = hmac256(key, s2c[:auth_done.end])
    exp_s = hmac256(key, c2s[:sig_c.off])
    R.check('SIG-1', sig_c.d['sig'] == exp_c, ctx)
    R.check('SIG-2', sig_s.d['sig'] == exp_s, ctx)
    R.check('SIG-4', sig_c.d['sig'] == exp_c and sig_s.d['sig'] == exp_s, ctx)
    # coverage alternatives must NOT verify
    alt_c = [hmac256(key, s2c[26:auth_done.end]),                       # without banner
             hmac256(key, s2c[:auth_done.off]),                         # without AUTH_DONE itself
             hmac256(key, s2c[:auth_done.end] + sig_s.raw)]             # including the server's signature frame
    alt_s = [hmac256(key, c2s[26:sig_c.off]),
             hmac256(key, c2s[:sig_c.end])]
    R.check('SIG-3', all(a != sig_c.d['sig'] for a in alt_c) and all(a != sig_s.d['sig'] for a in alt_s), ctx)
    if ci.mode == 2:
        R.check('SEC-7', sig_c.d['sig'] == exp_c and sig_s.d['sig'] == exp_s and sig_c.secure and sig_s.secure, ctx)
    R.obs('SIG-4:key_source', ci.auth_kind)


def finish_conn(ci, c2s, s2c, c_off, s_off, c_status, s_status, early=False):
    ctx = ci.ctx
    conn = ci.conn
    # frame-chain end state
    R.check('FRM-10', c_status in ('end', 'trunc') and s_status in ('end', 'trunc') or early or ci.gap,
            '%s c2s=%s s2c=%s' % (ctx, c_status, s_status))
    R.obs('FRM-10:end_state', (c_status, s_status))
    # re-encode every plain control frame from its decoded fields
    for f in ci.c2s + ci.s2c:
        if f.secure or f.d is None or f.tag == T_MESSAGE:
            continue
        try:
            re = build_frame(f.tag, [encode_control(f.tag, f.d)])
        except DecodeError:
            continue
        R.check('ENC-1', re == f.raw, '%s %s' % (ctx, f.name))
    # compression
    creq = [f for f in ci.c2s if f.tag == T_COMPRESSION_REQUEST and f.d]
    cdone = [f for f in ci.s2c if f.tag == T_COMPRESSION_DONE and f.d]
    sigs_c = [f for f in ci.c2s if f.tag == T_AUTH_SIGNATURE]
    if ci.mode in (1, 2):
        stock = (u64(c2s, 10) & 2) != 0
        if stock:
            ok = len(creq) == 1 and len(cdone) == 1
            if ok:
                idx_c = ci.c2s.index(creq[0])
                idx_s = ci.s2c.index(cdone[0])
                ok = ci.c2s[idx_c - 1].tag == T_AUTH_SIGNATURE and ci.s2c[idx_s - 1].tag == T_AUTH_SIGNATURE
                R.obs('CMP-1', (creq[0].d['is_compress'], tuple(creq[0].d['methods']), cdone[0].d['is_compress'], cdone[0].d['method']))
                ok = ok and creq[0].d['is_compress'] == 0 and cdone[0].d['is_compress'] == 0
            R.check('CMP-1', ok, ctx)
    # idents
    cid = next((f for f in ci.c2s if f.tag == T_CLIENT_IDENT and f.d), None)
    sid = next((f for f in ci.s2c if f.tag == T_SERVER_IDENT and f.d), None)
    if cid:
        d = cid.d
        ci.client_ident = d
        a = d['addrs']
        cli_ip = conn.key[0]
        R.check('ADR-3', len(a) == 1, ctx)
        for x in a:
            addr_checks(ci, x, 'ident-addr', ctx)
        addr_checks(ci, d['target'], 'ident-target', ctx)
        hello_dialled = ci.hello_c['peer_addr'] if ci.hello_c else None
        lossy = d['flags'] == LOSSY and d['cookie'] == 0
        lossless = d['flags'] == 0 and d['cookie'] != 0
        R.obs('IDN-1:policy by peer', (ENTITY_TYPES.get(ci.peer_type), 'lossy(flags=1,cookie=0)' if lossy else ('lossless(flags=0,cookie!=0)' if lossless else 'other')))
        R.check('IDN-1', len(a) == 1 and a[0].type == 3 and a[0].port == 0 and a[0].ip4 == cli_ip and (lossy or lossless)
                and hello_dialled is not None and d['target'].raw == hello_dialled.raw,
                '%s addrs=%s target=%r flags=%d cookie=%d' % (ctx, a, d['target'], d['flags'], d['cookie']))
        R.obs('IDN-1:target_vs_hello_peer_addr_equal', hello_dialled is not None and d['target'].raw == hello_dialled.raw)
        R.obs('IDN-1:ident_addr_ip_matches_hello_learned_ip', bool(ci.hello_s) and a[0].ip4 == ci.hello_s['peer_addr'].ip4)
        R.obs('IDN-1:target(type,nonce)', (d['target'].type, d['target'].nonce))
        R.check('IDN-3', d['supported'] == EXPECTED_FEATURES_ALL, '%s supported=%#x' % (ctx, d['supported']))
        R.obs('IDN-3', hex(d['supported']))
        R.obs('IDN-4', hex(d['required']))
        R.check('IDN-4', d['required'] & 0x0800000000000000 == 0x0800000000000000, ctx)
    if sid and cid:
        sd = sid.d
        ci.server_ident = sd
        ci.lossy = sd['flags'] == LOSSY
        R.obs('IDN-6:(peer, client flags, server flags, server cookie!=0)', (ENTITY_TYPES.get(ci.peer_type), cid.d['flags'], sd['flags'], sd['cookie'] != 0))
        R.check('IDN-6', any(x.raw == cid.d['target'].raw for x in sd['addrs'])
                and ((sd['flags'] == LOSSY and sd['cookie'] == 0) or (sd['flags'] == 0 and sd['cookie'] != 0))
                and True,
                '%s flags=%d cookie=%d addrs=%s target=%r' % (ctx, sd['flags'], sd['cookie'], sd['addrs'], cid.d['target']))
        R.check('IDN-8', cid.d['supported'] & sd['required'] == sd['required'], '%s required %#x' % (ctx, sd['required']))
        R.obs('IDN-8:server required by peer', (ENTITY_TYPES.get(ci.peer_type), hex(sd['required'])))
        R.obs('IDN-6:supported', hex(sd['supported']))
        R.obs('IDN-6:required', hex(sd['required']))
        R.obs('IDN-6:global_seq', sd['global_seq'])
        R.obs('IDN-6:server_gid_kind', 'mon' if conn.key[3] == 3300 else 'osd')
    # messages
    msgs = {}
    for dname, frames, td in (('c2s', ci.c2s, conn.c2s), ('s2c', ci.s2c, conn.s2c)):
        ml = []
        for f in frames:
            if f.tag != T_MESSAGE:
                continue
            ctxm = '%s %s@%d' % (ctx, dname, f.off)
            try:
                h = MsgHeader2(f.segs[0])
            except DecodeError as e:
                R.check('MSG-1', False, '%s %s' % (ctxm, e))
                continue
            h.frame = f
            h.ts = ts_of(td, f.end)
            ml.append(h)
            R.obs('MSG-1:flags', h.flags)
            R.check('MSG-1', len(f.segs[0]) == 41 and (h.flags & 1) == 1 and h.pre_padding == 0 and h.reserved == 0,
                    '%s len=%d flags=%d pad=%d rsv=%d' % (ctxm, len(f.segs[0]), h.flags, h.pre_padding, h.reserved))
            R.obs('MSG-3:data_off', h.data_off)
            R.check('MSG-3', h.compat != 0 and h.compat <= h.version, '%s v=%d compat=%d' % (ctxm, h.version, h.compat))
            R.obs('MSG-3:(type,ver,compat)', (h.type, h.version, h.compat))
            R.obs('MSG-1:priority', h.priority)
            n = f.nseg
            lens = f.lens
            R.check('MSG-5', lens[0] == 41 and (n <= 3 or lens[3] > 0) and all(len(f.segs[i]) == lens[i] for i in range(n)),
                    '%s lens=%s' % (ctxm, lens[:n]))
        msgs[dname] = ml
        for i, h in enumerate(ml):
            R.check('MSG-2', h.seq == i + 1, '%s %s seq %d at index %d' % (ctx, dname, h.seq, i))
    ci.msgs = msgs
    for dname, other in (('c2s', 's2c'), ('s2c', 'c2s')):
        for h in ([] if ci.gap else msgs[dname]):
            seen = sum(1 for o in msgs[other] if o.ts is not None and h.ts is not None and o.ts <= h.ts)
            R.check('MSG-4', h.ack_seq <= seen, '%s %s seq %d ack_seq %d but only %d peer messages seen' % (ctx, dname, h.seq, h.ack_seq, seen))
            R.obs('MSG-6:exact==seen (%s)' % dname, h.ack_seq == seen)
            R.obs('MSG-4:ack_seq_nonzero_%s' % dname, h.ack_seq != 0)
    # keepalives
    for dname, other, td in (('c2s', 's2c', conn.c2s), ('s2c', 'c2s', conn.s2c)):
        frames = ci.c2s if dname == 'c2s' else ci.s2c
        oframes = ci.s2c if dname == 'c2s' else ci.c2s
        ka = [f for f in frames if f.tag == T_KEEPALIVE2 and f.d]
        acks = [f for f in oframes if f.tag == T_KEEPALIVE2_ACK and f.d]
        for f in ka:
            if not f.secure:
                R.check('KAL-1', len(f.raw) == 44, ctx)
        for f, a in zip(ka, acks):
            R.check('KAL-1', (f.d['sec'], f.d['nsec']) == (a.d['sec'], a.d['nsec']), '%s stamp echo' % ctx)
        if len(ka) != len(acks):
            R.check('KAL-1', False, '%s %s keepalive %d vs ack %d' % (ctx, dname, len(ka), len(acks)))
        if ka:
            tl = [ts_of(td, f.end) for f in ka]
            gaps = [round(b - a, 1) for a, b in zip(tl, tl[1:])]
            R.obs('KAL-2', '%s port %s sender=%s n=%d gaps=%s' % (ctx.split('#')[0], conn.key[3], dname, len(ka), gaps[:6]))
            if conn.key[3] == 3300 and dname == 'c2s':
                R.check('KAL-4', all(9.5 <= g <= 10.5 for g in gaps) and len(acks) == len(ka), '%s gaps %s' % (ctx, gaps))
    if conn.key[3] != 3300 and ci.mode in (1, 2):
        nka = [sum(1 for f in fl if f.tag == T_KEEPALIVE2) for fl in (ci.c2s, ci.s2c)]
        dur = (conn.last_ts - conn.first_ts) if conn.last_ts else 0
        R.obs('KAL-3:OSD/mgr conn duration>=30s -> (keepalives c2s, s2c)', (dur >= 30, nka[0], nka[1]) if dur >= 30 else (False,))
        if dur >= 30:
            R.check('KAL-3', nka == [0, 0], '%s keepalives c2s/s2c %s in %.0fs' % (ctx, nka, dur))
    nack = sum(1 for f in ci.c2s + ci.s2c if f.tag == T_ACK)
    if getattr(ci, 'lossy', True):
        R.check('ACK-1', nack == 0, '%s %d ACK frames' % (ctx, nack))
    else:
        R.obs('ACK-1:lossless session (peer type) ACK frames c2s/s2c', (ENTITY_TYPES.get(ci.peer_type),
              sum(1 for f in ci.c2s if f.tag == T_ACK), sum(1 for f in ci.s2c if f.tag == T_ACK)))
    return ci


def log_session_keys(path):
    """Set of secret bytes printed as session_key by the client logs (cross-check only)."""
    out = set()
    try:
        with open(path) as f:
            for line in f:
                for m in re.finditer(r'session_key\s+([A-Za-z0-9+/=]{20,})', line):
                    try:
                        out.add(CryptoKey.from_base64(m.group(1)).secret)
                    except Exception:
                        pass
    except OSError:
        return None
    return out


def analyze_session(name, path, keyrings, secrets_dir):
    R.declare('AUT-11', 'every session key this tool derives from the wire equals one printed by the client log (debug_auth)')
    conns = load_conns(path)
    conns.sort(key=lambda c: c.first_ts)
    ks = Keystore()
    extra = {'retrans': 0, 'gaps': []}
    cis = []
    fails_before = R.total()[1]
    for i, c in enumerate(conns):
        ci = ConnInfo(c, i, name)
        try:
            analyze_conn(ci, ks, keyrings, extra)
        except DecodeError as e:
            R.declare('ANA-1', 'analysis completes without an unexpected decode error')
            R.check('ANA-1', False, '%s: %s' % (ci.ctx, e))
        cis.append(ci)
    # cross-check derived keys with the client logs
    logkeys = log_session_keys(os.path.join(secrets_dir, 'session-secrets', name + '.txt')) if secrets_dir else None
    if logkeys is not None:
        for ci in cis:
            if ci.session_key is not None:
                R.check('AUT-11', ci.session_key.secret in logkeys, ci.ctx)
        for blob, (svc, k) in ks.tickets.items():
            R.check('AUT-11', k.secret in logkeys, '%s service %#x ticket key' % (name, svc))
    # processes
    procs = []
    for ci in cis:
        if ci.client_ident is None:
            continue
        if ci.client_ident['gid'] == -1 or not procs:
            procs.append([])
        procs[-1].append(ci)
    for p in procs:
        R.check('IDN-2', p[0].client_ident['gid'] == -1 and all(
            x.client_ident['gid'] != -1 and x.client_ident['gid'] in (p[0].global_id,) for x in p[1:] if p[0].global_id is not None) if p[0].global_id is not None else True,
            '%s gid sequence %s global_id %s' % (name, [x.client_ident['gid'] for x in p], p[0].global_id))
        R.obs('IDN-2:first_gid_is_minus1', p[0].client_ident['gid'] == -1)
        gs = [x.client_ident['global_seq'] for x in p]
        R.check('IDN-5', gs[0] == 1 and all(b > a for a, b in zip(gs, gs[1:])) and gs[-1] <= len(conns), '%s global_seq %s (%d connections)' % (name, gs, len(conns)))
        R.obs('IDN-5:global_seq_in_syn_order_increasing', [x.client_ident['global_seq'] for x in p] == sorted(x.client_ident['global_seq'] for x in p))
        R.check('IDN-7', len({x.client_ident['addrs'][0].nonce for x in p}) == 1, '%s nonces %s' % (name, [x.client_ident['addrs'][0].nonce for x in p]))
        R.obs('IDN-7:nonce_values_per_process', len({x.client_ident['addrs'][0].nonce for x in p}))
    if name.endswith('wrongkey'):
        for ci in cis:
            ok = ci.bad_method is not None or ci.mode is None
            R.check('NEG-1', ok and ci.bad_method is not None and ci.bad_method['result'] == -13,
                    '%s bad=%s' % (ci.ctx, ci.bad_method))
    if name.startswith('x-'):
        R.check('NEG-2', R.total()[1] == fails_before, name)
    return cis, extra


# ---- note 5.1 vectors ---------------------------------------------------

def hexb(s):
    return bytes.fromhex(s.replace('\n', ' '))


def check_note_vectors():
    V = lambda ok, ctx: R.check('VEC-1', ok, ctx)
    V(crc32c(b'123456789', 0) == 0x58E3FA20, 'crc 123456789 seed 0')
    V(crc32c(b'123456789', 0xFFFFFFFF) == 0x1CF96D7C, 'crc 123456789 seed -1')
    V(crc32c(b'123456789', 0xFFFFFFFF) ^ 0xFFFFFFFF == 0xE3069283, 'textbook crc32c')
    V(crc32c(b'', 0xFFFFFFFF) == 0xFFFFFFFF, 'empty')
    V(crc32c(b'\x00' * 32, 0) == 0, '32 zero bytes')
    V((_CRC_T[1], _CRC_T[2], _CRC_T[255]) == (0xF26B8303, 0xE13B70F7, 0xAD7D5351), 'table entries')
    banner = b'ceph v2\n' + struct.pack('<HQQ', 16, 3, 0)
    V(banner == hexb('63 65 70 68 20 76 32 0a 10 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), 'server banner')
    banner1 = b'ceph v2\n' + struct.pack('<HQQ', 16, 1, 0)
    V(banner1 == hexb('63 65 70 68 20 76 32 0a 10 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'), 'client banner')
    addr = encode_addr_v4('192.0.2.10', 6789, 0, 2)
    V(addr == hexb('01 01 01 1c 00 00 00 02 00 00 00 00 00 00 00 10 00 00 00 02 00 1a 85 c0 00 02 0a 00 00 00 00 00 00 00 00'), 'entity_addr_t')
    hello = build_frame(T_HELLO, [p_u8(8) + addr])
    V(hello == hexb('''01 01 24 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3f bd 6b 06
        08 01 01 01 1c 00 00 00 02 00 00 00 00 00 00 00 10 00 00 00 02 00 1a 85 c0 00 02 0a 00 00 00 00 00 00 00 00
        eb a3 d6 5a'''), 'HELLO frame')
    V(build_frame(T_WAIT, [b'']) == hexb('10 01 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c8 e3 aa b0'), 'WAIT')
    V(build_frame(T_KEEPALIVE2, [struct.pack('<II', 0x5f000000, 1)]) == hexb('''12 01 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d8 d5 f5 99
        00 00 00 5f 01 00 00 00 65 e9 f0 7b'''), 'KEEPALIVE2')
    V(build_frame(T_ACK, [p_u64(5)]) == hexb('''14 01 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 74 bc 5b
        05 00 00 00 00 00 00 00 3f b2 f6 1b'''), 'ACK')
    h2 = struct.pack('<QQHHHIHQBHH', 1, 7, 0x2a, 127, 3, 0, 0, 0, 1, 1, 0)
    m4 = build_frame(T_MESSAGE, [h2, b'abc', b'', b'WXYZ'], [8, 8, 8, 4096])
    V(m4 == hexb('''11 04 29 00 00 00 08 00 03 00 00 00 08 00 00 00 00 00 08 00 04 00 00 00 00 10 00 00 77 1b 68 14
        01 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 2a 00 7f 00 03 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 01 01 00 00 00
        e6 3e 90 c3 61 62 63 57 58 59 5a 0e 48 c0 b4 c9 ff ff ff ff 1f bf 6f 17'''), 'MESSAGE 4 segments')
    m2 = build_frame(T_MESSAGE, [h2, b'abc'], [8, 8])
    V(m2 == hexb('''11 02 29 00 00 00 08 00 03 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 af 16 66 c2''')
      + h2 + hexb('e6 3e 90 c3 61 62 63 0e 48 c0 b4 c9 00 00 00 00 00 00 00 00'), 'MESSAGE 2 segments')
    # negative controls: every single-byte corruption of a 4-segment frame must be detected by the parser
    R.declare('SELF-1', 'negative control: a flipped bit in the preamble, segment 0, its crc, the front, the data, late_status or a crc slot is detected')
    expect = [(5, 'P-CRC'), (32 + 3, 'S0-CRC'), (32 + 41 + 1, 'S0-CRC'), (32 + 41 + 4 + 1, 'E-CRC'), (len(m4) - 13 - 2, 'E-CRC'),
              (len(m4) - 13, 'E-LATE'), (len(m4) - 12, 'E-CRC')]
    for off, code in expect:
        b = bytearray(m4)
        b[off] ^= 1
        R.check('SELF-1', code in [c for c, _ in parse_plain_frame(bytes(b), 0).problems], 'offset %d expected %s' % (off, code))
    R.check('SELF-1', not parse_plain_frame(m4, 0).problems, 'unmodified frame is clean')
    # cephx note regression value for the type-1 challenge proof (cephx 2.8)
    k1 = CryptoKey(1, bytes(range(16)))
    R.declare('VEC-3', 'cephx note 2.8 worked example (type-1 proof 0x4fadd85010bcad18) reproduced')
    R.check('VEC-3', proof_v1(k1, 0x1122334455667788, 0x99aabbccddeeff00) == 0x4fadd85010bcad18, 'type-1 proof')


# ---- secure-mode frame encoder (used only for the synthetic vectors, note 2.6.3) ----

def build_secure_frame(aead, tag, segs, aligns=None):
    segs = list(segs)
    while len(segs) > 1 and len(segs[-1]) == 0:
        segs.pop()
    n = len(segs)
    if aligns is None:
        aligns = [8] * n
    pre = bytearray(32)
    pre[0] = tag
    pre[1] = n
    for i in range(n):
        struct.pack_into('<IH', pre, 2 + 6 * i, len(segs[i]), aligns[i])
    struct.pack_into('<I', pre, 28, crc32c(bytes(pre[:28]), 0))
    seg0 = segs[0] + b'\x00' * (_round16(len(segs[0])) - len(segs[0]))
    inline = (seg0[:48]).ljust(48, b'\x00')
    out = aead.seal(bytes(pre) + inline)
    if len(seg0) > 48:
        out += aead.seal(seg0[48:])
    if n > 1:
        body = b''.join(s_ + b'\x00' * (_round16(len(s_)) - len(s_)) for s_ in segs[1:]) + b'\x0e' + b'\x00' * 15
        out += aead.seal(body)
    return out


def _aead_seal(self, pt):
    ct = self.g.encrypt(bytes(self.nonce), pt, None)
    self._bump()
    return ct


Aead.seal = _aead_seal


# ---- vectors: emission (scrubbed) and verification -------------------------------

PLACEHOLDER_PROOF = 0x1111111111111111
PLACEHOLDER_SIG = b'\x5a' * 32
VECTOR_CLIENT_IP = '10.77.0.20'          # replaces the capture namespace address of the client
SYN_KEY = bytes(range(32))               # synthetic, public test values: NOT a key of any cluster
SYN_SECRET = bytes(range(64))            # synthetic connection secret (secure-mode vectors)


def _addr_json(a):
    return {'type': a.type, 'nonce': a.nonce, 'family': a.family, 'ip': a.ip4, 'port': a.port, 'hex': a.raw.hex()}


def _fields_json(d):
    out = {}
    for k, v in d.items():
        if isinstance(v, Addr):
            out[k] = _addr_json(v)
        elif isinstance(v, list) and v and isinstance(v[0], Addr):
            out[k] = [_addr_json(a) for a in v]
        elif isinstance(v, (bytes, bytearray)):
            out[k] = {'hex': bytes(v).hex()} if len(v) <= 64 else {'len': len(v)}
        else:
            out[k] = v
    return out


def _swap_ip(b, old, new):
    return b.replace(bytes(int(x) for x in old.split('.')), bytes(int(x) for x in new.split('.')))


def _scrub(fr, ci):
    """Return (bytes of the scrubbed frame, description of what was replaced, fields dict)."""
    t = fr.tag
    segs = [bytes(x) for x in fr.segs]
    aligns = fr.aligns[:fr.nseg]
    note = ''
    cli_ip = ci.conn.key[0]
    if t in (T_HELLO, T_CLIENT_IDENT, T_SERVER_IDENT):
        segs[0] = _swap_ip(segs[0], cli_ip, VECTOR_CLIENT_IP)
        note = 'client address of the capture replaced by %s (CRCs recomputed)' % VECTOR_CLIENT_IP
    elif t == T_AUTH_REQUEST:
        d = decode_control(fr)
        if d['payload'][:1] != b'\x0a':      # authorizer: ticket blob and encrypted proof
            r = Reader(d['payload'])
            head = r.take(1 + 8 + 4)
            sid, data, raw = decode_ticket_blob(r)
            proof = r.blob()
            pay = head + b'\x01' + p_u64(0xAAAAAAAAAAAAAAAA) + p_blob(b'\xaa' * len(data)) + p_blob(b'\xbb' * len(proof))
            d['payload'] = pay
            segs[0] = encode_control(t, d)
            note = 'ticket secret_id, ticket blob and encrypted proof replaced by 0xAA/0xBB fill of the same length (CRCs recomputed)'
    elif t == T_AUTH_REPLY_MORE:
        d = decode_control(fr)
        if ci.auth_kind == 'authorizer':
            d['payload'] = b'\xcc' * len(d['payload'])
            segs[0] = encode_control(t, d)
            note = 'encrypted challenge replaced by 0xCC fill of the same length (CRCs recomputed)'
    elif t == T_AUTH_REQUEST_MORE:
        d = decode_control(fr)
        pl = bytearray(d['payload'])
        if ci.auth_kind == 'mon':
            struct.pack_into('<Q', pl, 2 + 1 + 8, PLACEHOLDER_PROOF)       # u16 header, u8 v, u64 client_challenge, then proof
            note = 'cephx proof (derived from the key) replaced by 0x1111111111111111 (CRCs recomputed)'
        else:
            r = Reader(bytes(pl))
            head = r.take(1 + 8 + 4)
            sid, data, raw = decode_ticket_blob(r)
            proof = r.blob()
            pl = bytearray(head + b'\x01' + p_u64(0xAAAAAAAAAAAAAAAA) + p_blob(b'\xaa' * len(data)) + p_blob(b'\xbb' * len(proof)))
            note = 'ticket and encrypted proof replaced by fill (CRCs recomputed)'
        d['payload'] = bytes(pl)
        segs[0] = encode_control(t, d)
    elif t == T_AUTH_DONE:
        d = decode_control(fr)
        d['payload'] = b'\xdd' * len(d['payload'])
        segs[0] = encode_control(t, d)
        note = 'cephx payload (encrypted tickets, session keys, connection secret) replaced by 0xDD fill of the same length (CRCs recomputed)'
    elif t == T_AUTH_SIGNATURE:
        segs[0] = PLACEHOLDER_SIG
        note = 'HMAC (derived from the session key) replaced by 32 x 0x5A (CRCs recomputed)'
    elif t == T_MESSAGE and fr.nseg == 4:
        segs[3] = bytes((i * 7 + 3) & 0xFF for i in range(len(segs[3])))
        note = 'data segment replaced by a counting pattern of the same length (CRCs recomputed)'
    raw = build_frame(t, segs, aligns)
    chk = parse_plain_frame(raw, 0)
    chk.direction = fr.direction
    d = None
    if t != T_MESSAGE:
        d = decode_control(chk)
    return raw, note, chk, d


def emit_vectors(outdir, caps, keyrings):
    import json
    os.makedirs(outdir, exist_ok=True)
    pdir = os.path.join(caps, 'pcap')

    def sess(name):
        cis, _ = analyze_session(name, os.path.join(pdir, name + '.pcap'), keyrings, None)
        return cis

    vectors = []

    def add(name, fr, ci, source, extra_note=''):
        raw, note, chk, d = _scrub(fr, ci)
        v = {'name': name, 'direction': 'client_to_server' if fr.direction == 'c2s' else 'server_to_client',
             'tag': fr.tag, 'tag_name': fr.name, 'source': source, 'hex': raw.hex(), 'size': len(raw),
             'segment_lengths': chk.lens[:chk.nseg], 'segment_alignments': chk.aligns[:chk.nseg],
             'preamble_crc': '0x%08x' % u32(raw, 28)}
        if chk.seg0_crc is not None:
            v['segment0_crc'] = '0x%08x' % chk.seg0_crc
        if chk.epi_crcs is not None:
            v['epilogue'] = {'late_status': chk.late_status, 'crc_slots': ['0x%08x' % c for c in chk.epi_crcs]}
        if d is not None:
            v['fields'] = _fields_json(d)
        elif fr.tag == T_MESSAGE:
            h = MsgHeader2(chk.segs[0])
            v['fields'] = {k: getattr(h, k) for k in ('seq', 'tid', 'type', 'priority', 'version', 'pre_padding', 'data_off', 'ack_seq', 'flags', 'compat', 'reserved')}
            v['fields']['front_len'] = len(chk.segs[1]) if chk.nseg > 1 else 0
            v['fields']['middle_len'] = len(chk.segs[2]) if chk.nseg > 2 else 0
            v['fields']['data_len'] = len(chk.segs[3]) if chk.nseg > 3 else 0
        sc = (note + ' ' + extra_note).strip()
        v['scrubbing'] = sc if sc else 'none (frame is byte-identical to the capture)'
        v['note'] = ''
        vectors.append(v)

    # --- monitor connection (crc mode), session k2-rados-small ---
    cis = sess('k2-rados-small')
    mon = next(c for c in cis if c.peer_type == 0x01 and c.mode == 1 and c.auth_kind == 'mon')
    bykey = lambda frames, tag, nth=0: [f for f in frames if f.tag == tag][nth]
    add('mon-hello-client', bykey(mon.c2s, T_HELLO), mon, 'capture k2-rados-small')
    add('mon-hello-server', bykey(mon.s2c, T_HELLO), mon, 'capture k2-rados-small')
    add('mon-auth-request', bykey(mon.c2s, T_AUTH_REQUEST), mon, 'capture k2-rados-small')
    add('mon-auth-reply-more', bykey(mon.s2c, T_AUTH_REPLY_MORE), mon, 'capture k2-rados-small')
    add('mon-auth-request-more', bykey(mon.c2s, T_AUTH_REQUEST_MORE), mon, 'capture k2-rados-small')
    add('mon-auth-done', bykey(mon.s2c, T_AUTH_DONE), mon, 'capture k2-rados-small')
    add('mon-auth-signature-client', bykey(mon.c2s, T_AUTH_SIGNATURE), mon, 'capture k2-rados-small')
    add('mon-auth-signature-server', bykey(mon.s2c, T_AUTH_SIGNATURE), mon, 'capture k2-rados-small')
    add('mon-compression-request', bykey(mon.c2s, T_COMPRESSION_REQUEST), mon, 'capture k2-rados-small')
    add('mon-compression-done', bykey(mon.s2c, T_COMPRESSION_DONE), mon, 'capture k2-rados-small')
    add('mon-client-ident-first-connection', bykey(mon.c2s, T_CLIENT_IDENT), mon, 'capture k2-rados-small')
    add('mon-server-ident', bykey(mon.s2c, T_SERVER_IDENT), mon, 'capture k2-rados-small')
    add('mon-message-first-client', bykey(mon.c2s, T_MESSAGE), mon, 'capture k2-rados-small')
    mon2 = next(c for c in cis if c.peer_type == 0x01 and c is not mon and c.client_ident and c.client_ident['flags'] == 0)
    add('mon-client-ident-lossless-intent', bykey(mon2.c2s, T_CLIENT_IDENT), mon2, 'capture k2-rados-small',
        'stock client second monitor connection: flags 0 and a non-zero cookie; the server still answers flags 1 / cookie 0')
    add('mon-server-ident-answer-to-lossless-intent', bykey(mon2.s2c, T_SERVER_IDENT), mon2, 'capture k2-rados-small')
    # --- OSD connection with a 4-segment message ---
    osd = next(c for c in cis if c.peer_type == 0x04 and c.mode == 1 and any(f.tag == T_MESSAGE and f.nseg == 4 for f in c.c2s))
    add('osd-auth-request-authorizer', bykey(osd.c2s, T_AUTH_REQUEST), osd, 'capture k2-rados-small')
    add('osd-auth-reply-more-challenge', bykey(osd.s2c, T_AUTH_REPLY_MORE), osd, 'capture k2-rados-small')
    add('osd-auth-request-more-authorizer', bykey(osd.c2s, T_AUTH_REQUEST_MORE), osd, 'capture k2-rados-small')
    add('osd-auth-done', bykey(osd.s2c, T_AUTH_DONE), osd, 'capture k2-rados-small')
    add('osd-client-ident', bykey(osd.c2s, T_CLIENT_IDENT), osd, 'capture k2-rados-small')
    add('osd-server-ident', bykey(osd.s2c, T_SERVER_IDENT), osd, 'capture k2-rados-small')
    m4 = next(f for f in osd.c2s if f.tag == T_MESSAGE and f.nseg == 4)
    add('osd-message-four-segments-client', m4, osd, 'capture k2-rados-small')
    m2 = next(f for f in osd.s2c if f.tag == T_MESSAGE and f.nseg == 2)
    add('osd-message-two-segments-server', m2, osd, 'capture k2-rados-small')
    m3 = next((f for f in osd.s2c + osd.c2s if f.tag == T_MESSAGE and f.nseg == 3), None)
    if m3 is not None:
        add('osd-message-three-segments', m3, osd, 'capture k2-rados-small')
    # --- keepalive pair from the idle session ---
    cis = sess('k2-idle75')
    mon = next(c for c in cis if c.peer_type == 0x01 and any(f.tag == T_KEEPALIVE2 for f in c.c2s))
    add('keepalive2-client', bykey(mon.c2s, T_KEEPALIVE2), mon, 'capture k2-idle75')
    add('keepalive2-ack-server', bykey(mon.s2c, T_KEEPALIVE2_ACK), mon, 'capture k2-idle75')
    # --- failures ---
    cis = sess('k2-wrongkey')
    w = cis[0]
    add('wrongkey-auth-bad-method', bykey(w.s2c, T_AUTH_BAD_METHOD), w, 'capture k2-wrongkey')
    cis = sess('x-t0-noosd')
    o = next(c for c in cis if c.bad_method)
    add('no-osd-caps-auth-bad-method', bykey(o.s2c, T_AUTH_BAD_METHOD), o, 'capture x-t0-noosd')
    # --- live-probe frames (generated by our own probe client; see README): not from pcaps ---
    synth = []
    synth.append(('ident-missing-features-probe', T_IDENT_MISSING, [p_u64(0x0800000000000000)],
                  'server answer observed with msgr2_probe.py noaddr2 (CLIENT_IDENT whose supported mask lacks MSG_ADDR2); re-encoded here'))
    for name, tag, segs, note in synth:
        raw = build_frame(tag, segs)
        chk = parse_plain_frame(raw, 0)
        chk.direction = 's2c'
        vectors.append({'name': name, 'direction': 'server_to_client', 'tag': tag, 'tag_name': TAGS[tag], 'source': 'live probe (re-encoded)',
                        'hex': raw.hex(), 'size': len(raw), 'segment_lengths': chk.lens[:chk.nseg], 'segment_alignments': chk.aligns[:chk.nseg],
                        'preamble_crc': '0x%08x' % u32(raw, 28), 'segment0_crc': '0x%08x' % chk.seg0_crc,
                        'fields': _fields_json(decode_control(chk)), 'scrubbing': 'none (no secrets involved)', 'note': note})
    frames = {'format': 1, 'description': 'msgr2 rev-1 crc-mode frames; see README.md for provenance and scrubbing. Every frame is a complete, self-consistent frame (all CRCs verify).',
              'frames': vectors}
    with open(os.path.join(outdir, 'frames-crc.json'), 'w') as f:
        json.dump(frames, f, indent=1)
        f.write('\n')

    # --- constants: CRC and banner vectors from the note, re-derived ---
    crc = {'format': 1, 'description': 'raw CRC-32C (no implicit inversion), see docs/spec/msgr2.md 2.5',
           'vectors': [{'input_ascii': '123456789', 'seed': 0, 'crc': '0x%08x' % crc32c(b'123456789', 0)},
                       {'input_ascii': '123456789', 'seed': '0xffffffff', 'crc': '0x%08x' % crc32c(b'123456789', 0xFFFFFFFF)},
                       {'input_hex': '', 'seed': '0xffffffff', 'crc': '0x%08x' % crc32c(b'', 0xFFFFFFFF)},
                       {'input_hex': '00' * 32, 'seed': 0, 'crc': '0x%08x' % crc32c(b'\x00' * 32, 0)},
                       {'input_hex': bytes(range(256)).hex(), 'seed': 0, 'crc': '0x%08x' % crc32c(bytes(range(256)), 0)},
                       {'input_hex': bytes(range(256)).hex(), 'seed': '0xffffffff', 'crc': '0x%08x' % crc32c(bytes(range(256)), 0xFFFFFFFF)}],
           'table_entries': {'1': '0x%08x' % _CRC_T[1], '2': '0x%08x' % _CRC_T[2], '128': '0x%08x' % _CRC_T[128], '255': '0x%08x' % _CRC_T[255]}}
    with open(os.path.join(outdir, 'crc32c.json'), 'w') as f:
        json.dump(crc, f, indent=1)
        f.write('\n')

    # --- synthetic pre-auth HMAC vector ---
    banner_s = b'ceph v2\n' + struct.pack('<HQQ', 16, 3, 0)
    srv_addr = encode_addr_v4('10.77.0.10', 3300, 0, 2)
    cli_addr = encode_addr_v4(VECTOR_CLIENT_IP, 41234, 0, 2)
    s_hello = build_frame(T_HELLO, [p_u8(1) + cli_addr])
    s_more = build_frame(T_AUTH_REPLY_MORE, [p_blob(b'\x01' + p_u64(0x0123456789abcdef))])
    s_done = build_frame(T_AUTH_DONE, [p_u64(4242) + p_u32(1) + p_blob(b'\xdd' * 40)])
    c_hello = build_frame(T_HELLO, [p_u8(8) + srv_addr])
    c_req = build_frame(T_AUTH_REQUEST, [p_u32(2) + p_vec_u32([1]) + p_blob(b'\x0a' + p_u32(8) + p_blob(b'example') + p_u64(0))])
    c_more = build_frame(T_AUTH_REQUEST_MORE, [p_blob(b'\x00' * 40)])
    c_banner = b'ceph v2\n' + struct.pack('<HQQ', 16, 3, 0)
    recv_log = banner_s + s_hello + s_more + s_done
    sent_log = c_banner + c_hello + c_req + c_more
    pre = {'format': 1,
           'description': 'AUTH_SIGNATURE (docs/spec/msgr2.md 3.3). SYNTHETIC: the key is 0x00..0x1f (public test value), the frames are built by the checker, no capture bytes. '
                          'The client signature is HMAC-SHA256(key, every byte received from the server up to and including AUTH_DONE, both banners and HELLO included); '
                          'the server signature is HMAC-SHA256(key, every byte the client sent before its own AUTH_SIGNATURE).',
           'session_key_secret_hex': SYN_KEY.hex(),
           'bytes_received_by_client_hex': recv_log.hex(), 'client_signature_hex': hmac256(SYN_KEY, recv_log).hex(),
           'bytes_sent_by_client_hex': sent_log.hex(), 'server_signature_hex': hmac256(SYN_KEY, sent_log).hex(),
           'must_not_verify': {
               'client_signature_without_server_banner': hmac256(SYN_KEY, recv_log[26:]).hex(),
               'server_signature_including_the_clients_own_signature_frame': hmac256(SYN_KEY, sent_log + build_frame(T_AUTH_SIGNATURE, [hmac256(SYN_KEY, recv_log)])).hex()}}
    with open(os.path.join(outdir, 'preauth-hmac.json'), 'w') as f:
        json.dump(pre, f, indent=1)
        f.write('\n')

    # --- synthetic secure-mode vector ---
    key = SYN_SECRET[:16]
    n_rx = SYN_SECRET[16:28]       # client receive / server transmit
    n_tx = SYN_SECRET[28:40]       # client transmit / server receive
    out = []
    a_c2s = Aead(key, n_tx)
    cases = [('keepalive2 (1 segment, 8 bytes, padded to 16)', T_KEEPALIVE2, [struct.pack('<II', 0x5f000000, 1)], [8]),
             ('client ident-sized control frame (123 bytes, spills past the 48-byte inline part)', T_CLIENT_IDENT, [bytes((i * 3 + 1) & 0xFF for i in range(123))], [8]),
             ('message with header + front (2 segments)', T_MESSAGE, [bytes(range(41)), b'abc'], [8, 8]),
             ('message with 4 segments, empty middle', T_MESSAGE, [bytes(range(41)), b'abc', b'', b'WXYZ' * 5], [8, 8, 8, 4096])]
    for desc, tag, segs, al in cases:
        before = bytes(a_c2s.nonce)
        wire = build_secure_frame(a_c2s, tag, segs, al)
        out.append({'description': desc, 'direction': 'client_to_server', 'tag': tag, 'segments_hex': [s_.hex() for s_ in segs],
                    'alignments': al, 'nonce_before_hex': before.hex(), 'nonce_after_hex': bytes(a_c2s.nonce).hex(),
                    'aead_operations': a_c2s.ops, 'wire_hex': wire.hex(), 'wire_size': len(wire)})
    sec = {'format': 1,
           'description': 'msgr2.1 secure-mode frames (docs/spec/msgr2.md 2.6.3). SYNTHETIC: connection_secret = 0x00..0x3f (public test value), built by the checker '
                          'and cross-checked by decrypting real captured secure frames with the same layout; no captured bytes. Key = secret[0:16], client-receive nonce = secret[16:28], '
                          'client-transmit nonce = secret[28:40]; frames below are client-transmit direction and are consecutive (the nonce counter carries over).',
           'connection_secret_hex': SYN_SECRET.hex(), 'frames': out}
    with open(os.path.join(outdir, 'secure-frames.json'), 'w') as f:
        json.dump(sec, f, indent=1)
        f.write('\n')

    # --- handshake skeletons (structure only) ---
    skel = {'format': 1, 'description': 'ordered frames of real connections of the stock client (lengths only, no content). Source captures named per entry.',
            'connections': []}

    def skeleton(name, ci):
        seq = []
        for dname, frames in (('c2s', ci.c2s), ('s2c', ci.s2c)):
            for f in frames:
                seq.append((f.ts if f.ts is not None else 0, dname, f))
        out = []
        for dname, frames in (('c2s', ci.c2s), ('s2c', ci.s2c)):
            out.append({'direction': 'client_to_server' if dname == 'c2s' else 'server_to_client',
                        'frames': [{'tag': f.tag, 'name': f.name, 'segment_lengths': f.lens[:f.nseg], 'wire_size': f.end - f.off} for f in frames[:12]]})
        return {'name': name, 'peer': ENTITY_TYPES.get(ci.peer_type), 'mode': {1: 'crc', 2: 'secure'}.get(ci.mode), 'streams': out}
    cis = sess('k2-rados-small')
    skel['connections'].append(skeleton('mon first connection, crc (k2-rados-small)', next(c for c in cis if c.peer_type == 1)))
    skel['connections'].append(skeleton('osd connection, crc (k2-rados-small)', next(c for c in cis if c.peer_type == 4)))
    cis = sess('k2-def-rbd-info')
    skel['connections'].append(skeleton('mon connection, stock default modes = secure (k2-def-rbd-info)', next(c for c in cis if c.peer_type == 1 and c.mode == 2)))
    with open(os.path.join(outdir, 'handshake-skeletons.json'), 'w') as f:
        json.dump(skel, f, indent=1)
        f.write('\n')
    leak_guard(outdir, caps, keyrings)
    return vectors


def leak_guard(outdir, caps, keyrings):
    """Refuse to leave vector files behind that contain any key secret known to the capture set (hex or base64)."""
    secrets = set()
    for keys in keyrings.values():
        for k in keys:
            secrets.add(k.secret)
    sdir = os.path.join(caps, 'secrets', 'session-secrets')
    if os.path.isdir(sdir):
        for fn in os.listdir(sdir):
            secrets |= (log_session_keys(os.path.join(sdir, fn)) or set())
    bad = []
    for fn in sorted(os.listdir(outdir)):
        if not fn.endswith('.json'):
            continue
        with open(os.path.join(outdir, fn)) as f:
            txt = f.read().lower()
        for sec in secrets:
            if len(sec) >= 8 and (sec.hex() in txt or base64.b64encode(sec).decode().lower() in txt):
                bad.append(fn)
    if bad:
        for fn in set(bad):
            os.remove(os.path.join(outdir, fn))
        raise SystemExit('leak guard: key material found in %s - files removed' % sorted(set(bad)))
    sys.stderr.write('leak guard: %d known secrets (%d keyring keys + session keys from logs) not present in the vector files\n'
                     % (len(secrets), sum(len(v) for v in keyrings.values())))


def check_vectors(vdir):
    """Re-verify the vector files in vdir with this tool's own parsers (does not need the captures)."""
    import json
    R.declare('VECF-1', 'frames-crc.json: every frame parses, all CRCs verify, decoded fields equal the stored expectations, re-encoding is byte-identical')
    R.declare('VECF-2', 'crc32c.json values reproduce')
    R.declare('VECF-3', 'preauth-hmac.json signatures reproduce and the must-not-verify variants differ')
    R.declare('VECF-4', 'secure-frames.json: frames decrypt with the stated layout and re-encode byte-identically')
    with open(os.path.join(vdir, 'frames-crc.json')) as f:
        doc = json.load(f)
    for v in doc['frames']:
        raw = bytes.fromhex(v['hex'])
        try:
            fr = parse_plain_frame(raw, 0)
            ok = not fr.problems and fr.end == len(raw) and fr.tag == v['tag'] and fr.lens[:fr.nseg] == v['segment_lengths']
            if fr.tag != T_MESSAGE:
                d = decode_control(fr)
                ok = ok and build_frame(fr.tag, [encode_control(fr.tag, d)]) == raw and _fields_json(d) == v['fields']
            else:
                ok = ok and build_frame(fr.tag, fr.segs, fr.aligns[:fr.nseg]) == raw
        except (DecodeError, Truncated) as e:
            ok = False
        R.check('VECF-1', ok, v['name'])
    with open(os.path.join(vdir, 'crc32c.json')) as f:
        doc = json.load(f)
    for v in doc['vectors']:
        data = bytes.fromhex(v['input_hex']) if 'input_hex' in v else v['input_ascii'].encode()
        seed = int(v['seed'], 16) if isinstance(v['seed'], str) else v['seed']
        R.check('VECF-2', crc32c(data, seed) == int(v['crc'], 16), str(v))
    for k, c in doc['table_entries'].items():
        R.check('VECF-2', _CRC_T[int(k)] == int(c, 16), 'T[%s]' % k)
    with open(os.path.join(vdir, 'preauth-hmac.json')) as f:
        doc = json.load(f)
    key = bytes.fromhex(doc['session_key_secret_hex'])
    rx, tx = bytes.fromhex(doc['bytes_received_by_client_hex']), bytes.fromhex(doc['bytes_sent_by_client_hex'])
    R.check('VECF-3', hmac256(key, rx).hex() == doc['client_signature_hex'] and hmac256(key, tx).hex() == doc['server_signature_hex'], 'signatures')
    R.check('VECF-3', all(doc['must_not_verify'][k] not in (doc['client_signature_hex'], doc['server_signature_hex']) for k in doc['must_not_verify']), 'variants')
    with open(os.path.join(vdir, 'secure-frames.json')) as f:
        doc = json.load(f)
    secret = bytes.fromhex(doc['connection_secret_hex'])
    enc = Aead(secret[:16], secret[28:40])
    dec = Aead(secret[:16], secret[28:40])
    for v in doc['frames']:
        wire = bytes.fromhex(v['wire_hex'])
        segs = [bytes.fromhex(x) for x in v['segments_hex']]
        again = build_secure_frame(enc, v['tag'], segs, v['alignments'])
        try:
            fr = parse_secure_frame(wire, 0, dec)
            ok = again == wire and not fr.problems and fr.end == len(wire) and [bytes(x) for x in fr.segs] == [x for x in segs if True][:len(fr.segs)] \
                and v['nonce_after_hex'] == bytes(dec.nonce).hex()
        except (DecodeError, Truncated):
            ok = False
        R.check('VECF-4', ok, v['description'])


# ---------------------------------------------------------------------------
# 6. command line / report
# ---------------------------------------------------------------------------

def report(verbose):
    ok_total, fail_total = R.total()
    print()
    print('%-8s %8s %6s  %s' % ('check', 'pass', 'fail', 'description'))
    for cid in R.order:
        e = R.info[cid]
        flag = 'FAIL' if e['fail'] else ('  --' if e['ok'] == 0 else '  ok')
        print('%-8s %8d %6d  %s  %s' % (cid, e['ok'], e['fail'], flag, e['desc']))
        for ex in e['examples'][:3 if not verbose else 5]:
            print('            e.g. %s' % ex)
    print()
    print('TOTAL: %d passed, %d failed' % (ok_total, fail_total))
    if verbose:
        print()
        print('Observed values (not pass/fail):')
        for cid in sorted(R.observed):
            items = R.observed[cid].most_common(12)
            print('  %s' % cid)
            for v, n in items:
                print('      %6d x %s' % (n, v))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--captures', help='capture set directory (contains pcap/); optional with --check-vectors')
    ap.add_argument('--keys', help='directory with the lab keyrings (default: <captures>/../lab-secrets)')
    ap.add_argument('--only', help='comma separated session names (default: all pcaps)')
    ap.add_argument('--emit-vectors', help='write scrubbed test vectors into this directory (needs the captures)')
    ap.add_argument('--check-vectors', help='verify the vector files in this directory (default: harness/vectors/msgr2 next to this tool, if present)')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args(argv)
    if not args.captures:
        if not args.check_vectors:
            ap.error('--captures is required (or use --check-vectors alone)')
        declare_all()
        check_note_vectors()
        check_vectors(args.check_vectors)
        report(args.verbose)
        return 0 if R.total()[1] == 0 else 1
    caps = os.path.abspath(args.captures)
    keysdir = args.keys or os.path.join(os.path.dirname(caps), 'lab-secrets')
    secrets_dir = os.path.join(caps, 'secrets')
    keyrings = load_keyrings([keysdir, os.path.join(secrets_dir, 'keys')])
    if not keyrings:
        sys.stderr.write('warning: no keyrings found; cephx / secure-mode checks will be skipped\n')
    declare_all()
    check_note_vectors()
    pdir = os.path.join(caps, 'pcap')
    names = sorted(fn[:-5] for fn in os.listdir(pdir) if fn.endswith('.pcap'))
    if args.only:
        want = set(args.only.split(','))
        names = [n for n in names if n in want]
    allc = {}
    warnings = []
    for n in names:
        sys.stderr.write('analysing %s ...\n' % n)
        cis, extra = analyze_session(n, os.path.join(pdir, n + '.pcap'), keyrings, secrets_dir)
        allc[n] = cis
        R.obs('TCP-1:retransmitted_segments_seen', extra['retrans'] > 0)
        warnings.extend(extra['gaps'])
    if args.emit_vectors:
        emit_vectors(args.emit_vectors, caps, keyrings)
        sys.stderr.write('vectors written to %s\n' % args.emit_vectors)
    vdir = args.check_vectors or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'vectors', 'msgr2')
    if args.emit_vectors:
        vdir = args.emit_vectors
    if os.path.isfile(os.path.join(vdir, 'frames-crc.json')):
        check_vectors(vdir)
    report(args.verbose)
    if warnings:
        print()
        print('WARNINGS (capture defects, not note defects):')
        for w in warnings:
            print('  ' + w)
    return 0 if R.total()[1] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
