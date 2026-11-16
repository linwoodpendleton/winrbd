# SPDX-License-Identifier: MIT
"""
wire.py - small shared helpers for the winrbd Phase 0 checkers.

Written from the spec notes in docs/spec/ only (never from Ceph source and never through Ceph's own
decoders).  Standard library plus `cryptography`.  Contributors: only ADD functions; do not change
the behaviour of existing ones (other checkers import them).

Contents
  - crc32c()                raw CRC-32C update (msgr2 note 2.5)
  - Rd                      little-endian reader with the Ceph primitive encodings
  - read_pcap(), tcp_streams()   classic pcap -> reassembled TCP byte streams (+ per-chunk timestamps)
  - msgr2 framing: read_crc_frame(), SecureRx, read_secure_frame()   (msgr2 + secure-mode notes)
  - cephx crypto: key_decode(), cx_decrypt() for key type 1 (aes) and 2 (aes256k), envelope helpers
Nothing in here prints or logs key material.
"""

import base64
import hashlib
import hmac
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WireError(Exception):
    pass


# --------------------------------------------------------------------------------------------------
# CRC-32C (raw update, caller supplied seed, no final inversion)
# --------------------------------------------------------------------------------------------------

def _crc_tables():
    poly = 0x82F63B78
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t0.append(c)
    tabs = [t0]
    for _ in range(1, 8):
        prev = tabs[-1]
        tabs.append([(prev[i] >> 8) ^ t0[prev[i] & 255] for i in range(256)])
    return tabs


_T = _crc_tables()


def crc32c(data, crc=0):
    """Raw CRC-32C update: crc = f(seed=crc, data); an empty buffer returns the seed."""
    t0, t1, t2, t3, t4, t5, t6, t7 = _T
    mv = memoryview(data)
    n = len(mv)
    end8 = n & ~7
    if end8:
        for a, b in struct.iter_unpack('<II', mv[:end8]):
            a ^= crc
            crc = (t7[a & 255] ^ t6[(a >> 8) & 255] ^ t5[(a >> 16) & 255] ^ t4[a >> 24] ^
                   t3[b & 255] ^ t2[(b >> 8) & 255] ^ t1[(b >> 16) & 255] ^ t0[b >> 24])
    for byte in mv[end8:]:
        crc = (crc >> 8) ^ t0[(crc ^ byte) & 255]
    return crc


# --------------------------------------------------------------------------------------------------
# little-endian reader
# --------------------------------------------------------------------------------------------------

class Rd:
    def __init__(self, b, pos=0, end=None):
        self.b = b
        self.p = pos
        self.end = len(b) if end is None else end

    def left(self):
        return self.end - self.p

    def raw(self, n):
        if n < 0 or self.p + n > self.end:
            raise WireError('short read: want %d have %d at %d' % (n, self.left(), self.p))
        r = bytes(self.b[self.p:self.p + n])
        self.p += n
        return r

    def u8(self):
        return self.raw(1)[0]

    def u16(self):
        return struct.unpack('<H', self.raw(2))[0]

    def i16(self):
        return struct.unpack('<h', self.raw(2))[0]

    def u32(self):
        return struct.unpack('<I', self.raw(4))[0]

    def i32(self):
        return struct.unpack('<i', self.raw(4))[0]

    def u64(self):
        return struct.unpack('<Q', self.raw(8))[0]

    def i64(self):
        return struct.unpack('<q', self.raw(8))[0]

    def blob(self):
        return self.raw(self.u32())

    def string(self):
        return self.blob().decode('utf-8', 'replace')

    def utime(self):
        s = self.u32()
        n = self.u32()
        return (s, n)

    def uuid(self):
        return self.raw(16).hex()

    def skip(self, n):
        self.raw(n)

    def env(self):
        """versioned-struct envelope: returns (struct_v, struct_compat, end_pos); sub-reader limit set by caller."""
        v = self.u8()
        c = self.u8()
        ln = self.u32()
        if self.p + ln > self.end:
            raise WireError('envelope length %d beyond buffer (%d left)' % (ln, self.left()))
        return v, c, self.p + ln


# --------------------------------------------------------------------------------------------------
# pcap -> TCP streams
# --------------------------------------------------------------------------------------------------

def read_pcap(path):
    """Yield (timestamp_float, frame_bytes) from a classic little-endian pcap (Ethernet)."""
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        e = '<'
        nano = False
    elif magic == b'\x4d\x3c\xb2\xa1':
        e = '<'
        nano = True
    else:
        raise WireError('not a little-endian classic pcap: %r' % magic)
    linktype = struct.unpack(e + 'I', data[20:24])[0]
    if linktype != 1:
        raise WireError('unsupported linktype %d' % linktype)
    p = 24
    n = len(data)
    div = 1e9 if nano else 1e6
    while p + 16 <= n:
        sec, frac, incl, orig = struct.unpack(e + 'IIII', data[p:p + 16])
        p += 16
        yield sec + frac / div, data[p:p + incl]
        p += incl


class Stream:
    """One direction of a TCP connection after reassembly by sequence number."""

    def __init__(self):
        self.isn = None
        self.segs = []          # (rel_off, bytes, ts)
        self.data = b''
        self.chunks = []        # (stream_offset, ts) of the first byte of every accepted segment
        self.retrans = 0
        self.overlap_mismatch = 0
        self.gaps = 0
        self.gap_at = None      # stream offset where reassembly stopped at a capture gap (missing packets), else None
        self.fin = False

    def finish(self):
        buf = bytearray()
        chunks = []
        for off, d, ts in sorted(self.segs, key=lambda s: s[0]):
            if off > len(buf):
                self.gaps += 1
                self.gap_at = len(buf)
                break
            if off < len(buf):
                self.retrans += 1
                ov = min(len(buf) - off, len(d))
                if bytes(buf[off:off + ov]) != d[:ov]:
                    self.overlap_mismatch += 1
                d = d[ov:]
                off = len(buf)
                if not d:
                    continue
            chunks.append((off, ts))
            buf += d
        self.data = bytes(buf)
        self.chunks = chunks
        self.segs = []

    def ts_at(self, off):
        """timestamp of the TCP segment that carried stream byte `off`"""
        lo, hi = 0, len(self.chunks) - 1
        best = self.chunks[0][1] if self.chunks else 0.0
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.chunks[mid][0] <= off:
                best = self.chunks[mid][1]
                lo = mid + 1
            else:
                hi = mid - 1
        return best


class Flow:
    def __init__(self, client, server):
        self.client = client      # (ip, port)
        self.server = server
        self.c2s = Stream()
        self.s2c = Stream()
        self.first_ts = None
        self.syn_ts = None

    def key(self):
        return '%s:%d>%s:%d' % (self.client + self.server)


def tcp_streams(path):
    """Return list of Flow (ordered by first packet) with reassembled c2s / s2c streams."""
    flows = {}
    order = []
    for ts, fr in read_pcap(path):
        if len(fr) < 14 or fr[12:14] != b'\x08\x00':
            continue
        ihl = (fr[14] & 15) * 4
        if fr[14 + 9] != 6:
            continue
        tot = struct.unpack('>H', fr[16:18])[0]
        src = '.'.join(str(x) for x in fr[26:30])
        dst = '.'.join(str(x) for x in fr[30:34])
        t = 14 + ihl
        sport, dport, seq, ack = struct.unpack('>HHII', fr[t:t + 12])
        doff = (fr[t + 12] >> 4) * 4
        fl = fr[t + 13]
        payload = fr[t + doff:14 + tot]
        a = (src, sport)
        b = (dst, dport)
        k = (a, b) if (a, b) in flows else ((b, a) if (b, a) in flows else None)
        syn = fl & 2
        if k is None:
            if syn and not (fl & 16):
                k = (a, b)
            else:
                k = (a, b)       # no SYN seen: assume first sender is the client
            flows[k] = Flow(k[0], k[1])
            flows[k].first_ts = ts
            order.append(k)
        f = flows[k]
        st = f.c2s if (a == f.client) else f.s2c
        if syn:
            st.isn = (seq + 1) & 0xFFFFFFFF
            if a == f.client and f.syn_ts is None:
                f.syn_ts = ts
        if fl & 1:
            st.fin = True
        if payload:
            if st.isn is None:
                st.isn = seq
            rel = (seq - st.isn) & 0xFFFFFFFF
            st.segs.append((rel, payload, ts))
    out = []
    for k in order:
        f = flows[k]
        f.c2s.finish()
        f.s2c.finish()
        out.append(f)
    return out


# --------------------------------------------------------------------------------------------------
# msgr2 framing
# --------------------------------------------------------------------------------------------------

TAGS = {1: 'HELLO', 2: 'AUTH_REQUEST', 3: 'AUTH_BAD_METHOD', 4: 'AUTH_REPLY_MORE', 5: 'AUTH_REQUEST_MORE',
        6: 'AUTH_DONE', 7: 'AUTH_SIGNATURE', 8: 'CLIENT_IDENT', 9: 'SERVER_IDENT', 10: 'IDENT_MISSING_FEATURES',
        11: 'SESSION_RECONNECT', 12: 'SESSION_RESET', 13: 'SESSION_RETRY', 14: 'SESSION_RETRY_GLOBAL',
        15: 'SESSION_RECONNECT_OK', 16: 'WAIT', 17: 'MESSAGE', 18: 'KEEPALIVE2', 19: 'KEEPALIVE2_ACK', 20: 'ACK',
        21: 'COMPRESSION_REQUEST', 22: 'COMPRESSION_DONE'}


class Frame:
    def __init__(self):
        self.tag = 0
        self.segs = []          # logical segment bytes
        self.align = []
        self.start = 0          # stream offset of the first wire byte
        self.end = 0            # stream offset after the last wire byte
        self.errors = []        # structural / checksum problems found while reading
        self.flags = 0
        self.late = None
        self.crc_checked = 0    # number of crc values verified OK
        self.secure = False

    @property
    def name(self):
        return TAGS.get(self.tag, 'TAG%d' % self.tag)


def read_banner(buf, pos=0):
    if buf[pos:pos + 8] != b'ceph v2\n':
        raise WireError('bad banner prefix %r' % bytes(buf[pos:pos + 8]))
    ln = struct.unpack('<H', buf[pos + 8:pos + 10])[0]
    if pos + 10 + ln > len(buf):
        raise WireError('short banner')
    sup, req = struct.unpack('<QQ', buf[pos + 10:pos + 26])
    return sup, req, ln, pos + 10 + ln


def read_crc_frame(buf, pos):
    """Read one msgr2.1 crc-mode frame at `pos`.  Returns Frame (errors recorded, not raised, for crc /
    structure problems) or raises WireError when the buffer ends inside the frame."""
    fr = Frame()
    fr.start = pos
    if pos + 32 > len(buf):
        raise WireError('short preamble')
    pre = bytes(buf[pos:pos + 32])
    fr.tag = pre[0]
    n = pre[1]
    lens = []
    for i in range(4):
        ln, al = struct.unpack('<IH', pre[2 + 6 * i:8 + 6 * i])
        lens.append(ln)
        fr.align.append(al)
    fr.flags = pre[26]
    pcrc = struct.unpack('<I', pre[28:32])[0]
    if crc32c(pre[:28], 0) != pcrc:
        fr.errors.append('preamble crc mismatch')
    else:
        fr.crc_checked += 1
    if not 1 <= n <= 4:
        fr.errors.append('bad segment count %d' % n)
        raise WireError('bad segment count %d at %d' % (n, pos))
    if n > 1 and lens[n - 1] == 0:
        fr.errors.append('last segment empty')
    if any(lens[i] for i in range(n, 4)):
        fr.errors.append('segment length beyond count')
    if pre[27] != 0:
        fr.errors.append('reserved preamble byte not zero')
    p = pos + 32
    need = (lens[0] + 4 if lens[0] else 0) + sum(lens[1:n]) + (13 if n > 1 else 0)
    if p + need > len(buf):
        raise WireError('short frame: need %d have %d' % (need, len(buf) - p))
    segs = []
    if lens[0]:
        s0 = bytes(buf[p:p + lens[0]])
        c0 = struct.unpack('<I', buf[p + lens[0]:p + lens[0] + 4])[0]
        if crc32c(s0, 0xFFFFFFFF) != c0:
            fr.errors.append('segment 0 crc mismatch')
        else:
            fr.crc_checked += 1
        p += lens[0] + 4
    else:
        s0 = b''
    segs.append(s0)
    for i in range(1, n):
        segs.append(bytes(buf[p:p + lens[i]]))
        p += lens[i]
    if n > 1:
        late = buf[p]
        fr.late = late
        if late & 15 != 0x0E:
            fr.errors.append('late_status low nibble %#x' % (late & 15))
        for i in range(1, 4):
            c = struct.unpack('<I', buf[p + 1 + 4 * (i - 1):p + 5 + 4 * (i - 1)])[0]
            if i < n:
                if crc32c(segs[i], 0xFFFFFFFF) != c:
                    fr.errors.append('segment %d crc mismatch' % i)
                else:
                    fr.crc_checked += 1
            elif c != 0:
                fr.errors.append('unused epilogue slot %d not zero' % i)
        p += 13
    fr.segs = segs
    fr.end = p
    return fr


class SecureRx:
    """AES-128-GCM stream state for one direction (msgr2.1 secure mode, secure-mode note 2.6)."""

    def __init__(self, key16, nonce12):
        self.aes = AESGCM(key16)
        self.nonce = bytearray(nonce12)

    def op(self, ct_and_tag):
        iv = bytes(self.nonce)
        ctr = (struct.unpack('<Q', bytes(self.nonce[4:12]))[0] + 1) & 0xFFFFFFFFFFFFFFFF
        self.nonce[4:12] = struct.pack('<Q', ctr)
        return self.aes.decrypt(iv, ct_and_tag, None)


def _pad16(x):
    return (x + 15) & ~15


def read_secure_frame(buf, pos, rx):
    """Read one msgr2.1 secure-mode frame, decrypting with `rx` (SecureRx).  Raises WireError on a short
    buffer or an authentication failure."""
    from cryptography.exceptions import InvalidTag
    fr = Frame()
    fr.start = pos
    fr.secure = True
    if pos + 96 > len(buf):
        raise WireError('short secure preamble')
    try:
        p1 = rx.op(bytes(buf[pos:pos + 96]))
    except InvalidTag:
        raise WireError('GCM tag failure on preamble block at %d' % pos)
    pre = p1[:32]
    inline = p1[32:80]
    fr.tag = pre[0]
    n = pre[1]
    lens = []
    for i in range(4):
        ln, al = struct.unpack('<IH', pre[2 + 6 * i:8 + 6 * i])
        lens.append(ln)
        fr.align.append(al)
    fr.flags = pre[26]
    if crc32c(pre[:28], 0) != struct.unpack('<I', pre[28:32])[0]:
        fr.errors.append('preamble crc mismatch')
    else:
        fr.crc_checked += 1
    if not 1 <= n <= 4:
        raise WireError('bad segment count %d' % n)
    p = pos + 96
    if lens[0] > 48:
        rl = _pad16(lens[0]) - 48
        if p + rl + 16 > len(buf):
            raise WireError('short secure segment 0 remainder')
        try:
            rest = rx.op(bytes(buf[p:p + rl + 16]))
        except InvalidTag:
            raise WireError('GCM tag failure on segment 0 remainder')
        s0 = (inline + rest)[:lens[0]]
        p += rl + 16
    else:
        s0 = inline[:lens[0]]
    segs = [s0]
    if n > 1:
        body = sum(_pad16(lens[i]) for i in range(1, n))
        if p + body + 32 > len(buf):
            raise WireError('short secure body')
        try:
            pl = rx.op(bytes(buf[p:p + body + 32]))
        except InvalidTag:
            raise WireError('GCM tag failure on body')
        q = 0
        for i in range(1, n):
            segs.append(pl[q:q + lens[i]])
            q += _pad16(lens[i])
        fr.late = pl[q]
        if pl[q] & 15 != 0x0E:
            fr.errors.append('late_status low nibble %#x' % (pl[q] & 15))
        p += body + 32
    fr.segs = segs
    fr.end = p
    return fr


# --------------------------------------------------------------------------------------------------
# cephx crypto (cephx note 2.3 - 2.6)
# --------------------------------------------------------------------------------------------------

CEPH_AES_IV = bytes.fromhex('63657068736167657975646167726567')
MAGIC = 0xff009cad8826aa55


def key_decode(b64):
    """Decode the base64 of a CryptoKey encoding -> (type, secret bytes)."""
    raw = base64.b64decode(b64)
    r = Rd(raw)
    t = r.u16()
    r.utime()
    ln = r.u16()
    sec = r.raw(ln)
    if r.left():
        raise WireError('trailing bytes in key')
    return t, sec


def _hmac(h, key, msg):
    return hmac.new(key, msg, h).digest()


def _kdf(base, usage, typebyte, bits):
    inp = b'\x00\x00\x00\x01' + struct.pack('>I', usage) + bytes([typebyte, 0]) + struct.pack('>I', bits)
    return _hmac(hashlib.sha384, base, inp)[:bits // 8]


def _cbc_dec(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()


def _ecb_dec(key, blk):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(blk) + d.finalize()


def _cs3_decrypt(ke, ct):
    n = len(ct)
    if n < 16:
        raise WireError('CS3 input shorter than a block')
    if n == 16:
        return _cbc_dec(ke, bytes(16), ct)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    head = ct[:16 * (k - 2)]
    ck = ct[16 * (k - 2):16 * (k - 1)]
    part = ct[16 * (k - 1):]
    assert len(part) == r
    dd = _ecb_dec(ke, ck)
    ckm1 = part + dd[r:]
    pk = bytes(a ^ b for a, b in zip(dd[:r], ckm1[:r]))
    prev = head[-16:] if head else bytes(16)
    pkm1 = bytes(a ^ b for a, b in zip(_ecb_dec(ke, ckm1), prev))
    ph = _cbc_dec(ke, bytes(16), head) if head else b''
    return ph + pkm1 + pk


def cx_decrypt(ktype, secret, usage, ct):
    """Decrypt one cephx ciphertext with a key of the given type; returns plaintext (envelope not stripped).
    Raises WireError on MAC / padding failure."""
    if ktype == 1:
        if len(ct) == 0 or len(ct) % 16:
            raise WireError('type-1 ciphertext length %d' % len(ct))
        pt = _cbc_dec(secret[:16], CEPH_AES_IV, ct)
        pad = pt[-1]
        if not 1 <= pad <= 16 or pt[-pad:] != bytes([pad]) * pad:
            raise WireError('type-1 bad padding')
        return pt[:-pad]
    if ktype == 2:
        if len(ct) < 40:
            raise WireError('type-2 ciphertext too short')
        body, mac = ct[:-24], ct[-24:]
        ki = _kdf(secret, usage, 0x55, 192)
        ke = _kdf(secret, usage, 0xAA, 256)
        if not hmac.compare_digest(_hmac(hashlib.sha384, ki, bytes(16) + body)[:24], mac):
            raise WireError('type-2 MAC mismatch')
        return _cs3_decrypt(ke, body)[16:]
    raise WireError('unknown key type %d' % ktype)


def cx_unseal(ktype, secret, usage, ct):
    """cx_decrypt + envelope check (u8 v, u64 magic); returns the item bytes after the envelope."""
    pt = cx_decrypt(ktype, secret, usage, ct)
    r = Rd(pt)
    v = r.u8()
    m = r.u64()
    if m != MAGIC:
        raise WireError('envelope magic mismatch')
    return r.raw(r.left()), v


def cx_encrypt_t1(secret, plain):
    """Type-1 (aes) encryption: AES-128-CBC, fixed IV, PKCS#7 padding with a full block when aligned (note 2.4).
    Only needed to recompute the type-1 challenge proof."""
    pad = 16 - (len(plain) % 16)
    e = Cipher(algorithms.AES(secret[:16]), modes.CBC(CEPH_AES_IV)).encryptor()
    return e.update(plain + bytes([pad]) * pad) + e.finalize()


def cx_challenge_proof(ktype, secret, server_chal, client_chal):
    """The `key` field of CephXAuthenticate (note 2.8)."""
    blob = struct.pack('<QQ', server_chal, client_chal)
    if ktype == 1:
        plain = b'\x01' + struct.pack('<Q', MAGIC) + blob
        ct = cx_encrypt_t1(secret, plain)
        enc = struct.pack('<I', len(ct)) + ct
        words = struct.unpack('<%dQ' % (len(enc) // 8), enc[:len(enc) // 8 * 8])
    else:
        d = hmac.new(secret, blob, hashlib.sha256).digest()
        words = struct.unpack('<4Q', d)
    x = 0
    for w in words:
        x ^= w
    return x


def hmac_sha256(key, msg):
    return hmac.new(key, msg, hashlib.sha256).digest()
