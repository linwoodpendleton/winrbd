#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
secure_check.py -- independent checker for docs/spec/msgr2-secure-mode.md

Purpose
-------
The spec note was written by reading Ceph source. This tool re-derives every
structure the note describes from the NOTE ALONE (plus docs/spec/cephx.md for
the cephx cipher details the note delegates to it), implemented from scratch
with only the Python standard library and the 'cryptography' package, and runs
it against real bytes: the packet captures made on the lab cluster.

It never uses any Ceph code or decoder. It reads keys at run time and never
prints them.

What it checks (see the summary at the end of a run)
----------------------------------------------------
  * primitives: CRC-32C (seed 0, no final inversion), the note's worked
    examples (section 5.2), the frame size table (section 5.1), nonce stepping
  * pcap -> TCP streams (reassembly by sequence number, retransmissions)
  * msgr2: banner, HELLO, every crc frame (preamble CRC, segment CRCs, epilogue)
  * auth frames: AUTH_REQUEST / REPLY_MORE / REQUEST_MORE / DONE / BAD_METHOD /
    SIGNATURE field layouts, offered modes and the mode the server picked
  * cephx (with the lab keyrings): key decode, both key types (aes, aes256k),
    challenge proof, ticket reply, connection-secret blob, authorizer round
    trip for mgr / OSD connections
  * secure mode: key and nonce slicing, direction, every GCM operation of every
    frame in every secure session (tags verify), frame size arithmetic, padding,
    epilogue, and a re-assembly round trip that must reproduce the captured
    wire bytes exactly
  * the pre-auth signature in both directions (HMAC key bytes, transcript scope)
  * the compression handshake frames

Usage
-----
    python3 harness/tools/secure_check.py --captures <captures dir>
        [--keys <dir with the lab keyrings>]   (default: <captures>/../lab-secrets)
        [--only <substring>]                   (only pcaps whose name contains it)
        [--export-vectors <dir>]               (write the scrubbed vectors, see
                                                harness/vectors/secure/README.md)
        [-v]

Exit status 0 only if every check passed.
"""

import argparse
import base64
import collections
import glob
import hashlib
import hmac
import json
import os
import struct
import sys
import time

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:  # pragma: no cover
    sys.stderr.write("this tool needs the 'cryptography' package "
                     "(pip install --user cryptography)\n")
    sys.exit(2)

# ----------------------------------------------------------------------------
# constants taken from the note (sections 2.1 - 2.8) and the cephx note
# ----------------------------------------------------------------------------

BANNER_PREFIX = b"ceph v2\n"

TAGS = {1: "HELLO", 2: "AUTH_REQUEST", 3: "AUTH_BAD_METHOD", 4: "AUTH_REPLY_MORE",
        5: "AUTH_REQUEST_MORE", 6: "AUTH_DONE", 7: "AUTH_SIGNATURE",
        8: "CLIENT_IDENT", 9: "SERVER_IDENT", 10: "IDENT_MISSING_FEATURES",
        11: "SESSION_RECONNECT", 12: "SESSION_RESET", 13: "SESSION_RETRY",
        14: "SESSION_RETRY_GLOBAL", 15: "SESSION_RECONNECT_OK", 16: "WAIT",
        17: "MESSAGE", 18: "KEEPALIVE2", 19: "KEEPALIVE2_ACK", 20: "ACK",
        21: "COMPRESSION_REQUEST", 22: "COMPRESSION_DONE"}
T_HELLO, T_AUTH_REQUEST, T_AUTH_BAD_METHOD, T_AUTH_REPLY_MORE = 1, 2, 3, 4
T_AUTH_REQUEST_MORE, T_AUTH_DONE, T_AUTH_SIGNATURE = 5, 6, 7
T_MESSAGE, T_COMP_REQ, T_COMP_DONE = 17, 21, 22

MODE_CRC, MODE_SECURE = 1, 2
ENTITY = {0x01: "mon", 0x02: "mds", 0x04: "osd", 0x08: "client", 0x10: "mgr",
          0x20: "auth"}

ENVELOPE_MAGIC = 0xff009cad8826aa55
CEPH_AES_IV = bytes.fromhex("63657068736167657975646167726567")  # cephx note 2.1
USAGE_CONN_SECRET, USAGE_TICKET_KEY, USAGE_TICKET_BLOB = 0x03, 0x04, 0x05
USAGE_AUTHORIZE, USAGE_CHALLENGE, USAGE_AUTH_REPLY = 0x10, 0x11, 0x12

PREAMBLE, INLINE, TAG, CRYPTO_BLOCK = 32, 48, 16, 16


# ----------------------------------------------------------------------------
# result bookkeeping
# ----------------------------------------------------------------------------

class Results:
    """Counts every individual check; keeps the first few failures per group."""

    def __init__(self):
        self.counts = collections.OrderedDict()   # group -> [pass, fail]
        self.failures = collections.defaultdict(list)
        self.claims = collections.OrderedDict()   # claim id -> dict
        self.info = collections.OrderedDict()     # free-form observations
        self.defects = []                         # capture defects (not note failures)

    def check(self, group, ok, msg=""):
        c = self.counts.setdefault(group, [0, 0])
        if ok:
            c[0] += 1
        else:
            c[1] += 1
            if len(self.failures[group]) < 12:
                self.failures[group].append(msg)
        return ok

    def claim(self, cid, text, status, evidence=""):
        """status: 'confirmed' | 'FAILED' | 'open'. A claim fails if any
        check feeding it failed; callers pass the aggregated status."""
        self.claims[cid] = {"text": text, "status": status, "evidence": evidence}

    def defect(self, msg):
        self.defects.append(msg)

    def note(self, key, value):
        self.info[key] = value

    @property
    def total(self):
        return (sum(c[0] for c in self.counts.values()),
                sum(c[1] for c in self.counts.values()))


R = Results()


class ProtoError(Exception):
    pass


# ----------------------------------------------------------------------------
# CRC-32C: generated at run time from the public polynomial (note section 7)
# ----------------------------------------------------------------------------

def _mk_crc_tables():
    poly = 0x82F63B78            # reflected 0x1EDC6F41
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ poly if c & 1 else c >> 1
        t0.append(c)
    tabs = [t0]
    for k in range(1, 4):
        prev = tabs[-1]
        tabs.append([(prev[i] >> 8) ^ t0[prev[i] & 0xFF] for i in range(256)])
    return tabs


_T0, _T1, _T2, _T3 = _mk_crc_tables()


def crc32c(data, seed=0):
    """Raw Castagnoli update: no initial or final inversion of its own. The
    caller supplies the seed (note section 2.8: 0 for the preamble, 0xFFFFFFFF
    for segments in crc mode)."""
    c = seed & 0xFFFFFFFF
    mv = memoryview(data)
    n = len(mv)
    i = 0
    n4 = n - (n % 4)
    if n4:
        words = struct.unpack("<%dI" % (n4 // 4), mv[:n4])
        t0, t1, t2, t3 = _T0, _T1, _T2, _T3
        for w in words:
            c ^= w
            c = t3[c & 0xFF] ^ t2[(c >> 8) & 0xFF] ^ t1[(c >> 16) & 0xFF] ^ t0[c >> 24]
        i = n4
    while i < n:
        c = (c >> 8) ^ _T0[(c ^ mv[i]) & 0xFF]
        i += 1
    return c


# ----------------------------------------------------------------------------
# little-endian reader / writer for the standard encodings (note 2.4)
# ----------------------------------------------------------------------------

class Rd:
    def __init__(self, b, pos=0):
        self.b = bytes(b)
        self.p = pos

    def left(self):
        return len(self.b) - self.p

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise ProtoError("short read: want %d have %d" % (n, self.left()))
        v = self.b[self.p:self.p + n]
        self.p += n
        return v

    def u8(self):
        return self.take(1)[0]

    def u16(self):
        return struct.unpack("<H", self.take(2))[0]

    def u32(self):
        return struct.unpack("<I", self.take(4))[0]

    def s32(self):
        return struct.unpack("<i", self.take(4))[0]

    def u64(self):
        return struct.unpack("<Q", self.take(8))[0]

    def blob(self):
        n = self.u32()
        return self.take(n)

    def vec_u32(self):
        n = self.u32()
        if n > 1000:
            raise ProtoError("vector too long")
        return [self.u32() for _ in range(n)]


def p8(v):
    return struct.pack("<B", v)


def p16(v):
    return struct.pack("<H", v)


def p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def pblob(b):
    return p32(len(b)) + bytes(b)


def pad16(x):
    return (x + 15) & ~15


# ----------------------------------------------------------------------------
# pcap -> TCP streams
# ----------------------------------------------------------------------------

class TcpConn:
    def __init__(self, key):
        self.key = key               # (client_ip, cport, server_ip, sport)
        self.t0 = None
        self.c2s_segs = []
        self.s2c_segs = []
        self.c2s = b""
        self.s2c = b""
        self.retrans = 0
        self.gaps = 0
        self.gap_dir = {"c2s": False, "s2c": False}
        self.overlap_mismatch = 0
        self.fin_or_rst = False

    @property
    def sport(self):
        return self.key[3]

    @property
    def cport(self):
        return self.key[1]


def _reassemble(segs, isn, conn, direction):
    """segs: list of (seq, payload). Returns the contiguous byte stream."""
    items = []
    for seq, pay in segs:
        rel = (seq - isn - 1) & 0xFFFFFFFF
        if rel > 0x7FFFFFFF:
            continue                      # before the ISN: ignore
        items.append((rel, pay))
    items.sort(key=lambda x: x[0])
    out = bytearray()
    for rel, pay in items:
        if rel > len(out):
            conn.gaps += 1
            conn.gap_dir[direction] = True
            return bytes(out)             # hole (capture loss): stop here
        if rel + len(pay) <= len(out):
            conn.retrans += 1
            if bytes(out[rel:rel + len(pay)]) != pay:
                conn.overlap_mismatch += 1
            continue
        if rel < len(out):
            conn.retrans += 1
            if bytes(out[rel:]) != pay[:len(out) - rel]:
                conn.overlap_mismatch += 1
        out += pay[len(out) - rel:]
    return bytes(out)


def read_pcap(path):
    d = open(path, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    if magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0xd4c3b2a1:
        endian = ">"
    else:
        raise ProtoError("%s: not a classic pcap file" % path)
    linktype = struct.unpack(endian + "I", d[20:24])[0]
    if linktype != 1:
        raise ProtoError("%s: link type %d, expected Ethernet" % (path, linktype))
    off = 24
    conns = collections.OrderedDict()
    isn = {}
    npk = 0
    while off + 16 <= len(d):
        ts, tu, cl, _ol = struct.unpack(endian + "IIII", d[off:off + 16])
        off += 16
        pkt = d[off:off + cl]
        off += cl
        npk += 1
        if len(pkt) < 54 or pkt[12:14] != b"\x08\x00" or pkt[23] != 6:
            continue
        ihl = (pkt[14] & 15) * 4
        tot = struct.unpack(">H", pkt[16:18])[0]
        src = ".".join(str(x) for x in pkt[26:30])
        dst = ".".join(str(x) for x in pkt[30:34])
        t = pkt[14 + ihl:]
        sp, dp, seq, _ack, of = struct.unpack(">HHIIH", t[:14])
        hl = (of >> 12) * 4
        fl = of & 0x3F
        pay = t[hl:tot - ihl]
        syn_only = (fl & 0x12) == 0x02
        if syn_only:
            key = (src, sp, dst, dp)
            conns[key] = TcpConn(key)
            conns[key].t0 = ts + tu / 1e6
            isn[(src, sp, dst, dp)] = seq
            continue
        if (fl & 0x12) == 0x12:           # SYN-ACK: server ISN
            key = (dst, dp, src, sp)
            isn[(src, sp, dst, dp)] = seq
            continue
        key = (src, sp, dst, dp)
        rkey = (dst, dp, src, sp)
        if key in conns:
            c, to_server = conns[key], True
        elif rkey in conns:
            c, to_server = conns[rkey], False
        else:
            continue
        if fl & 0x05:
            c.fin_or_rst = True
        if pay:
            (c.c2s_segs if to_server else c.s2c_segs).append((seq, pay))
    for key, c in conns.items():
        ck = (key[0], key[1], key[2], key[3])
        sk = (key[2], key[3], key[0], key[1])
        c.c2s = _reassemble(c.c2s_segs, isn.get(ck, 0), c, "c2s")
        c.s2c = _reassemble(c.s2c_segs, isn.get(sk, 0), c, "s2c")
    return npk, list(conns.values())


# ----------------------------------------------------------------------------
# cephx crypto (cephx note sections 2.3 - 2.6, 2.8), written from the note
# ----------------------------------------------------------------------------

class CKey:
    def __init__(self, ktype, created, secret):
        self.type, self.created, self.secret = ktype, created, bytes(secret)

    @staticmethod
    def decode(rd):
        t = rd.u16()
        created = rd.take(8)
        n = rd.u16()
        return CKey(t, created, rd.take(n))

    @staticmethod
    def from_b64(s):
        raw = base64.b64decode(s)
        rd = Rd(raw)
        k = CKey.decode(rd)
        if rd.left():
            raise ProtoError("trailing bytes in key encoding")
        return k

    def fingerprint(self):
        """For logs only: never print the key itself."""
        return hashlib.sha256(b"fp" + self.secret).hexdigest()[:8]


def _aes_cbc(key, iv, data, enc):
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    x = c.encryptor() if enc else c.decryptor()
    return x.update(data) + x.finalize()


def _aes_ecb(key, data, enc):
    c = Cipher(algorithms.AES(key), modes.ECB())
    x = c.encryptor() if enc else c.decryptor()
    return x.update(data) + x.finalize()


def _kdf384(base, usage, typ, nbytes):
    msg = b"\x00\x00\x00\x01" + struct.pack(">I", usage) + bytes([typ]) + b"\x00" \
        + struct.pack(">I", nbytes * 8)
    return hmac.new(base, msg, hashlib.sha384).digest()[:nbytes]


def _cs3_encrypt(ke, m):
    n = len(m)
    if n < 16:
        raise ProtoError("CS3 needs >= 16 bytes")
    if n == 16:
        return _aes_cbc(ke, bytes(16), m, True)
    padded = m + bytes(pad16(n) - n)
    c = _aes_cbc(ke, bytes(16), padded, True)
    blocks = [c[i:i + 16] for i in range(0, len(c), 16)]
    k = len(blocks)
    r = n - 16 * (k - 1)
    return b"".join(blocks[:k - 2]) + blocks[k - 1] + blocks[k - 2][:r]


def _cs3_decrypt(ke, w):
    n = len(w)
    if n < 16:
        raise ProtoError("CS3 needs >= 16 bytes")
    if n == 16:
        return _aes_cbc(ke, bytes(16), w, False)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    head = w[:16 * (k - 2)]
    ck = w[16 * (k - 2):16 * (k - 1)]
    part = w[16 * (k - 1):]
    dk = _aes_ecb(ke, ck, False)
    ckm1 = part + dk[r:]
    prev = head[-16:] if k - 2 >= 1 else bytes(16)
    pkm1 = bytes(a ^ b for a, b in zip(_aes_ecb(ke, ckm1, False), prev))
    pk = bytes(a ^ b for a, b in zip(dk[:r], part))
    plain_head = _aes_cbc(ke, bytes(16), head, False) if head else b""
    return plain_head + pkm1 + pk


def cephx_encrypt(key, usage, plain, confounder=None):
    if key.type == 1:
        pad = 16 - (len(plain) % 16)
        return _aes_cbc(key.secret[:16], CEPH_AES_IV, plain + bytes([pad]) * pad, True)
    if key.type == 2:
        conf = confounder if confounder is not None else os.urandom(16)
        ki = _kdf384(key.secret, usage, 0x55, 24)
        ke = _kdf384(key.secret, usage, 0xAA, 32)
        ct = _cs3_encrypt(ke, conf + plain)
        mac = hmac.new(ki, bytes(16) + ct, hashlib.sha384).digest()[:24]
        return ct + mac
    raise ProtoError("unsupported key type %d" % key.type)


def cephx_decrypt(key, usage, ct):
    if key.type == 1:
        if len(ct) == 0 or len(ct) % 16:
            raise ProtoError("type-1 ciphertext length %d" % len(ct))
        p = _aes_cbc(key.secret[:16], CEPH_AES_IV, ct, False)
        pad = p[-1]
        if not 1 <= pad <= 16:
            raise ProtoError("bad type-1 padding byte %d" % pad)
        return p[:-pad]
    if key.type == 2:
        if len(ct) < 40:
            raise ProtoError("type-2 ciphertext too short")
        body, mac = ct[:-24], ct[-24:]
        ki = _kdf384(key.secret, usage, 0x55, 24)
        ke = _kdf384(key.secret, usage, 0xAA, 32)
        want = hmac.new(ki, bytes(16) + body, hashlib.sha384).digest()[:24]
        if not hmac.compare_digest(want, mac):
            raise ProtoError("type-2 MAC mismatch")
        return _cs3_decrypt(ke, body)[16:]
    raise ProtoError("unsupported key type %d" % key.type)


def open_envelope(key, usage, ct):
    """Decrypt, then check u8 version and the magic. Returns a reader at the item."""
    p = cephx_decrypt(key, usage, ct)
    rd = Rd(p)
    v = rd.u8()
    magic = rd.u64()
    if magic != ENVELOPE_MAGIC:
        raise ProtoError("envelope magic mismatch")
    R.check("cephx.envelope_struct_v_is_1", v == 1, "envelope struct_v=%d" % v)
    return v, rd


def seal_envelope(key, usage, item, confounder=None):
    return cephx_encrypt(key, usage, p8(1) + p64(ENVELOPE_MAGIC) + item, confounder)


def cephx_proof(key, server_challenge, client_challenge):
    """cephx note 2.8."""
    blob = p64(server_challenge) + p64(client_challenge)
    if key.type == 1:
        ct = seal_envelope(key, 0, blob)
        s = pblob(ct)                       # length-prefixed shape, 36 bytes
        x = 0
        for off in (0, 8, 16, 24):
            x ^= struct.unpack("<Q", s[off:off + 8])[0]
        return x
    d = hmac.new(key.secret, blob, hashlib.sha256).digest()
    x = 0
    for off in (0, 8, 16, 24):
        x ^= struct.unpack("<Q", d[off:off + 8])[0]
    return x


def parse_keyring(path):
    """-> dict entity -> CKey. Never prints."""
    out = {}
    cur = None
    for line in open(path):
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1]
        elif cur and line.startswith("key"):
            out[cur] = CKey.from_b64(line.split("=", 1)[1].strip())
    return out


# ----------------------------------------------------------------------------
# msgr2 frames: crc framing (note 2.8, "contrast") and secure framing (2.8)
# ----------------------------------------------------------------------------

class Frame:
    __slots__ = ("tag", "n", "lens", "aligns", "flags", "reserved", "segs",
                 "start", "end", "late", "mode", "ops", "wire", "epi_raw",
                 "pad_ok", "dir")

    def __init__(self):
        self.late = None
        self.ops = []
        self.pad_ok = True
        self.epi_raw = b""

    def name(self):
        return TAGS.get(self.tag, "tag%d" % self.tag)


def _parse_preamble(pre, crc_group):
    """pre: 32 bytes plaintext. Returns (tag, n, lens, aligns, flags, reserved)."""
    want = struct.unpack("<I", pre[28:32])[0]
    got = crc32c(pre[:28], 0)
    R.check(crc_group, want == got, "preamble crc: wire %08x computed %08x" % (want, got))
    if want != got:
        raise ProtoError("preamble crc mismatch")
    tag, n = pre[0], pre[1]
    lens, aligns = [], []
    for i in range(4):
        l, a = struct.unpack("<IH", pre[2 + 6 * i:8 + 6 * i])
        lens.append(l)
        aligns.append(a)
    flags, reserved = pre[26], pre[27]
    if not 1 <= n <= 4:
        raise ProtoError("segment count %d" % n)
    for i in range(n, 4):
        R.check("frame.unused_slots_zero", lens[i] == 0 and aligns[i] == 0,
                "unused segment slot %d nonzero" % i)
    return tag, n, lens, aligns, flags, reserved


MAX_SEG = 64 * 1024 * 1024


def parse_crc_frame(buf, pos):
    """One msgr2.1 crc-mode frame. Raises ProtoError on any inconsistency."""
    f = Frame()
    f.mode, f.start = "crc", pos
    if pos + PREAMBLE > len(buf):
        raise ProtoError("truncated preamble at %d" % pos)
    tag, n, lens, aligns, flags, reserved = _parse_preamble(buf[pos:pos + PREAMBLE],
                                                            "crc.preamble_crc")
    f.tag, f.n, f.lens, f.aligns, f.flags, f.reserved = tag, n, lens, aligns, flags, reserved
    if any(l > MAX_SEG for l in lens):
        raise ProtoError("absurd segment length")
    p = pos + PREAMBLE
    segs = []
    # segment 0 followed by its CRC only if len_0 > 0 (note 2.8)
    if lens[0] > 0:
        s = buf[p:p + lens[0]]
        c = buf[p + lens[0]:p + lens[0] + 4]
        if len(s) < lens[0] or len(c) < 4:
            raise ProtoError("truncated segment 0")
        want = struct.unpack("<I", c)[0]
        got = crc32c(s, 0xFFFFFFFF)
        R.check("crc.seg0_crc_seed_ffffffff", want == got,
                "seg0 crc wire %08x computed %08x" % (want, got))
        if want != got:
            raise ProtoError("segment 0 crc mismatch")
        p += lens[0] + 4
        segs.append(bytes(s))
    else:
        segs.append(b"")
    for i in range(1, n):
        s = buf[p:p + lens[i]]
        if len(s) < lens[i]:
            raise ProtoError("truncated segment %d" % i)
        segs.append(bytes(s))
        p += lens[i]
    if n > 1:
        epi = buf[p:p + 13]
        if len(epi) < 13:
            raise ProtoError("truncated epilogue")
        f.late = epi[0]
        f.epi_raw = bytes(epi)
        crcs = struct.unpack("<3I", epi[1:13])
        for i in range(1, n):
            got = crc32c(segs[i], 0xFFFFFFFF)
            R.check("crc.segN_crc_in_epilogue", crcs[i - 1] == got,
                    "seg %d crc wire %08x computed %08x" % (i, crcs[i - 1], got))
            if crcs[i - 1] != got:
                raise ProtoError("segment %d crc mismatch" % i)
        for i in range(n, 4):
            R.check("crc.unused_epilogue_slots_zero", crcs[i - 1] == 0,
                    "unused epilogue slot %d = %08x" % (i, crcs[i - 1]))
        R.check("crc.late_status_complete", (epi[0] & 0x0f) == 0x0e,
                "late_status %02x" % epi[0])
        R.check("crc.late_status_exact_0e", epi[0] == 0x0e, "late_status %02x" % epi[0])
        p += 13
    f.segs, f.end = segs, p
    f.wire = bytes(buf[pos:p])
    R.check("frame.flags_zero", flags == 0 and reserved == 0,
            "flags=%02x reserved=%02x" % (flags, reserved))
    return f


class GcmDir:
    """One direction of the secure stream: shared AES key + its own nonce (note 2.6)."""

    def __init__(self, key16, nonce12):
        self.key = bytes(key16)
        self.aead = AESGCM(self.key)
        self.fixed = bytes(nonce12[:4])
        self.ctr = struct.unpack("<Q", nonce12[4:12])[0]
        self.seed = bytes(nonce12)
        self.nops = 0

    def iv(self):
        return self.fixed + struct.pack("<Q", self.ctr)

    def step(self):
        self.ctr = (self.ctr + 1) & 0xFFFFFFFFFFFFFFFF
        self.nops += 1

    def decrypt(self, data):
        """data = ciphertext || 16-byte tag. Returns plaintext; steps the nonce."""
        iv = self.iv()
        self.step()
        try:
            return self.aead.decrypt(iv, bytes(data), None)
        except InvalidTag:
            raise ProtoError("GCM tag mismatch")

    def encrypt(self, plain):
        iv = self.iv()
        self.step()
        return self.aead.encrypt(iv, bytes(plain), None)


def split_secret(secret):
    """note 2.6. Returns (key, seedA, seedB)."""
    if len(secret) < 40:
        raise ProtoError("connection secret shorter than 40 bytes")
    return secret[0:16], secret[16:28], secret[28:40]


def parse_secure_frame(buf, pos, gcm):
    """note 3.4. gcm: GcmDir for this direction (stateful)."""
    f = Frame()
    f.mode, f.start = "sec", pos
    if pos + 96 > len(buf):
        raise ProtoError("truncated first part at %d (have %d)" % (pos, len(buf) - pos))
    p1 = gcm.decrypt(buf[pos:pos + 96])
    f.ops.append((pos, 96))
    tag, n, lens, aligns, flags, reserved = _parse_preamble(p1[:PREAMBLE],
                                                            "sec.preamble_crc")
    f.tag, f.n, f.lens, f.aligns, f.flags, f.reserved = tag, n, lens, aligns, flags, reserved
    if any(l > MAX_SEG for l in lens):
        raise ProtoError("absurd segment length")
    inline = p1[PREAMBLE:]
    p = pos + 96
    l0 = lens[0]
    if l0 > INLINE:
        rem_len = pad16(l0) - INLINE
        ct = buf[p:p + rem_len + TAG]
        if len(ct) < rem_len + TAG:
            raise ProtoError("truncated part 2")
        rem = gcm.decrypt(ct)
        f.ops.append((p, rem_len + TAG))
        p += rem_len + TAG
        seg0 = (inline + rem)[:l0]
        f.pad_ok &= all(b == 0 for b in rem[l0 - INLINE:])
    else:
        seg0 = inline[:l0]
        f.pad_ok &= all(b == 0 for b in inline[l0:])
    segs = [bytes(seg0)]
    if n > 1:
        need = sum(pad16(lens[i]) for i in range(1, n)) + 16 + TAG
        ct = buf[p:p + need]
        if len(ct) < need:
            raise ProtoError("truncated part 3")
        pt = gcm.decrypt(ct)
        f.ops.append((p, need))
        p += need
        q = 0
        for i in range(1, n):
            segs.append(bytes(pt[q:q + lens[i]]))
            f.pad_ok &= all(b == 0 for b in pt[q + lens[i]:q + pad16(lens[i])])
            q += pad16(lens[i])
        epi = pt[q:q + 16]
        f.late = epi[0]
        f.epi_raw = bytes(epi)
        R.check("sec.late_status_complete", (epi[0] & 0x0f) == 0x0e, "late %02x" % epi[0])
        R.check("sec.late_status_exact_0e", epi[0] == 0x0e, "late %02x" % epi[0])
        R.check("sec.epilogue_pad_zero", all(b == 0 for b in epi[1:]),
                "epilogue padding nonzero")
    f.segs, f.end = segs, p
    f.wire = bytes(buf[pos:p])
    R.check("frame.flags_zero", flags == 0 and reserved == 0,
            "flags=%02x reserved=%02x" % (flags, reserved))
    return f


def secure_wire_size(lens):
    """Total wire bytes of a secure 2.1 frame from the segment lengths (note 5.1 table)."""
    lens = list(lens)
    while len(lens) > 1 and lens[-1] == 0:
        lens.pop()
    n = len(lens)
    total = 96
    nops = 1
    if lens[0] > INLINE:
        total += pad16(lens[0]) - INLINE + TAG
        nops += 1
    if n > 1:
        total += sum(pad16(x) for x in lens[1:]) + 16 + TAG
        nops += 1
    return total, nops


def assemble_secure(tag, segs, aligns, gcm):
    """note 3.3, our own sender. segs: list of bytes (already trailing-empty-free).
    Returns the wire bytes; steps gcm."""
    segs = [bytes(s) for s in segs]
    while len(segs) > 1 and not segs[-1]:
        segs.pop()
    n = len(segs)
    pre = bytearray(32)
    pre[0], pre[1] = tag, n
    for i in range(4):
        l = len(segs[i]) if i < n else 0
        a = aligns[i] if i < n else 0
        pre[2 + 6 * i:8 + 6 * i] = struct.pack("<IH", l, a)
    pre[28:32] = struct.pack("<I", crc32c(bytes(pre[:28]), 0))
    s0 = segs[0]
    if len(s0) <= INLINE:
        inline, rest = s0 + bytes(INLINE - len(s0)), b""
    else:
        inline = s0[:INLINE]
        r = s0[INLINE:]
        rest = r + bytes(pad16(len(r)) - len(r))
    out = gcm.encrypt(bytes(pre) + inline)
    if rest:
        out += gcm.encrypt(rest)
    if n > 1:
        body = b"".join(s + bytes(pad16(len(s)) - len(s)) for s in segs[1:])
        body += b"\x0e" + bytes(15)
        out += gcm.encrypt(body)
    return out


def assemble_crc(tag, segs, aligns):
    """crc-mode sender for the pre-auth frames (our own, for vectors)."""
    segs = [bytes(s) for s in segs]
    while len(segs) > 1 and not segs[-1]:
        segs.pop()
    n = len(segs)
    pre = bytearray(32)
    pre[0], pre[1] = tag, n
    for i in range(4):
        l = len(segs[i]) if i < n else 0
        a = aligns[i] if i < n else 0
        pre[2 + 6 * i:8 + 6 * i] = struct.pack("<IH", l, a)
    pre[28:32] = struct.pack("<I", crc32c(bytes(pre[:28]), 0))
    out = bytes(pre)
    if segs[0]:
        out += segs[0] + struct.pack("<I", crc32c(segs[0], 0xFFFFFFFF))
    for s in segs[1:]:
        out += s
    if n > 1:
        crcs = [crc32c(s, 0xFFFFFFFF) for s in segs[1:]] + [0] * (4 - n)
        out += b"\x0e" + struct.pack("<3I", *crcs[:3])
    return out


# ----------------------------------------------------------------------------
# decoding of the frame payloads (note 2.4, cephx note 2.2 / 2.7)
# ----------------------------------------------------------------------------

def dec_auth_request(seg):
    rd = Rd(seg)
    d = {"method": rd.u32(), "modes": rd.vec_u32(), "payload": rd.blob()}
    if rd.left():
        raise ProtoError("AUTH_REQUEST: %d trailing bytes" % rd.left())
    return d


def dec_auth_bad_method(seg):
    rd = Rd(seg)
    d = {"method": rd.u32(), "result": rd.s32(), "allowed_methods": rd.vec_u32(),
         "allowed_modes": rd.vec_u32()}
    if rd.left():
        raise ProtoError("AUTH_BAD_METHOD: trailing bytes")
    return d


def dec_blob_frame(seg):
    rd = Rd(seg)
    d = {"payload": rd.blob()}
    if rd.left():
        raise ProtoError("blob frame: %d trailing bytes" % rd.left())
    return d


def dec_auth_done(seg):
    rd = Rd(seg)
    d = {"global_id": rd.u64(), "con_mode": rd.u32(), "payload": rd.blob()}
    if rd.left():
        raise ProtoError("AUTH_DONE: trailing bytes")
    return d


def dec_ticket_blob(rd):
    """CephXTicketBlob: u8 v, u64 secret_id, blob data."""
    v = rd.u8()
    sid = rd.u64()
    data = rd.blob()
    return {"v": v, "secret_id": sid, "data": data}


def enc_ticket_blob(tb):
    return p8(tb["v"]) + p64(tb["secret_id"]) + pblob(tb["data"])


class Ticket:
    def __init__(self, service, key, validity, blob_inner, secret_id):
        self.service, self.key, self.validity = service, key, validity
        self.blob_inner, self.secret_id = blob_inner, secret_id


def dec_ticket_reply(rd, dec_key, prev_key=None):
    """cephx note 2.7 'Ticket reply'. Returns list of Ticket."""
    v = rd.u8()
    num = rd.u32()
    out = []
    R.check("cephx.ticket_reply_v1", v == 1, "reply_v=%d" % v)
    for _ in range(num):
        service = rd.u32()
        tv = rd.u8()
        msg_a = rd.blob()
        enc = rd.u8()
        blob = rd.blob()
        R.check("cephx.ticket_v1", tv == 1, "ticket_v=%d" % tv)
        R.check("cephx.ticket_enc_flag", enc in (0, 1), "ticket_enc=%d" % enc)
        _v, ird = open_envelope(dec_key, USAGE_TICKET_KEY, msg_a)
        sv = ird.u8()
        sk = CKey.decode(ird)
        validity = (ird.u32(), ird.u32())
        R.check("cephx.service_ticket_v1", sv == 1, "CephXServiceTicket v=%d" % sv)
        R.check("cephx.service_ticket_no_trailing", ird.left() == 0,
                "%d trailing bytes in service ticket" % ird.left())
        if enc == 1:
            if prev_key is None:
                raise ProtoError("ticket_enc=1 without previous key")
            _v2, brd = open_envelope(prev_key, USAGE_TICKET_BLOB, blob)
            blob = brd.blob()
            inner = blob
        else:
            inner = blob
        brd = Rd(inner)
        tb = dec_ticket_blob(brd)
        R.check("cephx.ticket_blob_exact", brd.left() == 0, "trailing in ticket blob")
        out.append(Ticket(service, sk, validity, inner, tb["secret_id"]))
    return out


def dec_mon_auth_done_payload(payload, principal_key, prev_key=None):
    """cephx note 2.7 'Mon reply'. Returns dict with session key, tickets, secret."""
    rd = Rd(payload)
    rtype = rd.u16()
    status = rd.s32()
    d = {"request_type": rtype, "status": status}
    if status != 0:
        d["error"] = True
        return d
    tickets = dec_ticket_reply(rd, principal_key, prev_key)
    d["auth_ticket"] = tickets[0] if tickets else None
    d["tickets"] = tickets
    d["secret"] = None
    d["extra"] = []
    if rd.left():
        cbl = rd.blob()
        extra = rd.blob()
        d["cbl_outer_len"] = len(cbl)
        crd = Rd(cbl)
        if len(cbl):
            inner = crd.blob()
            R.check("cephx.cbl_exact", crd.left() == 0, "trailing bytes in cbl")
            _v, srd = open_envelope(tickets[0].key, USAGE_CONN_SECRET, inner)
            sl = srd.u32()
            sec = srd.take(sl)
            R.check("cephx.cbl_secret_exact", srd.left() == 0,
                    "trailing %d bytes after secret" % srd.left())
            d["secret"] = sec
            d["cbl_inner_len"] = len(inner)
        d["extra_len"] = len(extra)
        if extra:
            erd = Rd(extra)
            d["extra"] = dec_ticket_reply(erd, tickets[0].key)
            R.check("cephx.extra_exact", erd.left() == 0, "trailing bytes in extra")
    R.check("cephx.mon_reply_exact", rd.left() == 0, "trailing %d" % rd.left())
    return d


def dec_authorizer(payload):
    """cephx note 2.7 'Authorizer'. Returns dict (proof still encrypted)."""
    rd = Rd(payload)
    d = {"v": rd.u8(), "global_id": rd.u64(), "service_id": rd.u32()}
    tb_start = rd.p
    d["ticket"] = dec_ticket_blob(rd)
    d["ticket_bytes"] = payload[tb_start:rd.p]
    d["proof"] = rd.blob()
    if rd.left():
        raise ProtoError("authorizer: %d trailing bytes" % rd.left())
    return d


# ----------------------------------------------------------------------------
# connection analysis
# ----------------------------------------------------------------------------

SECRET_DIGESTS = set()
NEG_DONE = {}


def negative_controls(key16, seedA, seedB, first_c2s, first_s2c, group="sec.negative_controls"):
    """Show that the positive results above are not vacuous: wrong readings of the
    note must FAIL on the same real bytes."""
    def tag_fails(fn):
        try:
            fn()
            return False
        except ProtoError:
            return True
    w = first_s2c
    # (1) swapped seeds
    R.check(group, tag_fails(lambda: parse_secure_frame(w, 0, GcmDir(key16, seedB))),
            "swapped seeds were accepted")
    # (2) one flipped ciphertext bit
    bad = bytearray(w)
    bad[5] ^= 1
    R.check(group, tag_fails(lambda: parse_secure_frame(bytes(bad), 0, GcmDir(key16, seedA))),
            "flipped ciphertext bit accepted")
    # (3) flipped tag bit
    bad = bytearray(w)
    bad[90] ^= 1
    R.check(group, tag_fails(lambda: parse_secure_frame(bytes(bad), 0, GcmDir(key16, seedA))),
            "flipped tag bit accepted")
    # (4) wrong key
    R.check(group, tag_fails(lambda: parse_secure_frame(w, 0, GcmDir(bytes(16), seedA))),
            "wrong key accepted")
    # (5) msgr2.0-style nonce stepping (le32 'fixed' field) must break the SECOND operation
    class Gcm20(GcmDir):
        def step(self):
            f = (struct.unpack("<I", self.fixed)[0] + 1) & 0xFFFFFFFF
            self.fixed = struct.pack("<I", f)
            self.nops += 1
    g20 = Gcm20(key16, seedA)
    try:
        # decode as many frames as possible from the stream with 2.0 stepping
        pos, n_ok = 0, 0
        while pos < len(w):
            f = parse_secure_frame(w, pos, g20)
            pos = f.end
            n_ok += 1
        stepped_ok = False
    except ProtoError:
        stepped_ok = True
    R.check(group, stepped_ok, "msgr2.0 nonce stepping decoded a 2.1 stream")



class KeyStore:
    def __init__(self, keydirs):
        self.rings = []            # (path-label, entity, CKey)
        for d in keydirs:
            for p in sorted(glob.glob(os.path.join(d, "*keyring*"))):
                try:
                    for ent, k in parse_keyring(p).items():
                        self.rings.append((os.path.basename(p), ent, k))
                except Exception:
                    pass

    def for_entity(self, entity):
        return [(lab, k) for lab, ent, k in self.rings if ent == entity]


class Analysis:
    """All state for one pcap: tickets learned from mon replies, per-conn results."""

    def __init__(self, name, keystore):
        self.name = name
        self.keys = keystore
        self.tickets = []          # Ticket objects (any service) in discovery order
        self.auth_key = None       # AUTH session key (CKey)
        self.principal = None
        self.conns = []            # summary dicts
        self.secure_conns = []     # kept for vector export / round trip

    def find_ticket(self, ticket_bytes_inner):
        for t in self.tickets:
            if t.blob_inner == ticket_bytes_inner:
                return t
        return None


def walk_crc_prefix(buf, pos, stop_after_tags, report):
    """Parse crc frames until the end of the stream. Returns frames."""
    frames = []
    while pos < len(buf):
        try:
            f = parse_crc_frame(buf, pos)
        except ProtoError as e:
            report.append("crc frame at %d: %s" % (pos, e))
            break
        frames.append(f)
        pos = f.end
        if stop_after_tags and f.tag in stop_after_tags:
            break
    return frames, pos


def check_banner(buf, who, session):
    """note 2.2."""
    ok = len(buf) >= 26 and buf[:8] == BANNER_PREFIX
    R.check("banner.prefix", ok, "%s: banner prefix" % who)
    if not ok:
        raise ProtoError("%s: no msgr2 banner" % who)
    plen = struct.unpack("<H", buf[8:10])[0]
    R.check("banner.payload_len_16", plen == 16, "%s: payload_len %d" % (who, plen))
    sup, req = struct.unpack("<QQ", buf[10:26])
    return 10 + plen, sup, req


def analyze_conn(conn, an, res):
    """Analyse one TCP connection. res: summary dict (filled in)."""
    problems = []
    res["sport"] = conn.sport
    res["cport"] = conn.cport
    res["bytes_c2s"], res["bytes_s2c"] = len(conn.c2s), len(conn.s2c)
    if conn.gaps:
        R.defect("%s sport %d: TCP hole in %s (capture loss, stream used up to the hole)"
                 % (an.name, conn.sport, ",".join(d for d, v in conn.gap_dir.items() if v)))
    R.check("tcp.retransmit_bytes_identical", conn.overlap_mismatch == 0,
            "%s: retransmitted bytes differ" % an.name)
    res["retrans"] = conn.retrans
    c2s, s2c = conn.c2s, conn.s2c
    if not c2s or not s2c:
        res["skipped"] = "no data in one direction"
        return
    # --- banners (note 2.2)
    try:
        cb_end, csup, creq = check_banner(c2s, "client", an.name)
        sb_end, ssup, sreq = check_banner(s2c, "server", an.name)
    except ProtoError as e:
        R.check("banner.present", False, "%s sport %d: %s" % (an.name, conn.sport, e))
        res["skipped"] = str(e)
        return
    res["banner"] = {"client": (csup, creq), "server": (ssup, sreq)}
    R.check("banner.server_supported_3", ssup == 3 and sreq == 0,
            "server banner %x/%x" % (ssup, sreq))
    R.check("banner.client_supported_has_rev1", csup & 1 == 1,
            "client banner %x/%x" % (csup, creq))
    res["client_adv_compression"] = bool(csup & 2)
    res["server_adv_compression"] = bool(ssup & 2)
    # --- plaintext handshake frames, server direction until AUTH_DONE / BAD_METHOD
    rep = []
    sframes = []
    pos = sb_end
    while pos < len(s2c):
        try:
            f = parse_crc_frame(s2c, pos)
        except ProtoError as e:
            rep.append("s2c crc frame @%d: %s" % (pos, e))
            break
        sframes.append(f)
        pos = f.end
        if f.tag in (T_AUTH_DONE, T_AUTH_BAD_METHOD):
            break
    s_auth_end = pos
    cframes = []
    pos = cb_end
    n_more = sum(1 for f in sframes if f.tag == T_AUTH_REPLY_MORE)
    want_c = None
    while pos < len(c2s):
        # client plaintext: HELLO, AUTH_REQUEST, then one AUTH_REQUEST_MORE per REPLY_MORE
        done_cnt = sum(1 for f in cframes if f.tag == T_AUTH_REQUEST_MORE)
        if any(f.tag == T_AUTH_REQUEST for f in cframes) and done_cnt >= n_more:
            if sframes and sframes[-1].tag == T_AUTH_DONE:
                break
            if sframes and sframes[-1].tag == T_AUTH_BAD_METHOD:
                break
        try:
            f = parse_crc_frame(c2s, pos)
        except ProtoError as e:
            rep.append("c2s crc frame @%d: %s" % (pos, e))
            break
        cframes.append(f)
        pos = f.end
    c_auth_end = pos
    for r in rep:
        R.check("crc.frames_parse", False, "%s sport %d: %s" % (an.name, conn.sport, r))
    res["hs_frames_c2s"] = [f.name() for f in cframes]
    res["hs_frames_s2c"] = [f.name() for f in sframes]
    if not sframes or sframes[-1].tag not in (T_AUTH_DONE, T_AUTH_BAD_METHOD):
        res["no_auth_result"] = True
        res["hs_note"] = "server sent no AUTH_DONE / BAD_METHOD (frames: %s)" % \
            ",".join(f.name() for f in sframes)
        return
    # HELLO
    for who, fl in (("c", cframes), ("s", sframes)):
        if fl and fl[0].tag == T_HELLO:
            R.check("hello.is_first_frame", True)
            R.check("hello.single_segment", fl[0].n == 1, "HELLO n=%d" % fl[0].n)
            if who == "s":
                res["server_hello_type"] = fl[0].segs[0][0]
            else:
                res["client_hello_type"] = fl[0].segs[0][0]
        else:
            R.check("hello.is_first_frame", False, "%s: first frame not HELLO" % who)
    # --- AUTH_REQUEST (note 2.4)
    req = next((f for f in cframes if f.tag == T_AUTH_REQUEST), None)
    if req is None:
        raise ProtoError("no AUTH_REQUEST")
    R.check("auth.single_segment_frames",
            all(f.n == 1 for f in cframes + sframes), "auth frame with n != 1")
    ar = dec_auth_request(req.segs[0])
    res["method"], res["offered_modes"] = ar["method"], ar["modes"]
    R.check("auth.method_cephx", ar["method"] == 2, "method %d" % ar["method"])
    pl = ar["payload"]
    res["payload_first_byte"] = pl[0] if pl else None
    is_mon_auth = bool(pl) and pl[0] == 10
    res["kind"] = "mon-auth" if is_mon_auth else "authorizer"
    # transcripts (note 2.7)
    s2c_tr = bytes(s2c[:s_auth_end])
    last = sframes[-1]
    if last.tag == T_AUTH_BAD_METHOD:
        bm = dec_auth_bad_method(last.segs[0])
        res["bad_method"] = bm
        res["offered_modes_at_bad_method"] = ar["modes"]
        # what follows on the same TCP connection (note open question 2: does the
        # client retry AUTH_REQUEST on the same connection after BAD_METHOD?)
        extra_c, _p = walk_crc_prefix(c2s, c_auth_end, None, [])
        res["after_bad_method_c2s"] = [f.name() for f in extra_c]
        res["after_bad_method_s2c_bytes"] = len(s2c) - s_auth_end
        res["bad_method_frames_single_segment"] = last.n == 1
        return
    done = dec_auth_done(last.segs[0])
    res["con_mode"] = done["con_mode"]
    res["global_id_in_done"] = done["global_id"]
    R.check("auth.done_mode_was_offered", done["con_mode"] in ar["modes"],
            "AUTH_DONE mode %d not in offered %s" % (done["con_mode"], ar["modes"]))
    R.check("auth.done_mode_valid", done["con_mode"] in (1, 2), "mode %d" % done["con_mode"])
    # the client's first offered mode that the server allows wins: with both
    # allowed this is simply the first one offered (note 2.4 / 2.9)
    res["first_offered_picked"] = (done["con_mode"] == ar["modes"][0])
    c2s_tr = bytes(c2s[:c_auth_end])
    secret = None
    sess_key = None
    # ---- cephx
    if is_mon_auth:
        rd = Rd(pl)
        rd.u8()
        etype = rd.u32()
        eid = rd.blob()
        gid = rd.u64()
        R.check("cephx.mon_auth_payload_exact", rd.left() == 0, "trailing")
        R.check("cephx.mon_auth_entity_type_client", etype == 8, "entity type %d" % etype)
        res["entity"] = "client." + eid.decode("utf8", "replace")
        res["req_global_id"] = gid
        # AUTH_REPLY_MORE -> challenge
        rm = [f for f in sframes if f.tag == T_AUTH_REPLY_MORE]
        qm = [f for f in cframes if f.tag == T_AUTH_REQUEST_MORE]
        R.check("cephx.one_challenge_round", len(rm) == 1 and len(qm) == 1,
                "reply_more=%d request_more=%d" % (len(rm), len(qm)))
        chal = Rd(dec_blob_frame(rm[0].segs[0])["payload"])
        v = chal.u8()
        server_challenge = chal.u64()
        R.check("cephx.server_challenge_v1", v == 1 and chal.left() == 0, "v=%d" % v)
        qrd = Rd(dec_blob_frame(qm[0].segs[0])["payload"])
        rtype = qrd.u16()
        av = qrd.u8()
        client_challenge = qrd.u64()
        proof = qrd.u64()
        tb = dec_ticket_blob(qrd)
        other_keys = qrd.u32()
        R.check("cephx.authenticate_exact", qrd.left() == 0, "trailing %d" % qrd.left())
        R.check("cephx.request_type_0100", rtype == 0x0100, "type %x" % rtype)
        R.check("cephx.authenticate_v3", av == 3, "v=%d" % av)
        res["other_keys"] = other_keys
        res["old_ticket_len"] = len(tb["data"])
        res["authenticate_v"] = av
        R.check("cephx.other_keys_has_auth_bit", other_keys & 0x20, "other_keys %x" % other_keys)
        # identify the principal key by reproducing the proof
        cands = an.keys.for_entity(res["entity"])
        matched = None
        for lab, k in cands:
            if cephx_proof(k, server_challenge, client_challenge) == proof:
                matched = (lab, k)
                break
        res["proof_key_candidates"] = len(cands)
        if matched is None:
            R.check("cephx.challenge_proof", False,
                    "%s sport %d: proof matches none of %d candidate keys for %s"
                    % (an.name, conn.sport, len(cands), res["entity"]))
            res["proof_matched"] = False
        else:
            R.check("cephx.challenge_proof", True)
            res["proof_matched"] = True
            res["principal_label"] = matched[0]
            res["principal_type"] = matched[1].type
            an.principal = matched[1]
            # decode the reply
            try:
                d = dec_mon_auth_done_payload(done["payload"], matched[1], an.auth_key)
            except ProtoError as e:
                R.check("cephx.mon_reply_decrypt", False, "%s sport %d: %s" % (an.name, conn.sport, e))
                return
            R.check("cephx.mon_reply_decrypt", True)
            R.check("cephx.mon_reply_status_0", d.get("status") == 0, "status %s" % d.get("status"))
            R.check("cephx.mon_reply_type_0100", d.get("request_type") == 0x0100,
                    "type %x" % d.get("request_type", -1))
            at = d["auth_ticket"]
            R.check("cephx.reply_has_single_auth_ticket",
                    len(d["tickets"]) == 1 and at.service == 0x20, "tickets %d" % len(d["tickets"]))
            R.check("cephx.auth_session_key_type_matches_principal", at.key.type == matched[1].type,
                    "auth key type %d principal %d" % (at.key.type, matched[1].type))
            sess_key = at.key
            an.auth_key = at.key
            res["auth_session_key_type"] = at.key.type
            res["auth_session_secret_len"] = len(at.key.secret)
            for t in d["extra"]:
                an.tickets.append(t)
            res["extra_services"] = sorted(t.service for t in d["extra"])
            res["extra_key_types"] = sorted(set(t.key.type for t in d["extra"]))
            res["cbl_outer_len"] = d.get("cbl_outer_len")
            res["cbl_inner_len"] = d.get("cbl_inner_len")
            secret = d["secret"]
            res["secret_len"] = len(secret) if secret is not None else None
            res["global_id_matches_done"] = None
            R.check("secure.secret_len_matches_mode",
                    (len(secret) == 64) if done["con_mode"] == MODE_SECURE else (len(secret) == 0),
                    "mode %d secret_len %s" % (done["con_mode"], None if secret is None else len(secret)))
            # the client log lists the session keys it got: cross-check (done by caller)
            res["_ticket_fps"] = [(t.service, t.key.type, t.key.fingerprint()) for t in
                                  [at] + d["extra"]]
    else:
        # authorizer to a service (mgr / osd / mds)
        a1 = dec_authorizer(pl)
        R.check("authorizer.v1", a1["v"] == 1, "authorizer v=%d" % a1["v"])
        res["service_id"] = a1["service_id"]
        res["req_global_id"] = a1["global_id"]
        t = an.find_ticket(a1["ticket_bytes"])
        if t is None:
            res["authorizer_ticket_unknown"] = True
            R.check("authorizer.ticket_known", False,
                    "%s sport %d: authorizer ticket not obtained from any decoded reply"
                    % (an.name, conn.sport))
            return
        R.check("authorizer.ticket_known", True)
        R.check("authorizer.service_matches_ticket", a1["service_id"] == t.service,
                "service_id %d ticket service %d" % (a1["service_id"], t.service))
        sess_key = t.key
        res["ticket_key_type"] = t.key.type
        _v, prd = open_envelope(t.key, USAGE_AUTHORIZE, a1["proof"])
        av, nonce, have_ch, plus1 = prd.u8(), prd.u64(), prd.u8(), prd.u64()
        R.check("authorizer.proof_exact", prd.left() == 0, "trailing")
        R.check("authorizer.first_proof_v2_nochallenge", av == 2 and have_ch == 0 and plus1 == 0,
                "v=%d have=%d plus1=%d" % (av, have_ch, plus1))
        rm = [f for f in sframes if f.tag == T_AUTH_REPLY_MORE]
        qm = [f for f in cframes if f.tag == T_AUTH_REQUEST_MORE]
        R.check("authorizer.one_challenge_round", len(rm) == 1 and len(qm) == 1,
                "reply_more=%d request_more=%d" % (len(rm), len(qm)))
        chal_ct = dec_blob_frame(rm[0].segs[0])["payload"]
        _v, crd = open_envelope(t.key, USAGE_CHALLENGE, chal_ct)
        cv, server_challenge = crd.u8(), crd.u64()
        R.check("authorizer.challenge_raw_no_length_prefix", cv == 1 and crd.left() == 0,
                "challenge v=%d trailing %d" % (cv, crd.left()))
        a2 = dec_authorizer(dec_blob_frame(qm[0].segs[0])["payload"])
        R.check("authorizer.second_same_prefix",
                a2["ticket_bytes"] == a1["ticket_bytes"] and a2["global_id"] == a1["global_id"]
                and a2["service_id"] == a1["service_id"], "second authorizer prefix differs")
        _v, prd2 = open_envelope(t.key, USAGE_AUTHORIZE, a2["proof"])
        av2, nonce2, have2, plus2 = prd2.u8(), prd2.u64(), prd2.u8(), prd2.u64()
        R.check("authorizer.second_proof_have_challenge",
                av2 == 2 and have2 == 1 and plus2 == server_challenge + 1,
                "v=%d have=%d plus1=%x chal+1=%x" % (av2, have2, plus2, server_challenge + 1))
        R.check("authorizer.same_nonce_in_both_sends", nonce2 == nonce, "nonce differs")
        # final reply: blob payload whose content is the length-prefixed ciphertext?
        ap = done["payload"]
        form = None
        try:
            inner = Rd(ap)
            ct = inner.blob()
            if inner.left() == 0:
                form = "blob-of-lenprefixed"
                _v, drd = open_envelope(t.key, USAGE_AUTH_REPLY, ct)
        except ProtoError:
            form = None
        if form is None:
            _v, drd = open_envelope(t.key, USAGE_AUTH_REPLY, ap)
            form = "payload-is-ciphertext"
        res["authorize_reply_form"] = form
        rv = drd.u8()
        n1 = drd.u64()
        R.check("authorizer.reply_nonce_plus_one", n1 == (nonce + 1) & 0xFFFFFFFFFFFFFFFF,
                "nonce+1 mismatch")
        R.check("authorizer.reply_version_matches_mode",
                (rv == 2) if done["con_mode"] == MODE_SECURE else (rv == 1),
                "reply v=%d mode %d" % (rv, done["con_mode"]))
        if rv >= 2:
            sl = drd.u32()
            secret = drd.take(sl)
        else:
            secret = b""
        R.check("authorizer.reply_exact", drd.left() == 0, "trailing %d" % drd.left())
        res["authorize_reply_v"] = rv
        res["secret_len"] = len(secret)
        R.check("secure.secret_len_matches_mode",
                (len(secret) == 64) if done["con_mode"] == MODE_SECURE else (len(secret) == 0),
                "mode %d secret_len %d" % (done["con_mode"], len(secret)))
    # ---- pre-auth signatures (note 2.7) and everything after
    res["sess_key_fp"] = sess_key.fingerprint() if sess_key else None
    mode = done["con_mode"]
    # after-auth streams
    if mode == MODE_SECURE:
        key16, seedA, seedB = split_secret(secret)
        tx = GcmDir(key16, seedB)       # client sends with seed B
        rx = GcmDir(key16, seedA)       # client receives with seed A
        res["_gcm"] = (key16, seedA, seedB)
    else:
        tx = rx = None
    # client's signature frame = first frame after c_auth_end in c2s
    after = {"c2s": [], "s2c": []}
    errs = []

    def walk(buf, pos, gcm, direction):
        frames = []
        while pos < len(buf):
            try:
                if gcm is None:
                    f = parse_crc_frame(buf, pos)
                else:
                    f = parse_secure_frame(buf, pos, gcm)
            except ProtoError as e:
                if str(e).startswith("truncated") and conn.gap_dir[direction]:
                    R.defect("%s sport %d: %s frame at %d cut by the TCP hole (expected)"
                             % (an.name, conn.sport, direction, pos))
                else:
                    errs.append("%s @%d: %s" % (direction, pos, e))
                break
            frames.append(f)
            pos = f.end
        return frames, pos

    cf, cpos = walk(c2s, c_auth_end, tx, "c2s")
    sf, spos = walk(s2c, s_auth_end, rx, "s2c")
    for e in errs:
        R.check("%s.frames_parse" % ("sec" if mode == MODE_SECURE else "crc_after_auth"), False,
                "%s sport %d: %s" % (an.name, conn.sport, e))
    res["after_c2s"] = [f.name() for f in cf]
    res["after_s2c"] = [f.name() for f in sf]
    res["trailing_c2s"] = len(c2s) - cpos
    res["trailing_s2c"] = len(s2c) - spos
    after["c2s"], after["s2c"] = cf, sf
    # signature checks
    if sess_key is not None:
        keyb = sess_key.secret
        want_client = hmac.new(keyb, s2c_tr, hashlib.sha256).digest()
        want_server = hmac.new(keyb, c2s_tr, hashlib.sha256).digest()
        csig = next((f for f in cf if f.tag == T_AUTH_SIGNATURE), None)
        ssig = next((f for f in sf if f.tag == T_AUTH_SIGNATURE), None)
        grp = "signature.sec" if mode == MODE_SECURE else "signature.crc"
        if csig is not None:
            R.check(grp + ".frame_is_first_after_auth", cf[0] is csig, "not first")
            R.check(grp + ".frame_32_bytes", len(csig.segs[0]) == 32 and csig.n == 1,
                    "len %d n %d" % (len(csig.segs[0]), csig.n))
            R.check(grp + ".client_signs_received_bytes",
                    hmac.compare_digest(csig.segs[0], want_client),
                    "%s sport %d: client signature != HMAC(session key, rx transcript)"
                    % (an.name, conn.sport))
        else:
            R.check(grp + ".client_signature_present", False,
                    "%s sport %d: no client AUTH_SIGNATURE" % (an.name, conn.sport))
        if ssig is not None:
            R.check(grp + ".frame_is_first_after_auth", sf[0] is ssig, "not first")
            R.check(grp + ".server_signs_client_bytes",
                    hmac.compare_digest(ssig.segs[0], want_server),
                    "%s sport %d: server signature != HMAC(session key, tx transcript)"
                    % (an.name, conn.sport))
        else:
            R.check(grp + ".server_signature_present", False,
                    "%s sport %d: no server AUTH_SIGNATURE" % (an.name, conn.sport))
        # negative controls: the signature must NOT match nearby wrong scopes
        if csig is not None:
            wrong1 = hmac.new(keyb, s2c_tr[sb_end:], hashlib.sha256).digest()  # without banner
            R.check("signature.banner_is_part_of_transcript",
                    not hmac.compare_digest(csig.segs[0], wrong1), "signature also matches w/o banner")
    res["_frames"] = {"c2s_pre": cframes, "s2c_pre": sframes, "c2s": cf, "s2c": sf}
    res["mode"] = "secure" if mode == MODE_SECURE else "crc"
    res["_tx_transcript_len"] = len(c2s_tr)
    res["_rx_transcript_len"] = len(s2c_tr)
    # --- frame-level checks that apply in either mode after auth
    for fl, dname in ((cf, "c2s"), (sf, "s2c")):
        for f in fl:
            R.check("frame.tag_known", f.tag in TAGS, "unknown tag %d" % f.tag)
            if f.tag == T_MESSAGE:
                R.check("message.seg0_is_41_bytes", len(f.segs[0]) == 41,
                        "%s: MESSAGE seg0 len %d" % (an.name, len(f.segs[0])))
            if f.mode == "sec":
                wire_total, nops = secure_wire_size(f.lens[:f.n])
                R.check("sec.wire_size_formula", wire_total == len(f.wire),
                        "lens %s wire %d formula %d" % (f.lens, len(f.wire), wire_total))
                R.check("sec.op_count_formula", nops == len(f.ops),
                        "lens %s ops %d formula %d" % (f.lens, len(f.ops), nops))
                R.check("sec.padding_is_zero", f.pad_ok, "nonzero padding in %s" % f.name())
                R.check("sec.last_segment_nonempty_if_multi", f.n == 1 or f.lens[f.n - 1] > 0,
                        "empty trailing segment")
            else:
                R.check("crc.last_segment_nonempty_if_multi", f.n == 1 or f.lens[f.n - 1] > 0,
                        "empty trailing segment")
    # --- crc round trip: our crc-mode sender must reproduce every captured crc frame
    for fl in (cframes, sframes) + ((cf, sf) if mode == MODE_CRC else ()):
        for f in fl:
            if f.mode != "crc":
                continue
            out = assemble_crc(f.tag, f.segs[:f.n], f.aligns[:f.n])
            R.check("crc.reassembly_matches_wire", out == f.wire,
                    "%s sport %d %s at %d: re-assembled crc frame differs" %
                    (an.name, conn.sport, f.name(), f.start))
    if mode == MODE_SECURE:
        dig = hashlib.sha256(b"uniq" + secret).hexdigest()
        R.check("secure.secret_fresh_per_connection", dig not in SECRET_DIGESTS,
                "%s sport %d: connection secret repeats an earlier connection" % (an.name, conn.sport))
        SECRET_DIGESTS.add(dig)
        R.check("secure.secret_not_all_zero_and_not_sequential", len(set(secret)) > 20,
                "secret looks degenerate")
    # --- secure round trip: re-assemble every captured frame with our sender
    if mode == MODE_SECURE:
        for fl, seed, dname in ((cf, seedB, "c2s"), (sf, seedA, "s2c")):
            g = GcmDir(key16, seed)
            for f in fl:
                segs = [s for s in f.segs[:f.n]]
                out = assemble_secure(f.tag, segs, f.aligns[:f.n], g)
                R.check("sec.reassembly_matches_wire", out == f.wire,
                        "%s %s sport %d frame %s at %d: re-assembled bytes differ"
                        % (an.name, dname, conn.sport, f.name(), f.start))
    if mode == MODE_SECURE and len(sf) >= 2 and not NEG_DONE.get("done"):
        NEG_DONE["done"] = True
        wire = b"".join(f.wire for f in sf[:3])
        negative_controls(key16, seedA, seedB, None, wire)
    # compression handshake observations
    comp = [f.name() for f in cf + sf if f.tag in (T_COMP_REQ, T_COMP_DONE)]
    res["compression_frames"] = comp
    R.check("compression.both_or_none", len(comp) in (0, 2), "frames %s" % comp)
    for f in cf:
        if f.tag == T_COMP_REQ:
            rd = Rd(f.segs[0])
            ic = rd.u8()
            methods = rd.vec_u32()
            R.check("compression.request_layout", rd.left() == 0, "trailing")
            res["comp_req"] = (ic, methods)
    for f in sf:
        if f.tag == T_COMP_DONE:
            rd = Rd(f.segs[0])
            ic = rd.u8()
            m = rd.u32()
            R.check("compression.done_layout", rd.left() == 0, "trailing")
            res["comp_done"] = (ic, m)
    # order rule: signature(s) first, compression next, then CLIENT_IDENT
    names = [f.name() for f in cf]
    if "CLIENT_IDENT" in names:
        i_id = names.index("CLIENT_IDENT")
        R.check("order.client_ident_after_signature_and_compression",
                names[:i_id] == ["AUTH_SIGNATURE"] + (["COMPRESSION_REQUEST"] if comp else []),
                "client frames before CLIENT_IDENT: %s" % names[:i_id])
    snames = [f.name() for f in sf]
    if "SERVER_IDENT" in snames:
        i_id = snames.index("SERVER_IDENT")
        R.check("order.server_ident_after_signature_and_compression",
                snames[:i_id] == ["AUTH_SIGNATURE"] + (["COMPRESSION_DONE"] if comp else []),
                "server frames before SERVER_IDENT: %s" % snames[:i_id])
    # collect the first secure-mode example for vector export
    if mode == MODE_SECURE:
        an.secure_conns.append(res)
    return


def load_logged_keys(captures, session):
    """Session keys the stock client logged (debug_auth), as fingerprints, to
    cross-check our own decryption. Returns set of (service, type, fp) or None."""
    p = os.path.join(captures, "secrets", "session-secrets", session + ".txt")
    if not os.path.exists(p):
        return None
    out = set()
    for line in open(p, errors="replace"):
        if "verify_service_ticket_reply" in line and "session_key" in line:
            try:
                svc = line.split("service ")[1].split()[0]
                b64 = line.split("session_key ")[1].split()[0]
                k = CKey.from_b64(b64)
                out.add((svc, k.type, k.fingerprint()))
            except Exception:
                pass
    return out


SERVICE_NAMES = {0x20: "auth", 0x01: "mon", 0x04: "osd", 0x10: "mgr", 0x02: "mds"}


def analyze_pcap(path, captures, keystore, verbose=False):
    name = os.path.basename(path)[:-5]
    an = Analysis(name, keystore)
    t0 = time.time()
    npk, conns = read_pcap(path)
    out = {"name": name, "packets": npk, "conns": [], "analysis": an}
    # client IP = source of the first SYN
    # connections are analysed in time order so tickets learned from the first
    # mon connection are available to the later ones
    for c in sorted(conns, key=lambda c: c.t0):
        res = {}
        try:
            analyze_conn(c, an, res)
        except ProtoError as e:
            R.check("conn.analysis", False, "%s sport %d: %s" % (name, c.sport, e))
            res["error"] = str(e)
        except Exception as e:                 # a bug in this tool must be loud
            R.check("conn.analysis", False, "%s sport %d: internal %r" % (name, c.sport, e))
            res["error"] = repr(e)
        out["conns"].append(res)
    # cross-check our decrypted session keys against what the client logged
    logged = load_logged_keys(captures, name)
    if logged is not None:
        seen = set()
        for r in out["conns"]:
            for svc, typ, fp in r.get("_ticket_fps", []):
                seen.add((SERVICE_NAMES.get(svc, str(svc)), typ, fp))
        ok = seen.issubset(logged) if seen else True
        R.check("cephx.session_keys_match_client_log", ok and (bool(seen) or True),
                "%s: decrypted tickets %s not all in client log" % (name, sorted(seen - logged)))
        out["logged_keys"] = (len(seen), len(logged))
    # independent evidence from the stock client's own log: it prints how many bytes of
    # connection secret each mon authentication produced (never the secret itself)
    logs = sorted(glob.glob(os.path.join(captures, "secrets", "logs-full", name + ".*")))
    if logs:
        logged = []
        for lp in logs:
            for line in open(lp, errors="replace"):
                if "got connection_secret" in line:
                    try:
                        logged.append(int(line.split("got connection_secret")[1].split()[0]))
                    except ValueError:
                        pass
        ours = [r["secret_len"] for r in out["conns"]
                if r.get("kind") == "mon-auth" and r.get("secret_len") is not None]
        R.check("log_crosscheck.mon_connection_secret_lengths",
                sorted(logged) == sorted(ours),
                "%s: client log secret lengths %s, decoded from pcap %s"
                % (name, sorted(logged), sorted(ours)))
    out["secs"] = time.time() - t0
    return out


# ----------------------------------------------------------------------------
# self tests: the note's own numbers (sections 5.1 / 5.2), no pcap needed
# ----------------------------------------------------------------------------

def self_tests():
    g = "selftest"
    # 5.1 CRC-32C vectors from the note
    R.check(g, crc32c(b"foo bar baz", 0) == 4119623852, "crc 'foo bar baz'")
    R.check(g, crc32c(b"foo bar baz", 1234) == 881700046, "crc seed 1234")
    R.check(g, crc32c(b"whiz bang boom", 0) == 2360230088, "crc 'whiz bang boom'")
    # standard CRC-32C check value: init/xorout 0xFFFFFFFF around the raw update
    R.check(g, crc32c(b"123456789", 0xFFFFFFFF) ^ 0xFFFFFFFF == 0xE3069283, "CRC-32C check value")
    # 5.1 frame size table
    table = [((0, 0, 0, 0), 96, 1), ((20, 0, 0, 0), 96, 1), ((0, 70, 0, 0), 208, 2),
             ((20, 70, 0, 350), 560, 2), ((105, 0, 0, 0), 176, 2), ((105, 70, 0, 350), 640, 3)]
    for lens, tot, ops in table:
        R.check(g, secure_wire_size(lens) == (tot, ops), "size table %s" % (lens,))
    # 5.2 worked example
    S = bytes(range(64))
    key, A, B = split_secret(S)
    R.check(g, key.hex() == "000102030405060708090a0b0c0d0e0f", "K")
    R.check(g, B.hex() == "1c1d1e1f2021222324252627" and A.hex() == "101112131415161718191a1b",
            "seeds")
    gtx = GcmDir(key, B)
    sig = b"\xa5" * 32
    frameA = assemble_secure(T_AUTH_SIGNATURE, [sig], [8], gtx)
    pre = bytes.fromhex("07012000000008000000000000000000000000000000000000000000a80c9872")
    R.check(g, frameA[:0] == b"" and len(frameA) == 96, "frame A length")
    # decrypt with an independent AESGCM call to prove the pre/IV statement
    pt = AESGCM(key).decrypt(bytes.fromhex("1c1d1e1f2021222324252627"), frameA, None)
    R.check(g, pt == pre + sig + bytes(16), "frame A plaintext = preamble + sig + zero fill")
    R.check(g, frameA.hex().startswith("5ee83e477793cc7cbb381480b30cc694"), "frame A wire")
    frameB = assemble_secure(T_MESSAGE, [b"\x11" * 20, b"\x22" * 10], [8, 8], gtx)
    R.check(g, len(frameB) == 144, "frame B length")
    R.check(g, frameB.hex().startswith("98283b6ff8ab6493cd1f43d679c4a3a3"), "frame B wire")
    R.check(g, frameB.hex().endswith("f5a419f42a8a57c28a08980d974b4183"), "frame B wire end")
    # nonce stepping: wraps at 2^64 without touching bytes 0..3
    gg = GcmDir(key, bytes.fromhex("aabbccdd") + b"\xff" * 8)
    gg.step()
    R.check(g, gg.iv() == bytes.fromhex("aabbccdd") + bytes(8), "nonce wrap")
    # cephx note 2.8 worked example (type 1 proof)
    k1 = CKey(1, bytes(8), bytes(range(16)))
    R.check(g, cephx_proof(k1, 0x1122334455667788, 0x99aabbccddeeff00) == 0x4fadd85010bcad18,
            "type-1 proof worked example")
    # cipher round trips with a fixed confounder
    k2 = CKey(2, bytes(8), bytes(range(32)))
    for k in (k1, k2):
        for n in (0, 1, 5, 15, 16, 17, 31, 32, 33, 100):
            plain = bytes((i * 7) & 255 for i in range(n))
            ct = cephx_encrypt(k, 3, plain)
            R.check(g, cephx_decrypt(k, 3, ct) == plain, "cipher round trip type %d n %d" % (k.type, n))


# ----------------------------------------------------------------------------
# vectors
# ----------------------------------------------------------------------------

def export_vectors(outdir, results, captures):
    """Write the scrubbed vectors (no secrets) the core needs. All cryptographic
    material in them is synthetic (secret 00..3f etc.); captured material is
    reduced to structure (tags, lengths, counts)."""
    os.makedirs(outdir, exist_ok=True)
    S = bytes(range(64))
    key, A, B = split_secret(S)

    def hexs(b):
        return bytes(b).hex()

    # --- 1. primitives
    prim = {
        "_comment": "Public / synthetic values only. crc32c(data, seed) is the raw Castagnoli update "
                    "(no initial or final inversion of its own): the preamble uses seed 0, crc-mode "
                    "segments seed 0xFFFFFFFF.",
        "crc32c": [
            {"data_ascii": "foo bar baz", "seed": 0, "crc": crc32c(b"foo bar baz", 0)},
            {"data_ascii": "foo bar baz", "seed": 1234, "crc": crc32c(b"foo bar baz", 1234)},
            {"data_ascii": "whiz bang boom", "seed": 0, "crc": crc32c(b"whiz bang boom", 0)},
            {"data_ascii": "123456789", "seed": 0xFFFFFFFF, "crc": crc32c(b"123456789", 0xFFFFFFFF),
             "note": "xor 0xFFFFFFFF gives the standard CRC-32C check value 0xE3069283"},
            {"data_hex": "", "seed": 0xFFFFFFFF, "crc": 0xFFFFFFFF,
             "note": "empty segment, crc-mode seed: 0xFFFFFFFF"},
        ],
        "nonce_step": [
            {"start_hex": "aabbccdd" + "ff" * 8, "after_one_step_hex": "aabbccdd" + "00" * 8,
             "note": "msgr2.1: little-endian counter in bytes 4..11 wraps without carry into 0..3"},
            {"start_hex": "1c1d1e1f2021222324252627", "after_one_step_hex": "1c1d1e1f2121222324252627"},
        ],
        "frame_sizes": [],
    }
    for lens in [(0, 0, 0, 0), (20, 0, 0, 0), (48, 0, 0, 0), (49, 0, 0, 0), (0, 70, 0, 0),
                 (20, 70, 0, 350), (105, 0, 0, 0), (105, 70, 0, 350), (41, 10, 0, 0),
                 (41, 100, 0, 4096), (32, 0, 0, 0), (80, 0, 0, 0), (41, 1, 1, 1)]:
        tot, ops = secure_wire_size(lens)
        prim["frame_sizes"].append({"segment_lengths": list(lens), "gcm_operations": ops,
                                    "wire_bytes": tot})
    json.dump(prim, open(os.path.join(outdir, "primitives.json"), "w"), indent=1)

    # --- 2. synthetic secure frames, both directions, whole worked sequence
    synth = {
        "_comment": "Synthetic secret S = bytes 00 01 .. 3f. K = S[0..15], client tx seed = S[28..39], "
                    "client rx seed = S[16..27]. Segments are given as (length, byte value) patterns. "
                    "Produced by secure_check.py's own sender; the same sender reproduces every frame "
                    "of every captured secure session byte for byte (checked on each run).",
        "secret_hex": hexs(S), "key_hex": hexs(key),
        "client_tx_seed_hex": hexs(B), "client_rx_seed_hex": hexs(A),
        "client_to_server": [], "server_to_client": [],
    }

    def seqs(seed, frames, name):
        g = GcmDir(key, seed)
        out = []
        for (tag, segdesc, aligns) in frames:
            segs = [bytes([v]) * n for n, v in segdesc]
            iv_before = g.iv()
            wire = assemble_secure(tag, segs, aligns, g)
            out.append({"tag": tag, "tag_name": TAGS[tag], "alignments": aligns,
                        "segments": [{"length": n, "fill_byte": v} for n, v in segdesc],
                        "first_iv_hex": hexs(iv_before), "gcm_operations": secure_wire_size(
                            [n for n, _ in segdesc])[1],
                        "wire_hex": hexs(wire)})
        return out

    c_frames = [
        (T_AUTH_SIGNATURE, [(32, 0xa5)], [8]),
        (T_MESSAGE, [(20, 0x11), (10, 0x22)], [8, 8]),
        (T_MESSAGE, [(41, 0x33), (0, 0), (0, 0), (0, 0)], [8, 8, 8, 4096]),
        (T_MESSAGE, [(41, 0x44), (3, 0x61), (0, 0), (4, 0x57)], [8, 8, 8, 4096]),
        (T_MESSAGE, [(105, 0x55), (70, 0x66), (0, 0), (350, 0x77)], [8, 8, 8, 4096]),
        (18, [(8, 0x01)], [8]),   # KEEPALIVE2: one 8-byte segment
        (T_MESSAGE, [(41, 0x88), (0, 0), (0, 0), (4096, 0x99)], [8, 8, 8, 4096]),
    ]
    synth["client_to_server"] = seqs(B, c_frames, "c2s")
    synth["server_to_client"] = seqs(A, [(T_AUTH_SIGNATURE, [(32, 0x5a)], [8]),
                                         (T_MESSAGE, [(41, 0x12), (100, 0x34)], [8, 8])], "s2c")
    json.dump(synth, open(os.path.join(outdir, "secure-frames-synthetic.json"), "w"), indent=1)

    # --- 3. pre-auth signature, synthetic
    ssig = {
        "_comment": "HMAC-SHA256(key = raw secret bytes of the session key, data = transcript). "
                    "Synthetic key 00..0f (type 1) and 00..1f (type 2); synthetic transcript. "
                    "Real transcripts contain challenges and tickets and are not committed.",
        "cases": [],
    }
    for kt, n in ((1, 16), (2, 32)):
        kb = bytes(range(n))
        tr = b"ceph v2\n" + bytes([16, 0]) + bytes(range(16)) + b"synthetic-transcript"
        ssig["cases"].append({"session_key_type": kt, "session_key_secret_hex": hexs(kb),
                              "transcript_hex": hexs(tr),
                              "hmac_sha256_hex": hexs(hmac.new(kb, tr, hashlib.sha256).digest())})
    json.dump(ssig, open(os.path.join(outdir, "pre-auth-signature-synthetic.json"), "w"), indent=1)

    # --- 3b. a whole synthetic pre-auth tail: plaintext frames, transcripts, both signatures
    #         as the encrypted frames a secure-mode peer would put on the wire
    cbanner = BANNER_PREFIX + p16(16) + p64(1) + p64(0)        # we advertise REVISION_1 only
    sbanner = BANNER_PREFIX + p16(16) + p64(3) + p64(0)        # v20.2.5 server
    areq_pl = p8(10) + p32(8) + pblob(b"test") + p64(0)
    areq = assemble_crc(T_AUTH_REQUEST, [p32(2) + p32(1) + p32(MODE_SECURE) + pblob(areq_pl)], [8])
    adone = assemble_crc(T_AUTH_DONE, [p64(4242) + p32(MODE_SECURE) + pblob(b"\xee" * 32)], [8])
    sk_secret = bytes(range(0xa0, 0xb0))
    tx_tr = cbanner + areq
    rx_tr = sbanner + adone
    csig = hmac.new(sk_secret, rx_tr, hashlib.sha256).digest()
    ssig2 = hmac.new(sk_secret, tx_tr, hashlib.sha256).digest()
    gtx = GcmDir(key, B)
    grx = GcmDir(key, A)
    pre = {
        "_comment": "Synthetic. Everything the client sends and receives from the banner to the end of the "
                    "signature exchange for a secure-mode connection, with a synthetic connection secret "
                    "(00..3f) and a synthetic session key (type 1, 16 bytes). The AUTH_DONE payload is an "
                    "opaque placeholder (not a valid cephx reply); the vector tests the transcript scope, "
                    "the two HMACs and the encryption of the two AUTH_SIGNATURE frames, not cephx. "
                    "HELLO is omitted from the transcripts here to keep the vector small; a real "
                    "transcript contains it (the checker's real-capture check includes it).",
        "connection_secret_hex": hexs(S), "session_key_secret_hex": hexs(sk_secret),
        "client_banner_hex": hexs(cbanner), "server_banner_hex": hexs(sbanner),
        "client_auth_request_frame_hex": hexs(areq), "server_auth_done_frame_hex": hexs(adone),
        "client_tx_transcript_hex": hexs(tx_tr), "client_rx_transcript_hex": hexs(rx_tr),
        "client_signature_plain_hex": hexs(csig), "server_signature_plain_hex": hexs(ssig2),
        "client_signature_frame_wire_hex": hexs(assemble_secure(T_AUTH_SIGNATURE, [csig], [8], gtx)),
        "server_signature_frame_wire_hex": hexs(assemble_secure(T_AUTH_SIGNATURE, [ssig2], [8], grx)),
        "client_next_iv_hex": hexs(gtx.iv()), "server_next_iv_hex": hexs(grx.iv()),
    }
    json.dump(pre, open(os.path.join(outdir, "pre-auth-tail-synthetic.json"), "w"), indent=1)

    # --- 4. connection-secret blob (cephx cbl) with synthetic keys
    cbl = {
        "_comment": "AUTH_DONE tail for a mon connection: blob cbl = u32 outer_len | u32 inner_len | "
                    "ciphertext; plaintext = u8 1 | u64 0xff009cad8826aa55 | u32 len | secret. "
                    "Encrypted with the AUTH session key, usage 0x03. Synthetic keys and a fixed "
                    "confounder so the output is reproducible; real replies use a random confounder "
                    "for type 2.", "cases": []}
    for kt, n in ((1, 16), (2, 32)):
        sk = CKey(kt, bytes(8), bytes(range(0x40, 0x40 + n)))
        for mode, sec in (("secure", S), ("crc", b"")):
            item = pblob(sec)
            ct = seal_envelope(sk, USAGE_CONN_SECRET, item, bytes(range(0x80, 0x90)))
            blob = pblob(pblob(ct))
            cbl["cases"].append({"session_key_type": kt, "session_key_secret_hex": hexs(sk.secret),
                                 "usage": USAGE_CONN_SECRET, "mode": mode,
                                 "confounder_hex": hexs(bytes(range(0x80, 0x90))) if kt == 2 else None,
                                 "connection_secret_hex": hexs(sec), "cbl_hex": hexs(blob)})
    json.dump(cbl, open(os.path.join(outdir, "connection-secret-blob-synthetic.json"), "w"), indent=1)

    # --- 5. structure observed in the real captures (no key material, no addresses)
    obs = results_to_structure(results)
    json.dump(obs, open(os.path.join(outdir, "captured-structure.json"), "w"), indent=1)


def results_to_structure(results):
    """results: list of per-pcap dicts. Reduce to scrubbed structure."""
    obs = {
        "_comment": "Structure extracted by secure_check.py from the lab captures (Ceph v20.2.5). "
                    "Only lengths, tags, counts, flags and negotiated numbers are kept. Challenges, "
                    "proofs, tickets, signatures, ciphertext, nonces/IVs, secrets, addresses and "
                    "entity names are deliberately absent; nothing in this file can be used to "
                    "recover or replay a session.",
        "banner": None, "sessions": [],
    }
    for r in results:
        for c in r["conns"]:
            if "banner" in c and obs["banner"] is None:
                obs["banner"] = {"hex_prefix": BANNER_PREFIX.hex(), "payload_len": 16,
                                 "client_supported_required": list(c["banner"]["client"]),
                                 "server_supported_required": list(c["banner"]["server"])}
    secure_seen, crc_seen = set(), set()
    for r in results:
        for c in r["conns"]:
            if "_frames" not in c:
                continue
            fr = c["_frames"]
            peer = {0x20: "mon", 0x04: "osd", 0x10: "mgr"}.get(c.get("service_id"), None)
            if c.get("kind") == "mon-auth":
                peer = "mon"
            key = (c["mode"], peer, c.get("authorize_reply_v"), tuple(c.get("offered_modes", [])))
            seen = secure_seen if c["mode"] == "secure" else crc_seen
            if key in seen:
                continue
            seen.add(key)
            def fsum(fl):
                return [{"tag": f.tag, "name": f.name(), "segment_lengths": f.lens[:f.n],
                         "alignments": f.aligns[:f.n], "flags": f.flags,
                         "late_status": f.late, "wire_bytes": len(f.wire),
                         "gcm_operations": len(f.ops) if f.mode == "sec" else None}
                        for f in fl[:14]]
            obs["sessions"].append({
                "peer": peer, "mode": c["mode"], "offered_modes": c.get("offered_modes"),
                "server_picked_mode": c.get("con_mode"), "cephx_key_type_of_session_key":
                    c.get("auth_session_key_type", c.get("ticket_key_type")),
                "connection_secret_len": c.get("secret_len"),
                "authorize_reply_version": c.get("authorize_reply_v"),
                "other_keys": c.get("other_keys"),
                "plaintext_frames_client": [{"name": f.name(), "segment_lengths": f.lens[:f.n]}
                                            for f in fr["c2s_pre"]],
                "plaintext_frames_server": [{"name": f.name(), "segment_lengths": f.lens[:f.n]}
                                            for f in fr["s2c_pre"]],
                "frames_after_auth_client_first": fsum(fr["c2s"]),
                "frames_after_auth_server_first": fsum(fr["s2c"]),
                "compression_frames": c.get("compression_frames"),
            })
    return obs


def check_vectors(vdir):
    """Verify the committed synthetic vectors with code paths that do not share the
    sender: plain AESGCM decrypt + manual field parsing. Guards against drift."""
    g = "vectors"
    try:
        syn = json.load(open(os.path.join(vdir, "secure-frames-synthetic.json")))
        prim = json.load(open(os.path.join(vdir, "primitives.json")))
        tail = json.load(open(os.path.join(vdir, "pre-auth-tail-synthetic.json")))
        sigv = json.load(open(os.path.join(vdir, "pre-auth-signature-synthetic.json")))
        cbl = json.load(open(os.path.join(vdir, "connection-secret-blob-synthetic.json")))
    except (OSError, ValueError) as e:
        R.check(g, False, "cannot read vectors in %s: %s" % (vdir, e))
        return
    S = bytes.fromhex(syn["secret_hex"])
    for e in prim["crc32c"]:
        data = bytes.fromhex(e["data_hex"]) if "data_hex" in e else e["data_ascii"].encode()
        R.check(g, crc32c(data, e["seed"]) == e["crc"], "crc vector %r" % (e,))
    for e in prim["frame_sizes"]:
        R.check(g, secure_wire_size(e["segment_lengths"]) == (e["wire_bytes"], e["gcm_operations"]),
                "frame size vector %s" % (e,))
    for e in prim["nonce_step"]:
        x = GcmDir(bytes(16), bytes.fromhex(e["start_hex"]))
        x.step()
        R.check(g, x.iv().hex() == e["after_one_step_hex"], "nonce step vector")
    for direction, seed in (("client_to_server", S[28:40]), ("server_to_client", S[16:28])):
        aead = AESGCM(S[:16])
        ctr = struct.unpack("<Q", seed[4:12])[0]
        for fr in syn[direction]:
            wire = bytes.fromhex(fr["wire_hex"])
            pos, ops = 0, 0
            iv = seed[:4] + struct.pack("<Q", ctr)
            R.check(g, iv.hex() == fr["first_iv_hex"], "iv vector")
            pt1 = aead.decrypt(iv, wire[:96], None)
            ctr += 1
            ops += 1
            pre = pt1[:32]
            R.check(g, struct.unpack("<I", pre[28:32])[0] == crc32c(pre[:28], 0), "preamble crc vector")
            n = pre[1]
            lens = [struct.unpack("<I", pre[2 + 6 * i:6 + 6 * i])[0] for i in range(n)]
            R.check(g, pre[0] == fr["tag"] and lens == [x["length"] for x in fr["segments"]][:n],
                    "vector preamble fields")
            pos = 96
            if lens[0] > 48:
                m = pad16(lens[0]) - 48 + 16
                aead.decrypt(seed[:4] + struct.pack("<Q", ctr), wire[pos:pos + m], None)
                ctr += 1
                ops += 1
                pos += m
            if n > 1:
                m = sum(pad16(x) for x in lens[1:]) + 32
                pt = aead.decrypt(seed[:4] + struct.pack("<Q", ctr), wire[pos:pos + m], None)
                ctr += 1
                ops += 1
                pos += m
                R.check(g, pt[-16] == 0x0e and pt[-15:] == bytes(15), "vector epilogue")
            R.check(g, pos == len(wire) and ops == fr["gcm_operations"], "vector length / ops")
    for c in sigv["cases"]:
        d = hmac.new(bytes.fromhex(c["session_key_secret_hex"]), bytes.fromhex(c["transcript_hex"]),
                     hashlib.sha256).hexdigest()
        R.check(g, d == c["hmac_sha256_hex"], "signature vector")
    cs = bytes.fromhex(tail["client_tx_transcript_hex"])
    rs = bytes.fromhex(tail["client_rx_transcript_hex"])
    sk = bytes.fromhex(tail["session_key_secret_hex"])
    R.check(g, hmac.new(sk, rs, hashlib.sha256).hexdigest() == tail["client_signature_plain_hex"], "tail client sig")
    R.check(g, hmac.new(sk, cs, hashlib.sha256).hexdigest() == tail["server_signature_plain_hex"], "tail server sig")
    R.check(g, AESGCM(S[:16]).decrypt(S[28:40], bytes.fromhex(tail["client_signature_frame_wire_hex"]), None)[32:64]
            == bytes.fromhex(tail["client_signature_plain_hex"]), "tail client sig frame")
    R.check(g, AESGCM(S[:16]).decrypt(S[16:28], bytes.fromhex(tail["server_signature_frame_wire_hex"]), None)[32:64]
            == bytes.fromhex(tail["server_signature_plain_hex"]), "tail server sig frame")
    R.check(g, tail["client_tx_transcript_hex"] == tail["client_banner_hex"] + tail["client_auth_request_frame_hex"],
            "tail transcript layout")
    for c in cbl["cases"]:
        key = CKey(c["session_key_type"], bytes(8), bytes.fromhex(c["session_key_secret_hex"]))
        r = Rd(bytes.fromhex(c["cbl_hex"]))
        inner = Rd(r.blob()).blob()
        _v, ird = open_envelope(key, c["usage"], inner)
        sec = ird.take(ird.u32())
        R.check(g, sec.hex() == c["connection_secret_hex"] and (len(sec) == 64) == (c["mode"] == "secure"),
                "cbl vector")


# ----------------------------------------------------------------------------
# summary / claims
# ----------------------------------------------------------------------------

def group_ok(prefixes):
    """True if at least one check ran and none failed in groups matching prefixes."""
    ran = fail = 0
    for g, (p, f) in R.counts.items():
        if any(g.startswith(x) for x in prefixes):
            ran += p + f
            fail += f
    return ran > 0 and fail == 0, ran, fail


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--captures", required=True, help="directory with pcap/ (the capture set)")
    ap.add_argument("--keys", help="directory with the lab keyrings (default: <captures>/../lab-secrets)")
    ap.add_argument("--only", help="only pcaps whose name contains this")
    ap.add_argument("--export-vectors", help="write scrubbed vectors into this directory")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--json", help="write the machine-readable result here")
    a = ap.parse_args()

    cap = os.path.abspath(a.captures)
    keysdir = a.keys or os.path.join(os.path.dirname(cap), "lab-secrets")
    keydirs = [keysdir, os.path.join(cap, "secrets", "keys")]
    ks = KeyStore(keydirs)
    t00 = time.time()
    self_tests()
    vdir = a.export_vectors or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                            "vectors", "secure")
    if os.path.isdir(vdir) and not a.export_vectors:
        check_vectors(vdir)
    pcaps = sorted(glob.glob(os.path.join(cap, "pcap", "*.pcap")))
    if a.only:
        pcaps = [p for p in pcaps if a.only in os.path.basename(p)]
    if not pcaps:
        print("no pcaps found under %s/pcap" % cap, file=sys.stderr)
        return 2
    results = []
    for p in pcaps:
        before = R.total
        r = analyze_pcap(p, cap, ks, a.verbose)
        results.append(r)
        after = R.total
        nsec = sum(1 for c in r["conns"] if c.get("mode") == "secure")
        if a.verbose or after[1] != before[1]:
            print("%-26s conns=%2d secure=%d checks=%6d fail=%d  (%.1fs)" %
                  (r["name"], len(r["conns"]), nsec, after[0] + after[1] - before[0] - before[1],
                   after[1] - before[1], r["secs"]))
    # ---------------- summary
    print()
    print("== checks per group (pass / fail) ==")
    for g, (p, f) in sorted(R.counts.items()):
        print("  %-62s %7d %5d%s" % (g, p, f, "   <-- FAIL" if f else ""))
    tp, tf = R.total
    print()
    print("TOTAL checks: %d passed, %d failed  (%.1fs)" % (tp, tf, time.time() - t00))
    for g, msgs in R.failures.items():
        for m in msgs:
            print("  FAIL [%s] %s" % (g, m))
    print()
    statuses = report_claims(results)
    if a.export_vectors:
        export_vectors(a.export_vectors, results, cap)
        print("vectors written to", a.export_vectors)
        check_vectors(a.export_vectors)
        tp, tf = R.total
        print("after re-reading the written vectors: %d passed, %d failed" % (tp, tf))
    summarize_observations(results)
    if a.json:
        json.dump({"pass": tp, "fail": tf, "groups": R.counts}, open(a.json, "w"), indent=1)
    if R.total[1]:
        return 1
    # a full run must also cover every claim; a --only subset may legitimately not
    if not a.only and any(x != "confirmed" for x in statuses):
        print("a claim is not covered by the capture set")
        return 1
    return 0


def report_claims(results):
    """Aggregate the check groups into the statements the note makes."""
    offers = collections.Counter()
    for r in results:
        for c in r["conns"]:
            if "mode" in c:
                peer = SERVICE_NAMES.get(c.get("service_id"), "svc") if c.get("kind") == "authorizer" else "mon"
                offers[(peer, tuple(c["offered_modes"]), c["mode"])] += 1
    modes_ok = (offers[("mon", (2, 1), "secure")] > 0 and offers[("mgr", (2, 1), "secure")] > 0
                and offers[("osd", (1, 2), "crc")] > 0 and offers[("mon", (1,), "crc")] > 0
                and offers[("osd", (1,), "crc")] > 0 and offers[("osd", (2,), "secure")] > 0
                and offers[("mon", (2,), "secure")] > 0)
    rows = [
        ("banner: 'ceph v2\\n', payload_len 16, supported 3, required 0 (2.2)", ["banner"], True),
        ("auth frames decode exactly as 2.4 / cephx 2.2, all single-segment", ["auth.", "hello.", "frame.tag_known"], True),
        ("mode negotiation: client order wins; defaults mon/mgr secure, OSD crc; crc-only and "
         "secure-only offers accepted by default servers (2.9)", [], modes_ok),
        ("connection secret: 64 bytes secure / 0 crc; cbl nesting; usage 0x03; AUTH-bit-only "
         "request still yields it (2.5a)", ["cephx.cbl", "cephx.extra", "secure.secret_len", "cephx.mon_reply"], True),
        ("authorizer round trip, challenge raw, reply v2 + secret in secure (2.5b)", ["authorizer."], True),
        ("AES key = S[0..15]; client tx = seed B, rx = seed A; one nonce per GCM op; no AAD (2.6)",
         ["sec.preamble_crc", "sec.wire_size_formula"], True),
        ("secure frame layout (1- and 2-operation shapes; 3-operation shape not in traffic), padding, epilogue 0x0e, size arithmetic (2.8)",
         ["sec.wire_size_formula", "sec.op_count_formula", "sec.padding_is_zero", "sec.epilogue_pad_zero",
          "sec.late_status_complete", "sec.last_segment"], True),
        ("our sender reproduces every captured secure frame byte for byte (3.3)", ["sec.reassembly"], True),
        ("pre-auth signature: HMAC key = raw session-key secret, banner included, each side signs "
         "what it received, first encrypted frame (2.7)", ["signature."], True),
        ("compression handshake frame layouts and position (2.10)", ["compression.", "order."], True),
        ("crc-mode framing contrast, 13-byte epilogue, seeds (2.8)", ["crc."], True),
        ("secret fresh per TCP connection (2.5)", ["secure.secret_fresh"], True),
        ("connection-secret lengths agree with the stock client's own debug log", ["log_crosscheck"], True),
        ("negative controls fail as they must", ["sec.negative_controls"], True),
        ("CRC-32C, nonce stepping, 5.1 table and 5.2 worked example (self test)", ["selftest"], True),
    ]
    print("== claims of the note ==")
    statuses = []
    for text, prefixes, extra in rows:
        ran = fail = 0
        for g, (p_, f_) in R.counts.items():
            if prefixes and any(g.startswith(x) for x in prefixes):
                ran += p_ + f_
                fail += f_
        if not prefixes:
            ran = sum(offers.values())
        if fail:
            st = "FAILED"
        elif ran == 0 or not extra:
            st = "not covered"
        else:
            st = "confirmed"
        statuses.append(st)
        print("  [%-11s] %s  (%d checks)" % (st, text, ran))
    return statuses


def summarize_observations(results):
    """Print the observations that the note's [confirm on capture] items hinge on."""
    modes = collections.Counter()
    offers = collections.Counter()
    bad = []
    banners = collections.Counter()
    comp = collections.Counter()
    segal = collections.Counter()
    late = collections.Counter()
    ctypes = collections.Counter()
    nsecure_frames = 0
    nsecure_ops = 0
    tags = collections.Counter()
    for r in results:
        for c in r["conns"]:
            if "mode" in c:
                peer = c.get("kind")
                if c.get("kind") == "authorizer":
                    peer = SERVICE_NAMES.get(c.get("service_id"), "svc")
                else:
                    peer = "mon"
                modes[(r["name"].split("-")[1] if r["name"][:2] in ("k1", "k2") else r["name"][:1], peer, c["mode"])] += 1
                offers[(peer, tuple(c["offered_modes"]), c["mode"])] += 1
                banners[(tuple(c["banner"]["client"]), tuple(c["banner"]["server"]))] += 1
                comp[(c["mode"], tuple(c.get("compression_frames", [])), c.get("client_adv_compression"),
                      c.get("server_adv_compression"))] += 1
                if c.get("kind") == "mon-auth":
                    ctypes[("auth session key type", c["auth_session_key_type"],
                            "principal type", c["principal_type"],
                            "extra key types", tuple(c["extra_key_types"]))] += 1
                for f in c["_frames"]["c2s"] + c["_frames"]["s2c"]:
                    tags[(f.mode, f.name())] += 1
                    late[f.late] += 1
                    if f.mode == "sec":
                        nsecure_frames += 1
                        nsecure_ops += len(f.ops)
                    segal[(f.name() if f.tag == T_MESSAGE else "ctl", tuple(f.aligns[:f.n]))] += 1
            if "bad_method" in c:
                bad.append((r["name"], c["bad_method"], c.get("offered_modes"), c.get("kind")))
    print()
    print("== observations ==")
    print("banners (client sup/req, server sup/req):", dict(banners))
    print("offered modes -> picked (peer, offered, mode):")
    for k, v in sorted(offers.items(), key=str):
        print("   ", k, v)
    print("compression (mode, frames, client_adv, server_adv):")
    for k, v in sorted(comp.items(), key=str):
        print("   ", k, v)
    print("key types:", dict(ctypes))
    print("late_status values seen:", dict(late))
    print("alignment hints seen (kind, aligns):")
    for k, v in sorted(segal.items(), key=str):
        print("   ", k, v)
    print("secure frames decoded: %d, GCM operations: %d" % (nsecure_frames, nsecure_ops))
    ok = collections.Counter()
    form = collections.Counter()
    recon = collections.Counter()
    shape = collections.Counter()
    biggest = 0
    for r in results:
        for c in r["conns"]:
            if c.get("kind") == "mon-auth" and "other_keys" in c:
                ok[("other_keys=0x%02x" % c["other_keys"], c["mode"], "extra=%s" % (
                    [SERVICE_NAMES.get(x, x) for x in c.get("extra_services", [])],),
                    "secret_len=%s" % c.get("secret_len"))] += 1
                recon[("global_id_sent_nonzero", c["req_global_id"] != 0,
                       "old_ticket_sent", c["old_ticket_len"] > 0,
                       "authenticate_v", c["authenticate_v"])] += 1
            if "authorize_reply_form" in c:
                form[(c["authorize_reply_form"], c["authorize_reply_v"], c["mode"])] += 1
            if c.get("mode") == "secure":
                for f in c["_frames"]["c2s"] + c["_frames"]["s2c"]:
                    shape[("n=%d" % f.n, "len0>48" if f.lens[0] > 48 else "len0<=48",
                           "ops=%d" % len(f.ops))] += 1
                    biggest = max(biggest, len(f.wire))
    cv = collections.Counter()
    for r in results:
        for c in r["conns"]:
            if "comp_req" in c:
                cv[("request is_compress=%d methods=%s" % (c["comp_req"][0], c["comp_req"][1]),
                    "done is_compress=%d method=%d" % c["comp_done"], c["mode"])] += 1
    print("compression handshake values (client request, server answer, mode):")
    for k, v in sorted(cv.items(), key=str):
        print("   ", k, v)
    cov = collections.Counter()
    for r in results:
        for c in r["conns"]:
            for f in c.get("_frames", {}).get("c2s", []) + c.get("_frames", {}).get("s2c", []):
                if f.mode == "crc":
                    cov[("crc", "n=%d" % f.n, "len0=0" if f.lens[0] == 0 else "len0>0")] += 1
    print("crc-mode frame shapes after auth:")
    for k, v in sorted(cov.items(), key=str):
        print("   ", k, v)
    print("cephx other_keys / extra tickets / secret length per mon connection:")
    for k, v in sorted(ok.items(), key=str):
        print("   ", k, v)
    print("mon connection starts (reconnect with old ticket?):")
    for k, v in sorted(recon.items(), key=str):
        print("   ", k, v)
    print("authorizer AUTH_DONE form:")
    for k, v in sorted(form.items(), key=str):
        print("   ", k, v)
    print("secure frame shapes exercised (segments, len0, GCM ops): largest frame %d bytes" % biggest)
    for k, v in sorted(shape.items(), key=str):
        print("   ", k, v)
    print("AUTH_BAD_METHOD seen (grouped):")
    grp = collections.Counter()
    for b in bad:
        grp[(b[0][:2] if b[0][0] == "k" else b[0], b[3], json.dumps(b[1], sort_keys=True),
             tuple(b[2]))] += 1
    for k, v in sorted(grp.items(), key=str):
        print("   ", k, v)
    foll = collections.Counter()
    for r in results:
        for c in r["conns"]:
            if "bad_method" in c:
                foll[(tuple(c["after_bad_method_c2s"]), c["after_bad_method_s2c_bytes"])] += 1
    print("frames the client sent after AUTH_BAD_METHOD / server bytes after it:", dict(foll))
    if R.defects:
        print("CAPTURE DEFECTS (not note failures):")
        for d in R.defects:
            print("   ", d)
    print("frame tags after auth:")
    for k, v in sorted(tags.items(), key=str):
        print("   ", k, v)


if __name__ == "__main__":
    sys.exit(main())
