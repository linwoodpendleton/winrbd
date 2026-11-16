#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent checker for docs/spec/cephx.md (and the msgr2 framing it rests on).

Written from the spec notes only (docs/spec/cephx.md, msgr2.md, msgr2-secure-mode.md),
not from Ceph source. Uses the standard library plus 'cryptography'.

Usage:
    python3 harness/tools/cephx_check.py                    (public vector set + committed vectors; nothing else needed)
    python3 harness/tools/cephx_check.py --captures <captures-dir> [--keys <dir>] [--jobs N]
    python3 harness/tools/cephx_check.py --vectors harness/vectors/cephx        (offline only)
    python3 harness/tools/cephx_check.py --emit-vectors harness/vectors/cephx   (regenerate synthetic vectors)

Exit status 0 only if every check passed. Key material is read at run time from the
keyring files and is never printed.
"""
import argparse
import base64
import glob
import hashlib
import hmac
import json
import os
import struct
import sys
from collections import Counter, defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pubset  # noqa: E402

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

# --------------------------------------------------------------------------------------
# constants taken from the notes (cephx.md 2.1, msgr2.md 2.4)
# --------------------------------------------------------------------------------------
MAGIC = 0xFF009CAD8826AA55
MAGIC_WIRE = bytes.fromhex("55aa2688ad9c00ff")      # cephx.md 2.1: magic as LE bytes
CBC_IV = bytes.fromhex("63657068736167657975646167726567")
TAGS = {1: "HELLO", 2: "AUTH_REQUEST", 3: "AUTH_BAD_METHOD", 4: "AUTH_REPLY_MORE",
        5: "AUTH_REQUEST_MORE", 6: "AUTH_DONE", 7: "AUTH_SIGNATURE", 8: "CLIENT_IDENT",
        9: "SERVER_IDENT", 10: "IDENT_MISSING_FEATURES", 11: "SESSION_RECONNECT",
        12: "SESSION_RESET", 13: "SESSION_RETRY", 14: "SESSION_RETRY_GLOBAL",
        15: "SESSION_RECONNECT_OK", 16: "WAIT", 17: "MESSAGE", 18: "KEEPALIVE2",
        19: "KEEPALIVE2_ACK", 20: "ACK", 21: "COMPRESSION_REQUEST", 22: "COMPRESSION_DONE"}
T_HELLO, T_AUTH_REQ, T_BAD, T_REPLY_MORE, T_REQ_MORE, T_DONE, T_SIG = 1, 2, 3, 4, 5, 6, 7
T_MESSAGE = 17
USAGE_CONN_SECRET, USAGE_TICKET_SESSION, USAGE_TICKET_BLOB = 0x03, 0x04, 0x05
USAGE_AUTHORIZE, USAGE_CHALLENGE, USAGE_REPLY = 0x10, 0x11, 0x12
ENT_MON, ENT_OSD, ENT_CLIENT, ENT_MGR, ENT_AUTH = 1, 4, 8, 0x10, 0x20


class CheckError(Exception):
    pass


# --------------------------------------------------------------------------------------
# result bookkeeping
# --------------------------------------------------------------------------------------
class Results:
    def __init__(self):
        self.counts = Counter()      # name -> [pass, fail] kept as two counters
        self.fails = Counter()
        self.failures = []           # (session, name, detail)
        self.notes = defaultdict(set)

    def ok(self, name, n=1):
        self.counts[name] += n

    def fail(self, name, where, detail):
        self.fails[name] += 1
        if len(self.failures) < 400:
            self.failures.append((where, name, detail))

    def expect(self, cond, name, where, detail=""):
        if cond:
            self.ok(name)
        else:
            self.fail(name, where, detail)
        return cond

    def note(self, name, text):
        self.notes[name].add(text)

    def merge(self, other):
        self.counts.update(other.counts)
        self.fails.update(other.fails)
        self.failures.extend(other.failures)
        for k, v in other.notes.items():
            self.notes[k] |= v


# --------------------------------------------------------------------------------------
# CRC-32C, raw update (msgr2.md 2.5): reflected poly 0x82F63B78, caller seed, no final xor
# --------------------------------------------------------------------------------------
def _crc_tables():
    t0 = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
        t0.append(c)
    tabs = [t0]
    for _ in range(7):
        prev = tabs[-1]
        tabs.append([(prev[i] >> 8) ^ t0[prev[i] & 255] for i in range(256)])
    return tabs


_T = _crc_tables()
_T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7 = _T


def crc32c(data, seed=0):
    """Raw CRC-32C update (slicing-by-8)."""
    crc = seed & 0xFFFFFFFF
    n = len(data)
    n8 = n & ~7
    if n8:
        t0, t1, t2, t3, t4, t5, t6, t7 = _T0, _T1, _T2, _T3, _T4, _T5, _T6, _T7
        for a, b in struct.iter_unpack("<II", memoryview(data)[:n8]):
            a ^= crc
            crc = (t7[a & 255] ^ t6[(a >> 8) & 255] ^ t5[(a >> 16) & 255] ^ t4[a >> 24] ^
                   t3[b & 255] ^ t2[(b >> 8) & 255] ^ t1[(b >> 16) & 255] ^ t0[b >> 24])
    for b in memoryview(data)[n8:]:
        crc = (crc >> 8) ^ _T0[(crc ^ b) & 255]
    return crc


# --------------------------------------------------------------------------------------
# primitive reader / writer (cephx.md 1.3)
# --------------------------------------------------------------------------------------
class Rd:
    def __init__(self, b, pos=0):
        self.b = bytes(b)
        self.p = pos

    def take(self, n):
        if n < 0 or self.p + n > len(self.b):
            raise CheckError("short read: need %d at %d of %d" % (n, self.p, len(self.b)))
        r = self.b[self.p:self.p + n]
        self.p += n
        return r

    def u8(self): return self.take(1)[0]
    def u16(self): return struct.unpack("<H", self.take(2))[0]
    def u32(self): return struct.unpack("<I", self.take(4))[0]
    def s32(self): return struct.unpack("<i", self.take(4))[0]
    def u64(self): return struct.unpack("<Q", self.take(8))[0]
    def blob(self): return self.take(self.u32())
    def string(self): return self.blob()
    def utime(self):
        s, ns = struct.unpack("<II", self.take(8))
        return s, ns
    def rest(self): return self.take(len(self.b) - self.p)
    def left(self): return len(self.b) - self.p
    def done(self): return self.p == len(self.b)


def p8(v): return struct.pack("<B", v)
def p16(v): return struct.pack("<H", v)
def p32(v): return struct.pack("<I", v)
def p64(v): return struct.pack("<Q", v)
def pblob(b): return p32(len(b)) + bytes(b)
def putime(s, ns): return struct.pack("<II", s, ns)


# --------------------------------------------------------------------------------------
# crypto: cephx.md 2.3 .. 2.6
# --------------------------------------------------------------------------------------
class Key:
    """CryptoKey: u16 type, utime created, u16 len, secret (cephx.md 2.3)."""

    def __init__(self, ktype, secret, created=(0, 0)):
        self.type = ktype
        self.secret = bytes(secret)
        self.created = created
        self.src = ""
        self._derived = {}
        if ktype == 1 and len(self.secret) < 16:
            raise CheckError("type 1 secret shorter than 16")
        if ktype == 2 and len(self.secret) < 32:
            raise CheckError("type 2 secret shorter than 32")
        if ktype not in (1, 2):
            raise CheckError("unsupported key type %d" % ktype)

    @classmethod
    def decode(cls, b):
        r = Rd(b)
        t = r.u16()
        created = r.utime()
        n = r.u16()
        sec = r.take(n)
        if not r.done():
            raise CheckError("trailing bytes after key")
        return cls(t, sec, created)

    @classmethod
    def from_base64(cls, s):
        return cls.decode(base64.b64decode(s))

    def encode(self):
        return p16(self.type) + putime(*self.created) + p16(len(self.secret)) + self.secret

    # ---- type 2 derivation (2.5) ----
    def _kd(self, usage, typebyte, nbytes):
        k = self._derived.get((usage, typebyte))
        if k is None:
            inp = b"\x00\x00\x00\x01" + struct.pack(">I", usage) + bytes([typebyte]) + b"\x00" + \
                struct.pack(">I", nbytes * 8)
            k = hmac.new(self.secret, inp, hashlib.sha384).digest()[:nbytes]
            self._derived[(usage, typebyte)] = k
        return k

    def ki(self, usage): return self._kd(usage, 0x55, 24)
    def ke(self, usage): return self._kd(usage, 0xAA, 32)

    # ---- raw encrypt/decrypt ----
    def encrypt(self, usage, plain, confounder=None):
        if self.type == 1:
            return _t1_encrypt(self.secret[:16], plain)
        return _t2_encrypt(self, usage, plain, confounder)

    def decrypt(self, usage, ct):
        if self.type == 1:
            return _t1_decrypt(self.secret[:16], ct)
        return _t2_decrypt(self, usage, ct)


def _cbc(key, iv, data, enc):
    c = Cipher(algorithms.AES(key), modes.CBC(iv))
    x = c.encryptor() if enc else c.decryptor()
    return x.update(data) + x.finalize()


def _ecb_dec(key, block):
    x = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return x.update(block) + x.finalize()


def _t1_encrypt(k16, plain):
    pad = 16 - (len(plain) % 16)          # always 1..16
    return _cbc(k16, CBC_IV, plain + bytes([pad]) * pad, True)


def _t1_decrypt(k16, ct):
    if not ct or len(ct) % 16:
        raise CheckError("type 1: ciphertext length not a non-zero multiple of 16")
    pt = _cbc(k16, CBC_IV, ct, False)
    pad = pt[-1]
    if pad == 0 or pad > 16:
        raise CheckError("type 1: bad pad byte")
    if pt[-pad:] != bytes([pad]) * pad:
        raise CheckError("type 1: bad padding bytes")
    return pt[:-pad]


def _cs3_encrypt(ke, m):
    n = len(m)
    if n < 16:
        raise CheckError("CS3 needs >= 16 bytes")
    if n == 16:
        return _cbc(ke, bytes(16), m, True)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    c = _cbc(ke, bytes(16), m + bytes(16 * k - n), True)
    blocks = [c[i * 16:(i + 1) * 16] for i in range(k)]
    return b"".join(blocks[:k - 2]) + blocks[k - 1] + blocks[k - 2][:r]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _cs3_decrypt(ke, ct):
    n = len(ct)
    if n < 16:
        raise CheckError("CS3 needs >= 16 bytes")
    if n == 16:
        return _cbc(ke, bytes(16), ct, False)
    k = (n + 15) // 16
    r = n - 16 * (k - 1)
    head = ct[:16 * (k - 2)]
    ck = ct[16 * (k - 2):16 * (k - 1)]
    part = ct[16 * (k - 1):]
    d = _ecb_dec(ke, ck)                      # = P_k (zero padded) xor C_{k-1}
    ck1 = part + d[r:]                        # zero padding => d[r:] == C_{k-1}[r:]
    prev = head[-16:] if k > 2 else bytes(16)
    pk1 = _xor(_ecb_dec(ke, ck1), prev)
    pk = _xor(d, ck1)[:r]
    ph = _cbc(ke, bytes(16), head, False) if head else b""
    return ph + pk1 + pk


def _t2_encrypt(key, usage, plain, confounder):
    if confounder is None:
        confounder = os.urandom(16)
    ct = _cs3_encrypt(key.ke(usage), confounder + plain)
    mac = hmac.new(key.ki(usage), bytes(16) + ct, hashlib.sha384).digest()[:24]
    return ct + mac


def _t2_decrypt(key, usage, data):
    if len(data) < 40:
        raise CheckError("type 2: ciphertext shorter than 40")
    ct, mac = data[:-24], data[-24:]
    exp = hmac.new(key.ki(usage), bytes(16) + ct, hashlib.sha384).digest()[:24]
    if not hmac.compare_digest(exp, mac):
        raise CheckError("type 2: MAC mismatch")
    return _cs3_decrypt(key.ke(usage), ct)[16:]


# ---- envelope (2.6) ----
def seal(key, usage, item, confounder=None):
    """encode_encrypt: u32 len || ct, plaintext = u8 1 || u64 magic || item."""
    return pblob(seal_raw(key, usage, item, confounder))


def seal_raw(key, usage, item, confounder=None):
    return key.encrypt(usage, p8(1) + p64(MAGIC) + item, confounder)


def open_raw(key, usage, ct):
    plain = key.decrypt(usage, ct)
    r = Rd(plain)
    r.u8()
    m = r.u64()
    if m != MAGIC:
        raise CheckError("envelope magic mismatch")
    return r.rest()


def open_prefixed(rd, key, usage):
    """Read u32 len + ct from reader rd, return item bytes."""
    return open_raw(key, usage, rd.blob())


# ---- challenge proof (2.8) ----
def challenge_proof(key, server_challenge, client_challenge):
    blob = p64(server_challenge) + p64(client_challenge)
    if key.type == 1:
        enc = seal(key, 0, blob)             # length-prefixed shape, deterministic for type 1
        assert len(enc) == 36
        x = 0
        for i in range(0, 32, 8):
            x ^= struct.unpack("<Q", enc[i:i + 8])[0]
        return x
    d = hmac.new(key.secret, blob, hashlib.sha256).digest()
    x = 0
    for i in range(0, 32, 8):
        x ^= struct.unpack("<Q", d[i:i + 8])[0]
    return x


def load_keyring(path):
    ent = None
    keys = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                ent = line[1:-1]
            elif line.startswith("key") and "=" in line and ent:
                keys[ent] = line.split("=", 1)[1].strip()
    return keys


# --------------------------------------------------------------------------------------
# pcap -> TCP streams
# --------------------------------------------------------------------------------------
def read_pcap_packets(path):
    """Yield (ts, ethernet-payload-bytes) from a classic pcap, linktype 1 (Ethernet) or 113 (SLL)."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        e = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        e = ">"
    else:
        raise CheckError("not a classic pcap: %s" % path)
    linktype = struct.unpack(e + "HHiIII", data[4:24])[5]
    pos = 24
    n = len(data)
    while pos + 16 <= n:
        ts_s, ts_us, incl, orig = struct.unpack(e + "IIII", data[pos:pos + 16])
        pos += 16
        yield (ts_s + ts_us / 1e6, linktype, data[pos:pos + incl], orig)
        pos += incl


def extract_tcp(path):
    """Return {flowkey: {dir: [(seq, flags, payload)]}} plus stats. Direction 'c' = from the
    lower-numbered... determined later; here keyed by (src, sport, dst, dport)."""
    flows = defaultdict(list)
    stats = Counter()
    for ts, lt, pkt, orig in read_pcap_packets(path):
        stats["packets"] += 1
        if orig != len(pkt):
            stats["truncated"] += 1
        if lt == 1:
            if len(pkt) < 14:
                continue
            et = struct.unpack(">H", pkt[12:14])[0]
            ip = pkt[14:]
            if et != 0x0800:
                stats["non_ipv4"] += 1
                continue
        elif lt == 113:
            et = struct.unpack(">H", pkt[14:16])[0]
            ip = pkt[16:]
            if et != 0x0800:
                continue
        else:
            raise CheckError("unsupported linktype %d" % lt)
        ihl = (ip[0] & 15) * 4
        if ip[9] != 6:
            stats["non_tcp"] += 1
            continue
        tot = struct.unpack(">H", ip[2:4])[0]
        src, dst = ip[12:16], ip[16:20]
        tcp = ip[ihl:tot]
        sport, dport, seq, ack = struct.unpack(">HHII", tcp[:12])
        doff = (tcp[12] >> 4) * 4
        flags = tcp[13]
        payload = tcp[doff:]
        flows[(src, sport, dst, dport)].append((ts, seq, flags, payload))
    return flows, stats


def reassemble(segs):
    """segs: [(ts, seq, flags, payload)] one direction.
    Returns (bytes, n_retrans, holes, mismatching_retrans, marks) where marks = [(stream_offset, ts)]."""
    isn = None
    for ts, seq, flags, pl in segs:
        if flags & 2:            # SYN
            isn = (seq + 1) & 0xFFFFFFFF
            break
    if isn is None:
        isn = min((seq for ts, seq, f, pl in segs if pl), default=0)
    out = bytearray()
    marks = []
    retrans = 0
    mismatch = 0
    pend = {}
    for ts, seq, flags, pl in segs:
        if not pl:
            continue
        rel = (seq - isn) & 0xFFFFFFFF
        if rel > 0x80000000:      # before ISN
            continue
        have = len(out)
        end = rel + len(pl)
        if end <= have:
            retrans += 1
            if bytes(out[rel:end]) != pl:
                mismatch += 1
            continue
        if rel > have:
            pend[rel] = (pl, ts)
            continue
        if rel < have:
            retrans += 1
            if bytes(out[rel:have]) != pl[:have - rel]:
                mismatch += 1
            pl = pl[have - rel:]
        marks.append((len(out), ts))
        out += pl
        while True:
            have = len(out)
            nxt = next((k for k in pend if k <= have), None)
            if nxt is None:
                break
            pp, pts = pend.pop(nxt)
            if nxt + len(pp) > have:
                marks.append((len(out), pts))
                out += pp[have - nxt:]
    return bytes(out), retrans, len(pend), mismatch, marks


def ts_at(marks, off):
    lo, hi = 0, len(marks) - 1
    r = marks[0][1] if marks else 0.0
    while lo <= hi:
        mid = (lo + hi) // 2
        if marks[mid][0] <= off:
            r = marks[mid][1]
            lo = mid + 1
        else:
            hi = mid - 1
    return r


def ip_s(b):
    return ".".join(str(x) for x in b)


# --------------------------------------------------------------------------------------
# msgr2 framing (msgr2.md 2.2, 2.3, 2.6.1; msgr2-secure-mode.md 2.8)
# --------------------------------------------------------------------------------------
class Frame:
    __slots__ = ("tag", "segs", "lens", "aligns", "start", "end", "secure", "flags", "nseg",
                 "late_status")

    def __init__(self):
        self.late_status = None


def parse_preamble(pre):
    """Return (tag, nseg, [(len, align)] x 4, flags, reserved) after verifying the CRC."""
    crc = struct.unpack("<I", pre[28:32])[0]
    if crc32c(pre[:28], 0) != crc:
        raise CheckError("preamble CRC mismatch")
    tag, nseg = pre[0], pre[1]
    sl = [struct.unpack("<IH", pre[2 + 6 * i:8 + 6 * i]) for i in range(4)]
    return tag, nseg, sl, pre[26], pre[27]


def check_preamble_rules(tag, nseg, sl, flags, rsv):
    if not 1 <= nseg <= 4:
        raise CheckError("bad segment count %d" % nseg)
    if nseg > 1 and sl[nseg - 1][0] == 0:
        raise CheckError("last segment empty with n>1")
    for i in range(nseg, 4):
        if sl[i] != (0, 0):
            raise CheckError("unused segment slot %d not zero" % i)
    if flags != 0 or rsv != 0:
        raise CheckError("preamble flags/reserved nonzero")


def parse_crc_frame(buf, pos, res=None, where=""):
    """Parse one msgr2.1 crc-mode frame at buf[pos:]. Returns Frame; raises CheckError."""
    if pos + 32 > len(buf):
        raise CheckError("truncated preamble")
    tag, nseg, sl, flags, rsv = parse_preamble(bytes(buf[pos:pos + 32]))
    check_preamble_rules(tag, nseg, sl, flags, rsv)
    lens = [sl[i][0] for i in range(nseg)]
    p = pos + 32
    segs = []
    if lens[0] > 0:
        seg0 = bytes(buf[p:p + lens[0]])
        if len(seg0) != lens[0] or p + lens[0] + 4 > len(buf):
            raise CheckError("truncated segment 0")
        c = struct.unpack("<I", buf[p + lens[0]:p + lens[0] + 4])[0]
        if crc32c(seg0, 0xFFFFFFFF) != c:
            raise CheckError("segment 0 CRC mismatch")
        p += lens[0] + 4
    else:
        seg0 = b""
    segs.append(seg0)
    rest_len = sum(lens[1:])
    ep_len = 13 if nseg > 1 else 0
    if p + rest_len + ep_len > len(buf):
        raise CheckError("truncated frame body")
    for i in range(1, nseg):
        segs.append(bytes(buf[p:p + lens[i]]))
        p += lens[i]
    late = None
    if nseg > 1:
        ep = bytes(buf[p:p + 13])
        late = ep[0]
        if late & 0x0F != 0x0E:
            raise CheckError("epilogue late_status %#x" % late)
        slots = struct.unpack("<III", ep[1:13])
        for i in range(1, 4):
            if i < nseg:
                exp = crc32c(segs[i], 0xFFFFFFFF)       # empty used segment -> seed passes through
            else:
                exp = 0
            if slots[i - 1] != exp:
                raise CheckError("epilogue CRC slot %d mismatch" % (i - 1))
        p += 13
    f = Frame()
    f.tag, f.segs, f.lens, f.aligns = tag, segs, lens, [sl[i][1] for i in range(nseg)]
    f.start, f.end, f.secure, f.flags, f.nseg, f.late_status = pos, p, False, flags, nseg, late
    return f


class SecureRx:
    """msgr2.1 secure framing receiver for one direction (msgr2-secure-mode.md 2.6, 2.8, 3.4)."""

    def __init__(self, key16, nonce12):
        self.aead = AESGCM(key16)
        self.nonce = bytearray(nonce12)
        self.nops = 0

    def _op(self, data):
        iv = bytes(self.nonce)
        out = self.aead.decrypt(iv, bytes(data), None)       # raises InvalidTag
        ctr = (struct.unpack("<Q", self.nonce[4:12])[0] + 1) & 0xFFFFFFFFFFFFFFFF
        self.nonce[4:12] = struct.pack("<Q", ctr)
        self.nops += 1
        return out

    def parse(self, buf, pos):
        try:
            if pos + 96 > len(buf):
                raise CheckError("truncated secure preamble")
            p1 = self._op(buf[pos:pos + 96])
        except CheckError:
            raise
        except Exception as e:                                  # InvalidTag
            raise CheckError("secure P1 tag failure (%s)" % type(e).__name__)
        pre, inline = p1[:32], p1[32:80]
        tag, nseg, sl, flags, rsv = parse_preamble(pre)
        check_preamble_rules(tag, nseg, sl, flags, rsv)
        lens = [sl[i][0] for i in range(nseg)]
        p = pos + 96
        pad16 = lambda x: (x + 15) & ~15
        if lens[0] > 48:
            n = pad16(lens[0]) - 48 + 16
            if p + n > len(buf):
                raise CheckError("truncated secure segment 0 remainder")
            try:
                rem = self._op(buf[p:p + n])
            except Exception as e:
                raise CheckError("secure P2 tag failure")
            seg0 = (inline + rem)[:lens[0]]
            p += n
        else:
            seg0 = inline[:lens[0]]
        segs = [seg0]
        late = None
        if nseg > 1:
            n = sum(pad16(lens[i]) for i in range(1, nseg)) + 16 + 16
            if p + n > len(buf):
                raise CheckError("truncated secure P3")
            try:
                body = self._op(buf[p:p + n])
            except Exception as e:
                raise CheckError("secure P3 tag failure")
            q = 0
            for i in range(1, nseg):
                segs.append(body[q:q + lens[i]])
                q += pad16(lens[i])
            late = body[q]
            if late & 0x0F != 0x0E:
                raise CheckError("secure epilogue late_status %#x" % late)
            if body[q + 1:q + 16] != bytes(15):
                raise CheckError("secure epilogue padding not zero")
            p += n
        f = Frame()
        f.tag, f.segs, f.lens, f.aligns = tag, segs, lens, [sl[i][1] for i in range(nseg)]
        f.start, f.end, f.secure, f.flags, f.nseg, f.late_status = pos, p, True, flags, nseg, late
        return f


# ---- control frame payload decoders (msgr2.md 2.7) ----
def dec_auth_request(seg0):
    r = Rd(seg0)
    method = r.u32()
    modes = [r.u32() for _ in range(r.u32())]
    payload = r.blob()
    if not r.done():
        raise CheckError("AUTH_REQUEST trailing bytes")
    return method, modes, payload


def dec_auth_bad_method(seg0):
    r = Rd(seg0)
    method = r.u32()
    result = r.s32()
    am = [r.u32() for _ in range(r.u32())]
    amo = [r.u32() for _ in range(r.u32())]
    if not r.done():
        raise CheckError("AUTH_BAD_METHOD trailing bytes")
    return method, result, am, amo


def dec_blob_frame(seg0):
    r = Rd(seg0)
    b = r.blob()
    if not r.done():
        raise CheckError("blob frame trailing bytes")
    return b


def dec_auth_done(seg0):
    r = Rd(seg0)
    gid = r.u64()
    mode = r.u32()
    payload = r.blob()
    if not r.done():
        raise CheckError("AUTH_DONE trailing bytes")
    return gid, mode, payload


def dec_hello(seg0):
    r = Rd(seg0)
    et = r.u8()
    addr = r.rest()
    return et, addr


def rd_entity_addr(r):
    marker = r.u8()
    if marker != 1:
        raise CheckError("entity_addr marker %d" % marker)
    r.u8(); r.u8()
    r.take(r.u32())


def dec_client_ident(seg0):
    r = Rd(seg0)
    mk = r.u8()
    if mk != 2:
        raise CheckError("addrvec marker %d" % mk)
    for _ in range(r.u32()):
        rd_entity_addr(r)
    rd_entity_addr(r)                      # target_addr
    gid = struct.unpack("<q", r.take(8))[0]
    gseq, sup, req, flags, cookie = struct.unpack("<QQQQQ", r.take(40))
    if not r.done():
        raise CheckError("CLIENT_IDENT trailing bytes")
    return dict(gid=gid, global_seq=gseq, supported=sup, required=req, flags=flags, cookie=cookie)


def dec_header2(b):
    if len(b) != 41:
        raise CheckError("ceph_msg_header2 length %d" % len(b))
    seq, tid, typ, prio, ver, ppad, doff, ackseq, flags, compat, rsv = struct.unpack("<QQHHHIHQBHH", b)
    return dict(seq=seq, tid=tid, type=typ, prio=prio, version=ver, pre_pad=ppad, data_off=doff,
                ack_seq=ackseq, flags=flags, compat=compat, reserved=rsv)


# --------------------------------------------------------------------------------------
# cephx structure decoders (cephx.md 2.7)
# --------------------------------------------------------------------------------------
def rd_key(rd):
    t = rd.u16()
    created = rd.utime()
    n = rd.u16()
    return Key(t, rd.take(n), created)


def dec_ticket_blob(b):
    r = Rd(b)
    v = r.u8()
    sid = r.u64()
    data = r.blob()
    return dict(v=v, secret_id=sid, data=data, consumed=r.p), r


def enc_ticket_blob(v, secret_id, data):
    return p8(v) + p64(secret_id) + pblob(data)


def dec_entity_name(r):
    t = r.u32()
    i = r.string()
    return t, i.decode()


def dec_service_ticket_item(item):
    """CephXServiceTicket: u8 v=1, CryptoKey session_key, utime validity."""
    r = Rd(item)
    v = r.u8()
    k = rd_key(r)
    val = r.utime()
    return dict(v=v, key=k, validity=val, trailing=r.left())


def dec_ticket_reply(r, decrypt_key, prev_auth_key=None, info=None):
    """Decode a cephx ticket reply (cephx.md 2.7 'Ticket reply').
    decrypt_key: Key used for every msg_a. Returns list of ticket dicts."""
    reply_v = r.u8()
    num = r.u32()
    out = []
    for _ in range(num):
        service_id = r.u32()
        ticket_v = r.u8()
        msg_a = r.blob()
        item = open_raw(decrypt_key, USAGE_TICKET_SESSION, msg_a)
        st = dec_service_ticket_item(item)
        enc = r.u8()
        if enc == 0:
            bl = r.blob()
        elif enc == 1:
            ct = r.blob()
            inner = open_raw(prev_auth_key, USAGE_TICKET_BLOB, ct)
            bl = Rd(inner).blob()
        else:
            raise CheckError("ticket_enc %d" % enc)
        tb, _ = dec_ticket_blob(bl)
        out.append(dict(reply_v=reply_v, service_id=service_id, ticket_v=ticket_v, st=st,
                        ticket_enc=enc, blob=bl, tb=tb, msg_a_len=len(msg_a),
                        msg_a_ct_type=decrypt_key.type, tb_trailing=len(bl) - tb["consumed"]))
    return out


def dec_mon_auth_request_payload(pl):
    r = Rd(pl)
    mode_byte = r.u8()
    et, ident = dec_entity_name(r)
    gid = r.u64()
    return dict(mode_byte=mode_byte, etype=et, ident=ident, global_id=gid, trailing=r.left())


def dec_authenticate(b):
    r = Rd(b)
    req_type = r.u16()
    v = r.u8()
    cc = r.u64()
    proof = r.u64()
    old = r.take(13) if False else None
    # old ticket: u8 v, u64 secret_id, blob
    ov = r.u8()
    osid = r.u64()
    odata = r.blob()
    other = r.u32()
    return dict(req_type=req_type, v=v, client_challenge=cc, proof=proof, old_v=ov,
                old_secret_id=osid, old_data_len=len(odata), other_keys=other, trailing=r.left())


def dec_authorizer(pl):
    r = Rd(pl)
    v = r.u8()
    gid = r.u64()
    sid = r.u32()
    tb_start = r.p
    tv = r.u8()
    tsid = r.u64()
    tdata = r.blob()
    tb_bytes = pl[tb_start:r.p]
    proof = r.blob()
    return dict(v=v, global_id=gid, service_id=sid, ticket_bytes=tb_bytes, ticket_v=tv,
                ticket_secret_id=tsid, ticket_data=tdata, proof=proof, prefix=pl[:r.p - 4 - len(proof)],
                trailing=r.left())


def enc_authorize_item(nonce, have_challenge, plus_one):
    return p8(2) + p64(nonce) + p8(1 if have_challenge else 0) + p64(plus_one)


def dec_authorize_item(item):
    r = Rd(item)
    v = r.u8()
    nonce = r.u64()
    hc = r.u8()
    po = r.u64()
    return dict(v=v, nonce=nonce, have_challenge=hc, plus_one=po, trailing=r.left())


def parse_session_log_keys(path):
    """From secrets/session-secrets/<s>.txt: set of (service, secret_id, session-key base64)."""
    out = []
    if not os.path.exists(path):
        return out
    import re
    rx = re.compile(r"verify_service_ticket_reply service (\w+) secret_id (\d+) session_key (\S+) validity=([\d.]+)")
    with open(path, errors="replace") as f:
        for line in f:
            m = rx.search(line)
            if m:
                out.append((m.group(1), int(m.group(2)), m.group(3), float(m.group(4))))
    return out


# --------------------------------------------------------------------------------------
# connection-level analysis
# --------------------------------------------------------------------------------------
CLIENT_IP = None   # inferred from the SYN


class Session:
    """State shared by all connections of one pcap (one capture session)."""

    def __init__(self, name, meta, keyrings, res, log_keys):
        self.name = name
        self.meta = meta
        self.keyrings = keyrings          # entity -> [Key]
        self.res = res
        self.tickets = []                 # dicts: service_id, secret_id, blob, key, validity
        self.auth_keys = {}               # AUTH session key per global_id (latest)
        self.decrypted_keys = []          # (service name, secret_id, Key) for log cross-check
        self.summary = []                 # per-connection structure summary (no secrets)
        self.log_keys = log_keys


SERVICE_NAMES = {1: "mon", 2: "mds", 4: "osd", 8: "client", 0x10: "mgr", 0x20: "auth"}


def split_stream_frames(buf, start, res, where, stop_after=None):
    """Parse consecutive crc frames. Returns (frames, pos, error). stop_after(frame, frames) -> bool."""
    frames = []
    pos = start
    err = None
    while pos < len(buf):
        try:
            f = parse_crc_frame(buf, pos)
        except CheckError as e:
            err = str(e)
            break
        frames.append(f)
        pos = f.end
        if stop_after and stop_after(f, frames):
            break
    return frames, pos, err


def check_banner(buf, res, where, who):
    ok = len(buf) >= 26 and buf[:8] == b"ceph v2\n" and struct.unpack("<H", buf[8:10])[0] == 16
    res.expect(ok, "msgr2.banner_shape", where, who)
    if ok:
        sup, req = struct.unpack("<QQ", buf[10:26])
        return sup, req
    return None, None


def hmac256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def analyze_connection(sess, conn_id, cbuf, sbuf, sport, res, t_first, cmarks, smarks):
    where = "%s:%s" % (sess.name, conn_id)
    info = dict(conn=conn_id, server_port=sport, t_start=t_first)
    info["_marks"] = (cmarks, smarks)
    csup, creq = check_banner(cbuf, res, where, "client")
    ssup, sreq = check_banner(sbuf, res, where, "server")
    info["client_banner"] = (csup, creq)
    info["server_banner"] = (ssup, sreq)
    res.expect(ssup == 3 and sreq == 0, "msgr2.server_banner_3_0", where, "got %r %r" % (ssup, sreq))
    res.expect(csup in (1, 3) and creq == 0, "msgr2.client_banner", where, "got %r %r" % (csup, creq))

    # --- server stream: crc until AUTH_DONE / AUTH_BAD_METHOD ---
    def s_stop(f, frames):
        return f.tag in (T_DONE, T_BAD)
    sframes, spos, serr = split_stream_frames(sbuf, 26, res, where, s_stop)
    res.expect(serr is None, "msgr2.server_crc_frames_parse", where, str(serr))
    tags = [f.tag for f in sframes]
    res.expect(tags[:1] == [T_HELLO], "msgr2.server_first_frame_hello", where, str(tags))
    res.ok("msgr2.frames_crc_verified", len(sframes))
    # --- client stream: HELLO, AUTH_REQUEST, N x AUTH_REQUEST_MORE ---
    n_more = sum(1 for f in sframes if f.tag == T_REPLY_MORE)
    done = sframes[-1].tag == T_DONE if sframes else False
    bad = sframes[-1].tag == T_BAD if sframes else False

    def c_stop(f, frames):
        return sum(1 for x in frames if x.tag in (T_AUTH_REQ, T_REQ_MORE)) >= 1 + n_more and \
            frames[-1].tag in (T_AUTH_REQ, T_REQ_MORE)
    cframes, cpos, cerr = split_stream_frames(cbuf, 26, res, where, c_stop)
    res.expect(cerr is None, "msgr2.client_crc_frames_parse", where, str(cerr))
    res.ok("msgr2.frames_crc_verified", len(cframes))
    ctags = [f.tag for f in cframes]
    res.expect(ctags[:2] == [T_HELLO, T_AUTH_REQ], "msgr2.client_hello_then_auth_request", where, str(ctags))
    if len(cframes) < 2 or not sframes:
        res.fail("cephx.conn_has_auth_exchange", where, "client tags %r server tags %r" % (ctags, tags))
        return info

    # HELLO contents (entity type, address shape)
    et, addr = dec_hello(sframes[0].segs[0])
    info["server_entity_type"] = et
    res.expect(et in (ENT_MON, ENT_OSD, ENT_MGR), "msgr2.server_hello_entity_type", where, str(et))
    cet, caddr = dec_hello(cframes[0].segs[0])
    res.expect(cet == ENT_CLIENT, "msgr2.client_hello_entity_type_8", where, str(cet))
    for a in (addr, caddr):
        r = Rd(a)
        try:
            marker, sv, sc, slen, typ, nonce, elen = r.u8(), r.u8(), r.u8(), r.u32(), r.u32(), r.u32(), r.u32()
            fam = r.u16()
            res.expect((marker, sv, sc, slen, elen, fam) == (1, 1, 1, 28, 16, 2),
                       "msgr2.entity_addr_ipv4_shape", where, str((marker, sv, sc, slen, elen, fam)))
            res.note("msgr2.hello_addr_type_observed", "type=%d nonce_is_zero=%s" % (typ, nonce == 0))
        except CheckError as e:
            res.fail("msgr2.entity_addr_ipv4_shape", where, str(e))

    method, modes, apayload = dec_auth_request(cframes[1].segs[0])
    info["method"], info["offered_modes"] = method, modes
    res.expect(method == 2, "cephx.auth_request_method_2", where, str(method))
    res.expect(len(modes) >= 1 and all(m in (1, 2) for m in modes), "cephx.auth_request_modes", where, str(modes))

    if bad:
        m2, result, allowed_m, allowed_modes = dec_auth_bad_method(sframes[-1].segs[0])
        info["bad_method"] = dict(method=m2, result=result, allowed_methods=allowed_m, allowed_modes=allowed_modes)
        info["kind"] = "mon" if apayload[:1] == b"\x0a" else "authorizer"
    if apayload[:1] == b"\x0a":
        analyze_mon_conn(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, apayload, modes, res)
    elif apayload[:1] == b"\x01":
        analyze_authorizer_conn(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, apayload, modes, res)
    else:
        res.fail("cephx.auth_payload_first_byte", where, "first byte %r" % apayload[:1])
    info.pop("_marks", None)
    info.pop("_gid", None)
    sess.summary.append(info)
    return info


def key_for_proof(sess, entity, sc, cc, proof):
    """Return (matching_keys, all_candidates)."""
    cands = sess.keyrings.get(entity, [])
    return [k for k in cands if challenge_proof(k, sc, cc) == proof], cands


def analyze_mon_conn(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, apayload, modes, res):
    info["kind"] = "mon"
    r0 = dec_mon_auth_request_payload(apayload)
    res.expect(r0["mode_byte"] == 10 and r0["etype"] == 8 and r0["trailing"] == 0, "cephx.mon_auth_request_payload",
               where, str(r0))
    res.expect(len(apayload) == 1 + 4 + 4 + len(r0["ident"]) + 8, "cephx.mon_auth_request_payload_length", where, "")
    info["entity"] = "client." + r0["ident"]
    info["global_id_in_request_is_zero"] = r0["global_id"] == 0
    # server challenge
    if len(sframes) < 2 or sframes[1].tag != T_REPLY_MORE:
        res.fail("cephx.mon_reply_more_present", where, "server tags %r" % [f.tag for f in sframes])
        return
    pl = dec_blob_frame(sframes[1].segs[0])
    r = Rd(pl)
    v, sc = r.u8(), r.u64()
    res.expect(v == 1 and r.done() and len(pl) == 9 and sc != 0, "cephx.server_challenge_shape", where,
               "v=%d len=%d" % (v, len(pl)))
    # AUTHENTICATE
    creq = [f for f in cframes if f.tag == T_REQ_MORE]
    if len(creq) != 1:
        res.fail("cephx.mon_one_request_more", where, "count %d" % len(creq))
        return
    auth = dec_authenticate(dec_blob_frame(creq[0].segs[0]))
    res.expect(auth["req_type"] == 0x0100 and auth["v"] == 3 and auth["trailing"] == 0, "cephx.authenticate_shape",
               where, str({k: v for k, v in auth.items() if k != "proof"}))
    info["authenticate"] = dict(v=auth["v"], req_type=auth["req_type"], other_keys=auth["other_keys"],
                                old_ticket_empty=(auth["old_secret_id"] == 0 and auth["old_data_len"] == 0),
                                old_v=auth["old_v"], old_data_len=auth["old_data_len"])
    res.expect(auth["other_keys"] & 0x20, "cephx.authenticate_other_keys_has_auth_bit", where, hex(auth["other_keys"]))
    # proof
    matches, cands = key_for_proof(sess, info["entity"], sc, auth["client_challenge"], auth["proof"])
    if not cands:
        res.fail("cephx.keyring_available", where, info["entity"])
        return
    res.expect(len(matches) == 1, "cephx.challenge_proof_matches_one_candidate", where,
               "%d of %d candidates match (%s)" % (len(matches), len(cands), info["entity"]))
    if not matches:
        info["principal_key_found"] = False
        # wrong-key sessions end here: server must answer BAD_METHOD
        res.expect(sframes[-1].tag == T_BAD, "cephx.no_key_match_implies_bad_method", where, "")
        return
    pk = matches[0]
    info["principal_key_type"] = pk.type
    res.ok("cephx.proof_type%d" % pk.type)
    if pk.type == 1:
        # negative controls for 2.8: the HMAC form must NOT reproduce a type-1 proof, and neither must
        # a word-aligned XOR of the ciphertext alone (the 4-byte length quirk).
        blob = p64(sc) + p64(auth["client_challenge"])
        d = hmac256(pk.secret, blob)
        x = 0
        for i in range(0, 32, 8):
            x ^= struct.unpack("<Q", d[i:i + 8])[0]
        res.expect(x != auth["proof"], "cephx.type1_proof_is_not_the_hmac_form", where, "")
        enc = seal(pk, 0, blob)
        y = 0
        ct = enc[4:]
        for i in range(0, 32, 8):
            y ^= struct.unpack("<Q", ct[i:i + 8])[0]
        res.expect(y != auth["proof"], "cephx.type1_proof_includes_length_prefix", where, "")
    is_wrong = pk.src.startswith("wrong.")
    info["wrong_key_session"] = is_wrong
    if sframes[-1].tag == T_BAD:
        bm = info.get("bad_method", {})
        res.expect(is_wrong, "cephx.bad_method_only_with_wrong_key", where, "key from %s" % pk.src)
        res.expect(bm.get("result") == -13 and bm.get("allowed_methods") == [2],
                   "cephx.wrong_key_bad_method_result_minus13", where, str(bm))
        res.expect(len(sframes) == 3 and [f.tag for f in sframes] == [T_HELLO, T_REPLY_MORE, T_BAD],
                   "cephx.wrong_key_frame_sequence_hello_replymore_badmethod", where, str([f.tag for f in sframes]))
        return
    res.expect(not is_wrong, "cephx.right_key_session_uses_the_keyring_key", where, "key from %s" % pk.src)
    if sframes[-1].tag != T_DONE:
        res.fail("cephx.mon_auth_done_present", where, "no AUTH_DONE")
        return
    gid, mode, payload = dec_auth_done(sframes[-1].segs[0])
    info["mode"], info["global_id_nonzero"] = mode, gid != 0
    info["_gid"] = gid
    res.expect(mode == modes[0], "cephx.server_picks_first_offered_mode", where, "mode %d offered %r" % (mode, modes))
    res.expect(mode in modes, "cephx.auth_done_mode_was_offered", where, "mode %d offered %r" % (mode, modes))
    res.expect(gid != 0, "cephx.auth_done_global_id_nonzero", where, "")
    if r0["global_id"] != 0:
        res.expect(gid == r0["global_id"], "cephx.reclaim_keeps_global_id", where, "")
    r = Rd(payload)
    rt, status = r.u16(), r.s32()
    res.expect(rt == 0x0100 and status == 0, "cephx.auth_done_response_header", where, "%x %d" % (rt, status))
    tickets = dec_ticket_reply(r, pk, sess.auth_keys.get(gid))
    res.expect(len(tickets) == 1 and tickets[0]["service_id"] == ENT_AUTH and tickets[0]["reply_v"] == 1 and
               tickets[0]["ticket_v"] == 1, "cephx.initial_ticket_reply_one_auth_ticket", where, "")
    t0 = tickets[0]
    res.expect(t0["st"]["v"] == 1 and t0["st"]["trailing"] == 0 and t0["tb_trailing"] == 0,
               "cephx.ticket_inner_shapes", where, "")
    auth_key = t0["st"]["key"]
    info["auth_session_key_type"] = auth_key.type
    res.expect(auth_key.type == pk.type, "cephx.auth_session_key_type_equals_principal_type", where,
               "%d vs %d" % (auth_key.type, pk.type))
    info["auth_ticket"] = dict(ticket_enc=t0["ticket_enc"], validity_s=t0["st"]["validity"][0],
                               validity_ns=t0["st"]["validity"][1], msg_a_len=t0["msg_a_len"],
                               blob_len=len(t0["blob"]), key_len=len(auth_key.secret))
    res.expect(0 < t0["st"]["validity"][0] <= 10 * 86400 and t0["st"]["validity"][1] < 10 ** 9,
               "cephx.validity_is_small_duration_not_timestamp", where, str(t0["st"]["validity"]))
    sess.auth_keys[gid] = auth_key
    sess.tickets.append(dict(service_id=ENT_AUTH, secret_id=t0["tb"]["secret_id"], blob=t0["blob"],
                             key=auth_key, validity=t0["st"]["validity"], gid=gid))
    sess.decrypted_keys.append(("auth", t0["tb"]["secret_id"], auth_key))
    secret = b""
    info["connection_secret_len"] = None
    extra_info = None
    if r.left():
        cbl = r.blob()
        extra = r.blob()
        res.expect(r.done(), "cephx.auth_done_payload_fully_consumed", where, "%d trailing" % r.left())
        info["cbl_len"], info["extra_len"] = len(cbl), len(extra)
        if cbl:
            rr = Rd(cbl)
            ct = rr.blob()
            res.expect(rr.done(), "cephx.cbl_is_one_length_prefixed_ciphertext", where, "")
            item = open_raw(auth_key, USAGE_CONN_SECRET, ct)
            ri = Rd(item)
            secret = ri.string()
            res.expect(ri.done(), "cephx.connection_secret_string_exact", where, "%d trailing" % ri.left())
            info["connection_secret_len"] = len(secret)
            res.expect(len(secret) == (64 if mode == 2 else 0), "cephx.connection_secret_len_by_mode", where,
                       "mode %d len %d" % (mode, len(secret)))
            # envelope wire check: raw plaintext header
            plain = auth_key.decrypt(USAGE_CONN_SECRET, ct)
            res.expect(plain[:1] == b"\x01" and plain[1:9] == MAGIC_WIRE, "cephx.envelope_v1_and_magic_bytes", where, "")
            info["cbl_inner_ct_len"] = len(ct)
        else:
            res.fail("cephx.cbl_present_when_other_keys_nonzero", where, "cbl empty")
        want = [b for b in (1, 2, 4, 8, 0x10) if auth["other_keys"] & b]
        if extra:
            ex = dec_ticket_reply(Rd(extra), auth_key)
            got = sorted(t["service_id"] for t in ex)
            res.expect(got == sorted(want), "cephx.extra_tickets_match_requested_mask", where,
                       "got %r want %r" % (got, want))
            res.expect(all(t["ticket_enc"] == 0 and t["tb_trailing"] == 0 for t in ex), "cephx.extra_tickets_not_encrypted_blob",
                       where, "")
            info["extra_tickets"] = []
            for t in ex:
                st = t["st"]
                res.expect(st["v"] == 1 and st["trailing"] == 0, "cephx.extra_ticket_inner_shape", where, "")
                sess.tickets.append(dict(service_id=t["service_id"], secret_id=t["tb"]["secret_id"], blob=t["blob"],
                                         key=st["key"], validity=st["validity"], gid=gid))
                sess.decrypted_keys.append((SERVICE_NAMES.get(t["service_id"], str(t["service_id"])),
                                            t["tb"]["secret_id"], st["key"]))
                info["extra_tickets"].append(dict(service_id=t["service_id"], key_type=st["key"].type,
                                                  key_len=len(st["key"].secret), validity_s=st["validity"][0],
                                                  msg_a_len=t["msg_a_len"], blob_len=len(t["blob"])))
        else:
            res.expect(not [b for b in want], "cephx.extra_empty_only_when_mask_is_auth_only", where,
                       "extra empty but mask %#x" % auth["other_keys"])
    else:
        res.fail("cephx.auth_done_has_cbl_and_extra", where, "no bytes after ticket reply")
        return
    post_auth(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, mode, auth_key, secret, res)


def analyze_authorizer_conn(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, apayload, modes, res):
    info["kind"] = "authorizer"
    a1 = dec_authorizer(apayload)
    res.expect(a1["v"] == 1 and a1["trailing"] == 0 and a1["ticket_v"] == 1, "cephx.authorizer_shape", where,
               str({k: v for k, v in a1.items() if k in ("v", "trailing", "ticket_v")}))
    sid = a1["service_id"]
    info["service_id"] = sid
    t = None
    for cand in sess.tickets:
        if cand["service_id"] == sid and cand["blob"] == a1["ticket_bytes"]:
            t = cand
    if t is None:
        res.fail("cephx.authorizer_ticket_from_mon_reply", where, "no ticket for service %#x" % sid)
        return
    res.ok("cephx.authorizer_ticket_from_mon_reply")
    res.expect(a1["global_id"] == t["gid"], "cephx.authorizer_global_id_equals_mon_global_id", where, "")
    key = t["key"]
    info["ticket_key_type"] = key.type
    item = dec_authorize_item(open_raw(key, USAGE_AUTHORIZE, a1["proof"]))
    res.expect(item["v"] == 2 and item["have_challenge"] == 0 and item["plus_one"] == 0 and item["trailing"] == 0,
               "cephx.authorize_first_shape", where, str(item))
    nonce = item["nonce"]
    # challenge
    more = [f for f in sframes if f.tag == T_REPLY_MORE]
    res.expect(len(more) == 1, "cephx.authorizer_challenge_always_sent", where, "%d AUTH_REPLY_MORE" % len(more))
    if len(more) != 1:
        return
    raw = dec_blob_frame(more[0].segs[0])
    # raw ciphertext, no extra u32 prefix: must decrypt directly
    ch = Rd(open_raw(key, USAGE_CHALLENGE, raw))
    cv, schal = ch.u8(), ch.u64()
    res.expect(cv == 1 and ch.done(), "cephx.authorizer_challenge_shape_raw_no_prefix", where, "")
    # does the same bytes also "work" if a u32 prefix were present? (negative control)
    try:
        open_raw(key, USAGE_CHALLENGE, raw[4:])
        res.fail("cephx.challenge_has_no_length_prefix_control", where, "decrypts with 4 bytes stripped")
    except CheckError:
        res.ok("cephx.challenge_has_no_length_prefix_control")
    reqs = [f for f in cframes if f.tag == T_REQ_MORE]
    if len(reqs) != 1:
        res.fail("cephx.authorizer_one_request_more", where, str(len(reqs)))
        return
    a2 = dec_authorizer(dec_blob_frame(reqs[0].segs[0]))
    res.expect(a2["prefix"] == a1["prefix"], "cephx.second_authorizer_same_prefix", where, "")
    item2 = dec_authorize_item(open_raw(key, USAGE_AUTHORIZE, a2["proof"]))
    res.expect(item2["v"] == 2 and item2["have_challenge"] == 1 and item2["plus_one"] == schal + 1 and
               item2["nonce"] == nonce and item2["trailing"] == 0, "cephx.second_authorize_has_challenge_plus_one", where,
               str(item2))
    info["authorize"] = dict(first_ct_len=len(a1["proof"]), second_ct_len=len(a2["proof"]),
                             nonce_same=item2["nonce"] == nonce,
                             ciphertexts_differ=(a1["proof"] != a2["proof"]))
    if key.type == 2:
        res.expect(a1["proof"] != a2["proof"], "cephx.type2_ciphertexts_differ_between_sends", where, "")
    else:
        res.expect(a1["proof"] != a2["proof"], "cephx.type1_ciphertexts_differ_due_to_content", where, "")
    if sframes[-1].tag == T_BAD:
        bm = info.get("bad_method", {})
        res.expect(bm.get("result") == -13 and [f.tag for f in sframes] == [T_HELLO, T_REPLY_MORE, T_BAD],
                   "cephx.authorizer_rejected_after_challenge_with_bad_method_minus13", where, str(bm))
        info["rejected_after_second_authorizer"] = True
        return
    if sframes[-1].tag != T_DONE:
        res.fail("cephx.authorizer_auth_done_present", where, "tags %r" % [f.tag for f in sframes])
        return
    gid, mode, payload = dec_auth_done(sframes[-1].segs[0])
    info["mode"] = mode
    info["_gid"] = t["gid"]
    res.expect(mode in modes, "cephx.auth_done_mode_was_offered", where, "mode %d offered %r" % (mode, modes))
    res.expect(mode == modes[0], "cephx.server_picks_first_offered_mode", where, "mode %d offered %r" % (mode, modes))
    info["auth_done_global_id_equals_ticket_gid"] = (gid == t["gid"])
    info["auth_done_global_id"] = "zero" if gid == 0 else ("same" if gid == t["gid"] else "other")
    rr = Rd(payload)
    ct = rr.blob()
    res.expect(rr.done(), "cephx.authorizer_reply_is_one_prefixed_ciphertext", where, "")
    ri = Rd(open_raw(key, USAGE_REPLY, ct))
    rv, npo = ri.u8(), ri.u64()
    secret = b""
    if rv >= 2:
        secret = ri.string()
    res.expect(ri.done(), "cephx.authorizer_reply_fully_consumed", where, "")
    res.expect(npo == nonce + 1, "cephx.authorizer_reply_nonce_plus_one", where, "")
    res.expect((rv == 2) == (mode == 2) and len(secret) == (64 if mode == 2 else 0),
               "cephx.authorizer_reply_v_and_secret_by_mode", where, "v=%d mode=%d secretlen=%d" % (rv, mode, len(secret)))
    info["reply_v"], info["connection_secret_len"] = rv, len(secret)
    post_auth(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, mode, key, secret, res)


def parse_rest(buf, pos, secure_rx, res, where, who):
    """Parse every remaining frame of one direction. Returns (frames, tail_status)."""
    frames = []
    err = None
    while pos < len(buf):
        try:
            f = secure_rx.parse(buf, pos) if secure_rx else parse_crc_frame(buf, pos)
        except CheckError as e:
            err = str(e)
            break
        frames.append(f)
        pos = f.end
    tail = len(buf) - pos
    return frames, pos, err


def post_auth(sess, where, info, cbuf, sbuf, cframes, sframes, cpos, spos, mode, skey, secret, res):
    rx = bytes(sbuf[:spos])          # server -> client, up to and including AUTH_DONE
    tx = bytes(cbuf[:cpos])          # client -> server, up to the end of the last AUTH_REQUEST(_MORE)
    exp_c = hmac256(skey.secret, rx)     # what the client sends
    exp_s = hmac256(skey.secret, tx)     # what the server sends
    c_rx = s_rx = None
    if mode == 2:
        res.expect(len(secret) >= 40, "secure.secret_at_least_40_bytes", where, str(len(secret)))
        if len(secret) < 40:
            return
        key16 = secret[:16]
        s_rx = SecureRx(key16, secret[16:28])        # server -> client direction: seed A
        c_rx = SecureRx(key16, secret[28:40])        # client -> server direction: seed B
    cm, sm = info.get("_marks", ([], []))
    info["t_auth_done"] = ts_at(sm, spos - 1)
    cf, cend, cerr = parse_rest(cbuf, cpos, c_rx, res, where, "client")
    sf, send, serr = parse_rest(sbuf, spos, s_rx, res, where, "server")
    cname = "secure" if mode == 2 else "crc"
    lossy_ok = lambda e: sess.lossy and e is not None and (e.startswith("truncated"))
    res.expect(cerr is None or lossy_ok(cerr), "msgr2.%s_frames_client_stream_parse" % cname, where, str(cerr))
    res.expect(serr is None or lossy_ok(serr), "msgr2.%s_frames_server_stream_parse" % cname, where, str(serr))
    res.ok("msgr2.frames_%s_verified" % cname, len(cf) + len(sf))
    info["post_frames"] = dict(client=len(cf), server=len(sf), mode=mode)
    if cend != len(cbuf) or send != len(sbuf):
        res.note("msgr2.trailing_partial_frame", "%s: client tail %d server tail %d bytes" %
                 (where, len(cbuf) - cend, len(sbuf) - send))
    # AUTH_SIGNATURE both ways
    for who, frames, exp in (("client", cf, exp_c), ("server", sf, exp_s)):
        if not frames or frames[0].tag != T_SIG:
            res.fail("cephx.auth_signature_frame_follows", where, "%s first frame %r" % (who, frames[:1] and frames[0].tag))
            continue
        f = frames[0]
        res.expect(f.nseg == 1 and f.lens == [32] and len(f.segs[0]) == 32, "cephx.auth_signature_is_32_byte_single_segment",
                   where, str(f.lens))
        res.expect(f.segs[0] == exp, "cephx.auth_signature_%s_hmac_sha256_full_transcript" % who, where, "mismatch")
        # variants that must NOT match (settles which bytes are covered)
        if who == "client":
            tr = rx
        else:
            tr = tx
        for label, cut in (("no_banner", tr[26:]), ("banner_only_plus_hello_skipped", None)):
            if cut is None:
                continue
            res.expect(f.segs[0] != hmac256(skey.secret, cut), "cephx.auth_signature_needs_banner_%s" % who, where, "")
        # the signature frame itself is excluded: including it must not match either
        res.expect(f.segs[0] != hmac256(skey.secret, tr + cbuf[cpos:cpos + 1]), "cephx.auth_signature_ctrl_extra_byte", where, "")
    # HMAC key = raw secret, not the whole encoded key
    res.expect(cf and cf[0].segs[0] != hmac256(skey.encode(), rx), "cephx.auth_signature_key_is_raw_secret_not_encoding",
               where, "")
    if skey.type == 2:
        res.expect(cf and cf[0].segs[0] != hmac256(skey.ke(0) if False else skey.secret[:16], rx),
                   "cephx.auth_signature_type2_uses_whole_secret", where, "")
    # frames after the signature
    tags_c = Counter(TAGS.get(f.tag, f.tag) for f in cf)
    tags_s = Counter(TAGS.get(f.tag, f.tag) for f in sf)
    info["post_tags_client"], info["post_tags_server"] = dict(tags_c), dict(tags_s)
    # MESSAGE header sanity (msgr2.md 2.9, incidental) and MAuth / MAuthReply (cephx.md 2.11)
    seq_c = seq_s = 0
    t_msg_last = 0.0
    for who, frames in (("client", cf), ("server", sf)):
        last_seq = 0
        for f in frames:
            if f.tag != T_MESSAGE:
                continue
            t_msg_last = max(t_msg_last, ts_at(cm if who == "client" else sm, f.start))
            h = dec_header2(f.segs[0])
            res.expect(h["seq"] == last_seq + 1, "msgr2.message_seq_counts_from_1_%s" % who, where,
                       "seq %d after %d" % (h["seq"], last_seq))
            last_seq = h["seq"]
            res.expect(h["flags"] & 1 and h["reserved"] == 0 and h["pre_pad"] == 0,
                       "msgr2.message_header2_flags_reserved_prepad", where, str(h))
            res.note("msgr2.message_flags_observed", "flags=%d (%s)" % (h["flags"], who))
            res.expect(h["compat"] != 0, "msgr2.message_compat_version_nonzero", where, str(h))
            res.expect(h["flags"] & 4 == 0, "cephx.no_per_message_signature_flag_in_msgr2", where, str(h["flags"]))
            if h["type"] in (17, 18):
                decode_mauth(sess, where, info, who, f, h, skey, res, ts_at(cm if who == "client" else sm, f.start))
    info["t_last_message"] = t_msg_last
    idents = [f for f in cf if f.tag == 8]
    if idents and info.get("_gid"):
        ci = dec_client_ident(idents[0].segs[0])
        if info.get("kind") == "mon":
            # observed on capture: a monitor connection announces gid -1 when it asked for a new global id,
            # and its (reclaimed) global id when AUTH_REQUEST already carried one
            want = -1 if info.get("global_id_in_request_is_zero") else info["_gid"]
            res.expect(ci["gid"] == want, "cephx.mon_client_ident_gid_minus1_or_reclaimed_global_id", where,
                       "gid %d" % ci["gid"])
        else:
            res.expect(ci["gid"] == info["_gid"], "cephx.service_client_ident_gid_equals_mon_assigned_global_id", where,
                       "CLIENT_IDENT gid differs")
        info["client_ident"] = dict(gid_is_minus1=(ci["gid"] == -1), gid_equals_auth_global_id=(ci["gid"] == info["_gid"]),
                                    flags=ci["flags"], cookie=ci["cookie"], supported=hex(ci["supported"]),
                                    required=hex(ci["required"]), global_seq=ci["global_seq"])


def decode_mauth(sess, where, info, who, f, h, skey, res, ts=0.0):
    """cephx.md 2.11 MAuth (17) / MAuthReply (18)."""
    front = f.segs[1] if len(f.segs) > 1 else b""
    info.setdefault("mauth", [])
    if h["type"] == 17:
        r = Rd(front)
        version, smon, stid = r.u64(), struct.unpack("<h", r.take(2))[0], r.u64()
        protocol = r.u32()
        payload = r.blob()
        monmap_epoch = r.u32()
        res.expect(r.done(), "cephx.mauth_payload_fully_consumed", where, "%d left" % r.left())
        res.expect((h["version"], h["compat"]) == (1, 1), "cephx.mauth_header_version_1_compat_1", where,
                   "%d/%d" % (h["version"], h["compat"]))
        res.expect((version, smon, stid) == (0, -1, 0), "cephx.mauth_paxos_header_fields", where,
                   str((version, smon, stid)))
        info["mauth"].append(dict(dir="c2s", t=ts, version=version, session_mon=smon, session_mon_tid=stid, protocol=protocol,
                                  payload_len=len(payload), monmap_epoch=monmap_epoch, hdr_version=h["version"],
                                  hdr_compat=h["compat"]))
        rr = Rd(payload)
        req_type = rr.u16()
        info["mauth"][-1]["req_type"] = req_type
        res.expect(protocol == 2, "cephx.mauth_protocol_2", where, str(protocol))
        if req_type == 0x0200:
            # authorizer for AUTH service + ServiceTicketRequest
            start = rr.p
            a = dec_authorizer(payload[start:])
            # trailing = bytes after the proof, i.e. the CephXServiceTicketRequest
            tr = Rd(a["trailing"] and payload[len(payload) - a["trailing"]:] or b"")
            tv, keys = tr.u8(), tr.u32()
            res.expect(a["service_id"] == ENT_AUTH and a["v"] == 1 and tv == 1 and tr.done(),
                       "cephx.renewal_request_layout", where,
                       "svc=%#x v=%d tv=%d trailing=%d" % (a["service_id"], a["v"], tv, tr.left()))
            res.expect(keys & ENT_AUTH == 0, "cephx.renewal_mask_excludes_auth_bit", where, hex(keys))
            # decrypt proof with the AUTH session key
            ak = sess.auth_keys.get(a["global_id"])
            if ak:
                it = dec_authorize_item(open_raw(ak, USAGE_AUTHORIZE, a["proof"]))
                res.expect(it["v"] == 2 and it["have_challenge"] == 0 and it["plus_one"] == 0,
                           "cephx.renewal_authorize_no_challenge", where, str(it))
            else:
                res.fail("cephx.renewal_auth_key_known", where, "")
            info["mauth"][-1].update(renew_mask=keys, authorizer_service_id=a["service_id"])
    else:
        r = Rd(front)
        protocol, result, gid = r.u32(), r.s32(), r.u64()
        result_bl = r.blob()
        result_msg = r.string()
        res.expect(r.done(), "cephx.mauth_reply_payload_fully_consumed", where, "%d left" % r.left())
        res.expect((h["version"], h["compat"]) == (1, 1), "cephx.mauth_reply_header_version_1_compat_1", where,
                   "%d/%d" % (h["version"], h["compat"]))
        d = dict(dir="s2c", t=ts, protocol=protocol, result=result, global_id_nonzero=gid != 0, result_bl_len=len(result_bl),
                 result_msg_len=len(result_msg), hdr_version=h["version"], hdr_compat=h["compat"])
        info["mauth"].append(d)
        rr = Rd(result_bl)
        if result_bl:
            rt, st = rr.u16(), rr.s32()
            d["req_type"], d["status"] = rt, st
            if rt == 0x0200:
                ak = skey
                tk = dec_ticket_reply(rr, ak)
                res.expect(rr.done(), "cephx.renewal_reply_fully_consumed", where, "%d left" % rr.left())
                res.expect(all(t["ticket_enc"] == 0 for t in tk), "cephx.renewal_reply_ticket_enc_0", where, "")
                d["tickets"] = [dict(service_id=t["service_id"], key_type=t["st"]["key"].type,
                                     validity_s=t["st"]["validity"][0]) for t in tk]
                for t in tk:
                    sess.tickets.append(dict(service_id=t["service_id"], secret_id=t["tb"]["secret_id"], blob=t["blob"],
                                             key=t["st"]["key"], validity=t["st"]["validity"], gid=gid))
                    sess.decrypted_keys.append((SERVICE_NAMES.get(t["service_id"], str(t["service_id"])),
                                                t["tb"]["secret_id"], t["st"]["key"]))


# --------------------------------------------------------------------------------------
# per-pcap driver
# --------------------------------------------------------------------------------------
def load_all_keyrings(dirs):
    """entity -> [Key]; several keyrings may name the same entity (wrong-key sessions)."""
    out = defaultdict(list)
    for d in dirs:
        for p in sorted(glob.glob(os.path.join(d, "*"))):
            if not os.path.isfile(p):
                continue
            try:
                for ent, b64 in load_keyring(p).items():
                    k = Key.from_base64(b64)
                    k.src = os.path.basename(p)
                    out[ent].append(k)
            except Exception:
                continue
    return out


def check_keyring_shapes(keydirs, res):
    """cephx.md 2.3: encoding sizes and the base64 look of type 1 / type 2 keys. Prints no key bytes."""
    for d in keydirs:
        for p in sorted(glob.glob(os.path.join(d, "*"))):
            if not os.path.isfile(p):
                continue
            for ent, b64 in load_keyring(p).items():
                raw = base64.b64decode(b64)
                k = Key.decode(raw)
                want = {1: (28, 40, "AQ"), 2: (44, 60, "Ag")}[k.type]
                where = "%s:%s" % (os.path.basename(p), ent)
                res.expect(len(raw) == want[0] and len(b64) == want[1] and b64.startswith(want[2]),
                           "cephx.keyring_base64_shape_type%d" % k.type, where,
                           "raw %d b64 %d" % (len(raw), len(b64)))
                res.expect(len(k.secret) == (16 if k.type == 1 else 32), "cephx.generated_key_secret_length", where, "")


def analyze_pcap(args):
    name, pcap, keydirs, secrets_dir, meta = args
    res = Results()
    keyrings = load_all_keyrings(keydirs)
    log_keys = parse_session_log_keys(os.path.join(secrets_dir, "session-secrets", name + ".txt")) if secrets_dir else []
    sess = Session(name, meta, keyrings, res, log_keys)
    flows, st = extract_tcp(pcap)
    res.ok("pcap.packets_parsed", st["packets"])
    res.expect(st.get("truncated", 0) == 0 and st.get("non_ipv4", 0) == 0 and st.get("non_tcp", 0) == 0,
               "pcap.only_complete_ipv4_tcp", name, str(dict(st)))
    # group into connections: client side = side that sent SYN without ACK
    conns = {}
    for k, segs in flows.items():
        syn_only = any((f & 0x12) == 0x02 for _, _, f, _ in segs)
        if syn_only:
            conns.setdefault((k[0], k[1], k[2], k[3]), {})["c"] = segs
    for k, d in list(conns.items()):
        rk = (k[2], k[3], k[0], k[1])
        d["s"] = flows.get(rk, [])
        d["t0"] = min(t for t, _, _, _ in d["c"])
    addrs = set()
    for k in conns:
        addrs.add(ip_s(k[0]))
        addrs.add(ip_s(k[2]))
    res.expect(len(addrs) == 2, "pcap.exactly_two_addresses", name, str(sorted(addrs)))
    n_retr = 0
    lossy = 0
    sess.lossy = False
    drops = tcpdump_drops(secrets_dir, name)
    order = sorted(conns.items(), key=lambda kv: kv[1]["t0"])
    for i, (k, d) in enumerate(order):
        cb, r1, g1, m1, cmarks = reassemble(d["c"])
        sb, r2, g2, m2, smarks = reassemble(d["s"])
        n_retr += r1 + r2
        res.expect(m1 == 0 and m2 == 0, "tcp.retransmissions_carry_identical_bytes", "%s:%d" % (name, i),
                   "mismatching retransmissions %d/%d" % (m1, m2))
        if g1 or g2:
            lossy += 1
            sess.lossy = True
            res.note("tcp.capture_loss", "%s:%d has %d/%d unfilled holes (tcpdump drops: %s)" %
                     (name, i, g1, g2, drops))
        if not cb and not sb:
            rst = any(f & 4 for _, _, f, _ in d["s"]) or any(f & 4 for _, _, f, _ in d["c"])
            res.expect(rst, "tcp.payloadless_connection_is_reset", "%s:%d" % (name, i), "no data and no RST")
            sess.summary.append(dict(conn=i, server_port=k[3], kind="no-data-reset"))
            continue
        try:
            analyze_connection(sess, i, cb, sb, k[3], res, d["t0"], cmarks, smarks)
        except CheckError as e:
            res.fail("cephx.connection_decodes", "%s:%d" % (name, i), str(e))
    res.ok("tcp.connections", len(order))
    session_timing_checks(sess, name, res)
    if lossy:
        res.expect(drops is not None and drops > 0, "tcp.holes_only_in_captures_where_tcpdump_reported_drops", name,
                   "%d lossy connections, tcpdump drops %r" % (lossy, drops))
    res.ok("tcp.retransmitted_segments_seen", n_retr)
    # cross-check with the client's own debug_auth log (secrets dir, optional)
    if log_keys:
        got = Counter((SERVICE_NAMES_LOG.get(svc, svc), sid, k.secret) for svc, sid, k in sess.decrypted_keys)
        logged = Counter((svc, sid, base64.b64decode(b)[12:]) for svc, sid, b, v in log_keys)
        # compare the secret (last bytes of the CryptoKey encoding) of each logged ticket
        miss = 0
        for (svc, sid, sec), n in logged.items():
            if got.get((svc, sid, sec), 0) < 1:
                miss += 1
        res.expect(miss == 0, "cephx.decrypted_session_keys_equal_client_log", name, "%d logged keys not reproduced" % miss)
        res.ok("cephx.logged_keys_reproduced", len(logged) - miss)
        extra = sum(1 for key in got if key not in logged)
        res.expect(extra == 0, "cephx.every_decrypted_key_appears_in_client_log", name, "%d extra" % extra)
    return name, res, sess.summary


def session_timing_checks(sess, name, res):
    """cephx.md 3.5: renew at 3/4 of validity; established connections survive ticket expiry."""
    if "renew-ttl60" not in name:
        return
    deltas = []
    for c in sess.summary:
        if c.get("kind") != "mon":
            continue
        prev = c["t_auth_done"]
        for m in c.get("mauth", []):
            if m["dir"] == "c2s" and m.get("req_type") == 0x0200:
                deltas.append(m["t"] - prev)       # each renewal is due 3/4 of the validity after the previous grant
                prev = m["t"]
    for d in deltas:
        res.expect(44.0 <= d <= 50.0, "cephx.renewal_request_sent_at_about_three_quarters_of_60s", name, "%.2f s" % d)
    res.expect(len(deltas) >= 1, "cephx.renewal_exchange_present_in_ttl60_session", name, "none")
    sess.renew_deltas = deltas
    survive = [c for c in sess.summary if c.get("kind") == "authorizer" and c.get("service_id") == ENT_OSD
               and c.get("t_last_message", 0) - c.get("t_auth_done", 0) > 60.0]
    res.expect(len(survive) >= 1, "cephx.osd_connection_alive_and_used_after_ticket_expiry", name, "none found")
    sess.survive = [round(c["t_last_message"] - c["t_auth_done"], 1) for c in survive]


def tcpdump_drops(secrets_dir, name):
    """'N packets dropped by kernel' from the capture's tcpdump stderr (outside secrets/)."""
    if not secrets_dir:
        return None
    p = os.path.join(os.path.dirname(secrets_dir.rstrip("/")), "stdout", name + ".tcpdump.err")
    try:
        with open(p) as f:
            for line in f:
                if "dropped by kernel" in line:
                    return int(line.split()[0])
    except OSError:
        return None
    return None


SERVICE_NAMES_LOG = {"auth": "auth", "mon": "mon", "osd": "osd", "mgr": "mgr"}


def read_sessions(captures):
    out = {}
    p = os.path.join(captures, "sessions.tsv")
    with open(p) as f:
        for line in f:
            c = line.rstrip("\n").split("\t")
            if len(c) >= 6:
                out[c[0]] = dict(name=c[0], key_type=c[1], entity=c[2], mode=c[3], debug=c[5])
    return out


def run_captures(a):
    captures = pubset.captures_dir(a.captures)
    if a.keys:
        keydirs = a.keys
    elif pubset.is_public_set(captures):
        keydirs = [pubset.PUBLIC_KEYS]
    else:
        keydirs = [pubset.default_keys_dir(captures), os.path.join(captures, "secrets", "keys")]
    secrets_dir = os.path.join(captures, "secrets")
    if not os.path.isdir(secrets_dir):
        secrets_dir = None
        pubset.skip("cephx_check", "cephx.decrypted_session_keys_equal_client_log",
                    "needs the stock client's own debug_auth logs (<captures>/secrets/session-secrets), which print "
                    "session keys and are not published; the tickets are still decrypted and cross-checked against the wire")
    sess = read_sessions(captures)
    total = Results()
    check_keyring_shapes(keydirs, total)
    pcaps = sorted(glob.glob(os.path.join(captures, "pcap", "*.pcap")))
    if a.only:
        pcaps = [p for p in pcaps if a.only in os.path.basename(p)]
    jobs = [(os.path.basename(p)[:-5], p, keydirs, secrets_dir, sess.get(os.path.basename(p)[:-5], {})) for p in pcaps]
    summaries = {}
    if a.jobs > 1:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(a.jobs) as ex:
            outs = list(ex.map(analyze_pcap, jobs))
    else:
        outs = [analyze_pcap(j) for j in jobs]
    for name, res, summ in outs:
        total.merge(res)
        summaries[name] = summ
        bad = sum(res.fails.values())
        print("  %-24s checks=%-6d fail=%d" % (name, sum(res.counts.values()) + bad, bad))
    return total, summaries


def report(total, title="checks"):
    names = sorted(set(total.counts) | set(total.fails))
    npass = sum(total.counts.values())
    nfail = sum(total.fails.values())
    print("\n%-70s %9s %6s" % (title, "pass", "fail"))
    for n in names:
        print("%-70s %9d %6d" % (n, total.counts.get(n, 0), total.fails.get(n, 0)))
    print("%-70s %9d %6d" % ("TOTAL (%d distinct checks)" % len(names), npass, nfail))
    for name, texts in sorted(total.notes.items()):
        for t in sorted(texts)[:5]:
            print("note[%s]: %s" % (name, t))
    for where, name, detail in total.failures[:40]:
        print("FAIL %s %s: %s" % (where, name, detail))
    return nfail


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", help="capture directory (contains pcap/, sessions.tsv; default: harness/vectors/public)")
    ap.add_argument("--keys", action="append", help="directory with keyring files (default: harness/vectors/public/keys "
                                                    "for the public set, else ../lab-secrets and secrets/keys)")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--only", help="substring filter on pcap names")
    ap.add_argument("--summary-json", help="write the per-connection structure summary (no secrets) here")
    ap.add_argument("--vectors", help="check the committed vectors in this directory (offline)")
    ap.add_argument("--emit-vectors", help="(re)generate the synthetic vectors in this directory "
                                           "(with --captures also the scrubbed real frames; with --summary-json the structure file)")
    a = ap.parse_args(argv)
    nfail = 0
    ran = False
    if not (a.captures or a.vectors or a.emit_vectors):
        # no arguments: the public capture set and the committed vectors
        a.captures = pubset.PUBLIC_SET
        a.vectors = os.path.join(pubset.REPO, "harness", "vectors", "cephx")
    if a.emit_vectors:
        ran = True
        emit_vectors(a.emit_vectors, a.captures, a.summary_json)
    npass = 0
    if a.vectors:
        ran = True
        t = Results()
        check_vectors(a.vectors, t)
        nfail += report(t, "vector checks")
        npass += sum(t.counts.values())
    if a.captures:
        ran = True
        total, summaries = run_captures(a)
        nfail += report(total, "capture checks")
        npass += sum(total.counts.values())
        if a.summary_json and not a.emit_vectors:
            with open(a.summary_json, "w") as f:
                json.dump(summaries, f, indent=1, default=str)
    if not ran:
        ap.error("give --captures and/or --vectors")
    print("\nRESULT: %s" % ("ALL CHECKS PASSED" if nfail == 0 else "%d FAILURES" % nfail))
    pubset.emit_result("cephx_check", npass, nfail)
    return 0 if nfail == 0 else 1


# --------------------------------------------------------------------------------------
# builders (used only to generate synthetic vectors; every decoder above is validated on captures)
# --------------------------------------------------------------------------------------
def det(label, n):
    """Deterministic 'random' bytes for synthetic vectors (not secret: labels are public)."""
    out = b""
    c = 0
    while len(out) < n:
        out += hashlib.sha256(("winrbd-vector|%s|%d" % (label, c)).encode()).digest()
        c += 1
    return out[:n]


def frame_crc(tag, segs, aligns=None):
    n = len(segs)
    if aligns is None:
        aligns = [8, 8, 8, 4096][:n]
    pre = bytes([tag, n])
    for i in range(4):
        if i < n:
            pre += struct.pack("<IH", len(segs[i]), aligns[i])
        else:
            pre += bytes(6)
    pre += bytes([0, 0])
    pre += p32(crc32c(pre, 0))
    out = pre
    if segs[0]:
        out += segs[0] + p32(crc32c(segs[0], 0xFFFFFFFF))
    for i in range(1, n):
        out += segs[i]
    if n > 1:
        ep = bytes([0x0E])
        for i in range(1, 4):
            ep += p32(crc32c(segs[i], 0xFFFFFFFF)) if i < n else p32(0)
        out += ep
    return out


class SecureTx:
    def __init__(self, key16, nonce12):
        self.aead = AESGCM(key16)
        self.nonce = bytearray(nonce12)

    def _op(self, data):
        out = self.aead.encrypt(bytes(self.nonce), bytes(data), None)
        self.nonce[4:12] = struct.pack("<Q", (struct.unpack("<Q", self.nonce[4:12])[0] + 1) & (2 ** 64 - 1))
        return out

    def frame(self, tag, segs, aligns=None):
        n = len(segs)
        if aligns is None:
            aligns = [8, 8, 8, 4096][:n]
        pre = bytes([tag, n])
        for i in range(4):
            pre += struct.pack("<IH", len(segs[i]), aligns[i]) if i < n else bytes(6)
        pre += bytes([0, 0])
        pre += p32(crc32c(pre, 0))
        pad16 = lambda b: b + bytes((-len(b)) % 16)
        s0 = segs[0]
        inline = (s0[:48] if len(s0) > 48 else s0 + bytes(48 - len(s0)))
        out = self._op(pre + inline)
        if len(s0) > 48:
            out += self._op(pad16(s0[48:]))
        if n > 1:
            out += self._op(b"".join(pad16(x) for x in segs[1:]) + bytes([0x0E]) + bytes(15))
        return out


def banner_bytes(sup, req=0):
    return b"ceph v2\n" + p16(16) + p64(sup) + p64(req)


def entity_addr_v4(ip, port, nonce=0, typ=2):
    return (bytes([1, 1, 1]) + p32(28) + p32(typ) + p32(nonce) + p32(16) + p16(2) + struct.pack(">H", port) +
            bytes(int(x) for x in ip.split(".")) + bytes(8))


def ticket_reply_bytes(tickets, enc_key, usage=USAGE_TICKET_SESSION):
    """tickets: [(service_id, session Key, validity_s, ticket_blob_bytes)] (ticket_enc = 0)."""
    out = p8(1) + p32(len(tickets))
    for sid, skey, val, blob in tickets:
        item = p8(1) + skey.encode() + putime(val, 0)
        out += p32(sid) + p8(1) + seal(enc_key, usage, item, det("conf-%x-%s" % (sid, val), 16)) + p8(0) + pblob(blob)
    return out


def build_mon_conn(ktype, mode, mask, principal, ent_id, tag, services, gid=14802):
    """Synthetic mon connection. Returns dict with hex streams and expectations."""
    sc, cc = 0x1122334455667788, 0x99AABBCCDDEEFF00
    auth_key = Key(ktype, det(tag + "-auth", 16 if ktype == 1 else 32), (0, 0))
    secret = det(tag + "-connsecret", 64) if mode == 2 else b""
    ident = ent_id.encode()
    c = banner_bytes(1)
    s = banner_bytes(3)
    chello = frame_crc(1, [p8(8) + entity_addr_v4("10.77.0.10", 3300)])
    shello = frame_crc(1, [p8(1) + entity_addr_v4("10.77.0.99", 40000, 7)])
    c += chello
    s += shello
    areq = p8(10) + p32(8) + pblob(ident) + p64(0)
    c += frame_crc(2, [p32(2) + p32(1) + p32(mode) + pblob(areq)])
    s += frame_crc(4, [pblob(p8(1) + p64(sc))])
    proof = challenge_proof(principal, sc, cc)
    auth = p16(0x0100) + p8(3) + p64(cc) + p64(proof) + enc_ticket_blob(1, 0, b"") + p32(mask)
    c += frame_crc(5, [pblob(auth)])
    c_len_at_sig = len(c)
    # ---- AUTH_DONE payload ----
    auth_blob = enc_ticket_blob(1, 2, det(tag + "-authticket", 150))
    reply = p16(0x0100) + p32(0) + ticket_reply_bytes([(0x20, auth_key, 259200, auth_blob)], principal)
    cbl = seal(auth_key, USAGE_CONN_SECRET, pblob(secret), det(tag + "-cbl-conf", 16))
    extra = b""
    tickets = []
    for sid in (1, 4, 0x10):
        if mask & sid and sid in services:
            tickets.append((sid, services[sid][0], 3600, services[sid][1]))
    if tickets:
        extra = ticket_reply_bytes(tickets, auth_key)
    payload = reply + pblob(cbl) + pblob(extra)
    s += frame_crc(6, [p64(gid) + p32(mode) + pblob(payload)])
    s_len_at_sig = len(s)
    rx, tx = s[:s_len_at_sig], c[:c_len_at_sig]
    sig_c = hmac256(auth_key.secret, rx)
    sig_s = hmac256(auth_key.secret, tx)
    # ---- post-auth frames ----
    if mode == 2:
        ctx, stx = SecureTx(secret[:16], secret[28:40]), SecureTx(secret[:16], secret[16:28])
        c += ctx.frame(7, [sig_c])
        s += stx.frame(7, [sig_s])
        c += ctx.frame(18, [putime(1700000000, 5)])
        s += stx.frame(19, [putime(1700000000, 5)])
    else:
        c += frame_crc(7, [sig_c])
        s += frame_crc(7, [sig_s])
        c += frame_crc(18, [putime(1700000000, 5)])
        s += frame_crc(19, [putime(1700000000, 5)])
    exp = dict(kind="mon", entity="client." + ent_id, mode=mode, request_mask=mask, global_id=gid,
               server_challenge=hex(sc), client_challenge=hex(cc), proof=hex(proof),
               auth_session_key_secret=auth_key.secret.hex(), auth_session_key_type=ktype,
               connection_secret=secret.hex(), auth_signature_client=sig_c.hex(), auth_signature_server=sig_s.hex(),
               tickets=[dict(service_id=sid, session_key_secret=k.secret.hex(), validity_s=3600) for sid, k, _, _ in tickets])
    return dict(server_port=3300, client_stream=c.hex(), server_stream=s.hex(), expect=exp)


def build_osd_conn(mode, ticket, tkey, tag, service_id=4, gid=14802):
    """Synthetic OSD connection with the authorizer round trip. ticket = opaque CephXTicketBlob bytes."""
    nonce = int.from_bytes(det(tag + "-nonce", 8), "little")
    schal = int.from_bytes(det(tag + "-schal", 8), "little")
    secret = det(tag + "-connsecret", 64) if mode == 2 else b""
    prefix = p8(1) + p64(gid) + p32(service_id) + ticket
    a1 = prefix + seal(tkey, USAGE_AUTHORIZE, enc_authorize_item(nonce, False, 0), det(tag + "-c1", 16))
    a2 = prefix + seal(tkey, USAGE_AUTHORIZE, enc_authorize_item(nonce, True, (schal + 1) & (2 ** 64 - 1)),
                       det(tag + "-c2", 16))
    c = banner_bytes(1)
    s = banner_bytes(3)
    c += frame_crc(1, [p8(8) + entity_addr_v4("10.77.0.10", 6800)])
    s += frame_crc(1, [p8(4) + entity_addr_v4("10.77.0.99", 40001, 7)])
    c += frame_crc(2, [p32(2) + p32(1) + p32(mode) + pblob(a1)])
    s += frame_crc(4, [pblob(seal_raw(tkey, USAGE_CHALLENGE, p8(1) + p64(schal), det(tag + "-c3", 16)))])
    c += frame_crc(5, [pblob(a2)])
    c_len_at_sig = len(c)
    rv = 2 if mode == 2 else 1
    item = p8(rv) + p64((nonce + 1) & (2 ** 64 - 1)) + (pblob(secret) if rv >= 2 else b"")
    s += frame_crc(6, [p64(gid) + p32(mode) + pblob(seal(tkey, USAGE_REPLY, item, det(tag + "-c4", 16)))])
    s_len_at_sig = len(s)
    sig_c = hmac256(tkey.secret, s[:s_len_at_sig])
    sig_s = hmac256(tkey.secret, c[:c_len_at_sig])
    if mode == 2:
        ctx, stx = SecureTx(secret[:16], secret[28:40]), SecureTx(secret[:16], secret[16:28])
        c += ctx.frame(7, [sig_c])
        s += stx.frame(7, [sig_s])
    else:
        c += frame_crc(7, [sig_c])
        s += frame_crc(7, [sig_s])
    exp = dict(kind="authorizer", service_id=service_id, mode=mode, global_id=gid, nonce=hex(nonce),
               server_challenge=hex(schal), connection_secret=secret.hex(), reply_v=rv,
               auth_signature_client=sig_c.hex(), auth_signature_server=sig_s.hex())
    return dict(server_port=6800, client_stream=c.hex(), server_stream=s.hex(), expect=exp)


def build_session_vector(ktype, mode):
    tag = "t%d-m%d" % (ktype, mode)
    ent = "vec%d" % ktype
    principal = Key(ktype, det(tag + "-principal", 16 if ktype == 1 else 32), (0, 0))
    services = {}
    for sid in (1, 4, 0x10):
        k = Key(ktype, det("%s-svc-%x" % (tag, sid), 16 if ktype == 1 else 32), (0, 0))
        blob = enc_ticket_blob(1, 2, det("%s-svcblob-%x" % (tag, sid), 140 + sid))
        services[sid] = (k, blob)
    conns = [build_mon_conn(ktype, mode, 0x35, principal, ent, tag + "-mon35", services),
             build_mon_conn(ktype, mode, 0x20, principal, ent, tag + "-mon20", services, gid=14801),
             build_osd_conn(mode, services[4][1], services[4][0], tag + "-osd")]
    return dict(
        description="Synthetic cephx session (no captured data): key type %d, connection mode %s. Keys, tickets and "
                    "secrets are derived from public labels by harness/tools/cephx_check.py (det()); the opaque ticket "
                    "blobs are random filler of realistic length. Streams are the exact bytes each side puts on the "
                    "TCP connection: banner, HELLO, AUTH_*, then the two AUTH_SIGNATURE frames and one keepalive "
                    "pair (encrypted in secure mode)." % (ktype, {1: "crc", 2: "secure"}[mode]),
        entity="client." + ent, keyring_key_base64=base64.b64encode(principal.encode()).decode(),
        principal_key_type=ktype, connections=conns)


def emit_vectors(d, captures=None, summary=None):
    os.makedirs(d, exist_ok=True)
    for kt in (1, 2):
        for mode in (1, 2):
            v = build_session_vector(kt, mode)
            with open(os.path.join(d, "session-type%d-%s.json" % (kt, {1: "crc", 2: "secure"}[mode])), "w") as f:
                json.dump(v, f, indent=1)
    # cipher vectors
    key1 = Key(1, bytes(range(16)))
    key2 = Key(2, bytes(range(32)))
    c1 = []
    for n in (0, 1, 15, 16, 17, 31, 32, 45):
        pt = bytes((i * 7 + 3) % 251 for i in range(n))
        c1.append(dict(plaintext=pt.hex(), ciphertext=key1.encrypt(0, pt).hex()))
    env1 = []
    for item in (b"", b"\x01\x02\x03", bytes(range(40))):
        env1.append(dict(item=item.hex(), usage=0x10, sealed_length_prefixed=seal(key1, 0x10, item).hex()))
    out1 = dict(description="Cipher type 1 (AES-128-CBC, fixed IV, PKCS#7-style padding) with a synthetic key; generated by "
                            "cephx_check.py, and the same implementation decrypts the captured type 1 traffic.",
                key_secret=key1.secret.hex(), iv=CBC_IV.hex(), vectors=c1, envelopes=env1)
    c2 = []
    for usage in (0x03, 0x04, 0x05, 0x10, 0x11, 0x12):
        for n in (0, 6, 16, 21, 60):
            pt = bytes((i * 11 + usage) % 251 for i in range(n))
            conf = det("t2-conf-%d-%d" % (usage, n), 16)
            c2.append(dict(usage=usage, confounder=conf.hex(), plaintext=pt.hex(),
                           ciphertext_with_mac=key2.encrypt(usage, pt, conf).hex()))
    kd = {("%#04x" % u): dict(ke=key2.ke(u).hex(), ki=key2.ki(u).hex()) for u in (0x03, 0x04, 0x05, 0x10, 0x11, 0x12)}
    env2 = []
    for item in (b"", bytes(range(40))):
        env2.append(dict(item=item.hex(), usage=0x10, confounder=det("env2", 16).hex(),
                         sealed_length_prefixed=seal(key2, 0x10, item, det("env2", 16)).hex()))
    out2 = dict(description="Cipher type 2 (AES-256 CTS CS3 + HMAC-SHA384, 24-byte MAC) with a synthetic key and the usage "
                            "values cephx uses. Derived keys included. The RFC 8009 file holds the public standard vectors.",
                key_secret=key2.secret.hex(), derived=kd, vectors=c2, envelopes=env2)
    with open(os.path.join(d, "cipher-type1.json"), "w") as f:
        json.dump(out1, f, indent=1)
    with open(os.path.join(d, "cipher-type2.json"), "w") as f:
        json.dump(out2, f, indent=1)
    # challenge proofs
    pr = []
    for kt, sec in ((1, bytes(range(16))), (2, bytes(range(32)))):
        k = Key(kt, sec)
        sc, cc = 0x1122334455667788, 0x99AABBCCDDEEFF00
        blob = p64(sc) + p64(cc)
        item = dict(key_type=kt, key_secret=sec.hex(), server_challenge=hex(sc), client_challenge=hex(cc),
                    blob=blob.hex(), proof=hex(challenge_proof(k, sc, cc)))
        if kt == 1:
            item["length_prefixed_ciphertext_36_bytes"] = seal(k, 0, blob).hex()
        else:
            item["hmac_sha256_digest"] = hmac256(sec, blob).hex()
        pr.append(item)
    with open(os.path.join(d, "challenge-proof.json"), "w") as f:
        json.dump(dict(description="cephx.md 2.8 challenge proof, synthetic keys. The type 1 entry is the note's worked "
                                   "example.", vectors=pr), f, indent=1)
    if captures:
        emit_scrubbed(d, captures, summary)


def emit_scrubbed(d, captures, summary_path=None):
    """Real frame bytes from the captures with every random / secret-derived field replaced, CRCs recomputed."""
    ph_sc, ph_cc, ph_proof = 0x1122334455667788, 0x99AABBCCDDEEFF00, 0x0123456789ABCDEF
    keydirs = [pubset.default_keys_dir(captures), os.path.join(captures, "secrets", "keys")]
    out = dict(description="Frames taken from real captures with every random or key-derived field replaced by a marked "
                           "placeholder and the CRCs recomputed. The structure (lengths, versions, tags) is the real "
                           "one. Placeholders: challenges 0x1122334455667788 / 0x99aabbccddeeff00, proof "
                           "0x0123456789abcdef, addresses 10.77.0.10:3300 (server) and 10.77.0.99:40000 (client).",
               frames={})
    for sname in ("k2-rbd-info-v1", "k1-rbd-info-v1", "k2-wrongkey"):
        flows, st = extract_tcp(os.path.join(captures, "pcap", sname + ".pcap"))
        conns = {}
        for k, segs in flows.items():
            if any((f & 0x12) == 0x02 for _, _, f, _ in segs):
                conns[k] = segs
        k0 = sorted(conns, key=lambda k: min(t for t, _, _, _ in conns[k]))[0]      # first connection (mon)
        cb = reassemble(conns[k0])[0]
        sb = reassemble(flows[(k0[2], k0[3], k0[0], k0[1])])[0]
        cf, cpos, _ = split_stream_frames(cb, 26, None, "", lambda f, fr: f.tag == T_REQ_MORE)
        sf, spos, _ = split_stream_frames(sb, 26, None, "", lambda f, fr: f.tag in (T_DONE, T_BAD))
        entry = dict(client_banner=cb[:26].hex(), server_banner=sb[:26].hex())
        entry["server_hello"] = frame_crc(1, [p8(sf[0].segs[0][0]) + entity_addr_v4("10.77.0.99", 40000, 0)]).hex()
        entry["client_hello"] = frame_crc(1, [p8(8) + entity_addr_v4("10.77.0.10", 3300, 0)]).hex()
        entry["auth_request"] = cb[cf[1].start:cf[1].end].hex()           # nothing secret in it (names only)
        entry["auth_reply_more"] = frame_crc(4, [pblob(p8(1) + p64(ph_sc))]).hex()
        auth = dec_authenticate(dec_blob_frame(cf[2].segs[0]))
        entry["auth_request_more"] = frame_crc(5, [pblob(
            p16(0x0100) + p8(3) + p64(ph_cc) + p64(ph_proof) + enc_ticket_blob(1, 0, b"") + p32(auth["other_keys"]))]).hex()
        if sf[-1].tag == T_BAD:
            entry["auth_bad_method"] = sb[sf[-1].start:sf[-1].end].hex()
        else:
            gid, mode, payload = dec_auth_done(sf[-1].segs[0])
            entry["auth_done_layout"] = dict(
                note="AUTH_DONE is not reproduced (encrypted blobs, ticket blobs). Lengths only.",
                mode=mode, payload_length=len(payload), frame_length=sf[-1].end - sf[-1].start,
                global_id_field="u64, non-zero")
        out["frames"][sname] = entry
    with open(os.path.join(d, "captured-scrubbed-frames.json"), "w") as f:
        json.dump(out, f, indent=1)
    if summary_path and os.path.exists(summary_path):
        emit_structure(d, summary_path)


def emit_structure(d, summary_path):
    """Aggregate per-connection structure (sizes, versions, counts) from the capture summary; no secrets."""
    data = json.load(open(summary_path))
    rows = {}
    for sname, conns in data.items():
        for c in conns:
            if c.get("kind") == "mon" and "authenticate" in c and "auth_ticket" in c:
                key = "mon|keytype=%d|mask=%#x|mode=%d" % (c["principal_key_type"], c["authenticate"]["other_keys"], c["mode"])
                rows.setdefault(key, set()).add(json.dumps(dict(
                    auth_msg_a_len=c["auth_ticket"]["msg_a_len"], auth_ticket_blob_len=c["auth_ticket"]["blob_len"],
                    auth_validity_s=c["auth_ticket"]["validity_s"], cbl_len=c["cbl_len"], extra_len=c["extra_len"],
                    connection_secret_len=c["connection_secret_len"]), sort_keys=True))
            if c.get("kind") == "authorizer" and "authorize" in c and "mode" in c:
                key = "authorizer|svc=%#x|keytype=%d|mode=%d" % (c["service_id"], c["ticket_key_type"], c["mode"])
                rows.setdefault(key, set()).add(json.dumps(dict(
                    first_proof_ct_len=c["authorize"]["first_ct_len"], second_proof_ct_len=c["authorize"]["second_ct_len"],
                    reply_v=c["reply_v"], connection_secret_len=c["connection_secret_len"]), sort_keys=True))
    ext = {}
    for sname, conns in data.items():
        for c in conns:
            for t in c.get("extra_tickets", []):
                key = "extra_ticket|svc=%#x|keytype=%d" % (t["service_id"], t["key_type"])
                ext.setdefault(key, set()).add(json.dumps(dict(msg_a_len=t["msg_a_len"], key_len=t["key_len"]), sort_keys=True))
    out = dict(description="Structure observed in the 39 captures (lengths and versions only, no values). Ticket blob "
                           "lengths vary a little between tickets because the opaque blob carries the name and "
                           "capability text; msg_a lengths are fixed per key type.",
               handshake_sizes={k: [json.loads(x) for x in sorted(v)] for k, v in sorted(rows.items())},
               extra_ticket_sizes={k: [json.loads(x) for x in sorted(v)] for k, v in sorted(ext.items())})
    with open(os.path.join(d, "captured-structure.json"), "w") as f:
        json.dump(out, f, indent=1)


# --------------------------------------------------------------------------------------
# offline vector checks
# --------------------------------------------------------------------------------------
def check_vectors(d, t):
    where = "vectors"
    # RFC 8009
    p = os.path.join(d, "rfc8009-aes256-cts-hmac-sha384-192.json")
    if os.path.exists(p):
        v = json.load(open(p))
        base = Key(2, bytes.fromhex(v["base_key"]))
        t.expect(base.ke(2).hex() == v["ke_usage2"], "vec.rfc8009_ke_derivation", where, "")
        t.expect(base.ki(2).hex() == v["ki_usage2"], "vec.rfc8009_ki_derivation", where, "")
        for x in v["vectors"]:
            pt = bytes.fromhex(x["plaintext"])
            ct = _t2_encrypt(base, 2, pt, bytes.fromhex(x["confounder"]))
            t.expect(ct.hex() == x["ciphertext"], "vec.rfc8009_encrypt", where, x["description"])
            t.expect(_t2_decrypt(base, 2, bytes.fromhex(x["ciphertext"])) == pt, "vec.rfc8009_decrypt", where, x["description"])
    else:
        t.fail("vec.rfc8009_file_present", where, p)
    # type 1
    p = os.path.join(d, "cipher-type1.json")
    v = json.load(open(p))
    k = Key(1, bytes.fromhex(v["key_secret"]))
    t.expect(v["iv"] == CBC_IV.hex(), "vec.type1_iv", where, "")
    for x in v["vectors"]:
        pt = bytes.fromhex(x["plaintext"])
        t.expect(k.encrypt(0, pt).hex() == x["ciphertext"], "vec.type1_encrypt", where, "")
        t.expect(k.decrypt(0, bytes.fromhex(x["ciphertext"])) == pt, "vec.type1_decrypt", where, "")
        t.expect(len(x["ciphertext"]) // 2 == 16 * (len(pt) // 16 + 1), "vec.type1_length_rule", where, "")
    for x in v["envelopes"]:
        t.expect(seal(k, x["usage"], bytes.fromhex(x["item"])).hex() == x["sealed_length_prefixed"], "vec.type1_envelope", where, "")
    # type 2
    v = json.load(open(os.path.join(d, "cipher-type2.json")))
    k = Key(2, bytes.fromhex(v["key_secret"]))
    for u, dd in v["derived"].items():
        t.expect(k.ke(int(u, 16)).hex() == dd["ke"] and k.ki(int(u, 16)).hex() == dd["ki"], "vec.type2_derived_keys", where, u)
    for x in v["vectors"]:
        pt = bytes.fromhex(x["plaintext"])
        ct = k.encrypt(x["usage"], pt, bytes.fromhex(x["confounder"]))
        t.expect(ct.hex() == x["ciphertext_with_mac"], "vec.type2_encrypt", where, "")
        t.expect(k.decrypt(x["usage"], ct) == pt, "vec.type2_decrypt", where, "")
        t.expect(len(ct) == 16 + len(pt) + 24, "vec.type2_length_rule", where, "")
        try:
            bad = bytearray(ct)
            bad[0] ^= 1
            k.decrypt(x["usage"], bytes(bad))
            t.fail("vec.type2_tamper_rejected", where, "")
        except CheckError:
            t.ok("vec.type2_tamper_rejected")
        try:
            k.decrypt(x["usage"] ^ 1, ct)
            t.fail("vec.type2_wrong_usage_rejected", where, "")
        except CheckError:
            t.ok("vec.type2_wrong_usage_rejected")
    for x in v["envelopes"]:
        t.expect(seal(k, x["usage"], bytes.fromhex(x["item"]), bytes.fromhex(x["confounder"])).hex() == x["sealed_length_prefixed"],
                 "vec.type2_envelope", where, "")
    # challenge proof
    v = json.load(open(os.path.join(d, "challenge-proof.json")))
    for x in v["vectors"]:
        k = Key(x["key_type"], bytes.fromhex(x["key_secret"]))
        sc, cc = int(x["server_challenge"], 16), int(x["client_challenge"], 16)
        t.expect(hex(challenge_proof(k, sc, cc)) == x["proof"], "vec.challenge_proof", where, "type %d" % x["key_type"])
        if x["key_type"] == 1:
            enc = bytes.fromhex(x["length_prefixed_ciphertext_36_bytes"])
            t.expect(enc[:4] == b"\x20\x00\x00\x00" and len(enc) == 36 and seal(k, 0, bytes.fromhex(x["blob"])) == enc,
                     "vec.challenge_proof_type1_intermediate", where, "")
            # the note's 2.8 worked example
            t.expect(enc.hex().startswith("200000005e4c58eba0ea931c") and x["proof"] == "0x4fadd85010bcad18",
                     "vec.note_2_8_worked_example_reproduced", where, "")
    # synthetic sessions through the same code path as the captures
    for p in sorted(glob.glob(os.path.join(d, "session-type*.json"))):
        v = json.load(open(p))
        name = os.path.basename(p)[:-5]
        k = Key.from_base64(v["keyring_key_base64"])
        keyrings = {v["entity"]: [k]}
        sess = Session(name, {}, keyrings, t, [])
        sess.lossy = False
        for i, c in enumerate(v["connections"]):
            cb, sb = bytes.fromhex(c["client_stream"]), bytes.fromhex(c["server_stream"])
            info = analyze_connection(sess, i, cb, sb, c["server_port"], t, 0.0, [], [])
            e = c["expect"]
            t.expect(info.get("mode") == e["mode"], "vec.session_mode", name, "%s" % info.get("mode"))
            if e["kind"] == "mon":
                got = {tk["service_id"]: tk["key"].secret.hex() for tk in sess.tickets if tk.get("gid") == e["global_id"]
                       and tk["service_id"] != ENT_AUTH}
                want = {x["service_id"]: x["session_key_secret"] for x in e["tickets"]}
                t.expect(got == want, "vec.session_ticket_keys", name, "")
                t.expect(info.get("connection_secret_len") == len(e["connection_secret"]) // 2, "vec.session_secret_len", name, "")
                auth_k = sess.auth_keys.get(e["global_id"])
                t.expect(auth_k is not None and auth_k.secret.hex() == e["auth_session_key_secret"], "vec.session_auth_key", name, "")
            else:
                t.expect(info.get("connection_secret_len") == len(e["connection_secret"]) // 2, "vec.session_secret_len", name, "")
    # scrubbed captured frames
    p = os.path.join(d, "captured-scrubbed-frames.json")
    if os.path.exists(p):
        v = json.load(open(p))
        for sname, e in v["frames"].items():
            for key in ("server_hello", "client_hello", "auth_request", "auth_reply_more", "auth_request_more", "auth_bad_method"):
                if key in e:
                    try:
                        f = parse_crc_frame(bytes.fromhex(e[key]), 0)
                        t.ok("vec.scrubbed_frame_crc_and_shape")
                        if key == "auth_request":
                            m, modes, pl = dec_auth_request(f.segs[0])
                            t.expect(m == 2 and modes == [1] and pl[:1] == b"\x0a", "vec.scrubbed_auth_request_fields", sname, str(modes))
                        if key == "auth_request_more":
                            a = dec_authenticate(dec_blob_frame(f.segs[0]))
                            t.expect(a["v"] == 3 and a["req_type"] == 0x100 and a["trailing"] == 0, "vec.scrubbed_authenticate_fields", sname, "")
                        if key == "auth_bad_method":
                            m, r, am, amo = dec_auth_bad_method(f.segs[0])
                            t.expect(r == -13, "vec.scrubbed_bad_method_minus13", sname, str(r))
                    except CheckError as ex:
                        t.fail("vec.scrubbed_frame_crc_and_shape", sname + ":" + key, str(ex))
            t.expect(e["client_banner"][:16] == b"ceph v2\n".hex(), "vec.scrubbed_banner", sname, "")



if __name__ == "__main__":
    sys.exit(main())
