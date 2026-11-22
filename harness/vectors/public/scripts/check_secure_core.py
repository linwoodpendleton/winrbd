#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
check_secure_core.py - the secure-mode capture set of module vectors-sec (harness/vectors/public/secure/): what the winrbd core itself put on the
wire in msgr2 SECURE mode (AES-128-GCM framing) against a real Ceph v20.2.5 monitor and OSDs, one session per cephx key type, and what the servers
answered when they refused the mode that was offered. An independent checker written from docs/spec/msgr2-secure-mode.md and cephx.md (python3, the
`cryptography` package; the frame, cephx and TCP code is the one of harness/tools/secure_check.py, which is written from the notes too; nothing of
the core is used). No cluster needed.

    python3 -I check_secure_core.py [check] [--dir DIR]       verify the committed vectors      (ctest: vectors_secure_check)
    python3 -I check_secure_core.py selftest [--dir DIR]      feed `check` damaged copies of them (ctest: vectors_secure_selftest)
    python3 -I check_secure_core.py extract --work W --out D  build the vectors from a capture    (capture_secure.sh, inside the lab VM)
    python3 -I check_secure_core.py reindex [--dir DIR]       rewrite INDEX.json after a hand edit of README.md

What a session file holds (sessions/<key>.json): per connection the plaintext handshake bytes of both directions (banner, HELLO, the auth frames, up to and
including AUTH_DONE; the transcripts of the pre-auth signature), the connection secret and the session key that the cephx exchange handed over, and every
secure frame of both directions: tag, alignments, the PLAINTEXT of every segment, the wire bytes (or, for the two 1 MiB data frames of the OSD
connection, the wire size and SHA-256, with the data segment given as the pattern wr-rbd wrote: the bytes of the real frame are then re-derived by
encrypting the pattern, and must hash to what the wire had).

check, in this order:
  - the file list against INDEX.json (size and SHA-256), no stray file, no symbolic link, a size budget, no key-looking text outside keys/, no key of a
    regular lab user, no address outside the lab nets (10.77.0.x, 192.0.2.x), no home directory path;
  - the keyrings are throwaway users of the capture (client.vec-sec-k2: type 2 = aes256k; client.vec-sec-k1: type 1 = aes) and nothing else;
  - per connection the cephx exchange is replayed from the handshake bytes with the published key (challenge proof, ticket reply, connection-secret blob or
    the OSD's authorizer reply, in order: the monitor first, whose ticket the OSD connections present) and the secret and session key it yields are the
    recorded ones; the secret is 64 bytes, differs from every other connection's, and the mode the server picked is secure;
  - the banners: the client advertised REVISION_1 and nothing else (supported 1, required 0), no compression frame crossed in either direction, and the
    server went on to SERVER_IDENT: the answer to sec.md 6.5 (REVISION_1 without COMPRESSION is accepted by a real server);
  - the pre-auth signature of both directions: HMAC-SHA256 of the received transcript under the session key, the first secure frame of each direction;
  - every frame of both directions: encrypted again with the recorded secret by the checker's own sender (nonces from the two seeds, one per GCM
    operation, in wire order) it gives exactly the recorded wire bytes (or the recorded size and SHA-256); the recorded wire bytes decrypted with a library
    give the recorded plaintext; the structure of sec.md 2.8 (preamble CRC, alignments, zero padding, late_status, wire size formula, operation count);
  - the frame order after authentication (AUTH_SIGNATURE, then CLIENT_IDENT / SERVER_IDENT, then messages) and the coverage the module promises: both key
    types, a monitor and OSD connections, a 1 MiB write and a 1 MiB read reply, frames of one and two GCM operations
    (three operations do not occur in real traffic: segment 0 is longer than 48 bytes only in single-segment frames; ../../secure has them synthetic);
  - the refusals (refusals.json): the server's AUTH_BAD_METHOD frame decoded from its bytes, its `result` (sec.md 6.4), the allowed modes against the server's
    setting and the client's offer, for a monitor and for an OSD, in both directions (secure only / crc only), for both key types.
"""
import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.normpath(os.path.join(HERE, "..", "..", "..", "tools"))
DEFAULT_DIR = os.path.normpath(os.path.join(HERE, "..", "secure"))

try:
    import cryptography  # noqa: F401
except ImportError:  # the checker needs it; a missing package is a skip, never a pass
    sys.stderr.write("SKIP: check_secure_core.py needs the 'cryptography' package\n")
    sys.exit(77)
sys.path.insert(0, TOOLS)
import secure_check as sc  # noqa: E402

BUDGET = 250_000                   # bytes of the whole tree
WIRE_LIMIT = 16384                 # a frame whose wire is larger than this is kept as size + SHA-256 (its big segments as a pattern)
BIG_SEG = 4096                     # a segment this long may be given as a pattern
M64 = (1 << 64) - 1
ALIGNS = (8, 8, 8, 4096)           # sec.md 2.8: the alignment of segments 0..3 of a stock client / our core
SECRET_LEN = 64
MODE_NAMES = {1: "crc", 2: "secure"}
EOPNOTSUPP = 95
SESSIONS = ("k2", "k1")
ENTITY = {"k2": "client.vec-sec-k2", "k1": "client.vec-sec-k1"}
KEYTYPE = {"k2": 2, "k1": 1}
LAB_ADDR = re.compile(r"^(10\.77\.0\.\d{1,3}|192\.0\.2\.\d{1,3})$")


# ---- results ----------------------------------------------------------------------------------------------------------------------------

class Chk:
    """Counts the checks and keeps the problems; a problem is never raised, so one run shows all of them."""

    def __init__(self):
        self.passed = 0
        self.problems = []
        self.cov = {}
        self.pairs = set()      # the (key, nonce seed) pairs of every connection of the set

    def ok(self, cond, msg):
        if cond:
            self.passed += 1
        else:
            self.problems.append(msg)
        return bool(cond)

    def fail(self, msg):
        self.problems.append(msg)

    def cover(self, key, n=1):
        self.cov[key] = self.cov.get(key, 0) + n


class ScGuard:
    """Runs code of secure_check.py, which records its failures in its own global results: they become problems here."""

    def __init__(self, chk, what):
        self.chk, self.what = chk, what

    def __enter__(self):
        self.before = {g: list(v) for g, v in sc.R.failures.items()}
        self.f0 = sc.R.total[1]
        self.p0 = sc.R.total[0]
        return self

    def __exit__(self, et, ev, tb):
        self.chk.passed += sc.R.total[0] - self.p0
        if sc.R.total[1] != self.f0:
            for g, v in sc.R.failures.items():
                for m in v[len(self.before.get(g, [])):]:
                    self.chk.fail("%s: %s: %s" % (self.what, g, m))
            if not any(True for g, v in sc.R.failures.items() if len(v) > len(self.before.get(g, []))):
                self.chk.fail("%s: %d failed checks of the frame / cephx code" % (self.what, sc.R.total[1] - self.f0))
        if et is not None and issubclass(et, (sc.ProtoError, struct.error, ValueError, IndexError, KeyError, TypeError)):
            self.chk.fail("%s: %s: %s" % (self.what, et.__name__, ev))
            return True
        return False


# ---- the patterns of wr-rbd (a function of the absolute byte offset; written here independently of the C code, as in check_imgio.py) -------------

def mix64(x):
    x = (x + 0x9e3779b97f4a7c15) & M64
    x = ((x ^ (x >> 30)) * 0xbf58476d1ce4e5b9) & M64
    x = ((x ^ (x >> 27)) * 0x94d049bb133111eb) & M64
    return x ^ (x >> 31)


def pattern(kind, arg, off, n):
    if kind == "zero":
        return bytes(n)
    if kind == "byte":
        return bytes([arg & 255]) * n
    if kind == "rand":
        out = bytearray()
        for w in range(off >> 3, (off + n + 7) >> 3):
            out += struct.pack("<Q", mix64((arg * 0x2545f4914f6cdd1d + w) & M64))
        s = off & 7
        return bytes(out[s:s + n])
    raise ValueError("pattern " + kind)


def parse_size(s):
    m = re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)([KMGT]?)", s)
    if not m:
        raise ValueError("size " + s)
    return int(m.group(1), 0) << {"": 0, "K": 10, "M": 20, "G": 30, "T": 40}[m.group(2)]


def script_patterns(lines):
    """The (kind, arg, off, len) of every write / verify line of a wr-rbd shell script."""
    out = []
    for ln in lines:
        w = ln.split()
        if len(w) >= 5 and w[0] in ("write", "verify") and w[3] == "--pattern":
            kind, _, a = w[4].partition(":")
            out.append((kind, int(a or "0", 0), parse_size(w[1]), parse_size(w[2])))
    return out


def seg_bytes(s):
    """A segment of a frame record: a hex string, or the pattern object of an elided data segment."""
    if isinstance(s, str):
        return bytes.fromhex(s)
    if isinstance(s, dict):
        return pattern(s["pattern"], s["arg"], s["off"], s["len"])
    raise ValueError("segment form")


def seg_len(s):
    return len(s) // 2 if isinstance(s, str) else s["len"]


# ---- JSON output: one frame per line -------------------------------------------------------------------------------------------------------------

def jdump(obj, depth=0, maxdepth=3):
    pad = " " * (depth + 1)
    if isinstance(obj, dict) and depth < maxdepth:
        items = ['%s%s: %s' % (pad, json.dumps(k), jdump(v, depth + 1, maxdepth)) for k, v in obj.items()]
        return "{\n" + ",\n".join(items) + "\n" + " " * depth + "}"
    if isinstance(obj, list) and depth < maxdepth and obj and not all(isinstance(x, (int, float, str)) for x in obj):
        items = [pad + jdump(v, depth + 1, maxdepth) for v in obj]
        return "[\n" + ",\n".join(items) + "\n" + " " * depth + "]"
    return json.dumps(obj, separators=(", ", ": "))


def write_json(path, obj, maxdepth=5):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(jdump(obj, 0, maxdepth) + "\n")


def sha(b):
    return hashlib.sha256(b).hexdigest()


# ---- the cephx exchange of one connection, from the handshake bytes (shared by extract and check) --------------------------------------------------

class Session:
    """What one capture session learned so far: the keyring, the AUTH session key and the service tickets the monitor handed out."""

    def __init__(self, name, keydir):
        self.an = sc.Analysis(name, sc.KeyStore([keydir]))
        self.secrets = set()


def split_frames(buf, pos, stop_tags):
    """Crc frames of a plaintext handshake from pos to the end of buf (a frame with a tag in stop_tags must be the last)."""
    frames = []
    while pos < len(buf):
        f = sc.parse_crc_frame(buf, pos)
        frames.append(f)
        pos = f.end
        if f.tag in stop_tags and pos != len(buf):
            raise sc.ProtoError("bytes after %s" % f.name())
    return frames, pos


def derive(sess, c2s, s2c, chk, what):
    """Replay the handshake of one connection (the bytes before the first secure frame of each direction). Returns a dict with the offered modes, the
    mode the server picked, the secret and the session key, or None when something failed (a problem is recorded)."""
    res = {}
    with ScGuard(chk, what):
        cb_end, csup, creq = sc.check_banner(c2s, "client", what)
        sb_end, ssup, sreq = sc.check_banner(s2c, "server", what)
        res["client_banner"] = (csup, creq)
        res["server_banner"] = (ssup, sreq)
        sframes, _ = split_frames(s2c, sb_end, (sc.T_AUTH_DONE, sc.T_AUTH_BAD_METHOD))
        cframes, _ = split_frames(c2s, cb_end, ())
        if not sframes or sframes[-1].tag != sc.T_AUTH_DONE:
            raise sc.ProtoError("the server's handshake does not end in AUTH_DONE")
        if not cframes or cframes[0].tag != sc.T_HELLO or sframes[0].tag != sc.T_HELLO:
            raise sc.ProtoError("no HELLO")
        if any(f.n != 1 for f in cframes + sframes):
            raise sc.ProtoError("an auth frame with several segments")
        req = next((f for f in cframes if f.tag == sc.T_AUTH_REQUEST), None)
        if req is None:
            raise sc.ProtoError("no AUTH_REQUEST")
        ar = sc.dec_auth_request(req.segs[0])
        done = sc.dec_auth_done(sframes[-1].segs[0])
        res["method"], res["offered_modes"], res["con_mode"] = ar["method"], ar["modes"], done["con_mode"]
        res["global_id"] = done["global_id"]
        res["c2s_frames"] = [f.name() for f in cframes]
        res["s2c_frames"] = [f.name() for f in sframes]
        pl = ar["payload"]
        rm = [f for f in sframes if f.tag == sc.T_AUTH_REPLY_MORE]
        qm = [f for f in cframes if f.tag == sc.T_AUTH_REQUEST_MORE]
        if len(rm) != 1 or len(qm) != 1:
            raise sc.ProtoError("expected one challenge round, saw %d / %d" % (len(rm), len(qm)))
        secret = sess_key = None
        an = sess.an
        if pl and pl[0] == 10:
            res["kind"] = "mon"
            rd = sc.Rd(pl)
            rd.u8()
            etype = rd.u32()
            eid = rd.blob()
            rd.u64()
            res["entity"] = "client." + eid.decode("utf8", "replace")
            chal = sc.Rd(sc.dec_blob_frame(rm[0].segs[0])["payload"])
            chal.u8()
            server_challenge = chal.u64()
            qrd = sc.Rd(sc.dec_blob_frame(qm[0].segs[0])["payload"])
            qrd.u16()
            qrd.u8()
            client_challenge = qrd.u64()
            proof = qrd.u64()
            sc.dec_ticket_blob(qrd)
            res["other_keys"] = qrd.u32()
            matched = None
            for _lab, k in an.keys.for_entity(res["entity"]):
                if sc.cephx_proof(k, server_challenge, client_challenge) == proof:
                    matched = k
                    break
            if etype != 8 or matched is None:
                raise sc.ProtoError("the challenge proof matches no published key of %s" % res["entity"])
            chk.passed += 1
            an.principal = matched
            res["key_type"] = matched.type
            d = sc.dec_mon_auth_done_payload(done["payload"], matched, an.auth_key)
            if d.get("status") != 0 or d["auth_ticket"] is None:
                raise sc.ProtoError("the monitor's reply carries an error")
            sess_key = d["auth_ticket"].key
            an.auth_key = sess_key
            for t in d["extra"]:
                an.tickets.append(t)
            res["extra_services"] = sorted(t.service for t in d["extra"])
            secret = d["secret"]
        else:
            res["kind"] = "osd"
            a1 = sc.dec_authorizer(pl)
            t = an.find_ticket(a1["ticket_bytes"])
            if t is None:
                raise sc.ProtoError("the authorizer's ticket was not handed out by an earlier monitor reply of the session")
            res["service_id"] = a1["service_id"]
            sess_key = t.key
            res["key_type"] = t.key.type
            _v, prd = sc.open_envelope(t.key, sc.USAGE_AUTHORIZE, a1["proof"])
            prd.u8()
            nonce = prd.u64()
            chal_ct = sc.dec_blob_frame(rm[0].segs[0])["payload"]
            _v, crd = sc.open_envelope(t.key, sc.USAGE_CHALLENGE, chal_ct)
            crd.u8()
            server_challenge = crd.u64()
            a2 = sc.dec_authorizer(sc.dec_blob_frame(qm[0].segs[0])["payload"])
            _v, prd2 = sc.open_envelope(t.key, sc.USAGE_AUTHORIZE, a2["proof"])
            prd2.u8()
            n2 = prd2.u64()
            have, plus1 = prd2.u8(), prd2.u64()
            chk.ok(n2 == nonce and have == 1 and plus1 == (server_challenge + 1) & M64, "%s: the second authorizer is not the answer to the challenge" % what)
            ap = done["payload"]
            inner = sc.Rd(ap)
            ct = inner.blob()
            if inner.left() == 0:
                _v, drd = sc.open_envelope(t.key, sc.USAGE_AUTH_REPLY, ct)
            else:
                _v, drd = sc.open_envelope(t.key, sc.USAGE_AUTH_REPLY, ap)
            rv = drd.u8()
            n1 = drd.u64()
            chk.ok(n1 == (nonce + 1) & M64, "%s: the authorizer reply does not carry nonce+1" % what)
            if rv >= 2:
                secret = drd.take(drd.u32())
            else:
                secret = b""
            chk.ok(drd.left() == 0, "%s: bytes after the authorizer reply" % what)
            chk.ok(rv == (2 if done["con_mode"] == sc.MODE_SECURE else 1), "%s: authorizer reply version %d for mode %d" % (what, rv, done["con_mode"]))
        res["secret"] = secret
        res["session_key"] = sess_key
    if "secret" not in res:
        return None
    return res


# ---- the frames of one direction ------------------------------------------------------------------------------------------------------------------

def wire_size_and_ops(lens):
    return sc.secure_wire_size(list(lens))


def frame_plain_check(chk, what, fr, f):
    """The structure rules of sec.md 2.8 on a parsed secure frame (secure_check's Frame) against the record."""
    n = len(fr["segs"])
    chk.ok(f.tag == fr["tag"] and f.n == n, "%s: tag / segment count differ from the record" % what)
    chk.ok(list(f.lens[:n]) == [seg_len(s) for s in fr["segs"]], "%s: segment lengths differ from the record" % what)
    chk.ok(list(f.aligns[:n]) == list(fr["aligns"]), "%s: alignments differ from the record" % what)
    chk.ok(f.flags == 0 and f.reserved == 0, "%s: preamble flags / reserved byte not zero" % what)
    chk.ok(f.pad_ok, "%s: nonzero padding" % what)
    chk.ok(1 <= f.tag <= 22, "%s: frame tag %d outside 1..22" % (what, f.tag))
    chk.ok(all(f.lens[i] == 0 and f.aligns[i] == 0 for i in range(n, 4)), "%s: unused segment slot not zero" % what)
    if n > 1:
        chk.ok(f.late == 0x0e, "%s: late_status %s, want 0x0e" % (what, f.late))
        chk.ok(f.lens[n - 1] > 0, "%s: the last segment of a multi-segment frame is empty" % what)
    total, nops = wire_size_and_ops(f.lens[:n])
    chk.ok(total == len(f.wire) and nops == len(f.ops), "%s: wire size / operation count do not follow the table of sec.md 5.1" % what)


def check_direction(chk, what, frames, key16, seed, direction):
    """Walk the frames of one direction. Returns the number of GCM operations used."""
    enc = sc.GcmDir(key16, seed)
    dec = sc.GcmDir(key16, seed)
    tags = []
    for i, fr in enumerate(frames):
        w = "%s %s frame %d" % (what, direction, i)
        segs = [seg_bytes(s) for s in fr["segs"]]
        n = len(segs)
        chk.ok(n >= 1 and len(fr["aligns"]) == n, "%s: shape" % w)
        chk.ok(all(a == ALIGNS[k] for k, a in enumerate(fr["aligns"])), "%s: alignments %s, want %s" % (w, fr["aligns"], ALIGNS[:n]))
        for k, s in enumerate(fr["segs"]):
            if isinstance(s, dict):
                chk.ok(s["len"] > BIG_SEG and k == n - 1, "%s: an elided segment must be the long last one" % w)
        with ScGuard(chk, w):
            out = sc.assemble_secure(fr["tag"], segs, fr["aligns"], enc)
        chk.ok(len(out) == fr["wire_len"] and sha(out) == fr["wire_sha256"],
               "%s: encrypting the recorded plaintext with the recorded secret does not give the recorded wire bytes" % w)
        if "wire" in fr:
            wire = bytes.fromhex(fr["wire"])
            chk.ok(wire == out, "%s: recorded wire bytes differ from the re-encryption" % w)
            chk.ok(len(wire) == fr["wire_len"] and sha(wire) == fr["wire_sha256"], "%s: wire size / hash differ from the record" % w)
            f = None
            with ScGuard(chk, w):
                f = sc.parse_secure_frame(wire, 0, dec)       # a library decrypt of the recorded wire bytes
            if f is not None:
                chk.ok(f.end == len(wire), "%s: bytes left after the frame" % w)
                chk.ok([bytes(s) for s in f.segs[:n]] == segs, "%s: decrypted segments differ from the recorded plaintext" % w)
                frame_plain_check(chk, w, fr, f)
        else:
            chk.ok(fr["wire_len"] > WIRE_LIMIT, "%s: a frame of %d wire bytes should carry its bytes" % (w, fr["wire_len"]))
            for _ in range(sc.secure_wire_size([len(x) for x in segs])[1]):
                dec.step()                                      # keep the two nonce streams in step
        tags.append(fr["tag"])
    return enc, tags


# ---- one session file -------------------------------------------------------------------------------------------------------------------------------

def check_session(chk, root, name, ses, index):
    what = "session " + name
    kp = os.path.join(root, "keys", "client.vec-sec-%s.keyring" % name)
    keydir = os.path.dirname(kp)
    sess = Session(name, keydir)
    chk.ok(os.path.exists(kp), "%s: keyring file missing" % what)
    rings = sc.parse_keyring(kp) if os.path.exists(kp) else {}
    chk.ok(list(rings) == [ENTITY[name]], "%s: the keyring must hold exactly %s" % (what, ENTITY[name]))
    chk.ok(all(k.type == KEYTYPE[name] for k in rings.values()), "%s: the keyring's key type is not %d" % (what, KEYTYPE[name]))
    chk.ok(ses.get("name") == name and ses.get("entity") == ENTITY[name] and ses.get("key_type") == KEYTYPE[name], "%s: header fields" % what)
    conns = ses.get("conns", [])
    chk.ok(len(conns) >= 2, "%s: needs a monitor and at least one OSD connection" % what)
    kinds = []
    for ci, c in enumerate(conns):
        w = "%s conn %s" % (what, c.get("id"))
        hs_c, hs_s = bytes.fromhex(c["hs_c2s"]), bytes.fromhex(c["hs_s2c"])
        d = derive(sess, hs_c, hs_s, chk, w)
        if d is None:
            continue
        kinds.append(d["kind"])
        chk.ok(d["kind"] == c["kind"], "%s: kind %s, derived %s" % (w, c["kind"], d["kind"]))
        chk.ok(d["offered_modes"] == c["offered_modes"] and d["con_mode"] == c["con_mode"] and d["global_id"] == c["global_id"],
               "%s: offered modes / picked mode / global id differ from the handshake bytes" % w)
        if d["kind"] == "mon":   # the monitor's AUTH session key is of the user's type; the service tickets follow the cluster's rotating key type (aes in this lab)
            chk.ok(d["key_type"] == KEYTYPE[name], "%s: the session key type is %d, expected %d" % (w, d["key_type"], KEYTYPE[name]))
        else:
            chk.ok(d["key_type"] in (1, 2) and len(d["session_key"].secret) == (16 if d["key_type"] == 1 else 32), "%s: the ticket key type and length disagree" % w)
        chk.ok(d["con_mode"] == sc.MODE_SECURE and d["offered_modes"] == [sc.MODE_SECURE], "%s: offered %s, picked %s (want [2] and 2)" % (w, d["offered_modes"], d["con_mode"]))
        secret = d["secret"]
        chk.ok(secret is not None and len(secret) == SECRET_LEN, "%s: the connection secret is %s bytes, want %d" % (w, None if secret is None else len(secret), SECRET_LEN))
        if secret is None or len(secret) != SECRET_LEN:
            continue
        chk.ok(secret.hex() == c["secret"], "%s: the secret derived from the handshake is not the recorded one" % w)
        chk.ok(d["session_key"].secret.hex() == c["session_key"], "%s: the session key derived from the handshake is not the recorded one" % w)
        chk.ok(len(set(secret)) > 20 and sha(secret) not in sess.secrets, "%s: the secret repeats or looks degenerate" % w)
        sess.secrets.add(sha(secret))
        # 6.5: REVISION_1 only, no compression
        csup, creq = d["client_banner"]
        chk.ok(csup == 1 and creq == 0, "%s: client banner supported 0x%x required 0x%x, want 0x1 / 0x0 (REVISION_1 without COMPRESSION)" % (w, csup, creq))
        chk.ok(d["server_banner"][0] & 1 == 1, "%s: the server does not support REVISION_1" % w)
        key16, seed_a, seed_b = sc.split_secret(secret)
        # one key with two nonce streams, kept apart only by their seeds: the seeds must differ, and no (key, seed) pair may come back on another connection
        chk.ok(seed_a != seed_b, "%s: the two nonce seeds of the secret are equal" % w)
        for pair in ((key16, seed_a), (key16, seed_b)):
            chk.ok(pair not in chk.pairs, "%s: a (key, nonce seed) pair of the set is used on two connections" % w)
            chk.pairs.add(pair)
        fr_c, fr_s = c["frames"]["c2s"], c["frames"]["s2c"]
        enc_c, tags_c = check_direction(chk, w, fr_c, key16, seed_b, "c2s")
        enc_s, tags_s = check_direction(chk, w, fr_s, key16, seed_a, "s2c")
        # the frame order after authentication, and no compression frames: the server accepted a client that did not offer them
        want_c, want_s = [sc.T_AUTH_SIGNATURE, 8], [sc.T_AUTH_SIGNATURE, 9]
        chk.ok(tags_c[:2] == want_c, "%s: client frames start %s, want AUTH_SIGNATURE, CLIENT_IDENT" % (w, tags_c[:2]))
        chk.ok(tags_s[:2] == want_s, "%s: server frames start %s, want AUTH_SIGNATURE, SERVER_IDENT" % (w, tags_s[:2]))
        chk.ok(not any(t in (21, 22) for t in tags_c + tags_s), "%s: a COMPRESSION frame crossed" % w)
        chk.ok(all(t in (sc.T_AUTH_SIGNATURE, 8, 9, 17, 18, 19, 20) for t in tags_c + tags_s), "%s: an unexpected frame tag" % w)
        # the pre-auth signature: each side signs what it received, under the session key
        keyb = d["session_key"].secret
        if fr_c and fr_s and fr_c[0]["tag"] == sc.T_AUTH_SIGNATURE and fr_s[0]["tag"] == sc.T_AUTH_SIGNATURE:
            csig, ssig = seg_bytes(fr_c[0]["segs"][0]), seg_bytes(fr_s[0]["segs"][0])
            chk.ok(len(csig) == 32 and hmac.compare_digest(csig, hmac.new(keyb, hs_s, hashlib.sha256).digest()),
                   "%s: the client's AUTH_SIGNATURE is not HMAC-SHA256(session key, the bytes it received)" % w)
            chk.ok(len(ssig) == 32 and hmac.compare_digest(ssig, hmac.new(keyb, hs_c, hashlib.sha256).digest()),
                   "%s: the server's AUTH_SIGNATURE is not HMAC-SHA256(session key, the bytes it received)" % w)
            chk.ok(not hmac.compare_digest(csig, hmac.new(keyb, hs_s[26:], hashlib.sha256).digest()), "%s: the transcript must include the banner" % w)
            chk.cover("signatures_verified")
        # coverage
        for fr in fr_c + fr_s:
            segs = fr["segs"]
            _t, nops = sc.secure_wire_size([seg_len(s) for s in segs])
            chk.cover("frames_%dop" % nops)
            if len(segs) == 1 and seg_len(segs[0]) > 48:
                chk.cover("frames_part2_only")
            if len(segs) > 1:
                chk.cover("frames_multiseg")
            chk.cover("frames_total")
            if any(isinstance(s, dict) for s in segs):
                chk.cover("big_data_%s" % ("c2s" if fr in fr_c else "s2c"))
                chk.ok(sum(seg_len(s) for s in segs) >= (1 << 20), "%s: the elided frame is shorter than 1 MiB" % w)
        chk.cover("conns_%s" % c["kind"])
        chk.cover("conns_secure")
        chk.cover("messages_c2s", sum(1 for t in tags_c if t == 17))
        chk.cover("messages_s2c", sum(1 for t in tags_s if t == 17))
        chk.ok(c.get("trailing_c2s", 0) == 0 and c.get("trailing_s2c", 0) == 0, "%s: unparsed bytes after the last frame" % w)
    chk.ok(kinds[:1] == ["mon"] and kinds.count("mon") >= 1 and kinds.count("osd") >= 1, "%s: the connections are not a monitor first and then OSDs: %s" % (what, kinds))
    chk.cover("sessions")
    chk.cover("key_type_%d" % KEYTYPE[name])


# ---- the refusals (sec.md 6.4) ------------------------------------------------------------------------------------------------------------------------

def check_refusals(chk, rf):
    seen = set()
    for a in rf.get("attempts", []):
        w = "refusal " + a.get("name", "?")
        c2s, s2c = bytes.fromhex(a["c2s"]), bytes.fromhex(a["s2c"])
        with ScGuard(chk, w):
            cb, csup, creq = sc.check_banner(c2s, "client", w)
            sb, ssup, sreq = sc.check_banner(s2c, "server", w)
            cframes, cpos = split_frames(c2s, cb, ())
            sframes, spos = split_frames(s2c, sb, (sc.T_AUTH_BAD_METHOD,))
            chk.ok(csup == 1 and creq == 0, "%s: client banner" % w)
            chk.ok(sframes and sframes[-1].tag == sc.T_AUTH_BAD_METHOD and sframes[-1].n == 1, "%s: the server's answer is not a single-segment AUTH_BAD_METHOD" % w)
            req = next((f for f in cframes if f.tag == sc.T_AUTH_REQUEST), None)
            chk.ok(req is not None and len(cframes) == 2 and cframes[0].tag == sc.T_HELLO, "%s: the client sent HELLO and one AUTH_REQUEST and then nothing" % w)
            if req is None or not sframes or sframes[-1].tag != sc.T_AUTH_BAD_METHOD:
                continue
            ar = sc.dec_auth_request(req.segs[0])
            bm = sc.dec_auth_bad_method(sframes[-1].segs[0])
            pl = ar["payload"]
            kind = "mon" if pl and pl[0] == 10 else "osd"
            chk.ok(kind == a["daemon"], "%s: the refusing daemon is a %s, the record says %s" % (w, kind, a["daemon"]))
            chk.ok(ar["method"] == 2 and bm["method"] == 2, "%s: auth method is not cephx (2)" % w)
            chk.ok(ar["modes"] == a["client_offers"], "%s: the client offered %s, the record says %s" % (w, ar["modes"], a["client_offers"]))
            chk.ok(bm["result"] == a["result"] == -EOPNOTSUPP, "%s: result %d, recorded %d, expected -%d (EOPNOTSUPP)" % (w, bm["result"], a["result"], EOPNOTSUPP))
            chk.ok(bm["allowed_methods"] == a["allowed_methods"] and bm["allowed_modes"] == a["allowed_modes"], "%s: allowed methods / modes differ from the record" % w)
            allowed_set = {"secure-only": [2], "crc-only": [1]}[a["server_setting"]]
            chk.ok(sorted(bm["allowed_modes"]) == allowed_set, "%s: the server allows %s but the setting is %s" % (w, bm["allowed_modes"], a["server_setting"]))
            chk.ok(not (set(ar["modes"]) & set(bm["allowed_modes"])), "%s: refused although the offer %s overlaps the allowed modes %s" % (w, ar["modes"], bm["allowed_modes"]))
            chk.ok(bm["allowed_methods"] == [2], "%s: allowed methods %s, want [2] (cephx)" % (w, bm["allowed_methods"]))
            chk.ok(cpos == len(c2s) and spos == len(s2c), "%s: bytes after the refusal" % w)
            chk.ok(a["key_type"] == KEYTYPE[a["key"]], "%s: key type" % w)
            seen.add((a["daemon"], a["server_setting"], a["key"]))
            chk.cover("refusals")
    want = {(d, s, k) for d in ("mon", "osd") for s in ("secure-only", "crc-only") for k in SESSIONS}
    chk.ok(seen == want, "refusals: missing combinations %s" % sorted(want - seen))
    chk.ok(rf.get("result_name") == "EOPNOTSUPP" and rf.get("result_value") == -EOPNOTSUPP, "refusals: the recorded result code is not -95 (EOPNOTSUPP)")


# ---- the file tree ----------------------------------------------------------------------------------------------------------------------------------------

KEY_B64 = re.compile(r"AQ[A-Za-z0-9+/]{20,}={0,2}")
HEX_RUN = re.compile(r"[0-9a-f]{32,}")
IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def list_tree(root):
    out = []
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for n in sorted(files + [x for x in dirs if os.path.islink(os.path.join(d, x))]):
            out.append(os.path.relpath(os.path.join(d, n), root))
    return out


def check_tree(chk, root):
    ip = os.path.join(root, "INDEX.json")
    if not chk.ok(os.path.isfile(ip), "INDEX.json is missing"):
        return None
    idx = json.load(open(ip))
    files = [f for f in list_tree(root) if f != "INDEX.json"]
    listed = idx.get("files", {})
    for f in files:
        p = os.path.join(root, f)
        if os.path.islink(p):
            chk.fail("%s is a symbolic link" % f)
            continue
        if f not in listed:
            chk.fail("stray file %s (not in INDEX.json)" % f)
            continue
        data = open(p, "rb").read()
        chk.ok(len(data) == listed[f]["size"] and sha(data) == listed[f]["sha256"], "%s differs from INDEX.json (size or SHA-256)" % f)
    for f in listed:
        chk.ok(f in files, "%s is listed in INDEX.json but missing" % f)
    total = sum(os.path.getsize(os.path.join(root, f)) for f in files if os.path.isfile(os.path.join(root, f)))
    chk.ok(total <= BUDGET, "the tree is %d bytes, over the budget of %d" % (total, BUDGET))
    for f in files:
        p = os.path.join(root, f)
        if os.path.islink(p) or not os.path.isfile(p):
            continue
        txt = open(p, "rb").read().decode("utf8", "replace")
        if not f.startswith("keys/"):
            chk.ok(not KEY_B64.search(txt) and "key =" not in txt and "key=" not in txt.replace("session_key=", ""), "%s holds key-looking text" % f)
        if not f.endswith(".json") and not f.startswith("keys/"):
            chk.ok(not HEX_RUN.search(txt), "%s holds a long hex string" % f)
        for m in IPV4.finditer(txt):
            a = m.group(0)
            if not LAB_ADDR.match(a) and not f.endswith(".keyring"):
                chk.fail("%s holds the address %s, outside the lab nets" % (f, a))
        for bad in ("/home/", "/Users/", "client.admin", "client.winrbd", "winrbd-aes"):
            chk.ok(bad not in txt, "%s mentions %s" % (f, bad))
    return idx


def check_dir(root):
    chk = Chk()
    sc.R.counts.clear()
    sc.R.failures.clear()
    sc.NEG_DONE.clear()
    sc.SECRET_DIGESTS.clear()
    idx = check_tree(chk, root)
    if idx is None:
        return chk
    for name in SESSIONS:
        p = os.path.join(root, "sessions", name + ".json")
        if not chk.ok(os.path.isfile(p), "sessions/%s.json is missing" % name):
            continue
        try:
            ses = json.load(open(p))
            check_session(chk, root, name, ses, idx)
        except (KeyError, ValueError, TypeError, IndexError, sc.ProtoError) as e:
            chk.fail("sessions/%s.json: %s: %s" % (name, type(e).__name__, e))
    p = os.path.join(root, "refusals.json")
    if chk.ok(os.path.isfile(p), "refusals.json is missing"):
        try:
            check_refusals(chk, json.load(open(p)))
        except (KeyError, ValueError, TypeError, IndexError, sc.ProtoError) as e:
            chk.fail("refusals.json: %s: %s" % (type(e).__name__, e))
    # coverage the module promises
    c = chk.cov
    chk.ok(c.get("sessions") == 2 and c.get("key_type_1") == 1 and c.get("key_type_2") == 1, "coverage: both key types")
    chk.ok(c.get("conns_mon", 0) >= 2 and c.get("conns_osd", 0) >= 2, "coverage: a monitor and an OSD connection per key type")
    chk.ok(c.get("big_data_c2s", 0) >= 2 and c.get("big_data_s2c", 0) >= 2, "coverage: a 1 MiB write and a 1 MiB read reply per key type")
    chk.ok(all(c.get("frames_%dop" % k, 0) >= 1 for k in (1, 2)), "coverage: frames of one and two GCM operations")
    chk.ok(c.get("frames_part2_only", 0) >= 1 and c.get("frames_multiseg", 0) >= 1, "coverage: a frame with a long segment 0 (part 2) and a multi-segment frame (part 3)")
    chk.ok(c.get("signatures_verified", 0) == c.get("conns_secure", -1), "coverage: every connection's signatures verified")
    chk.ok(c.get("refusals", 0) >= 8, "coverage: eight refusals")
    return chk


# ---- extract ----------------------------------------------------------------------------------------------------------------------------------------------

def tcp_streams(path):
    npk, conns = sc.read_pcap(path)
    for c in conns:
        if c.gaps:
            raise SystemExit("%s: the capture has a hole in a TCP stream (%d)" % (path, c.gaps))
        if c.overlap_mismatch:
            raise SystemExit("%s: retransmitted bytes differ" % path)
    return conns


def elide(frames_info, patterns, what):
    """Frame records of one direction from the parsed frames; the long data segments of a frame over WIRE_LIMIT become patterns."""
    out = []
    for f in frames_info:
        segs = []
        for k, s in enumerate(f.segs[:f.n]):
            segs.append(s.hex())
        rec = {"tag": f.tag, "aligns": list(f.aligns[:f.n]), "segs": segs, "wire_len": len(f.wire), "wire_sha256": sha(f.wire)}
        if len(f.wire) > WIRE_LIMIT:
            for k in range(f.n):
                s = f.segs[k]
                if len(s) <= BIG_SEG:
                    continue
                if k != f.n - 1:
                    raise SystemExit("%s: a long segment %d that is not the last one" % (what, k))
                hit = None
                offs = sorted({p[2] for p in patterns})
                for kind, arg, poff, plen in patterns:
                    for off in offs:
                        if len(s) <= plen and pattern(kind, arg, off, len(s)) == s:
                            hit = {"pattern": kind, "arg": arg, "off": off, "len": len(s)}
                            break
                    if hit:
                        break
                if hit is None:
                    raise SystemExit("%s: a %d byte data segment matches none of the script's patterns" % (what, len(s)))
                rec["segs"][k] = hit
            if not any(isinstance(x, dict) for x in rec["segs"]):
                raise SystemExit("%s: a frame of %d wire bytes without a long data segment" % (what, len(f.wire)))
        else:
            rec["wire"] = f.wire.hex()
        out.append(rec)
    return out


def extract(work, out):
    plan = json.load(open(os.path.join(work, "plan.json")))
    keydir = os.path.join(work, "keys")
    os.makedirs(os.path.join(out, "keys"), exist_ok=True)
    chk = Chk()
    for name in SESSIONS:
        shutil.copy(os.path.join(keydir, "client.vec-sec-%s.keyring" % name), os.path.join(out, "keys"))
        script = open(os.path.join(work, "run", name + ".script")).read().split("\n")
        script = [l for l in script if l.strip()]
        pats = script_patterns(script)
        meta = json.load(open(os.path.join(work, "meta", name + ".json")))
        stats = ""
        for ln in open(os.path.join(work, "run", name + ".out")):
            if " stats " in ln:
                stats = ln.split(" stats ", 1)[1].strip()
        sess = Session(name, keydir)
        rec = {"name": name, "about": "wr-rbd --mode secure (monitor and OSDs), one image of 4 MiB with 4 MiB objects: open, write 1 MiB, read it back and verify, a small write, "
               "a partial discard, a whole-object discard", "entity": ENTITY[name], "key_type": KEYTYPE[name], "key_type_name": meta["key_type"],
               "script": script, "start": meta["start"], "end": meta["end"], "osd_map_epoch": meta["epoch0"], "tool_stats": stats, "conns": []}
        n_osd = 0
        for c in tcp_streams(os.path.join(work, "pcap", name + ".pcap")):
            c2s, s2c = bytes(c.c2s), bytes(c.s2c)
            if not c2s or not s2c:
                continue
            cb, _a, _b = sc.check_banner(c2s, "client", name)
            sb, _c, _d = sc.check_banner(s2c, "server", name)
            sf, spos = split_frames_until(s2c, sb, sc.T_AUTH_DONE)
            cf, cpos = split_frames_until(c2s, cb, None, count_after=sf)
            d = derive(sess, c2s[:cpos], s2c[:spos], chk, "%s port %d" % (name, c.sport))
            if d is None or chk.problems:
                raise SystemExit("extraction failed: " + "; ".join(chk.problems))
            key16, seed_a, seed_b = sc.split_secret(d["secret"])
            gc, gs = sc.GcmDir(key16, seed_b), sc.GcmDir(key16, seed_a)
            fc, pc = walk_secure(c2s, cpos, gc)
            fs, ps = walk_secure(s2c, spos, gs)
            if pc != len(c2s) or ps != len(s2c):
                raise SystemExit("%s port %d: %d / %d bytes after the last frame" % (name, c.sport, len(c2s) - pc, len(s2c) - ps))
            if d["kind"] == "osd":
                n_osd += 1
            cid = "mon" if d["kind"] == "mon" else "osd-%d" % n_osd
            rec["conns"].append({"id": cid, "kind": d["kind"], "peer_port": c.sport, "offered_modes": d["offered_modes"], "con_mode": d["con_mode"],
                                 "global_id": d["global_id"], "secret": d["secret"].hex(), "session_key": d["session_key"].secret.hex(),
                                 "hs_c2s": c2s[:cpos].hex(), "hs_s2c": s2c[:spos].hex(), "trailing_c2s": 0, "trailing_s2c": 0,
                                 "frames": {"c2s": elide(fc, pats, name + " " + cid), "s2c": elide(fs, pats, name + " " + cid)}})
        write_json(os.path.join(out, "sessions", name + ".json"), rec)
    # the refusals
    attempts = []
    for fn in sorted(os.listdir(os.path.join(work, "pcap"))):
        if not fn.endswith(".pcap") or fn[:-5] in SESSIONS:
            continue
        nm = fn[:-5]                              # e.g. mon-secure-only-k2
        m = re.fullmatch(r"(mon|osd)-(secure-only|crc-only)-(k1|k2)", nm)
        if not m:
            raise SystemExit("unexpected pcap " + fn)
        daemon, setting, key = m.groups()
        first = None
        n_att = 0
        for c in tcp_streams(os.path.join(work, "pcap", fn)):
            c2s, s2c = bytes(c.c2s), bytes(c.s2c)
            if not c2s or not s2c:
                continue
            try:
                cb, _a, _b = sc.check_banner(c2s, "client", nm)
                sb, _c, _d = sc.check_banner(s2c, "server", nm)
                sf, spos = split_frames_until(s2c, sb, sc.T_AUTH_BAD_METHOD)
            except sc.ProtoError:
                continue
            if sf[-1].tag != sc.T_AUTH_BAD_METHOD:
                continue
            req = [f for f in split_all(c2s, cb) if f.tag == sc.T_AUTH_REQUEST]
            cend = req[0].end
            ar = sc.dec_auth_request(req[0].segs[0])
            kind = "mon" if ar["payload"] and ar["payload"][0] == 10 else "osd"
            if kind != daemon:
                continue
            bm = sc.dec_auth_bad_method(sf[-1].segs[0])
            n_att += 1
            if first is None:
                first = dict(name=nm, daemon=daemon, server_setting=setting, key=key, key_type=KEYTYPE[key], client_offers=ar["modes"], result=bm["result"],
                             allowed_methods=bm["allowed_methods"], allowed_modes=bm["allowed_modes"], c2s=c2s[:cend].hex(), s2c=s2c[:spos].hex())
            else:
                chk.ok(bm["result"] == first["result"] and bm["allowed_modes"] == first["allowed_modes"], nm + ": the attempts were refused differently")
        if first is None:
            raise SystemExit("%s: no refused connection of a %s in the capture" % (nm, daemon))
        first["attempts_in_capture"] = n_att
        attempts.append(first)
    res = {a["result"] for a in attempts}
    write_json(os.path.join(out, "refusals.json"), maxdepth=2, obj=
               {"about": "AUTH_BAD_METHOD answers of a real v20.2.5 monitor and OSD that were set to allow only one mode, to a core client that offered the other one "
                         "(docs/spec/msgr2-secure-mode.md 6.4): the first refused connection of each attempt, the bytes of both directions up to the refusal",
                "result_name": "EOPNOTSUPP", "result_value": -EOPNOTSUPP if res == {-EOPNOTSUPP} else sorted(res), "refusal_osd": plan.get("refusal_osd"), "attempts": attempts})
    if chk.problems:
        raise SystemExit("extraction problems: " + "; ".join(chk.problems))
    write_index(out, plan)
    print("extracted to %s" % out)


def split_all(buf, pos):
    frames = []
    while pos < len(buf):
        try:
            f = sc.parse_crc_frame(buf, pos)
        except sc.ProtoError:
            break
        frames.append(f)
        pos = f.end
    return frames


def split_frames_until(buf, pos, stop_tag, count_after=None):
    """Plaintext frames from pos until a frame with stop_tag (inclusive). For the client direction (stop_tag None) the number of frames is that of the
    server's handshake: HELLO, AUTH_REQUEST and one AUTH_REQUEST_MORE per AUTH_REPLY_MORE."""
    frames = []
    if stop_tag is None:
        n_more = sum(1 for f in count_after if f.tag == sc.T_AUTH_REPLY_MORE)
        want = 2 + n_more
        while len(frames) < want:
            f = sc.parse_crc_frame(buf, pos)
            frames.append(f)
            pos = f.end
        return frames, pos
    while True:
        f = sc.parse_crc_frame(buf, pos)
        frames.append(f)
        pos = f.end
        if f.tag == stop_tag:
            return frames, pos
        if f.tag == sc.T_AUTH_BAD_METHOD:
            return frames, pos


def walk_secure(buf, pos, gcm):
    frames = []
    while pos < len(buf):
        f = sc.parse_secure_frame(buf, pos, gcm)
        frames.append(f)
        pos = f.end
    return frames, pos


def write_index(root, plan=None):
    ip = os.path.join(root, "INDEX.json")
    old = json.load(open(ip)) if os.path.exists(ip) else {}
    files = {}
    for f in list_tree(root):
        if f == "INDEX.json":
            continue
        data = open(os.path.join(root, f), "rb").read()
        files[f] = {"size": len(data), "sha256": sha(data)}
    idx = dict(old)
    if plan is not None:
        idx.update({"about": plan["about"], "made": plan["made"], "cluster": plan["cluster"], "users": plan["users"], "verified_gone": plan["verified_gone"],
                    "key_published": plan["key_published"]})
    idx["files"] = files
    with open(ip, "w") as f:
        f.write(jdump(idx, 0, 2) + "\n")


# ---- self test: damaged copies must all be refused -------------------------------------------------------------------------------------------------

def mutate_json(path, fn):
    d = json.load(open(path))
    fn(d)
    write_json(path, d, 2 if path.endswith("refusals.json") else 5)


def flip_hex(h, i=10):
    b = bytearray(bytes.fromhex(h))
    b[i % len(b)] ^= 1
    return b.hex()


def first_conn(d, kind="osd", n=0):
    return [c for c in d["conns"] if c["kind"] == kind][n]


def first_big(frames):
    return next(f for f in frames if any(isinstance(s, dict) for s in f["segs"]))


def conn_with_big(d, direction):
    return next(c for c in d["conns"] if c["kind"] == "osd" and any(isinstance(s, dict) for f in c["frames"][direction] for s in f["segs"]))


def first_wire_msg(frames):
    return next(f for f in frames if f["tag"] == 17 and "wire" in f)


def selftest(root):
    base = tempfile.mkdtemp(prefix="vsec-selftest-")
    try:
        cases = []

        def m_stray(r):
            open(os.path.join(r, "stray.txt"), "w").write("x")

        def m_link(r):
            os.symlink("INDEX.json", os.path.join(r, "link.json"))

        def m_missing(r):
            os.remove(os.path.join(r, "revert-proof.txt"))

        def m_grow(r):
            open(os.path.join(r, "revert-proof.txt"), "a").write("\nmore\n")

        def reidx(r):
            write_index(r)

        def js(path, fn):
            def run(r):
                mutate_json(os.path.join(r, path), fn)
                reidx(r)
            return run

        def txt(path, add):
            def run(r):
                open(os.path.join(r, path), "a").write(add)
                reidx(r)
            return run

        def wire_flip(d):
            f = first_wire_msg(first_conn(d)["frames"]["s2c"])
            f["wire"] = flip_hex(f["wire"], 50)

        def plain_flip(d):
            f = first_wire_msg(first_conn(d)["frames"]["c2s"])
            f["segs"][1] = flip_hex(f["segs"][1], 0) if f["segs"][1] else "00"

        def sha_flip(d):
            f = first_big(conn_with_big(d, "c2s")["frames"]["c2s"])
            f["wire_sha256"] = "0" * 64

        def pat_arg(d):
            f = first_big(conn_with_big(d, "s2c")["frames"]["s2c"])
            f["segs"][-1]["arg"] += 1

        def pat_off(d):
            f = first_big(conn_with_big(d, "c2s")["frames"]["c2s"])
            f["segs"][-1]["off"] += 8

        def secret_flip(d):
            c = first_conn(d, "mon")
            c["secret"] = flip_hex(c["secret"], 20)

        def key_flip(d):
            c = first_conn(d, "osd")
            c["session_key"] = flip_hex(c["session_key"], 3)

        def hs_s_flip(d):
            c = first_conn(d, "mon")
            c["hs_s2c"] = flip_hex(c["hs_s2c"], len(c["hs_s2c"]) // 2 - 40)

        def hs_c_flip(d):
            c = first_conn(d, "mon")
            c["hs_c2s"] = flip_hex(c["hs_c2s"], 30)

        def banner_comp(d):
            c = first_conn(d, "mon")
            b = bytearray(bytes.fromhex(c["hs_c2s"]))
            b[10] = 3
            c["hs_c2s"] = b.hex()

        def swap_frames(d):
            fr = first_conn(d, "mon")["frames"]["s2c"]
            fr[2], fr[3] = fr[3], fr[2]

        def drop_frame(d):
            fr = first_conn(d, "mon")["frames"]["s2c"]
            del fr[3]

        def dup_frame(d):
            fr = first_conn(d, "mon")["frames"]["c2s"]
            fr.insert(3, dict(fr[2]))

        def tag_change(d):
            fr = first_conn(d, "mon")["frames"]["c2s"]
            fr[1]["tag"] = 11

        def comp_frame(d):
            fr = first_conn(d, "mon")["frames"]["c2s"]
            fr[1]["tag"] = 21

        def align_change(d):
            f = first_wire_msg(first_conn(d)["frames"]["c2s"])
            f["aligns"][0] = 16

        def mode_chg(d):
            first_conn(d, "mon")["con_mode"] = 1

        def r_result(d):
            d["attempts"][0]["result"] = -13

        def r_modes(d):
            a = d["attempts"][0]
            a["allowed_modes"] = a["client_offers"]

        def r_hex(d):
            a = d["attempts"][1]
            a["s2c"] = flip_hex(a["s2c"], len(a["s2c"]) // 2 - 3)

        def r_drop(d):
            del d["attempts"][2]

        def r_setting(d):
            a = d["attempts"][0]
            a["server_setting"] = "crc-only" if a["server_setting"] == "secure-only" else "secure-only"

        def key_swap(r):
            a, b = [os.path.join(r, "keys", "client.vec-sec-%s.keyring" % k) for k in SESSIONS]
            ta, tb = open(a).read(), open(b).read()
            open(a, "w").write(tb.replace("vec-sec-k1", "vec-sec-k2"))
            reidx(r)

        cases = [
            ("a stray file", m_stray), ("a symbolic link", m_link), ("a missing file", m_missing), ("a file that differs from its index entry", m_grow),
            ("a flipped bit in a recorded wire frame", js("sessions/k2.json", wire_flip)),
            ("a flipped bit in a recorded plaintext segment", js("sessions/k1.json", plain_flip)),
            ("a wrong SHA-256 of an elided frame", js("sessions/k2.json", sha_flip)),
            ("a changed pattern seed of an elided data segment", js("sessions/k1.json", pat_arg)),
            ("a changed pattern offset", js("sessions/k2.json", pat_off)),
            ("a flipped byte of a connection secret", js("sessions/k2.json", secret_flip)),
            ("a flipped byte of a session key", js("sessions/k1.json", key_flip)),
            ("a flipped byte in the server's handshake", js("sessions/k2.json", hs_s_flip)),
            ("a flipped byte in the client's handshake", js("sessions/k1.json", hs_c_flip)),
            ("a client banner that advertises compression", js("sessions/k2.json", banner_comp)),
            ("two frames swapped (the nonces no longer fit)", js("sessions/k2.json", swap_frames)),
            ("a frame dropped", js("sessions/k1.json", drop_frame)),
            ("a frame repeated", js("sessions/k2.json", dup_frame)),
            ("a frame with another tag", js("sessions/k1.json", tag_change)),
            ("a COMPRESSION frame", js("sessions/k2.json", comp_frame)),
            ("a changed alignment", js("sessions/k1.json", align_change)),
            ("a recorded mode the server did not pick", js("sessions/k2.json", mode_chg)),
            ("a refusal with another result code", js("refusals.json", r_result)),
            ("a refusal whose allowed modes include the offer", js("refusals.json", r_modes)),
            ("a damaged refusal frame", js("refusals.json", r_hex)),
            ("a missing refusal", js("refusals.json", r_drop)),
            ("a refusal under the wrong server setting", js("refusals.json", r_setting)),
            ("a key-looking text in the README", txt("README.md", "\nkey = AQBhZGFtbm90YXJlYWxrZXlhdGFsbDEyMw==\n")),
            ("an address outside the lab nets", txt("README.md", "\nconnect to 203.0.113.9\n")),
            ("a home directory path", txt("README.md", "\n/home/someone/x\n")),
            ("a long hex string in the README", txt("README.md", "\n" + "ab" * 20 + "\n")),
            ("a keyring of another user", key_swap),
        ]
        ref = os.path.join(base, "ref")
        shutil.copytree(root, ref)
        chk = check_dir(ref)
        bad = 0
        if chk.problems:
            print("selftest: the undamaged copy fails:", chk.problems[:3])
            return 1
        print("selftest: the undamaged copy passes (%d checks)" % chk.passed)
        for i, (label, fn) in enumerate(cases):
            d = os.path.join(base, "c%d" % i)
            shutil.copytree(root, d, symlinks=True)
            try:
                fn(d)
            except (KeyError, StopIteration, IndexError) as e:
                print("selftest: case %r could not be built (%s)" % (label, e))
                bad += 1
                continue
            r = check_dir(d)
            if r.problems:
                print("selftest: refused  %-52s %s" % (label, r.problems[0][:90]))
            else:
                print("selftest: ACCEPTED %s" % label)
                bad += 1
            shutil.rmtree(d)
        print("selftest: %d damaged copies, %d accepted" % (len(cases), bad))
        return 1 if bad else 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("cmd", nargs="?", default="check", choices=["check", "selftest", "extract", "reindex"])
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--work")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.cmd in ("check", "selftest", "reindex") and not os.path.isfile(os.path.join(a.dir, "INDEX.json")):
        sys.stderr.write("SKIP: %s has no INDEX.json (the secure vectors are not part of this source tree)\n" % a.dir)
        return 77
    if a.cmd == "extract":
        if not a.work or not a.out:
            ap.error("extract needs --work and --out")
        extract(a.work, a.out)
        return 0
    if a.cmd == "reindex":
        write_index(a.dir)
        print("reindexed")
        return 0
    if a.cmd == "selftest":
        return selftest(a.dir)
    chk = check_dir(a.dir)
    for p in chk.problems[:40]:
        print("FAIL: " + p)
    print("check_secure_core: %d checks passed, %d problems; coverage %s" % (chk.passed, len(chk.problems), json.dumps(chk.cov, sort_keys=True)))
    return 1 if chk.problems else 0


if __name__ == "__main__":
    sys.exit(main())
