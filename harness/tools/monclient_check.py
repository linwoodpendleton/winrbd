#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
Independent checker for docs/spec/mon-client.md.

Written from the NOTES ONLY (mon-client.md, msgr2.md, msgr2-secure-mode.md, cephx.md, osdmap.md), never from
Ceph source and never through Ceph's own decoders.  The real bytes are the pcaps of the Phase 0 capture set
(client in a network namespace, one TCP session per pcap); the Ceph tools' output (`ceph mon dump`, the
monitor-store copies of every OSDMap / Incremental, ceph-dencoder JSON) is used only as the EXPECTED answer.

What it does, per pcap:
  1. reassembles the TCP streams, parses msgr2 frames and verifies every length / tag / CRC-32C;
  2. runs the cephx handshake with the lab keyrings (read at run time, never printed): challenge proof, ticket
     reply, connection secret, authorizer round trips, pre-auth AUTH_SIGNATURE (both directions);
  3. for secure-mode connections derives the AES-128-GCM streams from the connection secret and decrypts;
  4. decodes the monitor client messages (MMonGetMap, MMonMap/MonMap, MMonSubscribe, MOSDMap, MAuth,
     MAuthReply, MMonGetVersion*, keepalives) and checks them against the note;
and across pcaps compares MonMap with `ceph mon dump`, MOSDMap blobs byte-for-byte with the monitor-store copies,
and so on.

Usage:  python3 harness/tools/monclient_check.py [--captures <dir>] [--secrets <dir>] [-v] [--jobs N]
                [--write-vectors <dir>] [--only <substring>]
Without arguments it checks the public vector set (harness/vectors/public) with the public throw-away keys.
Exit status 0 when every check passes, 1 otherwise.

Secrets: keyrings are read from harness/vectors/public/keys for the public set, else from <captures>/../lab-secrets
(override with --secrets); the optional session-key cross-check reads <captures>/secrets/session-secrets/*.txt when
present.  Nothing secret is ever printed or
written by this tool (vectors written with --write-vectors are scrubbed, see harness/vectors/monclient/README.md).
"""

import argparse
import collections
import concurrent.futures
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
import wire  # noqa: E402
from wire import Rd, WireError  # noqa: E402

# ----------------------------------------------------------------------------------------------------
# check tally (mergeable across worker processes)
# ----------------------------------------------------------------------------------------------------

MAX_EX = 3


class Tally:
    def __init__(self):
        self.d = {}                          # name -> [ok, fail, [examples]]
        self.notes = collections.Counter()   # informational observations (never fail the run)

    def chk(self, name, cond, detail=''):
        e = self.d.setdefault(name, [0, 0, []])
        if cond:
            e[0] += 1
        else:
            e[1] += 1
            if len(e[2]) < MAX_EX:
                e[2].append(detail)
        return bool(cond)

    def info(self, text):
        self.notes[text] += 1

    def merge(self, other):
        for k, (o, f, ex) in other.d.items():
            e = self.d.setdefault(k, [0, 0, []])
            e[0] += o
            e[1] += f
            for x in ex:
                if len(e[2]) < MAX_EX:
                    e[2].append(x)
        self.notes.update(other.notes)


ENT = {1: 'mon', 2: 'mds', 4: 'osd', 8: 'client', 16: 'mgr', 32: 'auth'}
# message types (note 2.2)
MT = {2: 'PING', 4: 'MON_MAP', 5: 'MON_GET_MAP', 6: 'MON_GET_OSDMAP', 15: 'MON_SUBSCRIBE', 16: 'MON_SUBSCRIBE_ACK',
      17: 'AUTH', 18: 'AUTH_REPLY', 19: 'MON_GET_VERSION', 20: 'MON_GET_VERSION_REPLY', 41: 'OSD_MAP',
      50: 'MON_COMMAND', 51: 'MON_COMMAND_ACK', 52: 'LOG', 53: 'LOGACK', 62: 'CONFIG', 63: 'GET_CONFIG',
      97: 'COMMAND', 98: 'COMMAND_REPLY'}


def load_keyring(path):
    """-> (entity, type, secret) ; the key text never leaves this function except as bytes"""
    ent = None
    key = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('[') and line.endswith(']'):
                ent = line[1:-1]
            elif line.startswith('key') and '=' in line:
                key = line.split('=', 1)[1].strip()
    t, sec = wire.key_decode(key)
    return ent, t, sec


# ----------------------------------------------------------------------------------------------------
# decoders of the structures in the note
# ----------------------------------------------------------------------------------------------------

def dec_entity_addr(r, tl):
    """entity_addr_t (marker 1 form) -> dict ; records raw sockaddr checks"""
    m = r.u8()
    if m != 1:
        raise WireError('entity_addr marker %d' % m)
    v, c, end = r.env()
    typ = r.u32()
    nonce = r.u32()
    elen = r.u32()
    d = {'type': typ, 'nonce': nonce, 'elen': elen, 'v': v, 'compat': c}
    if elen:
        fam = r.u16()
        sa = r.raw(elen - 2)
        d['family'] = fam
        if fam == 2:
            d['port'] = struct.unpack('>H', sa[0:2])[0]
            d['ip'] = '.'.join(str(x) for x in sa[2:6])
            d['pad_zero'] = sa[6:] == bytes(len(sa) - 6)
            d['sa_len'] = len(sa)
        elif fam == 10:
            d['port'] = struct.unpack('>H', sa[0:2])[0]
            d['flow'] = sa[2:6]
            d['ip6'] = sa[6:22].hex()
            d['scope'] = sa[22:26]
    if r.p != end:
        r.p = end
    return d


def dec_addrvec(r, tl):
    m = r.u8()
    if m == 2:
        n = r.u32()
        return [dec_entity_addr(r, tl) for _ in range(n)]
    if m == 1:
        r.p -= 1
        return [dec_entity_addr(r, tl)]
    raise WireError('addrvec marker %d' % m)


def dec_monmap(b, tl):
    """MonMap v6..v10 (note 2.4.1) -> dict"""
    r = Rd(b)
    v, c, end = r.env()
    d = {'struct_v': v, 'compat': c, 'len': end - r.p}
    r.end = end
    d['fsid'] = r.uuid()
    d['epoch'] = r.u32()
    d['last_changed'] = r.utime()
    d['created'] = r.utime()
    for nm in ('persistent_features', 'optional_features'):
        fv, fc, fe = r.env()
        flen = fe - r.p
        d[nm] = r.u64()
        d[nm + '_env'] = (fv, fc, flen)
        r.p = fe
    n = r.u32()
    mi = {}
    for _ in range(n):
        name = r.string()
        iv, ic, ie = r.env()
        sub = {'v': iv, 'compat': ic}
        sub['name'] = r.string()
        sub['addrs'] = dec_addrvec(r, tl)
        if iv >= 2:
            sub['priority'] = r.u16()
        if iv >= 4:
            sub['weight'] = r.u16()
        if iv >= 5:
            k = r.u32()
            sub['crush_loc'] = {r.string(): r.string() for _ in range(k)}
        if iv >= 6:
            sub['time_added'] = r.utime()
        r.p = ie
        mi[name] = sub
    d['mon_info'] = mi
    d['ranks'] = [r.string() for _ in range(r.u32())]
    d['min_mon_release'] = r.u8()
    d['removed_ranks'] = [r.u32() for _ in range(r.u32())]
    d['strategy'] = r.u8()
    d['disallowed_leaders'] = [r.string() for _ in range(r.u32())]
    d['stretch_mode_enabled'] = r.u8()
    d['tiebreaker_mon'] = r.string()
    d['stretch_marked_down_mons'] = [r.string() for _ in range(r.u32())]
    if v >= 10:
        d['auth_epoch'] = r.u32()
        d['auth_service_cipher'] = r.i32()
        d['auth_allowed_ciphers'] = [r.i32() for _ in range(r.u32())]
        d['auth_preferred_cipher'] = r.i32()
    d['trailing'] = r.end - r.p
    return d


def dec_subscribe(b, version):
    r = Rd(b)
    n = r.u32()
    what = []
    for _ in range(n):
        name = r.string()
        start = r.u64()
        flags = r.u8()
        what.append((name, start, flags))
    host = r.string() if version >= 3 else None
    return {'what': what, 'hostname': host, 'trailing': r.left()}


def dec_mosdmap(b, version):
    r = Rd(b)
    d = {'version': version}
    d['fsid'] = r.uuid()
    inc = {}
    for _ in range(r.u32()):
        e = r.u32()
        inc[e] = r.blob()
    full = {}
    for _ in range(r.u32()):
        e = r.u32()
        full[e] = r.blob()
    d['inc'] = inc
    d['full'] = full
    if version >= 2:
        d['trim_lower'] = r.u32()
        d['newest'] = r.u32()
    if version >= 4:
        d['gap_count'] = r.u32()
    d['trailing'] = r.left()
    return d


def dec_paxos_prefix(r):
    return {'version': r.u64(), 'session_mon': r.i16(), 'tid': r.u64()}


# ----------------------------------------------------------------------------------------------------
# connection analysis
# ----------------------------------------------------------------------------------------------------

class Conn:
    pass


def hdr2(seg):
    if len(seg) != 41:
        raise WireError('ceph_msg_header2 length %d' % len(seg))
    (seq, tid, typ, prio, ver, pad, doff, ack, flags, compat, rsv) = struct.unpack('<QQHHHIHQBHH', seg)
    return dict(seq=seq, tid=tid, type=typ, prio=prio, version=ver, pre_pad=pad, data_off=doff, ack_seq=ack,
                flags=flags, compat=compat, reserved=rsv)


class Session:
    """state shared by the connections of one pcap: the ticket store"""

    def __init__(self, ent, ktype, secret, tl, verbose=False):
        self.ent = ent
        self.ktype = ktype
        self.secret = secret
        self.tl = tl
        self.tickets = {}        # (service_id, secret_id, blob) -> (ktype, secret)
        self.tgid = {}           # same key -> global_id of the mon login that issued it
        self.verbose = verbose
        self.obs = collections.defaultdict(list)
        self.global_id = None
        self.auth_ticket = None  # (secret_id, blob)


def read_frames(stream, start, tl, tag, secure_rx=None, stop_after=None):
    """read all frames from stream.data starting at `start`; returns (frames, leftover_offset)"""
    out = []
    pos = start
    data = stream.data
    while pos < len(data):
        try:
            fr = wire.read_secure_frame(data, pos, secure_rx) if secure_rx else wire.read_crc_frame(data, pos)
        except WireError as e:
            if stream.gap_at is not None:
                return out, pos            # truncated by a capture gap (counted as a capture artefact)
            tl.chk('framing: stream ends on a frame boundary', False, '%s at %d/%d: %s' % (tag, pos, len(data), e))
            return out, pos
        for er in fr.errors:
            tl.chk('framing: frame structure / crc ok', False, '%s %s' % (fr.name, er))
        tl.chk('framing: frame structure / crc ok', not fr.errors)
        fr.ts = stream.ts_at(fr.start)
        out.append(fr)
        pos = fr.end
        if stop_after and fr.tag in stop_after:
            break
    return out, pos


def analyze_conn(sess, flow, cidx, meta, tl, only_pre=False):
    """Decode one TCP connection; returns Conn"""
    tag = '%s/%d' % (meta['name'], cidx)
    c = Conn()
    c.flow = flow
    c.idx = cidx
    c.msgs = []
    c.frames = []
    c.mode = 1
    c.peer = None
    c.port = flow.server[1]
    c.ok_auth = False
    cs, ss = flow.c2s.data, flow.s2c.data
    c.cs_len, c.ss_len = len(cs), len(ss)
    if len(cs) == 0 and len(ss) == 0:
        c.short = True
        tl.info('connection attempts without any payload byte (refused / reset while the monitor was down)')
        return c
    if len(cs) < 26 or len(ss) < 26:
        c.short = True
        tl.chk('conn: both banners present', False, '%s c=%d s=%d' % (tag, len(cs), len(ss)))
        return c
    c.short = False
    tl.chk('pcap: overlapping TCP retransmissions are byte-identical', flow.c2s.overlap_mismatch == 0 and flow.s2c.overlap_mismatch == 0)
    c.gap = flow.c2s.gaps + flow.s2c.gaps
    if c.gap:
        tl.info('capture artefact: %d TCP stream(s) lost packets in the capture (tcpdump drop on a 9 MiB transfer); the '
                'stream tail after the hole is not decodable and is not counted against the note' % c.gap)
    cb = wire.read_banner(cs)
    sb = wire.read_banner(ss)
    c.banner = (cb, sb)
    tl.chk('msgr2: client banner is 26 bytes, supported/required readable', cb[2] == 16 and cb[3] == 26)
    tl.chk('msgr2: server banner is 26 bytes, supported=3 (REVISION_1|COMPRESSION) required=0',
           sb[2] == 16 and sb[0] == 3 and sb[1] == 0, 'sup=%d req=%d' % (sb[0], sb[1]))
    # --- server side up to AUTH_DONE / AUTH_BAD_METHOD
    sfr, spos = read_frames(flow.s2c, 26, tl, tag + ' s2c', stop_after=(6, 3))
    cfr, cpos = [], 26
    # client frames until the end of auth (AUTH_SIGNATURE may be encrypted -> read only plaintext ones)
    pend = []
    pos = 26
    while pos < len(cs):
        try:
            fr = wire.read_crc_frame(cs, pos)
        except WireError:
            break
        if fr.errors or fr.tag not in (1, 2, 5, 7):
            break
        fr.ts = flow.c2s.ts_at(fr.start)
        pend.append(fr)
        pos = fr.end
        if fr.tag == 7:
            break
    names_s = [f.name for f in sfr]
    names_c = [f.name for f in pend]
    c.names_s, c.names_c = names_s, names_c
    if not sfr or sfr[0].tag != 1:
        tl.chk('conn: server sends HELLO first', False, tag)
        return c
    # HELLO
    hello_s = sfr[0]
    r = Rd(hello_s.segs[0])
    etype = r.u8()
    saddr = dec_entity_addr(r, tl)
    c.peer = ENT.get(etype, '?%d' % etype)
    tl.chk('msgr2: server HELLO carries a known entity type', etype in ENT, str(etype))
    tl.chk('msgr2: HELLO peer_addr is the client socket address (type 3 survives, ip/port match the TCP 4-tuple)',
           saddr.get('ip') == flow.client[0] and saddr.get('port') == flow.client[1] and saddr['type'] in (2, 3, 1),
           '%s vs %s' % (saddr, flow.client))
    if not pend or pend[0].tag != 1:
        tl.chk('conn: client sends HELLO first', False, tag)
        return c
    r = Rd(pend[0].segs[0])
    cet = r.u8()
    caddr = dec_entity_addr(r, tl)
    tl.chk('msgr2: client HELLO entity type is CLIENT (0x08)', cet == 8, str(cet))
    tl.chk('msgr2: client HELLO peer_addr is the dialled server address (ip, port, type 3)',
           caddr.get('ip') == flow.server[0] and caddr.get('port') == flow.server[1], str(caddr))
    tl.info('msgr2.md 2.1 / 2.8 predicts addresses in frames keep type 3 (ANY); observed HELLO types: server->client '
            'peer_addr %d, client->server peer_addr %d' % (saddr['type'], caddr['type']))
    c.hello_c = caddr
    c.hello_s = saddr
    # AUTH_REQUEST
    ar = [f for f in pend if f.tag == 2]
    if not ar:
        tl.chk('conn: client sent AUTH_REQUEST', False, tag)
        return c
    r = Rd(ar[0].segs[0])
    method = r.u32()
    modes = [r.u32() for _ in range(r.u32())]
    payload = r.blob()
    tl.chk('msgr2: AUTH_REQUEST has no trailing bytes', r.left() == 0)
    tl.chk('msgr2: AUTH_REQUEST method is CEPHX (2)', method == 2, str(method))
    c.modes_offered = modes
    ast = {'method': method, 'modes': modes}
    # ------------------------------------------------------------- auth by peer kind
    done = [f for f in sfr if f.tag == 6]
    bad = [f for f in sfr if f.tag == 3]
    if bad:
        r = Rd(bad[0].segs[0])
        m = r.u32()
        res = r.i32()
        meths = [r.u32() for _ in range(r.u32())]
        mds = [r.u32() for _ in range(r.u32())]
        c.bad_method = (m, res, meths, mds)
        sess.obs['auth_bad_method'].append((meta['name'], c.peer, res, meths, mds))
        rm = [f for f in sfr if f.tag == 4]
        qm = [f for f in pend if f.tag == 5]
        if c.peer == 'mon' and rm and qm:
            ch = Rd(Rd(rm[0].segs[0]).blob())
            ch.u8()
            schal = ch.u64()
            q = Rd(Rd(qm[0].segs[0]).blob())
            q.u16()
            q.u8()
            cchal = q.u64()
            proof = q.u64()
            tl.chk('cephx 2.8: the challenge proof is computed from the key the client holds even when it is the wrong key '
                   '(recomputation with that key matches the wire)',
                   wire.cx_challenge_proof(sess.ktype, sess.secret, schal, cchal) == proof)
        tl.chk('cephx 3.8: unknown / wrong key -> AUTH_BAD_METHOD with result -13 (EACCES)', res == -13, str(res))
        return c
    if not done:
        tl.chk('conn: AUTH_DONE present', False, tag + ' frames=' + ','.join(names_s))
        return c
    r = Rd(done[0].segs[0])
    gid = r.u64()
    cmode = r.u32()
    dpay = r.blob()
    tl.chk('msgr2: AUTH_DONE has no trailing bytes', r.left() == 0)
    c.mode = cmode
    c.global_id = gid
    tl.chk('msgr2: AUTH_DONE connection mode is one the client offered', cmode in modes, '%d not in %s' % (cmode, modes))
    skey = None            # (type, secret) used for AUTH_SIGNATURE
    conn_secret = b''
    if c.peer == 'mon':
        pr = Rd(payload)
        mode_byte = pr.u8()
        etype = pr.u32()
        eid = pr.string()
        gid0 = pr.u64()
        tl.chk('mon-client 3.3.2: mon auth payload = u8 10 | EntityName | u64 global_id, nothing more',
               mode_byte == 10 and etype == 8 and pr.left() == 0 and eid == sess.ent.split('.', 1)[1],
               'mode=%d type=%d id=%s left=%d' % (mode_byte, etype, eid, pr.left()))
        c.req_gid = gid0
        # challenge
        rm = [f for f in sfr if f.tag == 4]
        qm = [f for f in pend if f.tag == 5]
        tl.chk('cephx 3.2: exactly one AUTH_REPLY_MORE / AUTH_REQUEST_MORE round on a first mon login',
               len(rm) == 1 and len(qm) == 1, '%d/%d' % (len(rm), len(qm)))
        r = Rd(rm[0].segs[0])
        ch = Rd(r.blob())
        cv = ch.u8()
        schal = ch.u64()
        tl.chk('cephx 2.7: CephXServerChallenge = u8 1 | u64, no trailing bytes', cv == 1 and ch.left() == 0 and schal != 0)
        r = Rd(qm[0].segs[0])
        q = Rd(r.blob())
        rt = q.u16()
        av = q.u8()
        cchal = q.u64()
        proof = q.u64()
        ov = q.u8()
        osid = q.u64()
        oblob = q.blob()
        other = q.u32()
        tl.chk('cephx 3.2.3: AUTH_REQUEST_MORE = request header 0x0100 | CephXAuthenticate v3 ... no trailing bytes',
               rt == 0x0100 and av == 3 and q.left() == 0, 'rt=%#x av=%d left=%d' % (rt, av, q.left()))
        want = wire.cx_challenge_proof(sess.ktype, sess.secret, schal, cchal)
        tl.chk('cephx 2.8: challenge proof recomputed from the keyring equals the wire value (key type %d)' % sess.ktype,
               want == proof)
        tl.chk('cephx 3.1: other_keys mask contains the AUTH bit 0x20', other & 0x20 != 0, '%#x' % other)
        c.other_keys = other
        c.old_ticket_len = len(oblob)
        # AUTH_DONE payload
        d = Rd(dpay)
        rt = d.u16()
        st = d.i32()
        tl.chk('cephx 2.7: mon reply header request_type 0x0100, status 0', rt == 0x0100 and st == 0, '%#x %d' % (rt, st))
        prev = sess.tickets.get((0x20, osid, oblob)) if oblob else None
        if oblob:
            tl.chk('cephx 3.7: the old_ticket sent on a reclaim is an AUTH ticket blob handed out earlier in this capture',
                   prev is not None)
        c.old_ticket_ref = (osid, oblob)
        keys = decode_ticket_reply(d, sess.ktype, sess.secret, tl, 'AUTH reply', sess, prev)
        tl.chk('cephx 2.7: first ticket reply has exactly one ticket, service AUTH (0x20)',
               len(keys) == 1 and keys[0]['service'] == 0x20)
        ak = keys[0]
        akey = (ak['ktype'], ak['secret'])
        tl.chk('cephx 3.4: AUTH session key type equals the principal key type', ak['ktype'] == sess.ktype)
        c.auth_validity = ak['validity']
        tl.chk('mon-client 3.8.1 / cephx 3.5: the AUTH ticket validity on the wire is auth_mon_ticket_ttl = 72 h (259200 s) in '
               'every login of this capture set', ak['validity'] == 259200.0, str(ak['validity']))
        sess.auth_ticket = (ak['sid'], ak['blob'])
        sess.tickets[(0x20, ak['sid'], ak['blob'])] = akey
        sess.tgid[(0x20, ak['sid'], ak['blob'])] = gid
        sess.global_id = gid
        c.auth_secret_id = ak['sid']
        c.auth_key = akey
        c.auth_blob = ak['blob']
        c.auth_done_ts = flow.s2c.ts_at(done[0].start)
        c.ticket_validity = {}
        # cbl
        cbl = d.blob() if d.left() else None
        extra = d.blob() if d.left() else None
        tl.chk('cephx 2.7: reply has cbl and extra blobs after the first ticket reply and nothing after',
               cbl is not None and extra is not None and d.left() == 0)
        if cbl is not None:
            cr = Rd(cbl)
            inner = cr.blob()
            tl.chk('cephx 2.7: cbl = u32 inner_len | ciphertext (outer length covers it)', cr.left() == 0)
            sp, sv = wire.cx_unseal(ak['ktype'], ak['secret'], 3, inner)
            sr = Rd(sp)
            conn_secret = sr.blob()
            tl.chk('cephx 2.7: connection secret plaintext = u32 len | secret, nothing more', sr.left() == 0)
            tl.chk('cephx 2.7/secure 2.5: connection secret length is 0 in crc mode and 64 in secure mode',
                   len(conn_secret) == (64 if cmode == 2 else 0), 'mode=%d len=%d' % (cmode, len(conn_secret)))
        if extra:
            ex = Rd(extra)
            exk = decode_ticket_reply(ex, ak['ktype'], ak['secret'], tl, 'extra', sess)
            tl.chk('cephx 2.7: extra ticket reply has no trailing bytes', ex.left() == 0)
            tl.chk('cephx 2.7: extra tickets are for the requested non-AUTH services only',
                   all(k['service'] & other for k in exk) and all(k['service'] != 0x20 for k in exk),
                   str([hex(k['service']) for k in exk]))
            for k in exk:
                sess.tickets[(k['service'], k['sid'], k['blob'])] = (k['ktype'], k['secret'])
                sess.tgid[(k['service'], k['sid'], k['blob'])] = gid
            c.extra = [(hex(k['service']), k['ktype']) for k in exk]
            c.ticket_validity = {k['service']: k['validity'] for k in exk}
            tl.chk('mon-client 3.8.1 / cephx 3.5: service tickets carry validity = auth_service_ticket_ttl (3600 s by default, '
                   '60 s in the renew-ttl60 sessions)',
                   all(k['validity'] == (60.0 if 'renew-ttl60' in meta['name'] else 3600.0) for k in exk),
                   str([k['validity'] for k in exk]))
            tl.chk('cephx 3.4: extra service tickets: key type is min(principal type, service key type)',
                   all(k['ktype'] in (1, 2) and k['ktype'] <= ak['ktype'] for k in exk))
        else:
            c.extra = []
        skey = akey
        c.ok_auth = True
    else:
        # authorizer to osd / mgr
        pr = Rd(payload)
        av = pr.u8()
        gid0 = pr.u64()
        svc = pr.u32()
        tv = pr.u8()
        tsid = pr.u64()
        tblob = pr.blob()
        proof = pr.blob()
        tl.chk('cephx 2.7: authorizer = u8 1 | u64 global_id | u32 service | ticket blob | proof (no trailing bytes)',
               av == 1 and pr.left() == 0, 'v=%d left=%d' % (av, pr.left()))
        tk = sess.tickets.get((svc, tsid, tblob))
        tgid = sess.tgid.get((svc, tsid, tblob))
        tl.chk('cephx: ticket blob in the authorizer is the one the mon handed out (service %#x)' % svc, tk is not None)
        tl.chk('cephx 2.7: authorizer global_id equals the global_id the mon assigned (AUTH_DONE of the login that '
               'issued the ticket)', gid0 == tgid, '%s vs %s' % (gid0, tgid))
        tl.chk('cephx 3.3.1: authorizer service id matches peer (OSD 4 / MGR 0x10)',
               svc == {'osd': 4, 'mgr': 0x10}.get(c.peer), '%s %s' % (svc, c.peer))
        if tk is None:
            return c
        tkt, tks = tk
        pt, _ = wire.cx_unseal(tkt, tks, 0x10, proof)      # `proof` = ciphertext (pr.blob() stripped the u32 length)
        a = Rd(pt)
        av2 = a.u8()
        nonce = a.u64()
        hc = a.u8()
        plus1 = a.u64()
        tl.chk('cephx 2.7: CephXAuthorize first send = v2 | nonce | have_challenge 0 | plus_one 0',
               av2 == 2 and hc == 0 and plus1 == 0 and a.left() == 0, 'v=%d hc=%d p1=%d' % (av2, hc, plus1))
        rm = [f for f in sfr if f.tag == 4]
        qm = [f for f in pend if f.tag == 5]
        tl.chk('cephx 3.3: OSD/MGR connect = one challenge round (AUTH_REPLY_MORE then AUTH_REQUEST_MORE)',
               len(rm) == 1 and len(qm) == 1, '%d/%d' % (len(rm), len(qm)))
        # challenge: raw ciphertext, no u32 prefix  (note 3.3.2); the msgr2 field itself is a blob
        rr = Rd(rm[0].segs[0])
        craw = rr.blob()
        tl.chk('cephx 2.7: challenge payload is raw ciphertext (decrypts without stripping a length prefix)', True)
        cp, _ = wire.cx_unseal(tkt, tks, 0x11, craw)
        cr = Rd(cp)
        cv = cr.u8()
        schal = cr.u64()
        tl.chk('cephx 2.7: CephXAuthorizeChallenge = u8 1 | u64 server_challenge', cv == 1 and cr.left() == 0)
        qr = Rd(qm[0].segs[0])
        p2 = Rd(qr.blob())
        av_ = p2.u8()
        gid2 = p2.u64()
        svc2 = p2.u32()
        p2.u8()
        p2.u64()
        tb2 = p2.blob()
        pf2 = p2.blob()
        tl.chk('cephx 3.3.3: second authorizer repeats prefix and ticket verbatim',
               (av_, gid2, svc2, tb2) == (av, gid0, svc, tblob))
        pt2, _ = wire.cx_unseal(tkt, tks, 0x10, pf2)
        a2 = Rd(pt2)
        a2.u8()
        nonce2 = a2.u64()
        hc2 = a2.u8()
        pl2 = a2.u64()
        tl.chk('cephx 3.3.3: second authorizer has have_challenge 1, plus_one = server_challenge + 1, same nonce',
               hc2 == 1 and pl2 == schal + 1 and nonce2 == nonce, 'hc=%d p=%d s=%d' % (hc2, pl2, schal))
        # reply
        dr = Rd(dpay)
        rep = dr.blob()
        tl.chk('cephx 3.3.4: AUTH_DONE payload is u32 len | ciphertext', dr.left() == 0)
        rp, _ = wire.cx_unseal(tkt, tks, 0x12, rep)
        ra = Rd(rp)
        rv = ra.u8()
        np1 = ra.u64()
        sec = ra.blob() if rv >= 2 else b''
        tl.chk('cephx 3.3.4: AuthorizeReply nonce_plus_one == nonce + 1', np1 == nonce + 1)
        tl.chk('cephx 2.7: AuthorizeReply v2 with 64-byte secret in secure mode, v1 without secret in crc mode',
               (cmode == 2 and rv >= 2 and len(sec) == 64) or (cmode == 1 and rv == 1 and not sec),
               'mode=%d v=%d len=%d' % (cmode, rv, len(sec)))
        conn_secret = sec
        skey = (tkt, tks)
        c.ok_auth = True
    # ------------------------------------------------------------- pre-auth signatures
    rx_t = ss[:done[0].end]
    last_auth_c = [f for f in pend if f.tag in (2, 5)][-1]
    tx_t = cs[:last_auth_c.end]
    sk = skey[1]
    sig_c = wire.hmac_sha256(sk, rx_t)
    sig_s = wire.hmac_sha256(sk, tx_t)
    # signature frames
    rxs = txs = None
    if cmode == 2:
        tl.chk('secure 2.5: connection secret is at least 40 bytes', len(conn_secret) >= 40)
        key = conn_secret[:16]
        seedA, seedB = conn_secret[16:28], conn_secret[28:40]
        # client receives with seed A, transmits with seed B
        rxs = wire.SecureRx(key, seedA)
        txs = wire.SecureRx(key, seedB)
    # client signature frame
    cfr_rest = []
    pos = last_auth_c.end
    try:
        csig = wire.read_secure_frame(cs, pos, txs) if txs else wire.read_crc_frame(cs, pos)
        tl.chk('msgr2: client AUTH_SIGNATURE frame readable (mode %d)' % cmode, csig.tag == 7, csig.name)
        tl.chk('msgr2 2.9 / cephx 2.9: client AUTH_SIGNATURE = HMAC-SHA256(session key, every byte received up to and '
               'including AUTH_DONE)', csig.segs[0] == sig_c and len(csig.segs[0]) == 32)
        csig.ts = flow.c2s.ts_at(csig.start)
        cfr_rest.append(csig)
        cpos = csig.end
    except WireError as e:
        tl.chk('msgr2: client AUTH_SIGNATURE frame readable (mode %d)' % cmode, False, '%s: %s' % (tag, e))
        return c
    try:
        ssig = wire.read_secure_frame(ss, done[0].end, rxs) if rxs else wire.read_crc_frame(ss, done[0].end)
        tl.chk('msgr2: server AUTH_SIGNATURE frame readable (mode %d)' % cmode, ssig.tag == 7, ssig.name)
        tl.chk('msgr2 2.9 / cephx 2.9: server AUTH_SIGNATURE = HMAC-SHA256(session key, every byte the client sent up to '
               'its last AUTH_REQUEST(_MORE))', ssig.segs[0] == sig_s and len(ssig.segs[0]) == 32)
        ssig.ts = flow.s2c.ts_at(ssig.start)
        spos = ssig.end
    except WireError as e:
        tl.chk('msgr2: server AUTH_SIGNATURE frame readable (mode %d)' % cmode, False, '%s: %s' % (tag, e))
        return c
    c.sig_c = csig
    c.sig_s = ssig
    # ------------------------------------------------------------- the rest of the stream
    cfr2, cend = read_frames(flow.c2s, cpos, tl, tag + ' c2s', txs)
    sfr2, send = read_frames(flow.s2c, spos, tl, tag + ' s2c', rxs)
    c.c2s_leftover = len(cs) - cend
    c.s2c_leftover = len(ss) - send
    # annotate
    for dirn, lst in (('c', cfr_rest + cfr2), ('s', sfr2)):
        for fr in lst:
            fr.dir = dirn
    allf = [(f.ts, 'c', f) for f in cfr2] + [(f.ts, 's', f) for f in sfr2]
    allf.sort(key=lambda x: (x[0], x[1] != 'c'))
    c.frames = [x[2] for x in allf]
    c.frames_c, c.frames_s = cfr2, sfr2
    c.secret_mode = cmode
    return c


def decode_ticket_reply(d, ktype, secret, tl, what, sess, prev=None):
    """cephx 2.7 'ticket reply'; d is a Rd positioned at reply_v.  Returns list of ticket dicts."""
    rv = d.u8()
    num = d.u32()
    tl.chk('cephx 2.7: ticket reply version is 1 (%s)' % what, rv == 1)
    out = []
    for _ in range(num):
        svc = d.u32()
        tv = d.u8()
        msg_a = d.blob()
        enc = d.u8()
        blob_field = d.blob()
        tl.chk('cephx 2.7: ticket_v is 1 and ticket_enc is %s (%s)' % ('1 on a reclaim with a valid old ticket' if prev else '0', what),
               tv == 1 and enc == (1 if prev else 0))
        # blob_field is a bufferlist whose bytes are an encoded CephXTicketBlob (ticket_enc = 1: that bufferlist,
        # itself encrypted with the previous AUTH session key, usage 0x05)
        if enc == 1:
            ip, _ = wire.cx_unseal(prev[0], prev[1], 5, blob_field)
            ipr = Rd(ip)
            blob_field = ipr.blob()
            tl.chk('cephx 2.7: ticket_enc=1 plaintext is exactly one bufferlist', ipr.left() == 0)
        tb = Rd(blob_field)
        bv = tb.u8()
        sid = tb.u64()
        bl = tb.blob()
        tl.chk('cephx 2.7: ticket blob = u8 1 | u64 secret_id | blob, no trailing bytes', bv == 1 and tb.left() == 0)
        pt, _ = wire.cx_unseal(ktype, secret, 4, msg_a)
        t = Rd(pt)
        sv = t.u8()
        kt = t.u16()
        t.utime()
        ln = t.u16()
        ks = t.raw(ln)
        val = t.utime()
        tl.chk('cephx 2.7: CephXServiceTicket = u8 1 | CryptoKey | utime validity, no trailing bytes (%s)' % what,
               sv == 1 and t.left() == 0)
        tl.chk('cephx 2.3: session key length matches its type (16 for aes, 32 for aes256k)',
               (kt == 1 and ln == 16) or (kt == 2 and ln == 32), 'type=%d len=%d' % (kt, ln))
        out.append({'service': svc, 'sid': sid, 'blob': bl, 'ktype': kt, 'secret': ks, 'validity': val[0] + val[1] / 1e9})
    return out


# ----------------------------------------------------------------------------------------------------
# frames after authentication: idents, compression, messages
# ----------------------------------------------------------------------------------------------------

FEAT = {'SUBSCRIBE2': 4, 'MONNAMES': 5, 'MONENC': 15, 'SERVER_NAUTILUS_2': 2, 'SERVER_NAUTILUS_28': 28,
        'MON_STATEFUL_SUB/57': 57, 'MSG_ADDR2': 59, 'MSGR_KEEPALIVE2': 42, 'INCSUBOSDMAP': 10, 'PGID64': 9,
        'PGPOOL3': 11, 'OSDENC': 13}


def dec_ident(seg, server):
    r = Rd(seg)
    d = {}
    d['addrs'] = dec_addrvec(r, None)
    if not server:
        d['target'] = dec_entity_addr(r, None)
    d['gid'] = r.i64()
    d['global_seq'] = r.u64()
    d['supported'] = r.u64()
    d['required'] = r.u64()
    d['flags'] = r.u64()
    d['cookie'] = r.u64()
    d['trailing'] = r.left()
    return d


def analyze_post_auth(sess, c, tl, meta, tag):
    """CLIENT_IDENT / SERVER_IDENT / COMPRESSION_* / KEEPALIVE / MESSAGE frames of one connection"""
    c.msgs = []
    seqs = {'c': 0, 's': 0}
    ids = {}
    for fr in c.frames:
        if fr.tag in (21, 22):
            r = Rd(fr.segs[0])
            if fr.tag == 21:
                comp = r.u8()
                meths = [r.u32() for _ in range(r.u32())]
                c.comp_req = (comp, meths)
            else:
                comp = r.u8()
                meth = r.u32()
                c.comp_done = (comp, meth)
            tl.chk('msgr2: COMPRESSION_* payload has no trailing bytes', r.left() == 0)
        elif fr.tag == 8:
            d = dec_ident(fr.segs[0], False)
            ids['client'] = d
            c.cident = d
            tl.chk('msgr2: CLIENT_IDENT has no trailing bytes', d['trailing'] == 0)
        elif fr.tag == 9:
            d = dec_ident(fr.segs[0], True)
            ids['server'] = d
            c.sident = d
            tl.chk('msgr2: SERVER_IDENT has no trailing bytes', d['trailing'] == 0)
        elif fr.tag == 17:
            try:
                h = hdr2(fr.segs[0])
            except WireError as e:
                tl.chk('msgr2: MESSAGE header segment is 41 bytes', False, str(e))
                continue
            d = fr.dir
            seqs[d] += 1
            tl.chk('msgr2 2.9: MESSAGE seq counts 1,2,3.. per direction on a lossy session', h['seq'] == seqs[d],
                   '%s seq %d expect %d' % (d, h['seq'], seqs[d]))
            m = dict(h)
            m['dir'] = d
            m['nseg'] = len(fr.segs)
            m['front'] = fr.segs[1] if len(fr.segs) > 1 else b''
            m['middle'] = fr.segs[2] if len(fr.segs) > 2 else b''
            m['data_len'] = len(fr.segs[3]) if len(fr.segs) > 3 else 0
            m['data'] = fr.segs[3] if len(fr.segs) > 3 else b''
            m['ts'] = fr.ts
            m['align'] = fr.align
            m['wire_off'] = fr.start
            c.msgs.append(m)
        elif fr.tag in (18, 19):
            r = Rd(fr.segs[0])
            st = r.utime()
            tl.chk('msgr2: KEEPALIVE2 / ACK payload is exactly utime (8 bytes)', r.left() == 0 and len(fr.segs[0]) == 8)
            c.__dict__.setdefault('keepalive', []).append((fr.dir, fr.tag, fr.ts, st))
        elif fr.tag == 20:
            c.__dict__.setdefault('acks', []).append((fr.dir, fr.ts))
        else:
            tl.chk('msgr2: only expected tags after auth', False, fr.name)
    if 'client' in ids and 'server' in ids:
        cs_, ss_ = ids['client']['supported'], ids['server']['supported']
        c.features = cs_ & ss_
        sess.obs['client_ident'].append((meta['name'], c.peer, ids['client']))
        sess.obs['server_ident'].append((meta['name'], c.peer, ids['server']))
    return c


# ----------------------------------------------------------------------------------------------------
# monitor client checks (the subject of mon-client.md)
# ----------------------------------------------------------------------------------------------------

CRC_ONES = 0xFFFFFFFF
FEATURES_ALL = 0x3f07fffffffdffff     # msgr2.md 2.10 recommendation; compared with the observed CLIENT_IDENT


def enc_subscribe(what, host):
    """re-encode MMonSubscribe v3 exactly as the note describes (2.5.1)"""
    b = struct.pack('<I', len(what))
    for name, start, flags in what:
        nb = name.encode()
        b += struct.pack('<I', len(nb)) + nb + struct.pack('<QB', start, flags)
    hb = host.encode()
    return b + struct.pack('<I', len(hb)) + hb


def check_osdmap_blob(kind, key_epoch, blob, fsid, tl):
    """envelope / epoch / fsid / CRC of one OSDMap or Incremental blob (outer layer only; osdmap note 2.4, 2.6)"""
    r = Rd(blob)
    v, c, end = r.env()
    tl.chk('mon-client 2.6: %s blob is exactly one wrapper envelope (6 + struct_len = blob length)' % kind,
           end == len(blob), '%d vs %d' % (end, len(blob)))
    tl.chk('osdmap 2.4.2/2.6.2: %s wrapper written as struct_v 8, compat 7' % kind, (v, c) == (8, 7), '%d/%d' % (v, c))
    cv, cc, cend = r.env()
    f = r.uuid()
    e = r.u32()
    tl.chk('mon-client 2.6: %s fsid equals the MOSDMap fsid' % kind, f == fsid)
    tl.chk('mon-client 2.6: %s epoch equals its key in the MOSDMap map' % kind, e == key_epoch, '%d vs %d' % (e, key_epoch))
    if kind == 'full':
        crc = struct.unpack('<I', blob[-4:])[0]
        tl.chk('osdmap 2.4.5: full-map CRC = CRC-32C(seed 0xFFFFFFFF, wrapper bytes before the CRC), no final inversion',
               wire.crc32c(blob[:-4], CRC_ONES) == crc)
        tl.chk('osdmap 2.4.1: full map client block struct_v is 10 (v20.2.5 monitor, full feature set)', cv == 10, str(cv))
    else:
        inc_crc = struct.unpack('<I', blob[-8:-4])[0]
        calc = wire.crc32c(blob[-4:], wire.crc32c(blob[:-8], CRC_ONES))
        tl.chk('osdmap 2.6.1: inc_crc = CRC-32C(seed 0xFFFFFFFF) over wrapper up to inc_crc, continued over full_crc',
               calc == inc_crc)
        tl.chk('osdmap 2.6.3: incremental client block struct_v is 9', cv == 9, str(cv))
    return e


def parse_iso(s):
    m = re.match(r'(\d+)-(\d+)-(\d+)T(\d+):(\d+):(\d+)[.:](\d+)', s)
    import calendar
    y, mo, d, h, mi, se = (int(x) for x in m.groups()[:6])
    return calendar.timegm((y, mo, d, h, mi, se)), int(m.group(7).ljust(9, '0')[:9])


def check_monmap(d, raw, gt, tl, where):
    """compare one decoded MonMap with `ceph mon dump -f json` and the stored monmap bytes"""
    tl.chk('mon-client 2.4.1: MonMap struct_v = 10, struct_compat = 6', (d['struct_v'], d['compat']) == (10, 6),
           '%d/%d' % (d['struct_v'], d['compat']))
    tl.chk('mon-client 2.4.1: MonMap decodes with no bytes left inside struct_len after field 19', d['trailing'] == 0,
           str(d['trailing']))
    tl.chk('mon-client 2.4.1: persistent_features / optional_features are an envelope (v1, compat 1, len 8) + u64 mask',
           d['persistent_features_env'] == (1, 1, 8) and d['optional_features_env'] == (1, 1, 8),
           '%s %s' % (d['persistent_features_env'], d['optional_features_env']))
    if not gt:
        return
    j = gt['mon_dump']
    tl.chk('mon-client T2: MonMap fsid equals ceph mon dump', d['fsid'].replace('-', '') == j['fsid'].replace('-', ''))
    tl.chk('mon-client T2: MonMap epoch equals ceph mon dump', d['epoch'] == j['epoch'], '%s %s' % (d['epoch'], j['epoch']))
    cs, cn = parse_iso(j['created'])
    ms, mn = parse_iso(j['modified'])
    tl.chk('mon-client 2.4.1: created / last_changed are u32 sec + u32 nsec (match mon dump to the microsecond)',
           d['created'][0] == cs and d['created'][1] // 1000 == cn // 1000 and d['last_changed'][0] == ms and
           d['last_changed'][1] // 1000 == mn // 1000, '%s %s' % (d['created'], j['created']))
    tl.chk('mon-client 2.4.1: min_mon_release is the u8 release number (20 = tentacle)',
           d['min_mon_release'] == j['min_mon_release'] == 20)
    tl.chk('mon-client 2.4.1: strategy is u8 (1 = classic)', d['strategy'] == j['election_strategy'] == 1)
    tl.chk('mon-client 2.4.1 / Q15: removed_ranks (set<u32>), disallowed_leaders and stretch_marked_down_mons decode as '
           'u32 count + elements (empty here, count 0 confirmed)',
           d['removed_ranks'] == [] and d['disallowed_leaders'] == [] and d['stretch_marked_down_mons'] == [] and
           j['removed_ranks'] == '' and j['disallowed_leaders'] == '')
    tl.chk('mon-client 2.4.1: stretch_mode_enabled is a u8 bool and tiebreaker_mon an (empty) string',
           d['stretch_mode_enabled'] == 0 and d['tiebreaker_mon'] == '' and j['stretch_mode'] is False)
    tl.chk('mon-client 2.4.1: auth_epoch u32, auth_service_cipher i32',
           d['auth_epoch'] == j['auth_epoch'] and d['auth_service_cipher'] == j['auth_service_cipher']['value'])
    tl.chk('mon-client 2.4.1 / Q15: auth_allowed_ciphers is vector<i32> = u32 count + i32 elements (denc vector '
           'is byte-identical to the generic one for vector<i32>)',
           d['auth_allowed_ciphers'] == [x['value'] for x in j['auth_allowed_ciphers']] == [1, 2])
    tl.chk('mon-client 2.4.1: auth_preferred_cipher i32', d['auth_preferred_cipher'] == j['auth_preferred_cipher']['value'])
    tl.chk('mon-client 2.4.1: persistent_features is a u64 mask whose population count equals the number of names mon '
           'dump lists; optional_features = 0 matches the empty optional list',
           bin(d['persistent_features']).count('1') == len(j['features']['persistent']) and
           d['optional_features'] == 0 and j['features']['optional'] == [])
    mons = j['mons']
    tl.chk('mon-client 2.4.1: ranks vector equals the monitor names in rank order',
           d['ranks'] == [m['name'] for m in sorted(mons, key=lambda m: m['rank'])])
    tl.chk('mon-client 2.4.1: mon_info has one entry per monitor, key = monitor name', sorted(d['mon_info']) == sorted(
        m['name'] for m in mons))
    for m in mons:
        mi = d['mon_info'].get(m['name'])
        ok = mi is not None
        tl.chk('mon-client 2.4.2: mon_info_t is envelope v6 compat 1 with name, addrvec, priority, weight, crush_loc, '
               'time_added', ok and (mi['v'], mi['compat']) == (6, 1))
        if not ok:
            continue
        tl.chk('mon-client 2.4.2: mon_info_t name equals its map key', mi['name'] == m['name'])
        tl.chk('mon-client 2.4.2: priority / weight (u16) equal mon dump', mi['priority'] == m['priority'] and
               mi['weight'] == m['weight'])
        av = m['public_addrs']['addrvec']
        tl.chk('mon-client 2.4.3: address vector = same entries and order as mon dump (v2 first, then v1)',
               len(av) == len(mi['addrs']) and all(
                   {'v2': 2, 'v1': 1}[a['type']] == b['type'] and b['nonce'] == a['nonce'] and
                   '%s:%d' % (b['ip'], b['port']) == a['addr'] for a, b in zip(av, mi['addrs'])),
               str(mi['addrs']))
        tl.chk('mon-client 2.4.3: IPv4 entity_addr_t: struct_v 1 compat 1, elen 16, family 2, sa_data = port (big endian) '
               '+ 4 address bytes + 8 zero bytes (Q16, IPv4 part)',
               all(a['v'] == 1 and a['compat'] == 1 and a['elen'] == 16 and a['family'] == 2 and a['sa_len'] == 14 and
                   a['pad_zero'] for a in mi['addrs']))
        sec, nsec = parse_iso(m['time_added'])
        tl.chk('mon-client 2.4.2: time_added is utime (sec + nsec)',
               mi['time_added'][0] == sec and mi['time_added'][1] // 1000 == nsec // 1000, '%s %s' % (mi['time_added'], m['time_added']))
        tl.chk('mon-client 2.4.2: crush_loc map is empty here (count 0)', mi['crush_loc'] == {} and m['crush_location'] == [])
    if gt.get('monmap_bin') is not None:
        tl.chk('mon-client 2.4: the MonMap blob on the wire is byte-identical to the stored map (ceph mon getmap) '
               'at the same epoch', raw == gt['monmap_bin'] if d['epoch'] == j['epoch'] else True)


def check_mon_conn(sess, c, tl, meta, st, gt):
    msgs = sorted(c.msgs, key=lambda m: (m['ts'], m['dir'] != 'c', m['seq']))
    cm = [m for m in msgs if m['dir'] == 'c']
    sm = [m for m in msgs if m['dir'] == 's']
    name = meta['name']
    ctypes = [m['type'] for m in cm]
    stypes = [m['type'] for m in sm]
    st['mon_conns'] += 1
    if cm:
        tl.chk('mon-client 3.3.1: the first message a client sends on a new monitor connection is MMonGetMap (5)',
               ctypes[0] == 5, str(ctypes[:3]))
    # ---- headers
    for m in msgs:
        if m['dir'] == 'c':
            tl.chk('mon-client 2.1: messages the client sends carry priority 127 (default applied at send)',
                   m['prio'] == 127, 'type %d prio %d' % (m['type'], m['prio']))
        if m['dir'] == 's':
            tl.chk('mon-client 2.1 (correction): every message the monitor sends carries priority 196 (CEPH_MSG_PRIO_HIGH)',
                   m['prio'] == 196, 'type %d prio %d' % (m['type'], m['prio']))
        tl.chk('mon-client 2.1: data_pre_padding_len and reserved are zero', m['pre_pad'] == 0 and m['reserved'] == 0)
        tl.chk('mon-client 2.1: tid is 0 for every monitor-client message except MMonCommand (tid counted from 1) and '
               'the reply to it', m['tid'] == 0 or m['type'] in (50, 51), 'type %d tid %d' % (m['type'], m['tid']))
        tl.chk('mon-client 2.1: data_off is 0 on messages without a data segment', m['data_len'] != 0 or m['data_off'] == 0,
               'type %d off %d' % (m['type'], m['data_off']))
        st['prio'][(m['dir'], m['type'], m['prio'])] += 1
        st['hdrflags'][m['flags']] += 1
        st['types'][(m['dir'], m['type'], m['version'], m['compat'])] += 1
        exp = {5: (1, 1), 4: (1, 1), 17: (1, 1), 18: (1, 1), 19: (1, 1), 20: (2, 2), 62: (1, 1), 6: (1, 1), 15: (3, 1),
               41: (4, 3)}.get(m['type'])
        if exp:
            tl.chk('mon-client 2.2 / 2.1: header version / compat_version per type: 5, 4, 17, 18, 62 = 1/1 (a class '
                   'without compat goes out with compat = version); 15 = 3/1; 41 = 4/3',
                   (m['version'], m['compat']) == exp, 'type %d v%d/c%d' % (m['type'], m['version'], m['compat']))
    # ---- per type
    subs = []
    monmaps = []
    mosd = []
    cfg = []
    for m in msgs:
        t = m['type']
        if t == 5:
            tl.chk('mon-client 2.3: MMonGetMap is header version 1 / compat 1 with an empty body (one segment only)',
                   m['version'] == 1 and m['compat'] == 1 and m['nseg'] == 1)
        elif t == 15:
            d = dec_subscribe(m['front'], m['version'])
            tl.chk('mon-client 2.5.1: MMonSubscribe is header version 3 / compat 1', (m['version'], m['compat']) == (3, 1))
            tl.chk('mon-client 2.5.1: body = map<string, 9-byte item> + hostname string, exactly (re-encoding the decoded '
                   'fields reproduces the wire bytes)',
                   d['trailing'] == 0 and enc_subscribe(d['what'], d['hostname']) == m['front'])
            tl.chk('mon-client 2.5.1: item flags are 0 (continuous) or 1 (ONETIME) only', all(f in (0, 1) for _, _, f in d['what']))
            tl.chk('mon-client 2.5.1: subscription names are among monmap / osdmap / config / mgrmap',
                   all(n in ('monmap', 'osdmap', 'config', 'mgrmap') for n, _, _ in d['what']), str(d['what']))
            tl.chk('mon-client 2.5.1: map entries are in key order on the wire (sorted by name)',
                   [n for n, _, _ in d['what']] == sorted(n for n, _, _ in d['what']))
            tl.chk('mon-client 2.5.1: hostname is a short host name string (informational, may be empty)', True)
            d['ts'] = m['ts']
            subs.append(d)
            st['subs'].append((name, c.idx, m['seq'], d['what'], d['hostname']))
            for n, start, fl in d['what']:
                if n == 'monmap':
                    tl.chk('mon-client 3.3: monmap subscription start = 0 with no real map held, else held epoch + 1 (a held '
                           'map exists only after a reconnect within one process); flags 0 (continuous)',
                           start in (0, st['monmap_epoch'] + 1) and fl == 0,
                           'start %d held %d flags %d' % (start, st['monmap_epoch'], fl))
                elif n == 'config':
                    tl.chk('mon-client 3.3: config subscription start 0, flags 0 (reference client)', start == 0 and fl == 0)
                elif n == 'osdmap':
                    tl.chk('mon-client 3.5.3: osdmap subscription start = 0 (no map held yet) or held epoch + 1',
                           start in (0, st['have'] + 1), 'start %d held %d' % (start, st['have']))
                    tl.chk('mon-client 3.5.3: reference client subscribes to osdmap with ONETIME (flag 1) unless the map '
                           'says full/paused', fl == 1, str(fl))
                    st['osd_sub_start'] = start
                    st['osd_sub_ts'] = m['ts']
                    st['osd_sub_conn'] = c.idx
        elif t == 4:
            r = Rd(m['front'])
            try:
                b = r.blob()
                tl.chk('mon-client 2.4: MMonMap body is exactly one bufferlist (u32 length + MonMap), version 1 / compat 1',
                       r.left() == 0 and (m['version'], m['compat']) == (1, 1))
                d = dec_monmap(b, tl)
            except WireError as e:
                tl.chk('mon-client 2.4.1: MonMap decodes', False, '%s: %s' % (name, e))
                continue
            check_monmap(d, b, gt, tl, name)
            monmaps.append(d)
            st['monmap_epoch'] = max(st['monmap_epoch'], d['epoch'])
            st['fsid'] = d['fsid']
            st['monmaps'].append((name, c.idx, hashlib.sha256(b).hexdigest(), d['epoch'], len(b)))
        elif t == 41:
            try:
                d = dec_mosdmap(m['front'], m['version'])
            except WireError as e:
                tl.chk('mon-client 2.6: MOSDMap decodes', False, '%s: %s' % (name, e))
                continue
            d['ts'] = m['ts']
            mosd.append(d)
            tl.chk('mon-client 2.6: MOSDMap header version 4 / compat 3 (full-feature client)',
                   (m['version'], m['compat']) == (4, 3))
            tl.chk('mon-client 2.6: removed-snaps gap is exactly 4 zero bytes (u32 0) and nothing follows',
                   d['gap_count'] == 0 and d['trailing'] == 0)
            tl.chk('mon-client 2.6: MOSDMap fsid equals the monmap fsid of the session',
                   st['fsid'] is None or d['fsid'] == st['fsid'])
            keys = sorted(set(d['inc']) | set(d['full']))
            tl.chk('mon-client 2.6: every epoch appears at most once (incremental or full), epochs are contiguous',
                   not (set(d['inc']) & set(d['full'])) and keys == list(range(keys[0], keys[-1] + 1)) if keys else False)
            tl.chk('mon-client 2.6: cluster_osdmap_trim_lower_bound <= lowest epoch <= highest epoch <= newest_map',
                   keys and d['trim_lower'] <= keys[0] and keys[-1] <= d['newest'], '%s %s %s' % (d['trim_lower'], keys[:1], d['newest']))
            for e, b in d['inc'].items():
                check_osdmap_blob('inc', e, b, d['fsid'], tl)
                st['osd_blobs'].append(('inc', e, hashlib.sha256(b).hexdigest(), len(b), b if len(b) < 200000 else None, name))
            for e, b in d['full'].items():
                check_osdmap_blob('full', e, b, d['fsid'], tl)
                st['osd_blobs'].append(('full', e, hashlib.sha256(b).hexdigest(), len(b), b if len(b) < 200000 else None, name))
            if keys:
                st['have'] = max(st['have'], keys[-1])
            # reply to a start-0 subscription (3.5.1 row 1)
            if st.get('osd_sub_start') == 0 and st.get('osd_sub_conn') == c.idx and not st.get('osd_sub_answered'):
                st['osd_sub_answered'] = True
                tl.chk('mon-client 3.5.1 / T6: a start-0 osdmap subscription is answered with ONE message holding only the '
                       'newest full map (maps has one entry, incremental_maps empty), trim bound and newest_map set',
                       len(d['full']) == 1 and not d['inc'] and d['trim_lower'] >= 1 and d['newest'] == keys[-1],
                       '%s' % (sorted(d['full']), ))
                tl.chk('mon-client 3.5.1 / T6: ... and that reply comes after the subscribe, within 50 ms',
                       0 <= m['ts'] - st['osd_sub_ts'] < 0.05)
            elif st.get('osd_sub_start', 0) > 0:
                st['osd_nonzero_replies'] += 1
        elif t == 62:
            cfg.append(m)
        elif t == 16:
            tl.chk('mon-client 2.5.2: no MMonSubscribeAck is ever received (client advertises MON_STATEFUL_SUB)', False)
        elif t == 51:
            if 1000 < m['data_len'] < 100000:
                st['cmd_blobs'].append(m['data'])
        elif t in (50, 1796):
            pass
        elif t == 17:
            check_mauth(sess, c, m, tl, meta, st)
        elif t == 18:
            check_mauth_reply(sess, c, m, tl, meta, st)
        else:
            tl.chk('mon-client 2.2: monitor sent only message types in the table or the known extras', t in (4, 18, 16, 20, 41, 62, 51, 1796),
                   'type %d' % t)
    # ---- counts of MMonMap
    has_getmap = 5 in ctypes
    mm_sub = [s for s in subs if any(n == 'monmap' for n, _, _ in s['what'])]
    if has_getmap and mm_sub and 4 in stypes:
        first_mm_sub = mm_sub[0]
        starts = [start for n, start, f in first_mm_sub['what'] if n == 'monmap']
        want = 2 if starts and starts[0] == 0 else 1
        if starts and starts[0] > 0 and monmaps and starts[0] <= monmaps[0]['epoch']:
            want = 2
        tl.chk('mon-client 3.4 / Q17: a fresh session gets TWO MMonMap (answer to MMonGetMap + push for the monmap '
               'subscription) when the subscription start is 0; ONE when start = held epoch + 1 is above the map epoch',
               len(monmaps) == want, '%d monmap(s), start %s' % (len(monmaps), starts))
        if len(monmaps) == 2:
            tl.chk('mon-client 3.4: the two MMonMap carry the same epoch (idempotent handling is enough)',
                   monmaps[0]['epoch'] == monmaps[1]['epoch'])
    # ---- every monitor message answers something the client sent (nothing unsolicited)
    subnames = {n for sb in subs for n, _, _ in sb['what']}
    just = {4: (5 in ctypes) or ('monmap' in subnames), 62: 'config' in subnames, 1796: 'mgrmap' in subnames,
            41: 'osdmap' in subnames, 51: 50 in ctypes, 18: 17 in ctypes}
    for t_ in sorted(set(stypes)):
        tl.chk('mon-client 2.2 / Q3: every message type the monitor sends on a session is justified by a request or a '
               'subscription the client sent first (4 <- GetMap/monmap, 62 <- config, 41 <- osdmap, 51 <- command, '
               '18 <- MAuth, mgrmap push <- mgrmap)', just.get(t_, False), 'type %d' % t_)
    # ---- config
    if cfg:
        tl.chk('mon-client 2.2 / Q3: MConfig (62) arrives only when the client subscribed to "config"',
               any(n == 'config' for s in subs for n, _, _ in s['what']))
    if any(n == 'config' for s in subs for n, _, _ in s['what']):
        tl.chk('mon-client 2.5.1: a "config" subscription is answered with one MConfig (62)', len(cfg) >= 1)
    # ---- unsolicited traffic right after the handshake (Q3): before the first client message, anything from the mon?
    if cm:
        pre = [m for m in sm if m['ts'] < cm[0]['ts'] - 0.0005 and m['seq'] <= 1]
        tl.chk('mon-client Q3: the monitor sends no message before the client has sent its first (nothing unsolicited '
               'after the handshake)', not pre)
    # ---- keepalive
    ka = getattr(c, 'keepalive', [])
    kc = [k for k in ka if k[0] == 'c' and k[1] == 18]
    ks = [k for k in ka if k[0] == 's' and k[1] == 19]
    if kc:
        tl.chk('mon-client 3.6: every client KEEPALIVE2 (18) is answered by KEEPALIVE2_ACK (19) echoing the same utime',
               [k[3] for k in kc] == [k[3] for k in ks], '%d vs %d' % (len(kc), len(ks)))
        for a, b in zip(kc, ks):
            tl.chk('mon-client 3.6: the ack follows the keepalive within 50 ms', 0 <= b[2] - a[2] < 0.05, '%.4f' % (b[2] - a[2]))
            tl.chk('mon-client 3.6: the keepalive stamp is the sender wall clock (within 1 s of the capture time)',
                   abs(a[3][0] - a[2]) < 1.0, '%s %s' % (a[3][0], a[2]))
        for a, b in zip(kc, kc[1:]):
            tl.chk('mon-client 3.6: keepalives are 10 s apart (mon_client_ping_interval 10 s, tick 1 s)',
                   9.9 <= b[2] - a[2] <= 11.1, '%.3f' % (b[2] - a[2]))
        st['ka_first'].append(kc[0][2] - c.flow.first_ts)
        tl.info('first KEEPALIVE2 on a monitor connection goes out %.1f s after the TCP connect (idle sessions); later ones every '
                '10.0 s' % round(kc[0][2] - c.flow.first_ts, 0))
        st['ka_count'] += len(kc)
    # ---- subscribe for the session
    st['conn_summary'].append((name, c.idx, ctypes, stypes))


def check_mauth(sess, c, m, tl, meta, st):
    """MAuth (17) on an established mon session: renewal (note 3.8)"""
    r = Rd(m['front'])
    p = dec_paxos_prefix(r)
    proto = r.u32()
    pay = r.blob()
    mep = r.u32()
    tl.chk('mon-client 3.8.2: MAuth = PaxosServiceMessage prefix (u64 0, i16 -1, u64 0) + protocol 2 + auth_payload + '
           'monmap_epoch, no trailing bytes', p == {'version': 0, 'session_mon': -1, 'tid': 0} and proto == 2 and r.left() == 0,
           '%s proto %d left %d' % (p, proto, r.left()))
    tl.chk('mon-client 3.8.2 / cephx 2.11: MAuth header version 1 and wire compat_version 1', (m['version'], m['compat']) == (1, 1))
    tl.chk('mon-client 3.8.2: monmap_epoch is 0 on a renewal', mep == 0, str(mep))
    q = Rd(pay)
    rt = q.u16()
    tl.chk('cephx 3.6 B: renewal payload starts with CephXRequestHeader 0x0200', rt == 0x0200, hex(rt))
    av = q.u8()
    gid = q.u64()
    svc = q.u32()
    tv = q.u8()
    sid = q.u64()
    tb = q.blob()
    proof = q.blob()
    tl.chk('cephx 3.6 B: authorizer for service AUTH (0x20), global_id and ticket = the held AUTH ticket',
           av == 1 and svc == 0x20 and gid == c.global_id and sid == c.auth_secret_id and tb == c.auth_blob,
           'svc %#x gid %s sid %s' % (svc, gid, sid))
    pt, _ = wire.cx_unseal(c.auth_key[0], c.auth_key[1], 0x10, proof)
    a = Rd(pt)
    a.u8()
    a.u64()
    hc = a.u8()
    pl = a.u64()
    tl.chk('cephx 3.6 B: authorizer proof (usage 0x10, AUTH session key) has no challenge: have_challenge 0, plus_one 0',
           hc == 0 and pl == 0)
    tv_ = q.u8()
    keys = q.u32()
    tl.chk('cephx 3.6 B: CephXServiceTicketRequest v1 + key mask without the AUTH bit, nothing after',
           tv_ == 1 and keys & 0x20 == 0 and q.left() == 0, 'v%d keys %#x left %d' % (tv_, keys, q.left()))
    tl.info('MAuth renewal by the python rados client asks for service mask %#x (MON|OSD|MGR = 0x15 expected; AUTH bit clear)'
            % keys)
    st['mauth'].append((c.idx, m['ts'], keys))
    st['mauth_pending'] = (c.idx, m['ts'], keys)


def check_mauth_reply(sess, c, m, tl, meta, st):
    r = Rd(m['front'])
    proto = r.u32()
    res = r.i32()
    gid = r.u64()
    rbl = r.blob()
    msg = r.string()
    tl.chk('mon-client 3.8.3: MAuthReply = u32 protocol 2, s32 result 0, u64 global_id (= ours), bufferlist, string; '
           'header version 1 / compat 1',
           proto == 2 and res == 0 and gid == c.global_id and r.left() == 0 and (m['version'], m['compat']) == (1, 1),
           'proto %d res %d gid %s' % (proto, res, gid))
    q = Rd(rbl)
    rt = q.u16()
    status = q.i32()
    tl.chk('cephx 2.7: renewal reply = CephXResponseHeader (0x0200, status 0) + ticket reply', rt == 0x0200 and status == 0)
    keys = decode_ticket_reply(q, c.auth_key[0], c.auth_key[1], tl, 'renewal', sess)
    tl.chk('cephx 2.7: renewal ticket reply is under the AUTH session key (usage 4) with ticket_enc 0 and no trailing bytes',
           q.left() == 0)
    pend = st.get('mauth_pending')
    tl.chk('mon-client 3.8: the MAuthReply answers the MAuth (one outstanding at a time)', pend is not None)
    if pend:
        mask = pend[2]
        tl.chk('cephx 3.6 B: tickets returned = exactly the services in the request mask',
               sorted(k['service'] for k in keys) == sorted(b for b in (1, 2, 4, 8, 16) if mask & b),
               '%s vs %#x' % ([hex(k['service']) for k in keys], mask))
        # timing against the validity the previous tickets were issued with
        val = max([k['validity'] for k in keys] or [0])
        base = st.get('ticket_base_ts')
        if base is None:
            base = c.auth_done_ts
        delay = pend[1] - base
        tl.chk('mon-client 3.8.1: renewal request goes out at expiry - validity/4, i.e. about 0.75 x validity after the '
               'tickets were received (validity %.0f s, observed %.2f s)' % (val, delay),
               val > 0 and 0.75 * val - 0.5 <= delay <= 0.75 * val + 2.0, '%.2f vs %.1f' % (delay, 0.75 * val))
        st['ticket_base_ts'] = m['ts']
        st['mauth_pending'] = None
    st['mauth_replies'] += 1


# ----------------------------------------------------------------------------------------------------
# per-session driver
# ----------------------------------------------------------------------------------------------------

def new_state():
    return {'mon_conns': 0, 'prio': collections.Counter(), 'hdrflags': collections.Counter(),
            'types': collections.Counter(), 'subs': [], 'monmap_epoch': 0, 'fsid': None, 'have': 0, 'monmaps': [],
            'osd_blobs': [], 'osd_nonzero_replies': 0, 'conn_summary': [], 'ka_first': [], 'ka_count': 0,
            'mauth': [], 'mauth_replies': 0, 'cmd_blobs': [], 'ident': [], 'compress': [], 'notes': []}


def find_keyring(cap, lab_dir, name, entity):
    ident = entity.split('.', 1)[1]
    keys_dir = os.path.join(cap, 'secrets', 'keys')
    cands = []
    if 'wrongkey' in name:
        cands.append(os.path.join(keys_dir, 'wrong.%s.keyring' % ident))
        cands.append(os.path.join(lab_dir, 'wrong.%s.keyring' % ident))   # public set: keys/wrong.<id>.keyring
    cands.append(os.path.join(lab_dir, 'client.%s.keyring' % ident))
    cands.append(os.path.join(keys_dir, 'ceph.client.%s.keyring' % ident))
    for p in cands:
        if os.path.exists(p):
            return p
    return None


def load_gt(cap):
    gt = {}
    try:
        with open(os.path.join(cap, 'gt', 'mon-dump.json')) as f:
            gt['mon_dump'] = json.load(f)
        with open(os.path.join(cap, 'gt', 'monmap.bin'), 'rb') as f:
            gt['monmap_bin'] = f.read()
    except OSError:
        return None
    gt['cap'] = cap
    return gt


def read_file(p):
    try:
        with open(p, 'rb') as f:
            return f.read()
    except OSError:
        return None


def decode_session(cap, lab_dir, name, meta, tl, st):
    """TCP -> msgr2 -> cephx for every connection of one pcap.  Returns (Session, flows, {idx: Conn})."""
    kp = find_keyring(cap, lab_dir, name, meta['entity'])
    e, kt, sec = load_keyring(kp)
    sess = Session(meta['entity'], kt, sec, tl)
    flows = wire.tcp_streams(os.path.join(cap, 'pcap', name + '.pcap'))
    st['nflows'] = len(flows)
    st['retrans'] = sum(f.c2s.retrans + f.s2c.retrans for f in flows)
    order = sorted(range(len(flows)), key=lambda i: (flows[i].server[1] not in (3300, 6789), flows[i].first_ts))
    conns = {}
    for i in order:
        conns[i] = analyze_conn(sess, flows[i], i, meta, tl)
    return sess, flows, conns


def analyze_session(args):
    cap, lab_dir, name, meta, only_flag = args
    tl = Tally()
    st = new_state()
    try:
        kp = find_keyring(cap, lab_dir, name, meta['entity'])
        if kp is None:
            tl.chk('setup: keyring for %s found' % meta['entity'], False, name)
            return name, tl.d, dict(tl.notes), st
        sess, flows, conns = decode_session(cap, lab_dir, name, meta, tl, st)
        gt = load_gt(cap)
        # post-auth + per-peer checks in time order
        for i in sorted(conns, key=lambda i: flows[i].first_ts):
            c = conns[i]
            if not c.ok_auth or c.short:
                continue
            analyze_post_auth(sess, c, tl, meta, name)
            if getattr(c, 'cident', None):
                st['ident'].append((name, c.peer, c.cident['supported'], c.sident['supported'] if getattr(c, 'sident', None) else None,
                                    c.cident['required'], c.cident['flags'], c.cident['cookie'], c.cident['gid'],
                                    c.cident['global_seq'], c.mode))
            if hasattr(c, 'comp_req'):
                st['compress'].append((c.comp_req, getattr(c, 'comp_done', None), c.banner[0][0]))
            if c.peer == 'mon':
                check_mon_conn(sess, c, tl, meta, st, gt)
            tl.chk('framing: every connection ends on a frame boundary (no partial frame at the end of either stream)',
                   (getattr(c, 'c2s_leftover', 0) == 0 or c.flow.c2s.gap_at is not None) and
                   (getattr(c, 's2c_leftover', 0) == 0 or c.flow.s2c.gap_at is not None),
                   '%s conn %d c2s %s s2c %s' % (name, i, getattr(c, 'c2s_leftover', None), getattr(c, 's2c_leftover', None)))
        # features
        for item in st['ident']:
            _, peer, cs_, ss_, creq, cfl, cck, cgid, cgs, mode = item
            if peer != 'mon':
                continue
            tl.chk('mon-client Q1 / msgr2 2.10: CLIENT_IDENT.supported of the stock client = 0x3f07fffffffdffff',
                   cs_ == FEATURES_ALL, hex(cs_))
            tl.chk('mon-client Q1: the monitor SERVER_IDENT.supported contains every bit of the note 2.9 table (incl. the '
                   'incarnation marker bits 2, 28, 57)', all(ss_ >> b & 1 for b in FEAT.values()), hex(ss_ or 0))
            tl.chk('mon-client Q1: client supported & server supported contains every bit of the 2.9 table',
                   all((cs_ & ss_) >> b & 1 for b in FEAT.values()))
            tl.chk('mon-client 2.9: SERVER_NAUTILUS needs bits 2, 28 and 57 together (all set in the negotiated mask)',
                   all((cs_ & ss_) >> b & 1 for b in (2, 28, 57)))
        # ---- session-specific scenarios
        monconns = [conns[i] for i in sorted(conns, key=lambda i: flows[i].first_ts)
                    if conns[i].ok_auth and conns[i].peer == 'mon']
        if name.endswith('mon-restart'):
            check_restart(monconns, tl, st)
        if name.startswith('x-t0-noosd') or name.startswith('x-t0-ro'):
            check_caps(name, [conns[i] for i in conns], monconns, tl)
        if name.endswith('-renew-ttl60'):
            tl.chk('mon-client 3.8 / T14: at least three in-session MAuth renewals in 150 s with a 60 s ticket ttl',
                   len(st['mauth']) >= 3 and st['mauth_replies'] == len(st['mauth']), str(len(st['mauth'])))
        if name.endswith('idle75'):
            tl.chk('mon-client T13: an idle 75 s monitor session carries at least 6 keepalive round trips',
                   st['ka_count'] >= 6, str(st['ka_count']))
        if name.endswith('ceph-cli'):
            ref = read_file(os.path.join(cap, 'data', 'getmap.%s.bin' % name[:2]))
            gtm = read_file(os.path.join(cap, 'gt', 'osdmap.bin'))
            full = [b for k_, e_, s_, l_, b, n_ in st['osd_blobs'] if k_ == 'full' and b is not None]
            tl.chk('osdmap 2.8 / T9: the full map delivered by `ceph osd getmap` (MMonCommandAck data segment) is byte-'
                   'identical to the file the tool wrote, to the stored epoch-42 map, and to the full map the monitor pushed '
                   'for the osdmap subscription', ref in st['cmd_blobs'] and ref == gtm and bool(full) and full[0] == gtm)
        st['cmd_blobs'] = []
        # MOSDMap blobs against the monitor-store copies
        for kind, ep, sha, ln, blob, nm in st['osd_blobs']:
            fn = os.path.join(cap, 'gt3', 'full' if kind == 'full' else 'inc', '%s.%05d.bin' % (kind, ep))
            ref = read_file(fn)
            if ref is not None and blob is not None:
                tl.chk('mon-client 2.6 / osdmap 2.8: the %s blob in MOSDMap is byte-identical to the monitor-store copy of '
                       'that epoch when the client advertises the full feature mask' % kind, blob == ref,
                       '%s e%d' % (kind, ep))
        for kind, ep, sha, ln, blob, nm in st['osd_blobs']:
            st.setdefault('blob_keys', []).append((kind, ep, sha, ln))
            # do not ship raw bytes back
        st['osd_blobs'] = [(k, e_, s_, l_) for k, e_, s_, l_, b_, n_ in st['osd_blobs']]
    except Exception as ex:   # noqa
        import traceback
        tl.chk('session analysis completes without an exception', False, '%s: %s: %s' % (name, type(ex).__name__, ex) +
               traceback.format_exc().splitlines()[-3])
    for k in ('prio', 'hdrflags', 'types'):
        st[k] = dict(st[k])
    return name, tl.d, dict(tl.notes), st


def check_restart(monconns, tl, st):
    """T12 / T15: monitor restart under an open session"""
    tl.chk('mon-client T12: a monitor restart under an open session leads to a new monitor connection', len(monconns) >= 2)
    if len(monconns) < 3:
        return
    # the long-lived connection is the one that carried the osdmap subscription; the reconnect is the last one
    last = monconns[-1]
    prev = [c for c in monconns[:-1] if c.global_id is not None]
    tl.chk('mon-client 3.9 / T15: the reconnect asks for the stored global_id and presents the old AUTH ticket '
           '(CephXAuthenticate v3 old_ticket non-empty), and the monitor hands the same id back',
           last.req_gid != 0 and last.req_gid in [p.global_id for p in prev] and last.old_ticket_len > 0 and
           last.global_id == last.req_gid, 'req %s got %s old %s' % (last.req_gid, last.global_id, last.old_ticket_len))
    ct = [m['type'] for m in sorted(last.msgs, key=lambda m: m['ts']) if m['dir'] == 'c']
    tl.chk('mon-client 3.3 / 3.7 / T12: after the reconnect the client sends MMonGetMap first and re-sends its subscriptions',
           ct[:2] == [5, 15], str(ct))
    subs = [dec_subscribe(m['front'], m['version']) for m in last.msgs if m['dir'] == 'c' and m['type'] == 15]
    w = {n: (s, f) for sb in subs for n, s, f in sb['what']}
    tl.chk('mon-client 3.7: re-sent subscriptions ask for held + 1: monmap start = 4 (held epoch 3), continuous; '
           'osdmap start 93 (held 92), ONETIME; config 0; mgrmap 0',
           w.get('monmap') == (4, 0) and w.get('osdmap') == (93, 1) and w.get('config') == (0, 0) and w.get('mgrmap') == (0, 0),
           str(w))
    nmm = sum(1 for m in last.msgs if m['dir'] == 's' and m['type'] == 4)
    tl.chk('mon-client 3.4: with monmap start = held + 1 only the MMonGetMap answer arrives (one MMonMap, no push)', nmm == 1,
           str(nmm))
    nosd = sum(1 for m in last.msgs if m['dir'] == 's' and m['type'] == 41)
    tl.chk('mon-client 3.5.1 row 5 / T6: an osdmap subscription with start above the newest epoch gets nothing now',
           nosd == 0, str(nosd))


def check_caps(name, conns, monconns, tl):
    """T8: user with mon 'r' only (no osd caps) and user with osd read-only caps"""
    got41 = 0
    sub = 0
    for c in monconns:
        for m in c.msgs:
            if m['dir'] == 'c' and m['type'] == 15:
                sub += sum(1 for n, _, _ in dec_subscribe(m['front'], m['version'])['what'] if n == 'osdmap')
            if m['dir'] == 's' and m['type'] == 41:
                got41 += 1
    tl.chk('mon-client 2.5.1 / T8 (CORRECTION): an "osdmap" subscription is answered for a user whose caps are only '
           '"mon r" (no osd caps at all) and for "mon r, osd r pool=winrbd" - MOSDMap is delivered in both; the "osd" '
           'read capability of the note is satisfied by plain mon r', sub >= 1 and got41 >= 1, '%d subs %d maps' % (sub, got41))
    if name.startswith('x-t0-noosd'):
        bad = [c for c in conns if c.peer == 'osd' and getattr(c, 'bad_method', None)]
        tl.chk('cephx 3.1: a user without OSD caps gets its OSD connections refused with AUTH_BAD_METHOD result -13 '
               '(the OSDs reject the ticket), not a silent hang at the monitor',
               bool(bad) and all(c.bad_method[1] == -13 for c in bad), str(len(bad)))


# ----------------------------------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------------------------------

def load_sessions(cap):
    out = {}
    with open(os.path.join(cap, 'sessions.tsv')) as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) < 6:
                continue
            out[p[0]] = {'name': p[0], 'ktype': p[1], 'entity': p[2], 'mode': p[3], 'ncmds': p[4], 'debug': p[5],
                         'desc': p[10] if len(p) > 10 else ''}
    return out


def global_checks(cap, results, tl, verbose):
    """checks that need several sessions"""
    # every session's MonMap blob is the same bytes
    shas = collections.Counter()
    for name, d, notes, st in results:
        for _, _, sha, ep, ln in st['monmaps']:
            shas[(sha, ep, ln)] += 1
    tl.chk('mon-client T2: every MMonMap in the whole capture set carries the same single-monitor map (epoch 3, one sha256) '
           '- no map change happened during the runs', len(shas) == 1, str(list(shas)))
    # features
    idents = [i for _, _, _, st in results for i in st['ident']]
    byp = collections.Counter((i[1], hex(i[4]), i[5], i[6] != 0) for i in idents)
    for (peer, req, fl, ck), n in sorted(byp.items()):
        tl.info('CLIENT_IDENT of the stock client to a %s: required=%s flags=%d cookie %s (x%d)  [msgr2.md 2.7 predicts '
                'required 0x0800000000001000, flags 1, cookie 0]' % (peer, req, fl, 'non-zero' if ck else '0', n))
    comp = [c for _, _, _, st in results for c in st['compress']]
    tl.chk('msgr2 2.2: the stock client always sends COMPRESSION_REQUEST because every v20.2.5 server advertises the bit; '
           'the answer is "no compression"',
           comp and all(c[1] is not None and c[1][0] == 0 for c in comp), str(comp[:2]))
    # unexpected message types on monitor sessions
    seen = collections.Counter()
    for _, _, _, st in results:
        for k, v in st['types'].items():
            seen[k] += v
    sv = {k[1] for k in seen if k[0] == 's'}
    cv = {k[1] for k in seen if k[0] == 'c'}
    tl.chk('mon-client 2.2: messages seen from the monitor over the whole set are only types 4, 18, 41, 51, 62 and the '
           'mgrmap push (1796); no type 16 (SubscribeAck), 20, 6',
           sv <= {4, 18, 41, 51, 62, 1796}, str(sorted(sv)))
    tl.chk('mon-client 2.2: messages sent by the stock client to the monitor are only types 5, 15, 17, 50',
           cv <= {5, 15, 17, 50}, str(sorted(cv)))
    # stored maps: CRC rules on every Incremental / full map of the monitor store (epochs 1..89)
    fulls = {}
    incs = {}
    for fn in sorted(glob.glob(os.path.join(cap, 'gt3', 'full', 'full.*.bin'))):
        e = int(os.path.basename(fn).split('.')[1])
        fulls[e] = read_file(fn)
    for fn in sorted(glob.glob(os.path.join(cap, 'gt3', 'inc', 'inc.*.bin'))):
        e = int(os.path.basename(fn).split('.')[1])
        incs[e] = read_file(fn)
    if fulls:
        r0 = Rd(fulls[min(fulls)])
        r0.env()
        r0.env()
        fsid = r0.uuid()
        for e, b in fulls.items():
            check_osdmap_blob('full', e, b, fsid, tl)
        for e, b in incs.items():
            check_osdmap_blob('inc', e, b, fsid, tl)
        both = [e for e in incs if e in fulls]
        tl.chk('osdmap 2.6.1 / mon-client Q10: the full_crc at the end of the stored Incremental of epoch e equals the CRC '
               'stored in the stored full map of epoch e (all %d epochs held in both forms)' % len(both),
               bool(both) and all(incs[e][-4:] == fulls[e][-4:] for e in both),
               str([e for e in both if incs[e][-4:] != fulls[e][-4:]][:5]))
    return seen


def main():
    ap = argparse.ArgumentParser(description='independent checker for docs/spec/mon-client.md')
    ap.add_argument('--captures', help='capture directory (default: harness/vectors/public)')
    ap.add_argument('--secrets', help='directory with the keyrings (default: harness/vectors/public/keys for the public '
                                      'set, else <captures>/../lab-secrets)')
    ap.add_argument('--jobs', type=int, default=0)
    ap.add_argument('--only', help='run only sessions whose name contains this text')
    ap.add_argument('--write-vectors', metavar='DIR', help='regenerate the scrubbed test vectors from the captures into DIR')
    ap.add_argument('--vectors', metavar='DIR', help='verify the vectors in DIR (default harness/vectors/monclient)')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()
    cap = pubset.captures_dir(a.captures)
    lab = os.path.abspath(a.secrets) if a.secrets else pubset.default_keys_dir(cap)
    t0 = time.time()
    sessions = load_sessions(cap)
    names = [n for n in sessions if os.path.exists(os.path.join(cap, 'pcap', n + '.pcap'))]
    if a.only:
        names = [n for n in names if a.only in n]
    # x-* sessions are not in sessions.tsv? add them if missing
    for f in sorted(glob.glob(os.path.join(cap, 'pcap', '*.pcap'))):
        n = os.path.basename(f)[:-5]
        if n not in sessions and (not a.only or a.only in n):
            ent = {'x-t0-ro': 'client.t0-ro', 'x-t0-noosd': 'client.t0-noosd'}.get(n)
            if ent:
                sessions[n] = {'name': n, 'ktype': 'aes256k', 'entity': ent, 'mode': 'crc', 'ncmds': '3', 'debug': '', 'desc': ''}
                names.append(n)
    if not names:
        print('no pcap sessions found under %s' % cap)
        return 2
    if not os.path.isdir(lab):
        print('keyrings not found: %s (use --secrets)' % lab)
        return 2
    jobs = a.jobs or min(len(names), os.cpu_count() or 2)
    work = [(cap, lab, n, sessions[n], False) for n in sorted(names, key=lambda n: -os.path.getsize(os.path.join(cap, 'pcap', n + '.pcap')))]
    results = []
    if jobs <= 1:
        for w in work:
            results.append(analyze_session(w))
    else:
        with concurrent.futures.ProcessPoolExecutor(max_workers=jobs) as ex:
            for r in ex.map(analyze_session, work):
                results.append(r)
    tl = Tally()
    for name, d, notes, st in results:
        t2 = Tally()
        t2.d = d
        t2.notes = collections.Counter(notes)
        tl.merge(t2)
    seen = global_checks(cap, results, tl, a.verbose)
    vdir = a.vectors or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'vectors', 'monclient')
    nvec = check_vectors(vdir, tl) if os.path.isdir(vdir) else 0
    # report
    nfail = 0
    ninst = 0
    nchk = 0
    fails = []
    for k in sorted(tl.d):
        ok, bad, ex = tl.d[k]
        nchk += 1
        ninst += ok + bad
        if bad:
            nfail += 1
            fails.append((k, ok, bad, ex))
        if a.verbose:
            print('%s %-6s %s (%d/%d)' % ('FAIL' if bad else 'ok  ', '', k, ok, ok + bad))
    for k, ok, bad, ex in fails:
        print('FAIL: %s  [%d ok, %d failed]' % (k, ok, bad))
        for x in ex:
            print('      e.g. %s' % x)
    if tl.notes:
        print('\nObservations that differ from other notes or are informational (not counted as failures):')
        for k, v in sorted(tl.notes.items()):
            print('  - (%dx) %s' % (v, k))
    print('\nvector files verified: %d' % nvec)
    print('sessions analysed: %d   named checks: %d   individual assertions: %d   failed checks: %d   (%.1f s)' %
          (len(results), nchk, ninst, nfail, time.time() - t0))
    if a.verbose:
        print('message types seen (dir, type, version, compat): count')
        for k, v in sorted(seen.items()):
            print('  ', k, MT.get(k[1], '?'), v)
    if a.write_vectors:
        write_vectors(cap, lab, a.write_vectors, sessions)
    pubset.emit_result('monclient_check', nchk - nfail, nfail)
    return 1 if nfail else 0


# ----------------------------------------------------------------------------------------------------
# test vectors (scrubbed): writer and verifier
# ----------------------------------------------------------------------------------------------------

PLACEHOLDER = 0xEE


def build_crc_frame(tag, segs, align):
    """msgr2.1 crc-mode frame (msgr2 note 2.6.1), used to re-assemble frames after scrubbing"""
    segs = list(segs)
    while len(segs) > 1 and not segs[-1]:
        segs.pop()
    n = len(segs)
    lens = [len(x) for x in segs] + [0] * (4 - n)
    pre = bytes([tag, n])
    for k in range(4):
        pre += struct.pack('<IH', lens[k], align[k])
    pre += b'\x00\x00'
    pre += struct.pack('<I', wire.crc32c(pre, 0))
    out = pre
    if segs[0]:
        out += segs[0] + struct.pack('<I', wire.crc32c(segs[0], CRC_ONES))
    for x in segs[1:]:
        out += x
    if n > 1:
        out += b'\x0e'
        for k in range(1, 4):
            out += struct.pack('<I', wire.crc32c(segs[k], CRC_ONES) if k < n else 0)
    return out


def hdr_bytes(h):
    return struct.pack('<QQHHHIHQBHH', h['seq'], h['tid'], h['type'], h['prio'], h['version'], h['pre_pad'], h['data_off'],
                       h['ack_seq'], h['flags'], h['compat'], h['reserved'])


def scrub_mauth(front):
    """MAuth front with the ticket blob and the authorizer proof replaced by placeholders; returns (bytes, regions)"""
    r = Rd(front)
    dec_paxos_prefix(r)
    r.u32()
    ln = r.u32()
    q = Rd(front, r.p, r.p + ln)
    q.u16()
    q.u8()
    q.u64()
    q.u32()
    q.u8()
    q.u64()
    tl_ = q.u32()
    reg = [('authorizer ticket blob', q.p, tl_)]
    q.skip(tl_)
    pl = q.u32()
    reg.append(('authorizer proof (ciphertext)', q.p, pl))
    b = bytearray(front)
    for _, o, l in reg:
        b[o:o + l] = bytes([PLACEHOLDER]) * l
    return bytes(b), reg


def scrub_mauth_reply(front):
    r = Rd(front)
    r.u32()
    r.i32()
    r.u64()
    ln = r.u32()
    q = Rd(front, r.p, r.p + ln)
    q.u16()
    q.i32()
    q.u8()
    num = q.u32()
    reg = []
    for k in range(num):
        q.u32()
        q.u8()
        n1 = q.u32()
        reg.append(('ticket %d session-key ciphertext (msg_a)' % k, q.p, n1))
        q.skip(n1)
        q.u8()
        n2 = q.u32()
        reg.append(('ticket %d opaque ticket blob' % k, q.p, n2))
        q.skip(n2)
    b = bytearray(front)
    for _, o, l in reg:
        b[o:o + l] = bytes([PLACEHOLDER]) * l
    return bytes(b), reg


def msg_frame_bytes(c, m, direction):
    """wire bytes of the crc-mode MESSAGE frame of message m"""
    st = c.flow.c2s if direction == 'c' else c.flow.s2c
    for fr in (c.frames_c if direction == 'c' else c.frames_s):
        if fr.tag == 17 and fr.start == m['wire_off']:
            return bytes(st.data[fr.start:fr.end]), fr
    raise WireError('frame not found')


def vec(vid, desc, source, **kw):
    d = {'id': vid, 'description': desc, 'source': source}
    d.update(kw)
    return d


def write_vectors(cap, lab, outdir, sessions):
    os.makedirs(outdir, exist_ok=True)
    vs = []
    scratch = Tally()
    st = new_state()

    def conns_of(name):
        meta = sessions[name]
        sess, flows, conns = decode_session(cap, lab, name, meta, scratch, st)
        for i in sorted(conns, key=lambda i: flows[i].first_ts):
            c = conns[i]
            if c.ok_auth and not c.short:
                analyze_post_auth(sess, c, scratch, meta, name)
        return [conns[i] for i in sorted(conns, key=lambda i: flows[i].first_ts) if conns[i].ok_auth and not conns[i].short]

    cs = conns_of('k2-rbd-info-default')
    mon = [c for c in cs if c.peer == 'mon']
    real = mon[1]                               # the second monitor connection of the first command (osdmap user)
    boot = mon[0]                               # bootstrap connection
    src = 'session k2-rbd-info-default (crc mode, key type aes256k)'

    def first(c, d, t):
        return [m for m in sorted(c.msgs, key=lambda m: m['ts']) if m['dir'] == d and m['type'] == t][0]

    # 1 MMonGetMap
    m = first(real, 'c', 5)
    fb, fr = msg_frame_bytes(real, m, 'c')
    assert build_crc_frame(17, fr.segs, fr.align) == fb
    vs.append(vec('mmongetmap', 'MMonGetMap (type 5), client to monitor: header only, empty body; whole msgr2.1 crc-mode MESSAGE frame',
                  src + ' / connection to the monitor / first message sent', frame_hex=fb.hex(), header2_hex=hdr_bytes(m).hex(),
                  front_hex='', expect={'type': 5, 'version': 1, 'compat': 1, 'priority': 127, 'tid': 0, 'seq': 1, 'segments': 1,
                                        'frame_len': len(fb), 'note': 'mon-client 2.3, 3.3.1'}))

    # 2 subscribes (hostname scrubbed -> "host1"; frame re-assembled)
    def sub_vec(vid, desc, conn, k, origin):
        subs = [mm for mm in sorted(conn.msgs, key=lambda x: x['ts']) if mm['dir'] == 'c' and mm['type'] == 15]
        mm = subs[k]
        d = dec_subscribe(mm['front'], 3)
        front = enc_subscribe(d['what'], 'host1')
        fb2, fr2 = msg_frame_bytes(conn, mm, 'c')
        segs = [fr2.segs[0], front] + list(fr2.segs[2:])
        frame = build_crc_frame(17, segs, fr2.align)
        return vec(vid, desc, origin + '; hostname replaced by "host1" and the frame re-assembled with fresh lengths and CRCs',
                   frame_hex=frame.hex(), header2_hex=fr2.segs[0].hex(), front_hex=front.hex(),
                   expect={'type': 15, 'version': 3, 'compat': 1, 'priority': 127, 'what': [list(x) for x in d['what']],
                           'hostname': 'host1', 'front_len': len(front), 'note': 'mon-client 2.5.1'})
    vs.append(sub_vec('mmonsubscribe-config-monmap', 'MMonSubscribe v3: {"config" 0/0, "monmap" 0/0}, the first message after the '
                      'handshake of a fresh session', boot, 0, src))
    vs.append(sub_vec('mmonsubscribe-mgrmap', 'MMonSubscribe v3: {"mgrmap" 0/0}', real, 1, src))
    vs.append(sub_vec('mmonsubscribe-osdmap-start0-onetime', 'MMonSubscribe v3: {"osdmap" start 0, flags 1 (ONETIME)}: asks for the '
                      'newest full map', real, 2, src))
    # reconnect subscribe from the mon-restart capture
    rs = conns_of('k2-mon-restart')
    rm = [c for c in rs if c.peer == 'mon'][-1]
    vs.append(sub_vec('mmonsubscribe-reconnect', 'MMonSubscribe v3 re-sent after a monitor restart: monmap start 4 (held 3 + 1), '
                      'osdmap start 93 ONETIME (held 92 + 1), config 0, mgrmap 0', rm, 0,
                      'session k2-mon-restart (crc mode, key type aes256k), the connection made after the restart'))
    # derived example of the note (not captured)
    front = enc_subscribe([('monmap', 0, 0)], 'h')
    vs.append(vec('mmonsubscribe-derived-monmap-only', 'The 28-byte example derived in mon-client.md section 5 (monmap only, hostname "h"); '
                  'NOT captured: built from the layout, and equal to the bytes the real client produces for the same fields '
                  '(checked by re-encoding every captured subscribe)', 'derived from the note, verified by re-encoding captures',
                  front_hex=front.hex(), expect={'front_len': 28, 'what': [['monmap', 0, 0]], 'hostname': 'h'}))

    # 3 MMonMap
    m = [mm for mm in sorted(real.msgs, key=lambda x: x['ts']) if mm['dir'] == 's' and mm['type'] == 4][0]
    r = Rd(m['front'])
    blob = r.blob()
    d = dec_monmap(blob, scratch)
    jm = {'epoch': d['epoch'], 'fsid': d['fsid'], 'struct_v': d['struct_v'], 'struct_compat': d['compat'],
          'ranks': d['ranks'], 'min_mon_release': d['min_mon_release'], 'strategy': d['strategy'],
          'auth_epoch': d['auth_epoch'], 'auth_service_cipher': d['auth_service_cipher'],
          'auth_allowed_ciphers': d['auth_allowed_ciphers'], 'auth_preferred_cipher': d['auth_preferred_cipher'],
          'persistent_features': d['persistent_features'], 'optional_features': d['optional_features'],
          'mons': {k: {'priority': v['priority'], 'weight': v['weight'],
                       'addrs': [{'type': a['type'], 'ip': a['ip'], 'port': a['port'], 'nonce': a['nonce']} for a in v['addrs']]}
                   for k, v in d['mon_info'].items()}}
    vs.append(vec('mmonmap-e3', 'MMonMap (type 4), monitor to client: header2 + front = u32 length + MonMap struct_v 10 / compat 6, one '
                  'monitor with a v2 and a v1 address; identical bytes to `ceph mon getmap`. fsid and the lab host name are kept '
                  '(random lab values, not secrets)', src + ' / first MMonMap received', header2_hex=hdr_bytes(m).hex(),
                  front_hex=m['front'].hex(), monmap_hex=blob.hex(),
                  expect={'type': 4, 'version': 1, 'compat': 1, 'priority': 196, 'front_len': len(m['front']), 'monmap': jm,
                          'note': 'mon-client 2.4'}))

    # 4 MOSDMap v4 full map
    m = [mm for mm in sorted(real.msgs, key=lambda x: x['ts']) if mm['dir'] == 's' and mm['type'] == 41][0]
    d = dec_mosdmap(m['front'], 4)
    ep = list(d['full'])[0]
    vs.append(vec('mosdmap-v4-full-e%d' % ep, 'MOSDMap (type 41) v4/compat 3 answering an osdmap subscription with start 0: one full map, '
                  'no incrementals, trim bound and newest_map, 4 zero bytes at the end', src + ' / MOSDMap received on the second '
                  'monitor connection', header2_hex=hdr_bytes(m).hex(), front_hex=m['front'].hex(),
                  expect={'type': 41, 'version': 4, 'compat': 3, 'priority': 196, 'fsid': d['fsid'], 'incremental_epochs': [],
                          'full_epochs': sorted(d['full']), 'cluster_osdmap_trim_lower_bound': d['trim_lower'],
                          'newest_map': d['newest'], 'removed_snaps_gap_count': 0, 'front_len': len(m['front']),
                          'full_blob_len': len(d['full'][ep]), 'note': 'mon-client 2.6, 3.5.1 row 1'}))
    # 5 synthetic MOSDMap with two incrementals (assembled from the monitor-store copies)
    i1 = read_file(os.path.join(cap, 'gt3', 'inc', 'inc.00042.bin'))
    i2 = read_file(os.path.join(cap, 'gt3', 'inc', 'inc.00043.bin'))
    fsid = bytes.fromhex(d['fsid'])
    body = fsid + struct.pack('<I', 2)
    body += struct.pack('<I', 42) + struct.pack('<I', len(i1)) + i1 + struct.pack('<I', 43) + struct.pack('<I', len(i2)) + i2
    body += struct.pack('<I', 0) + struct.pack('<II', 1, 43) + struct.pack('<I', 0)
    vs.append(vec('mosdmap-v4-inc-e42-e43-synthetic', 'SYNTHETIC (not a capture): a MOSDMap v4 body laid out as mon-client.md 2.6 describes, '
                  'holding the two stored OSDMap::Incremental blobs of epochs 42 and 43 byte-for-byte from the monitor store; '
                  'no capture contains an incremental delivery (every captured MOSDMap carries one full map)',
                  'gt3/inc/inc.00042.bin and inc.00043.bin of the capture set, wrapped by this tool', front_hex=body.hex(),
                  expect={'type': 41, 'version': 4, 'compat': 3, 'fsid': d['fsid'], 'incremental_epochs': [42, 43],
                          'full_epochs': [], 'cluster_osdmap_trim_lower_bound': 1, 'newest_map': 43, 'removed_snaps_gap_count': 0,
                          'incremental_blob_lens': [len(i1), len(i2)], 'note': 'mon-client 2.6'}))

    # 6 MAuth renewal (scrubbed) from the renew session
    rn = conns_of('k2-renew-ttl60')
    rc = [c for c in rn if c.peer == 'mon' and any(mm['type'] == 17 for mm in c.msgs)][0]
    ma = first(rc, 'c', 17)
    mr = first(rc, 's', 18)
    sb, reg = scrub_mauth(ma['front'])
    rsrc = 'session k2-renew-ttl60 (crc mode, key type aes256k, auth_service_ticket_ttl=60) / first renewal'
    vs.append(vec('mauth-renewal-scrubbed', 'MAuth (type 17) in-session renewal request: PaxosServiceMessage prefix, protocol 2, '
                  'auth_payload = request header 0x0200 + authorizer for service AUTH + CephXServiceTicketRequest, monmap_epoch 0. '
                  'SCRUBBED: the AUTH ticket blob and the authorizer proof are replaced by 0xEE bytes of the same length (a real one '
                  'is ciphertext under the session key)', rsrc, header2_hex=hdr_bytes(ma).hex(), front_hex=sb.hex(),
                  scrubbed_regions=[{'what': w, 'offset': o, 'length': l, 'fill': 'EE'} for w, o, l in reg],
                  expect={'type': 17, 'version': 1, 'compat': 1, 'priority': 127, 'front_len': len(sb), 'paxos_prefix': [0, -1, 0],
                          'protocol': 2, 'request_type': 0x0200, 'authorizer_version': 1, 'service_id': 0x20,
                          'ticket_request_version': 1, 'ticket_request_keys': first_keys(ma['front']), 'monmap_epoch': 0,
                          'note': 'mon-client 3.8.2'}))
    sb2, reg2 = scrub_mauth_reply(mr['front'])
    vs.append(vec('mauthreply-renewal-scrubbed', 'MAuthReply (type 18): protocol 2, result 0, global_id, result_bl = response header '
                  '0x0200/status 0 + ticket reply (ticket_enc 0), result_msg "". SCRUBBED: every ciphertext (msg_a) and ticket blob is '
                  'replaced by 0xEE bytes of the same length', rsrc, header2_hex=hdr_bytes(mr).hex(), front_hex=sb2.hex(),
                  scrubbed_regions=[{'what': w, 'offset': o, 'length': l, 'fill': 'EE'} for w, o, l in reg2],
                  expect={'type': 18, 'version': 1, 'compat': 1, 'priority': 196, 'front_len': len(sb2), 'protocol': 2, 'result': 0,
                          'global_id_is_session_global_id': True, 'ticket_count': len(reg2) // 2, 'result_msg': '',
                          'note': 'mon-client 3.8.3'}))

    # 7 keepalive pair from the idle session
    ic = conns_of('k2-idle75')
    ac = [c for c in ic if c.peer == 'mon' and getattr(c, 'keepalive', None)][0]
    kc = [f for f in ac.frames_c if f.tag == 18][0]
    ks = [f for f in ac.frames_s if f.tag == 19][0]
    cb_ = bytes(ac.flow.c2s.data[kc.start:kc.end])
    sb_ = bytes(ac.flow.s2c.data[ks.start:ks.end])
    stamp = Rd(kc.segs[0]).utime()
    vs.append(vec('keepalive2-pair', 'KEEPALIVE2 (tag 18) from the client and the KEEPALIVE2_ACK (tag 19) echoing the same utime; 44-byte '
                  'crc-mode frames (32 preamble + 8 payload + 4 crc, one segment, no epilogue). The stamp is a wall-clock time of the '
                  'lab VM', 'session k2-idle75 (crc mode) / first keepalive on the monitor connection',
                  keepalive_frame_hex=cb_.hex(), ack_frame_hex=sb_.hex(),
                  expect={'frame_len': len(cb_), 'stamp_sec': stamp[0], 'stamp_nsec': stamp[1], 'ack_echoes_stamp': True,
                          'note': 'mon-client 3.6'}))

    # 8 scenarios (text only)
    def seqof(c):
        out = []
        for mm in sorted(c.msgs, key=lambda x: x['ts']):
            e = {'dir': 'client->mon' if mm['dir'] == 'c' else 'mon->client', 'type': mm['type'], 'name': MT.get(mm['type'], 'mgrmap push' if mm['type'] == 1796 else '?'),
                 'version': mm['version'], 'compat': mm['compat'], 'priority': mm['prio']}
            if mm['type'] == 15:
                e['subscribe'] = [list(x) for x in dec_subscribe(mm['front'], 3)['what']]
            if mm['type'] == 41:
                dd = dec_mosdmap(mm['front'], mm['version'])
                e['mosdmap'] = {'incremental_epochs': sorted(dd['inc']), 'full_epochs': sorted(dd['full']),
                                'trim_lower_bound': dd['trim_lower'], 'newest_map': dd['newest']}
            if mm['type'] == 4:
                e['monmap_epoch'] = dec_monmap(Rd(mm['front']).blob(), scratch)['epoch']
            out.append(e)
        return out
    vs.append(vec('scenario-fresh-session', 'Message sequence on the two monitor connections a stock tool opens at start-up (first one: '
                  'bootstrap that fetches monmap + config; second one: the real session). Order is by capture time; both sides are '
                  'listed. Types: 5 MMonGetMap, 15 MMonSubscribe, 4 MMonMap, 62 MConfig, 41 MOSDMap; 1796 is the mgrmap push (53 KB)',
                  src, expect={'connections': [seqof(boot), seqof(real)], 'note': 'mon-client 3.3, 3.4, 3.5.1 row 1'}))
    vs.append(vec('scenario-monitor-restart', 'Message sequence of the monitor connection made after the monitor was restarted under an '
                  'open session: global_id reclaimed with the old AUTH ticket, MMonGetMap first, subscriptions re-sent with held + 1, '
                  'one MMonMap only', 'session k2-mon-restart (crc mode, key type aes256k), last monitor connection',
                  expect={'global_id_reclaimed': True, 'old_ticket_sent': True, 'connection': seqof(rm),
                          'note': 'mon-client 3.7, 3.9'}))
    for v in vs:
        v['scrub'] = ('No key material, tickets, signatures, nonces derived from keys or encrypted blobs are present. See README.md '
                      'for what was kept / replaced.')
        with open(os.path.join(outdir, v['id'] + '.json'), 'w') as f:
            json.dump(v, f, indent=1, sort_keys=False)
            f.write('\n')
    print('wrote %d vector files to %s' % (len(vs), outdir))


def first_keys(front):
    r = Rd(front)
    dec_paxos_prefix(r)
    r.u32()
    ln = r.u32()
    q = Rd(front, r.p, r.p + ln)
    q.u16()
    q.u8()
    q.u64()
    q.u32()
    q.u8()
    q.u64()
    q.skip(q.u32())
    q.skip(q.u32())
    q.u8()
    return q.u32()


def check_vectors(vdir, tl):
    """decode every vector with the decoders above and compare with its expectation block"""
    files = sorted(glob.glob(os.path.join(vdir, '*.json')))
    if not files:
        return 0
    for fn in files:
        with open(fn) as f:
            v = json.load(f)
        e = v.get('expect', {})
        vid = v['id']
        try:
            if 'frame_hex' in v:
                fb = bytes.fromhex(v['frame_hex'])
                fr = wire.read_crc_frame(fb, 0)
                tl.chk('vectors: %s frame has valid preamble / segment / epilogue CRCs and consumes exactly its bytes' % vid,
                       not fr.errors and fr.end == len(fb) and fr.tag == 17)
                h = hdr2(fr.segs[0])
                tl.chk('vectors: %s header2 matches header2_hex and the type / version / compat / priority expectations' % vid,
                       fr.segs[0].hex() == v['header2_hex'] and all(h[k2] == e[k1] for k1, k2 in
                                                                    (('type', 'type'), ('version', 'version'), ('compat', 'compat'), ('priority', 'prio'))
                                                                    if k1 in e))
                front = fr.segs[1] if len(fr.segs) > 1 else b''
                tl.chk('vectors: %s front segment equals front_hex' % vid, front.hex() == v['front_hex'])
            if 'keepalive_frame_hex' in v:
                a = wire.read_crc_frame(bytes.fromhex(v['keepalive_frame_hex']), 0)
                b = wire.read_crc_frame(bytes.fromhex(v['ack_frame_hex']), 0)
                tl.chk('vectors: %s frames are tags 18 / 19 with equal payloads' % vid, a.tag == 18 and b.tag == 19 and
                       a.segs == b.segs and Rd(a.segs[0]).utime() == (e['stamp_sec'], e['stamp_nsec']) and
                       len(bytes.fromhex(v['keepalive_frame_hex'])) == e['frame_len'])
            if 'front_hex' in v and v['front_hex'] != '' and e.get('type') == 15 or vid == 'mmonsubscribe-derived-monmap-only':
                d = dec_subscribe(bytes.fromhex(v['front_hex']), 3)
                tl.chk('vectors: %s decodes to the expected subscription list and hostname, and re-encodes to the same bytes' % vid,
                       [list(x) for x in d['what']] == e['what'] and d['hostname'] == e['hostname'] and d['trailing'] == 0 and
                       enc_subscribe(d['what'], d['hostname']).hex() == v['front_hex'] and len(v['front_hex']) // 2 == e.get('front_len', len(v['front_hex']) // 2))
            if e.get('type') == 4:
                fb = bytes.fromhex(v['front_hex'])
                b = Rd(fb).blob()
                d = dec_monmap(b, tl)
                m = e['monmap']
                tl.chk('vectors: %s MonMap decodes to the expected fields' % vid,
                       d['epoch'] == m['epoch'] and d['fsid'] == m['fsid'] and d['ranks'] == m['ranks'] and
                       d['auth_allowed_ciphers'] == m['auth_allowed_ciphers'] and (d['struct_v'], d['compat']) == (10, 6) and
                       b.hex() == v['monmap_hex'] and
                       all([(a['type'], a['ip'], a['port'], a['nonce']) for a in d['mon_info'][k]['addrs']] ==
                           [(a['type'], a['ip'], a['port'], a['nonce']) for a in mv['addrs']] for k, mv in m['mons'].items()))
            if e.get('type') == 41:
                d = dec_mosdmap(bytes.fromhex(v['front_hex']), e['version'])
                ok = (sorted(d['inc']) == e['incremental_epochs'] and sorted(d['full']) == e['full_epochs'] and
                      d['trim_lower'] == e['cluster_osdmap_trim_lower_bound'] and d['newest'] == e['newest_map'] and
                      d['gap_count'] == 0 and d['trailing'] == 0 and d['fsid'] == e['fsid'])
                for k_, b_ in d['inc'].items():
                    check_osdmap_blob('inc', k_, b_, d['fsid'], tl)
                for k_, b_ in d['full'].items():
                    check_osdmap_blob('full', k_, b_, d['fsid'], tl)
                tl.chk('vectors: %s MOSDMap decodes to the expected epochs / bounds and every embedded blob passes its CRC' % vid, ok)
            if vid == 'mauth-renewal-scrubbed':
                fb = bytes.fromhex(v['front_hex'])
                r = Rd(fb)
                p = dec_paxos_prefix(r)
                proto = r.u32()
                pay = r.blob()
                mep = r.u32()
                q = Rd(pay)
                tl.chk('vectors: %s structure parses: prefix (0,-1,0), protocol 2, request header 0x0200, authorizer for AUTH, '
                       'ticket request keys, monmap_epoch 0' % vid,
                       p == {'version': 0, 'session_mon': -1, 'tid': 0} and proto == 2 and q.u16() == 0x0200 and
                       r.left() == 0 and mep == 0 and first_keys(fb) == e['ticket_request_keys'] and len(fb) == e['front_len'])
            if vid == 'mauthreply-renewal-scrubbed':
                fb = bytes.fromhex(v['front_hex'])
                r = Rd(fb)
                proto = r.u32()
                res = r.i32()
                r.u64()
                rb = r.blob()
                msg = r.string()
                q = Rd(rb)
                rt = q.u16()
                stt = q.i32()
                tl.chk('vectors: %s structure parses: protocol 2, result 0, response header 0x0200 / 0, ticket count, empty result_msg' % vid,
                       proto == 2 and res == 0 and rt == 0x0200 and stt == 0 and q.u8() == 1 and q.u32() == e['ticket_count'] and
                       msg == '' and r.left() == 0)
        except Exception as ex:   # noqa
            tl.chk('vectors: %s decodes without an exception' % vid, False, '%s: %s' % (type(ex).__name__, ex))
    return len(files)


if __name__ == '__main__':
    sys.exit(main())
