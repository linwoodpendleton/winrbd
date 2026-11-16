#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
msgr2_probe.py - tiny live msgr2 / cephx client used to settle open questions of docs/spec/msgr2.md
that a capture of the stock client cannot answer (the stock client always behaves the same way).

It is written from docs/spec/msgr2.md and docs/spec/cephx.md only and re-uses the encoders / crypto of
msgr2_check.py (same directory).  It talks to ONE monitor of a lab cluster, authenticates with cephx
(crc mode), and then runs one of the named experiments.  Keys are read from a keyring file and never printed.

    python3 msgr2_probe.py --mon 10.77.0.10:3300 --entity client.winrbd --keyring /etc/ceph/ceph.client.winrbd.keyring EXPERIMENT

Experiments (each opens its own TCP connection and closes it):
    baseline        banner 0x3, COMPRESSION_REQUEST{false, []} (what the stock client sends), ident, keepalive
    nocompress      banner supported = 0x1 (REVISION_1 only), no COMPRESSION_REQUEST, ident, keepalive
    skipcompress    banner 0x3 but no COMPRESSION_REQUEST, straight to CLIENT_IDENT (expected: server drops)
    (all experiments below advertise 0x1 only, i.e. no compression stage)
    align           keepalive with segment alignments 4, 16, 4096 (power-of-two variants)
    msgfields       MMonGetVersion with data_off / data_pre_padding_len zero, then non-zero
    earlyka         KEEPALIVE2 sent before CLIENT_IDENT
    earlymsg        MESSAGE sent before CLIENT_IDENT
    lossless        CLIENT_IDENT with flags 0 and a non-zero cookie
    badmode         AUTH_REQUEST offering only mode 7 (unknown)
    badmethod       AUTH_REQUEST with method 99
    noaddr2         CLIENT_IDENT supported mask without MSG_ADDR2
    kaseq           MESSAGE seq 1 twice (the second must be ignored by the server)
    close           close immediately after AUTH_SIGNATURE (no ident)
    msgflags        MMonGetVersion with header2.flags = 1, 0, 3 (one connection each)
    dropbits        one connection per feature bit: CLIENT_IDENT supported mask = full mask minus that bit (bits of the server's reported
                    required mask, plus bit 12); prints SERVER_IDENT or the IDENT_MISSING_FEATURES mask
"""

import argparse
import hmac
import hashlib
import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import msgr2_check as M  # noqa: E402


class Peer:
    def __init__(self, host, port, timeout=6.0):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.s.settimeout(timeout)
        self.rx = bytearray()          # every byte received (pre-auth log)
        self.tx = bytearray()          # every byte sent
        self.log_on = True
        self.local_ip = self.s.getsockname()[0]

    def send(self, b):
        if self.log_on:
            self.tx += b
        self.s.sendall(b)

    def recv_exact(self, n):
        out = bytearray()
        while len(out) < n:
            chunk = self.s.recv(n - len(out))
            if not chunk:
                raise EOFError("connection closed by peer after %d of %d bytes" % (len(out), n))
            out += chunk
        if self.log_on:
            self.rx += out
        return bytes(out)

    def frame(self):
        pre = self.recv_exact(32)
        fr = M.Frame()
        M.parse_preamble(pre, fr)
        if fr.problems:
            raise M.DecodeError("bad preamble %s" % fr.problems)
        n = fr.nseg
        segs = []
        if fr.lens[0]:
            body = self.recv_exact(fr.lens[0] + 4)
            segs.append(body[:-4])
            if M.crc32c(body[:-4], 0xFFFFFFFF) != M.u32(body, fr.lens[0]):
                raise M.DecodeError("segment 0 crc")
        else:
            segs.append(b'')
        for i in range(1, n):
            segs.append(self.recv_exact(fr.lens[i]))
        if n > 1:
            self.recv_exact(13)
        fr.segs = segs
        return fr

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass


def banner(supported):
    return b'ceph v2\n' + struct.pack('<HQQ', 16, supported, 0)


class Session:
    """connect + banner + HELLO + cephx + AUTH_SIGNATURE (crc mode), leaving the peer just before CLIENT_IDENT."""

    def __init__(self, mon, entity, keyring, supported=3, modes=(1,), method=2, send_hello=True):
        host, port = mon.split(':')
        self.host, self.port = host, int(port)
        self.entity = entity
        self.key = M.parse_keyring(keyring)[entity]
        self.supported = supported
        self.p = Peer(self.host, self.port)
        self.target = M.decode_addr(M.Reader(M.encode_addr_v4(self.host, self.port, 0, 2)))
        self.modes = list(modes)
        self.method = method
        self.global_id = None
        self.auth_key = None

    def handshake(self, stop_after=None):
        p = self.p
        p.send(banner(self.supported))
        sb = p.recv_exact(26)
        assert sb[:8] == b'ceph v2\n', sb
        self.server_supported = M.u64(sb, 10)
        p.send(M.build_frame(M.T_HELLO, [M.p_u8(8) + self.target.raw]))
        hello = p.frame()
        self.hello = M.decode_control(hello)
        eid = self.entity.split('.', 1)[1].encode()
        pay = b'\x0a' + M.p_u32(8) + M.p_blob(eid) + M.p_u64(0)
        p.send(M.build_frame(M.T_AUTH_REQUEST, [M.p_u32(self.method) + M.p_vec_u32(self.modes) + M.p_blob(pay)]))
        fr = p.frame()
        if fr.tag == M.T_AUTH_BAD_METHOD:
            self.bad = M.decode_control(fr)
            return 'AUTH_BAD_METHOD %s' % self.bad
        assert fr.tag == M.T_AUTH_REPLY_MORE, fr.tag
        r = M.Reader(M.decode_control(fr)['payload'])
        r.u8()
        chal = r.u64()
        cch = struct.unpack('<Q', os.urandom(8))[0]
        proof = M.proof_for(self.key, chal, cch)
        old = b'\x01' + M.p_u64(0) + M.p_blob(b'')
        more = struct.pack('<H', 0x0100) + b'\x03' + M.p_u64(cch) + M.p_u64(proof) + old + M.p_u32(0x20)
        p.send(M.build_frame(M.T_AUTH_REQUEST_MORE, [M.p_blob(more)]))
        fr = p.frame()
        if fr.tag != M.T_AUTH_DONE:
            return 'unexpected %s after AUTH_REQUEST_MORE' % M.TAGS.get(fr.tag, fr.tag)
        done = M.decode_control(fr)
        self.global_id = done['global_id']
        self.mode = done['mode']
        pr = M.Reader(done['payload'])
        pr.u16()
        pr.s32()
        tick = M.parse_ticket_reply(pr, self.key)
        self.auth_key = tick[0]['key']
        sig = hmac.new(self.auth_key.secret, bytes(p.rx), hashlib.sha256).digest()
        p.log_on = False
        p.send(M.build_frame(M.T_AUTH_SIGNATURE, [sig]))
        fr = p.frame()
        assert fr.tag == M.T_AUTH_SIGNATURE
        self.server_sig = M.decode_control(fr)['sig']
        return 'ok'

    def client_ident(self, gid=-1, flags=1, cookie=0, supported=0x3f07fffffffdffff, required=0x0800000000001000,
                     global_seq=1, nonce=None):
        nonce = nonce if nonce is not None else struct.unpack('<I', os.urandom(4))[0]
        raw = M.encode_addr_v4(self.p.local_ip, 0, nonce, 3)
        me = M.decode_addr(M.Reader(raw))
        d = {'addrs': [me], 'target': self.target, 'gid': gid, 'global_seq': global_seq, 'supported': supported,
             'required': required, 'flags': flags, 'cookie': cookie}
        self.p.send(M.build_frame(M.T_CLIENT_IDENT, [M.encode_control(M.T_CLIENT_IDENT, d)]))

    def read_one(self, what=''):
        try:
            fr = self.p.frame()
        except (EOFError, ConnectionResetError, socket.timeout) as e:
            return None, '%s: %s' % (type(e).__name__, e)
        return fr, ''

    def describe(self, fr):
        if fr is None:
            return 'none'
        try:
            d = M.decode_control(fr) if fr.tag != M.T_MESSAGE else {'type': M.MsgHeader2(fr.segs[0]).type}
        except M.DecodeError:
            d = {}
        short = {k: (v if not isinstance(v, (bytes, list)) else '..') for k, v in d.items()}
        return '%s %s' % (fr.name, short)


def stamp():
    t = time.time()
    return struct.pack('<II', int(t), int((t % 1) * 1e9))


def build_msg(seq, mtype, version, front, data=b'', data_off=0, pre_padding=0, ack_seq=0, tid=1, flags=3, compat=1):
    h = struct.pack('<QQHHHIHQBHH', seq, tid, mtype, 127, version, pre_padding, data_off, ack_seq, flags, compat, 0)
    return M.build_frame(M.T_MESSAGE, [h, front, b'', data], [8, 8, 8, 4096])


def mon_get_version(handle=1, what=b'osdmap'):
    # body per docs/spec/mon-client.md 2.7: handle u64, what string (no paxos prefix)
    return M.p_u64(handle) + M.p_blob(what)


def one_ident(args, supported=0x3f07fffffffdffff, msg_flags=None):
    sess = Session(args.mon, args.entity, args.keyring, supported=0x1)
    try:
        st = sess.handshake()
        if st != 'ok':
            return st
        sess.client_ident(supported=supported)
        fr, err = sess.read_one()
        if fr is None:
            return 'no answer: ' + err
        if fr.tag == M.T_IDENT_MISSING:
            return 'IDENT_MISSING_FEATURES %#018x' % M.decode_control(fr)['features']
        if fr.tag != M.T_SERVER_IDENT:
            return sess.describe(fr)
        if msg_flags is None:
            return 'SERVER_IDENT'
        sess.p.send(build_msg(1, 19, 1, mon_get_version(), flags=msg_flags))
        fr, err = sess.read_one()
        return 'SERVER_IDENT; MMonGetVersion flags=%d -> %s %s' % (msg_flags, sess.describe(fr), err)
    finally:
        sess.p.close()


def run(args):
    ex = args.experiment
    if ex == 'msgflags':
        return ['header2.flags=%d: %s' % (fl, one_ident(args, msg_flags=fl)) for fl in (1, 0, 3)]
    if ex == 'dropbits':
        full = 0x3f07fffffffdffff
        bits = [b for b in range(64) if (0x0c01020042040000 | 0x1000) >> b & 1]
        return ['drop bit %2d (%#018x): %s' % (b, 1 << b, one_ident(args, supported=full & ~(1 << b))) for b in bits]
    sess = Session(args.mon, args.entity, args.keyring,
                   supported=3 if ex in ('baseline', 'skipcompress') else 0x1,
                   modes=(7,) if ex == 'badmode' else (1,),
                   method=99 if ex == 'badmethod' else 2)
    out = []
    try:
        st = sess.handshake()
        out.append('handshake: %s (server banner supported=%d)' % (st, sess.server_supported))
        if st != 'ok':
            return out
        p = sess.p
        if ex == 'close':
            return out + ['closed right after AUTH_SIGNATURE']
        if ex == 'earlyka':
            p.send(M.build_frame(M.T_KEEPALIVE2, [stamp()]))
            fr, err = sess.read_one()
            return out + ['KEEPALIVE2 before ident -> %s %s' % (sess.describe(fr), err)]
        if ex == 'earlymsg':
            p.send(build_msg(1, 19, 1, mon_get_version()))
            fr, err = sess.read_one()
            return out + ['MESSAGE before ident -> %s %s' % (sess.describe(fr), err)]
        if ex in ('baseline',):
            p.send(M.build_frame(M.T_COMPRESSION_REQUEST, [M.encode_control(M.T_COMPRESSION_REQUEST, {'is_compress': 0, 'methods': []})]))
            fr, err = sess.read_one()
            out.append('COMPRESSION_REQUEST{false,[]} -> %s %s' % (sess.describe(fr), err))
        if ex == 'lossless':
            sess.client_ident(flags=0, cookie=0x1122334455667788)
        elif ex == 'noaddr2':
            sess.client_ident(supported=0x3f07fffffffdffff & ~0x0800000000000000)
        else:
            sess.client_ident()
        fr, err = sess.read_one()
        out.append('CLIENT_IDENT -> %s %s' % (sess.describe(fr), err))
        if fr is None or fr.tag != M.T_SERVER_IDENT:
            return out
        sd = M.decode_control(fr)
        out.append('SERVER_IDENT flags=%d cookie_nonzero=%s' % (sd['flags'], sd['cookie'] != 0))
        if ex in ('baseline', 'nocompress', 'lossless', 'skipcompress'):
            p.send(M.build_frame(M.T_KEEPALIVE2, [stamp()]))
            fr, err = sess.read_one()
            out.append('KEEPALIVE2 -> %s %s' % (sess.describe(fr), err))
        if ex == 'align':
            for al in (4, 16, 4096):
                st_ = stamp()
                pre = bytearray(32)
                pre[0] = M.T_KEEPALIVE2
                pre[1] = 1
                struct.pack_into('<IH', pre, 2, 8, al)
                struct.pack_into('<I', pre, 28, M.crc32c(bytes(pre[:28]), 0))
                p.send(bytes(pre) + st_ + M.p_u32(M.crc32c(st_, 0xFFFFFFFF)))
                fr, err = sess.read_one()
                out.append('KEEPALIVE2 with alignment %d -> %s %s' % (al, sess.describe(fr), err))
        if ex == 'msgfields':
            seq = 1
            for label, kw in (('data_off=0,pre_padding=0', {}), ('data_off=17', {'data_off': 17}),
                              ('pre_padding=5', {'pre_padding': 5}), ('data_off=17,pre_padding=5', {'data_off': 17, 'pre_padding': 5})):
                try:
                    p.send(build_msg(seq, 19, 1, mon_get_version(handle=seq), **kw))
                except OSError as e:
                    out.append('send of %s failed: %s' % (label, e))
                    break
                fr, err = sess.read_one()
                out.append('MMonGetVersion %s -> %s %s' % (label, sess.describe(fr), err))
                seq += 1
        if ex == 'kaseq-placeholder':
            pass
        if ex == 'kaseq':
            for seq in (1, 1, 2):
                try:
                    p.send(build_msg(seq, 19, 1, mon_get_version(handle=100 + seq)))
                except OSError as e:
                    out.append('send of seq=%d failed: %s' % (seq, e))
                    break
                fr, err = sess.read_one()
                out.append('MMonGetVersion seq=%d -> %s %s' % (seq, sess.describe(fr), err))
        return out
    finally:
        sess.p.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mon', default='10.77.0.10:3300')
    ap.add_argument('--entity', default='client.winrbd')
    ap.add_argument('--keyring', required=True)
    ap.add_argument('experiment')
    args = ap.parse_args()
    try:
        for line in run(args):
            print(line)
    except (EOFError, ConnectionResetError, socket.timeout, M.DecodeError, AssertionError) as e:
        print('EXCEPTION %s: %s' % (type(e).__name__, e))


if __name__ == '__main__':
    main()
