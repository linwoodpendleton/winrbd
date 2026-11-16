# SPDX-License-Identifier: MIT
# Per-flow TCP sanity check of classic pcap files (Ethernet, IPv4): reports gaps (missing bytes = capture loss),
# retransmissions (counted; a retransmission whose bytes differ from the first copy is an error, identical bytes
# are reported as "identical"), truncated frames, and the set of IP addresses (must be exactly two).
# usage: python3 -I pcap_loss_check.py [--allow-identical-retx] file.pcap [...]
# exit 1 if any file has a gap, a truncated frame, a differing retransmission, or (without the flag) any retransmission
import struct, sys, collections

def check(path, allow_retx=False):
    d = open(path, 'rb').read()
    magic = d[:4]
    if magic == b'\xd4\xc3\xb2\xa1': e = '<'; nano = False
    elif magic == b'\xa1\xb2\xc3\xd4': e = '>'; nano = False
    elif magic == b'\x4d\x3c\xb2\xa1': e = '<'; nano = True
    else: return ['not a classic pcap'], {}
    snap, lt = struct.unpack(e + 'II', d[16:24])
    if lt != 1: return ['linktype %d is not Ethernet' % lt], {}
    pos = 24; n = 0; non_ip = 0; probs = []; flows = {}; addrs = set(); trunc = 0
    while pos + 16 <= len(d):
        ts, tu, cl, ol = struct.unpack(e + 'IIII', d[pos:pos + 16]); pos += 16
        fr = d[pos:pos + cl]; pos += cl; n += 1
        if cl != ol: trunc += 1
        if len(fr) < 34 or fr[12:14] != b'\x08\x00':
            non_ip += 1; continue
        ihl = (fr[14] & 15) * 4; proto = fr[23]
        src = '.'.join(map(str, fr[26:30])); dst = '.'.join(map(str, fr[30:34])); addrs |= {src, dst}
        if proto != 6: probs.append('frame %d: proto %d' % (n, proto)); continue
        tl = struct.unpack('>H', fr[16:18])[0]
        t = 14 + ihl
        sp, dp, seq, ack, off, fl = struct.unpack('>HHIIBB', fr[t:t + 14]); off = (off >> 4) * 4
        plen = tl - ihl - off
        key = (src, sp, dst, dp)
        st = flows.setdefault(key, {'next': None, 'bytes': 0, 'gaps': 0, 'retx': 0, 'ooo': 0, 'pk': 0, 'seg': {}, 'retx_bad': 0})
        pay = fr[t + off:t + off + plen] if plen > 0 else b''
        st['pk'] += 1
        syn, fin, rst = fl & 2, fl & 1, fl & 4
        L = plen + (1 if syn else 0) + (1 if fin else 0)
        if st['next'] is None:
            st['next'] = (seq + L) & 0xffffffff; st['bytes'] += plen
            if plen: st['seg'][seq] = pay
            continue
        if L == 0: continue
        diff = (seq - st['next']) & 0xffffffff
        if diff == 0:
            st['next'] = (seq + L) & 0xffffffff; st['bytes'] += plen
            if plen: st['seg'][seq] = pay
        elif diff < 0x80000000:
            st['gaps'] += 1; st['next'] = (seq + L) & 0xffffffff        # bytes missing before this segment
        else:
            st['retx'] += 1
            if plen and st['seg'].get(seq) != pay: st['retx_bad'] += 1
    tot = collections.Counter()
    for k, s in flows.items():
        tot['gaps'] += s['gaps']
        if s['gaps']: probs.append('flow %s:%d->%s:%d: %d gap(s)' % (k + ()))
        tot['retx'] += s['retx']; tot['retx_bad'] += s['retx_bad']
        if s['retx_bad']: probs.append('flow %s:%d->%s:%d: %d retransmission(s) with DIFFERENT bytes' % (k + (s['retx_bad'],)))
        elif s['retx'] and not allow_retx: probs.append('flow %s:%d->%s:%d: %d retransmission(s), bytes identical to the first copy' % (k + (s['retx'],)))
    if trunc: probs.append('%d truncated frames' % trunc)
    if len(addrs) != 2: probs.append('addresses seen: %s' % sorted(addrs))
    return probs, {'frames': n, 'flows': len(flows), 'gaps': tot['gaps'], 'retx': tot['retx'], 'non_ip': non_ip, 'addrs': sorted(addrs)}

bad = 0
args = sys.argv[1:]
allow = '--allow-identical-retx' in args
args = [a for a in args if not a.startswith('--')]
for p in args:
    probs, info = check(p, allow)
    print('%-60s %s %s' % (p.split('/')[-1], 'OK ' if not probs else 'BAD', info))
    for x in probs: print('    ', x)
    bad += bool(probs)
sys.exit(1 if bad else 0)
