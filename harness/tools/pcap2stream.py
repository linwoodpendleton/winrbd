#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""pcap2stream.py - extract the TCP payload streams of every connection in a packet capture.

Input: classic pcap and pcapng files (Ethernet, optionally one 802.1Q tag; raw IP is accepted
too), IPv4 and TCP only. The payload of each direction of each TCP connection is reassembled by
sequence number (retransmissions and duplicates are tolerated, out-of-order segments are put in
place, a hole ends the stream and is reported), and written to its own file:

    <outdir>/<session>.c<NN>.c2s.bin    client to server
    <outdir>/<session>.c<NN>.s2c.bin    server to client

<session> is the capture file name without its extension, NN counts the connections of that file
in order of first appearance. The client is the side that sent the first SYN without ACK (the
sender of the first packet if the capture starts in mid-connection).

Besides the streams the tool writes <outdir>/index.tsv, one line per stream file with the
columns: session, connection, direction (c2s or s2c), server port, size in bytes, gap (-1 or the
stream offset of the first hole), file name. With --frames it also writes <name>.frames next to
every stream: an independent walk over the msgr2 frame structure of that stream (banner, then
preambles with their CRC-32C, segment lengths, epilogues), written from docs/spec/msgr2.md 2.2 to
2.6.1 and used by the replay test as the reference for frame boundaries. Lines:

    banner <total length>
    frame <offset> <tag> <nseg> <len0> <len1> <len2> <len3> <wire size>
    end <offset>                       the stream ends exactly at a frame boundary
    stop <offset> <reason>             the walk stopped (secure mode, truncation, corruption)

Only the Python 3 standard library is used. Usage:

    pcap2stream.py [--frames] [--only NAME[,NAME...]] OUTDIR PCAP|DIR [PCAP|DIR ...]
"""
import os
import struct
import sys

# ---- CRC-32C (raw update, no inversion), only for the optional frame walk -------------------------

_POLY = 0x82F63B78
_TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ _POLY if _c & 1 else _c >> 1
    _TAB.append(_c)


def crc32c(seed, data):
    c = seed
    for b in data:
        c = (c >> 8) ^ _TAB[(c ^ b) & 0xFF]
    return c


# ---- capture file readers -------------------------------------------------------------------------

LINK_ETHERNET = 1
LINK_RAW = 101
LINK_RAW_IP = 12
LINK_LINUX_SLL = 113  # "any" device captures: 16-byte pseudo header, then the protocol type

# Packets that were looked at and dropped, by reason (reported on stderr: a capture that silently
# loses its IPv6 or unsupported-link packets would otherwise look like a capture with fewer streams).
SKIPPED = {}


def skip(reason):
    SKIPPED[reason] = SKIPPED.get(reason, 0) + 1
    return None


def read_pcap(data):
    """Yield (linktype, packet bytes) of a classic pcap file."""
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        raise ValueError("not a pcap file")
    link = struct.unpack(end + "I", data[20:24])[0] & 0x0FFFFFFF
    pos = 24
    while pos + 16 <= len(data):
        incl = struct.unpack(end + "I", data[pos + 8:pos + 12])[0]
        pos += 16
        if pos + incl > len(data):
            break
        yield link, data[pos:pos + incl]
        pos += incl


def read_pcapng(data):
    """Yield (linktype, packet bytes) of a pcapng file (enhanced and simple packet blocks)."""
    pos = 0
    end = "<"
    links = []
    while pos + 12 <= len(data):
        btype = struct.unpack("<I", data[pos:pos + 4])[0]
        if btype == 0x0A0D0D0A:  # section header: learn the byte order
            bom = data[pos + 8:pos + 12]
            end = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        else:
            btype = struct.unpack(end + "I", data[pos:pos + 4])[0]
        blen = struct.unpack(end + "I", data[pos + 4:pos + 8])[0]
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 4:  # interface description
            links.append(struct.unpack(end + "H", body[0:2])[0])
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            ifid, _, _, caplen, _ = struct.unpack(end + "IIIII", body[:20])
            link = links[ifid] if ifid < len(links) else LINK_ETHERNET
            yield link, body[20:20 + caplen]
        elif btype == 3 and len(body) >= 4:  # simple packet
            link = links[0] if links else LINK_ETHERNET
            yield link, body[4:]
        pos += blen  # block lengths already include the padding to 32 bits


def read_capture(path):
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] == b"\x0a\x0d\x0d\x0a":
        return read_pcapng(data)
    return read_pcap(data)


# ---- packet decoding ------------------------------------------------------------------------------

def tcp_packet(link, pkt):
    """Return (src ip, sport, dst ip, dport, seq, flags, payload) or None if not IPv4/TCP."""
    if link == LINK_ETHERNET:
        if len(pkt) < 14:
            return skip("short ethernet frame")
        etype = struct.unpack(">H", pkt[12:14])[0]
        off = 14
        while etype == 0x8100 and len(pkt) >= off + 4:
            etype = struct.unpack(">H", pkt[off + 2:off + 4])[0]
            off += 4
        if etype != 0x0800:
            return skip("not IPv4 (ethertype 0x%04x)" % etype)
        ip = pkt[off:]
    elif link == LINK_LINUX_SLL:
        if len(pkt) < 16:
            return skip("short cooked frame")
        etype = struct.unpack(">H", pkt[14:16])[0]
        if etype != 0x0800:
            return skip("not IPv4 (ethertype 0x%04x)" % etype)
        ip = pkt[16:]
    elif link in (LINK_RAW, LINK_RAW_IP):
        ip = pkt
    else:
        return skip("unsupported link type %d" % link)
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return skip("not IPv4 / truncated")
    ihl = (ip[0] & 15) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    frag = struct.unpack(">H", ip[6:8])[0]
    if ip[9] != 6:
        return skip("not TCP")
    if ihl < 20 or (frag & 0x3FFF) != 0:  # no fragments
        return skip("IPv4 fragment or bad header length")
    ip = ip[:total] if 20 <= total <= len(ip) else ip  # drop Ethernet padding
    tcp = ip[ihl:]
    if len(tcp) < 20:
        return skip("truncated TCP header")
    sport, dport, seq = struct.unpack(">HHI", tcp[0:8])
    doff = (tcp[12] >> 4) * 4
    flags = tcp[13]
    if doff < 20 or len(tcp) < doff:
        return skip("bad TCP header length")
    return ip[12:16], sport, ip[16:20], dport, seq, flags, tcp[doff:]


# ---- reassembly -----------------------------------------------------------------------------------

SYN, ACK = 0x02, 0x10


class Half(object):
    """One direction of a connection."""

    def __init__(self):
        self.isn = None       # sequence number of the SYN, if seen
        self.first = None     # sequence number of the first packet seen
        self.segs = []        # (seq, payload)

    def add(self, seq, flags, payload):
        if self.first is None:
            self.first = seq
        if flags & SYN:
            self.isn = seq
            seq = (seq + 1) & 0xFFFFFFFF  # the SYN itself uses one number; data on a SYN follows it
        if payload:
            self.segs.append((seq, payload))

    def assemble(self):
        """Return (bytes, offset of the first hole or -1)."""
        if not self.segs:
            return b"", -1
        if self.isn is not None:
            base = (self.isn + 1) & 0xFFFFFFFF
        else:
            # Capture started mid-connection: the stream starts at the lowest sequence number seen,
            # judged relative to the first packet so a wrap of the 32-bit counter does not matter.
            ref = self.first
            base = ref
            low = 0
            for seq, _ in self.segs:
                rel = (seq - ref) & 0xFFFFFFFF
                rel = rel - 0x100000000 if rel >= 0x80000000 else rel
                if rel < low:
                    low = rel
            base = (ref + low) & 0xFFFFFFFF
        items = []
        for seq, pl in self.segs:
            off = (seq - base) & 0xFFFFFFFF
            if off >= 0x80000000:  # before the start of the stream (a stray old segment): ignore
                continue
            items.append((off, pl))
        items.sort(key=lambda t: t[0])
        out = bytearray()
        for off, pl in items:
            cur = len(out)
            if off + len(pl) <= cur:
                continue  # pure duplicate
            if off > cur:
                return bytes(out), cur  # a hole: the stream ends here
            out += pl[cur - off:]
        return bytes(out), -1


class Conn(object):
    def __init__(self, client, server):
        self.client = client  # (ip, port)
        self.server = server
        self.half = {client: Half(), server: Half()}
        self.syn_seen = False


def extract(path):
    """Return a list of connections of one capture in order of first appearance."""
    conns = []
    by_key = {}
    for link, pkt in read_capture(path):
        t = tcp_packet(link, pkt)
        if t is None:
            continue
        sip, sport, dip, dport, seq, flags, payload = t
        a, b = (sip, sport), (dip, dport)
        key = frozenset((a, b))
        c = by_key.get(key)
        is_syn = bool(flags & SYN) and not flags & ACK
        if c is not None and is_syn and c.half[a].isn is not None and c.half[a].isn != seq:
            c = None  # the same four-tuple again: a new connection
        if c is None:
            c = Conn(a, b)  # the sender of the first packet counts as the client
            by_key[key] = c
            conns.append(c)
        elif is_syn and not c.syn_seen:
            c.client, c.server = a, b  # the first packet seen was not the client's
        if is_syn:
            c.syn_seen = True
        c.half[a].add(seq, flags, payload)
    return conns


# ---- independent msgr2 frame walk (reference for the replay test) -------------------------------

def frame_walk(data):
    lines = []
    if len(data) < 10 or data[:8] != b"ceph v2\n":
        return ["stop 0 banner"]
    plen = struct.unpack("<H", data[8:10])[0]
    off = 10 + plen
    if off > len(data):
        return ["stop 0 banner truncated"]
    lines.append("banner %d" % off)
    while True:
        if off == len(data):
            lines.append("end %d" % off)
            return lines
        if off + 32 > len(data):
            lines.append("stop %d truncated preamble" % off)
            return lines
        pre = data[off:off + 32]
        if crc32c(0, pre[:28]) != struct.unpack("<I", pre[28:32])[0]:
            lines.append("stop %d preamble crc" % off)
            return lines
        tag, nseg = pre[0], pre[1]
        if nseg < 1 or nseg > 4:
            lines.append("stop %d nseg" % off)
            return lines
        lens = [struct.unpack("<I", pre[2 + 6 * i:6 + 6 * i])[0] for i in range(4)]
        size = 32 + (lens[0] + 4 if lens[0] else 0) + sum(lens[1:nseg]) + (13 if nseg > 1 else 0)
        if off + size > len(data):
            lines.append("stop %d truncated frame" % off)
            return lines
        lines.append("frame %d %d %d %d %d %d %d %d" % ((off, tag, nseg) + tuple(lens) + (size,)))
        off += size


# ---- main -----------------------------------------------------------------------------------------

def main(argv):
    frames = False
    only = None
    args = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--frames":
            frames = True
        elif a == "--only" and i + 1 < len(argv):
            i += 1
            only = set(argv[i].split(","))
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            args.append(a)
        i += 1
    if len(args) < 2:
        sys.stderr.write("usage: pcap2stream.py [--frames] [--only NAME,...] OUTDIR PCAP|DIR ...\n")
        return 2
    outdir = args[0]
    files = []
    for p in args[1:]:
        if os.path.isdir(p):
            for n in sorted(os.listdir(p)):
                if n.endswith((".pcap", ".pcapng", ".cap")):
                    files.append(os.path.join(p, n))
        else:
            files.append(p)
    os.makedirs(outdir, exist_ok=True)
    index = []
    for path in files:
        session = os.path.splitext(os.path.basename(path))[0]
        if only is not None and session not in only:
            continue
        for n, c in enumerate(extract(path)):
            for tag, who in (("c2s", c.client), ("s2c", c.server)):
                data, gap = c.half[who].assemble()
                if not data:
                    continue
                name = "%s.c%02d.%s.bin" % (session, n, tag)
                with open(os.path.join(outdir, name), "wb") as f:
                    f.write(data)
                if frames:
                    with open(os.path.join(outdir, name[:-4] + ".frames"), "w") as f:
                        f.write("\n".join(frame_walk(data)) + "\n")
                index.append((session, n, tag, c.server[1], len(data), gap, name))
    with open(os.path.join(outdir, "index.tsv"), "w") as f:
        for row in index:
            f.write("\t".join(str(x) for x in row) + "\n")
    for reason in sorted(SKIPPED):
        sys.stderr.write("pcap2stream: skipped %d packet(s): %s\n" % (SKIPPED[reason], reason))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
