#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
#
# secure_tamper_proxy.py: a transparent TCP relay for the lab that damages ONE bit of ONE direction of ONE connection at a chosen byte offset of the
# stream, and writes down what it did. It is the "attacker on the wire" of harness/lab/secure-tamper.sh (milestone 11): the winrbd core runs in a
# network namespace in which an iptables REDIRECT sends every connection to the lab's monitor and OSDs to this relay, which reads the original
# destination (SO_ORIGINAL_DST), connects to it (with a socket mark that the REDIRECT rule leaves alone) and copies the bytes both ways.
#
#   secure_tamper_proxy.py --listen-port 7777 --mark 119 --log FILE
#                          [--dir s2c|c2s] [--offset N] [--bit B] [--only-port P] [--count K] [--grep HEXPATTERN]
#
#   --dir      the direction to damage: s2c = bytes the daemon sent to the core, c2s = bytes the core sent (default s2c)
#   --offset   the 0-based offset in that direction's stream (counted from the first byte of the connection, TCP banner included) of the byte
#              whose bit --bit (0..7, default 0) is flipped. A connection that never carries that many bytes is passed untouched, so a small
#              offset past the handshake damages the first connection that sends a real frame, a big one only the connection that moves data.
#              Without --offset nothing is damaged (a pure relay, used for the control runs and for --grep).
#   --only-port  damage only connections whose original destination port is P (the monitor's 3300, an OSD's 68xx); default any
#   --count    how many connections get damaged in all (default 1: the first connection whose stream reaches the offset; the core's redial
#              must then go through clean)
#   --grep     hex pattern (e.g. 2a2b2c): the number of times it occurs in the raw bytes of each direction is logged when the connection ends, so a
#              run can show that the pattern written in a crc run is on the wire and that the same pattern is not on the wire of a secure run
#
# The log has one line per event, "TAMPER ...", "CONN ..." and "END ...", with the original destination and the byte counts. The relay never
# looks at what the bytes mean: it does not know msgr2, so a flipped bit is a flipped bit wherever it lands. It prints no key material because it
# never sees one (the keys are inside the encrypted authentication exchange and the relay does not decode it).
#
# Written for the lab VM (Python 3.8 or later, standard library only), run as root inside the network namespace (SO_MARK needs CAP_NET_ADMIN).

import argparse
import socket
import struct
import sys
import threading
import time

SO_ORIGINAL_DST = 80
SOL_IP = 0


def orig_dst(conn):
    raw = conn.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
    port, = struct.unpack("!H", raw[2:4])
    return socket.inet_ntoa(raw[4:8]), port


class Shared:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.left = args.count if args.offset is not None else 0
        self.conn_no = 0
        self.logf = open(args.log, "a", buffering=1)

    def log(self, text):
        with self.lock:
            self.logf.write("%.3f %s\n" % (time.time(), text))

    def next_conn(self):
        with self.lock:
            self.conn_no += 1
            return self.conn_no

    def eligible(self, port):
        a = self.args
        return a.offset is not None and (a.only_port is None or a.only_port == port)

    def claim(self):
        # called at the moment a stream reaches the offset: the first connection to get there takes one of the --count tokens
        with self.lock:
            if self.left > 0:
                self.left -= 1
                return True
        return False


def pump(sh, src, dst, label, tamper_here, stats, cid, pat):
    a = sh.args
    seen = 0
    tampered = False
    window = b""
    hits = 0
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            if pat:
                buf = window + data
                hits += buf.count(pat)
                window = buf[-(len(pat) - 1):] if len(pat) > 1 else b""
            if tamper_here and not tampered and seen <= a.offset < seen + len(data) and sh.claim():
                i = a.offset - seen
                data = data[:i] + bytes([data[i] ^ (1 << a.bit)]) + data[i + 1:]
                tampered = True
                stats["tampered"] = True
                sh.log("TAMPER conn=%d dst=%s dir=%s offset=%d bit=%d" % (cid, stats["dst"], label, a.offset, a.bit))
            seen += len(data)
            dst.sendall(data)
    except OSError:
        pass
    finally:
        stats[label] = seen
        stats[label + "_hits"] = hits
        for s, how in ((dst, socket.SHUT_WR), (src, socket.SHUT_RD)):
            try:
                s.shutdown(how)
            except OSError:
                pass


def handle(sh, cl):
    a = sh.args
    cid = sh.next_conn()
    try:
        ip, port = orig_dst(cl)
    except OSError as e:
        sh.log("CONN %d no original destination (%s)" % (cid, e))
        cl.close()
        return
    dst = "%s:%d" % (ip, port)
    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, a.mark)
    try:
        up.connect((ip, port))
    except OSError as e:
        sh.log("CONN %d dst=%s upstream connect failed: %s" % (cid, dst, e))
        cl.close()
        up.close()
        return
    for s in (cl, up):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    token = sh.eligible(port)
    sh.log("CONN %d dst=%s eligible=%d" % (cid, dst, 1 if token else 0))
    stats = {"dst": dst, "tampered": False}
    pat = bytes.fromhex(a.grep) if a.grep else b""
    c2s_t = token and a.dir == "c2s"
    s2c_t = token and a.dir == "s2c"
    t1 = threading.Thread(target=pump, args=(sh, cl, up, "c2s", c2s_t, stats, cid, pat), daemon=True)
    t2 = threading.Thread(target=pump, args=(sh, up, cl, "s2c", s2c_t, stats, cid, pat), daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    sh.log("END %d dst=%s c2s=%d s2c=%d c2s_pattern=%d s2c_pattern=%d tampered=%d" % (
        cid, dst, stats.get("c2s", 0), stats.get("s2c", 0), stats.get("c2s_hits", 0), stats.get("s2c_hits", 0), 1 if stats["tampered"] else 0))
    cl.close()
    up.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--listen-port", type=int, required=True)
    p.add_argument("--mark", type=int, required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--dir", choices=("s2c", "c2s"), default="s2c")
    p.add_argument("--offset", type=int, default=None)
    p.add_argument("--bit", type=int, default=0)
    p.add_argument("--only-port", type=int, default=None)
    p.add_argument("--count", type=int, default=1)
    p.add_argument("--grep", default="")
    a = p.parse_args()
    if not 0 <= a.bit <= 7 or (a.offset is not None and a.offset < 0) or a.count < 0:
        sys.exit("secure_tamper_proxy: bad --bit, --offset or --count")
    sh = Shared(a)
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", a.listen_port))
    ls.listen(64)
    sh.log("LISTEN port=%d dir=%s offset=%s bit=%d only_port=%s count=%d" % (a.listen_port, a.dir, a.offset, a.bit, a.only_port, a.count))
    print("ready", flush=True)
    while True:
        c, _ = ls.accept()
        threading.Thread(target=handle, args=(sh, c), daemon=True).start()


if __name__ == "__main__":
    main()
