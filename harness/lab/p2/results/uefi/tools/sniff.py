#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Watch the lab's private layer 2 (QEMU's multicast socket on the loopback address) and summarise the frames of one guest.

    sniff.py SECONDS MAC [GROUP:PORT]

QEMU's "-netdev socket,mcast=GROUP:PORT,localaddr=127.0.0.1" puts every Ethernet frame of every guest NIC into a UDP datagram to the group, so
joining the group on 127.0.0.1 shows all of them (read-only: nothing is sent). Prints, per second, how many frames the guest with MAC sent and
of what kind (ARP, DHCP, TCP by port, other), and the frames sent TO it (tx: from the guest, rx: to the guest), so that a firmware network stack that starts talking on the lab NIC, or a guest that goes silent,
is visible. The tool is a diagnostic for findings, not a test. Standard library only."""
import socket
import struct
import sys
import time
from collections import Counter


def kind(frame):
    if len(frame) < 14:
        return "short"
    et = struct.unpack("!H", frame[12:14])[0]
    if et == 0x0806:
        op = struct.unpack("!H", frame[20:22])[0] if len(frame) >= 22 else 0
        return "ARP-req" if op == 1 else "ARP-rep"
    if et == 0x86DD:
        return "IPv6"
    if et != 0x0800 or len(frame) < 34:
        return "eth-%04x" % et
    ihl = (frame[14] & 15) * 4
    proto = frame[23]
    p = 14 + ihl
    if proto == 17 and len(frame) >= p + 4:
        sp, dp = struct.unpack("!HH", frame[p:p + 4])
        if 67 in (sp, dp) or 68 in (sp, dp):
            return "DHCP"
        return "UDP"
    if proto == 6 and len(frame) >= p + 14:
        sp, dp = struct.unpack("!HH", frame[p:p + 4])
        fl = frame[p + 13]
        port = min(sp, dp)
        tag = "TCP:%d" % (3300 if 3300 in (sp, dp) else (6800 if 6800 <= port <= 7300 else port))
        if fl & 4:
            tag += "+RST"
        return tag
    return "ip-proto-%d" % proto


def main():
    secs, mac = float(sys.argv[1]), bytes.fromhex(sys.argv[2].replace(":", ""))
    group, port = ("230.77.12.1", 7712)
    if len(sys.argv) > 3:
        group, port = sys.argv[3].split(":")
        port = int(port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except (AttributeError, OSError):
        pass
    s.bind(("", port))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(group) + socket.inet_aton("127.0.0.1"))
    s.settimeout(0.2)
    t0 = time.monotonic()
    cur = Counter()
    sec = 0
    while time.monotonic() - t0 < secs:
        try:
            data = s.recv(65535)
        except socket.timeout:
            data = None
        if data and len(data) >= 14:
            if data[6:12] == mac:
                cur["tx:" + kind(data)] += 1
            elif data[0:6] == mac or (data[0:6] == b"\xff" * 6 and False):
                cur["rx:" + kind(data)] += 1
        now = int(time.monotonic() - t0)
        if now != sec:
            if cur:
                print("%s %4ds %s" % (time.strftime("%H:%M:%S"), sec, " ".join("%s=%d" % kv for kv in sorted(cur.items()))), flush=True)
            cur = Counter()
            sec = now
    if cur:
        print("%s %4ds %s" % (time.strftime("%H:%M:%S"), sec, " ".join("%s=%d" % kv for kv in sorted(cur.items()))), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
