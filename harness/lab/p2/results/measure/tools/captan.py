#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""captan.py - what a tcpdump of the guest's TCP traffic says about iPXE's one-packet-per-round-trip transmit (risk R6).

  captan.py FILE [--guest 10.77.0.61] [--json OUT]     FILE is "tcpdump -nn -tt" text taken on the lab VM's lab NIC (headers only)
  captan.py selftest

iPXE's tcp_xfer_window() is 0 while its transmit queue is not empty, so it sends one segment and waits for the acknowledgement before the next one. The
throughput of a write is then about MSS per round trip, and the round trip includes whatever the receiver does before it acknowledges (a Linux receiver may
hold the acknowledgement of a single segment back for its delayed-ACK timer). This reads the capture and reports, per connection of the guest and in total:

  data segments the guest sent, bytes, the largest segment (MSS as seen), the most bytes in flight at any moment (1 segment = stop and wait),
  the time between the guest's consecutive data segments (median, 90th percentile),
  the time from a data segment to the first acknowledgement that covers it (median, 90th percentile, and the share at or over 30 ms: the delayed-ACK signature),
  the rate the stop-and-wait model gives: MSS / (median time between consecutive data segments)

Only connections in which the guest sent at least 20 data segments are reported (the monitor and idle connections do not matter here).

Two things about the text of a capture that this tool has to live with (the review of the module found both in the evidence):
  * tcpdump prints sequence numbers relative to the first packet it saw of a direction, and that first packet itself in full. A connection that was
    already open when the capture started therefore has one packet in a different numbering from all the others; taken as it is, the first absolute
    acknowledgement keeps "the highest acknowledgement seen" above every later segment and the bytes in flight come out as 0 for the whole connection.
    The tool drops such a packet (a guest segment whose sequence is far above the next one, an acknowledgement far above every segment end) and, when it
    cannot tell the numbering apart at all, reports "inflight_max_bytes" as null instead of a number. A flow that has a data segment in flight always has
    at least that segment's length in flight, so 0 is never a measurement: readers treat 0 and null as "not measured". New captures should use
    "tcpdump -S" (absolute numbers everywhere), as mrun.sh now does.
  * on the lab VM's NIC every packet that the lab VM sent is in the capture twice (about 0.3 ms apart); the guest's own packets are in it once. The figures
    of the guest's segments (gaps, sizes, bytes in flight) are not affected; for the delay to the acknowledgement the first copy counts.
"""
import json, re, statistics, sys
from collections import defaultdict

LINE = re.compile(r"^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\](?:, seq (\d+)(?::(\d+))?)?(?:, ack (\d+))?.*?, length (\d+)")


def parse(text, guest):
    flows = defaultdict(list)
    for ln in text.splitlines():
        m = LINE.match(ln.strip())
        if not m:
            continue
        t, sa, sp, da, dp, flags, s1, s2, ack, ln_ = m.groups()
        t = float(t)
        length = int(ln_)
        if sa == guest:
            key = (dp, da)
            flows[key].append(("g", t, int(s1) if s1 else None, length, None, flags))
        elif da == guest:
            key = (sp, sa)
            flows[key].append(("p", t, None, length, int(ack) if ack else None, flags))
    return flows


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = min(len(xs) - 1, int(round(p / 100.0 * (len(xs) - 1))))
    return xs[k]


def analyse_flow(pkts):
    """pkts: list of (who, t, seq, len, ack, flags) in time order. Sequence numbers are used as they come (tcpdump -tt without -S prints relative ones)."""
    data = [p for p in pkts if p[0] == "g" and p[3] > 0 and "S" not in p[5]]
    # the first packet of a direction that tcpdump saw is printed with absolute numbers and all later ones relative to it: such a segment is far above the next
    # one (the numbers are relative to 2^32 only by chance of the ISN, so "far" is a quarter of the sequence space)
    far = 1 << 30
    while len(data) > 1 and data[0][2] is not None and data[1][2] is not None and data[0][2] > data[1][2] + far:
        data = data[1:]
    out = dict(segments=len(data), bytes=sum(p[3] for p in data))
    if not data:
        return out
    out["mss"] = max(p[3] for p in data)
    gaps = [b[1] - a[1] for a, b in zip(data, data[1:])]
    out["gap_median_ms"] = statistics.median(gaps) * 1000 if gaps else None
    out["gap_p90_ms"] = pct(gaps, 90) * 1000 if gaps else None
    # time to the first ack covering a segment, and the bytes in flight
    # (tcpdump prints the sequence and acknowledgement numbers of a SYN as absolute numbers and all others relative to it: the SYN-ACK is left out)
    acks = [(p[1], p[4]) for p in pkts if p[0] == "p" and p[4] is not None and "S" not in p[5]]
    top_end = max((d[2] or 0) + d[3] for d in data)
    # an acknowledgement that is above every segment end by more than a quarter of the sequence space is the one packet printed with absolute numbers
    mixed = any(a[1] > top_end + far for a in acks)
    acks = [a for a in acks if a[1] <= top_end + far]
    delays = []
    ai = 0
    inflight_max = 0
    first_seq = data[0][2] or 0
    for d in data:
        end = (d[2] or 0) + d[3]
        while ai < len(acks) and (acks[ai][1] < end or acks[ai][0] < d[1]):
            ai += 1
        if ai < len(acks):
            delays.append(acks[ai][0] - d[1])
    # in flight: highest sequence sent minus highest ack seen before this segment went out
    top_ack = first_seq
    k = 0
    for d in data:
        while k < len(acks) and acks[k][0] <= d[1]:
            top_ack = max(top_ack, acks[k][1])
            k += 1
        end = (d[2] or 0) + d[3]
        inflight_max = max(inflight_max, end - top_ack)
    out["inflight_max_bytes"] = inflight_max if inflight_max > 0 else None      # 0 cannot be a measurement of a flow that sent data: not measured
    out["numbering_mixed"] = mixed
    if delays:
        out["ack_delay_median_ms"] = statistics.median(delays) * 1000
        out["ack_delay_p90_ms"] = pct(delays, 90) * 1000
        out["ack_delay_ge_30ms_pct"] = 100.0 * sum(1 for x in delays if x >= 0.030) / len(delays)
    if gaps and out["gap_median_ms"]:
        out["model_mibs"] = out["mss"] / (out["gap_median_ms"] / 1000.0) / 1048576.0
    span = data[-1][1] - data[0][1]
    out["span_s"] = span
    if span > 0:
        out["rate_mibs"] = out["bytes"] / span / 1048576.0
    return out


def analyse(text, guest):
    flows = parse(text, guest)
    res = {}
    for key, pk in sorted(flows.items()):
        pk.sort(key=lambda p: p[1])
        a = analyse_flow(pk)
        if a["segments"] >= 20:
            res["%s:%s" % key[::-1]] = a
    return res


def selftest():
    fails = []

    def check(ok, what):
        if not ok:
            fails.append(what)
        print(("ok   " if ok else "FAIL ") + what)

    # a synthetic stop-and-wait flow: 1448-byte segments, one per 2 ms, each acknowledged 0.4 ms after it was sent
    lines = []
    t = 1000.0
    seq = 1
    for i in range(50):
        lines.append("%.6f IP 10.77.0.61.50000 > 10.77.0.10.6800: Flags [P.], seq %d:%d, ack 1, win 8192, length 1448" % (t, seq, seq + 1448))
        seq += 1448
        lines.append("%.6f IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [.], ack %d, win 501, length 0" % (t + 0.0004, seq))
        t += 0.002
    lines.insert(0, "999.999000 IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [S.], seq 1396575403, ack 1678047434, win 65160, options [mss 1460], length 0")
    r = analyse("\n".join(lines), "10.77.0.61")
    f = r["6800:10.77.0.10"] if "6800:10.77.0.10" in r else list(r.values())[0]
    check(f["segments"] == 50 and f["mss"] == 1448 and f["bytes"] == 50 * 1448, "segments, bytes and MSS are counted")
    check(abs(f["gap_median_ms"] - 2.0) < 0.01, "median gap between data segments is 2 ms (%.3f)" % f["gap_median_ms"])
    check(abs(f["ack_delay_median_ms"] - 0.4) < 0.01 and f["ack_delay_ge_30ms_pct"] == 0.0, "ACK delay 0.4 ms, none delayed")
    check(f["inflight_max_bytes"] == 1448, "stop and wait: one segment in flight at most (%d)" % f["inflight_max_bytes"])
    check(abs(f["model_mibs"] - 1448 / 0.002 / 1048576) < 1e-6, "the model rate is MSS / gap")
    # delayed ACKs: every ack comes 40 ms late
    lines = []
    t = 1000.0
    seq = 1
    for i in range(30):
        lines.append("%.6f IP 10.77.0.61.50000 > 10.77.0.10.6800: Flags [P.], seq %d:%d, ack 1, win 8192, length 1448" % (t, seq, seq + 1448))
        seq += 1448
        lines.append("%.6f IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [.], ack %d, win 501, length 0" % (t + 0.04, seq))
        t += 0.0401
    f = list(analyse("\n".join(lines), "10.77.0.61").values())[0]
    check(f["ack_delay_ge_30ms_pct"] == 100.0 and f["model_mibs"] < 0.05, "delayed ACKs are seen (100 %% at 30 ms or more, model %.3f MiB/s)" % f["model_mibs"])
    # a window of several segments in flight is not stop and wait
    lines = []
    t = 1000.0
    for i in range(40):
        lines.append("%.6f IP 10.77.0.61.50000 > 10.77.0.10.6800: Flags [.], seq %d:%d, ack 1, win 8192, length 1448" % (t + i * 0.0001, 1 + i * 1448, 1 + (i + 1) * 1448))
    lines.append("%.6f IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [.], ack %d, win 501, length 0" % (t + 0.01, 1 + 40 * 1448))
    f = list(analyse("\n".join(lines), "10.77.0.61").values())[0]
    check(f["inflight_max_bytes"] > 10 * 1448, "negative control: 40 segments back to back are more than one in flight (%d)" % f["inflight_max_bytes"])
    # a connection that was open when the capture started (the review's finding): tcpdump prints the first packet of each direction with absolute numbers and
    # every later packet relative to it. The peer's first packet carries an absolute acknowledgement, the guest's first data segment an absolute sequence.
    base = 3000000000
    lines = ["1000.000000 IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [P.], seq 77:100, ack %d, win 501, length 23" % (base + 1)]
    t = 1000.001
    seq = 0
    for i in range(40):
        if i == 0:
            lines.append("%.6f IP 10.77.0.61.50000 > 10.77.0.10.6800: Flags [P.], seq %d:%d, ack 100, win 8192, length 1208" % (t, base, base + 1208))
        else:
            lines.append("%.6f IP 10.77.0.61.50000 > 10.77.0.10.6800: Flags [P.], seq %d:%d, ack 1, win 8192, length 1208" % (t, seq, seq + 1208))
        seq += 1208
        lines.append("%.6f IP 10.77.0.10.6800 > 10.77.0.61.50000: Flags [.], ack %d, win 501, length 0" % (t + 0.0004, seq))
        t += 0.002
    f = list(analyse("\n".join(lines), "10.77.0.61").values())[0]
    check(f["segments"] == 39 and f["inflight_max_bytes"] == 1208, "mid-connection capture: the packet printed in absolute numbers is dropped and one segment in flight is found (%s segments, %s bytes)" %
          (f["segments"], f["inflight_max_bytes"]))
    check(f["ack_delay_median_ms"] is not None and abs(f["ack_delay_median_ms"] - 0.4) < 0.05, "mid-connection capture: the ACK delay is still measured (%.3f ms)" % f["ack_delay_median_ms"])
    # every packet of the peer twice (what the lab VM's capture shows): nothing changes
    dup = []
    for ln in lines:
        dup.append(ln)
        if " 10.77.0.10.6800 > " in ln:
            dup.append(ln)
    fd = list(analyse("\n".join(dup), "10.77.0.61").values())[0]
    check(fd["segments"] == f["segments"] and fd["inflight_max_bytes"] == f["inflight_max_bytes"] and abs(fd["gap_median_ms"] - f["gap_median_ms"]) < 1e-6,
          "the peer's packets twice in the capture change no figure of the guest's segments")
    check(analyse("garbage\n", "10.77.0.61") == {}, "negative control: a capture with no flow gives no result")
    print("selftest: %s" % ("PASS" if not fails else "FAIL (%d)" % len(fails)))
    return 0 if not fails else 1


def main(argv):
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) < 2:
        print(__doc__)
        return 2
    guest = argv[argv.index("--guest") + 1] if "--guest" in argv else "10.77.0.61"
    text = open(argv[1], errors="replace").read()
    res = analyse(text, guest)
    if "--json" in argv:
        json.dump(res, open(argv[argv.index("--json") + 1], "w"), indent=1, sort_keys=True)
    for k, v in res.items():
        print(k, json.dumps(v, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
