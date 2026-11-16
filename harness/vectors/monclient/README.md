# Monitor-client test vectors

Test vectors for `docs/spec/mon-client.md`: the messages a minimal client sends to and receives from a
Ceph monitor (MMonGetMap, MMonSubscribe, MMonMap with its MonMap, MOSDMap, MAuth / MAuthReply for ticket
renewal, msgr2 keepalives), plus two message-order scenarios.

License: MIT (see `COPYING.MIT`).

## Provenance

Everything here was taken from the Phase 0 capture set: packet captures of the stock Ceph v20.2.5 command
line tools (`rbd`, `rados`, `ceph`, python rados) talking to a disposable single-monitor lab cluster
(monitor at 10.77.0.10, ports 3300 / 6789). The client ran in a network namespace so the captures hold real
Ethernet frames. The capture set itself, the keyrings and all session keys stay OUTSIDE this repository.

The vectors are produced and re-verified by `harness/tools/monclient_check.py`; the checker decodes the
captured TCP streams with its own msgr2 / cephx code (the lab keyrings are read at run time to decrypt the
authentication exchange), so the bytes were obtained without any Ceph decoder. The Ceph tools' output
(`ceph mon dump`, `ceph mon getmap`, the monitor-store copies of every map) is used only as the expected
answer.

| Source session | What it contributes |
|---|---|
| `k2-rbd-info-default` | first connection: bootstrap monitor session; second connection: the real session (MMonGetMap, subscribes, MMonMap, MOSDMap) |
| `k2-mon-restart` | monitor connection made after a monitor restart (global_id reclaim, subscriptions re-sent with held + 1) |
| `k2-renew-ttl60` | in-session ticket renewal (MAuth / MAuthReply), `auth_service_ticket_ttl` = 60 s |
| `k2-idle75` | KEEPALIVE2 / KEEPALIVE2_ACK |
| monitor store copy of the lab cluster | the two Incrementals used by the synthetic MOSDMap |

All sessions in the set use key type aes256k (`k2-*`); the `k1-*` sessions (legacy aes key) gave identical
monitor-client behaviour and are covered by the checker run, not by separate vectors.

## Files

Each file is one JSON object: `id`, `description`, `source`, hex fields, `expect` (what a decoder must find),
`scrub`. Hex is lower case, no separators. A "frame" is a complete msgr2.1 crc-mode frame as it crosses the
wire (preamble, segment 0 with its CRC, front segment, epilogue); "header2" is the 41-byte `ceph_msg_header2`
(segment 0 of a MESSAGE frame); "front" is the message body (segment 1).

| File | Content |
|---|---|
| `mmongetmap.json` | MMonGetMap, whole frame (77 bytes) |
| `mmonsubscribe-config-monmap.json` | first MMonSubscribe of a session: {config 0/0, monmap 0/0} |
| `mmonsubscribe-mgrmap.json` | {mgrmap 0/0} |
| `mmonsubscribe-osdmap-start0-onetime.json` | {osdmap start 0, flags 1} |
| `mmonsubscribe-reconnect.json` | after a monitor restart: monmap 4, osdmap 93 ONETIME, config 0, mgrmap 0 |
| `mmonsubscribe-derived-monmap-only.json` | the 28-byte example derived in the note (not a capture, see below) |
| `mmonmap-e3.json` | MMonMap: header2, front, the MonMap blob (struct_v 10 / compat 6) and its decoded fields |
| `mosdmap-v4-full-e42.json` | MOSDMap v4 / compat 3 answering a start-0 subscription: one full map (epoch 42) |
| `mosdmap-v4-inc-e42-e43-synthetic.json` | SYNTHETIC: MOSDMap body with two stored Incrementals (see below) |
| `mauth-renewal-scrubbed.json` | MAuth renewal request, tickets and proof replaced by placeholders |
| `mauthreply-renewal-scrubbed.json` | MAuthReply to it, ciphertexts and ticket blobs replaced by placeholders |
| `keepalive2-pair.json` | KEEPALIVE2 and KEEPALIVE2_ACK frames (44 bytes each) |
| `scenario-fresh-session.json` | message order on the two monitor connections a tool opens at start-up |
| `scenario-monitor-restart.json` | message order after a monitor restart |

## What was scrubbed, and what was kept

Nothing secret is in these files. Rules applied (and checked by the generator):

- **Key material, session keys, tickets, signatures, nonces derived from keys, connection secrets and any
  encrypted blob are not present.** The MAuth / MAuthReply vectors keep only the structure: the AUTH ticket
  blob, the authorizer proof, every `msg_a` ciphertext and every opaque ticket blob are overwritten with
  `0xEE` bytes of the same length; `scrubbed_regions` lists offset, length and meaning of each replaced
  region (offsets are into `front_hex`). The scrubbed bytes are therefore not decryptable and not valid
  ciphertext; they are for parsing tests only. Plain fields (global_id, secret_id counters, service ids, lengths) are kept.
- The monitor-client messages of the sessions used here carry no other secrets. The authentication frames,
  the signatures and the secure-mode material are NOT part of these vectors (they belong to the msgr2 / cephx
  vectors).
- **Host name:** the stock client puts the machine's short host name into MMonSubscribe. It was replaced by
  `host1` and the frame was re-assembled with fresh segment lengths and CRCs (the generator asserts that its frame builder reproduces the unmodified captured
  MMonGetMap frame byte for byte, and the checker re-reads every vector frame with the independent frame reader). The frames are therefore not
  literal wire bytes for the subscribe vectors, but every other byte is.
- **Kept on purpose** (random lab values, not secrets): the lab cluster fsid, the monitor name and address
  (`10.77.0.10`, nonce 0), epochs, timestamps of the lab VM, global ids of the lab clients.
- The client's own address (the capture namespace) does not appear in any vector.

## Synthetic and derived vectors

- `mosdmap-v4-inc-e42-e43-synthetic.json` is NOT a capture. No captured MOSDMap contains an incremental (the
  stock tools only ask for the newest map, and the lab map history was never trimmed). The body is laid out
  as section 2.6 of the note describes (fsid, incremental_maps, empty maps, trim bound 1, newest 43, 4 zero
  bytes) around the two Incrementals of epochs 42 and 43 exactly as the monitor stores them. The real monitor
  sends the same blobs for a client with the full feature mask (the checker verifies that for full maps), but
  this message was not seen on the wire.
- `mmonsubscribe-derived-monmap-only.json` is the example derived in section 5 of the note, not captured. The
  checker confirms that re-encoding every captured MMonSubscribe from its decoded fields reproduces the wire
  bytes exactly, so the example is what the real client would send for these fields.

## Verifying and regenerating

```
python3 harness/tools/monclient_check.py                          # the public vector set (harness/vectors/public)
python3 harness/tools/monclient_check.py --captures <capture dir>
```

needs Python 3, the `cryptography` package and a capture directory (default: the public set; `pcap/`, `sessions.tsv`, `gt/`, `gt3/`,
`data/`; the keyrings are read from `harness/vectors/public/keys` for the public set, else from `<capture dir>/../lab-secrets`, or `--secrets <dir>`). It analyses every
session (a few seconds on a multi-core machine), prints every failed check with an example, lists
informational observations, verifies the vectors in this directory, and exits 0 only when every check passes.
The vectors are also checked on their own terms: frame CRCs, header2, front bytes, decoded fields and
re-encoding, MonMap and MOSDMap contents, CRC of every embedded map blob.

```
python3 harness/tools/monclient_check.py --captures <capture dir> --write-vectors harness/vectors/monclient
```

rewrites these files from the captures (deterministic). Without the capture directory the vectors can still
be consumed directly: they are plain JSON with hex fields.
