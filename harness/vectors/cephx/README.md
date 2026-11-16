# cephx test vectors and checker

Vectors for `docs/spec/cephx.md` (and the msgr2 framing it rests on), plus the checker that produced
and verifies them. Everything here is MIT-licensed project code or public-standard data. No secret from
any real cluster is committed.

## Running the checker

```
python3 harness/tools/cephx_check.py --vectors harness/vectors/cephx                 # offline, seconds
python3 harness/tools/cephx_check.py                                                 # public vector set + these vectors (what harness/tools/run-all.sh runs)
python3 harness/tools/cephx_check.py --captures <captures-dir> [--jobs N]           # another capture set
python3 harness/tools/cephx_check.py --captures <dir> --vectors harness/vectors/cephx
```

Exit status is 0 only if every check passed. Needs Python 3 and the `cryptography` package
(`pip install --user cryptography`).

Without arguments the tool checks the public set `harness/vectors/public/` with the keys in `harness/vectors/public/keys/`.
`--captures <dir>` expects the layout of a capture set: `pcap/*.pcap`, `sessions.tsv`, and (for a set other than the public one)
keyrings at `<dir>/../lab-secrets/*` and `<dir>/secrets/keys/*` (override with `--keys <dir>`, repeatable). Keys are read at
run time and never printed; the optional `<dir>/secrets/session-secrets/*.txt` (client `debug_auth` logs) is used
only as an after-the-fact cross-check of the decrypted session keys, and `<dir>/stdout/*.tcpdump.err` to explain
packets the capture host dropped. The private Phase 0 captures are not part of this repository; the public set is.

The checker was written from the spec notes only (`cephx.md`, `msgr2.md`, `msgr2-secure-mode.md`), not from Ceph
source. What it does per pcap: reassembles the TCP streams; parses every msgr2 frame in both directions and
verifies the preamble CRC, the inline segment-0 CRC, the epilogue CRCs and `late_status`; decodes the cephx
exchanges of every mon and OSD/MGR connection with the lab keys (both key types); recomputes the challenge proofs;
checks every field of every structure of `cephx.md` 2.2 to 2.11; recomputes both AUTH_SIGNATURE HMACs over the raw
transcripts; for secure-mode connections derives the AES-128-GCM key and nonces from the decrypted connection
secret and decrypts every frame to the end of the stream (all GCM tags and preamble CRCs checked); decodes MAuth /
MAuthReply renewal traffic; and checks renewal timing and connection survival in the 60 s ticket sessions.
`--emit-vectors <dir>` regenerates the synthetic vectors (deterministic) and, with `--captures`, the scrubbed
frames; `--summary-json` writes the per-connection structure summary (no secrets).

Not covered by this checker, because they belong to other notes: OSDMap / Incremental decoding, CRUSH placement,
MOSDOp / MOSDOpReply, RBD class calls, MMonMap / MMonSubscribe / MOSDMap decoding.

## Files

| File | Origin | Content |
|---|---|---|
| `rfc8009-aes256-cts-hmac-sha384-192.json` | public standard | The four AES-256 test vectors of RFC 8009 Appendix A (key usage 2): base key, derived Ke / Ki, confounder, plaintext, ciphertext and 24-byte MAC. Typed from the RFC text. Reproduced by the cipher the notes describe for key type 2. |
| `cipher-type1.json` | synthetic | AES-128-CBC with the fixed IV and padding of 2.4: key `00..0f`, plaintext lengths 0 to 45, plus three length-prefixed envelopes (2.6). |
| `cipher-type2.json` | synthetic | Type 2 with key `00..1f`: derived Ke / Ki for usages 0x03 0x04 0x05 0x10 0x11 0x12, 30 encryptions with fixed confounders (plaintext lengths 0, 6, 16, 21, 60), two envelopes. Includes the tamper and wrong-usage rejection checks done by the checker. |
| `challenge-proof.json` | synthetic | The 2.8 challenge proof for type 1 (the note's worked example, intermediate 36-byte string) and type 2. |
| `session-type{1,2}-{crc,secure}.json` | synthetic | A full session each: two mon connections (request masks 0x35 and 0x20) and one OSD connection with the authorizer round trip. For every connection the exact bytes each side sends on TCP (banner, HELLO, AUTH_REQUEST, AUTH_REPLY_MORE, AUTH_REQUEST_MORE, AUTH_DONE, both AUTH_SIGNATURE frames, one keepalive pair; encrypted after AUTH_DONE in the secure files), the keyring key (base64) for decoding, and the expected decoded values (challenges, proof, session keys, connection secret, both signatures). A core implementation should reproduce the client stream from the keyring key and the server stream, and verify the server stream. |
| `captured-scrubbed-frames.json` | real, scrubbed | Real frames from `k2-rbd-info-v1`, `k1-rbd-info-v1`, `k2-wrongkey`: banners, HELLO, AUTH_REQUEST, AUTH_REPLY_MORE, AUTH_REQUEST_MORE, and for the wrong-key session the real AUTH_BAD_METHOD frame. AUTH_DONE is given as lengths only. |
| `captured-structure.json` | real, lengths only | Per key type, request mask and mode: `msg_a` length, ticket blob length, validity, `cbl` / `extra` lengths, connection secret length, authorizer proof ciphertext lengths, as seen in the 39 captures. Use it to size buffers. |

## Provenance and scrubbing

- **Synthetic files.** Every key, nonce, challenge, confounder and connection secret is derived from public
  labels (SHA-256 of `winrbd-vector|<label>|<counter>`) or is a trivial pattern (`00 01 02 ...`). Opaque service
  ticket blobs are random filler of realistic length. They are valid inputs for the decoders in the notes but are
  not tickets of any cluster. The checker verifies them through the same code path that decodes the real captures;
  the builders were written second and are checked by the decoders, and the decoders were validated first on the real
  traffic, so a bug common to both would have shown as a capture failure.
- **`captured-scrubbed-frames.json`.** Fields that are random or key-derived are replaced by marked placeholders
  and every CRC is recomputed, so the frames still parse: server challenge `0x1122334455667788`, client challenge
  `0x99aabbccddeeff00`, proof `0x0123456789abcdef`, peer addresses `10.77.0.10:3300` (server) and `10.77.0.99:40000`
  (client), HELLO nonces 0. Left as captured: banners, tags, lengths, versions, the method / mode lists, the
  entity name `client.winrbd` and the BAD_METHOD frame (no secrets in them).
- **`captured-structure.json`.** Lengths, versions and counts only.
- **Never committed**: keyrings, session keys, tickets, connection secrets, real proofs or challenges, ciphertext
  blobs, raw pcaps, decrypted payloads. A scan of this directory and of the checker for every key and session key of
  the capture set (hex, base64, raw) found no match.
- The RFC 8009 file is public standard data (IETF Trust text; the vectors are facts about the algorithm).
