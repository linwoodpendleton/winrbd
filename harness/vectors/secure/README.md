<!-- SPDX-License-Identifier: MIT -->
# Test vectors for `docs/spec/msgr2-secure-mode.md`

Small, scrubbed files the core can load for unit tests of msgr2 secure mode (AES-128-GCM framing, key and nonce
slicing, the pre-auth signature) and for the pieces of cephx that hand over the connection secret.

**Nothing in this directory is key material of the lab or of anyone else.** Every key, secret, nonce seed and
transcript below is synthetic (bytes `00 01 02 ...`, or a fixed pattern), except the published test keys of `gcm-nist.json`. What came from real captures is reduced to
structure: tags, lengths, counts, flags, negotiated numbers.

## Files

| File | Contents | Origin |
| --- | --- | --- |
| `primitives.json` | CRC-32C vectors (raw update, seed given), nonce stepping (including the 2^64 wrap), the frame size table (segment lengths -> GCM operations -> wire bytes) | synthetic / public values; the CRC and size rows are re-checked against real traffic on every run |
| `secure-frames-synthetic.json` | secret `S` = `00..3f`, derived key and the two nonce seeds, then a sequence of whole frames in each direction (AUTH_SIGNATURE, MESSAGE shapes with 1 and 2 GCM operations, 4 segments, a 4096-byte data segment, KEEPALIVE2) as `wire_hex`, with the IV of each frame's first operation | produced by `secure_check.py`'s own sender; the same sender reproduces every captured secure frame byte for byte |
| `pre-auth-tail-synthetic.json` | a mini handshake (banners, AUTH_REQUEST, AUTH_DONE as crc frames), the two transcripts, both HMAC-SHA256 signatures, and the two encrypted AUTH_SIGNATURE frames with the next IV of each direction | synthetic (session key `a0..af`, secret `00..3f`); the AUTH_DONE payload is an opaque placeholder, not a valid cephx reply |
| `pre-auth-signature-synthetic.json` | HMAC-SHA256 over a short synthetic transcript, for a type-1 (16-byte) and a type-2 (32-byte) session key | synthetic |
| `connection-secret-blob-synthetic.json` | the `cbl` blob of a monitor's AUTH_DONE (`u32 outer | u32 inner | ciphertext`) for key type 1 and 2, in secure mode (64-byte secret) and crc mode (empty string), fixed confounder | synthetic keys; cipher code is the one that decrypts every real reply in the captures |
| `captured-structure.json` | for each distinct (peer, mode, offered modes) combination seen in the captures: the plaintext handshake frames and the first frames after authentication with their segment lengths, alignments, late status, wire sizes and GCM operation counts; the banner values | real captures, reduced to structure (see below) |
| `gcm-nist.json` | public AES-GCM known-answer tests: the 18 test cases of the GCM specification (McGrew and Viega, "The Galois/Counter Mode of Operation (GCM)", appendix B: AES-128, AES-192 and AES-256, 96-bit, 64-bit and 480-bit IVs, with and without additional data, whole and partial blocks) as `gcm-spec-tc1` .. `gcm-spec-tc18`, and two empty-message cases of the NIST CAVP GCM vectors (`gcmEncryptExtIV128`, 96-bit IV); each case names its source and has `key_hex`, `iv_hex`, `aad_hex`, `pt_hex`, `ct_hex`, `tag_hex` (full 16-byte tag) | public test vectors (see below) |

All integers inside the byte strings are little-endian; `*_hex` values are lower-case hex.

## What was scrubbed

Raw pcaps, keyrings, session keys, tickets, challenges, challenge proofs, signatures, nonces / IVs of real
connections, connection secrets, decrypted payloads, addresses, ports and entity names stay in the private capture
directory and are **not** copied here. `captured-structure.json` contains none of them: only lengths, tags, small
integers (modes, key types, the `other_keys` mask, secret length) and counts. The synthetic files contain values that
are chosen, not derived from any real key. `secure_check.py --export-vectors` regenerates all of this deterministically;
a leak scan (every secret of the lab keyrings and every session key in the logs, as hex and as base64, plus addresses
and entity names) was run on the generated files and found nothing.

## Running the checker

```sh
pip install --user cryptography           # only third-party dependency
python3 harness/tools/secure_check.py                              # the public vector set (harness/vectors/public)
python3 harness/tools/secure_check.py --captures <captures dir>
```

`<captures dir>` is a capture set (default: the public set; it needs `pcap/*.pcap`; keys are read at run time from
`harness/vectors/public/keys` for the public set, else from `<captures dir>/../lab-secrets` and `<captures dir>/secrets/keys`; override the first with `--keys <dir>`). The keys are never printed. Exit status
0 means every check passed **and** every claim of the note is covered by the set; 1 means a failed check or an
uncovered claim, 2 means bad arguments or no pcaps. Useful options: `--only <substring>` (subset of pcaps; then
claims that need the whole set are only reported), `--export-vectors <dir>` (rewrite these files, then re-verify them),
`-v` (one line per pcap), `--json <file>`.

Without `--export-vectors` the checker also re-verifies the committed vector files in this directory with a code path
that does not use its own sender (plain AES-GCM decrypt and manual field parsing), so a vector cannot drift unnoticed.

Recorded run (2026-11-16, capture set of 39 pcaps, 148 MB, about 50 s): **151,305 checks, 151,305 passed, 0 failed**;
499 TCP connections, 80 of them secure; 880 secure frames in 1,390 GCM operations (all tags verified, up to a 4 MiB data
frame); 15 claim groups, all confirmed. Both cephx key types (aes, aes256k) and all of mon, mgr and OSD peers are covered.

Known capture defect: three connections in two pcaps (`k1-rbd-bench-default`, `k1-sec-rados-big`) have a hole in the
TCP stream (the capture lost packets); they are analysed up to the hole and the cut frame is reported as expected, not
as a failure. They do not affect any claim (their start-of-connection handshakes are complete).

## What the checks are, in short

The checker is written from the note (and `cephx.md` for the cipher details), not from Ceph source, and uses only the
Python standard library plus `cryptography`:

1. TCP reassembly of each connection by sequence number (retransmissions are de-duplicated and must carry identical bytes).
2. msgr2 banner, then every frame: crc framing (preamble CRC seed 0, segment CRCs seed `0xFFFFFFFF`, 13-byte epilogue)
   and secure framing (the three GCM parts, nonces, tags, inline buffer, padding, epilogue).
3. The auth exchange: field layouts, offered and chosen modes; cephx with the lab keyrings: challenge proof, ticket reply,
   connection-secret blob, authorizer round trip for mgr / OSD connections; the session keys are also cross-checked against
   the stock client's debug log by hash.
4. Key and nonce slicing and directions, verified by every GCM tag of every secure connection; negative controls (swapped
   seeds, flipped bits, wrong key, msgr2.0 stepping) must fail.
5. The pre-auth signature in both directions for every connection.
6. A re-assembly round trip: the checker's sender must reproduce each captured frame, crc and secure, byte for byte.
7. The compression handshake frames and the frame order after authentication.

## `gcm-nist.json`: public AES-GCM vectors

The inputs of the 18 specification cases are the published ones (the keys `00..00` and `feffe992 8665731c 6d6a8f94
67308308` (repeated or extended with `feffe992 8665731c` for the longer keys), the 64-byte plaintext starting
`d9313225`, the 20-byte additional data `feedface deadbeef feedface deadbeef abaddad2`, the IVs `cafebabe facedbad
decaf888` (96 bits), `cafebabe facedbad` (64 bits) and the 60-byte `9313225d ...`). The expected ciphertexts and
tags were not typed in from the PDF: each was computed by two unrelated implementations, OpenSSL (through the Python
`cryptography` package) and `harness/test/support/ref_gcm.c` (the textbook reference of the secure-mode tests, which
`test_ref_gcm` runs against every case in both directions), and the file was generated from the OpenSSL result.
The two agree on all 20 cases. As a check against the printed specification, the tags of all 18 specification cases were compared with the published values and match; that check is a sanity check on the
inputs, the cross-check between the two implementations is the basis. The specification has no case whose IV is a
whole number of blocks (16, 32, 128 bytes), where the IV hash needs no zero padding: `test_ref_gcm` carries four
such cases as literals (computed with OpenSSL, not part of this file), and `test_ref_gcm_ossl` compares the
reference with OpenSSL on thousands of random cases of every IV length from 1 to 128 bytes.
The two CAVP cases are the first two vectors of the 128-bit, 96-bit-IV, empty-message group of `gcmEncryptExtIV128.rsp`
(key, IV and tag as published).

Use: the core's GCM tests (`test_crypto_gcm`), the accelerated hook's tests and `test_ref_gcm` read it; a case with
an IV that is not 96 bits is for the reference only (the core's GCM refuses those with `WR_E_CRYPTO_LEN`).
