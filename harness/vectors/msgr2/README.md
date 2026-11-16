<!-- SPDX-License-Identifier: MIT -->
# msgr2 test vectors and the checker that produced them

These files back `docs/spec/msgr2.md` (framing, handshake, message envelope) and the msgr2-facing parts of
`docs/spec/cephx.md` (AUTH_SIGNATURE, connection secret). They are small, hex plus JSON expectations, and every
one of them is verified by the independent checker `harness/tools/msgr2_check.py`.

## Files

| File | Content | Provenance |
|---|---|---|
| `frames-crc.json` | 28 complete msgr2.1 crc-mode frames (hex), with decoded field expectations: HELLO, AUTH_REQUEST / REPLY_MORE / REQUEST_MORE / DONE / SIGNATURE, COMPRESSION_REQUEST / DONE, CLIENT_IDENT, SERVER_IDENT (also the lossless-intent variant), MESSAGE with 1, 2 and 4 segments, KEEPALIVE2 / ACK, AUTH_BAD_METHOD, IDENT_MISSING_FEATURES | captures of stock Ceph v20.2.5 clients against the lab cluster, scrubbed (see below); one frame re-encoded from a live probe answer |
| `crc32c.json` | raw CRC-32C vectors (seeds 0 and 0xFFFFFFFF) and table spot values | computed by the checker, equal to the values in the note and to every CRC of the 11,946 captured frames |
| `preauth-hmac.json` | AUTH_SIGNATURE vector: transcripts, synthetic key, both signatures, and variants that must not verify | **synthetic**: key bytes `00..1f` (a public test value, not a key of any cluster), frames built by the checker |
| `secure-frames.json` | four consecutive secure-mode (AES-128-GCM) frames of the client-to-server direction | **synthetic**: connection secret bytes `00..3f`; the layout is the one the checker decrypts in real captured secure sessions |
| `handshake-skeletons.json` | ordered frame lists (tag, segment lengths, wire size) of a monitor connection in crc mode, an OSD connection in crc mode and a monitor connection in secure mode | structure only, taken from captures |

## Scrubbing (rule 4 of CONTRIBUTING.md)

Raw captures, keyrings, session keys, tickets and decrypted authentication payloads are **not** in this directory.
For every captured frame the checker rewrites the parts that could carry secrets and then rebuilds the frame, so all CRCs
in the stored hex are valid for the stored (scrubbed) bytes. Each entry of `frames-crc.json` has a `scrubbing` field that says what was replaced:

| Where | Replaced by |
|---|---|
| address of the capture client in HELLO / CLIENT_IDENT / SERVER_IDENT | `10.77.0.20` (the monitor and OSD addresses are the lab defaults `10.77.0.10`) |
| cephx proof in AUTH_REQUEST_MORE (a function of the secret key) | `0x1111111111111111` |
| AUTH_DONE payload (encrypted tickets, session keys, connection secret) | `0xDD` fill of the same length |
| OSD authorizer (ticket secret id, ticket blob, encrypted proof) and the encrypted challenge | `0xAA` / `0xBB` / `0xCC` fill of the same length |
| AUTH_SIGNATURE (HMAC under the session key) | 32 x `0x5A` |
| data segment of the OSD write message | counting pattern of the same length |

Left as captured: banner values, the server challenge in the monitor AUTH_REPLY_MORE (a plain random number, not key material),
the client nonce and global sequence numbers, entity and global ids, feature masks, lengths, timestamps of keepalives.
After writing, `--emit-vectors` runs a leak guard that compares every key secret known to the capture set (keyring keys and all session keys printed in the
client logs, in hex and base64) with the output files and deletes them if one is found.

Because the authentication payloads are replaced, frames of the AUTH_DONE / AUTH_SIGNATURE kind only exercise the framing and field layout; the
cryptography is covered by the synthetic vectors and by the checker's runs on the real captures.

## Running the checker

```
python3 harness/tools/msgr2_check.py [--captures <capture dir>] [--keys <keyring dir>] [-v] [--only SESSION,...]
```

* `<capture dir>` is a capture set (`pcap/<session>.pcap`, optionally `secrets/session-secrets/<session>.txt`); default: the public set `harness/vectors/public`. A private capture set is never committed.
* `--keys` is the directory with the keyrings (default: `harness/vectors/public/keys` for the public set, else `lab-secrets` next to the capture dir). Keys are read at run time and never printed.
* Needs Python 3 and the `cryptography` package; nothing else. It does not use any Ceph decoder or library.
* Exit status 0 only if every check passed. `-v` also prints the observed values (counters of what the captures actually contained).
* The vector files can be re-verified without any capture: `python3 harness/tools/msgr2_check.py --check-vectors harness/vectors/msgr2`. A normal run with `--captures` also verifies them when this directory exists.
* `--emit-vectors <dir>` regenerates the files in this directory from the captures.

What it checks (see the table printed at the end of a run; the ids are used in the note): the TCP reassembly, banners, every frame's preamble CRC, segment CRCs, epilogue slots and sizes; the tag table and
payload layouts of all control frames (decoded and re-encoded byte for byte); the address encoding; the cephx exchange (challenge proof, decryption of AUTH_DONE and of the OSD authorizer round trip with the
lab keys, both key types, with the session keys cross-checked against the client logs); both AUTH_SIGNATURE values and which bytes they cover; secure mode (AES-128-GCM layout, nonce stepping, padding)
for every secure connection; identification frames, sequence numbers and acks of MESSAGE frames; keepalive behaviour; negative cases (wrong key, no OSD caps).
Capture defects are reported as warnings, not failures (this capture set lost packets in four streams; those are analysed up to the hole, and a loss at the very end of a stream is detected from the peer's TCP acknowledgements).

## Live probe

`harness/tools/msgr2_probe.py` is a small msgr2 / cephx client (it re-uses the encoders of the checker) that was run against the lab monitor to settle questions a capture of the stock client cannot answer.
Results, all against a v20.2.5 monitor (crc mode, cephx):

| Experiment | Result |
|---|---|
| banner supported = 0x1, no COMPRESSION_REQUEST, then CLIENT_IDENT | SERVER_IDENT; the server skips the compression stage |
| banner supported = 0x3 but CLIENT_IDENT sent without COMPRESSION_REQUEST | the server closes the connection |
| banner 0x3, COMPRESSION_REQUEST `{false, []}` | COMPRESSION_DONE `{false, 0}` (what the stock client does) |
| KEEPALIVE2 with segment alignment 4, 16, 4096 | answered normally (alignment is advisory) |
| MESSAGE with `data_off` 17 and/or `data_pre_padding_len` 5 (no data segment) | processed normally |
| MESSAGE header flags 0, 1 and 3 | all processed normally |
| the same `seq` sent twice | the second message is ignored and the connection then stops being read (no reply to the next, higher `seq`, connection stays open) |
| KEEPALIVE2 or MESSAGE before CLIENT_IDENT | the server closes the connection |
| CLIENT_IDENT with flags 0 and a non-zero cookie | SERVER_IDENT with flags 1, cookie 0 (the monitor answers lossy) |
| CLIENT_IDENT whose supported mask lacks bit 59 (MSG_ADDR2) | IDENT_MISSING_FEATURES, mask 0x0800000000000000 |
| supported mask lacking one of bits 18, 25, 30, 41, 48, 58 | IDENT_MISSING_FEATURES naming exactly that bit; bit 12 (OSDREPLYMUX) is not required by the monitor |
| AUTH_REQUEST offering only connection mode 7, or method 99 | AUTH_BAD_METHOD, result -95, allowed methods `[2]`, allowed modes `[2, 1]` |

A segment alignment that is not a power of two was deliberately **not** tried: a failing allocation inside the only monitor of the lab could stop it.
