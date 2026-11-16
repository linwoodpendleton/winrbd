# OSD operation test vectors (MOSDOp, MOSDOpReply)

Scrubbed message dumps for `docs/spec/osd-ops.md`, plus the checker that produced and verifies them.
License: MIT (see `COPYING.MIT`).

## What is here

One JSON file per exchange, numbered in the order the generator writes them (`NN-<name>.json`).
Each file has:

| Field | Meaning |
|---|---|
| `name`, `note` | short name and one line about what the vector shows |
| `source` | which capture session and transaction id it came from, or `synthetic` |
| `request` / `reply` | the two messages of the exchange (`reply` is absent for the synthetic example) |
| `<msg>.type`, `version`, `compat_version`, `priority`, `tid`, `seq` | the msgr2 message header fields (41-byte `ceph_msg_header2`) |
| `<msg>.header2_hex` | the 41 header bytes exactly as they were on the wire |
| `<msg>.segment_lengths` | frame segment lengths: header (41), front, middle (always 0), data |
| `<msg>.front_hex` | the front segment (the encoded MOSDOp / MOSDOpReply body), exactly as on the wire |
| `<msg>.data` | the data segment: `length`, `sha256`, and either the full `hex` (up to 2048 bytes) or only `head_hex` (first 32 bytes) |
| `<msg>.summary` | the decoded fields the expectation is written against (pool, pg seed, hash, flags, ops, result, ...) |

The vector set covers: a `WRITEFULL`, `STAT`, whole-object `READ`, a read of a missing object (`-ENOENT`),
a `DELETE` as sent by `rados rm`, a 4 MiB `WRITE` chunk, a librbd `SETALLOCHINT` + `WRITE`, a 64 KiB
`SPARSE_READ` with its extent map, a compound read of five `CALL` ops, `lock get_info`, a `CALL` on a missing
object, a mutating `CALL` that fails inside the OSD (`rval` -2), `CREATE` + `CALL`, `OMAPGETVALSBYKEYS`, the second page
of an `OMAPGETVALS` listing, an `-EPERM` reply to a write with a read-only key, the same call layout with the legacy
key type, one message taken from a secure-mode connection, and the 217-byte worked example of section 5.1 of the note
rebuilt by the checker's own encoder.

## Provenance

All captured vectors come from one disposable Ceph v20.2.5 lab cluster (one monitor, three OSDs, one replicated pool
with 32 PGs, `require_osd_release` tentacle, OSDMap epoch 42 or later), driven by the stock `rados` / `rbd` command line
of the same release, in crc mode (and for one vector in secure mode, after decrypting the connection).
The packet captures themselves are not in the repository.

## Scrubbing

- A MOSDOp / MOSDOpReply body contains no key material, ticket, nonce, signature or connection secret: it holds pool id,
  placement hash, map epoch, object name, op records, snapshot context, the negotiated feature word and (for writes) a
  wall-clock time stamp. Nothing in it needed replacing, so the front segments and the 41-byte headers are unmodified
  wire bytes and their integrity fields are as captured.
- Frame preambles, CRCs, the epilogue, AUTH frames, tickets, authorizers, session keys and the secure-mode nonces and tags
  are **not** included in any vector. The secure-mode vector is the decrypted plaintext message; the keys needed to decrypt
  it are not stored anywhere in this repository.
- Data segments are the lab's own test patterns (byte `i` = `(i*7+3) mod 251`), not user data. Large data segments are
  reduced to length + SHA-256 + first 32 bytes.
- No IP address, host name, fsid, key or user name is present. Object names are lab object names (`t0-small`, `t0-big`,
  `rbd_header.<id>` of lab images, `rbd_data.<id>.<objno>`).
- `osdop_check.py` re-checks this on every run: a vector file may not contain anything that looks like an IPv4 address,
  a `key =` line or a long base64 string (hex fields are exempt because every message in the set is secret-free by
  construction).

## The checker

`harness/tools/osdop_check.py` is written from the notes only (`osd-ops.md`, `msgr2.md`, `msgr2-secure-mode.md`,
`cephx.md`, `rbd-format2.md`, `crush-and-placement.md` 3.1) and uses no Ceph code or decoder. It needs Python 3 and the
`cryptography` package (`pip install --user cryptography`).

```
# full run against the public vector set (about 10 s on 8 cores)
python3 harness/tools/osdop_check.py
#   or against another capture set:  --captures <captures dir>

# optional: --keys <dir with client.*.keyring>   (default: harness/vectors/public/keys for the public set,
#                                                  else <captures dir>/../lab-secrets)
#           --only k2-omap,k2-rados-small        (some sessions only)
#           --evidence                           (print what the captures show, used to settle the note)
#           -v                                   (one line per session)

# offline: only the vectors in this directory (no captures, no keys)
python3 harness/tools/osdop_check.py --vectors-only

# regenerate this directory from the captures
python3 harness/tools/osdop_check.py --captures <captures dir> --emit-vectors harness/vectors/osdop
```

Exit status 0 means every check passed. What it does with a capture:

1. Reassembles each TCP stream by sequence number (retransmissions, offloaded super-packets) and notes holes.
2. Parses msgr2.1 frames and verifies every preamble CRC, segment CRC, epilogue and length.
3. Opens the cephx exchange with the lab keyring (both key types), derives the session keys and the secure-mode connection
   secret, verifies both AUTH_SIGNATURE frames, and decrypts secure-mode connections (every GCM tag is verified).
4. Decodes every MOSDOp (version 9) and MOSDOpReply (version 8) with decoders written from the note and checks each field
   (header, segments, flags, request id, trace fields, locator, hash against its own rjenkins, pg seed against its own
   stable modulo, snapshot context, features against the negotiated word, per-op records, data segment cut).
5. Pairs replies with requests and checks result / rval / flags / version rules and the output layout of STAT, READ,
   SPARSE_READ, OMAPGETVALS, OMAPGETKEYS, OMAPGETVALSBYKEYS and CALL.
6. Compares against ground truth: bytes written and read against the lab's source files, read-back against writes,
   `cls_rbd` / `lock` outputs against the raw bytes the lab collected with librados, `rbd info` JSON, and the object-name
   hash and pg of 2194 `ceph osd map` lines.
7. Runs the offline vector self-test below.

The offline vector self-test decodes every file here, compares the decode with the stored `summary`, re-encodes each
captured request with the checker's own encoder and requires byte-identical output, checks the data digests, and runs the
scrub check.

### Known capture defects

Two of the 39 pcaps (`k1-sec-rados-big`, `k1-rbd-bench-default`) lost packets on the capture path: the receiver
acknowledged bytes that are not in the file. The checker reports these as warnings and does not count them as failures;
frames before the hole are checked, frames after it are not, and the byte-level data checks of those two sessions are
skipped. (The same traffic is covered by the other key type's session.)
