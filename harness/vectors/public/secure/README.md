<!-- SPDX-License-Identifier: MIT -->
# Secure-mode captures of the core's own sessions (`secure/`, module vectors-sec)

What the winrbd core itself put on the wire in msgr2 **secure** mode (AES-128-GCM framing, `docs/spec/msgr2-secure-mode.md`) when it talked to a real
Ceph v20.2.5 monitor and real OSDs, and what those daemons answered when they were set to allow only one mode and the core offered the other.
The older captures of this set (`../pcap/`) are of the stock client; here the client is the core, through the `wr-rbd` tool (`harness/host/tools/wr-rbd.c`,
`--mode secure`: the offer to the monitor and to the OSDs is `[secure]` and nothing else).

Everything is small (about 142 KB in 10 files, listed with sizes and SHA-256 in [`INDEX.json`](INDEX.json)) and **public on purpose**: the two cephx users of the
capture were throwaway users that were deleted from the cluster right after it, so their keys (`keys/`) authenticate nothing any more and let anyone
recompute every connection secret from the handshake bytes. No key, ticket or secret of any other user is in this tree (the lab's regular users and the
admin key were never used from inside the capture; the checker scans for key-looking text).

## 1 Provenance

| Item | Value |
|---|---|
| Ceph release | v20.2.5 "Tentacle", the lab cluster of `../MANIFEST.md` section 1 (one VM, 1 mon, 3 OSDs, replicated pool `winrbd`, size 3, 32 PGs) |
| Client | the winrbd core on the Linux host: `wr-rbd --mode secure --require-mode secure shell`, in its own network namespace under `tcpdump` (address 192.0.2.202, the lab's own addresses are 10.77.0.x) |
| Users | `client.vec-sec-k2` (cephx key type 2, `aes256k`, the cluster default) and `client.vec-sec-k1` (key type 1, `aes`, the legacy 16-byte key); caps `mon 'profile rbd'`, `osd 'profile rbd pool=winrbd'`; created and deleted by `scripts/capture_secure.sh` (`ceph auth get` fails afterwards, `INDEX.json` `verified_gone`) |
| Sessions | 2026-11-20, 09:53Z to 09:54Z, OSD map epoch 6785 before and after each session (the script refuses a session during which the epoch changes); `tcpdump` reported 0 packets dropped |
| Refusals | 2026-11-20, 09:54Z to 09:57Z: the monitor and `osd.1` (the primary of the image's id object) were set to one mode for a few minutes and restarted (the service-mode options are read at daemon start, `sec.md 2.9`), then put back and restarted again |
| Restore | `revert-proof.txt`: the state taken before and after (OSD tree, pools, upmap lines, flags, health checks and mutes, images, objects, auth entities, every set configuration option, the mode options in effect, the state of the ceph units) is identical; no `ms_*` option is set |

## 2 Files

| File | Contents |
|---|---|
| `INDEX.json` | the file list with size and SHA-256 of every file, the users and their deletion record |
| `keys/client.vec-sec-k2.keyring`, `keys/client.vec-sec-k1.keyring` | the two throwaway keyrings (deleted users, see above); `keys/.gitignore` lets git take them although the repository ignores `*.keyring` elsewhere |
| `sessions/k2.json`, `sessions/k1.json` | one session per key type, every connection of it (see 3) |
| `refusals.json` | eight refused attempts (see 5) |
| `revert-proof.txt` | the lab state before and after the capture |
| `live-tamper.txt` | a frame damaged on the wire (module secure-live, `harness/lab/secure-tamper.sh`, 2026-11-21): one bit of an OSD reply, of the core's write, of the monitor's stream and of the monitor's handshake flipped by a relay, in secure mode, and of an OSD reply in crc mode; the relay's log and the core's events and counters per case (the frame is refused with `WR_E_M2_SEC_TAG` / `WR_E_M2_FRAME_CRC`, the connection redialled, the data right). Text only, checked by nothing but the file list and the key / address scan |

## 3 What a session file holds

The session is the script `write 0 1M`, `verify 0 1M` (a read of the same 1 MiB, compared with the pattern), `write 2000000 100`, `discard 262144 262144`,
`discard 0 4M` on an image of 4 MiB with one 4 MiB object (layering only, writer profile), with `--depth 1`. The tool opens the monitor session and the image
(header reads on the OSD that holds `rbd_id.<name>`) and then does its I/O on the OSD of the data object, so each session has **one monitor connection and two or
three OSD connections** (the number depends on which OSDs the objects map to; all of them are kept, in the order of their first byte). Per connection:

- `hs_c2s`, `hs_s2c`: the plaintext handshake bytes of each direction, from the banner to the end of the last frame before the first secure frame: what the client
  sent (banner, HELLO, AUTH_REQUEST, AUTH_REQUEST_MORE) and what it received (banner, HELLO, AUTH_REPLY_MORE, AUTH_DONE). They are the two transcripts of the
  pre-auth signature (`sec.md 2.7`);
- `secret` (64 bytes) and `session_key` (the key of the AUTH ticket for the monitor, of the service ticket for an OSD): recovered by the independent checker
  from those handshake bytes with the published key, and equal to what the file records;
- `frames.c2s`, `frames.s2c`: every secure frame of the direction, in wire order: `tag`, `aligns`, `segs` (the PLAINTEXT of every segment), `wire_len`,
  `wire_sha256` and `wire` (the wire bytes as hex). The two 1 MiB data frames of the OSD connection that carried the I/O (the write going out, the read
  reply coming back) would be 2 MiB of incompressible ciphertext: they carry no `wire`, only its size and SHA-256, and their data segment is given as the
  pattern `wr-rbd` wrote (`{"pattern": "rand", "arg": 21, "off": 0, "len": 1048576}`, a function of the byte offset, documented in the tool's header). The bytes of
  such a frame are re-derived by encrypting the pattern with the recorded secret and nonces and must hash to what the wire had (a deterministic cipher: a wrong
  byte anywhere changes the hash).

Per session: the monitor connection has 4 client and 5 server frames (the server's biggest, 3,136 wire bytes), the OSD connections 3 to 8 frames per direction;
the first secure frame of every connection is AUTH_SIGNATURE, then CLIENT_IDENT / SERVER_IDENT, then MESSAGE frames of two GCM operations (header 41 bytes plus
front, middle and data, so a part 1 and a part 3) and CLIENT_IDENT / SERVER_IDENT of two (a long segment 0, part 1 and part 2). Frames of three operations do not
occur in real traffic: segment 0 is longer than 48 bytes only in the single-segment ident frames, and a MESSAGE's segment 0 is its 41-byte header. The three-operation
shape is covered by the synthetic vectors (`../../secure/secure-frames-synthetic.json`).

## 4 What the checks prove

`scripts/check_secure_core.py check` (ctest `vectors_secure_check`; python3 and the `cryptography` package; nothing of the core) re-derives everything from the files:

1. the file list against `INDEX.json`, no stray file, no symbolic link, a size budget; no key-looking text outside `keys/`, no key of a regular lab user, no address
   outside the lab nets (10.77.0.x and 192.0.2.x), no home directory path;
2. the cephx exchange of every connection, replayed from the handshake bytes with the published key (challenge proof, ticket reply, connection-secret blob; for an OSD
   the authorizer, its challenge and the sealed reply of version 2 that carries the secret; the OSD connections use the ticket the monitor handed out in the same
   session): the secret and the session key equal the recorded ones; the secret is 64 bytes and differs in every connection of the set; the server picked secure;
3. **sec.md 6.5**: the client banner is `supported 0x1, required 0x0` (REVISION_1 without COMPRESSION: the core never advertises compression), the server's is
   `supported 0x3`, no COMPRESSION_REQUEST / COMPRESSION_DONE crossed in either direction, and the server went on to SERVER_IDENT and served I/O: **a real v20.2.5 server
   accepts a client that advertises REVISION_1 only, with no compression frame at all**, in secure mode, for both key types, with the monitor and with OSDs;
4. the AUTH_SIGNATURE of both directions is HMAC-SHA256 of the bytes each side received under the session key (and does not match a transcript without the banner);
5. every frame, both directions: encrypted again with the recorded secret by the checker's own sender (key `S[0..15]`, nonce seeds `S[28..39]` for the client and
   `S[16..27]` for the server, one nonce per GCM operation in wire order, rev-1 counter in bytes 4..11) it gives exactly the recorded wire bytes or the recorded size and
   SHA-256; the recorded wire bytes decrypted with a library give the recorded plaintext; preamble CRC, alignments (8, 8, 8, 4096), zero padding, `late_status` 0x0e,
   the wire size and operation count of the table in `sec.md 5.1`;
6. the order after authentication and the coverage the module promises (both key types, a monitor and OSD connections, a 1 MiB write and a 1 MiB read reply, frames of one
   and two GCM operations, a long segment 0 and a multi-segment frame).

`scripts/check_secure_core.py selftest` (ctest `vectors_secure_selftest`) feeds the check 31 damaged copies (a stray file, a symbolic link, a flipped bit in a wire frame,
in a plaintext segment, in a secret, in a session key, in a handshake, a wrong hash, a changed pattern, swapped / dropped / repeated frames, a compression frame, a changed
alignment, a changed refusal, a key-looking text, a foreign address, ...); each must be refused. Every mutation is re-indexed first, so the refusal comes from the content
and not from the file list.

The C replay is ctest `m2.sec.replay` (`harness/test/test_m2_sec_replay.c`): the recorded server streams through the **real secure receive parser** with the recorded
secret (whole, random pieces, one byte at a time, ring only, small work budgets, exact / roomy / discarded sinks, with the portable and, when present, the accelerated GCM),
every frame decoding to the recorded plaintext; the **secure transmit** of the core fed the recorded plaintext frames reproducing the recorded client streams byte for byte (by
hash for the two 1 MiB frames), whatever the host's way of taking them; the independent encoder of the simulators reproducing the server's wire bytes (the simulator is the real
server); the recorded client streams through the parser of a server (the crossed seeds: the core's receive side reads what the real client sent); the core's pre-auth transcript code
reproducing both signatures; damaged, replayed and truncated streams, among them **every kind of byte of every recorded server frame damaged one bit at a time** (the first, the middle
and the last ciphertext byte, the first and the last byte of the tag of each GCM operation of the frame, the epilogue block; the operation boundaries are worked out in the test
from the segment lengths, not by the core): each is refused with the tag status at that frame, the frames before it were delivered and the damaged one never is, no event of it
was shown before the operation that carries the damage verified, and the same streams cut at those points show nothing and no error (a truncated tag is a tag that does
not verify, a short stream is a wait); the slot of the secure state is all zero after every wipe; and the refusals injected into a connection.

## 5 The mode refusals (`refusals.json`, `sec.md 6.4`)

A monitor, and one OSD, that allow only `secure` and only `crc` in turn (`ms_mon_service_mode`, `ms_service_mode`, startup-only options), against a core client that offered
only the other mode (`--mode crc` or `--mode secure`, for the monitor and for the OSD), for both key types: eight attempts, each the first refused connection of its capture
(the tool retries, `attempts_in_capture` says how many connections the capture held), as the bytes of both directions up to the refusal:

| daemon | server allows | client offered | server's answer |
|---|---|---|---|
| monitor | secure only | crc | AUTH_BAD_METHOD, **result -95 (-EOPNOTSUPP)**, allowed methods {cephx}, allowed modes {secure} |
| monitor | crc only | secure | AUTH_BAD_METHOD, result -95, allowed methods {cephx}, allowed modes {crc} |
| OSD | secure only | crc | AUTH_BAD_METHOD, result -95, allowed methods {cephx}, allowed modes {secure} |
| OSD | crc only | secure | AUTH_BAD_METHOD, result -95, allowed methods {cephx}, allowed modes {crc} |

So the `result` of a mode mismatch is **-95 (`EOPNOTSUPP` on Linux)**, the same for a monitor and an OSD, for both key types and both directions; it differs from the -13 (`EACCES`)
that the same frame carries for a wrong key or a missing OSD cap (`../MANIFEST.md` sections 3 and 4). The allowed-modes list holds only the mode the server allows. Nothing follows on that connection: the client sent nothing after its AUTH_REQUEST
and the refusal is the last server frame. The core reports it as `WR_E_M2_BAD_METHOD` with `peer_result` -95, allowed methods {2} and the allowed
modes in the errinfo (replayed by `m2.sec.replay`).

## 6 Things the captures showed that are worth knowing

- In this lab the service tickets of the monitor reply are of the legacy `aes` type (16-byte session key) even for the `aes256k` user: the cluster still rotates its service
  keys with the insecure type (its health warning says so, and it is muted). The OSD connections of `k2` therefore have a 16-byte `session_key`; the signature and the
  connection secret do not depend on it.
- Both directions always carry AUTH_SIGNATURE as the first secure frame, with no COMPRESSION frame between it and the ident frame, whatever the key type.

## 7 Regenerating

Inside the lab VM (passwordless sudo, the stock `ceph`, `rbd`, `tcpdump`, `systemctl`, and a built `wr-rbd`):
`WR=<path of wr-rbd> scripts/capture_secure.sh run [OUTDIR]` makes the sessions and the refusals, restores the cluster, writes `revert-proof.txt`, runs
`scripts/check_secure_core.py extract` and then `check`. `NO_REFUSALS=1` skips the part that restarts daemons (the extracted set then has no refusals and does not pass the check). `scripts/capture_secure.sh cleanup` puts back what an interrupted run
left (options, daemons, users, images, the namespace). After a hand edit of this README: `python3 -I scripts/check_secure_core.py reindex`. All scripts are our own code (MIT).
