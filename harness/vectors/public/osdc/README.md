<!-- SPDX-License-Identifier: MIT -->
# osdc: OSD and RBD captures of the stock client (module vectors-c)

Public, secret-free captures of what a Ceph v20.2.5 OSD and the stock client library (librados, crc mode) put on the wire for the
things the object client of `core/` does: the open of an RBD image (the eight-call header read), the object operations of the data path,
writes that carry a snapshot context, PG backoffs, and the data objects of patterned images. They are the oracle for
`core/src/osd/wri_osd_msg.h` and `core/src/rbd/wri_rbd_cls.h`: the ctest tests `osd.vec.replay`, `osd.vec.sweep`, `osd.vec.backoff` and `rbd.vec.replay` (files `test_osd_vec_replay.c`,
`test_osd_vec_sweep.c`, `test_osd_vec_backoff.c` and `test_rbd_vec_replay.c`) push them through the real code, and `vectors_osdc_check` checks the files with an
independent decoder. Notes: `docs/spec/osd-ops.md`, `docs/spec/rbd-format2.md`.

Made on 2026-11-17 on the private lab cluster (Ceph v20.2.5 "Tentacle", one VM, 3 OSDs, replicated pool `winrbd`, plus one throw-away pool
for the data-pool image). **Everything here is a copy of OSD message bodies and of what the stock tools reported; no pcap, key, ticket,
session secret or authentication frame is in the tree.** The client was a throw-away cephx user that is deleted again (section 5).

## 1 Files

| Path | Content |
|---|---|
| `INDEX.json` | the session list, the user record (name, caps, creation, deletion and proof that it is gone) and the size and SHA-256 of every file |
| `sessions/<name>.json` | one capture session: the commands, the OSD map epoch before and after, and its exchanges (below) |
| `images.json` | the ten images of the header sessions: the ground truth of the stock tools (`rbd info`, `rbd snap ls`, `rbd lock ls`), what the header replies decode to (`header`) and the refusal verdicts the independent checker derived from the note for the reader and the writer profile (`expect`) |
| `objects.json`, `objects/<image>/<objno>.bin` | the data objects of three patterned images (4 KiB, 16 KiB and 64 KiB objects) exported with `rados get`, with the recipe of the pattern |
| `revert-proof.txt` | the lab state before and after the run (osd tree, pools, upmaps, flags, health checks, images, objects, users, every configuration option): identical |

Total 2.0 MB in 37 files. `scripts/capture_osdc.sh` makes it, `scripts/check_osdc.py` checks it.

## 2 Sessions

One session is one `tcpdump` on the host side of a veth pair, with the client in its own network namespace, so the frames are real Ethernet
frames and the client never shares a loopback with the daemons. `crc` mode on every connection (`ms_client_mode` and `ms_mon_client_mode`
set to `crc`), so the message bodies are plain on the wire. The pcaps are not published (they hold the authentication frames); the tool cut
the MESSAGE frames of types 42 (MOSDOp), 43 (MOSDOpReply) and 61 (MOSDBackoff) out of them after checking every frame's CRCs.

| Session | Exchanges | Backoff messages | What it is |
|---|---|---|---|
| `hdr-wrtest-osdc-<f01 f05 f21 f3d f45 dp clone str snap lock>` | 4 to 5 each | | the open of one image as `core/` will do it: `get_id` on `rbd_id.<name>`, the eight-call header read on `rbd_header.<id>` in its reader form and in its writer form (`get_features` with `read_only` 1 and 0), `get_stripe_unit_count` for the striped image, and `lock get_info` |
| `hdr-missing` | 2 | | `get_id` of an image that does not exist and the header read of an id that does not exist: `-ENOENT` for the whole message, every `rval` 0, no output |
| `io-plain` | 34 | | READ of a missing object, a short object (4096 of 16384 bytes), exactly, past the end, with length 0; WRITE; a write after a hole; SPARSE_READ with two and with three extents; STAT; ZERO in the middle; ZERO to the end (the OSD answers TRUNCATE); TRUNCATE down and up; a whole-object write; ZERO of a whole object; DELETE, DELETE again (`-ENOENT`), read after delete; ZERO, TRUNCATE and STAT of an absent object; `SETALLOCHINT` (FAILOK) plus WRITE as librbd sends it |
| `io-snap` | 13 | | on the image with snapshots: writes with its snapshot context (two snapshot ids, the sequence above both: the OSD makes a clone), a write to a new object, ZERO, TRUNCATE and DELETE with the context (a whiteout is left), reads of the oldest and the newest snapshot, a read of the whiteout (`-ENOENT`), a write with the empty context |
| `objects-pat12`, `objects-pat14`, `objects-pat16` | 6 to 7 | | `rados get` of every data object of a patterned image and of one that does not exist (whole-object READ of 4 MiB, shortened by the OSD) |
| `backoff-restart` | 16 | 87 | six threads of writes and reads over 64 objects in many PGs while `osd.2` is restarted; the OSDs were told to back off on peering and when degraded |
| `backoff-out` | 13 | 51 | the same load while `osd.1` is marked out, and in again |

An **exchange** is `{n, conn, label?, probe?, request, resends?, reply, t_ms}`. A **message** is `{type, version, compat_version, priority,
tid, seq, header2_hex, segment_lengths, front_hex, data, summary}`: `header2_hex` and `front_hex` are the bytes of the 41-byte msgr2
message header and of the front segment exactly as on the wire; `data` is `{length, sha256}` plus `hex` when the segment is at most 20,000
bytes, else `head_hex` (the first 32 bytes); `summary` is what the independent decoder read out of them (pool, PG seed, hash, epoch, flags,
object, namespace, mtime, the operation records with their offsets, lengths, flags and payload lengths, snapshot id, snapshot context,
`retry_attempt`, the feature word; for a reply result, flags, echoed operation records with their output lengths, `rval`s,
`user_version`; for a backoff the pool, PG seed, op, id and the two hobject positions). 64-bit values that can pass 2^53 (snapshot ids,
features, `user_version`) are `"0x..."` strings. `resends` are the later transmissions of the same request after a backoff or a map change
(same tid, `retry_attempt` + 1, the RETRY flag; each carries the `conn` it went out on). `probe` is what the client library reported to the
driver at capture time (return code, class-call outputs, read data hash, extents, size): the checker compares it with the wire.

## 3 What the set shows (beyond what the notes already say)

- A real OSD sends **MOSDBackoff BLOCK in both forms**: for the whole PG (`begin` and `end` are the PG's first position and the first position of the
  next PG, ordered by the bit-reversed hash, so the raw `end.hash` can be below `begin.hash`) and for **one object** (`begin == end`, snapshot id
  NOSNAP, the name of the object) while its PG is degraded. The end of the last PG of a pool is the **maximum position** (max flag 1, pool
  `INT64_MIN`, hash 0, empty names). Every BLOCK is answered by an ACK_BLOCK that repeats the pgid, the id, the epoch and both positions, and
  later released by an UNBLOCK. The request that was held is **sent again with the same tid, `retry_attempt` + 1 and the RETRY flag**, on the
  same connection or after a reconnect on another, and the reply echoes the new attempt.
- The read of a **short object** returns fewer bytes than asked with result 0 (4096 of 16384), a read at or past the end returns 0 bytes with
  result 0, a read of an object that does not exist fails as a whole with `-ENOENT`: those are the zero-fill and `-ENOENT` rules of the image
  layer. `ZERO` that reaches the end of the object, and `ZERO` of the whole object, come back as `TRUNCATE`; a `DELETE` of an absent object in
  a mutating message is `-ENOENT` in its `rval` and in the result; ZERO and TRUNCATE of an absent object succeed.
- **SPARSE_READ** reports exact byte ranges: a zeroed middle of a block is a hole of its own (`[0,100) [300,4096) [10000,10100)`), not a page.
- A **released lock** keeps its type and tag: the default-feature image written once by `rbd bench` reads as lock type 1, tag `internal`, no locker;
  a lock added by `rbd lock add` reads as one locker with an empty tag.
- A **clone** made with `rbd clone` has the feature word 0x1 and no operation features: only `parent_get` and `parent_overlap_get` show it.
  An image with a data pool has the feature bit 0x80 and `get_data_pool` answers the id of the data pool; its object prefix carries the id of
  the metadata pool (`rbd_data.<pool>.<id>`).
- The write of the snapshot-context session and its replies match the encoder of `core/` byte for byte, including `SETALLOCHINT` with FAILOK
  and an `mtime`.
- The answer to a **resent write** may come back with ONDISK and **no ACK** (flags `0x0840002c`: 11 of the 19 resent writes of the two backoff
  sessions; the other 8 have `0x0840002d`, like every first answer, `0x08400025`): the OSD found the transaction id in its PG log and returned
  the stored result. Every reply that was a failure of the whole message before anything ran (`-ENOENT` of a read-only message) has no ACK either.
  A client must wait for the reply, never for the ACK bit; the decoder of `core/` does not look at the flags.

## 4 Checking and replaying

```sh
python3 -I harness/vectors/public/scripts/check_osdc.py check       # ctest vectors_osdc_check
python3 -I harness/vectors/public/scripts/check_osdc.py selftest    # ctest vectors_osdc_selftest: 23 damaged copies, all rejected, each for the right reason where it matters
ctest --test-dir build/harness -R 'osd.vec|rbd.vec|vectors_osdc'      # also the C replays, the backoff table replay and the damage sweeps
```

`check_osdc.py` is written from the notes only (python 3 standard library, no Ceph code, no `core/` code). It checks: every file's size and
SHA-256 against `INDEX.json`, no stray file or symbolic link, a 3 MB budget, no key-, ticket- or password-looking text, no address outside
`10.77.0.x` and `192.0.2.x`; every message decoded again from its recorded bytes (msgr2 header, MOSDOp v9, MOSDOpReply v8, MOSDBackoff, the
class-call outputs) and equal to its summary; requests and replies paired by transaction id with the invariants of the note (flags, priority,
`client_inc`, `mtime` set exactly for writes, `RETRY` exactly with `retry_attempt`, one echoed record per sent operation, the data segments add
up); every call output equal to what the client library reported; the header reads of each image against `rbd info`, the snapshot list and the
refusal table of `rbd-format2.md` 3.3 / 4.2; every exported object against the recipe of its pattern (byte by byte, and its size); the
backoffs (an ack equals its block, an unblock names a block, every held request lies inside the BLOCK of its PG, a one-object BLOCK covers no
other object); and the coverage the module promises (every operation kind, a short and a missing object, a write with a snapshot context, a
read of a snapshot, BLOCK / ACK_BLOCK / UNBLOCK in both forms, resends, every feature word of the refusal table 0x1, 0x3, 0x5, 0x21, 0x3d, 0x45,
0x81, a clone, a striped image, snapshots, a foreign lock, four object sizes from 4 KiB to 64 KiB).

`check_osdc.py` also refuses a published file that names a directory of the lab or of a developer machine (`/home/...`, `/Users/...`; the extractor
replaces the work directory of a recorded command by `<work>`), an exchange the OSD never answered, a transaction id used by two exchanges of one
client, a reply that lacks ONDISK (or ACK, except for the answer to a resent write), a READ that returned more than it asked for, a STAT output of
other than 16 bytes, output from a failed message or from a mutation, and an object count of `rbd info` that is not ceil(size / object size).
`test_osd_vec_replay.c` (ctest `osd.vec.replay`): every request of every session, and every resend, is rebuilt from its summary and encoded
with `wri_mosdop_encode`: the front must equal the capture byte for byte; every reply goes through `wri_mosdopreply_decode` (fields, operation
outputs adding up to the data segment, a cut at every 7th offset is refused), STAT and SPARSE_READ outputs through their decoders against what
the library reported, every backoff through `wri_mbackoff_decode`, every ACK_BLOCK against `wri_mbackoff_encode_ack` byte for byte, and every
held request against `wri_mbackoff_covers` (and a neighbouring object against a one-object block). `test_rbd_vec_replay.c` (`rbd.vec.replay`):
the class-call encoders reproduce every header message (operation records, data segment and the whole front), the decoders read every output
and the result equals `rbd info`, `wri_rbd_check_profile` gives the checker's verdict (status and numbers) for the reader and the writer of
every image, the exported objects equal the pattern through `wri_rbd_geom_extent`, and `wri_rbd_op_status` maps the captured results. The reply is checked against the request it answers (object, PG, attempt, echoed operation codes, what an operation may bring back), the
edges of every captured BLOCK (begin inside, end outside, a one-object block only that object), and the transaction ids of a session (rising,
unique). `test_osd_vec_sweep.c` (`osd.vec.sweep`) uses the same bytes as the seed of damage: every reply and backoff front is copied into an
allocation of exactly its size and has every byte set to seven other values, every four-byte window set to hostile lengths, every cut and
two lengthenings tried; a failed decode must leave a cleared output, a successful one must still hold together (at most 8 operations, strings
inside the input, an ACK_BLOCK that encodes into exactly `wri_mbackoff_ack_len` bytes and decodes to the same block); the SPARSE_READ and STAT
outputs get the same treatment together with synthetic tables (0, 1, 3, 64, 65 extents, a table at the top of the 64-bit range) and one byte
off either end of the request window; `wri_hobj_cmp` and `wri_mbackoff_covers` are compared with a model of the order of the note over some
900 positions; hand-made replies with 0 to 70 operations, hostile counts, 4 GiB-1 outputs, a redirect and a 2049-byte name; every captured
request is encoded into every shorter buffer (WR_E_TOOBIG, nothing past the buffer) and each refusal rule of `wri_mosdop_encode` is applied
to it (empty or over-long name, nine operations, a write at a snapshot, a write with the snapshot context taken apart, a WRITE whose length
differs from its data, a foreign operation code), each of which must give its status and write nothing. `test_osd_vec_backoff.c` (`osd.vec.backoff`) plays the two backoff captures, one connection at a time, into the backoff table of an OSD session
(`wri_osd_sess.h`, through the rig of the osd-sess tests): the ACK_BLOCK the table sends for each BLOCK equals the stock client's byte for byte, after
every message each request position of the capture is held exactly when a live BLOCK of its PG covers it (the model of the note), the requests the
stock client had to send again were each held at some moment, every UNBLOCK tells the request layer to resend its PG, the table is empty at the end
and a connection lost with a BLOCK standing clears it; then the same traffic against tables of 4, 2 and 1 slot (never a hold without a live BLOCK of
the PG, no UNBLOCK lost). `rbd.vec.replay` also damages every
class-call output (one byte more, one less, every cut, every byte, every 32-bit window: no read outside the allocation, a failed decoder leaves
its outputs clear), walks every image from byte 0 to its end through `wri_rbd_geom_extent` and compares the object count with `rbd info`,
applies the error mapping of design 22.5 to every operation the image layer sends (an absent object is a hole for READ, ZERO, TRUNCATE and
DELETE only, an unsupported operation, an I/O error or a permission error on a READ fails the request), and compares
`wri_rbd_check_profile` with a model of the refusal table over a grid of features, object sizes, layouts, parents, data pools and flags. Both skip
with a reason when `public/osdc` is absent.

## 5 Making it again

`scripts/capture_osdc.sh run [OUTDIR]`, inside the lab VM as a user with passwordless sudo (needs `ceph`, `rbd`, `rados`, `tcpdump`, `g++` with
the librados headers). It creates the throw-away cephx user `client.vec-osdc` (`mon 'profile rbd'`, `osd 'profile rbd pool=winrbd, profile
rbd pool=wrtest-osdc-data'`; the lab's regular users and the admin key are never used from the capture namespace), the pool
`wrtest-osdc-data`, the images `wrtest-osdc-*` (order 12 to 16, 1 to 8 MiB), runs the sessions, turns `osd_backoff_on_peering` and
`osd_backoff_on_degraded` on for the two backoff sessions and puts every setting it touched back to what it was (set again if it was set,
removed if it was not), cleans up, **verifies that the user is gone** (`ceph auth get` fails and the auth list does not name it), compares
the lab state with the one before the run (`revert-proof.txt`) and runs the extractor and the checker. The user's key is not part of the
tree: the crc-mode messages never needed it, and the script scans the finished tree for the key text and aborts on a hit.

The run keeps 14 images alive at once (the ten of the header sessions, the image for the object operations and the three patterned ones) and changes
the cluster-wide settings `osd_backoff_on_peering`, `osd_backoff_on_degraded` and (for the removal of the throw-away pool) `mon_allow_pool_delete` for a few minutes:
a lab that limits the number of test images, or forbids those settings, needs the phases split (create, capture and remove one group of images at a time).

The probe that sends what the stock tools never send (the eight-call compound read, writes with a snapshot context, a SPARSE_READ) is a
small C++ program over librados that the script embeds and compiles; it only calls the library's public API.

## 6 Checked on the lab afterwards (not part of the set)

Questions the captures cannot answer, put to the same cluster with the stock tools as the oracle (2026-11-17, throw-away images `wrtest-vecc-*`, all removed):

- **A WRITE whose `mtime` is 0 is accepted** by the OSD (v20.2.5), and the object's modification time becomes 0 (a `rados_write_op_operate` with an explicit time
  of 0, then 1, then now, then no time at all: every one succeeded, `rados stat` returned the time that was sent; no time at all means "now" in the library).
  So an object client whose host has no wall clock may send `mtime` 0 (design 22.3); the object then reads as modified in 1970.
- **Object placement of images whose size is not a multiple of the object size**, and past 2^31: images of 1,000,001 bytes with 4 KiB objects (245 objects, `rbd info`),
  of 327,757 bytes with 64 KiB objects (6 objects) and of 2 GiB with 4 KiB objects (524,288 objects) were written through librbd at byte ranges that cross object
  boundaries, end in the partial last object, overlap each other and sit at the very end of the image; every byte was read back with librados from the object
  that `wri_rbd_geom_extent` and `wri_rbd_obj_name` name, at the offset they name, and no other `rbd_data.<id>.*` object existed. The rows are in `test_rbd_vec_replay.c`
  (`check_partial_last_object`).
