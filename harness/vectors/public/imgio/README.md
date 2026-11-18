<!-- SPDX-License-Identifier: MIT -->
# imgio: the core's own image I/O against a real OSD (module vectors-d)

Public, secret-free captures of what the **winrbd core itself** put on the wire when it did block I/O on RBD images, and what a real Ceph
v20.2.5 OSD answered, for three small scripted sessions; plus the content of each image as the stock `rbd export` reported it before and after.
They complement `osdc/` (module vectors-c), which holds what the *stock client library* sends: there the core's encoder and decoders are
checked against the stock client's bytes; here the whole engine (image layer, request splitting, snapshot context, the profile checks of the
open) is compared with a real OSD, and the simulated OSD of the test harness is compared with the real one answer by answer.

Made on 2026-11-18 on the private lab cluster (Ceph v20.2.5 "Tentacle", one VM, 3 OSDs, replicated pool `winrbd`). **Everything here is a
copy of OSD message bodies and of what the stock tools reported; no pcap, key, ticket, session secret or authentication frame is in the tree.**
The client was `wr-rbd` (`harness/host/tools/wr-rbd.c`: the core on the Linux host) in its `shell` mode, one request at a time (`--depth 1`,
`--io-size 1M`, `--hdr-refresh 0`), as a throw-away cephx user that is deleted again (section 5).

## 1 Files

| Path | Content |
|---|---|
| `INDEX.json` | the session list, the user record (name, caps, creation, deletion and proof that it is gone) and the size and SHA-256 of every file |
| `sessions/<name>.json` | one session: the image block (name, id, object prefix, size, order, feature word, snapshot ids), the shell commands, the exit status of each, what the tool counted (resends, session resets), the OSD map epoch before and after, and its exchanges |
| `images/<name>.after.bin` | `rbd export` of the image after the session (holes as zeros) |
| `images/<name>.before.bin` | `rbd export` before the session, only for the reader session (the stock tool wrote that content); the other images start empty |
| `revert-proof.txt` | the lab state before and after the run (osd tree, pools, upmap lines, flags, health checks, images, objects, users, every set configuration option): identical |

Total 0.9 MB in 8 files. `scripts/capture_imgio.sh` makes it, `scripts/check_imgio.py` checks it.

## 2 Sessions

An **exchange** is `{n, conn, request, reply, t_ms}` in the format of `osdc/README.md` 2: a request is the bytes of the msgr2 message header
and of the front segment exactly as on the wire, the data segment in full (or length, SHA-256 and head when above 20,000 bytes) and the
decoded summary; a reply the same. No exchange has resends: the session ran on a quiet cluster (the OSD map epoch did not change) and the
tool reported `ops_resent=0`, `session_resets=0`.

| Session | Exchanges | What it is |
|---|---|---|
| `w4k` | 46 | a **writer** on an empty image of 4 KiB objects (order 12, feature word 0x1), 40,000 bytes (nine whole objects and a last one of 3,136 bytes): a read of the whole empty image (ten `-ENOENT`), writes inside an object, across two and across five objects, at the very end (the last partial object), reads of data, a discard of a whole object (`DELETE`), of a part (`ZERO`), write-zeroes inside and across objects and of a whole object (`ZERO` that the OSD rewrites as `TRUNCATE`), a discard that reaches the end of the image (`TRUNCATE` of an absent object: the OSD says yes and does not make the object) and a read of everything again (empty objects after a truncate to 0, an object of 1,329 bytes) |
| `snap64k` | 20 | a **writer** on an image of 64 KiB objects (order 16, 0x21 = layering and deep-flatten), 200,000 bytes, that already has **two snapshots** (ids 108 and 109) when it is opened: every write, discard and write-zeroes carries the snapshot context (the OSD makes clones), including a write across three objects, a discard of a whole object and of the last partial object |
| `rd64k` | 10 | a **reader** (profile R1, no `--rw`) on an image with the default feature set (0x3d: exclusive-lock, object-map, fast-diff), 131,079 bytes, written by the stock tool (`rbd bench`) before: the header reads of the reader form, reads across objects, over holes and short objects, the last partial object; no request mutates |

Each session starts with the open as the core does it: `get_id` on `rbd_id.<name>`, then one message of eight class calls on
`rbd_header.<id>` (size and order, object prefix, features, snapshot context, parent, ...). The core sends no `SETALLOCHINT` (the stock
client does; the note's profile leaves it out), no `STAT` and no `SPARSE_READ`: reads are plain `READ`s, one per object, all at once.

## 3 What the set shows

- The requests the engine sends for a block request are exactly the per-object operations the design says: one message per object, `WRITE` at
  the object offset, `DELETE` for a discard that covers a whole object, `ZERO` for a partial one (and for write-zeroes), `TRUNCATE` for a
  discard that reaches the end of the image inside an object, a `READ` per object for a read. The same flags on every message, the snapshot
  context of the image on every mutating message and none on a read.
- A real OSD answers `READ` of an object that does not exist with `-ENOENT` (the image layer turns it into zeros), of a short object with the
  bytes it has, of an emptied object with 0 bytes; `ZERO` of a whole object comes back as `TRUNCATE`; `TRUNCATE` and `ZERO` of an absent object
  succeed and leave it absent.
- Every one of those answers, and the result of every operation, is what the **simulated OSD** of the harness answers (`imgio.replay`): the
  simulator was written from the notes and the stock captures; this is the first time it is held against the answers of a real OSD to the
  requests of the core itself.

## 4 Checking and replaying

```sh
python3 -I harness/vectors/public/scripts/check_imgio.py check       # ctest vectors_imgio_check
python3 -I harness/vectors/public/scripts/check_imgio.py selftest    # ctest vectors_imgio_selftest: 12 damaged copies, all rejected for the right reason
ctest --test-dir build/harness -R 'imgio'                            # also the C replay imgio.replay
```

`check_imgio.py` is written from the notes (python 3 standard library, no Ceph code, no `core/` code; the msgr2 and message decoders are those
of `check_osdc.py`). It checks, besides everything `check_osdc.py` checks of a session (every message decoded again from its bytes and equal
to its summary, request and reply paired by transaction id, the invariants of the notes) and of the tree (sizes and hashes against
`INDEX.json`, no stray file or link, a size budget, no key-, ticket- or password-looking text, no address outside `10.77.0.x` / `192.0.2.x`,
the removal of the throw-away user):

- the image block against the header reply of the session (size, order, feature word, snapshot context) and the object prefix against the id;
- every data request names an object of the image (prefix and 16 hex digits, inside the image), lies inside its object's extent, a writer's
  mutating request carries exactly the image's snapshot context (none for an image without snapshots), a reader sends no mutation;
- the tool's exit statuses are all 0 and it counted no resend;
- the bytes the core put in every `WRITE` are the pattern of the script command that covers them (by hex, or by SHA-256 above 20,000 bytes);
- the requests, replayed on a model of the objects (`WRITE`, `ZERO` with the OSD's rewrite to `TRUNCATE`, `TRUNCATE`, `DELETE`), agree with
  **every read reply** (bytes or SHA-256, `-ENOENT` for an absent object, a short object) and give, at the end, the stock export; and the
  script applied on the image as it was gives the same export (the script, the wire and the export agree);
- the coverage: a write inside an object, across objects, of a whole object and to the end of the image, `ZERO`, `TRUNCATE`, `DELETE`, a read of
  a missing object, of a short object, a write with a snapshot context, the header read.

`test_imgio_replay.c` (ctest `imgio.replay`):
- **wire**: every request is rebuilt from its summary and encoded by `wri_mosdop_encode`: the front equals the capture byte for byte; every
  reply decodes by `wri_mosdopreply_decode` and agrees with its summary;
- **replay**: each script is run through the whole engine (public API, the rig of `client_osd_rig.h`: the engine, the simulated monitor and three
  simulated OSDs over one object store) on an image made like the real one (id, size, order, features, the snapshot context, and for the reader
  the objects the stock tool wrote). The requests the engine sends equal the captured ones, command by command (the same objects, operations,
  offsets, lengths, flags, snapshot context and payload sizes), the count of requests equals the capture's, and what the simulated OSD answers
  equals what the real one answered (result, result and output length of every operation); every read returns what the script wrote before, and
  at the end the whole image read through the engine and every object of the simulated store equal the stock export. A mutation of one answer in
  a copy of the files is reported with its place (tried by hand when the test was written).

## 5 Making it again

`scripts/capture_imgio.sh run [OUTDIR]`, inside the lab VM as a user with passwordless sudo (needs `ceph`, `rbd`, `tcpdump`, and a built
`wr-rbd`: `WR=<path>`). It creates the throw-away cephx user `client.vec-imgio` (`mon 'profile rbd'`, `osd 'profile rbd pool=winrbd'`; the lab's
regular users and the admin key are never used from the capture namespace), three images `wrtest-imgio-*` (and two snapshots on one), runs
`wr-rbd` in its own network namespace under `tcpdump` (a session is refused if the OSD map epoch changes during it: creating and removing
snapshots makes epochs, the script waits until the epoch has been still for four seconds), exports each image with `rbd export` before and
after, removes the images, the namespace and the user (`ceph auth get` must fail, which the script checks before it writes the tree) and writes
`revert-proof.txt`. The key text is scanned for in the finished tree. All scripts are our own code (MIT).
