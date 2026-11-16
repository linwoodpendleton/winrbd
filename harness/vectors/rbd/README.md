<!-- SPDX-License-Identifier: MIT -->
# RBD format 2 test vectors

Vectors for `docs/spec/rbd-format2.md`: class-method inputs and outputs, header omap values, whole OSD messages that carry them, striping and
object names. They come from one disposable Ceph v20.2.5 (Tentacle) lab cluster (one mon, three OSDs, replicated pool `winrbd`, object size
4 MiB). Each file starts with an `_about` field. All numbers are little-endian, as in the note.

| File | What it holds |
| --- | --- |
| `rbd-class-calls.json` | One `call` op each: `class`, `method`, `input_hex`, `output_hex`, `result` (op count or negative errno) and, for successful calls, `decoded` = the fields the note's layout gives. 77 vectors: every read method of note 2.3, the `lock` methods of 2.7 (inputs and replies), error cases (`-EINVAL`, `-ENOENT`, `-ENOEXEC`, `-EIO`, `-EOPNOTSUPP`, `-EPERM`, `-EBUSY`, `-EEXIST`). |
| `header-omap.json` | `rbd_header.<id>` omap values (hex) of six feature sets (layering only, default, exclusive-lock, striped, data pool, clone, with snapshots), the raw `rbd_id.<name>` object, the lock xattr, and the `rbd_directory` omap. |
| `osd-messages.json` | 29 whole OSD messages: `front_hex` of the MOSDOp (version 9) and of its MOSDOpReply (version 8), the op list, result, per-op `rval` and output lengths, and the data segment when it is at most 600 bytes. Covers the open sequence of `rbd info` (note 2.6 vectors A, B, C), the six-op request, a failing middle op with and without `FAILOK`, `-ENOENT` on a missing object, a whole-object `READ` with length 0, `ZERO` that is rewritten to `TRUNCATE`, `DELETE` of a missing object, `SETALLOCHINT` + `WRITE`, the librbd lock acquire, and a live lock record. |
| `striping-and-objects.json` | The worked examples of note 2.10, data object names (default and data-pool prefix), object counts (2.9), and the size and sha256 of real data objects after a known write recipe (below). |

## Provenance

* Class calls and omap values: `rados exec` / `rados listomapvals` against the lab cluster, and the same calls captured on the wire.
* Whole messages: the msgr2 front and data segments of `MESSAGE` frames in crc mode, cut out of packet captures made on a veth pair
  between a client network namespace and the cluster VM, after the connection was authenticated. Only the OSD message body is kept; no
  handshake, authentication or signature frame is in any vector.
* The probe that sent the requests the stock tools never send (multi-op class calls with a failing op, hand-built `lock` inputs, object
  semantics, capability profiles) links Ceph's librados, so it is kept out of this repository. The vectors are what it put on the wire.
* Written and re-read by `harness/tools/rbd_check.py` (see below); `--write-vectors` regenerates them from the private capture set.

## Scrubbing

* No cephx key, ticket, session key, connection secret, nonce derived from a key, signature or encrypted blob is present: the files hold
  nothing from the authentication frames, and crc-mode OSD messages carry no secret at this layer.
* The lab client's address inside `lock get_info` replies (a `locker_info_t.addr`) was replaced by `192.0.2.7` (documentation range) in
  the hex and in `decoded`. Everything else in those records is as captured: the entity number is the cephx global id of the lab client,
  `nonce` is that process's random messenger nonce. Neither is a credential.
* Image ids, names, pool ids and OSDMap epochs are lab values. Timestamps are the lab's clock (2026-11-16).
* Large payloads (64 KiB bench writes, 9 MiB objects) are not stored; `data_len` is given instead.

## Write recipe behind `striping-and-objects.json` (`written_objects`)

Image `t0-copy-def`, 4 GiB, order 22, default striping, created by `rbd cp` of an image that had 1 MiB of
`bytes((i*7+3)&0xFF for i in range(1<<20))` at image offsets 0 and 1073741824. Then six writes `(offset, length, k)` with data
`bytes((i*13+k)%251 for i in range(length))`: `(0,4096,1)`, `(12388,777,2)`, `(4193792,1024,3)` (spans objects 0 and 1),
`(12582913,5000,4)`, `(1073741824,8192,5)`, `(4294963200,4096,6)`. The objects listed are the ones that exist afterwards, with the size and
sha256 of `rados get`. The checker rebuilds them from the recipe and the note's mapping.

## Checking

```
python3 harness/tools/rbd_check.py --captures <capture dir>            # every check, exit 0 when all pass
python3 harness/tools/rbd_check.py --captures <capture dir> --write-vectors
python3 harness/tools/rbd_check.py --captures <capture dir> --skip-pcap  # ground truth only (seconds)
```

The capture directory is the private Phase 0 set (not in the repository). Without it, the vectors alone can still be checked:
`check_vectors()` in the tool decodes every file here with the layouts of the note and compares with the recorded fields; it runs at the end
of every invocation when this directory exists. The tool needs only Python 3 and its standard library, and reads no key file.

Run time is about 20 seconds for the full set (CRC-32C is a pure Python table loop; 150 MB of crc-mode captures).
