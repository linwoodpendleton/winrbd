# Client to OSD object I/O: MOSDOp, MOSDOpReply, MOSDBackoff (the "osdop" note)

Status: draft, Phase 0 spec note. Written from source reading, then checked against a live capture: 39 pcaps of
the stock `rados` / `rbd` / `ceph` client against a Ceph v20.2.5 lab cluster (1,933 answered MOSDOp exchanges, crc and
secure mode, both cephx key types), decoded by an independent checker written from this note only
(`harness/tools/osdop_check.py`, scrubbed vectors in `harness/vectors/osdop/`). What the capture settled is marked
**[confirmed: ...]**; what it corrected is listed at the end of section 6 ("Corrections after capture"). Items that
still need a capture stay marked **[confirm on capture]**, items that could not be pinned in source stay marked
**[unverified]**, each with the reason the capture could not settle it.

All `path:line` references are relative to the Ceph tree root at tag v20.2.5
(commit ed27c686770872022f4c1de04f6b0ac5d5384ded). Line numbers are from that tree only.
Everything below is written in my own words; layout tables and numeric constants are protocol
facts, not copied text.

---

## 1 Scope and sources

### 1.1 Scope

Goal: let an implementer write a minimal RADOS client (never a server) that sends object
operations to the primary OSD of a placement group and handles the answers, byte-exact against a
v20.2.5 cluster. Replicated pools only.

Covered:

1. The `MOSDOp` request message (type 42): body layout, the flags field, the per-op record, how
   operation input data is carried, which version the client must send.
2. The sub-operations a minimal RBD client needs (read, sparse read, write, write full, zero,
   truncate, create, delete, stat, call into an object class, omap reads, xattr read, hints) and
   what each does on the server, what it returns, which errors it produces.
3. The `MOSDOpReply` message (type 43): layout, result and per-operation result codes, output
   data, version fields, redirect.
4. The `MOSDBackoff` message (type 61) and the client rules for it.
5. Client logic that the reference library (the "Objecter") applies: target selection inputs,
   transaction ids, resend triggers, `EAGAIN`, redirects, map changes, connection resets, misdirected
   operations, snapshot context rules, ordering.

Not covered here (other notes own them):

- msgr2 framing and the message envelope: `docs/spec/msgr2.md` (2.9 message frame, 2.10 feature bits).
- OSDMap decoding, hashing of object names into PGs, CRUSH: `docs/spec/osdmap.md` (3.7) and the CRUSH note.
- The names, arguments and replies of the RBD object-class methods and the image header layout
  (the RBD note). This note only specifies the generic `CALL` and omap/xattr operations those use.
- Watch / notify (lingering operations), PG-level operations (listing), erasure-coded pools, cache
  tiering, pool snapshots mode. Mentioned only to say they are skipped.

### 1.2 Sources read

| File | Used for |
|---|---|
| `src/messages/MOSDOp.h` | request layout, every encoding version, feature tests, reqid rule |
| `src/messages/MOSDOpReply.h` | reply layout and versions |
| `src/messages/MOSDBackoff.h` | backoff message layout |
| `src/messages/MOSDFastDispatchOp.h` | base class (min epoch = map epoch) |
| `src/include/rados.h` | op codes, flags, `ceph_osd_op` record, backoff op codes, error code values |
| `src/osd/osd_types.h`, `src/osd/osd_types.cc` | `pg_t`, `spg_t`, `osd_reqid_t`, `object_locator_t`, `request_redirect_t`, `eversion_t`, `OSDOp` helpers |
| `src/common/hobject.h`, `src/common/hobject.cc` | `hobject_t` encoding and ordering (needed for backoff) |
| `src/common/snap_types.h`, `src/common/snap_types.cc` | `SnapContext` and its validity rule |
| `src/include/encoding.h`, `src/include/denc.h`, `src/include/types.h`, `src/include/utime.h`, `src/include/object.h`, `src/msg/msg_types.h` | scalar and struct encodings |
| `src/common/zipkin_trace.h`, `src/common/tracer.h`, `src/msg/Message.cc` | the two tracing fields |
| `src/include/ceph_features.h` | feature bits that select encodings |
| `src/osdc/Objecter.cc`, `src/osdc/Objecter.h` | client behaviour (read for facts, re-described here) |
| `src/osd/PrimaryLogPG.cc`, `src/osd/OSD.cc`, `src/osd/osd_op_util.cc`, `src/osd/PG.cc`, `src/osd/Session.cc` | what the server does with each field, which errors it returns, when it stays silent |
| `src/librbd/io/ObjectRequest.cc`, `src/librados/IoCtxImpl.cc`, `src/librados/RadosClient.cc` | which ops and flags the stock RBD client really uses |
| `src/common/options/global.yaml.in`, `src/common/options/osd.yaml.in`, `src/common/options/rbd.yaml.in` | default limits |
| `doc/dev/rados-client-protocol.rst`, `doc/dev/osd_internals/snaps.rst` | prose confirmation of resend and backoff rules (facts only) |

### 1.3 Conventions

- All integers are little-endian. `u8/u16/u32/u64` unsigned, `i8/i32/i64` signed.
- `string` = `u32 length` + that many raw bytes (no terminator). `bl` (a byte buffer) uses the same form.
- `bool` = one byte, 0 or 1.
- `vec<T>` = `u32 count` + elements. `set<T>` and `map<K,V>` likewise (`u32 count` + entries, entries
  of a map are key then value).
- "struct header" = the 6-byte versioned envelope `u8 struct_v, u8 struct_compat, u32 struct_len`,
  where `struct_len` counts the bytes after the 6 header bytes (`src/include/encoding.h:1455-1480`,
  decoder side `:1511-1524`; the same layout for `DENC` structs, `src/include/denc.h:1840-1880`).
  A decoder must reject a struct whose `struct_compat` exceeds the version it implements, must stop
  at `struct_len` and skip any unread tail (`denc.h:1870-1880`).
- Error codes on the wire are Linux errno numbers, negative in `result` and `rval`. On non-Linux
  hosts the reference code translates to and from the Linux numbering (`src/include/platform_errno.h:22-31`,
  `src/include/types.h:625-660`); the wire value is always the Linux one.
- Replies carry the original request's tid in the msgr2 message header (`tid` field, `msgr2.md` 2.9).

---

## 2 Wire structures

### 2.1 Envelope facts for the three messages

| Message | Type | Header `version` / `compat_version` | Source |
|---|---|---|---|
| MOSDOp (client to OSD) | 42 (`CEPH_MSG_OSD_OP`) | 9 / 3 (the sender writes the version it actually encoded, see 2.3) | `ceph_fs.h:177`, `MOSDOp.h:39-40,177` |
| MOSDOpReply (OSD to client) | 43 (`CEPH_MSG_OSD_OPREPLY`) | 8 / 2 (lower versions if the connection features lack bits, see 2.9) | `ceph_fs.h:178`, `MOSDOpReply.h:34-35` |
| MOSDBackoff (both ways) | 61 (`CEPH_MSG_OSD_BACKOFF`) | 1 / 1 | `ceph_fs.h:180`, `MOSDBackoff.h:24-25` |

Receiver gate: a message is dropped by the generic decoder if the receiver's own newest version is
lower than the message's `compat_version` (`src/msg/Message.cc:983-993`). The OSD's newest MOSDOp
version is 9, so any `compat_version` up to 9 passes; the sender uses 3.

Fields of the msgr2 header (see `msgr2.md` 2.9) that matter here:

- `tid` = the operation's transaction id (2.12 and 3.6). The reply echoes it (`MOSDOpReply.h:149`).
- `priority` = the reference client sets the configured client op priority, default 63
  (`Objecter.cc:3406-3409`, `src/common/options/global.yaml.in:3673-3676`). The same value is used for the
  backoff ack (`Objecter.cc:3874`). **[confirmed: all 1,935 captured MOSDOps carry 63; osdop_check.py]** The OSD's replies carry 127.
  **[unverified]** whether any other value changes OSD behaviour (a passive capture only holds what the stock client
  sends); use 63.
- `version` / `compat_version` as in the table. For MOSDOp, `compat_version` stays 3 whichever
  version is encoded (`MOSDOp.h:176-180`; only `header.version` is rewritten in the encoders).
- `data_off`: the reference message helpers set it to the write offset (`MOSDOp.h:216-225`), but the
  Objecter's normal send path never calls those helpers, the OSD never reads it from a request (a grep
  of `src/osd`, `src/osdc` and `src/messages` finds no consumer of the request header's `data_off`), and
  msgr2 only carries it through (`ProtocolV2.cc:1421-1433`). Send 0 **[confirmed: 0 in all 1,935 captured requests]**. The source says a read reply carries
  the offset of the first read op there (`PrimaryLogPG.cc:4360`, and in `complete_read_ctx`); **the capture shows 0
  in all 1,933 replies, including 496 SPARSE_READ replies for requests at a non-zero object offset (corrected after
  capture)**. Ignore the field in a reply.
- Segment placement: the encoded body goes in the front segment and the concatenated per-op input
  data goes in the data segment; the middle segment is unused (`MOSDOp.h:255-261`: ops' input data is
  merged into the message data; the generic encoder asserts the middle segment is empty before calling
  a message's encoder, `Message.cc:238-241`; `msgr2.md` 2.9 for segments). **[confirmed: osdop_check.py, 1,935 requests and
  1,933 replies, crc and secure mode]** segment 0 is the 41-byte header, segment 1 the front, segment 2 (middle) is
  empty in every message, segment 3 the data; a message without data has only two segments in the frame (the trailing
  empty ones are not sent), one with data has four. The header's own `flags` byte is 3 in every captured message in
  both directions, not 1 (reported to the msgr2 note, see "Corrections after capture").

### 2.2 Small building blocks

| Type | Layout | Source |
|---|---|---|
| `snapid_t` | `u64`. Constants: `CEPH_NOSNAP` = `0xFFFFFFFFFFFFFFFE` (the live head), `CEPH_SNAPDIR` = `0xFFFFFFFFFFFFFFFF`, `CEPH_MAXSNAP` = `0xFFFFFFFFFFFFFFFD` | `rados.h:38-40`, `object.h:114-130` |
| `utime_t` | `u32 sec`, `u32 nsec` (8 bytes) | `utime.h:163-185` |
| `eversion_t` | `u64 version`, `u32 epoch` (12 bytes; note version first) | `osd_types.h:927-943` |
| `entity_name_t` | `u8 type`, `i64 num` (9 bytes). Type values: mon 1, mds 2, osd 4, client 8, mgr 16 | `msg_types.h:96-99`, `msgr.h:91-96`; only 0 (unset) and 8 (client) matter here |
| `pg_t` | `u8 1` (a fixed leading version byte, not a struct header), `u64 pool`, `u32 seed`, `i32 -1` (a retired "preferred" field). 17 bytes | `osd_types.h:485-491` |
| `spg_t` | struct header (v1, compat 1, len 18) + `pg_t` (17 bytes) + `i8 shard`. 24 bytes. Shard is `-1` (byte `0xFF`) for replicated pools | `osd_types.h:602-613`, `src/common/types.cc:25` |
| `osd_reqid_t` | struct header (v2, compat 2, len 21) + `entity_name_t` (9) + `u64 tid` + `i32 inc`. 27 bytes. Compat is frozen at 2 | `osd_types.h:172-178`, `denc.h:1932-1939` |
| `object_locator_t` | struct header (v6, compat 3, len) + `i64 pool` + `i32 -1` (retired field) + `string key` + `string nspace` + `i64 hash`. `hash` is `-1` when unused; compat becomes 6 only if `hash` is set. A locator with a non-empty key must have hash -1 | `osd_types.cc:250-285` |
| `hobject_t` (full encoding, used by backoff) | struct header (v4, compat 3, len) + `string key` + `string oid` + `u64 snap` + `u32 hash` + `bool max` + `string nspace` + `i64 pool`. `key` is stored empty when it equals the object name | `hobject.cc:110-122`, `hobject.h:144-150` |
| `request_redirect_t` | struct header (v1, compat 1, len) + `object_locator_t` + `string redirect_object` + `u32 0` (a retired field; a decoder skips that many bytes if it is non-zero) | `osd_types.cc:312-337` |
| blkin trace info | `i64 trace_id`, `i64 span_id`, `i64 parent_span_id` (24 bytes). A client without tracing sends 24 zero bytes | `zipkin_trace.h:75-90`, `Message.cc:1026-1035` |
| otel trace (MOSDOp v9 only) | struct header (v1, compat 1, len 1) + `bool is_valid`. With no tracing the 7 bytes `01 01 01 00 00 00 00`. If valid it is followed by a 16-byte trace id, an 8-byte span id and a `u8` flags, all without length prefixes (a client does not need to send these) | `tracer.h:55-67` (real build), `:155-161` (stub, same bytes for "invalid") |
| `SnapContext` | on the wire inside MOSDOp it is two fields: `u64 snap_seq` and `vec<u64> snaps` (see 2.3) | `snap_types.h:79-107` |

Placement-hash facts needed to fill the request (the algorithms belong to the OSDMap note):

- The `hash` field of the request is the 32-bit placement hash of the object: the locator key if it is
  non-empty, else the object name (`OSDMap.cc:2704-2722`), run through the pool's configured string hash
  (`object_hash` in the pool record; default is the rjenkins string hash, whose reference
  implementation is public domain, `src/include/ceph_hash.cc`, `COPYING:32-34`), with the namespace
  prepended and separated by the byte `0x1F` when the namespace is non-empty (`osd_types.cc:1794-1805`).
  If the locator carries an explicit hash it is used instead (`OSDMap.cc:2724-2735`,
  `Objecter.h:1893-1900`). The value sent is the full 32-bit hash, not the folded PG seed.
- The `pgid` field is the effective PG: the hash folded with the "stable modulo" against the pool's
  current `pg_num` and `pg_num_mask` (`rados.h:96-102`, `Objecter.cc:3024-3025,3108-3125`). The stable
  modulo: take `x & mask`; if that is below `pg_num` it is the result, otherwise the result is
  `x & (mask >> 1)`. For replicated pools the shard is -1.
- The OSD drops (silently) a request whose hash does not belong to the PG named in `pgid` under the
  PG's current `pg_num` (`PrimaryLogPG.cc:2017-2026`). So `pgid` must always be recomputed from the
  newest map's `pg_num` before each (re)send.

### 2.3 MOSDOp body, version 9 (what a v20.2.5 OSD expects from a client)

Which version is sent is chosen by the sender from the connection's negotiated features: on the client
side that is the server's advertised bits ANDed with the client's own supported mask
(`ProtocolV2.cc:2183-2184`, `msgr2.md` 2.10); the messenger passes exactly this value to the message
encoder (`ProtocolV2.cc:432-437`, `Message.cc:233-242`):

| Version | Used when | Notes | Source |
|---|---|---|---|
| 9 | peer has the SERVER_SQUID feature mask (bits 49 and 57) | current; adds the otel trace field to 8 | `MOSDOp.h:397-427` |
| 8 | peer has RESEND_ON_SPLIT (bits 21 and 57) but not SERVER_SQUID | identical to 9 without the otel field | `MOSDOp.h:367-396` |
| 7 | peer lacks RESEND_ON_SPLIT | older field order, includes a `reassert_version` | `MOSDOp.h:343-366` |
| 6 | peer lacks NEW_OSDOP_ENCODING (bit 56) | | `MOSDOp.h:313-342` |
| 1 | peer lacks OBJECTLOCATOR (bit 8) | | `MOSDOp.h:262-312` |

A v20.2.5 OSD still decodes 1..9 (`MOSDOp.h:430-577`). A new client targeting v20.2.5 only needs
version 9. With Reef (no SERVER_SQUID bit) the right choice would be 8; not pursued here
(task scope: one pinned release).

Body of version 9 (`MOSDOp.h:397-427`), in order. The first block is what the OSD decodes up front to
route the message; the second block is decoded later (`MOSDOp.h:409`, `:579-614`). The split is
internal to the OSD; on the wire it is one run of bytes.

| # | Size | Field | Notes |
|---|---|---|---|
| 1 | 24 | `spg_t pgid` | effective PG, shard -1 for replicated (2.2) |
| 2 | 4 | `u32 hash` | object placement hash (2.2) |
| 3 | 4 | `u32 osdmap_epoch` | client's current OSDMap epoch at the time of this (re)send (`Objecter.cc:3389-3392`) |
| 4 | 4 | `u32 flags` | message flags, table in 2.4. 32 bits here (the reply uses 64) |
| 5 | 27 | `osd_reqid_t reqid` | see the rule below; a normal client sends name = (0,0), tid = 0, inc = `client_inc` |
| 6 | 24 | blkin trace | all zero |
| 7 | 7 | otel trace | `01 01 01 00 00 00 00` |
| 8 | 4 | `u32 client_inc` | client incarnation; the reference library uses 0 (`RadosClient.cc:313`) |
| 9 | 8 | `utime_t mtime` | wall-clock time for mutating operations (the OSD stamps the object with it, `PrimaryLogPG.cc:4234`); zero for reads **[confirmed: 678 write-flagged messages carry the send time, within 13 ms of the packet time; all 1,257 read-flagged messages carry 0]** |
| 10 | var | `object_locator_t oloc` | pool, key (normally empty), namespace, hash = -1 |
| 11 | var | `string oid` | object name, no terminator |
| 12 | 2 | `u16 num_ops` | |
| 13 | 38 x n | `ceph_osd_op ops[n]` | raw records, 2.5 |
| 14 | 8 | `u64 snapid` | the snapshot to read, or `CEPH_NOSNAP` for the head. Must be NOSNAP for any message that writes (`PrimaryLogPG.cc:2176-2183`) |
| 15 | 8 | `u64 snap_seq` | write snapshot context: the context's seq |
| 16 | 4 + 8m | `vec<u64> snaps` | write snapshot context: existing snapshot ids, strictly descending |
| 17 | 4 | `i32 retry_attempt` | 0 for the first transmission, 1, 2, ... for each resend of the same operation |
| 18 | 8 | `u64 features` | see below |

Notes on individual fields:

- `reqid` (field 5) and `client_inc` (field 8). If the client leaves `reqid.name` empty and `reqid.tid`
  zero, the OSD builds the request id itself from the connection's peer name (`client.<global id>`),
  `reqid.inc`, and the msgr2 header tid (`MOSDOp.h:107-118`). It then **asserts** that `reqid.inc`
  equals `client_inc` (`MOSDOp.h:112-113`; the check runs once the body has been fully decoded, and it
  is an always-on assert, not a debug check), so a client that sends different values can crash the OSD.
  `reqid.inc` is signed 32-bit, `client_inc` is unsigned 32-bit; the comparison casts, so any value works
  as long as both fields carry the same 32 bits. Send the same number in both (0). The reference library
  fills `reqid.inc` from the same variable in the constructor (`MOSDOp.h:195-197`) and only sets an
  explicit name / tid for proxied requests (`Objecter.cc:3411-3413`).
- `osdmap_epoch` (field 3). An OSD whose own map is older than this epoch parks the request and asks for the newer map
  (`PrimaryLogPG.cc:1855-1862`, `OSD.cc:7610-7613`); an OSD that sees an older epoch shares incremental maps back
  (3.4). So send the epoch of the map you really hold and used to compute `pgid`, never a guess.
- `mtime` (field 9). For a write the OSD uses it as the object's modification time. The reference
  library sets it from the caller; for pure reads it is the zero time (`Objecter.cc:3399`).
- `oloc` (field 10) is rebuilt from the target: pool = the data pool id, key = the locator key (empty for
  RBD data objects), nspace = the locator namespace (empty unless the image lives in a pool namespace),
  hash = -1. The OSD reconstructs its internal object id from `pool` + `nspace` + `key` + `oid` + the
  `hash` of field 2 (`MOSDOp.h:588-608`). Only when the object name is empty (a PG-level request)
  does the encoder put the hash into the locator instead (`MOSDOp.h:129-135`).
- `features` (field 18): the encoder writes the connection's negotiated feature word that the messenger
  hands to it (the parameter of the encode function shadows the message's own `features` member, so the
  per-op value stored by the Objecter is NOT what goes on the wire, `MOSDOp.h:255,426` versus
  `Objecter.cc:3389-3392`). So send exactly the negotiated set (server-advertised bits ANDed with the
  client's supported mask, `ProtocolV2.cc:2183-2184`), not the raw advertised mask. The OSD takes the
  wire value if it is non-zero and falls back to the connection's features if it is zero
  (`MOSDOp.h:166-174`); for plain replicated I/O the OSD's own contexts only use the connection's
  features (`PrimaryLogPG.h:848-853`; the `m->get_features()` callers at `PrimaryLogPG.cc:3120,3898` are
  cache-tier / copy paths a minimal client never triggers). So a zero here is tolerated by the code I
  read, but sending the negotiated word is the faithful choice. **[confirmed: all 1,935 captured requests carry
  `0x3f07fffffffdffff`, which is the server's advertised word ANDed with the client's (both ident frames carry that
  value); osdop_check.py]** A zero was not exercised, see question 2 in section 6.
- For a message with no mutation, fields 15 and 16 (snap seq and list) are still present but the OSD
  ignores them (`PrimaryLogPG.cc:4211-4221` only reads them in the may-write branch). Send 0 and an
  empty vector for reads.

Version 8 = fields 1-6, 8-18 (without 7). Version 7 and below: see `MOSDOp.h:262-366` if ever needed;
not recommended.

### 2.4 MOSDOp message flags (field 4)

Values from `rados.h:453-484`. The bit is "what the sender asks for"; most are server-private.

| Bit value | Name | Meaning for a minimal client |
|---|---|---|
| `0x0001` | ACK | do not set (the reference client does not; the OSD sets it on replies) |
| `0x0002` | ONNVRAM | do not set |
| `0x0004` | ONDISK | **set on every request**; the reference library always sets it for compatibility (`Objecter.cc:3378-3380`) and the OSD echoes it back |
| `0x0008` | RETRY | set exactly when `retry_attempt` is non-zero (`MOSDOp.h:246-252`) |
| `0x0010` | READ | set for messages issued via the read path (no mutating op). Used only by the client's own logic (it asserts that READ or WRITE is set, `Objecter.cc:2548`, and uses them to decide pausing, `Objecter.cc:2820-2830`); the OSD ignores it and derives read/write from the op codes (`osd_op_util.cc:84-98`) |
| `0x0020` | WRITE | set for messages issued via the mutate path (any mutating op, including a `CALL` of a mutating method). Same remark: only client-side logic reads it, so it must match what the ops really do or pause / full handling will misclassify the message |
| `0x0040` | ORDERSNAP | ask for `EOLDSNAPC` (85) if the snapshot context is older than the object's; librbd does not set it (no hit in `src/librbd`) |
| `0x0100` | BALANCE_READS | read from any replica; skip (primary only) |
| `0x0400` | PGOP | PG-level operation; skip |
| `0x2000` | LOCALIZE_READS | read from the nearest replica; skip |
| `0x4000` | RWORDERED | order this read against concurrent writes; librbd does not set it by default |
| `0x20000` | IGNORE_OVERLAY, `0x8000` IGNORE_CACHE | cache-tier flags; the client sets them itself only when following a redirect |
| `0x100000` | ENFORCE_SNAPC | use the snapshot context in the message even if the pool is in pool-snapshot mode (`PrimaryLogPG.cc:4211-4221`); for an RBD pool (self-managed snapshots) not needed |
| `0x200000` | REDIRECTED | set by the client when it follows a redirect reply |
| `0x400000` | KNOWN_REDIR | set on every request by the reference library (`Objecter.cc:3375`); say "the redirect bit is authoritative" |
| `0x800000` | FULL_TRY | send even though the map says the pool is full; see 3.8. **Captured:** the `rbd` command sets it on many metadata calls and on the DELETE ops of `rbd rm` (478 messages), not on data reads and writes |
| `0x1000000` | FULL_FORCE | send despite full, even failsafe; not for a client (the reference library adds it to every request only when its "honor pool full" switch is off, default on, `Objecter.cc:3382-3383`, `Objecter.h:1724`). **Captured:** `rados rm` sets it on its DELETE (10 of 10 messages), word `0x09400024` |
| `0x4000000` | RETURNVEC | let a mutating message return per-op output; skip (3.3) |
| `0x8000000` | SUPPORTSPOOLEIO | "I handle the pool EIO flag myself"; set on every request by the reference library (`Objecter.cc:3376`). If the pool has the EIO flag and this bit is SET, the OSD silently drops the request and expects the client to have failed it with `EIO` itself (the reference client does so from the map, `Objecter.cc:2965-2967`, `:1644-1656`); if the bit is missing the OSD replies `-EIO` (`PrimaryLogPG.cc:2166-2175`) |
| `0x0200`, `0x0800`, `0x1000`, `0x0080`, `0x10000`, `0x40000`, `0x80000`, `0x2000000` | PARALLELEXEC, EXEC, EXEC_PUBLIC, PEERSTAT_OLD, SKIPRWLOCKS, FLUSH, MAP_SNAP_CLONE, IGNORE_REDIRECT | never set by a minimal client (the Objecter does not set EXEC; the OSD answers a request carrying PARALLELEXEC with `-EINVAL`, `PrimaryLogPG.cc:2043-2048`) |

Flag words the reference library produces for plain RBD data I/O (derived: READ or WRITE, plus
ONDISK, KNOWN_REDIR, SUPPORTSPOOLEIO; librbd adds no extra flags by default, `ImageCtx.cc:314-330`):

- read: `0x08400014`; write: `0x08400024`; add `0x08` when `retry_attempt` is non-zero.
- **[confirmed for data I/O: the 932 captured reads and writes of `rbd_data.*` objects by `rbd bench` carry exactly these
  two words; osdop_check.py]** **Corrected after capture:** other messages of the stock tools carry more bits. `rbd`
  metadata calls and the DELETE ops of `rbd rm` add FULL_TRY (`0x08C00014` / `0x08C00024`, 478 messages) and `rados rm`
  adds FULL_FORCE (`0x09400024`, 10 messages). Every one of the 1,935 requests has ONDISK, KNOWN_REDIR and SUPPORTSPOOLEIO
  set, and none has ACK, ONNVRAM, RETRY, RETURNVEC or any bit the table marks "never set". READ and WRITE are exactly one
  per message; every message with a mutating non-CALL op has WRITE, and a given class method always has the same bit
  (`lock lock`, `unlock`, `assert_locked` and the `rbd` writers WRITE; `lock get_info` and the getters READ).

### 2.5 The per-operation record `ceph_osd_op` (38 bytes, raw, no struct header)

Defined at `rados.h:585-669`; the encoder writes the C struct as raw bytes (`types.h:399`), size
asserted at `rados.h:679-681`. The record is zeroed before use (`osd_types.h:4296-4305`); all unused
bytes must be zero.

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | `u16 op` code (2.6) |
| 2 | 4 | `u32 flags` per-op flags (below) |
| 6 | 28 | union of per-op arguments (below) |
| 34 | 4 | `u32 payload_len`: number of input-data bytes this op contributes to the message data segment |

Per-op flags (`rados.h:486-496`): `0x1` EXCL (create must fail if it exists), `0x2` FAILOK (a failure of
this op does not fail the message), `0x4`..`0x40` FADVISE hints (random, sequential, will-need, dont-need,
no-cache), `0x80` WITH_REFERENCE, `0x100` BYPASS_CLEAN_CACHE. A minimal client uses only EXCL. **[confirmed: CREATE
carries EXCL in 12 of 12 captured; all else 0 except what follows]** **Captured, not in the source reading:** librbd sends
SETALLOCHINT with FAILOK (`0x2`) in all 420 cases, and `rbd bench --io-pattern seq` puts `0x8` (the "sequential" hint) on
every WRITE and SPARSE_READ.

Union variants a minimal client needs (offsets are from the start of the record):

| Variant | Used by | Layout |
|---|---|---|
| extent | READ, SPARSE_READ, WRITE, WRITEFULL, ZERO, TRUNCATE | `u64 offset` @6, `u64 length` @14, `u64 truncate_size` @22, `u32 truncate_seq` @30 |
| xattr | GETXATTR (and SETXATTR, CMPXATTR) | `u32 name_len` @6, `u32 value_len` @10, `u8 cmp_op` @14, `u8 cmp_mode` @15 |
| cls | CALL | `u8 class_len` @6, `u8 method_len` @7, `u8 argc` @8 (unused, 0), `u32 indata_len` @9 |
| alloc hint | SETALLOCHINT | `u64 expected_object_size` @6, `u64 expected_write_size` @14, `u32 flags` @22 |
| writesame | WRITESAME | `u64 offset` @6, `u64 length` @14, `u64 data_length` @22 |

Other ops (STAT, CREATE, DELETE, OMAPGETVALS, OMAPGETVALSBYKEYS) use no union field except as noted in 2.7;
the reference library nevertheless writes `extent.offset = 0` and `extent.length = <input length>` into the
omap ops (`Objecter.h:990-1005,1031-1046`). The OSD reads their arguments from the input data, not from the
union. **[confirmed: the stock client sends `extent.offset` 0 and `extent.length` = input length in all 10 captured
omap ops (OMAPGETKEYS, OMAPGETVALS, OMAPGETVALSBYKEYS), and the reply echoes the union unchanged]** Whether an all-zero
union is also accepted cannot be tested from a passive capture and stays **[confirm on capture]**. For `truncate_seq` / `truncate_size`:
the OSD rewrites (seq 1, size -1) to (0, 0) (`PrimaryLogPG.cc:6087-6093`); RBD sends 0 and 0.

How input data is carried (`osd_types.h:4333-4341`, `:4313-4322`): the message data segment is the
concatenation, in op order, of each op's input bytes; an op with no input bytes has `payload_len` 0.
`payload_len` is the byte count the receiver uses to cut the data segment into per-op pieces. For
each op the input bytes are:

- WRITE, WRITEFULL: the data to store (`extent.length` must equal `payload_len`, 2.7);
- GETXATTR: the attribute name (`xattr.name_len` bytes);
- CALL: class name bytes, then method name bytes, then the method input
  (`class_len + method_len + indata_len` bytes in total; names are therefore at most 255 bytes each);
- OMAPGETVALS / OMAPGETVALSBYKEYS: the encoded arguments (2.7);
- READ, SPARSE_READ, STAT, ZERO, TRUNCATE, CREATE, DELETE: none.

### 2.6 Op codes needed by a minimal RBD client

An op code is `mode | type | number` (`rados.h:227-245`): mode RD `0x1000`, WR `0x2000`, RMW `0x3000`,
SUB `0x4000`, CACHE `0x8000`; type DATA `0x0200`, ATTR `0x0300`, EXEC `0x0400`, PG `0x0500`.
The comment at `rados.h:223-226` says not to use raw codes directly; the values below are computed from the
table at `rados.h:247-373`.

| Op | Code | Used for |
|---|---|---|
| READ | `0x1201` | data read, below the sparse-read threshold |
| STAT | `0x1202` | object size and mtime; also the "assert exists" probe (librados implements `assert_exists` as a STAT, `librados_cxx.cc:146-151`) |
| SPARSE_READ | `0x1205` | data read that reports holes (librbd: reads of 64 KiB or more, `rbd_sparse_read_threshold_bytes`, `rbd.yaml.in:239-248`, `ObjectRequest.cc:240-244`) |
| ASSERT_VER | `0x1208` | skip |
| WRITE | `0x2201` | partial object write |
| WRITEFULL | `0x2202` | replace the whole object (librbd uses it when a write covers an entire object, `ObjectRequest.cc:664-667`) |
| TRUNCATE | `0x2203` | set object size |
| ZERO | `0x2204` | zero a range (discard) |
| DELETE | `0x2205` | remove the object |
| CREATE | `0x220D` | create an empty object (optionally exclusive) |
| SETALLOCHINT | `0x2223` | optional performance hint; librbd puts it before WRITE |
| WRITESAME | `0x2226` | skip |
| CMPEXT | `0x1220` | skip (librbd uses it for compare-and-write) |
| OMAPGETKEYS | `0x1211` | skip (cls_rbd methods cover directory listing) |
| OMAPGETVALS | `0x1212` | read a range of omap key/values |
| OMAPGETHEADER | `0x1213` | skip |
| OMAPGETVALSBYKEYS | `0x1214` | read named omap keys |
| GETXATTR | `0x1301` | read one extended attribute |
| CALL | `0x1401` | execute an object-class method (all `cls_rbd` metadata access, `cls_lock`) |

**[confirmed: READ, STAT, SPARSE_READ, WRITE, WRITEFULL, DELETE, CREATE, SETALLOCHINT, OMAPGETKEYS, OMAPGETVALS,
OMAPGETVALSBYKEYS and CALL appear in the capture with exactly the numeric values above, and every record decodes with the
layout of 2.5; osdop_check.py]** Not seen, so their values are still from the source only: TRUNCATE, ZERO, GETXATTR,
WRITESAME, CMPEXT, ASSERT_VER, OMAPGETHEADER. Four more codes occur on librbd header and mirroring objects and are not in
this table: `0x220F`, `0x1206`, `0x1207`, `0x1209` (51, 31, 19 and 24 messages; their layout is out of scope, section 1.1
leaves out watch / notify and the capture alone does not name them).

### 2.7 What each op takes and returns

For every op the reply carries back the same 38-byte record (2.9) with `payload_len` replaced by the length of
that op's output bytes. Rules of the server dispatch that apply to all ops (`PrimaryLogPG.cc:6027-8219`):
ops run in order; each op stores its own `rval`, and the message `result` is the result of the LAST op that ran
(every op overwrites it; a failing FAILOK op resets it to 0); the first failing op without FAILOK stops the message
and its error becomes the message `result`; ops after it are not executed and keep `rval` 0 and no output
(`PrimaryLogPG.cc:8205-8218`). The message is run against ONE object; the OSD may rewrite an op's code in place
before running it (a ZERO that reaches the object end becomes TRUNCATE, `PrimaryLogPG.cc:6095-6109`), and the reply
echoes the rewritten record, so a client must not require the echoed op code to equal the one it sent.

| Op | Request | Success reply | Notes and errors |
|---|---|---|---|
| READ | extent offset, length; no input | output = the bytes; reply `extent.length` = bytes returned; `rval` 0 | `length == 0` means "whole object" (`PrimaryLogPG.cc:5855-5856`). A read starting at or past the object size returns 0 bytes with success; a read crossing the end is shortened (`:5858-5864`). For any message that cannot write (all ops read-only, including STAT / GETXATTR / OMAP reads / a read-only CALL), a missing object, or a head that is only a whiteout left by a delete with live snapshots, fails the whole message with `-ENOENT` before any op runs, `rval` all 0 (`:2526-2539`). Holes inside the object read as zeros |
| SPARSE_READ | as READ | output = `map<u64,u64> extents` followed by `bl data`: i.e. `u32 n`, `n` pairs of (`u64 offset`, `u64 length`), then `u32 data_len`, then the data bytes for those extents concatenated in order. The offsets are absolute in the object, not relative to the request offset (`:5978-6017`; the data blob is `u32 len` + bytes, `encoding.h:318-323`). Reply `extent.length` = data bytes (not the size of the whole output) | Bytes not covered by any extent are holes (read as zeros). Same ENOENT rule as READ. If the request goes past the end of the object it is clipped first (`:5947-5951`; here `offset == size` is not "past", so it goes on with length 0). `length == 0` is NOT "whole object" for this op, unlike READ: it asks for nothing, so always send an explicit length. An empty result is `u32 0` + `u32 0` (what the erasure path writes, `:5969-5975`; the replicated path produces the same bytes from an empty extent list **[confirm on capture]**). The extent list comes from the object store's allocation map, so extents inside the requested range are expected but not proven. **[confirmed: all 512 captured SPARSE_READ replies are
one extent equal to the requested range, with absolute object offsets (496 of the requests start at a non-zero offset); `n`,
the pairs, `u32 data_len` and the data decode as described and `extent.length` in the reply equals the data bytes]** An empty
or multi-extent result did not occur, see 6.4 and 6.15 |
| STAT | none | output = `u64 size` then `utime_t mtime` (8 + 8 = 16 bytes in total; `utime_t` is `u32 sec` + `u32 nsec`) (`:6265-6281`) | `-ENOENT` if the object does not exist or is a whiteout (as the whole-message result when it is a read-only message, 2.7 READ row) |
| WRITE | extent offset, length, truncate_seq/size (0, 0); input = data | no output | `extent.length` must equal `payload_len`, else `-EINVAL` (`:6737-6745`). Creates the object if absent. Writing zero bytes at an offset past the end extends the object to that offset (`:6816-6830`). `-EFBIG` when `offset >= osd_max_object_size`, or `length > max`, or `offset + length > max` (128 MiB default; note that `offset == max` fails even with length 0) (`:5368-5381`, `global.yaml.in:3784-3789`); the same check guards ZERO and TRUNCATE. A message whose total data segment exceeds `osd_max_write_size` (90 MiB default, the option is in MiB and the code shifts by 20) gets `-EMSGSIZE` (`:2185-2194`, `rados.h:218`, `osd.yaml.in:808-818`) |
| WRITEFULL | extent offset 0, length; input = data | no output | replaces the object contents; creates if absent; shrinks if the new data is shorter (`:6855-6893`) |
| ZERO | extent offset, length | no output | absent object: no-op, success. Length 0: no-op. If the range reaches or passes the current end the OSD turns the op into a TRUNCATE at `offset` (a no-op if `offset` is already at or past the end) (`:6095-6109,6907-6932`). So ZERO never makes an object grow |
| TRUNCATE | extent offset (= new size); `truncate_seq` 0 | no output | absent object: no-op, success. Can extend (sparse) as well as shrink (`:6961-7019`) |
| CREATE | per-op flags EXCL optional | no output | succeeds as a no-op if the object exists, unless EXCL is set, then `-EEXIST` (`:6934-6958`). Creates an empty object. Send no input data: non-empty input is decoded as a retired category string and a malformed one gives `-EINVAL` (`:6943-6952`) |
| DELETE | none | no output | `-ENOENT` if the object does not exist (`:7021-7027`, `:8273-8309`). If snapshots exist (the message's snapshot context shows clones) the head is kept as a "whiteout" instead of being removed, hence the snapshot context matters for DELETE |
| SETALLOCHINT | alloc-hint variant | no output | hint only, but it creates an empty object if none exists (`:6717-6729`) |
| GETXATTR | xattr name_len; input = name | output = value bytes; reply `xattr.value_len` = length | `-ENODATA` (61) if the attribute is absent (the object store returns it, `src/os/bluestore/BlueStore.cc:13551`), `-ENOENT` if the object is absent (`:6423-6439`; the `:16006-16008` lines are the erasure-pool variant of the same rule). The server prepends an underscore to the user name internally; the client sends the plain name |
| CALL | cls class_len, method_len, indata_len; input = class + method + argument bytes | output = whatever the method returns; reply `extent.length` = output length | An unknown class or method fails the whole message with `-EOPNOTSUPP` before any op runs (a class that exists but cannot be opened gives `-EPERM` if it is a permission problem, else `-EIO`), all `rval` 0 (`osd_op_util.cc:181-196`, `PrimaryLogPG.cc:2051-2055`; the in-execution variant is `:6228-6233`). The method's own return code becomes this op's `rval` and can be negative or positive; a method that reads or writes without being registered for it is failed with `-EIO` (`:6245-6254`). The OSD classifies the op as read or write from the method's registered flags, not from the client's message flags (`osd_op_util.cc:197-204`) |
| OMAPGETVALS | input = `string start_after`, `u64 max_entries`, `string filter_prefix` | output = `u32 n`, then `n` x (`string key`, `bl value`), then `bool truncated` (`:7779-7841`; a value is `u32 len` + bytes) | Keys come back strictly after `start_after`, in order, only those that begin with `filter_prefix`, limited to the smaller of `max_entries`, the OSD's `osd_max_omap_entries_per_request` (1024 default) and its byte cap (1 GiB default; the cap is tested before each entry is added, so the reply can exceed it by one entry) (`global.yaml.in:3813-3822`). `truncated` is true only when one more matching key was found after the limit was hit, so `false` is a reliable end marker; if true, ask again with `start_after` = the last key received. `max_entries == 0` returns nothing and `truncated = true` if any key matches: never send 0. A missing omap on an existing object returns an empty result, not an error (a missing OBJECT is the whole-message `-ENOENT` of the READ row). The reference helper has a copy-and-paste slip in one overload that sends the start-after string where the filter prefix belongs (`Objecter.h:1022`), so do not model the prefix argument on it |
| OMAPGETVALSBYKEYS | input = `set<string>` (`u32 n` + strings) | output = `map<string,bl>` (`u32 n` + entries); absent keys are omitted | (`:7856-7872`) **[confirmed for a present key; a missing key was not asked for]** |

Capture confirmations for the table above (osdop_check.py):

- READ: 28 captured; the reply `extent.length` equals the bytes returned; a 4 MiB read of a 9 MiB + 1,234 byte object came back
  as 4,194,304 + 4,194,304 + 1,049,810 bytes (the read crossing the end is shortened); `rados get` asks for 4 MiB, not 0.
  STAT: 16 bytes, `u64 size` + `u32 sec` + `u32 nsec`, the mtime equals the mtime that was sent with the write.
- OMAPGETVALS paging on a 1,100-key object: page 1 asks `start_after` empty, `max_entries` 1024, `filter_prefix` empty and
  returns 1,024 entries with `truncated` = true; page 2 asks `start_after` = the last key of page 1 and returns 76 entries with
  `truncated` = false. **[confirmed]** OMAPGETKEYS (skipped by this note) returns `u32 n`, n strings, `bool truncated`, and pages
  the same way.
- CALL: the reply `extent.length` field equals the output length in 1,028 of 1,028 captured CALL ops (the note says a client must
  not rely on it; it is also not wrong). The class and method names, input and output decode as described for every captured
  `rbd` and `lock` method listed in `rbd-format2.md` 2.3 and 2.7 (osdop_check.py compares 176 of them byte for byte with the raw output the lab collected through librados for the same
  call on the same object, and the decoded values with `rbd info`).
- A read-only message on a missing object fails as a whole: `result` -2, every `rval` 0, no data (58 captured, all with the object
  absent). A mutating message whose method fails inside the OSD (48 captured) and a read-flagged CALL whose method returns -ENOENT
  on an existing object (6 captured) give `result` = the failing `rval`. **[confirmed]**
- Not exercised: a positive `rval` or `result`, a failing op that is not the only op of its message, and a write message that would
  have returned output: none of the 629 successful write-flagged messages produced an output byte, and the 100 of them that
  carry a CALL use methods that return nothing. The output-discard rule below therefore stays source-only.
Server rule that explains empty replies for writes: when a message that may write succeeds AND its object
transaction is non-empty, the OSD, unless RETURNVEC was requested, sets the message result to 0 and
**discards all per-op output**; the per-op `rval` values are kept (`PrimaryLogPG.cc:4287-4307`). A write-class
message whose transaction ends up empty (for example a mutating CALL that changed nothing) is not subject to the
rule. So an op that must return data (a `CALL` returning a value, `STAT`, `GETXATTR`) has to be sent in a
message with no mutating op. With RETURNVEC the OSD returns output but caps it at
64 bytes per op (`global.yaml.in:3825-3832`); not used by a minimal client.

### 2.8 Which ops a minimal RBD client sends (how librbd composes them)

(Observed in `src/librbd/io/ObjectRequest.cc`; the stock client composes writes as one message with several ops.)

- Read of one object extent: one message with READ or SPARSE_READ per extent, snapid = the image's current
  read snapshot (NOSNAP for the head). A missing object (`-ENOENT`) means the extent is all zeros for an image with
  no parent (`ObjectRequest.cc:262-270`).
- Write: one message, op list = [SETALLOCHINT (optional)], WRITE or WRITEFULL, snapshot context = the image's
  (`:140-146`, `:640-668`).
- Discard of a whole object: DELETE. Discard of the tail: TRUNCATE. Discard of the middle: ZERO
  (`:675-690`; for a "remove or truncate" mode: CREATE (not exclusive) then TRUNCATE).
- Metadata: CALL (class `rbd`, method names in the RBD note) on the header, id and directory objects, sent on the
  read path when the method only reads and on the mutate path when it writes.
- Exclusive create: when the image layer asks for it, a write message starts with CREATE+EXCL (`:655-656`), then the
  allocation hint (`:136-146`, only when the image's alloc-hint option is on), then WRITE / WRITEFULL, so the op
  order is [CREATE(EXCL)] [SETALLOCHINT] WRITE. Whether a given data write carries CREATE+EXCL depends on librbd's
  object-map state and is not needed by a client that does not keep an object map.

### 2.9 MOSDOpReply, version 8

Server side choice of version (`MOSDOpReply.h:171-227`): if the connection's features (the client's advertised set
intersected with the server's) lack PGID64 (bit 9), the OSD sends the very old version 1 layout; if they lack
NEW_OSDOPREPLY_ENCODING (bit 58), version 6 (same as 8 but the redirect field is always present, with no
`do_redirect` flag in front; a trace block is still appended by the encoder but a v6 decoder does not read it,
`MOSDOpReply.h:215-225`, `:309-321`); otherwise version 8. The decoder also accepts version 7, which the encoder
never produces. A client advertising the recommended
mask (`msgr2.md` 4.4) always gets 8. A minimal client should decode 8 and reject other versions with a clear
message (the decode ladder is `MOSDOpReply.h:228-323`).

Header version 8, compat 2. Body (`MOSDOpReply.h:194-225` encode, `:233-258` decode):

| # | Size | Field | Notes |
|---|---|---|---|
| 1 | 4 + n | `string oid` | echo of the object name |
| 2 | 17 | `pg_t pgid` | the PG that handled it (the plain 17-byte form, not `spg_t`) |
| 3 | 8 | `i64 flags` | **64 bits** in the reply (`MOSDOpReply.h:41`); the request flags with ACK / ONNVRAM / ONDISK recomputed: a reply that executed has ACK and ONDISK set (`PrimaryLogPG.cc:9220`, `:4366`, `:4387`) **[confirmed for 1,819 successful replies and 54 replies of ops that failed while executing]**. **Corrected after capture:** a reply produced before execution (60 captured: 58 whole-message `-ENOENT`, 2 `-EPERM`) carries the request flags unchanged, so it has ONDISK but **no ACK**. **Corrected again after the captures of the object client** (`harness/vectors/public/osdc/README.md`): the answer to a resent write that the OSD recognises as a duplicate may also come back with ONDISK and no ACK (flags `0x0840002c`, 11 of the 19 resent writes of the two backoff sessions), so no client logic may depend on ACK; the decoders ignore the flag |
| 4 | 4 | `i32 result` | overall result, negative errno on failure, 0 or a small positive number on success |
| 5 | 12 | `eversion_t bad_replay_version` | legacy field; ignore. **Captured:** it is not zero; it holds (`user_version`, epoch of `replay_version`) in 1,896 of 1,933 replies |
| 6 | 4 | `u32 osdmap_epoch` | the OSD's map epoch when it replied |
| 7 | 4 | `u32 num_ops` | |
| 8 | 38 x n | `ceph_osd_op ops[n]` | echo of the request records; `payload_len` = this op's output length; some union fields updated (2.7) |
| 9 | 4 | `i32 retry_attempt` | echo of the request's `retry_attempt` |
| 10 | 4 x n | `i32 rval[n]` | per-op result codes, in op order |
| 11 | 12 | `eversion_t replay_version` | version of the write; all-zero for reads **[confirmed]**; its epoch equals the reply's `osdmap_epoch` for every successful write |
| 12 | 8 | `u64 user_version` | the object's user version (`objver`); for reads the current one, for ENOENT a floor value (`PrimaryLogPG.cc:9208-9217`). **Captured:** 0 in all 60 pre-execution errors (the "floor value" did not show up); for ops that failed while executing it is non-zero in 38 of 54 |
| 13 | 1 | `bool do_redirect` | |
| 14 | var | `request_redirect_t redirect` | present only if `do_redirect` is true |
| 15 | 24 | blkin trace | ignore |

The message data segment of the reply is the concatenation of every op's output bytes, in op order; cut it by the
`payload_len` values of the echoed op records (`osd_types.cc:7398-7416`). Check that the sum of the `payload_len`
values equals the data segment length and that `num_ops` equals the number of ops sent; the reference library only logs
a warning on a count mismatch (`Objecter.cc:3717-3720`), a minimal client should treat it as a protocol error.

How to read the result codes (`PrimaryLogPG.cc:9183-9223`, `:4287-4307`, `:8205-8214`):

- `result` below zero: the message failed; it is the first failing op's error (unless FAILOK). Treat the output data as
  absent. The ops after the failing one were not executed.
- `result` zero or above: every op succeeded (or was FAILOK). A read-only message can return a positive result when a
  `CALL` method returned one.
- A reply that executed has ONDISK and, usually, ACK (not for the answer to a resent duplicate write, see the `flags` row); only one reply per attempt is ever sent for the flags the client uses, so
  there is no separate "ack" and "commit" phase to wait for (`Objecter.cc:3792-3793`). **[confirmed: exactly one reply per
  request in all 1,933 exchanges]** **Corrected after capture:** not every reply has ACK, see the `flags` row above.
- Error replies produced before execution (`reply_op_error`, `OSD.cc:1630-1649`) carry the request's ACK / ONDISK bits and
  `result` = the errno, with the ops echoed and all `rval` 0. **[confirmed: 60 captured; the echoed records are the request
  records, `payload_len` 0, version fields 0; the `osdmap_epoch` field is the OSD's epoch]**
- Every captured reply has `osdmap_epoch` equal to the request's (1,933 of 1,933), version 8 / compat 2, `do_redirect` false,
  the retry attempt echoed, and the 24-byte trace block zero; the front is consumed exactly. **[confirmed]** A redirect reply
  did not occur.

### 2.10 MOSDBackoff

Type 61, header version 1, compat 1 (`MOSDBackoff.h:24-25`). Body (`:52-71`):

| # | Size | Field |
|---|---|---|
| 1 | 24 | `spg_t pgid` |
| 2 | 4 | `u32 map_epoch` |
| 3 | 1 | `u8 op`: 1 BLOCK, 2 ACK_BLOCK, 3 UNBLOCK (`rados.h:573-577`) |
| 4 | 8 | `u64 id` unique within this OSD session |
| 5 | var | `hobject_t begin` (full encoding, 2.2) |
| 6 | var | `hobject_t end` |

`begin == end` blocks the single object `begin`; otherwise it blocks the half-open range `[begin, end)`. Ordering of
`hobject_t` for range tests (`hobject.cc:331-368`, `hobject.h:280-282`): compare in this sequence, first difference wins:
the `max` flag, the `pool`, the 32-bit hash with its bits **reversed** (a "bitwise key"; max sorts above everything),
the namespace, the effective key (the key, or the object name when the key is empty; skipped if both keys are empty), the
object name, then the snapshot id. A request's own position is built with snapshot = NOSNAP, key = the locator key, hash =
the request hash, pool, namespace (`Objecter.h:1893-1906`).

### 2.11 Errors a client will see

Linux numbers; names as in Ceph. Source of each is given in 2.7 or here.

| Value | Name | When |
|---|---|---|
| -1 | EPERM | the cephx caps of the key do not allow the operation (`PrimaryLogPG.cc:2083-2086`). **[confirmed: a key with `osd r pool=winrbd` gets a pre-execution `-EPERM` for WRITEFULL and also for CALL (class methods need the class permission, even read-only ones), while STAT works]** |
| -2 | ENOENT | object (or pool, for the client) does not exist |
| -5 | EIO | object unreadable or failing its checksum and not repairable, or the pool carries the EIO flag and the request lacked the SUPPORTSPOOLEIO bit (with the bit set the OSD stays silent and the client must fail the request itself) |
| -11 | EAGAIN | not primary or unreadable on a replica; the client resubmits (3.5) |
| -17 | EEXIST | exclusive create on an existing object |
| -22 | EINVAL | bad op arguments, invalid snapshot context, write with a snapid other than NOSNAP, empty object name, PARALLELEXEC flag, WRITE whose `extent.length` differs from the supplied data (`PrimaryLogPG.cc:2043-2048,2114-2118,2176-2183,6743-6746,8984-8987`) |
| -23 | ENFILE | read of an object marked lost (`PrimaryLogPG.cc:2519-2526`) |
| -27 | EFBIG | range beyond `osd_max_object_size` |
| -28 | ENOSPC | pool full and the request carried FULL_TRY (`PrimaryLogPG.cc:9013-9025`); also possible from the object store when a device is full |
| -36 | ENAMETOOLONG | object name or locator key longer than 2048 bytes, or namespace longer than 256 bytes (defaults of `osd_max_object_name_len` / `osd_max_object_namespace_len`, `global.yaml.in:3791-3801`; checks at `PrimaryLogPG.cc:2092-2113`) |
| -61 | ENODATA | xattr absent |
| -85 | EOLDSNAPC | ORDERSNAP set and the snapshot context is older than the object's |
| -90 | EMSGSIZE | write message larger than `osd_max_write_size` |
| -95 | EOPNOTSUPP | unknown class or method, or op unsupported on this pool type |
| -108 | EBLOCKLISTED | this client's address is on the blocklist (`PrimaryLogPG.cc:2127-2132`); the session is permanently unusable |
| -122 | EDQUOT | pool full because of a quota (pool flag FULL_QUOTA) and the request carried FULL_TRY (`PrimaryLogPG.cc:9023-9024`) |

A key whose OSD cap is empty never reaches the op stage: the OSD refuses the connection's authorizer with AUTH_BAD_METHOD
(method 2, result -13 EACCES, allowed methods [2], allowed modes [1, 2]; 24 attempts in the capture) and the stock client keeps
opening new connections; no MOSDOp is ever sent. So the "hang" of such a client is not a silent drop of operations by the OSD
**[confirmed: x-t0-noosd, osdop_check.py]**.

Pool full WITHOUT FULL_TRY / FULL_FORCE: the OSD answers `-EAGAIN` internally, and the execution path then drops the
request without sending any reply (`PrimaryLogPG.cc:9026-9029`, `:4281-4285`); the client sees silence. ENOSPC and
EDQUOT are Linux numbers (28, 122); this note did not trace every other source of ENOSPC.

### 2.12 Transaction ids

The `tid` in the msgr2 header identifies an operation inside one client instance. It is assigned once, when the operation is
first submitted, from a counter starting at 1 that only increases (`Objecter.cc:2562-2563`), and is **kept** across
resends. It becomes part of the request id the OSD stores in its PG log for duplicate detection (3.6). A tid is **replaced
by a fresh one** only in two cases: a redirect reply and an `EAGAIN` reply (3.5).

---

## 3 Client procedure

### 3.1 Prepare an operation

Input: pool id, object name, locator key / namespace (normally empty), op list, snapshot id for reads or snapshot
context for writes, message class (read or mutate).

1. Check the pool (OSDMap note, 3.7): refuse a missing pool, an erasure pool, a pool with `FLAG_EIO`, a pool with cache
   tiers (OSDMap note 3.7 step 1 says to refuse `tier_of` / `read_tier` / `write_tier`). The reference library redirects
   operations to a tier pool unless IGNORE_OVERLAY is set (`Objecter.cc:2985-2995`); a minimal client rejects such pools.
2. Compute the hash (2.2), the effective PG and the acting primary from the current OSDMap. If there is no primary
   (PG has no up primary) the operation waits "homeless": ask for a newer map and resend when one arrives
   (`Objecter.cc:2555-2559`).
3. Allocate the tid (once).
4. Put the operation on a per-OSD list keyed by tid (the reference library keeps a session per OSD id, with its map of
   in-flight operations, `Objecter.cc:3198-3213`).

### 3.2 Build and send

For each transmission of the operation (first send and every resend, `Objecter.cc:3370-3427,3429-3500`):

1. If the target PG changed since the last build, rebuild `pgid` (`:3461-3467`).
2. If a backoff of this OSD session covers the operation (2.10 ordering), do not send; keep it queued (3.7).
3. Fill the body of 2.3: `osdmap_epoch` = current epoch; flags (2.4) plus RETRY if this is not the first transmission;
   `retry_attempt` = number of earlier transmissions of this operation (0 first); `snapid` and the snapshot context
   (2.3 and 3.9); `mtime` (now for mutating operations).
4. Set msgr2 header: type 42, version 9, compat 3, priority 63, tid. Front = the body, data = concatenated op input.
5. Send on the connection to the primary OSD. The connection policy is a lossy client (`RadosClient.cc:256`): when it
   breaks, nothing is retransmitted by the messenger, so everything in flight is lost and must be resent by this layer.

### 3.3 Process a reply

Match the reply to an in-flight operation by tid, using the connection it arrived on (`Objecter.cc:3558-3586`); a reply for
an unknown tid is dropped (stray). Then (`Objecter.cc:3553-3833`), in this order:

1. If the reply's `retry_attempt` is non-negative and differs from the operation's latest attempt (attempts sent minus 1),
   drop it as stale (`:3612-3627`).
2. If `do_redirect`: see 3.5. (A minimal client may instead fail the operation with a clear error, since it rejects pools
   that cause redirects.)
3. If `result == -EAGAIN`: see 3.5.
4. Otherwise the operation is complete. Cut the data segment into per-op outputs (2.9), look at `result` and each `rval`,
   record `user_version` if the caller wants it, and remove the operation from the in-flight list. The per-op `rval` is
   delivered to the caller after errno translation; `result` below zero fails the whole message.

### 3.4 Map changes

Whenever a new OSDMap epoch is adopted (`Objecter.cc:1078-1206,1346-1401`):

1. For every in-flight operation recompute its target. If the pool no longer exists, wait until a map at least as new as the
   one in which the deletion was seen, then fail the operation with `ENOENT` (`:1594-1642`).
2. The operation must be resent (to the same or to a different OSD) if: the primary OSD changed or the PG id changed;
   the pool's `pg_num` changed in a way that splits or merges this PG; the pool's `last_force_op_resend` equals the new epoch;
   the client skipped one or more epochs (a gap while catching up); or the cluster / pool "full" state flipped for an
   operation that respects it (`:1143-1160`, `Objecter.cc:3084-3188`; doc `rados-client-protocol.rst`
   "Resends"). It is not resent if only a replica changed. "Primary changed" here includes the acting set turning empty or
   non-empty and the primary's role index changing (`OSDMap.cc:3217-3233`, `Objecter.cc:2800-2818,3084-3089`). The reference
   also has a fuller "new placement interval" test (acting / up sets, `size`, `min_size`, `pg_num_pending`, bitwise-sort and
   recovery-delete flags, peering crush parameters, `Objecter.cc:3037-3078`), but it is only switched on for lingering
   (watch) operations (`Objecter.cc:3303,5149`), not for ordinary ones, so an ordinary I/O is not resent for those reasons.
3. The reference library also prunes, in every in-flight operation's snapshot context, snapshots that the new map says have
   been removed (`Objecter.cc:2917-2943,1142`).
4. Resend in ascending tid order (`Objecter.cc:1374-1401`, `:2133-2151`). The tid, the request id and the snapshot
   context are kept; `retry_attempt` increases.
5. Operations whose primary is gone (OSD down or removed) move to the "homeless" list until a map provides a new primary.
   The reference library also closes the session to an OSD the new map marks down or whose address changed
   (`Objecter.cc:1301-1314`).
6. The reference client also holds operations back (does not send them) while the map carries the cluster-wide
   PAUSERD flag (reads) or PAUSEWR flag (writes), while the pool or cluster is full for an operation that respects it,
   and while its epoch is below an "epoch barrier" it was told about (`Objecter.cc:2820-2830`). A minimal client should
   decide explicitly whether to honour PAUSERD / PAUSEWR (the reference does).

An OSD can also push a map to a client on the OSD connection: it sends the missing incrementals (message type 41,
`CEPH_MSG_OSD_MAP`) when it sees an older epoch in a request or drops a request for a PG it no longer serves
(`OSD.cc:7555-7599,9926,11340`). The client must accept and process MOSDMap on OSD connections exactly as on the
monitor connection (OSDMap note 3.2).

### 3.5 Resend triggers and rules, summarised

| Trigger | Action | Tid | Source |
|---|---|---|---|
| Connection to the OSD reset (lossy session lost) | open a new session to the same OSD's current address, clear this session's backoffs, resend all its in-flight operations | kept; `retry_attempt` + 1 | `Objecter.cc:4710-4741`, `:2124-2151` |
| New map moves the operation (3.4) | resend to the new target | kept | `Objecter.cc:1346-1401` |
| Reply with `result == -EAGAIN` | forget this attempt, clear BALANCE/LOCALIZE bits, recompute the target from scratch (forget the cached PG), resubmit as a **new** operation. The per-operation attempt counter is NOT reset, so the new message already carries a non-zero `retry_attempt` and the RETRY flag | **new tid** | `Objecter.cc:3662-3676`, `:3400` |
| Reply with `do_redirect` | replace locator and (if non-empty) object name by the redirect, add REDIRECTED + IGNORE_CACHE + IGNORE_OVERLAY, resubmit (attempt counter again not reset) | **new tid** | `Objecter.cc:3633-3651` |
| MOSDBackoff UNBLOCK | resend every in-flight operation of that PG whose position lies in the unblocked range, including ones sent earlier and dropped by the OSD | kept | `Objecter.cc:3879-3914` |
| Operation older than 10 s (`objecter_timeout`) | **no resend**; the reference library asks the monitor for a newer map and pings the OSD; ticks every 5 s (`objecter_tick_interval`) | n/a | `Objecter.cc:2200-2302`, `global.yaml.in:2410-2422` |
| OSD receives an operation it considers misdirected (not primary, PG mismatch) | **no reply at all** (the OSD drops it; `osd_debug_misdirected_ops` is false by default); the client recovers only through the map-change rule | n/a | `PrimaryLogPG.cc:2017-2026,2069-2073`, `OSD.cc:1651-1655`, `global.yaml.in:3318-3322` |
| Pool or cluster is "full" in the map | the reference library holds back operations that respect fullness (3.8) | n/a | `Objecter.cc:2820-2830`, `Objecter.h:1908-1912` |
| Write reaches an OSD whose pool is full, no FULL_TRY / FULL_FORCE | **no reply** (dropped); the client recovers only by the map (full flag clears and the held operations resubmit) | n/a | `PrimaryLogPG.cc:9013-9029`, `:4281-4285` |

Notes on the "new tid" cases: a resend with a **kept** tid lets the OSD recognise the second copy of a write as a duplicate
(3.6). An `EAGAIN` or redirect reply is returned before execution, so the earlier attempt did nothing and a fresh tid is safe.

The OSD silently dropping misdirected or stale-epoch requests means there is nothing in the protocol that tells the
client "go elsewhere". A client must therefore keep its map current (subscription) and have its own policy for operations
that stay unanswered (open question 6.6).

### 3.6 Duplicate detection (why the tid, the incarnation and the connection identity matter)

For any message with a mutating op the OSD looks up the request id (`client.<global id>`, `inc`, `tid`) in the PG log
before executing (`PrimaryLogPG.cc:2274-2301`). If it is found and committed it replies with the stored result; if it is
found and not yet committed it queues the reply for commit. This is what makes retransmitting a write after a connection
loss safe. Requirements that follow:

- Keep the tid across resends; never reuse a tid within the lifetime of a client identity (global id + incarnation).
- Keep `client_inc` (and `reqid.inc`) constant across resends.
- The identity part (`client.<global id>`) comes from the authenticated connection, not from the message; a client that
  re-authenticates and obtains a new global id loses duplicate protection for operations from before. Do not resend a
  completed-but-unacknowledged write across a re-authentication unless a duplicate write is acceptable
  (open question 6.5).
- `retry_attempt` only helps the client discard stale replies (3.3 step 1); it is not part of duplicate detection.

### 3.7 Backoff procedure (client side)

The OSD sends backoffs only to connections that advertise the RADOS_BACKOFF feature (`PrimaryLogPG.cc:2028-2029,1871`).
That is bit 21, and bit 21 is shared with RESEND_ON_SPLIT and SERVER_LUMINOUS (`ceph_features.h:114-116`). The recommended
advertised mask (`msgr2.md` 4.4) includes it, and a client cannot decline backoffs while keeping the split-aware routing
path of the OSD (`OSD.cc:7617-7623,7730-7738`). So a minimal client **must** handle MOSDBackoff.

1. On BLOCK (op 1) (`Objecter.cc:3857-3877`): store the entry in this OSD session, keyed by `pgid` then `begin`, also indexed by
   `id`. Immediately send ACK_BLOCK (op 2) with the same `pgid`, `id`, `begin`, `end` and the **same `map_epoch` as the BLOCK
   message** (the OSD uses it to discard the ack if the PG split in between), priority 63.
2. Before sending any operation to this session (3.2 step 2) test whether its position (2.10 ordering) lies in a stored
   entry's range (`begin <= pos < end`, or `pos == begin` when `begin == end`). If so, hold it back.
3. On UNBLOCK (op 3) (`Objecter.cc:3879-3920`): look the entry up by `id`; remove it. The range in the UNBLOCK may be smaller
   than the stored one (the PG may have split); the reference library tolerates a mismatch and removes the entry anyway.
   Then resend every in-flight operation of this session on that `pgid` whose position is inside the UNBLOCK range
   (re-checking other backoffs). Operations already sent earlier are included: the OSD may have dropped them.
4. When the session or connection is lost, discard all its backoffs (`Objecter.cc:2129-2131`).
5. While a backoff is in force the OSD silently drops operations in the range even if the client forgot (`Session.cc:88-106`).
6. Which backoffs happen with default settings: object-level backoff for an unfound object (`osd_backoff_on_unfound` true);
   PG-wide backoff when the PG is down, incomplete, or peered but not yet active (`PrimaryLogPG.cc:1880-1900`); degraded and
   peering backoffs are off by default (`global.yaml.in:3231-3246`).

OSD-side behaviour that the client may rely on (prose confirmation in `rados-client-protocol.rst`): the OSD itself may
still accept covered operations between sending BLOCK and receiving the ack, afterwards it considers receiving one a bug.

### 3.8 Full pools

If the map marks the cluster or the pool full, the reference library holds back mutating operations that "respect full"
(operations with WRITE or RWORDERED and without FULL_TRY / FULL_FORCE) until the flag clears (`Objecter.cc:2820-2830`,
`Objecter.h:1908-1912`). The OSD also discards write-ordered operations stamped with an epoch older than its last "marked
full" epoch, silently, unless they carry FULL_TRY or FULL_FORCE (`PrimaryLogPG.cc:2134-2152`). For a block device the user
likely prefers an I/O error to a hang; setting FULL_TRY on every write turns "full" into an `ENOSPC` (or `EDQUOT` when the pool
flag says quota) reply, but only for operations that would grow the pool (bytes or object count above zero, `PrimaryLogPG.cc:9013-9025`);
without FULL_TRY a write that would grow a full pool is dropped without a reply (3.5). This is a choice (open question 6.7).

### 3.9 Which operations carry a snapshot context

The OSD decides read versus write from the op codes and, for `CALL`, from the registered flags of the class method
(`osd_op_util.cc:84-98,120-124,171-205`), never from the message's READ/WRITE bits. For anything that may write:

- The snapshot context is `snap_seq` plus `snaps` (descending list of snapshot ids that exist, newest first). It must be
  valid: `snap_seq` at most CEPH_MAXSNAP, `snaps[0] <= snap_seq`, and strictly descending (`snap_types.cc:99-117`). An invalid
  context is answered with `-EINVAL` (`PrimaryLogPG.cc:8984-8987`).
- Messages that need it: any message containing WRITE, WRITEFULL, ZERO, TRUNCATE, DELETE, CREATE, SETALLOCHINT, WRITESAME,
  setxattr, omap writes, or a `CALL` to a mutating method. For DELETE and for WRITE onto an object that has older snapshots,
  a stale or empty context means the OSD creates no clone, and snapshot data is silently overwritten. Context validity also
  forbids a snapshot id of 0 being followed by another entry (`snap_types.cc:99-117`). The server does not
  detect it unless ORDERSNAP is set (`PrimaryLogPG.cc:4223-4229`).
- Image data objects: the image's current snapshot context (obtained from the RBD header by the RBD note's method). Header,
  id and directory objects: a plain librados I/O context starts with an empty write context (seq 0, no snaps,
  `IoCtxImpl.h:38`), so metadata calls made through it carry none; I did not trace every librbd call site.
  **Capture: all 878 messages to header, directory, id, trash, info, mirroring and object-map objects carry `snap_seq` 0 and no
  snapshots; every write to a data object carries exactly the context the same session read with `get_snapcontext` (420 of
  420). But those images had no snapshots, so the capture cannot tell "empty context" from "the image's context" for header
  calls: still [unverified].**
- Reads ignore `snap_seq` / `snaps`; reads of an image snapshot use `snapid` = that snapshot's id.
- In pool-snapshot mode the OSD substitutes the pool's own context unless ENFORCE_SNAPC (`PrimaryLogPG.cc:4211-4221`); an RBD
  pool uses self-managed snapshots (`snaps.rst` lines 7-27). A client should check the pool flags (POOL_SNAPS is bit 14, `osdmap.md` 2.7.2) and refuse a
  pool in pool-snapshot mode.
- A write whose `snapid` is not NOSNAP is rejected (`-EINVAL`).

### 3.10 Ordering

- Resends are made in tid order and a map change re-submits in tid order, which preserves the order the application issued
  writes to the same object (`Objecter.cc:1374-1401,2133-2151`).
- The OSD orders operations per object. A read is not ordered after an uncommitted write unless RWORDERED is set; a client
  that issues a read right after a write completed (ONDISK reply) always sees it. A client that must have read-after-
  write-in-flight semantics should wait for the write's reply.

### 3.11 Typical sequences

Read of 64 KiB at offset 0x1000 of data object `O` in pool `P`, head: hash = hash(O), `pgid` = fold, `flags` 0x08400014, one op
SPARSE_READ(offset 0x1000, length 0x10000), `snapid` NOSNAP, empty snapshot context, `retry_attempt` 0. Reply: result 0,
output = extents + data. Fill the user buffer with zeros, then copy each extent's bytes to `extent.offset - 0x1000`.
Reply `-ENOENT` = all zeros (image without parent).

Write of 4 KiB at 0x2000: flags 0x08400024, ops [SETALLOCHINT (optional), WRITE(offset 0x2000, length 0x1000, input 4096
bytes)], snapshot context of the image, mtime = now. Reply: result 0, no output.

Open the header object: CALL(class, method, args) read path messages, each independent.

---

## 4 Minimal-client choices

### 4.1 Must support

- Encode MOSDOp version 9 exactly (2.3), including the zero blkin trace and the 7-byte otel field, `reqid.inc == client_inc`,
  flags per 2.4, 38-byte op records, input data layout per 2.5.
- Decode MOSDOpReply version 8 (2.9) including `do_redirect` (at least detect it and fail clearly) and the 64-bit `flags`.
- Ops: READ, SPARSE_READ, STAT, WRITE, WRITEFULL, ZERO, TRUNCATE, CREATE (EXCL), DELETE, CALL, OMAPGETVALS, OMAPGETVALSBYKEYS,
  GETXATTR. SETALLOCHINT only if wanted.
- tid allocation and in-flight table; stale-reply drop by `retry_attempt`; resend rules (3.5); `EAGAIN` resubmission.
- MOSDBackoff block / ack / unblock (3.7).
- Snapshot context on every mutating message (3.9) and the validity check of the context before sending.
- MOSDMap from OSD connections (3.4).
- Error mapping per 2.11 and treatment of `EBLOCKLISTED` as fatal for the session.
- Bounded memory: in-flight operation count and bytes (the reference library caps at 1024 operations and 100 MiB,
  `global.yaml.in:2423-2434`).

### 4.2 May skip

| Feature | Why it can be skipped | Notes |
|---|---|---|
| tracing (blkin / otel) | fields are fixed zeros | still must be present |
| explicit `reqid` name / tid | the OSD builds it from the connection | only proxies set it |
| BALANCE_READS / LOCALIZE_READS | primary-only reads are always valid | |
| RETURNVEC | not needed for RBD | |
| watch / notify, linger ops, PG ops (listing) | the immutable-while-attached v1 profile does not need them | exclusive-lock and header watch are in the RBD note |
| CMPEXT, WRITESAME, CHECKSUM, MAPEXT | librbd's optional features | |
| ORDERSNAP, ENFORCE_SNAPC, RWORDERED | not used by librbd by default | |
| Redirect following | only arises with cache tiering / redirect pools | reject those pools, fail on a redirect reply |
| Messages version 1..8 | v9 is what a v20.2.5 server wants | v8 is the same minus 7 bytes if Reef is ever targeted |
| Per-op FADVISE flags | hints | send 0 |
| SETALLOCHINT | performance only | librbd sends it with every write; skipping does not change correctness |

### 4.3 Must reject (clear error)

- Erasure-coded pool, pool with tiers (`read_tier` / `write_tier` / `tier_of`), pool in pool-snapshot mode, pool with the EIO flag.
- Reply versions other than 8; reply with `num_ops` different from the request; data segment length not equal to the sum of
  `payload_len`.
- A SPARSE_READ reply whose extents are not strictly ascending, overlap, lie outside the requested range, or whose lengths
  do not add up to the data length (defensive, 6.4).
- Any MOSDBackoff for a PG the client has no operation on is harmless but must not grow state without bound; cap the table.
- Object names or locator keys above 2048 bytes, namespaces above 256 bytes (server defaults, `global.yaml.in:3791-3801`;
  checks at `PrimaryLogPG.cc:2092-2113`), and an empty object name, before sending.

### 4.4 Feature bits that matter to this note

The set to advertise is in `msgr2.md` 4.4 (`0x3f07fffffffdffff`). What each bit does to this note's messages:

| Bit | Name | Effect |
|---|---|---|
| 8 | OBJECTLOCATOR | sender may use MOSDOp v6+ |
| 9 | PGID64 | the OSD sends the modern reply, else v1 |
| 21 + 57 | RESEND_ON_SPLIT (also RADOS_BACKOFF, SERVER_LUMINOUS) | the OSD routes by the `pgid` in the message (else it re-derives it) and sends backoffs |
| 49 + 57 | SERVER_SQUID | MOSDOp v9 (else v8) |
| 50 + 57 | SERVER_TENTACLE | the OSD does not "repair" the shard in `pgid` for EC pools (replicated: no effect) (`OSD.cc:7628-7631,7721-7729`) |
| 56 | NEW_OSDOP_ENCODING | MOSDOp v7+ |
| 58 | NEW_OSDOPREPLY_ENCODING | the OSD sends reply v8, else v6 |

HAVE_FEATURE tests need both the bit and the incarnation marker bit 57 where noted (`ceph_features.h:37-39`).

---

## 5 Test vectors needed

### 5.1 Derived example (computed from the layout in 2.3 by hand, not captured)

One READ of 4096 bytes at offset 0 of object `a`, pool 1, hash `0x12345678`, effective PG seed `0x38` (pg_num 64),
epoch 5, flags `0x08400014`, client_inc 0, no snapshot context. Front segment, 217 bytes:

```
spg_t        01 01 12 00 00 00  01  01 00 00 00 00 00 00 00  38 00 00 00  ff ff ff ff  ff
hash         78 56 34 12
epoch        05 00 00 00
flags        14 00 40 08
reqid        02 02 15 00 00 00  00  00*8 (num)  00*8 (tid)  00*4 (inc)
blkin        00 * 24
otel         01 01 01 00 00 00 00
client_inc   00 00 00 00
mtime        00 00 00 00 00 00 00 00
oloc         06 03 1c 00 00 00  01 00 00 00 00 00 00 00  ff ff ff ff  00 00 00 00  00 00 00 00  ff ff ff ff ff ff ff ff
oid          01 00 00 00 61
num_ops      01 00
op           01 12  00 00 00 00  00*8 (offset)  00 10 00 00 00 00 00 00 (length 4096)  00*8  00*4  00*4 (payload_len)
snapid       fe ff ff ff ff ff ff ff
snap_seq     00 * 8
snaps        00 00 00 00
retry        00 00 00 00
features     00 * 8   (a real client writes the negotiated connection feature word here, see 2.3 field 18)
```

Data segment: empty. Header: type 42, version 9, compat 3, priority 63, tid = whatever. **[confirmed: layout and length.** `osdop_check.py` decodes all 1,935 captured fronts with the layout of 2.3 and no trailing
byte, and re-encodes the 18 captured vectors in `harness/vectors/osdop` byte for byte with an encoder written from 2.3; the
front of a one-op READ with an 8-byte object name is 224 bytes, which is 217 + 7 as the layout predicts. The values of this
example are synthetic (vector 19 rebuilds it); a captured equivalent is vector 03.**
Reply example: see vector 03 (result 0, one op, data = the object bytes) and vector 04 (`-ENOENT`).

### 5.2 What to capture on the test cluster (status after the first capture round: items 1 and 3 done; 2, 4 and 5 done in part (no holes in a sparse read, no mutating
CALL with output, no missing omap key); 6 to 10 not done) (crc mode, `ms_client_mode = crc` and `ms_mon_client_mode = crc` on the capturing client, keys scrubbed per CONTRIBUTING rule 4)

Use the stock `rbd` / `rados` command line against a throw-away replicated pool, with a client in crc mode so the frames are
readable, then decode the front segment against this note. Each capture also confirms the related structure with
`ceph-dencoder` where the type exists (`MOSDOp`, `MOSDOpReply`, `spg_t`, `pg_t`, `hobject_t`, `object_locator_t`,
`osd_reqid_t`, `request_redirect_t`, `eversion_t`, `SnapContext` are registered in `src/tools/ceph-dencoder/`; `MOSDBackoff`
is not).

1. `rados -p P put obj file` and `rados get`: one WRITEFULL, one READ; check flags, hash, epoch, `features`, reqid, mtime.
2. `rbd write` / `rbd read` on a test image: SETALLOCHINT + WRITE composition, SPARSE_READ request and reply with holes (write
   two small extents into an empty object, read the whole object).
3. STAT reply layout for an existing and a missing object; an ENOENT read reply (result -2, ops echoed, data empty).
4. A CALL read (e.g. the image size query) and a CALL write: confirm the outputs are dropped for a mutating message.
5. OMAPGETVALS paging (an object with more than 1024 keys) and OMAPGETVALSBYKEYS with a missing key.
6. Resend: kill and restart the primary OSD with a write in flight; confirm RETRY flag, `retry_attempt` 1, same tid, and
   the OSD answering the duplicate.
7. Backoff: set `osd_backoff_on_peering = true` on the test cluster and trigger peering (mark an OSD out) while I/O runs;
   capture BLOCK, ACK_BLOCK, UNBLOCK; also a PG-wide block with default settings by stopping a PG's OSDs.
8. Misdirected: send an operation to a non-primary OSD and confirm there is no reply (silence) and no connection reset.
9. A write with a deliberately older snapshot context on an image with a snapshot, with and without ORDERSNAP, to see what the OSD
   does (no error expected without the flag, EOLDSNAPC with it).
10. A write with `reqid.inc != client_inc` is **not** to be tried on a shared cluster (it asserts the OSD); try it only on a
    disposable cluster if at all.

---

## 6 Open questions

1. **Segment placement.** Which msgr2 segments carry the front and data parts for MOSDOp (front/data, middle
   unused, per the source). **[confirmed, see 2.1]** (`data_off` is resolved: the OSD never reads it, send 0, 2.1.)
2. **The `features` field of MOSDOp.** The encoder writes the negotiated connection word (2.3); the OSD falls back to the
   connection word when the field is 0, but I did not exercise a zero on a live cluster. **[confirmed: the stock client sends the negotiated word, see 2.3]** A zero
   could only be tested with our own client: **[confirm on capture]**
3. **Reef and Squid.** I did not research older releases. The code shows v8 for peers without the SERVER_SQUID bit; other
   differences would need their own read.
4. **Sparse-read extent sanity.** Whether the OSD can ever return an extent outside the requested range, overlapping or
   unsorted extents, or total length different from the data length. In the replicated path the extents come from the object store's
   allocation map and are re-encoded (`PrimaryLogPG.cc:5978-6017`). A client should validate, but exact bounds need a capture.
5. **Duplicate protection across re-authentication.** Whether a client that reconnects with a new global id can safely resend an
   unacknowledged write (it will not be recognised as a duplicate). Needs a design decision in the RBD note (exclusive-lock) and the
   cephx / monitor note (global id lifetime).
6. **Time-out policy.** Ceph itself does not resend on timeout; the OSD silently drops misdirected and stale-epoch operations. The
   reference library only asks for a newer map and pings (`Objecter.cc:2200-2302`). What a boot-time disk driver should do when an
   operation stays unanswered (resend on a timer? reconnect? fail the I/O?) is a project design question. The OSD de-duplicates
   resent writes with the same tid, so a timer-based resend of a write with the same tid is safe from the OSD's view
   **[confirm on capture]**: not exercised, no resend, RETRY flag or non-zero `retry_attempt` occurs in the capture set (the
   only fault injected was a monitor restart, which does not touch OSD connections), and it needs our own client to send a
   duplicate.
7. **Full pools.** Whether to set FULL_TRY by default. Source says: with FULL_TRY a growing write gets ENOSPC / EDQUOT; the
   fail-safe full check applies only without FULL_TRY (`PrimaryLogPG.cc:2156-2160`), the older-epoch discard is also skipped
   with FULL_TRY (`:2145-2152`). **[confirm on capture]** on a pool made full by a quota: not exercised, no pool was full. The stock tools do set the bits
   themselves: FULL_TRY on `rbd` metadata calls and `rbd rm` deletes, FULL_FORCE on `rados rm` (2.4).
8. **Snapshot context staleness.** librbd keeps its context fresh via the exclusive lock and header watch. A client that skips the
   watch must either refresh the context itself (re-read the header before the first write after a long idle, or periodically) or
   run on a snapshot-free image. The OSD does not enforce freshness unless ORDERSNAP is set, and a stale context silently loses snapshot
   data. Cross-link with the RBD note's exclusive-lock and watch decisions.
9. **Backoff range comparison for PG-wide ranges.** The bit-reversed hash ordering is documented in 2.10, but the PG-wide begin / end values
   are produced by helper functions I did not read (`get_hobj_start` / `get_hobj_end`). The client only needs to compare, so this
   should be enough; confirm with a captured PG-wide backoff. **[confirm on capture]**: not exercised, no MOSDBackoff occurs in
   the capture set (the only message types on OSD connections besides 42 and 43 are 52 messages of type 44, version 3, from the
   OSD, outside this note).
10. **ENOSPC / EDQUOT as `result` or `rval`.** The OSD produces them in the transaction-preparation step (2.11), which makes them the
    message `result`; the matching per-op `rval` was not checked. **[confirm on capture]**: not exercised, no ENOSPC / EDQUOT in the capture.
11. (resolved) namespace limit is 256 bytes by default (2.11, 4.3).
12. **Header-object snapshot context.** A plain librados I/O context starts with an empty write context, but I did not trace every
    librbd call site that targets header / directory objects (3.9). **[unverified]**: the capture is consistent (all 878 such
    messages carry the empty context) but those images had no snapshots, see 3.9.
13. **OSD pushes of MOSDMap.** Whether a minimal client may ignore maps pushed on the OSD connection and rely only on the monitor
    subscription. The reference library processes both; ignoring pushes was not analysed.
14. **ZERO rewritten to TRUNCATE in the reply.** The OSD edits the op record it echoes (2.7), so the reply op code can differ from
    the request. Confirm on a capture that nothing else in the echoed record changes (for example `extent.length`) for ZERO, TRUNCATE
    and a zero-length WRITE. **[confirm on capture]**: not exercised, the capture has no ZERO, TRUNCATE or zero-length WRITE (no
    `rbd discard`, `rbd resize` or `rados truncate` was run); the only ops whose echoed record was compared are in 2.7 (union
    unchanged for READ except `extent.length`).
15. **SPARSE_READ with `length == 0` on the replicated path.** The code leaves length at 0 and calls the object store's extent
    lookup with it (`PrimaryLogPG.cc:5947-5981`); what that returns was not checked. A client never needs to send it.
    **[unverified]**: not exercised, the stock client never sends length 0 with SPARSE_READ.
16. **Backoff priority.** The reference client copies the op priority (63) into the ACK_BLOCK message, with a comment that it must match
    the ops (`Objecter.cc:3873-3874`); whether a different value changes OSD behaviour was not checked. **[unverified]**: not exercised (no backoff occurred).


### Corrections after capture

What the capture changed in this note (each item is also corrected in place above):

1. 2.1: the reply's `data_off` is 0 in every reply, including reads at a non-zero offset; the source reading said it carries
   the offset of the first read op.
2. 2.9 / 2.7: not every reply has ACK. A reply produced before execution (whole-message `-ENOENT`, `-EPERM`) echoes the request
   flags and has no ACK; only replies of executed requests have ACK | ONDISK, except the answer to a resent duplicate write, which may have ONDISK alone (see 2.9).
3. 2.4: "librbd adds no extra flags" holds for data reads and writes only. The `rbd` command adds FULL_TRY to metadata calls
   and `rbd rm` deletes, and `rados rm` adds FULL_FORCE to its DELETE.
4. 2.5: librbd sends SETALLOCHINT with the FAILOK per-op flag (0x2), and the FADVISE "sequential" hint (0x8) on WRITE and
   SPARSE_READ of a sequential bench; "a minimal client uses only EXCL" is the minimum, not what the stock client does.
5. 2.9: `bad_replay_version` is not a dead zero field; it carries (`user_version`, write epoch). Still ignorable.
6. 2.9: `user_version` of a pre-execution `-ENOENT` is 0 (no "floor value").
7. 2.11: a key with an empty OSD cap is refused at authentication (AUTH_BAD_METHOD, -13); the operation hang seen with such a key
   is the client retrying connections, not the OSD dropping a MOSDOp.
8. 2.6 / 2.7: codes `0x220F`, `0x1206`, `0x1207`, `0x1209` occur in real librbd traffic and are not covered; OMAPGETKEYS layout
   recorded (`u32 n`, strings, `bool truncated`).
9. For the msgr2 note (not edited here): the 41-byte header's `flags` byte is 3 (COMPLETE | NOCRC) on every captured message
   in both directions, in crc and secure mode, where `msgr2.md` 2.9 says the encoder sets exactly 1.
10. For the crush note (not edited here): `ceph osd map` with an object name outside the Basic Multilingual Plane (the lab's
    emoji name) reports the hash of the CESU-8 form (each UTF-16 surrogate encoded as three bytes), because the name passes
    through the monitor's JSON path; the other 2,193 names, including the 80 with a namespace, hash exactly as in 3.1 of that note.
11. Capture defects, not note errors: `k1-rbd-bench-default` and `k1-sec-rados-big` have packets missing from the pcap (the
    receiver acknowledged them). The checker reports them as warnings and skips what lies behind a hole.

Confirmed without change: header version / compat / priority of both messages, the 41 / front / empty / data segments, every
field of MOSDOp v9 in the order of 2.3 (also the 24-byte and 7-byte trace fields, `reqid`, `client_inc`, locator v6 / compat 3),
the placement hash and pg seed (against 2,194 `ceph osd map` results), the features word, the 38-byte op record, the data
segment cut by `payload_len`, WRITE `extent.length` = payload, CALL lengths, reply v8 layout including the 64-bit flags, the
per-op `rval` and result rules above, STAT / READ / SPARSE_READ / OMAP / CALL outputs, the EPERM reply, tids strictly
ascending on every connection (88 of 159 connections start at 1, the rest where the client's counter stood), message `seq`
1..n per connection, one reply per request, secure-mode messages identical in
layout to crc-mode ones.

Still open, with the reason the capture could not settle it: priority values other than 63 (needs our own client); zero
`features`, zero omap union, resend with the same tid, `-EAGAIN`, redirect (needs fault injection or our own client); full pools,
backoff, ENOSPC / EDQUOT, ZERO / TRUNCATE rewrite, empty and multi-extent SPARSE_READ, SPARSE_READ length 0, snapshot-context of
header calls on an image with snapshots (not triggered by the stock commands that were run).

---

## 7 Licensing questions

- `src/include/rados.h` is listed as LGPL-2.1 or LGPL-3 (`COPYING:36-38`), except `ceph_stable_mod()`, which is public domain.
  The op codes, flag values, record layout and error numbers in this note are protocol constants I wrote out as numbers and field
  tables, not copied text. Open question for the project: whether the MIT core may use Ceph's symbolic names (`CEPH_OSD_OP_*`,
  `CEPH_OSD_FLAG_*`) as identifiers, or should rename them. This note quotes the Ceph names only as references.
- The op code table (`rados.h:247-373`) is generated by a macro; I listed only the ops a minimal client needs and computed the numbers
  from the mode / type / number scheme. The remaining codes should not be copied wholesale into the core.
- The stable-modulo formula (2.2) is described in words; the function is public domain per `COPYING:36`. The rjenkins string hash
  that fills the request `hash` field is in `src/include/ceph_hash.cc`, listed as public domain (`COPYING:32-34`); the osdmap note
  owns the algorithm.
- The `MOSDOp` / `MOSDOpReply` field orders, struct-version numbers and the 38-byte op record in this note are interface facts; no
  Ceph code, comments or tables were copied.
- `doc/*` is CC-BY-SA-3.0 (`COPYING:21-23`). I used `doc/dev/rados-client-protocol.rst` and `doc/dev/osd_internals/snaps.rst` only
  to confirm facts and rewrote them; if verbatim text is ever wanted in the repository, attribution and share-alike apply.
- The Objecter logic in section 3 is described, not transcribed. If the core mirrors its structure closely (for example the session /
  in-flight table layout), a reviewer should confirm it is an independent design.
