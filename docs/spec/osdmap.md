# OSDMap and OSDMap::Incremental: the client subset

Status: draft, Phase 0 spec note. Written from source reading (every `path:line` reference
was re-opened and re-checked against the v20.2.5 tree in a second review pass), then checked against the
lab capture set by an independent checker written from this note alone, not from Ceph source
(`harness/tools/osdmap_check.py`; vectors and provenance in `harness/vectors/osdmap/README.md`). Items still
needing a capture are marked **[confirm on capture]**, items that could not be pinned in source are marked
**[unverified]**, items the lab settled are marked **[confirmed: ...]**. The lab is one tentacle cluster
(1 mon, 3 OSDs, IPv4 only), captured in two rounds: epochs 1 to 92 (first round), then epochs 666 to 925 and a live
comparison run at epochs 2150 to 2550 (second round: `harness/vectors/public/mapb/`, `harness/tools/map_oracle_lab.sh`,
and the client of `core/` against the real monitor). Section 6, "Corrections after capture", lists what changed in this
note in each round and what the lab cannot settle.

All `path:line` references are relative to the Ceph tree root at tag v20.2.5
(commit ed27c686770872022f4c1de04f6b0ac5d5384ded). Line numbers are from that tree only.

---

## 1 Scope and sources

### 1.1 Scope

Goal: let an implementer write a minimal RADOS client (never a server) that

1. receives the cluster map from a monitor,
2. decodes the parts it needs (fsid, epoch, pools, per-OSD state / weight / address,
   primary affinity, pg_temp, primary_temp, pg_upmap, pg_upmap_items, pg_upmap_primary,
   the CRUSH blob location),
3. keeps that state current by applying incrementals, and
4. feeds the result to the placement pipeline (object -> PG -> OSD list; CRUSH itself is in a
   separate note).

Out of scope here: the CRUSH map encoding and the CRUSH algorithm, the monitor subscription
protocol, the msgr2 framing of the message, and the OSD op encoding. They are named where the
OSDMap note depends on them.

Replicated pools only. Erasure-coded pools are recognised (and rejected) but not supported.

### 1.2 Sources read

| File | Used for |
|---|---|
| `src/osd/OSDMap.h`, `src/osd/OSDMap.cc` | map and incremental encode / decode, `apply_incremental`, placement helpers |
| `src/osd/osd_types.h`, `src/osd/osd_types.cc` | `pg_pool_t`, `pg_t`, pool flags, pool encode / decode |
| `src/include/encoding.h` | envelope macros (version / compat / length), container encodings |
| `src/include/types.h`, `src/include/object.h`, `src/include/utime.h`, `src/include/uuid.h`, `src/include/interval_set.h`, `src/include/denc.h` | scalar and small types, interval sets, variable-length integers |
| `src/common/bitset_set.h`, `src/include/crc32c.h`, `src/common/sctp_crc32.c`, `src/common/buffer.cc` | the shard bitset inside `pg_pool_t`, and the CRC-32C routine used for the map checksums |
| `src/include/ceph_features.h` | feature bits that select encodings |
| `src/include/rados.h` | OSD state bits, weight constants, map flags |
| `src/msg/msg_types.h`, `src/msg/msg_types.cc` | address and address-vector encodings |
| `src/messages/MOSDMap.h` | the message that carries maps |
| `src/mon/OSDMonitor.cc` | which encoding the monitor sends to a client; how maps are re-encoded |
| `src/osdc/Objecter.cc` | how the reference client consumes maps (used only to say which fields matter) |
| `src/msg/async/AsyncMessenger.cc` | which entry of an address vector the reference messenger connects to |
| `doc/dev/encoding.rst`, `doc/dev/network-encoding.rst`, `doc/dev/osd_internals/osdmap_versions.txt` | documented encoding rules and version history (history stops at Nautilus) |

### 1.3 Conventions

- All integers are little-endian unless stated. `u8/u16/u32/u64` unsigned, `s32/s64` signed.
  (`doc/dev/network-encoding.rst:14-21`; integer encoders `src/include/encoding.h:112-129`.)
- "Envelope" means the 6-byte versioned header described in 2.1.
- "Blob" means a `u32` length followed by that many bytes (`src/include/encoding.h:227-243`).
- Field names below are the protocol names used in the source; they are protocol facts, not code.

---

## 2 Wire structures

### 2.1 Primitive encodings

| Type | Encoding | Source |
|---|---|---|
| `bool` | 1 byte, 0 or 1 | `src/include/encoding.h:98-108` |
| `string`, blob, bufferlist | `u32` length + raw bytes | `src/include/encoding.h:227-243`, `doc/dev/network-encoding.rst:141-160` |
| `vector<T>`, `set<T>` | `u32` count + count elements | `doc/dev/network-encoding.rst:123-139` |
| `map<K,V>` | `u32` count + count (K, V) pairs, in key order | `doc/dev/network-encoding.rst:164-183` |
| `pair<A,B>`, `tuple<...>` | members one after another, no header | `doc/dev/network-encoding.rst:93-120`, `src/include/encoding.h:694-708` |
| `optional<T>` | `u8` present flag, then T if present | `doc/dev/network-encoding.rst:78-91`, `src/include/encoding.h:668-691` |
| `epoch_t` | `u32` | `doc/dev/network-encoding.rst:57-70` |
| `utime_t` | `u32` seconds, `u32` nanoseconds (8 bytes) | `src/include/utime.h:162-176`, `doc/dev/network-encoding.rst:191-200` |
| `uuid_d` (fsid) | 16 raw bytes, no length | `src/include/uuid.h:70-72` |
| `snapid_t` | `u64` | `src/include/object.h:114-130` |
| `interval_set<snapid_t>` | encoded as its inner map: `u32` count (fixed width, not a varint) + count (start `u64`, length `u64`) | `src/include/interval_set.h:418-444` (the set wraps a map; the pair meaning is start / length), `src/include/denc.h:1140-1146` and `:1225-1241` (count is a fixed `u32`), `src/include/object.h:133-147` (`snapid_t` is a plain `u64`) |
| `shared_ptr<T>` vector | `u32` count + each element encoded in full (an empty / null slot is encoded as a default-constructed element) | `src/include/encoding.h:1031-1072` |
| varint (used only inside the pool's shard bitset, 2.5 row 53) | 7 bits per byte, least significant group first, high bit set means another byte follows | `src/include/denc.h:411-439` |

Elements of `map` and `set` are written in ascending key order because they are ordered
containers; a client can rely on sorted wire order but should not require it for correctness
**[confirmed: osdmap_check.py over the 89 stored maps and 89 incrementals of the lab: 870 adjacent key pairs
(pools, pool names, `pg_temp` with up to 32 entries, upmap maps), none out of order]**. Two containers in this note are not plain `std::map`s but have the same
wire form: `pg_temp` is a custom class that writes `u32` count, then per entry a `pg_t`, a `u32`
element count and that many little-endian `s32` (`src/osd/OSDMap.h:121-129` encode and `:130-155`
decode of the compiled-in branch `#if 1` at `:116`; an alternative branch at `:265-337` is
compiled out), and the `interval_set` above.

#### 2.1.1 `pg_t`

17 bytes (`src/osd/osd_types.h:485-499`; the struct itself starts at `:407`):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | version | always 1; ignored on decode |
| 1 | 8 | pool | `u64` |
| 9 | 4 | seed (`ps`) | `u32` |
| 13 | 4 | preferred | always -1 on encode; skipped on decode |

Ordering of `pg_t` (which defines map order) compares pool, then seed (members are declared in that
order, `src/osd/osd_types.h:407-412`, and the comparison is the defaulted one at `:482`).

#### 2.1.2 `entity_addr_t`

When the encoder was given `MSG_ADDR2` (the map encoders pass the feature mask they were given down
to the addresses; every v20 monitor encoding for the clients targeted here has it) an address is
(`src/msg/msg_types.h:476-516`, decode `:518-562`):

| Size | Field | Notes |
|---|---|---|
| 1 | marker | 1 (value 0 means a legacy form, see below; anything else is rejected, `msg_types.h:523-527`) |
| 1 | struct_v | 1 |
| 1 | struct_compat | 1 (a decoder must refuse larger, `msg_types.h:528`) |
| 4 | struct_len | length of the rest |
| 4 | type | 0 none, 1 legacy (msgr1), 2 msgr2, 3 any, 4 cidr (`msg_types.h:239-245`) |
| 4 | nonce | identifies the daemon incarnation; used again when connecting (see 3.7) |
| 4 | elen | length of the socket address that follows; see below for what values occur |
| elen | sockaddr | see below |

If the encoder lacks `SERVER_NAUTILUS`, type 3 (any) is written as 1 (legacy) (`msg_types.h:485-496`).
A client that advertises `SERVER_NAUTILUS` therefore sees type 3 unchanged. Type 3 entries
come from the blocklist (OSD-only block); OSD address vectors normally carry types 1 and 2.

Socket address body when `elen` is non-zero: a `u16` address family (little-endian), then
`elen - 2` raw bytes of the family-specific part of a Linux `sockaddr`. For IPv4 (family 2,
`elen` 16) the 14 raw bytes are: port (2 bytes, big-endian), IPv4 address (4 bytes), 8 zero bytes.
For IPv6 (family 10, `elen` 28) the 26 raw bytes are: port (2, big-endian), flow info (4),
IPv6 address (16), scope id (4). Flow info and scope id are copied from the in-memory structure, so
they are in the sender's host byte order (little-endian on x86 and arm64); in practice both are
zero. The byte layouts of the sockaddr body are derived from the Linux `sockaddr_in` /
`sockaddr_in6` layouts, not stated in the Ceph source. IPv4 **[confirmed: osdmap_check.py re-encoded 470
captured entries from their decoded fields and got the captured bytes back: port big-endian, address, 8 zero
bytes; `struct_len` 28, `elen` 16, family 2]**. IPv6 **[confirm on capture]**: the lab has no IPv6 network.

What `elen` values actually occur (derived from the encoder, `msg_types.h:321-328`, `:500-515`):
the encoder always writes the size of the in-memory address for its family: 16 for IPv4, 28 for
IPv6, and **28 also for an empty / unset address** (family 0, followed by 26 zero bytes), because
an unset address falls into the "any other family" case. The encoder never writes `elen` = 0, but
the decoder accepts it, and it accepts any `elen` from 2 up to 16 (IPv4) / 28 (any other family,
including IPv6 and family 0) **[derived from the bound check at `msg_types.h:549`; note that the
bound depends on the family just decoded]**. A minimal decoder should: read `elen`, read the
family, treat a family other than 2 and 10 as "no usable address", and in every case advance by
exactly `elen` bytes so that the stream stays aligned. Family 10 is the on-wire value for IPv6
only where the sender translates it: the Linux value is native on Linux; a Windows sender
rewrites its own IPv6 constant to 10 (`src/msg/msg_types.h:38`, `:507-511` encode, `:541-545`
decode). A sender on any other platform writes its native family number unchanged, which may not be 10
**[unverified: only the Windows translation is visible in the source; the captures cannot settle
it because every sender in the lab is Linux]**; the monitor and OSDs are Linux.

Legacy form (marker 0): `u8` marker already read, then `u8` marker2, `u16` rest, `u32` nonce, and
a raw 128-byte `sockaddr_storage` whose first two bytes are the family in network byte order
(`src/msg/msg_types.h:454-474`, `:150-200`). The first four bytes (marker, marker2, rest) are
four zero bytes as written by the encoder. Only senders without `MSG_ADDR2` produce it; the
client may reject it.

#### 2.1.3 `entity_addrvec_t`

(`src/msg/msg_types.cc:334-389`.)

| Size | Field | Notes |
|---|---|---|
| 1 | marker | 2 for the current form; 0 and 1 are older single-address forms (marker 1 is simply one `entity_addr_t` whose own marker byte has been consumed); > 2 is an error |
| 4 | count | marker 2 only |
| ... | entity_addr_t x count | each with its own marker byte and envelope |

An OSD that has never been up has an address vector with count 0 (marker 2, count 0), five bytes.
A slot of the per-OSD vector that was never filled is a null pointer inside the reference code and
is written as exactly this empty vector (`src/osd/OSDMap.cc:1549-1565` slots are created null by
`resize`; `src/include/encoding.h:1031-1058` writes a default element for a null slot), so a
decoder never sees a "missing" entry, only an empty vector.
Worked layout of one IPv4 msgr2 entry, derived from the tables above: marker 2, count 1,
then the 35-byte entity address (marker 1, 1, 1, len 28, type 2, nonce, elen 16, family 2,
port, ip, 8 zero bytes) **[confirmed: osdmap_check.py, 470 entries in the lab's maps; never-up OSDs carry
the 5-byte empty vector (11 seen) and no blank `elen` 28 entry occurs; every dual-stack OSD vector is
[v2 entry, v1 entry] in that order (235 seen); the only `elen` value seen is 16]**.

### 2.2 Versioned envelope (struct_v / struct_compat / struct_len)

(`src/include/encoding.h:1455-1482` encode (the length is back-filled after the body is written),
`:1511-1524` decode, `:1602-1622` legacy decode, `:1651-1659` finish; rules in
`doc/dev/encoding.rst:104-117`.)

| Size | Field | Meaning |
|---|---|---|
| 1 | struct_v | version the sender wrote |
| 1 | struct_compat | oldest decoder version that can read this; a decoder whose own maximum is lower must refuse |
| 4 | struct_len | number of bytes that follow, to the end of this struct |

Decoder contract, in my words:

1. Read the three fields. If `struct_compat` is greater than the highest version your decoder
   implements, fail. (The reference decoders do exactly this: `encoding.h:1517-1518`.)
2. If `struct_len` is larger than the bytes remaining in the enclosing buffer, fail
   (`encoding.h:1521-1522`). The reference compares against the remaining bytes of the whole
   buffer, not against the end of the enclosing struct; a careful client should compare against the
   enclosing struct's `end` (my addition, stricter than the reference).
3. Remember `end = position_after_header + struct_len`.
4. Decode the fields your code knows for `struct_v`. A larger `struct_v` than you know is fine
   (new fields are appended); a smaller one means fewer fields (each table below gives the
   "since" version).
5. At the end, if you consumed more than `end` fail; if less, jump to `end`
   (`encoding.h:1651-1659`). This jump is what lets a client skip fields and whole blocks it does
   not understand.

Legacy variant used by the outer map and incremental wrapper and by `pg_pool_t`
(`DECODE_START_LEGACY_COMPAT_LEN(v, compat_at, len_at)`): the first byte is `struct_v`. The
compat byte is present only when `struct_v >= compat_at`; the length is present only when
`struct_v >= len_at` (`encoding.h:1602-1622`). For the wrapper both thresholds are 7, for the
pool they are both 5. All v20.2.5 senders that include the client feature bits write the full
header, so a client can treat `struct_v` below the threshold as an error (see section 4).

### 2.3 MOSDMap message payload

Message type `CEPH_MSG_OSD_MAP` = 41 (`src/include/ceph_fs.h:176`). Message header version
`HEAD_VERSION` 4, `COMPAT_VERSION` 3 (`src/messages/MOSDMap.h:26-27`); the version is the one in the
message header (the msgr2 note's `ceph_msg_header2`), and the payload decoder branches on it
(`MOSDMap.h:82-100`). The sender lowers it to 2 or 1 only when the receiver lacks encoding feature bits
(`MOSDMap.h:106-115`); a client that advertises the feature bits in section 2.7.4 will see 4.
`MOSDMap::encode_payload` itself re-encodes every embedded map and incremental when the significant
feature bits of the receiver differ from the ones the maps were built with (`MOSDMap.h:116-153`); this
is a second, send-time layer in addition to the monitor-side re-encode in 2.8.

Payload (`src/messages/MOSDMap.h:82-100` decode, `:101-165` encode):

| Header version | Size | Field | Notes |
|---|---|---|---|
| all | 16 | fsid | cluster fsid |
| all | var | incremental_maps | `map<u32 epoch, blob>`; each blob is an `OSDMap::Incremental` encoding (2.6) |
| all | var | maps | `map<u32 epoch, blob>`; each blob is a full `OSDMap` encoding (2.4) |
| >= 2 | 4 | cluster_osdmap_trim_lower_bound | oldest epoch the monitor still holds (the field was formerly called oldest_map); `MOSDMap.h:34-48` |
| >= 2 | 4 | newest_map | newest epoch the monitor has |
| >= 4 | 4 | gap count | the removed-snaps-gap map was dropped in Octopus; v20 always writes a `u32` 0 here (`MOSDMap.h:161-163`). The v20 decoder reads this field as a `map<s64, interval_set<snapid>>` and throws the result away (`MOSDMap.h:95-99`), so a non-zero count is followed by that many (`s64` pool, interval set) entries; a client should decode and discard them rather than fail |

One message may mix full maps and incrementals for different epochs (`OSDMonitor.cc:4469-4501`:
for each epoch the monitor sends the incremental if it has one, otherwise the full map).
After a client falls behind the monitor's oldest stored map, the monitor starts with one full
map for the oldest epoch it has, then incrementals (`OSDMonitor.cc:4550-4571`). A subscription
with start 0 gets exactly one message holding one full map of the newest epoch
(`OSDMonitor.cc:4448-4466`, `:4867-4880`); a start of N >= 1 gets incrementals from N, batched at
`osd_map_message_max` epochs per message (`OSDMonitor.cc:4576-4590`). The monitor also remembers the
last epoch it sent to a session and silently raises a too-low start to that epoch + 1
(`OSDMonitor.cc:4544-4547`), so a client that re-subscribes with a lower start than it already
received will not be resent those epochs.

### 2.4 Full OSDMap

#### 2.4.1 Outer layout

An `OSDMap` is one envelope (wrapper, `struct_v` 8, `struct_compat` 7 as written by v20.2.5,
`src/osd/OSDMap.cc:3411`) containing, in order:

1. the **client-usable block**, its own envelope (`OSDMap.cc:3426`), compat 1;
2. the **OSD-only block**, its own envelope (`OSDMap.cc:3528`), compat 1;
3. `u32 crc` (`OSDMap.cc:3593`; only when wrapper `struct_v >= 8`).

The decoder entry point is `OSDMap.cc:3744-3975`. The wrapper is decoded with the legacy macro
with maximums (8, 7, 7) (`OSDMap.cc:3758`). A first byte below 7 selects an old whole-struct
format (the "classic" decoder, `OSDMap.cc:3759-3763`); a client rejects that.

The client block decoder accepts up to `struct_v` 10 (`OSDMap.cc:3768`); the OSD-only block up
to 12 (`OSDMap.cc:3854`). A client skips the OSD-only block entirely by its `struct_len`.

#### 2.4.2 Which versions v20.2.5 writes

The version of each block and of each `pg_pool_t` depends on the feature bits passed to the
encoder (`OSDMap.cc:3414-3425`, `:3511-3527`, `osd_types.cc:1965-1985`). The monitor encodes
the canonical stored map with `OSDMap::get_encoding_features()` (`OSDMonitor.cc:2007`), which
is the set of "significant" bits (`OSDMap.h:564-579`) minus the bits of releases newer than the
map's `require_osd_release` (`OSDMap.cc:3235-3267`).

| Cluster `require_osd_release` | Wrapper | Full-map client block | Incremental client block | OSD-only block (map / incremental) | `pg_pool_t` |
|---|---|---|---|---|---|
| tentacle (default for new v20 clusters, `OSDMonitor.cc:693-694`) | 8 / compat 7 | 10 | 9 | 9 (higher only if stretch mode, range blocklist or crimson is in use, `OSDMap.cc:3511-3527`, `:664-679`) | 32 |
| squid or reef | 8 / compat 7 | 10 | 9 | 9+ | 29 (30 if the pool is a stretch pool) |
| nautilus to quincy (cannot be running v20 daemons, see floor below) | 8 / compat 7 | 9 | 8 | 9 | 29 (30 for a stretch pool) |

Lower releases (not reachable with v20 daemons) step the client blocks down further: full-map block
7 without `SERVER_NAUTILUS`, 6 without `SERVER_MIMIC`, 3 without `SERVER_LUMINOUS` (`OSDMap.cc:3414-3425`);
incremental block 6 / 5 / 3 for the same three cases (`OSDMap.cc:588-597`); pool versions 27, 26,
24 and 21 for missing nautilus, mimic, luminous and `NEW_OSDOP_ENCODING` (`osd_types.cc:1968-1983`).

**[confirmed: osdmap_check.py, all 89 stored maps and 89 incrementals of the tentacle lab: wrapper 8 / compat 7,
full-map client block 10 / compat 1, incremental client block 9 / compat 1, OSD-only block 9 / compat 1,
`pg_pool_t` 32 / compat 5; the other rows of this table were not exercised, the lab only runs tentacle.]**

Floor: v20 OSDs refuse to start when the recorded `require_osd_release` is more than two
releases older than themselves (`src/ceph_osd.cc:529`, `src/common/ceph_releases.cc:28-55`), and the
monitor refuses to let a tentacle OSD boot while `require_osd_release` is below reef
(`OSDMonitor.cc:3511-3516`); both put reef (18) at the floor for a running v20 cluster. Whether a v20
monitor can still serve a map with a lower `require_osd_release` was not established in the code
paths read **[unverified]**; the lab cannot settle it either (it runs tentacle, and lowering
`require_osd_release` was not attempted on the shared lab).

Whether the monitor re-encodes the map for a given client depends on that client's connection
feature bits, see 2.8.

#### 2.4.3 Client-usable block (v10)

Order and types as encoded at `OSDMap.cc:3426-3505`, decoded at `OSDMap.cc:3768-3850`. "Since" is
the block `struct_v` in which the field appears.

| # | Field | Type | Since | Used by a client? |
|---|---|---|---|---|
| 1 | fsid | 16 raw bytes | 1 | yes: compare with the monitor's fsid |
| 2 | epoch | `u32` | 1 | yes |
| 3 | created | `utime_t` | 1 | no |
| 4 | modified | `utime_t` | 1 | no |
| 5 | pools | `map<s64 pool_id, pg_pool_t>` (2.5) | 1 | yes |
| 6 | pool_name | `map<s64 pool_id, string>` | 1 | yes (name to id lookup) |
| 7 | pool_max | `s32` | 1 | no |
| 8 | flags | `u32` (map flags, 2.7.3) | 1 | yes: pause and full flags |
| 9 | max_osd | `s32` | 1 | yes: sizes the per-OSD arrays |
| 10 | osd_state | `vector<u32>`; below v5 it was `vector<u8>` | 1 (u32 since 5) | yes: EXISTS and UP bits |
| 11 | osd_weight | `vector<u32>`, 16.16 fixed point | 1 | yes: in / out and CRUSH reweight |
| 12 | client_addrs | `vector<entity_addrvec_t>`, one per OSD (2.1.3) | 1 (real address vectors since 8; below 8 a single legacy address, `OSDMap.cc:3461-3465`) | yes |
| 13 | pg_temp | `map<pg_t, vector<s32>>` | 1 | yes |
| 14 | primary_temp | `map<pg_t, s32>` | 1 | yes |
| 15 | osd_primary_affinity | `vector<u32>`; empty means "all default" | 2 | yes |
| 16 | crush | blob (`u32` length + CRUSH map bytes) | 1 | yes: hand to the CRUSH decoder (separate note) |
| 17 | erasure_code_profiles | `map<string, map<string,string>>` | 3 | only to see that EC profiles exist; skip |
| 18 | pg_upmap | `map<pg_t, vector<s32>>` | 4 | yes |
| 19 | pg_upmap_items | `map<pg_t, vector<pair<s32,s32>>>` | 4 | yes |
| 20 | crush_version | `u32` | 6 | no |
| 21 | new_removed_snaps | `map<s64 pool_id, interval_set<snapid>>` | 7 | optional (2.9) |
| 22 | new_purged_snaps | same | 7 | no |
| 23 | last_up_change | `utime_t` | 9 | no |
| 24 | last_in_change | `utime_t` | 9 | no |
| 25 | pg_upmap_primaries | `map<pg_t, s32>` | 10 | yes |

Notes:

- `pool_max` is `s32` in the full map but `s64` in the incremental (`OSDMap.h:545` vs `:374`).
- Every per-OSD vector (rows 10, 11, 12, and 15 when non-empty) is expected to have exactly
  `max_osd` entries because the encoder sizes them together (`OSDMap.cc:1549-1565`). The decoder
  does not check; a client must (section 3.6).
- The CRUSH blob is just a length-prefixed byte range. A client can keep a pointer and length
  into the received buffer instead of copying it.

#### 2.4.4 OSD-only block (skipped)

Contents, for orientation only (`OSDMap.cc:3529-3591`): heartbeat addresses, per-OSD info
and extended info, the client blocklist, cluster addresses, cluster snapshot, per-OSD uuids, full
ratios, `require_min_compat_client`, `require_osd_release`, queued removed snaps, crush node and
device-class flags, stretch-mode fields, range blocklist, crimson flag. None of it is needed to
issue object I/O. **Exception to consider**: the blocklist. A blocklisted client has its ops
rejected by the OSD with error 108 (`EBLOCKLISTED`, `src/include/rados.h:499`,
`src/osd/PrimaryLogPG.cc:2130`); the reference client additionally scans the blocklist in each map
to notify its own watchers (`Objecter.cc:1259`, `:1463-1480`). A minimal client can detect the
rejection from the OSD's error reply rather than from the map **[decide in the OSD op note]**.

#### 2.4.5 Trailing CRC

A `u32` after the OSD-only block, inside the wrapper (wrapper `struct_v >= 8`). It is a CRC-32C
over: the whole wrapper from its first byte (including the 6-byte envelope header) up to but not
including the CRC field, continued over any bytes after the CRC field up to the end of the
wrapper (`OSDMap.cc:3946-3972`, encoder fill-in `:3593-3611`). The two pieces are chained: the
result of the first piece is the starting value for the second. The starting value for the first
piece is all ones (the code passes -1, `OSDMap.cc:3601`, `:3960`). The CRC routine is the plain
reflected CRC-32C register update with no final inversion: the entry point only forwards to the
table-driven update (`src/include/crc32c.h:33-51`, `src/common/sctp_crc32.c:517-578` and
`:783-786`; the other table-driven variants in `src/common/` have the same shape), and the buffer
chaining adds nothing (`src/common/buffer.cc:2089-2125`). So the stored value is the register after processing
with start 0xFFFFFFFF, i.e. the bitwise complement of what a CRC-32C library with the usual final
inversion returns for the same bytes (polynomial 0x1EDC6F41, reflected form 0x82F63B78)
**[confirmed: osdmap_check.py, vector T8: 89 of 89 stored maps; the textbook value with the final inversion
never matches]**. The value is written little-endian. The reference decoder
verifies it and throws on mismatch (`OSDMap.cc:3958-3972`).

A client may skip verification. If it does verify, it must hold the whole map in one contiguous
range, since the OSD-only block lies in the middle of the checked bytes. A map that the monitor
re-encoded for a client with fewer feature bits (2.8) carries a CRC recomputed for the re-encoded
bytes, because the encoder recomputes it (`OSDMap.cc:3598-3611`); do not compare it with a CRC
taken from a different feature set.

### 2.5 `pg_pool_t`

Defined at `src/osd/osd_types.h:1257`; encoder `src/osd/osd_types.cc:1861-2088`; decoder
`osd_types.cc:2090-2290`. The envelope is the legacy form with thresholds (5, 5); the decoder
maximum is 32 (`osd_types.cc:2092`). The sender writes compat 5 (`osd_types.cc:1986`).

Because the whole pool record has an envelope length, a client that does not care about a pool
(any pool other than the one holding its images) can skip it with one jump and keep only the id.

Fields in wire order. "Since" is the pool `struct_v`. A client built to the floor in section 4
(pool version 29 or higher) can treat every row with "since" 29 or lower as unconditionally
present.

| # | Field | Type | Since | Used by a client? |
|---|---|---|---|---|
| 1 | type | `u8`: 1 replicated, 3 erasure (`osd_types.h:1263-1266`) | 1 | yes: reject 3 |
| 2 | size | `u8` | 1 | yes: replica count |
| 3 | crush_rule | `u8` | 1 | yes: rule number for CRUSH |
| 4 | object_hash | `u8`: 1 linux dcache hash, 2 rjenkins (`src/include/ceph_hash.h:4-5`) | 1 | yes: object name to PG seed |
| 5 | pg_num | `u32` | 1 | yes |
| 6 | pgp_num | `u32` | 1 | yes |
| 7 | lpg_num, lpgp_num | `u32`, `u32`; always 0, ignore | 1 | no |
| 8 | last_change | `u32` epoch | 1 | no |
| 9 | snap_seq | `u64` | 1 | carry (pool-snap mode) |
| 10 | snap_epoch | `u32` | 1 | carry |
| 11 | snaps | `map<u64 snapid, pool_snap_info_t>`; each value is its own envelope (v2, compat 2: snapid `u64`, stamp `utime_t`, name string, `osd_types.cc:1295-1311`) | 3 | skip |
| 12 | removed_snaps | `interval_set<snapid>` | 3 | carry |
| 13 | auid | `u64`; unused | 3 | no |
| 14 | flags | `u64`; see 2.7.2 | 4 (full meaning since 27) | yes |
| 15 | crash_replay_interval | `u32`; always 0 | 4 | no |
| 16 | min_size | `u8` | 7 | yes |
| 17 | quota_max_bytes | `u64` | 8 | no |
| 18 | quota_max_objects | `u64` | 8 | no |
| 19 | tiers | `set<u64>` | 9 | yes: only to detect tiering |
| 20 | tier_of | `s64`; -1 if none | 9 | yes: only to detect tiering |
| 21 | cache_mode | `u8` | 9 | no |
| 22 | read_tier | `s64`; -1 if none | 9 | yes: only to detect overlay redirection |
| 23 | write_tier | `s64`; -1 if none | 9 | yes: same |
| 24 | properties | `map<string,string>`; obsolete | 10 | skip |
| 25 | hit_set_params | envelope (v1, compat 1) wrapping a type byte and parameters | 11 | skip by length (`src/osd/HitSet.cc:141-151`) |
| 26 | hit_set_period, hit_set_count | `u32`, `u32` | 11 | no |
| 27 | stripe_width | `u32` | 12 | no (EC) |
| 28 | target_max_bytes, target_max_objects | `u64`, `u64` | 13 | no |
| 29 | cache_target_dirty_ratio_micro, cache_target_full_ratio_micro | `u32`, `u32` | 13 | no |
| 30 | cache_min_flush_age, cache_min_evict_age | `u32`, `u32` | 13 | no |
| 31 | erasure_code_profile | string | 14 | yes: non-empty is another hint that the pool is EC |
| 32 | last_force_op_resend_preluminous | `u32` | 15 | no |
| 33 | min_read_recency_for_promote | `u32` | 16 | no |
| 34 | expected_num_objects | `u64` | 17 | no |
| 35 | cache_target_dirty_high_ratio_micro | `u32` | 19 | no |
| 36 | min_write_recency_for_promote | `u32` | 20 | no |
| 37 | use_gmt_hitset | `bool` | 21 | no |
| 38 | fast_read | `bool` | 22 | no |
| 39 | hit_set_grade_decay_rate, hit_set_search_last_n | `u32`, `u32` | 23 | no |
| 40 | opts | envelope (v2, compat 1) of `u32` count + (key `s32`, type `s32`, value) entries | 24 | skip by length (`osd_types.cc:1490-1540`) |
| 41 | last_force_op_resend_prenautilus | `u32` | 25 | no |
| 42 | application_metadata | `map<string, map<string,string>>` | 26 | skip (shows whether the pool is tagged `rbd`) |
| 43 | create_time | `utime_t` | 27 | no |
| 44 | pg_num_target | `u32` | 28 | no |
| 45 | pgp_num_target | `u32` | 28 | no |
| 46 | pg_num_pending | `u32` | 28 | yes: merge-in-progress detection |
| 47 | two ignored `u32` (old merge epochs) | `u32`, `u32` | 28 | no |
| 48 | last_force_op_resend | `u32` epoch | 28 | yes: forces resend of in-flight ops |
| 49 | pg_autoscale_mode | `u8` | 28 | no |
| 50 | last_pg_merge_meta | envelope (v1, compat 1) | 29 | skip by length (`osd_types.h:1211-1220`) |
| 51 | four stretch fields in this order: bucket_count, bucket_target, bucket_barrier (all `u32`), mandatory_member (`s32`, default 0x7fffffff when unused) | `u32` x3 + `s32` | exactly 30 only | yes: non-zero bucket_count means a stretch pool; reject (`osd_types.cc:2074-2079`, `:2267-2272`, field types `osd_types.h:1495-1503`) |
| 52 | peering crush data | `optional<tuple(u32 count, u32 target, u32 barrier, u32 mandatory_member)>`: one `u8` 0 for a non-stretch pool, otherwise `u8` 1 followed by 16 bytes | 31 and up | same (`osd_types.cc:2080-2083`, `:2274-2282`, `osd_types.h:1582-1592`). The fourth member is declared `u32` in the tuple but holds the same value as the `s32` of row 51 |
| 53 | nonprimary_shards | a 128-bit set written as two varints, one per 64-bit word, low word first (2.1); an empty set is the two bytes `00 00`. EC optimisation only | 32 | skip: it is inside the pool envelope (`osd_types.cc:2084-2086`, `:2283-2287`, `osd_types.h:152-153`, `src/common/bitset_set.h:325-345`) |

Source for the row order above: encoder `osd_types.cc:1991-2086`, decoder `osd_types.cc:2093-2288`.
All pool integer fields are fixed-width little-endian; the single-byte ones are `type`, `size`,
`min_size`, `crush_rule`, `object_hash`, `cache_mode`, `pg_autoscale_mode`
(`osd_types.h:1449-1454`, `:1476-1482`), all unsigned: a pool has at most 255 replicas and
`crush_rule` is 0..255 (it is read into an `int` that therefore can never be negative, so the
"no rule" branch at `OSDMap.cc:2780-2781` is unreachable from wire data).
The `opts` entry layout (`osd_types.cc:1490-1540`) is listed only for orientation; its envelope
header makes the exact entry layout unnecessary for a client.

When `struct_v < 28`, the decoder fills `last_force_op_resend` from the pre-nautilus field
(`osd_types.cc:2262-2265`); a floor of 29 makes that branch unreachable.

When `struct_v` is below 27 the sender strips the selfmanaged / pool-snap / creating flag bits
from `flags` (`osd_types.cc:2003-2007`). Independently of the version, the decoder adds one of
those two snapshot-mode bits when `snap_seq` is non-zero and neither bit is set: selfmanaged if
`removed_snaps` is non-empty, otherwise pool snaps (`osd_types.cc:2128-2136`). A client that reads
`flags` raw may therefore differ from the reference only for pools whose sender did not set either
bit; not relevant at a floor of 29.

Derived values the client computes after decoding (`osd_types.cc:2289`, `:1671-1675`):

- `pg_num_mask = (1 << bits(pg_num - 1)) - 1`, where `bits(x)` is the number of significant
  bits of `x` (0 for 0; `src/include/intarith.h:116-118`). `pgp_num_mask` likewise from `pgp_num`.
  For `pg_num` a power of two `n`, the mask is `n - 1`; for 100 it is 127; for 1 it is 0.
  `pg_num == 0` (or `pgp_num == 0`) makes the expression ill-defined (it would shift by 32), so
  reject it. The masks are not on the wire: recompute them for every pool record you store,
  including each record that arrives in `new_pools`.
- Stable modulo used with the masks (`src/include/rados.h:96-103`): for value `x`, count `b`,
  mask `m`, the result is `x & m` if that is below `b`, otherwise `x & (m >> 1)`. The reference
  declares all three as signed 32-bit `int`; with `pg_num` below 2^31 this makes no difference.

### 2.6 `OSDMap::Incremental`

#### 2.6.1 Outer layout

Same shape as the full map: wrapper envelope (`struct_v` 8, compat 7, `OSDMap.cc:585`), then
the client-usable block (`OSDMap.cc:598`), the OSD-only block (`OSDMap.cc:680`), then two `u32`
values (only when wrapper `struct_v >= 8`): `inc_crc` (CRC of the incremental, filled in at
`OSDMap.cc:740`) and `full_crc` (the CRC the *resulting full map* will carry, `OSDMap.cc:743`).
Decoder: `OSDMap.cc:864-1050`; wrapper macro with maximums (8, 7, 7) at `:878`; client block
maximum 9 at `:890`; OSD-only maximum 12 at `:949`. A wrapper `struct_v` below 7 selects an old
whole-struct form (`:879-888`) that a client rejects, as for the full map.

CRC coverage for `inc_crc`: everything from the wrapper's first byte up to the `inc_crc` field,
then continued over the bytes after it to the end of the wrapper, which includes `full_crc`
(`OSDMap.cc:1024-1050`, encoder `:746-757`); same CRC routine and start value as 2.4.5. The reference
decoder verifies `inc_crc` and throws on mismatch (`OSDMap.cc:1038-1050`).
**[confirmed: osdmap_check.py, 89 of 89 stored incrementals: `inc_crc` covers the wrapper up to its own field and
then `full_crc`; `full_crc` equals the `crc` of the monitor's stored full map of the same epoch.]**

`full_crc` equals the `crc` field the full map at that epoch carries when encoded with the
monitor's canonical feature set (`OSDMonitor.cc:2016-2017`). When the monitor re-encodes an
incremental for a client with fewer feature bits it decodes the incremental, re-encodes it and
re-encodes any embedded full map, but keeps the `full_crc` member untouched
(`OSDMonitor.cc:4610-4636`); the full map that a client reconstructs from re-encoded bytes may
therefore have a different CRC from `full_crc`. A client that keeps only decoded state cannot
reproduce it without re-encoding the full map byte-for-byte; it should not try. See open question Q4.

#### 2.6.2 Which versions v20.2.5 writes

Client block: 9 when the encoder has the `SERVER_REEF` bit, 8 without it but with `SERVER_NAUTILUS`,
6 without `SERVER_NAUTILUS`, 5 without `SERVER_MIMIC`, 3 without `SERVER_LUMINOUS`
(`OSDMap.cc:588-597`). OSD-only block: 9, or higher when stretch mode,
range blocklist or crimson changes are in the incremental (`OSDMap.cc:664-679`).

#### 2.6.3 Client-usable block (v9)

Encode `OSDMap.cc:599-661`, decode `OSDMap.cc:891-946`.

| # | Field | Type | Since | Used by a client? |
|---|---|---|---|---|
| 1 | fsid | 16 bytes | 1 | yes: check |
| 2 | epoch | `u32`; the epoch this incremental produces | 1 | yes |
| 3 | modified | `utime_t` | 1 | no (store if wanted) |
| 4 | new_pool_max | `s64`; -1 means "no change" | 1 | no |
| 5 | new_flags | `s32`; -1 means "no change" | 1 | yes |
| 6 | fullmap | blob; non-empty means "this epoch is delivered as a complete map, ignore everything else" | 1 | yes |
| 7 | crush | blob; empty means "no change", otherwise the complete new CRUSH map | 1 | yes |
| 8 | new_max_osd | `s32`; -1 means "no change" | 1 | yes |
| 9 | new_pools | `map<s64, pg_pool_t>`; each entry is a complete replacement pool record | 1 | yes |
| 10 | new_pool_names | `map<s64, string>` | 1 | yes |
| 11 | old_pools | `set<s64>`; pools removed | 1 | yes |
| 12 | new_up_client | `map<s32 osd, entity_addrvec_t>`; OSD becomes up at these client-facing addresses | 1 (address vectors since 7) | yes |
| 13 | new_state | `map<s32 osd, u32 mask>` (u8 values before 5); XOR mask, see 3.5 | 1 (u32 since 5) | yes |
| 14 | new_weight | `map<s32 osd, u32>` | 1 | yes |
| 15 | new_pg_temp | `map<pg_t, vector<s32>>`; empty vector removes | 1 | yes |
| 16 | new_primary_temp | `map<pg_t, s32>`; -1 removes | 1 | yes |
| 17 | new_primary_affinity | `map<s32 osd, u32>` | 2 | yes |
| 18 | new_erasure_code_profiles | `map<string, map<string,string>>` | 3 | skip |
| 19 | old_erasure_code_profiles | `vector<string>` | 3 | skip |
| 20 | new_pg_upmap | `map<pg_t, vector<s32>>` | 4 | yes |
| 21 | old_pg_upmap | `set<pg_t>` | 4 | yes |
| 22 | new_pg_upmap_items | `map<pg_t, vector<pair<s32,s32>>>` | 4 | yes |
| 23 | old_pg_upmap_items | `set<pg_t>` | 4 | yes |
| 24 | new_removed_snaps | `map<s64, interval_set>` | 6 | optional (2.9) |
| 25 | new_purged_snaps | same | 6 | no |
| 26 | new_last_up_change | `utime_t` | 8 | no |
| 27 | new_last_in_change | `utime_t` | 8 | no |
| 28 | new_pg_upmap_primary | `map<pg_t, s32>` | 9 | yes |
| 29 | old_pg_upmap_primary | `set<pg_t>` | 9 | yes |

#### 2.6.4 OSD-only block (skipped)

Heartbeat address changes, `new_up_thru`, `new_last_clean_interval`, `new_lost`, blocklist
additions and removals, cluster addresses, cluster snapshot, new uuids, new extended info, the
feature set the incremental was encoded with, ratios, `new_require_min_compat_client`,
`new_require_osd_release`, crush node and device-class flags, stretch-mode fields, range
blocklist changes, crimson flag (`OSDMap.cc:681-738`). Skip by length.

### 2.7 Constants

#### 2.7.1 OSD state bits (`osd_state` entries and `new_state` masks)

(`src/include/rados.h:125-137`; 13 bits, bit 12 is STOP.)

| Bit | Value | Name | Client cares? |
|---|---|---|---|
| 0 | 0x1 | EXISTS | yes |
| 1 | 0x2 | UP | yes |
| 2 | 0x4 | AUTOOUT | no |
| 3 | 0x8 | NEW | no |
| 4 | 0x10 | FULL | no |
| 5 | 0x20 | NEARFULL | no |
| 6 | 0x40 | BACKFILLFULL | no |
| 7 | 0x80 | DESTROYED | no |
| 8-11 | 0x100-0x800 | NOUP, NODOWN, NOIN, NOOUT | no |
| 12 | 0x1000 | STOP | no |

Predicates (`OSDMap.h:895-927`): an OSD "exists" if the id is in `0 <= id < max_osd` and EXISTS
is set; it is "up" if it exists and UP is set; "out" if it does not exist or its weight is 0;
"in" otherwise.

Weights: 16.16 fixed point, `0x10000` = in (1.0), `0` = out (`rados.h:142-143`). A weight above
`0x10000` is not forbidden by the wire format; the CRUSH note owns how the weight is used.
Primary affinity: the same scale, `0x10000` = default and maximum (`rados.h:145-146`).
CRUSH "no item" marker `0x7fffffff` (`src/crush/crush.h:36`; the pool header repeats it,
`osd_types.h:1270`) can appear in `pg_temp` and `pg_upmap` vectors and in mapping results. Because
OSD ids are `s32` on the wire, `0x7fffffff` is not a negative number, so every "valid OSD id"
test must bound-check against `max_osd`, not just against 0.

#### 2.7.2 Pool flags (`pg_pool_t.flags`, `u64`)

(`src/osd/osd_types.h:1281-1303`.) The client needs:

| Bit | Name | Meaning for a client |
|---|---|---|
| 0 | HASHPSPOOL | selects how the placement seed is derived (3.7 step 3); every pool created in the last decade has it, but honour both cases |
| 1 | FULL | pool is full: writes should be held |
| 10 | FULL_QUOTA | quota reached: writes should be held |
| 13 | SELFMANAGED_SNAPS | snapshots are managed by the client (the RBD case) |
| 14 | POOL_SNAPS | pool-level snapshots |
| 16 | EIO | all client ops must fail with EIO (`Objecter.cc:2965`) |
| 19 | EC_OPTIMIZATIONS | EC only; changes `pg_temp` interpretation (3.7 note) |

Other bits (EC overwrites, nodelete, nopgchange, scrub flags, nearfull, bulk, crimson, ...) can
be ignored.

#### 2.7.3 Map flags (`OSDMap.flags`, `u32`)

(`src/include/rados.h:152-175`.) Needed: PAUSERD (bit 2), PAUSEWR (bit 3) stop reads / writes;
FULL (bit 1, deprecated since mimic, `rados.h:153`; the reference client still honours it, `Objecter.cc:2877-2881`); SORTBITWISE (bit 15) and
RECOVERY_DELETES (bit 19) are read by the reference client when it calculates targets
(`Objecter.cc:3034-3035`) but only feed its interval-change test, not the placement result.

#### 2.7.4 Feature bits that select encodings

A feature "mask" has the bit itself plus incarnation marker bits; a feature is present only if
all mask bits are set (`ceph_features.h:12-17`, `:38-42`). Incarnation 2 adds bit 57;
incarnation 3 adds bits 57 and 28. The "significant" set that decides how a map or incremental is
encoded is listed at `OSDMap.h:564-579` (PGID64, PGPOOL3, OSDENC, OSDMAP_ENC, OSD_POOLRESEND,
NEW_OSDOP_ENCODING, MSG_ADDR2, CRUSH_TUNABLES5, CRUSH_CHOOSE_ARGS and the SERVER_LUMINOUS ..
SERVER_TENTACLE bits); `CRUSH_MSR` and `SERVER_SQUID` are not in it. The "Effect" column states the
encoding step each bit controls, taken from the encoders cited in 2.4.2 and 2.6.2.
Computed masks:

| Feature | Bit | Mask (hex) | Effect on the map encoding |
|---|---|---|---|
| PGID64 | 9 | 0x200 | without it (or without PGPOOL3) the monitor sends the oldest `MOSDMap` header version 1 (`MOSDMap.h:106-111`) |
| PGPOOL3 | 11 | 0x800 | without it the pool is written in the pre-envelope form `struct_v` 2 and snapshot entries in v1 (`osd_types.cc:1866-1890`, `:1295-1301`) |
| OSDENC | 13 | 0x2000 | without it the pool is written as `struct_v` 4 and `MOSDMap` header version 2 (`osd_types.cc:1892-1914`, `MOSDMap.h:112-114`) |
| SERVER_LUMINOUS (also CRUSH_CHOOSE_ARGS, OSDMAP_PG_UPMAP) | 21 | 0x0200000000200000 | without it: full-map client block 3, incremental client block 3, pool 24 |
| SERVER_MIMIC | 28 | 0x0200000010000000 | without it: full-map client block 6, incremental 5, pool 26 |
| SERVER_NAUTILUS | 2 | 0x0200000010000004 | without it: full-map client block 7, incremental 6, pool 27; also selects whether address `type` 3 is kept (2.1.2) |
| SERVER_OCTOPUS | 16 | 0x0200000010010000 | no encoding step found in the paths read |
| SERVER_REEF | 31 | 0x0200000090000000 | without it: full-map client block 9, incremental 8 (client block 10 / incremental 9 add the upmap-primary maps) |
| CRUSH_MSR | 38 | 0x0200004000000000 | not in the significant set; changes the CRUSH blob encoding (`src/crush/CrushWrapper.cc:3243`, CRUSH note) |
| OSDMAP_ENC | 39 | 0x0000008000000000 | without it the whole map and incremental use the old "classic" form (`OSDMap.cc:3393-3395`, `:567-569`) |
| OSD_POOLRESEND | 43 | 0x0000080000000000 | without it the pool is written as `struct_v` 14 (`osd_types.cc:1916-1957`) |
| SERVER_SQUID | 49 | 0x0202000000000000 | no encoding step found in the paths read |
| SERVER_TENTACLE | 50 | 0x0204000000000000 | without it the pool is 29 or 30 instead of 32 |
| NEW_OSDOP_ENCODING | 56 | 0x0100000000000000 | without it the pool is written as `struct_v` 21 (`osd_types.cc:1968-1971`) |
| CRUSH_TUNABLES5 | 58 | 0x0400000000000000 | CRUSH blob encoding (CRUSH note) |
| MSG_ADDR2 | 59 | 0x0800000000000000 | without it addresses are written in the single legacy form (2.1.2, 2.1.3) |
| RESERVED | 62 | 0x4000000000000000 | sentinel only encoders use; a client never sets it |

(Feature bit values from `src/include/ceph_features.h:88-187`; masks computed from the incarnation
rule; recompute them when pinning a different release.)

### 2.8 What the monitor does for a client with a given feature mask

The monitor keeps each epoch as stored (encoded with the map's own encoding features) and, per
request, compares the significant bits of the client's connection features with the monitor
quorum's (the client's side is the feature set negotiated for its session, or the quorum's for an
anonymous one, `OSDMonitor.cc:4541-4542`). If they differ it decodes, then re-encodes with the
intersection of the client's bits and the map's own encoding bits (incremental:
`OSDMonitor.cc:4610-4636`, selected at `:4651-4673`; full map: `:4638-4649`, selected at
`:4795-4820`). If they match it sends the stored bytes unchanged. Consequences:

- A client that advertises all the bits in 2.7.4 receives the canonical bytes (what the
  monitor's `osd getmap` command returns, `OSDMonitor.cc:5645-5647`).
- A client that advertises fewer bits receives older versions of the same structures (pool
  versions 29 / 30 instead of 32, client block 9 instead of 10, and so on, per the table in 2.7.4).
  A decoder written to the floors in section 4 handles both. The re-encoded map carries its own
  recomputed CRC, while an incremental keeps the canonical `full_crc` (2.6.1).
- The OSD-side feature requirements for a client come from the map itself
  (`OSDMap::get_features`, `OSDMap.cc:1754-1850`): CRUSH tunable bits, `OSDMAP_PG_UPMAP` (same
  bit as SERVER_LUMINOUS) if upmap is used, `SERVER_REEF` if `pg_upmap_primaries` is non-empty,
  `CRUSH_MSR` if MSR rules exist, `CEPHX_V2` per `require_min_compat_client`. A client missing a
  required bit is refused at connection time; which bits to advertise is a msgr2-note topic.

### 2.9 Optional: removed snapshots

`new_removed_snaps` (full map row 21, incremental row 24) lists, per pool, the snapshot ids
removed in exactly this epoch. The reference client uses it to drop removed snapshot ids from the
snap context of *in-flight* writes (`src/osdc/Objecter.cc:1142`, `:1296`; the pruning function
starts at `:2917`). A minimal client may ignore the field and simply refresh its image snap
context on error, but whether the OSD rejects a write whose snap context names a removed snapshot
was not checked **[unverified]**; the lab cannot settle it without a writer that sends a stale snap
context (an OSD-op test, see Q7). What the lab does show: the removal of a self-managed snapshot arrives in
`new_removed_snaps` of exactly one epoch (full-map row 21 at epoch 28, `[2~1]` for pool 2) and the same ids in
`new_purged_snaps` one epoch later (epoch 29), while the `removed_snaps` field of the pool record stays empty.

---

## 3 Client procedure

### 3.1 Getting maps

(Monitor subscription mechanics are in the monitor note; only the OSDMap-relevant parts here.)

1. Subscribe to the topic named `osdmap`. The reference client asks for start epoch 0 when it has
   no map (receives one full map of the latest epoch), otherwise start = current epoch + 1; it
   uses a one-time subscription unless the map has pause / full flags set, in which case
   continuous (`src/osdc/Objecter.cc:2074-2092`; subscription item is start `u64` + flags `u8`,
   one-time flag value 1, `src/include/ceph_fs.h:269-274`).
2. The monitor answers with `MOSDMap` messages (2.3). With a continuous subscription it sends a
   new one after each epoch.
3. If you need to re-synchronise at any time, subscribe again with start 0 (full map) or with
   current + 1. A start at or below the last epoch the monitor already sent on this session is
   raised to that epoch + 1 (`OSDMonitor.cc:4544-4547`), so a re-request for an epoch that was sent
   but lost on your side returns nothing new; recover from that by subscribing with start 0, which
   is answered with a full map regardless (`OSDMonitor.cc:4867-4880`) **[confirmed in round 2, see below]** (round 1 showed the
first half only: **[confirmed: osdmap_check.py, 79 MOSDMap messages]** a subscription with start 0 is answered by
exactly one MOSDMap holding one full map of the newest epoch, and the stock client then re-subscribes with
start = epoch + 1 and ONETIME (flag 1) and gets nothing more; re-subscribing with a low start after maps were
already sent on the session was not exercised in round 1; **[confirmed in round 2: the client of `core/` tracked a pool
after its first map was held (`harness/test/test_lab_map.c`, `WR_LAB_LATE_POOL`), asked again with start 0 on the same session, and the
monitor answered with one full map of the epoch it had already sent (epoch 2555 both times: two full maps, one re-request, no
incremental); both key types]**).
   Subscription mechanics in general belong to the monitor-client note.

### 3.2 Handling an MOSDMap message

Modelled on `Objecter::handle_osd_map` (`src/osdc/Objecter.cc:1208-1440`); my own steps:

1. Compare the message fsid with the fsid you know; ignore the message on mismatch
   (`Objecter.cc:1215-1219`).
2. Let `last` be the highest epoch present in either map. If `last <= your epoch`, ignore the
   message (`Objecter.cc:1236`).
3. If you have no map yet: if the message has a full map for `last`, decode it and adopt it;
   otherwise ask for a full map (start 0, one-time) and stop (`Objecter.cc:1320-1340`).
4. Otherwise walk epochs `your_epoch + 1` through `last`, one at a time:
   a. If your current epoch is exactly `e - 1` and an incremental for `e` is present, decode it
      and apply it (3.5).
   b. Else if a full map for `e` is present, decode it and replace your whole state with it.
   c. Else (neither): if `e >= cluster_osdmap_trim_lower_bound`, request the missing epoch
      (subscribe with start = your epoch + 1) and stop processing this message;
      if `e` is below that bound the epoch no longer exists anywhere, so continue the walk at
      `cluster_osdmap_trim_lower_bound` and expect a full map there (`Objecter.cc:1280-1290`).
5. After each adopted epoch, recompute the target OSD of every outstanding request (3.7) and
   resend those whose target changed; the reference client also closes OSD sessions whose OSD is
   now down or whose client address changed (`Objecter.cc:1301-1314`).

### 3.3 Decoding a full map

1. Read the wrapper envelope with the legacy rules (2.2). If `struct_v < 7`, fail.
   If `struct_compat > 8`, fail.
2. Read the client block envelope. If `struct_compat > 10`, fail. Decode rows 1-25 (2.4.3),
   honouring each "since", then jump to the end of the client block (it may hold fields newer than
   you know).
3. Read the OSD-only block envelope only to get its `struct_len`; jump past it (the reference would
   fail on an OSD-only `struct_compat` above 12; a skipping client has no reason to).
4. If wrapper `struct_v >= 8`, read the `u32 crc`. Optionally verify (2.4.5).
5. Jump to the wrapper end.
6. Post-process: build a name-to-id index from `pool_name`; compute `pg_num_mask` and
   `pgp_num_mask` for every pool you keep (2.5); validate (3.6).

### 3.4 Decoding an incremental

Same skeleton as 3.3 with the incremental tables (2.6): wrapper (legacy rules, thresholds 7 / 7),
client block (max 9), skip the OSD-only block by length, then `inc_crc` and `full_crc` when
wrapper `struct_v >= 8`.

### 3.5 Applying an incremental

Order matters. This is the order of `OSDMap::apply_incremental` (`src/osd/OSDMap.cc:2371-2700`),
listed for the fields in scope. All "OSD id" inputs must be bounds-checked against `max_osd`
**after** step 6 (3.6).

1. **Identity.** If the incremental's epoch is 1, adopt its fsid; otherwise its fsid must equal
   yours, else reject (`OSDMap.cc:2374-2378`).
2. **Contiguity.** Its epoch must equal your epoch + 1. The reference code treats a violation as
   a programming error (`OSDMap.cc:2379`); a client should simply not apply it and ask for the
   missing epoch (3.2 step 4c).
3. Set your epoch to the incremental's epoch, and `modified` from it (`OSDMap.cc:2381-2383`).
4. **Embedded full map.** If `fullmap` is non-empty, decode it as in 3.3, replace *all* state with
   it and stop; nothing else in the incremental is applied (`OSDMap.cc:2385-2389`).
5. **Flags.** If `new_flags >= 0`, replace `flags` (`OSDMap.cc:2392-2393`). (The reference code
   also nudges `require_osd_release` here for pre-luminous bits; irrelevant to a client.)
6. **Resize.** If `new_max_osd >= 0`, set `max_osd` to it and resize every per-OSD array.
   New slots get: state 0, weight 0 (out), empty address vector, and, if the affinity array
   exists, default affinity `0x10000`. Shrinking drops the tail (`OSDMap.cc:2410-2411`,
   `set_max_osd` at `:1549-1565`).
7. **Pool ceiling.** If `new_pool_max != -1`, set `pool_max` (`OSDMap.cc:2413-2414`). Optional.
8. **New pools.** For every entry in `new_pools`: insert or replace the whole pool record, then set
   that record's `last_change` to the new epoch (`OSDMap.cc:2415-2418`). Recompute the masks
   (they derive from fields in the record you just stored; the reference does it at decode time,
   `osd_types.cc:2289`).
9. **Pool names.** For every entry in `new_pool_names`: set or replace the name for that pool id
   and fix the reverse index (`OSDMap.cc:2445-2454`).
10. **Removed pools.** For every id in `old_pools`: drop the record and its name
    (`OSDMap.cc:2456-2460`). Because this runs after steps 8 and 9, a pool that appears in both
    `new_pools` and `old_pools` ends up removed.
11. **Weights.** For every (osd, weight) in `new_weight`: store the weight; if the weight is
    non-zero, also set the EXISTS bit in that OSD's state (`set_weight`, `OSDMap.h:834-839`), and
    clear AUTOOUT and NEW (`OSDMap.cc:2462-2471`). This is how a newly created OSD comes into
    existence: the monitor writes weight "in" and state NEW for it and deliberately leaves EXISTS
    out of `new_state`, relying on this side effect (`OSDMonitor.cc:9778-9781`). Because this step
    precedes step 13, an incremental that both gives a non-zero weight and sets the EXISTS bit in
    `new_state` for the same OSD would trigger the "destroy" branch below; the monitor code paths
    read do not produce that combination, but a client must still apply the steps in this order.
12. **Primary affinity.** For every (osd, value) in `new_primary_affinity`: store it; if the array
    does not exist yet, first create it with every entry set to `0x10000` for `max_osd` slots
    (`OSDMap.cc:2473-2476`, `OSDMap.h:849-856`).
13. **State changes.** For every (osd, mask) in `new_state` (`OSDMap.cc:2486-2509`):
    - A mask of 0 means "toggle UP", i.e. the effective mask is UP (0x2).
    - If the OSD currently has EXISTS set *and* the effective mask has EXISTS set, the OSD is being
      destroyed: set its state to 0, clear its client address vector to empty, reset its affinity
      to `0x10000`.
    - Otherwise XOR the effective mask into the OSD's state.
    Note that XOR toggles: the bits in `new_state` are "flip these", not "set these".
    A minimal client may keep only bits EXISTS and UP, but XOR on the full `u32` gives the same
    answer for those two bits and is simpler.
14. **New up OSDs.** For every (osd, addrvec) in `new_up_client`: set EXISTS and UP in the OSD's
    state, clear the STOP bit, and store the address vector as the OSD's client address
    (`OSDMap.cc:2511-2523`). This runs after step 13, so an incremental can destroy and
    immediately re-add an OSD in one epoch. A down OSD keeps its last address until the next
    `new_up_client`; mark-down does not clear it.
15. **pg_temp.** For every (pg, vector) in `new_pg_temp`: if the vector is empty remove the entry,
    otherwise replace it (`OSDMap.cc:2549-2553`).
16. **primary_temp.** For every (pg, osd) in `new_primary_temp`: if osd is -1 remove the entry,
    otherwise set it (`OSDMap.cc:2560-2564`).
17. **pg_upmap.** For every entry in `new_pg_upmap`: set. Then for every pg in `old_pg_upmap`:
    remove. Same pattern for `pg_upmap_items` and for `pg_upmap_primary` (set, then remove)
    (`OSDMap.cc:2567-2586`). Because removal comes second, a pg listed in both is removed.
18. **CRUSH.** If `crush` is non-empty, decode it and replace the whole CRUSH map; do this last,
    after the OSD changes (`OSDMap.cc:2657-2670`). The reference bumps its own `crush_version`
    when `require_osd_release >= luminous`; a client does not need that counter.
19. Recompute counts or any cached "number up / in" you keep (`OSDMap.cc:2698`).

Fields in the incremental that this procedure ignores (erasure-code profile changes, removed and
purged snapshots, up-thru, blocklist, heartbeat and cluster addresses, ratios, release
requirements, stretch fields, crimson flag) are all legitimately skipped for a client.

### 3.6 Validation (apply to every decoded map and incremental)

- Envelope lengths never exceed the remaining bytes (2.2 rule 2).
- `max_osd` (a signed `s32` on the wire) is not negative and is within a limit you choose
  (memory); `osd_state`, `osd_weight`, `client_addrs` have exactly `max_osd` entries;
  `osd_primary_affinity` has 0 or `max_osd` entries. The reference decoder does not check this
  (`OSDMap.cc:3768-3850`), but all later indexing assumes it.
- Every OSD id in `new_state`, `new_weight`, `new_up_client`, `new_primary_affinity` is in
  `[0, max_osd)` after the resize; reference code indexes without checking
  (`OSDMap.cc:2462-2523`).
- Every pool you keep has `pg_num > 0`, `pgp_num > 0` and `size >= 1`. (Do not enforce any
  ordering between `pgp_num` and `pg_num`; the source does not, and a split or merge can leave
  them momentarily different.)
- Counts of map entries (pools, pg_temp, upmap, vectors) are within your memory budget before
  allocating, and a count times the smallest possible element size does not exceed the bytes left
  in the enclosing struct (every count is a `u32`, so a hostile value can be 4 billion).
- An inner struct never ends beyond the end of its enclosing struct (2.2 rule 2).
- CRUSH rule index (`crush_rule`) exists in the decoded CRUSH map (checked at mapping time).

### 3.7 Using the decoded fields for placement

This note owns the map fields; the hash functions and CRUSH are in other notes. For
completeness this is how the reference client combines the OSDMap fields to find the OSDs for an
object (`src/osdc/Objecter.cc:2945-3200`, `src/osd/OSDMap.cc:2749-3180`), in my words:

1. Find the pool by id (or by name through the name index). Refuse if absent, if `FLAG_EIO`
   is set (fail the request), if the type is erasure, if `tier_of >= 0`, or if `read_tier` /
   `write_tier` redirect to another pool (a client that does not implement overlays should
   refuse these pools).
2. Compute the object's hash seed `ps` using the pool's `object_hash` (1 or 2; any other value
   makes the reference hash function return 0xFFFFFFFF, `src/common/ceph_hash.cc:95-105`, so reject
   it). The hashed string is the object locator key if the request has one, otherwise the object
   name (`OSDMap.cc:2704-2716`); if the namespace is non-empty the hashed bytes are the namespace,
   then the single byte 0x1F, then that name or key; with an empty namespace they are just the name
   or key (`osd_types.cc:1794-1805`). The raw PG is `(pool_id, ps)`. For RBD data objects the
   namespace and locator are normally empty; if a non-default image namespace is ever used, the
   0x1F rule matters.
3. The effective PG seed is the stable modulo of `ps` against `pg_num` and `pg_num_mask`
   (`osd_types.cc:1815-1819`, `Objecter.cc:2998-3000`).
4. Look the effective PG up in `pg_temp` and `primary_temp` (`OSDMap.cc:3060-3098`): drop every
   `pg_temp` member that does not exist or is down (a replicated pool compacts the list; an
   erasure pool keeps position with a "none" marker). If `primary_temp` has the PG, that is the
   temp primary; otherwise the first remaining `pg_temp` member is. A `primary_temp` entry applies
   even when there is no usable `pg_temp` list: then the acting set is the up set but the acting
   primary is the temp primary (step 10).
5. Placement seed for CRUSH (`osd_types.cc:1826-1841`): if HASHPSPOOL is set, hash the pair
   (stable modulo of `ps` against `pgp_num` and `pgp_num_mask`, pool id) with the CRUSH 32-bit
   two-input hash (rjenkins variant, hash type 0); otherwise add the pool id to that
   stable-modulo value. The pool id is a `s64` in the map but both the hash input and the sum are
   32-bit (the result is a 32-bit seed, so the sum wraps).
6. Run the CRUSH rule `crush_rule` for the placement seed with `size` replicas and the per-OSD
   `osd_weight` array as the reweight input (`OSDMap.cc:2773-2790`). The pool id is passed as
   the last argument, which selects the CRUSH choose-args set of that pool, if the map has one
   (CRUSH note). Then drop non-existent OSDs (compact for replicated pools).
7. Apply upmap (`OSDMap.cc:2803-2869`), keyed by the effective PG:
   a. If `pg_upmap` has the PG: if any listed OSD (other than "none") is a valid id with weight 0,
      abandon upmap for this PG altogether, including the items and primary steps below
      (the reference function returns at that point, `OSDMap.cc:2808-2816`); otherwise replace
      the list with it and carry on to b.
   b. If `pg_upmap_items` has the PG: for each (from, to) pair, in order: skip it if `to` is
      already in the list; find the first position holding `from`; skip it if `to` is a valid id
      with weight 0; otherwise replace that position with `to`. (Pairs are applied one after
      another, not as a simultaneous swap.)
   c. If `pg_upmap_primaries` has the PG with OSD `p`: if `p` is a valid id with non-zero weight
      and appears in the list at a position after the first, swap it with the first position.
8. Convert the list to the "up" set (`OSDMap.cc:2871-2894`): drop members that do not exist or are
   down (compact for replicated pools). The up-primary is the first remaining member
   (`OSDMap.cc:2793-2801`).
9. Primary affinity (`OSDMap.cc:2896-2954`), only if the affinity array exists and some member of
   the up set has a non-default affinity: walk the up set in order; for each member with affinity
   below `0x10000`, compute the CRUSH 32-bit two-input hash of (placement seed, OSD id), shift
   right by 16, and reject that member as primary if the result is at or above its affinity;
   the first non-rejected member becomes primary, or, if all were rejected, the first
   member that was merely a candidate. For replicated pools the chosen primary is moved to the
   front of the list.
10. The acting set is the temp list from step 4 if non-empty, otherwise the up set from step 8/9;
    the acting primary is the temp primary if one was found, otherwise the up primary
    (`OSDMap.cc:3137-3190`). Send the op to the acting primary.

Erasure-coded pools in v20 add one more rule: if the pool has EC_OPTIMIZATIONS and the PG has a
`pg_temp`, the temp list is reordered back to shard order (`OSDMap.cc:3060-3098`, helper at
`:2975-3010`); not needed because EC is rejected.

Pool fields besides these that the reference client reads while targeting: `last_force_op_resend`
(compare with the current epoch to force a resend, `Objecter.cc:2973-2980`), `pg_num_pending`,
`size`, `min_size`, and the stretch fields (`Objecter.cc:3017-3085`). They feed the reference
client's "did the interval change, so resend" decision rather than the placement result itself.

### 3.8 Memory and skipping hints for a small client

- Keep `pg_temp`, `primary_temp`, `pg_upmap`, `pg_upmap_items` and `pg_upmap_primaries` entries
  only for the pool(s) you use; entries for other pools can be dropped while decoding and while
  applying incrementals (their `pg_t` carries the pool id).
- Skip pool records you do not use with the envelope jump; keep only id and name.
- Do not copy the CRUSH blob; keep offset and length of the received buffer, or hand it to the
  CRUSH decoder directly.
- `client_addrs` entries are variable length, so every entry must be walked, but you can store
  just one connectable entry of each OSD instead of the whole vector. The reference messenger
  connects to the first entry of the vector whose type is 1 or 2 (types 0, 3 and 4 are skipped), after
  filtering the vector by its own bind configuration (`src/msg/async/AsyncMessenger.cc:846-857`);
  a msgr2-only client should take the first entry of type 2.
- Decoding sorted maps in wire order lets you build sorted arrays and use binary search without
  an extra sort pass **[confirmed: see 2.1]**.

---

## 4 Minimal-client choices

### 4.1 Must handle

| Item | Choice |
|---|---|
| Wrapper envelope | `struct_v` >= 7 (the standard form), `struct_compat` <= 8; v20.2.5 writes 8 / compat 7 |
| Full-map client block | `struct_v` 9 and 10 (floor 9; row 25 only in 10); `struct_compat` <= 10 (the table in 2.4.3 lists "since" for every row down to v1 if a lower floor is wanted) |
| Incremental client block | `struct_v` 8 and 9 (floor 8; rows 28 and 29 only in 9); `struct_compat` <= 9 |
| `pg_pool_t` | `struct_v` 29 through 32 (30 only for stretch pools, which are rejected; 31 is never written by v20.2.5 but the decoder knows it); `struct_compat` <= 32; versions above 32 accepted if compat allows |
| Larger `struct_v` than known | accept when `struct_compat` is within the known maximum; skip the unknown tail with the length |
| Address vectors | marker 2 with msgr2 entries; pick the first entry of type 2 per OSD; walk every entry by its own length; tolerate empty vectors and empty (family 0, `elen` 28) entries |
| Operations | decode full map; decode incremental; apply incremental in the order of 3.5; all of 3.2 |
| Missing epochs | request the missing epoch or a full map; never apply across a gap |

Why these floors: with the full set of encoding feature bits and a cluster at `require_osd_release`
reef or newer, the stored map is at the maximum client-block / pool version for its release
(2.4.2); v20 OSDs refuse older recorded releases (2.4.2 floor). A client that advertises fewer
bits can be sent older versions (2.8), which is why the table above lists the intermediate values.
If the implementer wants wider compatibility, the "since" columns give every conditional down to
the oldest versions.

### 4.2 May skip

| Item | Why it is safe |
|---|---|
| OSD-only block of the map and incremental | not used for I/O; skipped by length |
| CRC verification | integrity only; the transport already has its own CRC or authentication, see 4.4 |
| `full_crc` and any check that the map after an incremental equals the monitor's | needs a byte-exact re-encode; recover by re-fetching the full map |
| `created`, `modified`, `pool_max`, `crush_version`, last up / in change times | not needed |
| `erasure_code_profiles` and its incremental changes | only to recognise EC pools; the pool's `type` already says so |
| Pool snaps, tiering parameters, hit-set parameters, quotas, scrub / cache fields, application metadata | not needed for replicated, untiered pools |
| `new_removed_snaps` / `new_purged_snaps` | see 2.9 |
| Blocklist, heartbeat and cluster addresses, up-thru, uuids, xinfo | not used by a client |
| Legacy marker 0 / 1 address forms, classic (pre-v7) map form | only older senders |

### 4.3 Must reject (with a clear error)

| Condition | Reason |
|---|---|
| Wrapper `struct_v < 7` or `struct_compat` above your maximum | unknown format |
| Any `struct_compat` above the version your decoder implements for that struct | unknown layout |
| Envelope `struct_len` larger than remaining bytes, or fields that overrun the envelope | corrupt |
| Pool `type == 3` (erasure) or a non-empty `erasure_code_profile` on the pool you use | EC unsupported in v1 |
| Pool with `tier_of >= 0`, `tiers` non-empty, `read_tier` or `write_tier` >= 0 for the pool you use | cache tiering unsupported |
| Pool with `peering_crush_bucket_count != 0` (stretch) for the pool you use | stretch pools unsupported |
| Pool with the `POOL_SNAPS` flag (bit 14, 2.7.2) for a pool a writer uses | the OSD would replace the client's snapshot context with the pool's own (`osd-ops.md` 3.9) |
| Pool with the `EIO` flag (bit 16) | every op must fail with EIO; do not send (`osd-ops.md` 4.3) |
| Pool with `pg_num == 0`, or OSD arrays whose length differs from `max_osd` | corrupt |
| OSD address vector without a msgr2 entry for an OSD you must contact | cannot connect; treat that OSD as unreachable rather than failing the whole map |
| `fsid` mismatch with the cluster you authenticated to | wrong cluster |

### 4.4 Related choices

- Map flags PAUSERD / PAUSEWR and pool flag FULL / FULL_QUOTA / EIO: honour them; they change
  whether an op may be sent, not how the map decodes.
- If the map CRC is verified, a mismatch should trigger a re-fetch, not a crash.
- Whether to advertise less than the full feature mask to reduce version variety is a transport
  decision recorded as open question Q1.

---

## 5 Test vectors needed

For each item: how to obtain it and what to compare. Scrub keys and addresses of non-test hosts
before committing. Prefer small clusters with a few pools so vectors stay small.

| # | Vector | Obtain with | Check |
|---|---|---|---|
| T1 | Full map, latest epoch | `ceph osd getmap -o map.bin` (command at `OSDMonitor.cc:5490-5647`); also `ceph-monstore-tool <store> get osdmap -- --version N --out f` (`src/tools/ceph_monstore_tool.cc:190-239`) | decode and compare every field in 2.4.3 with `ceph osd dump -f json` and `osdmaptool map.bin --print`; check wrapper / block / pool `struct_v` values against 2.4.2 |
| T2 | Same cluster at `require_osd_release` squid or reef (set with `ceph osd require-osd-release`) | same | pool version 29, client block 10, no tentacle features **[confirm on capture]**: not run, needs a lower `require_osd_release` and the lab only runs tentacle |
| T3 | Raw incrementals for consecutive epochs, including at least: OSD down, OSD up (new address), reweight, primary-affinity change, pg_temp set and clear, primary_temp set and clear, pg-upmap and upmap-items set and clear, pg-upmap-primary set and clear, pool create, pool delete, new CRUSH map | capture the `MOSDMap` payloads in the harness (msgr2 crc mode so frames are readable); cross-check decoding with `ceph-dencoder type OSDMap::Incremental import <file> decode dump_json` (type registered at `src/tools/ceph-dencoder/osd_types.h:5`) | decoded fields equal the dencoder dump; and apply T3 to T1 gives the same result as the next full map from step T1 repeated at that epoch |
| T4 | MOSDMap with mixed full and incremental entries and with `cluster_osdmap_trim_lower_bound` above your epoch | capture after letting the client fall behind many epochs and after `osd_map_message_max` batching; or after trimming | the 3.2 walk reaches the right final epoch |
| T5 | Address vectors | in T1 and T3: one OSD with v2 only, one with v1 + v2, one never-up OSD, one IPv6 OSD if available | decoded family, port, ip, nonce, type equal `ceph osd dump`; confirm the byte layout of 2.1.2, including IPv6, the 8 zero pad bytes, and that a never-up OSD is the 5-byte empty vector (not an `elen` 28 entry) |
| T6 | Placement | for a set of synthetic object names across pools with and without HASHPSPOOL, pg_num not a power of two, with pg_temp / primary_temp / upmap / upmap-items / upmap-primary / affinity present | compare your up / acting / primary results with `osdmaptool map.bin --test-map-object <name> --pool <id>` and `--test-map-pgs-dump` (`src/tools/osdmaptool.cc:45-57`); cases: OSD out (weight 0), OSD down, destroyed OSD |
| T7 | Envelope-skip robustness | feed a map whose client block `struct_v` is artificially raised and whose tail has extra bytes | accepted when compat allows; rejected when compat is raised |
| T8 | CRC | T1 and T3 | your CRC-32C over the 2.4.5 / 2.6.1 ranges equals the stored value (expected: start 0xFFFFFFFF, no final inversion, 2.4.5); also check that a map obtained with a reduced feature mask (T2-style capture with fewer advertised bits) carries a CRC that matches its own bytes but not the `full_crc` of the neighbouring incremental |
| T9 | Negative inputs | truncated map, oversize `struct_len`, `max_osd` vs vector length mismatch, OSD id out of range in an incremental | rejected without crash or unbounded allocation (fuzz the decoders) |
| T10 | pg_pool_t with snapshots | a pool with several self-managed snapshots (RBD snapshots) and a pool with pool snaps | removed_snaps and snaps decode; skipping by envelope works |
| T11 | Pool versions | a stretch pool if a test cluster is available | version 30 / 32 layout of 2.5 rows 51-52 |

Status of these vectors after the capture run (details: `harness/vectors/osdmap/README.md`; all of it is
re-checked by `harness/tools/osdmap_check.py`):

- T1 done: 89 stored full maps against `ceph-dencoder` JSON, the epoch-42 map also against `osdmaptool`.
- T2 not run (needs a lower `require_osd_release`).
- T3 done from the monitor store, not from the wire: a stock client subscribes with start 0 and receives one full
  map, so no incremental ever crossed the wire in the captures. All 89 stored incrementals are decoded and applied;
  the kinds present are listed in the vector README (no pool deletion, no destroy, no `pg_upmap_primaries`).
- T4 not done (every captured MOSDMap is one full map, trim lower bound 1).
- T5 partly: IPv4, dual-stack and never-up OSDs only.
- T6 done for replicated HASHPSPOOL pools with a power-of-two `pg_num` (2,194 names, 825 `osdmaptool` PG results over
  25 map states); not done for `pg_upmap_primaries`, non-power-of-two `pg_num`, `pg_num` != `pgp_num`, legacy pools.
- T7 and T9 done on synthetic mutations of a real map, plus 3,000 seeded bit-flip inputs.
- T8 done for full-feature maps; the reduced-feature case needs our own client.
- T10 partly: self-managed snapshots only (see 2.9); no pool-snaps pool.
- T11 not run (no stretch pool).

Round 2 (2026-11-16 and 17; `harness/vectors/public/mapb/README.md`, `harness/tools/map_oracle_lab.sh`, the client of `core/`
against the real monitor) changed these statuses:

- T3 also done from the wire: the client of `core/`, subscribed from its held epoch + 1, took 38 and 66 incrementals in two
  runs while the cluster changed (upmap items, reweight, out and in, a pool created, split and deleted, primary affinity), 0 undecodable
  and 0 re-requests, and its placements at its final epoch equal `osdmaptool` on the monitor's map of that epoch. The 259 stored
  incrementals of epochs 667 to 925 add pool deletion (`old_pools`, 14 epochs), `pg_upmap_primaries` set and cleared (2 and 2), `primary_temp`
  (5), `pg_temp` (45) and erasure-code profiles; the core applies all 259 from the full map of epoch 666 and the result equals the monitor's
  own full map at each of the 21 epochs that have one and the `ceph osd dump` of every captured state (ctest `map.vec.full`, `map.vec.pgs`).
  The longest `old_*` list in them has one entry.
- T4 partly: a MOSDMap that carries incrementals now exists on the wire (above). A message that mixes kinds, and a trim lower bound above
  the client's epoch, were not produced.
- T6 done for every state of `harness/vectors/public/mapb` and for the live run: `pg_num` 12 and 7 (not a power of two), `pgp_num` below
  `pg_num`, a split and a merge in progress at every epoch, upmap items (one pair, several, invalid ones), `pg_upmap`, `pg_upmap_primaries`, `pg_temp`
  and `primary_temp`, primary affinity 0, 0.25 and 0.5, reweight and out, `noup` with an OSD down, a pool without HASHPSPOOL, an erasure pool
  and a cache tier (both refused by the core with a status), `choose_args`: 53 states of the live run and 70 captured states, 5,104 PG rows
  against `osdmaptool`, 6,300 names against `ceph osd map`, 0 differences.
- T10 partly more: pool snapshots now exist in `harness/vectors/public/denc-map/pools-e202.bin` (two pool snapshots, recorded pool options,
  application metadata, a cache tier, hit-set parameters; decoded and checked against the `ceph osd dump` pool lines).

---

## 6 Open questions

Q1. **Which feature bits to advertise** and therefore which struct versions arrive. The full mask
(2.7.4) gives the canonical bytes; whether the connection feature negotiation in msgr2 lets the
client advertise exactly that mask, and what the OSD and monitor require of a client for a given
map (2.8, `OSDMap::get_features`), is a msgr2 / auth note topic; the recommended answer is in `msgr2.md` 4.4 (advertise the full v20.2.5 set, `0x3f07fffffffdffff`). **[confirmed for the full mask: osdmap_check.py, 395
connections: the stock client advertises exactly `0x3f07fffffffdffff`; every mon, OSD and mgr advertises the same;
all 17 masks of the 2.7.4 table are contained in it and bit 62 is clear; with it the monitor sent MOSDMap header
version 4 / compat 3, client block 10, pool 32]**. **[confirm on capture]** for several advertised masks: only our
own client can send a reduced mask, the stock client always sends the full one.

Q2. **Lowest `require_osd_release` a v20.2.5 monitor will serve.** Only the OSD startup check
(2.4.2) was found; no equivalent monitor-side floor was located in the code paths read.
**[unverified]**. Determines whether the floors in section 4.1 are always sufficient.

Q3. **CRC details** (2.4.5): start value all ones and the absence of a final inversion are read
from the CRC routine's source; **[confirmed: osdmap_check.py, vector T8, 89 maps and 89 incrementals]**. The CRC
range for a full map is exactly the wrapper minus the CRC field, with an empty tail **[confirmed: same run]**.
Still open: the T8 case of a map re-encoded for a client with fewer feature bits (needs our own client).

Q4. **Verifying an applied incremental.** `full_crc` is the CRC of the new full map's encoding.
A client that does not re-encode cannot check it. Options: re-fetch the full map periodically,
on suspicious OSD replies, or implement a canonical re-encoder (large). Decision deferred.

Q5. **Interaction of `new_weight` and `new_state` in one epoch** (3.5 step 11): the monitor's OSD
creation path relies on the weight side effect and does not put EXISTS in `new_state`
(`OSDMonitor.cc:9778-9781`). Still confirm from real incrementals (create, boot, destroy, purge)
that a non-zero weight never accompanies an EXISTS bit toggle for the same OSD.
Lab result: **[confirmed for the create and boot path: osdmap_check.py, incrementals 3, 8, 13 create OSDs with a
non-zero weight and state NEW, never the EXISTS bit]**; destroy and purge were not exercised.

Q6. **Blocklist handling.** A blocklisted client is rejected by OSDs with error 108
(`EBLOCKLISTED`, `rados.h:499`, `PrimaryLogPG.cc:2130`); the list itself lives in the OSD-only block,
which a minimal client skips (2.4.4). Whether to decode it so the client can fail fast, instead of
reacting to the error reply, is settled in `osd-ops.md` 2.11 and 4.1: treat -108 as fatal for the session and do not decode the list.

Q7. **Removed snapshots** (2.9): does an OSD reject a write that carries a snap id already
removed, or is the snap context pruning purely an optimisation? **[unverified]**

Q8. **Sorted wire order** of maps and sets (2.1) is expected from the ordered containers but was
not pinned for every container used here **[confirmed for the containers present in the lab maps: see 2.1;
`old_pools`, `old_pg_upmap*` and `old_pg_upmap_primary` were empty or single-entry in every incremental, so their
order was not exercised]**.

Q9. **Header version 4 gap field** (2.3): the v20 receiver decodes and discards a non-zero map;
no v20 sender writes one. Whether a future sender could rely on a receiver acting on it is
**[unverified]**.

Q10. **Memory ceiling.** A full map on a large cluster may be many megabytes (OSD-only block,
pools, CRUSH). Whether the iPXE heap and the Windows non-paged pool can hold a received message
while decoding, or whether a streaming decoder over frame segments is required, needs
measurement on a realistic map. The decode order (client block first, then skip) allows streaming
for everything except the optional CRC.

Q11. **Addresses.** The IPv4 / IPv6 sockaddr byte layouts in 2.1.2 are inferred from the platform
structures; confirm with T5, including what a v1-only OSD looks like, how a dual-stack OSD's
vector is ordered, and that no OSD address in a real map has an `elen` other than 16 or 28.
Lab result: dual-stack order is v2 then v1, every `elen` is 16, no IPv6 and no v1-only OSD exist in the lab
(see 2.1.3); the IPv6 half stays open.

Q12. **OSDs with multiple addresses.** The reference messenger connects to the first entry whose
type is 1 or 2 after its own bind-config filtering (`AsyncMessenger.cc:846-857`, 3.8); the exact
filter (`_filter_addrs`) was not read, and which entry the daemon lists first (v2 before v1 is
expected) is **[confirmed: osdmap_check.py, 235 dual-stack vectors, v2 entry first, v1 second]**; the exact filter is
still unread. The note assumes "first entry of type 2".

Q13. **Nested length checks.** The reference decoder compares an inner `struct_len` only against
the bytes left in the whole buffer (2.2). The stricter rule in 2.2 (inner end within outer end) is
this note's recommendation; confirm it never rejects a real map (T1, T3, T10).

Q14. **Feature bits the client must advertise to receive version-10 / 32 encodings and to be
accepted by OSDs** (2.7.4, 2.8): `OSDMap::get_features` lists the bits the map requires of clients
(CRUSH tunables, hashpspool, primary affinity, upmap, reef bit for upmap-primary, MSR rules, cephx v2),
but the list was not cross-checked against what the monitor and OSD enforce at connection time
**[unverified]**; msgr2 / auth notes own the answer.

Q15. **Pool versions 31 and above beyond 32.** v20.2.5 writes 32 at most; a later point release could
add fields at the end. The envelope length makes that safe for decoding, but any newly meaningful
field (a flag, a placement rule) would be silently ignored; re-check the pool tables when pinning
a different release.

### Corrections after capture

What the capture run changed in this note (the lab: one tentacle cluster, IPv4 only, 89 stored epochs, 39 pcaps):

1. **No table was wrong.** Every row of 2.4.3, 2.5 (struct_v 32, rows 1 to 53) and 2.6.3 decoded all 178 stored maps
   and incrementals (and the 24 intermediate maps and the 79 maps seen on the wire) and ended exactly at the envelope
   end; the decoded values equal the `ceph-dencoder` JSON field by field. No version number, size or order in
   sections 2.1 to 2.6 had to be corrected.
2. **Marks changed from [confirm on capture] to confirmed:** sorted wire order (2.1, 3.8, Q8); IPv4 sockaddr layout
   (2.1.2) and the worked layout of an address vector (2.1.3); CRC rule for maps and incrementals (2.4.5, 2.6.1, Q3,
   T8); `MOSDMap` answer to a start-0 subscription (3.1); full-mask advertisement and received versions (Q1, first
   half); address order v2 before v1 (Q12); create path of Q5.
3. **Added facts (no earlier statement was contradicted):**
   - the monitor's trim lower bound in MOSDMap equals the store's `first_committed` (1 in the lab); the stock client
     subscribes to `osdmap` ONETIME with start 0, then with start = epoch + 1 (2.3, 3.1);
   - the full map and the stored map are byte-identical when the client advertises the full mask (2.8);
   - the `crush` blob inside a full map has no MSR tunable pair, the one in an incremental's `crush` field has it
     (crush note 2.1 (a), **confirmed**); the rule min / max bytes could not be told apart, every rule stores 1 / 100;
   - `new_primary_affinity` is on the wire as table 2.6.3 says; the dencoder JSON dump omits it, so a JSON-based
     test must take it from the bytes (epochs 55 and 57);
   - the pool record's `removed_snaps` stays empty on a tentacle cluster; removals arrive through
     `new_removed_snaps` and `new_purged_snaps` (2.9);
   - `osdmaptool`'s "raw" column is the CRUSH output after dropping non-existent OSDs and before upmap, which is what
     3.7 step 6 produces; primary affinity (3.7 step 9) changed 5 primaries in the oracle runs and every answer was
     reproduced; upmap items, upmap, `pg_temp`, `primary_temp`, reweight, out and down were each reproduced.
4. **Oracle quirk to remember when building vectors:** `ceph osd map` hashed an object name containing a non-BMP
   character (an emoji) as two separate 3-byte surrogates, not as UTF-8, because of how the monitor's JSON command
   parser treats `\u` escapes. The placement pipeline is right; the vector must carry the bytes the oracle hashed.
5. **Still marked, and why the captures cannot settle them:** IPv6 sockaddr layout and a non-Linux family number (no
   such sender in the lab); the `require_osd_release` floor, T2 and the older rows of the table in 2.4.2 (the lab only
   runs tentacle); Q7 and 2.9 (needs an OSD-op test with a stale snap context); Q9 (no sender writes a non-zero gap
   map); Q10 (no memory measurement); Q14 (needs our own client advertising reduced masks); re-subscribing with a
   low start (3.1); a MOSDMap carrying incrementals, a mix of kinds, or a trim bound above the client's epoch (T4);
   the re-encoded-for-fewer-features CRC case (T8). Never exercised by any lab epoch, so the corresponding steps of
   3.5 and 3.7 are checked against the note's text only: `old_pools`, OSD destroy, `new_state` mask 0, shrinking
   `max_osd`, `pg_upmap_primaries` (decode of rows 28 / 29 and 25 only with empty maps), stretch pool rows 51 / 52 with
   data, non-power-of-two `pg_num`, `pg_num` != `pgp_num`, pools without HASHPSPOOL. (Round 2, below, settled the memory
   measurement, re-subscribing with start 0, a MOSDMap carrying incrementals, and every item of that last list except OSD
   destroy, `new_state` mask 0, shrinking `max_osd` and the stretch pool.)

### Corrections after the second capture round (2026-11-16 and 17)

Evidence: the public set `harness/vectors/public/mapb/` (a base map of epoch 666, 259 incrementals to epoch 925, 21 full maps, 70 captured
states S1 to S15, a name oracle of 3,352 `ceph osd map` answers over 8 pools, 18 offline CRUSH maps and 8 offline OSDMaps, all checked
against `ceph-dencoder`); the live comparison `harness/tools/map_oracle_lab.sh` (53 states made on the lab with the admin CLI, every PG of every pool of every
state against `osdmaptool`, 6,300 names against `ceph osd map`, 901 comparisons with `ceph osd dump`, a chain of 149 incrementals, 0 differences,
the cluster restored and the restore verified); and the client of `core/` itself, which logged in to the real monitor with both key types,
took its maps and incrementals over msgr2, and was compared with `osdmaptool` on the monitor's map of its final epoch (400 placements, 0 differences).

1. **No row, version, size, order or rule of 2.1 to 2.6 and 3.3 to 3.7 had to be corrected.** The new states reach more of the note than round 1
   did (pool deletion, upmap primaries, split and merge, legacy pools, an erasure pool, a cache tier, `choose_args`) and every one was
   reproduced. The two things the review of the implementation found were in the code, not in the note: with a stored `primary_temp` of -1 and
   no usable `pg_temp` the acting primary is the up primary (3.7 step 7 says so; a test model had it wrong).
2. **Marks changed from [unverified] / [confirm on capture] / "never exercised" to confirmed:**
   - `old_pools` (a pool deleted: 14 epochs of the 259) and the pool-name records of a rename and a create (3.5; `pool_max` never goes down, a
     deleted id is not reused);
   - `pg_upmap_primaries`: rows 25, 28 and 29 with data (two sets and two clears) and the swap rule of 3.7 step 3, checked against `osdmaptool` primaries;
   - `pg_num` not a power of two (12 and 7), `pg_num` != `pgp_num` (12 with 8, 7 with 4, and every epoch of a split and of a merge with
     `pg_num_pending`), pools without HASHPSPOOL: 2.5 flags, 3.7 `stable_mod` and `pps`;
   - 3.1: re-subscribing with start 0 on a session that already received maps is answered with one full map of the held epoch (the mark at the end of 3.1);
   - T4, first half: a MOSDMap that carries incrementals is what a client subscribed from its own epoch + 1 receives (38 and 66 incrementals taken
     in two runs while the cluster changed, none undecodable, none re-requested);
   - Q10 (memory ceiling): measured on generated clusters (`docs/design/core-architecture.md` 15.3, 18.2): a full map costs 429 to 436 bytes per OSD
     at 2,048 to 8,192 OSDs without device classes and 478 to 485 with two, 487 to 539 at 100 OSDs; a 4 MiB message holds about 9,000 OSDs. No
     streaming decoder is needed up to that size: the client holds the message and decodes the client block in place, skipping the OSD-only block by length.
3. **Added facts (no earlier statement was contradicted):**
   - the monitor accepts a `pg_upmap_items` pair whose `to` is already in the set and keeps it (3.7 step 3 skips such a pair); a pair whose `from` is not in the
     set is accepted and removed in the epoch that would have carried it; a `pg_upmap` naming an OSD of weight 0 exists for the epoch of the reweight;
   - `pg_temp` entries are cleared by the OSDs within a few epochs, `primary_temp` is not (it stays until removed); in `ceph osd dump -f json` the `primary_temp` table is a
     flat list `[pgid, osd, ...]`;
   - a `primary_temp` naming an OSD that is not in the acting set (for instance because it was marked out) crashes that OSD (v20.2.5, an assertion in the peering
     code): the lab capture clears every temp before it marks an OSD out;
   - the CRUSH blob inside an incremental has the two MSR tunables that the blob inside a full map of the same epoch lacks (2.1 (a) again, now with 259 more
     incrementals): compare decoded structures, never bytes;
   - the monitor keeps only the last 500 epochs, so history before the capture window is gone; `ceph-dencoder` of this release crashes in `dump_json`
     for a map with a non-default primary affinity (`decode` alone, which verifies the CRC, is fine);
   - a comparison of a client's table with `ceph osd map` at a LATER epoch than the client's shows differences that are not placement errors when the pool's `pg_num` moves in between
     (the first live attempt compared the client's epoch 2442 with the cluster's 2447 on a pool whose autoscaler was on, and differed for that pool: the first ten differences listed were all in it).
     Compare at the client's own epoch: `ceph osd getmap <epoch>` and `osdmaptool` on that file. Both reruns did, one with the autoscaler off and one with it on, and had 0 differences over
     400 placements each (44 and 64 distinct PGs, epochs 2540 and 2599).
4. **Still marked, and why round 2 could not settle them:** IPv6 sockaddr layout and a non-Linux family number (the lab is IPv4 only); the
   `require_osd_release` floor, T2 and the older rows of 2.4.2 (the lab only runs tentacle); Q7 and 2.9 (needs an OSD-op test with a stale snap context);
   Q9 (no sender writes a non-zero gap map); Q14 and the re-encoded-for-fewer-features CRC case of T8 (needs a client advertising a reduced mask); T4 second half (a message
   that mixes full maps and incrementals, a trim lower bound above the client's epoch); Q8 for a multi-entry `old_*` list (the longest in any incremental has one entry; the
   core refuses unsorted keys with `WR_E_MAP_CORRUPT`, and no incremental of the 259 + 149 + 104 applied violated that); OSD destroy and purge, `new_state` mask 0, shrinking
   `max_osd` (the lab rules forbid removing OSDs), and a stretch pool (rows 51 and 52 are decoded from synthetic bytes only and cross-checked with `ceph-dencoder`
   in `mapgen_dencoder_check.sh`, never with a pool the cluster made).

---

## 7 Licensing questions

1. The numeric tables in this note (feature bit numbers, state and flag bit values, struct version
   numbers, field orders) are protocol facts and layouts, described in my own words. No code,
   comments or function bodies from Ceph were copied. Reviewers should confirm the layout tables
   are acceptable as "facts" for an MIT core.
2. The per-field "since" version columns and the order of fields are a transcription of what the
   source encodes. They are needed for byte-exact decoding and cannot be reduced further; if a
   stricter view is wanted, the alternative is to regenerate them from captures
   (`ceph-dencoder` output) instead of from source.
3. The feature-mask hex values in 2.7.4 are computed by me from the bit numbers and incarnation
   rule, not copied as a table. The bit numbers themselves are Ceph constants.
4. The Ceph files referenced are mostly LGPL-2.1 per their headers (for example the header of
   `src/messages/MOSDMap.h`); per-file licences for every file read have not been audited,
   consistent with the open item in `LICENSE`.
5. Test vectors captured from a live cluster contain fsids, addresses and pool names; they must
   be scrubbed (CONTRIBUTING rule 4) before being committed.
6. The CRC-32C routine in the Ceph tree is driven by large lookup tables. This note gives only the
   polynomial, the start value and the absence of a final inversion; the implementer must generate
   the table from the polynomial, not copy it. Likewise the varint format in 2.1 is described, not
   copied.
