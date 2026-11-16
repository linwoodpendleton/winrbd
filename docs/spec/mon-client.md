# Monitor client: monmap, subscriptions, OSDMap delivery, session lifecycle

Status: draft spec note, Phase 0. Target release: Ceph v20.2.5 (Tentacle), commit
ed27c686770872022f4c1de04f6b0ac5d5384ded. All source references are `path:line` relative to the
root of that tree (so `src/...` for code and `doc/...` for docs). Everything is written in our own
words; layout tables and numeric constants are protocol facts.

Markers used below:

- **[unverified]**: not pinned in the source we read; also listed in section 6.
- **[confirm on capture]**: source says so, but the bytes must be checked on a live v20.2.5 cluster
  before the core relies on it; also listed in section 5.
- **[confirmed: <capture / tool>]**: checked after the fact against the Phase 0 capture set (39 pcaps of a
  stock Ceph 20.2.5 client on the lab cluster) with the independent checker
  `harness/tools/monclient_check.py` (our own msgr2 / cephx / monitor-client decoders, no Ceph decoder in
  the loop; ground truth from `ceph mon dump`, `ceph mon getmap` and the monitor-store copies of every
  map). Scrubbed vectors: `harness/vectors/monclient/`. Items that were corrected instead of confirmed are
  listed at the end of section 6 ("Corrections after capture").

## 1 Scope and sources

### 1.1 What this note covers

What a minimal CLIENT (never a server) does with the monitors once it can open a msgr2 connection
and run the auth handshake (those two are separate notes):

- turning `mon_host` into an initial list of monitors to try (including v2 addresses and the
  default ports 3300 / 6789);
- obtaining and decoding the real MonMap (messages MMonGetMap and MMonMap);
- the global_id the monitor hands out and how it is reused across reconnects;
- subscribing (MMonSubscribe) to the monmap and the osdmap, and what the monitor does with the
  subscription;
- receiving MOSDMap (full maps, incrementals, `cluster_osdmap_trim_lower_bound`, `newest_map`),
  and how a client asks for a missing range;
- the optional MMonGetVersion / MMonGetOSDMap helpers;
- keepalive, hunting and failover between monitors, session reset;
- renewing cephx service tickets through the monitor (MAuth / MAuthReply after the session exists).

Out of scope here (other notes): msgr2 banner / frames / handshake tags, the cephx cipher and
ticket byte layout, the inner encoding of OSDMap and OSDMap::Incremental, CRUSH, and OSD
operations.

### 1.2 Sources read

Ceph code (all under `src/`):

- `mon/MonClient.cc`, `mon/MonClient.h`, `mon/MonSub.cc`, `mon/MonSub.h`: the client-side state
  machine.
- `mon/MonMap.cc`, `mon/MonMap.h`, `mon/mon_types.h`: MonMap structure and encoding, initial map
  construction from `mon_host`.
- `messages/MMonSubscribe.h`, `messages/MMonSubscribeAck.h`, `messages/MMonMap.h`,
  `messages/MMonGetMap.h`, `messages/MOSDMap.h`, `messages/MMonGetVersion.h`,
  `messages/MMonGetVersionReply.h`, `messages/MMonGetOSDMap.h`, `messages/MAuth.h`,
  `messages/MAuthReply.h`, `messages/MPing.h`, `messages/MConfig.h`,
  `messages/PaxosServiceMessage.h`.
- `include/ceph_fs.h`, `include/msgr.h`, `msg/Message.h`, `msg/Message.cc`,
  `include/ceph_features.h`, `include/encoding.h`: message type numbers, header layout, encoders.
- `msg/msg_types.h`, `msg/msg_types.cc`, `common/ceph_argparse.cc`, `common/addr_parsing.c`,
  `common/str_list.cc`: address types, address text parsing.
- Server side, only to learn what the monitor does with the client's requests (not for server
  code): `mon/Monitor.cc`, `mon/OSDMonitor.cc`, `mon/MonmapMonitor.cc`, `mon/AuthMonitor.cc`,
  `mon/Session.h`, `auth/cephx/CephxServiceHandler.cc`.
- Reference client behaviour (the Objecter and librados) to see how the OSDMap is consumed:
  `osdc/Objecter.cc`, `librados/RadosClient.cc`.
- Option defaults: `common/options/global.yaml.in`, `common/options/mon.yaml.in`.

Docs: a search of `doc/` for the message names (MMonSubscribe, MMonMap, MMonGetMap, MOSDMap) finds
only changelogs and `doc/dev/osd_internals/map_message_handling.rst` (OSD-side handling, no wire
layout), so the source is the only reference for the layouts. Doc pages used for facts:
`doc/rados/configuration/msgr2.rst:21-24` (monitors bind 3300 by default), `:59-61` (example
address vectors), `:70-72` (`mon_host` accepts the bracketed address-vector syntax), `:217-221`
(example `mon_host` values).

### 1.3 Conventions

- Every integer on the wire is little endian (`src/include/encoding.h:112-129` defines the integer
  encoders through little-endian wrapper types).
- `string` = u32 length + bytes, no terminator (`src/include/encoding.h:226-240`).
- `bufferlist` as a field = u32 length + bytes (`src/include/encoding.h:312-317`).
- `map<K,V>` = u32 count + (key, value) pairs in key order; `vector<T>` / `set<T>` = u32 count +
  elements (`src/include/encoding.h:831-851` set, `:950-956` vector, `:1079-1087` map). Those are the
  generic encoders; for element types with a fixed-size integer encoding the code may pick the
  denc-based container encoders in `src/include/denc.h` instead (e.g. `set<u32>`, `vector<i32>` in the
  MonMap). Whether the denc containers are byte-identical (they also lead with a u32
  count, `src/include/denc.h:982-989`; element bytes not traced): **[confirmed: every MMonMap in
  `pcap/*`, `gt/mon-dump.json`]** for `vector<i32>` (`auth_allowed_ciphers` = u32 count 2, then the i32
  values 1 and 2, equal to `ceph mon dump`) and for the count of the empty `set<u32>` / `set<string>`
  fields; the element bytes of a NON-empty `set<u32>` (`removed_ranks`) stay **[unverified]** (the lab
  monmap has no removed rank).
- `epoch_t` = u32, `version_t` = u64, `ceph_tid_t` = u64 (`src/include/types.h:412-414`).
- `uuid` (fsid) = 16 raw bytes, no length prefix (`src/include/uuid.h:70-72`).
- `utime_t` and C++ `time_point` fields = u32 seconds + u32 nanoseconds
  (`src/include/utime.h:163-171`, `src/include/encoding.h:343-356`).
- Versioned struct envelope ("ENCODE_START"): u8 struct_v, u8 struct_compat, u32 struct_len, then
  `struct_len` bytes of body (`src/include/encoding.h:1455-1482`). A decoder that understands up to
  version V must fail if `struct_compat > V`, and after reading the fields it knows must skip to
  the end given by `struct_len` (`src/include/encoding.h:1511-1530, 1651-1659`). This is how
  newer servers add trailing fields without breaking older clients; our decoders must do the same.

## 2 Wire structures

### 2.1 Message envelope fields that matter for monclient

The full msgr2 message frame is described in the msgr2 note. The per-message header
(`ceph_msg_header2`, `src/include/msgr.h:207-222`) carries these fields in this order:

| Field | Type | Meaning for monclient |
|---|---|---|
| seq | u64 | per-session message sequence, owned by the messenger layer |
| tid | u64 | transaction id; monclient does not set it on its own requests (see 2.7: version requests use `handle` in the body instead); a monitor copies the request tid into replies it builds for MMonGetVersion |
| type | u16 | message type, table 2.2 |
| priority | u16 | a message whose priority is still 0 gets the messenger default 127 (`CEPH_MSG_PRIO_DEFAULT`, `src/include/msgr.h:226`) when it is sent (`src/msg/async/AsyncConnection.cc:570-571`, default set at `src/msg/Messenger.cc:68`); no monclient message sets its own, so expect 127 on the wire **[confirmed: `pcap/*`, 714 of 714 messages the client sent to a monitor carry 127, and the monitor accepted all of them]**. Messages the MONITOR sends carry 196 (`CEPH_MSG_PRIO_HIGH`) on every reply and push (all 949 monitor messages checked); a client must not insist on 127 when receiving |
| version | u16 | encoding version of the body (HEAD version of that message type) |
| data_pre_padding_len | u32 | messenger layer |
| data_off | u16 | messenger layer |
| ack_seq | u64 | messenger layer |
| flags | u8 | messenger layer |
| compat_version | u16 | oldest decoder that can read the body; a message class that passes no compat gets compat = version on the wire (`src/msg/Message.cc:250-251`), so for example MMonGetMap goes out as version 1 / compat 1 and MMonGetVersionReply as version 2 / compat 2 |
| reserved | u16 | zero |

Receiver rule for `version` / `compat_version`: the receiver refuses to decode a message when its
own highest known version is lower than the message's `compat_version`
(`src/msg/Message.cc:984-993`). So a client that implements MOSDMap v4 (compat 3) may receive a
future v5 with compat 3 and must still parse it, ignoring trailing bytes. Decoders choose their
field layout from the message's own `version` (for example MOSDMap, 2.6), so the receiver must
honour `version` and cannot assume the HEAD layout.

### 2.2 Message types a monclient sends or receives

Constants: `src/include/ceph_fs.h:135-185`, `src/msg/Message.h:55-72, 120-121`.

| Number | Name | Direction | Used by a minimal client? | Body version sent |
|---|---|---|---|---|
| 2 | CEPH_MSG_PING (MPing) | both | optional | v1, empty body (`src/messages/MPing.h:18-26`) |
| 4 | CEPH_MSG_MON_MAP (MMonMap) | mon to client | required | v1, compat 0 in the class (wire compat 1) |
| 5 | CEPH_MSG_MON_GET_MAP (MMonGetMap) | client to mon | required (first message, see 3.3) | v1, empty body |
| 6 | CEPH_MSG_MON_GET_OSDMAP (MMonGetOSDMap) | client to mon | optional | v1 (wire compat 1) |
| 15 | CEPH_MSG_MON_SUBSCRIBE (MMonSubscribe) | client to mon | required | v3, compat 1 |
| 16 | CEPH_MSG_MON_SUBSCRIBE_ACK (MMonSubscribeAck) | mon to client | must tolerate | v1 |
| 17 | CEPH_MSG_AUTH (MAuth) | client to mon | required for ticket renewal | v1 (wire compat 1) |
| 18 | CEPH_MSG_AUTH_REPLY (MAuthReply) | mon to client | required for ticket renewal | v1 |
| 19 | CEPH_MSG_MON_GET_VERSION (MMonGetVersion) | client to mon | optional | v1 (wire compat 1) |
| 20 | CEPH_MSG_MON_GET_VERSION_REPLY | mon to client | only if 19 is used | v2 (wire compat 2) |
| 41 | CEPH_MSG_OSD_MAP (MOSDMap) | mon to client | required | v4, compat 3 for a full-feature client; v1 or v2 for a client lacking PGID64/PGPOOL3/OSDENC (2.6) |
| 62 | MSG_CONFIG (MConfig) | mon to client | skip (only sent if subscribed to "config") | v1 (compat 1; **[confirmed: `pcap/*`]**, 188 bytes in the lab) |
| 63 | MSG_GET_CONFIG | client to mon | skip | |
| 50 / 51 | MSG_MON_COMMAND / _ACK | both | skip (not needed to read or write an image) | |
| 52 / 53 | MSG_LOG / MSG_LOGACK | both | skip | |
| 97 / 98 | MSG_COMMAND / MSG_COMMAND_REPLY | both | skip | |

Message types the reference MonClient dispatches (everything else is passed on or dropped):
4, 18, 16, 20, 51, 98, 53, 62, and it silently discards 2 (`src/mon/MonClient.cc:314-333`).
MOSDMap (41) is not handled by MonClient; the reference client's Objecter consumes it
(`src/osdc/Objecter.cc:1068-1071`).

A client must ignore (not abort on) message types it does not implement. **[confirmed:
`pcap/*`, all 243 monitor connections]** that a monitor sends nothing unsolicited: every message it sent
answers something the client sent first (MMonMap <- MMonGetMap or the "monmap" subscription, MConfig <-
"config", MOSDMap <- "osdmap", the mgrmap push <- "mgrmap", MMonCommandAck <- MMonCommand, MAuthReply <-
MAuth) and nothing arrives before the client's first message. Caveat: the stock tools always subscribe to
"config" and "mgrmap" as well, so a session with ONLY {monmap, osdmap} was not captured. Types seen from
the monitor over the whole set: 4, 18, 41, 51, 62 and 1796 (never 16, 19, 20, 6). The monitor-sent 1796
(0x704) is the push for a "mgrmap" subscription (53,337 bytes in the lab); a minimal client never subscribes
to it and never sees it. Note also that the stock `ceph` CLI pulls a 246,845-byte command description with
MMonCommand (types 50 / 51) at start-up; that is tool behaviour, not needed here.

### 2.3 MMonGetMap (type 5), client to monitor

Empty body (`src/messages/MMonGetMap.h:20-37`). Class header version 1, compat 0 (so the sender
writes compat = 1, `src/msg/Message.h:340-344`, `src/msg/Message.cc:250-251`). The monitor answers
with MMonMap
(`src/mon/Monitor.cc:5590-5595`, dispatch at `src/mon/Monitor.cc:4722-4724`).

### 2.4 MMonMap (type 4), monitor to client

Body: one `bufferlist` field (u32 length + bytes) holding the encoded MonMap
(`src/messages/MMonMap.h:38-55`). The monitor encodes the map for the features of the connection:
`monmap->encode(bl, con->get_features())` (`src/mon/Monitor.cc:5583-5588`).

#### 2.4.1 MonMap (what the monitor sends a nautilus-or-newer client: struct_v 10)

The envelope for the current encoding is struct_v = 10, struct_compat = 6
(`src/mon/MonMap.cc:254`), so the blob inside MMonMap starts with the bytes `0a 06` followed by a
u32 length, then the 16-byte fsid. Fields in order (`src/mon/MonMap.cc:254-288`):

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | fsid | 16 raw bytes | cluster id; also used to check every MOSDMap |
| 2 | epoch | u32 | monmap epoch |
| 3 | last_changed | u32 sec + u32 nsec | |
| 4 | created | u32 sec + u32 nsec | |
| 5 | persistent_features | mon_feature_t | envelope (v1, compat 1, len 8) + u64 bit mask (`src/mon/mon_types.h:489-499`) |
| 6 | optional_features | mon_feature_t | same |
| 7 | mon_info | map<string, mon_info_t> | key = monitor name; value in 2.4.2 |
| 8 | ranks | vector<string> | monitor names in rank order |
| 9 | min_mon_release | u8 | release number; tentacle = 20 (`src/common/ceph_releases.h:13-35`, enum encoded as its underlying u8 by `src/include/denc.h:305-310`) |
| 10 | removed_ranks | set<u32> | |
| 11 | strategy | u8 | election strategy: 1 classic, 2 disallow, 3 connectivity (`src/mon/MonMap.h:167-173`) |
| 12 | disallowed_leaders | set<string> | |
| 13 | stretch_mode_enabled | u8 (bool) | |
| 14 | tiebreaker_mon | string | |
| 15 | stretch_marked_down_mons | set<string> | |
| 16 | auth_epoch | u32 | cephx key-generation epoch; see 3.9 |
| 17 | auth_service_cipher | i32 | 0 none, 1 AES, 2 AES256KRB5 (`src/include/ceph_fs.h:95-97`) |
| 18 | auth_allowed_ciphers | vector<i32> | |
| 19 | auth_preferred_cipher | i32 | |

Fields 16-19 are the "struct_v >= 10" additions (`src/mon/MonMap.cc:351-357`). The older shapes the
decoder also handles (v1 and v2 legacy, v3-v9) are not needed: a client that advertises the
features in 2.9 is sent v10. The decoder entry is "DECODE_START_LEGACY_COMPAT_LEN_16(10, 3, 3)"
(`src/mon/MonMap.cc:293`), which means: struct_v is read first as a u8; versions below 3 are
the legacy 16-bit-version layouts (skip one byte, no length), version 3 and above carry the
compat byte and the length.

For a minimal client, the useful fields are fsid, epoch, mon_info (names and addresses, priority,
weight), and ranks. Everything else is parsed only to get past it, or skipped through
`struct_len`.

#### 2.4.2 mon_info_t (value type of field 7)

Envelope struct_v = 6 (v2 only when the peer lacks the nautilus feature bit; the v2 form carries one
legacy single address instead of an address vector), compat 1 (`src/mon/MonMap.cc:54-90`; the
decoder reads the address with the address-vector decoder in every version, `src/mon/MonMap.cc:92-96`,
so a legacy marker 0 can appear there). Decode rules by version: priority exists from v2, weight from v4,
crush_loc from v5, time_added from v6 (`src/mon/MonMap.cc:92-110`).

| Field | Type | Notes |
|---|---|---|
| name | string | e.g. "a" for mon.a |
| public_addrs | entity_addrvec_t | the addresses clients use (2.4.3) |
| priority | u16 | lower value is preferred during hunting (`src/mon/MonMap.h:57-62`, used at `src/mon/MonClient.cc:866-880`) |
| weight | u16 | used for random weighting among equal priority |
| crush_loc | map<string,string> | ignore |
| time_added | u32 sec + u32 nsec | ignore |

#### 2.4.3 entity_addrvec_t and entity_addr_t

An address vector is what the monitor publishes per monitor: normally one v2 address and one v1
address of the same monitor, e.g. `[v2:10.0.0.1:3300/0, v1:10.0.0.1:6789/0]`.

`entity_addrvec_t` (`src/msg/msg_types.cc:334-391`): first a u8 marker.

- marker 2: u32 count, then `count` entity_addr_t values (this is what a current monitor sends
  when the client advertises MSG_ADDR2, `src/msg/msg_types.cc:334-342`).
- marker 1: a single entity_addr_t body follows (marker byte already consumed).
- marker 0: legacy single-address form (`src/msg/msg_types.cc:351-358`). After the marker byte the
  layout is: u8 0, u16 0, u32 nonce, then a 128-byte sockaddr_storage image whose first two bytes
  (sa_family) are BIG endian, unlike the v2-form family field (`src/msg/msg_types.h:454-470` for the
  address reader, `src/msg/msg_types.h:144-160` for the 128-byte struct and the family byte order,
  `src/msg/msg_types.h:198-202` for the Linux decoder that byte-swaps the family). The type becomes "none" when the family is 0 and
  "legacy (v1)" otherwise. A v2-only client cannot use such an address; treat a map whose only
  addresses are of this form as unusable and fail with a clear message. A marker above 2 is a decode
  error (`src/msg/msg_types.cc:388-389`).

`entity_addr_t` as used inside a vector (`src/msg/msg_types.h:476-540`):

| Field | Type | Notes |
|---|---|---|
| marker | u8 | = 1 |
| (envelope) | u8 struct_v = 1, u8 struct_compat = 1, u32 struct_len | `ENCODE_START(1, 1)` |
| type | u32 | 0 none, 1 legacy (v1), 2 msgr2 (v2), 3 any, 4 cidr (`src/msg/msg_types.h:239-245`); when the receiver lacks SERVER_NAUTILUS the sender writes 3 as 1 (`src/msg/msg_types.h:488-497`) |
| nonce | u32 | per-process nonce of the daemon; the connect target for msgr2 is ip:port, the nonce is part of the identity checked in the msgr2 handshake **[unverified]** whether a client must verify it (observed: the lab monitor's nonce is 0 in the MonMap and the stock client sends exactly that address, nonce 0, as CLIENT_IDENT `target_addr`; no capture has a wrong nonce, so whether it is checked is not settled) |
| elen | u32 | length of the sockaddr that follows (family field included); 0 means no sockaddr at all; a decoder must reject elen < 2 and an elen larger than the sockaddr it can hold (`src/msg/msg_types.h:538-550`) |
| sa_family | u16, only if elen > 0 | 2 = IPv4, 10 = IPv6 (Windows builds map their own AF_INET6 to the Linux value 10 on the wire, `src/msg/msg_types.h:506-523`) |
| sa_data | elen - 2 bytes | see below |

sa_data for IPv4 (elen = 16): 2 bytes port in network byte order, 4 bytes address, 8 zero bytes.
For IPv6 (elen = 28): 2 bytes port (network order), 4 bytes flow info, 16 bytes address, 4 bytes
scope id. These follow the in-memory C socket address structures (`src/msg/msg_types.h:321-329`
gives the length rule); the exact byte positions **[confirmed: `pcap/*` MonMap addresses, `gt/monmap.bin`]** for IPv4: struct_v 1 / compat 1 / struct_len 28, type, nonce, elen 16, family 2 (little endian), port big endian, 4 address bytes, 8 zero bytes, 14 `sa_data` bytes in total, and the whole MonMap blob is byte-identical to `ceph mon getmap`. The IPv6 layout stays **[confirm on capture]** (the lab has no IPv6 monitor address, T4).

Pick rule for a connecting client: the reference messenger takes the first address in the vector
whose type is v1 or v2 and skips entries of any other type; vector order decides, there is no
preference for v2 over v1 (`src/msg/async/AsyncMessenger.cc:846-857`). A v2-only client takes the
first entry with type 2 and ignores the rest. The reference hands the whole address vector of the
chosen rank to the messenger (`src/mon/MonClient.cc:846-860`).

### 2.5 MMonSubscribe (type 15) and MMonSubscribeAck (type 16)

#### 2.5.1 MMonSubscribe body (version 3)

Header version 3, compat_version 1 (`src/messages/MMonSubscribe.h:34-40`). Body, when the peer has
the SUBSCRIBE2 feature (`src/messages/MMonSubscribe.h:78-97`):

| Field | Type | Notes |
|---|---|---|
| what | map<string, item> | u32 count, then for each entry: string name, item |
| hostname | string | short host name of the client (`src/mon/MonClient.cc:1126`); informational: the monitor stores it in the session only when it is non-empty (`src/mon/Monitor.cc:5390-5392`), so an empty string is accepted |

Item (9 bytes, packed, no envelope; `src/include/ceph_fs.h:271-274`, raw-encoded per
`src/include/types.h:403`):

| Field | Type | Meaning |
|---|---|---|
| start | u64 | first version (epoch) the client wants; 0 = "give me the latest" |
| flags | u8 | bit 0 = ONETIME (`src/include/ceph_fs.h:269`): send once, then drop the subscription |

**[confirmed: `pcap/*`, 445 of 445 MMonSubscribe the stock client sent, `harness/vectors/monclient/mmonsubscribe-*.json`]**: header version 3 / compat 1, the body is exactly map<string, 9-byte item> + hostname (decoding then re-encoding with the layout above reproduces the wire bytes), entries are in name order, flags are 0 or 1, the hostname is the short host name of the client machine. The derived 28-byte example in section 5 is the same encoding.

If the connection lacks the SUBSCRIBE2 feature bit, the sender falls back to a version-0 body in an
older layout (`src/messages/MMonSubscribe.h:80-93`). A client that advertises SUBSCRIBE2 never
receives or sends that form.

Subscription names the monitor understands that matter here
(`src/mon/Monitor.cc:5394-5487`):

| Name | Needed capability | What the monitor sends |
|---|---|---|
| "monmap" | none | MMonMap whenever its epoch is at least `start` (immediately if `start` is 0 or already reached), then again on every change unless ONETIME (`src/mon/MonmapMonitor.cc:1548-1564`) |
| "osdmap" | "osd" read (**corrected**: a user whose only cap is `mon r`, no osd caps at all, is answered; see Corrections) | MOSDMap messages, see 2.6 and 3.5 |
| "config" | none | MConfig with config values for this entity; optional, a minimal client does not subscribe |
| "mgrmap", "mdsmap", "fsmap", "servicemap", ... | various | not needed; any name other than the ones handled specially needs the "mon" read capability or it is dropped (`src/mon/Monitor.cc:5427-5431`) |

A subscription for which the session lacks the capability is silently dropped: no error message
comes back (`src/mon/Monitor.cc:5406-5412`) **[confirm on capture]** (not exercised: the only restricted
users captured, `client.t0-noosd` with `mon r` only and `client.t0-ro` with `mon r, osd r pool=winrbd`, were BOTH
answered with a MOSDMap, so neither lacked the capability; a user with narrower mon caps would be needed). From the client's point of view this looks like
a monitor that never answers.

Subscribing again with the same name replaces the previous entry of that name on that session
(`src/mon/Session.h:263-277`: the stored `next` and `onetime` are overwritten). Re-sending the
whole set on a new session is the normal recovery path (3.7).

#### 2.5.2 MMonSubscribeAck body

| Field | Type |
|---|---|
| interval | u32 (seconds) |
| fsid | 16 raw bytes |

(`src/messages/MMonSubscribeAck.h:39-49`.) The monitor only sends it to clients that do NOT
advertise MON_STATEFUL_SUB, and only if at least one non-ONETIME subscription was sent
(`src/mon/Monitor.cc:5434-5436, 5489-5496`). The interval is `mon_subscribe_interval`, default one
day (`src/common/options/mon.yaml.in:1422-1430`); an old-style client has to resend its
subscription before it elapses (`src/mon/MonSub.cc:26-35`, `src/mon/MonClient.cc:1048-1056`).
A client that advertises MON_STATEFUL_SUB (feature bit 57) never gets the ack and never has to
renew while the connection lives. See 4 for the recommendation.

### 2.6 MOSDMap (type 41), monitor to client

Class header version 4, compat_version 3 (`src/messages/MOSDMap.h:26-27, 73-76`). A monitor may send
a LOWER header version to a client whose connection features lack bits: version 1 / compat 1 when
PGID64 or PGPOOL3 is missing, version 2 / compat 2 when OSDENC is missing, version 4 / compat 3
otherwise (`src/messages/MOSDMap.h:103-115`); version 3 is never produced. The decoder picks fields
by `header.version`: fields 4 and 5 exist from version 2, field 6 from version 4
(`src/messages/MOSDMap.h:82-99`). A minimal client that advertises the full feature set (2.9)
only sees version 4; it should reject version < 2 (no `newest_map` / trim bound, so the missing-range
logic in 3.5.2 cannot work). Body order:

| # | Field | Type | Present when | Meaning |
|---|---|---|---|---|
| 1 | fsid | 16 raw bytes | always | cluster id; must equal the monmap fsid, otherwise drop the message (`src/osdc/Objecter.cc:1216-1220`) |
| 2 | incremental_maps | map<u32 epoch, bufferlist> | always | each value is one encoded OSDMap::Incremental |
| 3 | maps | map<u32 epoch, bufferlist> | always | each value is one encoded full OSDMap |
| 4 | cluster_osdmap_trim_lower_bound | u32 | header version >= 2 | oldest epoch the sending monitor still stores (formerly named oldest_map; same wire position and meaning, `src/messages/MOSDMap.h:30-50`) |
| 5 | newest_map | u32 | header version >= 2 | newest epoch the sender has |
| 6 | (removed snaps gap) | map<i64, interval set> | header version >= 4 | obsolete since Octopus; the v20.2.5 sender always writes u32 0 here (`src/messages/MOSDMap.h:161-163`; decoder reads and discards a map at `:97-99`), so it is exactly 4 zero bytes. A client may reject a non-zero count as malformed; the interval-set layout was not read (moot for v20.2.5 senders) |

A map entry value is itself a length-prefixed blob, so a decoder can find epochs and sizes
without understanding OSDMap. The inner OSDMap / Incremental encodings are described in the OSDMap
note.

The "first" and "last" epoch of a message are the lowest and highest epoch among the keys of both
maps (`src/messages/MOSDMap.h:56-73`). A single message may contain a mix: incrementals for most
epochs and a full map for the first one, or only a single full map.

**[confirmed: `pcap/*`, all 97 MOSDMap received, `harness/vectors/monclient/mosdmap-v4-full-e42.json`]** for the stock client mask (2.9): header version 4 / compat 3, body order fsid, incremental_maps, maps, trim bound, newest_map, then exactly 4 zero bytes; fsid equal to the monmap fsid; each blob is one wrapper envelope (6 + struct_len = blob length) whose epoch and fsid match, passes the CRC rule of the OSDMap note, and (for the 88 whose epoch the monitor store holds) is byte-identical to the monitor-store copy (so the "canonical bytes" case of 2.8 of the OSDMap note is real). Only FULL maps were delivered in the captures (one per message); incrementals-only and mixed messages were never captured (T9 open); `harness/vectors/monclient/mosdmap-v4-inc-e42-e43-synthetic.json` is a synthetic stand-in built from stored Incrementals, labelled as such.

The monitor re-encodes both kinds of blob for the feature set of the receiving connection when it
differs from the monitor quorum's features (`src/mon/OSDMonitor.cc:4651-4671, 4795-4821`,
`src/messages/MOSDMap.h:117-157`). Practical consequence: the OSDMap encoding version a client
sees depends on the feature bits the client advertises in the msgr2 handshake (see 2.9).

### 2.7 MMonGetVersion (19) and MMonGetVersionReply (20), optional

Use: ask the monitor for the newest and oldest committed version of a map, to decide whether an
osdmap the client lacks exists yet (the reference Objecter uses it, for example before declaring a
pool missing, `src/osdc/Objecter.cc:1682, 2335-2347`).

MMonGetVersion body (`src/messages/MMonGetVersion.h:40-51`): handle u64, what string. `what` is
"osdmap", "monmap", "mdsmap" or "fsmap"; anything else is logged and gets no reply
(`src/mon/Monitor.cc:5515-5526`). A monitor that is not in quorum, or whose service is not yet
readable, holds the request and answers later instead of failing (`src/mon/Monitor.cc:5500-5535`). The reference client numbers handles from 1
(`src/mon/MonClient.h:793-796`).

MMonGetVersionReply body, header version 2 (wire compat 2; `src/messages/MMonGetVersionReply.h:29-56`): handle
u64, version u64, oldest_version u64 (the last one only if header version >= 2). `version` is the
latest committed version, `oldest_version` the first committed one
(`src/mon/Monitor.cc:5530-5540`). The reply also carries the request's header tid (0 for the reference client, which does not set one).
Requires the "mon" read capability (`src/mon/Monitor.cc:4800-4806`).

### 2.8 MMonGetOSDMap (type 6), optional

Body: a PaxosServiceMessage prefix (version u64 = 0, deprecated_session_mon i16 = **-1**
(bytes `ff ff`), deprecated tid u64 = 0; the constructor defaults are in
`src/messages/PaxosServiceMessage.h:24-32`, the encoder in `:36-41`; MMonGetOSDMap passes version 0,
`src/messages/MMonGetOSDMap.h:32-33`), then four u32: full_first, full_last, inc_first, inc_last
(`src/messages/MMonGetOSDMap.h:77-96`); a range with first = 0 means "none". The monitor replies
with one MOSDMap holding the requested full maps and the requested incrementals, clamped to
[first committed, latest]. The two caps are SHARED across both loops: the message holds at most
`osd_map_message_max` epochs (default 40) full plus incremental together, and the loops stop once
the running byte total reaches `osd_map_message_max_bytes` (default 10 MiB), checked before each
epoch is added, so a message can exceed the byte cap by up to one map
(`src/mon/OSDMonitor.cc:2819-2854`, `src/common/options/global.yaml.in:2896-2910`). Reply fields 4
and 5 are set to the monitor's first committed and latest epoch. The reply is built with the
connection's features, like every MOSDMap. In the sources we read, the only sender is the OSD
daemon (`src/osd/OSD.cc:7244`). The monitor dispatches the request to the OSD map service
(`src/mon/Monitor.cc:4738-4744`, whose comment says the caps are checked by the service); we found
no capability check in `OSDMonitor::preprocess_get_osdmap` or `src/mon/PaxosService.cc`, but did not
trace the whole service dispatch, so whether a plain client may use it is **[unverified]** and
**[confirm on capture]** (not settled by the Phase 0 captures: no stock tool sends type 6). Its value for a client is control over the size of
the reply (section 3.5, "bounded memory").

### 2.9 Feature bits that gate these encodings

The `features` argument used when the monitor encodes a message is the feature set of the
connection, which is the intersection of what the two sides advertised in the msgr2 handshake
(`src/msg/async/ProtocolV2.cc:2183, 2469-2470`: each side ANDs the peer's advertised mask with the constant it supports; the stock policy constant is CEPH_FEATURES_ALL, `src/msg/Policy.h:44-49`). Bit numbers from `src/include/ceph_features.h`;
the macro tests a bit and a per-bit "incarnation" marker (`src/include/ceph_features.h:12-15, 18-21,
37-38`), so a value of "bit n" below means the incarnation-qualified test in the real code. Incarnation 2
adds the marker bit 57, incarnation 3 adds bits 57 and 28.

| Feature | Bit | Why monclient cares |
|---|---|---|
| SUBSCRIBE2 | 4 | else MMonSubscribe falls back to an old body (`src/messages/MMonSubscribe.h:80-93`) |
| MONNAMES | 5 | MonMap shape (`src/mon/MonMap.cc:191-205`) |
| MONENC | 15 | MonMap shape (`src/mon/MonMap.cc:221-238`) |
| SERVER_NAUTILUS | 2 (incarnation 3: the test needs bits 2, 28 and 57 all set, `src/include/ceph_features.h:88, 128, 175-177`) | MonMap v10 vs v5; mon_info v6 vs v2; address type "any" mapped to legacy (`src/mon/MonMap.cc:240-252`, `src/mon/MonMap.cc:54-90`, `src/msg/msg_types.h:481-490`) |
| MSG_ADDR2 | 59 | address vectors instead of one legacy address (`src/msg/msg_types.cc:336-341`) |
| MON_STATEFUL_SUB | 57 (the same bit that serves as the SERVER_JEWEL marker, `src/include/ceph_features.h:175-177`) | no subscribe ack, no need to renew subscriptions (`src/mon/Monitor.cc:5493`) |
| MSGR_KEEPALIVE2 | 42 | client may time out on missing keepalive acks (`src/mon/MonClient.cc:1062-1070`) |
| INCSUBOSDMAP | 10 (`src/include/ceph_features.h:96`) | a ONETIME osdmap subscription is answered with one message only (`src/mon/Monitor.cc:5455`, `src/mon/OSDMonitor.cc:4531-4580`) |
| PGID64, PGPOOL3, OSDENC (bits 9, 11, 13) | | MOSDMap header version (1 / 2 / 4) and the OSDMap blob encoding the monitor uses (`src/messages/MOSDMap.h:103-115`) |

**[confirmed: `pcap/*`, 243 of 243 monitor connections]**: the stock client's CLIENT_IDENT `supported` is exactly `0x3f07fffffffdffff`; the monitor's SERVER_IDENT `supported` is the same value; every bit of this table, including the incarnation marker bits 2, 28 and 57 that SERVER_NAUTILUS needs, is set in both, and with that mask the monitor sent MonMap v10, MMonSubscribe v3 was accepted and MOSDMap came as v4 / compat 3 with client block v10. Reduced masks (the minimal set) were not tried.

We do NOT list the full advertised set here; that belongs in the msgr2 note
(CEPH_FEATURES_ALL is at `src/include/ceph_features.h:194-262`; `msgr2.md` in this directory
recommends advertising exactly that value, 0x3f07fffffffdffff, which contains every bit in this
table). The decision recorded here: the minimal client advertises at least every bit in this table,
and the capture test in section 5 verifies that the monitor answers with MonMap v10 / MOSDMap v4.
Related notes in this directory: `msgr2.md` (frames, KEEPALIVE2, CLIENT_IDENT) and `cephx.md`
(auth request payload, old_ticket, MAuth renewal payload).

## 3 Client procedure

### 3.1 Build the initial monitor list from mon_host

Input is a string (config file value or command-line argument) in `mon_host`. The reference
builder is `MonMap::build_initial` (`src/mon/MonMap.cc:1089-1177`); the order of sources it tries
is: `mon_host_override`, an address list the process already holds from an earlier lookup, a monmap
file, then `mon_host`, then per-monitor config sections, then DNS SRV lookup. For `mon_host` it first
tries the literal-address parser and only on a parse failure (-EINVAL) falls back to the resolver
(`src/mon/MonMap.cc:1141-1149`). A minimal client supports only `mon_host` (section 4). Docs:
`doc/rados/configuration/msgr2.rst:70-72, 217-221`.

Parsing of the `mon_host` text:

1. Split on spaces and semicolons (`src/common/ceph_argparse.cc:197-203`). A comma between two
   items is consumed too (`src/common/ceph_argparse.cc:216-218`). Hostnames are resolved by the
   system resolver and expanded to all A and AAAA addresses, separators `,; `
   (`src/common/addr_parsing.c:46-135`); a client with no resolver (the iPXE case) must be given
   literal addresses, or use its own resolver. See open question Q7.
2. Each item is either one address or a bracketed address vector. An address is
   `[v1:|v2:|any:]IP[:port][/nonce]`, where IPv6 literals are bracketed
   (`src/msg/msg_types.cc:101-219`). Without a prefix the type is "unspecified" (any) at this
   stage (`src/common/ceph_argparse.cc:197`, `type = TYPE_ANY` passed from
   `src/mon/MonMap.cc:682-695`). A bracketed vector such as `[v2:1.2.3.4:3300,v1:1.2.3.4:6789]`
   is parsed as one monitor with several addresses (`src/msg/msg_types.cc:279-332`); because it
   carries explicit types and ports, no guessing is done (`src/mon/MonMap.cc:664-679`).
3. A single address gets the default-port and type rules of `_add_ambiguous_addr`
   (`src/mon/MonMap.cc:579-662`). Constants: IANA port 3300 for v2, legacy port 6789 for v1
   (`src/include/msgr.h:22-23`).

| Input item | Result |
|---|---|
| `v2:IP` (no port) | v2 at port 3300 |
| `v2:IP:port` | v2 at that port |
| `v1:IP` (no port) | v1 at port 6789 |
| `v1:IP:port` | v1 at that port |
| `IP:3300` | v2 at 3300 |
| `IP:6789` | v1 at 6789, as an entry named with the "-legacy" suffix (`src/mon/MonMap.cc:607-617`) |
| `IP` (no port) | two monitor entries: v2 at 3300, and a second entry named with a "-legacy" suffix at v1 6789 |
| `IP:other` | v2 at that port, plus a second "-legacy" entry at v1 on the same port |

The generated names are `noname-a`, `noname-b`, ... in order of appearance
(`src/mon/MonMap.cc:664-679, 1126, 1144`), and every entry gets priority 0 and weight 0. These
names are placeholders; the real names arrive with the MonMap and replace them.

Result: a list of candidates, each with a name, one address vector and a priority. The initial map
has epoch 0 and, unless the `fsid` config option is set (then that value, `src/mon/MonMap.cc:1136-1139`),
a zero fsid. Its `auth_epoch` is set to the maximum value so that the first real map never looks
like a key rotation, and its cipher fields are "none" (`src/mon/MonMap.cc:1093-1106`). An address
vector given in brackets is added as ONE monitor with priority 0 and is not expanded
(`src/mon/MonMap.cc:664-679`).

A v2-only client drops every candidate whose address type is v1 (including all "-legacy"
entries), because it cannot speak the v1 messenger. If this empties the list, fail with a message
that says the cluster must expose v2 monitor addresses.

### 3.2 Choose monitors to try ("hunting")

The reference algorithm (`src/mon/MonClient.cc:862-918`):

1. Consider the candidates not yet tried in this round (`tried` set of ranks).
2. Keep only those with the lowest priority value.
3. If that set is empty, clear `tried` and start over.
4. Shuffle the survivors: uniformly if all weights are zero, else by a weighted shuffle using each
   monitor's weight.
5. Open up to `mon_client_hunt_parallel` (default 3, `src/common/options/global.yaml.in:2319-2323`)
   connections at once, mark those ranks as tried. The first connection to finish the msgr2
   handshake and auth wins; all other pending connections are closed
   (`src/mon/MonClient.cc:1612-1642` for the msgr2 path, `src/mon/MonClient.cc:733-750` for the
   message-based path).
6. If the round does not produce a session, every `mon_client_hunt_interval` seconds (default 3)
   multiplied by a back-off factor, the whole pending set is dropped and the next batch is started
   (`src/mon/MonClient.cc:1025-1030, 1094-1108`).

Back-off: the multiplier starts at `mon_client_hunt_interval_min_multiple` (1). Each time hunting
starts after having had at least one session before, it is multiplied by
`mon_client_hunt_interval_backoff` (1.5) up to `..._max_multiple` (10)
(`src/mon/MonClient.cc:974-985`, defaults at `src/common/options/global.yaml.in:2360-2376`). Every
successful keepalive tick and every successful session divides it back down, never below the
minimum (`src/mon/MonClient.cc:1083-1092`). So after repeated failures the interval grows from
3 s to at most 30 s.

If the option `mon_client_target_rank` is set (>= 0) the client only connects to that rank
(`src/mon/MonClient.cc:808-812`, default -1 at `src/common/options/global.yaml.in:2324-2330`); a
minimal client does not need it.

### 3.3 Open the session and the first messages

Over msgr2 the authentication happens inside the connection handshake (auth request / reply / done
frames), not through MAuth messages; those frames are specified in the msgr2 and cephx notes. The
parts that are monclient's business:

1. When the connection to a candidate is created, the reference client immediately queues one
   MMonGetMap on it (`src/mon/MonClient.cc:1829-1838`). For msgr2 this is the only thing
   `MonConnection::start` does (it also records the start time, used as the initial keepalive-ack
   time, 3.6). It is NOT what starts the TCP/msgr2 connection: `connect_to_mon` already starts
   the connection attempt (`src/msg/async/AsyncConnection.cc:506-526`); the message just waits in
   the outgoing queue until the handshake completes. Its purpose is to learn the real MonMap
   (the reply, 3.4). A minimal client should do the same: send MMonGetMap as the first message on
   every new monitor connection. The monitor also exempts MMonGetMap from the forced-reconnect
   rule in 3.9.
2. The auth request payload the client puts into the handshake for a monitor has this fixed
   prefix before the method-specific part (`src/mon/MonClient.cc:1863-1898`): a u8 mode value
   (AUTH_MODE_MON = 10; the monitor accepts 10 to 19 and answers anything else with an access error,
   `src/auth/Auth.h:41-42`, `src/mon/Monitor.cc:6636-6641`), the entity name (type + id, layout in
   the cephx note), and a u64 global_id (0 for a first-time client, otherwise the id from the
   previous session, see 3.9). The monitor reads exactly these three fields first
   (`src/mon/Monitor.cc:6633-6645`); the method-specific part (cephx) follows in the cephx note.
3. The monitor answers the handshake with AUTH_DONE carrying the (possibly newly assigned)
   global_id; the client stores it (`src/mon/MonClient.cc:1936-1955`) and sets the connection's
   last-keepalive-ack time to the start time recorded in item 1.
4. Pending subscriptions are not sent immediately. `MonClient::_reopen_session` queues an
   MMonSubscribe built from every subscription it wants, but since there is no session yet, the
   message sits in a waiting list and is flushed to the winning connection when hunting finishes
   (`src/mon/MonClient.cc:802-845, 988-1008, 1112-1131`). A minimal client should do likewise:
   build the MMonSubscribe once per session, send it after the handshake succeeded, on that
   connection only.

Observed with the stock tools (`rbd`, `rados`, `ceph`, python rados; `pcap/*`): **every tool run opens TWO monitor connections.** The first is a bootstrap session of a separate MonClient: it asks only for the AUTH ticket (`other_keys` = 0x20), its CLIENT_IDENT has flags 0 and a non-zero cookie (a lossless session; `required` = MSG_ADDR2 only), and it subscribes to {"config" 0/0, "monmap" 0/0} (monmap start 0), receives MMonMap, MConfig, MMonMap and goes away. The second is the real session (lossy: flags 1, cookie 0, `required` = 0x0800000000001000): AUTH ticket plus MON, OSD and MGR tickets (`other_keys` = 0x35), the same first subscribe, then {"mgrmap" 0/0} and {"osdmap" 0, ONETIME}. A minimal client needs only the second kind, and needs neither "config" nor "mgrmap". Every one of the 106 osdmap subscriptions used ONETIME (flag 1). The first two messages of each connection, MMonGetMap and the first MMonSubscribe, went out together (identical capture timestamp) right after the handshake **[confirmed: `pcap/*`]**.

What to subscribe to (the reference sends exactly this set at connect time,
`src/mon/MonClient.cc:622-623`, plus the librados extras):

| Name | start | flags | Reference value | Minimal client |
|---|---|---|---|---|
| "monmap" | 0 if no real map yet, otherwise current epoch + 1 | 0 (continuous) | yes | yes |
| "config" | 0 | 0 | yes | no |
| "osdmap" | 0 initially, then (held epoch + 1) | ONETIME or 0 | set by the Objecter, not by MonClient (`src/osdc/Objecter.cc:2074-2092`) | yes, see 3.5 |
| "mgrmap" | 0 | 0 | librados only (`src/librados/RadosClient.cc:302`) | no |

The authenticate call is not reported as finished until a monmap with epoch > 0 has arrived,
if the client started from an epoch-0 initial map (`src/mon/MonClient.cc:1636-1640`; and when the
monmap arrives later, handle_monmap calls the finish step if the state is still "in progress",
`src/mon/MonClient.cc:482-484`). In practice: the client is "connected" when (a) the msgr2 auth handshake succeeded
and (b) a MonMap with epoch greater than 0 was decoded.

### 3.4 Handling an incoming MMonMap

Expect TWO MMonMap messages on a fresh session: one answers MMonGetMap, and one is pushed because
the "monmap" subscription (start 0, or at most the held epoch + 1) is satisfied at once
(`src/mon/Monitor.cc:5471-5472`, `src/mon/MonmapMonitor.cc:1548-1564`). Both normally carry the
same epoch; handling the second one must be idempotent. **[confirmed: `pcap/*`, all 242 fresh
sessions with a monmap start of 0 got exactly two, same epoch and byte-identical; `pcap/k2-mon-restart`: the
reconnect that subscribed with monmap start 4 (held 3 + 1) got exactly one]**. With "config" subscribed the
order on the wire is MMonMap (answer), MConfig, MMonMap (push); both MMonMap came after the client's
MMonGetMap and subscribe, within a few milliseconds.

Steps (`src/mon/MonClient.cc:429-485`):

1. Decode the MonMap (2.4.1). The reference replaces its map unconditionally (it does not compare
   epochs). A minimal client should ignore a map whose epoch is lower than the one it holds
   [client choice, section 4].
2. If the epoch changed, forget which ranks have been tried.
3. The reference looks up the monitor's name by the connection's peer addresses in the OLD map
   BEFORE decoding (`src/mon/MonClient.cc:433`). If that lookup finds nothing (for example the
   initial `mon_host` entry does not match the address the connection really uses) it reopens the
   session right after decoding (hunt again, `src/mon/MonClient.cc:451-453`). Otherwise it looks the same address up in the NEW map:
   if it is no longer there ("went away"), or if the map shows v2 addresses for it but we are on a
   v1 connection, it also reopens the session (`src/mon/MonClient.cc:455-467`). We are always on v2,
   so the v1 case does not apply. A minimal client must avoid a reopen loop: after the first real
   map, match the connection by name or by any address of the monitor.
4. Cache the addresses of the new map for later hunting.
5. If `auth_epoch` increased, the cluster rotated the cephx keys: wipe all held service tickets
   and rotating secrets, then fetch tickets again (3.8) (`src/mon/MonClient.cc:473-476,
   658-664`). The comparison is old held `auth_epoch` < new, and the initial map holds the maximum
   value, so the first real map never triggers it. A client with only a service ticket (no rotating keys) just discards its tickets.
6. Record that the monmap subscription has advanced: the held epoch is now the received one
   (`src/mon/MonClient.cc:478`, `src/mon/MonSub.cc:46-66`: for a continuous subscription the start becomes held + 1).
7. Learn the fsid from the map if not known yet. The fsid is the key to accept MOSDMap messages.

### 3.5 Getting and following the OSDMap

#### 3.5.1 What the monitor does with an "osdmap" subscription

Monitor side behaviour, so that the client can rely on it:

| Client request | Monitor reaction | Source |
|---|---|---|
| start = 0 | sends ONE MOSDMap containing only the latest full map (`maps` has one entry, `incremental_maps` is empty), with fields 4 and 5 set; a continuous subscription then continues from latest + 1 | `src/mon/OSDMonitor.cc:4460-4467, 4867-4880` |
| start = N with first committed <= N <= latest | sends incrementals starting at N, in messages of at most `osd_map_message_max` epochs (40) each; an epoch whose incremental is not stored is sent as a full map in `maps` instead | `src/mon/OSDMonitor.cc:4531-4590`, `4483-4500` |
| start = N where N < the monitor's first committed epoch | first sends a message with just the full map of the first committed epoch (`maps` has one entry), then incrementals after it in chunks | `src/mon/OSDMonitor.cc:4550-4572` |
| start > latest epoch | nothing now; sent when that epoch is committed | `src/mon/OSDMonitor.cc:4867-4880` |
| continuous (flags 0) | sends every chunk up to the current epoch, then keeps the session subscribed and pushes each new epoch as it commits | `src/mon/OSDMonitor.cc:4875-4880`, loop at `4575-4590` |
| ONETIME (flag 1) with INCSUBOSDMAP | sends ONE incremental chunk of at most 40 epochs, then removes the subscription, even if more epochs exist; if start was older than the first committed epoch the base full map message comes first, so that case is TWO messages | `src/mon/OSDMonitor.cc:4550-4590`, `src/mon/Monitor.cc:5455`, `src/mon/Session.h:277-279` |
| ONETIME without INCSUBOSDMAP | sends all chunks, then removes the subscription | same |
| "osd" read capability missing | nothing, no error | `src/mon/Monitor.cc:5406-5412` |

For epochs where the monitor has no stored incremental but has a full map, the monitor puts the
full map into `maps` for that epoch instead (`src/mon/OSDMonitor.cc:4483-4500`). The monitor
also remembers per session the highest epoch it already sent and will not resend lower ones unless
the client resubscribes with a lower start (`src/mon/OSDMonitor.cc:4544-4548`,
`src/mon/Monitor.cc:5464-5467`).

Capture status of this table (`pcap/*`, `harness/vectors/monclient/scenario-*.json`): row 1 is **[confirmed:
`pcap/k2-rbd-info-default` and 36 more start-0 subscriptions]** for a start-0 subscription with the ONETIME flag: one
MOSDMap, `maps` = {newest epoch}, `incremental_maps` empty, trim bound 1 (this monitor never trimmed),
newest_map = the epoch, within 1 to 20 ms of the subscribe. Row 5 (start above the newest epoch) is
**[confirmed: `pcap/k2-mon-restart`, `k2-renew-ttl60`]**: the re-subscribe with start 93 at epoch 92 got no
message. Rows 2, 3, 4, 6 and 7 (start N inside the stored range, start older than the trim bound, continuous,
ONETIME with and without INCSUBOSDMAP) and the chunk size 40 were not captured: the stock tools only ever
subscribe with start 0, and the lab map history was never trimmed; they stay **[confirm on capture]**.

Note that the monitor does not limit the BYTES of a subscription reply; only the epoch count (40)
caps it in that path. The byte cap exists in the MMonGetOSDMap path (2.8). Worst case a message
holds 40 maps. See Q9.

#### 3.5.2 Client algorithm

State: `have` = epoch of the OSDMap held (0 if none), `fsid`, the current subscription for
"osdmap".

On receiving a MOSDMap `m` (follows the reference, `src/osdc/Objecter.cc:1208-1342`):

1. If `m.fsid != fsid`: drop it.
2. Let `last` = highest epoch among keys of `m.maps` and `m.incremental_maps`. If `last <= have`:
   ignore the message (stale or duplicate).
3. If `have == 0` (no map yet): we want a full map. If `m.maps` contains `last`, decode it and
   set `have = last`. Otherwise resubscribe with start 0 and ONETIME (the reference does this)
   and wait.
4. Else for each epoch `e` from `have + 1` to `last`:
   a. if `have == e - 1` and `m.incremental_maps` has `e`: decode and apply that incremental;
   b. else if `m.maps` has `e`: decode that full map and replace the current map with it;
   c. else the epoch is missing:
      - if `e >= m.cluster_osdmap_trim_lower_bound`: the monitor should have it, so request the
        range (3.5.3) from `have + 1` and stop processing this message;
      - else (the monitor no longer has it): jump forward. Set `e` to
        `trim_lower_bound - 1` (so the next iteration handles `trim_lower_bound`), and mark the
        step as "skipped history": the next epoch must then come as a full map, because an
        incremental cannot apply across the gap.
   After each applied epoch, the client's own OSDMap-derived state (OSD addresses, up flags,
   pool list) must be re-derived; in-flight work must be re-targeted (OSD note).
5. After processing, record held epoch = `have` for the subscription (3.5.4; the reference calls it
   once at the end of the message with the held epoch, also when it stopped at a missing epoch,
   `src/osdc/Objecter.cc:1435`). If the subscription
   was ONETIME, it is gone now; if `m.newest_map > have` and we want to be current, subscribe
   again (3.5.3). The reference Objecter does not do this unconditionally; it re-requests when
   something is waiting for a newer epoch (`src/osdc/Objecter.cc:1435-1440`). A boot-disk client
   that wants to be always current should either use a continuous subscription or loop on
   `newest_map` itself.

An incremental must also be applied only to the map of epoch `e - 1`; OSDMap::Incremental carries
checksums of the full map and of itself (field names `full_crc`, `inc_crc`,
`src/mon/OSDMonitor.cc:4673-4688` shows the monitor reading them). Whether the client must check
them, and how, belongs in the OSDMap note. The rules there are **[confirmed: `gt3/inc`, `gt3/full`, every
delivered MOSDMap]**: the CRC check of the OSDMap note (seed 0xFFFFFFFF, no final inversion) passes on all
89 stored Incrementals (`inc_crc`) and on all 89 stored plus all 97 delivered full maps, and the `full_crc`
at the end of each Incremental equals the CRC stored in the full map of the same epoch. Whether verifying is
mandatory for a client is a policy choice, not a wire fact; it stays with the OSDMap note.

#### 3.5.3 How to request a missing range

Two ways, both with the same effect on the wire:

- (a) Subscription: send MMonSubscribe with {"osdmap": start = `have + 1`, flags = ONETIME} (or 0
  for continuous). Use start = 0 to get the latest full map. This is what the reference client does
  (`src/osdc/Objecter.cc:2074-2092`: start is `have + 1` if a map is held, else 0; the flag is
  ONETIME unless the map says the cluster is full or paused). The result is a MOSDMap with
  incrementals (or full maps) from that epoch. When the requested start is older than the
  monitor's first committed epoch the monitor starts with a full map (table in 3.5.1), which is the
  recovery from a long-offline client.
- (b) MMonGetOSDMap (2.8): request `full_first..full_last` and `inc_first..inc_last` explicitly.
  The reply is one MOSDMap bounded by 40 epochs in total (full and incremental together) and a soft
  10 MiB byte cap (2.8). It does not create a subscription.

Detecting what exists: `cluster_osdmap_trim_lower_bound` (oldest the monitor stores) and
`newest_map` (latest) in every MOSDMap give the valid range. MMonGetVersion("osdmap") returns the
same two numbers (2.7) without carrying map data.

Rate limiting: the reference Objecter only re-requests after its own tick found that more than
twice the objecter tick interval passed since the last request (`src/osdc/Objecter.cc:2266-2290`).
A minimal client needs some similar guard so that a monitor that never answers (missing capability,
see 2.5.1) does not cause a request loop.

#### 3.5.4 Bookkeeping of the subscription

`got(name, epoch)` after a map was applied: if the stored start <= epoch, then for ONETIME the
entry is deleted, otherwise start becomes epoch + 1 (`src/mon/MonSub.cc:47-68`). `want(name, start,
flags)` overwrites the entry only if start or flags differ (`src/mon/MonSub.cc:70-87`). The two
sets "new" and "sent" exist so that after a session reset every previously sent entry that has not
been satisfied is sent again (3.7). A minimal client needs the same behaviour but can hold it as
two small fixed-size tables (names are few: monmap, osdmap).

### 3.6 Steady state: tick, keepalive, timeouts

The reference timer (`src/mon/MonClient.cc:1025-1081, 1094-1108`):

- When connected, a tick runs every `min(mon_client_ping_interval, mon_client_log_interval)`; with
  defaults 10 s and 1 s that is every 1 s (`src/common/options/global.yaml.in:2338-2359`).
- Each tick first checks tickets (3.8).
- If more than `mon_client_ping_interval` (10 s) passed since the last keepalive, the client sends
  a keepalive on the monitor connection. The keepalive frame is a msgr2 frame (KEEPALIVE2 carrying
  a timestamp, answered with KEEPALIVE2_ACK echoing it: `src/msg/async/ProtocolV2.cc:479-485,
  651-663, 1687-1732`); the frame layout is in the msgr2 note. **[confirmed: `pcap/k2-idle75`,
  `k1-idle75`, `k2-renew-ttl60`, `k1-renew-ttl60`, `k2-mon-restart`; 9 monitor connections, 61 keepalive
  round trips]**: the
  client sends KEEPALIVE2 every 10.0 s (9.9 to 11.1 s apart), the monitor answers with KEEPALIVE2_ACK
  within 1 ms carrying the identical utime, and the stamp is the sender's wall clock. The FIRST keepalive
  went out 3.0 s after the TCP connect (7.0 s on the connection made after a monitor restart), earlier than
  "10 s since the last keepalive" suggests: the initial "last keepalive" time is evidently old, so do not
  rely on a 10 s quiet period at start-up. The 30 s ack timeout was not exercised (every ack arrived).
- If `mon_client_ping_timeout` is positive (default 30 s) and the peer has MSGR_KEEPALIVE2: when
  the newest keepalive ack is older than 30 s, treat the monitor as dead and reopen the session
  (hunt for another monitor). This check only runs on ticks that also send a keepalive, so it
  fires at most once per ping interval (`src/mon/MonClient.cc:1058-1070`). The "newest ack" is initialised to the time the auth request was
  started (`src/mon/MonClient.cc:1936-1952`).
- Every message type 2 (CEPH_MSG_PING) from the monitor is simply dropped by MonClient
  (`src/mon/MonClient.cc:328-330`). The message-level MPing exists (a monitor answers one with a
  JSON status text, `src/mon/Monitor.cc:4926-4945`) but the reference client uses the msgr2
  keepalive for liveness, not MPing, on the monitor session.
- When not connected, the tick runs at the hunting interval instead and every tick reopens the
  session (3.2).

### 3.7 Session reset, hunting and failover

Triggers for "reopen session" (`src/mon/MonClient.cc:802-845`):

1. The messenger reports a reset of the active monitor connection (`MonClient::ms_handle_reset`,
   `src/mon/MonClient.cc:920-960`): the TCP connection dropped, or the monitor closed the session.
   A monitor closes sessions of clients when it falls out of quorum and cannot be useful
   (`src/mon/Monitor.cc:4505-4541`).
2. The ping timeout in 3.6.
3. A MonMap says our monitor vanished (3.4).
4. A tick while still hunting (3.2).

What a reopen does, in order:

1. Drop the active connection and any pending ones.
2. Mark authentication as "in progress".
3. Compute the next hunt batch (3.2) and start new connections to it.
4. Throw away every message that was queued waiting for a session
   (`waiting_for_session`; source line `src/mon/MonClient.cc:825`). Everything the client wants
   must therefore be re-derivable, not queued: subscriptions are re-sent from the subscription
   tables, outstanding MMonGetVersion requests are failed with an "session was reset" error
   (EAGAIN to the caller, `src/mon/MonClient.cc:828-836, 2145-2147, 2200-2202`) and the caller must ask again.
5. Move every "sent" subscription back to "new" so that the whole set is sent on the next session
   (`src/mon/MonClient.cc:841-844`, `src/mon/MonSub.cc:37-45`).

Because `got()` advances the start of the continuous "osdmap" and "monmap" subscriptions, the
re-sent subscription asks for exactly the epochs after the last one held (3.5.4). No epochs are
lost or repeated across a failover.

Lossy semantics: the monitor session is client-side "lossy" (nothing is replayed by the
messenger). The reference configures the client messenger with the lossy-client policy as the DEFAULT policy
(`src/librados/RadosClient.cc:256`); neither RadosClient nor `MonClient::init` sets a per-peer-type
policy for monitors (grep of `set_policy` finds none there), so monitor connections use it. That the
messenger falls back to the default policy for peer type MON is the standard lookup but was not
traced (messenger note). Messages sent just before a reset may or may not have
been seen by the monitor; all monclient messages are idempotent (subscribe, get-version, get-map,
renew-tickets), which is why dropping them is acceptable.

### 3.8 Ticket renewal through the monitor

The cephx exchanges themselves (what goes into the payloads, the cipher, the ticket structures)
are in the cephx note. What belongs here is when and how the monclient asks the monitor, after the
msgr2 session is established, for new service tickets.

1. Each tick the client asks the auth handler whether it needs tickets
   (`src/mon/MonClient.cc:1138-1155`). A service ticket "needs renewal" when its renewal time has
   passed; renewal time is the expiry minus one quarter of the ticket validity period
   (`src/auth/cephx/CephxProtocol.cc:218-222, 243-250`). With the default
   `auth_service_ticket_ttl` of 1 hour (`src/common/options/global.yaml.in:2265-2269`), tickets
   are renewed after about 45 minutes. (`auth_service_ticket_ttl` governs OSD and MDS tickets; the
   auth ticket itself, used to reclaim the global_id, has its own lifetime `auth_mon_ticket_ttl`,
   default 72 hours, `src/common/options/global.yaml.in:2254-2262`.) The tick runs every second
   and the reference does not guard against sending a second MAuth while one is in flight
   (`src/mon/MonClient.cc:1138-1152`); a minimal client should send at most one outstanding
   renewal.
2. If a renewal is needed, send MAuth (type 17) on the monitor connection. Body
   (`src/messages/MAuth.h:55-63`): PaxosServiceMessage prefix (u64 version = 0, i16 = -1, u64 = 0:
   encoder `src/messages/PaxosServiceMessage.h:36-41`; the defaults are version 0, session_mon -1,
   tid 0, `src/messages/PaxosServiceMessage.h:24-32`; MAuth passes version 0 and header version 1,
   `src/messages/MAuth.h:34`), then `protocol` u32 (the auth method in use,
   CEPHX = 2, `src/include/ceph_fs.h:104`), `auth_payload` bufferlist (the cephx request built by
   the auth handler), `monmap_epoch` u32 (the reference sets 0 on a renewal; it is meaningful only
   for the older MAuth-based login).
3. The reply is MAuthReply (type 18, header version 1) (`src/messages/MAuthReply.h:50-66`): protocol
   u32, result i32 (0 = ok, otherwise a negative errno in the Linux numbering on the wire; the
   reference converts to and from host values, `src/include/types.h:625-660`, so a non-Linux
   client must map wire values itself), global_id u64, result_bl bufferlist, result_msg string. If `global_id` in the reply differs from ours, the reference treats it as a
   NEW session and resets its auth state (`src/mon/MonClient.cc:2080-2088`); a minimal client
   should treat that as an error, because it means the monitor session identity changed
   [client choice]. Otherwise `result` and `result_bl` are handed to the auth handler; if it
   needs another round it returns "again" and the client sends another MAuth with the next payload
   (`src/mon/MonClient.cc:2090-2097`, loop until the handler returns 0).
4. A reply that arrives for a connection that is not the active monitor session is ignored; the
   reference ignores any monitor message not from the active (or a pending hunting) connection
   (`src/mon/MonClient.cc:343-358`).

**[confirmed: `pcap/k2-renew-ttl60`, `k1-renew-ttl60`, `harness/vectors/monclient/mauth-*.json`]** (T14, Q4):
with `auth_service_ticket_ttl` = 60 s the python rados client sent MAuth on its monitor session 45.0 s after
it received the tickets (expiry minus validity / 4), then again every 45 s (three renewals in 150 s, 6 of 6
exchanges). MAuth is header version 1 / compat 1 (the compat copied from version), body = PaxosServiceMessage
prefix (u64 0, i16 -1, u64 0), protocol 2, auth_payload, monmap_epoch 0, no trailing bytes; the payload is
request header 0x0200, an authorizer for service AUTH (0x20) with the held AUTH ticket blob and a proof under
the AUTH session key (usage 0x10, have_challenge 0, no challenge round trip), then CephXServiceTicketRequest
v1 with keys 0x15 (MON, OSD, MGR; AUTH bit clear). MAuthReply is version 1 / compat 1: protocol 2, result 0,
global_id equal to the session's, result_bl = response header 0x0200 / status 0 + a ticket reply with
ticket_enc 0 and `msg_a` under the AUTH session key (usage 4), result_msg empty. The monitor accepted a renewal
on a session whose authentication happened in the msgr2 handshake. The validity values on the wire were 259,200
s (72 h) for the AUTH ticket in every login and 3,600 s (60 s in the renew sessions) for service tickets.
Renewing the AUTH ticket itself in-session was not exercised (it would need a 54 h run).

Rotating secrets (`_check_auth_rotating`) are only needed by OSD, MDS and MGR daemons, not by a
client (`src/auth/Auth.h:264-270`, `src/mon/MonClient.cc:1157-1165`); skip.

The service-ticket request in the initial exchange asks for the keys given by the "want" mask
(`src/auth/cephx/CephxClientHandler.cc:96-102`, where the first request carries the wanted keys
so the initial auth also returns the OSD ticket). The reference librados client wants MON, OSD
and MGR keys (`src/librados/RadosClient.cc:278-279`); a minimal client wants MON and OSD only.

The renewed tickets matter at two places: when opening a NEW connection to an OSD (the
authorizer is built from the current OSD ticket) and when a connection to an OSD is re-established.
Whether msgr2 re-authenticates an already open OSD connection when the ticket rotates is in the
msgr2 / cephx notes.

### 3.9 global_id

- First connection: the client sends global_id = 0 in the auth request prefix (3.3). The monitor
  assigns a fresh id from its pool and returns it in AUTH_DONE
  (`src/mon/Monitor.cc:6679-6686`). The client stores it and uses it as its identity:
  the reference calls `set_myname(client.<global_id>)` after authentication
  (`src/librados/RadosClient.cc:294`).
- Reconnect (hunting after a reset, or another monitor): the client sends its stored
  global_id again (`src/mon/MonClient.cc:1863-1898` puts the stored id in the request; `_add_conn` hands the
  stored id to the new connection and clones the existing auth handler, which carries the previous
  auth ticket, `src/mon/MonClient.cc:846-860`). With
  cephx the request also has to prove ownership by presenting the earlier ticket as "old_ticket";
  the server rejects reclaim without a valid old ticket unless the legacy escape
  `auth_allow_insecure_global_id_reclaim` (default true) applies to a client that marks its old
  ticket as "may be omitted" (`src/auth/cephx/CephxServiceHandler.cc:75-135`,
  `src/common/options/global.yaml.in:2277-2312`). A modern client that always sends the old ticket
  and never sets "may be omitted" works under either setting. The cephx request body layout
  (field `old_ticket`, `other_keys`) is in the cephx note
  (`src/auth/cephx/CephxClientHandler.cc:64-102`).
- **[confirmed: `pcap/k2-mon-restart`]** (T15, first half): after the monitor restart the client dialled a new
  connection (at t = 26.6 s; the monitor had been restarted at about t = 25 s) and sent the stored global_id in AUTH_REQUEST with a non-empty `old_ticket`
  (the 151-byte AUTH ticket blob handed out by the first login) in CephXAuthenticate v3; the monitor returned
  the same global_id in AUTH_DONE and the AUTH ticket reply used `ticket_enc` = 1 (the new blob encrypted under
  the previous AUTH session key, usage 5, plaintext one bufferlist). It then sent MMonGetMap and a subscribe
  with held + 1 starts (3.7). Reclaim with an expired old ticket was not captured (Q5 stays open).
- If the monitor hands back a different global_id than the one we sent, the reference logs an
  error and carries on (`src/mon/MonClient.cc:1013-1020`). **[unverified]** what happens to
  existing OSD sessions in that case. A minimal client that wants identity continuity should treat a
  changed id as a reason to drop every OSD connection (they were authorized for the old id).
- The monitor can also force the client to reconnect: if a session's global_id is "new, not
  exposed" and `auth_expose_insecure_global_id_reclaim` (default true) is on, the monitor drops
  the first non-MMonGetMap message and closes the connection, so that the client reconnects and
  must send the old ticket (`src/mon/Monitor.cc:4705-4716`). This only affects clients that mark
  their old ticket as omissible; an unmodified minimal client does not trigger it.

### 3.10 Optional: version query

If the client needs to answer "does epoch E exist yet?" without pulling maps: send MMonGetVersion
with a fresh handle and what = "osdmap" (2.7), wait for the reply carrying that handle. The
request is lost on a session reset (3.7) and must be re-issued by the caller. The reference uses
this before deciding that an object's pool does not exist (the pool might exist in a newer map
the client has not got).

## 4 Minimal-client choices

Must handle:

- Parse `mon_host` items of the forms in 3.1 for IPv4 and bracketed IPv6; ports 3300 / 6789 rules;
  v1 entries are dropped.
- Decode MMonMap with MonMap struct_v >= 6 (that is, v6 to v10), skipping unknown trailing bytes
  using `struct_len` when struct_v is above what we know; refuse struct_compat above 10. Reject
  struct_v < 6 (the first byte is below 6; v1/v2 start with a 16-bit version, v3 to v5 lack the
  `ranks` vector, `src/mon/MonMap.cc:293-330`) and a monitor whose addresses are all marker-0
  legacy form, with a clear error (these mean a server too old or a client that did not advertise
  the features in 2.9).
- Send MMonGetMap first on each new monitor connection; send MMonSubscribe after the handshake.
- MMonSubscribe v3 encode with "monmap" and "osdmap"; keep the two-table (new/sent) bookkeeping in
  3.5.4.
- Decode MOSDMap v4 (and tolerate higher versions with compat <= 4); implement the algorithm in
  3.5.2. Reject header version < 2 (no `newest_map` / trim bound) and a non-zero removed-snaps
  count; with the feature mask of 2.9 a v20.2.5 monitor sends neither.
- Expect two MMonMap messages right after the session opens (3.4) and apply them idempotently.
- Tick-based keepalive and the 30 s ack timeout (3.6); failover with reset-and-resubscribe (3.7).
- MAuth / MAuthReply for cephx service-ticket renewal (3.8), including the "again" loop.
- Ignore any message type not listed in 2.2, and ignore monitor messages that arrive on a
  connection other than the active one.

May skip (decline):

- "config" subscription and MConfig; "mgrmap"; MMonCommand and tell commands; log client; MPing
  as a liveness tool; DNS SRV; per-monitor config sections; `mon_host_override`; a monmap file;
  `mon_client_target_rank`; the parallel hunting (try monitors one after the other instead, with
  the same priority / weight / back-off order); the legacy v1 messenger and every pre-nautilus
  encoding path; MMonSubscribeAck handling beyond "ignore" (assuming MON_STATEFUL_SUB is
  advertised, 2.9).
- Hostname resolution inside iPXE or the Windows driver: require literal addresses; Windows can
  resolve in user space and pass the result in the handoff table. Not decided (Q7).

Recommended (client choices, not wire requirements):

- Subscribe to "osdmap" CONTINUOUSLY (flags 0) with start 0 on the first session, then start =
  held + 1 on re-subscribe. Reason: with ONETIME the monitor stops after one message of at most
  40 epochs, so the client would have to re-request itself in a loop; a continuous subscription
  gets every epoch and every new one. Cost: a steady (small) stream of MOSDMap messages on a
  changing cluster. This also removes the "no longer subscribed" failure mode.
- Advertise MON_STATEFUL_SUB so that no ack ever arrives and no renewal timer is needed.
- Keep exactly one monitor session at a time. Parallel hunting is a latency optimization, not
  required for correctness.
- Ignore a MonMap whose epoch is lower than the held one.
- Bounded memory: the iPXE heap is 4 MiB while a single MOSDMap can hold 40 maps. Two ways to
  bound it: (a) use MMonGetOSDMap with narrow ranges (one epoch at a time) if the monitor accepts
  it from a client (Q8); (b) reject a message larger than a configured limit at the msgr2 layer
  and fall back to the full-map path (start 0). Neither is verified yet.
- Decode OSDMap blobs lazily: keep the raw `bufferlist` per epoch, and only decode the newest.

Reject with a clear message (the exact wording must be localised-friendly and carry the cause):

- no v2 monitor address in the list or in the map;
- MonMap that cannot be decoded (version or struct_compat too new);
- fsid mismatch between the monitor map and any later MOSDMap (drop the message; if it persists
  with a different fsid, fail the session as "wrong cluster");
- auth failure: reported by the msgr2 / cephx layer, never retried in a tight loop.

## 5 Test vectors needed

All captures must be scrubbed of cephx keys and tickets (CONTRIBUTING.md rule 4). Most useful form:
decrypted msgr2 frame payloads from a client running the reference stack against the pinned test
cluster, plus the Ceph CLI output to cross-check.

| # | What to capture | How to check |
|---|---|---|
| T1 | Bytes of MMonGetMap (header + empty body) | Header fields in 2.1; type = 5; version/compat as in 2.3 |
| T2 | MMonMap reply to T1 for a 3-monitor cluster with v2+v1 addresses; and for a 1-monitor cluster; also count how many MMonMap arrive after subscribing (3.4) | Decode with our decoder; compare name, addresses, priority, weight, fsid, epoch, ranks with `ceph mon dump -f json`; check struct_v = 10, compat = 6, and the trailing auth_* fields against `ceph mon dump` |
| T3 | The same MMonMap on a cluster where `auth_epoch` has been rotated (if reproducible) | check the effect in 3.4 step 5 [confirm on capture] |
| T4 | An IPv6 monitor address vector | verifies the sockaddr layout in 2.4.3 (port position, flowinfo, scope id) |
| T5 | MMonSubscribe as sent by the reference client for {monmap, config, osdmap} | check map order, 9-byte items, hostname; compare to hand-built bytes (derived example below) |
| T6 | MMonSubscribe for {osdmap start 0, flags 0} and {osdmap start N, ONETIME} and the monitor's replies | verifies 3.5.1 table: one full map for start 0; chunk size 40; ONETIME one message |
| T7 | A start older than the monitor's `cluster_osdmap_trim_lower_bound` | monitor first sends a full map at the oldest stored epoch, then incrementals (3.5.1 row 3) |
| T8 | A user whose osd capability is absent or read-only | verifies silent drop (2.5.1); and whether "mon r" is needed for MMonGetVersion |
| T9 | MOSDMap with incrementals only, with full only, and mixed | check header version 4 / compat 3, the u32 trailing (removed-snaps gap) is 4 zero bytes, field order (fsid, incrementals, fulls, trim bound, newest); cross-check epochs with `ceph osd dump` / `ceph osd stat` |
| T10 | MMonGetVersion("osdmap") and reply | cross-check with `ceph osd stat` / `ceph osd dump` epoch and the oldest epoch |
| T11 | MMonGetOSDMap requesting full e..e and inc e..e from a plain client user | whether it is accepted without extra caps; the reply caps (Q8) |
| T12 | A session across a monitor restart (kill the active monitor) | observe: reset, hunt, MMonGetMap + MMonSubscribe re-sent, start = held + 1 |
| T13 | Keepalive timing against the monitor: idle session for 60 s | check that the ack arrives and that an unacked keepalive triggers the 30 s rule |
| T14 | MAuth renewal exchange (shorten `auth_service_ticket_ttl` on the test cluster) | confirms 3.8 payload and that MAuthReply carries our global_id |
| T15 | Reconnect with the stored global_id, with and without old ticket | confirms 3.9 and that the global_id is kept |

Derived (not captured) example bytes for T5, subscribing to the monmap only, all values hex,
hostname "h": count 01 00 00 00; key length 06 00 00 00, "monmap" 6d 6f 6e 6d 61 70; start (8
bytes) 00 00 00 00 00 00 00 00; flags 00; hostname length 01 00 00 00, 68. Total 4+4+6+8+1+4+1 = 28
bytes. This is derived from the layout in 2.5.1. **[confirmed: `pcap/*`]**: re-encoding every one of the 445
captured MMonSubscribe from its decoded fields reproduces the wire bytes exactly, so this example is what the
real client would send for those fields (the captured hostname is the machine's short host name; vectors use
"host1"); `harness/vectors/monclient/mmonsubscribe-derived-monmap-only.json` holds it.

Capture status of the table above (Phase 0 set, one-monitor lab cluster; details in the checker's check
names): T1 **[confirmed]** (`mmongetmap.json`). T2: **[confirmed]** for the 1-monitor case, and the count of
MMonMap (two); a 3-monitor map was not captured (the lab has one monitor). T3 not captured (no `auth_epoch`
rotation). T4 not captured (no IPv6). T5 **[confirmed]**. T6: **[confirmed]** for start 0 + ONETIME and for start
above the newest epoch; start N, continuous and the chunk size 40 not captured. T7 not captured. T8:
**corrected** (see Corrections: both restricted users got the MOSDMap; the "silent drop" is not observed).
T9: **[confirmed]** for a full map only (header v4 / compat 3, 4 zero bytes, field order); incrementals-only and
mixed not captured. T10, T11 not captured (stock tools never send types 19 or 6). T12 **[confirmed]**. T13
**[confirmed]** for the 10 s cadence and the ack; the unacked 30 s rule is not exercised. T14 **[confirmed]**.
T15: **[confirmed]** with a valid old ticket; the expired-ticket case is not captured.

## 6 Open questions

Resolved during review (kept so numbers stay stable): Q6, Q11 (marker 0 part), Q13, Q14. Resolved or
changed by the Phase 0 capture set: Q1 (stock mask), Q3, Q4, Q14, Q15 (vector<i32> part), Q16 (IPv4 part), Q17;
see each item and "Corrections after capture" at the end of this section.

- Q1 **[confirmed: `pcap/*`, 243 of 243 monitor connections, for the stock mask `0x3f07fffffffdffff`; the minimal
  subset is NOT settled]**: the exact set of msgr2 feature bits the client must advertise so that a
  v20.2.5 monitor sends MonMap v10, MMonSubscribe is v3, and MOSDMap uses the encodings our
  OSDMap decoder supports (2.9, 2.6). The OSDMap note and the msgr2 note must agree on one
  advertised mask: they now do, both point to `msgr2.md` 4.4 (`0x3f07fffffffdffff`, the full v20.2.5 set); the capture check remains.
- Q2 (still open: the stock client always advertises the bit, and no captured subscription asked for more than
  one chunk; needs our own client with a reduced mask): INCSUBOSDMAP is bit 10 (`src/include/ceph_features.h:96`); it only changes the ONETIME
  behaviour (one chunk versus all chunks). [confirm on capture] which behaviour a client without
  the bit sees; with a continuous subscription it is irrelevant.
- Q3 **[confirmed: `pcap/*`, nothing was sent before the client's first message and nothing unsolicited later; the
  stock client's own subscription set included "config" and "mgrmap"]**: whether a v20.2.5 monitor sends anything unsolicited right after the
  msgr2 handshake (for example a MonMap or MConfig) when the client has not subscribed yet. The
  source shows only replies to requests and subscription pushes.
- Q4 **[confirmed: `pcap/k2-renew-ttl60`, `k1-renew-ttl60`]**: the MAuth renewal payload and header in an established msgr2 session
  (3.8), and that the monitor accepts a renewal when the original auth was done in the handshake.
- Q5 [unverified] (not captured: the mon restart reclaim used a valid ticket): what the monitor does with a client whose cephx old ticket has expired when it
  reconnects (3.9). Fallback options: reauthenticate with global_id 0 and accept a new identity, or
  fail.
- Q6 RESOLVED: the auth ticket lifetime is `auth_mon_ticket_ttl`, default 72 hours
  (`src/common/options/global.yaml.in:2254-2262`); **[confirmed: `pcap/*`]** the wire value is 259,200 s in
  every login. **[unverified]** here: how and when a client renews the auth ticket itself (cephx note; not
  exercised, it would need a run of about 54 hours).
- Q7: resolver strategy for hostnames in `mon_host` in iPXE and in the Windows driver. The
  reference expands names to all A and AAAA records at start-up, blocking
  (`src/common/addr_parsing.c:45-135`). DNS SRV is also unread (`src/mon/MonMap.cc:891-939` for the
  crimson copy; the classic path is `src/mon/MonMap.cc:1054-1087`, not traced).
- Q8 [unverified] / [confirm on capture] (not settled by the captures: no stock tool sends type 6): whether a normal client user may send MMonGetOSDMap (2.8:
  no capability check found, service dispatch not traced). The subscription path caps only the epoch
  count (`src/mon/OSDMonitor.cc:4550-4590`, the incremental builder has no byte test); the byte cap
  exists only in the MMonGetOSDMap path.
- Q9: memory for the biggest MOSDMap: a large cluster's full OSDMap can be megabytes and a message
  can hold 40 incrementals; the message limit in the msgr2 layer must accommodate it. Needs a
  measurement on a larger test cluster.
- Q10 [unverified, wire part **[confirmed: `gt3/*`, `pcap/*`]**: the CRC rules verify on every stored and delivered
  map, 3.5.2]: whether a MOSDMap incremental must be verified against its CRC fields before
  being trusted, and whether skipping verification is safe for a read-only boot disk (OSDMap
  note).
- Q11: RESOLVED for the legacy address marker 0 (layout in 2.4.3). The removed-snaps gap map
  is always written empty by a v20.2.5 sender (`src/messages/MOSDMap.h:161-163`); its non-empty
  layout was not read **[unverified]**, moot for this release.
- Q12 [unverified] (observation only: the monitor's nonce is 0 and the stock client's target_addr nonce is 0; no
  mismatch was captured): whether the entity_addr nonce of a monitor must be verified by the client during
  the msgr2 handshake (messenger note).
- Q13 RESOLVED: monitor connections use the default lossy-client policy (3.7); only the fallback
  lookup for peer type MON is untraced.
- Q14 RESOLVED: default message priority is 127, applied at send time when the message left it 0
  (2.1). **[confirmed: `pcap/*`]** the monitor does not care: it answered all 714 client messages sent with 127.
- Q15 **[confirmed for `vector<i32>`: `pcap/*`, `gt/mon-dump.json`]**, [unverified] for the elements of a non-empty `set<u32>` (the lab map has no removed rank): that the denc-based container encoders used for `set<u32>` and `vector<i32>`
  in the MonMap are byte-identical to the generic ones (u32 count + elements); first capture (T2)
  settles it.
- Q16 **[confirmed for IPv4: `pcap/*`, `gt/monmap.bin`]**, [confirm on capture] for IPv6 (no IPv6 monitor in the lab): exact sockaddr byte positions for IPv4 / IPv6 monitor addresses
  (2.4.3, T4), including whether the IPv6 flow-info and scope-id words are little or big endian
  (they are raw C struct bytes, only the port is network order by definition of the C struct).
- Q17 **[confirmed: `pcap/*`, 242 fresh sessions]**: that the monitor really sends two MMonMap (reply to MMonGetMap plus the
  subscription push) on a fresh session and that the second can be ignored when epochs are equal
  (3.4).
- Q18 [unverified]: what the reference does to existing OSD sessions when the monitor hands back a
  different global_id than the one sent (3.9); only the log line was read. (Not captured: every reclaim in
  the set got the same id back.)

### Corrections after capture

What the Phase 0 captures changed in this note (each also fixed in place above):

1. **Capability for the "osdmap" subscription (2.5.1, T8).** The note said the monitor needs an "osd" read
   capability for "osdmap" and silently drops the subscription otherwise. Observed: `client.t0-noosd` (caps
   `mon r` only) and `client.t0-ro` (`mon r`, `osd r pool=winrbd`) were both answered with a normal MOSDMap
   (v4 / compat 3, epoch 92). The user without OSD caps fails later and elsewhere: each OSD connection ends in
   AUTH_BAD_METHOD, result -13 (8 attempts in a row to the same OSD per command in the capture), so I/O stalls
   until the tool's timeout. The "silent drop" claim itself was NOT observed and stays **[confirm on capture]**
   (it needs a user with narrower mon caps).
2. **Priority (2.1).** Client-sent messages carry 127 as predicted; messages sent BY the monitor carry 196
   (high priority). The note only predicted the client side.
3. **Message table (2.2).** Added the type the monitor sends after a "mgrmap" subscription (1796 / 0x704,
   53,337 bytes) and the observation that the stock `ceph` CLI also uses MMonCommand (50 / 51) with a 246,845-byte
   reply at start-up. Neither concerns a minimal client.
4. **Two monitor connections per tool run (3.3).** Not in the source reading: the stock tools run a separate
   bootstrap session first (AUTH ticket only, lossless policy, subscribes config + monmap) and then the real one.
5. **MMonMap order (3.4).** Two MMonMap per fresh session confirmed; with "config" subscribed they arrive as
   MMonMap, MConfig, MMonMap, so the second MMonMap is not the next message after the first.
6. **First keepalive (3.6).** The first KEEPALIVE2 goes out about 3 s after connect, not after a 10 s quiet
   period; later ones every 10.0 s.
7. **Status marks.** [confirm on capture] / [unverified] turned into [confirmed: ...] for: priority 127 (Q14),
   unsolicited messages (Q3), IPv4 sockaddr layout (Q16 IPv4 part), `vector<i32>` denc form (Q15 part), the
   stock feature mask (Q1), two MMonMap (Q17), MAuth renewal (Q4), global_id reclaim (T15 first half), CRC rules
   on delivered maps (Q10, wire part), and the T1, T2 (1-monitor), T5, T6 (two rows), T9 (full only), T12-T14
   rows of section 5. Still open, and why: 3-monitor map, hunting and priority / weight (one monitor in the
   lab); IPv6 (no IPv6 listener); `auth_epoch` rotation; start-N, continuous, trimmed-start and chunk-size rows of
   3.5.1, incremental-only / mixed MOSDMap, MMonGetVersion and MMonGetOSDMap (stock tools do not send them; the
   lab map was never trimmed); INCSUBOSDMAP behaviour and reduced feature masks (need our own client); the
   30 s keepalive-ack timeout and expired-old-ticket reclaim (would need fault injection); non-empty
   `set<u32>` bytes (`removed_ranks`); nonce verification (Q12); AUTH-ticket renewal (54 h).

Observed differences from OTHER notes (not edited here, for the owners of those notes): `msgr2.md` 2.1 / 2.8
expects frame-encoded addresses to keep type 3 (ANY), but both HELLO frames carry type 2 (MSGR2) for the
addresses in every capture; `msgr2.md` 2.9 says message header `flags` is 1, every captured message in both
directions has 3; `msgr2.md` 2.7 predicts `required` = 0x0800000000001000, flags 1, cookie 0 for the stock
client, which holds for OSD, mgr and the real monitor session, but the bootstrap monitor session sends
required 0x0800000000000000, flags 0 and a non-zero cookie.

## 7 Licensing questions

- This note describes behaviour by reading Ceph source files whose headers state LGPL-2.1
  (for example `src/messages/MMonSubscribe.h:6-12`). Nothing is copied; field layouts, numeric
  constants and procedures are restated. Per CONTRIBUTING.md rule 1, the pull request that adds this
  note should list the sources read (section 1.2).
- Review pass: line references were re-checked against the pinned tree; no Ceph text was copied
  (names of Ceph options, message classes and constants are quoted as identifiers, not prose).
- No lookup table needs to be copied for this topic. The feature-bit numbers in 2.9 and the release
  numbers in 2.4.1 are protocol constants; if the core later needs the whole CEPH_FEATURES_ALL
  mask, derive it from the public bit numbers rather than copying the header's list (the msgr2
  note should record the decision).
- The reference Objecter flow in 3.5.2 is a behavioural description. The core's implementation must
  be written from this description and a live capture, not from `osdc/Objecter.cc`.
