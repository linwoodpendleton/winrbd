# Spec note: msgr2 (Messenger v2) framing, handshake and message envelope, client side

Status: draft, derived from reading the pinned source. Nothing in this note has been confirmed on a live capture yet; every such item is marked **[confirm on capture]**. Items that could not be pinned in source are marked **[unverified]** and repeated in section 6.

Reference tree: Ceph tag v20.2.5 (Tentacle), commit ed27c686770872022f4c1de04f6b0ac5d5384ded. All `path:line` references below are relative to that tree root unless stated otherwise. Everything is written from the point of view of a **client** that dials a monitor or an OSD. The server side is described only where it determines what a client sees.

---

## 1. Scope and sources

### 1.1 What this note covers

- The TCP-level banner exchange and how the two sides pick the msgr2 revision (2.0 vs 2.1).
- The 32-byte frame preamble, segments, epilogue, and CRC-32C usage in both revisions (crc mode in full; secure mode only as a reference summary).
- The complete tag list with numeric values and the byte layout of every control-frame payload.
- The frame shells of the authentication phase (AUTH_REQUEST, AUTH_BAD_METHOD, AUTH_REPLY_MORE, AUTH_REQUEST_MORE, AUTH_DONE, AUTH_SIGNATURE) and the auth-method / connection-mode negotiation. What goes inside the method-specific payload belongs to the cephx note and is not described here.
- The session handshake frames (CLIENT_IDENT, SERVER_IDENT, IDENT_MISSING_FEATURES, SESSION_RECONNECT, SESSION_RESET, SESSION_RETRY, SESSION_RETRY_GLOBAL, SESSION_RECONNECT_OK, WAIT), keepalive, ACK, and the MESSAGE frame with `ceph_msg_header2`.
- `entity_addr_t` / `entity_addrvec_t` wire encoding.
- Feature bits a minimal client should advertise (msgr2-level and CEPH_FEATURE-level).

### 1.2 What this note does not cover

- Contents of message payloads carried inside MESSAGE frames (front / middle / data segments): see the MOSDOp, MOSDMap and mon notes.
- cephx payloads, ticket handling, the derivation of `session_key` and `connection_secret`: see the cephx note.
- The legacy v1 protocol (banner `ceph v027`, TCP port 6789 style listeners). A client built from this note speaks v2 only.
- Server-side policy, throttling and connection-race resolution, except where visible to a client.

### 1.3 Sources read

| Source | Used for |
|---|---|
| `doc/dev/msgr2.rst` | prose description of banner, frames, handshake (section headings at lines 54, 90, 128, 188, 243, 255, 348, 401, 536, 594, 821). Some parts are out of date, see 1.4. |
| `src/msg/async/frames_v2.h`, `frames_v2.cc` | tag enum, preamble / epilogue structs, segment rules, all control-frame field lists, assembly and disassembly for the four mode/revision combinations |
| `src/msg/async/ProtocolV2.cc`, `ProtocolV2.h` | banner, hello, auth, ident, reconnect, keepalive, ack, message send/receive, pre-auth signature, timeouts |
| `src/msg/async/crypto_onwire.cc` | secure-mode key / nonce layout (reference only) |
| `src/msg/msg_types.h`, `src/msg/msg_types.cc` | `entity_addr_t`, `entity_addrvec_t` encoding |
| `src/include/msgr.h` | banner prefix, msgr2 feature bits, `ceph_msg_header2`, footer flag bits, entity type codes |
| `src/include/ceph_features.h` | CEPH_FEATURE bits, `CEPH_FEATURES_ALL` |
| `src/include/ceph_fs.h` | auth method and connection mode codes |
| `src/include/crc32c.h`, `src/common/crc32c.cc`, `src/common/sctp_crc32.c`, `src/common/crc32c_intel_baseline.c`, `src/common/buffer.cc` | CRC-32C parameters, which implementation is the portable default, and chaining |
| `src/include/encoding.h`, `src/include/denc.h`, `src/include/types.h`, `src/include/utime.h` | primitive encodings used inside control-frame payloads |
| `src/ceph_osd.cc`, `src/ceph_mon.cc`, `src/msg/Policy.h`, `src/librados/RadosClient.cc`, `src/common/options/global.yaml.in` | which feature bits and timeouts the servers impose, and what the stock client advertises |
| `src/auth/AuthRegistry.cc`, `src/mon/MonClient.cc`, `src/msg/async/AsyncMessenger.cc`, `src/msg/async/AsyncConnection.cc`, `src/msg/async/PosixStack.cc` | mode selection, auth request construction, address learning, timers, keepalive cadence |

### 1.4 Differences between `doc/dev/msgr2.rst` and the code (trust the code)

| Topic | rst says | v20.2.5 code does |
|---|---|---|
| TAG_CLOSE | listed (rst:861) | not in the tag enum (`src/msg/async/frames_v2.h:45-68`); an unknown tag makes the receiver drop the connection (`src/msg/async/ProtocolV2.cc:1212-1217`) |
| AUTH_SIGNATURE, COMPRESSION_REQUEST, COMPRESSION_DONE | not described in the frame list (the state diagrams mention a "sign" state) | present as tags 7, 21, 22 (`frames_v2.h:51,66,67`) |
| CLIENT_IDENT / RECONNECT address list | "num_addrs, then entity_addrvec_t * num_addrs" | one `entity_addrvec_t` value, which carries its own marker and count (`frames_v2.h:619-644`, section 2.8) |
| KEEPALIVE2 timestamp | `ceph_timespec` | `utime_t` (two little-endian u32, same 8 bytes) (`frames_v2.h:764`, `src/include/utime.h:163-171`) |
| msgr2.1 first-segment crc | "stored at the end of the first segment" | confirmed, 4 bytes, `frames_v2.cc:154-159` |
| Banner features | only REVISION_1 is defined (rst:69) | two bits exist: REVISION_1 (bit 0) and COMPRESSION (bit 1), and every v20.2.5 daemon advertises both (`src/include/msgr.h:53-62`, `ProtocolV2.cc:894`) |
| AUTH_REQUEST and AUTH_DONE "method specific payload" | drawn with no length prefix (rst:263, 292); only AUTH_REPLY_MORE / AUTH_REQUEST_MORE show `__le32 len` (rst:280, 285) | all four payloads are length-prefixed blobs (u32 length + bytes), because the field is an encoded bufferlist (`frames_v2.h:532-604`, `src/include/encoding.h:312-317`); the length is **not** implied by the segment length |
| MESSAGE frame layout | lists a `data_pre_padding` area between middle and data (rst:831, 839) | there is no such segment; the frame has exactly the four segments header / front / middle / data, and `data_pre_padding_len` in the header is always sent as 0 (`frames_v2.h:810-831`, `ProtocolV2.cc:546`) |
| RECONNECT address field | "`entity_addr_t * num_addrs`" (rst:651) | one `entity_addrvec_t` value (same as CLIENT_IDENT) |

---

## 2. Wire structures

All multi-byte integers on the msgr2 wire are **little-endian**, except the TCP port and IPv4/IPv6 address bytes inside a sockaddr (network order), see 2.8.

### 2.1 Primitive encodings used inside control-frame payloads

Control frames have **no struct_v / compat header of their own**: the payload is just the listed fields back to back (`frames_v2.h:455-496`). The only versioned object inside is `entity_addr_t` (2.8). New fields can therefore only be introduced by a new tag or a feature bit.

| Type | Encoding | Source |
|---|---|---|
| u8 / bool | 1 byte; bool is 0 or 1 | `src/include/encoding.h:98-105` |
| u16 / u32 / u64 / i32 / i64 | little-endian fixed width | `src/include/encoding.h:112-129` |
| `vector<u32>` (control-frame field) | u32 count, then count x u32 | `frames_v2.h:455-466` (special case in the frame encoder) |
| bufferlist ("method payload") | u32 length, then that many bytes | `src/include/encoding.h:312-317` |
| utime_t | u32 seconds, u32 nanoseconds (the in-memory layout is copied on little-endian hosts, so a client writes the two u32 explicitly) | `src/include/utime.h:163-171` |
| sha256 digest | exactly 32 raw bytes, no length prefix (a fixed-size array of u8 is encoded element by element) | `src/include/types.h:696-702`, `src/include/encoding.h:1419-1440`, `src/include/denc.h:1243-1295` |
| entity_addr_t / entity_addrvec_t | section 2.8 | |

When a frame is encoded, the features argument used for the contained addresses is fixed to the value `MSG_ADDR2 | SERVER_NAUTILUS` regardless of what the peers negotiated (`frames_v2.h:28-43`, `frames_v2.h:452`). Numerically: `CEPH_FEATUREMASK_MSG_ADDR2 = 0x0800000000000000`, `CEPH_FEATUREMASK_SERVER_NAUTILUS = 0x0200000010000004`, combined `0x0a00000010000004` (computed by compiling `src/include/ceph_features.h:88,183` with the incarnation masks at lines 13-15 and printing the constants). The practical effect: the address encoder keeps `type = ANY (3)` instead of rewriting it to LEGACY (1), see `src/msg/msg_types.h:487-498`; **[confirm on capture]** that addresses in captured frames show type 3 surviving unchanged.

### 2.2 Banner

Sent by both sides immediately after TCP connect, without waiting for the peer (`src/msg/async/ProtocolV2.cc:888-905`).

| Offset | Size | Field | Value sent by a v20.2.5 daemon |
|---|---|---|---|
| 0 | 8 | prefix | ASCII `ceph v2\n` (`src/include/msgr.h:38`) |
| 8 | 2 | payload length (u16) | 16 |
| 10 | 8 | supported msgr2 features (u64) | 3 = REVISION_1 (bit 0) + COMPRESSION (bit 1) (`msgr.h:53-62`) |
| 18 | 8 | required msgr2 features (u64) | 0 (`msgr.h:64`) |

Total 26 bytes. msgr2 feature bits live in their own namespace (`CEPH_MSGR2_FEATURE_*`), separate from the CEPH_FEATURE bits. Receiver rules (`ProtocolV2.cc:912-1011`):

- The first 8 bytes must equal the prefix. If they equal the legacy prefix `ceph v027` instead, the peer is a v1 endpoint and the connection is dropped (`ProtocolV2.cc:921-931`).
- The receiver reads `payload length` bytes and then decodes two u64 from them; a payload shorter than 16 bytes is a decode error, extra bytes are ignored (`ProtocolV2.cc:933-974`). The stock code allocates whatever length the peer sends (no cap), so a client should cap the length it will accept (a few hundred bytes is plenty). The 8-byte prefix and the 2-byte length are read first (10 bytes, `ProtocolV2.cc:907-910`), then the payload.
- If the peer's *required* mask contains bits we do not support, or we require bits the peer does not advertise, the connection is closed (`ProtocolV2.cc:985-1001`).
- **Revision selection:** each side switches itself to msgr2.1 framing if and only if the **peer's** supported mask has REVISION_1 (`ProtocolV2.cc:1009-1011`). Both frame assemblers are switched before the HELLO frame is sent, so HELLO is already a revision-1 frame. Because each side keys off the other's advertisement, a side must advertise REVISION_1 exactly when it implements it; then both sides agree.
- The COMPRESSION bit works the same way for the optional compression stage (2.6): each side stores the **peer's** supported mask (`ProtocolV2.cc:1003`); the stock client enters the stage when the **server** advertised the bit (`ProtocolV2.cc:1919-1921`), and the server expects it only when the **client** advertised it (`ProtocolV2.cc:1931-1937`, otherwise it goes straight to waiting for CLIENT_IDENT). Since every v20.2.5 server advertises the bit, the stock client always sends COMPRESSION_REQUEST. A client that does not implement compression must therefore **not advertise** the bit and must **not** send COMPRESSION_REQUEST; the server then skips the stage (read from source, so the logic is pinned, but still **[confirm on capture]**).

### 2.3 Frame preamble (32 bytes, every frame, every mode)

Source: `frames_v2.h:70-79,103-120`, filled at `frames_v2.cc:64-78`, checked at `frames_v2.cc:274-325`. The tag and segment fields are packed with no padding; segment length is u32, alignment is u16, both little-endian.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | tag | section 2.4 |
| 1 | 1 | number of segments | 1 to 4; a frame always has at least one segment, which may be empty |
| 2 | 6 | segment 0: length (u32), alignment (u16) | |
| 8 | 6 | segment 1: length, alignment | zero if unused |
| 14 | 6 | segment 2: length, alignment | zero if unused |
| 20 | 6 | segment 3: length, alignment | zero if unused |
| 26 | 1 | flags | bit 0 = FRAME_EARLY_DATA_COMPRESSED (`frames_v2.h:187`); otherwise 0 |
| 27 | 1 | reserved | 0 |
| 28 | 4 | CRC-32C of bytes 0..27 (u32) | seed 0, see 2.5 |

Receiver validation (`frames_v2.cc:289-318`): preamble CRC must match; `num_segments` must be 1..4; if more than one segment, the **last** segment must have non-zero length. There is no upper bound on segment lengths at this layer (throttling happens above it), so a client must impose its own cap.

Sender rule: trailing empty segments are dropped, but at least one segment is always kept (`frames_v2.cc:31-42`). Hence a MESSAGE with only a header and a front segment has 2 segments, while one whose only non-empty part is `data` has 4 (with empty segments 2 and 3 of length 0 in the middle).

The alignment field is advisory: the receiver passes it to its buffer allocator when it reads the segment (`ProtocolV2.cc:1233-1247`), and the allocator raises any value below `sizeof(void *)` to that size (`src/common/buffer.cc:203`). Settings found in the code: control frames use `sizeof(void *)` for their single segment (8 on a 64-bit build, **4 on a 32-bit build**, so a 32-bit Windows or iPXE client has no fixed expected value); MESSAGE uses `sizeof(void *)`, `sizeof(void *)`, `sizeof(void *)`, 4096 for header, front, middle, data (`frames_v2.h:70-79,810-815`). The alignment of a segment that is present in the preamble but empty (for example an empty middle in front of a non-empty data) is still the per-segment constant, not 0 (`frames_v2.cc:238-241`). A client should send 8 / 8 / 8 / 4096, must send a power of two (a non-power-of-two value would make the POSIX aligned allocation fail and the server fault; this is POSIX behaviour, **[unverified]** against a live server), and must not rely on the peer's values. **[confirm on capture]**.

### 2.4 Tags

Numeric values are the enum order starting at 1 (`frames_v2.h:45-68`); the enum is `uint8_t`-sized.

| Value | Tag | Direction | Payload | Needed by a lossy client |
|---|---|---|---|---|
| 1 | HELLO | both | entity type u8, entity_addr_t | yes |
| 2 | AUTH_REQUEST | C to S | method u32, preferred modes vec, auth payload | yes |
| 3 | AUTH_BAD_METHOD | S to C | method u32, result i32, allowed methods vec, allowed modes vec | yes (receive) |
| 4 | AUTH_REPLY_MORE | S to C | auth payload | yes (receive) |
| 5 | AUTH_REQUEST_MORE | C to S | auth payload | yes |
| 6 | AUTH_DONE | S to C | global id u64, connection mode u32, auth payload | yes (receive) |
| 7 | AUTH_SIGNATURE | both | 32-byte HMAC-SHA256 | yes |
| 8 | CLIENT_IDENT | C to S | see 2.7 | yes |
| 9 | SERVER_IDENT | S to C | see 2.7 | yes (receive) |
| 10 | IDENT_MISSING_FEATURES | S to C | missing feature mask u64 | receive, then fail |
| 11 | SESSION_RECONNECT | C to S | see 2.7 | no (lossless sessions only) |
| 12 | SESSION_RESET | S to C | full flag (bool) | no |
| 13 | SESSION_RETRY | S to C | connect_seq u64 | no |
| 14 | SESSION_RETRY_GLOBAL | S to C | global_seq u64 | no |
| 15 | SESSION_RECONNECT_OK | S to C | msg_seq u64 | no |
| 16 | WAIT | S to C | empty | receive, then back off |
| 17 | MESSAGE | both | ceph_msg_header2 + front + middle + data | yes |
| 18 | KEEPALIVE2 | both | utime_t | yes (answer it) |
| 19 | KEEPALIVE2_ACK | both | utime_t (echo) | yes |
| 20 | ACK | both | seq u64 | tolerate; only used on lossless sessions |
| 21 | COMPRESSION_REQUEST | C to S | is_compress bool, preferred methods vec | no (not advertised) |
| 22 | COMPRESSION_DONE | S to C | is_compress bool, method u32 | no |

The v1 tag numbers in `src/include/msgr.h:118-136` (CEPH_MSGR_TAG_*) are a different, unrelated numbering and must not be mixed up with the table above.

A receiver treats any tag outside the dispatch list as fatal (`ProtocolV2.cc:1183-1221`); frames that are valid but arrive in the wrong state are also fatal (each handler checks the state first, for example `ProtocolV2.cc:1692-1696`).

### 2.5 CRC-32C

Exact parameters. The implementation is picked at run time per CPU (`src/common/crc32c.cc:19-62`: x86 SSE4.2 / PCLMUL, ARMv8, POWER, s390x, otherwise the portable slice-by-8 routine `ceph_crc32c_sctp` in `src/common/sctp_crc32.c:648-662,783-786`), so every variant must produce the same function, because peers on different architectures talk to each other. Two portable variants were read: the byte-at-a-time table loop in `src/common/crc32c_intel_baseline.c` (also used by the x86 fast path for short buffers and tails, `src/common/crc32c_intel_fast.c:39-46`) and the slice-by-8 routine in `sctp_crc32.c`; both start from the caller's seed, use the same reflected table (first entries 0x00000000, 0xF26B8303, 0xE13B70F7 in both files) and apply no final inversion (the complementing helper in `sctp_crc32.c:749-775` is not on the path used by `ceph_crc32c_sctp`). Equality of the SIMD variants was not re-derived; it is assumed from the fact that mixed-architecture clusters interoperate. The byte-at-a-time variant is the one described in detail here:

| Parameter | Value | Source |
|---|---|---|
| Polynomial | 0x1EDC6F41 (normal form), i.e. 0x82F63B78 reflected | table in `src/common/crc32c_intel_baseline.c:41-106` and `src/common/sctp_crc32.c:99-117` (first nonzero entry 0xF26B8303 is the reflected-polynomial table value for index 1; the sctp file's table row for index 128 starts with 0x82F63B78) |
| Reflected input / output | yes (LSB-first, shift right) | update step at `crc32c_intel_baseline.c:120-124` |
| Initial value | **caller supplied seed**; no implicit inversion | `src/include/crc32c.h:43-51` |
| Final XOR | **none** | same |
| Per-byte step | `crc = (crc >> 8) XOR T[(crc XOR byte) AND 0xFF]` with T generated from the reflected polynomial | `crc32c_intel_baseline.c:123` |
| Chaining over buffers | the output of one buffer is the seed of the next; an empty buffer leaves the seed unchanged (empty nodes are skipped, and a zero-length call returns the seed) | `src/common/buffer.cc:2089-2125`, `src/common/sctp_crc32.c:654-656` |

Consequence: this is the "raw" CRC-32C update. The textbook CRC-32C (init 0xFFFFFFFF, final XOR 0xFFFFFFFF) is obtained as `raw(seed = 0xFFFFFFFF, data) XOR 0xFFFFFFFF`. The standard check string `123456789` gives 0xE3069283 for the textbook variant, `0x1CF96D7C` for `raw(0xFFFFFFFF, ...)` and `0x58E3FA20` for `raw(0, ...)` (computed with an independent implementation of the table-driven step above). The table is generated, not copied: for index i, start with i and apply 8 times "shift right one bit, and if the bit shifted out was 1, XOR 0x82F63B78".

Seeds and placement in msgr2 frames:

| What is checksummed | Seed | Bytes covered | Where the 4-byte little-endian result goes | Source |
|---|---|---|---|---|
| Preamble | 0 | preamble bytes 0..27 | preamble bytes 28..31 | `frames_v2.cc:75-77` |
| Rev 0: each used segment i | 0xFFFFFFFF (written `-1`) | the segment's logical bytes (no padding) | epilogue crc slot i (0..3) | `frames_v2.cc:107` |
| Rev 1: segment 0 (if non-empty) | 0xFFFFFFFF | segment 0 logical bytes | 4 bytes immediately after segment 0 | `frames_v2.cc:154-159` |
| Rev 1: segments 1..3 | 0xFFFFFFFF | segment logical bytes | epilogue crc slot i-1 (0..2) | `frames_v2.cc:164-171` |
| Used but empty segment (epilogue slot) | 0xFFFFFFFF | none | the slot holds 0xFFFFFFFF (the seed passes through) | follows from the above; rst:155-156 |
| Unused trailing segment (epilogue slot) | n/a | n/a | slot is 0 | `frames_v2.cc:101,148` (epilogue zero-initialised) |
| Rev 1: empty segment 0 | n/a | n/a | **no crc bytes at all** | `frames_v2.cc:155` |

The segment CRCs are only meaningful when the sender's `ms_crc_data` option is on (default true, `src/common/options/global.yaml.in:1143-1148`; the frame assemblers are built with it at `ProtocolV2.cc:99-101`); when it is off the sender writes zero in every CRC slot (`frames_v2.cc:107,156,167`), and a receiver with the option on then rejects the frame (`frames_v2.cc:44-51,335-337`). A client must therefore **write real CRCs** (default servers verify) and should verify received ones; if a cluster ever runs with the option off, a verifying client would reject that peer's frames, so make the receive-side check switchable. The preamble CRC is always computed and always verified, in every mode including secure.

### 2.6 Frame layouts by mode and revision

Notation: `L0..L3` are the segment lengths from the preamble, `n` the number of segments.

#### 2.6.1 Revision 1, crc mode (the recommended and primary target)

```
preamble                      32 bytes
segment 0 payload             L0 bytes          (absent if L0 = 0)
segment 0 crc                 4 bytes           (absent if L0 = 0)
segment 1 payload             L1 bytes          (absent if n < 2 or L1 = 0)
segment 2 payload             L2 bytes          (absent if n < 3 or L2 = 0)
segment 3 payload             L3 bytes          (absent if n < 4)
epilogue                      13 bytes          (ABSENT when n = 1)
```

Epilogue (`frames_v2.h:130-134`):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | late_status |
| 1 | 4 | crc of segment 1 (slot 0) |
| 5 | 4 | crc of segment 2 (slot 1) |
| 9 | 4 | crc of segment 3 (slot 2) |

- Senders write `late_status = 0x0E` ("complete") (`frames_v2.h:176`, `frames_v2.cc:149`). The high nibble is zero on the wire as written by Ceph; the reserved-bit constants at `frames_v2.h:179-181` are defined but not set by the assembler.
- Receivers look only at the low nibble: 0x1 means "sender aborted the frame, drop it silently"; 0xE means complete; any other value is a frame error (`frames_v2.cc:53-62`). Aborted frames are only produced by the kernel client; a userspace client may treat 0x1 as "discard the frame" and any other non-0xE value as fatal.
- Total frame size = `32 + (L0 > 0 ? L0 + 4 : 0) + L1 + L2 + L3 + (n > 1 ? 13 : 0)` (`frames_v2.h:251-312`).
- A single-segment frame (every control frame with a payload, an empty control frame, and a MESSAGE with only a header) has no epilogue, so it cannot be aborted and carries no late status.
- The inline segment-0 crc exists only when segment 0 is non-empty; for a frame whose segment 0 is empty but later segments are not (not produced by v20.2.5 for any frame this note covers), no 4 bytes follow the preamble and the epilogue still carries three slots (`frames_v2.cc:154-159,164-172`, `frames_v2.h:263-266`).
- On receive the peer's `late_status` high nibble is not checked at all (mask 0x0F, `frames_v2.cc:55-62`).

Examples: an empty frame such as WAIT is exactly the 32-byte preamble. A KEEPALIVE2 frame is 32 + 8 + 4 = 44 bytes.

#### 2.6.2 Revision 0, crc mode (not recommended for a new client)

```
preamble                      32 bytes
segment 0..n-1 payloads       L0 + ... + L(n-1) bytes, no per-segment crc inline
epilogue                      17 bytes, ALWAYS present
```

Epilogue (`frames_v2.h:124-128`): `late_flags` (1 byte, bit 0 = aborted, **not covered by any crc**), then four u32 crc slots for segments 0..3. Slots of used segments hold the crc (0xFFFFFFFF for a used empty segment), slots of unused trailing segments hold 0 (`frames_v2.cc:99-114`, rst:128-186). The first segment (`ceph_msg_header2` of a MESSAGE) therefore cannot be trusted until the whole frame has arrived, which was the motivation for revision 1.

Differences rev 0 vs rev 1 in one place:

| Aspect | Rev 0 | Rev 1 |
|---|---|---|
| Segment 0 crc | in epilogue slot 0 | inline, 4 bytes after segment 0 |
| Epilogue presence | always | only if n > 1 |
| Epilogue size (crc mode) | 17 | 13 |
| Late indicator | `late_flags`, bit 0 = aborted, unprotected | `late_status`, nibble code 0x1 / 0xE |
| Header usable before frame end | no | yes (segment 0 is checked as soon as it is read) |
| Secure-mode nonces | 32-bit counter in the first 4 nonce bytes | 64-bit counter in the last 8 nonce bytes |

#### 2.6.3 Secure mode (reference only; a crc-only client can skip it)

Mode is chosen by the AUTH_DONE `connection mode` field (value 2). All frames *after* AUTH_DONE use it, including the client's AUTH_SIGNATURE (the client builds its secure handlers before sending that frame, `ProtocolV2.cc:1904-1914`; the server builds its own after sending AUTH_DONE, `ProtocolV2.cc:2342-2356`). The preamble CRC is still computed and checked (inside the encryption).

- Cipher: AES-128-GCM, 16-byte key, 12-byte nonce, 16-byte tag, no additional authenticated data (`src/msg/async/crypto_onwire.cc:19-22`; no AAD call is made anywhere in that file).
- Key material: the first 16 bytes of `connection_secret` are the key; the next 12 bytes are the initial nonce for the **client's receive** direction, the next 12 the initial nonce for the **client's transmit** direction (the server swaps them, `crypto_onwire.cc:279-317`). So `connection_secret` must be at least 40 bytes (assertion at `crypto_onwire.cc:286-287`). How `connection_secret` is obtained belongs to the cephx note.
- Nonce layout: 12 bytes viewed as `u32 fixed` followed by `u64 counter`, little-endian (`crypto_onwire.cc:24-32`). The very first AEAD operation uses the initial nonce unchanged; the nonce is incremented **after** each AEAD operation: rev 0 increments the 32-bit first field, rev 1 the 64-bit second field (`crypto_onwire.cc:87-112`).
- Segments and the epilogue are zero-padded to multiples of 16 bytes (`frames_v2.cc:253-261`, `frames_v2.h:332-335`); the preamble length field carries the unpadded length.
- Rev 0: one AEAD operation over preamble + padded segments + 16-byte epilogue (`late_flags` + 15 zero bytes), then the 16-byte tag (`frames_v2.cc:116-144`).
- Rev 1: up to three AEAD operations, each with its own tag and its own nonce step (`frames_v2.cc:176-231`): (a) preamble (32 bytes) plus a fixed 48-byte inline buffer holding the start of segment 0, zero-filled if unused, then a tag: 96 bytes on the wire; (b) only if padded segment 0 is longer than 48 bytes, the rest of segment 0 padded to 16, then a tag; (c) only if n > 1, padded segments 1..3 and a 16-byte epilogue (`late_status` + 15 zero bytes), then a tag.
- Wire size of the rev-1 secure preamble = 32 + 48 + 16 = 96 (`frames_v2.h:152-153,235-241`).

**[confirm on capture]** every statement in 2.6.3 (not exercised by a crc-only client).

#### 2.6.4 Optional compression (reference only)

If both sides advertised COMPRESSION and a method is agreed with COMPRESSION_REQUEST / COMPRESSION_DONE, the sender may set preamble flag bit 0 and send each segment compressed (`frames_v2.cc:243-245,502-527,529-538`). The server does not negotiate it for secure-mode connections unless configured (rst:575). A client that does not advertise the bit never sees compressed frames.

### 2.7 Control-frame payloads

Field lists are in wire order (`frames_v2.h:518-805`). "addrvec" is the entity_addrvec_t of 2.8.

| Tag | Fields |
|---|---|
| HELLO | entity_type u8 (CEPH_ENTITY_TYPE_*), peer_addr entity_addr_t |
| AUTH_REQUEST | method u32, preferred_modes (u32 count + u32 each), auth_payload (u32 len + bytes) |
| AUTH_BAD_METHOD | method u32, result i32 (negative errno), allowed_methods (count + u32 each), allowed_modes (count + u32 each) |
| AUTH_REPLY_MORE | auth_payload (u32 len + bytes) |
| AUTH_REQUEST_MORE | auth_payload (u32 len + bytes) |
| AUTH_DONE | global_id u64, connection_mode u32, auth_payload (u32 len + bytes) |
| AUTH_SIGNATURE | 32 raw bytes |
| CLIENT_IDENT | addrs (addrvec), target_addr (entity_addr_t), gid i64, global_seq u64, supported_features u64, required_features u64, flags u64, cookie u64 |
| SERVER_IDENT | addrs (addrvec), gid i64, global_seq u64, supported_features u64, required_features u64, flags u64, cookie u64 |
| IDENT_MISSING_FEATURES | features u64 |
| SESSION_RECONNECT | addrs (addrvec), client_cookie u64, server_cookie u64, global_seq u64, connect_seq u64, msg_seq u64 |
| SESSION_RESET | full bool |
| SESSION_RETRY | connect_seq u64 |
| SESSION_RETRY_GLOBAL | global_seq u64 |
| SESSION_RECONNECT_OK | msg_seq u64 |
| WAIT | (no fields; the frame has one empty segment) |
| KEEPALIVE2 / KEEPALIVE2_ACK | stamp utime_t (u32 sec, u32 nsec); the ACK echoes the received stamp |
| ACK | seq u64 |
| COMPRESSION_REQUEST | is_compress bool, preferred_methods (count + u32 each) |
| COMPRESSION_DONE | is_compress bool, method u32 |

Constants:

| Name | Values | Source |
|---|---|---|
| Entity types (HELLO, banner of daemons) | MON 0x01, MDS 0x02, OSD 0x04, CLIENT 0x08, MGR 0x10, AUTH 0x20, ANY 0xFF | `src/include/msgr.h:91-98` |
| Auth methods | UNKNOWN 0, NONE 1, CEPHX 2, GSS 4 | `src/include/ceph_fs.h:102-104,120` |
| Connection modes | UNKNOWN 0, CRC 1, SECURE 2 | `src/include/ceph_fs.h:107-109` |
| CLIENT_IDENT / SERVER_IDENT flags | bit 0 = CEPH_MSG_CONNECT_LOSSY (1) | `src/include/msgr.h:162` |

Semantics a client needs:

- **gid:** a signed 64-bit value. A client that has not yet been given a global id by a monitor sends -1 (all bits set), because a fresh client messenger is created with the "new" name `client.-1` (`src/msg/Messenger.cc:31-37`, `src/msg/msg_types.h:60,72`). After the first successful monitor authentication the Ceph library renames itself to `client.<global_id>` (`src/librados/RadosClient.cc:294`), and later connections (OSDs) send that id. The `global_id` in AUTH_DONE is the same number.
- **global_seq:** a per-messenger counter, u32 range stored in u64. The first value handed out is 1 and it increases with every new connection attempt, including connections to other daemons made through the same messenger (`ProtocolV2.cc:1761`, `src/msg/async/AsyncMessenger.h:403-411`); on SESSION_RETRY_GLOBAL the client takes `max(local, server value) + 1` (`ProtocolV2.cc:2081-2099`). The server compares it only when it finds an existing registered connection from the same client address (3.5).
- **cookie:** the client cookie is 0 for lossy sessions and a random non-zero u64 for lossless ones (`ProtocolV2.cc:1959-1961`). For a lossy session the server cookie in SERVER_IDENT is also 0 (`ProtocolV2.cc:2937-2939`).
- **supported / required features** here are CEPH_FEATURE bits (2.10), not msgr2 banner bits. In CLIENT_IDENT the stock client sends its own policy's `required` mask (what it demands of the server) OR `MSG_ADDR2` (`ProtocolV2.cc:1968-1976`); the stock librados policy requires only OSDREPLYMUX (bit 12, 0x1000), so a stock client sends `required = 0x0800000000001000` (`src/librados/RadosClient.cc:256`). Neither side uses the *other's* `required_features` field: the server only tests its own required mask against the client's `supported` field (`ProtocolV2.cc:2457-2467`), and the client's SERVER_IDENT handler never reads the server's `required` field (`ProtocolV2.cc:2149-2202`). So `required` in CLIENT_IDENT is informational.
- **Policy selection by HELLO type:** the server picks its policy (lossy or not, which features it requires, whether it registers the connection) from the entity type in the *client's HELLO* (`ProtocolV2.cc:1051-1062`). A client must say `CLIENT (0x08)`; claiming a daemon type changes the server's behaviour and is out of scope.
- **flags:** lossy clients send bit 0 set (`ProtocolV2.cc:1963-1966`). The *server's* flag in SERVER_IDENT decides what the client adopts (`ProtocolV2.cc:2187`).
- **target_addr** in CLIENT_IDENT must match exactly one of the server's own advertised addresses (type, nonce, IP, port), see 3.6.

### 2.8 entity_addr_t and entity_addrvec_t

#### entity_addr_t (current format, marker 1)

Source: `src/msg/msg_types.h:476-517` (encode), `518-555` (decode).

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 1 | marker | 1 for the current format; 0 means "legacy sockaddr_storage format" (decoder only; do not send) |
| 1 | 1 | struct_v | 1 |
| 2 | 1 | struct_compat | 1 |
| 3 | 4 | struct_len (u32) | length of the rest, 28 for IPv4 |
| 7 | 4 | type (u32) | 0 NONE, 1 LEGACY (v1 protocol), 2 MSGR2, 3 ANY, 4 CIDR (`msg_types.h:238-245`). A sender whose feature argument lacks SERVER_NAUTILUS would rewrite 3 to 1 (`msg_types.h:487-498`); frames use the fixed argument of 2.1, so 3 is preserved |
| 11 | 4 | nonce (u32) | per-process unique value; for a client a random 32-bit value; a monitor's nonce is normally 0 **[confirm on capture]** |
| 15 | 4 | elen (u32) | number of bytes that follow, 16 for IPv4 and 28 for IPv6 (the length of the Linux `sockaddr_in` / `sockaddr_in6`) |
| 19 | 2 | address family (u16, little-endian) | 2 = AF_INET, 10 = AF_INET6 (Linux numbering). Only the Windows build translates its own AF_INET6 value to 10 (`msg_types.h:506-511,542-546`); the code has no such translation for macOS / BSD, where the native value is not 10, so a client on any non-Linux OS must write the literal numbers 2 and 10 itself |
| 21 | elen - 2 | `sa_data` | see below |

`sa_data` for IPv4 (14 bytes): port (2 bytes, **big-endian**), IPv4 address (4 bytes, network order), 8 zero bytes. For IPv6 (26 bytes): port (2, big-endian), flowinfo (4), address (16), scope id (4); flowinfo and scope id are normally 0 **[confirm on capture]**.

IPv4 total = 1 + 1 + 1 + 4 + 28 = 35 bytes, with `struct_len = 28`; IPv6 total = 3 + 4 + 40 = 47 bytes, `struct_len = 40`. A decoder accepts `elen` smaller than the full length (the remainder stays zero) but rejects one larger than the sockaddr for the decoded family (14 sa_data bytes for IPv4, 26 for IPv6, 26 for an unknown family), and `struct_compat` greater than 1; a larger `struct_v` is accepted and the extra bytes inside `struct_len` are skipped (`msg_types.h:526-531,549-554`). Equality of two addresses in the server's checks is a bytewise compare of the whole 36-byte object (`msg_types.h:566`), so every unused byte must be zero, including the 8 zero bytes in an IPv4 `sa_data` and the bytes of the union beyond it.

A decoder accepts `elen = 0` (no family, no bytes) as "no address" (`msg_types.h:533-553`), but the stock **encoder never emits it**: a blank address (family 0) is encoded with `elen = 28` (the size of the largest sockaddr in the union, `msg_types.h:321-329,258-264,500-515`), i.e. the family field 0 followed by 26 zero bytes, `struct_len = 40`. In memory the whole object is 36 bytes (type + nonce + a 28-byte sockaddr union), which is the size the server's equality test compares (`msg_types.h:566`).

#### entity_addrvec_t

Source: `src/msg/msg_types.cc:334-395`.

| Field | Size | Notes |
|---|---|---|
| marker | 1 | 2 for the vector form (always sent when the fixed feature argument of 2.1 is in effect); 1 = the versioned body of a single entity_addr_t follows directly (struct_v, struct_compat, struct_len, ...), i.e. the first marker byte is shared; 0 = legacy; anything above 2 is rejected |
| count | 4 | u32 |
| addresses | count x entity_addr_t | each in the marker-1 format above, including its own leading marker byte |

A client sending one address therefore writes `02 01 00 00 00` followed by one 35-byte IPv4 entity_addr_t (40 bytes total).

### 2.9 The MESSAGE frame

A MESSAGE frame has four segments (`frames_v2.h:810-873`, `SegmentIndex::Msg` at `frames_v2.h:81-87`):

| Segment | Content | Alignment hint |
|---|---|---|
| 0 | `ceph_msg_header2`, exactly 41 bytes | 8 |
| 1 | front (the primary message payload) | 8 |
| 2 | middle | 8 |
| 3 | data | 4096 |

Trailing empty segments are not transmitted (2.3). Segment lengths in the preamble **are** the message's front / middle / data lengths; there is no separate length field in the header (the old `front_len`, `middle_len`, `data_len` of v1 are reconstructed from the segment lengths on receive, `ProtocolV2.cc:1425-1437`).

`ceph_msg_header2` (`src/include/msgr.h:207-223`), little-endian, packed, 41 bytes:

| Offset | Size | Field | Meaning / what a client does |
|---|---|---|---|
| 0 | 8 | seq (u64) | per-session message sequence number, starting at 1 for the first message in each direction; sender sets `++out_seq` (`ProtocolV2.cc:533`) |
| 8 | 8 | tid (u64) | transaction id of the message (used by OSD ops to match replies) |
| 16 | 2 | type (u16) | message type code (CEPH_MSG_* / MSG_*), see the message notes |
| 18 | 2 | priority (u16) | e.g. 64 low, 127 default, 196 high, 255 highest (`msgr.h:225-228`) |
| 20 | 2 | version (u16) | encoding version of this message type's payload |
| 22 | 4 | data_pre_padding_len (u32) | always 0 when sent by v20.2.5 (`ProtocolV2.cc:546`); a client should send 0; **[unverified]** whether a receiver handles non-zero (the field is not used in the receive path read for this note, `ProtocolV2.cc:1404-1437`) |
| 26 | 2 | data_off (u16) | offset hint for the data payload, copied through to the dispatched message; clients using plain buffers send 0 **[confirm on capture]** |
| 28 | 8 | ack_seq (u64) | highest `seq` received from the peer so far (`ProtocolV2.cc:536`); piggybacked ack |
| 36 | 1 | flags (u8) | taken from the v1 footer flags: bit 0 COMPLETE, bit 1 NOCRC, bit 2 SIGNED (`msgr.h:247-249`). The messenger encodes messages with crc flags 0, so the encoder sets exactly COMPLETE (`ProtocolV2.cc:437`, `src/msg/Message.cc:263`); v20.2.5 sends 1 |
| 37 | 2 | compat_version (u16) | oldest decoder version able to read this payload; the message encoder copies `version` into it when the message type left it 0 (`src/msg/Message.cc:248-251`). The receiver hands it to the message decoder unchanged (`ProtocolV2.cc:1435`) |
| 39 | 2 | reserved (u16) | 0 |

Receive side mapping (`ProtocolV2.cc:1425-1439`): `header2.flags` becomes the footer flags; the old `src` name is not on the wire in msgr2 and is reconstructed as `<peer entity type>.<gid from the ident frame>`; the three footer crcs are set to zero because integrity is handled by the frame crcs. The message is decoded only after the whole frame (including the epilogue) has been verified; a MESSAGE frame arriving before the session is READY is fatal (`ProtocolV2.cc:1170-1174`).

Sequence numbers and acks (`ProtocolV2.cc:530-537,610-637,1482-1504,1529-1535,1584`):

- Receiver: a message with `seq <= in_seq` is dropped as old; `seq > in_seq + 1` is logged and accepted (a gap is tolerated); otherwise `in_seq = seq` (`ProtocolV2.cc:1482-1504,1523`). **Trap:** in the old-message branch the stock server returns without queueing another frame read (`ProtocolV2.cc:1488-1497`), so the connection stops being read until a timeout or the client closes it. A client must therefore never repeat or lower a `seq` on a session; after a failed send, open a new session instead of retransmitting numbered messages.
- On lossless sessions the receiver acknowledges by putting `in_seq` into `ack_seq` of its next outgoing message, or, if nothing is outgoing, by sending an ACK frame carrying `in_seq`. The sender then drops everything up to that seq from its resend queue.
- On lossy sessions (the normal case for a client of a monitor or OSD) neither `ack_left` nor the sent-queue exist (`ProtocolV2.cc:1530-1533,611-613,681`): no ACK frames are generated, `ack_seq` may be sent but is ignored. Sequence numbers still run and still matter: the server drops any message whose seq is not greater than the last one seen, so the client must count from 1.

### 2.10 Feature bits

#### msgr2 banner features (`src/include/msgr.h:53-64`)

| Bit | Name | Value | Meaning | Minimal client |
|---|---|---|---|---|
| 0 | REVISION_1 | 0x1 | msgr2.1 framing | advertise |
| 1 | COMPRESSION | 0x2 | on-wire compression handshake | do not advertise |

Minimal client banner: supported = 0x1, required = 0x0. Note the bit position in the banner mask equals the constant value of `CEPH_MSGR2_FEATURE_*`; the `FEATUREMASK` variants add an incarnation mask of 0 for both (`msgr.h:43-48`), so masks and bits coincide.

#### CEPH_FEATURE bits used in CLIENT_IDENT / SERVER_IDENT (`src/include/ceph_features.h`)

- Hard requirement imposed on every peer by the framing layer: `CEPH_FEATUREMASK_MSG_ADDR2` (bit 59, `ceph_features.h:183`). A client that leaves it out gets IDENT_MISSING_FEATURES (`ProtocolV2.cc:2457-2467`).
- Server policy for ordinary clients: the monitor requires nothing more for `TYPE_CLIENT` (`src/ceph_mon.cc:808-809`), and the OSD's public messenger default requires 0 (`src/ceph_osd.cc:598`); its `osd_required` (UID, PGID64, OSDENC, bits 0, 9, 13; `ceph_osd.cc:593-596`) applies to the connections the OSD *initiates* to monitors / managers (`ceph_osd.cc:602-605`), not to clients. Both default policies are the **lossy, server-side** kind (`src/msg/Policy.h:68-76`), which is why SERVER_IDENT carries the LOSSY flag. Other daemon types (MDS, MGR) were not read **[unverified]**.
- **What the advertised mask really controls:** the server stores `client supported & server supported` as the connection's feature set (`ProtocolV2.cc:2469-2470`) and encodes every message it sends on that connection, for example MOSDMap and OSDMap, using that set. Advertising fewer bits than the code can decode means older (or different) encodings arrive. The client does the same with `server supported & own supported` for messages it sends (`ProtocolV2.cc:2183-2184`). The `supported` field in each ident frame is the sender's full policy mask, not a negotiated value.
- Recommended advertisement for a v20.2.5 target: exactly the value of `CEPH_FEATURES_ALL` in this release, `0x3f07fffffffdffff` (`ceph_features.h:195-261`, value computed by compiling the header; bit 17 and bits 62..63 are clear, and several bits carry incarnation markers: bit 57 set via SERVER_JEWEL, bit 28 via SERVER_MIMIC). This is what the stock client library advertises (`src/msg/Policy.h:44-49` sets the supported default to this constant). **[confirm on capture]** that the value in a captured CLIENT_IDENT from `rbd` equals it.
- The CEPH_FEATURE value used by `HAVE_FEATURE` tests is the "mask" form (bit plus incarnation bits), so a peer is recognised as supporting, for example, SERVER_TENTACLE only if bits 50 and 57 are both set (`ceph_features.h:17-38,163`).

---

## 3. Client procedure

Steps are numbered for reference. "Fault" means: close the TCP connection, discard all connection state, and (for a lossy client) start again from step 1 after a back-off.

### 3.1 Connect and banner

1. Open a TCP connection to the **v2** address of the target (for monitors the msgr2 port from the monmap, for OSDs the address with `type = 2` in the OSD map). From the first byte, start a **pre-auth log** (3.4): keep a copy of every byte you receive and every byte you send, until the moment you build your own AUTH_SIGNATURE (step 8). The stock code has it switched on from connection setup (`ProtocolV2.cc:113`), so it includes both banners.
2. Send the 26-byte banner (2.2) and read the server's. Verify the prefix, read the payload, check required masks (2.2), check that the server advertises REVISION_1. A server that does not advertise it would use rev 0 framing, which a rev-1-only client cannot speak; reject it with a clear error.
3. After the server's banner payload has been read (not before; `ProtocolV2.cc:1021-1026`), send HELLO: `entity_type = 0x08` (client) and `peer_addr` = the target address you are dialling, as an entity_addr_t. Read the server's HELLO and verify its `entity_type` equals the one you expect (0x01 for a monitor, 0x04 for an OSD); a mismatch aborts the connection (`ProtocolV2.cc:1051-1073`). Take note of the HELLO's `peer_addr`: it is the address the server sees for you, and the stock client uses its IP part (port forced to 0, type ANY, nonce = its own random nonce) as the address it advertises in CLIENT_IDENT when it had no better one (`ProtocolV2.cc:1075-1110`, `src/msg/async/AsyncMessenger.cc:1113-1160`); with the option `ms_learn_addr_from_peer` off it uses the local socket address instead (`ProtocolV2.cc:1078-1088`). The server fills that HELLO address from the accepted socket and the listener's address type, so it carries the client's ephemeral source port (`src/msg/async/PosixStack.cc:259-263`, `src/msg/async/AsyncConnection.cc:540`).

### 3.2 Authentication frames

4. Send AUTH_REQUEST with `method` = the first method the client library prefers (the stock client takes the first entry of its configured list, `src/mon/MonClient.cc:1874-1881`; CEPHX = 2 in practice), `preferred_modes` = the connection modes you accept in order of preference (for a crc-only client: just `[1]`; the stock client sends its configured list, default `secure crc` toward monitors and managers and `crc secure` toward OSDs, `global.yaml.in:986-1000,1028-1040`, `src/auth/AuthRegistry.cc:185-213`), and the method-specific payload from the cephx note. What the payload contains depends on the peer: to a monitor it starts with a mode byte, the entity name and the global id (`MonClient.cc:1895-1900`); to an OSD it is a service authorizer built from a ticket (`MonClient.cc:1536-1548`). Both are the cephx note's business.
5. The server's possible answers (server logic at `ProtocolV2.cc:2258-2340`):
   - **AUTH_REPLY_MORE** (tag 4): hand the payload to the auth method; send the method's answer in **AUTH_REQUEST_MORE** (tag 5). Repeat as often as needed (`ProtocolV2.cc:1837-1869`).
   - **AUTH_BAD_METHOD** (tag 3): either the method/mode combination was refused (`result = -EOPNOTSUPP`, sent when the server cannot pick a mode, `ProtocolV2.cc:2273-2278`) or the auth handler returned a negative error (for example a failed authentication, `ProtocolV2.cc:2338`). The frame lists the methods and modes the server allows for you. Choose another method or mode from those lists if you have one, and send a fresh AUTH_REQUEST on the same connection (`ProtocolV2.cc:1806-1835`); the bytes of the AUTH_BAD_METHOD frame and of the second request stay inside the pre-auth logs (the logs are not reset between attempts); otherwise stop and report the server's `result` and lists. Error numbers are Linux errnos, negative **[unverified]** for non-Linux servers.
   - **AUTH_DONE** (tag 6): authentication finished; see step 7. A server that returns `-EBUSY` internally simply closes the connection instead of sending a frame (`ProtocolV2.cc:2334-2336`).
6. **Mode negotiation:** the server walks *your* `preferred_modes` list in order and takes the first mode it allows for this peer type and auth method (`src/auth/AuthRegistry.cc:308-324`). Defaults on the cluster side are `ms_mon_service_mode = secure crc` for monitors (`global.yaml.in:971-985`) and `ms_service_mode = crc secure` for OSDs (`global.yaml.in:1016-1027`), so both accept crc; for auth method NONE only crc is ever allowed (`AuthRegistry.cc:295-302`). A cluster whose allowed-mode list excludes `crc` rejects a crc-only client with AUTH_BAD_METHOD, and the allowed-modes list in that frame is how a client can tell the user why. A stock client talking to a default monitor will end up in **secure** mode, so a crc-only client must not copy the stock list.
7. On **AUTH_DONE**: record `global_id` (it becomes your `gid` for later connections) and `connection_mode` (1 = crc, 2 = secure). Pass the method payload to the cephx code, which yields `session_key` (and, in secure mode, `connection_secret`). If `connection_mode` is 2 and the client does not implement secure mode, fault with a clear message. Mode 1 means all further frames are in the crc layout of 2.6.1.

### 3.3 AUTH_SIGNATURE (pre-auth integrity check)

8. Immediately after handling AUTH_DONE, send **AUTH_SIGNATURE**: 32 bytes = `HMAC-SHA256(key = the secret bytes of session_key, message = every byte received so far)`. If no session key exists (auth method NONE) the signature is 32 zero bytes (`ProtocolV2.cc:1909-1914`). "Every byte received so far" means the raw wire bytes from the first byte of the server banner through the last byte of the AUTH_DONE frame (including its preamble, payload and inline crc), banners and HELLO frames included. Stop logging **before** you build and send this frame, so neither the signature frame you send nor the one you receive is part of any log (`ProtocolV2.cc:1912-1913,2354-2355,2399`). In crc mode the signature frame is an ordinary rev-1 frame; in secure mode it is already sent encrypted.
9. Read the server's AUTH_SIGNATURE and compare it with `HMAC-SHA256(session_key secret bytes, every byte you sent before your own AUTH_SIGNATURE)`, again 32 zero bytes if there is no session key (`ProtocolV2.cc:2373-2400`). A mismatch is fatal. What exactly counts as "the secret bytes of session_key" is the raw key material of the cephx session key (`src/auth/Crypto.cc:234-246` hashes the key handler's stored secret); `cephx.md` 2.9 pins the cephx side of that: the AUTH ticket session key for a monitor connection, the OSD ticket session key for an OSD connection (**[confirm on capture]**).
10. Only after this exchange the pre-auth log is released.

If the server had advertised COMPRESSION and so had the client, a COMPRESSION_REQUEST / COMPRESSION_DONE exchange would come next (`ProtocolV2.cc:1917-1924,2204-2236`); a minimal client does not advertise the bit, so nothing happens here.

### 3.4 Pre-auth log, practical rules

- The log must cover bytes in transmission order per direction: sent bytes in one buffer, received bytes in the other. The two buffers are independent.
- It covers exactly the stream that crosses the TCP socket in the crc framing used before authentication ends, nothing re-encoded.
- The stock implementation caps each log at about 20 MB as a debug assertion (`ProtocolV2.cc:817-830,859-863`); real handshakes are a few hundred bytes to a few kilobytes.

### 3.5 Session establishment (lossy client)

11. Send **CLIENT_IDENT**:
    - `addrs`: an addrvec with your address (marker 2, count 1). IP = what the server said you are in HELLO (or the real local IP), port 0, type = ANY (3), nonce = a random number kept for the process lifetime (the stock messenger draws 64 random bits and the address field keeps the low 32, `src/msg/Messenger.cc:39-47`). The server rejects an empty vector or a first address that equals an all-zero entity_addr_t (`ProtocolV2.cc:2436-2440`). Note that an OSD registers lossy clients on its public messenger by address and nonce (`register_lossy_clients` is true for its default policy, `src/msg/Policy.h:29-34,71-73`, `src/ceph_osd.cc:598`; the monitor's `stateless_server` policy does not register them, `Policy.h:74-76`). When a second connection arrives from the same address and nonce, the OSD closes the older one in favour of the new one, **provided the new connection's `global_seq` is not lower than the older one's**; otherwise the new connection is the one that gets closed (`ProtocolV2.cc:2482-2509,2701-2721`). So use **one connection per (address, nonce) and OSD**, or distinct nonces, and make `global_seq` strictly increase across connections.
    - `target_addr`: the exact entity_addr_t of the server (see 3.6).
    - `gid`: -1 before the first monitor authentication, afterwards the `global_id`.
    - `global_seq`: your counter (2.7). `supported_features`: 2.10. `required_features`: at least `0x0800000000000000` (MSG_ADDR2); the stock client sends `0x0800000000001000` (adds OSDREPLYMUX) and the servers ignore the field (2.7). `flags`: 1 (lossy). `cookie`: 0.
12. Wait for the answer:
    - **SERVER_IDENT**: verify that its `addrs` contain your `target_addr` byte for byte, otherwise fault (`ProtocolV2.cc:2173-2177`). Store the server `gid` (the peer's entity number), take `connection features = server supported & own supported`, adopt `lossy` from the server's `flags` (`ProtocolV2.cc:2179-2188`). If lossy is not set the server created a lossless session with a non-zero server cookie; a lossy-only client may accept it but must then never attempt SESSION_RECONNECT, simply opening a new session after any fault **[unverified which daemons would do this to a CLIENT-type peer; per the policies in 2.10 none are expected to]**.
    - **IDENT_MISSING_FEATURES**: the mask lists bits the server demands that you did not advertise. Log it and fault (`ProtocolV2.cc:2016-2033`).
    - **WAIT**: a connection race was detected on the server; fault and retry after the maximum back-off (default 15 s, `ProtocolV2.cc:2101-2115,402-404`, `global.yaml.in:1134-1141`).
    - Anything else in this state is fatal.
13. The session is now READY. The client is allowed to send MESSAGE frames; before this point it must not.

### 3.6 target_addr and the address matching rules

The server compares the `target_addr` of CLIENT_IDENT with the list of its own addresses (check at `ProtocolV2.cc:2441-2447`; membership is tested with a bytewise equality, `msg_types.h:566,712-719`). A client should therefore copy the entity_addr_t of the chosen address **unchanged** from the monitor map / OSD map, including its nonce. The stock client takes the first entry whose type is MSGR2 **or LEGACY** (`src/msg/async/AsyncMessenger.cc:846-857`) and chooses the protocol from that entry's type, so a v2-only client must filter explicitly for `type = 2` instead of copying that rule. For addresses typed by a user (for example from a configuration line) the stock library has extra conversion steps before connecting; whether and how a minimal client may synthesise a `type = 2, nonce = 0` address for the first monitor contact is an open question **[confirm on capture]**.

### 3.7 Message exchange and housekeeping

14. Sending: build `ceph_msg_header2` (2.9) with `seq = ++out_seq`, `ack_seq = in_seq`, `flags = 1`, `data_pre_padding_len = 0`; put front, middle, data into segments 1, 2, 3; compute CRCs per 2.5/2.6.1; write the frame. Segment lengths in the preamble must equal the payload lengths exactly.
15. Receiving: read the 32-byte preamble, verify its CRC and structure, read segment 0 plus its 4-byte crc, read segments 1..3, read the 13-byte epilogue if n > 1, verify crcs and late_status. For MESSAGE, check that segment 0 is at least 41 bytes (the stock code casts the buffer without a length check, `frames_v2.h:843-846`; a client must check). Apply the seq rules of 2.9. Then dispatch by `header2.type`.
16. KEEPALIVE2 from the server: answer with KEEPALIVE2_ACK carrying the same timestamp (`ProtocolV2.cc:1687-1718`). KEEPALIVE2_ACK is only informational. ACK frames: tolerated (and used to trim a resend queue on lossless sessions), no reply needed (`ProtocolV2.cc:1737-1750`).
17. Timers visible to a client (server side defaults, `global.yaml.in:1269-1280`, `src/msg/async/AsyncConnection.cc:835-880`): a connection that has not become ready within `ms_connection_ready_timeout` = 10 s of connect is dropped, so authentication (including any wait for ticket exchange) must finish inside 10 s; an established connection that sees no traffic for `ms_connection_idle_timeout` = 900 s is dropped. A client that may stay idle longer than that should send KEEPALIVE2 periodically, or accept the drop and reconnect. The stock monitor client sends one every `mon_client_ping_interval` = 10 s and reconnects if no KEEPALIVE2_ACK arrives within `mon_client_ping_timeout` (`src/mon/MonClient.cc:1058-1071`, `global.yaml.in:2348-2360`); the cadence used toward OSDs was not found. The idle timer is refreshed whenever the server's socket becomes readable (`AsyncConnection.cc:385-387`), so any inbound frame, a KEEPALIVE2 included, resets it. Send KEEPALIVE2 / ACK only in the READY state: both handlers treat any other state as fatal (`ProtocolV2.cc:1692-1696,1725-1729`).
18. Close by dropping the TCP connection. There is no goodbye frame in v20.2.5 (1.4).

### 3.8 Reconnect handling (not needed by a lossy client, listed for completeness)

On a lossless session the client, after a transport failure, reconnects with SESSION_RECONNECT (`client_cookie`, `server_cookie` from the earlier idents, `global_seq`, incremented `connect_seq`, `msg_seq = in_seq`; `ProtocolV2.cc:1995-2014`). The server answers SESSION_RECONNECT_OK (`msg_seq`, the last message it received, so the client drops acknowledged messages, `ProtocolV2.cc:2117-2147`), SESSION_RESET (`full = true` clears the session; false only clears the cookies and expects a fresh CLIENT_IDENT, `ProtocolV2.cc:2035-2059`), SESSION_RETRY (client sets `connect_seq = value + 1` and resends, `ProtocolV2.cc:2061-2079`), SESSION_RETRY_GLOBAL (client raises its global seq, `ProtocolV2.cc:2081-2099`), or WAIT. The server-side conditions that select each answer are at `ProtocolV2.cc:2515-2673`.

---

## 4. Minimal-client choices

### 4.1 Must support

- Banner exchange with REVISION_1, rev-1 framing in **crc mode** only.
- Preamble build/parse with CRC; 1..4 segment frames; rev-1 first-segment inline crc; rev-1 epilogue for n > 1; late_status check.
- A hand-written raw CRC-32C (2.5), table generated at start-up; no dependency on hardware CRC instructions (iPXE has no CRC-32C implementation, so this must be written).
- HELLO, AUTH_REQUEST / AUTH_REPLY_MORE / AUTH_REQUEST_MORE / AUTH_DONE / AUTH_BAD_METHOD, AUTH_SIGNATURE (with HMAC-SHA256 and the two pre-auth logs), CLIENT_IDENT, SERVER_IDENT, IDENT_MISSING_FEATURES, WAIT, KEEPALIVE2 / KEEPALIVE2_ACK, ACK (receive and ignore), MESSAGE.
- entity_addr_t / entity_addrvec_t encode for IPv4 (and decode for both families and the multi-address vectors that monitors and OSDs send).
- Lossy-session semantics: no resend queue, `seq` counting from 1, a new session after every fault.
- Defensive limits on everything attacker-controlled: banner payload length, per-segment length, number of addresses, vector counts, bufferlist lengths (the stock framing layer has none).
- Never reuse or lower a MESSAGE `seq`, and never send MESSAGE / KEEPALIVE2 before SERVER_IDENT has been processed (2.9, 3.7).
- Keep the pre-auth logs across AUTH_BAD_METHOD retries; they restart only on a new TCP connection (3.2).

### 4.2 May skip

| Feature | Why it can be skipped | What to do if the server insists |
|---|---|---|
| Secure mode (AES-128-GCM, rev 1 and rev 0) | `ms_service_mode` defaults to `crc secure`, so crc is accepted by default (`global.yaml.in:1016-1022`) | on AUTH_BAD_METHOD or AUTH_DONE mode 2, fail with a message that names the cluster setting |
| Revision 0 framing | v20.2.5 daemons advertise REVISION_1 | reject a peer without the bit |
| Compression stage | optional; only entered if both sides advertise the bit | do not advertise bit 1 |
| Lossless sessions and all reconnect frames (SESSION_RECONNECT, RESET, RETRY, RETRY_GLOBAL, RECONNECT_OK) | mon and OSD public policies for `TYPE_CLIENT` are lossy (`ceph_mon.cc:807-809`, `ceph_osd.cc:598`) | treat a non-lossy SERVER_IDENT as an unsupported configuration, or accept it and still never reconnect |
| Aborted-frame handling beyond "discard" | only the kernel client creates them | discard on late_status 0x1 |
| v1 protocol | out of scope | fail on the `ceph v027` banner |
| IPv6 sending | wire format is given; optional | decode IPv6 anyway |
| Sending KEEPALIVE2 | only needed to survive long idle periods | answer the server's; send your own if idle > ~ 15 min |
| Verifying segment CRCs on receive | TCP already protects the stream; verification is cheap debugging value | strongly recommended while developing, may be made optional later |

### 4.3 Must reject

- Banner prefix that is not `ceph v2\n` (log specially if it is the v1 prefix).
- Peer banner with required feature bits outside what we advertise (bit 1 would only be required if an administrator forced compression; we cannot comply).
- Peer HELLO with an unexpected entity type.
- Preamble CRC mismatch, `num_segments` outside 1..4, empty last segment when n > 1, tags outside 1..22, frames received in the wrong state.
- SERVER_IDENT whose `addrs` do not contain the dialled address.
- AUTH_SIGNATURE mismatch.
- Any frame that would exceed the client's configured memory budget.

### 4.4 Feature bits to advertise

- msgr2 banner: supported `0x1`, required `0x0`.
- CEPH_FEATURE mask in CLIENT_IDENT: `0x3f07fffffffdffff` (the v20.2.5 `CEPH_FEATURES_ALL`, compiled and printed during review), required `0x0800000000000000` (the stock client sends `0x0800000000001000`; servers ignore the field). Advertising less is possible but changes the encodings the server uses; every decoder the client implements must be able to read what the advertised set allows. Advertising less can also get the client refused: an OSD recomputes its client-facing required mask from the OSDMap (`src/osd/OSD.cc:8820-8826`, `src/osd/OSDMap.cc:1754-1850`, summarised in `osdmap.md` 2.8), which can include the CRUSH tunable bits, SERVER_LUMINOUS / SERVER_REEF, CRUSH_MSR, and CEPHX_V2 (bit 61, required of everyone once `require_min_compat_client` is nautilus or newer, `OSDMap.cc:1832-1842`); the full mask above contains all of them, which is another reason to send it unreduced.

---

## 5. Test vectors needed

### 5.1 Computed examples (derived from the source rules above, not captured)

Produced with an independent table-driven CRC-32C and the layouts above, and recomputed from scratch with a second independent script during review (all values below matched); **[confirm on capture]** each, because both scripts follow the same reading of the source. Use them as unit-test inputs for the framing and CRC code, then compare against real captures.

CRC checks (raw function, see 2.5):

| Input | Seed | Result |
|---|---|---|
| ASCII `123456789` | 0 | 0x58E3FA20 |
| ASCII `123456789` | 0xFFFFFFFF | 0x1CF96D7C (textbook CRC-32C 0xE3069283 is this XOR 0xFFFFFFFF) |
| empty | 0xFFFFFFFF | 0xFFFFFFFF |
| 32 zero bytes | 0 | 0x00000000 |
| table entries | n/a | T[1] = 0xF26B8303, T[2] = 0xE13B70F7, T[255] = 0xAD7D5351 |

Banner, server of v20.2.5 (supported 3, required 0), 26 bytes:

```
63 65 70 68 20 76 32 0a 10 00 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Banner of a rev-1-only client (supported 1):

```
63 65 70 68 20 76 32 0a 10 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

entity_addr_t for `v2:192.0.2.10:6789`, nonce 0 (35 bytes):

```
01 01 01 1c 00 00 00 02 00 00 00 00 00 00 00 10 00 00 00 02 00 1a 85 c0 00 02 0a 00 00 00 00 00 00 00 00
```

HELLO frame from a client to that address (rev 1, crc, 72 bytes: preamble 32, payload 36, crc 4; preamble crc 0x066bbd3f, payload crc 0x5ad6a3eb):

```
01 01 24 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 3f bd 6b 06
08 01 01 01 1c 00 00 00 02 00 00 00 00 00 00 00 10 00 00 00 02 00 1a 85 c0 00 02 0a 00 00 00 00 00 00 00 00
eb a3 d6 5a
```

WAIT frame (empty, preamble only, 32 bytes):

```
10 01 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 c8 e3 aa b0
```

KEEPALIVE2 with stamp sec = 0x5f000000, nsec = 1 (44 bytes):

```
12 01 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d8 d5 f5 99
00 00 00 5f 01 00 00 00 65 e9 f0 7b
```

ACK for seq 5 (44 bytes):

```
14 01 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 73 74 bc 5b
05 00 00 00 00 00 00 00 3f b2 f6 1b
```

MESSAGE with header2 (seq 1, tid 7, type 0x2a, priority 127, version 3, flags 1, compat 1), front `abc`, empty middle, data `WXYZ` (4 segments, 97 bytes: preamble 32 + header 41 + header crc 4 + front 3 + data 4 + epilogue 13). Exercises the "used empty segment = 0xFFFFFFFF" rule:

```
preamble:   11 04 29 00 00 00 08 00 03 00 00 00 08 00 00 00 00 00 08 00 04 00 00 00 00 10 00 00 77 1b 68 14
header2:    01 00 00 00 00 00 00 00 07 00 00 00 00 00 00 00 2a 00 7f 00 03 00 00 00 00 00 00 00
            00 00 00 00 00 00 00 00 01 01 00 00 00
hdr crc:    e6 3e 90 c3
front:      61 62 63
data:       57 58 59 5a
epilogue:   0e 48 c0 b4 c9 ff ff ff ff 1f bf 6f 17
```

(header crc 0xC3903EE6; front crc 0xC9B4C048; middle slot 0xFFFFFFFF; data crc 0x176FBF1F.)

Same MESSAGE without data (2 segments, 93 bytes): preamble `11 02 29 00 00 00 08 00 03 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 af 16 66 c2`, then header2, header crc, `61 62 63`, then epilogue `0e 48 c0 b4 c9 00 00 00 00 00 00 00 00` (slots 1 and 2 zero because those segments are unused).

### 5.2 What to capture on a live cluster (secrets scrubbed per CONTRIBUTING.md rule 4)

Capture with a packet capture on the client side while running a stock `rbd` / `ceph` command against a test cluster, with `ms_client_mode = crc` **and** `ms_mon_client_mode = crc` forced on the client (the monitor-facing list is a separate option and defaults to `secure crc`, 3.2) and, separately, once in default mode to see the secure negotiation.

| Capture | What to check against this note |
|---|---|
| Both banners, byte for byte | supported mask 3 / required 0 from the server; exact length 26 |
| First frames both ways (HELLO) | preamble layout, alignment value 8 (2.3), HELLO `peer_addr` type / port / nonce as sent by the server |
| AUTH_REQUEST to a monitor, with `mon_client` auth NONE and CEPHX if possible | `preferred_modes` order, method code, payload framing (length prefix) |
| AUTH_DONE and both AUTH_SIGNATURE frames | field order; with the session key obtained from the cephx test, recompute both HMACs and compare, confirming exactly which bytes are covered (3.3) |
| CLIENT_IDENT / SERVER_IDENT | addrvec bytes (marker 2), gid -1 vs global id, features mask in `rbd` (expect `0x3f07fffffffdffff`), flags, cookies = 0, `target_addr` bytes for a mon and for an OSD |
| A MESSAGE to a monitor and an OSD | header2 values (`flags`, `data_off`, `data_pre_padding_len`, alignment values 8,8,8,4096), CRC slots, 13-byte epilogue, `seq` start at 1 and the `ack_seq` progression |
| A KEEPALIVE2 / KEEPALIVE2_ACK pair (leave a connection idle) | cadence and who initiates |
| Failure cases on a test cluster: wrong key, crc disallowed (`ms_service_mode = secure`), client with a feature mask missing MSG_ADDR2 | AUTH_BAD_METHOD contents and errno values, IDENT_MISSING_FEATURES mask |
| Secure-mode connection (if ever implemented) | everything in 2.6.3, plus the 96-byte rev-1 secure preamble |

Check for each: decode with an independent script that follows this note, recompute every CRC, and diff against the capture. Any disagreement is a bug in this note.

---

## 6. Open questions

1. **[confirm on capture]** Alignment values in the preamble for control frames (`sizeof(void *)`, 8 on 64-bit builds, `frames_v2.h:75`) and for MESSAGE (8, 8, 8, 4096). **[unverified]** What a server does with a non-power-of-two alignment (the receiver passes it to a buffer allocator and faults on allocation failure, `ProtocolV2.cc:1233-1245`; that a non-power-of-two value fails the allocation is POSIX behaviour, not checked on a live server) and whether alignment 4 from a 32-bit build is accepted everywhere (it is raised to 8 by `buffer.cc:203`).
2. **[confirm on capture]** The type, port and nonce the server puts in its HELLO `peer_addr` (source reading: the listener's address type, the client's ephemeral port, nonce 0, `PosixStack.cc:259-263`), and the exact bytes the monitors accept in `target_addr` when the client was started from a plain `host:port` rather than from a monmap entry. Bootstrap rules for turning user input (`mon_host`) into a v2 target (default port 3300, type 2) are in `mon-client.md` 3.1; whether the monitor nonce must be 0 in `target_addr` is still **[confirm on capture]**.
3. **[confirm on capture]** The exact secret bytes used as the HMAC key in AUTH_SIGNATURE for cephx. Resolved from source in `cephx.md` 2.9 and `msgr2-secure-mode.md` 2.7: the raw secret bytes of the session key (AUTH ticket session key on a monitor connection, OSD ticket session key on an OSD connection), no KDF, no usage value (`src/auth/Crypto.cc:234-246`). Only the byte-exact check on a capture remains.
4. **[confirm on capture]** Whether the server tolerates a client that advertises REVISION_1 but not COMPRESSION against a server that advertises both. The server-side code was read and does skip the stage (`ProtocolV2.cc:1003,1926-1937`; the server looks only at the client's banner), but no live check was done, and it is the most important assumption for the "advertise 0x1" choice. If it fails, the fallback is to advertise 0x3 and implement a one-field COMPRESSION_REQUEST with `is_compress = false` and an empty method list (the server-side handler for that frame was not read **[unverified]**).
5. **[unverified]** Keepalive cadence toward OSDs (the monitor client's 10 s ping is pinned, `MonClient.cc:1058-1071`; no sender was found for OSD connections). The idle timer compares against `last_active`, which is refreshed whenever the socket becomes readable and in write-completion callbacks (`src/msg/async/AsyncConnection.cc:385-387,761,868-878`), so any inbound frame, including a client KEEPALIVE2, should reset the server's timer; **[confirm on capture]**.
6. **[unverified]** Whether any daemon type ever answers a client ident with a non-lossy (cookie != 0) session on its public port; and, if so, what an OSD does when the client then fails to send SESSION_RECONNECT.
7. **[unverified]** Behaviour of a receiver for `data_pre_padding_len != 0` and for `data_off != 0` on messages from a plain-buffer client.
8. **[unverified]** Whether AUTH_BAD_METHOD `result` values other than -EOPNOTSUPP and -EACCES occur (they come from the daemon's auth handler return codes), and their numeric values on non-Linux servers.
9. **[confirm on capture]** The exact numeric `CEPH_FEATURES_ALL` seen from a real v20.2.5 client versus the header-derived 0x3f07fffffffdffff, and whether any lower mask is accepted and safe (older encodings), in particular for the OSDMap decoder that another note defines.
10. Older releases: the msgr2 page's statement that revision 1 appeared later than 2.0 (so Reef / Squid daemons also advertise it) was not researched here, since the pinned target is Tentacle.
11. Secure mode (2.6.3) has not been checked against a capture at all. The authoritative description is now `msgr2-secure-mode.md` (key and nonce slicing, 96-byte first part, up to three tagged parts, worked example); 2.6.3 here is only a summary and defers to it. The 48-byte inline buffer / three-nonce-step description should still be verified on a capture before anyone implements it. The tag position (appended after each ciphertext run) and tag length were read from `frames_v2.h:337-339` and `crypto_onwire.cc:19-22` only.
12. **[unverified]** The SIMD CRC-32C variants (SSE4.2, PCLMUL, ARMv8, POWER, s390x) were not read; their equality with the table-driven reference is assumed (2.5). Compare the 5.1 CRC vectors on every target build.
13. **[unverified]** The address-family numbers used by non-Linux, non-Windows senders for IPv6 (2.8): the code shows no translation, so the on-wire value from such a sender is probably not 10; irrelevant to a client that writes literal numbers.
14. **[unverified]** Behaviour of the Mon / OSD towards a client that sends a KEEPALIVE2 or MESSAGE before it has processed SERVER_IDENT, beyond what the state checks at `ProtocolV2.cc:1170-1174,1692-1696` imply (fatal). The stock client never does this.
15. **[unverified]** The `ms_mon_client_mode` default of `secure crc` was read from the option table; whether a given distribution overrides it in its packaged `ceph.conf` is not known.

---

## 7. Licensing questions

1. **CRC-32C lookup table.** The standard reflected CRC-32C table (256 entries) is mathematically determined by the polynomial. The files that hold it in the Ceph tree carry their own third-party BSD-3-Clause style headers, distinct from the LGPL used by most of the tree: `src/common/crc32c_intel_baseline.c` (lines 1-35) and `src/common/sctp_crc32.c` (lines 1-27, each naming a different third-party copyright holder; this is the default portable implementation selected by `src/common/crc32c.cc:50`), so the licence of those files is not the same as the rest of the msgr2 sources. This note therefore gives only the generation rule (2.5) and three spot values; the implementer must generate the table at start-up (or write their own literal table from the rule) and must not copy the data file. Question for the project: is a generated table acceptable under the MIT intent for the core? We believe yes, because the table has exactly one possible value and is not creative expression, but this has not been reviewed.
2. **Tag numbers, field orders and constants** are protocol facts; they are listed here as tables in our own words. The field order of each frame was read from `frames_v2.h`, which is LGPL-2.1 (to be confirmed per file, as stated in `LICENSE`); no code or comments are reproduced.
3. **`CEPH_FEATURES_ALL` value.** It is a numeric constant derived from the header; we publish the number and the way to derive it, not the header text. The list of bit names in 2.10 is limited to the few that matter for framing.
4. **Test vectors in 5.1** were computed by us from the layout rules and contain no Ceph data. Captures taken from a live cluster (5.2) must be scrubbed of keys before they are committed.
5. The rst document is under Ceph's documentation licence (CC-BY-SA-3.0 per the Ceph tree; **[unverified]** which file header applies). We paraphrase, and cite section lines; we do not copy its diagrams or example frames.
