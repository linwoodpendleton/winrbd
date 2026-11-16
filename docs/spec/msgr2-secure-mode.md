# msgr2 secure mode (AES-128-GCM), client side

Status: draft spec note, Phase 0. Written from the Ceph tree pinned at v20.2.5 (Tentacle, commit
`ed27c686770872022f4c1de04f6b0ac5d5384ded`). All `path:line` references are relative to the root of that tree
unless stated otherwise. Descriptions are in our own words; no Ceph source text is reproduced.

Markers used below: **[unverified]** = not pinned in source, also listed in section 6.
**[confirm on capture]** = read from source, still to be confirmed against a live v20.2.5 cluster.

## 1. Scope and sources

### 1.1 Scope

What this note covers, for a **client only** (the side that opens the TCP connection):

- how the connection mode (crc or secure) is negotiated and what the defaults are in v20.2.5;
- where the 64-byte "connection secret" comes from (what the auth exchange hands to the messenger);
- how the AES-128-GCM key and the two nonces are cut out of that secret, which direction uses which nonce,
  the nonce layout and how it advances;
- exactly how frames change on the wire once secure mode is on (preamble, inline first segment, padding,
  tags, epilogue), with size arithmetic;
- the pre-auth signature frame, which is the first encrypted frame and ties the transcript to the session key;
- how a client declines on-wire compression.

Out of scope here (separate notes): banner and HELLO details, the cephx request/reply bodies and their cipher,
message frame contents (`ceph_msg_header2` semantics), session (ident / reconnect) frames, CRC-mode frame
bodies beyond what is needed for contrast.

### 1.2 Sources read

| Topic | File |
| --- | --- |
| AES-128-GCM handlers, key and nonce slicing | `src/msg/async/crypto_onwire.h`, `src/msg/async/crypto_onwire.cc` |
| Frame assembly / disassembly, constants, frame structs, tags | `src/msg/async/frames_v2.h`, `src/msg/async/frames_v2.cc` |
| Handshake state machine, pre-auth transcript, compression frames | `src/msg/async/ProtocolV2.cc`, `src/msg/async/ProtocolV2.h` |
| Banner features, entity type bits, `ceph_msg_header2` | `src/include/msgr.h` |
| Mode / method / crypto-type numbers, standard encodings | `src/include/ceph_fs.h`, `src/include/encoding.h`, `src/include/types.h` |
| Key handler (HMAC key, AES usage argument) | `src/auth/Crypto.cc`, `src/auth/Crypto.h` |
| Connection mode / auth method registry, mode picking | `src/auth/AuthRegistry.cc`, `src/auth/AuthRegistry.h`, `src/auth/AuthServer.h`, `src/auth/Auth.h` |
| cephx hand-off of the connection secret | `src/auth/cephx/CephxClientHandler.cc`, `src/auth/cephx/CephxServiceHandler.cc`, `src/auth/cephx/CephxProtocol.h`, `src/auth/cephx/CephxProtocol.cc`, `src/mon/MonClient.cc` |
| Option defaults | `src/common/options/global.yaml.in` |
| Compression registry | `src/msg/compressor_registry.cc`, `src/msg/async/compression_meta.h`, `src/compressor/Compressor.h` |
| Prose reference | `doc/dev/msgr2.rst`, `doc/rados/configuration/msgr2.rst` |

### 1.3 Headline facts

1. There is **no key derivation function**. The server generates 64 random bytes (the connection secret) and sends
   them to the client inside an encrypted cephx blob. The AES key is simply the first 16 bytes; two 12-byte nonce
   seeds are the next 24 bytes; the last 24 bytes are unused (`src/msg/async/crypto_onwire.cc:285-306`).
2. **One key, two nonce streams.** Both directions use the same AES key. They are kept apart only by starting from
   two different random nonce seeds (client-to-server stream starts at bytes 28..39, server-to-client at 16..27).
3. Encryption turns on **immediately after AUTH_DONE is processed**, before the pre-auth signature frame is sent.
   The signature frame is the first encrypted frame in both directions (`ProtocolV2.cc:1902-1914`,
   `ProtocolV2.cc:2342-2356`).
4. In msgr2.1 (the only revision this note recommends implementing) every GCM operation covers **one part of a
   frame**, and each operation consumes one nonce value. A frame uses between 1 and 3 operations.
5. Defaults in v20.2.5: clients prefer **secure when talking to monitors and managers** and **crc when talking to
   OSDs/MDS** (section 2.9). A crc-only client works against default clusters but is refused by clusters that were set to
   secure-only.

## 2. Wire structures

All integers are little-endian. Sizes in bytes.

### 2.1 Frame tags (numeric values follow from enum order, starting at 1)

`src/msg/async/frames_v2.h:45-68`

| Value | Tag | Value | Tag |
| --- | --- | --- | --- |
| 1 | HELLO | 12 | SESSION_RESET |
| 2 | AUTH_REQUEST | 13 | SESSION_RETRY |
| 3 | AUTH_BAD_METHOD | 14 | SESSION_RETRY_GLOBAL |
| 4 | AUTH_REPLY_MORE | 15 | SESSION_RECONNECT_OK |
| 5 | AUTH_REQUEST_MORE | 16 | WAIT |
| 6 | AUTH_DONE | 17 | MESSAGE |
| 7 | AUTH_SIGNATURE | 18 | KEEPALIVE2 |
| 8 | CLIENT_IDENT | 19 | KEEPALIVE2_ACK |
| 9 | SERVER_IDENT | 20 | ACK |
| 10 | IDENT_MISSING_FEATURES | 21 | COMPRESSION_REQUEST |
| 11 | SESSION_RECONNECT | 22 | COMPRESSION_DONE |

### 2.2 Banner feature bits

`src/include/msgr.h:38`, `src/include/msgr.h:45-64`, `ProtocolV2.cc:892-904`

Banner = the 8 ASCII bytes `ceph v2\n`, then `le16 payload_len` (= 16 as sent by v20.2.5), then `le64 supported`,
`le64 required` (`ProtocolV2.cc:892-904`). The receiver reads exactly `payload_len` bytes and decodes the first 16
of them, so a client should accept `payload_len >= 16` and ignore the rest (`ProtocolV2.cc:921-974`). A peer
that answers with the old msgr1 banner (`ceph v027`) is rejected by the reference code (`ProtocolV2.cc:923-928`).

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | REVISION_1 | msgr2.1 framing (the framing this note describes) |
| 1 | COMPRESSION | peer takes part in the compression handshake |

A v20.2.5 peer advertises `supported = 0x3`, `required = 0`.

**Each side decides "is this connection msgr2.1" from the PEER's banner**, not from its own
(`ProtocolV2.cc:1003-1011`). So a client that wants 2.1 must set bit 0 in its own banner, otherwise the server
will treat the client as 2.0 while the client (reading the server's bit 0) believes it is 2.1.
The same "peer's bit decides" rule governs the compression handshake (section 2.8).

### 2.3 Mode and method numbers

`src/include/ceph_fs.h:95-97`, `:102-104`, `:107-109`

| Item | Values |
| --- | --- |
| Connection mode (`con_mode`) | 0 unknown, 1 crc, 2 secure |
| Auth method | 1 none, 2 cephx, 4 gss (`ceph_fs.h:120`; 0 = unknown) |
| Key type | 0 none, 1 AES, 2 AES256KRB5 |

Auth method `none` is only ever allowed with crc: the registry filters every other mode out for it
(`src/auth/AuthRegistry.cc:288-306`). So secure mode implies cephx (or gss, not considered here).

### 2.4 Auth frames that carry the mode (all plaintext, 2.1 crc framing)

Payload encodings are the standard Ceph ones: integers little-endian, `bufferlist` / `string` = `le32 length`
then bytes, `vector<u32>` = `le32 count` then elements (`src/msg/async/frames_v2.h:454-478`), `bool` = one byte
(`src/include/encoding.h:98-106`). Each of these frames is a single-segment frame (`frames_v2.h:441`).

| Frame | Fields in order | Source |
| --- | --- | --- |
| AUTH_REQUEST (client to server) | `u32 method`, `vector<u32> preferred_modes`, `bufferlist auth_payload` | `frames_v2.h:532-546` |
| AUTH_BAD_METHOD (server to client) | `u32 method`, `i32 result` (negative errno), `vector<u32> allowed_methods`, `vector<u32> allowed_modes` | `frames_v2.h:548-564` |
| AUTH_REPLY_MORE (server to client) | `bufferlist auth_payload` | `frames_v2.h:566-576` |
| AUTH_REQUEST_MORE (client to server) | `bufferlist auth_payload` | `frames_v2.h:578-588` |
| AUTH_DONE (server to client) | `u64 global_id`, `u32 con_mode`, `bufferlist auth_payload` | `frames_v2.h:590-604` |
| AUTH_SIGNATURE (both ways) | `u8[32] hmac` (raw bytes, no length prefix) | `frames_v2.h:606-617`, `src/include/types.h:672-735`, `src/include/encoding.h:1419-1440` |

The first byte of the `auth_payload` of the first AUTH_REQUEST is an "auth mode" discriminator: 10 (`AUTH_MODE_MON`)
when the peer is a monitor (`MonClient.cc:1895`, `src/auth/Auth.h:38-42`), 1 (the cephx authorizer version byte,
`CephxProtocol.cc:357`) when the payload is a service authorizer; a server rejects other values
(`MonClient.cc:1747-1751`). The rest of the payload belongs to the cephx note.

AUTH_BAD_METHOD is also the server's generic answer when the auth handler itself fails (any negative result other
than the "try later" busy case, `ProtocolV2.cc:2334-2339`), so a client can receive it for a bad key or an expired
ticket, not only for a mode mismatch; only the `result` value tells them apart.

`preferred_modes` is ordered by the client's preference. The server walks the client's list and takes the first
mode that is also in its own allowed list, so **the client's order wins**
(`src/auth/AuthRegistry.cc:308-324`, `ProtocolV2.cc:2272-2278`). If nothing matches the server answers
AUTH_BAD_METHOD with `result = -EOPNOTSUPP` and its allowed modes (`ProtocolV2.cc:2276-2277`, `:2282-2299`).
AUTH_DONE's `con_mode` is therefore always one of the modes the client offered, from an honest server.
The reference client does not check this on receipt (`ProtocolV2.cc:1902`); a minimal client should.

### 2.5 The connection secret and where it comes from

`src/auth/Auth.h:129-164` (per-connection auth state; secret length 64 for secure at `:148-156`).

- Length: **64 bytes** when `con_mode` is secure, 0 when crc. The server asks its auth layer for exactly that many
  random bytes (`src/auth/Auth.h:148-156`, `src/mon/Monitor.cc:6580`, `src/mon/MonClient.cc:1771`).
- Only 40 are consumed (16 key + 12 + 12 nonces); the reference code asserts `length >= 40`, and **aborts the
  process if shorter** (`crypto_onwire.cc:285-288`). A client must reject a shorter or missing secret as an
  authentication failure before building the handlers.
- It is chosen fresh for every TCP connection, because every TCP connection starts with a full AUTH exchange
  (`ProtocolV2.cc:1766-1772`; transcript and security state are reset on reconnect, `ProtocolV2.cc:246-254`).

Two ways the secret reaches the client, depending on who the peer is:

**(a) Monitor connection (cephx "get auth session key" path).**

- The client must ask for it by sending a non-zero `other_keys` field in the cephx authenticate request; the server
  only generates a secret `if (req.other_keys)` (`CephxServiceHandler.cc:309-327`). The reference client always
  sets `other_keys = need` (`CephxClientHandler.cc:92-93`). A client that sends 0 gets no secret, and a server
  that picked secure mode then trips the same abort as above, so a minimal client must always send non-zero
  `other_keys` (ticket-bit mask).
- Reply layout, after the service-ticket reply part (`CephxClientHandler.cc:186-201`):
  `bufferlist cbl` then `bufferlist extra_tickets`. `cbl` is itself a `bufferlist` holding an encrypted blob,
  so on the wire it is `u32 outer_len | u32 inner_len | ciphertext` (server side: `CephxServiceHandler.cc:319-328`).
- The ciphertext is encrypted with the **session key of the AUTH ticket** (the one just received), key-usage
  value `0x03` (`src/auth/cephx/CephxProtocol.h:36`). After decryption the plaintext is
  `u8 struct_v (=1) | u64 magic 0xff009cad8826aa55 | u32 len | len bytes of secret`
  (`CephxProtocol.h:601, :631-657, :659-672`; the sender side wraps with `encode_encrypt`, `:741-751`). The
  reference decoder reads `struct_v` but does not check its value; it does check the magic (`:645-654`). The
  decrypt call is at `CephxClientHandler.cc:227-238`. Cipher details of that decryption belong to the cephx
  note; the usage value is never read by the AES key handler (`src/auth/Crypto.cc:316`, `:358`, `:403`; the parameter
  is only named), so it matters only for the Kerberos-style key type, which this client does not support.
- If this decryption fails the reference client only logs the failure and carries on with an empty secret
  (`CephxClientHandler.cc:230-233`); in secure mode that leads straight to the abort described above. A new client
  should treat it as an authentication failure.
- In crc mode the same blob is present but carries a zero-length string (`CephxServiceHandler.cc:313-321`).
- Frame sequence on a monitor connection with cephx: AUTH_REQUEST (initial payload) -> AUTH_REPLY_MORE (server
  challenge) -> AUTH_REQUEST_MORE (`CephXAuthenticate`, struct_v 3) -> AUTH_DONE (payload = response header,
  service-ticket reply, `cbl`, `extra_tickets`) (`CephxClientHandler.cc:148-164`, `:175-201`). The cephx note owns
  the byte layouts.
- Ticket-bit constants for `other_keys`: MON 0x01, MDS 0x02, OSD 0x04, CLIENT 0x08, MGR 0x10, AUTH 0x20
  (`src/include/msgr.h:91-96`). The server builds one extra service ticket per set bit except AUTH
  (`CephxServiceHandler.cc:331-347`); setting only the AUTH bit still yields the connection secret and no extra
  tickets.

**(b) Connection to a service daemon (OSD, MDS; ticket + authorizer path).**

- The AUTH_REQUEST payload is the authorizer; the server may answer AUTH_REPLY_MORE with a challenge first.
  The final AUTH_DONE payload is one encrypted blob `u32 len | ciphertext`, encrypted with the **service ticket's
  session key**, usage `0x12` (`CephxProtocol.h:48`, `CephxProtocol.cc:639-662`, `MonClient.cc:1645-1655`).
- Plaintext after decryption: `u8 struct_v | u64 magic | CephXAuthorizeReply`, where
  `CephXAuthorizeReply = u8 struct_v | u64 nonce_plus_one | [struct_v >= 2: u32 len | secret bytes]`
  (`CephxProtocol.h:324-348`). The server sends `struct_v = 2` only when it has a secret, i.e. in secure mode;
  otherwise `struct_v = 1` and no secret (`CephxProtocol.h:327-339`, server fill-in `CephxProtocol.cc:606-628`).
  The client must check `nonce_plus_one == authorizer nonce + 1` (`CephxProtocol.cc:650-655`). `connection_secret`
  is a `std::string`, so `u32 len | bytes`. The reference client copies the secret only when it is non-empty
  (`CephxProtocol.cc:657-660`), so a v1 reply in secure mode silently leaves the secret empty; a new client must
  reject that case itself. The server's challenge round (AUTH_REPLY_MORE, usage `0x11`, `CephxProtocol.h:46`) comes
  before this reply and is described in the cephx note.
- The server sizes the secret from the mode it picked (`MonClient.cc:1768-1772` for OSD-style servers,
  `Monitor.cc:6576-6587` for mon-side authorizer checks).

The key that feeds the pre-auth HMAC (section 2.7) is the same session key used to decrypt the secret:
the AUTH ticket session key for monitors (`CephxClientHandler.cc:222-226`), the service ticket session key for
OSDs (`MonClient.cc:1653`).

### 2.6 Key and nonce material

`src/msg/async/crypto_onwire.cc:19-34`, `:279-317`

Secret `S` (>= 40 bytes, 64 in practice):

| Offset | Length | Use |
| --- | --- | --- |
| 0 | 16 | AES-128 key `K`, used for both directions |
| 16 | 12 | nonce seed A |
| 28 | 12 | nonce seed B |
| 40 | 24 | unused by the messenger |

Direction assignment (the code names them from the non-crossed side's view; the client is the non-crossed side,
`ProtocolV2.cc:1904-1905`, server `ProtocolV2.cc:2347-2349`, `crossed` selects the swap at
`crypto_onwire.cc:308-313`):

| | Client | Server |
| --- | --- | --- |
| Encrypts (sends) with initial nonce | seed B (S[28..39]) | seed A (S[16..27]) |
| Decrypts (receives) with initial nonce | seed A (S[16..27]) | seed B (S[28..39]) |

Nonce layout (12 bytes, used verbatim as the GCM IV; `crypto_onwire.cc:24-32`):

| Bytes | Field | Type |
| --- | --- | --- |
| 0..3 | `fixed` | le32 |
| 4..11 | `counter` | le64 |

The initial value is just the 12 seed bytes copied in memory order. There is no separate "direction" bit.

Advance rule, per **GCM operation** (not per frame, not per byte):

- The IV for the operation is the **current** value. The first operation of a stream uses the seed unchanged.
- After starting the operation the nonce is incremented by one:
  - msgr2.1 (`REVISION_1` seen in the peer banner): add 1 to the le64 `counter` (bytes 4..11), wrapping
    modulo 2^64, no carry into `fixed` (`crypto_onwire.cc:105-111`, `:220-226`);
  - msgr2.0: add 1 to the le32 `fixed` field (bytes 0..3) instead (same lines). Overflows after 2^32 operations.
- Safety stop: if the current nonce equals the initial one again after a full wrap, the sender refuses to
  encrypt and reports a nonce-exhaustion error (`crypto_onwire.cc:87-95`) and the connection is dropped (`ProtocolV2.cc:846-849`).
  Only the transmit handler has this guard; the receive handler just keeps counting (`crypto_onwire.cc:213-227`).
  The counter is 64 bits in 2.1, so this is unreachable in practice; a client may still implement it as a cheap
  assertion.
- The increment happens when an operation is started (reset), not when it finishes, and a receiver steps its nonce
  even for a frame whose tag then fails to verify (`crypto_onwire.cc:213-227`, `frames_v2.cc:274-285`); since a tag
  failure closes the connection, this never matters.
- Transmit and receive keep independent counters. Each must advance in exactly the order operations occur on the
  wire. A transmitter that assembles frames on several threads must assign nonces and enqueue bytes under one lock.

Cipher parameters (`crypto_onwire.cc:19-22`, `:97-100`, `:142-167`, `:246-277`):

- AES-128-GCM, 96-bit IV, 128-bit tag, **no additional authenticated data** (no AAD call is made anywhere).
- Ciphertext length equals plaintext length; the 16-byte tag is appended after the ciphertext of that operation.
- On receive the reference code decrypts in place first and checks the tag at the end of the operation
  (`crypto_onwire.cc:246-277`). A client must not act on plaintext before the tag of its operation verified.
  For message data this means holding or discarding data-segment bytes until the final operation of the frame
  has verified. Any tag failure closes the connection; there is no resynchronisation.

### 2.7 Pre-auth signature (the first encrypted frame)

`ProtocolV2.cc:810-863` (transcript capture), `:1871-1915` (client), `:2342-2357` and `:2373-2411` (server side
and verification), `src/auth/Crypto.cc:234-246` (HMAC).

- Both peers record the **raw bytes on the wire** of the plaintext handshake, from the very first banner byte,
  separately for each direction. Capture starts at connect (`ProtocolV2.cc:110-114`) and runs until the
  signature frames are exchanged. It is cleared per TCP connection (`ProtocolV2.cc:246-254`).
- Client side: `rx_transcript` = every byte read from the socket up to and including the whole AUTH_DONE frame.
  `tx_transcript` = every byte written up to, but not including, the client's own AUTH_SIGNATURE frame.
  If the server sent AUTH_BAD_METHOD and the client retried on the same connection, earlier frames stay in the
  transcripts **[confirm on capture]**.
- Client's signature: `HMAC-SHA256(key = session key raw secret bytes, data = rx_transcript)`. The HMAC key is the
  key handler's stored secret, i.e. the raw key bytes (16 for the AES key type: `src/auth/Crypto.cc:234-246`
  uses the handler's `secret` buffer, `:320` and `:336-337` show it is the whole key buffer handed to the
  handler, `:525-531` requires at least 16 bytes), not the full encoded key structure (no type / timestamp /
  length prefix). Confirmed by source reading; the byte-exact check on a capture is still wanted
  **[confirm on capture]**. If there is no session key at all (auth none) the signature is 32 zero bytes
  (`ProtocolV2.cc:1909-1910`).
- The transcripts hold the plaintext frames as bytes on the wire: banner, HELLO, AUTH_* frames with their
  preambles, segment CRCs and any epilogue, not just frame payloads (`ProtocolV2.cc:810-837`, `:856-863`).
- Which side signs what: each side signs the bytes it **received** and verifies the peer's signature against the
  bytes it **sent**. The server's signature therefore covers the client's bytes (banner through the last
  AUTH_REQUEST / AUTH_REQUEST_MORE) and the client's covers the server's bytes up to and including AUTH_DONE
  (`ProtocolV2.cc:2351-2352` for the server, `:1909-1910` for the client).
- The client verifies the server's AUTH_SIGNATURE against `HMAC-SHA256(same key, tx_transcript)`; mismatch means
  close (`ProtocolV2.cc:2387-2394`). Use a constant-time compare (the reference uses a plain compare).
- In secure mode both signature frames are encrypted frames (the handlers exist by then); in crc mode they are
  plain frames. A client must install the crypto handlers **before** sending its AUTH_SIGNATURE and before reading
  the server's (`ProtocolV2.cc:1904-1914`).
- The AUTH_SIGNATURE frame has one 32-byte segment, so in secure 2.1 it is a single GCM operation of 80 bytes
  plaintext, 96 bytes on the wire (see worked example in 5.2).

### 2.8 Secure-mode frame layout, msgr2.1

Constants (`frames_v2.h:94-157`): crypto block 16; preamble 32; inline buffer 48; tag 16; at most 4 segments.

Preamble block (32 bytes, plaintext form; `frames_v2.h:103-120`, filled at `frames_v2.cc:64-78`):

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | tag |
| 1 | 1 | number of segments (1..4) |
| 2 + 6*i | 4 + 2 | segment i: `le32 length`, `le16 alignment` (i = 0..3, unused entries zero) |
| 26 | 1 | flags (bit 0 = FRAME_EARLY_DATA_COMPRESSED; must be 0 for us) |
| 27 | 1 | reserved, zero |
| 28 | 4 | `le32 crc` = CRC-32C over bytes 0..27 |

The preamble CRC is computed and checked **even in secure mode** (`frames_v2.cc:75-77`, `:294-300`;
`doc/dev/msgr2.rst:124-126`). CRC-32C here is the raw Castagnoli update with **seed 0 and no final inversion**
(`src/common/sctp_crc32.c:783-786`, `frames_v2.cc:75-77`, vector in section 5.1). Segment CRCs in crc mode use
seed `0xFFFFFFFF` (the reference passes -1; `frames_v2.cc:46`, `:156`), not needed in secure mode.

Contrast, msgr2.1 **crc** framing, which every pre-AUTH_DONE frame uses (all connections start in crc mode,
`doc/dev/msgr2.rst:96-97`): preamble (32 bytes, same layout as above), then segment 0 followed by `le32` CRC-32C
(seed `0xFFFFFFFF`) only if `len_0 > 0`, then segments 1..n-1 with no padding, then, only if `n > 1`, a 13-byte
epilogue (`u8 late_status`, three `le32` CRCs for segments 1..3; unused slots zero; 1 + 3 x 4 bytes)
(`frames_v2.cc:146-174`, `frames_v2.h:130-134`, `:251-267`, `:300-311`). A receiver checks the segment CRCs
when its `ms_crc_data` option is true, and that default is true (`frames_v2.cc:370-372`, `:386-388`,
`src/common/options/global.yaml.in:1143-1148`), so a client must write correct segment CRCs in its handshake
frames. A frame with a single segment has no epilogue. The late-status check is the same as in secure mode.

Frame structure rules: a frame always has at least one segment (an empty frame has one empty segment); trailing
empty segments are dropped; if there is more than one segment the last one is non-empty
(`frames_v2.cc:31-42`, `:303-311`). Alignment values are receive-buffer hints: control frames use 8, message
frames use 8, 8, 8 and 4096 for segments 0..3 (`frames_v2.h:70-79`, `:441`, `:810-815`).
They are `sizeof(void*)` and a page, so 8 / 4096 on 64-bit builds.

Let `len_i` be the logical length of segment i, `pad16(x)` = x rounded up to a multiple of 16, `n` = number of
segments. Every segment is zero padded to a multiple of 16 before encryption (`frames_v2.cc:250-262`).
The receiver does not check that padding is zero (`frames_v2.cc:23-29`).

A secure 2.1 frame is made of up to three independently tagged parts (`frames_v2.cc:176-231`):

| Part | Present when | Plaintext encrypted | On the wire |
| --- | --- | --- | --- |
| P1: preamble + inline | always | 32-byte preamble, then 48 bytes: the first 48 bytes of segment 0 if `len_0 > 48`, otherwise all of segment 0 followed by zero fill to 48 | 80 ciphertext + 16 tag = 96 |
| P2: first-segment remainder | `len_0 > 48` | `pad16(len_0) - 48` bytes: bytes 48.. of segment 0, zero padded | `pad16(len_0) - 48` + 16 tag |
| P3: remaining segments + epilogue | `n > 1` | `pad16(len_1) \|\| ... \|\| pad16(len_{n-1}) \|\| epilogue(16)` | that many bytes + 16 tag |

Epilogue (`frames_v2.h:144-149`, `:175-181`): `u8 late_status` then 15 zero bytes. A sender writes `0x0e`
(complete). On receive the low nibble must be `0x1` (sender aborted the frame; consume it and drop the content) or
`0xe` (complete); anything else is a protocol error (`frames_v2.cc:55-62`, `:433`). The upper nibble is
reserved and not checked by the reference code.

Operation order and nonce use per frame: P1 first, then P2 if present, then P3 if present, i.e. 1, 2 or 3
operations, in that order, on the wire in that order. The receiver mirrors it, one reset per operation
(`frames_v2.cc:274-285`, `:393-415`, `:417-434`).

Receive-side length arithmetic (`frames_v2.h:235-311`):

| Quantity | Value |
| --- | --- |
| Bytes to read first | 96 |
| Segment 0 extra bytes | `len_0 > 48 ? pad16(len_0) - 48 + 16 : 0` |
| Segment i >= 1 bytes | `pad16(len_i)` (no tag of its own) |
| Epilogue bytes | `n > 1 ? 16 + 16 : 0` |

After P1 decrypts and its tag verifies, the preamble CRC is checked, then the lengths are known and the rest can
be read. Segment 0 is reassembled as inline bytes `[0 .. min(len_0, 48))` followed by the remainder, truncated to
`len_0`.

### 2.9 Mode negotiation defaults in v20.2.5

Options, `src/common/options/global.yaml.in:957-1040`. All are string lists, startup-only (change needs a daemon
restart). Format: modes in order of preference.

| Option | Default | Who reads it |
| --- | --- | --- |
| `ms_mon_client_mode` (`:986-1002`) | `secure crc` | a client's offer when the peer is a monitor or manager |
| `ms_client_mode` (`:1028-1040`) | `crc secure` | a client's offer for every other peer (OSD, MDS) |
| `ms_mon_service_mode` (`:971-985`) | `secure crc` | a monitor: which modes it accepts from clients |
| `ms_service_mode` (`:1016-1027`) | `crc secure` | an OSD or MDS: which modes it accepts from clients |
| `ms_mon_cluster_mode` / `ms_cluster_mode` | `secure crc` / `crc secure` | daemon to daemon only; not relevant to a client |

Selection of the option by peer type: `src/auth/AuthRegistry.cc:185-272` (client branch at `:198-213`; server
branch for "peer is a client" at `:214-237` for mons and `:238-270` for other daemons). The client sends the list
as the `preferred_modes` of AUTH_REQUEST (`MonClient.cc:1883-1889` for monitors, `MonClient.cc:1548-1550` for
services, `ProtocolV2.cc:1780-1801`).

Consequences with unmodified defaults:

- Mode strings are whitespace/comma separated tokens `crc` and `secure`; unknown tokens are dropped with a
  warning (`src/auth/AuthRegistry.cc:91-106`).
- A stock client offers `[secure, crc]` to monitors (and managers) and so ends up in **secure** mode with them, and offers
  `[crc, secure]` to OSDs and so ends up in **crc** mode with them (both server lists contain both modes).
- A client that offers `[crc]` only is accepted by default monitors and OSDs. On a cluster whose service modes were
  set to `secure`, it is refused with AUTH_BAD_METHOD, result -EOPNOTSUPP, allowed_modes = `[2]`. The numeric
  value of -EOPNOTSUPP is host-errno dependent (95 on Linux servers) **[confirm on capture]**.
- A client that offers `[crc, secure]` works against every configuration where at least one of the two is allowed.
- To force secure in a test cluster: `ms_mon_service_mode secure` and `ms_service_mode secure`, then restart the
  daemons.

### 2.10 Compression handshake frames

`frames_v2.h:876-902`, `ProtocolV2.cc:1917-1940`, `:2204-2236`, `:3059-3099`.

| Frame | Fields |
| --- | --- |
| COMPRESSION_REQUEST (client to server) | `u8 is_compress`, `vector<u32> preferred_methods` |
| COMPRESSION_DONE (server to client) | `u8 is_compress`, `u32 method` |

The handshake happens once, after the AUTH_SIGNATURE exchange and before CLIENT_IDENT, **encrypted if the mode is
secure**. It happens only if the peer's banner has bit 1: the client sends COMPRESSION_REQUEST when the **server**
advertised COMPRESSION (`ProtocolV2.cc:1917-1924`); the server expects the request when the **client**
advertised it (`ProtocolV2.cc:1926-1937`); a CLIENT_IDENT arriving while the server still waits for the
compression request is a fault (`ProtocolV2.cc:2418-2421`).
Server defaults in v20.2.5: compression is off (`ms_osd_compress_mode` default `none`,
`global.yaml.in:1041-1054`), and it is also forced off in secure mode unless `ms_compress_secure` is true
(default `false`, `global.yaml.in:1080-1092`, `src/msg/compressor_registry.cc:109-126`). The mode lookup is keyed
on the **peer's** entity type and is non-none only when that peer is an OSD (`compressor_registry.cc:120-125`);
an OSD looking at a connecting client sees peer type CLIENT, so for an ordinary client the server's answer is
always "no compression" (`ProtocolV2.cc:3069-3082`), whatever `is_compress` the client sent. The wire value of
"none" is method 0 (`src/compressor/Compressor.h:35`), and an empty configured method list is also sent as `[0]`
by the reference (`compressor_registry.cc:56-58`). The client's `is_compress` byte is a one-byte bool.

## 3. Client procedure

Assumes the banner exchange and HELLO have been done (msgr2.1 crc framing, plaintext).

### 3.1 Connection setup (mode negotiation)

1. Banner: send `supported = REVISION_1` (bit 0) only; `required = 0`. Do not set COMPRESSION (bit 1) unless the
   compression handshake is going to be implemented (section 4). Read the server banner; if its `supported`
   lacks bit 0, stop (a 2.0-only server is not supported by this client). If its `required` has bits we do
   not know, stop.
2. Start recording the raw transcript of both directions from the first banner byte (section 2.7).
3. After HELLO, send AUTH_REQUEST with `method = 2 (cephx)` and `preferred_modes` per the client's policy
   (section 4.1) and the cephx initial payload (cephx note).
4. Handle AUTH_BAD_METHOD: surface the server's result, allowed methods and allowed modes to the caller. The
   reference client never retries with a different mode: for monitors it only moves on to another auth method
   from the server's allowed list, for OSD/MDS peers it simply fails the connection
   (`MonClient.cc:1658-1719`, `MonClient.cc:1963-1996`). Handle AUTH_REPLY_MORE by answering with
   AUTH_REQUEST_MORE, until AUTH_DONE arrives.
5. On AUTH_DONE: read `con_mode`. If it is not in the offered list, stop. Run the cephx finish step on the
   payload, which yields the session key and, for secure mode, the connection secret (section 2.5).
   If `con_mode` is secure and the secret is missing or shorter than 40 bytes, stop with an authentication error.

### 3.2 Switching on encryption

6. If `con_mode` is secure: key = S[0..15]; tx nonce = S[28..39]; rx nonce = S[16..27]; both counters start at
   the seed values (first operation uses the seed). Replace the frame reader and writer with the secure 2.1
   versions below. (crc mode: no handlers, keep crc framing.)
7. Compute the signature `HMAC-SHA256(session_key, rx_transcript)`, stop recording, and send AUTH_SIGNATURE
   (an encrypted frame in secure mode).
8. Read the server's AUTH_SIGNATURE (an encrypted frame), decrypt, compare with
   `HMAC-SHA256(session_key, tx_transcript)`. Mismatch: close.
9. If bit 1 was advertised by both sides, do the compression handshake (section 4.2). Then continue with
   CLIENT_IDENT (or RECONNECT) and message frames. Everything from here on, in both directions, uses the secure
   framing.

### 3.3 Sending a frame (secure 2.1)

1. Drop trailing empty segments, keep at least one. `n` = remaining count. Build the 32-byte preamble with
   flags 0 and its CRC.
2. If `len_0 <= 48`: inline = segment 0 followed by zero bytes up to 48; remainder empty.
   Else: inline = first 48 bytes of segment 0; remainder = rest of segment 0 zero padded to 16.
3. Operation 1: GCM-encrypt `preamble || inline` (80 bytes) with the current tx nonce, no AAD; emit the 80
   ciphertext bytes then the 16-byte tag; advance tx nonce.
4. If the remainder is non-empty: Operation 2 over the remainder; emit ciphertext then tag; advance nonce.
5. If `n > 1`: Operation 3 over `pad16(seg1) || ... || pad16(seg_{n-1}) || epilogue` where epilogue is `0x0e` plus
   15 zero bytes; the update calls may be split per segment but share one IV and produce one tag, emitted at the end.
   Advance nonce.
6. The three parts must hit the wire contiguously and in this order, and the nonce advance must be serialised
   with enqueueing (section 2.6).

### 3.4 Receiving a frame (secure 2.1)

1. Read 96 bytes. Operation 1 decrypt with the current rx nonce; verify the tag over the 80 ciphertext bytes;
   advance. On failure: close.
2. Check preamble CRC, `n` in 1..4, last segment non-empty when `n > 1`, flags bit 0 clear (we never negotiate
   compression). Enforce a sane upper bound on segment lengths before allocating.
3. If `len_0 > 48`: read `pad16(len_0) - 48 + 16` bytes, decrypt as Operation 2 (advance nonce, verify tag),
   then segment 0 = inline[0..47] followed by the remainder, truncated to `len_0`. Otherwise segment 0 is the
   first `len_0` bytes of the inline buffer.
4. If `n > 1`: read `pad16(len_i)` bytes for each segment 1..n-1 and then 32 bytes (epilogue + tag). Operation 3:
   one nonce, decrypt segments in order and then the epilogue, verify the tag at the end, advance. Only then
   interpret segment contents and the epilogue's `late_status` (dropping the frame if aborted).
5. Truncate each segment to its logical length; ignore padding content.
6. Dispatch by tag. Frames that arrive in the wrong state are protocol errors.

## 4. Minimal-client choices

### 4.1 What to support, skip, reject

| Topic | Choice | Reason / source |
| --- | --- | --- |
| msgr2 revision | support 2.1 only; advertise bit 0; reject a server without bit 0 | v20.2.5 always advertises it (`msgr.h:59-62`); 2.0 secure decrypts the preamble before its tag is checked and has a 32-bit nonce counter (`doc/dev/msgr2.rst:376-399`) |
| Connection modes | Phase A: offer `crc` only, report a clear error on AUTH_BAD_METHOD with allowed modes lacking 1. Phase B (roadmap milestone 11): offer `[crc, secure]` | stock default order for OSDs; works on default clusters (section 2.9) |
| Offer order for secure | optional user setting "prefer secure"; default order `crc secure` | the server honours the client's order (`AuthRegistry.cc:315-320`) |
| Other ciphers | none exist in v20.2.5 for this layer; reject unknown | `crypto_onwire.cc:285-316` has only AES-128-GCM |
| Connection secret | must be handled; require >= 40 bytes | `crypto_onwire.cc:285-288` aborts otherwise |
| `other_keys` in cephx authenticate | must be non-zero | `CephxServiceHandler.cc:309` |
| con_mode returned by server | verify it is in our offered list | reference client does not check (`ProtocolV2.cc:1902`) |
| Pre-auth signature | must implement both directions | otherwise the server drops the connection (`ProtocolV2.cc:2387-2394`) |
| Preamble CRC | must write; should check | server checks it in every mode (`frames_v2.cc:294-300`) |
| Epilogue padding / reserved nibble | write zeros; ignore on read | `frames_v2.cc:23-29`, `:55-62` |
| Frame aborted by sender (late_status 0x1) | handle (drop content, still advance nonces) | only the Linux kernel client is documented to send these (`doc/dev/msgr2.rst:145-153`), but handling costs nothing |
| Message throttling, rate limits | skip | not part of the wire format |
| Per-frame work in `ms_crc_data` / `ms_crc_header` | skip in secure mode | crc options only affect crc frames (`frames_v2.cc:156`, `:370-372`, `:386-388`); note they still apply to the pre-auth crc frames |
| Max GCM operations | none needed (2^64) | still keep the "nonce == seed again" guard |

### 4.2 Declining compression

Two equivalent ways; the first is preferred because it removes two frames and a failure mode:

1. **Do not advertise COMPRESSION** (leave bit 1 clear in our banner). The server then never enters its compression
   state (`ProtocolV2.cc:1926-1940`) and goes straight to the session phase, and the client must not send
   COMPRESSION_REQUEST even though the server advertises the bit (our own client logic must key off our own
   decision, not the server's bit as the reference client does at `ProtocolV2.cc:1917-1924`).
2. Advertise bit 1 and, after the signature exchange, send COMPRESSION_REQUEST with `is_compress = 0` and an
   empty method list, then read COMPRESSION_DONE. The server answers `is_compress = 0`, `method = none`
   whatever its own configuration (`ProtocolV2.cc:3069-3088`). Frame body: `00 | 00 00 00 00`.

In both cases, any received preamble with the compressed flag (flags bit 0) must be treated as a protocol error
and the connection closed, because no decompressor was set up. (The reference code does not close politely here: it
hits an always-on assertion and aborts the process, `frames_v2.cc:319-322`; a hostile or buggy server can therefore
only reach this in the reference client, never in ours.) With bit 1 clear on our side the server never compresses
towards us: the server reads our banner for the decision (`ProtocolV2.cc:1931-1937`).

### 4.3 Versions that matter

| Item | v20.2.5 server sends | v20.2.5 server accepts from a client | Source |
| --- | --- | --- | --- |
| msgr2 framing | 2.1 when the client banner has bit 0, else 2.0 | both | `ProtocolV2.cc:1003-1011` |
| Frame payloads | no per-frame version byte; shape fixed per tag | same | `frames_v2.h` |
| Encrypted-blob wrapper | `struct_v = 1` | not checked by the reference decoder; send 1 | `CephxProtocol.h:660-672`, `:645-654` |
| CephXAuthorizeReply | `struct_v = 2` in secure mode, 1 in crc | client decodes both; secure needs 2 | `CephxProtocol.h:327-347` |
| CephXAuthenticate (client sends) | n/a | decoder reads any `struct_v`; `other_keys` is present only for `struct_v >= 2` (so v1 gets no connection secret); send 3 (3 means `old_ticket` populated on reconnects) | `CephxProtocol.h:185-211` |
| Banner `payload_len` | 16 | reads `payload_len` bytes, decodes first 16 | `ProtocolV2.cc:912-974` |
| Frame preamble | fixed 32-byte layout, no version field | same | `frames_v2.h:103-120` |
| Connection secret length | 64 (secure), 0 (crc) | n/a | `src/auth/Auth.h:148-156` |
| Frame entity_addr_t encoding in HELLO / IDENT | encoded as if the peer has the Nautilus-level address features | n/a | `frames_v2.h:28-43`, `:452` |

Older releases (Reef, Squid): not researched. The reference code still contains the 2.0 secure path, so older
peers may legitimately negotiate it.

## 5. Test vectors needed

### 5.1 Primitive-level vectors (offline)

| What | How to check |
| --- | --- |
| CRC-32C, seed 0, no final inversion | `crc("foo bar baz", seed 0) = 4119623852`; seed 1234 gives 881700046; `crc("whiz bang boom", 0) = 2360230088` (from the reference unit test, `src/test/common/test_crc32c.cc:18-24`; re-derived independently for this note) |
| AES-128-GCM, 96-bit IV, empty AAD | standard published known-answer tests for the primitive, including empty-plaintext and multi-chunk update cases |
| Nonce stepping | unit test: counter wraps at 2^64 without touching bytes 0..3; msgr2.0 variant touches only bytes 0..3 |
| Length arithmetic | unit-test the table below |

Frame size table (derived from section 2.8; the first six also match the examples in `doc/dev/msgr2.rst:445-527`):

| Segment lengths | Operations | Total bytes on the wire |
| --- | --- | --- |
| 0+0+0+0 | 1 | 96 |
| 20+0+0+0 | 1 | 96 |
| 0+70+0+0 | 2 | 96 + 80 + 32 = 208 |
| 20+70+0+350 | 2 | 96 + 80 + 352 + 32 = 560 |
| 105+0+0+0 | 2 | 96 + 80 = 176 |
| 105+70+0+350 | 3 | 96 + 80 + 80 + 352 + 32 = 640 |
| 41 (a message header: `ceph_msg_header2` is 41 bytes, `src/include/msgr.h:207-223`, fits the 48-byte inline buffer) + front + middle + data, all non-empty | 2 | 96 + pad16(front) + pad16(middle) + pad16(data) + 32 |

### 5.2 Worked example with a synthetic secret (our own computation)

Secret `S` = bytes `00 01 02 ... 3f`. Then `K = 000102030405060708090a0b0c0d0e0f`, client tx seed
`1c1d1e1f2021222324252627`, client rx seed `101112131415161718191a1b`.

Frame A: AUTH_SIGNATURE sent by the client, signature = 32 bytes of `a5`.
Preamble plaintext: `07 01 20000000 0800 ... 00 00` followed by CRC `a80c9872` (bytes 28..31), i.e.
`07012000000008000000000000000000000000000000000000000000a80c9872`. IV = `1c1d1e1f2021222324252627`.
Plaintext = preamble (32) + 32 x `a5` + 16 x `00`. Wire (96 bytes, tag in the last 16):

```
5ee83e477793cc7cbb381480b30cc69431dabdf879b50b483d403cfd1b1ec96a
e363935876ea5233f5930611558cad49725d69ea832d072f15bad3bf4b43581f
01654a9d4a848c689172d4521fcf8108ee387f09dafe616e6a0c5adfa581ad5e
```

Frame B (next client frame, tag 17, segment 0 = 20 x `11`, segment 1 = 10 x `22`, alignments 8 and 8):
preamble `11021400000008000a000000080000000000000000000000000000007669e7cf`.
Operation 1 IV = `1c1d1e1f2121222324252627` (counter byte 4 advanced from `20` to `21`), operation 2 IV =
`1c1d1e1f2221222324252627`. Operation 2 plaintext = 10 x `22`, 6 x `00`, `0e`, 15 x `00` (32 bytes). Wire (144 bytes):

```
98283b6ff8ab6493cd1f43d679c4a3a38a8577da66639b20d42f050521ea2d40
4380360af91a14019d02906a063be428f187b4b3c0183c65656b15d047b91e7a
e9f5a5aadcdc5350ca29264420199b1b20d32c03240c290bc1cc826c68a2c43c
31004d2d0a48882efde2210977ac057a35e0d0b282f4010584c004c4ffd0a4ca
f5a419f42a8a57c28a08980d974b4183
```

These values were produced by an independent implementation of section 2.6 / 2.8 and checked only for
self-consistency (decrypt with the same rules); a second, separately written script (raw CRC-32C plus a stock
AES-GCM library) reproduced the preambles, IVs and all wire bytes exactly. Both follow the same reading of the
source, so neither proves agreement with a real peer. **[confirm on capture]**: cross-check against the reference
frame assembler built from the pinned tree with the same secret (section 7 covers the licensing handling of such a
harness) or by having a live v20.2.5 server accept them.

### 5.3 Live checks on the test cluster

1. Force secure on the cluster (`ms_mon_service_mode secure`, `ms_service_mode secure`, restart); our client
   completes AUTH, exchanges both signatures, subscribes to the monmap/osdmap, and does object I/O. Success
   criterion is that the server never closes the connection for a bad tag or bad signature.
2. The connection dump of the reference messenger prints the cipher per direction (`AES-128-GCM` or `PLAIN`)
   (`ProtocolV2.cc:776-808`); which admin-socket command exposes it is **[unverified]**.
3. Negative tests, expect close: flip one bit in each of preamble ciphertext, a tag, a data segment; send two
   frames with the same nonce; start with the wrong seed (swap seed A and B).
4. Offer `[crc]` only against a secure-only cluster; expect AUTH_BAD_METHOD with `allowed_modes = [2]`. Offer
   `[secure]` only against a crc-only cluster (`ms_*_service_mode crc`); expect the same frame with `[1]`.
5. Capture the plaintext handshake (banner through AUTH_DONE) and recompute the pre-auth HMAC offline from a
   known keyring to settle the exact HMAC key bytes (section 6, item 1).
6. Capture bytes of one secure session including the encrypted 96-byte AUTH_SIGNATURE frames, check
   lengths against section 2.8 arithmetic.

## 6. Open questions

1. **HMAC key bytes** for the pre-auth signature: source reading says the raw 16-byte AES session key
   (`src/auth/Crypto.cc:234-246`, `:336-337`); the key structure encoding and how the session key is extracted from
   the ticket reply are described in the cephx note, not here. Capture check still wanted.
   **[confirm on capture]**
2. Transcript scope on an AUTH_BAD_METHOD retry within one TCP connection: source says the buffers are never
   cleared between auth attempts (`ProtocolV2.cc:1834` re-sends the request without touching them). **[confirm on capture]**
3. Segment alignment values to send from a non-64-bit build, and whether any peer enforces them. The reference code
   uses `sizeof(void*)` (`frames_v2.h:75`), and the receiver allocates an aligned buffer from the sender's value
   (`ProtocolV2.cc:1234-1245`). Kernel and other clients' choices are **[unverified]**.
4. Exact numeric of the `result` field of AUTH_BAD_METHOD for "mode not allowed" on a v20.2.5 server
   (-EOPNOTSUPP, 95 on Linux). **[confirm on capture]**
5. Whether a v20.2.5 server really accepts a client that advertises REVISION_1 but not COMPRESSION without any
   compression frame (code path: `ProtocolV2.cc:1926-1940`). **[confirm on capture]**
6. Whether `ms_client_mode`-style options are consulted for a client built from other languages: the module type
   check is `CEPH_ENTITY_TYPE_CLIENT` in the registry (`AuthRegistry.cc:198`); our client simply chooses its own
   offer list, so this only matters for interpreting server logs.
7. The reference client does not validate `con_mode` against its offer and aborts on a short secret
   (`ProtocolV2.cc:1902`, `crypto_onwire.cc:285-288`). Whether a hostile server could exploit that is irrelevant
   for us; we add the checks. Noted so nobody copies the reference behaviour.
8. Whether the host crypto available to each target supports a GCM operation spanning several buffers with one tag
   and a 12-byte IV (needed for part P3 and for zero-copy data segments): iPXE ships GCM code under
   `third_party/ipxe/src/crypto/gcm.c` (our tree, not Ceph); its streaming behaviour and its performance on a
   firmware heap are **[unverified]**.
9. Memory strategy for the data segment in secure mode: bytes are only authenticated when the P3 tag verifies, so
   zero-copy reads into a caller buffer must be treated as scratch until then (a bounded-memory client may have to
   verify per request before copying out). Policy to be decided in Phase 1.
10. Upper bounds on segment lengths that a peer may legitimately send, and a safe cap for a bounded-memory client:
    not read from source in this note.
11. Older releases (Reef 18, Squid 19): not researched.
12. Session reconnect after a TCP loss: the reference code resets the per-connection security state and runs a new
    AUTH exchange (`ProtocolV2.cc:246-254`, `:1766-1772`), so no secret is ever reused. SESSION_RECONNECT (or
    CLIENT_IDENT) is only sent after AUTH, the signature exchange and the optional compression handshake
    (`ProtocolV2.cc:1917-1924`, `:1942-1953`, `:2235`), i.e. already inside the secure framing; this is read from
    source, so it is not an open question any more apart from the usual capture check **[confirm on capture]**.

## 7. Licensing questions

No data tables from Ceph are needed: the CRC-32C table is generated from the public polynomial (0x1EDC6F41,
reflected form 0x82F63B78) and the cipher comes from the host's crypto shim. Items to settle before relying on this
note:

1. `doc/dev/msgr2.rst` and `doc/rados/configuration/msgr2.rst` are under CC-BY-SA-3.0 (`COPYING:21-23`). This note
   restates their facts in its own words and computes its own size table; the six frame size examples in section 5.1
   coincide with the doc's examples because the layout is fixed by the protocol. Confirm that this is acceptable for
   an MIT-licensed project, or drop the cross-reference column.
2. `src/include/msgr.h` and `src/include/ceph_fs.h` are shared with the Linux kernel client, and `COPYING` gives no
   per-file entry for them (the default entry is LGPL-2.1 or LGPL-3, `COPYING:6-8`). Only numeric constants (bit
   positions, mode and method numbers, struct layout) were taken. Confirm per file.
3. Test-vector tooling that links Ceph's frame assembler to cross-check section 5.2 would be LGPL code; keep it
   outside `core/`, never copy output code into it, and document in the pull request which sources were read
   (CONTRIBUTING rule 1).
4. `src/test/common/test_crc32c.cc` values are quoted as test vectors (three numbers); they were independently
   recomputed. Confirm that quoting short test constants is fine.
