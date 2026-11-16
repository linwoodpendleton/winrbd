# cephx: client authentication to mons and OSDs over msgr2 (Ceph v20.2.5)

Status: spec note, Phase 0. Written from the pinned Ceph source only and then reviewed line by line against it; nothing here has been checked against a live capture yet. Two algorithms (cipher type 1 padding / IV, cipher type 2 key derivation / CTS / MAC) were additionally re-implemented independently during review and reproduced the known-answer vectors that Ceph's own unit tests use (see 2.4 and 2.5). Items marked **[confirm on capture]** need a capture, items marked **[unverified]** could not be pinned in the pinned tree.

## 1 Scope and sources

### 1.1 Scope

This note covers what a minimal Ceph **client** (never a server) needs to authenticate with cephx over msgr2, byte-exact:

- the mon handshake carried inside the msgr2 frames AUTH_REQUEST / AUTH_REPLY_MORE / AUTH_REQUEST_MORE / AUTH_DONE: entity name and global_id, server challenge, client proof, CEPHX_GET_AUTH_SESSION_KEY, the service tickets that come back, and CEPHX_GET_PRINCIPAL_SESSION_KEY (renewal);
- the crypto: key encoding, the two cipher types a v20.2.5 cluster can use (AES-128-CBC with a fixed IV, and the newer AES-256 CTS + HMAC-SHA384 type), the encrypted envelope, the challenge proof;
- the authorizer a client sends to an OSD, including the challenge round trip, ticket expiry and renewal;
- the AUTH_SIGNATURE frame that closes authentication in both crc and secure mode, whether per-message signatures exist in msgr2, and how the secure-mode connection secret is delivered (self-contained; the key schedule of the secure-mode frames themselves belongs to the secure-mode note).

Out of scope: msgr2 banner, HELLO, frame preamble/epilogue and CRC rules (msgr2 note); secure-mode frame encryption (secure-mode note); mon subscribe and map delivery; daemon-only functions (rotating secret fetch, verifying authorizers as a server, key server, caps parsing).

### 1.2 Pinned source

Ceph tag v20.2.5 (Tentacle), commit ed27c686770872022f4c1de04f6b0ac5d5384ded. All paths below are relative to the tree root. Main files read:

| Area | Files |
|---|---|
| cephx structures and algorithms | `src/auth/cephx/CephxProtocol.h`, `CephxProtocol.cc`, `CephxClientHandler.cc`, `CephxServiceHandler.cc`, `CephxKeyServer.cc/.h` |
| crypto | `src/auth/Crypto.h`, `Crypto.cc`, `src/include/ceph_fs.h` |
| common auth types | `src/auth/Auth.h`, `Auth.cc`, `AuthClient.h`, `AuthRegistry.cc`, `AuthServiceHandler.cc` |
| mon client side | `src/mon/MonClient.cc` |
| mon server side (to see what is accepted) | `src/mon/Monitor.cc`, `src/mon/AuthMonitor.cc`, `src/mon/MonMap.cc` |
| msgr2 hooks | `src/msg/async/ProtocolV2.cc`, `frames_v2.h`, `crypto_onwire.cc` |
| messages | `src/messages/MAuth.h`, `MAuthReply.h`, `PaxosServiceMessage.h` |
| docs | `doc/dev/cephx.rst`, `doc/dev/cephx_protocol.rst`, `doc/dev/msgr2.rst` |

### 1.3 Encoding primitives used below

All integers are little-endian. These are the standard Ceph encodings, as used by every structure in this note.

| Name | Wire form | Source |
|---|---|---|
| u8 / u16 / u32 / u64 / s32 | fixed-size LE integer | `src/include/encoding.h` (generic) |
| bool | 1 byte, 0 or 1 | same |
| string | u32 length, then that many bytes (no terminator) | same |
| bufferlist ("blob") | u32 length, then bytes (same shape as string) | same |
| utime | u32 seconds, u32 nanoseconds (8 bytes) | `src/include/utime.h:163-180` |
| sha256 digest | 32 raw bytes, no length prefix | `src/include/types.h:696-708`, `src/include/encoding.h:1429-1440` |
| vector of u32 (msgr2 frame fields) | u32 count, then count u32 values | `src/msg/async/frames_v2.h:454-478` |
| EntityName | u32 type, then string id (so "client.admin" is type 8, id "admin") | `src/common/entity_name.cc:27-45` |

Struct "version bytes": most cephx structs start with a u8 `struct_v` and are NOT wrapped in the generic start/finish length envelope. Decoders in the client path read the byte and never reject on its value (they only branch on `>= 2` etc.: for example CephXAuthenticate reads `other_keys` only when v >= 2, `CephxProtocol.h:201-203`; CephXAuthorize reads the challenge fields only when v >= 2, `:552-555`; CephXAuthorizeReply reads the secret only when v >= 2, `:345-347`), so a client should send the versions given here and ignore the value when receiving, except where noted.

### 1.4 Documentation drift (read this before trusting `doc/dev/cephx.rst`)

The pinned docs disagree with the pinned code in places that matter:

- `doc/dev/cephx.rst:89-95` shows CephXAuthenticate `struct_v` = 2 ("2 means nautilus+"); the code sends **3** (`src/auth/cephx/CephxProtocol.h:188`), and v3 means "old ticket is always present on reconnect" (`:205-210`).
- `doc/dev/cephx.rst:40` says a principal secret is 16 bytes; in v20.2.5 it can be 32 bytes (type 2 below).
- `doc/dev/cephx.rst:151-154` shows the service ticket carrying an expiration; the code carries a **validity duration** and the client computes the expiry from its own clock (`CephxProtocol.h:445-454`, `CephxProtocol.cc:217-224`).
- `doc/dev/msgr2.rst:255-296` documents AUTH_REQUEST .. AUTH_DONE but not the AUTH_SIGNATURE frame that follows AUTH_DONE (see 2.9).
- None of the docs mention the magic, the IV, padding or the new key type.

### 1.5 Headline findings

1. **Two key types matter in v20.2.5.** Type 1 "aes" (16-byte secret, AES-128-CBC) is the legacy type; type 2 "aes256k" (32-byte secret, AES-256 CTS + HMAC-SHA384, RFC 8009 profile) is the new default. A cluster created fresh by a v20.2.5 mon (`mkfs`) allows **only type 2** (`src/mon/MonMap.cc:1094-1098`); an upgraded cluster keeps type 1 allowed (`MonMap.cc:356-364`). The mon rejects authentication if the client's key type is not allowed (`src/auth/cephx/CephxServiceHandler.cc:195-210`). So a client that implements only type 1 will not work on a fresh Tentacle cluster. The mon even reports type 1 as "insecure" (`src/mon/AuthMonitor.cc:487-505`, `src/auth/Crypto.cc:1255-1259`).
2. **The challenge proof differs per type** (2.8) and the type-1 proof has a trap: it hashes the length-prefixed ciphertext, so a 4-byte length field is folded into the XOR.
3. **msgr2 has no per-message signatures**; cephx only contributes one HMAC-SHA256 "pre-auth signature" exchanged right after AUTH_DONE (2.9). Per-message signing is a msgr1-only feature (`src/msg/async/ProtocolV1.cc:972-976, 1153-1157`).
4. **The OSD authorizer always costs one extra round trip** (challenge) in msgr2, and the challenge blob has no length prefix while the final reply does (2.7).

## 2 Wire structures

### 2.1 Constants

| Constant | Value | Source |
|---|---|---|
| Entity type MON / MDS / OSD / CLIENT / MGR / AUTH | 0x01 / 0x02 / 0x04 / 0x08 / 0x10 / 0x20 | `src/include/msgr.h:91-96` |
| Auth method NONE / CEPHX | 1 / 2 (0 = unknown) | `src/include/ceph_fs.h:102-104` |
| Connection mode CRC / SECURE | 1 / 2 (0 = unknown) | `src/include/ceph_fs.h:107-109` |
| Crypto type NONE / AES / AES256KRB5 | 0 / 1 / 2 | `src/include/ceph_fs.h:95-97` |
| Auth payload first byte (mode) | 1..9 = authorizer (value is the authorizer version, sent as 1), 10..19 = mon auth (sent as 10) | `src/auth/Auth.h:37-43`, `CephxProtocol.cc:357` |
| cephx request type | GET_AUTH_SESSION_KEY 0x0100, GET_PRINCIPAL_SESSION_KEY 0x0200, GET_ROTATING_KEY 0x0400 (daemon only) | `CephxProtocol.h:26-28` |
| Envelope magic | 0xff009cad8826aa55 (wire bytes 55 aa 26 88 ad 9c 00 ff) | `CephxProtocol.h:601` |
| Type-1 CBC IV | 16 ASCII bytes, hex `63 65 70 68 73 61 67 65 79 75 64 61 67 72 65 67`, defined as `CEPH_AES_IV` | `src/include/ceph_fs.h:99` |
| AUTH_UID_DEFAULT | all-ones u64 (only appears inside opaque tickets) | `src/include/ceph_fs.h:123` |

Key-usage numbers (only matter for type 2; type 1 ignores them), `CephxProtocol.h:34-54`:

| Usage | Value | Used for |
|---|---|---|
| AUTH_CONNECTION_SECRET | 0x03 | connection secret in the mon reply, encrypted with the AUTH session key |
| TICKET_SESSION_KEY | 0x04 | the per-ticket `CephXServiceTicket` (session key + validity) |
| TICKET_BLOB | 0x05 | a renewed AUTH ticket blob, encrypted with the previous AUTH session key |
| AUTHORIZE | 0x10 | client authorizer proof (`CephXAuthorize`) |
| AUTHORIZE_CHALLENGE | 0x11 | server challenge to the authorizer |
| AUTHORIZE_REPLY | 0x12 | server final reply |
| ROTATING_SECRET / TICKET_INFO | 0x20 / 0x30 | daemon-only; the client never touches these |

### 2.2 msgr2 auth frames (payload of the control segment)

Tags: AUTH_REQUEST = 2, AUTH_BAD_METHOD = 3, AUTH_REPLY_MORE = 4, AUTH_REQUEST_MORE = 5, AUTH_DONE = 6, AUTH_SIGNATURE = 7 (`src/msg/async/frames_v2.h:45-52`; HELLO is 1). Fields are encoded one after another with the primitives of 1.3 (`frames_v2.h:441-509`). Frame structure around these payloads is in the msgr2 note.

| Frame | Direction | Fields | Source |
|---|---|---|---|
| AUTH_REQUEST | C to S | u32 method; vector<u32> preferred modes; blob auth_payload | `frames_v2.h:532-546` |
| AUTH_BAD_METHOD | S to C | u32 method; s32 result (negative errno); vector<u32> allowed methods; vector<u32> allowed modes | `frames_v2.h:548-564` |
| AUTH_REPLY_MORE | S to C | blob auth_payload | `frames_v2.h:566-576` |
| AUTH_REQUEST_MORE | C to S | blob auth_payload | `frames_v2.h:578-588` |
| AUTH_DONE | S to C | u64 global_id; u32 connection mode; blob auth_payload | `frames_v2.h:590-604` |
| AUTH_SIGNATURE | both | 32 raw bytes (HMAC-SHA256) | `frames_v2.h:606-617` |

Note "blob auth_payload" is itself u32 length plus bytes. The method-specific payload for cephx is what the rest of this note defines; "payload" below always means those inner bytes.

### 2.3 CryptoKey encoding and keyring text

A key as stored in a keyring and as carried inside tickets (`src/auth/Crypto.cc:1053-1075`):

| Field | Type | Meaning |
|---|---|---|
| type | u16 | crypto type (1 = aes, 2 = aes256k; 0 = none) |
| created | utime (8 bytes) | creation time; the client never checks it |
| secret_len | u16 | length of secret |
| secret | bytes | raw key bytes |

Validity of the secret: type 1 needs length >= 16 (`Crypto.cc:525-532`; cipher uses the first 16 bytes, but the HMAC in 2.9 uses all bytes); type 2 needs length >= 32 (`Crypto.cc:1022-1029`); decoding fails otherwise (`Crypto.cc:1103-1128`). Fresh keys are exactly 16 / 32 bytes (`Crypto.cc:517-523, 1014-1020`).

Typical sizes: type 1 = 2+8+2+16 = 28 bytes; type 2 = 2+8+2+32 = 44 bytes. A keyring file holds `key = <base64 of this encoding>` per entity (`src/auth/KeyRing.cc:109-113`, base64 via `CryptoKey::decode_base64`, `Crypto.h:226-233`). So type 1 keys look like `AQ...` (40 base64 characters) and type 2 keys like `Ag...` (60 characters) **[confirm on capture]**.

### 2.4 Cipher type 1 (aes): AES-128-CBC, fixed IV, PKCS#7 padding

Source: `src/auth/Crypto.cc:307-512`.

- Cipher AES-128 in CBC mode, key = first 16 bytes of the secret, IV = the constant in 2.1 re-used for every message (no per-message IV, no MAC).
- Padding: always add 1..16 bytes, each equal to the pad length (a full extra block when the input is already aligned) (`Crypto.cc:364-378, 451-463`). Ciphertext length is therefore `16 * (floor(len/16) + 1)`.
- Decrypt: ciphertext length must be a non-zero multiple of 16. The reference decrypter does not validate padding: it reads the last byte, caps it at 16 and strips that many bytes, and reports nothing on malformed padding (`Crypto.cc:403-435`). Integrity of type 1 therefore rests only on the magic check of 2.6. A client may be stricter (reject pad byte 0 or > 16) since a correct server never produces those.
- The usage argument is ignored for this type.
- Checked offline: an independent AES-128-CBC implementation with this IV and this padding reproduces the 32-byte known-answer ciphertext of Ceph's own single-block test (`src/test/crypto.cc:44-82`: key bytes 00..0f, plaintext 00 11 22 .. ff). The key is the first 16 bytes of the secret; for a block-aligned plaintext the extra full padding block is really emitted (that vector shows it).

### 2.5 Cipher type 2 (aes256k): AES-256 CTS + HMAC-SHA384

Source: `src/auth/Crypto.cc:551-1043`. This is the RFC 8009 profile "aes256-cts-hmac-sha384-192" (the source comment is at `Crypto.cc:552`; the unit tests state they use RFC 8009 vectors, `src/test/crypto.cc:389-451`, all with key usage 2 and a 32-byte base key). The RFC text itself is not in the pinned tree. **Checked offline during review:** the construction described in this section was re-implemented independently (raw AES-CBC plus HMAC-SHA384, no CTS library) and reproduced all four known-answer vectors of that unit test byte for byte (plaintext lengths 0, 6, 16 and 21 bytes, i.e. M of 16, 22, 32 and 37 bytes, so the single-block, unaligned and block-aligned CS3 cases are all covered). That settles KDF input layout, key lengths, CS3 behaviour, the zero-IV prefix of the MAC and the 24-byte truncation. Whether those vectors are literally the RFC appendix vectors rests on the test file's own comment.

Key derivation per usage value U (u32, big-endian inside the label), base key = the whole secret (32 bytes for generated keys; the validator only requires >= 32, and the KDF HMAC then uses the whole stored length, `Crypto.cc:718-724, 1022-1029`) (`Crypto.cc:695-731, 601-623`):

1. Build the 14-byte input: `00 00 00 01`, U as 4 bytes big-endian, one type byte, `00`, then the output length in **bits** as 4 bytes big-endian. (This is the RFC 8009 KDF with an empty context.)
2. Compute HMAC-SHA384 with the base key over that input, keep the first `k` bytes.
3. Two derived keys: integrity key **Ki**: type byte 0x55, 24 bytes (192 bits); encryption key **Ke**: type byte 0xAA, 32 bytes (256 bits). (The RFC's third key Kc, type byte 0x99, is not used by Ceph.)

Encrypt (plaintext P of any length >= 0) (`Crypto.cc:861-924`):

1. Generate a 16-byte random confounder. Form `M = confounder || P`.
2. Encrypt M with AES-256 in CBC mode with **ciphertext stealing, variant "CS3"** (library parameter value "CS3", `Crypto.cc:747, 795`), key Ke, IV = 16 zero bytes. Ciphertext length equals the length of M (no padding).
3. Compute HMAC-SHA384 with Ki over `(16 zero bytes || ciphertext)` and keep the first **24 bytes** (`Crypto.cc:653-693, 913-917`; note the IV is prepended to the data being MACed).
4. Output = ciphertext || mac. Total length = 16 + len(P) + 24 (`Crypto.cc:868-870, 1005-1008`).

Decrypt (`Crypto.cc:926-1003`): need length >= 40; split off the last 24 bytes; recompute the MAC over `(16 zero bytes || ciphertext)` with Ki and compare (mismatch means failure, nothing is decrypted); decrypt with Ke / CS3 / zero IV; drop the first 16 bytes (confounder).

CS3 in plain terms (verified by the offline re-implementation above): let n = len(M) >= 16. If n = 16 the output is the single CBC block. Otherwise zero-pad M to a multiple of 16, run plain CBC (zero IV) to get blocks C1..Ck, let r = n - 16*(k-1) (1..16), and output C1..C(k-2), then Ck, then the first r bytes of C(k-1). CS3 swaps the last two blocks even when n is a multiple of 16 (r = 16). Decryption is the inverse. A shim without a CTS mode can build this from raw AES-CBC/ECB.

Lazy derivation: derived keys are computed on first use per usage value (`Crypto.cc:625-637`), so a client can cache them per (key, usage).

### 2.6 The encrypted envelope and the "encode+encrypt" convention

Every encrypted cephx item is built the same way (`CephxProtocol.h:659-688, 727-753`):

1. `plain = u8 1 || u64 magic (2.1) || encoding of the item`.
2. `ct = encrypt(key, usage, plain)` using the cipher of that key's own type field.
3. Two output shapes:
   - **length-prefixed** ("encode_encrypt"): `u32 len(ct) || ct`. This is the common one.
   - **raw** ("encode_encrypt_enc_bl"): just `ct`. Used for the authorizer challenge (2.9) and inside tickets.

Decryption (`CephxProtocol.h:603-657`) decrypts, reads the u8 version (value ignored), reads the u64 and **requires it to equal the magic** (this is the only integrity check for type 1), then decodes the item. If the item has trailing bytes nothing complains.

Each key is used with its own type: tickets can carry session keys whose type differs from the type of the key that wrapped them (see 3.4).

The envelope helpers exist in a usage-less form (only used for the type-1 challenge proof in 2.8; the usage then defaults to 0 for a type-2 key, `src/auth/Crypto.h:73, 85-89, 320-323`) and a usage form (used everywhere else). A client only ever needs the usage form plus the type-1 proof.

### 2.7 cephx structures

All of these are plain-encoded as in 1.3. "v" is the leading u8.

**CephXServerChallenge** (`CephxProtocol.h:66-89`): u8 v=1, u64 server_challenge.

**CephXRequestHeader** (`:94-113`): u16 request_type. **CephXResponseHeader** (`:115-139`): u16 request_type, s32 status. The reference client ignores `status` and keys off the payload (`CephxClientHandler.cc:166-175`); a minimal client should still check it.

**CephXTicketBlob** (`:141-174`): u8 v=1, u64 secret_id, blob data. Opaque to the client, kept and re-sent verbatim. Empty blob form: v=1, secret_id=0, length 0 (13 bytes).

**CephXAuthenticate** (`:177-232`), sent as AUTH_REQUEST_MORE payload after the request header: u8 v=3, u64 client_challenge, u64 key (the proof, 2.8), CephXTicketBlob old_ticket, u32 other_keys (bit mask of wanted service tickets, including the AUTH bit 0x20 when the AUTH ticket is wanted). The server decoder accepts any leading byte; it reads `other_keys` only for v >= 2 and treats v < 3 as "old ticket may be omitted" (`CephxProtocol.h:194-211`). With v < 3 the mon tolerates a missing old ticket on reconnect, with v3 it does not (`CephxServiceHandler.cc:73-151`). The body of v2 and v3 is identical.

**CephXServiceTicketRequest** (`:292-317`): u8 v=1, u32 keys (mask).

**CephXServiceTicket** (`:445-475`): u8 v=1, CryptoKey session_key, utime validity. `validity` is a duration, not a date.

**Ticket reply** (built at `CephxProtocol.cc:112-168`, parsed by the client at `:174-232, 313-344`):

| Field | Type | Meaning |
|---|---|---|
| reply_v | u8 | 1 |
| num | u32 | number of tickets |
| per ticket: service_id | u32 | entity type bit (AUTH 0x20, MON, OSD, ...) |
| per ticket: ticket_v | u8 | 1 |
| per ticket: msg_a | u32 len + ciphertext | `CephXServiceTicket`, length-prefixed shape, usage 0x04, key = principal key for the AUTH ticket (initial reply) or the AUTH session key (all others) |
| per ticket: ticket_enc | u8 | 0 or 1 |
| per ticket: blob | see below | the opaque ticket |

If `ticket_enc` = 0 the blob field is a bufferlist (u32 len) whose bytes are an encoded CephXTicketBlob. If `ticket_enc` = 1 (only when the request presented a valid old AUTH ticket, `CephxServiceHandler.cc:145-150`) the field is a length-prefixed ciphertext, key = the **previous** AUTH session key, usage 0x05, whose plaintext item is that same bufferlist. The reference client decrypts with the key it held before overwriting it (`CephxProtocol.cc:191-216`).

**Mon reply to CEPHX_GET_AUTH_SESSION_KEY** (AUTH_DONE payload; `CephxServiceHandler.cc:288-355`, `CephxClientHandler.cc:176-256`):

1. CephXResponseHeader (request_type 0x0100, status 0).
2. Ticket reply with exactly one ticket, service_id = AUTH (0x20), `msg_a` under the principal's own key.
3. Only if the request had `other_keys != 0` (always in practice): 
   - blob `cbl` (u32 length, then bytes): its content is itself the length-prefixed ciphertext (`u32 inner_len || ct`) of the connection secret encoded as a string, usage 0x03, key = the new AUTH session key. So on the wire it is `u32 outer_len | u32 inner_len | ct`; the plaintext is `u8 1 | u64 magic | u32 secret_len | secret`. In crc mode the secret is empty (an encrypted empty string, still present, `secret_len` = 0); in secure mode it is 64 random bytes (`src/auth/Auth.h:148-156`, `CephxServiceHandler.cc:309-328`). If the mon did not get a connection-secret out-pointer (the MAuth path, 2.11) `cbl` is a zero-length blob.
   - blob `extra` (u32 length, then bytes): a second complete ticket reply (same layout as above, `ticket_enc` = 0 for every ticket) for every requested non-AUTH service, `msg_a` encrypted under the **new AUTH session key** (usage 0x04). If the request mask contained only the AUTH bit, `extra` is a **zero-length blob**, not a ticket reply with num = 0 (`CephxServiceHandler.cc:348-354`); the reference client skips `extra` when its length is 0 (`CephxClientHandler.cc:239-247`).

So in msgr2 a single AUTH_DONE can deliver the OSD ticket; the reference client skips `extra` only on msgr1 (`CephxClientHandler.cc:205-221`).

**Service ticket reply to CEPHX_GET_PRINCIPAL_SESSION_KEY** (renewal on an established mon session, see 3.6): CephXResponseHeader (request_type 0x0200, status) followed by a ticket reply with `ticket_enc` = 0 and `msg_a` under the AUTH session key (`CephxServiceHandler.cc:363-428`).

**Authorizer** (client to a service, built at `CephxProtocol.cc:351-375`, parsed by the server at `:450-513`):

| Field | Type | Meaning |
|---|---|---|
| authorizer_v | u8 | 1 (this is also the "mode" byte, must be in 1..9) |
| global_id | u64 | the client's global id from the mon; the OSD rejects the authorizer if it differs from the global_id sealed in the ticket (`CephxProtocol.cc:510-514`) |
| service_id | u32 | entity type of the peer (OSD = 4); a daemon only holds keys for its own type, so any other value fails the key lookup (`CephxProtocol.cc:489-496`, `src/auth/RotatingKeyRing.cc:77-82`) |
| ticket | CephXTicketBlob | the service ticket blob as received |
| proof | u32 len + ciphertext | `CephXAuthorize`, session key of the **service ticket**, usage 0x10 |

**CephXAuthorize** (`CephxProtocol.h:535-570`): u8 v=2, u64 nonce, u8 have_challenge (bool), u64 server_challenge_plus_one. First send: nonce random, have_challenge 0, plus_one 0.

**CephXAuthorizeChallenge** (`:511-533`): u8 v=1, u64 server_challenge.

**CephXAuthorizeReply** (`:324-361`): u8 v (2 if a connection secret is present, else 1), u64 nonce_plus_one, and if v>=2 a string connection_secret.

**AuthTicket / CephXServiceTicketInfo** (`src/auth/Auth.cc:105-131`, `CephxProtocol.h:478-509`) are what the mon seals inside the opaque ticket blob (usage 0x30, `CephxProtocol.cc:95`); a client never decodes them. Listed only so a capture can be sanity-checked: the blob decrypts (with the service's rotating key, not available to the client) to the envelope (u8 1, magic) followed by CephXServiceTicketInfo = {u8 v=1, AuthTicket {u8 v=2, EntityName, u64 global_id, u64 auid (always all-ones on the wire), utime created, utime expires, AuthCapsInfo caps, u32 flags}, CryptoKey session_key}. The AuthTicket comes **before** the session key.

### 2.8 Challenge proof ("key" in CephXAuthenticate)

Function of (principal key, server_challenge, client_challenge) at `CephxProtocol.cc:34-63`. Build the 16-byte `blob = u64 server_challenge || u64 client_challenge` (server first). Then, by the principal key's type:

- **Type 1 (aes)**: run the "encode+encrypt" convention of 2.6 (length-prefixed shape, usage ignored). The result is `u32 len || ct`, with `plain` = 1 + 8 + 16 = 25 bytes, ct = 32 bytes, so 36 bytes total. XOR together every complete u64 LE word of those 36 bytes, starting at offset 0: words at offsets 0, 8, 16, 24; the last 4 bytes are ignored. **The first word therefore contains the 4-byte length field (`20 00 00 00`) plus the first 4 ciphertext bytes**, so the words are not aligned to the ciphertext. The XOR is the proof.
- **Type 2 and anything else (not type 1)**: HMAC-SHA256 with key = the raw secret bytes (all 32), message = the 16-byte `blob` (no envelope, no magic). XOR the four u64 LE words of the 32-byte digest. (Chosen because a type-2 encryption has a random confounder and would not be reproducible, `CephxProtocol.cc:47-56`.)

Type 1 proof is deterministic given the two challenges (no randomness in the cipher), which makes it testable.

Worked example for regression only (computed during review by an independent implementation of the steps above, **not** captured from a Ceph process, so still **[confirm on capture]**): type-1 key = bytes 00 01 .. 0f, server_challenge = 0x1122334455667788, client_challenge = 0x99aabbccddeeff00. The 36-byte string whose words are XORed starts `20 00 00 00 5e 4c 58 eb a0 ea 93 1c ...` and the resulting `key` field is 0x4fadd85010bcad18.

### 2.9 AUTH_SIGNATURE (pre-auth signature) and message signing

After AUTH_DONE both sides exchange one AUTH_SIGNATURE frame (`ProtocolV2.cc:1907-1914, 2342-2357, 2373-2411`). Value = HMAC-SHA256, key = the raw secret bytes of the session key (`auth_meta.session_key`, see below; for a type-2 key that is the whole 32-byte secret, no KDF and no usage value, `Crypto.cc:234-246`), message = a transcript of raw wire bytes. All-zero 32 bytes when there is no session key (auth method none).

- The transcript is captured by the reader/writer helpers from the very start of the connection (`pre_auth.enabled` is set at connect time, `ProtocolV2.cc:113, 396, 418`; appended at `:810-837` for received bytes and `:856-863` for sent bytes), so it covers **every byte exchanged in that direction since the TCP connection opened**: the banner, the HELLO frame, the AUTH_* frames, with all frame headers and trailers as they appeared on the wire. **[confirm on capture]** that the banner and the final epilogue are included.
- A side signs the bytes it **received** and verifies the peer's signature against the bytes it **sent**. So the client sends `HMAC(session_key, all bytes received from the server up to and including AUTH_DONE)` and expects `HMAC(session_key, all bytes it sent up to and including its last AUTH_REQUEST / AUTH_REQUEST_MORE)` from the server. The client's own AUTH_SIGNATURE frame is not part of the transcripts (`pre_auth.enabled = false` is set before sending it, `ProtocolV2.cc:1912`).
- Which key: for a mon connection the AUTH ticket session key; for an OSD connection the OSD ticket session key (`MonClient.cc:1653`, `CephxClientHandler.cc:222-226`).
- The transcript buffers are only reset when the connection state is reset (`ProtocolV2.cc:246-254`), not between attempts. If the server answers AUTH_BAD_METHOD and the client re-sends AUTH_REQUEST on the same TCP connection (`ProtocolV2.cc:1831-1834`), the failed first attempt stays in both transcripts. A client that retries on the same connection must keep appending; one that opens a fresh connection starts clean.
- A mismatch faults the connection (`ProtocolV2.cc:2389-2394`).
- In secure mode the frame is already sent through the encrypted stream (the handlers are created just before it, `ProtocolV2.cc:1904-1911`); in crc mode it is a normal crc frame.
- There is no per-message signature in msgr2: crc mode protects only against bit errors (`doc/dev/msgr2.rst:158-161`). The cephx session handler that signs messages is only created by ProtocolV1 (`src/auth/AuthSessionHandler.cc:27-53`; users at `src/msg/async/ProtocolV1.cc:972-976, 1153-1157, 1825-1834`).

### 2.10 Secure-mode connection secret (hand-off only)

When the negotiated mode is secure the server generates 64 random bytes (`src/auth/Auth.h:148-156`) and delivers them encrypted: mon connection in `cbl` (2.7, usage 0x03, AUTH session key), OSD connection in CephXAuthorizeReply v2 (usage 0x12, ticket session key). The secure-mode frame layer slices it with no further KDF: bytes 0..15 = AES-128-GCM key, 16..27 = one 12-byte nonce, 28..39 = the other 12-byte nonce; bytes 40..63 are unused (`src/msg/async/crypto_onwire.cc:285-313`). The client uses the first nonce for receiving and the second for sending; a server swaps them (the `crossed` flag at `:309-312`; client passes `crossed=false`, `ProtocolV2.cc:1904-1905`). The reference code asserts the secret is at least 40 bytes before slicing (`crypto_onwire.cc:286-287`), so a client must reject a shorter or missing secret in secure mode instead of proceeding. A second flag, `new_nonce_format`, is taken from the peer's msgr2 REVISION_1 feature bit (`ProtocolV2.cc:1903-1905`); what it changes is the secure-mode note's job. Everything else (nonce layout, counters) is the secure-mode note's job.

### 2.11 MAuth / MAuthReply (renewal path on an established mon session)

Message types: CEPH_MSG_AUTH = 17, CEPH_MSG_AUTH_REPLY = 18 (`src/include/ceph_fs.h:147-148`).

- MAuth payload (`src/messages/MAuth.h:56-62`, `PaxosServiceMessage.h:36-41`): u64 version, s16 deprecated_session_mon, u64 deprecated_session_mon_tid (the three paxos header fields; the reference constructor sets version 0, session_mon -1, tid 0, `PaxosServiceMessage.h:16-31`; **[confirm on capture]**), u32 protocol (= 2, cephx), blob auth_payload, u32 monmap_epoch. Message header version is 1; the class leaves compat at 0 (the default of `src/msg/Message.h:340-344`, which `PaxosServiceMessage.h:21-24` and `MAuth.h` do not override), but the encoder copies `version` into `compat_version` when the class left it 0 (`src/msg/Message.cc:248-251`; `msgr2.md` 2.9), so the wire header carries version 1 / compat_version 1 (**[confirm on capture]**).
- MAuthReply payload (`MAuthReply.h:58-65` encode, `:49-57` decode): u32 protocol, s32 result, u64 global_id, blob result_bl, string result_msg. `result` is an `errorcode32_t`: a signed 32-bit value that goes through the Ceph errno wire mapping, which is the identity for Linux errno values (`src/include/types.h:625-660`). Header version 1 / wire compat_version 1 as above (`MAuthReply.h:29-30`).
- In this path the mon calls its handler with no connection-secret slot (`src/mon/AuthMonitor.cc:948-954`), so a CEPHX_GET_AUTH_SESSION_KEY reply carries a zero-length `cbl` (2.7); the reference client also passes null pointers to its response handler here and ignores `cbl` / `extra` (`MonClient.cc:2089-2090`, `CephxClientHandler.cc:221`).
- In both, `auth_payload` / `result_bl` carry the cephx request/response of 2.7. Message framing (header, footer, routing) belongs to the message-layer note.

## 3 Client procedure

### 3.1 Prerequisites

- Entity: a `client.<id>` name and its key from a keyring (2.3). Wanted tickets: `want = OSD (0x04)`; the request mask is `want | AUTH (0x20)` = 0x24. The reference RADOS client asks for MON, OSD and MGR (`src/librados/RadosClient.cc:278-279`) and sets the AUTH bit itself (`src/auth/AuthClientHandler.h:43-46`); a mon connection never uses the MON ticket (`MonClient.cc:1513-1533` always runs the full mon handshake for a mon peer), so MON is optional. By the mon's code a mask of 0x24 is accepted: it walks the set bits up to the highest one, skips the AUTH bit and builds one OSD ticket (`CephxServiceHandler.cc:331-347`); **[confirm on capture]** only to see it on the wire.
- The key's caps must include a non-empty mon cap, otherwise the mon refuses the whole authentication (`CephxServiceHandler.cc:296-307`). The OSD cap must be non-empty too or the OSD rejects the ticket (`src/osd/OSD.cc:7755-7799`).
- Clock: only relative durations are used on the client (3.6), so a monotonic clock is enough. The server does its own timestamp sanity checks on ticket contents (`CephxProtocol.cc:530-546`) that do not involve the client clock.

### 3.2 Mon handshake

Per mon connection, after the msgr2 banner and HELLO:

1. **AUTH_REQUEST** (`MonClient.cc:1863-1903`). method = 2; preferred modes = `[1]` (crc) for a crc-only client (the reference client sends its config list, default "secure crc" for mons (`ms_mon_client_mode`, `src/common/options/global.yaml.in:986-1002`) but "crc secure" for OSDs (`ms_client_mode`, `:1028-1040`); the server picks the first client-preferred mode it allows, `AuthRegistry.cc:308-324`; the mode in AUTH_DONE is not checked against the offered list by the reference client, `ProtocolV2.cc:1902`, so a minimal client should check it itself). auth_payload:
   - u8 10 (mon auth mode)
   - EntityName (u32 8, string id)
   - u64 global_id (0 for a new session)
   - nothing else for cephx (`AuthClientHandler.h:52-54`).
   Worked layout for `client.admin`, global_id 0 (22 bytes): `0a | 08 00 00 00 | 05 00 00 00 "admin" | 00*8`. **[confirm on capture]**
2. **AUTH_REPLY_MORE**: payload = CephXServerChallenge (u8 1, u64 server_challenge) (`CephxServiceHandler.cc:53-71`). Keep `server_challenge` (non-zero).
3. **AUTH_REQUEST_MORE** (`CephxClientHandler.cc:57-104`): auth_payload = CephXRequestHeader(0x0100) || CephXAuthenticate{ v=3, client_challenge = random u64, key = proof (2.8), old_ticket = empty blob (or the previous AUTH ticket blob when reclaiming, 3.7), other_keys = request mask }. No mode byte here.
4. **AUTH_DONE**: global_id (the id the mon assigned, or the reclaimed one), connection mode, auth_payload = mon reply (2.7). Client steps:
   1. Decode the CephXResponseHeader; require request_type 0x0100 and status 0.
   2. Ticket reply: decrypt `msg_a` with the principal key, usage 0x04, by the key's own type; read `session_key` and `validity`; keep the opaque AUTH ticket blob. For `ticket_enc` = 1 see 2.7.
   3. If bytes remain: read `cbl`, decrypt with the **AUTH session key** (usage 0x03) to get the connection secret; read `extra`, decode it as a ticket reply using the **AUTH session key** as the decrypting key for each `msg_a`, store the per-service session key, validity and ticket blob. The reference client only logs a failure to decrypt `cbl` or `extra` (`CephxClientHandler.cc:230-246`), but then fails the connection anyway if a wanted ticket is still missing, because the handler returns -EAGAIN and the messenger treats any negative result as a fault (`CephxClientHandler.cc:250-254`, `ProtocolV2.cc:1899-1901`). A minimal client should simply fail on any decode / decrypt error here.
   4. Remember global_id; compute and send AUTH_SIGNATURE (2.9) with the AUTH session key; verify the server's.
5. Failure: AUTH_BAD_METHOD carries a negative errno such as -13 (access denied: unknown entity, wrong key, key type not allowed, no mon caps), -95 (method or mode not supported) (`CephxServiceHandler.cc`, `ProtocolV2.cc:2273-2278, 2282-2299`). A closed connection with no frame means "busy, retry later" (`ProtocolV2.cc:2334-2336`). The reference client treats BAD_METHOD as terminal when it has no other method to try (`MonClient.cc:1963-1996`); if the server's allowed-methods list contains another method it supports, the messenger re-sends AUTH_REQUEST on the same connection with the new method (`ProtocolV2.cc:1831-1834`), which also extends the signature transcripts (2.9). A cephx-only client can treat any AUTH_BAD_METHOD as terminal. Decode failures of the cephx request on the mon give -EPERM (-1) rather than -EACCES (`CephxServiceHandler.cc:164-170, 179-186`). After AUTH_DONE the reference client immediately sends a monmap request (`MonClient.cc:1838`); that and everything after belongs to the mon-client note.

### 3.3 Connecting to an OSD (authorizer, challenge round trip)

Requires a valid OSD ticket (3.2 step 4.3) and the global_id.

1. **AUTH_REQUEST**: method = 2; preferred modes as chosen (crc only: `[1]`); auth_payload = the authorizer of 2.7 with `service_id` = 4 and `CephXAuthorize{nonce = random u64, have_challenge = 0, plus_one = 0}` encrypted under the **OSD ticket session key**, usage 0x10 (`CephxProtocol.cc:351-375`; hook `MonClient.cc:1536-1552`).
2. **AUTH_REPLY_MORE** (always, in msgr2; the server's challenge is created on first sight of any authorizer without a challenge, `CephxProtocol.cc:582-597`, `MonClient.cc:1760-1788`): payload = **raw ciphertext** (no u32 length prefix) of the envelope of CephXAuthorizeChallenge, usage 0x11 (`CephxProtocol.cc:591`). Decrypt it, take `server_challenge + 1`.
3. **AUTH_REQUEST_MORE**: payload = the full authorizer again (same prefix through the ticket blob, same `nonce`), but with the proof re-encrypted as `CephXAuthorize{nonce (same), have_challenge = 1, plus_one = server_challenge + 1}` (`CephxProtocol.cc:664-692`). Type-2 ciphertexts differ between the two sends because of the random confounder.
4. **AUTH_DONE**: auth_payload = length-prefixed ciphertext of the envelope of CephXAuthorizeReply, usage 0x12, OSD ticket session key. Decrypt; require `nonce_plus_one == nonce + 1`; take `connection_secret` if present (secure mode) (`CephxProtocol.cc:639-662`). The AUTH_DONE.global_id field is not used by the reference client for non-mon peers (`MonClient.cc:1645-1655`).
5. Send/verify AUTH_SIGNATURE (2.9) with the OSD ticket session key. Then continue with the msgr2 session handshake (CLIENT_IDENT carries the same global_id as client name number, `ProtocolV2.cc:1956-1983`; reference code sets the messenger name from the mon-assigned id, `RadosClient.cc:294`).

A bad or expired ticket (rotating-key id no longer known to the OSD, `src/auth/RotatingKeyRing.cc:85-90`), a wrong challenge answer, or an OSD that rejects the ticket's caps is answered with AUTH_BAD_METHOD, result -13 (`MonClient.cc:1785-1792`, `CephxProtocol.cc:598-604`).

### 3.4 Which cipher applies where

Decide by the **type field of the key being used**, never globally:

- principal key (keyring): type T_p; AUTH session key type = T_p (`CephxServiceHandler.cc:278`).
- Each service ticket's session key type = min(T_p, type of the service's rotating key) (`src/auth/cephx/CephxKeyServer.cc:591-604`; the extra tickets inside the mon reply use the AUTH key's type as T_p, `CephxServiceHandler.cc:340-345`). So on an upgraded cluster whose service keys are still type 1, a type-2 client gets type-1 OSD session keys, and a type-1 client on a type-2 cluster gets type-1 session keys too. The AUTH session key and an OSD session key can therefore have different types, and a `msg_a` of type X can wrap a session key of type Y. Implement both ciphers for every key you decode.
- The wrapped ticket blobs are opaque, so their cipher is invisible to the client.

### 3.5 Expiry and renewal

- Ticket timing on the client (`CephxProtocol.cc:217-224, 234-250`): `expires = now + validity`; `renew_after = expires - (validity_seconds / 4)` with a real-valued (not floored) division of the whole-second part of `validity`, the nanoseconds of `validity` are not used for the quarter. If `validity` is zero neither field is updated; on a fresh handler `expires` is still zero, so `have_key()` (now < expires) turns false at its first check and the ticket is unusable. A zero validity should be treated as an error. A ticket counts as held while now < expires and as needing renewal when now >= renew_after. Defaults: AUTH ticket TTL 72 h (`auth_mon_ticket_ttl`, `global.yaml.in:2254-2264`), service tickets 1 h (`auth_service_ticket_ttl`, `:2265-2276`), both capped by the expiry of the newest rotating key (`CephxKeyServer.cc:120-128`). So the OSD ticket renews at about 45 minutes and the AUTH ticket at about 54 hours.
- Servers do not enforce `expires` themselves (only sanity checks, `CephxProtocol.cc:530-546`). What actually kills an old ticket is the rotating-key id being dropped by the OSD (3 keys are kept, `src/auth/Auth.h:169`, `RotatingKeyRing.cc:85-90`). Hence: renew at `renew_after`, and on any -13 from an OSD connect, renew once and retry.
- msgr2 never re-authenticates an established connection; expiry only matters when (re)connecting. **[confirm on capture]** that a long-running OSD connection survives its ticket expiring.

### 3.6 How to renew

Two equivalent options:

A. **Re-run 3.2 on a fresh mon connection** (simplest, recommended for the minimal client). The reference client also does this when it reconnects.
B. **In-session renewal with MAuth/MAuthReply** (reference behaviour, `MonClient.cc:1138-1155`): send MAuth(protocol 2) with payload CephXRequestHeader(0x0200) || authorizer for service AUTH (2.7 layout, `service_id` = 0x20, ticket = the AUTH ticket blob, proof usage 0x10 under the AUTH session key; no challenge round trip, `CephxServiceHandler.cc:370-376`) || CephXServiceTicketRequest{v=1, keys = mask without the AUTH bit}. The reply is the ticket reply of 2.7. To renew the AUTH ticket itself in-session, resend a CEPHX_GET_AUTH_SESSION_KEY on the same session (the server challenge from the first exchange is reused). From the code read this looks workable: the reference client's build_request emits that request whenever its AUTH bit is in `need`, with the held AUTH ticket as `old_ticket` (`CephxClientHandler.cc:61-104`), and the mon handles MAuth on the session handler it created during AUTH_REQUEST (`Monitor.cc:6690`, `AuthMonitor.cc:948-954`); but nobody traced the server side of a second CEPHX_GET_AUTH_SESSION_KEY after the first completed, so it stays **[unverified]**.

### 3.7 global_id and reclaim

- First contact: global_id 0 in AUTH_REQUEST; the mon assigns a new one and returns it in AUTH_DONE (`Monitor.cc:6678-6686`). The old-ticket field must then be empty (a superfluous ticket is an error, `CephxServiceHandler.cc:84-89`).
- Reconnect keeping the same id: put the old id in AUTH_REQUEST and the old AUTH ticket blob in `old_ticket`; the mon verifies the ticket's global_id (`CephxServiceHandler.cc:116-150`). With a CephXAuthenticate of v3 the old ticket is mandatory; only v1/v2 clients can fall back to an unproven reclaim, and only while `auth_allow_insecure_global_id_reclaim` is true (default true, `global.yaml.in:2277-2295`).
- Why a minimal client should keep its global_id across reconnects: it is the client number in the CLIENT_IDENT and thus part of request ids; a new id on every reconnect defeats any OSD-side duplicate detection of resent writes. **[unverified]**: not traced in the OSD code in this note; check in the OSD/RBD note.

### 3.8 Error cases to handle explicitly

| Situation | Observable | Source |
|---|---|---|
| Unknown entity or wrong key | AUTH_BAD_METHOD, result -13 | `CephxServiceHandler.cc:189-250` |
| Key type not allowed by monmap | same, -13 | `:195-210`, `src/mon/Monitor.cc:7233-7244` |
| Entity has no mon caps | same, -13 | `:296-307` |
| Mon has not formed its first quorum (-EBUSY) | no AUTH_BAD_METHOD; the connection is dropped, retry later | `Monitor.cc:6608-6611`, `ProtocolV2.cc:2334-2336` |
| Server demands secure mode, client offered crc only | AUTH_BAD_METHOD, result -95, allowed_modes lists secure | `ProtocolV2.cc:2273-2278` |
| Decrypt fails, magic mismatch, MAC mismatch (type 2) | treat as authentication failure, drop connection, never retry blindly in a loop | `CephxProtocol.h:603-657`, `Crypto.cc:960-979` |
| AUTH_SIGNATURE mismatch | drop connection | `ProtocolV2.cc:2389-2394` |

## 4 Minimal-client choices

**Must implement**

- msgr2 control-frame bodies of 2.2 and the two flows of 3.2 / 3.3.
- Key decode (2.3) for types 1 and 2; keyring text `key = <base64>`.
- Cipher type 2 (2.5) **and** type 1 (2.4). Type 2 is required on any cluster built by a v20.2.5 mon (headline 1). Type 1 is only needed for upgraded clusters or hand-made keys; it can be implemented second, but the core API must dispatch per key type from day one.
- Primitives the shim must offer: AES-128/256 block ops (CBC and ECB), HMAC-SHA256, HMAC-SHA384, CSPRNG. `docs/ROADMAP.md` records that iPXE has AES, SHA-1/2 and HMAC; SHA-384 and a CTS mode were **not checked** here.
- Challenge proof for both types (2.8).
- Decode of the mon reply including `cbl` and `extra` (2.7), per-key-type decryption.
- Authorizer build, challenge handling, reply verification (3.3).
- AUTH_SIGNATURE both ways (2.9): requires the core to keep byte-exact transcripts of everything sent and received from connection start to the end of auth, in each direction.
- Ticket timing (3.5) and one retry on -13.

**May skip**

- Auth methods NONE and GSS (client side `auth_client_required` default is "cephx, none", `global.yaml.in:2176-2185`; a cephx-only client simply never offers NONE; **[unverified]** whether a cluster with auth disabled replies usefully to a cephx offer).
- Secure mode, as long as the cluster accepts crc for clients: offer `[1]` only. Defaults allow it (`ms_mon_service_mode` and `ms_service_mode` default to both modes, `global.yaml.in:971-977, 1016-1022`); a cluster pinned to secure fails with -95 and a message naming the cause. If secure is added later only 2.10 and the AUTH_REPLY/DONE secret plumbing (already in 2.7) are needed here.
- Rotating-key fetch (CEPHX_GET_ROTATING_KEY), verifying authorizers, serving, caps parsing, MGR/MDS tickets, the old-key retry of `pending_key` on the server side.
- Message signing: not applicable in msgr2.
- msgr1 and MAuth-based negotiation (the `protocol = 0` initial MAuth of `MonClient.cc:1829-1861` is msgr1 only).
- In-session renewal (3.6 option B) if the client prefers to reconnect.

**Should reject / refuse**

- Any key whose type is not 1 or 2, or whose secret is shorter than the minimum.
- Server replies where decrypt, magic, MAC or nonce checks fail.
- A server-assigned global_id of 0 (`MonClient.cc:2079-2081` logs it as invalid).
- Anything that would make it fall back to a weaker mode silently: it should refuse if the server answers with a mode it did not offer.

## 5 Test vectors needed

For each item: what to capture, how to check.

1. **Key decode.** From a test cluster, export `client.<id>` keyrings of type 1 and type 2 (create with `ceph auth get-or-create ... ` and the `key_type` option if the cluster allows both, `AuthMonitor.cc:1510-1548`). Check the type field, length and `created` against 2.3. Do not commit real keys; use throw-away keys on the test cluster and scrub.
2. **Type 1 cipher.** Known-answer vectors generated independently (any AES-128-CBC with the IV in 2.1 and the padding of 2.4), cross-checked against one ciphertext captured from a real session whose key is known. Ceph's own KATs are in `src/test/crypto.cc:44-167` (not to be copied, see 7); the single-block one was already reproduced during review (2.4).
3. **Type 2 cipher.** RFC 8009 appendix vectors (the Ceph test cites them, `src/test/crypto.cc:389-451`, with a fixed confounder injected, key usage 2). Check: derived Ke/Ki, ciphertext, 24-byte MAC, and the single-block case (empty plaintext). Cover plaintext lengths 0, 6, 16, 21 (these match the source tests' shapes). The review already reproduced the Ceph test's four vectors with an independent implementation (2.5), so this item mainly gates the implementation under test; the same vectors should be typed in from the RFC, not from Ceph's file (7). What a capture adds: type-2 behaviour with a real confounder and non-2 usage values (0x03, 0x04, 0x05, 0x10, 0x11, 0x12).
4. **Challenge proof.** Capture AUTH_REPLY_MORE and the following AUTH_REQUEST_MORE from a real client (crc mode: `ms_mon_client_mode = crc`, `ms_client_mode = crc` on the capturing client; mon must allow crc). The two challenges are in the frames; recompute `key` with the known keyring key for both key types. Type 1 confirms the 4-byte-length quirk; type 2 confirms the HMAC form.
5. **Mon reply decode.** Capture one full AUTH_DONE payload and decrypt it offline with the known keyring key; check magic, validity, the connection secret length (0 in crc, 64 in secure), and the `extra` ticket count (set `debug_auth 10` on the capturing client so it logs the session key and validity, `CephxProtocol.cc:211-215`; at level 30 more detail).
6. **Authorizer round trip.** Capture an OSD connect from a real client: AUTH_REQUEST, AUTH_REPLY_MORE, AUTH_REQUEST_MORE, AUTH_DONE. Check: first authorizer structure, challenge is raw (no length prefix), second authorizer has `have_challenge = 1` and `plus_one`, final reply decrypts to `nonce + 1`, and whether the nonce is the same across the two sends.
7. **AUTH_SIGNATURE.** From the same raw capture compute `HMAC-SHA256(session_key, rx bytes)` and `(session_key, tx bytes)` for both mon and OSD connections and compare with the AUTH_SIGNATURE frames; this settles which bytes are covered (banner, HELLO, epilogue).
8. **Renewal.** Run with `auth_service_ticket_ttl` set low on a throw-away cluster, capture the MAuth(0x0200) exchange and a reconnect with `old_ticket`.
9. **Rejection paths.** Wrong key, key type not allowed (use `mon_auth_emergency_allowed_ciphers` on a test mon), crc-only client against a secure-only cluster: record the exact AUTH_BAD_METHOD result codes.

## 6 Open questions

1. Which key type will our test cluster hand out for `client.*` (type 2 on a fresh v20.2.5 cluster by the source, headline 1)? Confirm with `ceph auth get` and the keyring base64 prefix. **[confirm on capture]**
2. Exact byte coverage of the pre-auth transcript (banner, HELLO, epilogues). Source suggests everything, since start; needs a capture (2.9, test 7).
3. Wire confirmation that requesting only OSD (+AUTH) tickets (mask 0x24) is accepted by the mon with no MON/MGR ticket (the code says yes, 3.1).
4. Whether the OSD checks that CLIENT_IDENT's gid equals the ticket's global_id (only name derivation seen in `ProtocolV2.cc:2452-2453`), and what resent-op identity depends on (3.7).
5. In-session renewal of the AUTH ticket itself over a long-lived mon connection: server challenge reuse (3.6 B) is **[unverified]**. The recommended simple path (reconnect, 3.6 A) avoids it but needs old-ticket reclaim to keep the id.
6. Behaviour when an OSD connection outlives its ticket and rotating key (3.5).
7. (Closed for the Ceph side.) CS3 single-block, unaligned and block-aligned cases were reproduced against the vectors in Ceph's unit test (2.5). Still open: that those vectors are byte-identical to the RFC 8009 appendix (take them from the RFC when writing the project's own test, 7).
8. Whether `status` in CephXResponseHeader carries useful errors on the GET_AUTH_SESSION_KEY reply (the reference client ignores it; only the ticket reply path sets non-zero in the code read, `CephxServiceHandler.cc:419-426`).
9. SHA-384 and a CTS mode in iPXE's crypto set, and in the Windows driver crypto API, are unchecked; the shim may need to supply them (4).
10. `auth_client_required` default "cephx, none": what a "none" cluster does with an AUTH_REQUEST method 2 (skipped by design, 4).
11. Mon-side limits on the number of failed attempts or lockouts for a wrong key (not looked at).
12. Doc drift (1.4): report upstream? Not our job; recorded so nobody relies on the doc.

## 7 Licensing questions

- The 16-byte CBC IV (2.1), the 8-byte envelope magic, the usage numbers and the tag/constant tables are protocol constants taken from Ceph headers (`src/include/ceph_fs.h:99`, `CephxProtocol.h:34-54, 601`). We treat them as protocol facts, not expression; the IV is written here as hex to avoid copying a source token. Needs a maintainer decision for the MIT core.
- Ceph's own test arrays (`src/test/crypto.cc`, AES KATs and the type-2 vectors) must not be copied into the MIT tree. The type-2 vectors are published in RFC 8009 and can be taken from the RFC; the type-1 vectors should be regenerated from captures or an independent implementation.
- RFC 8009 / RFC 3962 describe the key derivation, CTS and MAC layout that type 2 follows; implementing a public standard is fine. This note's description is derived from Ceph's code and cross-checked by running it against Ceph's own test vectors (data not copied here); statements about what the RFC text itself says are not verified against the RFC.
- The worked examples in 2.8 were computed with a throw-away implementation using trivial keys (00 01 02 ..); they contain no Ceph data other than the structure being described.
- `doc/dev/*.rst` files are Ceph documentation; their license is not confirmed here. They are cited, not quoted.
- The per-file license of `src/auth/*` and `src/mon/MonClient.cc` is stated in file headers as LGPL-2.1 in the files read (e.g. `src/auth/cephx/CephxProtocol.h:1-13`, `src/auth/Crypto.h:1-13`); `Crypto.cc` and `CephxClientHandler.cc` headers were seen only partially. Still to be confirmed per file as the roadmap already notes.
