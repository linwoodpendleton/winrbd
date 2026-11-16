# winrbd protocol spec notes (Phase 0)

[English](#en) | [中文](#zh)

---

<a name="en"></a>

## English

These are the Phase 0 protocol notes from [docs/ROADMAP.md](../ROADMAP.md): eight notes that together describe, byte for byte, what a **minimal Ceph client** (never a server) has to put on the wire to open an RBD image on one pinned Ceph release and read and write it. A later implementer should be able to write the portable core from these notes alone.

Ground rules for every note (see [CONTRIBUTING.md](../../CONTRIBUTING.md)):

- Written in our own words. Layout tables, numeric constants and protocol facts only; no Ceph code, comments or lookup data.
- Every claim carries a `path:line` reference relative to the Ceph tree root at the pinned tag, or a Ceph doc page.
- **[unverified]** = could not be pinned in source. **[confirm on capture]** = read from source but must be checked on a live cluster before the core relies on it. Both kinds are collected in section 6 of each note and, deduplicated, in section 7 below.
- Nothing in these notes has been confirmed on a live capture yet.

Contents of this page: 1 pinned release and compatibility stance; 2 the proposed v1 image profile; 3 the client capability profile; 4 table of notes; 5 cross-note consistency; 6 capture plan; 7 consolidated open questions; 8 licensing questions.

### 1 Pinned release and compatibility stance

- **Pinned: Ceph v20.2.5 "Tentacle", commit `ed27c686770872022f4c1de04f6b0ac5d5384ded`.** Reference source tree: `winrbd-ref/ceph-v20.2.5`, a read-only checkout kept next to this repository (not inside it, not a submodule); all `path:line` references in the notes are relative to its root.
- **Why this release:** it is the newest stable point release at the time of writing (stated by the project owner; not re-checked against upstream by this pass). Encodings are versioned and gated by feature bits, so pinning the newest release gives the newest encodings, and every older encoding that the notes still describe is described as "what a v20.2.5 daemon sends to a client that advertises fewer bits".
- **What v1 targets:** a v20.2.5 cluster whose `require_osd_release` is reef or newer. That is the floor for a running v20 cluster (v20 OSDs refuse to start below it, `osdmap.md` 2.4.2), and the decoder floors in `osdmap.md` 4.1 (full-map client block 9 or 10, incremental 8 or 9, pool 29 to 32) cover both a reef/squid-level and a tentacle-level map. Other v20.2.x point releases are expected to be wire-identical but were not looked at.
- **Reef 18 and Squid 19 daemons are not a v1 target and were not researched.** The notes only record differences that were visible in the code paths read; all of them are selected by feature bits or by `require_osd_release`, not by a daemon version string:
  - MOSDOp header version 9 needs the SERVER_SQUID feature bit on the connection, else version 8 (`osd-ops.md` 2.3, 4.4). A client that ever targets an older daemon must pick the version from the negotiated feature set, not hard-code 9.
  - Pool struct version 32 needs SERVER_TENTACLE; 29 (30 for stretch pools) otherwise; full-map client block 10 and incremental 9 need SERVER_REEF (`osdmap.md` 2.4.2, 2.7.4).
  - The CRUSH blob carries two extra fields only when the CRUSH_MSR / SERVER_QUINCY bits are in the encoding set (`crush-and-placement.md` 2.1, 2.5).
  - The address form inside `lock get_info` replies depends on the requester's feature bits (`rbd-format2.md` 2.7).
- Whether Reef or Squid daemons accept the client capability profile below is an open question (section 7, G1). The roadmap question "which release to pin" is answered by this section; the compatibility question stays open.

### 2 Proposed v1 image profile

Source: `rbd-format2.md` 4.2 and 2.8 (exact values; "features" is the `u64` from `get_features`). Format 2 only; format 1 is refused.

| Profile | Purpose | `features` rule | Usual values |
|---|---|---|---|
| **P1** | the recommended read-write profile | `features & ~0xA1 == 0`: only layering `0x01`, deep-flatten `0x20`, data-pool `0x80` | `0x01`, `0x21` |
| **P1-L** | read-write with the exclusive-lock bit present | `features & ~0xA5 == 0` (P1 plus exclusive-lock `0x04`); writing is refused until lock policy L2 is confirmed on a capture (`rbd-format2.md` 3.9, T15), reading is accepted | `0x05`, `0x25` |
| **R1** | read-only | `features & ~0x1FF == 0`: accepts `0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0x100`; striping bit only in default layout; object-map and fast-diff are ignored | the stock default `0x3D` is readable |

Common conditions:

- Refused for any use: migrating `0x200`, non-primary `0x400`, dirty-cache `0x800`, unknown bits, a clone (parent present), non-default layout (`stripe_count != 1` or `stripe_unit != object size`), erasure-coded data pool, non-default namespace, `flags != 0` for a writer.
- A writer additionally refuses object-map `0x08`, fast-diff `0x10`, journaling `0x40`, operations `0x100`, and a pool that has the POOL_SNAPS flag (see `osdmap.md` 4.3).
- Default layout: object size `1 << order`, `order` in 12..25 (default 22 = 4 MiB), stripe unit equal to object size, stripe count 1.
- Snapshots may exist; the writer sends the image's current snapshot context on every mutating op and neither creates nor reads snapshots. The staleness limit (no header watch) is open question F2.
- Data pool: replicated; may differ from the metadata pool (data-pool feature).
- Metadata is read only through class calls (`rbd` and `lock` classes), never by parsing omap keys; data objects are named `<object_prefix>.<16 hex digits of object number>`.
- Making a default image (`0x3D`) writable: `rbd feature disable <pool>/<image> fast-diff`, then `object-map`, then optionally `exclusive-lock`; the result is `0x21` (or `0x25`). `rbd create --image-format 2 --image-feature layering ...` gives `0x01`.
- Stable refusal identifiers for the core's error reporting are in `rbd-format2.md` 4.6.

Writer lock policy defaults (`rbd-format2.md` 4.5): reader L0 (no lock); writer on P1 L1 (no lock, concurrent writers are an operator error); writer on P1-L refused until L2 is confirmed.

### 3 Client capability profile

What the core implements, stated once. Each line points to the note that owns the detail.

| Area | v1 choice | Note |
|---|---|---|
| Messenger | msgr2 only; banner `ceph v2\n`, payload 16, supported mask `0x1` (REVISION_1), required `0x0`; revision 1 framing; the v1 messenger and revision 0 framing are refused | msgr2.md 2.2, 4 |
| Modes | **crc mode first**, offered as `preferred_modes = [1]`; **secure mode (AES-128-GCM) optional later**, specified separately; mode returned in AUTH_DONE is checked against the offer | msgr2.md 4.2, msgr2-secure-mode.md |
| Compression | not advertised (banner bit 1 clear), never send COMPRESSION_REQUEST | msgr2.md 2.2 |
| Session | lossy client session: HELLO type CLIENT `0x08`, CLIENT_IDENT flag bit 0 set, cookie 0, gid -1 until a global id is assigned; no reconnect frames; new TCP connection and full auth after every fault | msgr2.md 3.5, 4 |
| Feature bits | CLIENT_IDENT `supported_features = 0x3f07fffffffdffff` (the full v20.2.5 set), `required_features = 0x0800000000000000` (MSG_ADDR2). Advertise the full set: it yields the canonical encodings, and an OSD can refuse a client that lacks bits its map requires | msgr2.md 2.10, 4.4; osdmap.md 2.7.4, 2.8 |
| Auth | **cephx only** (method 2); no `none`, no GSS; mon handshake with auth mode byte 10, OSD handshake with the authorizer and challenge round trip; AUTH_SIGNATURE both ways with HMAC-SHA256 over byte-exact transcripts | cephx.md 3.2, 3.3 |
| Keys | key types 1 (AES-128-CBC) and 2 (AES-256 CTS with HMAC-SHA384); type 2 is mandatory because a fresh v20.2.5 cluster allows only type 2 | cephx.md 1.5, 4 |
| Tickets | request mask `0x24` (OSD plus AUTH); renew at 3/4 of validity; one monitor session at a time | cephx.md 3.1, 3.5; mon-client.md 3.8 |
| Monitor | `mon_host` given as literal addresses; v2 addresses only; first message MMonGetMap, then MMonSubscribe v3 for `monmap` and a continuous `osdmap` subscription (start 0, then held epoch + 1); MOSDMap v4 | mon-client.md 3, 4 |
| OSDMap | decode the client block only, skip the OSD-only block by length; floors in `osdmap.md` 4.1; reject erasure pools, tiering, stretch, pool-snapshot mode, EIO flag | osdmap.md 4 |
| Placement | object name to PG (rjenkins or Linux dcache hash by pool setting, namespace byte `0x1F` rule) then CRUSH for replicated pools: straw2 (legacy straw recommended, uniform and list optional) with firstn and chooseleaf; upmap, primary affinity, pg_temp, primary_temp applied; indep, MSR, tree buckets, EC rejected | crush-and-placement.md 3, 4 |
| OSD I/O | MOSDOp version 9 / compat 3, MOSDOpReply version 8, tid and resend rules, MOSDBackoff handling, snapshot context on every mutating message; ops: READ, SPARSE_READ (optional), STAT, WRITE, WRITEFULL, ZERO, TRUNCATE, CREATE, DELETE, CALL, OMAPGETVALS, OMAPGETVALSBYKEYS | osd-ops.md 2, 4 |
| Image layer | `rbd` and `lock` class calls, striping math, sparse reads as zeros | rbd-format2.md |
| Crypto and primitives the shim must offer | AES-128 and AES-256 block operations (CBC, ECB; CTS is built from them), HMAC-SHA256, HMAC-SHA384, CSPRNG; AES-128-GCM only if secure mode is built; CRC-32C (raw, generated table), rjenkins string hash and CRUSH hash written by us; the `crush_ln` table is a licensing question (section 8) | cephx.md 4; msgr2.md 2.5; crush-and-placement.md 3.4.2 |
| Limits | every length, count and vector read from the wire is capped by a configured budget; the stock framing layer has no caps | msgr2.md 4.1; osdmap.md 3.8 |

### 4 The notes

All eight are drafts. "Reviewed against source" means one independent pass that re-opened the cited lines in the pinned tree and recomputed what could be recomputed, followed by this cross-note pass. "Confirmed on capture" is **no** for every note.

| Note | Scope | Status | Reviewed against source | Confirmed on capture |
|---|---|---|---|---|
| [msgr2.md](msgr2.md) | msgr2.1 crc-mode client: banner, 32-byte preamble, segments, CRC-32C, tags and control-frame payloads, HELLO, auth frame shells, CLIENT_IDENT / SERVER_IDENT, the MESSAGE frame and 41-byte header, `entity_addr_t`, feature bits, pre-auth signature mechanics | draft | yes; CRC, frame-size and worked-frame vectors recomputed; crc path high confidence, secure summary only | no |
| [msgr2-secure-mode.md](msgr2-secure-mode.md) | optional secure mode: mode negotiation defaults, connection-secret slicing, AES-128-GCM nonce layout, secure 2.1 frame layout and size arithmetic, the pre-auth signature as first encrypted frame, declining compression | draft | yes; key/nonce slicing and two worked frames reproduced with separate scripts | no |
| [cephx.md](cephx.md) | cephx: key and keyring format, cipher types 1 and 2, encrypted envelope, tickets, challenge proof, monitor handshake, OSD authorizer, expiry, renewal and global id | draft | yes; both ciphers reproduced against the upstream known-answer vectors by an independent implementation | no |
| [mon-client.md](mon-client.md) | monitor client: `mon_host` parsing, MonMap, MMonGetMap and MMonSubscribe, MOSDMap delivery and gap handling, keepalive, hunting, MAuth renewal, global id | draft | yes; references re-checked | no |
| [osdmap.md](osdmap.md) | OSDMap and Incremental, client subset: envelopes, versions chosen by feature bits, `pg_pool_t`, apply order, constants, map CRC, how the fields feed placement | draft | yes; every field order re-read in source | no |
| [crush-and-placement.md](crush-and-placement.md) | object name to PG to placement seed to CRUSH for replicated pools: hashes, blob layout, tunables, straw2 and `crush_ln`, firstn with chooseleaf, upmap, affinity, temp maps | draft | yes; hashes and `crush_ln` rebuilt from the pinned C files, 688 in-tree expected mappings matched by a re-implementation of the note's procedure | no |
| [osd-ops.md](osd-ops.md) | MOSDOp v9, MOSDOpReply v8, MOSDBackoff; 38-byte op record; op semantics; errors; tids, resend, backoff, full pools, snapshot context, ordering | draft | yes; the 217-byte worked MOSDOp recomputed | no |
| [rbd-format2.md](rbd-format2.md) | RBD format 2: object naming, `rbd` and `lock` class calls, feature bits, striping and byte-range mapping, sparse I/O, exclusive-lock policies, the v1 image profile | draft | yes; striping and lock examples recomputed | no |

Suggested reading order for an implementer: msgr2, cephx, mon-client, osdmap, crush-and-placement, osd-ops, rbd-format2; msgr2-secure-mode only when secure mode is built.

### 5 Cross-note consistency

Method: the shared facts below were compared across all eight notes by section and by searching every note for each fact; the sections that own each fact were read in full. This was not a second line-by-line re-read of 7000 lines. Source lines cited in the fixes were re-opened in the pinned tree; the CRC-32C vectors were recomputed independently.

**Facts that agree everywhere they appear**

| Fact | Value | Where |
|---|---|---|
| Pinned release | v20.2.5, commit `ed27c686...` | every note header |
| CRC-32C | polynomial `0x1EDC6F41` (reflected `0x82F63B78`), raw update, no final inversion; preamble CRC seed 0; rev 1 segment CRC seed `0xFFFFFFFF`; OSDMap map CRC start `0xFFFFFFFF`; vectors `crc("123456789", seed 0xFFFFFFFF) = 0x1CF96D7C`, `crc("foo bar baz", 0) = 4119623852`, `crc("whiz bang boom", 0) = 2360230088` recomputed here | msgr2.md 2.5, 5.1; msgr2-secure-mode.md 2.8, 5.1; osdmap.md 2.4.5 |
| Banner | `ceph v2\n`, payload 16, daemons send supported `0x3`, required 0; client sends `0x1` / 0 | msgr2.md 2.2; msgr2-secure-mode.md 2.2 |
| Frame tags | 1 HELLO, 2 AUTH_REQUEST, 3 AUTH_BAD_METHOD, 4 AUTH_REPLY_MORE, 5 AUTH_REQUEST_MORE, 6 AUTH_DONE, 7 AUTH_SIGNATURE, 8 CLIENT_IDENT, 9 SERVER_IDENT, 17 MESSAGE, 18 KEEPALIVE2, 19 KEEPALIVE2_ACK, 20 ACK | msgr2.md 2.4; cephx.md 2.2; msgr2-secure-mode.md 2.1 |
| Entity types | MON 1, MDS 2, OSD 4, CLIENT 8, MGR 16, AUTH 32 | msgr2.md 2.7; cephx.md 2.1; msgr2-secure-mode.md 2.5 |
| Auth method / mode / key type | method NONE 1, CEPHX 2, GSS 4; mode CRC 1, SECURE 2; key type AES 1, AES256KRB5 2 | msgr2.md 2.7; cephx.md 2.1; msgr2-secure-mode.md 2.3 |
| Connection secret | 64 bytes in secure mode, 0 in crc mode; 40 consumed (16 key + 12 + 12); shorter must be rejected | cephx.md 2.10, 5; msgr2-secure-mode.md 2.5, 2.6 |
| Nonce direction | client receives with bytes 16..27, sends with bytes 28..39 | msgr2.md 2.6.3; msgr2-secure-mode.md 2.6 |
| Pre-auth signature | HMAC-SHA256, key = raw secret bytes of the session key, each side signs what it received and verifies against what it sent | msgr2.md 3.3; cephx.md 2.9; msgr2-secure-mode.md 2.7 |
| Message types | 2 PING, 4 MON_MAP, 5 MON_GET_MAP, 6 MON_GET_OSDMAP, 15/16 SUBSCRIBE/ACK, 17/18 AUTH/AUTH_REPLY, 19/20 GET_VERSION/REPLY, 41 OSD_MAP, 42 OSD_OP, 43 OSD_OPREPLY, 61 OSD_BACKOFF | mon-client.md 2.2; cephx.md 2.11; osd-ops.md 2.1 |
| Body versions | MonMap 10 (compat 6), MMonSubscribe 3 / compat 1, MOSDMap 4 / compat 3, MOSDOp 9 / compat 3, MOSDOpReply 8 / compat 2, MOSDBackoff 1 / 1, OSDMap wrapper 8 / compat 7 with client block 10, incremental 9, pool 32 | mon-client.md; osd-ops.md 2.1; osdmap.md 2.4.2 |
| Advertised feature mask | `0x3f07fffffffdffff` (clear bits: 17, 51..55, 62, 63); bit masks of SERVER_NAUTILUS `0x0200000010000004`, REEF `0x0200000090000000`, TENTACLE `0x0204000000000000` etc. recomputed from the incarnation rule | msgr2.md 4.4; osdmap.md 2.7.4; mon-client.md 2.9; osd-ops.md 4.4; crush-and-placement.md 2.8 |
| `pg_t` and seeds | 17-byte `pg_t`; effective PG = stable modulo against `pg_num`; CRUSH seed uses `pgp_num` (HASHPSPOOL: two-input hash with the pool id) | osdmap.md 2.1.1, 3.7; crush-and-placement.md 3.2; osd-ops.md 2.3 |
| Op codes and record | 38-byte `ceph_osd_op`; READ `0x1201`, WRITE `0x2201`, CALL `0x1401` etc. | osd-ops.md 2.5, 2.6; rbd-format2.md 2.11 |
| Ticket timing | OSD tickets 1 h, renew at 3/4 of validity; AUTH ticket 72 h | cephx.md 3.5; mon-client.md 3.8 |

**Inconsistencies found and fixed in the notes in this pass**

1. `cephx.md` 2.11 gave the MAuth / MAuthReply header as version 1 / compat 0. That is the class default; on the wire the encoder copies version into compat when the class left it 0 (`src/msg/Message.cc:248-251`), so the wire header is 1 / 1, which is what `mon-client.md` 2.1/2.2 and `msgr2.md` 2.9 already said. Fixed in `cephx.md`.
2. `msgr2.md` (section 3.3 item 9, open question 3) still called the AUTH_SIGNATURE key "unverified for cephx" although `cephx.md` 2.9 and `msgr2-secure-mode.md` 2.7 had pinned it (raw session-key secret, no KDF). Updated to "resolved from source, byte check on capture remains".
3. `msgr2.md` open question 2 said the `mon_host` bootstrap rules were unread; they are in `mon-client.md` 3.1. Pointer added.
4. `msgr2.md` open question 11 said secure mode was unchecked and unspecified; the dedicated `msgr2-secure-mode.md` now owns it. Pointer added; 2.6.3 is declared a summary.
5. Pool-snapshot mode: `osd-ops.md` 3.9 said "check the pool mode in the OSDMap note" and `rbd-format2.md` Q14 said detection "was not read", while `osdmap.md` 2.7.2 already lists the flag. Detection is flag bit 14 (POOL_SNAPS), confirmed at `src/osd/osd_types.cc:1717-1720`. Fixed `rbd-format2.md` (2.11, Q14), `osd-ops.md` (3.9) and added refusal rows to `osdmap.md` 4.3 (POOL_SNAPS and the EIO flag).
6. Capture recipe: `osd-ops.md` 5.2 forced only `ms_client_mode = crc`, but a stock client's monitor connection uses a separate option that defaults to secure (`msgr2-secure-mode.md` 2.9; `msgr2.md` 5.2 and `cephx.md` 5 already forced both). `osd-ops.md` 5.2 now forces both.
7. Feature mask: `osdmap.md` Q1 and `mon-client.md` Q1 both deferred the decision to the msgr2 note. They now point to `msgr2.md` 4.4, which gained the reason a reduced mask can be refused outright: the OSD recomputes its client-facing required mask from the OSDMap, including CEPHX_V2 (bit 61) once `require_min_compat_client` is nautilus or newer (`src/osd/OSD.cc:8820-8826`, `src/osd/OSDMap.cc:1832-1842`).
8. `osdmap.md` Q6 (blocklist handling) said "to be settled in the OSD op note"; `osd-ops.md` 2.11 and 4.1 settle it (-108 is fatal for the session). Cross-reference added.
9. `msgr2.md` licensing item 1 named two companies from third-party file headers; reworded without the names (the file paths stay).

**Differences that are deliberate, not inconsistencies**

- Address choice: the reference messenger connects to the first vector entry of type 1 or 2 (`msgr2.md` 2.8 / `mon-client.md` 2.4.3); our v2-only client takes the first entry of type 2 (`osdmap.md` 4.1, `mon-client.md` 2.4.3). Whether daemons list v2 before v1 is open (C2).
- Subscription: the reference allows ONETIME osdmap subscriptions; `mon-client.md` recommends a continuous one for the minimal client.
- An empty address is encoded with `elen` 28 by every encoder but the decoders of `msgr2.md`, `mon-client.md` and `osdmap.md` accept `elen` 0; the notes agree on both statements.

**Could not be resolved from the notes (carried into section 7)**

- Whether any real map ever deviates from the ordered-container assumption (sorted wire order) and from the sockaddr byte layouts: needs capture (C2).
- Whether the OSD requires, beyond MSG_ADDR2, bits that the full mask contains for some map state: derived from source only (A2).
- The `path:line` references number in the hundreds; each note's reviewer re-opened them, this pass re-opened only the ones listed above.

### 6 Capture plan

All oracles are stock Ceph tools run against a lab cluster; the client under test is never its own oracle. Notes keep their own vector tables (msgr2 5, secure 5, cephx 5, mon-client 5, osdmap 5, crush 5, osd-ops 5, rbd 5); this section groups them by what produces them and says how to run them safely.

**Lab cluster (needed for groups 1 to 5)**

- Fresh Ceph v20.2.5 deployment on a throw-away network of private addresses, never a cluster that holds anything else. Three monitors listening on v2 and v1; at least four OSDs; one IPv6 monitor if possible.
- Pools: replicated with `pg_num` a power of two; replicated with `pg_num` not a power of two (for example 48); one pool with a weight-set; one device-class rule; one erasure pool (only to test refusals); a pool made full by a quota.
- Cluster states: upmap, upmap-items, upmap-primary, primary affinity, pg_temp, an OSD out and an OSD down, a `pg_num` split in progress, a never-up OSD.
- Images: one per profile row (`0x01`, `0x21`, `0x05`, `0x25`, `0x3D`, `0x45`, striped, data-pool, clone, snapshot, migration prepare), see `rbd-format2.md` T14.
- Keys: client keys of both types (type 1 needs an upgraded-style or hand-made key, `cephx.md` 5 item 1); a read-only profile user and a pool-limited user.
- Secure and crc modes toggled with `ms_mon_service_mode` / `ms_service_mode` (restart needed, `msgr2-secure-mode.md` 2.9).
- The notes do not say whether `require_osd_release` can be lowered once raised **[unverified]**; plan on it only going up: capture reef-level maps (osdmap T2) before raising it to tentacle, or use a second cluster.

**Group 0: computed offline, no cluster**

- CRC-32C values and frame-size tables (`msgr2.md` 5.1), secure-mode primitive and worked-frame vectors with a synthetic secret (`msgr2-secure-mode.md` 5.1, 5.2), cephx known-answer vectors from RFC 8009 and the worked challenge-proof example (`cephx.md` 2.8, 5), `rjenkins`, CRUSH hash, `stable_mod`, placement-seed and `crush_ln` spot values (`crush-and-placement.md` 5.1), the 28-byte MMonSubscribe example (`mon-client.md` 5), the 217-byte MOSDOp example (`osd-ops.md` 5.1), the 42-byte `lock lock` input and the striping examples (`rbd-format2.md` 2.7, 2.10).
- Producer: our own scratch code, written from the notes, plus the pinned reference C files compiled in a scratch directory outside the repository for cross-checks. Output committed: inputs and expected values only.

**Group 1: oracle tool output, no packet capture**

- `ceph osd getmap`, `ceph osd getcrushmap`, `ceph osd crush show-tunables`, `ceph osd dump -f json`, `ceph mon dump -f json`, `ceph osd map <pool> <obj>`, `ceph osd crush rule dump`, `ceph osd stat`.
- `osdmaptool --print`, `--test-map-object`, `--test-map-pgs-dump-all`, `--test-map-pg`; `crushtool -d` and `crushtool --test --show-mappings` (mapping lines go to standard output, `crush-and-placement.md` 5.3 C2).
- `ceph-dencoder` for OSDMap, Incremental, MOSDOp, MOSDOpReply, `pg_t`, `hobject_t`, `SnapContext` and others registered there (`osd-ops.md` 5.2; `osdmap.md` T3).
- `ceph-monstore-tool ... get osdmap` for raw stored epochs (`osdmap.md` T1).
- `rbd info`, `rbd lock ls`, `rados get rbd_id.<name>`, `rados listomapvals rbd_directory` and `rbd_header.<id>`, `rados exec rbd_header.<id> rbd get_size|get_features|get_object_prefix|get_flags|get_snapcontext|get_data_pool|get_stripe_unit_count|parent_get|op_features_get`, `rados exec ... lock get_info`, `rados listsnaps`, `rados listwatchers` (`rbd-format2.md` T1 to T16).
- Covers: osdmap T1, T3, T5, T6, T10; crush C1 to C6, C8, C9; rbd T1 to T4, T6 to T16.

**Group 2: packet capture of a stock client in crc mode**

- Run: lab client with `ms_client_mode = crc` **and** `ms_mon_client_mode = crc` (the monitor-facing list is separate and defaults to secure), `tcpdump -w` on the client NIC, plus `debug_ms` and `debug_auth 10` logs on the client. Commands: `ceph mon dump`, `ceph osd getmap`, `rados put/get`, `rbd info`, `rbd bench --io-type read|write`, a read of a missing object, a CALL read and a CALL write, OMAPGETVALS paging over 1024 keys.
- Produces: banners, HELLO, AUTH exchanges with the two key types, AUTH_DONE with its encrypted blobs, both AUTH_SIGNATURE frames, CLIENT_IDENT / SERVER_IDENT, MMonGetMap / MMonMap (count them), MMonSubscribe, MOSDMap, MOSDOp / MOSDOpReply, keepalive pairs after 60 s idle.
- Covers: msgr2 5.2; cephx 5 items 4 to 7; mon-client T1, T2, T5, T6, T7, T9, T10, T11, T13; osdmap T3, T4; osd-ops 5.2 items 1 to 5; rbd T5, T17 to T20.
- Offline decoding needs the keyring key and the `debug_auth` log (it prints session keys and validity); these stay in the private lab store, see scrubbing below.

**Group 3: secure mode**

- Default configuration (a stock client is secure toward monitors, crc toward OSDs), then both forced secure. Capture the 96-byte first parts of the AUTH_SIGNATURE frames and one data frame. Negative tests from `msgr2-secure-mode.md` 5.3: flipped bit in preamble ciphertext, tag and data; repeated nonce; swapped seeds; crc-only against a secure-only cluster (expect AUTH_BAD_METHOD with allowed modes `[2]`).
- Covers: secure 5.3 items 1 to 6.

**Group 4: fault injection and policy captures**

- Monitor restart (mon-client T12); OSD kill with a write in flight (osd-ops 5.2 item 6); backoff with `osd_backoff_on_peering` (item 7); op to a non-primary (item 8); stale snapshot context with and without ORDERSNAP (item 9); short ticket TTL for renewal and reclaim with the old ticket (cephx 5 item 8, mon-client T14, T15); wrong key, key type not allowed, crc disallowed, missing MSG_ADDR2 (cephx 5 item 9, msgr2 5.2); read-only and pool-limited capabilities (mon-client T8, rbd T16); full pool with and without FULL_TRY (osd-ops Q7); `pg_num` split with lagging `pgp_num` (crush C9); IPv6 monitor address vector (mon-client T4); foreign-tag lock behaviour of stock tools (rbd T15).
- Never run on a shared cluster: an op with a wrong client incarnation (asserts the OSD, `osd-ops.md` 5.2 item 10).

**Group 5: our own client in the loop (harness, once it exists)**

- Reduced advertised masks: map and CRUSH versions received and whether the CRC matches (osdmap T2, T8; crush C7); `osdmaptool` differential for every PG of every used pool (crush C3); byte-compare against Linux krbd on the same image (roadmap Phase 1); decoder fuzzing inputs seeded from groups 1 and 2.

**Scrubbing and what may be committed (CONTRIBUTING rule 4)**

1. Raw packet captures, keyrings, `debug_auth` logs and anything containing a session key, ticket, authorizer, connection secret or key base64 never enter the repository, even from a throw-away cluster. They stay in private lab storage.
2. What may be committed: (a) Group 0 inputs and expected values computed with synthetic keys (for example the `00 01 02 ...` pattern used in the notes); (b) oracle output from group 1, which contains no secrets but does contain the cluster fsid, addresses and pool names: use a lab cluster on private addresses, treat its fsid as non-sensitive, and review before commit; (c) frame dumps from groups 2 to 4 as annotated hex with every secret-bearing field (ticket blobs, encrypted envelopes, authorizers, signatures, connection secret) replaced by a labelled placeholder of the same length, and a header line saying which integrity fields (CRC, HMAC, tag) are therefore no longer valid.
3. A vector that needs real integrity values (a CRC or HMAC over a secret-bearing frame) is committed only as the pair "synthetic input, expected output" that our own code computed and that was cross-checked against the private capture; the private capture itself decides pass or fail and the result is recorded as a sentence in the note.
4. Before any commit that contains capture-derived text: run a scrub check that fails on a keyring `key =` line, on a base64 string of cephx key length, on 16 or 32 byte hex runs that are not in the allow-list of synthetic test values, and on any address outside the lab range. The scrub check itself does not exist yet and is part of the harness work.
5. Never capture traffic of a cluster you do not own.

### 7 Consolidated open questions

Deduplicated; each points to the owning note and question number. `[c]` = confirm on capture, `[u]` = unverified in source. The ten that block the most work are marked **Top 10** and listed in order of how much they gate.

**Transport and handshake**

- **Top 1. A1 [c] Compression skip.** Does a v20.2.5 daemon accept a client whose banner has REVISION_1 but not COMPRESSION, going straight to CLIENT_IDENT? Source says yes. Fallback: advertise `0x3` and send COMPRESSION_REQUEST with `is_compress = false` (that handler was not read [u]). msgr2 Q4; msgr2-secure-mode Q5.
- **Top 2. A2 [c] Feature mask.** Is `0x3f07fffffffdffff` accepted unchanged by monitors and OSDs, is it exactly what a stock client sends, and what changes in the received encodings with a reduced mask (including what an OSD requires of a client for a given map)? msgr2 Q9; osdmap Q1, Q14; mon-client Q1; rbd-format2 Q15; crush C7.
- **Top 3. A3 [c] Pre-auth signature.** Exact bytes covered (banner, HELLO, epilogues), key bytes for mon versus OSD connections, behaviour across an AUTH_BAD_METHOD retry on one TCP connection. msgr2 Q3; cephx Q2; msgr2-secure-mode Q1, Q2.
- A4 [c][u] Alignment values to send (especially from a 32-bit build), non-zero `data_off` / `data_pre_padding_len` handling. msgr2 Q1, Q7; msgr2-secure-mode Q3.
- A5 [c] HELLO `peer_addr` and `target_addr` bytes for a mon and an OSD; whether the mon nonce must be verified. msgr2 Q2; mon-client Q12.
- A6 [u] Keepalive cadence toward OSDs and whether a client KEEPALIVE2 resets the server's idle timer. msgr2 Q5; mon-client T13.
- A7 [c][u] AUTH_BAD_METHOD result codes beyond -EOPNOTSUPP and -EACCES; whether any daemon ever answers a client ident with a non-lossy session. msgr2 Q6, Q8; msgr2-secure-mode Q4; cephx Q9.
- A8 Safe upper bounds for segment and message sizes in a bounded-memory client. msgr2-secure-mode Q10; mon-client Q9.

**Authentication**

- **Top 4. B1 [c] cephx first contact.** A request mask of only OSD plus AUTH (`0x24`) is accepted; key type 2 works end to end on a fresh cluster; the challenge proof for both key types matches the worked examples. cephx Q1, Q3; section 5 item 4.
- **Top 7. B2 [u] Identity across reconnects.** Does the OSD tie resent-op identity to the global id, and can an unacknowledged write be resent after re-authentication with a new global id? What happens to open OSD sessions when the monitor returns a different global id. cephx Q4; osd-ops Q5; mon-client Q18.
- B3 [u] In-session renewal of the AUTH ticket, an OSD connection outliving its ticket, an expired old ticket on reconnect. cephx Q5, Q6; mon-client Q4, Q5.
- B4 [u] Availability and streaming behaviour of SHA-384, a CTS construction and multi-buffer AES-GCM in iPXE and in the Windows driver. cephx Q9; msgr2-secure-mode Q8.

**Monitor client and OSDMap**

- C1 [c][u] Two MMonMap messages on a fresh session; nothing unsolicited after the handshake; whether a plain client may send MMonGetOSDMap. mon-client Q3, Q8, Q17.
- **Top 8. C2 [c] Wire details of addresses and containers.** IPv4 and IPv6 sockaddr byte layouts including flow info and scope id, v2-before-v1 order in address vectors, sorted wire order of maps and sets, denc container equivalence. osdmap Q8, Q11, Q12; mon-client Q15, Q16; msgr2 Q13.
- C3 [c] Map CRC is `0xFFFFFFFF`-seeded with no final inversion; whether a client may skip verifying incrementals and recover by re-fetching a full map. osdmap Q3, Q4; mon-client Q10.
- C4 [u] Lowest `require_osd_release` that a v20.2.5 monitor still serves. osdmap Q2.
- **Top 9. C5 Memory ceilings.** Largest realistic MOSDMap, OSDMap and CRUSH blob against the 4 MiB iPXE heap and the Windows non-paged pool; need for a streaming decoder; zero-copy data in secure mode. osdmap Q10; mon-client Q9; msgr2-secure-mode Q9.
- C6 Hostname resolution in iPXE and the driver (v1 assumes literal addresses). mon-client Q7.

**Placement**

- **Top 10. D1 [u] CRUSH runs.** `choose_args` weight sets (position semantics, pool-id versus default set), upmap-primary, primary-affinity rotation, MSR / QUINCY fields in the embedded blob, device-class rules: read from source, never run. Companion licensing question L1. crush Q4 to Q6, Q13; C5 to C9.
- D2 Legacy bucket algorithms (`uniform`, `list`, `tree`, `straw`) and odd `allowed_bucket_algs` bytes. crush Q3, Q14, Q15.

**OSD operations**

- E1 [c] MOSDOp segment placement, a zero `features` field, echoed op record for ZERO to TRUNCATE rewrite, ENOSPC as message result versus per-op result. osd-ops Q1, Q2, Q10, Q14.
- **Top 6 (with F2). E2 Unanswered operations.** What a boot-time driver does when an op gets no reply (timer resend with the same tid, reconnect, or fail the I/O); behaviour of a pool that is full without FULL_TRY (silent drop). osd-ops Q6, Q7.
- E3 [u][c] Sparse-read sanity bounds and zero-length behaviour; backoff range comparison and priority; whether OSD-pushed MOSDMap messages may be ignored. osd-ops Q4, Q9, Q13, Q15, Q16.

**RBD**

- **Top 5. F1 [c] Exclusive lock.** Lock policy L2 (lock under a foreign tag) is inferred from librbd, not observed; the lock does not survive the iPXE to Windows handoff (different session); what stock tools and Linux krbd do when a foreign lock is held. rbd-format2 Q2, Q3; T15.
- **Top 6 (with E2). F2 Header changes while attached.** No header watch means no notice of new snapshots or resizes; a stale snapshot context silently loses snapshot data; polling interval undecided. rbd-format2 Q1; osd-ops Q8, Q12.
- F3 [c][u] Multi-op reply semantics when an op fails, six-op request versus librbd's five, holes and zero-length writes, atomicity of the multi-op header read. rbd-format2 Q4, Q5, Q13, Q16, Q17.
- F4 [u] Trash and rename, namespaces, erasure data pools, reader and object-map flags, allocation hint, image size changes, whether RBD forbids pool-snapshot pools. rbd-format2 Q6 to Q11, Q14.

**Cross-release**

- G1 Reef 18 and Squid 19 daemons: not researched anywhere (section 1). msgr2 Q10; msgr2-secure-mode Q11; osd-ops Q3; rbd-format2 Q12; osdmap Q15; crush Q1 (table stability across releases).

The ten marked Top are, in order: 1 compression skip (A1), 2 feature mask (A2), 3 pre-auth signature (A3), 4 cephx first contact (B1), 5 exclusive lock (F1), 6 unanswered ops and stale snapshot context (E2, F2), 7 identity across reconnects (B2), 8 address and container wire details (C2), 9 memory ceilings (C5), 10 CRUSH runs (D1).

### 8 Licensing questions

None of these is decided. They need the project owner and, where noted, the Ceph maintainers or counsel. `LICENSE` already records that per-file headers of the Ceph files read were only partly audited.

- **L1. CRUSH `crush_ln` tables (`crush-and-placement.md` 7.1).** `RH_LH` (258 entries) has an exact closed form, so it can be regenerated at build time with integer arithmetic and verified entry for entry. `LL_tbl` (256 entries) has no closed form; a bit-compatible straw2 needs those values. Options: ask for permission to include them under MIT; argue they are functional numeric data; derive them through a documented black-box process (does not obviously avoid the issue); carry that one table in a separate LGPL-2.1 file. Decision needed before `core/` exists. This is the most important licensing item.
- **L2. CRC-32C table (`msgr2.md` 7.1, `osdmap.md` 7.6, `msgr2-secure-mode.md` 7).** The table is determined by the polynomial; the notes give only the generation rule and three spot values. The files that hold the table in the Ceph tree carry third-party BSD-style headers, not the tree's LGPL. Question: is a generated table acceptable for the MIT core (expected yes).
- **L3. Protocol constants taken from LGPL headers.** Field orders, struct versions, tag and message numbers, feature-bit numbers, op codes, flag values, error numbers, method names. Treated as interface facts and written as tables. Sub-questions: may the core reuse Ceph's symbolic names (`CEPH_OSD_OP_*` and the like) as identifiers (`osd-ops.md` 7); some headers are shared with the Linux kernel client and have no per-file entry in Ceph's `COPYING` (`msgr2-secure-mode.md` 7.2); the CRUSH hash source file carries no licence line (`crush-and-placement.md` 7.2).
- **L4. Descriptions detailed enough to reimplement.** The CRUSH firstn / chooseleaf procedure, the OSDMap placement pipeline, the Objecter resend logic, the striping algorithm and the `crush_ln` steps are written as pseudo-steps in our words; some structural resemblance to the source is unavoidable for a bit-exact description. Question: is that a derived work, and should a second author implement from the notes (or from the public docs and worked examples for striping) (`crush-and-placement.md` 7.3; `rbd-format2.md` 7.2; `osd-ops.md` 7).
- **L5. Ceph documentation licence.** `doc/` is CC-BY-SA-3.0. We paraphrase and cite; several worked frame sizes coincide with the doc's examples because the layout fixes them. Confirm this is acceptable for an MIT repository, or drop the cross-reference column (`msgr2-secure-mode.md` 7.1). The licence of `docs/` in this repository is itself undecided (`LICENSE`).
- **L6. Public-domain items.** The string hash, `ceph_stable_mod` and the CRUSH hash mix are labelled public domain in places; confirm for each before reuse (`crush-and-placement.md` 7.2; `osd-ops.md` 7).
- **L7. Ceph test data.** Do not commit copies of the CRUSH `.t` and `.crushmap` test files, of Ceph's crypto known-answer arrays, or of its CRC unit-test values; take cephx type-2 vectors from RFC 8009, regenerate maps with `crushtool` from our own text, and settle whether quoting three short CRC test constants is acceptable (`cephx.md` 7; `crush-and-placement.md` 7.4; `msgr2-secure-mode.md` 7.4).
- **L8. The cephx constants and the 8-byte envelope magic and 16-byte CBC IV** (`cephx.md` 7): protocol facts, written as hex rather than copied tokens; needs a maintainer decision for the MIT core.
- **L9. Tooling that links Ceph code.** Oracle helpers and cross-check harnesses compiled from Ceph sources stay outside this repository and their output code is never copied in (`crush-and-placement.md` 7.5; `msgr2-secure-mode.md` 7.3). Scratch implementations used for the vectors are not in the repository.
- **L10. Kernel client behaviour** described in `rbd-format2.md` comes only from Ceph's manual page; no kernel code was consulted (`rbd-format2.md` 7.5). Keep it that way.
- **L11. Captures.** Anything captured from a live cluster is subject to the scrubbing rules in section 6 before it can be committed.

---

<a name="zh"></a>

## 中文

这是 [docs/ROADMAP.md](../ROADMAP.md) 里 Phase 0 的协议笔记索引:八篇笔记合起来,逐字节描述一个**最小的 Ceph 客户端**(只做客户端,不做服务端)要在线上发什么,才能在一个固定版本的 Ceph 上打开 RBD 镜像并读写它。目标是:后续实现者只看这些笔记就能写出可移植的 core。

所有笔记共同遵守的规则(见 [CONTRIBUTING.md](../../CONTRIBUTING.md)):

- 用自己的话写;只放布局表、数字常量和协议事实,不抄 Ceph 的代码、注释或查找表数据。
- 每条结论都带 `path:line`(相对于固定 tag 的 Ceph 源码树根)或 Ceph 文档页。
- **[unverified]** = 在源码里没能钉死;**[confirm on capture]** = 源码里读到了,但 core 依赖它之前必须在真实集群上核对。每篇笔记的第 6 节收集这两类,本页第 7 节去重汇总。
- 目前**没有任何一条**经过真实抓包确认。

### 1 固定版本与兼容立场

- **固定版本:Ceph v20.2.5「Tentacle」,commit `ed27c686770872022f4c1de04f6b0ac5d5384ded`。** 参考源码树是与本仓库并列放置的只读检出 `winrbd-ref/ceph-v20.2.5`(不在仓库里,也不是子模块),各笔记的 `path:line` 都相对于它的根目录。
- **为什么选它:** 写作时它是最新的稳定小版本(由项目负责人说明,本轮未对照上游复核)。编码带版本号并由特性位控制,固定最新版就得到最新编码;笔记里仍保留的旧编码,都写成「v20.2.5 守护进程对声明较少特性位的客户端会发什么」。
- **v1 的目标:** `require_osd_release` 为 reef 或更新的 v20.2.5 集群。这是 v20 集群能运行的下限(`osdmap.md` 2.4.2),`osdmap.md` 4.1 的解码下限(全量图客户端块 9 或 10、增量 8 或 9、pool 29 至 32)同时覆盖 reef/squid 级别和 tentacle 级别的图。其他 v20.2.x 小版本预计线上一致,但没看过。
- **Reef 18 与 Squid 19 守护进程不是 v1 目标,也没研究过。** 笔记只记录读到的代码路径里看得见的差异,它们都由特性位或 `require_osd_release` 决定,与守护进程版本字符串无关:MOSDOp 版本 9 需要连接上有 SERVER_SQUID 位,否则是 8;pool 结构版本 32 需要 SERVER_TENTACLE;全量图客户端块 10 / 增量 9 需要 SERVER_REEF;CRUSH blob 仅在特性集含 CRUSH_MSR / SERVER_QUINCY 时带两个额外字段;`lock get_info` 回复里的地址形式取决于请求方的特性位。
- Reef / Squid 守护进程是否接受下面的客户端能力档案,仍是未决问题(第 7 节 G1)。路线图里「固定哪个版本」的问题由本节回答,兼容性问题继续保留。

### 2 拟定的 v1 镜像档案

来源:`rbd-format2.md` 4.2 与 2.8(精确数值;features 指 `get_features` 返回的 `u64`)。只支持 format 2,format 1 一律拒绝。

| 档案 | 用途 | features 规则 | 常见取值 |
|---|---|---|---|
| **P1** | 推荐的读写档案 | `features & ~0xA1 == 0`:只允许 layering `0x01`、deep-flatten `0x20`、data-pool `0x80` | `0x01`、`0x21` |
| **P1-L** | 读写且带 exclusive-lock 位 | `features & ~0xA5 == 0`(P1 加 `0x04`);写入在锁策略 L2 经抓包确认之前一律拒绝,读取允许 | `0x05`、`0x25` |
| **R1** | 只读 | `features & ~0x1FF == 0`;条带位只接受默认布局;忽略 object-map 与 fast-diff | 默认镜像 `0x3D` 可读 |

通用条件:

- 任何用途都拒绝:migrating `0x200`、non-primary `0x400`、dirty-cache `0x800`、未知位、克隆(有 parent)、非默认布局、纠删码数据池、非默认 namespace;写者遇到 `flags != 0` 也拒绝。
- 写者另外拒绝 object-map `0x08`、fast-diff `0x10`、journaling `0x40`、operations `0x100`,以及带 POOL_SNAPS 标志的存储池。
- 默认布局:对象大小 `1 << order`,`order` 取 12..25(默认 22 即 4 MiB),条带单位等于对象大小,条带数 1。
- 允许存在快照;写者在每个写操作里带上镜像当前的快照上下文,自己不创建、不读取快照。没有 header watch 带来的过期风险是未决问题 F2。
- 数据池必须是副本池,可与元数据池不同。
- 元数据只通过类调用(`rbd`、`lock` 类)读取,不直接解析 omap 键;数据对象名为 `<object_prefix>.<16 位十六进制对象号>`。
- 把默认镜像(`0x3D`)变成可写:依次 `rbd feature disable` fast-diff、object-map,可选 exclusive-lock,得到 `0x21`(或 `0x25`);`rbd create --image-format 2 --image-feature layering` 直接得到 `0x01`。
- 锁策略默认值:读者 L0(不加锁);P1 写者 L1(不加锁,两个写者同时映射同一镜像属于运维错误);P1-L 写者在 L2 确认前拒绝。

### 3 客户端能力档案

- 传输:只用 msgr2;banner `ceph v2\n`,supported `0x1`(REVISION_1),required `0`;revision 1 帧格式;拒绝 v1 messenger 和 revision 0。
- 模式:**先做 crc 模式**(`preferred_modes = [1]`),**secure 模式(AES-128-GCM)以后可选**,另有专门笔记;AUTH_DONE 返回的模式要与所提供的列表核对。
- 压缩:不声明(banner 第 1 位为 0),也不发 COMPRESSION_REQUEST。
- 会话:lossy 客户端会话;HELLO 类型 CLIENT `0x08`;CLIENT_IDENT 标志位 0 置位、cookie 0、拿到 global id 之前 gid 为 -1;没有重连帧;每次故障后新建 TCP 连接并完整认证。
- 特性位:`supported_features = 0x3f07fffffffdffff`(v20.2.5 全集),`required_features = 0x0800000000000000`(MSG_ADDR2)。声明全集才能拿到规范编码;若 OSDMap 要求的位缺失,OSD 会直接拒绝客户端。
- 认证:**只用 cephx**(方法 2),不支持 none 与 GSS;对 mon 的认证模式字节为 10;对 OSD 用 authorizer 加一轮 challenge;双向 AUTH_SIGNATURE(HMAC-SHA256,按字节精确的传输记录计算)。
- 密钥类型:类型 1(AES-128-CBC)和类型 2(AES-256 CTS + HMAC-SHA384)都要实现;全新的 v20.2.5 集群只允许类型 2。
- 票据:请求掩码 `0x24`(OSD 加 AUTH);在有效期 3/4 处续期;同一时刻只保持一个 mon 会话。
- Monitor:`mon_host` 给字面地址;只用 v2 地址;首条消息 MMonGetMap,随后 MMonSubscribe v3 订阅 `monmap` 和持续的 `osdmap`;MOSDMap v4。
- OSDMap:只解码客户端块,OSD 专用块按长度跳过;拒绝纠删码池、分层缓存、stretch、pool-snapshot 模式、EIO 标志。
- 定位:对象名 -> PG -> CRUSH,只做副本池:straw2 的 firstn 与 chooseleaf(旧 straw 建议实现,uniform/list 可选);应用 upmap、primary affinity、pg_temp、primary_temp;拒绝 indep、MSR、tree 桶、EC。
- OSD I/O:MOSDOp 版本 9 / compat 3,MOSDOpReply 版本 8;tid 与重发规则、MOSDBackoff、每个写类消息都带快照上下文。
- 垫片(shim)需要提供:AES-128/256 分组运算(CBC、ECB,CTS 由它们搭出)、HMAC-SHA256、HMAC-SHA384、安全随机数;secure 模式才需要 AES-128-GCM;CRC-32C(原始更新,由多项式生成表)、rjenkins 字符串哈希与 CRUSH 哈希自己写;`crush_ln` 表是许可问题(第 8 节 L1)。
- 限制:凡是从线上读到的长度、个数、向量,都要受配置预算限制;参考实现的帧层没有这些上限。

### 4 笔记一览

八篇都是草稿。「对照源码复核」指:有独立的一轮复核,重新打开所引用的源码行,并重算了能重算的内容,之后又做了本轮的跨笔记检查。「抓包确认」对所有笔记都是**否**。

| 笔记 | 范围 | 状态 | 对照源码复核 | 抓包确认 |
|---|---|---|---|---|
| [msgr2.md](msgr2.md) | msgr2.1 crc 模式客户端:banner、32 字节 preamble、分段、CRC-32C、tag 与控制帧载荷、HELLO、认证帧外壳、CLIENT/SERVER_IDENT、MESSAGE 帧及 41 字节头、`entity_addr_t`、特性位、pre-auth 签名机制 | 草稿 | 是;CRC、帧大小与示例帧已重算;crc 路径把握高,secure 仅为摘要 | 否 |
| [msgr2-secure-mode.md](msgr2-secure-mode.md) | 可选 secure 模式:模式协商默认值、连接密钥切分、AES-128-GCM nonce、secure 2.1 帧布局与长度算术、作为首个加密帧的 pre-auth 签名、拒绝压缩 | 草稿 | 是;密钥/nonce 切分与两个示例帧用独立脚本重现 | 否 |
| [cephx.md](cephx.md) | cephx:密钥与 keyring 格式、两种密码类型、加密信封、票据、challenge 证明、mon 握手、OSD authorizer、过期续期与 global id | 草稿 | 是;两种密码已用上游已知答案向量由独立实现重现 | 否 |
| [mon-client.md](mon-client.md) | monitor 客户端:`mon_host` 解析、MonMap、MMonGetMap/MMonSubscribe、MOSDMap 投递与缺口处理、keepalive、hunting、MAuth 续期、global id | 草稿 | 是;引用已复核 | 否 |
| [osdmap.md](osdmap.md) | OSDMap 与 Incremental 的客户端子集:信封、按特性位选版本、`pg_pool_t`、应用顺序、常量、图 CRC、字段如何用于定位 | 草稿 | 是;字段顺序逐一重读源码 | 否 |
| [crush-and-placement.md](crush-and-placement.md) | 副本池的 对象名 -> PG -> 放置种子 -> CRUSH:哈希、blob 布局、tunables、straw2 与 `crush_ln`、firstn + chooseleaf、upmap、affinity、temp 映射 | 草稿 | 是;哈希与 `crush_ln` 用固定版本的 C 文件重建,按笔记步骤重新实现后匹配了 688 条源码树内的期望映射 | 否 |
| [osd-ops.md](osd-ops.md) | MOSDOp v9、MOSDOpReply v8、MOSDBackoff;38 字节 op 记录;各 op 语义;错误;tid、重发、backoff、池满、快照上下文、顺序 | 草稿 | 是;217 字节示例 MOSDOp 已重算 | 否 |
| [rbd-format2.md](rbd-format2.md) | RBD format 2:对象命名、`rbd` 与 `lock` 类调用、特性位、条带与字节范围映射、稀疏 I/O、exclusive-lock 策略、v1 镜像档案 | 草稿 | 是;条带与锁的示例已重算 | 否 |

建议阅读顺序:msgr2、cephx、mon-client、osdmap、crush-and-placement、osd-ops、rbd-format2;只有要做 secure 模式时才读 msgr2-secure-mode。

### 5 跨笔记一致性

方法:对八篇笔记按章节、并用搜索逐项比对共享事实,各事实的归属章节通读;**不是**对七千行的第二遍逐行通读。修复项引用的源码行已在固定源码树里重新打开;CRC-32C 向量已独立重算。

**处处一致的事实**(详见英文表):固定版本;CRC-32C 参数与三个向量;banner;帧 tag 编号;实体类型;认证方法/模式/密钥类型;连接密钥 64 字节(secure)/ 0(crc),实际使用 40 字节;nonce 方向;pre-auth 签名(HMAC-SHA256,密钥为会话密钥原始字节,各方对收到的字节签名、对发出的字节验证);消息类型号;各消息体版本;特性掩码 `0x3f07fffffffdffff`(清零位 17、51..55、62、63)及各 SERVER_* 掩码;`pg_t` 与种子;op 编码与 38 字节记录;票据时效。

**本轮发现并已修正的不一致**

1. `cephx.md` 把 MAuth/MAuthReply 头写成 version 1 / compat 0;那是类默认值,编码器在 compat 为 0 时会把 version 抄进去(`src/msg/Message.cc:248-251`),线上是 1 / 1,与 `mon-client.md`、`msgr2.md` 一致。已改 `cephx.md`。
2. `msgr2.md` 仍称 AUTH_SIGNATURE 的 cephx 密钥「未核实」,而 `cephx.md` 2.9 与 `msgr2-secure-mode.md` 2.7 已钉死;已改为「源码已确定,仍待抓包核对」。
3. `msgr2.md` 说 `mon_host` 引导规则未读,实际在 `mon-client.md` 3.1;已加指向。
4. `msgr2.md` 说 secure 模式未核对未规范;现由 `msgr2-secure-mode.md` 负责;已加指向,2.6.3 标明只是摘要。
5. pool-snapshot 模式:`osd-ops.md` 与 `rbd-format2.md` 说检测方式未读,而 `osdmap.md` 2.7.2 已列出标志;检测方法是 pool 标志位 14(POOL_SNAPS),已在 `src/osd/osd_types.cc:1717-1720` 核实。已修 `rbd-format2.md`、`osd-ops.md`,并在 `osdmap.md` 4.3 加拒绝行(POOL_SNAPS 与 EIO)。
6. 抓包配方:`osd-ops.md` 5.2 只强制 `ms_client_mode = crc`,但标准客户端到 monitor 的连接用另一个默认 secure 的选项;已改为两个都强制。
7. 特性掩码:`osdmap.md` 与 `mon-client.md` 的 Q1 都把决定推给 msgr2 笔记;现已指向 `msgr2.md` 4.4,并补充了减少特性位可能被直接拒绝的原因(OSD 根据 OSDMap 重新计算对客户端的必需掩码,含 CEPHX_V2 即位 61)。
8. `osdmap.md` Q6(blocklist)写「留给 OSD op 笔记」,`osd-ops.md` 已解决(-108 对会话致命);已加交叉引用。
9. `msgr2.md` 许可项里出现了两个公司名,已改写(文件路径保留)。

**有意保留的差异(不是不一致)**:参考 messenger 取地址向量里第一个类型为 1 或 2 的条目,我们的纯 v2 客户端取第一个类型 2 的条目;参考实现允许 ONETIME osdmap 订阅,最小客户端建议持续订阅;空地址编码时 `elen` 为 28,而解码器接受 0。

**笔记内无法解决、转入第 7 节的**:真实地图是否偏离「有序容器」与 sockaddr 字节布局的假设(需抓包);OSD 是否对某些地图状态要求全集里的额外位(仅源码推断);几百条 `path:line` 引用中,本轮只重新打开了上面列出的那些。

### 6 抓包计划

所有「标准答案」都来自对实验集群运行的官方 Ceph 工具;被测客户端绝不自己当自己的标准。

**实验集群**:全新的 v20.2.5,私有地址的隔离网络,不放任何别的东西。3 个 monitor(v2 + v1),至少 4 个 OSD,可能的话一个 IPv6 monitor;副本池(`pg_num` 为 2 的幂 / 不是 2 的幂如 48)、带 weight-set 的池、设备类规则、纠删码池(只测拒绝)、被配额写满的池;upmap、upmap-items、upmap-primary、primary affinity、pg_temp、OSD out/down、`pg_num` 分裂中、从未 up 过的 OSD;每种镜像档案各一个(`0x01`、`0x21`、`0x05`、`0x25`、`0x3D`、`0x45`、条带、data-pool、克隆、快照、迁移准备);两种类型的客户端密钥;只读与限定池的用户;用 `ms_mon_service_mode` / `ms_service_mode` 切换 crc/secure(需重启)。笔记没有说明 `require_osd_release` 升高后能否降回 **[unverified]**,按只能升高来规划:先抓 reef 级别的图再升到 tentacle,或另建一套集群。

**分组**

- **组 0:离线计算,不需要集群。** CRC-32C 与帧长表、secure 模式用合成密钥的向量、cephx 已知答案(RFC 8009)与 challenge 证明示例、哈希/`stable_mod`/放置种子/`crush_ln` 抽样值、28 字节 MMonSubscribe 示例、217 字节 MOSDOp 示例、`lock lock` 输入与条带示例。产生者:我们按笔记写的临时代码,另用固定版本的 C 文件在仓库之外的临时目录里编译做交叉核对;入库的只有输入与期望值。
- **组 1:工具输出,不抓包。** `ceph osd getmap / getcrushmap / crush show-tunables / osd dump / mon dump / osd map`,`osdmaptool`(`--test-map-object`、`--test-map-pgs-dump-all`),`crushtool --test --show-mappings`,`ceph-dencoder`,`ceph-monstore-tool`,以及 `rbd info`、`rados get/listomapvals/exec`、`rbd lock ls`、`rados listsnaps/listwatchers`。覆盖 osdmap T1/T3/T5/T6/T10、crush C1–C6/C8/C9、rbd T1–T4/T6–T16。
- **组 2:标准客户端 crc 模式抓包。** 客户端同时设 `ms_client_mode = crc` 与 `ms_mon_client_mode = crc`,客户端网卡上 `tcpdump -w`,再加 `debug_ms`、`debug_auth 10` 日志;执行 `ceph mon dump`、`ceph osd getmap`、`rados put/get`、`rbd info`、`rbd bench`、读不存在的对象、CALL 读写、超过 1024 键的 OMAPGETVALS 翻页。离线解码需要 keyring 密钥与 `debug_auth` 日志(其中会打印会话密钥),它们只放私有实验室存储。覆盖 msgr2 5.2、cephx 5(4–7)、mon-client T1/T2/T5–T7/T9–T11/T13、osdmap T3/T4、osd-ops 5.2(1–5)、rbd T5/T17–T20。
- **组 3:secure 模式。** 默认配置(标准客户端对 mon 用 secure,对 OSD 用 crc),再两边都强制 secure;抓 AUTH_SIGNATURE 的 96 字节首段与一个数据帧;做反例:翻转 preamble 密文/tag/数据中的一个位、重复 nonce、交换 seed、仅 crc 的客户端连仅 secure 的集群(应得 AUTH_BAD_METHOD,允许模式 `[2]`)。
- **组 4:故障注入与策略。** monitor 重启、写入途中杀 OSD、backoff、发给非主 OSD、过期快照上下文(带/不带 ORDERSNAP)、缩短票据 TTL 测续期与 old ticket 回收、错误密钥/不允许的密钥类型/crc 被禁/缺 MSG_ADDR2、只读与限定池权限、池满(带/不带 FULL_TRY)、`pg_num` 分裂、IPv6 monitor、外来标签锁的标准工具行为。**禁止**在共享集群上发 client incarnation 错误的操作(会让 OSD 断言)。
- **组 5:我们自己的客户端接入后(harness)。** 减少特性位后收到的版本与 CRC;对用到的每个池的每个 PG 做 `osdmaptool` 差分;与 Linux krbd 做字节对比;用组 1、2 的数据作为解码器模糊测试的种子。

**脱敏与可入库内容(CONTRIBUTING 规则 4)**

1. 原始抓包、keyring、`debug_auth` 日志,以及任何含会话密钥、票据、authorizer、连接密钥、密钥 base64 的东西,即使来自一次性集群也**不进仓库**,留在私有实验室存储。
2. 可入库:(a) 组 0 用合成密钥(如笔记里的 `00 01 02 ...`)算出的输入与期望值;(b) 组 1 的工具输出(不含密钥,但含 fsid、地址、池名,实验集群用私有地址,入库前人工检查);(c) 组 2–4 的帧转储,写成带注释的十六进制,所有含密钥的字段(票据 blob、加密信封、authorizer、签名、连接密钥)用同长度的占位符替换,并在头部注明哪些完整性字段(CRC、HMAC、tag)因此已不再有效。
3. 需要真实完整性值的向量,只入库「合成输入 + 我们自己代码算出并与私有抓包交叉核对过的期望输出」;私有抓包本身决定通过与否,结果以一句话记在笔记里。
4. 含抓包衍生文本的提交之前必须跑脱敏检查:命中 keyring 的 `key =` 行、cephx 密钥长度的 base64 串、不在合成值白名单内的 16/32 字节十六进制串、实验室范围之外的地址就失败。该检查目前还不存在,属于 harness 的工作。
5. 绝不抓不属于自己的集群的流量。

### 7 汇总的未决问题

已去重,每条指向所属笔记与问题号。`[c]` = 待抓包确认,`[u]` = 源码未核实。**Top 10** 按「卡住多少后续工作」排序:

1. **压缩跳过(A1)。** 只带 REVISION_1、不带 COMPRESSION 的 banner,v20.2.5 守护进程是否直接进入 CLIENT_IDENT?源码说可以。备选:声明 `0x3` 并发 `is_compress = false` 的 COMPRESSION_REQUEST(该处理函数未读)。msgr2 Q4;secure Q5。
2. **特性掩码(A2)。** `0x3f07fffffffdffff` 是否被 monitor 和 OSD 原样接受、是否与标准客户端发的完全相同、减少位后收到的编码有何变化。msgr2 Q9;osdmap Q1/Q14;mon-client Q1;rbd Q15;crush C7。
3. **pre-auth 签名(A3)。** 覆盖的确切字节(banner、HELLO、epilogue)、对 mon 与 OSD 连接分别用哪个密钥、同一 TCP 连接上 AUTH_BAD_METHOD 重试后的行为。msgr2 Q3;cephx Q2;secure Q1/Q2。
4. **cephx 首次接触(B1)。** 只请求 OSD+AUTH(`0x24`)是否被接受;类型 2 密钥在全新集群上端到端可用;两种密钥的 challenge 证明与示例一致。cephx Q1/Q3。
5. **exclusive-lock(F1)。** 策略 L2 是从 librbd 推断的、没有观察;锁无法跨 iPXE 到 Windows 的交接(会话不同);外来锁存在时标准工具与 Linux krbd 的行为。rbd Q2/Q3;T15。
6. **无应答的操作与过期的快照上下文(E2、F2)。** 启动盘驱动在操作无回复时怎么做(同 tid 定时重发、重连还是让 I/O 失败);池满且无 FULL_TRY 时静默丢弃;没有 header watch 时不知道新快照,过期的快照上下文会悄悄丢快照数据。osd-ops Q6/Q7/Q8/Q12;rbd Q1。
7. **跨重连的身份(B2)。** OSD 是否把重发操作的身份绑定到 global id;以新 global id 重新认证后能否安全重发未确认的写。cephx Q4;osd-ops Q5;mon-client Q18。
8. **地址与容器的线上细节(C2)。** IPv4/IPv6 sockaddr 字节布局(含 flow info 与 scope id)、地址向量里 v2 与 v1 的先后、map/set 的有序线上顺序。osdmap Q8/Q11/Q12;mon-client Q15/Q16;msgr2 Q13。
9. **内存上限(C5)。** 最大的真实 MOSDMap/OSDMap/CRUSH blob 与 iPXE 4 MiB 堆、Windows 非分页池的关系;是否需要流式解码;secure 模式下的零拷贝。osdmap Q10;mon-client Q9;secure Q9。
10. **CRUSH 实跑(D1)。** `choose_args`/weight-set 的位置语义、upmap-primary、primary affinity 轮转、嵌入 blob 里的 MSR/QUINCY 字段、设备类规则:只读过源码,没跑过;与许可问题 L1 配套。crush Q4–Q6/Q13。

其余问题(传输与握手 A4–A8、认证 B3–B4、monitor 与 OSDMap C1/C3/C4/C6、旧桶算法 D2、OSD 操作 E1/E3、RBD F3/F4、跨版本 G1:Reef 18 / Squid 19 完全没研究)见英文第 7 节及各笔记第 6 节。

### 8 许可问题

以下都未决定,需要项目负责人,必要时还要 Ceph 维护者或律师。

- **L1(最重要)。CRUSH 的 `crush_ln` 表。** `RH_LH`(258 项)有精确的闭式,可在构建时用整数运算重新生成并逐项校验;`LL_tbl`(256 项)没有闭式,要与 Ceph 逐位兼容就必须有这些值。可选:请求许可以 MIT 收录;主张其为功能性数值数据;经文档化的黑盒过程取得(未必能回避问题);把这一张表放进单独的 LGPL-2.1 文件。必须在 `core/` 出现之前决定。
- **L2。CRC-32C 表。** 表由多项式唯一确定,笔记只给生成规则和三个抽样值;Ceph 树里放这张表的文件带第三方 BSD 风格文件头,不是树里通用的 LGPL。问题:自动生成的表对 MIT 的 core 是否可接受(预期可以)。
- **L3。取自 LGPL 头文件的协议常量。** 字段顺序、结构版本、tag/消息号、特性位号、op 编码、标志值、错误号、方法名,按接口事实写成表;子问题:core 能否沿用 `CEPH_OSD_OP_*` 之类符号名作标识符;部分头文件与 Linux 内核客户端共享,Ceph 的 `COPYING` 没有逐文件条目;CRUSH 哈希源文件没有许可行。
- **L4。详细到可复现的描述。** CRUSH firstn/chooseleaf、OSDMap 定位流程、Objecter 重发逻辑、条带算法、`crush_ln` 步骤都写成了自己措辞的伪步骤,逐位精确的描述不可避免与源码结构相似。问题:这算不算衍生作品,是否需要由第二位作者只看笔记(条带则只看公开文档和示例)来实现。
- **L5。Ceph 文档许可。** `doc/` 是 CC-BY-SA-3.0;我们改写并引用,几个帧长示例因布局固定而与文档示例一致。确认对 MIT 仓库是否可接受,否则去掉交叉引用列。本仓库 `docs/` 自己的许可也还没定(见 `LICENSE`)。
- **L6。公有领域项。** 字符串哈希、`ceph_stable_mod`、CRUSH 哈希混合在个别位置标注为公有领域,复用前逐项确认。
- **L7。Ceph 测试数据。** 不要入库 CRUSH 的 `.t`/`.crushmap` 测试文件、Ceph 密码学已知答案数组、CRC 单测数值;cephx 类型 2 的向量取自 RFC 8009,地图用我们自己的文本经 `crushtool` 重新生成;引用三个短 CRC 测试常量是否可行也要定。
- **L8。cephx 常量、8 字节信封魔数、16 字节 CBC IV** 属协议事实,以十六进制写出而非拷贝源码记号,需要维护者对 MIT core 做出判断。
- **L9。链接 Ceph 代码的工具。** 由 Ceph 源码编出的标准答案辅助程序与交叉核对程序留在仓库之外,其输出代码绝不拷入;生成向量用的临时实现不在仓库里。
- **L10。内核客户端行为** 只来自 Ceph 手册页,没有参考内核代码,请保持。
- **L11。抓包数据** 必须先按第 6 节的脱敏规则处理才能入库。
