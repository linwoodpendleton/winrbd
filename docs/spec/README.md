# winrbd protocol spec notes (Phase 0)

[English](#en) | [中文](#zh)

---

<a name="en"></a>

## English

These are the Phase 0 protocol notes from [docs/ROADMAP.md](../ROADMAP.md): eight notes that together describe, byte for byte, what a **minimal Ceph client** (never a server) has to put on the wire to open an RBD image on one pinned Ceph release and read and write it. A later implementer should be able to write the portable core from these notes alone.

Ground rules for every note (see [CONTRIBUTING.md](../../CONTRIBUTING.md)):

- Written in our own words. Layout tables, numeric constants and protocol facts only; no Ceph code, comments or lookup data.
- Every claim carries a `path:line` reference relative to the Ceph tree root at the pinned tag, or a Ceph doc page.
- **[unverified]** = could not be pinned in source. **[confirm on capture]** = read from source but must be checked on a live cluster before the core relies on it. Both kinds are collected in section 6 of each note and, deduplicated, in section 7 below. **[confirmed: <checker / capture>]** = settled by the capture round of 2026-11-16 (the check ids and capture names are the ones printed by the checkers in `harness/tools/`).
- Status after the capture round (2026-11-16): all eight notes were checked against 39 packet captures and `ceph` / `rbd` / `crushtool` / `osdmaptool` output from a lab cluster, by checkers written from the notes alone (section 4). Where the capture disagreed with the source reading, the note was corrected in place and the change is listed under "Corrections after capture" in its section 6. Items the capture could not settle keep their mark and a reason.

Contents of this page: 1 pinned release and compatibility stance; 2 the proposed v1 image profile; 3 the client capability profile; 4 table of notes and Phase 0 exit status (4.1); 5 cross-note consistency; 6 capture plan; 7 consolidated open questions; 8 licensing questions.

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

Status vocabulary: **draft** = written from source only; **reviewed against source** = one independent pass re-opened the cited lines in the pinned tree and recomputed what could be recomputed, followed by the cross-note pass of section 5; **confirmed on capture** = an independent checker, written from the note alone (no Ceph decoder in the loop), parsed the 39 pcaps and the tool output, and the note was corrected where it disagreed. All eight notes are now **confirmed on capture, with open marks remaining**; the last column gives the checker, its result and the marks left. "Open" counts the `[unverified]` (u) and `[confirm on capture]` (c) marks still in the text; "confirmed" counts the `[confirmed: ...]` marks (grep below the note header, so a mark repeated in a correction list counts again: read the numbers as approximate). All eight checkers exit 0 against the capture set; how to run them is in [harness/tools/README.md](../../harness/tools/README.md).

| Note | Scope | Status | Reviewed against source | Confirmed on capture (checker, result, open marks) |
|---|---|---|---|---|
| [msgr2.md](msgr2.md) | msgr2.1 crc-mode client: banner, 32-byte preamble, segments, CRC-32C, tags and control-frame payloads, HELLO, auth frame shells, CLIENT_IDENT / SERVER_IDENT, the MESSAGE frame and 41-byte header, `entity_addr_t`, feature bits, pre-auth signature mechanics | confirmed on capture | yes; CRC, frame-size and worked-frame vectors recomputed; crc path high confidence, secure summary only | yes: `msgr2_check.py`, 177,628 checks, 0 failed (74 check ids, 39 pcaps), plus the live probe `msgr2_probe.py`; 5 corrections; open 15 u / 2 c; 36 confirmed |
| [msgr2-secure-mode.md](msgr2-secure-mode.md) | optional secure mode: mode negotiation defaults, connection-secret slicing, AES-128-GCM nonce layout, secure 2.1 frame layout and size arithmetic, the pre-auth signature as first encrypted frame, declining compression | confirmed on capture | yes; key/nonce slicing and two worked frames reproduced with separate scripts | yes: `secure_check.py`, 151,305 checks, 0 failed (80 secure connections, 880 secure frames, 1,390 GCM operations); 3 corrections; open 3 u / 6 c; 9 confirmed |
| [cephx.md](cephx.md) | cephx: key and keyring format, cipher types 1 and 2, encrypted envelope, tickets, challenge proof, monitor handshake, OSD authorizer, expiry, renewal and global id | confirmed on capture | yes; both ciphers reproduced against the upstream known-answer vectors by an independent implementation | yes: `cephx_check.py`, 84,714 checks on the captures and 954 on the vectors, 0 failed (499 handshakes, both key types); 5 corrections; open 4 u / 1 c; 14 confirmed |
| [mon-client.md](mon-client.md) | monitor client: `mon_host` parsing, MonMap, MMonGetMap and MMonSubscribe, MOSDMap delivery and gap handling, keepalive, hunting, MAuth renewal, global id | confirmed on capture | yes; references re-checked | yes: `monclient_check.py`, 64,830 assertions in 206 named checks, 0 failed; 6 corrections; open 13 u / 10 c; 36 confirmed |
| [osdmap.md](osdmap.md) | OSDMap and Incremental, client subset: envelopes, versions chosen by feature bits, `pg_pool_t`, apply order, constants, map CRC, how the fields feed placement | confirmed on capture | yes; every field order re-read in source | yes: `osdmap_check.py`, 119 checks, 0 failed (item level: 178 stored maps and incrementals, 80,000 `crushtool` mappings, 2,194 `ceph osd map` answers, 792 `osdmaptool` PGs over 24 map states); no table needed correcting; open 7 u / 5 c; 14 confirmed |
| [crush-and-placement.md](crush-and-placement.md) | object name to PG to placement seed to CRUSH for replicated pools: hashes, blob layout, tunables, straw2 and `crush_ln`, firstn with chooseleaf, upmap, affinity, temp maps | confirmed on capture | yes; hashes and `crush_ln` rebuilt from the pinned C files, 688 in-tree expected mappings matched by a re-implementation of the note's procedure | yes: `crush_check.py`, 80 checks (636,903 comparisons), 0 failed; 3 corrections; open 11 u / 5 c; 12 confirmed. Variants the lab never had (other bucket types, `choose_args`, upmap-primary, split pools) stay unconfirmed |
| [osd-ops.md](osd-ops.md) | MOSDOp v9, MOSDOpReply v8, MOSDBackoff; 38-byte op record; op semantics; errors; tids, resend, backoff, full pools, snapshot context, ordering | confirmed on capture | yes; the 217-byte worked MOSDOp recomputed | yes: `osdop_check.py`, 119,197 checks, 0 failed (39 sessions, 19 vectors); 8 corrections; open 5 u / 8 c; 23 confirmed |
| [rbd-format2.md](rbd-format2.md) | RBD format 2: object naming, `rbd` and `lock` class calls, feature bits, striping and byte-range mapping, sparse I/O, exclusive-lock policies, the v1 image profile | confirmed on capture | yes; striping and lock examples recomputed | yes: `rbd_check.py`, 6,891 checks, 0 failed, plus extra probe captures for the cases stock runs never reach; 8 corrections; open 7 u / 2 c; 42 confirmed |

Suggested reading order for an implementer: msgr2, cephx, mon-client, osdmap, crush-and-placement, osd-ops, rbd-format2; msgr2-secure-mode only when secure mode is built.

#### 4.1 Phase 0 exit status

Roadmap exit criterion: "Each wire structure the core needs is described in the notes with a source reference and has been confirmed against a capture or `ceph` / `rbd` / `crushtool` output from the test cluster." Status on 2026-11-16, in the reading of this pass (the call is the project owner's):

**Met**

- **The eight notes**, in our own words, each structure with a source reference (sections 4 and 5).
- **Pinned release and v1 image profile written down** (sections 1 and 2): Ceph v20.2.5, profile rows P1 and the refusal list. Images with features `0x01`, `0x05`, `0x21`, `0x25`, `0x3D`, `0x45`, `0x03`, `0x81` and migrating `0x201` behave as `rbd-format2.md` says.
- **Test vectors from captures, scrubbed**: `harness/vectors/` holds eight directories (about 860 KB), each with a README on provenance and scrubbing; cephx session vectors are synthetic. Raw captures, keyrings and logs stay outside the repository.
- **The default path is confirmed byte for byte**: msgr2.1 crc and secure framing (all CRCs, tags, GCM tags), cephx with both key types (challenge, tickets, authorizers, both AUTH_SIGNATURE values, renewal), monitor subscribe and MOSDMap delivery, OSDMap and Incremental decoding with the map CRC rule, placement bit-exact against 2,194 `ceph osd map` answers, 80,000 `crushtool` mappings and `osdmaptool` over 24 stored map states, MOSDOp / MOSDOpReply, `rbd` and `lock` class calls, and striping against real objects.
- **Every checker passes** (section 4 table; re-run in this pass, exit 0).

**Not met, or met only in part**

1. **Lab shape.** One monitor, one manager, three OSDs, IPv4 only, one replicated data pool, OSDMap epochs 1 to 92: smaller than the plan in section 6. Everything that needs more (three-monitor hunting, IPv6 addresses, uniform / list / tree buckets, `choose_args`, upmap-primary, split or non-power-of-two `pg_num`, erasure pools, Reef and Squid daemons) is still read from source only.
2. **Needs our own client** (section 6, group 5): reduced feature masks, a request mask of `0x24`, zero `features` in MOSDOp, a resend with the same tid, non-power-of-two alignment. No stock tool does these.
3. **Fault injection (group 4) done only in part.** Done: monitor restart, short ticket TTL, wrong key, a user without OSD caps, read-only caps, foreign-tag lock behaviour. Not done: OSD kill with a write in flight, backoff, a full pool, stale snapshot context with and without ORDERSNAP.
4. **Capture defects.** `k1-rbd-bench-default` (63 dropped packets) and `k1-sec-rados-big` (4) lost packets on the 9 MiB transfers; the checkers analyse those streams up to the hole and report them as capture defects, not as failures. A re-capture would remove the caveat.
5. **Open marks remain** (table above; deduplicated in section 7). None of them is on the path of a plain read or write against the lab shape; several are policy decisions for Phase 1 (exclusive lock, unanswered ops, header changes while attached).
6. **No repository-wide scrub script yet** (section 6, scrubbing item 4). The vector writers carry their own leak guard (`msgr2_check.py` compares its output with every known key and removes the files on a hit); this pass added manual scans, listed in `harness/tools/README.md`.
7. **Licensing items L1 to L11 (section 8) are undecided**; L1 still gates `core/`.
8. **Text to reconcile.** `crush-and-placement.md` still says the upmap, temp-map and affinity states have no oracle output (its 6 and 7.x), while `osdmap_check.py` compared 24 stored map states, including those, with `osdmaptool` (0 mismatches). The two notes should be aligned in the next editing pass.

In short: the exit criterion holds for the structures a stock client uses on the single-monitor IPv4 default path, which is what Phase 1 needs to start; it does not yet hold for the variants listed above, which are tracked in section 7.


### 5 Cross-note consistency

Method: the shared facts below were compared across all eight notes by section and by searching every note for each fact; the sections that own each fact were read in full. This was not a second line-by-line re-read of 7000 lines. Source lines cited in the fixes were re-opened in the pinned tree; the CRC-32C vectors were recomputed independently.

**Facts that agree everywhere they appear**

| Fact | Value | Where |
|---|---|---|
| Pinned release | v20.2.5, commit `ed27c686...` | every note header |
| CRC-32C | polynomial `0x1EDC6F41` (reflected `0x82F63B78`), raw update, no final inversion; preamble CRC seed 0; rev 1 segment CRC seed `0xFFFFFFFF`; OSDMap map CRC start `0xFFFFFFFF`; vectors `crc("123456789", seed 0xFFFFFFFF) = 0x1CF96D7C`, `crc("foo bar baz", 0) = 4119623852`, `crc("whiz bang boom", 0) = 2360230088` recomputed here | msgr2.md 2.5, 5.1; msgr2-secure-mode.md 2.8, 5.1; osdmap.md 2.4.5 |
| Banner | `ceph v2\n`, payload 16, daemons send supported `0x3`, required 0; a stock client sends `0x3` / 0 and then COMPRESSION_REQUEST; `0x1` also works against monitors (live probe) | msgr2.md 2.2; msgr2-secure-mode.md 2.2 |
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

**Facts that changed in the capture round** (each is corrected in its owning note; listed here because several notes depend on them)

- Stock client banner is `0x3` (REVISION_1 plus COMPRESSION) and it always sends COMPRESSION_REQUEST; the server always answers "no compression". A monitor accepts `0x1` without COMPRESSION_REQUEST, and drops `0x3` without it.
- HELLO addresses of the peers carry type 2 (msgr2); only the client's own address is type 3. SERVER_IDENT also lists a second, type-1 address for the v1 port.
- `ceph_msg_header2.flags` is 3 (COMPLETE | NOCRC) on all 5,680 captured messages; a monitor accepts 0, 1 and 3.
- Servers enforce a required feature mask: monitor and OSD report `0x0c01020042040000` (bits 18, 25, 30, 41, 48, 58, 59) and refuse a client missing any of them. Stock CLIENT_IDENT sends `required` `0x0800000000001000` (OSD, manager, short monitor connections) or `0x0800000000000000` (persistent monitor connection, which also asks for lossless but is answered lossy).
- Stock clients send an empty auth-method list to monitors and managers and `[1]` to OSDs; they open two monitor connections per tool run (request masks `0x20` and `0x35`, each with its own global id; OSD connections use the second one's).
- Priority: monitor-bound client messages 127, OSD-bound 63, monitor replies 196.
- A user with no OSD caps still receives the OSDMap; every OSD connection then fails with AUTH_BAD_METHOD -13 and the stock client retries silently. This is the "hang"; the OSD does not drop ops.
- `MOSDOpReply.data_off` is 0 even for reads at a non-zero offset; 60 pre-execution errors echo the request flags without ACK; librbd's metadata calls add FULL_TRY.
- `lock get_info` after the last locker leaves keeps the lock type and tag; a clone has features `0x1` and op_features 0.


**Differences that are deliberate, not inconsistencies**

- Address choice: the reference messenger connects to the first vector entry of type 1 or 2 (`msgr2.md` 2.8 / `mon-client.md` 2.4.3); our v2-only client takes the first entry of type 2 (`osdmap.md` 4.1, `mon-client.md` 2.4.3). Whether daemons list v2 before v1 is open (C2).
- Subscription: the reference allows ONETIME osdmap subscriptions; `mon-client.md` recommends a continuous one for the minimal client.
- An empty address is encoded with `elen` 28 by every encoder but the decoders of `msgr2.md`, `mon-client.md` and `osdmap.md` accept `elen` 0; the notes agree on both statements.

**Could not be resolved from the notes (carried into section 7)**

- Whether any real map ever deviates from the ordered-container assumption (sorted wire order) and from the sockaddr byte layouts: needs capture (C2).
- Whether the OSD requires, beyond MSG_ADDR2, bits that the full mask contains for some map state: derived from source only (A2).
- The `path:line` references number in the hundreds; each note's reviewer re-opened them, this pass re-opened only the ones listed above.

### 6 Capture plan

**Status of this plan (2026-11-16).** Run against a smaller lab than the one below (one monitor, one manager, three OSDs, IPv4 only, pools `winrbd` replicated size 3 with `pg_num` 32 and `.mgr`; both key types). Group 0 done (vectors with synthetic secrets); group 1 done (stored maps and incrementals for epochs 1 to 89, `ceph osd map` for 2,194 names, `crushtool` for 80,000 inputs, `osdmaptool` over 24 map states, `rbd` / `rados` class-call output); groups 2 and 3 done (39 pcaps: both key types, crc, default and forced-secure, idle keepalive, ticket renewal, wrong key, no OSD caps, read-only caps, monitor restart, a 9 MiB transfer); group 4 partly (see section 4.1); group 5 not started (no client yet). The shape below stays the target for a second round.

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
4. Before any commit that contains capture-derived text: run a scrub check that fails on a keyring `key =` line, on a base64 string of cephx key length, on 16 or 32 byte hex runs that are not in the allow-list of synthetic test values, and on any address outside the lab range. Status: no repository-wide scrub script exists yet; the vector writers carry their own leak guard (for example `msgr2_check.py` compares its output with every key and session key known to the capture set and removes the files on a hit), and the manual scans used before publishing are listed in `harness/tools/README.md`. One script that does all of it remains harness work.
5. Never capture traffic of a cluster you do not own.

### 7 Consolidated open questions

Deduplicated; each points to the owning note and question number. `[c]` = confirm on capture, `[u]` = unverified in source. The A1 to G1 list below is the one from before the capture round (kept so that the ids in the notes still resolve); the status table right after this paragraph says what the capture round settled, and the new Top 10 (below the list) replaces the old ranking.

**Status after the capture round (2026-11-16).** *settled* = nothing left that the note's checker could still settle; *partly* = some settled, the rest is in the note's section 6; *open* = nothing in the captures reaches it.

| Id | Status | What the round showed, and what is left |
|---|---|---|
| A1 | settled for monitors; open for OSDs | Stock client sends banner `0x3` and COMPRESSION_REQUEST. Live probe on the monitor: `0x1` without COMPRESSION_REQUEST works, `0x3` without it is dropped. Not probed on an OSD. |
| A2 | partly | Stock mask `0x3f07fffffffdffff` on all 499 CLIENT_IDENT frames. Servers enforce a required mask (`0x0c01020042040000`; bit 12 optional). Effect of a reduced mask on map encodings and CRCs: needs our own client. |
| A3 | settled | HMAC key = raw session-key secret (16 bytes for type 1, the whole 32 for type 2), banner included; both signatures verified on 499 handshakes. Left: the transcript after an AUTH_BAD_METHOD retry on one connection (the stock client never retries). |
| A4 | partly | Alignments 4, 16 and 4096 accepted; non-zero `data_off` / pre-padding accepted on messages without data. Left: non-power-of-two (not tried: it could crash the only monitor), messages with data, 32-bit builds. |
| A5 | settled | Peer HELLO addresses type 2; monitor nonce 0; synthesised `target_addr` accepted. Left: whether a client must verify the monitor nonce. |
| A6 | partly | Stock client pings the monitor every 10.0 s (first one about 3 s after connect), the server never initiates; no keepalives at all on idle OSD connections. Left: does a client KEEPALIVE2 reset the server's 900 s idle timer. |
| A7 | partly | -13 (wrong key; no OSD caps) and -95 (unknown method or mode) seen; monitor answers lossy even to a lossless intent. Left: other codes, OSD lossless sessions. |
| A8 | open | Bounds for a bounded-memory client. |
| B1 | partly | Challenge proofs reproduced for both key types (245 seen); modern key is type 2 by default. Request mask `0x24` is never sent by stock clients (they send `0x20`, `0x35`, `0x15`): needs our own client. |
| B2 | partly | Reconnect with the old ticket keeps the global id. Left: does the OSD check CLIENT_IDENT's id against the ticket; what happens to open OSD sessions when the id changes. |
| B3 | partly | Service tickets renewed in-session every 45.0 s for a 60 s TTL; an OSD connection outlives its ticket. Left: renewing the 72 h AUTH ticket, expired old ticket on reconnect. |
| B4 | open | Not a wire question: SHA-384, CTS and multi-buffer GCM in iPXE and the driver. |
| C1 | settled | Two MMonMap per fresh session; nothing unsolicited. MMonGetOSDMap / MMonGetVersion never exercised (no stock tool sends them). |
| C2 | partly | IPv4 sockaddr, sorted wire order and v2-before-v1 confirmed. IPv6 and non-Linux family numbers: the lab has neither. |
| C3 | partly | Map and incremental CRC rule confirmed on 89 maps, 89 incrementals and every delivered map. Left: skipping incremental verification and re-fetching: no incrementals ever crossed the wire. |
| C4 | open | The lab only runs tentacle. |
| C5 | open | Observed wire sizes are small (largest: a 246 KB command reply, a 53 KB manager map). Not a ceiling study. |
| C6 | open | Hostname resolution. |
| D1 | partly | Placement bit-exact against `ceph osd map`, `crushtool` and `osdmaptool` (including reweight, affinity, upmap, pg_temp, primary_temp, out and down states). Left: `choose_args`, upmap-primary (needs `require-min-compat-client reef`), device-class variants, split pools, the Linux dcache hash, the local-fallback path (never reached by any run). |
| D2 | open | Only straw and straw2 buckets exist in the lab and in the in-tree maps. |
| E1 | partly | Segment layout, priority 63, features word, omap union, SPARSE_READ offsets confirmed. Left: zero `features`, all-zero omap union, ENOSPC variants. |
| E2 | open | Needs fault injection: OSD kill, backoff, full pool, same-tid resend. |
| E3 | open | Zero-length and multi-extent sparse reads, backoff ranges, ignoring pushed MOSDMap. |
| F1 | partly | Observed with stock tools: writes from a non-holder pass; `snap create` and `resize` fail at once with EROFS; a stock writer polls hundreds of times a second; `rbd bench` against a foreign-tag lock never completes. Left: krbd, the handoff to Windows. |
| F2 | open | Design question (no header watch). |
| F3 | mostly settled | Outputs before a failing op are delivered; FAILOK keeps later ops running; the six-op header request works. Left: atomicity of the multi-op header read. |
| F4 | partly | Q14 resolved (`rbd create` in a pool-snapshot-mode pool is refused with EINVAL). Left: trash, namespaces, erasure data pools, flags `0x100`, `0x400`, `0x800`. |
| G1 | open | No Reef or Squid daemon anywhere. |


**Transport and handshake**

- **A1 [c] Compression skip.** Does a v20.2.5 daemon accept a client whose banner has REVISION_1 but not COMPRESSION, going straight to CLIENT_IDENT? Source says yes. Fallback: advertise `0x3` and send COMPRESSION_REQUEST with `is_compress = false` (that handler was not read [u]). msgr2 Q4; msgr2-secure-mode Q5.
- **A2 [c] Feature mask.** Is `0x3f07fffffffdffff` accepted unchanged by monitors and OSDs, is it exactly what a stock client sends, and what changes in the received encodings with a reduced mask (including what an OSD requires of a client for a given map)? msgr2 Q9; osdmap Q1, Q14; mon-client Q1; rbd-format2 Q15; crush C7.
- **A3 [c] Pre-auth signature.** Exact bytes covered (banner, HELLO, epilogues), key bytes for mon versus OSD connections, behaviour across an AUTH_BAD_METHOD retry on one TCP connection. msgr2 Q3; cephx Q2; msgr2-secure-mode Q1, Q2.
- A4 [c][u] Alignment values to send (especially from a 32-bit build), non-zero `data_off` / `data_pre_padding_len` handling. msgr2 Q1, Q7; msgr2-secure-mode Q3.
- A5 [c] HELLO `peer_addr` and `target_addr` bytes for a mon and an OSD; whether the mon nonce must be verified. msgr2 Q2; mon-client Q12.
- A6 [u] Keepalive cadence toward OSDs and whether a client KEEPALIVE2 resets the server's idle timer. msgr2 Q5; mon-client T13.
- A7 [c][u] AUTH_BAD_METHOD result codes beyond -EOPNOTSUPP and -EACCES; whether any daemon ever answers a client ident with a non-lossy session. msgr2 Q6, Q8; msgr2-secure-mode Q4; cephx Q9.
- A8 Safe upper bounds for segment and message sizes in a bounded-memory client. msgr2-secure-mode Q10; mon-client Q9.

**Authentication**

- **B1 [c] cephx first contact.** A request mask of only OSD plus AUTH (`0x24`) is accepted; key type 2 works end to end on a fresh cluster; the challenge proof for both key types matches the worked examples. cephx Q1, Q3; section 5 item 4.
- **B2 [u] Identity across reconnects.** Does the OSD tie resent-op identity to the global id, and can an unacknowledged write be resent after re-authentication with a new global id? What happens to open OSD sessions when the monitor returns a different global id. cephx Q4; osd-ops Q5; mon-client Q18.
- B3 [u] In-session renewal of the AUTH ticket, an OSD connection outliving its ticket, an expired old ticket on reconnect. cephx Q5, Q6; mon-client Q4, Q5.
- B4 [u] Availability and streaming behaviour of SHA-384, a CTS construction and multi-buffer AES-GCM in iPXE and in the Windows driver. cephx Q9; msgr2-secure-mode Q8.

**Monitor client and OSDMap**

- C1 [c][u] Two MMonMap messages on a fresh session; nothing unsolicited after the handshake; whether a plain client may send MMonGetOSDMap. mon-client Q3, Q8, Q17.
- **C2 [c] Wire details of addresses and containers.** IPv4 and IPv6 sockaddr byte layouts including flow info and scope id, v2-before-v1 order in address vectors, sorted wire order of maps and sets, denc container equivalence. osdmap Q8, Q11, Q12; mon-client Q15, Q16; msgr2 Q13.
- C3 [c] Map CRC is `0xFFFFFFFF`-seeded with no final inversion; whether a client may skip verifying incrementals and recover by re-fetching a full map. osdmap Q3, Q4; mon-client Q10.
- C4 [u] Lowest `require_osd_release` that a v20.2.5 monitor still serves. osdmap Q2.
- **C5 Memory ceilings.** Largest realistic MOSDMap, OSDMap and CRUSH blob against the 4 MiB iPXE heap and the Windows non-paged pool; need for a streaming decoder; zero-copy data in secure mode. osdmap Q10; mon-client Q9; msgr2-secure-mode Q9.
- C6 Hostname resolution in iPXE and the driver (v1 assumes literal addresses). mon-client Q7.

**Placement**

- **D1 [u] CRUSH runs.** `choose_args` weight sets (position semantics, pool-id versus default set), upmap-primary, primary-affinity rotation, MSR / QUINCY fields in the embedded blob, device-class rules: read from source, never run. Companion licensing question L1. crush Q4 to Q6, Q13; C5 to C9.
- D2 Legacy bucket algorithms (`uniform`, `list`, `tree`, `straw`) and odd `allowed_bucket_algs` bytes. crush Q3, Q14, Q15.

**OSD operations**

- E1 [c] MOSDOp segment placement, a zero `features` field, echoed op record for ZERO to TRUNCATE rewrite, ENOSPC as message result versus per-op result. osd-ops Q1, Q2, Q10, Q14.
- **E2 Unanswered operations.** What a boot-time driver does when an op gets no reply (timer resend with the same tid, reconnect, or fail the I/O); behaviour of a pool that is full without FULL_TRY (silent drop). osd-ops Q6, Q7.
- E3 [u][c] Sparse-read sanity bounds and zero-length behaviour; backoff range comparison and priority; whether OSD-pushed MOSDMap messages may be ignored. osd-ops Q4, Q9, Q13, Q15, Q16.

**RBD**

- **F1 [c] Exclusive lock.** Lock policy L2 (lock under a foreign tag) is inferred from librbd, not observed; the lock does not survive the iPXE to Windows handoff (different session); what stock tools and Linux krbd do when a foreign lock is held. rbd-format2 Q2, Q3; T15.
- **F2 Header changes while attached.** No header watch means no notice of new snapshots or resizes; a stale snapshot context silently loses snapshot data; polling interval undecided. rbd-format2 Q1; osd-ops Q8, Q12.
- F3 [c][u] Multi-op reply semantics when an op fails, six-op request versus librbd's five, holes and zero-length writes, atomicity of the multi-op header read. rbd-format2 Q4, Q5, Q13, Q16, Q17.
- F4 [u] Trash and rename, namespaces, erasure data pools, reader and object-map flags, allocation hint, image size changes, whether RBD forbids pool-snapshot pools. rbd-format2 Q6 to Q11, Q14.

**Cross-release**

- G1 Reef 18 and Squid 19 daemons: not researched anywhere (section 1). msgr2 Q10; msgr2-secure-mode Q11; osd-ops Q3; rbd-format2 Q12; osdmap Q15; crush Q1 (table stability across releases).

**New Top 10 (what is still open, in order of how much it gates).** Replaces the ranking in the original list.

1. **Exclusive-lock policy (F1; rbd-format2 Q2, Q3, T15).** The effect of policy L2 on other clients is now observed (see the table). Still open: the choice for our writer, krbd's behaviour with a foreign lock (not run, it could wedge the lab's kernel client), and the loss of the lock across the iPXE to Windows handoff.
2. **Unanswered ops and header changes while attached (E2, F2; osd-ops Q6, Q7, Q8, Q12; rbd-format2 Q1).** Fault injection was never run: OSD kill with a write in flight, backoff, a full pool, stale snapshot context with and without ORDERSNAP, resend with the same tid.
3. **Reduced capability negotiation (A1 on OSDs, A2; msgr2 Q9; osdmap Q1, Q14; crush C7).** What a client with fewer feature bits receives, and the compression skip on an OSD: needs our own client.
4. **cephx edges (B1, B2, B3).** Request mask `0x24`, renewing the 72 h AUTH ticket, an expired old ticket on reconnect, the OSD's check of the global id, a disallowed key type, a crc-only client against a secure-only cluster.
5. **Memory ceilings (C5; osdmap Q10; mon-client Q9; msgr2-secure-mode Q9).** Unchanged: only the lab's small maps were seen.
6. **CRUSH variants never run (D1, D2).** `choose_args`, upmap-primary, uniform / list / tree buckets, device-class rules, split and non-power-of-two `pg_num`, the Linux dcache hash, the local-fallback path.
7. **Multi-monitor, IPv6 and incremental delivery (C2, C3).** Hunting, priority and weight, three-monitor maps, IPv6 sockaddr, a subscription start above 0, incrementals-only MOSDMap, a trimmed start.
8. **Edge-of-spec wire probes on OSDs (A4 to A7).** Non-power-of-two alignment, `data_off` on messages with data, KEEPALIVE2 against the 900 s idle timer, other AUTH_BAD_METHOD codes, lossless sessions, revision-0 secure framing, CRC-32C on non-x86 CPUs.
9. **Other releases (G1, C4).** Reef and Squid daemons; the lowest `require_osd_release` a v20.2.5 monitor still serves.
10. **Op and RBD corner cases (E1, E3, F3, F4).** Zero-length and multi-extent SPARSE_READ, ENOSPC and EDQUOT, redirect and `-EAGAIN`, trash and rename, namespaces, erasure data pools, image flags, WRITESAME and CMPEXT, atomicity of the multi-op header read.

The licensing items in section 8 (L1 first) are independent of these and still gate `core/`.

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
- **[unverified]** = 在源码里没能钉死;**[confirm on capture]** = 源码里读到了,但 core 依赖它之前必须在真实集群上核对。每篇笔记的第 6 节收集这两类,本页第 7 节去重汇总。 **[confirmed: <检查器 / 抓包>]** = 已被 2026-11-16 这轮抓包验证(检查编号与抓包名即 `harness/tools/` 里检查器打印的那些)。
- 抓包轮之后的状态(2026-11-16):八篇笔记都已对照 39 个抓包文件,以及实验集群上 `ceph` / `rbd` / `crushtool` / `osdmaptool` 的输出做过核对,检查器只依据笔记本身编写(见第 4 节)。抓包与源码解读不一致的地方,已在笔记中就地更正,并列在各笔记第 6 节的「Corrections after capture」下;抓包没能确定的条目保留标记并写明原因。

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

状态用语:**草稿** = 只依据源码写成;**对照源码复核** = 另有一轮独立复核,重新打开所引用的源码行并重算了能重算的内容,之后又做了第 5 节的跨笔记检查;**抓包确认** = 由只依据该笔记编写的独立检查器(不使用任何 Ceph 解码器)解析 39 个抓包文件与工具输出,不一致处已改笔记。八篇现在都是**抓包确认,但仍有未决标记**;最后一列给出检查器、结果与剩余标记。「未决」指文中仍有的 `[unverified]`(u)与 `[confirm on capture]`(c)标记数,「已确认」指 `[confirmed: ...]` 标记数(按笔记头部之后用 grep 统计,更正列表里重复出现的标记会重复计数,请当作近似值)。八个检查器对抓包集全部返回 0;运行方法见 [harness/tools/README.md](../../harness/tools/README.md)。

| 笔记 | 范围 | 状态 | 对照源码复核 | 抓包确认(检查器、结果、剩余标记) |
|---|---|---|---|---|
| [msgr2.md](msgr2.md) | msgr2.1 crc 模式客户端:banner、32 字节 preamble、分段、CRC-32C、tag 与控制帧载荷、HELLO、认证帧外壳、CLIENT/SERVER_IDENT、MESSAGE 帧及 41 字节头、`entity_addr_t`、特性位、pre-auth 签名机制 | 抓包确认 | 是;CRC、帧大小与示例帧已重算;crc 路径把握高,secure 仅为摘要 | 是:`msgr2_check.py`,177,628 项检查,0 失败(74 个检查编号,39 个抓包),另有现场探测 `msgr2_probe.py`;更正 5 处;未决 15 u / 2 c;已确认 36 |
| [msgr2-secure-mode.md](msgr2-secure-mode.md) | 可选 secure 模式:模式协商默认值、连接密钥切分、AES-128-GCM nonce、secure 2.1 帧布局与长度算术、作为首个加密帧的 pre-auth 签名、拒绝压缩 | 抓包确认 | 是;密钥/nonce 切分与两个示例帧用独立脚本重现 | 是:`secure_check.py`,151,305 项,0 失败(80 条 secure 连接、880 个 secure 帧、1,390 次 GCM 运算);更正 3 处;未决 3 u / 6 c;已确认 9 |
| [cephx.md](cephx.md) | cephx:密钥与 keyring 格式、两种密码类型、加密信封、票据、challenge 证明、mon 握手、OSD authorizer、过期续期与 global id | 抓包确认 | 是;两种密码已用上游已知答案向量由独立实现重现 | 是:`cephx_check.py`,抓包 84,714 项 + 向量 954 项,0 失败(499 次握手,两种密钥类型);更正 5 处;未决 4 u / 1 c;已确认 14 |
| [mon-client.md](mon-client.md) | monitor 客户端:`mon_host` 解析、MonMap、MMonGetMap/MMonSubscribe、MOSDMap 投递与缺口处理、keepalive、hunting、MAuth 续期、global id | 抓包确认 | 是;引用已复核 | 是:`monclient_check.py`,206 个检查、64,830 条断言,0 失败;更正 6 处;未决 13 u / 10 c;已确认 36 |
| [osdmap.md](osdmap.md) | OSDMap 与 Incremental 的客户端子集:信封、按特性位选版本、`pg_pool_t`、应用顺序、常量、图 CRC、字段如何用于定位 | 抓包确认 | 是;字段顺序逐一重读源码 | 是:`osdmap_check.py`,119 项,0 失败(明细:178 份存档图与增量、80,000 条 `crushtool` 映射、2,194 条 `ceph osd map`、24 种图状态下 792 个 `osdmaptool` PG);表格无需更正;未决 7 u / 5 c;已确认 14 |
| [crush-and-placement.md](crush-and-placement.md) | 副本池的 对象名 -> PG -> 放置种子 -> CRUSH:哈希、blob 布局、tunables、straw2 与 `crush_ln`、firstn + chooseleaf、upmap、affinity、temp 映射 | 抓包确认 | 是;哈希与 `crush_ln` 用固定版本的 C 文件重建,按笔记步骤重新实现后匹配了 688 条源码树内的期望映射 | 是:`crush_check.py`,80 项(636,903 次比较),0 失败;更正 3 处;未决 11 u / 5 c;已确认 12。实验室没有的变体(其他桶类型、`choose_args`、upmap-primary、分裂池)仍未确认 |
| [osd-ops.md](osd-ops.md) | MOSDOp v9、MOSDOpReply v8、MOSDBackoff;38 字节 op 记录;各 op 语义;错误;tid、重发、backoff、池满、快照上下文、顺序 | 抓包确认 | 是;217 字节示例 MOSDOp 已重算 | 是:`osdop_check.py`,119,197 项,0 失败(39 个会话、19 个向量);更正 8 处;未决 5 u / 8 c;已确认 23 |
| [rbd-format2.md](rbd-format2.md) | RBD format 2:对象命名、`rbd` 与 `lock` 类调用、特性位、条带与字节范围映射、稀疏 I/O、exclusive-lock 策略、v1 镜像档案 | 抓包确认 | 是;条带与锁的示例已重算 | 是:`rbd_check.py`,6,891 项,0 失败,另有为标准运行碰不到的情形补抓的探测;更正 8 处;未决 7 u / 2 c;已确认 42 |

建议阅读顺序:msgr2、cephx、mon-client、osdmap、crush-and-placement、osd-ops、rbd-format2;只有要做 secure 模式时才读 msgr2-secure-mode。

#### 4.1 Phase 0 退出状态

路线图的退出标准:「核心需要的每个线上结构,笔记里都有来源引用,并已用测试集群的抓包或 `ceph` / `rbd` / `crushtool` 输出核对过。」2026-11-16 的状态如下(本轮的判断,是否收口由项目负责人决定):

**已满足**

- **八篇笔记**,用自己的话写,每个结构都有来源引用(第 4、5 节)。
- **固定版本与 v1 镜像档案已写明**(第 1、2 节):Ceph v20.2.5、档案 P1 与拒绝清单。特性为 `0x01`、`0x05`、`0x21`、`0x25`、`0x3D`、`0x45`、`0x03`、`0x81` 以及迁移中的 `0x201` 的镜像,行为都与 `rbd-format2.md` 一致。
- **来自抓包的测试向量,已脱敏**:`harness/vectors/` 共八个目录(约 860 KB),各有说明来源与脱敏方式的 README;cephx 的会话向量是合成的。原始抓包、keyring 与日志都留在仓库之外。
- **默认路径逐字节确认**:msgr2.1 的 crc 与 secure 帧(全部 CRC、tag、GCM tag)、两种密钥类型的 cephx(challenge、票据、authorizer、两个 AUTH_SIGNATURE、续期)、monitor 订阅与 MOSDMap 投递、OSDMap 与 Incremental 解码及图 CRC 规则、与 2,194 条 `ceph osd map`、80,000 条 `crushtool` 映射、24 种图状态下 `osdmaptool` 逐位一致的定位、MOSDOp / MOSDOpReply、`rbd` 与 `lock` 类调用、与真实对象一致的条带映射。
- **所有检查器通过**(第 4 节表;本轮重跑,退出码均为 0)。

**未满足或只满足一部分**

1. **实验室规模。** 1 个 monitor、1 个 manager、3 个 OSD、仅 IPv4、1 个副本数据池、OSDMap 版本 1 到 92:比第 6 节的计划小。需要更多条件的内容(三 monitor 的 hunting、IPv6 地址、uniform / list / tree 桶、`choose_args`、upmap-primary、分裂或非 2 的幂的 `pg_num`、纠删码池、Reef 与 Squid 守护进程)仍然只读过源码。
2. **需要我们自己的客户端**(第 6 节组 5):减少特性位、`0x24` 请求掩码、MOSDOp 的 `features` 为零、同 tid 重发、非 2 的幂的对齐。标准工具做不到这些。
3. **故障注入(组 4)只做了一部分。** 已做:monitor 重启、缩短票据 TTL、错误密钥、没有 OSD 权限的用户、只读权限、外来标签锁的行为。未做:写入途中杀 OSD、backoff、池满、带/不带 ORDERSNAP 的过期快照上下文。
4. **抓包缺陷。** `k1-rbd-bench-default`(丢 63 个包)与 `k1-sec-rados-big`(丢 4 个)在 9 MiB 传输中有丢包;检查器只分析到缺口之前,并把它们记为抓包缺陷而非失败。重新抓一次即可去掉这个说明。
5. **仍有未决标记**(见上表,第 7 节去重)。其中没有一条在「对实验室规模做一次普通读写」的路径上;有几条是 Phase 1 的策略决定(exclusive-lock、无应答的操作、挂载期间的头部变化)。
6. **还没有覆盖整个仓库的脱敏脚本**(第 6 节脱敏第 4 条)。写向量的程序各有自己的泄漏检查(`msgr2_check.py` 会把输出与所有已知密钥比对,命中就删文件);本轮另做了人工扫描,方法写在 `harness/tools/README.md`。
7. **许可问题 L1 到 L11(第 8 节)都未决定**;L1 仍然卡着 `core/`。
8. **需要对齐的文字。** `crush-and-placement.md` 仍写 upmap、temp、affinity 状态没有标准答案输出(其第 6、7.x 节),而 `osdmap_check.py` 已用 `osdmaptool` 对 24 种存档图状态(含这些)做过比对,0 处不一致。下一轮修订时应让两篇一致。

简言之:退出标准对「标准客户端在单 monitor、IPv4 的默认路径上用到的结构」成立,这正是启动 Phase 1 需要的;对上面列出的变体尚不成立,它们记录在第 7 节。


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

**抓包轮中改变的事实**(各自已在所属笔记中更正;列在这里是因为多篇笔记依赖它们)

- 标准客户端的 banner 是 `0x3`(REVISION_1 加 COMPRESSION),并且总会发 COMPRESSION_REQUEST,服务端总回答「不压缩」。monitor 接受不带 COMPRESSION_REQUEST 的 `0x1`,对不带它的 `0x3` 直接断开。
- 对端的 HELLO 地址类型是 2(msgr2);只有客户端自己的地址是类型 3。SERVER_IDENT 还会列出一个给 v1 端口的类型 1 地址。
- `ceph_msg_header2.flags` 在全部 5,680 条抓到的消息里都是 3(COMPLETE | NOCRC);monitor 接受 0、1、3。
- 服务端会强制执行必需特性掩码:monitor 与 OSD 报告 `0x0c01020042040000`(位 18、25、30、41、48、58、59),缺任何一位的客户端都被拒。标准 CLIENT_IDENT 的 `required` 是 `0x0800000000001000`(OSD、manager、短连接 monitor)或 `0x0800000000000000`(常驻 monitor 连接;它还要求 lossless,但被回答为 lossy)。
- 标准客户端对 monitor 与 manager 发空的认证方法列表,对 OSD 发 `[1]`;每次运行工具会开两条 monitor 连接(请求掩码 `0x20` 与 `0x35`,各有自己的 global id;OSD 连接用第二条的)。
- 优先级:发往 monitor 的客户端消息 127,发往 OSD 的 63,monitor 的回复 196。
- 没有 OSD 权限的用户仍能收到 OSDMap;之后每条 OSD 连接都以 AUTH_BAD_METHOD -13 失败,标准客户端静默重试。「挂住」就是这个,不是 OSD 丢弃操作。
- `MOSDOpReply.data_off` 即使对非零偏移的读也是 0;60 个执行前的错误回显请求标志但没有 ACK;librbd 的元数据调用会加 FULL_TRY。
- 最后一个持锁者离开后 `lock get_info` 仍保留锁类型与 tag;克隆镜像的特性是 `0x1`、op_features 为 0。


**有意保留的差异(不是不一致)**:参考 messenger 取地址向量里第一个类型为 1 或 2 的条目,我们的纯 v2 客户端取第一个类型 2 的条目;参考实现允许 ONETIME osdmap 订阅,最小客户端建议持续订阅;空地址编码时 `elen` 为 28,而解码器接受 0。

**笔记内无法解决、转入第 7 节的**:真实地图是否偏离「有序容器」与 sockaddr 字节布局的假设(需抓包);OSD 是否对某些地图状态要求全集里的额外位(仅源码推断);几百条 `path:line` 引用中,本轮只重新打开了上面列出的那些。

### 6 抓包计划

**本计划的当前状态(2026-11-16)。** 实际用的实验室比下面写的小(1 个 monitor、1 个 manager、3 个 OSD、仅 IPv4;池 `winrbd` 为副本数 3、`pg_num` 32,另有 `.mgr`;两种密钥类型都有)。组 0 已完成(合成密钥的向量);组 1 已完成(版本 1 到 89 的存档图与增量、2,194 个名字的 `ceph osd map`、80,000 个输入的 `crushtool`、24 种图状态的 `osdmaptool`、`rbd` / `rados` 类调用输出);组 2、3 已完成(39 个抓包:两种密钥类型,crc、默认与强制 secure,空闲 keepalive,票据续期,错误密钥,无 OSD 权限,只读权限,monitor 重启,9 MiB 传输);组 4 完成一部分(见第 4.1 节);组 5 未开始(还没有客户端)。下面的规模仍是第二轮的目标。

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
4. 含抓包衍生文本的提交之前必须跑脱敏检查:命中 keyring 的 `key =` 行、cephx 密钥长度的 base64 串、不在合成值白名单内的 16/32 字节十六进制串、实验室范围之外的地址就失败。现状:还没有覆盖整个仓库的脱敏脚本;写向量的程序各有自己的泄漏检查(例如 `msgr2_check.py` 会把输出与抓包集里所有已知的密钥与会话密钥比对,命中就删文件),发布前用的人工扫描写在 `harness/tools/README.md`。把这些合成一个脚本仍是 harness 的工作。
5. 绝不抓不属于自己的集群的流量。

### 7 汇总的未决问题

已去重,每条指向所属笔记与问题号。`[c]` = 待抓包确认,`[u]` = 源码未核实。英文第 7 节保留了抓包轮之前的 A1 到 G1 列表(笔记里的编号仍要能对上),下表给出这一轮的结果,新的 Top 10 取代旧的排序。

**抓包轮之后的状态(2026-11-16)。** *已解决* = 笔记的检查器能确定的都已确定;*部分* = 一部分已确定,其余在该笔记第 6 节;*未决* = 抓包碰不到。

| 编号 | 状态 | 这一轮的结果与剩余问题 |
|---|---|---|
| A1 | monitor 已解决;OSD 未决 | 标准客户端发 banner `0x3` 和 COMPRESSION_REQUEST。对 monitor 的现场探测:不带 COMPRESSION_REQUEST 的 `0x1` 可用,不带它的 `0x3` 被断开。OSD 没探测。 |
| A2 | 部分 | 标准掩码 `0x3f07fffffffdffff` 出现在全部 499 个 CLIENT_IDENT 里。服务端强制必需掩码(`0x0c01020042040000`,位 12 可选)。减少位后的编码与 CRC:需要我们自己的客户端。 |
| A3 | 已解决 | HMAC 密钥 = 会话密钥的原始秘密(类型 1 为 16 字节,类型 2 为整 32 字节),含 banner;499 次握手的两个签名都验证。剩余:同一连接上 AUTH_BAD_METHOD 重试后的转录范围(标准客户端从不重试)。 |
| A4 | 部分 | 对齐 4、16、4096 被接受;无数据的消息里非零 `data_off` / 前置填充被接受。剩余:非 2 的幂(没试,可能弄崩唯一的 monitor)、带数据的消息、32 位构建。 |
| A5 | 已解决 | 对端 HELLO 地址类型 2;monitor nonce 为 0;合成的 `target_addr` 被接受。剩余:客户端是否必须校验 monitor nonce。 |
| A6 | 部分 | 标准客户端每 10.0 秒 ping monitor(第一次在连接后约 3 秒),服务端从不主动发;空闲的 OSD 连接上完全没有 keepalive。剩余:客户端 KEEPALIVE2 是否重置服务端 900 秒空闲计时。 |
| A7 | 部分 | 见到 -13(错误密钥、无 OSD 权限)与 -95(未知方法或模式);monitor 对 lossless 意图也回答 lossy。剩余:其他错误码、OSD 的 lossless 会话。 |
| A8 | 未决 | 内存受限客户端的上限。 |
| B1 | 部分 | 两种密钥类型的 challenge 证明都重现(见到 245 次);现代密钥默认是类型 2。标准客户端从不发请求掩码 `0x24`(只发 `0x20`、`0x35`、`0x15`):需要我们自己的客户端。 |
| B2 | 部分 | 用旧票据重连会保留 global id。剩余:OSD 是否核对 CLIENT_IDENT 的 id 与票据;id 变化时已打开的 OSD 会话怎样。 |
| B3 | 部分 | 服务票据在会话内每 45.0 秒续期(TTL 60 秒);OSD 连接活得比票据久。剩余:72 小时 AUTH 票据的续期、重连时旧票据已过期。 |
| B4 | 未决 | 不是线上问题:iPXE 与驱动里的 SHA-384、CTS、多缓冲 GCM。 |
| C1 | 已解决 | 新会话两个 MMonMap;之后没有主动下发。MMonGetOSDMap / MMonGetVersion 没被使用过(没有标准工具发它们)。 |
| C2 | 部分 | IPv4 sockaddr、有序线上顺序、v2 在 v1 之前,已确认。IPv6 与非 Linux 的地址族号:实验室都没有。 |
| C3 | 部分 | 图与增量的 CRC 规则在 89 份图、89 份增量和所有下发的图上确认。剩余:跳过增量校验并重新拉取:线上从未出现过增量。 |
| C4 | 未决 | 实验室只跑 tentacle。 |
| C5 | 未决 | 观察到的线上大小都很小(最大:246 KB 的命令回复、53 KB 的 manager 图)。这不是上限研究。 |
| C6 | 未决 | 主机名解析。 |
| D1 | 部分 | 定位与 `ceph osd map`、`crushtool`、`osdmaptool` 逐位一致(含 reweight、affinity、upmap、pg_temp、primary_temp、out、down 状态)。剩余:`choose_args`、upmap-primary(需要 `require-min-compat-client reef`)、设备类变体、分裂池、Linux dcache 哈希、本地回退路径(任何运行都没走到)。 |
| D2 | 未决 | 实验室与源码树内的图里只有 straw 与 straw2 桶。 |
| E1 | 部分 | 分段布局、优先级 63、features 字、omap 联合体、SPARSE_READ 偏移已确认。剩余:`features` 为零、全零 omap 联合体、ENOSPC 各变体。 |
| E2 | 未决 | 需要故障注入:杀 OSD、backoff、池满、同 tid 重发。 |
| E3 | 未决 | 零长度与多区段稀疏读、backoff 范围、忽略 OSD 推送的 MOSDMap。 |
| F1 | 部分 | 用标准工具观察到:非持锁者的写能通过;`snap create` 与 `resize` 立刻以 EROFS 失败;标准写者每秒轮询数百次;`rbd bench` 面对外来标签的锁永远完成不了。剩余:krbd、交接到 Windows。 |
| F2 | 未决 | 设计问题(没有 header watch)。 |
| F3 | 基本解决 | 失败操作之前的输出会返回;FAILOK 让后面的操作继续;六个操作的头部请求可用。剩余:多操作头部读取的原子性。 |
| F4 | 部分 | Q14 已解决(pool-snapshot 模式的池里 `rbd create` 被以 EINVAL 拒绝)。剩余:trash、namespace、纠删码数据池、标志 `0x100`、`0x400`、`0x800`。 |
| G1 | 未决 | 没有任何 Reef 或 Squid 守护进程。 |

**新的 Top 10(仍未决的,按卡住多少排序)。** 取代英文第 7 节原列表里的排序。

1. **exclusive-lock 策略(F1;rbd Q2/Q3/T15)。** 策略 L2 对其他客户端的影响现已观察到(见上表)。剩余:我们的写者怎么选、krbd 面对外来锁的行为(没跑,可能弄坏实验室的内核客户端)、锁在 iPXE 到 Windows 交接时丢失。
2. **无应答的操作与挂载期间的头部变化(E2、F2;osd-ops Q6/Q7/Q8/Q12;rbd Q1)。** 故障注入一次也没跑:写入途中杀 OSD、backoff、池满、带/不带 ORDERSNAP 的过期快照上下文、同 tid 重发。
3. **能力协商的缩减(OSD 上的 A1、A2;msgr2 Q9;osdmap Q1/Q14;crush C7)。** 特性位更少的客户端会收到什么,以及 OSD 上的压缩跳过:需要我们自己的客户端。
4. **cephx 的边角(B1、B2、B3)。** 请求掩码 `0x24`、72 小时 AUTH 票据的续期、重连时旧票据过期、OSD 对 global id 的核对、不被允许的密钥类型、仅 crc 的客户端连仅 secure 的集群。
5. **内存上限(C5;osdmap Q10;mon-client Q9;secure Q9)。** 不变:只见过实验室的小图。
6. **从未运行过的 CRUSH 变体(D1、D2)。** `choose_args`、upmap-primary、uniform / list / tree 桶、设备类规则、分裂与非 2 的幂的 `pg_num`、Linux dcache 哈希、本地回退路径。
7. **多 monitor、IPv6 与增量下发(C2、C3)。** hunting、优先级与权重、三 monitor 的图、IPv6 sockaddr、起点大于 0 的订阅、只含增量的 MOSDMap、被裁剪的起点。
8. **OSD 上贴近规范边缘的线上探测(A4 到 A7)。** 非 2 的幂对齐、带数据消息的 `data_off`、KEEPALIVE2 与 900 秒空闲计时、其他 AUTH_BAD_METHOD 错误码、lossless 会话、revision-0 的 secure 帧、非 x86 CPU 上的 CRC-32C。
9. **其他版本(G1、C4)。** Reef 与 Squid 守护进程;v20.2.5 monitor 仍支持的最低 `require_osd_release`。
10. **操作与 RBD 的边角情形(E1、E3、F3、F4)。** 零长度与多区段 SPARSE_READ、ENOSPC 与 EDQUOT、重定向与 `-EAGAIN`、trash 与重命名、namespace、纠删码数据池、镜像标志、WRITESAME 与 CMPEXT、多操作头部读取的原子性。

第 8 节的许可问题(首先是 L1)与上面这些无关,仍卡着 `core/`。

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
