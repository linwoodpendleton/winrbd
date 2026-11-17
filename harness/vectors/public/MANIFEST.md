# Public capture vectors: manifest

Compact, public, secret-free capture set for the winrbd Phase 0 checkers (`harness/tools/`), so that outside
developers can verify the protocol notes in `docs/spec/` and develop against real bytes without a Ceph cluster.
Produced 2026-11-16 on a private, disposable lab cluster; nothing here touches any other cluster.

**What is public here, and why that is safe.** The captures were made with two throwaway cephx users
(`client.vec-k2`, `client.vec-k1`) whose keyrings are published in [`keys/`](keys/README.md). Both users were
deleted from the cluster right after the last capture (2026-11-16T11:38:59Z; `ceph auth get` fails afterwards), so
the keys are useless. No other key, keyring, session secret or debug log is part of this set (scanned for
every lab key and every session key of the private set: 0 hits). The admin key and the lab's regular users are not
involved.

## 1 Provenance

| Item | Value |
|---|---|
| Ceph release | v20.2.5 "Tentacle", pinned commit `ed27c686770872022f4c1de04f6b0ac5d5384ded` (stock `ceph-common` 20.2.5 tools as the client) |
| Cluster | fsid `52762725-e19a-11f1-886d-525400770001`, one VM `winrbd-ceph1`: 1 mon (v2 3300 / v1 6789 on 10.77.0.10), 1 mgr, 3 OSDs; pool `winrbd` (id 2, size 3, pg_num 32, crush rule 1), pool `.mgr` (id 1); images `img-v1` (layering only, id 37841afbd1d7) and `img-default` (default features 0x3d, id 37863d7ada59) |
| Key types | the cluster accepts both (`auth_allowed_ciphers = aes, aes256k`, `mon_auth_allow_insecure_key = true`); `client.vec-k2` = `aes256k` (cluster default, 32-byte secret), `client.vec-k1` = `aes` (legacy, 16-byte secret, created with `--key_type aes`) |
| Caps of both users | `mon 'profile rbd'`, `osd 'profile rbd pool=winrbd'` (same as the lab's regular RBD user) |
| OSDMap epoch | **141 for every session** (read before and after each session: `epochs.tsv`, no change); the ground truth in `gt/` is regenerated at the same epoch |
| Capture window | 2026-11-16, 11:13Z to 11:33Z (UTC); six `k1-*` sessions were re-run at 11:32Z, see 3 |
| Client address | 10.78.0.2 (network namespace); servers answer from 10.77.0.10 (the two 10.77/10.78 lab addresses are the only addresses in the pcaps) |

## 2 How the captures were made

Same method as the Phase 0 set: the client and the daemons share one VM, so every client command runs in a network
namespace `t0c` (client address 10.78.0.2, veth pair `t0v1` in the namespace / `t0v0` on the host, host side
10.78.0.1) and `tcpdump -i t0v0 -s 0 -U -B 16384 -w <session>.pcap host 10.78.0.2` runs for exactly one session.
Result: real Ethernet frames, MTU 1500, no loopback echo. Both ARP caches are warmed before tcpdump starts so no
ARP frames land in a pcap. One pcap = one `.cmd` file = one set of fresh TCP connections.
Driver and helpers are in [`scripts/`](scripts/) (`pubdriver.sh`, `pubidle.py`, `pcap_loss_check.py`).

Client options per session (`cmd/<session>.cmd` has the exact list):

- every command: `-n client.<vec-k1|vec-k2> --keyring <keyring> --debug_ms 5 --debug_auth <10|30> --log_to_file=true --log_to_stderr=false --log_file <file>` (the logs are not published);
- mode **crc**: `--ms_client_mode crc --ms_mon_client_mode crc` (crc framing everywhere);
- mode **def**: no mode options (stock defaults: secure to the mon and mgr, crc to the OSDs);
- mode **sec**: `--ms_client_mode secure --ms_mon_client_mode secure` (and `debug_auth 30`);
- `idle40` / `renew-ttl60` use `scripts/pubidle.py`: python `rados` client, one `stat` and one `mon_command osd stat`, a sleep (40 s / 150 s), then both again;
- `renew-ttl60` ran while `ceph config set mon auth_service_ticket_ttl 60` was in force (set 11:24:53Z, removed 11:30:10Z; value read back as 3600.000000 before and after);
- `wrongkey`: the right entity name with a random secret of the right type and length (the `wrong.*.keyring` files); expected result `rbd: couldn't connect to the cluster!`, exit code 13.

Test data (`data/`, not secret): `small.bin` = 100 bytes, `big.bin` = 1 MiB + 1234 bytes (1,049,810 bytes); byte i = (i*7+3) mod 251.
`data/getmap.k1.bin` and `data/getmap.k2.bin` are the full maps written by the two `ceph osd getmap` sessions (both byte-identical to `gt/osdmap.bin`, epoch 141).
Every `t0-` object and image was created and removed by the session that made it.

## 3 Sessions

22 pcaps, 15,008,841 bytes in total (14.3 MiB). Same 11 sessions for each key type (`k2` = `aes256k`, `k1` = `aes`).
`TCP retx` = number of retransmitted TCP segments in the pcap (bytes verified identical to the first copy); there are no gaps anywhere (see 4).

| session | key | mode | pcap bytes | frames | TCP retx | commands (common options omitted) |
|---|---|---|---|---|---|---|
| `k2-rbd-info-v1` | aes256k | crc | 94,515 | 198 | 0 | `rbd info winrbd/img-v1` |
| `k2-rbd-info-default` | aes256k | crc | 189,554 | 402 | 0 | `rbd info winrbd/img-default`<br>`rbd info --format json winrbd/img-default` |
| `k2-rados-small` | aes256k | crc | 409,011 | 758 | 0 | `rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd stat t0-small`<br>`rados -p winrbd get t0-small <data>/small.k2.get`<br>`rados -p winrbd get t0-missing-k2 <data>/missing.k2.get`<br>`rados -p winrbd rm t0-small` |
| `k2-rados-big` | aes256k | crc | 2,435,230 | 711 | 0 | `rados -p winrbd put t0-big <data>/big.bin`<br>`rados -p winrbd stat t0-big`<br>`rados -p winrbd get t0-big <data>/big.k2.get`<br>`rados -p winrbd rm t0-big` |
| `k2-rbd-bench-v1` | aes256k | crc | 2,549,736 | 1085 | 0 | `rbd create --size 16M --image-feature layering winrbd/t0-bench-k2`<br>`rbd bench --io-type write --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k2`<br>`rbd bench --io-type read --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k2`<br>`rbd rm winrbd/t0-bench-k2` |
| `k2-ceph-cli` | aes256k | crc | 967,613 | 339 | 0 | `ceph mon dump`<br>`ceph osd getmap -o <data>/getmap.k2.bin`<br>`ceph osd stat` |
| `k2-idle40` | aes256k | crc | 81,027 | 152 | 0 | `python3 pubidle.py vec-k2 <keyring> crc 40` |
| `k2-def-rbd-info` | aes256k | def | 347,533 | 656 | 0 | `rbd info winrbd/img-v1`<br>`rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd get t0-small <data>/small.k2.defget`<br>`rados -p winrbd rm t0-small` |
| `k2-sec-rbd-info` | aes256k | sec | 350,508 | 652 | 0 | `rbd info winrbd/img-v1`<br>`rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd get t0-small <data>/small.k2.secget`<br>`rados -p winrbd rm t0-small` |
| `k2-wrongkey` | aes256k | crc | 1,976 | 18 | 0 | `rbd info winrbd/img-v1 (keyring = random key for client.vec-k2)` |
| `k2-renew-ttl60` | aes256k | crc | 89,588 | 194 | 0 | `python3 pubidle.py vec-k2 <keyring> crc 150` |
| `k1-rbd-info-v1` | aes | crc | 93,475 | 198 | 0 | `rbd info winrbd/img-v1` |
| `k1-rbd-info-default` | aes | crc | 187,472 | 401 | 1 | `rbd info winrbd/img-default`<br>`rbd info --format json winrbd/img-default` |
| `k1-rados-small` | aes | crc | 406,120 | 770 | 4 | `rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd stat t0-small`<br>`rados -p winrbd get t0-small <data>/small.k1.get`<br>`rados -p winrbd get t0-missing-k1 <data>/missing.k1.get`<br>`rados -p winrbd rm t0-small` |
| `k1-rados-big` | aes | crc | 2,430,720 | 694 | 3 | `rados -p winrbd put t0-big <data>/big.bin`<br>`rados -p winrbd stat t0-big`<br>`rados -p winrbd get t0-big <data>/big.k1.get`<br>`rados -p winrbd rm t0-big` |
| `k1-rbd-bench-v1` | aes | crc | 2,545,820 | 1087 | 1 | `rbd create --size 16M --image-feature layering winrbd/t0-bench-k1`<br>`rbd bench --io-type write --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k1`<br>`rbd bench --io-type read --io-size 65536 --io-threads 4 --io-total 1M --io-pattern seq winrbd/t0-bench-k1`<br>`rbd rm winrbd/t0-bench-k1` |
| `k1-ceph-cli` | aes | crc | 965,715 | 337 | 0 | `ceph mon dump`<br>`ceph osd getmap -o <data>/getmap.k1.bin`<br>`ceph osd stat` |
| `k1-idle40` | aes | crc | 80,131 | 150 | 0 | `python3 pubidle.py vec-k1 <keyring> crc 40` |
| `k1-def-rbd-info` | aes | def | 344,966 | 663 | 4 | `rbd info winrbd/img-v1`<br>`rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd get t0-small <data>/small.k1.defget`<br>`rados -p winrbd rm t0-small` |
| `k1-sec-rbd-info` | aes | sec | 347,917 | 659 | 4 | `rbd info winrbd/img-v1`<br>`rados -p winrbd put t0-small <data>/small.bin`<br>`rados -p winrbd get t0-small <data>/small.k1.secget`<br>`rados -p winrbd rm t0-small` |
| `k1-wrongkey` | aes | crc | 1,976 | 18 | 0 | `rbd info winrbd/img-v1 (keyring = random key for client.vec-k1)` |
| `k1-renew-ttl60` | aes | crc | 88,238 | 196 | 0 | `python3 pubidle.py vec-k1 <keyring> crc 150` |

Session notes:

- `rbd-bench-v1`: `rbd create --size 16M --image-feature layering`, `rbd bench` write 1 MiB then read 1 MiB (64 KiB IOs, 4 threads, sequential), `rbd rm`: 2 MiB of bench traffic in total.
- `ceph-cli`: the `osd getmap` command delivers the full epoch-141 map in a MMonCommandAck data segment; the same map is also pushed for the osdmap subscription.
- `def-rbd-info`, `sec-rbd-info`: `rbd info img-v1` and a 100-byte `rados put/get/rm`, with default and with forced-secure options.
- `wrongkey`: authentication fails at the monitor; the pcap is 18 frames.

## 4 Capture quality

`scripts/pcap_loss_check.py` (own code, run on every pcap; output in [`pcap-check.txt`](pcap-check.txt)) reassembles every TCP flow per direction.
Result for all 22 pcaps: **0 gaps (no missing bytes), 0 truncated frames, 0 non-IP frames, exactly two IP addresses**; tcpdump reported `0 packets dropped by kernel` for every session.
The kernel drop counters are in `stdout/<session>.tcpdump.err`.

TCP retransmissions: no `k2-*` pcap has any. The `k1-*` (legacy `aes` key) sessions have 0 to 4 per pcap, always on a monitor connection (port 3300), always exactly one monitor-to-client segment (68 bytes on crc connections, 96 bytes on secure ones,
early in the connection setup) sent twice 3 to 5 ms apart, which looks like a TCP tail-loss probe fired because the legacy-key client acknowledges a little later (the cause was not investigated further). They are real wire behaviour, both copies were captured, the retransmitted
bytes are identical to the first copy, and nothing is missing. Re-running the sessions (done once for the six affected `k1-*` sessions) gives the same result, so they are kept; a decoder must tolerate a duplicate segment in
a reassembled stream. (The private Phase 0 set has the same duplicates in its `k1-*` sessions.)

## 5 Ground truth

| Directory | Content | Epoch / state | Source |
|---|---|---|---|
| `gt/` | `ceph osd getmap`, `osd getcrushmap`, `mon getmap`, `osd dump`, `osd tree`, crush dump / tunables / rule dump, pool detail, `osd map` for 2194 object names (`osd-map-all.jsonl`, the `epoch` field of every line is 141), `crushtool` placement tests, `osdmaptool` and `ceph-dencoder` outputs | **epoch 141, regenerated** for this set (`gt/EPOCH.txt`; the CRUSH map is byte-identical to the one at epoch 42, crush version 11) | `scripts/gtpub.sh` + `scripts/gtpub_inner.sh` (read-only on the cluster; offline tools run in the cluster's own container image) |
| `gt2/` | one full map after each of 24 reversible map changes (reweight, primary-affinity, upmap, pg-temp, down/out ...) | epochs 42 to 92, **copied unchanged** from the Phase 0 set (earlier epochs of the same cluster) | Phase 0 `gt2` |
| `gt3/` | every stored OSDMap and Incremental, epochs 1 to 89, raw and as `ceph-dencoder` JSON | epochs 1 to 89 (history is immutable), **copied unchanged** | Phase 0 `gt3` |
| `gt4/` | RBD metadata of `img-v1`, `img-default` and two throw-away copies (cls call hex, omap, striping and data objects, snapshot case) | **copied unchanged**; `rbd_check.py` confirms it still matches the live images | Phase 0 `gt4` |
| `gt5/out/` | `osdmaptool --test-map-pgs-dump-all` over each `gt2` map | copied unchanged | Phase 0 `gt5` |
| `baseline/baseline-after/` | `osdmap.bin` and `osd-dump.txt` taken after the run (epoch 141, identical to `gt/osdmap.bin`) | epoch 141 | `scripts/` baseline step; see 7 |

All copied files were scanned: no keys, keyrings, tickets or session secrets (0 hits against every key and session key of the private set), no host names other than the lab VM name, no addresses other than 10.77.0.10.

## 6 Directory layout

```
pcap/            22 session captures
cmd/             exact command list and options per session
stdout/          client stdout/stderr per session (with exit codes) and tcpdump statistics
sessions.tsv     session, key type, entity, mode, #commands, debug options, start, end, pcap bytes, frames, description
epochs.tsv       session, OSDMap epoch before, epoch after (all 141)
data/            test inputs and the two getmap files
keys/            public keyrings of the two deleted users + the two random wrong keys (README.md)
gt/ gt2/ gt3/ gt4/ gt5/out/   ground truth (see 5)
baseline/        osdmap.bin + osd-dump.txt after the run; revert-proof.txt
scripts/         capture and ground-truth scripts (MIT)
pcap-check.txt   output of scripts/pcap_loss_check.py
denc-map/        pools-e202.bin: `ceph osd getmap 202` taken after creating throw-away pools (names `wrtest-denc-*`, since deleted)
                 that make the optional parts of pg_pool_t non-empty: two pool snapshots, recorded pool options, application
                 metadata, a cache tier and hit_set parameters; pools-e202.txt: the matching `ceph osd dump` pool lines
                 (ground truth). Used by harness/test/test_denc_map.c. Same lab, same fsid, only 10.77.0.10 addresses, no keys.
                 pools-e957.bin: `ceph osd getmap` at epoch 957 taken while throw-away pools (`wrtest-ec`, `wrtest-merge`,
                 `wrtest-merge2`, since deleted) existed: an erasure coded pool, a pool whose pg_num merge had finished, and a pool
                 in the middle of a merge (pg_num 32, pgp_num 31, pg_num_pending 31); pools-e957.txt: the matching
                 `ceph osd dump 957` pool lines plus the JSON fields (pg_num_pending, flags, type) the text line leaves out.
                 Used by harness/test/test_osdmap_pool.c. Same lab, same fsid, no keys.
crushleg/        five offline CRUSH maps made with `crushtool -c` and 10,368 `crushtool --test --show-mappings` results over them (about
                 0.2 MB; `gen_crushleg.py` regenerates all of it in the cluster's tool image, no cluster state is read or changed): flat
                 list, uniform, straw and straw2 buckets of 1 to 300 items under legacy (local retries 2, fallback 5) and jewel
                 tunables with devices out, and a mixed hierarchy (straw2 root, list racks, uniform hosts) under three tunable
                 profiles. Used by harness/test/test_crush_legacy.c. Same format as mapb/crush/*.mappings.json; no keys, no addresses.
```
Size: about 23 MB on disk (pcaps 15.0 MB, ground truth 6.7 MB).

## 7 Revert proof

Everything the run changed in the lab was reverted; `baseline/revert-proof.txt` has the sha256 of 13 state snapshots taken before the run and after the clean-up, all identical
(`ceph config dump`, `osd dump`, `osd tree`, pool settings, crush dump, mon dump, rbd and rados object lists, entity/caps list, health, the OSDMap itself).
Specifics:

- `client.vec-k1` and `client.vec-k2`: deleted 2026-11-16T11:38:59Z, `ceph auth get` fails (ENOENT) for both.
- `auth_service_ticket_ttl`: set to 60 on the mon for the renewal sessions only, removed with `ceph config rm`; `ceph config get mon auth_service_ticket_ttl` = 3600.000000 before and after; `ceph config dump` before/after: no difference.
- No `t0-` object or image is left (`rbd ls` and `rados ls` of pool `winrbd` identical to before); the namespace `t0c`, the veth pair and every tcpdump process are gone.
- Side effect found and undone: creating a second legacy-key entity (`client.vec-k1`) cleared the lab's mute of the `AUTH_INSECURE_CLIENT_KEY_TYPE` health warning (a mute is dropped when the count rises). The same mute was re-applied afterwards (`ceph health mute AUTH_INSECURE_CLIENT_KEY_TYPE`, as the lab's setup script does), and `ceph health detail` is identical to the "before" snapshot.
- The OSDMap epoch did not change at all during the run (141 before, during and after): no OSD, pool, crush or config change that touches the map was made.

## 8 Running the checkers on this set

From a fresh clone (Python 3, the `cryptography` package and `curl`; nothing else):

```sh
harness/tools/run-all.sh
```

It fetches the Ceph run-time data once (`harness/tools/fetch-ceph-ref.sh`, into the git-ignored `harness/.ceph-ref/`), runs the eight checkers with their defaults (this directory, `keys/` here, the fetched Ceph data) and prints a table of passed, failed and skipped checks. Each checker also runs alone with no arguments, e.g. `python3 harness/tools/msgr2_check.py`. See [`harness/tools/README.md`](../../tools/README.md).

Result of the run made when the checkers were made to work from this set alone (22 pcaps, every checker exit 0):

| Checker | Passed | Failed | Skipped |
|---|---|---|---|
| `msgr2_check.py` | 77,514 | 0 | 2 |
| `secure_check.py` | 69,676 | 0 | 1 |
| `cephx_check.py` | 38,793 (37,839 on captures, 954 on vectors), including both wrong-key sessions | 0 | 1 |
| `monclient_check.py` | 193 named checks (35,949 assertions) | 0 | 0 |
| `osdmap_check.py` | 119 | 0 | 1 |
| `crush_check.py` | 81 | 0 | 1 |
| `osdop_check.py` | 33,739 | 0 | 0 |
| `rbd_check.py` | 1,849 | 0 | 2 |

Skipped checks (input this set does not have; a skip is reported with its reason and is never a pass or a failure):

- (a) `msgr2_check.py` AUT-11, `secure_check.py` (claim "connection-secret lengths agree with the stock client's own debug log") and `cephx_check.py` (decrypted session keys equal the client log): they compare with the stock client's `debug_auth` logs, which print session keys and are not published. Every ticket is still decrypted from the wire and cross-checked against the other frames.
- (b) `osdmap_check.py` and `crush_check.py`: "`gt/osdmap.bin` equals the stored full map of its epoch". This set is at epoch 141 on purpose (the pcaps, `data/getmap.*.bin` and `gt/` must be the same epoch); the stored full maps in `gt3/` cover epochs 1 to 89. The map is compared byte for byte with `baseline/baseline-after/osdmap.bin` (epoch 141) instead, and the wire maps are checked against that file.
- (c) `msgr2_check.py` NEG-2 and one `rbd_check.py` check (EPERM for a client with only `osd r`): they need a session by a read-only cephx user, which this set does not contain.
- (d) one `rbd_check.py` check (the librbd exclusive-lock acquire): it needs a write session on a default-feature image; the bench here writes to a layering-only image.

The `rbd bench` shape check and the minimum number of CALL ops are not skipped: the shape is read from `cmd/<session>.cmd` (a 16 MiB image, 4 threads, 64 KiB IOs, 1 MiB in total here), and the CALL-op checks need at least 100 ops (this set has 360).

## 9 Regenerating

`scripts/pubdriver.sh setup|sessions|renew|teardown` (inside the lab VM, passwordless sudo, `ROOT` = work directory holding `keys/ceph.client.<id>.keyring`), `scripts/gtpub.sh` and `scripts/gtpub_inner.sh` for `gt/`,
`scripts/pcap_loss_check.py --allow-identical-retx pcap/*.pcap` for the capture check. `ONLY="<session> ..." scripts/pubdriver.sh sessions` re-runs single sessions.
All scripts are our own code (MIT); they contain no Ceph code or data.

## 10 map-b vectors (`mapb/`)

Placement states that the first set lacks (non power-of-two `pg_num`, split and merge, upmap, upmap primary, `pg_temp` / `primary_temp`, primary affinity,
reweight / out, `noup` + down, a legacy pool, pool create / rename / delete, an erasure pool and a cache tier, `choose_args`, all five bucket algorithms, legacy tunables,
device classes), about 1.9 MB in 170 files. Index, formats and what each state is: [`mapb/README.md`](mapb/README.md) and `mapb/INDEX.json` (size and SHA-256 of every file).

| Item | Value |
|---|---|
| Ceph release | v20.2.5 "Tentacle", pinned commit `ed27c686770872022f4c1de04f6b0ac5d5384ded`; the CLI tools (`osdmaptool`, `crushtool`, `ceph-dencoder`) from the cluster's own image |
| Cluster | the same private lab as section 1 (one VM, 1 mon, 3 OSDs, pools `.mgr` and `winrbd`) |
| Capture window | 2026-11-16 (UTC); OSDMap epochs 666 (base) to 925 (restored) |
| What was made on the cluster | pools `wrtest-mb-*` only (sizes 2 to 4, `pg_num` 4 to 16, a pool without HASHPSPOOL, an erasure pool with its profile and rule, a cache tier pair, a pool with a positional weight set), one extra crush rule, one erasure profile; upmaps, upmap primaries, temps, primary affinity, reweights, one OSD out and in, `noup` with one OSD down, `require_min_compat_client` reef and back, `mon_allow_pool_delete` |
| Restore | everything removed again; the check is in `mapb/INDEX.json` (`restore`: pools, OSD rows, flags, overrides, `require_min_compat_client`, `mon_allow_pool_delete`; the lab's decompiled CRUSH map is identical before and after, `mapb/crush/lab-before.txt` / `lab-after.txt`); pool `winrbd`, the OSDs, the monitor and every key were not touched |
| Names | 3,352 `ceph osd map -f json` answers (8 pools: `winrbd`, `pg_num` 16, 12, 7 with `pgp_num` 4, 12 with `pgp_num` 8, a legacy pool, a size-4 pool, a one-host-rule pool), all at epoch 709; object and namespace bytes as hex |
| Offline | 18 CRUSH maps (`crushtool --build` and `crushtool -c`, 6,240 `crushtool --test --show-mappings` results) and 8 OSDMaps (`osdmaptool --createsimple` + `--import-crush`) |
| Scrub | fsid and the three OSD uuids replaced (same placeholders as `harness/vectors/osdmap/README.md`), every CRC recomputed, Ceph's own decoder run on every map and incremental; no key material of any kind |
| Incident | during the first full run an OSD of the lab crashed (a `primary_temp` set by the capture named an OSD that was then marked out: assert in `PeeringState::init_hb_stamps`, Ceph 20.2.5) and could not restart until its stale PG copies of the deleted test pools were removed with `ceph-objectstore-tool`; the OSD is up again, all pools are clean, the capture now clears every temp first. |

Regenerate with `scripts/capture_mapb.sh capture | export | offline | build`; check with `scripts/capture_mapb.sh --check` (python3 only, a few seconds). Besides sizes, hashes, the scrub, CRCs, the chain of incrementals and every
name hash, the check replays the independent python mapper over the vectors by default (the CRUSH log tables are read from `core/crush_ln/`; `MAPB_DEEP=0` turns this off): 2,071 tabulated PG results, the 3,352 name rows
(up / acting against the `osdmaptool` table of their epoch), 58 targeted monitor answers, 360 offline PGs and 3,600 `crushtool` mappings agree, 0 differ. The check is also a ctest (`vectors_mapb_check`); `capture_mapb.sh --selftest` (ctest `vectors_mapb_selftest`) damages copies of the vectors in 16 ways (a stray file, a symbolic link, a damaged byte in a map or incremental, a wrong name row, answer, PG row, CRUSH mapping or offline PG row, the real fsid without dashes, a private path, a foreign address, a key) and requires the check to fail on each.
It was independently re-verified against Ceph's own tools in the lab (all 130 `crushtool --test` runs, the 8 offline and 21 full-map `osdmaptool` tables, every name row, `ceph-dencoder` on every map, incremental and CRUSH map).

## 11 Live placement vectors (`placement/`)

The proof that the core's map store and placement follow a real cluster: the whole client (`harness/src/winrbd-mapwatch`) ran against the lab monitor while the cluster was changed
under it (test pools on four CRUSH shapes, `pg_upmap`, `pg_upmap_items`, `pg_upmap_primary`, `pg_temp`, `primary_temp`, primary affinity, reweight, an OSD out and in, size and `pg_num`
changes, a pool deleted, a missed incremental, a killed connection), and every answer was compared with Ceph's own (`ceph osd map` for 2,000 names per pool at every state, `osdmaptool`
over the monitor's own map of every epoch the client adopted). The maps and incrementals are exactly the bytes the monitor sent to the client, so the chain replays offline (ctest `place.live`).
About 0.7 MB in 40 files. Index, formats, method and the restore check: [`placement/README.md`](placement/README.md), `placement/INDEX.json` (size and SHA-256 of every file), `placement/RESULT.json` (the counts).

| Item | Value |
|---|---|
| Ceph release | v20.2.5 "Tentacle", pinned commit `ed27c686770872022f4c1de04f6b0ac5d5384ded` |
| Cluster | the same private lab as section 1 (one VM, 1 mon, 3 OSDs, pool `winrbd`) |
| What was made on the cluster | pools `wrtest-pl-a` to `wrtest-pl-d` and two CRUSH rules `wrtest-pl-hdd`, `wrtest-pl-host` (all deleted again); upmaps, upmap primaries, temps, affinity and reweights for a few seconds each; one OSD out and in; `require_min_compat_client` reef and back; `mon_allow_pool_delete` (set to delete the pools, put back) |
| Restore | the snapshot taken first (pools, OSD rows, flags, override tables, rules, tree, options) equals the state after the run: `restore_problems` is empty in `placement/RESULT.json`; pool `winrbd`, the OSDs, the monitor and every key were not touched |
| Scrub | none needed: the maps are as the monitor sent them (the lab fsid and `10.77.0.x` addresses are public); no key, ticket or keyring is part of the set |
| Check | `python3 -I harness/vectors/public/scripts/check_placement.py` (ctest `vectors_placement_check`): hashes, the contiguous chain, `epochs.tsv`, no stray file, no key-looking text |
| Regenerate | `harness/tools/map_placement_lab.py run` then `export` on the lab VM (see `placement/README.md`); all scripts are our own code (MIT) |
