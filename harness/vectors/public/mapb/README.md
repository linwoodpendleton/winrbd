<!-- SPDX-License-Identifier: MIT -->
# map-b: placement states the first vector set lacks

Public, secret-free vectors for the OSDMap / CRUSH placement code (architecture 18.3, states S1 to S15). They come from
the private lab cluster (Ceph v20.2.5, 3 OSDs, one host) driven with the admin CLI, plus CRUSH maps and OSDMaps
built offline with `crushtool` and `osdmaptool`. Every file is listed with its size and SHA-256 in [`INDEX.json`](INDEX.json);
[`../scripts/capture_mapb.sh --check`](../scripts/capture_mapb.sh) verifies them (see "Checking").

The first set (`harness/vectors/osdmap`, `crush`, `public/gt*`) ends at epoch 141 of the same cluster. This set starts from the lab map of
**epoch 666**, taken right before the capture (pools `.mgr` and `winrbd`, 3 OSDs up and in, no overrides): `base-e666.hex` is that map and
`incrementals.hex` holds every epoch from 667 to 925 (the monitor keeps only the last 500 epochs, so the history between 141 and 666 is gone). A
consumer rebuilds the map of any epoch by applying incrementals in order, and every state below names an epoch. Epochs that no state names
(natural churn: `up_thru`, `pg_temp` set and cleared by the OSDs, other users of the lab) are still in the chain.

## Files

| Path | Content |
|---|---|
| `base-e666.hex` | the full OSDMap at epoch 666 (scrubbed, CRC recomputed): the starting point of `incrementals.hex` |
| `incrementals.hex` | every `OSDMap::Incremental` of epochs 667 to 925, one per line `<epoch> <hex>`, from the monitor store (the encoding the monitor sends to a client with the full feature mask). `inc_crc` and `full_crc` are recomputed after the scrub |
| `states/<label>.json` | one captured **state**: epoch, description, the commands that made it (with exit codes and the monitor's answer), the pruned `ceph osd dump -f json` of that epoch, the `osdmaptool --test-map-pgs-dump-all` table of the pools the state is about, and a few `osdmaptool --test-map-object` answers |
| `maps/e<epoch>.hex` | the full map (`ceph osd getmap <epoch>`) of the states whose JSON names it in `full_map`; for every other state the map is base + incrementals |
| `names/names-e<epoch>.json` | the **name oracle**: `ceph osd map -f json` for every (pool, name, namespace) of a large set, all answered at one epoch |
| `answers.json` | `ceph osd map -f json` for names chosen to hash into a PG that carries an upmap, upmap primary or choose_args, asked right after the override was set (each answer carries its epoch) |
| `crush/<name>.crush.hex`, `.txt`, `.mappings.json` | 18 offline CRUSH maps (S13, S14): the compiled map, the text `crushtool -d` prints for it, and 130 runs in all of 48 `crushtool --test --show-mappings` results each (x = 0 to 47; 6,240 mappings) |
| `crush/lab-before.txt`, `lab-after.txt` | the lab's own CRUSH map (decompiled) before the capture and after the restore: the same text, which is the visible part of the restore |
| `offline/<name>.osdmap.hex`, `.pgs.json` | eight OSDMaps made with `osdmaptool --createsimple` and the CRUSH maps above, OSDs set up and in, and the `osdmaptool --test-map-pgs-dump-all` table of their pool |
| `ops.log.txt` | the commands of the capture run with exit codes (polling commands omitted) |
| `INDEX.json` | machine-readable index: states, crush maps, offline maps, names, restore result, per-file size and SHA-256 |

Hex files hold `#` comment lines and then the bytes as wrapped hex (like `harness/vectors/osdmap/*.hex`).

### State JSON

`pgs` maps `"<pool>.<pg hex>"` to `[raw, up, up_primary, acting, acting_primary]` exactly as `osdmaptool --test-map-pgs-dump-all`
prints them (OSD ids; 2147483647 is the "none" item of an erasure pool). `pools_in_tables` lists the pool ids whose PGs are
tabulated (`null` = all pools). `objects` is `[pool, object_name_hex, pgid, acting]` from `osdmaptool --test-map-object`.
`dump` keeps the fields a client needs from `ceph osd dump`: pools (geometry, flags, tiers), OSD rows (up, in, weight,
primary affinity), the five override tables and `crush_version`.

### Name oracle rows

`[pool_id, object_bytes_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary]`, the layout of
`harness/vectors/osdmap/placement-names-e42.json`. The bytes are what the monitor hashed. For a name with a character above
U+FFFF the monitor's JSON parser produced two 3-byte surrogates (CESU-8), so those rows carry `eda0..` / `edb0..` sequences
(the capture script tries both encodings and keeps the one that reproduces the monitor's `raw_pgid`). The namespace enters
the hash as `namespace 0x1f name`. The geometry of every pool of the oracle (pg_num, pgp_num, size, rule, HASHPSPOOL) is in the
file header; the lab map at that epoch is `states/s00-base-pools.json`'s `full_map`.

## What the states cover

| Tag | State | Labels |
|---|---|---|
| S1 | `pg_num` not a power of two (12 and 7) and `pgp_num` below `pg_num` | `s01a`, `s01b`, `s01c` |
| S2 | a split in progress (`pg_num` raised, `pgp_num` lagging), every epoch | `s02-split-e*` |
| S3 | `pg_upmap_items`: one pair, two pairs, two invalid pairs (`to` already in the set, `from` not in the set); removed again | `s03a` to `s03d`, `s03z` |
| S4 | `pg_upmap`: reorder, replacement, a member with weight 0 (before and after the reweight); removed again | `s04a` to `s04d`, `s04z` |
| S5 | `pg_upmap_primary` (needs `require_min_compat_client` reef, restored afterwards) | `s05a` to `s05c`, `s05z` |
| S6 | `pg_temp` alone, `primary_temp` alone, both on one PG | `s06a` to `s06c`, `s06z` |
| S7 | primary affinity 0, 0.25, 0.5 on one, two, three OSDs | `s07a` to `s07c`, `s07z` |
| S8 | reweight 0.5, 0.1, 0; out and in | `s08a` to `s08f` |
| S9 | an OSD down and not out (`noup` + `osd down`), and up again | `s09a`, `s09b` |
| S10 | a pool without HASHPSPOOL | `s10-legacy-pool` (and its names in the oracle) |
| S11 | a pool created, renamed (`new_pool_names`), deleted (`old_pools`) | `s11b` to `s11e` |
| S12 | an erasure pool (profile, indep rule) and a cache tier (tiers, overlay, `cache_mode`) | `s12a` to `s12e`, `s12z` |
| S13 | `choose_args`: a positional weight set on a test pool of the lab (live, by pool id), a compat set; offline sets: key 0 positional with replaced ids, key 0 flat, key 1 positional + compat -1, compat with a zero weight; OSDMaps whose pool uses its own set, the compat fallback, and a key-0 set that a pool must not use | `s13a` to `s13z`, `crush/cm14a` to `cm15`, `offline/om06` to `om08` |
| S14 | bucket algorithms straw, list, uniform, tree, straw2; legacy tunables with fallback tries; `chooseleaf` over hosts and racks; device-class shadow roots; rules with `set_*` steps, two emits, `take` of a non-root bucket | `crush/cm01` to `cm13b`, `offline/om01` to `om05`, `s14a` |
| S15 | a merge in progress (`pg_num` lowered, `pg_num_pending`) | `s15-merge-e*` |

The exact list, with the epoch of each, is `states` in `INDEX.json`. Where the monitor cleaned a requested entry itself (it
removes `pg_temp` and invalid upmaps in a later epoch) the state is the **first epoch that holds it**, found by scanning the
epochs after the command; a state whose predicate was never true says `PREDICATE-NOT-MET` in `notes`. The incrementals after it
carry the removal (`old_pg_upmap_items`, empty `new_pg_temp` entries, ...).

### The offline CRUSH maps

24 OSDs, 6 hosts of 4, 2 racks of 3 hosts, a root named `root` (`default` in the class maps); the standard rule set is r0 to r7:
`chooseleaf firstn` over host and rack, flat `choose firstn`, `choose firstn 2 rack` + `chooseleaf firstn 2 host`, two indep rules
(with `set_chooseleaf_tries` / `set_choose_tries`), `take rack0`, and a rule with two `emit` blocks. `cm01` to `cm04` were made with
`crushtool --build --num_osds 24 host <alg> 4 rack <alg> 3 root <alg> 0` (the rule `--build` creates is replaced by the standard set);
the others are written as text and compiled with `crushtool -c`. `cm13b` is `cm13` with the hdd rule as rule 0, which the pool of `om05` uses. `cm08` and `cm12` use the argonaut tunables (`choose_local_tries 2`,
`choose_local_fallback_tries 5`, `choose_total_tries 19`) and are run with many devices out (`outA-*`, `outB-*`: `--weight DEV W`), which exercises
the retry, local retry and permutation fallback paths. The compat key -1 of `choose_args` cannot be written in `crushtool`'s text grammar: the maps
are compiled with key 3 and the key is renamed to -1 in the binary (the `.txt` of those maps is what `crushtool -d` prints for the result, which
the compiler cannot read back). **`crushtool --test` always asks for `choose_args` key 0 and falls back to -1; `--pool-id` only changes the hash of x** (it does not
select the pool's set), so the pool-specific sets (key = pool id) are exercised through the offline OSDMaps and the live pool, not through `crushtool` runs.

The offline OSDMaps are `osdmaptool --createsimple 24 --with-default-pool` maps whose CRUSH map was replaced with `--import-crush`; since
`osdmaptool` does not persist up / in, the saved map has all OSDs up and in through a byte patch of the two OSD vectors (the CRC recomputed); the patched map gives
the same table as `osdmaptool --mark-up-in` on the unpatched one (checked by the build). `om04` additionally has OSDs 2, 3, 17 out, OSD 5 down and two reweights.

## What the capture showed (relevant for the decoders and the placement code)

* The monitor **accepts** a `pg_upmap_items` pair whose `to` is already in the set (`s03c`) and keeps it; the mapping must ignore it. A pair whose `from` is not in the set is accepted and removed again in the epoch that would have carried it (`s03d`, `notes`): no epoch holds it.
* A `pg_upmap` that names an OSD with weight 0 exists in the epoch of the reweight (`s04c`), and the monitor also accepts one set after the reweight (`s04d`); both are cleaned by later epochs.
* `pg_temp` entries are cleared by the OSDs within a few epochs; **`primary_temp` is not**: it stays until `ceph osd rm-primary-temp`. In `ceph osd dump -f json` the `primary_temp` table is a flat list `[pgid, osd, pgid, osd, ...]`, the other tables are lists of objects.
* The one-host-rule pool (`wrtest-mb-host`, size 3 on one host) keeps a monitor-made `pg_temp` for each of its 8 PGs for good, so almost every state carries those 8 entries; nobody set them. While OSDs move (`s08b`, `s08c`, `s08f`) many more appear and disappear.
* A `primary_temp` naming an OSD that is not in the acting set (the OSD was marked out) **crashes that OSD** (`PeeringState::init_hb_stamps`, Ceph 20.2.5, the primary missing from `acting`). The capture clears every temp before it marks an OSD out.
* `pool_max` never goes down: deleted pool ids are not reused (`s11e`). A pool without HASHPSPOOL can be made with `osd pool set <pool> hashpspool false --yes-i-really-mean-it` and cannot be changed back without the same flag.
* The CRUSH blob inside an incremental has two more tunables (the MSR pair) than the blob re-encoded in a full map of the same epoch: compare decoded structures, not bytes.
* `crushtool --test` selects `choose_args` key 0, then -1, never the key given with `--pool-id` (see above). `osdmaptool` and the monitor use the pool id, then -1.
* The monitor keeps the last 500 epochs only; `ceph-dencoder` of this release segfaults in `dump_json` for a map with a non-default primary affinity (`decode` alone, which verifies the CRC, is fine).

## Scrub

Same rules as `harness/vectors/osdmap/README.md`: the cluster fsid becomes `00112233-4455-6677-8899-aabbccddeeff`, the three OSD uuids become
16 bytes of `0xA0 + osd id`, every CRC is recomputed (full map CRC, `inc_crc`, `full_crc`), and the result is run through Ceph's own
`ceph-dencoder` (which verifies the CRC) in the lab. Offline maps carry the placeholder fsid. Left as captured: the lab addresses `10.77.0.10:68xx`
and their nonces, pool names, timestamps. No keyring, ticket, key or log of any kind is part of the set.

## Checking

```sh
harness/vectors/public/scripts/capture_mapb.sh --check          # python3 only, a few seconds
MAPB_DEEP=0 harness/vectors/public/scripts/capture_mapb.sh --check   # without the independent python mapper cross-checks
```

`--check` verifies: every file's size and SHA-256 against `INDEX.json` and no stray file; the total size budget; the scrub (the real fsid and
OSD uuids, tested by hash over every 16-byte window of every blob, do not occur; no key-looking text; no address outside 10.77.0.x); every full map and
incremental decodes with the independent checker (`harness/tools/osdmap_check.py`), CRCs are right, the incrementals are contiguous and applying them to the base reproduces the stored full map
at every epoch that has one; every name of the oracle hashes to its raw ps and PG with the pool's `pg_num` (3,352 rows over 8 pools, lengths 0 to 25 and 255, namespaces, non-ASCII and CESU-8 rows, a power-of-two
pool, `pg_num` 12 and 7 with `pgp_num` below it, a legacy pool, `winrbd`); every state's override tables agree with the rebuilt map and its object names hash to their PG; the CRUSH maps decode and cover all five bucket algorithms,
several tunable profiles, `choose_args` keys 0, 1 and -1 and device classes; each offline OSDMap carries the CRUSH map it names; the capture's restore check passed.
The same run replays the python mapper of the checker (`harness/tools/osdmap_check.py`: replicated firstn rules, straw and straw2 buckets, `choose_args`; the CRUSH log tables are read from `core/crush_ln/`) over every
tabulated PG of the replicated pools (2,071 results), the 58 rows of `answers.json` (up / acting at the epoch of each answer), the offline OSDMaps (360 PGs) and the `crushtool` mappings (3,600), and fails on any disagreement:
there are none in this set. The name oracle's up / acting columns are compared with the `osdmaptool` table of epoch 709 (`states/s00-base-pools.json`). The runs the python mapper cannot do (indep rules,
list / uniform / tree buckets, the argonaut tunables of `om02`) are skipped, with a ceiling on how many may be skipped, and are covered by Ceph's own answers only. `MAPB_DEEP=0` turns the mapper cross-checks off.

## Regenerating

`capture_mapb.sh capture | export | offline | build` (see the header of the script; the first three run on the lab VM, the last one needs only `python3`
and the raw output directory). The lab run touches only pools named `wrtest-mb-*`, an extra crush rule, an erasure profile and a weight set made for them, OSD-wide
upmap / temp / affinity / reweight / out / noup entries for a few seconds each, `require_min_compat_client` (reef, then back) and `mon_allow_pool_delete`; it restores all of it and records the
check in `INDEX.json` (`restore`). It never touches the pool `winrbd`, the OSDs, the monitors or any key.
