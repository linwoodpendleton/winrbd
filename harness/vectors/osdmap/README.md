<!-- SPDX-License-Identifier: MIT -->
# OSDMap / Incremental / placement test vectors and the checker that produced them

These files back `docs/spec/osdmap.md` (and the placement part of `docs/spec/crush-and-placement.md` that
section 3.7 of the OSDMap note relies on). They are small: hex plus JSON expectations. Every file is verified by the
independent checker `harness/tools/osdmap_check.py`, which was written from the two notes only (not from Ceph source and
not through Ceph's decoders).

## Running the checker

```sh
# committed vectors only, a few seconds, needs nothing but Python 3:
python3 -I harness/tools/osdmap_check.py --vectors-only

# everything, against the public vector set (about one minute; run harness/tools/fetch-ceph-ref.sh once first):
python3 -I harness/tools/osdmap_check.py

# against another capture set, e.g. the private Phase 0 one:
python3 -I harness/tools/osdmap_check.py --captures <captures dir>

# regenerate these vectors from a capture set that holds gt2 / gt3 / gt5 (scrubs, recomputes the CRCs, then verifies them):
python3 -I harness/tools/osdmap_check.py --captures <captures dir> --write-vectors
```

Exit status 0 means every check passed. Placement checks need the two CRUSH log tables. They are **not** in this
repository: the checker parses `src/crush/crush_ln_table.h` from the pinned Ceph reference tree at run time
(`--ceph-src <dir>`, alias `--ref`; default `$WINRBD_CEPH_SRC`, else `harness/.ceph-ref`, which `harness/tools/fetch-ceph-ref.sh`
fills from the pinned Ceph commit). Without it those checks are reported as skipped, not as passed.

With `--vectors-only` the run covers: the arithmetic known answers of the notes (CRC-32C, string hashes, CRUSH hashes,
`stable_mod`, `crush_ln`), all files below, and the negative / robustness tests (synthetic mutations of `full-e42.hex`).
Against a capture set (the default) it adds: every stored map and incremental of epochs 1 to 89 against `ceph-dencoder` JSON, the 24
intermediate maps, 39 pcaps (every msgr2 frame CRC; MOSDMap and MMonSubscribe messages), CRUSH blob decoding against the
monitor's dump, and 80,000 `crushtool` mappings, 2,194 `ceph osd map` answers and 825 `osdmaptool` PG results over 25 map states.

## Files

| File | Content | Provenance |
|---|---|---|
| `full-e42.hex` | one complete OSDMap, epoch 42 (3,156 bytes): wrapper v8 / compat 7, client block v10, OSD-only block v9, 2 pools (`pg_pool_t` v32), 3 OSDs, CRC | the monitor's stored map, which is byte-identical to `ceph osd getmap` and to the map the monitor sent to the stock client in every captured session that ran at epoch 42 |
| `incrementals.hex` | all 89 `OSDMap::Incremental` blobs of the lab cluster, one per line `<epoch> <hex>`, epochs 1 to 89 (epoch 1 carries an embedded full map) | the monitor store (`osdmap` prefix), i.e. the canonical encodings the monitor would send to a client advertising the full feature mask |
| `mosdmap-front-e42.hex` | the front segment of a MOSDMap message (header version 4): fsid, 0 incrementals, 1 full map (epoch 42), trim lower bound 1, newest 42, gap count 0 | rebuilt from `full-e42.hex` in exactly the layout seen on the wire (the unscrubbed original was compared byte for byte with the captured message) |
| `crush-embedded.hex` | the CRUSH blob inside the epoch-42 OSDMap: 715 bytes, no MSR tunable pair | taken from the same map |
| `crush-incremental-form.hex` | the same CRUSH map as carried in an incremental's `crush` field (epoch 40) and returned by `ceph osd getcrushmap`: 723 bytes, the extra 8 bytes are the MSR tunable pair | taken from incremental 40 |
| `expected.json` | for `full-e42.hex`: versions, crc, a state summary; for each incremental: size, `inc_crc`, `full_crc`, which fields are non-empty; for every epoch 1 to 89: a state summary of the monitor's own full map of that epoch (what applying the incrementals must reproduce); the CRUSH map in decoded form | the state summaries come from the monitor's stored full maps, whose decoding equals `ceph-dencoder`'s JSON field by field (89 of 89 epochs); see "Cross-checks" |
| `placement-names-e42.json` | 219 object names (names of RBD objects, random names of 1 to 255 bytes, non-ASCII names, namespaced names) with the expected raw `ps`, pg, up / acting sets and primaries at epoch 42 | oracle: `ceph osd map -f json` on the lab cluster, 2,194 names in the full run |
| `placement-states.json` | for each of 24 saved map states (reweights, primary affinity, `pg_upmap_items`, `pg_upmap`, `primary_temp`, `pg_temp`, osd out / in, noup + osd down): `[raw, up, up_primary, acting, acting_primary]` of every PG of pools 1 and 2; the state itself is rebuilt by applying `incrementals.hex` | oracle: `osdmaptool --test-map-pgs-dump-all` over the maps saved at those epochs |
| `crush-mappings.json` | 4 sets of 300 CRUSH mappings (rule 0 and 1, 1 to 3 replicas, with and without the pool-id hash) | oracle: `crushtool --test --show-mappings` over `crush-embedded.hex`'s map |

The negative and robustness vectors (T7, T9) are not stored: the checker builds them from `full-e42.hex` and
`incrementals.hex` each time (raised `struct_v` with extra tail accepted, raised `struct_compat` rejected, every
truncation rejected, oversize `struct_len`, hostile element count, `max_osd` / vector mismatch, out-of-range OSD id in an
incremental, epoch gap, wrong fsid, and 3,000 seeded bit-flip inputs that may only produce a clean error).

## Scrubbing (rule 4 of CONTRIBUTING.md)

The source maps contain no key material, tickets or signatures; they do contain identifiers of the throw-away lab cluster.
What was replaced, everywhere it occurs (including inside the embedded full map of incremental 1):

| Original | Replacement |
|---|---|
| cluster fsid | `00112233-4455-6677-8899-aabbccddeeff` |
| the three OSD uuids | 16 bytes of `0xA0`, `0xA1`, `0xA2` |

After the replacement every CRC was recomputed with the rule of `osdmap.md` 2.4.5: the full map CRC over the scrubbed
bytes, `full_crc` of each incremental = CRC of the scrubbed full map of that epoch, then `inc_crc`. The scrubbed files
were then run through Ceph's own decoder (`ceph-dencoder type OSDMap` and `type OSDMap::Incremental`, which verifies the
CRC): all 90 decoded without error and their JSON equals the checker's decoding field by field.

Left as captured, because they are neither secret nor identifying beyond the lab defaults: the lab addresses
`10.77.0.10:68xx` and their nonces (random numbers chosen by the daemons), pool names (`.mgr`, `winrbd`), the CRUSH item
names of the lab host, timestamps, the OSD-only block (OSD info, blocklist entries of the lab's own earlier daemons).
`expected.json` and the placement files contain no fsid.

## Cross-checks done on the unscrubbed originals (details are in the checker's output)

* 89 stored full maps and 89 stored incrementals decode with the note's tables, consume every envelope exactly, and equal
  the `ceph-dencoder` JSON field by field (the dump omits `new_primary_affinity`; that field is checked through the applied
  state instead). Every CRC matches: raw CRC-32C, start value `0xFFFFFFFF`, no final inversion.
* Applying incrementals 1 to 89 in the order of `osdmap.md` 3.5 reproduces the monitor's full map of every epoch.
* Placement: 80,000 `crushtool` mappings, 2,194 `ceph osd map` answers (0 mismatches; the one name with a non-BMP
  character matches only when hashed as two 3-byte surrogates, which is what the oracle's JSON command parser delivered to
  the monitor), 825 `osdmaptool` PG results.

## What these vectors do not cover

Incrementals only exist for a replicated, hashpspool lab cluster at tentacle: no pool deletion (`old_pools`), no OSD
destroy / purge, no `new_state` mask 0, no shrinking `max_osd`, no `pg_upmap_primaries`, no stretch pool (pool rows 51 / 52
with data), no erasure pool, no pool snapshots, no IPv6, no non-power-of-two `pg_num`, no `pg_num` != `pgp_num`, no
choose_args weight set, no cluster below `require_osd_release` tentacle, no map re-encoded for a client advertising fewer
feature bits, no MOSDMap on the wire that carries incrementals. The checker lists these as open in its claims table.
