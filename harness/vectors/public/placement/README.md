<!-- SPDX-License-Identifier: MIT -->
# placement: the live proof of the core's placement

Public, secret-free vectors made while the **whole client** (`harness/src/winrbd-mapwatch`: msgr2, cephx, the monitor client and the OSD map
store of `core/`, nothing modelled in between) followed the private lab cluster (Ceph v20.2.5, one host, 3 OSDs) over a real monitor session, and
a script (`harness/tools/map_placement_lab.py run`) changed the cluster under it. The ground truth is Ceph's own: `ceph osd map -f json` for every
name, `ceph osd getmap <epoch>` + `osdmaptool --test-map-pgs-dump-all` for every epoch, `ceph osd dump <epoch>` for the overrides. The numbers of
the run that made this set are in [`RESULT.json`](RESULT.json). The C test `place.live` (`harness/test/test_place_live.c`) replays everything offline
through the core's real decoders, so CI checks placement without the lab; `vectors_placement_check` (`../scripts/check_placement.py`) checks the files.

## What the run did

Four test pools next to `winrbd`, on two extra CRUSH rules (all removed again, see "Restore"):

| Pool | `pg_num` | size | rule |
|---|---|---|---|
| `wrtest-pl-a` | 8 (later 16) | 3 (briefly 2) | `choose firstn osd` (the lab's default rule) |
| `wrtest-pl-b` | 13 (not a power of two; later 20) | 2 (briefly 3) | the same rule |
| `wrtest-pl-c` | 32 | 3 | a device-class rule (`take default~hdd`, shadow tree) |
| `wrtest-pl-d` | 64 | 2 | `chooseleaf firstn host`: the lab has one host, so every PG gets one OSD and some have none |

Then, in this order (every step is a state in `states/`, listed with its commands and exit codes): pools created; `pg_upmap_items` (valid pairs and
a pair whose `to` is already in the set); `pg_upmap` (reordered full sets); both removed; `pg_upmap_primary` (with `require_min_compat_client` raised
to reef and put back); primary affinity 0 and 0.5; reweight 0.6, 0.2 and 0 (a member CRUSH must skip), then 0.3 / 0 / 0.1 (some PGs of the one-host pool get no OSD); one OSD out and in again (the monitor's
`pg_temp` entries while PGs move); explicit `pg_temp` and `primary_temp` (the primary-temp OSD is a member of both the up and the temp set); pool sizes
changed; `pg_num` raised with `pgp_num` following; a **missed incremental**; a **killed monitor connection**; a pool deleted while tracked.

Two clients ran side by side for the whole run, one with the `aes256k` key and one with the legacy `aes` key; the second one is never disturbed.

## How the comparison is made

* **Names.** 2,000 synthetic object names (half `rbd_data.<id>.<16 hex>`, half plain; the recipe is in `names.json`) in every tracked pool at every
  state: the client prints its answer, a Python rados session asks the monitor (`osd map`) for the same name, and a row counts only when the
  monitor's reply names the **same epoch** as the client's row (the cluster is settled first; skewed rows are asked again, never counted). The object
  hash, the PG, the up and acting sets and both primaries must be equal.
* **Epochs.** The client writes the placement of every PG of every tracked pool at **every epoch it adopts** (including the transient ones: the epochs
  of an OSD going out, of the monitor's `pg_temp` entries, of the splits). Afterwards the monitor's own full map of each of those epochs is fetched and
  `osdmaptool --test-map-pgs-dump-all` is compared PG by PG (up, up primary, acting, acting primary). Every epoch from the first to the last is checked,
  also the one the client was made to miss. A PG that the client reports as unmappable must have an empty acting set in Ceph's table.
* **Faults.** (1) The client's map hook swallows one monitor message before the store sees it; the next incremental has a gap, the store asks for a
  full map (`n_resync` 1, `n_full` 2), and the placement after it is compared again. (2) The TCP connection of the client is killed from outside
  (`ss -K` on that one socket, four times) while the OSD is reweighted; the client reconnects, subscribes again and catches up. The second client is
  not touched and must end with one full map, no re-request and no failed entry.

## Files

| Path | Content |
|---|---|
| `base-e<E0>.hex` | the full OSD map the client started from, as the monitor sent it |
| `incrementals.hex` | every incremental from E0+1 to the last epoch, one per line `<epoch> <hex>`, exactly as received (the client saved them), also the one that was swallowed |
| `epochs.tsv` | for **every** epoch of the chain: the number of PG rows and the FNV-1a 64 digest of the PG rows of the tracked pools as `osdmaptool` printed them (text format in the header) |
| `names.json` | the recipe of the 2,000 names and the object hash the monitor gave each |
| `states/<label>.json` | one state: epoch, commands, the pruned `ceph osd dump`, the PG table of the tracked pools (`[raw, up, up_primary, acting, acting_primary]`, as in `../mapb`), the digest of all `ceph osd map` answers of that state and 120 to 200 of them in clear |
| `maps/e<E>.hex` | the monitor's own full map (`ceph osd getmap`) of some state epochs; `maps/resync-e<E>.hex` is the full map the client was sent after the incremental it missed |
| `ops.log.txt`, `RESULT.json` | the cluster commands of the run; the counts of the live run (what was compared, mismatches, both clients' counters, the restore check) |
| `INDEX.json` | size and SHA-256 of every file |

No fsid, OSD uuid or address was changed: the maps are as the monitor sent them (the lab's fsid and `10.77.0.x` addresses are public, see
`../MANIFEST.md`). There is no key, ticket or keyring of any kind in the set; the clients read their keyrings from files outside the repository.

## Restore

The run takes a snapshot first (pools, OSD weight / affinity / in / up, flags, `require_min_compat_client`, the five override tables, the CRUSH rules, the
decompiled tree, `mon_allow_pool_delete`) and puts everything back at the end: every override removed, weight and affinity 1, all OSDs in, the four pools
and the two rules deleted, `mon_allow_pool_delete` and `require_min_compat_client` as before. The check is `restore_problems` in `RESULT.json` (empty).
The pool `winrbd`, the OSDs, the monitor and every key were not touched.

## Regenerating

```sh
# on the lab VM (passwordless sudo, cephadm; python3 with the rados module under sudo; keyrings in ~/keys, never in the repository)
python3 -I harness/tools/map_placement_lab.py run --work ~/w/placement-live/work --names 2000
python3 -I harness/tools/map_placement_lab.py export --work ~/w/placement-live/work --out harness/vectors/public/placement
# after a failed run: ... cleanup --work <dir>      redo the epoch comparison of a finished run: ... reanalyze --work <dir>
```
