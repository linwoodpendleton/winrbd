# Test vectors: CRUSH and object placement

Vectors for [docs/spec/crush-and-placement.md](../../../docs/spec/crush-and-placement.md), plus the checker that
produced them. License: MIT.

Everything here comes from the disposable lab cluster (Ceph v20.2.5, one monitor, three OSDs, pool `winrbd` with
id 2, pool `.mgr` with id 1, OSDMap epoch 42 unless stated otherwise) or from arithmetic that the checker
recomputes. Nothing is copied from Ceph's source or test data.

## Running the checker

```
python3 harness/tools/crush_check.py --captures <captures-dir> [--ref <ceph-reference-tree>]
```

* Exit status 0 when every check passes, 1 when a check fails, 2 when an input is missing.
* Python 3 standard library only. It never runs a Ceph binary; Ceph tools appear only as output files in the capture
  directory (`ceph osd map`, `crushtool`, `osdmaptool`, `ceph-dencoder` JSON, the stored monitor maps).
* The checker reads no keys and prints none. It does not decrypt anything (secure-mode streams are recognised by their
  failing preamble CRC and skipped).
* `<captures-dir>` must contain `gt/`, `gt3/` and `pcap/` as laid out by the capture round (`MANIFEST.md` there).
  `--ref` defaults to `<captures-dir>/../ceph-v20.2.5`. The reference tree is read **at run time** for the two tables of
  `src/crush/crush_ln_table.h` (parsed from the header text, never embedded here) and for the in-tree known-answer
  tests of group F.
* Options: `--quick` (skip data-segment CRCs above 64 KiB and group F), `--no-pcap`, `--no-tree`,
  `--tree-x N` (group F compares `x < N`, default 8; 1024 is the whole files and takes a long time in Python),
  `--emit-vectors DIR` (regenerates the files in this directory), `-v` (print passing checks too).
* A full run takes one to two minutes on a laptop (the pcap group hashes 106 MB with a pure-Python CRC-32C).

Result of the run that produced these files: **80 checks passed, 0 failed**, 15 informational findings, 636,903
individual comparisons (mappings, fields, frames, CRC values).

### What the groups check

| Group | Checks (all against the note's own wording; the note's text is the only specification used) |
|---|---|
| A | The vectors of note 5.1 (string hashes, CRUSH hash2/3/4, `stable_mod`, `pps`, `crush_ln`); the table facts of 3.4.2 recomputed from the pinned header with 80-digit arithmetic: 129 + 128 exact `RH_LH` entries, `RH_LH[257]`, the 21 / 212 / 23 split of `LL_tbl`, 63,500 differing `crush_ln` inputs, maximum difference 343,343,104 |
| B | The CRUSH blob decoder (2.2, 2.4) against `ceph-dencoder` JSON: buckets, rules, tunables, names, classes; the two blob forms of 2.1 (embedded in an OSDMap, and `getcrushmap`); all 89 stored full maps and the 10 stored incrementals that carry a CRUSH map |
| C | The OSDMap and Incremental decoders (osdmap.md 2.4 - 2.6) for every stored epoch 1..89 against `ceph-dencoder` JSON; every CRC; replay of incrementals 1..89 with the rules of crush note 2.7 / osdmap.md 3.5, compared with the stored full map of each epoch |
| D | The pipeline of 3.1 - 3.7 against `ceph osd map` (2,194 names), `crushtool --test` (8 runs x 10,000 mappings, two with `--pool-id`), `osdmaptool --test-map-pgs-dump-all` (pools 1 and 2) and `--test-map-object` |
| D2 | Consistency only (no oracle output exists for these states): upmap, upmap items, primary temp, pg temp, out, down and primary affinity applied to the stored maps that contain them |
| E | The 39 pcaps: TCP reassembly, msgr2 revision-1 crc-mode frames (preamble, inline segment-0 and epilogue CRCs), MOSDMap, and every MOSDOp the stock client sent: its `hash` field, its masked pg, and the OSD connection it used, against our pipeline |
| F | The in-tree `crushtool` known-answer files (straw buckets, chooseleaf, `vary_r` 0..4, descend-once, local retries with the permutation fallback): 11 files, 600 mappings by default, 3,000 at `--tree-x 40`; these maps never reach the local-fallback / permutation path (0 uses), only the collision local retry (3 uses) |

## Files

All hex files are plain hex, 64 bytes per line.

| File | Content | Origin |
|---|---|---|
| `hash-vectors.json` | string hashes (rjenkins and Linux dcache), CRUSH hash2/3/4, `stable_mod`, HASHPSPOOL `pps`, `crush_ln` | arithmetic, the note's 5.1 table, reproduced by the checker; the live cluster confirms them in aggregate (see the note) |
| `crush-getcrushmap.hex` | CRUSH blob as `ceph osd getcrushmap` returns it (723 bytes, with the MSR tunable pair) | lab cluster, epoch 42 |
| `crush-embedded-in-osdmap.hex` | the CRUSH blob inside the epoch-42 OSDMap (715 bytes, without the MSR pair); identical to the first 715 bytes of the file above | lab cluster |
| `crush-blob.expected.json` | the decoded blob: 8 bucket slots of which 4 are used (root, host and their device-class shadow copies), 2 rules, tunables, names, classes | checker, equal to `ceph-dencoder` JSON |
| `osdmap-e42.placement-input.json` | what placement reads from the epoch-42 map: pools, `osd_state`, `osd_weight`, affinity (absent), empty temp and upmap tables | lab cluster, decoded by the checker |
| `placement-expected.json` | 137 `ceph osd map` results (pool, object bytes, namespace bytes, raw pg, pg, up, acting, primaries): every name length present, namespaces, non-ASCII, the `.mgr` pool, RBD-style names | `ceph osd map -f json`, lab cluster, epoch 42 |
| `crushtool-mappings.json` | `crushtool --test --show-mappings` results for x = 0..63: rules 0 and 1, 1 to 3 replicas, and the two `--pool-id` runs | `crushtool`, run on `crush-getcrushmap.hex` |
| `osdmap-e42.client-block.hex` / `.json` | the client-usable block (v10) of the epoch-42 full map | lab cluster |
| `incremental-client-blocks.json` | the client-usable block (v9) of 10 stored incrementals (affinity, upmap items, upmap, primary temp, pg temp, state XOR, CRUSH replace) with the decoded fields | lab monitor store |
| `mosdop-targets.json` | 40 distinct MOSDOp frames from the stock client: object, namespace, pool, `hash` field, pg seed, map epoch, the OSD the TCP connection went to, the acting set our pipeline gives | pcaps (crc mode) |

## Scrubbing

* **No key material.** No keyring, session key, ticket, nonce derived from a key, signature or encrypted blob is
  present. The checker never touches the key files of the capture set.
* Blobs were taken from the maps themselves; the OSDMap client block and the incremental client blocks have the 16-byte
  `fsid` replaced by zeros. The wrapper envelope, the OSD-only block and the CRCs are left out, so the files cannot be
  fed to a CRC-verifying decoder as they are; decode them from the block start with the envelope rules of osdmap.md 2.2.
* `osdmap-e42.client-block.*` still contains the lab daemon addresses (10.77.0.x) and the daemons' address nonces. A
  nonce here is a random process incarnation number, not a secret.
* `mosdop-targets.json` has object names and routing facts only, no payload bytes. Object names are the lab's own
  (`t0-...`, `rbd_*`, image ids of two throw-away lab images).
* The OSD uuids, the blocklist, the per-OSD extended info and the monitor's other state are not in these files.

## Things to know before using the vectors

* **Non-BMP characters in `ceph osd map`.** The monitor receives the object name inside a JSON command. A character above
  U+FFFF (the lab has one, U+1F600) arrives as two surrogate halves, each stored as three UTF-8 bytes (CESU-8), and the
  monitor hashes those bytes, not the four-byte UTF-8 form. A client that hashes the bytes it sends is not affected.
  The `object_hex` fields of `placement-expected.json` are the bytes the monitor hashed.
* `crushtool-mappings.json` with `pool_id_hash2_applied_by_tool` set: the tool maps x through `hash2(x, pool_id)` before
  CRUSH (the note's 5.3 C2 row); x is therefore the post-stable-mod seed, not an object hash.
* The lab map has no `choose_args`, no `uniform`, `list` or `tree` bucket, no `chooseleaf` rule, no erasure pool and
  no pool with a non-power-of-two `pg_num`. Those parts of the note are described from source only (the note says
  which). The stored maps do contain upmap, pg temp, primary temp, reweights and an affinity change, but no mapping
  was captured while they were in force, so for those states the checker can only test consistency (group D2).
* The pcap reassembly found three streams in which the capture itself lost packets (two `k1-rbd-bench-default`
  OSD connections and one `k1-sec-rados-big` OSD connection); parsing of those streams stops at the hole.
