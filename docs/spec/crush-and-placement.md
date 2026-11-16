# CRUSH and object placement: the client subset (replicated pools)

Status: spec note, Phase 0. Pinned release: Ceph v20.2.5 (Tentacle, commit
`ed27c686770872022f4c1de04f6b0ac5d5384ded`). Written in my own words from the source named in
section 1; no Ceph source text is reproduced.

Goal of this note: a later implementer can write a minimal CLIENT that turns "object name in pool P"
into "primary OSD (and acting set)" for a **replicated** pool, bit-exact with a v20.2.5 cluster,
using only this note plus a live cluster for checking. Nothing here is a server.

---

## 1 Scope and sources

### 1.1 Scope

In scope:

- The whole placement pipeline: object name -> hash -> `ps` -> stable modulo against `pg_num` ->
  raw PG -> placement seed (`pps`) -> CRUSH rule evaluation -> raw OSD list -> remove non-existent
  -> `pg_upmap` / `pg_upmap_items` / `pg_upmap_primaries` -> drop down OSDs (up set) -> primary
  affinity -> `pg_temp` / `primary_temp` -> acting set and acting primary.
- The CRUSH map blob as it sits inside an OSDMap (encoding of buckets, rules, tunables, device
  classes, choose_args).
- The CRUSH algorithms a client must re-implement: the 32-bit mixing hashes, `straw2`, the legacy
  bucket algorithms (short form), `choose firstn` / `chooseleaf firstn` with all retry tunables,
  and the rule interpreter.
- A verification plan using `ceph osd map`, `osdmaptool` and `crushtool`.

Out of scope (stated again in section 4): erasure-coded pools and `indep` rules, the multi-step
retry ("MSR") rule family, read-from-replica balancing, cache tiering overlays, and everything
about the wire format of the OSDMap itself except the few fields that placement needs (those are
owned by `docs/spec/osdmap.md`; this note only points at them).

### 1.2 Sources read (all paths relative to the Ceph tree root, tag v20.2.5)

| Area | File |
|---|---|
| CRUSH data structures, opcodes, constants | `src/crush/crush.h` |
| CRUSH hashes | `src/crush/hash.c`, `src/crush/hash.h` |
| CRUSH mapping algorithm | `src/crush/mapper.c`, `src/crush/mapper.h` |
| Fixed-point log tables (data only, see 7) | `src/crush/crush_ln_table.h` |
| Map finalization after decode | `src/crush/builder.c` (`crush_finalize`) |
| CRUSH map encode / decode, tunable profiles, `do_rule` wrapper, device-class shadow trees | `src/crush/CrushWrapper.cc`, `src/crush/CrushWrapper.h` |
| Object-name hash (string) | `src/include/ceph_hash.h`, `src/common/ceph_hash.cc` (the implementation is under `src/common/`, not `src/include/`) |
| Stable modulo, `ceph_pg`, OSD in/out constants | `src/include/rados.h` |
| Pool-side mapping (`hash_key`, `raw_pg_to_pg`, `raw_pg_to_pps`, masks) | `src/osd/osd_types.cc`, `src/osd/osd_types.h` |
| OSDMap-side mapping | `src/osd/OSDMap.cc`, `src/osd/OSDMap.h` |
| What the reference client does with the result | `src/osdc/Objecter.cc` (`_calc_target`), `src/osdc/Objecter.h` |
| Feature bits | `src/include/ceph_features.h` |
| Oracle tools | `src/tools/crushtool.cc`, `src/crush/CrushTester.cc`, `src/tools/osdmaptool.cc`, `src/mon/OSDMonitor.cc` (`osd map`) |
| Known-answer data already in the tree | `src/test/cli/crushtool/*.t`, `*.crushmap`, `src/test/cli/osdmaptool/*.t` |
| Docs | `doc/rados/operations/crush-map.rst` (tunables), `doc/dev/crush-msr.rst` (MSR) |

### 1.3 How this note was checked

Besides reading, I wrote a throw-away scratch implementation (not part of this repository, kept
outside it) of: the string hash, the CRUSH hashes, `crush_ln`, the five bucket algorithms, `choose
firstn`, `choose indep`, the rule interpreter and the CRUSH-map decoder, and compared it against
the expected output that ships with the Ceph tree in `src/test/cli/crushtool/`. Result: **1752
mappings, 0 mismatches**, over these (map, command) pairs, using the first 40 to 64 values of `x`
and a subset of replica counts from each file:

| Expected-output file (`src/test/cli/crushtool/`) | Map file used | Bucket alg | Tunable set exercised | Mappings compared |
|---|---|---|---|---|
| `test-map-jewel-tunables.t` | `test-map-jewel-tunables.crushmap` | straw2 | local 0/0, total 1000, descend_once 1, vary_r 1, stable 1 | 160 |
| `test-map-hammer-tunables.t` | `test-map-hammer-tunables.crushmap` | straw2 | stable 0, vary_r 1 | 120 |
| `test-map-legacy-tunables.t` | `test-map-a.crushmap` | straw | local 2, fallback 5, total 19 (argonaut) | 192 |
| `test-map-bobtail-tunables.t` | `test-map-a.crushmap` + overrides | straw | local 0/0, total 50, descend_once 1 | 192 |
| `test-map-firefly-tunables.t` | `test-map-vary-r.crushmap` + overrides | straw | + vary_r 1 | 192 |
| `test-map-tries-vs-retries.t` | `test-map-tries-vs-retries.crushmap` | straw | descend_once 1, 10 devices out of 16 | 320 |
| `test-map-vary-r-0.t`, `test-map-vary-r-3.t` | `test-map-vary-r.crushmap` | straw | vary_r 0 and 3 | 192 + 192 |
| `test-map-indep.t` | `test-map-indep.crushmap` + overrides | straw | `indep` rule, descend_once 2 | 192 |

Independent re-check (second reviewer, 2026-11): the numeric vectors of section 5.1 (string hashes,
CRUSH hashes `hash1`..`hash4`, `stable_mod`, `pps`, `crush_ln` for the ten listed inputs) were
regenerated by compiling the pinned `hash.c`, `mapper.c` (`crush_ln`) and `ceph_hash.cc` in a scratch
directory outside this repository: all values in 5.1 are reproduced exactly. The table facts of 3.4.2
(129 + 128 exact entries of `RH_LH`, `RH_LH[257]`, the 21 / 212 / 23 split of `LL_tbl`, 63,500 differing
inputs, maximum difference 343,343,104) were recomputed from the pinned header and also agree. The
firstn / chooseleaf procedure of 3.6 was re-implemented from the prose of this note alone and compared
with the expected output in the tree for 688 mappings (jewel, hammer, legacy, bobtail, firefly,
tries-vs-retries, vary-r-0, vary-r-3; the first 16 to 40 values of `x` and a subset of replica counts
each): 0 mismatches. The author's full 1752-mapping figure above was **not** re-run by the reviewer.

What this does NOT cover and is therefore marked **[unverified by a run]** below: `uniform`,
`list` and `tree` bucket algorithms, `choose_args` (weight sets and ids), device-class shadow trees,
MSR rules, and everything from the OSDMap side (upmap, temp, affinity). Those parts are described
from the source only and need the captures in section 5.

---

## 2 Wire structures and constants

All integers little-endian. `sNN` signed, `uNN` unsigned. Notation `S` for a length-prefixed string
is `u32 length` + that many bytes (no terminator).

### 2.1 Where the CRUSH blob lives

The CRUSH map is carried inside the OSDMap as one opaque byte string (`u32 length` + bytes): full
map `crush` field, and in each incremental a `crush` field which, when non-empty, is a **complete
replacement** map (`src/osd/OSDMap.cc:2657-2662`, `src/osd/OSDMap.h:393`). Row numbers and the
envelope versions are in `docs/spec/osdmap.md` (2.4.3 and 2.6.3). The blob itself has **no
struct_v / struct_compat / length envelope**: it starts directly with a magic number and the
decoder just reads fields until the buffer ends (`src/crush/CrushWrapper.cc:3268-3410`).

A decoder consequently has to decide "is there more data?" by buffer end for every trailing group.
Absent trailing groups keep the **legacy** default values (section 2.5), not the current ones
(`CrushWrapper.cc:3283`).

Which optional parts a blob contains depends on the feature mask its encoder was given
(`CrushWrapper.cc:3066-3247`). The monitor encodes the blob inside a full OSDMap, and re-encodes it for
a client, with `features & OSDMap::get_encoding_features()` (`OSDMonitor.cc:2007`, `:4644-4648`),
and that set is a subset of `SIGNIFICANT_FEATURES` (`OSDMap.h:564-578`, `OSDMap.cc:3235-3270`).
`SIGNIFICANT_FEATURES` contains `CRUSH_TUNABLES5`, `CRUSH_CHOOSE_ARGS` and `SERVER_LUMINOUS` but does
**not** contain `CRUSH_MSR` or `SERVER_QUINCY`. Consequence for a v20.2.5 cluster, derived from code
**[confirm on capture, C1/C7]**: the blob a client receives inside an OSDMap normally has
(a) no MSR tunable pair (row 20), and (b) the stored `min_size` / `max_size` bytes in each rule
instead of the constants 1 / 100 (rows 6e / 6f). A blob taken from `ceph osd getcrushmap` is encoded with
the monitor-quorum feature set (`OSDMonitor.cc:5649`) and may therefore differ in exactly those two
places. The same holds for the `crush` field of an incremental: the monitor fills it with the
quorum feature set when an admin command changes the map (`OSDMonitor.cc:7485`, `:7596`, `:9638`),
so an incremental can carry both the MSR pair and the 1 / 100 sizes, while the full map of the same
epoch does not (an incremental is re-encoded for clients only when their significant feature set
differs, `:4610-4635`). A decoder must accept both variants; neither place influences placement of a
replicated pool.

### 2.2 CRUSH blob layout

Source: encode `CrushWrapper.cc:3066-3247`, decode `:3268-3410`, bucket decode `:3412-3513`.

| # | Group | Field | Type | Meaning / rule |
|---|---|---|---|---|
| 1 | header | magic | u32 | must be `0x00010000` (`crush.h:24`); anything else is an error |
| 2 | header | max_buckets | s32 | number of bucket slots (including holes) |
| 3 | header | max_rules | u32 | number of rule slots (including holes) |
| 4 | header | max_devices | s32 | **overwritten after decode, see 2.4** |
| 5 | buckets | `max_buckets` entries, slot `i` holds the bucket with id `-1 - i` | | |
| 5a | | alg_marker | u32 | 0 = empty slot (hole, nothing else follows); otherwise the bucket algorithm, which is repeated in 5d (the decoder reads the marker, validates it as 1..5, then reads 5d again and uses that one: `CrushWrapper.cc:3415-3452`; a client should require both equal) |
| 5b | | id | s32 | negative; must equal `-1 - slot` (the mapper indexes by `-1 - id`, `crush.h:359`). The reference decoder does **not** check this (`CrushWrapper.cc:3449`); a client must check it itself and reject the map otherwise |
| 5c | | type | u16 | bucket type id from `type_map` (0 is reserved for devices) |
| 5d | | alg | u8 | 1 uniform, 2 list, 3 tree, 4 straw, 5 straw2 (`crush.h:141-191`); unknown = malformed |
| 5e | | hash | u8 | 0 = rjenkins1 (the only hash, `hash.h:10`); any other value makes every hash return 0 (`hash.c:96-99`), so reject the map |
| 5f | | weight | u32 | 16.16 fixed point total weight; **not used by straw2 selection** (the parent holds this bucket's weight as an item weight) |
| 5g | | size | u32 | number of items (for a tree bucket the in-memory `size` is documented as the tree size, `crush.h:322`; reject tree buckets anyway) |
| 5h | | items | s32[size] | `>= 0` device id, `< 0` bucket id |
| 5i | | alg tail | | see the table below |
| 6 | rules | `max_rules` entries, slot `i` is rule id `i` | | |
| 6a | | present | u32 | 0 = hole; non-zero = rule follows |
| 6b | | len | u32 | number of steps |
| 6c | | ruleset | u8 | must equal the slot index `i`; otherwise "encoding is too old" and the decode fails (`CrushWrapper.cc:3307-3311`) |
| 6d | | type | u8 | rule type: 1 replicated, 3 erasure, 4 MSR-firstn, 5 MSR-indep (`crush.h:96-101`) |
| 6e | | min_size | u8 | ignored by the mapper (the encoder writes 1 if its feature set has `SERVER_QUINCY`, else the stored value, `:3174-3180`; see the paragraph above on why a full-OSDMap blob normally carries the stored value) |
| 6f | | max_size | u8 | ignored (100 under the same condition, else the stored value) |
| 6g | | steps | `len` x {op u32, arg1 s32, arg2 s32} | 12 bytes per step, no padding (`CrushWrapper.h:37-50`) |
| 7 | names | type_map | `u32 n`, n x {s32 key, `u32 len`, bytes} with the **empty-name quirk** below | type id -> name; client does not need it but must parse past it |
| 8 | names | name_map | same shape | item id (device or bucket, shadow buckets included) -> name |
| 9 | names | rule_name_map | same shape | rule id -> name |
| 10 | tunables A | choose_local_tries, choose_local_fallback_tries, choose_total_tries | 3 x u32 | present or absent as a group |
| 11 | tunables B | chooseleaf_descend_once | u32 | each group below is present only if buffer remains |
| 12 | tunables C | chooseleaf_vary_r | u8 | |
| 13 | tunables D | straw_calc_version | u8 | **irrelevant to mapping** (only used when building straw buckets; the `straws` array is stored) |
| 14 | tunables E | allowed_bucket_algs | u32 | bitmask over alg ids; irrelevant to mapping |
| 15 | tunables F | chooseleaf_stable | u8 | written only if the receiving client has the `CRUSH_TUNABLES5` feature (`:3199-3201`) |
| 16 | classes | class_map | `u32 n`, n x {s32 item, s32 class id} | device -> class; not needed for mapping |
| 17 | classes | class_name | `u32 n`, n x {s32 class id, S name} | not needed |
| 18 | classes | class_bucket | `u32 n`, n x {s32 bucket id, `u32 m`, m x {s32 class id, s32 shadow bucket id}} | not needed for mapping (see 2.6) |
| 19 | choose_args | count | u32 | number of choose_args sets; written only if the encoder's feature set has `SERVER_LUMINOUS` (`:3203-3242`); `SERVER_LUMINOUS` is in `SIGNIFICANT_FEATURES`, so a normal Tentacle blob has it |
| 19a | | set key | s64 | pool id, or `-1` = the default set (`std::map<int64_t,...>`, `CrushWrapper.h:69`; `DEFAULT_CHOOSE_ARGS = -1`, `:55-59`) |
| 19b | | n_buckets | u32 | number of buckets that carry an override |
| 19c | | bucket_index | u32 | slot index (`-1 - id`); must be below max_buckets (the reference asserts, `:3371`). Only buckets with weight rows or ids are listed (`:3216-3222`); a set can therefore list zero buckets. Listed in ascending slot order by the encoder, but do not rely on it |
| 19d | | weight_set_positions | u32 | number of weight-set rows (0 = none) |
| 19e | | per row | u32 size, then u32 weights[size] | 16.16; `size` must equal the bucket size |
| 19f | | ids_size | u32 | 0 = none; otherwise must equal the bucket size |
| 19g | | ids | s32[ids_size] | substitute ids used only as hash input |
| 20 | MSR tunables | msr_descents, msr_collision_tries | 2 x u32 | written only if the encoder's feature set has `CRUSH_MSR` (`CrushWrapper.cc:3243-3246`), which a full-OSDMap blob normally does not (paragraph in 2.1); absent: defaults 100 / 100 (`CrushWrapper.h:242-245`, `CrushWrapper.cc:3400`). Irrelevant to firstn rules |

Items 16-18 are written/read as a unit gated on one `blp.end()` test, items 19-19g likewise, and 20
likewise (`CrushWrapper.cc:3349-3402`). Ordering on the wire is exactly the order in the table.

**Empty-name quirk of rows 7-9** (`CrushWrapper.cc:3249-3266`, comment at `:3321-3323`): an old encoder
wrote the map key as 64 bits instead of 32. The reference decoder therefore reads the `s32` key and
the `u32` length, and **if that length is 0 it reads one more `u32` and takes that as the real length**
(the upper half of a 64-bit key). The current encoder always writes 32-bit keys
(`CrushWrapper.cc:3187-3189`, plain `map<s32,string>` encoding; `CrushWrapper.h:61-63`), so the
tolerance matters only for blobs from old clusters, but it also means a zero-length name cannot
round-trip, and a skipper that always reads exactly `len` bytes after the first `u32` gets out of step
on such an entry. A skipper should apply the same rule. `class_name` (rows 16-18) has no such
tolerance (`CrushWrapper.cc:3350-3354`, plain `decode`); a skipper for rows 16-18
reads `u32 n` + n x {s32, s32}, then `u32 n` + n x {s32, `u32 len`, bytes}, then `u32 n` + n x
{s32, `u32 m`, m x {s32, s32}}.

Per-algorithm tail (row 5i):

| alg | Tail bytes | Used by mapping |
|---|---|---|
| 1 uniform | `u32 item_weight` (one weight for every item) | no (only `size`, `items`, `id`) |
| 2 list | `size` x {u32 item_weight, u32 sum_weight} | yes (`sum_weight` is the running total of weights from the start of the list up to and including that item, as stored; use it as given) |
| 3 tree | `u8 num_nodes`, then `u32 node_weights[num_nodes]` | yes; **tree is legacy and described as buggy in the source (`crush.h:195-197`); reject** |
| 4 straw | `size` x {u32 item_weight, u32 straw} | `straw` yes |
| 5 straw2 | `u32 item_weights[size]` | yes |

Weights are 16.16 fixed point: `0x10000` is 1.0. A device's weight is conventionally its capacity in
TiB; `crush.h:29-30` caps a device at `100 * 0x10000` and a bucket at `65535 * 0x10000`.

### 2.3 Constants a client needs

| Name | Value | Source |
|---|---|---|
| `CRUSH_ITEM_NONE` | `0x7fffffff` | `crush.h:36` |
| `CRUSH_ITEM_UNDEF` (internal) | `0x7ffffffe` | `crush.h:32` |
| max hierarchy depth | 10 | `crush.h:26` |
| max rules | 256 | `crush.h:27` |
| rule opcodes | 0 NOOP, 1 TAKE, 2 CHOOSE_FIRSTN, 3 CHOOSE_INDEP, 4 EMIT, 6 CHOOSELEAF_FIRSTN, 7 CHOOSELEAF_INDEP, 8 SET_CHOOSE_TRIES, 9 SET_CHOOSELEAF_TRIES, 10 SET_CHOOSE_LOCAL_TRIES, 11 SET_CHOOSE_LOCAL_FALLBACK_TRIES, 12 SET_CHOOSELEAF_VARY_R, 13 SET_CHOOSELEAF_STABLE, 14 SET_MSR_DESCENTS, 15 SET_MSR_COLLISION_TRIES, 16 CHOOSE_MSR | `crush.h:51-75` |
| step "count" argument | arg1 `> 0` means that many, `0` or negative means `result_max + arg1` | `mapper.c:938-945` |
| `ceph_pg` pool types | 1 replicated, 3 erasure | `rados.h:81-83` |
| string hash ids | 1 linux dcache, 2 rjenkins | `ceph_hash.h:4-5` |
| OSD in / out reweight | `0x10000` / `0` | `rados.h:141-143` |
| primary affinity max / default | `0x10000` / `0x10000` | `rados.h:145-146` |
| OSD state bits used here | `EXISTS` = bit 0, `UP` = bit 1 | `rados.h:125-126` |
| pool flag `HASHPSPOOL` | bit 0 of `pg_pool_t.flags` | `osd_types.h:1281` |

### 2.4 Post-decode fix-ups the reference performs (a client must reproduce them)

After decoding, the reference calls `update_choose_args(nullptr)` and then `finalize()`
(`CrushWrapper.cc:3403-3404`):

1. `max_devices` is **recomputed**: one more than the largest non-negative item id found in any
   bucket (`src/crush/builder.c:30-61`), then raised to one more than the largest key of `name_map`
   if that is larger (`CrushWrapper.h:1382-1390`). The value on the wire (row 4) is discarded. Effect:
   `max_devices` is the bound for "is this a legal device id" in the mapper (`mapper.c:512`, `:878`);
   a client that does not parse `name_map` should use `1 + max(item id in buckets)`, which is
   enough for every case where a bucket item is selected. This bound is also checked by a `take` of
   a device. Do not confuse it with the length of the OSD reweight array handed to the mapper: that
   array has `max_osd` entries (`CrushWrapper.h:1609-1610` passes its size as `weight_max`), and
   `is_out` (3.5) uses that length, not `max_devices`.
2. `update_choose_args` (`CrushWrapper.cc:442-505`), per choose_args set: for a slot that is empty or
   whose bucket is not straw2 it discards that slot's `ids` and weight rows; for a slot whose number
   of weight rows differs from the set's common row count (taken from the first slot that has any,
   `CrushWrapper.h:1590-1598`) it logs and leaves the slot as it is; for a row whose length differs
   from the bucket size it re-allocates the row at the bucket size, copying the common prefix and
   zero-filling the rest. A well-formed map from a v20.2.5 monitor should not need any of this; a
   client may reject the map if any of these conditions occurs. **[unverified by a run]**

### 2.5 Tunables: defaults, profiles, and what a v20.2.5 server sends

Values that a decoded map carries are what the mapper uses; the profile names only describe
common combinations (`CrushWrapper.h:108-178`, `doc/rados/operations/crush-map.rst:782-960`).

| Tunable | Decode default if absent ("legacy" / argonaut) | Bobtail | Firefly / Hammer | Jewel = `optimal` in v20.2.5 |
|---|---|---|---|---|
| choose_local_tries | 2 | 0 | 0 | 0 |
| choose_local_fallback_tries | 5 | 0 | 0 | 0 |
| choose_total_tries | 19 | 50 | 50 | 50 |
| chooseleaf_descend_once | 0 | 1 | 1 | 1 |
| chooseleaf_vary_r | 0 | 0 | 1 | 1 |
| chooseleaf_stable | 0 | 0 | 0 | 1 |
| straw_calc_version | 0 | not set by the profile | not set by the profile | 1 (set by `optimal`; unused for mapping) |
| allowed_bucket_algs | uniform+list+straw (0x16) | same | Hammer adds straw2 | uniform+list+straw+straw2 = `0x36` |
| msr_descents / msr_collision_tries | 100 / 100 | 100 / 100 | 100 / 100 | 100 / 100 |

`set_tunables_optimal` = jewel values with `straw_calc_version = 1` (`CrushWrapper.h:171-178`). A
fresh map from `osdmaptool --createsimple` prints exactly the Jewel column, with
`allowed_bucket_algs 54` (= 0x36) (`src/test/cli/osdmaptool/create-print.t:10-17`). Test maps in
the tree use other values (the Jewel test map has `choose_total_tries 1000`), so always use the
decoded values.

What the v20.2.5 monitor sends to a client depends on the features that client advertised: the full
map is re-encoded with `client features & encoding features` when they differ from the canonical set
(`OSDMonitor.cc:4638-4649`, called from `:4816` only if the client's significant feature set differs from the quorum's), and the CRUSH encoder switches on the feature
bits of that set (`CrushWrapper.cc:3066-3247`; the feature bits are in 2.8):

- Without `CRUSH_TUNABLES5`: no `chooseleaf_stable` byte, so the client would assume 0 and place
  differently from the cluster. The cluster refuses such clients when the map uses stable
  chooseleaf: `get_features` adds `CRUSH_TUNABLES5` to the required set when a tunable is non-default
  or a rule needs it (`OSDMap.cc:1767-1768`, `:1797-1798`).
- Without `SERVER_LUMINOUS` (shares its bit with `OSDMAP_PG_UPMAP` and `CRUSH_CHOOSE_ARGS`): no class
  section and no choose_args. If a single default (`-1`) weight set exists it is folded into the
  bucket weights: position-0 row replaces the plain weights (`:3130-3143`, and the encoder asserts
  there is no "incompatible" set, `:3083`). "Incompatible" means more than one set or a set whose key
  is not `-1` (`CrushWrapper.cc:186-193`); such maps make the monitor demand `CRUSH_CHOOSE_ARGS` from
  clients (`OSDMap.cc:1769-1770`). So a client without the feature either is refused or gets a map
  where only position 0 is represented.
- `CRUSH_MSR` and `SERVER_QUINCY` are not part of the OSDMap encoding feature set (2.1), so the MSR
  tunable pair and the 1 / 100 rule sizes do not appear in blobs inside a full OSDMap whatever the
  client advertises. The monitor does demand `CRUSH_MSR` from a client when non-default MSR tunables
  or MSR rules exist (`OSDMap.cc:1771-1773`).

Conclusion: the client should advertise the full feature set so that it receives the canonical,
complete encoding (see `docs/spec/osdmap.md` 2.8).

### 2.6 Device classes and shadow trees (what a client sees)

A rule such as "take default class hdd" is stored as a plain `take` step whose `arg1` is the id of a
**shadow bucket**. Shadow buckets are ordinary entries in the bucket array (negative ids), with the
same algorithm, hash and type as the bucket they clone, containing only the devices of that class
and the shadow clones of child buckets; their names are `<name>~<class>` and are not valid user
names (`CrushWrapper.cc:2818-2938` building, `CrushWrapper.h:607-610` naming, `:2320-2335` rule
creation using `class_bucket[root][class]`). Consequences for a client:

- The client does **not** need `class_map`, `class_name` or `class_bucket`; the rule already names
  the shadow root.
- Shadow buckets are real buckets with their own weights; each also has its own choose_args entry if
  weight sets exist (weight rows are copied per position, `:2904-2940`), but the substitute `ids`
  array is **not** cloned (`ids_size` is set to 0, `:2918`), so inside a shadow bucket the hash input
  is always the shadow bucket's own item ids. A straw2 hash input is the item id only (never the
  bucket's own id), so the shadow copy of a bucket draws from the same hash inputs as the original for
  its device items. Nothing special in the mapper.
- A leaf item's device class is irrelevant at mapping time.

### 2.7 Other maps and pool fields that the pipeline reads

Wire layouts are in `docs/spec/osdmap.md`; this is only the list of what placement consumes.

| Item | Where | Used in |
|---|---|---|
| `pg_pool_t.type` (u8), `size` (u8), `crush_rule` (u8), `object_hash` (u8), `pg_num` (u32), `pgp_num` (u32), `flags` (u64) | `osd_types.h:1477-1485`, decode `osd_types.cc:2090-2292` | everything |
| `pg_num_mask`, `pgp_num_mask` | **not on the wire**; computed after decode (`osd_types.cc:2289`, formula 3.2) | stable modulo |
| `read_tier`, `write_tier` (s64, -1 = none) | `osd_types.h:1540-1541` | overlay redirect, refuse |
| `OSDMap.max_osd` (s32), `osd_state[]` (u32 per OSD), `osd_weight[]` (u32 per OSD) | `OSDMap.h:553-554`, `:591`, `:895-914`; wire `OSDMap.cc:3781-3792` | existence, up/down, CRUSH reweight input (array length = `max_osd`), upmap checks |
| `osd_primary_affinity[]` (u32 per OSD; the wire vector may be empty, which the decoder turns into "absent", `OSDMap.cc:3800-3805`) | `OSDMap.h:596` | affinity |
| `pg_temp`: map pg -> list of s32 (wire = `u32 n` then n x {pg_t (17 bytes, `docs/spec/osdmap.md` 2.1.1), `u32 count`, s32[count]}) | `OSDMap.h:115-130` | acting |
| `primary_temp`: map pg -> s32 | `OSDMap.h:595` | acting primary |
| `pg_upmap`: map pg -> list of s32; `pg_upmap_items`: map pg -> list of (s32 from, s32 to); `pg_upmap_primaries`: map pg -> s32 (client block v10 only) | `OSDMap.h:599-601`, encode `OSDMap.cc:3483-3504` | upmap |
| CRUSH blob | 2.1 | CRUSH |

Applying incrementals to these (important for correctness of the cache): a `new_pg_temp` entry with
an empty list erases the entry; a `new_primary_temp` of -1 erases the entry; `old_pg_upmap`,
`old_pg_upmap_items`, `old_pg_upmap_primary` erase (`OSDMap.cc:2549-2586`; the `new_*` of each kind
is applied before the `old_*` of the same kind, so an id in both ends up erased). OSDs
beyond `max_osd` (when the array grows) get weight 0 = out, state 0, affinity `0x10000`
(`OSDMap.cc:1549-1566`). `new_primary_affinity` entries set the affinity (`OSDMap.cc:2473-2475`;
the `new_weight` loop is at `:2462-2471`, before it). An incremental `new_state` that toggles `EXISTS` on
an existing OSD ("destroy") also resets that OSD's affinity to the default (`:2494-2500`). The state
mask is XOR, with 0 meaning "toggle UP" (`:2486-2493`, details in `docs/spec/osdmap.md` 3.5).

Pool fields that the mapping does **not** use: `pg_num_pending`, `pg_num_target`, `pgp_num_target`
(`osd_types.h:1486-1488`): the reference uses `pg_num` and `pgp_num` only (`osd_types.cc:1809`,
`:1817`, `:1832`). Pool flag `FLAG_EIO` makes the reference client fail the op instead of mapping it
(`Objecter.cc:2965-2967`); `read_tier` / `write_tier` redirect the pool of the op unless the op carries
the ignore-overlay flag (`Objecter.cc:2985-2995`).

### 2.8 Feature bits relevant to this note

A feature is present only if its whole "mask" (bit plus incarnation marker bits) is set
(`ceph_features.h:12-17`, `:38-42`); the masks are tabulated in `docs/spec/osdmap.md` 2.7.4. The
ones that change what CRUSH-related data a client receives or may be required of it:

| Feature | Bit | Why it matters here | Source |
|---|---|---|---|
| CRUSH_TUNABLES, _TUNABLES2, _TUNABLES3 (same bit as OSD_PRIMARY_AFFINITY), _V2, _V4 (straw2) | 18, 25, 41, 36, 48 | needed to decode / use non-legacy tunables, straw2, firefly chooseleaf, primary affinity | `ceph_features.h:108`, `:124`, `:145-146`, `:140`, `:158` |
| CRUSH_TUNABLES5 | 58 | `chooseleaf_stable` byte present | `:178`, `CrushWrapper.cc:3199` |
| SERVER_LUMINOUS = OSDMAP_PG_UPMAP = CRUSH_CHOOSE_ARGS | 21 (+57) | class section, choose_args, upmap | `:114-118` |
| OSDHASHPSPOOL | 30 | the server requires it from clients when any pool has HASHPSPOOL | `:130`, `OSDMap.cc:1784-1785` |
| SERVER_REEF | 31 (+57, 28) | `pg_upmap_primaries` (client block v10); server requires it from clients once any entry exists | `:132`, `OSDMap.cc:1779-1781` |
| CRUSH_MSR | 38 (+57) | required from clients if MSR tunables are non-default or MSR rules exist; **not** in `SIGNIFICANT_FEATURES`, so it never selects a different encoding of a full OSDMap | `:142`, `OSDMap.cc:1771-1773`, `OSDMap.h:564-578` |
| SERVER_QUINCY | 33 (+57, 28) | selects the constant 1 / 100 rule min / max bytes in the CRUSH encoder; not in `SIGNIFICANT_FEATURES` | `:136`, `CrushWrapper.cc:3174` |
| SERVER_TENTACLE | 50 (+57) | pool struct version 32 | `:163`, `osd_types.cc:1968` |

---

## 3 Client procedure

Notation: `u32` arithmetic wraps modulo 2^32 unless stated. `>>` on unsigned is logical. Function
names are mine.

### 3.1 Object name to 32-bit seed (`ps`)

Source: `osd_types.cc:1794-1805`, `OSDMap.cc:2704-2735`.

1. Let `name` be the object name bytes; let `key` be the locator key (empty for RBD data objects,
   which use no locator key; the name is used); let `ns` be the namespace (empty unless the
   image lives in an RBD namespace).
2. If the request carries an explicit locator hash `>= 0` (not used by RBD), `ps` is that value
   (`OSDMap.cc:2727-2732`). Otherwise `subject = key` if key non-empty, else `name`.
3. If `ns` is empty, hash `subject`. If `ns` is non-empty, hash the byte string
   `ns || 0x1f || subject` (single byte `0x1f` separator).
4. The hash is the pool's `object_hash`: `2` = rjenkins string hash (3.1.1), `1` = Linux dcache
   hash (3.1.2). The monitor always creates pools with `2` (`OSDMonitor.cc:8266`). Any other id
   makes the reference return `0xffffffff` cast from -1 (`ceph_hash.cc:102-103`); treat as
   unsupported pool.
5. The raw PG is `(pool_id, ps)` with the full 32-bit `ps` (no masking yet). The same full `ps` is
   what the reference puts in the request's object hash field (`Objecter.h:1893-1900`), so keep it.

#### 3.1.1 rjenkins string hash

State: three u32 variables `a`, `b`, `c`. Initial `a = b = 0x9e3779b9`, `c = 0`. `len` = number of
input bytes still unconsumed, `n` = original length (`ceph_hash.cc:22-78`).

- While at least 12 bytes remain: read three little-endian u32 words from the next 12 bytes; add the
  first to `a`, the second to `b`, the third to `c`; run `mix(a,b,c)` (3.2.1); advance 12 bytes.
- Tail: first `c = c + n` (the total original length, not the remaining one). Then add the
  remaining 1..11 bytes `k[0..len-1]` as follows (no effect for `len = 0`):
  - bytes 0-3 form `a`'s little-endian word: add `k[0]`, `k[1] << 8`, `k[2] << 16`, `k[3] << 24` to `a`
    (only for those indexes below `len`);
  - bytes 4-7 likewise into `b` (`k[4]`, `k[5] << 8`, `k[6] << 16`, `k[7] << 24`);
  - bytes 8-10 into `c` but **shifted up by one byte** because `c`'s low byte holds the length:
    `k[8] << 8`, `k[9] << 16`, `k[10] << 24`.
- Run `mix(a,b,c)` once more and return `c`. This final mix always runs, including for an empty
  string and when the length is a multiple of 12.

The same nine-round `mix` is used by the CRUSH hashes (3.2.1). The source marks the original as
public domain (`ceph_hash.cc:4-7`).

#### 3.1.2 Linux dcache string hash

`h = 0`; for each byte `c` (unsigned): `h = (h + (c << 4) + (c >> 4)) * 11` in u32. Return `h`
(`ceph_hash.cc:83-92`). Implement only if you decide to support legacy pools.

### 3.2 `ps` to PG, placement seed, CRUSH input

Source: `osd_types.cc:1671-1675`, `:1815-1842`, `rados.h:96-102`, `Objecter.cc:3017-3025`.

Definitions:

- `cbits(v)` = number of bits needed to represent `v` (0 for 0, 1 for 1, 4 for 8..15, 5 for 16..31)
  (`src/include/intarith.h:114-118`).
- `pg_num_mask = (1 << cbits(pg_num - 1)) - 1`, `pgp_num_mask = (1 << cbits(pgp_num - 1)) - 1`,
  recomputed after every pool decode (`osd_types.cc:1671-1675`, `:2289`). For `pg_num = 1` the mask
  is 0.
- `stable_mod(x, b, bmask)`: if `(x & bmask) < b` return `x & bmask`, else return
  `x & (bmask >> 1)`. (`b <= bmask + 1`, `bmask` = 2^k - 1; `rados.h:96-102`, comment says public
  domain.)

Steps:

1. `pg_seed = stable_mod(ps, pg_num, pg_num_mask)`. The PG the OSDs and the monitor know is
   `(pool_id, pg_seed)`. The key for `pg_temp`, `primary_temp`, `pg_upmap*` lookups is this masked PG
   (`OSDMap.cc:2805`, `:3064`). The reference client does this masking itself before calling the
   mapper (`Objecter.cc:3024-3025`) and puts this masked PG in the request as the "actual pgid".
2. Placement seed for CRUSH:
   - if pool flag `HASHPSPOOL` is set: `pps = rjenkins2(stable_mod(ps, pgp_num, pgp_num_mask),
     pool_id)` using the CRUSH two-input hash (3.2.1), pool id truncated to u32;
   - otherwise (legacy pool): `pps = stable_mod(ps, pgp_num, pgp_num_mask) + pool_id` (u32 add).
   Note the **second** modulus uses `pgp_num`, not `pg_num`; they differ while a pool is splitting.
   The reference callers differ in what they hand to the mapper: the Objecter and `ceph osd map` pass
   the `pg_num`-masked pg (`Objecter.cc:3024-3029`, `OSDMonitor.cc:5912-5916`), while `ceph pg map`
   passes the pg as typed (`OSDMonitor.cc:5959-5960`), and the mapper accepts either
   (`OSDMap.cc:3142-3144`, default `raw_pg_to_pg = true`). Both orders give the same `pps`, because the
   monitor enforces `pgp_num <= pg_num` (`OSDMonitor.cc:8127`, `:8727`): checked exhaustively by the
   reviewer for `pg_num` 1..299, every `pgp_num <= pg_num` and 600+ values of `ps` including
   `0xffffffff`. A client may therefore mask first, as the reference client does, and use the masked
   value in the formula above.
   `ceph_stable_mod` takes **signed** `int` arguments in C (`rados.h:96`); with a mask below 2^31 the
   result is the same as with unsigned arithmetic, so a `u32` implementation is fine.
3. `pps` is the CRUSH input `x`.

#### 3.2.1 CRUSH hash functions

Source: `crush/hash.c:12-90`, seed constant `:24`. Only `rjenkins1` exists (`hash.h:10`). All
arguments are taken as u32 (negative bucket ids and negative `r` convert by two's complement).

`mix(a, b, c)`: nine rounds, variables updated in place, all arithmetic u32. Each round has the
form `t = t - u - v` followed by `t = t XOR (w shifted)` where `(t, u, v, w)` cycle as:

| Round | t | minus | minus | then XOR with |
|---|---|---|---|---|
| 1 | a | b | c | `c >> 13` |
| 2 | b | c | a | `a << 8` |
| 3 | c | a | b | `b >> 13` |
| 4 | a | b | c | `c >> 12` |
| 5 | b | c | a | `a << 16` |
| 6 | c | a | b | `b >> 5` |
| 7 | a | b | c | `c >> 3` |
| 8 | b | c | a | `a << 10` |
| 9 | c | a | b | `b >> 15` |

(Left shifts drop high bits: `x << s` is computed in u32.)

Constants: `seed = 1315423911` (`0x4E67C6A7`), `X = 231232`, `Y = 1232`. In each hash below `h` is a
fresh accumulator; `mix(p, q, r)` means the roles (a, b, c) of the table are played by the named
variables **by reference**, so later `mix` calls see the updated values of every variable.

| Function | Initial `h` | Sequence of mixes |
|---|---|---|
| `hash2(a, b)` | `seed ^ a ^ b` | `mix(a,b,h)`, `mix(X,a,h)`, `mix(b,Y,h)` |
| `hash3(a, b, c)` | `seed ^ a ^ b ^ c` | `mix(a,b,h)`, `mix(c,X,h)`, `mix(Y,a,h)`, `mix(b,X,h)`, `mix(Y,c,h)` |
| `hash4(a, b, c, d)` | `seed ^ a ^ b ^ c ^ d` | `mix(a,b,h)`, `mix(c,d,h)`, `mix(a,X,h)`, `mix(Y,b,h)`, `mix(c,X,h)`, `mix(Y,d,h)` |

`X` and `Y` are local variables initialised to the constants at the start of every call; the second
and later mixes consume them (and modify them). Result is `h`. The one-input and five-input
variants (`hash.c:26-35`, `:75-90`) are never called by the mapper; they are needed only if you
want to reproduce `crushtool` self-tests. **[verified against 1752 reference mappings via
scratch implementation, section 1.3; independent hash vectors in 5.1]**

### 3.3 Running the rule (`do_rule`)

Inputs: map, rule id `R = pool.crush_rule`, `x = pps`, `result_max = pool.size`, the per-OSD
reweight array `osd_weight[0..max_osd-1]` (`OSDMap.cc:2773-2791`, wrapper `CrushWrapper.h:1601-1617`),
and the choose_args set selected by **pool id**: use the set whose key equals the pool id; if none,
the set with key `-1`; if none, no override (`CrushWrapper.h:1471-1484`, `:1607-1608`).

If `R >= max_rules` the result is empty (`mapper.c:2023-2026`). The dispatcher does **not** check
for an empty rule slot (it reads the rule's type right away, `mapper.c:2028-2029`), so a client must
itself treat "the pool's rule id has no rule" as an error and not as an empty mapping.
The dispatcher sends rules of type 4 or 5 to the MSR interpreter (`mapper.c:2029-2039`); type 1
(replicated) goes to the classic interpreter described here. A replicated pool may legally point at
an MSR-firstn rule (`CrushWrapper.h:593-605`); see section 4.

Interpreter state (`mapper.c:826-1032`): two arrays `w` (working set) and `o` (output of the
current choose step) plus a third `c` for chooseleaf results, each of size `result_max`;
`wsize` entries valid in `w`. Per-run tunables start from the map:
`choose_tries = choose_total_tries + 1` (the stored total is a number of *retries*; the
interpreter loop counts *attempts*, so it is one larger; `mapper.c:848-853`), `choose_leaf_tries = 0`,
`local_retries = choose_local_tries`, `local_fallback_retries = choose_local_fallback_tries`,
`vary_r = chooseleaf_vary_r`, `stable = chooseleaf_stable` (`mapper.c:852-862`). The `SET_*` steps
change these copies only for the rest of this run; the next `do_rule` starts again from the map.

For each step in order:

| Opcode | Action |
|---|---|
| TAKE (1) | if `arg1` is a device id `0 <= arg1 < max_devices`, or a bucket id whose slot exists: `w = [arg1]`, `wsize = 1`; otherwise leave `w` unchanged (no error) |
| SET_CHOOSE_TRIES (8) | if `arg1 > 0`: `choose_tries = arg1` |
| SET_CHOOSELEAF_TRIES (9) | if `arg1 > 0`: `choose_leaf_tries = arg1` |
| SET_CHOOSE_LOCAL_TRIES (10) | if `arg1 >= 0`: `local_retries = arg1` |
| SET_CHOOSE_LOCAL_FALLBACK_TRIES (11) | if `arg1 >= 0`: `local_fallback_retries = arg1` |
| SET_CHOOSELEAF_VARY_R (12) | if `arg1 >= 0`: `vary_r = arg1` |
| SET_CHOOSELEAF_STABLE (13) | if `arg1 >= 0`: `stable = arg1` |
| CHOOSE_FIRSTN (2), CHOOSELEAF_FIRSTN (6) | see below |
| CHOOSE_INDEP (3), CHOOSELEAF_INDEP (7) | out of scope; see 3.8 |
| EMIT (4) | append `w[0..wsize)` to the result, stopping at `result_max` entries; `wsize = 0` |
| NOOP (0), anything else | ignored |

The firstn choose step (`mapper.c:920-1013`): if `wsize == 0` do nothing. Otherwise `osize = 0` and
for each `w[i]`:

1. `numrep = arg1`; if `numrep <= 0`, `numrep += result_max`; if still `<= 0`, skip this `w[i]`.
2. `bno = -1 - w[i]`; if `bno` is outside `[0, max_buckets)` (this includes devices and
   `CRUSH_ITEM_NONE`), skip this `w[i]` (so a `choose` after `take <device>` produces nothing).
3. `recurse_tries` = `choose_leaf_tries` if non-zero, else `1` if the map's
   `chooseleaf_descend_once` is set, else `choose_tries`.
4. Call `choose_firstn` (3.6) on bucket `bno` with: `numrep`, `type = arg2`, an output vector that
   starts empty (outpos 0) for **this call** (collisions are detected only among the results of this
   one call, not across different `w[i]`), at most `result_max - osize` results, `tries =
   choose_tries`, `recurse_tries`, the local-retry values, `leaf mode` = (opcode is CHOOSELEAF),
   `vary_r`, `stable`, a leaf output vector, `parent_r = 0`. It returns the number of results `n`;
   append them to `o` at `osize` (and the leaf results to `c`), `osize += n`.
5. After all `w[i]`: if leaf mode, copy `c[0..osize)` into `o` (so the chosen leaves, not the
   intermediate buckets, are what the next step sees); swap roles of `w` and `o`; `wsize = osize`.

The result list can be shorter than `result_max` (fewer devices found); firstn never pads with
`CRUSH_ITEM_NONE`.

### 3.4 Selecting an item inside one bucket

`choose_in_bucket(bucket, x, r, position)` returns the chosen item (device or bucket id). The bucket
must have `size > 0` (the mapper asserts; callers test emptiness first, 3.6). `position` is used
only by straw2 with weight sets and is the number of results already placed by the current
`choose_firstn` call chain, i.e. `outpos` (`mapper.c:507-511`; it restarts at 0 for every `w[i]`, see 3.6). The
`indep` variant passes its own `outpos` the same way (`:717-721`).

#### 3.4.1 straw2 (alg 5) - the one that matters

Source: `mapper.c:229-365`. For each item index `i` in order:

1. If the item's weight is 0, its draw is "minus infinity" (smallest possible signed 64-bit value,
   so it never wins unless every item has weight 0, in which case index 0 wins; see tie rule).
2. Otherwise: `u = hash3(x, id_i, r) & 0xffff`, where `id_i` is the item id, **or** the substitute id
   from the matching choose_args `ids` array if one exists. `ln = crush_ln(u) - 0x1000000000000`
   (a negative or zero signed 64-bit number; 3.4.2). `draw = ln / weight_i` with **signed 64-bit
   division truncating toward zero**.
3. Choose the item with the largest `draw`; on equal draws the **first** (lowest index) wins
   (strictly-greater comparison, index 0 initialises the maximum).

Details:

- `weight_i` is the bucket's stored item weight, or, if a choose_args set with `weight_set_positions
  > 0` applies to this bucket, row `min(position, positions - 1)` of that weight set
  (`mapper.c:290-299`). The `ids` array replaces only the hash input; the **returned** item is
  always the real `items[]` entry (`:364`).
- The weight is passed through a C `int` parameter (`mapper.c:315-340`), so a weight of `0x80000000`
  or more would be treated as negative. This cannot occur for a bucket sum below 32768 weight
  units; a client should still cast the weight to signed 32 bits before dividing to be bit-exact.
- A choose_args set is looked up by bucket **slot**: entry `-1 - bucket.id` (`mapper.c:510`).
- The draw does not depend on any other item's weight, which is what makes straw2 stable under
  reweighting.

#### 3.4.2 `crush_ln(u)`: fixed-point log (input 0..0xffff)

Source `mapper.c:229-271`; tables in `crush_ln_table.h` (**data not copied here**, see 7). Result
is an unsigned 64-bit approximation of `2^44 * log2(u + 1)`.

1. `x = u + 1` (range 1..0x10000). `iexpon = 15`.
2. If bits 15 and 16 of `x` are both clear (`x < 0x8000`): shift `x` left until bit 15 is set
   (`bits = 16 - bit_length(x)`, so 15 for `x = 1` and 1 for `x = 0x7fff`) and `iexpon = 15 - bits`.
   Otherwise no shift. After this `x` is in `0x8000..0x10000`.
3. `index1 = (x >> 8) << 1` (even, 256..512).
4. `RH = RH_LH[index1 - 256]`, `LH = RH_LH[index1 + 1 - 256]` (table `RH_LH` has 258 entries; see
   below for its content).
5. `xl = (x * RH) >> 48` computed in **unsigned 64-bit** (`x <= 0x10000`, `RH <= 2^48`; the product
   cannot overflow u64). `index2 = xl & 0xff`.
6. `LL = LL_tbl[index2]` (table `LL_tbl` has 256 entries).
7. Return `(iexpon << 44) + ((LH + LL) >> 4)` in u64.

What the tables contain (my measurements against the pinned header, scratch computation with
80-digit decimals):

- `RH_LH[2k]` (k = 0..128) = `ceil(2^48 / (1 + k/128))`: exact match for all 129 entries.
- `RH_LH[2k+1]` (k = 0..127) = `floor(2^48 * log2(1 + k/128))`: exact match for all 128 entries.
- `RH_LH[257]` (k = 128): **not** `2^48` but `2^48 - 2^32` (`0x0000ffff00000000`), a deliberate
  fudge; with it `crush_ln(0xffff) = 0xfffff0000000`.
- `LL_tbl[k]` (k = 0..255) is documented in the source as `2^48 * log2(1 + k/2^15)` but is **not**
  that function (compared against the floor of the exact value): 21 entries equal it (including
  entries 0 and 1), 212 equal it plus a near-constant `5,493,489,664` (0x147700000, deviating by at
  most 1), and the remaining 23 differ by other amounts. **It cannot be regenerated from a
  formula.**
  Replacing it with the exact formula values changes `crush_ln` for 63,500 of the 65,536 inputs
  (max difference 343,343,104), and although none of 400 test mappings changed, a table that is not
  bit-identical will eventually mis-place some objects. This is the biggest problem in this note;
  see 6 and 7.

#### 3.4.3 straw (alg 4, legacy) **[unverified beyond the straw test maps in 1.3]**

For each item `i`: `draw_i = (hash3(x, items[i], r) & 0xffff) * straws[i]` (u64, `straws[i]` is
the stored 32-bit value). The largest draw wins; first index wins ties. (`mapper.c:208-226`.) The
`straws` array is decoded as stored; `straw_calc_version` is only for building maps.

#### 3.4.4 list (alg 2, legacy) **[unverified by a run]**

Walk `i` from `size - 1` down to `0`: `w = hash4(x, items[i], r, bucket_id) & 0xffff`; `w = (w *
sum_weights[i]) >> 16` (u64); if `w < item_weights[i]` return `items[i]`. If none qualifies return
`items[0]`. (`mapper.c:122-145`.)

#### 3.4.5 uniform (alg 1, legacy) **[unverified by a run]**

Uses a permutation of the item indexes (`mapper.c:54-119`). Let `pr = r mod size`. Start with the
identity permutation `perm[0..size)`. For `p = 0, 1, ..., pr`, and only while `p < size - 1`: `j = p +
(hash3(x, bucket_id, p) mod (size - p))`; swap `perm[p]` and `perm[j]`. Return `items[perm[pr]]`.
The reference caches the partly built permutation per bucket between calls and has a shortcut for
`r mod size = 0` that is equivalent to the first swap; the result is a pure function of `(x, r,
bucket)`, so a client without a cache is correct. This same permutation function is also used by
the "local fallback" path in 3.6 for **any** bucket algorithm.

#### 3.4.6 tree (alg 3, legacy)

Described as buggy and excluded from allowed algorithms (`crush.h:195-197`). Reject maps in which
a rule can reach such a bucket (or simply reject any map containing one). The selection code is at
`mapper.c:148-203` if ever needed.

### 3.5 The out test (`is_out`)

`is_out(weight[], item, x)` (`mapper.c:405-419`); `weight[]` is the OSDMap `osd_weight` array:

1. If `item >= weight_max` (the array length): out.
2. If `weight[item] >= 0x10000`: in.
3. If `weight[item] == 0`: out.
4. Otherwise `hash2(x, item) & 0xffff` compared with `weight[item]`: in if strictly less, else out.

It is applied only to devices (type 0) and does not look at up/down state (down OSDs stay in CRUSH
output and are removed later, 3.7). The array is `osd_weight` exactly as decoded; an id below `max_osd`
whose OSD never existed or was removed normally carries weight 0 (out) because the array is padded
with 0 when `max_osd` grows (`OSDMap.cc:1549-1553`), but the mapper just reads the value. The hash
used here is always rjenkins1 `hash2`, independent of any bucket's `hash` byte (`mapper.c:415`); the same
holds for the placement seed (`osd_types.cc:1831`) and primary affinity (`OSDMap.cc:2926`).

### 3.6 `choose_firstn` (with chooseleaf)

Source `mapper.c:441-629`. Inputs of one call: start bucket `B`; `x`; `numrep`; wanted type `T`;
result vector `out` with a write position `outpos` (entries `out[0..outpos)` are the results already
chosen by this call chain); a `budget` (how many more results may be added); `tries`;
`recurse_tries`; `local_retries`; `local_fallback_retries`; `leaf` (boolean); `vary_r`; `stable`; a
second result vector `out2` for leaves; `parent_r` (0 at the top level); the choose_args set.

The call fills one replica slot after another. The slot index `rep` runs from `rep0` to
`numrep - 1`, where `rep0` is 0 if `stable` is set and `outpos` otherwise, and the loop also ends when
`budget` reaches 0. For each slot:

1. **Start a descent.** `fails_all = 0` (rejections for this slot so far, over all descents). Begin a
   descent at bucket `cur = B` with `fails_here = 0` (rejections in this descent).
2. **Draw number.** `r = rep + parent_r + fails_all`. Note that `r` is recomputed on every visit of
   this step.
3. **Empty bucket.** If `cur` has no items, the attempt counts as a rejection (go to step 8).
4. **Candidate.** If `local_fallback_retries > 0`, `fails_here >= cur.size / 2` (integer division) and
   `fails_here > local_fallback_retries`, take the item with the permutation chooser of 3.4.5 (this
   applies to every bucket algorithm). Otherwise use the chooser of `cur`'s own algorithm (3.4) with
   `position = outpos`.
5. **Sanity.** A candidate `>= max_devices` abandons the slot (go to step 9, nothing appended). The
   candidate's type is 0 for a device and the bucket's `type` for a bucket.
6. **Wrong type.** If the candidate's type differs from `T`: when it is a device, or its bucket slot is
   `>= max_buckets`, abandon the slot; otherwise set `cur` to that bucket and go back to step 2
   (no counter changes, so the next `r` is the same).
7. **Right type.** The attempt is a *collision* if the candidate equals any of `out[0..outpos)`. If it
   is not a collision and `leaf` is set:
   - for a bucket candidate, run the same procedure recursively on that bucket to find one device:
     wanted type 0, `numrep = 1` if `stable` else `outpos + 1`, result vector `out2` with the same
     `outpos`, `budget` as the caller's current value, `tries = recurse_tries`, `recurse_tries = 0`,
     the same local-retry values and `vary_r` / `stable`, `leaf` off, no `out2`, and `parent_r =
     r >> (vary_r - 1)` if `vary_r != 0`, else 0. If the recursive call returns a length that is not
     greater than `outpos`, the attempt is a *rejection*;
   - for a device candidate, `out2[outpos] = candidate`.
   Then, if the attempt is neither a collision nor a rejection and the candidate is a device
   (type 0), apply `is_out` (3.5): "out" makes it a rejection.
8. **Failure handling** (only when the attempt was a rejection or a collision): `fails_all += 1`,
   `fails_here += 1`; then take the first rule that applies:
   (a) it was a collision and `fails_here <= local_retries`: stay in `cur`, go to step 2;
   (b) `local_fallback_retries > 0` and `fails_here <= cur.size + local_fallback_retries`: stay in
   `cur`, go to step 2;
   (c) `fails_all < tries`: begin a new descent: `cur = B`, `fails_here = 0`, keep `fails_all`, go to
   step 2;
   (d) otherwise abandon the slot.
9. **Result.** On success `out[outpos] = candidate`, `outpos += 1`, `budget -= 1`. An abandoned slot
   appends nothing and the loop moves on to the next `rep` (the budget is unchanged).

The call returns the final `outpos`.

Notes that are easy to get wrong:

- `r` is recomputed on every visit of step 2, from the **current** `fails_all`. Moving down into a
  child bucket (step 6) re-uses the same `r` and increments nothing.
- The recursion for chooseleaf looks for **one device** under the chosen bucket: it is the same
  procedure with type 0, `numrep = outpos + 1` (non-stable) or `1` (stable), so its single slot has
  `rep = outpos` (non-stable) or `0` (stable); its result goes into `out2[outpos]`; "success" is the
  returned length exceeding `outpos`. With `stable = 1` the inner `r` therefore does not depend on how
  many results were already placed. Its `position` for weight sets is the same `outpos` as the
  outer one.
- Collisions in the recursion are checked against the **leaf** vector `out2[0..outpos)` (because the
  inner call's `out` is `out2`), while collisions at the outer level are against `out`.
- The inner call's budget is the outer **remaining** budget (an upper bound; it is positive whenever
  the inner call runs, so it never changes results).
- `position` for straw2 weight sets is `outpos`, not `rep` (`mapper.c:507-511`). In the interpreter
  every `w[i]` of a choose step starts a fresh call with `outpos = 0`, so the position restarts at 0
  for each `w[i]` (`mapper.c:946`, `:970`), not at the number of results of earlier `w[i]`.
- Failed leaf searches count as a rejection of the outer candidate, so they increment the outer
  `fails_all` and `fails_here`.
- With the optimal profile (`local_retries = 0`, `local_fallback_retries = 0`,
  `descend_once = 1`, `vary_r = 1`, `stable = 1`) steps 8(a) and 8(b) never fire and step 4 never
  uses the permutation: every collision or rejection restarts the descent (until `fails_all` reaches
  `tries`, where `tries` = 51, and the recursive call gets `tries = 1` because of `descend_once`);
  `parent_r = r`. A client may implement only that profile **provided it checks the decoded tunables
  (and any `SET_*` rule steps) and refuses anything else**; the general procedure is not much longer.
- Overflow notes: `r` is a C `int`; `tries` and the fail counters are `unsigned`. With the default
  50 tries none of them gets near a limit. `vary_r` shifts `r` right by `vary_r - 1`; reject
  `vary_r > 32` (4.3).
- The reference's stored-counter bookkeeping (`map->choose_tries[]`, `mapper.c:621-624`) is a
  statistics hook; ignore it.

### 3.7 After CRUSH: from raw list to acting set

Source `OSDMap.cc:2749-2949`, `:3060-3185`; the reference client calls
`pg_to_up_acting_osds(masked pg)` (`Objecter.cc:3024-3033`). `docs/spec/osdmap.md` 3.7 gives a
parallel summary; this section adds the exact edge cases found while reading.

Let `pg = (pool, pg_seed)` from 3.2 step 1 and `pps` from 3.2 step 2.

1. **Raw.** `raw = do_rule(...)` from 3.3. If `crush_rule` were negative the list would be empty
   (the field is `u8` in the pool so this cannot happen; `osd_types.h:1481`, `OSDMap.cc:2783`).
2. **Remove non-existent OSDs** (replicated pool: compact the list; an OSD "exists" iff `0 <= id <
   max_osd` and `osd_state[id] & EXISTS`; `OSDMap.cc:2749-2771`, `OSDMap.h:895-898`). Note: an OSD that
   exists but is down is **kept** at this stage.
3. **Upmap** (`OSDMap.cc:2803-2868`; key is `pg`):
   - `pg_upmap[pg]`: if any listed id is not NONE, is `< max_osd`, `>= 0`, and has `osd_weight == 0`,
     **return from the whole upmap step** (items and primaries below are skipped too). Otherwise
     replace `raw` with the listed OSDs (any length) and continue.
   - `pg_upmap_items[pg]`: for each pair `(from, to)` in order: scan `raw`; if `to` is present
     anywhere, skip the pair; else find the first index holding `from`, but ignore the pair when `to`
     is a valid id (not NONE, `0 <= to < max_osd`) with `osd_weight[to] == 0`; if a position was
     found and `to` is not present, write `to` there. Pairs apply sequentially (no simultaneous swap).
   - `pg_upmap_primaries[pg] = p`: if `p` is not NONE, `0 <= p < max_osd`, and `osd_weight[p] != 0`:
     look for `p` at positions `>= 1`; if found at index `k > 0`, swap `raw[k]` and `raw[0]`.
     **[unverified by a run]**
4. **Up set** (`:2871-2894`): drop (compact) every OSD that does not exist or is down (a down OSD
   is one without the `UP` bit; `OSDMap.h:904-914`). The **up primary** is the first non-NONE member
   of the resulting list (`_pick_primary`, `:2793-2801`). This is the primary of the *up set after
   dropping down OSDs*, not of the raw list.
5. **Primary affinity** (`:2896-2949`), skipped if the pool-wide affinity array is absent: if no
   member of the up set has affinity `!= 0x10000` skip. Else walk the up set in order; for member
   `o` with `a = affinity[o]`: if `a < 0x10000` and `(hash2(pps, o) >> 16) >= a`, remember the first
   such member as fallback and keep looking; else this member is the primary, stop. If nobody
   qualified, use the remembered fallback; if there was none, leave the primary unchanged. For a
   replicated pool, if the chosen primary is not at index 0, rotate it to the front by shifting the
   entries before it one place to the right. **[unverified by a run]**
6. **Temp overrides** (`:3060-3093`, `_get_temp_osds`): look `pg` up in `pg_temp`. Build `temp` by
   dropping every member that does not exist or is down (replicated: compact). Look `pg` up in
   `primary_temp`: if found, `temp_primary = that value` (no validity check at all); else if `temp`
   is non-empty, `temp_primary` = first member (first non-NONE member); else `temp_primary = -1`.
   (For pools with the EC-optimization flag the reference additionally reorders `temp` through
   `pgtemp_undo_primaryfirst`, `OSDMap.cc:3079`, `:2994-3016`; for a replicated pool this is the
   identity, `:2999`, and a client may ignore it.)
7. **Acting** (`:3137-3185`): if `temp` is empty, `acting = up` (after affinity) and, if
   `temp_primary == -1`, `acting_primary = up primary` (after affinity). Otherwise `acting = temp`
   and `acting_primary = temp_primary`.
   - Edge cases worth a test: a `primary_temp` entry **without** a `pg_temp` entry yields `acting =
     up` but `acting_primary = primary_temp value` (which need not be a member of `acting`); a
     `pg_temp` whose members are all down/non-existent behaves as if absent.
8. **Target OSD.** Send the op to `acting_primary` (`Objecter.cc:3175-3177`). If `acting` is empty
   or `acting_primary = -1`, the PG is currently unmappable: hold the op until a newer map arrives.

### 3.8 `indep` and MSR (explicitly not implemented; one-paragraph facts)

- `indep` (`mapper.c:636-824`) is the breadth-first, positionally stable variant used by
  erasure-coded rules; it pads with `CRUSH_ITEM_NONE` holes instead of compacting. My scratch
  implementation reproduces `test-map-indep.t` (192 mappings) so the description is easy to extend
  later, but it is not needed for replicated pools.
- MSR (rule types 4 and 5, opcodes 14-16, `mapper.c:1034-1960`) retries the whole descent when it
  hits an out device. It is new in the Squid generation (feature `CRUSH_MSR`, bit 38; the reference maps this feature to
a minimum client release of Squid, `OSDMap.cc:1853-1855`). A replicated
  pool *can* use an MSR-firstn rule (`CrushWrapper.h:593-605`); the default replicated rule does
  not. Not read in detail.

### 3.9 When to recompute

Recompute the target for an in-flight request whenever a new OSDMap epoch is applied, and when an
OSD connection resets. The reference's resend decision (`Objecter.cc:2802-2818`, `:3084-3097`):
the PG id changed, or `primary_changed_broken(old, new)` (acting emptiness changed, primary id changed,
or the primary's index in the acting list changed; `OSDMap.cc:3217-3233`), or the pool's PG count
changed in a way that splits/merges this PG, or the pool's `last_force_op_resend` equals the new epoch.
A minimal client can simply resend whenever `(pg, acting_primary)` differs from the values used when
the op was sent. Cache per `(pg_seed)` results keyed by epoch to avoid re-running CRUSH for every
object (`Objecter.cc:3026-3033` does so).

---

## 4 Minimal-client choices

### 4.1 Must implement

- rjenkins string hash (pool `object_hash = 2`), the `0x1f` namespace prefix rule, the optional
  locator-key substitution, stable modulo, the HASHPSPOOL and the legacy placement seed.
- CRUSH blob decode through row 20 of 2.2 (rows 7-9 and 16-18 can be parsed and discarded, but rows 7-9
  need the empty-name rule of 2.2, and every trailing group is optional), with the decode-time
  fix-ups of 2.4. Tolerate both the "full OSDMap" form (no MSR pair, stored rule sizes) and the "quorum
  features" form (2.1).
- `straw2` with `ids` and weight-set overrides (choose_args), signed 64-bit truncating division,
  the exact `crush_ln`, and the first-index tie rule.
- `choose firstn` / `chooseleaf firstn` with all tunables from the map (local retries, fallback
  retries, total tries, descend_once, vary_r, stable) and the rule-level `SET_*` steps.
- `take`, `emit`, `numrep <= 0` handling, `is_out` with `osd_weight`.
- After CRUSH: non-existent removal, `pg_upmap`, `pg_upmap_items`, `pg_upmap_primaries`, up/down
  filtering, primary affinity, `pg_temp`, `primary_temp`, acting primary selection.
- Legacy bucket algorithms: **straw** (alg 4) is recommended (small, and verified in 1.3); `uniform`
  and `list` are optional; refuse `tree`.

### 4.2 May skip

- Reading device classes (`class_map`, `class_name`, `class_bucket`) and all names, except to skip
  past them. Rule names, type names, device names.
- `straw_calc_version`, `allowed_bucket_algs`, bucket `weight`, rule min/max size.
- `indep`, MSR, EC, `pg_temp` re-ordering for EC-optimizations pools.
- Read balancing (`BALANCE_READS`, `LOCALIZE_READS`): always use the acting primary
  (`Objecter.cc:3138-3177` shows the replica choice; it needs the client's CRUSH location).
- Cache-tier overlays: refuse a pool with `read_tier >= 0` or `write_tier >= 0` or `tier_of >= 0`.
- The "legacy `object_hash = 1`" and the non-HASHPSPOOL placement: trivial to code, but a v20.2.5
  cluster never creates such pools; supporting them costs nothing, testing them is impossible on a
  new cluster **[confirm on capture if an old pool exists]**.

### 4.3 Must reject with a clear message

| Condition | Why |
|---|---|
| CRUSH magic not `0x00010000`, any `alg_marker` not in 1..5 or different from the bucket's own `alg` byte, `hash != 0`, bucket `id != -1 - slot` (not checked by the reference decoder), rule `ruleset != slot` | malformed or unknown encoding |
| bucket alg 3 (tree) reachable by the pool's rule | legacy, buggy |
| the pool's rule is missing, or its type is not 1 | MSR / erasure |
| the pool's rule contains opcodes 3, 7 (indep) or 14-16 | out of scope |
| `pool.type != 1`, `object_hash` not in {1, 2} | out of scope |
| choose_args entry whose `ids_size` differs from the bucket size (the reference asserts, `CrushWrapper.cc:3388`), or whose weight-set row length differs from the bucket size (the reference silently repairs it, 2.4 item 2) | reject both; a well-formed map has neither |
| items referencing a bucket slot beyond `max_buckets` | would be skipped by the mapper, but indicates corruption |
| any tunable value the implementation does not understand (for example `chooseleaf_vary_r` large) | accept any `vary_r` in `0..32` since the shift is by `vary_r - 1` on a 32-bit `int` (a shift of 32 or more is undefined in the reference); reject values above 32 |

### 4.4 Size and speed

- Straw2 evaluates **every** item of every bucket on the path: the cost of one attempt for one
  replica is the sum of the fan-outs along the descent (for example 10 racks + 10 hosts + 10 OSDs =
  about 30 `hash3` plus `crush_ln` evaluations), times the number of replicas and retries. A pool has a fixed PG count, so compute
  each PG's mapping lazily and cache it per map epoch (invalidate on any epoch).
- Memory: `crush_ln` needs about 258 + 256 u64 words (about 4 KiB of tables). The map blob can be
  kept in its received form and parsed on demand; per-bucket parsed state is `size` ids and
  `size` weights (+ weight-set rows). Permutation scratch (uniform/fallback) is `size` u32 per
  bucket in the reference; a client can use a per-call stack buffer instead.
- No floating point anywhere in the pipeline; all arithmetic is 32/64-bit integer. Good for the
  iPXE and Windows kernel hosts. Signed 64-bit division is the only operation that may need a
  helper on 32-bit targets (`__divdi3`-style).

---

## 5 Test vectors needed

### 5.1 Values already computed (all **[confirm on capture]** against a live cluster)

Provenance: produced by the author's scratch implementation and **independently reproduced** by a
second reviewer by compiling the pinned `src/crush/hash.c`, `src/common/ceph_hash.cc` and `mapper.c`
(for `crush_ln`, see the note after the `crush_ln` table) in a scratch directory outside this
repository. Every value below matched. That proves the arithmetic of this note against the pinned
source; it does not prove the placement of a live cluster, which is why the capture items stay.

String hash (`ceph_str_hash_rjenkins`, u32 hex), computed from the algorithm in 3.1.1:

| Input bytes | rjenkins | linux |
|---|---|---|
| `` (empty) | `0xbd49d10d` | `0x00000000` |
| `a` | `0x29eec818` | `0x000042f2` |
| `foo` | `0x7fc1f406` | `0x0024db2a` |
| `abcdefghijkl` (12 bytes) | `0x0b1b3ea5` | `0xf281eff0` |
| `abcdefghijklm` (13 bytes) | `0x3122b031` | `0x6b959a82` |
| `rbd_directory` | `0x30a98c1c` | `0x9569da2c` |
| `rbd_id.myimage` | `0xf8d9dc15` | `0xca6e1713` |
| `rbd_header.1234abcd5678` | `0xdb3ea4d9` | `0xc6227fd9` |
| `rbd_data.1234abcd5678.0000000000000000` | `0x89a0b515` | `0xe9caf84f` |
| `ns` + 0x1f + `foo` (namespace case) | `0xac17f0b6` | `0xccc913ee` |

(`foo` is also the object name used by `src/test/cli/osdmaptool/pool.t:22-29`, which checks only the
`1\..*` shape of the result, so there is no in-tree expected value. Compare against `ceph osd map
<pool> foo`: the printed raw pgid is `<poolid>.<hash hex>`.)

CRUSH hashes (u32 hex):

| Call | Result |
|---|---|
| `hash1(0)` / `hash1(1)` / `hash1(0xffffffff)` | `0x17c4a80b` / `0xd5082851` / `0x7f71bc2a` |
| `hash2(0,0)` | `0x19ad4ce9` |
| `hash2(1,2)` | `0xb78dee9c` |
| `hash2(0x7fc1f406, 1)` | `0x8ddb71b1` |
| `hash2(0xffffffff, 0xffffffff)` | `0x9f3c11cc` |
| `hash3(0,0,0)` | `0x7a3bf3b2` |
| `hash3(1,2,3)` | `0x735ad42b` |
| `hash3(0x12345678, 0xffffffff, 7)` | `0x03097224` |
| `hash3(5, 0xffffffff, 0)` (bucket id -1) | `0x3e502f1c` |
| `hash4(0,0,0,0)` | `0x3fafb04d` |
| `hash4(1,2,3,4)` | `0x696d1f16` |

`stable_mod` and placement seed:

| Case | Result |
|---|---|
| `stable_mod(0x7fc1f406, 12, 15)` | 6 |
| `stable_mod(0x7fc1f40e, 12, 15)` / `stable_mod(0x7fc1f40e, 16, 15)` | 6 / 14 |
| `stable_mod(0xffffffff, 100, 127)` / `stable_mod(100, 100, 127)` | 63 / 36 |
| `stable_mod(x, 1, 0)` | 0 |
| HASHPSPOOL `pps`, pool 1, seed 6 | `hash2(6,1) = 0xd77484f9` |
| HASHPSPOOL `pps`, pool 2, seed 6 | `hash2(6,2) = 0x37f72ca0` |
| HASHPSPOOL `pps`, pool 1, seed 14 | `hash2(14,1) = 0xadee4b52` |
| legacy `pps`, pool 1, seed 6 / pool 2, seed 6 (pgp_num 12) | 7 / 8 |

`crush_ln` (hex, with the pinned tables):

| `u` | `crush_ln(u)` |
|---|---|
| 0 | `0x000000000000` |
| 1 | `0x100000000000` |
| 2 | `0x195c01a39fbd` |
| 255 | `0x800000000000` |
| 256 | `0x80171e3b6d7a` |
| 0x1234 | `0xc2fb9e09ec18` |
| 0x7fff | `0xf00000000000` |
| 0x8000 | `0xf0002e2a60a0` |
| 0xfffe | `0xfffffd61ad10` |
| 0xffff | `0xfffff0000000` |

`crush_ln` is not exposed by any Ceph tool, and it is `static` inside `mapper.c`. Confirm it either
through the mapping vectors below (they depend on it for every straw2 decision), or by compiling
`src/crush/mapper.c` plus the table header in a scratch directory **outside this repository**, with a
tiny wrapper translation unit that `#include`s `mapper.c` (that is how the reviewer called it) and
exports a function calling it, for all 65,536 inputs. `mapper.c` needs only an empty `acconfig.h` on
the include path to compile outside the Ceph build.

### 5.2 Known-answer mappings that exist in the Ceph tree

Use these first; they need no live cluster. (`crushtool` itself is only needed to regenerate.)

- `src/test/cli/crushtool/test-map-jewel-tunables.crushmap` with the command on line 1 of
  `test-map-jewel-tunables.t`: `--rule 0 --weight 12 0 --weight 20 0 --weight 30 0 --min-rep 1
  --max-rep 10`, `x = 0..1023`, devices `12, 20, 30` out and all others `0x10000`. Examples
  verified by my scratch implementation: replicas 1, `x = 0` -> `[101]` (line 3); replicas 2,
  `x = 0` -> `[101,28]` (line 1028); replicas 3, `x = 0, 1, 2` -> `[101,28,17]`, `[80,13,75]`,
  `[91,11,68]` (lines 2053-2055). 10,240 expected mappings per file.
- The other `.t` files in the table of 1.3 for straw buckets, local retries, `vary_r`, `descend_once`,
  `indep`.
- How `crushtool` builds the weight vector, needed to reproduce a run: one entry per device index up to
  `max_devices`, `0x10000` by default, `0` for an id that is in no bucket, replaced by `--weight`
  (`CrushTester.cc:455-471`).

### 5.3 Captures needed from the test cluster

| # | What | How | Pass criterion |
|---|---|---|---|
| C1 | Raw CRUSH blob and the live tunables | `ceph osd getcrushmap -o crush.bin`; `crushtool -d crush.bin`; `ceph osd crush show-tunables`. **Also** capture the blob embedded in a full OSDMap as received by the client (`ceph osd getmap` or a wire capture): `getcrushmap` encodes with the quorum feature set (`OSDMonitor.cc:5649`), the embedded one with the OSDMap encoding set (2.1), so they may differ in the MSR pair and the rule min / max bytes | decoder (2.2) agrees with the decompile on every bucket, rule, tunable, for both forms; `max_devices` recomputation (2.4) agrees with `crushtool` output; the two blobs differ only where 2.1 predicts |
| C2 | CRUSH mappings for the pools' rules | `crushtool -i crush.bin --test --show-mappings --rule R --num-rep N --min-x 0 --max-x 1023 --pool-id P` (the mapping lines are written to the tester's `err` stream, which `crushtool` binds to standard output: `crushtool.cc:448`, `CrushTester.cc:574`, `:587-588`) with `--weight <osd> <w>` for every OSD whose reweight is not 1.0 (take them from `ceph osd dump`/`ceph osd tree`). **With `--pool-id P`, `crushtool` computes `hash2(x, P)` itself (the HASHPSPOOL rule, `CrushTester.cc:572-579`)**, so `x` there is the post-stable-mod seed | for each `x`, my `do_rule` equals the `CRUSH rule R x X [..]` line. Caveat: `crushtool` always selects the default choose_args set (`do_rule(..., 0)`, `:579`), not the pool's own set, so do not use it for pools with their own weight set |
| C3 | Whole-pipeline oracle | `ceph osd getmap -o osdmap.bin`; `osdmaptool osdmap.bin --test-map-pgs-dump-all --pool P` prints, for every PG `P.s`: `raw (...) up (...) acting (...)` with primaries (`osdmaptool.cc:766-816`). Also `osdmaptool osdmap.bin --test-map-pg <pool>.<hexseed>` | every PG of every pool you will use: raw list (after non-existent removal, before upmap), up, acting and the three primaries equal mine. Run it on maps with: no upmap; with `pg_upmap_items`; with `pg_upmap`; with `pg_upmap_primaries` (needs min-compat reef); with OSDs down; with reweighted OSDs; with `pg_temp`; with `primary_temp` (create with `ceph osd primary-temp`); with a non-default `osd primary-affinity`; with a pool whose `pg_num` is not a power of two (split in progress); and a pool with `pg_num != pgp_num` |
| C4 | Object-name path | `ceph osd map <pool> <object> [<nspace>]` for ~50 names including: empty-key RBD names (`rbd_data.<id>.<objno 16 hex>`, `rbd_header.<id>`, `rbd_id.<name>`), names of length 11, 12, 13, 23, 24, 25, names with the namespace form, names with non-ASCII bytes | the printed `pg <pool>.<ps hex> (<pool>.<masked>)` equals mine, and `up`/`acting` with primaries equal mine (`OSDMonitor.cc:5898-5951`) |
| C5 | choose_args | Create a weight set on a test pool (`ceph osd crush weight-set create <pool> positional`, adjust a few weights) and a compat (default) set | C3 passes for that pool (the weight set keyed by the pool id must be the one used, and the `-1` set for other pools). Confirms the position index (`outpos`) semantic **[unverified by a run]** |
| C6 | Device class rule | pool using `take default class ssd` | C3 passes |
| C7 | Feature gating | Connect with deliberately reduced feature masks (harness only) and diff the CRUSH blob and OSDMap versions received | confirm 2.5 statements: missing `chooseleaf_stable` byte, absent class / choose_args sections, folded weight-set 0 |
| C8 | Weight edge cases | an OSD with reweight `0.5` and one with `0` | C2/C3 pass; verifies `is_out` step 4 |
| C9 | Split in progress | raise `pg_num` while `pgp_num` lags | `pps` uses `pgp_num` while PG key uses `pg_num`; C3 passes at each intermediate epoch |

The oracle binaries (`crushtool`, `osdmaptool`, `ceph`) are used only at test time and are not
shipped; any oracle helper compiled from Ceph sources must stay outside this repository tree.

---

## 6 Open questions

1. **The `LL` table is irregular (3.4.2)**: not derivable from a formula. Is the shipped table the
   permanent definition of "straw2 compatible"? It must be, since changing it would remap data; but
   confirm it has been bit-identical in every release (Reef, Squid, Tentacle), and decide how the
   table enters the MIT core (section 7).
2. `crush_ln` vectors in 5.1 and the `RH_LH` formula claims were computed with scratch code against
   the table in the pinned header, not against a running cluster. **[confirm on capture]**
3. `uniform`, `list` and `tree` algorithms and the permutation fallback are described from source
   only. Are such buckets still present in any supported cluster? (A cluster built since Hammer
   defaults to straw2; clusters upgraded from older releases may keep `straw` or `list`.)
4. `choose_args` (weight sets and `ids`): position semantics (`outpos`, rows clipped to the last),
   the set-selection rule (pool id, then `-1`). Read from source (`mapper.c:290-307`, `:507-511`,
   `CrushWrapper.h:1471-1484`) but **[unverified by a run]** (C5). What a Tentacle monitor sends to a
   client lacking `SERVER_LUMINOUS` is read from source (2.5) but also unrun (C7).
5. `pg_upmap_primaries`: the swap uses only the position scan from index 1 (`OSDMap.cc:2855-2864`).
   `pg_to_raw_up` returns the primary of the **raw** list (`OSDMap.cc:3133`) while
   `_pg_to_up_acting_osds` (the one the client uses) takes the primary of the **up** list
   (`:3166`); both after upmap. Read from source; confirm on a PG with an upmap-primary whose target
   is down. **[confirm on capture]**
6. Primary affinity: rotation behaviour read from source (`OSDMap.cc:2942-2948`: entries before the
   chosen position shift one place toward the back, the chosen OSD goes to index 0); confirm on a
   replicated pool with three members of which the first is rejected (C3).
7. `max_devices` recomputation (2.4): any case where the recomputed value differs from the encoded
   one in a real map (a device in `name_map` but in no bucket)? It cannot change the result of a
   selected item, but it changes whether `take <device>` is accepted.
8. Behaviour of `x` values with the top bit set: the reference stores `x` in a signed int and the
   permutation cache compares `(u32) x`; hashes take the u32 bit pattern. No effect expected;
   check with `hash2` vectors where `pps >= 0x80000000` (the `0xd77484f9` vector above is one).
9. Items with weight >= `0x80000000` (signed-int quirk in 3.4.1): unreachable in practice but
   untested.
10. An MSR-firstn rule on a replicated pool: rejected here. How likely is it in a Tentacle test
    cluster? The default replicated rule is built by `add_simple_rule_at` (`CrushWrapper.cc:2279-2378`),
    and both callers pass `pg_pool_t::TYPE_REPLICATED` = 1 (`OSDMap.cc:5042-5044`,
    `OSDMonitor.cc:11554-11555`), i.e. rule type 1 (resolved from source). A rule of type 4 can only
    come from an explicit administrator action; confirm the live rule type with
    `ceph osd crush rule dump`.
11. Stretch-mode pools and `peering_crush_*` fields do not change placement but change which
    OSDs are usable; this note assumes none.
12. The exact point at which the reference refuses a map that is internally inconsistent (for
    example a `take` of a bucket id with no slot) versus silently producing fewer results is
    only partly read (`mapper.c:877-888`: silently ignored). A cluster map from a monitor should
    never exhibit it.
13. **MSR pair and rule sizes in the embedded blob (2.1)**: derived from `SIGNIFICANT_FEATURES` not
    containing `CRUSH_MSR` / `SERVER_QUINCY`. Confirm by capturing a real full map and an incremental
    that carries a crush change (C1). If the blob does contain the pair, nothing in this note breaks
    (the decoder reads it when present).
14. `test-map-jewel-tunables.crushmap` carries `allowed_bucket_algs` bytes that decode as `0x1600`
    (its tail is `... 01 01 00 16 00 00 01`) whereas the sibling hammer map decodes as `0x16`. The
    mapper does not use the field and the stable byte still sits last, so it is harmless, but do not
    build a validator that insists `allowed_bucket_algs` is a plausible bitmask. **[unverified]**
    which tool wrote that test file.
15. `uniform` buckets in the legacy reject / fallback paths (the permutation chooser) and `list`
    buckets are untested by any in-tree expected-output file that was compared; use C1/C2 on a map with
    such buckets if one exists on the test cluster, otherwise decline them (4.1).

---

## 7 Licensing questions

1. **`src/crush/crush_ln_table.h`** (copyright holder named in its header, LGPL-2.1) contains two
   numeric tables used by `crush_ln`:
   - `RH_LH` (258 entries): I found exact closed forms (3.4.2): `ceil(2^48 / (1 + k/128))`,
     `floor(2^48 * log2(1 + k/128))`, and a single special last entry `2^48 - 2^32`. Regenerating it
     from these formulas at build time (or at start-up with integer arithmetic only) needs no copied
     data. Question: is a table regenerated from a published formula and verified to equal the
     original entry-for-entry acceptable for an MIT component? (Facts and mathematical constants
     are normally not copyrightable, but the question should be asked.)
   - `LL_tbl` (256 entries): **no closed form** (3.4.2). To be bit-compatible the 256 values must be
     present in the MIT core. Options to put to the Ceph maintainers / counsel: (a) ask for explicit
     permission to include the 256 values (or the 65,536-entry derived `crush_ln` output) under MIT;
     (b) argue that a table of numeric constants is functional data without sufficient originality;
     (c) obtain the values by a documented independent process (for example measure `crush_ln`
     through a black-box oracle) - this does not obviously avoid the issue since the data is the
     same; (d) as a last resort, agree with the project that this one table is carried under
     LGPL-2.1 in a separate file with a clear notice. Decision needed before `core/` exists.
2. **Hash functions.** The source labels the string-hash mix and `ceph_stable_mod` as public domain
   (`ceph_hash.cc:4-7`, `rados.h:94`), and the CRUSH hash mix is the same construction
   (`hash.c:7-11`). Describing the arithmetic here and re-implementing it should be safe; the
   `crush/hash.c` file itself carries no licence line, so the CRUSH-specific constants and call
   sequences (3.2.1) are treated as protocol facts. Confirm.
3. **Algorithm descriptions.** Section 3 describes the mapper and the OSDMap pipeline step by step
   from `mapper.c`, `OSDMap.cc` and `Objecter.cc` (LGPL-2.1). It is written as pseudo-steps in my
   words and does not reproduce their code or comments, but is detailed enough to re-implement;
   whether such a description is "derived" is the general question already raised for the other
   notes. The review pass replaced the code-like pseudo-listing of the firstn procedure (3.6) by
   numbered prose with different names for the counters, because a line-for-line transcription of a
   function body is what the project rule forbids; the remaining structural resemblance is inherent
   in a description that must be bit-exact. Likewise the `crush_ln` steps (3.4.2) and the
   `is_out` / upmap / affinity rules are short factual procedures; counsel should decide whether any
   of them needs a clean-room second author.
4. **Test data.** The `.t` files and `.crushmap` binaries in `src/test/cli/crushtool/` are Ceph
   test data. This note cites file names, line numbers and a few output values only. Do not commit
   copies of those files; have the harness read them from the pinned reference tree, or regenerate
   equivalent maps with `crushtool` from our own source text.
5. **Scratch implementation.** The scratch code used for 1.3 and 5.1 parsed the tables out of the
   Ceph header at run time and is not in this repository. If a checked-in test needs the same
   known-answer vectors, they must come from the oracle tools or from our own `core/` once licensing
   item 1 is settled.
