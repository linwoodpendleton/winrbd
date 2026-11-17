/* SPDX-License-Identifier: MIT */
/*
 * wri_place.h - object placement: object name -> placement seed -> PG -> raw / up / acting OSD sets.
 *
 * Pure functions of (map, pool, name): the pipeline of docs/spec/crush-and-placement.md 3.1 to 3.7 and
 * osdmap.md 3.7, in this order and no other (docs/design/core-architecture.md 16.4):
 *
 *   1  ps        = object_hash(ns 0x1f subject)           subject = locator key if given, else the name
 *   2  pg_seed   = stable_mod(ps, pg_num, pg_num_mask)    the PG key is (pool, pg_seed)
 *   3  pps       = hash2(stable_mod(pg_seed, pgp_num, pgp_num_mask), pool)  (HASHPSPOOL) or the sum (legacy)
 *   4  raw       = CRUSH rule(pool.crush_rule, pps, size, osd_weight, choose_args of the pool); drop OSDs that do not exist
 *   5  upmap     = pg_upmap, then pg_upmap_items pairs in order, then pg_upmap_primaries (with the weight-0 early exit)
 *   6  up        = drop OSDs that are down or do not exist; up_primary = first member
 *   7  affinity  = primary affinity reorders the up set (only if some member has a non-default affinity)
 *   8  temp      = pg_temp (members that are down or do not exist dropped), primary_temp
 *   9  acting    = temp list if non-empty else up; acting_primary = temp primary if any else the up primary
 *
 * Modules: place (wri_place.c, wri_place_stage.c), place-cache (wri_place_cache.c).
 */
#ifndef WRI_PLACE_H
#define WRI_PLACE_H

#include "wri_crush.h"
#include "wri_crush_hash.h"
#include "wri_osdmap.h"

/* An object as the placement sees it: three byte strings, any may be empty (NULL with length 0). */
typedef struct wri_oid {
	const uint8_t *name;
	uint32_t name_len;
	const uint8_t *nspace;
	uint32_t nspace_len;
	const uint8_t *key; /* object locator key; empty for RBD data objects */
	uint32_t key_len;
} wri_oid;

#define WRI_PLACE_NAME_MAX 4096u /* longest name + namespace + key accepted (WR_E_TOOBIG above) */
/* Members the stage functions below can hold in a list: the buffers a caller passes to wri_place_upmap and wri_place_temp
 * have this many entries. The full-map decoder refuses a pg vector longer than this (the layout builder accepts twice as
 * many values, which an upmap-items pair list needs), and the stages cut a longer table vector rather than trust that. */
#define WRI_PLACE_LIST_MAX WRI_MAP_PGVEC_MAX

/*
 * The result for one PG. Counts are at most WRI_REP_MAX; up_primary is -1 when up is empty. acting_primary is -1 when
 * acting is empty too, except that a primary_temp entry names the acting primary even then (a PG with no usable OSD and
 * a stored primary_temp: the reference gives that OSD, and so do we; a caller that wants "unmappable" tests n_acting == 0).
 */
typedef struct wri_pg_result {
	uint32_t pps;            /* placement seed fed to CRUSH */
	uint8_t n_raw, n_up, n_acting;
	uint8_t reserved;
	int32_t raw[WRI_REP_MAX];    /* CRUSH output after dropping OSDs that do not exist, before upmap (osdmaptool's "raw") */
	int32_t up[WRI_REP_MAX];
	int32_t acting[WRI_REP_MAX];
	int32_t up_primary;
	int32_t acting_primary;
} wri_pg_result;

/* ---- object name to PG ------------------------------------------------------------------------------ */

/* Step 1. WR_E_TOOBIG when name_len + nspace_len + key_len is above WRI_PLACE_NAME_MAX (the key counts although the name is
 * then not hashed), WR_E_POOL_UNSUPPORTED for an object_hash that is neither 1 nor 2, WR_E_INVAL for a NULL argument or
 * announced bytes without a pointer; *ps is 0 on every failure. Nothing is allocated or assembled: the pieces are hashed in place. */
WR_MUST_CHECK wr_status wri_place_hash(const wri_map_pool *p, const wri_oid *o, uint32_t *ps);
/* Step 2: the PG seed of a full hash. */
uint32_t wri_place_pg_seed(const wri_map_pool *p, uint32_t ps);
/* Step 3: the CRUSH input of a PG seed. */
uint32_t wri_place_pps(const wri_map_pool *p, uint32_t pg_seed);

/* ---- PG to OSDs ---------------------------------------------------------------------------------------- */

/*
 * Steps 3 to 9 for PG (tracked pool `pool_idx`, `pg_seed`) of map `m`. pg_seed is the masked seed of wri_place_pg_seed (a larger
 * one is not masked here: it names no PG, so the tables are not found and the mapping is that of the seed as given). ws is the caller's workspace; ws->work is set from work_max first. `out` is cleared (counts 0, primaries -1)
 * on every failure, a NULL map or workspace included. Fails with WR_E_POOL_NOT_FOUND (the tracked pool is absent from the map), the pool's own
 * status when it is not WR_OK (unsupported pool, no usable rule), WR_E_MAP_NONE for a map without CRUSH, or the
 * mapper's errors. A PG with no usable OSD is NOT an error here: n_acting is 0 (see wri_pg_result for the primaries); the
 * caller decides (wr_target maps it to WR_E_PLACE_UNMAPPABLE). The lists in the result keep their first WRI_REP_MAX
 * members (a pool the client serves has size <= WRI_REP_MAX, and so has any list a monitor accepts).
 */
WR_MUST_CHECK wr_status wri_place_pg(const wri_osdmap *m, uint32_t pool_idx, uint32_t pg_seed, uint32_t work_max,
				     wri_crush_ws *ws, wri_pg_result *out, wr_errinfo *why);

/* ---- the stages, exposed so each one is testable alone (all in-place, none allocates) ------------------- */

/* Step 4 tail: remove OSDs that do not exist (compacting); returns the new count. */
uint32_t wri_place_drop_nonexistent(const wri_osdmap *m, int32_t *v, uint32_t n);
/* Step 5: apply pg_upmap, pg_upmap_items, pg_upmap_primaries for `pgkey` to v[0..*n) (the list may change length: v holds
 * WRI_PLACE_LIST_MAX entries, *n is at most that on entry, a longer table vector is cut). */
void wri_place_upmap(const wri_osdmap *m, uint64_t pgkey, int32_t *v, uint32_t *n);
/* Step 6: copy the up members of raw[0..n) (exist and UP) into up (room for n; up may be raw itself), return their count;
 * *primary = first member or -1 (may be NULL). */
uint32_t wri_place_up_set(const wri_osdmap *m, const int32_t *raw, uint32_t n, int32_t *up, int32_t *primary);
/* Step 7: primary affinity (osdmap.md 3.7 step 9, crush note 3.7 step 5): may rotate the chosen primary to the front and
 * then sets *primary (in and out, may be NULL) to it; a map without an affinity array, or with no non-default affinity among
 * the members, leaves both untouched. */
void wri_place_affinity(const wri_osdmap *m, uint32_t pps, int32_t *up, uint32_t n, int32_t *primary);
/* Step 8: pg_temp / primary_temp for `pgkey`: fills temp[0..*n) (WRI_PLACE_LIST_MAX entries of room) and *temp_primary (-1 if
 * none): primary_temp as stored (no validity check) if there is an entry, else the first temp member. */
void wri_place_temp(const wri_osdmap *m, uint64_t pgkey, int32_t *temp, uint32_t *n, int32_t *temp_primary);

/* ---- placement cache (module place-cache, wri_place_cache.c) ------------------------------------------ */

/*
 * A small direct-mapped cache of PG results keyed by (map epoch, pool id, pg_seed): CRUSH does not have to run for
 * every object of the same PG. Entries live in the arena (map_pg_cache of them); a lookup misses on any epoch change,
 * so nothing is ever invalidated explicitly and a stale result cannot be returned.
 */
typedef struct wri_pgc_entry {
	uint64_t key;     /* wri_pg_key(pool id, pg_seed) */
	uint32_t epoch;   /* 0 = empty */
	uint8_t n_up, n_acting;
	uint8_t reserved[2];
	int32_t up[WRI_REP_MAX];
	int32_t acting[WRI_REP_MAX];
	int32_t up_primary, acting_primary;
} wri_pgc_entry;

typedef struct wri_pgcache {
	wri_pgc_entry *e;
	uint32_t n;       /* entries, a power of two or any positive count (index = hash of the key modulo n) */
	uint32_t hits, misses;
} wri_pgcache;

/* Bytes of arena for n entries (for the store's memory plan). */
size_t wri_pgcache_bytes(uint32_t n);
/* Bind the cache to `mem` (wri_pgcache_bytes(n) bytes, zeroed, 8-byte aligned). n == 0 gives a cache that never hits. */
void wri_pgcache_init(wri_pgcache *c, void *mem, uint32_t n);
/* Forget every entry (counters stay). Epoch stamps already make a stale hit impossible when epochs only go forward; a holder
 * that ever replaces its map by a different map of the SAME epoch (it should not, but a hostile monitor could try) calls this. */
void wri_pgcache_clear(wri_pgcache *c);
/* 1 and *out filled (raw and pps are not cached: out->n_raw is 0) on a hit for (epoch, key), else 0. */
int wri_pgcache_get(wri_pgcache *c, uint32_t epoch, uint64_t key, wri_pg_result *out);
void wri_pgcache_put(wri_pgcache *c, uint32_t epoch, uint64_t key, const wri_pg_result *res);

#endif /* WRI_PLACE_H */
