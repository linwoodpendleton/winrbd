/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_dec.h - decoding an OSDMap or an OSDMap::Incremental into a map slot, and applying an
 * incremental to a held map. Pure functions: no store, no clock, no allocation. They take the budgets and the
 * tracked pool names in a wri_mapcfg, the bytes of ONE map (or incremental), and a destination slot; on any
 * failure the destination is left in an unusable state (magic 0) and the source map is untouched, which is
 * what makes "build the next epoch, swap on success" atomic (docs/design/core-architecture.md 15.5).
 *
 * Wire facts: docs/spec/osdmap.md 2.2 to 2.6 (rows and "since" versions), 3.3 to 3.6 (procedure and validation),
 * 4 (floors); crush-and-placement.md 2.7. Decoded and kept: see section 15.2 of the architecture document.
 *
 * Modules: osdmap-pool (wri_pool_decode), osdmap-full (wri_osdmap_decode_full and the shared row helpers),
 * osdmap-inc (wri_osdmap_inc_info, wri_osdmap_apply_inc).
 */
#ifndef WRI_OSDMAP_DEC_H
#define WRI_OSDMAP_DEC_H

#include "wri_cursor.h"
#include "wri_osdmap.h"

/* ---- what a decoder works within ----------------------------------------------------------------- */

typedef struct wri_mapcfg {
	uint32_t slot_bytes;     /* size of a map slot (from wr_config.map_slot_bytes) */
	uint32_t max_osd;        /* largest max_osd accepted (wr_config.map_max_osd, at most WRI_MAP_OSD_HARD_MAX) */
	uint32_t work_max;       /* CRUSH item draws per mapping (wr_config.crush_work_max): carried for the placement code; the rule audit
				  * is structural (it walks the rule and the buckets, it draws nothing), so the decoders do not read it */
	uint8_t n_pools;         /* tracked pools, 0 .. WRI_MAP_POOLS_MAX */
	uint8_t verify_crc;      /* verify map / incremental CRCs (wr_config.map_verify_crc) */
	uint8_t reserved[2];
	uint8_t name_len[WRI_MAP_POOLS_MAX];
	uint8_t name[WRI_MAP_POOLS_MAX][WRI_MAP_NAME_MAX]; /* tracked pool names, not NUL terminated */
} wri_mapcfg;

/* ---- supported encodings (osdmap.md 4.1) ---------------------------------------------------------- */

#define WRI_MAP_WRAPPER_MIN_V 7u       /* wrapper struct_v 7 and 8 (8 adds the CRC) */
#define WRI_MAP_WRAPPER_MAX_COMPAT 8u
#define WRI_MAP_FULL_BLOCK_MIN_V 9u    /* client-usable block of a full map: v9 and v10 (10 adds pg_upmap_primaries) */
#define WRI_MAP_FULL_BLOCK_MAX_COMPAT 10u
#define WRI_MAP_INC_BLOCK_MIN_V 8u     /* client-usable block of an incremental: v8 and v9 (9 adds upmap primaries) */
#define WRI_MAP_INC_BLOCK_MAX_COMPAT 9u
#define WRI_POOL_MIN_V 29u             /* pg_pool_t struct_v 29 .. 32 (30 only for stretch pools) */
#define WRI_POOL_MAX_COMPAT 32u

/* ---- header facts without building (the store uses them to sequence a message) ------------------------ */

typedef struct wri_map_blob_info {
	uint8_t fsid[16];
	uint32_t epoch;
	uint8_t has_fullmap; /* incremental only: it embeds a complete map (osdmap.md 3.5 step 4) */
	uint8_t reserved[3];
} wri_map_blob_info;

/* fsid and epoch of a full map blob / an incremental blob (rows 1 and 2 of the client block, nothing else is read). */
WR_MUST_CHECK wr_status wri_osdmap_full_info(const uint8_t *p, size_t n, wri_map_blob_info *out, wr_errinfo *why);
WR_MUST_CHECK wr_status wri_osdmap_inc_info(const uint8_t *p, size_t n, wri_map_blob_info *out, wr_errinfo *why);

/* ---- pg_pool_t (module osdmap-pool, wri_osdmap_pool.c) -------------------------------------------------- */

/*
 * Decode one pg_pool_t at the reader's position (osdmap.md 2.5): the legacy envelope (5, 5), then rows 1 to 52 as
 * far as the pool's struct_v has them; fields a client does not keep are stepped over, and the reader ends at
 * the envelope end whatever the pool's struct_v (unknown trailing rows are skipped). Fills out (everything but
 * `id`, `present` and `status`'s CRUSH part) and sets out->status to WR_E_POOL_UNSUPPORTED for a pool this client
 * cannot use (erasure type, tiers or overlay, non-empty erasure profile, stretch, object_hash not 1 or 2, size 0
 * or above WRI_REP_MAX, pg_num or pgp_num 0, pool id or struct_v below WRI_POOL_MIN_V); out->present is set to 1.
 * Computes pg_num_mask / pgp_num_mask. Returns a failing status only for a malformed pool (truncated, struct_compat
 * above WRI_POOL_MAX_COMPAT: WR_E_MAP_VERSION), never for an unsupported one.
 */
WR_MUST_CHECK wr_status wri_pool_decode(wri_rd *r, wri_map_pool *out, wr_errinfo *why);
/* Step over one pg_pool_t without decoding it (the legacy envelope: needs struct_v >= 5). */
WR_MUST_CHECK wr_status wri_pool_skip(wri_rd *r, wr_errinfo *why);

/* ---- full map (module osdmap-full, wri_osdmap_full.c) -------------------------------------------------- */

/*
 * Decode a complete OSDMap blob (osdmap.md 3.3) into `slot` (16-byte aligned, `cap` bytes, at most cfg->slot_bytes):
 * wrapper envelope, client block rows 1 to 25 (kept: fsid, epoch, flags, max_osd, osd_state / osd_weight /
 * client_addrs / osd_primary_affinity, pg_temp, primary_temp, pg_upmap, pg_upmap_items, pg_upmap_primaries,
 * the tracked pools and the CRUSH blob), the OSD-only block skipped by length, the CRC verified when
 * cfg->verify_crc. Pool names are matched against cfg first (names after pools on the wire: pass one skips the
 * pools map, reads pool_name, resolves the tracked ids; pass two decodes only those pools). Runs the rule audit
 * for every tracked pool that is present and sets its status. Validation of osdmap.md 3.6 is applied: arrays
 * with exactly max_osd entries, counts capped against the bytes left, max_osd <= cfg->max_osd.
 * Errors: WR_E_MAP_VERSION, WR_E_MAP_CORRUPT, WR_E_MAP_CRC, WR_E_MAP_BUDGET (does not fit the slot or the config),
 * the CRUSH decoder's codes. On success the slot holds a finished map (wri_osdmap_check passes).
 */
WR_MUST_CHECK wr_status wri_osdmap_decode_full(const wri_mapcfg *cfg, const uint8_t *p, size_t n, uint8_t *slot, size_t cap,
					       wr_errinfo *why);

/* ---- incremental (module osdmap-inc, wri_osdmap_inc.c) ------------------------------------------------- */

/*
 * Apply one OSDMap::Incremental to `src` and build the result into `slot` (a different slot than src):
 * wrapper (7, 7), client block (v8 .. v9) indexed once to find its rows, then the steps of osdmap.md 3.5 in
 * their order (identity and contiguity checks, embedded full map, flags, resize, pools, names, removed pools,
 * weights, affinity, state XOR, new up OSDs with their first msgr2 address, pg_temp, primary_temp, the three
 * upmap pairs, CRUSH last). The OSD-only block is skipped by length; inc_crc is verified when cfg->verify_crc.
 * The map flags change only through new_flags (the OSD-only block is skipped, so Ceph's side effect of new_require_osd_release on
 * RECOVERY_DELETES, PGLOG_HARDLIMIT and the legacy REQUIRE bits is not applied: a client reads the pause and full bits only, and a full map
 * of the same epoch can differ from the chain in those other bits).
 * The pg tables are rebuilt by merging the held sorted tables with the incremental's sorted lists (keys that are
 * not strictly ascending: WR_E_MAP_CORRUPT). A pool that changed or a new CRUSH map re-runs the rule audit for the
 * tracked pools. Errors: WR_E_MAP_FSID, WR_E_MAP_EPOCH (epoch != src->epoch + 1 and no embedded full map: an
 * embedded map is taken whatever the held epoch, but it must name the epoch of its incremental and the held fsid),
 * WR_E_MAP_VERSION, WR_E_MAP_CORRUPT, WR_E_MAP_CRC, WR_E_MAP_BUDGET, the CRUSH decoder's codes; an OSD id outside
 * [0, max_osd) after the resize is WR_E_MAP_CORRUPT, and so are keys that do not ascend in a pool-keyed or pg-keyed
 * list (the OSD-keyed lists may be in any order, they are applied as written). WR_E_MAP_RESYNC when the incremental
 * is fine but cannot be applied to what we kept: a tracked pool name appears for an id whose record neither the
 * incremental nor the held map has (a rename of an untracked pool), or for an id whose record is in new_pools but
 * the incremental creates no pool (new_pool_max is -1, or the id is above it: a pool that existed before and was not tracked, its
 * pg table entries were never kept; the held map does not keep the old pool ceiling, so an older pool renamed in the same epoch that
 * another pool is created in is taken for a new one), or the held map was decoded with another number of tracked pools than cfg->n_pools. WR_E_INVAL: a NULL
 * argument, a slot that overlaps src or the incremental's bytes, a src that is not a finished map. The previous content of `slot` is lost:
 * every failure but WR_E_INVAL leaves magic 0 in it. src is never modified.
 */
WR_MUST_CHECK wr_status wri_osdmap_apply_inc(const wri_mapcfg *cfg, const wri_osdmap *src, const uint8_t *p, size_t n,
					     uint8_t *slot, size_t cap, wr_errinfo *why);

/* ---- helpers shared by the full and incremental decoders (implemented in module osdmap-full) ---------- */

/* The first msgr2 (type 2) address with a usable family of an entity_addrvec_t at the reader, the rest of the
 * vector consumed. An empty vector or one without such an entry gives family 0 (not an error). */
WR_MUST_CHECK wr_status wri_osdmap_read_addr(wri_rd *r, wri_osd_addr *out);

/* Index of `pool_id` in ids[0..n) (the ids the name pass resolved for the tracked pools), or -1. */
WR_INLINE int wri_mapcfg_pool_index(const int64_t *ids, uint32_t n, int64_t pool_id)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (ids[i] == pool_id)
			return (int)i;
	return -1;
}

/* ---- internals of the full-map decoder (shared by wri_osdmap_full.c and wri_osdmap_full2.c; nothing else uses them) ---- */

/* The tracked pools as the name pass resolved them: id[k] is valid where found[k] is 1 (a wire id is any s64, so "not
 * found" is a flag, never a sentinel value). */
typedef struct wri_full_ids {
	int64_t id[WRI_MAP_POOLS_MAX];
	uint8_t found[WRI_MAP_POOLS_MAX];
	uint32_t n;
} wri_full_ids;

/*
 * One walk over rows 7 to 25 of the client block of a full map (wri_full_rows). With b == NULL it is the COUNT pass: it
 * validates, and learns max_osd, whether an affinity array follows and how many entries and values of each pg table
 * belong to tracked pools; nothing is written. With a builder it is the FILL pass over the same bytes: it writes the
 * per-OSD arrays, pushes the table entries and decodes the CRUSH blob into the room the caller carved (the OSD arrays,
 * the pool records, the five tables and the CRUSH room must already be carved from the counts of the first pass).
 */
typedef struct wri_full_walk {
	const uint8_t *base;       /* the whole blob, for the offsets in error reports */
	const wri_full_ids *ids;   /* tracked pools of this map */
	uint32_t block_v;          /* struct_v of the client block */
	uint32_t max_osd_limit;    /* largest max_osd accepted */
	wri_mapbuild *b;           /* NULL: count pass */
	wr_errinfo *why;           /* may be NULL */
	uint32_t flags;            /* row 8 */
	uint32_t max_osd;          /* row 9 (count pass: learned; fill pass: must be the same) */
	uint8_t has_aff;           /* row 15 is non-empty */
	uint8_t reserved[3];
	uint32_t tab_n[WRI_TAB_COUNT];
	uint32_t tab_nv[WRI_TAB_COUNT];
} wri_full_walk;

WR_MUST_CHECK wr_status wri_full_rows(wri_full_walk *w, wri_rd *r);
/* What a failure of a reader or a sub-decoder is called by the map decoders: the MAP_ and CRUSH_ codes stay, every other
 * status (truncated, encoding, too big) is WR_E_MAP_CORRUPT. */
wr_status wri_full_status(wr_status st);

#endif /* WRI_OSDMAP_DEC_H */
