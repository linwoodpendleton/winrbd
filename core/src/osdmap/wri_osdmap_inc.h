/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_inc.h - internals of the incremental decoder, shared by wri_osdmap_inc.c (entry point, envelope, row index, CRUSH),
 * wri_osdmap_inc2.c (tracked pool resolution, pool records, the rule audit) and wri_osdmap_inc3.c (the per-OSD arrays and the pg-table
 * merge). Nothing outside those three files uses it; the public entry point is wri_osdmap_apply_inc (wri_osdmap_dec.h).
 *
 * The incremental is read in two walks (docs/design/core-architecture.md 15.4). The INDEX walk (walk_rows in wri_osdmap_inc.c) steps over
 * the 29 rows of the client block once, validates the structure and every count, and records where each row starts. The
 * APPLY walk then re-reads the rows it needs in the order of osdmap.md 3.5 through a reader made by wri_inc_row. Because the
 * second walk only ever re-reads bytes the first one accepted, it cannot meet a structure the first one did not check.
 */
#ifndef WRI_OSDMAP_INC_H
#define WRI_OSDMAP_INC_H

#include "wri_ctx.h"
#include "wri_osdmap_dec.h"

/* rows of the client block (osdmap.md 2.6.3) */
#define WRI_INC_R_FSID 1u
#define WRI_INC_R_EPOCH 2u
#define WRI_INC_R_POOL_MAX 4u
#define WRI_INC_R_FLAGS 5u
#define WRI_INC_R_FULLMAP 6u
#define WRI_INC_R_CRUSH 7u
#define WRI_INC_R_MAX_OSD 8u
#define WRI_INC_R_NEW_POOLS 9u
#define WRI_INC_R_POOL_NAMES 10u
#define WRI_INC_R_OLD_POOLS 11u
#define WRI_INC_R_UP 12u
#define WRI_INC_R_STATE 13u
#define WRI_INC_R_WEIGHT 14u
#define WRI_INC_R_PG_TEMP 15u
#define WRI_INC_R_PRIMARY_TEMP 16u
#define WRI_INC_R_AFFINITY 17u
#define WRI_INC_R_NEW_UPMAP 20u
#define WRI_INC_R_OLD_UPMAP 21u
#define WRI_INC_R_NEW_ITEMS 22u
#define WRI_INC_R_OLD_ITEMS 23u
#define WRI_INC_R_NEW_UPMAP_PRIMARY 28u
#define WRI_INC_R_OLD_UPMAP_PRIMARY 29u
#define WRI_INC_ROWS_V8 27u /* rows 1 to 27 are in block v8, 28 and 29 come with v9 */
#define WRI_INC_ROWS_V9 29u

typedef struct wri_inc_ix {
	const uint8_t *base;   /* the whole blob, for the offsets in error reports */
	wri_rd body;           /* the client block body; pos 0 is the first byte of row 1 */
	wr_errinfo *why;       /* may be NULL */
	uint32_t block_v;      /* struct_v of the client block */
	uint32_t n_rows;       /* 27 or 29 */
	uint32_t epoch;        /* row 2 */
	uint8_t fsid[16];      /* row 1 */
	int64_t new_pool_max;  /* row 4, -1 = no change */
	int32_t new_flags;     /* row 5, below 0 = no change */
	int32_t new_max_osd;   /* row 8, below 0 = no change */
	uint32_t max_osd;      /* the size after the resize (the OSD ids of rows 12 to 14 and 17 are checked against it) */
	uint32_t max_osd_limit;/* largest max_osd accepted */
	uint32_t full_pos, full_len;   /* row 6 payload: offset in body, length (0 = no embedded map) */
	uint32_t crush_pos, crush_len; /* row 7 payload (0 = no change) */
	uint32_t n_aff;        /* entries of row 17 */
	uint32_t off[WRI_INC_ROWS_V9 + 2u]; /* start of row i in body; off[n_rows + 1] = end of the last row */
} wri_inc_ix;

/* A reader over the client block positioned at the start of `row` (1-based); an empty reader for a row the block lacks. */
WR_INLINE wri_rd wri_inc_row(const wri_inc_ix *ix, unsigned row)
{
	wri_rd r = ix->body;

	r.err = WR_OK;
	r.pos = row <= ix->n_rows ? (size_t)ix->off[row] : r.len;
	return r;
}

/* Offset of a reader's position in the blob, for error reports. */
WR_INLINE size_t wri_inc_off(const wri_inc_ix *ix, const wri_rd *r) { return (size_t)(r->p - ix->base) + r->pos; }

/* A reader failure or a bad value in the incremental, reported with the offset in the blob (module WR_MOD_MAP); the status is the map
 * decoders' name for it (wri_full_status). */
WR_INLINE wr_status wri_inc_fail_rd(const wri_inc_ix *ix, const wri_rd *r, const char *what)
{
	wr_status st = wri_full_status(r->err);

	WRI_ERRINFO(ix->why, st, WR_MOD_MAP, what, wri_inc_off(ix, r), r->len, (uint64_t)(int64_t)r->err);
	return st;
}

WR_INLINE wr_status wri_inc_fail_val(const wri_inc_ix *ix, const wri_rd *r, wr_status st, const char *what, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(ix->why, st, WR_MOD_MAP, what, wri_inc_off(ix, r), a1, a2);
	return st;
}

/* Shared helpers of wri_osdmap_inc2.c and wri_osdmap_inc3.c, used by the index walk in wri_osdmap_inc.c. Each steps over one value and fails with the
 * reason in ix->why; they return WR_OK or a map status (wri_full_status). */
#define WRI_INC_PGMAP_VEC 0u   /* map<pg_t, vector<s32>> */
#define WRI_INC_PGMAP_ONE 1u   /* map<pg_t, s32> */
#define WRI_INC_PGMAP_PAIRS 2u /* map<pg_t, vector<pair<s32, s32>>> */
WR_MUST_CHECK wr_status wri_inc_skip_pgmap(const wri_inc_ix *ix, wri_rd *r, unsigned style, const char *what);
WR_MUST_CHECK wr_status wri_inc_skip_pgset(const wri_inc_ix *ix, wri_rd *r, const char *what); /* set<pg_t>, ascending */
WR_MUST_CHECK wr_status wri_inc_skip_pools(const wri_inc_ix *ix, wri_rd *r); /* map<s64, pg_pool_t>, ascending keys */
WR_MUST_CHECK wr_status wri_inc_skip_names(const wri_inc_ix *ix, wri_rd *r); /* map<s64, string>, ascending keys */
WR_MUST_CHECK wr_status wri_inc_skip_idset(const wri_inc_ix *ix, wri_rd *r); /* set<s64>, ascending */

/* ---- the tracked pools of the new map ------------------------------------------------------------------- */

typedef struct wri_inc_pools {
	uint32_t n;                          /* tracked pools (cfg->n_pools) */
	int64_t id[WRI_MAP_POOLS_MAX];       /* valid where found[k] */
	uint8_t found[WRI_MAP_POOLS_MAX];    /* the pool exists in the new map */
	uint8_t in_inc[WRI_MAP_POOLS_MAX];   /* its record is in new_pools (decode it) */
	int8_t held[WRI_MAP_POOLS_MAX];      /* else: the held slot whose record is copied */
	uint8_t matched[WRI_MAP_POOLS_MAX];  /* scratch of wri_inc_resolve_pools: a name of new_pool_names is this slot's */
	uint8_t away[WRI_MAP_POOLS_MAX];     /* scratch: the id this slot held carries another name now */
	int64_t mid[WRI_MAP_POOLS_MAX];      /* scratch: the id that name belongs to */
} wri_inc_pools;

/*
 * Step 5 of osdmap.md 3.5 for the tracked pools, before anything is built: re-resolve the ids from new_pool_names, then
 * learn which ids new_pools carries, then apply old_pools (removal wins). Fails with WR_E_MAP_RESYNC when a tracked pool
 * is found at an id for which the incremental has no record and the held map has none, or when the pool looks as if it
 * existed before (its record is in new_pools, no held slot had it, and the incremental creates no pool: new_pool_max is -1 or below the id): its entries in
 * the pg tables were never kept. WR_E_MAP_CORRUPT for a tracked name on two ids.
 */
WR_MUST_CHECK wr_status wri_inc_resolve_pools(const wri_mapcfg *cfg, const wri_osdmap *src, const wri_inc_ix *ix, wri_inc_pools *pp);
/* Write the pool records of the new map into the carved array: held records copied (status reset, the audit decides it
 * again), new_pools records decoded, absent pools left zero. `note` gets the first decode reason for an unusable pool. */
WR_MUST_CHECK wr_status wri_inc_fill_pools(const wri_inc_ix *ix, const wri_inc_pools *pp, const wri_osdmap *src, wri_mapbuild *b,
					   wr_errinfo *note);
/* The sections of the held slot lie inside it, so what the copy reads is in bounds even if the slot was damaged (a finished map that
 * passed wri_osdmap_check always satisfies this; it is not a substitute for that check). */
int wri_inc_src_sane(const wri_osdmap *s);

/* The rule audit of every present tracked pool that is otherwise usable: its answer becomes the pool's status; `note` gets the first reason. */
void wri_inc_audit_pools(wri_mapbuild *b, wr_errinfo *note);

/*
 * The per-OSD steps of osdmap.md 3.5 (resize, weights, affinity, state, up) into the carved arrays of the new slot, from the held map `src`
 * and the incremental's rows. The OSD ids were checked against the new max_osd by the index walk.
 */
WR_MUST_CHECK wr_status wri_inc_apply_osds(const wri_inc_ix *ix, wri_mapbuild *b, const wri_osdmap *src);

/*
 * One pg table of the new map: the held table (sorted, only the pools still tracked) merged with the incremental's sorted
 * upserts, minus its removals. With b == NULL it only counts (*n entries, *nv values); with a builder it pushes. For
 * WRI_TAB_PG_TEMP an empty vector and for WRI_TAB_PRIMARY_TEMP the value -1 in the upserts remove the key.
 */
WR_MUST_CHECK wr_status wri_inc_merge_tab(const wri_inc_ix *ix, const wri_inc_pools *pp, const wri_osdmap *src, unsigned kind,
					  wri_mapbuild *b, uint32_t *n, uint32_t *nv);

#endif /* WRI_OSDMAP_INC_H */
