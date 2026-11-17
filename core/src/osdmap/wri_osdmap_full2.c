/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_full2.c - rows 7 to 25 of the client block of a full OSDMap (docs/spec/osdmap.md 2.4.3, architecture 15.2.2
 * and 15.4 step 4 and 5): the walk that wri_osdmap_decode_full runs twice over the same bytes.
 *
 * The COUNT pass (no builder) checks everything a hostile map could get wrong, and learns what the slot has to hold:
 * max_osd, whether an affinity array follows, and for each of the five pg tables how many entries and values belong to the
 * tracked pools. The caller then carves the slot exactly. The FILL pass (a builder) reads the same bytes again and writes:
 * the per-OSD arrays, the table entries, and the CRUSH blob straight into the room that ends the slot. Because both passes
 * run the same code, a count and a fill can never disagree about what an entry is.
 *
 * Nothing is allocated, nothing is trusted: every count is compared with the bytes that are left before it drives a loop
 * (wri_rd_count divides, so nothing wraps on a 32-bit size_t), array lengths must equal max_osd exactly, and the keys of
 * every pg-keyed map must ascend strictly across ALL entries, kept or not (a std::map is written in key order, so anything
 * else is damage; it also lets the tables be searched by bisection and merged by the incremental).
 */
#include "wri_osdmap_dec.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define PG_ENTRY_MIN 21u /* pg_t (17 bytes) + a u32 count or an s32 */
#define POOL_ID_LIMIT ((uint64_t)1 << WRI_MAP_NAME_ID_BITS)

#define STYLE_VEC 0u   /* u32 count, then s32 each */
#define STYLE_ONE 1u   /* one s32 */
#define STYLE_PAIRS 2u /* u32 count, then (s32, s32) each */

/* ---- failures --------------------------------------------------------------------------------------- */

wr_status wri_full_status(wr_status st)
{
	switch (st) {
	case WR_E_MAP_VERSION:
	case WR_E_MAP_BUDGET:
	case WR_E_MAP_CRC:
	case WR_E_MAP_FSID:
	case WR_E_MAP_EPOCH:
	case WR_E_MAP_RESYNC:
	case WR_E_MAP_CORRUPT:
	case WR_E_CRUSH_ENCODING:
	case WR_E_CRUSH_UNSUPPORTED:
	case WR_E_CRUSH_NO_RULE:
	case WR_E_CRUSH_LOOP:
	case WR_E_CRUSH_WORK:
		return st;
	default:
		return WR_E_MAP_CORRUPT;
	}
}

/* Offset of the reader's position in the blob (readers made by wri_rd_sub all point into the same buffer). */
static size_t off_of(const wri_full_walk *w, const wri_rd *r)
{
	return (size_t)(r->p - w->base) + r->pos;
}

/* The reader failed: the status is the map decoders' name for it, a1 the bytes of the block, a2 the raw status. */
static wr_status fail_rd(const wri_full_walk *w, const wri_rd *r, const char *what)
{
	wr_status st = wri_full_status(r->err);

	WRI_ERRINFO(w->why, st, WR_MOD_MAP, what, off_of(w, r), r->len, (uint64_t)(int64_t)r->err);
	return st;
}

static wr_status fail_val(const wri_full_walk *w, const wri_rd *r, wr_status st, const char *what, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(w->why, st, WR_MOD_MAP, what, off_of(w, r), a1, a2);
	return st;
}

/* ---- the pg-keyed tables ------------------------------------------------------------------------------ */

static int is_tracked(const wri_full_ids *ids, uint64_t pool)
{
	uint32_t k;

	if (pool >= POOL_ID_LIMIT)
		return 0; /* a tracked pool id fits 31 bits: any other id can only belong to a pool we do not keep */
	for (k = 0; k < ids->n; k++)
		if (ids->found[k] != 0 && ids->id[k] == (int64_t)pool)
			return 1;
	return 0;
}

static const char *tab_what(unsigned kind)
{
	switch (kind) {
	case WRI_TAB_PG_TEMP:
		return "pg_temp is malformed";
	case WRI_TAB_PRIMARY_TEMP:
		return "primary_temp is malformed";
	case WRI_TAB_PG_UPMAP:
		return "pg_upmap is malformed";
	case WRI_TAB_PG_UPMAP_ITEMS:
		return "pg_upmap_items is malformed";
	default:
		return "pg_upmap_primaries is malformed";
	}
}

/* One map<pg_t, ...> of the map (rows 13, 14, 18, 19, 25). */
static wr_status tab_walk(wri_full_walk *w, wri_rd *r, unsigned kind, unsigned style)
{
	uint32_t n, i, j, cnt, nv;
	uint64_t prev_pool = 0;
	uint32_t prev_seed = 0;
	size_t elem = style == STYLE_PAIRS ? 8u : 4u;
	int have_prev = 0;

	n = wri_rd_count(r, 0xFFFFFFFFu, PG_ENTRY_MIN);
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		int32_t vals[WRI_MAP_PGVEC_MAX * 2u];
		wri_pg pg;
		int tracked;
		wr_status st;

		if (wri_denc_pg(r, &pg) != WR_OK)
			break;
		if (have_prev && (pg.pool < prev_pool || (pg.pool == prev_pool && pg.seed <= prev_seed)))
			return fail_val(w, r, WR_E_MAP_CORRUPT, "pg keys are not strictly ascending", pg.pool, pg.seed);
		have_prev = 1;
		prev_pool = pg.pool;
		prev_seed = pg.seed;
		tracked = is_tracked(w->ids, pg.pool);

		if (style == STYLE_ONE) {
			vals[0] = wri_rd_i32(r);
			cnt = 1;
			nv = 1;
		} else {
			cnt = wri_rd_count(r, 0xFFFFFFFFu, elem);
			if (!wri_rd_ok(r))
				break;
			if (!tracked) {
				wri_rd_skip(r, (size_t)cnt * elem); /* cnt * elem is below the bytes left: wri_rd_count checked it */
				continue;
			}
			if (cnt > WRI_MAP_PGVEC_MAX)
				return fail_val(w, r, WR_E_MAP_BUDGET, "pg vector longer than the kept maximum", cnt, WRI_MAP_PGVEC_MAX);
			nv = style == STYLE_PAIRS ? cnt * 2u : cnt;
			for (j = 0; j < nv; j++)
				vals[j] = wri_rd_i32(r);
		}
		if (!wri_rd_ok(r) || !tracked)
			continue;
		if (w->b == NULL) {
			w->tab_n[kind]++;
			w->tab_nv[kind] += nv;
		} else {
			st = wri_pgtab_push(w->b, kind, wri_pg_key((uint32_t)pg.pool, pg.seed), vals, nv);
			if (st != WR_OK)
				return st; /* the builder has put the reason in the errinfo */
		}
	}
	if (!wri_rd_ok(r))
		return fail_rd(w, r, tab_what(kind));
	return WR_OK;
}

/* ---- the per-OSD rows --------------------------------------------------------------------------------- */

/* A vector with exactly max_osd entries of at least elem_min bytes each: its count read and checked. */
static wr_status osd_vec(const wri_full_walk *w, wri_rd *r, uint32_t max_osd, size_t elem_min, const char *what)
{
	uint32_t n = wri_rd_u32(r);

	if (!wri_rd_ok(r))
		return fail_rd(w, r, what);
	if (n != max_osd)
		return fail_val(w, r, WR_E_MAP_CORRUPT, what, max_osd, n);
	if ((size_t)n > wri_rd_left(r) / elem_min) {
		wri_rd_fail(r, WR_E_TRUNCATED);
		return fail_rd(w, r, what);
	}
	return WR_OK;
}

static wr_status osd_rows(wri_full_walk *w, wri_rd *r, uint32_t mo)
{
	wri_mapbuild *b = w->b;
	uint8_t *base = b != NULL ? wri_map_base_rw(b->m) : NULL;
	uint32_t i;
	wr_status st;

	/* 10 osd_state: only EXISTS and UP are kept */
	st = osd_vec(w, r, mo, 4u, "osd_state does not have max_osd entries");
	if (st != WR_OK)
		return st;
	if (b == NULL) {
		wri_rd_skip(r, (size_t)mo * 4u);
	} else {
		uint8_t *state = base + b->m->state_off;

		for (i = 0; i < mo; i++)
			state[i] = (uint8_t)(wri_rd_u32(r) & (WRI_OSD_EXISTS | WRI_OSD_UP));
	}

	/* 11 osd_weight */
	st = osd_vec(w, r, mo, 4u, "osd_weight does not have max_osd entries");
	if (st != WR_OK)
		return st;
	if (b == NULL) {
		wri_rd_skip(r, (size_t)mo * 4u);
	} else {
		uint32_t *wt = (uint32_t *)(void *)(base + b->m->weight_off);

		for (i = 0; i < mo; i++)
			wt[i] = wri_rd_u32(r);
	}

	/* 12 client_addrs: the first msgr2 entry of each vector */
	st = osd_vec(w, r, mo, 5u, "client_addrs does not have max_osd entries");
	if (st != WR_OK)
		return st;
	{
		wri_osd_addr scratch;
		wri_osd_addr *ad = b != NULL ? (wri_osd_addr *)(void *)(base + b->m->addr_off) : NULL;

		for (i = 0; i < mo; i++) {
			st = wri_osdmap_read_addr(r, ad != NULL ? &ad[i] : &scratch);
			if (st != WR_OK)
				return fail_val(w, r, st, st == WR_E_MAP_VERSION ? "OSD address in a form this client does not read"
									: "OSD address vector is malformed",
						i, mo);
		}
	}
	return WR_OK;
}

/* ---- rows 7 to 25 ------------------------------------------------------------------------------------- */

static void skip_snap_sets(wri_rd *r)
{
	uint32_t n = wri_denc_count(r, 0xFFFFFFFFu, 8u + 4u); /* map<s64, interval_set>: key + the interval count */
	uint32_t i;

	for (i = 0; i < n && wri_rd_ok(r); i++) {
		wri_rd_skip(r, 8u);
		wri_denc_skip_interval_set(r);
	}
}

wr_status wri_full_rows(wri_full_walk *w, wri_rd *r)
{
	wri_mapbuild *b = w->b;
	uint32_t mo, n;
	int32_t smo;
	wr_status st;

	wri_rd_skip(r, 4u);       /* 7 pool_max */
	w->flags = wri_rd_u32(r); /* 8 flags */
	smo = wri_rd_i32(r);      /* 9 max_osd */
	if (!wri_rd_ok(r))
		return fail_rd(w, r, "OSD map header rows cut short");
	if (smo < 0)
		return fail_val(w, r, WR_E_MAP_CORRUPT, "max_osd is negative", (uint64_t)(int64_t)smo, 0);
	mo = (uint32_t)smo;
	if (b == NULL) {
		if (mo > w->max_osd_limit)
			return fail_val(w, r, WR_E_MAP_BUDGET, "max_osd above the configured limit", mo, w->max_osd_limit);
		w->max_osd = mo;
	} else if (mo != w->max_osd) {
		return fail_val(w, r, WR_E_MAP_CORRUPT, "max_osd changed between the two passes", w->max_osd, mo);
	} else {
		b->m->flags = w->flags;
	}

	st = osd_rows(w, r, mo); /* 10, 11, 12 */
	if (st != WR_OK)
		return st;

	st = tab_walk(w, r, WRI_TAB_PG_TEMP, STYLE_VEC); /* 13 */
	if (st != WR_OK)
		return st;
	st = tab_walk(w, r, WRI_TAB_PRIMARY_TEMP, STYLE_ONE); /* 14 */
	if (st != WR_OK)
		return st;

	/* 15 osd_primary_affinity: empty = every OSD at the default, otherwise exactly max_osd entries */
	n = wri_rd_u32(r);
	if (!wri_rd_ok(r))
		return fail_rd(w, r, "osd_primary_affinity cut short");
	if (n != 0) {
		if (n != mo)
			return fail_val(w, r, WR_E_MAP_CORRUPT, "osd_primary_affinity is neither empty nor max_osd entries", mo, n);
		if ((size_t)n > wri_rd_left(r) / 4u) {
			wri_rd_fail(r, WR_E_TRUNCATED);
			return fail_rd(w, r, "osd_primary_affinity cut short");
		}
		if (b == NULL) {
			w->has_aff = 1;
			wri_rd_skip(r, (size_t)n * 4u);
		} else {
			uint32_t *af = (uint32_t *)(void *)(wri_map_base_rw(b->m) + b->m->aff_off);
			uint32_t i;

			if (b->m->aff_off == 0)
				return fail_val(w, r, WR_E_MAP_CORRUPT, "affinity array was not carved", 0, 0);
			for (i = 0; i < n; i++)
				af[i] = wri_rd_u32(r);
		}
	}

	/* 16 crush: a blob, decoded straight into the room that ends the slot */
	n = wri_rd_u32(r);
	{
		const uint8_t *blob = wri_rd_bytes(r, n);

		if (!wri_rd_ok(r) || blob == NULL)
			return fail_rd(w, r, "CRUSH blob cut short");
		if (b != NULL) {
			size_t used = 0;

			if (b->m->crush_off == 0)
				return fail_val(w, r, WR_E_MAP_CORRUPT, "CRUSH room was not carved", 0, 0);
			st = wri_crush_decode(blob, n, wri_map_base_rw(b->m) + b->m->crush_off, b->used - b->m->crush_off, &used, w->why);
			if (st != WR_OK)
				return st;
		}
	}

	wri_denc_skip_str_map_map(r); /* 17 erasure_code_profiles */
	if (!wri_rd_ok(r))
		return fail_rd(w, r, "erasure_code_profiles is malformed");
	st = tab_walk(w, r, WRI_TAB_PG_UPMAP, STYLE_VEC); /* 18 */
	if (st != WR_OK)
		return st;
	st = tab_walk(w, r, WRI_TAB_PG_UPMAP_ITEMS, STYLE_PAIRS); /* 19 */
	if (st != WR_OK)
		return st;
	wri_rd_skip(r, 4u); /* 20 crush_version */
	skip_snap_sets(r);  /* 21 new_removed_snaps */
	skip_snap_sets(r);  /* 22 new_purged_snaps */
	wri_rd_skip(r, 16u); /* 23, 24 last_up_change, last_in_change */
	if (!wri_rd_ok(r))
		return fail_rd(w, r, "OSD map rows 17 to 24 are malformed");
	if (w->block_v >= 10u) { /* 25 pg_upmap_primaries */
		st = tab_walk(w, r, WRI_TAB_PG_UPMAP_PRIMARY, STYLE_ONE);
		if (st != WR_OK)
			return st;
	}
	return WR_OK; /* rows above 25 are in the rest of the block, which the caller never reads */
}
