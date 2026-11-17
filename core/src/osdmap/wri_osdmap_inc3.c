/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_inc3.c - the data side of applying an OSDMap::Incremental: the per-OSD arrays (docs/spec/osdmap.md 3.5 steps 6 and 11 to 14)
 * and the five pg tables (steps 15 to 17), architecture 15.4. The entry point is in wri_osdmap_inc.c, the pools in wri_osdmap_inc2.c.
 *
 * A pg table is never edited in place. The held table, filtered to the pools that are still tracked, and the incremental's upserts are
 * walked together in key order and the result is appended to the new slot's table; the incremental's removals are a third sorted list
 * walked beside them. The same code runs once to COUNT (so the slot is carved exactly) and once to FILL, so a count and a fill cannot
 * disagree.
 */
#include "wri_osdmap_inc.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define PG_ENTRY_MIN 21u /* pg_t (17 bytes) + a u32 count or an s32 */
#define PG_KEY_MIN 17u
#define POOL_ID_LIMIT ((uint64_t)1 << WRI_MAP_NAME_ID_BITS)

/* push_upsert keeps the values of one vector on the stack (256 bytes); it must not be folded into the merge loop, or its frame adds them
 * up (the core builds with a 1 KiB frame limit, and under ASan every local costs its red zones as well). */
#if defined(__GNUC__) || defined(__clang__)
#define INC_NOINLINE __attribute__((noinline))
#else
#define INC_NOINLINE
#endif

/* ---- the per-OSD arrays ------------------------------------------------------------------------------- */

/* The arrays of the new slot, as the per-OSD steps use them. */
typedef struct osd_arrays {
	uint8_t *state;
	uint32_t *weight;
	uint32_t *aff; /* NULL: no affinity array */
	wri_osd_addr *addr;
	uint32_t max_osd;
} osd_arrays;

static osd_arrays arrays_of(wri_osdmap *m)
{
	osd_arrays a;
	uint8_t *base = wri_map_base_rw(m);

	a.state = base + m->state_off;
	a.weight = (uint32_t *)(void *)(base + m->weight_off);
	a.aff = m->aff_off != 0 ? (uint32_t *)(void *)(base + m->aff_off) : NULL;
	a.addr = (wri_osd_addr *)(void *)(base + m->addr_off);
	a.max_osd = m->max_osd;
	return a;
}

/* Step 11: store the weight; a non-zero one brings the OSD into existence. */
static wr_status step_weights(const wri_inc_ix *ix, const osd_arrays *a)
{
	wri_rd r = wri_inc_row(ix, WRI_INC_R_WEIGHT);
	uint32_t n = wri_rd_count(&r, 0xFFFFFFFFu, 8u), i;

	for (i = 0; i < n && wri_rd_ok(&r); i++) {
		int32_t id = wri_rd_i32(&r);
		uint32_t w = wri_rd_u32(&r);

		if (!wri_rd_ok(&r) || id < 0 || (uint32_t)id >= a->max_osd)
			return wri_inc_fail_rd(ix, &r, "new_weight is malformed");
		a->weight[id] = w;
		if (w != 0)
			a->state[id] = (uint8_t)(a->state[id] | WRI_OSD_EXISTS);
	}
	return WR_OK;
}

/* Step 12: the affinity array exists (it was carved because this row is not empty or the held map had one). */
static wr_status step_affinity(const wri_inc_ix *ix, const osd_arrays *a)
{
	wri_rd r = wri_inc_row(ix, WRI_INC_R_AFFINITY);
	uint32_t n = wri_rd_count(&r, 0xFFFFFFFFu, 8u), i;

	for (i = 0; i < n && wri_rd_ok(&r); i++) {
		int32_t id = wri_rd_i32(&r);
		uint32_t v = wri_rd_u32(&r);

		if (!wri_rd_ok(&r) || a->aff == NULL || id < 0 || (uint32_t)id >= a->max_osd)
			return wri_inc_fail_rd(ix, &r, "new_primary_affinity is malformed");
		a->aff[id] = v;
	}
	return WR_OK;
}

/* Step 13: XOR on the kept bits; a mask of 0 toggles UP; EXISTS on an existing OSD destroys it. */
static wr_status step_state(const wri_inc_ix *ix, const osd_arrays *a)
{
	wri_rd r = wri_inc_row(ix, WRI_INC_R_STATE);
	uint32_t n = wri_rd_count(&r, 0xFFFFFFFFu, 8u), i;

	for (i = 0; i < n && wri_rd_ok(&r); i++) {
		int32_t id = wri_rd_i32(&r);
		uint32_t mask = wri_rd_u32(&r);

		if (!wri_rd_ok(&r) || id < 0 || (uint32_t)id >= a->max_osd)
			return wri_inc_fail_rd(ix, &r, "new_state is malformed");
		if (mask == 0)
			mask = WRI_OSD_UP;
		if ((a->state[id] & WRI_OSD_EXISTS) != 0 && (mask & WRI_OSD_EXISTS) != 0) {
			a->state[id] = 0;
			WR_MEMSET(&a->addr[id], 0, sizeof(a->addr[id]));
			if (a->aff != NULL)
				a->aff[id] = WRI_OSD_IN_FULL;
		} else {
			a->state[id] = (uint8_t)(a->state[id] ^ (mask & (WRI_OSD_EXISTS | WRI_OSD_UP)));
		}
	}
	return WR_OK;
}

/* Step 14: after the state step, so an OSD can be destroyed and re-added in one epoch. */
static wr_status step_up(const wri_inc_ix *ix, const osd_arrays *a)
{
	wri_rd r = wri_inc_row(ix, WRI_INC_R_UP);
	uint32_t n = wri_rd_count(&r, 0xFFFFFFFFu, 4u + 5u), i;

	for (i = 0; i < n && wri_rd_ok(&r); i++) {
		int32_t id = wri_rd_i32(&r);

		if (!wri_rd_ok(&r) || id < 0 || (uint32_t)id >= a->max_osd)
			return wri_inc_fail_rd(ix, &r, "new_up_client is malformed");
		if (wri_osdmap_read_addr(&r, &a->addr[id]) != WR_OK)
			return wri_inc_fail_rd(ix, &r, "OSD address vector is malformed");
		a->state[id] = (uint8_t)(a->state[id] | WRI_OSD_EXISTS | WRI_OSD_UP);
	}
	return WR_OK;
}

/* The per-OSD steps: the resize (the common prefix is kept, a new slot is state 0, weight 0, no address, the default affinity),
 * then weights, affinity, state and up in the order of osdmap.md 3.5. */
wr_status wri_inc_apply_osds(const wri_inc_ix *ix, wri_mapbuild *b, const wri_osdmap *src)
{
	osd_arrays a = arrays_of(b->m);
	uint32_t n0 = src->max_osd < a.max_osd ? src->max_osd : a.max_osd;
	wr_status st;

	if (n0 != 0) {
		WR_MEMCPY(a.state, wri_map_state(src), n0);
		WR_MEMCPY(a.weight, wri_map_weight(src), (size_t)n0 * sizeof(uint32_t));
		WR_MEMCPY(a.addr, wri_map_addr(src), (size_t)n0 * sizeof(wri_osd_addr));
		if (a.aff != NULL && wri_map_aff(src) != NULL)
			WR_MEMCPY(a.aff, wri_map_aff(src), (size_t)n0 * sizeof(uint32_t));
	}
	st = step_weights(ix, &a);
	if (st == WR_OK)
		st = step_affinity(ix, &a);
	if (st == WR_OK)
		st = step_state(ix, &a);
	if (st == WR_OK)
		st = step_up(ix, &a);
	return st;
}

/* ---- the pg tables ------------------------------------------------------------------------------------- */

static int is_tracked(const wri_inc_pools *pp, uint64_t pool)
{
	uint32_t k;

	if (pool >= POOL_ID_LIMIT)
		return 0; /* a tracked pool id fits 31 bits: any other id can only belong to a pool we do not keep */
	for (k = 0; k < pp->n; k++)
		if (pp->found[k] != 0 && pp->id[k] == (int64_t)pool)
			return 1;
	return 0;
}

/* The incremental's upserts of one table, read one tracked entry at a time (the entries of untracked pools are stepped over). The values of
 * the loaded entry are not copied: `vr` is a reader at the first of them (a push reads them from there), `one` is the value of a one-value row. */
typedef struct upserts {
	wri_rd r;
	wri_rd vr;
	uint32_t left;
	unsigned style;
	unsigned kind;
	int have;       /* an entry is loaded */
	int del;        /* the loaded entry is a removal (empty pg_temp vector, primary_temp -1) */
	uint64_t key;
	uint32_t nv;
	int32_t one;
} upserts;

/* Load the tracked entry whose key and count were just read: the values are stepped over, a push reads them again. */
static wr_status up_load(upserts *u, const wri_inc_ix *ix, const wri_pg *pg, uint32_t cnt)
{
	if (cnt > WRI_MAP_PGVEC_MAX)
		return wri_inc_fail_val(ix, &u->r, WR_E_MAP_BUDGET, "pg vector longer than the kept maximum", cnt, WRI_MAP_PGVEC_MAX);
	u->vr = u->r;
	if (u->style == WRI_INC_PGMAP_ONE) {
		u->nv = 1;
		u->one = wri_rd_i32(&u->r);
	} else {
		u->nv = u->style == WRI_INC_PGMAP_PAIRS ? cnt * 2u : cnt;
		u->one = 0;
		wri_rd_skip(&u->r, (size_t)cnt * (u->style == WRI_INC_PGMAP_PAIRS ? 8u : 4u));
	}
	if (!wri_rd_ok(&u->r))
		return wri_inc_fail_rd(ix, &u->r, "an upsert list of the incremental is malformed");
	u->key = wri_pg_key((uint32_t)pg->pool, pg->seed);
	u->del = (u->kind == WRI_TAB_PG_TEMP && u->nv == 0) || (u->kind == WRI_TAB_PRIMARY_TEMP && u->one == -1);
	u->have = 1;
	return WR_OK;
}

/* The next entry of the upsert list that belongs to a tracked pool (the others are stepped over); u->have is 0 at the end. */
static wr_status up_next(upserts *u, const wri_inc_ix *ix, const wri_inc_pools *pp)
{
	u->have = 0;
	while (u->left > 0 && wri_rd_ok(&u->r)) {
		wri_pg pg;
		uint32_t cnt = 1;

		u->left--;
		if (wri_denc_pg(&u->r, &pg) != WR_OK)
			break;
		if (u->style != WRI_INC_PGMAP_ONE) {
			cnt = wri_rd_count(&u->r, 0xFFFFFFFFu, u->style == WRI_INC_PGMAP_PAIRS ? 8u : 4u);
			if (!wri_rd_ok(&u->r))
				break;
		}
		if (is_tracked(pp, pg.pool))
			return up_load(u, ix, &pg, cnt);
		wri_rd_skip(&u->r, u->style == WRI_INC_PGMAP_ONE ? 4u : (size_t)cnt * (u->style == WRI_INC_PGMAP_PAIRS ? 8u : 4u));
	}
	if (!wri_rd_ok(&u->r))
		return wri_inc_fail_rd(ix, &u->r, "an upsert list of the incremental is malformed");
	return WR_OK;
}

/* Push the loaded upsert into the new table: its values are read from the wire here, into a buffer of this frame only. */
INC_NOINLINE static wr_status push_upsert(const wri_inc_ix *ix, wri_mapbuild *b, unsigned kind, const upserts *u)
{
	int32_t vals[WRI_MAP_PGVEC_MAX * 2u];
	wri_rd r = u->vr;
	uint32_t j;

	if (u->style == WRI_INC_PGMAP_ONE) {
		vals[0] = u->one;
	} else {
		for (j = 0; j < u->nv; j++)
			vals[j] = wri_rd_i32(&r);
		if (!wri_rd_ok(&r))
			return wri_inc_fail_rd(ix, &r, "an upsert list of the incremental is malformed");
	}
	return wri_pgtab_push(b, kind, u->key, vals, u->nv);
}

/* The incremental's removals of one table (a set<pg_t>), one key at a time. */
typedef struct removals {
	wri_rd r;
	uint32_t left;
	int have;
	uint64_t key;
} removals;

static wr_status rm_next(removals *m, const wri_inc_ix *ix)
{
	wri_pg pg;

	m->have = 0;
	if (m->left == 0)
		return WR_OK;
	m->left--;
	if (wri_denc_pg(&m->r, &pg) != WR_OK)
		return wri_inc_fail_rd(ix, &m->r, "a removal list of the incremental is malformed");
	if (pg.pool >= POOL_ID_LIMIT) {
		m->left = 0; /* the list ascends, so every key left is of a pool we cannot track; the key would not even fit the table's */
		return WR_OK;
	}
	m->key = ((uint64_t)pg.pool << 32) | pg.seed;
	m->have = 1;
	return WR_OK;
}

static void rows_of_kind(unsigned kind, unsigned *urow, unsigned *drow, unsigned *style)
{
	*drow = 0;
	switch (kind) {
	case WRI_TAB_PG_TEMP:
		*urow = WRI_INC_R_PG_TEMP;
		*style = WRI_INC_PGMAP_VEC;
		break;
	case WRI_TAB_PRIMARY_TEMP:
		*urow = WRI_INC_R_PRIMARY_TEMP;
		*style = WRI_INC_PGMAP_ONE;
		break;
	case WRI_TAB_PG_UPMAP:
		*urow = WRI_INC_R_NEW_UPMAP;
		*drow = WRI_INC_R_OLD_UPMAP;
		*style = WRI_INC_PGMAP_VEC;
		break;
	case WRI_TAB_PG_UPMAP_ITEMS:
		*urow = WRI_INC_R_NEW_ITEMS;
		*drow = WRI_INC_R_OLD_ITEMS;
		*style = WRI_INC_PGMAP_PAIRS;
		break;
	default:
		*urow = WRI_INC_R_NEW_UPMAP_PRIMARY;
		*drow = WRI_INC_R_OLD_UPMAP_PRIMARY;
		*style = WRI_INC_PGMAP_ONE;
		break;
	}
}

/* One merge: the held table (filtered), the upserts and the removals, walked together in key order. */
typedef struct merge {
	const wri_inc_ix *ix;
	const wri_inc_pools *pp;
	wri_mapbuild *b;       /* NULL: count only */
	unsigned kind;
	const uint64_t *hk;    /* the held table: keys, offsets, values */
	const uint32_t *ho;
	const int32_t *hv;
	uint32_t hi, hn;       /* next held entry, held entries */
	uint32_t n, nv;        /* entries and values produced */
	upserts u;
	removals m;
} merge;

/* What one step of the merge decided about: the key, where its values are, and whether it is a removal. */
typedef struct mcand {
	uint64_t key;
	const int32_t *vals; /* a held entry: its values; NULL for an upsert (read from the wire when pushed) */
	uint32_t nvals;
	int from_u;
	int del;
} mcand;

static void held_init(merge *g, const wri_osdmap *src, unsigned kind)
{
	const wri_pgtab *t = &src->tab[kind];

	g->hk = t->n != 0 ? wri_pgtab_keys(src, kind) : NULL;
	g->ho = t->n != 0 ? wri_pgtab_offs(src, kind) : NULL;
	g->hv = t->n != 0 ? wri_pgtab_vals(src, kind) : NULL;
	g->hi = 0;
	g->hn = t->n;
	g->n = g->nv = 0;
}

static wr_status upserts_init(upserts *u, const wri_inc_ix *ix, unsigned kind, unsigned urow, unsigned style)
{
	u->r = wri_inc_row(ix, urow);
	u->left = urow <= ix->n_rows ? wri_rd_count(&u->r, 0xFFFFFFFFu, PG_ENTRY_MIN) : 0u; /* a block of v8 has no upmap-primary rows */
	u->style = style;
	u->kind = kind;
	u->vr = u->r;
	u->have = u->del = 0;
	u->key = 0;
	u->nv = 0;
	u->one = 0;
	return wri_rd_ok(&u->r) ? WR_OK : wri_inc_fail_rd(ix, &u->r, "a pg table row of the incremental is malformed");
}

static wr_status removals_init(removals *m, const wri_inc_ix *ix, unsigned drow)
{
	m->r = wri_inc_row(ix, drow != 0 ? drow : 1u);
	m->left = drow != 0 && drow <= ix->n_rows ? wri_rd_count(&m->r, 0xFFFFFFFFu, PG_KEY_MIN) : 0u;
	m->have = 0;
	m->key = 0;
	return wri_rd_ok(&m->r) ? WR_OK : wri_inc_fail_rd(ix, &m->r, "a pg table row of the incremental is malformed");
}

/* The two incremental lists of this table: the upserts and, for the tables that have them, the removals. */
static wr_status lists_init(merge *g, const wri_inc_ix *ix, unsigned kind)
{
	unsigned urow, drow, style;
	wr_status st;

	rows_of_kind(kind, &urow, &drow, &style);
	st = upserts_init(&g->u, ix, kind, urow, style);
	return st == WR_OK ? removals_init(&g->m, ix, drow) : st;
}

static wr_status merge_init(merge *g, const wri_inc_ix *ix, const wri_inc_pools *pp, const wri_osdmap *src, unsigned kind, wri_mapbuild *b)
{
	wr_status st;

	g->ix = ix;
	g->pp = pp;
	g->b = b;
	g->kind = kind;
	held_init(g, src, kind);
	st = lists_init(g, ix, kind);
	if (st == WR_OK)
		st = up_next(&g->u, ix, pp);
	return st == WR_OK ? rm_next(&g->m, ix) : st;
}

/* The held entries of pools that are no longer tracked are dropped. */
static void held_skip(merge *g)
{
	while (g->hi < g->hn && !is_tracked(g->pp, g->hk[g->hi] >> 32))
		g->hi++;
}

static void take_upsert(merge *g, mcand *c)
{
	c->from_u = 1;
	c->key = g->u.key;
	c->nvals = g->u.nv;
	c->del = g->u.del;
	c->vals = NULL;
	if (g->hi < g->hn && g->hk[g->hi] == c->key)
		g->hi++; /* an upsert replaces the held entry of the same key */
}

static void take_held(merge *g, mcand *c)
{
	uint32_t i = g->hi++;

	c->from_u = 0;
	c->key = g->hk[i];
	c->vals = g->hv + g->ho[i];
	c->nvals = g->ho[i + 1u] - g->ho[i];
	c->del = 0;
}

/* The next candidate in key order, the held entry or the upsert. 0 at the end. */
static int pick(merge *g, mcand *c)
{
	held_skip(g);
	if (g->hi >= g->hn && !g->u.have)
		return 0;
	if (g->u.have && (g->hi >= g->hn || g->u.key <= g->hk[g->hi]))
		take_upsert(g, c);
	else
		take_held(g, c);
	return 1;
}

/* Removals come after upserts: a key in the removal list is gone whatever it holds. */
static wr_status removed(merge *g, mcand *c)
{
	wr_status st = WR_OK;

	while (g->m.have && g->m.key < c->key && st == WR_OK)
		st = rm_next(&g->m, g->ix);
	if (g->m.have && g->m.key == c->key)
		c->del = 1;
	return st;
}

static wr_status emit(merge *g, const mcand *c)
{
	if (g->b == NULL) {
		g->n++;
		g->nv += c->nvals;
		return WR_OK;
	}
	/* a push that fails has put the reason in the errinfo of the builder */
	return c->from_u ? push_upsert(g->ix, g->b, g->kind, &g->u) : wri_pgtab_push(g->b, g->kind, c->key, c->vals, c->nvals);
}

/* Produce the next entry of the new table (or count it); *done is set when there is none left. */
static wr_status merge_step(merge *g, int *done)
{
	mcand c;
	wr_status st;

	if (!pick(g, &c)) {
		*done = 1;
		return WR_OK;
	}
	st = removed(g, &c);
	if (st == WR_OK && c.del == 0)
		st = emit(g, &c);
	if (st == WR_OK && c.from_u)
		st = up_next(&g->u, g->ix, g->pp);
	return st;
}

wr_status wri_inc_merge_tab(const wri_inc_ix *ix, const wri_inc_pools *pp, const wri_osdmap *src, unsigned kind, wri_mapbuild *b,
			    uint32_t *n, uint32_t *nv)
{
	merge g;
	int done = 0;
	wr_status st;

	if (kind >= WRI_TAB_COUNT)
		return WR_E_INVAL;
	st = merge_init(&g, ix, pp, src, kind, b);
	while (st == WR_OK && done == 0)
		st = merge_step(&g, &done);
	if (st != WR_OK)
		return st;
	if (n != NULL)
		*n = g.n;
	if (nv != NULL)
		*nv = g.nv;
	return WR_OK;
}
