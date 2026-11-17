/* SPDX-License-Identifier: MIT */
/*
 * test_place_stage.c - the stages of placement after CRUSH (core/src/osdmap/wri_place_stage.c).
 *
 * One table per stage, on compact maps built with the layout builder (place_rig.h turns a wrt_mapgen description into
 * a slot): wri_place_drop_nonexistent, wri_place_upmap (pg_upmap with a weight-0 member abandoning items and primaries,
 * items in order, a present `to`, a `to` at weight 0, NONE and ids at and past max_osd, the primary swap),
 * wri_place_up_set, wri_place_affinity (affinity 0 always rejects, so the rejections and the rotation are exact without
 * a search; fractional affinities use seeds found with the model's own hash), wri_place_temp (primary_temp without
 * pg_temp, a pg_temp of only down OSDs, a stored -1).
 *
 * Then 100,000 random (state, PG) pairs: the five stages, composed as wri_place_pg composes them, against
 * wrt_mg_model_stages, which shares no code and no format with the core.
 */
#include "place_rig.h"

#include <stdarg.h>

#define MAXO 64u  /* max_osd of the table maps */
#define OUT1 7    /* weight 0 */
#define OUT2 60   /* weight 0 */
#define GONE 62   /* state 0: destroyed / never existed */
#define DOWN 63   /* exists, not up */
#define NONE WRI_OSD_NONE

/* ---- small helpers -------------------------------------------------------------------------------------- */

typedef struct lst {
	int32_t v[WRI_PLACE_LIST_MAX];
	uint32_t n;
} lst;

static lst mk(uint32_t n, ...)
{
	lst l;
	va_list ap;
	uint32_t i;

	memset(&l, 0, sizeof(l));
	va_start(ap, n);
	for (i = 0; i < n; i++)
		l.v[i] = (int32_t)va_arg(ap, int);
	va_end(ap);
	l.n = n;
	return l;
}

static lst mk_seq(int32_t first, uint32_t n)
{
	lst l;
	uint32_t i;

	memset(&l, 0, sizeof(l));
	for (i = 0; i < n; i++)
		l.v[i] = first + (int32_t)i;
	l.n = n;
	return l;
}

static void check_list(const char *what, const int32_t *got, uint32_t ng, const lst *want)
{
	uint32_t i;
	int ok = ng == want->n;

	for (i = 0; ok && i < ng; i++)
		ok = got[i] == want->v[i];
	wrt_checks++;
	if (!ok) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s: got %u [", __FILE__, __LINE__, what, ng);
		for (i = 0; i < ng && i < WRI_PLACE_LIST_MAX; i++)
			fprintf(stderr, "%s%d", i ? " " : "", (int)got[i]);
		fprintf(stderr, "], want %u [", want->n);
		for (i = 0; i < want->n; i++)
			fprintf(stderr, "%s%d", i ? " " : "", (int)want->v[i]);
		fprintf(stderr, "]\n");
	}
}

static wrt_mg_pg PG(uint64_t pool, uint32_t seed)
{
	wrt_mg_pg pg;

	pg.pool = pool;
	pg.seed = seed;
	return pg;
}

static uint64_t key(uint64_t pool, uint32_t seed)
{
	return wri_pg_key((uint32_t)pool, seed);
}

static void d_aff(wrt_mg_map *d, int32_t osd, uint32_t a)
{
	uint32_t i;

	if (d->osd_primary_affinity.n == 0) {
		wrt_mg_vec_resize0(&d->osd_primary_affinity, sizeof(uint32_t), (uint32_t)d->max_osd);
		for (i = 0; i < (uint32_t)d->max_osd; i++)
			WRT_MG_E(d->osd_primary_affinity, uint32_t, i) = WRT_MG_W_IN;
	}
	WRT_MG_E(d->osd_primary_affinity, uint32_t, osd) = a;
}

/* n OSDs, all existing, up and in; pool 1 with 8 PGs (so the pool record exists). */
static void d_new(wrt_mg_map *d, int32_t n)
{
	wrt_mg_pool p;
	uint32_t i;

	wrt_mg_map_init(d);
	wrt_mg_map_resize(d, n);
	for (i = 0; i < (uint32_t)n; i++) {
		WRT_MG_E(d->osd_state, uint32_t, i) = WRT_MG_OSD_EXISTS | WRT_MG_OSD_UP;
		WRT_MG_E(d->osd_weight, uint32_t, i) = WRT_MG_W_IN;
	}
	wrt_mg_pool_init(&p, 32);
	p.pg_num = p.pgp_num = p.pg_num_target = p.pgp_num_target = p.pg_num_pending = 8;
	wrt_mg_map_add_pool(d, 1, "p1", &p);
	wrt_mg_pool_free(&p);
}

/* The map of the table tests: MAXO OSDs, OUT1 / OUT2 at weight 0, GONE destroyed, DOWN down. */
static void d_tab(wrt_mg_map *d)
{
	d_new(d, (int32_t)MAXO);
	WRT_MG_E(d->osd_weight, uint32_t, OUT1) = 0;
	WRT_MG_E(d->osd_weight, uint32_t, OUT2) = 0;
	WRT_MG_E(d->osd_state, uint32_t, GONE) = 0;
	WRT_MG_E(d->osd_state, uint32_t, DOWN) = WRT_MG_OSD_EXISTS;
}

/* ---- wri_place_drop_nonexistent -------------------------------------------------------------------------- */

static void t_drop(void)
{
	wrt_mg_map d;
	place_rig r = {NULL, 0, NULL, {0}, 0};
	lst a, want;
	uint32_t n;

	d_tab(&d);
	if (!rig_build(&r, &d, 0))
		goto out;
	/* kept: existing OSDs, up or down, in or out; dropped: NONE, negative, max_osd and above, destroyed */
	a = mk(14, 0, NONE, -1, 5, (int)MAXO, 63, GONE, OUT1, 1000000, -7, 0x7ffffffe, (int)MAXO - 1, 2, 5);
	want = mk(7, 0, 5, 63, OUT1, (int)MAXO - 1, 2, 5);
	n = wri_place_drop_nonexistent(r.m, a.v, a.n);
	check_list("drop mixed", a.v, n, &want);
	a = mk(0);
	WRT_CHECK_U64(wri_place_drop_nonexistent(r.m, a.v, 0), 0);
	a = mk(3, NONE, GONE, -1);
	WRT_CHECK_U64(wri_place_drop_nonexistent(r.m, a.v, a.n), 0);
	a = mk(3, 1, 2, 3);
	want = a;
	n = wri_place_drop_nonexistent(r.m, a.v, a.n);
	check_list("drop all kept", a.v, n, &want);
out:
	rig_free(&r);
	wrt_mg_map_free(&d);
}

/* ---- wri_place_upmap ------------------------------------------------------------------------------------- */

typedef struct up_case {
	const char *name;
	uint32_t seed;
	lst raw, want;
} up_case;

static void t_upmap(void)
{
	wrt_mg_map d;
	place_rig r = {NULL, 0, NULL, {0}, 0};
	uint32_t i;
	static const wrt_mg_pair it_seq[] = {{0, 5}, {5, 6}};
	static const wrt_mg_pair it_present[] = {{0, 2}, {1, 4}};
	static const wrt_mg_pair it_out[] = {{0, OUT1}, {1, GONE}};
	static const wrt_mg_pair it_edge[] = {{1, (int)MAXO}, {2, NONE}, {0, 100}};
	static const wrt_mg_pair it_nofrom[] = {{9, 3}};
	static const wrt_mg_pair it_twice[] = {{0, 5}, {0, 6}};
	static const wrt_mg_pair it_comb[] = {{4, 6}};
	static const wrt_mg_pair it_abandon[] = {{0, 9}};
	static const wrt_mg_pair it_none_from[] = {{NONE, 4}};
	static const wrt_mg_pair it_self[] = {{1, 1}};
	int32_t big[64];
	int32_t tmp[8];

	d_tab(&d);
	/* seed 0 .. 6: pg_upmap alone */
	tmp[0] = 4; tmp[1] = 5; tmp[2] = 6;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 0), tmp, 3);
	tmp[0] = 4; tmp[1] = OUT1; tmp[2] = 6;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 1), tmp, 3);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 1), it_abandon, 1);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 1), 2);
	tmp[0] = 4; tmp[1] = NONE; tmp[2] = 6;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 2), tmp, 3);
	tmp[0] = 4; tmp[1] = (int)MAXO; tmp[2] = -5; tmp[3] = 100;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 3), tmp, 4);
	tmp[0] = 3; tmp[1] = 4; tmp[2] = 5; tmp[3] = 6; tmp[4] = 1;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 4), tmp, 5);
	tmp[0] = 3;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 5), tmp, 1);
	wrt_mg_map_set_pg_upmap(&d, PG(1, 6), tmp, 0); /* an empty list replaces the raw one */
	/* items */
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 7), it_seq, 2);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 8), it_present, 2);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 9), it_out, 2);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 10), it_edge, 3);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 11), it_nofrom, 1);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 13), it_twice, 2);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 23), it_none_from, 1);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 24), it_self, 1);
	/* primaries */
	wrt_mg_map_set_upmap_primary(&d, PG(1, 14), 2);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 15), 0);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 16), 5);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 17), OUT1);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 18), NONE);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 19), 100);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 20), -1);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 21), 1);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 27), (int)MAXO);
	/* all three, in order: list {3,4,5}, pair 4 -> 6, primary 6 */
	tmp[0] = 3; tmp[1] = 4; tmp[2] = 5;
	wrt_mg_map_set_pg_upmap(&d, PG(1, 22), tmp, 3);
	wrt_mg_map_set_pg_upmap_items(&d, PG(1, 22), it_comb, 1);
	wrt_mg_map_set_upmap_primary(&d, PG(1, 22), 6);
	/* the same seed in another pool is another PG */
	tmp[0] = 9; tmp[1] = 9; tmp[2] = 9;
	wrt_mg_map_set_pg_upmap(&d, PG(2, 28), tmp, 3);
	/* long vectors: 40 values 8..47 are cut at the list limit; a weight-0 member past the limit still abandons */
	{
		uint32_t q;

		for (q = 0; q < 40; q++)
			big[q] = 8 + (int32_t)q;
		wrt_mg_map_set_pg_upmap(&d, PG(1, 25), big, 40);
		big[36] = OUT2;
		wrt_mg_map_set_pg_upmap(&d, PG(1, 26), big, 40);
	}
	if (!rig_build(&r, &d, 0))
		goto out;
	{
		const up_case cases[] = {
			{"pg_upmap replaces", 0, mk(3, 0, 1, 2), mk(3, 4, 5, 6)},
			{"pg_upmap member out abandons items and primary", 1, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"pg_upmap with NONE replaces", 2, mk(3, 0, 1, 2), mk(3, 4, NONE, 6)},
			{"pg_upmap at max_osd and below zero replaces", 3, mk(3, 0, 1, 2), mk(4, 4, (int)MAXO, -5, 100)},
			{"pg_upmap longer than raw", 4, mk(3, 0, 1, 2), mk(5, 3, 4, 5, 6, 1)},
			{"pg_upmap shorter than raw", 5, mk(3, 0, 1, 2), mk(1, 3)},
			{"pg_upmap empty", 6, mk(3, 0, 1, 2), mk(0)},
			{"pg_upmap on an empty raw", 0, mk(0), mk(3, 4, 5, 6)},
			{"items sequential", 7, mk(3, 0, 1, 2), mk(3, 6, 1, 2)},
			{"items skip a present to, then apply", 8, mk(3, 0, 1, 2), mk(3, 0, 4, 2)},
			{"items skip a to at weight 0, apply a destroyed one", 9, mk(3, 0, 1, 2), mk(3, 0, GONE, 2)},
			{"items at max_osd, NONE and far out apply", 10, mk(3, 0, 1, 2), mk(3, 100, (int)MAXO, NONE)},
			{"items whose from is absent", 11, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"items on an empty raw", 7, mk(0), mk(0)},
			{"items replace only the first from", 13, mk(3, 0, 1, 2), mk(3, 5, 1, 2)},
			{"each pair replaces the first from left on the list", 13, mk(4, 0, 1, 0, 2), mk(4, 5, 1, 6, 2)},
			{"items from NONE", 23, mk(3, 0, NONE, 2), mk(3, 0, 4, 2)},
			{"items to == from is a present to", 24, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"primary swap", 14, mk(3, 0, 1, 2), mk(3, 2, 1, 0)},
			{"primary already first", 15, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"primary absent", 16, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"primary at weight 0 is not swapped", 17, mk(3, 0, OUT1, 2), mk(3, 0, OUT1, 2)},
			{"primary NONE", 18, mk(3, 0, NONE, 2), mk(3, 0, NONE, 2)},
			{"primary 100", 19, mk(3, 0, 100, 2), mk(3, 0, 100, 2)},
			{"primary -1", 20, mk(3, 0, -1, 2), mk(3, 0, -1, 2)},
			{"primary at index 1", 21, mk(3, 0, 1, 2), mk(3, 1, 0, 2)},
			{"primary equal to max_osd is not a valid id", 27, mk(3, 0, (int)MAXO, 2), mk(3, 0, (int)MAXO, 2)},
			{"list, pair, primary in order", 22, mk(2, 8, 9), mk(3, 6, 3, 5)},
			{"no entry: another pool has one at this seed", 28, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"no entry at all", 31, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
			{"a 40 value vector is cut at the list limit", 25, mk(3, 0, 1, 2), mk_seq(8, WRI_PLACE_LIST_MAX)},
			{"a weight-0 member past the cut still abandons", 26, mk(3, 0, 1, 2), mk(3, 0, 1, 2)},
		};

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			lst v = cases[i].raw;
			uint32_t n = v.n;

			wri_place_upmap(r.m, key(1, cases[i].seed), v.v, &n);
			check_list(cases[i].name, v.v, n, &cases[i].want);
		}
		/* the same PG seed in pool 2 */
		{
			lst v = mk(3, 0, 1, 2), w = mk(3, 9, 9, 9);
			uint32_t n = v.n;

			wri_place_upmap(r.m, key(2, 28), v.v, &n);
			check_list("pool 2 seed 28", v.v, n, &w);
		}
	}
out:
	rig_free(&r);
	wrt_mg_map_free(&d);
}

/* A table with an items vector of odd length cannot come from a decoder, but the stage must not read the last value as a
 * pair: built by hand, without the rig. */
static void t_upmap_odd(void)
{
	static uint8_t slot[8192] __attribute__((aligned(16)));
	wri_mapbuild b;
	const int32_t odd[3] = {0, 5, 1};
	lst v = mk(3, 0, 1, 2), want = mk(3, 5, 1, 2);
	uint32_t n = v.n, k;
	uint8_t *st;
	wr_errinfo why;

	memset(&why, 0, sizeof(why));
	wri_mapbuild_begin(&b, slot, sizeof(slot), &why);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 4, 0));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP_ITEMS, 2, 8));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_ITEMS, key(1, 0), odd, 3));
	st = wri_map_base_rw(b.m) + b.m->state_off;
	for (k = 0; k < 4; k++) {
		st[k] = WRI_OSD_EXISTS | WRI_OSD_UP;
		((uint32_t *)(void *)(wri_map_base_rw(b.m) + b.m->weight_off))[k] = WRI_OSD_IN_FULL;
	}
	wri_mapbuild_finish(&b);
	wri_place_upmap(b.m, key(1, 0), v.v, &n);
	check_list("odd items vector: the pair applies, the stray value is ignored", v.v, n, &want);
}

/* A table vector longer than a stage's buffer (the layout builder takes twice WRI_PLACE_LIST_MAX values) is cut, never written
 * past the buffer; a caller count above the buffer size is cut on entry. Built by hand: the full-map decoder never produces it. */
static void t_long_vectors(void)
{
	static uint8_t slot[16384] __attribute__((aligned(16)));
	wri_mapbuild b;
	int32_t big[WRI_PLACE_LIST_MAX * 2u];
	int32_t buf[WRI_PLACE_LIST_MAX + 8u];
	uint32_t n, k, tn;
	int32_t tp;
	uint8_t *st;
	wr_errinfo why;

	for (k = 0; k < WRI_PLACE_LIST_MAX * 2u; k++)
		big[k] = (int32_t)(k % 4u);
	memset(&why, 0, sizeof(why));
	wri_mapbuild_begin(&b, slot, sizeof(slot), &why);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 4, 0));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_TEMP, 2, 2u * WRI_PLACE_LIST_MAX * 2u));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 2, 2u * WRI_PLACE_LIST_MAX * 2u));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, key(1, 0), big, WRI_PLACE_LIST_MAX * 2u));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, key(1, 0), big, WRI_PLACE_LIST_MAX * 2u));
	st = wri_map_base_rw(b.m) + b.m->state_off;
	for (k = 0; k < 4; k++) {
		st[k] = WRI_OSD_EXISTS | WRI_OSD_UP;
		((uint32_t *)(void *)(wri_map_base_rw(b.m) + b.m->weight_off))[k] = WRI_OSD_IN_FULL;
	}
	wri_mapbuild_finish(&b);

	/* pg_upmap of 64 values: the first WRI_PLACE_LIST_MAX replace the list, the guard behind them is untouched */
	memset(buf, 0x5a, sizeof(buf));
	buf[0] = 3;
	n = 1;
	wri_place_upmap(b.m, key(1, 0), buf, &n);
	WRT_CHECK_U64(WRI_PLACE_LIST_MAX, n);
	for (k = 0; k < WRI_PLACE_LIST_MAX; k++)
		WRT_CHECK(buf[k] == (int32_t)(k % 4u));
	for (k = WRI_PLACE_LIST_MAX; k < WRI_PLACE_LIST_MAX + 8u; k++)
		WRT_CHECK(buf[k] == 0x5a5a5a5a);

	/* no entry for the PG, but a count above the buffer: cut to the buffer, nothing beyond it is read or written */
	memset(buf, 0x5a, sizeof(buf));
	n = WRI_PLACE_LIST_MAX + 8u;
	wri_place_upmap(b.m, key(1, 5), buf, &n);
	WRT_CHECK_U64(WRI_PLACE_LIST_MAX, n);
	for (k = 0; k < WRI_PLACE_LIST_MAX + 8u; k++)
		WRT_CHECK(buf[k] == 0x5a5a5a5a);

	/* pg_temp of 64 values: the first WRI_PLACE_LIST_MAX members, primary = the first */
	memset(buf, 0x5a, sizeof(buf));
	wri_place_temp(b.m, key(1, 0), buf, &tn, &tp);
	WRT_CHECK_U64(WRI_PLACE_LIST_MAX, tn);
	WRT_CHECK(tp == 0);
	for (k = 0; k < WRI_PLACE_LIST_MAX; k++)
		WRT_CHECK(buf[k] == (int32_t)(k % 4u));
	for (k = WRI_PLACE_LIST_MAX; k < WRI_PLACE_LIST_MAX + 8u; k++)
		WRT_CHECK(buf[k] == 0x5a5a5a5a);
}

/* ---- wri_place_up_set -------------------------------------------------------------------------------------- */

static void t_up_set(void)
{
	wrt_mg_map d;
	place_rig r = {NULL, 0, NULL, {0}, 0};
	lst raw, out, want;
	int32_t primary = 12345;
	uint32_t n;

	d_tab(&d);
	if (!rig_build(&r, &d, 0))
		goto out;
	raw = mk(11, NONE, 0, DOWN, GONE, 3, 100, -1, 1, (int)MAXO, OUT1, 0x7ffffffe);
	want = mk(4, 0, 3, 1, OUT1); /* up but out is still up */
	n = wri_place_up_set(r.m, raw.v, raw.n, out.v, &primary);
	check_list("up set", out.v, n, &want);
	WRT_CHECK_U64((uint32_t)primary, 0);

	raw = mk(3, DOWN, GONE, NONE);
	n = wri_place_up_set(r.m, raw.v, raw.n, out.v, &primary);
	WRT_CHECK_U64(n, 0);
	WRT_CHECK(primary == -1);

	raw = mk(0);
	primary = 5;
	n = wri_place_up_set(r.m, raw.v, 0, out.v, &primary);
	WRT_CHECK_U64(n, 0);
	WRT_CHECK(primary == -1);

	/* the first member of the up set is the primary, not the first of the raw list */
	raw = mk(3, DOWN, 9, 4);
	n = wri_place_up_set(r.m, raw.v, raw.n, out.v, &primary);
	WRT_CHECK(n == 2 && primary == 9 && out.v[0] == 9 && out.v[1] == 4);

	/* in place, and with no primary wanted */
	raw = mk(4, 1, DOWN, 2, GONE);
	n = wri_place_up_set(r.m, raw.v, raw.n, raw.v, NULL);
	want = mk(2, 1, 2);
	check_list("up set in place", raw.v, n, &want);
out:
	rig_free(&r);
	wrt_mg_map_free(&d);
}

/* ---- wri_place_affinity ----------------------------------------------------------------------------------- */

/* A seed for which OSD `osd` is rejected at affinity `a` (the hash lands at or above a), or accepted. */
static uint32_t find_pps(int32_t osd, uint32_t a, int rejected)
{
	uint32_t pps;

	for (pps = 1; pps < 100000u; pps++)
		if (((wrt_mg_hash32_2(pps, (uint32_t)osd) >> 16) >= a) == (rejected != 0))
			return pps;
	return 0;
}

typedef struct af_case {
	const char *name;
	uint32_t pps;
	lst up, want;
	int32_t primary_in, primary_want;
} af_case;

static void run_af(const wri_osdmap *m, const af_case *c)
{
	lst v = c->up;
	int32_t pri = c->primary_in;

	wri_place_affinity(m, c->pps, v.v, v.n, &pri);
	check_list(c->name, v.v, v.n, &c->want);
	wrt_checks++;
	if (pri != c->primary_want) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s: primary %d, want %d\n", __FILE__, __LINE__, c->name, (int)pri, (int)c->primary_want);
	}
}

static void t_affinity(void)
{
	wrt_mg_map d;
	place_rig r = {NULL, 0, NULL, {0}, 0};
	uint32_t i, rej, acc;
	int32_t pri;
	lst v;

	/* no affinity array: nothing changes, the primary is left as given */
	d_new(&d, 16);
	if (rig_build(&r, &d, 0)) {
		v = mk(3, 0, 1, 2);
		pri = 99;
		wri_place_affinity(r.m, 1234, v.v, v.n, &pri);
		WRT_CHECK(v.v[0] == 0 && v.v[1] == 1 && v.v[2] == 2 && pri == 99);
	}
	rig_free(&r);
	/* an array of defaults only */
	d_aff(&d, 3, WRT_MG_W_IN);
	if (rig_build(&r, &d, 0)) {
		v = mk(3, 0, 1, 2);
		pri = 99;
		wri_place_affinity(r.m, 1234, v.v, v.n, &pri);
		WRT_CHECK(v.v[0] == 0 && v.v[1] == 1 && v.v[2] == 2 && pri == 99);
	}
	rig_free(&r);
	wrt_mg_map_free(&d);

	/* affinity 0 rejects whatever the hash says */
	d_new(&d, 16);
	d_aff(&d, 0, 0);
	d_aff(&d, 4, 0);
	d_aff(&d, 5, 0);
	d_aff(&d, 9, 0);
	d_aff(&d, 12, 0x8000);
	d_aff(&d, 13, 0x8000);
	if (!rig_build(&r, &d, 0))
		goto out;
	{
		const af_case cases[] = {
			{"first member rejected: the second leads", 7, mk(3, 0, 1, 2), mk(3, 1, 0, 2), 0, 1},
			{"two rejected in front", 7, mk(4, 0, 4, 2, 3), mk(4, 2, 0, 4, 3), 0, 2},
			{"first accepted, a later one rejected", 7, mk(3, 1, 0, 2), mk(3, 1, 0, 2), 1, 1},
			{"all rejected: the first is the fallback", 7, mk(3, 0, 4, 5), mk(3, 0, 4, 5), 0, 0},
			{"all rejected, a single member", 7, mk(1, 9), mk(1, 9), 9, 9},
			{"rejected members behind an accepted one stay", 7, mk(4, 3, 0, 4, 1), mk(4, 3, 0, 4, 1), 3, 3},
			{"rotation shifts the entries in front back by one", 7, mk(4, 0, 4, 5, 6), mk(4, 6, 0, 4, 5), 0, 6},
			{"accepted in the middle", 7, mk(4, 0, 1, 4, 6), mk(4, 1, 0, 4, 6), 0, 1},
			{"no member with a non-default affinity", 7, mk(3, 1, 2, 3), mk(3, 1, 2, 3), 1, 1},
			{"a non-default affinity on a non-member only", 7, mk(3, 1, 2, 3), mk(3, 1, 2, 3), 77, 77},
			{"empty up set", 7, mk(0), mk(0), -1, -1},
		};

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
			run_af(r.m, &cases[i]);
	}
	/* fractional: the member is rejected exactly when hash2(pps, osd) >> 16 >= affinity */
	rej = find_pps(12, 0x8000, 1);
	acc = find_pps(12, 0x8000, 0);
	WRT_CHECK(rej != 0 && acc != 0);
	{
		af_case rejected = {"fractional affinity, hash at or above: rejected", 0, mk(3, 12, 1, 2), mk(3, 1, 12, 2), 12, 1};
		af_case accepted = {"fractional affinity, hash below: accepted", 0, mk(3, 12, 1, 2), mk(3, 12, 1, 2), 12, 12};

		rejected.pps = rej;
		accepted.pps = acc;
		run_af(r.m, &rejected);
		run_af(r.m, &accepted);
	}
	/* the boundary: a hash equal to the affinity rejects, one below it accepts */
	{
		uint32_t p;
		int found_eq = 0, found_lt = 0;

		for (p = 1; p < 4000000u && !(found_eq && found_lt); p++) {
			uint32_t h = wrt_mg_hash32_2(p, 12) >> 16;

			if (h == 0x8000u && !found_eq) {
				af_case c = {"hash equal to the affinity: rejected", 0, mk(2, 12, 1), mk(2, 1, 12), 12, 1};

				c.pps = p;
				run_af(r.m, &c);
				found_eq = 1;
			} else if (h == 0x7fffu && !found_lt) {
				af_case c = {"hash one below the affinity: accepted", 0, mk(2, 12, 1), mk(2, 12, 1), 12, 12};

				c.pps = p;
				run_af(r.m, &c);
				found_lt = 1;
			}
		}
		WRT_CHECK(found_eq && found_lt);
	}
	/* two fractional members: each is judged by its own hash */
	{
		uint32_t p;
		int found = 0;

		for (p = 1; p < 100000u && !found; p++) {
			int r12 = (wrt_mg_hash32_2(p, 12) >> 16) >= 0x8000u, r13 = (wrt_mg_hash32_2(p, 13) >> 16) >= 0x8000u;

			if (r12 && !r13) {
				af_case c = {"two fractional: first rejected, second accepted", 0, mk(3, 12, 13, 2), mk(3, 13, 12, 2), 12, 13};

				c.pps = p;
				run_af(r.m, &c);
				found = 1;
			}
		}
		WRT_CHECK(found);
		found = 0;
		for (p = 1; p < 100000u && !found; p++) {
			int r12 = (wrt_mg_hash32_2(p, 12) >> 16) >= 0x8000u, r13 = (wrt_mg_hash32_2(p, 13) >> 16) >= 0x8000u;

			if (r12 && r13) {
				af_case c = {"two fractional, both rejected: the first leads", 0, mk(2, 13, 12), mk(2, 13, 12), 13, 13};

				c.pps = p;
				run_af(r.m, &c);
				found = 1;
			}
		}
		WRT_CHECK(found);
	}
out:
	rig_free(&r);
	wrt_mg_map_free(&d);
}

/* ---- wri_place_temp ---------------------------------------------------------------------------------------- */

typedef struct tp_case {
	const char *name;
	uint32_t seed;
	lst want;
	int32_t want_primary;
} tp_case;

static void t_temp(void)
{
	wrt_mg_map d;
	place_rig r = {NULL, 0, NULL, {0}, 0};
	uint32_t i;
	int32_t tmp[64];

	d_tab(&d);
	/* mixed members: only existing, up OSDs stay, in order */
	tmp[0] = 1; tmp[1] = DOWN; tmp[2] = GONE; tmp[3] = NONE; tmp[4] = 100; tmp[5] = 3; tmp[6] = -1; tmp[7] = (int)MAXO;
	wrt_mg_map_set_pg_temp(&d, PG(1, 0), tmp, 8);
	/* only down members: as absent */
	tmp[0] = DOWN; tmp[1] = GONE;
	wrt_mg_map_set_pg_temp(&d, PG(1, 1), tmp, 2);
	/* primary_temp without pg_temp, and for a down OSD, an out OSD, a destroyed one, one outside the map */
	wrt_mg_map_set_primary_temp(&d, PG(1, 2), 5);
	wrt_mg_map_set_primary_temp(&d, PG(1, 3), DOWN);
	wrt_mg_map_set_primary_temp(&d, PG(1, 4), GONE);
	wrt_mg_map_set_primary_temp(&d, PG(1, 5), 1000);
	/* both: the primary is not a member */
	tmp[0] = 1; tmp[1] = 3;
	wrt_mg_map_set_pg_temp(&d, PG(1, 6), tmp, 2);
	wrt_mg_map_set_primary_temp(&d, PG(1, 6), 9);
	/* a stored -1 is kept, with and without a list */
	wrt_mg_map_set_primary_temp(&d, PG(1, 7), -1);
	wrt_mg_map_set_pg_temp(&d, PG(1, 8), tmp, 2);
	wrt_mg_map_set_primary_temp(&d, PG(1, 8), -1);
	/* a list of its own: the first member leads */
	wrt_mg_map_set_pg_temp(&d, PG(1, 9), tmp, 2);
	/* an empty vector */
	wrt_mg_map_set_pg_temp(&d, PG(1, 10), tmp, 0);
	/* the same seed in another pool */
	wrt_mg_map_set_pg_temp(&d, PG(2, 9), tmp, 2);
	wrt_mg_map_set_primary_temp(&d, PG(2, 11), 4);
	/* 40 members 8..47 with a down OSD first: the list is cut after filtering, at the list limit */
	{
		uint32_t q;

		for (q = 0; q < 40; q++)
			tmp[q] = 8 + (int32_t)q;
		wrt_mg_map_set_pg_temp(&d, PG(1, 12), tmp, 40);
		tmp[0] = DOWN;
		wrt_mg_map_set_pg_temp(&d, PG(1, 13), tmp, 40);
	}
	if (!rig_build(&r, &d, 0))
		goto out;
	{
		const tp_case cases[] = {
			{"members that are gone or down are dropped", 0, mk(2, 1, 3), 1},
			{"all members down: absent", 1, mk(0), -1},
			{"primary_temp without pg_temp", 2, mk(0), 5},
			{"primary_temp of a down OSD, unchecked", 3, mk(0), DOWN},
			{"primary_temp of a destroyed OSD, unchecked", 4, mk(0), GONE},
			{"primary_temp outside the map, unchecked", 5, mk(0), 1000},
			{"primary_temp that is not a member", 6, mk(2, 1, 3), 9},
			{"a stored -1 without a list", 7, mk(0), -1},
			{"a stored -1 over a list", 8, mk(2, 1, 3), -1},
			{"pg_temp alone: the first member leads", 9, mk(2, 1, 3), 1},
			{"empty pg_temp vector", 10, mk(0), -1},
			{"no entry", 20, mk(0), -1},
			{"cut at the list limit", 12, mk_seq(8, WRI_PLACE_LIST_MAX), 8},
			{"cut after filtering", 13, mk_seq(9, WRI_PLACE_LIST_MAX), 9},
		};

		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			lst t;
			uint32_t n = 99;
			int32_t tp = 77;

			memset(&t, 0, sizeof(t));
			wri_place_temp(r.m, key(1, cases[i].seed), t.v, &n, &tp);
			check_list(cases[i].name, t.v, n, &cases[i].want);
			wrt_checks++;
			if (tp != cases[i].want_primary) {
				wrt_failures++;
				fprintf(stderr, "%s:%d: %s: temp primary %d, want %d\n", __FILE__, __LINE__, cases[i].name, (int)tp,
					(int)cases[i].want_primary);
			}
		}
		{
			lst t, w = mk(2, 1, 3);
			uint32_t n = 0;
			int32_t tp = 0;

			memset(&t, 0, sizeof(t));
			wri_place_temp(r.m, key(2, 9), t.v, &n, &tp);
			check_list("pool 2 seed 9", t.v, n, &w);
			WRT_CHECK(tp == 1);
			wri_place_temp(r.m, key(2, 11), t.v, &n, &tp);
			WRT_CHECK(n == 0 && tp == 4);
			wri_place_temp(r.m, key(1, 11), t.v, &n, &tp);
			WRT_CHECK(n == 0 && tp == -1);
		}
	}
out:
	rig_free(&r);
	wrt_mg_map_free(&d);
}

/* ---- random states against the model ---------------------------------------------------------------------- */

static wrt_mg_rng rng;

static uint32_t below(uint32_t n)
{
	return wrt_mg_rng_below(&rng, n);
}

/* An id as a hostile or stale table may name it: mostly a real OSD, sometimes NONE, max_osd and a bit more, -1, far out. */
static int32_t rid(uint32_t n)
{
	uint32_t k = below(100);

	if (k < 70)
		return (int32_t)below(n);
	if (k < 78)
		return NONE;
	if (k < 86)
		return (int32_t)(n + below(4)); /* includes max_osd itself */
	if (k < 92)
		return -1;
	return 100000 + (int32_t)below(1000);
}

static void gen_state(wrt_mg_map *d, uint32_t n)
{
	uint32_t i, seed, q;
	wrt_mg_pool p;

	wrt_mg_map_init(d);
	wrt_mg_map_resize(d, (int32_t)n);
	for (i = 0; i < n; i++) {
		uint32_t k = below(100), st;

		if (k < 8)
			st = below(4) == 0 ? 0x4u : 0u; /* destroyed, maybe with a stray bit */
		else if (k < 35)
			st = WRT_MG_OSD_EXISTS | (below(4) == 0 ? WRT_MG_OSD_AUTOOUT : 0u);
		else
			st = WRT_MG_OSD_EXISTS | WRT_MG_OSD_UP | (below(8) == 0 ? WRT_MG_OSD_NEW : 0u);
		WRT_MG_E(d->osd_state, uint32_t, i) = st;
		k = below(100);
		WRT_MG_E(d->osd_weight, uint32_t, i) = k < 15 ? 0u : (k < 70 ? WRT_MG_W_IN : 1u + below(0xffffu));
	}
	if (below(2)) {
		for (i = 0; i < n; i++) {
			uint32_t k = below(100);

			d_aff(d, (int32_t)i, k < 50 ? WRT_MG_W_IN : (k < 62 ? 0u : below(WRT_MG_W_IN)));
		}
	}
	wrt_mg_pool_init(&p, 32);
	p.pg_num = p.pgp_num = p.pg_num_target = p.pgp_num_target = p.pg_num_pending = 8;
	wrt_mg_map_add_pool(d, 1, "p1", &p);
	wrt_mg_map_add_pool(d, 2, "p2", &p);
	wrt_mg_pool_free(&p);
	for (seed = 0; seed < 8; seed++) {
		uint32_t pool;

		for (pool = 1; pool <= 2; pool++) {
			int32_t l[8];
			wrt_mg_pair pr[4];

			if (below(4) == 0) {
				uint32_t len = below(7);

				for (q = 0; q < len; q++)
					l[q] = rid(n);
				wrt_mg_map_set_pg_upmap(d, PG(pool, seed), l, len);
			}
			if (below(4) == 0) {
				uint32_t np = 1 + below(4);

				for (q = 0; q < np; q++) {
					pr[q].from = rid(n);
					pr[q].to = rid(n);
				}
				wrt_mg_map_set_pg_upmap_items(d, PG(pool, seed), pr, np);
			}
			if (below(5) == 0)
				wrt_mg_map_set_upmap_primary(d, PG(pool, seed), rid(n));
			if (below(10) < 3) {
				uint32_t len = below(6);

				for (q = 0; q < len; q++)
					l[q] = rid(n);
				wrt_mg_map_set_pg_temp(d, PG(pool, seed), l, len);
			}
			if (below(5) == 0)
				wrt_mg_map_set_primary_temp(d, PG(pool, seed), below(8) == 0 ? -1 : rid(n));
		}
	}
}

/* The stages in the order of wri_place_pg, from a raw CRUSH answer on; exact-size heap copies so ASan sees every stray
 * read of an input list. */
static void core_stages(const wri_osdmap *m, uint32_t pool, uint32_t seed, uint32_t pps, const int32_t *raw_in, uint32_t nraw,
			wri_pg_result *res)
{
	int32_t list[WRI_PLACE_LIST_MAX], temp[WRI_PLACE_LIST_MAX];
	int32_t *raw, *upl;
	uint32_t n, n_up, n_temp;
	int32_t up_primary = -1, temp_primary = -1;
	uint64_t pgkey = wri_pg_key(pool, seed);

	memset(res, 0, sizeof(*res));
	raw = (int32_t *)malloc(((size_t)nraw + 1u) * sizeof(int32_t));
	if (raw == NULL)
		exit(2);
	memcpy(raw, raw_in, (size_t)nraw * sizeof(int32_t));
	n = wri_place_drop_nonexistent(m, raw, nraw);
	memcpy(list, raw, (size_t)n * sizeof(int32_t));
	free(raw);
	wri_place_upmap(m, pgkey, list, &n);
	upl = (int32_t *)malloc(((size_t)n + 1u) * sizeof(int32_t));
	if (upl == NULL)
		exit(2);
	n_up = wri_place_up_set(m, list, n, upl, &up_primary);
	{
		int32_t *exact = (int32_t *)malloc(((size_t)n_up + 1u) * sizeof(int32_t));

		if (exact == NULL)
			exit(2);
		memcpy(exact, upl, (size_t)n_up * sizeof(int32_t));
		wri_place_affinity(m, pps, exact, n_up, &up_primary);
		memcpy(upl, exact, (size_t)n_up * sizeof(int32_t));
		free(exact);
	}
	wri_place_temp(m, pgkey, temp, &n_temp, &temp_primary);
	memcpy(res->up, upl, (size_t)(n_up < WRI_REP_MAX ? n_up : WRI_REP_MAX) * sizeof(int32_t));
	res->n_up = (uint8_t)(n_up < WRI_REP_MAX ? n_up : WRI_REP_MAX);
	res->up_primary = up_primary;
	free(upl);
	if (n_temp != 0u) {
		memcpy(res->acting, temp, (size_t)(n_temp < WRI_REP_MAX ? n_temp : WRI_REP_MAX) * sizeof(int32_t));
		res->n_acting = (uint8_t)(n_temp < WRI_REP_MAX ? n_temp : WRI_REP_MAX);
		res->acting_primary = temp_primary;
	} else {
		memcpy(res->acting, res->up, sizeof(res->up));
		res->n_acting = res->n_up;
		res->acting_primary = temp_primary != -1 ? temp_primary : up_primary;
	}
}

static void t_random(void)
{
	const uint32_t states = 12500, pgs_per_state = 8; /* 100,000 (state, PG) pairs */
	uint32_t s, bad = 0;

	wrt_mg_rng_seed(&rng, 0x706c616365ull);
	for (s = 0; s < states; s++) {
		wrt_mg_map d;
		place_rig r = {NULL, 0, NULL, {0}, 0};
		uint32_t n = below(10) < 7 ? 1u + below(12) : 1u + below(40), seed;

		gen_state(&d, n);
		if (!rig_build(&r, &d, 0)) {
			wrt_mg_map_free(&d);
			rig_free(&r);
			return;
		}
		for (seed = 0; seed < pgs_per_state; seed++) {
			uint32_t pool = 1u + below(2), nraw = below(7), pps = (uint32_t)wrt_mg_rng_next(&rng), q, k;
			int32_t raw[8];
			wri_pg_result got;
			wrt_mg_place want;

			for (q = 0; q < nraw; q++)
				raw[q] = rid(n);
			if (below(10) == 0 && nraw > 1)
				raw[nraw - 1] = raw[0]; /* a repeated id: CRUSH never returns one, a map could still make one */
			core_stages(r.m, pool, seed, pps, raw, nraw, &got);
			WRT_CHECK(wrt_mg_model_stages(&d, (int64_t)pool, seed, pps, raw, nraw, &want) == 0);
			k = 0;
			k |= want.nup != got.n_up || want.nacting != got.n_acting;
			k |= want.up_primary != got.up_primary || want.acting_primary != got.acting_primary;
			for (q = 0; q < want.nup && q < got.n_up; q++)
				k |= want.up[q] != got.up[q];
			for (q = 0; q < want.nacting && q < got.n_acting; q++)
				k |= want.acting[q] != got.acting[q];
			wrt_checks++;
			if (k) {
				wrt_failures++;
				if (bad++ < 5) {
					fprintf(stderr, "%s:%d: state %u seed %u pool %u: model up %u/%d acting %u/%d, core up %u/%d acting %u/%d\n",
						__FILE__, __LINE__, s, seed, pool, want.nup, (int)want.up_primary, want.nacting,
						(int)want.acting_primary, got.n_up, (int)got.up_primary, got.n_acting, (int)got.acting_primary);
				}
			}
		}
		rig_free(&r);
		wrt_mg_map_free(&d);
	}
}

int main(void)
{
	t_drop();
	t_upmap();
	t_upmap_odd();
	t_long_vectors();
	t_up_set();
	t_affinity();
	t_temp();
	t_random();
	return wrt_finish();
}
