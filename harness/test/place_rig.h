/* SPDX-License-Identifier: MIT */
/*
 * place_rig.h - shared by test_place_stage.c and test_place_pipe.c: turns a wrt_mapgen map description (the plain-array
 * model of tests) into a compact map slot built with the layout builder of the core, so the placement code and the
 * model look at the same state.
 *
 * The slot holds the per-OSD arrays (state, reweight, affinity when the description has any), one pool record per
 * description pool (status OK, present), the five pg tables, and, if asked, the CRUSH region decoded from the
 * description's own CRUSH blob. The slot is finished and passed through wri_osdmap_check before it is handed out.
 */
#ifndef PLACE_RIG_H
#define PLACE_RIG_H

#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_ctx.h"
#include "wri_place.h"

typedef struct place_rig {
	void *mem;
	size_t cap;
	wri_osdmap *m;
	int64_t ids[WRI_MAP_POOLS_MAX]; /* the tracked pools: ids[i] is the pool of tracked index i */
	uint32_t n_ids;
} place_rig;

/* Tracked index of pool `id` in the slot, -1 if the slot does not track it. */
WRT_UNUSED static int rig_idx(const place_rig *r, int64_t id)
{
	uint32_t i;

	for (i = 0; i < r->n_ids; i++)
		if (r->ids[i] == id)
			return (int)i;
	return -1;
}

static void rig_free(place_rig *r)
{
	free(r->mem);
	r->mem = NULL;
	r->m = NULL;
	r->cap = 0;
}

/* Table sizes of a description: entries and values of each of the five tables, in WRI_TAB_* order. */
static void rig_tab_sizes(const wrt_mg_map *d, uint32_t n[WRI_TAB_COUNT], uint32_t nv[WRI_TAB_COUNT])
{
	uint32_t i;

	memset(n, 0, WRI_TAB_COUNT * sizeof(uint32_t));
	memset(nv, 0, WRI_TAB_COUNT * sizeof(uint32_t));
	n[WRI_TAB_PG_TEMP] = d->pg_temp.n;
	for (i = 0; i < d->pg_temp.n; i++)
		nv[WRI_TAB_PG_TEMP] += WRT_MG_E(d->pg_temp, wrt_mg_pg_list, i).osds.n;
	n[WRI_TAB_PRIMARY_TEMP] = d->primary_temp.n;
	nv[WRI_TAB_PRIMARY_TEMP] = d->primary_temp.n;
	n[WRI_TAB_PG_UPMAP] = d->pg_upmap.n;
	for (i = 0; i < d->pg_upmap.n; i++)
		nv[WRI_TAB_PG_UPMAP] += WRT_MG_E(d->pg_upmap, wrt_mg_pg_list, i).osds.n;
	n[WRI_TAB_PG_UPMAP_ITEMS] = d->pg_upmap_items.n;
	for (i = 0; i < d->pg_upmap_items.n; i++)
		nv[WRI_TAB_PG_UPMAP_ITEMS] += 2u * WRT_MG_E(d->pg_upmap_items, wrt_mg_pg_items, i).items.n;
	n[WRI_TAB_PG_UPMAP_PRIMARY] = d->pg_upmap_primaries.n;
	nv[WRI_TAB_PG_UPMAP_PRIMARY] = d->pg_upmap_primaries.n;
}

static int rig_push(wri_mapbuild *b, unsigned kind, uint64_t key, const int32_t *v, uint32_t n)
{
	wr_status st = wri_pgtab_push(b, kind, key, v, n);

	WRT_CHECK_STATUS(WR_OK, st);
	return st == WR_OK;
}

/*
 * Build the slot tracking the pools `ids[0..nids)` of the description (at most WRI_MAP_POOLS_MAX, each must exist), in that
 * order; the pg tables keep every entry. Returns 1 on success (r->m valid), 0 on a failure (reported through WRT_CHECK).
 */
static int rig_build_pools(place_rig *r, const wrt_mg_map *d, int with_crush, const int64_t *ids, uint32_t nids)
{
	uint32_t tn[WRI_TAB_COUNT], tnv[WRI_TAB_COUNT], i, k;
	size_t cap;
	wri_mapbuild b;
	wr_errinfo why;
	uint8_t *base;
	wri_map_pool *pools;

	memset(r, 0, sizeof(*r));
	if (nids > WRI_MAP_POOLS_MAX) {
		WRT_CHECK(0);
		return 0;
	}
	for (i = 0; i < nids; i++)
		r->ids[i] = ids[i];
	r->n_ids = nids;
	rig_tab_sizes(d, tn, tnv);
	cap = 65536u + (size_t)(d->max_osd > 0 ? d->max_osd : 0) * 64u + (size_t)nids * 64u + (size_t)d->crush_len * 4u;
	for (k = 0; k < WRI_TAB_COUNT; k++)
		cap += 64u + (size_t)tn[k] * 16u + (size_t)tnv[k] * 4u;
	r->mem = malloc(cap + 16u); /* the slot is the 16-byte aligned part of the block (strict C99 has no aligned_alloc) */
	if (r->mem == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	r->cap = cap;
	memset(r->mem, 0xA5, cap + 16u);
	memset(&why, 0, sizeof(why));
	wri_mapbuild_begin(&b, (uint8_t *)(((uintptr_t)r->mem + 15u) & ~(uintptr_t)15u), cap, &why);
	r->m = b.m;
	WRT_CHECK(b.m != NULL);
	if (b.m == NULL)
		return 0;
	b.m->epoch = d->epoch;
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, (uint32_t)d->max_osd, d->osd_primary_affinity.n != 0u));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_pools(&b, nids));
	for (k = 0; k < WRI_TAB_COUNT; k++)
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, k, tn[k], tnv[k]));

	base = wri_map_base_rw(b.m);
	for (i = 0; i < (uint32_t)d->max_osd; i++) {
		uint32_t st = i < d->osd_state.n ? WRT_MG_E(d->osd_state, uint32_t, i) : 0u;

		base[b.m->state_off + i] = (uint8_t)(st & (WRI_OSD_EXISTS | WRI_OSD_UP));
		((uint32_t *)(void *)(base + b.m->weight_off))[i] = i < d->osd_weight.n ? WRT_MG_E(d->osd_weight, uint32_t, i) : 0u;
		if (b.m->aff_off != 0u)
			((uint32_t *)(void *)(base + b.m->aff_off))[i] = WRT_MG_E(d->osd_primary_affinity, uint32_t, i);
	}
	pools = (wri_map_pool *)(void *)(base + b.m->pool_off);
	for (i = 0; i < nids; i++) {
		const wrt_mg_pool_ent *pe = NULL;
		uint32_t q;

		for (q = 0; q < d->pools.n; q++)
			if (WRT_MG_E(d->pools, wrt_mg_pool_ent, q).id == ids[i])
				pe = &WRT_MG_E(d->pools, wrt_mg_pool_ent, q);
		WRT_CHECK(pe != NULL);
		if (pe == NULL)
			return 0;
		pools[i].id = pe->id;
		pools[i].flags = pe->p.flags;
		pools[i].pg_num = pe->p.pg_num;
		pools[i].pgp_num = pe->p.pgp_num;
		pools[i].pg_num_mask = wrt_mg_pg_mask(pe->p.pg_num);
		pools[i].pgp_num_mask = wrt_mg_pg_mask(pe->p.pgp_num);
		pools[i].pg_num_pending = pe->p.pg_num_pending;
		pools[i].last_force_op_resend = pe->p.last_force_op_resend;
		pools[i].status = WR_OK;
		pools[i].present = 1;
		pools[i].type = pe->p.type;
		pools[i].size = pe->p.size;
		pools[i].min_size = pe->p.min_size;
		pools[i].crush_rule = pe->p.crush_rule;
		pools[i].object_hash = pe->p.object_hash;
	}

	for (i = 0; i < d->pg_temp.n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(d->pg_temp, wrt_mg_pg_list, i);

		if (!rig_push(&b, WRI_TAB_PG_TEMP, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), (const int32_t *)e->osds.v, e->osds.n))
			return 0;
	}
	for (i = 0; i < d->primary_temp.n; i++) {
		const wrt_mg_pg_osd *e = &WRT_MG_E(d->primary_temp, wrt_mg_pg_osd, i);

		if (!rig_push(&b, WRI_TAB_PRIMARY_TEMP, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &e->osd, 1u))
			return 0;
	}
	for (i = 0; i < d->pg_upmap.n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(d->pg_upmap, wrt_mg_pg_list, i);

		if (!rig_push(&b, WRI_TAB_PG_UPMAP, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), (const int32_t *)e->osds.v, e->osds.n))
			return 0;
	}
	for (i = 0; i < d->pg_upmap_items.n; i++) {
		const wrt_mg_pg_items *e = &WRT_MG_E(d->pg_upmap_items, wrt_mg_pg_items, i);
		int32_t flat[2u * 64u];
		uint32_t q;

		if (e->items.n > 64u) {
			WRT_CHECK(0);
			return 0;
		}
		for (q = 0; q < e->items.n; q++) {
			flat[2u * q] = WRT_MG_E(e->items, wrt_mg_pair, q).from;
			flat[2u * q + 1u] = WRT_MG_E(e->items, wrt_mg_pair, q).to;
		}
		if (!rig_push(&b, WRI_TAB_PG_UPMAP_ITEMS, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), flat, 2u * e->items.n))
			return 0;
	}
	for (i = 0; i < d->pg_upmap_primaries.n; i++) {
		const wrt_mg_pg_osd *e = &WRT_MG_E(d->pg_upmap_primaries, wrt_mg_pg_osd, i);

		if (!rig_push(&b, WRI_TAB_PG_UPMAP_PRIMARY, wri_pg_key((uint32_t)e->pg.pool, e->pg.seed), &e->osd, 1u))
			return 0;
	}

	if (with_crush && d->crush != NULL && d->crush_len != 0u) {
		size_t room = wri_mapbuild_crush_left(&b), used = 0;
		uint8_t *p = wri_mapbuild_crush_room(&b, room);
		wr_status st;

		WRT_CHECK(p != NULL);
		if (p == NULL)
			return 0;
		st = wri_crush_decode(d->crush, d->crush_len, p, room, &used, &why);
		WRT_CHECK_STATUS(WR_OK, st);
		if (st != WR_OK) {
			fprintf(stderr, "crush decode: %s\n", why.what != NULL ? why.what : "?");
			return 0;
		}
	}
	wri_mapbuild_finish(&b);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	return 1;
}

/* The first WRI_MAP_POOLS_MAX pools of the description (all of them in every test that builds its own cluster). */
static int rig_build(place_rig *r, const wrt_mg_map *d, int with_crush)
{
	int64_t ids[WRI_MAP_POOLS_MAX];
	uint32_t i, n = d->pools.n < WRI_MAP_POOLS_MAX ? d->pools.n : WRI_MAP_POOLS_MAX;

	for (i = 0; i < n; i++)
		ids[i] = WRT_MG_E(d->pools, wrt_mg_pool_ent, i).id;
	return rig_build_pools(r, d, with_crush, ids, n);
}

#endif /* PLACE_RIG_H */
