/* SPDX-License-Identifier: MIT */
/*
 * wri_osdmap_tab.c - the pg-keyed tables of a map slot: append, search, copy (see wri_osdmap.h).
 *
 * A table is three arrays carved by wri_mapbuild_tab: keys u64[cap_n] ascending, offsets u32[cap_n + 1] and values
 * s32[cap_nv]; entry i owns values[offsets[i] .. offsets[i + 1]). Append keeps them consistent: a push that fails
 * changes nothing, so a table is never left with keys that have no offsets.
 */
#include "wri_osdmap.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define WRI_PGVEC_LIMIT (WRI_MAP_PGVEC_MAX * 2u)

wr_status wri_pgtab_push(wri_mapbuild *b, unsigned kind, uint64_t key, const int32_t *vals, uint32_t nvals)
{
	wri_pgtab *t;
	uint64_t *keys;
	uint32_t *offs;
	int32_t *dst;
	wr_status st = wri_mapbuild_status(b);

	if (st != WR_OK)
		return st;
	if (kind >= WRI_TAB_COUNT || (nvals != 0 && vals == NULL)) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, kind >= WRI_TAB_COUNT ? "unknown pg table kind" : "pg table values missing", kind, nvals, 0);
		return WR_E_INVAL;
	}
	t = &b->m->tab[kind];
	keys = (uint64_t *)(void *)(wri_map_base_rw(b->m) + t->key_off);
	if (t->n > 0 && key <= keys[t->n - 1u]) {
		WRI_ERRINFO(b->why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "pg table keys are not strictly ascending", key, keys[t->n - 1u], kind);
		return WR_E_MAP_CORRUPT;
	}
	if (nvals > WRI_PGVEC_LIMIT) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, "pg table vector longer than the kept maximum", nvals, WRI_PGVEC_LIMIT, kind);
		return WR_E_MAP_BUDGET;
	}
	if (t->n >= t->cap_n) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, "pg table entry room is full", (uint64_t)t->n + 1u, t->cap_n, kind);
		return WR_E_MAP_BUDGET;
	}
	if ((uint64_t)t->nv + nvals > t->cap_nv) {
		WRI_ERRINFO(b->why, WR_E_MAP_BUDGET, WR_MOD_MAP, "pg table value room is full", (uint64_t)t->nv + nvals, t->cap_nv, kind);
		return WR_E_MAP_BUDGET;
	}
	offs = (uint32_t *)(void *)(wri_map_base_rw(b->m) + t->off_off);
	dst = (int32_t *)(void *)(wri_map_base_rw(b->m) + t->val_off);
	if (nvals != 0)
		WR_MEMCPY(dst + t->nv, vals, (size_t)nvals * sizeof(int32_t));
	keys[t->n] = key;
	offs[t->n + 1u] = t->nv + nvals;
	t->n++;
	t->nv += nvals;
	return WR_OK;
}

int wri_pgtab_find(const wri_osdmap *m, unsigned kind, uint64_t key, const int32_t **vals, uint32_t *nvals)
{
	const uint64_t *keys;
	const uint32_t *offs;
	uint32_t lo, hi, mid;

	if (kind >= WRI_TAB_COUNT || m->tab[kind].n == 0)
		return 0;
	keys = wri_pgtab_keys(m, kind);
	lo = 0;
	hi = m->tab[kind].n;
	while (lo < hi) { /* the first key that is not below `key` */
		mid = lo + (hi - lo) / 2u;
		if (keys[mid] < key)
			lo = mid + 1u;
		else
			hi = mid;
	}
	if (lo >= m->tab[kind].n || keys[lo] != key)
		return 0;
	offs = wri_pgtab_offs(m, kind);
	if (vals != NULL)
		*vals = wri_pgtab_vals(m, kind) + offs[lo];
	if (nvals != NULL)
		*nvals = offs[lo + 1u] - offs[lo];
	return 1;
}

/* The source table lies inside its map and is consistent enough to copy by its counts. */
static int wri_tab_copyable(const wri_osdmap *src, const wri_pgtab *s)
{
	if (s->n > s->cap_n || s->nv > s->cap_nv)
		return 0;
	if (s->off_off == 0)
		return s->n == 0 && s->nv == 0;
	return (uint64_t)s->key_off + (uint64_t)s->n * 8u <= src->bytes && (uint64_t)s->off_off + ((uint64_t)s->n + 1u) * 4u <= src->bytes &&
	       (uint64_t)s->val_off + (uint64_t)s->nv * 4u <= src->bytes;
}

wr_status wri_mapbuild_copy_tab(wri_mapbuild *b, unsigned kind, const wri_osdmap *src)
{
	const wri_pgtab *s;
	wri_pgtab *t;
	wr_status st = wri_mapbuild_status(b);

	if (st != WR_OK)
		return st;
	if (kind >= WRI_TAB_COUNT || src == NULL || src->magic != WRI_MAP_MAGIC) {
		WRI_ERRINFO(b->why, WR_E_INVAL, WR_MOD_MAP, kind >= WRI_TAB_COUNT ? "unknown pg table kind" : "pg table source is not a finished map", kind, 0, 0);
		return WR_E_INVAL;
	}
	s = &src->tab[kind];
	if (!wri_tab_copyable(src, s)) {
		WRI_ERRINFO(b->why, WR_E_MAP_CORRUPT, WR_MOD_MAP, "pg table source is inconsistent", kind, s->n, s->nv);
		return WR_E_MAP_CORRUPT;
	}
	st = wri_mapbuild_tab(b, kind, s->n, s->nv); /* all or nothing; WR_E_INVAL when already carved */
	if (st != WR_OK)
		return st;
	t = &b->m->tab[kind];
	if (s->off_off != 0) { /* an uncarved source table is empty: the zeroed offsets[0] is already right */
		WR_MEMCPY(wri_map_base_rw(b->m) + t->key_off, wri_map_base(src) + s->key_off, (size_t)s->n * 8u);
		WR_MEMCPY(wri_map_base_rw(b->m) + t->off_off, wri_map_base(src) + s->off_off, ((size_t)s->n + 1u) * 4u);
		WR_MEMCPY(wri_map_base_rw(b->m) + t->val_off, wri_map_base(src) + s->val_off, (size_t)s->nv * 4u);
	}
	t->n = s->n;
	t->nv = s->nv;
	return WR_OK;
}
