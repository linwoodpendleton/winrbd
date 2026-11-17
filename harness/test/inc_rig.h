/* SPDX-License-Identifier: MIT */
/*
 * inc_rig.h - shared by test_osdmap_inc.c and test_osdmap_seq.c: map slots with guard bytes, the checks every
 * wri_osdmap_apply_inc call is put through, a comparison of a compact map with the plain-array model of wrt_mapgen, and a
 * comparison of two compact maps.
 *
 * What rig_apply checks on EVERY call (so a test only has to look at the status and at the result):
 *   - the same incremental applied twice, into slots pre-filled with two different bytes, gives the same status and, on
 *     success, the same bytes (a decision taken on a byte of the slot that the decoder did not write shows up);
 *   - the guard bytes around each slot are untouched (nothing is written outside the slot);
 *   - the held map is byte for byte what it was (it is never written);
 *   - a failure leaves magic 0 in the new slot and puts a module and a reason in the errinfo;
 *   - a success gives a map that passes wri_osdmap_check.
 * The incremental is an exact-size heap copy, so an over-read is an ASan report.
 */
#ifndef INC_RIG_H
#define INC_RIG_H

#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush.h"
#include "wri_ctx.h"
#include "wri_osdmap_dec.h"

#define RIG_GUARD 64u
#define RIG_GUARD_BYTE 0xA5u
#define RIG_SLOT_BYTES (1u << 20)

/* ---- slots ----------------------------------------------------------------------------------------- */

typedef struct islot {
	uint8_t *raw, *p;
	size_t cap, total;
} islot;

WRT_UNUSED static void islot_new(islot *s, size_t cap)
{
	uintptr_t a;

	s->total = cap + 2u * RIG_GUARD + 15u;
	s->raw = (uint8_t *)malloc(s->total);
	if (s->raw == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(s->raw, RIG_GUARD_BYTE, s->total);
	a = ((uintptr_t)s->raw + RIG_GUARD + 15u) & ~(uintptr_t)15u;
	s->p = (uint8_t *)a;
	s->cap = cap;
	/* the guard after the slot: everything from p + cap to the end of the block */
}

WRT_UNUSED static void islot_free(islot *s)
{
	free(s->raw);
	s->raw = s->p = NULL;
}

WRT_UNUSED static void islot_fill(islot *s, uint8_t pat) { memset(s->p, pat, s->cap); }

WRT_UNUSED static int islot_guard_ok(const islot *s)
{
	size_t i, pre = (size_t)(s->p - s->raw);

	for (i = 0; i < pre; i++)
		if (s->raw[i] != RIG_GUARD_BYTE)
			return 0;
	for (i = pre + s->cap; i < s->total; i++)
		if (s->raw[i] != RIG_GUARD_BYTE)
			return 0;
	return 1;
}

WRT_UNUSED static const wri_osdmap *islot_map(const islot *s) { return (const wri_osdmap *)(const void *)s->p; }

WRT_UNUSED static uint32_t islot_magic(const islot *s)
{
	uint32_t v = 0;

	if (s->cap >= 4u) /* a smaller slot cannot hold a magic: nothing to read */
		memcpy(&v, s->p, 4);
	return v;
}

WRT_UNUSED static uint8_t *rig_dup(const uint8_t *p, size_t n)
{
	uint8_t *c = (uint8_t *)malloc(n == 0 ? 1 : n);

	if (c == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n != 0)
		memcpy(c, p, n);
	return c;
}

/* ---- configuration ----------------------------------------------------------------------------------- */

WRT_UNUSED static void rig_cfg(wri_mapcfg *c, uint32_t slot_bytes, uint32_t max_osd, int verify, const char *const *names, unsigned n)
{
	unsigned k;

	memset(c, 0, sizeof(*c));
	c->slot_bytes = slot_bytes;
	c->max_osd = max_osd;
	c->work_max = 200000;
	c->verify_crc = (uint8_t)verify;
	c->n_pools = (uint8_t)n;
	for (k = 0; k < n; k++) {
		c->name_len[k] = (uint8_t)strlen(names[k]);
		memcpy(c->name[k], names[k], c->name_len[k]);
	}
}

/* ---- decode and apply, with the checks -------------------------------------------------------------- */

/* decode_full into `s` with the guards and magic checks; returns the status. */
WRT_UNUSED static wr_status rig_decode(const wri_mapcfg *cfg, const uint8_t *blob, size_t n, islot *s, wr_errinfo *why)
{
	uint8_t *c = rig_dup(blob, n);
	wr_status st;

	islot_fill(s, 0x00);
	if (why != NULL)
		memset(why, 0, sizeof(*why));
	st = wri_osdmap_decode_full(cfg, c, n, s->p, s->cap, why);
	free(c);
	WRT_CHECK(islot_guard_ok(s));
	if (st != WR_OK)
		WRT_CHECK_U64(islot_magic(s), 0);
	else
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(islot_map(s)));
	return st;
}

WRT_UNUSED static int rig_status_is_map(wr_status st)
{
	return st == WR_E_MAP_VERSION || st == WR_E_MAP_CORRUPT || st == WR_E_MAP_CRC || st == WR_E_MAP_BUDGET || st == WR_E_MAP_FSID ||
	       st == WR_E_MAP_EPOCH || st == WR_E_MAP_RESYNC || st == WR_E_CRUSH_ENCODING || st == WR_E_CRUSH_UNSUPPORTED;
}

/*
 * Apply `blob` to `src` into `dst` (a fresh slot of any size, pre-filled by this call) and run the checks listed at the top.
 * Returns the status; on WR_OK `dst` holds the new map.
 */
WRT_UNUSED static wr_status rig_apply(const wri_mapcfg *cfg, const wri_osdmap *src, const uint8_t *blob, size_t n, islot *dst, wr_errinfo *why)
{
	uint8_t *c = rig_dup(blob, n);
	uint8_t *held = rig_dup((const uint8_t *)src, src->bytes);
	islot other;
	wr_errinfo w2;
	wr_status st, st2;

	islot_new(&other, dst->cap);
	islot_fill(dst, 0x00);
	islot_fill(&other, 0xFF);
	if (why != NULL)
		memset(why, 0, sizeof(*why));
	memset(&w2, 0, sizeof(w2));
	st = wri_osdmap_apply_inc(cfg, src, c, n, dst->p, dst->cap, why);
	st2 = wri_osdmap_apply_inc(cfg, src, c, n, other.p, other.cap, &w2);
	free(c);
	WRT_CHECK_STATUS(st, st2);
	WRT_CHECK(islot_guard_ok(dst) && islot_guard_ok(&other));
	WRT_CHECK(memcmp(held, src, src->bytes) == 0); /* the held map is never written */
	free(held);
	if (st == WR_OK) {
		const wri_osdmap *a = islot_map(dst), *b = islot_map(&other);

		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(a));
		WRT_CHECK_U64(a->bytes, b->bytes);
		if (a->bytes == b->bytes)
			WRT_CHECK(memcmp(dst->p, other.p, a->bytes) == 0);
		WRT_CHECK(a->bytes <= dst->cap);
	} else {
		WRT_CHECK_U64(islot_magic(dst), 0);
		WRT_CHECK_U64(islot_magic(&other), 0);
		if (st != WR_E_INVAL) {
			WRT_CHECK(rig_status_is_map(st));
			if (why != NULL) {
				WRT_CHECK_STATUS(st, why->status);
				WRT_CHECK(why->module != 0 && why->what != NULL);
			}
		}
	}
	islot_free(&other);
	return st;
}

/* ---- comparison of two compact maps (the same state, however it was built) -------------------------------------- */

#define RIG_CMP(a, b) WRT_CHECK_U64((a), (b))

WRT_UNUSED static void rig_cmp_core(const wri_osdmap *a, const wri_osdmap *b)
{
	uint32_t i, k;
	const wri_crush *ca = wri_map_crush(a), *cb = wri_map_crush(b);

	RIG_CMP(a->epoch, b->epoch);
	WRT_CHECK(memcmp(a->fsid, b->fsid, 16) == 0);
	RIG_CMP(a->flags, b->flags);
	RIG_CMP(a->max_osd, b->max_osd);
	RIG_CMP(a->n_pools, b->n_pools);
	RIG_CMP(a->n_exists, b->n_exists);
	RIG_CMP(a->n_up, b->n_up);
	if (a->max_osd != b->max_osd)
		return;
	for (i = 0; i < a->max_osd; i++) {
		RIG_CMP(wri_map_state(a)[i], wri_map_state(b)[i]);
		RIG_CMP(wri_map_weight(a)[i], wri_map_weight(b)[i]);
		RIG_CMP(wri_osd_aff(a, (int32_t)i), wri_osd_aff(b, (int32_t)i));
		WRT_CHECK(memcmp(&wri_map_addr(a)[i], &wri_map_addr(b)[i], sizeof(wri_osd_addr)) == 0);
	}
	if (a->n_pools == b->n_pools)
		for (k = 0; k < a->n_pools; k++)
			WRT_CHECK(memcmp(&wri_map_pools(a)[k], &wri_map_pools(b)[k], sizeof(wri_map_pool)) == 0);
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		RIG_CMP(a->tab[k].n, b->tab[k].n);
		RIG_CMP(a->tab[k].nv, b->tab[k].nv);
		if (a->tab[k].n != b->tab[k].n || a->tab[k].nv != b->tab[k].nv || a->tab[k].n == 0)
			continue;
		WRT_CHECK(memcmp(wri_pgtab_keys(a, k), wri_pgtab_keys(b, k), (size_t)a->tab[k].n * 8u) == 0);
		WRT_CHECK(memcmp(wri_pgtab_offs(a, k), wri_pgtab_offs(b, k), ((size_t)a->tab[k].n + 1u) * 4u) == 0);
		WRT_CHECK(memcmp(wri_pgtab_vals(a, k), wri_pgtab_vals(b, k), (size_t)a->tab[k].nv * 4u) == 0);
	}
	WRT_CHECK(ca != NULL && cb != NULL);
	if (ca != NULL && cb != NULL) {
		RIG_CMP(ca->bytes, cb->bytes);
		if (ca->bytes == cb->bytes)
			WRT_CHECK(memcmp(ca, cb, ca->bytes) == 0);
	}
}

/* ---- comparison with the plain-array model -------------------------------------------------------------------- */

WRT_UNUSED static void rig_addr_ref(const wrt_mg_addrvec *av, wri_osd_addr *o)
{
	uint32_t i;

	memset(o, 0, sizeof(*o));
	for (i = 0; i < av->n && i < WRT_MG_AV_MAX; i++) {
		const wrt_mg_addr *a = &av->a[i];

		if (a->type != 2 || a->elen < 2 || (a->family != 2 && a->family != 10))
			continue;
		o->nonce = a->nonce;
		o->port = (uint16_t)(((unsigned)a->sa[0] << 8) | a->sa[1]);
		if (a->family == 2) {
			o->family = WR_AF_IPV4;
			memcpy(o->ip, a->sa + 2, 4);
		} else {
			o->family = WR_AF_IPV6;
			memcpy(o->ip, a->sa + 6, 16);
		}
		return;
	}
}

typedef struct rig_tracked {
	int found;
	int64_t id;
} rig_tracked;

WRT_UNUSED static void rig_resolve(const wrt_mg_map *mod, const wri_mapcfg *cfg, rig_tracked *t)
{
	uint32_t k, i;

	for (k = 0; k < cfg->n_pools; k++) {
		t[k].found = 0;
		t[k].id = 0;
		for (i = 0; i < mod->pool_names.n; i++) {
			const wrt_mg_pname *pn = &WRT_MG_E(mod->pool_names, wrt_mg_pname, i);

			if (cfg->name_len[k] != 0 && strlen(pn->name) == cfg->name_len[k] && memcmp(pn->name, cfg->name[k], cfg->name_len[k]) == 0) {
				t[k].found = 1;
				t[k].id = pn->id;
			}
		}
	}
}

WRT_UNUSED static int rig_is_tracked(const rig_tracked *t, uint32_t n, uint64_t pool)
{
	uint32_t k;

	for (k = 0; k < n; k++)
		if (t[k].found && pool < ((uint64_t)1 << 31) && t[k].id == (int64_t)pool)
			return 1;
	return 0;
}

/* One table against the model's vector of that table; `stride` is the element size of the model vector. */
WRT_UNUSED static void rig_cmp_tab(const wri_osdmap *m, unsigned kind, const wrt_mg_vec *vec, const rig_tracked *t, uint32_t nt)
{
	uint32_t i, n = 0, nv = 0;

	for (i = 0; i < vec->n; i++) {
		wrt_mg_pg pg;
		int32_t flat[2u * 64u];
		uint32_t cnt = 0;
		const int32_t *got;
		uint32_t ngot;

		if (kind == WRI_TAB_PG_TEMP || kind == WRI_TAB_PG_UPMAP) {
			const wrt_mg_pg_list *e = &WRT_MG_E(*vec, wrt_mg_pg_list, i);

			pg = e->pg;
			cnt = e->osds.n;
			if (cnt <= 64u && cnt != 0)
				memcpy(flat, e->osds.v, cnt * 4u);
		} else if (kind == WRI_TAB_PG_UPMAP_ITEMS) {
			const wrt_mg_pg_items *e = &WRT_MG_E(*vec, wrt_mg_pg_items, i);
			uint32_t q;

			pg = e->pg;
			cnt = e->items.n * 2u;
			for (q = 0; q < e->items.n && q < 32u; q++) {
				flat[2u * q] = WRT_MG_E(e->items, wrt_mg_pair, q).from;
				flat[2u * q + 1u] = WRT_MG_E(e->items, wrt_mg_pair, q).to;
			}
		} else {
			const wrt_mg_pg_osd *e = &WRT_MG_E(*vec, wrt_mg_pg_osd, i);

			pg = e->pg;
			cnt = 1;
			flat[0] = e->osd;
		}
		if (!rig_is_tracked(t, nt, pg.pool))
			continue;
		n++;
		nv += cnt;
		if (wri_pgtab_find(m, kind, wri_pg_key((uint32_t)pg.pool, pg.seed), &got, &ngot)) {
			WRT_CHECK_U64(ngot, cnt);
			if (ngot == cnt && cnt != 0 && cnt <= 64u)
				WRT_CHECK(memcmp(got, flat, cnt * 4u) == 0);
		} else {
			WRT_CHECK(0 && "an entry of a tracked pool is missing from the table");
		}
	}
	WRT_CHECK_U64(m->tab[kind].n, n);
	WRT_CHECK_U64(m->tab[kind].nv, nv);
	WRT_CHECK_U64(m->tab[kind].cap_n, n);
	WRT_CHECK_U64(m->tab[kind].cap_nv, nv);
}

#define RIG_WANT_ANY 0x7FFFFFFF /* in a `want` array: do not compare this pool's status */

/* The compact map against the model. `want` (n_pools statuses, or NULL = all WR_OK) are the expected pool statuses. */
WRT_UNUSED static void rig_cmp_model(const wri_osdmap *m, const wrt_mg_map *mod, const wri_mapcfg *cfg, const int32_t *want)
{
	rig_tracked t[WRI_MAP_POOLS_MAX];
	const uint8_t *state = wri_map_state(m);
	const wri_osd_addr *ad = wri_map_addr(m);
	uint32_t i, k;

	WRT_CHECK_U64(m->epoch, mod->epoch);
	WRT_CHECK(memcmp(m->fsid, mod->fsid, 16) == 0);
	WRT_CHECK_U64(m->flags, mod->flags);
	WRT_CHECK_U64(m->max_osd, (uint32_t)mod->max_osd);
	WRT_CHECK_U64(m->n_pools, cfg->n_pools);
	for (i = 0; i < m->max_osd && i < (uint32_t)mod->max_osd; i++) {
		wri_osd_addr want_ad;

		WRT_CHECK_U64(state[i], WRT_MG_E(mod->osd_state, uint32_t, i) & 3u);
		WRT_CHECK_U64(wri_map_weight(m)[i], WRT_MG_E(mod->osd_weight, uint32_t, i));
		WRT_CHECK_U64(wri_osd_aff(m, (int32_t)i), wrt_mg_affinity(mod, (int32_t)i));
		rig_addr_ref(&WRT_MG_E(mod->client_addrs, wrt_mg_addrvec, i), &want_ad);
		if (memcmp(&ad[i], &want_ad, sizeof(want_ad)) != 0) {
			WRT_CHECK(0 && "OSD address differs from the model");
			fprintf(stderr, "  osd %u: family %u/%u port %u/%u\n", i, ad[i].family, want_ad.family, ad[i].port, want_ad.port);
		}
	}
	rig_resolve(mod, cfg, t);
	for (k = 0; k < cfg->n_pools; k++) {
		const wri_map_pool *p = &wri_map_pools(m)[k];
		const wrt_mg_pool *mp = t[k].found ? wrt_mg_map_pool(mod, t[k].id) : NULL;
		wri_map_pool zero;

		if (mp == NULL) { /* absent: the whole record is zero, whatever was held before */
			memset(&zero, 0, sizeof(zero));
			WRT_CHECK(memcmp(p, &zero, sizeof(zero)) == 0);
			continue;
		}
		WRT_CHECK_U64(p->present, 1);
		WRT_CHECK_U64(p->id, t[k].id);
		WRT_CHECK_U64(p->type, mp->type);
		WRT_CHECK_U64(p->size, mp->size);
		WRT_CHECK_U64(p->min_size, mp->min_size);
		WRT_CHECK_U64(p->crush_rule, mp->crush_rule);
		WRT_CHECK_U64(p->object_hash, mp->object_hash);
		WRT_CHECK_U64(p->pg_num, mp->pg_num);
		WRT_CHECK_U64(p->pgp_num, mp->pgp_num);
		WRT_CHECK_U64(p->flags, mp->flags);
		WRT_CHECK_U64(p->pg_num_mask, wrt_mg_pg_mask(mp->pg_num));
		WRT_CHECK_U64(p->pgp_num_mask, wrt_mg_pg_mask(mp->pgp_num));
		WRT_CHECK_U64(p->last_force_op_resend, mp->last_force_op_resend);
		WRT_CHECK_U64(p->pg_num_pending, mp->pg_num_pending);
		if (want == NULL || want[k] != RIG_WANT_ANY)
			WRT_CHECK_U64((uint32_t)p->status, (uint32_t)(want != NULL ? want[k] : WR_OK));
	}
	rig_cmp_tab(m, WRI_TAB_PG_TEMP, &mod->pg_temp, t, cfg->n_pools);
	rig_cmp_tab(m, WRI_TAB_PRIMARY_TEMP, &mod->primary_temp, t, cfg->n_pools);
	rig_cmp_tab(m, WRI_TAB_PG_UPMAP, &mod->pg_upmap, t, cfg->n_pools);
	rig_cmp_tab(m, WRI_TAB_PG_UPMAP_ITEMS, &mod->pg_upmap_items, t, cfg->n_pools);
	rig_cmp_tab(m, WRI_TAB_PG_UPMAP_PRIMARY, &mod->pg_upmap_primaries, t, cfg->n_pools);

	/* the CRUSH region is what decoding the model's blob gives */
	{
		const wri_crush *c = wri_map_crush(m);
		uint8_t *tmp = (uint8_t *)malloc(RIG_SLOT_BYTES + 16u);
		uint8_t *aligned = (uint8_t *)(((uintptr_t)tmp + 15u) & ~(uintptr_t)15u);
		size_t used = 0;

		WRT_CHECK(c != NULL && tmp != NULL);
		if (c != NULL && tmp != NULL && mod->crush != NULL && mod->crush_len != 0) {
			WRT_CHECK_STATUS(WR_OK, wri_crush_decode(mod->crush, mod->crush_len, aligned, RIG_SLOT_BYTES, &used, NULL));
			WRT_CHECK_U64(c->bytes, used);
			if (c->bytes == used)
				WRT_CHECK(memcmp(c, aligned, used) == 0);
		}
		free(tmp);
	}
}

/* ---- a model + a held compact map, stepped together ------------------------------------------------------------- */

typedef struct rig {
	wri_mapcfg cfg;
	wrt_mg_map model;
	islot s[2];
	int cur;
} rig;

WRT_UNUSED static const wri_osdmap *rig_held(const rig *g) { return islot_map(&g->s[g->cur]); }

/* Start from a description: the held map is its full encoding decoded by the core, the model is a copy. */
WRT_UNUSED static int rig_start(rig *g, const wrt_mg_map *desc, uint32_t max_osd_limit, int verify, const char *const *names, unsigned n)
{
	wrt_mg_buf b;
	wr_errinfo why;
	wr_status st;

	memset(g, 0, sizeof(*g));
	rig_cfg(&g->cfg, RIG_SLOT_BYTES, max_osd_limit, verify, names, n);
	islot_new(&g->s[0], RIG_SLOT_BYTES);
	islot_new(&g->s[1], RIG_SLOT_BYTES);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_map_encode(desc, &b) == 0);
	WRT_CHECK(wrt_mg_map_clone(desc, &g->model) == 0);
	st = rig_decode(&g->cfg, b.p, b.len, &g->s[0], &why);
	WRT_CHECK_STATUS(WR_OK, st);
	wrt_mg_buf_free(&b);
	return st == WR_OK;
}

WRT_UNUSED static void rig_end(rig *g)
{
	islot_free(&g->s[0]);
	islot_free(&g->s[1]);
	wrt_mg_map_free(&g->model);
}

/*
 * Apply one incremental to the core and to the model. When both accept it, the new compact map must equal the model state
 * (rig_cmp_model, with `want` pool statuses) and the map a full decode of the model's own encoding gives (rig_cmp_core), and
 * it becomes the held map. When the core refuses, nothing changes (the held map and the model stay). The core's status is
 * returned; *model_rc gets the model's (WRT_MG_E_OK or an error), the model state is only advanced on WR_OK from both.
 */
WRT_UNUSED static wr_status rig_step_blob(rig *g, const uint8_t *blob, size_t n, const wrt_mg_inc *inc, const int32_t *want, int *model_rc, wr_errinfo *why)
{
	islot *dst = &g->s[1 - g->cur];
	wr_status st = rig_apply(&g->cfg, rig_held(g), blob, n, dst, why);
	wrt_mg_map trial;
	int rc;

	rc = -99;
	if (inc != NULL) {
		WRT_CHECK(wrt_mg_map_clone(&g->model, &trial) == 0);
		rc = wrt_mg_model_apply(&trial, inc);
	}
	if (model_rc != NULL)
		*model_rc = rc;
	if (inc != NULL && st == WR_OK && rc == WRT_MG_E_OK) {
		wrt_mg_buf fb;
		islot full;
		wr_errinfo w2;

		rig_cmp_model(islot_map(dst), &trial, &g->cfg, want);
		memset(&fb, 0, sizeof(fb));
		WRT_CHECK(wrt_mg_map_encode(&trial, &fb) == 0);
		islot_new(&full, RIG_SLOT_BYTES);
		if (rig_decode(&g->cfg, fb.p, fb.len, &full, &w2) == WR_OK)
			rig_cmp_core(islot_map(dst), islot_map(&full));
		islot_free(&full);
		wrt_mg_buf_free(&fb);
		wrt_mg_map_free(&g->model);
		g->model = trial;
		g->cur = 1 - g->cur;
	} else if (inc != NULL) {
		wrt_mg_map_free(&trial);
	}
	return st;
}

/* Encode `inc` and step. */
WRT_UNUSED static wr_status rig_step(rig *g, const wrt_mg_inc *inc, const int32_t *want, wr_errinfo *why)
{
	wrt_mg_buf b;
	wr_status st;
	int rc;

	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(inc, &b) == 0);
	st = rig_step_blob(g, b.p, b.len, inc, want, &rc, why);
	wrt_mg_buf_free(&b);
	WRT_CHECK((st == WR_OK) == (rc == WRT_MG_E_OK)); /* the core and the model accept the same incrementals */
	return st;
}

/* A fresh incremental for the next epoch of the model. */
WRT_UNUSED static void rig_inc(const rig *g, wrt_mg_inc *inc) { wrt_mg_inc_init(inc, g->model.fsid, g->model.epoch + 1u); }

#endif /* INC_RIG_H */
