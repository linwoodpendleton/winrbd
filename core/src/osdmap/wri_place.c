/* SPDX-License-Identifier: MIT */
/*
 * wri_place.c - object name to placement group to OSD sets (docs/design/core-architecture.md 16.4).
 *
 * The hash of step 1 runs over up to three pieces (namespace, the 0x1f separator, the subject) without
 * assembling them: the stack of a firmware or kernel caller is small and a name may be 4 KiB. The namespace-free
 * case, which is every RBD data object, goes straight to wri_str_hash; the namespaced case uses the gather
 * versions below, which the tests compare with the contiguous hashes over random splits.
 *
 * wri_place_pg chains the steps. Its buffers hold WRI_PLACE_LIST_MAX members (an upmap list can be longer than a
 * result); the result structure keeps the first WRI_REP_MAX members of each list, which loses nothing for a
 * pool the client can serve (size at most WRI_REP_MAX, and a monitor does not accept an upmap or pg_temp list
 * longer than the pool size).
 */
#include "wri_place.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define SEP_BYTE 0x1fu /* the separator between a namespace and the name or key */
#define GOLDEN 0x9e3779b9u

/* ---- a string hash over pieces ------------------------------------------------------------------------- */

typedef struct hash_acc {
	uint32_t a, b, c; /* rjenkins state */
	uint32_t h;       /* Linux dcache state */
	uint32_t fill;    /* bytes waiting in blk */
	uint32_t total;
	uint8_t blk[12];
} hash_acc;

/* The nine-round mix of crush note 3.2.1 (the rjenkins string hash and the CRUSH hashes share it). */
static void mix(uint32_t *pa, uint32_t *pb, uint32_t *pc)
{
	uint32_t a = *pa, b = *pb, c = *pc;

	a = a - b - c;
	a ^= c >> 13;
	b = b - c - a;
	b ^= a << 8;
	c = c - a - b;
	c ^= b >> 13;
	a = a - b - c;
	a ^= c >> 12;
	b = b - c - a;
	b ^= a << 16;
	c = c - a - b;
	c ^= b >> 5;
	a = a - b - c;
	a ^= c >> 3;
	b = b - c - a;
	b ^= a << 10;
	c = c - a - b;
	c ^= b >> 15;
	*pa = a;
	*pb = b;
	*pc = c;
}

static uint32_t le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void acc_init(hash_acc *x)
{
	WR_MEMSET(x, 0, sizeof(*x));
	x->a = GOLDEN;
	x->b = GOLDEN;
}

static void acc_feed(hash_acc *x, uint32_t hash_id, const uint8_t *s, uint32_t n)
{
	uint32_t i;

	if (hash_id == WRI_STR_HASH_LINUX) {
		for (i = 0; i < n; i++) {
			uint32_t ch = s[i];

			x->h = (x->h + (ch << 4) + (ch >> 4)) * 11u;
		}
		return;
	}
	for (i = 0; i < n; i++) {
		x->blk[x->fill++] = s[i];
		x->total++;
		if (x->fill == 12u) {
			x->a += le32(x->blk);
			x->b += le32(x->blk + 4);
			x->c += le32(x->blk + 8);
			mix(&x->a, &x->b, &x->c);
			x->fill = 0;
		}
	}
}

static uint32_t acc_done(hash_acc *x, uint32_t hash_id)
{
	const uint8_t *k = x->blk;
	uint32_t i;

	if (hash_id == WRI_STR_HASH_LINUX)
		return x->h;
	x->c += x->total;
	/* The tail of 0..11 bytes; c's low byte holds the length, so its bytes start one byte up. */
	for (i = 0; i < x->fill; i++) {
		uint32_t v = k[i];

		if (i < 4u)
			x->a += v << (8u * i);
		else if (i < 8u)
			x->b += v << (8u * (i - 4u));
		else
			x->c += v << (8u * (i - 7u));
	}
	mix(&x->a, &x->b, &x->c);
	return x->c;
}

/* ---- step 1 to 3 ----------------------------------------------------------------------------------------- */

wr_status wri_place_hash(const wri_map_pool *p, const wri_oid *o, uint32_t *ps)
{
	const uint8_t *subj;
	uint32_t subj_len, hid;
	uint64_t total;
	hash_acc x;
	uint8_t sep = (uint8_t)SEP_BYTE;

	if (ps == NULL)
		return WR_E_INVAL;
	*ps = 0;
	if (p == NULL || o == NULL)
		return WR_E_INVAL;
	if ((o->name == NULL && o->name_len != 0u) || (o->nspace == NULL && o->nspace_len != 0u) ||
	    (o->key == NULL && o->key_len != 0u))
		return WR_E_INVAL;
	total = (uint64_t)o->name_len + (uint64_t)o->nspace_len + (uint64_t)o->key_len;
	if (total > (uint64_t)WRI_PLACE_NAME_MAX)
		return WR_E_TOOBIG;
	hid = p->object_hash;
	if (hid != WRI_STR_HASH_RJENKINS && hid != WRI_STR_HASH_LINUX)
		return WR_E_POOL_UNSUPPORTED;

	/* The subject is the locator key when there is one, else the name. */
	if (o->key_len != 0u) {
		subj = o->key;
		subj_len = o->key_len;
	} else {
		subj = o->name;
		subj_len = o->name_len;
	}
	if (o->nspace_len == 0u) {
		*ps = wri_str_hash(hid, subj, subj_len, NULL);
		return WR_OK;
	}
	acc_init(&x);
	acc_feed(&x, hid, o->nspace, o->nspace_len);
	acc_feed(&x, hid, &sep, 1u);
	acc_feed(&x, hid, subj, subj_len);
	*ps = acc_done(&x, hid);
	return WR_OK;
}

uint32_t wri_place_pg_seed(const wri_map_pool *p, uint32_t ps)
{
	return wri_stable_mod(ps, p->pg_num, p->pg_num_mask);
}

uint32_t wri_place_pps(const wri_map_pool *p, uint32_t pg_seed)
{
	uint32_t m = wri_stable_mod(pg_seed, p->pgp_num, p->pgp_num_mask);
	uint32_t pool = (uint32_t)p->id; /* an s64 in the map; the hash input and the sum are 32 bit */

	if ((p->flags & (uint64_t)WRI_POOL_F_HASHPSPOOL) != 0u)
		return wri_crush_hash2(m, pool);
	return m + pool;
}

/* ---- steps 3 to 9 ------------------------------------------------------------------------------------------ */

static void copy_list(int32_t *dst, const int32_t *src, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		dst[i] = src[i];
}

/* A failed call leaves a clean result (nothing from a half-finished mapping) and says why. */
static wr_status fail(wri_pg_result *out, wr_errinfo *why, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WR_MEMSET(out, 0, sizeof(*out));
	out->up_primary = -1;
	out->acting_primary = -1;
	WRI_ERRINFO(why, st, WR_MOD_MAP, what, a0, a1, a2);
	return st;
}

/* The pool and the CRUSH region this call works with, or the reason there are none. */
static wr_status pick(const wri_osdmap *m, uint32_t pool_idx, const wri_map_pool **pp, const wri_crush **cp, wri_pg_result *out,
		      wr_errinfo *why)
{
	const wri_map_pool *p;

	if (pool_idx >= m->n_pools || !wri_map_pools(m)[pool_idx].present)
		return fail(out, why, WR_E_POOL_NOT_FOUND, "tracked pool is not in the map", pool_idx, m->n_pools, m->epoch);
	p = &wri_map_pools(m)[pool_idx];
	if (p->status != WR_OK)
		return fail(out, why, p->status, "pool cannot be used by this client", (uint64_t)p->id, 0, m->epoch);
	*cp = wri_map_crush(m);
	if (*cp == NULL)
		return fail(out, why, WR_E_MAP_NONE, "map has no CRUSH region", 0, 0, m->epoch);
	if (p->size == 0u || p->size > WRI_REP_MAX)
		return fail(out, why, WR_E_POOL_UNSUPPORTED, "pool size outside 1 to the replica limit", (uint64_t)p->id, p->size, WRI_REP_MAX);
	*pp = p;
	return WR_OK;
}

/* Steps 5 to 9 on out->raw (already without the OSDs that do not exist). One working list serves all of them: the raw list
 * with the upmap applied, then the up set, then the temp list. */
static void sets(const wri_osdmap *m, uint64_t pgkey, wri_pg_result *out)
{
	int32_t list[WRI_PLACE_LIST_MAX];
	int32_t up_primary = -1, temp_primary = -1;
	uint32_t n = out->n_raw, n_up, n_keep;

	copy_list(list, out->raw, n);
	wri_place_upmap(m, pgkey, list, &n);
	n_up = wri_place_up_set(m, list, n, list, &up_primary);
	wri_place_affinity(m, out->pps, list, n_up, &up_primary);
	n_keep = n_up < WRI_REP_MAX ? n_up : WRI_REP_MAX;
	copy_list(out->up, list, n_keep);
	out->n_up = (uint8_t)n_keep;
	out->up_primary = up_primary;

	wri_place_temp(m, pgkey, list, &n, &temp_primary);
	if (n != 0u) {
		n_keep = n < WRI_REP_MAX ? n : WRI_REP_MAX;
		copy_list(out->acting, list, n_keep);
		out->n_acting = (uint8_t)n_keep;
		out->acting_primary = temp_primary;
	} else {
		copy_list(out->acting, out->up, out->n_up);
		out->n_acting = out->n_up;
		/* a stored primary_temp of -1 says "none", like no entry */
		out->acting_primary = temp_primary != -1 ? temp_primary : up_primary;
	}
}

wr_status wri_place_pg(const wri_osdmap *m, uint32_t pool_idx, uint32_t pg_seed, uint32_t work_max, wri_crush_ws *ws,
		       wri_pg_result *out, wr_errinfo *why)
{
	const wri_map_pool *p = NULL;
	const wri_crush *c = NULL;
	wri_crush_in in;
	uint32_t n = 0;
	wr_status st;

	if (out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	out->up_primary = -1;
	out->acting_primary = -1;
	if (m == NULL || ws == NULL)
		return WR_E_INVAL;
	st = pick(m, pool_idx, &p, &c, out, why);
	if (st != WR_OK)
		return st;

	/* 3 and 4: the seed, then CRUSH straight into the result's raw list (result_max <= WRI_REP_MAX); the OSDs that do not
	 * exist go. */
	out->pps = wri_place_pps(p, pg_seed);
	ws->work = work_max;
	in.rule = p->crush_rule;
	in.x = out->pps;
	in.result_max = p->size;
	in.osd_weight = wri_map_weight(m);
	in.weight_max = m->max_osd;
	in.args_pool = (int32_t)p->id;
	st = wri_crush_do_rule(c, &in, ws, out->raw, &n, why);
	if (st != WR_OK) {
		WR_MEMSET(out, 0, sizeof(*out));
		out->up_primary = -1;
		out->acting_primary = -1;
		return st;
	}
	if (n > WRI_REP_MAX)
		n = WRI_REP_MAX; /* the mapper never returns more than result_max; belt and braces */
	out->n_raw = (uint8_t)wri_place_drop_nonexistent(m, out->raw, n);
	sets(m, wri_pg_key((uint32_t)p->id, pg_seed), out);
	return WR_OK;
}
