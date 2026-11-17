/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_dec2.c - the CRUSH blob decoder, second half: everything after the rules (names, tunables, device
 * classes, choose_args, the MSR pair, the trailing-bytes rule), and the structural self-check of a compact region.
 *
 * Written from docs/spec/crush-and-placement.md 2.2 (rows 7 to 20), 2.4 and 4.3, and docs/design/core-architecture.md
 * 16.1. The first half, which also owns the shared helpers, is wri_crush_dec.c.
 */
#include "wri_crush.h"

WR_FILE_LICENCE_MIT

#define WEIGHT_MAX 0x80000000u /* straw2 and weight-set weights at or above this are refused */

/* ---- names (rows 7 to 9) ---------------------------------------------------------------------------------- */

/*
 * type_map, name_map and rule_name_map are walked, never stored. A zero length is followed by the real length (an old
 * encoder wrote the key as 64 bits, so the upper half of the key reads as a zero length). Only the keys of name_map
 * matter afterwards: they raise max_devices (2.4 item 1). The keys of the other two maps are not device ids.
 */
static wr_status skip_names(wri_crush_dctx *c, int is_name_map)
{
	uint32_t n = wri_rd_count(&c->r, 0xffffffffu, 8), i;

	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "name map count truncated or beyond the data left");
	for (i = 0; i < n; i++) {
		int32_t key = wri_rd_i32(&c->r);
		uint32_t len = wri_rd_u32(&c->r);

		if (len == 0)
			len = wri_rd_u32(&c->r);
		wri_rd_skip(&c->r, (size_t)len);
		if (!wri_rd_ok(&c->r))
			return wri_crush_dec_rd_fail(c, "name map entry truncated");
		if (!is_name_map || key < 0)
			continue;
		if (key >= WRI_CRUSH_ITEM_UNDEF)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "name_map key is a reserved device id", c->r.pos, i,
						  (uint64_t)(uint32_t)key);
		if ((int64_t)key + 1 > c->max_dev)
			c->max_dev = (int64_t)key + 1;
	}
	return WR_OK;
}

/* ---- tunables (rows 10 to 15) ------------------------------------------------------------------------------ */

/* Each group is present only if bytes remain; a group cut short is truncation. Absent ones keep the legacy defaults. */
static wr_status dec_tunables(wri_crush_dctx *c)
{
	wri_rd *r = &c->r;

	if (wri_rd_left(r) != 0) {
		c->tun.choose_local_tries = wri_rd_u32(r);
		c->tun.choose_local_fallback_tries = wri_rd_u32(r);
		c->tun.choose_total_tries = wri_rd_u32(r);
	}
	if (wri_rd_left(r) != 0)
		c->tun.chooseleaf_descend_once = wri_rd_u32(r);
	if (wri_rd_left(r) != 0)
		c->tun.chooseleaf_vary_r = wri_rd_u8(r);
	if (wri_rd_left(r) != 0)
		(void)wri_rd_u8(r); /* straw_calc_version: only used when building straw buckets */
	if (wri_rd_left(r) != 0)
		(void)wri_rd_u32(r); /* allowed_bucket_algs: irrelevant to mapping */
	if (wri_rd_left(r) != 0)
		c->tun.chooseleaf_stable = wri_rd_u8(r);
	if (!wri_rd_ok(r))
		return wri_crush_dec_rd_fail(c, "tunables truncated");
	if (c->tun.chooseleaf_vary_r > WRI_CRUSH_VARY_R_MAX)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "chooseleaf_vary_r above 32", r->pos, c->tun.chooseleaf_vary_r,
					  WRI_CRUSH_VARY_R_MAX);
	return WR_OK;
}

/* ---- device classes (rows 16 to 18): walked and dropped --------------------------------------------------- */

static wr_status skip_classes(wri_crush_dctx *c)
{
	wri_rd *r = &c->r;
	uint32_t n, i, m;

	n = wri_rd_count(r, 0xffffffffu, 8); /* class_map: {item, class} */
	wri_rd_skip(r, 8u * (size_t)n);
	n = wri_rd_count(r, 0xffffffffu, 8); /* class_name: {class, string} */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		wri_rd_skip(r, 4);
		wri_rd_skip(r, (size_t)wri_rd_u32(r));
	}
	n = wri_rd_count(r, 0xffffffffu, 8); /* class_bucket: {bucket, {class, shadow bucket}[m]} */
	for (i = 0; i < n && wri_rd_ok(r); i++) {
		wri_rd_skip(r, 4);
		m = wri_rd_count(r, 0xffffffffu, 8);
		wri_rd_skip(r, 8u * (size_t)m);
	}
	return wri_rd_ok(r) ? WR_OK : wri_crush_dec_rd_fail(c, "device class maps truncated or a count beyond the data left");
}

/* ---- choose_args (rows 19 to 19g), strictly ---------------------------------------------------------------- */

/*
 * One listed bucket of a set: weight rows (each exactly the bucket's size) and substitute ids (none or the bucket's size).
 * `index` is the set's index table, or NULL to validate only (nothing is written, no room is used).
 */
static wr_status dec_args_bucket(wri_crush_dctx *c, uint8_t *index, size_t at)
{
	uint32_t bi = wri_rd_u32(&c->r), npos = wri_rd_u32(&c->r), size, k, l, ids_size, w;
	const wri_cbucket *b;
	uint8_t *rec = NULL, *ids;

	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "choose_args bucket entry truncated");
	if (bi >= c->max_buckets)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args bucket index beyond max_buckets", at, bi, c->max_buckets);
	b = wri_crush_bucket_at((const wri_crush *)(const void *)c->out, bi);
	if (b == NULL || b->alg != WRI_CRUSH_ALG_STRAW2)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args for a bucket that is not straw2", at, bi,
					  b == NULL ? 0u : b->alg);
	if (index != NULL && wri_crush_get32(index + 4u * (size_t)bi) != 0)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args lists a bucket twice", at, bi, 0);
	size = b->size;
	if ((uint64_t)npos * (4u + 4u * (uint64_t)size) > (uint64_t)wri_rd_left(&c->r))
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "weight rows run past the end of the blob", at, npos, size);
	if (index != NULL) {
		rec = wri_crush_dec_alloc(c, 8u + 4u * (uint64_t)npos * size, "choose_args record");
		if (rec == NULL)
			return WR_E_MAP_BUDGET;
		wri_crush_put32(rec, npos);
		wri_crush_put32(rec + 4, 0);
	}
	for (k = 0; k < npos; k++) {
		uint32_t sz = wri_rd_u32(&c->r);

		if (sz != size)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "weight row length differs from the bucket size", at, sz, size);
		for (l = 0; l < size; l++) {
			w = wri_rd_u32(&c->r);
			if (w >= WEIGHT_MAX)
				return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "weight-set weight of 0x80000000 or more", at, l, w);
			if (rec != NULL)
				wri_crush_put32(rec + 8u + 4u * ((size_t)k * size + l), w);
		}
	}
	ids_size = wri_rd_u32(&c->r);
	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "choose_args row or ids size truncated");
	if (ids_size != 0) {
		if (ids_size != size)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args ids size differs from the bucket size", at, ids_size,
						  size);
		if ((uint64_t)wri_rd_left(&c->r) < 4u * (uint64_t)size)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args ids run past the end of the blob", at, size,
						  (uint64_t)wri_rd_left(&c->r));
		if (rec != NULL) {
			ids = wri_crush_dec_alloc(c, 4u * (uint64_t)size, "choose_args ids"); /* directly behind the rows */
			if (ids == NULL)
				return WR_E_MAP_BUDGET;
			for (l = 0; l < size; l++)
				wri_crush_put32(ids + 4u * (size_t)l, wri_rd_u32(&c->r));
			wri_crush_put32(rec + 4, 1);
		} else {
			wri_rd_skip(&c->r, 4u * (size_t)size);
		}
	}
	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "choose_args ids truncated");
	if (rec != NULL)
		wri_crush_put32(index + 4u * (size_t)bi, (uint32_t)(rec - c->out));
	return WR_OK;
}

/*
 * One pass over the `count` sets. Keys must ascend strictly (the monitor's encoder walks an ordered map; this also rules
 * out duplicates without a quadratic search). A set whose key does not fit an s32 can never match a pool: it is validated
 * and not kept. dry: validate everything, use no room, count the kept sets into *kept. Otherwise build the kept sets and
 * fill `tab` (the set table); the dry pass has already proved the group well formed, so only a lack of room or a bucket
 * listed twice can fail here.
 */
static wr_status args_pass(wri_crush_dctx *c, uint32_t count, int dry, uint32_t *kept, uint8_t *tab)
{
	uint32_t i, j, nb;
	size_t at;
	uint8_t *index;
	int64_t key = 0, prev = 0;
	wr_status st;

	for (i = 0; i < count; i++) {
		int keep, build;

		at = c->r.pos;
		key = wri_rd_i64(&c->r);
		nb = wri_rd_u32(&c->r);
		if (!wri_rd_ok(&c->r))
			return wri_crush_dec_rd_fail(c, "choose_args set header truncated");
		if (i > 0 && key <= prev)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args set keys not strictly ascending", at, (uint64_t)key,
						  (uint64_t)prev);
		prev = key;
		if ((uint64_t)nb * 12u > (uint64_t)wri_rd_left(&c->r))
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "choose_args bucket count exceeds the data left", at, nb,
						  (uint64_t)wri_rd_left(&c->r));
		keep = key >= -2147483647 - 1 && key <= 2147483647;
		build = keep && !dry;
		index = NULL;
		if (build) {
			index = wri_crush_dec_alloc(c, 4u * (uint64_t)c->max_buckets, "choose_args index table");
			if (index == NULL)
				return WR_E_MAP_BUDGET;
			WR_MEMSET(index, 0, 4u * (size_t)c->max_buckets);
		}
		for (j = 0; j < nb; j++) {
			st = dec_args_bucket(c, index, at);
			if (st != WR_OK)
				return st;
		}
		if (!keep)
			continue;
		if (dry) {
			(*kept)++;
		} else {
			wri_cargs_set e;

			e.pool = (int32_t)key;
			e.index = (uint32_t)(index - c->out);
			WR_MEMCPY(tab + 8u * (size_t)c->n_sets, &e, sizeof(e));
			c->n_sets++;
		}
	}
	return WR_OK;
}

static wr_status dec_args(wri_crush_dctx *c)
{
	uint32_t count = wri_rd_count(&c->r, 0xffffffffu, 12), kept = 0;
	size_t save;
	uint8_t *tab;
	wr_status st;

	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "choose_args set count truncated or beyond the data left");
	if (count == 0)
		return WR_OK;
	save = c->r.pos;
	st = args_pass(c, count, 1, &kept, NULL);
	if (st != WR_OK || kept == 0)
		return st; /* nothing to keep: the region carries no set (and no set table) */
	c->r.pos = save;
	tab = wri_crush_dec_alloc(c, 8u * (uint64_t)kept, "choose_args set table");
	if (tab == NULL)
		return WR_E_MAP_BUDGET;
	WR_MEMSET(tab, 0, 8u * (size_t)kept);
	c->set_tab = (uint32_t)(tab - c->out);
	return args_pass(c, count, 0, NULL, tab);
}

/* ---- the groups after the rules, in wire order -------------------------------------------------------------- */

wr_status wri_crush_dec_tail(wri_crush_dctx *c)
{
	wr_status st;

	st = skip_names(c, 0); /* type_map */
	if (st == WR_OK)
		st = skip_names(c, 1); /* name_map */
	if (st == WR_OK)
		st = skip_names(c, 0); /* rule_name_map */
	if (st == WR_OK)
		st = dec_tunables(c);
	if (st == WR_OK && wri_rd_left(&c->r) != 0)
		st = skip_classes(c);
	if (st == WR_OK && wri_rd_left(&c->r) != 0)
		st = dec_args(c);
	if (st == WR_OK && wri_rd_left(&c->r) != 0) {
		(void)wri_rd_u32(&c->r); /* msr_descents and msr_collision_tries: irrelevant to firstn rules */
		(void)wri_rd_u32(&c->r);
		if (!wri_rd_ok(&c->r))
			st = wri_crush_dec_rd_fail(c, "MSR tunable pair truncated");
	}
	if (st == WR_OK && wri_rd_left(&c->r) != 0)
		st = wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "trailing bytes", c->r.pos, (uint64_t)wri_rd_left(&c->r), 0);
	return st;
}

/* ---- the structural self-check -------------------------------------------------------------------------------- */

static int span_ok(uint64_t bytes, uint32_t off, uint64_t len)
{
	return off >= WRI_CRUSH_HDR_BYTES && (off & 3u) == 0 && (uint64_t)off + len <= bytes;
}

static const wri_cbucket *chk_bucket_ptr(const wri_crush *c, uint32_t off)
{
	return (const wri_cbucket *)(const void *)((const uint8_t *)c + off);
}

static wr_status chk_bucket(const wri_crush *c, uint64_t bytes, uint32_t slot, uint32_t off)
{
	const wri_cbucket *b;
	const int32_t *it;
	uint64_t kept;
	uint32_t i;

	if (!span_ok(bytes, off, sizeof(wri_cbucket)))
		return WR_E_CRUSH_ENCODING;
	b = chk_bucket_ptr(c, off);
	if ((int64_t)b->id != -1 - (int64_t)slot || b->alg < WRI_CRUSH_ALG_UNIFORM || b->alg > WRI_CRUSH_ALG_STRAW2 || b->hash != 0 ||
	    b->reserved != 0 || b->size > WRI_CRUSH_MAX_BUCKET_SIZE)
		return WR_E_CRUSH_ENCODING;
	kept = b->alg == WRI_CRUSH_ALG_LIST ? 8u * (uint64_t)b->size
	       : (b->alg == WRI_CRUSH_ALG_STRAW || b->alg == WRI_CRUSH_ALG_STRAW2) ? 4u * (uint64_t)b->size : 0u;
	if (!span_ok(bytes, off, sizeof(wri_cbucket) + 4u * (uint64_t)b->size + kept))
		return WR_E_CRUSH_ENCODING;
	it = wri_cbucket_items(b);
	for (i = 0; i < b->size; i++) {
		if (it[i] >= 0 ? (it[i] >= WRI_CRUSH_ITEM_UNDEF || it[i] >= c->max_devices) : (uint32_t)(-1 - it[i]) >= c->max_buckets)
			return WR_E_CRUSH_ENCODING;
		if (b->alg == WRI_CRUSH_ALG_STRAW2 && wri_cbucket_w(b)[i] >= WEIGHT_MAX)
			return WR_E_CRUSH_ENCODING;
	}
	return WR_OK;
}

static wr_status chk_rule(const wri_crush *c, uint64_t bytes, uint32_t off)
{
	const wri_crule *r;

	if (off == 0 || off == WRI_CRUSH_RULE_OTHER)
		return WR_OK;
	if (!span_ok(bytes, off, sizeof(wri_crule)))
		return WR_E_CRUSH_ENCODING;
	r = (const wri_crule *)(const void *)((const uint8_t *)c + off);
	if (r->nsteps > WRI_CRUSH_MAX_STEPS || !span_ok(bytes, off, sizeof(wri_crule) + 12u * (uint64_t)r->nsteps))
		return WR_E_CRUSH_ENCODING;
	return WR_OK;
}

/* One set: its index table and every override it lists (straw2 bucket, row length and ids per the bucket's size). */
static wr_status chk_set(const wri_crush *c, uint64_t bytes, uint32_t index_off)
{
	uint32_t slot, k, l;

	if (!span_ok(bytes, index_off, 4u * (uint64_t)c->max_buckets))
		return WR_E_CRUSH_ENCODING;
	for (slot = 0; slot < c->max_buckets; slot++) {
		uint32_t off = wri_crush_words(c, index_off)[slot];
		const wri_cbucket *b;
		const wri_cargs *a;
		const uint32_t *row;

		if (off == 0)
			continue;
		b = wri_crush_bucket_at(c, slot);
		if (b == NULL || b->alg != WRI_CRUSH_ALG_STRAW2 || !span_ok(bytes, off, sizeof(wri_cargs)))
			return WR_E_CRUSH_ENCODING;
		a = (const wri_cargs *)(const void *)((const uint8_t *)c + off);
		if (a->has_ids > 1 ||
		    !span_ok(bytes, off, sizeof(wri_cargs) + 4u * (uint64_t)a->n_pos * b->size + (a->has_ids ? 4u * (uint64_t)b->size : 0u)))
			return WR_E_CRUSH_ENCODING;
		/* an empty bucket has no weights to look at: its rows cost no bytes, so n_pos is not bounded by the span check above
		 * and a corrupted count must not turn into a four-billion-pass loop */
		for (k = 0; b->size != 0 && k < a->n_pos; k++) {
			row = wri_cargs_row(a, b->size, k);
			for (l = 0; l < b->size; l++)
				if (row[l] >= WEIGHT_MAX)
					return WR_E_CRUSH_ENCODING;
		}
	}
	return WR_OK;
}

wr_status wri_crush_check(const wri_crush *c, size_t bytes)
{
	uint64_t lim;
	uint32_t i;
	const wri_cargs_set *s;

	if (c == NULL || ((size_t)(uintptr_t)c & 3u) != 0 || bytes < WRI_CRUSH_HDR_BYTES || c->magic != WRI_CRUSH_MAGIC)
		return WR_E_CRUSH_ENCODING;
	lim = c->bytes;
	if (lim < WRI_CRUSH_HDR_BYTES || lim > (uint64_t)bytes || c->max_buckets > WRI_CRUSH_MAX_BUCKETS || c->max_rules > WRI_CRUSH_MAX_RULES ||
	    c->max_devices < 0 || c->tun.chooseleaf_vary_r > WRI_CRUSH_VARY_R_MAX)
		return WR_E_CRUSH_ENCODING;
	if (!span_ok(lim, c->bucket_tab, 4u * (uint64_t)c->max_buckets) || !span_ok(lim, c->rule_tab, 4u * (uint64_t)c->max_rules))
		return WR_E_CRUSH_ENCODING;
	for (i = 0; i < c->max_buckets; i++) {
		uint32_t off = wri_crush_words(c, c->bucket_tab)[i];

		if (off != 0 && chk_bucket(c, lim, i, off) != WR_OK)
			return WR_E_CRUSH_ENCODING;
	}
	for (i = 0; i < c->max_rules; i++)
		if (chk_rule(c, lim, wri_crush_words(c, c->rule_tab)[i]) != WR_OK)
			return WR_E_CRUSH_ENCODING;
	if (c->n_sets == 0)
		return c->set_tab == 0 ? WR_OK : WR_E_CRUSH_ENCODING;
	if (!span_ok(lim, c->set_tab, 8u * (uint64_t)c->n_sets))
		return WR_E_CRUSH_ENCODING;
	s = (const wri_cargs_set *)(const void *)((const uint8_t *)c + c->set_tab);
	for (i = 0; i < c->n_sets; i++) {
		if ((i > 0 && s[i].pool <= s[i - 1u].pool) || chk_set(c, lim, s[i].index) != WR_OK)
			return WR_E_CRUSH_ENCODING;
	}
	return WR_OK;
}
