/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_dec.c - the CRUSH blob decoder, first half: header, buckets, rules and the driver.
 *
 * Written from docs/spec/crush-and-placement.md 2.2 to 2.5 and docs/design/core-architecture.md 16.1. One forward
 * pass over the blob; the compact region is built in the room the caller gives, at the pace the blob is read (a
 * bump allocator, so a failure at any point leaves the rest of the room untouched and nothing is ever written
 * past `cap`). The header's magic stays 0 until the very end: a region that was not finished never passes
 * wri_crush_check. Everything after the rules is wri_crush_dec2.c.
 */
#include "wri_crush.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define WRI_CRUSH_STRAW2_WEIGHT_MAX 0x80000000u /* a weight at or above this is refused (negative divisor in the reference) */

/* ---- shared helpers (declared in wri_crush.h) ----------------------------------------------------------- */

wr_status wri_crush_dec_fail(wri_crush_dctx *c, wr_status st, const char *what, size_t off, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(c->why, st, WR_MOD_CRUSH, what, off, a1, a2);
	return st;
}

wr_status wri_crush_dec_rd_fail(wri_crush_dctx *c, const char *what)
{
	return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, what, c->r.pos, (uint64_t)(c->r.len - c->r.pos), 0);
}

uint8_t *wri_crush_dec_alloc(wri_crush_dctx *c, uint64_t n, const char *what)
{
	uint8_t *p;

	if (n > (uint64_t)(c->cap - c->pos)) {
		(void)wri_crush_dec_fail(c, WR_E_MAP_BUDGET, what, c->r.pos, (uint64_t)c->pos + n, (uint64_t)c->cap);
		return NULL;
	}
	p = c->out + c->pos;
	c->pos += (size_t)n;
	return p;
}

/* ---- buckets (2.2 rows 5a to 5i) ------------------------------------------------------------------------- */

/* One item of a bucket: a device id (tracked for max_devices) or a bucket slot below max_buckets. */
static wr_status dec_item(wri_crush_dctx *c, size_t at, int32_t it, uint32_t index)
{
	if (it >= 0) {
		if (it >= WRI_CRUSH_ITEM_UNDEF)
			return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket item is a reserved device id", at, (uint64_t)index,
						  (uint64_t)(uint32_t)it);
		if ((int64_t)it + 1 > c->max_dev)
			c->max_dev = (int64_t)it + 1;
		return WR_OK;
	}
	if ((uint32_t)(-1 - it) >= c->max_buckets)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket item names a slot beyond max_buckets", at, (uint64_t)index,
					  (uint64_t)(uint32_t)it);
	return WR_OK;
}

/* Bytes of the algorithm tail on the wire (the fixed part; a tree adds 4 per node) and in the compact record. */
static void tail_sizes(uint32_t alg, uint32_t size, uint64_t *wire, uint64_t *kept)
{
	switch (alg) {
	case WRI_CRUSH_ALG_UNIFORM:
		*wire = 4;
		*kept = 0;
		break;
	case WRI_CRUSH_ALG_LIST:
		*wire = 8u * (uint64_t)size;
		*kept = 8u * (uint64_t)size;
		break;
	case WRI_CRUSH_ALG_TREE:
		*wire = 1;
		*kept = 0;
		break;
	case WRI_CRUSH_ALG_STRAW:
		*wire = 8u * (uint64_t)size;
		*kept = 4u * (uint64_t)size;
		break;
	default: /* straw2 */
		*wire = 4u * (uint64_t)size;
		*kept = 4u * (uint64_t)size;
		break;
	}
}

/* The algorithm tail: keep only what mapping reads, in host order. `w` is the first u32 array after the items. */
static wr_status dec_tail_arrays(wri_crush_dctx *c, uint8_t *w, uint32_t alg, uint32_t size, size_t at)
{
	uint32_t i, v, v2;

	switch (alg) {
	case WRI_CRUSH_ALG_UNIFORM:
		(void)wri_rd_u32(&c->r); /* the one item weight: mapping never reads it */
		break;
	case WRI_CRUSH_ALG_TREE: {
		uint32_t nodes = wri_rd_u8(&c->r); /* node_weights are not kept: a mapping that reaches a tree bucket fails */

		wri_rd_skip(&c->r, 4u * (size_t)nodes);
		break;
	}
	case WRI_CRUSH_ALG_STRAW:
		for (i = 0; i < size; i++) {
			(void)wri_rd_u32(&c->r); /* item weight: dropped */
			wri_crush_put32(w + 4u * (size_t)i, wri_rd_u32(&c->r));
		}
		break;
	case WRI_CRUSH_ALG_LIST:
		for (i = 0; i < size; i++) {
			v = wri_rd_u32(&c->r);
			v2 = wri_rd_u32(&c->r);
			wri_crush_put32(w + 4u * (size_t)i, v);
			wri_crush_put32(w + 4u * (size_t)size + 4u * (size_t)i, v2);
		}
		break;
	default: /* straw2 */
		for (i = 0; i < size; i++) {
			v = wri_rd_u32(&c->r);
			if (v >= WRI_CRUSH_STRAW2_WEIGHT_MAX)
				return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "straw2 weight of 0x80000000 or more", at, i, v);
			wri_crush_put32(w + 4u * (size_t)i, v);
		}
		break;
	}
	return wri_rd_ok(&c->r) ? WR_OK : wri_crush_dec_rd_fail(c, "bucket algorithm tail truncated");
}

static wr_status dec_bucket(wri_crush_dctx *c, uint32_t slot)
{
	size_t at = c->r.pos;
	uint32_t marker = wri_rd_u32(&c->r), size, i, alg;
	int32_t id;
	uint64_t wire_tail, kept_tail;
	uint16_t type;
	uint8_t alg8, hash;
	wri_cbucket head;
	uint8_t *rec;
	wr_status st;

	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "bucket marker truncated");
	if (marker == 0)
		return WR_OK; /* a hole: the slot stays 0 in bucket_tab */
	if (marker > WRI_CRUSH_ALG_STRAW2)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "unknown bucket algorithm", at, slot, marker);
	id = wri_rd_i32(&c->r);
	type = wri_rd_u16(&c->r);
	alg8 = wri_rd_u8(&c->r);
	hash = wri_rd_u8(&c->r);
	(void)wri_rd_u32(&c->r); /* total weight: straw2 and the others never read it (the parent holds the item weight) */
	size = wri_rd_u32(&c->r);
	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "bucket header truncated");
	alg = alg8;
	if (alg != marker)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket algorithm marker differs from its alg byte", at, marker, alg);
	if ((int64_t)id != -1 - (int64_t)slot)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket id does not match its slot", at, (uint64_t)(uint32_t)id, slot);
	if (hash != 0)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket hash is not rjenkins1 (0)", at, hash, slot);
	if (size > WRI_CRUSH_MAX_BUCKET_SIZE)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket has too many items", at, size, WRI_CRUSH_MAX_BUCKET_SIZE);
	tail_sizes(alg, size, &wire_tail, &kept_tail);
	if ((uint64_t)wri_rd_left(&c->r) < 4u * (uint64_t)size + wire_tail)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bucket items and tail run past the end of the blob", at, size,
					  (uint64_t)wri_rd_left(&c->r));

	rec = wri_crush_dec_alloc(c, 16u + 4u * (uint64_t)size + kept_tail, "bucket record");
	if (rec == NULL)
		return WR_E_MAP_BUDGET;
	WR_MEMSET(&head, 0, sizeof(head));
	head.id = id;
	head.type = type;
	head.alg = alg8;
	head.hash = 0;
	head.size = size;
	WR_MEMCPY(rec, &head, sizeof(head));
	for (i = 0; i < size; i++) {
		int32_t it = wri_rd_i32(&c->r);

		st = dec_item(c, at, it, i);
		if (st != WR_OK)
			return st;
		wri_crush_put32(rec + 16u + 4u * (size_t)i, (uint32_t)it);
	}
	st = dec_tail_arrays(c, rec + 16u + 4u * (size_t)size, alg, size, at);
	if (st != WR_OK)
		return st;
	wri_crush_put32(c->out + WRI_CRUSH_HDR_BYTES + 4u * (size_t)slot, (uint32_t)(rec - c->out));
	return WR_OK;
}

/* ---- rules (2.2 rows 6a to 6g) ----------------------------------------------------------------------------- */

static wr_status dec_rule(wri_crush_dctx *c, uint32_t slot)
{
	size_t at = c->r.pos;
	uint32_t present = wri_rd_u32(&c->r), len, i;
	uint8_t ruleset, type;
	uint8_t *rec;
	uint8_t *rtab = c->out + WRI_CRUSH_HDR_BYTES + 4u * (size_t)c->max_buckets + 4u * (size_t)slot;

	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "rule flag truncated");
	if (present == 0)
		return WR_OK;
	len = wri_rd_u32(&c->r);
	ruleset = wri_rd_u8(&c->r);
	type = wri_rd_u8(&c->r);
	(void)wri_rd_u8(&c->r); /* min_size and max_size: ignored by the mapper, any stored values are fine */
	(void)wri_rd_u8(&c->r);
	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "rule header truncated");
	if (ruleset != slot)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "rule ruleset differs from its slot", at, ruleset, slot);
	if (len > WRI_CRUSH_MAX_STEPS)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "rule has too many steps", at, len, WRI_CRUSH_MAX_STEPS);
	if ((uint64_t)wri_rd_left(&c->r) < 12u * (uint64_t)len)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "rule steps run past the end of the blob", at, len,
					  (uint64_t)wri_rd_left(&c->r));
	if (type != WRI_CRUSH_RULE_REPLICATED) {
		wri_rd_skip(&c->r, 12u * (size_t)len); /* not stored: the audit reports it for a pool that uses it */
		wri_crush_put32(rtab, WRI_CRUSH_RULE_OTHER);
		return WR_OK;
	}
	rec = wri_crush_dec_alloc(c, 4u + 12u * (uint64_t)len, "rule record");
	if (rec == NULL)
		return WR_E_MAP_BUDGET;
	wri_crush_put32(rec, len);
	for (i = 0; i < len; i++) {
		wri_cstep s;

		s.op = wri_rd_u32(&c->r); /* opcodes are judged by the audit, against the pool that uses the rule */
		s.arg1 = wri_rd_i32(&c->r);
		s.arg2 = wri_rd_i32(&c->r);
		WR_MEMCPY(rec + 4u + 12u * (size_t)i, &s, sizeof(s));
	}
	wri_crush_put32(rtab, (uint32_t)(rec - c->out));
	return WR_OK;
}

/* ---- the driver ------------------------------------------------------------------------------------------- */

static wr_status dec_header(wri_crush_dctx *c)
{
	uint32_t magic = wri_rd_u32(&c->r);
	int32_t max_buckets = wri_rd_i32(&c->r);
	uint32_t max_rules = wri_rd_u32(&c->r);
	uint64_t slots_min;
	uint8_t *p;
	wri_crush h;

	(void)wri_rd_i32(&c->r); /* max_devices on the wire: recomputed at the end */
	if (!wri_rd_ok(&c->r))
		return wri_crush_dec_rd_fail(c, "header truncated");
	if (magic != WRI_CRUSH_MAGIC_WIRE)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "bad magic", 0, magic, WRI_CRUSH_MAGIC_WIRE);
	if (max_buckets < 0 || (uint32_t)max_buckets > WRI_CRUSH_MAX_BUCKETS)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "too many bucket slots", 4, (uint64_t)(uint32_t)max_buckets,
					  WRI_CRUSH_MAX_BUCKETS);
	if (max_rules > WRI_CRUSH_MAX_RULES)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "too many rule slots", 8, max_rules, WRI_CRUSH_MAX_RULES);
	c->max_buckets = (uint32_t)max_buckets;
	c->max_rules = max_rules;
	/* every slot takes at least its 4-byte marker: a blob shorter than that cannot hold the slots it announces */
	slots_min = 4u * ((uint64_t)c->max_buckets + c->max_rules);
	if ((uint64_t)wri_rd_left(&c->r) < slots_min)
		return wri_crush_dec_fail(c, WR_E_CRUSH_ENCODING, "blob too short for the announced slots", 4, c->max_buckets,
					  c->max_rules);
	p = wri_crush_dec_alloc(c, WRI_CRUSH_HDR_BYTES + slots_min, "header and slot tables");
	if (p == NULL)
		return WR_E_MAP_BUDGET;
	WR_MEMSET(p, 0, WRI_CRUSH_HDR_BYTES + (size_t)slots_min);
	WR_MEMSET(&h, 0, sizeof(h));
	h.max_buckets = c->max_buckets;
	h.max_rules = c->max_rules;
	h.bucket_tab = WRI_CRUSH_HDR_BYTES;
	h.rule_tab = WRI_CRUSH_HDR_BYTES + 4u * c->max_buckets;
	WR_MEMCPY(p, &h, sizeof(h)); /* magic and bytes stay 0 until the region is complete */
	return WR_OK;
}

wr_status wri_crush_decode(const uint8_t *blob, size_t n, uint8_t *out, size_t cap, size_t *used, wr_errinfo *why)
{
	wri_crush_dctx c;
	wri_crush h;
	wr_status st;
	uint32_t i;
	uint64_t cap64 = cap;

	if (used != NULL)
		*used = 0;
	if (used == NULL || out == NULL || (blob == NULL && n != 0) || ((size_t)(uintptr_t)out & 7u) != 0) {
		WRI_ERRINFO(why, WR_E_INVAL, WR_MOD_CRUSH, "bad argument (null pointer or room not 8-byte aligned)", 0, 0, 0);
		return WR_E_INVAL;
	}
	WR_MEMSET(&c, 0, sizeof(c));
	wri_rd_init(&c.r, blob, n);
	c.out = out;
	c.cap = cap64 > 0xffffffffu ? (size_t)0xffffffffu : cap; /* offsets are u32 */
	c.why = why;
	c.tun.choose_local_tries = 2; /* the legacy defaults of 2.5, kept by every group the blob does not carry */
	c.tun.choose_local_fallback_tries = 5;
	c.tun.choose_total_tries = 19;

	st = dec_header(&c);
	for (i = 0; st == WR_OK && i < c.max_buckets; i++)
		st = dec_bucket(&c, i);
	for (i = 0; st == WR_OK && i < c.max_rules; i++)
		st = dec_rule(&c, i);
	if (st == WR_OK)
		st = wri_crush_dec_tail(&c);
	if (st != WR_OK)
		return st;

	WR_MEMSET(&h, 0, sizeof(h));
	h.magic = WRI_CRUSH_MAGIC;
	h.bytes = (uint32_t)c.pos;
	h.max_buckets = c.max_buckets;
	h.max_rules = c.max_rules;
	h.max_devices = (int32_t)c.max_dev; /* below 0x7ffffffe: every contributor is range-checked */
	h.bucket_tab = WRI_CRUSH_HDR_BYTES;
	h.rule_tab = WRI_CRUSH_HDR_BYTES + 4u * c.max_buckets;
	h.n_sets = c.n_sets;
	h.set_tab = c.set_tab;
	h.tun = c.tun;
	WR_MEMCPY(out, &h, sizeof(h));
	*used = c.pos;
	return WR_OK;
}
