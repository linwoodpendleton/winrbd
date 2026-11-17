/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_buck.c - the straw2 and straw bucket choosers (docs/spec/crush-and-placement.md 3.4.1, 3.4.2, 3.4.3), and the
 * dispatch of the rule interpreter to the choosers of every algorithm together with the work budget and the out test.
 *
 * Both read only the compact bucket record and the optional choose_args override, keep no state and touch
 * no memory outside the record. An empty bucket (size 0) has no item to give: both return WRI_CRUSH_ITEM_NONE
 * so a caller that forgot the emptiness test still gets a value the interpreter refuses (no device has that
 * id), never a read past the item array.
 */
#include "wri_crush_buck.h"
#include "wri_crush_hash.h"
#include "wri_crush_ln.h"
#include "wri_ctx.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define WRI_IN_WEIGHT 0x10000u /* an OSD weight of this or more is "in" */
#define WRI_CRUSH_LN_ONE 0x1000000000000ull /* 2^48: crush_ln(u) is below it for every 16-bit u, so the draw numerator is <= 0 */
#define WRI_CRUSH_DRAW_NEVER (-0x7fffffffffffffffll - 1ll) /* "minus infinity": the draw of a weight 0 item */

int32_t wri_crush_choose_straw2(const wri_cbucket *b, uint32_t x, uint32_t r, const wri_cargs *args, uint32_t position)
{
	const int32_t *items = wri_cbucket_items(b);
	const uint32_t *w = wri_cbucket_w(b);
	const int32_t *ids;
	const uint32_t *row;
	uint32_t i, best = 0;
	int64_t best_draw = WRI_CRUSH_DRAW_NEVER;

	if (b->size == 0)
		return WRI_CRUSH_ITEM_NONE;
	/* An override can replace the weights (row min(position, rows - 1)) and the ids that go into the hash; the item
	 * that is returned is always the real one. An override without weight rows keeps the bucket's own weights. */
	row = wri_cargs_row(args, b->size, position);
	if (row != NULL)
		w = row;
	ids = wri_cargs_ids(args, b->size);
	if (ids == NULL)
		ids = items;

	for (i = 0; i < b->size; i++) {
		int64_t draw;

		if (w[i] == 0u) {
			draw = WRI_CRUSH_DRAW_NEVER; /* never above the initial value, so it never displaces the current best */
		} else {
			uint32_t u = wri_crush_hash3(x, (uint32_t)ids[i], r) & 0xffffu;
			int64_t ln = -(int64_t)(WRI_CRUSH_LN_ONE - wri_crush_ln(u)); /* crush_ln(u) < 2^48, so the numerator is negative, -2^48 .. -2^28 */

			draw = wri_div_s64_u32(ln, w[i]);
		}
		if (draw > best_draw) { /* strictly greater: the first of equal draws wins; index 0 stays when all weights are 0 */
			best = i;
			best_draw = draw;
		}
	}
	return items[best];
}

int32_t wri_crush_choose_straw(const wri_cbucket *b, uint32_t x, uint32_t r)
{
	const int32_t *items = wri_cbucket_items(b);
	const uint32_t *straws = wri_cbucket_w(b);
	uint32_t i, best = 0;
	uint64_t best_draw = 0;

	if (b->size == 0)
		return WRI_CRUSH_ITEM_NONE;
	for (i = 0; i < b->size; i++) {
		uint64_t draw = (uint64_t)(wri_crush_hash3(x, (uint32_t)items[i], r) & 0xffffu) * straws[i];

		if (i == 0u || draw > best_draw) {
			best = i;
			best_draw = draw;
		}
	}
	return items[best];
}

/* ---- the dispatch and the work budget -------------------------------------------------------------------------------- */

wr_status wri_mapx_fail(const wri_mapx *k, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(k->why, st, WR_MOD_CRUSH, what, a0, a1, a2);
	return st;
}

wr_status wri_mapx_charge(const wri_mapx *k, const wri_cbucket *b)
{
	uint32_t cost = b->size == 0u ? 1u : b->size;

	if (k->ws->work < cost) {
		k->ws->work = 0;
		return wri_mapx_fail(k, WR_E_CRUSH_WORK, "work budget spent", (uint64_t)(uint32_t)b->id, b->size, 0);
	}
	k->ws->work -= cost;
	return WR_OK;
}

wr_status wri_mapx_draw(const wri_mapx *k, const wri_cbucket *b, uint32_t r, uint32_t position, int use_perm, int32_t *item)
{
	wr_status st = wri_mapx_charge(k, b);

	if (st != WR_OK)
		return st;
	if (use_perm) {
		st = wri_crush_choose_perm(b, k->in->x, r, k->ws->perm, item);
	} else {
		switch (b->alg) {
		case WRI_CRUSH_ALG_STRAW2:
			*item = wri_crush_choose_straw2(b, k->in->x, r, wri_crush_args_of(k->c, k->args, (uint32_t)(-1 - b->id)), position);
			break;
		case WRI_CRUSH_ALG_STRAW:
			*item = wri_crush_choose_straw(b, k->in->x, r);
			break;
		case WRI_CRUSH_ALG_LIST:
			st = wri_crush_choose_list(b, k->in->x, r, item);
			break;
		case WRI_CRUSH_ALG_UNIFORM:
			st = wri_crush_choose_uniform(b, k->in->x, r, k->ws->perm, item);
			break;
		default: /* tree (decoded for its items only) or an algorithm this build does not know */
			return wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "bucket algorithm not supported (tree)", (uint64_t)(uint32_t)b->id, b->alg, 0);
		}
	}
	if (st != WR_OK)
		return wri_mapx_fail(k, st, "bucket chooser not available", (uint64_t)(uint32_t)b->id, b->alg, b->size);
	return WR_OK;
}

int wri_mapx_is_out(const wri_mapx *k, int32_t dev)
{
	uint32_t w;

	if ((uint32_t)dev >= k->weight_max)
		return 1;
	w = k->in->osd_weight[dev];
	if (w >= WRI_IN_WEIGHT)
		return 0;
	if (w == 0u)
		return 1;
	return (wri_crush_hash2(k->in->x, (uint32_t)dev) & 0xffffu) >= w;
}
