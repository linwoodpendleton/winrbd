/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_legacy.c - the legacy bucket choosers: list, uniform and the permutation chooser
 * (docs/spec/crush-and-placement.md 3.4.4 and 3.4.5).
 *
 *   list     walks the items from the last one down to the first and keeps the first whose scaled draw falls below
 *            its own weight; the first item is the answer when none does. It reads the two weight arrays that follow
 *            the items (the weight of each item and the running sum up to and including it) and nothing else.
 *   uniform  and the local-fallback path of choose_firstn (for a bucket of ANY algorithm) use one permutation of the
 *            item indexes. Only the first r mod size steps of a Fisher-Yates shuffle are needed, and each step
 *            depends on nothing but (x, bucket id, step), so the answer is a pure function of the arguments: no
 *            cached state survives a call, the scratch array only carries the partly shuffled indexes inside one.
 *
 * Every function reads the compact bucket record only and keeps no state. Size 0 is not an error (the interpreter
 * never calls with it): the answer is WRI_CRUSH_ITEM_NONE, the same as straw and straw2 give. A bucket above
 * WRI_CRUSH_PERM_MAX items is refused by the two permutation choosers (the scratch array is that long), never
 * by list. Written from the note only.
 */
#include "wri_crush_buck.h"
#include "wri_crush_hash.h"

WR_FILE_LICENCE_MIT

wr_status wri_crush_choose_list(const wri_cbucket *b, uint32_t x, uint32_t r, int32_t *item)
{
	const int32_t *items;
	const uint32_t *weights, *sums;
	uint32_t i;

	if (item == NULL)
		return WR_E_INVAL;
	*item = WRI_CRUSH_ITEM_NONE;
	if (b == NULL)
		return WR_E_INVAL;
	if (b->size == 0u)
		return WR_OK;
	items = wri_cbucket_items(b);
	weights = wri_cbucket_w(b);
	sums = wri_cbucket_sums(b);
	for (i = b->size; i > 0u; i--) {
		uint64_t draw = (uint64_t)(wri_crush_hash4(x, (uint32_t)items[i - 1u], r, (uint32_t)b->id) & 0xffffu);

		draw = (draw * (uint64_t)sums[i - 1u]) >> 16;
		if (draw < (uint64_t)weights[i - 1u]) {
			*item = items[i - 1u];
			return WR_OK;
		}
	}
	*item = items[0]; /* nothing qualified: the first item (a malformed sum array can do this; a well-formed one never) */
	return WR_OK;
}

wr_status wri_crush_choose_perm(const wri_cbucket *b, uint32_t x, uint32_t r, uint16_t *perm, int32_t *item)
{
	uint32_t size, pr, i, p;

	if (item == NULL)
		return WR_E_INVAL;
	*item = WRI_CRUSH_ITEM_NONE;
	if (b == NULL || perm == NULL)
		return WR_E_INVAL;
	size = b->size;
	if (size == 0u)
		return WR_OK;
	if (size > WRI_CRUSH_PERM_MAX)
		return WR_E_CRUSH_UNSUPPORTED;
	pr = r % size;
	for (i = 0; i < size; i++)
		perm[i] = (uint16_t)i;
	/* Step p swaps position p with a position in [p, size); the last position has no choice left and is not a step. */
	for (p = 0; p <= pr && p + 1u < size; p++) {
		uint32_t j = p + wri_crush_hash3(x, (uint32_t)b->id, p) % (size - p);
		uint16_t t = perm[p];

		perm[p] = perm[j];
		perm[j] = t;
	}
	*item = wri_cbucket_items(b)[perm[pr]];
	return WR_OK;
}

wr_status wri_crush_choose_uniform(const wri_cbucket *b, uint32_t x, uint32_t r, uint16_t *perm, int32_t *item)
{
	/* A uniform bucket has no tail and no draw of its own: its answer is the permutation. */
	return wri_crush_choose_perm(b, x, r, perm, item);
}
