/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_buck.h - choosing one item inside one bucket, per algorithm (crush-and-placement.md 3.4).
 *
 * The rule interpreter (module crush-map, wri_crush_map.c) calls these; it owns the straw2 and straw choosers
 * (wri_crush_buck.c). The legacy choosers (list, uniform, and the permutation used by the local-fallback path
 * of any bucket) belong to module crush-legacy (wri_crush_legacy.c); the audit probes them once to learn which
 * of the three a build provides.
 *
 * Every chooser needs a bucket with size > 0 (the interpreter treats an empty bucket as a rejection before it
 * calls; straw2 and straw answer WRI_CRUSH_ITEM_NONE for an empty bucket rather than read past the items), reads only
 * the compact record, and never fails except where it returns a status. The interpreter charges the work budget
 * (ws->work) before every call, one unit per candidate item.
 */
#ifndef WRI_CRUSH_BUCK_H
#define WRI_CRUSH_BUCK_H

#include "wri_crush.h"

/*
 * straw2 (3.4.1): the item with the largest draw ln(hash3(x, id, r) & 0xffff) / weight (signed 64-bit division
 * truncating toward zero; weight 0 = no draw; first index wins ties). `args` is the bucket's choose_args override
 * or NULL; `position` selects the weight row (min(position, rows - 1)); override ids replace the hash input
 * only, the returned item is always the real one. Returns the item id.
 */
int32_t wri_crush_choose_straw2(const wri_cbucket *b, uint32_t x, uint32_t r, const wri_cargs *args, uint32_t position);

/* straw (3.4.3): the item with the largest (hash3(x, id, r) & 0xffff) * straw; first index wins ties. */
int32_t wri_crush_choose_straw(const wri_cbucket *b, uint32_t x, uint32_t r);

/* list (3.4.4), walking from the last item down. Any size up to WRI_CRUSH_MAX_BUCKET_SIZE; WR_E_INVAL for a null argument. */
WR_MUST_CHECK wr_status wri_crush_choose_list(const wri_cbucket *b, uint32_t x, uint32_t r, int32_t *item);

/*
 * uniform (3.4.5): the permutation chooser applied to a uniform bucket. perm is scratch of
 * WRI_CRUSH_PERM_MAX entries; a bucket larger than that is WR_E_CRUSH_UNSUPPORTED.
 */
WR_MUST_CHECK wr_status wri_crush_choose_uniform(const wri_cbucket *b, uint32_t x, uint32_t r, uint16_t *perm, int32_t *item);

/* The local-fallback chooser of choose_firstn for ANY bucket algorithm (3.6 step 4): same permutation, same limits. */
WR_MUST_CHECK wr_status wri_crush_choose_perm(const wri_cbucket *b, uint32_t x, uint32_t r, uint16_t *perm, int32_t *item);

/* ---- the run state of one mapping and the draw of one candidate (wri_crush_map.c uses them, wri_crush_buck.c defines them) ----
 *
 * The interpreter keeps its state in a few structs rather than many locals: a sanitizer build at -O0 gives every local its
 * own redzoned stack slot, and the frames must stay under 1 KiB there too.
 */
typedef struct wri_mapx {
	const wri_crush *c;
	const wri_crush_in *in;
	wri_crush_ws *ws;
	const uint32_t *args;   /* choose_args index table that applies to the pool, or NULL */
	wr_errinfo *why;        /* may be NULL */
	int32_t *result;
	int32_t *w;             /* the working set: w[0..wsize) */
	int32_t *o;             /* the output of the current choose step */
	uint32_t wsize;
	uint32_t rlen;          /* entries of the result so far */
	uint32_t weight_max;    /* length of in->osd_weight (0 when there is none: every device is out) */
	uint32_t choose_tries;  /* attempts: the stored total_tries counts retries, this is one more */
	uint32_t leaf_tries;    /* 0 = not set by a rule */
	uint32_t local_retries;
	uint32_t fallback_retries;
	uint32_t vary_r;        /* 0 = off, else the shift of parent_r is vary_r - 1 */
	uint32_t stable;        /* 0 or 1 */
	uint32_t descend_once;  /* 0 or 1 */
} wri_mapx;

/* Record a CRUSH failure in k->why (may be NULL; the first failure wins) and return `st`. */
wr_status wri_mapx_fail(const wri_mapx *k, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2);

/*
 * Spend the cost of evaluating bucket `b` from ws->work: one unit per candidate item, at least one (so an empty bucket is
 * not free). WR_E_CRUSH_WORK, with ws->work set to 0, when the budget does not cover it.
 */
WR_MUST_CHECK wr_status wri_mapx_charge(const wri_mapx *k, const wri_cbucket *b);

/*
 * The item of bucket `b` (size > 0) for draw number r, after charging the work budget: the bucket's own algorithm, or the
 * permutation chooser when use_perm; `position` is the output position (the choose_args weight row). WR_E_CRUSH_UNSUPPORTED
 * for a tree bucket or an algorithm whose chooser is not available.
 */
WR_MUST_CHECK wr_status wri_mapx_draw(const wri_mapx *k, const wri_cbucket *b, uint32_t r, uint32_t position, int use_perm, int32_t *item);

/* The out test of crush-and-placement.md 3.5 for device `dev` (>= 0): always the rjenkins hash2, whatever a bucket's hash byte says. */
int wri_mapx_is_out(const wri_mapx *k, int32_t dev);

#endif /* WRI_CRUSH_BUCK_H */
