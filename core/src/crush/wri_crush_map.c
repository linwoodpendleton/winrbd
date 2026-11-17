/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_map.c - the CRUSH rule interpreter: wri_crush_do_rule (docs/design/core-architecture.md 16.3.3 and 16.3.4,
 * docs/spec/crush-and-placement.md 3.3, 3.5 and 3.6).
 *
 * Shape of the code, from the outside in:
 *
 *   wri_crush_do_rule   the step loop (take, the SET_* steps, choose / chooseleaf firstn, emit) over the working set;
 *   choose_firstn       one call of the choose procedure for one working-set item: it fills replica slots one after
 *                       another and keeps the output position, which is also the choose_args position of every draw;
 *   run_slot            ONE replica slot: the descent, the collision / rejection counters and the retry rules of 3.6.
 *                       The chooseleaf "recursive call" is the same procedure on a chosen bucket with other
 *                       parameters and exactly one level of nesting, so it is not a call at all: run_slot owns two
 *                       explicit frames and a depth index (0 outer, 1 leaf search) and loops, which keeps the call graph
 *                       acyclic and the stack independent of the map;
 *   wri_mapx_draw       (wri_crush_buck.c) one candidate from one bucket (straw2 / straw / list / uniform, or the
 *                       permutation chooser of the local-fallback path), after charging the work budget.
 *
 * Bounds that protect against a hostile map (16.3.3): every bucket evaluation first spends max(1, bucket size) from
 * ws->work (the budget; running out is WR_E_CRUSH_WORK), so a map that makes the reference spin (four billion tries,
 * empty buckets, local retries without end) stops after a bounded amount of work; a descent of more than
 * WRI_CRUSH_DESCENT_MAX bucket steps is WR_E_CRUSH_LOOP (a cyclic hierarchy); all item ids are checked against
 * max_devices and max_buckets, the OSD weight array against weight_max.
 *
 * Where the reference leaves undefined behaviour on a malformed map this code picks a defined answer: an item that
 * names a missing bucket (a hole) is WR_E_CRUSH_UNSUPPORTED, the out test applies to devices only, and a SET_* step
 * with a vary_r above WRI_CRUSH_VARY_R_MAX (a shift by 32 or more) is refused.
 */
#include "wri_crush_buck.h"

WR_FILE_LICENCE_MIT

/* ---- one choose call and its replica slots (3.6) ---------------------------------------------------------------- */

/* One choose call: its parameters, its progress (outpos, rep) and the answer of the slot just tried (placed). */
typedef struct wri_cslot {
	const wri_cbucket *start;  /* B: where every descent of a slot begins */
	int32_t *out;              /* results of this call so far: out[0..outpos) */
	int32_t *out2;             /* chooseleaf results, indexed like out; NULL without leaf mode */
	uint32_t type;             /* wanted type */
	uint32_t numrep;
	uint32_t budget;           /* results this call may still add */
	uint32_t tries;
	uint32_t recurse_tries;    /* tries of the leaf search */
	uint32_t outpos;           /* also the choose_args position of every draw */
	uint32_t rep;
	uint32_t placed;           /* the slot just tried gave a result */
	int leaf;
} wri_cslot;

/* The mutable state of one level of the slot procedure. */
typedef struct wri_cframe {
	const wri_cbucket *start;
	const wri_cbucket *cur;
	int32_t *out;
	int32_t item;       /* the bucket candidate frame 0 is waiting on while frame 1 searches below it */
	uint32_t type;
	uint32_t tries;
	uint32_t parent_r;
	uint32_t rep;
	uint32_t outpos;
	uint32_t fails_all;  /* rejections of this slot over all descents */
	uint32_t fails_here; /* rejections in the current descent */
	uint32_t depth;      /* bucket steps taken in the current descent */
	int leaf;
} wri_cframe;

/* What the last pass of the slot procedure decided. */
#define WRI_ACT_JUDGE 0u   /* a candidate of the wanted type (or an empty bucket) waits to be judged */
#define WRI_ACT_AGAIN 1u   /* go round again: a new draw, a new descent or the leaf search just started */
#define WRI_ACT_ABANDON 2u /* the slot is abandoned */
#define WRI_ACT_PLACED 3u  /* the candidate was accepted */

/* Everything run_slot keeps between its passes: the two frames and the temporaries of one attempt. */
typedef struct wri_cwalk {
	wri_cframe f[2];
	const wri_cbucket *child;
	int32_t item;
	uint32_t d;          /* index of the active frame */
	uint32_t r;
	uint32_t itemtype;
	uint32_t act;
	int resume;          /* frame 0 continues after frame 1 finished */
	int inner_ok;        /* frame 1 found a device */
	int reject;
	int collide;
} wri_cwalk;

static void frame_init(wri_cframe *f, const wri_cbucket *start, uint32_t type, int32_t *out, uint32_t tries, uint32_t parent_r,
		       uint32_t rep, uint32_t outpos, int leaf)
{
	f->start = start;
	f->cur = start;
	f->out = out;
	f->item = 0;
	f->type = type;
	f->tries = tries;
	f->parent_r = parent_r;
	f->rep = rep;
	f->outpos = outpos;
	f->fails_all = 0;
	f->fails_here = 0;
	f->depth = 0;
	f->leaf = leaf;
}

/* Step 6: a candidate of another type: a device abandons the slot, a bucket is entered with the same r. */
static wr_status walk_descend(const wri_mapx *k, wri_cwalk *g, wri_cframe *F)
{
	if (g->item >= 0) {
		g->act = WRI_ACT_ABANDON;
		return WR_OK;
	}
	if (++F->depth > WRI_CRUSH_DESCENT_MAX)
		return wri_mapx_fail(k, WR_E_CRUSH_LOOP, "descent deeper than the limit", (uint64_t)(uint32_t)F->start->id, (uint64_t)(uint32_t)g->item,
				 F->depth);
	F->cur = g->child;
	g->act = WRI_ACT_AGAIN;
	return WR_OK;
}

/* Steps 5 and 6: judge the candidate by its id and its type. */
static wr_status walk_classify(const wri_mapx *k, wri_cwalk *g, wri_cframe *F)
{
	g->itemtype = 0;
	if (g->item >= k->c->max_devices) { /* also ITEM_NONE */
		g->act = WRI_ACT_ABANDON;
		return WR_OK;
	}
	if (g->item < 0) {
		if ((uint32_t)(-1 - g->item) >= k->c->max_buckets) {
			g->act = WRI_ACT_ABANDON;
			return WR_OK;
		}
		g->child = wri_crush_bucket(k->c, g->item);
		if (g->child == NULL)
			return wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "bucket item names a missing bucket", (uint64_t)(uint32_t)F->cur->id,
					 (uint64_t)(uint32_t)g->item, 0);
		g->itemtype = g->child->type;
	}
	if (g->itemtype != F->type)
		return walk_descend(k, g, F);
	return WR_OK;
}

/* Steps 2 to 4: the draw number and one candidate from the current bucket (an empty bucket is a rejection). */
static wr_status walk_draw(const wri_mapx *k, wri_cwalk *g, wri_cframe *F)
{
	wr_status st;

	g->act = WRI_ACT_JUDGE;
	g->child = NULL;
	g->item = 0;
	g->reject = 0;
	g->collide = 0;
	g->r = F->rep + F->parent_r + F->fails_all;
	if (F->cur->size == 0u) { /* it still costs one unit of work */
		g->reject = 1;
		return wri_mapx_charge(k, F->cur);
	}
	st = wri_mapx_draw(k, F->cur, g->r, F->outpos,
		  k->fallback_retries > 0u && F->fails_here >= F->cur->size / 2u && F->fails_here > k->fallback_retries, &g->item);
	return st != WR_OK ? st : walk_classify(k, g, F);
}

/* Step 7: a candidate of the wanted type: the collision test, and in leaf mode the search for a device below it. */
static void walk_leaf(const wri_mapx *k, const wri_cslot *si, wri_cwalk *g, wri_cframe *F)
{
	uint32_t i;

	for (i = 0; i < F->outpos; i++) /* collisions are checked against this call's own results */
		if (F->out[i] == g->item)
			g->collide = 1;
	if (g->collide || !F->leaf)
		return;
	if (g->item >= 0) {
		si->out2[F->outpos] = g->item;
		return;
	}
	F->item = g->item; /* chooseleaf: one device below the candidate, as a second frame */
	frame_init(&g->f[1], g->child, 0u, si->out2, si->recurse_tries, k->vary_r != 0u ? g->r >> (k->vary_r - 1u) : 0u,
		   k->stable != 0u ? 0u : F->outpos, F->outpos, 0);
	g->d = 1;
	g->act = WRI_ACT_AGAIN;
}

/* The end of step 7 and step 8: the out test, then accept, or count the failure and pick the retry rule. */
static void walk_judge(const wri_mapx *k, wri_cwalk *g, wri_cframe *F)
{
	if (!g->collide && !g->reject && g->item >= 0 && wri_mapx_is_out(k, g->item))
		g->reject = 1;
	if (!g->collide && !g->reject) {
		F->out[F->outpos] = g->item;
		g->act = WRI_ACT_PLACED;
		return;
	}
	F->fails_all++;
	F->fails_here++;
	g->act = WRI_ACT_AGAIN;
	if (g->collide && F->fails_here <= k->local_retries)
		return; /* (a) another draw in the same bucket */
	if (k->fallback_retries > 0u && (uint64_t)F->fails_here <= (uint64_t)F->cur->size + k->fallback_retries)
		return; /* (b) the same, towards the permutation fallback */
	if (F->fails_all < F->tries) { /* (c) a new descent from the start bucket, keeping fails_all */
		F->cur = F->start;
		F->fails_here = 0;
		F->depth = 0;
		return;
	}
	g->act = WRI_ACT_ABANDON; /* (d) */
}

/*
 * Try to fill slot si->rep (steps 1 to 9 of 3.6). si->placed is set to 1 when si->out[si->outpos] (and, in leaf mode,
 * si->out2[si->outpos]) was written, to 0 when the slot was abandoned. The chooseleaf recursion is frame 1. Returns a
 * failure status for the hard errors only (work, loop, unsupported).
 */
static wr_status run_slot(const wri_mapx *k, wri_cslot *si)
{
	wri_cwalk g;
	wri_cframe *F;
	wr_status st;

	frame_init(&g.f[0], si->start, si->type, si->out, si->tries, 0, si->rep, si->outpos, si->leaf);
	g.d = 0;
	g.resume = 0;
	g.inner_ok = 0;
	for (;;) {
		F = &g.f[g.d];
		if (g.resume) { /* the leaf search of frame 1 is over: its result decides this attempt */
			g.resume = 0;
			g.act = WRI_ACT_JUDGE;
			g.item = F->item;
			g.reject = !g.inner_ok;
			g.collide = 0;
		} else {
			st = walk_draw(k, &g, F);
			if (st != WR_OK)
				return st;
			if (g.act == WRI_ACT_JUDGE && !g.reject)
				walk_leaf(k, si, &g, F);
		}
		if (g.act == WRI_ACT_JUDGE)
			walk_judge(k, &g, F);
		if (g.act == WRI_ACT_AGAIN)
			continue;
		si->placed = g.act == WRI_ACT_PLACED;
		if (g.d == 0u)
			return WR_OK;
		g.d = 0; /* frame 1 is over: back to frame 0 with its answer */
		g.inner_ok = (int)si->placed;
		g.resume = 1;
	}
}

/* All replica slots of one choose call: si->numrep slots, at most si->budget results; si->outpos ends as the result count. */
static wr_status choose_firstn(const wri_mapx *k, wri_cslot *si)
{
	wr_status st;

	si->outpos = 0;
	for (si->rep = 0; si->rep < si->numrep && si->budget > 0u; si->rep++) { /* the output position starts at 0, so stable or not, rep starts at 0 */
		st = run_slot(k, si);
		if (st != WR_OK)
			return st;
		if (si->placed) {
			si->outpos++;
			si->budget--;
		}
	}
	return WR_OK;
}

/* ---- the steps ------------------------------------------------------------------------------------------- */

/* The choose call for working-set item w[i]: adds its results at o[*osize] (and the leaves at leaf[*osize]). */
static wr_status choose_item(wri_mapx *k, const wri_cstep *s, wri_cslot *si, uint32_t i, uint32_t *osize)
{
	int64_t numrep = (int64_t)s->arg1;
	wr_status st;

	if (numrep <= 0)
		numrep += (int64_t)k->in->result_max;
	if (numrep <= 0)
		return WR_OK;
	si->start = wri_crush_bucket(k->c, k->w[i]); /* NULL for a device, a hole or an id out of range: nothing to choose from */
	if (si->start == NULL)
		return WR_OK;
	si->out = k->o + *osize;
	si->out2 = si->leaf ? k->ws->leaf + *osize : NULL;
	si->numrep = (uint32_t)numrep;
	si->budget = k->in->result_max - *osize;
	st = choose_firstn(k, si);
	if (st == WR_OK)
		*osize += si->outpos;
	return st;
}

/* CHOOSE_FIRSTN / CHOOSELEAF_FIRSTN over every item of the working set. */
static wr_status step_choose(wri_mapx *k, const wri_cstep *s)
{
	wri_cslot si;
	uint32_t i, osize = 0;
	wr_status st;
	int32_t *tmp;

	if (k->wsize == 0u)
		return WR_OK;
	si.leaf = s->op == WRI_CRUSH_OP_CHOOSELEAF_FIRSTN;
	si.type = s->arg2 < 0 ? 0xffffffffu : (uint32_t)s->arg2; /* a negative type matches nothing */
	si.tries = k->choose_tries;
	si.recurse_tries = k->leaf_tries != 0u ? k->leaf_tries : (k->descend_once != 0u ? 1u : k->choose_tries);
	for (i = 0; i < k->wsize; i++) {
		st = choose_item(k, s, &si, i, &osize);
		if (st != WR_OK)
			return st;
	}
	if (si.leaf) { /* the chosen leaves, not the intermediate buckets, are what the next step sees */
		for (i = 0; i < osize; i++)
			k->o[i] = k->ws->leaf[i];
	}
	tmp = k->o;
	k->o = k->w;
	k->w = tmp;
	k->wsize = osize;
	return WR_OK;
}

static void step_take(wri_mapx *k, int32_t a1)
{
	if ((a1 >= 0 && a1 < k->c->max_devices) || (a1 < 0 && wri_crush_bucket(k->c, a1) != NULL)) {
		k->w[0] = a1;
		k->wsize = 1;
	}
}

static void step_emit(wri_mapx *k)
{
	uint32_t i;

	for (i = 0; i < k->wsize && k->rlen < k->in->result_max; i++)
		k->result[k->rlen++] = k->w[i];
	k->wsize = 0;
}

/* The six SET_* steps: a negative (or, for the tries, non-positive) argument leaves the value alone. */
static wr_status step_set(wri_mapx *k, const wri_cstep *s, uint32_t index)
{
	int32_t a1 = s->arg1;

	switch (s->op) {
	case WRI_CRUSH_OP_SET_CHOOSE_TRIES:
		if (a1 > 0)
			k->choose_tries = (uint32_t)a1;
		break;
	case WRI_CRUSH_OP_SET_CHOOSELEAF_TRIES:
		if (a1 > 0)
			k->leaf_tries = (uint32_t)a1;
		break;
	case WRI_CRUSH_OP_SET_CHOOSE_LOCAL_TRIES:
		if (a1 >= 0)
			k->local_retries = (uint32_t)a1;
		break;
	case WRI_CRUSH_OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES:
		if (a1 >= 0)
			k->fallback_retries = (uint32_t)a1;
		break;
	case WRI_CRUSH_OP_SET_CHOOSELEAF_VARY_R:
		if (a1 >= 0) {
			if ((uint32_t)a1 > WRI_CRUSH_VARY_R_MAX)
				return wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "SET_CHOOSELEAF_VARY_R above the supported maximum", (uint32_t)a1,
						 WRI_CRUSH_VARY_R_MAX, index);
			k->vary_r = (uint32_t)a1;
		}
		break;
	default: /* SET_CHOOSELEAF_STABLE */
		if (a1 >= 0)
			k->stable = a1 != 0 ? 1u : 0u;
		break;
	}
	return WR_OK;
}

static wr_status run_steps(wri_mapx *k, const wri_crule *rule)
{
	const wri_cstep *steps = wri_crule_steps(rule);
	uint32_t si;
	wr_status st = WR_OK;

	for (si = 0; si < rule->nsteps && st == WR_OK; si++) {
		const wri_cstep *s = &steps[si];

		switch (s->op) {
		case WRI_CRUSH_OP_TAKE:
			step_take(k, s->arg1);
			break;
		case WRI_CRUSH_OP_SET_CHOOSE_TRIES:
		case WRI_CRUSH_OP_SET_CHOOSELEAF_TRIES:
		case WRI_CRUSH_OP_SET_CHOOSE_LOCAL_TRIES:
		case WRI_CRUSH_OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES:
		case WRI_CRUSH_OP_SET_CHOOSELEAF_VARY_R:
		case WRI_CRUSH_OP_SET_CHOOSELEAF_STABLE:
			st = step_set(k, s, si);
			break;
		case WRI_CRUSH_OP_CHOOSE_FIRSTN:
		case WRI_CRUSH_OP_CHOOSELEAF_FIRSTN:
			st = step_choose(k, s);
			break;
		case WRI_CRUSH_OP_EMIT:
			step_emit(k);
			break;
		case WRI_CRUSH_OP_CHOOSE_INDEP:
		case WRI_CRUSH_OP_CHOOSELEAF_INDEP:
			st = wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "indep rule step not supported", s->op, si, 0);
			break;
		case 14u: /* the MSR steps */
		case 15u:
		case 16u:
			st = wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "MSR rule step not supported", s->op, si, 0);
			break;
		default: /* NOOP and anything unknown is ignored, as the reference does */
			break;
		}
	}
	return st;
}

/* The per-run copies of the tunables, and the checks on the map that go with them. */
static wr_status mapx_init(wri_mapx *k, const wri_crush *c, const wri_crush_in *in)
{
	k->args = wri_crush_args_index(c, in->args_pool);
	k->weight_max = in->osd_weight == NULL ? 0u : in->weight_max;
	k->choose_tries = c->tun.choose_total_tries == 0xffffffffu ? 0xffffffffu : c->tun.choose_total_tries + 1u;
	k->leaf_tries = 0;
	k->local_retries = c->tun.choose_local_tries;
	k->fallback_retries = c->tun.choose_local_fallback_tries;
	k->vary_r = c->tun.chooseleaf_vary_r;
	k->stable = c->tun.chooseleaf_stable != 0u ? 1u : 0u;
	k->descend_once = c->tun.chooseleaf_descend_once != 0u ? 1u : 0u;
	if (k->vary_r > WRI_CRUSH_VARY_R_MAX)
		return wri_mapx_fail(k, WR_E_CRUSH_UNSUPPORTED, "chooseleaf_vary_r above the supported maximum", k->vary_r, WRI_CRUSH_VARY_R_MAX, 0);
	return WR_OK;
}

wr_status wri_crush_do_rule(const wri_crush *c, const wri_crush_in *in, wri_crush_ws *ws, int32_t *result, uint32_t *n_out, wr_errinfo *why)
{
	wri_mapx k;
	const wri_crule *rule;
	wr_status st;

	if (n_out != NULL)
		*n_out = 0;
	if (c == NULL || in == NULL || ws == NULL || result == NULL || n_out == NULL || in->result_max == 0u ||
	    in->result_max > WRI_CRUSH_RESULT_MAX || (in->osd_weight == NULL && in->weight_max != 0u))
		return WR_E_INVAL;
	k.c = c;
	k.in = in;
	k.ws = ws;
	k.why = why;
	k.result = result;
	k.w = ws->w;
	k.o = ws->o;
	k.wsize = 0;
	k.rlen = 0;
	if (c->magic != WRI_CRUSH_MAGIC)
		return wri_mapx_fail(&k, WR_E_CRUSH_ENCODING, "not a compact CRUSH region", c->magic, 0, 0);
	rule = wri_crush_rule(c, in->rule);
	if (rule == NULL)
		return wri_mapx_fail(&k, WR_E_CRUSH_NO_RULE, wri_crush_rule_kind(c, in->rule) == 1u ? "rule is not a replicated rule" : "rule is missing",
				 in->rule, 0, 0);
	if (rule->nsteps > WRI_CRUSH_MAX_STEPS)
		return wri_mapx_fail(&k, WR_E_CRUSH_UNSUPPORTED, "rule has too many steps", rule->nsteps, WRI_CRUSH_MAX_STEPS, 0);
	st = mapx_init(&k, c, in);
	if (st == WR_OK)
		st = run_steps(&k, rule);
	if (st == WR_OK)
		*n_out = k.rlen;
	return st;
}
