/* SPDX-License-Identifier: MIT */
/*
 * wri_crush_audit.c - wri_crush_audit_rule: fail early, with a reason, for what wri_crush_do_rule would fail on later
 * (docs/design/core-architecture.md 16.3.5, 16.3.6; docs/spec/crush-and-placement.md 4.3).
 *
 * It walks the rule's steps, and under every `take` the whole hierarchy that mapping could descend into, with an
 * explicit stack (no recursion, a few hundred bytes, no allocation). Statuses: WR_E_CRUSH_NO_RULE (no replicated rule of
 * that id), WR_E_CRUSH_LOOP (a hierarchy that is cyclic or deeper than WRI_CRUSH_MAX_DEPTH, or one that fans out through
 * shared buckets more than any sane map does), WR_E_CRUSH_UNSUPPORTED for everything else.
 *
 * Which bucket algorithms count as supported is decided by asking the legacy choosers themselves, on a one-item bucket
 * built on the stack: a chooser that answers WR_E_CRUSH_UNSUPPORTED (the skeleton of module crush-legacy) makes the
 * audit refuse the algorithm, a real one makes it accept it, so this file needs no edit when that module lands.
 */
#include "wri_crush_buck.h"
#include "wri_ctx.h"

WR_FILE_LICENCE_MIT

#define WRI_AUDIT_FAN_FACTOR 4u    /* bucket scans per item of the map and per take, at most (a tree needs 1) */
#define WRI_AUDIT_FAN_SLACK 1024u

static wr_status afail(wr_errinfo *why, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(why, st, WR_MOD_CRUSH, what, a0, a1, a2);
	return st;
}

/* ---- what the build can do --------------------------------------------------------------------------------- */

/* One-item buckets for probing the legacy choosers: head, items[1], then the tail the algorithm reads. */
typedef struct wri_probe_list {
	wri_cbucket b;
	int32_t item;
	uint32_t weight;
	uint32_t sum;
} wri_probe_list;

typedef struct wri_probe_plain {
	wri_cbucket b;
	int32_t item;
	uint32_t tail;
} wri_probe_plain;

typedef struct wri_legacy_caps {
	int list, uniform, perm;
} wri_legacy_caps;

static void probe_legacy(wri_legacy_caps *caps)
{
	wri_probe_list pl;
	wri_probe_plain pu;
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	int32_t item = 0;

	WR_MEMSET(&pl, 0, sizeof(pl));
	pl.b.id = -1;
	pl.b.alg = (uint8_t)WRI_CRUSH_ALG_LIST;
	pl.b.size = 1;
	pl.item = 0;
	pl.weight = 0x10000u;
	pl.sum = 0x10000u;
	caps->list = wri_crush_choose_list(&pl.b, 0u, 0u, &item) != WR_E_CRUSH_UNSUPPORTED;

	WR_MEMSET(&pu, 0, sizeof(pu));
	pu.b.id = -1;
	pu.b.alg = (uint8_t)WRI_CRUSH_ALG_UNIFORM;
	pu.b.size = 1;
	pu.item = 0;
	caps->uniform = wri_crush_choose_uniform(&pu.b, 0u, 0u, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
	pu.b.alg = (uint8_t)WRI_CRUSH_ALG_STRAW2;
	caps->perm = wri_crush_choose_perm(&pu.b, 0u, 0u, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
}

/* ---- one bucket -------------------------------------------------------------------------------------------- */

static wr_status audit_bucket(const wri_cbucket *b, const wri_legacy_caps *caps, int perm_needed, wr_errinfo *why)
{
	uint64_t id = (uint64_t)(uint32_t)b->id;

	switch (b->alg) {
	case WRI_CRUSH_ALG_STRAW2:
	case WRI_CRUSH_ALG_STRAW:
		break;
	case WRI_CRUSH_ALG_LIST:
		if (!caps->list)
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "list bucket reachable (not supported yet)", id, b->alg, 0);
		break;
	case WRI_CRUSH_ALG_UNIFORM:
		if (!caps->uniform)
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "uniform bucket reachable (not supported yet)", id, b->alg, 0);
		if (b->size > WRI_CRUSH_PERM_MAX)
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "uniform bucket larger than the permutation chooser handles", id, b->size,
				     WRI_CRUSH_PERM_MAX);
		break;
	case WRI_CRUSH_ALG_TREE:
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "tree bucket reachable", id, b->alg, 0);
	default:
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "unknown bucket algorithm reachable", id, b->alg, 0);
	}
	if (perm_needed && b->size > WRI_CRUSH_PERM_MAX)
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "bucket larger than the permutation chooser handles (local fallback is on)", id, b->size,
			     WRI_CRUSH_PERM_MAX);
	return WR_OK;
}

/* ---- the hierarchy under one root ---------------------------------------------------------------------------- */

typedef struct wri_afr {
	const wri_cbucket *b;
	uint32_t next; /* index of the next item of b to look at */
} wri_afr;

/* Walk everything reachable from bucket `root`. *budget is the number of item scans still allowed. */
static wr_status audit_tree(const wri_crush *c, const wri_cbucket *root, const wri_legacy_caps *caps, int perm_needed, uint64_t *budget,
			    wr_errinfo *why)
{
	wri_afr st[WRI_CRUSH_MAX_DEPTH];
	uint32_t depth = 0, i;
	wr_status rc;

	rc = audit_bucket(root, caps, perm_needed, why);
	if (rc != WR_OK)
		return rc;
	st[0].b = root;
	st[0].next = 0;
	depth = 1;
	while (depth > 0u) {
		wri_afr *top = &st[depth - 1u];
		const wri_cbucket *child;
		int32_t item;

		if (top->next >= top->b->size) {
			depth--;
			continue;
		}
		if (*budget == 0u)
			return afail(why, WR_E_CRUSH_LOOP, "hierarchy revisits buckets too often (shared buckets fan out)", (uint64_t)(uint32_t)root->id, 0, 0);
		(*budget)--;
		item = wri_cbucket_items(top->b)[top->next++];
		if (item >= 0) {
			if (item >= c->max_devices)
				return afail(why, WR_E_CRUSH_UNSUPPORTED, "bucket item is a device beyond max_devices", (uint64_t)(uint32_t)top->b->id,
					     (uint64_t)(uint32_t)item, (uint64_t)(uint32_t)c->max_devices);
			continue;
		}
		child = wri_crush_bucket(c, item);
		if (child == NULL)
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "bucket item names a missing bucket", (uint64_t)(uint32_t)top->b->id,
				     (uint64_t)(uint32_t)item, 0);
		for (i = 0; i < depth; i++)
			if (st[i].b == child)
				return afail(why, WR_E_CRUSH_LOOP, "hierarchy is cyclic", (uint64_t)(uint32_t)top->b->id, (uint64_t)(uint32_t)item, depth);
		if (depth >= WRI_CRUSH_MAX_DEPTH)
			return afail(why, WR_E_CRUSH_LOOP, "hierarchy deeper than the supported depth", (uint64_t)(uint32_t)root->id,
				     (uint64_t)(uint32_t)item, depth + 1u);
		rc = audit_bucket(child, caps, perm_needed, why);
		if (rc != WR_OK)
			return rc;
		st[depth].b = child;
		st[depth].next = 0;
		depth++;
	}
	return WR_OK;
}

/* ---- the rule ---------------------------------------------------------------------------------------------- */

/* First pass over the steps: opcodes, the SET_* arguments; *perm_needed says whether the permutation chooser can be reached. */
static wr_status audit_steps(const wri_crush *c, const wri_crule *r, int *perm_needed, uint32_t *ntakes, wr_errinfo *why)
{
	const wri_cstep *steps = wri_crule_steps(r);
	uint32_t i;

	*perm_needed = c->tun.choose_local_fallback_tries > 0u;
	*ntakes = 0;
	for (i = 0; i < r->nsteps; i++) {
		const wri_cstep *s = &steps[i];

		switch (s->op) {
		case WRI_CRUSH_OP_CHOOSE_INDEP:
		case WRI_CRUSH_OP_CHOOSELEAF_INDEP:
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "indep rule step not supported", s->op, i, 0);
		case 14u: /* the MSR steps */
		case 15u:
		case 16u:
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "MSR rule step not supported", s->op, i, 0);
		case WRI_CRUSH_OP_SET_CHOOSELEAF_VARY_R:
			if (s->arg1 > 0 && (uint32_t)s->arg1 > WRI_CRUSH_VARY_R_MAX)
				return afail(why, WR_E_CRUSH_UNSUPPORTED, "SET_CHOOSELEAF_VARY_R above the supported maximum", (uint32_t)s->arg1,
					     WRI_CRUSH_VARY_R_MAX, i);
			break;
		case WRI_CRUSH_OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES:
			if (s->arg1 > 0)
				*perm_needed = 1;
			break;
		case WRI_CRUSH_OP_TAKE:
			(*ntakes)++;
			break;
		default:
			break;
		}
	}
	return WR_OK;
}

/* Second pass: every take must name something that exists, and everything below a bucket take must be mappable. */
static wr_status audit_takes(const wri_crush *c, const wri_crule *r, const wri_legacy_caps *caps, int perm_needed, uint64_t *budget, wr_errinfo *why)
{
	const wri_cstep *steps = wri_crule_steps(r);
	uint32_t i;

	for (i = 0; i < r->nsteps; i++) {
		const wri_cstep *s = &steps[i];
		const wri_cbucket *root;
		wr_status rc;

		if (s->op != WRI_CRUSH_OP_TAKE)
			continue;
		if (s->arg1 >= 0) {
			if (s->arg1 >= c->max_devices)
				return afail(why, WR_E_CRUSH_UNSUPPORTED, "take of a device beyond max_devices", (uint64_t)(uint32_t)s->arg1,
					     (uint64_t)(uint32_t)c->max_devices, i);
			continue;
		}
		root = wri_crush_bucket(c, s->arg1);
		if (root == NULL)
			return afail(why, WR_E_CRUSH_UNSUPPORTED, "take of a missing bucket", (uint64_t)(uint32_t)s->arg1, i, 0);
		rc = audit_tree(c, root, caps, perm_needed, budget, why);
		if (rc != WR_OK)
			return rc;
	}
	return WR_OK;
}

/* The budget of bucket-item scans for the whole walk: every item of the map, a few times over, once per take. */
static uint64_t audit_budget(const wri_crush *c, uint32_t ntakes)
{
	uint64_t total = 0;
	uint32_t slot;

	for (slot = 0; slot < c->max_buckets; slot++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, slot);

		if (b != NULL)
			total += b->size;
	}
	return (total * WRI_AUDIT_FAN_FACTOR + WRI_AUDIT_FAN_SLACK) * (ntakes == 0u ? 1u : ntakes);
}

wr_status wri_crush_audit_rule(const wri_crush *c, uint32_t rule, uint32_t result_max, wr_errinfo *why)
{
	const wri_crule *r;
	wri_legacy_caps caps;
	uint32_t ntakes;
	uint64_t budget;
	int perm_needed;
	wr_status rc;

	if (c == NULL)
		return WR_E_INVAL;
	if (c->magic != WRI_CRUSH_MAGIC)
		return afail(why, WR_E_CRUSH_ENCODING, "not a compact CRUSH region", c->magic, 0, 0);
	if (result_max == 0u || result_max > WRI_CRUSH_RESULT_MAX)
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "pool size outside 1 to the supported maximum", result_max, WRI_CRUSH_RESULT_MAX, 0);
	r = wri_crush_rule(c, rule);
	if (r == NULL)
		return afail(why, WR_E_CRUSH_NO_RULE, wri_crush_rule_kind(c, rule) == 1u ? "rule is not a replicated rule" : "rule is missing", rule, 0, 0);
	if (r->nsteps > WRI_CRUSH_MAX_STEPS)
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "rule has too many steps", r->nsteps, WRI_CRUSH_MAX_STEPS, 0);
	if (c->tun.chooseleaf_vary_r > WRI_CRUSH_VARY_R_MAX)
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "chooseleaf_vary_r above the supported maximum", c->tun.chooseleaf_vary_r, WRI_CRUSH_VARY_R_MAX, 0);
	rc = audit_steps(c, r, &perm_needed, &ntakes, why);
	if (rc != WR_OK)
		return rc;
	probe_legacy(&caps);
	if (perm_needed && !caps.perm)
		return afail(why, WR_E_CRUSH_UNSUPPORTED, "local fallback tries need the permutation chooser (not supported yet)",
			     c->tun.choose_local_fallback_tries, 0, 0);
	budget = audit_budget(c, ntakes);
	return audit_takes(c, r, &caps, perm_needed, &budget, why);
}
