/* SPDX-License-Identifier: MIT */
/*
 * test_crush_map.c - the rule interpreter wri_crush_do_rule and the straw2 / straw choosers
 * (core/src/crush/wri_crush_map.c, wri_crush_buck.c).
 *
 * What it checks, against what:
 *   1. Ground truth from real Ceph output (no shared code): the lab CRUSH map against crush-mappings.json (4 runs x 300
 *      x) and crushtool-mappings.json (8 runs x 64 x), the 18 offline maps of public/mapb/crush against their
 *      `crushtool --test` results (130 runs x 48 x, with devices out, choose_args, device classes, five tunable
 *      profiles, all bucket algorithms), and, when WINRBD_CEPH_SRC points at a Ceph tree, the in-tree crushtool
 *      known-answer files (read at test time, never copied). Where the answer needs a bucket algorithm or an
 *      opcode this build does not have (tree, indep, and list / uniform / the permutation fallback while module
 *      crush-legacy is a skeleton) the run must fail with WR_E_CRUSH_UNSUPPORTED and is counted as skipped.
 *   2. A differential oracle written in this file: a plain recursive reading of docs/spec/crush-and-placement.md 3.3
 *      to 3.6 over the generator's description structs (no compact format, no shared code with the core except the
 *      hash and ln primitives). It is run against the core over generated hierarchies (five tunable profiles, straw2 /
 *      straw / mixed algorithms, racks and flat, jitter), 14 rules (chooseleaf over hosts, racks and devices, SET_*
 *      steps, negative and zero counts, two-step choose, takes of devices) and seven weight scenarios (all in, out,
 *      fractional, all out, short weight array), with and without choose_args (several rows, substitute ids, sets
 *      by pool id and the default set).
 *   3. The straw2 and straw choosers on hand-built buckets: ties, zero weights, weight rows by position, substitute ids.
 *   4. Interpreter semantics one by one: counts, takes, rule kinds, the work budget (exact costs, exhaustion,
 *      four-billion tries, empty buckets), cycles, holes, tree buckets, invalid arguments.
 *
 * `test_crush_map --emit-seeds DIR` writes the inputs the fuzz target uses as seeds (and nothing else).
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush.h"
#include "wri_crush_buck.h"
#include "wri_crush_hash.h"
#include "wri_crush_ln.h"

#include <errno.h>
#include <sys/stat.h>
#include <time.h>

/* ---- small helpers ---------------------------------------------------------------------------------------- */

#define W_IN 0x10000u
#define WORK_DEFAULT 1000000u
#define NONE_ITEM 0x7fffffff

static const char *seed_dir; /* set by --emit-seeds */

static int legacy_list, legacy_uniform, legacy_perm; /* which legacy choosers this build has (probed once) */

typedef struct cmap {
	uint8_t *room;
	size_t used;
	wri_crush *c;
} cmap;

static int cm_load(cmap *m, const uint8_t *blob, size_t n)
{
	size_t cap = n * 4u + 65536u;
	wr_errinfo why;

	memset(&why, 0, sizeof(why));
	m->room = (uint8_t *)malloc(cap);
	m->used = 0;
	m->c = NULL;
	if (m->room == NULL)
		abort();
	if (wri_crush_decode(blob, n, m->room, cap, &m->used, &why) != WR_OK) {
		fprintf(stderr, "decode failed: %s\n", why.what ? why.what : "?");
		free(m->room);
		m->room = NULL;
		return -1;
	}
	m->c = (wri_crush *)(void *)m->room;
	return 0;
}

static void cm_free(cmap *m)
{
	free(m->room);
	m->room = NULL;
	m->c = NULL;
}

static int cm_from_mg(cmap *m, const wrt_mg_crush *mg)
{
	wrt_mg_buf b;
	int rc;

	memset(&b, 0, sizeof(b));
	if (wrt_mg_crush_encode(mg, &b) != 0)
		return -1;
	rc = cm_load(m, b.p, b.len);
	wrt_mg_buf_free(&b);
	return rc;
}

/* One mapping. `work` is in/out: the budget (0 = default) and what is left. */
static wr_status run_map(const wri_crush *c, uint32_t rule, uint32_t x, uint32_t nrep, const uint32_t *w, uint32_t wmax,
			 int32_t pool, int32_t *res, uint32_t *n, uint32_t *work, wr_errinfo *why)
{
	wri_crush_ws ws;
	wri_crush_in in;
	wr_status st;

	memset(&ws, 0, sizeof(ws));
	ws.work = (work != NULL && *work != 0u) ? *work : WORK_DEFAULT;
	in.rule = rule;
	in.x = x;
	in.result_max = nrep;
	in.osd_weight = w;
	in.weight_max = wmax;
	in.args_pool = pool;
	*n = 0xdeadu;
	st = wri_crush_do_rule(c, &in, &ws, res, n, why);
	if (work != NULL)
		*work = ws.work;
	return st;
}

static uint32_t *all_in(uint32_t n)
{
	uint32_t *w = (uint32_t *)malloc((n ? n : 1u) * sizeof(uint32_t)), i;

	if (w == NULL)
		abort();
	for (i = 0; i < n; i++)
		w[i] = W_IN;
	return w;
}

static int eq_list(const int32_t *a, uint32_t na, const int32_t *b, uint32_t nb)
{
	uint32_t i;

	if (na != nb)
		return 0;
	for (i = 0; i < na; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static void fmt_list(char *out, size_t cap, const int32_t *a, uint32_t n)
{
	uint32_t i;
	size_t k = 0;

	out[0] = 0;
	for (i = 0; i < n && k + 16 < cap; i++)
		k += (size_t)snprintf(out + k, cap - k, "%s%d", i ? "," : "", (int)a[i]);
}

/* What the compact region holds, as far as the skip rules need. */
typedef struct mapfacts {
	int has_tree, has_legacy, fallback;
} mapfacts;

static void map_facts(const wri_crush *c, mapfacts *f)
{
	uint32_t slot;

	memset(f, 0, sizeof(*f));
	for (slot = 0; slot < c->max_buckets; slot++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, slot);

		if (b == NULL)
			continue;
		if (b->alg == WRI_CRUSH_ALG_TREE)
			f->has_tree = 1;
		if (b->alg == WRI_CRUSH_ALG_LIST || b->alg == WRI_CRUSH_ALG_UNIFORM)
			f->has_legacy = 1;
	}
	f->fallback = c->tun.choose_local_fallback_tries > 0;
}

static int rule_has_op(const wri_crush *c, uint32_t rule, uint32_t op)
{
	const wri_crule *r = wri_crush_rule(c, rule);
	uint32_t i;

	if (r == NULL)
		return 0;
	for (i = 0; i < r->nsteps; i++)
		if (wri_crule_steps(r)[i].op == op)
			return 1;
	return 0;
}

static int rule_sets_fallback(const wri_crush *c, uint32_t rule)
{
	const wri_crule *r = wri_crush_rule(c, rule);
	uint32_t i;

	if (r == NULL)
		return 0;
	for (i = 0; i < r->nsteps; i++)
		if (wri_crule_steps(r)[i].op == WRI_CRUSH_OP_SET_CHOOSE_LOCAL_FALLBACK_TRIES && wri_crule_steps(r)[i].arg1 > 0)
			return 1;
	return 0;
}

/* Probe the legacy choosers of module crush-legacy on a one-item bucket. */
static void probe_legacy(void)
{
	uint32_t buf[8];
	wri_cbucket b;
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	int32_t item = 0;

	memset(buf, 0, sizeof(buf));
	memset(&b, 0, sizeof(b));
	b.id = -1;
	b.alg = (uint8_t)WRI_CRUSH_ALG_LIST;
	b.size = 1;
	memcpy(buf, &b, sizeof(b));
	buf[4] = 0;     /* item */
	buf[5] = W_IN;  /* item weight */
	buf[6] = W_IN;  /* sum */
	legacy_list = wri_crush_choose_list((const wri_cbucket *)(const void *)buf, 0, 0, &item) != WR_E_CRUSH_UNSUPPORTED;
	((wri_cbucket *)(void *)buf)->alg = (uint8_t)WRI_CRUSH_ALG_UNIFORM;
	legacy_uniform = wri_crush_choose_uniform((const wri_cbucket *)(const void *)buf, 0, 0, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
	legacy_perm = wri_crush_choose_perm((const wri_cbucket *)(const void *)buf, 0, 0, perm, &item) != WR_E_CRUSH_UNSUPPORTED;
	printf("legacy choosers present: list %d uniform %d permutation %d\n", legacy_list, legacy_uniform, legacy_perm);
}

static int legacy_all(void)
{
	return legacy_list && legacy_uniform && legacy_perm;
}

/* ---- seeds for the fuzz target ----------------------------------------------------------------------------- */

static unsigned seed_count;

/* Input of fuzz_crush_map: rule, result_max - 1, x (le32), args_pool, work exponent, nw, nw le16 weights, then the blob. */
static void seed_write(const char *name, const uint8_t *blob, size_t n, uint32_t rule, uint32_t rmax, uint32_t x, int pool,
		       uint32_t nw)
{
	char path[512];
	FILE *f;
	uint8_t hdr[9];
	uint32_t i;

	if (seed_dir == NULL)
		return;
	hdr[0] = (uint8_t)rule;
	hdr[1] = (uint8_t)(rmax - 1u);
	hdr[2] = (uint8_t)x;
	hdr[3] = (uint8_t)(x >> 8);
	hdr[4] = (uint8_t)(x >> 16);
	hdr[5] = (uint8_t)(x >> 24);
	hdr[6] = (uint8_t)(int8_t)pool;
	hdr[7] = 17;
	hdr[8] = (uint8_t)nw;
	snprintf(path, sizeof(path), "%s/%s", seed_dir, name);
	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "cannot write %s\n", path);
		exit(1);
	}
	fwrite(hdr, 1, sizeof(hdr), f);
	for (i = 0; i < nw; i++) { /* every fifth device out, one half in */
		uint16_t v = (i % 5u == 3u) ? 0u : ((i % 7u == 2u) ? 0x8000u : 0xffffu);

		fputc(v & 0xff, f);
		fputc(v >> 8, f);
	}
	if (n != 0 && fwrite(blob, 1, n, f) != n)
		exit(1);
	fclose(f);
	seed_count++;
}

/* ---- the oracle: a plain recursive reading of the note, over the generator's description structs ------------ */

typedef struct ora {
	const wrt_mg_crush *m;
	int32_t max_dev;
	int32_t pool;
	const uint32_t *wt;
	uint32_t wmax;
	uint32_t x;
	unsigned flags; /* 1: reached a tree bucket, 2: needed a legacy chooser (list, uniform, permutation) */
	uint32_t tries, leaf_tries, lt, lf, vary_r, stable, once;
} ora;

#define OF_TREE 1u
#define OF_LEGACY 2u

static const wrt_mg_bucket *o_bucket(const ora *o, int32_t id)
{
	uint32_t slot;
	const wrt_mg_bucket *b;

	if (id >= 0)
		return NULL;
	slot = (uint32_t)(-1 - id);
	if (slot >= o->m->buckets.n)
		return NULL;
	b = &WRT_MG_E(o->m->buckets, wrt_mg_bucket, slot);
	return b->present ? b : NULL;
}

static const wrt_mg_carg *o_args(const ora *o, const wrt_mg_bucket *b)
{
	const wrt_mg_cset *set = NULL;
	uint32_t i, slot = (uint32_t)(-1 - b->id);

	for (i = 0; i < o->m->choose_args.n; i++) {
		const wrt_mg_cset *s = &WRT_MG_E(o->m->choose_args, wrt_mg_cset, i);

		if (s->key == (int64_t)o->pool) {
			set = s;
			break;
		}
		if (s->key == -1)
			set = s;
	}
	if (set == NULL)
		return NULL;
	for (i = 0; i < set->bucks.n; i++)
		if (WRT_MG_E(set->bucks, wrt_mg_carg, i).index == slot)
			return &WRT_MG_E(set->bucks, wrt_mg_carg, i);
	return NULL;
}

static int32_t o_straw2(const ora *o, const wrt_mg_bucket *b, uint32_t r, uint32_t pos)
{
	const wrt_mg_carg *a = o_args(o, b);
	uint32_t i, best = 0;
	int64_t best_draw = 0;

	for (i = 0; i < b->items.n; i++) {
		uint32_t w = WRT_MG_E(b->item_weights, uint32_t, i);
		int32_t id = WRT_MG_E(b->items, int32_t, i);
		int64_t draw;

		if (a != NULL && a->rows.n > 0) {
			uint32_t row = pos < a->rows.n ? pos : a->rows.n - 1u;

			w = WRT_MG_E(WRT_MG_E(a->rows, wrt_mg_wrow, row).w, uint32_t, i);
		}
		if (a != NULL && a->ids.n > 0)
			id = WRT_MG_E(a->ids, int32_t, i);
		if (w == 0) {
			draw = -0x7fffffffffffffffll - 1;
		} else {
			uint32_t u = wri_crush_hash3(o->x, (uint32_t)id, r) & 0xffffu;
			int64_t ln = (int64_t)wri_crush_ln(u) - 0x1000000000000ll;

			draw = ln / (int64_t)w;
		}
		if (i == 0 || draw > best_draw) {
			best = i;
			best_draw = draw;
		}
	}
	return WRT_MG_E(b->items, int32_t, best);
}

static int32_t o_straw(const ora *o, const wrt_mg_bucket *b, uint32_t r)
{
	uint32_t i, best = 0;
	uint64_t best_draw = 0;

	for (i = 0; i < b->items.n; i++) {
		uint64_t draw = (uint64_t)(wri_crush_hash3(o->x, (uint32_t)WRT_MG_E(b->items, int32_t, i), r) & 0xffffu) *
				WRT_MG_E(b->straws, uint32_t, i);

		if (i == 0 || draw > best_draw) {
			best = i;
			best_draw = draw;
		}
	}
	return WRT_MG_E(b->items, int32_t, best);
}

static int32_t o_list(const ora *o, const wrt_mg_bucket *b, uint32_t r)
{
	uint32_t i;

	for (i = b->items.n; i-- > 0;) {
		uint64_t w = wri_crush_hash4(o->x, (uint32_t)WRT_MG_E(b->items, int32_t, i), r, (uint32_t)b->id) & 0xffffu;

		w = (w * WRT_MG_E(b->sum_weights, uint32_t, i)) >> 16;
		if (w < WRT_MG_E(b->item_weights, uint32_t, i))
			return WRT_MG_E(b->items, int32_t, i);
	}
	return WRT_MG_E(b->items, int32_t, 0);
}

static int32_t o_perm(const ora *o, const wrt_mg_bucket *b, uint32_t r)
{
	uint32_t size = b->items.n, pr = r % size, p;
	uint32_t perm[1024];

	for (p = 0; p < size; p++)
		perm[p] = p;
	for (p = 0; p <= pr && p + 1u < size; p++) {
		uint32_t j = p + wri_crush_hash3(o->x, (uint32_t)b->id, p) % (size - p), t = perm[p];

		perm[p] = perm[j];
		perm[j] = t;
	}
	return WRT_MG_E(b->items, int32_t, perm[pr]);
}

static int32_t o_choose(ora *o, const wrt_mg_bucket *b, uint32_t r, uint32_t pos, int perm)
{
	if (perm) {
		o->flags |= OF_LEGACY;
		return o_perm(o, b, r);
	}
	switch (b->alg) {
	case WRT_MG_ALG_STRAW2:
		return o_straw2(o, b, r, pos);
	case WRT_MG_ALG_STRAW:
		return o_straw(o, b, r);
	case WRT_MG_ALG_LIST:
		o->flags |= OF_LEGACY;
		return o_list(o, b, r);
	case WRT_MG_ALG_UNIFORM:
		o->flags |= OF_LEGACY;
		return o_perm(o, b, r);
	default:
		o->flags |= OF_TREE;
		return WRT_MG_E(b->items, int32_t, 0);
	}
}

static int o_is_out(const ora *o, int32_t dev)
{
	uint32_t w;

	if ((uint32_t)dev >= o->wmax)
		return 1;
	w = o->wt[dev];
	if (w >= W_IN)
		return 0;
	if (w == 0)
		return 1;
	return (wri_crush_hash2(o->x, (uint32_t)dev) & 0xffffu) >= w;
}

/* choose_firstn of 3.6, recursion included. Returns the final output position. */
static uint32_t o_firstn(ora *o, const wrt_mg_bucket *bk, uint32_t numrep, int32_t type, int32_t *out, uint32_t outpos, uint32_t count,
			 uint32_t tries, uint32_t rtries, int leaf, int32_t *out2, uint32_t parent_r)
{
	uint32_t rep;

	for (rep = o->stable ? 0u : outpos; rep < numrep && count > 0; rep++) {
		uint32_t fails_all = 0;
		int skip = 0, done = 0;

		while (!done && !skip) {
			const wrt_mg_bucket *cur = bk;
			uint32_t fails_here = 0;
			int retry_descent = 0;

			for (;;) {
				uint32_t r = rep + parent_r + fails_all, i;
				int reject = 0, collide = 0;
				int32_t item = 0;
				int32_t itype;

				if (cur->items.n == 0) {
					reject = 1;
				} else {
					int use_perm = o->lf > 0 && fails_here >= cur->items.n / 2u && fails_here > o->lf;

					item = o_choose(o, cur, r, outpos, use_perm);
					if (o->flags & OF_TREE)
						return outpos;
					if (item >= o->max_dev) {
						skip = 1;
						break;
					}
					if (item < 0) {
						const wrt_mg_bucket *nb = o_bucket(o, item);

						if (nb == NULL) { /* a hole: the real mapper refuses; the oracle never gets here (generated maps are whole) */
							skip = 1;
							break;
						}
						itype = nb->type;
					} else {
						itype = 0;
					}
					if (itype != type) {
						if (item >= 0) {
							skip = 1;
							break;
						}
						cur = o_bucket(o, item);
						continue;
					}
					for (i = 0; i < outpos; i++)
						if (out[i] == item)
							collide = 1;
					if (!collide && leaf) {
						if (item < 0) {
							uint32_t sub_r = o->vary_r ? r >> (o->vary_r - 1u) : 0u;

							if (o_firstn(o, o_bucket(o, item), o->stable ? 1u : outpos + 1u, 0, out2, outpos, count, rtries, 0, 0, NULL,
								     sub_r) <= outpos)
								reject = 1;
							if (o->flags & OF_TREE)
								return outpos;
						} else {
							out2[outpos] = item;
						}
					}
					if (!reject && !collide && itype == 0)
						reject = o_is_out(o, item);
				}
				if (reject || collide) {
					fails_all++;
					fails_here++;
					if (collide && fails_here <= o->lt)
						continue;
					if (o->lf > 0 && fails_here <= cur->items.n + o->lf)
						continue;
					if (fails_all < tries) {
						retry_descent = 1;
						break;
					}
					skip = 1;
					break;
				}
				out[outpos] = item;
				done = 1;
				break;
			}
			if (retry_descent)
				continue;
		}
		if (done) {
			outpos++;
			count--;
		}
	}
	return outpos;
}

/* The rule of 3.3. Returns 0, or 1 when the oracle cannot answer (an op it does not model). */
static int o_do_rule(ora *o, uint32_t rule, uint32_t rmax, int32_t *result, uint32_t *n_out)
{
	const wrt_mg_rule *ru = &WRT_MG_E(o->m->rules, wrt_mg_rule, rule);
	int32_t wa[64], oa[64], ca[64];
	int32_t *w = wa, *oo = oa;
	uint32_t wsize = 0, rlen = 0, si;

	o->tries = o->m->choose_total_tries + 1u;
	o->leaf_tries = 0;
	o->lt = o->m->choose_local_tries;
	o->lf = o->m->choose_local_fallback_tries;
	o->vary_r = o->m->chooseleaf_vary_r;
	o->stable = o->m->chooseleaf_stable != 0;
	o->once = o->m->chooseleaf_descend_once != 0;
	o->flags = 0;
	for (si = 0; si < ru->steps.n; si++) {
		const wrt_mg_step *s = &WRT_MG_E(ru->steps, wrt_mg_step, si);

		switch (s->op) {
		case 1:
			if ((s->a1 >= 0 && s->a1 < o->max_dev) || o_bucket(o, s->a1) != NULL) {
				w[0] = s->a1;
				wsize = 1;
			}
			break;
		case 8:
			if (s->a1 > 0)
				o->tries = (uint32_t)s->a1;
			break;
		case 9:
			if (s->a1 > 0)
				o->leaf_tries = (uint32_t)s->a1;
			break;
		case 10:
			if (s->a1 >= 0)
				o->lt = (uint32_t)s->a1;
			break;
		case 11:
			if (s->a1 >= 0)
				o->lf = (uint32_t)s->a1;
			break;
		case 12:
			if (s->a1 >= 0)
				o->vary_r = (uint32_t)s->a1;
			break;
		case 13:
			if (s->a1 >= 0)
				o->stable = s->a1 != 0;
			break;
		case 2:
		case 6: {
			uint32_t osize = 0, i, rt;
			int leaf = s->op == 6;

			if (wsize == 0)
				break;
			rt = o->leaf_tries ? o->leaf_tries : (o->once ? 1u : o->tries);
			for (i = 0; i < wsize; i++) {
				int64_t numrep = s->a1;
				const wrt_mg_bucket *b;

				if (numrep <= 0)
					numrep += (int64_t)rmax;
				if (numrep <= 0)
					continue;
				b = o_bucket(o, w[i]);
				if (b == NULL)
					continue;
				osize += o_firstn(o, b, (uint32_t)numrep, s->a2, oo + osize, 0, rmax - osize, o->tries, rt, leaf, ca + osize, 0);
				if (o->flags & OF_TREE)
					return 0;
			}
			if (leaf)
				for (i = 0; i < osize; i++)
					oo[i] = ca[i];
			{
				int32_t *t = oo;

				oo = w;
				w = t;
			}
			wsize = osize;
			break;
		}
		case 4: {
			uint32_t i;

			for (i = 0; i < wsize && rlen < rmax; i++)
				result[rlen++] = w[i];
			wsize = 0;
			break;
		}
		case 3:
		case 7:
			return 1;
		default:
			break;
		}
	}
	*n_out = rlen;
	return 0;
}

/* ---- the vectors of the lab and of crushtool ---------------------------------------------------------------- */

static unsigned long n_vec_ok, n_vec_skip;
static const wrt_mg_crush *vec_oracle_map; /* set: compare the oracle (not the core) with the expected answers */
static unsigned long n_orcvec_ok, n_orcvec_skip;

/* Compare one mapping with the expected answer. `allow_unsup` says the run may legitimately stop with UNSUPPORTED (bit 0)
 * or with NO_RULE, the answer for a rule that is not a replicated one (bit 1). */
static void vec_compare(const char *tag, const wri_crush *c, uint32_t rule, uint32_t x_in, uint32_t x, uint32_t nrep, const uint32_t *w,
			uint32_t wmax, int32_t pool, const int32_t *want, uint32_t nwant, int allow_unsup)
{
	int32_t got[WRI_CRUSH_RESULT_MAX];
	uint32_t ng = 0;
	wr_status st;

	if (vec_oracle_map != NULL) { /* the oracle against crushtool: it is what the legacy choosers will be held to */
		ora o;
		const wrt_mg_rule *ru = rule < vec_oracle_map->rules.n ? &WRT_MG_E(vec_oracle_map->rules, wrt_mg_rule, rule) : NULL;

		if (ru == NULL || !ru->present)
			return;
		memset(&o, 0, sizeof(o));
		o.m = vec_oracle_map;
		o.max_dev = c->max_devices;
		o.wt = w;
		o.wmax = wmax;
		o.x = x;
		if (o_do_rule(&o, rule, nrep, got, &ng) != 0 || (o.flags & OF_TREE)) {
			n_orcvec_skip++; /* an indep rule, or a tree bucket the oracle does not do */
			return;
		}
		wrt_checks++;
		if (!eq_list(got, ng, want, nwant)) {
			char a[128], b[128];

			wrt_failures++;
			fmt_list(a, sizeof(a), got, ng);
			fmt_list(b, sizeof(b), want, nwant);
			fprintf(stderr, "oracle %s: rule %u x %u (input %u) numrep %u: got [%s] want [%s]\n", tag, rule, x, x_in, nrep, a, b);
		}
		n_orcvec_ok++;
		return;
	}
	st = run_map(c, rule, x, nrep, w, wmax, pool, got, &ng, NULL, NULL);
	if (st == WR_OK) {
		wrt_checks++;
		if (!eq_list(got, ng, want, nwant)) {
			char a[128], b[128];

			wrt_failures++;
			fmt_list(a, sizeof(a), got, ng);
			fmt_list(b, sizeof(b), want, nwant);
			fprintf(stderr, "%s: rule %u x %u (input %u) numrep %u: got [%s] want [%s]\n", tag, rule, x, x_in, nrep, a, b);
		}
		n_vec_ok++;
		return;
	}
	wrt_checks++;
	if ((st == WR_E_CRUSH_UNSUPPORTED && (allow_unsup & 1)) || (st == WR_E_CRUSH_NO_RULE && (allow_unsup & 2))) {
		n_vec_skip++;
		return;
	}
	wrt_failures++;
	fprintf(stderr, "%s: rule %u x %u numrep %u: status %d (%s)\n", tag, rule, x, nrep, (int)st, wrt_status_name_(st));
}

static int load_blob_vec(cmap *m, const char *rel)
{
	uint8_t *blob;
	size_t n;
	int rc;

	if (wrt_mg_load_hex_file(wrt_vec_path(rel), &blob, &n) != 0) {
		fprintf(stderr, "cannot read %s\n", rel);
		return -1;
	}
	rc = cm_load(m, blob, n);
	free(blob);
	return rc;
}

static uint32_t jint(const wrt_json *j, wrt_tok t, int *ok)
{
	return (uint32_t)wrt_json_int(j, t, ok);
}

/* osdmap/crush-mappings.json: {"sets": {name: {rule, num_rep, pool_id_hash, mappings: [[x, [osds]], ...]}}} on the epoch-42 blob. */
static void check_osdmap_vectors(void)
{
	wrt_json j;
	cmap m;
	wrt_tok sets, v;
	size_t i, k, e;
	uint32_t *w;

	if (load_blob_vec(&m, "osdmap/crush-embedded.hex") != 0 || wrt_json_load_vec(&j, "osdmap/crush-mappings.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	w = all_in((uint32_t)m.c->max_devices);
	sets = wrt_json_get(&j, wrt_json_root(&j), "sets");
	WRT_CHECK(wrt_json_count(&j, sets) == 4);
	for (i = 0; i < wrt_json_count(&j, sets); i++) {
		const char *name = wrt_json_key_at(&j, sets, i, &v);
		int ok, has_pool;
		uint32_t rule = jint(&j, wrt_json_get(&j, v, "rule"), &ok), nrep = jint(&j, wrt_json_get(&j, v, "num_rep"), &ok);
		uint32_t pool = jint(&j, wrt_json_get(&j, v, "pool_id_hash"), &has_pool);
		wrt_tok mp = wrt_json_get(&j, v, "mappings");

		WRT_CHECK(wrt_json_count(&j, mp) == 300);
		for (k = 0; k < wrt_json_count(&j, mp); k++) {
			wrt_tok row = wrt_json_at(&j, mp, k), lst = wrt_json_at(&j, row, 1);
			uint32_t x = jint(&j, wrt_json_at(&j, row, 0), &ok), want_n = (uint32_t)wrt_json_count(&j, lst);
			int32_t want[WRI_CRUSH_RESULT_MAX];

			for (e = 0; e < want_n && e < WRI_CRUSH_RESULT_MAX; e++)
				want[e] = (int32_t)jint(&j, wrt_json_at(&j, lst, e), &ok);
			vec_compare(name, m.c, rule, x, has_pool ? wri_crush_hash2(x, pool) : x, nrep, w, (uint32_t)m.c->max_devices, 0, want,
				    want_n, 0);
		}
	}
	free(w);
	wrt_json_free(&j);
	cm_free(&m);
}

/* crush/crushtool-mappings.json on the getcrushmap blob. */
static void check_crushtool_vectors(void)
{
	wrt_json j;
	cmap m;
	wrt_tok runs, v;
	size_t i, k, e;

	if (load_blob_vec(&m, "crush/crush-getcrushmap.hex") != 0 || wrt_json_load_vec(&j, "crush/crushtool-mappings.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	runs = wrt_json_get(&j, wrt_json_root(&j), "runs");
	WRT_CHECK(wrt_json_count(&j, runs) == 8);
	for (i = 0; i < wrt_json_count(&j, runs); i++) {
		const char *name = wrt_json_key_at(&j, runs, i, &v);
		int ok, has_pool;
		uint32_t rule = jint(&j, wrt_json_get(&j, v, "rule"), &ok), nrep = jint(&j, wrt_json_get(&j, v, "num_rep"), &ok);
		uint32_t pool = jint(&j, wrt_json_get(&j, v, "pool_id_hash2_applied_by_tool"), &has_pool);
		wrt_tok dw = wrt_json_get(&j, v, "device_weights"), xr = wrt_json_get(&j, v, "x_to_result");
		uint32_t nd = (uint32_t)wrt_json_count(&j, dw), *w = (uint32_t *)malloc((nd ? nd : 1u) * sizeof(uint32_t));

		for (k = 0; k < nd; k++)
			w[k] = jint(&j, wrt_json_at(&j, dw, k), &ok);
		WRT_CHECK(wrt_json_count(&j, xr) == 64);
		for (k = 0; k < wrt_json_count(&j, xr); k++) {
			wrt_tok lst = wrt_json_at(&j, xr, k);
			uint32_t want_n = (uint32_t)wrt_json_count(&j, lst);
			int32_t want[WRI_CRUSH_RESULT_MAX];

			for (e = 0; e < want_n && e < WRI_CRUSH_RESULT_MAX; e++)
				want[e] = (int32_t)jint(&j, wrt_json_at(&j, lst, e), &ok);
			vec_compare(name, m.c, rule, (uint32_t)k, has_pool ? wri_crush_hash2((uint32_t)k, pool) : (uint32_t)k, nrep, w, nd, 0, want,
				    want_n, 0);
		}
		free(w);
	}
	wrt_json_free(&j);
	cm_free(&m);
}

static const char *const mapb_maps[] = {
	"cm01-host-straw-rack-list-root-uniform", "cm02-host-tree-rack-tree-root-straw2", "cm03-host-list-rack-straw-root-tree",
	"cm04-host-uniform-rack-straw2-root-list", "cm05-all-straw2-unequal", "cm06-all-straw-unequal-calc1",
	"cm07-all-straw-unequal-calc0", "cm08-argonaut-uniform-list-tree", "cm09-bobtail-list-straw-tree",
	"cm10-firefly-tree-tree-straw2", "cm11-hammer-straw2", "cm12-argonaut-fallback-stress", "cm13-device-classes",
	"cm13b-device-classes-hdd-rule0", "cm14a-choose-args-key0-positional", "cm14b-choose-args-key0-flat",
	"cm14c-choose-args-pool1-and-compat", "cm15-choose-args-zero"};

/* public/mapb/crush: 18 offline maps and the crushtool results over them; oracle_mode runs the oracle instead of the core. */
static void check_mapb_vectors(int oracle_mode)
{
	size_t mi;
	unsigned long runs_total = 0, indep_runs = 0;

	for (mi = 0; mi < sizeof(mapb_maps) / sizeof(mapb_maps[0]); mi++) {
		char rel[256], tag[96];
		wrt_json j;
		cmap m;
		wrt_tok runs, v;
		mapfacts f;
		size_t i, k, e;
		uint32_t nd;
		wrt_mg_crush omg;

		snprintf(rel, sizeof(rel), "public/mapb/crush/%s.crush.hex", mapb_maps[mi]);
		if (load_blob_vec(&m, rel) != 0) {
			WRT_CHECK(0);
			continue;
		}
		snprintf(rel, sizeof(rel), "public/mapb/crush/%s.mappings.json", mapb_maps[mi]);
		if (wrt_json_load_vec(&j, rel) != 0) {
			WRT_CHECK(0);
			cm_free(&m);
			continue;
		}
		map_facts(m.c, &f);
		nd = (uint32_t)m.c->max_devices;
		if (oracle_mode) {
			uint8_t *blob;
			size_t bn;

			snprintf(rel, sizeof(rel), "public/mapb/crush/%s.crush.hex", mapb_maps[mi]);
			if (wrt_mg_load_hex_file(wrt_vec_path(rel), &blob, &bn) != 0 || wrt_mg_crush_parse(blob, bn, &omg) != 0) {
				WRT_CHECK(0);
				continue;
			}
			free(blob);
			vec_oracle_map = &omg;
		}
		runs = wrt_json_get(&j, wrt_json_root(&j), "runs");
		for (i = 0; i < wrt_json_count(&j, runs); i++) {
			const char *name = wrt_json_key_at(&j, runs, i, &v);
			int ok, has_pool, has_min;
			uint32_t rule = jint(&j, wrt_json_get(&j, v, "rule"), &ok), nrep = jint(&j, wrt_json_get(&j, v, "num_rep"), &ok);
			uint32_t minx = jint(&j, wrt_json_get(&j, v, "min_x"), &has_min), pool = jint(&j, wrt_json_get(&j, v, "pool_id"), &has_pool);
			wrt_tok xr = wrt_json_get(&j, v, "x_to_result"), wm = wrt_json_get(&j, v, "weights");
			uint32_t *w = all_in(nd);
			/* an erasure rule (type 3) is not stored: NO_RULE; an indep step inside a type 1 rule: UNSUPPORTED */
			int other = wri_crush_rule_kind(m.c, rule) == 1u;
			int indep = other || rule_has_op(m.c, rule, WRI_CRUSH_OP_CHOOSE_INDEP) || rule_has_op(m.c, rule, WRI_CRUSH_OP_CHOOSELEAF_INDEP);
			int allow = (other ? 2 : 0) | ((indep && !other) || f.has_tree || (!legacy_all() && (f.has_legacy || f.fallback || rule_sets_fallback(m.c, rule))) ? 1 : 0);

			if (!has_min)
				minx = 0;
			if (wm != WRT_NONE) {
				for (k = 0; k < wrt_json_count(&j, wm); k++) {
					wrt_tok val;
					const char *dev = wrt_json_key_at(&j, wm, k, &val);
					int vok;
					int64_t iv = wrt_json_int(&j, val, &vok);
					uint32_t d = (uint32_t)strtoul(dev, NULL, 10);

					/* the files hold 0 and 0.5 only: a non-integer is the half weight */
					if (d < nd)
						w[d] = vok ? (uint32_t)(iv * (int64_t)W_IN) : W_IN / 2u;
				}
			}
			snprintf(tag, sizeof(tag), "%s/%s", mapb_maps[mi], name);
			runs_total++;
			indep_runs += (unsigned long)indep;
			for (k = 0; k < wrt_json_count(&j, xr); k++) {
				wrt_tok lst = wrt_json_at(&j, xr, k);
				uint32_t want_n = (uint32_t)wrt_json_count(&j, lst), x = minx + (uint32_t)k;
				int32_t want[WRI_CRUSH_RESULT_MAX];

				for (e = 0; e < want_n && e < WRI_CRUSH_RESULT_MAX; e++)
					want[e] = (int32_t)jint(&j, wrt_json_at(&j, lst, e), &ok);
				/* crushtool --test asks for choose_args key 0 (then -1); --pool-id only changes the hash of x */
				vec_compare(tag, m.c, rule, x, has_pool ? wri_crush_hash2(x, pool) : x, nrep, w, nd, 0, want, want_n, allow);
				if (indep && !oracle_mode) {
					int32_t got[WRI_CRUSH_RESULT_MAX];
					uint32_t ng;

					WRT_CHECK_STATUS(other ? WR_E_CRUSH_NO_RULE : WR_E_CRUSH_UNSUPPORTED,
							 run_map(m.c, rule, x, nrep, w, nd, 0, got, &ng, NULL, NULL));
				}
			}
			free(w);
		}
		if (oracle_mode) {
			vec_oracle_map = NULL;
			wrt_mg_crush_free(&omg);
		}
		wrt_json_free(&j);
		cm_free(&m);
	}
	WRT_CHECK(runs_total == 130);
	if (!oracle_mode)
		printf("mapb vectors: %lu runs, %lu of them indep rules\n", runs_total, indep_runs);
}

/* ---- the in-tree crushtool known-answer files (optional) ------------------------------------------------------ */

typedef struct tcase {
	char map[600];
	int have_rule;
	uint32_t rule, minrep;
	int nw;
	uint32_t wdev[64], wval[64];
	int64_t set[6]; /* local tries, local fallback tries, total tries, descend once, vary_r, stable; -1 = not given */
} tcase;

typedef struct texp {
	uint32_t nr, x, rule, n;
	int32_t res[WRI_CRUSH_RESULT_MAX];
} texp;

static unsigned long tree_ok, tree_skip, tree_files;
static uint32_t tree_xmax = 128; /* x below this are compared; WRT_CRUSH_TREE_X (up to 1024, the whole files) raises it */

static int parse_t_file(const char *path, const char *testdir, tcase *tc, texp **out, size_t *nout)
{
	uint8_t *txt;
	size_t n, pos = 0, cnt = 0, cap = 0;
	int seen_cmd = 0;
	uint32_t lastx = 0, nr = 0;
	int have_last = 0;
	texp *ex = NULL;

	if (wrt_read_file(path, &txt, &n) != 0)
		return -1;
	memset(tc, 0, sizeof(*tc));
	tc->minrep = 1;
	{
		int s;

		for (s = 0; s < 6; s++)
			tc->set[s] = -1;
	}
	while (pos < n) {
		size_t eol = pos;
		char line[4096];
		size_t len;

		while (eol < n && txt[eol] != '\n')
			eol++;
		len = eol - pos;
		if (len >= sizeof(line))
			len = sizeof(line) - 1u;
		memcpy(line, txt + pos, len);
		line[len] = 0;
		pos = eol + 1u;
		if (strncmp(line, "  $ ", 4) == 0) {
			char *tok[96], *p = line + 4;
			int nt = 0, ti;

			if (seen_cmd)
				break;
			seen_cmd = 1;
			while (*p != 0 && nt < 96) {
				while (*p == ' ')
					p++;
				if (*p == 0)
					break;
				tok[nt++] = p;
				while (*p != 0 && *p != ' ')
					p++;
				if (*p != 0)
					*p++ = 0;
			}
			for (ti = 1; ti < nt; ti++) {
				const char *t = tok[ti];

				if (strcmp(t, "-i") == 0 && ti + 1 < nt) {
					const char *mp = tok[ti + 1];
					const char *td = strstr(mp, "$TESTDIR");

					if (mp[0] == '"')
						mp++;
					td = strstr(mp, "$TESTDIR");
					if (td != NULL) {
						size_t tail = strlen(td + 8);
						char *q;

						snprintf(tc->map, sizeof(tc->map), "%s%s", testdir, td + 8);
						q = tc->map + strlen(tc->map);
						if (tail > 0 && q[-1] == '"')
							q[-1] = 0;
					} else {
						snprintf(tc->map, sizeof(tc->map), "%s", mp);
					}
					ti++;
				} else if (strcmp(t, "--rule") == 0 && ti + 1 < nt) {
					tc->have_rule = 1;
					tc->rule = (uint32_t)strtoul(tok[ti + 1], NULL, 10);
					ti++;
				} else if (strcmp(t, "--weight") == 0 && ti + 2 < nt) {
					if (tc->nw < 64) {
						tc->wdev[tc->nw] = (uint32_t)strtoul(tok[ti + 1], NULL, 10);
						tc->wval[tc->nw] = (uint32_t)(strtod(tok[ti + 2], NULL) * 65536.0);
						tc->nw++;
					}
					ti += 2;
				} else if ((strcmp(t, "--min-rep") == 0 || strcmp(t, "--num-rep") == 0) && ti + 1 < nt) {
					tc->minrep = (uint32_t)strtoul(tok[ti + 1], NULL, 10);
					ti++;
				} else if (strcmp(t, "--set-choose-local-tries") == 0 && ti + 1 < nt) {
					tc->set[0] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-choose-local-fallback-tries") == 0 && ti + 1 < nt) {
					tc->set[1] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-choose-total-tries") == 0 && ti + 1 < nt) {
					tc->set[2] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-descend-once") == 0 && ti + 1 < nt) {
					tc->set[3] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-vary-r") == 0 && ti + 1 < nt) {
					tc->set[4] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-stable") == 0 && ti + 1 < nt) {
					tc->set[5] = strtol(tok[++ti], NULL, 10);
				}
			}
			continue;
		}
		if (strncmp(line, "  CRUSH rule ", 13) == 0) {
			unsigned rr, xx;
			const char *lb = strchr(line, '[');
			texp e;

			if (sscanf(line, "  CRUSH rule %u x %u", &rr, &xx) != 2 || lb == NULL)
				continue;
			if (!have_last || xx <= lastx)
				nr++;
			have_last = 1;
			lastx = xx;
			e.nr = nr + tc->minrep - 1u;
			e.x = xx;
			e.rule = rr;
			e.n = 0;
			lb++;
			while (*lb != ']' && *lb != 0) {
				if (e.n < WRI_CRUSH_RESULT_MAX)
					e.res[e.n++] = (int32_t)strtol(lb, (char **)&lb, 10);
				else
					strtol(lb, (char **)&lb, 10);
				while (*lb == ',' || *lb == ' ')
					lb++;
			}
			if (cnt == cap) {
				cap = cap ? cap * 2u : 4096u;
				ex = (texp *)realloc(ex, cap * sizeof(texp));
				if (ex == NULL)
					abort();
			}
			ex[cnt++] = e;
		}
	}
	free(txt);
	*out = ex;
	*nout = cnt;
	return seen_cmd ? 0 : -1;
}

static void check_tree_known_answers(void)
{
	static const char *const files[] = {"test-map-jewel-tunables.t", "test-map-hammer-tunables.t", "test-map-legacy-tunables.t",
					    "test-map-bobtail-tunables.t", "test-map-firefly-tunables.t", "test-map-tries-vs-retries.t",
					    "test-map-vary-r-0.t", "test-map-vary-r-1.t", "test-map-vary-r-2.t", "test-map-vary-r-3.t",
					    "test-map-vary-r-4.t"};
	const char *src = getenv("WINRBD_CEPH_SRC");
	char testdir[512];
	size_t fi;

	if (src == NULL || *src == 0) {
		printf("in-tree crushtool known answers: skipped (WINRBD_CEPH_SRC not set)\n");
		return;
	}
	snprintf(testdir, sizeof(testdir), "%s/src/test/cli/crushtool", src);
	if (getenv("WRT_CRUSH_TREE_X") != NULL)
		tree_xmax = (uint32_t)strtoul(getenv("WRT_CRUSH_TREE_X"), NULL, 10);
	for (fi = 0; fi < sizeof(files) / sizeof(files[0]); fi++) {
		char path[700];
		tcase tc;
		texp *ex = NULL;
		size_t nex = 0, i;
		uint8_t *blob;
		size_t bn;
		cmap m;
		uint32_t *w, nd, rule;
		mapfacts f;
		uint8_t *inb;
		uint32_t slot;
		int s;

		snprintf(path, sizeof(path), "%s/%s", testdir, files[fi]);
		if (parse_t_file(path, testdir, &tc, &ex, &nex) != 0 || nex == 0) {
			printf("in-tree crushtool known answers: %s missing or empty, skipped\n", files[fi]);
			free(ex);
			continue;
		}
		if (wrt_read_file(tc.map, &blob, &bn) != 0) {
			printf("in-tree crushtool known answers: %s missing, skipped\n", tc.map);
			free(ex);
			continue;
		}
		if (cm_load(&m, blob, bn) != 0) {
			WRT_CHECK(0);
			free(blob);
			free(ex);
			continue;
		}
		free(blob);
		for (s = 0; s < 6; s++) {
			uint32_t v;

			if (tc.set[s] < 0)
				continue;
			v = (uint32_t)tc.set[s];
			switch (s) {
			case 0: m.c->tun.choose_local_tries = v; break;
			case 1: m.c->tun.choose_local_fallback_tries = v; break;
			case 2: m.c->tun.choose_total_tries = v; break;
			case 3: m.c->tun.chooseleaf_descend_once = v; break;
			case 4: m.c->tun.chooseleaf_vary_r = (uint8_t)v; break;
			default: m.c->tun.chooseleaf_stable = (uint8_t)v; break;
			}
		}
		nd = (uint32_t)m.c->max_devices;
		w = (uint32_t *)calloc(nd ? nd : 1u, sizeof(uint32_t));
		inb = (uint8_t *)calloc(nd ? nd : 1u, 1);
		for (slot = 0; slot < m.c->max_buckets; slot++) {
			const wri_cbucket *b = wri_crush_bucket_at(m.c, slot);
			uint32_t k;

			if (b == NULL)
				continue;
			for (k = 0; k < b->size; k++)
				if (wri_cbucket_items(b)[k] >= 0 && (uint32_t)wri_cbucket_items(b)[k] < nd)
					inb[wri_cbucket_items(b)[k]] = 1;
		}
		for (i = 0; i < nd; i++)
			w[i] = inb[i] ? W_IN : 0u;
		for (i = 0; i < (size_t)tc.nw; i++)
			if (tc.wdev[i] < nd)
				w[tc.wdev[i]] = tc.wval[i];
		rule = tc.have_rule ? tc.rule : ex[0].rule;
		map_facts(m.c, &f);
		for (i = 0; i < nex; i++) {
			int allow = (f.has_tree || (!legacy_all() && (f.has_legacy || f.fallback))) ? 1 : 0;
			int32_t got[WRI_CRUSH_RESULT_MAX];
			uint32_t ng = 0;
			wr_status st;

			if (ex[i].rule != rule || ex[i].x >= tree_xmax)
				continue;
			st = run_map(m.c, rule, ex[i].x, ex[i].nr, w, nd, 0, got, &ng, NULL, NULL);
			wrt_checks++;
			if (st == WR_OK) {
				if (!eq_list(got, ng, ex[i].res, ex[i].n)) {
					char a[160], b[160];

					wrt_failures++;
					fmt_list(a, sizeof(a), got, ng);
					fmt_list(b, sizeof(b), ex[i].res, ex[i].n);
					fprintf(stderr, "%s: rule %u x %u numrep %u: got [%s] want [%s]\n", files[fi], rule, ex[i].x, ex[i].nr, a, b);
				}
				tree_ok++;
			} else if (st == WR_E_CRUSH_UNSUPPORTED && allow) {
				tree_skip++;
			} else {
				wrt_failures++;
				fprintf(stderr, "%s: rule %u x %u numrep %u: status %d\n", files[fi], rule, ex[i].x, ex[i].nr, (int)st);
			}
		}
		tree_files++;
		free(w);
		free(inb);
		free(ex);
		cm_free(&m);
	}
	printf("in-tree crushtool known answers: %lu files, %lu mappings compared, %lu skipped\n", tree_files, tree_ok, tree_skip);
	WRT_CHECK(tree_files == 0 || tree_files == sizeof(files) / sizeof(files[0]));
}

/* ---- generated hierarchies ----------------------------------------------------------------------------------- */

typedef struct hspec {
	int tun;
	uint8_t alg_host, alg_rack, alg_root;
	uint32_t racks, hpr, dph; /* racks (0 = none: root holds the hosts), hosts per rack (or hosts in total when flat), devices per host */
	int jitter;
	int cargs; /* 0 none, 1 default set + a set for pool 1 */
	uint64_t seed;
} hspec;

#define T_HOST 1
#define T_RACK 3
#define T_ROOT 11

static void add_rule(wrt_mg_crush *m, uint32_t slot, const wrt_mg_step *st, uint32_t n)
{
	WRT_CHECK(wrt_mg_crush_add_rule(m, slot, 1, st, n) == (int)slot);
}

static void make_cargs(wrt_mg_crush *m, int32_t key, uint64_t seed)
{
	wrt_mg_cset cs;
	wrt_mg_rng rng;
	uint32_t slot;

	wrt_mg_rng_seed(&rng, seed);
	memset(&cs, 0, sizeof(cs));
	cs.key = key;
	for (slot = 0; slot < m->buckets.n; slot++) {
		const wrt_mg_bucket *b = &WRT_MG_E(m->buckets, wrt_mg_bucket, slot);
		wrt_mg_carg ca;
		uint32_t rows, r, i;

		if (!b->present || b->alg != WRT_MG_ALG_STRAW2 || b->items.n == 0)
			continue;
		memset(&ca, 0, sizeof(ca));
		ca.index = slot;
		rows = (slot + (uint32_t)key) % 4u; /* 0 (ids only), 1, 2 or 3 rows */
		for (r = 0; r < rows; r++) {
			wrt_mg_wrow row;

			memset(&row, 0, sizeof(row));
			for (i = 0; i < b->items.n; i++) {
				uint32_t w = WRT_MG_E(b->item_weights, uint32_t, i), pick = wrt_mg_rng_below(&rng, 8);

				if (pick == 0)
					w = 0;
				else if (pick < 4)
					w = w / 2u + wrt_mg_rng_below(&rng, w / 2u + 1u);
				else if (pick < 6)
					w = w + wrt_mg_rng_below(&rng, w + 1u);
				WRT_MG_PUSH(row.w, uint32_t, w);
			}
			WRT_MG_PUSH(ca.rows, wrt_mg_wrow, row);
		}
		if (rows == 0 || (slot % 2u) == 1u) /* substitute ids on half of the buckets, and on every bucket without rows */
			for (i = 0; i < b->items.n; i++)
				WRT_MG_PUSH(ca.ids, int32_t, WRT_MG_E(b->items, int32_t, i) * 3 + 1000 + (int32_t)wrt_mg_rng_below(&rng, 5));
		WRT_MG_PUSH(cs.bucks, wrt_mg_carg, ca);
	}
	WRT_MG_PUSH(m->choose_args, wrt_mg_cset, cs);
}

/* Rules of the matrix: slot -> steps. Types: osd 0, host 1, rack 3. */
#define N_RULES 16

static void build_hier(wrt_mg_crush *m, const hspec *s)
{
	uint32_t n_hosts = s->racks ? s->racks * s->hpr : s->hpr, n_dev = n_hosts * s->dph, h, r, i;
	int32_t first_host = -2 - (int32_t)s->racks;
	uint32_t *dw = (uint32_t *)calloc(n_dev ? n_dev : 1u, sizeof(uint32_t));
	uint32_t *hw = (uint32_t *)calloc(n_hosts ? n_hosts : 1u, sizeof(uint32_t));
	wrt_mg_rng rng;
	int32_t *items = (int32_t *)calloc(n_dev + n_hosts + 4u, sizeof(int32_t));
	uint32_t *wts = (uint32_t *)calloc(n_dev + n_hosts + 4u, sizeof(uint32_t));
	int32_t first_rack_or_host;
	uint32_t root_n = 0;

	wrt_mg_rng_seed(&rng, s->seed);
	wrt_mg_crush_init(m);
	wrt_mg_crush_tunables(m, s->tun);
	for (i = 0; i < n_dev; i++)
		dw[i] = s->jitter ? W_IN / 4u + wrt_mg_rng_below(&rng, W_IN * 2u) : W_IN;
	for (h = 0; h < n_hosts; h++) {
		uint32_t tot = 0;

		for (i = 0; i < s->dph; i++) {
			items[i] = (int32_t)(h * s->dph + i);
			wts[i] = dw[h * s->dph + i];
			tot += wts[i];
		}
		hw[h] = tot;
		WRT_CHECK(wrt_mg_crush_add_bucket(m, first_host - (int32_t)h, T_HOST, s->alg_host, items, wts, s->dph) >= 0);
	}
	if (s->racks) {
		for (r = 0; r < s->racks; r++) {
			uint32_t tot = 0;

			for (i = 0; i < s->hpr; i++) {
				items[i] = first_host - (int32_t)(r * s->hpr + i);
				wts[i] = hw[r * s->hpr + i];
				tot += wts[i];
			}
			WRT_CHECK(wrt_mg_crush_add_bucket(m, -2 - (int32_t)r, T_RACK, s->alg_rack, items, wts, s->hpr) >= 0);
			hw[r] = tot; /* reuse: rack totals (hosts already added) */
		}
		for (r = 0; r < s->racks; r++) {
			items[root_n] = -2 - (int32_t)r;
			wts[root_n++] = hw[r];
		}
	} else {
		for (h = 0; h < n_hosts; h++) {
			items[root_n] = first_host - (int32_t)h;
			wts[root_n++] = hw[h];
		}
	}
	WRT_CHECK(wrt_mg_crush_add_bucket(m, -1, T_ROOT, s->alg_root, items, wts, root_n) >= 0);
	first_rack_or_host = s->racks ? -2 : first_host;

	{
		const wrt_mg_step lf_host[] = {{1, -1, 0}, {6, 0, T_HOST}, {4, 0, 0}};
		const wrt_mg_step ch_osd[] = {{1, -1, 0}, {2, 0, 0}, {4, 0, 0}};
		const wrt_mg_step lf_rack[] = {{1, -1, 0}, {6, 0, T_RACK}, {4, 0, 0}};
		const wrt_mg_step two[] = {{1, -1, 0}, {2, 2, T_RACK}, {6, 2, T_HOST}, {4, 0, 0}};
		const wrt_mg_step sets[] = {{1, -1, 0}, {8, 100, 0}, {9, 5, 0}, {10, 3, 0}, {11, 2, 0}, {6, -1, T_HOST}, {4, 0, 0}};
		const wrt_mg_step vary[] = {{1, -1, 0}, {12, 2, 0}, {13, 1, 0}, {6, 3, T_HOST}, {4, 0, 0}};
		const wrt_mg_step sub[] = {{1, first_rack_or_host, 0}, {2, 0, 0}, {4, 0, 0}};
		const wrt_mg_step blocks[] = {{1, -1, 0}, {6, 1, T_HOST}, {4, 0, 0}, {1, -1, 0}, {2, 2, 0}, {4, 0, 0}};
		const wrt_mg_step lf_osd[] = {{1, -1, 0}, {6, 0, 0}, {4, 0, 0}};
		const wrt_mg_step take_dev[] = {{1, 2, 0}, {4, 0, 0}};
		const wrt_mg_step dev_ch[] = {{1, 2, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step neg[] = {{1, -1, 0}, {2, -1, T_HOST}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step stab0[] = {{1, -1, 0}, {13, 0, 0}, {12, 0, 0}, {9, 1, 0}, {6, 0, T_HOST}, {4, 0, 0}};
		const wrt_mg_step lt[] = {{1, -1, 0}, {10, 4, 0}, {11, 3, 0}, {6, 0, T_HOST}, {99, 7, 7}, {0, 0, 0}, {4, 0, 0}};
		const wrt_mg_step lt_osd[] = {{1, -1, 0}, {10, 3, 0}, {2, 0, 0}, {4, 0, 0}}; /* local retries without the fallback */
		const wrt_mg_step lt_host[] = {{1, -1, 0}, {10, 2, 0}, {6, 0, T_HOST}, {4, 0, 0}};

		add_rule(m, 0, lf_host, 3);
		add_rule(m, 1, ch_osd, 3);
		add_rule(m, 2, s->racks ? lf_rack : lf_host, 3);
		add_rule(m, 3, s->racks ? two : lf_osd, s->racks ? 4u : 3u);
		add_rule(m, 4, sets, 7);
		add_rule(m, 5, vary, 5);
		add_rule(m, 6, sub, 3);
		add_rule(m, 7, blocks, 6);
		add_rule(m, 8, lf_osd, 3);
		add_rule(m, 9, take_dev, 2);
		add_rule(m, 10, dev_ch, 3);
		add_rule(m, 11, neg, 4);
		add_rule(m, 12, stab0, 6);
		add_rule(m, 13, lt, 7);
		add_rule(m, 14, lt_osd, 4);
		add_rule(m, 15, lt_host, 4);
	}
	if (s->cargs) {
		make_cargs(m, -1, s->seed ^ 0x51);
		make_cargs(m, 1, s->seed ^ 0x77);
	}
	free(dw);
	free(hw);
	free(items);
	free(wts);
}

static void make_weights(uint32_t *w, uint32_t n, int scen, wrt_mg_rng *rng)
{
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint32_t d = wrt_mg_rng_below(rng, 10);

		switch (scen) {
		case 1: w[i] = d < 3 ? 0u : W_IN; break;
		case 2: w[i] = d < 4 ? W_IN : 0x2000u + wrt_mg_rng_below(rng, 0xd000u); break;
		case 3: w[i] = 0; break;
		case 4: w[i] = d < 6 ? 0u : 0x1000u + wrt_mg_rng_below(rng, 0xe000u); break;
		case 6: w[i] = d < 2 ? 0u : (d < 5 ? W_IN : 0x8000u); break;
		default: w[i] = W_IN; break;
		}
	}
}

static unsigned long n_orc_cmp, n_orc_unsup, n_orc_maps;

static void orc_case(const char *tag, const wrt_mg_crush *mg, const cmap *cm, uint32_t rule, uint32_t x, uint32_t rmax, const uint32_t *w,
		     uint32_t wmax, int32_t pool)
{
	ora o;
	int32_t want[WRI_CRUSH_RESULT_MAX], got[WRI_CRUSH_RESULT_MAX];
	uint32_t nw = 0, ng = 0;
	wr_status st;
	int unsupported_op;

	memset(&o, 0, sizeof(o));
	o.m = mg;
	o.max_dev = cm->c->max_devices;
	o.pool = pool;
	o.wt = w;
	o.wmax = wmax;
	o.x = x;
	unsupported_op = o_do_rule(&o, rule, rmax, want, &nw);
	st = run_map(cm->c, rule, x, rmax, w, wmax, pool, got, &ng, NULL, NULL);
	n_orc_cmp++;
	wrt_checks++;
	if (unsupported_op || (o.flags & OF_TREE) || ((o.flags & OF_LEGACY) && !legacy_all())) {
		/* the core must refuse at the same point; it only reaches the unsupported chooser if the oracle did */
		if ((o.flags & OF_LEGACY) && !(o.flags & OF_TREE) && !unsupported_op && !legacy_all()) {
			/* a partly present module: it may answer, then it must agree */
			if (st == WR_OK) {
				if (!eq_list(got, ng, want, nw)) {
					wrt_failures++;
					fprintf(stderr, "%s: rule %u x %u numrep %u pool %d: got a different answer from the oracle\n", tag, rule, x, rmax, pool);
				}
				return;
			}
		}
		n_orc_unsup++;
		if (st != WR_E_CRUSH_UNSUPPORTED) {
			wrt_failures++;
			fprintf(stderr, "%s: rule %u x %u numrep %u: want UNSUPPORTED, status %d\n", tag, rule, x, rmax, (int)st);
		}
		return;
	}
	if (st != WR_OK) {
		wrt_failures++;
		fprintf(stderr, "%s: rule %u x %u numrep %u: status %d (%s), oracle has %u results\n", tag, rule, x, rmax, (int)st,
			wrt_status_name_(st), nw);
		return;
	}
	if (!eq_list(got, ng, want, nw)) {
		char a[160], b[160];

		wrt_failures++;
		fmt_list(a, sizeof(a), got, ng);
		fmt_list(b, sizeof(b), want, nw);
		fprintf(stderr, "%s: rule %u x %u numrep %u pool %d: got [%s] oracle [%s]\n", tag, rule, x, rmax, pool, a, b);
	}
	if (ng > rmax) {
		wrt_failures++;
		fprintf(stderr, "%s: %u results for result_max %u\n", tag, ng, rmax);
	}
}

static void orc_run_map(const char *tag, const hspec *s)
{
	wrt_mg_crush mg;
	cmap cm;
	wrt_mg_rng rng;
	uint32_t n_dev, *w, scen, rule, x, ri, xmax;
	static const uint32_t rmaxes[] = {2, 3, 1, 5, 8};
	char t[160];

	build_hier(&mg, s);
	if (cm_from_mg(&cm, &mg) != 0) {
		WRT_CHECK(0);
		wrt_mg_crush_free(&mg);
		return;
	}
	n_orc_maps++;
	n_dev = (uint32_t)cm.c->max_devices;
	w = (uint32_t *)malloc((n_dev + 4u) * sizeof(uint32_t));
	wrt_mg_rng_seed(&rng, s->seed + 99u);
	for (scen = 0; scen < 7; scen++) {
		uint32_t wmax;

		make_weights(w, n_dev, scen, &rng);
		wmax = scen == 5 ? n_dev / 2u : n_dev; /* scenario 5: all in, but the array is half as long as max_devices */
		snprintf(t, sizeof(t), "%s scen %u", tag, scen);
		xmax = scen == 3 ? 2u : (scen == 4 ? 3u : 6u); /* the scenarios with many rejections cost the most per mapping */
		for (rule = 0; rule < N_RULES; rule++) {
			for (x = 0; x < xmax; x++) {
				for (ri = 0; ri < sizeof(rmaxes) / sizeof(rmaxes[0]); ri++) {
					if (ri < 2 ? 0 : x >= 2) /* the counts 1, 5 and 8 on the first two x only */
						continue;
					orc_case(t, &mg, &cm, rule, x * 7u + rule, rmaxes[ri], w, wmax, 0);
					if (s->cargs && ri < 2)
						orc_case(t, &mg, &cm, rule, x * 7u + rule, rmaxes[ri], w, wmax, 1);
				}
			}
		}
	}
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&mg);
}

static void check_oracle_matrix(void)
{
	static const struct {
		uint8_t host, rack, root;
		const char *name;
	} algs[] = {{WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW2, "straw2"},
		    {WRT_MG_ALG_STRAW, WRT_MG_ALG_STRAW, WRT_MG_ALG_STRAW, "straw"},
		    {WRT_MG_ALG_STRAW, WRT_MG_ALG_STRAW2, WRT_MG_ALG_STRAW, "straw/straw2"},
		    {WRT_MG_ALG_UNIFORM, WRT_MG_ALG_LIST, WRT_MG_ALG_STRAW2, "uniform/list/straw2"},
		    {WRT_MG_ALG_STRAW2, WRT_MG_ALG_TREE, WRT_MG_ALG_STRAW2, "tree rack"}};
	static const char *const prof[] = {"legacy", "bobtail", "firefly", "hammer", "jewel"};
	unsigned a, p, shape;
	uint64_t seed = 1;

	for (a = 0; a < sizeof(algs) / sizeof(algs[0]); a++) {
		for (p = 0; p < 5; p++) {
			{
				hspec s;
				char tag[96];

				shape = (a + p) % 3u; /* every algorithm meets every hierarchy shape over the five profiles */

				memset(&s, 0, sizeof(s));
				s.tun = (int)p;
				s.alg_host = algs[a].host;
				s.alg_rack = algs[a].rack;
				s.alg_root = algs[a].root;
				s.racks = shape == 1 ? 0u : 3u;
				s.hpr = shape == 1 ? 7u : (shape == 2 ? 2u : 3u);
				s.dph = shape == 2 ? 5u : 3u;
				s.jitter = (int)((a + p + shape) % 2u);
				s.cargs = algs[a].host == WRT_MG_ALG_STRAW2 && algs[a].root == WRT_MG_ALG_STRAW2 && (p + shape) % 2u == 0u;
				s.seed = seed++;
				snprintf(tag, sizeof(tag), "%s/%s/shape%u", algs[a].name, prof[p], shape);
				orc_run_map(tag, &s);
			}
		}
	}
	/* straw2 everywhere with choose_args on every tunable profile (the sets are only valid on straw2 buckets) */
	for (p = 0; p < 5; p++) {
		hspec s;
		char tag[96];

		memset(&s, 0, sizeof(s));
		s.tun = (int)p;
		s.alg_host = s.alg_rack = s.alg_root = WRT_MG_ALG_STRAW2;
		s.racks = 2;
		s.hpr = 3;
		s.dph = 4;
		s.jitter = 1;
		s.cargs = 1;
		s.seed = 1000u + p;
		snprintf(tag, sizeof(tag), "straw2+args/%s", prof[p]);
		orc_run_map(tag, &s);
	}
	printf("oracle: %lu maps, %lu mappings compared, %lu of them expected to be refused (tree / legacy)\n", n_orc_maps, n_orc_cmp, n_orc_unsup);
	WRT_CHECK(n_orc_cmp > 40000);
}

/* ---- the choosers on hand-built buckets ----------------------------------------------------------------------- */

static uint32_t bkbuf[1024];

/* A bucket record in bkbuf: head, items, tail1 (weights or straws). */
static const wri_cbucket *mk_bucket(int32_t id, uint8_t alg, uint32_t n, const int32_t *items, const uint32_t *tail)
{
	wri_cbucket b;

	memset(&b, 0, sizeof(b));
	b.id = id;
	b.type = 1;
	b.alg = alg;
	b.size = n;
	memcpy(bkbuf, &b, sizeof(b));
	if (n != 0) {
		memcpy(bkbuf + 4, items, n * 4u);
		memcpy(bkbuf + 4 + n, tail, n * 4u);
	}
	return (const wri_cbucket *)(const void *)bkbuf;
}

static uint32_t cabuf[1024];

/* A choose_args record: rows x n weights, then ids when ids != NULL. */
static const wri_cargs *mk_args(uint32_t n, uint32_t rows, const uint32_t *w, const int32_t *ids)
{
	cabuf[0] = rows;
	cabuf[1] = ids != NULL;
	if (rows != 0)
		memcpy(cabuf + 2, w, (size_t)rows * n * 4u);
	if (ids != NULL)
		memcpy(cabuf + 2 + (size_t)rows * n, ids, n * 4u);
	return (const wri_cargs *)(const void *)cabuf;
}

/* The draw of straw2 written out: the index of the best item. */
static uint32_t exp_straw2(uint32_t n, const uint32_t *w, const int32_t *ids, uint32_t x, uint32_t r)
{
	uint32_t i, best = 0;
	int64_t bd = 0;

	for (i = 0; i < n; i++) {
		int64_t d;

		if (w[i] == 0)
			d = -0x7fffffffffffffffll - 1;
		else
			d = ((int64_t)wri_crush_ln(wri_crush_hash3(x, (uint32_t)ids[i], r) & 0xffffu) - 0x1000000000000ll) / (int64_t)w[i];
		if (i == 0 || d > bd) {
			best = i;
			bd = d;
		}
	}
	return best;
}

static void check_choosers(void)
{
	int32_t items[8] = {10, 11, 12, 13, 14, 15, 16, 17}, same[8] = {7, 7, 7, 7, 7, 7, 7, 7};
	uint32_t w1[8] = {W_IN, W_IN, W_IN, W_IN, W_IN, W_IN, W_IN, W_IN};
	uint32_t wz[8] = {0, 0, 0, 0, 0, 0, 0, 0};
	uint32_t x, r, i;
	const wri_cbucket *b;
	wrt_mg_rng rng;

	/* equal weights and equal hash inputs: every draw ties, the first item wins */
	b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 8, items, w1);
	for (x = 0; x < 50; x++)
		WRT_CHECK(wri_crush_choose_straw2(b, x, x * 3u, mk_args(8, 0, NULL, same), 0) == 10);
	/* all weights zero: index 0 (nothing draws, the initial maximum stays) */
	b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 8, items, wz);
	for (x = 0; x < 50; x++)
		WRT_CHECK(wri_crush_choose_straw2(b, x, x, NULL, 0) == 10);
	/* one nonzero weight at the end wins every time; zero weights never draw */
	{
		uint32_t wl[8] = {0, 0, 0, 0, 0, 0, 0, 5};
		uint32_t wm[8] = {0, 0, 9, 0, 0, 0, 0, 0};

		b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 8, items, wl);
		for (x = 0; x < 200; x++)
			WRT_CHECK(wri_crush_choose_straw2(b, x, x ^ 5u, NULL, 0) == 17);
		b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 8, items, wm);
		for (x = 0; x < 200; x++)
			WRT_CHECK(wri_crush_choose_straw2(b, x, x ^ 9u, NULL, 3) == 12);
	}
	/* ties between equal draws on equal substitute ids, a larger weight wins (the numerator is negative) */
	{
		uint32_t wg[8] = {W_IN, 2 * W_IN, 3 * W_IN, W_IN, 3 * W_IN, W_IN, W_IN, W_IN};

		b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 8, items, wg);
		for (x = 0; x < 50; x++)
			WRT_CHECK(wri_crush_choose_straw2(b, x, 1, mk_args(8, 0, NULL, same), 0) == 12); /* first of the two heaviest */
	}
	/* random buckets against the draw written out, with and without a weight set, rows and ids; position clamps to the last row */
	wrt_mg_rng_seed(&rng, 12345);
	for (i = 0; i < 4000; i++) {
		uint32_t n = 1u + wrt_mg_rng_below(&rng, 8), k, rows = wrt_mg_rng_below(&rng, 4), pos = wrt_mg_rng_below(&rng, 6);
		int use_ids = (int)wrt_mg_rng_below(&rng, 2);
		uint32_t wbuck[8], wrows[3 * 8], *wuse;
		int32_t its[8], idv[8];
		const int32_t *hid;
		const wri_cargs *ca;

		for (k = 0; k < n; k++) {
			its[k] = (int32_t)wrt_mg_rng_below(&rng, 200) - 100;
			idv[k] = (int32_t)wrt_mg_rng_below(&rng, 2000) - 1000;
			wbuck[k] = wrt_mg_rng_below(&rng, 5) == 0 ? 0u : 1u + wrt_mg_rng_below(&rng, 0x30000u);
		}
		for (k = 0; k < rows * n; k++)
			wrows[k] = wrt_mg_rng_below(&rng, 5) == 0 ? 0u : 1u + wrt_mg_rng_below(&rng, 0x30000u);
		b = mk_bucket(-1 - (int32_t)wrt_mg_rng_below(&rng, 9), (uint8_t)WRI_CRUSH_ALG_STRAW2, n, its, wbuck);
		ca = (rows != 0 || use_ids) ? mk_args(n, rows, wrows, use_ids ? idv : NULL) : NULL;
		wuse = rows != 0 ? wrows + (size_t)(pos < rows ? pos : rows - 1u) * n : wbuck;
		hid = use_ids ? idv : its;
		x = wrt_mg_rng_below(&rng, 100000);
		r = wrt_mg_rng_below(&rng, 60);
		WRT_CHECK(wri_crush_choose_straw2(b, x, r, ca, pos) == its[exp_straw2(n, wuse, hid, x, r)]);
	}
	/* straw: the largest (hash & 0xffff) * straw, first wins; compared with the formula */
	for (i = 0; i < 2000; i++) {
		uint32_t n = 1u + wrt_mg_rng_below(&rng, 8), k, best = 0;
		uint64_t bd = 0;
		uint32_t straws[8];
		int32_t its[8];

		for (k = 0; k < n; k++) {
			its[k] = (int32_t)wrt_mg_rng_below(&rng, 100) - 50;
			straws[k] = wrt_mg_rng_below(&rng, 4) == 0 ? 0u : wrt_mg_rng_below(&rng, 0xffffffffu);
		}
		x = wrt_mg_rng_below(&rng, 100000);
		r = wrt_mg_rng_below(&rng, 40);
		for (k = 0; k < n; k++) {
			uint64_t d = (uint64_t)(wri_crush_hash3(x, (uint32_t)its[k], r) & 0xffffu) * straws[k];

			if (k == 0 || d > bd) {
				best = k;
				bd = d;
			}
		}
		b = mk_bucket(-3, (uint8_t)WRI_CRUSH_ALG_STRAW, n, its, straws);
		WRT_CHECK(wri_crush_choose_straw(b, x, r) == its[best]);
	}
	/* an empty bucket gives no item rather than reading past the record */
	b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 0, items, w1);
	WRT_CHECK(wri_crush_choose_straw2(b, 1, 1, NULL, 0) == NONE_ITEM);
	b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW, 0, items, w1);
	WRT_CHECK(wri_crush_choose_straw(b, 1, 1) == NONE_ITEM);
	/* ties in straw: equal straws and equal items give the first */
	{
		uint32_t sg[4] = {5, 5, 5, 5};
		int32_t it4[4] = {1, 1, 1, 1};

		b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW, 4, it4, sg);
		WRT_CHECK(wri_crush_choose_straw(b, 3, 3) == 1);
	}
	/* straw2 draw of the lab: rule 1 (osd) over three equal devices must reach every device (a sanity check of the spread) */
	{
		int32_t it3[3] = {0, 1, 2};
		uint32_t w3[3] = {W_IN, W_IN, W_IN};
		unsigned cnt[3] = {0, 0, 0};

		b = mk_bucket(-1, (uint8_t)WRI_CRUSH_ALG_STRAW2, 3, it3, w3);
		for (x = 0; x < 3000; x++)
			cnt[wri_crush_choose_straw2(b, x, 0, NULL, 0)]++;
		WRT_CHECK(cnt[0] > 800 && cnt[1] > 800 && cnt[2] > 800);
	}
}

/* ---- interpreter semantics, one by one --------------------------------------------------------------------------- */

static int flat_map(wrt_mg_crush *m, uint32_t n, uint8_t alg, int tun)
{
	int32_t *items = (int32_t *)malloc(n * sizeof(int32_t));
	uint32_t i;

	wrt_mg_crush_init(m);
	wrt_mg_crush_tunables(m, tun);
	for (i = 0; i < n; i++)
		items[i] = (int32_t)i;
	if (wrt_mg_crush_add_bucket(m, -1, T_ROOT, alg, items, NULL, n) < 0)
		abort();
	free(items);
	return 0;
}

#define RUN(res, nn, rule, x, rmax, w, wmax) run_map(cm.c, (rule), (x), (rmax), (w), (wmax), 0, (res), &(nn), NULL, NULL)

static void check_semantics(void)
{
	wrt_mg_crush m;
	cmap cm;
	int32_t res[WRI_CRUSH_RESULT_MAX];
	uint32_t n, *w, x, work;
	wr_errinfo why;

	/* a flat straw2 root of 10 devices, many rules */
	flat_map(&m, 10, WRT_MG_ALG_STRAW2, WRT_MG_TUN_JEWEL);
	{
		const wrt_mg_step r_ch[] = {{1, -1, 0}, {2, 0, 0}, {4, 0, 0}};
		const wrt_mg_step r_neg1[] = {{1, -1, 0}, {2, -1, 0}, {4, 0, 0}};
		const wrt_mg_step r_neg3[] = {{1, -1, 0}, {2, -3, 0}, {4, 0, 0}};
		const wrt_mg_step r_neg9[] = {{1, -1, 0}, {2, -9, 0}, {4, 0, 0}};
		const wrt_mg_step r_two[] = {{1, -1, 0}, {2, 2, 0}, {4, 0, 0}};
		const wrt_mg_step r_big[] = {{1, -1, 0}, {2, 2147483647, 0}, {4, 0, 0}};
		const wrt_mg_step r_tdev[] = {{1, 2, 0}, {4, 0, 0}};
		const wrt_mg_step r_tdev_ch[] = {{1, 2, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step r_tbad[] = {{1, 99, 0}, {4, 0, 0}};
		const wrt_mg_step r_tmiss[] = {{1, -1, 0}, {1, -99, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step r_tbucket[] = {{1, -1, 0}, {4, 0, 0}};
		const wrt_mg_step r_empty[] = {{4, 0, 0}};
		const wrt_mg_step r_indep[] = {{1, -1, 0}, {3, 0, 0}, {4, 0, 0}};
		const wrt_mg_step r_msr[] = {{1, -1, 0}, {14, 0, 0}, {4, 0, 0}};
		const wrt_mg_step r_emits[] = {{1, -1, 0}, {2, 2, 0}, {4, 0, 0}, {1, -1, 0}, {2, 2, 0}, {4, 0, 0}, {1, -1, 0}, {2, 2, 0}, {4, 0, 0}};
		const wrt_mg_step r_varyhigh[] = {{1, -1, 0}, {12, 33, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step r_varyok[] = {{1, -1, 0}, {12, 32, 0}, {6, 1, 0}, {4, 0, 0}};
		const wrt_mg_step r_chain[] = {{1, -1, 0}, {2, 3, 0}, {2, 2, 0}, {4, 0, 0}};

		add_rule(&m, 0, r_ch, 3);
		add_rule(&m, 1, r_neg1, 3);
		add_rule(&m, 2, r_neg3, 3);
		add_rule(&m, 3, r_neg9, 3);
		add_rule(&m, 4, r_two, 3);
		add_rule(&m, 5, r_big, 3);
		add_rule(&m, 6, r_tdev, 2);
		add_rule(&m, 7, r_tdev_ch, 3);
		add_rule(&m, 8, r_tbad, 2);
		add_rule(&m, 9, r_tmiss, 4);
		add_rule(&m, 10, r_tbucket, 2);
		add_rule(&m, 11, r_empty, 1);
		add_rule(&m, 12, r_indep, 3);
		add_rule(&m, 13, r_msr, 3);
		add_rule(&m, 14, r_emits, 9);
		add_rule(&m, 15, r_varyhigh, 4);
		add_rule(&m, 16, r_varyok, 4);
		add_rule(&m, 17, r_chain, 4);
		WRT_CHECK(wrt_mg_crush_add_rule(&m, 20, 3, r_ch, 3) == 20); /* a rule of type 3 (erasure) in slot 20 */
	}
	if (cm_from_mg(&cm, &m) != 0) {
		WRT_CHECK(0);
		return;
	}
	w = all_in(10);
	for (x = 0; x < 40; x++) {
		uint32_t i, j;

		/* choose firstn 0: result_max results, distinct devices */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 0, x, 3, w, 10));
		WRT_CHECK(n == 3);
		for (i = 0; i < n; i++)
			for (j = i + 1; j < n; j++)
				WRT_CHECK(res[i] != res[j]);
		for (i = 0; i < n; i++)
			WRT_CHECK(res[i] >= 0 && res[i] < 10);
		/* the first replica does not depend on the count asked for */
		{
			int32_t r1[16];
			uint32_t n1;

			WRT_CHECK_STATUS(WR_OK, RUN(r1, n1, 0, x, 1, w, 10));
			WRT_CHECK(n1 == 1 && r1[0] == res[0]);
		}
		/* -1 gives result_max - 1, -3 with result_max 3 nothing, -9 nothing, 2 gives 2 even for result_max 5, 2^31 - 1 fills result_max */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 1, x, 3, w, 10));
		WRT_CHECK(n == 2);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 2, x, 3, w, 10));
		WRT_CHECK(n == 0);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 3, x, 3, w, 10));
		WRT_CHECK(n == 0);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 4, x, 5, w, 10));
		WRT_CHECK(n == 2);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 4, x, 1, w, 10));
		WRT_CHECK(n == 1);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 5, x, 7, w, 10));
		WRT_CHECK(n == 7);
		/* take a device and emit it; choose below a device gives nothing; a take beyond max_devices leaves the working set alone */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 6, x, 3, w, 10));
		WRT_CHECK(n == 1 && res[0] == 2);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 7, x, 3, w, 10));
		WRT_CHECK(n == 0);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 8, x, 3, w, 10));
		WRT_CHECK(n == 0);
		/* take of a missing bucket changes nothing: the choose after it works on the root */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 9, x, 3, w, 10));
		WRT_CHECK(n == 1);
		{
			int32_t r1[16];
			uint32_t n1;

			WRT_CHECK_STATUS(WR_OK, RUN(r1, n1, 0, x, 1, w, 10));
			WRT_CHECK(res[0] == r1[0]);
		}
		/* take of a bucket and emit gives the bucket id */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 10, x, 3, w, 10));
		WRT_CHECK(n == 1 && res[0] == -1);
		/* an empty rule, and a rule of three emit blocks cut at result_max */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 11, x, 3, w, 10));
		WRT_CHECK(n == 0);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 14, x, 5, w, 10));
		WRT_CHECK(n == 5);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 14, x, 6, w, 10));
		WRT_CHECK(n == 6);
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 14, x, 3, w, 10));
		WRT_CHECK(n == 3);
		/* a choose after a choose works on the buckets the first one gave: devices give nothing */
		WRT_CHECK_STATUS(WR_OK, RUN(res, n, 17, x, 3, w, 10));
		WRT_CHECK(n == 0);
	}
	/* rule kinds and refused opcodes */
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_NO_RULE, run_map(cm.c, 200, 1, 3, w, 10, 0, res, &n, NULL, &why));
	WRT_CHECK(n == 0 && why.status == WR_E_CRUSH_NO_RULE && why.module == WR_MOD_CRUSH && why.what != NULL && strstr(why.what, "missing") != NULL);
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_NO_RULE, run_map(cm.c, 19, 1, 3, w, 10, 0, res, &n, NULL, &why)); /* in range, empty slot */
	WRT_CHECK(why.what != NULL && strstr(why.what, "missing") != NULL);
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_NO_RULE, run_map(cm.c, 20, 1, 3, w, 10, 0, res, &n, NULL, &why)); /* a rule of type 3 */
	WRT_CHECK(why.what != NULL && strstr(why.what, "not a replicated") != NULL);
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, run_map(cm.c, 12, 1, 3, w, 10, 0, res, &n, NULL, &why));
	WRT_CHECK(n == 0 && why.what != NULL && strstr(why.what, "indep") != NULL);
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, run_map(cm.c, 13, 1, 3, w, 10, 0, res, &n, NULL, &why));
	WRT_CHECK(why.what != NULL && strstr(why.what, "MSR") != NULL);
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, RUN(res, n, 15, 1, 3, w, 10)); /* SET_CHOOSELEAF_VARY_R 33: a shift by 32 */
	WRT_CHECK_STATUS(WR_OK, RUN(res, n, 16, 1, 3, w, 10));                    /* 32 is the largest accepted */
	/* invalid arguments */
	{
		wri_crush_ws ws;
		wri_crush_in in;

		memset(&ws, 0, sizeof(ws));
		ws.work = 100;
		in.rule = 0;
		in.x = 1;
		in.result_max = 3;
		in.osd_weight = w;
		in.weight_max = 10;
		in.args_pool = 0;
		n = 77;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(NULL, &in, &ws, res, &n, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, NULL, &ws, res, &n, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, NULL, res, &n, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, &ws, NULL, &n, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, &ws, res, NULL, NULL));
		in.result_max = 0;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL));
		WRT_CHECK(n == 0);
		in.result_max = WRI_CRUSH_RESULT_MAX + 1u;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL));
		in.result_max = WRI_CRUSH_RESULT_MAX;
		ws.work = WORK_DEFAULT;
		WRT_CHECK_STATUS(WR_OK, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL));
		WRT_CHECK(n == WRI_CRUSH_RESULT_MAX || n == 10);
		in.result_max = 3;
		in.osd_weight = NULL;
		ws.work = WORK_DEFAULT;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL)); /* a length without an array */
		in.weight_max = 0;
		ws.work = WORK_DEFAULT;
		WRT_CHECK_STATUS(WR_OK, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL)); /* no array at all: every device is out */
		WRT_CHECK(n == 0);
		in.osd_weight = w;
		in.weight_max = 10;
		((wri_crush *)(void *)cm.room)->magic ^= 1u;
		WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL));
		((wri_crush *)(void *)cm.room)->magic ^= 1u;
		{ /* a region that was not checked: a rule claiming more steps than the limit is refused before any step is read */
			wri_crule *rr = (wri_crule *)(void *)(cm.room + wri_crush_words(cm.c, cm.c->rule_tab)[0]);
			uint32_t saved = rr->nsteps;
			wr_errinfo why2;

			memset(&why2, 0, sizeof(why2));
			rr->nsteps = WRI_CRUSH_MAX_STEPS + 1u;
			ws.work = WORK_DEFAULT;
			n = 77;
			WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_do_rule(cm.c, &in, &ws, res, &n, &why2));
			WRT_CHECK(n == 0 && why2.module == WR_MOD_CRUSH && why2.what != NULL);
			rr->nsteps = saved;
		}
	}
	/* the work budget: exact costs. One choose firstn 1 on the 10-device root costs one draw of 10 items. */
	{
		const wrt_mg_step one[] = {{1, -1, 0}, {2, 1, 0}, {4, 0, 0}};
		wrt_mg_crush m2;
		cmap c2;

		flat_map(&m2, 10, WRT_MG_ALG_STRAW2, WRT_MG_TUN_JEWEL);
		add_rule(&m2, 0, one, 3);
		WRT_CHECK(cm_from_mg(&c2, &m2) == 0);
		work = 10;
		WRT_CHECK_STATUS(WR_OK, run_map(c2.c, 0, 5, 1, w, 10, 0, res, &n, &work, NULL));
		WRT_CHECK(n == 1 && work == 0);
		work = 9;
		memset(&why, 0, sizeof(why));
		WRT_CHECK_STATUS(WR_E_CRUSH_WORK, run_map(c2.c, 0, 5, 1, w, 10, 0, res, &n, &work, &why));
		WRT_CHECK(work == 0 && n == 0 && why.status == WR_E_CRUSH_WORK && why.module == WR_MOD_CRUSH);
		work = 25;
		WRT_CHECK_STATUS(WR_OK, run_map(c2.c, 0, 5, 1, w, 10, 0, res, &n, &work, NULL));
		WRT_CHECK(work == 15);
		cm_free(&c2);
		wrt_mg_crush_free(&m2);
	}
	/* chooseleaf over rack / host / device costs 3 + 2 + 4 draws when nothing is rejected */
	{
		hspec s;
		wrt_mg_crush m3;
		cmap c3;
		uint32_t *w3;
		const wrt_mg_step lf[] = {{1, -1, 0}, {6, 1, T_HOST}, {4, 0, 0}};

		memset(&s, 0, sizeof(s));
		s.tun = WRT_MG_TUN_JEWEL;
		s.alg_host = s.alg_rack = s.alg_root = WRT_MG_ALG_STRAW2;
		s.racks = 3;
		s.hpr = 2;
		s.dph = 4;
		build_hier(&m3, &s);
		add_rule(&m3, 20, lf, 3);
		WRT_CHECK(cm_from_mg(&c3, &m3) == 0);
		w3 = all_in((uint32_t)c3.c->max_devices);
		work = 1000;
		WRT_CHECK_STATUS(WR_OK, run_map(c3.c, 20, 11, 1, w3, (uint32_t)c3.c->max_devices, 0, res, &n, &work, NULL));
		WRT_CHECK(n == 1 && work == 1000 - 9);
		free(w3);
		cm_free(&c3);
		wrt_mg_crush_free(&m3);
	}
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&m);
}

static void check_budget_and_loops(void)
{
	wrt_mg_crush m;
	cmap cm;
	int32_t res[WRI_CRUSH_RESULT_MAX];
	uint32_t n, *w, work;
	wr_errinfo why;
	const wrt_mg_step ch1[] = {{1, -1, 0}, {2, 1, 0}, {4, 0, 0}};
	const wrt_mg_step lf1[] = {{1, -1, 0}, {6, 1, 0}, {4, 0, 0}};
	const wrt_mg_step big[] = {{1, -1, 0}, {2, 2147483647, 0}, {4, 0, 0}};
	const wrt_mg_step ch1_dev[] = {{1, -1, 0}, {2, 1, 0}, {4, 0, 0}};

	/* four billion tries and every device out: the budget stops it (the reference would run for hours) */
	flat_map(&m, 12, WRT_MG_ALG_STRAW2, WRT_MG_TUN_JEWEL);
	m.choose_total_tries = 4000000000u;
	add_rule(&m, 0, ch1, 3);
	add_rule(&m, 1, big, 3);
	add_rule(&m, 2, lf1, 3);
	WRT_CHECK(cm_from_mg(&cm, &m) == 0);
	w = (uint32_t *)calloc(12, sizeof(uint32_t)); /* all out */
	work = 200000;
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_WORK, run_map(cm.c, 0, 1, 3, w, 12, 0, res, &n, &work, &why));
	WRT_CHECK(work == 0 && n == 0 && why.what != NULL);
	work = 200000;
	WRT_CHECK_STATUS(WR_E_CRUSH_WORK, run_map(cm.c, 1, 1, 16, w, 12, 0, res, &n, &work, NULL)); /* and a count of 2^31 - 1 */
	work = 200000;
	WRT_CHECK_STATUS(WR_E_CRUSH_WORK, run_map(cm.c, 2, 1, 3, w, 12, 0, res, &n, &work, NULL)); /* chooseleaf over devices */
	work = 0; /* 0 means "the test default" in run_map; a real zero budget is set directly below */
	{
		wri_crush_ws ws;
		wri_crush_in in;

		memset(&ws, 0, sizeof(ws));
		in.rule = 0;
		in.x = 1;
		in.result_max = 1;
		in.osd_weight = w;
		in.weight_max = 12;
		in.args_pool = 0;
		ws.work = 0;
		WRT_CHECK_STATUS(WR_E_CRUSH_WORK, wri_crush_do_rule(cm.c, &in, &ws, res, &n, NULL));
		WRT_CHECK(ws.work == 0);
	}
	/* with a realistic budget all-out finishes (50 tries x 12 items x 3 replicas) when the tries are the stock 50 */
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&m);
	flat_map(&m, 12, WRT_MG_ALG_STRAW2, WRT_MG_TUN_JEWEL);
	add_rule(&m, 0, ch1, 3);
	WRT_CHECK(cm_from_mg(&cm, &m) == 0);
	w = (uint32_t *)calloc(12, sizeof(uint32_t));
	work = 200000;
	WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 0, 1, 3, w, 12, 0, res, &n, &work, NULL));
	WRT_CHECK(n == 0 && work == 200000u - 51u * 12u); /* 51 attempts, each one draw of 12 items */
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&m);

	/* an empty bucket is a rejection that still costs; with four billion tries the budget ends it */
	{
		wrt_mg_crush me;
		cmap ce;
		int32_t dev[1] = {0};

		wrt_mg_crush_init(&me);
		wrt_mg_crush_tunables(&me, WRT_MG_TUN_JEWEL);
		me.choose_total_tries = 4000000000u;
		WRT_CHECK(wrt_mg_crush_add_bucket(&me, -1, T_ROOT, WRT_MG_ALG_STRAW2, dev, NULL, 0) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&me, -2, T_HOST, WRT_MG_ALG_STRAW2, dev, NULL, 1) >= 0);
		add_rule(&me, 0, ch1, 3);
		WRT_CHECK(cm_from_mg(&ce, &me) == 0);
		w = all_in(1);
		work = 100000;
		WRT_CHECK_STATUS(WR_E_CRUSH_WORK, run_map(ce.c, 0, 1, 1, w, 1, 0, res, &n, &work, NULL));
		WRT_CHECK(work == 0);
		free(w);
		cm_free(&ce);
		wrt_mg_crush_free(&me);
	}

	/* a cyclic hierarchy: root (type 11) holds a rack (3) which holds the root; no device below. Descent depth > 16 */
	{
		wrt_mg_crush mc;
		cmap cc;
		int32_t a[1] = {-2}, b[1] = {-1}, d[1] = {0};
		const wrt_mg_step lfc[] = {{1, -1, 0}, {6, 1, T_HOST}, {4, 0, 0}};

		wrt_mg_crush_init(&mc);
		wrt_mg_crush_tunables(&mc, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mc, -1, T_ROOT, WRT_MG_ALG_STRAW2, a, NULL, 1) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mc, -2, T_RACK, WRT_MG_ALG_STRAW2, b, NULL, 1) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mc, -3, T_HOST, WRT_MG_ALG_STRAW2, d, NULL, 1) >= 0); /* gives max_devices 1 */
		add_rule(&mc, 0, ch1, 3);
		add_rule(&mc, 1, lfc, 3);
		WRT_CHECK(cm_from_mg(&cc, &mc) == 0);
		w = all_in(1);
		work = 100000;
		memset(&why, 0, sizeof(why));
		WRT_CHECK_STATUS(WR_E_CRUSH_LOOP, run_map(cc.c, 0, 1, 1, w, 1, 0, res, &n, &work, &why));
		WRT_CHECK(n == 0 && why.status == WR_E_CRUSH_LOOP && why.module == WR_MOD_CRUSH);
		WRT_CHECK(work > 100000u - 1000u); /* it stops after about 17 steps, not after the budget */
		WRT_CHECK_STATUS(WR_E_CRUSH_LOOP, run_map(cc.c, 1, 1, 1, w, 1, 0, res, &n, NULL, NULL));
		free(w);
		cm_free(&cc);
		wrt_mg_crush_free(&mc);
	}

	/* a self-contained loop of two buckets of the wanted type is fine, the descent stops at the first of them */
	/* a hole: an item names a bucket slot that is empty */
	{
		wrt_mg_crush mh;
		cmap ch;
		int32_t it[2] = {-3, 0};
		uint32_t wt[2] = {W_IN, 0};
		int32_t d[1] = {1};

		wrt_mg_crush_init(&mh);
		wrt_mg_crush_tunables(&mh, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mh, -1, T_ROOT, WRT_MG_ALG_STRAW2, it, wt, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mh, -4, T_HOST, WRT_MG_ALG_STRAW2, d, NULL, 1) >= 0); /* slots -2 and -3 stay holes */
		add_rule(&mh, 0, ch1, 3);
		WRT_CHECK(cm_from_mg(&ch, &mh) == 0);
		w = all_in(2);
		memset(&why, 0, sizeof(why));
		WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, run_map(ch.c, 0, 1, 1, w, 2, 0, res, &n, NULL, &why));
		WRT_CHECK(why.what != NULL && strstr(why.what, "missing bucket") != NULL);
		free(w);
		cm_free(&ch);
		wrt_mg_crush_free(&mh);
	}

	/* the descent limit: a chain of 17 buckets is 16 steps and passes, 18 is 17 steps and is a loop */
	{
		unsigned nb;

		for (nb = 17; nb <= 18; nb++) {
			wrt_mg_crush mc;
			cmap cc;
			int32_t it[1], dv[2] = {0, 1};
			unsigned k;

			wrt_mg_crush_init(&mc);
			wrt_mg_crush_tunables(&mc, WRT_MG_TUN_JEWEL);
			for (k = 1; k <= nb; k++) {
				it[0] = -(int32_t)(k + 1);
				WRT_CHECK(wrt_mg_crush_add_bucket(&mc, -(int32_t)k, 3, WRT_MG_ALG_STRAW2, k < nb ? it : dv, NULL, k < nb ? 1u : 2u) >= 0);
			}
			add_rule(&mc, 0, ch1_dev, 3);
			WRT_CHECK(cm_from_mg(&cc, &mc) == 0);
			w = all_in(2);
			WRT_CHECK_STATUS(nb == 17 ? WR_OK : WR_E_CRUSH_LOOP, run_map(cc.c, 0, 1, 1, w, 2, 0, res, &n, NULL, NULL));
			free(w);
			cm_free(&cc);
			wrt_mg_crush_free(&mc);
		}
	}
	/* SET_CHOOSE_TRIES 0 is ignored (the stock 51 attempts run); 1 allows one attempt */
	{
		wrt_mg_crush mt0;
		cmap ct0;
		const wrt_mg_step t0[] = {{1, -1, 0}, {8, 0, 0}, {2, 1, 0}, {4, 0, 0}};
		const wrt_mg_step t1[] = {{1, -1, 0}, {8, 1, 0}, {2, 1, 0}, {4, 0, 0}};

		flat_map(&mt0, 12, WRT_MG_ALG_STRAW2, WRT_MG_TUN_JEWEL);
		add_rule(&mt0, 0, t0, 4);
		add_rule(&mt0, 1, t1, 4);
		WRT_CHECK(cm_from_mg(&ct0, &mt0) == 0);
		w = (uint32_t *)calloc(12, sizeof(uint32_t));
		work = 100000;
		WRT_CHECK_STATUS(WR_OK, run_map(ct0.c, 0, 1, 1, w, 12, 0, res, &n, &work, NULL));
		WRT_CHECK(n == 0 && work == 100000u - 51u * 12u);
		work = 100000;
		WRT_CHECK_STATUS(WR_OK, run_map(ct0.c, 1, 1, 1, w, 12, 0, res, &n, &work, NULL));
		WRT_CHECK(n == 0 && work == 100000u - 12u);
		free(w);
		cm_free(&ct0);
		wrt_mg_crush_free(&mt0);
	}
	/* the out test is strict: a device with weight h is out when hash2(x, dev) & 0xffff == h, in when it is h + 1 */
	{
		wrt_mg_crush mo;
		cmap co;
		int32_t d0[1] = {0};
		const wrt_mg_step one[] = {{1, -1, 0}, {8, 1, 0}, {2, 1, 0}, {4, 0, 0}};
		uint32_t x, h = 0, wt;

		wrt_mg_crush_init(&mo);
		wrt_mg_crush_tunables(&mo, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mo, -1, T_ROOT, WRT_MG_ALG_STRAW2, d0, NULL, 1) >= 0);
		add_rule(&mo, 0, one, 4);
		WRT_CHECK(cm_from_mg(&co, &mo) == 0);
		for (x = 0; x < 50; x++) {
			h = wri_crush_hash2(x, 0) & 0xffffu;
			if (h == 0 || h >= 0xffffu)
				continue;
			wt = h;
			WRT_CHECK_STATUS(WR_OK, run_map(co.c, 0, x, 1, &wt, 1, 0, res, &n, NULL, NULL));
			WRT_CHECK(n == 0);
			wt = h + 1u;
			WRT_CHECK_STATUS(WR_OK, run_map(co.c, 0, x, 1, &wt, 1, 0, res, &n, NULL, NULL));
			WRT_CHECK(n == 1 && res[0] == 0);
		}
		cm_free(&co);
		wrt_mg_crush_free(&mo);
	}

	/* a tree bucket: reached = UNSUPPORTED; never drawn (weight 0 in its parent) = fine */
	{
		wrt_mg_crush mt;
		cmap ct;
		int32_t it[2] = {-2, -3}, d1[2] = {0, 1}, d2[2] = {2, 3};
		uint32_t wt[2] = {0, W_IN}, wt2[2] = {W_IN, 0};
		const wrt_mg_step lfh[] = {{1, -1, 0}, {6, 1, T_HOST}, {4, 0, 0}};

		wrt_mg_crush_init(&mt);
		wrt_mg_crush_tunables(&mt, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -1, T_ROOT, WRT_MG_ALG_STRAW2, it, wt, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -2, T_HOST, WRT_MG_ALG_TREE, d1, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -3, T_HOST, WRT_MG_ALG_STRAW2, d2, NULL, 2) >= 0);
		add_rule(&mt, 0, lfh, 3);
		WRT_CHECK(cm_from_mg(&ct, &mt) == 0);
		w = all_in(4);
		WRT_CHECK_STATUS(WR_OK, run_map(ct.c, 0, 1, 1, w, 4, 0, res, &n, NULL, NULL)); /* only -3 is drawn */
		WRT_CHECK(n == 1 && (res[0] == 2 || res[0] == 3));
		cm_free(&ct);
		wrt_mg_crush_free(&mt);
		wrt_mg_crush_init(&mt);
		wrt_mg_crush_tunables(&mt, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -1, T_ROOT, WRT_MG_ALG_STRAW2, it, wt2, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -2, T_HOST, WRT_MG_ALG_TREE, d1, NULL, 2) >= 0);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mt, -3, T_HOST, WRT_MG_ALG_STRAW2, d2, NULL, 2) >= 0);
		add_rule(&mt, 0, lfh, 3);
		WRT_CHECK(cm_from_mg(&ct, &mt) == 0);
		memset(&why, 0, sizeof(why));
		WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, run_map(ct.c, 0, 1, 1, w, 4, 0, res, &n, NULL, &why));
		WRT_CHECK(why.what != NULL && strstr(why.what, "tree") != NULL);
		free(w);
		cm_free(&ct);
		wrt_mg_crush_free(&mt);
	}
	{
		wrt_mg_crush mn;
		cmap cn;
		int32_t it[3] = {0, 1, 2};
		uint32_t wt[3] = {W_IN, W_IN, W_IN};
		const wrt_mg_step st[] = {{1, -1, 0}, {2, 3, 0}, {4, 0, 0}};

		/* an item id above max_devices is never a result: a hand-patched region whose bucket names device 5 of 3 */
		wrt_mg_crush_init(&mn);
		wrt_mg_crush_tunables(&mn, WRT_MG_TUN_JEWEL);
		WRT_CHECK(wrt_mg_crush_add_bucket(&mn, -1, T_ROOT, WRT_MG_ALG_STRAW2, it, wt, 3) >= 0);
		add_rule(&mn, 0, st, 3);
		WRT_CHECK(cm_from_mg(&cn, &mn) == 0);
		{
			const wri_cbucket *b = wri_crush_bucket(cn.c, -1);
			int32_t *items = (int32_t *)(void *)wri_cbucket_items(b);
			uint32_t x;

			items[1] = 5; /* beyond max_devices (3): the slot is abandoned, and no result carries it */
			w = all_in(6);
			for (x = 0; x < 200; x++) {
				uint32_t i;

				WRT_CHECK_STATUS(WR_OK, run_map(cn.c, 0, x, 3, w, 6, 0, res, &n, NULL, NULL));
				for (i = 0; i < n; i++)
					WRT_CHECK(res[i] != 5 && res[i] < 3);
			}
			items[1] = 3; /* exactly max_devices */
			for (x = 0; x < 200; x++) {
				uint32_t i;

				WRT_CHECK_STATUS(WR_OK, run_map(cn.c, 0, x, 3, w, 6, 0, res, &n, NULL, NULL));
				for (i = 0; i < n; i++)
					WRT_CHECK(res[i] < 3);
			}
			free(w);
		}
		cm_free(&cn);
		wrt_mg_crush_free(&mn);
	}
}

/* choose_args selected by pool id: the set keyed by the pool, else the default set, else none */
static void check_args_by_pool(void)
{
	hspec s;
	wrt_mg_crush m;
	cmap cm;
	uint32_t *w, x, diff1 = 0, diff2 = 0, same_default = 0;
	int32_t a[16], b[16], c0[16];
	uint32_t na, nb, nc;
	const wrt_mg_step rule[] = {{1, -1, 0}, {2, 3, 0}, {4, 0, 0}};

	memset(&s, 0, sizeof(s));
	s.tun = WRT_MG_TUN_JEWEL;
	s.alg_host = s.alg_rack = s.alg_root = WRT_MG_ALG_STRAW2;
	s.racks = 0;
	s.hpr = 1;
	s.dph = 12;
	s.jitter = 0;
	s.cargs = 1; /* sets -1 (default) and 1 */
	s.seed = 77;
	build_hier(&m, &s);
	add_rule(&m, 20, rule, 3);
	WRT_CHECK(cm_from_mg(&cm, &m) == 0);
	w = all_in((uint32_t)cm.c->max_devices);
	/* flat map: root holds one host which holds 12 devices; choose firstn 3 type osd goes root -> host -> devices */
	for (x = 0; x < 300; x++) {
		/* pool 1 uses its own set, every other pool the default set (-1); a pool with neither set cannot exist here */
		WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 20, x, 3, w, 12, 1, a, &na, NULL, NULL));
		WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 20, x, 3, w, 12, 5, b, &nb, NULL, NULL));
		WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 20, x, 3, w, 12, -1, c0, &nc, NULL, NULL));
		diff1 += !eq_list(a, na, b, nb);
		same_default += eq_list(b, nb, c0, nc); /* pool 5 and pool -1 both use the default set */
		(void)diff2;
	}
	WRT_CHECK(diff1 > 30);
	WRT_CHECK(same_default == 300);
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&m);
	/* a map without choose_args ignores the pool id */
	s.cargs = 0;
	build_hier(&m, &s);
	add_rule(&m, 20, rule, 3);
	WRT_CHECK(cm_from_mg(&cm, &m) == 0);
	w = all_in((uint32_t)cm.c->max_devices);
	for (x = 0; x < 100; x++) {
		WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 20, x, 3, w, 12, 1, a, &na, NULL, NULL));
		WRT_CHECK_STATUS(WR_OK, run_map(cm.c, 20, x, 3, w, 12, 9, b, &nb, NULL, NULL));
		WRT_CHECK(eq_list(a, na, b, nb));
	}
	free(w);
	cm_free(&cm);
	wrt_mg_crush_free(&m);
}

/* Properties over many generated maps: results valid, deterministic, never longer than result_max. */
static void check_properties(void)
{
	unsigned t;
	wrt_mg_rng rng;

	wrt_mg_rng_seed(&rng, 4242);
	for (t = 0; t < 24; t++) {
		hspec s;
		wrt_mg_crush m;
		cmap cm;
		uint32_t nd, *w, rule, x, rmax;

		memset(&s, 0, sizeof(s));
		s.tun = (int)wrt_mg_rng_below(&rng, 5);
		s.alg_host = (uint8_t)(wrt_mg_rng_below(&rng, 2) ? WRT_MG_ALG_STRAW2 : WRT_MG_ALG_STRAW);
		s.alg_rack = s.alg_root = s.alg_host;
		s.racks = wrt_mg_rng_below(&rng, 3) ? 2u + wrt_mg_rng_below(&rng, 3) : 0u;
		s.hpr = 2u + wrt_mg_rng_below(&rng, 4);
		s.dph = 1u + wrt_mg_rng_below(&rng, 6);
		s.jitter = 1;
		s.seed = 9000u + t;
		build_hier(&m, &s);
		WRT_CHECK(cm_from_mg(&cm, &m) == 0);
		nd = (uint32_t)cm.c->max_devices;
		w = (uint32_t *)malloc(nd * sizeof(uint32_t));
		make_weights(w, nd, (int)(t % 5), &rng);
		for (rule = 0; rule < N_RULES; rule++)
			for (x = 0; x < 10; x++)
				for (rmax = 1; rmax <= 4; rmax++) {
					int32_t r1[16], r2[16];
					uint32_t n1, n2, i, w1 = 5000, w2 = 5000;
					wr_status s1 = run_map(cm.c, rule, x, rmax, w, nd, 0, r1, &n1, &w1, NULL);
					wr_status s2 = run_map(cm.c, rule, x, rmax, w, nd, 0, r2, &n2, &w2, NULL);

					if (s1 == WR_E_CRUSH_WORK || s1 == WR_E_CRUSH_UNSUPPORTED) {
						WRT_CHECK_STATUS(s1, s2);
						continue;
					}
					WRT_CHECK_STATUS(WR_OK, s1);
					WRT_CHECK(s2 == s1 && n1 == n2 && w1 == w2 && eq_list(r1, n1, r2, n2));
					WRT_CHECK(n1 <= rmax && w1 <= 5000u);
					for (i = 0; i < n1; i++)
						WRT_CHECK(r1[i] < (int32_t)nd && (r1[i] >= 0 || wri_crush_bucket(cm.c, r1[i]) != NULL));
				}
		free(w);
		cm_free(&cm);
		wrt_mg_crush_free(&m);
	}
}

/* ---- seeds ----------------------------------------------------------------------------------------------------- */

static void emit_seeds(void)
{
	size_t i;
	unsigned k;
	static const struct {
		const char *rel;
		const char *name;
	} lab[] = {{"osdmap/crush-embedded.hex", "lab-embedded"}, {"crush/crush-getcrushmap.hex", "lab-getcrushmap"}};

	for (i = 0; i < sizeof(lab) / sizeof(lab[0]); i++) {
		uint8_t *blob;
		size_t n;
		char nm[96];

		if (wrt_mg_load_hex_file(wrt_vec_path(lab[i].rel), &blob, &n) != 0)
			exit(1);
		for (k = 0; k < 2; k++) {
			snprintf(nm, sizeof(nm), "%s-rule%u", lab[i].name, k);
			seed_write(nm, blob, n, k, 3, 100u + k, 2, 3);
		}
		free(blob);
	}
	for (i = 0; i < sizeof(mapb_maps) / sizeof(mapb_maps[0]); i++) {
		char rel[256], nm[128];
		uint8_t *blob;
		size_t n;

		snprintf(rel, sizeof(rel), "public/mapb/crush/%s.crush.hex", mapb_maps[i]);
		if (wrt_mg_load_hex_file(wrt_vec_path(rel), &blob, &n) != 0)
			exit(1);
		for (k = 0; k < 3; k++) {
			snprintf(nm, sizeof(nm), "mapb-%.5s-rule%u", mapb_maps[i], k);
			seed_write(nm, blob, n, k * 2u, 3u + k, 7u + 13u * k, (int)k - 1, 24);
		}
		free(blob);
	}
	/* generated maps with choose_args and the whole rule matrix's first rules */
	for (k = 0; k < 6; k++) {
		hspec s;
		wrt_mg_crush m;
		wrt_mg_buf b;
		char nm[64];

		memset(&s, 0, sizeof(s));
		s.tun = (int)(k % 5u);
		s.alg_host = s.alg_rack = s.alg_root = (uint8_t)(k < 4 ? WRT_MG_ALG_STRAW2 : WRT_MG_ALG_STRAW);
		s.racks = k % 2u ? 0u : 2u;
		s.hpr = 3;
		s.dph = 4;
		s.jitter = 1;
		s.cargs = k < 4;
		s.seed = 500u + k;
		build_hier(&m, &s);
		memset(&b, 0, sizeof(b));
		if (wrt_mg_crush_encode(&m, &b) != 0)
			exit(1);
		snprintf(nm, sizeof(nm), "gen-%u", k);
		seed_write(nm, b.p, b.len, k * 2u, 4, 1000u + k, 1, 24);
		wrt_mg_buf_free(&b);
		wrt_mg_crush_free(&m);
	}
	printf("wrote %u seeds\n", seed_count);
}

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "--emit-seeds") == 0) {
		struct stat st;

		seed_dir = argv[2];
		if (stat(seed_dir, &st) != 0 && mkdir(seed_dir, 0777) != 0 && errno != EEXIST) {
			fprintf(stderr, "cannot create %s\n", seed_dir);
			return 1;
		}
		emit_seeds();
		return 0;
	}
	probe_legacy();
#define STEP(call)                                                                                   \
	do {                                                                                         \
		clock_t t0_ = clock();                                                               \
		call;                                                                                \
		printf("  %-28s %6.2f s\n", #call, (double)(clock() - t0_) / (double)CLOCKS_PER_SEC); \
	} while (0)
	STEP(check_osdmap_vectors());
	STEP(check_crushtool_vectors());
	STEP(check_mapb_vectors(0));
	printf("vectors: %lu mappings compared, %lu refused as unsupported (tree / indep / legacy)\n", n_vec_ok, n_vec_skip);
	STEP(check_mapb_vectors(1));
	printf("oracle against crushtool: %lu mappings equal, %lu skipped (indep, tree)\n", n_orcvec_ok, n_orcvec_skip);
	WRT_CHECK(n_orcvec_ok > 3000);
	STEP(check_tree_known_answers());
	STEP(check_choosers());
	STEP(check_semantics());
	STEP(check_budget_and_loops());
	STEP(check_args_by_pool());
	STEP(check_properties());
	STEP(check_oracle_matrix());
	return wrt_finish();
}
