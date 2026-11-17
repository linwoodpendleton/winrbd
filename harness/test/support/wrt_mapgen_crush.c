/* SPDX-License-Identifier: MIT */
/*
 * wrt_mapgen_crush.c - the CRUSH half of the generator: the blob walker (encode / decode / free), the builders for
 * hand-made maps and the cluster CRUSH builder (racks, hosts, device classes with shadow trees, choose_args).
 * Layout: docs/spec/crush-and-placement.md 2.2. The walker is the only description of the layout here; the tests
 * check it against real bytes (the lab blobs) and against an independent reader in test_mapgen_self.c.
 */
#include "wrt_mapgen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- the walkers ------------------------------------------------------------------------------------------- */

static uint32_t vget(const wrt_mg_vec *v, uint32_t i)
{
	return i < v->n ? ((const uint32_t *)v->v)[i] : 0u;
}

static void vfree(wrt_mg_vec *v)
{
	free(v->v);
	memset(v, 0, sizeof(*v));
}

static void walk_name(wrt_mg_cx *cx, void *e)
{
	wrt_mg_name *n = (wrt_mg_name *)e;
	uint32_t len = 0, zero = 0;

	if (cx->mode == WRT_MG_FREE)
		return;
	wrt_mg_cx_s32(cx, &n->key);
	if (cx->mode == WRT_MG_ENC) {
		len = (uint32_t)strlen(n->name);
		if (n->legacy64)
			wrt_mg_cx_u32(cx, &zero);
		wrt_mg_cx_u32(cx, &len);
		wrt_mg_cx_bytes(cx, n->name, len);
		return;
	}
	wrt_mg_cx_u32(cx, &len);
	n->legacy64 = 0;
	if (len == 0) {
		n->legacy64 = 1;
		wrt_mg_cx_u32(cx, &len);
	}
	if (len >= sizeof(n->name)) {
		wrt_mg_cx_fail(cx);
		return;
	}
	wrt_mg_cx_bytes(cx, n->name, len);
	n->name[len] = 0;
}

static void walk_cls_map(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cls_map *m = (wrt_mg_cls_map *)e;

	wrt_mg_cx_s32(cx, &m->item);
	wrt_mg_cx_s32(cx, &m->cls);
}

static void walk_cls_name(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cls_name *m = (wrt_mg_cls_name *)e;

	wrt_mg_cx_s32(cx, &m->id);
	wrt_mg_cx_str(cx, m->name, sizeof(m->name));
}

static void walk_cls_bucket(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cls_bucket *m = (wrt_mg_cls_bucket *)e;

	wrt_mg_cx_s32(cx, &m->bucket);
	wrt_mg_cx_vec(cx, &m->shadows, sizeof(wrt_mg_pair), wrt_mg_walk_pair);
}

static void walk_wrow(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cx_vec(cx, &((wrt_mg_wrow *)e)->w, sizeof(uint32_t), wrt_mg_walk_u32);
}

static void walk_carg(wrt_mg_cx *cx, void *e)
{
	wrt_mg_carg *a = (wrt_mg_carg *)e;

	wrt_mg_cx_u32(cx, &a->index);
	wrt_mg_cx_vec(cx, &a->rows, sizeof(wrt_mg_wrow), walk_wrow);
	wrt_mg_cx_vec(cx, &a->ids, sizeof(int32_t), wrt_mg_walk_s32);
}

static void walk_cset(wrt_mg_cx *cx, void *e)
{
	wrt_mg_cset *s = (wrt_mg_cset *)e;

	wrt_mg_cx_s64(cx, &s->key);
	wrt_mg_cx_vec(cx, &s->bucks, sizeof(wrt_mg_carg), walk_carg);
}

/* A weight-like array without a count on the wire: its length is the bucket size. */
static void walk_u32s(wrt_mg_cx *cx, wrt_mg_vec *v, uint32_t size)
{
	wrt_mg_cx_vec_n(cx, v, size, sizeof(uint32_t), wrt_mg_walk_u32);
}

/* Two arrays of `size` entries written interleaved: (a[0], b[0], a[1], b[1], ...). */
static void walk_pairs(wrt_mg_cx *cx, wrt_mg_vec *a, wrt_mg_vec *b, uint32_t size)
{
	uint32_t i;

	if (cx->mode == WRT_MG_FREE) {
		vfree(a);
		vfree(b);
		return;
	}
	if (cx->mode == WRT_MG_DEC) {
		if (size > cx->len - cx->pos) {
			wrt_mg_cx_fail(cx);
			return;
		}
		wrt_mg_vec_resize0(a, sizeof(uint32_t), size);
		wrt_mg_vec_resize0(b, sizeof(uint32_t), size);
	}
	for (i = 0; i < size; i++) {
		uint32_t x = vget(a, i), y = vget(b, i);

		wrt_mg_cx_u32(cx, &x);
		wrt_mg_cx_u32(cx, &y);
		if (cx->mode == WRT_MG_DEC) {
			WRT_MG_E(*a, uint32_t, i) = x;
			WRT_MG_E(*b, uint32_t, i) = y;
		}
	}
}

static void walk_bucket(wrt_mg_cx *cx, void *e)
{
	wrt_mg_bucket *b = (wrt_mg_bucket *)e;
	uint32_t marker = 0, size;

	if (cx->mode == WRT_MG_FREE) {
		vfree(&b->items);
		vfree(&b->item_weights);
		vfree(&b->sum_weights);
		vfree(&b->straws);
		vfree(&b->node_weights);
		return;
	}
	if (cx->mode == WRT_MG_ENC && b->present)
		marker = b->alg_marker ? b->alg_marker : b->alg;
	wrt_mg_cx_u32(cx, &marker);
	if (cx->mode == WRT_MG_DEC) {
		b->present = marker != 0;
		b->alg_marker = marker;
	}
	if (!b->present && marker == 0)
		return; /* a hole: nothing follows */
	wrt_mg_cx_s32(cx, &b->id);
	wrt_mg_cx_u16(cx, &b->type);
	wrt_mg_cx_u8(cx, &b->alg);
	wrt_mg_cx_u8(cx, &b->hash);
	wrt_mg_cx_u32(cx, &b->weight);
	wrt_mg_cx_vec(cx, &b->items, sizeof(int32_t), wrt_mg_walk_s32); /* size, then the items */
	size = b->items.n;
	switch (b->alg) {
	case WRT_MG_ALG_UNIFORM: {
		uint32_t w = vget(&b->item_weights, 0);

		wrt_mg_cx_u32(cx, &w);
		if (cx->mode == WRT_MG_DEC) {
			wrt_mg_vec_resize0(&b->item_weights, sizeof(uint32_t), 1);
			WRT_MG_E(b->item_weights, uint32_t, 0) = w;
		}
		break;
	}
	case WRT_MG_ALG_LIST:
		walk_pairs(cx, &b->item_weights, &b->sum_weights, size);
		break;
	case WRT_MG_ALG_TREE: {
		uint8_t nn = (uint8_t)b->node_weights.n;

		wrt_mg_cx_u8(cx, &nn);
		walk_u32s(cx, &b->node_weights, nn);
		break;
	}
	case WRT_MG_ALG_STRAW:
		walk_pairs(cx, &b->item_weights, &b->straws, size);
		break;
	case WRT_MG_ALG_STRAW2:
		walk_u32s(cx, &b->item_weights, size);
		break;
	default:
		if (cx->mode == WRT_MG_DEC)
			wrt_mg_cx_fail(cx); /* unknown algorithm */
		break;
	}
}

static void walk_rule(wrt_mg_cx *cx, void *e)
{
	wrt_mg_rule *r = (wrt_mg_rule *)e;
	uint32_t yes = (uint32_t)(r->present != 0), len;

	if (cx->mode == WRT_MG_FREE) {
		vfree(&r->steps);
		return;
	}
	wrt_mg_cx_u32(cx, &yes);
	if (cx->mode == WRT_MG_DEC)
		r->present = yes != 0;
	if (yes == 0)
		return;
	len = r->steps.n;
	wrt_mg_cx_u32(cx, &len);
	wrt_mg_cx_u8(cx, &r->ruleset);
	wrt_mg_cx_u8(cx, &r->type);
	wrt_mg_cx_u8(cx, &r->min_size);
	wrt_mg_cx_u8(cx, &r->max_size);
	{
		/* steps: 12 bytes each, no count after the length above */
		uint32_t i;

		if (cx->mode == WRT_MG_DEC) {
			if (len > (cx->len - cx->pos) / 12u + 1u) {
				wrt_mg_cx_fail(cx);
				return;
			}
			wrt_mg_vec_resize0(&r->steps, sizeof(wrt_mg_step), len);
		}
		for (i = 0; i < len && !cx->err; i++) {
			wrt_mg_step st = WRT_MG_E(r->steps, wrt_mg_step, i);

			wrt_mg_cx_u32(cx, &st.op);
			wrt_mg_cx_s32(cx, &st.a1);
			wrt_mg_cx_s32(cx, &st.a2);
			if (cx->mode == WRT_MG_DEC)
				WRT_MG_E(r->steps, wrt_mg_step, i) = st;
		}
	}
}

/* Is the trailing group k present (ENC: by `upto`; DEC: the buffer has more bytes, and remember it)? */
static int grp(wrt_mg_cx *cx, wrt_mg_crush *c, int k)
{
	if (cx->mode == WRT_MG_ENC)
		return c->upto >= k;
	if (cx->mode == WRT_MG_FREE)
		return 1;
	if (cx->err || !wrt_mg_cx_more(cx))
		return 0;
	c->upto = k;
	return 1;
}

void wrt_mg_walk_crush(wrt_mg_cx *cx, wrt_mg_crush *c)
{
	uint32_t nb = c->buckets.n, nr = c->rules.n;

	if (cx->mode == WRT_MG_ENC && c->hdr_override) {
		/* a lie in the header: the real vectors follow, whatever the header says */
		uint32_t hb = c->hdr_max_buckets, hr = c->hdr_max_rules, real_b = nb, real_r = nr;

		wrt_mg_cx_u32(cx, &c->magic);
		wrt_mg_cx_u32(cx, &hb);
		wrt_mg_cx_u32(cx, &hr);
		wrt_mg_cx_s32(cx, &c->max_devices);
		wrt_mg_cx_vec_n(cx, &c->buckets, real_b, sizeof(wrt_mg_bucket), walk_bucket);
		wrt_mg_cx_vec_n(cx, &c->rules, real_r, sizeof(wrt_mg_rule), walk_rule);
		goto names;
	}
	wrt_mg_cx_u32(cx, &c->magic);
	wrt_mg_cx_u32(cx, &nb);
	wrt_mg_cx_u32(cx, &nr);
	wrt_mg_cx_s32(cx, &c->max_devices);
	if (cx->mode == WRT_MG_DEC && (nb > cx->len - cx->pos || nr > cx->len - cx->pos)) {
		wrt_mg_cx_fail(cx);
		return;
	}
	wrt_mg_cx_vec_n(cx, &c->buckets, nb, sizeof(wrt_mg_bucket), walk_bucket);
	wrt_mg_cx_vec_n(cx, &c->rules, nr, sizeof(wrt_mg_rule), walk_rule);
names:
	wrt_mg_cx_vec(cx, &c->type_names, sizeof(wrt_mg_name), walk_name);
	wrt_mg_cx_vec(cx, &c->item_names, sizeof(wrt_mg_name), walk_name);
	wrt_mg_cx_vec(cx, &c->rule_names, sizeof(wrt_mg_name), walk_name);
	if (cx->err)
		return;
	if (grp(cx, c, WRT_MG_UPTO_A)) {
		wrt_mg_cx_u32(cx, &c->choose_local_tries);
		wrt_mg_cx_u32(cx, &c->choose_local_fallback_tries);
		wrt_mg_cx_u32(cx, &c->choose_total_tries);
	}
	if (grp(cx, c, WRT_MG_UPTO_B))
		wrt_mg_cx_u32(cx, &c->chooseleaf_descend_once);
	if (grp(cx, c, WRT_MG_UPTO_C))
		wrt_mg_cx_u8(cx, &c->chooseleaf_vary_r);
	if (grp(cx, c, WRT_MG_UPTO_D))
		wrt_mg_cx_u8(cx, &c->straw_calc_version);
	if (grp(cx, c, WRT_MG_UPTO_E))
		wrt_mg_cx_u32(cx, &c->allowed_bucket_algs);
	if (grp(cx, c, WRT_MG_UPTO_F))
		wrt_mg_cx_u8(cx, &c->chooseleaf_stable);
	if (grp(cx, c, WRT_MG_UPTO_CLASSES)) {
		wrt_mg_cx_vec(cx, &c->class_map, sizeof(wrt_mg_cls_map), walk_cls_map);
		wrt_mg_cx_vec(cx, &c->class_names, sizeof(wrt_mg_cls_name), walk_cls_name);
		wrt_mg_cx_vec(cx, &c->class_bucket, sizeof(wrt_mg_cls_bucket), walk_cls_bucket);
	}
	if (grp(cx, c, WRT_MG_UPTO_CARGS))
		wrt_mg_cx_vec(cx, &c->choose_args, sizeof(wrt_mg_cset), walk_cset);
	if (grp(cx, c, WRT_MG_UPTO_MSR)) {
		wrt_mg_cx_u32(cx, &c->msr_descents);
		wrt_mg_cx_u32(cx, &c->msr_collision_tries);
	}
}

/* ---- public: init, free, encode, parse ---------------------------------------------------------------------- */

void wrt_mg_crush_tunables(wrt_mg_crush *c, int profile)
{
	c->choose_local_tries = 0;
	c->choose_local_fallback_tries = 0;
	c->choose_total_tries = 50;
	c->chooseleaf_descend_once = 1;
	c->chooseleaf_vary_r = 0;
	c->straw_calc_version = 0;
	c->allowed_bucket_algs = 0x16; /* uniform + list + straw */
	c->chooseleaf_stable = 0;
	switch (profile) {
	case WRT_MG_TUN_LEGACY:
		c->choose_local_tries = 2;
		c->choose_local_fallback_tries = 5;
		c->choose_total_tries = 19;
		c->chooseleaf_descend_once = 0;
		break;
	case WRT_MG_TUN_BOBTAIL:
		break;
	case WRT_MG_TUN_FIREFLY:
		c->chooseleaf_vary_r = 1;
		break;
	case WRT_MG_TUN_HAMMER:
		c->chooseleaf_vary_r = 1;
		c->allowed_bucket_algs = 0x36;
		break;
	default: /* JEWEL */
		c->chooseleaf_vary_r = 1;
		c->chooseleaf_stable = 1;
		c->straw_calc_version = 1;
		c->allowed_bucket_algs = 0x36;
		break;
	}
}

void wrt_mg_crush_init(wrt_mg_crush *c)
{
	memset(c, 0, sizeof(*c));
	c->magic = 0x00010000u;
	c->upto = WRT_MG_UPTO_CARGS;
	c->msr_descents = 100;
	c->msr_collision_tries = 100;
	wrt_mg_crush_tunables(c, WRT_MG_TUN_JEWEL);
}

void wrt_mg_crush_free(wrt_mg_crush *c)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_FREE;
	wrt_mg_walk_crush(&cx, c);
	memset(c, 0, sizeof(*c));
}

int wrt_mg_crush_encode(const wrt_mg_crush *c, wrt_mg_buf *out)
{
	wrt_mg_cx cx;

	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_ENC;
	cx.out = out;
	wrt_mg_walk_crush(&cx, (wrt_mg_crush *)c);
	return cx.err ? -1 : 0;
}

int wrt_mg_crush_parse(const uint8_t *p, size_t n, wrt_mg_crush *c)
{
	wrt_mg_cx cx;

	wrt_mg_crush_init(c);
	/* what a decoder assumes for a group that is absent: the legacy values, and the MSR defaults */
	wrt_mg_crush_tunables(c, WRT_MG_TUN_LEGACY);
	c->upto = WRT_MG_UPTO_NONE;
	memset(&cx, 0, sizeof(cx));
	cx.mode = WRT_MG_DEC;
	cx.in = p;
	cx.len = n;
	wrt_mg_walk_crush(&cx, c);
	if (cx.err || cx.pos != n || c->magic != 0x00010000u) {
		wrt_mg_crush_free(c);
		return -1;
	}
	return 0;
}

/* ---- hand-made maps ------------------------------------------------------------------------------------------- */

static int ilog2_bits(uint32_t v) /* number of significant bits */
{
	int b = 0;

	while (v) {
		b++;
		v >>= 1;
	}
	return b;
}

int wrt_mg_crush_add_bucket(wrt_mg_crush *c, int32_t id, uint16_t type, uint8_t alg, const int32_t *items,
			    const uint32_t *weights, uint32_t n)
{
	uint32_t slot, i;
	wrt_mg_bucket *b;
	uint64_t total = 0;

	if (id >= 0)
		return -1;
	slot = (uint32_t)(-1 - id);
	if (slot >= (1u << 20)) /* an absurd id would allocate gigabytes of empty slots */
		return -1;
	if (alg == WRT_MG_ALG_TREE && n > 64) /* the u8 node count holds 255 nodes: at most 64 leaves; refuse before touching anything */
		return -1;
	if (slot >= c->buckets.n)
		wrt_mg_vec_resize0(&c->buckets, sizeof(wrt_mg_bucket), slot + 1);
	b = &WRT_MG_E(c->buckets, wrt_mg_bucket, slot);
	{
		wrt_mg_cx cx;

		memset(&cx, 0, sizeof(cx));
		cx.mode = WRT_MG_FREE;
		walk_bucket(&cx, b);
	}
	memset(b, 0, sizeof(*b));
	b->present = 1;
	b->id = id;
	b->type = type;
	b->alg = alg;
	b->hash = 0;
	wrt_mg_vec_resize0(&b->items, sizeof(int32_t), n);
	wrt_mg_vec_resize0(&b->item_weights, sizeof(uint32_t), alg == WRT_MG_ALG_UNIFORM ? (n ? 1u : 0u) : n);
	for (i = 0; i < n; i++) {
		uint32_t w = weights ? weights[i] : WRT_MG_W_IN;

		if (alg == WRT_MG_ALG_UNIFORM)
			w = weights ? weights[0] : WRT_MG_W_IN;
		WRT_MG_E(b->items, int32_t, i) = items[i];
		if (alg != WRT_MG_ALG_UNIFORM)
			WRT_MG_E(b->item_weights, uint32_t, i) = w;
		else if (i == 0)
			WRT_MG_E(b->item_weights, uint32_t, 0) = w;
		total += w;
	}
	b->weight = (uint32_t)total;
	if (alg == WRT_MG_ALG_LIST) {
		uint64_t run = 0;

		wrt_mg_vec_resize0(&b->sum_weights, sizeof(uint32_t), n);
		for (i = 0; i < n; i++) {
			run += WRT_MG_E(b->item_weights, uint32_t, i);
			WRT_MG_E(b->sum_weights, uint32_t, i) = (uint32_t)run;
		}
	} else if (alg == WRT_MG_ALG_STRAW) {
		wrt_mg_vec_resize0(&b->straws, sizeof(uint32_t), n);
		for (i = 0; i < n; i++)
			WRT_MG_E(b->straws, uint32_t, i) = WRT_MG_E(b->item_weights, uint32_t, i);
	} else if (alg == WRT_MG_ALG_TREE) {
		/*
		 * Item i is the leaf at node 2 i + 1; a node's height is its number of trailing zero bits; an inner
		 * node holds the sum of its two children, which sit 2^(h-1) below and above it. The root is the node
		 * num_nodes / 2. At most 64 items fit the u8 node count.
		 */
		uint32_t depth = (uint32_t)(n ? 1 + ilog2_bits(n - 1) : 0), nn = depth ? (1u << depth) : 0, h, k;

		if (nn > 255) /* cannot happen after the check above */
			abort();
		wrt_mg_vec_resize0(&b->node_weights, sizeof(uint32_t), nn);
		for (i = 0; i < n; i++)
			WRT_MG_E(b->node_weights, uint32_t, 2 * i + 1) = WRT_MG_E(b->item_weights, uint32_t, i);
		for (h = 1; h < depth; h++)
			for (k = (1u << h); k < nn; k += (2u << h)) {
				uint32_t lo = k - (1u << (h - 1)), hi = k + (1u << (h - 1));

				WRT_MG_E(b->node_weights, uint32_t, k) =
					WRT_MG_E(b->node_weights, uint32_t, lo) +
					(hi < nn ? WRT_MG_E(b->node_weights, uint32_t, hi) : 0u);
			}
	}
	return (int)slot;
}

int wrt_mg_crush_add_rule(wrt_mg_crush *c, uint32_t slot, uint8_t type, const wrt_mg_step *steps, uint32_t nsteps)
{
	wrt_mg_rule *r;
	uint32_t i;

	if (slot > 255)
		return -1;
	if (slot >= c->rules.n)
		wrt_mg_vec_resize0(&c->rules, sizeof(wrt_mg_rule), slot + 1);
	r = &WRT_MG_E(c->rules, wrt_mg_rule, slot);
	vfree(&r->steps);
	memset(r, 0, sizeof(*r));
	r->present = 1;
	r->ruleset = (uint8_t)slot;
	r->type = type;
	r->min_size = 1;
	r->max_size = 100;
	wrt_mg_vec_resize0(&r->steps, sizeof(wrt_mg_step), nsteps);
	for (i = 0; i < nsteps; i++)
		WRT_MG_E(r->steps, wrt_mg_step, i) = steps[i];
	return (int)slot;
}

void wrt_mg_crush_name(wrt_mg_crush *c, int which, int32_t key, const char *name)
{
	wrt_mg_vec *v = which == 0 ? &c->type_names : which == 1 ? &c->item_names : &c->rule_names;
	uint32_t i;
	wrt_mg_name n;

	memset(&n, 0, sizeof(n));
	n.key = key;
	snprintf(n.name, sizeof(n.name), "%s", name);
	for (i = 0; i < v->n; i++) {
		if (WRT_MG_E(*v, wrt_mg_name, i).key == key) {
			WRT_MG_E(*v, wrt_mg_name, i) = n;
			return;
		}
		if (WRT_MG_E(*v, wrt_mg_name, i).key > key)
			break;
	}
	wrt_mg_vec_grow_(v, sizeof(wrt_mg_name));
	memmove((wrt_mg_name *)v->v + i + 1, (wrt_mg_name *)v->v + i, (v->n - i) * sizeof(wrt_mg_name));
	WRT_MG_E(*v, wrt_mg_name, i) = n;
	v->n++;
}

void wrt_mg_crush_recount(wrt_mg_crush *c)
{
	int32_t maxd = -1;
	uint32_t i, j;

	for (i = 0; i < c->buckets.n; i++) {
		wrt_mg_bucket *b = &WRT_MG_E(c->buckets, wrt_mg_bucket, i);

		if (!b->present)
			continue;
		for (j = 0; j < b->items.n; j++)
			if (WRT_MG_E(b->items, int32_t, j) > maxd)
				maxd = WRT_MG_E(b->items, int32_t, j);
	}
	for (i = 0; i < c->item_names.n; i++)
		if (WRT_MG_E(c->item_names, wrt_mg_name, i).key > maxd)
			maxd = WRT_MG_E(c->item_names, wrt_mg_name, i).key;
	c->max_devices = maxd + 1;
}

/* ---- the cluster CRUSH builder ------------------------------------------------------------------------------- */

static const char *const type_name_tab[12] = {"osd", "host", "chassis", "rack", "row", "pdu",
					      "pod", "room", "datacenter", "zone", "region", "root"};
static const char *const class_name_tab[3] = {"hdd", "ssd", "nvme"};

typedef struct {
	int32_t id;
	uint16_t type;
	uint32_t n, cap;
	int32_t *items;
	uint32_t *w;
} node;

static void node_add(node *nd, int32_t item, uint32_t w)
{
	if (nd->n == nd->cap) {
		nd->cap = nd->cap ? nd->cap * 2 : 8;
		nd->items = (int32_t *)realloc(nd->items, nd->cap * sizeof(int32_t));
		nd->w = (uint32_t *)realloc(nd->w, nd->cap * sizeof(uint32_t));
		if (!nd->items || !nd->w) {
			fprintf(stderr, "wrt_mapgen: out of memory\n");
			abort();
		}
	}
	nd->items[nd->n] = item;
	nd->w[nd->n] = w;
	nd->n++;
}

static uint32_t node_total(const node *nd)
{
	uint64_t t = 0;
	uint32_t i;

	for (i = 0; i < nd->n; i++)
		t += nd->w[i];
	return (uint32_t)t;
}

static int cmp_int32(const void *a, const void *b)
{
	int32_t x = *(const int32_t *)a, y = *(const int32_t *)b;

	return x < y ? -1 : x > y;
}

static uint8_t pick_alg(const wrt_mg_cluster_spec *s, uint32_t n)
{
	uint8_t alg = s->bucket_alg ? s->bucket_alg : WRT_MG_ALG_STRAW2;

	if (alg == WRT_MG_ALG_TREE && n > 64)
		alg = WRT_MG_ALG_STRAW2;
	return alg;
}

static void carg_rows(wrt_mg_carg *a, const wrt_mg_bucket *b, uint32_t rows, wrt_mg_rng *r)
{
	uint32_t k, i;

	a->index = (uint32_t)(-1 - b->id);
	wrt_mg_vec_resize0(&a->rows, sizeof(wrt_mg_wrow), rows);
	for (k = 0; k < rows; k++) {
		wrt_mg_wrow *row = &WRT_MG_E(a->rows, wrt_mg_wrow, k);

		wrt_mg_vec_resize0(&row->w, sizeof(uint32_t), b->items.n);
		for (i = 0; i < b->items.n; i++) {
			uint32_t w = WRT_MG_E(b->item_weights, uint32_t, i);
			uint32_t j = w / 4;

			WRT_MG_E(row->w, uint32_t, i) = w - j + (j ? wrt_mg_rng_below(r, 2 * j + 1) : 0u);
		}
	}
}

static void add_choose_args(wrt_mg_crush *c, const wrt_mg_cluster_spec *s, int64_t key, int with_ids, uint64_t seed,
			    int32_t first_shadow)
{
	wrt_mg_rng r;
	wrt_mg_cset set;
	uint32_t i, j;

	wrt_mg_rng_seed(&r, seed);
	memset(&set, 0, sizeof(set));
	set.key = key;
	for (i = 0; i < c->buckets.n; i++) {
		wrt_mg_bucket *b = &WRT_MG_E(c->buckets, wrt_mg_bucket, i);
		wrt_mg_carg a;

		if (!b->present || b->alg != WRT_MG_ALG_STRAW2 || b->items.n == 0)
			continue;
		memset(&a, 0, sizeof(a));
		carg_rows(&a, b, s->choose_args_rows, &r);
		if (with_ids && b->id > first_shadow) { /* shadow buckets (ids below first_shadow) carry no ids */
			wrt_mg_vec_resize0(&a.ids, sizeof(int32_t), b->items.n);
			for (j = 0; j < b->items.n; j++) {
				int32_t it = WRT_MG_E(b->items, int32_t, j);

				WRT_MG_E(a.ids, int32_t, j) = it >= 0 ? it + 100000 : it;
			}
		}
		WRT_MG_PUSH(set.bucks, wrt_mg_carg, a);
	}
	WRT_MG_PUSH(c->choose_args, wrt_mg_cset, set);
}

int wrt_mg_build_crush(wrt_mg_crush *c, const wrt_mg_cluster_spec *s)
{
	uint32_t n = s->n_osds, per_host = s->osds_per_host ? s->osds_per_host : 4;
	uint32_t n_hosts = n ? (n + per_host - 1) / per_host : 0;
	uint32_t hpr = s->hosts_per_rack, n_racks = hpr ? (n_hosts + hpr - 1) / hpr : 0;
	uint32_t ncls = s->n_classes > 3 ? 3 : s->n_classes;
	uint32_t i, h, r, k;
	uint32_t *dw;
	int32_t *cls;
	node root, *racks, *hosts;
	wrt_mg_rng rng;
	int32_t next_id, first_shadow;
	uint32_t dev_w = s->dev_weight ? s->dev_weight : WRT_MG_W_IN;
	char nm[64];

	wrt_mg_crush_init(c);
	wrt_mg_crush_tunables(c, s->tunables);
	c->upto = s->crush_upto;
	wrt_mg_rng_seed(&rng, s->seed ^ 0xc0ffee1234567ull);
	dw = (uint32_t *)calloc(n ? n : 1, sizeof(uint32_t));
	cls = (int32_t *)calloc(n ? n : 1, sizeof(int32_t));
	racks = (node *)calloc(n_racks ? n_racks : 1, sizeof(node));
	hosts = (node *)calloc(n_hosts ? n_hosts : 1, sizeof(node));
	if (!dw || !cls || !racks || !hosts)
		abort();
	memset(&root, 0, sizeof(root));
	root.id = -1;
	root.type = 11;
	for (i = 0; i < n; i++) {
		dw[i] = dev_w;
		if (s->weight_jitter)
			dw[i] = dev_w - dev_w / 4 + wrt_mg_rng_below(&rng, dev_w / 2 + 1);
		cls[i] = ncls ? (int32_t)(i % ncls) : -1;
	}
	next_id = -2;
	for (r = 0; r < n_racks; r++) {
		racks[r].id = next_id--;
		racks[r].type = 3;
	}
	for (h = 0; h < n_hosts; h++) {
		hosts[h].id = next_id--;
		hosts[h].type = 1;
		for (i = h * per_host; i < n && i < (h + 1) * per_host; i++)
			node_add(&hosts[h], (int32_t)i, dw[i]);
	}
	for (r = 0; r < n_racks; r++)
		for (h = r * hpr; h < n_hosts && h < (r + 1) * hpr; h++)
			node_add(&racks[r], hosts[h].id, node_total(&hosts[h]));
	if (n_racks)
		for (r = 0; r < n_racks; r++)
			node_add(&root, racks[r].id, node_total(&racks[r]));
	else
		for (h = 0; h < n_hosts; h++)
			node_add(&root, hosts[h].id, node_total(&hosts[h]));
	first_shadow = next_id;

	/* names of the types and of the devices and buckets */
	for (i = 0; i < 12; i++)
		wrt_mg_crush_name(c, 0, (int32_t)i, type_name_tab[i]);
	/* real buckets: root, racks, hosts (children first would not matter: slots are by id) */
	wrt_mg_crush_add_bucket(c, root.id, root.type, pick_alg(s, root.n), root.items, root.w, root.n);
	wrt_mg_crush_name(c, 1, root.id, "default");
	for (r = 0; r < n_racks; r++) {
		wrt_mg_crush_add_bucket(c, racks[r].id, racks[r].type, pick_alg(s, racks[r].n), racks[r].items,
					racks[r].w, racks[r].n);
		snprintf(nm, sizeof(nm), "rack%u", r);
		wrt_mg_crush_name(c, 1, racks[r].id, nm);
	}
	for (h = 0; h < n_hosts; h++) {
		wrt_mg_crush_add_bucket(c, hosts[h].id, hosts[h].type, pick_alg(s, hosts[h].n), hosts[h].items,
					hosts[h].w, hosts[h].n);
		snprintf(nm, sizeof(nm), "host%u", h);
		wrt_mg_crush_name(c, 1, hosts[h].id, nm);
	}
	for (i = 0; i < n; i++) {
		snprintf(nm, sizeof(nm), "osd.%u", i);
		wrt_mg_crush_name(c, 1, (int32_t)i, nm);
	}

	/* device classes: one shadow tree per class (crush note 2.6) */
	for (k = 0; k < ncls; k++) {
		wrt_mg_cls_name cn;
		node sroot;
		int32_t sroot_id = 0;

		memset(&cn, 0, sizeof(cn));
		cn.id = (int32_t)k;
		snprintf(cn.name, sizeof(cn.name), "%s", class_name_tab[k]);
		WRT_MG_PUSH(c->class_names, wrt_mg_cls_name, cn);
		memset(&sroot, 0, sizeof(sroot));
		sroot.type = 11;
		/* shadow hosts */
		{
			int32_t *hid = (int32_t *)calloc(n_hosts ? n_hosts : 1, sizeof(int32_t));
			int32_t *rid = (int32_t *)calloc(n_racks ? n_racks : 1, sizeof(int32_t));
			uint32_t *hw = (uint32_t *)calloc(n_hosts ? n_hosts : 1, sizeof(uint32_t));

			if (!hid || !rid || !hw)
				abort();
			for (h = 0; h < n_hosts; h++) {
				node sh;

				memset(&sh, 0, sizeof(sh));
				for (i = 0; i < hosts[h].n; i++)
					if (cls[hosts[h].items[i]] == (int32_t)k)
						node_add(&sh, hosts[h].items[i], hosts[h].w[i]);
				if (sh.n == 0) {
					hid[h] = 0;
					continue;
				}
				hid[h] = next_id--;
				hw[h] = node_total(&sh);
				wrt_mg_crush_add_bucket(c, hid[h], 1, pick_alg(s, sh.n), sh.items, sh.w, sh.n);
				snprintf(nm, sizeof(nm), "host%u~%s", h, class_name_tab[k]);
				wrt_mg_crush_name(c, 1, hid[h], nm);
				{
					wrt_mg_cls_bucket cb;

					memset(&cb, 0, sizeof(cb));
					cb.bucket = hosts[h].id;
					WRT_MG_PUSH(cb.shadows, wrt_mg_pair, ((wrt_mg_pair){(int32_t)k, hid[h]}));
					/* appended to the entry of this bucket below (merged by a later sort pass) */
					WRT_MG_PUSH(c->class_bucket, wrt_mg_cls_bucket, cb);
				}
				{
					wrt_mg_cls_map cm = {hid[h], (int32_t)k};

					WRT_MG_PUSH(c->class_map, wrt_mg_cls_map, cm);
				}
				free(sh.items);
				free(sh.w);
			}
			if (n_racks) {
				for (r = 0; r < n_racks; r++) {
					node sr;

					memset(&sr, 0, sizeof(sr));
					for (h = r * hpr; h < n_hosts && h < (r + 1) * hpr; h++)
						if (hid[h])
							node_add(&sr, hid[h], hw[h]);
					if (sr.n == 0) {
						rid[r] = 0;
						continue;
					}
					rid[r] = next_id--;
					wrt_mg_crush_add_bucket(c, rid[r], 3, pick_alg(s, sr.n), sr.items, sr.w, sr.n);
					snprintf(nm, sizeof(nm), "rack%u~%s", r, class_name_tab[k]);
					wrt_mg_crush_name(c, 1, rid[r], nm);
					{
						wrt_mg_cls_bucket cb;

						memset(&cb, 0, sizeof(cb));
						cb.bucket = racks[r].id;
						WRT_MG_PUSH(cb.shadows, wrt_mg_pair, ((wrt_mg_pair){(int32_t)k, rid[r]}));
						WRT_MG_PUSH(c->class_bucket, wrt_mg_cls_bucket, cb);
					}
					{
						wrt_mg_cls_map cm = {rid[r], (int32_t)k};

						WRT_MG_PUSH(c->class_map, wrt_mg_cls_map, cm);
					}
					node_add(&sroot, rid[r], node_total(&sr));
					free(sr.items);
					free(sr.w);
				}
			} else {
				for (h = 0; h < n_hosts; h++)
					if (hid[h])
						node_add(&sroot, hid[h], hw[h]);
			}
			free(hid);
			free(rid);
			free(hw);
		}
		sroot_id = next_id--;
		wrt_mg_crush_add_bucket(c, sroot_id, 11, pick_alg(s, sroot.n), sroot.items, sroot.w, sroot.n);
		snprintf(nm, sizeof(nm), "default~%s", class_name_tab[k]);
		wrt_mg_crush_name(c, 1, sroot_id, nm);
		{
			wrt_mg_cls_bucket cb;
			wrt_mg_cls_map cm = {sroot_id, (int32_t)k};

			memset(&cb, 0, sizeof(cb));
			cb.bucket = -1;
			WRT_MG_PUSH(cb.shadows, wrt_mg_pair, ((wrt_mg_pair){(int32_t)k, sroot_id}));
			WRT_MG_PUSH(c->class_bucket, wrt_mg_cls_bucket, cb);
			WRT_MG_PUSH(c->class_map, wrt_mg_cls_map, cm);
		}
		free(sroot.items);
		free(sroot.w);
	}
	/* merge the one-entry class_bucket rows of the same bucket into one row each, ascending by bucket id */
	{
		wrt_mg_vec merged;
		uint32_t a, b2;

		memset(&merged, 0, sizeof(merged));
		/* ascending bucket id: -1 first would be descending in magnitude; the wire is std::map order (ascending) */
		for (a = 0; a < c->class_bucket.n; a++) {
			wrt_mg_cls_bucket *src = &WRT_MG_E(c->class_bucket, wrt_mg_cls_bucket, a);
			int found = 0;

			for (b2 = 0; b2 < merged.n; b2++) {
				wrt_mg_cls_bucket *dst = &WRT_MG_E(merged, wrt_mg_cls_bucket, b2);

				if (dst->bucket == src->bucket) {
					WRT_MG_PUSH(dst->shadows, wrt_mg_pair, WRT_MG_E(src->shadows, wrt_mg_pair, 0));
					vfree(&src->shadows);
					found = 1;
					break;
				}
			}
			if (!found)
				WRT_MG_PUSH(merged, wrt_mg_cls_bucket, *src);
		}
		vfree(&c->class_bucket);
		c->class_bucket = merged;
		if (c->class_bucket.n > 1)
			qsort(c->class_bucket.v, c->class_bucket.n, sizeof(wrt_mg_cls_bucket), cmp_int32);
	}
	/* class_map: every device, plus every shadow bucket, ascending by item */
	for (i = 0; i < n; i++)
		if (cls[i] >= 0) {
			wrt_mg_cls_map cm = {(int32_t)i, cls[i]};

			WRT_MG_PUSH(c->class_map, wrt_mg_cls_map, cm);
		}
	if (c->class_map.n > 1)
		qsort(c->class_map.v, c->class_map.n, sizeof(wrt_mg_cls_map), cmp_int32);

	/* rules */
	{
		uint32_t slot = 0;
		wrt_mg_step st[3];

		st[0].op = WRT_MG_OP_TAKE;
		st[0].a1 = -1;
		st[0].a2 = 0;
		st[1].op = WRT_MG_OP_CHOOSELEAF_FIRSTN;
		st[1].a1 = 0;
		st[1].a2 = 1;
		st[2].op = WRT_MG_OP_EMIT;
		st[2].a1 = 0;
		st[2].a2 = 0;
		wrt_mg_crush_add_rule(c, slot, 1, st, 3);
		wrt_mg_crush_name(c, 2, (int32_t)slot++, "replicated_rule");
		st[1].op = WRT_MG_OP_CHOOSE_FIRSTN;
		st[1].a2 = 0;
		wrt_mg_crush_add_rule(c, slot, 1, st, 3);
		wrt_mg_crush_name(c, 2, (int32_t)slot++, "replicated_osd");
		if (n_racks) {
			st[1].op = WRT_MG_OP_CHOOSELEAF_FIRSTN;
			st[1].a2 = 3;
			wrt_mg_crush_add_rule(c, slot, 1, st, 3);
			wrt_mg_crush_name(c, 2, (int32_t)slot++, "replicated_rack");
		}
		for (k = 0; k < ncls; k++) {
			uint32_t b2;

			st[0].a1 = 0;
			for (b2 = 0; b2 < c->class_bucket.n; b2++)
				if (WRT_MG_E(c->class_bucket, wrt_mg_cls_bucket, b2).bucket == -1) {
					wrt_mg_cls_bucket *cb = &WRT_MG_E(c->class_bucket, wrt_mg_cls_bucket, b2);
					uint32_t q;

					for (q = 0; q < cb->shadows.n; q++)
						if (WRT_MG_E(cb->shadows, wrt_mg_pair, q).from == (int32_t)k)
							st[0].a1 = WRT_MG_E(cb->shadows, wrt_mg_pair, q).to;
				}
			st[1].op = WRT_MG_OP_CHOOSELEAF_FIRSTN;
			st[1].a2 = 1;
			wrt_mg_crush_add_rule(c, slot, 1, st, 3);
			snprintf(nm, sizeof(nm), "replicated_%s", class_name_tab[k]);
			wrt_mg_crush_name(c, 2, (int32_t)slot++, nm);
		}
	}
	/* choose_args last: they refer to the finished bucket table */
	if (s->choose_args_rows && c->upto >= WRT_MG_UPTO_CARGS) {
		add_choose_args(c, s, -1, s->choose_args_ids, s->seed + 1, first_shadow);
		if (s->choose_args_pool_set) {
			/* ascending key order: -1, then 1 */
			add_choose_args(c, s, 1, 0, s->seed + 2, first_shadow);
		}
	}
	wrt_mg_crush_recount(c);

	free(root.items);
	free(root.w);
	for (r = 0; r < n_racks; r++) {
		free(racks[r].items);
		free(racks[r].w);
	}
	for (h = 0; h < n_hosts; h++) {
		free(hosts[h].items);
		free(hosts[h].w);
	}
	free(racks);
	free(hosts);
	free(dw);
	free(cls);
	return 0;
}
