/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_tab.c - the pg-keyed tables of a map slot (core/src/osdmap/wri_osdmap_tab.c):
 *
 *  - tables of 0, 1, 2 and 1,000 entries with random vector lengths (0 to the maximum of 64), keys spread over the
 *    whole 64-bit range, compared with a plain-array model: raw arrays, find for every present key and for absent
 *    keys (the neighbours of every key, 0, UINT64_MAX, random ones);
 *  - keys 0 and UINT64_MAX, alone and together; nothing can follow UINT64_MAX;
 *  - out-of-order, duplicate and over-capacity pushes (entries and values), a vector one over the maximum, a NULL
 *    vector, an unknown kind, an uncarved table: each fails with the documented status and an errinfo and leaves the
 *    slot byte-identical, and the builder keeps working afterwards;
 *  - find on odd inputs (out parameters NULL, untouched on a miss, unknown kind, empty vectors);
 *  - copy_tab round trip over all five kinds (in a different order, into a slot of exactly the needed size), and its
 *    refusals (short slot, carved table, unfinished or inconsistent source, unknown kind);
 *  - five tables filled round-robin with vectors of different lengths: offsets and values stay consistent and the
 *    tables do not disturb each other.
 */
#include "wrt.h"
#include "wri_ctx.h"
#include "wri_osdmap.h"

#define HDR ((size_t)sizeof(wri_osdmap))
#define MAXN 1000u
#define VMAX (WRI_MAP_PGVEC_MAX * 2u)

/* ---- helpers ------------------------------------------------------------------------------------ */

static uint64_t g_rng = 0xd1b54a32d192ed03ull;

static uint32_t rnd(void)
{
	g_rng ^= g_rng >> 12;
	g_rng ^= g_rng << 25;
	g_rng ^= g_rng >> 27;
	return (uint32_t)((g_rng * 0x2545F4914F6CDD1Dull) >> 32);
}
static uint32_t rnd_n(uint32_t n) { return rnd() % n; }
static uint64_t rnd64(void) { return ((uint64_t)rnd() << 32) | rnd(); }

typedef struct slot {
	uint8_t *raw, *p;
	size_t cap, total;
	uint8_t fill;
} slot;

static void slot_new(slot *s, size_t cap, uint8_t fill)
{
	uintptr_t a;

	s->total = cap + 32u + 15u + 64u;
	s->raw = (uint8_t *)malloc(s->total);
	if (s->raw == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(s->raw, 0xA5, s->total);
	a = ((uintptr_t)s->raw + 32u + 15u) & ~(uintptr_t)15u;
	s->p = (uint8_t *)a;
	s->cap = cap;
	s->fill = fill;
	memset(s->p, fill, cap);
}
static void slot_free(slot *s) { free(s->raw); }
static int slot_guard_ok(const slot *s)
{
	size_t i, pre = (size_t)(s->p - s->raw);

	for (i = 0; i < pre; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	for (i = pre + s->cap; i < s->total; i++)
		if (s->raw[i] != 0xA5)
			return 0;
	return 1;
}

/* A table as a plain model. */
typedef struct mtab {
	uint32_t n, nv;
	uint64_t key[MAXN];
	uint32_t off[MAXN + 1u];
	int32_t val[MAXN * VMAX];
} mtab;

static mtab g_model[WRI_TAB_COUNT];

static uint32_t rnd_len(void) { return rnd_n(10) == 0 ? rnd_n(VMAX + 1u) : rnd_n(6); }
static int32_t rnd_val(void) { return rnd_n(8) == 0 ? WRI_OSD_NONE : (int32_t)rnd_n(100000) - 3; }

/* Append the next entry of a model: key above the last one by a random stride, a random vector. */
static void model_add(mtab *t, uint64_t key, uint32_t len)
{
	uint32_t j;

	t->key[t->n] = key;
	for (j = 0; j < len; j++)
		t->val[t->nv + j] = rnd_val();
	t->nv += len;
	t->off[++t->n] = t->nv;
}

/* A random table of n entries; the keys cover small ones, pool-style ones and ones with only the high bits set. */
static void model_gen(mtab *t, uint32_t n)
{
	uint64_t key = rnd_n(3) == 0 ? 0u : rnd64() >> (rnd_n(4) * 16u + 8u);
	uint64_t stride;
	uint32_t i;

	memset(t->off, 0, sizeof(t->off[0]));
	t->n = t->nv = 0;
	for (i = 0; i < n; i++) {
		model_add(t, key, rnd_len());
		stride = 1u + (rnd64() >> (32u + rnd_n(32)));
		if (key > (uint64_t)-3 - stride) /* stay clear of the top: a test may put UINT64_MAX on the last key */
			break;
		key += stride;
	}
}

static int model_find(const mtab *t, uint64_t key, const int32_t **v, uint32_t *nv)
{
	uint32_t i;

	for (i = 0; i < t->n; i++)
		if (t->key[i] == key) {
			*v = t->val + t->off[i];
			*nv = t->off[i + 1u] - t->off[i];
			return 1;
		}
	return 0;
}

/* Carve the table at the given kind with exactly the model's sizes and push every entry. */
static void fill_tab(wri_mapbuild *b, unsigned kind, const mtab *t)
{
	uint32_t i;

	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(b, kind, t->n, t->nv));
	for (i = 0; i < t->n; i++)
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(b, kind, t->key[i], t->val + t->off[i], t->off[i + 1u] - t->off[i]));
}

/* The table of a map equals the model: counts, raw arrays, find for present and absent keys. */
static void expect_tab(const wri_osdmap *m, unsigned kind, const mtab *t)
{
	const wri_pgtab *p = &m->tab[kind];
	const int32_t *v, *mv;
	uint32_t nv, mnv, i, r;
	uint64_t k;

	WRT_CHECK_U64(p->n, t->n);
	WRT_CHECK_U64(p->nv, t->nv);
	if (p->n != t->n || p->nv != t->nv)
		return;
	if (t->n != 0) {
		WRT_CHECK_MEM(wri_pgtab_keys(m, kind), t->key, 8u * t->n);
		WRT_CHECK_MEM(wri_pgtab_offs(m, kind), t->off, 4u * (t->n + 1u));
	}
	if (t->nv != 0)
		WRT_CHECK_MEM(wri_pgtab_vals(m, kind), t->val, 4u * t->nv);
	for (i = 0; i < t->n; i++) {
		WRT_CHECK(wri_pgtab_find(m, kind, t->key[i], &v, &nv) == 1);
		WRT_CHECK(model_find(t, t->key[i], &mv, &mnv) == 1 && nv == mnv && v == wri_pgtab_vals(m, kind) + t->off[i]);
		/* the neighbours of a key, and keys that differ only in the high or the low half */
		k = t->key[i];
		WRT_CHECK(wri_pgtab_find(m, kind, k + 1u, NULL, NULL) == model_find(t, k + 1u, &mv, &mnv));
		WRT_CHECK(wri_pgtab_find(m, kind, k - 1u, NULL, NULL) == model_find(t, k - 1u, &mv, &mnv));
		WRT_CHECK(wri_pgtab_find(m, kind, k ^ (1ull << 32), NULL, NULL) == model_find(t, k ^ (1ull << 32), &mv, &mnv));
		WRT_CHECK(wri_pgtab_find(m, kind, k ^ 0x80000000u, NULL, NULL) == model_find(t, k ^ 0x80000000u, &mv, &mnv));
	}
	for (r = 0; r < 200; r++) {
		k = rnd_n(4) == 0 ? rnd64() : (t->n != 0 ? t->key[rnd_n(t->n)] + rnd_n(3) : rnd_n(5));
		WRT_CHECK(wri_pgtab_find(m, kind, k, &v, &nv) == model_find(t, k, &mv, &mnv));
	}
	WRT_CHECK(wri_pgtab_find(m, kind, 0, NULL, NULL) == model_find(t, 0, &mv, &mnv));
	WRT_CHECK(wri_pgtab_find(m, kind, (uint64_t)-1, NULL, NULL) == model_find(t, (uint64_t)-1, &mv, &mnv));
}

/* ---- tests ---------------------------------------------------------------------------------------- */

static void test_sizes(void)
{
	static const uint32_t sizes[] = {0, 1, 2, 3, 17, 1000};
	unsigned i, rep, kind;
	size_t cap;
	slot s;
	wri_mapbuild b;
	mtab *t = &g_model[0];

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		for (rep = 0; rep < (sizes[i] > 100 ? 2u : 12u); rep++) {
			kind = rnd_n(WRI_TAB_COUNT);
			model_gen(t, sizes[i]);
			if (sizes[i] > 1 && rnd_n(2) == 0 && t->n == sizes[i]) { /* make the last key the top of the range */
				t->key[t->n - 1u] = (uint64_t)-1;
			}
			cap = HDR + 8u * (t->n + 1u) + 4u * (t->n + 1u) + 4u * t->nv + 64u;
			slot_new(&s, cap, 0xCC);
			wri_mapbuild_begin(&b, s.p, cap, NULL);
			fill_tab(&b, kind, t);
			WRT_CHECK_U64(b.m->tab[kind].cap_n, t->n);
			WRT_CHECK_U64(b.m->tab[kind].cap_nv, t->nv);
			wri_mapbuild_finish(&b);
			WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
			expect_tab(b.m, kind, t);
			/* the other kinds are empty and say so */
			WRT_CHECK(wri_pgtab_find(b.m, (kind + 1u) % WRI_TAB_COUNT, t->n ? t->key[0] : 0, NULL, NULL) == 0);
			WRT_CHECK(slot_guard_ok(&s));
			slot_free(&s);
		}
	}
}

static void test_extreme_keys(void)
{
	slot s;
	wri_mapbuild b;
	wr_errinfo e = { 0 };
	const int32_t *v;
	uint32_t nv;
	int32_t a[2] = {7, 8}, c[1] = {9};
	size_t cap = HDR + 1024u;

	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 4, 8));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 0, a, 2)); /* the first key may be 0 */
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 1, NULL, 0)); /* an empty vector is an entry */
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 0x100000000ull, c, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, (uint64_t)-1, a, 2));
	/* nothing can follow the largest key, not even itself, and the table is full anyway: keys are judged first */
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, (uint64_t)-1, NULL, 0));
	memset(&e, 0, sizeof(e)); /* the errinfo keeps the first failure */
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 5, NULL, 0));
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, e.status);
	WRT_CHECK(e.what != NULL && e.a0 == 5 && e.a1 == (uint64_t)-1 && e.a2 == WRI_TAB_PG_UPMAP);
	wri_mapbuild_finish(&b);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 0, &v, &nv) && nv == 2 && v[0] == 7 && v[1] == 8);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 1, &v, &nv) && nv == 0);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 0x100000000ull, &v, &nv) && nv == 1 && v[0] == 9);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, (uint64_t)-1, &v, &nv) && nv == 2 && v[1] == 8);
	WRT_CHECK(!wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 2, NULL, NULL) && !wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 0xffffffffull, NULL, NULL));
	WRT_CHECK(!wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, (uint64_t)-1 - 1u, NULL, NULL) && !wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP, 0x100000001ull, NULL, NULL));
	slot_free(&s);

	/* a table that holds only UINT64_MAX; and only 0 */
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PRIMARY_TEMP, 1, 1));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP_PRIMARY, 1, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PRIMARY_TEMP, (uint64_t)-1, c, 1));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_PRIMARY, 0, c, 1));
	wri_mapbuild_finish(&b);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PRIMARY_TEMP, (uint64_t)-1, &v, &nv) && nv == 1 && *v == 9);
	WRT_CHECK(!wri_pgtab_find(b.m, WRI_TAB_PRIMARY_TEMP, 0, NULL, NULL));
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_PRIMARY, 0, &v, &nv) && nv == 1 && *v == 9);
	WRT_CHECK(!wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_PRIMARY, (uint64_t)-1, NULL, NULL));
	slot_free(&s);
}

/* One failing push: the status, the errinfo, and the slot and the builder byte-identical. */
static void expect_push_fail(wri_mapbuild *b, wr_errinfo *e, slot *s, unsigned kind, uint64_t key, const int32_t *vals, uint32_t nvals,
			     wr_status want, const char *what_part)
{
	uint8_t *before = (uint8_t *)malloc(s->cap);
	size_t used = b->used;

	if (before == NULL)
		exit(2);
	memcpy(before, s->p, s->cap);
	memset(e, 0, sizeof(*e));
	WRT_CHECK_STATUS(want, wri_pgtab_push(b, kind, key, vals, nvals));
	WRT_CHECK_STATUS(want, e->status);
	WRT_CHECK_U64(e->module, WR_MOD_MAP);
	WRT_CHECK(e->what != NULL && strstr(e->what, what_part) != NULL);
	WRT_CHECK(memcmp(before, s->p, s->cap) == 0 && b->used == used && slot_guard_ok(s));
	free(before);
}

static void test_push_errors(void)
{
	slot s;
	wri_mapbuild b;
	wr_errinfo e = { 0 };
	int32_t vv[VMAX + 1u], one[1] = {4};
	uint32_t i;
	const int32_t *v;
	uint32_t nv;
	size_t cap = HDR + 4096u;

	for (i = 0; i < VMAX + 1u; i++)
		vv[i] = (int32_t)i;
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, &e);

	/* a table that was never carved has no room */
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 1, one, 1, WR_E_MAP_BUDGET, "entry room");
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_TEMP, 3, 5));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 2, VMAX));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 10, vv, 2));

	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 9, one, 1, WR_E_MAP_CORRUPT, "ascending"); /* out of order */
	WRT_CHECK(e.a0 == 9 && e.a1 == 10 && e.a2 == WRI_TAB_PG_TEMP);
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 10, one, 1, WR_E_MAP_CORRUPT, "ascending"); /* duplicate */
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 0, NULL, 0, WR_E_MAP_CORRUPT, "ascending");
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 11, vv, 4, WR_E_MAP_BUDGET, "value room"); /* 2 + 4 > 5 */
	WRT_CHECK(e.a0 == 6 && e.a1 == 5 && e.a2 == WRI_TAB_PG_TEMP);
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 11, NULL, 1, WR_E_INVAL, "missing");
	expect_push_fail(&b, &e, &s, WRI_TAB_COUNT, 11, one, 1, WR_E_INVAL, "kind");
	expect_push_fail(&b, &e, &s, 0xffffffffu, 11, one, 1, WR_E_INVAL, "kind");
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_UPMAP, 1, vv, VMAX + 1u, WR_E_MAP_BUDGET, "longer"); /* one over the maximum */
	WRT_CHECK(e.a0 == VMAX + 1u && e.a1 == VMAX);
	/* the maximum itself is fine */
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 1, vv, VMAX));
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_UPMAP, 2, one, 1, WR_E_MAP_BUDGET, "value room"); /* values full, entries not */

	/* the failures did not poison the builder: fill the first table to its entry limit, then one more */
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 11, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 12, vv, 3));
	expect_push_fail(&b, &e, &s, WRI_TAB_PG_TEMP, 13, NULL, 0, WR_E_MAP_BUDGET, "entry room"); /* an empty vector needs an entry */
	WRT_CHECK(e.a0 == 4 && e.a1 == 3);
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 3, NULL, 0)); /* the other table still takes entries */

	wri_mapbuild_finish(&b);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_TEMP, 10, &v, &nv) && nv == 2 && v[0] == 0 && v[1] == 1);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_TEMP, 12, &v, &nv) && nv == 3 && v[2] == 2);
	WRT_CHECK_U64(b.m->tab[WRI_TAB_PG_TEMP].n, 3);
	WRT_CHECK_U64(b.m->tab[WRI_TAB_PG_TEMP].nv, 5);
	WRT_CHECK_U64(b.m->tab[WRI_TAB_PG_UPMAP].n, 2);
	WRT_CHECK_U64(b.m->tab[WRI_TAB_PG_UPMAP].nv, VMAX);
	slot_free(&s);
}

static void test_find_odd(void)
{
	slot s;
	wri_mapbuild b;
	const int32_t *v = (const int32_t *)0x1;
	uint32_t nv = 77;
	int32_t a[3] = {1, 2, 3};
	size_t cap = HDR + 512u;

	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP_ITEMS, 3, 4));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_ITEMS, 4, a, 3));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_ITEMS, 8, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_ITEMS, 9, a + 2, 1));
	wri_mapbuild_finish(&b);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_ITEMS, 4, NULL, NULL) == 1);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_ITEMS, 4, &v, NULL) == 1 && v[2] == 3);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_ITEMS, 4, NULL, &nv) == 1 && nv == 3);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_ITEMS, 8, &v, &nv) == 1 && nv == 0);
	v = (const int32_t *)0x1;
	nv = 77;
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_UPMAP_ITEMS, 5, &v, &nv) == 0); /* a miss leaves the outputs alone */
	WRT_CHECK(v == (const int32_t *)0x1 && nv == 77);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_COUNT, 4, &v, &nv) == 0 && wri_pgtab_find(b.m, 99, 4, &v, &nv) == 0);
	WRT_CHECK(v == (const int32_t *)0x1 && nv == 77);
	WRT_CHECK(wri_pgtab_find(b.m, WRI_TAB_PG_TEMP, 4, &v, &nv) == 0); /* a table that was never carved */
	slot_free(&s);
}

static void test_copy_tab(void)
{
	static const unsigned order[WRI_TAB_COUNT] = {3, 0, 4, 2, 1};
	static const uint32_t counts[WRI_TAB_COUNT] = {17, 0, 1, 40, 2};
	unsigned k, o, rep;
	size_t cap, need;
	slot src, dst;
	wri_mapbuild bs, bd;
	wr_errinfo e = { 0 };
	wri_osdmap fake;
	uint8_t *before;

	for (rep = 0; rep < 8; rep++) {
		need = HDR;
		cap = HDR + 8000u + 4u * 5u * 40u * VMAX;
		slot_new(&src, cap, 0xCC);
		wri_mapbuild_begin(&bs, src.p, cap, NULL);
		for (k = 0; k < WRI_TAB_COUNT; k++) {
			model_gen(&g_model[k], rep == 0 ? 0u : counts[(k + rep) % WRI_TAB_COUNT]);
			fill_tab(&bs, k, &g_model[k]);
			need += (size_t)(8u * g_model[k].n + 4u * (g_model[k].n + 1u) + 4u * g_model[k].nv);
		}
		wri_mapbuild_finish(&bs);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(bs.m));

		/* a slot of exactly the size of the five tables plus their padding: copy them in another order */
		cap = HDR + 5u * 8u + need - HDR; /* the 8-byte alignment of each key array costs at most 4 bytes */
		slot_new(&dst, cap, 0x77);
		wri_mapbuild_begin(&bd, dst.p, cap, &e);
		for (o = 0; o < WRI_TAB_COUNT; o++)
			WRT_CHECK_STATUS(WR_OK, wri_mapbuild_copy_tab(&bd, order[o], bs.m));
		WRT_CHECK(bd.used <= cap);
		for (o = 0; o < WRI_TAB_COUNT; o++) {
			WRT_CHECK_U64(bd.m->tab[order[o]].cap_n, bs.m->tab[order[o]].n);
			WRT_CHECK_U64(bd.m->tab[order[o]].cap_nv, bs.m->tab[order[o]].nv);
		}
		wri_mapbuild_finish(&bd);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(bd.m));
		for (k = 0; k < WRI_TAB_COUNT; k++)
			expect_tab(bd.m, k, &g_model[k]);
		WRT_CHECK(slot_guard_ok(&dst));

		/* a copy has no room left: a further push is a budget error */
		slot_free(&dst);
		slot_new(&dst, cap, 0x77);
		wri_mapbuild_begin(&bd, dst.p, cap, &e);
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_copy_tab(&bd, WRI_TAB_PG_TEMP, bs.m));
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_pgtab_push(&bd, WRI_TAB_PG_TEMP, (uint64_t)-1, NULL, 0));

		/* refusals leave the slot and the builder as they were */
		memset(&e, 0, sizeof(e));
		before = (uint8_t *)malloc(cap);
		if (before == NULL)
			exit(2);
		memcpy(before, dst.p, cap);
		need = bd.used;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_copy_tab(&bd, WRI_TAB_PG_TEMP, bs.m)); /* carved already */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_copy_tab(&bd, WRI_TAB_COUNT, bs.m));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_copy_tab(&bd, WRI_TAB_PRIMARY_TEMP, NULL));
		fake = *bs.m;
		fake.magic = 0; /* a map that is not finished */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_copy_tab(&bd, WRI_TAB_PRIMARY_TEMP, &fake));
		fake = *bs.m;
		fake.tab[WRI_TAB_PRIMARY_TEMP].n = fake.tab[WRI_TAB_PRIMARY_TEMP].cap_n + 1u; /* inconsistent source */
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_mapbuild_copy_tab(&bd, WRI_TAB_PRIMARY_TEMP, &fake));
		fake = *bs.m;
		fake.tab[WRI_TAB_PRIMARY_TEMP].nv = 0xffffffffu;
		fake.tab[WRI_TAB_PRIMARY_TEMP].cap_nv = 0xffffffffu; /* counts that point far outside the source */
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_mapbuild_copy_tab(&bd, WRI_TAB_PRIMARY_TEMP, &fake));
		WRT_CHECK(memcmp(before, dst.p, cap) == 0 && bd.used == need && slot_guard_ok(&dst));
		free(before);
		slot_free(&dst);

		/* a slot one byte short for a table: BUDGET, nothing changed */
		if (bs.m->tab[WRI_TAB_PG_UPMAP].n != 0) {
			size_t sz = (size_t)(8u * bs.m->tab[WRI_TAB_PG_UPMAP].n + 4u * (bs.m->tab[WRI_TAB_PG_UPMAP].n + 1u) + 4u * bs.m->tab[WRI_TAB_PG_UPMAP].nv);

			slot_new(&dst, HDR + sz - 1u, 0x77); /* the key array starts at 240 with no more than 4 bytes of padding: one byte short is short */
			wri_mapbuild_begin(&bd, dst.p, dst.cap, &e);
			memset(&e, 0, sizeof(e));
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_copy_tab(&bd, WRI_TAB_PG_UPMAP, bs.m));
			WRT_CHECK(e.what != NULL && e.a0 > e.a1 && bd.used == HDR && slot_guard_ok(&dst));
			slot_free(&dst);
		}
		slot_free(&src);
	}

	/* copy of a table that was never carved in the source: an empty table in the copy */
	slot_new(&src, HDR, 0xCC);
	wri_mapbuild_begin(&bs, src.p, HDR, NULL);
	wri_mapbuild_finish(&bs);
	slot_new(&dst, HDR + 64u, 0x77);
	wri_mapbuild_begin(&bd, dst.p, HDR + 64u, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_copy_tab(&bd, WRI_TAB_PG_UPMAP, bs.m));
	wri_mapbuild_finish(&bd);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(bd.m));
	WRT_CHECK(bd.m->tab[WRI_TAB_PG_UPMAP].n == 0 && !wri_pgtab_find(bd.m, WRI_TAB_PG_UPMAP, 0, NULL, NULL));
	WRT_CHECK(slot_guard_ok(&dst));
	slot_free(&dst);
	slot_free(&src);
}

static void test_interleaved(void)
{
	unsigned k, rounds, rep;
	uint32_t i, done[WRI_TAB_COUNT], want[WRI_TAB_COUNT], len;
	size_t cap = HDR + 5u * (8u * 60u + 4u * 61u + 4u * 60u * VMAX) + 64u;
	slot s;
	wri_mapbuild b;

	for (rep = 0; rep < 6; rep++) {
		for (k = 0; k < WRI_TAB_COUNT; k++) {
			model_gen(&g_model[k], rep == 0 ? 60u : rnd_n(61));
			want[k] = g_model[k].n;
			done[k] = 0;
		}
		slot_new(&s, cap, 0xCC);
		wri_mapbuild_begin(&b, s.p, cap, NULL);
		for (k = 0; k < WRI_TAB_COUNT; k++)
			WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, k, g_model[k].n, g_model[k].nv));
		/* round robin, one entry per table per round, in a different table order each round */
		for (rounds = 0; rounds < 60u; rounds++) {
			unsigned start = rnd_n(WRI_TAB_COUNT);

			for (i = 0; i < WRI_TAB_COUNT; i++) {
				k = (start + i) % WRI_TAB_COUNT;
				if (done[k] >= want[k])
					continue;
				len = g_model[k].off[done[k] + 1u] - g_model[k].off[done[k]];
				WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, k, g_model[k].key[done[k]], g_model[k].val + g_model[k].off[done[k]], len));
				done[k]++;
			}
		}
		wri_mapbuild_finish(&b);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
		for (k = 0; k < WRI_TAB_COUNT; k++)
			expect_tab(b.m, k, &g_model[k]);
		WRT_CHECK(slot_guard_ok(&s));
		slot_free(&s);
	}
}

int main(void)
{
	test_sizes();
	test_extreme_keys();
	test_push_errors();
	test_find_odd();
	test_copy_tab();
	test_interleaved();
	return wrt_finish();
}
