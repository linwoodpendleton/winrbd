/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_core.c - the map slot builder and the structural check (core/src/osdmap/wri_osdmap.c).
 *
 *  - random maps (random section sizes, random carve order, random content) built into a guarded slot and compared with
 *    a plain-array model through every accessor; the layout (offsets, padding, zeroing, the affinity default) is
 *    predicted from the carve sizes; a second build over a differently pre-filled slot gives the same bytes;
 *  - the slot made one byte too short at each section that grows it: BUDGET with a useful errinfo, the builder and
 *    the slot untouched, the guard bands around the slot intact;
 *  - slots that cannot even hold the header, a NULL and a misaligned slot, a slot of exactly the header size;
 *  - max_osd 0, 1, the hard cap and one above it (with and without the affinity array);
 *  - the CRUSH room: carve errors, the tail given back by finish when the region is last, bad regions not trimmed;
 *  - wri_osdmap_check accepts every build and rejects a copy of a rich map with each header field and each kind of
 *    content corrupted (and accepts the fields that have no invariant).
 *
 * The CRUSH region in the maps is a small hand-built one (one straw2 bucket, one rule); wri_crush_check judges it.
 */
#include "wrt.h"
#include "wri_ctx.h"
#include "wri_osdmap.h"

#include <stddef.h>

#define HDR ((size_t)sizeof(wri_osdmap))

/* ---- helpers ------------------------------------------------------------------------------------ */

static uint64_t g_rng = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(void)
{
	g_rng ^= g_rng >> 12;
	g_rng ^= g_rng << 25;
	g_rng ^= g_rng >> 27;
	return (uint32_t)((g_rng * 0x2545F4914F6CDD1Dull) >> 32);
}
static uint32_t rnd_n(uint32_t n) { return rnd() % n; }
static size_t up(size_t v, size_t a) { return (v + a - 1u) / a * a; }

/* A slot inside a malloc block: 16-byte aligned, guard bands of 0xA5 before and after, the slot itself pre-filled. */
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
static int slot_tail_untouched(const slot *s, size_t used)
{
	size_t i;

	for (i = used; i < s->cap; i++)
		if (s->p[i] != s->fill)
			return 0;
	return 1;
}

/* A small valid CRUSH region (one straw2 bucket of two devices, one replicated rule: take, emit); returns its size. */
static size_t make_crush(uint8_t *p)
{
	wri_crush *c = (wri_crush *)(void *)p;
	wri_cbucket *bk;
	wri_crule *r;
	wri_cstep *st;

	memset(p, 0, 124);
	c->magic = WRI_CRUSH_MAGIC;
	c->max_buckets = 1;
	c->max_rules = 1;
	c->max_devices = 2;
	c->bucket_tab = (uint32_t)sizeof(wri_crush);
	c->rule_tab = c->bucket_tab + 4u;
	c->set_tab = 0; /* no choose_args sets */
	c->tun.choose_total_tries = 50;
	c->tun.chooseleaf_descend_once = 1;
	bk = (wri_cbucket *)(void *)(p + 64);
	bk->id = -1;
	bk->type = 1;
	bk->alg = WRI_CRUSH_ALG_STRAW2;
	bk->size = 2;
	((int32_t *)(void *)(bk + 1))[0] = 0;
	((int32_t *)(void *)(bk + 1))[1] = 1;
	((uint32_t *)(void *)(p + 64 + 16 + 8))[0] = 0x10000u;
	((uint32_t *)(void *)(p + 64 + 16 + 8))[1] = 0x10000u;
	((uint32_t *)(void *)(p + c->bucket_tab))[0] = 64u;
	r = (wri_crule *)(void *)(p + 96);
	r->nsteps = 2;
	st = (wri_cstep *)(void *)(r + 1);
	st[0].op = WRI_CRUSH_OP_TAKE;
	st[0].arg1 = -1;
	st[1].op = WRI_CRUSH_OP_EMIT;
	((uint32_t *)(void *)(p + c->rule_tab))[0] = 96u;
	c->bytes = 124u;
	return 124u;
}

/* ---- the model ------------------------------------------------------------------------------------ */

#define MAXOSD 2100u
#define TN 24u
#define TV 1600u
#define OP_OSDS 0u
#define OP_POOLS 1u
#define OP_TAB 2u /* .. 6 */
#define OP_CRUSH 7u
#define NOPS 8u

typedef struct mtab {
	uint32_t n, nv;
	uint64_t key[TN];
	uint32_t off[TN + 1u];
	int32_t val[TV];
} mtab;

typedef struct model {
	int have[NOPS];
	unsigned order[NOPS], nops;
	uint32_t max_osd, n_pools;
	int has_aff;
	uint8_t state[MAXOSD];
	uint32_t weight[MAXOSD], aff[MAXOSD];
	wri_osd_addr addr[MAXOSD];
	wri_map_pool pool[WRI_MAP_POOLS_MAX];
	mtab tab[WRI_TAB_COUNT];
	uint32_t cap_n[WRI_TAB_COUNT], cap_nv[WRI_TAB_COUNT];
	uint8_t crush[128];
	size_t crush_len, crush_n;
	uint32_t n_exists, n_up;
} model;

static model g_md;

static void gen_tab(mtab *t, int exact)
{
	uint32_t i, len, j;
	uint64_t k;

	memset(t, 0, sizeof(*t));
	t->n = rnd_n(4) == 0 ? 0u : rnd_n(TN + 1u);
	(void)exact;
	k = rnd_n(3) == 0 ? 0u : (((uint64_t)rnd_n(5) << 32) | rnd_n(100));
	for (i = 0; i < t->n; i++) {
		t->key[i] = k;
		k += 1u + rnd_n(4) * rnd_n(100000);
		len = rnd_n(10) == 0 ? rnd_n(WRI_MAP_PGVEC_MAX * 2u + 1u) : rnd_n(5);
		for (j = 0; j < len; j++)
			t->val[t->nv + j] = rnd_n(8) == 0 ? WRI_OSD_NONE : (int32_t)rnd_n(3000) - 5;
		t->nv += len;
		t->off[i + 1u] = t->nv;
	}
}

static void gen_model(model *md)
{
	uint32_t i, r;
	unsigned op, k, j, t;

	memset(md, 0, sizeof(*md));
	for (op = 0; op < NOPS; op++)
		md->have[op] = rnd_n(100) >= 12;
	r = rnd_n(10);
	md->max_osd = !md->have[OP_OSDS] ? 0u : r == 0 ? 0u : r == 1 ? 1u : r < 6 ? rnd_n(40) : r < 9 ? rnd_n(300) : rnd_n(2049);
	md->has_aff = md->have[OP_OSDS] && rnd_n(2) == 0;
	for (i = 0; i < md->max_osd; i++) {
		md->state[i] = (uint8_t)rnd_n(4);
		md->weight[i] = rnd_n(3) == 0 ? 0u : rnd_n(0x10001u);
		md->aff[i] = rnd_n(0x10001u);
		md->addr[i].nonce = rnd();
		md->addr[i].port = (uint16_t)rnd();
		md->addr[i].family = (uint8_t)((uint8_t[]){0, WR_AF_IPV4, WR_AF_IPV6}[rnd_n(3)]);
		md->addr[i].reserved = (uint8_t)rnd();
		for (j = 0; j < 16; j++)
			md->addr[i].ip[j] = (uint8_t)rnd();
		if ((md->state[i] & WRI_OSD_EXISTS) != 0) {
			md->n_exists++;
			if ((md->state[i] & WRI_OSD_UP) != 0)
				md->n_up++;
		}
	}
	md->n_pools = md->have[OP_POOLS] ? rnd_n(WRI_MAP_POOLS_MAX + 1u) : 0u;
	for (i = 0; i < md->n_pools; i++) {
		md->pool[i].id = (int64_t)rnd_n(1000);
		md->pool[i].flags = rnd();
		md->pool[i].pg_num = rnd_n(4096);
		md->pool[i].pgp_num = rnd_n(4096);
		md->pool[i].status = (int32_t)rnd_n(3) * -141;
		md->pool[i].present = (uint8_t)rnd_n(2);
		md->pool[i].size = (uint8_t)rnd_n(5);
		md->pool[i].crush_rule = (uint8_t)rnd_n(9);
	}
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		if (md->have[OP_TAB + k])
			gen_tab(&md->tab[k], 0);
		md->cap_n[k] = md->have[OP_TAB + k] ? md->tab[k].n + (rnd_n(2) ? rnd_n(4) : 0u) : 0u;
		md->cap_nv[k] = md->have[OP_TAB + k] ? md->tab[k].nv + (rnd_n(2) ? rnd_n(40) : 0u) : 0u;
	}
	if (md->have[OP_CRUSH]) {
		md->crush_len = make_crush(md->crush);
	}
	/* carve order: the present ops shuffled; the CRUSH room last in most runs, anywhere in the others (an exact room, so
	 * that no hole is left in the middle of the slot) */
	for (op = 0; op < NOPS; op++)
		if (md->have[op] && op != OP_CRUSH)
			md->order[md->nops++] = op;
	for (j = md->nops; j > 1; j--) {
		t = md->order[j - 1u];
		i = rnd_n(j);
		md->order[j - 1u] = md->order[i];
		md->order[i] = t;
	}
	if (md->have[OP_CRUSH]) {
		j = rnd_n(10) < 7 ? md->nops : rnd_n(md->nops + 1u);
		for (i = md->nops; i > j; i--)
			md->order[i] = md->order[i - 1u];
		md->order[j] = OP_CRUSH;
		md->nops++;
		if (j == md->nops - 1u)
			md->crush_n = md->crush_len + (rnd_n(2) ? rnd_n(50) : 0u);
		else
			md->crush_n = md->crush_len;
	}
}

/* ---- one build ------------------------------------------------------------------------------------ */

typedef struct build {
	slot s;
	wri_mapbuild b;
	wr_errinfo why;
	size_t before[NOPS], after[NOPS], start[NOPS];
	wr_status st[NOPS];
	unsigned done; /* ops that succeeded, in order */
	uint8_t *croom;
	size_t end_used; /* used after all carves */
} build;

static wr_status do_op(build *bd, const model *md, unsigned op)
{
	wr_status st;

	switch (op) {
	case OP_OSDS:
		return wri_mapbuild_osds(&bd->b, md->max_osd, md->has_aff);
	case OP_POOLS:
		return wri_mapbuild_pools(&bd->b, md->n_pools);
	case OP_CRUSH:
		bd->croom = wri_mapbuild_crush_room(&bd->b, md->crush_n);
		return bd->croom != NULL ? WR_OK : bd->why.status;
	default:
		st = wri_mapbuild_tab(&bd->b, op - OP_TAB, md->cap_n[op - OP_TAB], md->cap_nv[op - OP_TAB]);
		return st;
	}
}

/* Begin and carve in the model's order until the first failure. */
static void build_carve(build *bd, const model *md, size_t cap, uint8_t fill)
{
	unsigned i;

	memset(bd, 0, sizeof(*bd));
	slot_new(&bd->s, cap, fill);
	wri_mapbuild_begin(&bd->b, bd->s.p, cap, &bd->why);
	bd->end_used = bd->b.used;
	for (i = 0; i < md->nops; i++) {
		bd->before[i] = bd->b.used;
		bd->st[i] = do_op(bd, md, md->order[i]);
		bd->after[i] = bd->b.used;
		if (bd->st[i] != WR_OK)
			return;
		bd->done++;
		bd->end_used = bd->b.used;
	}
}

/* The offsets the carve of each op must have produced, from the sizes alone. */
static void expect_layout(const build *bd, const model *md)
{
	const wri_osdmap *m = bd->b.m;
	size_t pos = HDR, so, wo, ao, dro;
	unsigned i, op, k;

	for (i = 0; i < md->nops; i++) {
		op = md->order[i];
		if (op == OP_OSDS) {
			so = up(pos, 4);
			wo = up(so + md->max_osd, 4);
			ao = md->has_aff ? up(wo + 4u * md->max_osd, 4) : 0;
			dro = up((md->has_aff ? ao : wo) + 4u * md->max_osd, 4);
			WRT_CHECK_U64(m->state_off, so);
			WRT_CHECK_U64(m->weight_off, wo);
			WRT_CHECK_U64(m->aff_off, ao);
			WRT_CHECK_U64(m->addr_off, dro);
			WRT_CHECK_U64(m->max_osd, md->max_osd);
			pos = dro + 24u * md->max_osd;
		} else if (op == OP_POOLS) {
			so = up(pos, 8);
			WRT_CHECK_U64(m->pool_off, so);
			WRT_CHECK_U64(m->n_pools, md->n_pools);
			pos = so + 56u * md->n_pools;
		} else if (op == OP_CRUSH) {
			so = up(pos, 8);
			WRT_CHECK_U64(m->crush_off, so);
			pos = so + md->crush_n;
		} else {
			k = op - OP_TAB;
			so = up(pos, 8);
			WRT_CHECK_U64(m->tab[k].key_off, so);
			WRT_CHECK_U64(m->tab[k].off_off, so + 8u * md->cap_n[k]);
			WRT_CHECK_U64(m->tab[k].val_off, so + 8u * md->cap_n[k] + 4u * (md->cap_n[k] + 1u));
			WRT_CHECK_U64(m->tab[k].cap_n, md->cap_n[k]);
			WRT_CHECK_U64(m->tab[k].cap_nv, md->cap_nv[k]);
			WRT_CHECK_U64(m->tab[k].n | m->tab[k].nv, 0);
			pos = so + 8u * md->cap_n[k] + 4u * (md->cap_n[k] + 1u) + 4u * md->cap_nv[k];
		}
		WRT_CHECK_U64(bd->after[i], pos);
	}
}

/* Everything the carves advanced over is zero, except the affinity array, which is the default. */
static void expect_zeroed(const build *bd, const model *md)
{
	size_t i, n = bd->b.used;
	uint8_t *img = (uint8_t *)calloc(n, 1);
	uint32_t j, one = WRI_OSD_IN_FULL;

	if (img == NULL)
		exit(2);
	if (md->has_aff)
		for (j = 0; j < md->max_osd; j++)
			memcpy(img + bd->b.m->aff_off + 4u * j, &one, 4);
	for (i = HDR; i < n; i++)
		if (bd->s.p[i] != img[i]) {
			WRT_CHECK(0 && "carved bytes are zero (affinity: the default)");
			break;
		}
	free(img);
}

/* Write the model's content through the builder (tables) and the slot (the arrays). */
static void fill_content(build *bd, const model *md)
{
	wri_osdmap *m = bd->b.m;
	uint8_t *base = wri_map_base_rw(m);
	unsigned k;
	uint32_t i;

	if (md->have[OP_OSDS] && md->max_osd != 0) {
		memcpy(base + m->state_off, md->state, md->max_osd);
		memcpy(base + m->weight_off, md->weight, 4u * md->max_osd);
		if (md->has_aff)
			memcpy(base + m->aff_off, md->aff, 4u * md->max_osd);
		memcpy(base + m->addr_off, md->addr, sizeof(wri_osd_addr) * md->max_osd);
	}
	if (md->n_pools != 0)
		memcpy(base + m->pool_off, md->pool, sizeof(wri_map_pool) * md->n_pools);
	for (k = 0; k < WRI_TAB_COUNT; k++)
		for (i = 0; i < md->tab[k].n; i++)
			WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&bd->b, k, md->tab[k].key[i], md->tab[k].val + md->tab[k].off[i],
							       md->tab[k].off[i + 1u] - md->tab[k].off[i]));
	if (bd->croom != NULL)
		memcpy(bd->croom, md->crush, md->crush_len);
}

static void verify_model(const wri_osdmap *m, const model *md, size_t used)
{
	int32_t id;
	uint32_t i, nv, nvv, got = 0;
	unsigned k;
	const int32_t *v;

	WRT_CHECK_U64(m->magic, WRI_MAP_MAGIC);
	WRT_CHECK_U64(m->n_exists, md->n_exists);
	WRT_CHECK_U64(m->n_up, md->n_up);
	WRT_CHECK(m->bytes <= m->cap && m->bytes >= HDR);
	if (md->have[OP_CRUSH] && used - m->crush_off >= md->crush_len && md->order[md->nops - 1u] == OP_CRUSH)
		WRT_CHECK_U64(m->bytes, (size_t)m->crush_off + md->crush_len); /* the unused tail of the room is given back */
	else
		WRT_CHECK_U64(m->bytes, used);
	WRT_CHECK((wri_map_aff(m) != NULL) == (md->has_aff != 0));
	for (id = -2; id < (int32_t)md->max_osd + 3; id++) {
		int in = id >= 0 && (uint32_t)id < md->max_osd;
		int ex = in && (md->state[id] & WRI_OSD_EXISTS) != 0;
		int upv = ex && (md->state[id] & WRI_OSD_UP) != 0;

		WRT_CHECK(wri_osd_exists(m, id) == ex);
		WRT_CHECK(wri_osd_up(m, id) == upv);
		WRT_CHECK_U64(wri_osd_weight(m, id), in ? md->weight[id] : 0u);
		WRT_CHECK_U64(wri_osd_aff(m, id), (in && md->has_aff) ? md->aff[id] : (uint32_t)WRI_OSD_IN_FULL);
	}
	WRT_CHECK(wri_osd_aff(m, 0x7fffffff) == WRI_OSD_IN_FULL && wri_osd_weight(m, -1) == 0 && !wri_osd_exists(m, 0x7fffffff));
	if (md->max_osd != 0) {
		WRT_CHECK_MEM(wri_map_state(m), md->state, md->max_osd);
		WRT_CHECK_MEM(wri_map_weight(m), md->weight, 4u * md->max_osd);
		WRT_CHECK_MEM(wri_map_addr(m), md->addr, sizeof(wri_osd_addr) * md->max_osd);
	}
	if (md->n_pools != 0)
		WRT_CHECK_MEM(wri_map_pools(m), md->pool, sizeof(wri_map_pool) * md->n_pools);
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		const mtab *t = &md->tab[k];

		WRT_CHECK_U64(m->tab[k].n, t->n);
		WRT_CHECK_U64(m->tab[k].nv, t->nv);
		for (i = 0; i < t->n; i++) {
			WRT_CHECK(wri_pgtab_find(m, k, t->key[i], &v, &nv) == 1);
			nvv = t->off[i + 1u] - t->off[i];
			WRT_CHECK_U64(nv, nvv);
			if (nv == nvv && nvv != 0)
				WRT_CHECK_MEM(v, t->val + t->off[i], 4u * nvv);
			got++;
			WRT_CHECK(wri_pgtab_find(m, k, t->key[i] + 1u, NULL, NULL) == (i + 1u < t->n && t->key[i + 1u] == t->key[i] + 1u));
		}
	}
	if (md->have[OP_CRUSH])
		WRT_CHECK(wri_map_crush(m) != NULL && memcmp(wri_map_crush(m), md->crush, md->crush_len) == 0);
	else
		WRT_CHECK(wri_map_crush(m) == NULL);
	(void)got;
}

static size_t img_copy(const build *bd, uint8_t *dst) { memcpy(dst, bd->s.p, bd->b.m->bytes); return bd->b.m->bytes; }

static void test_random_builds(void)
{
	enum { ROUNDS = 400 };
	static uint8_t imgA[1u << 18], imgB[1u << 18];
	size_t big = 160000u, na, nb, used;
	int r;
	unsigned i;
	build bd, bd2;
	const model *md = &g_md;
	wr_errinfo e;

	for (r = 0; r < ROUNDS; r++) {
		gen_model(&g_md);
		/* a build in a roomy slot pre-filled with zeros, and one pre-filled with 0xFF */
		build_carve(&bd, md, big, 0x00);
		WRT_CHECK_U64(bd.done, md->nops);
		WRT_CHECK_U64(bd.why.status, WR_OK);
		if (bd.done != md->nops) {
			slot_free(&bd.s);
			continue;
		}
		expect_layout(&bd, md);
		expect_zeroed(&bd, md);
		used = bd.b.used;
		WRT_CHECK_U64(wri_mapbuild_left(&bd.b), big - used);
		fill_content(&bd, md);
		wri_mapbuild_finish(&bd.b);
		verify_model(bd.b.m, md, used);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(bd.b.m));
		WRT_CHECK(slot_guard_ok(&bd.s) && slot_tail_untouched(&bd.s, used));
		na = img_copy(&bd, imgA);

		build_carve(&bd2, md, big, 0xFF);
		fill_content(&bd2, md);
		wri_mapbuild_finish(&bd2.b);
		nb = img_copy(&bd2, imgB);
		WRT_CHECK(na == nb && memcmp(imgA, imgB, na) == 0); /* a map does not depend on what the slot held before */
		slot_free(&bd2.s);

		/* exactly enough room: the same map, nothing left over */
		build_carve(&bd2, md, used, 0x5A);
		WRT_CHECK_U64(bd2.done, md->nops);
		WRT_CHECK_U64(wri_mapbuild_left(&bd2.b), 0);
		fill_content(&bd2, md);
		wri_mapbuild_finish(&bd2.b);
		verify_model(bd2.b.m, md, used);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(bd2.b.m));
		WRT_CHECK(slot_guard_ok(&bd2.s));
		slot_free(&bd2.s);

		/* one byte short at each section that grows the slot */
		for (i = 0; i < md->nops; i++) {
			wri_osdmap hdr;
			size_t cap;

			if (bd.after[i] <= bd.before[i])
				continue;
			cap = bd.after[i] - 1u;
			build_carve(&bd2, md, cap, 0xCC);
			WRT_CHECK_U64(bd2.done, i);
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, bd2.st[i]);
			e = bd2.why;
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, e.status);
			WRT_CHECK_U64(e.module, WR_MOD_MAP);
			WRT_CHECK(e.what != NULL && strstr(e.what, "too small") != NULL);
			WRT_CHECK(e.a0 > e.a1); /* the section wanted more than was left where it would start */
			WRT_CHECK_U64(e.a2, cap);
			WRT_CHECK(e.a1 <= cap - bd.before[i]); /* equal for a one-array section, less when an earlier array of the op was planned */
			WRT_CHECK_U64(bd2.b.used, bd.before[i]); /* all or nothing: the builder did not move */
			hdr = *bd2.b.m;
			WRT_CHECK(slot_guard_ok(&bd2.s) && slot_tail_untouched(&bd2.s, bd.before[i]));
			/* a retry of the same op on the failed builder fails the same way; the slot is still untouched */
			bd2.why.status = WR_OK;
			WRT_CHECK_STATUS(WR_E_MAP_BUDGET, do_op(&bd2, md, md->order[i]));
			WRT_CHECK(memcmp(&hdr, bd2.b.m, sizeof(hdr)) == 0 && slot_tail_untouched(&bd2.s, bd.before[i]));
			slot_free(&bd2.s);
		}
		slot_free(&bd.s);
	}
}

/* ---- slots that cannot be used -------------------------------------------------------------------- */

static void test_bad_slots(void)
{
	size_t caps[] = {0, 1, 100, HDR - 1u};
	unsigned i;
	slot s;
	wri_mapbuild b;
	wr_errinfo e;
	uint8_t *room;
	wri_osdmap fin;

	for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
		slot_new(&s, caps[i] + 512u, 0xCC); /* the slot has room behind it that must stay untouched */
		memset(&e, 0, sizeof(e));
		wri_mapbuild_begin(&b, s.p, caps[i], &e);
		WRT_CHECK(b.m == NULL);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, e.status);
		WRT_CHECK(e.what != NULL && e.a0 == HDR && e.a1 == caps[i]);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_status(&b));
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_osds(&b, 1, 0));
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_pools(&b, 1));
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_tab(&b, WRI_TAB_PG_TEMP, 1, 1));
		WRT_CHECK(wri_mapbuild_crush_room(&b, 8) == NULL);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 1, NULL, 0));
		memset(&fin, 0, sizeof(fin));
		fin.magic = WRI_MAP_MAGIC;
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_copy_tab(&b, WRI_TAB_PG_TEMP, &fin));
		WRT_CHECK_U64(wri_mapbuild_left(&b), 0);
		wri_mapbuild_finish(&b); /* nothing to finish */
		WRT_CHECK(slot_guard_ok(&s) && slot_tail_untouched(&s, 0));
		slot_free(&s);
	}

	/* NULL slot, no errinfo wanted: a bad argument, as the header says (a NULL slot with no room for the header is still too small) */
	wri_mapbuild_begin(&b, NULL, 4096, NULL);
	WRT_CHECK(b.m == NULL && wri_mapbuild_left(&b) == 0 && wri_mapbuild_crush_left(&b) == 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_status(&b));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_osds(&b, 1, 0));
	WRT_CHECK(wri_mapbuild_crush_room(&b, 8) == NULL);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, NULL, 4096, &e);
	WRT_CHECK_STATUS(WR_E_INVAL, e.status);
	WRT_CHECK(e.what != NULL && strstr(e.what, "NULL") != NULL);
	wri_mapbuild_begin(&b, NULL, 8, NULL);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_status(&b));
	wri_mapbuild_begin(&b, NULL, 0, NULL);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_status(&b));

	/* misaligned slot: refused as a bad argument, nothing written */
	slot_new(&s, 4096, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p + 4, 4000, &e);
	WRT_CHECK(b.m == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, e.status);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_status(&b));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_osds(&b, 1, 0));
	room = wri_mapbuild_crush_room(&b, 16);
	WRT_CHECK(room == NULL && wri_mapbuild_left(&b) == 0);
	WRT_CHECK(slot_guard_ok(&s) && slot_tail_untouched(&s, 0));
	slot_free(&s);

	/* a slot of exactly the header size: an empty map (nothing carved) is valid and has no room for anything */
	slot_new(&s, HDR, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, HDR, &e);
	WRT_CHECK(b.m != NULL && e.status == WR_OK);
	WRT_CHECK_U64(wri_mapbuild_left(&b), 0);
	WRT_CHECK_U64(b.m->magic, 0);
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_osdmap_check(b.m)); /* not finished */
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_osds(&b, 1, 0));
	WRT_CHECK_U64(e.status, WR_E_MAP_BUDGET);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 0, 0)); /* zero bytes at a 4-aligned offset: fits */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_osds(&b, 0, 0)); /* twice is a caller bug */
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_pools(&b, 0)); /* the 8-byte alignment of the records needs 4 bytes more than the slot has */
	wri_mapbuild_finish(&b);
	WRT_CHECK_U64(b.m->bytes, HDR);
	WRT_CHECK_U64(b.m->magic, WRI_MAP_MAGIC);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	WRT_CHECK(!wri_osd_exists(b.m, 0) && wri_osd_weight(b.m, 0) == 0 && wri_osd_aff(b.m, 0) == WRI_OSD_IN_FULL);
	WRT_CHECK(!wri_pgtab_find(b.m, WRI_TAB_PG_TEMP, 0, NULL, NULL));
	WRT_CHECK(slot_guard_ok(&s));
	slot_free(&s);

	/* a clamp: cap beyond 4 GiB cannot be carved by offsets, but a small request is unaffected (64-bit hosts only) */
	if (sizeof(size_t) > 4u) {
		slot_new(&s, 4096, 0xCC);
		wri_mapbuild_begin(&b, s.p, 4096, NULL);
		WRT_CHECK_U64(b.cap, 4096);
		slot_free(&s);
	}
}

/* ---- max_osd limits ------------------------------------------------------------------------------- */

static void test_max_osd(void)
{
	uint32_t sizes[] = {0, 1, 2, WRI_MAP_OSD_HARD_MAX};
	unsigned i, aff;
	slot s;
	wri_mapbuild b;
	wr_errinfo e;
	size_t cap;
	uint32_t n, j;
	wri_osdmap hdr;

	for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		for (aff = 0; aff < 2; aff++) {
			n = sizes[i];
			cap = HDR + (size_t)n * (1u + 4u + 4u + 24u) + 64u;
			slot_new(&s, cap, 0xCC);
			memset(&e, 0, sizeof(e));
			wri_mapbuild_begin(&b, s.p, cap, &e);
			WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, n, (int)aff));
			WRT_CHECK_U64(b.m->max_osd, n);
			WRT_CHECK_U64(b.m->aff_off != 0, aff);
			wri_mapbuild_finish(&b);
			WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
			WRT_CHECK_U64(b.m->n_exists | b.m->n_up, 0);
			for (j = 0; j < n; j += (n > 5000 ? 977u : 1u)) {
				WRT_CHECK(!wri_osd_exists(b.m, (int32_t)j) && wri_osd_weight(b.m, (int32_t)j) == 0);
				WRT_CHECK_U64(wri_osd_aff(b.m, (int32_t)j), WRI_OSD_IN_FULL);
				WRT_CHECK_U64(wri_map_addr(b.m)[j].family, 0);
			}
			if (n != 0) {
				/* the last element is addressable: write it, check the check still passes and the guard holds */
				wri_map_base_rw(b.m)[b.m->state_off + n - 1u] = WRI_OSD_EXISTS | WRI_OSD_UP;
				((uint32_t *)(void *)(wri_map_base_rw(b.m) + b.m->weight_off))[n - 1u] = 0x10000u;
				((wri_osd_addr *)(void *)(wri_map_base_rw(b.m) + b.m->addr_off))[n - 1u].family = WR_AF_IPV4;
				b.m->n_exists = b.m->n_up = 1;
				WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
				WRT_CHECK(wri_osd_up(b.m, (int32_t)(n - 1u)) && !wri_osd_exists(b.m, (int32_t)n));
			}
			WRT_CHECK(slot_guard_ok(&s));
			slot_free(&s);
		}
	}

	/* one above the cap fails whatever the slot size, and changes nothing */
	cap = HDR + (size_t)(WRI_MAP_OSD_HARD_MAX + 1u) * 40u;
	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	hdr = *b.m;
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_osds(&b, WRI_MAP_OSD_HARD_MAX + 1u, 0));
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, e.status);
	WRT_CHECK(e.what != NULL && strstr(e.what, "hard cap") != NULL);
	WRT_CHECK_U64(e.a0, WRI_MAP_OSD_HARD_MAX + 1u);
	WRT_CHECK_U64(e.a1, WRI_MAP_OSD_HARD_MAX);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_osds(&b, 0xffffffffu, 1));
	WRT_CHECK(memcmp(&hdr, b.m, sizeof(hdr)) == 0 && b.used == HDR && slot_tail_untouched(&s, HDR));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 3, 1)); /* the failed attempts left the builder usable */
	slot_free(&s);
}

/* ---- the CRUSH room ------------------------------------------------------------------------------- */

static void test_crush_room(void)
{
	slot s;
	wri_mapbuild b;
	wr_errinfo e;
	uint8_t *room, *room2;
	size_t cap = 4096, left, n;
	const wri_osdmap *m;

	/* the whole rest of the slot, a smaller region decoded into it, the room being last: finish gives the tail back */
	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 5, 1));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_pools(&b, 2));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_TEMP, 0, 0));
	left = wri_mapbuild_crush_left(&b);
	WRT_CHECK(left <= wri_mapbuild_left(&b) && wri_mapbuild_left(&b) - left < 8u); /* what is left, less what the alignment eats */
	WRT_CHECK(wri_mapbuild_crush_room(&b, left + 1u) == NULL); /* one more does not fit */
	room = wri_mapbuild_crush_room(&b, left);
	WRT_CHECK(room != NULL);
	if (room == NULL) {
		slot_free(&s);
		return;
	}
	WRT_CHECK_U64(wri_mapbuild_left(&b), 0);
	WRT_CHECK_U64(wri_mapbuild_crush_left(&b), 0);
	WRT_CHECK(((uintptr_t)room & 7u) == 0);
	WRT_CHECK_U64(room - s.p, b.m->crush_off);
	for (n = 0; n < 128; n++)
		if (room[n] != 0)
			WRT_CHECK(0 && "room zeroed");
	memset(&e, 0, sizeof(e)); /* the errinfo keeps the first failure: the one-too-many attempt above */
	WRT_CHECK(wri_mapbuild_crush_room(&b, 16) == NULL); /* twice */
	WRT_CHECK_STATUS(WR_E_INVAL, e.status);
	n = make_crush(room);
	wri_mapbuild_finish(&b);
	m = b.m;
	WRT_CHECK_U64(m->bytes, (size_t)m->crush_off + n);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(m));
	WRT_CHECK(slot_guard_ok(&s));
	slot_free(&s);

	/* a region that is not there (zeros: no magic) is not trimmed, and the check refuses the map */
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 1, 0));
	room = wri_mapbuild_crush_room(&b, 200);
	WRT_CHECK(room != NULL);
	wri_mapbuild_finish(&b);
	WRT_CHECK_U64(b.m->bytes, (size_t)b.m->crush_off + 200u);
	WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_osdmap_check(b.m));
	slot_free(&s);

	/* a region that says it is longer than its room is not trimmed either (and is refused by the check) */
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	room = wri_mapbuild_crush_room(&b, 130);
	WRT_CHECK(room != NULL);
	if (room != NULL) {
		(void)make_crush(room);
		((wri_crush *)(void *)room)->bytes = 131;
		wri_mapbuild_finish(&b);
		WRT_CHECK_U64(b.m->bytes, (size_t)b.m->crush_off + 130u);
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_osdmap_check(b.m));
	}
	slot_free(&s);

	/* the room is not last: nothing is trimmed; an exact room is a valid map, an oversized one leaves a hole the check refuses */
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	room = wri_mapbuild_crush_room(&b, 124);
	WRT_CHECK(room != NULL);
	if (room != NULL) {
		(void)make_crush(room);
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 1, 1));
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 7, (int32_t[]){3}, 1));
		wri_mapbuild_finish(&b);
		WRT_CHECK_U64(b.m->bytes, b.used);
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(b.m));
	}
	slot_free(&s);
	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, NULL);
	room = wri_mapbuild_crush_room(&b, 164);
	if (room != NULL) {
		(void)make_crush(room);
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 1, 1));
		wri_mapbuild_finish(&b);
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_osdmap_check(b.m));
	}
	slot_free(&s);

	/* a zero-size room and a room that does not fit */
	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK(wri_mapbuild_crush_room(&b, 0) == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, e.status);
	memset(&e, 0, sizeof(e));
	WRT_CHECK(wri_mapbuild_crush_room(&b, cap) == NULL); /* header + room > slot */
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, e.status);
	WRT_CHECK(e.what != NULL && strstr(e.what, "CRUSH") != NULL && e.a0 > e.a1);
	WRT_CHECK(b.m->crush_off == 0 && b.used == HDR);
	room2 = wri_mapbuild_crush_room(&b, cap - HDR - 8u); /* fits after the failed attempts */
	WRT_CHECK(room2 != NULL || cap - HDR - 8u > cap);
	WRT_CHECK(slot_guard_ok(&s));
	slot_free(&s);
}

/* ---- sizes that come from a hostile map: no wrap, no write, no change -------------------------------- */

static void test_huge_sizes(void)
{
	/* sizes a decoder could compute from lengths in an attacker's map; the second group wraps a 64-bit start + len */
	static const uint64_t room_sizes[] = {4096u - HDR + 1u, 4096u, 0x7fffffffull, 0xffffffffull, 0x100000000ull, 0x100000100ull,
					      0x7fffffffffffffffull, 0xfffffffffffffff0ull, 0xffffffffffffff00ull, 0xffffffffffffffffull};
	size_t cap = 4096;
	slot s;
	wri_mapbuild b;
	wr_errinfo e;
	wri_osdmap hdr;
	unsigned i;
	size_t n, used;
	uint8_t *room;

	slot_new(&s, cap, 0xCC);
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 3, 0));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_TEMP, 1, 1));
	hdr = *b.m;
	used = b.used;
	for (i = 0; i < sizeof(room_sizes) / sizeof(room_sizes[0]); i++) {
		if (room_sizes[i] > (uint64_t)(size_t)-1) /* a 32-bit size_t cannot say it */
			continue;
		n = (size_t)room_sizes[i];
		memset(&e, 0, sizeof(e));
		room = wri_mapbuild_crush_room(&b, n);
		WRT_CHECK(room == NULL);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, e.status);
		WRT_CHECK(e.what != NULL && strstr(e.what, "CRUSH") != NULL && e.a0 >= e.a1);
		WRT_CHECK(b.used == used && memcmp(&hdr, b.m, sizeof(hdr)) == 0 && slot_tail_untouched(&s, used) && slot_guard_ok(&s));
	}
	/* a length that would make start + len wrap to just the right place: the start is the aligned end of what is carved */
	n = (size_t)0 - ((used + 7u) & ~(size_t)7u);
	WRT_CHECK(wri_mapbuild_crush_room(&b, n) == NULL && b.used == used && b.m->crush_off == 0);
	WRT_CHECK(slot_tail_untouched(&s, used) && slot_guard_ok(&s));
	/* the biggest table and array requests at once: planned in 64 bits, refused, nothing carved */
	memset(&e, 0, sizeof(e));
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 0xffffffffu, 0xffffffffu));
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP_ITEMS, 0xffffffffu, 0));
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_tab(&b, WRI_TAB_PRIMARY_TEMP, 0, 0xffffffffu));
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP_PRIMARY, 0x40000000u, 0x40000000u));
	WRT_CHECK(b.used == used && memcmp(&hdr, b.m, sizeof(hdr)) == 0 && slot_tail_untouched(&s, used) && slot_guard_ok(&s));
	/* the builder still works */
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, WRI_TAB_PG_UPMAP, 2, 2));
	room = wri_mapbuild_crush_room(&b, wri_mapbuild_crush_left(&b));
	WRT_CHECK(room != NULL);
	slot_free(&s);

	/* a claimed slot beyond 4 GiB is clamped to what offsets can address: the header says so, and a room of 4 GiB is refused
	 * (the slot behind the header is a few KiB, so nothing is carved that is not there) */
	if (sizeof(size_t) > 4u) {
		slot_new(&s, cap, 0xCC);
		wri_mapbuild_begin(&b, s.p, (size_t)1 << 33, NULL);
		WRT_CHECK(b.m != NULL);
		WRT_CHECK_U64(b.cap, 0xffffffffu);
		WRT_CHECK_U64(b.m->cap, 0xffffffffu);
		WRT_CHECK(wri_mapbuild_crush_room(&b, (size_t)1 << 32) == NULL && b.used == HDR && slot_tail_untouched(&s, HDR));
		WRT_CHECK(wri_mapbuild_crush_room(&b, (size_t)0xffffffffu) == NULL && b.used == HDR && slot_tail_untouched(&s, HDR));
		WRT_CHECK_U64(wri_mapbuild_crush_left(&b), 0xffffffffu - ((HDR + 7u) & ~(size_t)7u));
		slot_free(&s);
	}
}

/* ---- caller bugs ---------------------------------------------------------------------------------- */

static void test_caller_errors(void)
{
	slot s;
	wri_mapbuild b;
	wr_errinfo e;
	unsigned k;
	size_t cap = 8192;

	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 4, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_osds(&b, 4, 0));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_pools(&b, WRI_MAP_POOLS_MAX));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_pools(&b, 1));
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, k, 2, 2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_tab(&b, k, 2, 2));
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapbuild_tab(&b, WRI_TAB_COUNT, 1, 1));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgtab_push(&b, WRI_TAB_COUNT, 1, NULL, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 1, NULL, 1));
	slot_free(&s);

	/* too many tracked pools is a budget error and changes nothing */
	slot_new(&s, cap, 0xCC);
	memset(&e, 0, sizeof(e));
	wri_mapbuild_begin(&b, s.p, cap, &e);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_mapbuild_pools(&b, WRI_MAP_POOLS_MAX + 1u));
	WRT_CHECK(e.what != NULL && e.a0 == WRI_MAP_POOLS_MAX + 1u && e.a1 == WRI_MAP_POOLS_MAX);
	WRT_CHECK(b.used == HDR && b.m->pool_off == 0 && slot_tail_untouched(&s, HDR));
	slot_free(&s);
}

/* ---- wri_osdmap_check: accepts every build, rejects corrupted copies ------------------------------ */

/*
 * The rich map: every section non-empty and exactly sized, no alignment padding anywhere but in front of the
 * pool records (so a count that grows or shrinks by one always breaks the packing), CRUSH region last.
 */
static void build_rich(slot *s, size_t cap)
{
	wri_mapbuild b;
	uint32_t i;
	static const uint32_t nn[WRI_TAB_COUNT] = {3, 2, 3, 3, 2};
	static const uint32_t nvv[WRI_TAB_COUNT] = {8, 3, 12, 8, 3}; /* cap_n + 1 + nv is even for each: no padding after the values */
	int32_t vals[8] = {5, 6, 7, 8, 9, 10, 11, 12};
	uint8_t *room;
	uint32_t lens[3];
	unsigned k;
	wri_osdmap *m;

	slot_new(s, cap, 0xCC);
	wri_mapbuild_begin(&b, s->p, cap, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_osds(&b, 36, 1));
	WRT_CHECK_STATUS(WR_OK, wri_mapbuild_pools(&b, 3));
	for (k = 0; k < WRI_TAB_COUNT; k++)
		WRT_CHECK_STATUS(WR_OK, wri_mapbuild_tab(&b, k, nn[k], nvv[k]));
	room = wri_mapbuild_crush_room(&b, 124);
	WRT_CHECK(room != NULL);
	m = b.m;
	for (i = 0; i < 36; i++) {
		wri_map_base_rw(m)[m->state_off + i] = (uint8_t)(i % 4u == 3u ? 3u : (i % 4u));
		((uint32_t *)(void *)(wri_map_base_rw(m) + m->weight_off))[i] = i % 5u == 0 ? 0u : 0x10000u;
		((uint32_t *)(void *)(wri_map_base_rw(m) + m->aff_off))[i] = 0x8000u + i;
		((wri_osd_addr *)(void *)(wri_map_base_rw(m) + m->addr_off))[i].family = (uint8_t)(i % 3u == 0 ? 0u : i % 3u == 1 ? WR_AF_IPV4 : WR_AF_IPV6);
	}
	wri_map_base_rw(m)[m->state_off + 35] = WRI_OSD_EXISTS | WRI_OSD_UP;
	for (i = 0; i < 3; i++) {
		wri_map_pool *p = (wri_map_pool *)(void *)(wri_map_base_rw(m) + m->pool_off) + i;
		p->id = (int64_t)i + 1;
		p->present = (uint8_t)(i != 1);
		p->pg_num = 32;
	}
	lens[0] = 2, lens[1] = 3, lens[2] = 3;
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_TEMP, 10u + i, vals, lens[i]));
	for (i = 0; i < 2; i++) /* a real primary_temp entry has one value; two here so that the table has no padding behind it */
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PRIMARY_TEMP, 5u + i, vals, 1u + i));
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP, 100u * (i + 1u), vals, 4));
	lens[0] = 2, lens[1] = 4, lens[2] = 2;
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_ITEMS, 1000u * (i + 1u), vals, lens[i]));
	for (i = 0; i < 2; i++)
		WRT_CHECK_STATUS(WR_OK, wri_pgtab_push(&b, WRI_TAB_PG_UPMAP_PRIMARY, 7u + i, vals, 1u + i));
	(void)make_crush(room);
	m->epoch = 42;
	wri_mapbuild_finish(&b);
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(m));
}

static void test_check(void)
{
	slot rich, cp;
	wri_osdmap *m, *c;
	size_t n;
	unsigned k;
	wri_crush *cc;
	uint8_t *copy;

	build_rich(&rich, 4096);
	m = (wri_osdmap *)(void *)rich.p;
	n = m->bytes;
	slot_new(&cp, 4096, 0x00);
	copy = cp.p;
	c = (wri_osdmap *)(void *)copy;
	cc = NULL;

#define RESET() memcpy(copy, rich.p, n)
#define BAD(stmt)                                                                                      \
	do {                                                                                           \
		RESET();                                                                               \
		stmt;                                                                                  \
		wrt_checks++;                                                                          \
		if (wri_osdmap_check(c) != WR_E_MAP_CORRUPT) {                                         \
			wrt_failures++;                                                                \
			fprintf(stderr, "%s:%d: corruption not rejected: %s\n", __FILE__, __LINE__, #stmt); \
		}                                                                                      \
	} while (0)
#define GOOD(stmt)                                                                                     \
	do {                                                                                           \
		RESET();                                                                               \
		stmt;                                                                                  \
		wrt_checks++;                                                                          \
		if (wri_osdmap_check(c) != WR_OK) {                                                    \
			wrt_failures++;                                                                \
			fprintf(stderr, "%s:%d: valid change rejected: %s\n", __FILE__, __LINE__, #stmt); \
		}                                                                                      \
	} while (0)

	RESET();
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(c));
	WRT_CHECK(wri_osdmap_check(NULL) == WR_E_MAP_CORRUPT);
	WRT_CHECK(wri_osdmap_check((const wri_osdmap *)(const void *)(rich.p + 4)) == WR_E_MAP_CORRUPT); /* misaligned header */

	/* header words */
	BAD(c->magic ^= 1u);
	BAD(c->magic = 0);
	BAD(c->magic = WRI_CRUSH_MAGIC);
	BAD(c->bytes = (uint32_t)sizeof(wri_osdmap) - 1u);
	BAD(c->bytes = 0);
	BAD(c->bytes = c->cap + 1u);
	BAD(c->bytes -= 1u);
	BAD(c->bytes -= 8u);
	BAD(c->bytes += 8u);
	BAD(c->bytes = c->cap);
	BAD(c->cap = c->bytes - 1u);
	BAD(c->cap = 0);
	BAD(c->max_osd += 1u);
	BAD(c->max_osd -= 1u);
	BAD(c->max_osd = 0);
	BAD(c->max_osd = WRI_MAP_OSD_HARD_MAX + 1u);
	BAD(c->max_osd = 0xffffffffu);
	BAD(c->n_pools += 1u);
	BAD(c->n_pools -= 1u);
	BAD(c->n_pools = 0);
	BAD(c->n_pools = WRI_MAP_POOLS_MAX + 1u);
	BAD(c->state_off += 1u);
	BAD(c->state_off += 4u);
	BAD(c->state_off = 0);
	BAD(c->state_off = c->bytes);
	BAD(c->state_off = c->bytes + 4u);
	BAD(c->state_off = c->weight_off);
	BAD(c->state_off = (uint32_t)sizeof(wri_osdmap) - 4u);
	BAD(c->weight_off += 1u);
	BAD(c->weight_off += 4u);
	BAD(c->weight_off = 0);
	BAD(c->weight_off = c->state_off);
	BAD(c->weight_off = c->bytes);
	BAD(c->aff_off += 1u);
	BAD(c->aff_off += 4u);
	BAD(c->aff_off = 0); /* the affinity array would be an orphan hole */
	BAD(c->aff_off = c->bytes);
	BAD(c->aff_off = c->weight_off);
	BAD(c->addr_off += 1u);
	BAD(c->addr_off += 4u);
	BAD(c->addr_off = 0);
	BAD(c->addr_off = c->bytes);
	BAD(c->addr_off = c->aff_off);
	BAD(c->pool_off += 1u);
	BAD(c->pool_off += 8u);
	BAD(c->pool_off = 0);
	BAD(c->pool_off = c->bytes);
	BAD(c->pool_off = c->addr_off);
	BAD(c->crush_off += 1u);
	BAD(c->crush_off += 8u);
	BAD(c->crush_off -= 8u);
	BAD(c->crush_off = 0); /* the region becomes a hole */
	BAD(c->crush_off = c->bytes);
	BAD(c->crush_off = c->pool_off);
	BAD(c->n_exists += 1u);
	BAD(c->n_exists -= 1u);
	BAD(c->n_up += 1u);
	BAD(c->n_up -= 1u);
	/* fields with no invariant */
	GOOD(c->epoch = 0);
	GOOD(c->epoch = 0xffffffffu);
	GOOD(memset(c->fsid, 0xEE, sizeof(c->fsid)));
	GOOD(c->flags = 0xffffffffu);

	/* the five tables */
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		BAD(c->tab[k].n += 1u);
		BAD(c->tab[k].n -= 1u);
		BAD(c->tab[k].n = 0);
		BAD(c->tab[k].n = 0xffffffffu);
		BAD(c->tab[k].nv += 1u);
		BAD(c->tab[k].nv -= 1u);
		BAD(c->tab[k].nv = 0);
		BAD(c->tab[k].cap_n += 1u);
		BAD(c->tab[k].cap_n -= 1u);
		BAD(c->tab[k].cap_n = 0xffffffffu);
		BAD(c->tab[k].cap_nv += 1u);
		BAD(c->tab[k].cap_nv -= 1u);
		BAD(c->tab[k].cap_nv = 0xffffffffu);
		BAD(c->tab[k].key_off += 1u);
		BAD(c->tab[k].key_off += 8u);
		BAD(c->tab[k].key_off = 0);
		BAD(c->tab[k].key_off = c->bytes);
		BAD(c->tab[k].off_off += 1u);
		BAD(c->tab[k].off_off += 4u);
		BAD(c->tab[k].off_off = 0); /* an uncarved table has all zeros, this one has counts */
		BAD(c->tab[k].off_off = c->bytes);
		BAD(c->tab[k].val_off += 1u);
		BAD(c->tab[k].val_off += 4u);
		BAD(c->tab[k].val_off = 0);
		BAD(c->tab[k].val_off = c->bytes);
		GOOD(c->tab[k].reserved = 0xdeadbeefu);
		/* contents: keys out of order or equal, offsets not monotonic, the first offset not 0, the last not nv */
		BAD(((uint64_t *)(void *)(copy + c->tab[k].key_off))[1] = ((uint64_t *)(void *)(copy + c->tab[k].key_off))[0]);
		BAD(((uint64_t *)(void *)(copy + c->tab[k].key_off))[0] = ~(uint64_t)0);
		BAD(((uint32_t *)(void *)(copy + c->tab[k].off_off))[0] = 1u);
		BAD(((uint32_t *)(void *)(copy + c->tab[k].off_off))[1] = c->tab[k].nv + 1u);
		BAD(((uint32_t *)(void *)(copy + c->tab[k].off_off))[c->tab[k].n] += 1u);
		BAD(((uint32_t *)(void *)(copy + c->tab[k].off_off))[c->tab[k].n] -= 1u);
		BAD(((uint32_t *)(void *)(copy + c->tab[k].off_off))[1] = 0xffffffffu);
		GOOD(((int32_t *)(void *)(copy + c->tab[k].val_off))[0] = -77); /* values are not judged */
	}
	/* a vector longer than the kept maximum */
	BAD(((uint32_t *)(void *)(copy + c->tab[WRI_TAB_PG_TEMP].off_off))[1] = WRI_MAP_PGVEC_MAX * 2u + 1u;
	    c->tab[WRI_TAB_PG_TEMP].cap_nv = 1000u; c->tab[WRI_TAB_PG_TEMP].nv = 1000u);

	/* per-OSD and per-pool content */
	BAD(copy[c->state_off + 3] = 0x80);
	BAD(copy[c->state_off + 0] = 4);
	BAD(copy[c->state_off + 35] = 0x11);
	GOOD(copy[c->state_off + 0] = 0); /* UP without EXISTS is a state the wire can carry; the derived counts must still agree */
	BAD(((wri_osd_addr *)(void *)(copy + c->addr_off))[0].family = 5);
	BAD(((wri_osd_addr *)(void *)(copy + c->addr_off))[35].family = 255);
	GOOD(((wri_osd_addr *)(void *)(copy + c->addr_off))[1].port = 9999);
	GOOD(((uint32_t *)(void *)(copy + c->weight_off))[7] = 0xffffffffu);
	GOOD(((uint32_t *)(void *)(copy + c->aff_off))[7] = 0xffffffffu);
	BAD(((wri_map_pool *)(void *)(copy + c->pool_off))[0].present = 2);
	BAD(((wri_map_pool *)(void *)(copy + c->pool_off))[2].present = 255);
	GOOD(((wri_map_pool *)(void *)(copy + c->pool_off))[2].pg_num = 0xffffffffu);

	/* CRUSH region */
	cc = (wri_crush *)(void *)(copy + c->crush_off);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->magic = 0);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->magic ^= 0x100u);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bytes += 1u);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bytes += 8u);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bytes -= 4u);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bytes = 0);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bytes = 0xffffffffu);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->bucket_tab = 0xffffu);
	BAD(((wri_crush *)(void *)(copy + c->crush_off))->rule_tab = 0xfffffffcu);
	BAD(((uint32_t *)(void *)(copy + c->crush_off + ((wri_crush *)(void *)(copy + c->crush_off))->bucket_tab))[0] = 0xfffffffcu);
	(void)cc;

	/* the map is only readable as long as the copy is the same size: truncating the copy's header word of the slot size */
	RESET();
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_check(c));
	WRT_CHECK(slot_guard_ok(&cp));
	slot_free(&cp);
	slot_free(&rich);
#undef RESET
#undef BAD
#undef GOOD
}

int main(void)
{
	test_random_builds();
	test_bad_slots();
	test_max_osd();
	test_crush_room();
	test_huge_sizes();
	test_caller_errors();
	test_check();
	return wrt_finish();
}
