/* SPDX-License-Identifier: MIT */
/*
 * test_mapstore_mem.c - the memory plan of the map store (core/src/osdmap/wri_mapstore.c, docs/design/core-architecture.md 15.3).
 *
 *  - wri_mapstore_mem is exactly what wri_mapstore_init takes from the arena and the bulk region, for the three profiles and for
 *    odd configurations (a slot size that is not a multiple of 16, no placement cache), at four base alignments;
 *  - a region one byte short fails with WR_E_BUDGET and is left untouched, whichever region it is;
 *  - a configuration the store cannot use is WR_E_INVAL from both calls, and nothing is taken;
 *  - a disabled store (map_slot_bytes 0) costs nothing and every call on it is inert;
 *  - the slots are 16-byte aligned, disjoint and inside the bulk region, the cache is 8-byte aligned inside the arena;
 *  - the tracked-pool table: the limit from the configuration, the name limits, the same name giving the same handle.
 */
#include "mapstore_rig.h"

typedef struct region {
	uint8_t *raw;
	uint8_t *base;
	size_t cap;
} region;

/* A region of `cap` usable bytes whose base is `off` bytes past a 64-byte boundary, with a guard byte pattern around it. */
static void region_new(region *r, size_t cap, unsigned off)
{
	uintptr_t a;

	r->raw = (uint8_t *)malloc(cap + 256u);
	if (r->raw == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(r->raw, 0xA5, cap + 256u);
	a = ((uintptr_t)r->raw + 63u) & ~(uintptr_t)63u;
	r->base = (uint8_t *)a + off;
	r->cap = cap;
}

/* Everything around the usable bytes still carries the guard pattern: nothing was written outside the region. */
static int region_guard_ok(const region *r)
{
	const uint8_t *p;

	for (p = r->raw; p < r->base; p++)
		if (*p != 0xA5)
			return 0;
	for (p = r->base + r->cap; p < r->raw + r->cap + 256u; p++)
		if (*p != 0xA5)
			return 0;
	return 1;
}

static size_t round16(size_t n) { return (n + 15u) & ~(size_t)15u; }

static void check_plan(const wr_config *cfg, const char *label)
{
	static const unsigned offs[] = {0, 16, 32, 48};
	size_t ab = 0, bb = 0, want_a, want_b;
	unsigned k;

	fprintf(stderr, "plan: %s\n", label);
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_mem(cfg, &ab, &bb));
	want_a = (size_t)cfg->map_pg_cache * sizeof(wri_pgc_entry); /* one section, no tail padding */
	want_b = round16(cfg->map_slot_bytes) + cfg->map_slot_bytes;
	WRT_CHECK_U64(ab, want_a);
	WRT_CHECK_U64(bb, want_b);
	for (k = 0; k < sizeof(offs) / sizeof(offs[0]); k++) {
		region ra, rb;
		wri_arena A, B;
		wri_mapstore *s = (wri_mapstore *)calloc(1, sizeof(*s));
		wr_status st;

		region_new(&ra, ab, offs[k]);
		region_new(&rb, bb, offs[k]);
		wri_arena_init(&A, ra.cap == 0 ? NULL : ra.base, ra.cap);
		wri_arena_init(&B, rb.base, rb.cap);
		st = wri_mapstore_init(s, cfg, &A, &B);
		WRT_CHECK_STATUS(WR_OK, st);
		if (st == WR_OK) {
			/* the plan is the consumption, to the byte, at every base alignment of the host contract */
			WRT_CHECK_U64(A.used, ab);
			WRT_CHECK_U64(B.used, bb);
			WRT_CHECK(s->enabled == 1);
			WRT_CHECK(((uintptr_t)s->slot[0] & 15u) == 0 && ((uintptr_t)s->slot[1] & 15u) == 0);
			WRT_CHECK(s->slot[0] >= rb.base && s->slot[0] + cfg->map_slot_bytes <= s->slot[1]);
			WRT_CHECK(s->slot[1] + cfg->map_slot_bytes <= rb.base + rb.cap);
			if (cfg->map_pg_cache != 0) {
				WRT_CHECK(s->cache.n == cfg->map_pg_cache);
				WRT_CHECK(((uintptr_t)s->cache.e & 7u) == 0);
				WRT_CHECK((uint8_t *)s->cache.e >= ra.base && (uint8_t *)(s->cache.e + s->cache.n) <= ra.base + ra.cap);
			} else {
				WRT_CHECK(s->cache.n == 0 && s->cache.e == NULL); /* no cache: a cache that never hits */
			}
			WRT_CHECK_U64(s->cfg.slot_bytes, cfg->map_slot_bytes);
			WRT_CHECK_U64(s->cfg.max_osd, cfg->map_max_osd);
			WRT_CHECK_U64(s->cfg.work_max, cfg->crush_work_max);
			WRT_CHECK_U64(s->cfg.verify_crc, cfg->map_verify_crc != 0);
			WRT_CHECK(s->have_map == 0 && wri_mapstore_map(s) == NULL);
		}
		WRT_CHECK(region_guard_ok(&ra) && region_guard_ok(&rb)); /* nothing written outside the regions */
		free(ra.raw);
		free(rb.raw);
		free(s);
	}
}

/* One byte short in one region: WR_E_BUDGET, both regions as they were, the store left disabled. */
static void check_short(const wr_config *cfg)
{
	size_t ab = 0, bb = 0;
	unsigned which;

	WRT_CHECK_STATUS(WR_OK, wri_mapstore_mem(cfg, &ab, &bb));
	for (which = 0; which < 2; which++) {
		region ra, rb;
		wri_arena A, B, A0, B0;
		wri_mapstore *s;
		size_t ca = ab - (which == 0 && ab != 0 ? 1u : 0u), cb = bb - (which == 1 ? 1u : 0u);

		if (which == 0 && ab == 0)
			continue; /* no cache, no arena region to be short of */
		s = (wri_mapstore *)calloc(1, sizeof(*s));
		region_new(&ra, ca, 0);
		region_new(&rb, cb, 0);
		wri_arena_init(&A, ra.base, ra.cap);
		wri_arena_init(&B, rb.base, rb.cap);
		A0 = A;
		B0 = B;
		WRT_CHECK_STATUS(WR_E_BUDGET, wri_mapstore_init(s, cfg, &A, &B));
		WRT_CHECK(A.used == A0.used && A.cap == A0.cap && B.used == B0.used && B.cap == B0.cap); /* all or nothing */
		WRT_CHECK(s->enabled == 0 && s->slot[0] == NULL && s->slot[1] == NULL);
		free(ra.raw);
		free(rb.raw);
		free(s);
	}
}

static void profiles(void)
{
	static const wr_map_profile ps[] = {WR_MAPS_IPXE, WR_MAPS_KERNEL, WR_MAPS_HARNESS};
	static const char *const names[] = {"ipxe", "kernel", "harness"};
	unsigned i;

	for (i = 0; i < 3; i++) {
		wr_config cfg;

		wr_config_profile_harness(&cfg);
		wr_config_enable_maps(&cfg, ps[i]);
		check_plan(&cfg, names[i]);
		check_short(&cfg);
	}
}

static void odd_configs(void)
{
	wr_config cfg;

	ms_cfg(&cfg);
	cfg.map_slot_bytes = 16u * 1024u + 1u; /* not a multiple of 16: the second slot starts after padding */
	cfg.map_pg_cache = 1;
	check_plan(&cfg, "slot 16385, one cache entry");
	check_short(&cfg);
	cfg.map_slot_bytes = 16u * 1024u;
	cfg.map_pg_cache = 0;
	check_plan(&cfg, "minimum slot, no cache");
	check_short(&cfg);
	cfg.map_slot_bytes = 7u * 1024u * 1024u + 13u;
	cfg.map_pg_cache = 65535;
	cfg.map_pools = 1;
	cfg.map_max_osd = 262144; /* the hard maximum itself is valid */
	check_plan(&cfg, "large odd slot, biggest cache");
}

static void invalid_configs(void)
{
	wr_config good, c;
	size_t ab = 77, bb = 88;
	uint8_t mem[64];
	wri_arena A, B;
	wri_mapstore *s = (wri_mapstore *)calloc(1, sizeof(*s));
	unsigned i;

	ms_cfg(&good);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_mem(NULL, &ab, &bb));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_mem(&good, NULL, &bb));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_mem(&good, &ab, NULL));
	for (i = 0; i < 8; i++) {
		c = good;
		switch (i) {
		case 0:
			c.map_slot_bytes = 16u * 1024u - 1u;
			break;
		case 1:
			c.map_slot_bytes = 1;
			break;
		case 2:
			c.map_pools = 0;
			break;
		case 3:
			c.map_pools = 9;
			break;
		case 4:
			c.map_max_osd = 0;
			break;
		case 5:
			c.map_max_osd = 262145u;
			break;
		case 6:
			c.crush_work_max = 0; /* no work budget: every mapping would fail */
			break;
		default:
			c.map_pools = 65535;
			break;
		}
		ab = 77;
		bb = 88;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_mem(&c, &ab, &bb));
		WRT_CHECK_U64(ab, 0); /* outputs are cleared on a failure */
		WRT_CHECK_U64(bb, 0);
		wri_arena_init(&A, mem, sizeof(mem));
		wri_arena_init(&B, mem, sizeof(mem));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_init(s, &c, &A, &B));
		WRT_CHECK(A.used == 0 && B.used == 0 && s->enabled == 0);
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_init(NULL, &good, &A, &B));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_init(s, NULL, &A, &B));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_init(s, &good, NULL, &B));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_init(s, &good, &A, NULL));
	free(s);
}

/* A store that is off costs nothing and does nothing. */
static void disabled(void)
{
	wr_config cfg;
	size_t ab = 5, bb = 6;
	wri_mapstore *s = (wri_mapstore *)calloc(1, sizeof(*s));
	wri_arena A, B;
	ms_src src;
	wri_map_io io;
	wri_ctx x;
	uint32_t budget = 1000, h = 7;
	wr_target t;
	wr_map_stats st;
	const wri_map_pool *p = NULL;

	wr_config_profile_harness(&cfg); /* map_slot_bytes 0 */
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_mem(&cfg, &ab, &bb));
	WRT_CHECK_U64(ab, 0);
	WRT_CHECK_U64(bb, 0);
	wri_arena_init(&A, NULL, 0);
	wri_arena_init(&B, NULL, 0);
	memset(s, 0xff, sizeof(*s)); /* init clears it whatever it held */
	WRT_CHECK_STATUS(WR_OK, wri_mapstore_init(s, &cfg, &A, &B));
	WRT_CHECK(s->enabled == 0 && s->have_map == 0 && A.used == 0 && B.used == 0);

	memset(&src, 0, sizeof(src));
	memset(&x, 0, sizeof(x));
	io.ctx = &src;
	io.peek = ms_peek;
	io.release = ms_release;
	io.want_osdmap = ms_want;
	io.event = ms_event;
	ms_post(&src, WR_MAPMSG_OSDMAP, 4, 5, (const uint8_t *)"x", 1);
	WRT_CHECK_U64(wri_mapstore_step(&x, s, &io, &budget), 0);
	WRT_CHECK_U64(src.n_peek, 0); /* it did not even look at the message */
	WRT_CHECK_U64(budget, 1000);
	WRT_CHECK_U64(wri_mapstore_deadline(s), WR_DEADLINE_NONE);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_track(s, (const uint8_t *)"p", 1, &h));
	WRT_CHECK_U64(h, 0);
	WRT_CHECK(wri_mapstore_map(s) == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_pool(s, 0, &p));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_target_pg(s, 0, 0, &t));
	wri_mapstore_stats(s, &st);
	WRT_CHECK(st.epoch == 0 && st.n_full == 0 && st.slot_bytes == 0);
	ms_src_free(&src);
	free(s);
}

/* The tracked-pool table: the limit comes from the configuration, names are bounded, a name is tracked once. */
static void tracking(void)
{
	wr_config cfg;
	ms_fix *f = (ms_fix *)calloc(1, sizeof(*f));
	uint8_t big[WRI_MAP_NAME_MAX + 1u];
	uint32_t h = 55;

	ms_cfg(&cfg);
	cfg.map_pools = 3;
	ms_open(f, &cfg);
	memset(big, 'n', sizeof(big));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_track(&f->s, (const uint8_t *)"", 0, &h));
	WRT_CHECK_U64(h, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_track(&f->s, NULL, 3, &h));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_mapstore_track(&f->s, big, WRI_MAP_NAME_MAX + 1u, &h));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mapstore_track(NULL, big, 3, &h));
	ms_track(f, "alpha", 0);
	ms_track(f, "beta", 1);
	ms_track(f, "alpha", 0); /* the same name: the same handle, no slot used */
	ms_track(f, "alph", 2);  /* a prefix is another name */
	ms_track(f, "beta", 1);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_mapstore_track(&f->s, (const uint8_t *)"gamma", 5, &h));
	WRT_CHECK_U64(h, 0);
	WRT_CHECK_U64(f->s.cfg.n_pools, 3);
	ms_track(f, "alph", 2); /* a known name still answers when the table is full */
	/* the longest name is accepted and kept whole */
	{
		ms_fix *g = (ms_fix *)calloc(1, sizeof(*g));

		ms_cfg(&cfg);
		ms_open(g, &cfg);
		WRT_CHECK_STATUS(WR_OK, wri_mapstore_track(&g->s, big, WRI_MAP_NAME_MAX, &h));
		WRT_CHECK_U64(g->s.cfg.name_len[0], WRI_MAP_NAME_MAX);
		WRT_CHECK(memcmp(g->s.cfg.name[0], big, WRI_MAP_NAME_MAX) == 0);
		ms_close(g);
		free(g);
	}
	/* before a map there is nothing to re-resolve: tracking asks for no full map */
	WRT_CHECK(f->s.want_full == 0);
	ms_close(f);
	free(f);
}

int main(void)
{
	profiles();
	odd_configs();
	invalid_configs();
	disabled();
	tracking();
	return wrt_finish();
}
