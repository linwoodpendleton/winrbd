/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_inc.c - wri_osdmap_apply_inc on generated incrementals (core/src/osdmap/wri_osdmap_inc.c, wri_osdmap_inc2.c;
 * architecture 15.4, osdmap.md 3.4 to 3.6). What the lab's real incrementals (test_osdmap_seq.c) do not contain.
 *
 * Every case is built from a plain description (wrt_mapgen), applied by the core and by the independent model, and compared
 * (inc_rig.h: the compact map against the model, and against a full decode of the model's own encoding of the new state);
 * every apply is also run twice with different pre-fills, with guards, with the held map checked untouched, and a failure checked
 * to leave magic 0 in the new slot.
 *
 *  - no-op and flags; resize (growing with and without an affinity array, shrinking, to zero, unchanged); OSD ids at, above and
 *    below max_osd, valid only because of the growth in the same incremental;
 *  - weights (a non-zero weight creates the OSD), affinity (the array is created on first use), state (XOR on the kept bits, mask
 *    0 toggles UP, destroy, destroy and re-add in one epoch, weight plus EXISTS in one epoch), new up OSDs (every address vector
 *    shape: first msgr2 entry, v1 only, IPv6, empty, blank, legacy form refused);
 *  - the five pg tables: every merge case (same key set, removals, empty vector, -1, a new key before / inside / after the held
 *    keys, an empty held table, everything removed, a key in both lists, untracked pools filtered, vectors above the kept length);
 *  - pools: old_pools, a pool in both lists, a replaced record, a tracked pool appearing, renamed away, swapped names, the same
 *    name tracked twice, a name on two ids, WR_E_MAP_RESYNC for a record the held map cannot have, unsupported pools, a record the
 *    decoder refuses, status recomputed when the CRUSH map changes, the CRUSH region copied when it does not;
 *  - identity: wrong fsid, an epoch gap, a repeat, an older epoch, an embedded full map (consecutive and not, wrong fsid, wrong
 *    epoch, bad CRC, damaged, too big);
 *  - envelope and structure: CRC good and bad with the check on and off, wrapper v7 (no CRC), client block v8, versions and compat
 *    refused, raised struct_v with a tail, an OSD-only block with a huge length, trailing bytes, unsorted and repeated keys of every
 *    sorted list, every truncation, every single-byte mutation;
 *  - arguments (NULL, misaligned, overlapping slots, another tracked set, too many tracked pools, a slot smaller than the header)
 *    and a budget sweep: a slot one byte short of the map, and a slot cut at every section boundary, fails with WR_E_MAP_BUDGET.
 */
#include "inc_rig.h"

static const char *const NAMES[] = {"pool1", "pool2"};
#define NNAMES 2u

/* ---- descriptions ------------------------------------------------------------------------------------------------ */

static void add_pg_list(wrt_mg_vec *v, uint64_t pool, uint32_t seed, const int32_t *osds, uint32_t n)
{
	wrt_mg_pg_list e;
	uint32_t i;

	memset(&e, 0, sizeof(e));
	e.pg.pool = pool;
	e.pg.seed = seed;
	for (i = 0; i < n; i++)
		WRT_MG_PUSH(e.osds, int32_t, osds[i]);
	WRT_MG_PUSH(*v, wrt_mg_pg_list, e);
}

static void add_pg_items(wrt_mg_vec *v, uint64_t pool, uint32_t seed, const int32_t *flat, uint32_t npairs)
{
	wrt_mg_pg_items e;
	uint32_t i;

	memset(&e, 0, sizeof(e));
	e.pg.pool = pool;
	e.pg.seed = seed;
	for (i = 0; i < npairs; i++) {
		wrt_mg_pair p;

		p.from = flat[2u * i];
		p.to = flat[2u * i + 1u];
		WRT_MG_PUSH(e.items, wrt_mg_pair, p);
	}
	WRT_MG_PUSH(*v, wrt_mg_pg_items, e);
}

static void add_pg_osd(wrt_mg_vec *v, uint64_t pool, uint32_t seed, int32_t osd)
{
	wrt_mg_pg_osd e;

	e.pg.pool = pool;
	e.pg.seed = seed;
	e.osd = osd;
	WRT_MG_PUSH(*v, wrt_mg_pg_osd, e);
}

static void add_pg(wrt_mg_vec *v, uint64_t pool, uint32_t seed)
{
	wrt_mg_pg p;

	p.pool = pool;
	p.seed = seed;
	WRT_MG_PUSH(*v, wrt_mg_pg, p);
}

/* A cluster of `n_osds` OSDs, three pools of 16 PGs (pool1 and pool2 are tracked, pool3 is not), tables on all three pools. */
static void mk_desc_t(wrt_mg_map *m, uint32_t n_osds, int with_aff, uint64_t seed, int tables)
{
	wrt_mg_cluster_spec s;
	wrt_mg_pg pg;
	const int32_t l2[2] = {1, 2}, l3[3] = {2, 1, 0}, it[4] = {0, 1, 1, 2};
	uint32_t i;

	wrt_mg_cluster_spec_init(&s, n_osds);
	s.n_pools = 3;
	s.pg_num = 16;
	s.n_upmap_items = tables ? 3u : 0u;
	s.n_upmap = tables ? 3u : 0u;
	s.n_pg_temp = tables ? 4u : 0u;
	s.n_primary_temp = tables ? 3u : 0u;
	s.n_upmap_primaries = tables ? 3u : 0u;
	s.n_affinity = with_aff ? 3u : 0u;
	s.up_pct = 70;
	s.never_up_pct = 15;
	s.out_pct = 10;
	s.epoch = 10;
	s.seed = seed;
	WRT_CHECK(wrt_mg_build_map(m, &s) == 0);
	for (i = 0; i < n_osds && i < 8; i++) { /* known states for the first eight OSDs: up, down, never up, out */
		static const uint32_t st[8] = {3, 1, 9, 3, 3, 3, 1, 3};
		wrt_mg_addrvec *av = &WRT_MG_E(m->client_addrs, wrt_mg_addrvec, i);

		WRT_MG_E(m->osd_state, uint32_t, i) = st[i];
		WRT_MG_E(m->osd_weight, uint32_t, i) = i == 6 ? 0u : WRT_MG_W_IN;
		if (st[i] == 9u)
			wrt_mg_av_empty(av);
		else
			wrt_mg_av_v2v1(av, 0x0a4d0100u + i, (uint16_t)(6800 + 16 * i), 1000u + i);
	}
	if (with_aff && n_osds >= 8)
		for (i = 0; i < n_osds; i++)
			WRT_MG_E(m->osd_primary_affinity, uint32_t, i) = 0x10000u - 0x1000u * (i % 8u);
	for (i = 0; tables && i < 2; i++) { /* pool 2 (tracked) and pool 3 (not) */
		uint64_t pool = 2u + i;

		pg.pool = pool;
		pg.seed = 3;
		wrt_mg_map_set_pg_temp(m, pg, l2, 2);
		pg.seed = 9;
		wrt_mg_map_set_pg_upmap(m, pg, l3, 3);
		pg.seed = 5;
		wrt_mg_map_set_pg_upmap_items(m, pg, (const wrt_mg_pair *)(const void *)it, 2);
		pg.seed = 7;
		wrt_mg_map_set_primary_temp(m, pg, 1);
		pg.seed = 11;
		wrt_mg_map_set_upmap_primary(m, pg, 2);
	}
}

static void mk_desc(wrt_mg_map *m, uint32_t n_osds, int with_aff, uint64_t seed) { mk_desc_t(m, n_osds, with_aff, seed, 1); }

/* ---- running ------------------------------------------------------------------------------------------------------- */

static void start(rig *g, uint32_t n_osds, int with_aff, uint64_t seed)
{
	wrt_mg_map m;

	mk_desc(&m, n_osds, with_aff, seed);
	WRT_CHECK(rig_start(g, &m, 4096, 1, NAMES, NNAMES));
	wrt_mg_map_free(&m);
}

/* Apply `inc` to the core and the model, both must accept it. */
static void ok(rig *g, wrt_mg_inc *inc)
{
	wr_errinfo why = { 0 };
	wr_status st = rig_step(g, inc, NULL, &why);

	if (st != WR_OK)
		fprintf(stderr, "  incremental refused: %s (a0 %llu a1 %llu)\n", why.what != NULL ? why.what : "?", (unsigned long long)why.a0,
			(unsigned long long)why.a1);
	WRT_CHECK_STATUS(WR_OK, st);
	wrt_mg_inc_free(inc);
}

static void ok_want(rig *g, wrt_mg_inc *inc, const int32_t *want)
{
	WRT_CHECK_STATUS(WR_OK, rig_step(g, inc, want, NULL));
	wrt_mg_inc_free(inc);
}

/* The core refuses `inc` with `want`; the held map stays. */
static void refuse(rig *g, const wrt_mg_inc *inc, wr_status want)
{
	wrt_mg_buf b;
	islot dst;
	wr_errinfo why = { 0 };

	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(inc, &b) == 0);
	islot_new(&dst, RIG_SLOT_BYTES);
	WRT_CHECK_STATUS(want, rig_apply(&g->cfg, rig_held(g), b.p, b.len, &dst, &why));
	islot_free(&dst);
	wrt_mg_buf_free(&b);
}

static void refuse_free(rig *g, wrt_mg_inc *inc, wr_status want)
{
	refuse(g, inc, want);
	wrt_mg_inc_free(inc);
}

/* The core refuses and the model refuses too (for the cases the model knows about: fsid, epoch, OSD ids). */
static void refuse_both(rig *g, wrt_mg_inc *inc, wr_status want, int want_model_rc)
{
	wrt_mg_buf b;
	int rc = 0;
	wr_status st;

	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(inc, &b) == 0);
	st = rig_step_blob(g, b.p, b.len, inc, NULL, &rc, NULL);
	WRT_CHECK_STATUS(want, st);
	WRT_CHECK_STATUS(want_model_rc, rc);
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(inc);
}

static void new_inc(const rig *g, wrt_mg_inc *inc) { wrt_mg_inc_init(inc, g->model.fsid, g->model.epoch + 1u); }

static void av_v4(wrt_mg_addrvec *av, uint32_t host, uint16_t port, uint32_t nonce) { wrt_mg_av_v2v1(av, 0x0a4d0000u | host, port, nonce); }

/* ---- basics ---------------------------------------------------------------------------------------------------- */

static void test_basics(void)
{
	rig g;
	wrt_mg_inc inc;
	const wri_osdmap *a;
	uint8_t before[64];

	start(&g, 8, 0, 1);
	/* nothing changes but the epoch */
	new_inc(&g, &inc);
	a = rig_held(&g);
	memcpy(before, a->fsid, 16);
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->epoch, 11);
	WRT_CHECK(memcmp(rig_held(&g)->fsid, before, 16) == 0);
	/* flags: set, kept (-1), set to 0 */
	new_inc(&g, &inc);
	inc.new_flags = 0x4001;
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->flags, 0x4001);
	new_inc(&g, &inc);
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->flags, 0x4001);
	new_inc(&g, &inc);
	inc.new_flags = 0;
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->flags, 0);
	/* the pool ceiling and the other rows the client skips change nothing it keeps */
	new_inc(&g, &inc);
	inc.new_pool_max = 9;
	inc.modified.sec = 5;
	ok(&g, &inc);
	rig_end(&g);
}

/* ---- resize --------------------------------------------------------------------------------------------------- */

static void test_resize(void)
{
	int with_aff;

	for (with_aff = 0; with_aff <= 1; with_aff++) {
		rig g;
		wrt_mg_inc inc;
		uint32_t i;

		start(&g, 8, with_aff, 2);
		/* grow: the new OSDs are state 0, weight 0, no address, the default affinity */
		new_inc(&g, &inc);
		inc.new_max_osd = 12;
		ok(&g, &inc);
		WRT_CHECK_U64(rig_held(&g)->max_osd, 12);
		for (i = 8; i < 12; i++) {
			WRT_CHECK_U64(wri_map_state(rig_held(&g))[i], 0);
			WRT_CHECK_U64(wri_map_weight(rig_held(&g))[i], 0);
			WRT_CHECK_U64(wri_osd_aff(rig_held(&g), (int32_t)i), WRI_OSD_IN_FULL);
			WRT_CHECK_U64(wri_map_addr(rig_held(&g))[i].family, 0);
		}
		/* the OSDs that did not exist are used in the same epoch they appear in (the ids are valid after the resize) */
		new_inc(&g, &inc);
		inc.new_max_osd = 14;
		wrt_mg_inc_set_weight(&inc, 12, 0x10000);
		wrt_mg_inc_set_affinity(&inc, 13, 0x8000);
		{
			wrt_mg_addrvec av;

			av_v4(&av, 99, 6900, 7);
			wrt_mg_inc_mark_up(&inc, 13, &av);
		}
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[12], WRI_OSD_EXISTS);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[13], WRI_OSD_EXISTS | WRI_OSD_UP);
		/* the same size: nothing changes */
		new_inc(&g, &inc);
		inc.new_max_osd = 14;
		ok(&g, &inc);
		/* shrink: the tail is dropped, tables that name dropped OSDs keep their numbers */
		new_inc(&g, &inc);
		inc.new_max_osd = 5;
		ok(&g, &inc);
		WRT_CHECK_U64(rig_held(&g)->max_osd, 5);
		/* shrink and grow again in two epochs: the dropped slots come back empty */
		new_inc(&g, &inc);
		inc.new_max_osd = 8;
		ok(&g, &inc);
		for (i = 5; i < 8; i++)
			WRT_CHECK_U64(wri_map_state(rig_held(&g))[i], 0);
		/* to zero, and out of zero */
		new_inc(&g, &inc);
		inc.new_max_osd = 0;
		ok(&g, &inc);
		WRT_CHECK_U64(rig_held(&g)->max_osd, 0);
		WRT_CHECK_U64(rig_held(&g)->n_exists, 0);
		new_inc(&g, &inc);
		inc.new_max_osd = 3;
		wrt_mg_inc_set_weight(&inc, 2, 0x10000);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[2], WRI_OSD_EXISTS);
		rig_end(&g);
	}
}

static void test_osd_ids(void)
{
	rig g;
	wrt_mg_inc inc;
	unsigned row;
	static const int32_t bad[] = {8, 9, -1, 0x7fffffff, -2147483647 - 1};
	unsigned b;

	start(&g, 8, 0, 3);
	for (b = 0; b < sizeof(bad) / sizeof(bad[0]); b++) {
		for (row = 0; row < 5; row++) {
			new_inc(&g, &inc);
			switch (row) {
			case 0:
				wrt_mg_inc_set_weight(&inc, bad[b], 1);
				break;
			case 1:
				wrt_mg_inc_set_affinity(&inc, bad[b], 1);
				break;
			case 2: {
				wrt_mg_osd_u32 e;

				e.osd = bad[b];
				e.val = 2;
				WRT_MG_PUSH(inc.new_state, wrt_mg_osd_u32, e);
				break;
			}
			case 3: {
				wrt_mg_addrvec av;

				av_v4(&av, 1, 6800, 1);
				wrt_mg_inc_mark_up(&inc, bad[b], &av);
				break;
			}
			default: /* one good entry and one bad one */
				wrt_mg_inc_set_weight(&inc, 1, 1);
				wrt_mg_inc_set_weight(&inc, bad[b], 1);
				break;
			}
			if (bad[b] >= 0 && bad[b] < 8)
				continue;
			refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
		}
	}
	/* max_osd is the new one: 8 is fine after growing to 9, but 9 is not */
	new_inc(&g, &inc);
	inc.new_max_osd = 9;
	wrt_mg_inc_set_weight(&inc, 8, 0x10000);
	ok(&g, &inc);
	new_inc(&g, &inc);
	inc.new_max_osd = 9;
	wrt_mg_inc_set_weight(&inc, 9, 0x10000);
	refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
	/* ... and shrinking makes an id that was valid a moment ago invalid */
	new_inc(&g, &inc);
	inc.new_max_osd = 4;
	wrt_mg_inc_set_weight(&inc, 6, 0x10000);
	refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
	rig_end(&g);
}

/* ---- weights, affinity, state, up ----------------------------------------------------------------------------- */


static void test_weights_affinity(void)
{
	int with_aff;

	for (with_aff = 0; with_aff <= 1; with_aff++) {
		rig g;
		wrt_mg_inc inc;

		start(&g, 10, with_aff, 4);
		/* a non-zero weight sets EXISTS on an OSD that did not have it (OSD 8 and 9 are beyond the generated ones' states) */
		new_inc(&g, &inc);
		inc.new_max_osd = 12;
		ok(&g, &inc);
		new_inc(&g, &inc);
		wrt_mg_inc_set_weight(&inc, 10, 0x10000);
		wrt_mg_inc_set_weight(&inc, 11, 0); /* weight 0: no EXISTS */
		wrt_mg_inc_set_weight(&inc, 2, 0x8000); /* never up: weight only */
		wrt_mg_inc_set_weight(&inc, 6, 0x10000); /* out -> in */
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[10], WRI_OSD_EXISTS);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[11], 0);
		WRT_CHECK_U64(wri_map_weight(rig_held(&g))[6], 0x10000);
		/* affinity: the array exists afterwards, whatever it was before; the others stay at the default or what they were */
		new_inc(&g, &inc);
		wrt_mg_inc_set_affinity(&inc, 0, 0);
		wrt_mg_inc_set_affinity(&inc, 4, 0x4000);
		wrt_mg_inc_set_affinity(&inc, 11, 0xffff);
		wrt_mg_inc_set_affinity(&inc, 3, 0x12345678u); /* any u32 is stored as it is */
		wrt_mg_inc_set_weight(&inc, 7, 0xdeadbeefu);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 3), 0x12345678u);
		WRT_CHECK_U64(wri_map_weight(rig_held(&g))[7], 0xdeadbeefu);
		WRT_CHECK(wri_map_aff(rig_held(&g)) != NULL);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 0), 0);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 4), 0x4000);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 11), 0xffff);
		/* the array survives a resize in both directions */
		new_inc(&g, &inc);
		inc.new_max_osd = 14;
		ok(&g, &inc);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 13), WRI_OSD_IN_FULL);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 4), 0x4000);
		new_inc(&g, &inc);
		inc.new_max_osd = 6;
		ok(&g, &inc);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 4), 0x4000);
		rig_end(&g);
	}
}

static void put_state(wrt_mg_inc *inc, int32_t osd, uint32_t mask)
{
	wrt_mg_osd_u32 e;

	e.osd = osd;
	e.val = mask;
	WRT_MG_PUSH(inc->new_state, wrt_mg_osd_u32, e);
}

/* A fresh base with 8 OSDs (states 3, 1, 9, 3, 3, 3, 1, 3 and addresses on all but OSD 2) grown to 10: OSDs 8 and 9 do not exist. */
static void start_grown(rig *g, int with_aff)
{
	wrt_mg_inc inc;

	start(g, 8, with_aff, 5);
	new_inc(g, &inc);
	inc.new_max_osd = 10;
	ok(g, &inc);
}

static void test_state(void)
{
	rig g;
	wrt_mg_inc inc;
	int with_aff;

	for (with_aff = 0; with_aff <= 1; with_aff++) {
		/* mask 0 toggles UP, mask 2 does too; two toggles in one epoch cancel */
		start_grown(&g, with_aff);
		new_inc(&g, &inc);
		put_state(&inc, 0, 0);
		put_state(&inc, 1, 2);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[0], WRI_OSD_EXISTS);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[1], WRI_OSD_EXISTS | WRI_OSD_UP);
		WRT_CHECK_U64(wri_map_addr(rig_held(&g))[0].family, WR_AF_IPV4); /* a down OSD keeps its last address */
		new_inc(&g, &inc);
		put_state(&inc, 0, 0);
		put_state(&inc, 0, 2);
		put_state(&inc, 3, 0);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[0], WRI_OSD_EXISTS);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[3], WRI_OSD_EXISTS);
		/* bits the client does not keep (NEW, AUTOOUT, STOP, high bits) change nothing it keeps; with UP they toggle UP */
		new_inc(&g, &inc);
		put_state(&inc, 4, 0x8);
		put_state(&inc, 5, 0x4);
		put_state(&inc, 7, 0x1000);
		put_state(&inc, 3, 0x80000000u);
		put_state(&inc, 0, 0xA | 0x1000);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[4], WRI_OSD_EXISTS | WRI_OSD_UP);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[0], WRI_OSD_EXISTS | WRI_OSD_UP);
		/* EXISTS on an OSD that does not exist makes it exist (XOR) */
		new_inc(&g, &inc);
		put_state(&inc, 8, 1);
		put_state(&inc, 9, 3);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[8], WRI_OSD_EXISTS);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[9], WRI_OSD_EXISTS | WRI_OSD_UP);
		rig_end(&g);

		/* EXISTS on an existing OSD destroys it: state 0, address gone, the affinity back to the default */
		start_grown(&g, with_aff);
		new_inc(&g, &inc);
		wrt_mg_inc_set_affinity(&inc, 3, 0x2000);
		wrt_mg_inc_set_affinity(&inc, 4, 0x3000);
		ok(&g, &inc);
		new_inc(&g, &inc);
		put_state(&inc, 3, 1);
		put_state(&inc, 4, 3);
		put_state(&inc, 1, 0x1001);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[3], 0);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[4], 0);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[1], 0);
		WRT_CHECK_U64(wri_map_addr(rig_held(&g))[3].family, 0);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 3), WRI_OSD_IN_FULL);
		WRT_CHECK_U64(wri_osd_aff(rig_held(&g), 4), WRI_OSD_IN_FULL);
		WRT_CHECK_U64(wri_map_weight(rig_held(&g))[3], WRT_MG_W_IN); /* the weight stays */
		/* destroyed twice in one epoch: the second finds it gone and XORs EXISTS back on */
		new_inc(&g, &inc);
		put_state(&inc, 5, 1);
		put_state(&inc, 5, 1);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[5], WRI_OSD_EXISTS);
		rig_end(&g);

		/* destroy and re-add in one epoch: the state step runs before the up step */
		start_grown(&g, with_aff);
		new_inc(&g, &inc);
		put_state(&inc, 3, 1);
		{
			wrt_mg_addrvec av;

			av_v4(&av, 77, 7000, 77);
			wrt_mg_inc_mark_up(&inc, 3, &av);
		}
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[3], WRI_OSD_EXISTS | WRI_OSD_UP);
		WRT_CHECK_U64(wri_map_addr(rig_held(&g))[3].port, 7000);
		WRT_CHECK_U64(wri_map_addr(rig_held(&g))[3].nonce, 77);
		rig_end(&g);

		/* a weight and EXISTS in one epoch: the weight (applied first) creates the OSD, then the mask destroys it */
		start_grown(&g, with_aff);
		new_inc(&g, &inc);
		wrt_mg_inc_set_weight(&inc, 8, 0x10000);
		put_state(&inc, 8, 1);
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[8], 0);
		WRT_CHECK_U64(wri_map_weight(rig_held(&g))[8], 0x10000);
		new_inc(&g, &inc);
		wrt_mg_inc_set_weight(&inc, 9, 0x10000);
		put_state(&inc, 9, 2); /* UP only: weight made it exist, the mask makes it up */
		ok(&g, &inc);
		WRT_CHECK_U64(wri_map_state(rig_held(&g))[9], WRI_OSD_EXISTS | WRI_OSD_UP);
		rig_end(&g);
	}
}

static void test_up_addresses(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_addrvec av;
	uint8_t ip6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34};

	start_grown(&g, 0);
	new_inc(&g, &inc);
	av_v4(&av, 21, 6801, 21);
	wrt_mg_inc_mark_up(&inc, 8, &av); /* v2 then v1: the v2 one is kept */
	wrt_mg_av_v1(&av, 0x0a4d0016u, 6802, 22);
	wrt_mg_inc_mark_up(&inc, 9, &av); /* v1 only: no usable address, the OSD is up but cannot be contacted */
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[8].port, 6801);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[9].family, 0);
	WRT_CHECK_U64(wri_map_state(rig_held(&g))[9], WRI_OSD_EXISTS | WRI_OSD_UP);

	new_inc(&g, &inc);
	wrt_mg_av_v6(&av, ip6, 6803, 23);
	wrt_mg_inc_mark_up(&inc, 8, &av); /* an OSD that is up gets a new address */
	wrt_mg_av_empty(&av);
	wrt_mg_inc_mark_up(&inc, 9, &av);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[8].family, WR_AF_IPV6);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[9].family, 0);

	new_inc(&g, &inc);
	wrt_mg_av_blank(&av);
	wrt_mg_inc_mark_up(&inc, 8, &av);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[8].family, 0);

	/* an entry of a family the client does not speak is passed over, the next one is used */
	new_inc(&g, &inc);
	av_v4(&av, 31, 6810, 31);
	av.a[0].family = 5;
	wrt_mg_inc_mark_up(&inc, 8, &av);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[8].family, 0); /* the v2 entry was the one with the odd family, the v1 one is not msgr2 */

	/* the old single-address form (marker 0) is a form this client does not read: refused with a clear status */
	new_inc(&g, &inc);
	wrt_mg_av_legacy(&av, 0x0a4d0020u, 6811, 32);
	wrt_mg_inc_mark_up(&inc, 8, &av);
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	/* marker 1: one entity_addr_t without a count, a form the notes allow */
	new_inc(&g, &inc);
	av_v4(&av, 41, 6812, 41);
	av.marker = 1;
	av.n = 1;
	wrt_mg_inc_mark_up(&inc, 8, &av);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_addr(rig_held(&g))[8].port, 6812);
	rig_end(&g);
}

/* ---- the pg tables ------------------------------------------------------------------------------------------------ */

/* A base with chosen entries in the five tables (pools 1 and 2 are tracked, pool 3 is not). */
static void start_tables(rig *g)
{
	wrt_mg_map m;
	wrt_mg_pg pg;
	const int32_t t1[] = {0, 1}, t2[] = {1}, t3[] = {2, 3}, t4[] = {3}, t5[] = {0, 2}, t6[] = {4};
	const int32_t u1[] = {0, 1}, u2[] = {2, 3}, u3[] = {1};
	const int32_t i1[] = {0, 1}, i2[] = {1, 2, 3, 4}, i3[] = {0, 5};

	mk_desc_t(&m, 8, 0, 6, 0);
	pg.pool = 1;
	pg.seed = 2;
	wrt_mg_map_set_pg_temp(&m, pg, t1, 2);
	pg.seed = 4;
	wrt_mg_map_set_pg_temp(&m, pg, t2, 1);
	pg.seed = 6;
	wrt_mg_map_set_pg_temp(&m, pg, t3, 2);
	pg.seed = 8;
	wrt_mg_map_set_pg_temp(&m, pg, t4, 1);
	pg.pool = 2;
	pg.seed = 3;
	wrt_mg_map_set_pg_temp(&m, pg, t5, 2);
	pg.pool = 3;
	pg.seed = 1;
	wrt_mg_map_set_pg_temp(&m, pg, t6, 1);

	pg.pool = 1;
	pg.seed = 1;
	wrt_mg_map_set_primary_temp(&m, pg, 2);
	pg.seed = 3;
	wrt_mg_map_set_primary_temp(&m, pg, 1);
	pg.pool = 2;
	pg.seed = 2;
	wrt_mg_map_set_primary_temp(&m, pg, 0);

	pg.pool = 1;
	pg.seed = 1;
	wrt_mg_map_set_pg_upmap(&m, pg, u1, 2);
	pg.seed = 5;
	wrt_mg_map_set_pg_upmap(&m, pg, u2, 2);
	pg.pool = 2;
	pg.seed = 2;
	wrt_mg_map_set_pg_upmap(&m, pg, u3, 1);

	pg.pool = 1;
	pg.seed = 2;
	wrt_mg_map_set_pg_upmap_items(&m, pg, (const wrt_mg_pair *)(const void *)i1, 1);
	pg.seed = 3;
	wrt_mg_map_set_pg_upmap_items(&m, pg, (const wrt_mg_pair *)(const void *)i2, 2);
	pg.pool = 2;
	pg.seed = 2;
	wrt_mg_map_set_pg_upmap_items(&m, pg, (const wrt_mg_pair *)(const void *)i3, 1);

	pg.pool = 1;
	pg.seed = 1;
	wrt_mg_map_set_upmap_primary(&m, pg, 1);
	pg.pool = 2;
	pg.seed = 1;
	wrt_mg_map_set_upmap_primary(&m, pg, 2);
	WRT_CHECK(rig_start(g, &m, 4096, 1, NAMES, NNAMES));
	wrt_mg_map_free(&m);
}

static void test_tables_merge(void)
{
	rig g;
	wrt_mg_inc inc;
	const wri_osdmap *m;
	const int32_t a[] = {5, 6}, b[] = {7, 7}, c1[] = {1}, c0[] = {0}, d[] = {1, 2, 3};
	const int32_t flat[] = {5, 6};
	const int32_t flat2[] = {9, 8, 7, 6};

	start_tables(&g);
	m = rig_held(&g);
	WRT_CHECK_U64(m->tab[WRI_TAB_PG_TEMP].n, 5); /* the entry of pool 3 is not kept */
	WRT_CHECK_U64(m->tab[WRI_TAB_PRIMARY_TEMP].n, 3);

	new_inc(&g, &inc);
	/* pg_temp: a key before the first, a replaced one, the removal of a key that is not there, a removal, a key inside, one after the
	 * last, pool 2's only entry removed and one added, pool 3 (untracked) and a pool that does not exist */
	add_pg_list(&inc.new_pg_temp, 1, 1, a, 2);
	add_pg_list(&inc.new_pg_temp, 1, 4, b, 2);
	add_pg_list(&inc.new_pg_temp, 1, 5, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 6, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 7, c1, 1);
	add_pg_list(&inc.new_pg_temp, 1, 20, c0, 1);
	add_pg_list(&inc.new_pg_temp, 2, 3, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 2, 4, d, 3);
	add_pg_list(&inc.new_pg_temp, 3, 1, c0, 1);
	add_pg_list(&inc.new_pg_temp, 3, 2, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 9, 0, c1, 1);
	add_pg_list(&inc.new_pg_temp, 0x80000001u, 0, c1, 1);
	/* primary_temp: -1 removes, a replaced value, a new one */
	add_pg_osd(&inc.new_primary_temp, 1, 1, -1);
	add_pg_osd(&inc.new_primary_temp, 1, 2, 3);
	add_pg_osd(&inc.new_primary_temp, 1, 3, 0);
	add_pg_osd(&inc.new_primary_temp, 2, 2, -1);
	add_pg_osd(&inc.new_primary_temp, 3, 3, 1);
	/* pg_upmap: upserts, and a key in both lists (removal wins), a removal of an absent key */
	add_pg_list(&inc.new_pg_upmap, 1, 0, c0, 1);
	add_pg_list(&inc.new_pg_upmap, 1, 5, c0, 1);
	add_pg(&inc.old_pg_upmap, 1, 1);
	add_pg(&inc.old_pg_upmap, 1, 5);
	add_pg(&inc.old_pg_upmap, 1, 9);
	/* pg_upmap_items: a new key, an entry with no pairs, removals */
	add_pg_items(&inc.new_pg_upmap_items, 1, 1, flat, 1);
	add_pg_items(&inc.new_pg_upmap_items, 1, 3, NULL, 0);
	add_pg_items(&inc.new_pg_upmap_items, 2, 7, flat2, 2);
	add_pg(&inc.old_pg_upmap_items, 1, 2);
	add_pg(&inc.old_pg_upmap_items, 2, 2);
	/* pg_upmap_primary */
	add_pg_osd(&inc.new_pg_upmap_primary, 1, 0, 0);
	add_pg_osd(&inc.new_pg_upmap_primary, 1, 1, 2);
	add_pg(&inc.old_pg_upmap_primary, 1, 5);
	add_pg(&inc.old_pg_upmap_primary, 2, 1);
	ok(&g, &inc);

	/* the same keys again, only removals: the tables shrink, a table can end up empty */
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_temp, 1, 1, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 2, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 4, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 7, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 8, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 1, 20, NULL, 0);
	add_pg_list(&inc.new_pg_temp, 2, 4, NULL, 0);
	add_pg_osd(&inc.new_primary_temp, 1, 2, -1);
	add_pg_osd(&inc.new_primary_temp, 1, 3, -1);
	add_pg(&inc.old_pg_upmap, 1, 0);
	add_pg(&inc.old_pg_upmap, 2, 2);
	add_pg(&inc.old_pg_upmap_items, 1, 1);
	add_pg(&inc.old_pg_upmap_items, 1, 3);
	add_pg(&inc.old_pg_upmap_items, 2, 7);
	add_pg(&inc.old_pg_upmap_primary, 1, 0);
	add_pg(&inc.old_pg_upmap_primary, 1, 1);
	ok(&g, &inc);
	m = rig_held(&g);
	{
		unsigned k;

		for (k = 0; k < WRI_TAB_COUNT; k++)
			WRT_CHECK_U64(m->tab[k].n, 0);
	}

	/* an empty held table gets upserts; an incremental with empty lists keeps the tables */
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_temp, 2, 5, d, 3);
	add_pg_osd(&inc.new_primary_temp, 1, 9, 2);
	add_pg_list(&inc.new_pg_upmap, 1, 3, a, 2);
	add_pg_items(&inc.new_pg_upmap_items, 1, 3, flat2, 2);
	add_pg_osd(&inc.new_pg_upmap_primary, 2, 0, 1);
	ok(&g, &inc);
	new_inc(&g, &inc);
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->tab[WRI_TAB_PG_TEMP].n, 1);
	rig_end(&g);
}

/* Vectors above the kept length (WRI_MAP_PGVEC_MAX = 32) are a budget failure for a tracked pool and nothing for another. */
static void test_tables_long(void)
{
	rig g;
	wrt_mg_inc inc;
	int32_t v[80]; /* an items entry of n pairs reads 2n values */
	unsigned i;

	for (i = 0; i < 80; i++)
		v[i] = (int32_t)(i % 8);
	start_tables(&g);
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_temp, 1, 1, v, 32);
	add_pg_list(&inc.new_pg_upmap, 1, 3, v, 32);
	add_pg_items(&inc.new_pg_upmap_items, 1, 4, v, 32);
	ok(&g, &inc); /* exactly the kept length */
	WRT_CHECK_U64(rig_held(&g)->tab[WRI_TAB_PG_UPMAP_ITEMS].nv, 2 + 4 + 2 + 64); /* the three held entries and the 32 pairs */
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_temp, 3, 1, v, 33); /* pool 3 is not tracked */
	add_pg_list(&inc.new_pg_temp, 9, 1, v, 40);
	add_pg_list(&inc.new_pg_upmap, 3, 1, v, 40);
	add_pg_items(&inc.new_pg_upmap_items, 3, 1, v, 20);
	ok(&g, &inc);
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_temp, 2, 1, v, 33);
	refuse_free(&g, &inc, WR_E_MAP_BUDGET);
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_upmap, 1, 8, v, 33);
	refuse_free(&g, &inc, WR_E_MAP_BUDGET);
	new_inc(&g, &inc);
	add_pg_items(&inc.new_pg_upmap_items, 2, 8, v, 33);
	refuse_free(&g, &inc, WR_E_MAP_BUDGET);
	rig_end(&g);
}

/* ---- pools ---------------------------------------------------------------------------------------------------- */

static void put_pool(wrt_mg_inc *inc, int64_t id, const char *name, uint32_t pg_num, int shape)
{
	wrt_mg_pool_ent pe;
	wrt_mg_pname pn;

	pe.id = id;
	wrt_mg_pool_init(&pe.p, 32);
	pe.p.size = 3;
	pe.p.pg_num = pe.p.pgp_num = pe.p.pg_num_target = pe.p.pgp_num_target = pe.p.pg_num_pending = pg_num;
	if (shape != 0)
		wrt_mg_pool_shape(&pe.p, shape);
	WRT_MG_PUSH(inc->new_pools, wrt_mg_pool_ent, pe);
	if (name != NULL) {
		memset(&pn, 0, sizeof(pn));
		pn.id = id;
		snprintf(pn.name, sizeof(pn.name), "%s", name);
		WRT_MG_PUSH(inc->new_pool_names, wrt_mg_pname, pn);
	}
}

static void put_name(wrt_mg_inc *inc, int64_t id, const char *name)
{
	wrt_mg_pname pn;

	memset(&pn, 0, sizeof(pn));
	pn.id = id;
	snprintf(pn.name, sizeof(pn.name), "%s", name);
	WRT_MG_PUSH(inc->new_pool_names, wrt_mg_pname, pn);
}

static void put_old(wrt_mg_inc *inc, int64_t id) { WRT_MG_PUSH(inc->old_pools, int64_t, id); }

/* A base like start(), tracking `names` instead (all of "pool1" .. "pool3" exist). */
static void start_names(rig *g, const char *const *names, unsigned nn, uint32_t n_osds)
{
	wrt_mg_map m;

	mk_desc(&m, n_osds, 0, 7);
	WRT_CHECK(rig_start(g, &m, 4096, 1, names, nn));
	wrt_mg_map_free(&m);
}

static void test_pools_basic(void)
{
	rig g;
	wrt_mg_inc inc;
	const wri_map_pool *p;

	/* a replaced record: new size, new masks (pg_num 24 is not a power of two) */
	start(&g, 8, 0, 8);
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 24, 0);
	ok(&g, &inc);
	p = &wri_map_pools(rig_held(&g))[0];
	WRT_CHECK_U64(p->pg_num, 24);
	WRT_CHECK_U64(p->pg_num_mask, 31);
	/* a record of a pool that is not tracked is stepped over */
	new_inc(&g, &inc);
	put_pool(&inc, 3, NULL, 64, 0);
	put_pool(&inc, 7, NULL, 8, 0);
	ok(&g, &inc);
	/* removal of a tracked pool: the record is gone, so are its table entries; the other pool is untouched */
	WRT_CHECK(rig_held(&g)->tab[WRI_TAB_PG_TEMP].n > 0);
	new_inc(&g, &inc);
	put_old(&inc, 2);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[1].present, 0);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].present, 1);
	/* removal of an untracked pool and of one that does not exist */
	new_inc(&g, &inc);
	put_old(&inc, 3);
	put_old(&inc, 99);
	ok(&g, &inc);
	rig_end(&g);

	/* a pool in both lists is removed (removals come last) */
	start(&g, 8, 0, 9);
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 32, 0);
	put_old(&inc, 1);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].present, 0);
	rig_end(&g);
}

static void test_pools_names(void)
{
	rig g;
	wrt_mg_inc inc;
	static const char *const three[] = {"pool1", "pool2", "pool4"};
	static const char *const dup[] = {"pool1", "pool1", "pool2"};
	wr_errinfo why = { 0 };

	/* a tracked pool that does not exist yet appears: record, name and the new pool ceiling in one epoch, with table entries */
	start_names(&g, three, 3, 8);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].present, 0);
	new_inc(&g, &inc);
	put_pool(&inc, 4, "pool4", 16, 0);
	inc.new_pool_max = 4;
	add_pg_list(&inc.new_pg_temp, 4, 1, (const int32_t[]){0, 1}, 2);
	add_pg_osd(&inc.new_primary_temp, 4, 2, 1);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].present, 1);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].id, 4);
	/* the same pool removed and created again under a new id */
	new_inc(&g, &inc);
	put_old(&inc, 4);
	ok(&g, &inc);
	new_inc(&g, &inc);
	put_pool(&inc, 5, "pool4", 16, 0);
	inc.new_pool_max = 5;
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].id, 5);
	rig_end(&g);

	/* a tracked name that gains an id: with no record anywhere, or a record but no sign the pool is new, a full map is needed */
	start_names(&g, three, 3, 8);
	new_inc(&g, &inc);
	put_name(&inc, 3, "pool4"); /* pool3 was untracked: the client has no record of it */
	refuse_free(&g, &inc, WR_E_MAP_RESYNC);
	new_inc(&g, &inc);
	put_pool(&inc, 4, "pool4", 16, 0); /* a record, but new_pool_max says nothing */
	refuse_free(&g, &inc, WR_E_MAP_RESYNC);
	new_inc(&g, &inc);
	put_pool(&inc, 4, "pool4", 16, 0);
	inc.new_pool_max = 3; /* below the id */
	refuse_free(&g, &inc, WR_E_MAP_RESYNC);
	new_inc(&g, &inc);
	put_pool(&inc, 4, "pool4", 16, 0);
	inc.new_pool_max = 4;
	ok(&g, &inc);
	rig_end(&g);

	/* an absent tracked pool is not a record of pool 0: a name that gains id 0 needs a full map as well */
	start_names(&g, three, 3, 8);
	new_inc(&g, &inc);
	put_name(&inc, 0, "pool4");
	refuse_free(&g, &inc, WR_E_MAP_RESYNC);
	rig_end(&g);

	/* renamed away: the pool is absent, its entries are gone; renamed back later needs a full map (no record, no new_pool_max) */
	start(&g, 8, 0, 11);
	new_inc(&g, &inc);
	put_name(&inc, 1, "other");
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].present, 0);
	{
		unsigned kind;
		uint32_t i;

		for (kind = 0; kind < WRI_TAB_COUNT; kind++) /* no entry of pool 1 is left in any table */
			for (i = 0; i < rig_held(&g)->tab[kind].n; i++)
				WRT_CHECK((wri_pgtab_keys(rig_held(&g), kind)[i] >> 32) != 1);
	}
	new_inc(&g, &inc);
	put_name(&inc, 1, "pool1");
	refuse_free(&g, &inc, WR_E_MAP_RESYNC);
	rig_end(&g);

	/* swapped names: pool1 and pool2 trade ids; the held records are re-used, nothing is lost */
	start(&g, 8, 0, 12);
	new_inc(&g, &inc);
	put_name(&inc, 1, "pool2");
	put_name(&inc, 2, "pool1");
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].id, 2);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[1].id, 1);
	rig_end(&g);

	/* a name tracked twice is the same record twice, and is replaced twice */
	start_names(&g, dup, 3, 8);
	WRT_CHECK(memcmp(&wri_map_pools(rig_held(&g))[0], &wri_map_pools(rig_held(&g))[1], sizeof(wri_map_pool)) == 0);
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 48, 0);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].pg_num, 48);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[1].pg_num, 48);
	rig_end(&g);

	/* a tracked name on two ids in one incremental is damage */
	start(&g, 8, 0, 13);
	new_inc(&g, &inc);
	put_name(&inc, 1, "pool1");
	put_name(&inc, 2, "pool1");
	refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
	new_inc(&g, &inc);
	put_name(&inc, 1, "pool1");
	put_name(&inc, 5, "pool1");
	refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
	/* a name that only has the tracked name as a prefix or suffix is another name */
	new_inc(&g, &inc);
	put_name(&inc, 1, "pool10");
	put_name(&inc, 4, "pool");
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].present, 0);
	(void)why;
	rig_end(&g);

	/* no tracked pools at all: the incremental still applies */
	start_names(&g, NULL, 0, 8);
	new_inc(&g, &inc);
	put_pool(&inc, 9, "x", 8, 0);
	put_old(&inc, 2);
	wrt_mg_inc_set_weight(&inc, 1, 5);
	ok(&g, &inc);
	rig_end(&g);
}

static void test_pools_status(void)
{
	rig g;
	wrt_mg_inc inc;
	int32_t want[2];
	wrt_mg_crush cr;
	wrt_mg_map desc;
	wrt_mg_cluster_spec s;

	/* a new record the client cannot use: the map is accepted, the pool says why */
	start(&g, 8, 0, 14);
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 32, WRT_MG_SHAPE_ERASURE);
	want[0] = WR_E_POOL_UNSUPPORTED;
	want[1] = WR_OK;
	ok_want(&g, &inc, want);
	/* ... and it stays unusable through an unrelated epoch, and is fixed by a good record */
	new_inc(&g, &inc);
	ok_want(&g, &inc, want);
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 32, 0);
	ok(&g, &inc);
	/* a few more shapes */
	new_inc(&g, &inc);
	put_pool(&inc, 2, NULL, 32, WRT_MG_SHAPE_SIZE17);
	want[0] = WR_OK;
	want[1] = WR_E_POOL_UNSUPPORTED;
	ok_want(&g, &inc, want);
	new_inc(&g, &inc);
	put_pool(&inc, 2, NULL, 32, WRT_MG_SHAPE_TIERS);
	ok_want(&g, &inc, want);
	new_inc(&g, &inc);
	put_pool(&inc, 2, NULL, 32, WRT_MG_SHAPE_HASH3);
	ok_want(&g, &inc, want);
	new_inc(&g, &inc);
	put_pool(&inc, 2, NULL, 32, WRT_MG_SHAPE_POOL_SNAPS); /* a pool flag, not a reason to refuse the pool */
	want[1] = WR_OK;
	ok_want(&g, &inc, want);
	rig_end(&g);

	/* a record the decoder cannot read at all (struct_compat above what it knows) is a map failure for a tracked pool ... */
	start(&g, 8, 0, 15);
	new_inc(&g, &inc);
	put_pool(&inc, 2, NULL, 32, 0);
	WRT_MG_E(inc.new_pools, wrt_mg_pool_ent, 0).p.compat = 33;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	/* ... and nothing for a pool that is not tracked (it is stepped over by its length) */
	new_inc(&g, &inc);
	put_pool(&inc, 3, NULL, 32, 0);
	WRT_MG_E(inc.new_pools, wrt_mg_pool_ent, 0).p.compat = 33;
	ok(&g, &inc);
	/* a pool with a trailing newer row and a raised struct_v is fine */
	new_inc(&g, &inc);
	put_pool(&inc, 1, NULL, 32, 0);
	WRT_MG_E(inc.new_pools, wrt_mg_pool_ent, 0).p.tail = 9;
	ok(&g, &inc);
	rig_end(&g);

	/* the CRUSH map changes: the status of every pool is decided again. A map without rule 0 leaves pools on rule 0 unusable. */
	wrt_mg_cluster_spec_init(&s, 8);
	s.n_pools = 2;
	s.pg_num = 16;
	WRT_CHECK(wrt_mg_build_map(&desc, &s) == 0);
	{
		wrt_mg_pool_ent *pe = &WRT_MG_E(desc.pools, wrt_mg_pool_ent, 1);

		pe->p.crush_rule = 1; /* pool2 uses rule 1 ("replicated_osd"), pool1 rule 0 */
	}
	WRT_CHECK(rig_start(&g, &desc, 4096, 1, NAMES, NNAMES));
	WRT_CHECK(wrt_mg_crush_parse(desc.crush, desc.crush_len, &cr) == 0);
	WRT_MG_E(cr.rules, wrt_mg_rule, 0).present = 0;
	new_inc(&g, &inc);
	wrt_mg_inc_set_crush(&inc, &cr);
	want[0] = RIG_WANT_ANY;
	want[1] = WR_OK;
	ok_want(&g, &inc, want);
	WRT_CHECK(wri_map_pools(rig_held(&g))[0].status != WR_OK);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[1].status, WR_OK);
	/* an epoch that changes nothing about CRUSH keeps the status (the region is copied and audited again) */
	new_inc(&g, &inc);
	wrt_mg_inc_set_weight(&inc, 1, 0x8000);
	ok_want(&g, &inc, want);
	WRT_CHECK(wri_map_pools(rig_held(&g))[0].status != WR_OK);
	/* the rule comes back */
	wrt_mg_crush_free(&cr);
	WRT_CHECK(wrt_mg_crush_parse(desc.crush, desc.crush_len, &cr) == 0);
	new_inc(&g, &inc);
	wrt_mg_inc_set_crush(&inc, &cr);
	ok(&g, &inc);
	WRT_CHECK_U64(wri_map_pools(rig_held(&g))[0].status, WR_OK);
	/* a CRUSH blob that is not one: refused, the held map stays */
	new_inc(&g, &inc);
	inc.crush = (uint8_t *)malloc(5);
	memcpy(inc.crush, "\1\2\3\4\5", 5);
	inc.crush_len = 5;
	refuse_free(&g, &inc, WR_E_CRUSH_ENCODING);
	/* an unchanged CRUSH region is copied byte for byte */
	{
		const wri_crush *c0 = wri_map_crush(rig_held(&g));
		uint8_t *keep = rig_dup((const uint8_t *)c0, c0->bytes);
		size_t kn = c0->bytes;

		new_inc(&g, &inc);
		ok(&g, &inc);
		WRT_CHECK(wri_map_crush(rig_held(&g))->bytes == kn && memcmp(wri_map_crush(rig_held(&g)), keep, kn) == 0);
		free(keep);
	}
	wrt_mg_crush_free(&cr);
	wrt_mg_map_free(&desc);
	rig_end(&g);
}

/* Pool ids above 31 bits: a pool with such an id can be tracked but never used, none of its pg entries is kept, and a key of such
 * a pool in a removal list must not be mistaken for a key of a small pool (the key packs the id into 32 bits). */
static void test_pools_huge_ids(void)
{
	rig g;
	wrt_mg_inc inc;
	static const char *const three[] = {"pool1", "pool2", "pool4"};
	int32_t want[3];
	const int32_t v[2] = {1, 2};
	static const int64_t ids[] = {0x80000001LL, 0x100000001LL, 0x7fffffffLL};
	unsigned i;

	for (i = 0; i < 3; i++) {
		start_names(&g, three, 3, 8);
		new_inc(&g, &inc);
		put_pool(&inc, ids[i], "pool4", 16, 0);
		inc.new_pool_max = ids[i];
		add_pg_list(&inc.new_pg_temp, (uint64_t)ids[i], 1, v, 2);
		add_pg_osd(&inc.new_primary_temp, (uint64_t)ids[i], 2, 1);
		want[0] = want[1] = WR_OK;
		want[2] = i < 2 ? WR_E_POOL_UNSUPPORTED : WR_OK;
		ok_want(&g, &inc, want);
		WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].present, 1);
		WRT_CHECK_U64(wri_map_pools(rig_held(&g))[2].status, want[2]);
		/* nothing of the unusable pool is kept; the usable one (id 2^31 - 1) keeps its entries */
		WRT_CHECK_U64(rig_held(&g)->tab[WRI_TAB_PG_TEMP].n, i < 2 ? 4 : 5);
		rig_end(&g);
	}
	/* removal keys of a pool whose id does not fit 31 bits never hit a small pool's entry */
	start(&g, 8, 0, 30);
	new_inc(&g, &inc);
	add_pg(&inc.old_pg_upmap, 1, 3);
	add_pg(&inc.old_pg_upmap, 0x100000001ULL, 9);
	add_pg(&inc.old_pg_upmap_items, 2, 1);
	add_pg(&inc.old_pg_upmap_items, 0x100000002ULL, 5);
	add_pg(&inc.old_pg_upmap_items, 0x100000002ULL + 7, 5);
	ok(&g, &inc);
	new_inc(&g, &inc);
	add_pg_list(&inc.new_pg_upmap, 1, 9, v, 2);
	add_pg(&inc.old_pg_upmap, 1, 8);
	add_pg(&inc.old_pg_upmap, 0x100000001ULL, 9); /* aliases (1, 9) in a 32-bit key: must not remove it */
	ok(&g, &inc);
	WRT_CHECK(wri_pgtab_find(rig_held(&g), WRI_TAB_PG_UPMAP, wri_pg_key(1, 9), NULL, NULL));
	rig_end(&g);
}

/* The held CRUSH region is copied whole, also when it ends in choose_args rows (the nonzero tail of a region). */
static void test_crush_copy(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_map desc;
	wrt_mg_cluster_spec s;
	const wri_crush *c0;
	uint8_t *keep;
	size_t kn;

	wrt_mg_cluster_spec_init(&s, 12);
	s.n_pools = 2;
	s.pg_num = 16;
	s.choose_args_rows = 2;
	s.choose_args_ids = 1;
	s.choose_args_pool_set = 1;
	WRT_CHECK(wrt_mg_build_map(&desc, &s) == 0);
	WRT_CHECK(rig_start(&g, &desc, 4096, 1, NAMES, NNAMES));
	c0 = wri_map_crush(rig_held(&g));
	kn = c0->bytes;
	keep = rig_dup((const uint8_t *)c0, kn);
	WRT_CHECK(c0->n_sets >= 1);
	new_inc(&g, &inc);
	wrt_mg_inc_set_weight(&inc, 1, 0x8000);
	ok(&g, &inc);
	WRT_CHECK(wri_map_crush(rig_held(&g))->bytes == kn && memcmp(wri_map_crush(rig_held(&g)), keep, kn) == 0);
	/* and after being copied once more through a resize */
	new_inc(&g, &inc);
	inc.new_max_osd = 16;
	ok(&g, &inc);
	WRT_CHECK(wri_map_crush(rig_held(&g))->bytes == kn && memcmp(wri_map_crush(rig_held(&g)), keep, kn) == 0);
	free(keep);
	wrt_mg_map_free(&desc);
	rig_end(&g);
}

/* ---- identity, embedded full maps ----------------------------------------------------------------------------- */

static void test_identity(void)
{
	rig g;
	wrt_mg_inc inc;
	uint32_t epoch;
	static const uint32_t bad_epochs[] = {0, 1, 9, 10, 12, 13, 0xffffffffu, 11u + 0x10000u};
	unsigned i;

	start(&g, 8, 0, 20);
	epoch = g.model.epoch;
	/* another cluster's incremental */
	new_inc(&g, &inc);
	inc.fsid[0] ^= 1;
	refuse_both(&g, &inc, WR_E_MAP_FSID, WRT_MG_E_FSID);
	new_inc(&g, &inc);
	inc.fsid[15] ^= 0x80;
	refuse_both(&g, &inc, WR_E_MAP_FSID, WRT_MG_E_FSID);
	/* the epoch must be the next one: a gap, a repeat, an older one, zero, the largest value */
	for (i = 0; i < sizeof(bad_epochs) / sizeof(bad_epochs[0]); i++) {
		new_inc(&g, &inc);
		inc.epoch = bad_epochs[i];
		refuse_both(&g, &inc, WR_E_MAP_EPOCH, WRT_MG_E_EPOCH);
	}
	/* the fsid is looked at first */
	new_inc(&g, &inc);
	inc.fsid[3] ^= 1;
	inc.epoch = epoch + 5u;
	refuse_both(&g, &inc, WR_E_MAP_FSID, WRT_MG_E_FSID);
	new_inc(&g, &inc);
	ok(&g, &inc);
	WRT_CHECK_U64(rig_held(&g)->epoch, epoch + 1u);

	/* an embedded full map of the next epoch replaces everything: other size, other pools, other tables */
	{
		wrt_mg_map nm;
		wrt_mg_pg pg = {1, 2};
		const int32_t l[2] = {1, 0};

		mk_desc(&nm, 6, 1, 77);
		memcpy(nm.fsid, g.model.fsid, 16);
		nm.epoch = g.model.epoch + 1u;
		nm.flags = 0x1234;
		wrt_mg_map_set_pg_temp(&nm, pg, l, 2);
		new_inc(&g, &inc);
		wrt_mg_inc_set_fullmap(&inc, &nm);
		inc.new_flags = 7;           /* everything else in the incremental is ignored ... */
		wrt_mg_inc_set_weight(&inc, 1, 5); /* ... even rows that would be refused on their own */
		wrt_mg_inc_set_weight(&inc, 99, 5);
		{
			wrt_mg_buf b;
			islot dst;
			wr_errinfo why = { 0 };

			memset(&b, 0, sizeof(b));
			WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
			islot_new(&dst, RIG_SLOT_BYTES);
			WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
			WRT_CHECK_U64(islot_map(&dst)->flags, 0x1234);
			WRT_CHECK_U64(islot_map(&dst)->max_osd, 6);
			islot_free(&dst);
			wrt_mg_buf_free(&b);
		}
		wrt_mg_inc_free(&inc);

		/* the same without the rows that make the model refuse: model and core agree on the new state */
		new_inc(&g, &inc);
		wrt_mg_inc_set_fullmap(&inc, &nm);
		ok(&g, &inc);
		WRT_CHECK_U64(rig_held(&g)->max_osd, 6);
		WRT_CHECK_U64(rig_held(&g)->flags, 0x1234);

		/* not the next epoch: allowed when the map is embedded (the store decides what to do with a gap); it must be the epoch the
		 * incremental names, and the cluster's own */
		{
			wrt_mg_map far;
			wrt_mg_buf b;
			islot dst, full;
			wr_errinfo why = { 0 };

			mk_desc(&far, 9, 0, 78);
			memcpy(far.fsid, g.model.fsid, 16);
			far.epoch = 500;
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far);
			memset(&b, 0, sizeof(b));
			WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
			islot_new(&dst, RIG_SLOT_BYTES);
			islot_new(&full, RIG_SLOT_BYTES);
			WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
			WRT_CHECK_STATUS(WR_OK, rig_decode(&g.cfg, inc.fullmap, inc.fullmap_len, &full, &why));
			rig_cmp_core(islot_map(&dst), islot_map(&full));
			WRT_CHECK_U64(islot_map(&dst)->epoch, 500);
			islot_free(&dst);
			islot_free(&full);
			wrt_mg_buf_free(&b);
			wrt_mg_inc_free(&inc);

			wrt_mg_inc_init(&inc, g.model.fsid, 501); /* the map inside says 500 */
			wrt_mg_inc_set_fullmap(&inc, &far);
			refuse_free(&g, &inc, WR_E_MAP_EPOCH);
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			far.fsid[2] ^= 1; /* the map inside is another cluster's */
			wrt_mg_inc_set_fullmap(&inc, &far);
			refuse_free(&g, &inc, WR_E_MAP_FSID);
			far.fsid[2] ^= 1;
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			inc.fsid[2] ^= 1; /* the incremental is */
			wrt_mg_inc_set_fullmap(&inc, &far);
			refuse_free(&g, &inc, WR_E_MAP_FSID);
			/* a map with a pool this client cannot use leaves a note in the decoder's errinfo; a failure found afterwards must still be the
			 * status and the reason the caller gets (the fuzz target found the status of one and the errinfo of the other) */
			wrt_mg_pool_shape(&WRT_MG_E(far.pools, wrt_mg_pool_ent, 0).p, WRT_MG_SHAPE_ERASURE);
			far.fsid[2] ^= 1;
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far);
			refuse_free(&g, &inc, WR_E_MAP_FSID);
			far.fsid[2] ^= 1;
			wrt_mg_inc_init(&inc, g.model.fsid, 501);
			wrt_mg_inc_set_fullmap(&inc, &far);
			refuse_free(&g, &inc, WR_E_MAP_EPOCH);
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far); /* and the same map accepted: the note is reported with the success */
			{
				wrt_mg_buf b2;
				islot d2;
				wr_errinfo w2;

				memset(&b2, 0, sizeof(b2));
				WRT_CHECK(wrt_mg_inc_encode(&inc, &b2) == 0);
				islot_new(&d2, RIG_SLOT_BYTES);
				WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), b2.p, b2.len, &d2, &w2));
				WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, w2.status);
				islot_free(&d2);
				wrt_mg_buf_free(&b2);
			}
			wrt_mg_inc_free(&inc);
			/* a map that is damaged: its CRC does not match (checked), or its bytes are cut */
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far);
			inc.fullmap[40] ^= 1;
			refuse_free(&g, &inc, WR_E_MAP_CRC);
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far);
			inc.fullmap_len -= 3;
			refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
			wrt_mg_inc_init(&inc, g.model.fsid, 500);
			wrt_mg_inc_set_fullmap(&inc, &far);
			inc.fullmap_len = 5;
			refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
			/* too big for the slot */
			{
				wri_mapcfg small = g.cfg;
				islot tiny;

				small.slot_bytes = 400;
				islot_new(&tiny, 400);
				wrt_mg_inc_init(&inc, g.model.fsid, 500);
				wrt_mg_inc_set_fullmap(&inc, &far);
				memset(&b, 0, sizeof(b));
				WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
				WRT_CHECK_STATUS(WR_E_MAP_BUDGET, rig_apply(&small, rig_held(&g), b.p, b.len, &tiny, &why));
				wrt_mg_buf_free(&b);
				wrt_mg_inc_free(&inc);
				islot_free(&tiny);
			}
			wrt_mg_map_free(&far);
		}
		wrt_mg_map_free(&nm);
	}
	rig_end(&g);

	/* a held epoch of 0xffffffff has no next one: epoch 0 is not it (the sum is done in 64 bits, it does not wrap) */
	{
		wrt_mg_map m;

		mk_desc(&m, 8, 0, 80);
		m.epoch = 0xffffffffu;
		WRT_CHECK(rig_start(&g, &m, 4096, 1, NAMES, NNAMES));
		wrt_mg_map_free(&m);
		wrt_mg_inc_init(&inc, g.model.fsid, 0);
		refuse_free(&g, &inc, WR_E_MAP_EPOCH);
		rig_end(&g);
	}
}

/* ---- CRC, versions, envelope --------------------------------------------------------------------------------- */

static void test_envelope(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_buf b;
	wrt_mg_layout lay;
	islot dst;
	wr_errinfo why = { 0 };
	wri_mapcfg off;

	start(&g, 8, 0, 21);
	off = g.cfg;
	off.verify_crc = 0;
	islot_new(&dst, RIG_SLOT_BYTES);

	/* a wrong inc_crc: refused when the CRC is checked, accepted when it is not */
	new_inc(&g, &inc);
	wrt_mg_inc_set_weight(&inc, 1, 9);
	inc.inc_crc_override = 1;
	inc.inc_crc = 0x12345678u;
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK_STATUS(WR_E_MAP_CRC, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
	WRT_CHECK_STATUS(WR_OK, rig_apply(&off, rig_held(&g), b.p, b.len, &dst, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	/* a flipped byte in the body of a good incremental */
	new_inc(&g, &inc);
	wrt_mg_inc_set_weight(&inc, 1, 9);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
	WRT_CHECK(wrt_mg_wrapper_layout(b.p, b.len, &lay) == 0);
	b.p[lay.client_body + 40] ^= 0x40;
	WRT_CHECK_STATUS(WR_E_MAP_CRC, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
	b.p[lay.client_body + 40] ^= 0x40;
	b.p[b.len - 1] ^= 1; /* full_crc is covered too, though never compared */
	WRT_CHECK_STATUS(WR_E_MAP_CRC, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
	WRT_CHECK_STATUS(WR_OK, rig_apply(&off, rig_held(&g), b.p, b.len, &dst, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);

	/* the wrapper without a CRC (struct_v 7) is fine, verified or not */
	new_inc(&g, &inc);
	inc.wrapper_v = 7;
	wrt_mg_inc_set_weight(&inc, 2, 9);
	ok(&g, &inc);
	/* client block v8 has no upmap-primary rows; the others work */
	new_inc(&g, &inc);
	inc.client_v = 8;
	add_pg_list(&inc.new_pg_temp, 1, 12, (const int32_t[]){1, 2}, 2);
	ok(&g, &inc);
	/* raised struct_v with a tail (the wrapper, the client block, the OSD-only block): skipped by length */
	new_inc(&g, &inc);
	inc.wrapper_v = 9;
	inc.wrapper_tail = 7;
	inc.client_v = 11;
	inc.client_tail = 5;
	inc.osd_v = 13;
	inc.osd_tail = 3;
	wrt_mg_inc_set_weight(&inc, 3, 9);
	ok(&g, &inc);
	/* compat byte at the limit is fine, one above is not; the OSD-only block's compat is never looked at */
	new_inc(&g, &inc);
	inc.client_compat = 9;
	inc.osd_compat = 200;
	ok(&g, &inc);
	new_inc(&g, &inc);
	inc.client_compat = 10;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	new_inc(&g, &inc);
	inc.wrapper_compat = 9;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	new_inc(&g, &inc);
	inc.wrapper_v = 6;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	new_inc(&g, &inc);
	inc.wrapper_v = 1;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	new_inc(&g, &inc);
	inc.client_v = 7;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);
	new_inc(&g, &inc);
	inc.client_v = 3;
	refuse_free(&g, &inc, WR_E_MAP_VERSION);

	/* an OSD-only block that claims more than there is, one that leaves no room for the CRC fields, bytes after the wrapper */
	new_inc(&g, &inc);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK(wrt_mg_wrapper_layout(b.p, b.len, &lay) == 0);
	{
		uint8_t *p = rig_dup(b.p, b.len);
		uint8_t *q = rig_dup(b.p, b.len + 3u);

		p[lay.osd_off + 2] = 0xf0;
		p[lay.osd_off + 3] = 0xff;
		p[lay.osd_off + 4] = 0xff;
		p[lay.osd_off + 5] = 0x7f;
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, rig_apply(&off, rig_held(&g), p, b.len, &dst, &why));
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, rig_apply(&g.cfg, rig_held(&g), p, b.len, &dst, &why));
		memcpy(q, b.p, b.len);
		q[b.len] = q[b.len + 1] = q[b.len + 2] = 0;
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, rig_apply(&off, rig_held(&g), q, b.len + 3u, &dst, &why));
		free(p);
		free(q);
	}
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	islot_free(&dst);
	rig_end(&g);
}

/* ---- sorted lists must ascend ------------------------------------------------------------------------------- */

static void test_unsorted(void)
{
	rig g;
	wrt_mg_inc inc;
	unsigned which, dup;
	const int32_t v[2] = {1, 2};
	const int32_t f[2] = {1, 2};

	for (which = 0; which < 12; which++) {
		start(&g, 8, 0, 22);
		for (dup = 0; dup < 3; dup++) {
			if (which == 11 && dup != 0)
				continue;
			/* dup 0: ascending (accepted), 1: a repeated key, 2: descending */
			uint64_t pa = dup == 2 ? 2 : 1, pb = dup == 1 ? 1 : (dup == 2 ? 1 : 2);
			unsigned seed_a = dup == 2 ? 6 : 5, seed_b = dup == 1 ? 5 : (dup == 2 ? 5 : 6);

			new_inc(&g, &inc);
			switch (which) {
			case 0:
				put_pool(&inc, (int64_t)pa, NULL, 16, 0);
				put_pool(&inc, (int64_t)pb, NULL, 16, 0);
				break;
			case 1:
				put_name(&inc, (int64_t)pa, "x");
				put_name(&inc, (int64_t)pb, "y");
				break;
			case 2:
				put_old(&inc, (int64_t)pa);
				put_old(&inc, (int64_t)pb);
				break;
			case 3:
				add_pg_list(&inc.new_pg_temp, 1, seed_a, v, 2);
				add_pg_list(&inc.new_pg_temp, 1, seed_b, v, 2);
				break;
			case 4:
				add_pg_osd(&inc.new_primary_temp, 1, seed_a, 1);
				add_pg_osd(&inc.new_primary_temp, 1, seed_b, 1);
				break;
			case 5:
				add_pg_list(&inc.new_pg_upmap, 1, seed_a, v, 2);
				add_pg_list(&inc.new_pg_upmap, 1, seed_b, v, 2);
				break;
			case 6:
				add_pg(&inc.old_pg_upmap, 1, seed_a);
				add_pg(&inc.old_pg_upmap, 1, seed_b);
				break;
			case 7:
				add_pg_items(&inc.new_pg_upmap_items, 1, seed_a, f, 1);
				add_pg_items(&inc.new_pg_upmap_items, 1, seed_b, f, 1);
				break;
			case 8:
				add_pg(&inc.old_pg_upmap_items, 1, seed_a);
				add_pg(&inc.old_pg_upmap_items, 1, seed_b);
				break;
			case 9:
				add_pg_osd(&inc.new_pg_upmap_primary, 1, seed_a, 1);
				add_pg_osd(&inc.new_pg_upmap_primary, 1, seed_b, 1);
				break;
			case 10:
				add_pg(&inc.old_pg_upmap_primary, 1, seed_a);
				add_pg(&inc.old_pg_upmap_primary, 1, seed_b);
				break;
			default: /* the pool is the major key: (2, 9) then (1, 20) descends even though 20 > 9 */
				add_pg_list(&inc.new_pg_temp, 2, 9, v, 2);
				add_pg_list(&inc.new_pg_temp, 1, 20, v, 2);
				break;
			}
			if (which == 11 || dup != 0)
				refuse_free(&g, &inc, WR_E_MAP_CORRUPT);
			else
				ok(&g, &inc);
		}
		rig_end(&g);
	}
}

/* ---- every skipped row filled in ---------------------------------------------------------------------------------- */

/* An incremental that carries something in every row the decoder only steps over (erasure-code profile changes, removed and purged
 * snapshots, the two change times, the whole OSD-only block with every optional part) next to real changes in the rows around
 * them: the rows after a skipped one are found only if every skip ended exactly at the row's end. Also with the later versions of
 * the OSD-only block (stretch mode, range blocklist, crimson), and for a client block of v8 (which ends at row 27). */
static void busy_skipped(wrt_mg_inc *inc)
{
	wrt_mg_ecprof ep;
	wrt_mg_kv kv;
	wrt_mg_str st;
	wrt_mg_snapset ss;
	wrt_mg_blk bl;
	wrt_mg_addr ad;
	wrt_mg_osd_xinfo xi;
	wrt_mg_osd_uuid uu;
	int i;

	memset(&ep, 0, sizeof(ep));
	memset(&kv, 0, sizeof(kv));
	memset(&st, 0, sizeof(st));
	snprintf(ep.name, sizeof(ep.name), "prof");
	for (i = 0; i < 3; i++) {
		snprintf(kv.k, sizeof(kv.k), "k%d", i);
		snprintf(kv.v, sizeof(kv.v), "value-%d", i);
		WRT_MG_PUSH(ep.kv, wrt_mg_kv, kv);
	}
	WRT_MG_PUSH(inc->new_erasure_code_profiles, wrt_mg_ecprof, ep);
	memset(&ep, 0, sizeof(ep)); /* each pushed description owns its vectors */
	snprintf(ep.name, sizeof(ep.name), "prof2");
	snprintf(kv.k, sizeof(kv.k), "plugin");
	snprintf(kv.v, sizeof(kv.v), "isa");
	WRT_MG_PUSH(ep.kv, wrt_mg_kv, kv);
	WRT_MG_PUSH(inc->new_erasure_code_profiles, wrt_mg_ecprof, ep);
	snprintf(st.s, sizeof(st.s), "oldprof");
	WRT_MG_PUSH(inc->old_erasure_code_profiles, wrt_mg_str, st);
	snprintf(st.s, sizeof(st.s), "oldprof-two-with-a-longer-name");
	WRT_MG_PUSH(inc->old_erasure_code_profiles, wrt_mg_str, st);
	for (i = 0; i < 2; i++) {
		memset(&ss, 0, sizeof(ss));
		ss.pool = 2 + i;
		WRT_MG_PUSH(ss.iv, wrt_mg_iv, ((wrt_mg_iv){2, 1}));
		WRT_MG_PUSH(ss.iv, wrt_mg_iv, ((wrt_mg_iv){7, 4}));
		WRT_MG_PUSH(inc->new_removed_snaps, wrt_mg_snapset, ss);
		memset(&ss, 0, sizeof(ss));
		ss.pool = 2 + i;
		WRT_MG_PUSH(ss.iv, wrt_mg_iv, ((wrt_mg_iv){2, 1}));
		WRT_MG_PUSH(inc->new_purged_snaps, wrt_mg_snapset, ss);
	}
	inc->new_last_up_change.sec = 1700000001u;
	inc->new_last_in_change.sec = 1700000002u;
	WRT_MG_PUSH(inc->new_up_thru, wrt_mg_osd_u32, ((wrt_mg_osd_u32){1, 2}));
	WRT_MG_PUSH(inc->new_last_clean_interval, wrt_mg_osd_pair, ((wrt_mg_osd_pair){2, 3, 4}));
	WRT_MG_PUSH(inc->new_lost, wrt_mg_osd_u32, ((wrt_mg_osd_u32){3, 9}));
	memset(&bl, 0, sizeof(bl));
	wrt_mg_addr_v4(&bl.addr, 3, 0x0a000001, 0, 77);
	bl.until.sec = 1700001000u;
	WRT_MG_PUSH(inc->new_blocklist, wrt_mg_blk, bl);
	wrt_mg_addr_v4(&ad, 3, 0x0a000002, 0, 78);
	WRT_MG_PUSH(inc->old_blocklist, wrt_mg_addr, ad);
	memset(&xi, 0, sizeof(xi));
	xi.osd = 1;
	xi.x.v = 4;
	xi.x.compat = 1;
	xi.x.features = WRT_MG_FEATURES_ALL;
	WRT_MG_PUSH(inc->new_xinfo, wrt_mg_osd_xinfo, xi);
	memset(&uu, 0, sizeof(uu));
	uu.osd = 1;
	memset(uu.uuid, 0x5a, 16);
	WRT_MG_PUSH(inc->new_uuid, wrt_mg_osd_uuid, uu);
	snprintf(inc->cluster_snapshot, sizeof(inc->cluster_snapshot), "snap1");
	inc->new_nearfull_bits = 0x3f59999au;
	inc->new_require_min_compat_client = 16;
	/* new_require_osd_release stays unchanged here: the model applies Ceph's side effect on the map flags, the compact map does not (see below) */
	WRT_MG_PUSH(inc->new_crush_node_flags, wrt_mg_osd_u32, ((wrt_mg_osd_u32){-3, 1}));
	WRT_MG_PUSH(inc->new_device_class_flags, wrt_mg_osd_u32, ((wrt_mg_osd_u32){0, 1}));
}

/* The real changes around the skipped rows: every row the decoder applies, with a key or an id before and after each skipped one. */
static void busy_real(wrt_mg_inc *inc, int primaries)
{
	const int32_t l2[2] = {2, 1}, it[4] = {0, 2, 1, 3};
	wrt_mg_addrvec av;

	inc->new_flags = 0x10000;
	wrt_mg_inc_set_weight(inc, 4, 0x8000);
	wrt_mg_inc_set_affinity(inc, 1, 0x4000);
	wrt_mg_inc_mark_down(inc, 0);
	av_v4(&av, 7, 6850, 4242);
	wrt_mg_inc_mark_up(inc, 6, &av);
	add_pg_list(&inc->new_pg_temp, 2, 3, NULL, 0);
	add_pg_list(&inc->new_pg_temp, 2, 8, l2, 2);
	add_pg_osd(&inc->new_primary_temp, 2, 7, -1);
	add_pg_osd(&inc->new_primary_temp, 2, 12, 2);
	add_pg_list(&inc->new_pg_upmap, 2, 1, l2, 2);
	add_pg(&inc->old_pg_upmap, 2, 9);
	add_pg_items(&inc->new_pg_upmap_items, 2, 6, it, 2);
	add_pg(&inc->old_pg_upmap_items, 2, 5);
	if (primaries) { /* rows 28 and 29: the last two rows, after every skipped one */
		add_pg_osd(&inc->new_pg_upmap_primary, 2, 2, 1);
		add_pg_osd(&inc->new_pg_upmap_primary, 2, 13, 2);
		add_pg(&inc->old_pg_upmap_primary, 2, 11);
	}
}

static void test_skipped_rows(void)
{
	unsigned v;

	for (v = 0; v < 6; v++) { /* v 0: the OSD-only block of v9, 1 to 4 the later ones (v 1 is the same as 0 with the stretch row off), 5: client block v8 */
		rig g;
		wrt_mg_inc inc;
		const wri_osdmap *m;
		const uint64_t key_pm = wri_pg_key(2, 2);
		const int32_t *vals;
		uint32_t nv;

		start(&g, 10, 1, 40u + v);
		new_inc(&g, &inc);
		busy_skipped(&inc);
		busy_real(&inc, v != 5);
		if (v >= 1 && v <= 4) {
			inc.osd_v = (uint8_t)(8u + v); /* 9 to 12: stretch mode, range blocklist, crimson */
			inc.change_stretch_mode = inc.osd_v >= 10 ? 1 : 0;
			inc.new_stretch_bucket_count = 2;
			inc.stretch_mode_enabled = 1;
			inc.mutate_allow_crimson = inc.osd_v >= 12 ? 1 : 0;
		}
		if (v == 5)
			inc.client_v = 8;
		ok(&g, &inc);
		m = rig_held(&g);
		WRT_CHECK_U64(m->flags, 0x10000);
		WRT_CHECK_U64(wri_osd_weight(m, 4), 0x8000);
		WRT_CHECK_U64(wri_osd_aff(m, 1), 0x4000);
		WRT_CHECK(!wri_osd_up(m, 0) && wri_osd_up(m, 6));
		if (v != 5) {
			WRT_CHECK(wri_pgtab_find(m, WRI_TAB_PG_UPMAP_PRIMARY, key_pm, &vals, &nv) && nv == 1 && vals[0] == 1);
			WRT_CHECK(!wri_pgtab_find(m, WRI_TAB_PG_UPMAP_PRIMARY, wri_pg_key(2, 11), NULL, NULL));
		}
		WRT_CHECK(wri_pgtab_find(m, WRI_TAB_PG_UPMAP_ITEMS, wri_pg_key(2, 6), &vals, &nv) && nv == 4);
		rig_end(&g);
	}

	/* new_require_osd_release (OSD-only block) makes Ceph set RECOVERY_DELETES and PGLOG_HARDLIMIT and clear the legacy REQUIRE bits in the
	 * map flags; the compact map keeps only what a client reads (pause and full), so it leaves the flags as they were. The other
	 * rows of the incremental still apply. */
	{
		rig g;
		wrt_mg_inc inc;
		wrt_mg_buf b;
		islot dst;
		wr_errinfo why = { 0 };
		uint32_t before;

		start(&g, 10, 0, 50);
		before = rig_held(&g)->flags;
		new_inc(&g, &inc);
		inc.new_require_osd_release = 20;
		wrt_mg_inc_set_weight(&inc, 4, 0x8000);
		memset(&b, 0, sizeof(b));
		WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
		islot_new(&dst, RIG_SLOT_BYTES);
		WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), b.p, b.len, &dst, &why));
		WRT_CHECK_U64(islot_map(&dst)->flags, before);
		WRT_CHECK_U64(wri_osd_weight(islot_map(&dst), 4), 0x8000);
		islot_free(&dst);
		wrt_mg_buf_free(&b);
		wrt_mg_inc_free(&inc);
		rig_end(&g);
	}
}

/* ---- random chains against the model ------------------------------------------------------------------------------- */

typedef struct rnd {
	uint64_t s;
} rnd;

static uint32_t rnd_next(rnd *r) /* xorshift64*, the top 32 bits */
{
	r->s ^= r->s >> 12;
	r->s ^= r->s << 25;
	r->s ^= r->s >> 27;
	return (uint32_t)((r->s * 0x2545F4914F6CDD1Dull) >> 32);
}

static uint32_t rnd_below(rnd *r, uint32_t n) { return rnd_next(r) % n; }

static int32_t rnd_osd_value(rnd *r)
{
	uint32_t k = rnd_below(r, 8);

	return k == 0 ? -1 : k == 1 ? WRI_OSD_NONE : (int32_t)rnd_below(r, 14);
}

/* One random incremental for the next epoch: every OSD-level row and the five pg tables, keys strictly ascending, OSD ids valid for the size
 * after the resize. Pools 1 and 2 are tracked, 3 is not, 5 does not exist. */
static void rnd_inc(rnd *r, rig *g, wrt_mg_inc *inc)
{
	static const uint32_t weights[] = {0u, 0x1000u, 0x8000u, 0x10000u};
	static const uint32_t affs[] = {0u, 0x4000u, 0x10000u};
	static const uint32_t masks[] = {0u, 1u, 2u, 3u, 0x10u, 0x04u, 0x13u};
	static const uint64_t pools[] = {1, 2, 3, 5};
	uint32_t max_osd = g->model.max_osd, osd, p, seed, k;
	int32_t osds[8];

	new_inc(g, inc);
	if (rnd_below(r, 5) == 0) { /* a resize, to a size that keeps the ids of the model valid or not: the OSD ids below use the new size */
		int32_t nm = (int32_t)max_osd + (int32_t)rnd_below(r, 7) - 3;

		inc->new_max_osd = nm < 0 ? 0 : nm > 16 ? 16 : nm;
		max_osd = (uint32_t)inc->new_max_osd;
	}
	if (rnd_below(r, 6) == 0)
		inc->new_flags = (int32_t)(rnd_below(r, 4) << 2);
	for (osd = 0; osd < max_osd; osd++) {
		if (rnd_below(r, 6) == 0)
			wrt_mg_inc_set_weight(inc, (int32_t)osd, weights[rnd_below(r, 4)]);
		if (rnd_below(r, 8) == 0)
			wrt_mg_inc_set_affinity(inc, (int32_t)osd, affs[rnd_below(r, 3)]);
		if (rnd_below(r, 6) == 0)
			put_state(inc, (int32_t)osd, masks[rnd_below(r, 7)]);
		if (rnd_below(r, 6) == 0) {
			wrt_mg_addrvec av;

			av_v4(&av, osd, (uint16_t)(6800 + osd), rnd_next(r));
			wrt_mg_inc_mark_up(inc, (int32_t)osd, &av);
		}
	}
	for (p = 0; p < 4; p++) {
		for (seed = 0; seed < 20; seed++) {
			for (k = 0; k < 8; k++)
				osds[k] = rnd_osd_value(r);
			if (rnd_below(r, 14) == 0)
				add_pg_list(&inc->new_pg_temp, pools[p], seed, osds, rnd_below(r, 4)); /* an empty vector removes */
			if (rnd_below(r, 14) == 0)
				add_pg_osd(&inc->new_primary_temp, pools[p], seed, rnd_below(r, 3) == 0 ? -1 : osds[0]);
			if (rnd_below(r, 16) == 0)
				add_pg_list(&inc->new_pg_upmap, pools[p], seed, osds, rnd_below(r, 5));
			if (rnd_below(r, 16) == 0)
				add_pg(&inc->old_pg_upmap, pools[p], seed);
			if (rnd_below(r, 16) == 0)
				add_pg_items(&inc->new_pg_upmap_items, pools[p], seed, osds, rnd_below(r, 4));
			if (rnd_below(r, 16) == 0)
				add_pg(&inc->old_pg_upmap_items, pools[p], seed);
			if (rnd_below(r, 16) == 0)
				add_pg_osd(&inc->new_pg_upmap_primary, pools[p], seed, osds[1]);
			if (rnd_below(r, 16) == 0)
				add_pg(&inc->old_pg_upmap_primary, pools[p], seed);
		}
	}
}

static void test_random_chains(void)
{
	uint32_t run, step, applied = 0, refused = 0;

	for (run = 0; run < 24; run++) {
		rig g;
		rnd r;

		r.s = 0x9E3779B97F4A7C15ull * (run + 1u);
		start(&g, 6 + run % 5, (int)(run & 1u), 900u + run);
		for (step = 0; step < 40; step++) {
			wrt_mg_inc inc;
			wr_errinfo why = { 0 };
			wr_status st;

			rnd_inc(&r, &g, &inc);
			st = rig_step(&g, &inc, NULL, &why); /* core and model must accept the same ones, and the new states must agree */
			if (st == WR_OK)
				applied++;
			else
				refused++;
			wrt_mg_inc_free(&inc);
		}
		rig_end(&g);
	}
	WRT_CHECK(applied > 400); /* the generator makes mostly valid incrementals; a rate far below that means it stopped testing */
	(void)refused;
}

/* ---- arguments ---------------------------------------------------------------------------------------------- */

static void test_arguments(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_buf b;
	islot dst;
	wr_errinfo why = { 0 };
	uint8_t *blob;
	const wri_osdmap *src;
	wri_mapcfg cfg;

	start(&g, 8, 0, 23);
	src = rig_held(&g);
	new_inc(&g, &inc);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	blob = rig_dup(b.p, b.len);
	islot_new(&dst, RIG_SLOT_BYTES);
	cfg = g.cfg;

	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(NULL, src, blob, b.len, dst.p, dst.cap, &why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, NULL, blob, b.len, dst.p, dst.cap, &why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, NULL, b.len, dst.p, dst.cap, &why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, NULL, dst.cap, &why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p + 1, dst.cap - 16, &why)); /* misaligned */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p + 4, dst.cap - 16, &why)); /* 4-aligned only */
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, 100, &why)); /* smaller than the header */
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, 0, &why));
	WRT_CHECK(wri_osdmap_apply_inc(&cfg, src, blob, 0, dst.p, dst.cap, &why) != WR_OK); /* an empty incremental */
	WRT_CHECK(wri_osdmap_apply_inc(&cfg, src, blob, 1, dst.p, dst.cap, &why) != WR_OK);
	WRT_CHECK(islot_guard_ok(&dst));
	WRT_CHECK_STATUS(WR_OK, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));

	/* the new slot may not be, or lie in, the held map (the held map is never written) */
	{
		islot held2;

		islot_new(&held2, RIG_SLOT_BYTES);
		memcpy(held2.p, src, src->bytes);
		src = islot_map(&held2);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, held2.p, held2.cap, &why));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, held2.p + 64, held2.cap - 64, &why));
		WRT_CHECK_U64(src->magic, WRI_MAP_MAGIC);
		/* a held map that is not a map */
		held2.p[0] ^= 0xff;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
		held2.p[0] ^= 0xff;
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
		/* a held map whose table points outside itself is refused, not read */
		{
			wri_osdmap *w = (wri_osdmap *)(void *)held2.p;

			w->tab[WRI_TAB_PG_TEMP].key_off = w->bytes;
			WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
		}
		islot_free(&held2);
	}
	src = rig_held(&g);

	/* nor may it hold or touch the incremental's own bytes (the build would write over what it still reads); the bytes stay as they were */
	{
		islot ov;
		uint8_t *copy = rig_dup(blob, b.len);

		islot_new(&ov, RIG_SLOT_BYTES);
		memcpy(ov.p + 4096, blob, b.len);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, ov.p + 4096, b.len, ov.p, ov.cap, &why)); /* inside the slot */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, ov.p + 4096, b.len, ov.p + 4096, ov.cap - 4096u, &why)); /* at its start */
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, src, ov.p + 4096, b.len, ov.p + 4096 + b.len - 1u, ov.cap - 4096u - b.len + 1u, &why));
		WRT_CHECK_MEM(ov.p + 4096, copy, b.len);
		WRT_CHECK(islot_guard_ok(&ov));
		/* next to each other is fine */
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_apply_inc(&cfg, src, ov.p + 4096, b.len, ov.p + 4096 + ((b.len + 15u) & ~15u), ov.cap - 4096u - ((b.len + 15u) & ~15u), &why));
		islot_free(&ov);
		free(copy);
	}

	/* the tracked set of the held map is the one the incremental is applied with */
	cfg.n_pools = 1;
	WRT_CHECK_STATUS(WR_E_MAP_RESYNC, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
	cfg.n_pools = 0;
	WRT_CHECK_STATUS(WR_E_MAP_RESYNC, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
	cfg.n_pools = 9;
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_osdmap_apply_inc(&cfg, src, blob, b.len, dst.p, dst.cap, &why));
	WRT_CHECK_U64(islot_magic(&dst), 0);
	free(blob);
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);

	/* new_max_osd against the configured limit: at it is fine, above is a budget failure */
	cfg = g.cfg;
	cfg.max_osd = 20;
	new_inc(&g, &inc);
	inc.new_max_osd = 20;
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK_STATUS(WR_OK, rig_apply(&cfg, src, b.p, b.len, &dst, &why));
	WRT_CHECK_U64(islot_map(&dst)->max_osd, 20);
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	new_inc(&g, &inc);
	inc.new_max_osd = 21;
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, rig_apply(&cfg, src, b.p, b.len, &dst, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	new_inc(&g, &inc);
	inc.new_max_osd = 0x7fffffff;
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, rig_apply(&g.cfg, src, b.p, b.len, &dst, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	/* the slot is smaller than cfg->slot_bytes says: the smaller one counts; a bigger slot than the config allows is cut to it */
	new_inc(&g, &inc);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	cfg = g.cfg;
	cfg.slot_bytes = src->bytes - 1u;
	WRT_CHECK_STATUS(WR_E_MAP_BUDGET, rig_apply(&cfg, src, b.p, b.len, &dst, &why));
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);

	/* a held map that is damaged is refused (WR_E_INVAL), not read: every offset, count and size that locates something the copy reads */
	{
		islot h;
		wri_osdmap *w;
		unsigned k, f;
		uint32_t bytes;

		new_inc(&g, &inc);
		memset(&b, 0, sizeof(b));
		WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
		islot_new(&h, RIG_SLOT_BYTES);
		w = (wri_osdmap *)(void *)h.p;
		src = rig_held(&g);
		bytes = src->bytes;
		for (f = 0; f < 24; f++) {
			memcpy(h.p, src, bytes);
			switch (f) {
			case 0:
				w->state_off = bytes;
				break;
			case 1:
				w->weight_off = 0;
				break;
			case 2:
				w->addr_off = bytes - 1u;
				break;
			case 3:
				w->aff_off = bytes;
				break;
			case 4:
				w->pool_off = bytes;
				break;
			case 5:
				w->max_osd = WRI_MAP_OSD_HARD_MAX + 1u;
				break;
			case 6:
				w->n_pools = WRI_MAP_POOLS_MAX + 1u;
				break;
			case 7:
				w->crush_off = bytes;
				break;
			case 8:
				((wri_crush *)(void *)(h.p + w->crush_off))->bytes = 0x00ffffffu;
				break;
			case 9:
				((wri_crush *)(void *)(h.p + w->crush_off))->bytes = 4;
				break;
			case 10:
				w->bytes = w->cap + 1u;
				break;
			case 11:
				w->bytes = 8;
				break;
			default:
				break;
			}
			if (f >= 12) { /* the tables: a size above the carved room, and each of the three arrays out of the slot */
				k = (f - 12u) / 4u;
				if (w->tab[k].n == 0)
					continue;
				switch ((f - 12u) % 4u) {
				case 0:
					w->tab[k].n = w->tab[k].cap_n + 1u;
					break;
				case 1:
					w->tab[k].key_off = bytes;
					break;
				case 2:
					w->tab[k].off_off = bytes;
					break;
				default:
					w->tab[k].val_off = bytes;
					break;
				}
			}
			WRT_CHECK_STATUS(WR_E_INVAL, wri_osdmap_apply_inc(&cfg, w, b.p, b.len, dst.p, dst.cap, &why));
		}
		/* a held map without a CRUSH region: only an incremental that brings one can be applied to it */
		memcpy(h.p, src, bytes);
		w->crush_off = 0;
		WRT_CHECK_STATUS(WR_E_MAP_CORRUPT, wri_osdmap_apply_inc(&cfg, w, b.p, b.len, dst.p, dst.cap, &why));
		islot_free(&h);
		wrt_mg_buf_free(&b);
		wrt_mg_inc_free(&inc);
		/* a length that cannot be an incremental is refused before a byte of it is read */
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_osdmap_apply_inc(&cfg, src, dst.p, 0x80000000u, dst.p, dst.cap, &why));
	}
	islot_free(&dst);
	rig_end(&g);
}

/* ---- budgets: every section, and every truncation and mutation ---------------------------------------------- */

/* A busy incremental: flags, resize, weights, affinity, state, up, every table, a pool record, a removal. */
static void rich_inc(rig *g, wrt_mg_inc *inc, int with_crush)
{
	wrt_mg_addrvec av;
	const int32_t v[3] = {3, 1, 2};
	const int32_t f[4] = {0, 3, 1, 2};

	new_inc(g, inc);
	inc->new_flags = 0x1000;
	inc->new_max_osd = 11;
	wrt_mg_inc_set_weight(inc, 8, 0x10000);
	wrt_mg_inc_set_weight(inc, 1, 0x4000);
	wrt_mg_inc_set_affinity(inc, 2, 0x100);
	wrt_mg_inc_set_affinity(inc, 10, 0xff00);
	put_state(inc, 0, 0);
	put_state(inc, 3, 1);
	av_v4(&av, 88, 6999, 88);
	wrt_mg_inc_mark_up(inc, 3, &av);
	wrt_mg_inc_mark_up(inc, 9, &av);
	add_pg_list(&inc->new_pg_temp, 1, 0, v, 3);
	add_pg_list(&inc->new_pg_temp, 1, 5, v, 2);
	add_pg_list(&inc->new_pg_temp, 2, 2, NULL, 0);
	add_pg_osd(&inc->new_primary_temp, 1, 1, 2);
	add_pg_list(&inc->new_pg_upmap, 1, 2, v, 3);
	add_pg(&inc->old_pg_upmap, 2, 2);
	add_pg_items(&inc->new_pg_upmap_items, 1, 4, f, 2);
	add_pg_osd(&inc->new_pg_upmap_primary, 2, 4, 1);
	put_pool(inc, 2, NULL, 40, 0);
	put_pool(inc, 3, NULL, 8, 0);
	if (with_crush) {
		wrt_mg_crush cr;
		const int32_t items[2] = {0, 1};

		wrt_mg_crush_init(&cr);
		WRT_CHECK(wrt_mg_crush_add_bucket(&cr, -1, 11, WRT_MG_ALG_STRAW2, items, NULL, 2) == 0);
		{
			wrt_mg_step st[3] = {{WRT_MG_OP_TAKE, -1, 0}, {WRT_MG_OP_CHOOSE_FIRSTN, 0, 0}, {WRT_MG_OP_EMIT, 0, 0}};

			WRT_CHECK(wrt_mg_crush_add_rule(&cr, 0, 1, st, 3) == 0);
		}
		wrt_mg_crush_recount(&cr);
		wrt_mg_inc_set_crush(inc, &cr);
		wrt_mg_crush_free(&cr);
	}
}

static void budget_sweep(const rig *g, const uint8_t *blob, size_t n)
{
	islot big, s;
	wri_mapcfg cfg = g->cfg;
	wr_errinfo why = { 0 };
	const wri_osdmap *m;
	size_t caps[96], nc = 0, i, used, k;
	uint32_t sec[40], ns = 0;

	islot_new(&big, RIG_SLOT_BYTES);
	WRT_CHECK_STATUS(WR_OK, rig_apply(&cfg, rig_held(g), blob, n, &big, &why));
	m = islot_map(&big);
	used = m->bytes;
	sec[ns++] = m->state_off;
	sec[ns++] = m->weight_off;
	sec[ns++] = m->aff_off;
	sec[ns++] = m->addr_off;
	sec[ns++] = m->pool_off;
	sec[ns++] = m->crush_off;
	for (k = 0; k < WRI_TAB_COUNT; k++) {
		sec[ns++] = m->tab[k].key_off;
		sec[ns++] = m->tab[k].off_off;
		sec[ns++] = m->tab[k].val_off;
	}
	caps[nc++] = 0;
	caps[nc++] = 1;
	caps[nc++] = 3;
	caps[nc++] = 4;
	caps[nc++] = 8;
	caps[nc++] = sizeof(wri_osdmap) - 1u;
	caps[nc++] = sizeof(wri_osdmap);
	caps[nc++] = sizeof(wri_osdmap) + 1u;
	for (i = 0; i < ns; i++) {
		if (sec[i] == 0 || nc + 3 > sizeof(caps) / sizeof(caps[0]))
			continue;
		caps[nc++] = sec[i] - 1u;
		caps[nc++] = sec[i];
		caps[nc++] = (size_t)sec[i] + 1u;
	}
	for (i = 1; i <= 8 && nc + 2 <= sizeof(caps) / sizeof(caps[0]); i++)
		caps[nc++] = used * i / 9u;
	caps[nc++] = used - 1u;
	for (i = 0; i < nc; i++) {
		wr_status st;

		if (caps[i] >= used)
			continue;
		cfg.slot_bytes = (uint32_t)caps[i];
		islot_new(&s, caps[i]);
		st = rig_apply(&cfg, rig_held(g), blob, n, &s, &why);
		if (st != WR_E_MAP_BUDGET)
			fprintf(stderr, "  cap %zu of %zu: status %d\n", caps[i], used, (int)st);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, st);
		islot_free(&s);
	}
	/* exactly the size: the same map (only the `cap` field of the header differs) */
	cfg.slot_bytes = (uint32_t)used;
	islot_new(&s, used);
	WRT_CHECK_STATUS(WR_OK, rig_apply(&cfg, rig_held(g), blob, n, &s, &why));
	WRT_CHECK(memcmp(s.p, big.p, 8) == 0 && memcmp(s.p + 12, big.p + 12, used - 12u) == 0);
	islot_free(&s);
	islot_free(&big);
}

static void test_budget(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_buf b;
	int with_crush;

	start(&g, 8, 1, 24);
	for (with_crush = 0; with_crush <= 1; with_crush++) { /* the held region copied, a new one decoded */
		rich_inc(&g, &inc, with_crush);
		memset(&b, 0, sizeof(b));
		WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
		budget_sweep(&g, b.p, b.len);
		wrt_mg_buf_free(&b);
		wrt_mg_inc_free(&inc);
	}
	/* an embedded full map */
	{
		wrt_mg_map nm;

		mk_desc(&nm, 9, 1, 79);
		memcpy(nm.fsid, g.model.fsid, 16);
		nm.epoch = g.model.epoch + 1u;
		new_inc(&g, &inc);
		wrt_mg_inc_set_fullmap(&inc, &nm);
		memset(&b, 0, sizeof(b));
		WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
		budget_sweep(&g, b.p, b.len);
		wrt_mg_buf_free(&b);
		wrt_mg_inc_free(&inc);
		wrt_mg_map_free(&nm);
	}
	rig_end(&g);
}

/* Every truncation of a busy incremental is refused (the wrapper claims more than there is); every single-byte mutation either
 * applies to a map that passes the structural check or is refused with a map status, never anything else (rig_apply checks). */
static void test_sweeps(void)
{
	rig g;
	wrt_mg_inc inc;
	wrt_mg_buf b;
	islot dst;
	size_t k;
	unsigned pass;
	wr_errinfo why = { 0 };
	wri_mapcfg off;

	start(&g, 8, 0, 25);
	off = g.cfg;
	off.verify_crc = 0;
	rich_inc(&g, &inc, 1);
	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(&inc, &b) == 0);
	islot_new(&dst, 64u * 1024u);
	for (k = 0; k < b.len; k++) {
		WRT_CHECK(rig_apply(&g.cfg, rig_held(&g), b.p, k, &dst, &why) != WR_OK);
		WRT_CHECK(rig_apply(&off, rig_held(&g), b.p, k, &dst, &why) != WR_OK);
	}
	for (pass = 0; pass < 3; pass++) {
		static const uint8_t flips[3] = {0x01, 0x80, 0xff};
		unsigned accepted = 0;

		for (k = 0; k < b.len; k++) {
			uint8_t *c = rig_dup(b.p, b.len);

			c[k] ^= flips[pass];
			if (rig_apply(&off, rig_held(&g), c, b.len, &dst, &why) == WR_OK)
				accepted++;
			/* with the CRC recomputed, so the mutation reaches the parsers when the envelopes still nest */
			if (wrt_mg_fix_crc(c, b.len, 1) == 0)
				(void)rig_apply(&g.cfg, rig_held(&g), c, b.len, &dst, &why);
			free(c);
		}
		WRT_CHECK(accepted > 0); /* some bytes (modified, features, unused rows) change nothing the client keeps */
	}
	islot_free(&dst);
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(&inc);
	rig_end(&g);
}

int main(void)
{
	test_basics();
	test_resize();
	test_osd_ids();
	test_weights_affinity();
	test_state();
	test_up_addresses();
	test_tables_merge();
	test_tables_long();
	test_pools_basic();
	test_pools_names();
	test_pools_status();
	test_pools_huge_ids();
	test_crush_copy();
	test_identity();
	test_envelope();
	test_unsorted();
	test_skipped_rows();
	test_random_chains();
	test_arguments();
	test_budget();
	test_sweeps();
	return wrt_finish();
}
