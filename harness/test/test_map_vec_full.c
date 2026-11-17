/* SPDX-License-Identifier: MIT */
/*
 * test_map_vec_full.c - the committed vectors through wri_osdmap_decode_full: real full maps of a Ceph cluster, decoded by the core
 * and nothing else (no model between the bytes and the answer), then asked the placement questions Ceph answered for the same map.
 *
 *   osdmap/full-e42.hex                    the first lab set's map of epoch 42, decoded with two orders of tracked names; its PG
 *                                          table (placement-states.json, state e42), the 219 + 137 object answers of
 *                                          placement-names-e42.json / crush/placement-expected.json and the 40 MOSDOp frames of
 *                                          crush/mosdop-targets.json; and equal to what the incrementals 1 .. 42 build
 *   public/mapb/maps/e<epoch>.hex          the 21 monitor maps of the second set: each is decoded directly, equal to the chain of
 *                                          incrementals at that epoch, compared with `ceph osd dump` of the epoch, and its PG
 *                                          table of the state is checked (three tracked-name sets cover the 16 pools)
 *   public/mapb/maps/e709.hex              decoded directly and asked the 3,352 object answers of names/names-e709.json
 *                                          (8 pools, CESU-8 names, namespaces, pg_num 7 / 12 / 8 with pgp_num below it, a legacy pool)
 *   public/mapb/offline/om*.osdmap.hex     eight OSDMaps made by osdmaptool with every bucket algorithm, tunables of five releases,
 *                                          device classes, choose_args, OSDs out / down / reweighted: decoded, the OSD states checked
 *                                          against the capture's patch list, and their PG tables compared; a pool whose rule needs a
 *                                          tree bucket must be refused with CRUSH_UNSUPPORTED (and the map must really hold one)
 *
 * The first mismatch stops the run and prints the vector set, state, pool, PG or object bytes, and both answers.
 */
#include "map_vec_rig.h"

/* ---- the first set: the map of epoch 42 ----------------------------------------------------------------------------------- */

typedef struct set1 {
	uint8_t *full;
	size_t full_n;
	mv_tally t;
	unsigned compared_with_chain;
} set1;

/* At epoch 42 of the chain of incrementals: the real full map decodes to the same compact map. */
static void set1_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	set1 *s = (set1 *)user;
	islot real;
	wr_errinfo why;

	if (epoch != 42)
		return;
	if (mv_decode_one(cfg, s->full, s->full_n, &real, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: osdmap/full-e42.hex does not decode: %s\n", why.what != NULL ? why.what : "?");
		mv_die();
	}
	rig_cmp_core(m, islot_map(&real));
	s->compared_with_chain++;
	islot_free(&real);
}

static void test_set1(void)
{
	static const char *const order_a[] = {".mgr", "winrbd"};
	static const char *const order_b[] = {"winrbd", "no-such-pool", ".mgr"};
	set1 s;
	wrt_json states;
	wrt_tok obj;
	unsigned pass;
	size_t k;

	memset(&s, 0, sizeof(s));
	mv_load_hex("osdmap/full-e42.hex", &s.full, &s.full_n);
	mv_load_json(&states, "osdmap/placement-states.json");
	obj = wrt_json_get(&states, wrt_json_root(&states), "states");

	for (pass = 0; pass < 2; pass++) {
		/* the tracked names in another order, with a name the map does not have: the indexes move, the answers do not */
		wri_mapcfg cfg;
		islot slot;
		wr_errinfo why;
		mv_tally t;
		const wri_osdmap *m;
		mv_ctx cx;
		unsigned found = 0;

		memset(&t, 0, sizeof(t));
		if (pass == 0)
			rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, order_a, 2);
		else
			rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, order_b, 3);
		if (mv_decode_one(&cfg, s.full, s.full_n, &slot, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: osdmap/full-e42.hex does not decode: %s\n", why.what != NULL ? why.what : "?");
			mv_die();
		}
		m = islot_map(&slot);
		WRT_CHECK_U64(m->epoch, 42);
		WRT_CHECK_U64(m->max_osd, 3);
		WRT_CHECK_U64(m->n_up, 3);
		/* the PG table of the state at epoch 42 */
		cx.set = "osdmap/full-e42.hex";
		for (k = 0; k < wrt_json_count(&states, obj); k++) {
			wrt_tok sv;
			const char *label = wrt_json_key_at(&states, obj, k, &sv);
			wrt_tok pgs;

			if (mv_int(&states, wrt_json_get(&states, sv, "epoch")) != 42)
				continue;
			cx.label = label;
			cx.epoch = 42;
			pgs = wrt_json_get(&states, sv, "pgs");
			WRT_CHECK_U64(mv_table(&cx, m, &states, pgs, WRT_NONE, &t), wrt_json_count(&states, pgs));
			found++;
		}
		WRT_CHECK_U64(found, 1);
		mv_names_e42(m, "osdmap/full-e42.hex", &t);
		WRT_CHECK_U64(t.names, 219 + 137 + 40); /* every object of the three sets was asked and answered */
		WRT_CHECK_U64(t.pgs, 33 + 219 + 137);   /* the 33 PGs of the state and the PG of each of the 356 hashed objects */
		WRT_CHECK_U64(t.toobig, 0);
		WRT_CHECK_U64(t.refused, 0);
		if (pass == 0)
			s.t = t;
		islot_free(&slot);
	}
	mv_replay_set1(order_a, 2, set1_epoch, &s);
	WRT_CHECK_U64(s.compared_with_chain, 1);
	fprintf(stderr, "osdmap/full-e42.hex: %u PGs compared (33 table rows, %u object answers), equal to the chain of incrementals 1..42\n", s.t.pgs, s.t.names);
	free(s.full);
	wrt_json_free(&states);
}

/* ---- the second set: the 21 monitor maps -------------------------------------------------------------------------------- */

#define MAXST 80u

typedef struct mapb_full {
	wrt_json idx;
	wrt_json sj[MAXST];
	char label[MAXST][64];
	char map[MAXST][96]; /* "maps/e<epoch>.hex" or "" */
	uint32_t epoch[MAXST];
	uint32_t rows[MAXST], handled[MAXST];
	unsigned n, decoded;
	mv_tally t;
} mapb_full;

static void mapb_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	mapb_full *s = (mapb_full *)user;
	unsigned i;

	for (i = 0; i < s->n; i++) {
		mv_ctx cx;
		wrt_tok root, pgs, dump;
		uint8_t *bytes = NULL;
		size_t nb = 0;
		char rel[256];
		islot real;
		wr_errinfo why;

		if (s->epoch[i] != epoch || s->map[i][0] == 0)
			continue;
		snprintf(rel, sizeof(rel), "public/mapb/%s", s->map[i]);
		mv_load_hex(rel, &bytes, &nb);
		cx.set = "public/mapb/maps";
		cx.label = s->label[i];
		cx.epoch = epoch;
		if (mv_decode_one(cfg, bytes, nb, &real, &why) != WR_OK) {
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u): %s does not decode: %s\n", cx.set, cx.label, epoch, rel,
				why.what != NULL ? why.what : "?");
			mv_die();
		}
		WRT_CHECK_U64(islot_map(&real)->epoch, epoch);
		rig_cmp_core(m, islot_map(&real)); /* the chain of incrementals and the monitor's full map are the same compact map */
		root = wrt_json_root(&s->sj[i]);
		pgs = wrt_json_get(&s->sj[i], root, "pgs");
		dump = wrt_json_get(&s->sj[i], root, "dump");
		mv_check_dump(&cx, islot_map(&real), cfg, &s->sj[i], dump, &s->t);
		s->handled[i] += mv_table(&cx, islot_map(&real), &s->sj[i], pgs, dump, &s->t);
		s->decoded++;
		islot_free(&real);
		free(bytes);
	}
}

static void test_mapb_maps(void)
{
	static const struct {
		const char *const *names;
		unsigned n;
	} chains[3] = {{mv_set_a, MV_SET_A_N}, {mv_set_b, MV_SET_B_N}, {mv_set_c, MV_SET_C_N}};
	mapb_full *s = (mapb_full *)calloc(1, sizeof(*s));
	wrt_tok states;
	unsigned i, c, with_map = 0;
	uint32_t rows_with_map = 0;

	if (s == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	mv_load_json(&s->idx, "public/mapb/INDEX.json");
	states = wrt_json_get(&s->idx, wrt_json_root(&s->idx), "states");
	s->n = (unsigned)wrt_json_count(&s->idx, states);
	if (s->n > MAXST)
		mv_die();
	for (i = 0; i < s->n; i++) {
		wrt_tok e = wrt_json_at(&s->idx, states, i);
		char *label = wrt_json_strdup(&s->idx, wrt_json_get(&s->idx, e, "label")), *file = wrt_json_strdup(&s->idx, wrt_json_get(&s->idx, e, "file"));
		char *fm = wrt_json_strdup(&s->idx, wrt_json_get(&s->idx, e, "full_map"));
		char rel[256];

		if (label == NULL || file == NULL) {
			fprintf(stderr, "map-vectors: INDEX.json state %u has no label or file\n", i);
			mv_die();
		}
		snprintf(s->label[i], sizeof(s->label[i]), "%s", label);
		snprintf(s->map[i], sizeof(s->map[i]), "%s", fm != NULL ? fm : "");
		s->epoch[i] = (uint32_t)mv_int(&s->idx, wrt_json_get(&s->idx, e, "epoch"));
		snprintf(rel, sizeof(rel), "public/mapb/%s", file);
		mv_load_json(&s->sj[i], rel);
		s->rows[i] = (uint32_t)wrt_json_count(&s->sj[i], wrt_json_get(&s->sj[i], wrt_json_root(&s->sj[i]), "pgs"));
		with_map += fm != NULL;
		rows_with_map += fm != NULL ? s->rows[i] : 0u;
		free(label);
		free(file);
		free(fm);
	}
	WRT_CHECK_U64(with_map, 21);
	for (c = 0; c < 3; c++)
		mv_replay_mapb(chains[c].names, chains[c].n, mapb_epoch, s);
	WRT_CHECK_U64(s->decoded, 3u * with_map);
	for (i = 0; i < s->n; i++) {
		if (s->map[i][0] != 0 && s->handled[i] != s->rows[i]) {
			fprintf(stderr, "MISMATCH public/mapb/maps: state %s (epoch %u): %u of %u PG rows were handled\n", s->label[i], s->epoch[i],
				(unsigned)s->handled[i], (unsigned)s->rows[i]);
			mv_die();
		}
	}
	WRT_CHECK_U64(s->t.pgs + s->t.refused, rows_with_map);
	WRT_CHECK(s->t.pgs >= 600);
	fprintf(stderr, "public/mapb/maps: %u full maps decoded (x3 tracked-name sets), %u PGs compared, %u refused, %u osd-dump fields compared; each equal to the chain\n",
		with_map, s->t.pgs, s->t.refused, s->t.dumps);
	for (i = 0; i < s->n; i++)
		wrt_json_free(&s->sj[i]);
	wrt_json_free(&s->idx);
	free(s);
}

/* ---- the name oracle of epoch 709 on the monitor's own map -------------------------------------------------------------------- */

static void test_names_e709(void)
{
	/* the eight pools of the oracle (INDEX "names" pools), 2 = winrbd and 42 .. 48 = the test pools */
	static const char *const names[] = {"winrbd", "wrtest-mb-p16", "wrtest-mb-p12", "wrtest-mb-p7", "wrtest-mb-np", "wrtest-mb-leg", "wrtest-mb-s4", "wrtest-mb-host"};
	wrt_json oracle;
	uint8_t *bytes = NULL;
	size_t nb = 0;
	wri_mapcfg cfg;
	islot slot;
	wr_errinfo why;
	mv_ctx cx;
	mv_tally t;

	memset(&t, 0, sizeof(t));
	mv_load_json(&oracle, "public/mapb/names/names-e709.json");
	mv_load_hex("public/mapb/maps/e709.hex", &bytes, &nb);
	rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, names, 8);
	if (mv_decode_one(&cfg, bytes, nb, &slot, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: public/mapb/maps/e709.hex does not decode: %s\n", why.what != NULL ? why.what : "?");
		mv_die();
	}
	WRT_CHECK_U64(islot_map(&slot)->epoch, mv_int(&oracle, wrt_json_get(&oracle, wrt_json_root(&oracle), "epoch")));
	cx.set = "public/mapb/names/names-e709.json";
	cx.label = "s00-base-pools";
	cx.epoch = islot_map(&slot)->epoch;
	mv_name_file(&cx, islot_map(&slot), &oracle, 0, &t);
	WRT_CHECK_U64(t.names, wrt_json_count(&oracle, wrt_json_get(&oracle, wrt_json_root(&oracle), "entries")));
	WRT_CHECK_U64(t.other, 0);
	WRT_CHECK(t.names >= 3000);
	fprintf(stderr, "public/mapb/maps/e709.hex: %u object answers compared over 8 pools (%u of them above the name cap: the core refuses the hash call, the PG is compared from a hash built here)\n", t.names, t.toobig);
	islot_free(&slot);
	free(bytes);
	wrt_json_free(&oracle);
}

/* ---- the offline maps of osdmaptool -------------------------------------------------------------------------------------- */

/* Does the map's CRUSH hold a bucket of this algorithm? */
static int crush_has_alg(const wri_osdmap *m, unsigned alg)
{
	const wri_crush *c = wri_map_crush(m);
	uint32_t i;

	for (i = 0; c != NULL && i < c->max_buckets; i++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, i);

		if (b != NULL && b->alg == alg)
			return 1;
	}
	return 0;
}

/* The capture's patch of an offline map ({"down": [..], "out": [..], "reweight": {"<osd>": w16}}) against the decoded OSD arrays. */
static void check_patch(const mv_ctx *cx, const wri_osdmap *m, const wrt_json *j, wrt_tok patch)
{
	uint32_t i;
	size_t q;
	wrt_tok down = wrt_json_get(j, patch, "down"), out = wrt_json_get(j, patch, "out"), rew = wrt_json_get(j, patch, "reweight");

	for (i = 0; i < m->max_osd; i++) {
		int is_down = 0, is_out = 0;
		uint32_t want_w = WRI_OSD_IN_FULL;

		for (q = 0; down != WRT_NONE && q < wrt_json_count(j, down); q++)
			is_down |= mv_int(j, wrt_json_at(j, down, q)) == (int64_t)i;
		for (q = 0; out != WRT_NONE && q < wrt_json_count(j, out); q++)
			is_out |= mv_int(j, wrt_json_at(j, out, q)) == (int64_t)i;
		for (q = 0; rew != WRT_NONE && q < wrt_json_count(j, rew); q++) {
			wrt_tok v;
			const char *k = wrt_json_key_at(j, rew, q, &v);

			if ((uint32_t)strtoul(k, NULL, 10) == i)
				want_w = (uint32_t)mv_int(j, v);
		}
		if (is_out)
			want_w = 0;
		wrt_checks += 3;
		if (!wri_osd_exists(m, (int32_t)i) || (wri_osd_up(m, (int32_t)i) != 0) == (is_down != 0) || wri_osd_weight(m, (int32_t)i) != want_w) {
			fprintf(stderr, "MISMATCH %s: state %s: osd %u: exists %d up %d weight 0x%x; the capture says up %d weight 0x%x\n", cx->set, cx->label,
				(unsigned)i, wri_osd_exists(m, (int32_t)i), wri_osd_up(m, (int32_t)i), (unsigned)wri_osd_weight(m, (int32_t)i), !is_down,
				(unsigned)want_w);
			mv_die();
		}
	}
}

static void test_offline(void)
{
	static const char *const names[] = {"rbd"};
	wrt_json idx;
	wrt_tok maps;
	size_t i;
	unsigned compared_maps = 0, refused_maps = 0;
	mv_tally t;

	memset(&t, 0, sizeof(t));
	mv_load_json(&idx, "public/mapb/INDEX.json");
	maps = wrt_json_get(&idx, wrt_json_root(&idx), "osdmaps");
	WRT_CHECK_U64(wrt_json_count(&idx, maps), 8);
	for (i = 0; i < wrt_json_count(&idx, maps); i++) {
		wrt_tok e = wrt_json_at(&idx, maps, i);
		char *name = wrt_json_strdup(&idx, wrt_json_get(&idx, e, "name")), *hexrel = wrt_json_strdup(&idx, wrt_json_get(&idx, e, "osdmap"));
		char *pgrel = wrt_json_strdup(&idx, wrt_json_get(&idx, e, "pgs")), p1[300], p2[300];
		uint8_t *bytes = NULL;
		size_t nb = 0;
		wrt_json pj;
		wri_mapcfg cfg;
		islot slot;
		wr_errinfo why;
		const wri_osdmap *m;
		const wri_map_pool *pool;
		mv_ctx cx;
		wrt_tok pgs;

		if (name == NULL || hexrel == NULL || pgrel == NULL) {
			fprintf(stderr, "map-vectors: INDEX.json osdmaps entry %u is incomplete\n", (unsigned)i);
			mv_die();
		}
		snprintf(p1, sizeof(p1), "public/mapb/%s", hexrel);
		snprintf(p2, sizeof(p2), "public/mapb/%s", pgrel);
		mv_load_hex(p1, &bytes, &nb);
		mv_load_json(&pj, p2);
		rig_cfg(&cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, names, 1);
		if (mv_decode_one(&cfg, bytes, nb, &slot, &why) != WR_OK) {
			fprintf(stderr, "MISMATCH public/mapb/offline: %s does not decode: %s\n", name, why.what != NULL ? why.what : "?");
			mv_die();
		}
		m = islot_map(&slot);
		cx.set = "public/mapb/offline";
		cx.label = name;
		cx.epoch = m->epoch;
		pool = &wri_map_pools(m)[0];
		WRT_CHECK(pool->present && pool->id == 1);
		WRT_CHECK_U64(m->max_osd, 24);
		WRT_CHECK_U64(pool->pg_num, mv_int(&pj, wrt_json_get(&pj, wrt_json_root(&pj), "pg_num")));
		WRT_CHECK_U64(pool->size, mv_int(&pj, wrt_json_get(&pj, wrt_json_root(&pj), "pool_size")));
		check_patch(&cx, m, &pj, wrt_json_get(&pj, wrt_json_root(&pj), "patch"));
		pgs = wrt_json_get(&pj, wrt_json_root(&pj), "pgs");
		WRT_CHECK_U64(wrt_json_count(&pj, pgs), pool->pg_num);
		if (pool->status == WR_OK) {
			WRT_CHECK_U64(mv_table(&cx, m, &pj, pgs, WRT_NONE, &t), wrt_json_count(&pj, pgs));
			compared_maps++;
		} else {
			/* the core refuses this map's pool: that must be for a reason this core documents, and the map must show it */
			int justified = (pool->status == WR_E_CRUSH_UNSUPPORTED && crush_has_alg(m, WRI_CRUSH_ALG_TREE)) ||
					(pool->status == WR_E_CRUSH_NO_RULE && wri_crush_rule_kind(wri_map_crush(m), pool->crush_rule) != 2u);

			wrt_checks++;
			if (!justified) {
				fprintf(stderr, "MISMATCH public/mapb/offline: %s: pool refused with %d (%s) for no reason the map shows\n", name, (int)pool->status,
					wrt_status_name_(pool->status));
				mv_die();
			}
			/* refusing must be what a placement call does too, for every PG of the table */
			{
				size_t q;

				for (q = 0; q < wrt_json_count(&pj, pgs); q++) {
					wrt_tok v;
					const char *k = wrt_json_key_at(&pj, pgs, q, &v);
					uint64_t pl = 0;
					uint32_t seed = 0;
					wri_pg_result res;

					WRT_CHECK(mv_parse_pgid(k, &pl, &seed));
					WRT_CHECK_STATUS(pool->status, wri_place_pg(m, 0, seed, MV_WORK_MAX, &mv_ws, &res, NULL));
					WRT_CHECK_U64(res.n_acting, 0);
					t.refused++;
				}
			}
			refused_maps++;
		}
		fprintf(stderr, "  %s (%s): pool status %s\n", name, hexrel, wrt_status_name_(pool->status));
		islot_free(&slot);
		wrt_json_free(&pj);
		free(bytes);
		free(name);
		free(hexrel);
		free(pgrel);
	}
	fprintf(stderr, "public/mapb/offline: %u maps compared (%u PGs), %u refused for a tree bucket (%u PGs)\n", compared_maps, t.pgs, refused_maps, t.refused);
	WRT_CHECK(compared_maps >= 5);
	WRT_CHECK_U64(compared_maps + refused_maps, 8);
	wrt_json_free(&idx);
}

int main(void)
{
	test_set1();
	test_mapb_maps();
	test_names_e709();
	test_offline();
	return wrt_finish();
}
