/* SPDX-License-Identifier: MIT */
/*
 * test_map_vec_place.c - object names and CRUSH mappings of the committed vectors through the real decoding path of the core.
 *
 * Object names (bytes, hex in the vectors, including the CESU-8 case: a character above U+FFFF is two 3-byte surrogates, which is
 * what Ceph's monitor hashed) are hashed by wri_place_hash, folded into a PG by wri_place_pg_seed and mapped by wri_place_pg on a
 * map that wri_osdmap_decode_full / wri_osdmap_apply_inc built from the bytes of the capture:
 *
 *   osdmap/placement-names-e42.json        219 names   \
 *   crush/placement-expected.json          137 names    } the map of epoch 42, rebuilt from incrementals 1 .. 89 (epoch 1 = the
 *   crush/mosdop-targets.json              40 frames   /  full map inside incremental 1): hash, PG, up / acting sets, primaries; for
 *                                                         the frames the hash and pg seed the stock client sent and the OSD it
 *                                                         connected to
 *   public/mapb/names/names-e709.json      3,352 names over 8 pools (power-of-two and not, pgp_num below pg_num, a pool without
 *                                          HASHPSPOOL, namespaces, 0 to 4096 bytes, CESU-8), asked at epoch 709 of the chain
 *                                          base-e666 + incrementals 667 .. 709
 *   public/mapb/answers.json               58 answers of `ceph osd map` for names that fall into a PG with an override (pg_upmap,
 *                                          pg_upmap_items with valid and invalid pairs, pg_upmap_primaries, a choose_args weight
 *                                          set), each at the epoch of its answer
 *
 * CRUSH, the rule interpreter on the compact region the decoders build (crushtool --test --show-mappings is the oracle):
 *
 *   osdmap/crush-mappings.json             4 sets x 300 x on the lab map (rules 0 and 1, 1 to 3 replicas, with and without the pool-id hash)
 *   crush/crushtool-mappings.json          8 runs x 64 x on the getcrushmap blob
 *   public/mapb/crush/cm*.mappings.json    130 runs x 48 x on 18 maps: every bucket algorithm, five tunable profiles, devices out or at
 *                                          half weight, chooseleaf over hosts and racks, device classes, choose_args keys 0 / 1 / -1
 *   Where the core refuses a run (a tree bucket, which it does not implement, or a rule that is not replicated firstn) the status must
 *   be the documented one and the map must show the reason; every other run must agree with crushtool.
 *
 * The first mismatch stops the run and prints the vector set, state, pool, object bytes or x, and both answers.
 */
#include "map_vec_rig.h"

/* ---- CRUSH regions ------------------------------------------------------------------------------------------------------ */

typedef struct cregion {
	uint8_t *mem;
	size_t used;
	const wri_crush *c;
} cregion;

static void cr_load(cregion *r, const char *rel)
{
	uint8_t *blob = NULL;
	size_t n = 0, cap;
	wr_errinfo why;
	wr_status st;

	mv_load_hex(rel, &blob, &n);
	cap = n * 4u + 65536u;
	r->mem = (uint8_t *)malloc(cap);
	if (r->mem == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(&why, 0, sizeof(why));
	st = wri_crush_decode(blob, n, r->mem, cap, &r->used, &why);
	if (st != WR_OK) {
		fprintf(stderr, "map-vectors: %s does not decode: %s\n", rel, why.what != NULL ? why.what : wrt_status_name_(st));
		mv_die();
	}
	r->c = (const wri_crush *)(const void *)r->mem;
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(r->c, r->used));
	free(blob);
}

static void cr_free(cregion *r)
{
	free(r->mem);
	r->mem = NULL;
}

static int rule_has_indep(const wri_crush *c, uint32_t rule)
{
	const wri_crule *r = wri_crush_rule(c, rule);
	uint32_t i;

	for (i = 0; r != NULL && i < r->nsteps; i++)
		if (wri_crule_steps(r)[i].op == WRI_CRUSH_OP_CHOOSE_INDEP || wri_crule_steps(r)[i].op == WRI_CRUSH_OP_CHOOSELEAF_INDEP)
			return 1;
	return 0;
}

static int has_alg(const wri_crush *c, unsigned alg)
{
	uint32_t i;

	for (i = 0; i < c->max_buckets; i++) {
		const wri_cbucket *b = wri_crush_bucket_at(c, i);

		if (b != NULL && b->alg == alg)
			return 1;
	}
	return 0;
}

typedef struct cr_tally {
	uint32_t compared;   /* mappings that agree with crushtool */
	uint32_t no_rule;    /* refused: the rule is not a replicated one */
	uint32_t unsupported; /* refused: a tree bucket, or an indep step */
	uint32_t runs;
} cr_tally;

/* One crushtool mapping. `x_in` is crushtool's x, `x` what the interpreter gets (hash2(x, pool) when --pool-id was given). */
static void cr_one(const char *set, const char *map, const char *run, const cregion *r, uint32_t rule, uint32_t x_in, uint32_t x, uint32_t nrep,
		   const uint32_t *w, uint32_t wmax, const wrt_json *j, wrt_tok want, cr_tally *t)
{
	wri_crush_in in;
	wri_crush_ws ws;
	int32_t got[WRI_CRUSH_RESULT_MAX];
	uint32_t ng = 0;
	wr_errinfo why;
	wr_status st;
	char a[160], b[160];

	memset(&ws, 0, sizeof(ws));
	memset(&why, 0, sizeof(why));
	ws.work = MV_WORK_MAX;
	in.rule = rule;
	in.x = x;
	in.result_max = nrep;
	in.osd_weight = w;
	in.weight_max = wmax;
	in.args_pool = 0; /* crushtool --test asks for choose_args key 0, then -1, whatever --pool-id says */
	st = wri_crush_do_rule(r->c, &in, &ws, got, &ng, &why);
	wrt_checks++;
	if (st == WR_OK) {
		if (ng > nrep) { /* the mapper must never return more than the caller's room */
			fprintf(stderr, "MISMATCH %s: map %s, run %s: rule %u, x %u: %u results for room of %u\n", set, map, run, (unsigned)rule, (unsigned)x_in,
				(unsigned)ng, (unsigned)nrep);
			mv_die();
		}
		if (!mv_jlist_eq(j, want, got, ng)) {
			mv_fmt_jlist(a, sizeof(a), j, want);
			mv_fmt_list(b, sizeof(b), got, ng);
			fprintf(stderr, "MISMATCH %s: map %s, run %s: rule %u, x %u (crush input %u), %u replicas: crushtool [%s], core [%s]\n", set, map, run, (unsigned)rule,
				(unsigned)x_in, (unsigned)x, (unsigned)nrep, a, b);
			mv_die();
		}
		t->compared++;
		return;
	}
	if (st == WR_E_CRUSH_NO_RULE && wri_crush_rule_kind(r->c, rule) != 2u) {
		t->no_rule++;
		return;
	}
	if (st == WR_E_CRUSH_UNSUPPORTED && (has_alg(r->c, WRI_CRUSH_ALG_TREE) || rule_has_indep(r->c, rule))) {
		t->unsupported++;
		return;
	}
	mv_fmt_jlist(a, sizeof(a), j, want);
	fprintf(stderr, "MISMATCH %s: map %s, run %s: rule %u, x %u, %u replicas: the core refused with %d (%s: %s) and the map shows no reason; crushtool [%s]\n", set,
		map, run, (unsigned)rule, (unsigned)x_in, (unsigned)nrep, (int)st, wrt_status_name_(st), why.what != NULL ? why.what : "?", a);
	mv_die();
}

/* osdmap/crush-mappings.json {"sets": {name: {rule, num_rep, pool_id_hash, mappings: [[x, [osds]], ...]}}} on `c`, all devices in. */
static void cr_set1_sets(const wri_crush *c_in, const char *set, cr_tally *t)
{
	wrt_json j;
	wrt_tok sets;
	size_t i, k;
	cregion r;
	uint32_t w[8] = {0x10000u, 0x10000u, 0x10000u, 0x10000u, 0x10000u, 0x10000u, 0x10000u, 0x10000u};

	mv_load_json(&j, "osdmap/crush-mappings.json");
	sets = wrt_json_get(&j, wrt_json_root(&j), "sets");
	r.mem = NULL;
	r.used = 0;
	r.c = c_in;
	WRT_CHECK(c_in->max_devices == 3);
	for (i = 0; i < wrt_json_count(&j, sets); i++) {
		wrt_tok v, mp;
		const char *name = wrt_json_key_at(&j, sets, i, &v);
		uint32_t rule = (uint32_t)mv_int(&j, wrt_json_get(&j, v, "rule")), nrep = (uint32_t)mv_int(&j, wrt_json_get(&j, v, "num_rep"));
		int ok;
		uint32_t pool = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, v, "pool_id_hash"), &ok);

		mp = wrt_json_get(&j, v, "mappings");
		for (k = 0; k < wrt_json_count(&j, mp); k++) {
			wrt_tok row = wrt_json_at(&j, mp, k);
			uint32_t x = (uint32_t)mv_int(&j, wrt_json_at(&j, row, 0));

			cr_one(set, "epoch-42 lab map", name, &r, rule, x, ok ? wri_crush_hash2(x, pool) : x, nrep, w, 3, &j, wrt_json_at(&j, row, 1), t);
		}
		t->runs++;
	}
	wrt_json_free(&j);
}

/* crush/crushtool-mappings.json {"runs": {name: {rule, num_rep, pool_id_hash2_applied_by_tool, device_weights, x_to_result}}}, x = 0 .. 63. */
static void cr_set1_runs(const wri_crush *c_in, const char *set, cr_tally *t)
{
	wrt_json j;
	wrt_tok runs;
	size_t i, k;
	cregion r;

	mv_load_json(&j, "crush/crushtool-mappings.json");
	runs = wrt_json_get(&j, wrt_json_root(&j), "runs");
	r.mem = NULL;
	r.used = 0;
	r.c = c_in;
	for (i = 0; i < wrt_json_count(&j, runs); i++) {
		wrt_tok v, xr, dw;
		const char *name = wrt_json_key_at(&j, runs, i, &v);
		uint32_t rule = (uint32_t)mv_int(&j, wrt_json_get(&j, v, "rule")), nrep = (uint32_t)mv_int(&j, wrt_json_get(&j, v, "num_rep")), w[8];
		int ok;
		uint32_t pool = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, v, "pool_id_hash2_applied_by_tool"), &ok);

		dw = wrt_json_get(&j, v, "device_weights");
		xr = wrt_json_get(&j, v, "x_to_result");
		WRT_CHECK(wrt_json_count(&j, dw) == 3);
		for (k = 0; k < 3; k++)
			w[k] = (uint32_t)mv_int(&j, wrt_json_at(&j, dw, k));
		for (k = 0; k < wrt_json_count(&j, xr); k++)
			cr_one(set, "getcrushmap of epoch 42", name, &r, rule, (uint32_t)k, ok ? wri_crush_hash2((uint32_t)k, pool) : (uint32_t)k, nrep, w, 3, &j,
			       wrt_json_at(&j, xr, k), t);
		t->runs++;
	}
	wrt_json_free(&j);
}

/* ---- the first set, names and mappings on the map of epoch 42 -------------------------------------------------------------- */

typedef struct set1 {
	cregion blob;
	mv_tally t;
	cr_tally c;
	unsigned at42;
} set1;

static void set1_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	set1 *s = (set1 *)user;
	const wri_crush *mc;

	(void)cfg;
	if (epoch != 42)
		return;
	s->at42++;
	/* the names of the three vector files, on the map the chain built */
	mv_names_e42(m, "osdmap chain 1..42: names", &s->t);
	/* the CRUSH region the chain holds is the one decoding the monitor's blob gives, and it answers crushtool's questions */
	mc = wri_map_crush(m);
	WRT_CHECK(mc != NULL);
	if (mc == NULL)
		return;
	WRT_CHECK_U64(mc->bytes, s->blob.used);
	if (mc->bytes == s->blob.used)
		WRT_CHECK_MEM(mc, s->blob.mem, s->blob.used);
	cr_set1_sets(mc, "osdmap chain 1..42: osdmap/crush-mappings.json", &s->c);
	cr_set1_runs(mc, "osdmap chain 1..42: crush/crushtool-mappings.json", &s->c);
}

static void test_set1(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	set1 s;
	cregion getcrush, incform, in_osdmap;

	memset(&s, 0, sizeof(s));
	cr_load(&s.blob, "osdmap/crush-embedded.hex");
	cr_load(&getcrush, "crush/crush-getcrushmap.hex");
	cr_load(&incform, "osdmap/crush-incremental-form.hex");
	cr_load(&in_osdmap, "crush/crush-embedded-in-osdmap.hex");
	/* four encodings of the same map (the two forms differ in the MSR tunable pair, which the compact format does not keep) */
	WRT_CHECK_U64(getcrush.used, s.blob.used);
	WRT_CHECK_U64(incform.used, s.blob.used);
	WRT_CHECK_U64(in_osdmap.used, s.blob.used);
	if (getcrush.used == s.blob.used && incform.used == s.blob.used && in_osdmap.used == s.blob.used) {
		WRT_CHECK_MEM(getcrush.mem, s.blob.mem, s.blob.used);
		WRT_CHECK_MEM(incform.mem, s.blob.mem, s.blob.used);
		WRT_CHECK_MEM(in_osdmap.mem, s.blob.mem, s.blob.used);
	}
	cr_set1_sets(getcrush.c, "crush/crush-getcrushmap.hex: osdmap/crush-mappings.json", &s.c);
	cr_set1_runs(getcrush.c, "crush/crush-getcrushmap.hex: crush/crushtool-mappings.json", &s.c);
	mv_replay_set1(names, 2, set1_epoch, &s);
	WRT_CHECK_U64(s.at42, 1);
	WRT_CHECK_U64(s.t.names, 219 + 137 + 40);
	WRT_CHECK_U64(s.t.toobig, 0);
	WRT_CHECK_U64(s.c.runs, 2u * (4u + 8u));
	WRT_CHECK_U64(s.c.compared, 2u * (4u * 300u + 8u * 64u)); /* the lab map has only straw2 buckets and replicated rules: nothing is refused */
	WRT_CHECK_U64(s.c.no_rule + s.c.unsupported, 0);
	fprintf(stderr, "epoch 42: %u object answers compared (names of osdmap/ and crush/, MOSDOp frames); %u CRUSH mappings compared (%u runs, blob and chain)\n",
		s.t.names, s.c.compared, s.c.runs);
	cr_free(&s.blob);
	cr_free(&getcrush);
	cr_free(&incform);
	cr_free(&in_osdmap);
}

/* ---- the second set: names of epoch 709 and the answers of overrides ------------------------------------------------------ */

typedef struct mapb_names {
	wrt_json names, answers;
	uint32_t names_epoch, name_rows, answer_rows;
	wrt_tok ans;
	mv_tally t;
	unsigned at_names_epoch;
} mapb_names;

static void mapb_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	mapb_names *s = (mapb_names *)user;
	size_t k;
	mv_ctx cx;

	(void)cfg;
	if (epoch == s->names_epoch) {
		cx.set = "public/mapb/names/names-e709.json";
		cx.label = "s00-base-pools";
		cx.epoch = epoch;
		mv_name_file(&cx, m, &s->names, 0, &s->t);
		s->at_names_epoch++;
	}
	/* the answers of `ceph osd map` right after an override was set: [label, epoch, pool, ...] */
	for (k = 0; k < wrt_json_count(&s->answers, s->ans); k++) {
		wrt_tok row = wrt_json_at(&s->answers, s->ans, k);
		char *label;

		if ((uint32_t)mv_int(&s->answers, wrt_json_at(&s->answers, row, 1)) != epoch)
			continue;
		label = wrt_json_strdup(&s->answers, wrt_json_at(&s->answers, row, 0));
		cx.set = "public/mapb/answers.json";
		cx.label = label != NULL ? label : "?";
		cx.epoch = epoch;
		mv_name_row(&cx, m, &s->answers, row, 2, &s->t);
		free(label);
	}
}

static void test_mapb_names(void)
{
	static const struct {
		const char *const *names;
		unsigned n;
	} chains[2] = {{mv_set_a, MV_SET_A_N}, {mv_set_b, MV_SET_B_N}}; /* the pools 2, 42 .. 55 (the erasure pool has no names asked) */
	mapb_names s;
	unsigned c;
	int64_t pool_ids[16];
	unsigned n_pools = 0, q;
	size_t i;

	memset(&s, 0, sizeof(s));
	mv_load_json(&s.names, "public/mapb/names/names-e709.json");
	mv_load_json(&s.answers, "public/mapb/answers.json");
	s.names_epoch = (uint32_t)mv_int(&s.names, wrt_json_get(&s.names, wrt_json_root(&s.names), "epoch"));
	s.ans = wrt_json_get(&s.answers, wrt_json_root(&s.answers), "entries");
	s.name_rows = (uint32_t)wrt_json_count(&s.names, wrt_json_get(&s.names, wrt_json_root(&s.names), "entries"));
	s.answer_rows = (uint32_t)wrt_json_count(&s.answers, s.ans);
	WRT_CHECK_U64(s.name_rows, 3352);
	WRT_CHECK_U64(s.answer_rows, 58);
	for (i = 0; i < s.name_rows; i++) { /* the pools of the oracle: 8 of them */
		int64_t id = mv_int(&s.names, wrt_json_at(&s.names, wrt_json_at(&s.names, wrt_json_get(&s.names, wrt_json_root(&s.names), "entries"), i), 0));

		for (q = 0; q < n_pools && pool_ids[q] != id; q++)
			;
		if (q == n_pools && n_pools < 16u)
			pool_ids[n_pools++] = id;
	}
	WRT_CHECK_U64(n_pools, 8);
	for (c = 0; c < 2; c++)
		mv_replay_mapb(chains[c].names, chains[c].n, mapb_epoch, &s);
	WRT_CHECK_U64(s.at_names_epoch, 2);
	/* every row was taken by one chain: the pools of the oracle are split between them */
	WRT_CHECK_U64(s.t.names, s.name_rows + s.answer_rows);
	WRT_CHECK(s.t.names >= 3000);
	fprintf(stderr, "public/mapb names: %u names of epoch 709 (8 pools) and %u override answers compared, %u of them hashed above the name cap\n", s.name_rows,
		s.answer_rows, s.t.toobig);
	wrt_json_free(&s.names);
	wrt_json_free(&s.answers);
}

/* ---- the second set: crushtool runs on the 18 offline CRUSH maps ----------------------------------------------------------- */

static void test_mapb_crush(void)
{
	wrt_json idx;
	wrt_tok crush;
	size_t i, k, e;
	cr_tally t;
	unsigned maps_with_tree = 0, algs_seen = 0;

	memset(&t, 0, sizeof(t));
	mv_load_json(&idx, "public/mapb/INDEX.json");
	crush = wrt_json_get(&idx, wrt_json_root(&idx), "crush");
	WRT_CHECK_U64(wrt_json_count(&idx, crush), 18);
	for (i = 0; i < wrt_json_count(&idx, crush); i++) {
		wrt_tok ent = wrt_json_at(&idx, crush, i);
		char *name = wrt_json_strdup(&idx, wrt_json_get(&idx, ent, "name")), *hexrel = wrt_json_strdup(&idx, wrt_json_get(&idx, ent, "crush"));
		char *mrel = wrt_json_strdup(&idx, wrt_json_get(&idx, ent, "mappings")), p1[300], p2[300];
		cregion r;
		wrt_json mj;
		wrt_tok runs;
		uint32_t nd;
		uint32_t *w;
		unsigned a;

		if (name == NULL || hexrel == NULL || mrel == NULL) {
			fprintf(stderr, "map-vectors: INDEX.json crush entry %u is incomplete\n", (unsigned)i);
			mv_die();
		}
		snprintf(p1, sizeof(p1), "public/mapb/%s", hexrel);
		snprintf(p2, sizeof(p2), "public/mapb/%s", mrel);
		cr_load(&r, p1);
		mv_load_json(&mj, p2);
		nd = (uint32_t)r.c->max_devices;
		w = (uint32_t *)malloc((nd + 1u) * sizeof(uint32_t));
		if (w == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		for (a = WRI_CRUSH_ALG_UNIFORM; a <= WRI_CRUSH_ALG_STRAW2; a++)
			algs_seen |= has_alg(r.c, a) ? 1u << a : 0u;
		maps_with_tree += has_alg(r.c, WRI_CRUSH_ALG_TREE) ? 1u : 0u;
		runs = wrt_json_get(&mj, wrt_json_root(&mj), "runs");
		for (k = 0; k < wrt_json_count(&mj, runs); k++) {
			wrt_tok v, xr, wm;
			const char *run = wrt_json_key_at(&mj, runs, k, &v);
			uint32_t rule = (uint32_t)mv_int(&mj, wrt_json_get(&mj, v, "rule")), nrep = (uint32_t)mv_int(&mj, wrt_json_get(&mj, v, "num_rep")), minx = 0, pool = 0, d;
			int ok;

			if (wrt_json_get(&mj, v, "min_x") != WRT_NONE)
				minx = (uint32_t)mv_int(&mj, wrt_json_get(&mj, v, "min_x"));
			pool = (uint32_t)wrt_json_int(&mj, wrt_json_get(&mj, v, "pool_id"), &ok);
			for (d = 0; d < nd; d++)
				w[d] = WRI_OSD_IN_FULL;
			wm = wrt_json_get(&mj, v, "weights");
			for (e = 0; wm != WRT_NONE && e < wrt_json_count(&mj, wm); e++) {
				wrt_tok val;
				const char *dev = wrt_json_key_at(&mj, wm, e, &val);
				int vok;
				int64_t iv = wrt_json_int(&mj, val, &vok);

				d = (uint32_t)strtoul(dev, NULL, 10);
				/* the files hold 0 (out) and 0.5 only (vectors_mapb_check pins that): a number that is not an integer is the half weight.
				 * A device the map does not have, or an integer other than 0, is a vector this test would silently weaken: stop. */
				if (d >= nd || (vok && iv != 0 && iv != 1) || !wrt_json_is_number(&mj, val)) {
					fprintf(stderr, "map-vectors: public/mapb/crush: map %s run %s: a weight override this test does not model (device %s)\n", name, run, dev);
					mv_die();
				}
				w[d] = vok ? (uint32_t)(iv * (int64_t)WRI_OSD_IN_FULL) : WRI_OSD_IN_FULL / 2u;
			}
			xr = wrt_json_get(&mj, v, "x_to_result");
			WRT_CHECK_U64(wrt_json_count(&mj, xr), 48);
			for (e = 0; e < wrt_json_count(&mj, xr); e++) {
				uint32_t x = minx + (uint32_t)e;

				cr_one("public/mapb/crush", name, run, &r, rule, x, ok ? wri_crush_hash2(x, pool) : x, nrep, w, nd, &mj,
				       wrt_json_at(&mj, xr, e), &t);
			}
			t.runs++;
		}
		free(w);
		wrt_json_free(&mj);
		cr_free(&r);
		free(name);
		free(hexrel);
		free(mrel);
	}
	WRT_CHECK_U64(t.runs, 130);
	WRT_CHECK_U64(t.compared + t.no_rule + t.unsupported, 130u * 48u);
	WRT_CHECK(t.compared >= 3000);
	/* every bucket algorithm is in the set of maps (uniform 1, list 2, tree 3, straw 4, straw2 5) */
	WRT_CHECK_U64(algs_seen, (1u << 1) | (1u << 2) | (1u << 3) | (1u << 4) | (1u << 5));
	WRT_CHECK(maps_with_tree >= 3);
	fprintf(stderr, "public/mapb/crush: %u runs on 18 maps: %u mappings agree with crushtool, %u refused for a tree bucket or an indep step, %u for a rule that is not replicated\n",
		t.runs, t.compared, t.unsupported, t.no_rule);
	wrt_json_free(&idx);
}

int main(void)
{
	test_set1();
	test_mapb_names();
	test_mapb_crush();
	return wrt_finish();
}
