/* SPDX-License-Identifier: MIT */
/*
 * test_place_real.c - the placement pipeline against what Ceph itself answered (the committed lab vectors).
 *
 * The map states are rebuilt by the wrt_mapgen reader and model (no code of the core): a full map, then every
 * incremental in order. At each epoch a vector names, the state goes into a compact slot (place_rig.h, with its CRUSH
 * region decoded by the core) and wri_place_pg must give, for every PG the vector lists, the five columns of
 * `osdmaptool --test-map-pgs-dump-all` (raw, up, up primary, acting, acting primary); for every object name of an oracle
 * (`ceph osd map`) the hash, the PG and the sets. Together they cover reweights, primary affinity, pg_upmap, pg_upmap_items,
 * pg_upmap_primaries, pg_temp, primary_temp, OSDs down and out, pools whose pg_num is not a power of two, pgp_num below
 * pg_num, a split and a merge in progress, a pool without HASHPSPOOL, choose_args and several rule shapes.
 *
 *   osdmap/      full-e42 + incrementals 1..N, placement-states.json (24 states), placement-names-e42.json (219 names);
 *                crush/placement-expected.json (137 names) and crush/mosdop-targets.json (ps, pg seed and acting set of the
 *                MOSDOp frames of a stock client)
 *   public/mapb/ base-e666 + incrementals 667..925, 70 states, the answers of overrides, the 3,352 names of epoch 709, and
 *                eight offline maps made by osdmaptool with every bucket algorithm
 *
 * A PG whose pool cannot be served by this core (an erasure pool, a rule that is not replicated firstn, a legacy bucket
 * algorithm the mapper does not implement yet) is counted as skipped and the totals are asserted, so a skip can never
 * hide the whole data set.
 */
#include "place_rig.h"

#define WORK_MAX 1000000u

typedef struct tally {
	uint32_t compared, skipped, bad;
} tally;

static wri_crush_ws g_ws;

static int pool_index(const wrt_mg_map *d, int64_t id)
{
	uint32_t i;

	for (i = 0; i < d->pools.n; i++)
		if (WRT_MG_E(d->pools, wrt_mg_pool_ent, i).id == id)
			return (int)i;
	return -1;
}

static int64_t jint(const wrt_json *j, wrt_tok t)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, t, &ok);

	WRT_CHECK(ok);
	return v;
}

static int jlist_eq(const wrt_json *j, wrt_tok arr, const int32_t *got, uint32_t n)
{
	size_t i, cnt = wrt_json_count(j, arr);

	if (cnt != n)
		return 0;
	for (i = 0; i < cnt; i++)
		if (jint(j, wrt_json_at(j, arr, i)) != (int64_t)got[i])
			return 0;
	return 1;
}

static void print_jlist(const wrt_json *j, wrt_tok arr)
{
	size_t i;

	fprintf(stderr, "[");
	for (i = 0; i < wrt_json_count(j, arr); i++)
		fprintf(stderr, "%s%d", i ? " " : "", (int)jint(j, wrt_json_at(j, arr, i)));
	fprintf(stderr, "]");
}

static void print_list(const int32_t *v, uint32_t n)
{
	uint32_t i;

	fprintf(stderr, "[");
	for (i = 0; i < n; i++)
		fprintf(stderr, "%s%d", i ? " " : "", (int)v[i]);
	fprintf(stderr, "]");
}

/* One PG against its expected columns. `raw` may be WRT_NONE (the name oracles have no raw column). */
static void check_pg(const wri_osdmap *m, uint32_t idx, uint32_t seed, const char *label, const char *pgid, const wrt_json *j,
		     wrt_tok raw, wrt_tok up, wrt_tok upp, wrt_tok act, wrt_tok actp, tally *t)
{
	wri_pg_result res;
	wr_errinfo why;
	wr_status st;
	int ok;

	memset(&why, 0, sizeof(why));
	st = wri_place_pg(m, idx, seed, WORK_MAX, &g_ws, &res, &why);
	if (st == WR_E_CRUSH_NO_RULE || st == WR_E_CRUSH_UNSUPPORTED || st == WR_E_POOL_UNSUPPORTED) {
		t->skipped++;
		return;
	}
	WRT_CHECK_STATUS(WR_OK, st);
	if (st != WR_OK) {
		t->bad++;
		return;
	}
	ok = jlist_eq(j, up, res.up, res.n_up) && jlist_eq(j, act, res.acting, res.n_acting) &&
	     jint(j, upp) == (int64_t)res.up_primary && jint(j, actp) == (int64_t)res.acting_primary;
	if (raw != WRT_NONE)
		ok = ok && jlist_eq(j, raw, res.raw, res.n_raw);
	wrt_checks++;
	t->compared++;
	if (!ok) {
		wrt_failures++;
		t->bad++;
		if (t->bad <= 12) {
			fprintf(stderr, "%s:%d: %s pg %s: expected up ", __FILE__, __LINE__, label, pgid);
			print_jlist(j, up);
			fprintf(stderr, "/%d acting ", (int)jint(j, upp));
			print_jlist(j, act);
			fprintf(stderr, "/%d", (int)jint(j, actp));
			if (raw != WRT_NONE) {
				fprintf(stderr, " raw ");
				print_jlist(j, raw);
			}
			fprintf(stderr, "; got up ");
			print_list(res.up, res.n_up);
			fprintf(stderr, "/%d acting ", (int)res.up_primary);
			print_list(res.acting, res.n_acting);
			fprintf(stderr, "/%d raw ", (int)res.acting_primary);
			print_list(res.raw, res.n_raw);
			fprintf(stderr, "\n");
		}
	}
}

/* A table `pgs`: {"<pool>.<pg hex>": [raw, up, up_primary, acting, acting_primary], ...} */
static void check_table(const wrt_mg_map *d, const place_rig *r, const char *label, const wrt_json *j, wrt_tok pgs, tally *t)
{
	size_t i, n = wrt_json_count(j, pgs);

	for (i = 0; i < n; i++) {
		wrt_tok v;
		const char *k = wrt_json_key_at(j, pgs, i, &v);
		char *end = NULL;
		unsigned long pool = strtoul(k, &end, 10), seed;
		int idx;

		WRT_CHECK(end != NULL && *end == '.');
		if (end == NULL || *end != '.')
			continue;
		seed = strtoul(end + 1, NULL, 16);
		idx = pool_index(d, (int64_t)pool);
		WRT_CHECK(idx >= 0); /* a pool the description does not have */
		if (idx < 0 || rig_idx(r, (int64_t)pool) < 0)
			continue; /* another batch of tracked pools takes it */
		if (WRT_MG_E(d->pools, wrt_mg_pool_ent, idx).p.type != WRI_POOL_REPLICATED) {
			t->skipped++;
			continue;
		}
		idx = rig_idx(r, (int64_t)pool);
		check_pg(r->m, (uint32_t)idx, (uint32_t)seed, label, k, j, wrt_json_at(j, v, 0), wrt_json_at(j, v, 1), wrt_json_at(j, v, 2),
			 wrt_json_at(j, v, 3), wrt_json_at(j, v, 4), t);
	}
}

/* Name oracle rows: [(label, epoch,) pool, name hex, ns hex, raw ps, pgid, up, up primary, acting, acting primary]. */
static void check_name(const wrt_mg_map *d, const place_rig *r, const char *label, const wrt_json *j, wrt_tok row, size_t at, tally *t)
{
	int64_t pool_id = jint(j, wrt_json_at(j, row, at));
	uint8_t *name = NULL, *ns = NULL;
	size_t nn = 0, nsn = 0;
	int didx = pool_index(d, pool_id), idx = rig_idx(r, pool_id);
	wri_oid oid;
	uint32_t ps = 0, seed;
	wr_status st;
	char *pgid;
	char want_pg[48];
	const wri_map_pool *p;

	WRT_CHECK(didx >= 0);
	if (didx < 0 || idx < 0)
		return; /* unknown pool, or another batch of tracked pools takes it */
	if (WRT_MG_E(d->pools, wrt_mg_pool_ent, didx).p.type != WRI_POOL_REPLICATED) {
		t->skipped++;
		return;
	}
	p = &wri_map_pools(r->m)[idx];
	WRT_CHECK(wrt_json_hex(j, wrt_json_at(j, row, at + 1), &name, &nn) == 0);
	WRT_CHECK(wrt_json_hex(j, wrt_json_at(j, row, at + 2), &ns, &nsn) == 0);
	memset(&oid, 0, sizeof(oid));
	oid.name = name;
	oid.name_len = (uint32_t)nn;
	oid.nspace = ns;
	oid.nspace_len = (uint32_t)nsn;
	st = wri_place_hash(p, &oid, &ps);
	if (nn + nsn > WRI_PLACE_NAME_MAX) {
		/* the oracle was asked about a 4096-byte name with a namespace; the core's cap is on the sum (WR_E_TOOBIG) */
		WRT_CHECK_STATUS(WR_E_TOOBIG, st);
		t->skipped++;
		free(name);
		free(ns);
		return;
	}
	WRT_CHECK_STATUS(WR_OK, st);
	WRT_CHECK_U64(ps, (uint64_t)jint(j, wrt_json_at(j, row, at + 3)));
	seed = wri_place_pg_seed(p, ps);
	pgid = wrt_json_strdup(j, wrt_json_at(j, row, at + 4));
	snprintf(want_pg, sizeof(want_pg), "%u.%x", (unsigned)pool_id, (unsigned)seed);
	WRT_CHECK(pgid != NULL && strcmp(pgid, want_pg) == 0);
	if (pgid != NULL && strcmp(pgid, want_pg) != 0)
		fprintf(stderr, "%s: name pg %s, want %s\n", label, want_pg, pgid);
	check_pg(r->m, (uint32_t)idx, seed, label, want_pg, j, WRT_NONE, wrt_json_at(j, row, at + 5), wrt_json_at(j, row, at + 6),
		 wrt_json_at(j, row, at + 7), wrt_json_at(j, row, at + 8), t);
	free(pgid);
	free(name);
	free(ns);
}

static void names_table(const wrt_mg_map *d, const place_rig *r, const char *label, const wrt_json *j, wrt_tok entries, size_t at, tally *t)
{
	size_t i;

	for (i = 0; i < wrt_json_count(j, entries); i++)
		check_name(d, r, label, j, wrt_json_at(j, entries, i), at, t);
}

/* The slots track at most WRI_MAP_POOLS_MAX pools: a state with more pools is judged in batches of tracked pools. */
static void table_all(const wrt_mg_map *d, const char *label, const wrt_json *j, wrt_tok pgs, tally *t)
{
	int64_t ids[WRI_MAP_POOLS_MAX];
	uint32_t start, i, n;

	for (start = 0; start < d->pools.n; start += WRI_MAP_POOLS_MAX) {
		place_rig r;

		n = d->pools.n - start < WRI_MAP_POOLS_MAX ? d->pools.n - start : WRI_MAP_POOLS_MAX;
		for (i = 0; i < n; i++)
			ids[i] = WRT_MG_E(d->pools, wrt_mg_pool_ent, start + i).id;
		if (rig_build_pools(&r, d, 1, ids, n))
			check_table(d, &r, label, j, pgs, t);
		rig_free(&r);
	}
}

static void names_all(const wrt_mg_map *d, const char *label, const wrt_json *j, wrt_tok entries, size_t at, tally *t)
{
	int64_t ids[WRI_MAP_POOLS_MAX];
	uint32_t start, i, n;

	for (start = 0; start < d->pools.n; start += WRI_MAP_POOLS_MAX) {
		place_rig r;

		n = d->pools.n - start < WRI_MAP_POOLS_MAX ? d->pools.n - start : WRI_MAP_POOLS_MAX;
		for (i = 0; i < n; i++)
			ids[i] = WRT_MG_E(d->pools, wrt_mg_pool_ent, start + i).id;
		if (rig_build_pools(&r, d, 1, ids, n))
			names_table(d, &r, label, j, entries, at, t);
		rig_free(&r);
	}
}

/* ---- the osdmap/ set ------------------------------------------------------------------------------------- */

static void real_osdmap_set(void)
{
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i, k;
	wrt_mg_map d;
	wrt_json states, names, exp137, mosdop;
	wrt_tok st_obj, names_t, cases, samples;
	tally ts = {0, 0, 0}, tn = {0, 0, 0};

	WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &ls, &nl) == 0);
	WRT_CHECK(wrt_json_load_vec(&states, "osdmap/placement-states.json") == 0);
	WRT_CHECK(wrt_json_load_vec(&names, "osdmap/placement-names-e42.json") == 0);
	WRT_CHECK(wrt_json_load_vec(&exp137, "crush/placement-expected.json") == 0);
	WRT_CHECK(wrt_json_load_vec(&mosdop, "crush/mosdop-targets.json") == 0);
	st_obj = wrt_json_get(&states, wrt_json_root(&states), "states");
	names_t = wrt_json_get(&names, wrt_json_root(&names), "entries");
	cases = wrt_json_get(&exp137, wrt_json_root(&exp137), "cases");
	samples = wrt_json_get(&mosdop, wrt_json_root(&mosdop), "samples");
	wrt_mg_model_init(&d);
	for (i = 0; i < nl; i++) {
		wrt_mg_inc inc;
		uint32_t epoch = ls[i].epoch;
		place_rig r;
		int built = 0;

		WRT_CHECK(wrt_mg_inc_parse(ls[i].p, ls[i].n, &inc) == 0);
		WRT_CHECK_STATUS(WRT_MG_E_OK, wrt_mg_model_apply(&d, &inc));
		wrt_mg_inc_free(&inc);
		memset(&r, 0, sizeof(r));
		for (k = 0; k < wrt_json_count(&states, st_obj); k++) {
			wrt_tok sv;
			const char *label = wrt_json_key_at(&states, st_obj, k, &sv);

			if ((uint32_t)jint(&states, wrt_json_get(&states, sv, "epoch")) != epoch)
				continue;
			table_all(&d, label, &states, wrt_json_get(&states, sv, "pgs"), &ts);
		}
		if (epoch == 42) {
			built = rig_build(&r, &d, 1); /* two pools */
			names_all(&d, "names-e42", &names, names_t, 0, &tn);
			if (built) {
				for (k = 0; k < wrt_json_count(&exp137, cases); k++) {
					wrt_tok c = wrt_json_at(&exp137, cases, k);
					/* a case is an object: build the row layout of the oracle from its members */
					int64_t pool_id = jint(&exp137, wrt_json_get(&exp137, c, "pool_id"));
					uint8_t *nm = NULL, *ns = NULL;
					size_t nn = 0, nsn = 0;
					char *raw_pg = wrt_json_strdup(&exp137, wrt_json_get(&exp137, c, "raw_pgid")), *pgid;
					int idx = pool_index(&d, pool_id);
					wri_oid oid;
					uint32_t ps = 0, seed;
					char want[48];

					WRT_CHECK(idx >= 0 && raw_pg != NULL);
					WRT_CHECK(wrt_json_get_hex(&exp137, c, "object_hex", &nm, &nn) == 0);
					WRT_CHECK(wrt_json_get_hex(&exp137, c, "nspace_hex", &ns, &nsn) == 0);
					if (idx >= 0 && raw_pg != NULL) {
						const wri_map_pool *p = &wri_map_pools(r.m)[idx];

						memset(&oid, 0, sizeof(oid));
						oid.name = nm;
						oid.name_len = (uint32_t)nn;
						oid.nspace = ns;
						oid.nspace_len = (uint32_t)nsn;
						WRT_CHECK_STATUS(WR_OK, wri_place_hash(p, &oid, &ps));
						/* raw_pgid is "<pool>.<ps in hex>" */
						WRT_CHECK_U64(ps, strtoul(strchr(raw_pg, '.') + 1, NULL, 16));
						seed = wri_place_pg_seed(p, ps);
						pgid = wrt_json_strdup(&exp137, wrt_json_get(&exp137, c, "pgid"));
						snprintf(want, sizeof(want), "%u.%x", (unsigned)pool_id, (unsigned)seed);
						WRT_CHECK(pgid != NULL && strcmp(pgid, want) == 0);
						check_pg(r.m, (uint32_t)idx, seed, "placement-expected", want, &exp137, WRT_NONE,
							 wrt_json_get(&exp137, c, "up"), wrt_json_get(&exp137, c, "up_primary"),
							 wrt_json_get(&exp137, c, "acting"), wrt_json_get(&exp137, c, "acting_primary"), &tn);
						free(pgid);
					}
					free(raw_pg);
					free(nm);
					free(ns);
				}
				/* the MOSDOp frames of a stock client: the hash it put in the message, the pg seed and the acting set */
				for (k = 0; k < wrt_json_count(&mosdop, samples); k++) {
					wrt_tok s = wrt_json_at(&mosdop, samples, k);
					int64_t pool_id = jint(&mosdop, wrt_json_get(&mosdop, s, "pool"));
					char *oidname = wrt_json_strdup(&mosdop, wrt_json_get(&mosdop, s, "oid"));
					char *nsp = wrt_json_strdup(&mosdop, wrt_json_get(&mosdop, s, "nspace"));
					int idx = pool_index(&d, pool_id);
					wri_oid oid;
					uint32_t ps = 0, seed;
					wri_pg_result res;

					WRT_CHECK(idx >= 0 && oidname != NULL && nsp != NULL);
					if (idx >= 0 && oidname != NULL && nsp != NULL) {
						const wri_map_pool *p = &wri_map_pools(r.m)[idx];

						memset(&oid, 0, sizeof(oid));
						oid.name = (const uint8_t *)oidname;
						oid.name_len = (uint32_t)strlen(oidname);
						oid.nspace = (const uint8_t *)nsp;
						oid.nspace_len = (uint32_t)strlen(nsp);
						WRT_CHECK_STATUS(WR_OK, wri_place_hash(p, &oid, &ps));
						WRT_CHECK_U64(ps, jint(&mosdop, wrt_json_get(&mosdop, s, "hash")));
						seed = wri_place_pg_seed(p, ps);
						WRT_CHECK_U64(seed, jint(&mosdop, wrt_json_get(&mosdop, s, "seed")));
						WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, (uint32_t)idx, seed, WORK_MAX, &g_ws, &res, NULL));
						WRT_CHECK(jlist_eq(&mosdop, wrt_json_get(&mosdop, s, "acting"), res.acting, res.n_acting));
						WRT_CHECK_U64(res.acting_primary, jint(&mosdop, wrt_json_get(&mosdop, s, "osd")));
					}
					free(oidname);
					free(nsp);
				}
			}
		}
		if (built)
			rig_free(&r);
	}
	fprintf(stderr, "osdmap set: %u PGs and %u names compared, %u and %u skipped\n", ts.compared, tn.compared, ts.skipped, tn.skipped);
	WRT_CHECK(ts.compared >= 600 && tn.compared >= 340);
	WRT_CHECK(ts.bad == 0 && tn.bad == 0);
	wrt_mg_free_lines(ls, nl);
	wrt_mg_map_free(&d);
	wrt_json_free(&states);
	wrt_json_free(&names);
	wrt_json_free(&exp137);
	wrt_json_free(&mosdop);
}

/* ---- the map-b set ---------------------------------------------------------------------------------------- */

static void mapb_offline(void)
{
	wrt_json idx;
	wrt_tok maps;
	size_t i;
	tally t = {0, 0, 0};

	WRT_CHECK(wrt_json_load_vec(&idx, "public/mapb/INDEX.json") == 0);
	maps = wrt_json_get(&idx, wrt_json_root(&idx), "osdmaps");
	for (i = 0; i < wrt_json_count(&idx, maps); i++) {
		wrt_tok m = wrt_json_at(&idx, maps, i);
		char *hexrel = wrt_json_strdup(&idx, wrt_json_get(&idx, m, "osdmap")), *pgrel = wrt_json_strdup(&idx, wrt_json_get(&idx, m, "pgs"));
		char p1[512], p2[512];
		uint8_t *bytes = NULL;
		size_t n = 0;
		wrt_mg_map d;
		wrt_json pj;
		tally before = t;

		WRT_CHECK(hexrel != NULL && pgrel != NULL);
		if (hexrel == NULL || pgrel == NULL) {
			free(hexrel);
			free(pgrel);
			continue;
		}
		snprintf(p1, sizeof(p1), "public/mapb/%s", hexrel);
		snprintf(p2, sizeof(p2), "public/mapb/%s", pgrel);
		WRT_CHECK(wrt_mg_load_hex_file(wrt_vec_path(p1), &bytes, &n) == 0);
		WRT_CHECK(wrt_mg_map_parse(bytes, n, &d) == 0);
		WRT_CHECK(wrt_json_load_vec(&pj, p2) == 0);
		table_all(&d, hexrel, &pj, wrt_json_get(&pj, wrt_json_root(&pj), "pgs"), &t);
		fprintf(stderr, "  %s: %u compared, %u skipped\n", hexrel, t.compared - before.compared, t.skipped - before.skipped);
		wrt_mg_map_free(&d);
		wrt_json_free(&pj);
		free(bytes);
		free(hexrel);
		free(pgrel);
	}
	fprintf(stderr, "offline maps: %u PGs compared, %u skipped\n", t.compared, t.skipped);
	WRT_CHECK(t.compared >= 200 && t.bad == 0);
	wrt_json_free(&idx);
}

static void mapb_replay(void)
{
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i, k;
	uint8_t *base = NULL;
	size_t bn = 0;
	wrt_mg_map d;
	wrt_json idx, answers, names;
	wrt_tok states, entries, ans, nentries;
	tally ts = {0, 0, 0}, ta = {0, 0, 0}, tn = {0, 0, 0};
	uint32_t names_epoch;

	WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("public/mapb/incrementals.hex"), &ls, &nl) == 0);
	WRT_CHECK(wrt_mg_load_hex_file(wrt_vec_path("public/mapb/base-e666.hex"), &base, &bn) == 0);
	WRT_CHECK(wrt_json_load_vec(&idx, "public/mapb/INDEX.json") == 0);
	WRT_CHECK(wrt_json_load_vec(&answers, "public/mapb/answers.json") == 0);
	WRT_CHECK(wrt_json_load_vec(&names, "public/mapb/names/names-e709.json") == 0);
	WRT_CHECK(wrt_mg_map_parse(base, bn, &d) == 0);
	states = wrt_json_get(&idx, wrt_json_root(&idx), "states");
	ans = wrt_json_get(&answers, wrt_json_root(&answers), "entries");
	entries = wrt_json_get(&names, wrt_json_root(&names), "entries");
	names_epoch = (uint32_t)jint(&names, wrt_json_get(&names, wrt_json_root(&names), "epoch"));
	nentries = states;
	for (i = 0; i < nl; i++) {
		wrt_mg_inc inc;
		uint32_t epoch = ls[i].epoch;

		WRT_CHECK(wrt_mg_inc_parse(ls[i].p, ls[i].n, &inc) == 0);
		WRT_CHECK_STATUS(WRT_MG_E_OK, wrt_mg_model_apply(&d, &inc));
		wrt_mg_inc_free(&inc);
		for (k = 0; k < wrt_json_count(&idx, nentries); k++) {
			wrt_tok s = wrt_json_at(&idx, nentries, k);
			char *file, *label, path[512];
			wrt_json sj;

			if ((uint32_t)jint(&idx, wrt_json_get(&idx, s, "epoch")) != epoch)
				continue;
			file = wrt_json_strdup(&idx, wrt_json_get(&idx, s, "file"));
			label = wrt_json_strdup(&idx, wrt_json_get(&idx, s, "label"));
			if (file == NULL || label == NULL) {
				WRT_CHECK(0);
			} else {
				snprintf(path, sizeof(path), "public/mapb/%s", file);
				WRT_CHECK(wrt_json_load_vec(&sj, path) == 0);
				table_all(&d, label, &sj, wrt_json_get(&sj, wrt_json_root(&sj), "pgs"), &ts);
				wrt_json_free(&sj);
			}
			free(file);
			free(label);
		}
		/* the answers of `ceph osd map` right after an override was set: [label, epoch, pool, ...] */
		for (k = 0; k < wrt_json_count(&answers, ans); k++) {
			wrt_tok row = wrt_json_at(&answers, ans, k);

			if ((uint32_t)jint(&answers, wrt_json_at(&answers, row, 1)) != epoch)
				continue;
			{
				place_rig r1;
				int64_t pool = jint(&answers, wrt_json_at(&answers, row, 2));
				char *label = wrt_json_strdup(&answers, wrt_json_at(&answers, row, 0));

				if (rig_build_pools(&r1, &d, 1, &pool, 1))
					check_name(&d, &r1, label != NULL ? label : "answer", &answers, row, 2, &ta);
				rig_free(&r1);
				free(label);
			}
		}
		if (epoch == names_epoch)
			names_all(&d, "names-e709", &names, entries, 0, &tn);
	}
	fprintf(stderr, "map-b replay: %u PGs, %u override answers and %u names compared; %u, %u and %u skipped\n", ts.compared,
		ta.compared, tn.compared, ts.skipped, ta.skipped, tn.skipped);
	WRT_CHECK(ts.compared >= 1000 && ta.compared >= 40 && tn.compared >= 2500);
	WRT_CHECK(ts.bad == 0 && ta.bad == 0 && tn.bad == 0);
	wrt_mg_free_lines(ls, nl);
	free(base);
	wrt_mg_map_free(&d);
	wrt_json_free(&idx);
	wrt_json_free(&answers);
	wrt_json_free(&names);
}

int main(void)
{
	real_osdmap_set();
	mapb_offline();
	mapb_replay();
	return wrt_finish();
}
