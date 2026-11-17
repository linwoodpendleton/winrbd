/* SPDX-License-Identifier: MIT */
/*
 * test_osdmap_seq.c - wri_osdmap_apply_inc over the real incrementals of the lab cluster (core/src/osdmap/wri_osdmap_inc.c,
 * wri_osdmap_inc2.c; docs/spec/osdmap.md 3.5).
 *
 *  - harness/vectors/osdmap: the 89 stored incrementals, epoch 1 (an embedded full map) to 89, applied one after the other
 *    with the CRCs verified. After every epoch the compact map is compared with the monitor's own state of that epoch
 *    (expected.json "chain": flags, max_osd, state, weight, primary affinity, first msgr2 address, both pools, every pg table,
 *    and "the CRUSH map is the same exactly when its digest is the same"), with the wrt_mapgen model replaying the same
 *    incrementals (pools, tables, the CRUSH region of the model's blob), and with a full decode of the model's own encoding of
 *    the state. Epoch 42 is also compared with the real full map (full-e42.hex).
 *  - harness/vectors/public/mapb: the full map of epoch 666 and the 259 incrementals up to 925, with the lab's test pools
 *    created, split, merged, renamed, deleted, tiered, erasure coded and given weight sets, upmaps, temps, affinity, reweights
 *    and down / up marks on the way. Three chains with different tracked names run over it; at each of the 21 epochs for
 *    which the capture holds the monitor's own full map, the chain state must equal a full decode of that map (the same
 *    tables, pool records, status and CRUSH region). One chain tracks a pool the held map has no record of at its rename
 *    (epoch 848): the apply must say WR_E_MAP_RESYNC, and after a full decode the chain must carry on and agree again.
 *
 * Every apply goes through rig_apply (inc_rig.h): two pre-fills, guards, the held map untouched, a failure leaves magic 0.
 */
#include "inc_rig.h"

/* ---- expected.json: one entry of "chain" against a compact map ---------------------------------------------------- */

static int64_t jint(const wrt_json *j, wrt_tok obj, const char *key)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, wrt_json_get(j, obj, key), &ok);

	WRT_CHECK(ok);
	return v;
}

/* "10.77.0.10:6802" -> ip and port */
static void parse_addr(const char *s, uint8_t ip[4], unsigned *port)
{
	unsigned a, b, c, d;

	if (sscanf(s, "%u.%u.%u.%u:%u", &a, &b, &c, &d, port) != 5) {
		WRT_CHECK(0 && "address string");
		return;
	}
	ip[0] = (uint8_t)a;
	ip[1] = (uint8_t)b;
	ip[2] = (uint8_t)c;
	ip[3] = (uint8_t)d;
}

static int name_tracked(const wri_mapcfg *cfg, const char *name, uint32_t *k)
{
	uint32_t i;

	for (i = 0; i < cfg->n_pools; i++)
		if (strlen(name) == cfg->name_len[i] && memcmp(name, cfg->name[i], cfg->name_len[i]) == 0) {
			*k = i;
			return 1;
		}
	return 0;
}

/* The five tables of one chain entry against the compact map's. */
static void check_chain_tables(const wri_osdmap *m, const wrt_json *j, wrt_tok exp, const int64_t *tracked_ids, uint32_t nt)
{
	static const char *const keys[WRI_TAB_COUNT] = {"pg_temp", "primary_temp", "pg_upmap", "pg_upmap_items", "pg_upmap_primaries"};
	unsigned kind;

	for (kind = 0; kind < WRI_TAB_COUNT; kind++) {
		wrt_tok t = wrt_json_get(j, exp, keys[kind]);
		size_t i, n = wrt_json_count(j, t);
		uint32_t kept = 0;

		for (i = 0; i < n; i++) {
			wrt_tok val;
			const char *key = wrt_json_key_at(j, t, i, &val);
			char *dot;
			uint64_t pool = strtoull(key, &dot, 10);
			uint32_t seed = (uint32_t)strtoul(dot + 1, NULL, 16), q, tr = 0;
			const int32_t *got;
			uint32_t ngot;
			int ok = 0;

			for (q = 0; q < nt; q++)
				if (tracked_ids[q] >= 0 && (uint64_t)tracked_ids[q] == pool)
					tr = 1;
			if (!tr)
				continue;
			kept++;
			if (!wri_pgtab_find(m, kind, wri_pg_key((uint32_t)pool, seed), &got, &ngot)) {
				WRT_CHECK(0 && "an entry of the monitor's table is missing");
				continue;
			}
			if (kind == WRI_TAB_PRIMARY_TEMP || kind == WRI_TAB_PG_UPMAP_PRIMARY) {
				WRT_CHECK_U64(ngot, 1);
				if (ngot == 1)
					WRT_CHECK_U64((uint32_t)got[0], (uint32_t)wrt_json_int(j, val, &ok));
			} else if (kind == WRI_TAB_PG_UPMAP_ITEMS) {
				WRT_CHECK_U64(ngot, 2u * wrt_json_count(j, val));
				for (q = 0; q < wrt_json_count(j, val) && 2u * q + 1u < ngot; q++) {
					WRT_CHECK_U64((uint32_t)got[2u * q], (uint32_t)wrt_json_int(j, wrt_json_at(j, wrt_json_at(j, val, q), 0), &ok));
					WRT_CHECK_U64((uint32_t)got[2u * q + 1u], (uint32_t)wrt_json_int(j, wrt_json_at(j, wrt_json_at(j, val, q), 1), &ok));
				}
			} else {
				WRT_CHECK_U64(ngot, wrt_json_count(j, val));
				for (q = 0; q < wrt_json_count(j, val) && q < ngot; q++)
					WRT_CHECK_U64((uint32_t)got[q], (uint32_t)wrt_json_int(j, wrt_json_at(j, val, q), &ok));
			}
		}
		WRT_CHECK_U64(m->tab[kind].n, kept);
	}
}

/* The monitor's summary of the epoch (state, weight, affinity, first msgr2 address, pools, tables). */
static void check_chain(const wri_osdmap *m, const wrt_json *j, wrt_tok exp, const wri_mapcfg *cfg)
{
	wrt_tok osd_state = wrt_json_get(j, exp, "osd_state"), weight = wrt_json_get(j, exp, "osd_weight");
	wrt_tok addrs = wrt_json_get(j, exp, "client_addrs"), aff = wrt_json_get(j, exp, "osd_primary_affinity");
	wrt_tok pools = wrt_json_get(j, exp, "pools");
	int64_t tracked_ids[WRI_MAP_POOLS_MAX];
	uint32_t seen[WRI_MAP_POOLS_MAX];
	uint32_t i, k;
	size_t pi;

	WRT_CHECK_U64(m->epoch, jint(j, exp, "epoch"));
	WRT_CHECK_U64(m->flags, jint(j, exp, "flags"));
	WRT_CHECK_U64(m->max_osd, jint(j, exp, "max_osd"));
	WRT_CHECK_U64(wrt_json_count(j, osd_state), m->max_osd);
	for (i = 0; i < m->max_osd; i++) {
		int ok = 0;
		wrt_tok v = wrt_json_at(j, addrs, i);
		size_t e, ne = wrt_json_count(j, v);
		wri_osd_addr want;
		int have = 0;

		WRT_CHECK_U64(wri_map_state(m)[i], wrt_json_int(j, wrt_json_at(j, osd_state, i), &ok) & 3);
		WRT_CHECK_U64(wri_map_weight(m)[i], wrt_json_int(j, wrt_json_at(j, weight, i), &ok));
		WRT_CHECK_U64(wri_osd_aff(m, (int32_t)i), wrt_json_int(j, wrt_json_at(j, aff, i), &ok));
		memset(&want, 0, sizeof(want));
		for (e = 0; e < ne && !have; e++) { /* [type, "ip:port", nonce] */
			wrt_tok ent = wrt_json_at(j, v, e);
			unsigned port = 0;
			char *s;

			if (wrt_json_int(j, wrt_json_at(j, ent, 0), &ok) != 2)
				continue;
			s = wrt_json_strdup(j, wrt_json_at(j, ent, 1));
			parse_addr(s, want.ip, &port);
			free(s);
			want.family = WR_AF_IPV4;
			want.port = (uint16_t)port;
			want.nonce = (uint32_t)wrt_json_int(j, wrt_json_at(j, ent, 2), &ok);
			have = 1;
		}
		WRT_CHECK(memcmp(&wri_map_addr(m)[i], &want, sizeof(want)) == 0);
	}

	memset(seen, 0, sizeof(seen));
	for (k = 0; k < WRI_MAP_POOLS_MAX; k++)
		tracked_ids[k] = -1;
	for (pi = 0; pi < wrt_json_count(j, pools); pi++) {
		wrt_tok t;
		const char *key = wrt_json_key_at(j, pools, pi, &t);
		int64_t id = atoll(key);
		char *name = wrt_json_strdup(j, wrt_json_get(j, t, "name"));
		const wri_map_pool *p;

		if (name == NULL || !name_tracked(cfg, name, &k)) {
			free(name);
			continue;
		}
		free(name);
		p = &wri_map_pools(m)[k];
		seen[k] = 1;
		tracked_ids[k] = id;
		WRT_CHECK_U64(p->present, 1);
		WRT_CHECK_U64(p->id, id);
		WRT_CHECK_U64(p->status, WR_OK);
		WRT_CHECK_U64(p->type, jint(j, t, "type"));
		WRT_CHECK_U64(p->size, jint(j, t, "size"));
		WRT_CHECK_U64(p->min_size, jint(j, t, "min_size"));
		WRT_CHECK_U64(p->crush_rule, jint(j, t, "crush_rule"));
		WRT_CHECK_U64(p->object_hash, jint(j, t, "object_hash"));
		WRT_CHECK_U64(p->pg_num, jint(j, t, "pg_num"));
		WRT_CHECK_U64(p->pgp_num, jint(j, t, "pgp_num"));
		WRT_CHECK_U64(p->flags, jint(j, t, "flags"));
	}
	for (k = 0; k < cfg->n_pools; k++)
		if (!seen[k])
			WRT_CHECK_U64(wri_map_pools(m)[k].present, 0); /* a tracked name the monitor's map does not have */
	check_chain_tables(m, j, exp, tracked_ids, cfg->n_pools);
}

static uint64_t fnv(const uint8_t *p, size_t n)
{
	uint64_t h = 1469598103934665603ull;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ull;
	return h;
}

/* ---- the 89 incrementals of the lab ------------------------------------------------------------------------------- */

static void test_lab_chain(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	wrt_mg_line *ls;
	size_t nl, i;
	wrt_json j;
	wrt_tok chain;
	wrt_mg_inc inc1;
	wrt_mg_map mm;
	rig g;
	char digest[96][20];
	uint64_t canon[96];
	size_t nd = 0;
	uint8_t *full42;
	size_t n42;
	unsigned with_crush = 0, with_pools = 0;

	WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &ls, &nl) == 0);
	WRT_CHECK_U64(nl, 89);
	WRT_CHECK(wrt_json_load_vec(&j, "osdmap/expected.json") == 0);
	WRT_CHECK(wrt_mg_load_hex_file(wrt_vec_path("osdmap/full-e42.hex"), &full42, &n42) == 0);
	chain = wrt_json_get(&j, wrt_json_root(&j), "chain");
	if (nl != 89)
		return;

	/* epoch 1 is the map embedded in incremental 1: the model adopts it, the core decodes the real bytes */
	WRT_CHECK(wrt_mg_inc_parse(ls[0].p, ls[0].n, &inc1) == 0);
	wrt_mg_model_init(&mm);
	WRT_CHECK_STATUS(WRT_MG_E_OK, wrt_mg_model_apply(&mm, &inc1));
	WRT_CHECK(rig_start(&g, &mm, 4096, 1, names, 2));
	{
		islot real;
		wr_errinfo why;

		islot_new(&real, RIG_SLOT_BYTES);
		WRT_CHECK_STATUS(WR_OK, rig_decode(&g.cfg, inc1.fullmap, inc1.fullmap_len, &real, &why));
		rig_cmp_core(rig_held(&g), islot_map(&real));
		check_chain(rig_held(&g), &j, wrt_json_get(&j, chain, "1"), &g.cfg);
		islot_free(&real);
	}
	/* incremental 1 on top of its own map: an embedded full map replaces everything, whatever the held epoch */
	{
		islot out;
		wr_errinfo why;

		islot_new(&out, RIG_SLOT_BYTES);
		WRT_CHECK_STATUS(WR_OK, rig_apply(&g.cfg, rig_held(&g), ls[0].p, ls[0].n, &out, &why));
		rig_cmp_core(islot_map(&out), rig_held(&g));
		islot_free(&out);
	}
	wrt_mg_inc_free(&inc1);
	wrt_mg_map_free(&mm);

	for (i = 1; i < nl; i++) {
		char key[32];
		wrt_tok exp;
		wrt_mg_inc inc;
		const wri_osdmap *m;
		wr_errinfo why;
		wr_status st;
		wri_map_blob_info bi;
		int rc = 0;
		char *dg;
		uint64_t cn;
		size_t q;
		int matched = 0;

		WRT_CHECK(ls[i].epoch == i + 1);
		WRT_CHECK(wrt_mg_inc_parse(ls[i].p, ls[i].n, &inc) == 0);
		with_crush += inc.crush_len != 0;
		with_pools += inc.new_pools.n != 0;
		WRT_CHECK_STATUS(WR_OK, wri_osdmap_inc_info(ls[i].p, ls[i].n, &bi, &why));
		WRT_CHECK_U64(bi.epoch, ls[i].epoch);
		st = rig_step_blob(&g, ls[i].p, ls[i].n, &inc, NULL, &rc, &why);
		WRT_CHECK_STATUS(WR_OK, st);
		WRT_CHECK_STATUS(WRT_MG_E_OK, rc);
		wrt_mg_inc_free(&inc);
		if (st != WR_OK)
			break;
		m = rig_held(&g);
		snprintf(key, sizeof(key), "%zu", i + 1);
		exp = wrt_json_get(&j, chain, key);
		check_chain(m, &j, exp, &g.cfg);

		/* the CRUSH map: two epochs have the same digest exactly when the compact regions are equal */
		dg = wrt_json_strdup(&j, wrt_json_get(&j, exp, "crush"));
		cn = fnv((const uint8_t *)wri_map_crush(m), wri_map_crush(m)->bytes);
		for (q = 0; q < nd; q++) {
			if (strcmp(digest[q], dg ? dg : "") == 0) {
				matched = 1;
				WRT_CHECK(canon[q] == cn);
			} else {
				WRT_CHECK(canon[q] != cn);
			}
		}
		if (!matched && nd < 96) {
			snprintf(digest[nd], sizeof(digest[nd]), "%s", dg ? dg : "");
			canon[nd++] = cn;
		}
		free(dg);

		if (i + 1 == 42) { /* the monitor's own full map of epoch 42 */
			islot real;

			islot_new(&real, RIG_SLOT_BYTES);
			WRT_CHECK_STATUS(WR_OK, rig_decode(&g.cfg, full42, n42, &real, &why));
			rig_cmp_core(m, islot_map(&real));
			islot_free(&real);
		}
	}
	WRT_CHECK(nd >= 8);
	WRT_CHECK(with_crush >= 5 && with_pools >= 2); /* the chain really exercises the CRUSH and pool rows */
	rig_end(&g);
	free(full42);
	wrt_mg_free_lines(ls, nl);
	wrt_json_free(&j);
}

/* ---- the public capture: 259 epochs from 667 to 925 -------------------------------------------------------------- */

/* The epochs the capture holds the monitor's full map of (files maps/e<epoch>.hex), found by listing INDEX.json "states". */
typedef struct fullmap {
	uint32_t epoch;
	uint8_t *p;
	size_t n;
} fullmap;

static unsigned load_fullmaps(fullmap *out, unsigned cap)
{
	static const unsigned epochs[] = {667, 681, 693, 698, 709, 710, 720, 740, 747, 764, 773, 782, 789, 848, 849, 852, 861, 866, 872, 875, 925};
	unsigned i, n = 0;

	for (i = 0; i < sizeof(epochs) / sizeof(epochs[0]) && n < cap; i++) {
		char rel[64];

		snprintf(rel, sizeof(rel), "public/mapb/maps/e%u.hex", epochs[i]);
		if (wrt_mg_load_hex_file(wrt_vec_path(rel), &out[n].p, &out[n].n) != 0) {
			WRT_CHECK(0 && "cannot load a full map of the capture");
			continue;
		}
		out[n].epoch = epochs[i];
		n++;
	}
	return n;
}

static const fullmap *find_full(const fullmap *f, unsigned n, uint32_t epoch)
{
	unsigned i;

	for (i = 0; i < n; i++)
		if (f[i].epoch == epoch)
			return &f[i];
	return NULL;
}

/*
 * One chain over the capture. `resync_at` is the epoch at which the apply must say WR_E_MAP_RESYNC (0 = never); after it the chain
 * is re-seeded by a full decode of the monitor's map of that epoch (it must be one the capture holds) and goes on.
 */
static void run_mapb(const char *const *names, unsigned nn, uint32_t resync_at, const char *label)
{
	wrt_mg_line *ls;
	size_t nl, i;
	uint8_t *base;
	size_t nbase;
	fullmap fm[24];
	unsigned nfm, checked = 0, resyncs = 0;
	wri_mapcfg cfg;
	islot s[2];
	int cur = 0;
	wr_errinfo why;

	WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("public/mapb/incrementals.hex"), &ls, &nl) == 0);
	WRT_CHECK(wrt_mg_load_hex_file(wrt_vec_path("public/mapb/base-e666.hex"), &base, &nbase) == 0);
	nfm = load_fullmaps(fm, 24);
	WRT_CHECK_U64(nl, 259);
	if (nl != 259)
		return;
	rig_cfg(&cfg, RIG_SLOT_BYTES, 4096, 1, names, nn);
	islot_new(&s[0], RIG_SLOT_BYTES);
	islot_new(&s[1], RIG_SLOT_BYTES);
	WRT_CHECK_STATUS(WR_OK, rig_decode(&cfg, base, nbase, &s[0], &why));

	for (i = 0; i < nl; i++) {
		wr_status st;
		const fullmap *f;

		WRT_CHECK_U64(ls[i].epoch, 667 + i);
		st = rig_apply(&cfg, islot_map(&s[cur]), ls[i].p, ls[i].n, &s[1 - cur], &why);
		if (resync_at != 0 && ls[i].epoch == resync_at) {
			WRT_CHECK_STATUS(WR_E_MAP_RESYNC, st);
			resyncs++;
			f = find_full(fm, nfm, ls[i].epoch);
			WRT_CHECK(f != NULL);
			if (f == NULL)
				break;
			WRT_CHECK_STATUS(WR_OK, rig_decode(&cfg, f->p, f->n, &s[1 - cur], &why));
			cur = 1 - cur;
			continue;
		}
		if (st != WR_OK) {
			fprintf(stderr, "chain %s: epoch %u: %s\n", label, ls[i].epoch, why.what != NULL ? why.what : "?");
			WRT_CHECK_STATUS(WR_OK, st);
			break;
		}
		cur = 1 - cur;
		WRT_CHECK_U64(islot_map(&s[cur])->epoch, ls[i].epoch);
		f = find_full(fm, nfm, ls[i].epoch);
		if (f != NULL) { /* the monitor's own full map of this epoch */
			islot real;

			islot_new(&real, RIG_SLOT_BYTES);
			WRT_CHECK_STATUS(WR_OK, rig_decode(&cfg, f->p, f->n, &real, &why));
			rig_cmp_core(islot_map(&s[cur]), islot_map(&real));
			islot_free(&real);
			checked++;
		}
	}
	WRT_CHECK_U64(checked, resync_at != 0 ? nfm - 1u : nfm);
	WRT_CHECK_U64(resyncs, resync_at != 0 ? 1 : 0);
	islot_free(&s[0]);
	islot_free(&s[1]);
	free(base);
	wrt_mg_free_lines(ls, nl);
	for (i = 0; i < nfm; i++)
		free(fm[i].p);
}

static void test_public_chains(void)
{
	/* the pools of the capture: created, split, merged, renamed, deleted, tiered, erasure coded, weight sets */
	static const char *const a[] = {".mgr", "winrbd", "wrtest-mb-p16", "wrtest-mb-p12", "wrtest-mb-p7", "wrtest-mb-np", "wrtest-mb-leg", "wrtest-mb-s4"};
	static const char *const b[] = {"wrtest-mb-host", "wrtest-mb-sp", "wrtest-mb-mg", "wrtest-mb-del", "wrtest-mb-ren", "wrtest-mb-ec", "wrtest-mb-base", "wrtest-mb-cache"};
	/* the renamed pool without the one it was renamed from: its record is not in the held map */
	static const char *const c[] = {"winrbd", "wrtest-mb-ws", "wrtest-mb-ren"};
	/* nothing tracked, and a name nothing has */
	static const char *const d[] = {"no-such-pool"};

	run_mapb(a, 8, 0, "a");
	run_mapb(b, 8, 0, "b");
	run_mapb(c, 3, 848, "c");
	run_mapb(d, 1, 0, "d");
	run_mapb(NULL, 0, 0, "none");
}


/* ---- random sequences against the model ---------------------------------------------------------------------------- */

static void r_pg_list(wrt_mg_vec *v, uint64_t pool, uint32_t seed, const int32_t *osds, uint32_t n)
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

static void r_pg_items(wrt_mg_vec *v, uint64_t pool, uint32_t seed, const int32_t *flat, uint32_t np)
{
	wrt_mg_pg_items e;
	uint32_t i;

	memset(&e, 0, sizeof(e));
	e.pg.pool = pool;
	e.pg.seed = seed;
	for (i = 0; i < np; i++) {
		wrt_mg_pair p;

		p.from = flat[2u * i];
		p.to = flat[2u * i + 1u];
		WRT_MG_PUSH(e.items, wrt_mg_pair, p);
	}
	WRT_MG_PUSH(*v, wrt_mg_pg_items, e);
}

static void r_pg_osd(wrt_mg_vec *v, uint64_t pool, uint32_t seed, int32_t osd)
{
	wrt_mg_pg_osd e;

	e.pg.pool = pool;
	e.pg.seed = seed;
	e.osd = osd;
	WRT_MG_PUSH(*v, wrt_mg_pg_osd, e);
}

static void r_pg(wrt_mg_vec *v, uint64_t pool, uint32_t seed)
{
	wrt_mg_pg p;

	p.pool = pool;
	p.seed = seed;
	WRT_MG_PUSH(*v, wrt_mg_pg, p);
}

static int rig_pool4_absent(const rig *g) { return wri_map_pools(rig_held(g))[2].present == 0; }

#define R_POOLS 4u
#define R_SEEDS 12u

/* The five tables' upserts and removals of one random incremental: keys ascend (pool, then seed) in every list. */
static void r_tables(wrt_mg_rng *rng, wrt_mg_inc *inc, uint32_t max_osd)
{
	static const uint64_t pools[R_POOLS] = {1, 2, 3, 9};
	uint32_t pi, sd, q;
	int32_t v[8];

	for (pi = 0; pi < R_POOLS; pi++) {
		for (sd = 0; sd < R_SEEDS; sd++) {
			uint32_t len;

			if (wrt_mg_rng_below(rng, 5) == 0) { /* pg_temp: an upsert, empty = removal */
				len = wrt_mg_rng_below(rng, 5);
				for (q = 0; q < len; q++)
					v[q] = (int32_t)wrt_mg_rng_below(rng, max_osd ? max_osd : 1);
				r_pg_list(&inc->new_pg_temp, pools[pi], sd, v, len);
			}
			if (wrt_mg_rng_below(rng, 5) == 0) /* primary_temp: -1 removes */
				r_pg_osd(&inc->new_primary_temp, pools[pi], sd, wrt_mg_rng_below(rng, 4) == 0 ? -1 : (int32_t)wrt_mg_rng_below(rng, max_osd ? max_osd : 1));
			if (wrt_mg_rng_below(rng, 6) == 0) {
				len = wrt_mg_rng_below(rng, 4);
				for (q = 0; q < len; q++)
					v[q] = (int32_t)wrt_mg_rng_below(rng, max_osd ? max_osd : 1);
				r_pg_list(&inc->new_pg_upmap, pools[pi], sd, v, len);
			}
			if (wrt_mg_rng_below(rng, 6) == 0)
				r_pg(&inc->old_pg_upmap, pools[pi], sd);
			if (wrt_mg_rng_below(rng, 6) == 0) {
				len = wrt_mg_rng_below(rng, 4);
				for (q = 0; q < 2u * len; q++)
					v[q] = (int32_t)wrt_mg_rng_below(rng, max_osd ? max_osd : 1);
				r_pg_items(&inc->new_pg_upmap_items, pools[pi], sd, v, len);
			}
			if (wrt_mg_rng_below(rng, 6) == 0)
				r_pg(&inc->old_pg_upmap_items, pools[pi], sd);
			if (wrt_mg_rng_below(rng, 6) == 0)
				r_pg_osd(&inc->new_pg_upmap_primary, pools[pi], sd, (int32_t)wrt_mg_rng_below(rng, max_osd ? max_osd : 1));
			if (wrt_mg_rng_below(rng, 6) == 0)
				r_pg(&inc->old_pg_upmap_primary, pools[pi], sd);
		}
	}
}

static void r_av(wrt_mg_rng *rng, wrt_mg_addrvec *av, uint32_t osd)
{
	uint8_t ip6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	ip6[15] = (uint8_t)osd;
	switch (wrt_mg_rng_below(rng, 5)) {
	case 0:
		wrt_mg_av_v1(av, 0x0a4d0000u + osd, (uint16_t)(7000 + osd), (uint32_t)wrt_mg_rng_next(rng));
		break;
	case 1:
		wrt_mg_av_v6(av, ip6, (uint16_t)(7100 + osd), (uint32_t)wrt_mg_rng_next(rng));
		break;
	case 2:
		wrt_mg_av_empty(av);
		break;
	default:
		wrt_mg_av_v2v1(av, 0x0a4d0000u + osd, (uint16_t)(7200 + osd), (uint32_t)wrt_mg_rng_next(rng));
		break;
	}
}

/*
 * A cluster of 4 to 24 OSDs and a few epochs of random changes: weights, affinity, state toggles and destroys, new up OSDs,
 * growth and shrinking, and the tables of four pools (pools 1 and 2 are tracked), pool records replaced and removed, new pools.
 * The core must accept every incremental the model accepts and end in the same state (rig_step).
 */
static void test_random_sequences(void)
{
	static const char *const names[] = {"pool1", "pool2", "pool4"};
	uint64_t seed;
	unsigned total_steps = 0;

	for (seed = 1; seed <= 60; seed++) {
		wrt_mg_rng rng;
		wrt_mg_map d;
		wrt_mg_cluster_spec s;
		rig g;
		unsigned step;
		uint32_t next_pool = 4;

		wrt_mg_rng_seed(&rng, seed * 7919u);
		wrt_mg_cluster_spec_init(&s, 4u + wrt_mg_rng_below(&rng, 21));
		s.n_pools = 3;
		s.pg_num = 16;
		s.n_upmap_items = 3;
		s.n_upmap = 2;
		s.n_pg_temp = 3;
		s.n_primary_temp = 2;
		s.n_upmap_primaries = 2;
		s.n_affinity = (seed & 1u) ? 2u : 0u;
		s.up_pct = 70;
		s.never_up_pct = 10;
		s.out_pct = 10;
		s.epoch = 5;
		s.seed = seed;
		s.ipv6_every = (seed % 3u == 0) ? 3 : 0;
		s.v1_only_every = (seed % 4u == 0) ? 5 : 0;
		WRT_CHECK(wrt_mg_build_map(&d, &s) == 0);
		WRT_CHECK(rig_start(&g, &d, 4096, (int)(seed & 1u), names, 3));
		wrt_mg_map_free(&d);

		for (step = 0; step < 10; step++) {
			wrt_mg_inc inc;
			uint32_t max_osd = (uint32_t)g.model.max_osd, i, n, k;
			wr_errinfo why;
			wr_status st;
			int32_t want[3] = {RIG_WANT_ANY, RIG_WANT_ANY, RIG_WANT_ANY};

			wrt_mg_inc_init(&inc, g.model.fsid, g.model.epoch + 1u);
			if (wrt_mg_rng_below(&rng, 6) == 0)
				inc.new_flags = (int32_t)wrt_mg_rng_below(&rng, 0x10000);
			if (wrt_mg_rng_below(&rng, 5) == 0) { /* resize: grow, shrink, or stay */
				uint32_t nm = 1u + wrt_mg_rng_below(&rng, 2u * max_osd + 2u);

				inc.new_max_osd = (int32_t)nm;
				max_osd = nm;
			}
			n = wrt_mg_rng_below(&rng, 4);
			for (k = 0; k < n && max_osd > 0; k++) {
				uint32_t id = wrt_mg_rng_below(&rng, max_osd);

				wrt_mg_inc_set_weight(&inc, (int32_t)id, wrt_mg_rng_below(&rng, 3) == 0 ? 0u : 0x10000u - wrt_mg_rng_below(&rng, 0x8000));
			}
			n = wrt_mg_rng_below(&rng, 3);
			for (k = 0; k < n && max_osd > 0; k++)
				wrt_mg_inc_set_affinity(&inc, (int32_t)wrt_mg_rng_below(&rng, max_osd), wrt_mg_rng_below(&rng, 0x10001u));
			n = wrt_mg_rng_below(&rng, 4);
			for (k = 0; k < n && max_osd > 0; k++) {
				static const uint32_t masks[] = {0, 1, 2, 3, 8, 4, 0x1000, 0x1001};
				wrt_mg_osd_u32 e;

				e.osd = (int32_t)wrt_mg_rng_below(&rng, max_osd);
				e.val = masks[wrt_mg_rng_below(&rng, 8)];
				WRT_MG_PUSH(inc.new_state, wrt_mg_osd_u32, e);
			}
			n = wrt_mg_rng_below(&rng, 4);
			for (k = 0; k < n && max_osd > 0; k++) {
				wrt_mg_addrvec av;
				uint32_t id = wrt_mg_rng_below(&rng, max_osd);

				r_av(&rng, &av, id);
				wrt_mg_inc_mark_up(&inc, (int32_t)id, &av);
			}
			r_tables(&rng, &inc, max_osd);
			if (wrt_mg_rng_below(&rng, 5) == 0) { /* a pool record replaced (the tracked ones and an untracked one) */
				for (i = 1; i <= 3; i++) {
					wrt_mg_pool_ent pe;

					if (wrt_mg_rng_below(&rng, 2))
						continue;
					pe.id = (int64_t)i;
					wrt_mg_pool_init(&pe.p, 32);
					pe.p.size = (uint8_t)(1 + wrt_mg_rng_below(&rng, 3));
					pe.p.min_size = 1;
					pe.p.pg_num = pe.p.pgp_num = pe.p.pg_num_target = pe.p.pgp_num_target = pe.p.pg_num_pending = 8u + wrt_mg_rng_below(&rng, 40);
					WRT_MG_PUSH(inc.new_pools, wrt_mg_pool_ent, pe);
				}
			}
			if (wrt_mg_rng_below(&rng, 12) == 0) { /* a new pool named like a tracked name that is absent, with the new ceiling */
				wrt_mg_pool_ent pe;
				wrt_mg_pname pn;

				pe.id = (int64_t)next_pool;
				wrt_mg_pool_init(&pe.p, 32);
				WRT_MG_PUSH(inc.new_pools, wrt_mg_pool_ent, pe);
				memset(&pn, 0, sizeof(pn));
				pn.id = (int64_t)next_pool;
				snprintf(pn.name, sizeof(pn.name), "%s", rig_pool4_absent(&g) ? "pool4" : "other");
				WRT_MG_PUSH(inc.new_pool_names, wrt_mg_pname, pn);
				inc.new_pool_max = (int64_t)next_pool++;
			}
			if (wrt_mg_rng_below(&rng, 16) == 0) { /* a pool removed */
				int64_t id = (int64_t)(1 + wrt_mg_rng_below(&rng, 3));

				WRT_MG_PUSH(inc.old_pools, int64_t, id);
			}
			st = rig_step(&g, &inc, want, &why);
			if (st != WR_OK)
				fprintf(stderr, "seed %llu step %u: %s\n", (unsigned long long)seed, step, why.what != NULL ? why.what : "?");
			WRT_CHECK_STATUS(WR_OK, st);
			wrt_mg_inc_free(&inc);
			if (st != WR_OK)
				break;
			total_steps++;
		}
		rig_end(&g);
	}
	WRT_CHECK(total_steps >= 400);
}

/* ---- the lab's map of epoch 42 and what can happen to it next ---------------------------------------------------------- */

/*
 * Incrementals of epoch 43 for the real full map of epoch 42 (harness/vectors/osdmap/full-e42.hex: three OSDs, pools .mgr and
 * winrbd, no tables): the shapes the real chain does not have, applied by the core and the model. The tracked names are the ones
 * of fuzz_osdmap_inc.c, so the same bytes are its seeds: when WRT_INC_SEEDS_DIR is set the test writes every incremental it builds
 * (and the 89 real ones, as they are and with their epoch patched to 43) there as lab-*.bin / real-*.bin.
 */
static const char *const LAB_NAMES[] = {".mgr", "winrbd", "pool1", "pool2"};

static void seed_write(const char *name, const uint8_t *p, size_t n)
{
	const char *dir = getenv("WRT_INC_SEEDS_DIR");
	char path[512];
	FILE *f;

	if (dir == NULL || dir[0] == 0)
		return;
	snprintf(path, sizeof(path), "%s/%s.bin", dir, name);
	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "cannot write %s\n", path);
		WRT_CHECK(0);
		return;
	}
	if (fwrite(p, 1, n, f) != n)
		WRT_CHECK(0 && "short write of a seed");
	fclose(f);
}

static int lab_start(rig *g, wrt_mg_map *d)
{
	uint8_t *raw;
	size_t n;
	int ok;

	if (wrt_mg_load_hex_file(wrt_vec_path("osdmap/full-e42.hex"), &raw, &n) != 0) {
		WRT_CHECK(0 && "full-e42.hex");
		return 0;
	}
	WRT_CHECK(wrt_mg_map_parse(raw, n, d) == 0);
	free(raw);
	ok = rig_start(g, d, 4096, 1, LAB_NAMES, 4);
	WRT_CHECK(ok);
	return ok;
}

/* Encode, write the seed, apply. want == WR_OK: the core and the model accept it and agree; otherwise only the core is asked. */
static void lab_run2(rig *g, const char *name, wrt_mg_inc *inc, wr_status want, const int32_t *want_pools, int use_model)
{
	wrt_mg_buf b;
	wr_errinfo why;
	char label[96];
	wr_status st;
	int rc = 0;

	memset(&b, 0, sizeof(b));
	WRT_CHECK(wrt_mg_inc_encode(inc, &b) == 0);
	snprintf(label, sizeof(label), "lab-%s", name);
	seed_write(label, b.p, b.len);
	if (use_model) {
		st = rig_step_blob(g, b.p, b.len, inc, want_pools, &rc, &why);
		if (st != WR_OK || rc != WRT_MG_E_OK)
			fprintf(stderr, "  case %s: status %d (%s), model %d\n", name, (int)st, why.what != NULL ? why.what : "?", rc);
		WRT_CHECK_STATUS(WR_OK, st);
		WRT_CHECK_STATUS(WRT_MG_E_OK, rc);
	} else {
		islot dst;

		islot_new(&dst, RIG_SLOT_BYTES);
		st = rig_apply(&g->cfg, rig_held(g), b.p, b.len, &dst, &why);
		islot_free(&dst);
		if (st != want)
			fprintf(stderr, "  case %s: status %d, want %d\n", name, (int)st, (int)want);
		WRT_CHECK_STATUS(want, st);
	}
	wrt_mg_buf_free(&b);
	wrt_mg_inc_free(inc);
}

/* Applied by the core and the model when the core is expected to accept it; only by the core when it is expected to refuse. */
static void lab_run(rig *g, const char *name, wrt_mg_inc *inc, wr_status want, const int32_t *want_pools)
{
	lab_run2(g, name, inc, want, want_pools, want == WR_OK);
}

static void lab_pool(wrt_mg_inc *inc, int64_t id, const char *name, uint32_t pg_num, int shape)
{
	wrt_mg_pool_ent pe;
	wrt_mg_pname pn;

	pe.id = id;
	wrt_mg_pool_init(&pe.p, 32);
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

static void lab_state(wrt_mg_inc *inc, int32_t osd, uint32_t mask)
{
	wrt_mg_osd_u32 e;

	e.osd = osd;
	e.val = mask;
	WRT_MG_PUSH(inc->new_state, wrt_mg_osd_u32, e);
}

static void test_lab_scenarios(void)
{
	rig g;
	wrt_mg_map d;
	wrt_mg_inc inc;
	wrt_mg_addrvec av;
	wrt_mg_crush cr;
	const int32_t t2[2] = {1, 0}, t1[1] = {2}, u3[3] = {2, 1, 0}, big[40] = {0};
	const int32_t flat[4] = {0, 1, 1, 2};
	unsigned i;
	/* the cases that start from the plain map: one fresh start each */
#define LAB_BEGIN() do { WRT_CHECK(lab_start(&g, &d)); wrt_mg_inc_init(&inc, g.model.fsid, g.model.epoch + 1u); } while (0)
#define LAB_END() do { wrt_mg_map_free(&d); rig_end(&g); } while (0)

	LAB_BEGIN();
	lab_run(&g, "noop", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.new_flags = 0x5800001;
	lab_run(&g, "flags", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_inc_mark_down(&inc, 1);
	lab_run(&g, "down-osd1", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_av_v2v1(&av, 0x0a4d000au, 6900, 4242);
	wrt_mg_inc_mark_up(&inc, 1, &av);
	lab_run(&g, "up-osd1-new-addr", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_av_v1(&av, 0x0a4d000au, 6901, 4243);
	wrt_mg_inc_mark_up(&inc, 2, &av);
	lab_run(&g, "up-v1-only", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	{
		uint8_t ip6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};

		wrt_mg_av_v6(&av, ip6, 6902, 4244);
		wrt_mg_inc_mark_up(&inc, 0, &av);
	}
	lab_run(&g, "up-v6", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_inc_set_weight(&inc, 2, 0);
	lab_run(&g, "weight-out", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_inc_set_weight(&inc, 0, 0x8000);
	wrt_mg_inc_set_affinity(&inc, 1, 0x4000);
	lab_run(&g, "weight-affinity", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_state(&inc, 2, 1);
	lab_run(&g, "destroy-osd2", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_state(&inc, 2, 1);
	wrt_mg_av_v2v1(&av, 0x0a4d000bu, 6903, 4245);
	wrt_mg_inc_mark_up(&inc, 2, &av);
	lab_run(&g, "destroy-readd", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.new_max_osd = 6;
	wrt_mg_inc_set_weight(&inc, 3, 0x10000);
	wrt_mg_inc_set_affinity(&inc, 5, 0x2000);
	wrt_mg_av_v2v1(&av, 0x0a4d000cu, 6904, 4246);
	wrt_mg_inc_mark_up(&inc, 4, &av);
	lab_run(&g, "grow", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.new_max_osd = 2;
	lab_run(&g, "shrink", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.new_max_osd = 0;
	lab_run(&g, "shrink-zero", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	r_pg_list(&inc.new_pg_temp, 2, 0, t2, 2);
	r_pg_list(&inc.new_pg_temp, 2, 1, t1, 1);
	r_pg_osd(&inc.new_primary_temp, 1, 0, -1);
	r_pg_osd(&inc.new_primary_temp, 2, 0, 1);
	lab_run(&g, "temps", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	r_pg_items(&inc.new_pg_upmap_items, 2, 2, flat, 2);
	r_pg_list(&inc.new_pg_upmap, 2, 3, u3, 3);
	r_pg_osd(&inc.new_pg_upmap_primary, 2, 4, 1);
	r_pg(&inc.old_pg_upmap, 2, 7);
	r_pg(&inc.old_pg_upmap_items, 2, 8);
	r_pg(&inc.old_pg_upmap_primary, 2, 9);
	lab_run(&g, "upmaps", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	r_pg_list(&inc.new_pg_temp, 2, 5, big, 32);
	r_pg_list(&inc.new_pg_temp, 7, 5, big, 40);
	lab_run(&g, "long-vector-ok", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	r_pg_list(&inc.new_pg_temp, 2, 5, big, 33);
	lab_run(&g, "long-vector", &inc, WR_E_MAP_BUDGET, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 2, NULL, 64, 0);
	lab_run(&g, "pool-replace", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 3, "pool1", 16, 0);
	inc.new_pool_max = 3;
	lab_run(&g, "pool-new", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 3, "pool1", 16, 0);
	lab_run(&g, "pool-new-no-ceiling", &inc, WR_E_MAP_RESYNC, NULL);
	LAB_END();
	LAB_BEGIN();
	{
		wrt_mg_pname pn;

		memset(&pn, 0, sizeof(pn));
		pn.id = 2;
		snprintf(pn.name, sizeof(pn.name), "renamed");
		WRT_MG_PUSH(inc.new_pool_names, wrt_mg_pname, pn);
	}
	lab_run(&g, "pool-rename-away", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	{
		wrt_mg_pname pn;

		memset(&pn, 0, sizeof(pn));
		pn.id = 7;
		snprintf(pn.name, sizeof(pn.name), "pool2");
		WRT_MG_PUSH(inc.new_pool_names, wrt_mg_pname, pn);
	}
	lab_run(&g, "pool-rename-in", &inc, WR_E_MAP_RESYNC, NULL);
	LAB_END();
	LAB_BEGIN();
	WRT_MG_PUSH(inc.old_pools, int64_t, 2);
	lab_run(&g, "pool-old", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 2, NULL, 32, 0);
	WRT_MG_PUSH(inc.old_pools, int64_t, 2);
	lab_run(&g, "pool-both", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 2, NULL, 32, WRT_MG_SHAPE_ERASURE);
	{
		int32_t want[4] = {WR_OK, WR_E_POOL_UNSUPPORTED, WR_OK, WR_OK};

		lab_run(&g, "pool-erasure", &inc, WR_OK, want);
	}
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 2, NULL, 32, 0);
	WRT_MG_E(inc.new_pools, wrt_mg_pool_ent, 0).p.compat = 33;
	lab_run(&g, "pool-bad-compat", &inc, WR_E_MAP_VERSION, NULL);
	LAB_END();
	LAB_BEGIN();
	WRT_CHECK(wrt_mg_crush_parse(d.crush, d.crush_len, &cr) == 0);
	wrt_mg_inc_set_crush(&inc, &cr);
	lab_run(&g, "crush-same", &inc, WR_OK, NULL);
	wrt_mg_crush_free(&cr);
	LAB_END();
	LAB_BEGIN();
	WRT_CHECK(wrt_mg_crush_parse(d.crush, d.crush_len, &cr) == 0);
	WRT_MG_E(cr.rules, wrt_mg_rule, 0).present = 0;
	wrt_mg_inc_set_crush(&inc, &cr);
	{
		int32_t want[4] = {RIG_WANT_ANY, RIG_WANT_ANY, RIG_WANT_ANY, RIG_WANT_ANY};

		lab_run(&g, "crush-no-rule", &inc, WR_OK, want);
	}
	wrt_mg_crush_free(&cr);
	LAB_END();
	LAB_BEGIN();
	inc.crush = (uint8_t *)malloc(7);
	memcpy(inc.crush, "\0\0\1\0\1\2\3", 7);
	inc.crush_len = 7;
	lab_run(&g, "crush-bad", &inc, WR_E_CRUSH_ENCODING, NULL);
	LAB_END();

	/* embedded full maps: the next epoch (the model takes it too), a far one, a damaged one */
	LAB_BEGIN();
	{
		wrt_mg_map nm;

		WRT_CHECK(wrt_mg_map_clone(&d, &nm) == 0);
		nm.epoch = 43;
		nm.flags = 0x1234;
		wrt_mg_map_resize(&nm, 5);
		wrt_mg_inc_set_fullmap(&inc, &nm);
		lab_run(&g, "embedded", &inc, WR_OK, NULL);
		wrt_mg_map_free(&nm);
	}
	LAB_END();
	LAB_BEGIN();
	{
		wrt_mg_map nm;

		WRT_CHECK(wrt_mg_map_clone(&d, &nm) == 0);
		nm.epoch = 99;
		wrt_mg_inc_init(&inc, g.model.fsid, 99);
		wrt_mg_inc_set_fullmap(&inc, &nm);
		lab_run2(&g, "embedded-far", &inc, WR_OK, NULL, 0); /* the model wants the next epoch, the core does not for an embedded map */
		wrt_mg_map_free(&nm);
	}
	LAB_END();
	LAB_BEGIN();
	{
		wrt_mg_map nm;

		WRT_CHECK(wrt_mg_map_clone(&d, &nm) == 0);
		nm.epoch = 43;
		wrt_mg_inc_set_fullmap(&inc, &nm);
		inc.fullmap[200] ^= 0x10;
		inc.fullmap_len -= 1;
		lab_run(&g, "embedded-cut", &inc, WR_E_MAP_CORRUPT, NULL);
		wrt_mg_map_free(&nm);
	}
	LAB_END();

	/* identity, envelope and structure */
	LAB_BEGIN();
	inc.fsid[4] ^= 1;
	lab_run(&g, "wrong-fsid", &inc, WR_E_MAP_FSID, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.epoch = 45;
	lab_run(&g, "epoch-gap", &inc, WR_E_MAP_EPOCH, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.client_v = 8;
	wrt_mg_inc_set_weight(&inc, 1, 0x9000);
	lab_run(&g, "block-v8", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.wrapper_v = 7;
	wrt_mg_inc_set_weight(&inc, 1, 0x9000);
	lab_run(&g, "wrapper-v7", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.wrapper_v = 9;
	inc.wrapper_tail = 6;
	inc.client_v = 11;
	inc.client_tail = 9;
	inc.osd_v = 13;
	inc.osd_tail = 4;
	lab_run(&g, "tails", &inc, WR_OK, NULL);
	LAB_END();
	LAB_BEGIN();
	lab_pool(&inc, 3, "x", 8, 0);
	lab_pool(&inc, 2, "y", 8, 0);
	lab_run(&g, "unsorted-pools", &inc, WR_E_MAP_CORRUPT, NULL);
	LAB_END();
	LAB_BEGIN();
	r_pg_list(&inc.new_pg_temp, 2, 4, t2, 2);
	r_pg_list(&inc.new_pg_temp, 2, 2, t2, 2);
	lab_run(&g, "unsorted-pgtemp", &inc, WR_E_MAP_CORRUPT, NULL);
	LAB_END();
	LAB_BEGIN();
	wrt_mg_inc_set_weight(&inc, 3, 1);
	lab_run(&g, "osd-out-of-range", &inc, WR_E_MAP_CORRUPT, NULL);
	LAB_END();
	LAB_BEGIN();
	inc.new_max_osd = 20;
	lab_run(&g, "max-osd-above-alt-limit", &inc, WR_OK, NULL); /* the main set allows it, the second one (limit 16) does not */
	LAB_END();
	LAB_BEGIN();
	inc.client_compat = 10;
	lab_run(&g, "compat-too-new", &inc, WR_E_MAP_VERSION, NULL);
	LAB_END();

	/* a real incremental of the lab chain, with the epoch patched to the one that follows 42, applies or fails on its own terms:
	 * the bytes are seeds (the CRC is wrong after the patch, which the first run of the fuzz target does not check) */
	{
		wrt_mg_line *ls;
		size_t nl;

		WRT_CHECK(wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &ls, &nl) == 0);
		for (i = 0; i < nl; i++) {
			char name[64];
			uint8_t *c = (uint8_t *)malloc(ls[i].n);

			snprintf(name, sizeof(name), "real-%02u", ls[i].epoch);
			seed_write(name, ls[i].p, ls[i].n);
			memcpy(c, ls[i].p, ls[i].n);
			if (ls[i].n > 32) {
				c[28] = 43;
				c[29] = c[30] = c[31] = 0;
				snprintf(name, sizeof(name), "real-%02u-e43", ls[i].epoch);
				seed_write(name, c, ls[i].n);
			}
			free(c);
		}
		wrt_mg_free_lines(ls, nl);
	}
#undef LAB_BEGIN
#undef LAB_END
	(void)i;
}

int main(void)
{
	test_lab_chain();
	test_public_chains();
	test_random_sequences();
	test_lab_scenarios();
	return wrt_finish();
}
