/* SPDX-License-Identifier: MIT */
/*
 * test_place_pipe.c - object name to PG to OSD sets, end to end (core/src/osdmap/wri_place.c).
 *
 *  - ps (wri_place_hash): the names of hash-vectors.json with both pool hashes; a namespace (the 0x1f separator only when it
 *    is non-empty), a locator key as the subject and an embedded NUL against the contiguous hash over random splits; the
 *    4,096-byte cap, an unsupported object_hash, bad arguments;
 *  - pg seed and pps (wri_place_pg_seed, wri_place_pps): the known answers of hash-vectors.json, then pg_num and pgp_num that
 *    are not powers of two, pgp_num below pg_num, a pool without HASHPSPOOL, against the model of wrt_mapgen;
 *  - wri_place_pg on random clusters built by wrt_mapgen (racks, hosts, classes, tunable profiles, choose_args, upmaps, temps,
 *    affinity, down and out OSDs): the same answer as the mapper plus the model stages, and the invariants of a result
 *    (members exist and are up, primaries belong to their set or are -1, no duplicates in up without a pg_upmap);
 *  - a PG that cannot be mapped (all OSDs down or out) is a successful, empty result; pools that are absent, unsupported or
 *    without a rule, a map without CRUSH, the work budget, bad arguments.
 *
 * The answers of Ceph itself are in test_place_real.c.
 */
#include "place_rig.h"

#define WORK 1000000u

static wrt_mg_rng rng;
static wri_crush_ws ws;

static uint32_t below(uint32_t n)
{
	return wrt_mg_rng_below(&rng, n);
}

static uint32_t hexu(const char *s)
{
	return (uint32_t)strtoul(s, NULL, 16);
}

static wri_map_pool mkpool(int64_t id, uint32_t pg_num, uint32_t pgp_num, int hashpspool, uint32_t object_hash)
{
	wri_map_pool p;

	memset(&p, 0, sizeof(p));
	p.id = id;
	p.flags = hashpspool ? WRI_POOL_F_HASHPSPOOL : 0u;
	p.pg_num = pg_num;
	p.pgp_num = pgp_num;
	p.pg_num_mask = wrt_mg_pg_mask(pg_num);
	p.pgp_num_mask = wrt_mg_pg_mask(pgp_num);
	p.present = 1;
	p.type = WRI_POOL_REPLICATED;
	p.size = 3;
	p.min_size = 2;
	p.object_hash = (uint8_t)object_hash;
	return p;
}

static uint32_t hash_of(const wri_map_pool *p, const uint8_t *name, uint32_t nn, const uint8_t *ns, uint32_t nsn, const uint8_t *key,
			uint32_t kn)
{
	wri_oid o;
	uint32_t ps = 0xdeadbeefu;

	o.name = name;
	o.name_len = nn;
	o.nspace = ns;
	o.nspace_len = nsn;
	o.key = key;
	o.key_len = kn;
	WRT_CHECK_STATUS(WR_OK, wri_place_hash(p, &o, &ps));
	return ps;
}

/* ---- ps ----------------------------------------------------------------------------------------------------- */

static void t_hash_vectors(void)
{
	wrt_json j;
	wrt_tok arr;
	size_t i;
	wri_map_pool pj = mkpool(2, 32, 32, 1, WRI_STR_HASH_RJENKINS), pl = mkpool(2, 32, 32, 1, WRI_STR_HASH_LINUX);

	WRT_CHECK(wrt_json_load_vec(&j, "crush/hash-vectors.json") == 0);
	arr = wrt_json_get(&j, wrt_json_root(&j), "rjenkins_str");
	WRT_CHECK(wrt_json_count(&j, arr) >= 10);
	for (i = 0; i < wrt_json_count(&j, arr); i++) {
		wrt_tok e = wrt_json_at(&j, arr, i);
		uint8_t *in = NULL;
		size_t n = 0;
		char *rj = wrt_json_strdup(&j, wrt_json_get(&j, e, "rjenkins")), *lx = wrt_json_strdup(&j, wrt_json_get(&j, e, "linux_dcache"));
		uint8_t other[3] = {'x', 'y', 'z'};

		WRT_CHECK(wrt_json_get_hex(&j, e, "input_hex", &in, &n) == 0 && rj != NULL && lx != NULL);
		if (rj != NULL && lx != NULL) {
			/* the name, with no namespace and no key */
			WRT_CHECK_U64(hash_of(&pj, in, (uint32_t)n, NULL, 0, NULL, 0), hexu(rj));
			WRT_CHECK_U64(hash_of(&pl, in, (uint32_t)n, NULL, 0, NULL, 0), hexu(lx));
			/* as a locator key: the name is ignored */
			WRT_CHECK_U64(hash_of(&pj, other, 3, NULL, 0, in, (uint32_t)n), n == 0 ? hash_of(&pj, other, 3, NULL, 0, NULL, 0) : hexu(rj));
			WRT_CHECK_U64(hash_of(&pl, other, 3, NULL, 0, in, (uint32_t)n), n == 0 ? hash_of(&pl, other, 3, NULL, 0, NULL, 0) : hexu(lx));
		}
		free(rj);
		free(lx);
		free(in);
	}
	/* stable_mod and pps of the same file */
	arr = wrt_json_get(&j, wrt_json_root(&j), "stable_mod");
	for (i = 0; i < wrt_json_count(&j, arr); i++) {
		wrt_tok e = wrt_json_at(&j, arr, i);
		int ok = 0;
		uint32_t x = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "x"), &ok), b = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "b"), &ok),
			 m = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "mask"), &ok),
			 want = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "result"), &ok);
		wri_map_pool p = mkpool(1, b, b, 1, 2);

		p.pg_num_mask = m;
		WRT_CHECK(ok);
		WRT_CHECK_U64(wri_place_pg_seed(&p, x), want);
	}
	arr = wrt_json_get(&j, wrt_json_root(&j), "pps_hashpspool");
	WRT_CHECK(wrt_json_count(&j, arr) >= 3);
	for (i = 0; i < wrt_json_count(&j, arr); i++) {
		wrt_tok e = wrt_json_at(&j, arr, i);
		int ok = 0;
		int64_t pool = wrt_json_int(&j, wrt_json_get(&j, e, "pool"), &ok);
		uint32_t seed = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, e, "seed"), &ok);
		char *want = wrt_json_strdup(&j, wrt_json_get(&j, e, "pps"));
		wri_map_pool p = mkpool(pool, 32, 32, 1, 2);

		WRT_CHECK(ok && want != NULL);
		if (want != NULL)
			WRT_CHECK_U64(wri_place_pps(&p, seed), hexu(want));
		free(want);
	}
	wrt_json_free(&j);
}

static void fill(uint8_t *p, uint32_t n)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)below(256);
}

static void t_hash_pieces(void)
{
	static const uint32_t lens[] = {0, 1, 2, 11, 12, 13, 23, 24, 25, 35, 36, 37, 255, 256};
	uint32_t hid, a, b, it;
	uint8_t buf[600], cat[700];
	const uint8_t nul[3] = {'a', 0, 'b'}, a_only[1] = {'a'};

	memset(buf, 0x42, sizeof(buf));
	for (hid = 1; hid <= 2; hid++) {
		wri_map_pool p = mkpool(7, 64, 64, 1, hid);

		for (a = 0; a < sizeof(lens) / sizeof(lens[0]); a++)
			for (b = 0; b < sizeof(lens) / sizeof(lens[0]); b++) {
				uint32_t nn = lens[a], nsn = lens[b];
				uint8_t name[300], ns[300];
				int ok = 0;

				fill(name, nn);
				fill(ns, nsn);
				/* namespace + 0x1f + name; the separator only when the namespace is non-empty */
				memcpy(cat, ns, nsn);
				cat[nsn] = 0x1f;
				memcpy(cat + nsn + 1u, name, nn);
				if (nsn != 0) {
					WRT_CHECK_U64(hash_of(&p, name, nn, ns, nsn, NULL, 0), wri_str_hash(hid, cat, nsn + 1u + nn, &ok));
				} else {
					WRT_CHECK_U64(hash_of(&p, name, nn, ns, nsn, NULL, 0), wri_str_hash(hid, name, nn, &ok));
				}
				WRT_CHECK(ok);
				/* the key is the subject: same value for any name */
				WRT_CHECK_U64(hash_of(&p, buf, 17, ns, nsn, name, nn == 0 ? 0u : nn),
					      nn == 0 ? hash_of(&p, buf, 17, ns, nsn, NULL, 0) : hash_of(&p, name, nn, ns, nsn, NULL, 0));
			}
		/* random splits of random buffers */
		for (it = 0; it < 3000; it++) {
			uint32_t nn = below(200), nsn = below(60) == 0 ? 0u : 1u + below(60), kn = below(3) == 0 ? below(100) : 0u;
			uint8_t name[300], ns[100], key[100];
			uint32_t sl = kn != 0 ? kn : nn;
			const uint8_t *subj = kn != 0 ? key : name;
			int ok = 0, want_ok;
			uint32_t want, total;

			fill(name, nn);
			fill(ns, nsn);
			fill(key, kn);
			if (nsn != 0) {
				memcpy(cat, ns, nsn);
				cat[nsn] = 0x1f;
				memcpy(cat + nsn + 1u, subj, sl);
				total = nsn + 1u + sl;
				want = wri_str_hash(hid, cat, total, &ok);
			} else {
				want = wri_str_hash(hid, subj, sl, &ok);
			}
			want_ok = ok;
			WRT_CHECK(want_ok);
			WRT_CHECK_U64(hash_of(&p, name, nn, ns, nsn, key, kn), want);
		}
		/* an embedded NUL is a byte of the name */
		WRT_CHECK(hash_of(&p, nul, 3, NULL, 0, NULL, 0) != hash_of(&p, a_only, 1, NULL, 0, NULL, 0));
		{
			int ok = 0;

			WRT_CHECK_U64(hash_of(&p, nul, 3, NULL, 0, NULL, 0), wri_str_hash(hid, nul, 3, &ok));
		}
		/* NULL with length 0 is the empty string */
		WRT_CHECK_U64(hash_of(&p, NULL, 0, NULL, 0, NULL, 0), wri_str_hash(hid, NULL, 0, NULL));
	}
}

static void t_hash_limits(void)
{
	static uint8_t big[5000];
	wri_map_pool p = mkpool(1, 8, 8, 1, WRI_STR_HASH_RJENKINS);
	wri_oid o;
	uint32_t ps;

	memset(big, 'q', sizeof(big));
	memset(&o, 0, sizeof(o));
	/* exactly the cap: accepted, in every combination of the three parts */
	o.name = big;
	o.name_len = WRI_PLACE_NAME_MAX;
	ps = 1;
	WRT_CHECK_STATUS(WR_OK, wri_place_hash(&p, &o, &ps));
	WRT_CHECK_U64(ps, wri_str_hash_rjenkins(big, WRI_PLACE_NAME_MAX));
	o.name_len = 2000;
	o.nspace = big;
	o.nspace_len = 1000;
	o.key = big;
	o.key_len = WRI_PLACE_NAME_MAX - 3000u;
	WRT_CHECK_STATUS(WR_OK, wri_place_hash(&p, &o, &ps));
	/* one over: refused, the output is zero */
	o.key_len++;
	ps = 77;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_place_hash(&p, &o, &ps));
	WRT_CHECK_U64(ps, 0);
	memset(&o, 0, sizeof(o));
	o.name = big;
	o.name_len = WRI_PLACE_NAME_MAX + 1u;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_place_hash(&p, &o, &ps));
	o.name_len = 1;
	o.nspace = big;
	o.nspace_len = WRI_PLACE_NAME_MAX;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_place_hash(&p, &o, &ps));
	o.nspace_len = 0;
	o.key = big;
	o.key_len = WRI_PLACE_NAME_MAX;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_place_hash(&p, &o, &ps)); /* the name counts although the key is the subject */
	/* a length that would wrap a 32-bit sum */
	o.name_len = 0xffffffffu;
	o.key_len = 0xffffffffu;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_place_hash(&p, &o, &ps));
	/* object_hash other than 1 and 2 */
	memset(&o, 0, sizeof(o));
	o.name = big;
	o.name_len = 5;
	{
		uint32_t h;

		for (h = 0; h < 256; h++) {
			wri_map_pool q = mkpool(1, 8, 8, 1, h);
			wr_status st;

			ps = 5;
			st = wri_place_hash(&q, &o, &ps);
			if (h == 1 || h == 2) {
				WRT_CHECK_STATUS(WR_OK, st);
			} else {
				WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, st);
				WRT_CHECK_U64(ps, 0);
			}
		}
	}
	/* bad arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(&p, &o, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(NULL, &o, &ps));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(&p, NULL, &ps));
	memset(&o, 0, sizeof(o));
	o.name_len = 3; /* bytes announced, none given */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(&p, &o, &ps));
	o.name_len = 0;
	o.nspace_len = 1;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(&p, &o, &ps));
	o.nspace_len = 0;
	o.key_len = 1;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_hash(&p, &o, &ps));
}

/* ---- pg seed and pps ------------------------------------------------------------------------------------- */

static void t_seed_pps(void)
{
	static const uint32_t nums[] = {1, 2, 3, 4, 5, 7, 8, 12, 13, 31, 32, 33, 100, 127, 128, 129, 1000, 4096, 5000, 65537};
	static const int64_t ids[] = {0, 1, 2, 43, 0x7fffffff};
	uint32_t a, b, k, i;
	wri_map_pool z;

	for (a = 0; a < sizeof(nums) / sizeof(nums[0]); a++) {
		for (b = 0; b < sizeof(nums) / sizeof(nums[0]); b++) {
			uint32_t pg_num = nums[a], pgp_num = nums[b];

			if (pgp_num > pg_num)
				continue; /* the monitor keeps pgp_num <= pg_num; a pool the other way round is never seen */
			for (k = 0; k < 2; k++) {
				int64_t id = ids[(a + b + k) % (sizeof(ids) / sizeof(ids[0]))];
				wri_map_pool p = mkpool(id, pg_num, pgp_num, (int)k, 2);
				wrt_mg_pool mp;

				wrt_mg_pool_init(&mp, 32);
				mp.pg_num = pg_num;
				mp.pgp_num = pgp_num;
				mp.flags = k ? WRT_MG_POOL_HASHPSPOOL : 0u;
				for (i = 0; i < 400; i++) {
					uint32_t ps = i < 6 ? (i == 0 ? 0u : (i == 1 ? 0xffffffffu : (i == 2 ? pg_num : (i == 3 ? pg_num - 1u : (i == 4 ? pg_num + 1u : 0x80000000u)))))
							    : (uint32_t)wrt_mg_rng_next(&rng);
					uint32_t seed = wri_place_pg_seed(&p, ps);

					WRT_CHECK_U64(seed, wrt_mg_pg_seed(&mp, ps));
					WRT_CHECK(seed < pg_num);
					WRT_CHECK_U64(wri_place_pps(&p, seed), wrt_mg_pps(&mp, id, seed));
					/* masking first or not gives the same pps while pgp_num <= pg_num (crush note 3.2) */
					WRT_CHECK_U64(wri_place_pps(&p, seed), wrt_mg_pps(&mp, id, ps));
				}
				wrt_mg_pool_free(&mp);
			}
		}
	}
	/* a pool with a zero pg_num is refused by the decoder; the arithmetic still must not trap */
	z = mkpool(1, 0, 0, 1, 2);
	WRT_CHECK_U64(wri_place_pg_seed(&z, 12345), 0);
	(void)wri_place_pps(&z, 0);
	/* the legacy sum wraps in 32 bits */
	z = mkpool(5, 0xffffffffu, 0xffffffffu, 0, 2);
	z.pg_num_mask = z.pgp_num_mask = 0xffffffffu;
	WRT_CHECK_U64(wri_place_pps(&z, 0xfffffffeu), 3u);
	/* pg_num 1 (mask 0): every ps is PG 0 */
	z = mkpool(1, 1, 1, 1, 2);
	WRT_CHECK_U64(wri_place_pg_seed(&z, 0xffffffffu), 0);
	/* a pool id above 2^31 is only a 32-bit pattern in the hash */
	z = mkpool((int64_t)0x7fffffff, 32, 32, 1, 2);
	WRT_CHECK_U64(wri_place_pps(&z, 6), wri_crush_hash2(6, 0x7fffffffu));
}

/* ---- the pipeline on random clusters ---------------------------------------------------------------------- */

static int32_t rid(uint32_t n)
{
	uint32_t k = below(100);

	if (k < 75)
		return (int32_t)below(n);
	if (k < 82)
		return WRI_OSD_NONE;
	if (k < 90)
		return (int32_t)(n + below(3));
	if (k < 95)
		return -1;
	return 100000 + (int32_t)below(100);
}

static int has_list(const wrt_mg_vec *v, uint32_t pool, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < v->n; i++) {
		const wrt_mg_pg_list *e = &WRT_MG_E(*v, wrt_mg_pg_list, i);

		if (e->pg.pool == pool && e->pg.seed == seed)
			return 1;
	}
	return 0;
}

static const wrt_mg_pg_osd *find_osd(const wrt_mg_vec *v, uint32_t pool, uint32_t seed)
{
	uint32_t i;

	for (i = 0; i < v->n; i++) {
		const wrt_mg_pg_osd *e = &WRT_MG_E(*v, wrt_mg_pg_osd, i);

		if (e->pg.pool == pool && e->pg.seed == seed)
			return e;
	}
	return NULL;
}

/* One PG: the pipeline against the mapper and the model stages, and the invariants of the result. */
static void check_one(const wrt_mg_map *d, const place_rig *r, uint32_t idx, uint32_t seed, uint32_t *n_cmp, uint32_t *n_bad)
{
	const wri_map_pool *p = &wri_map_pools(r->m)[idx];
	const wrt_mg_pool *mp = &WRT_MG_E(d->pools, wrt_mg_pool_ent, idx).p;
	uint32_t pool = (uint32_t)p->id, pps_ref = wrt_mg_pps(mp, p->id, seed), i, nraw = 0, bad = 0;
	wri_pg_result res;
	wr_errinfo why;
	wr_status st, st_ref;
	wri_crush_in in;
	wri_crush_ws ws2;
	int32_t raw[WRI_REP_MAX], raw_kept[WRI_REP_MAX];
	uint32_t nkept = 0;
	wrt_mg_place want;
	const wrt_mg_pg_osd *ptmp;

	memset(&why, 0, sizeof(why));
	st = wri_place_pg(r->m, idx, seed, WORK, &ws, &res, &why);
	in.rule = p->crush_rule;
	in.x = pps_ref;
	in.result_max = p->size;
	in.osd_weight = wri_map_weight(r->m);
	in.weight_max = r->m->max_osd;
	in.args_pool = (int32_t)p->id;
	memset(&ws2, 0, sizeof(ws2));
	ws2.work = WORK;
	st_ref = wri_crush_do_rule(wri_map_crush(r->m), &in, &ws2, raw, &nraw, NULL);
	WRT_CHECK_STATUS(st_ref, st);
	if (st != st_ref || st != WR_OK) {
		(*n_bad) += st != st_ref;
		return;
	}
	WRT_CHECK_U64(res.pps, pps_ref);
	for (i = 0; i < nraw; i++)
		if (wrt_mg_exists(d, raw[i]))
			raw_kept[nkept++] = raw[i];
	bad |= (res.n_raw != nkept) ? 1u : 0u;
	for (i = 0; i < nkept && i < res.n_raw; i++)
		bad |= (res.raw[i] != raw_kept[i]) ? 2u : 0u;
	WRT_CHECK(wrt_mg_model_stages(d, p->id, seed, pps_ref, raw, nraw, &want) == 0);
	bad |= (want.nup != res.n_up || want.nacting != res.n_acting || want.up_primary != res.up_primary ||
	       want.acting_primary != res.acting_primary) ? 4u : 0u;
	for (i = 0; i < want.nup && i < res.n_up; i++)
		bad |= (want.up[i] != res.up[i]) ? 8u : 0u;
	for (i = 0; i < want.nacting && i < res.n_acting; i++)
		bad |= (want.acting[i] != res.acting[i]) ? 16u : 0u;

	/* the invariants */
	bad |= (res.n_raw > p->size || res.n_up > WRI_REP_MAX || res.n_acting > WRI_REP_MAX) ? 32u : 0u;
	for (i = 0; i < res.n_raw; i++)
		bad |= (!wrt_mg_exists(d, res.raw[i])) ? 64u : 0u;
	for (i = 0; i < res.n_up; i++) {
		uint32_t q;

		bad |= (!wrt_mg_is_up(d, res.up[i])) ? 128u : 0u;
		if (!has_list(&d->pg_upmap, pool, seed))
			for (q = 0; q < i; q++)
				bad |= (res.up[q] == res.up[i]) ? 256u : 0u;
	}
	for (i = 0; i < res.n_acting; i++)
		bad |= (!wrt_mg_is_up(d, res.acting[i])) ? 512u : 0u;
	bad |= (res.up_primary != (res.n_up ? res.up[0] : -1)) ? 1024u : 0u;
	ptmp = find_osd(&d->primary_temp, pool, seed);
	if (ptmp == NULL)
		bad |= (res.acting_primary != (res.n_acting ? res.acting[0] : -1)) ? 2048u : 0u;
	else
		/* a stored -1 says "none": with a pg_temp list the primary stays -1, without one it is the up primary */
		bad |= (res.acting_primary != ptmp->osd && !(ptmp->osd == -1 && res.acting_primary == res.up_primary)) ? 4096u : 0u;
	wrt_checks++;
	(*n_cmp)++;
	if (bad) {
		wrt_failures++;
		if ((*n_bad)++ < 8)
			fprintf(stderr, "%s:%d: pool %u seed %u: pipeline disagrees with the mapper + model, or an invariant failed (bits 0x%x)\n", __FILE__,
				__LINE__, pool, seed, bad);
	}
}

static void t_clusters(void)
{
	static const uint32_t pgn[] = {1, 2, 3, 5, 7, 8, 12, 16, 24, 31, 32, 48, 63, 64};
	static const int tun[] = {WRT_MG_TUN_BOBTAIL, WRT_MG_TUN_FIREFLY, WRT_MG_TUN_HAMMER, WRT_MG_TUN_JEWEL, WRT_MG_TUN_JEWEL};
	uint32_t c, n_cmp = 0, n_bad = 0, names = 0, empty = 0;

	for (c = 0; c < 160; c++) {
		wrt_mg_cluster_spec s;
		wrt_mg_map d;
		place_rig r;
		uint32_t n = 3u + below(46), i, pool_i;

		wrt_mg_cluster_spec_init(&s, n);
		s.osds_per_host = 1u + below(6);
		s.hosts_per_rack = below(3) == 0 ? 2u + below(2) : 0u;
		s.n_classes = below(4) == 0 ? 1u + below(3) : 0u;
		s.bucket_alg = below(5) == 0 ? WRT_MG_ALG_STRAW : WRT_MG_ALG_STRAW2;
		s.weight_jitter = (int)below(2);
		s.tunables = tun[below(5)];
		if (s.bucket_alg == WRT_MG_ALG_STRAW2 && below(3) == 0) {
			s.choose_args_rows = 1u + below(2);
			s.choose_args_ids = (int)below(2);
			s.choose_args_pool_set = (int)below(2);
		}
		s.n_pools = 1u + below(3);
		s.pg_num = pgn[below(sizeof(pgn) / sizeof(pgn[0]))];
		s.pool_size = 1u + below(4);
		s.up_pct = below(4) == 0 ? 20u + below(60) : 100u;
		s.never_up_pct = below(5) == 0 ? below(20) : 0u;
		s.out_pct = below(3) == 0 ? below(35) : 0u;
		s.n_upmap_items = below(s.pg_num / 2u + 1u);
		s.n_upmap = below(s.pg_num / 3u + 1u);
		s.n_pg_temp = below(s.pg_num / 3u + 1u);
		s.n_primary_temp = below(s.pg_num / 4u + 1u);
		s.n_upmap_primaries = below(s.pg_num / 4u + 1u);
		s.n_affinity = below(3) == 0 ? below(n / 2u + 1u) : 0u;
		s.epoch = 1u + below(1000);
		s.seed = rng.s ^ (uint64_t)c;
		if (wrt_mg_build_map(&d, &s) != 0) {
			WRT_CHECK(0);
			continue;
		}
		/* pools of their own kind: pgp_num below pg_num, no HASHPSPOOL, another rule; and more overrides, with stale ids */
		for (pool_i = 0; pool_i < d.pools.n; pool_i++) {
			wrt_mg_pool *mp = &WRT_MG_E(d.pools, wrt_mg_pool_ent, pool_i).p;
			uint32_t pool = (uint32_t)WRT_MG_E(d.pools, wrt_mg_pool_ent, pool_i).id, q;

			if (below(3) == 0 && mp->pg_num > 1)
				mp->pgp_num = 1u + below(mp->pg_num);
			if (below(4) == 0)
				mp->flags &= ~(uint64_t)WRT_MG_POOL_HASHPSPOOL;
			mp->crush_rule = (uint8_t)below(s.hosts_per_rack ? 3u : 2u);
			for (q = 0; q < mp->pg_num; q++) {
				int32_t l[6];
				uint32_t len, z;

				if (below(8) == 0) {
					len = below(5);
					for (z = 0; z < len; z++)
						l[z] = rid(n);
					wrt_mg_map_set_pg_upmap(&d, (wrt_mg_pg){pool, q}, l, len);
				}
				if (below(8) == 0) {
					len = below(5);
					for (z = 0; z < len; z++)
						l[z] = rid(n);
					wrt_mg_map_set_pg_temp(&d, (wrt_mg_pg){pool, q}, l, len);
				}
				if (below(10) == 0)
					wrt_mg_map_set_primary_temp(&d, (wrt_mg_pg){pool, q}, rid(n));
				if (below(10) == 0)
					wrt_mg_map_set_upmap_primary(&d, (wrt_mg_pg){pool, q}, rid(n));
			}
		}
		/* OSDs that no longer exist but are still in the CRUSH map: CRUSH may pick them, the pipeline must drop them */
		if (below(3) == 0)
			for (i = 0; i < n; i++)
				if (below(8) == 0)
					WRT_MG_E(d.osd_state, uint32_t, i) = 0u;
		if (!rig_build(&r, &d, 1)) {
			rig_free(&r);
			wrt_mg_map_free(&d);
			continue;
		}
		for (pool_i = 0; pool_i < d.pools.n && pool_i < WRI_MAP_POOLS_MAX; pool_i++) {
			const wri_map_pool *p = &wri_map_pools(r.m)[pool_i];
			uint32_t seed;

			for (seed = 0; seed < p->pg_num; seed++)
				check_one(&d, &r, pool_i, seed, &n_cmp, &n_bad);
			/* a few seeds a caller should not pass (at or above pg_num) must not trap and still agree */
			check_one(&d, &r, pool_i, p->pg_num, &n_cmp, &n_bad);
			check_one(&d, &r, pool_i, p->pg_num + 5u, &n_cmp, &n_bad);
			/* names through the whole chain: hash, seed, sets */
			for (i = 0; i < 40; i++) {
				uint8_t name[40], ns[8];
				uint32_t nn = below(40), nsn = below(4) == 0 ? 1u + below(7) : 0u, ps, sd;
				wri_oid o;
				wri_pg_result a, b;

				fill(name, nn);
				fill(ns, nsn);
				memset(&o, 0, sizeof(o));
				o.name = name;
				o.name_len = nn;
				o.nspace = ns;
				o.nspace_len = nsn;
				WRT_CHECK_STATUS(WR_OK, wri_place_hash(p, &o, &ps));
				sd = wri_place_pg_seed(p, ps);
				WRT_CHECK_U64(sd, wrt_mg_pg_seed(&WRT_MG_E(d.pools, wrt_mg_pool_ent, pool_i).p, ps));
				check_one(&d, &r, pool_i, sd, &n_cmp, &n_bad);
				/* the same PG twice gives the same answer (no state survives in the workspace) */
				if (wri_place_pg(r.m, pool_i, sd, WORK, &ws, &a, NULL) == WR_OK && wri_place_pg(r.m, pool_i, sd, WORK, &ws, &b, NULL) == WR_OK)
					WRT_CHECK(memcmp(&a, &b, sizeof(a)) == 0);
				names++;
			}
		}
		/* a PG with no usable OSD counts as an empty result */
		for (pool_i = 0; pool_i < d.pools.n && pool_i < WRI_MAP_POOLS_MAX; pool_i++) {
			uint32_t seed;

			for (seed = 0; seed < wri_map_pools(r.m)[pool_i].pg_num; seed++) {
				wri_pg_result res;

				if (wri_place_pg(r.m, pool_i, seed, WORK, &ws, &res, NULL) == WR_OK && res.n_acting == 0)
					empty++;
			}
		}
		rig_free(&r);
		wrt_mg_map_free(&d);
	}
	fprintf(stderr, "clusters: %u PG results compared with the mapper and the model, %u names, %u empty results\n", n_cmp, names, empty);
	WRT_CHECK(n_bad == 0);
	WRT_CHECK(n_cmp > 5000 && empty > 0);
}

/* ---- PGs that cannot be mapped, and pools that cannot be used --------------------------------------------- */

static void pool_rw(place_rig *r, uint32_t idx, wri_map_pool **p)
{
	*p = (wri_map_pool *)(void *)(wri_map_base_rw(r->m) + r->m->pool_off) + idx;
}

static void t_unmappable(void)
{
	wrt_mg_cluster_spec s;
	wrt_mg_map d;
	place_rig r;
	uint32_t seed, i;
	wri_pg_result res;

	/* every OSD down: raw is full, up and acting are empty, both primaries -1 */
	wrt_mg_cluster_spec_init(&s, 12);
	s.n_pools = 1;
	s.pg_num = 16;
	s.up_pct = 0;
	s.seed = 11;
	WRT_CHECK(wrt_mg_build_map(&d, &s) == 0);
	if (rig_build(&r, &d, 1)) {
		for (seed = 0; seed < 16; seed++) {
			memset(&res, 0x55, sizeof(res));
			WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, seed, WORK, &ws, &res, NULL));
			WRT_CHECK(res.n_raw == 3 && res.n_up == 0 && res.n_acting == 0);
			WRT_CHECK(res.up_primary == -1 && res.acting_primary == -1);
		}
	}
	rig_free(&r);
	/* pg_temp of members that are all down is as absent; a primary_temp alone still names the acting primary */
	{
		int32_t t[2] = {1, 2};

		wrt_mg_map_set_pg_temp(&d, (wrt_mg_pg){1, 0}, t, 2);
		wrt_mg_map_set_primary_temp(&d, (wrt_mg_pg){1, 1}, 5);
	}
	if (rig_build(&r, &d, 1)) {
		WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, 0, WORK, &ws, &res, NULL));
		WRT_CHECK(res.n_acting == 0 && res.acting_primary == -1);
		WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, 1, WORK, &ws, &res, NULL));
		WRT_CHECK(res.n_acting == 0 && res.n_up == 0 && res.up_primary == -1 && res.acting_primary == 5);
	}
	rig_free(&r);
	wrt_mg_map_free(&d);

	/* every OSD out: CRUSH finds nothing, the raw list is empty too */
	wrt_mg_cluster_spec_init(&s, 12);
	s.n_pools = 1;
	s.pg_num = 8;
	s.out_pct = 100;
	s.seed = 12;
	WRT_CHECK(wrt_mg_build_map(&d, &s) == 0);
	if (rig_build(&r, &d, 1)) {
		for (seed = 0; seed < 8; seed++) {
			WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, seed, WORK, &ws, &res, NULL));
			WRT_CHECK(res.n_raw == 0 && res.n_up == 0 && res.n_acting == 0 && res.up_primary == -1 && res.acting_primary == -1);
		}
	}
	rig_free(&r);
	wrt_mg_map_free(&d);

	/* two hosts for three replicas: two members, not an error */
	wrt_mg_cluster_spec_init(&s, 8);
	s.osds_per_host = 4;
	s.n_pools = 1;
	s.pg_num = 16;
	s.seed = 13;
	WRT_CHECK(wrt_mg_build_map(&d, &s) == 0);
	if (rig_build(&r, &d, 1)) {
		for (seed = 0; seed < 16; seed++) {
			WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, seed, WORK, &ws, &res, NULL));
			WRT_CHECK(res.n_raw == 2 && res.n_up == 2 && res.n_acting == 2 && res.up_primary == res.up[0]);
		}
	}
	rig_free(&r);
	/* an up_pct of 0 for the 2 OSDs of one host only: the PG keeps its other member */
	for (i = 0; i < 4; i++)
		WRT_MG_E(d.osd_state, uint32_t, i) = WRT_MG_OSD_EXISTS;
	if (rig_build(&r, &d, 1)) {
		for (seed = 0; seed < 16; seed++) {
			WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, seed, WORK, &ws, &res, NULL));
			WRT_CHECK(res.n_raw == 2 && res.n_up == 1 && res.n_acting == 1 && res.up[0] >= 4 && res.up_primary == res.up[0]);
		}
	}
	rig_free(&r);
	wrt_mg_map_free(&d);
}

static void t_pool_errors(void)
{
	wrt_mg_cluster_spec s;
	wrt_mg_map d;
	place_rig r;
	wri_pg_result res;
	wr_errinfo why;
	wri_map_pool *p;
	wri_crush_ws w2;

	wrt_mg_cluster_spec_init(&s, 12);
	s.n_pools = 2;
	s.pg_num = 16;
	s.seed = 21;
	WRT_CHECK(wrt_mg_build_map(&d, &s) == 0);
	if (!rig_build(&r, &d, 1)) {
		rig_free(&r);
		wrt_mg_map_free(&d);
		return;
	}
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, 3, WORK, &ws, &res, NULL));
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));

	/* a tracked pool that is not in the map: absent, or beyond the tracked records */
	pool_rw(&r, 1, &p);
	p->present = 0;
	memset(&why, 0, sizeof(why));
	memset(&res, 0x55, sizeof(res));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, &why));
	WRT_CHECK(why.status == WR_E_POOL_NOT_FOUND && why.what != NULL);
	WRT_CHECK(res.n_raw == 0 && res.n_up == 0 && res.n_acting == 0 && res.up_primary == -1 && res.acting_primary == -1);
	p->present = 1;
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(r.m, 2, 3, WORK, &ws, &res, NULL));
	WRT_CHECK_STATUS(WR_E_POOL_NOT_FOUND, wri_place_pg(r.m, 0xffffffffu, 3, WORK, &ws, &res, NULL));

	/* the pool's own status wins, whatever it is */
	pool_rw(&r, 1, &p);
	p->status = WR_E_POOL_UNSUPPORTED;
	memset(&res, 0x55, sizeof(res));
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, &why));
	WRT_CHECK(why.status == WR_E_POOL_UNSUPPORTED && res.n_up == 0 && res.acting_primary == -1);
	p->status = WR_E_CRUSH_NO_RULE;
	WRT_CHECK_STATUS(WR_E_CRUSH_NO_RULE, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));
	p->status = WR_OK;
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));

	/* a pool whose rule does not exist (the status said OK: the mapper reports it) */
	p->crush_rule = 200;
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_CRUSH_NO_RULE, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, &why));
	WRT_CHECK(why.status == WR_E_CRUSH_NO_RULE);
	WRT_CHECK(res.n_raw == 0 && res.n_acting == 0 && res.up_primary == -1 && res.acting_primary == -1);
	p->crush_rule = 0;

	/* sizes the mapper cannot serve */
	p->size = 0;
	WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));
	p->size = (uint8_t)(WRI_REP_MAX + 1u);
	WRT_CHECK_STATUS(WR_E_POOL_UNSUPPORTED, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));
	p->size = (uint8_t)WRI_REP_MAX;
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 1, 3, WORK, &ws, &res, NULL));
	WRT_CHECK(res.n_raw <= 12);
	p->size = 3;

	/* the work budget: the caller's value is used, whatever the workspace held */
	WRT_CHECK_STATUS(WR_E_CRUSH_WORK, wri_place_pg(r.m, 0, 3, 1, &ws, &res, NULL));
	WRT_CHECK(res.n_raw == 0 && res.acting_primary == -1);
	memset(&w2, 0xff, sizeof(w2));
	w2.work = 0;
	WRT_CHECK_STATUS(WR_OK, wri_place_pg(r.m, 0, 3, WORK, &w2, &res, NULL));
	WRT_CHECK(w2.work < WORK); /* the mapper spent some */
	WRT_CHECK_STATUS(WR_E_CRUSH_WORK, wri_place_pg(r.m, 0, 3, 0, &w2, &res, NULL));

	/* bad arguments: the result is cleared whenever there is one */
	memset(&res, 0x55, sizeof(res));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_pg(NULL, 0, 3, WORK, &ws, &res, NULL));
	WRT_CHECK(res.n_raw == 0 && res.n_up == 0 && res.n_acting == 0 && res.up_primary == -1 && res.acting_primary == -1);
	memset(&res, 0x55, sizeof(res));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_pg(r.m, 0, 3, WORK, NULL, &res, NULL));
	WRT_CHECK(res.n_raw == 0 && res.n_up == 0 && res.n_acting == 0 && res.up_primary == -1 && res.acting_primary == -1);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_place_pg(r.m, 0, 3, WORK, &ws, NULL, NULL));
	rig_free(&r);

	/* a map without a CRUSH region */
	if (rig_build(&r, &d, 0)) {
		memset(&why, 0, sizeof(why));
		memset(&res, 0x55, sizeof(res));
		WRT_CHECK_STATUS(WR_E_MAP_NONE, wri_place_pg(r.m, 0, 3, WORK, &ws, &res, &why));
		WRT_CHECK(why.status == WR_E_MAP_NONE && res.n_up == 0 && res.up_primary == -1);
	}
	rig_free(&r);
	wrt_mg_map_free(&d);
}

int main(void)
{
	wrt_mg_rng_seed(&rng, 0x706970657069ull);
	t_hash_vectors();
	t_hash_pieces();
	t_hash_limits();
	t_seed_pps();
	t_clusters();
	t_unmappable();
	t_pool_errors();
	return wrt_finish();
}
