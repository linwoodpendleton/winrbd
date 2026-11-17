/* SPDX-License-Identifier: MIT */
/*
 * map_vec_rig.h - shared by test_map_vec_full.c, test_map_vec_place.c and test_map_vec_pgs.c (module map-vectors): the committed
 * placement vectors of harness/vectors/ put through the REAL decoding path of the core and nothing else:
 *
 *     bytes of a full OSDMap  --wri_osdmap_decode_full-->  slot  --wri_place_hash / wri_place_pg-->  answer
 *     bytes of incrementals   --wri_osdmap_apply_inc---->  slot  --------------------------------->  answer
 *
 * No model (wrt_mapgen) stands between the vector and the core: the only help taken from test support is the hex / JSON readers
 * and, for epoch 1 of the first set, the reader that cuts the full map out of incremental 1 (that incremental carries a whole
 * map, and apply_inc needs a held map to start from).
 *
 * What a vector holds is what Ceph's own tools answered (osdmaptool --test-map-pgs-dump-all, ceph osd map, crushtool --test, ceph
 * osd dump, MOSDOps of the stock client). The first mismatch of a comparison stops the test with a report that names the vector
 * set, the state (label and epoch), the pool, the PG or the object bytes, and both answers.
 *
 * Every decode and every apply goes through inc_rig.h (rig_decode / rig_apply): two pre-fills of the slot, guard bytes, the held
 * map untouched, a failure leaves magic 0, a success passes wri_osdmap_check.
 */
#ifndef MAP_VEC_RIG_H
#define MAP_VEC_RIG_H

#include "inc_rig.h"
#include "wri_crush_hash.h"
#include "wri_place.h"

#define MV_WORK_MAX 1000000u
#define MV_MAX_OSD 4096u

static wri_crush_ws mv_ws;

/* ---- failing on the first mismatch ----------------------------------------------------------------------------------- */

/* A mismatch was reported on stderr: count it and end the run (the first one is the one worth reading). */
WRT_UNUSED static void mv_die(void)
{
	wrt_checks++;
	wrt_failures++;
	exit(wrt_finish());
}

/* Where a comparison is: the vector set, the state inside it and its epoch. */
typedef struct mv_ctx {
	const char *set;
	const char *label;
	uint32_t epoch;
} mv_ctx;

/* How many comparisons of each kind were made (a vector set that compared nothing would pass without this). */
typedef struct mv_tally {
	uint32_t pgs;     /* PG rows whose five columns were compared */
	uint32_t names;   /* object rows whose hash, PG, sets and primaries were compared */
	uint32_t refused; /* PG rows of a pool the core must refuse: the refusal was checked, there is nothing to compare */
	uint32_t other;   /* PG rows of a pool this chain does not track (another chain takes it) */
	uint32_t toobig;  /* object rows above the core's name cap: WR_E_TOOBIG was checked */
	uint32_t dumps;   /* fields of `ceph osd dump` compared with the map */
} mv_tally;

/* ---- JSON helpers ----------------------------------------------------------------------------------------------------- */

WRT_UNUSED static int64_t mv_int(const wrt_json *j, wrt_tok t)
{
	int ok = 0;
	int64_t v = wrt_json_int(j, t, &ok);

	if (!ok) {
		fprintf(stderr, "map-vectors: a vector field that must be an integer is not one\n");
		mv_die();
	}
	return v;
}

/* Integer member `key` of `obj`; *ok is 0 for a missing member or a number that is not an integer (a float). */
WRT_UNUSED static int64_t mv_member_int(const wrt_json *j, wrt_tok obj, const char *key, int *ok)
{
	wrt_tok t = wrt_json_get(j, obj, key);

	*ok = 0;
	if (t == WRT_NONE)
		return 0;
	return wrt_json_int(j, t, ok);
}

WRT_UNUSED static int mv_jlist_eq(const wrt_json *j, wrt_tok arr, const int32_t *got, uint32_t n)
{
	size_t i, cnt = wrt_json_count(j, arr);

	if (arr == WRT_NONE || cnt != n)
		return 0;
	for (i = 0; i < cnt; i++)
		if (mv_int(j, wrt_json_at(j, arr, i)) != (int64_t)got[i])
			return 0;
	return 1;
}

WRT_UNUSED static void mv_fmt_jlist(char *out, size_t cap, const wrt_json *j, wrt_tok arr)
{
	size_t i, o = 0, cnt = arr == WRT_NONE ? 0 : wrt_json_count(j, arr);

	out[0] = 0;
	for (i = 0; i < cnt && o + 16u < cap; i++)
		o += (size_t)snprintf(out + o, cap - o, "%s%d", i ? " " : "", (int)mv_int(j, wrt_json_at(j, arr, i)));
}

WRT_UNUSED static void mv_fmt_list(char *out, size_t cap, const int32_t *v, uint32_t n)
{
	uint32_t i;
	size_t o = 0;

	out[0] = 0;
	for (i = 0; i < n && o + 16u < cap; i++)
		o += (size_t)snprintf(out + o, cap - o, "%s%d", i ? " " : "", (int)v[i]);
}

/* "<pool>.<seed hex>" -> pool and seed; 0 on a malformed string. */
WRT_UNUSED static int mv_parse_pgid(const char *s, uint64_t *pool, uint32_t *seed)
{
	char *end = NULL;

	if (s == NULL || *s < '0' || *s > '9')
		return 0;
	*pool = strtoull(s, &end, 10);
	if (end == NULL || *end != '.' || end[1] == 0)
		return 0;
	*seed = (uint32_t)strtoul(end + 1, &end, 16);
	return *end == 0;
}

/* Object bytes for a message: printable ASCII as is, everything else as \xHH, cut at 48 bytes. */
WRT_UNUSED static void mv_fmt_bytes(char *out, size_t cap, const uint8_t *p, size_t n)
{
	size_t i, o = 0;

	out[0] = 0;
	for (i = 0; i < n && i < 48u && o + 8u < cap; i++) {
		if (p[i] >= 0x20u && p[i] < 0x7fu && p[i] != '\\')
			out[o++] = (char)p[i];
		else
			o += (size_t)snprintf(out + o, cap - o, "\\x%02x", (unsigned)p[i]);
	}
	if (n > 48u && o + 4u < cap)
		o += (size_t)snprintf(out + o, cap - o, "...");
	out[o] = 0;
}

/* ---- the held map ------------------------------------------------------------------------------------------------------- */

/* Index of tracked pool `id` in the map (its record is present), -1 if the map has no such pool. */
WRT_UNUSED static int mv_pool_idx(const wri_osdmap *m, int64_t id)
{
	uint32_t k;

	for (k = 0; k < m->n_pools; k++)
		if (wri_map_pools(m)[k].present && wri_map_pools(m)[k].id == id)
			return (int)k;
	return -1;
}

/* A chain: a configuration (which pools are tracked), two slots, the epoch that is held. */
typedef struct mv_chain {
	wri_mapcfg cfg;
	islot s[2];
	int cur;
} mv_chain;

WRT_UNUSED static void mv_chain_open(mv_chain *c, const char *const *names, unsigned n)
{
	memset(c, 0, sizeof(*c));
	rig_cfg(&c->cfg, RIG_SLOT_BYTES, MV_MAX_OSD, 1, names, n);
	islot_new(&c->s[0], RIG_SLOT_BYTES);
	islot_new(&c->s[1], RIG_SLOT_BYTES);
}

WRT_UNUSED static void mv_chain_close(mv_chain *c)
{
	islot_free(&c->s[0]);
	islot_free(&c->s[1]);
}

WRT_UNUSED static const wri_osdmap *mv_chain_map(const mv_chain *c) { return islot_map(&c->s[c->cur]); }

/* Replace the held map by a decode of `blob` (a monitor's full map, or the map embedded in an incremental). */
WRT_UNUSED static wr_status mv_chain_full(mv_chain *c, const uint8_t *blob, size_t n, wr_errinfo *why)
{
	wr_status st = rig_decode(&c->cfg, blob, n, &c->s[1 - c->cur], why);

	if (st == WR_OK)
		c->cur = 1 - c->cur;
	return st;
}

/* Apply the incremental to the held map; on success the new map is the held one. */
WRT_UNUSED static wr_status mv_chain_inc(mv_chain *c, const uint8_t *blob, size_t n, wr_errinfo *why)
{
	wr_status st = rig_apply(&c->cfg, mv_chain_map(c), blob, n, &c->s[1 - c->cur], why);

	if (st == WR_OK)
		c->cur = 1 - c->cur;
	return st;
}

/* Decode a full map into a slot of its own (not part of a chain): for the direct-decode comparisons. */
WRT_UNUSED static wr_status mv_decode_one(const wri_mapcfg *cfg, const uint8_t *blob, size_t n, islot *s, wr_errinfo *why)
{
	islot_new(s, RIG_SLOT_BYTES);
	return rig_decode(cfg, blob, n, s, why);
}

/* ---- loading ------------------------------------------------------------------------------------------------------------ */

WRT_UNUSED static void mv_load_hex(const char *rel, uint8_t **p, size_t *n)
{
	if (wrt_mg_load_hex_file(wrt_vec_path(rel), p, n) != 0) {
		fprintf(stderr, "map-vectors: cannot read %s\n", rel);
		mv_die();
	}
}

WRT_UNUSED static void mv_load_json(wrt_json *j, const char *rel)
{
	if (wrt_json_load_vec(j, rel) != 0) {
		fprintf(stderr, "map-vectors: cannot read %s\n", rel);
		mv_die();
	}
}

/* `cfg` is the chain's configuration (the tracked names), for the checks that need them. */
typedef void (*mv_epoch_fn)(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch);

/* The chains over both capture sets: `fn` is called with the held map at every epoch from the first to the last. */

/* osdmap/: incrementals 1..89 (epoch 1 embeds a full map) and, for the real map of epoch 42, osdmap/full-e42.hex. */
WRT_UNUSED static void mv_replay_set1(const char *const *names, unsigned nn, mv_epoch_fn fn, void *user)
{
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i;
	wrt_mg_inc inc1;
	mv_chain c;
	wr_errinfo why;

	if (wrt_mg_load_epoch_lines(wrt_vec_path("osdmap/incrementals.hex"), &ls, &nl) != 0 || nl != 89u) {
		fprintf(stderr, "map-vectors: osdmap/incrementals.hex must hold 89 incrementals\n");
		mv_die();
	}
	mv_chain_open(&c, names, nn);
	/* epoch 1 is the map embedded in incremental 1: decode it (the held map), then apply incremental 1 on top of it, which
	 * must take the embedded map again, whatever the held epoch is, and give the same bytes */
	if (wrt_mg_inc_parse(ls[0].p, ls[0].n, &inc1) != 0 || inc1.fullmap == NULL) {
		fprintf(stderr, "map-vectors: incremental 1 does not carry a full map\n");
		mv_die();
	}
	if (mv_chain_full(&c, inc1.fullmap, inc1.fullmap_len, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: the full map inside incremental 1 does not decode: %s\n", why.what != NULL ? why.what : "?");
		mv_die();
	}
	{
		islot again;

		islot_new(&again, RIG_SLOT_BYTES);
		if (rig_apply(&c.cfg, mv_chain_map(&c), ls[0].p, ls[0].n, &again, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: incremental 1 does not apply on its own map: %s\n", why.what != NULL ? why.what : "?");
			mv_die();
		}
		rig_cmp_core(islot_map(&again), mv_chain_map(&c));
		islot_free(&again);
	}
	wrt_mg_inc_free(&inc1);
	WRT_CHECK_U64(mv_chain_map(&c)->epoch, 1);
	fn(user, mv_chain_map(&c), &c.cfg, 1);
	for (i = 1; i < nl; i++) {
		if (ls[i].epoch != i + 1u || mv_chain_inc(&c, ls[i].p, ls[i].n, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: osdmap/ chain, epoch %u: %s\n", ls[i].epoch, why.what != NULL ? why.what : "does not follow");
			mv_die();
		}
		WRT_CHECK_U64(mv_chain_map(&c)->epoch, ls[i].epoch);
		fn(user, mv_chain_map(&c), &c.cfg, ls[i].epoch);
	}
	mv_chain_close(&c);
	wrt_mg_free_lines(ls, nl);
}

/* public/mapb: the full map of epoch 666, then incrementals 667..925. */
WRT_UNUSED static void mv_replay_mapb(const char *const *names, unsigned nn, mv_epoch_fn fn, void *user)
{
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i, nbase = 0;
	uint8_t *base = NULL;
	mv_chain c;
	wr_errinfo why;

	if (wrt_mg_load_epoch_lines(wrt_vec_path("public/mapb/incrementals.hex"), &ls, &nl) != 0 || nl != 259u) {
		fprintf(stderr, "map-vectors: public/mapb/incrementals.hex must hold 259 incrementals\n");
		mv_die();
	}
	mv_load_hex("public/mapb/base-e666.hex", &base, &nbase);
	mv_chain_open(&c, names, nn);
	if (mv_chain_full(&c, base, nbase, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: mapb base map does not decode: %s\n", why.what != NULL ? why.what : "?");
		mv_die();
	}
	WRT_CHECK_U64(mv_chain_map(&c)->epoch, 666);
	fn(user, mv_chain_map(&c), &c.cfg, 666);
	for (i = 0; i < nl; i++) {
		if (ls[i].epoch != 667u + i || mv_chain_inc(&c, ls[i].p, ls[i].n, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: mapb chain, epoch %u: %s\n", ls[i].epoch, why.what != NULL ? why.what : "does not follow");
			mv_die();
		}
		WRT_CHECK_U64(mv_chain_map(&c)->epoch, ls[i].epoch);
		fn(user, mv_chain_map(&c), &c.cfg, ls[i].epoch);
	}
	mv_chain_close(&c);
	free(base);
	wrt_mg_free_lines(ls, nl);
}

/* The tracked-name sets that together cover every pool of the map-b capture (16 pools, at most 8 tracked at a time). Pool 51 is
 * `wrtest-mb-del` until epoch 847 and `wrtest-mb-ren` after its rename, so set B tracks both names; set C is the erasure pool. */
#define MV_SET_A_N 8u
#define MV_SET_B_N 8u
#define MV_SET_C_N 1u
WRT_UNUSED static const char *const mv_set_a[MV_SET_A_N] = {".mgr",          "winrbd",        "wrtest-mb-p16", "wrtest-mb-p12",
							    "wrtest-mb-p7", "wrtest-mb-np",  "wrtest-mb-leg", "wrtest-mb-s4"};
WRT_UNUSED static const char *const mv_set_b[MV_SET_B_N] = {"wrtest-mb-host", "wrtest-mb-sp",   "wrtest-mb-mg",    "wrtest-mb-del",
							    "wrtest-mb-ren",  "wrtest-mb-ws",   "wrtest-mb-base",  "wrtest-mb-cache"};
WRT_UNUSED static const char *const mv_set_c[MV_SET_C_N] = {"wrtest-mb-ec"};

/* ---- one PG against the five columns of a vector ----------------------------------------------------------------------- */

/* The columns of one expected answer; raw may be WRT_NONE (the name oracles have no raw column). */
typedef struct mv_exp {
	const wrt_json *j;
	wrt_tok raw, up, up_primary, acting, acting_primary;
} mv_exp;

/*
 * wri_place_pg for tracked pool index `idx`, PG seed `seed`, against `e`. `want` is the status the call must return: WR_OK
 * (the columns are then compared), or the refusal the pool must give (the status is checked, nothing is compared). `what` is
 * "pg P.S" or the object, for the report.
 */
WRT_UNUSED static void mv_pg(const mv_ctx *cx, const wri_osdmap *m, uint32_t idx, uint32_t seed, const char *what, const mv_exp *e,
			     wr_status want, mv_tally *t)
{
	wri_pg_result res;
	wr_errinfo why;
	wr_status st;
	char a[160], b[160], c[160], d[160];
	int ok;
	const wrt_json *j = e->j;

	memset(&why, 0, sizeof(why));
	st = wri_place_pg(m, idx, seed, MV_WORK_MAX, &mv_ws, &res, &why);
	if (want != WR_OK || st != WR_OK) {
		if (st != want) {
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: wri_place_pg returned %d (%s), want %d (%s)%s%s\n", cx->set,
				cx->label, cx->epoch, wri_map_pools(m)[idx].id, what, (int)st, wrt_status_name_(st), (int)want, wrt_status_name_(want),
				why.what != NULL ? ": " : "", why.what != NULL ? why.what : "");
			mv_die();
		}
		t->refused++;
		return;
	}
	ok = mv_jlist_eq(j, e->up, res.up, res.n_up) && mv_jlist_eq(j, e->acting, res.acting, res.n_acting) &&
	     mv_int(j, e->up_primary) == (int64_t)res.up_primary && mv_int(j, e->acting_primary) == (int64_t)res.acting_primary;
	if (e->raw != WRT_NONE)
		ok = ok && mv_jlist_eq(j, e->raw, res.raw, res.n_raw);
	wrt_checks++;
	t->pgs++;
	if (!ok) {
		fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s\n", cx->set, cx->label, cx->epoch, wri_map_pools(m)[idx].id, what);
		if (e->raw != WRT_NONE) {
			mv_fmt_jlist(a, sizeof(a), j, e->raw);
			mv_fmt_list(b, sizeof(b), res.raw, res.n_raw);
			fprintf(stderr, "  raw     want [%s]  got [%s]\n", a, b);
		}
		mv_fmt_jlist(a, sizeof(a), j, e->up);
		mv_fmt_list(b, sizeof(b), res.up, res.n_up);
		fprintf(stderr, "  up      want [%s] primary %d   got [%s] primary %d\n", a, (int)mv_int(j, e->up_primary), b, (int)res.up_primary);
		mv_fmt_jlist(c, sizeof(c), j, e->acting);
		mv_fmt_list(d, sizeof(d), res.acting, res.n_acting);
		fprintf(stderr, "  acting  want [%s] primary %d   got [%s] primary %d\n", c, (int)mv_int(j, e->acting_primary), d,
			(int)res.acting_primary);
		mv_die();
	}
}

/* Does `ceph osd dump` say a pool is one this client can serve? 1 yes, 0 no (erasure, a tier or an overlay), -1 not in the dump. */
WRT_UNUSED static int mv_dump_pool_servable(const wrt_json *j, wrt_tok dump, int64_t id)
{
	wrt_tok pools = wrt_json_get(j, dump, "pools");
	size_t i;

	for (i = 0; pools != WRT_NONE && i < wrt_json_count(j, pools); i++) {
		wrt_tok p = wrt_json_at(j, pools, i);
		int ok;

		if (mv_member_int(j, p, "pool", &ok) != id || !ok)
			continue;
		if (mv_member_int(j, p, "type", &ok) != (int64_t)WRI_POOL_REPLICATED)
			return 0;
		if (mv_member_int(j, p, "tier_of", &ok) >= 0 && ok)
			return 0;
		if (mv_member_int(j, p, "read_tier", &ok) >= 0 && ok)
			return 0;
		if (mv_member_int(j, p, "write_tier", &ok) >= 0 && ok)
			return 0;
		if (wrt_json_count(j, wrt_json_get(j, p, "tiers")) != 0)
			return 0;
		return 1;
	}
	return -1;
}

/*
 * A `pgs` table, {"<pool>.<seed hex>": [raw, up, up primary, acting, acting primary], ...}, against the held map. PGs of a pool the
 * map does not track are counted in t->other (the caller makes sure another chain takes them). With a `dump` (`ceph osd dump` of the
 * same epoch) a pool it lists as erasure coded or tiered must be refused with WR_E_POOL_UNSUPPORTED; every other pool must be served.
 * Returns the number of rows handled (compared or refused).
 */
WRT_UNUSED static uint32_t mv_table(const mv_ctx *cx, const wri_osdmap *m, const wrt_json *j, wrt_tok pgs, wrt_tok dump, mv_tally *t)
{
	size_t i, n = wrt_json_count(j, pgs);
	uint32_t handled = 0;

	for (i = 0; i < n; i++) {
		wrt_tok v;
		const char *k = wrt_json_key_at(j, pgs, i, &v);
		uint64_t pool = 0;
		uint32_t seed = 0;
		int idx, servable = 1;
		mv_exp e;

		if (!mv_parse_pgid(k, &pool, &seed)) {
			fprintf(stderr, "map-vectors: %s: state %s: bad PG id '%s'\n", cx->set, cx->label, k);
			mv_die();
		}
		idx = mv_pool_idx(m, (int64_t)pool);
		if (idx < 0) {
			t->other++;
			continue;
		}
		if (dump != WRT_NONE) {
			servable = mv_dump_pool_servable(j, dump, (int64_t)pool);
			if (servable < 0) {
				fprintf(stderr, "MISMATCH %s: state %s (epoch %u): pool %u is in the map and in the table but not in `osd dump`\n", cx->set,
					cx->label, cx->epoch, (unsigned)pool);
				mv_die();
			}
		}
		e.j = j;
		e.raw = wrt_json_at(j, v, 0);
		e.up = wrt_json_at(j, v, 1);
		e.up_primary = wrt_json_at(j, v, 2);
		e.acting = wrt_json_at(j, v, 3);
		e.acting_primary = wrt_json_at(j, v, 4);
		mv_pg(cx, m, (uint32_t)idx, seed, k, &e, servable ? WR_OK : WR_E_POOL_UNSUPPORTED, t);
		handled++;
	}
	return handled;
}

/* ---- one object against an oracle answer --------------------------------------------------------------------------------- */

/*
 * One object (name and namespace as bytes) in tracked pool `pool_id` against what `ceph osd map` answered: the object hash `want_ps`
 * (-1 = not given), the PG it falls into `want_pg` ("<pool>.<seed hex>", may be NULL), then the five answers of that PG (`e`, raw
 * absent). The pool must be present in the map (else t->other). Checked in this order: the object hash, the PG the hash falls into
 * with the map's pg_num, the sets. A name above the core's cap must be refused with WR_E_TOOBIG.
 */
WRT_UNUSED static void mv_name_check(const mv_ctx *cx, const wri_osdmap *m, int64_t pool_id, const uint8_t *name, size_t nn, const uint8_t *ns,
				     size_t nsn, int64_t want_ps, const char *want_pg, const mv_exp *e, mv_tally *t)
{
	int idx = mv_pool_idx(m, pool_id);
	wri_oid oid;
	uint32_t ps = 0, seed;
	wr_status st;
	char got_pg[48], what[400], bytes[200], nsb[100];
	const wri_map_pool *p;

	if (idx < 0) {
		t->other++;
		return;
	}
	p = &wri_map_pools(m)[idx];
	mv_fmt_bytes(bytes, sizeof(bytes), name, nn);
	mv_fmt_bytes(nsb, sizeof(nsb), ns, nsn);
	snprintf(what, sizeof(what), "object '%s' namespace '%s' (%u + %u bytes)", bytes, nsb, (unsigned)nn, (unsigned)nsn);
	memset(&oid, 0, sizeof(oid));
	oid.name = name;
	oid.name_len = (uint32_t)nn;
	oid.nspace = ns;
	oid.nspace_len = (uint32_t)nsn;
	st = wri_place_hash(p, &oid, &ps);
	if (nn + nsn > WRI_PLACE_NAME_MAX) {
		/* The oracle was asked about a name above the core's cap (name plus namespace). The core refuses it by design; the rest of
		 * the pipeline has no such cap, so the hash is built here from the same bytes and the PG is still compared. */
		uint8_t *buf = (uint8_t *)malloc(nn + nsn + 2u);
		size_t len = 0;
		int hok = 0;

		if (st != WR_E_TOOBIG) {
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: wri_place_hash returned %d (%s), want TOOBIG\n", cx->set,
				cx->label, cx->epoch, pool_id, what, (int)st, wrt_status_name_(st));
			mv_die();
		}
		if (buf == NULL) {
			fprintf(stderr, "out of memory\n");
			exit(2);
		}
		if (nsn != 0) {
			memcpy(buf, ns, nsn);
			buf[nsn] = 0x1f;
			len = nsn + 1u;
		}
		memcpy(buf + len, name, nn);
		len += nn;
		ps = wri_str_hash(p->object_hash, buf, (uint32_t)len, &hok);
		free(buf);
		WRT_CHECK(hok);
		t->toobig++;
		st = WR_OK;
	}
	if (st != WR_OK) {
		fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: wri_place_hash returned %d (%s)\n", cx->set, cx->label, cx->epoch,
			pool_id, what, (int)st, wrt_status_name_(st));
		mv_die();
	}
	wrt_checks++;
	if (want_ps >= 0 && (uint64_t)ps != (uint64_t)want_ps) {
		fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: object hash want %u got %u\n", cx->set, cx->label, cx->epoch,
			pool_id, what, (unsigned)want_ps, (unsigned)ps);
		mv_die();
	}
	seed = wri_place_pg_seed(p, ps);
	snprintf(got_pg, sizeof(got_pg), "%u.%x", (unsigned)pool_id, (unsigned)seed);
	wrt_checks++;
	if (want_pg != NULL && strcmp(got_pg, want_pg) != 0) {
		fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: hash %u falls into pg %s, want %s (pg_num %u, mask %u)\n", cx->set,
			cx->label, cx->epoch, pool_id, what, (unsigned)ps, got_pg, want_pg, (unsigned)p->pg_num, (unsigned)p->pg_num_mask);
		mv_die();
	}
	mv_pg(cx, m, (uint32_t)idx, seed, what, e, WR_OK, t);
	t->names++;
}

/*
 * A row [.., pool_id, object_hex, namespace_hex, raw_ps, pgid, up, up_primary, acting, acting_primary] with pool_id at index `at`
 * (the name oracles and answers.json differ in what precedes it).
 */
WRT_UNUSED static void mv_name_row(const mv_ctx *cx, const wri_osdmap *m, const wrt_json *j, wrt_tok row, size_t at, mv_tally *t)
{
	uint8_t *name = NULL, *ns = NULL;
	size_t nn = 0, nsn = 0;
	char *pgid;
	mv_exp e;

	if (wrt_json_hex(j, wrt_json_at(j, row, at + 1), &name, &nn) != 0 || wrt_json_hex(j, wrt_json_at(j, row, at + 2), &ns, &nsn) != 0) {
		fprintf(stderr, "map-vectors: %s: state %s: object bytes are not hex\n", cx->set, cx->label);
		mv_die();
	}
	pgid = wrt_json_strdup(j, wrt_json_at(j, row, at + 4));
	e.j = j;
	e.raw = WRT_NONE;
	e.up = wrt_json_at(j, row, at + 5);
	e.up_primary = wrt_json_at(j, row, at + 6);
	e.acting = wrt_json_at(j, row, at + 7);
	e.acting_primary = wrt_json_at(j, row, at + 8);
	mv_name_check(cx, m, mv_int(j, wrt_json_at(j, row, at)), name, nn, ns, nsn, mv_int(j, wrt_json_at(j, row, at + 3)), pgid, &e, t);
	free(pgid);
	free(name);
	free(ns);
}

/* A name oracle file, {"entries": [row, ...]}, row layout as above with pool_id at `at`, against the held map. */
WRT_UNUSED static void mv_name_file(const mv_ctx *cx, const wri_osdmap *m, const wrt_json *j, size_t at, mv_tally *t)
{
	wrt_tok entries = wrt_json_get(j, wrt_json_root(j), "entries");
	size_t i;

	for (i = 0; i < wrt_json_count(j, entries); i++)
		mv_name_row(cx, m, j, wrt_json_at(j, entries, i), at, t);
}

/*
 * The three object sets of the first lab set, all asked at epoch 42, against the map held at epoch 42 (a chain or a direct decode):
 *   osdmap/placement-names-e42.json   219 names: RBD objects, random names of 1 to 255 bytes, non-ASCII, namespaced
 *   crush/placement-expected.json     137 names with their raw pgid (hash in hex): every length, namespaces, CESU-8
 *   crush/mosdop-targets.json         40 MOSDOp frames of the stock client: the hash and the pg seed it put in the message and
 *                                     the OSD it connected to (the acting primary); the frames of other epochs are skipped
 */
WRT_UNUSED static void mv_names_e42(const wri_osdmap *m, const char *set, mv_tally *t)
{
	wrt_json names, exp137, mosdop;
	wrt_tok cases, samples;
	mv_ctx cx;
	size_t k;

	mv_load_json(&names, "osdmap/placement-names-e42.json");
	mv_load_json(&exp137, "crush/placement-expected.json");
	mv_load_json(&mosdop, "crush/mosdop-targets.json");
	cx.set = set;
	cx.epoch = m->epoch;
	cx.label = "placement-names-e42";
	mv_name_file(&cx, m, &names, 0, t);

	cx.label = "placement-expected";
	cases = wrt_json_get(&exp137, wrt_json_root(&exp137), "cases");
	for (k = 0; k < wrt_json_count(&exp137, cases); k++) {
		wrt_tok c = wrt_json_at(&exp137, cases, k);
		uint8_t *nm = NULL, *ns = NULL;
		size_t nn = 0, nsn = 0;
		char *raw_pg = wrt_json_strdup(&exp137, wrt_json_get(&exp137, c, "raw_pgid")), *pgid = wrt_json_strdup(&exp137, wrt_json_get(&exp137, c, "pgid"));
		mv_exp e;

		if (raw_pg == NULL || pgid == NULL || strchr(raw_pg, '.') == NULL || wrt_json_get_hex(&exp137, c, "object_hex", &nm, &nn) != 0 ||
		    wrt_json_get_hex(&exp137, c, "nspace_hex", &ns, &nsn) != 0) {
			fprintf(stderr, "map-vectors: crush/placement-expected.json: a case without its fields\n");
			mv_die();
		}
		e.j = &exp137;
		e.raw = WRT_NONE;
		e.up = wrt_json_get(&exp137, c, "up");
		e.up_primary = wrt_json_get(&exp137, c, "up_primary");
		e.acting = wrt_json_get(&exp137, c, "acting");
		e.acting_primary = wrt_json_get(&exp137, c, "acting_primary");
		/* raw_pgid is "<pool>.<hash in hex>" */
		mv_name_check(&cx, m, mv_int(&exp137, wrt_json_get(&exp137, c, "pool_id")), nm, nn, ns, nsn, (int64_t)strtoul(strchr(raw_pg, '.') + 1, NULL, 16),
			      pgid, &e, t);
		free(raw_pg);
		free(pgid);
		free(nm);
		free(ns);
	}

	cx.label = "mosdop-targets";
	samples = wrt_json_get(&mosdop, wrt_json_root(&mosdop), "samples");
	for (k = 0; k < wrt_json_count(&mosdop, samples); k++) {
		wrt_tok s = wrt_json_at(&mosdop, samples, k);
		int64_t pool_id = mv_int(&mosdop, wrt_json_get(&mosdop, s, "pool"));
		char *oid = wrt_json_strdup(&mosdop, wrt_json_get(&mosdop, s, "oid")), *nsp = wrt_json_strdup(&mosdop, wrt_json_get(&mosdop, s, "nspace"));
		char *pcap = wrt_json_strdup(&mosdop, wrt_json_get(&mosdop, s, "pcap"));
		char pg[48], what[400];
		int idx = mv_pool_idx(m, pool_id);
		wri_oid o;
		uint32_t ps = 0, seed;
		wri_pg_result res;
		wr_status st;

		if (oid == NULL || nsp == NULL) {
			fprintf(stderr, "map-vectors: crush/mosdop-targets.json: a frame without its object\n");
			mv_die();
		}
		if ((uint32_t)mv_int(&mosdop, wrt_json_get(&mosdop, s, "epoch")) != m->epoch || idx < 0) {
			t->other++;
			free(oid);
			free(nsp);
			free(pcap);
			continue;
		}
		memset(&o, 0, sizeof(o));
		o.name = (const uint8_t *)oid;
		o.name_len = (uint32_t)strlen(oid);
		o.nspace = (const uint8_t *)nsp;
		o.nspace_len = (uint32_t)strlen(nsp);
		snprintf(what, sizeof(what), "MOSDOp frame of the stock client (pcap %.60s): object '%.100s' namespace '%.40s'",
			 pcap != NULL ? pcap : "?", oid, nsp);
		st = wri_place_hash(&wri_map_pools(m)[idx], &o, &ps);
		wrt_checks += 2;
		seed = wri_place_pg_seed(&wri_map_pools(m)[idx], ps);
		snprintf(pg, sizeof(pg), "%u.%x", (unsigned)pool_id, (unsigned)seed);
		if (st != WR_OK || (int64_t)ps != mv_int(&mosdop, wrt_json_get(&mosdop, s, "hash")) || (int64_t)seed != mv_int(&mosdop, wrt_json_get(&mosdop, s, "seed"))) {
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", %s: hash %u pg seed %u (status %d), the client sent hash %d seed %d\n", cx.set,
				cx.label, cx.epoch, pool_id, what, (unsigned)ps, (unsigned)seed, (int)st, (int)mv_int(&mosdop, wrt_json_get(&mosdop, s, "hash")),
				(int)mv_int(&mosdop, wrt_json_get(&mosdop, s, "seed")));
			mv_die();
		}
		st = wri_place_pg(m, (uint32_t)idx, seed, MV_WORK_MAX, &mv_ws, &res, NULL);
		if (st != WR_OK || !mv_jlist_eq(&mosdop, wrt_json_get(&mosdop, s, "acting"), res.acting, res.n_acting) ||
		    (int64_t)res.acting_primary != mv_int(&mosdop, wrt_json_get(&mosdop, s, "osd"))) {
			char a[100], b[100];

			mv_fmt_jlist(a, sizeof(a), &mosdop, wrt_json_get(&mosdop, s, "acting"));
			mv_fmt_list(b, sizeof(b), res.acting, res.n_acting);
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u), pool %" PRId64 ", pg %s, %s: acting want [%s] (connected to osd %d), got [%s] primary %d (status %d)\n",
				cx.set, cx.label, cx.epoch, pool_id, pg, what, a, (int)mv_int(&mosdop, wrt_json_get(&mosdop, s, "osd")), b, (int)res.acting_primary, (int)st);
			mv_die();
		}
		t->names++;
		free(oid);
		free(nsp);
		free(pcap);
	}
	wrt_json_free(&names);
	wrt_json_free(&exp137);
	wrt_json_free(&mosdop);
}

/* ---- the map against `ceph osd dump` -------------------------------------------------------------------------------------- */

#define MV_DUMP_CHECK(cond, ...)                                                                                       \
	do {                                                                                                           \
		wrt_checks++;                                                                                          \
		t->dumps++;                                                                                            \
		if (!(cond)) {                                                                                         \
			fprintf(stderr, "MISMATCH %s: state %s (epoch %u): osd dump vs map: ", cx->set, cx->label, cx->epoch); \
			fprintf(stderr, __VA_ARGS__);                                                                  \
			fprintf(stderr, "\n");                                                                         \
			mv_die();                                                                                      \
		}                                                                                                      \
	} while (0)

/* One override table of the dump against the held map's table: entries of tracked pools only, in both directions. */
WRT_UNUSED static void mv_dump_table(const mv_ctx *cx, const wri_osdmap *m, const wrt_json *j, wrt_tok dump, const char *key, unsigned kind,
				     mv_tally *t)
{
	wrt_tok tab = wrt_json_get(j, dump, key);
	size_t i, cnt = tab == WRT_NONE ? 0 : wrt_json_count(j, tab), kept = 0, step = kind == WRI_TAB_PRIMARY_TEMP ? 2u : 1u;

	for (i = 0; i < cnt; i += step) {
		wrt_tok e = wrt_json_at(j, tab, i);
		char *pgid = wrt_json_strdup(j, kind == WRI_TAB_PRIMARY_TEMP ? e : wrt_json_get(j, e, "pgid"));
		uint64_t pool = 0;
		uint32_t seed = 0, got_n = 0, q;
		const int32_t *got = NULL;
		int found;

		MV_DUMP_CHECK(pgid != NULL && mv_parse_pgid(pgid, &pool, &seed), "%s: a pg id that does not parse", key);
		if (mv_pool_idx(m, (int64_t)pool) < 0) {
			free(pgid);
			continue;
		}
		kept++;
		found = wri_pgtab_find(m, kind, wri_pg_key((uint32_t)pool, seed), &got, &got_n);
		MV_DUMP_CHECK(found, "%s: the entry of pg %s is missing from the map", key, pgid);
		if (!found) {
			free(pgid);
			continue;
		}
		if (kind == WRI_TAB_PRIMARY_TEMP) {
			MV_DUMP_CHECK(got_n == 1 && (int64_t)got[0] == mv_int(j, wrt_json_at(j, tab, i + 1)), "%s: pg %s primary is %d, `osd dump` says %d", key,
				      pgid, got_n == 1 ? (int)got[0] : -9, (int)mv_int(j, wrt_json_at(j, tab, i + 1)));
		} else if (kind == WRI_TAB_PG_UPMAP_PRIMARY) {
			MV_DUMP_CHECK(got_n == 1 && (int64_t)got[0] == mv_int(j, wrt_json_get(j, e, "primary_osd")), "%s: pg %s primary is %d, `osd dump` says %d",
				      key, pgid, got_n == 1 ? (int)got[0] : -9, (int)mv_int(j, wrt_json_get(j, e, "primary_osd")));
		} else if (kind == WRI_TAB_PG_UPMAP_ITEMS) {
			wrt_tok mp = wrt_json_get(j, e, "mappings");

			MV_DUMP_CHECK(got_n == 2u * wrt_json_count(j, mp), "%s: pg %s has %u values, `osd dump` says %u pairs", key, pgid, (unsigned)got_n,
				      (unsigned)wrt_json_count(j, mp));
			for (q = 0; q < wrt_json_count(j, mp) && 2u * q + 1u < got_n; q++)
				MV_DUMP_CHECK((int64_t)got[2u * q] == mv_int(j, wrt_json_get(j, wrt_json_at(j, mp, q), "from")) &&
						      (int64_t)got[2u * q + 1u] == mv_int(j, wrt_json_get(j, wrt_json_at(j, mp, q), "to")),
					      "%s: pg %s pair %u differs", key, pgid, (unsigned)q);
		} else {
			wrt_tok os = wrt_json_get(j, e, "osds");

			MV_DUMP_CHECK(got_n == wrt_json_count(j, os), "%s: pg %s has %u OSDs, `osd dump` says %u", key, pgid, (unsigned)got_n,
				      (unsigned)wrt_json_count(j, os));
			for (q = 0; q < wrt_json_count(j, os) && q < got_n; q++)
				MV_DUMP_CHECK((int64_t)got[q] == mv_int(j, wrt_json_at(j, os, q)), "%s: pg %s member %u differs", key, pgid, (unsigned)q);
		}
		free(pgid);
	}
	MV_DUMP_CHECK(m->tab[kind].n == kept, "%s: the map keeps %u entries, `osd dump` lists %u for the tracked pools", key, (unsigned)m->tab[kind].n,
		      (unsigned)kept);
}

/*
 * The held map against the `dump` of the same epoch (`ceph osd dump -f json`, pruned): epoch, max_osd, which OSDs exist, up and in,
 * weight and primary affinity (exact where the dump prints an integer, strictly between 0 and 1 where it prints a fraction: the
 * PG tables check the exact value through the answers), the pause flags, every tracked pool (present exactly when its name is in
 * the dump; geometry, size, rule, flags, hash), and the five override tables. `cfg` names the tracked pools.
 */
WRT_UNUSED static void mv_check_dump(const mv_ctx *cx, const wri_osdmap *m, const wri_mapcfg *cfg, const wrt_json *j, wrt_tok dump, mv_tally *t)
{
	wrt_tok osds = wrt_json_get(j, dump, "osds"), pools = wrt_json_get(j, dump, "pools");
	size_t i, n_osds = osds == WRT_NONE ? 0 : wrt_json_count(j, osds);
	uint32_t k, listed = 0;
	char *fl = wrt_json_strdup(j, wrt_json_get(j, dump, "flags"));
	int ok;

	MV_DUMP_CHECK((uint64_t)mv_member_int(j, dump, "epoch", &ok) == m->epoch && ok, "epoch %u, dump says %d", (unsigned)m->epoch,
		      (int)mv_member_int(j, dump, "epoch", &ok));
	MV_DUMP_CHECK((uint64_t)mv_member_int(j, dump, "max_osd", &ok) == m->max_osd && ok, "max_osd %u, dump says %d", (unsigned)m->max_osd,
		      (int)mv_member_int(j, dump, "max_osd", &ok));
	MV_DUMP_CHECK(fl != NULL, "the dump has no flags");
	if (fl != NULL) {
		/* the pause bits are the ones the chain keeps exactly (the other bits follow new_require_osd_release, see wri_osdmap_dec.h) */
		MV_DUMP_CHECK(((m->flags & WRI_MAP_F_PAUSERD) != 0) == (strstr(fl, "pauserd") != NULL), "pauserd bit: map flags 0x%x, dump '%s'", (unsigned)m->flags, fl);
		MV_DUMP_CHECK(((m->flags & WRI_MAP_F_PAUSEWR) != 0) == (strstr(fl, "pausewr") != NULL), "pausewr bit: map flags 0x%x, dump '%s'", (unsigned)m->flags, fl);
	}
	free(fl);

	for (i = 0; i < n_osds; i++) {
		wrt_tok o = wrt_json_at(j, osds, i);
		int64_t id = mv_member_int(j, o, "osd", &ok), up = mv_member_int(j, o, "up", &ok), in = mv_member_int(j, o, "in", &ok);
		int wok, aok;
		int64_t w = mv_member_int(j, o, "weight", &wok), a = mv_member_int(j, o, "primary_affinity", &aok);
		uint32_t cw, ca;

		MV_DUMP_CHECK(id >= 0 && (uint64_t)id < m->max_osd, "osd %d is outside max_osd %u", (int)id, (unsigned)m->max_osd);
		if (id < 0 || (uint64_t)id >= m->max_osd)
			continue;
		listed++;
		cw = wri_osd_weight(m, (int32_t)id);
		ca = wri_osd_aff(m, (int32_t)id);
		MV_DUMP_CHECK(wri_osd_exists(m, (int32_t)id), "osd %d is in the dump but does not exist in the map", (int)id);
		MV_DUMP_CHECK((wri_osd_up(m, (int32_t)id) != 0) == (up != 0), "osd %d up: map %d, dump %d", (int)id, wri_osd_up(m, (int32_t)id), (int)up);
		MV_DUMP_CHECK((cw != 0u) == (in != 0), "osd %d in: map weight 0x%x, dump in %d", (int)id, (unsigned)cw, (int)in);
		if (wok)
			MV_DUMP_CHECK((int64_t)cw == w * (int64_t)WRI_OSD_IN_FULL, "osd %d weight 0x%x, dump %d", (int)id, (unsigned)cw, (int)w);
		else
			MV_DUMP_CHECK(cw > 0u && cw < WRI_OSD_IN_FULL, "osd %d weight 0x%x, dump has a fraction", (int)id, (unsigned)cw);
		if (aok)
			MV_DUMP_CHECK((int64_t)ca == a * (int64_t)WRI_OSD_IN_FULL, "osd %d primary affinity 0x%x, dump %d", (int)id, (unsigned)ca, (int)a);
		else
			MV_DUMP_CHECK(ca > 0u && ca < WRI_OSD_IN_FULL, "osd %d primary affinity 0x%x, dump has a fraction", (int)id, (unsigned)ca);
	}
	MV_DUMP_CHECK(m->n_exists == listed, "the map has %u OSDs that exist, the dump lists %u", (unsigned)m->n_exists, (unsigned)listed);

	for (k = 0; k < cfg->n_pools; k++) {
		const wri_map_pool *p = &wri_map_pools(m)[k];
		wrt_tok found = WRT_NONE;
		size_t q;
		int64_t id = 0;

		for (q = 0; pools != WRT_NONE && q < wrt_json_count(j, pools); q++) {
			wrt_tok pe = wrt_json_at(j, pools, q);
			char *nm = wrt_json_strdup(j, wrt_json_get(j, pe, "pool_name"));
			int same = nm != NULL && strlen(nm) == cfg->name_len[k] && memcmp(nm, cfg->name[k], cfg->name_len[k]) == 0;

			free(nm);
			if (same) {
				found = pe;
				id = mv_member_int(j, pe, "pool", &ok);
			}
		}
		if (found == WRT_NONE) {
			MV_DUMP_CHECK(!p->present, "tracked pool name #%u is not in the dump but the map has its record (id %d)", (unsigned)k, (int)p->id);
			continue;
		}
		MV_DUMP_CHECK(p->present && p->id == id, "tracked pool name #%u is pool %d in the dump; the map record is present %d, id %d", (unsigned)k,
			      (int)id, (int)p->present, (int)p->id);
		if (!p->present)
			continue;
		MV_DUMP_CHECK((int64_t)p->pg_num == mv_member_int(j, found, "pg_num", &ok), "pool %d pg_num %u, dump %d", (int)id, (unsigned)p->pg_num,
			      (int)mv_member_int(j, found, "pg_num", &ok));
		MV_DUMP_CHECK((int64_t)p->pgp_num == mv_member_int(j, found, "pg_placement_num", &ok), "pool %d pgp_num %u, dump %d", (int)id,
			      (unsigned)p->pgp_num, (int)mv_member_int(j, found, "pg_placement_num", &ok));
		MV_DUMP_CHECK((int64_t)p->pg_num_pending == mv_member_int(j, found, "pg_num_pending", &ok), "pool %d pg_num_pending %u, dump %d", (int)id,
			      (unsigned)p->pg_num_pending, (int)mv_member_int(j, found, "pg_num_pending", &ok));
		MV_DUMP_CHECK((int64_t)p->size == mv_member_int(j, found, "size", &ok), "pool %d size %u, dump %d", (int)id, (unsigned)p->size,
			      (int)mv_member_int(j, found, "size", &ok));
		MV_DUMP_CHECK((int64_t)p->min_size == mv_member_int(j, found, "min_size", &ok), "pool %d min_size %u, dump %d", (int)id, (unsigned)p->min_size,
			      (int)mv_member_int(j, found, "min_size", &ok));
		MV_DUMP_CHECK((int64_t)p->crush_rule == mv_member_int(j, found, "crush_rule", &ok), "pool %d crush_rule %u, dump %d", (int)id,
			      (unsigned)p->crush_rule, (int)mv_member_int(j, found, "crush_rule", &ok));
		MV_DUMP_CHECK((int64_t)p->object_hash == mv_member_int(j, found, "object_hash", &ok), "pool %d object_hash %u, dump %d", (int)id,
			      (unsigned)p->object_hash, (int)mv_member_int(j, found, "object_hash", &ok));
		MV_DUMP_CHECK((int64_t)p->type == mv_member_int(j, found, "type", &ok), "pool %d type %u, dump %d", (int)id, (unsigned)p->type,
			      (int)mv_member_int(j, found, "type", &ok));
		MV_DUMP_CHECK((int64_t)p->flags == mv_member_int(j, found, "flags", &ok), "pool %d flags 0x%x, dump %d", (int)id, (unsigned)p->flags,
			      (int)mv_member_int(j, found, "flags", &ok));
		MV_DUMP_CHECK((p->status == WR_OK) == (mv_dump_pool_servable(j, dump, id) == 1),
			      "pool %d: map status %d (%s), dump says servable %d", (int)id, (int)p->status, wrt_status_name_(p->status),
			      mv_dump_pool_servable(j, dump, id));
	}
	mv_dump_table(cx, m, j, dump, "pg_temp", WRI_TAB_PG_TEMP, t);
	mv_dump_table(cx, m, j, dump, "primary_temp", WRI_TAB_PRIMARY_TEMP, t);
	mv_dump_table(cx, m, j, dump, "pg_upmap", WRI_TAB_PG_UPMAP, t);
	mv_dump_table(cx, m, j, dump, "pg_upmap_items", WRI_TAB_PG_UPMAP_ITEMS, t);
	mv_dump_table(cx, m, j, dump, "pg_upmap_primaries", WRI_TAB_PG_UPMAP_PRIMARY, t);
}

#endif /* MAP_VEC_RIG_H */
