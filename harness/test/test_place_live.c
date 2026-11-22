/* SPDX-License-Identifier: MIT */
/*
 * test_place_live.c - the live placement proof, replayed offline (module place-live; vectors in harness/vectors/public/placement/,
 * made by harness/tools/map_placement_lab.py against the lab cluster with the whole client following it over a real monitor session).
 *
 * The chain is what the client was handed on the wire: the full map of the first epoch and every incremental after it, exactly the bytes
 * the monitor sent (CRCs verified). It is applied by the real incremental path of the core, and at EVERY epoch of it:
 *
 *   - epochs.tsv: the PG rows of the tracked pools (winrbd and the four wrtest-pl-* pools of the capture) through wri_place_pg, as text,
 *     digested with FNV-1a 64, must equal the digest of what `osdmaptool --test-map-pgs-dump-all` printed over the monitor's own map of
 *     that epoch (every epoch the client adopted: creations of pools, upmaps, upmap primaries, temps, affinity, reweight, out, splits,
 *     the pool delete, the epochs around the swallowed incremental and the killed connection);
 *   - at the epoch of each state (states/<label>.json): the whole PG table column by column (raw, up, up primary, acting, acting primary),
 *     the held map against the pruned `ceph osd dump` of that epoch, the object hash of every synthetic name against the monitor's
 *     (names.json), every name of every tracked pool through the object -> hash -> PG -> OSDs pipeline against the digest of the
 *     monitor's `ceph osd map` answers (names_digest), and the answers kept in clear (the sample) one by one;
 *   - maps/e<E>.hex: the monitor's own full map of a state epoch decodes to the same compact map as the chain holds at that epoch;
 *     maps/resync-e<E>.hex: the full map the client fetched after the incremental it missed does too.
 *
 * The first mismatch stops the test and names the epoch, state, pool, PG or object and both answers.
 */
#include "map_vec_rig.h"

#define PL_TRACKED 5u
#define PL_MAXST 40u
#define PL_MAXEP 4096u

static const char *const pl_names[PL_TRACKED] = {"winrbd", "wrtest-pl-a", "wrtest-pl-b", "wrtest-pl-c", "wrtest-pl-d"};

static uint64_t fnv_add(uint64_t h, const char *s)
{
	while (*s != '\0') {
		h ^= (uint8_t)*s++;
		h *= 0x100000001B3ull;
	}
	return h;
}

#define FNV_INIT 0xCBF29CE484222325ull

typedef struct pl_state {
	wrt_json j;
	char label[64];
	uint32_t epoch;
	int done;
} pl_state;

typedef struct live {
	wrt_json names;
	uint32_t n_names;
	uint32_t *ps;
	pl_state st[PL_MAXST];
	unsigned n_st;
	uint32_t ep[PL_MAXEP], rows[PL_MAXEP];
	uint64_t dig[PL_MAXEP];
	unsigned n_ep;
	uint8_t seen[PL_MAXEP];
	uint32_t first, last;
	mv_tally t;
	uint32_t epochs_checked, pg_rows, name_rows, answers, full_maps;
	/* the full maps to compare with the chain */
	uint32_t map_epoch[32];
	uint8_t *map_blob[32];
	size_t map_len[32];
	unsigned n_map;
} live;

static void fmt_csv(char *out, size_t cap, const int32_t *v, uint32_t n)
{
	uint32_t i;
	size_t o = 0;

	out[0] = 0;
	for (i = 0; i < n && o + 16u < cap; i++)
		o += (size_t)snprintf(out + o, cap - o, "%s%d", i ? "," : "", (int)v[i]);
}

static void name_of(char *out, size_t cap, uint32_t i)
{
	if ((i & 1u) == 0)
		snprintf(out, cap, "rbd_data.5ae8a7c3d6e4.%016x", (unsigned)i);
	else
		snprintf(out, cap, "wrtest-pl-obj-%u", (unsigned)i);
}

/* pool indexes of the map in ascending pool id */
static unsigned pools_by_id(const wri_osdmap *m, uint32_t *idx)
{
	unsigned n = 0, a, b;
	uint32_t k;

	for (k = 0; k < m->n_pools; k++)
		if (wri_map_pools(m)[k].present)
			idx[n++] = k;
	for (a = 1; a < n; a++)
		for (b = a; b > 0 && wri_map_pools(m)[idx[b - 1]].id > wri_map_pools(m)[idx[b]].id; b--) {
			uint32_t t = idx[b];

			idx[b] = idx[b - 1];
			idx[b - 1] = t;
		}
	return n;
}

static void die_at(const live *lv, const char *what, uint32_t epoch, const char *extra)
{
	(void)lv;
	fprintf(stderr, "MISMATCH public/placement: epoch %u: %s%s%s\n", (unsigned)epoch, what, extra != NULL ? ": " : "", extra != NULL ? extra : "");
	mv_die();
}

/* The digest of the PG rows of every tracked pool of the held map, and how many rows. */
static uint64_t pg_digest(live *lv, const wri_osdmap *m, uint32_t *rows)
{
	uint32_t idx[WRI_MAP_POOLS_MAX];
	unsigned n = pools_by_id(m, idx), p;
	uint64_t h = FNV_INIT;

	*rows = 0;
	for (p = 0; p < n; p++) {
		const wri_map_pool *pool = &wri_map_pools(m)[idx[p]];
		uint32_t s;

		for (s = 0; s < pool->pg_num; s++) {
			wri_pg_result res;
			wr_errinfo why;
			wr_status st;
			char a[160], b[160], line[400];

			memset(&why, 0, sizeof(why));
			st = wri_place_pg(m, idx[p], s, MV_WORK_MAX, &mv_ws, &res, &why);
			if (st != WR_OK) {
				snprintf(line, sizeof(line), "pool %d pg %x: wri_place_pg returned %s", (int)pool->id, (unsigned)s, wrt_status_name_(st));
				die_at(lv, "a PG that the monitor maps cannot be placed", m->epoch, line);
			}
			fmt_csv(a, sizeof(a), res.up, res.n_up);
			fmt_csv(b, sizeof(b), res.acting, res.n_acting);
			snprintf(line, sizeof(line), "%d.%x %s %d %s %d\n", (int)pool->id, (unsigned)s, a, (int)res.up_primary, b, (int)res.acting_primary);
			h = fnv_add(h, line);
			(*rows)++;
		}
	}
	return h;
}

/* every name of every pool listed in `ids` (ascending) through hash -> PG -> OSDs: the digest, and the hash of each name against names.json */
static uint64_t names_digest(live *lv, const wri_osdmap *m, const mv_ctx *cx, const wrt_json *sj, wrt_tok ids_tok, uint32_t *rows)
{
	uint64_t h = FNV_INIT;
	size_t k;

	*rows = 0;
	for (k = 0; k < wrt_json_count(sj, ids_tok); k++) {
		int64_t id = mv_int(sj, wrt_json_at(sj, ids_tok, k));
		int pi = mv_pool_idx(m, id);
		uint32_t i;

		if (pi < 0)
			die_at(lv, "a pool the monitor answered for is not in the held map", m->epoch, cx->label);
		for (i = 0; i < lv->n_names; i++) {
			char nm[64], line[400], a[160], b[160];
			wri_oid oid;
			wri_pg_result res;
			wr_errinfo why;
			uint32_t ps = 0, seed;
			wr_status st;

			name_of(nm, sizeof(nm), i);
			memset(&oid, 0, sizeof(oid));
			oid.name = (const uint8_t *)nm;
			oid.name_len = (uint32_t)strlen(nm);
			if (wri_place_hash(&wri_map_pools(m)[pi], &oid, &ps) != WR_OK || ps != lv->ps[i]) {
				snprintf(line, sizeof(line), "object %s: hash %08x, the monitor's is %08x", nm, (unsigned)ps, (unsigned)lv->ps[i]);
				die_at(lv, "object hash", m->epoch, line);
			}
			seed = wri_place_pg_seed(&wri_map_pools(m)[pi], ps);
			memset(&why, 0, sizeof(why));
			st = wri_place_pg(m, (uint32_t)pi, seed, MV_WORK_MAX, &mv_ws, &res, &why);
			if (st != WR_OK) {
				snprintf(line, sizeof(line), "pool %d object %s: wri_place_pg returned %s", (int)id, nm, wrt_status_name_(st));
				die_at(lv, "placement", m->epoch, line);
			}
			fmt_csv(a, sizeof(a), res.up, res.n_up);
			fmt_csv(b, sizeof(b), res.acting, res.n_acting);
			snprintf(line, sizeof(line), "%d %u %s %d %s %d\n", (int)id, (unsigned)i, a, (int)res.up_primary, b, (int)res.acting_primary);
			h = fnv_add(h, line);
			(*rows)++;
		}
	}
	return h;
}

static uint64_t parse_hex64(const char *s)
{
	return strtoull(s, NULL, 16);
}

/* The answers kept in clear: [pool_id, index, epoch, ps hex, pgid, up, up_primary, acting, acting_primary]. */
static void check_answers(live *lv, const wri_osdmap *m, const mv_ctx *cx, const wrt_json *sj, wrt_tok answers)
{
	size_t k;

	for (k = 0; k < wrt_json_count(sj, answers); k++) {
		wrt_tok r = wrt_json_at(sj, answers, k);
		int64_t id = mv_int(sj, wrt_json_at(sj, r, 0));
		uint32_t i = (uint32_t)mv_int(sj, wrt_json_at(sj, r, 1));
		char nm[64], *pgid = wrt_json_strdup(sj, wrt_json_at(sj, r, 4)), *pshex = wrt_json_strdup(sj, wrt_json_at(sj, r, 3));
		mv_exp e;
		size_t nl;

		if (pgid == NULL || pshex == NULL || i >= lv->n_names || (uint32_t)mv_int(sj, wrt_json_at(sj, r, 2)) != cx->epoch)
			die_at(lv, "an answer row of a state does not fit the state", cx->epoch, cx->label);
		name_of(nm, sizeof(nm), i);
		e.j = sj;
		e.raw = WRT_NONE;
		e.up = wrt_json_at(sj, r, 5);
		e.up_primary = wrt_json_at(sj, r, 6);
		e.acting = wrt_json_at(sj, r, 7);
		e.acting_primary = wrt_json_at(sj, r, 8);
		nl = strlen(nm);
		if (nl > sizeof(nm) - 1u) /* cannot happen (name_of() bounds the name); the clamp lets gcc 15 see it: -Warray-bounds at -Os with the sanitizers */
			nl = sizeof(nm) - 1u;
		mv_name_check(cx, m, id, (const uint8_t *)nm, nl, NULL, 0, (int64_t)parse_hex64(pshex), pgid, &e, &lv->t);
		lv->answers++;
		free(pgid);
		free(pshex);
	}
}

static void live_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	live *lv = (live *)user;
	unsigned i, e;
	uint32_t rows = 0;
	uint64_t d;

	/* epochs.tsv */
	for (e = 0; e < lv->n_ep && lv->ep[e] != epoch; e++)
		;
	if (e == lv->n_ep) {
		char x[64];

		snprintf(x, sizeof(x), "epoch %u is in the chain but not in epochs.tsv", (unsigned)epoch);
		die_at(lv, x, epoch, NULL);
	}
	d = pg_digest(lv, m, &rows);
	wrt_checks++;
	if (rows != lv->rows[e] || d != lv->dig[e]) {
		char x[200];

		snprintf(x, sizeof(x), "%u PG rows of the tracked pools digest to %016llx, osdmaptool's %u rows digest to %016llx", (unsigned)rows,
			 (unsigned long long)d, (unsigned)lv->rows[e], (unsigned long long)lv->dig[e]);
		die_at(lv, "the PG tables of the tracked pools differ from osdmaptool's (see the states for the column-by-column view)", epoch, x);
	}
	lv->seen[e] = 1;
	lv->epochs_checked++;
	lv->pg_rows += rows;

	/* the states of this epoch */
	for (i = 0; i < lv->n_st; i++) {
		mv_ctx cx;
		wrt_tok pgs, dump;
		mv_tally before;
		uint32_t h, nrows, want_rows;
		const wrt_json *sj = &lv->st[i].j;

		if (lv->st[i].epoch != epoch)
			continue;
		cx.set = "public/placement/states";
		cx.label = lv->st[i].label;
		cx.epoch = epoch;
		pgs = wrt_json_get(sj, wrt_json_root(sj), "pgs");
		dump = wrt_json_get(sj, wrt_json_root(sj), "dump");
		mv_check_dump(&cx, m, cfg, sj, dump, &lv->t);
		before = lv->t;
		h = mv_table(&cx, m, sj, pgs, dump, &lv->t);
		WRT_CHECK_U64(h, wrt_json_count(sj, pgs));
		WRT_CHECK_U64(lv->t.pgs + lv->t.refused - before.pgs - before.refused, h);
		WRT_CHECK_U64(lv->t.refused, 0);
		{
			char *want = wrt_json_strdup(sj, wrt_json_get(sj, wrt_json_root(sj), "names_digest"));
			uint64_t got = names_digest(lv, m, &cx, sj, wrt_json_get(sj, wrt_json_root(sj), "names_pool_ids"), &nrows);

			want_rows = (uint32_t)mv_int(sj, wrt_json_get(sj, wrt_json_root(sj), "names_compared"));
			if (want == NULL || nrows != want_rows || got != parse_hex64(want)) {
				char x[200];

				snprintf(x, sizeof(x), "%u names digest to %016llx, the monitor's %u answers digest to %s", (unsigned)nrows, (unsigned long long)got,
					 (unsigned)want_rows, want != NULL ? want : "?");
				die_at(lv, "the object placements differ from `ceph osd map`", epoch, x);
			}
			free(want);
			wrt_checks++;
			lv->name_rows += nrows;
		}
		check_answers(lv, m, &cx, sj, wrt_json_get(sj, wrt_json_root(sj), "answers"));
		lv->st[i].done++;
	}

	/* full maps of this epoch against the chain */
	for (i = 0; i < lv->n_map; i++) {
		islot s;
		wr_errinfo why;
		wr_status st;

		if (lv->map_epoch[i] != epoch)
			continue;
		st = mv_decode_one(cfg, lv->map_blob[i], lv->map_len[i], &s, &why);
		if (st != WR_OK) {
			char x[160];

			snprintf(x, sizeof(x), "the monitor's full map does not decode: %s (%s)", wrt_status_name_(st), why.what != NULL ? why.what : "");
			die_at(lv, "full map", epoch, x);
		}
		WRT_CHECK_U64(islot_map(&s)->epoch, epoch);
		rig_cmp_core(islot_map(&s), m);
		islot_free(&s);
		lv->full_maps++;
	}
}

static void load_epochs_tsv(live *lv)
{
	FILE *f = fopen(wrt_vec_path("public/placement/epochs.tsv"), "r");
	char ln[256];

	if (f == NULL) {
		fprintf(stderr, "map-vectors: cannot read public/placement/epochs.tsv\n");
		mv_die();
	}
	while (fgets(ln, sizeof(ln), f) != NULL) {
		unsigned e, r;
		char dg[40];

		if (ln[0] == '#')
			continue;
		if (sscanf(ln, "%u %u %39s", &e, &r, dg) != 3 || lv->n_ep >= PL_MAXEP) {
			fprintf(stderr, "map-vectors: bad line in epochs.tsv: %s", ln);
			mv_die();
		}
		lv->ep[lv->n_ep] = e;
		lv->rows[lv->n_ep] = r;
		lv->dig[lv->n_ep] = parse_hex64(dg);
		lv->n_ep++;
	}
	fclose(f);
}

static void load_names(live *lv)
{
	wrt_tok ps;
	size_t i;

	mv_load_json(&lv->names, "public/placement/names.json");
	lv->n_names = (uint32_t)mv_int(&lv->names, wrt_json_get(&lv->names, wrt_json_root(&lv->names), "count"));
	ps = wrt_json_get(&lv->names, wrt_json_root(&lv->names), "ps");
	WRT_CHECK_U64(wrt_json_count(&lv->names, ps), lv->n_names);
	WRT_CHECK(lv->n_names >= 2000u);
	lv->ps = (uint32_t *)calloc(lv->n_names, sizeof(uint32_t));
	if (lv->ps == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	for (i = 0; i < lv->n_names; i++) {
		char *s = wrt_json_strdup(&lv->names, wrt_json_at(&lv->names, ps, i));

		lv->ps[i] = s != NULL ? (uint32_t)parse_hex64(s) : 0;
		free(s);
	}
}

static void load_states(live *lv)
{
	wrt_json idx;
	wrt_tok states, files;
	size_t i;

	mv_load_json(&idx, "public/placement/INDEX.json");
	states = wrt_json_get(&idx, wrt_json_root(&idx), "states");
	lv->first = (uint32_t)mv_int(&idx, wrt_json_get(&idx, wrt_json_root(&idx), "base_epoch"));
	lv->last = (uint32_t)mv_int(&idx, wrt_json_get(&idx, wrt_json_root(&idx), "last_epoch"));
	lv->n_st = (unsigned)wrt_json_count(&idx, states);
	WRT_CHECK(lv->n_st >= 20u && lv->n_st <= PL_MAXST);
	for (i = 0; i < lv->n_st && i < PL_MAXST; i++) {
		char *label = wrt_json_strdup(&idx, wrt_json_at(&idx, states, i)), rel[200];

		if (label == NULL)
			mv_die();
		snprintf(lv->st[i].label, sizeof(lv->st[i].label), "%s", label);
		snprintf(rel, sizeof(rel), "public/placement/states/%s.json", label);
		mv_load_json(&lv->st[i].j, rel);
		lv->st[i].epoch = (uint32_t)mv_int(&lv->st[i].j, wrt_json_get(&lv->st[i].j, wrt_json_root(&lv->st[i].j), "epoch"));
		free(label);
	}
	/* the full maps listed in the index: maps/e<E>.hex of state epochs and maps/resync-e<E>.hex */
	files = wrt_json_get(&idx, wrt_json_root(&idx), "files");
	for (i = 0; i < wrt_json_count(&idx, files); i++) {
		wrt_tok v;
		const char *key = wrt_json_key_at(&idx, files, i, &v);
		unsigned e = 0;
		const char *p;

		if (strncmp(key, "maps/", 5) != 0)
			continue;
		p = key + 5;
		if (strncmp(p, "resync-e", 8) == 0)
			e = (unsigned)strtoul(p + 8, NULL, 10);
		else if (p[0] == 'e')
			e = (unsigned)strtoul(p + 1, NULL, 10);
		if (e == 0 || lv->n_map >= 32u) {
			fprintf(stderr, "map-vectors: unexpected file %s in the index\n", key);
			mv_die();
		}
		{
			char rel[200];

			snprintf(rel, sizeof(rel), "public/placement/%s", key);
			mv_load_hex(rel, &lv->map_blob[lv->n_map], &lv->map_len[lv->n_map]);
		}
		lv->map_epoch[lv->n_map++] = e;
	}
	wrt_json_free(&idx);
}

int main(void)
{
	static live lv;
	wrt_mg_line *ls = NULL;
	size_t nl = 0, i, nbase = 0;
	uint8_t *base = NULL;
	mv_chain c;
	wr_errinfo why;
	char rel[128];
	unsigned s, covered_states = 0;

	load_epochs_tsv(&lv);
	load_names(&lv);
	load_states(&lv);
	if (wrt_mg_load_epoch_lines(wrt_vec_path("public/placement/incrementals.hex"), &ls, &nl) != 0 || nl < 50u) {
		fprintf(stderr, "map-vectors: public/placement/incrementals.hex is missing or short\n");
		mv_die();
	}
	snprintf(rel, sizeof(rel), "public/placement/base-e%u.hex", (unsigned)lv.first);
	mv_load_hex(rel, &base, &nbase);
	WRT_CHECK_U64(ls[0].epoch, lv.first + 1u);
	WRT_CHECK_U64(ls[nl - 1u].epoch, lv.last);
	mv_chain_open(&c, pl_names, PL_TRACKED);
	if (mv_chain_full(&c, base, nbase, &why) != WR_OK) {
		fprintf(stderr, "map-vectors: the base map does not decode: %s\n", why.what != NULL ? why.what : "?");
		mv_die();
	}
	WRT_CHECK_U64(mv_chain_map(&c)->epoch, lv.first);
	live_epoch(&lv, mv_chain_map(&c), &c.cfg, lv.first);
	for (i = 0; i < nl; i++) {
		if (ls[i].epoch != lv.first + 1u + (uint32_t)i || mv_chain_inc(&c, ls[i].p, ls[i].n, &why) != WR_OK) {
			fprintf(stderr, "map-vectors: placement chain, epoch %u: %s\n", ls[i].epoch, why.what != NULL ? why.what : "does not follow");
			mv_die();
		}
		WRT_CHECK_U64(mv_chain_map(&c)->epoch, ls[i].epoch);
		live_epoch(&lv, mv_chain_map(&c), &c.cfg, ls[i].epoch);
	}
	mv_chain_close(&c);
	wrt_mg_free_lines(ls, nl);
	free(base);

	/* everything in epochs.tsv was reached once, every state was reached once, every full map was compared */
	for (s = 0; s < lv.n_ep; s++)
		if (lv.ep[s] >= lv.first && lv.ep[s] <= lv.last && !lv.seen[s]) {
			fprintf(stderr, "MISMATCH public/placement: epoch %u of epochs.tsv was never reached by the chain\n", (unsigned)lv.ep[s]);
			mv_die();
		}
	for (s = 0; s < lv.n_st; s++) {
		WRT_CHECK_U64(lv.st[s].done, 1);
		covered_states += lv.st[s].done == 1;
	}
	WRT_CHECK_U64(lv.full_maps, lv.n_map);
	WRT_CHECK(lv.n_map >= 5u);
	WRT_CHECK(lv.t.dumps >= 2000u);
	WRT_CHECK(lv.name_rows >= 100000u);
	WRT_CHECK(lv.epochs_checked >= 90u);
	fprintf(stderr,
		"public/placement: %u epochs (%u..%u) digested PG table by PG table, %u PG rows; %u states: %u PG rows column by column, %u names through the "
		"object pipeline (%u answers in clear), %u osd-dump fields, %u full maps equal to the chain\n",
		(unsigned)lv.epochs_checked, (unsigned)lv.first, (unsigned)lv.last, (unsigned)lv.pg_rows, covered_states, (unsigned)lv.t.pgs, (unsigned)lv.name_rows,
		(unsigned)lv.answers, (unsigned)lv.t.dumps, (unsigned)lv.full_maps);
	for (s = 0; s < lv.n_st; s++)
		wrt_json_free(&lv.st[s].j);
	for (s = 0; s < lv.n_map; s++)
		free(lv.map_blob[s]);
	wrt_json_free(&lv.names);
	free(lv.ps);
	return wrt_finish();
}
