/* SPDX-License-Identifier: MIT */
/*
 * test_map_vec_pgs.c - the PG tables of the committed vectors, through the real incremental path of the core: every state is rebuilt
 * by wri_osdmap_apply_inc from the bytes of the incrementals (nothing else), and wri_place_pg must give, for every PG the vector
 * lists, the five columns Ceph printed (osdmaptool --test-map-pgs-dump-all: raw, up, up primary, acting, acting primary).
 *
 *   osdmap/placement-states.json   24 states of pools 1 and 2 of the first lab set, epochs 1 .. 89 (epoch 1 is the full map inside
 *                                  incremental 1; the rest are incrementals applied in order, CRCs verified)
 *   public/mapb/states/<label>.json the 70 states S0 .. S15 of the second set, from the full map of epoch 666 and the 259
 *                                  incrementals up to 925: pg_num not a power of two, pgp_num below pg_num, splits and merges in
 *                                  progress, pg_upmap, pg_upmap_items (valid and invalid pairs), pg_upmap_primaries, pg_temp,
 *                                  primary_temp, affinity, reweight, out, down, a pool without HASHPSPOOL, pool create / rename /
 *                                  delete, an erasure pool and a cache tier (must be refused), choose_args weight sets
 *
 * Three chains with different tracked pool names cover the 16 pools of the second set (a slot tracks at most 8); a row of a pool the
 * chain does not track is taken by another chain, and every row of every state must be handled exactly once. At every state the
 * held map is also compared with the `ceph osd dump` of that epoch (OSD up / in / weight / affinity, pool geometry, five tables).
 *
 * The first mismatch stops the run and prints the vector set, state, pool, PG and both answers.
 */
#include "map_vec_rig.h"

/* ---- the first set ------------------------------------------------------------------------------------------------------ */

typedef struct set1 {
	wrt_json states;
	wrt_tok obj;
	mv_tally t;
	uint32_t visited, rows, handled;
} set1;

static void set1_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	set1 *s = (set1 *)user;
	size_t k;

	(void)cfg;
	for (k = 0; k < wrt_json_count(&s->states, s->obj); k++) {
		wrt_tok sv, pgs;
		const char *label = wrt_json_key_at(&s->states, s->obj, k, &sv);
		mv_ctx cx;
		uint32_t h;

		if ((uint32_t)mv_int(&s->states, wrt_json_get(&s->states, sv, "epoch")) != epoch)
			continue;
		pgs = wrt_json_get(&s->states, sv, "pgs");
		cx.set = "osdmap/placement-states.json";
		cx.label = label;
		cx.epoch = epoch;
		h = mv_table(&cx, m, &s->states, pgs, WRT_NONE, &s->t);
		s->visited++;
		s->rows += (uint32_t)wrt_json_count(&s->states, pgs);
		s->handled += h;
		WRT_CHECK_U64(h, wrt_json_count(&s->states, pgs)); /* both pools are tracked: nothing is left to another chain */
	}
}

static void test_set1(void)
{
	static const char *const names[] = {".mgr", "winrbd"};
	set1 s;
	size_t k;

	memset(&s, 0, sizeof(s));
	mv_load_json(&s.states, "osdmap/placement-states.json");
	s.obj = wrt_json_get(&s.states, wrt_json_root(&s.states), "states");
	WRT_CHECK_U64(wrt_json_count(&s.states, s.obj), 24);
	mv_replay_set1(names, 2, set1_epoch, &s);
	WRT_CHECK_U64(s.visited, 24);
	WRT_CHECK_U64(s.handled, s.rows);
	WRT_CHECK_U64(s.t.refused, 0); /* both pools are replicated, nothing is refused */
	WRT_CHECK_U64(s.t.pgs, s.rows);
	WRT_CHECK(s.rows >= 600);
	for (k = 0; k < wrt_json_count(&s.states, s.obj); k++) { /* every state names an epoch the chain reached */
		wrt_tok sv;

		(void)wrt_json_key_at(&s.states, s.obj, k, &sv);
		WRT_CHECK(mv_int(&s.states, wrt_json_get(&s.states, sv, "epoch")) <= 89);
	}
	fprintf(stderr, "osdmap/ states: %u states, %u PGs compared (raw, up, up primary, acting, acting primary)\n", s.visited, s.t.pgs);
	wrt_json_free(&s.states);
}

/* ---- the second set ------------------------------------------------------------------------------------------------------ */

#define MAXST 80u

typedef struct mapb_states {
	wrt_json idx;
	wrt_json sj[MAXST];
	char label[MAXST][64];
	uint32_t epoch[MAXST];
	uint32_t rows[MAXST], handled[MAXST];
	unsigned n;
	mv_tally t;
	uint32_t dump_epochs;
} mapb_states;

static void mapb_epoch(void *user, const wri_osdmap *m, const wri_mapcfg *cfg, uint32_t epoch)
{
	mapb_states *s = (mapb_states *)user;
	unsigned i;

	for (i = 0; i < s->n; i++) {
		mv_ctx cx;
		wrt_tok pgs, dump;
		mv_tally before = s->t;
		uint32_t h;

		if (s->epoch[i] != epoch)
			continue;
		cx.set = "public/mapb/states";
		cx.label = s->label[i];
		cx.epoch = epoch;
		pgs = wrt_json_get(&s->sj[i], wrt_json_root(&s->sj[i]), "pgs");
		dump = wrt_json_get(&s->sj[i], wrt_json_root(&s->sj[i]), "dump");
		mv_check_dump(&cx, m, cfg, &s->sj[i], dump, &s->t);
		h = mv_table(&cx, m, &s->sj[i], pgs, dump, &s->t);
		s->handled[i] += h;
		WRT_CHECK_U64(h, s->t.pgs + s->t.refused - before.pgs - before.refused);
		s->dump_epochs++;
	}
}

/* "s07c-primary-affinity" -> 7, "s00-base-pools" -> 0, "s99-restored" -> 99; -1 if it does not look like that. */
static int state_class(const char *label)
{
	if (label[0] != 's' || label[1] < '0' || label[1] > '9' || label[2] < '0' || label[2] > '9')
		return -1;
	return (label[1] - '0') * 10 + (label[2] - '0');
}

static void test_mapb(void)
{
	static const struct {
		const char *const *names;
		unsigned n;
	} chains[3] = {{mv_set_a, MV_SET_A_N}, {mv_set_b, MV_SET_B_N}, {mv_set_c, MV_SET_C_N}};
	mapb_states *s = (mapb_states *)calloc(1, sizeof(*s));
	wrt_tok states;
	unsigned i, c, seen_class[100];
	uint32_t total_rows = 0;

	if (s == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	memset(seen_class, 0, sizeof(seen_class));
	mv_load_json(&s->idx, "public/mapb/INDEX.json");
	states = wrt_json_get(&s->idx, wrt_json_root(&s->idx), "states");
	s->n = (unsigned)wrt_json_count(&s->idx, states);
	WRT_CHECK_U64(s->n, 70);
	if (s->n > MAXST)
		mv_die();
	for (i = 0; i < s->n; i++) {
		wrt_tok e = wrt_json_at(&s->idx, states, i);
		char *label = wrt_json_strdup(&s->idx, wrt_json_get(&s->idx, e, "label")), *file = wrt_json_strdup(&s->idx, wrt_json_get(&s->idx, e, "file"));
		char rel[256];

		if (label == NULL || file == NULL) {
			fprintf(stderr, "map-vectors: INDEX.json state %u has no label or file\n", i);
			mv_die();
		}
		snprintf(s->label[i], sizeof(s->label[i]), "%s", label);
		s->epoch[i] = (uint32_t)mv_int(&s->idx, wrt_json_get(&s->idx, e, "epoch"));
		snprintf(rel, sizeof(rel), "public/mapb/%s", file);
		mv_load_json(&s->sj[i], rel);
		s->rows[i] = (uint32_t)wrt_json_count(&s->sj[i], wrt_json_get(&s->sj[i], wrt_json_root(&s->sj[i]), "pgs"));
		WRT_CHECK_U64(mv_int(&s->sj[i], wrt_json_get(&s->sj[i], wrt_json_root(&s->sj[i]), "epoch")), s->epoch[i]);
		total_rows += s->rows[i];
		if (state_class(label) >= 0)
			seen_class[state_class(label)]++;
		free(label);
		free(file);
	}
	for (c = 0; c < 3; c++)
		mv_replay_mapb(chains[c].names, chains[c].n, mapb_epoch, s);

	/* every row of every state was taken by exactly one chain (compared, or refused for an erasure or tiered pool) */
	for (i = 0; i < s->n; i++) {
		if (s->handled[i] != s->rows[i]) {
			fprintf(stderr, "MISMATCH public/mapb/states: state %s (epoch %u): %u of %u PG rows were handled by a chain\n", s->label[i], s->epoch[i],
				(unsigned)s->handled[i], (unsigned)s->rows[i]);
			mv_die();
		}
	}
	WRT_CHECK_U64(s->t.pgs + s->t.refused, total_rows);
	WRT_CHECK(total_rows >= 2000);
	WRT_CHECK(s->t.refused >= 20); /* the erasure pool and the cache tier are in the tables, and must have been refused, not compared */
	WRT_CHECK(s->t.pgs >= 1900);
	WRT_CHECK(s->t.dumps >= 5000);
	/* the capture's scenario classes S0 .. S15 (S0 base, S99 restored) are all there, each with at least one state */
	for (c = 0; c <= 15; c++)
		WRT_CHECK(seen_class[c] != 0);
	WRT_CHECK(seen_class[99] != 0);
	fprintf(stderr, "public/mapb states: %u states, %u PGs compared, %u refused (erasure / tier), %u osd-dump fields compared\n", s->n, s->t.pgs,
		s->t.refused, s->t.dumps);
	for (i = 0; i < s->n; i++)
		wrt_json_free(&s->sj[i]);
	wrt_json_free(&s->idx);
	free(s);
}

int main(void)
{
	test_set1();
	test_mapb();
	return wrt_finish();
}
