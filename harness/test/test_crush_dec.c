/* SPDX-License-Identifier: MIT */
/*
 * test_crush_dec.c - the CRUSH blob decoder (core/src/crush/wri_crush_dec.c, wri_crush_dec2.c) and wri_crush_check.
 *
 *   - the two lab blobs of harness/vectors/crush against crush-blob.expected.json (buckets, items, weights, rules, tunables,
 *     max_devices), their compact regions byte for byte equal, and every truncation point of both;
 *   - the kitchen sink map of crush_dec_gen.h (every algorithm, a hole, two rule types, names with the empty-name quirk,
 *     every tunable group, classes, choose_args, the MSR pair) decoded at every stage and read back through the accessors;
 *   - special maps: empty map, empty buckets, the largest bucket, the most slots, keys of choose_args that do not fit an s32;
 *   - the negative table: one patched field, one refusal, with the reason in the errinfo;
 *   - the room: every capacity below the region size is WR_E_MAP_BUDGET with the guard bytes intact; two pre-fills give the
 *     same bytes;
 *   - wri_crush_check on every success and on corrupted regions.
 *
 * `test_crush_dec --emit-seeds DIR` writes the blobs the fuzz target uses as seeds (and nothing else).
 */
#include "wrt.h"
#include "crush_dec_gen.h"
#include "crush_dec_real.h"
#include "wri_crush.h"

#include <errno.h>
#include <sys/stat.h>

static const char *seed_dir; /* set by --emit-seeds: every blob a test builds is also written there */

static void seed_write(const char *name, const uint8_t *p, size_t n)
{
	char path[512];
	FILE *f;

	if (seed_dir == NULL)
		return;
	snprintf(path, sizeof(path), "%s/%s", seed_dir, name);
	f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "cannot write %s\n", path);
		exit(1);
	}
	if (n != 0 && fwrite(p, 1, n, f) != n)
		exit(1);
	fclose(f);
}

/* ---- rooms with guard bands ------------------------------------------------------------------------------- */

#define GUARD 32u

typedef struct room {
	uint8_t *buf, *out;
	size_t cap;
	uint8_t pat;
} room;

static void room_new(room *r, size_t cap, uint8_t pat)
{
	r->buf = (uint8_t *)malloc(cap + 2u * GUARD);
	r->out = r->buf + GUARD;
	r->cap = cap;
	r->pat = pat;
	memset(r->buf, pat, cap + 2u * GUARD);
}

static int room_guards_ok(const room *r)
{
	size_t i;

	for (i = 0; i < GUARD; i++)
		if (r->buf[i] != r->pat || r->buf[GUARD + r->cap + i] != r->pat)
			return 0;
	return 1;
}

static void room_free(room *r)
{
	free(r->buf);
	r->buf = r->out = NULL;
}

/* Decode into a fresh room of `cap` bytes filled with `pat`; the room stays allocated for the caller to read and free. */
static wr_status dec(const uint8_t *blob, size_t n, size_t cap, uint8_t pat, room *r, size_t *used, wr_errinfo *why)
{
	wr_status st;

	room_new(r, cap, pat);
	memset(why, 0, sizeof(*why));
	*used = 12345;
	st = wri_crush_decode(blob, n, r->out, cap, used, why);
	WRT_CHECK(room_guards_ok(r));
	return st;
}

#define BIG 700000u /* a room large enough for every test map */

/* Decode, expect success, structural check, the pre-fill independence, and a decode into a room of exactly the region's
 * size. Returns the first room (caller frees). */
static const wri_crush *dec_ok(const uint8_t *blob, size_t n, room *r, size_t *used)
{
	wr_errinfo why;
	room r2, r3;
	size_t u2, u3;

	WRT_CHECK_STATUS(WR_OK, dec(blob, n, BIG, 0x00, r, used, &why));
	WRT_CHECK(why.status == WR_OK);
	WRT_CHECK(*used >= WRI_CRUSH_HDR_BYTES && *used <= BIG);
	WRT_CHECK(*used % 4u == 0u);
	WRT_CHECK_STATUS(WR_OK, dec(blob, n, BIG, 0xff, &r2, &u2, &why));
	WRT_CHECK_STATUS(WR_OK, dec(blob, n, *used, 0xa5, &r3, &u3, &why));
	WRT_CHECK(u2 == *used && u3 == *used);
	WRT_CHECK_MEM(r->out, r2.out, *used);
	WRT_CHECK_MEM(r->out, r3.out, *used);
	room_free(&r2);
	room_free(&r3);
	WRT_CHECK_STATUS(WR_OK, wri_crush_check((const wri_crush *)(const void *)r->out, *used));
	return (const wri_crush *)(const void *)r->out;
}

/* Decode, expect `want`, a reason containing `what`, used 0, the header unusable. a0 is checked unless SIZE_MAX. */
static void dec_bad(const char *name, const uint8_t *blob, size_t n, wr_status want, const char *what, size_t a0)
{
	wr_errinfo why;
	room r;
	size_t used;
	wr_status st = dec(blob, n, BIG, 0xa5, &r, &used, &why);

	if (st != want)
		fprintf(stderr, "%s: status %d (%s), want %d (%s)\n", name, st, wr_status_name(st), want, wr_status_name(want));
	WRT_CHECK(st == want);
	WRT_CHECK(used == 0);
	WRT_CHECK(why.status == want);
	WRT_CHECK(why.module == WR_MOD_CRUSH);
	WRT_CHECK(why.what != NULL);
	if (why.what != NULL && what != NULL && strstr(why.what, what) == NULL) {
		fprintf(stderr, "%s: reason \"%s\" does not contain \"%s\"\n", name, why.what, what);
		WRT_CHECK(0);
	}
	if (a0 != SIZE_MAX && why.a0 != a0) {
		fprintf(stderr, "%s: a0 = %llu, want %llu\n", name, (unsigned long long)why.a0, (unsigned long long)a0);
		WRT_CHECK(0);
	}
	WRT_CHECK(((const wri_crush *)(const void *)r.out)->magic != WRI_CRUSH_MAGIC);
	/* the errinfo is optional */
	WRT_CHECK_STATUS(want, wri_crush_decode(blob, n, r.out, BIG, &used, NULL));
	room_free(&r);
}

/* ---- read back through the accessors ---------------------------------------------------------------------- */

static void expect_bucket(const wri_crush *c, uint32_t slot, int32_t id, unsigned type, unsigned alg, uint32_t size,
			  const int32_t *items, const uint32_t *w1, const uint32_t *w2)
{
	const wri_cbucket *b = wri_crush_bucket_at(c, slot);

	WRT_CHECK(b != NULL);
	if (b == NULL)
		return;
	WRT_CHECK(b->id == id && b->type == type && b->alg == alg && b->hash == 0 && b->size == size && b->reserved == 0);
	if (size != 0 && items != NULL)
		WRT_CHECK_MEM(wri_cbucket_items(b), items, 4u * size);
	if (size != 0 && w1 != NULL)
		WRT_CHECK_MEM(wri_cbucket_w(b), w1, 4u * size);
	if (size != 0 && w2 != NULL)
		WRT_CHECK_MEM(wri_cbucket_sums(b), w2, 4u * size);
	WRT_CHECK(wri_crush_bucket(c, id) == b);
}

static void expect_tun(const wri_crush *c, int stage)
{
	WRT_CHECK_U64(c->tun.choose_local_tries, stage >= KS_STAGE_TUN_A ? 0 : 2);
	WRT_CHECK_U64(c->tun.choose_local_fallback_tries, stage >= KS_STAGE_TUN_A ? 0 : 5);
	WRT_CHECK_U64(c->tun.choose_total_tries, stage >= KS_STAGE_TUN_A ? 50 : 19);
	WRT_CHECK_U64(c->tun.chooseleaf_descend_once, stage >= KS_STAGE_DESCEND ? 1 : 0);
	WRT_CHECK_U64(c->tun.chooseleaf_vary_r, stage >= KS_STAGE_VARY_R ? 1 : 0);
	WRT_CHECK_U64(c->tun.chooseleaf_stable, stage >= KS_STAGE_STABLE ? 1 : 0);
	WRT_CHECK(c->tun.reserved[0] == 0 && c->tun.reserved[1] == 0);
}

static void expect_args(const wri_crush *c, int stage)
{
	const uint32_t *ix;
	const wri_cargs *a;

	if (stage < KS_STAGE_ARGS) {
		WRT_CHECK(c->n_sets == 0 && c->set_tab == 0);
		WRT_CHECK(wri_crush_args_index(c, -1) == NULL && wri_crush_args_index(c, 5) == NULL);
		return;
	}
	WRT_CHECK(c->n_sets == 2 && c->set_tab != 0);
	/* pool 5: its own set, only bucket slot 1, ids only */
	ix = wri_crush_args_index(c, 5);
	WRT_CHECK(ix != NULL);
	if (ix != NULL) {
		WRT_CHECK(wri_crush_args_of(c, ix, 0) == NULL);
		a = wri_crush_args_of(c, ix, 1);
		WRT_CHECK(a != NULL && a->n_pos == 0 && a->has_ids == 1);
		if (a != NULL) {
			WRT_CHECK(wri_cargs_row(a, 3, 0) == NULL);
			WRT_CHECK(wri_cargs_ids(a, 3) != NULL);
			WRT_CHECK_MEM(wri_cargs_ids(a, 3), ks_a1b0_ids, 12);
		}
	}
	/* any other pool: the default set */
	ix = wri_crush_args_index(c, 77);
	WRT_CHECK(ix != NULL && ix != wri_crush_args_index(c, 5));
	if (ix != NULL) {
		a = wri_crush_args_of(c, ix, 0);
		WRT_CHECK(a != NULL && a->n_pos == 1 && a->has_ids == 0 && wri_cargs_ids(a, 3) == NULL);
		if (a != NULL)
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 0), ks_a0b0_row, 12);
		a = wri_crush_args_of(c, ix, 1);
		WRT_CHECK(a != NULL && a->n_pos == 2 && a->has_ids == 1);
		if (a != NULL) {
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 0), ks_a0b1_rows[0], 12);
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 1), ks_a0b1_rows[1], 12);
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 9), ks_a0b1_rows[1], 12);
			WRT_CHECK_MEM(wri_cargs_ids(a, 3), ks_a0b1_ids, 12);
		}
		WRT_CHECK(wri_crush_args_of(c, ix, 2) == NULL);
	}
}

static void ks_verify(const wri_crush *c, size_t used, int stage)
{
	const wri_crule *r;

	WRT_CHECK(c->magic == WRI_CRUSH_MAGIC && c->bytes == used);
	WRT_CHECK(c->max_buckets == KS_BUCKETS && c->max_rules == KS_RULES);
	WRT_CHECK(c->max_devices == 13); /* item 11 gives 12, the name_map key 12 raises it; the wire said 999 */
	expect_tun(c, stage);
	expect_bucket(c, 0, -1, 11, 5, 3, ks_b0_items, ks_b0_w, NULL);
	expect_bucket(c, 1, -2, 1, 5, 3, ks_b1_items, ks_b1_w, NULL);
	expect_bucket(c, 2, -3, 1, 2, 2, ks_b2_items, ks_b2_w, ks_b2_sums);
	WRT_CHECK(wri_crush_bucket_at(c, 3) == NULL);
	expect_bucket(c, 4, -5, 1, 4, 2, ks_b4_items, ks_b4_straws, NULL);
	expect_bucket(c, 5, -6, 1, 1, 3, ks_b5_items, NULL, NULL);
	expect_bucket(c, 6, -7, 1, 3, 2, ks_b6_items, NULL, NULL);
	WRT_CHECK(wri_crush_bucket_at(c, 7) == NULL && wri_crush_bucket(c, -8) == NULL && wri_crush_bucket(c, 0) == NULL);
	WRT_CHECK(wri_crush_bucket(c, -4) == NULL && wri_crush_bucket(c, (int32_t)0x80000000) == NULL);
	WRT_CHECK(wri_crush_rule_kind(c, 0) == 2 && wri_crush_rule_kind(c, 1) == 1 && wri_crush_rule_kind(c, 2) == 0 &&
		  wri_crush_rule_kind(c, 3) == 0);
	r = wri_crush_rule(c, 0);
	WRT_CHECK(r != NULL && r->nsteps == 3);
	if (r != NULL)
		WRT_CHECK_MEM(wri_crule_steps(r), ks_r0_steps, 36);
	WRT_CHECK(wri_crush_rule(c, 1) == NULL && wri_crush_rule(c, 2) == NULL && wri_crush_rule(c, 3) == NULL);
	expect_args(c, stage);
}

/* ---- the lab blobs ------------------------------------------------------------------------------------------ */

static int load_hex(const char *rel, uint8_t **out, size_t *n)
{
	uint8_t *txt;
	size_t tn;
	int rc;

	size_t i, k = 0;
	int bol = 1, comment = 0;

	if (wrt_read_file(wrt_vec_path(rel), &txt, &tn) != 0)
		return -1;
	/* some vector files start with '#' comment lines */
	for (i = 0; i < tn; i++) {
		if (bol)
			comment = txt[i] == '#';
		bol = txt[i] == '\n';
		if (!comment)
			txt[k++] = txt[i];
	}
	tn = k;
	rc = wrt_hex_decode((const char *)txt, tn, out, n);
	free(txt);
	return rc;
}

static void check_lab_json(const wri_crush *c, size_t used)
{
	wrt_json j;
	wrt_tok root, bk, ru, tn, t;
	size_t i, k, nb;
	int ok;
	uint32_t slot_seen = 0;

	if (wrt_json_load_vec(&j, "crush/crush-blob.expected.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wri_crush_check(c, used) == WR_OK);
	WRT_CHECK_U64(c->max_buckets, wrt_json_int(&j, wrt_json_get(&j, root, "max_buckets"), &ok));
	WRT_CHECK_U64(c->max_rules, wrt_json_int(&j, wrt_json_get(&j, root, "max_rules"), &ok));
	WRT_CHECK_U64((uint32_t)c->max_devices, wrt_json_int(&j, wrt_json_get(&j, root, "max_devices_recomputed"), &ok));
	WRT_CHECK(c->max_devices == 3);
	bk = wrt_json_get(&j, root, "buckets");
	nb = wrt_json_count(&j, bk);
	WRT_CHECK(nb == 4);
	for (i = 0; i < nb; i++) {
		wrt_tok b = wrt_json_at(&j, bk, i), items = wrt_json_get(&j, b, "items"), iw = wrt_json_get(&j, b, "item_weights");
		uint32_t slot = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, b, "slot"), &ok);
		const wri_cbucket *cb = wri_crush_bucket_at(c, slot);

		WRT_CHECK(cb != NULL && slot < 16);
		if (cb == NULL || slot >= 16)
			continue;
		slot_seen |= 1u << slot;
		WRT_CHECK_U64((uint32_t)cb->id, (uint32_t)wrt_json_int(&j, wrt_json_get(&j, b, "id"), &ok));
		WRT_CHECK_U64(cb->type, wrt_json_int(&j, wrt_json_get(&j, b, "type"), &ok));
		WRT_CHECK_U64(cb->alg, wrt_json_int(&j, wrt_json_get(&j, b, "alg"), &ok));
		WRT_CHECK_U64(cb->hash, wrt_json_int(&j, wrt_json_get(&j, b, "hash"), &ok));
		WRT_CHECK_U64(cb->size, wrt_json_count(&j, items));
		for (k = 0; k < cb->size && k < wrt_json_count(&j, items); k++) {
			WRT_CHECK_U64((uint32_t)wri_cbucket_items(cb)[k], (uint32_t)wrt_json_int(&j, wrt_json_at(&j, items, k), &ok));
			WRT_CHECK_U64(wri_cbucket_w(cb)[k], wrt_json_int(&j, wrt_json_at(&j, iw, k), &ok));
		}
	}
	for (i = 0; i < c->max_buckets; i++)
		WRT_CHECK((wri_crush_bucket_at(c, (uint32_t)i) != NULL) == ((slot_seen >> i) & 1u));
	ru = wrt_json_get(&j, root, "rules");
	WRT_CHECK(wrt_json_count(&j, ru) == c->max_rules);
	for (i = 0; i < wrt_json_count(&j, ru); i++) {
		wrt_tok r = wrt_json_at(&j, ru, i), steps = wrt_json_get(&j, r, "steps");
		uint32_t slot = (uint32_t)wrt_json_int(&j, wrt_json_get(&j, r, "slot"), &ok);
		const wri_crule *cr = wri_crush_rule(c, slot);

		WRT_CHECK_U64(wrt_json_int(&j, wrt_json_get(&j, r, "type"), &ok), 1);
		WRT_CHECK(cr != NULL);
		if (cr == NULL)
			continue;
		WRT_CHECK_U64(cr->nsteps, wrt_json_count(&j, steps));
		for (k = 0; k < cr->nsteps && k < wrt_json_count(&j, steps); k++) {
			wrt_tok s = wrt_json_at(&j, steps, k);

			WRT_CHECK_U64(wri_crule_steps(cr)[k].op, wrt_json_int(&j, wrt_json_at(&j, s, 0), &ok));
			WRT_CHECK_U64((uint32_t)wri_crule_steps(cr)[k].arg1, (uint32_t)wrt_json_int(&j, wrt_json_at(&j, s, 1), &ok));
			WRT_CHECK_U64((uint32_t)wri_crule_steps(cr)[k].arg2, (uint32_t)wrt_json_int(&j, wrt_json_at(&j, s, 2), &ok));
		}
	}
	tn = wrt_json_get(&j, root, "tunables");
	t = wrt_json_get(&j, tn, "choose_local_tries");
	WRT_CHECK_U64(c->tun.choose_local_tries, wrt_json_int(&j, t, &ok));
	WRT_CHECK_U64(c->tun.choose_local_fallback_tries, wrt_json_int(&j, wrt_json_get(&j, tn, "choose_local_fallback_tries"), &ok));
	WRT_CHECK_U64(c->tun.choose_total_tries, wrt_json_int(&j, wrt_json_get(&j, tn, "choose_total_tries"), &ok));
	WRT_CHECK_U64(c->tun.chooseleaf_descend_once, wrt_json_int(&j, wrt_json_get(&j, tn, "chooseleaf_descend_once"), &ok));
	WRT_CHECK_U64(c->tun.chooseleaf_vary_r, wrt_json_int(&j, wrt_json_get(&j, tn, "chooseleaf_vary_r"), &ok));
	WRT_CHECK_U64(c->tun.chooseleaf_stable, wrt_json_int(&j, wrt_json_get(&j, tn, "chooseleaf_stable"), &ok));
	WRT_CHECK(c->n_sets == 0 && c->set_tab == 0);
	wrt_json_free(&j);
}

/* Every prefix of a blob: OK exactly at the group boundaries in `good` (ascending, ending with n), else a CRUSH encoding error. */
static void sweep_prefixes(const char *name, const uint8_t *blob, size_t n, const size_t *good, size_t ngood)
{
	size_t len, g = 0;
	static uint8_t room_mem[8192] __attribute__((aligned(8)));

	for (len = 0; len <= n; len++) {
		wr_errinfo why;
		size_t used = 77;
		wr_status st;
		int expect_ok = g < ngood && good[g] == len;

		memset(&why, 0, sizeof(why));
		memset(room_mem, 0x5a, sizeof(room_mem));
		st = wri_crush_decode(blob, len, room_mem, sizeof(room_mem), &used, &why);
		if (expect_ok) {
			g++;
			if (st != WR_OK)
				fprintf(stderr, "%s: prefix %zu should decode, got %s (%s)\n", name, len, wr_status_name(st),
					why.what ? why.what : "-");
			WRT_CHECK(st == WR_OK);
			if (st == WR_OK)
				WRT_CHECK_STATUS(WR_OK, wri_crush_check((const wri_crush *)(const void *)room_mem, used));
		} else {
			if (st != WR_E_CRUSH_ENCODING)
				fprintf(stderr, "%s: prefix %zu: %s, want WR_E_CRUSH_ENCODING\n", name, len, wr_status_name(st));
			WRT_CHECK(st == WR_E_CRUSH_ENCODING);
			WRT_CHECK(used == 0 && why.what != NULL && why.module == WR_MOD_CRUSH);
		}
		if (seed_dir != NULL && (len % 97u == 0u || expect_ok)) {
			char nm[96];

			snprintf(nm, sizeof(nm), "%s-prefix-%04zu", name, len);
			seed_write(nm, blob, len);
		}
	}
	WRT_CHECK(g == ngood);
}

static void test_lab_blobs(void)
{
	uint8_t *emb, *get;
	size_t ne, ng, ue, ug, i;
	room re, rg;
	const wri_crush *ce, *cg;
	size_t good_e[16], good_g[16], ng_e = 0, ng_g;
	static const size_t steps[] = {0, 12, 16, 17, 18, 22, 23};
	const size_t names_end = 593, classes_len = 95;

	if (load_hex("crush/crush-embedded-in-osdmap.hex", &emb, &ne) != 0 || load_hex("crush/crush-getcrushmap.hex", &get, &ng) != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(ne == 715 && ng == 723);
	ce = dec_ok(emb, ne, &re, &ue);
	cg = dec_ok(get, ng, &rg, &ug);
	check_lab_json(ce, ue);
	check_lab_json(cg, ug);
	WRT_CHECK(ue == ug);
	WRT_CHECK_MEM(re.out, rg.out, ue < ug ? ue : ug); /* the MSR pair is skipped: the two forms give the same region */
	WRT_CHECK(ue == 304); /* 56 header + 32 + 8 tables + 2 x 24 + 2 x 40 buckets + 2 x 40 rules */
	seed_write("lab-embedded", emb, ne);
	seed_write("lab-getcrushmap", get, ng);

	for (i = 0; i < sizeof(steps) / sizeof(steps[0]); i++)
		good_e[ng_e++] = names_end + steps[i];
	good_e[ng_e++] = names_end + 23 + classes_len;
	good_e[ng_e++] = ne;
	memcpy(good_g, good_e, ng_e * sizeof(size_t));
	ng_g = ng_e;
	good_g[ng_g++] = ng;
	sweep_prefixes("lab-embedded", emb, ne, good_e, ng_e);
	sweep_prefixes("lab-getcrushmap", get, ng, good_g, ng_g);
	room_free(&re);
	room_free(&rg);
	free(emb);
	free(get);
}

/* The incremental form of the osdmap vectors is the same blob as getcrushmap. */
static void test_lab_incremental_form(void)
{
	uint8_t *a, *b;
	size_t na, nb, ua, ub;
	room ra, rb;

	if (load_hex("osdmap/crush-incremental-form.hex", &a, &na) != 0 || load_hex("crush/crush-getcrushmap.hex", &b, &nb) != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(na == nb && memcmp(a, b, na) == 0);
	(void)dec_ok(a, na, &ra, &ua);
	(void)dec_ok(b, nb, &rb, &ub);
	WRT_CHECK(ua == ub);
	room_free(&ra);
	room_free(&rb);
	free(a);
	free(b);
}

/* ---- the kitchen sink ------------------------------------------------------------------------------------------ */

static void test_kitchen_sink(void)
{
	int stage;
	ks_off o;
	size_t good[16], ngood = 0;
	gb full;

	for (stage = KS_STAGE_NAMES; stage <= KS_STAGE_MSR; stage++) {
		gb g;
		room r;
		size_t used;
		const wri_crush *c;
		char nm[32];

		gb_init(&g);
		ks_build(&g, stage, &o);
		c = dec_ok(g.p, g.n, &r, &used);
		ks_verify(c, used, stage);
		snprintf(nm, sizeof(nm), "ks-stage-%d", stage);
		seed_write(nm, g.p, g.n);
		room_free(&r);
		gb_free(&g);
	}
	/* a stage that ends mid-way is refused, and the stages are the only prefixes that decode */
	gb_init(&full);
	ks_build(&full, KS_STAGE_MSR, &o);
	good[ngood++] = o.tun;
	good[ngood++] = o.tun + 12;
	good[ngood++] = o.tun + 16;
	good[ngood++] = o.tun + 17;
	good[ngood++] = o.tun + 18;
	good[ngood++] = o.tun + 22;
	good[ngood++] = o.cls;
	good[ngood++] = o.ca;
	good[ngood++] = o.msr;
	good[ngood++] = o.end;
	sweep_prefixes("ks", full.p, full.n, good, ngood);
	gb_free(&full);
}

/* ---- special maps ---------------------------------------------------------------------------------------------- */

static const int32_t mini_steps[3][3] = {{1, -1, 0}, {2, 0, 1}, {4, 0, 0}};

/* header, one straw2 bucket (id -1, items 0 and 1), one replicated rule, empty names, the six tunable groups, empty classes */
static void mini_head(gb *g, uint32_t max_buckets)
{
	static const int32_t items[2] = {0, 1};
	static const uint32_t w[2] = {0x10000, 0x10000};
	uint32_t i;

	gb_header(g, max_buckets, 1, 2);
	gb_bucket(g, 5, -1, 11, 2, items, w, NULL, 0);
	for (i = 1; i < max_buckets; i++)
		gb_hole(g);
	gb_rule(g, 0, 1, 3, mini_steps, 1, 100);
	gb_u32(g, 0);
	gb_u32(g, 0);
	gb_u32(g, 0);
	gb_u32(g, 0);
	gb_u32(g, 0);
	gb_u32(g, 50);
	gb_u32(g, 1);
	gb_u8(g, 1);
	gb_u8(g, 1);
	gb_u32(g, 0x36);
	gb_u8(g, 1);
	gb_u32(g, 0);
	gb_u32(g, 0);
	gb_u32(g, 0);
}

static void mini_args(gb *g, const int64_t *keys, size_t nkeys)
{
	size_t i;

	mini_head(g, 1);
	gb_u32(g, (uint32_t)nkeys);
	for (i = 0; i < nkeys; i++) {
		gb_u64(g, (uint64_t)keys[i]);
		gb_u32(g, 1);
		gb_u32(g, 0); /* bucket slot 0 */
		gb_u32(g, 0); /* no rows */
		gb_u32(g, 2); /* ids */
		gb_i32(g, (int32_t)(1000 + i));
		gb_i32(g, 7);
	}
}

static int32_t first_id(const wri_crush *c, int32_t pool)
{
	const uint32_t *ix = wri_crush_args_index(c, pool);
	const wri_cargs *a = ix == NULL ? NULL : wri_crush_args_of(c, ix, 0);

	return (a == NULL || wri_cargs_ids(a, 2) == NULL) ? -1 : wri_cargs_ids(a, 2)[0];
}

static void test_args_keys(void)
{
	static const int64_t keys[5] = {-2147483648LL - 1, -2147483648LL, -1, 2147483647LL, 2147483648LL};
	static const int64_t dropped[2] = {4294967299LL, 8589934592LL};
	gb g, none;
	room r, r2;
	size_t used, used2;
	const wri_crush *c;

	gb_init(&g);
	mini_args(&g, keys, 5); /* the first and the last do not fit an s32 */
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(c->n_sets == 3);
	WRT_CHECK(first_id(c, (int32_t)0x80000000) == 1001 && first_id(c, -1) == 1002 && first_id(c, 2147483647) == 1003);
	WRT_CHECK(first_id(c, 5) == 1002); /* no set for pool 5: the default one */
	seed_write("mini-args-keys", g.p, g.n);
	room_free(&r);
	gb_free(&g);

	/* sets that are all dropped leave the same region as a blob with a zero count, down to the byte */
	gb_init(&g);
	mini_args(&g, dropped, 2);
	gb_init(&none);
	mini_args(&none, NULL, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	(void)dec_ok(none.p, none.n, &r2, &used2);
	WRT_CHECK(c->n_sets == 0 && c->set_tab == 0 && used == used2);
	WRT_CHECK_MEM(r.out, r2.out, used < used2 ? used : used2);
	seed_write("mini-args-dropped", g.p, g.n);
	room_free(&r);
	room_free(&r2);
	gb_free(&g);
	gb_free(&none);
}

/* A set that is dropped is still validated; many of them cost nothing. */
static void test_dropped_sets(void)
{
	gb g;
	room r;
	size_t used, i;
	const wri_crush *c;
	static const int64_t k = 4294967296LL;

	/* the same set, valid: dropped */
	gb_init(&g);
	mini_args(&g, &k, 1);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(c->n_sets == 0);
	room_free(&r);
	/* a bucket index beyond the slots in the dropped set: refused all the same (the entry is the last 5 words of the set) */
	gb_patch(&g, g.n - 5 * 4, 99, 4);
	dec_bad("dropped-bad-index", g.p, g.n, WR_E_CRUSH_ENCODING, "beyond max_buckets", SIZE_MAX);
	gb_patch(&g, g.n - 5 * 4, 0, 4);
	gb_patch(&g, g.n - 3 * 4, 3, 4); /* ids size 3 for a bucket of 2 */
	dec_bad("dropped-bad-ids", g.p, g.n, WR_E_CRUSH_ENCODING, "ids size", SIZE_MAX);
	gb_free(&g);

	/* fifty thousand dropped sets over the most bucket slots: no work per set beyond reading it */
	gb_init(&g);
	mini_head(&g, 32768);
	gb_u32(&g, 50000);
	for (i = 0; i < 50000; i++) {
		gb_u64(&g, (uint64_t)(4294967296ULL + i));
		gb_u32(&g, 1);
		gb_u32(&g, 0);
		gb_u32(&g, 0);
		gb_u32(&g, 0);
	}
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(c->n_sets == 0 && c->set_tab == 0);
	{
		gb none;
		room r2;
		size_t used2;

		gb_init(&none);
		mini_head(&none, 32768);
		gb_u32(&none, 0);
		(void)dec_ok(none.p, none.n, &r2, &used2);
		WRT_CHECK(used == used2);
		WRT_CHECK_MEM(r.out, r2.out, used < used2 ? used : used2);
		room_free(&r2);
		gb_free(&none);
	}
	room_free(&r);
	gb_free(&g);
}

static void test_edge_maps(void)
{
	gb g;
	room r;
	size_t used, i;
	const wri_crush *c;
	static const int32_t it1[1] = {5}, it_hole[2] = {-2, 4};
	static const uint32_t w1[1] = {0x7fffffffu}, wl[2] = {0xffffffffu, 0xffffffffu};
	int32_t *big;
	uint32_t *bw;

	/* empty map: no buckets, no rules, empty names, nothing after */
	gb_init(&g);
	gb_header(&g, 0, 0, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(used == 56 && c->max_devices == 0 && c->max_buckets == 0 && c->max_rules == 0 && c->n_sets == 0);
	WRT_CHECK(wri_crush_bucket_at(c, 0) == NULL && wri_crush_rule(c, 0) == NULL && wri_crush_rule_kind(c, 0) == 0);
	expect_tun(c, KS_STAGE_NAMES);
	seed_write("empty-map", g.p, g.n);
	room_free(&r);
	gb_free(&g);

	/* an empty bucket of each algorithm, an item that names a hole, a straw2 weight just under the limit, list weights of all ones */
	gb_init(&g);
	gb_header(&g, 6, 0, 0);
	gb_bucket(&g, 5, -1, 3, 0, NULL, NULL, NULL, 0);
	gb_bucket(&g, 2, -2, 3, 0, NULL, NULL, NULL, 0);
	gb_bucket(&g, 4, -3, 3, 0, NULL, NULL, NULL, 0);
	{
		static const uint32_t u1[1] = {0};
		static const uint32_t nodes1[1] = {0};

		gb_bucket(&g, 1, -4, 3, 0, NULL, u1, NULL, 0);
		gb_bucket(&g, 3, -5, 3, 0, NULL, nodes1, NULL, 0); /* num_nodes 0 */
	}
	gb_bucket(&g, 5, -6, 3, 1, it1, w1, NULL, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	for (i = 0; i < 5; i++)
		WRT_CHECK(wri_crush_bucket_at(c, (uint32_t)i) != NULL && wri_crush_bucket_at(c, (uint32_t)i)->size == 0);
	WRT_CHECK(wri_crush_bucket_at(c, 5)->size == 1 && wri_cbucket_w(wri_crush_bucket_at(c, 5))[0] == 0x7fffffffu);
	WRT_CHECK(c->max_devices == 6);
	seed_write("empty-buckets", g.p, g.n);
	room_free(&r);
	gb_free(&g);

	gb_init(&g);
	gb_header(&g, 3, 0, 0);
	gb_bucket(&g, 2, -1, 3, 2, it_hole, wl, wl, 0); /* -2 is a hole: allowed, the mapper skips it */
	gb_hole(&g);
	gb_hole(&g);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(wri_cbucket_w(wri_crush_bucket_at(c, 0))[1] == 0xffffffffu && wri_cbucket_sums(wri_crush_bucket_at(c, 0))[0] == 0xffffffffu);
	room_free(&r);
	gb_free(&g);

	/* the largest bucket: 65535 items; one more is refused */
	big = (int32_t *)malloc(65535u * 4u);
	bw = (uint32_t *)malloc(65535u * 4u);
	for (i = 0; i < 65535u; i++) {
		big[i] = (int32_t)i;
		bw[i] = 0x10000;
	}
	gb_init(&g);
	gb_header(&g, 1, 0, 0);
	gb_bucket(&g, 5, -1, 1, 65535, big, bw, NULL, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(c->max_devices == 65535 && wri_crush_bucket_at(c, 0)->size == 65535 && used == 56 + 4 + 16 + 8u * 65535u);
	room_free(&r);
	gb_free(&g);
	free(big);
	free(bw);

	/* the most slots: 32768 bucket slots and 256 rule slots, all holes */
	gb_init(&g);
	gb_header(&g, 32768, 256, 0);
	for (i = 0; i < 32768u + 256u; i++)
		gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(used == 56 + 4u * (32768u + 256u) && c->max_buckets == 32768 && c->max_rules == 256);
	room_free(&r);
	gb_free(&g);

	/* rules of the other types leave only the sentinel, even with the most steps; a replicated rule keeps its steps verbatim */
	gb_init(&g);
	gb_header(&g, 0, 4, 0);
	{
		int32_t st64[64][3];

		for (i = 0; i < 64; i++) {
			st64[i][0] = (int32_t)(i % 17);
			st64[i][1] = (int32_t)i - 40;
			st64[i][2] = (int32_t)0x80000000 + (int32_t)i;
		}
		gb_rule(&g, 0, 4, 64, (const int32_t(*)[3])st64, 0, 255);
		gb_rule(&g, 1, 5, 0, NULL, 1, 100);
		gb_rule(&g, 2, 1, 64, (const int32_t(*)[3])st64, 1, 100);
		gb_u32(&g, 0);
		gb_u32(&g, 0);
		gb_u32(&g, 0);
		gb_u32(&g, 0);
		c = dec_ok(g.p, g.n, &r, &used);
		WRT_CHECK(wri_crush_rule_kind(c, 0) == 1 && wri_crush_rule_kind(c, 1) == 1 && wri_crush_rule_kind(c, 2) == 2 &&
			  wri_crush_rule_kind(c, 3) == 0);
		WRT_CHECK(wri_crush_rule(c, 2) != NULL && wri_crush_rule(c, 2)->nsteps == 64);
		WRT_CHECK_MEM(wri_crule_steps(wri_crush_rule(c, 2)), st64, sizeof(st64));
		room_free(&r);
	}
	gb_free(&g);
}

/* ---- blobs written by Ceph's own crushtool ---------------------------------------------------------------- */

static void expect_flat_host(const wri_crush *c, uint32_t slot, int32_t id, unsigned alg, int32_t first_dev, uint32_t n)
{
	const wri_cbucket *b = wri_crush_bucket_at(c, slot);
	uint32_t i;

	WRT_CHECK(b != NULL && b->id == id && b->type == 1 && b->alg == alg);
	if (b == NULL)
		return;
	WRT_CHECK(b->size == n);
	for (i = 0; i < b->size && b->size == n; i++) {
		WRT_CHECK(wri_cbucket_items(b)[i] == first_dev + (int32_t)i);
		if (alg == WRI_CRUSH_ALG_STRAW || alg == WRI_CRUSH_ALG_STRAW2)
			WRT_CHECK(wri_cbucket_w(b)[i] == 0x10000u); /* straws of equal weights, and straw2 weights */
	}
}

static void expect_rep_rule(const wri_crush *c, uint32_t slot, int32_t root)
{
	const wri_crule *r = wri_crush_rule(c, slot);

	WRT_CHECK(r != NULL && r->nsteps == 3);
	if (r == NULL || r->nsteps != 3)
		return;
	WRT_CHECK(wri_crule_steps(r)[0].op == WRI_CRUSH_OP_TAKE && wri_crule_steps(r)[0].arg1 == root);
	WRT_CHECK(wri_crule_steps(r)[1].op == WRI_CRUSH_OP_CHOOSELEAF_FIRSTN && wri_crule_steps(r)[1].arg1 == 0 &&
		  wri_crule_steps(r)[1].arg2 == 1);
	WRT_CHECK(wri_crule_steps(r)[2].op == WRI_CRUSH_OP_EMIT);
}

/* m5: every algorithm in one hierarchy with classes (shadow buckets), three rules and choose_args; values from `crushtool --dump` */
static void test_real_m5(void)
{
	static const int32_t i1[2] = {0, 2}, i2[3] = {0, 1, 2}, i3[3] = {3, 4, 5}, i4[2] = {6, 7}, i5[2] = {9, 20}, i6[3] = {0, 1, 9};
	static const int32_t i8[5] = {-2, -3, -4, -5, -6}, i10[1] = {-8};
	static const uint32_t w1[2] = {65536, 0}, w2[3] = {65536, 163840, 0}, w3[3] = {65536, 196608, 32768};
	static const uint32_t s3[3] = {65536, 262144, 294912}, w6[3] = {65536, 65536, 152917};
	static const uint32_t w8[5] = {229376, 294912, 131072, 196608, 458752}, w10[1] = {1310720};
	static const uint32_t a2r0[3] = {65536, 131072, 196608}, a2r1[3] = {32768, 16384, 0}, a8r0[5] = {65536, 65536, 65536, 65536, 65536};
	static const int32_t a2ids[3] = {100, 101, -102}, a10ids[1] = {77};
	static const int32_t r0[3][3] = {{1, -10, 0}, {6, 0, 1}, {4, 0, 0}};
	static const int32_t r3[6][3] = {{8, 100, 0}, {12, 2, 0}, {1, -8, 0}, {2, 2, 1}, {6, -1, 0}, {4, 0, 0}};
	room r;
	size_t used;
	const wri_crush *c;
	const uint32_t *ix;
	const wri_cargs *a;
	const wri_crule *ru;
	uint32_t i;

	c = dec_ok(real_m5, sizeof(real_m5), &r, &used);
	WRT_CHECK(c->max_buckets == 32 && c->max_rules == 6 && c->max_devices == 21 && c->n_sets == 2 && used == 1300);
	expect_tun(c, KS_STAGE_STABLE);
	expect_bucket(c, 0, -1, 1, 5, 2, i1, w1, NULL);
	expect_bucket(c, 1, -2, 1, 5, 3, i2, w2, NULL);
	expect_bucket(c, 2, -3, 1, 2, 3, i3, w3, s3);
	expect_bucket(c, 3, -4, 1, 1, 2, i4, NULL, NULL);
	expect_bucket(c, 4, -5, 1, 3, 2, i5, NULL, NULL);
	expect_bucket(c, 5, -6, 1, 4, 3, i6, w6, NULL);
	expect_bucket(c, 6, -7, 1, 2, 0, NULL, NULL, NULL); /* the shadow buckets of the list, uniform and tree hosts are empty */
	expect_bucket(c, 7, -8, 2, 5, 5, i8, w8, NULL);
	expect_bucket(c, 8, -9, 1, 1, 0, NULL, NULL, NULL);
	expect_bucket(c, 9, -10, 11, 5, 1, i10, w10, NULL);
	expect_bucket(c, 20, -21, 11, 5, 1, NULL, NULL, NULL);
	for (i = 21; i < 32; i++)
		WRT_CHECK(wri_crush_bucket_at(c, i) == NULL);
	WRT_CHECK(wri_crush_rule_kind(c, 0) == 2 && wri_crush_rule_kind(c, 1) == 0 && wri_crush_rule_kind(c, 3) == 2 &&
		  wri_crush_rule_kind(c, 5) == 1);
	ru = wri_crush_rule(c, 0);
	WRT_CHECK(ru != NULL && ru->nsteps == 3);
	if (ru != NULL && ru->nsteps == 3)
		WRT_CHECK_MEM(wri_crule_steps(ru), r0, sizeof(r0));
	ru = wri_crush_rule(c, 3);
	WRT_CHECK(ru != NULL && ru->nsteps == 6);
	if (ru != NULL && ru->nsteps == 6)
		WRT_CHECK_MEM(wri_crule_steps(ru), r3, sizeof(r3));
	ix = wri_crush_args_index(c, 0);
	WRT_CHECK(ix != NULL);
	if (ix != NULL) {
		a = wri_crush_args_of(c, ix, 1);
		WRT_CHECK(a != NULL && a->n_pos == 2 && a->has_ids == 1);
		if (a != NULL) {
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 0), a2r0, 12);
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 1), a2r1, 12);
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 7), a2r1, 12); /* a position past the rows takes the last row */
			WRT_CHECK_MEM(wri_cargs_ids(a, 3), a2ids, 12);
		}
		a = wri_crush_args_of(c, ix, 7);
		WRT_CHECK(a != NULL && a->n_pos == 1 && a->has_ids == 0);
		if (a != NULL)
			WRT_CHECK_MEM(wri_cargs_row(a, 5, 0), a8r0, 20);
		WRT_CHECK(wri_crush_args_of(c, ix, 0) == NULL && wri_crush_args_of(c, ix, 9) == NULL);
	}
	ix = wri_crush_args_index(c, 5);
	WRT_CHECK(ix != NULL && ix != wri_crush_args_index(c, 0));
	a = ix == NULL ? NULL : wri_crush_args_of(c, ix, 9);
	WRT_CHECK(a != NULL && a->n_pos == 0 && a->has_ids == 1);
	if (a != NULL)
		WRT_CHECK_MEM(wri_cargs_ids(a, 1), a10ids, 4);
	WRT_CHECK(ix != NULL && wri_crush_args_of(c, ix, 1) == NULL);
	WRT_CHECK(wri_crush_args_index(c, 3) == NULL); /* no default set: pools without their own get none */
	seed_write("real-all-algs-classes", real_m5, sizeof(real_m5));
	room_free(&r);
}

static void test_real_blobs(void)
{
	room r;
	size_t used;
	const wri_crush *c;
	const wri_cbucket *b;
	uint32_t i;
	const uint32_t sums[3] = {262144, 524288, 786432};
	const uint32_t w3[3] = {262144, 262144, 262144};
	const int32_t l1[3] = {-1, -2, -3}, l2[3] = {-4, -5, -6}, root1[2] = {-7, -8}, root2[4] = {-1, -2, -3, -4};

	/* m1: straw hosts, list racks, a uniform root */
	c = dec_ok(real_m1, sizeof(real_m1), &r, &used);
	WRT_CHECK(c->max_buckets == 16 && c->max_rules == 1 && c->max_devices == 24 && c->n_sets == 0);
	expect_tun(c, KS_STAGE_STABLE);
	for (i = 0; i < 6; i++)
		expect_flat_host(c, i, -1 - (int32_t)i, WRI_CRUSH_ALG_STRAW, 4 * (int32_t)i, 4);
	expect_bucket(c, 6, -7, 2, 2, 3, l1, w3, sums);
	expect_bucket(c, 7, -8, 2, 2, 3, l2, w3, sums);
	expect_bucket(c, 8, -9, 3, 1, 2, root1, NULL, NULL);
	for (i = 9; i < 16; i++)
		WRT_CHECK(wri_crush_bucket_at(c, i) == NULL);
	expect_rep_rule(c, 0, -9);
	seed_write("real-straw-list-uniform", real_m1, sizeof(real_m1));
	room_free(&r);

	/* m2: tree hosts under a straw2 root; a tree bucket is decoded for its items only */
	c = dec_ok(real_m2, sizeof(real_m2), &r, &used);
	WRT_CHECK(c->max_buckets == 8 && c->max_devices == 16);
	expect_tun(c, KS_STAGE_STABLE);
	for (i = 0; i < 4; i++) {
		b = wri_crush_bucket_at(c, i);
		WRT_CHECK(b != NULL && b->alg == WRI_CRUSH_ALG_TREE && b->size == 4 && wri_cbucket_items(b)[0] == 4 * (int32_t)i);
	}
	{
		const uint32_t w4[4] = {262144, 262144, 262144, 262144};

		expect_bucket(c, 4, -5, 2, 5, 4, root2, w4, NULL);
	}
	expect_rep_rule(c, 0, -5);
	seed_write("real-tree", real_m2, sizeof(real_m2));
	room_free(&r);

	/* m3: legacy tunables written explicitly */
	c = dec_ok(real_m3, sizeof(real_m3), &r, &used);
	WRT_CHECK(c->max_devices == 12);
	expect_tun(c, KS_STAGE_NAMES);
	expect_flat_host(c, 0, -1, WRI_CRUSH_ALG_STRAW2, 0, 3);
	seed_write("real-legacy-tunables", real_m3, sizeof(real_m3));
	room_free(&r);

	/* m4: an erasure rule (kept as the sentinel), choose_args with weight positions and ids */
	c = dec_ok(real_m4, sizeof(real_m4), &r, &used);
	WRT_CHECK(c->max_devices == 12 && c->max_rules == 3);
	expect_tun(c, KS_STAGE_STABLE);
	WRT_CHECK(wri_crush_rule_kind(c, 0) == 2 && wri_crush_rule_kind(c, 1) == 1 && wri_crush_rule_kind(c, 2) == 2);
	expect_rep_rule(c, 0, -5);
	expect_rep_rule(c, 2, -5);
	WRT_CHECK(c->n_sets == 2);
	{
		static const uint32_t row0[2][3] = {{65536, 131072, 196608}, {262144, 327680, 393216}};
		static const uint32_t half[3] = {98304, 98304, 98304};
		static const int32_t ids[3] = {101, 102, 103};
		const uint32_t *ix = wri_crush_args_index(c, 0);
		const wri_cargs *a;

		WRT_CHECK(ix != NULL);
		for (i = 0; ix != NULL && i < 2; i++) {
			a = wri_crush_args_of(c, ix, i);
			WRT_CHECK(a != NULL && a->n_pos == 2 && a->has_ids == 1);
			if (a == NULL)
				continue;
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 0), row0[0], 12);
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 1), row0[1], 12);
			WRT_CHECK_MEM(wri_cargs_ids(a, 3), ids, 12);
		}
		WRT_CHECK(ix != NULL && wri_crush_args_of(c, ix, 2) == NULL);
		ix = wri_crush_args_index(c, 5);
		WRT_CHECK(ix != NULL && ix != wri_crush_args_index(c, 0));
		a = ix == NULL ? NULL : wri_crush_args_of(c, ix, 0);
		WRT_CHECK(a != NULL && a->n_pos == 1 && a->has_ids == 0);
		if (a != NULL)
			WRT_CHECK_MEM(wri_cargs_row(a, 3, 0), half, 12);
		WRT_CHECK(ix != NULL && wri_crush_args_of(c, ix, 1) == NULL);
		WRT_CHECK(wri_crush_args_index(c, 7) == NULL); /* no set for pool 7 and no default set */
	}
	seed_write("real-choose-args-ec", real_m4, sizeof(real_m4));
	room_free(&r);

	test_real_m5();
}

/* ---- the negative table ---------------------------------------------------------------------------------------- */

static void neg(const char *name, const gb *base, size_t off, uint32_t val, unsigned width, const char *what, size_t a0)
{
	gb m = gb_copy(base);

	gb_patch(&m, off, val, width);
	dec_bad(name, m.p, m.n, WR_E_CRUSH_ENCODING, what, a0);
	if (seed_dir != NULL) {
		char nm[96];

		snprintf(nm, sizeof(nm), "neg-%s", name);
		seed_write(nm, m.p, m.n);
	}
	gb_free(&m);
}

static void neg64(const char *name, const gb *base, size_t off, uint32_t lo, uint32_t hi, const char *what, size_t a0)
{
	gb m = gb_copy(base);

	gb_patch(&m, off, lo, 4);
	gb_patch(&m, off + 4, hi, 4);
	dec_bad(name, m.p, m.n, WR_E_CRUSH_ENCODING, what, a0);
	if (seed_dir != NULL) {
		char nm[96];

		snprintf(nm, sizeof(nm), "neg-%s", name);
		seed_write(nm, m.p, m.n);
	}
	gb_free(&m);
}

static void test_negative(void)
{
	gb g, m;
	ks_off o;
	uint32_t i;

	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, &o);

	neg("bad-magic", &g, 0, 0x00010001u, 4, "bad magic", 0);
	neg("bad-magic-zero", &g, 0, 0, 4, "bad magic", 0);
	neg("max-buckets-32769", &g, 4, 32769, 4, "too many bucket slots", 4);
	neg("max-buckets-negative", &g, 4, 0xffffffffu, 4, "too many bucket slots", 4);
	neg("max-rules-257", &g, 8, 257, 4, "too many rule slots", 8);
	neg("max-buckets-vs-blob", &g, 4, 32768, 4, "too short for the announced slots", 4);
	neg("marker-6", &g, o.bk[0], 6, 4, "unknown bucket algorithm", o.bk[0]);
	neg("marker-not-alg", &g, o.bk[0] + 10, 4, 1, "marker differs", o.bk[0]);
	neg("alg-byte-0", &g, o.bk[1] + 10, 0, 1, "marker differs", o.bk[1]);
	neg("id-not-slot", &g, o.bk[1] + 4, (uint32_t)-9, 4, "id does not match", o.bk[1]);
	neg("id-positive", &g, o.bk[0] + 4, 1, 4, "id does not match", o.bk[0]);
	neg("id-of-slot-0-on-slot-4", &g, o.bk[4] + 4, (uint32_t)-1, 4, "id does not match", o.bk[4]);
	neg("hash-1", &g, o.bk[2] + 11, 1, 1, "hash", o.bk[2]);
	neg("hash-255", &g, o.bk[0] + 11, 255, 1, "hash", o.bk[0]);
	neg("size-65536", &g, o.bk[0] + 16, 65536, 4, "too many items", o.bk[0]);
	neg("size-huge", &g, o.bk[4] + 16, 0xffffffffu, 4, "too many items", o.bk[4]);
	neg("size-past-end", &g, o.bk[1] + 16, 60000, 4, "run past the end", o.bk[1]);
	neg("item-beyond-slots", &g, o.bk[0] + 20, (uint32_t)-8, 4, "beyond max_buckets", o.bk[0]);
	neg("item-int-min", &g, o.bk[0] + 24, 0x80000000u, 4, "beyond max_buckets", o.bk[0]);
	neg("item-none", &g, o.bk[1] + 20, 0x7fffffffu, 4, "reserved device id", o.bk[1]);
	neg("item-undef", &g, o.bk[5] + 20, 0x7ffffffeu, 4, "reserved device id", o.bk[5]);
	neg("straw2-weight-2^31", &g, o.bk[0] + 20 + 12 + 4, 0x80000000u, 4, "0x80000000", o.bk[0]);
	neg("straw2-weight-max", &g, o.bk[1] + 20 + 12, 0xffffffffu, 4, "0x80000000", o.bk[1]);
	neg("ruleset-not-slot", &g, o.ru[0] + 8, 1, 1, "ruleset", o.ru[0]);
	neg("ruleset-255", &g, o.ru[1] + 8, 255, 1, "ruleset", o.ru[1]);
	neg("rule-65-steps", &g, o.ru[0] + 4, 65, 4, "too many steps", o.ru[0]);
	neg("rule-huge-steps", &g, o.ru[1] + 4, 0xffffffffu, 4, "too many steps", o.ru[1]);
	neg("vary-r-33", &g, o.tun + 16, 33, 1, "vary_r", SIZE_MAX);
	neg("vary-r-255", &g, o.tun + 16, 255, 1, "vary_r", SIZE_MAX);
	neg("name-count-huge", &g, o.nmap, 0xffffffffu, 4, "name map count", SIZE_MAX);
	neg("type-count-huge", &g, o.tmap, 0x10000000u, 4, "name map count", SIZE_MAX);
	neg("name-key-reserved", &g, o.nmap_key12, 0x7ffffffeu, 4, "reserved device id", SIZE_MAX);
	neg("name-length-past-end", &g, o.nmap_key12 + 4, 0x7fffffffu, 4, "truncated", SIZE_MAX);
	neg("class-count-huge", &g, o.cls, 0xffffffffu, 4, "device class", SIZE_MAX);
	neg("args-count-huge", &g, o.ca, 0x7fffffffu, 4, "choose_args set count", SIZE_MAX);
	neg("args-set-nb-huge", &g, o.set_nb[0], 0x10000000u, 4, "bucket count exceeds", o.set_key[0]);
	neg("args-set-nb-too-many", &g, o.set_nb[1], 2, 4, "beyond max_buckets", SIZE_MAX);
	neg("args-index-beyond", &g, o.s0b0, 7, 4, "beyond max_buckets", o.set_key[0]);
	neg("args-index-huge", &g, o.s0b0, 0xffffffffu, 4, "beyond max_buckets", o.set_key[0]);
	neg("args-index-list-bucket", &g, o.s0b0, 2, 4, "not straw2", o.set_key[0]);
	neg("args-index-straw-bucket", &g, o.s0b0, 4, 4, "not straw2", o.set_key[0]);
	neg("args-index-uniform-bucket", &g, o.s0b0, 5, 4, "not straw2", o.set_key[0]);
	neg("args-index-tree-bucket", &g, o.s0b0, 6, 4, "not straw2", o.set_key[0]);
	neg("args-index-hole", &g, o.s0b0, 3, 4, "not straw2", o.set_key[0]);
	neg("args-index-twice", &g, o.s0b1, 0, 4, "twice", o.set_key[0]);
	neg("args-npos-huge", &g, o.s0b1 + 4, 0x40000000u, 4, "run past the end", o.set_key[0]);
	neg("args-row-too-short", &g, o.s0b1_row0_size, 2, 4, "row length", o.set_key[0]);
	neg("args-row-too-long", &g, o.s0b1_row0_size, 4, 4, "row length", o.set_key[0]);
	neg("args-row-zero", &g, o.s0b1_row0_size, 0, 4, "row length", o.set_key[0]);
	neg("args-weight-2^31", &g, o.s0b1_row0_w0 + 4, 0x80000000u, 4, "weight-set weight", o.set_key[0]);
	neg("args-ids-too-few", &g, o.s0b1_ids_size, 2, 4, "ids size", o.set_key[0]);
	neg("args-ids-too-many", &g, o.s0b1_ids_size, 4, 4, "ids size", o.set_key[0]);
	neg("args-ids-huge", &g, o.s0b1_ids_size, 0xffffffffu, 4, "ids size", o.set_key[0]);
	neg64("args-keys-duplicate", &g, o.set_key[1], 0xffffffffu, 0xffffffffu, "ascending", o.set_key[1]);
	neg64("args-keys-descending", &g, o.set_key[1], 0xfffffffeu, 0xffffffffu, "ascending", o.set_key[1]);

	/* truncated or extended at the end */
	m = gb_copy(&g);
	gb_u8(&m, 0);
	dec_bad("trailing-1", m.p, m.n, WR_E_CRUSH_ENCODING, "trailing bytes", o.end);
	seed_write("neg-trailing-1", m.p, m.n);
	for (i = 0; i < 11; i++)
		gb_u8(&m, (uint8_t)i);
	dec_bad("trailing-12", m.p, m.n, WR_E_CRUSH_ENCODING, "trailing bytes", o.end);
	gb_free(&m);
	m = gb_copy(&g);
	m.n = o.end - 4;
	dec_bad("msr-half", m.p, m.n, WR_E_CRUSH_ENCODING, "MSR", SIZE_MAX);
	m.n = o.end - 7;
	dec_bad("msr-seven", m.p, m.n, WR_E_CRUSH_ENCODING, "MSR", SIZE_MAX);
	gb_free(&m);
	/* a map without the MSR pair and without choose_args, one byte too long */
	{
		gb h;

		gb_init(&h);
		ks_build(&h, KS_STAGE_CLASSES, NULL);
		gb_u8(&h, 1);
		dec_bad("trailing-after-classes", h.p, h.n, WR_E_CRUSH_ENCODING, "choose_args set count", SIZE_MAX); /* read as a choose_args count */
		gb_free(&h);
	}
	dec_bad("empty", g.p, 0, WR_E_CRUSH_ENCODING, "header", 0);
	dec_bad("three-bytes", g.p, 3, WR_E_CRUSH_ENCODING, "header", SIZE_MAX);
	gb_free(&g);
}

/* ---- arguments ------------------------------------------------------------------------------------------------- */

static void test_arguments(void)
{
	gb g;
	size_t used = 5;
	uint8_t aligned[8192] __attribute__((aligned(8)));
	wr_errinfo why;

	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_decode(g.p, g.n, NULL, sizeof(aligned), &used, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_decode(g.p, g.n, aligned, sizeof(aligned), NULL, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_decode(NULL, 5, aligned, sizeof(aligned), &used, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_decode(g.p, g.n, aligned + 4, sizeof(aligned) - 4, &used, NULL));
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_decode(g.p, g.n, aligned + 1, sizeof(aligned) - 1, &used, &why));
	WRT_CHECK(why.status == WR_E_INVAL && used == 0);
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_decode(NULL, 0, aligned, sizeof(aligned), &used, NULL));
	WRT_CHECK_STATUS(WR_OK, wri_crush_decode(g.p, g.n, aligned, sizeof(aligned), &used, NULL));
	/* an errinfo that already holds a failure keeps it (first failure wins) */
	memset(&why, 0, sizeof(why));
	why.status = WR_E_TIMEOUT;
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_decode(g.p, 5, aligned, sizeof(aligned), &used, &why));
	WRT_CHECK(why.status == WR_E_TIMEOUT);
	gb_free(&g);
}

/* ---- the room --------------------------------------------------------------------------------------------------- */

static void budget_sweep(const char *name, const uint8_t *blob, size_t n)
{
	room r;
	size_t used, cap;
	wr_errinfo why;
	wr_status st = dec(blob, n, BIG, 0x00, &r, &used, &why);
	size_t full = used;

	WRT_CHECK_STATUS(WR_OK, st);
	room_free(&r);
	for (cap = 0; cap < full; cap++) {
		st = dec(blob, n, cap, 0xa5, &r, &used, &why);
		if (st != WR_E_MAP_BUDGET)
			fprintf(stderr, "%s: cap %zu of %zu: %s\n", name, cap, full, wr_status_name(st));
		WRT_CHECK(st == WR_E_MAP_BUDGET);
		WRT_CHECK(used == 0 && why.status == WR_E_MAP_BUDGET && why.module == WR_MOD_CRUSH && why.what != NULL);
		WRT_CHECK(why.a2 == cap && why.a1 > cap);
		room_free(&r);
		if (st != WR_E_MAP_BUDGET)
			return;
	}
	/* exactly enough */
	WRT_CHECK_STATUS(WR_OK, dec(blob, n, full, 0xa5, &r, &used, &why));
	WRT_CHECK(used == full);
	room_free(&r);
}

static void test_budget(void)
{
	uint8_t *emb;
	size_t ne;
	gb g;
	ks_off o;

	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, &o);
	budget_sweep("ks", g.p, g.n);
	gb_free(&g);
	if (load_hex("crush/crush-embedded-in-osdmap.hex", &emb, &ne) == 0) {
		budget_sweep("lab", emb, ne);
		free(emb);
	}
	/* a budget error never hides a blob error that comes first: a bad magic is an encoding error whatever the room */
	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, &o);
	gb_patch(&g, 0, 0, 4);
	{
		room r;
		size_t used;
		wr_errinfo why;

		WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, dec(g.p, g.n, 0, 0xa5, &r, &used, &why));
		room_free(&r);
	}
	gb_free(&g);
}

/* ---- wri_crush_check on corrupted regions ----------------------------------------------------------------------- */

typedef struct region {
	uint8_t *buf; /* 16-byte aligned copy of the decoded region, with 16 spare bytes after it */
	size_t n;
} region;

static void region_load(region *rg, const uint8_t *src, size_t n)
{
	rg->buf = (uint8_t *)malloc(n + 32);
	memset(rg->buf, 0, n + 32);
	memcpy(rg->buf, src, n);
	rg->n = n;
}

static uint32_t rd32(const region *rg, size_t at)
{
	uint32_t v;

	memcpy(&v, rg->buf + at, 4);
	return v;
}

static void wr32(region *rg, size_t at, uint32_t v)
{
	memcpy(rg->buf + at, &v, 4);
}

/* Corrupt one word, expect the check to fail, restore it. */
static void corrupt(const char *name, region *rg, size_t at, uint32_t val, size_t bytes)
{
	uint32_t keep = rd32(rg, at);
	wr_status st;

	wr32(rg, at, val);
	st = wri_crush_check((const wri_crush *)(const void *)rg->buf, bytes);
	if (st != WR_E_CRUSH_ENCODING)
		fprintf(stderr, "check accepted corruption %s (word at %zu = 0x%x)\n", name, at, val);
	WRT_CHECK(st == WR_E_CRUSH_ENCODING);
	wr32(rg, at, keep);
}

static void test_check(void)
{
	gb g;
	room r;
	size_t used, b0, b1, b2, b4, r0, set_tab, idx0, a0, a1, i;
	const wri_crush *c;
	region rg;
	const uint8_t *src;

	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, NULL);
	c = dec_ok(g.p, g.n, &r, &used);
	src = r.out;
	region_load(&rg, src, used);
	c = (const wri_crush *)(const void *)rg.buf;
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(c, used));
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(c, used + 16)); /* a larger room is fine, c->bytes rules */
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check(c, used - 1));
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check(c, 0));
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check(c, 55));
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check(NULL, used));
	{
		region odd;

		odd.buf = (uint8_t *)malloc(used + 64);
		memset(odd.buf, 0, used + 64);
		memcpy(odd.buf + 1, rg.buf, used);
		WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check((const wri_crush *)(const void *)(odd.buf + 1), used));
		free(odd.buf);
	}
	b0 = rd32(&rg, c->bucket_tab);
	b1 = rd32(&rg, c->bucket_tab + 4);
	b2 = rd32(&rg, c->bucket_tab + 8);
	b4 = rd32(&rg, c->bucket_tab + 16);
	r0 = rd32(&rg, c->rule_tab);
	set_tab = c->set_tab;
	WRT_CHECK((int32_t)rd32(&rg, set_tab) == -1); /* the default set comes first */
	idx0 = rd32(&rg, set_tab + 4);
	a0 = rd32(&rg, idx0);          /* its override of slot 0 */
	a1 = rd32(&rg, idx0 + 4);      /* and of slot 1 */
	WRT_CHECK(a0 != 0 && a1 != 0);

	corrupt("magic", &rg, 0, 0, used);
	corrupt("magic-wire", &rg, 0, 0x00010000u, used);
	corrupt("bytes-below-header", &rg, 4, 20, used);
	corrupt("bytes-above-room", &rg, 4, (uint32_t)used + 4, used);
	corrupt("max-buckets", &rg, 8, 32769, used);
	corrupt("max-buckets-bigger", &rg, 8, 8, used); /* the tables no longer match their contents */
	corrupt("max-rules", &rg, 12, 257, used);
	corrupt("max-devices-negative", &rg, 16, 0xffffffffu, used);
	corrupt("max-devices-small", &rg, 16, 3, used); /* a device item at or above it */
	corrupt("bucket-tab-unaligned", &rg, 20, 57, used);
	corrupt("bucket-tab-beyond", &rg, 20, (uint32_t)used, used);
	corrupt("bucket-tab-in-header", &rg, 20, 0, used);
	corrupt("rule-tab-beyond", &rg, 24, (uint32_t)used - 4, used);
	corrupt("n-sets-beyond", &rg, 28, 100000, used);
	corrupt("set-tab-with-no-sets", &rg, 28, 0, used);
	corrupt("set-tab-beyond", &rg, 32, (uint32_t)used - 4, used);
	corrupt("set-tab-unaligned", &rg, 32, c->set_tab + 2, used);
	corrupt("vary-r", &rg, 52, 33, used);
	/* the bucket table entries */
	corrupt("bucket-offset-beyond", &rg, c->bucket_tab, (uint32_t)used, used);
	corrupt("bucket-offset-unaligned", &rg, c->bucket_tab, (uint32_t)b0 + 2, used);
	corrupt("bucket-offset-in-header", &rg, c->bucket_tab, 8, used);
	corrupt("bucket-offset-tail", &rg, c->bucket_tab, (uint32_t)used - 8, used);
	corrupt("bucket-id", &rg, b0, (uint32_t)-5, used);
	corrupt("bucket-id-positive", &rg, b0, 1, used);
	corrupt("bucket-alg-0", &rg, b0 + 4, 11u, used); /* type 11, alg byte 0 */
	corrupt("bucket-alg-6", &rg, b0 + 4, 11u | (6u << 16), used);
	corrupt("bucket-hash", &rg, b0 + 4, 0x01050000u | 11u, used);
	corrupt("bucket-size-big", &rg, b0 + 8, 65536, used);
	corrupt("bucket-size-past-end", &rg, b0 + 8, 5000, used);
	corrupt("bucket-reserved", &rg, b0 + 12, 1, used);
	corrupt("bucket-item-slot", &rg, b0 + 16, (uint32_t)-8, used);
	corrupt("bucket-item-undef", &rg, b0 + 16, 0x7ffffffeu, used);
	corrupt("bucket-item-device", &rg, b1 + 16, 13, used); /* max_devices is 13 */
	corrupt("straw2-weight", &rg, b1 + 16 + 12, 0x80000000u, used);
	corrupt("bucket-of-other-slot", &rg, c->bucket_tab + 4, (uint32_t)b0, used); /* id -1 in slot 1 */
	(void)b2;
	(void)b4;
	/* rules */
	corrupt("rule-offset-beyond", &rg, c->rule_tab, (uint32_t)used, used);
	corrupt("rule-offset-unaligned", &rg, c->rule_tab, (uint32_t)r0 + 2, used);
	corrupt("rule-offset-header", &rg, c->rule_tab, 4, used);
	corrupt("rule-steps-65", &rg, r0, 65, used);
	corrupt("rule-steps-huge", &rg, r0, 0xffffffffu, used);
	/* choose_args */
	corrupt("set-index-beyond", &rg, set_tab + 4, (uint32_t)used, used);
	corrupt("set-index-unaligned", &rg, set_tab + 4, (uint32_t)idx0 + 1, used);
	corrupt("sets-not-ascending", &rg, set_tab, 9, used); /* pools 9 and 5 */
	corrupt("set-override-beyond", &rg, idx0, (uint32_t)used, used);
	corrupt("set-override-unaligned", &rg, idx0, (uint32_t)a0 + 1, used);
	corrupt("set-override-on-list-bucket", &rg, idx0 + 8, (uint32_t)a0, used);
	corrupt("set-override-on-hole", &rg, idx0 + 12, (uint32_t)a0, used);
	corrupt("args-n-pos-huge", &rg, a0, 0x10000000u, used);
	corrupt("args-has-ids", &rg, a0 + 4, 2, used);
	corrupt("args-weight", &rg, a0 + 8, 0x80000000u, used);
	(void)a1;
	/* what was restored passes again */
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(c, used));
	/* a region that is a prefix of itself is not accepted: cut at every 4th byte below c->bytes */
	for (i = 4; i < used; i += 4) {
		region cut;

		region_load(&cut, rg.buf, i);
		WRT_CHECK(wri_crush_check((const wri_crush *)(const void *)cut.buf, i) != WR_OK);
		free(cut.buf);
	}
	free(rg.buf);
	room_free(&r);
	gb_free(&g);
}

/* wri_crush_check on an override of an empty bucket: its rows cost no bytes, so a corrupted row count must neither be
 * accepted as a reason to loop four billion times nor be refused for its size alone. */
static void test_check_empty_override(void)
{
	gb g;
	room r;
	size_t used, idx, a;
	const wri_crush *c;
	region rg;

	gb_init(&g);
	gb_header(&g, 1, 0, 0);
	gb_bucket(&g, 5, -1, 3, 0, NULL, NULL, NULL, 0); /* straw2 bucket with no items */
	gb_u32(&g, 0);                                   /* three empty name maps */
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);                                   /* tunables: local tries 0, fallback 0, total 50, descend_once 1, */
	gb_u32(&g, 0);
	gb_u32(&g, 50);
	gb_u32(&g, 1);
	gb_u8(&g, 1);                                    /* vary_r 1, straw_calc_version 1, allowed algs, stable 1 */
	gb_u8(&g, 1);
	gb_u32(&g, 0x36);
	gb_u8(&g, 1);
	gb_u32(&g, 0);                                   /* three empty class maps */
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 1);                                   /* one choose_args set: key 0, bucket slot 0, two rows of length 0, no ids */
	gb_u64(&g, 0);
	gb_u32(&g, 1);
	gb_u32(&g, 0);
	gb_u32(&g, 2);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	gb_u32(&g, 0);
	c = dec_ok(g.p, g.n, &r, &used);
	WRT_CHECK(c->n_sets == 1);
	region_load(&rg, r.out, used);
	c = (const wri_crush *)(const void *)rg.buf;
	idx = rd32(&rg, c->set_tab + 4);
	a = rd32(&rg, idx);
	WRT_CHECK(a != 0 && rd32(&rg, a) == 2);
	wr32(&rg, a, 0xffffffffu); /* four billion rows of nothing: still a well-formed region, and the check returns at once */
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(c, used));
	wr32(&rg, a + 4, 2); /* ids flag beyond 1 is still refused */
	WRT_CHECK_STATUS(WR_E_CRUSH_ENCODING, wri_crush_check(c, used));
	free(rg.buf);
	room_free(&r);
	gb_free(&g);
}

/* ---- seeds ------------------------------------------------------------------------------------------------------ */

static void emit_more_seeds(void)
{
	gb g;
	ks_off o;
	int i;
	static const uint32_t vals[] = {0, 1, 0x7fffffffu, 0x80000000u, 0xffffffffu};

	/* single-field mutations of the kitchen sink: a count or a size set to the values that break arithmetic */
	gb_init(&g);
	ks_build(&g, KS_STAGE_MSR, &o);
	for (i = 0; i < 5; i++) {
		char nm[64];
		gb m = gb_copy(&g);

		gb_patch(&m, o.set_nb[0], vals[i], 4);
		snprintf(nm, sizeof(nm), "mut-args-nb-%d", i);
		seed_write(nm, m.p, m.n);
		gb_free(&m);
		m = gb_copy(&g);
		gb_patch(&m, o.nmap, vals[i], 4);
		snprintf(nm, sizeof(nm), "mut-name-count-%d", i);
		seed_write(nm, m.p, m.n);
		gb_free(&m);
		m = gb_copy(&g);
		gb_patch(&m, o.bk[2] + 16, vals[i], 4);
		snprintf(nm, sizeof(nm), "mut-list-size-%d", i);
		seed_write(nm, m.p, m.n);
		gb_free(&m);
	}
	gb_free(&g);
}

int main(int argc, char **argv)
{
	if (argc >= 3 && strcmp(argv[1], "--emit-seeds") == 0) {
		struct stat st;

		seed_dir = argv[2];
		if (stat(seed_dir, &st) != 0 && mkdir(seed_dir, 0755) != 0) {
			fprintf(stderr, "cannot create %s\n", seed_dir);
			return 1;
		}
	}
	test_lab_blobs();
	test_lab_incremental_form();
	test_kitchen_sink();
	test_args_keys();
	test_dropped_sets();
	test_edge_maps();
	test_real_blobs();
	test_negative();
	test_arguments();
	test_budget();
	test_check();
	test_check_empty_override();
	if (seed_dir != NULL)
		emit_more_seeds();
	return wrt_finish();
}
