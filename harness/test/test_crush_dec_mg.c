/* SPDX-License-Identifier: MIT */
/*
 * test_crush_dec_mg.c - the CRUSH decoder against the description that wrt_mapgen wrote the blob from.
 *
 * wrt_mapgen builds clusters (every bucket algorithm, racks, device classes with shadow buckets, every tunable profile,
 * every "how many trailing groups" stage, choose_args with weight rows, ids and a pool set) and encodes their CRUSH
 * blob. The description is the model: the compact region the core decodes must say the same thing, field by field, and
 * max_devices must be what 2.4 of the CRUSH note computes from the description. Also: bit flips and every truncation of
 * mapgen blobs never decode to something wri_crush_check refuses.
 *
 * `test_crush_dec_mg --emit-seeds DIR` writes a few of the blobs as fuzz seeds (mg-*).
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush.h"

#include <sys/stat.h>

static const char *seed_dir;

static void seed_write(const char *name, const uint8_t *p, size_t n)
{
	char path[512];
	FILE *f;

	if (seed_dir == NULL || n > 4096u) /* seeds stay small */
		return;
	snprintf(path, sizeof(path), "%s/%s", seed_dir, name);
	f = fopen(path, "wb");
	if (f == NULL || (n != 0 && fwrite(p, 1, n, f) != n))
		exit(1);
	fclose(f);
}

#define ROOM (4u * 1024u * 1024u)

/* The tunables the decoder must report for a description that carries `upto` groups. */
static void expect_tunables(const wrt_mg_crush *d, const wri_crush *c)
{
	int u = d->upto;

	WRT_CHECK_U64(c->tun.choose_local_tries, u >= WRT_MG_UPTO_A ? d->choose_local_tries : 2);
	WRT_CHECK_U64(c->tun.choose_local_fallback_tries, u >= WRT_MG_UPTO_A ? d->choose_local_fallback_tries : 5);
	WRT_CHECK_U64(c->tun.choose_total_tries, u >= WRT_MG_UPTO_A ? d->choose_total_tries : 19);
	WRT_CHECK_U64(c->tun.chooseleaf_descend_once, u >= WRT_MG_UPTO_B ? d->chooseleaf_descend_once : 0);
	WRT_CHECK_U64(c->tun.chooseleaf_vary_r, u >= WRT_MG_UPTO_C ? d->chooseleaf_vary_r : 0);
	WRT_CHECK_U64(c->tun.chooseleaf_stable, u >= WRT_MG_UPTO_F ? d->chooseleaf_stable : 0);
}

static void expect_bucket(const wrt_mg_crush *d, const wri_crush *c, uint32_t slot, int32_t *max_item)
{
	const wrt_mg_bucket *b = &WRT_MG_E(d->buckets, wrt_mg_bucket, slot);
	const wri_cbucket *cb = wri_crush_bucket_at(c, slot);
	uint32_t i;

	if (!b->present) {
		WRT_CHECK(cb == NULL);
		return;
	}
	WRT_CHECK(cb != NULL);
	if (cb == NULL)
		return;
	WRT_CHECK(cb->id == b->id && cb->id == -1 - (int32_t)slot);
	WRT_CHECK(cb->type == b->type && cb->alg == b->alg && cb->hash == 0 && cb->size == b->items.n);
	if (cb->size != b->items.n)
		return;
	for (i = 0; i < b->items.n; i++) {
		int32_t it = WRT_MG_E(b->items, int32_t, i);

		WRT_CHECK(wri_cbucket_items(cb)[i] == it);
		if (it > *max_item)
			*max_item = it;
		switch (b->alg) {
		case WRT_MG_ALG_STRAW2:
			WRT_CHECK(wri_cbucket_w(cb)[i] == WRT_MG_E(b->item_weights, uint32_t, i));
			break;
		case WRT_MG_ALG_STRAW:
			WRT_CHECK(wri_cbucket_w(cb)[i] == WRT_MG_E(b->straws, uint32_t, i));
			break;
		case WRT_MG_ALG_LIST:
			WRT_CHECK(wri_cbucket_w(cb)[i] == WRT_MG_E(b->item_weights, uint32_t, i));
			WRT_CHECK(wri_cbucket_sums(cb)[i] == WRT_MG_E(b->sum_weights, uint32_t, i));
			break;
		default:
			break;
		}
	}
}

static void expect_rule(const wrt_mg_crush *d, const wri_crush *c, uint32_t slot)
{
	const wrt_mg_rule *r = &WRT_MG_E(d->rules, wrt_mg_rule, slot);
	const wri_crule *cr = wri_crush_rule(c, slot);
	uint32_t i;

	if (!r->present) {
		WRT_CHECK(wri_crush_rule_kind(c, slot) == 0 && cr == NULL);
		return;
	}
	if (r->type != 1) {
		WRT_CHECK(wri_crush_rule_kind(c, slot) == 1 && cr == NULL);
		return;
	}
	WRT_CHECK(wri_crush_rule_kind(c, slot) == 2 && cr != NULL);
	if (cr == NULL)
		return;
	WRT_CHECK(cr->nsteps == r->steps.n);
	for (i = 0; i < cr->nsteps && i < r->steps.n; i++) {
		const wrt_mg_step *s = &WRT_MG_E(r->steps, wrt_mg_step, i);

		WRT_CHECK(wri_crule_steps(cr)[i].op == s->op && wri_crule_steps(cr)[i].arg1 == s->a1 && wri_crule_steps(cr)[i].arg2 == s->a2);
	}
}

static void expect_args(const wrt_mg_crush *d, const wri_crush *c)
{
	uint32_t s, k, i, j;

	if (d->upto < WRT_MG_UPTO_CARGS) {
		WRT_CHECK(c->n_sets == 0);
		return;
	}
	WRT_CHECK(c->n_sets == d->choose_args.n);
	for (s = 0; s < d->choose_args.n && s < c->n_sets; s++) {
		const wrt_mg_cset *set = &WRT_MG_E(d->choose_args, wrt_mg_cset, s);
		const uint32_t *ix = wri_crush_args_index(c, (int32_t)set->key);

		WRT_CHECK(ix != NULL);
		if (ix == NULL)
			continue;
		for (i = 0; i < c->max_buckets; i++) {
			const wri_cargs *a = wri_crush_args_of(c, ix, i);
			const wrt_mg_carg *want = NULL;

			for (k = 0; k < set->bucks.n; k++)
				if (WRT_MG_E(set->bucks, wrt_mg_carg, k).index == i)
					want = &WRT_MG_E(set->bucks, wrt_mg_carg, k);
			WRT_CHECK((a != NULL) == (want != NULL));
			if (a == NULL || want == NULL)
				continue;
			WRT_CHECK(a->n_pos == want->rows.n && a->has_ids == (want->ids.n != 0 ? 1u : 0u));
			for (k = 0; k < a->n_pos && k < want->rows.n; k++) {
				const wrt_mg_wrow *row = &WRT_MG_E(want->rows, wrt_mg_wrow, k);

				for (j = 0; j < row->w.n; j++)
					WRT_CHECK(wri_cargs_row(a, row->w.n, k)[j] == WRT_MG_E(row->w, uint32_t, j));
			}
			for (j = 0; j < want->ids.n; j++)
				WRT_CHECK(wri_cargs_ids(a, want->ids.n)[j] == WRT_MG_E(want->ids, int32_t, j));
		}
	}
}

/* Encode the description, decode the blob, compare. Returns the blob (caller frees) for the robustness tests. */
static int check_one(const char *name, const wrt_mg_crush *d, wrt_mg_buf *blob)
{
	static uint64_t room[ROOM / 8];
	wr_errinfo why;
	size_t used = 0;
	wr_status st;
	const wri_crush *c = (const wri_crush *)(const void *)room;
	int32_t max_item = -1;
	int64_t want_dev;
	uint32_t i;

	blob->p = NULL;
	blob->len = blob->cap = 0;
	WRT_CHECK(wrt_mg_crush_encode(d, blob) == 0);
	memset(&why, 0, sizeof(why));
	st = wri_crush_decode(blob->p, blob->len, (uint8_t *)room, sizeof(room), &used, &why);
	if (st != WR_OK) {
		fprintf(stderr, "%s: decode failed: %s (%s) at %llu\n", name, wr_status_name(st), why.what ? why.what : "-",
			(unsigned long long)why.a0);
		WRT_CHECK(0);
		return -1;
	}
	WRT_CHECK_STATUS(WR_OK, wri_crush_check(c, used));
	WRT_CHECK(c->max_buckets == d->buckets.n && c->max_rules == d->rules.n);
	expect_tunables(d, c);
	for (i = 0; i < d->buckets.n; i++)
		expect_bucket(d, c, i, &max_item);
	for (i = 0; i < d->rules.n; i++)
		expect_rule(d, c, i);
	expect_args(d, c);
	want_dev = (int64_t)max_item + 1;
	if (want_dev < 0)
		want_dev = 0;
	for (i = 0; i < d->item_names.n; i++) {
		int32_t key = WRT_MG_E(d->item_names, wrt_mg_name, i).key;

		if (key >= 0 && (int64_t)key + 1 > want_dev)
			want_dev = (int64_t)key + 1;
	}
	WRT_CHECK(c->max_devices == want_dev);
	/* sizes: a decode into exactly that room works, one byte less is a budget error and writes nothing past it */
	{
		uint8_t *tight = (uint8_t *)malloc(used + 8u + 8u);
		size_t u2 = 0;

		memset(tight, 0xcc, used + 16u);
		WRT_CHECK_STATUS(WR_E_MAP_BUDGET, wri_crush_decode(blob->p, blob->len, tight + 8, used - 1u, &u2, NULL));
		WRT_CHECK(tight[8 + used - 1u] == 0xcc && tight[8 + used] == 0xcc && tight[7] == 0xcc);
		memset(tight, 0xcc, used + 16u);
		WRT_CHECK_STATUS(WR_OK, wri_crush_decode(blob->p, blob->len, tight + 8, used, &u2, NULL));
		WRT_CHECK(u2 == used && tight[8 + used] == 0xcc);
		free(tight);
	}
	return 0;
}

static void grid(void)
{
	static const uint32_t osds[] = {1, 2, 5, 12, 40, 100};
	static const int tuns[] = {WRT_MG_TUN_LEGACY, WRT_MG_TUN_BOBTAIL, WRT_MG_TUN_FIREFLY, WRT_MG_TUN_HAMMER, WRT_MG_TUN_JEWEL};
	unsigned o, a, t, up, v;
	char name[96];
	unsigned count = 0;
	wrt_mg_rng rng;

	wrt_mg_rng_seed(&rng, 0x43525553u);
	for (o = 0; o < sizeof(osds) / sizeof(osds[0]); o++) {
		for (a = 1; a <= 5; a++) {
			for (t = 0; t < sizeof(tuns) / sizeof(tuns[0]); t++) {
				for (up = WRT_MG_UPTO_NONE; up <= WRT_MG_UPTO_MSR; up++) {
					wrt_mg_cluster_spec s;
					wrt_mg_crush d;
					wrt_mg_buf blob;

					/* every combination is a lot of maps: thin the grid with the PRNG, keep every stage for straw2 */
					if (a != 5 && up != WRT_MG_UPTO_MSR && up != WRT_MG_UPTO_NONE && wrt_mg_rng_below(&rng, 4) != 0)
						continue;
					wrt_mg_cluster_spec_init(&s, osds[o]);
					s.bucket_alg = (uint8_t)a;
					s.tunables = tuns[t];
					s.crush_upto = (int)up;
					s.osds_per_host = 1 + wrt_mg_rng_below(&rng, 6);
					s.hosts_per_rack = wrt_mg_rng_below(&rng, 3) == 0 ? 0 : 1 + wrt_mg_rng_below(&rng, 4);
					/* at least one class: wrt_mapgen's builder passes a NULL vector to qsort() with none (UBSan), and maps
					 * without classes are covered by shapes() */
					s.n_classes = 1 + wrt_mg_rng_below(&rng, 3);
					s.weight_jitter = (int)wrt_mg_rng_below(&rng, 2);
					s.choose_args_rows = wrt_mg_rng_below(&rng, 3);
					s.choose_args_ids = (int)wrt_mg_rng_below(&rng, 2);
					s.choose_args_pool_set = (int)wrt_mg_rng_below(&rng, 2);
					s.seed = wrt_mg_rng_next(&rng);
					snprintf(name, sizeof(name), "grid osds=%u alg=%u tun=%u upto=%u", osds[o], a, t, up);
					memset(&d, 0, sizeof(d));
					if (wrt_mg_build_crush(&d, &s) != 0) {
						fprintf(stderr, "%s: build failed\n", name);
						WRT_CHECK(0);
						continue;
					}
					if (check_one(name, &d, &blob) == 0) {
						count++;
						if (seed_dir != NULL && (count % 23u) == 0) {
							snprintf(name, sizeof(name), "mg-grid-%03u", count);
							seed_write(name, blob.p, blob.len);
						}
						/* mutations: flip bytes of the blob, whatever decodes must pass the structural check */
						if ((count % 7u) == 0) {
							static uint64_t room[(1u << 20) / 8];
							uint8_t *m = (uint8_t *)malloc(blob.len);

							for (v = 0; v < 150 && blob.len > 0; v++) {
								size_t at = wrt_mg_rng_below(&rng, (uint32_t)blob.len);
								size_t used = 0;
								wr_errinfo why;
								wr_status st;

								memcpy(m, blob.p, blob.len);
								m[at] = (uint8_t)(m[at] ^ (1u << wrt_mg_rng_below(&rng, 8)));
								memset(&why, 0, sizeof(why));
								st = wri_crush_decode(m, blob.len, (uint8_t *)room, sizeof(room), &used, &why);
								WRT_CHECK(st == WR_OK || st == WR_E_CRUSH_ENCODING || st == WR_E_MAP_BUDGET);
								if (st == WR_OK)
									WRT_CHECK_STATUS(WR_OK, wri_crush_check((const wri_crush *)(const void *)room, used));
								else
									WRT_CHECK(why.status == st && why.what != NULL && used == 0);
							}
							free(m);
						}
					}
					wrt_mg_buf_free(&blob);
					wrt_mg_crush_free(&d);
				}
			}
		}
	}
	WRT_CHECK(count > 300);
}

/* Hand-shaped descriptions the grid does not reach: a zero-length name, legacy 64-bit name keys, holes in both tables. */
static void shapes(void)
{
	wrt_mg_crush d;
	wrt_mg_buf blob;
	static const int32_t it0[2] = {0, 1}, it1[3] = {2, 3, 4}, itroot[2] = {-1, -2};
	static const wrt_mg_step steps[3] = {{WRT_MG_OP_TAKE, -3, 0}, {WRT_MG_OP_CHOOSELEAF_FIRSTN, 0, 1}, {WRT_MG_OP_EMIT, 0, 0}};
	int up;

	for (up = WRT_MG_UPTO_NONE; up <= WRT_MG_UPTO_MSR; up++) {
		char nm[64];

		memset(&d, 0, sizeof(d));
		wrt_mg_crush_init(&d);
		wrt_mg_crush_tunables(&d, WRT_MG_TUN_BOBTAIL);
		d.upto = up;
		/* slot 0 and 1: two hosts, slot 2: the root, slot 3: a hole, slot 4: a list bucket under nobody */
		(void)wrt_mg_crush_add_bucket(&d, -1, 1, WRT_MG_ALG_STRAW2, it0, NULL, 2);
		(void)wrt_mg_crush_add_bucket(&d, -2, 1, WRT_MG_ALG_STRAW2, it1, NULL, 3);
		(void)wrt_mg_crush_add_bucket(&d, -3, 2, WRT_MG_ALG_STRAW2, itroot, NULL, 2);
		(void)wrt_mg_crush_add_bucket(&d, -5, 1, WRT_MG_ALG_LIST, it0, NULL, 2);
		(void)wrt_mg_crush_add_rule(&d, 0, 1, steps, 3);
		(void)wrt_mg_crush_add_rule(&d, 3, 3, steps, 2); /* an erasure rule in slot 3, slots 1 and 2 are holes */
		wrt_mg_crush_name(&d, 0, 0, "osd");
		wrt_mg_crush_name(&d, 0, 1, "");     /* a zero-length name: key, 0, 0 on the wire */
		wrt_mg_crush_name(&d, 1, -1, "h0");
		wrt_mg_crush_name(&d, 1, 4, "osd.4");
		wrt_mg_crush_name(&d, 1, 9, "osd.9");  /* past every item */
		wrt_mg_crush_name(&d, 2, 0, "rep");
		if (d.item_names.n > 1)
			WRT_MG_E(d.item_names, wrt_mg_name, 0).legacy64 = 1;
		if (d.type_names.n > 0)
			WRT_MG_E(d.type_names, wrt_mg_name, d.type_names.n - 1).legacy64 = 1;
		wrt_mg_crush_recount(&d);
		snprintf(nm, sizeof(nm), "shape upto=%d", up);
		if (check_one(nm, &d, &blob) == 0 && up == WRT_MG_UPTO_MSR)
			seed_write("mg-shape-msr", blob.p, blob.len);
		else if (up == WRT_MG_UPTO_CARGS)
			seed_write("mg-shape-cargs", blob.p, blob.len);
		wrt_mg_buf_free(&blob);
		wrt_mg_crush_free(&d);
	}
}

/* Every truncation of a mapgen blob: refused, or a valid map that passes the check. */
static void truncations(void)
{
	wrt_mg_cluster_spec s;
	wrt_mg_crush d;
	wrt_mg_buf blob;
	static uint64_t room[(1u << 20) / 8];
	size_t len, ok = 0;

	wrt_mg_cluster_spec_init(&s, 9);
	s.osds_per_host = 3;
	s.hosts_per_rack = 2;
	s.n_classes = 2;
	s.choose_args_rows = 2;
	s.choose_args_ids = 1;
	s.choose_args_pool_set = 1;
	s.crush_upto = WRT_MG_UPTO_MSR;
	memset(&d, 0, sizeof(d));
	WRT_CHECK(wrt_mg_build_crush(&d, &s) == 0);
	WRT_CHECK(check_one("truncations", &d, &blob) == 0);
	for (len = 0; len < blob.len; len++) {
		size_t used = 0;
		wr_errinfo why;
		wr_status st;

		memset(&why, 0, sizeof(why));
		st = wri_crush_decode(blob.p, len, (uint8_t *)room, sizeof(room), &used, &why);
		WRT_CHECK(st == WR_OK || st == WR_E_CRUSH_ENCODING);
		if (st == WR_OK) {
			ok++;
			WRT_CHECK_STATUS(WR_OK, wri_crush_check((const wri_crush *)(const void *)room, used));
		}
	}
	WRT_CHECK(ok >= 8 && ok <= 10); /* the group boundaries after the names: six tunable groups, classes, choose_args */
	seed_write("mg-trunc-base", blob.p, blob.len);
	wrt_mg_buf_free(&blob);
	wrt_mg_crush_free(&d);
}

int main(int argc, char **argv)
{
	if (argc >= 3 && strcmp(argv[1], "--emit-seeds") == 0) {
		struct stat st;

		seed_dir = argv[2];
		if (stat(seed_dir, &st) != 0 && mkdir(seed_dir, 0755) != 0)
			return 1;
	}
	shapes();
	truncations();
	grid();
	return wrt_finish();
}
