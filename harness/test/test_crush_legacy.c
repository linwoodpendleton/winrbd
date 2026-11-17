/* SPDX-License-Identifier: MIT */
/*
 * test_crush_legacy.c - the legacy bucket choosers: list, uniform and the permutation chooser of the local-fallback path
 * (core/src/crush/wri_crush_legacy.c, docs/spec/crush-and-placement.md 3.4.4, 3.4.5 and 3.6 step 4).
 *
 * What it checks, against what:
 *   1. The choosers on hand-built buckets against references written in this file (the list walk spelled out, and the
 *      permutation as a COMPLETE Fisher-Yates shuffle where the core stops after r mod size steps): every bucket size 1 to
 *      256 and every r below the size (and beyond it), three placement seeds, bucket ids positive-looking and negative;
 *      the answers over r = 0 .. size - 1 are a permutation of the items; the scratch array is a permutation of the
 *      indexes after every call; the answer does not depend on what the scratch held before; uniform and permutation are
 *      the same function and the permutation ignores the algorithm of the bucket it is given; a bucket of 257 and more is
 *      WR_E_CRUSH_UNSUPPORTED for both permutation choosers (and the item is NONE) but not for list (up to 65535 items);
 *      empty buckets, null arguments; extreme weights and sums (64-bit product, malformed sum arrays); the draw of list is
 *      proportional to the weights and the draw of uniform is flat.
 *   2. Ground truth from crushtool (Ceph v20.2.5, the .mappings.json files of public/crushleg, made by gen_crushleg.py): flat list,
 *      uniform, straw and straw2 buckets of 1 to 300 items under legacy and jewel tunables with devices out (the draw
 *      number r grows, and with local_fallback_tries 5 the permutation takes over), and a mixed hierarchy (straw2 root, list racks, uniform hosts of unequal
 *      weight) under three tunable profiles. Every run must match, except the ones that need a permutation of more than
 *      256 items, which must be refused as UNSUPPORTED on every x. A second pass switches the fallback off in a copy of
 *      each legacy map and requires that the answers then DIFFER from crushtool: the vectors do reach the fallback.
 *   3. Every list and uniform bucket of the decoded vector maps against the references, over x and r.
 *   4. The rule audit: list and uniform buckets, the fallback tunable and the 256-item limit give the answers the
 *      note's 4.3 asks for, and an audited rule maps without a refusal.
 *   5. When WINRBD_CEPH_SRC points at a Ceph tree: the in-tree crushtool known-answer files (legacy, bobtail, firefly
 *      and vary-r tunables, chooseleaf) with the fallback and local-retry paths on (read at test time, never copied).
 *      The note records that those files never reach the permutation (0 uses); the run is a regression test of the
 *      interpreter with the real choosers linked, not a proof of the permutation.
 */
#include "wrt.h"
#include "wrt_mapgen.h"
#include "wri_crush.h"
#include "wri_crush_buck.h"
#include "wri_crush_hash.h"

#define W_IN 0x10000u
#define WORK_BIG 200000000u

/* ---- references ------------------------------------------------------------------------------------------------ */

/* 3.4.4 spelled out: from the last item down, the first whose scaled draw is below its own weight; items[0] if none. */
static int32_t ref_list(uint32_t n, const int32_t *items, const uint32_t *wt, const uint32_t *sum, int32_t id, uint32_t x, uint32_t r)
{
	int64_t i;

	for (i = (int64_t)n - 1; i >= 0; i--) {
		uint64_t h = (uint64_t)(wri_crush_hash4(x, (uint32_t)items[i], r, (uint32_t)id) & 0xffffu);

		h = (h * (uint64_t)sum[i]) >> 16;
		if (h < (uint64_t)wt[i])
			return items[i];
	}
	return items[0];
}

/* 3.4.5 as a complete shuffle (every step p = 0 .. n - 2), then the entry r mod n. The core does only the first r mod n + 1 steps;
 * a step p swaps positions >= p, so the entry at r mod n is final once step r mod n has run. */
static int32_t ref_perm(uint32_t n, const int32_t *items, int32_t id, uint32_t x, uint32_t r)
{
	uint32_t perm[WRI_CRUSH_PERM_MAX], p, i;

	for (i = 0; i < n; i++)
		perm[i] = i;
	for (p = 0; p + 1u < n; p++) {
		uint32_t j = p + wri_crush_hash3(x, (uint32_t)id, p) % (n - p), t = perm[p];

		perm[p] = perm[j];
		perm[j] = t;
	}
	return items[perm[r % n]];
}

/* ---- a bucket record in a big aligned buffer --------------------------------------------------------------------- */

#define BK_MAX 65535u
static uint32_t *bkbuf; /* 4 head words, then three arrays of BK_MAX words */

static const wri_cbucket *mk(uint8_t alg, uint32_t n, int32_t id, const int32_t *items, const uint32_t *wt, const uint32_t *sum)
{
	wri_cbucket b;

	memset(&b, 0, sizeof(b));
	b.id = id;
	b.type = 1;
	b.alg = alg;
	b.size = n;
	memcpy(bkbuf, &b, sizeof(b));
	if (n != 0u) {
		memcpy(bkbuf + 4, items, (size_t)n * 4u);
		if (wt != NULL)
			memcpy(bkbuf + 4 + n, wt, (size_t)n * 4u);
		if (sum != NULL)
			memcpy(bkbuf + 4 + 2u * (size_t)n, sum, (size_t)n * 4u);
	}
	return (const wri_cbucket *)(const void *)bkbuf;
}

static int is_perm(const uint16_t *p, uint32_t n)
{
	static uint8_t seen[WRI_CRUSH_PERM_MAX];
	uint32_t i;

	memset(seen, 0, sizeof(seen));
	for (i = 0; i < n; i++) {
		if (p[i] >= n || seen[p[i]])
			return 0;
		seen[p[i]] = 1;
	}
	return 1;
}

static const uint32_t XS[3] = {0u, 12345u, 0xdeadbeefu};

static void check_permutation(void)
{
	static int32_t items[WRI_CRUSH_PERM_MAX + 8];
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	uint32_t n, i, xi, r;
	unsigned long calls = 0, bad_perm = 0, bad_ref = 0, bad_set = 0, bad_dirty = 0;

	for (n = 1; n <= WRI_CRUSH_PERM_MAX; n++) {
		for (i = 0; i < n; i++)
			items[i] = (int32_t)(1000u + i * 3u);
		for (xi = 0; xi < 3; xi++) {
			int32_t id = (n & 1u) ? -1 - (int32_t)(n % 37u) : (int32_t)(n + 5u); /* a real bucket id is negative; the formula is blind to it */
			const wri_cbucket *b = mk((uint8_t)WRI_CRUSH_ALG_UNIFORM, n, id, items, NULL, NULL);
			static uint8_t used[WRI_CRUSH_PERM_MAX + 8];
			uint32_t x = XS[xi] + n * 7u;

			memset(used, 0, sizeof(used));
			for (r = 0; r < n + 3u; r++) {
				int32_t got = 0, got2 = 0;
				uint16_t perm2[WRI_CRUSH_PERM_MAX];

				memset(perm, 0xaa, sizeof(perm));
				memset(perm2, 0x55, sizeof(perm2));
				calls++;
				if (wri_crush_choose_uniform(b, x, r, perm, &got) != WR_OK || wri_crush_choose_perm(b, x, r, perm2, &got2) != WR_OK) {
					bad_perm++;
					continue;
				}
				if (!is_perm(perm, n))
					bad_perm++;
				if (got != ref_perm(n, items, id, x, r))
					bad_ref++;
				if (got != got2 || memcmp(perm, perm2, (size_t)n * 2u) != 0)
					bad_dirty++; /* the scratch contents before the call changed the answer, or uniform and perm differ */
				if (r < n) {
					uint32_t idx = (uint32_t)(got - 1000) / 3u;

					if (got < 1000 || (uint32_t)(got - 1000) % 3u != 0u || idx >= n || used[idx])
						bad_set++;
					else
						used[idx] = 1;
				}
			}
			/* r beyond the size wraps: r and r + n * k are the same draw, up to the largest r */
			{
				int32_t a = 0, c = 0, d = 0;

				WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, 0u, perm, &a));
				WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, n, perm, &c));
				WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, n * 1000u, perm, &d));
				WRT_CHECK(a == c && a == d);
				WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, 0xffffffffu, perm, &a));
				WRT_CHECK(a == ref_perm(n, items, id, x, 0xffffffffu));
			}
		}
	}
	WRT_CHECK(calls > 100000);
	WRT_CHECK(bad_perm == 0);
	WRT_CHECK(bad_ref == 0);
	WRT_CHECK(bad_set == 0);
	WRT_CHECK(bad_dirty == 0);
	printf("permutation: %lu calls, sizes 1..256, %lu wrong\n", calls, bad_perm + bad_ref + bad_set + bad_dirty);
}

static void check_perm_any_algorithm(void)
{
	int32_t items[40], a, b2, c, d;
	uint32_t wt[40], sm[40], i, x, r;
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	uint32_t acc = 0;
	const uint8_t algs[5] = {1, 2, 3, 4, 5};
	unsigned k;

	for (i = 0; i < 40; i++) {
		items[i] = (int32_t)i * 2 + 1;
		wt[i] = 0x10000u + i * 100u;
		acc += wt[i];
		sm[i] = acc;
	}
	for (x = 0; x < 50; x++) {
		for (r = 0; r < 60; r++) {
			const wri_cbucket *u = mk(1, 40, -7, items, wt, sm);

			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(u, x, r, perm, &a));
			for (k = 0; k < 5; k++) { /* the algorithm byte and the weight tails do not matter */
				const wri_cbucket *o = mk(algs[k], 40, -7, items, wt, sm);

				WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(o, x, r, perm, &b2));
				WRT_CHECK(a == b2);
			}
			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(u, x, r, perm, &c));
			WRT_CHECK(a == c);
			WRT_CHECK(a == ref_perm(40, items, -7, x, r));
			d = ref_perm(40, items, -8, x, r); /* a different bucket id gives a different permutation (not always a different item) */
			(void)d;
		}
	}
	/* the bucket id is an input: over many (x, r) two ids must differ somewhere */
	{
		unsigned diff = 0;

		for (x = 0; x < 200; x++) {
			const wri_cbucket *b = mk(1, 40, -7, items, wt, sm);
			int32_t p1, p2;

			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, 3, perm, &p1));
			b = mk(1, 40, -9, items, wt, sm);
			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x, 3, perm, &p2));
			diff += (p1 != p2);
		}
		WRT_CHECK(diff > 100);
	}
}

static void check_limits_and_args(void)
{
	static int32_t items[BK_MAX];
	static uint32_t wt[BK_MAX], sm[BK_MAX];
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	int32_t item = 0;
	uint32_t i, acc = 0;
	const wri_cbucket *b;

	for (i = 0; i < BK_MAX; i++) {
		items[i] = (int32_t)i;
		wt[i] = 0x10000u;
		acc += wt[i];
		sm[i] = acc; /* wraps above 65535 items: only the first 65535 * 0x10000 fits, the product still does in 64 bit */
	}
	/* 256 works, 257 and more do not (permutation); list has no such limit */
	b = mk(1, 256, -1, items, NULL, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(b, 5, 3, perm, &item));
	WRT_CHECK(item == ref_perm(256, items, -1, 5, 3));
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, 5, 3, perm, &item));
	b = mk(1, 257, -1, items, NULL, NULL);
	item = 123;
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_choose_uniform(b, 5, 3, perm, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);
	item = 123;
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_choose_perm(b, 5, 3, perm, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);
	b = mk(5, 65535, -1, items, wt, sm); /* straw2 alg byte: the permutation still refuses by size alone */
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_choose_perm(b, 5, 3, perm, &item));
	b = mk(2, 257, -1, items, wt, sm);
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, 5, 3, &item));
	WRT_CHECK(item == ref_list(257, items, wt, sm, -1, 5, 3));
	b = mk(2, 65535, -3, items, wt, sm);
	for (i = 0; i < 20; i++) {
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, i, i * 3u, &item));
		WRT_CHECK(item == ref_list(65535, items, wt, sm, -3, i, i * 3u));
	}

	/* empty buckets: no item, no failure, the NONE item the interpreter refuses */
	b = mk(2, 0, -1, items, wt, sm);
	item = 5;
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, 1, 1, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);
	b = mk(1, 0, -1, items, wt, sm);
	item = 5;
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(b, 1, 1, perm, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);
	item = 5;
	WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, 1, 1, perm, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);

	/* null arguments */
	b = mk(2, 3, -1, items, wt, sm);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_list(NULL, 1, 1, &item));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_list(b, 1, 1, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_uniform(NULL, 1, 1, perm, &item));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_uniform(b, 1, 1, NULL, &item));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_uniform(b, 1, 1, perm, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_perm(NULL, 1, 1, perm, &item));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_perm(b, 1, 1, NULL, &item));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_perm(b, 1, 1, perm, NULL));
	item = 77;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_crush_choose_perm(NULL, 1, 1, perm, &item));
	WRT_CHECK(item == WRI_CRUSH_ITEM_NONE);

	/* a one-item bucket answers its item for every r and x, without a hash */
	{
		int32_t one[1] = {-42};
		uint32_t w1[1] = {0x10000u}, s1[1] = {0x10000u}, r;

		for (r = 0; r < 300; r++) {
			b = mk(1, 1, -1, one, w1, s1);
			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(b, r * 31u, r, perm, &item));
			WRT_CHECK(item == -42);
			b = mk(2, 1, -1, one, w1, s1);
			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, r * 31u, r, &item));
			WRT_CHECK(item == -42);
		}
		w1[0] = 0; /* even a zero-weight single item is the answer (the fallback) */
		s1[0] = 0;
		b = mk(2, 1, -1, one, w1, s1);
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, 3, 4, &item));
		WRT_CHECK(item == -42);
	}
}

static void check_list(void)
{
	int32_t items[64], item = 0;
	uint32_t wt[64], sm[64], i, n, x, r, k;
	const wri_cbucket *b;
	unsigned long cnt[8];

	/* equal, unequal, zero and huge weights; sums as a builder writes them and as a hostile map could */
	for (k = 0; k < 6; k++) {
		for (n = 1; n <= 40; n += (k < 2 ? 1 : 7)) {
			uint64_t acc = 0;

			for (i = 0; i < n; i++) {
				items[i] = (int32_t)(i * 5u) - 20;
				switch (k) {
				case 0: wt[i] = 0x10000u; break;
				case 1: wt[i] = 0x2000u + (i * 0x1234u) % 0x30000u; break;
				case 2: wt[i] = (i % 3u == 1u) ? 0u : 0x10000u; break;
				case 3: wt[i] = 0xffffffffu - i; break;
				case 4: wt[i] = (i * 2654435761u) | 1u; break;
				default: wt[i] = 1u + i; break;
				}
				acc += wt[i];
				sm[i] = (k == 4 || k == 5) ? (uint32_t)(acc * 3u) : (uint32_t)acc; /* k 3, 4: wrapped or oversized sums */
			}
			if (k == 5)
				for (i = 0; i < n; i++)
					sm[i] = (i * 97u) % 11u; /* sums below the weights: nothing may qualify, the fallback must answer */
			b = mk(2, n, -3 - (int32_t)n, items, wt, sm);
			for (x = 0; x < 40; x++) {
				for (r = 0; r < 12; r++) {
					WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, x * 977u, r, &item));
					WRT_CHECK(item == ref_list(n, items, wt, sm, -3 - (int32_t)n, x * 977u, r));
				}
			}
		}
	}

	/* proportional: weights 1, 2, 3, 4 (sums 1, 3, 6, 10) */
	for (i = 0; i < 4; i++) {
		items[i] = (int32_t)i;
		wt[i] = (i + 1u) * 0x10000u;
		sm[i] = ((i + 1u) * (i + 2u) / 2u) * 0x10000u;
	}
	memset(cnt, 0, sizeof(cnt));
	b = mk(2, 4, -1, items, wt, sm);
	for (x = 0; x < 40000; x++) {
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, x, 0, &item));
		cnt[item]++;
	}
	for (i = 0; i < 4; i++) {
		unsigned long want = 4000ul * (i + 1u);

		WRT_CHECK(cnt[i] > want - want / 12u && cnt[i] < want + want / 12u);
	}
	/* nothing qualifies (every weight 0): the answer is the first item, whatever x and r are */
	for (n = 1; n <= 9; n++) {
		for (i = 0; i < n; i++) {
			items[i] = 500 + (int32_t)i;
			wt[i] = 0;
			sm[i] = (i + 1u) * 0x10000u;
		}
		b = mk(2, n, -5, items, wt, sm);
		for (x = 0; x < 50; x++) {
			WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, x * 3u, x % 7u, &item));
			WRT_CHECK(item == 500);
		}
	}
	/* a zero-weight item is never chosen while another has weight */
	for (i = 0; i < 4; i++) {
		wt[i] = (i == 2u) ? 0u : 0x10000u;
		sm[i] = ((i < 2u ? i + 1u : i) * 0x10000u);
	}
	b = mk(2, 4, -1, items, wt, sm);
	for (x = 0; x < 5000; x++) {
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, x, x % 9u, &item));
		WRT_CHECK(item != 2);
	}
}

static void check_uniform_flat(void)
{
	int32_t items[10], item = 0;
	unsigned long cnt[10], first[10];
	uint16_t perm[WRI_CRUSH_PERM_MAX];
	uint32_t i, x;
	const wri_cbucket *b;

	for (i = 0; i < 10; i++)
		items[i] = (int32_t)i;
	b = mk(1, 10, -2, items, NULL, NULL);
	memset(cnt, 0, sizeof(cnt));
	memset(first, 0, sizeof(first));
	for (x = 0; x < 30000; x++) {
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(b, x, 0, perm, &item));
		cnt[item]++;
		WRT_CHECK_STATUS(WR_OK, wri_crush_choose_uniform(b, x, 7, perm, &item));
		first[item]++;
	}
	for (i = 0; i < 10; i++) {
		WRT_CHECK(cnt[i] > 2600 && cnt[i] < 3400);
		WRT_CHECK(first[i] > 2600 && first[i] < 3400);
	}
}

/* ---- the decoded maps of the vectors ------------------------------------------------------------------------------- */

typedef struct cmap {
	uint8_t *room;
	size_t used;
	wri_crush *c;
} cmap;

static int cm_load(cmap *m, const char *rel)
{
	uint8_t *blob;
	size_t n, cap;
	wr_errinfo why;

	memset(&why, 0, sizeof(why));
	memset(m, 0, sizeof(*m));
	if (wrt_mg_load_hex_file(wrt_vec_path(rel), &blob, &n) != 0) {
		fprintf(stderr, "cannot read %s\n", rel);
		return -1;
	}
	cap = n * 4u + 65536u;
	m->room = (uint8_t *)malloc(cap);
	if (m->room == NULL)
		abort();
	if (wri_crush_decode(blob, n, m->room, cap, &m->used, &why) != WR_OK) {
		fprintf(stderr, "decode of %s failed: %s\n", rel, why.what ? why.what : "?");
		free(blob);
		free(m->room);
		m->room = NULL;
		return -1;
	}
	free(blob);
	m->c = (wri_crush *)(void *)m->room;
	return 0;
}

static void cm_free(cmap *m)
{
	free(m->room);
	m->room = NULL;
}

typedef struct vres {
	unsigned long cmp;   /* mappings compared */
	unsigned long bad;   /* compared and different, or a status other than OK / the expected refusal */
	unsigned long unsup; /* refused as UNSUPPORTED */
	unsigned long runs;
	unsigned long unsup_runs;
} vres;

static int eq_list(const int32_t *a, uint32_t na, const int32_t *b, uint32_t nb)
{
	uint32_t i;

	if (na != nb)
		return 0;
	for (i = 0; i < na; i++)
		if (a[i] != b[i])
			return 0;
	return 1;
}

static void fmt_list(char *out, size_t cap, const int32_t *a, uint32_t n)
{
	size_t p = 0;
	uint32_t i;

	out[0] = 0;
	for (i = 0; i < n && p + 12 < cap; i++)
		p += (size_t)snprintf(out + p, cap - p, "%s%d", i ? "," : "", (int)a[i]);
}

/* A run that needs a permutation of more than 256 items has to be refused on every x. */
static int run_is_big_uniform(const char *name)
{
	return strstr(name, "uni257") != NULL || strstr(name, "uni300") != NULL;
}

static uint32_t jint(const wrt_json *j, wrt_tok t, int *ok)
{
	return (uint32_t)wrt_json_int(j, t, ok);
}

/* Run every run of a vector file against the region `c`. quiet: count only (the switched-off-fallback pass). */
static void run_vector(const char *tag, const wri_crush *c, const wrt_json *j, vres *vr, int quiet)
{
	wrt_tok runs = wrt_json_get(j, wrt_json_root(j), "runs"), v;
	size_t i, k, e, shown = 0;
	uint32_t nd = (uint32_t)c->max_devices;
	uint32_t *w = (uint32_t *)malloc((nd ? nd : 1u) * sizeof(uint32_t));

	if (w == NULL)
		abort();
	memset(vr, 0, sizeof(*vr));
	for (i = 0; i < wrt_json_count(j, runs); i++) {
		const char *name = wrt_json_key_at(j, runs, i, &v);
		int ok;
		uint32_t rule = jint(j, wrt_json_get(j, v, "rule"), &ok), nrep = jint(j, wrt_json_get(j, v, "num_rep"), &ok);
		uint32_t minx = jint(j, wrt_json_get(j, v, "min_x"), &ok);
		wrt_tok xr = wrt_json_get(j, v, "x_to_result"), wm = wrt_json_get(j, v, "weights");
		int big = run_is_big_uniform(name);
		unsigned long run_unsup = 0;

		for (k = 0; k < nd; k++)
			w[k] = W_IN;
		for (k = 0; k < wrt_json_count(j, wm); k++) {
			wrt_tok val;
			const char *dev = wrt_json_key_at(j, wm, k, &val);
			int vok;
			int64_t iv = wrt_json_int(j, val, &vok);
			uint32_t d = (uint32_t)strtoul(dev, NULL, 10);

			if (d < nd)
				w[d] = vok ? (uint32_t)(iv * (int64_t)W_IN) : W_IN / 2u; /* the files hold 0 and 0.5 only */
		}
		vr->runs++;
		for (k = 0; k < wrt_json_count(j, xr); k++) {
			wrt_tok lst = wrt_json_at(j, xr, k);
			uint32_t want_n = (uint32_t)wrt_json_count(j, lst), x = minx + (uint32_t)k, ng = 0;
			int32_t want[WRI_CRUSH_RESULT_MAX], got[WRI_CRUSH_RESULT_MAX];
			wri_crush_ws ws;
			wri_crush_in in;
			wr_errinfo why;
			wr_status st;

			for (e = 0; e < want_n && e < WRI_CRUSH_RESULT_MAX; e++)
				want[e] = (int32_t)jint(j, wrt_json_at(j, lst, e), &ok);
			memset(&ws, 0, sizeof(ws));
			memset(&why, 0, sizeof(why));
			ws.work = WORK_BIG;
			in.rule = rule;
			in.x = x;
			in.result_max = nrep;
			in.osd_weight = w;
			in.weight_max = nd;
			in.args_pool = 0;
			st = wri_crush_do_rule(c, &in, &ws, got, &ng, &why);
			vr->cmp++;
			if (st == WR_E_CRUSH_UNSUPPORTED && big) {
				vr->unsup++;
				run_unsup++;
				continue;
			}
			if (st != WR_OK || big || !eq_list(got, ng, want, want_n)) {
				vr->bad++;
				if (!quiet && shown++ < 6) {
					char a[128], b[128];

					fmt_list(a, sizeof(a), got, st == WR_OK ? ng : 0u);
					fmt_list(b, sizeof(b), want, want_n);
					fprintf(stderr, "%s/%s: rule %u x %u numrep %u: status %d (%s) got [%s] want [%s]%s%s\n", tag, name, rule, x, nrep, (int)st,
						wrt_status_name_(st), a, b, why.what ? " why: " : "", why.what ? why.what : "");
				}
			}
		}
		if (run_unsup != 0)
			vr->unsup_runs++;
	}
	free(w);
}

static const char *const VECS[] = {"cl01-flat-legacy-choosers", "cl02-jewel-large-buckets", "cl03-mixed-legacy", "cl04-mixed-firefly",
				   "cl05-mixed-odd"};
#define N_VECS (sizeof(VECS) / sizeof(VECS[0]))

static void check_vectors(void)
{
	size_t mi;
	unsigned long total = 0;

	for (mi = 0; mi < N_VECS; mi++) {
		char rel[256];
		cmap m;
		wrt_json j;
		vres vr, vr0;

		snprintf(rel, sizeof(rel), "public/crushleg/%s.crush.hex", VECS[mi]);
		if (cm_load(&m, rel) != 0) {
			WRT_CHECK(0);
			continue;
		}
		snprintf(rel, sizeof(rel), "public/crushleg/%s.mappings.json", VECS[mi]);
		if (wrt_json_load_vec(&j, rel) != 0) {
			WRT_CHECK(0);
			cm_free(&m);
			continue;
		}
		run_vector(VECS[mi], m.c, &j, &vr, 0);
		WRT_CHECK(vr.bad == 0);
		total += vr.cmp - vr.unsup;
		printf("%-28s %3lu runs, %6lu mappings: %6lu equal, %5lu refused (%lu runs), %lu wrong\n", VECS[mi], vr.runs, vr.cmp, vr.cmp - vr.unsup - vr.bad,
		       vr.unsup, vr.unsup_runs, vr.bad);
		if (mi == 1) { /* jewel, large buckets: exactly the runs on 257 and 300 uniform items are refused, every one of their x */
			WRT_CHECK(vr.unsup_runs == 4);
			WRT_CHECK(vr.unsup == 4u * 64u);
			WRT_CHECK(vr.cmp - vr.unsup == 8u * 64u);
		} else {
			WRT_CHECK(vr.unsup == 0);
		}
		/* the fallback tunable switched off in a copy: the vectors must then disagree, so they do reach the permutation */
		if (m.c->tun.choose_local_fallback_tries > 0u) {
			cmap cp;

			cp.used = m.used;
			cp.room = (uint8_t *)malloc(m.used);
			if (cp.room == NULL)
				abort();
			memcpy(cp.room, m.room, m.used);
			cp.c = (wri_crush *)(void *)cp.room;
			cp.c->tun.choose_local_fallback_tries = 0;
			run_vector(VECS[mi], cp.c, &j, &vr0, 1);
			printf("%-28s fallback off: %lu of %lu mappings differ\n", "", vr0.bad, vr0.cmp);
			WRT_CHECK(vr0.bad > 50);
			free(cp.room);
		}
		wrt_json_free(&j);
		cm_free(&m);
	}
	WRT_CHECK(total > 10000);
}

/* ---- every list and uniform bucket of the vector maps against the references ----------------------------------- */

static void check_decoded_buckets(void)
{
	size_t mi;
	unsigned long nl = 0, nu = 0, calls = 0;

	for (mi = 0; mi < N_VECS; mi++) {
		char rel[256];
		cmap m;
		uint32_t slot;

		snprintf(rel, sizeof(rel), "public/crushleg/%s.crush.hex", VECS[mi]);
		if (cm_load(&m, rel) != 0) {
			WRT_CHECK(0);
			continue;
		}
		for (slot = 0; slot < m.c->max_buckets; slot++) {
			const wri_cbucket *b = wri_crush_bucket_at(m.c, slot);
			uint16_t perm[WRI_CRUSH_PERM_MAX];
			uint32_t x, r;

			if (b == NULL || b->size == 0u)
				continue;
			if (b->alg == WRI_CRUSH_ALG_LIST) {
				nl++;
				for (x = 0; x < 48; x++)
					for (r = 0; r < 24; r++) {
						int32_t got = 0;

						WRT_CHECK_STATUS(WR_OK, wri_crush_choose_list(b, x * 131u, r, &got));
						WRT_CHECK(got == ref_list(b->size, wri_cbucket_items(b), wri_cbucket_w(b), wri_cbucket_sums(b), b->id, x * 131u, r));
						calls++;
					}
			}
			if (b->alg == WRI_CRUSH_ALG_LIST || b->alg == WRI_CRUSH_ALG_UNIFORM || b->alg == WRI_CRUSH_ALG_STRAW2 || b->alg == WRI_CRUSH_ALG_STRAW) {
				if (b->alg == WRI_CRUSH_ALG_UNIFORM)
					nu++;
				if (b->size > WRI_CRUSH_PERM_MAX) {
					int32_t got = 0;

					WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_choose_perm(b, 1, 1, perm, &got));
					continue;
				}
				for (x = 0; x < 48; x++)
					for (r = 0; r < 24; r++) {
						int32_t got = 0;

						WRT_CHECK_STATUS(WR_OK, wri_crush_choose_perm(b, x * 131u, r, perm, &got));
						WRT_CHECK(got == ref_perm(b->size, wri_cbucket_items(b), b->id, x * 131u, r));
						calls++;
					}
			}
		}
		cm_free(&m);
	}
	WRT_CHECK(nl >= 10 && nu >= 20);
	printf("decoded buckets: %lu list, %lu uniform, %lu chooser calls checked\n", nl, nu, calls);
}

/* ---- the rule audit ---------------------------------------------------------------------------------------------------- */

static void check_audit(void)
{
	cmap m;
	uint32_t rule;
	wr_errinfo why;

	/* legacy tunables, buckets up to 256 items: every rule of the flat map is accepted, and an audited rule maps */
	if (cm_load(&m, "public/crushleg/cl01-flat-legacy-choosers.crush.hex") != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(m.c->tun.choose_local_fallback_tries == 5u);
	for (rule = 0; rule < 13; rule++) {
		memset(&why, 0, sizeof(why));
		WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, rule, 3, &why));
	}
	cm_free(&m);

	/* jewel, large buckets: list of any size is fine, uniform of 257 or more is not */
	if (cm_load(&m, "public/crushleg/cl02-jewel-large-buckets.crush.hex") != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(&why, 0, sizeof(why));
	WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, 0, 3, &why)); /* list256 */
	WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, 1, 3, &why)); /* list300 */
	WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, 2, 3, &why)); /* uni256 */
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_audit_rule(m.c, 3, 3, &why)); /* uni257 */
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_audit_rule(m.c, 4, 3, &why)); /* uni300 */
	WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, 5, 3, &why)); /* straw2_300 */
	/* the fallback tunable on: any bucket above 256 items needs the permutation, so list300 and straw2_300 are refused too */
	m.c->tun.choose_local_fallback_tries = 5;
	WRT_CHECK_STATUS(WR_OK, wri_crush_audit_rule(m.c, 0, 3, &why));
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_audit_rule(m.c, 1, 3, &why));
	WRT_CHECK_STATUS(WR_E_CRUSH_UNSUPPORTED, wri_crush_audit_rule(m.c, 5, 3, &why));
	WRT_CHECK(why.what != NULL);
	/* and an accepted rule never ends in UNSUPPORTED while mapping */
	{
		uint32_t w[300], x, i, n = 0;
		int32_t res[WRI_CRUSH_RESULT_MAX];
		wri_crush_ws ws;
		wri_crush_in in;

		for (i = 0; i < 300; i++)
			w[i] = (i % 3u) ? W_IN : 0u;
		for (rule = 0; rule < 3; rule++) {
			for (x = 0; x < 200; x++) {
				memset(&ws, 0, sizeof(ws));
				ws.work = WORK_BIG;
				in.rule = rule;
				in.x = x;
				in.result_max = 3;
				in.osd_weight = w;
				in.weight_max = 300;
				in.args_pool = 0;
				WRT_CHECK_STATUS(WR_OK, wri_crush_do_rule(m.c, &in, &ws, res, &n, NULL));
			}
		}
	}
	cm_free(&m);
}

/* ---- the in-tree crushtool known answers (optional) ------------------------------------------------------------- */

typedef struct tcase {
	char map[600];
	int have_rule;
	uint32_t rule, minrep;
	int nw;
	uint32_t wdev[64], wval[64];
	int64_t set[6]; /* local tries, local fallback tries, total tries, descend once, vary_r, stable; -1 = not given */
} tcase;

typedef struct texp {
	uint32_t nr, x, rule, n;
	int32_t res[WRI_CRUSH_RESULT_MAX];
} texp;

/* The first command of a cram-style .t file and the mappings it prints. */
static int parse_t_file(const char *path, const char *testdir, tcase *tc, texp **out, size_t *nout)
{
	uint8_t *txt;
	size_t n, pos = 0, cnt = 0, cap = 0;
	int seen_cmd = 0, have_last = 0, s;
	uint32_t lastx = 0, nr = 0;
	texp *ex = NULL;

	if (wrt_read_file(path, &txt, &n) != 0)
		return -1;
	memset(tc, 0, sizeof(*tc));
	tc->minrep = 1;
	for (s = 0; s < 6; s++)
		tc->set[s] = -1;
	while (pos < n) {
		size_t eol = pos, len;
		char line[4096];

		while (eol < n && txt[eol] != '\n')
			eol++;
		len = eol - pos;
		if (len >= sizeof(line))
			len = sizeof(line) - 1u;
		memcpy(line, txt + pos, len);
		line[len] = 0;
		pos = eol + 1u;
		if (strncmp(line, "  $ ", 4) == 0) {
			char *tok[96], *p = line + 4;
			int nt = 0, ti;

			if (seen_cmd)
				break;
			seen_cmd = 1;
			while (*p != 0 && nt < 96) {
				while (*p == ' ')
					p++;
				if (*p == 0)
					break;
				tok[nt++] = p;
				while (*p != 0 && *p != ' ')
					p++;
				if (*p != 0)
					*p++ = 0;
			}
			for (ti = 1; ti < nt; ti++) {
				const char *t = tok[ti];

				if (strcmp(t, "-i") == 0 && ti + 1 < nt) {
					const char *mp = tok[ti + 1], *td;

					if (mp[0] == '"')
						mp++;
					td = strstr(mp, "$TESTDIR");
					if (td != NULL) {
						size_t tail = strlen(td + 8);
						char *q;

						snprintf(tc->map, sizeof(tc->map), "%s%s", testdir, td + 8);
						q = tc->map + strlen(tc->map);
						if (tail > 0 && q[-1] == '"')
							q[-1] = 0;
					} else {
						snprintf(tc->map, sizeof(tc->map), "%s", mp);
					}
					ti++;
				} else if (strcmp(t, "--rule") == 0 && ti + 1 < nt) {
					tc->have_rule = 1;
					tc->rule = (uint32_t)strtoul(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--weight") == 0 && ti + 2 < nt) {
					if (tc->nw < 64) {
						tc->wdev[tc->nw] = (uint32_t)strtoul(tok[ti + 1], NULL, 10);
						tc->wval[tc->nw] = (uint32_t)(strtod(tok[ti + 2], NULL) * 65536.0);
						tc->nw++;
					}
					ti += 2;
				} else if ((strcmp(t, "--min-rep") == 0 || strcmp(t, "--num-rep") == 0) && ti + 1 < nt) {
					tc->minrep = (uint32_t)strtoul(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-choose-local-tries") == 0 && ti + 1 < nt) {
					tc->set[0] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-choose-local-fallback-tries") == 0 && ti + 1 < nt) {
					tc->set[1] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-choose-total-tries") == 0 && ti + 1 < nt) {
					tc->set[2] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-descend-once") == 0 && ti + 1 < nt) {
					tc->set[3] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-vary-r") == 0 && ti + 1 < nt) {
					tc->set[4] = strtol(tok[++ti], NULL, 10);
				} else if (strcmp(t, "--set-chooseleaf-stable") == 0 && ti + 1 < nt) {
					tc->set[5] = strtol(tok[++ti], NULL, 10);
				}
			}
			continue;
		}
		if (strncmp(line, "  CRUSH rule ", 13) == 0) {
			unsigned rr, xx;
			const char *lb = strchr(line, '[');
			texp e;

			if (sscanf(line, "  CRUSH rule %u x %u", &rr, &xx) != 2 || lb == NULL)
				continue;
			if (!have_last || xx <= lastx)
				nr++;
			have_last = 1;
			lastx = xx;
			e.nr = nr + tc->minrep - 1u;
			e.x = xx;
			e.rule = rr;
			e.n = 0;
			lb++;
			while (*lb != ']' && *lb != 0) {
				long v = strtol(lb, (char **)&lb, 10);

				if (e.n < WRI_CRUSH_RESULT_MAX)
					e.res[e.n++] = (int32_t)v;
				while (*lb == ',' || *lb == ' ')
					lb++;
			}
			if (cnt == cap) {
				cap = cap ? cap * 2u : 4096u;
				ex = (texp *)realloc(ex, cap * sizeof(texp));
				if (ex == NULL)
					abort();
			}
			ex[cnt++] = e;
		}
	}
	free(txt);
	*out = ex;
	*nout = cnt;
	return seen_cmd ? 0 : -1;
}

static void check_tree_known_answers(void)
{
	static const char *const files[] = {"test-map-legacy-tunables.t", "test-map-bobtail-tunables.t", "test-map-firefly-tunables.t",
					    "test-map-hammer-tunables.t", "test-map-jewel-tunables.t", "test-map-tries-vs-retries.t",
					    "test-map-vary-r-0.t", "test-map-vary-r-1.t", "test-map-vary-r-2.t", "test-map-vary-r-3.t",
					    "test-map-vary-r-4.t"};
	const char *src = getenv("WINRBD_CEPH_SRC");
	char testdir[512];
	uint32_t xmax = 128;
	unsigned long ok = 0, nfiles = 0, refused = 0;
	size_t fi;

	if (src == NULL || *src == 0) {
		printf("in-tree crushtool known answers: skipped (WINRBD_CEPH_SRC not set)\n");
		return;
	}
	if (getenv("WRT_CRUSH_TREE_X") != NULL)
		xmax = (uint32_t)strtoul(getenv("WRT_CRUSH_TREE_X"), NULL, 10);
	snprintf(testdir, sizeof(testdir), "%s/src/test/cli/crushtool", src);
	for (fi = 0; fi < sizeof(files) / sizeof(files[0]); fi++) {
		char path[700];
		tcase tc;
		texp *ex = NULL;
		size_t nex = 0, i, bn;
		uint8_t *blob;
		cmap m;
		uint32_t *w, nd, rule, slot;
		uint8_t *inb;
		int s;
		wr_errinfo why;

		snprintf(path, sizeof(path), "%s/%s", testdir, files[fi]);
		if (parse_t_file(path, testdir, &tc, &ex, &nex) != 0 || nex == 0) {
			printf("in-tree crushtool known answers: %s missing or empty, skipped\n", files[fi]);
			free(ex);
			continue;
		}
		if (wrt_read_file(tc.map, &blob, &bn) != 0) {
			printf("in-tree crushtool known answers: %s missing, skipped\n", tc.map);
			free(ex);
			continue;
		}
		memset(&m, 0, sizeof(m));
		memset(&why, 0, sizeof(why));
		m.room = (uint8_t *)malloc(bn * 4u + 65536u);
		if (m.room == NULL || wri_crush_decode(blob, bn, m.room, bn * 4u + 65536u, &m.used, &why) != WR_OK) {
			fprintf(stderr, "%s: decode failed: %s\n", tc.map, why.what ? why.what : "?");
			WRT_CHECK(0);
			free(m.room);
			free(blob);
			free(ex);
			continue;
		}
		free(blob);
		m.c = (wri_crush *)(void *)m.room;
		for (s = 0; s < 6; s++) {
			uint32_t v;

			if (tc.set[s] < 0)
				continue;
			v = (uint32_t)tc.set[s];
			switch (s) {
			case 0: m.c->tun.choose_local_tries = v; break;
			case 1: m.c->tun.choose_local_fallback_tries = v; break;
			case 2: m.c->tun.choose_total_tries = v; break;
			case 3: m.c->tun.chooseleaf_descend_once = v; break;
			case 4: m.c->tun.chooseleaf_vary_r = (uint8_t)v; break;
			default: m.c->tun.chooseleaf_stable = (uint8_t)v; break;
			}
		}
		nd = (uint32_t)m.c->max_devices;
		w = (uint32_t *)calloc(nd ? nd : 1u, sizeof(uint32_t));
		inb = (uint8_t *)calloc(nd ? nd : 1u, 1);
		for (slot = 0; slot < m.c->max_buckets; slot++) {
			const wri_cbucket *b = wri_crush_bucket_at(m.c, slot);
			uint32_t k;

			for (k = 0; b != NULL && k < b->size; k++)
				if (wri_cbucket_items(b)[k] >= 0 && (uint32_t)wri_cbucket_items(b)[k] < nd)
					inb[wri_cbucket_items(b)[k]] = 1;
		}
		for (i = 0; i < nd; i++)
			w[i] = inb[i] ? W_IN : 0u;
		for (i = 0; i < (size_t)tc.nw; i++)
			if (tc.wdev[i] < nd)
				w[tc.wdev[i]] = tc.wval[i];
		rule = tc.have_rule ? tc.rule : ex[0].rule;
		for (i = 0; i < nex; i++) {
			int32_t got[WRI_CRUSH_RESULT_MAX];
			uint32_t ng = 0;
			wri_crush_ws ws;
			wri_crush_in in;
			wr_status st;

			if (ex[i].rule != rule || ex[i].x >= xmax)
				continue;
			memset(&ws, 0, sizeof(ws));
			ws.work = WORK_BIG;
			in.rule = rule;
			in.x = ex[i].x;
			in.result_max = ex[i].nr;
			in.osd_weight = w;
			in.weight_max = nd;
			in.args_pool = 0;
			st = wri_crush_do_rule(m.c, &in, &ws, got, &ng, NULL);
			wrt_checks++;
			if (st == WR_OK && eq_list(got, ng, ex[i].res, ex[i].n)) {
				ok++;
			} else if (st == WR_E_CRUSH_UNSUPPORTED) {
				refused++; /* a tree bucket or an indep rule: not this module's */
			} else {
				char a[160], b[160];

				wrt_failures++;
				fmt_list(a, sizeof(a), got, st == WR_OK ? ng : 0u);
				fmt_list(b, sizeof(b), ex[i].res, ex[i].n);
				fprintf(stderr, "%s: rule %u x %u numrep %u: status %d got [%s] want [%s]\n", files[fi], rule, ex[i].x, ex[i].nr, (int)st, a, b);
			}
		}
		nfiles++;
		free(w);
		free(inb);
		free(ex);
		free(m.room);
	}
	printf("in-tree crushtool known answers: %lu files, %lu mappings equal, %lu refused (tree / indep)\n", nfiles, ok, refused);
	WRT_CHECK(nfiles == 0 || nfiles == sizeof(files) / sizeof(files[0]));
}

int main(void)
{
	bkbuf = (uint32_t *)calloc(4u + 3u * (size_t)BK_MAX + 8u, sizeof(uint32_t));
	if (bkbuf == NULL)
		abort();
	check_permutation();
	check_perm_any_algorithm();
	check_limits_and_args();
	check_list();
	check_uniform_flat();
	check_vectors();
	check_decoded_buckets();
	check_audit();
	check_tree_known_answers();
	free(bkbuf);
	return wrt_finish();
}
