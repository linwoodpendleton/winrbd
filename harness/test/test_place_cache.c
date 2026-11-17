/* SPDX-License-Identifier: MIT */
/*
 * test_place_cache.c - the placement cache (core/src/osdmap/wri_place_cache.c).
 *
 *  - sizes: bytes for n entries, init zeroes whatever memory it is given, a cache with no memory / n of 0 / misaligned
 *    memory is disabled and counts misses;
 *  - hit and miss: what a hit returns (sets and primaries, no raw set, no pps, a clean tail), a different key and a different
 *    epoch miss, epoch 0 never hits and never stores, a NULL out is a probe, counts above the array size are clamped;
 *  - init clears exactly n entries and a put stays inside the table, a get never writes an entry, clear empties the table;
 *  - an epoch change misses every entry, and the new epoch's results replace the old ones one by one;
 *  - conflicts: n of 1 (everything collides), colliding keys found by search at other sizes, the newest wins and the older
 *    key misses, a second put of the same key replaces the data;
 *  - sizes of 0, 1, 2, a non-power-of-two and a large n: no key ever returns another key's data, no more distinct keys hit than
 *    there are entries, and neighbouring seeds of one pool spread over the entries;
 *  - a long random sequence on real placements (random clusters with upmaps, temps, affinity, down and out OSDs, four maps of
 *    four different epochs interleaved so epoch changes happen all the time): the cached path (get, else compute and put)
 *    returns exactly what uncached wri_place_pg returns, for cache sizes from 1 to 1000;
 *  - counters: hits + misses is the number of lookups, always.
 *
 * Each cache lives in an exact-size heap block so that AddressSanitizer sees any access past the n-th entry.
 */
#include "place_rig.h"

#define WORK 1000000u

static wrt_mg_rng rng;
static wri_crush_ws ws;

static uint32_t below(uint32_t n)
{
	return wrt_mg_rng_below(&rng, n);
}

/* ---- helpers ------------------------------------------------------------------------------------------------- */

typedef struct tc {
	wri_pgcache c;
	void *mem;
	size_t bytes;
} tc;

/* A cache of n entries in an exact-size block pre-filled with garbage (init must clear it). */
static void tc_open(tc *t, uint32_t n)
{
	t->bytes = wri_pgcache_bytes(n);
	t->mem = t->bytes != 0 ? malloc(t->bytes) : NULL;
	if (t->bytes != 0 && t->mem == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (t->mem != NULL)
		memset(t->mem, 0xA5, t->bytes);
	wri_pgcache_init(&t->c, t->mem, n);
}

static void tc_close(tc *t)
{
	free(t->mem);
	t->mem = NULL;
}

/* A recognisable result derived from a tag: different tags give different sets. */
static wri_pg_result mkres(uint32_t tag)
{
	wri_pg_result r;
	uint32_t i;

	memset(&r, 0, sizeof(r));
	r.pps = 0x70707073u ^ tag;
	r.n_raw = 3;
	r.n_up = (uint8_t)(1u + tag % 3u);
	r.n_acting = (uint8_t)(tag % 4u);
	for (i = 0; i < WRI_REP_MAX; i++) {
		r.raw[i] = (int32_t)(tag * 7u + i);
		r.up[i] = i < r.n_up ? (int32_t)(tag * 3u + i) : 0;
		r.acting[i] = i < r.n_acting ? (int32_t)(tag * 5u + i) : 0;
	}
	r.up_primary = (int32_t)(tag * 3u);
	r.acting_primary = r.n_acting != 0 ? (int32_t)(tag * 5u) : -1;
	return r;
}

/* Everything a hit must reproduce of `want`, and the fields a hit does not carry. */
static int same_cached(const wri_pg_result *got, const wri_pg_result *want)
{
	uint32_t i;

	if (got->n_up != want->n_up || got->n_acting != want->n_acting || got->up_primary != want->up_primary ||
	    got->acting_primary != want->acting_primary)
		return 0;
	for (i = 0; i < want->n_up; i++)
		if (got->up[i] != want->up[i])
			return 0;
	for (i = 0; i < want->n_acting; i++)
		if (got->acting[i] != want->acting[i])
			return 0;
	return got->n_raw == 0 && got->pps == 0;
}

static uint64_t key_of(uint32_t pool, uint32_t seed)
{
	return wri_pg_key(pool, seed);
}

/* ---- tests --------------------------------------------------------------------------------------------------- */

static void t_sizes(void)
{
	tc t;
	void *p;
	wri_pgcache c;
	wri_pg_result r = mkres(1), o;

	WRT_CHECK_U64(sizeof(wri_pgc_entry), 8u + 4u + 4u + 8u * WRI_REP_MAX + 8u); /* the 152 bytes of the design for WRI_REP_MAX 16 */
	WRT_CHECK_U64(wri_pgcache_bytes(0), 0);
	WRT_CHECK_U64(wri_pgcache_bytes(1), sizeof(wri_pgc_entry));
	WRT_CHECK_U64(wri_pgcache_bytes(100), 100u * sizeof(wri_pgc_entry));
	WRT_CHECK_U64(wri_pgcache_bytes(0xffffffffu), (size_t)0xffffffffu * sizeof(wri_pgc_entry));

	/* init zeroes what it is given and starts the counters at 0 */
	tc_open(&t, 16);
	WRT_CHECK(t.c.e == (wri_pgc_entry *)t.mem && t.c.n == 16 && t.c.hits == 0 && t.c.misses == 0);
	{
		uint32_t i;
		int clean = 1;

		for (i = 0; i < 16; i++)
			clean &= t.c.e[i].epoch == 0 && t.c.e[i].key == 0 && t.c.e[i].n_up == 0;
		WRT_CHECK(clean);
	}
	WRT_CHECK(wri_pgcache_get(&t.c, 1, 0, &o) == 0); /* an empty cache has no key 0 either */
	tc_close(&t);

	/* a cache with no memory, n of 0 or a misaligned block is disabled: every lookup misses */
	p = malloc(4096);
	memset(&c, 0xEE, sizeof(c));
	wri_pgcache_init(&c, NULL, 8);
	WRT_CHECK(c.e == NULL && c.n == 0 && c.hits == 0 && c.misses == 0);
	wri_pgcache_put(&c, 1, 1, &r);
	WRT_CHECK(wri_pgcache_get(&c, 1, 1, &o) == 0 && c.misses == 1 && c.hits == 0);
	wri_pgcache_init(&c, p, 0);
	WRT_CHECK(c.e == NULL && c.n == 0);
	wri_pgcache_put(&c, 1, 1, &r);
	WRT_CHECK(wri_pgcache_get(&c, 1, 1, &o) == 0 && c.misses == 1);
	wri_pgcache_init(&c, (uint8_t *)p + 4, 4); /* 4 mod 8: the contract is 8-byte aligned memory */
	WRT_CHECK(c.e == NULL && c.n == 0);
	WRT_CHECK(wri_pgcache_get(&c, 1, 1, &o) == 0);
	free(p);

	/* NULL arguments do nothing and do not crash */
	wri_pgcache_init(NULL, NULL, 0);
	wri_pgcache_put(NULL, 1, 1, &r);
	WRT_CHECK(wri_pgcache_get(NULL, 1, 1, &o) == 0);
	tc_open(&t, 4);
	wri_pgcache_put(&t.c, 1, 1, NULL);
	WRT_CHECK(wri_pgcache_get(&t.c, 1, 1, &o) == 0);
	tc_close(&t);
}

static void t_hit_miss(void)
{
	tc t;
	wri_pg_result r, o, big;
	uint32_t i;

	tc_open(&t, 64);
	r = mkres(5);
	r.acting_primary = 42; /* e.g. from a primary_temp that is not in the set */

	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 9), &o) == 0);
	wri_pgcache_put(&t.c, 7, key_of(3, 9), &r);
	memset(&o, 0x55, sizeof(o));
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 9), &o) == 1);
	WRT_CHECK(same_cached(&o, &r));
	WRT_CHECK_U64(o.n_raw, 0);
	WRT_CHECK_U64(o.pps, 0);
	WRT_CHECK_U64(o.reserved, 0);
	for (i = 0; i < WRI_REP_MAX; i++) { /* the part of each list beyond its count is zero, whatever out held before */
		WRT_CHECK(o.raw[i] == 0);
		WRT_CHECK(i < o.n_up || o.up[i] == 0);
		WRT_CHECK(i < o.n_acting || o.acting[i] == 0);
	}
	WRT_CHECK_U64(o.acting_primary, 42);

	/* other key, same epoch / same key, other epoch / epoch 0 */
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 10), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(4, 9), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 8, key_of(3, 9), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 6, key_of(3, 9), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 0, key_of(3, 9), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 9), &o) == 1); /* and the entry is still there after all the misses */
	WRT_CHECK(same_cached(&o, &r));

	/* epoch 0 is the empty marker: a put under it stores nothing */
	wri_pgcache_put(&t.c, 0, key_of(1, 1), &r);
	WRT_CHECK(wri_pgcache_get(&t.c, 0, key_of(1, 1), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 1, key_of(1, 1), &o) == 0);

	/* a NULL out is a probe: answers and counts, writes nothing */
	{
		uint32_t h = t.c.hits, m = t.c.misses;

		WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 9), NULL) == 1);
		WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(3, 11), NULL) == 0);
		WRT_CHECK(t.c.hits == h + 1 && t.c.misses == m + 1);
	}

	/* empty sets and a -1 primary survive the round trip; a result of 0 / 0 is a result like any other */
	memset(&r, 0, sizeof(r));
	r.up_primary = -1;
	r.acting_primary = -1;
	wri_pgcache_put(&t.c, 7, key_of(2, 2), &r);
	memset(&o, 0x55, sizeof(o));
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(2, 2), &o) == 1);
	WRT_CHECK(same_cached(&o, &r) && o.n_up == 0 && o.n_acting == 0 && o.up_primary == -1 && o.acting_primary == -1);

	/* a result claiming more members than the arrays hold is cut, not read past the array */
	big = mkres(3);
	big.n_up = 255;
	big.n_acting = 200;
	wri_pgcache_put(&t.c, 7, key_of(2, 3), &big);
	WRT_CHECK(wri_pgcache_get(&t.c, 7, key_of(2, 3), &o) == 1);
	WRT_CHECK_U64(o.n_up, WRI_REP_MAX);
	WRT_CHECK_U64(o.n_acting, WRI_REP_MAX);
	for (i = 0; i < WRI_REP_MAX; i++)
		WRT_CHECK(o.up[i] == big.up[i] && o.acting[i] == big.acting[i]);

	/* the largest and the odd keys: pool ids and seeds with the high bits set */
	r = mkres(9);
	wri_pgcache_put(&t.c, 0xffffffffu, key_of(0xffffffffu, 0xffffffffu), &r);
	WRT_CHECK(wri_pgcache_get(&t.c, 0xffffffffu, key_of(0xffffffffu, 0xffffffffu), &o) == 1 && same_cached(&o, &r));
	wri_pgcache_put(&t.c, 1, 0, &r); /* key 0 under epoch 1 */
	WRT_CHECK(wri_pgcache_get(&t.c, 1, 0, &o) == 1 && same_cached(&o, &r));
	tc_close(&t);
}

/* The entries themselves: what a put leaves in the table, and what a get does with an entry it should not trust. */
static void t_entries(void)
{
	tc t;
	wri_pg_result big = mkres(3), small = mkres(0), o;
	uint32_t i;

	tc_open(&t, 1);
	/* a short result over a full one leaves nothing of the old members behind (no stale tail in the entry) */
	big.n_up = WRI_REP_MAX;
	big.n_acting = WRI_REP_MAX;
	for (i = 0; i < WRI_REP_MAX; i++) {
		big.up[i] = 100 + (int32_t)i;
		big.acting[i] = 200 + (int32_t)i;
	}
	wri_pgcache_put(&t.c, 5, key_of(1, 1), &big);
	memset(&small, 0, sizeof(small));
	small.n_up = 1;
	small.up[0] = 7;
	small.up_primary = 7;
	small.acting_primary = -1;
	wri_pgcache_put(&t.c, 5, key_of(1, 2), &small);
	for (i = 1; i < WRI_REP_MAX; i++)
		WRT_CHECK(t.c.e[0].up[i] == 0 && t.c.e[0].acting[i] == 0);
	WRT_CHECK(t.c.e[0].acting[0] == 0 && t.c.e[0].n_acting == 0 && t.c.e[0].reserved[0] == 0 && t.c.e[0].reserved[1] == 0);

	/* a put under epoch 0 must not evict a valid entry (every key collides at n == 1) */
	wri_pgcache_put(&t.c, 0, key_of(1, 3), &big);
	WRT_CHECK(wri_pgcache_get(&t.c, 5, key_of(1, 2), &o) && o.n_up == 1 && o.up[0] == 7);

	/* an entry whose counts were damaged in memory is read cut to the array size, not past it */
	t.c.e[0].n_up = 255;
	t.c.e[0].n_acting = 255;
	WRT_CHECK(wri_pgcache_get(&t.c, 5, key_of(1, 2), &o) == 1);
	WRT_CHECK_U64(o.n_up, WRI_REP_MAX);
	WRT_CHECK_U64(o.n_acting, WRI_REP_MAX);
	tc_close(&t);
}

/* init touches exactly the n entries; get never writes an entry; clear empties the table and keeps the counters. */
static void t_clear_and_bounds(void)
{
	enum { N = 8, SLACK = 64 };
	uint8_t *blk, *snap;
	size_t bytes = wri_pgcache_bytes(N);
	wri_pgcache c;
	wri_pg_result r = mkres(4), o;
	uint32_t k, hits;

	blk = (uint8_t *)malloc(bytes + SLACK);
	snap = (uint8_t *)malloc(bytes);
	WRT_CHECK(blk != NULL && snap != NULL);
	if (blk == NULL || snap == NULL) {
		free(blk);
		free(snap);
		return;
	}
	memset(blk, 0x5A, bytes + SLACK);
	wri_pgcache_init(&c, blk, N);
	for (k = 0; k < SLACK; k++)
		WRT_CHECK(blk[bytes + k] == 0x5A); /* init cleared the entries and not one byte more */
	for (k = 0; k < 40; k++)
		wri_pgcache_put(&c, 3, key_of(1, k), &r);
	for (k = 0; k < SLACK; k++)
		WRT_CHECK(blk[bytes + k] == 0x5A); /* nor did a put reach past the table */
	memcpy(snap, blk, bytes);
	for (k = 0; k < 80; k++)
		(void)wri_pgcache_get(&c, k % 2u ? 3u : 4u, key_of(1, k), k % 3u ? &o : NULL);
	WRT_CHECK(memcmp(snap, blk, bytes) == 0); /* hits and misses leave the entries alone */

	hits = 0;
	for (k = 0; k < 40; k++)
		hits += (uint32_t)wri_pgcache_get(&c, 3, key_of(1, k), NULL);
	WRT_CHECK(hits >= 1);
	{
		uint32_t h = c.hits, m = c.misses;

		wri_pgcache_clear(&c);
		WRT_CHECK(c.hits == h && c.misses == m && c.n == N && c.e == (wri_pgc_entry *)blk);
		for (k = 0; k < 40; k++)
			WRT_CHECK(wri_pgcache_get(&c, 3, key_of(1, k), NULL) == 0);
		for (k = 0; k < SLACK; k++)
			WRT_CHECK(blk[bytes + k] == 0x5A);
		for (k = 0; k < N; k++)
			WRT_CHECK(c.e[k].epoch == 0 && c.e[k].n_up == 0 && c.e[k].key == 0);
	}
	wri_pgcache_put(&c, 3, key_of(1, 1), &r); /* usable again after a clear */
	WRT_CHECK(wri_pgcache_get(&c, 3, key_of(1, 1), &o) == 1 && same_cached(&o, &r));

	/* clear on a disabled cache and on NULL does nothing */
	wri_pgcache_clear(NULL);
	wri_pgcache_init(&c, NULL, 4);
	wri_pgcache_clear(&c);
	WRT_CHECK(c.e == NULL && c.n == 0);
	free(blk);
	free(snap);
}

static void t_epoch(void)
{
	enum { N = 64, K = 300 };
	tc t;
	uint32_t k, hits5 = 0, hits6 = 0, same;
	wri_pg_result r, o;

	tc_open(&t, N);
	for (k = 0; k < K; k++) {
		r = mkres(k);
		wri_pgcache_put(&t.c, 5, key_of(1, k), &r);
	}
	for (k = 0; k < K; k++) {
		r = mkres(k);
		if (wri_pgcache_get(&t.c, 5, key_of(1, k), &o)) {
			hits5++;
			WRT_CHECK(same_cached(&o, &r));
		}
	}
	WRT_CHECK(hits5 > 0 && hits5 <= N);
	/* the next epoch: every one of the keys misses, for any key, and so does epoch 4, and nothing changed in the entries */
	for (k = 0; k < K; k++) {
		WRT_CHECK(wri_pgcache_get(&t.c, 6, key_of(1, k), &o) == 0);
		WRT_CHECK(wri_pgcache_get(&t.c, 4, key_of(1, k), &o) == 0);
		WRT_CHECK(wri_pgcache_get(&t.c, 0xffffffffu, key_of(1, k), &o) == 0);
	}
	/* a fresh epoch needs no flush: store under 6 and the old epoch's entries are replaced on the way, never mixed */
	for (k = 0; k < K; k += 2) {
		r = mkres(k + 1000u);
		wri_pgcache_put(&t.c, 6, key_of(1, k), &r);
	}
	for (k = 0; k < K; k++) {
		if (wri_pgcache_get(&t.c, 6, key_of(1, k), &o)) {
			r = mkres(k + 1000u);
			WRT_CHECK((k & 1u) == 0 && same_cached(&o, &r));
			hits6++;
		}
	}
	WRT_CHECK(hits6 > 0 && hits6 <= N);
	same = 0;
	for (k = 0; k < K; k++)
		if (wri_pgcache_get(&t.c, 5, key_of(1, k), &o)) {
			r = mkres(k);
			WRT_CHECK(same_cached(&o, &r));
			same++;
		}
	WRT_CHECK(same + hits6 <= N); /* an entry holds one epoch: the two epochs share the table, not add up */
	tc_close(&t);
}

static void t_conflict(void)
{
	tc t;
	wri_pg_result a = mkres(11), b = mkres(22), c = mkres(33), o;
	uint32_t n, k, found;

	/* n == 1: every key collides */
	tc_open(&t, 1);
	wri_pgcache_put(&t.c, 3, key_of(1, 1), &a);
	WRT_CHECK(wri_pgcache_get(&t.c, 3, key_of(1, 1), &o) && same_cached(&o, &a));
	wri_pgcache_put(&t.c, 3, key_of(1, 2), &b);
	WRT_CHECK(wri_pgcache_get(&t.c, 3, key_of(1, 2), &o) && same_cached(&o, &b));
	WRT_CHECK(wri_pgcache_get(&t.c, 3, key_of(1, 1), &o) == 0); /* replaced */
	wri_pgcache_put(&t.c, 4, key_of(1, 2), &c); /* the same key under a newer epoch replaces too */
	WRT_CHECK(wri_pgcache_get(&t.c, 3, key_of(1, 2), &o) == 0);
	WRT_CHECK(wri_pgcache_get(&t.c, 4, key_of(1, 2), &o) && same_cached(&o, &c));
	wri_pgcache_put(&t.c, 4, key_of(1, 2), &a); /* and the same key and epoch again: the data are replaced */
	WRT_CHECK(wri_pgcache_get(&t.c, 4, key_of(1, 2), &o) && same_cached(&o, &a));
	tc_close(&t);

	/* other sizes: find a key that collides with key (9, 9) by search, then check the replacement both ways */
	{
		static const uint32_t sizes[] = {2, 3, 8, 16, 100, 128, 1000};

		for (n = 0; n < sizeof(sizes) / sizeof(sizes[0]); n++) {
			tc_open(&t, sizes[n]);
			wri_pgcache_put(&t.c, 2, key_of(9, 9), &a);
			found = 0;
			for (k = 0; k < 100000u && !found; k++) {
				if (k == 9)
					continue;
				wri_pgcache_put(&t.c, 2, key_of(9, k), &b);
				if (wri_pgcache_get(&t.c, 2, key_of(9, 9), &o) == 0) {
					found = 1;
					WRT_CHECK(wri_pgcache_get(&t.c, 2, key_of(9, k), &o) && same_cached(&o, &b));
					/* back again: the older key replaces the newer one */
					wri_pgcache_put(&t.c, 2, key_of(9, 9), &a);
					WRT_CHECK(wri_pgcache_get(&t.c, 2, key_of(9, 9), &o) && same_cached(&o, &a));
					WRT_CHECK(wri_pgcache_get(&t.c, 2, key_of(9, k), &o) == 0);
				} else {
					wri_pgcache_put(&t.c, 2, key_of(9, 9), &a); /* no collision yet: restore and try the next key */
				}
			}
			WRT_CHECK(found);
			tc_close(&t);
		}
	}
	/* the same seed of two pools and the same pool id with two seeds are different keys, whichever entry they land in */
	tc_open(&t, 4096);
	wri_pgcache_put(&t.c, 2, key_of(1, 7), &a);
	wri_pgcache_put(&t.c, 2, key_of(7, 1), &b);
	WRT_CHECK(wri_pgcache_get(&t.c, 2, key_of(1, 7), &o) && same_cached(&o, &a));
	WRT_CHECK(wri_pgcache_get(&t.c, 2, key_of(7, 1), &o) && same_cached(&o, &b));
	tc_close(&t);
}

static void t_n_sizes(void)
{
	static const uint32_t sizes[] = {0, 1, 2, 3, 5, 6, 7, 31, 64, 100, 1000, 4099};
	uint32_t s;

	for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
		uint32_t n = sizes[s], k, hits = 0, keys = 3u * n + 40u, h0, m0;
		tc t;
		wri_pg_result o;

		tc_open(&t, n);
		for (k = 0; k < keys; k++) {
			wri_pg_result r = mkres(k);

			wri_pgcache_put(&t.c, 9, key_of(2, k), &r);
		}
		h0 = t.c.hits;
		m0 = t.c.misses;
		for (k = 0; k < keys; k++) {
			wri_pg_result r = mkres(k);

			if (wri_pgcache_get(&t.c, 9, key_of(2, k), &o)) {
				hits++;
				WRT_CHECK(same_cached(&o, &r)); /* a hit is that key's own data, never another key's */
			}
		}
		WRT_CHECK(hits <= n);
		WRT_CHECK(t.c.hits == h0 + hits && t.c.misses == m0 + (keys - hits));
		if (n == 0)
			WRT_CHECK(hits == 0);
		else
			WRT_CHECK(hits >= 1);
		if (n >= 64) /* spread: 3n sequential seeds of one pool should keep most of a random placement's survivors (~95 %) */
			WRT_CHECK(hits * 100u >= n * 80u);
		tc_close(&t);
	}

	/* neighbouring seeds of one pool, fewer than there are entries, must mostly keep their own entry (a power of two too) */
	{
		static const uint32_t ns[] = {64, 128, 1024, 1000};
		uint32_t q;

		for (q = 0; q < sizeof(ns) / sizeof(ns[0]); q++) {
			uint32_t n = ns[q], k, hits = 0;
			tc t;
			wri_pg_result o;

			tc_open(&t, n);
			for (k = 0; k < n / 2u; k++) {
				wri_pg_result r = mkres(k);

				wri_pgcache_put(&t.c, 1, key_of(5, k), &r);
			}
			for (k = 0; k < n / 2u; k++)
				if (wri_pgcache_get(&t.c, 1, key_of(5, k), &o))
					hits++;
			/* half a table of random placements keeps 1 - 1/4 of the keys on average (n/2 balls in n bins: ~88 %) */
			WRT_CHECK(hits * 100u >= (n / 2u) * 75u);
			tc_close(&t);
		}
	}
}

/* ---- the long random sequence ------------------------------------------------------------------------------- */

#define NMAPS 4u

typedef struct world {
	wrt_mg_map d[NMAPS];
	place_rig r[NMAPS];
	uint32_t epoch[NMAPS];
	int ok;
} world;

static void world_build(world *w)
{
	static const uint32_t pgn[] = {1, 3, 7, 8, 12, 16, 24, 32, 48, 63};
	uint32_t c, i;

	w->ok = 1;
	for (c = 0; c < NMAPS; c++) {
		wrt_mg_cluster_spec s;
		uint32_t n = 6u + below(40), pool_i;

		wrt_mg_cluster_spec_init(&s, n);
		s.osds_per_host = 1u + below(5);
		s.hosts_per_rack = below(3) == 0 ? 2u : 0u;
		s.n_classes = below(4) == 0 ? 1u + below(2) : 0u;
		s.weight_jitter = (int)below(2);
		s.n_pools = 1u + below(3);
		s.pg_num = pgn[below(sizeof(pgn) / sizeof(pgn[0]))];
		s.pool_size = 1u + below(4);
		s.up_pct = below(4) == 0 ? 30u + below(60) : 100u;
		s.out_pct = below(3) == 0 ? below(30) : 0u;
		s.n_upmap_items = below(s.pg_num / 2u + 1u);
		s.n_upmap = below(s.pg_num / 3u + 1u);
		s.n_pg_temp = below(s.pg_num / 3u + 1u);
		s.n_primary_temp = below(s.pg_num / 4u + 1u);
		s.n_upmap_primaries = below(s.pg_num / 4u + 1u);
		s.n_affinity = below(3) == 0 ? below(n / 2u + 1u) : 0u;
		w->epoch[c] = 100u + 17u * c + below(10); /* four different epochs */
		s.epoch = w->epoch[c];
		s.seed = rng.s ^ (uint64_t)(c + 1u);
		memset(&w->r[c], 0, sizeof(w->r[c]));
		if (wrt_mg_build_map(&w->d[c], &s) != 0) {
			WRT_CHECK(0);
			w->ok = 0;
			memset(&w->d[c], 0, sizeof(w->d[c]));
			continue;
		}
		for (pool_i = 0; pool_i < w->d[c].pools.n; pool_i++)
			WRT_MG_E(w->d[c].pools, wrt_mg_pool_ent, pool_i).p.crush_rule = 0;
		if (!rig_build(&w->r[c], &w->d[c], 1))
			w->ok = 0;
		for (i = 0; i < c; i++)
			WRT_CHECK(w->epoch[i] != w->epoch[c]);
	}
}

static void world_free(world *w)
{
	uint32_t c;

	for (c = 0; c < NMAPS; c++) {
		rig_free(&w->r[c]);
		wrt_mg_map_free(&w->d[c]);
	}
}

static int same_result(const wri_pg_result *a, const wri_pg_result *b)
{
	uint32_t i;

	if (a->n_up != b->n_up || a->n_acting != b->n_acting || a->up_primary != b->up_primary || a->acting_primary != b->acting_primary)
		return 0;
	for (i = 0; i < a->n_up; i++)
		if (a->up[i] != b->up[i])
			return 0;
	for (i = 0; i < a->n_acting; i++)
		if (a->acting[i] != b->acting[i])
			return 0;
	return 1;
}

static void t_random(void)
{
	static const uint32_t sizes[] = {1, 2, 3, 7, 16, 64, 100, 1000};
	static const uint32_t steps = 12000;
	uint32_t s, total_hits = 0, total_gets = 0, total_bad = 0, total_cmp = 0, round;
	world w;

	for (round = 0; round < 3; round++) {
		world_build(&w);
		if (!w.ok) {
			world_free(&w);
			continue;
		}
		for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
			tc t;
			uint32_t k, gets = 0;
			uint32_t hot_map[24], hot_pool[24], hot_seed[24];

			tc_open(&t, sizes[s]);
			for (k = 0; k < 24; k++) { /* a small hot set so that repeats (hits) happen at every cache size */
				hot_map[k] = below(NMAPS);
				hot_pool[k] = below(w.r[hot_map[k]].n_ids);
				hot_seed[k] = below(wri_map_pools(w.r[hot_map[k]].m)[hot_pool[k]].pg_num);
			}
			for (k = 0; k < steps; k++) {
				uint32_t mi, pi, seed;
				const wri_osdmap *m;
				const wri_map_pool *p;
				wri_pg_result got, want;
				uint64_t key;
				wr_status st;
				int hit;

				if (below(3) != 0) {
					uint32_t h = below(24);

					mi = hot_map[h];
					pi = hot_pool[h];
					seed = hot_seed[h];
				} else {
					mi = below(NMAPS);
					pi = below(w.r[mi].n_ids);
					seed = below(wri_map_pools(w.r[mi].m)[pi].pg_num);
				}
				m = w.r[mi].m;
				p = &wri_map_pools(m)[pi];
				key = key_of((uint32_t)p->id, seed);

				st = wri_place_pg(m, pi, seed, WORK, &ws, &want, NULL); /* uncached */
				memset(&got, 0x33, sizeof(got));
				hit = wri_pgcache_get(&t.c, m->epoch, key, &got);
				gets++;
				if (st != WR_OK) {
					/* nothing the cache could answer: a failing PG is never put, so it can never hit */
					WRT_CHECK(!hit);
					continue;
				}
				if (hit) {
					total_hits++;
					total_cmp++;
					if (!same_result(&got, &want) || got.n_raw != 0 || got.pps != 0) {
						total_bad++;
						if (total_bad < 6)
							fprintf(stderr, "%s:%d: cache size %u step %u map %u pool %u seed %u: hit differs from the uncached result\n",
								__FILE__, __LINE__, sizes[s], k, mi, pi, seed);
					}
				} else {
					wri_pgcache_put(&t.c, m->epoch, key, &want);
					WRT_CHECK(wri_pgcache_get(&t.c, m->epoch, key, &got) == 1); /* straight after a put the entry is there */
					gets++;
					WRT_CHECK(same_result(&got, &want));
				}
			}
			WRT_CHECK_U64(t.c.hits + t.c.misses, gets); /* counters add up */
			total_gets += gets;
			tc_close(&t);
		}
		world_free(&w);
	}
	WRT_CHECK(total_bad == 0);
	WRT_CHECK(total_hits > 1000);
	WRT_CHECK(total_gets > 100000);
	fprintf(stderr, "random: %u lookups, %u hits compared with the uncached result, %u differences\n", total_gets, total_cmp, total_bad);
}

/* ---- counters over a mixed workload ------------------------------------------------------------------------- */

static void t_counters(void)
{
	tc t;
	uint32_t k, gets = 0, hits = 0;
	wri_pg_result o;

	tc_open(&t, 10);
	for (k = 0; k < 5000; k++) {
		uint32_t seed = below(40), epoch = 1u + below(3);
		uint64_t key = key_of(below(2), seed);

		if (below(2)) {
			wri_pg_result r = mkres(seed);

			wri_pgcache_put(&t.c, epoch, key, &r); /* a put changes no counter */
		} else {
			hits += (uint32_t)wri_pgcache_get(&t.c, epoch, key, below(4) == 0 ? NULL : &o);
			gets++;
		}
		WRT_CHECK(t.c.hits + t.c.misses == gets && t.c.hits == hits);
	}
	WRT_CHECK(hits > 0 && hits < gets);
	tc_close(&t);
}

int main(void)
{
	wrt_mg_rng_seed(&rng, 0x706c6163655f63ull);
	t_sizes();
	t_hit_miss();
	t_entries();
	t_clear_and_bounds();
	t_epoch();
	t_conflict();
	t_n_sizes();
	t_counters();
	t_random();
	return wrt_finish();
}
