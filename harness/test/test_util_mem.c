/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of the memory building blocks (core/src/util/wri_mem.c): bump arena, index pool,
 * byte ring (the ring is checked against a plain byte-array model over 100k random operations).
 */
#include "wrt.h"
#include "wri_mem.h"

/* ---- arena -------------------------------------------------------------------------------- */

static void test_arena_basic(void)
{
	static uint8_t raw[1024 + 128];
	uint8_t *base = raw;
	wri_arena a;
	uint8_t *p, *q;
	size_t i, align;

	/* Start from a 64-aligned base so offsets are predictable. */
	while (((uintptr_t)base & 63u) != 0)
		base++;
	memset(raw, 0xFF, sizeof(raw));
	wri_arena_init(&a, base, 1024);
	WRT_CHECK_U64(wri_arena_left(&a), 1024);

	p = (uint8_t *)wri_arena_take(&a, 10, 1);
	WRT_CHECK(p == base);
	for (i = 0; i < 10; i++)
		WRT_CHECK_U64(p[i], 0); /* zeroed even though the region was 0xFF */
	q = (uint8_t *)wri_arena_take(&a, 5, 16);
	WRT_CHECK(q == base + 16);
	WRT_CHECK_U64(a.used, 21);
	WRT_CHECK_U64(base[10], 0xFF); /* the padding is not touched */
	q = (uint8_t *)wri_arena_take(&a, 1, 64);
	WRT_CHECK(q == base + 64);
	WRT_CHECK_U64(a.used, 65);

	/* every alignment is honoured on the real address, for every start offset */
	for (align = 1; align <= 64; align <<= 1) {
		size_t off;

		for (off = 0; off < 70; off++) {
			wri_arena_init(&a, base + 3, 1024); /* deliberately misaligned base */
			if (off)
				WRT_CHECK(wri_arena_take(&a, off, 1) != NULL);
			p = (uint8_t *)wri_arena_take(&a, 7, align);
			WRT_CHECK(p != NULL);
			WRT_CHECK(((uintptr_t)p & (align - 1)) == 0);
			WRT_CHECK(p >= base + 3 + off);
			WRT_CHECK(p < base + 3 + off + align);
			WRT_CHECK_U64(a.used, (size_t)(p - (base + 3)) + 7);
		}
	}
}

static void test_arena_limits(void)
{
	static uint8_t raw[256 + 64];
	uint8_t *base = raw;
	wri_arena a;
	size_t before;

	while (((uintptr_t)base & 63u) != 0)
		base++;
	wri_arena_init(&a, base, 100);

	WRT_CHECK(wri_arena_take(&a, 100, 1) != NULL); /* exact fit */
	WRT_CHECK_U64(a.used, 100);
	WRT_CHECK(wri_arena_take(&a, 1, 1) == NULL);
	WRT_CHECK(wri_arena_take(&a, 0, 1) != NULL); /* zero bytes still fine at the very end */
	WRT_CHECK_U64(a.used, 100);

	wri_arena_init(&a, base, 100);
	WRT_CHECK(wri_arena_take(&a, 99, 1) != NULL);
	before = a.used;
	WRT_CHECK(wri_arena_take(&a, 2, 1) == NULL);
	WRT_CHECK(wri_arena_take(&a, 1, 64) == NULL); /* padding alone does not fit: 64 - 99 % 64 */
	WRT_CHECK_U64(a.used, before); /* a failed take changes nothing */

	/* overflow-sized requests */
	wri_arena_init(&a, base, 100);
	WRT_CHECK(wri_arena_take(&a, (size_t)-1, 1) == NULL);
	WRT_CHECK(wri_arena_take(&a, (size_t)-1, 64) == NULL);
	WRT_CHECK(wri_arena_take(&a, (size_t)-63, 64) == NULL);
	WRT_CHECK(wri_arena_take_array(&a, (size_t)-1, 2, 1) == NULL); /* count * elem wraps */
	WRT_CHECK(wri_arena_take_array(&a, 5, 20, 8) != NULL);
	WRT_CHECK_U64(a.used, 100);
	WRT_CHECK_U64(wri_arena_left(&a), 0);

	/* invalid alignments */
	wri_arena_init(&a, base, 100);
	WRT_CHECK(wri_arena_take(&a, 1, 0) == NULL);
	WRT_CHECK(wri_arena_take(&a, 1, 3) == NULL);
	WRT_CHECK(wri_arena_take(&a, 1, 128) == NULL);
	WRT_CHECK(wri_arena_take(&a, 1, 6) == NULL);
	WRT_CHECK_U64(a.used, 0);

	/* an empty arena (NULL base) never hands anything out */
	wri_arena_init(&a, NULL, 100);
	WRT_CHECK_U64(a.cap, 0);
	WRT_CHECK(wri_arena_take(&a, 1, 1) == NULL);
	WRT_CHECK(wri_arena_take(&a, 0, 1) == NULL);
}

static void test_arena_plan(void)
{
	size_t used = 0, u2;
	static uint8_t raw[4096 + 64];
	uint8_t *base = raw;
	wri_arena a;
	uint32_t seed = 12345;
	int i;

	while (((uintptr_t)base & 63u) != 0)
		base++;

	WRT_CHECK_STATUS(WR_OK, wri_arena_plan(&used, 10, 1));
	WRT_CHECK_U64(used, 10);
	WRT_CHECK_STATUS(WR_OK, wri_arena_plan(&used, 5, 16));
	WRT_CHECK_U64(used, 21);
	WRT_CHECK_STATUS(WR_OK, wri_arena_plan(&used, 1, 64));
	WRT_CHECK_U64(used, 65);
	WRT_CHECK_STATUS(WR_OK, wri_arena_plan_array(&used, 3, 7, 8));
	WRT_CHECK_U64(used, 72 + 21);

	/* bad align, overflow: *used unchanged */
	u2 = used;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_arena_plan(&used, 1, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_arena_plan(&used, 1, 3));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_arena_plan(&used, 1, 128));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_arena_plan(&used, (size_t)-1, 1));
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_arena_plan_array(&used, (size_t)-1, 2, 1));
	used = (size_t)-5;
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_arena_plan(&used, 0, 16)); /* align_up wraps */
	WRT_CHECK_U64(used, (size_t)-5);
	used = (size_t)-8;
	WRT_CHECK_STATUS(WR_OK, wri_arena_plan(&used, 7, 8)); /* lands exactly on SIZE_MAX - 0 */
	WRT_CHECK_U64(used, (size_t)-1);
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_arena_plan(&used, 1, 1));
	WRT_CHECK(u2 == 93);

	/* plan mirrors take: random sequences, 64-aligned base, identical `used` after each step */
	for (i = 0; i < 2000; i++) {
		int step;

		used = 0;
		wri_arena_init(&a, base, 4096);
		for (step = 0; step < 20; step++) {
			size_t n, align;
			void *p;
			wr_status st;

			seed = seed * 1664525u + 1013904223u;
			n = (seed >> 8) % 300;
			align = (size_t)1 << ((seed >> 4) % 7);
			p = wri_arena_take(&a, n, align);
			st = wri_arena_plan(&used, n, align);
			WRT_CHECK_STATUS(WR_OK, st);
			if (p == NULL) {
				WRT_CHECK(used > 4096); /* plan says it does not fit either */
				break;
			}
			WRT_CHECK(used <= 4096);
			WRT_CHECK_U64(a.used, used);
		}
	}
}

/* ---- pool --------------------------------------------------------------------------------- */

struct obj {
	uint32_t a;
	uint8_t pad[28];
};

static void test_pool_basic(void)
{
	static uint8_t raw[4096 + 64];
	wri_arena a;
	wri_pool p;
	uint32_t idx[10], i;
	struct obj *o;

	wri_arena_init(&a, raw, sizeof(raw));
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, (uint32_t)sizeof(struct obj), 10));
	WRT_CHECK_U64(p.nobj, 10);
	WRT_CHECK_U64(p.nfree, 10);
	WRT_CHECK_U64(p.hiwater, 0);
	WRT_CHECK(((uintptr_t)p.base & 15u) == 0);

	for (i = 0; i < 10; i++) {
		idx[i] = wri_pool_get(&p);
		WRT_CHECK(idx[i] < 10);
		o = (struct obj *)wri_pool_at(&p, idx[i]);
		WRT_CHECK(o != NULL);
		WRT_CHECK_U64(o->a, 0); /* zeroed, including the bytes that held the free link */
		WRT_CHECK_U64(o->pad[27], 0);
		o->a = 0xFFFFFFFFu; /* dirty it: must come back zero */
		memset(o->pad, 0xEE, sizeof(o->pad));
	}
	/* all distinct */
	{
		uint32_t j;
		for (i = 0; i < 10; i++)
			for (j = i + 1; j < 10; j++)
				WRT_CHECK(idx[i] != idx[j]);
	}
	WRT_CHECK_U64(p.nfree, 0);
	WRT_CHECK_U64(p.hiwater, 10);
	/* exhaustion is backpressure, repeatedly, not an error state */
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);

	/* reuse: a put object comes back (zeroed) */
	wri_pool_put(&p, idx[3]);
	WRT_CHECK_U64(p.nfree, 1);
	WRT_CHECK_U64(wri_pool_get(&p), idx[3]);
	o = (struct obj *)wri_pool_at(&p, idx[3]);
	WRT_CHECK_U64(o->a, 0);
	WRT_CHECK_U64(o->pad[0], 0);
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);

	/* stride: objects do not overlap */
	WRT_CHECK((uint8_t *)wri_pool_at(&p, 1) - (uint8_t *)wri_pool_at(&p, 0) == (ptrdiff_t)sizeof(struct obj));

	/* out-of-range: at -> NULL, put ignored (counters unchanged) */
	WRT_CHECK(wri_pool_at(&p, 10) == NULL);
	WRT_CHECK(wri_pool_at(&p, WRI_NIL) == NULL);
	wri_pool_put(&p, 10);
	wri_pool_put(&p, WRI_NIL);
	wri_pool_put(&p, 0xFFFFFFFEu);
	WRT_CHECK_U64(p.nfree, 0);
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);
}

static void test_pool_hiwater_and_wipe(void)
{
	static uint8_t raw[1024 + 64];
	wri_arena a;
	wri_pool p;
	uint32_t i0, i1, i2, i3;
	uint8_t *o;

	wri_arena_init(&a, raw, sizeof(raw));
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 16, 8));
	i0 = wri_pool_get(&p);
	i1 = wri_pool_get(&p);
	i2 = wri_pool_get(&p);
	WRT_CHECK_U64(p.hiwater, 3);
	wri_pool_put(&p, i1);
	wri_pool_put(&p, i2);
	WRT_CHECK_U64(p.hiwater, 3); /* a high-water mark never falls */
	i3 = wri_pool_get(&p);
	WRT_CHECK_U64(p.hiwater, 3);
	wri_pool_put(&p, i3);
	wri_pool_put(&p, i0);

	/* put wipes: no stale data in a free slot beyond the 4 link bytes */
	i0 = wri_pool_get(&p);
	o = (uint8_t *)wri_pool_at(&p, i0);
	memset(o, 0x77, 16);
	wri_pool_put(&p, i0);
	WRT_CHECK_U64(o[4] | o[5] | o[8] | o[15], 0);

	/* more puts than gets are ignored instead of corrupting the list */
	wri_pool_put(&p, 1);
	wri_pool_put(&p, 2);
	WRT_CHECK_U64(p.nfree, 8);
	{
		uint32_t seen = 0, k, idx;
		for (k = 0; k < 8; k++) {
			idx = wri_pool_get(&p);
			WRT_CHECK(idx < 8);
			WRT_CHECK((seen & (1u << idx)) == 0);
			seen |= 1u << idx;
		}
		WRT_CHECK_U64(seen, 0xFF);
		WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);
		WRT_CHECK_U64(p.hiwater, 8);
	}
}

/* put, put of the same object right away must not link it twice (it would be handed out twice) */
static void test_pool_double_put(void)
{
	static uint8_t raw[256];
	wri_arena a;
	wri_pool p;
	uint32_t x, y, g1, g2, g3;

	wri_arena_init(&a, raw, sizeof(raw));
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 16, 4));
	x = wri_pool_get(&p);
	y = wri_pool_get(&p);
	WRT_CHECK(x != y && x < 4 && y < 4);
	wri_pool_put(&p, x);
	wri_pool_put(&p, x);
	WRT_CHECK_U64(p.nfree, 3);
	g1 = wri_pool_get(&p);
	g2 = wri_pool_get(&p);
	g3 = wri_pool_get(&p);
	WRT_CHECK(g1 < 4 && g2 < 4 && g3 < 4);
	WRT_CHECK(g1 != g2 && g1 != g3 && g2 != g3);
	WRT_CHECK(g1 != y && g2 != y && g3 != y); /* y is still in use */
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);
}

static void test_pool_init_errors(void)
{
	static uint8_t raw_storage[256 + 64 + 16];
	/* the pool takes its slots 16-aligned: start the arena on a 16-byte boundary, as x86-64 gives a
	 * static array of this size and i386 does not, so "exactly 256 bytes fit" holds on both */
	uint8_t *raw = raw_storage + ((16u - ((uintptr_t)raw_storage & 15u)) & 15u);
	wri_arena a;
	wri_pool p;

	wri_arena_init(&a, raw, 256);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_init(&p, &a, 3, 4));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_init(&p, &a, 0, 4));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_pool_init(&p, &a, 8, WRI_NIL));
	WRT_CHECK_U64(a.used, 0);
	WRT_CHECK_STATUS(WR_E_BUDGET, wri_pool_init(&p, &a, 64, 5)); /* 320 > 256 */
	WRT_CHECK_U64(a.used, 0); /* nothing taken on failure */
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 64, 4)); /* exactly 256 */
	/* a pool needs more than a pointer's worth of arithmetic on a 32-bit host: a total that does
	 * not fit size_t is an overflow, not a tiny allocation */
	if (sizeof(size_t) == 4) {
		wri_arena_init(&a, raw, 256);
		WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_pool_init(&p, &a, 0x10000u, 0x10000u));
	}
	/* an empty pool: valid, always backpressure */
	wri_arena_init(&a, raw, 256);
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 8, 0));
	WRT_CHECK_U64(wri_pool_get(&p), WRI_NIL);
	WRT_CHECK(wri_pool_at(&p, 0) == NULL);
	wri_pool_put(&p, 0);
	WRT_CHECK_U64(p.nfree, 0);
	/* two pools share one arena without overlapping */
	{
		wri_pool p2;
		uint8_t *e1, *s2;

		wri_arena_init(&a, raw, 256);
		WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 24, 3));
		WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p2, &a, 20, 4));
		e1 = p.base + 3 * 24;
		s2 = p2.base;
		WRT_CHECK(s2 >= e1);
		WRT_CHECK(((uintptr_t)s2 & 15u) == 0);
	}
}

/* A corrupted free slot (written after put by a buggy owner) must not lead out of the pool. */
static void test_pool_corrupt_free_link(void)
{
	static uint8_t raw[256 + 64];
	wri_arena a;
	wri_pool p;
	uint32_t i, n = 0;
	uint8_t *o;

	wri_arena_init(&a, raw, sizeof(raw));
	WRT_CHECK_STATUS(WR_OK, wri_pool_init(&p, &a, 16, 4));
	i = wri_pool_get(&p);
	wri_pool_put(&p, i); /* head of the free list again */
	o = (uint8_t *)wri_pool_at(&p, i);
	o[0] = 0x00;
	o[1] = 0x00;
	o[2] = 0x00;
	o[3] = 0x7F; /* link = 0x7F000000, far out of range */
	while ((i = wri_pool_get(&p)) != WRI_NIL) {
		WRT_CHECK(i < 4);
		WRT_CHECK(++n <= 4);
	}
	WRT_CHECK(n >= 1);
}

/* ---- ring --------------------------------------------------------------------------------- */

#define RING_CAP 61u /* odd and not a power of two on purpose */

static uint32_t rng_state = 0x9E3779B9u;
static uint32_t rng(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

/* Model: a plain array with the stored bytes at [0, mlen). */
struct model {
	uint8_t d[RING_CAP];
	uint32_t len;
};

static uint8_t next_byte;

static void model_check(const wri_ring *r, const struct model *m)
{
	uint8_t tmp[RING_CAP];
	uint32_t got;

	WRT_CHECK_U64(r->len, m->len);
	WRT_CHECK_U64(wri_ring_free(r), RING_CAP - m->len);
	WRT_CHECK(r->head < RING_CAP);
	got = wri_ring_peek(r, tmp, RING_CAP);
	WRT_CHECK_U64(got, m->len);
	WRT_CHECK_MEM(tmp, m->d, m->len);
}

static void test_ring_basic(void)
{
	uint8_t buf[8];
	uint8_t *wp;
	const uint8_t *rp;
	uint32_t n;
	wri_ring r;
	uint8_t out[8];

	wri_ring_init(&r, buf, sizeof(buf));
	WRT_CHECK_U64(wri_ring_free(&r), 8);
	n = wri_ring_write_span(&r, &wp);
	WRT_CHECK_U64(n, 8);
	WRT_CHECK(wp == buf);
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 0);

	memcpy(wp, "abcdef", 6);
	wri_ring_commit(&r, 6);
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 2);
	WRT_CHECK(wp == buf + 6);
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 6);
	wri_ring_drop(&r, 4); /* "ef" left, head = 4 */
	/* free space wraps: first span runs to the end, then the start */
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 2);
	WRT_CHECK(wp == buf + 6);
	memcpy(wp, "gh", 2);
	wri_ring_commit(&r, 2);
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 4); /* wrapped: bytes 0..3 */
	WRT_CHECK(wp == buf);
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 4); /* only up to the end of the buffer */
	WRT_CHECK(rp == buf + 4);
	memcpy(wp, "ijkl", 4);
	wri_ring_commit(&r, 4);
	WRT_CHECK_U64(wri_ring_free(&r), 0);
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 0); /* full */
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 4);
	WRT_CHECK_U64(wri_ring_peek(&r, out, 8), 8);
	WRT_CHECK_MEM(out, "efghijkl", 8);
	WRT_CHECK_U64(r.len, 8); /* peek removes nothing */
	wri_ring_drop(&r, 4);
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 4);
	WRT_CHECK(rp == buf); /* wrapped read position */
	wri_ring_drop(&r, 100); /* clamped */
	WRT_CHECK_U64(r.len, 0);
	WRT_CHECK_U64(r.head, 0); /* empty ring restarts at 0: longest possible span next */
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 8);

	/* commit is clamped, write/read copy helpers wrap */
	wri_ring_commit(&r, 1000);
	WRT_CHECK_U64(r.len, 8);
	wri_ring_drop(&r, 5);
	WRT_CHECK_U64(wri_ring_write(&r, (const uint8_t *)"WXYZ12", 6), 5);
	WRT_CHECK_U64(wri_ring_read(&r, out, 8), 8);
	WRT_CHECK_MEM(out + 3, "WXYZ1", 5);
	WRT_CHECK_U64(r.len, 0);

	/* wipe */
	wri_ring_write(&r, (const uint8_t *)"secret!!", 8);
	wri_ring_reset_wipe(&r);
	WRT_CHECK_U64(r.len, 0);
	WRT_CHECK_U64(buf[0] | buf[3] | buf[7], 0);

	/* degenerate rings */
	wri_ring_init(&r, NULL, 10);
	WRT_CHECK_U64(r.cap, 0);
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 0);
	WRT_CHECK_U64(wri_ring_read_span(&r, &rp), 0);
	WRT_CHECK_U64(wri_ring_write(&r, (const uint8_t *)"x", 1), 0);
	wri_ring_commit(&r, 5);
	wri_ring_drop(&r, 5);
	WRT_CHECK_U64(wri_ring_peek(&r, out, 8), 0);
	wri_ring_init(&r, buf, 0);
	WRT_CHECK_U64(wri_ring_write_span(&r, &wp), 0);
	WRT_CHECK_U64(wri_ring_free(&r), 0);
}

static void test_ring_model(void)
{
	uint8_t buf[RING_CAP + 8]; /* 8 canary bytes after the ring */
	uint8_t canary[8];
	wri_ring r;
	struct model m;
	uint32_t op;
	unsigned long fulls = 0, empties = 0;

	memset(buf, 0xA5, sizeof(buf));
	memset(canary, 0xA5, sizeof(canary));
	wri_ring_init(&r, buf, RING_CAP);
	memset(&m, 0, sizeof(m));
	next_byte = 1;

	for (op = 0; op < 100000; op++) {
		uint32_t k = rng() % 8;
		uint32_t n = rng() % (RING_CAP + 8);

		if (k < 2) { /* span write + commit, like a recv(); a second round takes the wrapped part */
			int round;

			for (round = 0; round < 2; round++) {
				uint8_t *wp;
				uint32_t span = wri_ring_write_span(&r, &wp);
				uint32_t i, take = n < span ? n : span;

				WRT_CHECK(span <= wri_ring_free(&r));
				WRT_CHECK(span == 0 || (wp >= buf && wp + span <= buf + RING_CAP));
				for (i = 0; i < take; i++) {
					wp[i] = next_byte;
					m.d[m.len + i] = next_byte++;
				}
				wri_ring_commit(&r, take);
				m.len += take;
				n -= take;
			}
		} else if (k < 3) { /* copy-in helper, may split across the wrap */
			uint8_t src[RING_CAP + 8];
			uint32_t i, want = n, fit, put;

			for (i = 0; i < want; i++)
				src[i] = next_byte++;
			fit = RING_CAP - m.len;
			put = wri_ring_write(&r, src, want);
			WRT_CHECK_U64(put, want < fit ? want : fit);
			memcpy(m.d + m.len, src, put);
			m.len += put;
		} else if (k < 5) { /* span read + drop */
			const uint8_t *rp;
			uint32_t span = wri_ring_read_span(&r, &rp);
			uint32_t take = n < span ? n : span;

			WRT_CHECK(span <= r.len);
			WRT_CHECK(span == 0 || rp + span <= buf + RING_CAP);
			WRT_CHECK(span == 0 || memcmp(rp, m.d, span) == 0);
			wri_ring_drop(&r, take);
			memmove(m.d, m.d + take, m.len - take);
			m.len -= take;
		} else if (k < 6) { /* copy-out helper */
			uint8_t dst[RING_CAP + 8];
			uint32_t got = wri_ring_read(&r, dst, n);
			uint32_t want = n < m.len ? n : m.len;

			WRT_CHECK_U64(got, want);
			WRT_CHECK_MEM(dst, m.d, want);
			memmove(m.d, m.d + want, m.len - want);
			m.len -= want;
		} else if (k < 7) { /* oversized drop and commit are clamped */
			if (rng() % 2) {
				uint32_t d = rng() % 3 == 0 ? 0xFFFFFFFFu : n;

				wri_ring_drop(&r, d);
				if (d > m.len)
					d = m.len;
				memmove(m.d, m.d + d, m.len - d);
				m.len -= d;
			}
		} else { /* peek with a partial window */
			uint8_t dst[RING_CAP + 8];
			uint32_t got = wri_ring_peek(&r, dst, n);
			uint32_t want = n < m.len ? n : m.len;

			WRT_CHECK_U64(got, want);
			WRT_CHECK_MEM(dst, m.d, want);
		}
		if (m.len == RING_CAP)
			fulls++;
		if (m.len == 0)
			empties++;
		model_check(&r, &m);
		WRT_CHECK_MEM(buf + RING_CAP, canary, 8);
		if (wrt_failures)
			break; /* stop at the first divergence, the rest would only repeat it */
	}
	WRT_CHECK(fulls > 100);
	WRT_CHECK(empties > 100);
}

int main(void)
{
	test_arena_basic();
	test_arena_limits();
	test_arena_plan();
	test_pool_basic();
	test_pool_hiwater_and_wipe();
	test_pool_double_put();
	test_pool_init_errors();
	test_pool_corrupt_free_link();
	test_ring_basic();
	test_ring_model();
	return wrt_finish();
}
