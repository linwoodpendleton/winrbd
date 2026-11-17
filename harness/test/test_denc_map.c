/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/denc/wri_denc_map.c: the legacy envelope (threshold tables, compat limit, truncation),
 * pg_t (round trip with a writer), varints (known answers, limits, round trip), the skip helpers (every
 * truncation point, hostile counts at every nesting level, a differential check against a reference walker
 * that works on raw offsets and not on the cursors), and the pools of osdmap/full-e42.hex and of
 * public/denc-map/pools-e202.bin (snapshots, options, tiers, hit set) walked with the skip helpers only.
 *
 * Buffers handed to the code under test are exact-size heap allocations, so under ASan any read or write
 * outside them is reported.
 */
#include "wrt.h"

#include "wri_denc_map.h"

/* ---- helpers ------------------------------------------------------------------------------ */

static uint8_t *dup_bytes(const uint8_t *p, size_t n)
{
	uint8_t *q = (uint8_t *)malloc(n ? n : 1);

	if (!q) {
		fprintf(stderr, "out of memory\n");
		exit(2);
	}
	if (n)
		memcpy(q, p, n);
	return q;
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/* xorshift64*: deterministic test randomness (the harness may keep state; core may not). */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return (uint32_t)((rng_state * 0x2545F4914F6CDD1Dull) >> 32);
}

static int is_count_err(wr_status st)
{
	return st == WR_E_TRUNCATED || st == WR_E_TOOBIG;
}

/* ---- legacy envelope ---------------------------------------------------------------------- */

/* Write a legacy envelope exactly as the thresholds say; returns the length written. */
static size_t build_legacy(uint8_t *o, uint8_t v, uint8_t compat, uint8_t compat_at, uint8_t len_at,
			   const uint8_t *body, size_t bn)
{
	size_t n = 0;

	o[n++] = v;
	if (v >= compat_at)
		o[n++] = compat;
	if (v >= len_at) {
		put32(o + n, (uint32_t)bn);
		n += 4;
	}
	if (bn)
		memcpy(o + n, body, bn);
	return n + bn;
}

static void legacy_threshold_table(uint8_t min_v, uint8_t compat_at, uint8_t len_at, uint8_t supported)
{
	static const uint8_t body[3] = {0xA1, 0xA2, 0xA3};
	unsigned v;

	for (v = 1; v <= 40; v++) {
		uint8_t wire[32];
		size_t n = build_legacy(wire, (uint8_t)v, 2, compat_at, len_at, body, 3);
		uint8_t *buf;
		wri_rd r;
		wri_env e;
		int ok = (v >= min_v && v >= len_at);
		wr_status st;

		/* two trailing bytes that belong to the parent */
		wire[n++] = 0xEE;
		wire[n++] = 0xEF;
		buf = dup_bytes(wire, n);
		wri_rd_init(&r, buf, n);
		st = wri_env_open_legacy(&r, min_v, compat_at, len_at, supported, &e);
		if (ok) {
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK_U64(e.v, v);
			WRT_CHECK_U64(e.compat, v >= compat_at ? 2 : 0);
			WRT_CHECK_U64(e.body.len, 3);
			WRT_CHECK_U64(wri_rd_left(&r), 2); /* parent is past the body */
			WRT_CHECK_U64(wri_rd_u8(&e.body), 0xA1);
			WRT_CHECK_U64(wri_rd_u8(&e.body), 0xA2);
			WRT_CHECK_U64(wri_rd_u8(&e.body), 0xA3);
			WRT_CHECK(wri_rd_ok(&e.body) && wri_rd_left(&e.body) == 0);
			WRT_CHECK_U64(wri_rd_u8(&r), 0xEE);
		} else {
			WRT_CHECK_STATUS(WR_E_MAP_VERSION, st);
			WRT_CHECK_U64(r.err, WR_E_MAP_VERSION);
			WRT_CHECK_U64(e.body.err, WR_E_MAP_VERSION); /* an ignored status reads an errored, empty body */
			WRT_CHECK_U64(wri_rd_left(&e.body), 0);
			WRT_CHECK_U64(e.v, 0);
		}
		free(buf);
	}
}

static void test_legacy_thresholds(void)
{
	/* the two real uses: the map wrapper and the incremental (7, 7), pg_pool_t (5, 5) */
	legacy_threshold_table(7, 7, 7, 7);
	legacy_threshold_table(5, 5, 5, 5);
	/* min_v above the thresholds: refused below min_v although the layout is readable */
	legacy_threshold_table(9, 7, 7, 7);
	/* a layout with no length below 5: refused through "length absent" even when min_v is 1 */
	legacy_threshold_table(1, 3, 5, 5);
	/* a length without a compat byte (len_at < compat_at): compat reads back as 0 */
	legacy_threshold_table(1, 5, 3, 5);
	/* thresholds of 1: everything has all three fields */
	legacy_threshold_table(1, 1, 1, 2);
}

static void test_legacy_compat_limit(void)
{
	uint8_t c;

	for (c = 0; c < 12; c++) {
		uint8_t wire[16];
		uint8_t *buf;
		wri_rd r;
		wri_env e;
		size_t n = build_legacy(wire, 8, c, 7, 7, (const uint8_t *)"xy", 2);

		buf = dup_bytes(wire, n);
		wri_rd_init(&r, buf, n);
		if (c <= 7) {
			WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
			WRT_CHECK_U64(e.compat, c);
		} else {
			WRT_CHECK_STATUS(WR_E_MAP_VERSION, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
		}
		free(buf);
	}
	/* the compat check wins over the length check: unsupported even when the body is not there */
	{
		static const uint8_t wire[] = {8, 9, 0xFF, 0xFF, 0xFF, 0xFF};
		uint8_t *buf = dup_bytes(wire, sizeof(wire));
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, sizeof(wire));
		WRT_CHECK_STATUS(WR_E_MAP_VERSION, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
		free(buf);
	}
	/* supported_compat 255 accepts every compat byte */
	{
		static const uint8_t wire[] = {8, 255, 0, 0, 0, 0};
		uint8_t *buf = dup_bytes(wire, sizeof(wire));
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, sizeof(wire));
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&r, 7, 7, 7, 255, &e));
		WRT_CHECK_U64(e.compat, 255);
		free(buf);
	}
}

static void test_legacy_truncation(void)
{
	uint8_t wire[32];
	size_t n = build_legacy(wire, 8, 7, 7, 7, (const uint8_t *)"abcdefgh", 8), cut;

	for (cut = 0; cut < n; cut++) {
		uint8_t *buf = dup_bytes(wire, cut);
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, cut);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
		WRT_CHECK_U64(wri_rd_left(&e.body), 0);
		free(buf);
	}
	/* a length that passes the parent, down to one byte too many; and the hostile maximum */
	{
		uint8_t w2[32];
		uint32_t extra;

		for (extra = 1; extra <= 3; extra++) {
			uint8_t *buf;
			wri_rd r;
			wri_env e;

			memcpy(w2, wire, n);
			put32(w2 + 2, 8 + extra); /* v, compat, then the length */
			buf = dup_bytes(w2, n);
			wri_rd_init(&r, buf, n);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
			free(buf);
		}
		memcpy(w2, wire, n);
		put32(w2 + 2, 0xFFFFFFFFu);
		{
			uint8_t *buf = dup_bytes(w2, n);
			wri_rd r;
			wri_env e;

			wri_rd_init(&r, buf, n);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open_legacy(&r, 7, 7, 7, 7, &e));
			free(buf);
		}
	}
	/* exactly all the bytes is fine, empty body is fine */
	{
		uint8_t w2[8];
		size_t m = build_legacy(w2, 5, 5, 5, 5, NULL, 0);
		uint8_t *buf = dup_bytes(w2, m);
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, m);
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&r, 5, 5, 5, 5, &e));
		WRT_CHECK_U64(e.body.len, 0);
		WRT_CHECK_U64(wri_rd_left(&r), 0);
		free(buf);
	}
}

static void test_legacy_misc(void)
{
	wri_rd r;
	wri_env e;
	static const uint8_t wire[] = {8, 7, 0, 0, 0, 0};

	/* NULL arguments */
	wri_rd_init(&r, wire, sizeof(wire));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_env_open_legacy(&r, 7, 7, 7, 7, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_env_open_legacy(NULL, 7, 7, 7, 7, &e));
	/* a reader that already failed stays failed */
	wri_rd_init(&r, wire, sizeof(wire));
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK(wri_env_open_legacy(&r, 7, 7, 7, 7, &e) != WR_OK);
	WRT_CHECK_U64(r.err, WR_E_ENCODING);
	/* nesting: a (5,5) envelope inside a (7,7) body is checked against the outer body, not the whole buffer */
	{
		uint8_t inner[16], outer[32];
		size_t in = build_legacy(inner, 32, 5, 5, 5, (const uint8_t *)"pool", 4);
		size_t on = build_legacy(outer, 8, 7, 7, 7, inner, in);
		wri_rd pr;
		wri_env oe, ie;
		uint8_t *buf;
		wr_status st;

		/* a trailing byte after the outer envelope, so that the buffer is longer than the outer body */
		outer[on++] = 0x55;
		buf = dup_bytes(outer, on);
		wri_rd_init(&pr, buf, on);
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&pr, 7, 7, 7, 7, &oe));
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&oe.body, 5, 5, 5, 5, &ie));
		WRT_CHECK_U64(ie.v, 32);
		WRT_CHECK_U64(ie.body.len, 4);
		WRT_CHECK_U64(wri_rd_left(&oe.body), 0);
		free(buf);

		/* the inner length points past the outer body but inside the buffer: refused */
		in = build_legacy(inner, 32, 5, 5, 5, (const uint8_t *)"pool", 4);
		put32(inner + 2, 5); /* one byte more than the outer body holds */
		on = build_legacy(outer, 8, 7, 7, 7, inner, in);
		outer[on++] = 0x55;
		buf = dup_bytes(outer, on);
		wri_rd_init(&pr, buf, on);
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&pr, 7, 7, 7, 7, &oe));
		st = wri_env_open_legacy(&oe.body, 5, 5, 5, 5, &ie);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, st);
		free(buf);
	}
}

/* ---- pg_t --------------------------------------------------------------------------------- */

static void test_pg(void)
{
	static const uint64_t pools[] = {0, 1, 2, 0x7FFFFFFFull, 0x80000000ull, 0xFFFFFFFFull, 0x100000000ull,
					 0x8000000000000005ull, 0xFFFFFFFFFFFFFFFFull};
	static const uint32_t seeds[] = {0, 1, 63, 0x7FFFFFFFu, 0xFFFFFFFFu};
	static const uint8_t vers[] = {1, 0, 2, 0xFF};
	size_t i, j, k;

	for (i = 0; i < sizeof(pools) / sizeof(pools[0]); i++) {
		for (j = 0; j < sizeof(seeds) / sizeof(seeds[0]); j++) {
			uint8_t wire[17 + 3];
			uint8_t *buf;
			wri_wr w;
			wri_rd r;
			wri_pg pg;
			size_t cut;

			k = (i + j) % (sizeof(vers) / sizeof(vers[0]));
			wri_wr_init(&w, wire, sizeof(wire));
			wri_wr_u8(&w, vers[k]);
			wri_wr_u64(&w, pools[i]);
			wri_wr_u32(&w, seeds[j]);
			wri_wr_i32(&w, k == 0 ? -1 : (int32_t)rnd()); /* preferred: any value, skipped */
			WRT_CHECK(wri_wr_ok(&w));
			WRT_CHECK_U64(wri_wr_len(&w), 17);
			wri_wr_u8(&w, 0x77);
			wri_wr_u8(&w, 0x78);

			buf = dup_bytes(wire, 19);
			wri_rd_init(&r, buf, 19);
			WRT_CHECK_STATUS(WR_OK, wri_denc_pg(&r, &pg));
			WRT_CHECK_U64(pg.pool, pools[i]); /* returned as read, huge ids included */
			WRT_CHECK_U64(pg.seed, seeds[j]);
			WRT_CHECK_U64(r.pos, 17);
			WRT_CHECK_U64(wri_rd_u8(&r), 0x77);
			free(buf);

			for (cut = 0; cut < 17; cut++) {
				buf = dup_bytes(wire, cut);
				wri_rd_init(&r, buf, cut);
				pg.pool = 5;
				pg.seed = 5;
				WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_denc_pg(&r, &pg));
				WRT_CHECK_U64(pg.pool, 0);
				WRT_CHECK_U64(pg.seed, 0);
				free(buf);
			}
		}
	}
	/* NULL out */
	{
		static const uint8_t wire[17] = {1};
		wri_rd r;

		wri_rd_init(&r, wire, sizeof(wire));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_denc_pg(&r, NULL));
	}
	/* the sort key: ascending keys = wire order of pg-keyed maps */
	WRT_CHECK_U64(wri_pg_key(1, 0), 0x100000000ull);
	WRT_CHECK_U64(wri_pg_key(2, 0xFFFFFFFFu), 0x2FFFFFFFFull);
	WRT_CHECK(wri_pg_key(1, 0xFFFFFFFFu) < wri_pg_key(2, 0));
	WRT_CHECK(wri_pg_key(0x7FFFFFFFu, 5) < wri_pg_key(0x7FFFFFFFu, 6));
}

/* ---- varint ------------------------------------------------------------------------------- */

/* reference encoder, written independently of the decoder */
static size_t varint_put(uint8_t *o, uint64_t v)
{
	size_t n = 0;

	while (v >= 0x80) {
		o[n++] = (uint8_t)(v | 0x80);
		v >>= 7;
	}
	o[n++] = (uint8_t)v;
	return n;
}

static void test_varint_known(void)
{
	struct {
		uint8_t b[10];
		size_t n;
		uint64_t v;
	} k[] = {
		{{0x00}, 1, 0},
		{{0x01}, 1, 1},
		{{0x7F}, 1, 127},
		{{0x80, 0x01}, 2, 128},
		{{0xAC, 0x02}, 2, 300},
		{{0xFF, 0x7F}, 2, 16383},
		{{0x80, 0x80, 0x01}, 3, 16384},
		{{0xFF, 0xFF, 0xFF, 0xFF, 0x0F}, 5, 0xFFFFFFFFull},
		{{0x80, 0x80, 0x80, 0x80, 0x10}, 5, 0x100000000ull},
		{{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}, 10, 0x8000000000000000ull},
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, 10, 0xFFFFFFFFFFFFFFFFull},
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}, 9, 0x7FFFFFFFFFFFFFFFull},
		/* non-canonical but terminating forms are accepted, as the reference decoder does */
		{{0x80, 0x00}, 2, 0},
		{{0x81, 0x80, 0x00}, 3, 1},
	};
	size_t i, cut;

	for (i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
		uint8_t tail[11];
		uint8_t *buf;
		wri_rd r;

		memcpy(tail, k[i].b, k[i].n);
		tail[k[i].n] = 0x42;
		buf = dup_bytes(tail, k[i].n + 1);
		wri_rd_init(&r, buf, k[i].n + 1);
		WRT_CHECK_U64(wri_denc_varint(&r), k[i].v);
		WRT_CHECK(wri_rd_ok(&r));
		WRT_CHECK_U64(r.pos, k[i].n); /* consumed exactly its own bytes */
		WRT_CHECK_U64(wri_rd_u8(&r), 0x42);
		free(buf);

		/* every strict prefix runs out before the terminator */
		for (cut = 0; cut < k[i].n; cut++) {
			buf = dup_bytes(k[i].b, cut);
			wri_rd_init(&r, buf, cut);
			WRT_CHECK_U64(wri_denc_varint(&r), 0);
			WRT_CHECK_U64(r.err, WR_E_TRUNCATED);
			free(buf);
		}
	}
}

static void test_varint_overflow(void)
{
	size_t i;
	struct {
		uint8_t b[12];
		size_t n;
	} bad[] = {
		/* tenth byte carries more than bit 63 */
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x02}, 10},
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F}, 10},
		{{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7F}, 10},
		/* tenth byte asks for an eleventh: the 11-byte form of 0 and of 1 */
		{{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 11},
		{{0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 11},
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, 11},
		/* never ends */
		{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 12},
	};

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		uint8_t *buf = dup_bytes(bad[i].b, bad[i].n);
		wri_rd r;

		wri_rd_init(&r, buf, bad[i].n);
		WRT_CHECK_U64(wri_denc_varint(&r), 0);
		WRT_CHECK_U64(r.err, WR_E_ENCODING);
		/* sticky: the next read does nothing */
		WRT_CHECK_U64(wri_denc_varint(&r), 0);
		WRT_CHECK_U64(r.err, WR_E_ENCODING);
		free(buf);
	}
	/* a reader that already failed returns 0 and keeps its error */
	{
		static const uint8_t one[] = {5};
		wri_rd r;

		wri_rd_init(&r, one, 1);
		wri_rd_fail(&r, WR_E_TOOBIG);
		WRT_CHECK_U64(wri_denc_varint(&r), 0);
		WRT_CHECK_U64(r.err, WR_E_TOOBIG);
	}
}

static void test_varint_roundtrip(void)
{
	uint8_t stream[64 * 10];
	uint64_t vals[64];
	size_t n = 0, i, nv = 0;
	unsigned b;
	uint8_t *buf;
	wri_rd r;

	for (b = 0; b < 64 && nv + 3 <= 64; b++) {
		vals[nv++] = (uint64_t)1 << b;
		vals[nv++] = ((uint64_t)1 << b) - 1;
		vals[nv++] = ((uint64_t)1 << b) + 1;
	}
	for (i = 0; i < nv; i++)
		n += varint_put(stream + n, vals[i]);
	buf = dup_bytes(stream, n);
	wri_rd_init(&r, buf, n);
	for (i = 0; i < nv; i++)
		WRT_CHECK_U64(wri_denc_varint(&r), vals[i]);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	free(buf);

	/* random values, one stream */
	n = 0;
	for (i = 0; i < 64; i++) {
		vals[i] = ((uint64_t)rnd() << 32 | rnd()) >> (rnd() % 64);
		n += varint_put(stream + n, vals[i]);
	}
	buf = dup_bytes(stream, n);
	wri_rd_init(&r, buf, n);
	for (i = 0; i < 64; i++)
		WRT_CHECK_U64(wri_denc_varint(&r), vals[i]);
	WRT_CHECK(wri_rd_ok(&r) && wri_rd_left(&r) == 0);
	free(buf);

	/* the empty nonprimary_shards set of a pool: two varints, 00 00 */
	{
		static const uint8_t two[] = {0, 0};
		wri_rd r2;

		wri_rd_init(&r2, two, 2);
		WRT_CHECK_U64(wri_denc_varint(&r2), 0);
		WRT_CHECK_U64(wri_denc_varint(&r2), 0);
		WRT_CHECK(wri_rd_ok(&r2) && wri_rd_left(&r2) == 0);
	}
}

/* ---- reference walkers (raw offsets, no cursors) ------------------------------------------ */

#define REF_FAIL ((size_t)-1)

static int ref_u32(const uint8_t *b, size_t len, size_t off, uint32_t *v)
{
	if (off > len || len - off < 4)
		return 0;
	*v = (uint32_t)b[off] | (uint32_t)b[off + 1] << 8 | (uint32_t)b[off + 2] << 16 | (uint32_t)b[off + 3] << 24;
	return 1;
}

static size_t ref_str(const uint8_t *b, size_t len, size_t off)
{
	uint32_t n;

	if (!ref_u32(b, len, off, &n))
		return REF_FAIL;
	off += 4;
	if ((uint64_t)n > len - off)
		return REF_FAIL;
	return off + n;
}

static size_t ref_str_map(const uint8_t *b, size_t len, size_t off)
{
	uint32_t n, i;

	if (!ref_u32(b, len, off, &n))
		return REF_FAIL;
	off += 4;
	for (i = 0; i < n; i++) { /* every entry is at least 8 bytes, so a hostile n runs out of bytes at once */
		off = ref_str(b, len, off);
		if (off == REF_FAIL)
			return REF_FAIL;
		off = ref_str(b, len, off);
		if (off == REF_FAIL)
			return REF_FAIL;
	}
	return off;
}

static size_t ref_str_map_map(const uint8_t *b, size_t len, size_t off)
{
	uint32_t n, i;

	if (!ref_u32(b, len, off, &n))
		return REF_FAIL;
	off += 4;
	for (i = 0; i < n; i++) {
		off = ref_str(b, len, off);
		if (off == REF_FAIL)
			return REF_FAIL;
		off = ref_str_map(b, len, off);
		if (off == REF_FAIL)
			return REF_FAIL;
	}
	return off;
}

static size_t ref_fixed_vec(const uint8_t *b, size_t len, size_t off, size_t elem, uint32_t max)
{
	uint32_t n;

	if (!ref_u32(b, len, off, &n) || n > max)
		return REF_FAIL;
	off += 4;
	if ((uint64_t)n * elem > len - off)
		return REF_FAIL;
	return off + (size_t)n * elem;
}

static size_t ref_env(const uint8_t *b, size_t len, size_t off)
{
	uint32_t n;

	if (off > len || len - off < 2 || !ref_u32(b, len, off + 2, &n))
		return REF_FAIL;
	off += 6;
	if ((uint64_t)n > len - off)
		return REF_FAIL;
	return off + n;
}

/* ---- skip helpers: kinds ------------------------------------------------------------------ */

enum { K_STR, K_MAP, K_MAPMAP, K_IVSET, K_ENV, K_VEC, K_COUNT };
#define VEC_MAX 5u

static const char *const kind_name[K_COUNT] = {"str", "str_map", "str_map_map", "interval_set", "env", "i32_vec"};

static void do_skip(int kind, wri_rd *r)
{
	switch (kind) {
	case K_STR: wri_denc_skip_str(r); break;
	case K_MAP: wri_denc_skip_str_map(r); break;
	case K_MAPMAP: wri_denc_skip_str_map_map(r); break;
	case K_IVSET: wri_denc_skip_interval_set(r); break;
	case K_ENV: wri_denc_skip_env(r); break;
	default: wri_denc_skip_i32_vec(r, VEC_MAX); break;
	}
}

static size_t do_ref(int kind, const uint8_t *b, size_t len)
{
	switch (kind) {
	case K_STR: return ref_str(b, len, 0);
	case K_MAP: return ref_str_map(b, len, 0);
	case K_MAPMAP: return ref_str_map_map(b, len, 0);
	case K_IVSET: return ref_fixed_vec(b, len, 0, 16, 0xFFFFFFFFu);
	case K_ENV: return ref_env(b, len, 0);
	default: return ref_fixed_vec(b, len, 0, 4, VEC_MAX);
	}
}

/* random valid encodings (the writer is independent of the skippers) */
static void gen_str(wri_wr *w)
{
	uint8_t s[24];
	size_t n = rnd() % 20, i;

	for (i = 0; i < n; i++)
		s[i] = (uint8_t)rnd();
	wri_denc_put_str(w, s, n);
}

static void gen_map(wri_wr *w)
{
	uint32_t n = rnd() % 4, i;

	wri_wr_u32(w, n);
	for (i = 0; i < n; i++) {
		gen_str(w);
		gen_str(w);
	}
}

static void gen_mapmap(wri_wr *w)
{
	uint32_t n = rnd() % 3, i;

	wri_wr_u32(w, n);
	for (i = 0; i < n; i++) {
		gen_str(w);
		gen_map(w);
	}
}

static void gen_ivset(wri_wr *w)
{
	uint32_t n = rnd() % 4, i;

	wri_wr_u32(w, n);
	for (i = 0; i < n; i++) {
		wri_wr_u64(w, ((uint64_t)rnd() << 32) | rnd());
		wri_wr_u64(w, rnd());
	}
}

static void gen_env(wri_wr *w)
{
	size_t mark = wri_env_begin(w, (uint8_t)rnd(), (uint8_t)rnd()), i, n = rnd() % 12;

	for (i = 0; i < n; i++)
		wri_wr_u8(w, (uint8_t)rnd());
	wri_env_end(w, mark);
}

static void gen_vec(wri_wr *w)
{
	uint32_t n = rnd() % (VEC_MAX + 1), i;

	wri_wr_u32(w, n);
	for (i = 0; i < n; i++)
		wri_wr_i32(w, (int32_t)rnd());
}

static void gen(int kind, wri_wr *w)
{
	switch (kind) {
	case K_STR: gen_str(w); break;
	case K_MAP: gen_map(w); break;
	case K_MAPMAP: gen_mapmap(w); break;
	case K_IVSET: gen_ivset(w); break;
	case K_ENV: gen_env(w); break;
	default: gen_vec(w); break;
	}
}

/* ---- skip helpers: every truncation point, empty values, sticky errors --------------------- */

static void test_skip_truncation(void)
{
	int kind;
	unsigned iter;

	for (kind = 0; kind < K_COUNT; kind++) {
		for (iter = 0; iter < 60; iter++) {
			uint8_t wire[1024];
			wri_wr w;
			size_t total, cut;
			uint8_t *buf;
			wri_rd r;

			wri_wr_init(&w, wire, sizeof(wire) - 1);
			gen(kind, &w);
			WRT_CHECK(wri_wr_ok(&w));
			total = wri_wr_len(&w);
			wire[total] = 0x5A; /* the next value of the parent */

			buf = dup_bytes(wire, total + 1);
			wri_rd_init(&r, buf, total + 1);
			do_skip(kind, &r);
			if (!wri_rd_ok(&r) || r.pos != total) {
				WRT_CHECK(0);
				fprintf(stderr, "  %s: pos %zu, want %zu\n", kind_name[kind], r.pos, total);
			}
			WRT_CHECK_U64(wri_rd_u8(&r), 0x5A);
			free(buf);

			for (cut = 0; cut < total; cut++) {
				buf = dup_bytes(wire, cut);
				wri_rd_init(&r, buf, cut);
				do_skip(kind, &r);
				if (!is_count_err(r.err)) {
					WRT_CHECK(0);
					fprintf(stderr, "  %s cut %zu/%zu: err %d\n", kind_name[kind], cut, total, (int)r.err);
				}
				free(buf);
			}
		}
	}
}

static void test_skip_empty_and_sticky(void)
{
	/* the smallest valid value of each kind */
	static const uint8_t z4[4] = {0, 0, 0, 0};
	static const uint8_t env0[6] = {1, 1, 0, 0, 0, 0};
	int kind;

	for (kind = 0; kind < K_COUNT; kind++) {
		const uint8_t *src = kind == K_ENV ? env0 : z4;
		size_t n = kind == K_ENV ? 6 : 4;
		uint8_t *buf = dup_bytes(src, n);
		wri_rd r;

		wri_rd_init(&r, buf, n);
		do_skip(kind, &r);
		WRT_CHECK(wri_rd_ok(&r));
		WRT_CHECK_U64(r.pos, n);
		free(buf);

		/* a reader that already failed does not move and keeps its error */
		buf = dup_bytes(src, n);
		wri_rd_init(&r, buf, n);
		wri_rd_fail(&r, WR_E_ENCODING);
		do_skip(kind, &r);
		WRT_CHECK_U64(r.err, WR_E_ENCODING);
		WRT_CHECK_U64(r.pos, 0);
		free(buf);

		/* and on an empty buffer */
		wri_rd_init(&r, z4, 0);
		do_skip(kind, &r);
		WRT_CHECK_U64(r.err, WR_E_TRUNCATED);
	}
}

/* ---- hostile counts at every nesting level ------------------------------------------------ */

static void le32(uint8_t *o, uint32_t v)
{
	put32(o, v);
}

static void expect_fail(int kind, const uint8_t *wire, size_t n, wr_status want, int line)
{
	uint8_t *buf = dup_bytes(wire, n);
	wri_rd r;

	wri_rd_init(&r, buf, n);
	do_skip(kind, &r);
	wrt_checks++;
	if (r.err != want) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s: err %d, want %d\n", __FILE__, line, kind_name[kind], (int)r.err, (int)want);
	}
	free(buf);
}
#define EXPECT_FAIL(kind, wire, n, want) expect_fail((kind), (wire), (n), (want), __LINE__)

static void test_skip_hostile(void)
{
	uint8_t w[64];
	size_t i;

	/* string: a hostile length is a truncation */
	le32(w, 0xFFFFFFFFu);
	EXPECT_FAIL(K_STR, w, 4, WR_E_TRUNCATED);
	EXPECT_FAIL(K_STR, w, 4, WR_E_TRUNCATED);
	le32(w, 0x80000000u);
	EXPECT_FAIL(K_STR, w, 4, WR_E_TRUNCATED);
	le32(w, 3);
	EXPECT_FAIL(K_STR, w, 6, WR_E_TRUNCATED); /* 2 of 3 bytes */

	/* map<string,string>: hostile count, and a count of one more than there are entries */
	le32(w, 0xFFFFFFFFu);
	EXPECT_FAIL(K_MAP, w, 4, WR_E_TOOBIG);
	for (i = 4; i < 64; i++)
		w[i] = 0; /* plenty of zero bytes: 15 empty-entry pairs would fit, 4G do not */
	EXPECT_FAIL(K_MAP, w, 64, WR_E_TOOBIG);
	le32(w, 8); /* 8 entries claim 64 bytes, 60 are left */
	EXPECT_FAIL(K_MAP, w, 64, WR_E_TOOBIG);
	le32(w, 2); /* one empty pair present, the second one missing */
	memset(w + 4, 0, 8);
	EXPECT_FAIL(K_MAP, w, 12, WR_E_TOOBIG);
	/* a value string whose length is hostile, inside a good count */
	le32(w, 1);
	le32(w + 4, 0); /* key "" */
	le32(w + 8, 0xFFFFFFFFu);
	EXPECT_FAIL(K_MAP, w, 12, WR_E_TRUNCATED);

	/* map<string,map<string,string>>: outer count */
	le32(w, 0xFFFFFFFFu);
	EXPECT_FAIL(K_MAPMAP, w, 4, WR_E_TOOBIG);
	le32(w, 0x20000000u);
	memset(w + 4, 0, 60);
	EXPECT_FAIL(K_MAPMAP, w, 64, WR_E_TOOBIG);
	/* inner count (one outer entry: key "a", then the inner map) */
	le32(w, 1);
	le32(w + 4, 1);
	w[8] = 'a';
	le32(w + 9, 0xFFFFFFFFu);
	EXPECT_FAIL(K_MAPMAP, w, 13, WR_E_TOOBIG);
	/* inner key string length */
	le32(w + 9, 1);
	le32(w + 13, 0xFFFFFFFFu);
	le32(w + 17, 0); /* pad, so that the inner entry passes the count check */
	EXPECT_FAIL(K_MAPMAP, w, 21, WR_E_TRUNCATED);
	/* key string length at the outer level */
	le32(w, 1);
	le32(w + 4, 0xFFFFFFFFu);
	le32(w + 8, 0);
	EXPECT_FAIL(K_MAPMAP, w, 12, WR_E_TRUNCATED);
	/* inner count that fits the bytes left but then the entries are missing */
	le32(w, 1);
	le32(w + 4, 0);
	le32(w + 8, 1); /* one inner entry */
	memset(w + 12, 0, 4);
	EXPECT_FAIL(K_MAPMAP, w, 16, WR_E_TOOBIG);

	/* interval set */
	le32(w, 0xFFFFFFFFu);
	EXPECT_FAIL(K_IVSET, w, 4, WR_E_TOOBIG);
	le32(w, 0x10000000u); /* 2^28 * 16 wraps a 32-bit size_t to 0: must still be refused */
	memset(w + 4, 0, 32);
	EXPECT_FAIL(K_IVSET, w, 36, WR_E_TOOBIG);
	le32(w, 0x10000001u);
	EXPECT_FAIL(K_IVSET, w, 36, WR_E_TOOBIG);
	le32(w, 3); /* 48 bytes claimed, 32 present */
	EXPECT_FAIL(K_IVSET, w, 36, WR_E_TOOBIG);

	/* envelope */
	w[0] = 1;
	w[1] = 1;
	le32(w + 2, 0xFFFFFFFFu);
	EXPECT_FAIL(K_ENV, w, 6, WR_E_TRUNCATED);
	le32(w + 2, 1);
	EXPECT_FAIL(K_ENV, w, 6, WR_E_TRUNCATED);

	/* vector<s32> with a cap */
	le32(w, 0xFFFFFFFFu);
	EXPECT_FAIL(K_VEC, w, 4, WR_E_TOOBIG);
	le32(w, 0x40000000u); /* 2^30 * 4 wraps a 32-bit size_t */
	memset(w + 4, 0, 16);
	EXPECT_FAIL(K_VEC, w, 20, WR_E_TOOBIG);
	le32(w, VEC_MAX + 1); /* above the cap although the bytes are there */
	memset(w + 4, 0, 40);
	EXPECT_FAIL(K_VEC, w, 4 + 4 * (VEC_MAX + 1), WR_E_TOOBIG);
	le32(w, VEC_MAX); /* exactly the cap is fine */
	{
		uint8_t *buf = dup_bytes(w, 4 + 4 * VEC_MAX);
		wri_rd r;

		wri_rd_init(&r, buf, 4 + 4 * VEC_MAX);
		wri_denc_skip_i32_vec(&r, VEC_MAX);
		WRT_CHECK(wri_rd_ok(&r));
		WRT_CHECK_U64(wri_rd_left(&r), 0);
		free(buf);
	}
	/* within the cap, but the bytes for all elements (4 each, not 1) are not there: refused by the count, not later */
	le32(w, VEC_MAX);
	memset(w + 4, 0, 40);
	EXPECT_FAIL(K_VEC, w, 4 + 4 * VEC_MAX - 1, WR_E_TOOBIG);
	/* the same for the two nested maps: the smallest entry is 8 bytes, so n entries need 8 * n bytes up front */
	le32(w, 2);
	memset(w + 4, 0, 60);
	EXPECT_FAIL(K_MAPMAP, w, 4 + 15, WR_E_TOOBIG); /* 15 bytes for two entries of 8 */
	EXPECT_FAIL(K_MAP, w, 4 + 15, WR_E_TOOBIG);
	{
		uint8_t *buf = dup_bytes(w, 4 + 16); /* exactly the smallest entries: fine */
		wri_rd r;

		wri_rd_init(&r, buf, 4 + 16);
		wri_denc_skip_str_map_map(&r);
		WRT_CHECK(wri_rd_ok(&r));
		WRT_CHECK_U64(r.pos, 4 + 16);
		wri_rd_init(&r, buf, 4 + 16);
		wri_denc_skip_str_map(&r);
		WRT_CHECK(wri_rd_ok(&r));
		WRT_CHECK_U64(r.pos, 4 + 16);
		free(buf);
	}
	/* max 0 allows only the empty vector */
	le32(w, 1);
	memset(w + 4, 0, 4);
	{
		uint8_t *buf = dup_bytes(w, 8);
		wri_rd r;

		wri_rd_init(&r, buf, 8);
		wri_denc_skip_i32_vec(&r, 0);
		WRT_CHECK_U64(r.err, WR_E_TOOBIG);
		free(buf);
	}
}

static void test_count(void)
{
	uint8_t w[40];
	uint8_t *buf;
	wri_rd r;

	memset(w, 0, sizeof(w));

	le32(w, 5);
	buf = dup_bytes(w, 4 + 20);
	wri_rd_init(&r, buf, 24);
	WRT_CHECK_U64(wri_denc_count(&r, 5, 4), 5); /* exactly max, exactly the bytes */
	WRT_CHECK(wri_rd_ok(&r));
	free(buf);

	buf = dup_bytes(w, 4 + 19);
	wri_rd_init(&r, buf, 23);
	WRT_CHECK_U64(wri_denc_count(&r, 5, 4), 0); /* one byte short */
	WRT_CHECK_U64(r.err, WR_E_TOOBIG);
	free(buf);

	buf = dup_bytes(w, 24);
	wri_rd_init(&r, buf, 24);
	WRT_CHECK_U64(wri_denc_count(&r, 4, 4), 0); /* above max */
	WRT_CHECK_U64(r.err, WR_E_TOOBIG);
	free(buf);

	le32(w, 1000);
	buf = dup_bytes(w, 4);
	wri_rd_init(&r, buf, 4);
	WRT_CHECK_U64(wri_denc_count(&r, 0xFFFFFFFFu, 0), 1000); /* elem_min 0: only max applies */
	free(buf);

	buf = dup_bytes(w, 3);
	wri_rd_init(&r, buf, 3);
	WRT_CHECK_U64(wri_denc_count(&r, 10, 1), 0);
	WRT_CHECK_U64(r.err, WR_E_TRUNCATED);
	free(buf);
}

/* ---- differential check against the reference walkers ------------------------------------- */

static void diff_one(int kind, const uint8_t *wire, size_t n)
{
	uint8_t *buf = dup_bytes(wire, n);
	wri_rd r;
	size_t want = do_ref(kind, buf, n);

	wri_rd_init(&r, buf, n);
	do_skip(kind, &r);
	wrt_checks++;
	if (want == REF_FAIL ? r.err == WR_OK : (r.err != WR_OK || r.pos != want)) {
		wrt_failures++;
		fprintf(stderr, "%s:%d: %s differs from the reference: skip %s pos %zu, reference %s %zu (n=%zu)\n",
			__FILE__, __LINE__, kind_name[kind], r.err == WR_OK ? "ok" : "fail", r.pos,
			want == REF_FAIL ? "fail" : "ok", want == REF_FAIL ? (size_t)0 : want, n);
	}
	free(buf);
}

static void test_skip_differential(void)
{
	int kind;
	unsigned iter;

	for (kind = 0; kind < K_COUNT; kind++) {
		for (iter = 0; iter < 3000; iter++) {
			uint8_t wire[512];
			wri_wr w;
			size_t n, i, flips;

			wri_wr_init(&w, wire, sizeof(wire));
			gen(kind, &w);
			n = wri_wr_len(&w);
			diff_one(kind, wire, n); /* valid */

			/* mutated: flip 1 to 3 bytes (counts and lengths get hit often enough) */
			flips = 1 + rnd() % 3;
			for (i = 0; i < flips && n > 0; i++)
				wire[rnd() % n] = (uint8_t)(rnd() % 3 == 0 ? 0xFF : rnd());
			diff_one(kind, wire, n);
			if (n > 0)
				diff_one(kind, wire, rnd() % n); /* mutated and cut */
		}
		/* garbage biased towards small numbers, so that counts and lengths are often plausible */
		for (iter = 0; iter < 3000; iter++) {
			static const uint8_t pal[] = {0, 0, 0, 0, 1, 2, 3, 4, 0xFF, 8, 16};
			uint8_t wire[96];
			size_t n = rnd() % sizeof(wire), i;

			for (i = 0; i < n; i++)
				wire[i] = pal[rnd() % sizeof(pal)];
			diff_one(kind, wire, n);
		}
	}
}

/* ---- the pools of full-e42.hex, walked with the skip helpers only ------------------------- */

/*
 * Reads the vector (the file has '#' comment lines), decodes the hex. Returns the bytes in a malloc'd buffer.
 */
static int load_e42(uint8_t **out, size_t *n)
{
	uint8_t *raw;
	size_t rawn, i, k = 0;
	char *clean;
	int rc;

	if (wrt_read_file(wrt_vec_path("osdmap/full-e42.hex"), &raw, &rawn) != 0)
		return -1;
	clean = (char *)malloc(rawn + 1);
	if (!clean) {
		free(raw);
		return -1;
	}
	for (i = 0; i < rawn;) {
		size_t j = i;

		while (j < rawn && raw[j] != '\n')
			j++;
		if (raw[i] != '#') {
			memcpy(clean + k, raw + i, j - i);
			k += j - i;
			clean[k++] = '\n';
		}
		i = j + 1;
	}
	rc = wrt_hex_decode(clean, k, out, n);
	free(clean);
	free(raw);
	return rc;
}

/* check one skip against the reference walker, and the size it consumed */
#define WALK_SKIP(body, helper, ref)                                                              \
	do {                                                                                      \
		size_t start_ = (body)->pos;                                                      \
		size_t want_ = wri_rd_ok(body) ? ref((body)->p, (body)->len, start_) : REF_FAIL;   \
		helper(body);                                                                     \
		if (strict) {                                                                     \
			WRT_CHECK(wri_rd_ok(body));                                               \
			WRT_CHECK(want_ != REF_FAIL && (body)->pos == want_);                     \
		}                                                                                 \
	} while (0)

static size_t ref_ivset(const uint8_t *b, size_t len, size_t off)
{
	return ref_fixed_vec(b, len, off, 16, 0xFFFFFFFFu);
}

/* the field table of osdmap.md 2.5 for a pool of struct_v >= 29; fixed-width fields are read with the cursor
 * primitives, everything that has to be stepped over goes through the skip helpers */
/* what a walk saw, so that a test can tell that the interesting (non-empty) structures were really present */
typedef struct pool_stats {
	uint32_t nsnaps;     /* pool snapshots (map<u64, envelope>) */
	uint32_t ntiers;     /* set<u64> */
	size_t hit_set_len;  /* bytes of the hit_set_params envelope, header included */
	size_t opts_len;     /* bytes of the pool opts envelope */
	size_t appmeta_len;  /* bytes of application_metadata */
} pool_stats;

static void walk_pool(wri_rd *b, uint8_t v, int strict, pool_stats *st)
{
	uint32_t n, i;
	size_t mark;

	(void)wri_rd_u8(b);                   /* type */
	(void)wri_rd_u8(b);                   /* size */
	(void)wri_rd_u8(b);                   /* crush_rule */
	(void)wri_rd_u8(b);                   /* object_hash */
	wri_rd_skip(b, 4 * 2 + 4 * 2 + 4);    /* pg_num, pgp_num, lpg_num, lpgp_num, last_change */
	wri_rd_skip(b, 8 + 4);                /* snap_seq, snap_epoch */
	n = wri_denc_count(b, 0xFFFFFFFFu, 8 + 6); /* snaps: map<u64, envelope> */
	if (st)
		st->nsnaps = n;
	for (i = 0; i < n && wri_rd_ok(b); i++) {
		wri_rd_skip(b, 8);
		WALK_SKIP(b, wri_denc_skip_env, ref_env);
	}
	WALK_SKIP(b, wri_denc_skip_interval_set, ref_ivset); /* removed_snaps */
	wri_rd_skip(b, 8 + 8 + 4);            /* auid, flags, crash_replay_interval */
	(void)wri_rd_u8(b);                   /* min_size */
	wri_rd_skip(b, 8 + 8);                /* quotas */
	n = wri_denc_count(b, 0xFFFFFFFFu, 8); /* tiers: set<u64> */
	if (st)
		st->ntiers = n;
	wri_rd_skip(b, (size_t)n * 8);
	wri_rd_skip(b, 8);                    /* tier_of */
	(void)wri_rd_u8(b);                   /* cache_mode */
	wri_rd_skip(b, 8 + 8);                /* read_tier, write_tier */
	WALK_SKIP(b, wri_denc_skip_str_map, ref_str_map); /* properties */
	mark = b->pos;
	WALK_SKIP(b, wri_denc_skip_env, ref_env);         /* hit_set_params */
	if (st)
		st->hit_set_len = b->pos - mark;
	wri_rd_skip(b, 4 + 4);                /* hit_set_period, hit_set_count */
	wri_rd_skip(b, 4);                    /* stripe_width */
	wri_rd_skip(b, 8 + 8);                /* target_max_bytes, target_max_objects */
	wri_rd_skip(b, 4 + 4);                /* cache ratios */
	wri_rd_skip(b, 4 + 4);                /* cache min flush / evict age */
	WALK_SKIP(b, wri_denc_skip_str, ref_str); /* erasure_code_profile */
	wri_rd_skip(b, 4);                    /* last_force_op_resend_preluminous */
	wri_rd_skip(b, 4);                    /* min_read_recency_for_promote */
	wri_rd_skip(b, 8);                    /* expected_num_objects */
	wri_rd_skip(b, 4);                    /* cache_target_dirty_high_ratio_micro */
	wri_rd_skip(b, 4);                    /* min_write_recency_for_promote */
	wri_rd_skip(b, 1 + 1);                /* use_gmt_hitset, fast_read */
	wri_rd_skip(b, 4 + 4);                /* hit_set_grade_decay_rate, hit_set_search_last_n */
	mark = b->pos;
	WALK_SKIP(b, wri_denc_skip_env, ref_env);         /* opts */
	if (st)
		st->opts_len = b->pos - mark;
	wri_rd_skip(b, 4);                    /* last_force_op_resend_prenautilus */
	mark = b->pos;
	WALK_SKIP(b, wri_denc_skip_str_map_map, ref_str_map_map); /* application_metadata */
	if (st)
		st->appmeta_len = b->pos - mark;
	wri_rd_skip(b, 8);                    /* create_time */
	wri_rd_skip(b, 4 * 3);                /* pg_num_target, pgp_num_target, pg_num_pending */
	wri_rd_skip(b, 4 + 4);                /* two ignored epochs */
	wri_rd_skip(b, 4);                    /* last_force_op_resend */
	(void)wri_rd_u8(b);                   /* pg_autoscale_mode */
	WALK_SKIP(b, wri_denc_skip_env, ref_env); /* last_pg_merge_meta, v >= 29 */
	if (v == 30) {
		wri_rd_skip(b, 4 * 3 + 4); /* stretch fields */
	} else if (v >= 31) {
		uint8_t present = wri_rd_u8(b);

		if (present)
			wri_rd_skip(b, 16);
	}
	if (v >= 32) {
		(void)wri_denc_varint(b);
		(void)wri_denc_varint(b);
	}
}

#define MAX_POOLS 16

/*
 * Walk the pools of one full map with the skip helpers only: every pool must end exactly on its envelope end, the pool
 * names must follow right after, then pool_max. Returns the number of pools; fills stats[]. `cut_check` also walks every
 * pool through every shorter buffer.
 */
static uint32_t walk_map(const uint8_t *map, size_t mapn, pool_stats *stats, uint32_t *pool_ids, uint32_t *pool_max, int cut_check)
{
	wri_rd r;
	wri_env wrap, cb;
	uint32_t npools, i, nnames;

	wri_rd_init(&r, map, mapn);
	WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&r, 7, 7, 7, 7, &wrap)); /* wrapper v8 */
	WRT_CHECK_U64(wrap.v, 8);
	WRT_CHECK_U64(wrap.compat, 7);
	/* the crc follows the two blocks and is part of the wrapper body, so the parent is at its end */
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&wrap.body, 1, &cb)); /* client block, a modern envelope */
	WRT_CHECK_U64(cb.v, 10);
	wri_rd_skip(&cb.body, 16 + 4 + 8 + 8); /* fsid, epoch, created, modified */

	npools = wri_denc_count(&cb.body, 0xFFFFFFFFu, 8 + 6);
	WRT_CHECK(npools >= 1 && npools <= MAX_POOLS);
	if (npools > MAX_POOLS)
		return 0;
	for (i = 0; i < npools && wri_rd_ok(&cb.body); i++) {
		wri_env pe;
		uint64_t id = wri_rd_u64(&cb.body); /* pool id */

		pool_ids[i] = (uint32_t)id;
		WRT_CHECK(id < 0x80000000ull); /* a tracked pool id is below 2^31 */
		memset(&stats[i], 0, sizeof(stats[i]));
		WRT_CHECK_STATUS(WR_OK, wri_env_open_legacy(&cb.body, 5, 5, 5, 5, &pe));
		WRT_CHECK_U64(pe.v, 32);
		WRT_CHECK_U64(pe.compat, 5);
		walk_pool(&pe.body, pe.v, 1, &stats[i]);
		/* the walk must end exactly on the envelope end */
		WRT_CHECK(wri_rd_ok(&pe.body));
		WRT_CHECK_U64(wri_rd_left(&pe.body), 0);
		/* every pool walked through every shorter buffer: the walk must fail, never read past the cut */
		if (cut_check) {
			size_t cut;

			for (cut = 0; cut < pe.body.len; cut++) {
				uint8_t *copy = dup_bytes(pe.body.p, cut);
				wri_rd body;

				wri_rd_init(&body, copy, cut);
				walk_pool(&body, pe.v, 0, NULL);
				WRT_CHECK(!wri_rd_ok(&body));
				free(copy);
			}
		}
	}
	/* the pool names follow immediately: a count of npools only if the pool walks left the parent in the right place */
	nnames = wri_denc_count(&cb.body, 0xFFFFFFFFu, 8 + 4);
	WRT_CHECK_U64(nnames, npools);
	for (i = 0; i < nnames; i++) {
		wri_rd_skip(&cb.body, 8);
		wri_denc_skip_str(&cb.body);
	}
	WRT_CHECK(wri_rd_ok(&cb.body));
	*pool_max = wri_rd_u32(&cb.body);
	WRT_CHECK(wri_rd_ok(&cb.body));

	return npools;
}

static void test_e42_pools(void)
{
	uint8_t *map;
	size_t mapn;
	pool_stats st[MAX_POOLS];
	uint32_t ids[MAX_POOLS], pmax = 0;

	if (load_e42(&map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load osdmap/full-e42.hex");
		return;
	}
	WRT_CHECK_U64(walk_map(map, mapn, st, ids, &pmax, 1), 2);
	free(map);
}

/*
 * public/denc-map/pools-e202.bin: `ceph osd getmap 202` of the lab after creating pools that make the optional parts of
 * pg_pool_t non-empty (ground truth: pools-e202.txt, the `ceph osd dump` pool lines). Pool 9 has two pool snapshots,
 * recorded options and application metadata; pool 10 has a cache tier (pool 12); pool 12 has hit_set parameters.
 * Walked with the skip helpers only, every pool must end exactly on its envelope end.
 */
static void test_pools_e202(void)
{
	uint8_t *map;
	size_t mapn;
	pool_stats st[MAX_POOLS];
	uint32_t ids[MAX_POOLS], pmax = 0, i, n;
	static const uint32_t want_ids[] = {1, 2, 7, 8, 9, 10, 11, 12};

	if (wrt_read_file(wrt_vec_path("public/denc-map/pools-e202.bin"), &map, &mapn) != 0) {
		WRT_CHECK(0 && "cannot load public/denc-map/pools-e202.bin");
		return;
	}
	n = walk_map(map, mapn, st, ids, &pmax, 1);
	WRT_CHECK_U64(n, 8);
	WRT_CHECK_U64(pmax, 12);
	for (i = 0; i < n && i < 8; i++)
		WRT_CHECK_U64(ids[i], want_ids[i]);
	if (n == 8) {
		/* pool 2 ('winrbd') has none of the optional parts: the baseline sizes */
		WRT_CHECK_U64(st[1].nsnaps, 0);
		WRT_CHECK_U64(st[1].ntiers, 0);
		/* pool 9: two pool snapshots, non-empty options and application metadata */
		WRT_CHECK_U64(st[4].nsnaps, 2);
		WRT_CHECK(st[4].opts_len > st[1].opts_len);
		WRT_CHECK(st[4].appmeta_len > st[1].appmeta_len);
		/* pool 10: one tier, two application metadata keys under one application */
		WRT_CHECK_U64(st[5].ntiers, 1);
		WRT_CHECK(st[5].appmeta_len > st[1].appmeta_len);
		/* pool 12: bloom hit set parameters */
		WRT_CHECK(st[7].hit_set_len > st[1].hit_set_len);
		WRT_CHECK_U64(st[7].ntiers, 0);
	}
	free(map);
}

/* ---- main --------------------------------------------------------------------------------- */

int main(void)
{
	test_legacy_thresholds();
	test_legacy_compat_limit();
	test_legacy_truncation();
	test_legacy_misc();
	test_pg();
	test_varint_known();
	test_varint_overflow();
	test_varint_roundtrip();
	test_skip_truncation();
	test_skip_empty_and_sticky();
	test_skip_hostile();
	test_count();
	test_skip_differential();
	test_e42_pools();
	test_pools_e202();
	return wrt_finish();
}
