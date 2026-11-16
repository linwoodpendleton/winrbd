/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of core/src/denc/wri_denc.c: versioned envelopes (open, compat check, truncation,
 * nesting, skip-to-end, writer back-patch), blobs and strings with a cap, utime.
 *
 * Buffers handed to the code under test are exact-size heap allocations, so under ASan any read
 * or write outside them is reported.
 */
#include "wrt.h"

#include "wri_denc.h"

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

/* ---- open: the plain case ----------------------------------------------------------------- */

static void test_open_basic(void)
{
	static const uint8_t wire[] = {2, 1, 5, 0, 0, 0, 'h', 'e', 'l', 'l', 'o', 0xAA, 0xBB};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env e;
	const uint8_t *p;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(e.v, 2);
	WRT_CHECK_U64(e.compat, 1);
	WRT_CHECK_U64(e.body.len, 5);
	WRT_CHECK_U64(e.body.pos, 0);
	/* the parent is already past the body; the two trailing bytes are the parent's */
	WRT_CHECK_U64(wri_rd_left(&r), 2);
	p = wri_rd_bytes(&e.body, 5);
	WRT_CHECK(p != NULL && memcmp(p, "hello", 5) == 0);
	WRT_CHECK_U64(wri_rd_u8(&r), 0xAA);
	WRT_CHECK_U64(wri_rd_u8(&r), 0xBB);
	WRT_CHECK(wri_rd_ok(&r) && wri_rd_ok(&e.body));
	free(buf);
}

static void test_open_empty_body(void)
{
	static const uint8_t wire[] = {1, 1, 0, 0, 0, 0};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(e.body.len, 0);
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	WRT_CHECK(wri_rd_ok(&e.body));
	free(buf);
}

static void test_open_bad_args(void)
{
	static const uint8_t wire[] = {1, 1, 0, 0, 0, 0};
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, wire, sizeof(wire));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_env_open(&r, 1, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_env_open(NULL, 1, &e));
	WRT_CHECK_U64(e.body.len, 0);
}

/* ---- truncation --------------------------------------------------------------------------- */

static void test_open_every_truncation(void)
{
	static const uint8_t wire[] = {3, 2, 7, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7};
	size_t n;

	for (n = 0; n < sizeof(wire); n++) {
		uint8_t *buf = dup_bytes(wire, n); /* exactly n bytes: ASan sees any over-read */
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, n);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open(&r, 2, &e));
		WRT_CHECK(!wri_rd_ok(&r));
		/* a caller that ignores the status gets an errored, empty body */
		WRT_CHECK(!wri_rd_ok(&e.body));
		WRT_CHECK_U64(wri_rd_u8(&e.body), 0);
		free(buf);
	}
	{
		uint8_t *buf = dup_bytes(wire, sizeof(wire));
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, buf, sizeof(wire));
		WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 2, &e));
		free(buf);
	}
}

static void test_open_huge_len(void)
{
	static const uint8_t wire[] = {1, 1, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open(&r, 1, &e));
	free(buf);
}

/* ---- compat ------------------------------------------------------------------------------- */

static void test_open_compat(void)
{
	/* struct_v 9, struct_compat 3, two body bytes */
	static const uint8_t wire[] = {9, 3, 2, 0, 0, 0, 0x11, 0x22};
	uint8_t sup;

	for (sup = 0; sup <= 5; sup++) {
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, wire, sizeof(wire));
		if (sup >= 3) {
			WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, sup, &e));
			WRT_CHECK_U64(e.v, 9); /* v above compat is fine */
		} else {
			WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_env_open(&r, sup, &e));
			WRT_CHECK(!wri_rd_ok(&r));
		}
	}
	{
		/* compat is checked before the length: an unreadable body is "unsupported", not
		 * "truncated", even when it also claims more bytes than exist */
		static const uint8_t big[] = {5, 5, 0xFF, 0xFF, 0, 0};
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, big, sizeof(big));
		WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_env_open(&r, 4, &e));
	}
	{
		/* compat 0 is accepted by every reader */
		static const uint8_t zero[] = {0, 0, 0, 0, 0, 0};
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, zero, sizeof(zero));
		WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 0, &e));
	}
	{
		/* 255 against 255 */
		static const uint8_t top[] = {255, 255, 0, 0, 0, 0};
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, top, sizeof(top));
		WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 255, &e));
		wri_rd_init(&r, top, sizeof(top));
		WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_env_open(&r, 254, &e));
	}
}

static void test_open_sticky(void)
{
	static const uint8_t wire[] = {1, 9, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0};
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, wire, sizeof(wire));
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_env_open(&r, 1, &e));
	/* first failure wins: the second envelope is fine but the reader is already failed */
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_env_open(&r, 1, &e));
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, r.err);
}

/* ---- skip to end, nesting ----------------------------------------------------------------- */

static void test_skip_to_end(void)
{
	/* The reader of version 1 knows one u16 field; the writer was version 3 and appended
	 * ten more bytes. After the envelope, a trailing u32 field of the parent must be next. */
	static const uint8_t wire[] = {3, 1, 12, 0, 0, 0, 0x34, 0x12, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
				       0xEF, 0xBE, 0xAD, 0xDE};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(wri_rd_u16(&e.body), 0x1234);
	WRT_CHECK_U64(wri_rd_left(&e.body), 10); /* never read: skipped for free */
	WRT_CHECK_U64(wri_rd_u32(&r), 0xDEADBEEFu);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	free(buf);
}

static void test_body_is_bounded(void)
{
	/* A decoder that reads more than the body holds must fail on the body, not eat the
	 * parent's next field. */
	static const uint8_t wire[] = {1, 1, 2, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env e;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(wri_rd_u32(&e.body), 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, e.body.err);
	WRT_CHECK(wri_rd_ok(&r)); /* the parent is unharmed */
	WRT_CHECK_U64(wri_rd_u32(&r), 0x06050403u);
	free(buf);
}

static void test_nested(void)
{
	/* outer(v2): u8 0x55, inner(v1): u32 0xCAFEF00D, + 2 junk bytes inside inner, u8 0x66 */
	static const uint8_t wire[] = {2,    1,    14,   0,    0,    0,    0x55, 1,    1,    6,    0,
				       0,    0,    0x0D, 0xF0, 0xFE, 0xCA, 0x77, 0x88, 0x66, 0x99};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env outer, inner;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &outer));
	WRT_CHECK_U64(outer.body.len, 14);
	WRT_CHECK_U64(wri_rd_left(&r), 1); /* 0x99 is outside */
	WRT_CHECK_U64(wri_rd_u8(&outer.body), 0x55);
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&outer.body, 1, &inner));
	WRT_CHECK_U64(inner.body.len, 6);
	WRT_CHECK_U64(wri_rd_u32(&inner.body), 0xCAFEF00Du);
	/* inner's two leftover bytes are skipped: outer continues with its own next byte */
	WRT_CHECK_U64(wri_rd_u8(&outer.body), 0x66);
	WRT_CHECK_U64(wri_rd_left(&outer.body), 0);
	WRT_CHECK_U64(wri_rd_u8(&r), 0x99);
	WRT_CHECK(wri_rd_ok(&r) && wri_rd_ok(&outer.body) && wri_rd_ok(&inner.body));
	free(buf);
}

static void test_inner_longer_than_outer(void)
{
	/* the inner envelope claims more bytes than the outer body has left */
	static const uint8_t wire[] = {1, 1, 8, 0, 0, 0, 1, 1, 100, 0, 0, 0, 0, 0};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	wri_env outer, inner;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &outer));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, wri_env_open(&outer.body, 1, &inner));
	WRT_CHECK(wri_rd_ok(&r));
	free(buf);
}

#define DEPTH 8

static void test_nested_depth_iterative(void)
{
	/* eight nested envelopes, written then read with explicit stacks and no recursion */
	uint8_t out[256];
	size_t marks[DEPTH];
	wri_wr w;
	wri_rd stack[DEPTH + 1];
	wri_env e;
	unsigned i;
	uint8_t *buf;
	size_t n;

	wri_wr_init(&w, out, sizeof(out));
	for (i = 0; i < DEPTH; i++) {
		marks[i] = wri_env_begin(&w, (uint8_t)(i + 1), 1);
		wri_wr_u8(&w, (uint8_t)(0xA0 + i));
	}
	wri_wr_u32(&w, 0x0BADF00Du);
	for (i = DEPTH; i-- > 0;)
		wri_env_end(&w, marks[i]);
	WRT_CHECK(wri_wr_ok(&w));
	n = wri_wr_len(&w);
	WRT_CHECK_U64(n, 8u * (6u + 1u) + 4u);

	buf = dup_bytes(out, n);
	wri_rd_init(&stack[0], buf, n);
	for (i = 0; i < DEPTH; i++) {
		WRT_CHECK_STATUS(WR_OK, wri_env_open(&stack[i], 1, &e));
		WRT_CHECK_U64(e.v, i + 1);
		WRT_CHECK_U64(wri_rd_u8(&e.body), 0xA0 + i);
		stack[i + 1] = e.body;
	}
	WRT_CHECK_U64(wri_rd_u32(&stack[DEPTH]), 0x0BADF00Du);
	WRT_CHECK_U64(wri_rd_left(&stack[DEPTH]), 0);
	for (i = 0; i < DEPTH; i++)
		WRT_CHECK_U64(wri_rd_left(&stack[i]), 0);
	free(buf);
}

/* ---- writer ------------------------------------------------------------------------------- */

static void test_writer_roundtrip(void)
{
	uint8_t out[64];
	wri_wr w;
	size_t mark;
	static const uint8_t want[] = {4, 2, 7, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 0xAA, 0xBB, 0xCC};

	wri_wr_init(&w, out, sizeof(out));
	mark = wri_env_begin(&w, 4, 2);
	WRT_CHECK_U64(mark, 2);
	WRT_CHECK_U64(wri_wr_len(&w), 6);
	wri_wr_u32(&w, 0x12345678u);
	wri_wr_u8(&w, 0xAA);
	wri_wr_u8(&w, 0xBB);
	wri_wr_u8(&w, 0xCC);
	wri_env_end(&w, mark);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), sizeof(want));
	WRT_CHECK_MEM(out, want, sizeof(want));

	{
		wri_rd r;
		wri_env e;

		wri_rd_init(&r, out, wri_wr_len(&w));
		WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 2, &e));
		WRT_CHECK_U64(e.v, 4);
		WRT_CHECK_U64(wri_rd_u32(&e.body), 0x12345678u);
		WRT_CHECK_U64(wri_rd_left(&e.body), 3);
	}
}

static void test_writer_empty_body(void)
{
	uint8_t out[8];
	wri_wr w;
	size_t mark;
	static const uint8_t want[] = {1, 1, 0, 0, 0, 0};

	wri_wr_init(&w, out, sizeof(out));
	mark = wri_env_begin(&w, 1, 1);
	wri_env_end(&w, mark);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 6);
	WRT_CHECK_MEM(out, want, sizeof(want));
}

static void test_writer_sibling_and_offset(void)
{
	/* two envelopes in a row after other data: each patch lands on its own length field */
	uint8_t out[64];
	wri_wr w;
	size_t m1, m2;
	wri_rd r;
	wri_env e;

	wri_wr_init(&w, out, sizeof(out));
	wri_wr_u32(&w, 0x11111111u);
	m1 = wri_env_begin(&w, 1, 1);
	wri_wr_u16(&w, 0x2222);
	wri_env_end(&w, m1);
	m2 = wri_env_begin(&w, 2, 1);
	wri_wr_u8(&w, 0x33);
	wri_env_end(&w, m2);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(m1, 6);
	WRT_CHECK_U64(m2, 6 + 4 + 2 + 2);

	wri_rd_init(&r, out, wri_wr_len(&w));
	WRT_CHECK_U64(wri_rd_u32(&r), 0x11111111u);
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(e.body.len, 2);
	WRT_CHECK_STATUS(WR_OK, wri_env_open(&r, 1, &e));
	WRT_CHECK_U64(e.v, 2);
	WRT_CHECK_U64(e.body.len, 1);
	WRT_CHECK_U64(wri_rd_left(&r), 0);
}

static void test_writer_overflow_every_cap(void)
{
	/* the same envelope into every too-small exact-size heap buffer: error, never a write past cap */
	size_t cap;

	for (cap = 0; cap <= 10; cap++) {
		uint8_t *buf = (uint8_t *)malloc(cap ? cap : 1);
		wri_wr w;
		size_t mark;

		WRT_CHECK(buf != NULL);
		wri_wr_init(&w, buf, cap);
		mark = wri_env_begin(&w, 1, 1);
		wri_wr_u32(&w, 0xFFFFFFFFu);
		wri_env_end(&w, mark);
		if (cap < 10) {
			WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
		} else {
			WRT_CHECK(wri_wr_ok(&w));
			WRT_CHECK_U64(wri_wr_len(&w), 10);
		}
		free(buf);
	}
}

static void test_writer_end_bad_mark(void)
{
	uint8_t out[16];
	wri_wr w;

	wri_wr_init(&w, out, sizeof(out));
	wri_wr_u8(&w, 1);
	wri_env_end(&w, 0); /* only one byte written: no room for a length field */
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);

	wri_wr_init(&w, out, sizeof(out));
	wri_wr_u32(&w, 0);
	wri_env_end(&w, 1000);
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);

	/* an earlier error stays the error */
	wri_wr_init(&w, out, 2);
	wri_wr_u32(&w, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	wri_env_end(&w, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
}

/* ---- blobs and strings -------------------------------------------------------------------- */

static void test_blob_roundtrip(void)
{
	uint8_t out[64];
	wri_wr w;
	wri_rd r;
	uint32_t n = 99;
	const uint8_t *p;
	static const uint8_t data[] = {1, 2, 3, 4, 5};

	wri_wr_init(&w, out, sizeof(out));
	wri_denc_put_blob(&w, data, sizeof(data));
	wri_denc_put_str(&w, (const uint8_t *)"rbd", 3);
	wri_denc_put_blob(&w, NULL, 0);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 4 + 5 + 4 + 3 + 4);

	wri_rd_init(&r, out, wri_wr_len(&w));
	p = wri_denc_blob(&r, &n, 16);
	WRT_CHECK(p != NULL);
	WRT_CHECK_U64(n, 5);
	WRT_CHECK_MEM(p, data, 5);
	p = wri_denc_str(&r, &n, 3);
	WRT_CHECK(p != NULL && n == 3 && memcmp(p, "rbd", 3) == 0);
	p = wri_denc_blob(&r, &n, 0);
	WRT_CHECK(p != NULL);
	WRT_CHECK_U64(n, 0);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
}

static void test_blob_max(void)
{
	static const uint8_t wire[] = {5, 0, 0, 0, 1, 2, 3, 4, 5};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	uint32_t n = 77;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK(wri_denc_blob(&r, &n, 4) == NULL);
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	WRT_CHECK_U64(n, 0);

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK(wri_denc_blob(&r, &n, 5) != NULL);
	WRT_CHECK_U64(n, 5);
	WRT_CHECK(wri_rd_ok(&r));
	free(buf);
}

static void test_blob_hostile_len(void)
{
	/* the cap is applied before anything else: 0xFFFFFFFF is TOOBIG, not a huge read */
	static const uint8_t wire[] = {0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3};
	uint8_t *buf = dup_bytes(wire, sizeof(wire));
	wri_rd r;
	uint32_t n = 1;

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK(wri_denc_blob(&r, &n, 0xFFFFFFFFu) == NULL); /* cap allows it: now it is truncated */
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	WRT_CHECK_U64(n, 0);

	wri_rd_init(&r, buf, sizeof(wire));
	WRT_CHECK(wri_denc_blob(&r, &n, 1u << 20) == NULL);
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	free(buf);
}

static void test_blob_every_truncation(void)
{
	static const uint8_t wire[] = {3, 0, 0, 0, 'a', 'b', 'c'};
	size_t k;

	for (k = 0; k < sizeof(wire); k++) {
		uint8_t *buf = dup_bytes(wire, k);
		wri_rd r;
		uint32_t n = 5;

		wri_rd_init(&r, buf, k);
		WRT_CHECK(wri_denc_blob(&r, &n, 16) == NULL);
		WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
		WRT_CHECK_U64(n, 0);
		free(buf);
	}
}

static void test_blob_null_len_and_sticky(void)
{
	static const uint8_t wire[] = {1, 0, 0, 0, 'x', 1, 0, 0, 0, 'y'};
	wri_rd r;
	const uint8_t *p;

	wri_rd_init(&r, wire, sizeof(wire));
	p = wri_denc_blob(&r, NULL, 4); /* length out-parameter is optional */
	WRT_CHECK(p != NULL && *p == 'x');
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK(wri_denc_blob(&r, NULL, 4) == NULL);
	WRT_CHECK_STATUS(WR_E_ENCODING, r.err);
}

static void test_blob_writer_errors(void)
{
	uint8_t out[8];
	wri_wr w;
	static const uint8_t data[8] = {0};

	wri_wr_init(&w, out, sizeof(out));
	wri_denc_put_blob(&w, NULL, 3);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);

	wri_wr_init(&w, out, sizeof(out));
	wri_denc_put_blob(&w, data, 5); /* 4 + 5 > 8 */
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	{
		/* the length prefix alone does not leak a partial write past cap */
		uint8_t *buf = (uint8_t *)malloc(6);

		wri_wr_init(&w, buf, 6);
		wri_denc_put_blob(&w, data, 3);
		WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
		free(buf);
	}
}

/* ---- utime -------------------------------------------------------------------------------- */

static void test_utime(void)
{
	uint8_t out[8];
	wri_wr w;
	wri_rd r;
	uint32_t s = 1, ns = 1;
	static const uint8_t want[] = {0x80, 0x51, 0x01, 0x6A, 0x15, 0xCD, 0x5B, 0x07};

	wri_wr_init(&w, out, sizeof(out));
	wri_denc_put_utime(&w, 0x6A015180u, 123456789u);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_MEM(out, want, sizeof(want));

	wri_rd_init(&r, out, sizeof(out));
	wri_denc_utime(&r, &s, &ns);
	WRT_CHECK_U64(s, 0x6A015180u);
	WRT_CHECK_U64(ns, 123456789u);
	WRT_CHECK(wri_rd_ok(&r));

	{
		size_t k;

		for (k = 0; k < 8; k++) {
			uint8_t *buf = dup_bytes(out, k);

			wri_rd_init(&r, buf, k);
			s = ns = 9;
			wri_denc_utime(&r, &s, &ns);
			WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
			WRT_CHECK_U64(s | ns, k >= 4 ? 0x6A015180u : 0); /* sec read when it fit, nsec zero */
			free(buf);
		}
	}
	/* NULL out-parameters are accepted */
	wri_rd_init(&r, out, sizeof(out));
	wri_denc_utime(&r, NULL, NULL);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
}

int main(void)
{
	test_open_basic();
	test_open_empty_body();
	test_open_bad_args();
	test_open_every_truncation();
	test_open_huge_len();
	test_open_compat();
	test_open_sticky();
	test_skip_to_end();
	test_body_is_bounded();
	test_nested();
	test_inner_longer_than_outer();
	test_nested_depth_iterative();
	test_writer_roundtrip();
	test_writer_empty_body();
	test_writer_sibling_and_offset();
	test_writer_overflow_every_cap();
	test_writer_end_bad_mark();
	test_blob_roundtrip();
	test_blob_max();
	test_blob_hostile_len();
	test_blob_every_truncation();
	test_blob_null_len_and_sticky();
	test_blob_writer_errors();
	test_utime();
	return wrt_finish();
}
