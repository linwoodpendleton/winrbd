/* SPDX-License-Identifier: MIT */
/*
 * Unit tests of the bounds-checked cursors (core/src/util/wri_cursor.c): truncation at every
 * length of a sample structure, sticky errors, sub-readers, count caps, writer limits, patching.
 */
#include "wrt.h"
#include "wri_cursor.h"

/* A sample structure: u8 u16 u32 u64 i32 i64, a counted list of u16, a 5-byte blob. */
#define SAMPLE_LIST_N 3
#define SAMPLE_LEN (1 + 2 + 4 + 8 + 4 + 8 + 4 + 2 * SAMPLE_LIST_N + 5)

struct sample {
	uint8_t a;
	uint16_t b;
	uint32_t c;
	uint64_t d;
	int32_t e;
	int64_t f;
	uint32_t n;
	uint16_t list[8];
	uint8_t blob[5];
};

static void sample_encode(wri_wr *w)
{
	uint8_t blob[5] = {1, 2, 3, 4, 5};

	wri_wr_u8(w, 0xA1);
	wri_wr_u16(w, 0xB2C3);
	wri_wr_u32(w, 0xDEADBEEFu);
	wri_wr_u64(w, 0x0102030405060708ull);
	wri_wr_i32(w, -2);
	wri_wr_i64(w, -3);
	wri_wr_u32(w, SAMPLE_LIST_N);
	wri_wr_u16(w, 10);
	wri_wr_u16(w, 20);
	wri_wr_u16(w, 30);
	wri_wr_bytes(w, blob, sizeof(blob));
}

static void sample_decode(wri_rd *r, struct sample *s)
{
	uint32_t i;

	memset(s, 0xEE, sizeof(*s)); /* so a decoder that skips a field is visible */
	s->a = wri_rd_u8(r);
	s->b = wri_rd_u16(r);
	s->c = wri_rd_u32(r);
	s->d = wri_rd_u64(r);
	s->e = wri_rd_i32(r);
	s->f = wri_rd_i64(r);
	s->n = wri_rd_count(r, 8, 2);
	for (i = 0; i < s->n; i++)
		s->list[i] = wri_rd_u16(r);
	wri_rd_copy(r, s->blob, sizeof(s->blob));
}

static void test_roundtrip(void)
{
	uint8_t buf[SAMPLE_LEN];
	wri_wr w;
	wri_rd r;
	struct sample s;
	static const uint8_t first[] = {0xA1, 0xC3, 0xB2, 0xEF, 0xBE, 0xAD, 0xDE, 8, 7, 6, 5, 4, 3, 2, 1};

	wri_wr_init(&w, buf, sizeof(buf));
	sample_encode(&w);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), SAMPLE_LEN);
	WRT_CHECK_U64(wri_wr_left(&w), 0);
	WRT_CHECK_MEM(buf, first, sizeof(first)); /* little-endian on the wire */

	wri_rd_init(&r, buf, sizeof(buf));
	sample_decode(&r, &s);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	WRT_CHECK_U64(s.a, 0xA1);
	WRT_CHECK_U64(s.b, 0xB2C3);
	WRT_CHECK_U64(s.c, 0xDEADBEEFu);
	WRT_CHECK_U64(s.d, 0x0102030405060708ull);
	WRT_CHECK(s.e == -2);
	WRT_CHECK(s.f == -3);
	WRT_CHECK_U64(s.n, 3);
	WRT_CHECK_U64(s.list[2], 30);
	WRT_CHECK_U64(s.blob[4], 5);
}

/* Offset of the list count in the sample, and the bytes its list needs: a cut that leaves the count
 * readable but the list short is refused at the count (WR_E_TOOBIG, "cannot fit"), every other cut
 * runs out of bytes (WR_E_TRUNCATED). */
#define SAMPLE_COUNT_END (1 + 2 + 4 + 8 + 4 + 8 + 4)
#define SAMPLE_LIST_BYTES (2 * SAMPLE_LIST_N)

/* A reader over any prefix shorter than the whole structure must fail (never crash) and leave
 * nothing but zeros for the fields it could not read. */
static void test_every_truncation_point(void)
{
	uint8_t buf[SAMPLE_LEN];
	wri_wr w;
	size_t cut;

	wri_wr_init(&w, buf, sizeof(buf));
	sample_encode(&w);
	for (cut = 0; cut < SAMPLE_LEN; cut++) {
		wri_rd r;
		struct sample s;

		wri_rd_init(&r, buf, cut);
		sample_decode(&r, &s);
		WRT_CHECK(!wri_rd_ok(&r));
		if (cut >= SAMPLE_COUNT_END && cut < SAMPLE_COUNT_END + SAMPLE_LIST_BYTES)
			WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
		else
			WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
		WRT_CHECK_U64(wri_rd_left(&r), 0);
		WRT_CHECK(r.pos <= cut);
		/* the last field (the blob) can only have been read if everything fit */
		WRT_CHECK_U64(s.blob[0] | s.blob[4], 0);
	}
}

static void test_sticky_error(void)
{
	static const uint8_t b[] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t dst[4] = {9, 9, 9, 9};
	static const uint8_t zero4[4] = {0, 0, 0, 0};
	wri_rd r;
	size_t pos;

	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_u32(&r), 0x04030201u);
	WRT_CHECK_U64(wri_rd_u64(&r), 0); /* only 4 bytes left */
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	pos = r.pos;
	WRT_CHECK_U64(pos, 4); /* a failed read does not advance */
	/* the first failure wins and nothing is read any more, even a read that would fit */
	WRT_CHECK_U64(wri_rd_u8(&r), 0);
	WRT_CHECK_U64(wri_rd_u16(&r), 0);
	WRT_CHECK_U64(wri_rd_u32(&r), 0);
	WRT_CHECK(wri_rd_bytes(&r, 1) == NULL);
	wri_rd_skip(&r, 1);
	wri_rd_copy(&r, dst, sizeof(dst));
	WRT_CHECK_MEM(dst, zero4, 4); /* copy on a failed cursor zeroes the destination */
	WRT_CHECK_U64(r.pos, pos);
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err); /* does not overwrite */
	WRT_CHECK_U64(wri_rd_left(&r), 0);

	/* wri_rd_fail on a healthy cursor records the code and keeps pos */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, 2);
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK_STATUS(WR_E_ENCODING, r.err);
	WRT_CHECK_U64(r.pos, 2);
	WRT_CHECK_U64(wri_rd_u8(&r), 0);
	WRT_CHECK_STATUS(WR_E_ENCODING, r.err); /* a later read does not turn it into TRUNCATED */
}

static void test_bytes_skip_copy(void)
{
	static const uint8_t b[] = {10, 11, 12, 13, 14, 15};
	uint8_t dst[3];
	wri_rd r;
	const uint8_t *p;

	wri_rd_init(&r, b, sizeof(b));
	p = wri_rd_bytes(&r, 2);
	WRT_CHECK(p == b);
	wri_rd_skip(&r, 1);
	wri_rd_copy(&r, dst, 3);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(dst[0], 13);
	WRT_CHECK_U64(dst[2], 15);
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	/* exactly at the end: zero-length operations succeed, one more byte fails */
	WRT_CHECK(wri_rd_bytes(&r, 0) != NULL);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK(wri_rd_bytes(&r, 1) == NULL);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);

	/* huge n must not wrap */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, 1);
	WRT_CHECK(wri_rd_bytes(&r, (size_t)-1) == NULL);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, (size_t)-2);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
}

static void test_empty_and_null(void)
{
	wri_rd r;
	wri_wr w;
	uint8_t one;

	wri_rd_init(&r, NULL, 0);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(wri_rd_u8(&r), 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);

	wri_rd_init(&r, NULL, 5); /* length without memory */
	WRT_CHECK_STATUS(WR_E_INVAL, r.err);
	WRT_CHECK_U64(wri_rd_left(&r), 0);

	wri_wr_init(&w, NULL, 0);
	WRT_CHECK(wri_wr_ok(&w));
	wri_wr_bytes(&w, NULL, 0); /* nothing to do */
	WRT_CHECK(wri_wr_ok(&w));
	wri_wr_u8(&w, 1);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);

	wri_wr_init(&w, NULL, 7);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);

	wri_wr_init(&w, &one, 1);
	wri_wr_u8(&w, 7);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(one, 7);
}

static void test_sub_reader(void)
{
	static const uint8_t b[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	wri_rd r, s, t;

	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, 2);
	s = wri_rd_sub(&r, 4); /* bytes 3..6 */
	WRT_CHECK(wri_rd_ok(&s));
	WRT_CHECK_U64(s.len, 4);
	WRT_CHECK_U64(r.pos, 6); /* parent already past the envelope */
	WRT_CHECK_U64(wri_rd_u8(&r), 7);
	WRT_CHECK_U64(wri_rd_u16(&s), 0x0403);
	WRT_CHECK_U64(wri_rd_left(&s), 2);
	/* the sub-reader cannot read into the parent's remaining bytes */
	WRT_CHECK_U64(wri_rd_u32(&s), 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, s.err);
	WRT_CHECK(wri_rd_ok(&r)); /* and its failure does not poison the parent */

	/* a sub-reader reads exactly its window and can be left half read */
	wri_rd_init(&r, b, sizeof(b));
	s = wri_rd_sub(&r, 10);
	WRT_CHECK(wri_rd_ok(&s));
	WRT_CHECK_U64(wri_rd_left(&r), 0);
	WRT_CHECK_U64(wri_rd_left(&s), 10);

	/* zero-length sub-reader: valid, empty */
	wri_rd_init(&r, b, sizeof(b));
	s = wri_rd_sub(&r, 0);
	WRT_CHECK(wri_rd_ok(&s));
	WRT_CHECK_U64(s.len, 0);
	WRT_CHECK_U64(r.pos, 0);
	WRT_CHECK_U64(wri_rd_u8(&s), 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, s.err);

	/* n too large: parent gets the error, the returned reader is empty with the same error */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, 8);
	s = wri_rd_sub(&r, 3);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, s.err);
	WRT_CHECK_U64(s.len, 0);
	WRT_CHECK_U64(wri_rd_u8(&s), 0);
	WRT_CHECK_U64(r.pos, 8);

	/* sub-reader of an already failed parent */
	t = wri_rd_sub(&r, 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, t.err);

	/* wrap-around size */
	wri_rd_init(&r, b, sizeof(b));
	s = wri_rd_sub(&r, (size_t)-1);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, s.err);

	/* nested envelopes */
	wri_rd_init(&r, b, sizeof(b));
	s = wri_rd_sub(&r, 6);
	t = wri_rd_sub(&s, 2);
	WRT_CHECK(wri_rd_ok(&t));
	WRT_CHECK_U64(wri_rd_u16(&t), 0x0201);
	WRT_CHECK_U64(wri_rd_left(&s), 4);
	t = wri_rd_sub(&s, 5);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, s.err);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, t.err);
}

static void put_u32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static void test_count(void)
{
	uint8_t b[4 + 64];
	wri_rd r;

	memset(b, 0, sizeof(b));

	/* ok: 3 elements of >= 4 bytes in 64 bytes left */
	put_u32(b, 3);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 10, 4), 3);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(r.pos, 4);

	/* hostile 0xFFFFFFFF with every combination of max and elem_min */
	put_u32(b, 0xFFFFFFFFu);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 0xFFFFFFFFu, 1), 0); /* passes max, fails bytes-left */
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 1000, 1), 0); /* fails max */
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 0xFFFFFFFFu, (size_t)-1), 0); /* count * elem_min would wrap */
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 0xFFFFFFFFu, 0), 0xFFFFFFFFu); /* elem_min 0: only max applies */
	WRT_CHECK(wri_rd_ok(&r));

	/* the byte budget is exact: 64 bytes left hold 16 elements of 4, not 17 */
	put_u32(b, 16);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 100, 4), 16);
	WRT_CHECK(wri_rd_ok(&r));
	put_u32(b, 17);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 100, 4), 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);
	/* count == max is allowed, max + 1 is not */
	put_u32(b, 8);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 8, 1), 8);
	put_u32(b, 9);
	wri_rd_init(&r, b, sizeof(b));
	WRT_CHECK_U64(wri_rd_count(&r, 8, 1), 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.err);

	/* a count that is itself truncated reports TRUNCATED, not TOOBIG */
	wri_rd_init(&r, b, 3);
	WRT_CHECK_U64(wri_rd_count(&r, 8, 1), 0);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	/* and an already failed cursor keeps its error */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_fail(&r, WR_E_ENCODING);
	WRT_CHECK_U64(wri_rd_count(&r, 8, 1), 0);
	WRT_CHECK_STATUS(WR_E_ENCODING, r.err);
}

static void test_writer_overflow(void)
{
	uint8_t buf[16 + 8];
	static const uint8_t guard[8] = {0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A, 0x5A};
	wri_wr w;
	size_t i;

	/* capacity 16, canary after it; the last write that does not fit must write nothing */
	memset(buf, 0x5A, sizeof(buf));
	wri_wr_init(&w, buf, 16);
	wri_wr_u64(&w, 1);
	wri_wr_u32(&w, 2);
	wri_wr_u16(&w, 3);
	wri_wr_u8(&w, 4);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 15);
	WRT_CHECK_U64(wri_wr_left(&w), 1);
	wri_wr_u16(&w, 0xFFFF); /* 2 bytes, 1 left: refused whole */
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), 15);
	WRT_CHECK_U64(buf[15], 0x5A); /* the byte that would have fit was not half written */
	WRT_CHECK_MEM(buf + 16, guard, 8);
	/* sticky: a write that would fit is now refused too, error stays the first one */
	wri_wr_u8(&w, 9);
	WRT_CHECK_U64(wri_wr_len(&w), 15);
	WRT_CHECK_U64(buf[15], 0x5A);
	wri_wr_fail(&w, WR_E_ENCODING);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	WRT_CHECK_U64(wri_wr_left(&w), 0);

	/* every width and helper against every capacity: never past cap, always TOOBIG or exact fit */
	for (i = 0; i <= 9; i++) {
		memset(buf, 0x5A, sizeof(buf));
		wri_wr_init(&w, buf, i);
		wri_wr_u64(&w, 0x1122334455667788ull);
		WRT_CHECK(wri_wr_ok(&w) == (i >= 8));
		WRT_CHECK_MEM(buf + i, guard, 8 > sizeof(buf) - i ? sizeof(buf) - i : 8);
		memset(buf, 0x5A, sizeof(buf));
		wri_wr_init(&w, buf, i);
		wri_wr_bytes(&w, guard, 8);
		WRT_CHECK(wri_wr_ok(&w) == (i >= 8));
		wri_wr_init(&w, buf, i);
		wri_wr_zero(&w, 9);
		WRT_CHECK(wri_wr_ok(&w) == (i >= 9));
		WRT_CHECK_MEM(buf + i, guard, 8 > sizeof(buf) - i ? sizeof(buf) - i : 8);
	}

	/* huge sizes must not wrap */
	wri_wr_init(&w, buf, 16);
	wri_wr_u8(&w, 1);
	WRT_CHECK(wri_wr_reserve(&w, (size_t)-1) == NULL);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	wri_wr_init(&w, buf, 16);
	wri_wr_zero(&w, (size_t)-3);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), 0);
}

static void test_reserve_zero_bytes(void)
{
	uint8_t buf[12];
	wri_wr w;
	uint8_t *p;
	static const uint8_t blob[3] = {7, 8, 9};

	memset(buf, 0xCC, sizeof(buf));
	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_u8(&w, 1);
	p = wri_wr_reserve(&w, 4);
	WRT_CHECK(p == buf + 1);
	memset(p, 0x42, 4);
	wri_wr_zero(&w, 2);
	wri_wr_bytes(&w, blob, 3);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 10);
	WRT_CHECK_U64(buf[0], 1);
	WRT_CHECK_U64(buf[4], 0x42);
	WRT_CHECK_U64(buf[5], 0);
	WRT_CHECK_U64(buf[6], 0);
	WRT_CHECK_U64(buf[7], 7);
	WRT_CHECK_U64(buf[9], 9);
	WRT_CHECK_U64(buf[10], 0xCC);
	/* reserve of 0 at exactly full is fine, and so is reserving the last 2 */
	p = wri_wr_reserve(&w, 2);
	WRT_CHECK(p == buf + 10);
	WRT_CHECK(wri_wr_reserve(&w, 0) != NULL);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK(wri_wr_reserve(&w, 1) == NULL);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
}

static void test_patch(void)
{
	uint8_t buf[16];
	wri_wr w;
	wri_rd r;
	size_t at;

	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_u8(&w, 0xAA);
	at = wri_wr_len(&w);
	wri_wr_u32(&w, 0); /* length placeholder */
	wri_wr_u16(&w, 0x1234);
	wri_wr_patch_u32(&w, at, 0xCAFEBABEu);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(wri_wr_len(&w), 7);
	wri_rd_init(&r, buf, wri_wr_len(&w));
	WRT_CHECK_U64(wri_rd_u8(&r), 0xAA);
	WRT_CHECK_U64(wri_rd_u32(&r), 0xCAFEBABEu);
	WRT_CHECK_U64(wri_rd_u16(&r), 0x1234);
	/* patching the very last 4 written bytes is allowed */
	wri_wr_patch_u32(&w, 3, 0x01020304u);
	WRT_CHECK(wri_wr_ok(&w));
	WRT_CHECK_U64(buf[3], 4);
	WRT_CHECK_U64(buf[6], 1);
	WRT_CHECK_U64(wri_wr_len(&w), 7); /* patching never moves pos */

	/* out of range: straddles the end of the written part, or lies beyond it */
	wri_wr_patch_u32(&w, 4, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);

	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_u32(&w, 1);
	wri_wr_patch_u32(&w, 8, 0); /* beyond pos, inside cap */
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);

	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_u32(&w, 1);
	wri_wr_patch_u32(&w, (size_t)-1, 0); /* wrap-around offset */
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);
	WRT_CHECK_U64(buf[0], 1);

	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_u16(&w, 1);
	wri_wr_patch_u32(&w, 0, 0); /* only 2 bytes written */
	WRT_CHECK_STATUS(WR_E_RANGE, w.err);

	/* a failed writer ignores patches and keeps its first error */
	wri_wr_init(&w, buf, 2);
	wri_wr_u32(&w, 1);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
	wri_wr_patch_u32(&w, 0, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, w.err);
}

static void test_signed_extremes(void)
{
	uint8_t buf[12];
	wri_wr w;
	wri_rd r;

	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_i32(&w, INT32_MIN);
	wri_wr_i64(&w, INT64_MIN);
	wri_rd_init(&r, buf, sizeof(buf));
	WRT_CHECK(wri_rd_i32(&r) == INT32_MIN);
	WRT_CHECK(wri_rd_i64(&r) == INT64_MIN);
	WRT_CHECK(wri_rd_ok(&r));
	WRT_CHECK_U64(buf[3], 0x80);
	WRT_CHECK_U64(buf[11], 0x80);
}

/* NULL means "error" and nothing else; NULL pointers with a non-zero length never reach memcpy. */
static void test_null_arguments(void)
{
	static const uint8_t b[4] = {1, 2, 3, 4};
	uint8_t buf[8];
	wri_rd r, s;
	wri_wr w;

	/* a zero-length claim on a reader with no memory succeeds and is not NULL */
	wri_rd_init(&r, NULL, 0);
	WRT_CHECK(wri_rd_bytes(&r, 0) != NULL);
	WRT_CHECK(wri_rd_ok(&r));
	s = wri_rd_sub(&r, 0);
	WRT_CHECK(s.p != NULL);
	WRT_CHECK(wri_rd_ok(&s));
	WRT_CHECK(wri_rd_bytes(&r, 1) == NULL);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.err);
	/* ... and after an error it is NULL again */
	WRT_CHECK(wri_rd_bytes(&r, 0) == NULL);

	/* a zero-length claim at the end of a real buffer is non-NULL too */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_skip(&r, 4);
	WRT_CHECK(wri_rd_bytes(&r, 0) != NULL);
	WRT_CHECK(wri_rd_ok(&r));

	/* copy into NULL: invalid, nothing read, sticky */
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_copy(&r, NULL, 2);
	WRT_CHECK_STATUS(WR_E_INVAL, r.err);
	WRT_CHECK_U64(r.pos, 0);
	wri_rd_init(&r, b, sizeof(b));
	wri_rd_copy(&r, NULL, 0); /* nothing to copy, nowhere needed */
	WRT_CHECK(wri_rd_ok(&r));

	/* append from NULL: invalid, nothing written, sticky */
	memset(buf, 0xCC, sizeof(buf));
	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_bytes(&w, NULL, 3);
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);
	WRT_CHECK_U64(wri_wr_len(&w), 0);
	WRT_CHECK_U64(buf[0], 0xCC);
	wri_wr_u8(&w, 1);
	WRT_CHECK_U64(wri_wr_len(&w), 0); /* sticky */
	WRT_CHECK_STATUS(WR_E_INVAL, w.err);

	/* first failure wins on the writer too */
	wri_wr_init(&w, buf, sizeof(buf));
	wri_wr_fail(&w, WR_E_ENCODING);
	wri_wr_fail(&w, WR_E_TOOBIG);
	WRT_CHECK_STATUS(WR_E_ENCODING, w.err);
	WRT_CHECK_U64(wri_wr_left(&w), 0);
}

int main(void)
{
	test_null_arguments();
	test_roundtrip();
	test_every_truncation_point();
	test_sticky_error();
	test_bytes_skip_copy();
	test_empty_and_null();
	test_sub_reader();
	test_count();
	test_writer_overflow();
	test_reserve_zero_bytes();
	test_patch();
	test_signed_extremes();
	return wrt_finish();
}
