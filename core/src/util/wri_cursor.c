/* SPDX-License-Identifier: MIT */
/*
 * wri_cursor.c - bounds-checked read and write cursors (see wri_cursor.h for the contract).
 *
 * Design notes:
 *   - Every access goes through one "take n bytes" step that checks the error flag first and
 *     then n against what is left. Nothing here computes pos + n, so no size_t arithmetic can
 *     wrap on a 32-bit host, whatever the (untrusted) n is.
 *   - A failed read does not advance pos (the offset of the failure stays available) and all
 *     later reads return zeros; a failed write writes nothing at all.
 */
#include "wri_cursor.h"
#include "wri_le.h"

WR_FILE_LICENCE_MIT

/* ---- reader ------------------------------------------------------------------------------- */

void wri_rd_init(wri_rd *r, const uint8_t *p, size_t len)
{
	r->p = p;
	r->len = len;
	r->pos = 0;
	r->err = WR_OK;
	if (p == NULL && len != 0) {
		/* a non-empty window with no memory behind it: refuse every read */
		r->len = 0;
		r->err = WR_E_INVAL;
	}
}

void wri_rd_fail(wri_rd *r, wr_status st)
{
	if (r->err == WR_OK)
		r->err = st;
}

/* Stand-in address for a zero-length claim on a reader with no memory behind it (read-only data,
 * never dereferenced), so that "NULL" always and only means "error". */
static const uint8_t wri_rd_nil[1] = {0};

/* Claim the next n bytes; NULL (error recorded) if they are not all there. */
static const uint8_t *wri_rd_take(wri_rd *r, size_t n)
{
	const uint8_t *q;

	if (r->err != WR_OK)
		return NULL;
	if (n > r->len - r->pos) {
		r->err = WR_E_TRUNCATED;
		return NULL;
	}
	q = r->p ? r->p + r->pos : wri_rd_nil; /* no memory only for the empty reader (n == 0 here) */
	r->pos += n;
	return q;
}

uint8_t wri_rd_u8(wri_rd *r)
{
	const uint8_t *q = wri_rd_take(r, 1);

	return q ? q[0] : 0;
}

uint16_t wri_rd_u16(wri_rd *r)
{
	const uint8_t *q = wri_rd_take(r, 2);

	return q ? wri_le16_get(q) : 0;
}

uint32_t wri_rd_u32(wri_rd *r)
{
	const uint8_t *q = wri_rd_take(r, 4);

	return q ? wri_le32_get(q) : 0;
}

uint64_t wri_rd_u64(wri_rd *r)
{
	const uint8_t *q = wri_rd_take(r, 8);

	return q ? wri_le64_get(q) : 0;
}

int32_t wri_rd_i32(wri_rd *r)
{
	return (int32_t)wri_rd_u32(r); /* two's complement reinterpretation */
}

int64_t wri_rd_i64(wri_rd *r)
{
	return (int64_t)wri_rd_u64(r);
}

const uint8_t *wri_rd_bytes(wri_rd *r, size_t n)
{
	return wri_rd_take(r, n);
}

void wri_rd_skip(wri_rd *r, size_t n)
{
	(void)wri_rd_take(r, n);
}

void wri_rd_copy(wri_rd *r, uint8_t *dst, size_t n)
{
	const uint8_t *q;

	if (n == 0)
		return;
	if (dst == NULL) { /* a caller bug, but never a NULL write */
		wri_rd_fail(r, WR_E_INVAL);
		return;
	}
	q = wri_rd_take(r, n);
	if (q)
		WR_MEMCPY(dst, q, n);
	else
		WR_MEMSET(dst, 0, n);
}

wri_rd wri_rd_sub(wri_rd *r, size_t n)
{
	wri_rd s;
	const uint8_t *q = wri_rd_take(r, n);

	if (q) {
		s.p = q;
		s.len = n;
		s.pos = 0;
		s.err = WR_OK;
	} else {
		s.p = NULL;
		s.len = 0;
		s.pos = 0;
		s.err = r->err;
	}
	return s;
}

uint32_t wri_rd_count(wri_rd *r, uint32_t max, size_t elem_min)
{
	uint32_t c = wri_rd_u32(r);

	if (r->err != WR_OK)
		return 0;
	if (c > max) {
		r->err = WR_E_TOOBIG;
		return 0;
	}
	/* c * elem_min <= left, written as a division so it cannot overflow */
	if (elem_min != 0 && (size_t)c > (r->len - r->pos) / elem_min) {
		r->err = WR_E_TOOBIG;
		return 0;
	}
	return c;
}

/* ---- writer ------------------------------------------------------------------------------- */

void wri_wr_init(wri_wr *w, uint8_t *p, size_t cap)
{
	w->p = p;
	w->cap = cap;
	w->pos = 0;
	w->err = WR_OK;
	if (p == NULL && cap != 0) {
		w->cap = 0;
		w->err = WR_E_INVAL;
	}
}

void wri_wr_fail(wri_wr *w, wr_status st)
{
	if (w->err == WR_OK)
		w->err = st;
}

/* Claim n bytes of output space; NULL (error recorded) if they do not fit. */
static uint8_t *wri_wr_take(wri_wr *w, size_t n)
{
	uint8_t *q;

	if (w->err != WR_OK)
		return NULL;
	if (n > w->cap - w->pos) {
		w->err = WR_E_TOOBIG;
		return NULL;
	}
	q = w->p ? w->p + w->pos : NULL; /* NULL only for the empty writer (cap 0) */
	w->pos += n;
	return q;
}

void wri_wr_u8(wri_wr *w, uint8_t v)
{
	uint8_t *q = wri_wr_take(w, 1);

	if (q)
		q[0] = v;
}

void wri_wr_u16(wri_wr *w, uint16_t v)
{
	uint8_t *q = wri_wr_take(w, 2);

	if (q)
		wri_le16_put(q, v);
}

void wri_wr_u32(wri_wr *w, uint32_t v)
{
	uint8_t *q = wri_wr_take(w, 4);

	if (q)
		wri_le32_put(q, v);
}

void wri_wr_u64(wri_wr *w, uint64_t v)
{
	uint8_t *q = wri_wr_take(w, 8);

	if (q)
		wri_le64_put(q, v);
}

void wri_wr_i32(wri_wr *w, int32_t v)
{
	wri_wr_u32(w, (uint32_t)v);
}

void wri_wr_i64(wri_wr *w, int64_t v)
{
	wri_wr_u64(w, (uint64_t)v);
}

void wri_wr_bytes(wri_wr *w, const uint8_t *p, size_t n)
{
	uint8_t *q;

	if (n == 0)
		return;
	if (p == NULL) { /* a caller bug, but never a NULL read */
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	q = wri_wr_take(w, n);
	if (q)
		WR_MEMMOVE(q, p, n); /* the source may live inside the destination buffer */
}

void wri_wr_zero(wri_wr *w, size_t n)
{
	uint8_t *q;

	if (n == 0)
		return;
	q = wri_wr_take(w, n);
	if (q)
		WR_MEMSET(q, 0, n);
}

uint8_t *wri_wr_reserve(wri_wr *w, size_t n)
{
	return wri_wr_take(w, n);
}

void wri_wr_patch_u32(wri_wr *w, size_t at, uint32_t v)
{
	if (w->err != WR_OK)
		return;
	if (at > w->pos || w->pos - at < 4) {
		w->err = WR_E_RANGE;
		return;
	}
	wri_le32_put(w->p + at, v);
}
