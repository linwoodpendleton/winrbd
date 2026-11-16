/* SPDX-License-Identifier: MIT */
/*
 * wri_cursor.h - bounds-checked read and write cursors. Every decoder and encoder in core uses
 * these and nothing else touches wire bytes.
 *
 * Errors are sticky and first-failure-wins: after one failed read the cursor returns zeros
 * and further reads do nothing, so a decoder may read a whole structure and check wri_rd_ok()
 * once at the end. A decoder never trusts a length: counts go through wri_rd_count().
 * Failures set WR_E_TRUNCATED (ran out of bytes) or WR_E_ENCODING / WR_E_TOOBIG (bad value).
 * Writers set WR_E_TOOBIG when the buffer is too small; they never write past cap.
 */
#ifndef WRI_CURSOR_H
#define WRI_CURSOR_H

#include "wr_err.h"
#include "wr_port.h"

/* ---- reader ------------------------------------------------------------------------------- */

typedef struct wri_rd {
	const uint8_t *p;
	size_t len; /* total bytes */
	size_t pos; /* consumed */
	wr_status err;
} wri_rd;

void wri_rd_init(wri_rd *r, const uint8_t *p, size_t len);
/* Bytes still readable; 0 once an error is recorded (so a "while (left)" loop cannot spin). */
WR_INLINE size_t wri_rd_left(const wri_rd *r) { return r->err == WR_OK ? r->len - r->pos : 0; }
WR_INLINE int wri_rd_ok(const wri_rd *r) { return r->err == WR_OK; }
/* Record an error unless one is already recorded (first failure wins). pos is left where it was,
 * so a decoder can report the offset of the failure. */
void wri_rd_fail(wri_rd *r, wr_status st);

uint8_t wri_rd_u8(wri_rd *r);
uint16_t wri_rd_u16(wri_rd *r); /* little-endian */
uint32_t wri_rd_u32(wri_rd *r);
uint64_t wri_rd_u64(wri_rd *r);
int32_t wri_rd_i32(wri_rd *r);
int64_t wri_rd_i64(wri_rd *r);

/* Pointer to the next n bytes (valid as long as the underlying buffer), or NULL on overrun.
 * NULL always means an error is recorded: n == 0 on a healthy reader returns a non-NULL pointer
 * that must not be dereferenced. */
const uint8_t *wri_rd_bytes(wri_rd *r, size_t n);
void wri_rd_skip(wri_rd *r, size_t n);
/* Copy exactly n bytes into dst. On overrun dst is zeroed. dst == NULL with n > 0 is WR_E_INVAL. */
void wri_rd_copy(wri_rd *r, uint8_t *dst, size_t n);

/*
 * Consume n bytes from r and return a reader over exactly them (the "skip to end of the
 * envelope" operation: r is already past the sub-structure when this returns). On overrun the
 * parent gets the error and the returned reader is empty with the same error.
 */
wri_rd wri_rd_sub(wri_rd *r, size_t n);

/*
 * Read a u32 element count for a list whose elements are at least elem_min bytes each.
 * Fails (returns 0, sets WR_E_TOOBIG) if count > max or count * elem_min > bytes left, so a
 * hostile 0xFFFFFFFF cannot cause a long loop.
 */
uint32_t wri_rd_count(wri_rd *r, uint32_t max, size_t elem_min);

/* ---- writer ------------------------------------------------------------------------------- */

typedef struct wri_wr {
	uint8_t *p;
	size_t cap;
	size_t pos;
	wr_status err;
} wri_wr;

void wri_wr_init(wri_wr *w, uint8_t *p, size_t cap);
WR_INLINE size_t wri_wr_len(const wri_wr *w) { return w->pos; }
WR_INLINE int wri_wr_ok(const wri_wr *w) { return w->err == WR_OK; }
/* Bytes still writable; 0 once an error is recorded. */
WR_INLINE size_t wri_wr_left(const wri_wr *w) { return w->err == WR_OK ? w->cap - w->pos : 0; }
/* Record an error unless one is already recorded (first failure wins). */
void wri_wr_fail(wri_wr *w, wr_status st);

void wri_wr_u8(wri_wr *w, uint8_t v);
void wri_wr_u16(wri_wr *w, uint16_t v);
void wri_wr_u32(wri_wr *w, uint32_t v);
void wri_wr_u64(wri_wr *w, uint64_t v);
void wri_wr_i32(wri_wr *w, int32_t v);
void wri_wr_i64(wri_wr *w, int64_t v);
/* Append n bytes; p == NULL with n > 0 is WR_E_INVAL. */
void wri_wr_bytes(wri_wr *w, const uint8_t *p, size_t n);
void wri_wr_zero(wri_wr *w, size_t n);
/* Reserve n bytes and return a pointer to fill in place (NULL + error on overflow). The bytes
 * are NOT cleared: the caller must fill all n of them. For n == 0 on a writer with no memory
 * (cap 0, p NULL) the result is NULL without an error: test wri_wr_ok(), not the pointer. */
uint8_t *wri_wr_reserve(wri_wr *w, size_t n);
/* Overwrite a u32 already written at offset `at` (length back-patching). The four bytes must lie
 * inside the written part (at + 4 <= wri_wr_len), otherwise WR_E_RANGE is recorded. */
void wri_wr_patch_u32(wri_wr *w, size_t at, uint32_t v);

#endif /* WRI_CURSOR_H */
