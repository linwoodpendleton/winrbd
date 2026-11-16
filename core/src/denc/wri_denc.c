/* SPDX-License-Identifier: MIT */
/*
 * wri_denc.c - Ceph's primitive encodings on the cursors (see wri_denc.h): versioned envelopes,
 * length-prefixed blobs, utime. Written from docs/spec/msgr2.md 2.1.
 */
#include "wri_denc.h"

WR_FILE_LICENCE_MIT

/* True when n survives a round trip through u32 (always on a 32-bit host). Written without a
 * comparison against 0xFFFFFFFF so no compiler can call it "always false" there. */
static int fits_u32(size_t n)
{
	return (size_t)(uint32_t)n == n;
}

/* ---- envelope ---------------------------------------------------------------------------- */

wr_status wri_env_open(wri_rd *r, uint8_t supported_compat, wri_env *e)
{
	uint8_t v, compat;
	uint32_t len;

	if (e == NULL) {
		if (r != NULL)
			wri_rd_fail(r, WR_E_INVAL);
		return WR_E_INVAL;
	}
	e->v = 0;
	e->compat = 0;
	wri_rd_init(&e->body, NULL, 0);
	if (r == NULL)
		return WR_E_INVAL;

	v = wri_rd_u8(r);
	compat = wri_rd_u8(r);
	len = wri_rd_u32(r);
	if (r->err != WR_OK)
		goto fail;

	/* The compat check comes before the length check: a body we are not allowed to read is
	 * "unsupported" no matter how long it claims to be. */
	if (compat > supported_compat) {
		wri_rd_fail(r, WR_E_UNSUPPORTED);
		goto fail;
	}
	if ((size_t)len > wri_rd_left(r)) {
		wri_rd_fail(r, WR_E_TRUNCATED);
		goto fail;
	}
	e->v = v;
	e->compat = compat;
	e->body = wri_rd_sub(r, (size_t)len);
	return r->err;

fail:
	/* a caller that ignores the status reads an errored, empty body, never stale bytes */
	e->body.err = r->err;
	return r->err;
}

size_t wri_env_begin(wri_wr *w, uint8_t v, uint8_t compat)
{
	size_t mark;

	wri_wr_u8(w, v);
	wri_wr_u8(w, compat);
	mark = w->pos;
	wri_wr_u32(w, 0); /* patched by wri_env_end */
	return mark;
}

void wri_env_end(wri_wr *w, size_t mark)
{
	size_t len;

	if (w->err != WR_OK)
		return;
	/* the placeholder must be fully inside what was written */
	if (mark > w->pos || w->pos - mark < 4) {
		wri_wr_fail(w, WR_E_RANGE);
		return;
	}
	len = w->pos - mark - 4;
	if (!fits_u32(len)) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	wri_wr_patch_u32(w, mark, (uint32_t)len);
}

/* ---- blobs and strings ------------------------------------------------------------------- */

const uint8_t *wri_denc_blob(wri_rd *r, uint32_t *len, uint32_t max)
{
	uint32_t n = wri_rd_u32(r);
	const uint8_t *p;

	if (len != NULL)
		*len = 0;
	if (r->err != WR_OK)
		return NULL;
	if (n > max) {
		wri_rd_fail(r, WR_E_TOOBIG);
		return NULL;
	}
	p = wri_rd_bytes(r, (size_t)n);
	if (p == NULL)
		return NULL;
	if (len != NULL)
		*len = n;
	return p;
}

void wri_denc_put_blob(wri_wr *w, const uint8_t *p, size_t n)
{
	if (!fits_u32(n)) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	if (n > 0 && p == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	wri_wr_u32(w, (uint32_t)n);
	wri_wr_bytes(w, p, n);
}

/* ---- utime ------------------------------------------------------------------------------- */

void wri_denc_utime(wri_rd *r, uint32_t *sec, uint32_t *nsec)
{
	uint32_t s = wri_rd_u32(r);
	uint32_t n = wri_rd_u32(r);

	if (sec != NULL)
		*sec = s;
	if (nsec != NULL)
		*nsec = n;
}

void wri_denc_put_utime(wri_wr *w, uint32_t sec, uint32_t nsec)
{
	wri_wr_u32(w, sec);
	wri_wr_u32(w, nsec);
}
