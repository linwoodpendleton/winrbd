/* SPDX-License-Identifier: MIT */
/*
 * wri_denc_map.c - the encodings the OSDMap, the incrementals and the CRUSH blob need beyond wri_denc.c
 * (see wri_denc_map.h): the legacy envelope, pg_t, varints and the skip helpers. Written from
 * docs/spec/osdmap.md 2.1 and 2.2.
 *
 * Every helper works on the cursor it is given and leaves the error in it (sticky, first failure wins).
 * No helper loops on a count it has not checked against the bytes that are left, so a hostile count cannot
 * make one spin: wri_rd_count refuses a count whose elements (at their smallest size) do not fit.
 */
#include "wri_denc_map.h"

WR_FILE_LICENCE_MIT

/* ---- legacy envelope ---------------------------------------------------------------------- */

wr_status wri_env_open_legacy(wri_rd *r, uint8_t min_v, uint8_t compat_at, uint8_t len_at,
			      uint8_t supported_compat, wri_env *e)
{
	uint8_t v, compat = 0;
	uint32_t len = 0;

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
	if (r->err != WR_OK)
		goto fail;
	/* Below min_v the structure has no length to skip by (or an older layout we do not decode), so it is
	 * refused before another byte is looked at. */
	if (v < min_v || v < len_at) {
		wri_rd_fail(r, WR_E_MAP_VERSION);
		goto fail;
	}
	if (v >= compat_at)
		compat = wri_rd_u8(r);
	len = wri_rd_u32(r); /* v >= len_at here, so the length is present */
	if (r->err != WR_OK)
		goto fail;

	/* As in wri_env_open: a body we may not read is "unsupported" whatever length it claims. */
	if (compat > supported_compat) {
		wri_rd_fail(r, WR_E_MAP_VERSION);
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

/* ---- pg_t --------------------------------------------------------------------------------- */

wr_status wri_denc_pg(wri_rd *r, wri_pg *out)
{
	if (out == NULL) {
		if (r != NULL)
			wri_rd_fail(r, WR_E_INVAL);
		return WR_E_INVAL;
	}
	out->pool = 0;
	out->seed = 0;
	if (r == NULL)
		return WR_E_INVAL;

	(void)wri_rd_u8(r); /* version: ignored */
	out->pool = wri_rd_u64(r);
	out->seed = wri_rd_u32(r);
	(void)wri_rd_i32(r); /* preferred: skipped */
	if (r->err != WR_OK) {
		out->pool = 0;
		out->seed = 0;
	}
	return r->err;
}

/* ---- varint ------------------------------------------------------------------------------- */

uint64_t wri_denc_varint(wri_rd *r)
{
	uint64_t v = 0;
	unsigned i;

	for (i = 0; i < 10; i++) {
		uint8_t b = wri_rd_u8(r);

		if (r->err != WR_OK)
			return 0;
		if (i == 9) {
			/* The tenth byte carries bit 63 only: it must be 0 or 1, which also means "last". Anything
			 * else either overflows 64 bits or asks for an eleventh byte. */
			if (b > 1) {
				wri_rd_fail(r, WR_E_ENCODING);
				return 0;
			}
			v |= (uint64_t)b << 63;
			return v;
		}
		v |= (uint64_t)(b & 0x7f) << (7 * i);
		if ((b & 0x80) == 0)
			return v;
	}
	/* not reached: the loop returns on its last turn */
	wri_rd_fail(r, WR_E_ENCODING);
	return 0;
}

/* ---- counts ------------------------------------------------------------------------------- */

uint32_t wri_denc_count(wri_rd *r, uint32_t max, size_t elem_min)
{
	return wri_rd_count(r, max, elem_min);
}

/* ---- skip helpers ------------------------------------------------------------------------- */

void wri_denc_skip_str(wri_rd *r)
{
	uint32_t n = wri_rd_u32(r);

	if (r->err != WR_OK)
		return;
	wri_rd_skip(r, (size_t)n); /* checked against the bytes left, no arithmetic on it */
}

void wri_denc_skip_str_map(wri_rd *r)
{
	uint32_t n, i;

	n = wri_denc_count(r, 0xFFFFFFFFu, 8); /* key and value are strings of at least 4 bytes each */
	for (i = 0; i < n && r->err == WR_OK; i++) {
		wri_denc_skip_str(r);
		wri_denc_skip_str(r);
	}
}

void wri_denc_skip_str_map_map(wri_rd *r)
{
	uint32_t n, i;

	n = wri_denc_count(r, 0xFFFFFFFFu, 8); /* key string (4) + the inner map's count (4) */
	for (i = 0; i < n && r->err == WR_OK; i++) {
		wri_denc_skip_str(r);
		wri_denc_skip_str_map(r);
	}
}

void wri_denc_skip_interval_set(wri_rd *r)
{
	uint32_t n = wri_denc_count(r, 0xFFFFFFFFu, 16); /* (u64 start, u64 length) */

	if (r->err != WR_OK)
		return;
	wri_rd_skip(r, (size_t)n * 16); /* n * 16 <= bytes left, so no wrap */
}

void wri_denc_skip_env(wri_rd *r)
{
	wri_env e;

	/* Skipping does not decode, so no compat limit applies: 255 accepts every envelope. */
	/* the status is the cursor's own error, which the caller reads from r */
	if (wri_env_open(r, 0xFF, &e) != WR_OK)
		return;
}

void wri_denc_skip_i32_vec(wri_rd *r, uint32_t max)
{
	uint32_t n = wri_denc_count(r, max, 4);

	if (r->err != WR_OK)
		return;
	wri_rd_skip(r, (size_t)n * 4); /* n * 4 <= bytes left, so no wrap */
}
