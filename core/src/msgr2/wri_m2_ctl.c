/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_ctl.c - msgr2 control-frame payload codecs (wri_m2_ctl.h, docs/spec/msgr2.md 2.7).
 *
 * Every payload is a fixed list of fields back to back. A decoder reads the whole list through the
 * cursor, then insists the reader is exactly at its end and that no error was recorded; on any
 * failure the output structure is zeroed so a caller that ignores the status still sees nothing
 * half-filled. Vectors are counted through wri_rd_count (a hostile count cannot spin a loop),
 * capped at WRI_M2_VEC_WIRE_MAX, and only the first WRI_M2_MODES_MAX entries are kept.
 */
#include "wri_m2_ctl.h"

#include "wri_denc.h"

WR_FILE_LICENCE_MIT

/* ---- shared helpers ----------------------------------------------------------------------- */

/* Final verdict of a decoder: the first recorded error, else "bytes left over" is an encoding error. */
static wr_status finish(const wri_rd *r)
{
	if (r->err != WR_OK)
		return r->err;
	if (r->pos != r->len)
		return WR_E_ENCODING;
	return WR_OK;
}

/* u32 vector: count + entries; keeps the first `max` entries in dst, returns how many were kept. */
static uint32_t rd_u32_vec(wri_rd *r, uint32_t *dst, uint32_t max)
{
	uint32_t n = wri_rd_count(r, WRI_M2_VEC_WIRE_MAX, 4u);
	uint32_t kept = 0;
	uint32_t i;

	for (i = 0; i < n; i++) {
		uint32_t v = wri_rd_u32(r);

		if (kept < max) {
			dst[kept] = v;
			kept++;
		}
	}
	return kept;
}

static void put_u32_vec(wri_wr *w, const uint32_t *v, size_t n)
{
	size_t i;

	if (n > WRI_M2_VEC_WIRE_MAX || (n != 0 && v == NULL)) {
		wri_wr_fail(w, n > WRI_M2_VEC_WIRE_MAX ? WR_E_TOOBIG : WR_E_INVAL);
		return;
	}
	wri_wr_u32(w, (uint32_t)n);
	for (i = 0; i < n; i++)
		wri_wr_u32(w, v[i]);
}

static void put_blob(wri_wr *w, const uint8_t *p, size_t n)
{
	if (n > WRI_M2_AUTH_BLOB_MAX) {
		wri_wr_fail(w, WR_E_TOOBIG);
		return;
	}
	wri_denc_put_blob(w, p, n);
}

/* ---- HELLO -------------------------------------------------------------------------------- */

wr_status wri_m2_hello_decode(wri_rd *r, wri_m2_hello *out)
{
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	out->entity_type = wri_rd_u8(r);
	st = wri_eaddr_decode(r, &out->peer_addr);
	if (st != WR_OK)
		wri_rd_fail(r, st);
	st = finish(r);
	if (st != WR_OK)
		WR_MEMSET(out, 0, sizeof(*out));
	return st;
}

void wri_m2_hello_encode(wri_wr *w, const wri_m2_hello *h)
{
	if (w == NULL)
		return;
	if (h == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	wri_wr_u8(w, h->entity_type);
	wri_eaddr_encode(w, &h->peer_addr);
}

/* ---- AUTH_REQUEST ------------------------------------------------------------------------- */

void wri_m2_auth_request_encode(wri_wr *w, uint32_t method, const uint32_t *modes, size_t nmodes,
				const uint8_t *payload, size_t payload_len)
{
	if (w == NULL)
		return;
	wri_wr_u32(w, method);
	put_u32_vec(w, modes, nmodes);
	put_blob(w, payload, payload_len);
}

/* ---- AUTH_BAD_METHOD ---------------------------------------------------------------------- */

wr_status wri_m2_bad_method_decode(wri_rd *r, wri_m2_bad_method *out)
{
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	out->method = wri_rd_u32(r);
	out->result = wri_rd_i32(r);
	out->n_methods = rd_u32_vec(r, out->allowed_methods, WRI_M2_MODES_MAX);
	out->n_modes = rd_u32_vec(r, out->allowed_modes, WRI_M2_MODES_MAX);
	st = finish(r);
	if (st != WR_OK)
		WR_MEMSET(out, 0, sizeof(*out));
	return st;
}

void wri_m2_bad_method_encode(wri_wr *w, const wri_m2_bad_method *b)
{
	if (w == NULL)
		return;
	if (b == NULL || b->n_methods > WRI_M2_MODES_MAX || b->n_modes > WRI_M2_MODES_MAX) {
		wri_wr_fail(w, b == NULL ? WR_E_INVAL : WR_E_TOOBIG);
		return;
	}
	wri_wr_u32(w, b->method);
	wri_wr_i32(w, b->result);
	put_u32_vec(w, b->allowed_methods, b->n_methods);
	put_u32_vec(w, b->allowed_modes, b->n_modes);
}

/* ---- AUTH_REPLY_MORE / AUTH_REQUEST_MORE -------------------------------------------------- */

wr_status wri_m2_auth_more_decode(wri_rd *r, const uint8_t **payload, uint32_t *len)
{
	const uint8_t *p;
	uint32_t n = 0;
	wr_status st;

	if (payload != NULL)
		*payload = NULL;
	if (len != NULL)
		*len = 0;
	if (r == NULL || payload == NULL || len == NULL)
		return WR_E_INVAL;
	p = wri_denc_blob(r, &n, WRI_M2_AUTH_BLOB_MAX);
	st = finish(r);
	if (st != WR_OK)
		return st;
	*payload = p;
	*len = n;
	return WR_OK;
}

void wri_m2_auth_more_encode(wri_wr *w, const uint8_t *payload, size_t len)
{
	if (w == NULL)
		return;
	put_blob(w, payload, len);
}

/* ---- AUTH_DONE ---------------------------------------------------------------------------- */

wr_status wri_m2_auth_done_decode(wri_rd *r, wri_m2_auth_done *out)
{
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	out->global_id = wri_rd_u64(r);
	out->mode = wri_rd_u32(r);
	out->payload = wri_denc_blob(r, &out->payload_len, WRI_M2_AUTH_BLOB_MAX);
	st = finish(r);
	if (st != WR_OK)
		WR_MEMSET(out, 0, sizeof(*out));
	return st;
}

void wri_m2_auth_done_encode(wri_wr *w, const wri_m2_auth_done *d)
{
	if (w == NULL)
		return;
	if (d == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	wri_wr_u64(w, d->global_id);
	wri_wr_u32(w, d->mode);
	put_blob(w, d->payload, d->payload_len);
}

/* ---- AUTH_SIGNATURE ----------------------------------------------------------------------- */

wr_status wri_m2_auth_sig_decode(wri_rd *r, uint8_t out[32])
{
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	wri_rd_copy(r, out, 32u); /* zeroes out on overrun */
	st = finish(r);
	if (st != WR_OK)
		WR_MEMSET(out, 0, 32u);
	return st;
}

void wri_m2_auth_sig_encode(wri_wr *w, const uint8_t sig[32])
{
	if (w == NULL)
		return;
	wri_wr_bytes(w, sig, 32u);
}

/* ---- CLIENT_IDENT / SERVER_IDENT ---------------------------------------------------------- */

void wri_m2_client_ident_encode(wri_wr *w, const wri_m2_client_ident *c)
{
	if (w == NULL)
		return;
	if (c == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	wri_eaddrvec_encode(w, c->addrs, 1u);
	wri_eaddr_encode(w, &c->target);
	wri_wr_i64(w, c->gid);
	wri_wr_u64(w, c->global_seq);
	wri_wr_u64(w, c->supported);
	wri_wr_u64(w, c->required);
	wri_wr_u64(w, c->flags);
	wri_wr_u64(w, c->cookie);
}

wr_status wri_m2_server_ident_decode(wri_rd *r, wri_m2_server_ident *out)
{
	size_t n_total = 0;
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	WR_MEMSET(out, 0, sizeof(*out));
	st = wri_eaddrvec_decode(r, out->addrs, WRI_EADDRVEC_MAX, &out->n_addrs, &n_total);
	if (st != WR_OK)
		wri_rd_fail(r, st);
	out->gid = wri_rd_i64(r);
	out->global_seq = wri_rd_u64(r);
	out->supported = wri_rd_u64(r);
	out->required = wri_rd_u64(r);
	out->flags = wri_rd_u64(r);
	out->cookie = wri_rd_u64(r);
	st = finish(r);
	if (st != WR_OK)
		WR_MEMSET(out, 0, sizeof(*out));
	return st;
}

void wri_m2_server_ident_encode(wri_wr *w, const wri_m2_server_ident *s)
{
	size_t n;

	if (w == NULL)
		return;
	if (s == NULL) {
		wri_wr_fail(w, WR_E_INVAL);
		return;
	}
	n = s->n_addrs < WRI_EADDRVEC_MAX ? s->n_addrs : WRI_EADDRVEC_MAX;
	wri_eaddrvec_encode(w, s->addrs, n);
	wri_wr_i64(w, s->gid);
	wri_wr_u64(w, s->global_seq);
	wri_wr_u64(w, s->supported);
	wri_wr_u64(w, s->required);
	wri_wr_u64(w, s->flags);
	wri_wr_u64(w, s->cookie);
}

/* ---- single-field payloads ---------------------------------------------------------------- */

wr_status wri_m2_u64_decode(wri_rd *r, uint64_t *out)
{
	wr_status st;

	if (r == NULL || out == NULL)
		return WR_E_INVAL;
	*out = wri_rd_u64(r);
	st = finish(r);
	if (st != WR_OK)
		*out = 0;
	return st;
}

void wri_m2_u64_encode(wri_wr *w, uint64_t v)
{
	if (w != NULL)
		wri_wr_u64(w, v);
}

wr_status wri_m2_keepalive_decode(wri_rd *r, uint32_t *sec, uint32_t *nsec)
{
	uint32_t s = 0, n = 0;
	wr_status st;

	if (r == NULL || sec == NULL || nsec == NULL)
		return WR_E_INVAL;
	wri_denc_utime(r, &s, &n);
	st = finish(r);
	if (st != WR_OK)
		s = n = 0;
	*sec = s;
	*nsec = n;
	return st;
}

void wri_m2_keepalive_encode(wri_wr *w, uint32_t sec, uint32_t nsec)
{
	if (w != NULL)
		wri_denc_put_utime(w, sec, nsec);
}
