/* SPDX-License-Identifier: MIT */
/*
 * wri_ctx.c - host-backed helpers of the per-client environment: random bytes, log emission and
 * the first-failure-wins error record (see wri_ctx.h).
 */
#include "wri_ctx.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

wr_status wri_random(const wri_ctx *x, uint8_t *out, size_t n)
{
	wr_status st;

	if (x == NULL || x->host.random == NULL)
		return WR_E_HOST_RANDOM; /* no source: never fall back to something weaker */
	if (n == 0)
		return WR_OK;
	if (out == NULL)
		return WR_E_INVAL;
	st = x->host.random(x->host.ctx, out, n);
	if (st != WR_OK) {
		/* Whatever the host wrote is not trustworthy randomness: do not leave it behind. */
		wri_secure_zero(out, n);
		return WR_E_HOST_RANDOM;
	}
	return WR_OK;
}

void wri_log_emit(const wri_ctx *x, unsigned level, unsigned module, wr_conn_id conn, wr_status st,
		  const char *msg, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3)
{
	wr_log_rec rec;

	if (x == NULL || x->host.log == NULL)
		return;
	if (level < WR_LOG_ERR || level > WR_LOG_MAX_LEVEL || level > WR_LOG_TRACE)
		return;
	rec.level = (uint8_t)level;
	rec.module = (uint8_t)(module & 0xffu);
	rec.reserved16 = 0;
	rec.conn = conn;
	rec.status = st;
	rec.msg = msg;
	rec.a0 = a0;
	rec.a1 = a1;
	rec.a2 = a2;
	rec.a3 = a3;
	x->host.log(x->host.ctx, &rec);
}

void wri_errinfo_set(wr_errinfo *e, wr_status st, unsigned module, unsigned line, const char *what,
		     uint64_t a0, uint64_t a1, uint64_t a2)
{
	if (e == NULL || st == WR_OK)
		return;
	if (e->status != WR_OK)
		return; /* first failure wins: the root cause must not be overwritten by its fallout */
	e->status = st;
	e->module = (uint8_t)(module & 0xffu);
	e->line = (uint16_t)(line > 0xffffu ? 0xffffu : line);
	e->what = what;
	e->a0 = a0;
	e->a1 = a1;
	e->a2 = a2;
	/* peer_result and conn are the caller's to set, before or after; they are not touched. */
}
