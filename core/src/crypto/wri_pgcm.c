/* SPDX-License-Identifier: MIT */
/*
 * wri_pgcm.c - host or portable GCM for one direction (see wri_pgcm.h and docs/design/core-architecture.md 35.4).
 *
 * The choice between the host override and wri_gcm is made once, in wri_pgcm_setkey, and kept in the object. Both paths sit behind
 * the same operation rules (the object tracks "idle / running / refused" and the direction), so a host is never called outside its
 * contract and a refusal behaves alike for both. Nothing here depends on a key or data byte.
 */
#include "wri_pgcm.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

enum { PG_IDLE = 0, PG_RUN = 1, PG_REFUSED = 2 };

/* SP 800-38D 5.2.1.1: 2^36 - 32 bytes = 2^32 - 2 blocks per operation (the block counter starts at 2 and must not wrap). */
#define PG_MAX_BLOCKS 0xfffffffeu

/* [in, in + n) and [out, out + n) overlap without being the same range (n > 0); a host is promised disjoint or identical buffers. */
static int pg_partial_overlap(const uint8_t *in, const uint8_t *out, size_t n)
{
	const uintptr_t a = (uintptr_t)in, b = (uintptr_t)out;

	if (a == b)
		return 0;
	return (a < b) ? ((b - a) < (uintptr_t)n) : ((a - b) < (uintptr_t)n);
}

/* The host table covers all six GCM members iff its size reaches the end of the last one (members are laid out in order). */
static int pg_host_usable(const wr_prim_ops *p)
{
	if (p == NULL)
		return 0;
	if (p->size < offsetof(wr_prim_ops, gcm_wipe) + sizeof(p->gcm_wipe))
		return 0;
	if (p->gcm_state_bytes < 1u || p->gcm_state_bytes > WR_GCM_HOST_STATE_MAX)
		return 0;
	return p->gcm_setkey != NULL && p->gcm_start != NULL && p->gcm_update != NULL && p->gcm_final_enc != NULL &&
	       p->gcm_final_dec != NULL && p->gcm_wipe != NULL;
}

wr_status wri_pgcm_setkey(wri_pgcm *g, const wr_prim_ops *prim, const uint8_t key[16])
{
	wr_status st;

	if (g == NULL)
		return WR_E_INVAL;
	wri_secure_zero(g, sizeof(*g)); /* the previous contents are not looked at (see the header) */
	if (key == NULL)
		return WR_E_INVAL;
	if (pg_host_usable(prim)) {
		st = prim->gcm_setkey(prim->ctx, g->u.host_state, key);
		if (st != WR_OK) {
			prim->gcm_wipe(prim->ctx, g->u.host_state);
			wri_secure_zero(g, sizeof(*g));
			return (st < 0) ? st : WR_E_CRYPTO_KEY; /* a host must not answer a refused key with success-like codes */
		}
		g->host = prim;
	} else {
		st = wri_gcm_setkey(&g->u.sw, key, 16);
		if (st != WR_OK) {
			wri_secure_zero(g, sizeof(*g));
			return st;
		}
	}
	g->keyed = 1;
	return WR_OK;
}

/* Close an operation that was refused: a host gets a real final (result discarded) so its state is ready for the next start. */
static void pg_close(wri_pgcm *g)
{
	if (g->op != PG_IDLE) {
		if (g->host != NULL) {
			uint8_t scratch[WRI_GCM_TAG_LEN];

			WR_MEMSET(scratch, 0, sizeof(scratch));
			if (g->dir)
				(void)g->host->gcm_final_dec(g->host->ctx, g->u.host_state, scratch);
			else
				g->host->gcm_final_enc(g->host->ctx, g->u.host_state, scratch);
			wri_secure_zero(scratch, sizeof(scratch));
		} else {
			wri_gcm_abort(&g->u.sw);
		}
	}
	g->op = PG_IDLE;
}

/* A refusal inside an operation: the operation is dead and its final will say so. */
static wr_status pg_refuse(wri_pgcm *g, wr_status st)
{
	if (g->op == PG_RUN) {
		if (g->host == NULL)
			wri_gcm_abort(&g->u.sw);
		g->op = PG_REFUSED;
	}
	return st;
}

wr_status wri_pgcm_start(wri_pgcm *g, const uint8_t iv[WRI_GCM_IV_LEN], int decrypt)
{
	wr_status st;

	if (g == NULL)
		return WR_E_INVAL;
	if (!g->keyed)
		return WR_E_STATE;
	pg_close(g); /* an operation that was never finished */
	if (iv == NULL || (decrypt != 0 && decrypt != 1))
		return WR_E_INVAL;
	if (g->host != NULL)
		st = g->host->gcm_start(g->host->ctx, g->u.host_state, iv, decrypt);
	else
		st = wri_gcm_start(&g->u.sw, iv, WRI_GCM_IV_LEN, decrypt);
	if (st != WR_OK)
		return (st < 0) ? st : WR_E_STATE;
	g->op = PG_RUN;
	g->dir = (uint8_t)decrypt;
	g->blocks = 0;
	return WR_OK;
}

wr_status wri_pgcm_update(wri_pgcm *g, const uint8_t *in, uint8_t *out, size_t n)
{
	if (g == NULL)
		return WR_E_INVAL;
	if (!g->keyed || g->op != PG_RUN)
		return pg_refuse(g, WR_E_STATE);
	if ((n & 15u) != 0u)
		return pg_refuse(g, WR_E_CRYPTO_LEN);
	if (n == 0)
		return WR_OK;
	if (in == NULL || out == NULL)
		return pg_refuse(g, WR_E_INVAL);
	if (pg_partial_overlap(in, out, n))
		return pg_refuse(g, WR_E_INVAL);
	if ((uint64_t)(n >> 4) > (uint64_t)(PG_MAX_BLOCKS - g->blocks))
		return pg_refuse(g, WR_E_CRYPTO_LEN); /* the counter would wrap: refused before any byte is written, also for a host */
	if (g->host != NULL) {
		g->blocks += (uint32_t)(n >> 4);
		g->host->gcm_update(g->host->ctx, g->u.host_state, in, out, n);
		return WR_OK;
	}
	g->blocks += (uint32_t)(n >> 4);
	return wri_gcm_update(&g->u.sw, in, out, n);
}

wr_status wri_pgcm_final_enc(wri_pgcm *g, uint8_t tag[WRI_GCM_TAG_LEN])
{
	wr_status st = WR_OK;

	if (g == NULL) {
		if (tag != NULL)
			WR_MEMSET(tag, 0, WRI_GCM_TAG_LEN);
		return WR_E_INVAL;
	}
	if (tag == NULL) {
		pg_close(g);
		return WR_E_INVAL;
	}
	if (!g->keyed || g->op != PG_RUN || g->dir != 0u) {
		pg_close(g); /* also a final of the other direction ends the operation */
		WR_MEMSET(tag, 0, WRI_GCM_TAG_LEN);
		return WR_E_STATE;
	}
	if (g->host != NULL)
		g->host->gcm_final_enc(g->host->ctx, g->u.host_state, tag);
	else
		st = wri_gcm_final_enc(&g->u.sw, tag);
	g->op = PG_IDLE;
	return st;
}

wr_status wri_pgcm_final_dec(wri_pgcm *g, const uint8_t tag[WRI_GCM_TAG_LEN])
{
	wr_status st;

	if (g == NULL)
		return WR_E_INVAL;
	if (tag == NULL) {
		pg_close(g);
		return WR_E_INVAL;
	}
	if (!g->keyed || g->op != PG_RUN || g->dir != 1u) {
		pg_close(g);
		return WR_E_STATE;
	}
	if (g->host != NULL) {
		st = g->host->gcm_final_dec(g->host->ctx, g->u.host_state, tag);
		if (st != WR_OK && st != WR_E_CRYPTO_MAC)
			st = (st < 0) ? st : WR_E_CRYPTO_MAC; /* never a positive non-OK code that a caller might read as success */
	} else {
		st = wri_gcm_final_dec(&g->u.sw, tag);
	}
	g->op = PG_IDLE;
	return st;
}

int wri_pgcm_is_host(const wri_pgcm *g)
{
	return g != NULL && g->host != NULL;
}

void wri_pgcm_abort(wri_pgcm *g)
{
	if (g != NULL && g->keyed)
		pg_close(g);
}

void wri_pgcm_wipe(wri_pgcm *g)
{
	if (g == NULL)
		return;
	if (g->host != NULL && g->keyed)
		g->host->gcm_wipe(g->host->ctx, g->u.host_state);
	wri_secure_zero(g, sizeof(*g));
}
