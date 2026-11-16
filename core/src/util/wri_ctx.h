/* SPDX-License-Identifier: MIT */
/*
 * wri_ctx.h - the environment every stateful module receives: host ops, config, current time.
 * One instance lives in the client; modules take a `const wri_ctx *` as first parameter.
 * Stateless code (cursors, crypto reference implementations, decoders) does not need it.
 */
#ifndef WRI_CTX_H
#define WRI_CTX_H

#include "wr_config.h"
#include "wr_host.h"
#include "wr_types.h"

typedef struct wri_ctx {
	wr_host_ops host; /* copy; host.prim may be NULL */
	wr_config cfg;    /* copy */
	wr_clock now;     /* set by wr_client_run() at its start; modules read it, never write it */
} wri_ctx;

/* Fill out[0..n) from host.random. WR_E_HOST_RANDOM if the host has no source or it failed. */
WR_MUST_CHECK wr_status wri_random(const wri_ctx *x, uint8_t *out, size_t n);

/* Emit a log record if the host has a sink and level <= WR_LOG_MAX_LEVEL. Never pass secrets. */
void wri_log_emit(const wri_ctx *x, unsigned level, unsigned module, wr_conn_id conn, wr_status st,
		  const char *msg, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3);

#define WRI_LOG(x, lvl, mod, conn, st, msg, a0, a1, a2, a3)                                      \
	do {                                                                                     \
		if ((lvl) <= WR_LOG_MAX_LEVEL)                                                   \
			wri_log_emit((x), (lvl), (mod), (conn), (st), (msg), (uint64_t)(a0),     \
				     (uint64_t)(a1), (uint64_t)(a2), (uint64_t)(a3));           \
	} while (0)

/* Record the first error into an errinfo (ignored if one is already recorded). */
void wri_errinfo_set(wr_errinfo *e, wr_status st, unsigned module, unsigned line, const char *what,
		     uint64_t a0, uint64_t a1, uint64_t a2);
#define WRI_ERRINFO(e, st, mod, what, a0, a1, a2) \
	wri_errinfo_set((e), (st), (mod), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

#endif /* WRI_CTX_H */
