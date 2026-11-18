/* SPDX-License-Identifier: MIT */
/*
 * wri_client_osd_conn.c - the OSD session layer's view of the engine's connection table (wri_osd_link, wri_osd_sess.h): the same slots, handshake pool
 * and msgr2 machine as the monitor's connection, opened with role OSD and the slot's own cephx handshake context (design 21.1, 21.2).
 *
 * The session table remembers a slot number only; everything it asks for goes through the hooks below (features is left out: the connection handed to the session's ready callback carries the word). The slot work itself (free slot, free
 * handshake slot, the per-slot cephx context, accounting) is wri_client_conn_open in wri_client_conn.c; this file adds the ticket gate and the
 * queries.
 */
#include "wri_client_osd.h"

WR_FILE_LICENCE_MIT

static int engine_ok(const wr_client *c)
{
	return c != NULL && c->magic == WRI_CLIENT_MAGIC && c->og != NULL;
}

wr_status wri_client_conn_open_osd(wr_client *c, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot)
{
	if (!engine_ok(c) || addr == NULL || up == NULL || slot == NULL)
		return WR_E_INVAL;
	/* An authorizer needs an OSD ticket: without one the open would only fail after a connect (design 21.2). */
	if (!wri_cx_have(&c->cx, WRI_CX_SERVICE_OSD, c->x.now.mono_ms))
		return WR_E_BUSY;
	return wri_client_conn_open(c, WRI_ENTITY_OSD, addr, up, up_ctx, slot);
}

static wr_status osd_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot)
{
	return wri_client_conn_open_osd((wr_client *)ctx, addr, up, up_ctx, slot);
}

/* Static wrappers: the address of an extern function would need the global offset table in a position-independent build (core_no_libc). */
static void osd_close(void *ctx, uint16_t slot, wr_status why)
{
	wri_client_link_close(ctx, slot, why);
}

static wr_status osd_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	return wri_client_link_send(ctx, slot, m);
}

static int osd_tx_idle(void *ctx, uint16_t slot)
{
	const wr_client *c = (const wr_client *)ctx;

	if (!engine_ok(c) || slot >= c->n_slot || !c->slot[slot].in_use)
		return 1; /* nothing of ours is queued on a connection that is not there */
	return wri_m2_txq_idle(&c->slot[slot].conn.tx) != 0;
}

static int osd_have_ticket(void *ctx)
{
	const wr_client *c = (const wr_client *)ctx;

	return engine_ok(c) && wri_cx_have(&c->cx, WRI_CX_SERVICE_OSD, c->x.now.mono_ms) != 0;
}

static int osd_handshake_free(void *ctx)
{
	const wr_client *c = (const wr_client *)ctx;
	uint32_t i;

	if (!engine_ok(c))
		return 0;
	for (i = 0; i < c->n_pa; i++)
		if (!c->pa_used[i])
			return 1;
	return 0;
}

void wri_client_osd_link(wr_client *c, wri_osd_link *out)
{
	WR_MEMSET(out, 0, sizeof(*out));
	out->ctx = c;
	out->open = osd_open;
	out->close = osd_close;
	out->send = osd_send;
	out->tx_idle = osd_tx_idle;
	out->features = NULL; /* optional: the connection handed to the ready callback carries the negotiated word */
	out->have_ticket = osd_have_ticket;
	out->handshake_free = osd_handshake_free;
}
