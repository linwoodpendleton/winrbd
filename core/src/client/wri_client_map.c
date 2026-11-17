/* SPDX-License-Identifier: MIT */
/*
 * wri_client_map.c - the OSD map store inside the engine (docs/design/core-architecture.md 15.6).
 *
 * With wr_config.map_slot_bytes != 0 the engine is the consumer of the monitor's map messages: the store (wri_mapstore.h)
 * polls the monitor client's slots itself, so the monitor link swallows WR_EV_MAPMSG and wr_client_mapmsg_peek hands out
 * nothing (one consumer, not two). This file is the glue: the store's io over the monitor client and the event ring, the
 * stage of wr_client_run, and the end of the client when the first map can never be used.
 */
#include "wri_client.h"

WR_FILE_LICENCE_MIT

/* ---- the store's io ---------------------------------------------------------------------------------- */

static int io_peek(void *ctx, wr_mapmsg *out)
{
	return wri_mon_mapmsg_peek(&((wr_client *)ctx)->mon, out);
}

static void io_release(void *ctx)
{
	wri_mon_mapmsg_release(&((wr_client *)ctx)->mon);
}

static void io_want_osdmap(void *ctx, uint32_t start)
{
	wri_mon_want_osdmap(&((wr_client *)ctx)->mon, start);
}

static void io_event(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	wri_client_push_event((wr_client *)ctx, kind, epoch, err);
}

void wri_client_map_io_init(wr_client *c)
{
	WR_MEMSET(&c->map_io, 0, sizeof(c->map_io));
	c->map_io.ctx = c;
	c->map_io.peek = io_peek;
	c->map_io.release = io_release;
	c->map_io.want_osdmap = io_want_osdmap;
	c->map_io.event = io_event;
}

/* ---- the stage of a run -------------------------------------------------------------------------------- */

/* The first map can never be decoded (WR_EV_FATAL was raised by the store): the client ends like it does without randomness. */
static void map_fatal(wr_client *c)
{
	wr_errinfo why = c->map.err;

	if (c->state == WR_CS_FAILED)
		return;
	if (why.status == WR_OK)
		WRI_ERRINFO(&why, WR_E_MAP_BUDGET, WR_MOD_MAP, "the first OSD map cannot be used", 0, 0, 0);
	c->state = WR_CS_FAILED;
	WRI_LOG(&c->x, WR_LOG_ERR, WR_MOD_CLIENT, 0, why.status, "OSD map unusable, client stopped", 0, 0, 0, 0);
	wri_client_conn_close_all(c, why.status);
}

int wri_client_map_step(wr_client *c, uint32_t budget)
{
	uint32_t asked = c->map.st.n_resync;
	int more;

	if (!c->map.enabled)
		return 0;
	if (budget == 0u)
		budget = 1u;
	more = wri_mapstore_step(&c->x, &c->map, &c->map_io, &budget);
	if (c->map.fatal)
		map_fatal(c);
	/* The store asked the monitor client for a full map during this step. The monitor step ran before it, so the request
	 * goes out at the next run: say so, instead of leaving it to the host's timer (the monitor client's deadline is "now" too). */
	if (c->map.st.n_resync != asked)
		more = 1;
	return more;
}

uint64_t wri_client_map_deadline(const wr_client *c)
{
	return c->map.enabled ? wri_mapstore_deadline(&c->map) : WR_DEADLINE_NONE;
}
