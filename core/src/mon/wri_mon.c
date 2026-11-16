/* SPDX-License-Identifier: MIT */
/*
 * wri_mon.c - the monitor client: memory budget and init, the upper-layer table the monitor
 * connection reports to, the consumer's calls, and ticket renewal over the session (MAuth /
 * MAuthReply, docs/spec/mon-client.md 3.8). The hunting policy and the timers are in
 * wri_mon_hunt.c, the map messages in wri_mon_maps.c.
 *
 * The upper-layer callbacks run inside the connection's step and only record what happened or move
 * bytes; everything that sends, raises an event or decides is done by wri_mon_step().
 */
#include "wri_mon.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define MON_MSG_CAP_MIN 64u         /* smallest mon_msg_cap that can hold a monitor message at all */
#define MON_TICKET_CAP_MAX (1u << 20)
#define MON_AUX_SLACK 2048u         /* renewal buffers: ticket_cap + this (framing, sealed proof, ticket reply) */
#define MON_RENEW_TIMEOUT_DEFAULT_MS 30000u

/* ---- memory ------------------------------------------------------------------------------------ */

static wr_status mon_aux_size(const wr_config *cfg, size_t *out)
{
	size_t n;
	wr_status st = wri_add_sz((size_t)cfg->ticket_cap, MON_AUX_SLACK, &n);

	if (st != WR_OK)
		return st;
	return wri_align_up(n, 16u, out);
}

/* One routine, so mem() and init() cannot disagree. */
static wr_status mon_plan(const wr_config *cfg, size_t *used, size_t *aux)
{
	unsigned i;
	wr_status st;

	if (cfg == NULL || used == NULL || aux == NULL)
		return WR_E_INVAL;
	if (cfg->mapmsg_queue == 0 || cfg->mapmsg_queue > WRI_MON_MAXSLOTS || cfg->mon_msg_cap < MON_MSG_CAP_MIN ||
	    cfg->ticket_cap > MON_TICKET_CAP_MAX)
		return WR_E_INVAL;
	st = mon_aux_size(cfg, aux);
	if (st != WR_OK)
		return st;
	*used = 0;
	for (i = 0; i < cfg->mapmsg_queue; i++) {
		st = wri_arena_plan(used, cfg->mon_msg_cap, 16u);
		if (st != WR_OK)
			return st;
	}
	for (i = 0; i < 2u; i++) {
		st = wri_arena_plan(used, *aux, 16u);
		if (st != WR_OK)
			return st;
	}
	return WR_OK;
}

wr_status wri_mon_bulk_mem(const wr_config *cfg, size_t *bulk_bytes)
{
	size_t used = 0, aux = 0;
	wr_status st;

	if (bulk_bytes == NULL)
		return WR_E_INVAL;
	*bulk_bytes = 0;
	st = mon_plan(cfg, &used, &aux);
	if (st == WR_OK)
		*bulk_bytes = used;
	return st;
}

/* The cluster spec's addresses become msgr2 addresses (family 0 entries are ignored, port 0 means 3300). */
static unsigned mon_init_addrs(wri_mon *m, const wr_cluster_spec *spec)
{
	unsigned i, n = 0;

	for (i = 0; i < spec->n_mons && i < WR_MAX_MONS && n < WRI_MON_MAXMONS; i++) {
		wr_addr a = spec->mons[i];

		if (a.family != WR_AF_IPV4 && a.family != WR_AF_IPV6)
			continue;
		if (a.port == 0)
			a.port = (uint16_t)WRI_MON_DEFAULT_PORT;
		wri_eaddr_from_wr(&m->addrs[n], &a, WRI_EADDR_TYPE_MSGR2);
		n++;
	}
	m->n_addrs = (uint8_t)n;
	return n;
}

static wr_status mon_init_bulk(wri_mon *m, const wri_ctx *x, wri_arena *bulk, size_t aux)
{
	unsigned i;

	for (i = 0; i < x->cfg.mapmsg_queue; i++) {
		m->slot[i].buf = (uint8_t *)wri_arena_take(bulk, x->cfg.mon_msg_cap, 16u);
		if (m->slot[i].buf == NULL)
			return WR_E_BUDGET;
	}
	m->abuf = (uint8_t *)wri_arena_take(bulk, aux, 16u);
	m->fbuf = (uint8_t *)wri_arena_take(bulk, aux, 16u);
	if (m->abuf == NULL || m->fbuf == NULL)
		return WR_E_BUDGET;
	m->abuf_cap = (uint32_t)aux;
	m->nslots = x->cfg.mapmsg_queue;
	return WR_OK;
}

static void mon_init_state(wri_mon *m, const wri_ctx *x)
{
	/* The back-off never goes below WRI_MON_MIN_WAIT_MS, so no configuration makes a tight retry loop. */
	m->min_wait_ms = x->cfg.hunt_backoff_min_ms < WRI_MON_MIN_WAIT_MS ? WRI_MON_MIN_WAIT_MS : x->cfg.hunt_backoff_min_ms;
	m->max_wait_ms = x->cfg.hunt_backoff_max_ms < m->min_wait_ms ? m->min_wait_ms : x->cfg.hunt_backoff_max_ms;
	m->backoff_ms = m->min_wait_ms;
	m->conn_slot = WRI_MON_NO_SLOT;
	m->plan_slot = 0xffu;
	m->renew_at_ms = WR_DEADLINE_NONE;
	m->deadline_ms = 0;
	m->x = x;
	m->st = WRI_MON_IDLE;
}

wr_status wri_mon_init(wri_mon *m, const wri_ctx *x, wri_arena *bulk, const wr_cluster_spec *spec)
{
	size_t used = 0, aux = 0;
	wr_status st;

	if (m == NULL)
		return WR_E_INVAL;
	WR_MEMSET(m, 0, sizeof(*m));
	if (x == NULL || bulk == NULL || spec == NULL)
		return WR_E_INVAL;
	st = mon_plan(&x->cfg, &used, &aux);
	if (st != WR_OK)
		return st;
	if (mon_init_addrs(m, spec) == 0) {
		WR_MEMSET(m, 0, sizeof(*m));
		return WR_E_MON_NO_V2_ADDR;
	}
	st = mon_init_bulk(m, x, bulk, aux);
	if (st != WR_OK) {
		WR_MEMSET(m, 0, sizeof(*m));
		return st;
	}
	if (spec->fsid_known) {
		WR_MEMCPY(m->fsid, spec->fsid, sizeof(m->fsid));
		m->fsid_known = 1;
	}
	mon_init_state(m, x);
	return WR_OK;
}

/* ---- the upper-layer table ----------------------------------------------------------------------- */

/* The callbacks of a connection that is not the current monitor connection are ignored. */
static int mon_mine(const wri_mon *m, const wri_m2_conn *c)
{
	return m != NULL && c != NULL && m->conn_slot != WRI_MON_NO_SLOT && c->slot == m->conn_slot;
}

static wr_status up_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3],
			 wri_m2_sink sink[3])
{
	wri_mon *m = (wri_mon *)ctx;
	unsigned i;

	if (m == NULL || c == NULL || hdr == NULL || seglen == NULL || sink == NULL)
		return WR_E_INVAL;
	for (i = 0; i < 3u; i++) {
		sink[i].dst = NULL;
		sink[i].cap = 0;
	}
	if (!mon_mine(m, c))
		return WR_OK; /* a stale connection: read through and thrown away */
	return wri_mon_plan_msg(m, hdr, seglen, sink);
}

static void up_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	wri_mon *m = (wri_mon *)ctx;

	if (mon_mine(m, c) && hdr != NULL && stored != NULL)
		wri_mon_on_msg(m, hdr, stored);
}

static void up_ready(void *ctx, wri_m2_conn *c)
{
	wri_mon *m = (wri_mon *)ctx;

	if (mon_mine(m, c) && m->st == WRI_MON_CONNECTING)
		m->ev_ready = 1;
}

static void up_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	wri_mon *m = (wri_mon *)ctx;

	if (!mon_mine(m, c) || m->ev_closed)
		return;
	m->ev_closed = 1;
	if (err != NULL)
		m->close_err = *err;
	else
		WR_MEMSET(&m->close_err, 0, sizeof(m->close_err));
	if (m->close_err.status == WR_OK) { /* closed by the owner without a cause: still the end of the session */
		m->close_err.status = WR_E_NET_CLOSED;
		m->close_err.module = (uint8_t)WR_MOD_MON;
		m->close_err.what = "monitor connection closed";
	}
}

const wri_m2_upper *wri_mon_upper(void)
{
	static const wri_m2_upper up = {up_plan, up_message, up_ready, up_closed};

	return &up;
}

uint64_t wri_mon_deadline(const wri_mon *m)
{
	if (m == NULL)
		return WR_DEADLINE_NONE;
	return m->deadline_ms;
}

/* ---- ticket renewal over the session (mon-client.md 3.8) ---------------------------------------------- */

/* Build the MAuth front into fbuf: the cephx request payload (in abuf) wrapped as the message body. Returns its length or 0. */
static uint32_t renew_build(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	wri_wr w, f;
	wr_status st;

	wri_wr_init(&w, m->abuf, m->abuf_cap);
	st = wri_cx_renew_build(cx, 0, &w);
	if (st != WR_OK) {
		WRI_MON_FAIL(x, m, cx, link, st, "could not build the ticket renewal request", cx->err.status, 0, 0);
		return 0;
	}
	wri_wr_init(&f, m->fbuf, m->abuf_cap);
	wri_mauth_encode(&f, WRI_AUTH_METHOD_CEPHX, m->abuf, wri_wr_len(&w), 0);
	if (!wri_wr_ok(&f)) {
		WRI_MON_FAIL(x, m, cx, link, f.err, "ticket renewal message does not fit", wri_wr_len(&w), m->abuf_cap, 0);
		return 0;
	}
	return (uint32_t)wri_wr_len(&f);
}

/* Send the MAuth request. Returns 1 if it is out (state RENEW), 0 if the queue was full (retry), -1 if the renewal failed. */
static int renew_send(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	wri_m2_msg_out out;
	wr_status st;
	uint32_t n = renew_build(x, m, cx, link);

	if (n == 0)
		return -1;
	WR_MEMSET(&out, 0, sizeof(out));
	out.type = (uint16_t)WRI_MSG_AUTH;
	out.priority = 127u; /* CEPH_MSG_PRIO_HIGH, as the stock client sends it (vector mauth-renewal) */
	out.version = 1u;
	out.compat_version = 1u;
	out.front = m->fbuf;
	out.front_len = n;
	st = link->send(link->ctx, m->conn_slot, &out);
	if (st == WR_E_BUSY)
		return 0;
	if (st != WR_OK) {
		WRI_MON_FAIL(x, m, cx, link, st, "ticket renewal request could not be sent", 0, 0, 0);
		return -1;
	}
	m->ar_len = 0;
	m->st = WRI_MON_RENEW;
	m->renew_deadline_ms = wri_mon_add_ms(x->now.mono_ms, x->cfg.keepalive_timeout_ms != 0
								   ? x->cfg.keepalive_timeout_ms
								   : MON_RENEW_TIMEOUT_DEFAULT_MS);
	return 1;
}

/* Something is due: renew the OSD ticket in place, or reconnect when the AUTH ticket itself is due. */
static void renew_due(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	const wri_cx_ticket *t = wri_cx_ticket_get(cx, WRI_CX_SERVICE_AUTH);
	uint64_t now = x->now.mono_ms;
	wr_errinfo planned;
	int r;

	if (t != NULL && t->have && now >= t->renew_at_ms) {
		/* The AUTH ticket cannot be renewed in-session (cephx.md 3.6): a new session reclaims the global id
		 * with the old ticket and gets a new one. Planned, not a failure; it waits the minimum back-off. */
		WR_MEMSET(&planned, 0, sizeof(planned));
		planned.module = (uint8_t)WR_MOD_MON;
		planned.line = (uint16_t)__LINE__;
		planned.what = "reconnecting to renew the AUTH ticket";
		wri_mon_lose(x, m, cx, link, &planned, 0);
		return;
	}
	if (m->renew_rounds >= WRI_MON_RENEW_AGAIN_MAX) {
		m->renew_rounds = 0;
		m->renew_hold_ms = wri_mon_add_ms(now, m->min_wait_ms);
		return;
	}
	r = renew_send(x, m, cx, link);
	if (r > 0)
		m->renew_rounds++;
	else if (r == 0) {
		m->retry = 1;
		m->renew_hold_ms = wri_mon_add_ms(now, WRI_MON_RETRY_MS); /* the queue was full: ask again in a moment */
	}
}

/* Checks of a decoded MAuthReply that do not need the ticket store; fails the session and returns -1 on a bad one. */
static int renew_reply_ok(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link, const wri_mauth_reply *rep)
{
	if (rep->protocol != WRI_AUTH_METHOD_CEPHX) {
		WRI_MON_FAIL(x, m, cx, link, WR_E_AUTH_PROTO, "MAuthReply for another auth method", rep->protocol, 0, 0);
		return -1;
	}
	/* A different global id means the monitor session identity changed: treated as an error (mon-client.md 3.8). */
	if (rep->global_id != 0 && rep->global_id != cx->global_id) {
		WRI_MON_FAIL(x, m, cx, link, WR_E_AUTH_PROTO, "MAuthReply carries another global id", rep->global_id,
			     cx->global_id, 0);
		return -1;
	}
	if (rep->result != 0) {
		wr_errinfo e;

		WR_MEMSET(&e, 0, sizeof(e));
		e.status = WR_E_AUTH_RESULT;
		e.module = (uint8_t)WR_MOD_MON;
		e.line = (uint16_t)__LINE__;
		e.peer_result = rep->result;
		e.what = "monitor refused the ticket renewal";
		wri_mon_lose(x, m, cx, link, &e, 0);
		return -1;
	}
	return 0;
}

/* A MAuthReply is waiting in abuf. */
static void renew_reply(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	wri_mauth_reply rep;
	wr_status st = wri_mauth_reply_decode(m->abuf, m->ar_len, &rep);
	uint64_t due;

	m->ar_len = 0;
	if (st != WR_OK) {
		WRI_MON_FAIL(x, m, cx, link, st, "malformed MAuthReply", 0, 0, 0);
		return;
	}
	if (renew_reply_ok(x, m, cx, link, &rep) != 0)
		return;
	st = wri_cx_renew_handle(cx, rep.payload, rep.payload_len);
	if (st != WR_OK) {
		WRI_MON_FAIL(x, m, cx, link, st, "ticket renewal reply rejected", cx->err.status, 0, 0);
		return;
	}
	m->st = WRI_MON_ACTIVE;
	link->event(link->ctx, WR_EV_TICKETS_RENEWED, 0, NULL);
	due = wri_cx_next_renew_ms(cx);
	m->renew_at_ms = due;
	if (due != WR_DEADLINE_NONE && x->now.mono_ms >= due)
		renew_due(x, m, cx, link); /* still something due: the "again" loop, capped */
	else
		m->renew_rounds = 0;
}

void wri_mon_renew_step(const wri_ctx *x, wri_mon *m, wri_cx_client *cx, const wri_mon_link *link)
{
	uint64_t now = x->now.mono_ms;

	if (cx == NULL || link->send == NULL || link->event == NULL)
		return;
	if (m->st == WRI_MON_RENEW) {
		if (m->ar_err != WR_OK)
			WRI_MON_FAIL(x, m, cx, link, m->ar_err, "MAuthReply cannot be used", 0, 0, 0);
		else if (m->ar_len != 0)
			renew_reply(x, m, cx, link);
		else if (now >= m->renew_deadline_ms)
			WRI_MON_FAIL(x, m, cx, link, WR_E_TIMEOUT, "no MAuthReply for the ticket renewal", 0, 0, 0);
		return;
	}
	if (m->st != WRI_MON_ACTIVE)
		return;
	m->renew_at_ms = wri_cx_next_renew_ms(cx);
	if (m->renew_at_ms != WR_DEADLINE_NONE && now >= m->renew_at_ms && now >= m->renew_hold_ms)
		renew_due(x, m, cx, link);
}
