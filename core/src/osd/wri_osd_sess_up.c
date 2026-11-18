/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_sess_up.c - the wri_m2_upper table of an OSD connection (design 21.4, 21.6): where the bytes of a message go (plan), what a
 * complete message means (message), what READY needs (ready) and what the end of the connection does to the session (closed).
 *
 * The context pointer of the connection is the session entry. A callback of a connection the entry no longer belongs to (the table
 * forgot the slot when it closed it) is ignored: the table never acts on a stale connection.
 *
 * Rules kept here:
 *   - a reply front goes into the session's own front buffer, a longer one is WR_E_OSD_PROTO (the connection fails); the middle segment
 *     must be empty; the data segment goes where the request layer says for that tid, or is thrown away;
 *   - a complete reply is delivered only when its front decodes, its data segment length is the sum of the payload lengths it echoes and
 *     its operation count is the one that was sent: anything else is up->bad_reply and the session closes itself;
 *   - MOSDBackoff is acknowledged only when the transmit queue has room (plan answers WR_E_BUSY otherwise: the frame is held, nothing is
 *     lost), so an ACK_BLOCK is never dropped for lack of room;
 *   - MOSDMap (41) and every other type is discarded and counted.
 */
#include "wri_osd_sess.h"

WR_FILE_LICENCE_MIT

static wri_osd_sess *mine(void *ctx, const wri_m2_conn *c)
{
	wri_osd_sess *s = (wri_osd_sess *)ctx;

	if (s == NULL || c == NULL || s->tab == NULL)
		return NULL;
	if ((s->state != WRI_OS_OPENING && s->state != WRI_OS_READY) || s->conn_slot != c->slot)
		return NULL;
	return s;
}

static uint32_t idx_of(const wri_osd_sess *s)
{
	return (uint32_t)(s - s->tab->s);
}

/* A violation found while planning: remember what it was (it is the cause the request layer sees) and fail the connection. */
static wr_status refuse(wri_osd_sess *s, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	wri_os_err(&s->err, WR_E_OSD_PROTO, line, what, a0, a1, a2);
	return WR_E_OSD_PROTO;
}
#define REFUSE(s, what, a0, a1, a2) refuse((s), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

static wr_status plan_reply(wri_osd_sess *s, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	wri_osd_sess_tab *t = s->tab;
	uint32_t cap = t->x->cfg.osd_front_cap, dcap = 0, nops = 0;
	uint8_t *dst = NULL;

	if (seglen[0] > cap)
		return REFUSE(s, "reply front above osd_front_cap", seglen[0], cap, hdr->tid);
	if (seglen[1] != 0)
		return REFUSE(s, "reply with a middle segment", seglen[1], 0, hdr->tid);
	s->front_len = seglen[0];
	s->rx_data_len = seglen[2];
	sink[0].dst = s->front;
	sink[0].cap = cap;
	t->up.sink(t->up.ctx, idx_of(s), hdr->tid, &dst, &dcap, &nops);
	if (dst != NULL && seglen[2] > dcap) { /* does not fit: read it through, report it when the frame is complete */
		s->rx_flags |= WRI_OSRX_OVER;
		dst = NULL;
	}
	if (dst == NULL)
		dcap = 0;
	s->rx_n_ops = nops > 255u ? 255u : (uint8_t)nops;
	sink[2].dst = dst;
	sink[2].cap = dcap;
	s->rx_tid = dst != NULL && seglen[2] != 0 ? hdr->tid : 0u;
	return WR_OK;
}

static wr_status plan_backoff(wri_osd_sess *s, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	wri_osd_sess_tab *t = s->tab;
	uint32_t cap = t->x->cfg.osd_front_cap;

	if (seglen[0] > cap)
		return REFUSE(s, "backoff front above osd_front_cap", seglen[0], cap, hdr->tid);
	if (seglen[1] != 0 || seglen[2] != 0)
		return REFUSE(s, "backoff with a middle or data segment", seglen[1], seglen[2], hdr->tid);
	/* the ACK_BLOCK this may need is queued at once: wait until the queue is empty rather than drop it */
	if (!t->link.tx_idle(t->link.ctx, s->conn_slot))
		return WR_E_BUSY;
	s->front_len = seglen[0];
	sink[0].dst = s->front;
	sink[0].cap = cap;
	return WR_OK;
}

static wr_status up_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	wri_osd_sess *s;
	unsigned i;

	if (ctx == NULL || c == NULL || hdr == NULL || seglen == NULL || sink == NULL)
		return WR_E_INVAL;
	for (i = 0; i < 3u; i++) {
		sink[i].dst = NULL;
		sink[i].cap = 0;
	}
	s = mine(ctx, c);
	if (s == NULL || s->state != WRI_OS_READY)
		return WR_OK; /* a stale connection, or one that has not passed the feature check: read through and thrown away */
	s->rx_tid = 0;
	s->rx_flags = 0;
	s->rx_n_ops = 0;
	s->front_len = 0;
	s->rx_data_len = 0;
	if (hdr->type == WRI_MSG_OSD_OPREPLY)
		return plan_reply(s, hdr, seglen, sink);
	if (hdr->type == WRI_MSG_OSD_BACKOFF)
		return plan_backoff(s, hdr, seglen, sink);
	return WR_OK; /* MOSDMap and the rest: discarded (counted when the frame is complete) */
}

/* The reply cannot be delivered: tell the request layer which tid, then end the session. */
static void bad_reply(wri_osd_sess *s, uint64_t tid, const wr_errinfo *e)
{
	wri_osd_sess_tab *t = s->tab;

	t->n_bad_replies++;
	t->up.bad_reply(t->up.ctx, idx_of(s), tid, e);
	wri_os_end(t, s, e, 0);
}

static void message_reply(wri_osd_sess *s, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	wri_osd_sess_tab *t = s->tab;
	wri_mosdopreply rep;
	wr_errinfo e;
	uint32_t data_len = s->rx_data_len, nops = s->rx_n_ops, front_n = stored[0];
	uint8_t over = (uint8_t)(s->rx_flags & WRI_OSRX_OVER);
	wr_status st;

	s->rx_tid = 0; /* the data segment is complete: nothing refers to the destination any more */
	s->rx_flags = 0;
	s->rx_n_ops = 0;
	if (over) {
		WRI_OS_ERR(&e, WR_E_OSD_PROTO, "reply data longer than the operation's destination", data_len, 0, hdr->tid);
		bad_reply(s, hdr->tid, &e);
		return;
	}
	st = wri_mosdopreply_decode(s->front, front_n, hdr->version, hdr->compat_version, &rep);
	if (st != WR_OK) {
		WRI_OS_ERR(&e, st, "reply front did not decode", front_n, hdr->version, hdr->tid);
		bad_reply(s, hdr->tid, &e);
		return;
	}
	if (rep.out_total != data_len) {
		WRI_OS_ERR(&e, WR_E_OSD_PROTO, "reply data length differs from the sum of its payload lengths", rep.out_total, data_len,
			   hdr->tid);
		bad_reply(s, hdr->tid, &e);
		return;
	}
	if (nops != 0 && rep.n_ops != nops) {
		WRI_OS_ERR(&e, WR_E_OSD_PROTO, "reply operation count differs from the request's", rep.n_ops, nops, hdr->tid);
		bad_reply(s, hdr->tid, &e);
		return;
	}
	if (!s->replied) { /* it answered once: the failures before it are history */
		s->replied = 1;
		s->fail_streak = 0;
	}
	s->last_used_ms = t->x->now.mono_ms;
	t->n_replies++;
	t->up.reply(t->up.ctx, idx_of(s), hdr->tid, &rep, stored[2]);
}

static void up_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	wri_osd_sess *s;
	wri_mbackoff m;
	wr_errinfo e;
	wr_status st;

	if (ctx == NULL || c == NULL || hdr == NULL || stored == NULL)
		return;
	s = mine(ctx, c);
	if (s == NULL || s->state != WRI_OS_READY)
		return;
	switch (hdr->type) {
	case WRI_MSG_OSD_OPREPLY:
		message_reply(s, hdr, stored);
		break;
	case WRI_MSG_OSD_BACKOFF:
		st = wri_mbackoff_decode(s->front, stored[0], hdr->version, hdr->compat_version, &m);
		if (st != WR_OK) {
			WRI_OS_ERR(&e, st, "backoff front did not decode", stored[0], hdr->version, 0);
			s->tab->n_bad_replies++;
			wri_os_end(s->tab, s, &e, 0);
			break;
		}
		wri_os_bo_handle(s->tab, s, &m);
		break;
	case WRI_MSG_OSD_MAP:
		s->tab->n_osdmap_discarded++;
		break;
	default:
		s->tab->n_other_discarded++;
		break;
	}
}

static void up_ready(void *ctx, wri_m2_conn *c)
{
	wri_osd_sess *s;
	wri_osd_sess_tab *t;
	uint64_t feats, missing;
	wr_errinfo e;

	if (ctx == NULL || c == NULL)
		return;
	s = mine(ctx, c);
	if (s == NULL || s->state != WRI_OS_OPENING)
		return;
	t = s->tab;
	feats = t->link.features != NULL ? t->link.features(t->link.ctx, s->conn_slot) : c->features;
	missing = WRI_OSDFEAT_NEED & ~feats;
	if (missing != 0) { /* an older cluster: say what is missing instead of sending messages it would misread */
		WRI_OS_ERR(&e, WR_E_OSD_VERSION, "OSD connection lacks features the messages need", missing, feats, WRI_OSDFEAT_NEED);
		wri_os_end(t, s, &e, 0);
		return;
	}
	s->features = feats;
	s->msg_version = (feats & WRI_OSDFEAT_SQUID) == WRI_OSDFEAT_SQUID ? WRI_MOSDOP_VERSION : WRI_MOSDOP_VERSION_V8;
	s->state = WRI_OS_READY;
	s->last_used_ms = t->x->now.mono_ms;
	t->up.ready(t->up.ctx, idx_of(s));
}

static void up_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	wri_osd_sess *s;

	if (ctx == NULL || c == NULL)
		return;
	s = mine(ctx, c);
	if (s == NULL)
		return;
	/* a cause this table recorded while planning (it says more than the connection's "upper layer refused") comes first */
	wri_os_lost(s->tab, s, s->err.status != WR_OK ? &s->err : err);
}

const wri_m2_upper *wri_osd_sess_upper(void)
{
	static const wri_m2_upper up = {up_plan, up_message, up_ready, up_closed};

	return &up;
}
