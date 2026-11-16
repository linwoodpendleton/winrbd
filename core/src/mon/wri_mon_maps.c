/* SPDX-License-Identifier: MIT */
/*
 * wri_mon_maps.c - the messages of a monitor session: routing the incoming MMonMap / MOSDMap /
 * MAuthReply fronts into their buffers, applying them (docs/spec/mon-client.md 3.4, 3.5), the
 * bulk slots the consumer reads, and the two messages the client sends after READY
 * (MMonGetMap, MMonSubscribe, 3.3).
 *
 * Maps are delivered RAW: a slot holds the msgr2 front exactly as received (already checksum
 * verified); only the header facts are read (wri_mosdmap_info_decode, the MonMap epoch and fsid).
 * A message that turns out to be a duplicate, an older MonMap, damaged or from another cluster
 * leaves its slot free, so the consumer never sees it.
 */
#include "wri_mon.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define NO_PLAN 0xffu

/* ---- slots ---------------------------------------------------------------------------------------- */

static int slot_find_free(const wri_mon *m)
{
	unsigned i;

	for (i = 0; i < m->nslots; i++)
		if (m->slot[i].kind == 0)
			return (int)i;
	return -1;
}

/* The occupied slot with the smallest order, filtered by `want_unnotified` (only slots without an event yet) or not. */
static wri_mapslot *slot_oldest(wri_mon *m, int want_unnotified)
{
	wri_mapslot *best = NULL;
	unsigned i;

	for (i = 0; i < m->nslots; i++) {
		wri_mapslot *s = &m->slot[i];

		if (s->kind == 0 || (want_unnotified && s->notified))
			continue;
		if (best == NULL || (int32_t)(s->order - best->order) < 0)
			best = s;
	}
	return best;
}

void wri_mon_notify_maps(wri_mon *m, const wri_mon_link *link)
{
	unsigned guard;

	if (link->event == NULL)
		return;
	for (guard = 0; guard < m->nslots; guard++) {
		wri_mapslot *s = slot_oldest(m, 1);

		if (s == NULL)
			return;
		s->notified = 1;
		link->event(link->ctx, WR_EV_MAPMSG, s->newest_epoch, NULL);
	}
}

/* A new session starts clean as far as the messages in flight go; slots already delivered stay. */
void wri_mon_slots_reset_session(wri_mon *m)
{
	m->plan_slot = NO_PLAN;
	m->plan_auth = 0;
	m->ar_len = 0;
	m->ar_err = WR_OK;
	m->stalled = 0;
}

void wri_mon_mapmsg_stats(const wri_mon *m, uint32_t *in_use, uint32_t *hiwater)
{
	unsigned i;
	uint32_t n = 0;

	if (m == NULL)
		return;
	for (i = 0; i < m->nslots; i++)
		n += m->slot[i].kind != 0;
	if (in_use != NULL)
		*in_use = n;
	if (hiwater != NULL)
		*hiwater = m->slot_hiwater;
}

int wri_mon_mapmsg_peek(wri_mon *m, wr_mapmsg *out)
{
	wri_mapslot *s;

	if (m == NULL || out == NULL)
		return 0;
	s = slot_oldest(m, 0);
	if (s == NULL)
		return 0;
	s->held = 1;
	out->kind = (wr_mapmsg_kind)s->kind;
	out->msg_version = s->msg_version;
	out->msg_compat = s->msg_compat;
	out->newest_epoch = s->newest_epoch;
	out->front = s->buf;
	out->front_len = s->len;
	return 1;
}

void wri_mon_mapmsg_release(wri_mon *m)
{
	wri_mapslot *s;

	if (m == NULL)
		return;
	s = slot_oldest(m, 0);
	if (s == NULL || !s->held)
		return; /* nothing peeked: nothing to free */
	s->kind = 0;
	s->held = 0;
	s->notified = 0;
	s->len = 0;
	s->newest_epoch = 0;
	s->msg_version = s->msg_compat = 0;
}

void wri_mon_want_osdmap(wri_mon *m, uint32_t start)
{
	if (m == NULL)
		return;
	m->sub_osdmap_start = start;
	m->osdmap_have = start != 0 ? start - 1u : 0;
	m->resub = 1;
	m->deadline_ms = 0; /* the cached deadline is stale now: the new subscription goes out at the next step, not at the next timer */
}

/* ---- receive routing ---------------------------------------------------------------------------------- */

/* Where a map front goes: a free slot, or busy / discard. */
static wr_status plan_map(wri_mon *m, uint16_t type, uint16_t compat, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	const wri_ctx *x = m->x;
	int idx;

	if (seglen[0] == 0) {
		m->n_bad_msg++;
		return WR_OK;
	}
	/* A layout newer than the one we read cannot be told apart from garbage: refuse it like any damaged map. */
	if (compat > (type == WRI_MSG_MON_MAP ? WRI_MMONMAP_MAX_VERSION : WRI_MOSDMAP_MAX_VERSION)) {
		m->n_bad_msg++;
		WRI_LOG(x, WR_LOG_WARN, WR_MOD_MON, 0, WR_E_MON_PROTO, "map message needs a newer decoder, discarded", type,
			compat, seglen[0], m->n_bad_msg);
		return WR_OK;
	}
	if (seglen[0] > x->cfg.mon_msg_cap) { /* open question R2: discard, count, keep the session */
		m->n_toobig++;
		WRI_LOG(x, WR_LOG_WARN, WR_MOD_MON, 0, WR_E_MON_MSG_TOOBIG, "map message above mon_msg_cap discarded", type,
			seglen[0], x->cfg.mon_msg_cap, m->n_toobig);
		return WR_OK;
	}
	idx = slot_find_free(m);
	if (idx < 0) {
		m->stalled = 1; /* every slot is held by the consumer: the connection stalls, nothing is dropped */
		return WR_E_BUSY;
	}
	m->stalled = 0;
	m->plan_slot = (uint8_t)idx;
	sink[0].dst = m->slot[idx].buf;
	sink[0].cap = x->cfg.mon_msg_cap;
	return WR_OK;
}

wr_status wri_mon_plan_msg(wri_mon *m, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	m->plan_slot = NO_PLAN;
	m->plan_auth = 0;
	if (hdr->type == WRI_MSG_MON_MAP || hdr->type == WRI_MSG_OSD_MAP)
		return plan_map(m, hdr->type, hdr->compat_version, seglen, sink);
	/* The answer to a renewal request in flight, and only while the last one has been dealt with. */
	if (hdr->type == WRI_MSG_AUTH_REPLY && m->st == WRI_MON_RENEW && m->ar_len == 0 && m->ar_err == WR_OK) {
		if (seglen[0] == 0 || hdr->compat_version > WRI_MAUTHREPLY_MAX_VERSION) {
			m->ar_err = WR_E_MON_PROTO; /* the answer, but not one we can read: step fails the session at once, not by timeout */
			return WR_OK;
		}
		if (seglen[0] > m->abuf_cap) {
			m->ar_err = WR_E_MON_MSG_TOOBIG;
			return WR_OK;
		}
		m->plan_auth = 1;
		sink[0].dst = m->abuf;
		sink[0].cap = m->abuf_cap;
		return WR_OK;
	}
	m->n_ignored++; /* MMonSubscribeAck, MConfig, MPing, MgrMap, anything else: tolerated and ignored (mon-client.md 4) */
	return WR_OK;
}

/* ---- applying maps ---------------------------------------------------------------------------------------- */

/* 0 = the message may be used, -1 = drop it. The first fsid seen is learned when the spec had none. */
static int fsid_check(wri_mon *m, const uint8_t fsid[16])
{
	const wri_ctx *x = m->x;

	if (!m->fsid_known) {
		WR_MEMCPY(m->fsid, fsid, sizeof(m->fsid));
		m->fsid_known = 1;
		m->fsid_bad = 0;
		return 0;
	}
	if (wri_ct_memeq(m->fsid, fsid, sizeof(m->fsid))) {
		m->fsid_bad = 0;
		return 0;
	}
	m->n_fsid_drop++;
	if (m->fsid_bad < 255u)
		m->fsid_bad++;
	if (m->fsid_bad >= WRI_MON_FSID_MAX)
		m->fsid_fail = 1; /* step ends the session with WR_E_MON_FSID */
	WRI_LOG(x, WR_LOG_WARN, WR_MOD_MON, 0, WR_E_MON_FSID, "map message of another cluster dropped", m->fsid_bad,
		m->n_fsid_drop, 0, 0);
	return -1;
}

static void slot_fill(wri_mon *m, wri_mapslot *s, unsigned kind, const wri_m2_hdr2 *hdr, uint32_t len, uint32_t epoch)
{
	s->kind = (uint8_t)kind;
	s->held = 0;
	s->notified = 0;
	s->msg_version = hdr->version;
	s->msg_compat = hdr->compat_version;
	s->newest_epoch = epoch;
	s->len = len;
	s->order = ++m->order_next;
	{
		unsigned i;
		uint32_t n = 0;

		for (i = 0; i < m->nslots; i++)
			n += m->slot[i].kind != 0;
		if (n > m->slot_hiwater)
			m->slot_hiwater = n;
	}
}

/* The monitors of the new map replace the literal addresses; the rank pointer stays on the monitor we are talking to. */
static void monmap_adopt(wri_mon *m)
{
	unsigned i, j = 0;
	int match = -1;

	for (i = 0; i < m->mm.n_mons && i < WRI_MON_MAXMONS; i++) {
		if (!m->mm.rank_valid[i])
			continue;
		m->addrs[j] = m->mm.addr[i];
		if (m->conn_slot != WRI_MON_NO_SLOT && wri_eaddr_equal(&m->mm.addr[i], &m->cur_addr))
			match = (int)j;
		j++;
	}
	if (j == 0)
		return; /* the decoder refuses such a map (WR_E_MON_NO_V2_ADDR); nothing to adopt */
	m->n_addrs = (uint8_t)j;
	m->from_monmap = 1;
	if (match >= 0)
		m->cur_rank = (uint8_t)match, m->rank = (uint8_t)((unsigned)(match + 1) % j);
	else
		m->rank = (uint8_t)(m->rank % j);
	if (m->failed_in_round >= j)
		m->failed_in_round = 0;
}

static void apply_monmap(wri_mon *m, wri_mapslot *s, const wri_m2_hdr2 *hdr, uint32_t n)
{
	const wri_ctx *x = m->x;
	const uint8_t *blob = NULL;
	size_t blen = 0;
	wr_status st = wri_mmonmap_front(s->buf, n, &blob, &blen);

	if (st == WR_OK)
		st = wri_monmap_decode(blob, blen, &m->mm);
	if (st != WR_OK || m->mm.epoch == 0) { /* damaged, too new, or the epoch-0 placeholder: never a map we can use */
		m->n_bad_msg++;
		WRI_LOG(x, WR_LOG_WARN, WR_MOD_MON, 0, st != WR_OK ? st : WR_E_MON_PROTO, "MMonMap not usable, discarded",
			n, m->mm.epoch, 0, 0);
		return;
	}
	if (fsid_check(m, m->mm.fsid) != 0)
		return;
	m->got_monmap = 1; /* the session works, whether or not the map is news */
	if (m->have_monmap && m->mm.epoch <= m->monmap_epoch) {
		m->n_dup_monmap++; /* the second MMonMap of a fresh session, or an older one: idempotent */
		return;
	}
	monmap_adopt(m);
	m->monmap_epoch = m->mm.epoch;
	m->have_monmap = 1;
	slot_fill(m, s, WR_MAPMSG_MONMAP, hdr, n, m->mm.epoch);
}

static void apply_osdmap(wri_mon *m, wri_mapslot *s, const wri_m2_hdr2 *hdr, uint32_t n)
{
	const wri_ctx *x = m->x;
	wr_status st = wri_mosdmap_info_decode(s->buf, n, hdr->version, &m->info);
	uint32_t last;

	if (st != WR_OK) {
		m->n_bad_msg++;
		WRI_LOG(x, WR_LOG_WARN, WR_MOD_MON, 0, st, "MOSDMap not usable, discarded", n, hdr->version, 0, 0);
		return;
	}
	if (fsid_check(m, m->info.fsid) != 0)
		return;
	last = m->info.last_epoch;
	/* The subscription continues after the newest epoch received: a reconnect asks for held + 1. */
	if (last != 0 && last >= m->sub_osdmap_start && last != 0xffffffffu)
		m->sub_osdmap_start = last + 1u;
	if (last > m->osdmap_have)
		m->osdmap_have = last;
	slot_fill(m, s, WR_MAPMSG_OSDMAP, hdr, n, last);
}

void wri_mon_on_msg(wri_mon *m, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	unsigned idx = m->plan_slot;

	switch (hdr->type) {
	case WRI_MSG_MON_MAP:
	case WRI_MSG_OSD_MAP:
		m->plan_slot = NO_PLAN;
		if (idx >= m->nslots || stored[0] == 0 || stored[0] > m->x->cfg.mon_msg_cap || m->slot[idx].kind != 0)
			return; /* discarded at plan time, or the slot is no longer ours (or a connection reported more than it was given) */
		if (hdr->type == WRI_MSG_MON_MAP)
			apply_monmap(m, &m->slot[idx], hdr, stored[0]);
		else
			apply_osdmap(m, &m->slot[idx], hdr, stored[0]);
		return;
	case WRI_MSG_AUTH_REPLY:
		if (m->plan_auth && stored[0] <= m->abuf_cap)
			m->ar_len = stored[0];
		m->plan_auth = 0;
		return;
	default:
		return;
	}
}

/* ---- what the client sends after READY ---------------------------------------------------------------------- */

/* MMonGetMap: empty body, header version 1, priority 127 (vector mmongetmap). */
wr_status wri_mon_send_getmap(const wri_mon_link *link, uint16_t slot)
{
	wri_m2_msg_out out;

	WR_MEMSET(&out, 0, sizeof(out));
	out.type = (uint16_t)WRI_MSG_MON_GET_MAP;
	out.priority = 127u;
	out.version = 1u;
	out.compat_version = 1u;
	return link->send(link->ctx, slot, &out);
}

/*
 * MMonSubscribe v3 (version 3, compat 1, priority 127): "monmap" with start 0 until a real map is held, then
 * epoch + 1; "osdmap" CONTINUOUS (flags 0) from sub_osdmap_start (0 on the first session, then held + 1); the
 * host name is left empty. Items go in name order, as the monitor's map would hold them.
 */
wr_status wri_mon_send_subscribe(const wri_mon *m, const wri_mon_link *link, uint16_t slot)
{
	wri_sub_item items[2];
	uint8_t buf[64];
	wri_wr w;
	wri_m2_msg_out out;

	items[0].what = "monmap";
	items[0].start = m->have_monmap ? (uint64_t)m->monmap_epoch + 1u : 0u;
	items[0].flags = 0;
	items[1].what = "osdmap";
	items[1].start = m->sub_osdmap_start;
	items[1].flags = 0;
	wri_wr_init(&w, buf, sizeof(buf));
	wri_mmonsubscribe_encode(&w, items, 2u, "");
	if (!wri_wr_ok(&w))
		return w.err;
	WR_MEMSET(&out, 0, sizeof(out));
	out.type = (uint16_t)WRI_MSG_MON_SUBSCRIBE;
	out.priority = 127u;
	out.version = 3u;
	out.compat_version = 1u;
	out.front = buf;
	out.front_len = (uint32_t)wri_wr_len(&w);
	return link->send(link->ctx, slot, &out);
}
