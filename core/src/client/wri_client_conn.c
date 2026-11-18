/* SPDX-License-Identifier: MIT */
/*
 * wri_client_conn.c - the connection table of the engine: slots with generation-checked ids, the
 * host-facing wr_conn_* calls, the derived action scan (wr_client_next_action) and the hooks the
 * monitor client drives its connection through (wri_mon_link).
 *
 * Actions are not queued. Three flags per slot (WANT_CONNECT, CONNECT_SENT, CLOSE_SENT, TX_NOTIFIED)
 * plus the state of the msgr2 connection say what the host still has to be told:
 *   - CONNECT: the connection waits for TCP and the host was not told yet;
 *   - CLOSE:   the connection ended (failed or asked to close) after the host was told to connect;
 *   - TX_READY: the transmit queue went from idle to busy.
 * Each is emitted once; a slot whose connection ended before the host saw a CONNECT is freed silently.
 *
 * A slot is opened with a role: MON authenticates with the cephx client's embedded handshake, OSD with a context of its own per slot.
 *
 * Handshake slots. A connection borrows one of max_handshakes transcript pairs at open; the msgr2
 * connection sets its `pa` pointer to NULL once the transcript is wiped (signature verified, or any
 * failure), and the engine then returns the slot (housekeeping runs after every call that can do it).
 */
#include "wri_client.h"

#include "wri_client_osd.h"

WR_FILE_LICENCE_MIT

static int engine_ok(const wr_client *c)
{
	return c != NULL && c->magic == WRI_CLIENT_MAGIC;
}

static int is_live(unsigned st)
{
	return st >= WRI_M2_BANNER && st <= WRI_M2_READY;
}

static int is_dead(unsigned st)
{
	return st == WRI_M2_FAILED || st == WRI_M2_CLOSING;
}

static uint64_t min_u64(uint64_t a, uint64_t b)
{
	return a < b ? a : b;
}

wri_cslot *wri_client_slot_of(wr_client *c, wr_conn_id id)
{
	uint32_t idx;
	wri_cslot *s;

	if (!engine_ok(c) || id == WR_CONN_NONE)
		return NULL;
	idx = id & 0xffffu;
	if (idx == 0u || idx > c->n_slot)
		return NULL;
	s = &c->slot[idx - 1u];
	if (!s->in_use || s->conn.gen != (uint16_t)(id >> 16))
		return NULL;
	return s;
}

/* ---- slots and handshake slots --------------------------------------------------------------------- */

/* Return handshake slot i to the pool. */
static void pa_put(wr_client *c, uint32_t i)
{
	if (i < c->n_pa && c->pa_used[i]) {
		c->pa_used[i] = 0;
		if (c->pa_in_use != 0u)
			c->pa_in_use--;
	}
}

/* The connection let go of its transcript (its `pa` is NULL): the handshake slot goes back to the pool. */
static void pa_reclaim(wr_client *c, wri_cslot *s)
{
	uint32_t i = s->conn.pa_slot;

	if (i == WRI_NIL || s->conn.pa != NULL)
		return;
	s->conn.pa_slot = WRI_NIL;
	pa_put(c, i);
}

static void slot_release(wr_client *c, wri_cslot *s)
{
	if (s->conn.pa != NULL) { /* cannot happen after on_closed(); wipe and return the transcript anyway */
		wri_m2_preauth_wipe(s->conn.pa);
		s->conn.pa = NULL;
	}
	pa_reclaim(c, s);
	if (c->og != NULL) /* the slot's cephx handshake context (challenges, nonce, the view of the session key): never outlives the connection */
		wri_cx_hs_wipe(&c->og->hs[s - c->slot]);
	s->flags = 0;
	s->in_use = 0;
	s->connect_deadline_ms = WR_DEADLINE_NONE;
}

static uint32_t conns_in_use(const wr_client *c)
{
	uint32_t i, n = 0;

	for (i = 0; i < c->n_slot; i++)
		n += c->slot[i].in_use != 0;
	return n;
}

/* ---- the monitor link ---------------------------------------------------------------------------------- */

static wri_cslot *free_slot(wr_client *c, uint32_t *idx)
{
	uint32_t i;

	for (i = 0; i < c->n_slot; i++) {
		if (!c->slot[i].in_use) {
			*idx = i;
			return &c->slot[i];
		}
	}
	return NULL;
}

static uint32_t free_pa(const wr_client *c)
{
	uint32_t i;

	for (i = 0; i < c->n_pa; i++)
		if (!c->pa_used[i])
			return i;
	return WRI_NIL;
}

/* Open a connection with `role` in a free slot and handshake slot (the monitor link and the OSD link both come here). */
wr_status wri_client_conn_open(wr_client *c, uint8_t role, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot_out)
{
	const wri_auth_ops *auth = wri_cx_ops();
	void *auth_ctx = &c->cx;
	wri_cslot *s;
	uint32_t i = 0, pa, n;
	wr_addr dial;
	wr_conn_id id;

	if (!engine_ok(c) || addr == NULL || up == NULL || slot_out == NULL || (role != WRI_ENTITY_MON && role != WRI_ENTITY_OSD))
		return WR_E_INVAL;
	if (role == WRI_ENTITY_OSD && c->og == NULL)
		return WR_E_INVAL; /* no OSD client, no handshake contexts */
	if (c->state == WR_CS_FAILED)
		return WR_E_BUSY; /* the engine is dead: the callers wait */
	s = free_slot(c, &i);
	pa = free_pa(c);
	if (s == NULL || pa == WRI_NIL)
		return WR_E_BUSY; /* no free connection or handshake slot (an old one is still closing): retry later */
	if (role == WRI_ENTITY_OSD) {
		if (wri_cx_hs_init(&c->og->hs[i], &c->cx) != WR_OK)
			return WR_E_INVAL;
		auth = wri_cx_hs_ops();
		auth_ctx = &c->og->hs[i];
	}
	c->pa_used[pa] = 1;
	c->pa_in_use++;
	if (c->pa_in_use > c->stats.handshakes_hiwater)
		c->stats.handshakes_hiwater = c->pa_in_use;
	wri_eaddr_to_wr(&dial, addr);
	s->conn.gen = (uint16_t)(s->conn.gen + 1u);
	s->conn.pa_slot = pa;
	c->global_seq++;
	id = ((wr_conn_id)s->conn.gen << 16) | (wr_conn_id)(i + 1u);
	wri_m2_conn_open(&s->conn, id, role, addr, &dial, auth, auth_ctx, up, up_ctx, &c->pa[pa], c->my_nonce, c->global_seq);
	s->flags = (uint8_t)WRI_CF_WANT_CONNECT;
	s->in_use = 1;
	s->connect_deadline_ms = WR_DEADLINE_NONE;
	pa_reclaim(c, s); /* a refused open() already let go of the transcript */
	n = conns_in_use(c);
	if (n > c->stats.conns_hiwater)
		c->stats.conns_hiwater = n;
	*slot_out = (uint16_t)i;
	return WR_OK;
}

static wr_status link_open(void *ctx, const wri_eaddr *addr, uint16_t *slot_out)
{
	return wri_client_conn_open((wr_client *)ctx, WRI_ENTITY_MON, addr, wri_mon_upper(), &((wr_client *)ctx)->mon, slot_out);
}

void wri_client_link_close(void *ctx, uint16_t slot, wr_status why)
{
	wr_client *c = (wr_client *)ctx;
	wri_cslot *s;

	if (!engine_ok(c) || slot >= c->n_slot)
		return;
	s = &c->slot[slot];
	if (!s->in_use)
		return;
	wri_m2_conn_close(&c->x, &s->conn, why);
	pa_reclaim(c, s);
}

wr_status wri_client_link_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	wr_client *c = (wr_client *)ctx;

	if (!engine_ok(c) || slot >= c->n_slot || !c->slot[slot].in_use)
		return WR_E_STATE;
	return wri_m2_conn_send_message(&c->x, &c->slot[slot].conn, m);
}

static void link_event(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	/* with maps on the store polls the monitor's slots itself: a raw-message event would send the host to an empty peek (architecture 15.6) */
	if (kind == WR_EV_MAPMSG && ((const wr_client *)ctx)->map.enabled)
		return;
	wri_client_push_event((wr_client *)ctx, kind, epoch, err);
}

static wr_status link_keepalive(void *ctx, uint16_t slot, uint32_t sec, uint32_t nsec)
{
	wr_client *c = (wr_client *)ctx;

	if (!engine_ok(c) || slot >= c->n_slot || !c->slot[slot].in_use)
		return WR_E_STATE;
	return wri_m2_conn_send_keepalive(&c->x, &c->slot[slot].conn, sec, nsec);
}

static uint32_t link_acks(void *ctx, uint16_t slot)
{
	wr_client *c = (wr_client *)ctx;

	if (!engine_ok(c) || slot >= c->n_slot || !c->slot[slot].in_use)
		return 0;
	return c->slot[slot].conn.n_ka_ack;
}

void wri_client_link_init(wr_client *c)
{
	WR_MEMSET(&c->link, 0, sizeof(c->link));
	c->link.ctx = c;
	c->link.open = link_open;
	c->link.close = wri_client_link_close;
	c->link.send = wri_client_link_send;
	c->link.event = link_event;
	c->link.keepalive = link_keepalive;
	c->link.keepalive_acks = link_acks;
}

/* ---- scheduler support ------------------------------------------------------------------------------------ */

int wri_client_conn_step_all(wr_client *c, uint32_t *budget)
{
	uint32_t k, n = c->n_slot, hit = WRI_NIL;

	for (k = 0; k < n; k++) {
		uint32_t i = (c->step_cursor + k) % n;
		wri_cslot *s = &c->slot[i];

		if (!s->in_use)
			continue;
		if (wri_m2_conn_step(&c->x, &s->conn, budget) && hit == WRI_NIL)
			hit = i; /* the first connection that ran the budget out with work left */
		pa_reclaim(c, s);
	}
	if (hit == WRI_NIL)
		return 0;
	/* The next run starts right behind the connection that used the budget up, so the others get their turn first:
	 * no connection with a lot to parse starves the rest. */
	c->step_cursor = (hit + 1u) % n;
	return 1;
}

void wri_client_conn_rebase(wr_client *c)
{
	uint32_t i;
	uint64_t now = c->x.now.mono_ms;

	for (i = 0; i < c->n_slot; i++) {
		wri_cslot *s = &c->slot[i];

		if (!s->in_use || !(s->flags & WRI_CF_REBASE))
			continue;
		s->flags = (uint8_t)(s->flags & ~WRI_CF_REBASE);
		if (s->conn.state >= WRI_M2_BANNER && s->conn.state <= WRI_M2_IDENT && s->conn.deadline_ms != WR_DEADLINE_NONE &&
		    c->x.cfg.handshake_timeout_ms != 0u) {
			s->conn.deadline_ms = wri_mon_add_ms(now, c->x.cfg.handshake_timeout_ms); /* saturating: a huge clock never wraps */
			s->conn.last_rx_ms = s->conn.last_tx_ms = now;
		}
	}
}

void wri_client_conn_housekeeping(wr_client *c)
{
	uint32_t i;

	for (i = 0; i < c->n_slot; i++) {
		wri_cslot *s = &c->slot[i];
		unsigned st;

		if (!s->in_use)
			continue;
		pa_reclaim(c, s);
		st = s->conn.state;
		if (is_dead(st) && !(s->flags & WRI_CF_CONNECT_SENT) && s->conn.close_reported) {
			/* ended before the host saw a connect: there is no socket, nobody will call wr_conn_closed */
			wri_m2_conn_on_closed(&c->x, &s->conn, 0);
			slot_release(c, s);
			continue;
		}
		if (st == WRI_M2_CONNECTING && (s->flags & WRI_CF_CONNECT_SENT) && s->connect_deadline_ms != WR_DEADLINE_NONE &&
		    c->x.now.mono_ms >= s->connect_deadline_ms) {
			/* the host did not report the connect within the time it was given (+ grace): give up on it */
			wri_m2_conn_close(&c->x, &s->conn, WR_E_TIMEOUT);
			pa_reclaim(c, s);
		}
	}
}

uint64_t wri_client_conn_deadline(const wr_client *c)
{
	uint64_t d = WR_DEADLINE_NONE;
	uint32_t i;

	for (i = 0; i < c->n_slot; i++) {
		const wri_cslot *s = &c->slot[i];

		if (!s->in_use)
			continue;
		d = min_u64(d, wri_m2_conn_deadline(&s->conn));
		if (s->conn.state == WRI_M2_CONNECTING && (s->flags & WRI_CF_CONNECT_SENT))
			d = min_u64(d, s->connect_deadline_ms);
	}
	return d;
}

void wri_client_conn_close_all(wr_client *c, wr_status why)
{
	uint32_t i;

	for (i = 0; i < c->n_slot; i++) {
		wri_cslot *s = &c->slot[i];

		if (!s->in_use)
			continue;
		wri_m2_conn_close(&c->x, &s->conn, why);
		pa_reclaim(c, s);
	}
}

void wri_client_conn_stats(const wr_client *c, wr_stats *out)
{
	out->conns_in_use = conns_in_use(c);
	out->conns_hiwater = c->stats.conns_hiwater;
	out->handshakes_in_use = c->pa_in_use;
	out->handshakes_hiwater = c->stats.handshakes_hiwater;
}

/* ---- derived actions ------------------------------------------------------------------------------------------ */

/* The next thing the host has to be told about slot s, or 0. Sets the flag that makes it once-only. */
static int slot_action(wr_client *c, wri_cslot *s, wr_action *out)
{
	unsigned st = s->conn.state;

	if ((s->flags & WRI_CF_WANT_CONNECT) && !(s->flags & WRI_CF_CONNECT_SENT) && st == WRI_M2_CONNECTING) {
		s->flags = (uint8_t)(s->flags | WRI_CF_CONNECT_SENT);
		out->kind = WR_ACT_CONNECT;
		out->conn = s->conn.id;
		out->addr = s->conn.dial;
		out->timeout_ms = s->conn.role == WRI_ENTITY_OSD ? c->x.cfg.osd_connect_timeout_ms : c->x.cfg.connect_timeout_ms; /* a dead OSD must not hold a handshake slot as long as a monitor may */
		s->connect_deadline_ms = WR_DEADLINE_NONE;
		if (out->timeout_ms != 0u)
			s->connect_deadline_ms = wri_mon_add_ms(c->x.now.mono_ms, (uint64_t)out->timeout_ms + WRI_CLIENT_CONNECT_GRACE_MS);
		return 1;
	}
	if (is_dead(st) && (s->flags & WRI_CF_CONNECT_SENT) && !(s->flags & WRI_CF_CLOSE_SENT)) {
		s->flags = (uint8_t)(s->flags | WRI_CF_CLOSE_SENT);
		out->kind = WR_ACT_CLOSE;
		out->conn = s->conn.id;
		return 1;
	}
	if (!is_live(st))
		return 0;
	if (wri_m2_txq_idle(&s->conn.tx)) {
		s->flags = (uint8_t)(s->flags & ~WRI_CF_TX_NOTIFIED); /* idle again: the next busy edge counts */
		return 0;
	}
	if (s->flags & WRI_CF_TX_NOTIFIED)
		return 0;
	s->flags = (uint8_t)(s->flags | WRI_CF_TX_NOTIFIED);
	out->kind = WR_ACT_TX_READY;
	out->conn = s->conn.id;
	return 1;
}

int wr_client_next_action(wr_client *c, wr_action *out)
{
	uint32_t k, n;

	if (out == NULL)
		return 0;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!engine_ok(c))
		return 0;
	wri_client_conn_housekeeping(c);
	n = c->n_slot;
	for (k = 0; k < n; k++) {
		uint32_t i = (c->act_cursor + k) % n;

		if (c->slot[i].in_use && slot_action(c, &c->slot[i], out)) {
			c->act_cursor = (i + 1u) % n;
			return 1;
		}
	}
	return 0;
}

/* ---- host reports ----------------------------------------------------------------------------------------------- */

void wr_conn_connected(wr_client *c, wr_conn_id id)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (s == NULL || s->conn.state != WRI_M2_CONNECTING || !(s->flags & WRI_CF_CONNECT_SENT))
		return;
	s->flags = (uint8_t)((s->flags & ~WRI_CF_WANT_CONNECT) | WRI_CF_REBASE);
	s->connect_deadline_ms = WR_DEADLINE_NONE;
	wri_m2_conn_on_connected(&c->x, &s->conn);
	pa_reclaim(c, s);
}

void wr_conn_closed(wr_client *c, wr_conn_id id, int host_errno)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (s == NULL)
		return;
	wri_m2_conn_on_closed(&c->x, &s->conn, host_errno); /* tells the monitor client (closed callback) if nobody was told yet */
	slot_release(c, s);
}

/* ---- receive and transmit ------------------------------------------------------------------------------------------ */

size_t wr_conn_rx_window(wr_client *c, wr_conn_id id, uint8_t **ptr)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (ptr != NULL)
		*ptr = NULL;
	if (s == NULL)
		return 0;
	return wri_m2_conn_rx_window(&s->conn, ptr);
}

void wr_conn_rx_commit(wr_client *c, wr_conn_id id, size_t n)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (s == NULL || n == 0u)
		return;
	wri_m2_conn_rx_commit(&s->conn, n);
}

size_t wr_conn_rx_push(wr_client *c, wr_conn_id id, const uint8_t *data, size_t n)
{
	wri_cslot *s = wri_client_slot_of(c, id);
	size_t taken = 0;

	if (s == NULL || data == NULL)
		return 0;
	while (taken < n) {
		uint8_t *w = NULL;
		size_t room = wri_m2_conn_rx_window(&s->conn, &w), k;

		if (room == 0u || w == NULL)
			break;
		k = n - taken < room ? n - taken : room;
		WR_MEMCPY(w, data + taken, k);
		wri_m2_conn_rx_commit(&s->conn, k);
		taken += k;
	}
	return taken;
}

size_t wr_conn_tx_peek(wr_client *c, wr_conn_id id, wr_iov *iov, size_t max_iov)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (s == NULL || iov == NULL || max_iov == 0u)
		return 0;
	return wri_m2_conn_tx_peek(&s->conn, iov, max_iov);
}

void wr_conn_tx_consume(wr_client *c, wr_conn_id id, size_t n)
{
	wri_cslot *s = wri_client_slot_of(c, id);

	if (s == NULL || n == 0u)
		return;
	wri_m2_conn_tx_consume(&s->conn, n);
	if (is_live(s->conn.state) && wri_m2_txq_idle(&s->conn.tx))
		s->flags = (uint8_t)(s->flags & ~WRI_CF_TX_NOTIFIED);
}
