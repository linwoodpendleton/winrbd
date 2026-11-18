/* SPDX-License-Identifier: MIT */
/*
 * osd_sess_world.h - the rig of the osd-sess tests that run the real connections: a cephx client that logged in to sim_mon with the product's own
 * machine (and so holds an OSD ticket), a handful of sim_osd servers over one store, a small engine in the shape of wri_client_conn.c (connection
 * slots, one handshake slot's worth of limit, the host closing a socket a run after the connection asked for it) that implements wri_osd_link, and an
 * in-test byte pump between each wri_m2_conn and its simulator. The table under test is the product's. Test code: libc allowed, static inline.
 */
#ifndef OSD_SESS_WORLD_H
#define OSD_SESS_WORLD_H

#include "auth_cx_srv.h"
#include "osd_sess_rig.h"
#include "sim_mon.h"
#include "sim_osd.h"
#include "wri_cx.h"
#include "wri_m2_conn.h"

#define W_OSD 4u
#define W_EC 10u
#define W_RING 65536u
#define W_CTL 16384u
#define W_TX 65536u
#define W_PA 16384u
#define W_SEG 4194304u
#define W_POOL 2

typedef struct econn {
	int in_use, connected, dead_target;
	wri_m2_conn c;
	uint8_t *ring, *ctl, *tx, *pa_rx, *pa_tx;
	wri_m2_preauth pa;
	wri_cx_hs hs;
	sim_osd_conn *sc;
	sim_mon_conn *mc;
	int osd_idx;
	uint16_t gen;
	unsigned n_host_closed;
} econn;

typedef struct world {
	cxt_env e;
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd[W_OSD];
	sim_osd_cfg ocfg[W_OSD];
	wr_addr addr[W_OSD];
	int osd_down[W_OSD];            /* connecting to this OSD is refused */
	unsigned n_osd;
	econn ec[W_EC];
	econn mon_ec;
	uint64_t gseq;
	unsigned max_hs;                /* handshakes that may run at once (the engine's pool) */
	int ticket_off;                 /* 1: the link says there is no OSD ticket */
	uint8_t *tab_raw;
	wri_arena arena;
	wri_osd_sess_tab t;
	orec r;
	size_t rx_chunk;                /* 0 = as much as the window takes; else at most this many bytes per commit */
	size_t rx_first;                /* the next delivery commits at most this many bytes, then the connection is stepped (0 = off) */
	int rx_budget_on;               /* 1: only rx_budget more bytes are delivered to the connections (the rest stays in the simulator) */
	size_t rx_budget;
	int tx_hold;                    /* 1: the host does not consume the transmit queues (they stay full: tx_idle is 0) */
	int tx_hold_only;               /* k > 0: the host does not consume the transmit queue of the connection to OSD k - 1 only */
	unsigned live_max;              /* most connections in use at once (OPENING / READY / waiting for the host's close) */
	unsigned mon_ready, mon_closed;
} world;

/* ---- the monitor's upper layer: login only ----------------------------------------------------------------------------- */

static inline wr_status wm_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *h, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	(void)ctx, (void)c, (void)h, (void)seglen, (void)sink;
	return WR_OK; /* everything the monitor volunteers is discarded */
}
static inline void wm_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *h, const uint32_t stored[3])
{
	(void)ctx, (void)c, (void)h, (void)stored;
}
static inline void wm_ready(void *ctx, wri_m2_conn *c)
{
	(void)c;
	((world *)ctx)->mon_ready++;
}
static inline void wm_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	(void)c, (void)err;
	((world *)ctx)->mon_closed++;
}
static const wri_m2_upper wm_up = {wm_plan, wm_message, wm_ready, wm_closed};

/* ---- one connection's byte pump -------------------------------------------------------------------------------------------- */

static inline int ec_peer_closed(const econn *ec)
{
	if (ec->sc != NULL)
		return sim_osd_closed(ec->sc);
	if (ec->mc != NULL)
		return sim_mon_closed(ec->mc);
	return 0;
}

static inline size_t ec_feed(econn *ec, const uint8_t *p, size_t n)
{
	if (ec->sc != NULL)
		return sim_osd_feed(ec->sc, p, n);
	if (ec->mc != NULL)
		return sim_mon_feed(ec->mc, p, n);
	return n;
}

static inline size_t ec_drain(econn *ec, uint8_t *out, size_t cap)
{
	if (ec->sc != NULL)
		return sim_osd_drain(ec->sc, out, cap);
	if (ec->mc != NULL)
		return sim_mon_drain(ec->mc, out, cap);
	return 0;
}

static inline void ec_release(econn *ec)
{
	if (ec->sc != NULL)
		sim_osd_conn_free(ec->sc);
	if (ec->mc != NULL)
		sim_mon_conn_free(ec->mc);
	ec->sc = NULL;
	ec->mc = NULL;
	wri_cx_hs_wipe(&ec->hs);
	ec->in_use = 0;
	ec->connected = 0;
}

static inline void ec_bind(econn *ec, uint16_t idx)
{
	wri_m2_conn_bind(&ec->c, idx, ec->ring, W_RING, ec->ctl, W_CTL, ec->tx, W_TX, W_SEG);
	ec->c.gen = ++ec->gen;
	wri_m2_preauth_init(&ec->pa, ec->pa_rx, ec->pa_tx, W_PA);
	ec->c.pa_slot = idx;
}

/* Move bytes both ways and step the connection once. 1 if anything happened. */
static inline int ec_pump(world *w, econn *ec)
{
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, moved = 0, room, k;
	uint8_t *win = NULL;
	int progress = 0;

	if (!ec->in_use)
		return 0;
	if (ec->c.state == WRI_M2_CONNECTING) {
		if (ec->dead_target) {
			wri_m2_conn_on_closed(&w->e.x, &ec->c, 111);
			ec_release(ec);
			return 1;
		}
		wri_m2_conn_on_connected(&w->e.x, &ec->c);
		ec->connected = 1;
		progress = 1;
	}
	n = (w->tx_hold && ec != &w->mon_ec) || (w->tx_hold_only > 0 && ec->osd_idx == w->tx_hold_only - 1) ? 0 : wri_m2_conn_tx_peek(&ec->c, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		(void)ec_feed(ec, iov[i].base, iov[i].len);
		moved += iov[i].len;
	}
	if (moved != 0) {
		wri_m2_conn_tx_consume(&ec->c, moved);
		progress = 1;
	}
	room = wri_m2_conn_rx_window(&ec->c, &win);
	if (room != 0 && win != NULL) {
		k = room;
		if (w->rx_chunk != 0 && k > w->rx_chunk)
			k = w->rx_chunk;
		if (w->rx_first != 0 && k > w->rx_first)
			k = w->rx_first;
		if (w->rx_budget_on && k > w->rx_budget)
			k = w->rx_budget;
		n = k != 0 ? ec_drain(ec, win, k) : 0;
		if (n != 0) {
			wri_m2_conn_rx_commit(&ec->c, n);
			progress = 1;
			w->rx_first = 0;
			if (w->rx_budget_on)
				w->rx_budget -= n;
		}
	}
	(void)wri_m2_conn_step(&w->e.x, &ec->c, NULL);
	if (ec_peer_closed(ec) && ec->c.state != WRI_M2_FAILED && ec->c.state != WRI_M2_CLOSING && ec->c.state != WRI_M2_FREE) {
		wri_m2_conn_on_closed(&w->e.x, &ec->c, 104); /* the peer's EOF / reset */
		ec_release(ec);
		return 1;
	}
	if (ec->c.state == WRI_M2_FAILED || ec->c.state == WRI_M2_CLOSING) { /* the host closes the socket and reports it */
		wri_m2_conn_on_closed(&w->e.x, &ec->c, 0);
		ec->n_host_closed++;
		ec_release(ec);
		progress = 1;
	}
	return progress;
}

static inline unsigned w_live(const world *w)
{
	unsigned i, n = 0;

	for (i = 0; i < W_EC; i++)
		n += w->ec[i].in_use ? 1u : 0u;
	return n;
}

/* Pump every connection until nothing moves (bounded). Returns the rounds. */
static inline int w_pump(world *w)
{
	int rounds = 0, progress;
	unsigned i;

	do {
		progress = 0;
		for (i = 0; i < W_EC; i++)
			progress |= ec_pump(w, &w->ec[i]);
		if (w_live(w) > w->live_max)
			w->live_max = w_live(w);
	} while (progress && ++rounds < 200000);
	return rounds;
}

/* ---- the engine side of wri_osd_link ------------------------------------------------------------------------------------- */

static inline unsigned w_handshakes(const world *w)
{
	unsigned i, n = 0;

	for (i = 0; i < W_EC; i++)
		n += (w->ec[i].in_use && w->ec[i].c.pa != NULL) ? 1u : 0u;
	return n;
}

static inline wr_status w_open(void *ctx, const wri_eaddr *addr, const wri_m2_upper *up, void *up_ctx, uint16_t *slot)
{
	world *w = (world *)ctx;
	unsigned i, k;
	wr_addr dial;
	econn *ec = NULL;

	if (w_handshakes(w) >= w->max_hs)
		return WR_E_BUSY;
	for (i = 0; i < W_EC; i++) {
		if (!w->ec[i].in_use) {
			ec = &w->ec[i];
			break;
		}
	}
	if (ec == NULL)
		return WR_E_BUSY;
	ec->in_use = 1;
	ec->dead_target = 1;
	ec->osd_idx = -1;
	wri_eaddr_to_wr(&dial, addr);
	for (k = 0; k < w->n_osd; k++) {
		if (w->addr[k].port == dial.port && w->addr[k].ip[3] == dial.ip[3]) {
			ec->osd_idx = (int)k;
			if (!w->osd_down[k]) {
				ec->sc = sim_osd_accept(w->osd[k]);
				ec->dead_target = ec->sc == NULL;
			}
		}
	}
	ec_bind(ec, (uint16_t)i);
	if (wri_cx_hs_init(&ec->hs, &w->e.c) != WR_OK)
		return WR_E_INVAL;
	wri_m2_conn_open(&ec->c, ((wr_conn_id)ec->c.gen << 16) | (wr_conn_id)(i + 1u), WRI_ENTITY_OSD, addr, &dial, wri_cx_hs_ops(), &ec->hs, up,
			 up_ctx, &ec->pa, 0x5eed0000u + (uint32_t)i, ++w->gseq);
	*slot = (uint16_t)i;
	if (w_live(w) > w->live_max)
		w->live_max = w_live(w);
	return WR_OK;
}

static inline void w_close(void *ctx, uint16_t slot, wr_status why)
{
	world *w = (world *)ctx;

	if (slot < W_EC && w->ec[slot].in_use)
		wri_m2_conn_close(&w->e.x, &w->ec[slot].c, why);
}

static inline wr_status w_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	world *w = (world *)ctx;

	if (slot >= W_EC || !w->ec[slot].in_use)
		return WR_E_STATE;
	return wri_m2_conn_send_message(&w->e.x, &w->ec[slot].c, m);
}

static inline int w_tx_idle(void *ctx, uint16_t slot)
{
	world *w = (world *)ctx;
	wr_iov iov[1];

	if (slot >= W_EC || !w->ec[slot].in_use)
		return 1;
	return wri_m2_conn_tx_peek(&w->ec[slot].c, iov, 1) == 0;
}

static inline int w_have_ticket(void *ctx)
{
	world *w = (world *)ctx;

	return !w->ticket_off && wri_cx_have(&w->e.c, WRI_CX_SERVICE_OSD, w->e.x.now.mono_ms);
}

static inline int w_handshake_free(void *ctx)
{
	world *w = (world *)ctx;

	return w_handshakes(w) < w->max_hs;
}

/* ---- the world -------------------------------------------------------------------------------------------------------------- */

static inline void w_login(world *w)
{
	econn *m = &w->mon_ec;
	wri_eaddr target;
	wr_addr dial;
	int rounds;

	memset(&dial, 0, sizeof(dial));
	dial.family = WR_AF_IPV4;
	dial.ip[0] = 10, dial.ip[1] = 77, dial.ip[2] = 0, dial.ip[3] = 10;
	dial.port = 3300;
	wri_eaddr_from_wr(&target, &dial, WRI_EADDR_TYPE_MSGR2);
	m->in_use = 1;
	m->mc = sim_mon_accept(w->mon);
	ec_bind(m, 15);
	wri_m2_conn_open(&m->c, 0x00010010u, WRI_ENTITY_MON, &target, &dial, wri_cx_ops(), &w->e.c, &wm_up, w, &m->pa, 0x5eedbeefu, ++w->gseq);
	for (rounds = 0; rounds < 100 && w->mon_ready == 0 && w->mon_closed == 0; rounds++)
		(void)ec_pump(w, m);
}

/* Fields of the OSD client in the context: osd_sessions, front cap, backoff slots; the rest as the harness profile. 0 = ok. */
static inline int w_open_world(world *w, unsigned n_osd, unsigned n_sess, unsigned front_cap, unsigned bo_slots, unsigned key_type)
{
	sim_mon_cfg mcfg;
	wr_key pk = cxt_key(key_type, 5);
	unsigned i;

	memset(w, 0, sizeof(*w));
	w->n_osd = n_osd;
	w->max_hs = 2;
	cxt_rng_free();
	sim_mon_cfg_default(&mcfg);
	mcfg.key = pk;
	memset(mcfg.user, 0, sizeof(mcfg.user));
	strcpy(mcfg.user, "winrbd");
	w->mon = sim_mon_new(&mcfg);
	w->store = sim_store_new();
	if (w->mon == NULL || w->store == NULL || cxt_env_init(&w->e, "client.winrbd", &pk, 0) != 0)
		return -1;
	w->e.x.cfg.osd_sessions = (uint16_t)n_sess;
	w->e.x.cfg.osd_front_cap = (uint16_t)front_cap;
	w->e.x.cfg.backoff_slots = (uint16_t)bo_slots;
	w->e.x.cfg.osd_connect_timeout_ms = 2000;
	w->e.x.cfg.osd_idle_ms = 0;
	w->e.x.cfg.handshake_timeout_ms = 10000;
	for (i = 0; i < W_EC + 1u; i++) {
		econn *ec = i < W_EC ? &w->ec[i] : &w->mon_ec;

		ec->ring = (uint8_t *)calloc(1, W_RING);
		ec->ctl = (uint8_t *)calloc(1, W_CTL);
		ec->tx = (uint8_t *)calloc(1, W_TX);
		ec->pa_rx = (uint8_t *)calloc(1, W_PA);
		ec->pa_tx = (uint8_t *)calloc(1, W_PA);
		if (ec->ring == NULL || ec->ctl == NULL || ec->tx == NULL || ec->pa_rx == NULL || ec->pa_tx == NULL)
			return -1;
	}
	w_login(w);
	if (w->mon_ready == 0 || !wri_cx_have(&w->e.c, WRI_CX_SERVICE_OSD, w->e.x.now.mono_ms))
		return -2;
	for (i = 0; i < n_osd; i++) {
		memset(&w->addr[i], 0, sizeof(w->addr[i]));
		w->addr[i].family = WR_AF_IPV4;
		w->addr[i].ip[0] = 10, w->addr[i].ip[1] = 77, w->addr[i].ip[2] = 0, w->addr[i].ip[3] = (uint8_t)(40u + i);
		w->addr[i].port = (uint16_t)(6810u + i);
		w->addr[i].nonce = 7000u + i;
		sim_osd_cfg_default(&w->ocfg[i]);
		w->ocfg[i].mon = w->mon;
		w->ocfg[i].store = w->store;
		w->ocfg[i].id = (int32_t)i;
		w->ocfg[i].seed = 11u + i;
		w->ocfg[i].m2.server_ip[0] = 10, w->ocfg[i].m2.server_ip[1] = 77, w->ocfg[i].m2.server_ip[2] = 0;
		w->ocfg[i].m2.server_ip[3] = w->addr[i].ip[3];
		w->ocfg[i].m2.server_port = w->addr[i].port;
		w->ocfg[i].m2.server_nonce = w->addr[i].nonce;
		w->ocfg[i].m2.check_target = 1; /* the client must name the OSD's address byte for byte */
	}
	return 0;
}

/* Start the OSDs and the table. 0 = ok. Call after adjusting w->ocfg[] and the context's config. */
static inline int w_start(world *w)
{
	size_t need = 0;
	unsigned i;
	wri_osd_link l;
	wri_osd_sess_up u;

	for (i = 0; i < w->n_osd; i++) {
		w->osd[i] = sim_osd_new(&w->ocfg[i]);
		if (w->osd[i] == NULL)
			return -1;
	}
	if (wri_osd_sess_mem(&w->e.x.cfg, &need) != WR_OK)
		return -2;
	w->tab_raw = (uint8_t *)calloc(1, need + 128u);
	if (w->tab_raw == NULL)
		return -3;
	wri_arena_init(&w->arena, (uint8_t *)(((uintptr_t)w->tab_raw + 63u) & ~(uintptr_t)63u), need + 64u);
	memset(&l, 0, sizeof(l));
	l.ctx = w;
	l.open = w_open;
	l.close = w_close;
	l.send = w_send;
	l.tx_idle = w_tx_idle;
	l.features = NULL; /* the connection passed to ready() carries the word */
	l.have_ticket = w_have_ticket;
	l.handshake_free = w_handshake_free;
	u = orec_up(&w->r);
	if (wri_osd_sess_init(&w->t, &w->e.x, &w->arena, &l, &u) != WR_OK)
		return -4;
	return 0;
}

static inline void w_free(world *w)
{
	unsigned i;

	for (i = 0; i < W_EC; i++)
		ec_release(&w->ec[i]);
	ec_release(&w->mon_ec);
	for (i = 0; i < W_EC + 1u; i++) {
		econn *ec = i < W_EC ? &w->ec[i] : &w->mon_ec;

		free(ec->ring), free(ec->ctl), free(ec->tx), free(ec->pa_rx), free(ec->pa_tx);
		ec->ring = ec->ctl = ec->tx = ec->pa_rx = ec->pa_tx = NULL;
	}
	for (i = 0; i < W_OSD; i++)
		if (w->osd[i] != NULL)
			sim_osd_free(w->osd[i]);
	free(w->tab_raw);
	w->tab_raw = NULL;
	if (w->mon != NULL)
		sim_mon_free(w->mon);
	if (w->store != NULL)
		sim_store_free(w->store);
	cxt_env_free(&w->e);
}

/* Acquire a session for OSD k and pump until it is READY or gone. Returns the session index (READY) or WRI_NIL. */
static inline uint32_t w_get(world *w, unsigned k)
{
	uint32_t s = WRI_NIL;
	int rounds;

	if (wri_osd_sess_acquire(&w->t, (int32_t)k, &w->addr[k], &s) != WR_OK)
		return WRI_NIL;
	for (rounds = 0; rounds < 50 && !wri_osd_sess_ready(&w->t, s) && w->t.s[s].state == WRI_OS_OPENING; rounds++)
		(void)w_pump(w);
	return wri_osd_sess_ready(&w->t, s) ? s : WRI_NIL;
}

/* ---- requests ------------------------------------------------------------------------------------------------------------ */

/* Send one single-operation MOSDOp on READY session s: READ (len bytes at off) or WRITE (data). Returns the send status. */
static inline wr_status w_op(world *w, uint32_t s, uint64_t tid, const char *oid, uint16_t code, uint64_t off, uint64_t len, const uint8_t *data,
			     int32_t retry)
{
	wri_mosdop_hdr h;
	wri_osd_opd op;
	uint8_t front[512];
	wri_wr wr;
	wri_m2_msg_out m;
	const wri_osd_sess *p = wri_osd_sess_at(&w->t, s);
	wr_status st;

	memset(&h, 0, sizeof(h));
	h.version = p->msg_version;
	h.pool = W_POOL;
	h.pg_seed = 3;
	h.hash = 0x12345678u;
	h.map_epoch = 5;
	h.flags = code == WRI_OSD_OP_WRITE ? WRI_OSDF_BASE_WRITE : WRI_OSDF_BASE_READ;
	h.mtime_sec = code == WRI_OSD_OP_WRITE ? 1700000000u : 0u;
	h.oid = (const uint8_t *)oid;
	h.oid_len = (uint32_t)strlen(oid);
	h.snapid = WRI_SNAP_NOSNAP;
	h.retry_attempt = retry;
	h.features = p->features;
	memset(&op, 0, sizeof(op));
	op.code = code;
	op.off = off;
	op.len = len;
	op.in_len = code == WRI_OSD_OP_WRITE ? (uint32_t)len : 0u;
	wri_wr_init(&wr, front, sizeof(front));
	st = wri_mosdop_encode(&wr, &h, &op, 1);
	if (st != WR_OK)
		return st;
	memset(&m, 0, sizeof(m));
	m.type = (uint16_t)WRI_MSG_OSD_OP;
	m.priority = (uint16_t)WRI_MSG_PRIO_CLIENT;
	m.version = p->msg_version;
	m.compat_version = (uint16_t)WRI_MOSDOP_COMPAT;
	m.tid = tid;
	m.front = front;
	m.front_len = (uint32_t)wri_wr_len(&wr);
	m.data = data;
	m.data_len = op.in_len;
	st = wri_osd_sess_send(&w->t, s, &m);
	if (st == WR_OK)
		(void)w_pump(w); /* the bytes are consumed at once: nothing of the caller's is referenced afterwards */
	return st;
}

/* The server-side connection of session s (the sim_osd_conn the pump talks to). */
static inline sim_osd_conn *w_srv(world *w, uint32_t s)
{
	const wri_osd_sess *p = wri_osd_sess_at(&w->t, s);

	return p != NULL && p->conn_slot < W_EC ? w->ec[p->conn_slot].sc : NULL;
}

/* Bytes the simulator has queued for session s's connection and the client has not read yet. */
static inline size_t w_pending(world *w, uint32_t s)
{
	sim_osd_conn *c = w_srv(w, s);

	return c != NULL ? sim_m2_pending(sim_osd_conn_m2(c)) : 0u;
}

/* The same message queued on the simulator's connection, not pumped. */
static inline wr_status w_queue(world *w, uint32_t s, uint16_t type, uint64_t tid, uint16_t ver, const uint8_t *front, uint32_t flen,
				const uint8_t *middle, uint32_t mlen, const uint8_t *data, uint32_t dlen)
{
	sim_osd_conn *c = w_srv(w, s);

	if (c == NULL)
		return WR_E_STATE;
	return sim_m2_send_message(sim_osd_conn_m2(c), type, tid, ver, front, flen, middle, mlen, data, dlen);
}

/* A message from the OSD of session s with the given segments, queued on the simulator's connection and pumped through (rx_chunk / rx_first apply). */
static inline wr_status w_inject(world *w, uint32_t s, uint16_t type, uint64_t tid, uint16_t ver, const uint8_t *front, uint32_t flen,
				 const uint8_t *middle, uint32_t mlen, const uint8_t *data, uint32_t dlen)
{
	sim_osd_conn *c = w_srv(w, s);
	wr_status st;

	if (c == NULL)
		return WR_E_STATE;
	st = sim_m2_send_message(sim_osd_conn_m2(c), type, tid, ver, front, flen, middle, mlen, data, dlen);
	if (st == WR_OK)
		(void)w_pump(w);
	return st;
}

#endif /* OSD_SESS_WORLD_H */
