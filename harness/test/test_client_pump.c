/* SPDX-License-Identifier: MIT */
/*
 * test_client_pump.c - the client engine against the simulated monitor, through the PUBLIC pump API only
 * (wr_client_run / next_action / wr_conn_* / events / map messages). A small in-test host plays the part
 * of the Linux loop: it performs the actions, connects every CONNECT to a fresh sim_mon connection, moves
 * bytes both ways and advances a virtual clock. Its knobs (partial transmit, rx_push, tiny windows, a
 * connect that never completes, a connection cut mid-handshake ...) are what the tests turn.
 *
 * Checked: a full session to WR_CS_ACTIVE for both key types and for the iPXE / kernel profiles; the
 * semantics of the derived actions (CONNECT / CLOSE / TX_READY once, stale ids ignored, close then
 * reconnect); window sizes and backpressure; rx_push; partial transmit; raw map messages (peek, release,
 * ordering against EV_MAPMSG); a connection reset mid-handshake and a monitor restart (hunting and
 * recovery); refusals (wrong key); a host that never reports the connect; a failing random source;
 * round-robin of actions, handshake pool accounting, the event ring; destroy in the middle of a session.
 */
#include "sim_mon_tc.h"
#include "wri_client.h"

#define MAXH 8u
#define MAXEV 2048u
#define MAXIDS 64u
#define MAXMAPS 64u
#define TICK_MS 50u

typedef struct region {
	uint8_t *raw, *base;
	size_t size;
} region;

typedef struct hconn {
	int used, connected, closing, failing;
	wr_conn_id id;
	sim_mon_conn *sc;
	uint64_t fed;
	uint8_t stash[2048];
	size_t stash_len;
} hconn;

typedef struct idlog {
	wr_conn_id id;
	unsigned n_connect, n_close, n_txready;
	uint64_t t_connect, t_close;
} idlog;

typedef struct mapseen {
	wr_mapmsg_kind kind;
	uint32_t epoch;
	size_t len;
} mapseen;

typedef struct opts {
	unsigned key_type;
	int wrong_key;
	int profile; /* 0 harness (small caps), 1 ipxe, 2 kernel */
	void (*tweak_cfg)(wr_config *);
	void (*tweak_sim)(sim_mon_cfg *);
} opts;

typedef struct host {
	wr_config cfg;
	wr_host_ops ops;
	wr_cluster_spec spec;
	region arena, bulk;
	wr_client *c;
	sim_mon *sim;
	sim_mon_cfg scfg;
	uint64_t rng;
	int rng_fail;
	hconn hc[MAXH];
	uint64_t now;

	/* knobs */
	uint32_t budget;
	size_t tx_chunk, rx_chunk;
	int push_mode, hold_maps, connect_hang, connect_fail, garbage;
	int ignore_close; /* the host never answers a CLOSE with wr_conn_closed (a stuck socket layer) */
	int abuse; /* a hostile host: lying sizes, bogus ids, a clock that steps back (test_hostile_host) */
	uint64_t cut_after;
	int cut_done;

	/* observations */
	wr_event ev[MAXEV];
	uint64_t ev_at[MAXEV];
	unsigned n_ev;
	idlog ids[MAXIDS];
	unsigned n_ids;
	unsigned n_connect, n_close, zero_windows, push_partial, n_more;
	size_t max_window_pre_up;
	uint32_t hw_pa_rx, hw_pa_tx, hw_tx_used; /* high-water marks of the buffers the profiles size */
	int seen_up;
	mapseen maps[MAXMAPS];
	unsigned n_maps;
	wr_run_result last_run;
} host;

/* ---- the engine under test ------------------------------------------------------------------------------ */

static wr_status h_random(void *ctx, uint8_t *out, size_t n)
{
	host *h = (host *)ctx;
	size_t i;

	if (h->rng_fail)
		return WR_E_HOST_RANDOM;
	for (i = 0; i < n; i++) {
		h->rng ^= h->rng >> 12;
		h->rng ^= h->rng << 25;
		h->rng ^= h->rng >> 27;
		out[i] = (uint8_t)((h->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

static uint64_t h_random_u(host *h)
{
	uint8_t b[8] = {0}; /* h_random leaves it alone when the test makes the random source fail */
	uint64_t v = 0;
	unsigned i;

	(void)h_random(h, b, sizeof(b));
	for (i = 0; i < 8u; i++)
		v = (v << 8) | b[i];
	return v;
}

static void region_new(region *r, size_t size)
{
	uintptr_t p;

	r->raw = (uint8_t *)calloc(1, size + 128u);
	if (r->raw == NULL)
		abort();
	p = ((uintptr_t)r->raw + 63u) & ~(uintptr_t)63u;
	r->base = (uint8_t *)p;
	r->size = size;
}

static host *host_new(const opts *o)
{
	host *h = (host *)calloc(1, sizeof(*h));
	wr_mem_req req;

	if (h == NULL)
		abort();
	switch (o->profile) {
	case 1:
		wr_config_profile_ipxe(&h->cfg);
		break;
	case 2:
		wr_config_profile_kernel(&h->cfg);
		break;
	default:
		wr_config_profile_harness(&h->cfg);
		h->cfg.mon_msg_cap = 256u * 1024u;
		break;
	}
	if (o->tweak_cfg != NULL)
		o->tweak_cfg(&h->cfg);
	h->rng = 0xfeedfacecafebeefull;
	h->now = 10000;
	h->ops.size = (uint32_t)sizeof(h->ops);
	h->ops.ctx = h;
	h->ops.random = h_random;

	mt_cfg(&h->scfg, o->key_type);
	if (o->tweak_sim != NULL)
		o->tweak_sim(&h->scfg);
	h->sim = sim_mon_new(&h->scfg);
	if (h->sim == NULL)
		abort();
	strcpy(h->spec.user, "client.winrbd");
	if (o->wrong_key)
		mt_key(&h->spec.key, o->key_type, 99);
	else
		h->spec.key = h->scfg.key;
	h->spec.n_mons = 1;
	h->spec.mons[0].family = WR_AF_IPV4;
	h->spec.mons[0].ip[0] = 10, h->spec.mons[0].ip[1] = 77, h->spec.mons[0].ip[3] = 10;
	h->spec.mons[0].port = 3300;

	WRT_CHECK_STATUS(WR_OK, wr_client_mem_required(&h->cfg, &req));
	region_new(&h->arena, req.arena);
	region_new(&h->bulk, req.bulk);
	WRT_CHECK_STATUS(WR_OK, wr_client_create(&h->cfg, &h->ops, &h->spec, (wr_mem_region){h->arena.base, h->arena.size},
						 (wr_mem_region){h->bulk.base, h->bulk.size}, &h->c));
	if (h->c == NULL)
		abort();
	return h;
}

static void host_free(host *h)
{
	unsigned i;

	if (h->c != NULL)
		wr_client_destroy(h->c);
	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].sc != NULL)
			sim_mon_conn_free(h->hc[i].sc);
	sim_mon_free(h->sim);
	free(h->arena.raw);
	free(h->bulk.raw);
	free(h);
}

/* ---- the host ------------------------------------------------------------------------------------------------ */

static idlog *id_get(host *h, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < h->n_ids; i++)
		if (h->ids[i].id == id)
			return &h->ids[i];
	if (h->n_ids == MAXIDS)
		abort();
	memset(&h->ids[h->n_ids], 0, sizeof(h->ids[0]));
	h->ids[h->n_ids].id = id;
	return &h->ids[h->n_ids++];
}

static hconn *hc_find(host *h, wr_conn_id id)
{
	unsigned i;

	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].id == id)
			return &h->hc[i];
	return NULL;
}

static unsigned count_ev(const host *h, wr_ev_kind k)
{
	unsigned i, n = 0;

	for (i = 0; i < h->n_ev; i++)
		n += h->ev[i].kind == k;
	return n;
}

static const wr_event *last_ev(const host *h, wr_ev_kind k)
{
	unsigned i;

	for (i = h->n_ev; i > 0; i--)
		if (h->ev[i - 1u].kind == k)
			return &h->ev[i - 1u];
	return NULL;
}

static void host_events(host *h)
{
	wr_event e;

	while (wr_client_next_event(h->c, &e)) {
		if (h->n_ev < MAXEV) {
			h->ev[h->n_ev] = e;
			h->ev_at[h->n_ev++] = h->now;
		}
		if (e.kind == WR_EV_MON_SESSION_UP)
			h->seen_up = 1;
	}
	if (h->hold_maps)
		return;
	for (;;) {
		wr_mapmsg m;

		if (!wr_client_mapmsg_peek(h->c, &m))
			break;
		if (h->n_maps < MAXMAPS) {
			h->maps[h->n_maps].kind = m.kind;
			h->maps[h->n_maps].epoch = m.newest_epoch;
			h->maps[h->n_maps].len = m.front_len;
			h->n_maps++;
		}
		wr_client_mapmsg_release(h->c);
	}
}

static unsigned host_actions(host *h)
{
	wr_action a;
	unsigned n = 0;

	while (wr_client_next_action(h->c, &a)) {
		idlog *l = id_get(h, a.conn);
		hconn *hc;
		unsigned i;

		n++;
		switch (a.kind) {
		case WR_ACT_CONNECT:
			h->n_connect++;
			l->n_connect++;
			l->t_connect = h->now;
			WRT_CHECK_U64(a.timeout_ms, h->cfg.connect_timeout_ms);
			WRT_CHECK(a.addr.family == WR_AF_IPV4 && a.addr.port == 3300 && a.addr.ip[0] == 10 && a.addr.ip[3] == 10);
			WRT_CHECK(hc_find(h, a.conn) == NULL);
			for (i = 0; i < MAXH && h->hc[i].used; i++) {
			}
			if (i == MAXH)
				abort();
			memset(&h->hc[i], 0, sizeof(h->hc[i]));
			h->hc[i].used = 1;
			h->hc[i].id = a.conn;
			h->hc[i].failing = h->connect_fail;
			break;
		case WR_ACT_CLOSE:
			h->n_close++;
			l->n_close++;
			l->t_close = h->now;
			hc = hc_find(h, a.conn);
			WRT_CHECK(hc != NULL);
			if (hc != NULL)
				hc->closing = 1;
			break;
		case WR_ACT_TX_READY:
			l->n_txready++;
			hc = hc_find(h, a.conn);
			WRT_CHECK(hc != NULL && hc->connected);
			break;
		default:
			WRT_CHECK(0);
			break;
		}
	}
	return n;
}

static void hc_end(host *h, hconn *hc, int err)
{
	if (hc->sc != NULL)
		sim_mon_conn_free(hc->sc);
	hc->sc = NULL;
	wr_conn_closed(h->c, hc->id, err);
	hc->used = 0;
}

/* Sample how full the sized buffers of a connection are (white box, to tune the profiles). */
static void hc_sample(host *h, hconn *hc)
{
	wri_cslot *s = wri_client_slot_of(h->c, hc->id);

	if (s == NULL)
		return;
	if (s->conn.pa != NULL) {
		if (s->conn.pa->rx_len > h->hw_pa_rx)
			h->hw_pa_rx = s->conn.pa->rx_len;
		if (s->conn.pa->tx_len > h->hw_pa_tx)
			h->hw_pa_tx = s->conn.pa->tx_len;
	}
	if (s->conn.tx.used > h->hw_tx_used)
		h->hw_tx_used = s->conn.tx.used;
}

static int hc_tx(host *h, hconn *hc)
{
	wr_iov iov[8];
	size_t n = wr_conn_tx_peek(h->c, hc->id, iov, 8), i, sent = 0, room = h->tx_chunk ? h->tx_chunk : (size_t)-1;

	for (i = 0; i < n && room > 0; i++) {
		size_t take = iov[i].len < room ? iov[i].len : room;

		(void)sim_mon_feed(hc->sc, iov[i].base, take);
		sent += take;
		room -= take;
	}
	if (sent == 0)
		return 0;
	wr_conn_tx_consume(h->c, hc->id, sent);
	hc->fed += sent;
	return 1;
}

static int hc_rx(host *h, hconn *hc)
{
	uint8_t *w = NULL;
	size_t room, n;

	if (h->push_mode) {
		int progress = 0;

		if (hc->stash_len == 0) {
			size_t cap = h->rx_chunk && h->rx_chunk < sizeof(hc->stash) ? h->rx_chunk : sizeof(hc->stash);

			hc->stash_len = sim_mon_drain(hc->sc, hc->stash, cap);
		}
		if (hc->stash_len != 0) {
			size_t taken = wr_conn_rx_push(h->c, hc->id, hc->stash, hc->stash_len);

			if (taken < hc->stash_len)
				h->push_partial++;
			memmove(hc->stash, hc->stash + taken, hc->stash_len - taken);
			hc->stash_len -= taken;
			progress = taken != 0;
		}
		return progress;
	}
	room = wr_conn_rx_window(h->c, hc->id, &w);
	if (room == 0) {
		h->zero_windows++;
		return 0;
	}
	WRT_CHECK(w != NULL);
	if (h->garbage) { /* not a monitor at all: random bytes */
		uint8_t r[8] = {0}; /* untouched when the random source is made to fail */

		n = room < 61u ? room : 61u;
		for (room = 0; room < n; room++) {
			(void)h_random(h, r, 1);
			w[room] = r[0];
		}
		wr_conn_rx_commit(h->c, hc->id, n);
		return 1;
	}
	if (!h->seen_up && room > h->max_window_pre_up)
		h->max_window_pre_up = room;
	if (h->rx_chunk && room > h->rx_chunk)
		room = h->rx_chunk;
	n = sim_mon_drain(hc->sc, w, room);
	if (n == 0)
		return 0;
	wr_conn_rx_commit(h->c, hc->id, n);
	return 1;
}

static int host_io(host *h)
{
	unsigned i;
	int progress = 0;

	for (i = 0; i < MAXH; i++) {
		hconn *hc = &h->hc[i];

		if (!hc->used)
			continue;
		if (hc->closing) {
			if (h->ignore_close)
				continue;
			hc_end(h, hc, 0);
			progress = 1;
			continue;
		}
		if (!hc->connected) {
			if (h->connect_hang)
				continue;
			if (hc->failing) {
				hc_end(h, hc, 111);
				progress = 1;
				continue;
			}
			hc->sc = sim_mon_accept(h->sim);
			WRT_CHECK(hc->sc != NULL);
			if (hc->sc == NULL)
				abort();
			wr_conn_connected(h->c, hc->id);
			hc->connected = 1;
			progress = 1;
		}
		hc_sample(h, hc);
		if (hc_tx(h, hc))
			progress = 1;
		hc_sample(h, hc);
		if (h->cut_after != 0 && !h->cut_done && hc->fed >= h->cut_after) { /* the network drops it mid-handshake */
			h->cut_done = 1;
			hc_end(h, hc, 104);
			progress = 1;
			continue;
		}
		if (hc_rx(h, hc))
			progress = 1;
		if (hc->sc != NULL && sim_mon_closed(hc->sc) && hc->stash_len == 0) {
			hc_end(h, hc, 0);
			progress = 1;
		}
	}
	return progress;
}

/* One round of hostile calls. Everything here is a contract violation by the host (or an id that is none of
 * the engine's); the engine may fail the connection it concerns, but must stay memory safe and keep its books. */
static void abuse_round(host *h)
{
	uint64_t r = h_random_u(h);
	unsigned i;
	wr_iov iov[8];
	uint8_t junk[40], *w = NULL;
	size_t room;

	for (i = 0; i < sizeof(junk); i++)
		junk[i] = (uint8_t)(r >> (i % 8u));
	for (i = 0; i < MAXH; i++) {
		hconn *hc = &h->hc[i];
		wr_conn_id id;

		if (!hc->used)
			continue;
		id = hc->id;
		switch ((h_random_u(h) >> 8) % 12u) {
		case 0:
			wr_conn_rx_commit(h->c, id, (size_t)-1); /* far more than the window */
			break;
		case 1:
			room = wr_conn_rx_window(h->c, id, &w);
			wr_conn_rx_commit(h->c, id, room + 1u + (size_t)(r % 7u)); /* one past the window */
			break;
		case 2:
			wr_conn_tx_consume(h->c, id, (size_t)-1); /* more than was ever queued */
			break;
		case 3:
			(void)wr_conn_rx_push(h->c, id, junk, sizeof(junk)); /* bytes nobody sent */
			break;
		case 4:
			wr_conn_connected(h->c, id); /* a second (or a premature) report */
			break;
		case 5:
			(void)wr_conn_tx_peek(h->c, id, iov, 1u + (size_t)(r % 8u));
			wr_conn_tx_consume(h->c, id, (size_t)(r % 5u));
			break;
		case 6:
			(void)wr_conn_rx_push(h->c, id, NULL, 9);
			(void)wr_conn_rx_window(h->c, id, NULL);
			break;
		default:
			break;
		}
	}
	/* ids that belong to nobody (other generation, other slot, beyond the table, NONE): all ignored */
	wr_conn_closed(h->c, (wr_conn_id)(r >> 32) | 0x80000000u, 5);
	wr_conn_connected(h->c, (wr_conn_id)(r >> 16));
	wr_conn_rx_commit(h->c, (wr_conn_id)(r >> 8), 99);
	wr_conn_tx_consume(h->c, (wr_conn_id)(r >> 24), 99);
	(void)wr_conn_rx_window(h->c, (wr_conn_id)r, &w);
	/* a clock that steps back for one run: held at the last value, nothing breaks */
	if (h->now > 5000u && (r & 3u) == 0u) {
		wr_clock clk;

		clk.mono_ms = h->now - 4000u;
		clk.wall_ms = 0;
		(void)wr_client_run(h->c, &clk, (uint32_t)(1u + (r >> 40) % 300u));
	}
}

static unsigned long g_rounds; /* all pump rounds of this process: a runaway engine must fail the test, not hang it */

/* Run to quiescence at the current virtual time. */
static void pump(host *h)
{
	unsigned guard;

	for (guard = 0; guard < 200000u; guard++) {
		if (++g_rounds > 4000000ul) {
			fprintf(stderr, "test_client_pump: pump rounds exceed the budget, the engine does not settle\n");
			exit(1);
		}
		wr_clock clk;
		unsigned acts;
		int io;

		if (h->abuse)
			abuse_round(h);
		clk.mono_ms = h->now;
		clk.wall_ms = 1700000000000ull + h->now;
		h->last_run = wr_client_run(h->c, &clk, h->budget);
		if (h->last_run.more_work)
			h->n_more++;
		host_events(h);
		acts = host_actions(h);
		io = host_io(h);
		host_events(h);
		if (acts == 0 && !io && !h->last_run.more_work)
			return;
	}
	WRT_CHECK(0 && "pump did not settle");
}

static void run_ms(host *h, uint64_t ms)
{
	uint64_t end = h->now + ms;

	pump(h);
	while (h->now < end) {
		h->now += TICK_MS;
		pump(h);
	}
}

static int reach_active(host *h, uint64_t max_ms)
{
	uint64_t end = h->now + max_ms;

	pump(h);
	while (h->now < end && wr_client_get_state(h->c) != WR_CS_ACTIVE) {
		h->now += TICK_MS;
		pump(h);
	}
	return wr_client_get_state(h->c) == WR_CS_ACTIVE;
}

static sim_mon_conn *newest_conn(const sim_mon *m)
{
	sim_mon_conn *best = NULL;
	unsigned i;

	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL && (best == NULL || m->conns[i]->index > best->index))
			best = m->conns[i];
	return best;
}

/* ---- tests -------------------------------------------------------------------------------------------------------- */

static const opts k1 = {WR_KEY_TYPE_AES, 0, 0, NULL, NULL};
static const opts k2 = {WR_KEY_TYPE_AES256K, 0, 0, NULL, NULL};

/* The whole way to ACTIVE, and what the host can see of it. */
static void check_session(const opts *o, const char *label)
{
	host *h = host_new(o);
	wr_stats st;
	unsigned i, n_monmap = 0, n_osdmap = 0, k = 0;
	uint32_t osd_epoch = 0;
	sim_mon_conn *sc;

	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_CREATED);
	WRT_CHECK(h->n_connect == 0);
	WRT_CHECK(reach_active(h, 20000));
	if (wr_client_get_state(h->c) != WR_CS_ACTIVE) {
		fprintf(stderr, "  (%s) not active, events %u, last status %d\n", label, h->n_ev, wr_client_last_error(h->c)->status);
		host_free(h);
		return;
	}
	run_ms(h, 2000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_UP), 1);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(count_ev(h, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	WRT_CHECK_U64(h->n_connect, 1);
	WRT_CHECK_U64(h->n_close, 0);
	WRT_CHECK_U64(h->sim->n_logins, 1);
	WRT_CHECK_STATUS(WR_OK, wr_client_last_error(h->c)->status);
	WRT_CHECK(h->ids[0].n_txready >= 1u);

	/* the pools: one connection, the handshake slot is back as soon as the signature was verified */
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 1);
	WRT_CHECK_U64(st.conns_hiwater, 1);
	WRT_CHECK_U64(st.handshakes_in_use, 0);
	WRT_CHECK_U64(st.handshakes_hiwater, 1);
	WRT_CHECK(st.arena_used != 0 && st.bulk_used != 0);
	printf("session %-9s arena %u B, bulk %u B, conns hiwater %u, handshakes hiwater %u, mapmsg hiwater %u; buffers used: "
	       "transcript rx %u / tx %u, encode %u\n",
	       label, st.arena_used, st.bulk_used, st.conns_hiwater, st.handshakes_hiwater, st.mapmsg_hiwater, h->hw_pa_rx, h->hw_pa_tx,
	       h->hw_tx_used);

	/* the monitor saw a proper subscription */
	sc = newest_conn(h->sim);
	WRT_CHECK(sc != NULL);
	if (sc != NULL) {
		WRT_CHECK(sc->n_getmap >= 1u && sc->n_subscribe >= 1u);
		for (i = 0; i < sc->n_last_sub; i++)
			if (strcmp(sc->last_sub[i].name, "osdmap") == 0) {
				WRT_CHECK(sc->last_sub[i].start == 0 && sc->last_sub[i].flags == 0); /* from scratch, continuous */
				k = 99;
			}
		WRT_CHECK_U64(k, 99);
		k = 0;
	}

	/* raw map messages came in order: EV_MAPMSG epochs equal the delivered messages' epochs, monmap and osdmap both there */
	for (i = 0; i < h->n_maps; i++) {
		n_monmap += h->maps[i].kind == WR_MAPMSG_MONMAP;
		if (h->maps[i].kind == WR_MAPMSG_OSDMAP && h->maps[i].epoch > osd_epoch)
			osd_epoch = h->maps[i].epoch;
		WRT_CHECK(h->maps[i].len != 0);
	}
	n_osdmap = h->n_maps - n_monmap;
	WRT_CHECK(n_monmap >= 1u && n_osdmap >= 1u);
	WRT_CHECK_U64(osd_epoch, 42);
	for (i = 0; i < h->n_ev; i++) {
		if (h->ev[i].kind != WR_EV_MAPMSG)
			continue;
		WRT_CHECK(k < h->n_maps && h->ev[i].epoch == h->maps[k].epoch);
		k++;
	}
	WRT_CHECK_U64(k, h->n_maps);
	/* the session event comes first: the subscription is out before any map can arrive */
	for (i = 0; i < h->n_ev && h->ev[i].kind != WR_EV_MON_SESSION_UP; i++)
		WRT_CHECK(h->ev[i].kind != WR_EV_MAPMSG);
	host_free(h);
}

static void test_sessions(void)
{
	static const opts ip1 = {WR_KEY_TYPE_AES, 0, 1, NULL, NULL};
	static const opts ip2 = {WR_KEY_TYPE_AES256K, 0, 1, NULL, NULL};
	static const opts kn2 = {WR_KEY_TYPE_AES256K, 0, 2, NULL, NULL};

	check_session(&k1, "k1 harn");
	check_session(&k2, "k2 harn");
	check_session(&ip1, "k1 ipxe");
	check_session(&ip2, "k2 ipxe");
	check_session(&kn2, "k2 kern");
}

/* CONNECT / TX_READY are handed out once; calling again without a change in between gives nothing. */
static void test_action_once(void)
{
	host *h = host_new(&k2);
	wr_clock clk;
	wr_action a;
	wr_iov iov[8];
	sim_mon_conn *sc;
	wr_conn_id id;
	size_t n, total = 0, i, room;
	uint8_t *w;

	clk.mono_ms = h->now;
	clk.wall_ms = 0;
	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_CONNECT);
	id = a.conn;
	WRT_CHECK(id != WR_CONN_NONE);
	WRT_CHECK_U64(a.timeout_ms, h->cfg.connect_timeout_ms);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0 && a.kind == WR_ACT_NONE);
	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0); /* still no second CONNECT for the same connection */
	/* before the host reports the connect there is nothing to read or write */
	WRT_CHECK_U64(wr_conn_rx_window(h->c, id, &w), 0);
	WRT_CHECK_U64(wr_conn_tx_peek(h->c, id, iov, 8), 0);

	wr_conn_connected(h->c, id);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_TX_READY && a.conn == id); /* the banner */
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0);
	n = wr_conn_tx_peek(h->c, id, iov, 8);
	WRT_CHECK(n >= 1u);
	for (i = 0; i < n; i++)
		total += iov[i].len;
	WRT_CHECK_U64(total, 26); /* "ceph v2\n" + the banner payload (msgr2.md 2.2) */
	wr_conn_tx_consume(h->c, id, 10); /* partial: still busy, no new edge */
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0);
	n = wr_conn_tx_peek(h->c, id, iov, 8);
	WRT_CHECK(n >= 1u && iov[0].len == 16);
	sc = sim_mon_accept(h->sim);
	WRT_CHECK(sc != NULL);
	wr_conn_tx_consume(h->c, id, 16);
	WRT_CHECK_U64(wr_conn_tx_peek(h->c, id, iov, 8), 0); /* idle again; no action scan in this window on purpose */
	/* the monitor's banner arrives: the engine answers with HELLO, a NEW busy edge, a new TX_READY */
	{
		uint8_t buf[4096];
		size_t got = sim_mon_drain(sc, buf, sizeof(buf));

		WRT_CHECK(got >= 26u);
		room = wr_conn_rx_window(h->c, id, &w);
		WRT_CHECK(room >= got);
		memcpy(w, buf, got);
		wr_conn_rx_commit(h->c, id, got);
	}
	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_TX_READY && a.conn == id);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0);
	sim_mon_conn_free(sc);
	host_free(h);
}

/* The host reports the connect long after the last run (a main loop that slept in between): the handshake
 * clock starts at the next run, not at the stale time of the previous one, and run reports that deadline. */
static void test_late_connect(void)
{
	host *h = host_new(&k2);
	wr_clock clk = {10000, 0};
	wr_action a;
	wr_run_result r;
	wr_stats st;

	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_CONNECT);
	wr_conn_connected(h->c, a.conn); /* the TCP connect finished at 14000, but no run happened in between */
	clk.mono_ms = 14000;
	r = wr_client_run(h->c, &clk, 0);
	WRT_CHECK_U64(r.next_deadline_ms, 14000u + h->cfg.handshake_timeout_ms); /* 22000, not 18000 */
	clk.mono_ms = 19000; /* past a handshake clock that had started at 10000 */
	(void)wr_client_run(h->c, &clk, 0);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 1);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	WRT_CHECK_STATUS(WR_OK, wr_client_last_error(h->c)->status);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_TX_READY); /* the banner, never taken */
	clk.mono_ms = 22000;
	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK_STATUS(WR_E_M2_HANDSHAKE_TIMEOUT, wr_client_last_error(h->c)->status);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_CLOSE);
	host_free(h);
}

/* An id of a connection that is gone is ignored by every call, also after its slot was reused. */
static void test_stale_ids(void)
{
	host *h = host_new(&k2);
	wr_conn_id old;
	uint8_t *w = (uint8_t *)1;
	wr_iov iov[8];
	wr_stats st;
	uint8_t junk[16] = {0};

	h->connect_fail = 1; /* the first connect fails: the slot is released and the next attempt reuses it */
	run_ms(h, 1000);
	WRT_CHECK(h->n_connect >= 1u);
	old = h->ids[0].id;
	WRT_CHECK_U64(h->ids[0].n_connect, 1);
	WRT_CHECK_U64(h->ids[0].n_close, 0); /* the host closed it itself: no CLOSE action for a failed connect */
	h->connect_fail = 0;
	WRT_CHECK(reach_active(h, 20000));
	WRT_CHECK(h->n_ids >= 2u);
	WRT_CHECK(h->ids[h->n_ids - 1u].id != old);
	WRT_CHECK_U64(h->ids[h->n_ids - 1u].id & 0xffffu, old & 0xffffu); /* the same slot, another generation */
	WRT_CHECK(h->ids[h->n_ids - 1u].id >> 16 != old >> 16);

	wr_conn_connected(h->c, old);
	WRT_CHECK_U64(wr_conn_rx_window(h->c, old, &w), 0);
	WRT_CHECK(w == NULL);
	WRT_CHECK_U64(wr_conn_rx_push(h->c, old, junk, sizeof(junk)), 0);
	wr_conn_rx_commit(h->c, old, 5);
	WRT_CHECK_U64(wr_conn_tx_peek(h->c, old, iov, 8), 0);
	wr_conn_tx_consume(h->c, old, 5);
	wr_conn_closed(h->c, old, 1); /* must not take the new connection down */
	wr_conn_closed(h->c, 0, 1);
	wr_conn_closed(h->c, 0xffffffffu, 1);
	run_ms(h, 3000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 1);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 0);
	host_free(h);
}

static void tweak_tiny_rx(wr_config *c)
{
	c->rx_buf_bytes = 64;
}

/* A 64-byte staging ring still carries a session; windows before the session is up never exceed it. */
static void test_tiny_window(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, 0, tweak_tiny_rx, NULL};
	host *h = host_new(&o);

	WRT_CHECK(reach_active(h, 30000));
	WRT_CHECK(h->max_window_pre_up != 0 && h->max_window_pre_up <= 64u);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	host_free(h);
}

static void tweak_one_slot(wr_config *c)
{
	c->mapmsg_queue = 1;
	c->rx_buf_bytes = 256;
}

/* The consumer holds the only map slot: the connection stalls (zero window), nothing is lost, release resumes it. */
static void test_backpressure(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, 0, tweak_one_slot, NULL};
	host *h = host_new(&o);
	wr_mapmsg m, m2;
	unsigned i;
	int got_osd = 0;
	uint32_t held_epoch;
	const uint8_t *front;

	h->hold_maps = 1;
	run_ms(h, 6000);
	WRT_CHECK(h->zero_windows != 0); /* the ring filled up behind the held map */
	WRT_CHECK(wr_client_mapmsg_peek(h->c, &m) == 1);
	WRT_CHECK(m.kind == WR_MAPMSG_MONMAP);
	held_epoch = m.newest_epoch;
	front = m.front;
	WRT_CHECK(m.front != NULL && m.front_len != 0);
	WRT_CHECK(wr_client_mapmsg_peek(h->c, &m2) == 1 && m2.front == front && m2.newest_epoch == held_epoch); /* idempotent */
	WRT_CHECK(count_ev(h, WR_EV_MAPMSG) == 1u);
	WRT_CHECK(wr_client_get_state(h->c) != WR_CS_FAILED);
	WRT_CHECK(count_ev(h, WR_EV_MON_SESSION_DOWN) == 0u);

	wr_client_mapmsg_release(h->c);
	h->hold_maps = 0;
	run_ms(h, 5000);
	for (i = 0; i < h->n_maps; i++)
		got_osd |= h->maps[i].kind == WR_MAPMSG_OSDMAP && h->maps[i].epoch == 42u;
	WRT_CHECK(got_osd);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(h->n_connect, 1);
	host_free(h);
}

static void tweak_small_rx(wr_config *c)
{
	c->rx_buf_bytes = 128;
}

/* rx_push: copies through the window, takes less than offered when the ring is short, the session works. */
static void test_rx_push(void)
{
	opts o = {WR_KEY_TYPE_AES, 0, 0, tweak_small_rx, NULL};
	host *h = host_new(&o);

	h->push_mode = 1;
	WRT_CHECK(reach_active(h, 30000));
	WRT_CHECK(h->push_partial != 0); /* 2 KiB offered at a time against a 128-byte ring */
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	WRT_CHECK(h->n_maps >= 2u);
	host_free(h);

	h = host_new(&k2);
	h->push_mode = 1;
	h->rx_chunk = 7; /* tiny pushes */
	WRT_CHECK(reach_active(h, 60000));
	host_free(h);
}

/* Partial acceptance on the transmit side: 1 byte, then 7 bytes per round. */
static void test_partial_tx(void)
{
	static const size_t chunks[] = {1, 7};
	unsigned i;

	for (i = 0; i < 2; i++) {
		host *h = host_new(&k2);

		h->tx_chunk = chunks[i];
		WRT_CHECK(reach_active(h, 30000));
		WRT_CHECK_U64(h->n_connect, 1);
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		host_free(h);
	}
	/* and more than offered is no harm */
	{
		host *h = host_new(&k1);
		wr_clock clk = {h->now, 0};
		wr_action a;
		wr_iov iov[8];

		(void)wr_client_run(h->c, &clk, 0);
		WRT_CHECK(wr_client_next_action(h->c, &a) == 1);
		wr_conn_connected(h->c, a.conn);
		wr_conn_tx_consume(h->c, a.conn, 1000000); /* more than is queued: clamped */
		WRT_CHECK_U64(wr_conn_tx_peek(h->c, a.conn, iov, 8), 0);
		host_free(h);
	}
}

/* A small work budget: the session completes through more_work, which is reported. */
static void test_budget(void)
{
	host *h = host_new(&k2);

	h->budget = 40;
	WRT_CHECK(reach_active(h, 60000));
	WRT_CHECK(h->n_more != 0);
	host_free(h);
}

/* The network drops the first connection in the middle of the handshake: hunting, then recovery. */
static void test_reset_mid_handshake(void)
{
	host *h = host_new(&k2);
	const wr_errinfo *e;

	h->cut_after = 100; /* 26 banner + HELLO ... the handshake is not over */
	pump(h);
	run_ms(h, 100);
	WRT_CHECK(h->cut_done);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	e = wr_client_last_error(h->c);
	WRT_CHECK(e != NULL);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, e->status); /* the first failure since the last success */
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 0); /* it was never up */
	WRT_CHECK(reach_active(h, 30000));
	WRT_CHECK(h->n_connect >= 2u);
	WRT_CHECK_U64(h->n_close, 0); /* the host ended it itself */
	WRT_CHECK_STATUS(WR_OK, wr_client_last_error(h->c)->status); /* cleared by the success */
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_UP), 1);
	host_free(h);
}

/* The monitor restarts under a live session: DOWN, hunting, a new session that resubscribes from held + 1. */
static void test_monitor_restart(void)
{
	host *h = host_new(&k1);
	sim_mon_conn *sc;
	uint32_t n_up;

	WRT_CHECK(reach_active(h, 20000));
	run_ms(h, 1000);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_UP), 1);
	sim_mon_restart(h->sim);
	run_ms(h, 100);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	WRT_CHECK(last_ev(h, WR_EV_MON_SESSION_DOWN)->err.status != WR_OK);
	WRT_CHECK(wr_client_last_error(h->c)->status != WR_OK);
	WRT_CHECK(reach_active(h, 30000));
	n_up = count_ev(h, WR_EV_MON_SESSION_UP);
	WRT_CHECK_U64(n_up, 2);
	sc = newest_conn(h->sim);
	WRT_CHECK(sc != NULL);
	if (sc != NULL) {
		unsigned j, found = 0;

		for (j = 0; j < sc->n_last_sub; j++)
			if (strcmp(sc->last_sub[j].name, "osdmap") == 0) {
				WRT_CHECK(sc->last_sub[j].start == 43u && sc->last_sub[j].flags == 0); /* held epoch 42 + 1, continuous */
				found = 1;
			}
		WRT_CHECK(found);
	}
	WRT_CHECK_U64(h->sim->n_logins, 2);
	WRT_CHECK_U64(h->sim->n_reclaims, 1); /* the second session reclaimed its global id */
	WRT_CHECK_STATUS(WR_OK, wr_client_last_error(h->c)->status);
	host_free(h);
}

/* A wrong key: the monitor refuses, the engine reports it, closes the connection once and retries slowly. */
static void test_auth_failure(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 1, 0, NULL, NULL};
	host *h = host_new(&o);
	unsigned i;

	run_ms(h, 60000);
	WRT_CHECK(count_ev(h, WR_EV_AUTH_FAILED) >= 1u);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK(wr_client_last_error(h->c)->status != WR_OK);
	WRT_CHECK(h->n_connect >= 2u && h->n_connect <= 12u); /* back-off, no tight loop */
	for (i = 0; i < h->n_ids; i++) {
		WRT_CHECK(h->ids[i].n_connect == 1u);
		WRT_CHECK(h->ids[i].n_close <= 1u); /* CLOSE at most once */
	}
	WRT_CHECK(h->n_close >= 1u);
	host_free(h);
}

/* A host that never completes the connect: the engine gives up after the action's timeout (+ grace) and hunts on. */
static void test_connect_timeout(void)
{
	host *h = host_new(&k2);
	uint64_t t0;

	h->connect_hang = 1;
	pump(h);
	t0 = h->ids[0].t_connect;
	run_ms(h, 5900);
	WRT_CHECK_U64(h->ids[0].n_close, 0);
	run_ms(h, 1000);
	WRT_CHECK_U64(h->ids[0].n_close, 1);
	WRT_CHECK(h->ids[0].t_close >= t0 + 6000u && h->ids[0].t_close <= t0 + 6200u);
	WRT_CHECK(wr_client_last_error(h->c)->status == WR_E_TIMEOUT);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	run_ms(h, 30000);
	WRT_CHECK(count_ev(h, WR_EV_CLUSTER_UNREACHABLE) >= 1u); /* one monitor failed = a full round */
	WRT_CHECK(h->n_connect >= 2u);
	host_free(h);
}

/* A connect that fails outright (refused): UNREACHABLE after a round, retries with back-off. */
static void test_connect_refused(void)
{
	host *h = host_new(&k1);

	h->connect_fail = 1;
	run_ms(h, 40000);
	WRT_CHECK(count_ev(h, WR_EV_CLUSTER_UNREACHABLE) >= 1u);
	WRT_CHECK(h->n_connect >= 3u && h->n_connect <= 12u);
	WRT_CHECK_STATUS(WR_E_NET_CONNECT, wr_client_last_error(h->c)->status);
	h->connect_fail = 0;
	WRT_CHECK(reach_active(h, 60000));
	host_free(h);
}

/* Without randomness the engine stops for good: FATAL, FAILED, a CLOSE for what is open, no new connection. */
static void test_fatal_random(void)
{
	host *h = host_new(&k2);
	unsigned n_before;

	h->rng_fail = 1;
	run_ms(h, 8000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_FAILED);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 1);
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, last_ev(h, WR_EV_FATAL)->err.status);
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wr_client_last_error(h->c)->status);
	n_before = h->n_connect;
	run_ms(h, 60000);
	WRT_CHECK_U64(h->n_connect, n_before);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_FAILED);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 1);
	host_free(h);
}

/* Keepalive over a minute and what run reports as the next deadline. */
static void test_steady_state(void)
{
	host *h = host_new(&k2);
	wr_clock clk;
	wr_run_result r;

	WRT_CHECK(reach_active(h, 20000));
	run_ms(h, 70000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(h->n_connect, 1);
	clk.mono_ms = h->now;
	clk.wall_ms = 0;
	r = wr_client_run(h->c, &clk, 0);
	WRT_CHECK(r.next_deadline_ms != WR_DEADLINE_NONE);
	WRT_CHECK(r.next_deadline_ms <= h->now + h->cfg.keepalive_ms + 100u); /* the next keepalive */
	WRT_CHECK(r.more_work == 0);
	/* a clock that steps back is held at the last value: nothing explodes */
	clk.mono_ms = h->now - 5000u;
	r = wr_client_run(h->c, &clk, 0);
	WRT_CHECK(r.next_deadline_ms != WR_DEADLINE_NONE);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
	host_free(h);
}

/* Destroy in the middle of a session and of a handshake: the arena is wiped, nothing dangles (ASan). */
static void test_destroy_mid_session(void)
{
	host *h = host_new(&k2);
	size_t i;
	wr_stats st;

	WRT_CHECK(reach_active(h, 20000));
	wr_client_get_stats(h->c, &st);
	wr_client_destroy(h->c);
	for (i = 0; i < st.arena_used; i++)
		if (h->arena.base[i] != 0) {
			WRT_CHECK(0 && "arena not wiped");
			break;
		}
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_FAILED); /* the magic is gone: a dead handle reads as dead */
	WRT_CHECK(wr_client_next_action(h->c, &(wr_action){0}) == 0);
	wr_client_destroy(h->c); /* twice is harmless */
	h->c = NULL;
	host_free(h);

	h = host_new(&k1);
	h->cut_after = 1000000000u; /* never */
	{
		wr_clock clk = {h->now, 0};
		wr_action a;

		(void)wr_client_run(h->c, &clk, 0);
		WRT_CHECK(wr_client_next_action(h->c, &a) == 1);
		wr_conn_connected(h->c, a.conn); /* a connection in the middle of the handshake */
	}
	wr_client_destroy(h->c);
	h->c = NULL;
	host_free(h);
}

static void tweak_two_handshakes(wr_config *c)
{
	c->max_handshakes = 2;
}

/* White box: connections opened through the monitor link are announced round-robin, once each; the handshake pool
 * limits the connections in handshake and gets its slot back when the connection ends. */
static void test_action_order_and_pools(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, 0, tweak_two_handshakes, NULL};
	host *h = host_new(&o);
	wri_eaddr ea;
	uint16_t s1 = 0, s2 = 0, s3 = 0;
	wr_action a1, a2, a3;
	wr_stats st;
	wri_mon_link *l = &h->c->link;

	wri_eaddr_from_wr(&ea, &h->spec.mons[0], WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &s1));
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &s2));
	WRT_CHECK_STATUS(WR_E_BUSY, l->open(l->ctx, &ea, &s3)); /* connection slots are free, handshake slots are not */
	WRT_CHECK(s1 != s2);
	WRT_CHECK(wr_client_next_action(h->c, &a1) == 1 && a1.kind == WR_ACT_CONNECT);
	WRT_CHECK(wr_client_next_action(h->c, &a2) == 1 && a2.kind == WR_ACT_CONNECT);
	WRT_CHECK(a1.conn != a2.conn);
	WRT_CHECK(wr_client_next_action(h->c, &a3) == 0);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 2);
	WRT_CHECK_U64(st.handshakes_in_use, 2);
	/* one connect fails: its handshake slot is free again, and the slot comes back with a new generation */
	wr_conn_closed(h->c, a1.conn, 111);
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &s3));
	WRT_CHECK(wr_client_next_action(h->c, &a3) == 1 && a3.kind == WR_ACT_CONNECT);
	WRT_CHECK(a3.conn != a1.conn && a3.conn != a2.conn);
	wr_conn_closed(h->c, a2.conn, 111);
	wr_conn_closed(h->c, a3.conn, 111);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 0);
	WRT_CHECK_U64(st.handshakes_in_use, 0);
	WRT_CHECK_U64(st.conns_hiwater, 2);
	WRT_CHECK_U64(st.handshakes_hiwater, 2);
	host_free(h);
}

/* White box: the monitor client withdraws a connection before the host ever saw its CONNECT: nothing is announced
 * (there is no socket), and the connection slot and the handshake slot are free again at once. */
static void test_silent_release(void)
{
	host *h = host_new(&k2);
	wri_mon_link *l = &h->c->link;
	wri_eaddr ea;
	uint16_t s1 = 0;
	wr_action a;
	wr_stats st;

	wri_eaddr_from_wr(&ea, &h->spec.mons[0], WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &s1));
	l->close(l->ctx, s1, WR_E_CANCELLED);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 0 && a.kind == WR_ACT_NONE); /* neither CONNECT nor CLOSE */
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 0);
	WRT_CHECK_U64(st.handshakes_in_use, 0);
	/* the slot is reusable, with a new generation */
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &s1));
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_CONNECT);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK_U64(st.conns_in_use, 1);
	host_free(h);
}

/* Fairness under a work budget: two connections with data to parse take turns, the second one is not starved. */
static void io_conn(host *h, wr_conn_id id, sim_mon_conn *sc)
{
	wr_iov iov[8];
	uint8_t *w = NULL;
	size_t k, i, room;

	k = wr_conn_tx_peek(h->c, id, iov, 8);
	for (i = 0; i < k; i++) {
		(void)sim_mon_feed(sc, iov[i].base, iov[i].len);
		wr_conn_tx_consume(h->c, id, iov[i].len);
	}
	room = wr_conn_rx_window(h->c, id, &w);
	if (room != 0 && w != NULL)
		wr_conn_rx_commit(h->c, id, sim_mon_drain(sc, w, room < 40 ? room : 40));
}

static unsigned at_auth(host *h, wr_conn_id id)
{
	wri_cslot *s = wri_client_slot_of(h->c, id);

	return s != NULL && s->conn.state >= WRI_M2_AUTH;
}

static void test_step_fairness(void)
{
	host *h = host_new(&k2);
	wri_mon_link *l = &h->c->link;
	wri_eaddr ea;
	uint16_t sa = 0, sb = 0;
	wr_clock clk = {h->now, 0};
	wr_action a;
	wr_conn_id ida = 0, idb = 0;
	sim_mon_conn *sca, *scb;
	unsigned i, na = 0, nb = 0;

	wri_eaddr_from_wr(&ea, &h->spec.mons[0], WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &sa));
	WRT_CHECK_STATUS(WR_OK, l->open(l->ctx, &ea, &sb));
	while (wr_client_next_action(h->c, &a)) {
		if (a.kind == WR_ACT_CONNECT && ida == 0)
			ida = a.conn;
		else if (a.kind == WR_ACT_CONNECT && idb == 0)
			idb = a.conn;
	}
	WRT_CHECK(ida != 0 && idb != 0);
	sca = sim_mon_accept(h->sim);
	scb = sim_mon_accept(h->sim);
	wr_conn_connected(h->c, ida);
	wr_conn_connected(h->c, idb);
	/* Each connection needs the server's banner and HELLO parsed at 8 bytes of work per run. With a rotating start
	 * both get there at about the same run; with a fixed start the second would wait for the first. */
	for (i = 1; i <= 600u && (na == 0 || nb == 0); i++) {
		(void)wr_client_run(h->c, &clk, 8);
		io_conn(h, ida, sca);
		io_conn(h, idb, scb);
		if (na == 0 && at_auth(h, ida))
			na = i;
		if (nb == 0 && at_auth(h, idb))
			nb = i;
	}
	printf("fairness: connection A reached AUTH after %u runs, B after %u\n", na, nb);
	WRT_CHECK(na != 0 && nb != 0);
	WRT_CHECK((na > nb ? na - nb : nb - na) <= 4u);
	sim_mon_conn_free(sca);
	sim_mon_conn_free(scb);
	host_free(h);
}

/* White box: the event ring drops the oldest informational event on overflow and never a fatal one. */
static void test_event_ring(void)
{
	host *h = host_new(&k2);
	wr_event e;
	unsigned i, n = 0, fatal = 0;
	wr_errinfo er;
	uint32_t last_epoch = 0;

	memset(&er, 0, sizeof(er));
	er.status = WR_E_TIMEOUT;
	for (i = 1; i <= 3; i++)
		wri_client_push_event(h->c, WR_EV_MAPMSG, i, NULL);
	wri_client_push_event(h->c, WR_EV_FATAL, 0, &er);
	for (i = 4; i <= 40; i++)
		wri_client_push_event(h->c, WR_EV_MAPMSG, i, NULL);
	WRT_CHECK_U64(h->c->ev_len, WRI_EVENT_RING);
	WRT_CHECK(h->c->ev_dropped >= 30u);
	while (wr_client_next_event(h->c, &e)) {
		n++;
		fatal += e.kind == WR_EV_FATAL;
		if (e.kind == WR_EV_MAPMSG) {
			WRT_CHECK(e.epoch > last_epoch); /* order kept */
			last_epoch = e.epoch;
		}
	}
	WRT_CHECK_U64(n, WRI_EVENT_RING);
	WRT_CHECK_U64(fatal, 1);
	WRT_CHECK_U64(last_epoch, 40); /* the newest survive */
	WRT_CHECK(wr_client_next_event(h->c, &e) == 0 && e.kind == WR_EV_NONE);
	host_free(h);
}

/* A "monitor" that sends random bytes: every connection fails, the engine hunts with back-off and leaks nothing. */
static void test_garbage_monitor(void)
{
	host *h = host_new(&k2);
	wr_stats st;
	unsigned i;

	h->garbage = 1;
	run_ms(h, 60000);
	WRT_CHECK(wr_client_get_state(h->c) == WR_CS_HUNTING);
	WRT_CHECK(h->n_connect >= 3u && h->n_connect <= 12u);
	WRT_CHECK_U64(count_ev(h, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
	for (i = 0; i < h->n_ids; i++)
		WRT_CHECK(h->ids[i].n_connect == 1u && h->ids[i].n_close <= 1u);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK(st.conns_in_use <= 1u && st.handshakes_in_use <= 1u && st.handshakes_hiwater <= 1u);
	WRT_CHECK(wr_client_last_error(h->c)->status != WR_OK);
	host_free(h);
}

/* Random schedules: partial transmit and receive, push or window, a connection cut at a random byte. The
 * engine must always end up ACTIVE, with consistent pools and no fatal event (ASan / UBSan watch the rest). */
static void test_random_schedules(void)
{
	unsigned seed;

	for (seed = 1; seed <= 40u; seed++) {
		host *h = host_new(seed % 2u ? &k1 : &k2);
		wr_stats st;

		h->rng ^= (uint64_t)seed * 0x9e3779b97f4a7c15ull;
		h->tx_chunk = seed % 3u == 0 ? 0 : 1u + (size_t)(h_random_u(h) % 300u);
		h->rx_chunk = seed % 4u == 0 ? 0 : 1u + (size_t)(h_random_u(h) % 500u);
		h->push_mode = (int)(seed % 5u == 1u);
		h->budget = seed % 7u == 0 ? 64u + (uint32_t)(h_random_u(h) % 2000u) : 0;
		h->cut_after = seed % 2u ? 0 : 30u + h_random_u(h) % 400u;
		WRT_CHECK(reach_active(h, 120000));
		run_ms(h, 3000);
		WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		wr_client_get_stats(h->c, &st);
		WRT_CHECK(st.conns_in_use == 1u && st.handshakes_in_use == 0u);
		host_free(h);
	}
}

/* A hostile host for a while (see abuse_round), then a well-behaved one: the engine must not crash (ASan / UBSan),
 * must not leak connection or handshake slots, and must reach and keep a healthy monitor session again. */
static void test_hostile_host(void)
{
	unsigned seed, hostile_conns = 0;

	for (seed = 1; seed <= 24u; seed++) {
		host *h = host_new(seed % 2u ? &k1 : &k2);
		wr_stats st;
		unsigned i;

		h->rng ^= (uint64_t)seed * 0x9e3779b97f4a7c15ull;
		h->push_mode = (int)(seed % 3u == 1u);
		h->rx_chunk = seed % 4u == 0 ? 0 : 1u + (size_t)(h_random_u(h) % 400u);
		h->budget = seed % 5u == 0 ? 100u + (uint32_t)(h_random_u(h) % 3000u) : 0;
		h->abuse = 1;
		run_ms(h, 12000);
		wr_client_get_stats(h->c, &st);
		WRT_CHECK(st.conns_in_use <= h->cfg.max_conns && st.handshakes_in_use <= h->cfg.max_handshakes);
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		hostile_conns += h->n_connect;
		h->abuse = 0;
		WRT_CHECK(reach_active(h, 180000));
		run_ms(h, 3000);
		WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
		wr_client_get_stats(h->c, &st);
		WRT_CHECK(st.conns_in_use == 1u && st.handshakes_in_use == 0u);
		for (i = 0; i < MAXH; i++) /* no connection the host still owes a close for, but the engine forgot */
			WRT_CHECK(!h->hc[i].used || wri_client_slot_of(h->c, h->hc[i].id) != NULL);
		host_free(h);
	}
	printf("hostile host: %u connections opened over 24 seeds\n", hostile_conns);
	WRT_CHECK(hostile_conns > 24u * 3u); /* the lies really did break connections: the engine kept reconnecting */
}

/* A host that never completes a close: the slots stay taken, the engine must neither crash, nor spin, nor invent a free
 * slot. It waits (hunting) and recovers as soon as the host finally reports the closes. */
static void tw_three_slots(wr_config *c) { c->max_conns = 3, c->max_handshakes = 2; }

static void test_close_never_acknowledged(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, 0, tw_three_slots, NULL};
	host *h = host_new(&o);
	wr_stats st;
	unsigned i, spins = 0;
	uint64_t t_end;

	h->garbage = 1;
	h->ignore_close = 1;
	run_ms(h, 120000);
	wr_client_get_stats(h->c, &st);
	WRT_CHECK(st.conns_in_use <= h->cfg.max_conns);
	WRT_CHECK(h->n_connect <= h->cfg.max_conns); /* never more connections than slots */
	/* while every slot is stuck the engine asks for a wake-up in the future, not for "now" */
	t_end = h->now + 5000u;
	while (h->now < t_end) {
		wr_clock clk = {h->now, 0};
		wr_run_result r = wr_client_run(h->c, &clk, 0);

		if (r.next_deadline_ms <= h->now && wr_client_get_state(h->c) != WR_CS_ACTIVE)
			spins++;
		h->now += TICK_MS;
	}
	WRT_CHECK(spins <= 2u);
	/* the host catches up: closes are reported, the engine recovers with a good monitor */
	h->garbage = 0;
	h->ignore_close = 0;
	for (i = 0; i < MAXH; i++)
		if (h->hc[i].used && h->hc[i].sc != NULL) {
			sim_mon_conn_free(h->hc[i].sc);
			h->hc[i].sc = NULL;
		}
	WRT_CHECK(reach_active(h, 180000));
	host_free(h);
}

/* A clock close to the end of the 64-bit range: the engine's own deadline arithmetic saturates instead of wrapping into
 * the past (a wrapped connect deadline would close every connection at once). */
static void test_clock_near_wrap(void)
{
	host *h = host_new(&k2);
	wr_clock clk = {0xfffffffffffff000ull, 0};
	wr_action a;
	wri_cslot *s;
	wr_run_result r;

	(void)wr_client_run(h->c, &clk, 0);
	WRT_CHECK(wr_client_next_action(h->c, &a) == 1 && a.kind == WR_ACT_CONNECT);
	s = wri_client_slot_of(h->c, a.conn);
	WRT_CHECK(s != NULL);
	if (s != NULL)
		WRT_CHECK(s->connect_deadline_ms >= clk.mono_ms);
	r = wr_client_run(h->c, &clk, 0);
	WRT_CHECK(r.next_deadline_ms >= clk.mono_ms);
	wr_conn_connected(h->c, a.conn);
	clk.mono_ms += 10;
	(void)wr_client_run(h->c, &clk, 0);
	if (s != NULL && s->conn.state >= WRI_M2_BANNER && s->conn.state <= WRI_M2_IDENT && s->conn.deadline_ms != WR_DEADLINE_NONE)
		WRT_CHECK(s->conn.deadline_ms >= clk.mono_ms);
	host_free(h);
}

/* ---- extreme configurations ------------------------------------------------------------------------------ */

static void tw_rx(wr_config *c) { c->rx_buf_bytes = 64; }
static void tw_edge(wr_config *c)
{
	c->ticket_cap = 1024;
	c->tx_buf_bytes = 2u * (c->ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME;
}
static void tws_biggest_tickets(sim_mon_cfg *s)
{
	unsigned i;

	for (i = 0; i < SIM_MON_TSLOTS; i++)
		s->tkt[i].blob_len = 1011; /* + 13 bytes of CephXTicketBlob framing = ticket_cap: the largest the engine keeps */
}
static void tw_ctl(wr_config *c) { c->ctl_buf_bytes = 64; }
/* the smallest encode buffer create accepts for the ticket_cap: the reclaim after a restart must still fit */
static uint32_t tx_min_for(uint32_t ticket_cap)
{
	return 2u * (ticket_cap + WRI_CLIENT_AUTH_SLACK) + WRI_CLIENT_TX_FRAME;
}
static void tw_tx(wr_config *c)
{
	c->ticket_cap = 256; /* the 151-byte tickets of the simulator fit */
	c->tx_buf_bytes = tx_min_for(c->ticket_cap);
}
static void tw_pre(wr_config *c) { c->preauth_cap = 256; }
static void tw_ticket(wr_config *c) { c->ticket_cap = 64; }
static void tw_msg(wr_config *c) { c->mon_msg_cap = 64; }
static void tw_minall(wr_config *c)
{
	c->rx_buf_bytes = 64, c->ctl_buf_bytes = 64, c->preauth_cap = 256, c->ticket_cap = 64;
	c->tx_buf_bytes = tx_min_for(c->ticket_cap);
	c->mon_msg_cap = 64, c->max_conns = 2, c->max_handshakes = 1, c->mapmsg_queue = 1;
}
static void tw_wide(wr_config *c)
{
	c->max_conns = 1024, c->max_handshakes = 1024, c->rx_buf_bytes = 256, c->ctl_buf_bytes = 2048, c->tx_buf_bytes = tx_min_for(c->ticket_cap);
	c->preauth_cap = 2048;
}
static void tw_notimers(wr_config *c)
{
	c->connect_timeout_ms = c->handshake_timeout_ms = c->keepalive_ms = c->keepalive_timeout_ms = 0;
	c->hunt_backoff_min_ms = c->hunt_backoff_max_ms = 0;
}
static void tw_fast(wr_config *c)
{
	c->connect_timeout_ms = c->handshake_timeout_ms = c->keepalive_ms = c->keepalive_timeout_ms = 1;
	c->hunt_backoff_min_ms = 1, c->hunt_backoff_max_ms = 2;
}
static void tw_huge_timers(wr_config *c)
{
	c->connect_timeout_ms = c->handshake_timeout_ms = c->keepalive_ms = c->keepalive_timeout_ms = 0xffffffffu;
	c->hunt_backoff_min_ms = c->hunt_backoff_max_ms = 0xffffffffu;
}

/* Legal but extreme configurations (every minimum, every timer at 0 / 1 ms / 2^32-1, the widest tables): whatever the
 * numbers allow, the engine either reaches a monitor session or fails the way a refused connection fails (error recorded,
 * hunting), never crashes, never raises FATAL, never busy-loops (the pump's round budget watches that). */
static void test_extreme_configs(void)
{
	static const struct {
		void (*tweak)(wr_config *);
		int profile;
		int must_work;   /* the first login must succeed */
		int must_again;  /* and so must the second one, after a monitor restart */
		const char *name;
	} cases[] = {
		{tw_rx, 0, 1, 1, "rx 64"},           {tw_ctl, 0, 0, 0, "ctl 64"},       {tw_tx, 0, 1, 1, "tx minimum"},
		{tw_pre, 0, 0, 0, "preauth 256"},    {tw_ticket, 0, 0, 0, "ticket 64"}, {tw_msg, 0, 0, 0, "mon_msg 64"},
		{tw_minall, 1, 0, 0, "all minima"},  {tw_wide, 1, 1, 1, "1024 conns"},  {tw_notimers, 0, 1, 1, "no timers"},
		{tw_fast, 0, 0, 1, "1 ms timers"},   {tw_huge_timers, 0, 1, 0, "huge timers"}, /* back-off of 49 days: no second try */
	};
	unsigned i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		opts o = {WR_KEY_TYPE_AES256K, 0, cases[i].profile, cases[i].tweak, NULL};
		host *h = host_new(&o);
		wr_stats st;
		wr_client_state state;

		run_ms(h, 30000);
		state = wr_client_get_state(h->c);
		if (cases[i].must_work)
			WRT_CHECK(state == WR_CS_ACTIVE);
		if (state == WR_CS_ACTIVE) { /* a configuration that logs in must also log in again: the reclaim carries the held ticket */
			sim_mon_restart(h->sim);
			run_ms(h, 60000);
			state = wr_client_get_state(h->c);
			if (state != WR_CS_ACTIVE)
				fprintf(stderr, "  (%s) no second session, first error %d, latest %d (%s)\n", cases[i].name,
					(int)wr_client_last_error(h->c)->status, (int)h->c->mon.err.status,
					h->c->mon.err.what != NULL ? h->c->mon.err.what : "-");
			WRT_CHECK(state == WR_CS_ACTIVE || cases[i].must_again == 0);
			WRT_CHECK_U64(h->sim->n_reclaims, state == WR_CS_ACTIVE ? 1 : h->sim->n_reclaims);
		}
		if (state != WR_CS_ACTIVE) {
			WRT_CHECK(state == WR_CS_HUNTING);
			WRT_CHECK(wr_client_last_error(h->c)->status != WR_OK);
		}
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		wr_client_get_stats(h->c, &st);
		WRT_CHECK(st.conns_in_use <= h->cfg.max_conns && st.handshakes_in_use <= h->cfg.max_handshakes);
		WRT_CHECK(st.conns_in_use <= 2u); /* one session, one that is still closing at most */
		if (state != WR_CS_ACTIVE || cases[i].must_work == 0)
			printf("extreme config %-12s: state %d, last error %d, %u connection attempts\n", cases[i].name, (int)state,
			       (int)wr_client_last_error(h->c)->status, h->n_connect);
		host_free(h);
	}
	/* the largest ticket the engine keeps in the smallest encode buffer create allows: the reclaim after a restart
	 * carries it back in AUTH_REQUEST_MORE and must still fit */
	{
		opts o = {WR_KEY_TYPE_AES256K, 0, 0, tw_edge, tws_biggest_tickets};
		host *h = host_new(&o);

		WRT_CHECK(reach_active(h, 30000));
		sim_mon_restart(h->sim);
		run_ms(h, 60000);
		WRT_CHECK(wr_client_get_state(h->c) == WR_CS_ACTIVE);
		WRT_CHECK_U64(h->sim->n_reclaims, 1);
		WRT_CHECK_U64(count_ev(h, WR_EV_FATAL), 0);
		host_free(h);
	}
}

int main(void)
{
	test_sessions();
	test_action_once();
	test_late_connect();
	test_stale_ids();
	test_tiny_window();
	test_backpressure();
	test_rx_push();
	test_partial_tx();
	test_budget();
	test_reset_mid_handshake();
	test_monitor_restart();
	test_auth_failure();
	test_connect_timeout();
	test_connect_refused();
	test_fatal_random();
	test_steady_state();
	test_destroy_mid_session();
	test_action_order_and_pools();
	test_silent_release();
	test_step_fairness();
	test_event_ring();
	test_garbage_monitor();
	test_random_schedules();
	test_hostile_host();
	test_extreme_configs();
	test_close_never_acknowledged();
	test_clock_near_wrap();
	printf("pump rounds in all tests: %lu\n", g_rounds);
	return wrt_finish();
}
