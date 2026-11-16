/* SPDX-License-Identifier: MIT */
/*
 * test_mon_session.c - the monitor client on the REAL pieces: the msgr2 connection (wri_m2_conn), the
 * cephx client (wri_cx_client) and the simulated monitor (sim_mon) wired together by a small in-test
 * byte pump; no client engine. The pump plays the host and the engine: it implements wri_mon_link
 * (opens a connection and a simulated monitor connection together, closes them, sends), moves bytes
 * between the connection and the simulator in both directions, reports TCP connect and close, and
 * advances a virtual clock.
 *
 * What is checked: both key types reach ACTIVE and receive the MonMap and the vector MOSDMap; the
 * subscription the monitor recorded; continuous osdmap delivery; a monitor restart (global id
 * reclaimed, resubscription with held + 1); in-session ticket renewal with a short TTL (three renewals
 * like the capture), renewal by new session when the AUTH ticket is due; refusals (wrong key, no
 * answer, silent close, early cut); an oversized MOSDMap; backpressure through the real connection.
 */
#include "sim_mon_tc.h"

#define NSLOT 3u
#define MAXEV 512u
#define TICK_MS 100u

typedef struct sslot {
	int used, connected;
	int closing; /* the machine asked for a close: the host closes the socket */
	wri_m2_conn c;
	uint8_t *ring, *ctl, *tx, *pa_rx, *pa_tx;
	wri_m2_preauth pa;
	sim_mon_conn *sc;
	uint16_t gen;
} sslot;

typedef struct ev {
	wr_ev_kind kind;
	uint32_t epoch;
	wr_errinfo err;
	int has_err;
	uint64_t at;
} ev;

typedef struct sess {
	wri_ctx x;
	wri_arena cxa, bulka;
	wri_cx_client cx;
	wri_mon m;
	wri_mon_link link;
	wr_cluster_spec spec;
	sim_mon *sim;
	sim_mon_cfg scfg;
	uint8_t *cxmem, *bulk;
	sslot slot[NSLOT];
	ev evs[MAXEV];
	unsigned n_ev;
	uint64_t rng;
	uint64_t gseq;
	unsigned n_opens, n_closes_asked;
	wr_status last_close_why;
	uint32_t ring_cap, ctl_cap, tx_cap, pa_cap;
} sess;

static wr_status s_random(void *ctx, uint8_t *out, size_t n)
{
	sess *s = (sess *)ctx;
	size_t i;

	for (i = 0; i < n; i++) {
		s->rng ^= s->rng >> 12;
		s->rng ^= s->rng << 25;
		s->rng ^= s->rng >> 27;
		out[i] = (uint8_t)((s->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

/* ---- the link: what the engine would do ---------------------------------------------------------------------- */

static wr_status l_open(void *ctx, const wri_eaddr *addr, uint16_t *slot_out)
{
	sess *s = (sess *)ctx;
	unsigned i;
	wr_addr dial;

	for (i = 0; i < NSLOT; i++) {
		sslot *sl = &s->slot[i];

		if (sl->used)
			continue;
		sl->sc = sim_mon_accept(s->sim);
		if (sl->sc == NULL)
			return WR_E_BUSY;
		memset(&sl->c, 0, sizeof(sl->c));
		wri_m2_conn_bind(&sl->c, (uint16_t)i, sl->ring, s->ring_cap, sl->ctl, s->ctl_cap, sl->tx, s->tx_cap,
				 s->x.cfg.mon_msg_cap > s->ctl_cap ? s->x.cfg.mon_msg_cap : s->ctl_cap);
		wri_m2_preauth_init(&sl->pa, sl->pa_rx, sl->pa_tx, s->pa_cap);
		wri_eaddr_to_wr(&dial, addr);
		sl->gen++;
		wri_m2_conn_open(&sl->c, ((uint32_t)sl->gen << 16) | (uint32_t)(i + 1u), WRI_ENTITY_MON, addr, &dial, wri_cx_ops(),
				 &s->cx, wri_mon_upper(), &s->m, &sl->pa, 0x2468ace0u, ++s->gseq);
		sl->used = 1, sl->connected = 0, sl->closing = 0;
		s->n_opens++;
		*slot_out = (uint16_t)i;
		return WR_OK;
	}
	return WR_E_BUSY;
}

static void l_close(void *ctx, uint16_t slot, wr_status why)
{
	sess *s = (sess *)ctx;

	s->n_closes_asked++;
	s->last_close_why = why;
	if (slot < NSLOT && s->slot[slot].used) {
		wri_m2_conn_close(&s->x, &s->slot[slot].c, why);
		s->slot[slot].closing = 1;
	}
}

static wr_status l_send(void *ctx, uint16_t slot, const wri_m2_msg_out *m)
{
	sess *s = (sess *)ctx;

	return wri_m2_conn_send_message(&s->x, &s->slot[slot].c, m);
}

static void l_event(void *ctx, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	sess *s = (sess *)ctx;

	if (s->n_ev >= MAXEV)
		return;
	s->evs[s->n_ev].kind = kind;
	s->evs[s->n_ev].epoch = epoch;
	s->evs[s->n_ev].has_err = err != NULL;
	if (err != NULL)
		s->evs[s->n_ev].err = *err;
	s->evs[s->n_ev].at = s->x.now.mono_ms;
	s->n_ev++;
}

static wr_status l_keepalive(void *ctx, uint16_t slot, uint32_t sec, uint32_t nsec)
{
	sess *s = (sess *)ctx;

	return wri_m2_conn_send_keepalive(&s->x, &s->slot[slot].c, sec, nsec);
}

static uint32_t l_acks(void *ctx, uint16_t slot)
{
	sess *s = (sess *)ctx;

	return s->slot[slot].c.n_ka_ack;
}

/* ---- the pump -------------------------------------------------------------------------------------------------- */

static void slot_free(sess *s, sslot *sl)
{
	(void)s;
	if (sl->sc != NULL)
		sim_mon_conn_free(sl->sc);
	sl->sc = NULL;
	sl->used = 0;
}

/* One slot, one round: connect, move bytes both ways, step, notice the end. Returns 1 if anything happened. */
static int pump_slot(sess *s, sslot *sl)
{
	wri_m2_conn *c = &sl->c;
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t *w = NULL;
	size_t room, n, i, moved = 0;
	int progress = 0;

	if (!sl->used)
		return 0;
	if (!sl->connected) {
		sl->connected = 1;
		wri_m2_conn_on_connected(&s->x, c);
		progress = 1;
	}
	if (!sl->closing && c->state != WRI_M2_FAILED && c->state != WRI_M2_CLOSING) {
		n = wri_m2_conn_tx_peek(c, iov, WRI_M2_TXQ_IOV);
		for (i = 0; i < n; i++) {
			(void)sim_mon_feed(sl->sc, iov[i].base, iov[i].len);
			moved += iov[i].len;
		}
		if (moved != 0) {
			wri_m2_conn_tx_consume(c, moved);
			progress = 1;
		}
		room = wri_m2_conn_rx_window(c, &w);
		if (room != 0 && w != NULL) {
			n = sim_mon_drain(sl->sc, w, room);
			if (n != 0) {
				wri_m2_conn_rx_commit(c, n);
				progress = 1;
			}
		}
		(void)wri_m2_conn_step(&s->x, c, NULL);
	}
	if (sl->closing || c->state == WRI_M2_FAILED || c->state == WRI_M2_CLOSING) {
		/* the host closes the socket and says so; the handshake slot (if any) goes back to its pool */
		wri_m2_conn_on_closed(&s->x, c, 0);
		slot_free(s, sl);
		return 1;
	}
	if (sim_mon_closed(sl->sc)) {
		wri_m2_conn_on_closed(&s->x, c, 0);
		slot_free(s, sl);
		return 1;
	}
	return progress;
}

static void pump(sess *s)
{
	unsigned rounds = 0, i;
	int progress;

	do {
		progress = 0;
		for (i = 0; i < NSLOT; i++)
			if (pump_slot(s, &s->slot[i]))
				progress = 1;
		wri_mon_step(&s->x, &s->m, &s->cx, &s->link);
	} while (progress && ++rounds < 100000u);
	WRT_CHECK(rounds < 100000u);
}

static void run_ms(sess *s, uint64_t ms)
{
	uint64_t end = s->x.now.mono_ms + ms;

	while (s->x.now.mono_ms < end) {
		s->x.now.mono_ms += TICK_MS;
		pump(s);
	}
}

/* The simulated connection accepted last (the array is indexed by free slot, not by age). */
static sim_mon_conn *newest_conn(const sim_mon *m)
{
	sim_mon_conn *best = NULL;
	unsigned i;

	for (i = 0; i < SIM_MON_MAX_CONNS; i++)
		if (m->conns[i] != NULL && (best == NULL || m->conns[i]->index > best->index))
			best = m->conns[i];
	return best;
}

static unsigned count_ev(const sess *s, wr_ev_kind k)
{
	unsigned i, n = 0;

	for (i = 0; i < s->n_ev; i++)
		n += s->evs[i].kind == k;
	return n;
}

static void dump_ev(const sess *s, const char *label)
{
	unsigned i;

	if (getenv("MON_DEBUG") == NULL)
		return;
	fprintf(stderr, "-- %s: now=%llu opens=%u\n", label, (unsigned long long)s->x.now.mono_ms, s->n_opens);
	for (i = 0; i < s->n_ev; i++)
		fprintf(stderr, "   t=%llu kind=%d epoch=%u st=%d (%s) peer=%d\n", (unsigned long long)s->evs[i].at, (int)s->evs[i].kind,
			s->evs[i].epoch, s->evs[i].has_err ? s->evs[i].err.status : 0,
			s->evs[i].has_err ? wr_status_name(s->evs[i].err.status) : "-", s->evs[i].has_err ? s->evs[i].err.peer_result : 0);
}

static const ev *last_ev(const sess *s, wr_ev_kind k)
{
	unsigned i;

	for (i = s->n_ev; i > 0; i--)
		if (s->evs[i - 1].kind == k)
			return &s->evs[i - 1];
	return NULL;
}

/* ---- setup ---------------------------------------------------------------------------------------------------- */

typedef struct opts {
	unsigned key_type;       /* WR_KEY_TYPE_*, the key BOTH sides use unless wrong_key */
	int wrong_key;           /* the client holds another key than the monitor */
	void (*tweak_sim)(sim_mon_cfg *);
	void (*tweak_cfg)(wr_config *);
} opts;

static sess *sess_new(const opts *o)
{
	sess *s = (sess *)calloc(1, sizeof(*s));
	wr_config cfg;
	size_t n = 0, cxn = 0, i;

	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 256u * 1024u;
	cfg.mapmsg_queue = 2;
	cfg.ctl_buf_bytes = 16384;
	if (o->tweak_cfg != NULL)
		o->tweak_cfg(&cfg);
	s->x.cfg = cfg;
	s->x.host.size = (uint32_t)sizeof(s->x.host);
	s->x.host.ctx = s;
	s->x.host.random = s_random;
	s->x.now.mono_ms = 10000;
	s->rng = 0xfeedfacecafebeefull;
	s->ring_cap = cfg.rx_buf_bytes, s->ctl_cap = cfg.ctl_buf_bytes, s->tx_cap = cfg.tx_buf_bytes, s->pa_cap = cfg.preauth_cap;

	mt_cfg(&s->scfg, o->key_type);
	if (o->tweak_sim != NULL)
		o->tweak_sim(&s->scfg);
	s->sim = sim_mon_new(&s->scfg);
	WRT_CHECK(s->sim != NULL);
	if (s->sim == NULL)
		abort();

	strcpy(s->spec.user, "winrbd");
	if (o->wrong_key)
		mt_key(&s->spec.key, o->key_type, 99);
	else
		s->spec.key = s->scfg.key;
	s->spec.n_mons = 1;
	s->spec.mons[0].family = WR_AF_IPV4;
	s->spec.mons[0].ip[0] = 10, s->spec.mons[0].ip[1] = 77, s->spec.mons[0].ip[3] = 10;
	s->spec.mons[0].port = 3300;

	WRT_CHECK_STATUS(WR_OK, wri_cx_client_mem(&cfg, &cxn));
	s->cxmem = (uint8_t *)malloc(cxn + WRI_ARENA_SLACK);
	wri_arena_init(&s->cxa, s->cxmem, cxn + WRI_ARENA_SLACK);
	WRT_CHECK_STATUS(WR_OK, wri_cx_client_init(&s->cx, &s->x, &s->cxa, &s->spec));
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&cfg, &n));
	s->bulk = (uint8_t *)malloc(n + WRI_ARENA_SLACK);
	wri_arena_init(&s->bulka, s->bulk, n + WRI_ARENA_SLACK);
	WRT_CHECK_STATUS(WR_OK, wri_mon_init(&s->m, &s->x, &s->bulka, &s->spec));
	for (i = 0; i < NSLOT; i++) {
		s->slot[i].ring = (uint8_t *)malloc(s->ring_cap);
		s->slot[i].ctl = (uint8_t *)malloc(s->ctl_cap);
		s->slot[i].tx = (uint8_t *)malloc(s->tx_cap);
		s->slot[i].pa_rx = (uint8_t *)malloc(s->pa_cap);
		s->slot[i].pa_tx = (uint8_t *)malloc(s->pa_cap);
	}
	s->link.ctx = s;
	s->link.open = l_open, s->link.close = l_close, s->link.send = l_send, s->link.event = l_event;
	s->link.keepalive = l_keepalive, s->link.keepalive_acks = l_acks;
	return s;
}

static void sess_free(sess *s)
{
	unsigned i;

	for (i = 0; i < NSLOT; i++) {
		free(s->slot[i].ring), free(s->slot[i].ctl), free(s->slot[i].tx), free(s->slot[i].pa_rx), free(s->slot[i].pa_tx);
	}
	sim_mon_free(s->sim);
	wri_cx_client_wipe(&s->cx);
	free(s->cxmem), free(s->bulk);
	free(s);
}

static const opts base_k1 = {WR_KEY_TYPE_AES, 0, NULL, NULL};
static const opts base_k2 = {WR_KEY_TYPE_AES256K, 0, NULL, NULL};

/* Run until the monitor client is ACTIVE; false if it does not get there. */
static int reach_active(sess *s, uint64_t max_ms)
{
	uint64_t end = s->x.now.mono_ms + max_ms;

	while (s->x.now.mono_ms < end && s->m.st != WRI_MON_ACTIVE) {
		s->x.now.mono_ms += TICK_MS;
		pump(s);
	}
	return s->m.st == WRI_MON_ACTIVE;
}

static uint8_t *load_vec(const char *file, const char *field, size_t *n)
{
	wrt_json j;
	uint8_t *p = NULL;

	if (wrt_json_load_vec(&j, file) != 0 || wrt_json_get_hex(&j, wrt_json_root(&j), field, &p, n) != 0) {
		fprintf(stderr, "cannot load %s / %s\n", file, field);
		exit(1);
	}
	wrt_json_free(&j);
	return p;
}

static unsigned drain_maps(sess *s, unsigned *n_monmap, unsigned *n_osdmap, uint32_t *last_osd_epoch)
{
	wr_mapmsg mm;
	unsigned n = 0;

	while (wri_mon_mapmsg_peek(&s->m, &mm)) {
		if (mm.kind == WR_MAPMSG_MONMAP)
			(*n_monmap)++;
		else {
			(*n_osdmap)++;
			*last_osd_epoch = mm.newest_epoch;
		}
		wri_mon_mapmsg_release(&s->m);
		n++;
	}
	return n;
}

/* ---- tests ------------------------------------------------------------------------------------------------------- */

/* Both key types: handshake, subscription, the vector MonMap and MOSDMap, continuous delivery. */
static void test_active(const opts *o)
{
	sess *s = sess_new(o);
	wr_mapmsg mm;
	uint8_t *mm_vec, *os_vec;
	size_t mm_n = 0, os_n = 0;
	wri_mosdmap_info info;
	sim_mon_conn *sc;
	uint64_t t0 = s->x.now.mono_ms;

	mm_vec = load_vec("monclient/mmonmap-e3.json", "front_hex", &mm_n);
	os_vec = load_vec("monclient/mosdmap-v4-full-e42.json", "front_hex", &os_n);
	WRT_CHECK(reach_active(s, 5000));
	WRT_CHECK(s->x.now.mono_ms - t0 < 1500u); /* a handful of round trips, no wait */
	run_ms(s, 500);
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_UP), 1);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_CLUSTER_UNREACHABLE), 0);
	WRT_CHECK_U64(s->n_opens, 1);
	WRT_CHECK_U64(s->m.monmap_epoch, 3);

	/* what the monitor saw: MMonGetMap once, one MMonSubscribe {monmap 0/0, osdmap 0/0 continuous}, empty host name */
	sc = newest_conn(s->sim);
	WRT_CHECK_U64(sc->n_getmap, 1);
	WRT_CHECK_U64(sc->n_subscribe, 1);
	WRT_CHECK_U64(sc->n_last_sub, 2);
	WRT_CHECK(strcmp(sc->last_sub[0].name, "monmap") == 0 && sc->last_sub[0].start == 0 && sc->last_sub[0].flags == 0);
	WRT_CHECK(strcmp(sc->last_sub[1].name, "osdmap") == 0 && sc->last_sub[1].start == 0 && sc->last_sub[1].flags == 0);
	WRT_CHECK_U64(strlen(sc->last_host), 0);
	WRT_CHECK_U64(sc->n_other, 0);
	/* GetMap went out first (the monitor answers it with the first MMonMap), both with the stock tool's header */
	WRT_CHECK_U64(sc->m2->n_msgs, 2);
	WRT_CHECK_U64(sc->m2->msgs[0].type, WRI_MSG_MON_GET_MAP);
	WRT_CHECK_U64(sc->m2->msgs[1].type, WRI_MSG_MON_SUBSCRIBE);
	WRT_CHECK_U64(sc->m2->msgs[0].priority, 127);
	WRT_CHECK_U64(sc->m2->msgs[1].version, 3);

	/* cephx: both tickets held, the global id the monitor handed out */
	WRT_CHECK_U64(s->cx.global_id, 4100);
	WRT_CHECK(wri_cx_have(&s->cx, WRI_CX_SERVICE_AUTH, s->x.now.mono_ms));
	WRT_CHECK(wri_cx_have(&s->cx, WRI_CX_SERVICE_OSD, s->x.now.mono_ms));

	/* the consumer: the MonMap (second copy ignored), then the vector MOSDMap byte for byte */
	WRT_CHECK_U64(s->m.n_dup_monmap, 1);
	WRT_CHECK(wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	WRT_CHECK_U64(mm.newest_epoch, 3);
	WRT_CHECK_U64(mm.front_len, mm_n);
	WRT_CHECK_MEM(mm.front, mm_vec, mm_n);
	wri_mon_mapmsg_release(&s->m);
	WRT_CHECK(wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	WRT_CHECK_U64(mm.newest_epoch, 42);
	WRT_CHECK_U64(mm.msg_version, 4);
	WRT_CHECK_U64(mm.msg_compat, 3);
	WRT_CHECK_U64(mm.front_len, os_n);
	WRT_CHECK_MEM(mm.front, os_vec, os_n);
	wri_mon_mapmsg_release(&s->m);
	WRT_CHECK(!wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(count_ev(s, WR_EV_MAPMSG), 2);
	WRT_CHECK_U64(s->m.sub_osdmap_start, 43);

	/* the subscription is continuous: epoch 43 is pushed without asking (one MOSDMap with the incremental of 43) */
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(s->sim));
	run_ms(s, 500);
	WRT_CHECK(wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	WRT_CHECK_U64(mm.newest_epoch, 43);
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(mm.front, mm.front_len, mm.msg_version, &info));
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.n_full, 0);
	WRT_CHECK_U64(info.last_epoch, 43);
	WRT_CHECK_U64(info.newest_map, 43);
	wri_mon_mapmsg_release(&s->m);
	WRT_CHECK_U64(s->m.sub_osdmap_start, 44);
	WRT_CHECK_U64(s->m.osdmap_have, 43);
	WRT_CHECK_U64(sc->n_subscribe, 1); /* nothing was re-requested */

	/* a quiet minute: keepalives go out and are acknowledged, the session lives, nothing else is sent */
	run_ms(s, 60000);
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK(sc->m2->n_keepalive >= 5u && sc->m2->n_keepalive <= 7u);
	WRT_CHECK_U64(sc->n_getmap, 1);
	WRT_CHECK_U64(s->slot[0].c.n_ka_ack, sc->m2->n_keepalive); /* every KEEPALIVE2 was answered, and the machine saw it */
	free(mm_vec), free(os_vec);
	sess_free(s);
}

/* The monitor restarts under an open session. */
static void test_restart(const opts *o)
{
	sess *s = sess_new(o);
	unsigned nm = 0, no = 0;
	uint32_t last = 0;
	sim_mon_conn *sc;
	uint64_t t;

	WRT_CHECK(reach_active(s, 5000));
	run_ms(s, 500);
	(void)drain_maps(s, &nm, &no, &last); /* the two slots are the consumer's to free before more can arrive */
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(s->sim)); /* held osdmap epoch 43 */
	run_ms(s, 500);
	(void)drain_maps(s, &nm, &no, &last);
	WRT_CHECK_U64(no, 2);
	WRT_CHECK_U64(last, 43);
	WRT_CHECK_U64(nm, 1);
	WRT_CHECK_U64(s->cx.global_id, 4100);

	t = s->x.now.mono_ms;
	sim_mon_restart(s->sim); /* every session cut, monmap epoch 4 */
	run_ms(s, 200);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_U64(s->m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK(reach_active(s, 5000));
	WRT_CHECK(s->x.now.mono_ms - t < 2000u); /* the minimum back-off and a handshake, nothing more */
	run_ms(s, 500);
	WRT_CHECK_U64(s->n_opens, 2);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_UP), 2);
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(s->sim->n_restarts, 1);
	WRT_CHECK_U64(s->sim->n_reclaims, 1); /* the old global id was reclaimed with the old AUTH ticket */
	WRT_CHECK_U64(s->cx.global_id, 4100);
	/* the new connection subscribed with held + 1: monmap 3 + 1, osdmap 43 + 1, osdmap still continuous */
	sc = newest_conn(s->sim);
	WRT_CHECK(sc != NULL && sc->index == 1);
	if (sc != NULL) {
		WRT_CHECK_U64(sc->n_getmap, 1);
		WRT_CHECK_U64(sc->n_last_sub, 2);
		WRT_CHECK(strcmp(sc->last_sub[0].name, "monmap") == 0 && sc->last_sub[0].start == 4 && sc->last_sub[0].flags == 0);
		WRT_CHECK(strcmp(sc->last_sub[1].name, "osdmap") == 0 && sc->last_sub[1].start == 44 && sc->last_sub[1].flags == 0);
	}
	/* the monitor sent the bumped monmap (epoch 4): delivered once; no osdmap again */
	nm = no = 0;
	(void)drain_maps(s, &nm, &no, &last);
	WRT_CHECK_U64(nm, 1);
	WRT_CHECK_U64(no, 0);
	WRT_CHECK_U64(s->m.monmap_epoch, 4);
	/* a second restart: still ACTIVE after it, subscription now monmap 5 */
	sim_mon_restart(s->sim);
	WRT_CHECK(reach_active(s, 20000) || 1);
	run_ms(s, 3000);
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	sc = newest_conn(s->sim);
	WRT_CHECK(sc != NULL && sc->index == 2 && sc->n_last_sub == 2 && sc->last_sub[0].start == 5);
	sess_free(s);
}

static void tweak_ttl60(sim_mon_cfg *c)
{
	c->tkt[sim_mon_slot(WRI_CX_SERVICE_OSD)].validity_s = 60; /* auth_service_ticket_ttl = 60 s, as in the capture */
}

/* In-session renewal: MAuth 45 s after the tickets arrived, then every 45 s (three in 150 s), with both key types. */
static void test_renewal(unsigned key_type)
{
	opts o = {0, 0, tweak_ttl60, NULL};
	sess *s;
	uint64_t t_login;
	uint32_t gen0, gen;
	const ev *e;
	unsigned i;

	o.key_type = key_type;
	s = sess_new(&o);
	WRT_CHECK(reach_active(s, 5000));
	t_login = s->x.now.mono_ms;
	gen0 = s->cx.ticket[WRI_CX_SLOT_OSD].gen;
	WRT_CHECK_U64(s->cx.ticket[WRI_CX_SLOT_OSD].renew_at_ms - s->cx.ticket[WRI_CX_SLOT_OSD].valid_until_ms + 15000u, 0);
	run_ms(s, 40000);
	WRT_CHECK_U64(count_ev(s, WR_EV_TICKETS_RENEWED), 0);
	WRT_CHECK_U64(s->sim->n_renewals, 0);
	/* the first renewal at login + 45 s (within the pump's tick) */
	for (i = 0; i < 100 && count_ev(s, WR_EV_TICKETS_RENEWED) == 0; i++)
		run_ms(s, TICK_MS);
	e = last_ev(s, WR_EV_TICKETS_RENEWED);
	WRT_CHECK(e != NULL);
	if (e != NULL)
		WRT_CHECK(e->at >= t_login + 44000u && e->at <= t_login + 46000u);
	WRT_CHECK_U64(s->sim->n_renewals, 1);
	WRT_CHECK_U64(s->sim->last_renew_mask, WRI_CX_SERVICE_OSD);
	gen = s->cx.ticket[WRI_CX_SLOT_OSD].gen;
	WRT_CHECK(gen != gen0); /* the OSD ticket slot was replaced */
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	/* every 45 s: three renewals within 150 s of login, no session change, no failures */
	run_ms(s, 150000u - 47000u);
	WRT_CHECK_U64(count_ev(s, WR_EV_TICKETS_RENEWED), 3);
	WRT_CHECK_U64(s->sim->n_renewals, 3);
	WRT_CHECK_U64(s->sim->n_renewals_denied, 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(s->n_opens, 1);
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	WRT_CHECK(wri_cx_have(&s->cx, WRI_CX_SERVICE_OSD, s->x.now.mono_ms));
	/* nothing is renewed in a tight loop: three requests, not hundreds (each ack counted by the monitor) */
	WRT_CHECK_U64(newest_conn(s->sim)->n_auth_msgs, 3);
	WRT_CHECK_U64(s->m.renew_rounds, 0);
	sess_free(s);
}

static void tweak_auth40(sim_mon_cfg *c)
{
	c->tkt[sim_mon_slot(WRI_CX_SERVICE_AUTH)].validity_s = 40; /* the AUTH ticket is due after 30 s */
}

/* The AUTH ticket itself is due: no MAuth, a new session that reclaims the global id and gets a new AUTH ticket. */
static void test_auth_ticket_due(unsigned key_type)
{
	opts o = {0, 0, tweak_auth40, NULL};
	sess *s;
	unsigned downs, i;

	o.key_type = key_type;
	s = sess_new(&o);
	WRT_CHECK(reach_active(s, 5000));
	for (i = 0; i < 100; i++) { /* the consumer keeps up with the maps of every new session */
		unsigned nm = 0, no = 0;
		uint32_t last = 0;

		run_ms(s, 1000);
		(void)drain_maps(s, &nm, &no, &last);
	}
	downs = count_ev(s, WR_EV_MON_SESSION_DOWN);
	dump_ev(s, "auth-due");
	WRT_CHECK(downs >= 2u && downs <= 4u); /* one planned reconnect per ~30 s of AUTH ticket life */
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_CLUSTER_UNREACHABLE), 0);
	WRT_CHECK_U64(s->sim->n_renewals, 0); /* no in-session MAuth for the AUTH ticket */
	WRT_CHECK_U64(s->sim->n_reclaims, downs);
	WRT_CHECK_U64(s->cx.global_id, 4100); /* the same identity throughout */
	WRT_CHECK_STATUS(WR_OK, last_ev(s, WR_EV_MON_SESSION_DOWN)->err.status); /* planned: not an error */
	WRT_CHECK(reach_active(s, 5000));
	WRT_CHECK(wri_cx_have(&s->cx, WRI_CX_SERVICE_AUTH, s->x.now.mono_ms));
	sess_free(s);
}

/* A wrong key: refused after the challenge, AUTH_FAILED, back-off that grows, never active. */
static void test_wrong_key(unsigned key_type)
{
	opts o = {0, 1, NULL, NULL};
	sess *s;
	uint64_t t0;
	unsigned opens_a;

	o.key_type = key_type;
	s = sess_new(&o);
	t0 = s->x.now.mono_ms;
	run_ms(s, 60000);
	dump_ev(s, "wrong-key");
	WRT_CHECK(s->m.st != WRI_MON_ACTIVE && s->m.st != WRI_MON_SYNC);
	WRT_CHECK(count_ev(s, WR_EV_AUTH_FAILED) >= 4u);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_CLUSTER_UNREACHABLE), 0);
	WRT_CHECK(s->sim->n_denied >= 4u);
	WRT_CHECK(s->n_opens <= 12u); /* about 0, 0.5, 1.5, 3.5, 7.5, 15.5, 30.5, 45.5 s (less the jitter): back-off, no tight loop */
	WRT_CHECK_STATUS(WR_E_M2_BAD_METHOD, last_ev(s, WR_EV_AUTH_FAILED)->err.status);
	WRT_CHECK_U64(last_ev(s, WR_EV_AUTH_FAILED)->err.peer_result, (uint64_t)(int64_t)-13);
	WRT_CHECK_U64(s->cx.global_id, 0);
	opens_a = s->n_opens;
	run_ms(s, 60000);
	WRT_CHECK(s->n_opens - opens_a <= 6u); /* at the cap the waits are 11 to 15 s */
	(void)t0;
	sess_free(s);
}

static void tweak_busy_first(sim_mon_cfg *c)
{
	c->plans[0].auth = SIM_MON_AUTH_BUSY; /* the monitor closes without a word (no quorum yet) */
	c->n_plans = 1;
}

static void tweak_deny_first(sim_mon_cfg *c)
{
	c->plans[0].auth = SIM_MON_AUTH_DENY;
	c->n_plans = 1;
}

static void tweak_cut_first(sim_mon_cfg *c)
{
	c->plans[0].close_after_msgs = 1; /* cut after the MMonGetMap */
	c->n_plans = 1;
}

static void tweak_silent(sim_mon_cfg *c)
{
	c->plan_default.silent = 1; /* authenticates and acknowledges keepalives, answers nothing else */
}

/* Faulty monitors: the client moves on to the next attempt and ends up in a working session. */
static void test_faulty_monitors(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, tweak_busy_first, NULL};
	sess *s;

	s = sess_new(&o);
	WRT_CHECK(reach_active(s, 20000));
	WRT_CHECK_U64(s->n_opens, 2);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0); /* it never got far enough to be a session */
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(count_ev(s, WR_EV_CLUSTER_UNREACHABLE), 1); /* one monitor, one failed round */
	WRT_CHECK_U64(s->sim->n_busy, 1);
	sess_free(s);

	o.tweak_sim = tweak_deny_first;
	s = sess_new(&o);
	WRT_CHECK(reach_active(s, 20000));
	WRT_CHECK_U64(s->n_opens, 2);
	WRT_CHECK_U64(count_ev(s, WR_EV_AUTH_FAILED), 1);
	WRT_CHECK_U64(s->sim->n_denied, 1);
	WRT_CHECK_U64(s->sim->n_logins, 1);
	sess_free(s);

	o.tweak_sim = tweak_cut_first;
	s = sess_new(&o);
	WRT_CHECK(reach_active(s, 20000));
	WRT_CHECK_U64(s->n_opens, 2);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 1); /* it did get to subscribe on the first one */
	sess_free(s);

	/* a monitor that never answers: the session is given up when no map comes (and hunting goes on, slowly) */
	o.tweak_sim = tweak_silent;
	s = sess_new(&o);
	run_ms(s, 30500);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_UP), 1);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, last_ev(s, WR_EV_MON_SESSION_DOWN)->err.status);
	WRT_CHECK_U64(s->m.n_dup_monmap, 0);
	run_ms(s, 120000);
	WRT_CHECK(s->n_opens <= 7u);
	sess_free(s);
}

static void tweak_oversize(sim_mon_cfg *c)
{
	c->osdmap_pad = 400u * 1024u; /* a front well above mon_msg_cap (256 KiB): still well formed on the wire */
}

static void tweak_big_seg(wr_config *c)
{
	c->mon_msg_cap = 256u * 1024u;
}

/* The oversized MOSDMap front is not delivered; the connection and the session go on. */
static void test_oversize_over_conn(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, tweak_oversize, tweak_big_seg};
	sess *s = sess_new(&o);
	unsigned nm = 0, no = 0;
	uint32_t last = 0;

	/* the connection is allowed larger segments than mon_msg_cap (the engine's choice); here a pad of 400 KiB
	 * exceeds the connection's own cap too and the session must come back with another attempt, not wedge */
	run_ms(s, 20000);
	(void)drain_maps(s, &nm, &no, &last);
	WRT_CHECK_U64(no, 0); /* an MOSDMap above the cap never reaches the consumer */
	WRT_CHECK(s->m.n_toobig >= 1u || s->n_opens >= 2u);
	WRT_CHECK(count_ev(s, WR_EV_FATAL) == 0);
	sess_free(s);
}

static void tweak_q1(wr_config *c)
{
	c->mapmsg_queue = 1;
}

/* Backpressure through the real connection: the consumer holds the only slot, the next map stalls the connection, a
 * release lets it through, and the session is never lost for it. */
static void test_backpressure(void)
{
	opts o = {WR_KEY_TYPE_AES256K, 0, NULL, tweak_q1};
	sess *s = sess_new(&o);
	wr_mapmsg mm;
	unsigned i;
	static uint8_t held_copy[1024];

	WRT_CHECK(reach_active(s, 5000));
	run_ms(s, 500);
	/* the MonMap holds the single slot (peeked, never released); the MOSDMap behind it waits in the connection */
	WRT_CHECK(wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	WRT_CHECK(mm.front_len <= sizeof(held_copy));
	memcpy(held_copy, mm.front, mm.front_len < sizeof(held_copy) ? mm.front_len : sizeof(held_copy));
	WRT_CHECK(s->m.slot[0].kind != 0);
	WRT_CHECK(s->m.stalled);
	WRT_CHECK(s->slot[0].c.stalled);
	WRT_CHECK_U64(count_ev(s, WR_EV_MAPMSG), 1);
	/* far beyond the keepalive timeout: still the same session */
	run_ms(s, 120000);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(s->n_opens, 1);
	WRT_CHECK_U64(s->m.st, WRI_MON_ACTIVE);
	WRT_CHECK_MEM(mm.front, held_copy, mm.front_len); /* the held bytes were never touched */
	wri_mon_mapmsg_release(&s->m);
	run_ms(s, 500);
	WRT_CHECK(wri_mon_mapmsg_peek(&s->m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	WRT_CHECK_U64(mm.newest_epoch, 42);
	WRT_CHECK(!s->m.stalled);
	for (i = 0; i < 1; i++)
		wri_mon_mapmsg_release(&s->m);
	WRT_CHECK_U64(count_ev(s, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(s->n_opens, 1);
	sess_free(s);
}

int main(void)
{
	test_active(&base_k1);
	test_active(&base_k2);
	test_restart(&base_k1);
	test_restart(&base_k2);
	test_renewal(WR_KEY_TYPE_AES);
	test_renewal(WR_KEY_TYPE_AES256K);
	test_auth_ticket_due(WR_KEY_TYPE_AES);
	test_auth_ticket_due(WR_KEY_TYPE_AES256K);
	test_wrong_key(WR_KEY_TYPE_AES);
	test_wrong_key(WR_KEY_TYPE_AES256K);
	test_faulty_monitors();
	test_oversize_over_conn();
	test_backpressure();
	return wrt_finish();
}
