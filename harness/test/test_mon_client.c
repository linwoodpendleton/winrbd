/* SPDX-License-Identifier: MIT */
/*
 * test_mon_client.c - the monitor client's session machine (core/src/mon/wri_mon*.c) against a fake
 * link, a fake connection (the upper-layer callbacks are called by hand), a virtual clock and a
 * fake random source. No msgr2, no cephx: the machine's decisions only. The same machine on the real
 * connection and the simulated monitor is test_mon_session.c.
 *
 * The wire bytes the machine produces are checked against harness/vectors/monclient (the
 * MMonGetMap / MMonSubscribe shapes of scenario-fresh-session / scenario-monitor-restart, the item
 * bytes of the subscribe vectors, the MAuth shape of mauth-renewal-scrubbed); the maps it receives are
 * the vector MMonMap and MOSDMap.
 */
#include "wrt.h"
#include "wri_misc.h"
#include "wri_mon.h"

#define MAXLOG 256u

typedef struct sent_msg {
	uint16_t slot, type, prio, version, compat;
	uint32_t flen;
	uint8_t front[512];
	uint64_t at;
} sent_msg;

typedef struct ev_rec {
	wr_ev_kind kind;
	uint32_t epoch;
	wr_errinfo err;
	int has_err;
	uint64_t at;
} ev_rec;

typedef struct rg {
	wri_ctx x;
	wri_mon m;
	wri_cx_client cx;
	int have_cx;
	wri_mon_link link;
	wr_cluster_spec spec;
	uint8_t *bulk, *cxmem;
	/* fake link */
	uint16_t next_slot;
	wr_status open_st;
	int busy_opens;
	unsigned n_open_calls, n_open;
	uint64_t open_at[MAXLOG];
	uint8_t open_ip[MAXLOG];
	unsigned n_close;
	wr_status close_why;
	uint16_t close_slot;
	sent_msg sent[MAXLOG];
	unsigned n_sent;
	int send_busy;
	int send_pass; /* the next this-many sends succeed before send_busy / send_st apply */
	wr_status send_st;
	ev_rec ev[MAXLOG];
	unsigned n_ev;
	unsigned n_ka;
	int ka_busy;
	wr_status ka_st;
	uint32_t ka_sec, ka_nsec;
	uint64_t ka_at[MAXLOG];
	uint32_t acks;
	int have_ka;
	/* fake random */
	uint8_t rng_byte;
	int rng_fail;
	/* fake connection */
	wri_m2_conn fc;
	uint64_t seq;
} rg;

/* ---- vector fixtures --------------------------------------------------------------------------------- */

static uint8_t *monmap_front, *osdmap_front, *sub_vec, *sub_derived;
static size_t monmap_front_n, osdmap_front_n, sub_vec_n, sub_derived_n;
static uint16_t osdmap_ver, osdmap_compat;
static wrt_json scen_fresh;

static void load_hex(const char *file, const char *field, uint8_t **p, size_t *n)
{
	wrt_json j;

	if (wrt_json_load_vec(&j, file) != 0 || wrt_json_get_hex(&j, wrt_json_root(&j), field, p, n) != 0) {
		fprintf(stderr, "cannot load %s / %s\n", file, field);
		exit(1);
	}
	wrt_json_free(&j);
}

static void load_fixtures(void)
{
	load_hex("monclient/mmonmap-e3.json", "front_hex", &monmap_front, &monmap_front_n);
	load_hex("monclient/mosdmap-v4-full-e42.json", "front_hex", &osdmap_front, &osdmap_front_n);
	load_hex("monclient/mmonsubscribe-reconnect.json", "front_hex", &sub_vec, &sub_vec_n);
	load_hex("monclient/mmonsubscribe-derived-monmap-only.json", "front_hex", &sub_derived, &sub_derived_n);
	osdmap_ver = 4, osdmap_compat = 3;
	if (wrt_json_load_vec(&scen_fresh, "monclient/scenario-fresh-session.json") != 0)
		exit(1);
}

static void put32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16), p[3] = (uint8_t)(v >> 24);
}

static void put64(uint8_t *p, uint64_t v)
{
	put32(p, (uint32_t)v);
	put32(p + 4, (uint32_t)(v >> 32));
}

/* The vector MonMap front with another epoch (offset 4 + 22: length prefix, struct header 6, fsid 16). */
static uint8_t *monmap_with(uint32_t epoch, int fsid_flip)
{
	uint8_t *p = (uint8_t *)malloc(monmap_front_n);

	memcpy(p, monmap_front, monmap_front_n);
	put32(p + 26, epoch);
	if (fsid_flip)
		p[10] ^= 0xff;
	return p;
}

static uint8_t *osdmap_with(int fsid_flip)
{
	uint8_t *p = (uint8_t *)malloc(osdmap_front_n);

	memcpy(p, osdmap_front, osdmap_front_n);
	if (fsid_flip)
		p[0] ^= 0xff;
	return p;
}

/* ---- the rig -------------------------------------------------------------------------------------------- */

static wr_status fl_random(void *c, uint8_t *out, size_t n)
{
	rg *r = (rg *)c;

	if (r->rng_fail)
		return WR_E_HOST_RANDOM;
	memset(out, r->rng_byte, n);
	return WR_OK;
}

static wr_status fl_open(void *c, const wri_eaddr *a, uint16_t *slot)
{
	rg *r = (rg *)c;

	r->n_open_calls++;
	if (r->busy_opens > 0) {
		r->busy_opens--;
		return WR_E_BUSY;
	}
	if (r->open_st != WR_OK)
		return r->open_st;
	if (r->n_open < MAXLOG) {
		r->open_at[r->n_open] = r->x.now.mono_ms;
		r->open_ip[r->n_open] = a->ip[3];
	}
	r->n_open++;
	*slot = r->next_slot++;
	memset(&r->fc, 0, sizeof(r->fc));
	r->fc.slot = *slot;
	return WR_OK;
}

static void fl_close(void *c, uint16_t slot, wr_status why)
{
	rg *r = (rg *)c;

	r->n_close++;
	r->close_slot = slot;
	r->close_why = why;
}

static wr_status fl_send(void *c, uint16_t slot, const wri_m2_msg_out *m)
{
	rg *r = (rg *)c;
	sent_msg *s;

	if (r->send_pass > 0) {
		r->send_pass--;
	} else {
		if (r->send_busy > 0) {
			r->send_busy--;
			return WR_E_BUSY;
		}
		if (r->send_st != WR_OK)
			return r->send_st;
	}
	if (r->n_sent >= MAXLOG)
		return WR_OK;
	s = &r->sent[r->n_sent++];
	s->slot = slot, s->type = m->type, s->prio = m->priority, s->version = m->version, s->compat = m->compat_version;
	s->flen = m->front_len;
	s->at = r->x.now.mono_ms;
	memset(s->front, 0, sizeof(s->front));
	if (m->front_len != 0)
		memcpy(s->front, m->front, m->front_len < sizeof(s->front) ? m->front_len : sizeof(s->front));
	return WR_OK;
}

static void fl_event(void *c, wr_ev_kind kind, uint32_t epoch, const wr_errinfo *err)
{
	rg *r = (rg *)c;

	if (r->n_ev >= MAXLOG)
		return;
	r->ev[r->n_ev].kind = kind;
	r->ev[r->n_ev].epoch = epoch;
	r->ev[r->n_ev].has_err = err != NULL;
	if (err != NULL)
		r->ev[r->n_ev].err = *err;
	r->ev[r->n_ev].at = r->x.now.mono_ms;
	r->n_ev++;
}

static wr_status fl_keepalive(void *c, uint16_t slot, uint32_t sec, uint32_t nsec)
{
	rg *r = (rg *)c;

	(void)slot;
	if (r->ka_busy > 0) {
		r->ka_busy--;
		return WR_E_BUSY;
	}
	if (r->ka_st != WR_OK)
		return r->ka_st;
	if (r->n_ka < MAXLOG)
		r->ka_at[r->n_ka] = r->x.now.mono_ms;
	r->n_ka++;
	r->ka_sec = sec, r->ka_nsec = nsec;
	return WR_OK;
}

static uint32_t fl_acks(void *c, uint16_t slot)
{
	(void)slot;
	return ((rg *)c)->acks;
}

static void rg_init_cfg(rg *r, void (*tweak)(wr_config *))
{
	wr_config cfg;

	memset(r, 0, sizeof(*r));
	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 64u * 1024u;
	cfg.mapmsg_queue = 2;
	if (tweak != NULL)
		tweak(&cfg);
	r->x.cfg = cfg;
	r->x.host.size = (uint32_t)sizeof(r->x.host);
	r->x.host.ctx = r;
	r->x.host.random = fl_random;
	r->x.now.mono_ms = 1000;
	r->next_slot = 3;
	r->link.ctx = r;
	r->link.open = fl_open, r->link.close = fl_close, r->link.send = fl_send, r->link.event = fl_event;
	r->link.keepalive = fl_keepalive, r->link.keepalive_acks = fl_acks;
	r->spec.n_mons = 3;
	r->spec.mons[0].family = r->spec.mons[1].family = r->spec.mons[2].family = WR_AF_IPV4;
	r->spec.mons[0].ip[0] = r->spec.mons[1].ip[0] = r->spec.mons[2].ip[0] = 10;
	r->spec.mons[0].ip[1] = r->spec.mons[1].ip[1] = r->spec.mons[2].ip[1] = 77;
	r->spec.mons[0].ip[3] = 10, r->spec.mons[1].ip[3] = 11, r->spec.mons[2].ip[3] = 12;
	r->spec.mons[0].port = 3300, r->spec.mons[1].port = 3300, r->spec.mons[2].port = 0; /* 0 = the default */
}

static void rg_start(rg *r)
{
	wri_arena a;
	size_t n = 0;

	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&r->x.cfg, &n));
	n += WRI_ARENA_SLACK;
	r->bulk = (uint8_t *)malloc(n);
	wri_arena_init(&a, r->bulk, n);
	WRT_CHECK_STATUS(WR_OK, wri_mon_init(&r->m, &r->x, &a, &r->spec));
}

static void rg_init(rg *r, void (*tweak)(wr_config *))
{
	rg_init_cfg(r, tweak);
	rg_start(r);
}

static void rg_free(rg *r)
{
	free(r->bulk);
	free(r->cxmem);
}

static void rg_step(rg *r)
{
	wri_mon_step(&r->x, &r->m, r->have_cx ? &r->cx : NULL, &r->link);
}

/* Step at every deadline up to `until`, then leave the clock there. Fails the test if the machine wants to
 * run again at the same instant over and over (a tight loop). */
static void rg_run(rg *r, uint64_t until)
{
	unsigned same = 0;

	for (;;) {
		uint64_t d;

		rg_step(r);
		d = wri_mon_deadline(&r->m);
		if (d == WR_DEADLINE_NONE || d > until)
			break;
		if (d <= r->x.now.mono_ms) {
			if (++same > 20) {
				WRT_CHECK(!"the machine wants to step again at once, over and over");
				break;
			}
		} else {
			r->x.now.mono_ms = d;
			same = 0;
		}
	}
	if (r->x.now.mono_ms < until) {
		r->x.now.mono_ms = until;
		rg_step(r);
	}
}

/* ---- calls into the upper-layer table ---------------------------------------------------------------------- */

static void cb_ready(rg *r)
{
	wri_mon_upper()->ready(&r->m, &r->fc);
}

static void cb_closed(rg *r, wr_status st)
{
	wr_errinfo e;

	memset(&e, 0, sizeof(e));
	e.status = st;
	e.module = WR_MOD_M2;
	wri_mon_upper()->closed(&r->m, &r->fc, &e);
}

/* Deliver one message the way the connection would: plan, copy into the sink, message. Returns plan's status. */
static wr_status deliver(rg *r, uint16_t type, uint16_t ver, uint16_t compat, const uint8_t *front, uint32_t n)
{
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t seglen[3], stored[3] = {0, 0, 0};
	wr_status st;

	memset(&h, 0, sizeof(h));
	h.seq = ++r->seq, h.type = type, h.priority = 196, h.version = ver, h.compat_version = compat, h.flags = 3;
	seglen[0] = n, seglen[1] = seglen[2] = 0;
	memset(sink, 0xAB, sizeof(sink)); /* plan must set every sink */
	st = wri_mon_upper()->plan(&r->m, &r->fc, &h, seglen, sink);
	if (st != WR_OK)
		return st;
	if (sink[0].dst != NULL) {
		WRT_CHECK(sink[0].cap >= n);
		memcpy(sink[0].dst, front, n);
		stored[0] = n;
	}
	WRT_CHECK(sink[1].dst == NULL && sink[2].dst == NULL); /* middle and data are always discarded */
	wri_mon_upper()->message(&r->m, &r->fc, &h, stored);
	return WR_OK;
}

static wr_status deliver_monmap(rg *r, uint32_t epoch)
{
	uint8_t *f = monmap_with(epoch, 0);
	wr_status st = deliver(r, WRI_MSG_MON_MAP, 1, 1, f, (uint32_t)monmap_front_n);

	free(f);
	return st;
}

static wr_status deliver_osdmap(rg *r)
{
	return deliver(r, WRI_MSG_OSD_MAP, osdmap_ver, osdmap_compat, osdmap_front, (uint32_t)osdmap_front_n);
}

/* Bring a session up to SYNC: first attempt, READY, the two messages out. */
static void bring_to_sync(rg *r)
{
	rg_step(r);
	cb_ready(r);
	rg_step(r);
}

static void bring_to_active(rg *r)
{
	bring_to_sync(r);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(r, 3));
	rg_step(r);
}

static unsigned count_ev(const rg *r, wr_ev_kind k)
{
	unsigned i, n = 0;

	for (i = 0; i < r->n_ev && i < MAXLOG; i++)
		if (r->ev[i].kind == k)
			n++;
	return n;
}

static const ev_rec *last_ev(const rg *r, wr_ev_kind k)
{
	unsigned i;

	for (i = r->n_ev < MAXLOG ? r->n_ev : MAXLOG; i > 0; i--)
		if (r->ev[i - 1].kind == k)
			return &r->ev[i - 1];
	return NULL;
}

/* ---- tests ------------------------------------------------------------------------------------------------- */

static void test_init(void)
{
	rg r;
	size_t n = 0, one = 0;
	wr_config cfg;
	wri_arena a;
	uint8_t small[64];

	/* sizes: queue slots of mon_msg_cap plus two renewal buffers, plain plan sum */
	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 4096;
	cfg.mapmsg_queue = 1;
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&cfg, &one));
	cfg.mapmsg_queue = 3;
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&cfg, &n));
	WRT_CHECK_U64(n - one, 2u * 4096u); /* every slot adds exactly mon_msg_cap */
	WRT_CHECK(one > 4096u + 2u * 2048u);
	cfg.mapmsg_queue = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(&cfg, &n));
	WRT_CHECK_U64(n, 0);
	cfg.mapmsg_queue = WRI_MON_MAXSLOTS + 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(&cfg, &n));
	cfg.mapmsg_queue = 1;
	cfg.mon_msg_cap = 10;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(&cfg, &n));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(&cfg, NULL));

	/* init takes exactly the planned bytes (aligned base), spec addresses become msgr2 addresses, port 0 -> 3300 */
	rg_init_cfg(&r, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&r.x.cfg, &n));
	r.bulk = (uint8_t *)malloc(n + WRI_ARENA_SLACK);
	wri_arena_init(&a, r.bulk, n);
	WRT_CHECK_STATUS(WR_OK, wri_mon_init(&r.m, &r.x, &a, &r.spec));
	WRT_CHECK_U64(a.used, n);
	WRT_CHECK_U64(r.m.n_addrs, 3);
	WRT_CHECK_U64(r.m.addrs[0].port, 3300);
	WRT_CHECK_U64(r.m.addrs[2].port, 3300);
	WRT_CHECK_U64(r.m.addrs[1].type, WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK_U64(r.m.addrs[1].ip[3], 11);
	WRT_CHECK_U64(r.m.st, WRI_MON_IDLE);
	WRT_CHECK_U64(r.m.conn_slot, WRI_MON_NO_SLOT);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 0); /* wants its first step at once */
	WRT_CHECK(!r.m.fsid_known);
	free(r.bulk);

	/* too little bulk: nothing partly initialised */
	wri_arena_init(&a, small, sizeof(small));
	WRT_CHECK_STATUS(WR_E_BUDGET, wri_mon_init(&r.m, &r.x, &a, &r.spec));
	WRT_CHECK_U64(r.m.n_addrs, 0);
	WRT_CHECK(r.m.slot[0].buf == NULL);
	/* no usable address */
	memset(&r.spec.mons, 0, sizeof(r.spec.mons));
	r.bulk = (uint8_t *)malloc(n + WRI_ARENA_SLACK);
	wri_arena_init(&a, r.bulk, n);
	WRT_CHECK_STATUS(WR_E_MON_NO_V2_ADDR, wri_mon_init(&r.m, &r.x, &a, &r.spec));
	/* argument checks */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_init(NULL, &r.x, &a, &r.spec));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_init(&r.m, NULL, &a, &r.spec));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_init(&r.m, &r.x, NULL, &r.spec));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_init(&r.m, &r.x, &a, NULL));
	free(r.bulk);
	/* a known fsid is kept */
	rg_init_cfg(&r, NULL);
	r.spec.fsid_known = 1;
	memset(r.spec.fsid, 0x5a, 16);
	rg_start(&r);
	WRT_CHECK(r.m.fsid_known && r.m.fsid[0] == 0x5a);
	rg_free(&r);
	/* the effective back-off bounds never allow a tight loop */
	{
		wr_config c2;

		wr_config_profile_harness(&c2);
		c2.hunt_backoff_min_ms = 0, c2.hunt_backoff_max_ms = 0;
		rg_init_cfg(&r, NULL);
		r.x.cfg = c2;
		rg_start(&r);
		WRT_CHECK(r.m.min_wait_ms >= WRI_MON_MIN_WAIT_MS && r.m.max_wait_ms >= r.m.min_wait_ms);
		rg_free(&r);
	}
}

/* Hunting order and the back-off sequence: every attempt fails at once, with a zero random source (no jitter). */
static void test_hunt_sequence(void)
{
	rg r;
	static const uint64_t want_wait[] = {500, 1000, 2000, 4000, 8000, 15000, 15000, 15000};
	uint64_t t0, expect;
	unsigned i;

	rg_init(&r, NULL);
	t0 = r.x.now.mono_ms;
	rg_step(&r);
	WRT_CHECK_U64(r.n_open, 1); /* the first attempt is immediate */
	WRT_CHECK_U64(r.open_at[0], t0);
	WRT_CHECK_U64(r.open_ip[0], 10);
	WRT_CHECK_U64(r.m.st, WRI_MON_CONNECTING);
	expect = t0;
	for (i = 0; i < 8; i++) {
		cb_closed(&r, WR_E_NET_CONNECT);
		rg_step(&r);
		WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
		WRT_CHECK_U64(wri_mon_deadline(&r.m), expect + want_wait[i]);
		rg_run(&r, expect + want_wait[i] - 1u);
		WRT_CHECK_U64(r.n_open, i + 1u); /* not before the wait is over */
		expect += want_wait[i];
		rg_run(&r, expect);
		WRT_CHECK_U64(r.n_open, i + 2u);
		WRT_CHECK_U64(r.open_at[i + 1u], expect);
		WRT_CHECK_U64(r.open_ip[i + 1u], 10 + ((i + 1u) % 3u)); /* ranks in order, wrapping */
	}
	/* no session ever came up: no DOWN; a round of three failures raises UNREACHABLE (two rounds in eight failures) */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(count_ev(&r, WR_EV_CLUSTER_UNREACHABLE), 2);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	{
		const ev_rec *e = last_ev(&r, WR_EV_CLUSTER_UNREACHABLE);

		WRT_CHECK(e != NULL && e->has_err);
		if (e != NULL) {
			WRT_CHECK_STATUS(WR_E_MON_UNREACHABLE, e->err.status);
			WRT_CHECK_U64(e->err.a0, 3);                 /* monitors in the round */
			WRT_CHECK_U64(e->err.a1, (uint64_t)-WR_E_NET_CONNECT); /* the last cause */
			WRT_CHECK_U64(e->err.module, WR_MOD_MON);
		}
	}
	/* the machine keeps trying: one more failure, one more wait, one more open */
	cb_closed(&r, WR_E_NET_CONNECT);
	rg_run(&r, r.x.now.mono_ms + 15000);
	WRT_CHECK_U64(r.n_open, 10);
	rg_free(&r);
}

/* A jitter only ever shortens the wait, never below the minimum, never above the base. */
static void test_hunt_jitter(void)
{
	rg r;
	unsigned i, bad = 0;
	uint8_t vals[] = {0x00, 0x01, 0x7f, 0xff, 0x55};
	uint32_t base = 500;

	rg_init(&r, NULL);
	rg_step(&r);
	for (i = 0; i < 12; i++) {
		uint64_t before = r.x.now.mono_ms, w;
		uint32_t lo = base - base / 4u;

		if (lo < 500u)
			lo = 500u;
		r.rng_byte = vals[i % sizeof(vals)];
		cb_closed(&r, WR_E_NET_CLOSED);
		rg_step(&r);
		w = wri_mon_deadline(&r.m) - before;
		if (w < lo || w > base)
			bad++;
		r.x.now.mono_ms = wri_mon_deadline(&r.m);
		rg_step(&r);
		base = base * 2u > 15000u ? 15000u : base * 2u;
	}
	WRT_CHECK_U64(bad, 0);
	rg_free(&r);
	/* no random source: no jitter, the plain base */
	rg_init(&r, NULL);
	r.rng_fail = 1;
	rg_step(&r);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 1500);
	rg_free(&r);
}

static void tweak_wide(wr_config *c)
{
	c->hunt_backoff_min_ms = 4000; /* a wide range so the jitter is visible */
	c->hunt_backoff_max_ms = 60000;
}

static void test_hunt_jitter_value(void)
{
	rg r;
	uint64_t w, t;

	rg_init(&r, tweak_wide);
	r.rng_byte = 0xff;
	rg_step(&r);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	w = wri_mon_deadline(&r.m) - 1000u;
	WRT_CHECK_U64(w, 4000u); /* the first wait is the minimum: the jitter only shortens, and never below the minimum */
	t = r.x.now.mono_ms = wri_mon_deadline(&r.m);
	rg_step(&r);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	w = wri_mon_deadline(&r.m) - t;
	/* base 8000, random 0xffffffff: jitter = 0xffffffff % (8000 / 4 + 1) */
	WRT_CHECK_U64(w, 8000u - (0xffffffffu % 2001u));
	WRT_CHECK(w >= 6000u && w <= 8000u);
	rg_free(&r);
}

/* No tight retry loop, whatever way the attempts fail: count the open calls per simulated minute. */
static void test_no_tight_loop(void)
{
	rg r;
	uint64_t t;

	/* (a) the connection fails after being opened */
	rg_init(&r, NULL);
	rg_step(&r);
	t = r.x.now.mono_ms;
	while (r.x.now.mono_ms < t + 60000u) {
		uint64_t d;

		rg_step(&r);
		if (r.m.st == WRI_MON_CONNECTING) {
			cb_closed(&r, WR_E_NET_CONNECT);
			rg_step(&r);
		}
		d = wri_mon_deadline(&r.m);
		r.x.now.mono_ms = d > t + 60000u ? t + 60000u : (d > r.x.now.mono_ms ? d : r.x.now.mono_ms + 1u);
	}
	WRT_CHECK(r.n_open_calls <= 10u);
	WRT_CHECK(r.n_open_calls >= 6u); /* and it does keep trying */
	rg_free(&r);

	/* (b) open() itself fails */
	rg_init(&r, NULL);
	r.open_st = WR_E_NET_CONNECT;
	t = r.x.now.mono_ms;
	rg_run(&r, t + 60000u);
	WRT_CHECK(r.n_open_calls <= 10u && r.n_open_calls >= 6u);
	WRT_CHECK_U64(r.n_open, 0);
	WRT_CHECK(count_ev(&r, WR_EV_CLUSTER_UNREACHABLE) >= 2u);
	rg_free(&r);

	/* (c) no connection slot free: retried at the minimum back-off, not counted as a failed monitor */
	rg_init(&r, NULL);
	r.busy_opens = 1000000;
	t = r.x.now.mono_ms;
	rg_run(&r, t + 60000u);
	WRT_CHECK(r.n_open_calls <= 125u && r.n_open_calls >= 100u);
	WRT_CHECK_U64(count_ev(&r, WR_EV_CLUSTER_UNREACHABLE), 0);
	/* the slot frees up: a session starts */
	r.busy_opens = 0;
	rg_run(&r, r.x.now.mono_ms + 600u);
	WRT_CHECK_U64(r.n_open, 1);
	rg_free(&r);

	/* (d) the same with the smallest configuration: the floor of the back-off */
	{
		wr_config c2;

		rg_init_cfg(&r, NULL);
		c2 = r.x.cfg;
		c2.hunt_backoff_min_ms = 0, c2.hunt_backoff_max_ms = 0;
		r.x.cfg = c2;
		rg_start(&r);
		r.open_st = WR_E_NET_CONNECT;
		t = r.x.now.mono_ms;
		rg_run(&r, t + 1000u);
		WRT_CHECK(r.n_open_calls <= 101u);
		rg_free(&r);
	}
}

static void check_sub_front(const uint8_t *f, uint32_t n, uint64_t mon_start, uint64_t osd_start, uint8_t osd_flags)
{
	uint8_t want[4 + 19 + 19 + 4];
	size_t mi = 4 + 19 + 19; /* offset of the monmap item in the vector: after config and mgrmap */

	WRT_CHECK(sub_vec_n >= 80u && sub_derived_n == 28u);
	/* the vector items are the independent bytes: name length, name, start, flags */
	WRT_CHECK(memcmp(sub_vec + mi + 4, "monmap", 6) == 0 && memcmp(sub_vec + mi + 19 + 4, "osdmap", 6) == 0);
	put32(want, 2);
	memcpy(want + 4, sub_vec + mi, 19);
	put64(want + 4 + 10, mon_start);
	want[4 + 18] = 0;
	memcpy(want + 23, sub_vec + mi + 19, 19);
	put64(want + 23 + 10, osd_start);
	want[23 + 18] = osd_flags;
	put32(want + 42, 0); /* host name left empty */
	WRT_CHECK_U64(n, sizeof(want));
	if (n == sizeof(want))
		WRT_CHECK_MEM(f, want, sizeof(want));
	/* the monmap item with start 0 is byte for byte the item of the derived vector of the note */
	if (mon_start == 0 && n >= 23u)
		WRT_CHECK_MEM(f + 4, sub_derived + 4, 19);
}

static int64_t jget_int(const wrt_json *j, wrt_tok t, const char *k)
{
	return wrt_json_int(j, wrt_json_get(j, t, k), NULL);
}

/* First messages of a session: MMonGetMap, then MMonSubscribe, header fields as in scenario-fresh-session. */
static void test_first_messages(void)
{
	rg r;
	wrt_tok conn, m0, m1, sub, it;
	uint64_t t;
	char *name0;

	rg_init(&r, NULL);
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 0); /* nothing is sent before READY */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 0);
	t = r.x.now.mono_ms;
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(r.sent[0].type, WRI_MSG_MON_GET_MAP);
	WRT_CHECK_U64(r.sent[0].flen, 0);
	WRT_CHECK_U64(r.sent[1].type, WRI_MSG_MON_SUBSCRIBE);
	WRT_CHECK_U64(r.sent[0].at, t);
	WRT_CHECK_U64(r.sent[0].slot, r.fc.slot);
	/* header fields against the scenario of the stock tool's second connection */
	conn = wrt_json_at(&scen_fresh, wrt_json_get(&scen_fresh, wrt_json_get(&scen_fresh, wrt_json_root(&scen_fresh), "expect"),
						      "connections"),
			   1);
	m0 = wrt_json_at(&scen_fresh, conn, 0);
	m1 = wrt_json_at(&scen_fresh, conn, 1);
	name0 = wrt_json_strdup(&scen_fresh, wrt_json_get(&scen_fresh, m0, "dir"));
	WRT_CHECK(name0 != NULL && strcmp(name0, "client->mon") == 0);
	free(name0);
	WRT_CHECK_U64(r.sent[0].type, jget_int(&scen_fresh, m0, "type"));
	WRT_CHECK_U64(r.sent[0].version, jget_int(&scen_fresh, m0, "version"));
	WRT_CHECK_U64(r.sent[0].compat, jget_int(&scen_fresh, m0, "compat"));
	WRT_CHECK_U64(r.sent[0].prio, jget_int(&scen_fresh, m0, "priority"));
	WRT_CHECK_U64(r.sent[1].type, jget_int(&scen_fresh, m1, "type"));
	WRT_CHECK_U64(r.sent[1].version, jget_int(&scen_fresh, m1, "version"));
	WRT_CHECK_U64(r.sent[1].compat, jget_int(&scen_fresh, m1, "compat"));
	WRT_CHECK_U64(r.sent[1].prio, jget_int(&scen_fresh, m1, "priority"));
	sub = wrt_json_get(&scen_fresh, m1, "subscribe");
	it = wrt_json_at(&scen_fresh, sub, 1); /* [monmap, 0, 0] (the stock tool also asks for config, which we do not) */
	{
		char *nm = wrt_json_strdup(&scen_fresh, wrt_json_at(&scen_fresh, it, 0));

		WRT_CHECK(nm != NULL && strcmp(nm, "monmap") == 0);
		free(nm);
		WRT_CHECK_U64(wrt_json_int(&scen_fresh, wrt_json_at(&scen_fresh, it, 1), NULL), 0);
	}
	/* exact bytes: monmap start 0 continuous, osdmap start 0 continuous, empty host name */
	check_sub_front(r.sent[1].front, r.sent[1].flen, 0, 0, 0);
	/* the event comes once both are out, with the monmap epoch 0 of a fresh client */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 1);
	WRT_CHECK_U64(r.ev[0].kind, WR_EV_MON_SESSION_UP);
	/* not ACTIVE before the first MonMap; no unsolicited traffic afterwards */
	rg_run(&r, t + 5000);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 3));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.m.monmap_epoch, 3);
	rg_free(&r);

	/* a full queue: GetMap is retried alone, the subscribe goes out after it, the order never changes */
	rg_init(&r, NULL);
	rg_step(&r);
	cb_ready(&r);
	r.send_busy = 1;
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 0);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK(wri_mon_deadline(&r.m) <= r.x.now.mono_ms + WRI_MON_RETRY_MS); /* a short retry, not a stall */
	r.x.now.mono_ms += WRI_MON_RETRY_MS;
	r.send_busy = 0;
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(r.sent[0].type, WRI_MSG_MON_GET_MAP);
	WRT_CHECK_U64(r.sent[1].type, WRI_MSG_MON_SUBSCRIBE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 1);
	rg_free(&r);

	/* a send that fails for good ends the session */
	rg_init(&r, NULL);
	rg_step(&r);
	cb_ready(&r);
	r.send_st = WR_E_STATE;
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_U64(r.n_close, 1);
	WRT_CHECK_STATUS(WR_E_STATE, r.m.err.status);
	rg_free(&r);
}

/* The maps arrive, are delivered raw, and a reconnect asks for held + 1 (scenario-monitor-restart). */
static void test_maps_and_reconnect(void)
{
	rg r;
	wr_mapmsg mm;
	uint64_t t;

	rg_init(&r, NULL);
	bring_to_active(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 1);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	rg_step(&r);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 2);
	WRT_CHECK_U64(r.m.sub_osdmap_start, 43);
	WRT_CHECK_U64(r.m.osdmap_have, 42);
	WRT_CHECK_U64(r.ev[r.n_ev - 1].epoch, 42);
	/* the consumer sees them in order, raw, with header version / compat and the newest epoch */
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	WRT_CHECK_U64(mm.newest_epoch, 3);
	WRT_CHECK_U64(mm.msg_version, 1);
	WRT_CHECK_U64(mm.msg_compat, 1);
	WRT_CHECK_U64(mm.front_len, monmap_front_n);
	WRT_CHECK_MEM(mm.front, monmap_front, monmap_front_n);
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	WRT_CHECK_U64(mm.newest_epoch, 42);
	WRT_CHECK_U64(mm.msg_version, 4);
	WRT_CHECK_U64(mm.msg_compat, 3);
	WRT_CHECK_U64(mm.front_len, osdmap_front_n);
	WRT_CHECK_MEM(mm.front, osdmap_front, osdmap_front_n);
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
	wri_mon_mapmsg_release(&r.m); /* nothing held: harmless */

	/* the monitor goes away: the session ends, hunting resumes after the minimum wait */
	r.n_sent = 0;
	t = r.x.now.mono_ms;
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_U64(r.n_close, 0); /* the connection reported it itself: nothing to close */
	WRT_CHECK_U64(r.m.n_addrs, 1); /* the monmap's single monitor replaced the three literal addresses */
	WRT_CHECK_U64(r.m.from_monmap, 1);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), t + 500);
	rg_run(&r, t + 500);
	WRT_CHECK_U64(r.n_open, 2);
	WRT_CHECK_U64(r.open_ip[1], 10); /* from the map: 10.77.0.10 */
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(r.sent[0].type, WRI_MSG_MON_GET_MAP);
	/* monmap held 3 -> start 4 (the vector item of the restart scenario), osdmap held 42 -> start 43, continuous */
	check_sub_front(r.sent[1].front, r.sent[1].flen, 4, 43, 0);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 2);
	{
		wrt_tok c = wrt_json_get(&scen_fresh, wrt_json_get(&scen_fresh, wrt_json_root(&scen_fresh), "expect"), "connections");

		(void)c;
	}
	/* one MonMap only this time (epoch 3 <= 3 would be a duplicate): ACTIVE all the same */
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 3));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.m.n_dup_monmap, 1);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm)); /* and nothing new for the consumer */
	rg_free(&r);

	/* a restart that bumped the monmap epoch: 4 arrives, is delivered, the next reconnect asks for 5 */
	rg_init(&r, NULL);
	bring_to_active(&r);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	rg_run(&r, r.x.now.mono_ms + 500);
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 4));
	rg_step(&r);
	WRT_CHECK_U64(r.m.monmap_epoch, 4);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 2);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	r.n_sent = 0;
	rg_run(&r, r.x.now.mono_ms + 1000);
	cb_ready(&r);
	rg_step(&r);
	check_sub_front(r.sent[1].front, r.sent[1].flen, 5, 0, 0);
	rg_free(&r);
}

/* The second MMonMap of a fresh session and older maps are ignored; a newer one is delivered. */
static void test_monmap_idempotent(void)
{
	rg r;
	wr_mapmsg mm;

	rg_init(&r, NULL);
	bring_to_active(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 3)); /* the second one of the pair */
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 2)); /* an older one */
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 1));
	rg_step(&r);
	WRT_CHECK_U64(r.m.n_dup_monmap, 3);
	WRT_CHECK_U64(r.m.monmap_epoch, 3);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 1); /* only the first was delivered */
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 4));
	rg_step(&r);
	WRT_CHECK_U64(r.m.monmap_epoch, 4);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.newest_epoch, 4);
	wri_mon_mapmsg_release(&r.m);
	/* the ignored copies did not hold a slot: all of them are free again */
	{
		unsigned i, free_n = 0;

		for (i = 0; i < r.m.nslots; i++)
			free_n += r.m.slot[i].kind == 0;
		WRT_CHECK_U64(free_n, r.m.nslots);
	}
	/* a MonMap with epoch 0 is the placeholder of a monitor that has no map: never applied */
	{
		unsigned bad = r.m.n_bad_msg;

		WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 0));
		WRT_CHECK_U64(r.m.n_bad_msg, bad + 1u);
		WRT_CHECK_U64(r.m.monmap_epoch, 4);
	}
	rg_free(&r);

	/* a first MonMap with epoch 0 does not make the session ACTIVE */
	rg_init(&r, NULL);
	bring_to_sync(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 0));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	/* a damaged MonMap neither */
	{
		uint8_t junk[40];

		memset(junk, 0x11, sizeof(junk));
		WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_MON_MAP, 1, 1, junk, sizeof(junk)));
		rg_step(&r);
		WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
		WRT_CHECK_U64(r.m.n_bad_msg, 2);
	}
	rg_free(&r);
}

static void tweak_q1(wr_config *c)
{
	c->mapmsg_queue = 1;
}

static void tweak_q2(wr_config *c)
{
	c->mapmsg_queue = 2;
}

/* All slots held: plan says busy (the connection stalls), a release lets the same message through. */
static void test_slot_backpressure(void)
{
	rg r;
	wr_mapmsg mm;
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t seglen[3] = {(uint32_t)osdmap_front_n, 0, 0};

	rg_init(&r, tweak_q1);
	bring_to_active(&r); /* the MonMap occupies the only slot */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 1);
	memset(&h, 0, sizeof(h));
	h.seq = 50, h.type = WRI_MSG_OSD_MAP, h.version = 4, h.compat_version = 3;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink)); /* asked again: still busy, nothing lost */
	WRT_CHECK(r.m.stalled);
	/* other message types are never held back by it */
	h.type = 62;
	WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK(sink[0].dst == NULL);
	/* the consumer peeks: still occupied (held), still busy */
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	h.type = WRI_MSG_OSD_MAP;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm)); /* idempotent until released */
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	WRT_CHECK(!r.m.stalled);
	rg_step(&r);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 2);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	wri_mon_mapmsg_release(&r.m);
	rg_free(&r);

	/* two slots: FIFO, and the held message stays valid while the second one arrives */
	rg_init(&r, tweak_q2);
	bring_to_active(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	rg_step(&r);
	{
		uint32_t in_use = 99, hi = 99;

		wri_mon_mapmsg_stats(&r.m, &in_use, &hi);
		WRT_CHECK_U64(in_use, 2);
		WRT_CHECK_U64(hi, 2);
		wri_mon_mapmsg_stats(&r.m, NULL, NULL);
		wri_mon_mapmsg_stats(NULL, &in_use, &hi);
	}
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	WRT_CHECK_MEM(mm.front, monmap_front, monmap_front_n);
	WRT_CHECK_STATUS(WR_E_BUSY, deliver_osdmap(&r)); /* both slots taken */
	WRT_CHECK_MEM(mm.front, monmap_front, monmap_front_n); /* the held bytes were not touched */
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	rg_step(&r);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP); /* the older of the two osdmaps first */
	wri_mon_mapmsg_release(&r.m);
	{
		uint32_t in_use = 99, hi = 99;

		wri_mon_mapmsg_stats(&r.m, &in_use, &hi);
		WRT_CHECK_U64(in_use, 1);
		WRT_CHECK_U64(hi, 2); /* the high-water mark stays */
	}
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
	rg_free(&r);

	/* a held slot survives the loss of the session; the keepalive timer does not run while we are the ones stalling */
	rg_init(&r, tweak_q1);
	bring_to_active(&r);
	WRT_CHECK_STATUS(WR_E_BUSY, deliver_osdmap(&r));
	WRT_CHECK(r.m.stalled);
	rg_run(&r, r.x.now.mono_ms + 120000u); /* four ack timeouts' worth, no ACK ever, but the connection is stalled */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK(r.n_ka >= 10u);
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_MONMAP);
	WRT_CHECK(!r.m.stalled);
	rg_free(&r);
}

static void tweak_small_cap(wr_config *c)
{
	c->mon_msg_cap = 4096;
}

/* A front above mon_msg_cap is discarded, counted, and the session carries on. */
static void test_oversize(void)
{
	rg r;
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t seglen[3];
	wr_mapmsg mm;
	uint8_t *junk;

	rg_init(&r, tweak_small_cap);
	bring_to_active(&r);
	wri_mon_mapmsg_release(&r.m);
	(void)wri_mon_mapmsg_peek(&r.m, &mm);
	wri_mon_mapmsg_release(&r.m);
	memset(&h, 0, sizeof(h));
	h.type = WRI_MSG_OSD_MAP, h.version = 4, h.compat_version = 3;
	seglen[0] = 4097, seglen[1] = seglen[2] = 0;
	memset(sink, 0xAB, sizeof(sink));
	WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK(sink[0].dst == NULL && sink[0].cap == 0);
	WRT_CHECK_U64(r.m.n_toobig, 1);
	/* the front of exactly mon_msg_cap is accepted (and is not a map: counted as damaged) */
	seglen[0] = 4096;
	WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK(sink[0].dst != NULL && sink[0].cap == 4096);
	junk = (uint8_t *)calloc(1, 4097);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, 3, junk, 4097)); /* too big through the full path */
	WRT_CHECK_U64(r.m.n_toobig, 2);
	free(junk);
	/* the session is untouched and the next map is delivered */
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.n_close, 0);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r)); /* 3200 bytes fit */
	rg_step(&r);
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(mm.kind, WR_MAPMSG_OSDMAP);
	wri_mon_mapmsg_release(&r.m);
	/* a connection that reports more stored bytes than the sink could hold is not believed */
	{
		uint32_t big[3] = {4097, 0, 0};
		unsigned bad = r.m.n_bad_msg;

		h.seq = 99;
		seglen[0] = 100;
		WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
		wri_mon_upper()->message(&r.m, &r.fc, &h, big);
		WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
		WRT_CHECK_U64(r.m.n_bad_msg, bad);
	}
	/* an empty front for a map is nothing to store */
	seglen[0] = 0;
	WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &r.fc, &h, seglen, sink));
	WRT_CHECK(sink[0].dst == NULL);
	rg_free(&r);
}

/* Other message types, a stale connection and a MAuthReply nobody asked for are all ignored. */
static void test_ignored_messages(void)
{
	rg r;
	uint8_t junk[64];
	wri_m2_conn other;
	wri_m2_hdr2 h;
	wri_m2_sink sink[3];
	uint32_t seglen[3] = {100, 0, 0};
	unsigned before;

	rg_init(&r, NULL);
	bring_to_active(&r);
	memset(junk, 0x77, sizeof(junk));
	before = r.m.n_ignored;
	WRT_CHECK_STATUS(WR_OK, deliver(&r, 62, 1, 1, junk, sizeof(junk)));                  /* MConfig */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_MON_SUBSCRIBE_ACK, 1, 1, junk, 8));    /* MMonSubscribeAck */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, 1796, 1, 1, junk, sizeof(junk)));                /* MgrMap push */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, junk, sizeof(junk))); /* no renewal pending */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, 2, 1, 1, junk, 0));                              /* MPing, empty */
	WRT_CHECK_U64(r.m.n_ignored, before + 5u);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.m.ar_len, 0);
	/* a connection that is not the monitor connection: plan discards, message / ready / closed do nothing */
	memset(&other, 0, sizeof(other));
	other.slot = (uint16_t)(r.fc.slot + 1u);
	memset(&h, 0, sizeof(h));
	h.type = WRI_MSG_OSD_MAP;
	WRT_CHECK_STATUS(WR_OK, wri_mon_upper()->plan(&r.m, &other, &h, seglen, sink));
	WRT_CHECK(sink[0].dst == NULL);
	{
		uint32_t stored[3] = {100, 0, 0};

		wri_mon_upper()->message(&r.m, &other, &h, stored);
	}
	{
		wr_errinfo e;

		memset(&e, 0, sizeof(e));
		e.status = WR_E_NET_CLOSED;
		wri_mon_upper()->closed(&r.m, &other, &e);
	}
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	/* bad arguments do not crash */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_upper()->plan(NULL, &r.fc, &h, seglen, sink));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_upper()->plan(&r.m, &r.fc, NULL, seglen, sink));
	wri_mon_upper()->message(NULL, &r.fc, &h, seglen);
	wri_mon_upper()->ready(&r.m, NULL);
	wri_mon_upper()->closed(NULL, &r.fc, NULL);
	rg_free(&r);
}

/* Keepalive: one KEEPALIVE2 every keepalive_ms, an ACK keeps the session, none for keepalive_timeout_ms ends it. */
static void test_keepalive(void)
{
	rg r;
	uint64_t t;
	unsigned i;

	rg_init(&r, NULL);
	r.x.now.wall_ms = 1794821231757ull; /* the stamp of the keepalive vector */
	bring_to_active(&r);
	t = r.x.now.mono_ms;
	rg_run(&r, t + 9999);
	WRT_CHECK_U64(r.n_ka, 0);
	rg_run(&r, t + 10000);
	WRT_CHECK_U64(r.n_ka, 1);
	WRT_CHECK_U64(r.ka_at[0], t + 10000);
	WRT_CHECK_U64(r.ka_sec, 1794821231u); /* the stamp is the wall clock: ms since the epoch split into s and ns */
	WRT_CHECK_U64(r.ka_nsec, 757000000u);
	/* answered in time, every time: pings stay 10 s apart and the session lives */
	for (i = 1; i <= 6; i++) {
		r.acks++;
		rg_run(&r, t + 10000u * (i + 1u) - 1u);
		WRT_CHECK_U64(r.n_ka, i);
		rg_run(&r, t + 10000u * (i + 1u));
		WRT_CHECK_U64(r.n_ka, i + 1u);
		WRT_CHECK_U64(r.ka_at[i], t + 10000u * (i + 1u));
	}
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	/* now the monitor goes quiet: the oldest unanswered ping is the one at t0; dead 30 s later, to the millisecond */
	t = r.ka_at[r.n_ka - 1u];
	rg_run(&r, t + 29999);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	WRT_CHECK(r.m.ping_out);
	WRT_CHECK_U64(r.m.ping_since_ms, t);
	rg_run(&r, t + 30000);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, last_ev(&r, WR_EV_MON_SESSION_DOWN)->err.status);
	WRT_CHECK_U64(r.n_close, 1); /* the connection is closed by us */
	WRT_CHECK_STATUS(WR_E_TIMEOUT, r.close_why);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_U64(r.m.conn_slot, WRI_MON_NO_SLOT);
	/* pings #1..#9 went out (every 10 s from the start); #10 was due at the very instant the session was declared dead */
	WRT_CHECK_U64(r.n_ka, 9);
	rg_free(&r);

	/* a full transmit queue delays the ping by a retry, not by a period */
	rg_init(&r, NULL);
	bring_to_active(&r);
	t = r.x.now.mono_ms;
	r.ka_busy = 1;
	rg_run(&r, t + 10000);
	WRT_CHECK_U64(r.n_ka, 0);
	rg_run(&r, t + 10000 + WRI_MON_RETRY_MS);
	WRT_CHECK_U64(r.n_ka, 1);
	rg_free(&r);

	/* a link without the keepalive hooks: no pings, no ack timeout */
	rg_init(&r, NULL);
	r.link.keepalive = NULL, r.link.keepalive_acks = NULL;
	bring_to_active(&r);
	rg_run(&r, r.x.now.mono_ms + 200000u);
	WRT_CHECK_U64(r.n_ka, 0);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK(wri_mon_deadline(&r.m) == WR_DEADLINE_NONE || wri_mon_deadline(&r.m) > r.x.now.mono_ms);
	rg_free(&r);
}

/* A session that never gets going: no READY, no monmap. */
static void test_guards(void)
{
	rg r;
	uint64_t t;

	/* the host never reports the connection: connect + handshake timeouts plus a second of grace */
	rg_init(&r, NULL);
	rg_step(&r);
	t = r.x.now.mono_ms;
	WRT_CHECK_U64(wri_mon_deadline(&r.m), t + 5000u + 8000u + 1000u);
	rg_run(&r, t + 14000u);
	WRT_CHECK_U64(r.n_close, 1);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, r.m.err.status);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	rg_free(&r);

	/* the same wait is not held against the monitor while the consumer has every slot and the connection stalls */
	rg_init(&r, tweak_q1);
	bring_to_active(&r); /* the MonMap holds the only slot */
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	rg_run(&r, r.x.now.mono_ms + 500);
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	WRT_CHECK_STATUS(WR_E_BUSY, deliver_monmap(&r, 4)); /* nowhere to put it */
	t = r.x.now.mono_ms;
	rg_run(&r, t + 120000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1); /* only the loss of the first session */
	wri_mon_mapmsg_release(&r.m); /* the consumer frees the slot (never peeked: peek, then release) */
	{
		wr_mapmsg mm;

		WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm));
		wri_mon_mapmsg_release(&r.m);
	}
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 4));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	rg_free(&r);

	/* authenticated, subscribed, but the monitor never sends a map: the keepalive ACKs alone do not keep it alive */
	rg_init(&r, NULL);
	bring_to_sync(&r);
	t = r.x.now.mono_ms;
	r.acks = 1;
	rg_run(&r, t + 29999);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	rg_run(&r, t + 30000);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1); /* it had been UP */
	WRT_CHECK_U64(wri_mon_deadline(&r.m), r.x.now.mono_ms + 500u); /* first failure of this process: base 500 */
	rg_free(&r);
}

/* A cephx refusal: AUTH_FAILED, no UNREACHABLE, growing waits, tickets forgotten, never a tight loop. */
static void test_auth_failed(void)
{
	rg r;
	static const wr_status causes[] = {WR_E_M2_BAD_METHOD, WR_E_AUTH_DENIED, WR_E_AUTH_DECRYPT, WR_E_AUTH_PROTO,
					   WR_E_AUTH_GID0, WR_E_AUTH_RESULT, WR_E_M2_SIGNATURE, WR_E_M2_MODE};
	unsigned i;
	uint64_t wait[3];
	wri_arena a;
	size_t n = 0;

	rg_init(&r, NULL);
	r.cxmem = (uint8_t *)malloc(64u * 1024u);
	wri_arena_init(&a, r.cxmem, 64u * 1024u);
	r.spec.key.type = WR_KEY_TYPE_AES256K, r.spec.key.len = 32;
	memset(r.spec.key.secret, 0x42, 32);
	strcpy(r.spec.user, "winrbd");
	r.x.cfg.ticket_cap = 2048;
	WRT_CHECK_STATUS(WR_OK, wri_cx_client_init(&r.cx, &r.x, &a, &r.spec));
	r.have_cx = 1;
	r.cx.global_id = 4100;
	r.cx.ticket[WRI_CX_SLOT_OSD].have = 1;
	r.cx.ticket[WRI_CX_SLOT_OSD].valid_until_ms = r.x.now.mono_ms + 100000u;
	(void)n;
	rg_step(&r);
	for (i = 0; i < 3; i++) {
		uint64_t t = r.x.now.mono_ms;

		cb_closed(&r, causes[i]);
		rg_step(&r);
		wait[i] = wri_mon_deadline(&r.m) - t;
		WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), i + 1u);
		WRT_CHECK_STATUS(causes[i], last_ev(&r, WR_EV_AUTH_FAILED)->err.status);
		WRT_CHECK_U64(wri_cx_have(&r.cx, WRI_CX_SERVICE_OSD, t), 0); /* forgotten: the next try is a clean login */
		WRT_CHECK_U64(r.cx.global_id, 0);
		rg_run(&r, wri_mon_deadline(&r.m));
		WRT_CHECK_U64(r.n_open, i + 2u);
	}
	WRT_CHECK_U64(wait[0], 500);
	WRT_CHECK_U64(wait[1], 1000);
	WRT_CHECK_U64(wait[2], 2000);
	WRT_CHECK_U64(count_ev(&r, WR_EV_CLUSTER_UNREACHABLE), 0); /* three refusals are no unreachable cluster */
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	/* the remaining causes are all classified the same way */
	for (i = 3; i < sizeof(causes) / sizeof(causes[0]); i++) {
		unsigned before = count_ev(&r, WR_EV_AUTH_FAILED);

		cb_closed(&r, causes[i]);
		rg_step(&r);
		WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), before + 1u);
		rg_run(&r, wri_mon_deadline(&r.m));
	}
	/* a refusal per minute at most: count the opens over a simulated minute of refusals */
	{
		uint64_t t0 = r.x.now.mono_ms;
		unsigned opens0 = r.n_open_calls;

		while (r.x.now.mono_ms < t0 + 60000u) {
			uint64_t d;

			rg_step(&r);
			if (r.m.st == WRI_MON_CONNECTING) {
				cb_closed(&r, WR_E_M2_BAD_METHOD);
				rg_step(&r);
			}
			d = wri_mon_deadline(&r.m);
			r.x.now.mono_ms = d > t0 + 60000u ? t0 + 60000u : (d > r.x.now.mono_ms ? d : r.x.now.mono_ms + 1u);
		}
		WRT_CHECK(r.n_open_calls - opens0 <= 6u);
	}
	/* not an auth failure: a plain loss of the connection leaves the tickets alone */
	rg_free(&r);
}

/* The cluster id: a wrong-cluster map is dropped; repeated, it ends the session with WR_E_MON_FSID. */
static void test_fsid(void)
{
	rg r;
	uint8_t *bad;
	unsigned i;
	wr_mapmsg mm;
	uint64_t t;

	rg_init_cfg(&r, NULL);
	r.spec.fsid_known = 1;
	{
		/* the fsid of the vector maps */
		static const uint8_t fsid[16] = {0x52, 0x76, 0x27, 0x25, 0xe1, 0x9a, 0x11, 0xf1, 0x88, 0x6d, 0x52, 0x54, 0x00, 0x77, 0x00, 0x01};

		memcpy(r.spec.fsid, fsid, 16);
	}
	rg_start(&r);
	bring_to_sync(&r);
	/* a MonMap of another cluster is dropped: not applied, not delivered, the session stays SYNC */
	bad = monmap_with(3, 1);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_MON_MAP, 1, 1, bad, (uint32_t)monmap_front_n));
	free(bad);
	rg_step(&r);
	WRT_CHECK_U64(r.m.n_fsid_drop, 1);
	WRT_CHECK_U64(r.m.st, WRI_MON_SYNC);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(r.m.monmap_epoch, 0);
	/* a good map in between resets the count */
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 3));
	rg_step(&r);
	WRT_CHECK_U64(r.m.fsid_bad, 0);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	/* an MOSDMap of another cluster: dropped, no slot, no subscription progress */
	bad = osdmap_with(1);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, 3, bad, (uint32_t)osdmap_front_n));
	rg_step(&r);
	WRT_CHECK_U64(r.m.n_fsid_drop, 2);
	WRT_CHECK_U64(r.m.sub_osdmap_start, 0);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 1);
	/* repeated: the third in a row ends the session */
	t = r.x.now.mono_ms;
	for (i = 0; i < WRI_MON_FSID_MAX - 1u; i++)
		WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, 3, bad, (uint32_t)osdmap_front_n));
	free(bad);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_MON_FSID, r.m.err.status);
	WRT_CHECK_STATUS(WR_E_MON_FSID, last_ev(&r, WR_EV_MON_SESSION_DOWN)->err.status);
	WRT_CHECK_U64(r.n_close, 1);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), t + 15000u); /* the wrong cluster waits the longest back-off */
	rg_free(&r);

	/* the fsid is learned from the first map when the spec has none */
	rg_init(&r, NULL);
	bring_to_sync(&r);
	WRT_CHECK(!r.m.fsid_known);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 3));
	WRT_CHECK(r.m.fsid_known && r.m.fsid[0] == 0x52);
	bad = osdmap_with(1);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, 3, bad, (uint32_t)osdmap_front_n));
	free(bad);
	WRT_CHECK_U64(r.m.n_fsid_drop, 1);
	rg_free(&r);
}

/* The consumer asks for another osdmap start. */
static void drain_slots(rg *r)
{
	wr_mapmsg mm;

	while (wri_mon_mapmsg_peek(&r->m, &mm))
		wri_mon_mapmsg_release(&r->m);
}

static void test_want_osdmap(void)
{
	rg r;

	rg_init(&r, NULL);
	bring_to_active(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	rg_step(&r);
	drain_slots(&r);
	r.n_sent = 0;
	wri_mon_want_osdmap(&r.m, 0); /* from scratch: the full map again must be delivered, not taken for a duplicate */
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 1);
	WRT_CHECK_U64(r.sent[0].type, WRI_MSG_MON_SUBSCRIBE);
	check_sub_front(r.sent[0].front, r.sent[0].flen, 4, 0, 0);
	WRT_CHECK_STATUS(WR_OK, deliver_osdmap(&r));
	rg_step(&r);
	WRT_CHECK_U64(r.m.sub_osdmap_start, 43);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 3);
	wri_mon_want_osdmap(&r.m, 17);
	WRT_CHECK_U64(r.m.osdmap_have, 16);
	r.n_sent = 0;
	rg_step(&r);
	check_sub_front(r.sent[0].front, r.sent[0].flen, 4, 17, 0);
	/* between sessions it only changes what the next session asks for */
	cb_closed(&r, WR_E_NET_CLOSED);
	rg_step(&r);
	wri_mon_want_osdmap(&r.m, 5);
	r.n_sent = 0;
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 0);
	rg_run(&r, r.x.now.mono_ms + 1000u);
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 2);
	check_sub_front(r.sent[1].front, r.sent[1].flen, 4, 5, 0);
	WRT_CHECK_U64(r.m.resub, 0);
	wri_mon_want_osdmap(NULL, 1); /* no crash */
	rg_free(&r);
}

/* Ticket renewal scheduling and the MAuth message, with a hand-made ticket store. */
static void renew_rig(rg *r, uint64_t renew_at_osd, uint64_t renew_at_auth)
{
	wri_arena a;
	wri_cx_ticket *t;

	rg_init_cfg(r, NULL);
	r->cxmem = (uint8_t *)malloc(64u * 1024u);
	wri_arena_init(&a, r->cxmem, 64u * 1024u);
	r->spec.key.type = WR_KEY_TYPE_AES256K, r->spec.key.len = 32;
	memset(r->spec.key.secret, 0x42, 32);
	strcpy(r->spec.user, "winrbd");
	WRT_CHECK_STATUS(WR_OK, wri_cx_client_init(&r->cx, &r->x, &a, &r->spec));
	r->have_cx = 1;
	r->cx.global_id = 4100;
	t = &r->cx.ticket[WRI_CX_SLOT_AUTH];
	t->have = 1, t->service = WRI_CX_SERVICE_AUTH, t->secret_id = 7;
	t->session_key.type = WR_KEY_TYPE_AES256K, t->session_key.len = 32;
	memset(t->session_key.secret, 0x33, 32);
	t->blob_len = 13u + 20u;
	t->blob[0] = 1, put64(t->blob + 1, 7), put32(t->blob + 9, 20);
	memset(t->blob + 13, 0xEE, 20);
	t->valid_until_ms = r->x.now.mono_ms + 3600u * 1000u * 72u;
	t->renew_at_ms = renew_at_auth;
	t = &r->cx.ticket[WRI_CX_SLOT_OSD];
	t->have = 1, t->service = WRI_CX_SERVICE_OSD, t->secret_id = 8;
	t->session_key.type = WR_KEY_TYPE_AES256K, t->session_key.len = 32;
	memset(t->session_key.secret, 0x44, 32);
	t->blob_len = 13u + 20u;
	t->blob[0] = 1, put64(t->blob + 1, 8), put32(t->blob + 9, 20);
	memset(t->blob + 13, 0xDD, 20);
	t->valid_until_ms = r->x.now.mono_ms + 60000u;
	t->renew_at_ms = renew_at_osd;
	rg_start(r);
}

/* The MAuthReply front with a given result and an opaque payload. */
static uint32_t authreply_front(uint8_t *out, uint32_t proto, int32_t result, uint64_t gid, const uint8_t *pl, uint32_t n)
{
	put32(out, proto);
	put32(out + 4, (uint32_t)result);
	put64(out + 8, gid);
	put32(out + 16, n);
	memcpy(out + 20, pl, n);
	put32(out + 20 + n, 0); /* result_msg "" */
	return 24u + n;
}

static uint32_t get32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t get64(const uint8_t *p)
{
	return (uint64_t)get32(p) | (uint64_t)get32(p + 4) << 32;
}

/* The MAuth front of the first renewal: the shape of vectors/monclient/mauth-renewal-scrubbed.json (paxos prefix 0 / -1 / 0,
 * protocol 2, payload = request header 0x0200 + authorizer for AUTH + ticket request v1, monmap_epoch 0), with our keys. */
static void check_mauth(const sent_msg *s)
{
	const uint8_t *f = s->front, *p;
	uint32_t plen, ct = 67u; /* type-2 ciphertext of the 27-byte authorizer item: 16 confounder + 27 + 24 MAC */
	uint8_t blob[33];

	WRT_CHECK_U64(get64(f), 0);
	WRT_CHECK(f[8] == 0xff && f[9] == 0xff);
	WRT_CHECK_U64(get64(f + 10), 0);
	WRT_CHECK_U64(get32(f + 18), 2);
	plen = get32(f + 22);
	WRT_CHECK_U64(s->flen, 26u + plen + 4u);
	WRT_CHECK_U64(plen, 2u + 1u + 8u + 4u + 33u + 4u + ct + 5u);
	if (s->flen != 26u + plen + 4u || plen != 2u + 1u + 8u + 4u + 33u + 4u + ct + 5u)
		return;
	WRT_CHECK_U64(get32(f + 26 + plen), 0); /* monmap_epoch 0 */
	p = f + 26;
	WRT_CHECK(p[0] == 0x00 && p[1] == 0x02); /* CEPHX_GET_PRINCIPAL_SESSION_KEY, 0x0200 */
	WRT_CHECK_U64(p[2], 1);                  /* authorizer version */
	WRT_CHECK_U64(get64(p + 3), 4100);       /* global id */
	WRT_CHECK_U64(get32(p + 11), WRI_CX_SERVICE_AUTH);
	blob[0] = 1, put64(blob + 1, 7), put32(blob + 9, 20), memset(blob + 13, 0xEE, 20);
	WRT_CHECK_MEM(p + 15, blob, 33); /* the held AUTH ticket blob, re-sent whole */
	WRT_CHECK_U64(get32(p + 48), ct);
	p += 52 + ct;
	WRT_CHECK_U64(p[0], 1);                  /* CephXServiceTicketRequest v1 */
	WRT_CHECK_U64(get32(p + 1), WRI_CX_SERVICE_OSD); /* keys wanted: want mask 0x24 without the AUTH bit */
}

#define H72 (3600u * 1000u * 72u)

/* A session that is ACTIVE with the OSD ticket due at `t0 + 45 s`, the AUTH ticket far in the future (or due, as given). */
static void renew_active(rg *r, uint64_t osd_at, uint64_t auth_at)
{
	renew_rig(r, osd_at, auth_at);
	r->link.keepalive = NULL, r->link.keepalive_acks = NULL; /* keep the keepalive out of these timings */
	bring_to_active(r);
}

static void renew_enter(rg *r)
{
	renew_active(r, 1000u + 45000u, 1000u + H72);
	rg_run(r, 1000u + 45000u);
	WRT_CHECK_U64(r->m.st, WRI_MON_RENEW);
}

static void test_renewal(void)
{
	rg r;
	uint8_t front[128], pl[8];
	uint32_t n;

	memset(pl, 0, sizeof(pl));
	/* the OSD ticket is due 45 s after login (renew_at = valid - validity / 4): the request goes out then, not before */
	renew_active(&r, 1000u + 45000u, 1000u + H72);
	rg_run(&r, 1000u + 44999u);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 1000u + 45000u);
	rg_run(&r, 1000u + 45000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_RENEW);
	WRT_CHECK_U64(r.n_sent, 3);
	WRT_CHECK_U64(r.sent[2].type, WRI_MSG_AUTH);
	WRT_CHECK_U64(r.sent[2].version, 1);
	WRT_CHECK_U64(r.sent[2].compat, 1);
	WRT_CHECK_U64(r.sent[2].prio, 127);
	WRT_CHECK_U64(r.sent[2].at, 1000u + 45000u);
	check_mauth(&r.sent[2]);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 1000u + 45000u + 30000u); /* the reply is awaited keepalive_timeout_ms */
	/* a reply for another request type arriving now is not a map and not a reply: only type 18 is taken */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, 62, 1, 1, pl, sizeof(pl)));
	WRT_CHECK_U64(r.m.ar_len, 0);
	/* nobody answers: a failed renewal after 30 s, the session is replaced by a new one; no auth failure */
	rg_run(&r, 1000u + 45000u + 29999u);
	WRT_CHECK_U64(r.m.st, WRI_MON_RENEW);
	rg_run(&r, 1000u + 45000u + 30000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_TIMEOUT, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(r.n_close, 1);
	WRT_CHECK_U64(r.cx.global_id, 4100); /* a timeout is no refusal: nothing is forgotten */
	rg_run(&r, r.x.now.mono_ms + 1000u);
	WRT_CHECK_U64(r.n_open, 2); /* and it opens the new session */
	rg_free(&r);

	/* the monitor refuses: -13 in the reply. AUTH_FAILED, tickets and global id forgotten (a clean login next time) */
	renew_enter(&r);
	n = authreply_front(front, 2, -13, 4100, pl, 0);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, n));
	WRT_CHECK_U64(r.m.ar_len, n);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_AUTH_RESULT, r.m.err.status);
	WRT_CHECK_U64(r.m.err.peer_result, (uint64_t)(int64_t)-13);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 1);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_U64(r.cx.global_id, 0);
	WRT_CHECK_U64(wri_cx_have(&r.cx, WRI_CX_SERVICE_AUTH, r.x.now.mono_ms), 0);
	WRT_CHECK_U64(r.n_close, 1);
	rg_free(&r);

	/* a reply with another global id: the session identity changed, an error (mon-client.md 3.8) */
	renew_enter(&r);
	n = authreply_front(front, 2, 0, 9999, pl, sizeof(pl));
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, n));
	rg_step(&r);
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, r.m.err.status);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	rg_free(&r);

	/* another auth method */
	renew_enter(&r);
	n = authreply_front(front, 1, 0, 4100, pl, sizeof(pl));
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, n));
	rg_step(&r);
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, r.m.err.status);
	rg_free(&r);

	/* a reply whose payload is not a renewal answer: refused by the cephx layer, tickets forgotten */
	renew_enter(&r);
	n = authreply_front(front, 2, 0, 4100, pl, sizeof(pl));
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, n));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK(r.m.err.status != WR_OK);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 1);
	WRT_CHECK_U64(r.cx.global_id, 0);
	rg_free(&r);

	/* a front too short to decode is no refusal: the session fails, the tickets stay */
	renew_enter(&r);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, 7));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_TRUNCATED, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(r.cx.global_id, 4100);
	rg_free(&r);

	/* a reply nobody asked for (no request pending) is not read at all */
	renew_active(&r, 1000u + 45000u, 1000u + H72);
	n = authreply_front(front, 2, -13, 4100, pl, 0);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, n));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.m.ar_len, 0);
	rg_free(&r);

	/* a full transmit queue: the request is retried a moment later, not given up */
	renew_active(&r, 1000u + 45000u, 1000u + H72);
	r.send_busy = 1;
	rg_run(&r, 1000u + 45000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.n_sent, 2);
	rg_run(&r, 1000u + 45000u + WRI_MON_RETRY_MS);
	WRT_CHECK_U64(r.m.st, WRI_MON_RENEW);
	WRT_CHECK_U64(r.n_sent, 3);
	rg_free(&r);

	/* a request that cannot be built (the AUTH ticket is gone): the renewal fails, a new login follows */
	renew_active(&r, 1000u + 45000u, 1000u + H72);
	r.cx.ticket[WRI_CX_SLOT_AUTH].have = 0;
	rg_run(&r, 1000u + 45000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, r.m.err.status);
	WRT_CHECK_U64(r.n_sent, 2);
	rg_free(&r);

	/* the AUTH ticket itself is due: no MAuth (it cannot renew itself in-session), a planned new session instead:
	 * not a failure, nothing forgotten, the minimum wait, the old connection closed */
	renew_active(&r, 1000u + H72, 1000u + 45000u);
	rg_run(&r, 1000u + 44999u);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	rg_run(&r, 1000u + 45000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(r.n_close, 1);
	WRT_CHECK_STATUS(WR_OK, r.close_why);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	WRT_CHECK_STATUS(WR_OK, last_ev(&r, WR_EV_MON_SESSION_DOWN)->err.status);
	WRT_CHECK(last_ev(&r, WR_EV_MON_SESSION_DOWN)->err.what != NULL);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(count_ev(&r, WR_EV_CLUSTER_UNREACHABLE), 0);
	WRT_CHECK_U64(r.cx.global_id, 4100); /* the reclaim needs both */
	WRT_CHECK_U64(r.cx.ticket[WRI_CX_SLOT_AUTH].have, 1);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 1000u + 45000u + 500u);
	rg_run(&r, 1000u + 45500u);
	WRT_CHECK_U64(r.n_open, 2);
	rg_free(&r);

	/* without a cephx machine (cx NULL) nothing is ever renewed and nothing breaks */
	rg_init(&r, NULL);
	r.link.keepalive = NULL, r.link.keepalive_acks = NULL;
	bring_to_active(&r);
	rg_run(&r, r.x.now.mono_ms + 3600u * 1000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.n_sent, 2);
	rg_free(&r);
}


/* ---- review regressions and error paths ------------------------------------------------------------------------- */

/* A wrong-cluster session ends with WR_E_MON_FSID; the NEXT session (another monitor, the right cluster) must work.
 * (The fsid failure flag used to survive the session and end every later one at its first step.) */
static void test_fsid_recovers(void)
{
	rg r;
	uint8_t *bad;
	unsigned i;
	uint64_t t;
	static const uint8_t fsid[16] = {0x52, 0x76, 0x27, 0x25, 0xe1, 0x9a, 0x11, 0xf1, 0x88, 0x6d, 0x52, 0x54, 0x00, 0x77, 0x00, 0x01};

	rg_init_cfg(&r, NULL);
	r.spec.fsid_known = 1;
	memcpy(r.spec.fsid, fsid, 16);
	rg_start(&r);
	bring_to_active(&r);
	bad = osdmap_with(1);
	for (i = 0; i < WRI_MON_FSID_MAX; i++)
		WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, 3, bad, (uint32_t)osdmap_front_n));
	free(bad);
	rg_step(&r);
	WRT_CHECK_STATUS(WR_E_MON_FSID, r.m.err.status);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_U64(r.m.fsid_fail, 0); /* per session */
	WRT_CHECK_U64(r.m.fsid_bad, 0);
	t = wri_mon_deadline(&r.m);
	rg_run(&r, t);
	WRT_CHECK_U64(r.n_open, 2);
	cb_ready(&r);
	rg_step(&r);
	WRT_CHECK_STATUS(WR_OK, deliver_monmap(&r, 4));
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.n_close, 1); /* nothing closed the new session */
	rg_free(&r);
}

/* A message whose compat_version is above what the decoder reads is refused like a damaged one (mon-client.md 2.1);
 * the highest compat we do read, and a higher header version with a readable compat, still go through. */
static void test_compat_gate(void)
{
	rg r;
	wr_mapmsg mm;
	uint8_t *f;

	rg_init(&r, NULL);
	bring_to_sync(&r);
	f = monmap_with(3, 0);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_MON_MAP, 2, 2, f, (uint32_t)monmap_front_n));
	WRT_CHECK_U64(r.m.n_bad_msg, 1);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, &mm));
	WRT_CHECK_U64(r.m.have_monmap, 0);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_MON_MAP, 2, 1, f, (uint32_t)monmap_front_n)); /* newer version, readable compat */
	WRT_CHECK_U64(r.m.n_bad_msg, 1);
	WRT_CHECK_U64(r.m.monmap_epoch, 3);
	free(f);
	/* MOSDMap */
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 5, WRI_MOSDMAP_MAX_VERSION + 1u, osdmap_front, (uint32_t)osdmap_front_n));
	WRT_CHECK_U64(r.m.n_bad_msg, 2);
	WRT_CHECK_U64(r.m.sub_osdmap_start, 0);
	WRT_CHECK_U64(r.m.osdmap_have, 0);
	rg_step(&r);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MAPMSG), 1); /* the MonMap only */
	WRT_CHECK(wri_mon_mapmsg_peek(&r.m, &mm) && mm.kind == WR_MAPMSG_MONMAP);
	wri_mon_mapmsg_release(&r.m);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_OSD_MAP, 4, WRI_MOSDMAP_MAX_VERSION, osdmap_front, (uint32_t)osdmap_front_n));
	WRT_CHECK_U64(r.m.n_bad_msg, 2);
	WRT_CHECK(r.m.osdmap_have != 0);
	rg_free(&r);
}

/* A MAuthReply that can never be read ends the renewal at once, with its own reason, not after the 30 s timeout. */
static void test_renewal_unreadable_reply(void)
{
	rg r;
	uint8_t front[128], pl[8];
	uint32_t n;

	memset(pl, 0, sizeof(pl));
	/* compat above what we read */
	renew_enter(&r);
	n = authreply_front(front, 2, 0, 4100, pl, sizeof(pl));
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 2, 2, front, n));
	WRT_CHECK_U64(r.m.ar_len, 0);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_MON_PROTO, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(r.cx.global_id, 4100); /* not a refusal: nothing forgotten */
	WRT_CHECK_U64(r.m.ar_err, WR_OK);    /* cleared with the session */
	WRT_CHECK_U64(r.x.now.mono_ms, 1000u + 45000u);
	rg_free(&r);
	/* an empty front */
	renew_enter(&r);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, 0));
	rg_step(&r);
	WRT_CHECK_STATUS(WR_E_MON_PROTO, r.m.err.status);
	rg_free(&r);
	/* above the renewal buffer: never copied (no sink), reported as too big */
	renew_enter(&r);
	WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, front, r.m.abuf_cap + 1u));
	WRT_CHECK_U64(r.m.ar_len, 0);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_MON_MSG_TOOBIG, r.m.err.status);
	rg_free(&r);
	/* exactly the buffer size is taken (and then fails in the cephx layer, not here) */
	renew_enter(&r);
	{
		uint8_t *big = (uint8_t *)calloc(1, r.m.abuf_cap);

		WRT_CHECK_STATUS(WR_OK, deliver(&r, WRI_MSG_AUTH_REPLY, 1, 1, big, r.m.abuf_cap));
		free(big);
	}
	WRT_CHECK_U64(r.m.ar_len, r.m.abuf_cap);
	WRT_CHECK_U64(r.m.ar_err, WR_OK);
	rg_free(&r);
}

/* The consumer's request for another start must not wait for an unrelated timer. */
static void test_want_wakes(void)
{
	rg r;

	rg_init(&r, NULL);
	r.link.keepalive = NULL, r.link.keepalive_acks = NULL;
	bring_to_active(&r);
	WRT_CHECK(wri_mon_deadline(&r.m) > r.x.now.mono_ms);
	wri_mon_want_osdmap(&r.m, 7);
	WRT_CHECK(wri_mon_deadline(&r.m) <= r.x.now.mono_ms);
	rg_step(&r);
	WRT_CHECK_U64(r.n_sent, 3);
	WRT_CHECK_U64(r.sent[2].type, WRI_MSG_MON_SUBSCRIBE);
	WRT_CHECK(wri_mon_deadline(&r.m) > r.x.now.mono_ms);
	rg_free(&r);
}

/* A clock that steps back must not make timers fire. */
static void test_clock_back(void)
{
	rg r;
	uint64_t t;

	rg_init(&r, NULL);
	bring_to_active(&r);
	t = r.x.now.mono_ms;
	rg_run(&r, t + 10000); /* one ping out, unanswered */
	WRT_CHECK_U64(r.n_ka, 1);
	r.x.now.mono_ms = t + 5000;
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 0);
	rg_free(&r);

	/* the same before the session counted as stable */
	rg_init(&r, NULL);
	bring_to_active(&r);
	t = r.x.now.mono_ms;
	r.x.now.mono_ms = t - 100;
	rg_step(&r);
	WRT_CHECK_U64(r.m.stable, 0);
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	rg_free(&r);
}

/* Failures of the link while the session sets up and runs. */
static void test_link_failures(void)
{
	rg r;

	/* MMonGetMap goes out, the subscription finds the queue full: retried a moment later; UP only after it left */
	rg_init(&r, NULL);
	r.send_pass = 1, r.send_busy = 1;
	bring_to_sync(&r);
	WRT_CHECK_U64(r.n_sent, 1);
	WRT_CHECK_U64(r.sent[0].type, WRI_MSG_MON_GET_MAP);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK_U64(wri_mon_deadline(&r.m), r.x.now.mono_ms + WRI_MON_RETRY_MS);
	rg_run(&r, r.x.now.mono_ms + WRI_MON_RETRY_MS);
	WRT_CHECK_U64(r.n_sent, 2);
	WRT_CHECK_U64(r.sent[1].type, WRI_MSG_MON_SUBSCRIBE);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 1);
	rg_free(&r);

	/* MMonGetMap cannot be sent at all: the session fails with that reason, no UP */
	rg_init(&r, NULL);
	r.send_st = WR_E_STATE;
	bring_to_sync(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_STATE, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 0);
	WRT_CHECK_U64(r.n_close, 1);
	rg_free(&r);

	/* MMonSubscribe cannot be sent: same */
	rg_init(&r, NULL);
	r.send_pass = 1, r.send_st = WR_E_TOOBIG;
	bring_to_sync(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_TOOBIG, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_UP), 0);
	rg_free(&r);

	/* a keepalive that cannot be sent ends the session with its reason */
	rg_init(&r, NULL);
	bring_to_active(&r);
	r.ka_st = WR_E_NET_CLOSED;
	rg_run(&r, r.x.now.mono_ms + 10000);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_MON_SESSION_DOWN), 1);
	rg_free(&r);

	/* a renewal request that cannot be sent: the session fails with that reason, tickets stay */
	renew_active(&r, 1000u + 45000u, 1000u + H72);
	r.send_st = WR_E_NET_CLOSED;
	rg_run(&r, 1000u + 45000u);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.m.err.status);
	WRT_CHECK_U64(count_ev(&r, WR_EV_AUTH_FAILED), 0);
	WRT_CHECK_U64(r.cx.global_id, 4100);
	rg_free(&r);
}

/* The connection says "closed" without an errinfo: still the end of the session, with a status. */
static void test_closed_without_error(void)
{
	rg r;

	rg_init(&r, NULL);
	bring_to_active(&r);
	wri_mon_upper()->closed(&r.m, &r.fc, NULL);
	rg_step(&r);
	WRT_CHECK_U64(r.m.st, WRI_MON_HUNT_WAIT);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.m.err.status);
	WRT_CHECK_U64(r.m.err.module, WR_MOD_MON);
	WRT_CHECK(r.m.err.what != NULL);
	WRT_CHECK_U64(r.n_close, 0); /* it reported itself closed: no close request */
	rg_free(&r);
}

/* The "again" cap: back-to-back renewal rounds stop at WRI_MON_RENEW_AGAIN_MAX and wait the minimum back-off. */
static void test_renewal_again_cap(void)
{
	rg r;
	uint64_t t = 1000u + 45000u;

	renew_active(&r, t, 1000u + H72);
	rg_run(&r, t - 1u);
	r.x.now.mono_ms = t;
	r.m.renew_rounds = WRI_MON_RENEW_AGAIN_MAX;
	wri_mon_renew_step(&r.x, &r.m, &r.cx, &r.link);
	WRT_CHECK_U64(r.n_sent, 2); /* held back */
	WRT_CHECK_U64(r.m.st, WRI_MON_ACTIVE);
	WRT_CHECK_U64(r.m.renew_rounds, 0);
	WRT_CHECK_U64(r.m.renew_hold_ms, t + r.m.min_wait_ms);
	rg_run(&r, t + r.m.min_wait_ms - 1u);
	WRT_CHECK_U64(r.n_sent, 2);
	rg_run(&r, t + r.m.min_wait_ms);
	WRT_CHECK_U64(r.n_sent, 3); /* then the next round goes out */
	WRT_CHECK_U64(r.m.st, WRI_MON_RENEW);
	rg_free(&r);
}

/* Small helpers and argument checks. */
static void test_helpers(void)
{
	rg r;
	uint32_t a = 5, b = 5;

	WRT_CHECK_U64(wri_mon_add_ms(5, 10), 15);
	WRT_CHECK_U64(wri_mon_add_ms(0, 0), 0);
	WRT_CHECK_U64(wri_mon_add_ms(WR_DEADLINE_NONE - 3u, 1), WR_DEADLINE_NONE - 2u);
	WRT_CHECK_U64(wri_mon_add_ms(WR_DEADLINE_NONE - 3u, 5), WR_DEADLINE_NONE - 1u); /* saturates below "none" */
	WRT_CHECK_U64(wri_mon_add_ms(WR_DEADLINE_NONE - 1u, 0), WR_DEADLINE_NONE - 1u);
	WRT_CHECK_U64(wri_mon_add_ms(WR_DEADLINE_NONE, 7), WR_DEADLINE_NONE - 1u);
	WRT_CHECK_U64(wri_mon_add_ms(3, WR_DEADLINE_NONE), WR_DEADLINE_NONE - 1u);
	WRT_CHECK_U64(wri_mon_add_ms(3, WR_DEADLINE_NONE - 1u), WR_DEADLINE_NONE - 1u);
	WRT_CHECK_U64(wri_mon_deadline(NULL), WR_DEADLINE_NONE);
	wri_mon_mapmsg_stats(NULL, &a, &b);
	WRT_CHECK_U64(a, 5); /* untouched */
	wri_mon_want_osdmap(NULL, 3);
	WRT_CHECK(!wri_mon_mapmsg_peek(NULL, NULL));
	wri_mon_mapmsg_release(NULL);
	rg_init(&r, NULL);
	WRT_CHECK(!wri_mon_mapmsg_peek(&r.m, NULL));
	wri_mon_mapmsg_stats(&r.m, NULL, NULL);
	wri_mon_mapmsg_release(&r.m); /* nothing peeked */
	WRT_CHECK_U64(wri_mon_deadline(&r.m), 0);
	/* step with an unusable link does nothing and does not crash */
	{
		wri_mon_link none;

		memset(&none, 0, sizeof(none));
		wri_mon_step(&r.x, &r.m, NULL, &none);
		wri_mon_step(&r.x, &r.m, NULL, NULL);
		wri_mon_step(NULL, &r.m, NULL, &r.link);
		wri_mon_step(&r.x, NULL, NULL, &r.link);
		WRT_CHECK_U64(r.m.st, WRI_MON_IDLE);
	}
	rg_free(&r);
}

/* init refuses a configuration or a bulk region it cannot serve, whatever the size, and leaves nothing behind. */
static void test_init_budget_sweep(void)
{
	rg r;
	wr_config cfg;
	size_t n = 0, sz;
	wri_arena a;
	uint8_t *mem;
	unsigned bad = 0;

	wr_config_profile_harness(&cfg);
	cfg.mon_msg_cap = 4096, cfg.mapmsg_queue = 2;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(NULL, &n));
	cfg.ticket_cap = (1u << 20) + 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_mon_bulk_mem(&cfg, &n));
	cfg.ticket_cap = 1u << 20;
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&cfg, &n));
	cfg.ticket_cap = 2048;
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&cfg, &n));
	rg_init_cfg(&r, NULL);
	r.x.cfg.mon_msg_cap = 4096, r.x.cfg.mapmsg_queue = 2, r.x.cfg.ticket_cap = 2048;
	WRT_CHECK_STATUS(WR_OK, wri_mon_bulk_mem(&r.x.cfg, &n));
	mem = (uint8_t *)malloc(n + WRI_ARENA_SLACK);
	/* every region size below the plan fails with WR_E_BUDGET (no slack: the plan sum is exact for an aligned base) */
	for (sz = 0; sz < n; sz += 509u) {
		wri_arena_init(&a, mem, sz);
		memset(&r.m, 0x77, sizeof(r.m));
		if (wri_mon_init(&r.m, &r.x, &a, &r.spec) != WR_E_BUDGET)
			bad++;
		else if (r.m.n_addrs != 0 || r.m.slot[0].buf != NULL || r.m.abuf != NULL)
			bad++;
	}
	/* one 16-byte unit short fails inside the last (renewal) buffer */
	wri_arena_init(&a, mem, n - 16u);
	WRT_CHECK_STATUS(WR_E_BUDGET, wri_mon_init(&r.m, &r.x, &a, &r.spec));
	WRT_CHECK_U64(bad, 0);
	free(mem);
	rg_free(&r);
}

int main(void)
{
	load_fixtures();
	test_init();
	test_hunt_sequence();
	test_hunt_jitter();
	test_hunt_jitter_value();
	test_no_tight_loop();
	test_first_messages();
	test_maps_and_reconnect();
	test_monmap_idempotent();
	test_slot_backpressure();
	test_oversize();
	test_ignored_messages();
	test_keepalive();
	test_guards();
	test_auth_failed();
	test_fsid();
	test_want_osdmap();
	test_renewal();
	test_fsid_recovers();
	test_compat_gate();
	test_renewal_unreadable_reply();
	test_want_wakes();
	test_clock_back();
	test_link_failures();
	test_closed_without_error();
	test_renewal_again_cap();
	test_helpers();
	test_init_budget_sweep();
	return wrt_finish();
}
