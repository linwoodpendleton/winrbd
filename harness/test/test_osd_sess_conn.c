/* SPDX-License-Identifier: MIT */
/*
 * test_osd_sess_conn.c - OSD sessions over real connections: the product's wri_m2_conn, its cephx machine (one wri_cx_hs per connection, a client that
 * logged in to sim_mon and holds an OSD ticket), sim_osd and an in-test byte pump (osd_sess_world.h). READY with the authorizer's challenge round trip,
 * the global id the OSD sees, a request and its reply, MOSDOp v9 / v8 by the feature word, a connection refused for missing features, a refused ticket
 * (cool-down and the errinfo the request layer sees), an unreachable OSD, a lost connection, an OSD restart, the handshake and ticket gates against the
 * real engine, and the number of connections under eviction churn.
 */
#include "osd_sess_world.h"

static world W;

static int start(unsigned n_osd, unsigned n_sess, unsigned key_type, void (*tweak)(world *))
{
	int rc = w_open_world(&W, n_osd, n_sess, 2048, 8, key_type);

	if (rc != 0) {
		fprintf(stderr, "w_open_world failed: %d\n", rc);
		WRT_CHECK(0);
		return -1;
	}
	if (tweak != NULL)
		tweak(&W);
	rc = w_start(&W);
	if (rc != 0) {
		fprintf(stderr, "w_start failed: %d\n", rc);
		WRT_CHECK(0);
		return -1;
	}
	return 0;
}

static void stop(void)
{
	w_free(&W);
}

static uint64_t rec_gid(unsigned osd)
{
	uint32_t n = 0;
	const sim_osd_rec *r = sim_osd_recs(W.osd[osd], &n);

	return n != 0 ? r[n - 1u].global_id : 0u;
}

static void test_ready_and_request(void)
{
	static const unsigned kt[2] = {WR_KEY_TYPE_AES, WR_KEY_TYPE_AES256K};
	unsigned k;

	for (k = 0; k < 2; k++) {
		uint32_t s;
		uint8_t data[300], got[512];
		uint32_t n_recs = 0;
		const sim_osd_rec *rec;
		unsigned i;

		if (start(2, 3, kt[k], NULL) != 0)
			return;
		for (i = 0; i < sizeof(data); i++)
			data[i] = (uint8_t)(i * 7u + 3u);
		WRT_CHECK_STATUS(WR_OK, sim_store_write(W.store, W_POOL, "obj.read", 0, data, sizeof(data)));
		s = w_get(&W, 0);
		WRT_CHECK(s != WRI_NIL);
		if (s == WRI_NIL) {
			stop();
			return;
		}
		WRT_CHECK(W.r.n_ready == 1u && W.r.ready_s[0] == s);
		WRT_CHECK(W.t.s[s].state == WRI_OS_READY && W.t.s[s].msg_version == WRI_MOSDOP_VERSION);
		/* the negotiated word is the server's supported bits and ours: all of the needed ones */
		WRT_CHECK((W.t.s[s].features & WRI_OSDFEAT_NEED) == WRI_OSDFEAT_NEED);
		WRT_CHECK(W.t.s[s].features == W.ec[W.t.s[s].conn_slot].c.features);
		/* the authorizer, its challenge round trip and the signature: one AUTH_REQUEST, one AUTH_REQUEST_MORE */
		{
			const sim_m2 *m2 = sim_osd_conn_m2(w_srv(&W, s));

			WRT_CHECK(m2->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST] == 1u);
			WRT_CHECK(m2->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST_MORE] == 1u);
			WRT_CHECK(m2->n_rx_by_tag[WRI_M2_TAG_AUTH_SIGNATURE] == 1u);
		}
		WRT_CHECK(W.ec[W.t.s[s].conn_slot].c.pa == NULL); /* the transcript is gone: the handshake slot is free again */
		WRT_CHECK(w_handshake_free(&W));
		/* a request and its reply, into the sink the "request layer" names for that tid */
		memset(got, 0xAB, sizeof(got));
		W.r.sink_tid = 0x10001;
		W.r.sink_dst = got;
		W.r.sink_cap = 256;
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, w_op(&W, s, 0x10001, "obj.read", WRI_OSD_OP_READ, 0, 256, NULL, 0));
		WRT_CHECK(W.r.n_reply == 1u && W.r.n_bad == 0u);
		WRT_CHECK(W.r.reply[0].tid == 0x10001u && W.r.reply[0].s == s && W.r.reply[0].stored == 256u);
		WRT_CHECK(W.r.reply[0].rep.result == 256 || W.r.reply[0].rep.result == 0);
		WRT_CHECK(W.r.reply[0].rep.n_ops == 1u && W.r.reply[0].rep.out_total == 256u);
		WRT_CHECK(memcmp(got, data, 256) == 0 && got[256] == 0xAB); /* and not a byte more */
		WRT_CHECK(W.t.s[s].rx_tid == 0u && W.t.s[s].replied && W.t.n_replies == 1u);
		rec = sim_osd_recs(W.osd[0], &n_recs);
		WRT_CHECK(n_recs == 1u && rec[0].version == 9u && rec[0].tid == 0x10001u);
		/* the OSD saw the monitor-assigned global id (cephx.md 3.3, msgr2.md 3.5) */
		WRT_CHECK(rec_gid(0) == W.e.c.global_id && W.e.c.global_id != 0u);
		/* a second OSD gets its own session and its own authorizer */
		{
			uint32_t s1 = w_get(&W, 1);

			WRT_CHECK(s1 != WRI_NIL && s1 != s);
			WRT_CHECK(W.t.s[s1].osd == 1 && W.t.hiwater == 2u);
		}
		stop();
	}
}

static void tweak_v8(world *w) { w->ocfg[0].v8_only = 1; }

static void test_v8(void)
{
	uint32_t s;
	uint8_t data[64], got[64];
	const sim_osd_rec *rec;
	uint32_t n = 0;

	if (start(1, 2, WR_KEY_TYPE_AES256K, tweak_v8) != 0)
		return;
	memset(data, 0x5C, sizeof(data));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(W.store, W_POOL, "o8", 0, data, sizeof(data)));
	s = w_get(&W, 0);
	WRT_CHECK(s != WRI_NIL);
	if (s != WRI_NIL) {
		/* a server without SERVER_SQUID: the session takes v8, still READY, and the request goes out as v8 */
		WRT_CHECK(W.t.s[s].msg_version == WRI_MOSDOP_VERSION_V8);
		WRT_CHECK((W.t.s[s].features & WRI_OSDFEAT_SQUID) != WRI_OSDFEAT_SQUID);
		W.r.sink_dst = got;
		W.r.sink_cap = sizeof(got);
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, w_op(&W, s, 0x20001, "o8", WRI_OSD_OP_READ, 0, 64, NULL, 0));
		rec = sim_osd_recs(W.osd[0], &n);
		WRT_CHECK(n == 1u && rec[0].version == 8u && sim_osd_n_violations(W.osd[0]) == 0u);
		WRT_CHECK(W.r.n_reply == 1u && memcmp(got, data, 64) == 0);
	}
	stop();
}

/* A server whose feature word lacks something the messages need: no session, a clear status, the missing bits. */
static uint64_t g_drop;
static void tweak_drop(world *w) { w->ocfg[0].m2.ident_supported = 0x3f07fffffffdffffull & ~g_drop; }

static void test_features_refused(void)
{
	static const uint64_t drops[] = {1ull << 8, 1ull << 9, 1ull << 21, 1ull << 56, 1ull << 58, 1ull << 57, (1ull << 9) | (1ull << 58)};
	unsigned i;

	for (i = 0; i < sizeof(drops) / sizeof(drops[0]); i++) {
		uint32_t s;
		wr_addr a;

		g_drop = drops[i];
		if (start(1, 2, WR_KEY_TYPE_AES256K, tweak_drop) != 0)
			return;
		a = W.addr[0];
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 0, &a, &s));
		(void)w_pump(&W);
		WRT_CHECK(!wri_osd_sess_ready(&W.t, s) && W.t.s[s].state == WRI_OS_COOLDOWN);
		WRT_CHECK(W.r.n_ready == 0u && W.r.n_lost == 1u && W.r.lost[0].st == WR_E_OSD_VERSION);
		/* what is missing: the bits the messages need that the server does not offer (the word it offers is a subset of ours) */
		WRT_CHECK(W.r.lost[0].a0 == (WRI_OSDFEAT_NEED & g_drop));
		WRT_CHECK(W.r.lost[0].a0 != 0u && (W.r.lost[0].a0 & ~WRI_OSDFEAT_NEED) == 0u);
		WRT_CHECK(w_live(&W) == 0u); /* the connection really went away */
		WRT_CHECK(W.t.s[s].cooldown_until_ms == W.e.x.now.mono_ms + 2000u);
		stop();
	}
}

static void tweak_refuse(world *w) { w->ocfg[0].fault.refuse_auth = 1; }

static void test_refused_ticket(void)
{
	uint32_t s, x = WRI_NIL;
	wr_addr a;
	uint64_t t0;

	if (start(1, 2, WR_KEY_TYPE_AES256K, tweak_refuse) != 0)
		return;
	a = W.addr[0];
	t0 = W.e.x.now.mono_ms;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 0, &a, &s));
	(void)w_pump(&W);
	/* AUTH_BAD_METHOD -13 after the round trip: the status and the server's masks reach the request layer as the cause of the stall */
	WRT_CHECK(W.t.s[s].state == WRI_OS_COOLDOWN && W.r.n_lost == 1u);
	WRT_CHECK(W.r.lost[0].st == WR_E_M2_BAD_METHOD);
	WRT_CHECK(W.r.lost[0].a0 == (1ull << 2)); /* the methods the OSD allows: cephx only */
	WRT_CHECK(W.t.s[s].err.status == WR_E_M2_BAD_METHOD && W.t.s[s].err.peer_result == -13);
	WRT_CHECK(W.t.s[s].fail_streak == 1u && W.t.s[s].cooldown_until_ms == t0 + 2000u);
	WRT_CHECK(sim_osd_n_requests(W.osd[0]) == 0u); /* no MOSDOp was ever sent */
	/* the operation waits: no new attempt until the cool-down has passed, then one per cool-down, growing */
	W.e.x.now.mono_ms = t0 + 1999u;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 0, &a, &x));
	WRT_CHECK(sim_osd_n_conns_accepted(W.osd[0]) == 1u);
	W.e.x.now.mono_ms = t0 + 2000u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 0, &a, &x));
	(void)w_pump(&W);
	WRT_CHECK(sim_osd_n_conns_accepted(W.osd[0]) == 2u && W.t.s[x].fail_streak == 2u);
	WRT_CHECK(W.t.s[x].cooldown_until_ms == t0 + 2000u + 4000u);
	/* the OSD accepts the key now (its caps were fixed): the next attempt reaches READY and a reply resets the streak */
	sim_osd_faults(W.osd[0])->refuse_auth = 0;
	W.e.x.now.mono_ms = t0 + 6000u;
	x = w_get(&W, 0);
	WRT_CHECK(x != WRI_NIL && W.t.s[x].fail_streak == 2u);
	{
		uint8_t buf[8];

		WRT_CHECK_STATUS(WR_OK, sim_store_write(W.store, W_POOL, "q", 0, (const uint8_t *)"abcdefgh", 8));
		W.r.sink_dst = buf;
		W.r.sink_cap = sizeof(buf);
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, w_op(&W, x, 5, "q", WRI_OSD_OP_READ, 0, 8, NULL, 0));
		WRT_CHECK(W.r.n_reply == 1u && W.t.s[x].fail_streak == 0u);
	}
	WRT_CHECK(w_live(&W) == 1u);
	stop();
}

static void test_unreachable_and_lost(void)
{
	uint32_t s, x = WRI_NIL;
	wr_addr a;
	uint64_t t0;

	if (start(2, 2, WR_KEY_TYPE_AES, NULL) != 0)
		return;
	/* connect refused: OPENING, then the host reports the failure, cool-down */
	W.osd_down[1] = 1;
	a = W.addr[1];
	t0 = W.e.x.now.mono_ms;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 1, &a, &s));
	WRT_CHECK(W.t.s[s].state == WRI_OS_OPENING);
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[s].state == WRI_OS_COOLDOWN && W.r.n_lost == 1u && W.r.lost[0].st != WR_OK);
	WRT_CHECK(W.t.s[s].cooldown_until_ms == t0 + 2000u && w_live(&W) == 0u);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 1, &a, &x));
	/* another OSD is unaffected */
	x = w_get(&W, 0);
	WRT_CHECK(x != WRI_NIL && x != s);
	/* the READY connection of OSD 0 is cut by the OSD (a restart): lost, the count of operations in flight is dropped with it */
	wri_osd_sess_inflight(&W.t, x, 3);
	sim_osd_restart(W.osd[0]);
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[x].state == WRI_OS_COOLDOWN && W.t.s[x].n_inflight == 0u && W.r.n_lost == 2u && W.r.lost[1].s == x);
	WRT_CHECK(w_live(&W) == 0u);
	/* the first failure of a healthy OSD: the base cool-down; the connection after it works */
	WRT_CHECK(W.t.s[x].cooldown_until_ms == W.e.x.now.mono_ms + 2000u);
	W.e.x.now.mono_ms += 2000u;
	x = w_get(&W, 0);
	WRT_CHECK(x != WRI_NIL);
	stop();
}

static void tweak_one_hs(world *w) { w->max_hs = 1; }

static void test_gates_real_engine(void)
{
	uint32_t s0, s1 = WRI_NIL;
	wr_addr a0, a1;

	if (start(3, 3, WR_KEY_TYPE_AES256K, tweak_one_hs) != 0)
		return;
	a0 = W.addr[0], a1 = W.addr[1];
	/* one handshake slot: the second authentication waits until the first has finished */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 0, &a0, &s0));
	WRT_CHECK(!w_handshake_free(&W));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 1, &a1, &s1));
	WRT_CHECK(sim_osd_n_conns_accepted(W.osd[1]) == 0u);
	(void)w_pump(&W);
	WRT_CHECK(wri_osd_sess_ready(&W.t, s0) && w_handshake_free(&W));
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 1, &a1, &s1));
	(void)w_pump(&W);
	WRT_CHECK(wri_osd_sess_ready(&W.t, s1));
	/* a held session needs no gate; a new one needs the ticket */
	W.ticket_off = 1;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 1, &a1, &s1));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 2, &W.addr[2], &s0));
	W.ticket_off = 0;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 2, &W.addr[2], &s0));
	/* an expired OSD ticket is the real thing the gate reads: now beyond its validity */
	(void)w_pump(&W);
	{
		uint64_t until = wri_cx_ticket_get(&W.e.c, WRI_CX_SERVICE_OSD)->valid_until_ms;

		W.e.x.now.mono_ms = until;
		WRT_CHECK(!w_have_ticket(&W));
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&W.t, 2, &W.addr[2], &s0)); /* held, whatever the ticket says */
		if (W.t.s[s0].state == WRI_OS_READY)
			wri_osd_sess_reset(&W.t, s0, NULL);
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 2, &W.addr[2], &s0));
	}
	stop();
}

static void test_churn_connection_limit(void)
{
	unsigned i, k;
	uint8_t buf[16];

	if (start(4, 2, WR_KEY_TYPE_AES256K, NULL) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, sim_store_write(W.store, W_POOL, "c", 0, (const uint8_t *)"0123456789abcdef", 16));
	W.r.sink_dst = buf;
	W.r.sink_cap = sizeof(buf);
	W.r.sink_n_ops = 1;
	for (i = 0; i < 24; i++) {
		uint32_t s;

		k = (i * 3u + i / 4u) % 4u;
		s = w_get(&W, k);
		WRT_CHECK(s != WRI_NIL);
		if (s == WRI_NIL)
			break;
		WRT_CHECK(W.t.s[s].osd == (int32_t)k);
		WRT_CHECK_STATUS(WR_OK, w_op(&W, s, 100u + i, "c", WRI_OSD_OP_READ, 0, 16, NULL, 0));
		WRT_CHECK(W.r.n_reply == i + 1u && W.r.reply[i].tid == 100u + i);
		WRT_CHECK(w_live(&W) <= 2u); /* after the pump: never more connections than osd_sessions */
		WRT_CHECK(W.t.hiwater <= 2u);
	}
	WRT_CHECK(W.t.n_evicted != 0u && W.live_max <= 3u); /* at most one closing connection beside the two sessions, within one acquire */
	printf("churn: %u opens, %u evictions, live max %u\n", W.t.n_opened, W.t.n_evicted, W.live_max);
	/* the idle reaper frees the connection too */
	W.e.x.cfg.osd_idle_ms = 3000;
	W.e.x.now.mono_ms += 3001;
	(void)wri_osd_sess_step(&W.t);
	(void)w_pump(&W);
	WRT_CHECK(w_live(&W) == 0u && W.t.n_idle_closed == 2u);
	WRT_CHECK(W.t.n_resets == 0u);
	stop();
}

int main(void)
{
	test_ready_and_request();
	test_v8();
	test_features_refused();
	test_refused_ticket();
	test_unreachable_and_lost();
	test_gates_real_engine();
	test_churn_connection_limit();
	return wrt_finish();
}
