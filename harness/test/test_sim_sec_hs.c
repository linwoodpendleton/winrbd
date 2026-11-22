/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the secure-mode peer of the fake monitor and the fake OSD, part 3: the whole handshake and a session in secure mode,
 * driven by a scripted client written from the notes (sim_sec_tc.h, sim_sec_cx.h: its own framing, CRC, SHA-256, HMAC and type 1
 * cipher; the cipher of key type 2 comes from the cephx cipher layer of the core, as it does for the simulators; no client machine
 * of the core is involved).
 *
 *   - the monitor, key type 1 and 2: AUTH_REQUEST with the offer, the challenge, CEPHX_GET_AUTH_SESSION_KEY, AUTH_DONE whose `cbl`
 *     carries the connection secret (64 bytes, sealed under the AUTH session key with usage 3), the signature frames in secure
 *     framing, CLIENT_IDENT / SERVER_IDENT, then MMonGetMap -> MMonMap in both modes (the same bytes), keepalives, a secret per
 *     connection, all of them recorded and different;
 *   - the OSD: the ticket from the monitor, the authorizer and its challenge round trip, AUTH_DONE with the sealed
 *     CephXAuthorizeReply (version 2 with the secret in secure mode, version 1 and no secret in crc mode), the session;
 *   - delivery one byte at a time in both directions, for a monitor and an OSD connection;
 *   - what the hooks put on the wire: no secret in secure mode (empty `cbl`, a version 1 reply), a secret in crc mode, secrets of 39 /
 *     40 / 128 bytes; a monitor and an OSD that allow only one mode, with the allowed list in the refusal.
 */
#include "sim_sec_cx.h"

static void mon_cfg(sim_mon_cfg *c, unsigned type)
{
	tkey k;

	tc_key(&k, type, 1);
	sim_mon_cfg_default(c);
	WRT_CHECK(wr_key_from_raw(&c->key, type, k.s, k.len) == WR_OK);
}

typedef struct sess {
	stc c;
	tlogin L;
	sim_mon_conn *mc;
	sim_osd_conn *oc;
	sim_osd *osd;
} sess;

/* A monitor connection up to a finished handshake (or as far as it gets). Returns tc_finish's verdict. */
static int mon_session(sim_mon *m, sess *s, const tkey *key, const uint32_t *offer, unsigned n, uint32_t other, size_t chunk)
{
	memset(s, 0, sizeof(*s));
	s->mc = sim_mon_accept(m);
	WRT_CHECK(s->mc != NULL);
	if (s->mc == NULL)
		exit(1);
	stc_init_mon(&s->c, s->mc);
	s->c.chunk = chunk;
	s->c.dchunk = chunk;
	if (!tc_mon_login(&s->c, key, "winrbd", offer, n, other, &s->L))
		return 0;
	return tc_finish(&s->c, &s->L, 1);
}

static void sess_free(sess *s)
{
	stc_free(&s->c);
	if (s->mc != NULL)
		sim_mon_conn_free(s->mc);
	if (s->oc != NULL)
		sim_osd_conn_free(s->oc);
}

/* MMonGetMap: the reply is an MMonMap (type 4) whose front is the monitor's monmap. Returns the front length; copies it to out. */
static uint32_t get_monmap(sess *s, uint8_t *out, uint32_t cap)
{
	static const uint8_t front[8] = {1, 0, 0, 0, 0, 0, 0, 0};

	WRT_CHECK(stc_send_msg(&s->c, 5, 1, front, sizeof(front), NULL, 0, NULL, 0) == 0);
	WRT_CHECK(stc_recv(&s->c) == 1 && s->c.tag == 17 && s->c.nseg == 2);
	WRT_CHECK_U64(ld32le(s->c.seg[0].p + 16) & 0xffff, 4); /* header: type 4 = MMonMap */
	if (s->c.len[1] > cap)
		return 0;
	memcpy(out, s->c.seg[1].p, s->c.len[1]);
	return s->c.len[1];
}

static void keepalive(sess *s)
{
	uint8_t stamp[8] = {9, 8, 7, 6, 5, 4, 3, 2};

	WRT_CHECK(stc_send1(&s->c, 18, stamp, 8) == 0);
	WRT_CHECK(stc_recv(&s->c) == 1 && s->c.tag == 19 && s->c.len[0] == 8);
	if (s->c.len[0] == 8)
		WRT_CHECK_MEM(s->c.seg[0].p, stamp, 8);
}

/* ---- the monitor ------------------------------------------------------------------------------------------------------------- */

static void test_monitor(void)
{
	static const uint32_t o_stock[] = {2, 1}, o_crc[] = {1}, o_sec[] = {2}, o_cs[] = {1, 2};
	static const struct {
		const uint32_t *v;
		unsigned n;
		uint32_t want;
	} offers[] = {{o_stock, 2, 2}, {o_crc, 1, 1}, {o_sec, 1, 2}, {o_cs, 2, 1}};
	unsigned type, i, nsec = 0;

	for (type = 1; type <= 2; type++) {
		sim_mon_cfg cfg;
		sim_mon *m;
		tkey key;
		uint8_t crc_map[4096], map[4096];
		uint32_t crc_len = 0;
		unsigned nsec_t = 0; /* secure connections of this monitor */

		mon_cfg(&cfg, type);
		m = sim_mon_new(&cfg);
		WRT_CHECK(m != NULL);
		if (m == NULL)
			return;
		tc_key(&key, type, 1);
		for (i = 0; i < sizeof(offers) / sizeof(offers[0]); i++) {
			sess s;
			uint32_t len;
			int ok = mon_session(m, &s, &key, offers[i].v, offers[i].n, 0x24, 0);

			WRT_CHECK(ok == 1);
			WRT_CHECK_U64(s.L.mode, offers[i].want);
			WRT_CHECK_U64(s.L.ntickets, 1); /* the OSD ticket of `extra` */
			if (s.L.ntickets == 1)
				WRT_CHECK_U64(s.L.tickets[0].service, WRI_CX_SERVICE_OSD);
			WRT_CHECK_U64(sim_m2_is_secure(s.mc->m2), offers[i].want == 2);
			WRT_CHECK_U64(s.c.secure, offers[i].want == 2);
			if (offers[i].want == 2) {
				const sim_sec_log *lg = sim_mon_secrets(m);

				WRT_CHECK(s.L.have_secret && s.L.secret_len == 64);
				WRT_CHECK_U64(lg->n, nsec_t + 1u);
				WRT_CHECK(sim_sec_log_has(lg, s.L.secret, s.L.secret_len)); /* the one the client opened is the one issued */
				WRT_CHECK_MEM(s.mc->m2->sec.secret, s.L.secret, 64);
				nsec_t++;
				nsec++;
			} else {
				WRT_CHECK(!s.L.have_secret && s.L.secret_len == 0); /* an encrypted EMPTY string in crc mode */
				WRT_CHECK_U64(sim_mon_secrets(m)->n, nsec_t);
			}
			len = get_monmap(&s, map, sizeof(map));
			WRT_CHECK(len > 16);
			if (offers[i].want == 1 && crc_len == 0) {
				memcpy(crc_map, map, len);
				crc_len = len;
			} else if (crc_len != 0) { /* the same bytes in either mode */
				WRT_CHECK_U64(len, crc_len);
				WRT_CHECK_MEM(map, crc_map, crc_len < len ? crc_len : len);
			}
			keepalive(&s);
			WRT_CHECK_STATUS(WR_OK, sim_mon_send_message(s.mc, 4, 1, 1, map, len)); /* an unsolicited push */
			WRT_CHECK(stc_recv(&s.c) == 1 && s.c.tag == 17 && s.c.len[1] == len);
			WRT_CHECK_U64(sim_m2_error(s.mc->m2)->status, 0);
			sess_free(&s);
		}
		/* every secure connection got a secret of its own */
		WRT_CHECK_U64(sim_mon_secrets(m)->n, 2);
		WRT_CHECK(sim_sec_log_distinct(sim_mon_secrets(m)));
		sim_mon_free(m);
	}
	WRT_CHECK_U64(nsec, 4);
}

/* A stock monitor allows both; one that allows one mode says so in the refusal, in its order, with -95. */
static void test_monitor_modes(void)
{
	static const uint32_t o_crc[] = {1}, o_sec[] = {2}, o_sc[] = {2, 1};
	unsigned i;
	static const struct {
		uint32_t allowed[2];
		unsigned n;
		const uint32_t *offer;
		unsigned noffer;
		uint32_t want; /* 0 = refused */
	} t[] = {
		{{2, 0}, 1, o_crc, 1, 0}, {{2, 0}, 1, o_sec, 1, 2}, {{2, 0}, 1, o_sc, 2, 2},
		{{1, 0}, 1, o_sec, 1, 0}, {{1, 0}, 1, o_crc, 1, 1}, {{1, 0}, 1, o_sc, 2, 1},
		{{2, 1}, 2, o_crc, 1, 1}, {{2, 1}, 2, o_sec, 1, 2},
	};

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		sim_mon_cfg cfg;
		sim_mon *m;
		sess s;
		tkey key;
		unsigned k;
		int ok;

		mon_cfg(&cfg, 2);
		cfg.m2.n_modes = t[i].n;
		for (k = 0; k < t[i].n; k++)
			cfg.m2.modes[k] = t[i].allowed[k];
		m = sim_mon_new(&cfg);
		WRT_CHECK(m != NULL);
		tc_key(&key, 2, 1);
		ok = mon_session(m, &s, &key, t[i].offer, t[i].noffer, 0x24, 0);
		if (t[i].want == 0) {
			WRT_CHECK(!ok && s.L.outcome == TL_BAD_METHOD);
			WRT_CHECK_U64(s.L.bm_result, -95);
			WRT_CHECK_U64(s.L.bm_nmodes, t[i].n);
			for (k = 0; k < t[i].n; k++)
				WRT_CHECK_U64(s.L.bm_modes[k], t[i].allowed[k]);
			WRT_CHECK_U64(sim_mon_secrets(m)->n, 0);
			WRT_CHECK_U64(m->n_logins, 0); /* refused before any cephx step: no challenge */
		} else {
			WRT_CHECK(ok == 1 && s.L.mode == t[i].want);
		}
		sess_free(&s);
		sim_mon_free(m);
	}
}

/* ---- the OSD ------------------------------------------------------------------------------------------------------------------ */

/* An OSD that allows both modes, like a stock one (the simulator's default is crc only, as it always was). */
static void osd_cfg_both(sim_osd_cfg *c)
{
	sim_osd_cfg_default(c);
	c->m2.n_modes = 2;
	c->m2.modes[0] = SIM_M2_MODE_CRC;
	c->m2.modes[1] = SIM_M2_MODE_SECURE;
}

typedef struct osdw {
	sim_mon *mon;
	sim_store *store;
	sim_osd *osd;
	tkey key;
	tticket ticket;
	uint64_t gid;
} osdw;

static void osd_world(osdw *w, unsigned type, const sim_osd_cfg *tweak)
{
	sim_mon_cfg mc;
	sim_osd_cfg oc;
	sess s;
	static const uint32_t crc[] = {1};

	memset(w, 0, sizeof(*w));
	mon_cfg(&mc, type);
	w->mon = sim_mon_new(&mc);
	w->store = sim_store_new();
	WRT_CHECK(w->mon != NULL && w->store != NULL);
	if (tweak != NULL)
		oc = *tweak;
	else
		osd_cfg_both(&oc);
	oc.mon = w->mon;
	oc.store = w->store;
	w->osd = sim_osd_new(&oc);
	WRT_CHECK(w->osd != NULL);
	tc_key(&w->key, type, 1);
	/* the OSD ticket comes from a monitor login (crc: the ticket is what is wanted here) */
	WRT_CHECK(mon_session(w->mon, &s, &w->key, crc, 1, 0x24, 0) == 1);
	WRT_CHECK(s.L.ntickets == 1 && s.L.tickets[0].service == WRI_CX_SERVICE_OSD);
	w->ticket = s.L.tickets[0];
	w->gid = s.L.gid;
	sess_free(&s);
}

static void osd_free(osdw *w)
{
	sim_osd_free(w->osd);
	sim_store_free(w->store);
	sim_mon_free(w->mon);
}

static int osd_session(osdw *w, sess *s, const uint32_t *offer, unsigned n, size_t chunk)
{
	memset(s, 0, sizeof(*s));
	s->osd = w->osd;
	s->oc = sim_osd_accept(w->osd);
	WRT_CHECK(s->oc != NULL);
	if (s->oc == NULL)
		exit(1);
	stc_init_osd(&s->c, s->oc);
	s->c.chunk = chunk;
	s->c.dchunk = chunk;
	if (!tc_osd_login(&s->c, &w->ticket, w->gid, offer, n, &s->L)) {
		if (getenv("SIMSEC_DEBUG") != NULL)
			fprintf(stderr, "osd login: outcome %d (%s)\n", s->L.outcome, s->L.err != NULL ? s->L.err : "-");
		return 0;
	}
	return tc_finish(&s->c, &s->L, 1);
}

static void osd_traffic(sess *s)
{
	static const uint8_t front[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	uint32_t before = sim_osd_n_other(s->osd);

	keepalive(s);
	WRT_CHECK(stc_send_msg(&s->c, 999, 5, front, sizeof(front), NULL, 0, NULL, 0) == 0);
	WRT_CHECK_U64(sim_osd_n_other(s->osd), before + 1u); /* a message of another type: counted and ignored */
	/* an OSD-initiated message (an MOSDMap push, type 41) arrives whole in whatever framing the connection has */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_map_push(s->oc, front, sizeof(front)));
	WRT_CHECK(stc_recv(&s->c) == 1 && s->c.tag == 17 && s->c.nseg == 2 && s->c.len[1] == sizeof(front));
	if (s->c.len[1] == sizeof(front))
		WRT_CHECK_MEM(s->c.seg[1].p, front, sizeof(front));
	WRT_CHECK_U64(ld32le(s->c.seg[0].p + 16) & 0xffff, 41);
	WRT_CHECK_U64(sim_m2_error(sim_osd_conn_m2(s->oc))->status, 0);
}

static void test_osd(void)
{
	static const uint32_t o_stock[] = {1, 2}, o_sec[] = {2}, o_sc[] = {2, 1}, o_crc[] = {1};
	static const struct {
		const uint32_t *v;
		unsigned n;
		uint32_t want;
	} offers[] = {{o_stock, 2, 1}, {o_sec, 1, 2}, {o_sc, 2, 2}, {o_crc, 1, 1}};
	unsigned type, i, nsec = 0;

	for (type = 1; type <= 2; type++) {
		osdw w;
		unsigned nsec_t = 0;

		osd_world(&w, type, NULL);
		for (i = 0; i < sizeof(offers) / sizeof(offers[0]); i++) {
			sess s;
			int ok = osd_session(&w, &s, offers[i].v, offers[i].n, 0);

			WRT_CHECK(ok == 1);
			WRT_CHECK_U64(s.L.mode, offers[i].want);
			WRT_CHECK_U64(s.L.reply_version, offers[i].want == 2 ? 2 : 1); /* CephXAuthorizeReply v2 only with a secret */
			WRT_CHECK_U64(sim_m2_is_secure(sim_osd_conn_m2(s.oc)), offers[i].want == 2);
			if (offers[i].want == 2) {
				WRT_CHECK(s.L.have_secret && s.L.secret_len == 64);
				WRT_CHECK(sim_sec_log_has(sim_osd_secrets(w.osd), s.L.secret, 64));
				nsec++;
				nsec_t++;
				WRT_CHECK_U64(sim_osd_secrets(w.osd)->n, nsec_t);
			} else {
				WRT_CHECK(!s.L.have_secret);
			}
			osd_traffic(&s);
			sess_free(&s);
		}
		WRT_CHECK(sim_sec_log_distinct(sim_osd_secrets(w.osd)));
		osd_free(&w);
	}
	WRT_CHECK_U64(nsec, 4);
}

/* An OSD that allows one mode: the refusal comes after the cephx round trip is not needed, it is the first answer. */
static void test_osd_modes(void)
{
	static const uint32_t o_crc[] = {1}, o_sec[] = {2};
	sim_osd_cfg oc;
	osdw w;
	sess s;

	sim_osd_cfg_default(&oc);
	oc.m2.n_modes = 1;
	oc.m2.modes[0] = 2;
	osd_world(&w, 1, &oc);
	WRT_CHECK(osd_session(&w, &s, o_crc, 1, 0) == 0);
	WRT_CHECK_U64(s.L.outcome, TL_BAD_METHOD);
	WRT_CHECK_U64(s.L.bm_result, -95);
	WRT_CHECK(s.L.bm_nmodes == 1 && s.L.bm_modes[0] == 2);
	sess_free(&s);
	WRT_CHECK(osd_session(&w, &s, o_sec, 1, 0) == 1);
	WRT_CHECK_U64(s.L.mode, 2);
	osd_traffic(&s);
	sess_free(&s);
	osd_free(&w);
}

/* ---- one byte at a time ----------------------------------------------------------------------------------------------------------- */

static void test_one_byte(void)
{
	static const uint32_t sec[] = {2}, stock[] = {1, 2};
	sim_mon_cfg cfg;
	sim_mon *m;
	tkey key;
	sess s;
	uint8_t map[4096];
	osdw w;

	/* the client feeds one byte per call and reads one byte per call; the monitor also delivers one byte per drain */
	mon_cfg(&cfg, 2);
	cfg.m2.f.out_chunk = 1;
	m = sim_mon_new(&cfg);
	tc_key(&key, 2, 1);
	WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 1) == 1);
	WRT_CHECK_U64(s.L.mode, 2);
	WRT_CHECK_U64(sim_m2_is_secure(s.mc->m2), 1);
	WRT_CHECK(get_monmap(&s, map, sizeof(map)) > 16);
	keepalive(&s);
	sess_free(&s);
	sim_mon_free(m);

	/* the same for an OSD, in secure mode and, for contrast, crc */
	{
		sim_osd_cfg oc;

		osd_cfg_both(&oc);
		oc.m2.f.out_chunk = 1;
		osd_world(&w, 1, &oc);
		WRT_CHECK(osd_session(&w, &s, sec, 1, 1) == 1);
		WRT_CHECK_U64(s.L.mode, 2);
		osd_traffic(&s);
		sess_free(&s);
		WRT_CHECK(osd_session(&w, &s, stock, 2, 1) == 1);
		WRT_CHECK_U64(s.L.mode, 1);
		osd_traffic(&s);
		sess_free(&s);
		osd_free(&w);
	}
}

/* done_mode = crc with secure negotiated: the monitor's `cbl` carries a secret in a crc conversation (a client must refuse it); the compression stage
 * of a client that advertises it, in secure framing. */
static void test_misc(void)
{
	static const uint32_t sec[] = {2};
	sim_mon_cfg cfg;
	sim_mon *m;
	tkey key;
	sess s;

	tc_key(&key, 2, 1);
	mon_cfg(&cfg, 2);
	cfg.plan_default.has_fault = 1;
	cfg.plan_default.fault = sim_mon_fault_default();
	cfg.plan_default.fault.done_mode = 1;
	m = sim_mon_new(&cfg);
	WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 0) == 1);
	WRT_CHECK_U64(s.L.mode, 1);
	WRT_CHECK(s.L.have_secret && s.L.secret_len == 64 && !s.c.secure && !sim_m2_is_secure(s.mc->m2));
	sess_free(&s);
	sim_mon_free(m);

	mon_cfg(&cfg, 1);
	m = sim_mon_new(&cfg);
	memset(&s, 0, sizeof(s));
	s.mc = sim_mon_accept(m);
	stc_init_mon(&s.c, s.mc);
	s.c.banner_supported = 3;
	tc_key(&key, 1, 1);
	WRT_CHECK(tc_mon_login(&s.c, &key, "winrbd", sec, 1, 0x24, &s.L) == 1 && tc_finish(&s.c, &s.L, 1) == 1);
	WRT_CHECK(s.c.secure && s.mc->m2->compression_requested);
	keepalive(&s);
	sess_free(&s);
	sim_mon_free(m);
}

/* ---- the secret hooks as the cephx payloads show them ---------------------------------------------------------------------------------- */

static void test_secret_hooks(void)
{
	static const uint32_t sec[] = {2}, crc[] = {1};
	unsigned i;

	/* monitor: omit_secret (an empty cbl in secure mode), secret_in_crc (64 bytes in crc mode), lengths 40 / 128 / 39 */
	{
		sim_mon_cfg cfg;
		sim_mon *m;
		tkey key;
		sess s;
		static const uint32_t lens[] = {40, 128};

		tc_key(&key, 1, 1);
		mon_cfg(&cfg, 1);
		cfg.plan_default.has_fault = 1;
		cfg.plan_default.fault = sim_mon_fault_default();
		cfg.plan_default.fault.sec.omit_secret = 1;
		m = sim_mon_new(&cfg);
		WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 0) == 0); /* the client cannot go secure without a secret */
		WRT_CHECK_U64(s.L.mode, 2);
		WRT_CHECK(!s.L.have_secret && s.L.secret_len == 0);
		WRT_CHECK_U64(sim_mon_secrets(m)->n, 0);
		sess_free(&s);
		sim_mon_free(m);

		mon_cfg(&cfg, 1);
		cfg.plan_default.has_fault = 1;
		cfg.plan_default.fault = sim_mon_fault_default();
		cfg.plan_default.fault.sec.secret_in_crc = 1;
		m = sim_mon_new(&cfg);
		WRT_CHECK(mon_session(m, &s, &key, crc, 1, 0x24, 0) == 1);
		WRT_CHECK_U64(s.L.mode, 1);
		WRT_CHECK(s.L.have_secret && s.L.secret_len == 64); /* what a client must refuse: a secret it will not use */
		WRT_CHECK(!s.c.secure);
		sess_free(&s);
		sim_mon_free(m);

		for (i = 0; i < 2; i++) {
			mon_cfg(&cfg, 1);
			cfg.plan_default.has_fault = 1;
			cfg.plan_default.fault = sim_mon_fault_default();
			cfg.plan_default.fault.sec.secret_len = lens[i];
			m = sim_mon_new(&cfg);
			WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 0) == 1);
			WRT_CHECK_U64(s.L.secret_len, lens[i]);
			WRT_CHECK_U64(sim_m2_is_secure(s.mc->m2), 1);
			sess_free(&s);
			sim_mon_free(m);
		}
		mon_cfg(&cfg, 1);
		cfg.plan_default.has_fault = 1;
		cfg.plan_default.fault = sim_mon_fault_default();
		cfg.plan_default.fault.sec.secret_len = 39;
		m = sim_mon_new(&cfg);
		WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 0) == 0); /* 39 bytes cannot be sliced: neither side goes secure */
		WRT_CHECK_U64(s.L.mode, 2);
		WRT_CHECK(s.L.secret_len == 39 && !sim_m2_is_secure(s.mc->m2));
		sess_free(&s);
		sim_mon_free(m);
	}
	/* OSD: the same three over the authorizer reply */
	{
		sim_osd_cfg oc;
		osdw w;
		sess s;

		osd_cfg_both(&oc);
		oc.m2.f.sec.omit_secret = 1;
		osd_world(&w, 2, &oc);
		WRT_CHECK(osd_session(&w, &s, sec, 1, 0) == 0);
		WRT_CHECK_U64(s.L.mode, 2);
		WRT_CHECK(s.L.reply_version == 1 && !s.L.have_secret);
		sess_free(&s);
		osd_free(&w);

		osd_cfg_both(&oc);
		oc.m2.f.sec.secret_in_crc = 1;
		osd_world(&w, 2, &oc);
		WRT_CHECK(osd_session(&w, &s, crc, 1, 0) == 1);
		WRT_CHECK_U64(s.L.mode, 1);
		WRT_CHECK(s.L.reply_version == 2 && s.L.have_secret && s.L.secret_len == 64);
		sess_free(&s);
		osd_free(&w);
	}
}

/* The first connection of a monitor and the first connections of two OSDs, all with default seeds: three different secrets. (Daemons that
 * issued the same secret to their first connection would hide a client that mixes up the contexts of two connections: every secret
 * would decrypt every connection.) */
static void test_secrets_differ_across_daemons(void)
{
	static const uint32_t sec[] = {2};
	sim_mon_cfg mc;
	sim_mon *m;
	tkey key;
	sess s;
	uint8_t from_mon[64], from_osd[2][64];
	unsigned i;

	tc_key(&key, 1, 1);
	mon_cfg(&mc, 1);
	m = sim_mon_new(&mc);
	WRT_CHECK(m != NULL);
	WRT_CHECK(mon_session(m, &s, &key, sec, 1, 0x24, 0) == 1);
	WRT_CHECK(s.L.have_secret && s.L.secret_len == 64);
	memcpy(from_mon, s.L.secret, 64);
	sess_free(&s);
	sim_mon_free(m);
	for (i = 0; i < 2; i++) { /* OSD 0 and OSD 1: same seed (none), same connection index (0 of the secure ones) */
		sim_osd_cfg oc;
		osdw w;

		osd_cfg_both(&oc);
		oc.id = (int32_t)i;
		osd_world(&w, 1, &oc);
		/* the ticket login of osd_world was a crc connection of the MONITOR; the OSD's own first connection is this one */
		WRT_CHECK(osd_session(&w, &s, sec, 1, 0) == 1);
		WRT_CHECK(s.L.have_secret && s.L.secret_len == 64);
		memcpy(from_osd[i], s.L.secret, 64);
		sess_free(&s);
		osd_free(&w);
	}
	WRT_CHECK(memcmp(from_mon, from_osd[0], 64) != 0);
	WRT_CHECK(memcmp(from_mon, from_osd[1], 64) != 0);
	WRT_CHECK(memcmp(from_osd[0], from_osd[1], 64) != 0);
	/* not even the key or one seed alone is shared */
	WRT_CHECK(memcmp(from_mon, from_osd[0], 16) != 0 && memcmp(from_osd[0], from_osd[1], 16) != 0);
}

int main(void)
{
	test_secrets_differ_across_daemons();
	test_monitor();
	test_monitor_modes();
	test_osd();
	test_osd_modes();
	test_one_byte();
	test_misc();
	test_secret_hooks();
	return wrt_finish();
}
