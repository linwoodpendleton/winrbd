/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the secure-mode peer of the msgr2 test server (sim_m2), part 2: the mode negotiation and the session over it. A
 * scripted client (sim_sec_tc.h: its own framing, CRC, SHA-256 and HMAC, sim_m2_sec for everything secure; nothing of the core)
 * walks the handshake against a sim_m2 with the scripted auth callbacks (no cephx here: the secret is read from the simulator).
 *
 *   - the mode matrix: every client offer against every server allowed list. The server takes the first of the client's list that
 *     it allows (the client's order wins), else AUTH_BAD_METHOD, -EOPNOTSUPP (95) and its own methods and modes in its own order;
 *     a method it does not allow is refused the same way; a refused attempt leaves the connection open for another;
 *   - the stock configurations of v20.2.5 (monitor: allows both, a stock client offers [secure, crc] and ends in secure; OSD: a stock
 *     client offers [crc, secure] and ends in crc);
 *   - a whole session in each mode that came out of the matrix: AUTH_DONE, the signature frames (secure framing from the first),
 *     CLIENT_IDENT / SERVER_IDENT, a MESSAGE of one, two and three segments in both directions, KEEPALIVE2 and its ACK;
 *   - the secrets: one per secure negotiation, from a seeded generator, 64 bytes (or what the hooks say), recorded in the log,
 *     different for different connections and for a new attempt on the same connection, the fixed secret of the configuration,
 *     counters patched into the seeds, nothing issued in crc mode; the short, missing and crc-mode secrets of the hooks.
 */
#include "sim_sec_cx.h"

static const uint8_t k_sess_key[32] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
				       0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};

typedef struct run {
	sim_m2 *s;
	sim_m2_auth_script sc;
	sim_m2_auth_ops ops;
	stc c;
	tlogin L;
	sim_sec_log log;
} run;

static void run_new(run *r, const sim_m2_cfg *cfg_in)
{
	sim_m2_cfg cfg;

	memset(r, 0, sizeof(*r));
	if (cfg_in != NULL)
		cfg = *cfg_in;
	else
		sim_m2_cfg_default(&cfg);
	cfg.sec.issue_at_done = 1; /* the scripted callbacks never ask for the secret: issue it at AUTH_DONE */
	r->sc.done_len = 4;
	memcpy(r->sc.done_payload, "done", 4);
	memcpy(r->sc.key, k_sess_key, 32);
	r->sc.key_len = 32;
	sim_m2_auth_script_ops(&r->ops, &r->sc);
	r->s = sim_m2_new(&cfg, &r->ops);
	WRT_CHECK(r->s != NULL);
	if (r->s == NULL)
		exit(1);
	sim_m2_sec_setup(r->s, &r->log, 0x1234abcdull);
	stc_init_m2(&r->c, r->s);
}

static void run_free(run *r)
{
	stc_free(&r->c);
	sim_m2_free(r->s);
}

/* One AUTH_REQUEST (method, modes) after the banner and HELLO; fills r->L: outcome DONE (mode) or BAD_METHOD. */
static void attempt(run *r, int first, uint32_t method, const uint32_t *offer, unsigned n)
{
	tlogin *L = &r->L;
	int tag;
	stc_rd rd;

	if (first) {
		memset(L, 0, sizeof(*L));
		WRT_CHECK(tc_connect(&r->c, L) == 1);
	}
	L->outcome = 0;
	WRT_CHECK(stc_auth_request(&r->c, method, offer, n, (const uint8_t *)"req", 3) == 0);
	tag = tc_next_auth(&r->c, L);
	if (tag == 3) {
		(void)tc_bad_method(&r->c, L);
		return;
	}
	WRT_CHECK(tag == 6);
	if (tag != 6)
		return;
	rd_init(&rd, r->c.seg[0].p, r->c.seg[0].n);
	L->gid = rd64(&rd);
	L->mode = rd32(&rd);
	L->outcome = TL_OK;
	r->c.log_on = 0;
}

static uint32_t expect_mode(const uint32_t *offer, unsigned n, const uint32_t *allowed, unsigned na)
{
	unsigned i, j;

	for (i = 0; i < n; i++)
		for (j = 0; j < na; j++)
			if (offer[i] == allowed[j])
				return offer[i];
	return 0;
}

/* The session after a successful attempt: signatures, idents, messages and keepalives both ways, in whatever mode came out. */
static void session(run *r, uint32_t mode)
{
	tlogin *L = &r->L;
	sim_m2 *s = r->s;
	uint8_t front[70], middle[33], data[5000];
	unsigned i;

	for (i = 0; i < sizeof(front); i++)
		front[i] = (uint8_t)(i + 1);
	for (i = 0; i < sizeof(middle); i++)
		middle[i] = (uint8_t)(0x80 + i);
	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 3u);
	if (mode == SIM_M2_MODE_SECURE) { /* the secret is not in the (scripted) payload: take it from the simulator */
		L->have_secret = 1;
		L->secret_len = s->sec.secret_len;
		memcpy(L->secret, s->sec.secret, s->sec.secret_len);
	}
	L->key.type = 2;
	L->key.len = 32;
	memcpy(L->key.s, k_sess_key, 32);
	WRT_CHECK(tc_finish(&r->c, L, 1) == 1);
	WRT_CHECK(L->sig_ok && L->signed_ok);
	WRT_CHECK_U64(s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(sim_m2_is_secure(s), mode == SIM_M2_MODE_SECURE);
	WRT_CHECK_U64(r->c.secure, mode == SIM_M2_MODE_SECURE);
	/* client -> server: one segment, two, three, four (the last with a 5000 byte data segment) */
	WRT_CHECK(stc_send_msg(&r->c, 100, 1, NULL, 0, NULL, 0, NULL, 0) == 0);
	WRT_CHECK(stc_send_msg(&r->c, 101, 2, front, sizeof(front), NULL, 0, NULL, 0) == 0);
	WRT_CHECK(stc_send_msg(&r->c, 102, 3, front, 7, middle, sizeof(middle), NULL, 0) == 0);
	WRT_CHECK(stc_send_msg(&r->c, 103, 4, front, sizeof(front), middle, sizeof(middle), data, sizeof(data)) == 0);
	WRT_CHECK_U64(sim_m2_error(s)->status, 0);
	WRT_CHECK_U64(s->n_msgs, 4);
	if (s->n_msgs == 4) {
		WRT_CHECK(s->msgs[0].type == 100 && s->msgs[0].nseg == 1 && s->msgs[0].seg_len[0] == 0);
		WRT_CHECK(s->msgs[1].type == 101 && s->msgs[1].seg_len[0] == sizeof(front));
		WRT_CHECK_MEM(s->msgs[1].seg[0], front, sizeof(front));
		WRT_CHECK(s->msgs[2].seg_len[0] == 7 && s->msgs[2].seg_len[1] == sizeof(middle));
		WRT_CHECK_MEM(s->msgs[2].seg[1], middle, sizeof(middle));
		WRT_CHECK(s->msgs[3].tid == 4 && s->msgs[3].seg_len[2] == sizeof(data));
		WRT_CHECK_MEM(s->msgs[3].seg[2], data, sizeof(data));
		WRT_CHECK_MEM(s->msgs[3].seg[1], middle, sizeof(middle));
	}
	/* server -> client */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(s, 200, 9, 1, front, sizeof(front), middle, sizeof(middle), data, sizeof(data)));
	WRT_CHECK(stc_recv(&r->c) == 1 && r->c.tag == 17 && r->c.nseg == 4);
	WRT_CHECK_U64(r->c.len[0], 41);
	WRT_CHECK_U64(r->c.len[3], sizeof(data));
	if (r->c.len[3] == sizeof(data)) {
		WRT_CHECK_MEM(r->c.seg[3].p, data, sizeof(data));
		WRT_CHECK_U64(ld32le(r->c.seg[0].p + 16) & 0xffff, 200);
	}
	/* keepalive: the stamp comes back in the ACK */
	{
		uint8_t stamp[8] = {1, 2, 3, 4, 5, 6, 7, 8};

		WRT_CHECK(stc_send1(&r->c, 18, stamp, 8) == 0);
		WRT_CHECK(stc_recv(&r->c) == 1 && r->c.tag == 19 && r->c.len[0] == 8);
		if (r->c.len[0] == 8)
			WRT_CHECK_MEM(r->c.seg[0].p, stamp, 8);
		WRT_CHECK_U64(s->n_keepalive, 1);
	}
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(s, 11, 22));
	WRT_CHECK(stc_recv(&r->c) == 1 && r->c.tag == 18 && r->c.len[0] == 8);
	if (mode == SIM_M2_MODE_SECURE) { /* every frame after AUTH_DONE was secure, in step on both sides */
		WRT_CHECK(s->sec.n_tx_frames >= 5 && s->sec.n_rx_frames >= 7);
		WRT_CHECK_U64(s->sec.ctx.tx.ops, r->c.ctx.rx.ops);
		WRT_CHECK_U64(s->sec.ctx.rx.ops, r->c.ctx.tx.ops);
	}
}

/* The compression stage (both banners advertise it): COMPRESSION_REQUEST / DONE are the first frames after the signatures and travel in the
 * mode's framing; the server declines (is_compress 0, method none). */
static void test_compression_stage(void)
{
	static const uint32_t sec[] = {2}, crc[] = {1};
	unsigned i;

	for (i = 0; i < 2; i++) {
		run r;

		run_new(&r, NULL);
		r.c.banner_supported = 3;
		attempt(&r, 1, 2, i == 0 ? sec : crc, 1);
		WRT_CHECK_U64(r.L.mode, i == 0 ? 2u : 1u);
		session(&r, i == 0 ? 2u : 1u);
		WRT_CHECK_U64(r.s->compression_requested, 1);
		run_free(&r);
	}
}

/* done_mode: the server says crc in AUTH_DONE although secure was negotiated (and a secret may have been issued): the conversation is crc. */
static void test_done_mode(void)
{
	static const uint32_t sec[] = {2};
	sim_m2_cfg cfg;
	run r;
	uint32_t n = 0;

	sim_m2_cfg_default(&cfg);
	cfg.f.done_mode = 1;
	run_new(&r, &cfg);
	attempt(&r, 1, 2, sec, 1);
	WRT_CHECK_U64(sim_m2_negotiated_mode(r.s), 2);
	WRT_CHECK_U64(r.L.mode, 1); /* what AUTH_DONE says is what counts */
	WRT_CHECK(sim_m2_conn_secret(r.s, &n) != NULL && n == 64); /* a callback that asks for the secret still gets one */
	session(&r, 1);
	WRT_CHECK(!sim_m2_is_secure(r.s));
	run_free(&r);
	/* secure in AUTH_DONE although only crc was negotiated: the server holds no secret and stops */
	sim_m2_cfg_default(&cfg);
	cfg.f.done_mode = 2;
	run_new(&r, &cfg);
	attempt(&r, 1, 2, (const uint32_t[]){1}, 1);
	WRT_CHECK_U64(r.L.mode, 2);
	WRT_CHECK_U64(r.s->state, SIM_M2_ST_REFUSED);
	run_free(&r);
}

/* ---- the mode matrix ------------------------------------------------------------------------------------------------------- */

static void test_matrix(void)
{
	static const uint32_t o_none[1] = {0};
	static const uint32_t o_crc[] = {1}, o_sec[] = {2}, o_cs[] = {1, 2}, o_sc[] = {2, 1}, o_junk[] = {3}, o_zero_sec[] = {0, 2},
			      o_dup[] = {1, 1, 2}, o_ssc[] = {2, 2, 1}, o_big[] = {0x80000001u, 2}, o_unk_crc[] = {7, 1, 2};
	static const struct {
		const uint32_t *v;
		unsigned n;
	} offers[] = {{o_none, 0}, {o_crc, 1}, {o_sec, 1}, {o_cs, 2}, {o_sc, 2}, {o_junk, 1}, {o_zero_sec, 2}, {o_dup, 3}, {o_ssc, 3},
		      {o_big, 2}, {o_unk_crc, 3}};
	static const uint32_t a_crc[] = {1}, a_sec[] = {2}, a_cs[] = {1, 2}, a_sc[] = {2, 1};
	static const struct {
		const uint32_t *v;
		unsigned n;
	} allowed[] = {{a_crc, 1}, {a_sec, 1}, {a_cs, 2}, {a_sc, 2}};
	unsigned i, j, cases = 0, refused = 0, chosen[3] = {0, 0, 0};

	for (j = 0; j < sizeof(allowed) / sizeof(allowed[0]); j++)
		for (i = 0; i < sizeof(offers) / sizeof(offers[0]); i++) {
			sim_m2_cfg cfg;
			run r;
			uint32_t want = expect_mode(offers[i].v, offers[i].n, allowed[j].v, allowed[j].n);
			unsigned k;

			sim_m2_cfg_default(&cfg);
			cfg.n_modes = allowed[j].n;
			for (k = 0; k < allowed[j].n; k++)
				cfg.modes[k] = allowed[j].v[k];
			run_new(&r, &cfg);
			attempt(&r, 1, 2, offers[i].v, offers[i].n);
			cases++;
			if (want == 0) {
				refused++;
				WRT_CHECK_U64(r.L.outcome, TL_BAD_METHOD);
				WRT_CHECK_U64(r.L.bm_result, -95); /* -EOPNOTSUPP */
				WRT_CHECK_U64(r.L.bm_nmethods, 1);
				WRT_CHECK_U64(r.L.bm_methods[0], 2);
				WRT_CHECK_U64(r.L.bm_nmodes, allowed[j].n);
				for (k = 0; k < allowed[j].n && k < 8u; k++)
					WRT_CHECK_U64(r.L.bm_modes[k], allowed[j].v[k]); /* the server's own list, in its own order */
				WRT_CHECK_U64(sim_m2_negotiated_mode(r.s), 0);
				WRT_CHECK_U64(r.log.n, 0);
				WRT_CHECK(!sim_m2_closed(r.s) && r.s->state == SIM_M2_ST_AUTH);
				/* the connection is still there: a second attempt with an acceptable list works and the whole session runs on it */
				{
					const uint32_t *fix = allowed[j].v;

					attempt(&r, 0, 2, fix, 1);
					WRT_CHECK_U64(r.L.outcome, TL_OK);
					WRT_CHECK_U64(r.L.mode, fix[0]);
					session(&r, fix[0]);
				}
			} else {
				WRT_CHECK_U64(r.L.outcome, TL_OK);
				WRT_CHECK_U64(r.L.mode, want);
				WRT_CHECK_U64(sim_m2_negotiated_mode(r.s), want);
				WRT_CHECK_U64(r.log.n, want == 2u ? 1u : 0u);
				chosen[want]++;
				session(&r, want);
			}
			run_free(&r);
		}
	WRT_CHECK(cases == 44 && refused > 8 && chosen[1] > 5 && chosen[2] > 5);

	/* a method the server does not allow is refused the same way whatever the modes */
	{
		run r;

		run_new(&r, NULL);
		attempt(&r, 1, 1 /* none */, o_cs, 2);
		WRT_CHECK_U64(r.L.outcome, TL_BAD_METHOD);
		WRT_CHECK_U64(r.L.bm_result, -95);
		WRT_CHECK(r.L.bm_nmethods == 1 && r.L.bm_methods[0] == 2 && r.L.bm_nmodes == 2);
		WRT_CHECK_U64(r.log.n, 0);
		run_free(&r);
	}
}

/* What a stock v20.2.5 client gets from stock servers (msgr2-secure-mode.md 2.9). */
static void test_stock(void)
{
	static const uint32_t mon_client[] = {2, 1}, osd_client[] = {1, 2}, both[] = {1, 2}, mon_server[] = {2, 1}, sec_only[] = {2},
			      crc_only[] = {1};
	static const struct {
		const char *what;
		const uint32_t *client;
		unsigned nclient;
		const uint32_t *server;
		unsigned nserver;
		uint32_t want;
	} t[] = {
		{"stock client to a stock monitor", mon_client, 2, mon_server, 2, 2},
		{"stock client to a stock OSD", osd_client, 2, both, 2, 1},
		{"stock client to a cluster forced secure (mon)", mon_client, 2, sec_only, 1, 2},
		{"stock client to a cluster forced secure (osd)", osd_client, 2, sec_only, 1, 2},
		{"stock client to a crc-only server (mon)", mon_client, 2, crc_only, 1, 1},
		{"stock client to a crc-only server (osd)", osd_client, 2, crc_only, 1, 1},
	};
	unsigned i, k;

	for (i = 0; i < sizeof(t) / sizeof(t[0]); i++) {
		sim_m2_cfg cfg;
		run r;

		sim_m2_cfg_default(&cfg);
		cfg.n_modes = t[i].nserver;
		for (k = 0; k < t[i].nserver; k++)
			cfg.modes[k] = t[i].server[k];
		run_new(&r, &cfg);
		attempt(&r, 1, 2, t[i].client, t[i].nclient);
		WRT_CHECK_U64(r.L.outcome, TL_OK);
		WRT_CHECK_U64(r.L.mode, t[i].want);
		session(&r, t[i].want);
		run_free(&r);
	}
}

/* ---- the secrets ----------------------------------------------------------------------------------------------------------- */

static void test_secrets(void)
{
	static const uint32_t sec[] = {2}, both[] = {2, 1}, crc[] = {1};
	run a, b, c;
	sim_m2_cfg cfg;
	sim_sec_ctx cli, srv;
	uint8_t first[64];
	uint32_t n = 0;
	const uint8_t *p;

	/* a seeded generator: the same seed gives the same secret, another seed another one; 64 bytes; recorded once */
	sim_m2_cfg_default(&cfg);
	cfg.sec.seed = 77;
	run_new(&a, &cfg);
	run_new(&b, &cfg);
	cfg.sec.seed = 78;
	run_new(&c, &cfg);
	attempt(&a, 1, 2, sec, 1);
	attempt(&b, 1, 2, sec, 1);
	attempt(&c, 1, 2, sec, 1);
	WRT_CHECK_U64(a.s->sec.secret_len, 64);
	WRT_CHECK_MEM(a.s->sec.secret, b.s->sec.secret, 64);
	WRT_CHECK(memcmp(a.s->sec.secret, c.s->sec.secret, 64) != 0);
	WRT_CHECK_U64(a.log.n, 1);
	WRT_CHECK(sim_sec_log_has(&a.log, a.s->sec.secret, 64));
	p = sim_m2_conn_secret(a.s, &n);
	WRT_CHECK(p == a.s->sec.secret && n == 64);
	WRT_CHECK_U64(a.log.n, 1); /* asking again does not issue another */
	memcpy(first, p, 64);
	run_free(&a);
	/* a new attempt on the same connection is a new secret (after a refusal; the key of a connection must never repeat): attempt 1
	 * is refused by the auth callback after a callback asked for a secret, attempt 2 is the real one */
	cfg.sec.seed = 77;
	run_new(&a, &cfg);
	a.sc.fail_result = -13;
	attempt(&a, 1, 2, sec, 1);
	WRT_CHECK_U64(a.L.outcome, TL_BAD_METHOD);
	WRT_CHECK_U64(a.L.bm_result, -13);
	p = sim_m2_conn_secret(a.s, &n);
	WRT_CHECK(p != NULL && n == 64);
	memcpy(first, p, 64);
	WRT_CHECK_U64(a.log.n, 1);
	a.sc.fail_result = 0;
	attempt(&a, 0, 2, sec, 1);
	WRT_CHECK_U64(a.L.outcome, TL_OK);
	WRT_CHECK(memcmp(first, a.s->sec.secret, 64) != 0);
	WRT_CHECK_U64(a.log.n, 2);
	WRT_CHECK(sim_sec_log_distinct(&a.log));
	WRT_CHECK(sim_sec_log_has(&a.log, first, 64) && sim_sec_log_has(&a.log, a.s->sec.secret, 64));
	/* the secret is no all-zero string and its sliced seeds are different (two streams that never share a nonce) */
	{
		uint8_t k[16], sa[12], sb[12];

		WRT_CHECK(sim_sec_slice(a.s->sec.secret, 64, k, sa, sb) == 0 && memcmp(sa, sb, 12) != 0);
	}
	run_free(&a);
	run_free(&b);
	run_free(&c);

	/* crc negotiated: nothing is issued, nothing is logged */
	run_new(&a, NULL);
	attempt(&a, 1, 2, crc, 1);
	WRT_CHECK(sim_m2_conn_secret(a.s, &n) == NULL && n == 0 && a.log.n == 0 && a.s->sec.secret_len == 0);
	session(&a, 1);
	run_free(&a);

	/* the fixed secret of the configuration: the synthetic one 00..3f; the whole session decodes with it */
	sim_m2_cfg_default(&cfg);
	cfg.sec.fixed_len = 64;
	{
		unsigned i;

		for (i = 0; i < 64; i++)
			cfg.sec.fixed[i] = (uint8_t)i;
	}
	run_new(&a, &cfg);
	attempt(&a, 1, 2, both, 2);
	WRT_CHECK_U64(a.L.mode, 2);
	WRT_CHECK(a.s->sec.secret[63] == 63 && a.s->sec.secret[0] == 0);
	session(&a, 2);
	/* the client's and the server's contexts agree: the server's first frame (its signature) was IV seed A, counter 0 */
	WRT_CHECK(sim_sec_ctx_init(&cli, a.s->sec.secret, 64, 0) == 0 && sim_sec_ctx_init(&srv, a.s->sec.secret, 64, 1) == 0);
	WRT_CHECK_MEM(srv.tx.seed, cli.rx.seed, 12);
	WRT_CHECK_MEM(srv.rx.seed, cli.tx.seed, 12);
	run_free(&a);

	/* a fixed secret longer than the 128 bytes the simulator keeps (fixed_len is a uint8_t, up to 255): cut to 128, never read past the
	 * array (the sanitizer builds catch an over-read of cfg.sec.fixed or an over-write of the secret buffer) */
	sim_m2_cfg_default(&cfg);
	cfg.sec.fixed_len = 255;
	{
		unsigned i;

		for (i = 0; i < sizeof(cfg.sec.fixed); i++)
			cfg.sec.fixed[i] = (uint8_t)(i * 3u + 1u);
	}
	run_new(&a, &cfg);
	attempt(&a, 1, 2, sec, 1);
	WRT_CHECK_U64(a.L.mode, 2);
	WRT_CHECK_U64(a.s->sec.secret_len, SIM_SEC_SECRET_MAX);
	WRT_CHECK_U64(a.log.len[0], SIM_SEC_SECRET_MAX);
	WRT_CHECK_MEM(a.s->sec.secret, cfg.sec.fixed, SIM_SEC_SECRET_MAX);
	session(&a, 2);
	run_free(&a);

	/* the hooks: a secret of 40 and of 128 bytes still gives a secure session (the first 40 bytes are used); 39 does not */
	{
		static const uint32_t lens[] = {40, 64, 100, 128};
		unsigned i;

		for (i = 0; i < 4; i++) {
			sim_m2_cfg_default(&cfg);
			cfg.f.sec.secret_len = lens[i];
			run_new(&a, &cfg);
			attempt(&a, 1, 2, sec, 1);
			WRT_CHECK_U64(a.s->sec.secret_len, lens[i]);
			WRT_CHECK_U64(a.log.len[0], lens[i]);
			session(&a, 2);
			run_free(&a);
		}
		sim_m2_cfg_default(&cfg);
		cfg.f.sec.secret_len = 39;
		run_new(&a, &cfg);
		attempt(&a, 1, 2, sec, 1);
		WRT_CHECK_U64(a.L.mode, 2); /* AUTH_DONE still says secure ... */
		WRT_CHECK_U64(a.s->sec.secret_len, 39);
		WRT_CHECK_U64(a.s->state, SIM_M2_ST_REFUSED); /* ... but the server cannot slice 39 bytes: it never goes on */
		WRT_CHECK(!sim_m2_is_secure(a.s));
		run_free(&a);
	}
	/* omit_secret: secure was negotiated, nobody gets a secret, the server stays plain */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.omit_secret = 1;
	run_new(&a, &cfg);
	attempt(&a, 1, 2, sec, 1);
	WRT_CHECK(sim_m2_conn_secret(a.s, &n) == NULL && a.log.n == 0);
	WRT_CHECK_U64(a.s->state, SIM_M2_ST_REFUSED);
	run_free(&a);
	/* secret_in_crc: crc negotiated, a secret is still handed out (and recorded), the session stays crc */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.secret_in_crc = 1;
	run_new(&a, &cfg);
	attempt(&a, 1, 2, crc, 1);
	p = sim_m2_conn_secret(a.s, &n);
	WRT_CHECK(p != NULL && n == 64 && a.log.n == 1);
	session(&a, 1);
	run_free(&a);
	/* counters patched into the seeds: the streams start there (the wrap is one or two operations away) */
	sim_m2_cfg_default(&cfg);
	cfg.f.sec.has_ctr_a = 1;
	cfg.f.sec.ctr_a = 0xfffffffffffffffdull;
	cfg.f.sec.has_ctr_b = 1;
	cfg.f.sec.ctr_b = 0xfffffffffffffff0ull;
	run_new(&a, &cfg);
	attempt(&a, 1, 2, sec, 1);
	WRT_CHECK(sim_sec_ctx_init(&srv, a.s->sec.secret, 64, 1) == 0);
	WRT_CHECK_U64(sim_sec_dir_counter(&srv.tx), 0xfffffffffffffffdull);
	WRT_CHECK_U64(sim_sec_dir_counter(&srv.rx), 0xfffffffffffffff0ull);
	session(&a, 2); /* the server's counter wraps through 2^64 during the session: the stream goes on, no carry into the fixed field */
	WRT_CHECK(memcmp(a.s->sec.ctx.tx.nonce, srv.tx.seed, 4) == 0);
	WRT_CHECK(sim_sec_dir_counter(&a.s->sec.ctx.tx) < 0xfffffffffffffffdull); /* wrapped */
	run_free(&a);
}

int main(void)
{
	test_matrix();
	test_stock();
	test_compression_stage();
	test_done_mode();
	test_secrets();
	return wrt_finish();
}
