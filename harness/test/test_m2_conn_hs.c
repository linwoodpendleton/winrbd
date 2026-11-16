/* SPDX-License-Identifier: MIT */
/*
 * m2-conn, handshake half: wri_m2_conn from "TCP connected" to READY against the scriptable server of
 * sim_m2.h with a test-defined wri_auth_ops (fixed session key) and wri_m2_upper.
 *
 *   - the happy path with the exact byte sequence the client writes (banner, HELLO, AUTH_REQUEST,
 *     AUTH_REQUEST_MORE, AUTH_SIGNATURE, CLIENT_IDENT field by field), both pre-auth transcripts as the
 *     server saw them, the signature recomputed independently;
 *   - byte-at-a-time and split delivery in both directions: identical bytes on the wire;
 *   - the scenario of harness/vectors/msgr2/preauth-hmac.json replayed byte for byte on the receive
 *     side (our AUTH_SIGNATURE is the vector's), the sent stream equal to the vector's except our
 *     banner, and the vector's server signatures refused;
 *   - the handshake timeout with a fake clock, backpressure in the middle of the handshake, the
 *     lifecycle calls (connect failure, host close, orderly close).
 * The rejections are in test_m2_conn_rej.c.
 */
#include "m2_conn_rig.h"

/* ---- happy path ----------------------------------------------------------------------------------- */

static size_t stream_off(const rig_fr *f, size_t n) /* offset after frame n-1 inside the frame stream */
{
	size_t i, off = 0;

	for (i = 0; i < n; i++)
		off += f[i].total;
	return off;
}

static void check_happy_state(rig *r)
{
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(r->up.n_ready, 1);
	WRT_CHECK_U64(r->up.n_closed, 0);
	WRT_CHECK_U64(r->c.err.status, 0);
	WRT_CHECK(r->c.pa == NULL); /* the handshake slot is released */
	WRT_CHECK_U64(r->c.global_id, 4242);
	WRT_CHECK_U64(r->c.mode, WRI_CONN_MODE_CRC);
	WRT_CHECK_U64((uint64_t)r->c.peer_gid, 1);
	WRT_CHECK_U64(r->c.features, 0x3f07fffffffdffffull);
	WRT_CHECK_U64(r->c.server_flags, 1);
	WRT_CHECK_U64(r->c.server_cookie, 0);
	WRT_CHECK_U64(r->c.my_family, WR_AF_IPV4);
	WRT_CHECK(memcmp(r->c.my_ip, TC_CLIENT_IP, 4) == 0);
	WRT_CHECK_U64(r->c.out_seq, 0);
	WRT_CHECK_U64(r->c.in_seq, 0);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r->c), WR_DEADLINE_NONE);
	WRT_CHECK_U64(r->c.revision1, 1);
	WRT_CHECK_U64(r->au.n_begin, 1);
	WRT_CHECK_U64(r->au.last_target_type, WRI_ENTITY_MON);
	WRT_CHECK_U64(r->au.n_more, 1);
	WRT_CHECK_U64(r->au.last_reply_len, 9);
	WRT_CHECK(r->au.last_reply[0] == 0x33 && r->au.last_reply[8] == 0x33);
	WRT_CHECK_U64(r->au.n_done, 1);
	WRT_CHECK_U64(r->au.done_gid, 4242);
	WRT_CHECK_U64(r->au.done_mode, WRI_CONN_MODE_CRC);
	WRT_CHECK_U64(r->au.done_len, 40);
	WRT_CHECK(r->au.done_payload[0] == 0xDD && r->au.done_payload[39] == 0xDD);
	WRT_CHECK_U64(r->s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(sim_m2_error(r->s)->status, 0);
}

/* Exact bytes of every frame the client wrote, and what the server logged. */
static void check_happy_bytes(rig *r)
{
	uint8_t banner[WRI_M2_BANNER_LEN], addr[SIM_M2_ADDR4_LEN], exp[512], sig[32];
	rig_fr f[8], g[8];
	size_t used, n, gused, ng;
	tb t;

	WRT_CHECK(r->sent_len > WRI_M2_BANNER_LEN);
	wri_m2_banner_build(banner);
	WRT_CHECK_MEM(r->sent, banner, WRI_M2_BANNER_LEN); /* supported 1, required 0 */
	n = rig_split(r->sent + WRI_M2_BANNER_LEN, r->sent_len - WRI_M2_BANNER_LEN, f, 8, &used);
	WRT_CHECK_U64(n, 5);
	WRT_CHECK_U64(used, r->sent_len - WRI_M2_BANNER_LEN); /* nothing left over, nothing in between */
	if (n != 5)
		return;
	WRT_CHECK_U64(f[0].tag, WRI_M2_TAG_HELLO);
	WRT_CHECK_U64(f[1].tag, WRI_M2_TAG_AUTH_REQUEST);
	WRT_CHECK_U64(f[2].tag, WRI_M2_TAG_AUTH_REQUEST_MORE);
	WRT_CHECK_U64(f[3].tag, WRI_M2_TAG_AUTH_SIGNATURE);
	WRT_CHECK_U64(f[4].tag, WRI_M2_TAG_CLIENT_IDENT);
	/* HELLO: entity type 0x08 and the address we dialled, type 2, nonce 0 */
	sim_m2_put_addr4(addr, 2, 0, TC_SERVER_IP, 3300);
	exp[0] = 0x08;
	memcpy(exp + 1, addr, sizeof(addr));
	WRT_CHECK_U64(f[0].nseg, 1);
	WRT_CHECK_U64(f[0].len[0], 1 + sizeof(addr));
	WRT_CHECK_MEM(f[0].seg[0], exp, 1 + sizeof(addr));
	/* AUTH_REQUEST: method 2, modes [1], payload from begin() */
	t.n = 0;
	tb_u32(&t, 2), tb_u32(&t, 1), tb_u32(&t, 1), tb_u32(&t, 24), tb_fill(&t, 0x41, 24);
	WRT_CHECK_U64(f[1].len[0], t.n);
	WRT_CHECK_MEM(f[1].seg[0], t.b, t.n);
	/* AUTH_REQUEST_MORE: the blob that more() wrote */
	t.n = 0;
	tb_u32(&t, 40), tb_fill(&t, 0x42, 40);
	WRT_CHECK_U64(f[2].len[0], t.n);
	WRT_CHECK_MEM(f[2].seg[0], t.b, t.n);
	/* AUTH_SIGNATURE: HMAC-SHA256(key, every byte received up to and including AUTH_DONE), recomputed here */
	ng = rig_split(r->rcvd + WRI_M2_BANNER_LEN, r->rcvd_len - WRI_M2_BANNER_LEN, g, 8, &gused);
	WRT_CHECK_U64(ng, 5); /* HELLO, REPLY_MORE, DONE, AUTH_SIGNATURE, SERVER_IDENT */
	if (ng == 5) {
		WRT_CHECK_U64(g[2].tag, WRI_M2_TAG_AUTH_DONE);
		tc_hmac(TC_KEY, 32, r->rcvd, WRI_M2_BANNER_LEN + stream_off(g, 3), sig);
		WRT_CHECK_U64(f[3].len[0], 32);
		WRT_CHECK_MEM(f[3].seg[0], sig, 32);
		/* what the server logged is exactly the stream, banner included, and stops before the signatures */
		WRT_CHECK_U64(r->s->tx_log_len, WRI_M2_BANNER_LEN + stream_off(g, 3));
		WRT_CHECK_MEM(r->s->tx_log, r->rcvd, r->s->tx_log_len);
	}
	WRT_CHECK_U64(r->s->rx_log_len, WRI_M2_BANNER_LEN + stream_off(f, 3));
	WRT_CHECK_MEM(r->s->rx_log, r->sent, r->s->rx_log_len);
	/* CLIENT_IDENT as a stock client sends it: the IP the server saw, port 0, type 3, our nonce, target as dialled,
	 * gid -1, global_seq, features, required, flags 1, cookie 0 */
	tc_pay_ident(&t, 0x3f07fffffffdffffull, r->gseq, r->nonce);
	WRT_CHECK_U64(f[4].len[0], t.n);
	WRT_CHECK_MEM(f[4].seg[0], t.b, t.n);
	WRT_CHECK_U64(r->s->ident.gid, -1);
	WRT_CHECK_U64(r->s->ident.global_seq, r->gseq);
	WRT_CHECK_U64(r->s->ident.flags, 1);
	WRT_CHECK_U64(r->s->ident.cookie, 0);
	WRT_CHECK_U64(r->s->ident.required, 0x0800000000000000ull);
}

static uint8_t g_base_sent[2048], g_base_rcvd[2048];
static size_t g_base_sent_len, g_base_rcvd_len;

static void test_happy(void)
{
	rig r;

	rig_init(&r);
	rig_start(&r);
	rig_pump(&r);
	check_happy_state(&r);
	check_happy_bytes(&r);
	WRT_CHECK(r.sent_len <= sizeof(g_base_sent) && r.rcvd_len <= sizeof(g_base_rcvd));
	memcpy(g_base_sent, r.sent, r.sent_len);
	memcpy(g_base_rcvd, r.rcvd, r.rcvd_len);
	g_base_sent_len = r.sent_len;
	g_base_rcvd_len = r.rcvd_len;
	/* the deadline of the handshake was armed at on_connected and is gone once READY */
	rig_free(&r);

	/* an OSD target: the gid comes from the auth layer, the auth layer is told the target type */
	rig_init(&r);
	r.role = WRI_ENTITY_OSD;
	r.scfg.entity_type = SIM_M2_ENT_OSD;
	r.au.gid = 4242;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.au.last_target_type, WRI_ENTITY_OSD);
	WRT_CHECK_U64(r.s->ident.gid, 4242);
	rig_free(&r);
}

static void test_chunks(void)
{
	static const size_t rx[] = {1, 7, 13, 0, 0, 64};
	static const size_t tx[] = {1, 3, 0, 5, 1, 0};
	size_t i;

	for (i = 0; i < sizeof(rx) / sizeof(rx[0]); i++) {
		rig r;

		rig_init(&r);
		r.rx_chunk = rx[i];
		r.tx_chunk = tx[i];
		rig_start(&r);
		rig_pump(&r);
		check_happy_state(&r);
		WRT_CHECK_U64(r.sent_len, g_base_sent_len);
		WRT_CHECK_U64(r.rcvd_len, g_base_rcvd_len);
		WRT_CHECK_MEM(r.sent, g_base_sent, g_base_sent_len < r.sent_len ? g_base_sent_len : r.sent_len);
		WRT_CHECK_MEM(r.rcvd, g_base_rcvd, g_base_rcvd_len < r.rcvd_len ? g_base_rcvd_len : r.rcvd_len);
		rig_free(&r);
	}
	{ /* a tiny ring: the window shrinks, the parser still gets everything through */
		rig r;

		rig_init(&r);
		r.ring_cap = 40;
		r.rx_chunk = 11;
		rig_start(&r);
		rig_pump(&r);
		check_happy_state(&r);
		rig_free(&r);
	}
	{ /* a budgeted step: the connection says "more work" until the ring is drained */
		rig r;
		uint32_t budget;
		int more = 0, steps = 0;

		rig_init(&r);
		rig_start(&r);
		(void)rig_flush_tx(&r);
		while (sim_m2_pending(r.s) != 0 || more) {
			int p = 0;

			(void)rig_deliver(&r, &p);
			budget = 5;
			more = wri_m2_conn_step(&r.x, &r.c, &budget);
			while (more && steps++ < 10000) {
				budget = 5;
				more = wri_m2_conn_step(&r.x, &r.c, &budget);
			}
			(void)rig_flush_tx(&r);
			if (steps >= 10000)
				break;
		}
		rig_pump(&r);
		check_happy_state(&r);
		rig_free(&r);
	}
}

/* ---- the preauth-hmac.json scenario ------------------------------------------------------------------- */

static int vec_hex(const wrt_json *j, const char *key, uint8_t **b, size_t *n)
{
	return wrt_json_get_hex(j, wrt_json_root(j), key, b, n);
}

/* variant 0: the server answers with HMAC over what we really sent (must be accepted);
 * 1: the vector's own server signature (computed over the stock client's banner: must differ from ours);
 * 2: the vector's variant "includes the client's own signature frame". */
static void vector_replay(int variant)
{
	wrt_json j;
	uint8_t *key, *rcv, *sent, *csig, *ssig, *bad = NULL, mine[32], sigframe_pay[32];
	size_t nkey, nrcv, nsent, ncsig, nssig, nbad = 0, patched_sent = 0, fl;
	rig r;
	wri_m2_seg_src seg;
	uint8_t *sf;
	uint8_t want[254];

	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/preauth-hmac.json") == 0);
	WRT_CHECK(vec_hex(&j, "session_key_secret_hex", &key, &nkey) == 0);
	WRT_CHECK(vec_hex(&j, "bytes_received_by_client_hex", &rcv, &nrcv) == 0);
	WRT_CHECK(vec_hex(&j, "bytes_sent_by_client_hex", &sent, &nsent) == 0);
	WRT_CHECK(vec_hex(&j, "client_signature_hex", &csig, &ncsig) == 0);
	WRT_CHECK(vec_hex(&j, "server_signature_hex", &ssig, &nssig) == 0);
	{
		wrt_tok mnv = wrt_json_get(&j, wrt_json_root(&j), "must_not_verify");

		WRT_CHECK(wrt_json_get_hex(&j, mnv, "server_signature_including_the_clients_own_signature_frame", &bad,
					   &nbad) == 0);
	}
	WRT_CHECK_U64(nrcv, 239);
	WRT_CHECK_U64(nsent, 254);
	(void)patched_sent;

	rig_init(&r);
	memcpy(r.au.key, key, 32);
	r.au.key_len = 32;
	memcpy(r.au.begin_payload, sent + 98 + 32 + 16, 24); /* the stock client's AUTH_REQUEST payload */
	memcpy(r.au.more_payload, sent + 174 + 32 + 4, 40);  /* and its AUTH_REQUEST_MORE blob */
	r.x.now.mono_ms = 5;
	rig_start(&r);
	/* the server's bytes of the vector, frame by frame, with our answers flushed in between */
	(void)rig_flush_tx(&r);
	rig_inject(&r, rcv, 26); /* banner (supported 3) */
	(void)rig_flush_tx(&r);
	rig_inject(&r, rcv + 26, 72); /* HELLO */
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	(void)rig_flush_tx(&r);
	rig_inject(&r, rcv + 98, 49); /* AUTH_REPLY_MORE */
	(void)rig_flush_tx(&r);
	rig_inject(&r, rcv + 147, 92); /* AUTH_DONE */
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	WRT_CHECK(r.c.pa != NULL); /* the slot is held until the server's signature is checked */
	(void)rig_flush_tx(&r);
	/* what we sent so far equals the stock client's stream, except for our banner (supported 1, not 3) */
	WRT_CHECK_U64(r.sent_len, 254 + 68);
	memcpy(want, sent, sizeof(want));
	want[10] = 0x01;
	WRT_CHECK_MEM(r.sent, want, sizeof(want));
	/* ... and the transcripts the connection kept are those bytes */
	WRT_CHECK_U64(r.pa.rx_len, 239);
	WRT_CHECK_MEM(r.pa.rx_buf, rcv, 239);
	WRT_CHECK_U64(r.pa.tx_len, 254);
	WRT_CHECK_MEM(r.pa.tx_buf, want, 254);
	{ /* our AUTH_SIGNATURE is the vector's client signature: HMAC over the 239 received bytes */
		rig_fr f[1];

		WRT_CHECK_U64(rig_split(r.sent + 254, 68, f, 1, NULL), 1);
		WRT_CHECK_U64(f[0].tag, WRI_M2_TAG_AUTH_SIGNATURE);
		WRT_CHECK_U64(f[0].len[0], 32);
		WRT_CHECK_MEM(f[0].seg[0], csig, 32);
		memcpy(sigframe_pay, f[0].seg[0], 32);
	}
	tc_hmac(key, 32, want, 254, mine);
	seg.len = 32;
	seg.ref = 0;
	seg.p = variant == 0 ? mine : variant == 1 ? ssig : bad;
	sf = rig_build_frame(WRI_M2_TAG_AUTH_SIGNATURE, &seg, 1, &fl);
	rig_inject(&r, sf, fl);
	free(sf);
	if (variant == 0) {
		WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
		WRT_CHECK(r.c.pa == NULL);
		WRT_CHECK_U64(r.pa.rx_len, 0); /* wiped */
		WRT_CHECK_U64(r.pa.tx_len, 0);
		WRT_CHECK_U64(r.pa.rx_buf[0], 0);
		WRT_CHECK_U64(r.pa.tx_buf[0], 0);
	} else {
		/* the stock client's banner is not ours, so its transcript is not ours: refused */
		rig_check_failed(&r, WR_E_M2_SIGNATURE);
	}
	rig_free(&r);
	wrt_json_free(&j);
	free(key), free(rcv), free(sent), free(csig), free(ssig), free(bad);
}

static void test_vector(void)
{
	vector_replay(0);
	vector_replay(1);
	vector_replay(2);
}

/* ---- deadlines ------------------------------------------------------------------------------------- */

static void test_timeout(void)
{
	static const int64_t limit[] = {26, 98, 239, 307}; /* HELLO, AUTH, SIG, IDENT: where the server goes quiet */
	static const unsigned state[] = {WRI_M2_HELLO, WRI_M2_AUTH, WRI_M2_SIG, WRI_M2_IDENT};
	size_t i;

	for (i = 0; i < 4; i++) {
		rig r;
		uint8_t zero[32];

		memset(zero, 0, sizeof(zero));
		rig_init(&r);
		r.scfg.f.out_limit = limit[i];
		rig_start(&r);
		WRT_CHECK_U64(r.c.deadline_ms, 1000 + 8000);
		WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 9000);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, state[i]);
		WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 9000);
		r.x.now.mono_ms = 8999; /* one millisecond early: still waiting */
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		WRT_CHECK_U64(r.c.state, state[i]);
		WRT_CHECK_U64(r.up.n_closed, 0);
		r.x.now.mono_ms = 9000;
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		rig_check_failed(&r, WR_E_M2_HANDSHAKE_TIMEOUT);
		WRT_CHECK(memcmp(r.c.sig_want, zero, 32) == 0); /* the expected signature is wiped */
		rig_free(&r);
	}
	{ /* a late clock reading at the first step also fails; a zero timeout means no deadline at all */
		rig r;

		rig_init(&r);
		r.x.cfg.handshake_timeout_ms = 0;
		r.scfg.f.out_limit = 26;
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), WR_DEADLINE_NONE);
		r.x.now.mono_ms = 1000000;
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		WRT_CHECK_U64(r.c.state, WRI_M2_HELLO);
		rig_free(&r);
	}
	{ /* READY has no handshake deadline */
		rig r;

		rig_init(&r);
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		r.x.now.mono_ms = 100000;
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		rig_free(&r);
	}
}

/* ---- backpressure in the handshake -------------------------------------------------------------------- */

static void test_backpressure(void)
{
	rig r;
	uint8_t banner[WRI_M2_BANNER_LEN], hello[1 + SIM_M2_ADDR4_LEN], addr[SIM_M2_ADDR4_LEN];
	wri_m2_seg_src seg;
	uint8_t *fr;
	size_t fl;
	rig_fr f[4];

	rig_init(&r);
	rig_start(&r); /* the banner is queued and NOT consumed */
	wri_m2_banner_build(banner);
	rig_inject(&r, banner, sizeof(banner));
	WRT_CHECK_U64(r.c.state, WRI_M2_HELLO); /* HELLO queued behind the banner, still nothing consumed */
	sim_m2_put_addr4(addr, 2, 0, TC_SERVER_IP, 41234);
	hello[0] = WRI_ENTITY_MON;
	memcpy(hello + 1, addr, sizeof(addr));
	seg.p = hello, seg.len = sizeof(hello), seg.ref = 0;
	fr = rig_build_frame(WRI_M2_TAG_HELLO, &seg, 1, &fl);
	rig_inject(&r, fr, fl);
	free(fr);
	/* AUTH_REQUEST is built in the empty encode buffer only: the connection waits for the host to drain it */
	WRT_CHECK_U64(r.c.state, WRI_M2_HELLO);
	WRT_CHECK_U64(r.c.stalled, 1);
	WRT_CHECK_U64(r.au.n_begin, 0); /* nothing irreversible happened */
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), r.x.now.mono_ms + WRI_M2C_STALL_RETRY_MS);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.c.state, WRI_M2_HELLO); /* still held, and the same frame is not lost */
	WRT_CHECK_U64(r.c.stalled, 1);
	/* the host consumes the output: the connection asks for a step at once, and then goes on */
	{
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), i, tot = 0;

		for (i = 0; i < n; i++)
			tot += iov[i].len;
		WRT_CHECK_U64(tot, 26 + 72);
		wri_m2_conn_tx_consume(&r.c, tot);
	}
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), 0);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	WRT_CHECK_U64(r.c.stalled, 0);
	WRT_CHECK_U64(r.au.n_begin, 1);
	{
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);

		WRT_CHECK_U64(n, 1);
		WRT_CHECK_U64(rig_split(iov[0].base, iov[0].len, f, 4, NULL), 1);
		WRT_CHECK_U64(f[0].tag, WRI_M2_TAG_AUTH_REQUEST);
	}
	rig_free(&r);
}

/* ---- lifecycle ----------------------------------------------------------------------------------------- */

static void test_lifecycle(void)
{
	rig r;

	/* open() with a role that cannot be dialled: refused, reported by the first step, once */
	rig_init(&r);
	r.role = WRI_ENTITY_CLIENT;
	rig_start(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_FAILED);
	WRT_CHECK_U64(r.up.n_closed, 0);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.up.n_closed, 1);
	WRT_CHECK_STATUS(WR_E_INVAL, r.up.closed_err.status);
	rig_free(&r);

	/* a connect failure is reported by the host; close requests; nothing moves before the TCP connection */
	{
		rig q;

		rig_init(&q);
		rig_start(&q);
		wri_m2_conn_bind(&q.c, 1, q.ring_buf, q.ring_cap, q.ctl_buf, q.ctl_cap, q.tx_buf, q.tx_cap, q.seg_cap_max);
		wri_m2_conn_open(&q.c, 0x20001, WRI_ENTITY_MON, &q.target, &q.dial, &stub_ops, &q.au, &up_ops, &q.up, &q.pa,
				 1, 1);
		WRT_CHECK_U64(q.c.state, WRI_M2_CONNECTING);
		q.up.n_closed = 0;
		wri_m2_conn_on_closed(&q.x, &q.c, 111);
		WRT_CHECK_U64(q.up.n_closed, 1);
		WRT_CHECK_STATUS(WR_E_NET_CONNECT, q.up.closed_err.status);
		WRT_CHECK_U64(q.up.closed_err.a0, 111);
		WRT_CHECK_U64(q.c.state, WRI_M2_FREE);
		/* nothing is accepted before the TCP connection is reported */
		wri_m2_conn_open(&q.c, 0x20002, WRI_ENTITY_MON, &q.target, &q.dial, &stub_ops, &q.au, &up_ops, &q.up, &q.pa,
				 1, 1);
		{
			uint8_t *w;
			wr_iov iov[2];

			WRT_CHECK_U64(wri_m2_conn_rx_window(&q.c, &w), 0);
			WRT_CHECK_U64(wri_m2_conn_tx_peek(&q.c, iov, 2), 0);
			WRT_CHECK_U64(wri_m2_conn_deadline(&q.c), WR_DEADLINE_NONE);
		}
		q.up.n_closed = 0;
		wri_m2_conn_close(&q.x, &q.c, WR_E_CANCELLED);
		WRT_CHECK_U64(q.c.state, WRI_M2_CLOSING);
		WRT_CHECK_U64(q.up.n_closed, 1);
		WRT_CHECK_STATUS(WR_E_CANCELLED, q.up.closed_err.status);
		wri_m2_conn_close(&q.x, &q.c, WR_E_CANCELLED);
		wri_m2_conn_on_closed(&q.x, &q.c, 0);
		WRT_CHECK_U64(q.up.n_closed, 1); /* once */
		WRT_CHECK_U64(q.c.state, WRI_M2_FREE);
		rig_free(&q);
	}

	/* the host loses the socket in the middle of the handshake, and after READY */
	rig_init(&r);
	r.scfg.f.out_limit = 98;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	wri_m2_conn_on_closed(&r.x, &r.c, 104);
	WRT_CHECK_U64(r.up.n_closed, 1);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.up.closed_err.status);
	WRT_CHECK(r.c.pa == NULL);
	rig_free(&r);

	rig_init(&r);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	wri_m2_conn_on_closed(&r.x, &r.c, 0);
	WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.up.closed_err.status);
	WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
	rig_free(&r);

	/* an orderly close from READY keeps the first cause: none */
	rig_init(&r);
	rig_start(&r);
	rig_pump(&r);
	wri_m2_conn_close(&r.x, &r.c, WR_OK);
	WRT_CHECK_U64(r.c.state, WRI_M2_CLOSING);
	WRT_CHECK_U64(r.up.n_closed, 1);
	WRT_CHECK_STATUS(WR_OK, r.up.closed_err.status);
	rig_free(&r);
}

int main(void)
{
	test_happy();
	test_chunks();
	test_vector();
	test_timeout();
	test_backpressure();
	test_lifecycle();
	return wrt_finish();
}
