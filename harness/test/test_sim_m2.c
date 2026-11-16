/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the msgr2 test server (harness/test/support/sim_m2.*), part 1: the happy paths.
 * The server is driven by hand with frames built by the m2-frame builder (sim_m2_tc.h), against
 * harness/vectors/msgr2/preauth-hmac.json (exact transcript bytes and both signatures) and
 * harness/vectors/msgr2/handshake-skeletons.json (frame order and segment lengths of a monitor and
 * an OSD connection). Also: message receive and send, sequence numbers, KEEPALIVE2 echo, ACK
 * tolerance, byte-at-a-time delivery in both directions, AUTH_BAD_METHOD and a fresh attempt.
 * Fault hooks and protocol violations are in test_sim_m2_faults.c. No module built after wave 2
 * is used: only the m2-frame parser / builder, hash and util.
 */
#include "sim_m2_tc.h"

/* ---- vector replay: preauth-hmac.json --------------------------------------------------------------- */

static int hexfield(const wrt_json *j, const char *key, uint8_t **b, size_t *n)
{
	return wrt_json_get_hex(j, wrt_json_root(j), key, b, n);
}

static void replay(int variant)
{
	wrt_json j;
	uint8_t *key, *rcv, *sent, *csig, *ssig, *bad = NULL, out[2048];
	size_t nkey, nrcv, nsent, ncsig, nssig, nbad = 0, n, i;
	sim_m2_cfg cfg;
	sim_m2_auth_script sc;
	sim_m2_auth_ops ops;
	sim_m2 *s;
	wri_m2_seg_src seg;
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t enc[256], sigframe[256];
	size_t nsig = 0;

	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/preauth-hmac.json") == 0);
	WRT_CHECK(hexfield(&j, "session_key_secret_hex", &key, &nkey) == 0);
	WRT_CHECK(hexfield(&j, "bytes_received_by_client_hex", &rcv, &nrcv) == 0);
	WRT_CHECK(hexfield(&j, "bytes_sent_by_client_hex", &sent, &nsent) == 0);
	WRT_CHECK(hexfield(&j, "client_signature_hex", &csig, &ncsig) == 0);
	WRT_CHECK(hexfield(&j, "server_signature_hex", &ssig, &nssig) == 0);
	if (variant == 1) {
		wrt_tok mnv = wrt_json_get(&j, wrt_json_root(&j), "must_not_verify");

		WRT_CHECK(wrt_json_get_hex(&j, mnv, "client_signature_without_server_banner", &bad, &nbad) == 0);
	}
	WRT_CHECK_U64(nkey, 32);
	WRT_CHECK_U64(nrcv, 239);
	WRT_CHECK_U64(nsent, 254);
	/* the server's answers sit at known offsets of the vector: banner 26, HELLO 72, REPLY_MORE 49, DONE 92 */
	WRT_CHECK(rcv[98] == WRI_M2_TAG_AUTH_REPLY_MORE && rcv[147] == WRI_M2_TAG_AUTH_DONE);

	sim_m2_cfg_default(&cfg);
	cfg.client_port = 0xa112; /* the address HELLO reports in the vector: 10.77.0.20:41234 */
	memset(&sc, 0, sizeof(sc));
	sc.rounds = 1;
	sc.more_len = 9;
	memcpy(sc.more_payload, rcv + 134, 9);
	sc.done_len = 40;
	memcpy(sc.done_payload, rcv + 195, 40);
	memcpy(sc.key, key, 32);
	sc.key_len = 32;
	sim_m2_auth_script_ops(&ops, &sc);
	s = sim_m2_new(&cfg, &ops);
	WRT_CHECK(s != NULL);
	if (s == NULL)
		return;

	/* the client's bytes up to and including AUTH_REQUEST_MORE, in one piece */
	WRT_CHECK_U64(sim_m2_feed(s, sent, nsent), nsent);
	n = sim_m2_drain(s, out, sizeof(out));
	WRT_CHECK_U64(n, nrcv);
	WRT_CHECK_MEM(out, rcv, nrcv < n ? nrcv : n); /* banner, HELLO, REPLY_MORE, DONE: the bytes of the vector */
	WRT_CHECK_U64(s->tx_log_len, nrcv);
	WRT_CHECK_MEM(s->tx_log, rcv, nrcv);
	WRT_CHECK_U64(sim_m2_error(s)->status, 0);
	WRT_CHECK_U64(s->state, SIM_M2_ST_SIGNATURE);
	WRT_CHECK_U64(s->conn_mode, 1);
	WRT_CHECK_U64(s->global_id, 4242);

	/* the client's AUTH_SIGNATURE: the vector's, or one that must not verify */
	seg.p = variant == 1 ? bad : csig;
	seg.len = 32;
	seg.ref = 0;
	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_AUTH_SIGNATURE, &seg, 1, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		memcpy(sigframe + nsig, iov[i].base, iov[i].len);
		nsig += iov[i].len;
	}
	WRT_CHECK_U64(sim_m2_feed(s, sigframe, nsig), nsig);
	n = sim_m2_drain(s, out, sizeof(out));
	if (variant == 0) {
		WRT_CHECK_U64(sim_m2_error(s)->status, 0);
		WRT_CHECK_U64(n, 68); /* preamble 32 + 32 + CRC 4 */
		WRT_CHECK(n == 68 && out[0] == WRI_M2_TAG_AUTH_SIGNATURE);
		WRT_CHECK_MEM(out + 32, ssig, 32);
		WRT_CHECK_U64(s->rx_log_len, nsent); /* the log of what we received stops before the signature frame */
		WRT_CHECK_MEM(s->rx_log, sent, nsent);
		WRT_CHECK_U64(s->state, SIM_M2_ST_COMPRESSION); /* the vector's client banner advertises 0x3 */
	} else {
		WRT_CHECK_U64(sim_m2_error(s)->status, WR_E_M2_SIGNATURE);
		WRT_CHECK_U64(n, 0);
		WRT_CHECK(sim_m2_closed(s));
	}
	sim_m2_free(s);
	wrt_json_free(&j);
	free(key), free(rcv), free(sent), free(csig), free(ssig), free(bad);
}

/* ---- handshake skeletons ------------------------------------------------------------------------------ */

/* Frame k (tag, first segment length) of the server_to_client stream of connection `conn`. */
static int skeleton(const wrt_json *j, int conn, int k, int *tag, int *len0, int *nseg)
{
	wrt_tok c = wrt_json_at(j, wrt_json_get(j, wrt_json_root(j), "connections"), (size_t)conn);
	wrt_tok st = wrt_json_at(j, wrt_json_get(j, c, "streams"), 1);
	wrt_tok f = wrt_json_at(j, wrt_json_get(j, st, "frames"), (size_t)k);
	wrt_tok sl = wrt_json_get(j, f, "segment_lengths");
	int ok = 0;

	*tag = (int)wrt_json_int(j, wrt_json_get(j, f, "tag"), &ok);
	*len0 = (int)wrt_json_int(j, wrt_json_at(j, sl, 0), &ok);
	*nseg = (int)wrt_json_count(j, sl);
	return ok;
}

static void check_msg_frame(const tc_frame *f, uint64_t seq, uint64_t ack, uint32_t flen)
{
	WRT_CHECK_U64(f->tag, WRI_M2_TAG_MESSAGE);
	WRT_CHECK_U64(f->nseg, 2);
	WRT_CHECK_U64(f->len[0], 41);
	WRT_CHECK_U64(f->len[1], flen);
	if (f->seg[0] != NULL && f->len[0] == 41) {
		WRT_CHECK_U64(wri_le64_get(f->seg[0]), seq);
		WRT_CHECK_U64(wri_le64_get(f->seg[0] + 28), ack);
		WRT_CHECK_U64(f->seg[0][36], 3);
	}
}

static void flow(int osd, uint64_t client_supported)
{
	env e;
	wrt_json j;
	int tag, l0, nseg, k, conn = osd ? 1 : 0, nsrv = client_supported == 3 ? 6 : 5;
	static uint8_t front[300], mid[10], data[100];
	size_t i;
	const sim_m2_ident *id;

	env_prep(&e, osd);
	env_start(&e);
	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/handshake-skeletons.json") == 0);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, client_supported, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(e.t.banner.supported, 3);
	WRT_CHECK_U64(e.t.banner.required, 0);
	WRT_CHECK_U64(e.t.nfr, (size_t)nsrv);

	/* server frames in the order and with the lengths of the captured connection: HELLO, REPLY_MORE,
	 * DONE, SIGNATURE, [COMPRESSION_DONE], SERVER_IDENT */
	for (k = 0; k < nsrv && k < (int)e.t.nfr; k++) {
		int sk = (client_supported != 3 && k == 4) ? 5 : k; /* no COMPRESSION_DONE without the bit */
		WRT_CHECK(skeleton(&j, conn, sk, &tag, &l0, &nseg));
		WRT_CHECK_U64(e.t.fr[k].tag, tag);
		WRT_CHECK_U64(e.t.fr[k].len[0], l0);
		WRT_CHECK_U64(e.t.fr[k].nseg, nseg);
	}
	/* HELLO: our type and the client's address as the server sees it */
	WRT_CHECK_U64(e.t.fr[0].seg[0][0], osd ? SIM_M2_ENT_OSD : SIM_M2_ENT_MON);
	{
		uint8_t want[SIM_M2_ADDR4_LEN];

		sim_m2_put_addr4(want, 2, 0, TC_CLIENT_IP, 50000);
		WRT_CHECK_MEM(e.t.fr[0].seg[0] + 1, want, sizeof(want));
	}
	/* AUTH_DONE: global id, mode 1, the scripted payload */
	WRT_CHECK_U64(wri_le64_get(e.t.fr[2].seg[0]), 4242);
	WRT_CHECK_U64(wri_le32_get(e.t.fr[2].seg[0] + 8), 1);
	WRT_CHECK_U64(wri_le32_get(e.t.fr[2].seg[0] + 12), e.sc.done_len);
	/* what the script saw */
	WRT_CHECK_U64(e.sc.n_request, 1);
	WRT_CHECK_U64(e.sc.n_more, 1);
	WRT_CHECK_U64(e.sc.last_method, 2);
	WRT_CHECK_U64(e.sc.last_nmodes, 1);
	WRT_CHECK_U64(e.sc.last_modes[0], 1);
	WRT_CHECK_U64(e.sc.last_more_len, 40);
	/* SERVER_IDENT: [target echoed, legacy twin], gid, seq echo, features, lossy flag */
	{
		const tc_frame *si = tc_last(&e.t);
		uint8_t want[SIM_M2_ADDR4_LEN], leg[SIM_M2_ADDR4_LEN];
		const uint8_t *p = si->seg[0];

		WRT_CHECK_U64(si->tag, WRI_M2_TAG_SERVER_IDENT);
		WRT_CHECK_U64(si->len[0], 123);
		sim_m2_put_addr4(want, 2, 0, TC_SERVER_IP, 3300);
		sim_m2_put_addr4(leg, 1, 0, TC_SERVER_IP, 6789);
		WRT_CHECK(p[0] == 2 && wri_le32_get(p + 1) == 2);
		WRT_CHECK_MEM(p + 5, want, sizeof(want));
		WRT_CHECK_MEM(p + 5 + 35, leg, sizeof(leg));
		WRT_CHECK_U64(wri_le64_get(p + 75), 1);              /* gid */
		WRT_CHECK_U64(wri_le64_get(p + 83), 1);              /* global_seq echoes the client's */
		WRT_CHECK_U64(wri_le64_get(p + 91), 0x3f07fffffffdffffull);
		WRT_CHECK_U64(wri_le64_get(p + 99), 0x0800000000000000ull);
		WRT_CHECK_U64(wri_le64_get(p + 107), 1);             /* lossy */
		WRT_CHECK_U64(wri_le64_get(p + 115), 0);             /* cookie */
	}
	id = &e.s->ident;
	WRT_CHECK_U64(id->n_addrs, 1);
	WRT_CHECK_U64(id->addrs_len, 35);
	WRT_CHECK_U64(id->target_len, 35);
	WRT_CHECK_U64((uint64_t)id->gid, (uint64_t)-1);
	WRT_CHECK_U64(id->global_seq, 1);
	WRT_CHECK_U64(id->supported, 0x3f07fffffffdffffull);
	WRT_CHECK_U64(id->flags, 1);
	WRT_CHECK_U64(wri_le32_get(id->addrs + 7), 3);       /* the client's own address: type ANY, port 0 */
	WRT_CHECK_U64(wri_le32_get(id->addrs + 11), 0x1234); /* with its nonce */
	WRT_CHECK_U64(e.s->client_hello_type, SIM_M2_ENT_CLIENT);
	WRT_CHECK_U64(e.s->compression_requested, client_supported == 3 ? 1 : 0);

	/* the first client frames of the captured connection: MESSAGEs 1 and 2 (and a 4-segment one for an OSD) */
	for (i = 0; i < sizeof(front); i++)
		front[i] = (uint8_t)(i * 7);
	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i + 1);
	WRT_CHECK_U64(tc_send_msg(&e.t, e.s, 1, 11, 0x10, NULL, 0, NULL, 0, NULL, 0), 77u);
	WRT_CHECK_U64(tc_send_msg(&e.t, e.s, 2, 12, 0x11, front, 58, NULL, 0, NULL, 0), 148u);
	WRT_CHECK_U64(tc_send_msg(&e.t, e.s, 3, 13, 0x12, front, 224, mid, 0, data, 100), 414u);
	WRT_CHECK_U64(e.s->n_msgs, 3);
	WRT_CHECK_U64(e.s->in_seq, 3);
	WRT_CHECK_U64(e.s->msgs[0].seq, 1);
	WRT_CHECK_U64(e.s->msgs[0].nseg, 1);
	WRT_CHECK_U64(e.s->msgs[0].tid, 11);
	WRT_CHECK_U64(e.s->msgs[0].type, 0x10);
	WRT_CHECK_U64(e.s->msgs[0].flags, 3);
	WRT_CHECK_U64(e.s->msgs[1].seg_len[0], 58);
	WRT_CHECK_MEM(e.s->msgs[1].seg[0], front, 58);
	WRT_CHECK_U64(e.s->msgs[2].nseg, 4);
	WRT_CHECK_U64(e.s->msgs[2].seg_len[0], 224);
	WRT_CHECK_U64(e.s->msgs[2].seg_len[1], 0);
	WRT_CHECK_U64(e.s->msgs[2].seg_len[2], 100);
	WRT_CHECK(e.s->msgs[2].seg[1] == NULL);
	WRT_CHECK_MEM(e.s->msgs[2].seg[2], data, 100);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK(!sim_m2_closed(e.s));
	/* nothing is answered to messages (a lossy session sends no ACK) */
	{
		size_t before = e.t.nfr;

		tc_pull(&e.t, e.s);
		WRT_CHECK_U64(e.t.nfr, before);
	}

	/* the server's own messages: 41 + front, its own seq from 1, ack_seq = what it received */
	{
		static const uint32_t mon_front[3] = {270, 188, 270};
		size_t before = e.t.nfr;

		for (k = 0; k < 3; k++) {
			uint32_t fl = osd ? 152u : mon_front[k];

			if (osd && k > 0)
				break;
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 0x20, 100u + (uint32_t)k, 3, front, fl, NULL, 0, NULL, 0));
		}
		tc_pull(&e.t, e.s);
		WRT_CHECK_U64(e.t.nfr, before + (osd ? 1u : 3u));
		for (k = 0; k < (osd ? 1 : 3); k++)
			if (e.t.nfr > before + (size_t)k)
				check_msg_frame(&e.t.fr[before + (size_t)k], (uint64_t)k + 1u, 3, osd ? 152u : mon_front[k]);
		WRT_CHECK_U64(e.s->out_seq, osd ? 1u : 3u);
	}
	WRT_CHECK_U64(e.t.rx_err, 0);
	wrt_json_free(&j);
	env_end(&e);
}

/* ---- keepalive, ack, server-initiated frames ------------------------------------------------------------ */

static void keepalive(void)
{
	env e;
	tb p;
	size_t before;

	env_prep(&e, 0);
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 3, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	/* KEEPALIVE2 -> KEEPALIVE2_ACK carrying the same stamp */
	p.n = 0;
	tb_u32(&p, 1700000000u);
	tb_u32(&p, 123456789u);
	before = e.t.nfr;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.nfr, before + 1);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_KEEPALIVE2_ACK);
	WRT_CHECK_U64(tc_last(&e.t)->len[0], 8);
	WRT_CHECK_MEM(tc_last(&e.t)->seg[0], p.b, 8);
	WRT_CHECK_U64(e.s->n_keepalive, 1);
	WRT_CHECK_U64(e.s->last_ka_sec, 1700000000u);
	WRT_CHECK_U64(e.s->last_ka_nsec, 123456789u);
	/* the server's own KEEPALIVE2, and the client's ACK of it, are tolerated */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(e.s, 5, 6));
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_KEEPALIVE2);
	p.n = 0;
	tb_u32(&p, 5);
	tb_u32(&p, 6);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2_ACK, &p);
	WRT_CHECK_U64(e.s->n_keepalive_ack, 1);
	WRT_CHECK_U64(e.s->last_kaack_sec, 5);
	p.n = 0;
	tb_u64(&p, 9);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_ACK, &p);
	WRT_CHECK_U64(e.s->n_ack, 1);
	WRT_CHECK_U64(e.s->last_ack_seq, 9);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	/* a message after them still has to be seq 1 */
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, NULL, 0, NULL, 0, NULL, 0);
	WRT_CHECK_U64(e.s->n_msgs, 1);
	env_end(&e);
}

/* ---- delivery granularity ------------------------------------------------------------------------------- */

static void split(void)
{
	env a, b;
	size_t i;
	static uint8_t big[5000];

	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)(i * 13);
	env_prep(&a, 0);
	env_start(&a);
	env_prep(&b, 0);
	b.cfg.f.out_chunk = 1;                      /* the server's bytes one at a time ... */
	env_start(&b);
	b.t.feed_chunk = 1;                         /* ... and the client's bytes one at a time */
	WRT_CHECK_U64(tc_drive(&a.t, a.s, 3, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(tc_drive(&b.t, b.s, 3, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(b.t.rx_err, 0);
	WRT_CHECK_U64(sim_m2_error(b.s)->status, 0);
	WRT_CHECK_U64(a.s->tx_log_len, b.s->tx_log_len);
	WRT_CHECK_MEM(a.s->tx_log, b.s->tx_log, a.s->tx_log_len);
	WRT_CHECK_U64(a.s->delivered, b.s->delivered);
	WRT_CHECK_U64(a.s->rx_log_len, b.s->rx_log_len);
	WRT_CHECK_U64(a.s->ident.global_seq, b.s->ident.global_seq);
	(void)tc_send_msg(&b.t, b.s, 1, 7, 9, big, 5000, big, 700, big, 3000);
	WRT_CHECK_U64(b.s->n_msgs, 1);
	WRT_CHECK_U64(b.s->msgs[0].seg_len[2], 3000);
	WRT_CHECK_MEM(b.s->msgs[0].seg[0], big, 5000);
	/* a one-byte drain never returns more than one byte */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(b.s, 1, 1, 1, big, 100, NULL, 0, big, 50));
	{
		uint8_t x[16];

		WRT_CHECK_U64(sim_m2_drain(b.s, x, sizeof(x)), 1);
	}
	env_end(&a);
	env_end(&b);
}

/* ---- AUTH_BAD_METHOD and a fresh attempt on the same connection -------------------------------------------- */

static void bad_method(void)
{
	env e;
	tb p;
	size_t before, sent_before_sig;
	uint8_t sig[32];
	const tc_frame *f;

	env_prep(&e, 0);
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	/* unknown method 99: -EOPNOTSUPP, allowed methods [2], allowed modes [1, 2] (the server's own order) */
	tc_pay_auth_request(&p, 99, SIM_M2_MODE_CRC, 8);
	before = e.t.nfr;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.nfr, before + 1);
	f = tc_last(&e.t);
	WRT_CHECK_U64(f->tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	WRT_CHECK_U64(f->len[0], 4 + 4 + 8 + 12);
	WRT_CHECK_U64(wri_le32_get(f->seg[0]), 99);
	WRT_CHECK_U64((int32_t)wri_le32_get(f->seg[0] + 4), -95);
	WRT_CHECK_U64(wri_le32_get(f->seg[0] + 8), 1);
	WRT_CHECK_U64(wri_le32_get(f->seg[0] + 12), 2);
	WRT_CHECK_U64(wri_le32_get(f->seg[0] + 16), 2);
	WRT_CHECK_U64(wri_le32_get(f->seg[0] + 20), 1);
	WRT_CHECK_U64(wri_le32_get(f->seg[0] + 24), 2);
	WRT_CHECK_U64(e.sc.n_request, 0); /* the callback was never asked */
	/* a mode the server does not know: -EOPNOTSUPP again */
	tc_pay_auth_request(&p, 2, 7, 8);
	before = e.t.nfr;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.nfr, before + 1);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	/* a fresh, valid AUTH_REQUEST on the same connection works; both refusals are in the transcripts */
	tc_pay_auth_request(&p, 2, SIM_M2_MODE_CRC, 24);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pay_blob(&p, 40, 0x42);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_U64(e.s->tx_log_len, e.t.log_len);
	WRT_CHECK_MEM(e.s->tx_log, e.t.log, e.t.log_len);
	tc_hmac(TC_KEY, 32, e.t.log, e.t.log_len, sig);
	sent_before_sig = e.t.sent_len;
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_SIGNATURE);
	tc_hmac(TC_KEY, 32, e.t.sent, sent_before_sig, sig);
	WRT_CHECK_MEM(tc_last(&e.t)->seg[0], sig, 32);
	env_end(&e);

	/* the callback refuses (wrong key): -EACCES with the configured lists */
	env_prep(&e, 0);
	e.sc.rounds = 1;
	e.sc.fail_result = -13;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_REPLY_MORE);
	tc_pay_blob(&p, 40, 0x42);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	WRT_CHECK_U64((int32_t)wri_le32_get(tc_last(&e.t)->seg[0] + 4), -13);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_AUTH); /* still waiting for another attempt */
	env_end(&e);

	/* mode negotiation walks the CLIENT's list: [secure, crc] gives secure when both are allowed ... */
	env_prep(&e, 0);
	e.sc.rounds = 0;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	p.n = 0;
	tb_u32(&p, 2);
	tb_u32(&p, 2);
	tb_u32(&p, 2);
	tb_u32(&p, 1);
	tb_u32(&p, 0);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(wri_le32_get(tc_last(&e.t)->seg[0] + 8), 2);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_REFUSED); /* secure mode is not simulated: nothing more is read */
	env_end(&e);
	/* ... and crc when the server only allows crc */
	env_prep(&e, 0);
	e.sc.rounds = 0;
	e.cfg.modes[0] = SIM_M2_MODE_CRC;
	e.cfg.n_modes = 1;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(wri_le32_get(tc_last(&e.t)->seg[0] + 8), 1);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_SIGNATURE);
	env_end(&e);
}

/* ---- the callback may call back: on_message ----------------------------------------------------------------- */

static void echo_cb(void *ctx, sim_m2 *s, const sim_m2_msg *m)
{
	unsigned *count = (unsigned *)ctx;

	(*count)++;
	if (m->seg[0] != NULL)
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(s, m->type, m->tid, m->version, m->seg[0], m->seg_len[0], NULL, 0, NULL, 0));
}

static void on_message_hook(void)
{
	env e;
	unsigned count = 0;
	static uint8_t front[4000];
	size_t i, before;

	for (i = 0; i < sizeof(front); i++)
		front[i] = (uint8_t)(i ^ 0x5a);
	env_prep(&e, 1);
	e.cfg.max_msgs = 1;
	env_start(&e);
	e.s->on_message = echo_cb;
	e.s->on_message_ctx = &count;
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	before = e.t.nfr;
	(void)tc_send_msg(&e.t, e.s, 1, 5, 0x44, front, 4000, NULL, 0, NULL, 0);
	(void)tc_send_msg(&e.t, e.s, 2, 6, 0x45, front, 100, NULL, 0, NULL, 0);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(count, 2);
	WRT_CHECK_U64(e.s->n_msgs, 1);       /* max_msgs = 1 keeps only the first ... */
	WRT_CHECK_U64(e.s->n_msgs_seen, 2);  /* ... but counts both and still calls back */
	WRT_CHECK_U64(e.t.nfr, before + 2);
	check_msg_frame(&e.t.fr[before], 1, 1, 4000);
	WRT_CHECK_MEM(e.t.fr[before].seg[1], front, 4000);
	check_msg_frame(&e.t.fr[before + 1], 2, 2, 100);
	WRT_CHECK_U64(wri_le16_get(e.t.fr[before + 1].seg[0] + 16), 0x45);
	WRT_CHECK_U64(wri_le64_get(e.t.fr[before + 1].seg[0] + 8), 6);
	sim_m2_msgs_clear(e.s);
	WRT_CHECK_U64(e.s->n_msgs, 0);
	env_end(&e);
}

int main(void)
{
	replay(0);
	replay(1);
	flow(0, 3); /* a stock monitor connection: banner 0x3, COMPRESSION stage */
	flow(0, 1); /* banner 0x1: the server skips the compression stage */
	flow(1, 3); /* an OSD connection */
	keepalive();
	split();
	bad_method();
	on_message_hook();
	return wrt_finish();
}
