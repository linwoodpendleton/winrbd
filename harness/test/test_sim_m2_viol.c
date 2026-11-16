/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the msgr2 test server (harness/test/support/sim_m2.*), part 3: the way the server reacts to a
 * client that breaks the rules (frame in the wrong state, bad or missing signature, bad identification,
 * sequence numbers, caps), large segments, the sender's abort, API edges (send before ready, close, tags seen)
 * and pluggable auth callbacks. Same approach as part 1: hand-driven with the m2-frame builder, no module built
 * after wave 2.
 */
#include "sim_m2_tc.h"

/* ---- a client that breaks the rules ------------------------------------------------------------------------------- */

static void wrong_state(void)
{
	env e;
	tb p;
	wri_m2_seg_src two[2];

	/* MESSAGE and KEEPALIVE2 before CLIENT_IDENT: the server closes (probe results of msgr2.md) */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, NULL, 0, NULL, 0, NULL, 0);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	p.n = 0;
	tb_u64(&p, 1);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	/* AUTH_REQUEST_MORE nobody asked for */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_HELLO);
	tc_pay_blob(&p, 8, 1);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	/* HELLO twice */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_HELLO);
	tc_pay_hello(&p, 8, 3300);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_HELLO, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	/* a control frame with two segments */
	env_prep(&e, 0);
	env_start(&e);
	tc_pull(&e.t, e.s);
	(void)tc_send_banner(&e.t, e.s, 1, 0);
	tc_pay_hello(&p, 8, 3300);
	two[0].p = p.b, two[0].len = (uint32_t)p.n, two[0].ref = 0;
	two[1].p = p.b, two[1].len = 4, two[1].ref = 0;
	(void)tc_send(&e.t, e.s, WRI_M2_TAG_HELLO, two, 2);
	env_expect_closed(&e, WR_E_M2_FRAME_FORM);
	env_end(&e);
	/* the client banner lacks REVISION_1 / is garbage */
	env_prep(&e, 0);
	env_start(&e);
	(void)tc_send_banner(&e.t, e.s, 0, 0);
	env_expect_closed(&e, WR_E_M2_FEATURES);
	env_end(&e);
	env_prep(&e, 0);
	env_start(&e);
	p.n = 0;
	tb_fill(&p, 'x', 26);
	(void)sim_m2_feed(e.s, p.b, p.n);
	env_expect_closed(&e, WR_E_M2_BANNER);
	env_end(&e);
	/* compression stage: banner 0x3 but CLIENT_IDENT instead of COMPRESSION_REQUEST; banner 0x1 but a request */
	env_prep(&e, 0);
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 3, TC_ST_SIGNED, SIM_M2_ENT_CLIENT), TC_ST_SIGNED);
	tc_pay_ident(&p, 0x3f07fffffffdffffull, 1, 5);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	p.n = 0;
	tb_u8(&p, 0);
	tb_u32(&p, 0);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_COMPRESSION_REQUEST, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
}

static void signatures(void)
{
	env e;
	tb p;

	/* a wrong client signature */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_DONE);
	p.n = 0;
	tb_fill(&p, 0x5a, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_DONE); /* nothing answered */
	env_expect_closed(&e, WR_E_M2_SIGNATURE);
	env_end(&e);
	/* a signature of the wrong length */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_DONE);
	p.n = 0;
	tb_fill(&p, 0x5a, 31);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	env_expect_closed(&e, WR_E_M2_FRAME_FORM);
	env_end(&e);
	/* no session key (auth method NONE): both signatures are 32 zero bytes */
	env_prep(&e, 0);
	e.sc.key_len = 0;
	env_ready(&e, TC_ST_DONE);
	p.n = 0;
	tb_fill(&p, 0, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_AUTH_SIGNATURE);
	WRT_CHECK_U64(tc_last(&e.t)->len[0], 32);
	{
		static const uint8_t zero[32];

		WRT_CHECK_MEM(tc_last(&e.t)->seg[0], zero, 32);
	}
	env_end(&e);
}

static void idents(void)
{
	env e;
	tb p;
	uint8_t me[SIM_M2_ADDR4_LEN], blank[47];

	/* check_target: the dialled address must be ours byte for byte */
	env_prep(&e, 0);
	e.cfg.check_target = 1;
	e.cfg.server_port = 3301;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_SIGNED);
	env_expect_closed(&e, WR_E_M2_ADDR);
	env_end(&e);
	env_prep(&e, 0);
	e.cfg.check_target = 1;
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_READY);
	env_end(&e);
	/* an empty addrvec and a blank first address are refused */
	memset(blank, 0, sizeof(blank));
	blank[0] = blank[1] = blank[2] = 1;
	wri_le32_put(blank + 3, 40);
	wri_le32_put(blank + 15, 28);
	sim_m2_put_addr4(me, 2, 0, TC_SERVER_IP, 3300);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	tc_pay_ident(&p, 0x3f07fffffffdffffull, 1, 5);
	wri_le32_put(p.b + 1, 0); /* addrvec count 0 */
	p.n = 5 + 35 + 48;
	memmove(p.b + 5, p.b + 5 + 35, 35 + 48);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	env_expect_closed(&e, WR_E_M2_IDENT);
	env_end(&e);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	p.n = 0;
	tb_u8(&p, 2);
	tb_u32(&p, 1);
	tb_bytes(&p, blank, sizeof(blank));
	tb_bytes(&p, me, sizeof(me));
	tb_u64(&p, 0), tb_u64(&p, 1), tb_u64(&p, 0), tb_u64(&p, 0), tb_u64(&p, 1), tb_u64(&p, 0);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	env_expect_closed(&e, WR_E_M2_IDENT);
	env_end(&e);
	/* a truncated CLIENT_IDENT */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	tc_pay_ident(&p, 0x3f07fffffffdffffull, 1, 5);
	p.n -= 10;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	env_expect_closed(&e, WR_E_ENCODING);
	env_end(&e);
	/* configured SERVER_IDENT fields */
	env_prep(&e, 0);
	e.cfg.server_gid = 77;
	e.cfg.server_global_seq = 9;
	e.cfg.ident_flags = 0;
	e.cfg.ident_cookie = 0xc0ffee;
	e.cfg.legacy_port = 7000;
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0] + 75), 77);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0] + 83), 9);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0] + 107), 0);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0] + 115), 0xc0ffee);
	WRT_CHECK_U64(wri_be16_get(tc_last(&e.t)->seg[0] + 5 + 35 + 21), 7000);
	env_end(&e);
}

/* ---- sequence numbers ------------------------------------------------------------------------------------------ */

static void seq_strict(uint64_t a, uint64_t b, int ok_second)
{
	env e;

	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, a, 1, 1, NULL, 0, NULL, 0, NULL, 0);
	if (b != 0)
		(void)tc_send_msg(&e.t, e.s, b, 2, 1, NULL, 0, NULL, 0, NULL, 0);
	if (a == 1 && (b == 0 || ok_second)) {
		WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
		WRT_CHECK_U64(e.s->n_msgs, b == 0 ? 1u : 2u);
	} else {
		tc_pull(&e.t, e.s);
		WRT_CHECK_STATUS(WR_E_M2_SEQ, sim_m2_error(e.s)->status);
		WRT_CHECK(sim_m2_closed(e.s));
		WRT_CHECK_U64(e.s->n_msgs, a == 1 ? 1u : 0u);
	}
	env_end(&e);
}

static void seq(void)
{
	env e;

	seq_strict(1, 2, 1); /* 1, 2: fine */
	seq_strict(1, 0, 0); /* a single 1 */
	seq_strict(0, 0, 0); /* seq 0 */
	seq_strict(2, 0, 0); /* the first seq is 1 */
	seq_strict(1, 1, 0); /* repeated */
	seq_strict(1, 3, 0); /* gap */

	/* the stock daemon: a gap is accepted, an old seq silently stalls the connection (probe `kaseq`) */
	env_prep(&e, 0);
	e.cfg.seq_policy = SIM_M2_SEQ_STOCK;
	env_ready(&e, TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, NULL, 0, NULL, 0, NULL, 0);
	(void)tc_send_msg(&e.t, e.s, 3, 2, 1, NULL, 0, NULL, 0, NULL, 0);
	WRT_CHECK_U64(e.s->n_msgs, 2);
	WRT_CHECK_U64(e.s->n_seq_gaps, 1);
	WRT_CHECK_U64(e.s->in_seq, 3);
	(void)tc_send_msg(&e.t, e.s, 3, 3, 1, NULL, 0, NULL, 0, NULL, 0); /* old */
	WRT_CHECK_U64(e.s->n_msgs, 2);
	WRT_CHECK_U64(e.s->n_seq_dups, 1);
	(void)tc_send_msg(&e.t, e.s, 4, 4, 1, NULL, 0, NULL, 0, NULL, 0); /* never read */
	WRT_CHECK_U64(e.s->n_msgs, 2);
	WRT_CHECK_U64(e.s->in_seq, 3);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK(!sim_m2_closed(e.s)); /* silent, still open */
	env_end(&e);
}

/* ---- caps, big segments, the sender's abort ---------------------------------------------------------------------- */

static void caps_and_big(void)
{
	env e;
	static uint8_t a[700000], b[300000], c[2000];
	size_t i;

	for (i = 0; i < sizeof(a); i++)
		a[i] = (uint8_t)(i * 31 + (i >> 8));
	for (i = 0; i < sizeof(b); i++)
		b[i] = (uint8_t)(i * 17);
	/* a 700 KB data segment in, and 200 KB front + 1 KB middle + 300 KB data out, intact */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, c, 2000, NULL, 0, a, sizeof(a));
	WRT_CHECK_U64(e.s->n_msgs, 1);
	WRT_CHECK_U64(e.s->msgs[0].seg_len[2], sizeof(a));
	WRT_CHECK_MEM(e.s->msgs[0].seg[2], a, sizeof(a));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 9, 1, 2, a, 200000, c, 1000, b, sizeof(b)));
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_U64(e.t.nfr, 6);
	WRT_CHECK_U64(e.t.fr[5].len[1], 200000);
	WRT_CHECK_U64(e.t.fr[5].len[2], 1000);
	WRT_CHECK_U64(e.t.fr[5].len[3], sizeof(b));
	WRT_CHECK_MEM(e.t.fr[5].seg[1], a, 200000);
	WRT_CHECK_MEM(e.t.fr[5].seg[3], b, sizeof(b));
	env_end(&e);
	/* segments above seg_cap */
	env_prep(&e, 0);
	e.cfg.seg_cap = 1024;
	env_ready(&e, TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, c, 2000, NULL, 0, NULL, 0);
	env_expect_closed(&e, WR_E_M2_FRAME_TOOBIG);
	env_end(&e);
	/* pre-auth logs have a cap too */
	env_prep(&e, 0);
	e.cfg.preauth_cap = 100;
	env_start(&e);
	(void)tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT);
	WRT_CHECK_STATUS(WR_E_M2_PREAUTH_TOOBIG, sim_m2_error(e.s)->status);
	env_end(&e);
	/* a frame the sender aborted (late_status 1) is dropped without a word */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	e.t.patch_late = 0x01;
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, c, 100, NULL, 0, NULL, 0);
	e.t.patch_late = 0;
	WRT_CHECK_U64(e.s->n_msgs, 0);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, c, 100, NULL, 0, NULL, 0);
	WRT_CHECK_U64(e.s->n_msgs, 1);
	e.t.patch_late = 0x03; /* any other low nibble is a frame error */
	(void)tc_send_msg(&e.t, e.s, 2, 1, 1, c, 100, NULL, 0, NULL, 0);
	env_expect_closed(&e, WR_E_M2_FRAME_FORM);
	env_end(&e);
}

/* ---- API edges: send before ready, close, tags seen ---------------------------------------------------------------- */

static void api_edges(void)
{
	env e;
	tb p;
	uint8_t buf[256];
	size_t n;

	env_prep(&e, 0);
	env_start(&e);
	WRT_CHECK_STATUS(WR_E_STATE, sim_m2_send_message(e.s, 1, 1, 1, NULL, 0, NULL, 0, NULL, 0));
	WRT_CHECK_STATUS(WR_E_STATE, sim_m2_send_keepalive(e.s, 1, 1));
	env_end(&e);

	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_U64(e.s->n_rx_frames, 5);
	WRT_CHECK_U64(e.s->rx_tags[0], WRI_M2_TAG_HELLO);
	WRT_CHECK_U64(e.s->rx_tags[1], WRI_M2_TAG_AUTH_REQUEST);
	WRT_CHECK_U64(e.s->rx_tags[2], WRI_M2_TAG_AUTH_REQUEST_MORE);
	WRT_CHECK_U64(e.s->rx_tags[3], WRI_M2_TAG_AUTH_SIGNATURE);
	WRT_CHECK_U64(e.s->rx_tags[4], WRI_M2_TAG_CLIENT_IDENT);
	WRT_CHECK_U64(e.s->n_rx_by_tag[WRI_M2_TAG_HELLO], 1);
	/* a frame queued and then the server closes: the client still reads it, then EOF */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(e.s, 1, 2));
	sim_m2_close(e.s);
	WRT_CHECK(!sim_m2_closed(e.s));
	n = sim_m2_drain(e.s, buf, sizeof(buf));
	WRT_CHECK_U64(n, 44);
	WRT_CHECK(sim_m2_closed(e.s));
	WRT_CHECK_STATUS(WR_E_STATE, sim_m2_send_keepalive(e.s, 1, 2));
	WRT_CHECK_STATUS(WR_E_STATE, sim_m2_send_frame(e.s, WRI_M2_TAG_WAIT, NULL, 1));
	env_end(&e);

	/* no_keepalive_ack: swallowed, still counted */
	env_prep(&e, 0);
	e.cfg.f.no_keepalive_ack = 1;
	env_ready(&e, TC_ST_IDENT);
	p.n = 0;
	tb_u64(&p, 77);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.s->n_keepalive, 1);
	WRT_CHECK_U64(e.t.nfr, 5);
	env_end(&e);
}

/* ---- pluggable auth callbacks --------------------------------------------------------------------------------------- */

static int cb_close(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
		    uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n, (void)rep;
	return SIM_AUTH_CLOSE;
}

static int cb_custom_bad(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			 uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n;
	rep->result = -1234;
	rep->methods[0] = 1, rep->methods[1] = 2, rep->methods[2] = 4, rep->n_methods = 3;
	rep->modes[0] = 2, rep->n_modes = 1;
	return SIM_AUTH_BAD_METHOD;
}

static int cb_done_mode(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n;
	rep->global_id = 99;
	rep->mode = 1;
	rep->payload = (const uint8_t *)"abc";
	rep->payload_len = 3;
	return SIM_AUTH_DONE;
}

static void callbacks(void)
{
	sim_m2_auth_ops ops;
	sim_m2_cfg cfg;
	sim_m2 *s;
	env e;
	tc t;
	tb p;

	memset(&ops, 0, sizeof(ops));
	/* the server drops the connection without a frame */
	env_prep(&e, 0);
	env_start(&e);
	e.ops.request = cb_close;
	e.s->auth = e.ops;
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	tc_pull(&e.t, e.s);
	WRT_CHECK(sim_m2_closed(e.s));
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	env_end(&e);

	sim_m2_cfg_default(&cfg);
	/* BAD_METHOD with the callback's own result and lists */
	ops.request = cb_custom_bad;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	WRT_CHECK_U64(tc_last(&t)->tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	WRT_CHECK_U64((int32_t)wri_le32_get(tc_last(&t)->seg[0] + 4), -1234);
	WRT_CHECK_U64(tc_last(&t)->len[0], 4 + 4 + 16 + 8);
	WRT_CHECK_U64(wri_le32_get(tc_last(&t)->seg[0] + 8), 3);
	WRT_CHECK_U64(wri_le32_get(tc_last(&t)->seg[0] + 24), 1);
	WRT_CHECK_U64(wri_le32_get(tc_last(&t)->seg[0] + 28), 2);
	tc_free(&t);
	sim_m2_free(s);

	/* DONE with its own global id and an explicit mode, no REPLY_MORE round, no key: zero signature */
	ops.request = cb_done_mode;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	tc_pay_auth_request(&p, 2, 1, 4);
	(void)tc_send_ctl(&t, s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&t, s);
	WRT_CHECK_U64(tc_last(&t)->tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(wri_le64_get(tc_last(&t)->seg[0]), 99);
	WRT_CHECK_U64(tc_last(&t)->len[0], 8 + 4 + 4 + 3);
	WRT_CHECK_U64(s->global_id, 99);
	WRT_CHECK_U64(s->key_len, 0);
	tc_free(&t);
	sim_m2_free(s);
	/* no callbacks at all: every AUTH_REQUEST is answered with AUTH_DONE */
	s = sim_m2_new(NULL, NULL);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	tc_pay_auth_request(&p, 2, 1, 4);
	(void)tc_send_ctl(&t, s, WRI_M2_TAG_AUTH_REQUEST, &p);
	tc_pull(&t, s);
	WRT_CHECK_U64(tc_last(&t)->tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(wri_le64_get(tc_last(&t)->seg[0]), 4242);
	tc_free(&t);
	sim_m2_free(s);
}

int main(void)
{
	wrong_state();
	signatures();
	idents();
	seq();
	caps_and_big();
	api_edges();
	callbacks();
	return wrt_finish();
}
