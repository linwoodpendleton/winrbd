/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the msgr2 test server (harness/test/support/sim_m2.*), part 4: hardening. What a hostile or
 * clumsy client or test author can do to the server itself: malformed control payloads of every handshake
 * frame, address structures that lie about their own length, signatures that differ in one bit anywhere,
 * required banner features, configurations the server must refuse, callbacks that hand back oversize lengths
 * or lists, the output and recording budgets. Everything is checked under the sanitizers of the harness build.
 * Same approach as parts 1 to 3: hand-driven with the m2-frame builder.
 */
#include "sim_m2_tc.h"

#define FEAT_ALL 0x3f07fffffffdffffull

/* A CLIENT_IDENT payload from tc_pay_ident, to be patched: addrvec marker at 0, count at 1, the first address
 * (35 bytes) at 5: marker 5, struct_v 6, struct_compat 7, struct_len 8, type 12, nonce 16, elen 20. */
static void ident_closed_with(void (*patch)(tb *), wr_status why)
{
	env e;
	tb p;

	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	tc_pay_ident(&p, FEAT_ALL, 1, 5);
	patch(&p);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	env_expect_closed(&e, why);
	env_end(&e);
}

static void pt_compat2(tb *p) { p->b[5 + 2] = 2; }
static void pt_elen_short(tb *p) { wri_le32_put(p->b + 5 + 15, 10); }
static void pt_elen_long(tb *p) { wri_le32_put(p->b + 5 + 15, 17); }
static void pt_len_small(tb *p) { wri_le32_put(p->b + 5 + 3, 5); }
static void pt_len_huge(tb *p) { wri_le32_put(p->b + 5 + 3, 0xfffffff0u); }
static void pt_len_64(tb *p) { wri_le32_put(p->b + 5 + 3, 58); } /* one more than the server stores */
static void pt_marker0(tb *p) { p->b[5] = 0; }
static void pt_vec_marker1(tb *p) { p->b[0] = 1; }
static void pt_vec_marker3(tb *p) { p->b[0] = 3; }
static void pt_count3(tb *p) { wri_le32_put(p->b + 1, 3); }
static void pt_count2_short(tb *p) { wri_le32_put(p->b + 1, 2); } /* the target becomes the second address, the real one is missing */
static void pt_trailing(tb *p) { tb_u8(p, 0); }
static void pt_empty(tb *p) { p->n = 0; }
static void pt_target_bad(tb *p) { p->b[5 + 35 + 2] = 9; } /* target_addr: struct_compat 9 */

static void idents(void)
{
	env e;
	tb p;
	uint8_t a2[SIM_M2_ADDR4_LEN];

	ident_closed_with(pt_compat2, WR_E_ENCODING);
	ident_closed_with(pt_elen_short, WR_E_ENCODING);
	ident_closed_with(pt_elen_long, WR_E_ENCODING);
	ident_closed_with(pt_len_small, WR_E_ENCODING);
	ident_closed_with(pt_len_huge, WR_E_ENCODING);
	ident_closed_with(pt_len_64, WR_E_ENCODING);
	ident_closed_with(pt_marker0, WR_E_ENCODING);
	ident_closed_with(pt_vec_marker1, WR_E_ENCODING);
	ident_closed_with(pt_vec_marker3, WR_E_ENCODING);
	ident_closed_with(pt_count3, WR_E_M2_IDENT);
	ident_closed_with(pt_count2_short, WR_E_ENCODING);
	ident_closed_with(pt_trailing, WR_E_ENCODING);
	ident_closed_with(pt_empty, WR_E_ENCODING);
	ident_closed_with(pt_target_bad, WR_E_ENCODING);

	/* two addresses in the addrvec are fine, both are recorded back to back */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	sim_m2_put_addr4(a2, 3, 77, TC_CLIENT_IP, 0);
	tc_pay_ident(&p, FEAT_ALL, 1, 5);
	wri_le32_put(p.b + 1, 2);
	memmove(p.b + 5 + 70, p.b + 5 + 35, p.n - (5 + 35));
	memcpy(p.b + 5 + 35, a2, sizeof(a2));
	p.n += 35;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_CLIENT_IDENT, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(e.s->ident.n_addrs, 2);
	WRT_CHECK_U64(e.s->ident.addrs_len, 70);
	WRT_CHECK_MEM(e.s->ident.addrs + 35, a2, 35);
	env_end(&e);
}

/* ---- the other handshake payloads -------------------------------------------------------------------- */

static void hello_bad(int variant)
{
	env e;
	tb p;

	env_prep(&e, 0);
	env_start(&e);
	tc_pull(&e.t, e.s);
	(void)tc_send_banner(&e.t, e.s, 1, 0);
	tc_pay_hello(&p, SIM_M2_ENT_CLIENT, 3300);
	switch (variant) {
	case 0:
		tb_u8(&p, 0); /* a trailing byte */
		break;
	case 1:
		p.n -= 1; /* one byte short */
		break;
	case 2:
		p.n = 0; /* empty */
		break;
	case 3:
		wri_le32_put(p.b + 1 + 3, 5); /* the address struct is too short for its own fields */
		break;
	default:
		p.b[1] = 0; /* address marker 0 (the legacy form) */
		break;
	}
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_HELLO, &p);
	env_expect_closed(&e, WR_E_ENCODING);
	env_end(&e);
}

static void auth_payloads(void)
{
	env e;
	tb p;
	int v;

	for (v = 0; v < 8; v++) {
		env_prep(&e, 0);
		env_ready(&e, TC_ST_HELLO);
		p.n = 0;
		tb_u32(&p, 2);
		switch (v) {
		case 0: /* nine preferred modes: more than the server stores */
			tb_u32(&p, 9);
			tb_fill(&p, 1, 36);
			tb_u32(&p, 0);
			break;
		case 1: /* the preferred-mode count claims more than the frame holds */
			tb_u32(&p, 0xffffffffu);
			break;
		case 2: /* a payload length that runs past the frame */
			tb_u32(&p, 1);
			tb_u32(&p, 1);
			tb_u32(&p, 0xffffffffu);
			break;
		case 3: /* a payload length one past the frame */
			tb_u32(&p, 1);
			tb_u32(&p, 1);
			tb_u32(&p, 5);
			tb_fill(&p, 7, 4);
			break;
		case 4: /* a trailing byte after the payload */
			tb_u32(&p, 1);
			tb_u32(&p, 1);
			tb_u32(&p, 1);
			tb_u8(&p, 7);
			tb_u8(&p, 7);
			break;
		case 5: /* truncated in the mode list */
			tb_u32(&p, 2);
			tb_u32(&p, 1);
			break;
		case 6: /* only the method */
			break;
		default: /* empty frame */
			p.n = 0;
			break;
		}
		(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST, &p);
		env_expect_closed(&e, WR_E_ENCODING);
		WRT_CHECK_U64(e.sc.n_request, 0); /* the callback never saw a malformed request */
		env_end(&e);
	}
	/* AUTH_REQUEST_MORE: length past the frame, trailing byte, empty */
	for (v = 0; v < 3; v++) {
		env_prep(&e, 0);
		env_ready(&e, TC_ST_REPLY_MORE);
		p.n = 0;
		if (v == 0) {
			tb_u32(&p, 100);
			tb_fill(&p, 1, 8);
		} else if (v == 1) {
			tb_u32(&p, 2);
			tb_fill(&p, 1, 3);
		}
		(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
		env_expect_closed(&e, WR_E_ENCODING);
		WRT_CHECK_U64(e.sc.n_more, 0);
		env_end(&e);
	}
	/* COMPRESSION_REQUEST: a method count the frame cannot hold, a trailing byte, empty */
	for (v = 0; v < 3; v++) {
		env_prep(&e, 0);
		env_start(&e);
		WRT_CHECK_U64(tc_drive(&e.t, e.s, 3, TC_ST_SIGNED, SIM_M2_ENT_CLIENT), TC_ST_SIGNED);
		p.n = 0;
		if (v == 0) {
			tb_u8(&p, 0);
			tb_u32(&p, 0xffffffffu);
		} else if (v == 1) {
			tb_u8(&p, 0);
			tb_u32(&p, 0);
			tb_u8(&p, 0);
		}
		(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_COMPRESSION_REQUEST, &p);
		env_expect_closed(&e, WR_E_ENCODING);
		WRT_CHECK_U64(e.s->compression_requested, 0);
		env_end(&e);
	}
	/* ... and a well formed one with methods is accepted */
	env_prep(&e, 0);
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 3, TC_ST_SIGNED, SIM_M2_ENT_CLIENT), TC_ST_SIGNED);
	p.n = 0;
	tb_u8(&p, 0);
	tb_u32(&p, 2);
	tb_u32(&p, 1);
	tb_u32(&p, 2);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_COMPRESSION_REQUEST, &p);
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_COMPRESSION_DONE);
	env_end(&e);
}

static void session_payloads(void)
{
	env e;
	tb p;
	uint8_t h[SIM_M2_HDR2_LEN];
	wri_m2_seg_src seg;
	int k;

	/* a MESSAGE whose segment 0 is shorter than ceph_msg_header2 */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	tc_pay_hdr2(h, 1, 1, 1, 0);
	seg.p = h, seg.len = SIM_M2_HDR2_LEN - 1u, seg.ref = 0;
	(void)tc_send(&e.t, e.s, WRI_M2_TAG_MESSAGE, &seg, 1);
	env_expect_closed(&e, WR_E_M2_FRAME_FORM);
	WRT_CHECK_U64(e.s->n_msgs, 0);
	env_end(&e);
	/* a MESSAGE with an empty segment 0 */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	seg.p = h, seg.len = 0, seg.ref = 0;
	(void)tc_send(&e.t, e.s, WRI_M2_TAG_MESSAGE, &seg, 1);
	env_expect_closed(&e, WR_E_M2_FRAME_FORM);
	env_end(&e);
	/* KEEPALIVE2 of 7 and of 9 bytes, empty */
	for (k = 0; k < 3; k++) {
		tb q;

		env_prep(&e, 0);
		env_ready(&e, TC_ST_IDENT);
		q.n = 0;
		tb_fill(&q, 1, k == 0 ? 7u : k == 1 ? 9u : 0u);
		(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2, &q);
		env_expect_closed(&e, WR_E_M2_FRAME_FORM);
		WRT_CHECK_U64(e.s->n_keepalive, 0);
		env_end(&e);
	}
	/* KEEPALIVE2_ACK and ACK of the wrong size are state errors (not valid in this shape) */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	p.n = 0;
	tb_fill(&p, 1, 7);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_KEEPALIVE2_ACK, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	p.n = 0;
	tb_fill(&p, 1, 4);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_ACK, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	WRT_CHECK_U64(e.s->n_ack, 0);
	env_end(&e);
	/* tags that only a server sends, or reconnect frames, are refused in READY */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	p.n = 0;
	tb_u64(&p, 1);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_SERVER_IDENT, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	p.n = 0;
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_SESSION_RECONNECT, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
}

/* ---- AUTH_SIGNATURE differing in any single bit --------------------------------------------------------- */

static void signature_bits(void)
{
	env e;
	tb p;
	uint8_t sig[32];
	unsigned i;

	for (i = 0; i < 32u * 8u; i += 5) { /* every byte, a varying bit of it */
		env_prep(&e, 0);
		env_ready(&e, TC_ST_DONE);
		tc_hmac(TC_KEY, sizeof(TC_KEY), e.t.log, e.t.log_len, sig);
		sig[i / 8u] ^= (uint8_t)(1u << (i % 8u));
		p.n = 0;
		tb_bytes(&p, sig, 32);
		(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
		env_expect_closed(&e, WR_E_M2_SIGNATURE);
		env_end(&e);
	}
	/* a key of the wrong length signs differently: the first 31 bytes of the right key are refused */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_DONE);
	tc_hmac(TC_KEY, sizeof(TC_KEY) - 1u, e.t.log, e.t.log_len, sig);
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	env_expect_closed(&e, WR_E_M2_SIGNATURE);
	env_end(&e);
	/* an all-zero signature is only right when the server has no session key */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_DONE);
	p.n = 0;
	tb_fill(&p, 0, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	env_expect_closed(&e, WR_E_M2_SIGNATURE);
	env_end(&e);
	/* and the other way: with no key a signed (non-zero) client signature is refused */
	env_prep(&e, 0);
	e.sc.key_len = 0;
	env_ready(&e, TC_ST_DONE);
	tc_hmac(TC_KEY, sizeof(TC_KEY), e.t.log, e.t.log_len, sig);
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	env_expect_closed(&e, WR_E_M2_SIGNATURE);
	env_end(&e);
	/* a second AUTH_SIGNATURE after the exchange is a state error */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_SIGNED);
	tc_hmac(TC_KEY, sizeof(TC_KEY), e.t.log, e.t.log_len, sig);
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(&e.t, e.s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	env_expect_closed(&e, WR_E_M2_STATE);
	env_end(&e);
}

/* ---- banner features the server requires --------------------------------------------------------------- */

static void banner_required(void)
{
	env e;
	uint8_t b[WRI_M2_BANNER_LEN];

	/* the server requires COMPRESSION (bit 1); a client that does not advertise it is dropped */
	env_prep(&e, 0);
	e.cfg.banner_required = 2;
	env_start(&e);
	wri_m2_banner_build(b); /* supported 1, required 0 */
	WRT_CHECK_U64(tc_feed(&e.t, e.s, b, sizeof(b)), sizeof(b));
	env_expect_closed(&e, WR_E_M2_FEATURES);
	WRT_CHECK_U64(sim_m2_error(e.s)->a0, 2);
	WRT_CHECK_U64(sim_m2_error(e.s)->a1, 1);
	env_end(&e);
	/* a client that does advertise it gets on */
	env_prep(&e, 0);
	e.cfg.banner_required = 2;
	env_start(&e);
	(void)tc_send_banner(&e.t, e.s, 3, 0);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_HELLO);
	env_end(&e);
}

/* ---- configurations the server refuses ----------------------------------------------------------------- */

static void bad_configs(void)
{
	sim_m2_cfg c;
	sim_m2 *s;

	sim_m2_cfg_default(&c);
	c.n_methods = SIM_M2_LIST_MAX + 1u;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	sim_m2_cfg_default(&c);
	c.n_modes = SIM_M2_LIST_MAX + 1u;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	sim_m2_cfg_default(&c);
	c.n_methods = 0xffffffffu;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	sim_m2_cfg_default(&c);
	c.ctl_cap = 0;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	sim_m2_cfg_default(&c);
	c.seg_cap = 0;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	/* 16 KiB + 2 * 2^31 + 512 does not fit the 32-bit encode buffer size: refused, not wrapped to a small one */
	sim_m2_cfg_default(&c);
	c.seg_cap = 0x80000000u;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	sim_m2_cfg_default(&c);
	c.ctl_cap = 0xffffffffu;
	c.seg_cap = 0xffffffffu;
	WRT_CHECK(sim_m2_new(&c, NULL) == NULL);
	/* the limits themselves are fine */
	sim_m2_cfg_default(&c);
	c.n_methods = SIM_M2_LIST_MAX;
	c.n_modes = SIM_M2_LIST_MAX;
	s = sim_m2_new(&c, NULL);
	WRT_CHECK(s != NULL);
	sim_m2_free(s);
	sim_m2_free(NULL);
}

/* ---- callbacks that hand back too much ------------------------------------------------------------------- */

static int cb_long_lists(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			 uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n;
	rep->n_methods = SIM_M2_LIST_MAX + 1u;
	return SIM_AUTH_BAD_METHOD;
}

static int cb_bad_plain(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n, (void)rep;
	return SIM_AUTH_BAD_METHOD; /* no result: a failed authentication */
}

static int cb_null_payload(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			   uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n;
	rep->payload = NULL;
	rep->payload_len = 77; /* a lie: no bytes behind it, sent as an empty payload */
	return SIM_AUTH_MORE;
}

static int cb_unknown(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
		      uint32_t n, sim_m2_auth_reply *rep)
{
	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n, (void)rep;
	return 99;
}

static int cb_big_more(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
		       uint32_t n, sim_m2_auth_reply *rep)
{
	static uint8_t big[64];

	(void)ctx, (void)method, (void)modes, (void)nmodes, (void)p, (void)n;
	rep->payload = big;
	rep->payload_len = 100000; /* far above ctl_cap; the sim must not read 100000 bytes of `big` */
	return SIM_AUTH_MORE;
}

static void callbacks(void)
{
	sim_m2_auth_ops ops;
	sim_m2 *s;
	tc t;
	sim_m2_cfg cfg;

	memset(&ops, 0, sizeof(ops));
	sim_m2_cfg_default(&cfg);

	ops.request = cb_long_lists;
	s = sim_m2_new(&cfg, &ops);
	WRT_CHECK(s != NULL);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	tc_pull(&t, s);
	WRT_CHECK_STATUS(WR_E_INVAL, sim_m2_error(s)->status);
	WRT_CHECK(sim_m2_closed(s));
	tc_free(&t);
	sim_m2_free(s);

	ops.request = cb_bad_plain;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_HELLO);
	WRT_CHECK_U64(tc_last(&t)->tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	WRT_CHECK_U64((int32_t)wri_le32_get(tc_last(&t)->seg[0] + 4), -13); /* EACCES, as sim_m2.h says */
	WRT_CHECK_U64(wri_le32_get(tc_last(&t)->seg[0]), 2);                /* the method is echoed */
	WRT_CHECK_U64(s->state, SIM_M2_ST_AUTH);
	tc_free(&t);
	sim_m2_free(s);

	ops.request = cb_null_payload;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	WRT_CHECK_U64(tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT), TC_ST_REPLY_MORE);
	WRT_CHECK_U64(tc_last(&t)->len[0], 4); /* just the empty blob */
	tc_free(&t);
	sim_m2_free(s);

	ops.request = cb_unknown;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	(void)tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT);
	tc_pull(&t, s);
	WRT_CHECK_STATUS(WR_E_INVAL, sim_m2_error(s)->status);
	WRT_CHECK(sim_m2_closed(s));
	tc_free(&t);
	sim_m2_free(s);

	ops.request = cb_big_more;
	s = sim_m2_new(&cfg, &ops);
	tc_init(&t, 1u << 16);
	(void)tc_drive(&t, s, 1, TC_ST_REPLY_MORE, SIM_M2_ENT_CLIENT);
	tc_pull(&t, s);
	WRT_CHECK_STATUS(WR_E_TOOBIG, sim_m2_error(s)->status);
	WRT_CHECK(sim_m2_closed(s));
	tc_free(&t);
	sim_m2_free(s);

	/* the scripted callbacks cut lengths that exceed their own arrays instead of reading past them */
	{
		env e;

		env_prep(&e, 0);
		e.sc.more_len = 100000;
		e.sc.done_len = 100000;
		e.sc.key_len = 100000;
		env_start(&e);
		WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_DONE, SIM_M2_ENT_CLIENT), TC_ST_DONE);
		WRT_CHECK_U64(e.t.fr[1].len[0], 4u + sizeof(e.sc.more_payload));
		WRT_CHECK_U64(e.t.fr[2].len[0], 8u + 4u + 4u + sizeof(e.sc.done_payload));
		WRT_CHECK_U64(e.s->key_len, SIM_M2_KEY_MAX);
		env_end(&e);
	}
}

/* ---- budgets: kept messages and queued output ------------------------------------------------------------- */

static void seen_cb(void *ctx, sim_m2 *s, const sim_m2_msg *m)
{
	unsigned *n = (unsigned *)ctx;

	(void)s;
	(*n)++;
	WRT_CHECK(m->seg[0] != NULL && m->seg_len[0] == 600); /* the callback sees the data even if it is not kept */
	if (m->seg[0] != NULL)
		WRT_CHECK(m->seg[0][0] == 0xa5 && m->seg[0][599] == 0xa5);
}

static void budgets(void)
{
	env e;
	unsigned seen = 0;
	static uint8_t front[600], big[8000];
	size_t i;

	memset(front, 0xa5, sizeof(front));
	for (i = 0; i < sizeof(big); i++)
		big[i] = (uint8_t)i;

	/* recorded bytes are capped: 600 + 600 fits 1500, the third message would make 1800 */
	env_prep(&e, 0);
	e.cfg.msg_bytes_cap = 1500;
	env_start(&e);
	e.s->on_message = seen_cb;
	e.s->on_message_ctx = &seen;
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, front, 600, NULL, 0, NULL, 0);
	(void)tc_send_msg(&e.t, e.s, 2, 2, 1, front, 600, NULL, 0, NULL, 0);
	(void)tc_send_msg(&e.t, e.s, 3, 3, 1, front, 600, NULL, 0, NULL, 0);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK_U64(seen, 3);
	WRT_CHECK_U64(e.s->n_msgs, 2);
	WRT_CHECK_U64(e.s->n_msgs_seen, 3);
	WRT_CHECK_U64(e.s->msgs_bytes, 1200);
	WRT_CHECK_U64(e.s->in_seq, 3);
	sim_m2_msgs_clear(e.s);
	WRT_CHECK_U64(e.s->msgs_bytes, 0);
	(void)tc_send_msg(&e.t, e.s, 4, 4, 1, front, 600, NULL, 0, NULL, 0);
	WRT_CHECK_U64(e.s->n_msgs, 1); /* room again after the clear */
	env_end(&e);

	/* max_msgs = 0 keeps nothing, counts everything */
	env_prep(&e, 0);
	e.cfg.max_msgs = 0;
	env_ready(&e, TC_ST_IDENT);
	(void)tc_send_msg(&e.t, e.s, 1, 1, 1, front, 600, NULL, 0, NULL, 0);
	WRT_CHECK_U64(e.s->n_msgs, 0);
	WRT_CHECK_U64(e.s->n_msgs_seen, 1);
	env_end(&e);

	/* queued output is capped: a message that does not fit is refused, nothing half-queued, keepalives go on */
	env_prep(&e, 0);
	e.cfg.out_cap = 4096;
	env_ready(&e, TC_ST_IDENT);
	tc_pull(&e.t, e.s);
	WRT_CHECK_STATUS(WR_E_TOOBIG, sim_m2_send_message(e.s, 1, 1, 1, big, sizeof(big), NULL, 0, NULL, 0));
	WRT_CHECK_U64(sim_m2_pending(e.s), 0);
	WRT_CHECK_U64(e.s->out_seq, 0); /* a refused message does not use a sequence number */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 2, 1, big, 1000, NULL, 0, NULL, 0));
	WRT_CHECK_U64(e.s->out_seq, 1);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 3, 1, big, 1000, NULL, 0, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 4, 1, big, 1000, NULL, 0, NULL, 0));
	WRT_CHECK(sim_m2_pending(e.s) <= 4096);
	WRT_CHECK_STATUS(WR_E_TOOBIG, sim_m2_send_message(e.s, 1, 5, 1, big, 1000, NULL, 0, NULL, 0));
	WRT_CHECK_U64(e.s->out_seq, 3);
	WRT_CHECK(sim_m2_pending(e.s) <= 4096);
	tc_pull(&e.t, e.s); /* drain: the three that were queued arrive whole and in order, then there is room again */
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 6, 1, big, 1000, NULL, 0, NULL, 0));
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	env_end(&e);

	/* the builder's own refusals pass through and leave the server alive: a NULL segment with a length */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_STATUS(WR_E_INVAL, sim_m2_send_message(e.s, 1, 1, 1, NULL, 10, NULL, 0, NULL, 0));
	WRT_CHECK_U64(e.s->out_seq, 0);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_READY);
	WRT_CHECK_STATUS(WR_E_INVAL, sim_m2_send_frame(e.s, WRI_M2_TAG_KEEPALIVE2, NULL, 1));
	env_end(&e);

	/* the oversize hook with no segments to describe: the builder's verdict, not a crash */
	env_prep(&e, 0);
	e.cfg.f.oversize_frame = 1;
	e.cfg.f.oversize_len = 100;
	env_start(&e);
	WRT_CHECK_STATUS(WR_E_INVAL, sim_m2_send_frame(e.s, WRI_M2_TAG_WAIT, NULL, 1));
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_BANNER);
	env_end(&e);
}

int main(void)
{
	int v;

	idents();
	for (v = 0; v < 5; v++)
		hello_bad(v);
	auth_payloads();
	session_payloads();
	signature_bits();
	banner_required();
	bad_configs();
	callbacks();
	budgets();
	return wrt_finish();
}
