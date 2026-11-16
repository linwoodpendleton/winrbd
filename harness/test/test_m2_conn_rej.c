/* SPDX-License-Identifier: MIT */
/*
 * m2-conn, handshake rejections: wri_m2_conn against the scriptable server of sim_m2.h and hand-built frames.
 *
 *   - a rejection table (every case asserts the status code, a single close report, the released handshake
 *     slot and that nothing is sent afterwards) with the details a caller reads from the errinfo;
 *   - IPv6 and nonce-carrying addresses: carried as the map gave them, in HELLO, CLIENT_IDENT and SERVER_IDENT;
 *   - SERVER_IDENT address matching, byte for byte;
 *   - a matrix of every frame tag in every connection state: allowed ones are not refused as WR_E_M2_STATE,
 *     all others are.
 * The happy path, deadlines and backpressure are in test_m2_conn_hs.c.
 */
#include "m2_conn_msgs.h"

/* The number of bytes the server has said once the client is READY (the state the matrix stops at). */
static size_t baseline_rcvd_len(void)
{
	rig r;
	size_t n;

	rig_init(&r);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	n = r.rcvd_len;
	rig_free(&r);
	return n;
}

/* ---- rejection table --------------------------------------------------------------------------------- */

static void set_v1(rig *r) { r->scfg.banner_v1 = 1; }
static void set_no_rev1(rig *r) { r->scfg.banner_supported = 2; }
static void set_required2(rig *r) { r->scfg.banner_required = 2; }
static void set_short_banner(rig *r) { r->scfg.banner_payload_len = 15; }
static void set_crc_hello(rig *r) { r->scfg.f.corrupt_frame = 1, r->scfg.f.corrupt_part = SIM_M2_CORRUPT_PREAMBLE; }
static void set_crc_seg0(rig *r) { r->scfg.f.corrupt_frame = 2, r->scfg.f.corrupt_part = SIM_M2_CORRUPT_SEG0; }
static void set_hello_osd(rig *r) { r->scfg.entity_type = SIM_M2_ENT_OSD; }
static void set_bad_method(rig *r) { r->script.fail_result = -13; }
static void set_mode_refused(rig *r)
{
	r->scfg.n_modes = 1;
	r->scfg.modes[0] = SIM_M2_MODE_SECURE;
}
static void set_done_secure(rig *r) { r->scfg.f.done_mode = 2; }
static void set_bad_sig(rig *r) { r->scfg.f.bad_signature = 1; }
static void set_missing(rig *r) { r->scfg.f.missing_features = 0x1000; }
static void set_wait(rig *r) { r->scfg.f.send_wait = 1; }
static void set_pa_tx_overflow(rig *r) { r->pa_cap = 100; }
static void set_pa_rx_overflow(rig *r)
{
	r->pa_cap = 300;
	r->script.done_len = 400;
	memset(r->script.done_payload, 0xDD, 400);
}
static void set_rounds5(rig *r) { r->script.rounds = 5; }
static void set_begin_fail(rig *r) { r->au.begin_st = WR_E_AUTH_DENIED; }
static void set_more_fail(rig *r) { r->au.more_st = WR_E_AUTH_DECRYPT; }
static void set_done_fail(rig *r) { r->au.done_st = WR_E_AUTH_GID0; }
static void set_no_key(rig *r) { r->au.key_len = 0; }
static void set_tiny_tx(rig *r) /* the payload is larger than the in-place scratch of a 1 KiB encode buffer */
{
	r->tx_cap = 1024;
	r->au.begin_len = 1024;
	memset(r->au.begin_payload, 0x41, 1024);
}
static void set_ctl_small(rig *r) { r->ctl_cap = 32; } /* AUTH_DONE does not fit segment 0 */
static void set_eof(rig *r) { r->scfg.f.out_limit = 26, r->scfg.f.out_limit_close = 1; }

typedef struct hs_case {
	const char *name;
	void (*setup)(rig *r);
	wr_status want;
} hs_case;

static const hs_case cases[] = {
	{"v1 banner", set_v1, WR_E_M2_PEER_V1},
	{"banner without REVISION_1", set_no_rev1, WR_E_M2_FEATURES},
	{"banner requires compression", set_required2, WR_E_M2_FEATURES},
	{"banner payload too short", set_short_banner, WR_E_M2_BANNER},
	{"bad preamble crc (HELLO)", set_crc_hello, WR_E_M2_FRAME_CRC},
	{"bad segment 0 crc (REPLY_MORE)", set_crc_seg0, WR_E_M2_FRAME_CRC},
	{"HELLO type mismatch", set_hello_osd, WR_E_M2_HELLO},
	{"AUTH_BAD_METHOD after the cephx rounds", set_bad_method, WR_E_M2_BAD_METHOD},
	{"AUTH_BAD_METHOD, mode not allowed", set_mode_refused, WR_E_M2_BAD_METHOD},
	{"AUTH_DONE in secure mode", set_done_secure, WR_E_M2_MODE},
	{"bad server signature", set_bad_sig, WR_E_M2_SIGNATURE},
	{"IDENT_MISSING_FEATURES", set_missing, WR_E_M2_MISSING_FEATURES},
	{"WAIT", set_wait, WR_E_M2_WAIT},
	{"pre-auth overflow, sent log", set_pa_tx_overflow, WR_E_M2_PREAUTH_TOOBIG},
	{"pre-auth overflow, received log", set_pa_rx_overflow, WR_E_M2_PREAUTH_TOOBIG},
	{"more than 4 AUTH_REPLY_MORE rounds", set_rounds5, WR_E_M2_STATE},
	{"auth begin fails", set_begin_fail, WR_E_AUTH_DENIED},
	{"auth more fails", set_more_fail, WR_E_AUTH_DECRYPT},
	{"auth done fails", set_done_fail, WR_E_AUTH_GID0},
	{"no session key after AUTH_DONE", set_no_key, WR_E_CRYPTO_KEY},
	{"authentication payload larger than the buffer", set_tiny_tx, WR_E_TOOBIG},
	{"control frame larger than segment 0", set_ctl_small, WR_E_M2_FRAME_TOOBIG},
	{"peer closes during the handshake", set_eof, WR_E_NET_CLOSED},
};

static void test_rejections(void)
{
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		rig r;

		rig_init(&r);
		cases[i].setup(&r);
		rig_start(&r);
		rig_pump(&r);
		if (cases[i].want == WR_E_NET_CLOSED) {
			/* the transport reports the loss: that is how the engine learns about it */
			wri_m2_conn_on_closed(&r.x, &r.c, 104);
			WRT_CHECK_STATUS(WR_E_NET_CLOSED, r.up.closed_err.status);
			WRT_CHECK_U64(r.up.closed_err.a0, 104);
			WRT_CHECK_U64(r.up.n_closed, 1);
			WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
			WRT_CHECK(r.c.pa == NULL);
		} else {
			if (r.c.err.status != cases[i].want)
				fprintf(stderr, "case \"%s\"\n", cases[i].name);
			rig_check_failed(&r, cases[i].want);
		}
		if (cases[i].want == WR_E_M2_BAD_METHOD) {
			WRT_CHECK_U64(r.c.err.peer_result < 0, 1);
			WRT_CHECK_U64(r.up.closed_err.peer_result, r.c.err.peer_result);
			WRT_CHECK_U64(r.c.err.a2, 2); /* the method we offered */
			WRT_CHECK_U64(r.c.err.a1 & ~(uint64_t)6, 0);
			WRT_CHECK_U64(r.au.n_begin, 1); /* no second attempt: no silent downgrade */
			WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST], 1);
		}
		rig_free(&r);
	}
}

static void test_reject_details(void)
{
	rig r;

	/* AUTH_BAD_METHOD: result and both lists are in the errinfo (methods {2}, modes {2}; result -13) */
	rig_init(&r);
	set_bad_method(&r);
	r.scfg.n_methods = 1, r.scfg.methods[0] = 2;
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_BAD_METHOD);
	WRT_CHECK_U64((int64_t)r.c.err.peer_result, -13);
	WRT_CHECK_U64(r.c.err.a0, 1u << 2);               /* allowed methods {2} */
	WRT_CHECK_U64(r.c.err.a1, (1u << 1) | (1u << 2)); /* allowed modes {crc, secure} */
	WRT_CHECK_U64(r.c.err.a2, 2);
	WRT_CHECK_U64(r.au.n_more, 1);
	WRT_CHECK_U64(r.c.err.module, WR_MOD_M2);
	WRT_CHECK(r.c.err.what != NULL);
	rig_free(&r);

	/* the server cannot pick a mode: refused right after AUTH_REQUEST, nothing else is sent */
	rig_init(&r);
	set_mode_refused(&r);
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_BAD_METHOD);
	WRT_CHECK_U64(r.au.n_more, 0);
	WRT_CHECK_U64(r.c.err.a1, 1u << 2); /* allowed modes {secure} */
	WRT_CHECK_U64((int64_t)r.c.err.peer_result, -95);
	rig_free(&r);

	/* secure-mode AUTH_DONE: auth->done is never told about it, no signature goes out */
	rig_init(&r);
	set_done_secure(&r);
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_MODE);
	WRT_CHECK_U64(r.au.n_done, 0);
	WRT_CHECK_U64(r.c.err.a0, 2);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_SIGNATURE], 0);
	rig_free(&r);

	/* a bad server signature: no CLIENT_IDENT */
	rig_init(&r);
	set_bad_sig(&r);
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_SIGNATURE);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_CLIENT_IDENT], 0);
	WRT_CHECK_U64(r.au.n_done, 1);
	rig_free(&r);

	/* missing features: the mask is in the errinfo */
	rig_init(&r);
	set_missing(&r);
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_MISSING_FEATURES);
	WRT_CHECK_U64(r.c.err.a0, 0x1000);
	rig_free(&r);

	/* four rounds are fine */
	rig_init(&r);
	r.script.rounds = 4;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.au.n_more, 4);
	rig_free(&r);
	/* the fifth is not */
	rig_init(&r);
	set_rounds5(&r);
	rig_start(&r);
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_STATE);
	WRT_CHECK_U64(r.au.n_more, 4);
	rig_free(&r);

	/* a server frame injected right after the banner: wrong for the HELLO state */
	rig_init(&r);
	{
		uint8_t b[8] = {0};
		wri_m2_seg_src seg;

		seg.p = b, seg.len = 8, seg.ref = 0;
		rig_start(&r);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, WRI_M2_TAG_KEEPALIVE2, &seg, 1));
		rig_pump(&r);
		rig_check_failed(&r, WR_E_M2_STATE);
		WRT_CHECK_U64(r.c.err.a0, WRI_M2_HELLO);
		WRT_CHECK_U64(r.c.err.a1, WRI_M2_TAG_KEEPALIVE2);
	}
	rig_free(&r);

	/* a HELLO that does not tell us our address */
	{
		uint8_t banner[WRI_M2_BANNER_LEN], hello[1 + WRI_EADDR_MAX_WIRE];
		wri_eaddr blank;
		wri_wr w;
		wri_m2_seg_src seg;
		uint8_t *fr;
		size_t fl;

		rig_init(&r);
		rig_start(&r);
		wri_m2_banner_build(banner);
		rig_inject(&r, banner, sizeof(banner));
		memset(&blank, 0, sizeof(blank));
		wri_wr_init(&w, hello + 1, sizeof(hello) - 1);
		hello[0] = WRI_ENTITY_MON;
		wri_eaddr_encode(&w, &blank);
		seg.p = hello, seg.len = (uint32_t)(1 + wri_wr_len(&w)), seg.ref = 0;
		fr = rig_build_frame(WRI_M2_TAG_HELLO, &seg, 1, &fl);
		rig_inject(&r, fr, fl);
		free(fr);
		rig_check_failed(&r, WR_E_M2_HELLO);
		rig_free(&r);
	}
	/* a transcript overflow is noticed while the bytes are consumed, before the frame is even looked at: a
	 * HELLO with a 1000 byte payload overflows a 300 byte log (a later check would say "malformed HELLO") */
	{
		uint8_t big[1000];
		wri_m2_seg_src seg;
		uint8_t *fr;
		size_t fl;

		rig_init(&r);
		r.pa_cap = 300;
		r.scfg.f.out_limit = 26;
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_HELLO);
		memset(big, 0, sizeof(big));
		big[0] = WRI_ENTITY_MON;
		seg.p = big, seg.len = sizeof(big), seg.ref = 0;
		fr = rig_build_frame(WRI_M2_TAG_HELLO, &seg, 1, &fl);
		rig_inject(&r, fr, fl);
		free(fr);
		rig_check_failed(&r, WR_E_M2_PREAUTH_TOOBIG);
		rig_free(&r);
	}
	/* a control frame with two segments is malformed */
	{
		uint8_t banner[WRI_M2_BANNER_LEN], b[8] = {0};
		wri_m2_seg_src seg[2];
		uint8_t *fr;
		size_t fl;

		rig_init(&r);
		rig_start(&r);
		wri_m2_banner_build(banner);
		rig_inject(&r, banner, sizeof(banner));
		seg[0].p = b, seg[0].len = 8, seg[0].ref = 0;
		seg[1].p = b, seg[1].len = 8, seg[1].ref = 0;
		fr = rig_build_frame(WRI_M2_TAG_HELLO, seg, 2, &fl);
		rig_inject(&r, fr, fl);
		free(fr);
		rig_check_failed(&r, WR_E_M2_FRAME_FORM);
		rig_free(&r);
	}
}

/* ---- IPv6 and a nonce: the addresses are carried as the map gave them ----------------------------------- */

static void test_ipv6(void)
{
	static const uint8_t t6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
	static const uint8_t me6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20};
	rig r;
	wri_eaddr hello_addr, got_target;
	wr_addr a;
	uint8_t banner[WRI_M2_BANNER_LEN], hp[1 + WRI_EADDR_MAX_WIRE], sig[32];
	wri_wr w;
	tb t;
	rig_fr f[8];
	size_t n, used;
	wri_rd rd;
	wri_eaddr ids[2];
	size_t nst = 0, ntot = 0;

	rig_init(&r);
	r.role = WRI_ENTITY_OSD;
	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV6;
	memcpy(a.ip, t6, 16);
	a.port = 6800;
	a.nonce = 99; /* an OSD address carries its daemon nonce */
	r.dial = a;
	wri_eaddr_from_wr(&r.target, &a, WRI_EADDR_TYPE_MSGR2);
	r.au.gid = 4242;
	rig_start(&r);
	(void)rig_flush_tx(&r);
	wri_m2_banner_build(banner);
	rig_inject(&r, banner, sizeof(banner));
	(void)rig_flush_tx(&r);
	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV6;
	memcpy(a.ip, me6, 16);
	a.port = 43210;
	wri_eaddr_from_wr(&hello_addr, &a, WRI_EADDR_TYPE_MSGR2);
	hp[0] = WRI_ENTITY_OSD;
	wri_wr_init(&w, hp + 1, sizeof(hp) - 1);
	wri_eaddr_encode(&w, &hello_addr);
	inject_ctl(&r, WRI_M2_TAG_HELLO, hp, 1 + wri_wr_len(&w));
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	WRT_CHECK_U64(r.c.my_family, WR_AF_IPV6);
	(void)rig_flush_tx(&r);
	t.n = 0, tb_u32(&t, 9), tb_fill(&t, 0x33, 9);
	inject_ctl(&r, WRI_M2_TAG_AUTH_REPLY_MORE, t.b, t.n);
	(void)rig_flush_tx(&r);
	t.n = 0, tb_u64(&t, 4242), tb_u32(&t, 1), tb_u32(&t, 40), tb_fill(&t, 0xDD, 40);
	inject_ctl(&r, WRI_M2_TAG_AUTH_DONE, t.b, t.n);
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	(void)rig_flush_tx(&r);
	/* the server signs everything we sent before our own signature frame (the last 68 bytes) */
	tc_hmac(TC_KEY, 32, r.sent, r.sent_len - 68, sig);
	inject_ctl(&r, WRI_M2_TAG_AUTH_SIGNATURE, sig, 32);
	WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
	(void)rig_flush_tx(&r);

	n = rig_split(r.sent + WRI_M2_BANNER_LEN, r.sent_len - WRI_M2_BANNER_LEN, f, 8, &used);
	WRT_CHECK_U64(n, 5);
	if (n == 5) {
		uint8_t exp[1 + WRI_EADDR_MAX_WIRE];

		/* HELLO: our type and the dialled IPv6 address with its nonce */
		exp[0] = WRI_ENTITY_CLIENT;
		wri_wr_init(&w, exp + 1, sizeof(exp) - 1);
		wri_eaddr_encode(&w, &r.target);
		WRT_CHECK_U64(f[0].len[0], 1 + wri_wr_len(&w));
		WRT_CHECK_MEM(f[0].seg[0], exp, 1 + wri_wr_len(&w));
		/* CLIENT_IDENT: addrs [the address the server saw, port 0, type ANY, our nonce], the target as dialled, gid */
		WRT_CHECK_U64(f[4].tag, WRI_M2_TAG_CLIENT_IDENT);
		wri_rd_init(&rd, f[4].seg[0], f[4].len[0]);
		WRT_CHECK_STATUS(WR_OK, wri_eaddrvec_decode(&rd, ids, 2, &nst, &ntot));
		WRT_CHECK_U64(nst, 1);
		WRT_CHECK_U64(ntot, 1);
		WRT_CHECK_U64(ids[0].type, WRI_EADDR_TYPE_ANY);
		WRT_CHECK_U64(ids[0].family, WR_AF_IPV6);
		WRT_CHECK_MEM(ids[0].ip, me6, 16);
		WRT_CHECK_U64(ids[0].port, 0);
		WRT_CHECK_U64(ids[0].nonce, r.nonce);
		WRT_CHECK_STATUS(WR_OK, wri_eaddr_decode(&rd, &got_target));
		WRT_CHECK(wri_eaddr_equal(&got_target, &r.target));
		WRT_CHECK_U64(got_target.nonce, 99);
		WRT_CHECK_U64(wri_rd_i64(&rd), 4242); /* the monitor-assigned global id: what the auth layer says */
		WRT_CHECK_U64(wri_rd_u64(&rd), r.gseq);
	}
	/* SERVER_IDENT carrying the IPv6 address as map-given */
	{
		wri_wr w2;
		uint8_t b[256];

		wri_wr_init(&w2, b, sizeof(b));
		wri_wr_u8(&w2, 2);
		wri_wr_u32(&w2, 1);
		wri_eaddr_encode(&w2, &r.target);
		wri_wr_u64(&w2, 5), wri_wr_u64(&w2, 7), wri_wr_u64(&w2, 0x3f07fffffffdffffull);
		wri_wr_u64(&w2, 0x0800000000000000ull), wri_wr_u64(&w2, 1), wri_wr_u64(&w2, 0);
		inject_ctl(&r, WRI_M2_TAG_SERVER_IDENT, b, wri_wr_len(&w2));
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64((uint64_t)r.c.peer_gid, 5);
	}
	rig_free(&r);

	/* an IPv4 OSD address with a nonce, through the sim: the server echoes it, CLIENT_IDENT carries it unchanged */
	rig_init(&r);
	r.role = WRI_ENTITY_OSD;
	r.scfg.entity_type = SIM_M2_ENT_OSD;
	r.scfg.server_nonce = 4711;
	r.dial.nonce = 4711;
	wri_eaddr_from_wr(&r.target, &r.dial, WRI_EADDR_TYPE_MSGR2);
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.s->ident.target_len, r.target.raw_len);
	WRT_CHECK_MEM(r.s->ident.target, r.target.raw, r.target.raw_len);
	rig_free(&r);
}

/* ---- SERVER_IDENT address matching ---------------------------------------------------------------------- */

/* Put the client in IDENT (the server is mute after its signature) and answer with our own SERVER_IDENT. */
static void ident_case(const char *name, unsigned naddr, uint8_t addr[2][SIM_M2_ADDR4_LEN], wr_status want)
{
	rig r;
	tb t;
	wri_m2_seg_src seg;
	uint8_t *fr;
	size_t fl;

	rig_init(&r);
	r.scfg.f.out_limit = 307;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
	t.n = 0;
	tb_u8(&t, 2);
	tb_u32(&t, naddr);
	if (naddr > 0)
		tb_bytes(&t, addr[0], SIM_M2_ADDR4_LEN);
	if (naddr > 1)
		tb_bytes(&t, addr[1], SIM_M2_ADDR4_LEN);
	tb_u64(&t, 77), tb_u64(&t, 7), tb_u64(&t, 0x3f07fffffffdffffull), tb_u64(&t, 0x0800000000000000ull);
	tb_u64(&t, 1), tb_u64(&t, 0);
	seg.p = t.b, seg.len = (uint32_t)t.n, seg.ref = 0;
	fr = rig_build_frame(WRI_M2_TAG_SERVER_IDENT, &seg, 1, &fl);
	rig_inject(&r, fr, fl);
	free(fr);
	if (want == WR_OK) {
		if (r.c.state != WRI_M2_READY)
			fprintf(stderr, "ident case \"%s\"\n", name);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_ready, 1);
		WRT_CHECK_U64((uint64_t)r.c.peer_gid, 77);
	} else {
		if (r.c.err.status != want)
			fprintf(stderr, "ident case \"%s\"\n", name);
		rig_check_failed(&r, want);
		WRT_CHECK_U64(r.up.n_ready, 0);
	}
	rig_free(&r);
}

static void test_server_ident(void)
{
	static const uint8_t ip[4] = {10, 77, 0, 10}, other[4] = {10, 77, 0, 11};
	uint8_t a[2][SIM_M2_ADDR4_LEN];

	sim_m2_put_addr4(a[0], 2, 0, ip, 3300); /* exactly the dialled address */
	ident_case("exact", 1, a, WR_OK);
	sim_m2_put_addr4(a[0], 2, 0, ip, 3301);
	ident_case("other port", 1, a, WR_E_M2_ADDR);
	sim_m2_put_addr4(a[0], 2, 0, other, 3300);
	ident_case("other ip", 1, a, WR_E_M2_ADDR);
	sim_m2_put_addr4(a[0], 2, 9, ip, 3300);
	ident_case("other nonce", 1, a, WR_E_M2_ADDR);
	sim_m2_put_addr4(a[0], 1, 0, ip, 3300);
	ident_case("legacy type only", 1, a, WR_E_M2_ADDR);
	ident_case("empty vector", 0, a, WR_E_M2_ADDR);
	sim_m2_put_addr4(a[0], 1, 0, ip, 6789);
	sim_m2_put_addr4(a[1], 2, 0, ip, 3300);
	ident_case("target second in the vector", 2, a, WR_OK);
	sim_m2_put_addr4(a[0], 2, 0, other, 3300);
	sim_m2_put_addr4(a[1], 1, 0, ip, 3300);
	ident_case("two foreign addresses", 2, a, WR_E_M2_ADDR);
}

/* ---- tag by state ------------------------------------------------------------------------------------- */

static int allowed(unsigned st, unsigned tag)
{
	switch (st) {
	case WRI_M2_HELLO:
		return tag == WRI_M2_TAG_HELLO;
	case WRI_M2_AUTH:
		return tag == 3 || tag == 4 || tag == 6;
	case WRI_M2_SIG:
		return tag == 7;
	case WRI_M2_IDENT:
		return tag == 9 || tag == 10 || tag == 16;
	case WRI_M2_READY:
		return tag == 17 || tag == 18 || tag == 19 || tag == 20;
	default:
		return 0;
	}
}

static void test_tag_matrix(void)
{
	static const unsigned st[] = {WRI_M2_HELLO, WRI_M2_AUTH, WRI_M2_SIG, WRI_M2_IDENT, WRI_M2_READY};
	size_t si;
	unsigned tag;

	for (si = 0; si < 5; si++) {
		int64_t limit = st[si] == WRI_M2_HELLO ? 26 : st[si] == WRI_M2_AUTH ? 98 : st[si] == WRI_M2_SIG ? 239 :
				st[si] == WRI_M2_IDENT ? 307 : (int64_t)baseline_rcvd_len();

		for (tag = 1; tag <= WRI_M2_TAG_MAX; tag++) {
			rig r;
			uint8_t b[8] = {0};
			wri_m2_seg_src seg;
			uint8_t *fr;
			size_t fl;

			rig_init(&r);
			r.io_cap = 1u << 16;
			r.scfg.f.out_limit = limit;
			rig_start(&r);
			rig_pump(&r);
			if (r.c.state != st[si]) {
				fprintf(stderr, "matrix: state %u, want %u\n", (unsigned)r.c.state, st[si]);
				WRT_CHECK(0);
				rig_free(&r);
				continue;
			}
			seg.p = b, seg.len = 8, seg.ref = 0;
			fr = rig_build_frame((uint8_t)tag, &seg, 1, &fl);
			rig_inject(&r, fr, fl);
			free(fr);
			if (allowed(st[si], tag)) {
				WRT_CHECK(r.c.err.status != WR_E_M2_STATE);
			} else {
				if (r.c.err.status != WR_E_M2_STATE)
					fprintf(stderr, "matrix: state %u tag %u not refused\n", st[si], tag);
				rig_check_failed(&r, WR_E_M2_STATE);
				WRT_CHECK_U64(r.c.err.a0, st[si]);
				WRT_CHECK_U64(r.c.err.a1, tag);
			}
			rig_free(&r);
		}
	}
}

int main(void)
{
	test_rejections();
	test_reject_details();
	test_ipv6();
	test_server_ident();
	test_tag_matrix();
	return wrt_finish();
}
