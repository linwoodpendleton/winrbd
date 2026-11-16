/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the msgr2 test server (harness/test/support/sim_m2.*), part 2: every fault hook (close or
 * stall at byte N, one-byte chunks, bad CRC at frame K, wrong signature, IDENT_MISSING_FEATURES, WAIT, mode 2
 * in AUTH_DONE, oversize frame) and the banner variants. Part 3 (test_sim_m2_viol.c) is the client that breaks
 * the rules. Same approach as part 1: hand-driven with the m2-frame builder, no module built after wave 2.
 */
#include "sim_m2_tc.h"

/* ---- out_limit: close or stall at byte N --------------------------------------------------------------- */

static void limit(void)
{
	env e;
	uint8_t buf[64];

	env_prep(&e, 0);
	e.cfg.f.out_limit = 10;
	e.cfg.f.out_limit_close = 1;
	env_start(&e);
	WRT_CHECK(sim_m2_pending(e.s) >= 26);
	WRT_CHECK_U64(sim_m2_drain(e.s, buf, 4), 4);
	WRT_CHECK(!sim_m2_closed(e.s));
	WRT_CHECK_U64(sim_m2_drain(e.s, buf, sizeof(buf)), 6); /* the limit cuts the banner at byte 10 */
	WRT_CHECK_U64(sim_m2_drain(e.s, buf, sizeof(buf)), 0);
	WRT_CHECK(sim_m2_closed(e.s));
	WRT_CHECK_U64(sim_m2_feed(e.s, buf, 1), 0);
	env_end(&e);

	/* stall mode: exactly the banner, then silence, and the connection stays open */
	env_prep(&e, 0);
	e.cfg.f.out_limit = 26;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_HELLO, SIM_M2_ENT_CLIENT), TC_ST_BANNER);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK(!sim_m2_closed(e.s));
	WRT_CHECK(sim_m2_pending(e.s) > 0); /* the HELLO is queued but never delivered */
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	env_end(&e);

	/* cut inside AUTH_DONE (banner 26 + HELLO 72 + REPLY_MORE 49 + 50 bytes of a 408-byte frame), then EOF */
	env_prep(&e, 0);
	e.cfg.f.out_limit = 26 + 72 + 49 + 50;
	e.cfg.f.out_limit_close = 1;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_REPLY_MORE);
	WRT_CHECK_U64(e.t.nfr, 2);
	WRT_CHECK_U64(e.t.rx_err, 0); /* a truncated frame is no frame and no error: the client sees EOF */
	WRT_CHECK(sim_m2_closed(e.s));
	env_end(&e);
}

static void chunk(void)
{
	env e;
	uint8_t buf[64];
	size_t n, total = 0;

	env_prep(&e, 0);
	e.cfg.f.out_chunk = 3;
	env_start(&e);
	n = sim_m2_pending(e.s);
	while ((n = sim_m2_drain(e.s, buf, sizeof(buf))) != 0) {
		WRT_CHECK(n <= 3);
		total += n;
	}
	WRT_CHECK_U64(total, 26);
	env_end(&e);
}

/* ---- corrupt the CRC of frame K ------------------------------------------------------------------------ */

static void corrupt(void)
{
	static const uint8_t parts[3] = {SIM_M2_CORRUPT_PREAMBLE, SIM_M2_CORRUPT_SEG0, SIM_M2_CORRUPT_EPILOGUE};
	static uint8_t big[2000];
	unsigned k, pi;
	env e;

	for (pi = 0; pi < 3; pi++) {
		for (k = 1; k <= 5; k++) { /* HELLO, REPLY_MORE, AUTH_DONE, AUTH_SIGNATURE, SERVER_IDENT */
			env_prep(&e, 0);
			e.cfg.f.corrupt_frame = k;
			e.cfg.f.corrupt_part = parts[pi];
			env_start(&e);
			(void)tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT);
			WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, e.t.rx_err);
			WRT_CHECK_U64(e.t.nfr, k - 1u); /* every frame before K is fine, K is rejected whole */
			env_end(&e);
		}
		/* frame 6 is the first MESSAGE: header-only, then with front / middle / data (epilogue slots) */
		env_prep(&e, 0);
		e.cfg.f.corrupt_frame = 7;
		e.cfg.f.corrupt_part = parts[pi];
		env_ready(&e, TC_ST_IDENT);
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 1, 1, NULL, 0, NULL, 0, NULL, 0));
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 2, 1, big, 2000, big, 10, big, 500));
		tc_pull(&e.t, e.s);
		WRT_CHECK_U64(e.t.nfr, 6); /* 5 handshake frames + the first message */
		WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, e.t.rx_err);
		env_end(&e);
	}
	/* the hook is off when corrupt_frame is 0: the same message arrives */
	env_prep(&e, 0);
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 2, 1, big, 2000, big, 10, big, 500));
	tc_pull(&e.t, e.s);
	WRT_CHECK_U64(e.t.nfr, 6);
	WRT_CHECK_U64(e.t.rx_err, 0);
	WRT_CHECK_U64(e.t.fr[5].nseg, 4);
	WRT_CHECK_U64(e.t.fr[5].len[3], 500);
	env_end(&e);
}

/* ---- signature, features, WAIT, secure mode, oversize ---------------------------------------------------- */

static void signature(void)
{
	env a, b;
	uint8_t want[32];

	env_prep(&a, 0);
	env_ready(&a, TC_ST_SIGNED);
	tc_hmac(TC_KEY, 32, a.t.sent, a.t.sent_len - 68, want); /* what we sent before our AUTH_SIGNATURE frame (68 bytes) */
	WRT_CHECK_MEM(tc_last(&a.t)->seg[0], want, 32);
	env_end(&a);

	env_prep(&b, 0);
	b.cfg.f.bad_signature = 1;
	env_ready(&b, TC_ST_SIGNED);
	WRT_CHECK(memcmp(tc_last(&b.t)->seg[0], want, 32) != 0);
	want[0] ^= 1;
	WRT_CHECK_MEM(tc_last(&b.t)->seg[0], want, 32); /* exactly one bit off */
	env_end(&b);
}

static void features(void)
{
	env e;
	const tc_frame *f;

	/* the stock monitor's required mask, a client that lacks bit 18 only */
	env_prep(&e, 0);
	e.cfg.ident_required = 0x0c01020042040000ull | 0x0800000000000000ull;
	env_start(&e);
	e.t.ident_supported = 0x3f07fffffffdffffull & ~(1ull << 18);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	f = tc_last(&e.t);
	WRT_CHECK_U64(f->tag, WRI_M2_TAG_IDENT_MISSING_FEATURES);
	WRT_CHECK_U64(f->len[0], 8);
	WRT_CHECK_U64(wri_le64_get(f->seg[0]), 1ull << 18);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_REFUSED);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	{
		size_t n = e.t.nfr;

		WRT_CHECK_U64(sim_m2_feed(e.s, (const uint8_t *)"abcd", 4), 4); /* taken, ignored */
		tc_pull(&e.t, e.s);
		WRT_CHECK_U64(e.t.nfr, n);
	}
	env_end(&e);

	/* no MSG_ADDR2 at all */
	env_prep(&e, 0);
	env_start(&e);
	e.t.ident_supported = 0x3f07fffffffdffffull & ~(1ull << 59);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_IDENT_MISSING_FEATURES);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0]), 0x0800000000000000ull);
	env_end(&e);

	/* forced by the hook, whatever the client says */
	env_prep(&e, 0);
	e.cfg.f.missing_features = 0xabc;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(tc_last(&e.t)->tag, WRI_M2_TAG_IDENT_MISSING_FEATURES);
	WRT_CHECK_U64(wri_le64_get(tc_last(&e.t)->seg[0]), 0xabc);
	env_end(&e);

	/* WAIT: an empty single-segment frame; the connection stays open */
	env_prep(&e, 0);
	e.cfg.f.send_wait = 1;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	f = tc_last(&e.t);
	WRT_CHECK_U64(f->tag, WRI_M2_TAG_WAIT);
	WRT_CHECK_U64(f->nseg, 1);
	WRT_CHECK_U64(f->len[0], 0);
	WRT_CHECK(!sim_m2_closed(e.s));
	env_end(&e);
}

static void secure_and_oversize(void)
{
	env e;
	tb p;

	/* mode 2 written into AUTH_DONE although the client asked for crc: the client must fault, the server
	 * stops reading */
	env_prep(&e, 0);
	e.cfg.f.done_mode = 2;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_DONE);
	WRT_CHECK_U64(wri_le32_get(tc_last(&e.t)->seg[0] + 8), 2);
	WRT_CHECK_U64(e.s->conn_mode, 2);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_REFUSED);
	env_end(&e);

	/* frame 3 (AUTH_DONE) is only a preamble that claims 0x7fffffff bytes: the client's cap rejects it */
	env_prep(&e, 0);
	e.cfg.f.oversize_frame = 3;
	e.cfg.f.oversize_len = 0x7fffffffu;
	env_start(&e);
	(void)tc_drive(&e.t, e.s, 1, TC_ST_IDENT, SIM_M2_ENT_CLIENT);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, e.t.rx_err);
	WRT_CHECK_U64(e.t.nfr, 2);
	WRT_CHECK(!sim_m2_closed(e.s)); /* the stream stalls, it does not end */
	env_end(&e);

	/* the same on a MESSAGE: the last segment is the lie, the header segment is honest */
	env_prep(&e, 0);
	e.cfg.f.oversize_frame = 6;
	e.cfg.f.oversize_len = 0x40000000u;
	env_ready(&e, TC_ST_IDENT);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 1, 1, (const uint8_t *)"front", 5, NULL, 0, NULL, 0));
	tc_pull(&e.t, e.s);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, e.t.rx_err);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(e.s, 1, 2, 1, NULL, 0, NULL, 0, NULL, 0)); /* swallowed */
	WRT_CHECK_U64(sim_m2_pending(e.s), 0);
	env_end(&e);

	/* the client's banner is cut off: the server just waits */
	env_prep(&e, 0);
	env_start(&e);
	p.n = 0;
	tb_bytes(&p, "ceph v2\n", 8);
	WRT_CHECK_U64(sim_m2_feed(e.s, p.b, p.n), 8);
	WRT_CHECK_U64(sim_m2_error(e.s)->status, 0);
	WRT_CHECK(!sim_m2_closed(e.s));
	env_end(&e);
}

/* ---- the server's banner ------------------------------------------------------------------------------------ */

static wr_status banner_err(uint32_t len, int v1, uint64_t sup, uint64_t req, int *got)
{
	env e;
	wr_status st;

	env_prep(&e, 0);
	e.cfg.banner_payload_len = len;
	e.cfg.banner_v1 = (uint8_t)v1;
	e.cfg.banner_supported = sup;
	e.cfg.banner_required = req;
	env_start(&e);
	tc_pull(&e.t, e.s);
	st = e.t.rx_err;
	*got = e.t.got_banner;
	env_end(&e);
	return st;
}

static void banners(void)
{
	int got;

	WRT_CHECK_STATUS(WR_OK, banner_err(16, 0, 3, 0, &got));
	WRT_CHECK(got);
	WRT_CHECK_STATUS(WR_OK, banner_err(64, 0, 1, 0, &got)); /* extra payload bytes are ignored */
	WRT_CHECK(got);
	WRT_CHECK_STATUS(WR_OK, banner_err(16, 0, 1, 1, &got));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, banner_err(15, 0, 3, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, banner_err(8, 0, 3, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, banner_err(65, 0, 3, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_BANNER, banner_err(1024, 0, 3, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_PEER_V1, banner_err(16, 1, 3, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, banner_err(16, 0, 0, 0, &got)); /* no REVISION_1 */
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, banner_err(16, 0, 2, 0, &got));
	WRT_CHECK_STATUS(WR_E_M2_FEATURES, banner_err(16, 0, 3, 2, &got)); /* requires something we lack */
}

static void no_compression(void)
{
	env e;

	/* a server that does not advertise COMPRESSION skips the stage even for a client that does */
	env_prep(&e, 0);
	e.cfg.banner_supported = 1;
	env_start(&e);
	WRT_CHECK_U64(tc_drive(&e.t, e.s, 3, TC_ST_IDENT, SIM_M2_ENT_CLIENT), TC_ST_IDENT);
	WRT_CHECK_U64(e.t.nfr, 5);
	WRT_CHECK_U64(e.s->compression_requested, 0);
	WRT_CHECK_U64(e.s->state, SIM_M2_ST_READY);
	env_end(&e);
}

int main(void)
{
	limit();
	chunk();
	corrupt();
	signature();
	features();
	secure_and_oversize();
	banners();
	no_compression();
	return wrt_finish();
}
