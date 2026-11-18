/* SPDX-License-Identifier: MIT */
/*
 * test_osd_sess_rx.c - what arrives on an OSD connection (design 21.4), through the real msgr2 receive parser: replies routed to the sink the request
 * layer names for their tid (whole, byte at a time, split at every offset of the frame), rx_tid while a data segment is being received, a stale tid
 * discarded without a store, a front above osd_front_cap, a middle segment, data that does not add up or does not fit, an operation count that is not
 * the one sent, undecodable fronts and versions (each one closes the session after the bad_reply call), and MOSDMap pushes and unknown types that are
 * discarded and counted while the stream stays in step.
 */
#include "osd_sess_world.h"

#define FRONT_CAP 2048u

static world W;
static uint32_t S;
static uint8_t guard[1 << 14];

static int start(unsigned n_sess)
{
	if (w_open_world(&W, 2, n_sess, FRONT_CAP, 8, WR_KEY_TYPE_AES256K) != 0 || w_start(&W) != 0) {
		WRT_CHECK(0);
		return -1;
	}
	S = w_get(&W, 0);
	WRT_CHECK(S != WRI_NIL);
	return S == WRI_NIL ? -1 : 0;
}

static void reset_rec(void)
{
	memset(&W.r, 0, sizeof(W.r));
}

/* A destination with guard bands: 64 bytes of 0xEE before and 0xEE after `cap` usable bytes. */
static uint8_t *sinkbuf(void)
{
	memset(guard, 0xEE, sizeof(guard));
	return guard + 64;
}

static int guards_intact(uint32_t used)
{
	uint32_t i;

	for (i = 0; i < 64; i++)
		if (guard[i] != 0xEE)
			return 0;
	for (i = used; i < sizeof(guard) - 64u; i++)
		if (guard[64 + i] != 0xEE)
			return 0;
	return 1;
}

static uint8_t pat(unsigned i) { return (uint8_t)(i * 13u + 5u); }

static void fill_data(uint8_t *d, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		d[i] = pat(i);
}

/* One valid reply message of one READ with `dlen` output bytes. */
static wr_status send_reply(uint64_t tid, uint32_t dlen, int pump)
{
	rframe f;
	uint8_t data[512];
	uint32_t plen[1];

	plen[0] = dlen;
	rf_reply(&f, "rbd_data.1234.0000000000000001", 1, plen, (int32_t)dlen, 0);
	fill_data(data, dlen);
	return pump ? w_inject(&W, S, WRI_MSG_OSD_OPREPLY, tid, 8, f.b, f.n, NULL, 0, dlen != 0 ? data : NULL, dlen)
		    : w_queue(&W, S, WRI_MSG_OSD_OPREPLY, tid, 8, f.b, f.n, NULL, 0, dlen != 0 ? data : NULL, dlen);
}

/* ---- a reply, whole and in pieces ----------------------------------------------------------------------------------------------- */

static void check_good_reply(uint64_t tid, uint32_t dlen, uint8_t *dst, unsigned n_before)
{
	unsigned i;

	WRT_CHECK(W.r.n_reply == n_before + 1u && W.r.n_bad == 0u);
	if (W.r.n_reply != n_before + 1u)
		return;
	WRT_CHECK(W.r.reply[n_before].tid == tid && W.r.reply[n_before].s == S && W.r.reply[n_before].stored == dlen);
	WRT_CHECK(W.r.reply[n_before].rep.n_ops == 1u && W.r.reply[n_before].rep.out_len[0] == dlen);
	for (i = 0; i < dlen; i++)
		if (dst[i] != pat(i)) {
			WRT_CHECK(0);
			break;
		}
	WRT_CHECK(guards_intact(dlen));
	WRT_CHECK(W.t.s[S].rx_tid == 0u && wri_osd_sess_ready(&W.t, S));
}

static void test_whole_and_chunked(void)
{
	static const size_t chunks[] = {0, 1, 2, 7, 64, 333};
	unsigned c;

	if (start(2) != 0)
		return;
	for (c = 0; c < sizeof(chunks) / sizeof(chunks[0]); c++) {
		uint8_t *dst = sinkbuf();
		unsigned before = W.r.n_reply;
		uint64_t tid = 0x500u + c;

		W.rx_chunk = chunks[c];
		W.r.sink_tid = tid;
		W.r.sink_dst = dst;
		W.r.sink_cap = 300;
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, send_reply(tid, 200, 1));
		check_good_reply(tid, 200, dst, before);
	}
	W.rx_chunk = 0;
	/* a reply with no data segment at all, and one with a zero-length data segment's worth of output */
	{
		uint8_t *dst = sinkbuf();
		unsigned before = W.r.n_reply;

		W.r.sink_tid = 0x600;
		W.r.sink_dst = dst;
		W.r.sink_cap = 16;
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, send_reply(0x600, 0, 1));
		check_good_reply(0x600, 0, dst, before);
	}
	WRT_CHECK(W.t.n_bad_replies == 0u && W.t.n_replies == 7u);
	w_free(&W);
}

/* The frame split in two at every offset: the sink is chosen when the header arrives and the bytes land wherever the split falls. rx_tid is
 * set from the moment the segments' lengths are known until the frame is complete. */
static void test_split_anywhere(void)
{
	size_t frame, k;
	unsigned seen_mid = 0, seen_before = 0;

	if (start(2) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, send_reply(1, 120, 0));
	frame = w_pending(&W, S);
	WRT_CHECK(frame > 200u);
	/* drop that probe: deliver it, then run the split for every offset */
	W.r.sink_dst = NULL;
	(void)w_pump(&W);
	WRT_CHECK(W.r.n_reply == 1u && W.r.reply[0].stored == 0u); /* no sink was named: discarded, the front was still delivered */
	for (k = 1; k < frame; k++) {
		uint8_t *dst = sinkbuf();
		unsigned before;
		uint64_t tid = 0x1000u + (uint64_t)k;

		reset_rec();
		W.r.sink_tid = tid;
		W.r.sink_dst = dst;
		W.r.sink_cap = 200;
		W.r.sink_n_ops = 1;
		before = 0;
		WRT_CHECK_STATUS(WR_OK, send_reply(tid, 120, 0));
		WRT_CHECK(w_pending(&W, S) == frame);
		W.rx_budget_on = 1;
		W.rx_budget = k;
		(void)w_pump(&W);
		/* half way: nothing delivered yet; rx_tid says whether the data segment can be written into the destination */
		WRT_CHECK(W.r.n_reply == 0u && W.r.n_bad == 0u);
		if (W.t.s[S].rx_tid != 0u) {
			WRT_CHECK(W.t.s[S].rx_tid == tid);
			seen_mid++;
		} else {
			seen_before++;
		}
		W.rx_budget_on = 0;
		(void)w_pump(&W);
		check_good_reply(tid, 120, dst, before);
		if (wrt_failures != 0)
			break;
	}
	/* before the segment lengths are known (the preamble and header 2: 32 + 45 bytes) rx_tid is 0, after them it is the tid; at least those offsets */
	WRT_CHECK(seen_before >= 76u && seen_mid >= 100u && seen_before + seen_mid == frame - 1u);
	WRT_CHECK(W.t.n_bad_replies == 0u);
	w_free(&W);
}

/* ---- the sink is a function of the tid -------------------------------------------------------------------------------------- */

static void test_stale_tid(void)
{
	uint8_t *dst;

	if (start(2) != 0)
		return;
	dst = sinkbuf();
	/* the request layer names a destination for tid 7 only: a reply for tid 8 (finished meanwhile) is read through and stored nowhere, yet its
	 * front is delivered so the layer can drop it by what it echoes */
	W.r.sink_tid = 7;
	W.r.sink_dst = dst;
	W.r.sink_cap = 200;
	W.r.sink_n_ops = 1;
	WRT_CHECK_STATUS(WR_OK, send_reply(8, 150, 1));
	WRT_CHECK(W.r.n_sink == 1u && W.r.sink_last_tid == 8u);
	WRT_CHECK(W.r.n_reply == 1u && W.r.reply[0].tid == 8u && W.r.reply[0].stored == 0u);
	WRT_CHECK(guards_intact(0)); /* not one byte stored */
	WRT_CHECK(W.t.s[S].rx_tid == 0u);
	/* mid-frame the session does not claim a buffer it does not write to */
	W.rx_budget_on = 1;
	W.rx_budget = 120;
	WRT_CHECK_STATUS(WR_OK, send_reply(9, 150, 0));
	(void)w_pump(&W);
	WRT_CHECK(W.t.s[S].rx_tid == 0u);
	W.rx_budget_on = 0;
	(void)w_pump(&W);
	WRT_CHECK(W.r.n_reply == 2u && guards_intact(0));
	/* the live tid lands */
	WRT_CHECK_STATUS(WR_OK, send_reply(7, 150, 1));
	check_good_reply(7, 150, dst, 2);
	/* a reply for tid 0 (which no request has) gets no destination either */
	WRT_CHECK_STATUS(WR_OK, send_reply(0, 10, 1));
	WRT_CHECK(W.t.s[S].rx_tid == 0u && W.r.n_reply == 4u);
	w_free(&W);
}

/* ---- frames that close the session ---------------------------------------------------------------------------------------- */

/* The session is gone: bad_reply first (when it names a tid), then lost once; the connection is closed; a cool-down runs. */
static void check_closed(wr_status st, int expect_bad_tid, uint64_t tid)
{
	WRT_CHECK(W.t.s[S].state == WRI_OS_COOLDOWN);
	WRT_CHECK(W.r.n_lost == 1u && W.r.lost[0].st == st && W.r.lost[0].s == S);
	if (expect_bad_tid) {
		WRT_CHECK(W.r.n_bad == 1u && W.r.bad[0].tid == tid && W.r.bad[0].st == st);
		WRT_CHECK(W.r.bad[0].seq < W.r.lost[0].seq); /* the request layer learns which reply was bad before the session is gone */
		WRT_CHECK(W.t.n_bad_replies == 1u);
	} else {
		WRT_CHECK(W.r.n_bad == 0u);
	}
	WRT_CHECK(w_live(&W) == 0u && W.t.s[S].conn_slot == WRI_OS_NOSLOT && W.t.s[S].rx_tid == 0u);
	WRT_CHECK(W.t.s[S].cooldown_until_ms > W.e.x.now.mono_ms);
	{
		wr_addr a = W.addr[0];
		uint32_t x;

		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&W.t, 0, &a, &x));
	}
}

static void test_front_above_cap(void)
{
	rframe f;
	uint32_t plen[1] = {10};
	char oid[3000];
	uint32_t base, L;

	/* what a front of exactly the cap and one byte more look like */
	memset(oid, 'x', sizeof(oid));
	oid[sizeof(oid) - 1] = 0;
	{
		/* the front without the name is `base` bytes (rf_reply): find the name length that makes it FRONT_CAP */
		char probe[2] = "x";

		rf_reply(&f, probe, 1, plen, 10, 0);
		base = f.n - 1u;
	}
	L = FRONT_CAP - base;
	oid[L] = 0;
	if (start(2) != 0)
		return;
	{
		uint8_t *dst = sinkbuf();
		uint8_t data[10];

		fill_data(data, 10);
		rf_reply(&f, oid, 1, plen, 10, 0);
		WRT_CHECK(f.n == FRONT_CAP);
		W.r.sink_dst = dst;
		W.r.sink_cap = 16;
		W.r.sink_n_ops = 1;
		WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, 3, 8, f.b, f.n, NULL, 0, data, 10));
		WRT_CHECK(W.r.n_reply == 1u && W.r.n_bad == 0u && W.r.n_lost == 0u && W.r.reply[0].rep.oid_len == L); /* exactly the cap: fine */
		oid[L] = 'x';
		oid[L + 1] = 0;
		rf_reply(&f, oid, 1, plen, 10, 0);
		WRT_CHECK(f.n == FRONT_CAP + 1u);
		WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, 4, 8, f.b, f.n, NULL, 0, data, 10));
		/* one byte more: a protocol error found at plan time, before any byte of the front is stored; no reply, no bad_reply (no tid was
		 * accepted), the session is lost with the status and what the table recorded */
		WRT_CHECK(W.r.n_reply == 1u);
		check_closed(WR_E_OSD_PROTO, 0, 0);
		WRT_CHECK(W.r.lost[0].what != NULL && strstr(W.r.lost[0].what, "front") != NULL);
		WRT_CHECK(W.r.lost[0].a0 == FRONT_CAP + 1u && W.r.lost[0].a1 == FRONT_CAP);
	}
	w_free(&W);
}

static void test_middle_and_shapes(void)
{
	rframe f;
	uint32_t plen[1] = {10};
	uint8_t data[10], mid[4] = {1, 2, 3, 4};

	/* a middle segment on a reply */
	if (start(2) != 0)
		return;
	rf_reply(&f, "o", 1, plen, 10, 0);
	fill_data(data, 10);
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, 3, 8, f.b, f.n, mid, 4, data, 10));
	check_closed(WR_E_OSD_PROTO, 0, 0);
	WRT_CHECK(W.r.n_reply == 0u);
	w_free(&W);
	/* a backoff with data, and one with a middle */
	if (start(2) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_BACKOFF, 0, 1, f.b, 40, NULL, 0, data, 10));
	check_closed(WR_E_OSD_PROTO, 0, 0);
	w_free(&W);
	if (start(2) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_BACKOFF, 0, 1, f.b, 40, mid, 4, data, 10));
	check_closed(WR_E_OSD_PROTO, 0, 0);
	w_free(&W);
	/* a backoff front above the cap */
	if (start(2) != 0)
		return;
	{
		static uint8_t big[FRONT_CAP + 100];

		memset(big, 0, sizeof(big));
		WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_BACKOFF, 0, 1, big, sizeof(big), NULL, 0, NULL, 0));
		check_closed(WR_E_OSD_PROTO, 0, 0);
	}
	w_free(&W);
}

static void bad_case(const char *name, wr_status want, const uint8_t *front, uint32_t flen, uint16_t ver, const uint8_t *data, uint32_t dlen,
		     uint32_t sink_cap, uint32_t sink_nops, uint64_t tid)
{
	uint8_t *dst;

	if (start(2) != 0)
		return;
	dst = sinkbuf();
	W.r.sink_tid = tid;
	W.r.sink_dst = dst;
	W.r.sink_cap = sink_cap;
	W.r.sink_n_ops = sink_nops;
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, tid, ver, front, flen, NULL, 0, data, dlen));
	if (W.r.n_reply != 0u)
		fprintf(stderr, "case %s: a reply was delivered\n", name);
	WRT_CHECK(W.r.n_reply == 0u);
	check_closed(want, 1, tid);
	if (!(W.r.n_bad == 1u && W.r.bad[0].what != NULL))
		fprintf(stderr, "case %s\n", name);
	/* what was stored before the verdict is the OSD's own bytes in the destination of that tid and nothing outside it */
	WRT_CHECK(guards_intact(sink_cap));
	w_free(&W);
}

static void test_bad_replies(void)
{
	rframe f;
	uint8_t data[512];
	uint32_t plen[2];

	fill_data(data, sizeof(data));
	/* data longer than its operations say, shorter, and with nothing */
	plen[0] = 100;
	rf_reply(&f, "o", 1, plen, 100, 0);
	bad_case("data one byte short", WR_E_OSD_PROTO, f.b, f.n, 8, data, 99, 200, 1, 21);
	bad_case("data one byte long", WR_E_OSD_PROTO, f.b, f.n, 8, data, 101, 200, 1, 22);
	bad_case("no data", WR_E_OSD_PROTO, f.b, f.n, 8, NULL, 0, 200, 1, 23);
	/* output that does not fit the destination (the op's buffer is smaller than what the OSD says it returns) */
	bad_case("output above the destination", WR_E_OSD_PROTO, f.b, f.n, 8, data, 100, 50, 1, 24);
	/* two operations were sent, the OSD answers one */
	bad_case("operation count", WR_E_OSD_PROTO, f.b, f.n, 8, data, 100, 200, 2, 25);
	plen[0] = 40, plen[1] = 60;
	rf_reply(&f, "o", 2, plen, 0, 0);
	bad_case("two echoed, one sent", WR_E_OSD_PROTO, f.b, f.n, 8, data, 100, 200, 1, 26);
	/* a front that is not a reply at all, or cut one byte short, or with a version this client does not decode */
	{
		uint8_t junk[40];

		memset(junk, 0x77, sizeof(junk));
		bad_case("junk front", WR_E_OSD_PROTO, junk, sizeof(junk), 8, NULL, 0, 16, 1, 27);
	}
	plen[0] = 10;
	rf_reply(&f, "o", 1, plen, 10, 0);
	bad_case("cut front", WR_E_OSD_PROTO, f.b, f.n - 1u, 8, data, 10, 16, 1, 28);
	bad_case("empty front", WR_E_OSD_PROTO, f.b, 0, 8, data, 10, 16, 1, 29);
	bad_case("version 7", WR_E_OSD_VERSION, f.b, f.n, 7, data, 10, 16, 1, 30);
	bad_case("version 9", WR_E_OSD_VERSION, f.b, f.n, 9, data, 10, 16, 1, 31);
}

/* A good reply after nothing wrong still works, and a bad one leaves the other session alone. */
static void test_other_sessions_unaffected(void)
{
	uint32_t s1;
	rframe f;
	uint32_t plen[1] = {10};
	uint8_t data[9];

	if (start(2) != 0)
		return;
	s1 = w_get(&W, 1);
	WRT_CHECK(s1 != WRI_NIL);
	rf_reply(&f, "o", 1, plen, 10, 0);
	fill_data(data, 9);
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, 3, 8, f.b, f.n, NULL, 0, data, 9));
	WRT_CHECK(W.t.s[S].state == WRI_OS_COOLDOWN && W.t.s[s1].state == WRI_OS_READY && W.r.n_lost == 1u);
	plen[0] = 9;
	rf_reply(&f, "o", 1, plen, 9, 0);
	W.r.sink_dst = NULL;
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, s1, WRI_MSG_OSD_OPREPLY, 4, 8, f.b, f.n, NULL, 0, data, 9));
	WRT_CHECK(W.r.n_reply == 1u && W.r.reply[0].s == s1 && wri_osd_sess_ready(&W.t, s1));
	w_free(&W);
}

/* ---- MOSDMap and other types ---------------------------------------------------------------------------------------------- */

static void test_discarded_types(void)
{
	uint8_t junk[3000], data[5000];
	rframe f;
	uint32_t plen[1] = {10};
	unsigned i;
	static const uint16_t types[] = {41, 17, 42, 100, 0x7fff, 0, 60, 62, 4};

	if (start(2) != 0)
		return;
	memset(junk, 0x3c, sizeof(junk));
	memset(data, 0xd1, sizeof(data));
	/* a pushed MOSDMap, built by the simulator's own call */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_map_push(w_srv(&W, S), junk, 1500));
	(void)w_pump(&W);
	WRT_CHECK(W.t.n_osdmap_discarded == 1u && W.t.n_other_discarded == 0u && W.r.n_sink == 0u && W.r.n_reply == 0u);
	/* the same with a front above the cap, a middle and data: still read through and thrown away, the session untouched */
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, 41, 0, 4, junk, 3000, junk, 100, data, 5000));
	WRT_CHECK(W.t.n_osdmap_discarded == 2u && wri_osd_sess_ready(&W.t, S) && W.r.n_lost == 0u);
	for (i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (types[i] == 41)
			continue;
		WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, types[i], 5, 1, junk, 700, NULL, 0, i % 2u ? data : NULL, i % 2u ? 321u : 0u));
	}
	WRT_CHECK(W.t.n_other_discarded == sizeof(types) / sizeof(types[0]) - 1u && W.r.n_sink == 0u && W.r.n_reply == 0u && W.r.n_bad == 0u);
	WRT_CHECK(wri_osd_sess_ready(&W.t, S) && W.t.s[S].rx_tid == 0u);
	/* byte at a time, and the stream is still in step: the reply after them is delivered */
	W.rx_chunk = 1;
	WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, 41, 0, 4, junk, 200, NULL, 0, NULL, 0));
	rf_reply(&f, "o", 1, plen, 10, 0);
	{
		uint8_t *dst = sinkbuf();

		W.r.sink_dst = dst;
		W.r.sink_cap = 16;
		W.r.sink_n_ops = 1;
		fill_data(data, 10);
		WRT_CHECK_STATUS(WR_OK, w_inject(&W, S, WRI_MSG_OSD_OPREPLY, 9, 8, f.b, f.n, NULL, 0, data, 10));
		check_good_reply(9, 10, dst, 0);
	}
	W.rx_chunk = 0;
	WRT_CHECK(W.t.n_osdmap_discarded == 3u);
	w_free(&W);
}

/* A real request round trip with the simulator's own reply, byte at a time. */
static void test_real_reply_bytewise(void)
{
	uint8_t data[200], *dst;
	uint32_t n = 0;
	const sim_osd_rec *rec;

	if (start(2) != 0)
		return;
	fill_data(data, sizeof(data));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(W.store, W_POOL, "rbd_data.x.0", 0, data, sizeof(data)));
	dst = sinkbuf();
	W.rx_chunk = 1;
	W.r.sink_tid = 0x2a;
	W.r.sink_dst = dst;
	W.r.sink_cap = 200;
	W.r.sink_n_ops = 1;
	WRT_CHECK_STATUS(WR_OK, w_op(&W, S, 0x2a, "rbd_data.x.0", WRI_OSD_OP_READ, 0, 200, NULL, 0));
	check_good_reply(0x2a, 200, dst, 0);
	/* a short object: READ of 300 from a 200 byte object returns 200 and the sum of payload lengths matches */
	W.r.sink_tid = 0x2b;
	W.r.sink_cap = 300;
	{
		uint8_t *d2 = sinkbuf();

		W.r.sink_dst = d2;
		WRT_CHECK_STATUS(WR_OK, w_op(&W, S, 0x2b, "rbd_data.x.0", WRI_OSD_OP_READ, 0, 300, NULL, 0));
		WRT_CHECK(W.r.n_reply == 2u && W.r.reply[1].stored >= 200u && W.r.n_bad == 0u);
	}
	rec = sim_osd_recs(W.osd[0], &n);
	WRT_CHECK(n == 2u && sim_osd_n_violations(W.osd[0]) == 0u);
	/* a write: the reply has no data; a write's tid the layer names no sink for */
	W.r.sink_dst = NULL;
	WRT_CHECK_STATUS(WR_OK, w_op(&W, S, 0x2c, "rbd_data.x.1", WRI_OSD_OP_WRITE, 0, 200, data, 0));
	WRT_CHECK(W.r.n_reply == 3u && W.r.reply[2].stored == 0u && W.r.reply[2].tid == 0x2c && W.r.n_bad == 0u);
	(void)rec;
	W.rx_chunk = 0;
	w_free(&W);
}

int main(void)
{
	test_whole_and_chunked();
	test_split_anywhere();
	test_stale_tid();
	test_front_above_cap();
	test_middle_and_shapes();
	test_bad_replies();
	test_other_sessions_unaffected();
	test_discarded_types();
	test_real_reply_bytewise();
	return wrt_finish();
}
