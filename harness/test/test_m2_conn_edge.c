/* SPDX-License-Identifier: MIT */
/*
 * m2-conn, error paths and edge cases that the other m2-conn tests leave out:
 *
 *   - authentication callbacks that answer WR_E_BUSY (a final failure, never backpressure), blobs over the
 *     cap in AUTH_REQUEST and AUTH_REQUEST_MORE;
 *   - encode buffers too small for a frame: a clear WR_E_TOOBIG at once instead of a wait that never ends;
 *   - backpressure at AUTH_DONE and at the server's AUTH_SIGNATURE with a tight encode buffer: the
 *     authentication step is not repeated, the connection ends up READY;
 *   - malformed control frames in IDENT and READY, ACK with any payload, a used-up sequence space,
 *     argument checks of the send calls, NULL tolerance of every entry point;
 *   - the owner closing the connection from inside the ready / plan / message callbacks.
 * Shared rig: m2_conn_rig.h; helpers: m2_conn_msgs.h.
 */
#include "m2_conn_msgs.h"

/* ---- callbacks that answer BUSY --------------------------------------------------------------------- */

static void run_busy_case(const char *name, void (*setup)(rig *r), int n_begin, int n_more, int n_done)
{
	rig r;

	rig_init(&r);
	setup(&r);
	rig_start(&r);
	rig_pump(&r);
	if (r.c.err.status != WR_E_BUSY)
		fprintf(stderr, "busy case \"%s\"\n", name);
	rig_check_failed(&r, WR_E_BUSY);
	WRT_CHECK_U64(r.c.stalled, 0); /* a failed connection is not "stalled": nobody should come back for it */
	WRT_CHECK_U64(r.au.n_begin, (uint64_t)n_begin);
	WRT_CHECK_U64(r.au.n_more, (uint64_t)n_more);
	WRT_CHECK_U64(r.au.n_done, (uint64_t)n_done);
	rig_free(&r);
}

static void busy_begin(rig *r) { r->au.begin_st = WR_E_BUSY; }
static void busy_more(rig *r) { r->au.more_st = WR_E_BUSY; }
static void busy_done(rig *r) { r->au.done_st = WR_E_BUSY; }

static void test_auth_busy_is_final(void)
{
	run_busy_case("begin", busy_begin, 1, 0, 0);
	run_busy_case("more", busy_more, 1, 1, 0);
	run_busy_case("done", busy_done, 1, 1, 1);
}

/* ---- blobs over the cap ------------------------------------------------------------------------------- */

#define BIG_PAYLOAD (WRI_M2_AUTH_BLOB_MAX + 1u)
static uint8_t big_buf[BIG_PAYLOAD];

static wr_status big_begin(void *a, uint8_t target_type, wri_wr *out)
{
	(void)target_type;
	((stub_auth *)a)->n_begin++;
	wri_wr_bytes(out, big_buf, BIG_PAYLOAD);
	return WR_OK;
}

static wr_status big_more(void *a, const uint8_t *reply, size_t n, wri_wr *out)
{
	(void)reply, (void)n;
	((stub_auth *)a)->n_more++;
	wri_wr_bytes(out, big_buf, BIG_PAYLOAD);
	return WR_OK;
}

static void test_blob_caps(void)
{
	wri_auth_ops big_ops;
	rig r;

	/* AUTH_REQUEST payload one byte over WRI_M2_AUTH_BLOB_MAX: refused before anything is sent */
	rig_init(&r);
	r.tx_cap = 2u * (BIG_PAYLOAD + 64u) + 128u;
	r.pa_cap = 1u << 18;
	rig_start(&r);
	big_ops = stub_ops;
	big_ops.begin = big_begin;
	r.c.auth = &big_ops;
	/* the connection was opened with the stub ops; the swap happens before the first byte is processed */
	rig_pump(&r);
	rig_check_failed(&r, WR_E_TOOBIG);
	WRT_CHECK_U64(r.au.n_begin, 1);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST], 0);
	rig_free(&r);

	/* AUTH_REQUEST_MORE payload over the cap: the same limit, and the step is not sent */
	rig_init(&r);
	r.tx_cap = 2u * (BIG_PAYLOAD + 64u) + 128u;
	r.pa_cap = 1u << 18;
	rig_start(&r);
	big_ops = stub_ops;
	big_ops.more = big_more;
	r.c.auth = &big_ops;
	rig_pump(&r);
	rig_check_failed(&r, WR_E_TOOBIG);
	WRT_CHECK_U64(r.au.n_begin, 1);
	WRT_CHECK_U64(r.au.n_more, 1);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST], 1);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST_MORE], 0);
	rig_free(&r);
}

/* ---- encode buffers that are too small ---------------------------------------------------------------- */

static void test_tiny_encode_buffer(void)
{
	static const uint32_t caps[] = {16, 40, 52, 60, 83, 120, 195};
	size_t i;

	for (i = 0; i < sizeof(caps) / sizeof(caps[0]); i++) {
		rig r;

		rig_init(&r);
		r.tx_cap = caps[i];
		rig_start(&r);
		rig_pump(&r);
		/* never a silent wait for the handshake timeout: the connection fails at once */
		if (r.c.err.status != WR_E_TOOBIG)
			fprintf(stderr, "tx_cap %u: status %d state %u\n", caps[i], (int)r.c.err.status, (unsigned)r.c.state);
		rig_check_failed(&r, WR_E_TOOBIG);
		WRT_CHECK(r.c.err.what != NULL);
		rig_free(&r);
	}
}

/* ---- backpressure at AUTH_DONE and at the server's signature ------------------------------------------ */

/* Like rig_pump, but while `hold` says so the bytes the client queued are shown to the server without being
 * consumed, so the encode buffer stays occupied. Returns as soon as the connection reports backpressure. */
static void pump_hold(rig *r, int (*hold)(const rig *), size_t *fed)
{
	int rounds = 0, progress;

	do {
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n, i, seen = 0;

		progress = 0;
		if (hold(r)) {
			n = wri_m2_conn_tx_peek(&r->c, iov, WRI_M2_TXQ_IOV);
			for (i = 0; i < n; i++) {
				size_t k = iov[i].len, skip = 0;

				if (seen + k <= *fed) {
					seen += k;
					continue;
				}
				if (seen < *fed)
					skip = *fed - seen;
				memcpy(r->sent + r->sent_len, iov[i].base + skip, k - skip);
				r->sent_len += k - skip;
				(void)sim_m2_feed(r->s, iov[i].base + skip, k - skip);
				*fed += k - skip;
				seen += k;
				progress = 1;
			}
		} else {
			if (*fed != 0) {
				wri_m2_conn_tx_consume(&r->c, *fed); /* the bytes the server has seen already */
				*fed = 0;
				progress = 1;
			}
			if (rig_flush_tx(r) != 0)
				progress = 1;
		}
		(void)rig_deliver(r, &progress);
		(void)wri_m2_conn_step(&r->x, &r->c, NULL);
		if (r->c.stalled)
			return; /* the connection asks for room: the caller looks at it, then calls again */
	} while (progress && ++rounds < 100000);
}

static int hold_until_stall_auth(const rig *r)
{
	return !r->c.stalled && r->c.state == WRI_M2_AUTH && r->c.auth_rounds == 1;
}

static int hold_until_stall_sig(const rig *r) { return !r->c.stalled && r->c.state == WRI_M2_SIG; }

static void tight_rig(rig *r)
{
	rig_init(r);
	r->tx_cap = 200; /* scratch for 82 payload bytes: AUTH_REQUEST_MORE (118 bytes) leaves 82 < 84 for the signature */
	r->au.more_len = 78;
	memset(r->au.more_payload, 0x42, 78);
}

static void test_backpressure_at_done(void)
{
	rig r;
	size_t fed = 0;

	tight_rig(&r);
	rig_start(&r);
	pump_hold(&r, hold_until_stall_auth, &fed);
	/* AUTH_DONE is here, the queue has no room for the answer: the step is held and not taken */
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	WRT_CHECK_U64(r.c.stalled, 1);
	WRT_CHECK_U64(r.au.n_done, 0);
	WRT_CHECK_U64(r.au.n_more, 1);
	WRT_CHECK(r.c.pa != NULL);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c) <= r.x.now.mono_ms + WRI_M2C_STALL_RETRY_MS, 1);
	/* the host catches up: the same frame is handled once */
	pump_hold(&r, hold_until_stall_auth, &fed);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.au.n_done, 1);
	WRT_CHECK_U64(r.au.n_more, 1);
	WRT_CHECK_U64(r.up.n_ready, 1);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_AUTH_SIGNATURE], 1);
	WRT_CHECK_U64(r.s->state, SIM_M2_ST_READY);
	rig_free(&r);
}

static void test_backpressure_at_signature(void)
{
	rig r;
	size_t fed = 0;

	tight_rig(&r);
	rig_start(&r);
	pump_hold(&r, hold_until_stall_sig, &fed);
	/* our AUTH_SIGNATURE is queued and not consumed; the server's signature is here; no room for CLIENT_IDENT */
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	WRT_CHECK_U64(r.c.stalled, 1);
	WRT_CHECK(r.c.pa != NULL); /* nothing was wiped: the comparison is repeated later */
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_CLIENT_IDENT], 0);
	pump_hold(&r, hold_until_stall_sig, &fed);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.au.n_done, 1);
	WRT_CHECK_U64(r.s->n_rx_by_tag[WRI_M2_TAG_CLIENT_IDENT], 1);
	WRT_CHECK(r.c.pa == NULL);
	rig_free(&r);
}

/* ---- malformed and odd frames in IDENT / READY -------------------------------------------------------- */

static void test_malformed_control(void)
{
	static const uint8_t four[4] = {1, 2, 3, 4}, nine[9] = {0, 0, 0, 0, 0, 0, 0, 0, 0};
	rig r;

	/* IDENT_MISSING_FEATURES needs exactly a u64 */
	rig_init(&r);
	r.scfg.f.out_limit = 307;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
	inject_ctl(&r, WRI_M2_TAG_IDENT_MISSING_FEATURES, four, sizeof(four));
	WRT_CHECK(r.c.err.status != WR_E_M2_MISSING_FEATURES);
	rig_check_failed(&r, r.c.err.status);
	WRT_CHECK(r.c.err.status != WR_OK);
	rig_free(&r);

	/* KEEPALIVE2_ACK and KEEPALIVE2 need exactly a utime: short and long payloads fail the connection */
	{
		uint8_t tags[2] = {WRI_M2_TAG_KEEPALIVE2_ACK, WRI_M2_TAG_KEEPALIVE2};
		const uint8_t *pay[2] = {four, nine};
		uint32_t len[2] = {4, 9};
		unsigned i;

		for (i = 0; i < 2; i++) {
			rig_init(&r);
			ready_rig(&r);
			inject_ctl(&r, tags[i], pay[i], len[i]);
			WRT_CHECK(r.c.err.status != WR_OK);
			rig_check_failed(&r, r.c.err.status);
			WRT_CHECK_U64(r.c.n_ka_ack, 0);
			rig_free(&r);
		}
	}

	/* ACK is ignored whatever it carries; nothing is answered and the counters stay */
	rig_init(&r);
	ready_rig(&r);
	{
		size_t before = r.sent_len;

		inject_ctl(&r, WRI_M2_TAG_ACK, four, sizeof(four));
		inject_ctl(&r, WRI_M2_TAG_ACK, nine, sizeof(nine));
		inject_ctl(&r, WRI_M2_TAG_ACK, NULL, 0);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.sent_len, before);
		WRT_CHECK_U64(r.c.n_msg_in, 0);
		WRT_CHECK_U64(r.c.n_ka_ack, 0);
	}
	rig_free(&r);
}

/* ---- the send calls ----------------------------------------------------------------------------------- */

static void test_send_edges(void)
{
	static const uint8_t b[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	wri_m2_msg_out m;
	wr_iov iov[WRI_M2_TXQ_IOV];
	rig r;

	rig_init(&r);
	ready_rig(&r);
	m = mk(5, 1, b, 8, NULL, 0);

	/* argument checks: nothing is queued, no sequence number is used */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(NULL, &r.c, &m));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, NULL, &m));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, NULL));
	m.front = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, &m)); /* front_len 8 without bytes */
	m = mk(5, 1, NULL, 0, NULL, 16);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, &m)); /* data_len 16 without bytes */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_keepalive(NULL, &r.c, 1, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_keepalive(&r.x, NULL, 1, 2));
	WRT_CHECK_U64(wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), 0);
	WRT_CHECK_U64(r.c.out_seq, 0);

	/* a message larger than the whole encode buffer: TOOBIG, the connection lives, the number is not used */
	{
		uint8_t *big = (uint8_t *)calloc(1, r.tx_cap + 64u);

		m = mk(5, 1, big, r.tx_cap + 64u, NULL, 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_conn_send_message(&r.x, &r.c, &m));
		WRT_CHECK_U64(r.c.out_seq, 0);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		free(big);
	}

	/* the sequence space is used up: refused for good, keepalive still works */
	r.c.out_seq = UINT64_MAX;
	m = mk(5, 1, b, 8, NULL, 0);
	WRT_CHECK_STATUS(WR_E_OVERFLOW, wri_m2_conn_send_message(&r.x, &r.c, &m));
	WRT_CHECK_U64(r.c.out_seq, UINT64_MAX);
	WRT_CHECK_U64(wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), 0);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	rig_free(&r);

	/* a keepalive in a full queue: BUSY, nothing changes */
	rig_init(&r);
	r.tx_cap = 4096;
	ready_rig(&r);
	{
		unsigned n = 0;

		while (wri_m2_conn_send_keepalive(&r.x, &r.c, n, n) == WR_OK && n < 1000)
			n++;
		WRT_CHECK(n > 10 && n < 1000);
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 1));
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.err.status, 0);
		rig_flush_tx(&r);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 1));
	}
	rig_free(&r);
}

/* ---- NULL tolerance ----------------------------------------------------------------------------------- */

static void test_null_arguments(void)
{
	rig r;
	uint8_t *w = (uint8_t *)1;
	wr_iov iov[2];
	uint32_t budget = 5;

	wri_m2_conn_bind(NULL, 0, NULL, 0, NULL, 0, NULL, 0, 0);
	wri_m2_conn_open(NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0);
	WRT_CHECK_U64(wri_m2_conn_rx_window(NULL, &w), 0);
	WRT_CHECK(w == NULL);
	WRT_CHECK_U64(wri_m2_conn_rx_window(NULL, NULL), 0);
	wri_m2_conn_rx_commit(NULL, 3);
	WRT_CHECK_U64(wri_m2_conn_tx_peek(NULL, iov, 2), 0);
	wri_m2_conn_tx_consume(NULL, 3);
	WRT_CHECK_U64(wri_m2_conn_step(NULL, NULL, &budget), 0);
	wri_m2_conn_close(NULL, NULL, WR_OK);
	wri_m2_conn_on_closed(NULL, NULL, 0);
	WRT_CHECK_U64(wri_m2_conn_deadline(NULL), WR_DEADLINE_NONE);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(NULL, NULL, NULL));

	/* a slot that was never opened is inert */
	rig_init(&r);
	rig_start(&r);
	wri_m2_conn_on_closed(&r.x, &r.c, 0);
	WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
	WRT_CHECK_U64(wri_m2_conn_rx_window(&r.c, &w), 0);
	WRT_CHECK_U64(wri_m2_conn_step(&r.x, &r.c, &budget), 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
	wri_m2_conn_on_connected(&r.x, &r.c); /* not CONNECTING: ignored */
	WRT_CHECK_U64(r.c.state, WRI_M2_FREE);
	rig_free(&r);
}

/* ---- open() with bad arguments ------------------------------------------------------------------------ */

#define OPEN_CASES 9

static void open_case(unsigned which)
{
	static uint8_t ring[256], ctl[256], txb[256], pb1[256], pb2[256];
	wri_m2_conn c;
	wri_m2_preauth pa;
	rig r;

	rig_init(&r);
	wri_m2_preauth_init(&pa, pb1, pb2, sizeof(pb1));
	if (which == 8)
		wri_m2_preauth_init(&pa, NULL, NULL, 0);
	memset(&c, 0, sizeof(c));
	wri_m2_conn_bind(&c, 1, which == 0 ? NULL : ring, sizeof(ring), which == 1 ? NULL : ctl, sizeof(ctl),
			 which == 2 ? NULL : txb, sizeof(txb), 1024);
	wri_m2_conn_open(&c, 9, which == 3 ? 7 : WRI_ENTITY_MON, which == 4 ? NULL : &r.target, &r.dial,
			 which == 5 ? NULL : &stub_ops, &r.au, which == 6 ? NULL : &up_ops, &r.up, which == 7 ? NULL : &pa, 1,
			 1);
	if (c.state != WRI_M2_FAILED)
		fprintf(stderr, "open case %u: state %u\n", which, (unsigned)c.state);
	WRT_CHECK_U64(c.state, WRI_M2_FAILED);
	WRT_CHECK_STATUS(WR_E_INVAL, c.err.status);
	WRT_CHECK(c.pa == NULL);
	WRT_CHECK_U64(r.up.n_closed, 0); /* reported by the first step, like any other failure */
	wri_m2_conn_on_connected(&r.x, &c); /* not CONNECTING: ignored */
	WRT_CHECK_U64(c.state, WRI_M2_FAILED);
	(void)wri_m2_conn_step(&r.x, &c, NULL);
	(void)wri_m2_conn_step(&r.x, &c, NULL);
	WRT_CHECK_U64(r.up.n_closed, which == 6 ? 0u : 1u);
	if (which != 6)
		WRT_CHECK_STATUS(WR_E_INVAL, r.up.closed_err.status);
	wri_m2_conn_close(&r.x, &c, WR_OK); /* nothing to close */
	WRT_CHECK_U64(wri_m2_conn_deadline(&c), WR_DEADLINE_NONE);
	wri_m2_conn_on_closed(&r.x, &c, 0);
	WRT_CHECK_U64(c.state, WRI_M2_FREE);
	WRT_CHECK_U64(r.up.n_closed, which == 6 ? 0u : 1u);
	rig_free(&r);
}

static void test_open_arguments(void)
{
	unsigned i;

	for (i = 0; i < OPEN_CASES; i++)
		open_case(i);
}

/* ---- secrets do not stay in the control buffer ---------------------------------------------------------- */

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static void test_control_buffer_wiped(void)
{
	rig r;

	/* after the answer to AUTH_REPLY_MORE (state AUTH again): the server's challenge (13 bytes) is gone */
	rig_init(&r);
	r.scfg.f.out_limit = 98 + 49;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_AUTH);
	WRT_CHECK_U64(r.au.n_more, 1);
	WRT_CHECK(all_zero(r.ctl_buf, 13));
	rig_free(&r);

	/* after AUTH_DONE (state SIG): the final payload (tickets in real life) is gone */
	rig_init(&r);
	r.scfg.f.out_limit = 239;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_SIG);
	WRT_CHECK_U64(r.au.n_done, 1);
	WRT_CHECK(all_zero(r.ctl_buf, 56));
	rig_free(&r);

	/* once the server's signature is checked (state IDENT) the expected value and both transcripts are gone */
	rig_init(&r);
	r.scfg.f.out_limit = 307;
	rig_start(&r);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_IDENT);
	WRT_CHECK(all_zero(r.c.sig_want, sizeof(r.c.sig_want)));
	WRT_CHECK_U64(r.pa.rx_len, 0);
	WRT_CHECK_U64(r.pa.tx_len, 0);
	WRT_CHECK(all_zero(r.pa_rx, 239));
	WRT_CHECK(all_zero(r.pa_tx, 254));
	rig_free(&r);

	/* a closed connection keeps nothing: control buffer, ring, both transcripts and the expected signature are wiped */
	rig_init(&r);
	r.scfg.f.out_limit = 239;
	rig_start(&r);
	rig_pump(&r);
	wri_m2_conn_close(&r.x, &r.c, WR_E_CANCELLED);
	WRT_CHECK(all_zero(r.ctl_buf, r.ctl_cap));
	WRT_CHECK(all_zero(r.ring_buf, r.ring_cap));
	WRT_CHECK(all_zero(r.pa_rx, 239)); /* the transcripts of the handshake (239 bytes received, 254 sent) */
	WRT_CHECK(all_zero(r.pa_tx, 254));
	WRT_CHECK_U64(r.pa.rx_len, 0);
	WRT_CHECK_U64(r.pa.tx_len, 0);
	WRT_CHECK(all_zero(r.c.sig_want, sizeof(r.c.sig_want)));
	rig_free(&r);
}

/* ---- what SERVER_IDENT leaves behind ------------------------------------------------------------------ */

static void test_ident_results(void)
{
	rig r;

	/* the connection features are what both sides support: bits the server has and we do not advertise are cut */
	rig_init(&r);
	r.scfg.ident_supported = ~(uint64_t)0;
	ready_rig(&r);
	WRT_CHECK_U64(r.c.features, 0x3f07fffffffdffffull);
	/* and the handshake timer is off for good once READY: even much later nothing times out */
	WRT_CHECK_U64(r.c.deadline_ms, WR_DEADLINE_NONE);
	r.x.now.mono_ms += 1000000;
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), WR_DEADLINE_NONE);
	rig_free(&r);

	/* a server that supports less: the intersection */
	rig_init(&r);
	r.scfg.ident_supported = 0x0800000000000001ull;
	ready_rig(&r);
	WRT_CHECK_U64(r.c.features, 0x0800000000000001ull);
	rig_free(&r);
}

/* ---- the owner closes from inside a callback ---------------------------------------------------------- */

static void close_on_ready(void *ctx, wri_m2_conn *c)
{
	rig_up *u = (rig_up *)ctx;

	u->n_ready++;
	wri_m2_conn_close(&u->r->x, c, WR_OK);
}

static wr_status close_in_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3],
			       wri_m2_sink sink[3])
{
	rig_up *u = (rig_up *)ctx;
	wr_status st = up_plan(ctx, c, hdr, seglen, sink);

	wri_m2_conn_close(&u->r->x, c, WR_E_CANCELLED);
	return st;
}

static void close_in_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	rig_up *u = (rig_up *)ctx;

	up_message(ctx, c, hdr, stored);
	wri_m2_conn_close(&u->r->x, c, WR_E_CANCELLED);
}

static void check_closed_by_owner(rig *r, wr_status why)
{
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t *w;
	size_t before = r->sent_len;

	WRT_CHECK_U64(r->c.state, WRI_M2_CLOSING);
	WRT_CHECK_U64(r->up.n_closed, 1);
	WRT_CHECK_STATUS(why, r->up.closed_err.status);
	WRT_CHECK(r->c.pa == NULL);
	WRT_CHECK_U64(wri_m2_conn_tx_peek(&r->c, iov, WRI_M2_TXQ_IOV), 0);
	WRT_CHECK_U64(wri_m2_conn_rx_window(&r->c, &w), 0);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r->c), WR_DEADLINE_NONE);
	rig_pump(r);
	WRT_CHECK_U64(r->sent_len, before);
	WRT_CHECK_U64(r->up.n_closed, 1);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r->x, &r->c, 1, 2));
	wri_m2_conn_on_closed(&r->x, &r->c, 0); /* the host confirms the close */
	WRT_CHECK_U64(r->c.state, WRI_M2_FREE);
	WRT_CHECK_U64(r->up.n_closed, 1);
}

static void test_close_from_callbacks(void)
{
	static const uint8_t front[16] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
	wri_m2_upper ops;
	rig r;

	/* from ready(): the session was just established and is closed at once */
	rig_init(&r);
	ops = up_ops;
	ops.ready = close_on_ready;
	rig_start(&r);
	r.c.up = &ops;
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_ready, 1);
	check_closed_by_owner(&r, WR_OK);
	rig_free(&r);

	/* from plan(): the message is not delivered, later frames are ignored */
	rig_init(&r);
	ops = up_ops;
	ops.plan = close_in_plan;
	ready_rig(&r);
	r.c.up = &ops;
	inject_msg(&r, 1, 1, 5, front, sizeof(front), NULL, 0, 0);
	inject_msg(&r, 2, 2, 5, front, sizeof(front), NULL, 0, 0);
	WRT_CHECK_U64(r.up.n_message, 0);
	check_closed_by_owner(&r, WR_E_CANCELLED);
	rig_free(&r);

	/* from message(): that message counted, the next one never arrives */
	rig_init(&r);
	ops = up_ops;
	ops.message = close_in_message;
	ready_rig(&r);
	r.c.up = &ops;
	inject_msg(&r, 1, 1, 5, front, sizeof(front), NULL, 0, 0);
	inject_msg(&r, 2, 2, 5, front, sizeof(front), NULL, 0, 0);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.c.in_seq, 1);
	check_closed_by_owner(&r, WR_E_CANCELLED);
	rig_free(&r);
}

int main(void)
{
	test_auth_busy_is_final();
	test_blob_caps();
	test_tiny_encode_buffer();
	test_backpressure_at_done();
	test_backpressure_at_signature();
	test_malformed_control();
	test_send_edges();
	test_null_arguments();
	test_open_arguments();
	test_control_buffer_wiped();
	test_ident_results();
	test_close_from_callbacks();
	return wrt_finish();
}
