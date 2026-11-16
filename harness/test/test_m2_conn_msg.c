/* SPDX-License-Identifier: MIT */
/*
 * m2-conn, READY half: the MESSAGE / KEEPALIVE2 flow of wri_m2_conn against the scriptable server of
 * sim_m2.h (and hand-built frames where the server would never misbehave): sequence numbers from 1 and
 * never reused, ack_seq, send_message only in READY (WR_E_STATE otherwise) and WR_E_BUSY when the queue
 * is full (the number is not burnt), the zero-copy data segment, partial transmit consumption, and
 * KEEPALIVE2 answered with the stamp echoed. The receive side is in test_m2_conn_rx.c.
 */
#include "m2_conn_msgs.h"

/* ---- sending ---------------------------------------------------------------------------------------- */

static void test_send_states(void)
{
	static const int64_t limit[] = {26, 98, 239, 307};
	size_t i;
	wri_m2_msg_out m = mk(1, 1, NULL, 0, NULL, 0);

	for (i = 0; i < 4; i++) {
		rig r;

		rig_init(&r);
		r.scfg.f.out_limit = limit[i];
		rig_start(&r);
		rig_pump(&r);
		WRT_CHECK(r.c.state != WRI_M2_READY);
		WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
		WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
		WRT_CHECK_U64(r.c.out_seq, 0);
		rig_free(&r);
	}
	{ /* before the TCP connection is reported, and after the connection failed */
		rig r;

		rig_init(&r);
		rig_start(&r);
		rig_pump(&r);
		wri_m2_conn_close(&r.x, &r.c, WR_E_CANCELLED);
		WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
		wri_m2_conn_on_closed(&r.x, &r.c, 0);
		WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &m));
		rig_free(&r);
	}
	{ /* argument errors */
		rig r;
		wri_m2_msg_out bad = mk(1, 1, NULL, 5, NULL, 0);

		rig_init(&r);
		ready_rig(&r);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, &bad));
		bad = mk(1, 1, NULL, 0, NULL, 5);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_conn_send_message(&r.x, &r.c, &bad));
		WRT_CHECK_U64(r.c.out_seq, 0);
		rig_free(&r);
	}
}

static void test_send_numbering(void)
{
	rig r;
	uint8_t front[300], data[5000];
	wri_m2_msg_out m;
	size_t i;

	fill(front, sizeof(front), 1);
	fill(data, sizeof(data), 9);
	rig_init(&r);
	ready_rig(&r);
	/* an empty message, a front only, a front and data, data only */
	m = mk(0x10, 11, NULL, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	m = mk(0x11, 12, front, 300, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	m = mk(0x12, 13, front, 100, data, 5000);
	m.compat_version = 0; /* as the stock encoder: compat_version = version when left 0 */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	m = mk(0x13, 14, NULL, 0, data, 4096);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	WRT_CHECK_U64(r.c.out_seq, 4);
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.s->n_msgs, 4);
	WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
	for (i = 0; i < r.s->n_msgs; i++) {
		const sim_m2_msg *g = &r.s->msgs[i];

		WRT_CHECK_U64(g->seq, i + 1);
		WRT_CHECK_U64(g->tid, 11 + i);
		WRT_CHECK_U64(g->type, 0x10 + i);
		WRT_CHECK_U64(g->priority, 127);
		WRT_CHECK_U64(g->version, 3);
		WRT_CHECK_U64(g->flags, 3);
		WRT_CHECK_U64(g->pre_padding, 0);
		WRT_CHECK_U64(g->data_off, 0);
		WRT_CHECK_U64(g->ack_seq, 0); /* we have received nothing yet */
	}
	WRT_CHECK_U64(r.s->msgs[0].nseg, 1);
	WRT_CHECK_U64(r.s->msgs[1].nseg, 2);
	WRT_CHECK_U64(r.s->msgs[1].compat_version, 1);
	WRT_CHECK_U64(r.s->msgs[2].compat_version, 3);
	WRT_CHECK_U64(r.s->msgs[2].nseg, 4);
	WRT_CHECK_U64(r.s->msgs[3].nseg, 4); /* the middle segment is there, empty, because data follows */
	WRT_CHECK_U64(r.s->msgs[1].seg_len[0], 300);
	WRT_CHECK_MEM(r.s->msgs[1].seg[0], front, 300);
	WRT_CHECK_U64(r.s->msgs[2].seg_len[0], 100);
	WRT_CHECK_MEM(r.s->msgs[2].seg[0], front, 100);
	WRT_CHECK_U64(r.s->msgs[2].seg_len[2], 5000);
	WRT_CHECK_MEM(r.s->msgs[2].seg[2], data, 5000);
	WRT_CHECK_U64(r.s->msgs[3].seg_len[0], 0);
	WRT_CHECK_U64(r.s->msgs[3].seg_len[2], 4096);
	WRT_CHECK_MEM(r.s->msgs[3].seg[2], data, 4096);
	rig_free(&r);
}

static void test_ack_seq(void)
{
	rig r;
	uint8_t f[40];
	wri_m2_msg_out m = mk(1, 1, NULL, 0, NULL, 0);
	unsigned i;

	fill(f, sizeof(f), 3);
	rig_init(&r);
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->msgs[0].ack_seq, 0);
	for (i = 1; i <= 3; i++)
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 5, i, 1, f, sizeof(f), NULL, 0, NULL, 0));
	rig_pump(&r);
	WRT_CHECK_U64(r.c.in_seq, 3);
	WRT_CHECK_U64(r.up.n_message, 3);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs, 2);
	WRT_CHECK_U64(r.s->msgs[1].seq, 2);
	WRT_CHECK_U64(r.s->msgs[1].ack_seq, 3); /* piggybacked ack: what we received so far */
	/* the stock server's strictness: seq 1, 2 accepted, nothing complained about */
	WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
	rig_free(&r);
}

static void test_busy_and_zero_copy(void)
{
	rig r;
	uint8_t data[6000], front[64];
	wri_m2_msg_out m;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, accepted = 0, seen_data = 0;
	wr_status st = WR_OK;

	fill(data, sizeof(data), 5);
	fill(front, sizeof(front), 77);
	rig_init(&r);
	ready_rig(&r);
	/* messages with a data segment each add gather entries: the queue is full by entries before bytes */
	m = mk(0x20, 1, front, sizeof(front), data, sizeof(data));
	for (i = 0; i < 20 && st == WR_OK; i++) {
		m.tid = i + 1;
		st = wri_m2_conn_send_message(&r.x, &r.c, &m);
		if (st == WR_OK)
			accepted++;
	}
	WRT_CHECK_STATUS(WR_E_BUSY, st);
	WRT_CHECK(accepted >= 3 && accepted < 8);
	WRT_CHECK_U64(r.c.out_seq, accepted); /* a refused send does not burn a sequence number */
	/* zero copy: the data segment is in the gather list as our own memory, the front is not */
	n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		if (iov[i].base == data) {
			seen_data++;
			WRT_CHECK_U64(iov[i].len, sizeof(data));
		}
		WRT_CHECK(!(iov[i].base >= front && iov[i].base < front + sizeof(front)));
	}
	WRT_CHECK_U64(seen_data, accepted); /* one gather entry per message, pointing at our buffer */
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs, accepted);
	for (i = 0; i < r.s->n_msgs; i++) {
		WRT_CHECK_U64(r.s->msgs[i].seq, i + 1);
		WRT_CHECK_U64(r.s->msgs[i].seg_len[2], sizeof(data));
		WRT_CHECK_MEM(r.s->msgs[i].seg[2], data, sizeof(data));
		WRT_CHECK_MEM(r.s->msgs[i].seg[0], front, sizeof(front));
	}
	/* after the queue drained the next send gets the next number */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->msgs[accepted].seq, accepted + 1);
	rig_free(&r);

	/* too large for the encode buffer even when empty: TOOBIG, not BUSY (waiting does not help) */
	{
		uint8_t *big = (uint8_t *)malloc(20000);
		wri_m2_msg_out bm;

		fill(big, 20000, 1);
		rig_init(&r);
		ready_rig(&r);
		bm = mk(1, 1, big, 20000, NULL, 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		WRT_CHECK_U64(r.c.out_seq, 0);
		bm = mk(1, 1, front, 64, NULL, 0);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		WRT_CHECK_U64(r.c.out_seq, 1);
		rig_free(&r);
		free(big);
	}
	/* byte-count BUSY: a front that nearly fills the buffer, then a second one */
	{
		uint8_t *big = (uint8_t *)malloc(5000);
		wri_m2_msg_out bm;

		fill(big, 5000, 1);
		rig_init(&r);
		ready_rig(&r);
		bm = mk(1, 1, big, 5000, NULL, 0);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		WRT_CHECK_U64(r.c.out_seq, 1);
		rig_pump(&r);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		rig_pump(&r);
		WRT_CHECK_U64(r.s->n_msgs, 2);
		WRT_CHECK_U64(r.s->msgs[1].seq, 2);
		rig_free(&r);
		free(big);
	}
}

static void test_partial_consume(void)
{
	rig r;
	uint8_t data[3000], front[50];
	wri_m2_msg_out m;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t before, after, n, i;

	fill(data, sizeof(data), 21);
	fill(front, sizeof(front), 22);
	rig_init(&r);
	ready_rig(&r);
	m = mk(0x30, 9, front, sizeof(front), data, sizeof(data));
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
	for (before = 0, i = 0; i < n; i++)
		before += iov[i].len;
	WRT_CHECK_U64(before, 32 + 41 + 4 + 50 + 3000 + 13);
	/* the host wrote only part of it, into the middle of the data segment */
	wri_m2_conn_tx_consume(&r.c, 32 + 41 + 4 + 50 + 700);
	n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
	for (after = 0, i = 0; i < n; i++)
		after += iov[i].len;
	WRT_CHECK_U64(after, before - (32 + 41 + 4 + 50 + 700));
	WRT_CHECK(n >= 1 && iov[0].base == data + 700 && iov[0].len == 2300);
	/* a new message queues behind the old one, which is still half out */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	WRT_CHECK_U64(r.c.out_seq, 2);
	rig_free(&r);

	/* byte-at-a-time transmit of two messages, data included, is byte-exact at the server */
	rig_init(&r);
	r.tx_chunk = 1;
	ready_rig(&r);
	m = mk(0x30, 9, front, sizeof(front), data, sizeof(data));
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs, 2);
	WRT_CHECK_MEM(r.s->msgs[0].seg[2], data, sizeof(data));
	WRT_CHECK_MEM(r.s->msgs[1].seg[2], data, sizeof(data));
	WRT_CHECK_U64(r.s->msgs[1].seq, 2);
	rig_free(&r);
}

/* ---- keepalive ---------------------------------------------------------------------------------------- */

static void test_keepalive(void)
{
	rig r;
	uint8_t b[8];
	wri_m2_msg_out m = mk(1, 1, NULL, 0, NULL, 0);
	wr_iov iov[WRI_M2_TXQ_IOV];

	/* the server pings: the reply carries the same stamp, and no MESSAGE seq is used */
	rig_init(&r);
	ready_rig(&r);
	r.x.now.mono_ms = 5000;
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(r.s, 123, 456789));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_keepalive_ack, 1);
	WRT_CHECK_U64(r.s->last_kaack_sec, 123);
	WRT_CHECK_U64(r.s->last_kaack_nsec, 456789);
	WRT_CHECK_U64(r.c.out_seq, 0);
	WRT_CHECK_U64(r.c.last_rx_ms, 5000);
	WRT_CHECK_U64(r.c.last_tx_ms, 5000);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->msgs[0].seq, 1);

	/* we ping: the stamp comes back and is recorded for the owner */
	r.x.now.mono_ms = 6000;
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 77, 88));
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_keepalive, 1);
	WRT_CHECK_U64(r.s->last_ka_sec, 77);
	WRT_CHECK_U64(r.s->last_ka_nsec, 88);
	WRT_CHECK_U64(r.c.n_ka_ack, 1);
	WRT_CHECK_U64(r.c.ka_ack_sec, 77);
	WRT_CHECK_U64(r.c.ka_ack_nsec, 88);
	WRT_CHECK_U64(r.c.ka_ack_ms, 6000);
	WRT_CHECK_U64(r.up.n_closed, 0);
	rig_free(&r);

	/* answer waits for room: the queue is nearly full, the ping arrives, nothing is lost */
	{
		uint8_t *big = (uint8_t *)malloc(4096);
		wri_m2_msg_out bm;
		size_t n, i, tot = 0;

		fill(big, 4096, 1);
		rig_init(&r);
		ready_rig(&r);
		bm = mk(1, 1, big, 8192 - 90 - 10, NULL, 0); /* leaves 10 free bytes */
		free(big);
		big = (uint8_t *)malloc(8192);
		fill(big, 8192, 1);
		bm.front = big;
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &bm));
		memset(b, 0, sizeof(b));
		wri_le32_put(b, 9), wri_le32_put(b + 4, 10);
		inject_ctl(&r, WRI_M2_TAG_KEEPALIVE2, b, 8);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.stalled, 1);
		n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV);
		for (i = 0; i < n; i++)
			tot += iov[i].len;
		WRT_CHECK_U64(tot, 90 + 8192 - 100);
		rig_pump(&r); /* the host drains, the held frame is answered */
		WRT_CHECK_U64(r.s->n_keepalive_ack, 1);
		WRT_CHECK_U64(r.s->last_kaack_sec, 9);
		WRT_CHECK_U64(r.s->last_kaack_nsec, 10);
		WRT_CHECK_U64(r.s->n_msgs, 1);
		WRT_CHECK_U64(r.up.n_closed, 0);
		rig_free(&r);
		free(big);
	}
	/* ACK frames of any content are ignored, KEEPALIVE2_ACK is only recorded; nothing is sent */
	rig_init(&r);
	ready_rig(&r);
	{
		size_t sent = r.sent_len;
		uint8_t a[8] = {1, 2, 3, 4, 5, 6, 7, 8};

		inject_ctl(&r, WRI_M2_TAG_ACK, a, 8);
		inject_ctl(&r, WRI_M2_TAG_ACK, a, 3);
		inject_ctl(&r, WRI_M2_TAG_KEEPALIVE2_ACK, a, 8);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.n_ka_ack, 1);
		WRT_CHECK_U64(r.sent_len, sent);
		WRT_CHECK_U64(wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), 0);
	}
	/* a malformed keepalive is fatal */
	{
		uint8_t a[7] = {0};

		inject_ctl(&r, WRI_M2_TAG_KEEPALIVE2, a, 7);
		rig_check_failed(&r, WR_E_TRUNCATED);
	}
	rig_free(&r);
}

static void test_ready_sends(void)
{
	rig r;
	wri_m2_msg_out m;
	uint8_t f[30];

	fill(f, sizeof(f), 1);
	rig_init(&r);
	m = mk(0x50, 1, f, sizeof(f), NULL, 0);
	r.up.send_on_ready = &m; /* the ready() callback may send at once */
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, r.up.ready_send_st);
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs, 1);
	WRT_CHECK_U64(r.s->msgs[0].seq, 1);
	WRT_CHECK_U64(r.s->msgs[0].type, 0x50);
	rig_free(&r);
}

static void test_close_then_send(void)
{
	rig r;

	rig_init(&r);
	ready_rig(&r);
	wri_m2_conn_close(&r.x, &r.c, WR_E_CANCELLED);
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.up.n_closed, 1);
	WRT_CHECK_U64(r.c.state, WRI_M2_CLOSING);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_message(&r.x, &r.c, &(wri_m2_msg_out){0}));
	rig_free(&r);
}

int main(void)
{
	test_send_states();
	test_send_numbering();
	test_ack_seq();
	test_busy_and_zero_copy();
	test_partial_consume();
	test_keepalive();
	test_ready_sends();
	test_close_then_send();
	return wrt_finish();
}
