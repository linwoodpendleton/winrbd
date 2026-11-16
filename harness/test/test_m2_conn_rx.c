/* SPDX-License-Identifier: MIT */
/*
 * m2-conn, READY half, receive side: MESSAGE frames from the server (the scriptable server of sim_m2.h and
 * hand-built frames where a real server would never misbehave): sinks chosen by plan() and filled in place,
 * unknown message types discarded through plan(), plan() backpressure and refusal, oversized segments, short
 * headers, old / duplicate / gapped sequence numbers, aborted frames, many messages in one feed. The send side
 * is in test_m2_conn_msg.c.
 */
#include "m2_conn_msgs.h"

static void test_receive_basic(void)
{
	rig r;
	uint8_t front[900], mid[30], data[70000];
	size_t i;

	fill(front, sizeof(front), 1);
	fill(mid, sizeof(mid), 2);
	fill(data, sizeof(data), 3);
	rig_init(&r);
	ready_rig(&r);
	memset(r.up.fbuf, 0xA5, 64);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x42, 99, 4, front, sizeof(front), mid, sizeof(mid), data,
						    sizeof(data)));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x43, 100, 1, front, 10, NULL, 0, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x44, 101, 1, NULL, 0, NULL, 0, NULL, 0));
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, 3);
	WRT_CHECK_U64(r.up.n_plan, 3);
	WRT_CHECK_U64(r.c.in_seq, 3);
	WRT_CHECK_U64(r.c.n_msg_in, 3);
	WRT_CHECK_U64(r.up.msgs[0].hdr.seq, 1);
	WRT_CHECK_U64(r.up.msgs[0].hdr.tid, 99);
	WRT_CHECK_U64(r.up.msgs[0].hdr.type, 0x42);
	WRT_CHECK_U64(r.up.msgs[0].hdr.version, 4);
	WRT_CHECK_U64(r.up.msgs[0].stored[0], sizeof(front));
	WRT_CHECK_U64(r.up.msgs[0].stored[1], sizeof(mid));
	WRT_CHECK_U64(r.up.msgs[0].stored[2], sizeof(data));
	WRT_CHECK_MEM(r.up.msgs[0].seg[0], front, sizeof(front));
	WRT_CHECK_MEM(r.up.msgs[0].seg[1], mid, sizeof(mid));
	WRT_CHECK_MEM(r.up.msgs[0].seg[2], data, sizeof(data));
	WRT_CHECK_U64(r.up.msgs[1].stored[0], 10);
	WRT_CHECK_U64(r.up.msgs[1].stored[1], 0);
	WRT_CHECK_U64(r.up.msgs[1].stored[2], 0);
	WRT_CHECK_U64(r.up.msgs[2].stored[0], 0);
	WRT_CHECK_U64(r.up.msgs[2].hdr.seq, 3);
	for (i = 0; i < 3; i++)
		WRT_CHECK_U64(r.up.msgs[i].hdr.seq, i + 1);
	rig_free(&r);

	/* a big data segment arrives in odd pieces too */
	rig_init(&r);
	r.rx_chunk = 777;
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x42, 99, 4, front, sizeof(front), mid, sizeof(mid), data,
						    sizeof(data)));
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_MEM(r.up.msgs[0].seg[2], data, sizeof(data));
	rig_free(&r);
}

static void test_unknown_types(void)
{
	rig r;
	uint8_t front[100], data[2000];

	fill(front, sizeof(front), 1);
	fill(data, sizeof(data), 2);
	rig_init(&r);
	r.up.discard_type = 999;
	r.up.discard_type_set = 1;
	ready_rig(&r);
	memset(r.up.fbuf, 0xA5, 256);
	memset(r.up.dbuf, 0xA5, 4096);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 999, 1, 1, front, sizeof(front), NULL, 0, data, sizeof(data)));
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 1, 2, 1, front, sizeof(front), NULL, 0, NULL, 0));
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK_U64(r.up.n_plan, 2);
	WRT_CHECK_U64(r.up.n_message, 2);
	WRT_CHECK_U64(r.up.msgs[0].hdr.type, 999);
	WRT_CHECK_U64(r.up.msgs[0].stored[0], 0); /* discarded: nothing was stored, the sinks are untouched */
	WRT_CHECK_U64(r.up.msgs[0].stored[2], 0);
	WRT_CHECK_U64(r.up.fbuf[0], front[0]); /* the second one went to the sink */
	WRT_CHECK_U64(r.up.msgs[1].stored[0], 100);
	WRT_CHECK_MEM(r.up.msgs[1].seg[0], front, 100);
	WRT_CHECK_U64(r.up.dbuf[0], 0xA5);
	WRT_CHECK_U64(r.up.seglen[0], 100); /* plan saw the lengths of the second message */
	WRT_CHECK_U64(r.up.seglen[2], 0);
	WRT_CHECK_U64(r.c.in_seq, 2);
	rig_free(&r);

	rig_init(&r);
	r.up.discard_all = 1;
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 5, 1, 1, front, sizeof(front), NULL, 0, data, sizeof(data)));
	rig_pump(&r);
	WRT_CHECK_U64(r.up.seglen[0], 100);
	WRT_CHECK_U64(r.up.seglen[1], 0);
	WRT_CHECK_U64(r.up.seglen[2], 2000);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.up.n_closed, 0);
	rig_free(&r);
}

static void test_oversize(void)
{
	rig r;
	uint8_t front[300], data[2000];

	fill(front, sizeof(front), 1);
	fill(data, sizeof(data), 2);
	/* the upper layer's sink is smaller than the segment */
	rig_init(&r);
	r.up.fcap = 100;
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 1, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_FRAME_TOOBIG);
	WRT_CHECK_U64(r.up.n_message, 0);
	rig_free(&r);

	/* a segment above the configured cap is refused at the preamble, whatever plan would say */
	rig_init(&r);
	r.seg_cap_max = 1000;
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 1, 1, 1, front, sizeof(front), NULL, 0, data, sizeof(data)));
	rig_pump(&r);
	rig_check_failed(&r, WR_E_M2_FRAME_TOOBIG);
	WRT_CHECK_U64(r.up.n_plan, 0);
	rig_free(&r);

	/* the upper layer refuses: its status is the connection's */
	rig_init(&r);
	r.up.plan_fail = WR_E_MON_MSG_TOOBIG;
	ready_rig(&r);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 1, 1, 1, front, sizeof(front), NULL, 0, NULL, 0));
	rig_pump(&r);
	rig_check_failed(&r, WR_E_MON_MSG_TOOBIG);
	WRT_CHECK_U64(r.up.n_message, 0);
	rig_free(&r);
}

static void test_short_header(void)
{
	rig r;
	uint8_t h[64], *fr;
	wri_m2_seg_src seg;
	size_t fl, len;

	tc_pay_hdr2(h, 1, 1, 7, 0);
	memset(h + 41, 0, 23);
	for (len = 0; len <= 50; len += (len < 38 ? 38 : 1)) {
		rig_init(&r);
		ready_rig(&r);
		seg.p = h, seg.len = (uint32_t)len, seg.ref = 0;
		fr = rig_build_frame(WRI_M2_TAG_MESSAGE, &seg, 1, &fl);
		rig_inject(&r, fr, fl);
		free(fr);
		if (len < 41) { /* the stock code reads past the buffer here; we refuse */
			rig_check_failed(&r, WR_E_M2_FRAME_FORM);
			WRT_CHECK_U64(r.up.n_message, 0);
		} else {
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			WRT_CHECK_U64(r.up.n_message, 1); /* extra bytes after the 41 are ignored */
		}
		rig_free(&r);
	}
}

static void test_sequence_rules(void)
{
	rig r;
	uint8_t f[20];
	static const uint64_t seqs[] = {1, 2, 2, 1, 5, 0, 6, 6, 5, 9};
	static const int deliver[] = {1, 1, 0, 0, 1, 0, 1, 0, 0, 1};
	size_t i, delivered = 0, dropped = 0;

	fill(f, sizeof(f), 1);
	rig_init(&r);
	ready_rig(&r);
	for (i = 0; i < sizeof(seqs) / sizeof(seqs[0]); i++) {
		int before = r.up.n_message;
		int plan_before = r.up.n_plan;

		inject_msg(&r, seqs[i], 100 + i, 5, f, sizeof(f), NULL, 0, 0);
		WRT_CHECK_U64(r.up.n_message - before, deliver[i]);
		WRT_CHECK_U64(r.up.n_plan - plan_before, deliver[i]); /* an old message is not even offered to plan() */
		delivered += (size_t)deliver[i];
		dropped += deliver[i] ? 0u : 1u;
	}
	WRT_CHECK_U64(r.c.in_seq, 9);
	WRT_CHECK_U64(r.c.n_msg_in, delivered);
	WRT_CHECK_U64(r.c.n_msg_dropped, dropped);
	WRT_CHECK_U64(r.c.n_seq_gaps, 2); /* 2 -> 5 and 6 -> 9 */
	WRT_CHECK_U64(r.up.n_closed, 0);
	/* what we send carries the highest seq received; our own numbering is independent */
	{
		wri_m2_msg_out m = mk(1, 1, NULL, 0, NULL, 0);

		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
		rig_pump(&r);
		WRT_CHECK_U64(r.s->msgs[0].ack_seq, 9);
		WRT_CHECK_U64(r.s->msgs[0].seq, 1);
	}
	rig_free(&r);
}

static void test_aborted_frame(void)
{
	rig r;
	uint8_t f[200];

	fill(f, sizeof(f), 4);
	rig_init(&r);
	ready_rig(&r);
	inject_msg(&r, 1, 1, 5, f, sizeof(f), NULL, 0, WRI_M2_LATE_ABORTED); /* the sender gave up on it */
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_message, 0);
	WRT_CHECK_U64(r.up.n_plan, 1); /* the sinks were offered; the frame never completed */
	WRT_CHECK_U64(r.c.in_seq, 0);  /* an aborted message does not count: its number may come again */
	WRT_CHECK_U64(r.c.n_msg_dropped, 1);
	inject_msg(&r, 1, 2, 5, f, sizeof(f), NULL, 0, 0);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.c.in_seq, 1);
	rig_free(&r);
}

static void test_plan_backpressure(void)
{
	rig r;
	uint8_t f[64];
	uint32_t budget = 100;
	int i;

	fill(f, sizeof(f), 6);
	rig_init(&r);
	ready_rig(&r);
	r.up.busy_times = 3;
	inject_msg(&r, 1, 1, 5, f, sizeof(f), NULL, 0, 0);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_plan, 1);
	WRT_CHECK_U64(r.up.n_message, 0);
	WRT_CHECK_U64(r.c.stalled, 1);
	WRT_CHECK_U64(wri_m2_conn_deadline(&r.c), r.x.now.mono_ms + WRI_M2C_STALL_RETRY_MS);
	/* two frames behind the held one wait in the ring; the window keeps working until it is full */
	{
		uint8_t *w;

		WRT_CHECK(wri_m2_conn_rx_window(&r.c, &w) > 0);
	}
	for (i = 0; i < 2; i++) {
		(void)wri_m2_conn_step(&r.x, &r.c, &budget);
		WRT_CHECK_U64(r.up.n_message, 0);
		WRT_CHECK_U64(r.c.stalled, 1);
	}
	WRT_CHECK_U64(r.up.n_plan, 3);
	(void)wri_m2_conn_step(&r.x, &r.c, &budget); /* plan finally says yes */
	WRT_CHECK_U64(r.up.n_plan, 4);
	WRT_CHECK_U64(r.up.n_message, 1);
	WRT_CHECK_U64(r.c.stalled, 0);
	WRT_CHECK_U64(r.c.in_seq, 1);
	WRT_CHECK_U64(r.up.msgs[0].stored[0], sizeof(f));
	WRT_CHECK_MEM(r.up.msgs[0].seg[0], f, sizeof(f));
	WRT_CHECK_U64(r.up.n_closed, 0);
	rig_free(&r);

	/* the order of frames behind a held message is kept */
	rig_init(&r);
	ready_rig(&r);
	r.up.busy_times = 1;
	{
		size_t k;

		for (k = 1; k <= 3; k++)
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 5, k, 1, f, sizeof(f), NULL, 0, NULL, 0));
	}
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, 3);
	WRT_CHECK_U64(r.up.msgs[0].hdr.tid, 1);
	WRT_CHECK_U64(r.up.msgs[1].hdr.tid, 2);
	WRT_CHECK_U64(r.up.msgs[2].hdr.tid, 3);
	WRT_CHECK_U64(r.up.n_plan, 4);
	rig_free(&r);
}

static void test_many_messages(void)
{
	rig r;
	uint8_t f[40];
	size_t i, n = 200;

	fill(f, sizeof(f), 9);
	rig_init(&r);
	r.ring_cap = 16384;
	ready_rig(&r);
	for (i = 1; i <= n; i++) {
		wri_le64_put(f, i); /* the message tells its own number */
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 5, i, 1, f, sizeof(f), NULL, 0, NULL, 0));
	}
	/* one feed: everything the server has goes into the ring in one go, one step handles all of it */
	{
		int progress = 0;

		(void)rig_deliver(&r, &progress);
		WRT_CHECK(progress);
		(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	}
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, RIG_MAXMSG > n ? n : RIG_MAXMSG);
	WRT_CHECK_U64(r.c.in_seq, n);
	for (i = 0; i < r.up.n_msgs; i++) {
		WRT_CHECK_U64(r.up.msgs[i].hdr.seq, i + 1);
		WRT_CHECK_U64(wri_le64_get(r.up.msgs[i].seg[0]), i + 1);
	}
	WRT_CHECK_U64(r.up.n_closed, 0);
	rig_free(&r);

	/* a tiny budget per step: the connection reports more work until it is done */
	rig_init(&r);
	r.ring_cap = 16384;
	ready_rig(&r);
	for (i = 1; i <= 50; i++)
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 5, i, 1, f, sizeof(f), NULL, 0, NULL, 0));
	{
		int progress = 0, more, rounds = 0;
		uint32_t budget;

		(void)rig_deliver(&r, &progress);
		do {
			budget = 50;
			more = wri_m2_conn_step(&r.x, &r.c, &budget);
			rounds++;
		} while (more && rounds < 10000);
		WRT_CHECK(rounds > 10);
		WRT_CHECK_U64(r.up.n_message, 50);
	}
	rig_free(&r);
}

int main(void)
{
	test_receive_basic();
	test_unknown_types();
	test_oversize();
	test_short_header();
	test_sequence_rules();
	test_aborted_frame();
	test_plan_backpressure();
	test_many_messages();
	return wrt_finish();
}
