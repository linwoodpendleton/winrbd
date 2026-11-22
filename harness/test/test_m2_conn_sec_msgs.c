/* SPDX-License-Identifier: MIT */
/*
 * m2-conn-sec, session half (docs/design/core-architecture.md 34.6, 34.7, 34.9): messages in secure mode, both ways, against the secure peer of
 * sim_m2.h (its own codec, ref_gcm underneath; nothing of the core's crypto is on the other end of the wire).
 *
 *   - client -> server: MESSAGE frames of one, two and four segments (the connection's shapes), front and data lengths around the 16-byte block
 *     and the 48-byte inline limit, bounce buffers of 256 bytes and up, the host consuming whole queues, 7 bytes at a time and 1 byte at a time;
 *   - server -> client: one, two, three and four segments (an empty middle in front of data), delivered whole, in the pieces of the notes and one
 *     byte at a time; every segment lands in the sink the upper layer chose, sequence numbers and ack_seq as the sender wrote them;
 *   - 4 MiB data segments each way: the client's send through a bounce buffer of 256 bytes and of 64 KiB (the stream), the server's through the
 *     direct window of the receive parser;
 *   - KEEPALIVE2 and ACK frames interleaved with a stream in progress: WR_E_BUSY for the sender (no sequence number, no nonce used) and the
 *     retry; the keepalive of the server mid-stream is answered after the stream drained, in order;
 *   - a frame whose sender aborted it (late_status 1) is dropped, nonces already advanced, the next message is delivered;
 *   - an upper layer that answers WR_E_BUSY to plan() while a secure frame waits;
 *   - a long randomised conversation with every kind of frame in both directions and random host chunking;
 *   - the nonce counters of both directions started a few operations below 2^64 (the wrap, defined and exercised);
 *   - a connection slot used twice: a new connection after a closed one gets a new secret and a clean slot.
 * Time: the independent GCM is slow (about 1 MB/s), so the bulk cases are kept to what they need.
 */
#include "m2_conn_msgs.h"
#include "m2_conn_sec_cx.h"
#include "wri_le.h"

#define OFFER_BOTH (WRI_M2_OFFER_CRC | WRI_M2_OFFER_SECURE | WRI_M2_OFFER_SECURE_FIRST)

/* A secure session up to READY. */
static void secure_ready(rig *r, uint32_t bounce_cap)
{
	r->bounce_cap = bounce_cap;
	rig_enable_secure(r, OFFER_BOTH);
	rig_server_modes(r, 2, 1);
	rig_start(r);
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(r->c.mode, WRI_CONN_MODE_SECURE);
	WRT_CHECK_U64(sim_m2_is_secure(r->s), 1);
	WRT_CHECK_U64(r->up.n_ready, 1);
}

static uint64_t t_rng = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void)
{
	t_rng ^= t_rng << 13;
	t_rng ^= t_rng >> 7;
	t_rng ^= t_rng << 17;
	return (uint32_t)(t_rng >> 11);
}

/* ---- client -> server ----------------------------------------------------------------------------------------------- */

static void send_and_check(rig *r, uint16_t type, uint64_t tid, uint32_t flen, uint32_t dlen, uint8_t seed)
{
	uint8_t *front = (uint8_t *)malloc(flen + 1u), *data = (uint8_t *)malloc(dlen + 1u);
	wri_m2_msg_out m;
	uint32_t k = r->s->n_msgs, seen = r->s->n_msgs_seen;
	const sim_m2_msg *g;

	fill(front, flen, seed);
	fill(data, dlen, (uint8_t)(seed + 91u));
	m = mk(type, tid, flen != 0 ? front : NULL, flen, dlen != 0 ? data : NULL, dlen);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r->x, &r->c, &m));
	rig_pump(r);
	WRT_CHECK_U64(r->c.state, WRI_M2_READY);
	WRT_CHECK_U64(r->s->n_msgs_seen, seen + 1u);
	WRT_CHECK_U64(r->s->n_msgs, k + 1u);
	if (r->s->n_msgs == k + 1u) {
		g = &r->s->msgs[k];
		WRT_CHECK_U64(g->type, type);
		WRT_CHECK_U64(g->tid, tid);
		WRT_CHECK_U64(g->seq, r->c.out_seq);
		WRT_CHECK_U64(g->priority, 127);
		WRT_CHECK_U64(g->version, 3);
		WRT_CHECK_U64(g->compat_version, 1);
		WRT_CHECK_U64(g->seg_len[0], flen);
		WRT_CHECK_U64(g->seg_len[1], 0);
		WRT_CHECK_U64(g->seg_len[2], dlen);
		WRT_CHECK_U64(g->nseg, dlen != 0 ? 4 : flen != 0 ? 2 : 1);
		if (flen != 0 && g->seg_len[0] == flen)
			WRT_CHECK_MEM(g->seg[0], front, flen);
		if (dlen != 0 && g->seg_len[2] == dlen)
			WRT_CHECK_MEM(g->seg[2], data, dlen);
	}
	free(front);
	free(data);
}

static void test_to_server(void)
{
	static const uint32_t F[] = {0, 1, 15, 16, 17, 47, 48, 49, 1000};
	static const uint32_t D[] = {0, 1, 15, 16, 255, 256, 257, 4097};
	static const struct {
		uint32_t bounce;
		size_t tx_chunk;
		int all;
	} cfgs[] = {{4096, 0, 1}, {256, 0, 0}, {272, 7, 0}, {65536, 0, 0}, {256, 1, 0}};
	size_t c, i, j;

	for (c = 0; c < sizeof(cfgs) / sizeof(cfgs[0]); c++) {
		rig r;
		uint64_t tid = 100;
		uint8_t seed = (uint8_t)(c * 3u);

		rig_init(&r);
		r.tx_chunk = cfgs[c].tx_chunk;
		secure_ready(&r, cfgs[c].bounce);
		for (i = 0; i < sizeof(F) / sizeof(F[0]); i++) {
			for (j = 0; j < sizeof(D) / sizeof(D[0]); j++) {
				/* the first configuration walks the whole grid; the others the shapes that cross a bounce piece or a block edge */
				if (!cfgs[c].all && !(D[j] >= 255u || (F[i] % 16u) == 1u))
					continue;
				if (D[j] == 4097u && F[i] != 0u && F[i] != 17u && F[i] != 48u)
					continue; /* (time: the independent GCM is slow) */
				if (cfgs[c].tx_chunk == 1u && D[j] > 257u)
					continue; /* one byte per peek/consume pair: the longer data segments are covered by the other configurations */
				send_and_check(&r, (uint16_t)(0x100u + (uint16_t)i), tid++, F[i], D[j], (uint8_t)(i * 13u + j + seed));
			}
		}
		/* a longer data segment through the stream at this bounce size */
		if (cfgs[c].tx_chunk != 1u)
			send_and_check(&r, 0x1ff, tid++, 33, 20000, 0x6d);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
		WRT_CHECK_U64(r.c.out_seq, r.s->n_msgs_seen);
		/* the nonces: one per operation, so the counters of the two ends agree (the server's decoder verified every tag in order) */
		WRT_CHECK_U64(r.slot->s.tx_n.ops, r.s->sec.dec.rx->ops);
		rig_free(&r);
	}
}

/* ---- server -> client ----------------------------------------------------------------------------------------------- */

static void test_to_client(void)
{
	static const size_t rx_chunks[] = {0, 1, 7, 16, 95, 4096};
	static const uint32_t FL[] = {0, 1, 16, 49, 3000};
	static const uint32_t ML[] = {0, 5, 48, 17};
	static const uint32_t DL[] = {0, 1, 16, 255, 5000};
	size_t c, f, m, d;

	for (c = 0; c < sizeof(rx_chunks) / sizeof(rx_chunks[0]); c++) {
		rig r;
		uint64_t tid = 500;
		size_t expect = 0;

		rig_init(&r);
		r.rx_chunk = rx_chunks[c];
		secure_ready(&r, 4096);
		for (f = 0; f < sizeof(FL) / sizeof(FL[0]); f++) {
			for (m = 0; m < sizeof(ML) / sizeof(ML[0]); m++) {
				for (d = 0; d < sizeof(DL) / sizeof(DL[0]); d++) {
					uint8_t *front, *mid, *data;
					uint32_t fl = FL[f], ml = ML[m], dl = DL[d];
					size_t k = r.up.n_msgs;
					const rig_msg *g;

					if (rx_chunks[c] == 1u && (dl > 255u || fl > 49u))
						continue; /* one byte per commit and step: the big ones go through the other chunkings */
					if (rx_chunks[c] != 0u && rx_chunks[c] != 4096u && (f + m + d) % 3u != 0u)
						continue; /* a sample of the grid for the odd chunk sizes */
					front = (uint8_t *)malloc(fl + 1u);
					mid = (uint8_t *)malloc(ml + 1u);
					data = (uint8_t *)malloc(dl + 1u);
					fill(front, fl, (uint8_t)(f * 5u + 1u));
					fill(mid, ml, (uint8_t)(m * 7u + 2u));
					fill(data, dl, (uint8_t)(d * 11u + 3u));
					WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x200, tid, 4, fl != 0 ? front : NULL, fl, ml != 0 ? mid : NULL, ml,
										    dl != 0 ? data : NULL, dl));
					rig_pump(&r);
					expect++;
					WRT_CHECK_U64(r.up.n_msgs, k + 1u);
					if (r.up.n_msgs == k + 1u) {
						g = &r.up.msgs[k];
						WRT_CHECK_U64(g->hdr.type, 0x200);
						WRT_CHECK_U64(g->hdr.tid, tid);
						WRT_CHECK_U64(g->hdr.seq, r.s->out_seq);
						WRT_CHECK_U64(g->hdr.ack_seq, r.s->in_seq);
						WRT_CHECK_U64(g->stored[0], fl);
						WRT_CHECK_U64(g->stored[1], ml);
						WRT_CHECK_U64(g->stored[2], dl);
						if (fl != 0 && g->stored[0] == fl)
							WRT_CHECK_MEM(g->seg[0], front, fl);
						if (ml != 0 && g->stored[1] == ml)
							WRT_CHECK_MEM(g->seg[1], mid, ml);
						if (dl != 0 && g->stored[2] == dl)
							WRT_CHECK_MEM(g->seg[2], data, dl);
					}
					tid++;
					free(front), free(mid), free(data);
					if (r.up.n_msgs >= RIG_MAXMSG - 2u)
						goto done; /* the rig keeps 512 messages */
				}
			}
		}
	done:
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.n_msg_in, expect);
		WRT_CHECK_U64(r.c.n_seq_gaps, 0);
		WRT_CHECK_U64(r.c.in_seq, r.s->out_seq);
		WRT_CHECK_U64(r.slot->s.rx_n.ops, r.s->sec.ctx.tx.ops); /* one nonce per operation on both ends */
		rig_free(&r);
	}
}

/* ---- 4 MiB each way ---------------------------------------------------------------------------------------------------- */

/* The bytes of the sealed 4 MiB message of the first bounce size, kept to compare the second run with: the stream the connection produces is a
 * function of the secret and the frame alone, whatever the bounce buffer. */
static void test_big(void)
{
	static const uint32_t bounces[] = {256, 65536};
	const uint32_t big = 4u << 20;
	uint8_t *ref = NULL, *data = (uint8_t *)malloc(big);
	size_t ref_len = 0, i, k;
	uint8_t front[300];

	fill(front, sizeof(front), 0x11);
	for (i = 0; i < sizeof(bounces) / sizeof(bounces[0]); i++) {
		rig r;
		wri_m2_msg_out m;

		rig_init(&r);
		r.io_cap = 24u << 20;
		r.seg_cap_max = 8u << 20;
		r.scfg.seg_cap = 8u << 20;
		r.scfg.msg_bytes_cap = 32u << 20;
		secure_ready(&r, bounces[i]);
		/* client -> server: the data segment is a stream sealed piece by piece out of the caller's memory */
		fill(data, big, 0x31);
		m = mk(0x300, 1, front, sizeof(front), data, big);
		if (i != 0u)
			r.skip_tx = (size_t)-1; /* the second run is compared with the first run's bytes, not decoded again (the independent GCM needs seconds per MiB) */
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
		{
			uint64_t before = r.c.tx.pending;
			wr_iov iov[WRI_M2_TXQ_IOV];
			size_t n = wri_m2_conn_tx_peek(&r.c, iov, WRI_M2_TXQ_IOV), j, shown = 0;

			WRT_CHECK(before > big); /* everything counted from the start, the stream included */
			for (j = 0; j < n; j++)
				shown += iov[j].len;
			WRT_CHECK(shown < before);                /* what peek shows is only what is produced so far... */
			WRT_CHECK(shown <= 8192u + bounces[i]);   /* ... the encode buffer and one bounce piece */
		}
		/* a second frame while the stream is active: WR_E_BUSY, and it takes no nonce and no sequence number */
		{
			uint64_t ops = r.slot->s.tx_n.ops, seq = r.c.out_seq;
			wri_m2_msg_out m2 = mk(0x301, 2, front, 10, NULL, 0);

			WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_message(&r.x, &r.c, &m2));
			WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
			WRT_CHECK_U64(r.slot->s.tx_n.ops, ops);
			WRT_CHECK_U64(r.c.out_seq, seq);
		}
		{
			size_t before = r.sent_len;

			rig_pump(&r);
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			WRT_CHECK(r.sent_len > before + big);
			if (i == 0u) {
				ref_len = r.sent_len - before;
				ref = (uint8_t *)malloc(ref_len);
				memcpy(ref, r.sent + before, ref_len);
			} else {
				WRT_CHECK_U64(r.sent_len - before, ref_len); /* the same bytes at every bounce size */
				if (r.sent_len - before == ref_len)
					WRT_CHECK_MEM(r.sent + before, ref, ref_len);
			}
		}
		if (i == 0u) {
			WRT_CHECK_U64(r.s->n_msgs, 1);
			if (r.s->n_msgs == 1u) {
				WRT_CHECK_U64(r.s->msgs[0].seg_len[2], big);
				if (r.s->msgs[0].seg_len[2] == big)
					WRT_CHECK_MEM(r.s->msgs[0].seg[2], data, big);
				WRT_CHECK_MEM(r.s->msgs[0].seg[0], front, sizeof(front));
			}
			/* the retry after the drain works, with the next sequence number */
			{
				wri_m2_msg_out m2 = mk(0x301, 2, front, 10, NULL, 0);

				WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m2));
				WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 1, 2));
				rig_pump(&r);
				WRT_CHECK_U64(r.s->n_msgs, 2);
				WRT_CHECK_U64(r.s->msgs[1].seq, 2);
				WRT_CHECK_U64(r.c.n_ka_ack, 1);
			}
			/* server -> client (once: the receive side does not depend on our bounce size): 4 MiB straight into the sink through the direct window */
			free(r.up.dbuf);
			r.up.dcap = big;
			r.up.dbuf = (uint8_t *)malloc(big);
			fill(data, big, 0x62);
			k = r.up.n_msgs;
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x301, 7, 4, front, 100, NULL, 0, data, big));
			rig_pump(&r);
			WRT_CHECK_U64(r.up.n_msgs, k + 1u);
			if (r.up.n_msgs == k + 1u && r.up.msgs[k].stored[2] == big)
				WRT_CHECK_MEM(r.up.msgs[k].seg[2], data, big);
			WRT_CHECK_U64(r.c.state, WRI_M2_READY);
			WRT_CHECK_U64(r.up.n_closed, 0);
		}
		rig_free(&r);
	}
	free(ref);
	free(data);
}

/* ---- keepalives and ACKs interleaved with a stream; BUSY and its retry ------------------------------------------------------ */

static void test_interleaved(void)
{
	rig r;
	uint8_t front[64], *data;
	wri_m2_msg_out m;
	const uint32_t dl = 40000;
	uint64_t ops0;
	size_t i;

	rig_init(&r);
	secure_ready(&r, 256);
	data = (uint8_t *)malloc(dl);
	fill(front, sizeof(front), 3);
	fill(data, dl, 9);
	/* the host does not consume: the first frame's stream stays active, every other send is BUSY and changes nothing */
	m = mk(0x400, 1, front, sizeof(front), data, dl);
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
	ops0 = r.slot->s.tx_n.ops;
	for (i = 0; i < 3; i++) {
		wri_m2_msg_out m2 = mk(0x401, 2, front, 8, NULL, 0);

		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_message(&r.x, &r.c, &m2));
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_conn_send_keepalive(&r.x, &r.c, 10, 20));
	}
	WRT_CHECK_U64(r.slot->s.tx_n.ops, ops0); /* a refused frame takes no nonce */
	WRT_CHECK_U64(r.c.out_seq, 1);           /* ... and burns no sequence number */
	/* the server's keepalive arrives while the stream is still being drained: its answer waits (the connection stalls on it) */
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(r.s, 77, 88));
	{
		uint8_t *w = NULL;
		size_t room = wri_m2_conn_rx_window(&r.c, &w), n = sim_m2_drain(r.s, w, room);

		/* (the first bytes the server has are the rest of its handshake already consumed: what is pending is just the keepalive) */
		memcpy(r.rcvd + r.rcvd_len, w, n), r.rcvd_len += n;
		wri_m2_conn_rx_commit(&r.c, n);
	}
	(void)wri_m2_conn_step(&r.x, &r.c, NULL);
	WRT_CHECK_U64(r.s->n_keepalive_ack, 0); /* nothing of the answer yet: the stream owns the end of the wire */
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	/* now the host drains: everything arrives, in order, nothing lost or doubled */
	rig_pump(&r);
	WRT_CHECK_U64(r.s->n_msgs, 1);
	WRT_CHECK_U64(r.s->n_keepalive_ack, 1);
	WRT_CHECK_U64(r.s->last_kaack_sec, 77);
	WRT_CHECK_U64(r.s->last_kaack_nsec, 88);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	if (r.s->n_msgs == 1u)
		WRT_CHECK_MEM(r.s->msgs[0].seg[2], data, dl);
	/* and the retries go through */
	{
		wri_m2_msg_out m2 = mk(0x401, 2, front, 8, NULL, 0);

		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m2));
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 10, 20));
		rig_pump(&r);
		WRT_CHECK_U64(r.s->n_msgs, 2);
		WRT_CHECK_U64(r.s->msgs[1].seq, 2);
		WRT_CHECK_U64(r.s->n_keepalive, 1);
		WRT_CHECK_U64(r.c.n_ka_ack, 1);
	}
	free(data);
	rig_free(&r);
}

/* A frame the sender aborted (late_status 1): contents dropped, tag verified, nonces advanced, the next message is delivered. */
static void test_aborted(void)
{
	rig r;
	uint8_t front[100], data[3000];

	rig_init(&r);
	secure_ready(&r, 4096);
	fill(front, sizeof(front), 1);
	fill(data, sizeof(data), 2);
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x500, 1, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
	rig_pump(&r);
	WRT_CHECK_U64(r.up.n_message, 1);
	/* the next server frame is sent with late_status 1 */
	r.s->cfg.f.sec.mut_frame = r.s->n_tx_frames + 1u;
	r.s->cfg.f.sec.mut.mask = SIM_SEC_M_LATE;
	r.s->cfg.f.sec.mut.late_status = SIM_SEC_LATE_ABORTED;
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x501, 2, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
	r.s->cfg.f.sec.mut_frame = 0;
	WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x502, 3, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_closed, 0);
	WRT_CHECK_U64(r.up.n_message, 2);        /* the aborted one was not delivered... */
	WRT_CHECK_U64(r.c.n_msg_dropped, 1);     /* ... it was dropped, and counted */
	WRT_CHECK_U64(r.c.n_seq_gaps, 1);        /* its sequence number was used by the sender: the next delivered one skips it */
	WRT_CHECK_U64(r.up.msgs[1].hdr.type, 0x502);
	WRT_CHECK_U64(r.up.msgs[1].hdr.seq, 3);
	WRT_CHECK_U64(r.c.in_seq, 3);
	WRT_CHECK_U64(r.slot->s.rx_n.ops, r.s->sec.ctx.tx.ops); /* the aborted frame's operations were counted */
	/* and the session goes on in both directions */
	WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_keepalive(&r.x, &r.c, 4, 5));
	rig_pump(&r);
	WRT_CHECK_U64(r.c.n_ka_ack, 1);
	rig_free(&r);
}

/* plan() answers WR_E_BUSY: the frame is held, nothing is lost, the secure parser does not run ahead of it. */
static void test_plan_busy(void)
{
	rig r;
	uint8_t front[200], data[9000];
	size_t i;

	rig_init(&r);
	secure_ready(&r, 4096);
	fill(front, sizeof(front), 5);
	fill(data, sizeof(data), 6);
	r.up.busy_times = 4;
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x600, i + 1u, 4, front, sizeof(front), NULL, 0, data, sizeof(data)));
	rig_pump(&r);
	WRT_CHECK_U64(r.c.state, WRI_M2_READY);
	WRT_CHECK_U64(r.up.n_message, 3);
	WRT_CHECK_U64(r.up.n_plan, 3 + 4); /* asked again after every BUSY, once per message otherwise */
	for (i = 0; i < 3; i++) {
		WRT_CHECK_U64(r.up.msgs[i].hdr.tid, i + 1u);
		WRT_CHECK_MEM(r.up.msgs[i].seg[2], data, sizeof(data));
	}
	rig_free(&r);
}

/* ---- a long conversation ---------------------------------------------------------------------------------------------------- */

static void test_conversation(void)
{
	static const uint32_t bounces[] = {256, 1024, 8192};
	size_t b;

	for (b = 0; b < sizeof(bounces) / sizeof(bounces[0]); b++) {
		rig r;
		size_t sent_msgs = 0, got_msgs = 0, sent_ka = 0, srv_ka = 0, step;
		uint64_t tid = 1000;

		t_rng = 0x1234567890abcdefull + b;
		rig_init(&r);
		r.rx_chunk = (b == 0) ? 0u : (b == 1) ? 3u : 100u;
		r.tx_chunk = (b == 0) ? 5u : (b == 1) ? 0u : 4096u;
		r.up.dcap = 1u << 18;
		free(r.up.dbuf);
		r.up.dbuf = (uint8_t *)malloc(r.up.dcap);
		secure_ready(&r, bounces[b]);
		for (step = 0; step < 150 && r.up.n_msgs < RIG_MAXMSG - 4u; step++) {
			uint32_t pick = rnd() % 8u;
			uint8_t buf[4096 + 64];
			uint32_t fl = rnd() % 200u, dl = (rnd() % 3u == 0u) ? rnd() % 20000u : rnd() % 100u, i;
			wri_m2_msg_out m;
			wr_status st;

			for (i = 0; i < sizeof(buf); i++)
				buf[i] = (uint8_t)(rnd() >> 3);
			switch (pick) {
			case 0:
			case 1: { /* a client message; the data buffer must live until the host consumed it, so it is allocated per send and kept */
				uint8_t *data = (uint8_t *)malloc(dl + 1u);

				for (i = 0; i < dl; i++)
					data[i] = (uint8_t)(i * 7u + step);
				m = mk(0x700, tid, buf, fl, dl != 0 ? data : NULL, dl);
				st = wri_m2_conn_send_message(&r.x, &r.c, &m);
				if (st == WR_E_BUSY) {
					rig_pump(&r); /* drain, then retry once */
					st = wri_m2_conn_send_message(&r.x, &r.c, &m);
				}
				WRT_CHECK_STATUS(WR_OK, st);
				if (st == WR_OK)
					sent_msgs++, tid++;
				rig_pump(&r); /* the host consumed everything by now: the caller's buffer may go */
				free(data);
				break;
			}
			case 2:
			case 3:
				st = wri_m2_conn_send_keepalive(&r.x, &r.c, (uint32_t)step, 99);
				if (st == WR_E_BUSY) {
					rig_pump(&r);
					st = wri_m2_conn_send_keepalive(&r.x, &r.c, (uint32_t)step, 99);
				}
				WRT_CHECK_STATUS(WR_OK, st);
				if (st == WR_OK)
					sent_ka++;
				break;
			case 4:
			case 5:
			{
				uint32_t ml = (rnd() & 1u) ? 30u : 0u, dd = dl > sizeof(buf) ? (uint32_t)sizeof(buf) : dl;

				WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x701, tid++, 4, buf, fl, ml != 0 ? buf + 100 : NULL, ml, dd != 0 ? buf : NULL, dd));
				break;
			}
			case 6:
				WRT_CHECK_STATUS(WR_OK, sim_m2_send_keepalive(r.s, (uint32_t)step, 7));
				srv_ka++;
				break;
			default: { /* an ACK frame of the server: the content is not needed, the nonce is */
				uint8_t ack[8] = {1, 0, 0, 0, 0, 0, 0, 0};
				wri_m2_seg_src seg;

				seg.p = ack, seg.len = 8, seg.ref = 0;
				WRT_CHECK_STATUS(WR_OK, sim_m2_send_frame(r.s, WRI_M2_TAG_ACK, &seg, 1));
				break;
			}
			}
			if (rnd() % 3u == 0u)
				rig_pump(&r);
		}
		rig_pump(&r);
		got_msgs = r.up.n_msgs;
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(sim_m2_error(r.s)->status, 0);
		WRT_CHECK_U64(r.s->n_msgs_seen, sent_msgs);
		WRT_CHECK_U64(r.s->n_keepalive, sent_ka);
		WRT_CHECK_U64(r.c.n_ka_ack, sent_ka);
		WRT_CHECK_U64(r.s->n_keepalive_ack, srv_ka);
		WRT_CHECK_U64(r.c.n_msg_in, got_msgs);
		WRT_CHECK_U64(r.slot->s.tx_n.ops, r.s->sec.dec.rx->ops);
		WRT_CHECK_U64(r.slot->s.rx_n.ops, r.s->sec.ctx.tx.ops);
		rig_free(&r);
	}
}

/* ---- the nonce counters across 2^64 --------------------------------------------------------------------------------------------- */

static void test_counter_wrap(void)
{
	rig r;
	size_t i;
	uint8_t front[120];
	uint64_t ctrs[3] = {0xfffffffffffffffcull, 0xfffffffffffffffeull, 0xffffffffffffffffull};

	for (i = 0; i < 3; i++) {
		size_t k;

		rig_init(&r);
		/* both seeds patched in the secret the server issues: our transmit counter (seed B) and our receive counter (seed A) start just below 2^64 */
		r.scfg.f.sec.has_ctr_a = r.scfg.f.sec.has_ctr_b = 1;
		r.scfg.f.sec.ctr_a = ctrs[i];
		r.scfg.f.sec.ctr_b = ctrs[(i + 1) % 3];
		secure_ready(&r, 4096);
		fill(front, sizeof(front), 4);
		for (k = 0; k < 12; k++) { /* the counters wrap early in the handshake or early in the session: either way many frames follow */
			wri_m2_msg_out m = mk(0x800, k + 1u, front, 10 + (uint32_t)k * 8u, NULL, 0);

			WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
			WRT_CHECK_STATUS(WR_OK, sim_m2_send_message(r.s, 0x801, k + 1u, 4, front, 10 + (uint32_t)k * 8u, NULL, 0, NULL, 0));
			rig_pump(&r);
		}
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.up.n_closed, 0);
		WRT_CHECK_U64(r.s->n_msgs, 12);
		WRT_CHECK_U64(r.up.n_msgs, 12);
		WRT_CHECK(r.slot->s.tx_n.ops > 12 && r.slot->s.rx_n.ops > 12);
		/* the counter really went round: the nonce in use is now small, the seed's was near the top */
		WRT_CHECK(wri_le64_get(r.slot->s.tx_n.cur + 4) < 100u);
		WRT_CHECK(wri_le64_get(r.slot->s.rx_n.cur + 4) < 100u);
		rig_free(&r);
	}
}

/* ---- a connection slot used twice ----------------------------------------------------------------------------------------------- */

static void test_reuse(void)
{
	rig r;
	uint8_t secret1[64], secret2[64];
	wri_m2_msg_out m;
	uint8_t front[30];
	int life;

	rig_init(&r);
	secure_ready(&r, 4096);
	memcpy(secret1, r.s->sec.secret, 64);
	fill(front, sizeof(front), 8);
	for (life = 0; life < 2; life++) {
		m = mk(0x900, 1, front, sizeof(front), NULL, 0);
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_send_message(&r.x, &r.c, &m));
		rig_pump(&r);
		WRT_CHECK_U64(r.s->n_msgs, 1);
		if (life == 1)
			break;
		/* the first connection ends: slot and bounce zero, the seam back to crc, nothing of the key anywhere */
		wri_m2_conn_close(&r.x, &r.c, WR_OK);
		WRT_CHECK(rig_slot_zero(&r));
		WRT_CHECK(r.c.rx.sx == NULL && r.c.tx.sx == NULL);
		/* a new connection on the same connection slot and the same secure slot, with a server that issues another secret */
		sim_m2_free(r.s);
		r.scfg.sec.seed = 0x5eed1234ull;
		r.s = sim_m2_new(&r.scfg, &r.sops);
		WRT_CHECK(r.s != NULL);
		r.sent_len = r.rcvd_len = 0;
		r.up.n_ready = 0;
		r.up.n_closed = 0;
		r.au.n_secret = r.au.n_done = r.au.n_begin = r.au.n_more = 0;
		r.au.seq_done = r.au.seq_secret = r.au.seq_key = r.au.ord = 0;
		memset(r.slot, 0xab, sizeof(*r.slot)); /* whatever the host left there */
		wri_m2_preauth_init(&r.pa, r.pa_rx, r.pa_tx, r.pa_cap);
		wri_m2_conn_open(&r.c, 0x00010005u, r.role, &r.target, &r.dial, r.ops, r.ops_ctx, &up_ops, &r.up, &r.pa, r.nonce, r.gseq + 1u);
		WRT_CHECK(r.c.sec == NULL); /* open() starts the connection crc only: the slot is handed over again */
		WRT_CHECK_STATUS(WR_OK, wri_m2_conn_set_secure(&r.c, r.offer, r.slot, r.bounce, r.bounce_cap));
		wri_m2_conn_on_connected(&r.x, &r.c);
		rig_pump(&r);
		WRT_CHECK_U64(r.c.state, WRI_M2_READY);
		WRT_CHECK_U64(r.c.mode, 2);
		memcpy(secret2, r.s->sec.secret, 64);
		WRT_CHECK(memcmp(secret1, secret2, 64) != 0); /* a new connection has a new secret and so a new key and new nonces (34.5) */
		WRT_CHECK(rig_secret_absent(&r, secret1, 64));
	}
	rig_free(&r);

	/* open() of a slot whose previous life never ended through close / on_closed wipes the old key all the same */
	rig_init(&r);
	secure_ready(&r, 4096);
	WRT_CHECK(r.slot->s.active == 1);
	wri_m2_preauth_init(&r.pa, r.pa_rx, r.pa_tx, r.pa_cap);
	wri_m2_conn_open(&r.c, 0x00010006u, r.role, &r.target, &r.dial, r.ops, r.ops_ctx, &up_ops, &r.up, &r.pa, r.nonce, r.gseq + 2u);
	WRT_CHECK(rig_slot_zero(&r));
	WRT_CHECK(r.c.sec == NULL);
	rig_free(&r);
}

/* A name on the command line runs only the tests whose name contains it (for debugging); no argument runs everything. */
#define RUN(fn)                                                       \
	do {                                                          \
		if (argc < 2 || strstr(#fn, argv[1]) != NULL) {       \
			fprintf(stderr, "-- %s\n", #fn);               \
			fn();                                         \
		}                                                     \
	} while (0)

int main(int argc, char **argv)
{
	RUN(test_to_server);
	RUN(test_to_client);
	RUN(test_big);
	RUN(test_interleaved);
	RUN(test_aborted);
	RUN(test_plan_busy);
	RUN(test_conversation);
	RUN(test_counter_wrap);
	RUN(test_reuse);
	return wrt_finish();
}
