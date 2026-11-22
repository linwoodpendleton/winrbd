/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_conn_msg.c - the READY half of a msgr2 client connection: MESSAGE receive and send,
 * KEEPALIVE2, ACK (docs/spec/msgr2.md 2.9, 3.7).
 *
 * Receive. A MESSAGE is announced by its SEG0 event: the 41-byte header2 is decoded (a shorter
 * segment 0 is a malformed frame, the stock code does not check), the sequence rule is applied
 * (seq <= in_seq: dropped, the frame is still read through so the stream stays in step, nothing
 * reaches the upper layer; a gap is accepted and counted) and for a delivered message the upper
 * layer's plan() picks where front / middle / data go. The message() callback fires at the FRAME
 * event, after every checksum passed. in_seq moves only then.
 *
 * Send. A MESSAGE frame is header2 (flags 3, seq = out_seq + 1, ack_seq = in_seq) + front copied into
 * the encode buffer + data referenced in place. out_seq moves only when the frame is queued: a
 * rejected send (BUSY, TOOBIG) never burns a sequence number and a number is never reused, because
 * the stock server stops reading a connection that repeats one (msgr2.md 2.9).
 *
 * Secure mode changes nothing here except sizes and one more reason to say WR_E_BUSY: a MESSAGE whose data is still being sealed piece by
 * piece (a stream, 34.6) owns the end of the wire, so the next send waits (BUSY, nothing consumed, no sequence number and no nonce used)
 * until the host has drained it. A refused nonce (34.5) ends the connection before any byte of the frame exists (WR_E_M2_NONCE in c->err);
 * the send returns WR_E_STATE and the upper layer hears of it at the next step (wri_m2c_tx_status).
 */
#include "wri_m2_conn.h"

WR_FILE_LICENCE_MIT

#define FAIL(x, c, st, what, a0, a1, a2) \
	(WRI_M2C_FAIL((x), (c), (st), (what), (a0), (a1), (a2)), (st))
#define FAIL0(x, c, st, what) FAIL((x), (c), (st), (what), 0, 0, 0)

#define KEEPALIVE_PAYLOAD 8u

/* ---- receive ------------------------------------------------------------------------------ */

/* Ask the upper layer where the segments go and apply its answer to the parser. */
static wr_status plan_sinks(const wri_ctx *x, wri_m2_conn *c, const wri_m2_hdr2 *h)
{
	const wri_m2_desc *d = &c->rx.desc;
	wri_m2_sink sink[3];
	uint32_t seglen[3];
	unsigned i;
	wr_status st;

	for (i = 0; i < 3u; i++) {
		seglen[i] = d->len[i + 1u]; /* 0 for the segments the frame does not have */
		sink[i].dst = NULL;
		sink[i].cap = 0;
	}
	st = c->up->plan(c->up_ctx, c, h, seglen, sink);
	if (st == WR_E_BUSY)
		return st; /* the upper layer has no room yet: hold the frame, nothing was changed */
	if (st != WR_OK)
		return FAIL(x, c, st, "upper layer refused the message", h->type, h->seq, 0);
	for (i = 0; i < 3u; i++)
		if (i + 1u < d->nseg)
			wri_m2_rx_sink(&c->rx, i + 1u, sink[i].dst, sink[i].cap);
	return WR_OK;
}

wr_status wri_m2c_msg_seg0(const wri_ctx *x, wri_m2_conn *c)
{
	const wri_m2_desc *d = &c->rx.desc;
	wri_m2_hdr2 h;
	wr_status st;

	if (d->len[0] < WRI_M2_HDR2_LEN)
		return FAIL(x, c, WR_E_M2_FRAME_FORM, "MESSAGE header segment shorter than 41 bytes", d->len[0],
			    WRI_M2_HDR2_LEN, 0);
	st = wri_m2_hdr2_decode(c->ctl_buf, d->len[0], &h);
	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed MESSAGE header");
	c->cur_keep = 0;
	if (h.seq > c->in_seq) { /* an old one is read through and thrown away: its sinks stay unset (discard) */
		st = plan_sinks(x, c, &h);
		if (st != WR_OK)
			return st;
		c->cur_keep = 1;
	}
	c->cur_hdr = h;
	return WR_OK;
}

static wr_status on_message(const wri_ctx *x, wri_m2_conn *c)
{
	wri_m2_hdr2 h = c->cur_hdr;
	uint32_t stored[3];
	unsigned i;

	(void)x;
	if (!c->cur_keep) {
		c->n_msg_dropped++;
		return WR_OK;
	}
	c->cur_keep = 0;
	if (h.seq - c->in_seq > 1u) /* delivered only if h.seq > in_seq, so the difference is positive */
		c->n_seq_gaps++;
	c->in_seq = h.seq;
	c->n_msg_in++;
	for (i = 0; i < 3u; i++)
		stored[i] = c->rx.stored[i + 1u];
	c->up->message(c->up_ctx, c, &h, stored);
	return WR_OK;
}

static wr_status on_keepalive(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	uint32_t sec = 0, nsec = 0;
	uint8_t b[8];
	wri_wr w;
	wr_status st = wri_m2_keepalive_decode(r, &sec, &nsec);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed KEEPALIVE2");
	st = wri_m2c_need_room(x, c, wri_m2c_frame_bytes(c->tx.sx != NULL, KEEPALIVE_PAYLOAD)); /* a secure frame is 96 bytes */
	if (st != WR_OK)
		return st;
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_keepalive_encode(&w, sec, nsec); /* the same stamp, as the sender matches it */
	st = wri_m2c_send(x, c, WRI_M2_TAG_KEEPALIVE2_ACK, b, (uint32_t)wri_wr_len(&w));
	if (st == WR_E_BUSY)
		return st;
	if (st != WR_OK)
		return FAIL0(x, c, st, "KEEPALIVE2_ACK could not be queued");
	return WR_OK;
}

static wr_status on_keepalive_ack(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	uint32_t sec = 0, nsec = 0;
	wr_status st = wri_m2_keepalive_decode(r, &sec, &nsec);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed KEEPALIVE2_ACK");
	c->ka_ack_ms = x->now.mono_ms;
	c->ka_ack_sec = sec;
	c->ka_ack_nsec = nsec;
	c->n_ka_ack++;
	return WR_OK;
}

wr_status wri_m2c_ready_frame(const wri_ctx *x, wri_m2_conn *c)
{
	wri_rd r;

	wri_rd_init(&r, c->ctl_buf, c->rx.desc.len[0]);
	switch (c->rx.desc.tag) {
	case WRI_M2_TAG_MESSAGE:
		return on_message(x, c);
	case WRI_M2_TAG_KEEPALIVE2:
		return on_keepalive(x, c, &r);
	case WRI_M2_TAG_KEEPALIVE2_ACK:
		return on_keepalive_ack(x, c, &r);
	case WRI_M2_TAG_ACK: /* lossy session: nothing is resent, so nothing to trim; the content is not needed */
		return WR_OK;
	default:
		return FAIL(x, c, WR_E_M2_STATE, "frame not allowed in this state", c->state, c->rx.desc.tag, 0);
	}
}

/* ---- send --------------------------------------------------------------------------------- */

/* header2 of the next message: seq = out_seq + 1, ack_seq = in_seq, flags 3. */
static void build_header(const wri_m2_conn *c, const wri_m2_msg_out *m, uint8_t hb[WRI_M2_HDR2_LEN])
{
	wri_m2_hdr2 h;

	WR_MEMSET(&h, 0, sizeof(h));
	h.seq = c->out_seq + 1u;
	h.tid = m->tid;
	h.type = m->type;
	h.priority = m->priority;
	h.version = m->version;
	h.compat_version = m->compat_version != 0 ? m->compat_version : m->version; /* as the stock encoder does */
	h.ack_seq = c->in_seq;
	h.flags = WRI_M2_MSGF_COMPLETE_NOCRC;
	wri_m2_hdr2_encode(hb, &h);
}

static void set_seg(wri_m2_seg_src *s, const uint8_t *p, uint32_t n, uint8_t ref, const uint8_t *dummy)
{
	s->p = p != NULL ? p : dummy; /* an empty segment still gets a valid pointer */
	s->len = n;
	s->ref = ref;
}

wr_status wri_m2_conn_send_message(const wri_ctx *x, wri_m2_conn *c, const wri_m2_msg_out *m)
{
	wri_m2_seg_src seg[4];
	uint8_t hb[WRI_M2_HDR2_LEN];
	wr_status st;

	if (x == NULL || c == NULL || m == NULL)
		return WR_E_INVAL;
	if (c->state != WRI_M2_READY)
		return WR_E_STATE; /* never before SERVER_IDENT was processed */
	if ((m->front_len != 0 && m->front == NULL) || (m->data_len != 0 && m->data == NULL))
		return WR_E_INVAL;
	if (c->out_seq + 1u == 0)
		return WR_E_OVERFLOW; /* a sequence number is never reused: this session is used up */
	build_header(c, m, hb);
	set_seg(&seg[0], hb, WRI_M2_HDR2_LEN, 0, hb);
	set_seg(&seg[1], m->front, m->front_len, 0, hb);
	set_seg(&seg[2], NULL, 0, 0, hb); /* no middle segment; present (empty) only when data follows */
	set_seg(&seg[3], m->data, m->data_len, 1, hb); /* the data segment is referenced, never copied */
	st = wri_m2_tx_frame(&c->tx, x->host.prim, WRI_M2_TAG_MESSAGE, seg,
			     m->data_len != 0 ? 4u : (m->front_len != 0 ? 2u : 1u), NULL, NULL);
	if (st != WR_OK) /* BUSY (a secure stream is still draining, or no room) / TOOBIG / INVAL: the sequence number was not used;
			  * a refused nonce (WR_E_M2_NONCE) also ends the connection */
		return wri_m2c_tx_status(x, c, st);
	c->out_seq++;
	c->last_tx_ms = x->now.mono_ms;
	return WR_OK;
}

wr_status wri_m2_conn_send_keepalive(const wri_ctx *x, wri_m2_conn *c, uint32_t sec, uint32_t nsec)
{
	uint8_t b[8];
	wri_wr w;

	if (x == NULL || c == NULL)
		return WR_E_INVAL;
	if (c->state != WRI_M2_READY)
		return WR_E_STATE;
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_keepalive_encode(&w, sec, nsec);
	return wri_m2c_tx_status(x, c, wri_m2c_send(x, c, WRI_M2_TAG_KEEPALIVE2, b, (uint32_t)wri_wr_len(&w))); /* BUSY while a stream drains */
}

/* ---- plumbing: the bytes in and out (the host's side of the pump; moved here to keep wri_m2_conn.c under the 500 lines of the core) ---------- */

size_t wri_m2_conn_rx_window(wri_m2_conn *c, uint8_t **ptr)
{
	if (ptr != NULL)
		*ptr = NULL;
	if (c == NULL || !wri_m2c_state_live(c->state))
		return 0;
	return wri_m2_rx_window(&c->rx, &c->ring, ptr);
}

void wri_m2_conn_rx_commit(wri_m2_conn *c, size_t n)
{
	if (c == NULL || !wri_m2c_state_live(c->state))
		return;
	wri_m2_rx_commit(&c->rx, &c->ring, n);
}

size_t wri_m2_conn_tx_peek(const wri_m2_conn *c, wr_iov *iov, size_t max)
{
	if (c == NULL || !wri_m2c_state_live(c->state))
		return 0;
	return wri_m2_txq_peek(&c->tx, iov, max);
}

void wri_m2_conn_tx_consume(wri_m2_conn *c, size_t n)
{
	if (c == NULL || !wri_m2c_state_live(c->state))
		return;
	wri_m2_txq_consume(&c->tx, n);
	wri_m2c_tx_check(NULL, c); /* no context here: the failure is recorded and reported at the next step, without a log line of its own */
	if (c->stalled)
		c->retry_ms = 0; /* room may have appeared: ask for a step at once */
}
