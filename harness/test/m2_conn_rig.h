/* SPDX-License-Identifier: MIT */
/*
 * m2_conn_rig.h - the shared rig of the m2-conn tests (test_m2_conn_hs.c, test_m2_conn_msg.c). Harness code,
 * libc allowed, never part of the core. Everything is static inline so each test executable carries its own
 * copy.
 *
 * The rig connects a wri_m2_conn to the scriptable server of sim_m2.h through an in-memory duplex, plays the
 * part of the client engine (binds the buffers, reports the TCP connection, moves bytes both ways in chosen
 * chunk sizes, steps the connection) and records everything: every byte the client wrote and read, the
 * callbacks of a test-defined wri_auth_ops and of a test-defined wri_m2_upper.
 */
#ifndef M2_CONN_RIG_H
#define M2_CONN_RIG_H

#include "sim_m2_tc.h"
#include "wri_ctx.h"
#include "wri_m2_conn.h"
#include "wri_misc.h"

/* ---- test-defined auth ops (fixed session key) ----------------------------------------------------- */

typedef struct stub_auth {
	uint8_t key[32];
	size_t key_len;                 /* 0 = the stub reports "no key" */
	uint8_t begin_payload[1024];
	size_t begin_len;
	uint8_t more_payload[1024];
	size_t more_len;
	wr_status begin_st, more_st, done_st;
	int64_t gid;
	int n_begin, n_more, n_done;
	uint8_t last_target_type;
	uint8_t last_reply[512];
	size_t last_reply_len;
	uint64_t done_gid;
	uint32_t done_mode;
	uint8_t done_payload[512];
	size_t done_len;
} stub_auth;

static inline wr_status stub_begin(void *a, uint8_t target_type, wri_wr *out)
{
	stub_auth *s = (stub_auth *)a;

	s->n_begin++;
	s->last_target_type = target_type;
	wri_wr_bytes(out, s->begin_payload, s->begin_len);
	return s->begin_st;
}

static inline wr_status stub_more(void *a, const uint8_t *reply, size_t n, wri_wr *out)
{
	stub_auth *s = (stub_auth *)a;

	s->n_more++;
	s->last_reply_len = n < sizeof(s->last_reply) ? n : sizeof(s->last_reply);
	memcpy(s->last_reply, reply, s->last_reply_len);
	wri_wr_bytes(out, s->more_payload, s->more_len);
	return s->more_st;
}

static inline wr_status stub_done(void *a, uint64_t gid, uint32_t mode, const uint8_t *payload, size_t n)
{
	stub_auth *s = (stub_auth *)a;

	s->n_done++;
	s->done_gid = gid;
	s->done_mode = mode;
	s->done_len = n < sizeof(s->done_payload) ? n : sizeof(s->done_payload);
	memcpy(s->done_payload, payload, s->done_len);
	return s->done_st;
}

static inline void stub_key(void *a, const uint8_t **key, size_t *len)
{
	stub_auth *s = (stub_auth *)a;

	*key = s->key_len != 0 ? s->key : NULL;
	*len = s->key_len;
}

static inline int64_t stub_gid(void *a, uint8_t target_type)
{
	(void)target_type;
	return ((stub_auth *)a)->gid;
}

static const wri_auth_ops stub_ops = {stub_begin, stub_more, stub_done, stub_key, stub_gid};

/* ---- test-defined upper layer ---------------------------------------------------------------------- */

#define RIG_MAXMSG 512u

typedef struct rig_msg {
	wri_m2_hdr2 hdr;
	uint32_t stored[3];
	uint8_t *seg[3]; /* malloc'd copies of what the sinks held, NULL when nothing stored */
} rig_msg;

typedef struct rig rig;

typedef struct rig_up {
	rig *r;
	int n_plan, n_message, n_ready, n_closed;
	wr_errinfo closed_err;
	wri_m2_state state_at_closed;
	rig_msg msgs[RIG_MAXMSG];
	size_t n_msgs;
	/* sinks */
	uint8_t *fbuf, *mbuf, *dbuf;
	uint32_t fcap, mcap, dcap;
	/* plan behaviour */
	int discard_all;       /* every message goes to the bin */
	uint16_t discard_type; /* messages of this type go to the bin when discard_type_set */
	int discard_type_set;
	int busy_times;        /* plan answers WR_E_BUSY this many times first */
	wr_status plan_fail;   /* != 0: plan returns it */
	uint32_t seglen[3];    /* what plan saw last */
	wri_m2_hdr2 plan_hdr;
	/* ready() hook */
	wri_m2_msg_out *send_on_ready;
	wr_status ready_send_st;
} rig_up;

static inline wr_status up_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3],
				wri_m2_sink sink[3])
{
	rig_up *u = (rig_up *)ctx;

	(void)c;
	u->n_plan++;
	u->plan_hdr = *hdr;
	memcpy(u->seglen, seglen, sizeof(u->seglen));
	if (u->busy_times > 0) {
		u->busy_times--;
		return WR_E_BUSY;
	}
	if (u->plan_fail != WR_OK)
		return u->plan_fail;
	if (u->discard_all || (u->discard_type_set && hdr->type == u->discard_type))
		return WR_OK;
	sink[0].dst = u->fbuf, sink[0].cap = u->fcap;
	sink[1].dst = u->mbuf, sink[1].cap = u->mcap;
	sink[2].dst = u->dbuf, sink[2].cap = u->dcap;
	return WR_OK;
}

static inline void up_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	rig_up *u = (rig_up *)ctx;
	uint8_t *src[3];
	unsigned i;

	(void)c;
	src[0] = u->fbuf, src[1] = u->mbuf, src[2] = u->dbuf;
	u->n_message++;
	if (u->n_msgs < RIG_MAXMSG) {
		rig_msg *m = &u->msgs[u->n_msgs++];

		m->hdr = *hdr;
		for (i = 0; i < 3; i++) {
			m->stored[i] = stored[i];
			m->seg[i] = NULL;
			if (stored[i] != 0) {
				m->seg[i] = (uint8_t *)malloc(stored[i]);
				memcpy(m->seg[i], src[i], stored[i]);
			}
		}
	}
}

static inline void up_ready(void *ctx, wri_m2_conn *c);
static inline void up_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	rig_up *u = (rig_up *)ctx;

	u->n_closed++;
	u->closed_err = *err;
	u->state_at_closed = c->state;
}

static const wri_m2_upper up_ops = {up_plan, up_message, up_ready, up_closed};

/* ---- the rig --------------------------------------------------------------------------------------- */

struct rig {
	wri_ctx x;
	wri_m2_conn c;
	uint8_t *ring_buf, *ctl_buf, *tx_buf;
	uint32_t ring_cap, ctl_cap, tx_cap, seg_cap_max, pa_cap;
	wri_m2_preauth pa;
	uint8_t *pa_rx, *pa_tx;
	sim_m2 *s;
	sim_m2_cfg scfg;
	sim_m2_auth_script script;
	sim_m2_auth_ops sops;
	stub_auth au;
	rig_up up;
	wri_eaddr target;
	wr_addr dial;
	uint8_t *sent, *rcvd; /* every byte the client wrote to / read from the socket */
	size_t sent_len, rcvd_len, io_cap;
	size_t rx_chunk, tx_chunk; /* 0 = as much as possible per call */
	uint8_t role;
	uint32_t nonce;
	uint64_t gseq;
	uint16_t target_port;
};

static inline void up_ready(void *ctx, wri_m2_conn *c)
{
	rig_up *u = (rig_up *)ctx;

	u->n_ready++;
	if (u->send_on_ready != NULL)
		u->ready_send_st = wri_m2_conn_send_message(&u->r->x, c, u->send_on_ready);
}

static inline void rig_set_target(rig *r, uint16_t port)
{
	wr_addr a;

	memset(&a, 0, sizeof(a));
	a.family = WR_AF_IPV4;
	a.ip[0] = 10, a.ip[1] = 77, a.ip[2] = 0, a.ip[3] = 10;
	a.port = port;
	a.nonce = 0;
	r->target_port = port;
	r->dial = a;
	wri_eaddr_from_wr(&r->target, &a, WRI_EADDR_TYPE_MSGR2);
}

/* Defaults: monitor connection to 10.77.0.10:3300, harness-sized buffers, a one-round cephx-like script. */
static inline void rig_init(rig *r)
{
	memset(r, 0, sizeof(*r));
	r->ring_cap = 4096u;
	r->ctl_cap = 8192u;
	r->tx_cap = 8192u;
	r->seg_cap_max = 1u << 20;
	r->pa_cap = 8192u;
	r->io_cap = 1u << 22;
	r->role = WRI_ENTITY_MON;
	r->nonce = 0x1234abcdu;
	r->gseq = 7;
	r->x.cfg.handshake_timeout_ms = 8000;
	r->x.now.mono_ms = 1000;
	memcpy(r->au.key, TC_KEY, 32);
	r->au.key_len = 32;
	r->au.gid = -1;
	memset(r->au.begin_payload, 0x41, 24);
	r->au.begin_len = 24;
	memset(r->au.more_payload, 0x42, 40);
	r->au.more_len = 40;
	r->up.r = r;
	r->up.fcap = 1u << 16, r->up.mcap = 1u << 12, r->up.dcap = 1u << 20;
	r->up.fbuf = (uint8_t *)malloc(r->up.fcap);
	r->up.mbuf = (uint8_t *)malloc(r->up.mcap);
	r->up.dbuf = (uint8_t *)malloc(r->up.dcap);
	sim_m2_cfg_default(&r->scfg);
	r->scfg.check_target = 1;
	memset(&r->script, 0, sizeof(r->script));
	r->script.rounds = 1;
	memset(r->script.more_payload, 0x33, 9);
	r->script.more_len = 9;
	memset(r->script.done_payload, 0xDD, 40);
	r->script.done_len = 40;
	memcpy(r->script.key, TC_KEY, 32);
	r->script.key_len = 32;
	rig_set_target(r, 3300);
}

/* Create buffers, the server and the connection; report the TCP connection. */
static inline void rig_start(rig *r)
{
	r->ring_buf = (uint8_t *)malloc(r->ring_cap);
	r->ctl_buf = (uint8_t *)malloc(r->ctl_cap);
	r->tx_buf = (uint8_t *)malloc(r->tx_cap);
	r->pa_rx = (uint8_t *)malloc(r->pa_cap);
	r->pa_tx = (uint8_t *)malloc(r->pa_cap);
	r->sent = (uint8_t *)malloc(r->io_cap);
	r->rcvd = (uint8_t *)malloc(r->io_cap);
	wri_m2_preauth_init(&r->pa, r->pa_rx, r->pa_tx, r->pa_cap);
	sim_m2_auth_script_ops(&r->sops, &r->script);
	r->s = sim_m2_new(&r->scfg, &r->sops);
	if (r->s == NULL) {
		fprintf(stderr, "rig: sim_m2_new failed\n");
		abort();
	}
	wri_m2_conn_bind(&r->c, 3, r->ring_buf, r->ring_cap, r->ctl_buf, r->ctl_cap, r->tx_buf, r->tx_cap,
			 r->seg_cap_max);
	wri_m2_conn_open(&r->c, 0x00010004u, r->role, &r->target, &r->dial, &stub_ops, &r->au, &up_ops, &r->up, &r->pa,
			 r->nonce, r->gseq);
	wri_m2_conn_on_connected(&r->x, &r->c);
}

static inline void rig_free(rig *r)
{
	size_t i, j;

	for (i = 0; i < r->up.n_msgs; i++)
		for (j = 0; j < 3; j++)
			free(r->up.msgs[i].seg[j]);
	sim_m2_free(r->s);
	free(r->ring_buf), free(r->ctl_buf), free(r->tx_buf), free(r->pa_rx), free(r->pa_tx);
	free(r->sent), free(r->rcvd);
	free(r->up.fbuf), free(r->up.mbuf), free(r->up.dbuf);
}

/* Client -> server: everything the connection has queued (in tx_chunk pieces, consuming as it goes). */
static inline size_t rig_flush_tx(rig *r)
{
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t moved = 0, n, i;

	for (;;) {
		n = wri_m2_conn_tx_peek(&r->c, iov, WRI_M2_TXQ_IOV);
		if (n == 0)
			return moved;
		for (i = 0; i < n; i++) {
			size_t off = 0;

			while (off < iov[i].len) {
				size_t k = iov[i].len - off;

				if (r->tx_chunk != 0 && k > r->tx_chunk)
					k = r->tx_chunk;
				if (r->sent_len + k > r->io_cap) {
					fprintf(stderr, "rig: sent log full\n");
					abort();
				}
				memcpy(r->sent + r->sent_len, iov[i].base + off, k);
				r->sent_len += k;
				(void)sim_m2_feed(r->s, iov[i].base + off, k);
				off += k;
				moved += k;
				if (r->tx_chunk != 0) { /* consume in the same small pieces: the queue is re-peeked each time */
					wri_m2_conn_tx_consume(&r->c, k);
					goto again;
				}
			}
		}
		wri_m2_conn_tx_consume(&r->c, moved);
		return moved;
	again:;
	}
}

/* Server -> client: bytes the server has, committed through the connection's window. */
static inline size_t rig_deliver(rig *r, int *progress)
{
	uint8_t *w = NULL;
	size_t room = wri_m2_conn_rx_window(&r->c, &w), k, n;

	if (room == 0 || w == NULL || sim_m2_pending(r->s) == 0)
		return 0;
	k = room;
	if (r->rx_chunk != 0 && k > r->rx_chunk)
		k = r->rx_chunk;
	n = sim_m2_drain(r->s, w, k);
	if (n != 0) {
		if (r->rcvd_len + n > r->io_cap) {
			fprintf(stderr, "rig: rcvd log full\n");
			abort();
		}
		memcpy(r->rcvd + r->rcvd_len, w, n);
		r->rcvd_len += n;
		wri_m2_conn_rx_commit(&r->c, n);
		*progress = 1;
	}
	return n;
}

/* Run both directions and the connection until nothing moves any more. Returns the rounds used. */
static inline int rig_pump(rig *r)
{
	int rounds = 0, progress;

	do {
		progress = 0;
		if (rig_flush_tx(r) != 0)
			progress = 1;
		(void)rig_deliver(r, &progress);
		(void)wri_m2_conn_step(&r->x, &r->c, NULL);
	} while ((progress || r->c.stalled) && ++rounds < 2000000);
	return rounds;
}

/* Deliver server bytes that did not come from the sim (hand-built frames). Goes through the window. */
static inline void rig_inject(rig *r, const uint8_t *p, size_t n)
{
	size_t off = 0;

	while (off < n) {
		uint8_t *w = NULL;
		size_t room = wri_m2_conn_rx_window(&r->c, &w), k = n - off;

		if (room == 0 || w == NULL) {
			(void)wri_m2_conn_step(&r->x, &r->c, NULL);
			room = wri_m2_conn_rx_window(&r->c, &w);
			if (room == 0 || w == NULL)
				return; /* dead connection: the rest is not delivered */
		}
		if (k > room)
			k = room;
		if (r->rx_chunk != 0 && k > r->rx_chunk)
			k = r->rx_chunk;
		memcpy(w, p + off, k);
		memcpy(r->rcvd + r->rcvd_len, p + off, k);
		r->rcvd_len += k;
		wri_m2_conn_rx_commit(&r->c, k);
		off += k;
		(void)wri_m2_conn_step(&r->x, &r->c, NULL);
	}
}

/* ---- frame splitting of a byte log ------------------------------------------------------------------- */

typedef struct rig_fr {
	uint8_t tag, nseg;
	uint32_t len[4];
	const uint8_t *seg[4];
	size_t off, total;
} rig_fr;

/* Split a stream of frames (no banner) into frames; returns the count, *used = bytes covered. */
static inline size_t rig_split(const uint8_t *p, size_t n, rig_fr *out, size_t max, size_t *used)
{
	size_t off = 0, k = 0;

	while (off + WRI_M2_PREAMBLE_LEN <= n && k < max) {
		wri_m2_desc d;
		size_t pos, i;
		uint64_t body;

		if (wri_m2_preamble_parse(NULL, p + off, &d) != WR_OK)
			break;
		body = wri_m2_frame_body_len(&d);
		if (off + WRI_M2_PREAMBLE_LEN + body > n)
			break;
		pos = off + WRI_M2_PREAMBLE_LEN;
		memset(&out[k], 0, sizeof(out[k]));
		out[k].tag = d.tag;
		out[k].nseg = d.nseg;
		out[k].off = off;
		for (i = 0; i < d.nseg; i++) {
			out[k].len[i] = d.len[i];
			out[k].seg[i] = d.len[i] != 0 ? p + pos : NULL;
			pos += d.len[i];
			if (i == 0 && d.len[0] != 0)
				pos += WRI_M2_CRC_LEN;
		}
		if (d.nseg > 1)
			pos += WRI_M2_EPILOGUE_LEN;
		out[k].total = pos - off;
		off = pos;
		k++;
	}
	if (used != NULL)
		*used = off;
	return k;
}

/* A MESSAGE or control frame of the server, built by hand, as one byte string (malloc'd). */
static inline uint8_t *rig_build_frame(uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg, size_t *n)
{
	size_t total = 512, i, k, len = 0;
	uint8_t *enc, *flat;
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];

	for (i = 0; i < nseg; i++)
		total += seg[i].len;
	enc = (uint8_t *)malloc(total);
	flat = (uint8_t *)malloc(total);
	wri_m2_txq_init(&q, enc, (uint32_t)total);
	if (wri_m2_tx_frame(&q, NULL, tag, seg, nseg, NULL, NULL) != WR_OK) {
		fprintf(stderr, "rig_build_frame: builder refused\n");
		abort();
	}
	k = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < k; i++) {
		memcpy(flat + len, iov[i].base, iov[i].len);
		len += iov[i].len;
	}
	free(enc);
	*n = len;
	return flat;
}

/* The common assertions about a failed connection. */
static inline void rig_check_failed(rig *r, wr_status want)
{
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t before = r->sent_len;
	uint8_t *w;

	WRT_CHECK_STATUS(want, r->c.err.status);
	WRT_CHECK_U64(r->c.state, WRI_M2_FAILED);
	WRT_CHECK_U64(r->up.n_closed, 1);
	WRT_CHECK_STATUS(want, r->up.closed_err.status);
	WRT_CHECK_U64(r->up.closed_err.module, WR_MOD_M2);
	WRT_CHECK_U64(r->up.closed_err.conn, r->c.id);
	WRT_CHECK(r->c.pa == NULL);
	WRT_CHECK_U64(wri_m2_conn_tx_peek(&r->c, iov, WRI_M2_TXQ_IOV), 0); /* nothing is sent after the failure */
	WRT_CHECK_U64(wri_m2_conn_rx_window(&r->c, &w), 0);
	rig_pump(r);
	WRT_CHECK_U64(r->sent_len, before);
	WRT_CHECK_U64(r->up.n_closed, 1); /* reported once, however often the owner steps */
	WRT_CHECK_U64(wri_m2_conn_deadline(&r->c), WR_DEADLINE_NONE);
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_conn_send_keepalive(&r->x, &r->c, 1, 2));
}

#endif /* M2_CONN_RIG_H */
