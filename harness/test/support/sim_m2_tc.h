/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_tc.h - a tiny hand-driven TEST CLIENT for the sim_m2 server tests (test_sim_m2*.c). It is
 * not a real client: it builds frames with the m2-frame builder, parses what the server says with the
 * m2-frame receive parser, keeps the raw logs the pre-auth signature needs, and has just enough
 * payload encoders to walk the handshake by hand. Everything is static inline so that each test
 * executable carries its own copy and nothing here needs a source file of its own.
 */
#ifndef SIM_M2_TC_H
#define SIM_M2_TC_H

#include "sim_m2.h"
#include "wrt.h"
#include "wri_hash.h"
#include "wri_le.h"
#include "wri_mem.h"

/* ---- payload builder ------------------------------------------------------------------------ */

typedef struct tb {
	uint8_t b[4096];
	size_t n;
} tb;

static inline void tb_bytes(tb *t, const void *p, size_t n)
{
	if (t->n + n > sizeof(t->b)) {
		fprintf(stderr, "tb overflow\n");
		abort();
	}
	memcpy(t->b + t->n, p, n);
	t->n += n;
}
static inline void tb_fill(tb *t, uint8_t v, size_t n)
{
	if (t->n + n > sizeof(t->b)) {
		fprintf(stderr, "tb overflow\n");
		abort();
	}
	memset(t->b + t->n, v, n);
	t->n += n;
}
static inline void tb_u8(tb *t, uint8_t v) { tb_bytes(t, &v, 1); }
static inline void tb_u32(tb *t, uint32_t v)
{
	uint8_t b[4];
	wri_le32_put(b, v);
	tb_bytes(t, b, 4);
}
static inline void tb_u64(tb *t, uint64_t v)
{
	uint8_t b[8];
	wri_le64_put(b, v);
	tb_bytes(t, b, 8);
}

static const uint8_t TC_SERVER_IP[4] = {10, 77, 0, 10};
static const uint8_t TC_CLIENT_IP[4] = {10, 77, 0, 20};

static inline void tc_pay_hello(tb *t, uint8_t type, uint16_t port)
{
	uint8_t a[SIM_M2_ADDR4_LEN];

	t->n = 0;
	sim_m2_put_addr4(a, 2, 0, TC_SERVER_IP, port); /* the address we dial */
	tb_u8(t, type);
	tb_bytes(t, a, sizeof(a));
}

static inline void tc_pay_auth_request(tb *t, uint32_t method, uint32_t mode, size_t plen)
{
	t->n = 0;
	tb_u32(t, method);
	tb_u32(t, 1);
	tb_u32(t, mode);
	tb_u32(t, (uint32_t)plen);
	tb_fill(t, 0x41, plen);
}

static inline void tc_pay_blob(tb *t, size_t plen, uint8_t v)
{
	t->n = 0;
	tb_u32(t, (uint32_t)plen);
	tb_fill(t, v, plen);
}

/* CLIENT_IDENT as a stock client sends it (123 bytes): addrvec [ip, port 0, type 3, nonce], target, gid -1... */
static inline void tc_pay_ident(tb *t, uint64_t supported, uint64_t global_seq, uint32_t nonce)
{
	uint8_t me[SIM_M2_ADDR4_LEN], target[SIM_M2_ADDR4_LEN];

	t->n = 0;
	sim_m2_put_addr4(me, 3, nonce, TC_CLIENT_IP, 0);
	sim_m2_put_addr4(target, 2, 0, TC_SERVER_IP, 3300);
	tb_u8(t, 2);
	tb_u32(t, 1);
	tb_bytes(t, me, sizeof(me));
	tb_bytes(t, target, sizeof(target));
	tb_u64(t, (uint64_t)-1);
	tb_u64(t, global_seq);
	tb_u64(t, supported);
	tb_u64(t, 0x0800000000000000ull);
	tb_u64(t, 1);
	tb_u64(t, 0);
}

/* A ceph_msg_header2 (41 bytes) for a client message. */
static inline void tc_pay_hdr2(uint8_t h[SIM_M2_HDR2_LEN], uint64_t seq, uint64_t tid, uint16_t type, uint64_t ack)
{
	memset(h, 0, SIM_M2_HDR2_LEN);
	wri_le64_put(h, seq);
	wri_le64_put(h + 8, tid);
	wri_le16_put(h + 16, type);
	wri_le16_put(h + 18, 127);
	wri_le16_put(h + 20, 3);
	wri_le64_put(h + 28, ack);
	h[36] = 3;
	wri_le16_put(h + 37, 1);
}

/* ---- the client ------------------------------------------------------------------------------- */

typedef struct tc_frame {
	uint8_t tag, nseg;
	uint32_t len[4];
	uint8_t *seg[4]; /* malloc'd copies, NULL when empty */
} tc_frame;

#define TC_MAXFR 64u

typedef struct tc {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ring_buf[8192];
	uint8_t *seg0, *sink[3];
	uint32_t seg_cap;
	wr_status rx_err;      /* first receive-parser error, 0 = none */
	int got_banner;
	wri_m2_banner banner;
	tc_frame fr[TC_MAXFR];
	size_t nfr;
	uint8_t *log;          /* raw bytes received, until log_on drops (AUTH_DONE) */
	size_t log_len;
	uint8_t log_on;
	uint8_t *sent;         /* raw bytes sent */
	size_t sent_len;
	size_t feed_chunk;     /* 0 = the whole buffer per feed call */
	uint64_t ident_supported; /* tc_drive: supported features in CLIENT_IDENT, 0 = a stock client's */
	uint8_t patch_late;    /* tc_send: != 0 overwrites the epilogue late_status of multi-segment frames */
} tc;

static inline void tc_rx_tap(void *log, const uint8_t *p, size_t n)
{
	tc *t = (tc *)log;

	memcpy(t->log + t->log_len, p, n);
	t->log_len += n;
}

static inline void tc_init(tc *t, uint32_t seg_cap)
{
	memset(t, 0, sizeof(*t));
	t->seg_cap = seg_cap;
	t->seg0 = (uint8_t *)malloc(16384);
	t->sink[0] = (uint8_t *)malloc(seg_cap);
	t->sink[1] = (uint8_t *)malloc(seg_cap);
	t->sink[2] = (uint8_t *)malloc(seg_cap);
	t->log = (uint8_t *)malloc(1u << 20);
	t->sent = (uint8_t *)malloc(1u << 22);
	t->log_on = 1;
	wri_ring_init(&t->ring, t->ring_buf, sizeof(t->ring_buf));
	wri_m2_rx_init(&t->rx, t->seg0, 16384, seg_cap);
}

static inline void tc_free(tc *t)
{
	size_t i, j;

	for (i = 0; i < t->nfr; i++)
		for (j = 0; j < 4; j++)
			free(t->fr[i].seg[j]);
	free(t->seg0);
	free(t->sink[0]);
	free(t->sink[1]);
	free(t->sink[2]);
	free(t->log);
	free(t->sent);
}

static inline void tc_step(tc *t)
{
	for (;;) {
		wri_m2_rx_ev ev = wri_m2_rx_step(&t->rx, &t->ring, NULL, NULL, t->log_on ? tc_rx_tap : NULL, t);
		unsigned i;

		if (ev == WRI_RXE_NONE)
			return;
		if (ev == WRI_RXE_ERROR) {
			t->rx_err = wri_m2_rx_error(&t->rx)->status;
			return;
		}
		if (ev == WRI_RXE_BANNER) {
			t->banner = *wri_m2_rx_banner(&t->rx);
			t->got_banner = 1;
		} else if (ev == WRI_RXE_SEG0) {
			for (i = 1; i < t->rx.desc.nseg; i++)
				wri_m2_rx_sink(&t->rx, i, t->sink[i - 1u], t->seg_cap);
		} else if (ev == WRI_RXE_FRAME) {
			tc_frame *f;

			if (t->nfr == TC_MAXFR) {
				fprintf(stderr, "tc: too many frames\n");
				abort();
			}
			f = &t->fr[t->nfr++];
			f->tag = t->rx.desc.tag;
			f->nseg = t->rx.desc.nseg;
			for (i = 0; i < f->nseg; i++) {
				const uint8_t *src = i == 0 ? t->seg0 : t->sink[i - 1u];

				f->len[i] = t->rx.stored[i];
				if (f->len[i] != 0) {
					f->seg[i] = (uint8_t *)malloc(f->len[i]);
					memcpy(f->seg[i], src, f->len[i]);
				}
			}
			if (f->tag == WRI_M2_TAG_AUTH_DONE)
				t->log_on = 0; /* the signature covers up to and including AUTH_DONE */
			wri_m2_rx_next_frame(&t->rx);
		}
	}
}

/* Read everything the server has for us and parse it. */
static inline void tc_pull(tc *t, sim_m2 *s)
{
	uint8_t buf[1024];
	size_t n;

	while (t->rx_err == 0 && (n = sim_m2_drain(s, buf, sizeof(buf))) != 0) {
		size_t off = 0;

		while (off < n && t->rx_err == 0) {
			uint32_t k = wri_ring_write(&t->ring, buf + off, (uint32_t)(n - off));

			off += k;
			tc_step(t);
			if (k == 0)
				break;
		}
	}
}

static inline size_t tc_feed(tc *t, sim_m2 *s, const uint8_t *p, size_t n)
{
	size_t done = 0, got = 0;

	memcpy(t->sent + t->sent_len, p, n);
	t->sent_len += n;
	while (done < n) {
		size_t k = t->feed_chunk != 0 && n - done > t->feed_chunk ? t->feed_chunk : n - done;

		got += sim_m2_feed(s, p + done, k);
		done += k;
	}
	return got;
}

static inline size_t tc_send_banner(tc *t, sim_m2 *s, uint64_t supported, uint64_t required)
{
	uint8_t b[WRI_M2_BANNER_LEN];

	wri_m2_banner_build(b);
	wri_le64_put(b + 10, supported);
	wri_le64_put(b + 18, required);
	return tc_feed(t, s, b, sizeof(b));
}

/* Build one frame with the m2-frame builder and feed it to the server. */
static inline size_t tc_send(tc *t, sim_m2 *s, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t total = 512, i, k, n = 0, got;
	uint8_t *enc, *flat;

	for (i = 0; i < nseg; i++)
		total += seg[i].len;
	enc = (uint8_t *)malloc(total);
	flat = (uint8_t *)malloc(total);
	wri_m2_txq_init(&q, enc, (uint32_t)total);
	if (wri_m2_tx_frame(&q, NULL, tag, seg, nseg, NULL, NULL) != WR_OK) {
		fprintf(stderr, "tc_send: builder refused\n");
		abort();
	}
	k = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < k; i++) {
		memcpy(flat + n, iov[i].base, iov[i].len);
		n += iov[i].len;
	}
	if (t->patch_late != 0 && nseg > 1)
		flat[n - WRI_M2_EPILOGUE_LEN] = t->patch_late;
	got = tc_feed(t, s, flat, n);
	free(enc);
	free(flat);
	return got;
}

/* One-segment control frame from a payload builder. */
static inline size_t tc_send_ctl(tc *t, sim_m2 *s, uint8_t tag, const tb *p)
{
	wri_m2_seg_src seg;

	seg.p = p->b;
	seg.len = (uint32_t)p->n;
	seg.ref = 0;
	return tc_send(t, s, tag, &seg, 1);
}

/* A client MESSAGE: header2 for (seq, tid, type) and the front / middle / data segments. */
static inline size_t tc_send_msg(tc *t, sim_m2 *s, uint64_t seq, uint64_t tid, uint16_t type, const uint8_t *front,
				 uint32_t flen, const uint8_t *mid, uint32_t mlen, const uint8_t *data, uint32_t dlen)
{
	uint8_t h[SIM_M2_HDR2_LEN];
	wri_m2_seg_src seg[4];
	unsigned nseg = dlen != 0 ? 4u : mlen != 0 ? 3u : flen != 0 ? 2u : 1u;

	tc_pay_hdr2(h, seq, tid, type, 0);
	seg[0].p = h, seg[0].len = sizeof(h);
	seg[1].p = front, seg[1].len = flen;
	seg[2].p = mid, seg[2].len = mlen;
	seg[3].p = data, seg[3].len = dlen;
	seg[0].ref = seg[1].ref = seg[2].ref = seg[3].ref = 0;
	return tc_send(t, s, WRI_M2_TAG_MESSAGE, seg, nseg);
}

static inline const tc_frame *tc_last(const tc *t) { return t->nfr != 0 ? &t->fr[t->nfr - 1u] : NULL; }

/* ---- the handshake, step by step ----------------------------------------------------------------- */

enum { /* tc_drive stops after reaching this stage */
	TC_ST_BANNER = 1, /* server banner received */
	TC_ST_HELLO,      /* server HELLO */
	TC_ST_REPLY_MORE, /* AUTH_REPLY_MORE (the scripted auth needs rounds >= 1) */
	TC_ST_DONE,       /* AUTH_DONE */
	TC_ST_SIGNED,     /* server AUTH_SIGNATURE (after ours) */
	TC_ST_COMPRESSION,/* COMPRESSION_DONE (client banner supported 3) */
	TC_ST_IDENT       /* SERVER_IDENT / IDENT_MISSING_FEATURES / WAIT: the answer to CLIENT_IDENT */
};

static const uint8_t TC_KEY[32] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
				   16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

static inline void tc_hmac(const uint8_t *key, size_t klen, const uint8_t *log, size_t n, uint8_t out[32])
{
	wr_iov v;

	v.base = log;
	v.len = n;
	wri_hmac_sha256(key, klen, &v, 1, out);
}

/* Walk the handshake of the manual from the client side as far as `upto`; returns the last stage that
 * produced the expected server frame (0 = none). Stops at the first stage whose server answer is missing. */
static inline int tc_drive(tc *t, sim_m2 *s, uint64_t client_supported, int upto, uint8_t hello_type)
{
	tb p;
	size_t before;
	int stage = 0;
	uint8_t sig[32];

	tc_pull(t, s);
	if (!t->got_banner)
		return stage;
	stage = TC_ST_BANNER;
	if (upto <= stage)
		return stage;
	(void)tc_send_banner(t, s, client_supported, 0);
	tc_pay_hello(&p, hello_type, 3300);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_HELLO, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before || t->fr[before].tag != WRI_M2_TAG_HELLO)
		return stage;
	stage = TC_ST_HELLO;
	if (upto <= stage)
		return stage;
	tc_pay_auth_request(&p, SIM_M2_AUTH_CEPHX, SIM_M2_MODE_CRC, 24);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before || t->fr[before].tag != WRI_M2_TAG_AUTH_REPLY_MORE)
		return stage;
	stage = TC_ST_REPLY_MORE;
	if (upto <= stage)
		return stage;
	tc_pay_blob(&p, 40, 0x42);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before || t->fr[before].tag != WRI_M2_TAG_AUTH_DONE)
		return stage;
	stage = TC_ST_DONE;
	if (upto <= stage)
		return stage;
	tc_hmac(TC_KEY, sizeof(TC_KEY), t->log, t->log_len, sig);
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before || t->fr[before].tag != WRI_M2_TAG_AUTH_SIGNATURE)
		return stage;
	stage = TC_ST_SIGNED;
	if (upto <= stage)
		return stage;
	if ((client_supported & 2u) != 0 && (s->cfg.banner_supported & 2u) != 0) {
		p.n = 0;
		tb_u8(&p, 0);
		tb_u32(&p, 0);
		(void)tc_send_ctl(t, s, WRI_M2_TAG_COMPRESSION_REQUEST, &p);
		before = t->nfr;
		tc_pull(t, s);
		if (t->nfr == before || t->fr[before].tag != WRI_M2_TAG_COMPRESSION_DONE)
			return stage;
		stage = TC_ST_COMPRESSION;
		if (upto <= stage)
			return stage;
	}
	tc_pay_ident(&p, t->ident_supported != 0 ? t->ident_supported : 0x3f07fffffffdffffull, 1, 0x1234);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_CLIENT_IDENT, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr != before)
		stage = TC_ST_IDENT;
	return stage;
}

/* ---- one server + one client, with the scripted auth of a stock monitor / OSD ------------------------ */

typedef struct env {
	sim_m2_cfg cfg;
	sim_m2_auth_script sc;
	sim_m2_auth_ops ops;
	sim_m2 *s;
	tc t;
} env;

/* Defaults a test may change before env_start: the lengths follow handshake-skeletons.json (monitor:
 * AUTH_REPLY_MORE 13 / AUTH_DONE 372 (payload 356), OSD: 62 / 78), session key = TC_KEY. */
static inline void env_prep(env *e, int osd)
{
	memset(e, 0, sizeof(*e));
	sim_m2_cfg_default(&e->cfg);
	e->cfg.entity_type = osd ? SIM_M2_ENT_OSD : SIM_M2_ENT_MON;
	e->sc.rounds = 1;
	e->sc.more_len = osd ? 58u : 9u;
	memset(e->sc.more_payload, 0x4d, e->sc.more_len);
	e->sc.done_len = osd ? 62u : 356u;
	memset(e->sc.done_payload, 0xdd, e->sc.done_len);
	memcpy(e->sc.key, TC_KEY, sizeof(TC_KEY));
	e->sc.key_len = sizeof(TC_KEY);
}

static inline void env_start(env *e)
{
	sim_m2_auth_script_ops(&e->ops, &e->sc);
	e->s = sim_m2_new(&e->cfg, &e->ops);
	if (e->s == NULL) {
		fprintf(stderr, "sim_m2_new failed\n");
		abort();
	}
	tc_init(&e->t, 1u << 20);
}

static inline void env_end(env *e)
{
	tc_free(&e->t);
	sim_m2_free(e->s);
}

/* A server (client banner 0x1, so no compression stage) with the handshake done up to the point asked for. */
static inline void env_ready(env *e, int upto)
{
	env_start(e);
	WRT_CHECK_U64(tc_drive(&e->t, e->s, 1, upto, SIM_M2_ENT_CLIENT), (uint64_t)upto);
}

static inline void env_expect_closed(env *e, wr_status why)
{
	tc_pull(&e->t, e->s);
	WRT_CHECK_STATUS(why, sim_m2_error(e->s)->status);
	WRT_CHECK(sim_m2_closed(e->s));
	WRT_CHECK_U64(e->s->state, SIM_M2_ST_DEAD);
	WRT_CHECK_U64(sim_m2_feed(e->s, (const uint8_t *)"x", 1), 0); /* nobody reads any more */
}

#endif /* SIM_M2_TC_H */
