/* SPDX-License-Identifier: MIT */
/*
 * sim_sec_tc.h - a scripted msgr2 CLIENT for the secure-mode tests of the simulators (test_sim_sec_*.c). It is not a client of the
 * product and shares nothing with the core: written from docs/spec/msgr2.md and msgr2-secure-mode.md, it has its own CRC-32C
 * (sim_sec_crc32c), SHA-256 and HMAC, its own crc-framing builder and parser, and uses sim_m2_sec for everything secure (the
 * client side of the context: tx seed B, rx seed A). The cephx half is in sim_sec_cx.h. Everything is static inline, so every
 * test executable carries its own copy.
 *
 * The transport is any of the three simulators: sim_m2, sim_mon_conn, sim_osd_conn (stc_wire_*). The simulators are synchronous:
 * a feed is handled at once and the answer can be drained right away, so a login is a plain sequence of sends and receives.
 */
#ifndef SIM_SEC_TC_H
#define SIM_SEC_TC_H

#include "wrt.h"

#include "sim_m2.h"
#include "sim_m2_sec.h"
#include "sim_mon.h"
#include "sim_osd.h"

/* ---- growable byte buffer, writer, reader ------------------------------------------------------------------------------ */

typedef struct stc_buf {
	uint8_t *p;
	size_t n, cap;
} stc_buf;

static inline void stc_buf_add(stc_buf *b, const void *src, size_t n)
{
	if (n == 0)
		return;
	if (b->n + n > b->cap) {
		size_t nc = b->cap != 0 ? b->cap : 256u;

		while (nc < b->n + n)
			nc *= 2u;
		b->p = (uint8_t *)realloc(b->p, nc);
		b->cap = nc;
	}
	memcpy(b->p + b->n, src, n);
	b->n += n;
}

static inline void stc_buf_drop(stc_buf *b, size_t n)
{
	if (n > b->n)
		n = b->n;
	memmove(b->p, b->p + n, b->n - n);
	b->n -= n;
}

static inline void stc_buf_free(stc_buf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

static inline void w8(stc_buf *b, uint8_t v) { stc_buf_add(b, &v, 1); }

static inline void w16(stc_buf *b, uint16_t v)
{
	uint8_t t[2] = {(uint8_t)v, (uint8_t)(v >> 8)};

	stc_buf_add(b, t, 2);
}

static inline void w32(stc_buf *b, uint32_t v)
{
	uint8_t t[4] = {(uint8_t)v, (uint8_t)(v >> 8), (uint8_t)(v >> 16), (uint8_t)(v >> 24)};

	stc_buf_add(b, t, 4);
}

static inline void w64(stc_buf *b, uint64_t v)
{
	w32(b, (uint32_t)v);
	w32(b, (uint32_t)(v >> 32));
}

static inline void wblob(stc_buf *b, const void *p, size_t n)
{
	w32(b, (uint32_t)n);
	stc_buf_add(b, p, n);
}

typedef struct stc_rd {
	const uint8_t *p;
	size_t n, pos;
	int bad;
} stc_rd;

static inline void rd_init(stc_rd *r, const uint8_t *p, size_t n)
{
	r->p = p, r->n = n, r->pos = 0, r->bad = 0;
}

static inline const uint8_t *rd_take(stc_rd *r, size_t k)
{
	const uint8_t *q;

	if (r->bad || k > r->n - r->pos) {
		r->bad = 1;
		return NULL;
	}
	q = r->p + r->pos;
	r->pos += k;
	return q;
}

static inline uint8_t rd8(stc_rd *r)
{
	const uint8_t *q = rd_take(r, 1);

	return q != NULL ? q[0] : 0;
}

static inline uint16_t rd16(stc_rd *r)
{
	const uint8_t *q = rd_take(r, 2);

	return q != NULL ? (uint16_t)(q[0] | q[1] << 8) : 0;
}

static inline uint32_t rd32(stc_rd *r)
{
	const uint8_t *q = rd_take(r, 4);

	return q != NULL ? (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24 : 0;
}

static inline uint64_t rd64(stc_rd *r)
{
	uint64_t lo = rd32(r), hi = rd32(r);

	return lo | hi << 32;
}

/* A length-prefixed blob: the pointer to its bytes (NULL on error), its length in *n. */
static inline const uint8_t *rd_blob(stc_rd *r, uint32_t *n)
{
	*n = rd32(r);
	return rd_take(r, *n);
}

static inline uint32_t ld32le(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/* ---- SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104), written for this file ------------------------------------------------ */

typedef struct stc_sha {
	uint32_t h[8];
	uint8_t blk[64];
	size_t fill;
	uint64_t total;
} stc_sha;

static inline uint32_t sha_ror(uint32_t x, unsigned k) { return (x >> k) | (x << (32u - k)); }

static inline void sha_block(stc_sha *s, const uint8_t *b)
{
	static const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
		0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
		0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
		0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	uint32_t w[64], a, b2, c, d, e, f, g, h;
	unsigned i;

	for (i = 0; i < 16u; i++)
		w[i] = (uint32_t)b[4u * i] << 24 | (uint32_t)b[4u * i + 1u] << 16 | (uint32_t)b[4u * i + 2u] << 8 | b[4u * i + 3u];
	for (i = 16; i < 64u; i++) {
		uint32_t s0 = sha_ror(w[i - 15], 7) ^ sha_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = sha_ror(w[i - 2], 17) ^ sha_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = s->h[0], b2 = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4], f = s->h[5], g = s->h[6], h = s->h[7];
	for (i = 0; i < 64u; i++) {
		uint32_t t1 = h + (sha_ror(e, 6) ^ sha_ror(e, 11) ^ sha_ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
		uint32_t t2 = (sha_ror(a, 2) ^ sha_ror(a, 13) ^ sha_ror(a, 22)) + ((a & b2) ^ (a & c) ^ (b2 & c));

		h = g, g = f, f = e, e = d + t1, d = c, c = b2, b2 = a, a = t1 + t2;
	}
	s->h[0] += a, s->h[1] += b2, s->h[2] += c, s->h[3] += d, s->h[4] += e, s->h[5] += f, s->h[6] += g, s->h[7] += h;
}

static inline void sha_init(stc_sha *s)
{
	static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	memcpy(s->h, iv, sizeof(iv));
	s->fill = 0;
	s->total = 0;
}

static inline void sha_add(stc_sha *s, const uint8_t *p, size_t n)
{
	s->total += n;
	while (n > 0) {
		size_t k = 64u - s->fill < n ? 64u - s->fill : n;

		memcpy(s->blk + s->fill, p, k);
		s->fill += k, p += k, n -= k;
		if (s->fill == 64u) {
			sha_block(s, s->blk);
			s->fill = 0;
		}
	}
}

static inline void sha_done(stc_sha *s, uint8_t out[32])
{
	uint64_t bits = s->total * 8u;
	uint8_t pad = 0x80, zero = 0, len[8];
	unsigned i;

	sha_add(s, &pad, 1);
	while (s->fill != 56u)
		sha_add(s, &zero, 1);
	for (i = 0; i < 8u; i++)
		len[i] = (uint8_t)(bits >> (56u - 8u * i));
	sha_add(s, len, 8);
	for (i = 0; i < 8u; i++) {
		out[4u * i] = (uint8_t)(s->h[i] >> 24);
		out[4u * i + 1u] = (uint8_t)(s->h[i] >> 16);
		out[4u * i + 2u] = (uint8_t)(s->h[i] >> 8);
		out[4u * i + 3u] = (uint8_t)s->h[i];
	}
}

static inline void stc_hmac256(const uint8_t *key, size_t klen, const uint8_t *msg, size_t n, uint8_t out[32])
{
	uint8_t k[64], ip[64], op[64], inner[32];
	stc_sha s;
	unsigned i;

	memset(k, 0, sizeof(k));
	if (klen > 64u) {
		sha_init(&s);
		sha_add(&s, key, klen);
		sha_done(&s, k);
	} else {
		memcpy(k, key, klen);
	}
	for (i = 0; i < 64u; i++) {
		ip[i] = (uint8_t)(k[i] ^ 0x36);
		op[i] = (uint8_t)(k[i] ^ 0x5c);
	}
	sha_init(&s);
	sha_add(&s, ip, 64);
	sha_add(&s, msg, n);
	sha_done(&s, inner);
	sha_init(&s);
	sha_add(&s, op, 64);
	sha_add(&s, inner, 32);
	sha_done(&s, out);
}

/* ---- the transport and the client state ---------------------------------------------------------------------------------- */

typedef struct stc {
	void *obj;
	size_t (*feed)(void *, const uint8_t *, size_t);
	size_t (*drain)(void *, uint8_t *, size_t);
	int (*closed)(void *);
	stc_buf in;            /* server bytes drained and not parsed yet (plaintext phase) */
	stc_buf rxlog, txlog;  /* the pre-auth transcripts (msgr2.md 3.4), while log_on */
	int log_on;
	size_t chunk;          /* bytes per feed call, 0 = all at once */
	size_t dchunk;         /* bytes per drain call, 0 = 4096 */
	int secure;            /* secure framing live in both directions */
	sim_sec_ctx ctx;
	sim_sec_dec dec;
	int dec_live;
	int eof;               /* the server closed and everything it said was read */
	uint64_t banner_supported; /* what our banner advertises: 1 = REVISION_1 (default), 3 adds COMPRESSION (the compression frames follow the signatures) */
	/* the last frame received */
	uint8_t tag;
	unsigned nseg;
	uint32_t len[4];
	stc_buf seg[4];
	uint8_t late;
	wr_status err;         /* WR_OK, or what the secure decoder / crc parser said */
	uint64_t out_seq, in_seq;
	uint32_t n_frames_tx, n_frames_rx;
} stc;

static inline size_t stc_m2_feed(void *o, const uint8_t *p, size_t n) { return sim_m2_feed((sim_m2 *)o, p, n); }
static inline size_t stc_m2_drain(void *o, uint8_t *p, size_t n) { return sim_m2_drain((sim_m2 *)o, p, n); }
static inline int stc_m2_closed(void *o) { return sim_m2_closed((sim_m2 *)o); }
static inline size_t stc_mon_feed(void *o, const uint8_t *p, size_t n) { return sim_mon_feed((sim_mon_conn *)o, p, n); }
static inline size_t stc_mon_drain(void *o, uint8_t *p, size_t n) { return sim_mon_drain((sim_mon_conn *)o, p, n); }
static inline int stc_mon_closed(void *o) { return sim_mon_closed((sim_mon_conn *)o); }
static inline size_t stc_osd_feed(void *o, const uint8_t *p, size_t n) { return sim_osd_feed((sim_osd_conn *)o, p, n); }
static inline size_t stc_osd_drain(void *o, uint8_t *p, size_t n) { return sim_osd_drain((sim_osd_conn *)o, p, n); }
static inline int stc_osd_closed(void *o) { return sim_osd_closed((sim_osd_conn *)o); }

static inline void stc_init(stc *c, void *obj, size_t (*feed)(void *, const uint8_t *, size_t),
			    size_t (*drain)(void *, uint8_t *, size_t), int (*closed)(void *))
{
	memset(c, 0, sizeof(*c));
	c->obj = obj, c->feed = feed, c->drain = drain, c->closed = closed;
	c->log_on = 1;
	c->banner_supported = 1;
}

static inline void stc_init_m2(stc *c, sim_m2 *s) { stc_init(c, s, stc_m2_feed, stc_m2_drain, stc_m2_closed); }
static inline void stc_init_mon(stc *c, sim_mon_conn *m) { stc_init(c, m, stc_mon_feed, stc_mon_drain, stc_mon_closed); }
static inline void stc_init_osd(stc *c, sim_osd_conn *o) { stc_init(c, o, stc_osd_feed, stc_osd_drain, stc_osd_closed); }

static inline void stc_free(stc *c)
{
	unsigned i;

	stc_buf_free(&c->in);
	stc_buf_free(&c->rxlog);
	stc_buf_free(&c->txlog);
	for (i = 0; i < 4u; i++)
		stc_buf_free(&c->seg[i]);
	if (c->dec_live)
		sim_sec_dec_free(&c->dec);
	sim_sec_ctx_wipe(&c->ctx);
}

/* Read everything the server has for us: into the decoder once secure, else into the plaintext buffer (and the transcript). */
static inline void stc_pull(stc *c)
{
	uint8_t tmp[4096];
	size_t n, cap = c->dchunk != 0 && c->dchunk < sizeof(tmp) ? c->dchunk : sizeof(tmp);

	while ((n = c->drain(c->obj, tmp, cap)) != 0) {
		if (c->secure) {
			(void)sim_sec_dec_feed(&c->dec, tmp, n);
		} else {
			stc_buf_add(&c->in, tmp, n);
			if (c->log_on)
				stc_buf_add(&c->rxlog, tmp, n);
		}
	}
	c->eof = c->closed(c->obj);
}

/* Write bytes to the server (in pieces of chunk when set); logged while the transcript is on. */
static inline void stc_put(stc *c, const uint8_t *p, size_t n)
{
	size_t at = 0;

	if (c->log_on)
		stc_buf_add(&c->txlog, p, n);
	while (at < n) {
		size_t k = c->chunk != 0 && c->chunk < n - at ? c->chunk : n - at;
		size_t took = c->feed(c->obj, p + at, k);

		if (took == 0)
			break;
		at += took;
	}
}

/* ---- the banner and plaintext (crc) frames ---------------------------------------------------------------------------------- */

#define STC_BANNER_LEN 26u

static inline void stc_send_banner(stc *c, uint64_t supported, uint64_t required)
{
	stc_buf b = {0, 0, 0};

	stc_buf_add(&b, "ceph v2\n", 8);
	w16(&b, 16);
	w64(&b, supported);
	w64(&b, required);
	stc_put(c, b.p, b.n);
	stc_buf_free(&b);
}

/* Returns 1 with the server's supported / required, 0 when it has not arrived whole. */
static inline int stc_recv_banner(stc *c, uint64_t *supported, uint64_t *required)
{
	stc_pull(c);
	if (c->in.n < STC_BANNER_LEN)
		return 0;
	if (memcmp(c->in.p, "ceph v2\n", 8) != 0 || c->in.p[8] != 16 || c->in.p[9] != 0)
		return -1;
	*supported = (uint64_t)ld32le(c->in.p + 10) | (uint64_t)ld32le(c->in.p + 14) << 32;
	*required = (uint64_t)ld32le(c->in.p + 18) | (uint64_t)ld32le(c->in.p + 22) << 32;
	stc_buf_drop(&c->in, STC_BANNER_LEN);
	return 1;
}

/* One frame in crc framing (msgr2.md: preamble, segment 0 and its CRC when not empty, the other segments, and for several
 * segments the 13-byte epilogue: late_status and the CRCs of segments 1..3). The CRC of a segment starts from 0xffffffff. */
static inline void stc_crc_frame(stc_buf *out, uint8_t tag, unsigned nseg, const uint8_t *const *seg, const uint32_t *len)
{
	uint8_t pre[32];
	unsigned i;
	uint32_t crc;

	memset(pre, 0, sizeof(pre));
	pre[0] = tag;
	pre[1] = (uint8_t)nseg;
	for (i = 0; i < nseg; i++) {
		pre[2 + 6 * i] = (uint8_t)len[i];
		pre[3 + 6 * i] = (uint8_t)(len[i] >> 8);
		pre[4 + 6 * i] = (uint8_t)(len[i] >> 16);
		pre[5 + 6 * i] = (uint8_t)(len[i] >> 24);
		pre[6 + 6 * i] = i == 3u ? 0x00 : 0x08; /* alignment 8, 8, 8, 4096 */
		pre[7 + 6 * i] = i == 3u ? 0x10 : 0x00;
	}
	crc = sim_sec_crc32c(0, pre, 28);
	pre[28] = (uint8_t)crc, pre[29] = (uint8_t)(crc >> 8), pre[30] = (uint8_t)(crc >> 16), pre[31] = (uint8_t)(crc >> 24);
	stc_buf_add(out, pre, 32);
	if (len[0] != 0) {
		stc_buf_add(out, seg[0], len[0]);
		w32(out, sim_sec_crc32c(0xffffffffu, seg[0], len[0]));
	}
	for (i = 1; i < nseg; i++)
		stc_buf_add(out, seg[i], len[i]);
	if (nseg > 1u) {
		w8(out, 0x0e);
		for (i = 1; i < 4u; i++)
			w32(out, i < nseg ? sim_sec_crc32c(0xffffffffu, seg[i], len[i]) : 0u);
	}
}

/* Send one frame: secure framing once the switch happened, crc framing before. */
static inline int stc_send(stc *c, uint8_t tag, unsigned nseg, const uint8_t *const *seg, const uint32_t *len)
{
	stc_buf b = {0, 0, 0};
	int rc = 0;

	if (c->secure) {
		sim_sec_spec sp;
		unsigned i;
		size_t total, n = 0;

		memset(&sp, 0, sizeof(sp));
		sp.tag = tag, sp.nseg = nseg;
		for (i = 0; i < nseg; i++)
			sp.seg[i] = seg[i], sp.len[i] = len[i];
		total = sim_sec_frame_len(&sp, NULL, NULL);
		if (total == 0)
			return -1;
		b.p = (uint8_t *)malloc(total);
		b.cap = total;
		if (sim_sec_encode(&c->ctx.tx, &sp, NULL, b.p, total, &n) != 0)
			rc = -1;
		b.n = n;
	} else {
		stc_crc_frame(&b, tag, nseg, seg, len);
	}
	if (rc == 0)
		stc_put(c, b.p, b.n);
	stc_buf_free(&b);
	c->n_frames_tx++;
	return rc;
}

static inline int stc_send1(stc *c, uint8_t tag, const uint8_t *p, uint32_t n)
{
	const uint8_t *seg[1];
	uint32_t len[1];

	seg[0] = p, len[0] = n;
	return stc_send(c, tag, 1, seg, len);
}

/* Switch to secure framing from a connection secret (the client's side: tx seed B, rx seed A). */
static inline int stc_go_secure(stc *c, const uint8_t *secret, size_t n)
{
	if (sim_sec_ctx_init(&c->ctx, secret, n, 0) != 0)
		return -1;
	sim_sec_dec_init(&c->dec, &c->ctx.rx, 0, 0);
	c->dec_live = 1;
	/* whatever the server already sent behind AUTH_DONE belongs to the decoder */
	if (c->in.n != 0) {
		(void)sim_sec_dec_feed(&c->dec, c->in.p, c->in.n);
		stc_buf_drop(&c->in, c->in.n);
	}
	c->secure = 1;
	return 0;
}

/* Receive one frame: 1 = c->tag / nseg / len / seg hold it, 0 = not complete yet, -1 = error (c->err). A frame the sender
 * aborted (late_status 0x1) is returned with c->late = 0x01. */
static inline int stc_recv(stc *c)
{
	unsigned i;

	stc_pull(c);
	if (c->secure) {
		sim_sec_frame f;
		int r = sim_sec_dec_next(&c->dec, &f);

		if (r == SIM_SEC_DEC_NEED)
			return 0;
		if (r == SIM_SEC_DEC_ERROR) {
			c->err = c->dec.err;
			return -1;
		}
		c->tag = f.tag, c->nseg = f.nseg, c->late = f.late_status;
		for (i = 0; i < 4u; i++) {
			c->len[i] = f.len[i];
			c->seg[i].n = 0;
			if (i < f.nseg)
				stc_buf_add(&c->seg[i], f.seg[i], f.len[i]);
		}
		c->n_frames_rx++;
		return 1;
	} else {
		const uint8_t *p = c->in.p;
		uint32_t len[4];
		unsigned nseg;
		size_t need;

		if (c->in.n < 32u)
			return 0;
		if (sim_sec_crc32c(0, p, 28) != ld32le(p + 28) || p[1] < 1u || p[1] > 4u) {
			c->err = WR_E_M2_FRAME_FORM;
			return -1;
		}
		nseg = p[1];
		need = 32;
		for (i = 0; i < 4u; i++) {
			len[i] = i < nseg ? ld32le(p + 2 + 6 * i) : 0u;
			if (i == 0)
				need += len[0] != 0 ? (size_t)len[0] + 4u : 0u;
			else
				need += len[i];
		}
		if (nseg > 1u)
			need += 13u;
		if (c->in.n < need)
			return 0;
		{
			size_t at = 32;

			c->tag = p[0], c->nseg = nseg, c->late = 0;
			for (i = 0; i < 4u; i++) {
				c->seg[i].n = 0;
				c->len[i] = len[i];
				if (i >= nseg)
					continue;
				stc_buf_add(&c->seg[i], p + at, len[i]);
				at += len[i];
				if (i == 0 && len[0] != 0) {
					if (sim_sec_crc32c(0xffffffffu, p + at - len[0], len[0]) != ld32le(p + at)) {
						c->err = WR_E_M2_FRAME_CRC;
						return -1;
					}
					at += 4;
				}
			}
			if (nseg > 1u)
				c->late = p[at];
		}
		stc_buf_drop(&c->in, need);
		c->n_frames_rx++;
		return 1;
	}
}

/* ---- the control frames of the handshake ------------------------------------------------------------------------------------- */

/* The entity_addr_t of the simulators' helper: marker 1, type, nonce, IPv4 and port. */
static inline void stc_addr(stc_buf *b, uint32_t type, uint32_t nonce, uint8_t a, uint8_t b2, uint8_t c, uint8_t d, uint16_t port)
{
	uint8_t ip[4] = {a, b2, c, d}, t[SIM_M2_ADDR4_LEN];

	sim_m2_put_addr4(t, type, nonce, ip, port);
	stc_buf_add(b, t, sizeof(t));
}

/* The client's HELLO, then reads the server's HELLO (tag 1); 1 on success. */
static inline int stc_hello(stc *c)
{
	stc_buf p = {0, 0, 0};
	int r;

	w8(&p, 8); /* entity type: client */
	stc_addr(&p, 2, 0, 10, 77, 0, 20, 50000);
	r = stc_send1(c, 1, p.p, (uint32_t)p.n);
	stc_buf_free(&p);
	if (r != 0)
		return 0;
	return stc_recv(c) == 1 && c->tag == 1 && c->nseg == 1;
}

/* AUTH_REQUEST: u32 method | vector<u32> modes | blob payload. */
static inline int stc_auth_request(stc *c, uint32_t method, const uint32_t *modes, unsigned nmodes, const uint8_t *pl, uint32_t pl_len)
{
	stc_buf p = {0, 0, 0};
	unsigned i;
	int r;

	w32(&p, method);
	w32(&p, nmodes);
	for (i = 0; i < nmodes; i++)
		w32(&p, modes[i]);
	wblob(&p, pl, pl_len);
	r = stc_send1(c, 2, p.p, (uint32_t)p.n);
	stc_buf_free(&p);
	return r;
}

static inline int stc_auth_more(stc *c, const uint8_t *pl, uint32_t pl_len)
{
	stc_buf p = {0, 0, 0};
	int r;

	wblob(&p, pl, pl_len);
	r = stc_send1(c, 5, p.p, (uint32_t)p.n);
	stc_buf_free(&p);
	return r;
}

/* The two signatures (msgr2-secure-mode.md 2.7): we sign what we received up to and including AUTH_DONE and send it as our
 * first frame after it (secure framing when the mode is secure: the caller has called stc_go_secure), and verify the server's,
 * which is the HMAC of what we sent. 1 = ours sent and the server's verified; 0 = not (c->err or no frame). */
static inline int stc_signatures(stc *c, const uint8_t *key, size_t klen, int *server_sig_ok)
{
	uint8_t mine[32], theirs[32];
	int r;

	c->log_on = 0;
	stc_hmac256(key, klen, c->rxlog.p, c->rxlog.n, mine);
	stc_hmac256(key, klen, c->txlog.p, c->txlog.n, theirs);
	if (stc_send1(c, 7, mine, 32) != 0)
		return 0;
	r = stc_recv(c);
	if (r != 1 || c->tag != 7 || c->nseg != 1 || c->len[0] != 32)
		return 0;
	*server_sig_ok = memcmp(c->seg[0].p, theirs, 32) == 0;
	return 1;
}

/* COMPRESSION_REQUEST (is_compress = 0, no methods: the decline of msgr2-secure-mode.md 4.2), then COMPRESSION_DONE (tag 22: u8 is_compress, u32 method). */
static inline int stc_compression(stc *c)
{
	static const uint8_t req[5] = {0, 0, 0, 0, 0};

	if (stc_send1(c, 21, req, 5) != 0)
		return 0;
	return stc_recv(c) == 1 && c->tag == 22 && c->len[0] == 5 && c->seg[0].p[0] == 0 && ld32le(c->seg[0].p + 1) == 0;
}

/* CLIENT_IDENT, then reads SERVER_IDENT (tag 9). 1 on success. */
static inline int stc_ident(stc *c)
{
	stc_buf p = {0, 0, 0};
	int r;

	w8(&p, 2); /* addrvec marker */
	w32(&p, 1);
	stc_addr(&p, 2, 77, 10, 77, 0, 20, 50000);
	stc_addr(&p, 2, 0, 10, 77, 0, 10, 3300);
	w64(&p, 4242);                     /* gid */
	w64(&p, 1);                        /* global_seq */
	w64(&p, 0x3f07fffffffdffffull);    /* supported */
	w64(&p, 0x0800000000000000ull);    /* required */
	w64(&p, 1);                        /* flags: lossy */
	w64(&p, 0);                        /* cookie */
	r = stc_send1(c, 8, p.p, (uint32_t)p.n);
	stc_buf_free(&p);
	if (r != 0)
		return 0;
	return stc_recv(c) == 1 && c->tag == 9;
}

/* A MESSAGE frame: the 41-byte header (seq, tid, type, priority, version, ... ack_seq, flags 3, compat) and up to three payload segments. */
static inline int stc_send_msg(stc *c, uint16_t type, uint64_t tid, const uint8_t *front, uint32_t flen, const uint8_t *middle,
			       uint32_t mlen, const uint8_t *data, uint32_t dlen)
{
	uint8_t h[41];
	stc_buf hb = {0, 0, 0};
	const uint8_t *seg[4];
	uint32_t len[4];
	unsigned nseg = dlen != 0 ? 4u : mlen != 0 ? 3u : flen != 0 ? 2u : 1u;
	int r;

	w64(&hb, ++c->out_seq);
	w64(&hb, tid);
	w16(&hb, type);
	w16(&hb, 127);
	w16(&hb, 1);       /* version */
	w32(&hb, 0);       /* data pre padding */
	w16(&hb, 0);       /* data_off */
	w64(&hb, c->in_seq);
	w8(&hb, 3);        /* flags: COMPLETE | NOCRC */
	w16(&hb, 1);       /* compat */
	w16(&hb, 0);
	memcpy(h, hb.p, sizeof(h));
	stc_buf_free(&hb);
	seg[0] = h, len[0] = sizeof(h);
	seg[1] = front, len[1] = flen;
	seg[2] = middle, len[2] = mlen;
	seg[3] = data, len[3] = dlen;
	r = stc_send(c, 17, nseg, seg, len);
	return r;
}

#endif /* SIM_SEC_TC_H */
