/* SPDX-License-Identifier: MIT */
/*
 * m2_sec_tx_rig.h - the shared rig of the secure-transmit tests (test_m2_sec_tx_frames.c, test_m2_sec_tx_stream.c,
 * test_m2_sec_tx_diff.c) and of the fuzz target fuzz_m2_sec_tx.c. Harness code, libc allowed, never part of the core; everything is static
 * inline so each executable carries its own copy. The includer defines TXR_CHECK(cond) first (WRT_CHECK in a test, a trap in the fuzzer).
 *
 * The rig owns what one connection's transmit side stands on: a crc receive parser brought to a frame boundary (wri_m2_secure_on wants
 * one), a transmit queue with an encode buffer of a chosen size, the secure slot and a bounce buffer of a chosen size (both with guard
 * bytes), and the independent peer of sim_m2_sec.h: its encoder (what the core must produce, byte for byte, from the same secret) and its
 * decoder (what the wire says, read by code that shares nothing with the core).
 *
 * Every byte the host "consumes" is recorded, frame by frame the expected bytes are appended from the independent encoder, and each host
 * step checks what the queue promises: the pending count is exact, a peek never shows more than is pending nor less than progress needs,
 * a second peek is identical, the queue is idle exactly when everything is consumed.
 */
#ifndef M2_SEC_TX_RIG_H
#define M2_SEC_TX_RIG_H

#include <stdlib.h>
#include <string.h>

#include "sim_m2_sec.h"
#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_m2_sec.h"

#ifndef TXR_CHECK
#error "define TXR_CHECK(cond) before including m2_sec_tx_rig.h"
#endif

#define TXR_GUARD 64u
#define TXR_GUARD_BYTE 0xa7u
#define TXR_MAX_PEEK (WRI_M2_TXQ_IOV + 2u)

typedef struct txr_sent {
	uint8_t tag;
	unsigned nseg;
	uint32_t len[4];
	uint8_t *data[4];
} txr_sent;

typedef struct txr {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ringbuf[64];
	uint8_t seg0[64];
	wri_m2_txq q;
	uint8_t *enc_raw, *enc; /* encode buffer with a guard before and after */
	uint32_t enc_cap;
	uint8_t *bnc_raw, *bounce;
	uint32_t bounce_cap;
	wri_m2s_slot slot;
	uint8_t secret[64];
	const wr_prim_ops *prim;
	sim_sec_ctx ref; /* the client's view: ref.tx is what the core's transmit side must reproduce */
	int open;
	/* what the host consumed, and what the independent encoder says it must be */
	uint8_t *wire, *exp;
	size_t wire_len, wire_cap, exp_len, exp_cap;
	uint64_t queued, consumed; /* wire bytes of accepted frames; bytes the host consumed */
	unsigned frames;           /* accepted frames */
	/* frames kept for the decoder */
	int keep;
	int noref; /* do not run the independent encoder (a 4 MiB frame costs it seconds): the decoder and a second core run are the checks */
	txr_sent *sent;
	size_t nsent, sent_cap;
	uint64_t rng;
	size_t max_iov_seen;
	/* ranges of exp that were dropped by a reset (the host's wire stops there, the nonces of those frames are spent) */
	size_t skip_from[8], skip_to[8], skipped;
	unsigned nskip;
} txr;

static inline uint32_t txr_rnd(txr *r)
{
	r->rng ^= r->rng >> 12;
	r->rng ^= r->rng << 25;
	r->rng ^= r->rng >> 27;
	return (uint32_t)((r->rng * 0x2545f4914f6cdd1dull) >> 32);
}

static inline void txr_buf_add(uint8_t **b, size_t *len, size_t *cap, const void *p, size_t n)
{
	if (*len + n > *cap) {
		size_t nc = *cap != 0u ? *cap : 4096u;
		uint8_t *nb;

		while (nc < *len + n)
			nc *= 2u;
		nb = (uint8_t *)realloc(*b, nc);
		TXR_CHECK(nb != NULL);
		if (nb == NULL)
			abort();
		*b = nb;
		*cap = nc;
	}
	if (n > 0u)
		memcpy(*b + *len, p, n);
	*len += n;
}

static inline int txr_guard_ok(const uint8_t *raw, size_t cap)
{
	size_t i;

	for (i = 0; i < TXR_GUARD; i++)
		if (raw[i] != TXR_GUARD_BYTE || raw[TXR_GUARD + cap + i] != TXR_GUARD_BYTE)
			return 0;
	return 1;
}

static inline uint8_t *txr_alloc_guarded(uint8_t **raw, size_t cap, uint8_t fill)
{
	*raw = (uint8_t *)malloc(cap + 2u * TXR_GUARD);
	TXR_CHECK(*raw != NULL);
	if (*raw == NULL)
		abort();
	memset(*raw, TXR_GUARD_BYTE, cap + 2u * TXR_GUARD);
	memset(*raw + TXR_GUARD, fill, cap);
	return *raw + TXR_GUARD;
}

/* The crc parser of a fresh connection after its banner: a frame boundary, the state wri_m2_secure_on() needs. */
static inline void txr_rx_to_boundary(txr *r)
{
	uint8_t b[WRI_M2_BANNER_LEN];
	wri_m2_rx_ev ev, last = WRI_RXE_NONE;

	wri_m2_rx_init(&r->rx, r->seg0, sizeof(r->seg0), 1024u);
	wri_ring_init(&r->ring, r->ringbuf, sizeof(r->ringbuf));
	wri_m2_banner_build(b);
	wri_le64_put(b + 10, 3);
	TXR_CHECK(wri_ring_write(&r->ring, b, sizeof(b)) == sizeof(b));
	while ((ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL)) != WRI_RXE_NONE)
		last = ev;
	TXR_CHECK(last == WRI_RXE_BANNER);
}

/* Open the transmit side: encode buffer of enc_cap bytes, bounce buffer of bounce_cap, secret = the given 64 bytes or the synthetic 00..3f. */
static inline wr_status txr_open2(txr *r, uint32_t enc_cap, uint32_t bounce_cap, const wr_prim_ops *prim, const uint8_t *secret64,
				  uint8_t *bounce_given)
{
	size_t i;
	wr_status st;

	memset(r, 0, sizeof(*r));
	r->rng = 0x9e3779b97f4a7c15ull;
	r->prim = prim;
	r->enc_cap = enc_cap;
	r->bounce_cap = bounce_cap;
	r->enc = txr_alloc_guarded(&r->enc_raw, enc_cap, 0xcd);
	if (bounce_given != NULL)
		r->bounce = bounce_given; /* the test owns it (and watches it itself) */
	else
		r->bounce = txr_alloc_guarded(&r->bnc_raw, bounce_cap, 0xcd);
	for (i = 0; i < sizeof(r->secret); i++)
		r->secret[i] = secret64 != NULL ? secret64[i] : (uint8_t)i;
	txr_rx_to_boundary(r);
	wri_m2_txq_init(&r->q, r->enc, enc_cap);
	st = wri_m2_secure_on(&r->rx, &r->q, &r->slot, prim, r->secret, sizeof(r->secret), r->bounce, bounce_cap);
	if (st != WR_OK)
		return st;
	TXR_CHECK(sim_sec_ctx_init(&r->ref, r->secret, sizeof(r->secret), 0) == 0);
	r->open = 1;
	return WR_OK;
}

static inline wr_status txr_open(txr *r, uint32_t enc_cap, uint32_t bounce_cap, const wr_prim_ops *prim, const uint8_t *secret64)
{
	return txr_open2(r, enc_cap, bounce_cap, prim, secret64, NULL);
}

/* Guard bytes intact, then everything released (the slot wiped through wri_m2_secure_off). */
static inline void txr_close(txr *r)
{
	size_t i, k;

	TXR_CHECK(txr_guard_ok(r->enc_raw, r->enc_cap));
	if (r->bnc_raw != NULL)
		TXR_CHECK(txr_guard_ok(r->bnc_raw, r->bounce_cap));
	wri_m2_secure_off(&r->rx, &r->q, &r->slot);
	sim_sec_ctx_wipe(&r->ref);
	for (i = 0; i < r->nsent; i++)
		for (k = 0; k < 4u; k++)
			free(r->sent[i].data[k]);
	free(r->sent);
	free(r->wire);
	free(r->exp);
	free(r->enc_raw);
	free(r->bnc_raw);
	r->open = 0;
}

/* The wire bytes of a frame of this shape, worked out from the spec's table alone (part 1, part 2 above 48 bytes of segment 0, part 3). */
static inline uint64_t txr_shape_wire(const wri_m2_seg_src *seg, unsigned nseg)
{
	uint64_t n = 96u;
	unsigned i;

	if (seg[0].len > 48u)
		n += (((uint64_t)seg[0].len + 15u) & ~(uint64_t)15u) - 48u + 16u;
	if (nseg > 1u) {
		for (i = 1; i < nseg; i++)
			n += ((uint64_t)seg[i].len + 15u) & ~(uint64_t)15u;
		n += 32u;
	}
	return n;
}

static inline void txr_keep_frame(txr *r, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	txr_sent s;
	unsigned i;

	memset(&s, 0, sizeof(s));
	s.tag = tag;
	s.nseg = nseg;
	for (i = 0; i < nseg; i++) {
		s.len[i] = seg[i].len;
		if (seg[i].len != 0u) {
			s.data[i] = (uint8_t *)malloc(seg[i].len);
			TXR_CHECK(s.data[i] != NULL);
			if (s.data[i] == NULL)
				abort();
			memcpy(s.data[i], seg[i].p, seg[i].len);
		}
	}
	if (r->nsent == r->sent_cap) {
		r->sent_cap = r->sent_cap != 0u ? r->sent_cap * 2u : 16u;
		r->sent = (txr_sent *)realloc(r->sent, r->sent_cap * sizeof(*r->sent));
		TXR_CHECK(r->sent != NULL);
		if (r->sent == NULL)
			abort();
	}
	r->sent[r->nsent++] = s;
}

/* Hand a frame to the queue the way the connection does (the dispatching wri_m2_tx_frame). On WR_OK the independent encoder produces the
 * same frame and the expected bytes grow; any other status leaves the expectation alone, which is what "no nonce was taken" means. */
static inline wr_status txr_send(txr *r, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	wr_status st = wri_m2_tx_frame(&r->q, r->prim, tag, seg, nseg, NULL, NULL);
	unsigned i;

	if (st != WR_OK)
		return st;
	if (r->noref) {
		r->queued += txr_shape_wire(seg, nseg);
	} else {
		sim_sec_spec f;
		size_t n = 0, cap;
		uint8_t *out;

		memset(&f, 0, sizeof(f));
		f.tag = tag;
		f.nseg = nseg;
		for (i = 0; i < nseg; i++) {
			f.seg[i] = seg[i].p;
			f.len[i] = seg[i].len;
		}
		cap = sim_sec_frame_len(&f, NULL, NULL);
		TXR_CHECK(cap != 0u && cap == txr_shape_wire(seg, nseg));
		out = (uint8_t *)malloc(cap);
		TXR_CHECK(out != NULL);
		if (out == NULL)
			abort();
		TXR_CHECK(sim_sec_encode(&r->ref.tx, &f, NULL, out, cap, &n) == 0);
		TXR_CHECK(n == cap);
		txr_buf_add(&r->exp, &r->exp_len, &r->exp_cap, out, n);
		r->queued += n;
		free(out);
	}
	if (r->keep)
		txr_keep_frame(r, tag, seg, nseg);
	r->frames++;
	return WR_OK;
}

/* The invariants the queue promises, checked after every host step and after every accepted frame. */
static inline void txr_check_queue(txr *r)
{
	uint64_t held = 0;
	unsigned i;

	TXR_CHECK(r->q.pending == r->queued - r->consumed);
	/* white box: what is pending is exactly the gather entries, the bounce piece and the part of the stream not produced yet */
	for (i = 0; i < r->q.niov; i++)
		held += r->q.iov[i].len;
	if (r->q.sx != NULL)
		held += (uint64_t)r->q.sx->b_len + r->q.sx->stream_left;
	TXR_CHECK(held == r->q.pending);
	TXR_CHECK((wri_m2_txq_idle(&r->q) != 0) == (r->queued == r->consumed));
}

/*
 * One host cycle: peek, check the peek, take up to `want` bytes of it (the order of the entries is the order of the wire), consume them.
 * Returns the bytes taken (0 means the host has nothing to send: the queue must then be idle). `want` 0 takes everything shown.
 */
static inline size_t txr_pull(txr *r, size_t want)
{
	wr_iov a[TXR_MAX_PEEK], b[TXR_MAX_PEEK];
	size_t n, n2, i, total = 0, take, left;

	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	n = wri_m2_txq_peek(&r->q, a, WRI_M2_TXQ_IOV + 1u);
	n2 = wri_m2_txq_peek(&r->q, b, WRI_M2_TXQ_IOV + 1u);
	TXR_CHECK(n == n2 && n <= WRI_M2_TXQ_IOV + 1u);
	if (n > r->max_iov_seen)
		r->max_iov_seen = n;
	for (i = 0; i < n && i < TXR_MAX_PEEK; i++) {
		TXR_CHECK(a[i].base == b[i].base && a[i].len == b[i].len && a[i].len > 0u);
		total += a[i].len;
	}
	TXR_CHECK(total <= r->q.pending);        /* never beyond what is promised */
	TXR_CHECK((total == 0u) == (r->q.pending == 0u)); /* and always progress while something is pending */
	take = (want == 0u || want > total) ? total : want;
	left = take;
	for (i = 0; i < n && left > 0u; i++) {
		size_t k = a[i].len < left ? a[i].len : left;

		txr_buf_add(&r->wire, &r->wire_len, &r->wire_cap, a[i].base, k);
		left -= k;
	}
	if (take > 0u) {
		wri_m2_txq_consume(&r->q, take);
		r->consumed += take;
	}
	txr_check_queue(r);
	return take;
}

/* Drain the queue completely with one host strategy: fixed `step` bytes per cycle (0 = everything shown), or random sizes up to `step` when
 * `randomize` is set. */
static inline void txr_drain(txr *r, size_t step, int randomize)
{
	for (;;) {
		size_t want = step;
		size_t got;

		if (randomize && step > 0u)
			want = 1u + (size_t)txr_rnd(r) % step;
		got = txr_pull(r, want);
		if (got == 0u)
			break;
	}
	TXR_CHECK(wri_m2_txq_idle(&r->q));
}

/* wri_m2_txq_reset in the middle of the traffic (the connection is going away): the frames that did not leave are dropped from the
 * expectation, their nonces stay spent in both the core and the encoder, and later frames must still match. */
static inline void txr_reset(txr *r)
{
	size_t from = r->wire_len + r->skipped;

	wri_m2_txq_reset(&r->q);
	TXR_CHECK(wri_m2_txq_idle(&r->q) && wri_m2s_tx_done(&r->q) && r->nskip < 8u);
	if (r->nskip < 8u) {
		r->skip_from[r->nskip] = from;
		r->skip_to[r->nskip] = r->exp_len;
		r->nskip++;
		r->skipped += r->exp_len - from;
	}
	r->queued = r->consumed;
}

/* The bytes the host consumed are exactly what the independent encoder produced from the same frames (same key, same nonces), less the
 * ranges a reset dropped. */
static inline int txr_wire_matches(const txr *r)
{
	size_t pos = 0, w = 0, i;

	for (i = 0; i <= r->nskip; i++) {
		size_t end = i < r->nskip ? r->skip_from[i] : r->exp_len;
		size_t n;

		if (end < pos || end > r->exp_len)
			return 0;
		n = end - pos;
		if (w + n > r->wire_len || (n != 0u && memcmp(r->wire + w, r->exp + pos, n) != 0))
			return 0;
		w += n;
		pos = i < r->nskip ? r->skip_to[i] : end;
	}
	return w == r->wire_len;
}

/* The independent decoder (the server's view of the same secret) reads the consumed bytes and finds the kept frames, segment for segment. */
static inline void txr_check_decode(txr *r, size_t feed_chunk)
{
	sim_sec_ctx srv;
	sim_sec_dec d;
	sim_sec_frame f;
	size_t i, k, off = 0;
	int rc;

	TXR_CHECK(sim_sec_ctx_init(&srv, r->secret, sizeof(r->secret), 1) == 0);
	sim_sec_dec_init(&d, &srv.rx, 0, 0);
	if (feed_chunk == 0u)
		feed_chunk = r->wire_len != 0u ? r->wire_len : 1u;
	for (i = 0; i < r->nsent; i++) {
		const txr_sent *s = &r->sent[i];

		for (;;) {
			rc = sim_sec_dec_next(&d, &f);
			if (rc != SIM_SEC_DEC_NEED)
				break;
			TXR_CHECK(off < r->wire_len);
			if (off >= r->wire_len)
				goto out;
			k = r->wire_len - off < feed_chunk ? r->wire_len - off : feed_chunk;
			TXR_CHECK(sim_sec_dec_feed(&d, r->wire + off, k) == 0);
			off += k;
		}
		TXR_CHECK(rc == SIM_SEC_DEC_FRAME);
		if (rc != SIM_SEC_DEC_FRAME)
			goto out;
		TXR_CHECK(f.tag == s->tag && f.nseg == s->nseg && f.flags == 0u && f.reserved == 0u);
		TXR_CHECK(f.late_status == (s->nseg > 1u ? SIM_SEC_LATE_COMPLETE : 0u));
		for (k = 0; k < s->nseg; k++) {
			TXR_CHECK(f.len[k] == s->len[k]);
			TXR_CHECK(f.align[k] == (k == 3u ? 4096u : 8u));
			if (f.len[k] == s->len[k] && s->len[k] != 0u)
				TXR_CHECK(memcmp(f.seg[k], s->data[k], s->len[k]) == 0);
		}
	}
	TXR_CHECK(sim_sec_dec_next(&d, &f) == SIM_SEC_DEC_NEED);
	TXR_CHECK(sim_sec_dec_buffered(&d) == 0u && off == r->wire_len);
out:
	sim_sec_dec_free(&d);
	sim_sec_ctx_wipe(&srv);
}

#endif /* M2_SEC_TX_RIG_H */
