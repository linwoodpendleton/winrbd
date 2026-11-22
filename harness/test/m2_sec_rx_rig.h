/* SPDX-License-Identifier: MIT */
/*
 * m2_sec_rx_rig.h - the rig of the secure receive parser tests and its fuzz target (harness code, libc allowed, header only).
 *
 * What it gives:
 *   - a parser rig: the real crc receive parser brought to a frame boundary with a real banner, then switched with the real
 *     wri_m2_secure_on() (or, for a "server view" parser that reads with the other seed, bound by hand), a ring, a segment 0 buffer;
 *   - the pump: bytes in with any chunking through window()/commit() (so a big segment goes through the direct window) or through
 *     the ring only, a work budget per step, a stop point, the owner's side of every event (copy segment 0 at SEG0, choose sinks,
 *     copy the sinks at FRAME, release the frame), every sink a heap block with canary bands around and behind its data;
 *   - frame generation: a shape (tag and segment lengths) with deterministic content, encoded by the simulator's secure encoder
 *     (harness/test/support/sim_m2_sec.h), never by the core.
 * Nothing here checks anything: the run records what happened (events, error, copies, band violations) and the tests judge.
 */
#ifndef M2_SEC_RX_RIG_H
#define M2_SEC_RX_RIG_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim_m2_sec.h"
#include "wri_m2_frame.h"
#include "wri_m2_sec.h"
#include "wri_m2_sec_rxi.h" /* the parser's state names, for the hidden-work check */

#if defined(__GNUC__) || defined(__clang__)
#define SXR_UNUSED __attribute__((unused))
#else
#define SXR_UNUSED
#endif

#define SXR_RING_MAX 4096u
#define SXR_SEG0_MAX 4096u
#define SXR_MAX_FRAMES 16u
#define SXR_MAX_EVENTS 64u
#define SXR_BAND 32u
#define SXR_CANARY 0xA5u

/* ---- the rig ------------------------------------------------------------------------------------------ */

typedef struct sxr {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ringbuf[SXR_RING_MAX];
	wri_m2_txq q;
	uint8_t enc[512];
	uint8_t bounce[256];
	wri_m2s_slot slot;
	uint8_t seg0[SXR_SEG0_MAX];
	const wr_prim_ops *prim;
	uint32_t seg0_cap;
	int secure; /* 1 once bound */
} sxr;

/* A secret of 64 bytes that is not a pattern, with two different nonce seeds; salt picks one. */
SXR_UNUSED static void sxr_secret(uint8_t out[64], uint32_t salt)
{
	uint32_t x = salt * 2654435761u + 12345u;
	unsigned i;

	for (i = 0; i < 64; i++) {
		x ^= x << 13;
		x ^= x >> 17;
		x ^= x << 5;
		out[i] = (uint8_t)(x >> 11);
	}
}

/*
 * Build a rig whose parser is secure. crossed = 0: a client (reads with seed A, switched by wri_m2_secure_on); crossed = 1: the parser of
 * a server (reads with seed B), bound by hand the way the switch does. Returns 0 or the failing status.
 */
SXR_UNUSED static int sxr_init_pre(sxr *r, const wr_prim_ops *prim, const uint8_t *secret, size_t n, int crossed, uint32_t seg0_cap,
				   uint32_t seg_cap_max, uint32_t ring_cap, const uint8_t *pre, size_t pre_n)
{
	uint8_t banner[WRI_M2_BANNER_LEN];
	uint32_t budget = 0xffffffffu;
	wr_status st;

	memset(r, 0, sizeof(*r));
	r->prim = prim;
	r->seg0_cap = seg0_cap;
	memset(r->seg0, SXR_CANARY, sizeof(r->seg0));
	wri_m2_rx_init(&r->rx, r->seg0, seg0_cap, seg_cap_max);
	wri_ring_init(&r->ring, r->ringbuf, ring_cap);
	wri_m2_txq_init(&r->q, r->enc, sizeof(r->enc));
	/* a real banner, so that the crc parser stands at a frame boundary the way it does after the handshake */
	wri_m2_banner_build(banner);
	if (wri_ring_write(&r->ring, banner, 16) != 16)
		return -1;
	(void)wri_m2_rx_step(&r->rx, &r->ring, prim, &budget, NULL, NULL);
	if (wri_ring_write(&r->ring, banner + 16, 10) != 10)
		return -1;
	if (wri_m2_rx_step(&r->rx, &r->ring, prim, &budget, NULL, NULL) != WRI_RXE_BANNER)
		return -1;
	/* bytes of the first secure frame that came in together with the banner: they sit in the ring when the switch happens */
	if (pre_n != 0 && wri_ring_write(&r->ring, pre, (uint32_t)pre_n) != (uint32_t)pre_n)
		return -1;
	if (crossed == 0) {
		st = wri_m2_secure_on(&r->rx, &r->q, &r->slot, prim, secret, n, r->bounce, sizeof(r->bounce));
	} else {
		st = wri_m2s_init(&r->slot.s, prim, secret, n, 1);
		if (st == WR_OK) {
			r->slot.rx.s = &r->slot.s;
			r->rx.sx = &r->slot.rx;
			wri_m2s_rx_next(&r->rx);
		}
	}
	if (st != WR_OK)
		return (int)st;
	r->secure = 1;
	return 0;
}

SXR_UNUSED static int sxr_init(sxr *r, const wr_prim_ops *prim, const uint8_t *secret, size_t n, int crossed, uint32_t seg0_cap,
			       uint32_t seg_cap_max, uint32_t ring_cap)
{
	return sxr_init_pre(r, prim, secret, n, crossed, seg0_cap, seg_cap_max, ring_cap, NULL, 0);
}

SXR_UNUSED static void sxr_wipe(sxr *r)
{
	if (r->secure)
		wri_m2_secure_off(&r->rx, &r->q, &r->slot);
	r->secure = 0;
}

/* ---- sinks and the owner's side of the events ------------------------------------------------------------- */

#define SXR_SINK_EXACT 0u   /* a block of exactly the segment's length */
#define SXR_SINK_BIG 1u     /* a block of length + 50 bytes (the padding must not land in it) */
#define SXR_SINK_NONE 2u    /* no sink: the segment is discarded */
#define SXR_SINK_SHORT 3u   /* a block one byte shorter than the segment (the parser must refuse it after SEG0) */

typedef struct sxr_cfg {
	uint32_t split;     /* 0 = what the window takes, 1 = one byte, 2 = random pieces up to `chunk`, 3 = pieces of `chunk` */
	uint32_t chunk;
	uint32_t budget;    /* per step call; 0 = NULL (no limit) */
	uint32_t seed;
	int via_ring;       /* 1 = bytes go through wri_ring_write, never through window() / commit() */
	uint8_t sink_mode[4]; /* [1..3] SXR_SINK_* */
	size_t stop_at;     /* 0 = feed everything; else stop feeding after this many bytes */
	int keep_going;     /* 1 = after an ERROR keep calling step/window/next_frame a few times (stickiness is checked by the caller) */
} sxr_cfg;

typedef struct sxr_sink {
	uint8_t *base;    /* the block with its bands: [band][cap][band] */
	uint8_t *dst;     /* base + band */
	uint32_t cap;
	uint32_t len;     /* the segment's length */
} sxr_sink;

typedef struct sxr_frame {
	uint8_t ev;                 /* WRI_RXE_FRAME or WRI_RXE_ABORTED */
	wri_m2_desc desc;
	uint32_t stored[4];
	uint8_t *seg[4];            /* copies: segment 0 as seen at SEG0, the others as they lay in the sink at FRAME; NULL for none */
	uint8_t seg0_at_event_ok;   /* the bytes past segment 0 in its buffer were untouched at SEG0 */
} sxr_frame;

typedef struct sxr_out {
	unsigned nframes;
	sxr_frame fr[SXR_MAX_FRAMES];
	uint8_t evs[SXR_MAX_EVENTS]; /* every event other than NONE, in order (WRI_RXE_*) */
	unsigned nev;
	int errored;
	wr_status err;               /* the status of the ERROR */
	unsigned direct_hits;        /* calls of window() that handed out a pointer inside a sink */
	unsigned steps;
	uint64_t units;              /* budget units spent (only when a budget is given) */
	unsigned guard_bad;          /* a band or a tail behind a sink or the segment 0 buffer was written */
	unsigned order_bad;          /* FRAME / ABORTED without SEG0 before, SEG0 twice, an event after ERROR */
	unsigned hidden_bad;         /* a step ended with NONE and an empty ring and direct window while a whole block / part 1 was waiting to be decrypted:
				      * the connection's "work left" test could not see that work, and would sleep on it */
	int stalled;                 /* the pump could not go on (a bug of the parser or of the test) */
	size_t fed;
	size_t ring_left;            /* bytes still in the ring at the end */
	uint32_t direct_left;
	/* the run state, kept here so that a second call continues the same stream: the sinks of the frame in progress (base == NULL: none /
	 * discarded), whether a frame is open, the random state of the chunking */
	sxr_sink sk[4];
	int in_frame;
	uint32_t rng;
} sxr_out;

SXR_UNUSED static void sxr_out_free(sxr_out *o)
{
	unsigned i, k;

	for (i = 0; i < o->nframes + (unsigned)(o->in_frame != 0 && o->nframes < SXR_MAX_FRAMES); i++)
		for (k = 0; k < 4; k++)
			free(o->fr[i].seg[k]); /* a frame in progress (SEG0 seen) holds its copy of segment 0 too */
	for (k = 0; k < 4; k++)
		free(o->sk[k].base);
	memset(o, 0, sizeof(*o));
}

static uint32_t sxr_rnd(uint32_t *s)
{
	*s ^= *s << 13;
	*s ^= *s >> 17;
	*s ^= *s << 5;
	return *s;
}

static int sxr_all_canary(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != SXR_CANARY)
			return 0;
	return 1;
}

static int sxr_sink_new(sxr_sink *s, uint32_t len, unsigned mode)
{
	memset(s, 0, sizeof(*s));
	s->len = len;
	if (mode == SXR_SINK_NONE)
		return 0;
	s->cap = mode == SXR_SINK_SHORT ? (len != 0 ? len - 1u : 0u) : len + (mode == SXR_SINK_BIG ? 50u : 0u);
	s->base = (uint8_t *)malloc((size_t)s->cap + 2u * SXR_BAND);
	if (s->base == NULL)
		return -1;
	memset(s->base, SXR_CANARY, (size_t)s->cap + 2u * SXR_BAND);
	s->dst = s->base + SXR_BAND;
	return 0;
}

/* Work the parser is sitting on that nothing outside it can see: part 1 staged in full, or a whole block / a whole tag waiting. */
static int sxr_hidden_work(const sxr *r)
{
	const wri_m2s_rx *sx = r->rx.sx;

	if (sx == NULL || r->rx.state == WRI_RX_DEAD)
		return 0;
	switch (sx->state) {
	case WRI_M2SR_P1:
		return sx->pos >= WRI_M2S_P1_WIRE;
	case WRI_M2SR_P2T:
	case WRI_M2SR_P3T:
		return sx->pos >= WRI_M2S_TAG_LEN;
	case WRI_M2SR_P2:
	case WRI_M2SR_P3:
	case WRI_M2SR_P3E:
		return sx->pos - sx->dec >= WRI_M2S_BLOCK;
	default:
		return 0;
	}
}

/* bands and tail untouched? (the data part is judged by the caller) */
static int sxr_sink_guard_ok(const sxr_sink *s)
{
	if (s->base == NULL)
		return 1;
	if (s->cap < s->len) /* a short sink: only the band behind it counts */
		return sxr_all_canary(s->base, SXR_BAND) && sxr_all_canary(s->dst + s->cap, SXR_BAND);
	return sxr_all_canary(s->base, SXR_BAND) && sxr_all_canary(s->dst + s->len, (size_t)(s->cap - s->len) + SXR_BAND);
}

/*
 * Pump wire[0 .. n) into the rig. See sxr_cfg. The rig keeps its state, so a second call continues the same stream (the frames recorded
 * by the first call stay in `o`; a caller that wants a fresh record clears it first).
 */
SXR_UNUSED static void sxr_run(sxr *r, const uint8_t *wire, size_t n, const sxr_cfg *c, sxr_out *o)
{
	sxr_sink *sk = o->sk;
	size_t limit = (c->stop_at != 0 && c->stop_at < n) ? c->stop_at : n;
	size_t off = o->fed;
	unsigned iter, i, extra = 0;
	uint32_t budget, spent;

	if (o->rng == 0)
		o->rng = c->seed | 1u;
	for (iter = 0; iter < 20000000u; iter++) {
		wri_m2_rx_ev ev;

		budget = c->budget;
		ev = wri_m2_rx_step(&r->rx, &r->ring, r->prim, c->budget != 0 ? &budget : NULL, NULL, NULL);
		o->steps++;
		if (c->budget != 0) {
			spent = c->budget - budget;
			o->units += spent;
		}
		if (ev != WRI_RXE_NONE && o->nev < SXR_MAX_EVENTS)
			o->evs[o->nev++] = (uint8_t)ev;
		if (o->errored && ev != WRI_RXE_ERROR && ev != WRI_RXE_NONE)
			o->order_bad++;
		if (ev == WRI_RXE_SEG0) {
			sxr_frame *f;

			if (o->in_frame || o->nframes >= SXR_MAX_FRAMES) {
				o->order_bad++;
				break;
			}
			o->in_frame = 1;
			f = &o->fr[o->nframes];
			memset(f, 0, sizeof(*f));
			f->desc = r->rx.desc;
			f->seg0_at_event_ok = f->desc.len[0] > r->seg0_cap || sxr_all_canary(r->seg0 + f->desc.len[0], r->seg0_cap - f->desc.len[0]);
			f->seg[0] = (uint8_t *)malloc(f->desc.len[0] + 1u);
			if (f->seg[0] == NULL)
				abort();
			if (r->rx.sink[0].dst != NULL)
				memcpy(f->seg[0], r->rx.sink[0].dst, f->desc.len[0]);
			for (i = 1; i < f->desc.nseg; i++) {
				if (sxr_sink_new(&sk[i], f->desc.len[i], c->sink_mode[i]) != 0)
					abort();
				if (sk[i].dst != NULL)
					wri_m2_rx_sink(&r->rx, i, sk[i].dst, sk[i].cap);
			}
			continue;
		}
		if (ev == WRI_RXE_FRAME || ev == WRI_RXE_ABORTED) {
			sxr_frame *f = &o->fr[o->nframes];

			if (!o->in_frame) {
				o->order_bad++;
				break;
			}
			f->ev = (uint8_t)ev;
			for (i = 0; i < 4; i++)
				f->stored[i] = r->rx.stored[i];
			for (i = 1; i < f->desc.nseg; i++) {
				if (sk[i].dst != NULL) {
					f->seg[i] = (uint8_t *)malloc(f->desc.len[i] + 1u);
					if (f->seg[i] == NULL)
						abort();
					memcpy(f->seg[i], sk[i].dst, f->desc.len[i]);
				}
				if (!sxr_sink_guard_ok(&sk[i]))
					o->guard_bad++;
				free(sk[i].base);
				memset(&sk[i], 0, sizeof(sk[i]));
			}
			if (f->desc.len[0] <= r->seg0_cap && !sxr_all_canary(r->seg0 + f->desc.len[0], r->seg0_cap - f->desc.len[0]))
				o->guard_bad++;
			o->nframes++;
			o->in_frame = 0;
			wri_m2_rx_next_frame(&r->rx);
			memset(r->seg0, SXR_CANARY, sizeof(r->seg0));
			continue;
		}
		if (ev == WRI_RXE_ERROR) {
			uint8_t *p;

			o->errored = 1;
			o->err = r->rx.err.status;
			for (i = 1; i < 4; i++)
				if (!sxr_sink_guard_ok(&sk[i]))
					o->guard_bad++;
			if (r->rx.desc.len[0] <= r->seg0_cap && !sxr_all_canary(r->seg0 + r->rx.desc.len[0], r->seg0_cap - r->rx.desc.len[0]))
				o->guard_bad++;
			/* stickiness: the same event again, no window, next_frame changes nothing */
			if (wri_m2_rx_step(&r->rx, &r->ring, r->prim, NULL, NULL, NULL) != WRI_RXE_ERROR || wri_m2_rx_window(&r->rx, &r->ring, &p) != 0)
				o->order_bad++;
			wri_m2_rx_next_frame(&r->rx);
			if (wri_m2_rx_step(&r->rx, &r->ring, r->prim, NULL, NULL, NULL) != WRI_RXE_ERROR)
				o->order_bad++;
			if (c->keep_going && extra++ < 3)
				continue;
			break;
		}
		/* NONE */
		if (r->ring.len == 0 && r->rx.direct == 0 && sxr_hidden_work(r))
			o->hidden_bad++;
		if (c->budget != 0 && budget == 0)
			continue; /* out of budget, there may be more work */
		if (off >= limit)
			break;
		{
			size_t want, got = 0;
			uint8_t *p;

			switch (c->split) {
			case 1:
				want = 1;
				break;
			case 2:
				want = 1u + (sxr_rnd(&o->rng) % (c->chunk != 0 ? c->chunk : 200u));
				break;
			case 3:
				want = c->chunk != 0 ? c->chunk : 1;
				break;
			default:
				want = limit - off;
				break;
			}
			if (want > limit - off)
				want = limit - off;
			if (c->via_ring) {
				uint32_t fr = wri_ring_free(&r->ring);

				if (want > fr)
					want = fr;
				if (want == 0) {
					o->stalled = 1;
					break;
				}
				got = wri_ring_write(&r->ring, wire + off, (uint32_t)want);
			} else {
				size_t w = wri_m2_rx_window(&r->rx, &r->ring, &p);

				if (w == 0) {
					o->stalled = 1;
					break;
				}
				if (want > w)
					want = w;
				for (i = 1; i < 4; i++)
					if (sk[i].dst != NULL && p >= sk[i].dst && p < sk[i].dst + sk[i].cap) {
						o->direct_hits++;
						break;
					}
				memcpy(p, wire + off, want);
				wri_m2_rx_commit(&r->rx, &r->ring, want);
				got = want;
			}
			off += got;
			o->fed = off;
		}
	}
	if (iter >= 20000000u)
		o->stalled = 1;
	o->fed = off;
	o->ring_left = r->ring.len;
	o->direct_left = r->rx.direct;
	/* an unfinished frame: its sinks stay in o->sk (the bands are checked when it finishes, or by the caller) */
}

/* ---- frames --------------------------------------------------------------------------------------------- */

typedef struct sxr_shape {
	uint8_t tag;
	unsigned nseg;     /* 1 .. 4 */
	uint32_t len[4];
} sxr_shape;

/* Deterministic content of segment k of a frame (salt picks the frame). */
SXR_UNUSED static void sxr_fill(uint8_t *p, size_t n, unsigned k, unsigned salt)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(k * 37u + salt * 11u + i * 7u + (i >> 8) * 13u + 1u);
}

typedef struct sxr_frame_src {
	sxr_shape shape;
	uint8_t *data[4];
	sim_sec_spec spec;
} sxr_frame_src;

SXR_UNUSED static void sxr_src_make(sxr_frame_src *s, const sxr_shape *sh, unsigned salt)
{
	unsigned k;

	memset(s, 0, sizeof(*s));
	s->shape = *sh;
	s->spec.tag = sh->tag;
	s->spec.nseg = sh->nseg;
	for (k = 0; k < sh->nseg; k++) {
		s->data[k] = (uint8_t *)malloc((size_t)sh->len[k] + 1u);
		if (s->data[k] == NULL)
			abort();
		sxr_fill(s->data[k], sh->len[k], k, salt);
		s->spec.seg[k] = s->data[k];
		s->spec.len[k] = sh->len[k];
	}
}

SXR_UNUSED static void sxr_src_free(sxr_frame_src *s)
{
	unsigned k;

	for (k = 0; k < 4; k++)
		free(s->data[k]);
	memset(s, 0, sizeof(*s));
}

/* Encode a frame with the next nonces of tx; the bytes are malloc'd (caller frees). NULL when the encoder refuses. */
SXR_UNUSED static uint8_t *sxr_encode(sim_sec_dir *tx, const sim_sec_spec *spec, const sim_sec_mut *m, size_t *n)
{
	size_t need = sim_sec_frame_len_m(spec, m, NULL, NULL);
	uint8_t *out;

	if (need == 0)
		need = sim_sec_frame_len(spec, NULL, NULL);
	out = (uint8_t *)malloc(need + 64u);
	if (out == NULL)
		abort();
	if (sim_sec_encode(tx, spec, m, out, need + 64u, n) != 0) {
		free(out);
		*n = 0;
		return NULL;
	}
	return out;
}

/* Operations a frame of this shape takes (1 .. 3). */
SXR_UNUSED static unsigned sxr_nops(const sxr_shape *sh)
{
	return 1u + (sh->len[0] > WRI_M2S_INLINE ? 1u : 0u) + (sh->nseg > 1u ? 1u : 0u);
}

#endif /* M2_SEC_RX_RIG_H */
