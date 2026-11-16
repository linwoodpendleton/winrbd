/* SPDX-License-Identifier: MIT */
/*
 * Fuzz target for the msgr2.1 receive parser and frame builder (core/src/msgr2/wri_m2_rx.c,
 * wri_m2_tx.c, wri_m2_preamble.c, wri_m2_banner.c).
 *
 * Input layout:
 *
 *   byte 0       bits 0-2 start state (0 banner head, 1 banner payload, 2 preamble, 3 segment 0,
 *                4 segments 1..3, 5 epilogue; 6 and 7 count as 0), bit 3 attach sinks to segments
 *                1..3, bits 4-5 staging ring size (16, 64, 1024, 8192), bits 6-7 feeding style
 *                (all at once, one byte at a time, random pieces, pieces of 7)
 *   byte 1       bit 0 round-trip mode (see below), bit 1 flip one bit in that round trip,
 *                bits 4-7 work budget per step (0 = unlimited, else 1, 2, 3, 7, 16, ...)
 *   bytes 2-3    seg_cap_max - 1
 *   byte 4       segment 0 buffer size / 16 (at least 16)
 *   byte 5       segment count of the prefix frame (1 + b % 4)
 *   bytes 6-13   four u16 lengths of that frame (each % 2048; the last segment of a multi-segment
 *                frame is made non-empty)
 *   rest         the bytes fed to the parser
 *
 * "Started in state S": a valid frame of the shape above is built with the library's own builder
 * and the parser is first fed a valid banner and the prefix of that frame that leaves it in
 * state S; the fuzz bytes follow. In round-trip mode nothing else is fed: the frame is built from
 * the rest of the input (segment bytes), parsed in odd pieces and must come out byte for byte;
 * with the flip bit one bit of it is inverted and the parser must then report an error.
 *
 * Properties: no crash or undefined behaviour; nothing is written outside the sinks (they are
 * exact-size heap blocks with canary bytes behind them, and ASan sees the rest); the transcript
 * callback receives exactly a prefix of the fed bytes; the event sequence is legal (BANNER once
 * and first, SEG0 before FRAME / ABORTED, nothing but ERROR after an error); the ring never
 * overflows; a segment is never stored beyond its length.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wri_le.h"
#include "wri_m2_frame.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define HDR 14u
#define CANARY 8u
#define ENC_CAP 65536u
#define MAX_FEED 200000u

static void check(int cond)
{
	if (!cond)
		__builtin_trap();
}

static uint8_t g_stage[4 * 2048]; /* segment bytes of the frame built by build() */
static size_t g_off[4];           /* offset of each segment in g_stage */

typedef struct sinkbuf {
	uint8_t *p;
	uint32_t len;
} sinkbuf;

typedef struct run {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t *ringbuf;
	uint8_t *seg0;
	uint32_t seg0_cap;
	sinkbuf sink[3];
	int use_sinks;
	uint8_t *fed;       /* everything committed so far, for the transcript check */
	size_t fed_len, fed_cap;
	uint8_t *logged;
	size_t logged_len;
	unsigned banners, seg0s, frames, aborts, errors;
	int in_frame;       /* SEG0 seen, FRAME / ABORTED not yet */
	int short_sink;     /* a sink smaller than its segment was announced in this frame */
	int expect_content; /* round trip: the segments must equal g_stage */
	uint8_t last_tag, last_nseg;
	wri_m2_rx_ev last;
	uint32_t budget_per_step;
	uint32_t rng;
} run;

static uint32_t rnd(run *r)
{
	r->rng ^= r->rng << 13;
	r->rng ^= r->rng >> 17;
	r->rng ^= r->rng << 5;
	return r->rng;
}

static void log_cb(void *log, const uint8_t *p, size_t n)
{
	run *r = (run *)log;

	check(r->logged_len + n <= r->fed_len); /* only bytes that were committed can be consumed */
	check(memcmp(r->fed + r->logged_len, p, n) == 0);
	r->logged_len += n;
}

static void sinks_free(run *r)
{
	unsigned i;

	for (i = 0; i < 3; i++) {
		if (r->sink[i].p != NULL) {
			unsigned k;

			for (k = 0; k < CANARY; k++)
				check(r->sink[i].p[r->sink[i].len + k] == 0xA5); /* nothing written past the end */
			free(r->sink[i].p);
			r->sink[i].p = NULL;
		}
	}
}

static void run_init(run *r, unsigned ring_sel, uint32_t seg0_cap, uint32_t seg_cap_max, size_t total, int use_sinks,
		     uint32_t budget, uint32_t seed)
{
	static const uint32_t ring_caps[4] = {16, 64, 1024, 8192};

	memset(r, 0, sizeof(*r));
	r->ringbuf = (uint8_t *)malloc(ring_caps[ring_sel]);
	r->seg0 = (uint8_t *)malloc(seg0_cap);
	r->seg0_cap = seg0_cap;
	r->fed_cap = total + 1;
	r->fed = (uint8_t *)malloc(r->fed_cap);
	r->use_sinks = use_sinks;
	r->budget_per_step = budget;
	r->rng = seed | 1u;
	check(r->ringbuf && r->seg0 && r->fed);
	wri_ring_init(&r->ring, r->ringbuf, ring_caps[ring_sel]);
	wri_m2_rx_init(&r->rx, r->seg0, seg0_cap, seg_cap_max);
}

static void run_free(run *r)
{
	sinks_free(r);
	free(r->ringbuf);
	free(r->seg0);
	free(r->fed);
}

/* Handle one event of the parser. Returns 1 when the run is over (error). */
static int on_event(run *r, wri_m2_rx_ev ev)
{
	unsigned i;

	check(r->errors == 0); /* nothing but the sticky error after an error */
	switch (ev) {
	case WRI_RXE_BANNER:
		check(r->banners == 0 && r->seg0s == 0);
		r->banners++;
		check((wri_m2_rx_banner(&r->rx)->supported & 1u) != 0);
		check((wri_m2_rx_banner(&r->rx)->required & ~(uint64_t)1) == 0);
		break;
	case WRI_RXE_SEG0:
		check(r->banners == 1 && !r->in_frame);
		r->in_frame = 1;
		r->seg0s++;
		r->last_tag = r->rx.desc.tag;
		r->last_nseg = r->rx.desc.nseg;
		check(r->rx.desc.nseg >= 1 && r->rx.desc.nseg <= 4);
		check(r->rx.desc.tag >= 1 && r->rx.desc.tag <= 22);
		check(r->rx.desc.len[0] <= r->seg0_cap || r->seg0 == NULL);
		for (i = r->rx.desc.nseg; i < 4; i++)
			check(r->rx.desc.len[i] == 0);
		if (r->use_sinks) {
			for (i = 1; i < r->rx.desc.nseg; i++) {
				uint32_t len = r->rx.desc.len[i];
				unsigned k;

				r->sink[i - 1].p = (uint8_t *)malloc((size_t)len + CANARY);
				check(r->sink[i - 1].p != NULL);
				r->sink[i - 1].len = len;
				for (k = 0; k < CANARY; k++)
					r->sink[i - 1].p[len + k] = 0xA5;
				/* now and then announce a sink one byte short: the parser must refuse the segment
				 * (WR_E_M2_FRAME_TOOBIG) before a single byte goes into it */
				if (!r->expect_content && len != 0 && rnd(r) % 8 == 0) {
					wri_m2_rx_sink(&r->rx, i, r->sink[i - 1].p, len - 1);
					r->short_sink = 1;
				} else {
					wri_m2_rx_sink(&r->rx, i, r->sink[i - 1].p, len);
				}
			}
		}
		break;
	case WRI_RXE_FRAME:
		check(r->in_frame);
		check(!r->short_sink); /* a segment larger than its sink never completes */
		r->in_frame = 0;
		r->frames++;
		for (i = 1; i < r->rx.desc.nseg; i++)
			check(r->rx.stored[i] <= r->rx.desc.len[i]);
		if (r->expect_content) { /* round trip: every segment is what was put in */
			check(memcmp(r->seg0, g_stage + g_off[0], r->rx.desc.len[0]) == 0);
			for (i = 1; i < r->rx.desc.nseg; i++) {
				check(r->rx.stored[i] == r->rx.desc.len[i]);
				check(memcmp(r->sink[i - 1].p, g_stage + g_off[i], r->rx.desc.len[i]) == 0);
			}
		}
		sinks_free(r);
		wri_m2_rx_next_frame(&r->rx);
		break;
	case WRI_RXE_ABORTED:
		check(r->in_frame);
		check(!r->short_sink);
		r->in_frame = 0;
		r->aborts++;
		sinks_free(r);
		wri_m2_rx_next_frame(&r->rx);
		break;
	case WRI_RXE_ERROR:
		r->errors++;
		if (r->short_sink && r->in_frame) {
			/* the refusal comes at the first step after SEG0, before any segment byte */
			check(wri_m2_rx_error(&r->rx)->status == WR_E_M2_FRAME_TOOBIG);
		}
		check(wri_m2_rx_error(&r->rx)->status < 0);
		check(wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL) == WRI_RXE_ERROR);
		{
			uint8_t *w = NULL;

			check(wri_m2_rx_window(&r->rx, &r->ring, &w) == 0);
		}
		return 1;
	default:
		check(0);
	}
	return 0;
}

/* Feed `n` bytes; style: 0 all at once, 1 one byte, 2 random pieces, 3 pieces of 7. */
static void feed(run *r, const uint8_t *p, size_t n, unsigned style)
{
	static const uint32_t budgets[16] = {0, 1, 2, 3, 7, 16, 31, 64, 100, 255, 500, 1000, 4096, 5000, 10000, 65536};
	size_t pos = 0, guard = 0;

	while (r->errors == 0 && guard++ < 8 * n + 64) {
		uint8_t *w = NULL;
		size_t room = wri_m2_rx_window(&r->rx, &r->ring, &w), k;
		wri_m2_rx_ev ev;

		if (room != 0 && pos < n) {
			k = style == 0 ? n : style == 1 ? 1 : style == 2 ? 1 + rnd(r) % 300 : 7;
			k = k < room ? k : room;
			k = k < n - pos ? k : n - pos;
			memcpy(w, p + pos, k);
			memcpy(r->fed + r->fed_len, p + pos, k);
			r->fed_len += k;
			wri_m2_rx_commit(&r->rx, &r->ring, k);
			pos += k;
		}
		check(r->ring.len <= r->ring.cap);
		for (;;) {
			uint32_t b = budgets[r->budget_per_step & 15u], *bp = b ? &b : NULL;

			ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, bp, log_cb, r);
			if (ev == WRI_RXE_NONE) {
				if (bp != NULL && b == 0 && (r->ring.len != 0 || r->rx.direct != 0))
					continue; /* budget spent with input left: go on */
				break;
			}
			r->last = ev;
			if (on_event(r, ev))
				return;
		}
		if (pos >= n && r->ring.len == 0 && r->rx.direct == 0)
			break;
	}
}

#define FRAME_MAX (32u + 4u * 2048u + 4u + 13u)

/* Build a valid frame of the given shape with the library's builder. Segment bytes come from src
 * (cycled; zeros when src is empty); bit i of flavour makes segment i a referenced one. */
static size_t build(uint8_t *out, uint8_t tag, unsigned nseg, const uint32_t *len, const uint8_t *src, size_t src_len,
		    uint32_t flavour)
{
	static uint8_t enc[ENC_CAP];
	wri_m2_txq q;
	wri_m2_seg_src s[4];
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t i, n, total = 0, off = 0;

	for (i = 0; i < 4; i++) {
		s[i].len = i < nseg ? len[i] : 0;
		s[i].p = g_stage + off;
		s[i].ref = (uint8_t)((flavour >> i) & 1u);
		g_off[i] = off;
		check(off + s[i].len <= sizeof(g_stage));
		for (n = 0; n < s[i].len; n++)
			g_stage[off + n] = src_len != 0 ? src[(off + n) % src_len] : 0;
		off += s[i].len;
	}
	wri_m2_txq_init(&q, enc, sizeof(enc));
	check(wri_m2_tx_frame(&q, NULL, tag, s, nseg, NULL, NULL) == WR_OK);
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		check(total + iov[i].len <= FRAME_MAX);
		memcpy(out + total, iov[i].base, iov[i].len);
		total += iov[i].len;
	}
	return total;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t mode, flags;
	uint32_t seg_cap_max, seg0_cap, len[4], seed = 1;
	unsigned nseg, state, i, style;
	size_t rest, total, flen, cut = 0, banner_len = WRI_M2_BANNER_LEN;
	const uint8_t *fuzz;
	uint8_t *wire;
	uint8_t banner[WRI_M2_BANNER_LEN];
	run r;

	if (size < HDR || size > MAX_FEED)
		return 0;
	mode = data[0];
	flags = data[1];
	seg_cap_max = 1u + (uint32_t)wri_le16_get(data + 2);
	seg0_cap = 16u * (data[4] ? data[4] : 1u);
	nseg = 1u + data[5] % 4u;
	for (i = 0; i < 4; i++)
		len[i] = (uint32_t)wri_le16_get(data + 6 + 2 * i) % 2048u;
	for (i = nseg; i < 4; i++)
		len[i] = 0;
	if (nseg > 1u && len[nseg - 1u] == 0)
		len[nseg - 1u] = 1;
	fuzz = data + HDR;
	rest = size - HDR;
	state = mode & 7u;
	if (state > 5u)
		state = 0;
	style = (mode >> 6) & 3u;
	for (i = 0; i < size && i < 16; i++)
		seed = seed * 31u + data[i];
	wri_m2_banner_build(banner);

	if (flags & 1u) {
		/* round trip: build a frame from the input, parse it in pieces, compare; optionally flip a bit */
		static uint8_t wirebuf[FRAME_MAX];
		uint8_t tag = (uint8_t)(1u + (rest ? fuzz[0] : 0u) % 22u);
		size_t flip = 0;
		int do_flip = (flags & 2u) != 0;
		uint32_t flavour = rest > 1 ? fuzz[1] : 0u;
		size_t flip_ok_lo, flip_ok_hi;

		memset(wirebuf, 0, sizeof(wirebuf));
		flen = build(wirebuf, tag, nseg, len, rest > 2 ? fuzz + 2 : fuzz, rest > 2 ? rest - 2 : 0, flavour);
		check(flen >= 32);
		/* the part of the frame a single-bit flip is certain to break: everything except the epilogue's
		 * late_status high nibble and its unused slots */
		flip_ok_lo = 0;
		flip_ok_hi = nseg > 1u ? flen - 13u + 1u + 4u * (nseg - 1u) : flen;
		wire = (uint8_t *)malloc(WRI_M2_BANNER_LEN + flen);
		check(wire != NULL);
		memcpy(wire, banner, WRI_M2_BANNER_LEN);
		memcpy(wire + WRI_M2_BANNER_LEN, wirebuf, flen);
		if (do_flip) {
			flip = (rest > 3 ? (size_t)fuzz[2] | ((size_t)fuzz[3] << 8) : 0u) % (flip_ok_hi - flip_ok_lo) + flip_ok_lo;
			if (nseg > 1u && flip >= flen - 13u && flip < flen - 12u)
				flip = 0; /* late_status itself: only its low nibble counts, skip */
			wire[WRI_M2_BANNER_LEN + flip] ^= (uint8_t)(1u << (rest > 4 ? fuzz[4] & 7u : 0u));
		}
		run_init(&r, (mode >> 4) & 3u, 4u * 2048u + 16u, 4u * 2048u + 16u, WRI_M2_BANNER_LEN + flen, 1,
			 flags >> 4, seed);
		r.expect_content = !do_flip;
		feed(&r, wire, WRI_M2_BANNER_LEN + flen, style);
		if (!do_flip) {
			check(r.errors == 0 && r.frames == 1);
			check(r.logged_len == WRI_M2_BANNER_LEN + flen); /* exactly the stream, byte for byte */
			check(r.last_tag == tag && r.last_nseg == nseg);
		} else {
			check(r.frames == 0 && r.errors == 1); /* every flipped bit is caught by one of the CRCs */
		}
		run_free(&r);
		free(wire);
		return 0;
	}

	/* started in a state: a valid prefix, then the fuzz bytes */
	{
		static uint8_t wirebuf[FRAME_MAX];
		static const uint8_t pat[1] = {0x5A};

		memset(wirebuf, 0, sizeof(wirebuf));
		flen = build(wirebuf, WRI_M2_TAG_MESSAGE, nseg, len, pat, 1, 0);
		switch (state) {
		case 0:
			cut = 0;
			banner_len = 0;
			break;
		case 1:
			cut = 0;
			banner_len = WRI_M2_BANNER_HEAD;
			break;
		case 2:
			cut = 0;
			break;
		case 3:
			cut = WRI_M2_PREAMBLE_LEN;
			break;
		case 4:
			cut = WRI_M2_PREAMBLE_LEN + (len[0] ? len[0] + WRI_M2_CRC_LEN : 0u);
			break;
		default:
			cut = nseg > 1u ? flen - WRI_M2_EPILOGUE_LEN : flen;
			break;
		}
		check(cut <= flen);
		total = banner_len + cut + rest;
		wire = (uint8_t *)malloc(total + 1);
		check(wire != NULL);
		memcpy(wire, banner, banner_len);
		memcpy(wire + banner_len, wirebuf, cut);
		memcpy(wire + banner_len + cut, fuzz, rest);
		run_init(&r, (mode >> 4) & 3u, seg0_cap, seg_cap_max, total, (mode >> 3) & 1u, flags >> 4, seed);
		feed(&r, wire, total, style);
		/* an event sequence that ends mid-frame is fine; what was consumed is a prefix of the input */
		check(r.logged_len <= r.fed_len);
		run_free(&r);
		free(wire);
	}
	return 0;
}
