/* SPDX-License-Identifier: MIT */
/*
 * Unit test of the msgr2.1 receive parser and the transmit queue (core/src/msgr2/wri_m2_frame.h):
 * feeding granularity (byte at a time, random splits, one piece, tiny and large rings) must not
 * change the events, direct-to-sink windows must land data in place, a work budget must resume
 * exactly where it stopped and account every byte once, sinks default to discard, the transcript
 * callback sees every raw byte in wire order, and the queue's peek / consume / partial / reset /
 * busy rules.
 */
#include "wrt.h"

#include "wri_crc32c.h"
#include "wri_le.h"
#include "wri_m2_frame.h"

#define BIG 80000u
#define SEG0_CAP 4096u
#define SEG_MAX 100000u

/* ---- a deterministic stream of frames ------------------------------------------------------ */

static uint32_t g_rng = 12345;

static uint32_t rnd(void)
{
	g_rng ^= g_rng << 13;
	g_rng ^= g_rng >> 17;
	g_rng ^= g_rng << 5;
	return g_rng;
}

static uint8_t g_data[BIG + 1024];
static uint8_t g_stream[400000];
static size_t g_stream_len;
static uint8_t g_enc[300000];

static void put_frame(uint8_t tag, unsigned nseg, uint32_t l0, uint32_t l1, uint32_t l2, uint32_t l3, int late)
{
	wri_m2_txq q;
	wri_m2_seg_src s[4];
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, start = g_stream_len;

	s[0].p = g_data;
	s[1].p = g_data + 300;
	s[2].p = g_data + 600;
	s[3].p = g_data + 900;
	s[0].len = l0;
	s[1].len = l1;
	s[2].len = l2;
	s[3].len = l3;
	for (i = 0; i < 4; i++)
		s[i].ref = 0;
	wri_m2_txq_init(&q, g_enc, sizeof(g_enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, tag, s, nseg, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		memcpy(g_stream + g_stream_len, iov[i].base, iov[i].len);
		g_stream_len += iov[i].len;
	}
	if (late >= 0)
		g_stream[g_stream_len - 13] = (uint8_t)late;
	(void)start;
}

static void build_stream(void)
{
	size_t i;
	uint8_t b[WRI_M2_BANNER_LEN];

	for (i = 0; i < sizeof(g_data); i++)
		g_data[i] = (uint8_t)(rnd() >> 11);
	wri_m2_banner_build(b);
	wri_le64_put(b + 10, 3); /* what a stock daemon sends */
	memcpy(g_stream, b, sizeof(b));
	g_stream_len = sizeof(b);
	put_frame(WRI_M2_TAG_HELLO, 1, 36, 0, 0, 0, -1);
	put_frame(WRI_M2_TAG_WAIT, 1, 0, 0, 0, 0, -1);                     /* empty frame: preamble only */
	put_frame(WRI_M2_TAG_MESSAGE, 2, 41, 5000, 0, 0, -1);
	put_frame(WRI_M2_TAG_MESSAGE, 4, 41, 3000, 0, 20000, -1);           /* empty middle segment */
	put_frame(WRI_M2_TAG_KEEPALIVE2, 1, 8, 0, 0, 0, -1);
	put_frame(WRI_M2_TAG_MESSAGE, 2, 0, 100, 0, 0, -1);                 /* empty segment 0: no inline CRC */
	put_frame(WRI_M2_TAG_MESSAGE, 2, 41, 100, 0, 0, 0x01);              /* aborted by the sender */
	put_frame(WRI_M2_TAG_MESSAGE, 4, 41, 200, 100, 70000, -1);          /* a large data segment */
	put_frame(WRI_M2_TAG_MESSAGE, 3, 41, 1, 1, 0, -1);
	put_frame(WRI_M2_TAG_ACK, 1, 8, 0, 0, 0, -1);
}

/* ---- driver and recorder ------------------------------------------------------------------- */

typedef struct rec {
	uint32_t w[4096];
	size_t n;
} rec;

static void rec_add(rec *r, uint32_t v)
{
	if (r->n < sizeof(r->w) / sizeof(r->w[0]))
		r->w[r->n++] = v;
}

static uint32_t fnv(const uint8_t *p, size_t n)
{
	uint32_t h = 2166136261u;
	size_t i;

	for (i = 0; i < n; i++)
		h = (h ^ p[i]) * 16777619u;
	return h;
}

typedef struct logbuf {
	uint8_t *p;
	size_t n, cap;
} logbuf;

static void log_cb(void *log, const uint8_t *p, size_t n)
{
	logbuf *l = (logbuf *)log;

	if (l->n + n <= l->cap)
		memcpy(l->p + l->n, p, n);
	l->n += n;
}

enum { SINK_NONE = 0, SINK_STATIC = 1, SINK_EXACT = 2 };
enum { CHUNK_ONE = 0, CHUNK_RANDOM = 1, CHUNK_ALL = 2 };

typedef struct opts {
	uint32_t ring_cap;
	int chunk;
	int sinks;
	uint32_t budget; /* per step call; 0 = unlimited */
	uint32_t seed;
} opts;

typedef struct result {
	rec r;
	size_t consumed;      /* bytes of the stream committed */
	uint64_t spent;       /* budget spent in total (only counted when a budget is set) */
	unsigned direct_wins; /* windows handed out that pointed into a sink */
	size_t log_n;
	int log_ok;
	int errored;
	unsigned frames, aborted;
} result;

static uint8_t g_sink[3][BIG];

static void drive(const uint8_t *data, size_t len, const opts *o, result *res)
{
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t *ringbuf = (uint8_t *)malloc(o->ring_cap);
	uint8_t *seg0 = (uint8_t *)malloc(SEG0_CAP);
	uint8_t *exact[3] = {NULL, NULL, NULL};
	logbuf lb;
	size_t pos = 0, guard = 0;
	int done = 0;
	unsigned i;

	memset(res, 0, sizeof(*res));
	lb.p = (uint8_t *)malloc(len + 1);
	lb.n = 0;
	lb.cap = len;
	g_rng = o->seed ? o->seed : 1;
	wri_ring_init(&ring, ringbuf, o->ring_cap);
	wri_m2_rx_init(&rx, seg0, SEG0_CAP, SEG_MAX);

	while (!done && guard++ < 4 * len + 1000) {
		uint8_t *w = NULL;
		size_t room = wri_m2_rx_window(&rx, &ring, &w);
		wri_m2_rx_ev ev;

		if (room != 0 && pos < len) {
			size_t want = o->chunk == CHUNK_ONE ? 1 : o->chunk == CHUNK_RANDOM ? 1 + rnd() % 97 : len;
			size_t k = want < room ? want : room;

			if (k > len - pos)
				k = len - pos;
			for (i = 0; i < 3; i++) {
				if ((uintptr_t)w >= (uintptr_t)g_sink[i] && (uintptr_t)w < (uintptr_t)g_sink[i] + BIG)
					res->direct_wins++;
				if (exact[i] != NULL && (uintptr_t)w >= (uintptr_t)exact[i] &&
				    (uintptr_t)w < (uintptr_t)exact[i] + rx.desc.len[i + 1])
					res->direct_wins++;
			}
			memcpy(w, data + pos, k);
			wri_m2_rx_commit(&rx, &ring, k);
			pos += k;
		}
		for (;;) {
			uint32_t budget = o->budget ? o->budget : 0x40000000u, before = budget;

			ev = wri_m2_rx_step(&rx, &ring, NULL, &budget, log_cb, &lb);
			if (o->budget)
				res->spent += before - budget;
			else
				res->spent += before - budget;
			if (ev == WRI_RXE_NONE) {
				if (o->budget && budget == 0)
					continue; /* out of budget, not out of input: call again */
				break;
			}
			if (ev == WRI_RXE_BANNER) {
				rec_add(&res->r, 1);
				rec_add(&res->r, (uint32_t)wri_m2_rx_banner(&rx)->supported);
				rec_add(&res->r, (uint32_t)wri_m2_rx_banner(&rx)->required);
			} else if (ev == WRI_RXE_SEG0) {
				rec_add(&res->r, 2);
				rec_add(&res->r, rx.desc.tag);
				rec_add(&res->r, rx.desc.nseg);
				for (i = 0; i < 4; i++)
					rec_add(&res->r, rx.desc.len[i]);
				rec_add(&res->r, fnv(seg0, rx.desc.len[0]));
				for (i = 1; i < rx.desc.nseg && i < 4; i++) {
					if (o->sinks == SINK_STATIC)
						wri_m2_rx_sink(&rx, i, g_sink[i - 1], BIG);
					else if (o->sinks == SINK_EXACT) {
						exact[i - 1] = (uint8_t *)malloc(rx.desc.len[i] ? rx.desc.len[i] : 1);
						wri_m2_rx_sink(&rx, i, exact[i - 1], rx.desc.len[i]);
					}
				}
			} else if (ev == WRI_RXE_FRAME) {
				rec_add(&res->r, 3);
				for (i = 1; i < 4; i++) {
					const uint8_t *src = o->sinks == SINK_STATIC ? g_sink[i - 1] : exact[i - 1];

					rec_add(&res->r, rx.stored[i]);
					rec_add(&res->r, src != NULL && i < rx.desc.nseg ? fnv(src, rx.stored[i]) : 0);
				}
				res->frames++;
				wri_m2_rx_next_frame(&rx);
				for (i = 0; i < 3; i++) {
					free(exact[i]);
					exact[i] = NULL;
				}
			} else if (ev == WRI_RXE_ABORTED) {
				rec_add(&res->r, 4);
				res->aborted++;
				wri_m2_rx_next_frame(&rx);
				for (i = 0; i < 3; i++) {
					free(exact[i]);
					exact[i] = NULL;
				}
			} else {
				rec_add(&res->r, 5);
				rec_add(&res->r, (uint32_t)wri_m2_rx_error(&rx)->status);
				res->errored = 1;
				done = 1;
				break;
			}
		}
		if (pos >= len && ring.len == 0 && rx.direct == 0)
			done = 1;
	}
	for (i = 0; i < 3; i++)
		free(exact[i]);
	res->consumed = pos;
	res->log_n = lb.n;
	res->log_ok = lb.n <= len && memcmp(lb.p, data, lb.n) == 0;
	free(lb.p);
	free(ringbuf);
	free(seg0);
}

static int same(const result *a, const result *b)
{
	return a->r.n == b->r.n && memcmp(a->r.w, b->r.w, a->r.n * sizeof(a->r.w[0])) == 0;
}

static result g_ref, g_cur;

static void test_equivalence(void)
{
	static const uint32_t rings[] = {1, 7, 33, 64, 1000, 65536};
	static const int sinks[] = {SINK_NONE, SINK_STATIC, SINK_EXACT};
	size_t ri, si;
	int ci;
	opts o;

	/* reference: everything in one piece, big ring */
	o.ring_cap = 400000;
	o.chunk = CHUNK_ALL;
	o.sinks = SINK_STATIC;
	o.budget = 0;
	o.seed = 1;
	drive(g_stream, g_stream_len, &o, &g_ref);
	WRT_CHECK_U64(g_ref.errored, 0);
	WRT_CHECK_U64(g_ref.frames, 9);   /* 10 frames, one of them aborted by its sender */
	WRT_CHECK_U64(g_ref.aborted, 1);
	WRT_CHECK(g_ref.log_ok);
	WRT_CHECK_U64(g_ref.log_n, g_stream_len); /* the transcript is the whole stream, byte for byte */
	WRT_CHECK_U64(g_ref.spent, g_stream_len); /* and every byte cost budget exactly once */

	for (si = 0; si < sizeof(sinks) / sizeof(sinks[0]); si++) {
		result nosink;

		for (ri = 0; ri < sizeof(rings) / sizeof(rings[0]); ri++) {
			for (ci = 0; ci < 3; ci++) {
				unsigned seed;

				if (ci == CHUNK_ONE && rings[ri] > 64)
					continue; /* byte at a time only needs the small rings */
				for (seed = 1; seed <= (ci == CHUNK_RANDOM ? 4u : 1u); seed++) {
					o.ring_cap = rings[ri];
					o.chunk = ci;
					o.sinks = sinks[si];
					o.budget = 0;
					o.seed = seed;
					drive(g_stream, g_stream_len, &o, &g_cur);
					WRT_CHECK_U64(g_cur.errored, 0);
					WRT_CHECK_U64(g_cur.frames, g_ref.frames);
					WRT_CHECK_U64(g_cur.aborted, 1);
					WRT_CHECK(g_cur.log_ok);
					WRT_CHECK_U64(g_cur.log_n, g_stream_len);
					WRT_CHECK_U64(g_cur.spent, g_stream_len);
					if (sinks[si] == SINK_STATIC || sinks[si] == SINK_EXACT) {
						/* with sinks the full record (event order, descriptors, stored, data hashes) matches */
						if (!same(&g_ref, &g_cur))
							fprintf(stderr, "records differ: ring %u chunk %d sinks %d seed %u\n",
								(unsigned)rings[ri], ci, sinks[si], seed);
						WRT_CHECK(same(&g_ref, &g_cur));
					} else {
						/* without sinks: same events and descriptors, nothing stored, hashes of nothing */
						nosink = g_cur;
						WRT_CHECK_U64(nosink.frames, g_ref.frames);
					}
				}
			}
		}
	}
}

/* Direct windows: data lands in the sink in place; without a sink the window is the ring. */
static void test_direct(void)
{
	opts o;

	o.ring_cap = 256;
	o.chunk = CHUNK_ALL;
	o.sinks = SINK_STATIC;
	o.budget = 0;
	o.seed = 3;
	drive(g_stream, g_stream_len, &o, &g_cur);
	WRT_CHECK_U64(g_cur.errored, 0);
	WRT_CHECK(g_cur.direct_wins > 0);
	WRT_CHECK(same(&g_ref, &g_cur));
	o.sinks = SINK_EXACT;
	drive(g_stream, g_stream_len, &o, &g_cur);
	WRT_CHECK(g_cur.direct_wins > 0);
	WRT_CHECK(same(&g_ref, &g_cur));
	o.sinks = SINK_NONE;
	drive(g_stream, g_stream_len, &o, &g_cur);
	WRT_CHECK_U64(g_cur.direct_wins, 0);
	WRT_CHECK_U64(g_cur.frames, g_ref.frames);
	/* a big ring that is non-empty blocks direct mode, a small segment never goes direct */
	{
		wri_m2_rx rx;
		wri_ring ring;
		uint8_t rb[64], s0[64];
		static uint8_t sink[4096];
		uint8_t *w;
		uint8_t f[SEG0_CAP];
		wri_m2_seg_src s[2];
		wri_m2_txq q;
		wr_iov iov[WRI_M2_TXQ_IOV];
		size_t n, off = 0, i, k, done = 0;
		uint8_t b[WRI_M2_BANNER_LEN];

		wri_ring_init(&ring, rb, sizeof(rb));
		wri_m2_rx_init(&rx, s0, sizeof(s0), SEG_MAX);
		wri_m2_banner_build(b);
		k = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(k > 0 && k <= sizeof(rb));
		memcpy(w, b, sizeof(b));
		wri_m2_rx_commit(&rx, &ring, sizeof(b));
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_BANNER);
		/* one 4000 byte segment 1, with a sink: the window after SEG0 is the sink itself */
		s[0].p = g_data;
		s[0].len = 41;
		s[0].ref = 0;
		s[1].p = g_data + 100;
		s[1].len = 4000;
		s[1].ref = 0;
		wri_m2_txq_init(&q, g_enc, sizeof(g_enc));
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, 17, s, 2, NULL, NULL));
		n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
		for (i = 0; i < n; i++) {
			memcpy(f + off, iov[i].base, iov[i].len);
			off += iov[i].len;
		}
		/* preamble + segment 0 + its CRC (77 bytes) through the ring */
		k = 77;
		while (k > 0) { /* done = bytes of f fed so far */
			size_t room = wri_m2_rx_window(&rx, &ring, &w), c = k < room ? k : room;

			memcpy(w, f + done, c);
			wri_m2_rx_commit(&rx, &ring, c);
			done += c;
			k -= c;
			if (wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL) == WRI_RXE_SEG0)
				break;
		}
		WRT_CHECK_U64(rx.pending_ev, WRI_RXE_SEG0);
		wri_m2_rx_sink(&rx, 1, sink, sizeof(sink));
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_NONE);
		WRT_CHECK_U64(ring.len, 0);
		k = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(w == sink);        /* straight into the sink */
		WRT_CHECK_U64(k, 4000);      /* up to the end of the segment, not into the epilogue */
		memcpy(w, f + 77, 1000);
		wri_m2_rx_commit(&rx, &ring, 1000);
		k = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(w == sink + 1000);
		WRT_CHECK_U64(k, 3000);
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_NONE);
		WRT_CHECK_U64(rx.stored[1], 1000);
		WRT_CHECK_U64(rx.direct, 0);
		k = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(w == sink + 1000);
		memcpy(w, f + 77 + 1000, 2900);
		wri_m2_rx_commit(&rx, &ring, 2900);
		/* the step settles the direct bytes; only 100 of the segment are left, below the direct
		 * threshold, so the ring takes them (and the epilogue) from here */
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_NONE);
		WRT_CHECK_U64(rx.stored[1], 3900);
		k = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(w >= rb && w < rb + sizeof(rb));
		for (i = 0, off = 77 + 3900; i < 10 && off < 77 + 4013; i++) { /* the last 100 bytes and the epilogue, 64 at a time */
			k = wri_m2_rx_window(&rx, &ring, &w);
			k = k < 77 + 4013 - off ? k : 77 + 4013 - off;
			memcpy(w, f + off, k);
			wri_m2_rx_commit(&rx, &ring, k);
			off += k;
			if (wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL) == WRI_RXE_FRAME)
				break;
		}
		WRT_CHECK_U64(rx.pending_ev, WRI_RXE_FRAME);
		WRT_CHECK_MEM(sink, g_data + 100, 4000);
	}
}

/* Budget: tiny budgets resume exactly, every byte is accounted once, zero budget makes no progress. */
static void test_budget(void)
{
	static const uint32_t budgets[] = {1, 2, 3, 7, 32, 100, 1000, 100000};
	size_t i;
	opts o;

	for (i = 0; i < sizeof(budgets) / sizeof(budgets[0]); i++) {
		unsigned sk;

		for (sk = 0; sk < 3; sk++) {
			o.ring_cap = i % 2 ? 97 : 65536;
			o.chunk = CHUNK_ALL;
			o.sinks = (int)sk;
			o.budget = budgets[i];
			o.seed = 9;
			drive(g_stream, g_stream_len, &o, &g_cur);
			WRT_CHECK_U64(g_cur.errored, 0);
			WRT_CHECK_U64(g_cur.frames, g_ref.frames);
			WRT_CHECK_U64(g_cur.spent, g_stream_len);
			WRT_CHECK(g_cur.log_ok);
			WRT_CHECK_U64(g_cur.log_n, g_stream_len);
			if (sk != SINK_NONE)
				WRT_CHECK(same(&g_ref, &g_cur));
		}
	}
	/* budget 0: no byte is touched, no event that needs bytes is produced */
	{
		wri_m2_rx rx;
		wri_ring ring;
		uint8_t rb[256], s0[64];
		uint32_t budget = 0;
		uint8_t *w;
		size_t room;
		uint8_t b[WRI_M2_BANNER_LEN];

		wri_ring_init(&ring, rb, sizeof(rb));
		wri_m2_rx_init(&rx, s0, sizeof(s0), SEG_MAX);
		wri_m2_banner_build(b);
		room = wri_m2_rx_window(&rx, &ring, &w);
		WRT_CHECK(room >= sizeof(b));
		memcpy(w, b, sizeof(b));
		wri_m2_rx_commit(&rx, &ring, sizeof(b));
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, &budget, NULL, NULL), WRI_RXE_NONE);
		WRT_CHECK_U64(ring.len, sizeof(b));
		budget = 10;
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, &budget, NULL, NULL), WRI_RXE_NONE);
		WRT_CHECK_U64(budget, 0);
		WRT_CHECK_U64(ring.len, sizeof(b) - 10);
		budget = 100;
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, &budget, NULL, NULL), WRI_RXE_BANNER);
		WRT_CHECK_U64(budget, 100 - 16);
		WRT_CHECK_U64(ring.len, 0);
	}
}

/* Events are sticky where they must be, sinks only count between SEG0 and the next step. */
static void test_event_rules(void)
{
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t rb[512], s0[64];
	static uint8_t sink[100];
	uint8_t *w;
	size_t room, off = 0;
	wri_m2_txq q;
	wri_m2_seg_src s[2];
	wr_iov iov[WRI_M2_TXQ_IOV];
	uint8_t f[300];
	size_t i, n;

	wri_ring_init(&ring, rb, sizeof(rb));
	wri_m2_rx_init(&rx, s0, sizeof(s0), SEG_MAX);
	s[0].p = g_data;
	s[0].len = 20;
	s[0].ref = 0;
	s[1].p = g_data + 50;
	s[1].len = 30;
	s[1].ref = 0;
	wri_m2_txq_init(&q, g_enc, sizeof(g_enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, 17, s, 2, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		memcpy(f + off, iov[i].base, iov[i].len);
		off += iov[i].len;
	}
	{
		uint8_t b[WRI_M2_BANNER_LEN];

		wri_m2_banner_build(b);
		room = wri_m2_rx_window(&rx, &ring, &w);
		memcpy(w, b, sizeof(b));
		wri_m2_rx_commit(&rx, &ring, sizeof(b));
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_BANNER);
		(void)room;
	}
	wri_m2_rx_sink(&rx, 1, sink, sizeof(sink)); /* too early: ignored */
	WRT_CHECK(rx.sink[1].dst == NULL);
	room = wri_m2_rx_window(&rx, &ring, &w);
	memcpy(w, f, off);
	wri_m2_rx_commit(&rx, &ring, off);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_SEG0);
	wri_m2_rx_sink(&rx, 0, sink, 10); /* segment 0 is not selectable */
	WRT_CHECK(rx.sink[0].dst == s0);
	wri_m2_rx_sink(&rx, 4, sink, 10); /* out of range */
	wri_m2_rx_sink(&rx, 1, sink, sizeof(sink));
	WRT_CHECK(rx.sink[1].dst == sink);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
	wri_m2_rx_sink(&rx, 2, sink, 5); /* late: ignored */
	WRT_CHECK(rx.sink[2].dst == NULL);
	/* FRAME is sticky until released */
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
	WRT_CHECK_MEM(s0, g_data, 20);
	WRT_CHECK_MEM(sink, g_data + 50, 30);
	WRT_CHECK_U64(rx.stored[1], 30);
	/* bytes of the next frame may already be committed while the event is pending: they wait */
	room = wri_m2_rx_window(&rx, &ring, &w);
	WRT_CHECK(room > 0);
	memcpy(w, f, 32);
	wri_m2_rx_commit(&rx, &ring, 32);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
	WRT_CHECK_U64(ring.len, 32);
	wri_m2_rx_next_frame(&rx);
	WRT_CHECK(rx.sink[1].dst == NULL); /* sinks are cleared for the next frame */
	WRT_CHECK_U64(rx.stored[1], 0);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_NONE);
	/* next_frame at any other time does nothing */
	wri_m2_rx_next_frame(&rx);
	WRT_CHECK_U64(rx.state, WRI_RX_SEG0);
	/* sinks default to discard: nothing is written anywhere, stored stays 0, the CRC is still checked */
	memset(sink, 0xEE, sizeof(sink));
	room = wri_m2_rx_window(&rx, &ring, &w);
	memcpy(w, f + 32, off - 32);
	wri_m2_rx_commit(&rx, &ring, off - 32);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_SEG0);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
	WRT_CHECK_U64(rx.stored[1], 0);
	WRT_CHECK_U64(sink[0], 0xEE);
}

/* ---- transmit queue ------------------------------------------------------------------------ */

static size_t drain(wri_m2_txq *q, uint8_t *out, size_t cap)
{
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n = wri_m2_txq_peek(q, iov, WRI_M2_TXQ_IOV), i, total = 0;

	for (i = 0; i < n; i++) {
		if (total + iov[i].len > cap)
			return 0;
		memcpy(out + total, iov[i].base, iov[i].len);
		total += iov[i].len;
	}
	return total;
}

static void test_txq(void)
{
	static uint8_t enc[64 * 1024], flat[64 * 1024], one[4096];
	wri_m2_txq q;
	wr_iov iov[WRI_M2_TXQ_IOV];
	wri_m2_seg_src s[4];
	logbuf lb;
	uint8_t ban[WRI_M2_BANNER_LEN];
	size_t n, i;

	wri_m2_banner_build(ban);
	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK(wri_m2_txq_idle(&q));
	WRT_CHECK_U64(wri_m2_txq_peek(&q, iov, 8), 0);

	/* banner, partial consume */
	lb.p = flat;
	lb.n = 0;
	lb.cap = sizeof(flat);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, log_cb, &lb));
	WRT_CHECK(!wri_m2_txq_idle(&q));
	WRT_CHECK_U64(q.pending, 26);
	WRT_CHECK_U64(lb.n, 26);
	WRT_CHECK_MEM(flat, ban, 26);
	n = wri_m2_txq_peek(&q, iov, 8);
	WRT_CHECK_U64(n, 1);
	WRT_CHECK_U64(iov[0].len, 26);
	WRT_CHECK_MEM(iov[0].base, ban, 26);
	wri_m2_txq_consume(&q, 10);
	n = wri_m2_txq_peek(&q, iov, 8);
	WRT_CHECK_U64(n, 1);
	WRT_CHECK_U64(iov[0].len, 16);
	WRT_CHECK_MEM(iov[0].base, ban + 10, 16);
	WRT_CHECK_U64(q.pending, 16);
	wri_m2_txq_consume(&q, 1000); /* more than pending: clamped, queue empty */
	WRT_CHECK(wri_m2_txq_idle(&q));
	WRT_CHECK_U64(q.used, 0);
	WRT_CHECK_U64(q.niov, 0);
	WRT_CHECK_U64(wri_m2_txq_peek(&q, iov, 8), 0);
	wri_m2_txq_consume(&q, 5); /* nothing queued: harmless */
	WRT_CHECK(wri_m2_txq_idle(&q));

	/* several copied frames share one gather entry; the bytes are the frames back to back */
	{
		static uint8_t want[8192];
		size_t wl = 0;

		for (i = 0; i < 4; i++) {
			wri_m2_txq q2;

			s[0].p = g_data + i;
			s[0].len = 36 + (uint32_t)i;
			s[0].ref = 0;
			s[1].p = g_data + 77;
			s[1].len = 10 * (uint32_t)i + 1;
			s[1].ref = 0;
			WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 2, NULL, NULL));
			wri_m2_txq_init(&q2, one, sizeof(one));
			WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q2, NULL, WRI_M2_TAG_MESSAGE, s, 2, NULL, NULL));
			wl += drain(&q2, want + wl, sizeof(want) - wl);
		}
		WRT_CHECK_U64(q.niov, 1);
		WRT_CHECK_U64(q.pending, wl);
		n = drain(&q, flat, sizeof(flat));
		WRT_CHECK_U64(n, wl);
		WRT_CHECK_MEM(flat, want, wl);
		/* partial consume byte by byte keeps the stream intact */
		{
			size_t got = 0;

			while (!wri_m2_txq_idle(&q)) {
				n = wri_m2_txq_peek(&q, iov, 8);
				WRT_CHECK(n >= 1);
				if (n == 0)
					break;
				WRT_CHECK(memcmp(iov[0].base, want + got, 1) == 0);
				wri_m2_txq_consume(&q, 1);
				got++;
			}
			WRT_CHECK_U64(got, wl);
		}
	}

	/* referenced segments: data is not copied into the encode buffer; segment 3 is always referenced */
	{
		static uint8_t data[3000];
		size_t before;
		uint8_t want[4096];

		for (i = 0; i < sizeof(data); i++)
			data[i] = (uint8_t)i;
		wri_m2_txq_reset(&q);
		s[0].p = g_data;
		s[0].len = 41;
		s[0].ref = 0;
		s[1].p = g_data + 50;
		s[1].len = 100;
		s[1].ref = 0;
		s[2].p = g_data + 70;
		s[2].len = 0;
		s[2].ref = 0;
		s[3].p = data;
		s[3].len = 3000;
		s[3].ref = 0; /* segment 3 is referenced whatever ref says */
		lb.n = 0;
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 4, log_cb, &lb));
		WRT_CHECK_U64(q.pending, 32 + 41 + 4 + 100 + 3000 + 13);
		WRT_CHECK(q.used < 300); /* the 3000 bytes are not in the encode buffer */
		before = q.used;
		n = wri_m2_txq_peek(&q, iov, 8);
		WRT_CHECK_U64(n, 3); /* head, data, epilogue */
		WRT_CHECK(iov[1].base == data);
		WRT_CHECK_U64(iov[1].len, 3000);
		WRT_CHECK_U64(lb.n, q.pending); /* the transcript saw all of it, in wire order */
		WRT_CHECK_U64(drain(&q, want, sizeof(want)), q.pending);
		WRT_CHECK_MEM(want, lb.p, lb.n);
		/* consume into the middle of the referenced data */
		wri_m2_txq_consume(&q, iov[0].len + 1000);
		n = wri_m2_txq_peek(&q, iov, 8);
		WRT_CHECK_U64(n, 2);
		WRT_CHECK(iov[0].base == data + 1000);
		WRT_CHECK_U64(iov[0].len, 2000);
		wri_m2_txq_consume(&q, 2000 + 5);
		n = wri_m2_txq_peek(&q, iov, 8);
		WRT_CHECK_U64(n, 1);
		WRT_CHECK_U64(iov[0].len, 8);
		WRT_CHECK_U64(q.pending, 8);
		wri_m2_txq_consume(&q, 8);
		WRT_CHECK(wri_m2_txq_idle(&q));
		WRT_CHECK_U64(q.used, 0);
		(void)before;

		/* explicit ref on segments 0..2 */
		s[0].ref = s[1].ref = 1;
		lb.n = 0;
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 4, log_cb, &lb));
		n = wri_m2_txq_peek(&q, iov, 8);
		WRT_CHECK_U64(n, 6); /* preamble, seg0, crc0, seg1, seg3, epilogue */
		WRT_CHECK(iov[1].base == g_data);
		WRT_CHECK(iov[3].base == g_data + 50);
		WRT_CHECK(iov[4].base == data);
		WRT_CHECK_U64(lb.n, q.pending);
		n = drain(&q, want, sizeof(want));
		WRT_CHECK_U64(n, lb.n);
		WRT_CHECK_MEM(want, lb.p, lb.n);
		/* peek with a smaller array returns that many */
		WRT_CHECK_U64(wri_m2_txq_peek(&q, iov, 2), 2);
		WRT_CHECK_U64(wri_m2_txq_peek(&q, iov, 0), 0);
	}

	/* the gather list is bounded: a fourth referenced-data frame is BUSY, the queue is untouched */
	{
		static uint8_t data[100];
		uint64_t pend;
		uint32_t used, niov;

		wri_m2_txq_reset(&q);
		s[0].ref = s[1].ref = 0;
		s[3].p = data;
		s[3].len = sizeof(data);
		for (i = 0; i < 3; i++)
			WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 4, NULL, NULL));
		pend = q.pending;
		used = q.used;
		niov = q.niov;
		WRT_CHECK_U64(niov, 7);
		lb.n = 0;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 4, log_cb, &lb));
		WRT_CHECK_U64(lb.n, 0); /* a refused frame reports nothing */
		WRT_CHECK_U64(q.pending, pend);
		WRT_CHECK_U64(q.used, used);
		WRT_CHECK_U64(q.niov, niov);
		WRT_CHECK_U64(q.err, WR_OK); /* BUSY is not a failure */
		/* a plain control frame still fits (it merges into the last run) */
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_KEEPALIVE2, s, 1, NULL, NULL));
		/* drain the first entry and the busy condition clears */
		n = wri_m2_txq_peek(&q, iov, 8);
		wri_m2_txq_consume(&q, iov[0].len);
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_MESSAGE, s, 4, NULL, NULL));
	}

	/* encode buffer full: BUSY while something is queued, TOOBIG when it could never fit */
	{
		static uint8_t small[100];
		uint8_t d2[200];

		wri_m2_txq_init(&q, small, sizeof(small));
		memset(d2, 1, sizeof(d2));
		s[0].p = d2;
		s[0].len = 36; /* 32 + 36 + 4 = 72 bytes */
		s[0].ref = 0;
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
		WRT_CHECK_U64(q.pending, 72);
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
		WRT_CHECK_U64(q.pending, 72);
		WRT_CHECK_U64(q.err, WR_OK);
		wri_m2_txq_consume(&q, 71); /* not yet drained: space is not reclaimed piecemeal */
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
		wri_m2_txq_consume(&q, 1);
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
		wri_m2_txq_reset(&q);
		s[0].len = 100; /* 32 + 100 + 4 > 100 */
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
		WRT_CHECK_U64(q.err, WR_E_TOOBIG);
		WRT_CHECK(wri_m2_txq_idle(&q));
		/* the banner needs 26 bytes */
		wri_m2_txq_init(&q, small, 25);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_banner(&q, NULL, NULL));
		wri_m2_txq_init(&q, NULL, 0);
		WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_banner(&q, NULL, NULL));
		wri_m2_txq_init(&q, small, sizeof(small));
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, NULL, NULL));
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, NULL, NULL));
		WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, NULL, NULL));
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_banner(&q, NULL, NULL));
		WRT_CHECK_U64(q.pending, 78);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_banner(NULL, NULL, NULL));
	}

	/* reset drops everything and clears the error */
	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, NULL, NULL));
	q.err = WR_E_TOOBIG;
	wri_m2_txq_reset(&q);
	WRT_CHECK(wri_m2_txq_idle(&q));
	WRT_CHECK_U64(q.used, 0);
	WRT_CHECK_U64(q.niov, 0);
	WRT_CHECK_U64(q.err, WR_OK);
	WRT_CHECK_U64(wri_m2_txq_peek(&q, iov, 8), 0);
}

/* What the builder writes is what the parser reads, with random shapes and referenced data. */
static void test_roundtrip(void)
{
	static uint8_t enc[8192];
	static uint8_t wire[400000];
	static uint8_t refd[3][2000];
	wri_m2_txq q;
	size_t wl = 0, iter, i;
	uint32_t shapes[40][5];
	wr_iov iov[WRI_M2_TXQ_IOV];
	opts o;
	logbuf lb;
	uint8_t ban[WRI_M2_BANNER_LEN];

	g_rng = 777;
	wri_m2_txq_init(&q, enc, sizeof(enc));
	lb.p = wire;
	lb.cap = sizeof(wire);
	lb.n = 0;
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, log_cb, &lb));
	wri_m2_banner_build(ban);
	for (iter = 0; iter < 40; iter++) {
		wri_m2_seg_src s[4];
		unsigned nseg = 1 + rnd() % 4;

		shapes[iter][0] = nseg;
		for (i = 0; i < 4; i++) {
			uint32_t len = i < nseg ? rnd() % 1500 : 0;

			if (i == nseg - 1 && nseg > 1 && len == 0)
				len = 1 + rnd() % 100;
			if (i == 0 && rnd() % 5 == 0 && nseg == 1)
				len = 0;
			s[i].len = len;
			s[i].p = i == 0 ? g_data + rnd() % 100 : i == 1 ? g_data + 5000 : i == 2 ? g_data + 9000 : refd[0];
			s[i].ref = (uint8_t)(rnd() % 2);
			shapes[iter][1 + i] = len;
		}
		for (i = 0; i < sizeof(refd[0]); i++)
			refd[0][i] = (uint8_t)(i * 7 + iter);
		/* the queue is drained into `wire` before the next frame so referenced memory may change */
		{
			wr_status st = wri_m2_tx_frame(&q, NULL, (uint8_t)(1 + rnd() % 22), s, nseg, log_cb, &lb);

			WRT_CHECK_STATUS(WR_OK, st);
		}
		while (!wri_m2_txq_idle(&q)) {
			size_t k = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV), tot = 0, j;

			for (j = 0; j < k; j++)
				tot += iov[j].len;
			wri_m2_txq_consume(&q, tot);
		}
	}
	wl = lb.n;
	WRT_CHECK_U64(wl > 1000, 1);
	/* the transcript is a valid stream: parse it back in odd pieces, frames and boundaries intact */
	o.ring_cap = 997;
	o.chunk = CHUNK_RANDOM;
	o.sinks = SINK_EXACT;
	o.budget = 0;
	o.seed = 5;
	drive(wire, wl, &o, &g_cur);
	WRT_CHECK_U64(g_cur.errored, 0);
	WRT_CHECK_U64(g_cur.frames, 40);
	WRT_CHECK_U64(g_cur.log_n, wl);
	WRT_CHECK(g_cur.log_ok);
	WRT_CHECK_U64(g_cur.spent, wl);
	(void)shapes;
	(void)ban;
}

/* ---- queue against a model, CRC work on refusal, discarded segment 0 ----------------------- */

static uint64_t g_crc_calls;

static uint32_t counting_crc(void *ctx, uint32_t seed, const uint8_t *p, size_t n)
{
	(void)ctx;
	g_crc_calls++;
	return wri_crc32c(seed, p, n);
}

/* A frame that is refused (BUSY or TOOBIG) must not cost a CRC over its segments: a caller that
 * retries a multi-megabyte data segment on every pump round would otherwise hash it every time. */
static void test_refusal_costs_no_crc(void)
{
	static uint8_t small[100], data[5000];
	wr_prim_ops prim;
	wri_m2_txq q;
	wri_m2_seg_src s[4];
	unsigned i;

	memset(&prim, 0, sizeof(prim));
	prim.size = sizeof(prim);
	prim.crc32c = counting_crc;
	for (i = 0; i < 4; i++) {
		s[i].p = data;
		s[i].len = 40;
		s[i].ref = 0;
	}
	wri_m2_txq_init(&q, small, sizeof(small));
	g_crc_calls = 0;
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, &prim, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
	WRT_CHECK(g_crc_calls > 0); /* the hook is really in use */
	g_crc_calls = 0;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&q, &prim, WRI_M2_TAG_HELLO, s, 1, NULL, NULL));
	s[3].len = 5000; /* referenced data is not copied, but the copied parts alone do not fit either */
	s[0].len = 41;
	s[1].len = 40;
	s[2].len = 40;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_frame(&q, &prim, WRI_M2_TAG_MESSAGE, s, 4, NULL, NULL));
	wri_m2_txq_reset(&q);
	s[0].len = 300; /* copied segment 0 larger than the whole encode buffer */
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_m2_tx_frame(&q, &prim, WRI_M2_TAG_MESSAGE, s, 4, NULL, NULL));
	WRT_CHECK_U64(g_crc_calls, 0);
	/* argument errors are remembered like the other hard failures */
	wri_m2_txq_reset(&q);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_tx_frame(&q, &prim, 0, s, 1, NULL, NULL));
	WRT_CHECK_U64(q.err, WR_E_INVAL);
	WRT_CHECK_U64(g_crc_calls, 0);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, &prim, WRI_M2_TAG_WAIT, s + 1, 1, NULL, NULL)); /* never blocked */
}

/* Random appends interleaved with partial consumes of the gather list: the bytes that leave the
 * queue, in order, are exactly the bytes the builder reported through the transcript, and that
 * stream parses back into the frames that were appended. BUSY must leave the queue untouched. */
static void test_txq_model(void)
{
	static uint8_t enc[1500], model[300000], out[300000], refd[3][700];
	wri_m2_txq q;
	logbuf lb, ob;
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t iter, i, k, took, frames = 0, busy = 0;
	opts o;
	result res;

	g_rng = 4242;
	for (i = 0; i < sizeof(refd); i++)
		refd[i / 700][i % 700] = (uint8_t)(i * 13 + 5);
	wri_m2_txq_init(&q, enc, sizeof(enc));
	lb.p = model;
	lb.n = 0;
	lb.cap = sizeof(model);
	ob.p = out;
	ob.n = 0;
	ob.cap = sizeof(out);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_banner(&q, log_cb, &lb));
	for (iter = 0; iter < 3000; iter++) {
		if (rnd() % 2 != 0) {
			wri_m2_seg_src s[4];
			unsigned nseg = 1 + rnd() % 4;
			uint64_t pend = q.pending;
			uint32_t used = q.used, niov = q.niov;
			size_t before = lb.n;
			wr_status st;

			for (i = 0; i < 4; i++) {
				s[i].len = i < nseg ? rnd() % 300 : 0;
				if (i == nseg - 1u && nseg > 1u && s[i].len == 0)
					s[i].len = 1 + rnd() % 50;
				s[i].p = i == 0 ? g_data + rnd() % 64 : i == 3 ? refd[2] : refd[i - 1];
				s[i].ref = (uint8_t)(rnd() % 2);
			}
			st = wri_m2_tx_frame(&q, NULL, (uint8_t)(1 + rnd() % 22), s, nseg, log_cb, &lb);
			if (st == WR_OK) {
				frames++;
			} else {
				WRT_CHECK_STATUS(WR_E_BUSY, st); /* every shape fits an empty queue */
				WRT_CHECK_U64(q.pending, pend);
				WRT_CHECK_U64(q.used, used);
				WRT_CHECK_U64(q.niov, niov);
				WRT_CHECK_U64(lb.n, before); /* a refused frame reports nothing */
				busy++;
			}
		} else {
			size_t n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV), have = 0;

			for (i = 0; i < n; i++)
				have += iov[i].len;
			WRT_CHECK_U64(have, q.pending);
			took = have ? 1 + rnd() % (have > 1000 ? 1000 : have) : 0;
			/* the first `took` bytes of the gather list leave the queue */
			for (i = 0, k = took; i < n && k > 0; i++) {
				size_t c = iov[i].len < k ? iov[i].len : k;

				log_cb(&ob, iov[i].base, c);
				k -= c;
			}
			wri_m2_txq_consume(&q, took);
		}
	}
	while (!wri_m2_txq_idle(&q)) {
		size_t n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);

		for (i = 0; i < n; i++)
			log_cb(&ob, iov[i].base, iov[i].len);
		wri_m2_txq_consume(&q, q.pending);
	}
	if (frames <= 500 || busy <= 20)
		fprintf(stderr, "txq model: %zu frames, %zu refusals\n", frames, busy);
	WRT_CHECK(frames > 500 && busy > 20); /* both the success and the refusal paths ran */
	WRT_CHECK_U64(ob.n, lb.n);
	WRT_CHECK(ob.n <= sizeof(out) && lb.n <= sizeof(model));
	WRT_CHECK_MEM(out, model, lb.n);
	o.ring_cap = 613;
	o.chunk = CHUNK_RANDOM;
	o.sinks = SINK_EXACT;
	o.budget = 0;
	o.seed = 9;
	drive(out, ob.n, &o, &res);
	WRT_CHECK_U64(res.errored, 0);
	WRT_CHECK_U64(res.frames, frames);
	WRT_CHECK_U64(res.log_n, ob.n);
}

/* A parser given no segment 0 buffer discards segment 0 (checking its CRC) under the segment
 * limit instead of the buffer size. */
static void test_discard_seg0(void)
{
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t rb[512], f[256], *w;
	wri_m2_txq q;
	wri_m2_seg_src s[1];
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, off = 0;
	uint8_t b[WRI_M2_BANNER_LEN];

	s[0].p = g_data;
	s[0].len = 100;
	s[0].ref = 0;
	wri_m2_txq_init(&q, g_enc, sizeof(g_enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, WRI_M2_TAG_KEEPALIVE2, s, 1, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		memcpy(f + off, iov[i].base, iov[i].len);
		off += iov[i].len;
	}
	wri_m2_banner_build(b);
	/* limit 100: exactly fits; limit 99: too big, rejected at the preamble */
	for (i = 0; i < 2; i++) {
		wri_ring_init(&ring, rb, sizeof(rb));
		wri_m2_rx_init(&rx, NULL, 0, 100 - (uint32_t)i);
		(void)wri_m2_rx_window(&rx, &ring, &w);
		memcpy(w, b, sizeof(b));
		wri_m2_rx_commit(&rx, &ring, sizeof(b));
		WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_BANNER);
		(void)wri_m2_rx_window(&rx, &ring, &w);
		memcpy(w, f, off);
		wri_m2_rx_commit(&rx, &ring, off);
		if (i == 0) {
			WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_SEG0);
			WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_FRAME);
			WRT_CHECK_U64(rx.stored[0], 0); /* nothing was kept */
			WRT_CHECK_U64(rx.desc.len[0], 100);
		} else {
			WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_ERROR);
			WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, wri_m2_rx_error(&rx)->status);
		}
	}
	/* the discarded bytes are still integrity checked */
	f[32 + 50] ^= 0x01;
	wri_ring_init(&ring, rb, sizeof(rb));
	wri_m2_rx_init(&rx, NULL, 0, 100);
	(void)wri_m2_rx_window(&rx, &ring, &w);
	memcpy(w, b, sizeof(b));
	wri_m2_rx_commit(&rx, &ring, sizeof(b));
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_BANNER);
	(void)wri_m2_rx_window(&rx, &ring, &w);
	memcpy(w, f, off);
	wri_m2_rx_commit(&rx, &ring, off);
	WRT_CHECK_U64(wri_m2_rx_step(&rx, &ring, NULL, NULL, NULL, NULL), WRI_RXE_ERROR);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, wri_m2_rx_error(&rx)->status);
}

int main(void)
{
	build_stream();
	test_equivalence();
	test_direct();
	test_budget();
	test_event_rules();
	test_txq();
	test_roundtrip();
	test_refusal_costs_no_crc();
	test_txq_model();
	test_discard_seg0();
	return wrt_finish();
}
