/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_rx_budget - the work budget and the window / commit contract of the secure receive parser (core/src/msgr2/wri_m2_sec_rx.c and
 * wri_m2_sec_rx2.c, design 34.7 item 5, wri_m2_sec.h).
 *
 * What is checked:
 *   - the result of a frame (events, descriptor, stored counts, every byte of segment 0 and of the sinks) is identical for a budget of 1, 2,
 *     15, 16, 17, 100, 1000 and none, with every delivery (whole, one byte at a time, random pieces, ring only), with and without the direct
 *     window, with a sink or discarded: the budget changes how many step() calls it takes, never what comes out;
 *   - the work is counted once per byte of ingress (a byte taken from the ring or settled from the direct window) and once per byte
 *     decrypted (padding and the epilogue block included, tags not), the two paid together when the byte comes in (two units for a
 *     payload byte, one for a tag byte): with a budget large enough never to clamp, the units spent over a frame are exactly
 *     wire + (wire - 16 * operations), whatever the delivery;
 *   - nothing is ever left hidden: when a step ends because the budget is spent, either the ring or the direct window still holds bytes
 *     (which the connection's work_left() test sees), or the parser is waiting for input: no whole block, no complete part 1 is sitting
 *     undecrypted behind an empty ring (checked after every step of every run of every test, the rig's hidden_bad);
 *   - a budget of 1 makes progress: every step() call that was given a unit and has input does something (the ring shrinks, the direct bytes
 *     are settled, the state moves), and a call never spends more than it was given;
 *   - events that need no bytes are free: with a budget of 0 the parser still returns SEG0 and FRAME when they are due, and does no work
 *     (the ring is not touched) while a frame is under way;
 *   - the work is resumable at every unit: the budget is spent in the middle of part 1, between part 1's last byte and its decrypt, after
 *     a decrypt and before the tag check, and the answer is the same;
 *   - a step settles no more direct-window bytes than its budget pays for (two units a byte, the last one may be paid in part), also at a budget
 *     of 1, and the frame completes with the right bytes;
 *   - window() never offers more than there is room for, commit() of more than the window is clamped (a ring never overflows, the direct
 *     window never writes past its segment) and commit() with n = 0 is a no-op; a NULL budget is unlimited.
 */
#include "wrt.h"

#include "m2_sec_rx_rig.h"

static uint8_t g_secret[64];

#define SEG0_CAP 512u
#define SEG_CAP_MAX 100000u

typedef struct wire {
	uint8_t *p;
	size_t n;
} wire;

static sxr_shape shape(unsigned nseg, uint32_t l0, uint32_t l1, uint32_t l2, uint32_t l3)
{
	sxr_shape s;

	memset(&s, 0, sizeof(s));
	s.tag = WRI_M2_TAG_MESSAGE;
	s.nseg = nseg;
	s.len[0] = l0;
	s.len[1] = l1;
	s.len[2] = l2;
	s.len[3] = l3;
	return s;
}

/* The same outcome? (frame count, events, descriptors, stored, contents) */
static int same_out(const sxr_out *a, const sxr_out *b)
{
	unsigned i, k;

	if (a->nframes != b->nframes || a->nev != b->nev || memcmp(a->evs, b->evs, a->nev) != 0 || a->errored != b->errored || a->err != b->err)
		return 0;
	for (i = 0; i < a->nframes; i++) {
		const sxr_frame *x = &a->fr[i], *y = &b->fr[i];

		if (x->ev != y->ev || memcmp(&x->desc, &y->desc, sizeof(x->desc)) != 0 || memcmp(x->stored, y->stored, sizeof(x->stored)) != 0)
			return 0;
		for (k = 0; k < 4; k++) {
			if ((x->seg[k] == NULL) != (y->seg[k] == NULL))
				return 0;
			if (x->seg[k] != NULL && memcmp(x->seg[k], y->seg[k], x->desc.len[k]) != 0)
				return 0;
		}
	}
	return 1;
}

static void run_one(const wire *w, const sxr_cfg *c, uint32_t ring, sxr *r, sxr_out *o)
{
	memset(o, 0, sizeof(*o));
	WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, ring), 0);
	sxr_run(r, w->p, w->n, c, o);
}

static sxr_cfg cfg(unsigned split, unsigned chunk, unsigned budget, int via_ring, unsigned sink)
{
	sxr_cfg c;

	memset(&c, 0, sizeof(c));
	c.split = split;
	c.chunk = chunk;
	c.budget = budget;
	c.via_ring = via_ring;
	c.seed = 9;
	c.sink_mode[1] = c.sink_mode[2] = c.sink_mode[3] = (uint8_t)sink;
	return c;
}

/* ---- identical results, exact accounting ------------------------------------------------------------ */

static void test_identical_and_counted(void)
{
	sxr_shape shapes[7];
	static const unsigned budgets[] = {1, 2, 15, 16, 17, 100, 1000, 0};
	size_t k, b, m;

	shapes[0] = shape(1, 5, 0, 0, 0);
	shapes[1] = shape(1, 100, 0, 0, 0);
	shapes[2] = shape(2, 20, 70, 0, 0);
	shapes[3] = shape(4, 100, 40, 0, 20);
	shapes[4] = shape(3, 49, 17, 1, 0);
	shapes[5] = shape(4, 41, 0, 0, 4097);
	shapes[6] = shape(3, 0, 1500, 15, 0);
	for (k = 0; k < sizeof(shapes) / sizeof(shapes[0]); k++) {
		sim_sec_ctx srv;
		sxr_frame_src src;
		wire w;
		unsigned nops = 0, sink;
		sxr rig, *r = &rig;
		sxr_out base, o;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		sxr_src_make(&src, &shapes[k], 70u + (unsigned)k);
		w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
		WRT_CHECK(w.p != NULL);
		if (w.p == NULL)
			continue;
		WRT_CHECK_U64(w.n, wri_m2s_wire_len(shapes[k].len, shapes[k].nseg, &nops));
		for (sink = SXR_SINK_EXACT; sink <= SXR_SINK_NONE; sink += 2u) { /* with sinks, and everything discarded */
			sxr_cfg c0 = cfg(0, 0, 0, 0, sink);

			run_one(&w, &c0, 2048, r, &base);
			WRT_CHECK(base.nframes == 1 && !base.errored && !base.stalled && base.guard_bad == 0 && base.hidden_bad == 0);
			sxr_wipe(r);
			for (b = 0; b < sizeof(budgets) / sizeof(budgets[0]); b++) {
				for (m = 0; m < 5; m++) {
					static const unsigned splits[5] = {0, 1, 2, 0, 3};
					sxr_cfg c = cfg(splits[m], m == 4 ? 13 : 250, budgets[b], m == 3, sink);
					int ok;

					run_one(&w, &c, m == 2 ? 64 : 2048, r, &o);
					ok = same_out(&base, &o) && !o.stalled && o.guard_bad == 0 && o.order_bad == 0 && o.hidden_bad == 0;
					WRT_CHECK(ok);
					if (!ok)
						fprintf(stderr, "  [identical] shape %zu sink %u budget %u split %u: frames %u errored %d stalled %d\n", k, sink,
							budgets[b], splits[m], o.nframes, o.errored, o.stalled);
					sxr_out_free(&o);
					sxr_wipe(r);
				}
			}
			sxr_out_free(&base);
		}
		/* exact accounting: a budget that never clamps */
		for (m = 0; m < 5; m++) {
			static const unsigned splits[5] = {0, 1, 2, 0, 3};
			sxr_cfg c = cfg(splits[m], m == 4 ? 13 : 250, 0x40000000u, m == 3, SXR_SINK_EXACT);
			uint64_t want = (uint64_t)w.n + ((uint64_t)w.n - 16u * nops);

			run_one(&w, &c, m == 2 ? 64 : 2048, r, &o);
			/* the per-call budget is reset to 2^30 every call, so units = what was spent in calls that did work */
			WRT_CHECK(o.nframes == 1);
			WRT_CHECK_U64(o.units, want);
			sxr_out_free(&o);
			sxr_wipe(r);
		}
		free(w.p);
		sxr_src_free(&src);
		sim_sec_ctx_wipe(&srv);
	}
}

/* ---- a budget of 1 progresses --------------------------------------------------------------------- */

static uint64_t progress_mark(const sxr *r)
{
	const wri_m2s_rx *sx = r->rx.sx;
	uint64_t h = 1469598103934665603ull;
	uint64_t v[8];
	unsigned i;

	v[0] = r->ring.len;
	v[1] = r->rx.direct;
	v[2] = sx->pos;
	v[3] = sx->dec;
	v[4] = sx->state;
	v[5] = r->rx.pending_ev;
	v[6] = r->rx.seg;
	v[7] = sx->s->rx_n.ops;
	for (i = 0; i < 8; i++)
		h = (h ^ v[i]) * 1099511628211ull;
	return h;
}

static void test_budget_one_progresses(void)
{
	sxr_shape shapes[3];
	size_t k;

	shapes[0] = shape(2, 20, 70, 0, 0);
	shapes[1] = shape(4, 100, 40, 0, 20);
	shapes[2] = shape(2, 60, 1800, 0, 0);
	for (k = 0; k < 3; k++) {
		sim_sec_ctx srv;
		sxr_frame_src src;
		wire w;
		sxr rig, *r = &rig;
		unsigned calls = 0, nframes = 0;
		size_t fed = 0;
		uint32_t budget;
		int done = 0;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		sxr_src_make(&src, &shapes[k], 80u + (unsigned)k);
		w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
		WRT_CHECK(w.p != NULL && w.n <= 2048);
		WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
		/* the whole frame is in the ring; sinks are chosen at SEG0 */
		fed = wri_ring_write(&r->ring, w.p, (uint32_t)w.n);
		WRT_CHECK_U64(fed, w.n);
		while (!done && calls < 20000u) {
			uint64_t before = progress_mark(r);
			wri_m2_rx_ev ev;

			budget = 1;
			ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &budget, NULL, NULL);
			calls++;
			WRT_CHECK(budget <= 1u); /* never spends more than it was given */
			if (ev == WRI_RXE_SEG0) {
				uint8_t *sinks[4] = {NULL, NULL, NULL, NULL};
				unsigned i;

				for (i = 1; i < r->rx.desc.nseg; i++) {
					sinks[i] = (uint8_t *)malloc(r->rx.desc.len[i] + 1u);
					wri_m2_rx_sink(&r->rx, i, sinks[i], r->rx.desc.len[i]);
				}
				/* run the rest, then check the contents */
				for (;;) {
					before = progress_mark(r);
					budget = 1;
					ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &budget, NULL, NULL);
					calls++;
					WRT_CHECK(budget <= 1u);
					if (ev == WRI_RXE_FRAME || ev == WRI_RXE_ERROR || calls > 20000u)
						break;
					WRT_CHECK(ev == WRI_RXE_NONE);
					/* the whole frame is in the ring, so the only reason to stop is that the unit is spent, and it bought something */
					WRT_CHECK_U64(budget, 0);
					WRT_CHECK(progress_mark(r) != before);
				}
				WRT_CHECK(ev == WRI_RXE_FRAME);
				for (i = 1; i < r->rx.desc.nseg; i++) {
					WRT_CHECK(memcmp(sinks[i], src.data[i], r->rx.desc.len[i]) == 0);
					free(sinks[i]);
				}
				nframes++;
				done = 1;
				continue;
			}
			if (ev == WRI_RXE_NONE) {
				WRT_CHECK_U64(budget, 0);
				WRT_CHECK(progress_mark(r) != before);
			}
			WRT_CHECK(ev == WRI_RXE_NONE || ev == WRI_RXE_SEG0);
		}
		WRT_CHECK_U64(nframes, 1);
		WRT_CHECK(calls < 20000u);
		WRT_CHECK_U64(r->ring.len, 0);
		sxr_wipe(r);
		free(w.p);
		sxr_src_free(&src);
		sim_sec_ctx_wipe(&srv);
	}
}

/* ---- events are free, work is not, and every unit is a resting place --------------------------------- */

static void test_free_events_and_zero_budget(void)
{
	sxr_shape sh = shape(1, 20, 0, 0, 0); /* one part of 96 bytes: 96 of ingress, 80 of decrypt */
	sim_sec_ctx srv;
	sxr_frame_src src;
	wire w, w2;
	sxr rig, *r = &rig;
	uint32_t b;
	wri_m2_rx_ev ev;
	size_t cut;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	sxr_src_make(&src, &sh, 3);
	w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
	w2.p = sxr_encode(&srv.tx, &src.spec, NULL, &w2.n);
	WRT_CHECK(w.p != NULL && w.n == 96 && w2.p != NULL);

	/* exactly 176 units: the work of the whole frame (80 payload bytes at two units, 16 tag bytes at one), and then SEG0 comes although the
	 * budget is spent */
	WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
	WRT_CHECK_U64(wri_ring_write(&r->ring, w.p, 96), 96);
	b = 176;
	ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_SEG0);
	WRT_CHECK_U64(b, 0);
	WRT_CHECK_U64(memcmp(r->rx.sink[0].dst, src.data[0], 20), 0);
	/* with nothing left to spend: the FRAME of a one-segment frame needs no bytes */
	b = 0;
	ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_FRAME);
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL) == WRI_RXE_FRAME); /* sticky, still free */
	wri_m2_rx_next_frame(&r->rx);
	/* the next frame is in the ring: a budget of 0 does no work at all */
	WRT_CHECK_U64(wri_ring_write(&r->ring, w2.p, 96), 96);
	b = 0;
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL) == WRI_RXE_NONE);
	WRT_CHECK_U64(r->ring.len, 96);
	WRT_CHECK_U64(r->slot.s.rx_n.ops, 1);
	/* a budget of 1 buys one byte (payload bytes cost two units: a unit that is there is spent on one byte, never refused) */
	b = 1;
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL) == WRI_RXE_NONE);
	WRT_CHECK_U64(r->ring.len, 95);
	WRT_CHECK_U64(b, 0);
	/* 158 units pay for the 79 payload bytes that are left: the 16 of the tag wait in the ring, so the work is visible, and no nonce is taken yet */
	b = 158;
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL) == WRI_RXE_NONE);
	WRT_CHECK_U64(r->ring.len, 16);
	WRT_CHECK_U64(b, 0);
	WRT_CHECK_U64(r->slot.s.rx_n.ops, 1);
	b = 0;
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL) == WRI_RXE_NONE);
	WRT_CHECK_U64(r->ring.len, 16);
	/* 16 units take the tag; the decrypt of part 1 (paid for with the bytes) and the free tag check follow, and SEG0 */
	b = 16;
	ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_SEG0);
	WRT_CHECK_U64(b, 0);
	WRT_CHECK_U64(r->ring.len, 0);
	WRT_CHECK_U64(r->slot.s.rx_n.ops, 2);
	WRT_CHECK_U64(memcmp(r->rx.sink[0].dst, src.data[0], 20), 0);
	sxr_wipe(r);

	/* cut the budget at every position of the frame: the answer is the same */
	for (cut = 1; cut < 176; cut++) {
		uint32_t b1 = (uint32_t)cut;

		WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
		WRT_CHECK_U64(wri_ring_write(&r->ring, w.p, 96), 96);
		ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b1, NULL, NULL);
		WRT_CHECK(ev == WRI_RXE_NONE); /* the frame costs 176: less than that never gets as far as SEG0 */
		WRT_CHECK(r->ring.len != 0);   /* and what it could not take is in the ring, where the connection can see it */
		b1 = 1000;
		ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b1, NULL, NULL);
		WRT_CHECK(ev == WRI_RXE_SEG0);
		WRT_CHECK_U64(memcmp(r->rx.sink[0].dst, src.data[0], 20), 0);
		b1 = 1;
		WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, &b1, NULL, NULL) == WRI_RXE_FRAME);
		sxr_wipe(r);
	}
	/* a NULL budget is no limit */
	WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
	WRT_CHECK_U64(wri_ring_write(&r->ring, w.p, 96), 96);
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL) == WRI_RXE_SEG0);
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL) == WRI_RXE_FRAME);
	sxr_wipe(r);
	free(w.p);
	free(w2.p);
	sxr_src_free(&src);
	sim_sec_ctx_wipe(&srv);
}

/* ---- window and commit ---------------------------------------------------------------------------- */

static void test_window_commit(void)
{
	sxr_shape sh = shape(4, 41, 0, 0, 6000);
	sim_sec_ctx srv;
	sxr_frame_src src;
	wire w;
	sxr rig, *r = &rig;
	uint8_t *p, *sink;
	size_t win;
	uint32_t b;
	wri_m2_rx_ev ev;
	int guard;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	sxr_src_make(&src, &sh, 4);
	w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
	WRT_CHECK(w.p != NULL);
	WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 256), 0);

	/* the ring window: at most the free space; commit() of more than the window never overruns the ring, 0 is a no-op */
	win = wri_m2_rx_window(&r->rx, &r->ring, &p);
	WRT_CHECK(win == 256 && p == r->ring.buf);
	wri_m2_rx_commit(&r->rx, &r->ring, 0);
	WRT_CHECK_U64(r->ring.len, 0);
	memcpy(p, w.p, 256);
	wri_m2_rx_commit(&r->rx, &r->ring, 100000); /* far more than the window */
	WRT_CHECK_U64(r->ring.len, 256);
	WRT_CHECK_U64(wri_m2_rx_window(&r->rx, &r->ring, &p), 0); /* full ring: nothing to offer until step() made room */
	b = 1000; /* part 1 costs 176, the rest of the budget goes on the bytes behind it, and the step stops at SEG0 */
	ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_SEG0);
	/* a pending SEG0 does not close the window: what follows waits in the ring */
	WRT_CHECK(wri_m2_rx_window(&r->rx, &r->ring, &p) > 0);
	/* the owner's sinks: the big segment gets a heap block with a guard band behind it */
	sink = (uint8_t *)malloc(6000u + 64u);
	memset(sink, SXR_CANARY, 6000u + 64u);
	wri_m2_rx_sink(&r->rx, 3, sink, 6000);
	/* drain the ring (the first bytes of segment 3 are in it), so that the direct window opens */
	b = 100000;
	ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_NONE);
	WRT_CHECK_U64(r->ring.len, 0);
	win = wri_m2_rx_window(&r->rx, &r->ring, &p);
	WRT_CHECK(win > 1024 && p >= sink && p < sink + 6000);
	{
		size_t room = win;
		uint32_t got_before = r->rx.direct;

		WRT_CHECK_U64(got_before, 0);
		wri_m2_rx_commit(&r->rx, &r->ring, room + 5000); /* more than the window: clamped to it */
		WRT_CHECK_U64(r->rx.direct, room);
		/* the bytes of the network, for what was committed (they are the next ones of the wire) */
		(void)room;
	}
	/* the rest of the test is covered by the pump tests: here the clamp is the point; abandon the frame */
	guard = sxr_all_canary(sink + 6000, 64);
	WRT_CHECK(guard);
	free(sink);
	sxr_wipe(r);
	free(w.p);
	sxr_src_free(&src);
	sim_sec_ctx_wipe(&srv);
}

/* ---- a step settles no more direct bytes than its budget pays for ------------------------------------------ */

static void test_direct_settle_bounded(void)
{
	static const uint32_t L1 = 3000u;
	static const unsigned budgets[] = {1, 2, 3, 100};
	sxr_shape sh = shape(2, 20, L1, 0, 0);
	size_t bi;

	for (bi = 0; bi < sizeof(budgets) / sizeof(budgets[0]); bi++) {
		sim_sec_ctx srv;
		sxr_frame_src src;
		wire w;
		sxr rig, *r = &rig;
		uint8_t *sink, *p;
		size_t win, off = 96, fed;
		uint32_t b, before, steps = 0;
		wri_m2_rx_ev ev;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		sxr_src_make(&src, &sh, 12);
		w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
		WRT_CHECK(w.p != NULL);
		WRT_CHECK_U64(sxr_init(r, NULL, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 4096), 0);
		WRT_CHECK_U64(wri_ring_write(&r->ring, w.p, 96), 96);
		ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);
		WRT_CHECK(ev == WRI_RXE_SEG0);
		sink = (uint8_t *)malloc(L1 + 64u);
		memset(sink, SXR_CANARY, L1 + 64u);
		wri_m2_rx_sink(&r->rx, 1, sink, L1);
		ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);
		WRT_CHECK(ev == WRI_RXE_NONE && r->ring.len == 0);
		/* 2000 bytes of segment 1 arrive straight in the sink */
		win = wri_m2_rx_window(&r->rx, &r->ring, &p);
		WRT_CHECK(win >= 2000u && p == sink);
		memcpy(p, w.p + off, 2000u);
		wri_m2_rx_commit(&r->rx, &r->ring, 2000u);
		off += 2000u;
		WRT_CHECK_U64(r->rx.direct, 2000u);
		while (r->rx.direct != 0 && steps < 5000u) {
			before = r->rx.direct;
			b = budgets[bi];
			ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, &b, NULL, NULL);
			steps++;
			WRT_CHECK(ev == WRI_RXE_NONE);
			WRT_CHECK(b < budgets[bi] || r->rx.direct < before); /* it did something */
			/* two units a payload byte (ingress and decryption paid together), the last byte of a call may be paid in part */
			WRT_CHECK(before - r->rx.direct <= (budgets[bi] + 1u) / 2u);
		}
		WRT_CHECK_U64(r->rx.direct, 0);
		/* the rest of the frame, unlimited */
		fed = w.n - off;
		for (steps = 0; ev != WRI_RXE_FRAME && steps < 1000u; steps++) {
			size_t n = wri_m2_rx_window(&r->rx, &r->ring, &p);

			if (n > fed)
				n = fed;
			if (n != 0) {
				memcpy(p, w.p + off, n);
				wri_m2_rx_commit(&r->rx, &r->ring, n);
				off += n;
				fed -= n;
			}
			ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);
			WRT_CHECK(ev == WRI_RXE_NONE || ev == WRI_RXE_FRAME);
		}
		WRT_CHECK(ev == WRI_RXE_FRAME && r->rx.stored[1] == L1);
		WRT_CHECK(memcmp(sink, src.data[1], L1) == 0 && sxr_all_canary(sink + L1, 64u));
		free(sink);
		sxr_wipe(r);
		free(w.p);
		sxr_src_free(&src);
		sim_sec_ctx_wipe(&srv);
	}
}

int main(void)
{
	sxr_secret(g_secret, 3);
	test_identical_and_counted();
	test_budget_one_progresses();
	test_free_events_and_zero_budget();
	test_window_commit();
	test_direct_settle_bounded();
	return wrt_finish();
}
