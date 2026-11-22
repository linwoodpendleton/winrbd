/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_rx_frames - the secure receive parser on good frames (core/src/msgr2/wri_m2_sec_rx.c and wri_m2_sec_rx2.c, design 34.7,
 * docs/spec/msgr2-secure-mode.md 2.5 to 2.8). The frames come from the simulator's encoder (harness/test/support/sim_m2_sec.c, written from
 * the spec with its own AES-GCM) and from the committed vector file; the core encrypts nothing here.
 *
 * What is checked:
 *   - frames of every shape (one to four segments, segment 0 empty / inside the first 48 bytes / across it / a long one, middle segments
 *     empty, lengths on and around every multiple of 16, around the direct-window threshold) come out byte for byte, with the right
 *     descriptor, `stored` counts and event order (SEG0 then FRAME), however they are delivered: whole, one byte at a time, random pieces,
 *     pieces of 7 and 16, through window()/commit() or through the ring only, with a ring of 16 bytes or 2 KiB, with every sink choice
 *     (exact size, 50 bytes of room, none: discarded, mixed) and with a work budget of 1, 16, 100 or none;
 *   - the bytes after the data of a segment (the zero padding, the epilogue) never land in a sink or in the segment 0 buffer;
 *   - a frame with late_status 1 is ABORTED, after SEG0, its tag verified and its nonces taken: the frames behind it parse;
 *   - one nonce is taken per GCM operation (the receive counter after N frames is the sum of their operations);
 *   - a counter that wraps modulo 2^64 in the middle of a stream (also in the middle of a three-operation frame) is no event;
 *   - the committed synthetic vectors (secure-frames-synthetic.json) in both directions: the frames of the client side through a server
 *     view parser (every shape of the file, a three-operation frame and a 4096-byte data segment among them), those of the server side
 *     through the client;
 *   - the direct window is really used for big segments (the pointer window() hands out lies in the sink), never for the last partial
 *     block, never when a segment has no sink, never through the ring-only feed;
 *   - the same with the host's accelerated GCM (the AES-NI hook of harness/host) when it is there and WRT_GCM_ACCEL is not 0.
 * Timing never matters: the budget is a count of work, the "clock" is the order of the calls.
 */
#include "wrt.h"

#include "m2_sec_rx_rig.h"

#include "../host/wrl_gcm_aesni.c"

static const wr_prim_ops *g_prim; /* NULL: portable GCM */
static int g_light;               /* 1: the reduced matrix (the accelerated pass) */
static uint8_t g_secret[64];

#define SEG0_CAP 4096u
#define SEG_CAP_MAX 200000u

/* ---- helpers ------------------------------------------------------------------------------------ */

static void ctx_fail(const char *what, const sxr_shape *sh, const sxr_cfg *c, unsigned ring)
{
	fprintf(stderr, "  [%s] tag %u nseg %u len %u/%u/%u/%u split %u chunk %u budget %u via_ring %d ring %u sinks %u%u%u\n", what, sh->tag,
		sh->nseg, sh->len[0], sh->len[1], sh->len[2], sh->len[3], c->split, c->chunk, c->budget, c->via_ring, ring, c->sink_mode[1],
		c->sink_mode[2], c->sink_mode[3]);
}

/* One frame, as the owner saw it, against what was sent. Returns 1 when everything is as expected. */
static int frame_ok(const sxr_frame *f, const sxr_frame_src *src, const sxr_cfg *c, unsigned want_ev)
{
	const sxr_shape *sh = &src->shape;
	unsigned i;

	if (f->ev != want_ev || f->desc.tag != sh->tag || f->desc.nseg != sh->nseg)
		return 0;
	for (i = 0; i < sh->nseg; i++)
		if (f->desc.len[i] != sh->len[i])
			return 0;
	if (f->desc.flags != 0 || !f->seg0_at_event_ok)
		return 0;
	if (sh->len[0] != 0 && memcmp(f->seg[0], src->data[0], sh->len[0]) != 0)
		return 0;
	if (f->stored[0] != sh->len[0])
		return 0;
	if (want_ev == WRI_RXE_ABORTED)
		return 1; /* the contents of an aborted frame are dropped: nothing more is promised */
	for (i = 1; i < sh->nseg; i++) {
		if (c->sink_mode[i] == SXR_SINK_NONE) {
			if (f->seg[i] != NULL || f->stored[i] != 0)
				return 0;
		} else if (f->seg[i] == NULL || f->stored[i] != sh->len[i] ||
			   (sh->len[i] != 0 && memcmp(f->seg[i], src->data[i], sh->len[i]) != 0)) {
			return 0;
		}
	}
	return 1;
}

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

static sxr_cfg cfg(unsigned split, unsigned chunk, unsigned budget)
{
	sxr_cfg c;

	memset(&c, 0, sizeof(c));
	c.split = split;
	c.chunk = chunk;
	c.budget = budget;
	c.seed = 5;
	c.sink_mode[1] = c.sink_mode[2] = c.sink_mode[3] = SXR_SINK_EXACT;
	return c;
}

static wire encode_one(const sxr_frame_src *src, const sim_sec_mut *m, sim_sec_ctx *srv)
{
	wire w;

	w.p = sxr_encode(&srv->tx, &src->spec, m, &w.n);
	return w;
}

/* ---- every shape, every way of delivering it ------------------------------------------------------- */

typedef struct mode {
	uint32_t split, chunk;
	int via_ring;
	uint32_t ring;
	uint32_t budget;
	uint8_t sinks[3];
} mode;

static const mode modes_full[] = {
	/* split chunk ring? ring budget sinks */
	{0, 0, 0, 2048, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{0, 0, 1, 2048, 0, {SXR_SINK_BIG, SXR_SINK_EXACT, SXR_SINK_BIG}},
	{1, 0, 0, 2048, 0, {SXR_SINK_EXACT, SXR_SINK_BIG, SXR_SINK_EXACT}},
	{2, 100, 0, 64, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{2, 40, 0, 16, 0, {SXR_SINK_NONE, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{3, 7, 0, 2048, 0, {SXR_SINK_EXACT, SXR_SINK_NONE, SXR_SINK_EXACT}},
	{3, 16, 1, 16, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_NONE}},
	{3, 33, 0, 2048, 1, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{2, 300, 0, 2048, 16, {SXR_SINK_BIG, SXR_SINK_BIG, SXR_SINK_BIG}},
	{2, 17, 1, 64, 100, {SXR_SINK_EXACT, SXR_SINK_NONE, SXR_SINK_NONE}},
	{0, 0, 0, 4096, 7, {SXR_SINK_NONE, SXR_SINK_NONE, SXR_SINK_NONE}},
};

static const mode modes_light[] = {
	{0, 0, 0, 2048, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{2, 50, 0, 64, 0, {SXR_SINK_BIG, SXR_SINK_NONE, SXR_SINK_EXACT}},
	{3, 1, 1, 16, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
	{2, 100, 0, 2048, 16, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}},
};

static void one_mode(const sxr_frame_src *src, const wire *w, const mode *m, unsigned seed)
{
	sxr_cfg c;
	sxr_out o;
	sxr rig_storage, *r = &rig_storage;
	int rc;
	unsigned i;
	int ok;

	memset(&c, 0, sizeof(c));
	memset(&o, 0, sizeof(o));
	c.split = m->split;
	c.chunk = m->chunk;
	c.via_ring = m->via_ring;
	c.budget = m->budget;
	c.seed = seed;
	for (i = 0; i < 3; i++)
		c.sink_mode[i + 1] = m->sinks[i];
	rc = sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, m->ring);
	WRT_CHECK_U64(rc, 0);
	if (rc != 0)
		return;
	sxr_run(r, w->p, w->n, &c, &o);
	ok = o.nframes == 1 && !o.errored && !o.stalled && o.guard_bad == 0 && o.order_bad == 0 && o.hidden_bad == 0 && o.nev == 2 && o.evs[0] == WRI_RXE_SEG0 &&
	     o.evs[1] == WRI_RXE_FRAME && o.fed == w->n && o.ring_left == 0 && o.direct_left == 0 && frame_ok(&o.fr[0], src, &c, WRI_RXE_FRAME);
	if (ok)
		ok = r->slot.s.rx_n.ops == sxr_nops(&src->shape); /* one nonce per operation */
	WRT_CHECK(ok);
	if (!ok) {
		ctx_fail("shape", &src->shape, &c, m->ring);
		fprintf(stderr, "    frames %u err %d stalled %d guard %u order %u nev %u fed %zu/%zu ring_left %zu direct_left %u ops %llu\n", o.nframes,
			(int)o.err, o.stalled, o.guard_bad, o.order_bad, o.nev, o.fed, w->n, o.ring_left, o.direct_left,
			(unsigned long long)r->slot.s.rx_n.ops);
	}
	sxr_out_free(&o);
	sxr_wipe(r);
}

static void run_shape(const sxr_shape *sh, unsigned salt)
{
	sxr_frame_src src;
	sim_sec_ctx srv;
	wire w;
	const mode *ms = g_light ? modes_light : modes_full;
	size_t nm = g_light ? sizeof(modes_light) / sizeof(modes_light[0]) : sizeof(modes_full) / sizeof(modes_full[0]);
	size_t i;

	sxr_src_make(&src, sh, salt);
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	w = encode_one(&src, NULL, &srv);
	WRT_CHECK(w.p != NULL);
	if (w.p != NULL) {
		unsigned nops = 0;

		WRT_CHECK_U64(w.n, wri_m2s_wire_len(sh->len, sh->nseg, &nops)); /* the core's arithmetic against the encoder's size */
		WRT_CHECK_U64(nops, sxr_nops(sh));
		for (i = 0; i < nm; i++)
			one_mode(&src, &w, &ms[i], salt * 31u + (unsigned)i);
	}
	free(w.p);
	sim_sec_ctx_wipe(&srv);
	sxr_src_free(&src);
}

static uint32_t g_rs = 0x2468ace1u;
static uint32_t pick(uint32_t n) { return sxr_rnd(&g_rs) % n; }

static void test_shapes(void)
{
	static const uint32_t l0[] = {0, 1, 15, 16, 17, 31, 47, 48, 49, 50, 63, 64, 65, 112, 113, 300};
	static const uint32_t ln[] = {1, 15, 16, 17, 33, 255, 256, 1023, 1024, 1025, 1040, 2047, 3000, 5000};
	sxr_shape sh;
	size_t a, b;
	unsigned n, salt = 1;

	/* one segment: every length of the list (and 4 around the inline size), nothing else on the wire */
	for (a = 0; a < sizeof(l0) / sizeof(l0[0]); a++) {
		memset(&sh, 0, sizeof(sh));
		sh.tag = (uint8_t)(1u + (unsigned)a);
		sh.nseg = 1;
		sh.len[0] = l0[a];
		run_shape(&sh, salt++);
	}
	/* two segments: every length of segment 0 with a few of the second */
	for (a = 0; a < sizeof(l0) / sizeof(l0[0]); a++) {
		for (b = 0; b < sizeof(ln) / sizeof(ln[0]); b += (g_light ? 4u : 1u)) {
			memset(&sh, 0, sizeof(sh));
			sh.tag = WRI_M2_TAG_MESSAGE;
			sh.nseg = 2;
			sh.len[0] = l0[a];
			sh.len[1] = ln[(b + a) % (sizeof(ln) / sizeof(ln[0]))];
			run_shape(&sh, salt++);
		}
	}
	/* three and four segments, random picks, with empty middle segments among them */
	for (n = 0; n < (g_light ? 10u : 50u); n++) {
		unsigned k;

		memset(&sh, 0, sizeof(sh));
		sh.tag = WRI_M2_TAG_MESSAGE;
		sh.nseg = 3u + (n & 1u);
		sh.len[0] = l0[pick(sizeof(l0) / sizeof(l0[0]))];
		for (k = 1; k < sh.nseg; k++)
			sh.len[k] = (pick(4) == 0 && k + 1 < sh.nseg) ? 0u : ln[pick(sizeof(ln) / sizeof(ln[0]))];
		run_shape(&sh, salt++);
	}
	/* the shapes of a real MESSAGE: control, front, middle empty, data */
	memset(&sh, 0, sizeof(sh));
	sh.tag = WRI_M2_TAG_MESSAGE;
	sh.nseg = 4;
	sh.len[0] = 41;
	sh.len[3] = 4096;
	run_shape(&sh, salt++);
	sh.len[3] = 4097;
	run_shape(&sh, salt++);
	sh.len[0] = 105;
	sh.len[1] = 70;
	sh.len[3] = 350;
	run_shape(&sh, salt++);
}

/* ---- the direct window --------------------------------------------------------------------------- */

static void test_direct_window(void)
{
	static const uint32_t lens[] = {1024, 1040, 4096, 4097, 4111, 9000, 40000};
	size_t i;

	for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		sxr_shape sh;
		sxr_frame_src src;
		sim_sec_ctx srv;
		wire w;
		sxr_cfg c;
		sxr_out o;
		sxr rig, *r = &rig;
		unsigned pass;

		memset(&sh, 0, sizeof(sh));
		sh.tag = WRI_M2_TAG_MESSAGE;
		sh.nseg = 4;
		sh.len[0] = 41;
		sh.len[3] = lens[i];
		sxr_src_make(&src, &sh, 90u + (unsigned)i);
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = encode_one(&src, NULL, &srv);
		for (pass = 0; pass < 4 && w.p != NULL; pass++) {
			memset(&c, 0, sizeof(c));
			memset(&o, 0, sizeof(o));
			c.sink_mode[3] = SXR_SINK_EXACT;
			c.sink_mode[1] = SXR_SINK_EXACT;
			c.sink_mode[2] = SXR_SINK_EXACT;
			c.via_ring = pass == 1;                       /* ring only */
			c.sink_mode[3] = pass == 2 ? SXR_SINK_NONE : SXR_SINK_EXACT; /* discarded: never direct */
			c.split = pass == 3 ? 3u : 0u;                /* pieces of 1000: some direct, some not */
			c.chunk = 1000;
			c.budget = pass == 3 ? 64u : 0u;
			WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
			sxr_run(r, w.p, w.n, &c, &o);
			WRT_CHECK(o.nframes == 1 && !o.errored && !o.stalled && o.guard_bad == 0 && o.order_bad == 0 && o.hidden_bad == 0);
			if (o.nframes == 1)
				WRT_CHECK(frame_ok(&o.fr[0], &src, &c, WRI_RXE_FRAME));
			if (pass == 0 || pass == 3)
				WRT_CHECK(lens[i] < 4096u ? 1 : o.direct_hits > 0); /* big enough to outlast the ring: the network wrote into the sink */
			else
				WRT_CHECK_U64(o.direct_hits, 0);
			sxr_out_free(&o);
			sxr_wipe(r);
		}
		free(w.p);
		sim_sec_ctx_wipe(&srv);
		sxr_src_free(&src);
	}
}

/* ---- streams: several frames, aborted ones, nonces, the counter wrap ---------------------------------- */

typedef struct step {
	sxr_shape sh;
	int aborted; /* late_status 1 */
} step;

static void run_stream(const uint8_t *secret, const step *st, unsigned n, const mode *m)
{
	sxr_frame_src src[16];
	sim_sec_ctx srv;
	uint8_t *bytes = NULL;
	size_t total = 0, off;
	wire ws[16];
	unsigned i, ops = 0;
	sxr_cfg c;
	sxr_out o;
	sxr rig, *r = &rig;

	memset(&c, 0, sizeof(c));
	memset(&o, 0, sizeof(o));
	WRT_CHECK(sim_sec_ctx_init(&srv, secret, 64, 1) == 0);
	for (i = 0; i < n; i++) {
		sim_sec_mut mu;

		memset(&mu, 0, sizeof(mu));
		if (st[i].aborted) {
			mu.mask = SIM_SEC_M_LATE;
			mu.late_status = 1;
		}
		sxr_src_make(&src[i], &st[i].sh, 500u + i);
		ws[i] = encode_one(&src[i], st[i].aborted ? &mu : NULL, &srv);
		WRT_CHECK(ws[i].p != NULL);
		total += ws[i].n;
		ops += sxr_nops(&st[i].sh);
	}
	bytes = (uint8_t *)malloc(total + 1u);
	for (off = 0, i = 0; i < n; i++) {
		memcpy(bytes + off, ws[i].p, ws[i].n);
		off += ws[i].n;
	}
	c.split = m->split;
	c.chunk = m->chunk;
	c.via_ring = m->via_ring;
	c.budget = m->budget;
	c.seed = 77;
	for (i = 0; i < 3; i++)
		c.sink_mode[i + 1] = m->sinks[i];
	WRT_CHECK_U64(sxr_init(r, g_prim, secret, 64, 0, SEG0_CAP, SEG_CAP_MAX, m->ring), 0);
	sxr_run(r, bytes, total, &c, &o);
	WRT_CHECK(!o.errored && !o.stalled && o.guard_bad == 0 && o.order_bad == 0 && o.hidden_bad == 0);
	WRT_CHECK_U64(o.nframes, n);
	WRT_CHECK_U64(o.nev, 2u * n);
	for (i = 0; i < n && i < o.nframes; i++) {
		WRT_CHECK(o.evs[2 * i] == WRI_RXE_SEG0);
		WRT_CHECK(o.evs[2 * i + 1] == (st[i].aborted ? WRI_RXE_ABORTED : WRI_RXE_FRAME));
		WRT_CHECK(frame_ok(&o.fr[i], &src[i], &c, st[i].aborted ? WRI_RXE_ABORTED : WRI_RXE_FRAME));
	}
	WRT_CHECK_U64(r->slot.s.rx_n.ops, ops); /* aborted frames took their nonces too */
	sxr_out_free(&o);
	sxr_wipe(r);
	free(bytes);
	for (i = 0; i < n; i++) {
		free(ws[i].p);
		sxr_src_free(&src[i]);
	}
	sim_sec_ctx_wipe(&srv);
}

static void test_streams(void)
{
	static const step plan[] = {
		{{WRI_M2_TAG_AUTH_SIGNATURE, 1, {32, 0, 0, 0}}, 0},
		{{WRI_M2_TAG_MESSAGE, 2, {20, 10, 0, 0}}, 0},
		{{WRI_M2_TAG_MESSAGE, 4, {41, 3, 0, 4}}, 1}, /* aborted */
		{{WRI_M2_TAG_MESSAGE, 4, {105, 70, 0, 350}}, 0},
		{{WRI_M2_TAG_KEEPALIVE2, 1, {8, 0, 0, 0}}, 0},
		{{WRI_M2_TAG_MESSAGE, 2, {60, 1500, 0, 0}}, 1}, /* aborted, three operations, a big segment */
		{{WRI_M2_TAG_MESSAGE, 4, {41, 0, 0, 4096}}, 0},
		{{WRI_M2_TAG_ACK, 1, {8, 0, 0, 0}}, 0},
		{{WRI_M2_TAG_MESSAGE, 3, {0, 16, 7, 0}}, 1}, /* aborted, empty segment 0 */
		{{WRI_M2_TAG_MESSAGE, 3, {0, 16, 7, 0}}, 0},
	};
	unsigned k;
	uint8_t secret[64];

	for (k = 0; k < (g_light ? 2u : (unsigned)(sizeof(modes_full) / sizeof(modes_full[0]))); k++) {
		sxr_secret(secret, 40u + k);
		run_stream(secret, plan, sizeof(plan) / sizeof(plan[0]), g_light ? &modes_light[k] : &modes_full[k]);
	}
	/* an aborted frame first, then a good one, in the smallest pieces */
	sxr_secret(secret, 99);
	run_stream(secret, plan + 2, 2, &modes_full[2]);
}

static void test_counter_wrap(void)
{
	/* The receive counter (seed A, S[20..27]) is 2 below the wrap: frames of one, two and three operations carry it over 2^64 and on. */
	static const step plan[] = {
		{{WRI_M2_TAG_KEEPALIVE2, 1, {8, 0, 0, 0}}, 0},                /* counter 2^64-2 */
		{{WRI_M2_TAG_MESSAGE, 4, {105, 70, 0, 350}}, 0},               /* 2^64-1, 0, 1: across the wrap, three operations */
		{{WRI_M2_TAG_MESSAGE, 2, {60, 1500, 0, 0}}, 0},
		{{WRI_M2_TAG_KEEPALIVE2, 1, {8, 0, 0, 0}}, 0},
	};
	uint8_t secret[64];
	unsigned k;

	sxr_secret(secret, 5);
	sim_sec_secret_set_counters(secret, 64, 1, 0xfffffffffffffffeull, 0, 0);
	for (k = 0; k < 3; k++)
		run_stream(secret, plan, sizeof(plan) / sizeof(plan[0]), &modes_full[k * 2]);
	/* the fixed field of the seed is all ones: it must not be touched by the carry (bytes 0..3 of the nonce stay) */
	sxr_secret(secret, 6);
	memset(secret + 16, 0xff, 4);
	sim_sec_secret_set_counters(secret, 64, 1, 0xffffffffffffffffull, 0, 0);
	run_stream(secret, plan, sizeof(plan) / sizeof(plan[0]), &modes_full[0]);
}

/* ---- the committed vectors ---------------------------------------------------------------------------- */

static void vector_dir(wrt_json *j, const char *dir, int crossed, const uint8_t *secret)
{
	wrt_tok root = wrt_json_root(j);
	wrt_tok arr = wrt_json_get(j, root, dir);
	size_t n = wrt_json_count(j, arr), i;
	uint8_t *wirebuf = NULL, *all = NULL;
	size_t total = 0, off = 0;
	sxr_frame_src srcs[16];
	sxr_shape shapes[16];
	sxr_cfg c;
	sxr_out o;
	sxr rig, *r = &rig;
	unsigned pass;

	WRT_CHECK(n >= 2 && n <= 16);
	if (n < 2 || n > 16)
		return;
	for (i = 0; i < n; i++) {
		wrt_tok f = wrt_json_at(j, arr, i), segs = wrt_json_get(j, f, "segments");
		size_t k, nseg = wrt_json_count(j, segs), last = 0;
		size_t wl = 0;
		int ok = 0;

		memset(&shapes[i], 0, sizeof(shapes[i]));
		shapes[i].tag = (uint8_t)wrt_json_int(j, wrt_json_get(j, f, "tag"), &ok);
		for (k = 0; k < nseg && k < 4; k++) {
			wrt_tok s = wrt_json_at(j, segs, k);

			shapes[i].len[k] = (uint32_t)wrt_json_int(j, wrt_json_get(j, s, "length"), &ok);
			if (shapes[i].len[k] != 0)
				last = k + 1;
		}
		shapes[i].nseg = (unsigned)last; /* the file lists four slots; trailing empty ones are not on the wire */
		memset(&srcs[i], 0, sizeof(srcs[i]));
		srcs[i].shape = shapes[i];
		for (k = 0; k < nseg && k < 4; k++) {
			wrt_tok s = wrt_json_at(j, segs, k);
			uint32_t len = shapes[i].len[k];
			int64_t fill = wrt_json_int(j, wrt_json_get(j, s, "fill_byte"), &ok);

			srcs[i].data[k] = (uint8_t *)malloc((size_t)len + 1u);
			memset(srcs[i].data[k], (int)fill, len);
		}
		WRT_CHECK(wrt_json_get_hex(j, f, "wire_hex", &wirebuf, &wl) == 0);
		WRT_CHECK_U64(wl, wri_m2s_wire_len(shapes[i].len, shapes[i].nseg, NULL));
		all = (uint8_t *)realloc(all, total + wl + 1u);
		memcpy(all + total, wirebuf, wl);
		total += wl;
		free(wirebuf);
		wirebuf = NULL;
	}
	for (pass = 0; pass < 4; pass++) {
		memset(&c, 0, sizeof(c));
		memset(&o, 0, sizeof(o));
		c.split = pass == 0 ? 0u : (pass == 1 ? 1u : 2u);
		c.chunk = 90;
		c.seed = pass + 5;
		c.budget = pass == 3 ? 16u : 0u;
		c.sink_mode[1] = c.sink_mode[2] = c.sink_mode[3] = pass == 2 ? SXR_SINK_BIG : SXR_SINK_EXACT;
		WRT_CHECK_U64(sxr_init(r, g_prim, secret, 64, crossed, SEG0_CAP, SEG_CAP_MAX, 2048), 0);
		sxr_run(r, all, total, &c, &o);
		WRT_CHECK(!o.errored && !o.stalled && o.guard_bad == 0 && o.order_bad == 0);
		WRT_CHECK_U64(o.nframes, n);
		for (i = 0, off = 0; i < n && i < o.nframes; i++) {
			int ok = frame_ok(&o.fr[i], &srcs[i], &c, WRI_RXE_FRAME);

			WRT_CHECK(ok);
			if (!ok)
				ctx_fail(dir, &shapes[i], &c, 2048);
		}
		(void)off;
		sxr_out_free(&o);
		sxr_wipe(r);
	}
	for (i = 0; i < n; i++)
		sxr_src_free(&srcs[i]);
	free(all);
}

static void test_vectors(void)
{
	wrt_json j;
	uint8_t *secret = NULL;
	size_t sn = 0;

	if (wrt_json_load_vec(&j, "secure/secure-frames-synthetic.json") != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_root(&j), "secret_hex", &secret, &sn) == 0 && sn == 64);
	if (secret != NULL && sn == 64) {
		vector_dir(&j, "server_to_client", 0, secret); /* what a client reads */
		vector_dir(&j, "client_to_server", 1, secret); /* what a server reads: the other seed */
	}
	free(secret);
	wrt_json_free(&j);
}


/* ---- the switch with bytes already in the ring ---------------------------------------------------------- */

static void test_bytes_before_switch(void)
{
	static const size_t cuts[] = {1, 31, 32, 79, 95, 96, 97, 130};
	sxr_shape sh = shape(4, 100, 40, 0, 20);
	sxr_frame_src src;
	sim_sec_ctx srv;
	wire w;
	size_t i;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	sxr_src_make(&src, &sh, 123);
	w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
	WRT_CHECK(w.p != NULL);
	/* the first n bytes of the frame arrived with the banner and the plaintext handshake: they are in the ring when the parser switches
	 * (design 34.4), and the parser reads them as secure; the rest comes later, in pieces, with a budget */
	for (i = 0; w.p != NULL && i < sizeof(cuts) / sizeof(cuts[0]); i++) {
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg(3, 11, i & 1u ? 16u : 0u);

		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init_pre(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 2048, w.p, cuts[i]), 0);
		WRT_CHECK_U64(r->ring.len, cuts[i]);
		o.fed = cuts[i]; /* the pump continues behind what is already in */
		sxr_run(r, w.p, w.n, &c, &o);
		WRT_CHECK(o.nframes == 1 && !o.errored && !o.stalled && o.guard_bad == 0 && o.hidden_bad == 0 && frame_ok(&o.fr[0], &src, &c, WRI_RXE_FRAME));
		sxr_out_free(&o);
		sxr_wipe(r);
	}
	free(w.p);
	sxr_src_free(&src);
	sim_sec_ctx_wipe(&srv);
}

/* ---- the pass --------------------------------------------------------------------------------------- */

static void pass_all(const char *name, const wr_prim_ops *prim, int light)
{
	g_prim = prim;
	g_light = light;
	g_rs = 0x2468ace1u;
	printf("pass %s%s\n", name, light ? " (reduced matrix)" : "");
	test_shapes();
	test_direct_window();
	test_streams();
	test_counter_wrap();
	test_vectors();
	test_bytes_before_switch();
}

int main(void)
{
	const char *env = getenv("WRT_GCM_ACCEL");
	wr_prim_ops accel;
	int want_accel = env == NULL || strcmp(env, "0") != 0;

	sxr_secret(g_secret, 1);
	if (env != NULL && strcmp(env, "1") == 0 && !wrl_gcm_aesni_available())
		fprintf(stderr, "note: WRT_GCM_ACCEL=1 but this CPU has no AES-NI/PCLMULQDQ: the accelerated pass is skipped\n");
	pass_all("portable", NULL, 0);
	if (want_accel && wrl_gcm_aesni_available() && wrl_gcm_aesni_ops(&accel) == 0) {
		WRT_CHECK(accel.gcm_state_bytes >= 1u);
		pass_all("accelerated", &accel, env != NULL && strcmp(env, "1") == 0 ? 0 : 1);
	}
	return wrt_finish();
}
