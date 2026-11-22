/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_rx_bad - the secure receive parser on bad input (core/src/msgr2/wri_m2_sec_rx.c and wri_m2_sec_rx2.c, design 34.7 and the
 * attack matrix of 39.2). The frames are made by the simulator's encoder (harness/test/support/sim_m2_sec.c), with its deliberate defects.
 *
 * What is checked:
 *   - every single-bit flip of a finished frame, in every region (the ciphertext and the tag of part 1, of part 2, the data, the padding, the
 *     epilogue block and the tag of part 3), however the bytes are delivered, is WR_E_M2_SEC_TAG, the parser is dead and sticky (the same
 *     event again, window() 0, next_frame() and more input change nothing), no frame is ever delivered, and SEG0 is delivered only for a flip
 *     behind the tag that carried the last byte of segment 0;
 *   - a flip in a frame whose preamble also lies (a huge length, a bad CRC) is a tag failure, not the other error: nothing in a frame
 *     whose tag did not verify is acted on;
 *   - a replayed frame, a skipped frame, frames in the wrong order, the other direction's seed, a key one bit off, a nonce one off in each
 *     operation of a three-operation frame, the msgr2.0 stepping of the nonce: WR_E_M2_SEC_TAG;
 *   - behind a RIGHT tag, each defect has its own status, and none is detected before the tag: a bad preamble CRC (FRAME_CRC), nseg 0 / 5 /
 *     255 (FRAME_FORM), an empty last segment, the reserved byte, the compressed flag, a junk byte in an unused slot (FRAME_FORM), an unknown
 *     tag (M2_TAG), lengths above the caps (FRAME_TOOBIG: segment 0 above its buffer, another segment above seg_cap_max, a sink one byte too
 *     short), and a bad epilogue nibble (FRAME_FORM; the high nibble is ignored as in crc mode); lengths exactly at a cap pass;
 *     a discarded segment 0 is capped by seg_cap_max;
 *   - truncation at every offset: no event but the right SEG0, no error, the plaintext of segment 0 is not in its buffer before the first
 *     tag verified, and what follows the cut completes the frame (the parser is resumable at every byte);
 *   - garbage in every padding byte (part 1 fill, the padding of each segment, the epilogue's 15 bytes) is ignored and never leaks into
 *     a sink or into the segment 0 buffer;
 *   - the nonce rules: a lowered operation limit refuses the operation after it (WR_E_M2_NONCE) before any plaintext of it is produced (also in
 *     the middle of a frame: before part 2, before part 3), a stream that is back at its seed refuses, a limit of 0 means none;
 *   - no way back to crc: frames built by the core's crc builder (a short AUTH_SIGNATURE, a message, four segments), alone or repeated, are
 *     never a frame and never SEG0: WR_E_M2_SEC_TAG once 96 bytes are in, "need more" before;
 *   - an ABORTED frame is sticky until the owner releases it (the ring is not touched), and the frame behind it parses normally (the nonces
 *     advanced over the aborted one);
 *   - the staging holds no plaintext it should not keep: part 1's decrypted bytes are wiped once accepted and on a tag failure, the scratch block
 *     and the tag buffer on every failure and at the end of a frame (also after a failure behind a right tag);
 *   - after SEG0 the window stays the ring until the next step has checked the owner's sinks: a sink one byte too short never receives a byte
 *     (WR_E_M2_FRAME_TOOBIG), a right one is filled afterwards; and the window is the ring as long as the ring holds bytes (the direct
 *     window would reorder the stream);
 *   - a parser that is not set up (inactive state, state never started) reports WR_E_STATE and dies;
 *   - the same bit flips and defects with the host's accelerated GCM when it is there and WRT_GCM_ACCEL is not 0.
 */
#include "wrt.h"

#include "m2_sec_rx_rig.h"

#include "../host/wrl_gcm_aesni.c"

static const wr_prim_ops *g_prim;
static int g_light;
static uint8_t g_secret[64];

#define SEG0_CAP 300u
#define SEG_CAP_MAX 5000u
#define RING 2048u

typedef struct wire {
	uint8_t *p;
	size_t n;
} wire;

static const sxr_cfg cfg_whole = {0, 0, 0, 0, 0, {SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}, 0, 0};

static sxr_cfg cfg_of(unsigned split, unsigned chunk, unsigned budget)
{
	sxr_cfg c = cfg_whole;

	c.split = split;
	c.chunk = chunk;
	c.budget = budget;
	c.seed = 3;
	return c;
}

static wire enc(const sxr_shape *sh, const sim_sec_mut *m, unsigned salt, sim_sec_ctx *srv)
{
	sxr_frame_src src;
	wire w;

	sxr_src_make(&src, sh, salt);
	w.p = sxr_encode(&srv->tx, &src.spec, m, &w.n);
	sxr_src_free(&src);
	return w;
}

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

static uint32_t pad16(uint32_t x) { return (x + 15u) & ~15u; }

/* Where a frame's parts end on the wire: the tag of part 1, the end of what carries segment 0, the end. */
static void part_ends(const sxr_shape *sh, size_t *p1, size_t *seg0_end, size_t *total)
{
	size_t t = 96;

	*p1 = 96;
	if (sh->len[0] > 48)
		t += pad16(sh->len[0]) - 48 + 16;
	*seg0_end = t;
	if (sh->nseg > 1) {
		unsigned i;

		for (i = 1; i < sh->nseg; i++)
			t += pad16(sh->len[i]);
		t += 32;
	}
	*total = t;
}

/* A fresh rig, the bytes through it. */
static void parse(const wire *w, const sxr_cfg *c, uint32_t seg0_cap, uint32_t seg_cap_max, sxr *r, sxr_out *o)
{
	memset(o, 0, sizeof(*o));
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, seg0_cap, seg_cap_max, RING), 0);
	sxr_run(r, w->p, w->n, c, o);
}

static void done(sxr *r, sxr_out *o)
{
	sxr_out_free(o);
	sxr_wipe(r);
}

static int has_ev(const sxr_out *o, unsigned ev)
{
	unsigned i;

	for (i = 0; i < o->nev; i++)
		if (o->evs[i] == ev)
			return 1;
	return 0;
}

/* The run ended in this error, with no frame, and the stickiness checks of the rig held. */
static int died_with(const sxr_out *o, wr_status st)
{
	return o->errored && o->err == st && o->nframes == 0 && !has_ev(o, WRI_RXE_FRAME) && !has_ev(o, WRI_RXE_ABORTED) && o->order_bad == 0 &&
	       !o->stalled && o->guard_bad == 0 && o->hidden_bad == 0;
}

/* ---- bit flips -------------------------------------------------------------------------------------- */

static void flip_case(const sxr_shape *sh, const wire *w, size_t bit, const sxr_cfg *c)
{
	size_t p1, s0, tot, byte = bit / 8u;
	sxr rig, *r = &rig;
	sxr_out o;
	int ok;
	wire f = *w;

	f.p = (uint8_t *)malloc(w->n);
	memcpy(f.p, w->p, w->n);
	f.p[byte] ^= (uint8_t)(1u << (bit % 8u));
	part_ends(sh, &p1, &s0, &tot);
	parse(&f, c, SEG0_CAP, SEG_CAP_MAX, r, &o);
	ok = died_with(&o, WR_E_M2_SEC_TAG);
	/* SEG0 comes only behind the tag that carried the last byte of segment 0: a flip before that end never lets it through */
	ok = ok && (has_ev(&o, WRI_RXE_SEG0) == (byte >= s0));
	WRT_CHECK(ok);
	if (!ok)
		fprintf(stderr, "  flip bit %zu (byte %zu of %zu; seg0 ends at %zu): err %d errored %d frames %u seg0 %d order %u guard %u\n", bit, byte,
			w->n, s0, (int)o.err, o.errored, o.nframes, has_ev(&o, WRI_RXE_SEG0), o.order_bad, o.guard_bad);
	done(r, &o);
	free(f.p);
}

static void test_bit_flips(void)
{
	sxr_shape shapes[4];
	size_t k, i;
	sim_sec_ctx srv;

	shapes[0] = shape(1, 30, 0, 0, 0);          /* one part */
	shapes[1] = shape(2, 20, 70, 0, 0);         /* parts 1 and 3 */
	shapes[2] = shape(4, 100, 40, 0, 20);       /* all three parts, an empty middle segment */
	shapes[3] = shape(3, 60, 1100, 33, 0);      /* a big segment (direct window), three parts */
	for (k = 0; k < (g_light ? 3u : 4u); k++) {
		wire w;
		size_t nbits, step = 1;
		unsigned m;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&shapes[k], NULL, 7u + (unsigned)k, &srv);
		WRT_CHECK(w.p != NULL);
		if (w.p == NULL)
			continue;
		nbits = w.n * 8u;
		if (k == 3)
			step = 37; /* a prime step: every region, every bit position, in a sample */
		if (g_light)
			step = step * 5u;
		for (m = 0; m < (g_light ? 1u : 3u); m++) {
			sxr_cfg c = m == 0 ? cfg_of(0, 0, 0) : (m == 1 ? cfg_of(1, 0, 0) : cfg_of(2, 60, 16));
			size_t bit;

			for (bit = (size_t)m; bit < nbits; bit += step)
				flip_case(&shapes[k], &w, bit, &c);
			if (k == 3) /* all bits of the first 100 bytes and the last 40 */
				for (i = 0; i < 100u * 8u; i += (m + 1u))
					flip_case(&shapes[k], &w, i, &c);
		}
		free(w.p);
		sim_sec_ctx_wipe(&srv);
	}
}

/* ---- the parser is dead for good ------------------------------------------------------------------------- */

static void test_no_resync(void)
{
	sxr_shape sh = shape(2, 20, 70, 0, 0);
	sim_sec_ctx srv;
	wire bad, good;
	sxr rig, *r = &rig;
	sxr_out o;
	uint8_t *p;
	uint32_t budget = 1000;
	int i;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	bad = enc(&sh, NULL, 1, &srv);
	good = enc(&sh, NULL, 2, &srv);
	bad.p[5] ^= 0x40; /* ciphertext of part 1 */
	parse(&bad, &(sxr_cfg){0, 0, 0, 0, 0, {0, SXR_SINK_EXACT, SXR_SINK_EXACT, SXR_SINK_EXACT}, 0, 0}, SEG0_CAP, SEG_CAP_MAX, r, &o);
	WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
	/* the next frame is perfectly good, and arrives in the ring: the parser stays dead, no resynchronisation */
	WRT_CHECK_U64(wri_m2_rx_window(&r->rx, &r->ring, &p), 0);
	WRT_CHECK(p == NULL);
	{
		uint32_t before = r->ring.len;

		wri_m2_rx_commit(&r->rx, &r->ring, 10); /* ignored */
		WRT_CHECK_U64(r->ring.len, before);
	}
	for (i = 0; i < 3; i++) {
		(void)wri_ring_write(&r->ring, good.p, (uint32_t)(good.n < 400 ? good.n : 400));
		WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL) == WRI_RXE_ERROR);
		WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, g_prim, NULL, NULL, NULL) == WRI_RXE_ERROR);
		wri_m2_rx_next_frame(&r->rx);
	}
	WRT_CHECK_U64(wri_m2_rx_error(&r->rx)->status, WR_E_M2_SEC_TAG);
	WRT_CHECK_U64(budget, 1000); /* a dead parser does no work */
	done(r, &o);
	free(bad.p);
	free(good.p);
	sim_sec_ctx_wipe(&srv);
}

/* ---- nonces, keys, seeds ------------------------------------------------------------------------------ */

static void expect_second_fails(const wire *a, const wire *b, const char *what)
{
	sxr rig, *r = &rig;
	sxr_out o;
	wire both;
	int ok;

	both.n = a->n + b->n;
	both.p = (uint8_t *)malloc(both.n);
	memcpy(both.p, a->p, a->n);
	memcpy(both.p + a->n, b->p, b->n);
	{
		sxr_cfg c = cfg_of(0, 0, 0);

		parse(&both, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
	}
	ok = o.errored && o.err == WR_E_M2_SEC_TAG && o.nframes == 1 && o.order_bad == 0 && !o.stalled;
	WRT_CHECK(ok);
	if (!ok)
		fprintf(stderr, "  [%s] errored %d err %d frames %u\n", what, o.errored, (int)o.err, o.nframes);
	done(r, &o);
	free(both.p);
}

static void test_nonce_attacks(void)
{
	sxr_shape sh1 = shape(2, 20, 70, 0, 0), sh3 = shape(4, 100, 40, 0, 20);
	sim_sec_ctx srv;
	wire f1, f2, f3;
	unsigned part, d;

	/* replay: the same bytes twice */
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	f1 = enc(&sh1, NULL, 1, &srv);
	expect_second_fails(&f1, &f1, "replay");
	/* skipped: frame 1 never arrives, frame 3 does after frame 2... (here: 2 is dropped) */
	f2 = enc(&sh1, NULL, 2, &srv);
	f3 = enc(&sh3, NULL, 3, &srv);
	expect_second_fails(&f1, &f3, "skipped one frame");
	/* wrong order: the second frame first is already wrong */
	{
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg_of(0, 0, 0);

		parse(&f2, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
		done(r, &o);
	}
	free(f1.p);
	free(f2.p);
	free(f3.p);
	sim_sec_ctx_wipe(&srv);

	/* the other direction's seed (the server encrypts with the client's seed): the very first frame fails */
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 0) == 0);
	f1 = enc(&sh1, NULL, 1, &srv);
	{
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg_of(0, 0, 0);

		parse(&f1, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
		done(r, &o);
	}
	free(f1.p);
	sim_sec_ctx_wipe(&srv);

	/* a key one bit off, and a nonce one off (-1 repeats the last, +1 skips) in each operation of a three-operation frame */
	{
		sim_sec_mut m;
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg_of(0, 0, 0);
		size_t p1, s0, tot;

		part_ends(&sh3, &p1, &s0, &tot);
		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_KEY;
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		f1 = enc(&sh3, &m, 4, &srv);
		parse(&f1, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG) && !has_ev(&o, WRI_RXE_SEG0));
		done(r, &o);
		free(f1.p);
		sim_sec_ctx_wipe(&srv);
		for (part = 1; part <= 3; part++) {
			for (d = 0; d < 2; d++) {
				memset(&m, 0, sizeof(m));
				m.mask = SIM_SEC_M_NONCE;
				m.nonce_part = (uint8_t)part;
				m.nonce_delta = d == 0 ? -1 : 1;
				WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
				if (part == 1 && d == 0) { /* "-1" at the very first operation is the nonce before the seed: the encoder allows it */
				}
				f1 = enc(&sh3, &m, 5, &srv);
				WRT_CHECK(f1.p != NULL);
				if (f1.p != NULL) {
					int ok;

					parse(&f1, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
					ok = died_with(&o, WR_E_M2_SEC_TAG) && (has_ev(&o, WRI_RXE_SEG0) == (part == 3));
					WRT_CHECK(ok);
					if (!ok)
						fprintf(stderr, "  nonce part %u delta %d: err %d seg0 %d\n", part, (int)m.nonce_delta, (int)o.err,
							has_ev(&o, WRI_RXE_SEG0));
					done(r, &o);
					free(f1.p);
				}
				sim_sec_ctx_wipe(&srv);
			}
		}
	}

	/* the msgr2.0 stepping: after the first frame the FIXED field is stepped instead of the counter; frame 1 is fine, frame 2 fails */
	{
		sxr_frame_src src;
		sim_sec_ctx s2;
		wire a, b;

		WRT_CHECK(sim_sec_ctx_init(&s2, g_secret, sizeof(g_secret), 1) == 0);
		sxr_src_make(&src, &sh1, 6);
		a.p = sxr_encode(&s2.tx, &src.spec, NULL, &a.n);
		/* frame 1 took two operations; the rev 1 nonce is seed + 2 in the counter: replace it by the 2.0 one (fixed field + 2) */
		memcpy(s2.tx.nonce, s2.tx.seed, sizeof(s2.tx.nonce));
		s2.tx.nonce[0] = (uint8_t)(s2.tx.nonce[0] + 2u);
		b.p = sxr_encode(&s2.tx, &src.spec, NULL, &b.n);
		WRT_CHECK(a.p != NULL && b.p != NULL);
		expect_second_fails(&a, &b, "2.0 stepping");
		free(a.p);
		free(b.p);
		sxr_src_free(&src);
		sim_sec_ctx_wipe(&s2);
	}
}

/* ---- right tag, bad plaintext ---------------------------------------------------------------------------- */

/* One defect behind a right tag: parse it, expect this status and no SEG0 unless segment 0 was already through (stage_seg0 = 1). */
static void defect(const char *what, const sxr_shape *sh, const sim_sec_mut *m, wr_status want, int want_seg0, uint32_t seg0_cap,
		   uint32_t seg_cap_max, const sxr_cfg *c)
{
	sim_sec_ctx srv;
	sxr rig, *r = &rig;
	sxr_out o;
	wire w;
	int ok;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	w = enc(sh, m, 11, &srv);
	WRT_CHECK(w.p != NULL);
	if (w.p == NULL) {
		fprintf(stderr, "  [%s] the encoder refused\n", what);
		sim_sec_ctx_wipe(&srv);
		return;
	}
	parse(&w, c, seg0_cap, seg_cap_max, r, &o);
	ok = died_with(&o, want) && has_ev(&o, WRI_RXE_SEG0) == want_seg0;
	WRT_CHECK(ok);
	if (!ok)
		fprintf(stderr, "  [%s] want err %d seg0 %d, got errored %d err %d (%s) frames %u seg0 %d order %u guard %u stalled %d\n", what, (int)want,
			want_seg0, o.errored, (int)o.err, wrt_status_name_(o.err), o.nframes, has_ev(&o, WRI_RXE_SEG0), o.order_bad, o.guard_bad,
			o.stalled);
	/* and the same, a byte at a time and with a budget of 1: the verdict does not depend on the delivery */
	if (ok && !g_light) {
		sxr_cfg c2 = cfg_of(1, 0, 1);

		done(r, &o);
		c2.sink_mode[1] = c->sink_mode[1];
		c2.sink_mode[2] = c->sink_mode[2];
		c2.sink_mode[3] = c->sink_mode[3];
		parse(&w, &c2, seg0_cap, seg_cap_max, r, &o);
		ok = died_with(&o, want) && has_ev(&o, WRI_RXE_SEG0) == want_seg0;
		WRT_CHECK(ok);
		if (!ok)
			fprintf(stderr, "  [%s, byte by byte] err %d\n", what, (int)o.err);
	}
	done(r, &o);
	free(w.p);
	sim_sec_ctx_wipe(&srv);
}

static void test_behind_the_tag(void)
{
	sxr_shape one = shape(1, 30, 0, 0, 0), two = shape(2, 60, 70, 0, 0), four = shape(4, 41, 20, 0, 30), three = shape(3, 16, 8, 4, 0);
	sxr_cfg c = cfg_of(0, 0, 0);
	sim_sec_mut m;
	unsigned i;

	/* the preamble */
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_PRE_CRC;
	defect("bad preamble crc (1 part)", &one, &m, WR_E_M2_FRAME_CRC, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	defect("bad preamble crc (3 parts)", &four, &m, WR_E_M2_FRAME_CRC, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_crc_xor = 0x80;
	defect("bad preamble crc (other bit)", &two, &m, WR_E_M2_FRAME_CRC, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	{
		static const uint8_t nsegs[] = {0, 5, 6, 255};

		for (i = 0; i < sizeof(nsegs); i++) {
			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_PRE_NSEG;
			m.pre_nseg = nsegs[i];
			defect("nseg out of range", &two, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
		}
	}
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_RESERVED;
	m.pre_reserved = 1;
	defect("reserved byte", &two, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_reserved = 0x80;
	defect("reserved byte 0x80", &one, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_FLAGS;
	m.pre_flags = 1;
	defect("compressed flag", &four, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_flags = 0x80;
	defect("flag 0x80", &one, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_SLOT;
	m.slot_junk = 1;
	defect("junk in an unused slot", &two, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_KEEP_TAIL;
	{
		sxr_shape tail = shape(3, 20, 30, 0, 0); /* the last segment empty on the wire */

		defect("empty last segment", &tail, &m, WR_E_M2_FRAME_FORM, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	}
	{
		static const uint8_t tags[] = {0, 23, 24, 100, 255};

		for (i = 0; i < sizeof(tags); i++) {
			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_PRE_TAG;
			m.pre_tag = tags[i];
			defect("unknown frame tag", &two, &m, WR_E_M2_TAG, 0, SEG0_CAP, SEG_CAP_MAX, &c);
		}
		for (i = 0; i < 2; i++) { /* the lowest and the highest known tag pass */
			sxr rig, *r = &rig;
			sxr_out o;
			sim_sec_ctx srv;
			wire w;

			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_PRE_TAG;
			m.pre_tag = i == 0 ? 1 : 22;
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
			w = enc(&two, &m, 12, &srv);
			parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
			WRT_CHECK(!o.errored && o.nframes == 1 && o.fr[0].desc.tag == m.pre_tag);
			done(r, &o);
			free(w.p);
			sim_sec_ctx_wipe(&srv);
		}
	}

	/* the lengths: caps are checked only after the tag, and exactly at a cap is fine */
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_PRE_LEN;
	m.pre_len_mask = 1;
	m.pre_len[0] = SEG0_CAP + 1u;
	defect("segment 0 one byte over its buffer", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_len[0] = 0xffffffffu;
	defect("segment 0 of 4 GiB - 1", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, 0xffffffffu, &c);
	m.pre_len[0] = 0xfffffff0u;
	defect("segment 0 of 4 GiB - 16 (padding would wrap)", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, 0xffffffffu, &c);
	m.pre_len_mask = 2;
	m.pre_len[1] = SEG_CAP_MAX + 1u;
	defect("segment 1 one byte over seg_cap_max", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_len_mask = 8;
	m.pre_len[3] = 0x7fffffffu;
	defect("segment 3 of 2 GiB", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, SEG_CAP_MAX, &c);
	/* a lie that is within the caps is no length error: the stream then fails its tags (the bytes are not what was announced) */
	m.pre_len_mask = 2;
	m.pre_len[1] = 10; /* 20 bytes are on the wire (two blocks), 10 announced (one block): everything after it is shifted */
	defect("segment 1 announced shorter", &four, &m, WR_E_M2_SEC_TAG, 1, SEG0_CAP, SEG_CAP_MAX, &c);
	m.pre_len[1] = 0xfffffff0u;
	defect("segment 1 of 4 GiB - 16 (padding would wrap)", &four, &m, WR_E_M2_FRAME_TOOBIG, 0, SEG0_CAP, 0xffffffffu, &c);

	/* exactly at the caps: fine (segment 0 at its buffer, a segment at seg_cap_max) */
	for (i = 0; i < 2; i++) {
		sxr_shape at = i == 0 ? shape(2, SEG0_CAP, 5, 0, 0) : shape(3, 10, SEG_CAP_MAX, 5, 0);
		sxr rig, *r = &rig;
		sxr_out o;
		sim_sec_ctx srv;
		wire w;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&at, NULL, 13, &srv);
		{
			sxr_cfg c2 = cfg_of(2, 500, 0);

			parse(&w, &c2, SEG0_CAP, SEG_CAP_MAX, r, &o);
		}
		WRT_CHECK(!o.errored && o.nframes == 1 && o.guard_bad == 0);
		done(r, &o);
		free(w.p);
		sim_sec_ctx_wipe(&srv);
	}

	/* a segment 0 that is discarded (no buffer) is capped by seg_cap_max instead, and passes through the scratch block */
	for (i = 0; i < 3; i++) {
		static const uint32_t l0[] = {300, 4999, 5001};
		sxr_shape sh = shape(2, l0[i], 5, 0, 0);
		sxr rig, *r = &rig;
		sxr_out o;
		sim_sec_ctx srv;
		sxr_cfg c2 = cfg_of(2, 90, 0);
		wire w;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&sh, NULL, 14, &srv);
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
		r->rx.sink[0].dst = NULL;
		r->rx.sink[0].cap = 0;
		sxr_run(r, w.p, w.n, &c2, &o);
		if (i < 2) {
			WRT_CHECK(!o.errored && o.nframes == 1 && o.fr[0].stored[0] == 0 && o.fr[0].stored[1] == 5 && o.guard_bad == 0);
		} else {
			WRT_CHECK(died_with(&o, WR_E_M2_FRAME_TOOBIG));
		}
		done(r, &o);
		free(w.p);
		sim_sec_ctx_wipe(&srv);
	}

	/* a DISCARDED segment 0 is capped only by seg_cap_max, so the padded length must not wrap either: 4 GiB - 16 is refused (seg_cap_max 4 GiB - 1) */
	{
		sxr rig, *r = &rig;
		sxr_out o;
		sim_sec_ctx srv;
		sxr_cfg c2 = cfg_of(0, 0, 0);
		wire w;

		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_PRE_LEN;
		m.pre_len_mask = 1;
		m.pre_len[0] = 0xfffffff0u;
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&two, &m, 17, &srv);
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, 0xffffffffu, RING), 0);
		r->rx.sink[0].dst = NULL;
		r->rx.sink[0].cap = 0;
		sxr_run(r, w.p, w.n, &c2, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_FRAME_TOOBIG) && !has_ev(&o, WRI_RXE_SEG0));
		done(r, &o);
		free(w.p);
		sim_sec_ctx_wipe(&srv);
	}

	/* a sink one byte short: refused at the step after SEG0, with the segment's number in the record */
	for (i = 1; i <= 3; i += 2) { /* segments 1 and 3; segment 2 of this shape is empty, and an empty segment needs no room */
		sxr_cfg c2 = cfg_of(0, 0, 0);

		c2.sink_mode[i] = SXR_SINK_SHORT;
		defect("sink one byte short", &four, NULL, WR_E_M2_FRAME_TOOBIG, 1, SEG0_CAP, SEG_CAP_MAX, &c2);
	}
	(void)three;

	/* the epilogue: only the low nibble counts; 1 is aborted (a frame, not an error), e is complete, anything else is a form error */
	{
		static const uint8_t bad[] = {0x00, 0x02, 0x03, 0x0d, 0x0f, 0x10, 0x30, 0x80, 0xe0, 0xf0, 0xff};
		static const uint8_t good[] = {0x0e, 0xfe, 0x1e, 0x01, 0xf1, 0x81};

		for (i = 0; i < sizeof(bad); i++) {
			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_LATE;
			m.late_status = bad[i];
			defect("bad late_status", &four, &m, WR_E_M2_FRAME_FORM, 1, SEG0_CAP, SEG_CAP_MAX, &c);
			defect("bad late_status (2 parts)", &two, &m, WR_E_M2_FRAME_FORM, 1, SEG0_CAP, SEG_CAP_MAX, &c);
		}
		for (i = 0; i < sizeof(good); i++) {
			sxr rig, *r = &rig;
			sxr_out o;
			sim_sec_ctx srv;
			wire w;

			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_LATE;
			m.late_status = good[i];
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
			w = enc(&four, &m, 15, &srv);
			parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
			WRT_CHECK(!o.errored && o.nframes == 1 && o.fr[0].ev == ((good[i] & 0x0f) == 1 ? WRI_RXE_ABORTED : WRI_RXE_FRAME));
			done(r, &o);
			free(w.p);
			sim_sec_ctx_wipe(&srv);
		}
	}

	/* A bit flipped in a frame that ALSO lies (a huge length, a bad CRC) is a tag failure: the lie was never looked at. */
	{
		sim_sec_mut mm;
		sim_sec_ctx srv;
		wire w;
		size_t b;

		for (i = 0; i < 2; i++) {
			memset(&mm, 0, sizeof(mm));
			if (i == 0) {
				mm.mask = SIM_SEC_M_PRE_LEN;
				mm.pre_len_mask = 2;
				mm.pre_len[1] = 0x7fffffffu;
			} else {
				mm.mask = SIM_SEC_M_PRE_CRC | SIM_SEC_M_PRE_NSEG;
				mm.pre_nseg = 9;
			}
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
			w = enc(&four, &mm, 16, &srv);
			for (b = 0; b < 96; b += 7) {
				sxr rig, *r = &rig;
				sxr_out o;

				w.p[b] ^= 0x01;
				parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
				WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG) && !has_ev(&o, WRI_RXE_SEG0));
				done(r, &o);
				w.p[b] ^= 0x01;
			}
			free(w.p);
			sim_sec_ctx_wipe(&srv);
		}
	}
}

/* ---- plaintext staging is wiped; a pending event keeps the window on the ring --------------------------------------------- */

static int all_canary_buf(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != SXR_CANARY)
			return 0;
	return 1;
}

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* The parser's staging (part 1 with the decrypted preamble, the scratch block, the tag) holds no plaintext it has no business keeping. */
static void test_staging_wiped(void)
{
	sxr_shape sh = shape(2, 20, 70, 0, 0);
	sxr_shape sh2 = shape(3, 100, 21, 33, 0);
	sim_sec_ctx srv;
	wire w;
	sxr rig, *r = &rig;
	sxr_out o;
	sxr_cfg c = cfg_of(0, 0, 0);
	size_t p1, s0, tot;

	/* part 1 verified and accepted: SEG0 is out, the 80 decrypted bytes are not kept; then the whole frame, released */
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	w = enc(&sh, NULL, 1, &srv);
	part_ends(&sh, &p1, &s0, &tot);
	c.stop_at = 96;
	parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
	WRT_CHECK(!o.errored && has_ev(&o, WRI_RXE_SEG0) && o.nframes == 0);
	WRT_CHECK(all_zero(r->slot.rx.p1, sizeof(r->slot.rx.p1)));
	c.stop_at = 0;
	sxr_run(r, w.p, w.n, &c, &o);
	WRT_CHECK(!o.errored && o.nframes == 1);
	WRT_CHECK(all_zero(r->slot.rx.p1, sizeof(r->slot.rx.p1)) && all_zero(r->slot.rx.blk, sizeof(r->slot.rx.blk)));
	done(r, &o);
	free(w.p);
	/* part 1 fails its tag: the decrypted (unauthenticated) preamble is wiped with the rest of the staging */
	sim_sec_ctx_wipe(&srv);
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	w = enc(&sh, NULL, 2, &srv);
	w.p[90] ^= 0x04;
	parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
	WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
	WRT_CHECK(all_zero(r->slot.rx.p1, sizeof(r->slot.rx.p1)) && all_zero(r->slot.rx.blk, sizeof(r->slot.rx.blk)) &&
		  all_zero(r->slot.rx.tag, sizeof(r->slot.rx.tag)));
	done(r, &o);
	free(w.p);
	/* part 3 fails its tag after the last partial blocks went through the scratch block */
	sim_sec_ctx_wipe(&srv);
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	w = enc(&sh2, NULL, 3, &srv);
	w.p[w.n - 3] ^= 0x10;
	parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
	WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
	WRT_CHECK(all_zero(r->slot.rx.p1, sizeof(r->slot.rx.p1)) && all_zero(r->slot.rx.blk, sizeof(r->slot.rx.blk)) &&
		  all_zero(r->slot.rx.tag, sizeof(r->slot.rx.tag)));
	done(r, &o);
	free(w.p);
	/* a failure behind a right tag (a bad epilogue nibble): the epilogue block is wiped too */
	{
		sim_sec_mut m;

		memset(&m, 0, sizeof(m));
		m.mask = SIM_SEC_M_LATE;
		m.late_status = 0x07;
		sim_sec_ctx_wipe(&srv);
		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&sh2, &m, 4, &srv);
		parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_FRAME_FORM));
		WRT_CHECK(all_zero(r->slot.rx.p1, sizeof(r->slot.rx.p1)) && all_zero(r->slot.rx.blk, sizeof(r->slot.rx.blk)));
		done(r, &o);
		free(w.p);
	}
	sim_sec_ctx_wipe(&srv);
}

/*
 * After SEG0 the owner chooses sinks, but until the next step() has checked them against the lengths the window is the ring, never a sink:
 * a sink that is too short must not receive a single byte (as in the crc parser), and a good one is filled only after that check.
 */
static void test_window_after_seg0(void)
{
	static const uint32_t L1 = 3000u;
	sxr_shape sh = shape(2, 20, L1, 0, 0);
	unsigned variant;

	for (variant = 0; variant < 3; variant++) {
		sim_sec_ctx srv;
		wire w;
		sxr rig, *r = &rig;
		uint8_t *sink, *p, *want;
		uint32_t cap = variant == 0 ? L1 - 1u : L1, b = 20u;
		size_t off = 0, k;
		wri_m2_rx_ev ev;
		int guard = 0;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		w = enc(&sh, NULL, 5, &srv);
		WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, 4096), 0);
		sink = (uint8_t *)malloc((size_t)cap + 64u);
		want = (uint8_t *)malloc(L1);
		memset(sink, SXR_CANARY, (size_t)cap + 64u);
		sxr_fill(want, L1, 1, 5);
		/* part 1 through the window, up to SEG0 */
		for (ev = WRI_RXE_NONE; ev != WRI_RXE_SEG0 && guard++ < 64;) {
			size_t n = wri_m2_rx_window(&r->rx, &r->ring, &p);

			if (n > 96u - off)
				n = 96u - off;
			if (n != 0) {
				memcpy(p, w.p + off, n);
				wri_m2_rx_commit(&r->rx, &r->ring, n);
				off += n;
			}
			ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, NULL, NULL, NULL);
		}
		WRT_CHECK(ev == WRI_RXE_SEG0);
		wri_m2_rx_sink(&r->rx, 1, sink, cap);
		/* the event is still pending: the window is the ring, and the bytes committed there stay out of the sink */
		for (k = 0; k < 2; k++) {
			size_t n = wri_m2_rx_window(&r->rx, &r->ring, &p);

			WRT_CHECK(n != 0 && p >= r->ringbuf && p < r->ringbuf + sizeof(r->ringbuf));
			if (n > 1500u)
				n = 1500u;
			if (n > w.n - off)
				n = w.n - off;
			memcpy(p, w.p + off, n);
			wri_m2_rx_commit(&r->rx, &r->ring, n);
			off += n;
		}
		WRT_CHECK(all_canary_buf(sink, (size_t)cap + 64u));
		ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, variant == 2 ? &b : NULL, NULL, NULL);
		if (variant == 2) { /* a budget that left bytes in the ring: the next window is still the ring, or the stream would be reordered */
			size_t n;

			WRT_CHECK(ev == WRI_RXE_NONE && r->ring.len != 0);
			n = wri_m2_rx_window(&r->rx, &r->ring, &p);
			WRT_CHECK(n != 0 && p >= r->ringbuf && p < r->ringbuf + sizeof(r->ringbuf));
		}
		if (variant == 0) {
			WRT_CHECK(ev == WRI_RXE_ERROR && wri_m2_rx_error(&r->rx)->status == WR_E_M2_FRAME_TOOBIG);
			WRT_CHECK(all_canary_buf(sink, (size_t)cap + 64u)); /* still nothing in it */
		} else {
			for (guard = 0; ev != WRI_RXE_FRAME && ev != WRI_RXE_ERROR && guard < 1000; guard++) {
				size_t n = wri_m2_rx_window(&r->rx, &r->ring, &p);

				if (n > w.n - off)
					n = w.n - off;
				if (n != 0) {
					memcpy(p, w.p + off, n);
					wri_m2_rx_commit(&r->rx, &r->ring, n);
					off += n;
				}
				ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, NULL, NULL, NULL);
			}
			WRT_CHECK(ev == WRI_RXE_FRAME && r->rx.stored[1] == L1);
			WRT_CHECK(memcmp(sink, want, L1) == 0);
		}
		free(sink);
		free(want);
		free(w.p);
		sxr_wipe(r);
		sim_sec_ctx_wipe(&srv);
	}
}

/* ---- ABORTED and FRAME wait for the owner ------------------------------------------------------------------------------- */

/* An aborted frame (the tag verified, the epilogue says "dropped") is sticky like a finished one: nothing of the next frame is taken from the
 * ring until the owner released it, and the next frame (nonces advanced over the aborted one) is parsed normally afterwards. */
static void test_aborted_is_sticky(void)
{
	sxr_shape sh = shape(2, 20, 70, 0, 0);
	sim_sec_ctx srv;
	sim_sec_mut m;
	wire a, b;
	sxr rig, *r = &rig;
	size_t before;
	uint32_t budget = 100000;
	wri_m2_rx_ev ev;
	unsigned i;

	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	memset(&m, 0, sizeof(m));
	m.mask = SIM_SEC_M_LATE;
	m.late_status = WRI_M2_LATE_ABORTED;
	a = enc(&sh, &m, 1, &srv);
	b = enc(&sh, NULL, 2, &srv);
	WRT_CHECK(a.p != NULL && b.p != NULL);
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
	WRT_CHECK_U64(wri_ring_write(&r->ring, a.p, (uint32_t)a.n), a.n);
	WRT_CHECK_U64(wri_ring_write(&r->ring, b.p, (uint32_t)b.n), b.n);
	ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_SEG0);
	ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_ABORTED);
	before = r->ring.len;
	for (i = 0; i < 3; i++) { /* the same answer, and not a byte of the next frame is touched */
		budget = 100000;
		WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL) == WRI_RXE_ABORTED);
		WRT_CHECK_U64(r->ring.len, before);
		WRT_CHECK_U64(budget, 100000);
	}
	wri_m2_rx_next_frame(&r->rx);
	ev = wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_SEG0);
	WRT_CHECK(wri_m2_rx_step(&r->rx, &r->ring, g_prim, &budget, NULL, NULL) == WRI_RXE_FRAME);
	free(a.p);
	free(b.p);
	sxr_wipe(r);
	sim_sec_ctx_wipe(&srv);
}

/* ---- no way back to crc: plaintext frames are never accepted once the parser is secure ---------------------------------- */

/*
 * A peer (or a man in the middle) that keeps talking crc after AUTH_DONE in secure mode: the first 96 bytes are read as part 1 and their
 * "tag" is not one, whatever the frame is made of. The frames are built by the core's own crc builder (the bytes a client would put on the
 * wire in crc mode), so a frame that was well formed in every crc sense is still refused. Fewer than 96 bytes (a short control frame, 68
 * bytes for an AUTH_SIGNATURE) is "need more", never an event: the downgrade cannot be completed by stopping early either.
 */
static size_t crc_bytes(const sxr_shape *sh, unsigned salt, uint8_t *out, size_t cap)
{
	uint8_t buf[2048];
	wri_m2_txq q;
	wri_m2_seg_src src[4];
	uint8_t data[4][600];
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, k, got = 0, i;

	wri_m2_txq_init(&q, buf, sizeof(buf));
	for (k = 0; k < sh->nseg; k++) {
		sxr_fill(data[k], sh->len[k], (unsigned)k, salt);
		src[k].p = data[k];
		src[k].len = sh->len[k];
		src[k].ref = 0;
	}
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, sh->tag, src, sh->nseg, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		WRT_CHECK(got + iov[i].len <= cap);
		memcpy(out + got, iov[i].base, iov[i].len);
		got += iov[i].len;
	}
	return got;
}

static void test_no_downgrade(void)
{
	sxr_shape shapes[4];
	unsigned k, m;

	shapes[0] = shape(1, 32, 0, 0, 0);    /* AUTH_SIGNATURE: 32 + 32 + 4 = 68 bytes in crc */
	shapes[1] = shape(2, 48, 100, 0, 0);  /* a message-like frame */
	shapes[2] = shape(1, 300, 0, 0, 0);
	shapes[3] = shape(4, 20, 10, 5, 90);
	for (k = 0; k < 4; k++) {
		uint8_t cw[4096];
		size_t cn = crc_bytes(&shapes[k], 3u + k, cw, sizeof(cw));

		WRT_CHECK(cn >= 64u);
		for (m = 0; m < 3; m++) {
			sxr_cfg c = m == 0 ? cfg_of(0, 0, 0) : (m == 1 ? cfg_of(1, 0, 0) : cfg_of(2, 50, 16));
			sxr rig, *r = &rig;
			sxr_out o;
			wire w;

			/* the crc frame alone: if it is shorter than a secure part 1 the parser waits, otherwise it dies on the tag */
			w.p = cw;
			w.n = cn;
			parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
			WRT_CHECK(o.nframes == 0 && !has_ev(&o, WRI_RXE_SEG0) && !has_ev(&o, WRI_RXE_FRAME) && o.order_bad == 0 && !o.stalled);
			if (cn >= WRI_M2S_P1_WIRE)
				WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG));
			else
				WRT_CHECK(!o.errored);
			done(r, &o);
			/* followed by more crc frames (a sender that never switches): the same */
			{
				uint8_t two[8192];

				memcpy(two, cw, cn);
				memcpy(two + cn, cw, cn);
				w.p = two;
				w.n = 2u * cn;
				parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
				WRT_CHECK(died_with(&o, WR_E_M2_SEC_TAG) && !has_ev(&o, WRI_RXE_SEG0));
				done(r, &o);
			}
		}
	}
}

/* ---- garbage in the padding ----------------------------------------------------------------------------- */

static void test_padding(void)
{
	static const uint8_t fills[] = {0x00, 0xab, 0xff};
	sxr_shape shapes[6];
	unsigned k, f;

	shapes[0] = shape(1, 5, 0, 0, 0);
	shapes[1] = shape(1, 30, 0, 0, 0);
	shapes[2] = shape(2, 100, 20, 0, 0);
	shapes[3] = shape(4, 41, 3, 0, 1000);
	shapes[4] = shape(3, 0, 17, 15, 0);
	shapes[5] = shape(4, 70, 1, 1, 33);
	for (k = 0; k < 6; k++) {
		for (f = 0; f < (g_light ? 1u : 3u); f++) {
			sim_sec_mut m;
			sim_sec_ctx srv;
			sxr_frame_src src;
			sxr rig, *r = &rig;
			sxr_out o;
			wire w;
			unsigned i;
			sxr_cfg c = cfg_of(2, 77, 0);

			memset(&m, 0, sizeof(m));
			m.mask = SIM_SEC_M_PAD;
			m.pad_fill = fills[f];
			c.sink_mode[1] = SXR_SINK_BIG; /* 50 bytes of room behind the data: the padding must not land there (guard check) */
			c.sink_mode[2] = SXR_SINK_BIG;
			c.sink_mode[3] = SXR_SINK_BIG;
			WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
			sxr_src_make(&src, &shapes[k], 20u + k);
			w.p = sxr_encode(&srv.tx, &src.spec, &m, &w.n);
			WRT_CHECK(w.p != NULL);
			parse(&w, &c, SEG0_CAP, SEG_CAP_MAX, r, &o);
			WRT_CHECK(!o.errored && o.nframes == 1 && o.guard_bad == 0 && o.order_bad == 0);
			if (o.nframes == 1) {
				WRT_CHECK(shapes[k].len[0] == 0 || memcmp(o.fr[0].seg[0], src.data[0], shapes[k].len[0]) == 0);
				for (i = 1; i < shapes[k].nseg; i++)
					WRT_CHECK(memcmp(o.fr[0].seg[i], src.data[i], shapes[k].len[i]) == 0 && o.fr[0].stored[i] == shapes[k].len[i]);
			}
			done(r, &o);
			sxr_src_free(&src);
			free(w.p);
			sim_sec_ctx_wipe(&srv);
		}
	}
}

/* ---- truncation at every offset ------------------------------------------------------------------------- */

static void truncate_case(const sxr_shape *sh, const sxr_frame_src *src, const wire *w, size_t t, const sxr_cfg *c)
{
	size_t p1, s0, tot;
	sxr rig, *r = &rig;
	sxr_out o;
	sxr_cfg c1 = *c;
	int ok, seg0_seen;

	part_ends(sh, &p1, &s0, &tot);
	memset(&o, 0, sizeof(o));
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
	c1.stop_at = t;
	sxr_run(r, w->p, w->n, &c1, &o);
	seg0_seen = has_ev(&o, WRI_RXE_SEG0);
	ok = !o.errored && !o.stalled && o.guard_bad == 0 && o.order_bad == 0 && o.hidden_bad == 0 && o.nframes == 0 && !has_ev(&o, WRI_RXE_FRAME) && seg0_seen == (t >= s0);
	/* before the first tag verified, nothing of segment 0 is in its buffer; the whole buffer is still the canary */
	if (ok && t < p1)
		ok = sxr_all_canary(r->seg0, SXR_SEG0_MAX) && r->rx.stored[0] == 0;
	WRT_CHECK(ok);
	if (!ok) {
		fprintf(stderr, "  [truncate at %zu of %zu, seg0 ends %zu] errored %d err %d seg0 %d frames %u order %u guard %u\n", t, w->n, s0, o.errored,
			(int)o.err, seg0_seen, o.nframes, o.order_bad, o.guard_bad);
		done(r, &o);
		return;
	}
	/* and the rest of the frame completes it, from any cut */
	c1.stop_at = 0;
	sxr_run(r, w->p, w->n, &c1, &o);
	ok = !o.errored && !o.stalled && o.nframes == 1 && o.guard_bad == 0 && o.order_bad == 0 && o.fed == w->n;
	if (ok) {
		unsigned i;

		ok = (sh->len[0] == 0 || memcmp(o.fr[0].seg[0], src->data[0], sh->len[0]) == 0);
		for (i = 1; ok && i < sh->nseg; i++)
			ok = memcmp(o.fr[0].seg[i], src->data[i], sh->len[i]) == 0 && o.fr[0].stored[i] == sh->len[i];
	}
	WRT_CHECK(ok);
	if (!ok)
		fprintf(stderr, "  [resume after a cut at %zu of %zu] errored %d err %d frames %u\n", t, w->n, o.errored, (int)o.err, o.nframes);
	done(r, &o);
}

static void test_truncation(void)
{
	sxr_shape shapes[5];
	unsigned k;

	shapes[0] = shape(1, 30, 0, 0, 0);
	shapes[1] = shape(1, 100, 0, 0, 0);
	shapes[2] = shape(2, 20, 70, 0, 0);
	shapes[3] = shape(4, 100, 40, 0, 20);
	shapes[4] = shape(3, 60, 1100, 33, 0);
	for (k = 0; k < (g_light ? 3u : 5u); k++) {
		sim_sec_ctx srv;
		sxr_frame_src src;
		wire w;
		size_t t;
		unsigned m;

		WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
		sxr_src_make(&src, &shapes[k], 30u + k);
		w.p = sxr_encode(&srv.tx, &src.spec, NULL, &w.n);
		WRT_CHECK(w.p != NULL);
		for (m = 0; m < (g_light ? 1u : 2u); m++) {
			sxr_cfg c = m == 0 ? cfg_of(0, 0, 0) : cfg_of(3, 13, 0);

			for (t = 1; t < w.n; t += (k == 4 && !g_light ? 3u : 1u))
				truncate_case(&shapes[k], &src, &w, t, &c);
			/* and exactly one byte before the end of each tag, where an off-by-one would let plaintext out */
			{
				size_t p1, s0, tot;

				part_ends(&shapes[k], &p1, &s0, &tot);
				truncate_case(&shapes[k], &src, &w, p1 - 1u, &c);
				truncate_case(&shapes[k], &src, &w, s0 - 1u, &c);
				truncate_case(&shapes[k], &src, &w, tot - 1u, &c);
			}
		}
		free(w.p);
		sxr_src_free(&src);
		sim_sec_ctx_wipe(&srv);
	}
}

/* ---- nonce limits and the wrap guard ---------------------------------------------------------------------- */

static void test_nonce_limits(void)
{
	/* operations: 1, 2 (parts 1 and 3), 3, 1 = 7 in total */
	sxr_shape plan[4];
	sim_sec_ctx srv;
	sxr_frame_src src[4];
	wire ws[4], all;
	unsigned ops[4] = {1, 2, 3, 1}, i, limit, upto;
	size_t off = 0;

	plan[0] = shape(1, 30, 0, 0, 0);
	plan[1] = shape(2, 20, 70, 0, 0);
	plan[2] = shape(4, 100, 40, 0, 20);
	plan[3] = shape(1, 8, 0, 0, 0);
	WRT_CHECK(sim_sec_ctx_init(&srv, g_secret, sizeof(g_secret), 1) == 0);
	all.n = 0;
	for (i = 0; i < 4; i++) {
		sxr_src_make(&src[i], &plan[i], 60u + i);
		ws[i].p = sxr_encode(&srv.tx, &src[i].spec, NULL, &ws[i].n);
		all.n += ws[i].n;
	}
	all.p = (uint8_t *)malloc(all.n);
	for (i = 0; i < 4; i++) {
		memcpy(all.p + off, ws[i].p, ws[i].n);
		off += ws[i].n;
	}
	for (limit = 0; limit <= 8; limit++) {
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg_of(2, 90, 0);
		unsigned total = 0, frames_ok = 0, k;
		int ok;

		/* the frames that fit entirely under the limit */
		for (k = 0; k < 4 && (limit == 0 || total + ops[k] <= limit); k++) {
			total += ops[k];
			frames_ok++;
		}
		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
		r->slot.s.ops_limit = limit; /* 0 = none */
		sxr_run(r, all.p, all.n, &c, &o);
		if (limit == 0 || limit >= 7) {
			ok = !o.errored && o.nframes == 4 && r->slot.s.rx_n.ops == 7;
		} else {
			/* the operation after the limit is refused: before any plaintext of it exists, and nothing after it is delivered */
			int seg0_ok;

			upto = limit - total; /* operations of the cut frame that did run */
			seg0_ok = (plan[frames_ok].len[0] > 48) ? (upto >= 2) : (upto >= 1);
			ok = o.errored && o.err == WR_E_M2_NONCE && o.nframes == frames_ok && r->slot.s.rx_n.ops == limit && o.order_bad == 0 &&
			     !o.stalled && o.guard_bad == 0;
			/* SEG0 of the frame that was cut comes only if the operation that carries segment 0 ran; then the ERROR */
			ok = ok && o.nev == 2u * frames_ok + (seg0_ok ? 2u : 1u);
			/* the refused operation produced nothing: the cut frame's sinks hold no plaintext */
			if (ok && seg0_ok && plan[frames_ok].nseg > 1)
				ok = r->rx.stored[1] == 0 && r->rx.stored[2] == 0 && r->rx.stored[3] == 0;
		}
		WRT_CHECK(ok);
		if (!ok)
			fprintf(stderr, "  [limit %u] errored %d err %d frames %u (want %u) ops %llu nev %u\n", limit, o.errored, (int)o.err, o.nframes,
				frames_ok, (unsigned long long)r->slot.s.rx_n.ops, o.nev);
		done(r, &o);
	}
	/* back at the seed after a start: the counter went all the way round: the next operation is refused, before anything is decrypted */
	{
		sxr rig, *r = &rig;
		sxr_out o;
		sxr_cfg c = cfg_of(0, 0, 0);

		memset(&o, 0, sizeof(o));
		WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
		r->slot.s.rx_n.started = 1; /* cur == seed and started: what 2^64 takes would leave */
		sxr_run(r, ws[0].p, ws[0].n, &c, &o);
		WRT_CHECK(died_with(&o, WR_E_M2_NONCE) && !has_ev(&o, WRI_RXE_SEG0));
		WRT_CHECK_U64(r->slot.s.rx_n.ops, 0);
		done(r, &o);
	}
	free(all.p);
	for (i = 0; i < 4; i++) {
		free(ws[i].p);
		sxr_src_free(&src[i]);
	}
	sim_sec_ctx_wipe(&srv);
}

/* ---- a parser that was never set up ------------------------------------------------------------------------ */

static void test_not_set_up(void)
{
	sxr rig, *r = &rig;
	sxr_out o;
	sxr_cfg c = cfg_of(0, 0, 0);
	uint8_t junk[200];

	memset(junk, 0x5a, sizeof(junk));
	/* the state byte is zero: the parser has not been through wri_m2s_rx_next() */
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
	r->slot.rx.state = 0;
	memset(&o, 0, sizeof(o));
	sxr_run(r, junk, sizeof(junk), &c, &o);
	WRT_CHECK(died_with(&o, WR_E_STATE));
	done(r, &o);
	/* the connection state is inactive (wiped under the parser's feet) */
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
	r->slot.s.active = 0;
	memset(&o, 0, sizeof(o));
	sxr_run(r, junk, sizeof(junk), &c, &o);
	WRT_CHECK(died_with(&o, WR_E_STATE));
	done(r, &o);
	/* a parser whose slot has no connection state at all */
	WRT_CHECK_U64(sxr_init(r, g_prim, g_secret, sizeof(g_secret), 0, SEG0_CAP, SEG_CAP_MAX, RING), 0);
	r->slot.rx.s = NULL;
	memset(&o, 0, sizeof(o));
	sxr_run(r, junk, sizeof(junk), &c, &o);
	WRT_CHECK(died_with(&o, WR_E_STATE));
	done(r, &o);
}

static void pass_all(const char *name, const wr_prim_ops *prim, int light)
{
	g_prim = prim;
	g_light = light;
	printf("pass %s%s\n", name, light ? " (reduced matrix)" : "");
	test_bit_flips();
	test_no_resync();
	test_no_downgrade();
	test_staging_wiped();
	test_aborted_is_sticky();
	test_window_after_seg0();
	test_nonce_attacks();
	test_behind_the_tag();
	test_padding();
	test_truncation();
	test_nonce_limits();
	test_not_set_up();
}

int main(void)
{
	const char *env = getenv("WRT_GCM_ACCEL");
	wr_prim_ops accel;
	int want_accel = env == NULL || strcmp(env, "0") != 0;

	sxr_secret(g_secret, 2);
	pass_all("portable", NULL, 0);
	if (want_accel && wrl_gcm_aesni_available() && wrl_gcm_aesni_ops(&accel) == 0)
		pass_all("accelerated", &accel, env != NULL && strcmp(env, "1") == 0 ? 0 : 1);
	return wrt_finish();
}
