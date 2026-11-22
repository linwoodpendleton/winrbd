/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_switch - the switch from crc to secure framing: wri_m2_secure_on / wri_m2_secure_off (core/src/msgr2/wri_m2_sec.c,
 * design 34.4), driven against the real crc receive parser and transmit queue.
 *
 * What is checked:
 *   - on success both seam pointers are bound to the slot's halves, the slot's state is derived from the secret (seeds, limit, both
 *     GCM directions keyed), the bounce buffer and its size are bound, the offer the connection stored in the slot is kept, the
 *     previous contents of the rest of the slot are ignored (a slot full of garbage works), the bounce buffer is not written, and a
 *     crc frame that was still queued is left exactly as it was (the switch does not require an empty queue);
 *   - the parser must be at a frame boundary: before the banner, mid-preamble, after the preamble, mid-segment (ring and direct
 *     window not involved: bytes taken), with SEG0 or FRAME not yet released, and dead: WR_E_STATE, both sides stay crc, the slot is
 *     all zero; at a boundary it works: after the banner, after a released frame, after an aborted frame released, with the next
 *     frame's first bytes already sitting in the ring (they are not parsed by the switch);
 *   - every field of the boundary rule on its own: a parser at a clean boundary with ONLY one field off (each state but the one waiting for
 *     a preamble, `seg`, `seg_pos`, `direct`, each pending event) is refused; the redundancy between those fields in reachable states
 *     must not hide a missing check;
 *   - a second call (same slot, or another slot) is WR_E_STATE and touches nothing: the live slot is byte for byte what it was, the
 *     other slot keeps its contents;
 *   - the bounce buffer: NULL, 0, 16, 240, 255, 257, a size that is not a multiple of 16: WR_E_INVAL, slot zero; 256, 272, 4096, 65536 work;
 *   - the secret: NULL, 39, 129 bytes, equal seeds: WR_E_M2_SECRET, slot zero, both sides crc; a host that refuses the key: its status;
 *     a host override is used for both directions and released by secure_off;
 *   - one side bound and not the other (parser bound, queue not; queue bound, parser not): WR_E_STATE, nothing touched;
 *   - the secure parser's own first-frame state is the one wri_m2s_rx_next() leaves (a reference slot is driven through it and compared);
 *   - the order of the checks: arguments, already switched, bounce, frame boundary, secret;
 *   - NULL rx, q or slot: WR_E_INVAL without a crash;
 *   - wri_m2_secure_off: clears the seam pointers of this slot only, zeroes the slot (also after it was "used": scribbled halves) and the
 *     bounce buffer (its size, not a byte more), releases the host key objects, is safe twice, on a slot that never switched, with
 *     NULL, and the slot can be used for a new connection afterwards.
 * The receive stream is built with the real crc builder, so what the parser stands on is a real banner and real frames.
 */
#include "wrt.h"

#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_m2_modes.h"
#include "wri_m2_sec.h"

#define SEG0_CAP 4096u
#define SEG_MAX 100000u
#define BOUNCE_BYTES 1024u

/* ---- the rig ------------------------------------------------------------------------------------ */

typedef struct rig {
	wri_m2_rx rx;
	wri_ring ring;
	uint8_t ringbuf[2048];
	uint8_t seg0[SEG0_CAP];
	wri_m2_txq q;
	uint8_t enc[512];
	wri_m2s_slot slot;
	uint8_t bounce[BOUNCE_BYTES];
	uint8_t secret[64];
} rig;

static int all_byte(const void *p, size_t n, uint8_t v)
{
	const uint8_t *b = (const uint8_t *)p;
	size_t i;

	for (i = 0; i < n; i++)
		if (b[i] != v)
			return 0;
	return 1;
}

static void rig_init(rig *r)
{
	size_t i;

	memset(r, 0, sizeof(*r));
	wri_m2_rx_init(&r->rx, r->seg0, SEG0_CAP, SEG_MAX);
	wri_ring_init(&r->ring, r->ringbuf, sizeof(r->ringbuf));
	wri_m2_txq_init(&r->q, r->enc, sizeof(r->enc));
	for (i = 0; i < sizeof(r->secret); i++)
		r->secret[i] = (uint8_t)i; /* the synthetic secret 00 .. 3f of the vector file */
	memset(r->bounce, 0xcd, sizeof(r->bounce));
}

/* The bytes of a crc frame, made by the real builder. */
static size_t crc_frame(uint8_t *out, size_t cap, uint8_t tag, unsigned nseg, uint32_t l0, uint32_t l1)
{
	static uint8_t data[8192];
	uint8_t enc[16384];
	wri_m2_txq q;
	wri_m2_seg_src s[4];
	wr_iov iov[WRI_M2_TXQ_IOV];
	size_t n, i, total = 0;

	memset(data, 0x42, sizeof(data));
	memset(s, 0, sizeof(s));
	s[0].p = data;
	s[0].len = l0;
	s[1].p = data + 100;
	s[1].len = l1;
	wri_m2_txq_init(&q, enc, sizeof(enc));
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&q, NULL, tag, s, nseg, NULL, NULL));
	n = wri_m2_txq_peek(&q, iov, WRI_M2_TXQ_IOV);
	for (i = 0; i < n; i++) {
		if (total + iov[i].len > cap)
			return 0;
		memcpy(out + total, iov[i].base, iov[i].len);
		total += iov[i].len;
	}
	return total;
}

static size_t banner_bytes(uint8_t *out)
{
	wri_m2_banner_build(out);
	wri_le64_put(out + 10, 3); /* what a stock daemon sends */
	return WRI_M2_BANNER_LEN;
}

/* Feed bytes (they must fit the ring) and step until the parser has nothing more to say; returns the last event. */
static wri_m2_rx_ev feed(rig *r, const uint8_t *p, size_t n)
{
	wri_m2_rx_ev ev = WRI_RXE_NONE;

	WRT_CHECK(wri_ring_write(&r->ring, p, (uint32_t)n) == n);
	for (;;) {
		wri_m2_rx_ev e = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);

		if (e == WRI_RXE_NONE)
			return ev;
		ev = e;
		if (e == WRI_RXE_SEG0 || e == WRI_RXE_FRAME || e == WRI_RXE_ABORTED || e == WRI_RXE_ERROR)
			return ev;
	}
}

/* Release events until the parser is between frames; returns 0 when it ended without error. */
static void release_frame(rig *r)
{
	wri_m2_rx_ev ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);

	if (ev == WRI_RXE_SEG0)
		ev = wri_m2_rx_step(&r->rx, &r->ring, NULL, NULL, NULL, NULL);
	WRT_CHECK(ev == WRI_RXE_FRAME || ev == WRI_RXE_ABORTED);
	wri_m2_rx_next_frame(&r->rx);
}

/* Banner and one complete frame, released: the state after AUTH_DONE has been processed. */
static void rig_at_boundary(rig *r)
{
	uint8_t b[256];
	size_t n = banner_bytes(b);

	WRT_CHECK(feed(r, b, n) == WRI_RXE_BANNER); /* the banner event is the last event feed saw */
	n = crc_frame(b, sizeof(b), WRI_M2_TAG_AUTH_DONE, 1, 36, 0);
	WRT_CHECK(n > 0u);
	(void)feed(r, b, n);
	release_frame(r);
	WRT_CHECK(r->rx.state == WRI_RX_PREAMBLE && r->rx.seg_pos == 0u && r->rx.pending_ev == WRI_RXE_NONE);
}

static wr_status do_on(rig *r, const wr_prim_ops *prim, size_t secret_len, uint32_t bounce_cap)
{
	return wri_m2_secure_on(&r->rx, &r->q, &r->slot, prim, r->secret, secret_len, r->bounce, bounce_cap);
}

static void check_crc_and_zero(const rig *r)
{
	WRT_CHECK(r->rx.sx == NULL && r->q.sx == NULL);
	WRT_CHECK(all_byte(&r->slot, sizeof(r->slot), 0));
}

/* ---- host spy -------------------------------------------------------------------------------------- */

typedef struct spy {
	unsigned setkeys, wipes;
	unsigned fail_at;
	wr_status fail_status;
	void *states[4];
	void *wiped[8];
} spy;

static wr_status sp_setkey(void *ctx, void *state, const uint8_t key[16])
{
	spy *sp = (spy *)ctx;
	unsigned k = sp->setkeys++;

	if (k < 4u)
		sp->states[k] = state;
	if (sp->fail_at != 0u && sp->setkeys == sp->fail_at)
		return sp->fail_status;
	memcpy(state, key, 16);
	return WR_OK;
}

static wr_status sp_start(void *ctx, void *state, const uint8_t iv[12], int decrypt)
{
	(void)ctx;
	(void)state;
	(void)iv;
	(void)decrypt;
	return WR_OK;
}

static void sp_update(void *ctx, void *state, const uint8_t *in, uint8_t *out, size_t n)
{
	(void)ctx;
	(void)state;
	(void)in;
	(void)out;
	(void)n;
}

static void sp_final_enc(void *ctx, void *state, uint8_t tag[16])
{
	(void)ctx;
	(void)state;
	memset(tag, 0, 16);
}

static wr_status sp_final_dec(void *ctx, void *state, const uint8_t tag[16])
{
	(void)ctx;
	(void)state;
	(void)tag;
	return WR_OK;
}

static void sp_wipe(void *ctx, void *state)
{
	spy *sp = (spy *)ctx;

	if (sp->wipes < 8u)
		sp->wiped[sp->wipes] = state;
	sp->wipes++;
	memset(state, 0, 16);
}

static void spy_table(wr_prim_ops *t, spy *sp)
{
	memset(t, 0, sizeof(*t));
	t->size = (uint32_t)sizeof(*t);
	t->ctx = sp;
	t->gcm_state_bytes = 16u;
	t->gcm_setkey = sp_setkey;
	t->gcm_start = sp_start;
	t->gcm_update = sp_update;
	t->gcm_final_enc = sp_final_enc;
	t->gcm_final_dec = sp_final_dec;
	t->gcm_wipe = sp_wipe;
}

/* ---- tests ---------------------------------------------------------------------------------------- */

static void test_success(void)
{
	static rig r;
	size_t sz;

	rig_init(&r);
	rig_at_boundary(&r);
	r.slot.offer = WRI_M2_OFFER_SECURE; /* stored by the connection when it built AUTH_REQUEST */
	memset(&r.slot.s, 0xab, sizeof(r.slot.s)); /* the rest of the slot is garbage: ignored */
	memset(&r.slot.rx, 0xab, sizeof(r.slot.rx));
	memset(&r.slot.tx, 0xab, sizeof(r.slot.tx));
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	WRT_CHECK(r.rx.sx == &r.slot.rx && r.q.sx == &r.slot.tx);
	WRT_CHECK(r.slot.s.active == 1u && r.slot.s.tx.keyed == 1u && r.slot.s.rx.keyed == 1u);
	WRT_CHECK_MEM(r.slot.s.tx_n.seed, r.secret + 28, 12); /* the client: transmits with seed B */
	WRT_CHECK_MEM(r.slot.s.rx_n.seed, r.secret + 16, 12);
	WRT_CHECK(r.slot.s.tx_n.ops == 0u && r.slot.s.rx_n.ops == 0u && r.slot.s.ops_limit == WRI_M2S_OPS_LIMIT_DEFAULT);
	WRT_CHECK(r.slot.rx.s == &r.slot.s && r.slot.tx.s == &r.slot.s);
	WRT_CHECK(r.slot.tx.bounce == r.bounce && r.slot.tx.bounce_cap == 256u);
	WRT_CHECK(r.slot.tx.stream_left == 0u && r.slot.tx.phase == 0u && r.slot.tx.b_len == 0u && r.slot.tx.b_off == 0u);
	WRT_CHECK(r.slot.rx.op_open == 0u && r.slot.rx.pos == 0u); /* no operation open, nothing taken; the state byte itself is wri_m2s_rx_next()'s (test_rx_next_applied) */
	WRT_CHECK(r.slot.offer == WRI_M2_OFFER_SECURE); /* the offer is the connection's, not ours */
	WRT_CHECK(all_byte(r.bounce, sizeof(r.bounce), 0xcd)); /* the bounce buffer was not written */
	sz = wri_m2s_slot_bytes();
	WRT_CHECK(sz == sizeof(wri_m2s_slot) && sz <= 2048u);
	printf("sizeof(wri_m2s_slot) = %zu\n", sz);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
	WRT_CHECK(all_byte(r.bounce, 256, 0) && all_byte(r.bounce + 256, sizeof(r.bounce) - 256u, 0xcd));
}

static void test_queued_crc_frame_is_untouched(void)
{
	static rig r;
	wri_m2_seg_src s;
	uint8_t data[40];
	wr_iov before[WRI_M2_TXQ_IOV];
	size_t nb;
	uint8_t copy[512];
	uint64_t pending;
	uint32_t used;

	rig_init(&r);
	rig_at_boundary(&r);
	memset(data, 0x11, sizeof(data));
	memset(&s, 0, sizeof(s));
	s.p = data;
	s.len = sizeof(data);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&r.q, NULL, WRI_M2_TAG_HELLO, &s, 1, NULL, NULL));
	nb = wri_m2_txq_peek(&r.q, before, WRI_M2_TXQ_IOV);
	WRT_CHECK(nb >= 1u && r.q.pending > 0u);
	memcpy(before, r.q.iov, sizeof(before));
	memcpy(copy, r.enc, sizeof(copy));
	pending = r.q.pending;
	used = r.q.used;
	/* the host has consumed a few bytes of it already, then the connection switches */
	wri_m2_txq_consume(&r.q, 5);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	WRT_CHECK(r.q.pending == pending - 5u && r.q.used == used && r.q.niov == nb);
	WRT_CHECK(r.q.iov[0].base == before[0].base + 5 && r.q.iov[0].len + 5u == before[0].len);
	WRT_CHECK(memcmp(copy, r.enc, sizeof(copy)) == 0);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
}

static void test_frame_boundary(void)
{
	static rig r;
	uint8_t b[512], f[512];
	size_t nb, nf;
	size_t cut;

	/* before the banner, in the banner, between banner and first frame (a boundary: the banner is done) */
	rig_init(&r);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	nb = banner_bytes(b);
	WRT_CHECK(feed(&r, b, 5) == WRI_RXE_NONE);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	(void)feed(&r, b + 5, nb - 5u);
	/* right after the banner event the parser waits for a preamble with nothing taken: a boundary */
	WRT_CHECK(r.rx.state == WRI_RX_PREAMBLE && r.rx.seg_pos == 0u);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);

	/* after half a frame, at every cut point of a short frame that is not 0 or the end: not a boundary */
	nf = crc_frame(f, sizeof(f), WRI_M2_TAG_AUTH_DONE, 1, 36, 0);
	WRT_CHECK(nf == 32u + 36u + 4u);
	for (cut = 1; cut < nf; cut++) {
		rig_init(&r);
		(void)feed(&r, b, nb);
		(void)feed(&r, f, cut);
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
		check_crc_and_zero(&r);
		/* and the same parser works once the frame is complete and released */
		(void)feed(&r, f + cut, nf - cut);
		release_frame(&r);
		WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
		wri_m2_secure_off(&r.rx, &r.q, &r.slot);
		check_crc_and_zero(&r);
	}

	/* FRAME event not yet released (the switch must come after wri_m2_rx_next_frame) */
	rig_init(&r);
	(void)feed(&r, b, nb);
	WRT_CHECK(feed(&r, f, nf) == WRI_RXE_SEG0);
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	WRT_CHECK(wri_m2_rx_step(&r.rx, &r.ring, NULL, NULL, NULL, NULL) == WRI_RXE_FRAME);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	wri_m2_rx_next_frame(&r.rx);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);

	/* in the middle of a multi-segment frame (segment 1 half in) and with the bytes of the next frame already in the ring */
	{
		uint8_t g[1024];
		size_t ng = crc_frame(g, sizeof(g), WRI_M2_TAG_MESSAGE, 2, 41, 300);

		WRT_CHECK(ng > 0u);
		rig_init(&r);
		(void)feed(&r, b, nb);
		(void)feed(&r, g, 32u + 41u + 4u + 100u);
		WRT_CHECK(r.rx.state == WRI_RX_SEGS || r.rx.pending_ev == WRI_RXE_SEG0);
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
		check_crc_and_zero(&r);
		/* complete frame, released, then two bytes of the next one sit in the ring unparsed: still a boundary */
		rig_init(&r);
		(void)feed(&r, b, nb);
		(void)feed(&r, g, ng);
		release_frame(&r);
		WRT_CHECK(wri_ring_write(&r.ring, g, 2) == 2u); /* not stepped: the owner has not run the parser yet */
		WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
		WRT_CHECK(r.ring.len == 2u); /* the switch took nothing from the ring */
		wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	}

	/* an aborted frame, released, is a boundary too */
	{
		uint8_t g[1024];
		size_t ng = crc_frame(g, sizeof(g), WRI_M2_TAG_MESSAGE, 2, 41, 100);

		g[ng - 13] = 0x01; /* late status: aborted */
		rig_init(&r);
		(void)feed(&r, b, nb);
		(void)feed(&r, g, ng);
		release_frame(&r);
		WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
		wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	}

	/* a dead parser (a hostile preamble) is not a boundary */
	rig_init(&r);
	(void)feed(&r, b, nb);
	memset(f, 0x77, 32);
	WRT_CHECK(feed(&r, f, 32) == WRI_RXE_ERROR);
	WRT_CHECK(r.rx.state == WRI_RX_DEAD);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
}

static void test_twice(void)
{
	static rig r;
	static wri_m2s_slot other;
	wri_m2s_slot snap, other_snap;

	rig_init(&r);
	rig_at_boundary(&r);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	memcpy(&snap, &r.slot, sizeof(snap));
	/* the same slot again: refused, the live slot is byte for byte what it was, the seam stays bound */
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	WRT_CHECK(memcmp(&snap, &r.slot, sizeof(snap)) == 0);
	WRT_CHECK(r.rx.sx == &r.slot.rx && r.q.sx == &r.slot.tx);
	/* another slot: refused and not touched either */
	memset(&other, 0xab, sizeof(other));
	memcpy(&other_snap, &other, sizeof(other));
	WRT_CHECK_STATUS(WR_E_STATE, wri_m2_secure_on(&r.rx, &r.q, &other, NULL, r.secret, 64, r.bounce, 256));
	WRT_CHECK(memcmp(&other_snap, &other, sizeof(other)) == 0);
	WRT_CHECK(memcmp(&snap, &r.slot, sizeof(snap)) == 0);
	WRT_CHECK(r.rx.sx == &r.slot.rx && r.q.sx == &r.slot.tx);
	/* only one side bound (cannot happen through the API; the switch still refuses and touches nothing) */
	r.q.sx = NULL;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	WRT_CHECK(memcmp(&snap, &r.slot, sizeof(snap)) == 0);
	r.q.sx = &r.slot.tx;
	/* off, then on again with the same slot works, and the new state is fresh */
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	WRT_CHECK(r.slot.s.tx_n.ops == 0u && r.slot.s.active == 1u);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
}

static void test_bounce(void)
{
	static rig r;
	static const uint32_t bad[] = {0, 1, 15, 16, 32, 240, 255, 257, 271, 273, 1000, 4097, 0xffffffffu};
	static const uint32_t good[] = {256, 272, 512, 1024};
	size_t i;

	rig_init(&r);
	rig_at_boundary(&r);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_INVAL, do_on(&r, NULL, 64, bad[i]));
		check_crc_and_zero(&r);
	}
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_secure_on(&r.rx, &r.q, &r.slot, NULL, r.secret, 64, NULL, 256));
	check_crc_and_zero(&r);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_secure_on(&r.rx, &r.q, &r.slot, NULL, r.secret, 64, NULL, 0));
	check_crc_and_zero(&r);
	for (i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
		WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, good[i]));
		WRT_CHECK(r.slot.tx.bounce_cap == good[i]);
		wri_m2_secure_off(&r.rx, &r.q, &r.slot);
		check_crc_and_zero(&r);
	}
	/* a big bounce buffer (the harness profile's size) */
	{
		static uint8_t big[65536];

		memset(big, 0xcd, sizeof(big));
		WRT_CHECK_STATUS(WR_OK, wri_m2_secure_on(&r.rx, &r.q, &r.slot, NULL, r.secret, 64, big, 65536));
		wri_m2_secure_off(&r.rx, &r.q, &r.slot);
		WRT_CHECK(all_byte(big, sizeof(big), 0));
	}
}

static void test_secret_errors(void)
{
	static rig r;
	static const size_t bad[] = {0, 1, 39, 129, 200, (size_t)-1};
	size_t i;

	rig_init(&r);
	rig_at_boundary(&r);
	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_M2_SECRET, do_on(&r, NULL, bad[i], 256));
		check_crc_and_zero(&r);
	}
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_M2_SECRET, wri_m2_secure_on(&r.rx, &r.q, &r.slot, NULL, NULL, 64, r.bounce, 256));
	check_crc_and_zero(&r);
	memcpy(r.secret + 28, r.secret + 16, 12); /* equal seeds */
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_M2_SECRET, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	WRT_CHECK_STATUS(WR_E_M2_SECRET, do_on(&r, NULL, 40, 256));
	check_crc_and_zero(&r);
	WRT_CHECK(all_byte(r.bounce, sizeof(r.bounce), 0xcd)); /* nothing was written there */
	/* the parser is still usable after the refusal: fix the secret and switch */
	r.secret[16] ^= 1u;
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
}

static void test_check_order(void)
{
	static rig r;

	rig_init(&r);
	/* not at a boundary (fresh parser), bad bounce, bad secret: the bounce comes first, then the boundary, then the secret */
	WRT_CHECK_STATUS(WR_E_INVAL, do_on(&r, NULL, 5, 100));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 5, 256));
	rig_at_boundary(&r);
	WRT_CHECK_STATUS(WR_E_M2_SECRET, do_on(&r, NULL, 5, 256));
	/* the arguments: NULL rx, q, slot */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_secure_on(NULL, &r.q, &r.slot, NULL, r.secret, 64, r.bounce, 256));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_secure_on(&r.rx, NULL, &r.slot, NULL, r.secret, 64, r.bounce, 256));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_m2_secure_on(&r.rx, &r.q, NULL, NULL, r.secret, 64, r.bounce, 256));
	check_crc_and_zero(&r);
	/* already switched wins over a bad bounce and a bad secret */
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 5, 100));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
}

static void test_host_override(void)
{
	static rig r;
	wr_prim_ops t;
	spy sp;

	rig_init(&r);
	rig_at_boundary(&r);
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, &t, 64, 256));
	WRT_CHECK(sp.setkeys == 2u && sp.states[0] == (void *)r.slot.s.tx.u.host_state && sp.states[1] == (void *)r.slot.s.rx.u.host_state);
	WRT_CHECK(sp.wipes == 0u);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot); /* releases both host key objects */
	WRT_CHECK_U64(sp.wipes, 2);
	WRT_CHECK(sp.wiped[0] == sp.states[0] && sp.wiped[1] == sp.states[1]);
	check_crc_and_zero(&r);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot); /* twice: no more host calls */
	WRT_CHECK_U64(sp.wipes, 2);

	/* the host refuses the second key: its status, everything wiped, both sides crc */
	memset(&sp, 0, sizeof(sp));
	sp.fail_at = 2;
	sp.fail_status = WR_E_CRYPTO_KEY;
	spy_table(&t, &sp);
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_CRYPTO_KEY, do_on(&r, &t, 64, 256));
	check_crc_and_zero(&r);
	WRT_CHECK(sp.wipes >= 2u); /* the keyed first state and the refused second one */
	/* the host is not asked at all when the switch is refused before the key */
	memset(&sp, 0, sizeof(sp));
	spy_table(&t, &sp);
	WRT_CHECK_STATUS(WR_E_INVAL, do_on(&r, &t, 64, 255));
	WRT_CHECK_STATUS(WR_E_M2_SECRET, do_on(&r, &t, 39, 256));
	WRT_CHECK(sp.setkeys == 0u && sp.wipes == 0u);
}

static void test_off(void)
{
	static rig r, other;
	static wri_m2s_slot never;
	size_t i;

	/* a "used" slot: scribble into every part of it, as a running connection does, then off */
	rig_init(&r);
	rig_at_boundary(&r);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 512));
	memset(r.slot.rx.p1, 0x99, sizeof(r.slot.rx.p1));
	memset(r.slot.rx.blk, 0x98, sizeof(r.slot.rx.blk));
	memset(r.slot.rx.tag, 0x97, sizeof(r.slot.rx.tag));
	r.slot.rx.state = 5;
	r.slot.rx.op_open = 1;
	r.slot.tx.stream_left = 1234;
	r.slot.tx.b_len = 99;
	r.slot.tx.phase = 2;
	r.slot.s.tx_n.ops = 77;
	r.slot.offer = WRI_M2_OFFER_SECURE;
	memset(r.bounce, 0x55, 512); /* plaintext-ish staging in the bounce buffer */
	for (i = 0; i < 512u; i += 64u)
		r.bounce[i + 3] = 0x66;
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
	WRT_CHECK(all_byte(r.bounce, 512, 0)); /* exactly the bounce capacity: the rest of the (larger) buffer is the caller's */
	WRT_CHECK(all_byte(r.bounce + 512, sizeof(r.bounce) - 512u, 0xcd));
	/* twice, with NULL pointers, on a slot that never switched, and with the seam pointers of another slot left alone */
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	wri_m2_secure_off(NULL, NULL, &r.slot);
	wri_m2_secure_off(&r.rx, &r.q, NULL);
	wri_m2_secure_off(NULL, NULL, NULL);
	check_crc_and_zero(&r);
	wri_m2_secure_off(&r.rx, &r.q, &never);
	WRT_CHECK(all_byte(&never, sizeof(never), 0));
	rig_init(&other);
	rig_at_boundary(&other);
	WRT_CHECK_STATUS(WR_OK, do_on(&other, NULL, 64, 256));
	wri_m2_secure_off(&other.rx, &other.q, &never); /* a slot that is not the bound one: the binding stays */
	WRT_CHECK(other.rx.sx == &other.slot.rx && other.q.sx == &other.slot.tx && other.slot.s.active == 1u);
	wri_m2_secure_off(&other.rx, &other.q, &other.slot);
	check_crc_and_zero(&other);
}

/* Each field of the frame-boundary rule alone: the rig is at a clean boundary and exactly one thing is changed. */
static void test_boundary_each_field(void)
{
	static rig r;
	static const uint8_t states[] = {WRI_RX_BANNER_HEAD, WRI_RX_BANNER_PAYLOAD, WRI_RX_SEG0, WRI_RX_SEGS, WRI_RX_EPILOGUE, WRI_RX_DEAD};
	static const uint8_t evs[] = {WRI_RXE_BANNER, WRI_RXE_SEG0, WRI_RXE_FRAME, WRI_RXE_ABORTED, WRI_RXE_ERROR};
	size_t i;

	rig_init(&r);
	rig_at_boundary(&r);
	for (i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
		r.rx.state = states[i];
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
		check_crc_and_zero(&r);
		r.rx.state = WRI_RX_PREAMBLE;
	}
	for (i = 0; i < sizeof(evs) / sizeof(evs[0]); i++) {
		r.rx.pending_ev = evs[i];
		memset(&r.slot, 0xab, sizeof(r.slot));
		WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
		check_crc_and_zero(&r);
		r.rx.pending_ev = WRI_RXE_NONE;
	}
	r.rx.seg = 1;
	memset(&r.slot, 0xab, sizeof(r.slot));
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	r.rx.seg = 3;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	r.rx.seg = 0;
	r.rx.seg_pos = 1;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	r.rx.seg_pos = 0xffffffffu;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	r.rx.seg_pos = 0;
	r.rx.direct = 1;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	r.rx.direct = 0xffffffffu;
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	check_crc_and_zero(&r);
	r.rx.direct = 0;
	/* all clean again: the switch goes through (the fields were the only obstacle) */
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
}

/* A seam bound on one side only (cannot happen through the API): refused whichever side it is, nothing touched. */
static void test_one_side_bound(void)
{
	static rig r;
	wri_m2s_slot snap;

	rig_init(&r);
	rig_at_boundary(&r);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	memcpy(&snap, &r.slot, sizeof(snap));
	r.rx.sx = NULL; /* queue bound, parser not */
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	WRT_CHECK(memcmp(&snap, &r.slot, sizeof(snap)) == 0 && r.q.sx == &r.slot.tx && r.rx.sx == NULL);
	r.rx.sx = &r.slot.rx;
	r.q.sx = NULL; /* parser bound, queue not */
	WRT_CHECK_STATUS(WR_E_STATE, do_on(&r, NULL, 64, 256));
	WRT_CHECK(memcmp(&snap, &r.slot, sizeof(snap)) == 0 && r.rx.sx == &r.slot.rx && r.q.sx == NULL);
	r.q.sx = &r.slot.tx;
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
	check_crc_and_zero(&r);
}

/* The secure parser starts in the state wri_m2s_rx_next() leaves: whatever that function does (nothing in the skeleton, a reset of the
 * per-frame fields in the real parser) the switch must have called it, once, with the seam bound. Reference: a zero slot driven through it. */
static void test_rx_next_applied(void)
{
	static rig r;
	static wri_m2_rx rx2;
	static wri_m2s_slot ref;

	rig_init(&r);
	rig_at_boundary(&r);
	memset(&ref, 0, sizeof(ref));
	memset(&rx2, 0, sizeof(rx2));
	ref.rx.s = &ref.s;
	rx2.sx = &ref.rx;
	wri_m2s_rx_next(&rx2);
	WRT_CHECK_STATUS(WR_OK, do_on(&r, NULL, 64, 256));
	ref.rx.s = &r.slot.s; /* the one field that legitimately differs: where the key state lives */
	WRT_CHECK(memcmp(&ref.rx, &r.slot.rx, sizeof(ref.rx)) == 0);
	wri_m2_secure_off(&r.rx, &r.q, &r.slot);
}

int main(void)
{
	test_success();
	test_queued_crc_frame_is_untouched();
	test_frame_boundary();
	test_twice();
	test_bounce();
	test_secret_errors();
	test_check_order();
	test_host_override();
	test_off();
	test_boundary_each_field();
	test_one_side_bound();
	test_rx_next_applied();
	return wrt_finish();
}
