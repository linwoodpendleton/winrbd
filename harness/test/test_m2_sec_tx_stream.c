/* SPDX-License-Identifier: MIT */
/*
 * test_m2_sec_tx_stream - the secure transmit stream: the third part of a frame that is produced piece by piece through the bounce buffer
 * (core/src/msgr2/wri_m2_sec_tx2.c, design 34.6), seen from the host that peeks and consumes.
 *
 * What is checked:
 *   - a frame of four segments (odd lengths, so partial blocks and padding fall inside and at the end of pieces) behind an earlier frame, at
 *     bounce sizes 256, 272, 4096 and 65536, host steps of 1, 7, 16 and 4096 bytes, random steps and "everything shown": the bytes are the
 *     independent encoder's, the pending count is exact after every step (white box too: the gather entries, the bounce piece and the
 *     unproduced rest add up to it), a peek is repeatable and never shows more than is pending nor less than progress needs, a piece never
 *     exceeds the bounce size, the queue is idle exactly when the last byte is out;
 *   - a second frame while a stream is active is WR_E_BUSY at every host step (also when it would fit the encode buffer, also while only the
 *     tag is left) and takes no nonce; the first frame accepted after the drain carries the next nonce on the wire, for every bounce size;
 *   - the peek list: with a small `max` the bounce piece is never shown before every encode-buffer entry; the piece is the last entry; after a
 *     partial consume it starts where the host stopped; an over-long consume is clamped (the count never underflows);
 *   - reset in the middle of a stream (at every piece boundary and in between): the queue is idle, the bounce buffer erased, the stream gone;
 *     a frame built afterwards carries the next nonce, the nonces of the dropped frame are spent (never reused);
 *   - the caller's memory is read once, before the host consumed the piece it went into: freed (and poisoned) the moment the host has consumed
 *     the last data byte, the rest of the stream (epilogue, tag) comes out unchanged, under the address sanitizer too; never written (guard
 *     bytes around the segments, contents compared afterwards);
 *   - a refusal from the GCM layer in the middle of a stream (caller memory that overlaps the bounce buffer, which only a caller bug can
 *     cause): q->err, the stream dropped, the bounce erased, the key wiped, the queue goes idle (no wait for bytes that never come), later
 *     frames WR_E_STATE; the same at the first piece (the frame is refused, the queue as it was);
 *   - everything again with the accelerated GCM hook when WRT_GCM_ACCEL=1 and the CPU has it.
 */
#include <stdlib.h>
#include <string.h>

#include "wrt.h"

#define TXR_CHECK WRT_CHECK
#include "m2_sec_tx_rig.h"

#include "../host/wrl_gcm_aesni.c"

static const wr_prim_ops *g_prim;

typedef struct fb {
	uint8_t *p[4];
	uint8_t *raw[4]; /* the allocations with a guard before and after */
	wri_m2_seg_src s[4];
	unsigned n;
	uint32_t len[4];
} fb;

#define FB_GUARD 16u

static uint8_t pat(unsigned seg, size_t i)
{
	return (uint8_t)(0x47u * (seg + 1u) + i * 11u + (i >> 9));
}

static void fb_make(fb *f, unsigned nseg, const uint32_t *len)
{
	unsigned i;
	size_t k;

	memset(f, 0, sizeof(*f));
	f->n = nseg;
	for (i = 0; i < nseg; i++) {
		f->len[i] = len[i];
		if (len[i] != 0u) {
			f->raw[i] = (uint8_t *)malloc((size_t)len[i] + 2u * FB_GUARD);
			WRT_CHECK(f->raw[i] != NULL);
			memset(f->raw[i], 0x5c, (size_t)len[i] + 2u * FB_GUARD);
			f->p[i] = f->raw[i] + FB_GUARD;
			for (k = 0; k < len[i]; k++)
				f->p[i][k] = pat(i, k);
		}
		f->s[i].p = f->p[i];
		f->s[i].len = len[i];
		f->s[i].ref = 1; /* referenced: freed when the host consumed it (the copy rule is tested in test_m2_sec_tx_frames) */
	}
}

/* Guard bytes untouched and the contents what they were (the caller's memory is only ever read). */
static void fb_check_untouched(const fb *f)
{
	unsigned i;
	size_t k;

	for (i = 0; i < f->n; i++) {
		if (f->raw[i] == NULL)
			continue;
		for (k = 0; k < FB_GUARD; k++)
			WRT_CHECK(f->raw[i][k] == 0x5c && f->raw[i][FB_GUARD + f->len[i] + k] == 0x5c);
		for (k = 0; k < f->len[i]; k++)
			if (f->p[i][k] != pat(i, k)) {
				WRT_CHECK(0);
				break;
			}
	}
}

/* Free every segment now (a use after this point is an address sanitizer report, and a poisoned read shows in the bytes). */
static void fb_poison_free(fb *f)
{
	unsigned i;

	for (i = 0; i < 4u; i++) {
		if (f->raw[i] != NULL) {
			memset(f->raw[i], 0xee, (size_t)f->len[i] + 2u * FB_GUARD);
			free(f->raw[i]);
			f->raw[i] = NULL;
			f->p[i] = NULL;
		}
	}
}

static void fb_free(fb *f)
{
	unsigned i;

	for (i = 0; i < 4u; i++)
		free(f->raw[i]);
	memset(f, 0, sizeof(*f));
}

static uint64_t pad16u(uint64_t x)
{
	return (x + 15u) & ~(uint64_t)15u;
}

/* ---- the stream at every bounce size and host step -------------------------------------------------------------------------- */

static void run_stream(uint32_t bounce_cap, size_t step, int randomize, int poison, int big)
{
	static const uint32_t l0[4] = {20, 10, 0, 0};
	uint32_t l1[4] = {41, 3001, 17, 9000}; /* partial blocks inside pieces and at their ends; seg 2 shorter than a block */
	/* big: several pieces even of the 64 KiB bounce buffer */
	txr r;
	fb f0, f1;
	uint64_t data_end;
	int freed = 0;
	size_t cycles = 0, n;

	if (big)
		l1[3] = 140001u;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, bounce_cap, g_prim, NULL));
	fb_make(&f0, 2, l0);
	fb_make(&f1, 4, l1);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, f0.s, 2)); /* 144 bytes in the encode buffer ... */
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f1.s, 4));    /* ... then 96 + a stream */
	data_end = 144u + 96u + pad16u(l1[1]) + pad16u(l1[2]) + pad16u(l1[3]);
	WRT_CHECK(!wri_m2s_tx_done(&r.q));
	WRT_CHECK_U64(r.q.pending, data_end + 32u);
	for (;;) {
		wr_iov a[WRI_M2_TXQ_IOV + 1];
		size_t want = step, got, k;

		if (randomize)
			want = 1u + (size_t)txr_rnd(&r) % step;
		n = wri_m2_txq_peek(&r.q, a, WRI_M2_TXQ_IOV + 1u);
		for (k = 0; k < n; k++)
			if (a[k].base >= r.bounce && a[k].base < r.bounce + bounce_cap)
				WRT_CHECK(a[k].len <= bounce_cap && a[k].base + a[k].len <= r.bounce + bounce_cap); /* a piece never exceeds the bounce buffer */
		got = txr_pull(&r, want);
		if (got == 0u)
			break;
		if (poison && !freed && r.consumed >= data_end) {
			fb_poison_free(&f1); /* the host has all the data bytes: the caller's memory is no longer needed */
			freed = 1;
		}
		cycles++;
	}
	WRT_CHECK(cycles > 0u);
	WRT_CHECK(wri_m2s_tx_done(&r.q) && wri_m2_txq_idle(&r.q));
	WRT_CHECK(poison == 0 || freed);
	WRT_CHECK(txr_wire_matches(&r));
	if (!poison)
		fb_check_untouched(&f1);
	fb_check_untouched(&f0);
	fb_free(&f0);
	fb_free(&f1);
	txr_close(&r);
}

static void test_stream_matrix(void)
{
	static const uint32_t bounces[] = {256u, 272u, 4096u, 65536u};
	static const size_t steps[] = {1u, 7u, 16u, 4096u, 0u};
	unsigned b, s;

	for (b = 0; b < sizeof(bounces) / sizeof(bounces[0]); b++) {
		for (s = 0; s < sizeof(steps) / sizeof(steps[0]); s++) {
			run_stream(bounces[b], steps[s], 0, 0, 0); /* step 0: everything the peek shows */
			run_stream(bounces[b], steps[s], 0, 1, 0);
		}
		run_stream(bounces[b], 5000u, 1, 0, 0); /* random steps up to 5000 */
		run_stream(bounces[b], 5000u, 1, 1, 0);
		run_stream(bounces[b], 40u, 1, 0, 0);
	}
	/* a data segment of 140 KB: three pieces of the 64 KiB buffer, 546 of the smallest */
	run_stream(65536u, 4096u, 0, 1, 1);
	run_stream(65536u, 0u, 0, 0, 1);
	run_stream(65536u, 70000u, 1, 1, 1);
	run_stream(4096u, 4096u, 0, 0, 1);
	run_stream(256u, 100000u, 1, 1, 1);
}

/* ---- a second frame during a stream ----------------------------------------------------------------------------------------- */

static void test_busy_during_stream(void)
{
	static const uint32_t bounces[] = {256u, 272u, 4096u};
	unsigned b;

	for (b = 0; b < 3u; b++) {
		txr r;
		uint32_t l1[4] = {41, 700, 0, 2500}, l2[4] = {8, 0, 0, 0}, l3[4] = {41, 5, 0, 0};
		fb f1, f2, f3;
		wri_m2s_nonce snap;
		unsigned tries = 0;

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, 1024u, bounces[b], g_prim, NULL));
		fb_make(&f1, 4, l1);
		fb_make(&f2, 1, l2); /* would fit the encode buffer many times over */
		fb_make(&f3, 2, l3);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f1.s, 4)); /* parts 1 and (stream): 1024 bytes of room, 96 used */
		WRT_CHECK(!wri_m2s_tx_done(&r.q));
		snap = r.slot.s.tx_n;
		while (!wri_m2_txq_idle(&r.q)) {
			WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_KEEPALIVE2, f2.s, 1, NULL, NULL));
			WRT_CHECK_STATUS(WR_E_BUSY, wri_m2s_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, f3.s, 2));
			WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0); /* no nonce was taken */
			WRT_CHECK(r.q.err == WR_OK);                                   /* BUSY is not a failure: it is not recorded */
			tries++;
			WRT_CHECK(txr_pull(&r, 97u) > 0u);
		}
		WRT_CHECK(tries > 10u && wri_m2_txq_idle(&r.q));
		/* the stream is out: the next frame is accepted and has the next nonce on the wire (the encoder only advances for accepted frames) */
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, f2.s, 1));
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f3.s, 2));
		txr_drain(&r, 0, 0);
		WRT_CHECK(txr_wire_matches(&r));
		fb_free(&f1);
		fb_free(&f2);
		fb_free(&f3);
		txr_close(&r);
	}
}

/* While only the tag is left (the last piece holds the tag alone or the tag with the epilogue) the stream is still active. */
static void test_busy_until_last_byte(void)
{
	txr r;
	uint32_t l1[4] = {20, 240 - 16, 0, 0}; /* data 224 bytes + epilogue 16 + tag 16 = 256: exactly one piece of a 256-byte bounce buffer */
	uint32_t l2[4] = {20, 240, 0, 0};      /* 240 + 16 + 16 = 272: the tag alone makes a second piece */
	uint32_t l[2][4];
	fb f, g;
	unsigned c;

	memcpy(l[0], l1, sizeof(l1));
	memcpy(l[1], l2, sizeof(l2));
	for (c = 0; c < 2u; c++) {
		size_t before;
		wri_m2s_nonce snap;

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, 160u, 256u, g_prim, NULL));
		fb_make(&f, 2, l[c]);
		fb_make(&g, 1, l1); /* segment 0 only (20 bytes) */
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f.s, 2));
		/* take the encode part (96) and all but the last byte of the stream, one byte at a time at the end */
		while (r.q.pending > 1u)
			(void)txr_pull(&r, r.q.pending > 64u ? 64u : 1u);
		WRT_CHECK_U64(r.q.pending, 1);
		before = r.q.niov;
		snap = r.slot.s.tx_n;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, g.s, 1, NULL, NULL));
		WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0 && r.q.niov == before);
		(void)txr_pull(&r, 1u);
		WRT_CHECK(wri_m2_txq_idle(&r.q) && wri_m2s_tx_done(&r.q));
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, g.s, 1));
		txr_drain(&r, 0, 0);
		WRT_CHECK(txr_wire_matches(&r));
		fb_free(&f);
		fb_free(&g);
		txr_close(&r);
	}
}

/* ---- the peek list ------------------------------------------------------------------------------------------------------------- */

static void test_peek_list(void)
{
	txr r;
	uint32_t l0[4] = {20, 10, 0, 0}, l1[4] = {41, 1500, 0, 0};
	fb f0, f1;
	wr_iov a[4];
	size_t n, shown;
	uint64_t pend;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, 272u, g_prim, NULL));
	fb_make(&f0, 2, l0);
	fb_make(&f1, 2, l1);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, f0.s, 2));
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f1.s, 2));
	/* one entry (the two frames share the encode buffer's run) then the piece */
	WRT_CHECK_U64(r.q.niov, 1);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 0), 0);
	n = wri_m2_txq_peek(&r.q, a, 1);
	WRT_CHECK(n == 1u && a[0].base == r.enc && a[0].len == 144u + 96u); /* the bounce piece does not jump the queue */
	n = wri_m2_txq_peek(&r.q, a, 2);
	WRT_CHECK(n == 2u && a[1].base == r.bounce && a[1].len == 272u);
	WRT_CHECK(wri_m2_txq_peek(&r.q, NULL, 2) == 0u);
	/* the host consumes the encode run and 100 bytes of the piece: the piece starts where it stopped, alone in the list */
	wri_m2_txq_consume(&r.q, 144u + 96u + 100u);
	n = wri_m2_txq_peek(&r.q, a, 1);
	WRT_CHECK(n == 1u && a[0].base == r.bounce + 100u && a[0].len == 272u - 100u);
	WRT_CHECK_U64(r.q.pending, 144u + 96u + pad16u(1500u) + 32u - 144u - 96u - 100u);
	pend = r.q.pending;
	/* consuming more than is shown takes what is shown (the piece) and refills; the count never underflows */
	wri_m2_txq_consume(&r.q, 272u - 100u + 10u);
	WRT_CHECK(r.q.pending == pend - (272u - 100u));
	shown = wri_m2_txq_peek(&r.q, a, 1);
	WRT_CHECK(shown == 1u && a[0].base == r.bounce && a[0].len == 272u);
	wri_m2_txq_consume(&r.q, (size_t)-1 / 2u); /* an absurd claim: clamped to the piece */
	WRT_CHECK(r.q.pending == pend - (272u - 100u) - 272u);
	/* the rest goes out normally (the claimed bytes beyond the pieces were not counted, so only the real ones count as consumed) */
	{
		uint64_t gone = 144u + 96u + 100u + (272u - 100u) + 272u;

		r.consumed = gone; /* what the host really took (the over-long claims counted for nothing) */
		txr_check_queue(&r);
		while (r.q.pending > 0u) {
			size_t got = txr_pull(&r, 0);

			WRT_CHECK(got > 0u);
			if (got == 0u)
				break;
		}
	}
	WRT_CHECK(wri_m2_txq_idle(&r.q));
	wri_m2_txq_consume(&r.q, 1000u); /* nothing pending: nothing changes */
	WRT_CHECK(wri_m2_txq_idle(&r.q) && r.q.pending == 0u && r.q.used == 0u);
	fb_free(&f0);
	fb_free(&f1);
	txr_close(&r);
}

/* Two gather entries ahead of the stream (crc-framed bytes queued before the switch, as the connection may leave them): a short peek list never
 * shows the bounce piece before every one of them, and shows it last when there is room. */
static void test_peek_cut(void)
{
	static const uint32_t l1[4] = {41, 1500, 0, 0};
	uint8_t junk[8];
	txr r;
	fb f;
	wr_iov a[6];
	unsigned i;

	memset(junk, 0x5a, sizeof(junk));
	memset(&r, 0, sizeof(r));
	r.rng = 1;
	r.enc_cap = 512u;
	r.bounce_cap = 256u;
	r.enc = txr_alloc_guarded(&r.enc_raw, r.enc_cap, 0xcd);
	r.bounce = txr_alloc_guarded(&r.bnc_raw, r.bounce_cap, 0xcd);
	r.prim = g_prim;
	for (i = 0; i < sizeof(r.secret); i++)
		r.secret[i] = (uint8_t)i;
	txr_rx_to_boundary(&r);
	wri_m2_txq_init(&r.q, r.enc, r.enc_cap);
	r.q.iov[0].base = r.enc; /* four bytes of the encode buffer, then eight referenced ones */
	r.q.iov[0].len = 4u;
	r.q.iov[1].base = junk;
	r.q.iov[1].len = sizeof(junk);
	r.q.niov = 2u;
	r.q.used = 4u;
	r.q.pending = 12u;
	WRT_CHECK_STATUS(WR_OK, wri_m2_secure_on(&r.rx, &r.q, &r.slot, g_prim, r.secret, sizeof(r.secret), r.bounce, r.bounce_cap));
	r.open = 1;
	fb_make(&f, 2, l1);
	WRT_CHECK_STATUS(WR_OK, wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, f.s, 2, NULL, NULL));
	WRT_CHECK_U64(r.q.niov, 3); /* the junk entry does not end where the new bytes begin: an entry of their own */
	WRT_CHECK(!wri_m2s_tx_done(&r.q));
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 1), 1);
	WRT_CHECK(a[0].base == r.enc && a[0].len == 4u);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 2), 2);
	WRT_CHECK(a[1].base == junk);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 3), 3); /* all three encode-buffer entries, and no room left for the piece */
	WRT_CHECK(a[2].base == r.enc + 4u && a[2].len == 96u);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 4), 4); /* with room, the piece comes last */
	WRT_CHECK(a[3].base == r.bounce && a[3].len == 256u);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 6), 4);
	/* the host takes the first two entries: the list shrinks, the piece stays last */
	wri_m2_txq_consume(&r.q, 12u);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 1), 1);
	WRT_CHECK(a[0].base == r.enc + 4u);
	WRT_CHECK_U64(wri_m2_txq_peek(&r.q, a, 2), 2);
	WRT_CHECK(a[1].base == r.bounce);
	fb_free(&f);
	txr_close(&r);
}

/* ---- reset in the middle ------------------------------------------------------------------------------------------------------ */

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static void reset_at(uint32_t bounce_cap, uint64_t cut)
{
	uint32_t l1[4] = {41, 3001, 17, 6000}, l2[4] = {30, 100, 0, 0};
	txr r;
	fb f1, f2;
	uint64_t total1;
	size_t aborted_n;
	wri_m2s_nonce snap;

	WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, bounce_cap, g_prim, NULL));
	fb_make(&f1, 4, l1);
	fb_make(&f2, 2, l2);
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f1.s, 4));
	total1 = r.queued;
	aborted_n = r.exp_len;
	while (r.consumed < cut && r.q.pending > 0u)
		(void)txr_pull(&r, cut - r.consumed > 333u ? 333u : (size_t)(cut - r.consumed));
	snap = r.slot.s.tx_n;
	wri_m2_txq_reset(&r.q);
	WRT_CHECK(wri_m2_txq_idle(&r.q) && r.q.niov == 0u && r.q.used == 0u && r.q.err == WR_OK);
	WRT_CHECK(wri_m2s_tx_done(&r.q));
	WRT_CHECK(all_zero(r.bounce, bounce_cap)); /* ciphertext and padding blocks of the dropped stream are erased */
	WRT_CHECK(r.q.sx == &r.slot.tx && r.slot.tx.stream_left == 0u && r.slot.tx.b_len == 0u && r.slot.tx.phase == 0u);
	WRT_CHECK(memcmp(&r.slot.s.tx_n, &snap, sizeof(snap)) == 0); /* the nonces of the dropped frame stay spent */
	{
		wr_iov none[1];

		WRT_CHECK(wri_m2_txq_peek(&r.q, none, 1) == 0u);
	}
	/* the host's bookkeeping: the bytes of the dropped frame that never left are not coming */
	r.queued = r.consumed;
	/* a frame built after the reset carries the next nonce: the wire is the consumed part of the dropped frame, then the new frame as the
	 * independent encoder makes it after the three nonces of the dropped one */
	WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_MESSAGE, f2.s, 2));
	txr_drain(&r, 0, 0);
	{
		size_t consumed_of_first = (size_t)(r.consumed - (r.exp_len - aborted_n)); /* before the new frame's bytes */

		WRT_CHECK(r.wire_len == r.consumed);
		WRT_CHECK(consumed_of_first <= total1);
		WRT_CHECK(memcmp(r.wire, r.exp, consumed_of_first) == 0);
		WRT_CHECK(memcmp(r.wire + consumed_of_first, r.exp + aborted_n, r.exp_len - aborted_n) == 0);
	}
	fb_free(&f1);
	fb_free(&f2);
	txr_close(&r);
}

static void test_reset_mid_stream(void)
{
	static const uint32_t bounces[] = {256u, 272u, 4096u};
	uint64_t cut;
	unsigned b;

	for (b = 0; b < 3u; b++) {
		for (cut = 0; cut < 600u; cut += 29u)
			reset_at(bounces[b], cut);
		for (cut = 600u; cut < 9400u; cut += 1237u)
			reset_at(bounces[b], cut);
		reset_at(bounces[b], 9300u);
	}
	{
		/* a reset with no stream, and twice */
		txr r;
		uint32_t l[4] = {20, 0, 0, 0};
		fb f;

		WRT_CHECK_STATUS(WR_OK, txr_open(&r, 256u, 256u, g_prim, NULL));
		fb_make(&f, 1, l);
		wri_m2_txq_reset(&r.q);
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, f.s, 1));
		wri_m2_txq_reset(&r.q);
		wri_m2_txq_reset(&r.q);
		r.queued = r.consumed;
		WRT_CHECK_STATUS(WR_OK, txr_send(&r, WRI_M2_TAG_KEEPALIVE2, f.s, 1));
		txr_drain(&r, 0, 0);
		WRT_CHECK(r.wire_len == 96u && memcmp(r.wire, r.exp + 96u, 96u) == 0);
		fb_free(&f);
		txr_close(&r);
	}
}

/* ---- a refusal from the GCM layer in the middle of a stream ------------------------------------------------------------------------ */

/* The caller's memory overlaps the bounce buffer: the GCM layer refuses (fail closed) at the first piece that does. */
static void test_overlap_failure(void)
{
	static const uint32_t cap = 256u;
	static const uint8_t h[20] = {3};
	uint8_t *region = (uint8_t *)malloc((size_t)cap * 8u + 64u);
	const uint32_t len1 = 3u * 256u;
	unsigned c;

	WRT_CHECK(region != NULL);
	if (region == NULL)
		return;
	for (c = 0; c < 3u; c++) {
		/* c 2: as c 0, the host side calls the codec's consume directly (the accounting must not depend on the queue's own reset).
		 * c 0: the data is at region + 0 and the bounce buffer at region + 264: piece 1 (data 0 .. 256 into 264 .. 520) is clean, piece 2
		 * (data 256 .. 512 into 264 ..) overlaps: an error in the middle of the stream.
		 * c 1: the data begins 8 bytes before the bounce buffer: piece 1 overlaps and the frame itself is refused. */
		uint8_t *bounce = c != 1u ? region + cap + 8u : region + 64u;
		wri_m2_seg_src src[2];
		wri_m2s_nonce snap;
		txr r;
		size_t i;
		wr_status st;

		memset(region, 0x3c, (size_t)cap * 8u + 64u);
		src[0].p = h;
		src[0].len = sizeof(h);
		src[0].ref = 1;
		src[1].p = c != 1u ? region : bounce - 8u;
		src[1].len = len1;
		src[1].ref = 1;
		WRT_CHECK_STATUS(WR_OK, txr_open2(&r, 256u, cap, g_prim, NULL, bounce));
		snap = r.slot.s.tx_n;
		st = wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, src, 2, NULL, NULL);
		if (c == 1u) {
			WRT_CHECK_STATUS(WR_E_INVAL, st);
			WRT_CHECK(r.q.pending == 0u && r.q.niov == 0u && r.q.used == 0u && r.slot.s.tx.keyed == 0u);
			WRT_CHECK_U64(r.slot.s.tx_n.ops - snap.ops, 2); /* part 1 and the stream's: two nonces, spent; no part 2 (20 <= 48) */
			WRT_CHECK(wri_m2s_tx_done(&r.q) && all_zero(r.enc, 96u)); /* what was built in the encode buffer is erased */
			WRT_CHECK(all_zero(bounce, cap));
			WRT_CHECK_STATUS(WR_E_STATE, wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, src, 2, NULL, NULL));
		} else if (c == 2u) {
			WRT_CHECK_STATUS(WR_OK, st);
			WRT_CHECK_U64(r.q.pending, 96u + 768u + 32u);
			wri_m2_txq_consume(&r.q, 96u);                    /* the encode-buffer part */
			WRT_CHECK(wri_m2s_tx_consume(&r.q, 256u) == 0u);  /* the first piece: the refill of the second one fails */
			WRT_CHECK(r.q.pending == 0u && r.q.err == WR_E_INVAL && wri_m2s_tx_done(&r.q)); /* the accounting is exact on its own */
			WRT_CHECK(r.slot.s.tx.keyed == 0u && all_zero(bounce, cap));
		} else {
			size_t shown = 0;

			WRT_CHECK_STATUS(WR_OK, st);
			/* the host takes everything it is shown: the first piece is fine, refilling the second one fails */
			for (;;) {
				wr_iov a[3];
				size_t n = wri_m2_txq_peek(&r.q, a, 3), k, tot = 0;

				for (k = 0; k < n; k++)
					tot += a[k].len;
				if (tot == 0u)
					break;
				shown += tot;
				wri_m2_txq_consume(&r.q, tot);
			}
			WRT_CHECK(shown == 96u + 256u); /* part 1 and the first piece, nothing of the failed one */
			WRT_CHECK(r.q.err == WR_E_INVAL && wri_m2_txq_idle(&r.q) && wri_m2s_tx_done(&r.q));
			WRT_CHECK(r.slot.s.tx.keyed == 0u && r.q.pending == 0u);
			WRT_CHECK(all_zero(bounce, cap)); /* the half-made piece and the finished one are erased */
			WRT_CHECK_STATUS(WR_E_STATE, wri_m2_tx_frame(&r.q, g_prim, WRI_M2_TAG_MESSAGE, src, 2, NULL, NULL));
		}
		(void)i;
		txr_close(&r);
	}
	free(region);
}

static void run_all(const wr_prim_ops *prim)
{
	g_prim = prim;
	test_stream_matrix();
	test_busy_during_stream();
	test_busy_until_last_byte();
	test_peek_list();
	test_peek_cut();
	test_reset_mid_stream();
	test_overlap_failure();
}

int main(void)
{
	const char *accel = getenv("WRT_GCM_ACCEL");

	run_all(NULL);
	if (accel != NULL && strcmp(accel, "1") == 0) {
		static wr_prim_ops ops;

		if (wrl_gcm_aesni_ops(&ops) == 0) {
			txr probe;

			WRT_CHECK_STATUS(WR_OK, txr_open(&probe, 4096u, 4096u, &ops, NULL));
			WRT_CHECK(wri_pgcm_is_host(&probe.slot.s.tx));
			txr_close(&probe);
			run_all(&ops);
		} else {
			fprintf(stderr, "note: WRT_GCM_ACCEL=1 but the CPU lacks AES / PCLMULQDQ / SSE4.1: the accelerated pass is skipped\n");
		}
	}
	return wrt_finish();
}
