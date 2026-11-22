/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_rx.c - secure-mode receive parser, first half: the seam functions the crc parser dispatches to (window, commit, step,
 * next), part 1 of a frame and the helpers both halves share (see wri_m2_sec.h for the contract, wri_m2_sec_rxi.h for the machine, and
 * docs/design/core-architecture.md 34.7 for the design; wire facts: docs/spec/msgr2-secure-mode.md 2.5 to 2.8).
 *
 * The order inside part 1 is the point of the file: the 96 bytes are staged, the 80 ciphertext bytes are decrypted in place, the tag
 * is verified, and only then does anyone look at the preamble. A length, a segment count or a tag in the plaintext of a frame whose
 * tag has not verified is attacker-chosen text and is never acted on.
 *
 * Budget: one unit per byte taken from the ring (or settled from the direct window) and one unit per byte decrypted, and the two are paid
 * together when a payload byte comes in (two units; a tag byte is one). So a byte is never left undecrypted for lack of budget: every
 * whole block that is in is decrypted in the same call, and when a call ends with an exhausted budget there is nothing hidden behind an
 * empty ring and an empty direct window (the connection's "work left" test looks at those two only). A budget of 1 still makes progress
 * (a byte is bought whenever a unit is left, the charge is clamped at what is left), and the total over a frame, when the budget never
 * clamps, is exactly ingress plus decryption.
 */
#include "wri_ctx.h"
#include "wri_m2_sec_rxi.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define RC_CONT (-1) /* internal: state changed, run the loop again; any value >= 0 is a wri_m2_rx_ev */
/* A segment goes straight into its sink only when at least this much of it is still to come (as in the crc parser). */
#define DIRECT_MIN 1024u

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

/* ---- helpers shared with wri_m2_sec_rx2.c ------------------------------------------------------------- */

/* End a running GCM operation that will never finish (a failure, a reset): its final is run with a zero tag and the answer dropped. */
static void op_abort(wri_m2s_rx *sx)
{
	wr_status st;

	if (sx->op_open != 0u && sx->s != NULL) {
		WR_MEMSET(sx->tag, 0, sizeof(sx->tag));
		st = wri_pgcm_final_dec(&sx->s->rx, sx->tag);
		(void)st; /* it can only say "tag wrong": the operation is closed either way */
	}
	sx->op_open = 0;
}

static void wipe_staging(wri_m2s_rx *sx)
{
	wri_secure_zero(sx->p1, sizeof(sx->p1));
	wri_secure_zero(sx->blk, sizeof(sx->blk));
	wri_secure_zero(sx->tag, sizeof(sx->tag));
}

int wri_m2sr_fail(wri_m2_rx *rx, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	wri_m2s_rx *sx = rx->sx;

	wri_errinfo_set(&rx->err, st, WR_MOD_M2, line, what, a0, a1, a2);
	if (sx != NULL) {
		op_abort(sx);
		wipe_staging(sx); /* the plaintext of unverified parts is not kept around */
		sx->state = WRI_M2SR_DEAD;
	}
	rx->state = WRI_RX_DEAD;
	rx->pending_ev = (uint8_t)WRI_RXE_ERROR;
	rx->direct = 0;
	return (int)WRI_RXE_ERROR;
}

void wri_m2sr_set_state(wri_m2_rx *rx, wri_m2s_rx *sx, unsigned state)
{
	sx->state = (uint8_t)state;
	switch (state) { /* the crc parser's state, for whoever looks at it (the switch refuses anything but a clean boundary) */
	case WRI_M2SR_P1:
		rx->state = WRI_RX_PREAMBLE;
		break;
	case WRI_M2SR_P2:
	case WRI_M2SR_P2T:
		rx->state = WRI_RX_SEG0;
		break;
	case WRI_M2SR_P3:
		rx->state = WRI_RX_SEGS;
		break;
	case WRI_M2SR_P3E:
	case WRI_M2SR_P3T:
		rx->state = WRI_RX_EPILOGUE;
		break;
	default:
		break;
	}
}

uint32_t wri_m2sr_pull(wri_ring *ring, uint8_t *dst, uint32_t want, uint32_t *budget, uint32_t unit)
{
	const uint8_t *p;
	uint32_t got = 0, span, n, afford;

	/* what the budget pays for: `unit` units a byte, the last byte may be paid only in part (a budget of 1 progresses, and a call that
	 * stops for want of budget has spent all of it) */
	afford = *budget / unit + (*budget % unit != 0u ? 1u : 0u); /* rounded up, without overflowing at 2^32 - 1 ("no limit") */
	if (afford < want)
		want = afford;
	while (got < want) {
		span = wri_ring_read_span(ring, &p);
		if (span == 0)
			break;
		n = min_u32(span, want - got);
		WR_MEMCPY(dst + got, p, n);
		wri_ring_drop(ring, n);
		got += n;
	}
	*budget -= min_u32(*budget, got > 0xffffffffu / unit ? 0xffffffffu : got * unit);
	return got;
}

static unsigned part_of(const wri_m2s_rx *sx)
{
	switch (sx->state) {
	case WRI_M2SR_P1:
		return 1u;
	case WRI_M2SR_P2:
	case WRI_M2SR_P2T:
		return 2u;
	default:
		return 3u;
	}
}

int wri_m2sr_begin(wri_m2_rx *rx, wri_m2s_rx *sx)
{
	uint8_t iv[WRI_M2S_NONCE_LEN];
	wri_m2s *s = sx->s;
	wr_status st;

	if (sx->op_open != 0u)
		return 0;
	/* One take per operation, in wire order, before anything of the operation is decrypted. */
	st = wri_m2s_nonce_take(&s->rx_n, s->ops_limit, iv);
	if (st != WR_OK)
		return WRI_M2SR_FAIL(rx, st, "receive nonce refused", s->rx_n.ops, s->ops_limit, part_of(sx)) != 0;
	st = wri_pgcm_start(&s->rx, iv, 1);
	wri_secure_zero(iv, sizeof(iv));
	if (st != WR_OK)
		return WRI_M2SR_FAIL(rx, st, "gcm start", s->rx_n.ops, part_of(sx), 0) != 0;
	sx->op_open = 1u;
	return 0;
}

int wri_m2sr_update(wri_m2_rx *rx, wri_m2s_rx *sx, const uint8_t *in, uint8_t *out, size_t n)
{
	wr_status st = wri_pgcm_update(&sx->s->rx, in, out, n);

	if (st != WR_OK)
		return WRI_M2SR_FAIL(rx, st, "gcm update", n, part_of(sx), 0) != 0;
	return 0;
}

/* The verdict of a finished operation: the tag failure has its own status, anything else is passed on as it came. */
static int verdict(wri_m2_rx *rx, wri_m2s_rx *sx, wr_status st, unsigned part)
{
	if (st == WR_OK)
		return WRI_M2SR_DONE;
	if (st == WR_E_CRYPTO_MAC)
		WRI_M2SR_FAIL(rx, WR_E_M2_SEC_TAG, "secure frame failed authentication", part, sx->s->rx_n.ops, 0);
	else
		WRI_M2SR_FAIL(rx, st, "gcm final", part, sx->s->rx_n.ops, 0);
	return WRI_M2SR_ERR;
}

int wri_m2sr_tag(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget, unsigned part)
{
	wr_status st;

	sx->pos += wri_m2sr_pull(ring, sx->tag + sx->pos, WRI_M2S_TAG_LEN - sx->pos, budget, 1u);
	if (sx->pos < WRI_M2S_TAG_LEN)
		return WRI_M2SR_WAIT;
	st = wri_pgcm_final_dec(&sx->s->rx, sx->tag);
	sx->op_open = 0u;
	sx->pos = 0;
	sx->dec = 0;
	return verdict(rx, sx, st, part);
}

int wri_m2sr_frame_done(wri_m2_rx *rx, wri_m2s_rx *sx, wri_m2_rx_ev ev)
{
	wri_m2sr_set_state(rx, sx, WRI_M2SR_P1); /* the next frame, once the owner has released this event */
	sx->pos = 0;
	sx->dec = 0;
	rx->direct = 0;
	wri_secure_zero(sx->blk, sizeof(sx->blk));
	rx->pending_ev = (uint8_t)ev;
	return (int)ev;
}

/* ---- window and commit ---------------------------------------------------------------------------------- */

/*
 * Can the next network bytes go straight into the current segment's sink? Only for the whole-block part of a segment of part 3 (the
 * last partial block and the padding always go through the ring: they need the scratch block), and as in the crc parser only when the
 * ring is empty, no event is waiting and enough of the segment is still to come. Used by window() and commit() alike.
 */
static int direct_ok(const wri_m2_rx *rx, const wri_ring *ring, uint32_t *room)
{
	const wri_m2s_rx *sx = rx->sx;
	uint32_t whole, done;

	if (sx->state != WRI_M2SR_P3 || rx->pending_ev != (uint8_t)WRI_RXE_NONE || ring->len != 0)
		return 0;
	if (rx->seg < 1u || rx->seg >= rx->desc.nseg || rx->sink[rx->seg].dst == NULL)
		return 0;
	whole = rx->desc.len[rx->seg] & ~(WRI_M2S_BLOCK - 1u);
	done = sx->pos + rx->direct;
	if (done >= whole)
		return 0;
	if (whole - done < DIRECT_MIN && rx->direct == 0)
		return 0;
	*room = whole - done;
	return 1;
}

size_t wri_m2s_rx_window(wri_m2_rx *rx, wri_ring *ring, uint8_t **ptr)
{
	uint32_t room = 0;

	if (ptr != NULL)
		*ptr = NULL;
	if (rx->state == WRI_RX_DEAD || rx->sx == NULL)
		return 0;
	if (direct_ok(rx, ring, &room)) {
		if (ptr != NULL)
			*ptr = rx->sink[rx->seg].dst + rx->sx->pos + rx->direct;
		return room;
	}
	return wri_ring_write_span(ring, ptr);
}

void wri_m2s_rx_commit(wri_m2_rx *rx, wri_ring *ring, size_t n)
{
	uint32_t room = 0, k;

	if (rx->state == WRI_RX_DEAD || rx->sx == NULL || n == 0)
		return;
	if (direct_ok(rx, ring, &room)) {
		k = n < room ? (uint32_t)n : room;
		rx->direct += k;
		return;
	}
	k = (uint32_t)n;
	if ((size_t)k != n)
		k = 0xffffffffu; /* more than a ring can hold anyway */
	wri_ring_commit(ring, k);
}

/* ---- part 1 ------------------------------------------------------------------------------------------- */

/* Caps: segment 0 by its buffer (or the configured maximum when it is discarded), segments 1 .. 3 by the maximum. */
static int preamble_caps(wri_m2_rx *rx)
{
	const wri_m2_desc *d = &rx->desc;
	uint32_t lim = rx->sink[0].dst != NULL ? rx->sink[0].cap : rx->seg_cap_max;
	unsigned i;

	if (d->len[0] > lim || d->len[0] > WRI_M2SR_LEN_MAX)
		return WRI_M2SR_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment 0 too big", d->len[0], lim, 0);
	for (i = 1; i < d->nseg; i++) {
		if (d->len[i] > rx->seg_cap_max || d->len[i] > WRI_M2SR_LEN_MAX)
			return WRI_M2SR_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment too big", d->len[i], rx->seg_cap_max, i);
	}
	return RC_CONT;
}

/* Part 1 has verified: the preamble (CRC, shape, tag value, caps), the inline bytes of segment 0, the next state. */
static int p1_accept(wri_m2_rx *rx, wri_m2s_rx *sx, const wr_prim_ops *prim)
{
	wri_m2_desc *d = &rx->desc;
	uint32_t n0;
	wr_status st = wri_m2_preamble_parse(prim, sx->p1, d);
	int rc;

	if (st != WR_OK)
		return WRI_M2SR_FAIL(rx, st, "preamble", sx->p1[0], sx->p1[1], 0);
	rc = preamble_caps(rx);
	if (rc != RC_CONT)
		return rc;
	WR_MEMSET(rx->stored, 0, sizeof(rx->stored));
	WR_MEMSET(rx->seg_crc, 0, sizeof(rx->seg_crc));
	rx->seg0_inline_crc_ok = 0;
	rx->seg = 0;
	rx->direct = 0;
	sx->nops = (uint8_t)(1u + (d->len[0] > WRI_M2S_INLINE ? 1u : 0u) + (d->nseg > 1u ? 1u : 0u));
	/* The inline part of segment 0 is already authenticated by this part's tag; it goes to the buffer now, the rest (if any) follows. */
	n0 = d->len[0] < WRI_M2S_INLINE ? d->len[0] : WRI_M2S_INLINE;
	if (rx->sink[0].dst != NULL && n0 != 0) {
		WR_MEMCPY(rx->sink[0].dst, sx->p1 + WRI_M2_PREAMBLE_LEN, n0);
		rx->stored[0] = n0;
	}
	wri_secure_zero(sx->p1, sizeof(sx->p1));
	sx->pos = 0;
	sx->dec = 0;
	if (d->len[0] <= WRI_M2S_INLINE) { /* nothing more of segment 0: SEG0 right away, also for an empty segment 0 */
		wri_m2sr_set_state(rx, sx, WRI_M2SR_P3);
		rx->seg = 1;
		rx->seg0_inline_crc_ok = 1;
		rx->pending_ev = (uint8_t)WRI_RXE_SEG0;
		return (int)WRI_RXE_SEG0;
	}
	wri_m2sr_set_state(rx, sx, WRI_M2SR_P2);
	return RC_CONT;
}

static int st_p1(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget)
{
	wr_status st;

	/* 80 ciphertext bytes (two units each: their decryption is paid with them), then the 16 of the tag (one each) */
	if (sx->pos < WRI_M2S_P1_PLAIN)
		sx->pos += wri_m2sr_pull(ring, sx->p1 + sx->pos, WRI_M2S_P1_PLAIN - sx->pos, budget, 2u);
	if (sx->pos >= WRI_M2S_P1_PLAIN && sx->pos < WRI_M2S_P1_WIRE)
		sx->pos += wri_m2sr_pull(ring, sx->p1 + sx->pos, WRI_M2S_P1_WIRE - sx->pos, budget, 1u);
	if (sx->pos < WRI_M2S_P1_WIRE)
		return (int)WRI_RXE_NONE;
	/* All of part 1 is here, and its decryption has been paid for: done in this call, so no work is ever left hidden behind an empty ring. */
	if (wri_m2sr_begin(rx, sx) != 0 || wri_m2sr_update(rx, sx, sx->p1, sx->p1, WRI_M2S_P1_PLAIN) != 0)
		return (int)WRI_RXE_ERROR;
	st = wri_pgcm_final_dec(&sx->s->rx, sx->p1 + WRI_M2S_P1_PLAIN);
	sx->op_open = 0u;
	if (verdict(rx, sx, st, 1u) != WRI_M2SR_DONE)
		return (int)WRI_RXE_ERROR;
	/* The tag said these 80 bytes are the server's. Now, and only now, the preamble. */
	return p1_accept(rx, sx, prim);
}

/* First step after a SEG0 event: the owner has chosen its sinks, check them against the lengths. */
static int after_seg0(wri_m2_rx *rx)
{
	unsigned i;

	for (i = 1; i < rx->desc.nseg; i++) {
		if (rx->desc.len[i] != 0 && rx->sink[i].dst != NULL && rx->desc.len[i] > rx->sink[i].cap)
			return WRI_M2SR_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment exceeds its sink", rx->desc.len[i],
					     rx->sink[i].cap, i);
	}
	rx->pending_ev = (uint8_t)WRI_RXE_NONE;
	return RC_CONT;
}

/* ---- the seam ----------------------------------------------------------------------------------------- */

wri_m2_rx_ev wri_m2s_rx_step(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget)
{
	wri_m2s_rx *sx = rx->sx;
	uint32_t unlimited = 0xffffffffu;
	int rc;

	if (budget == NULL)
		budget = &unlimited;
	for (;;) {
		if (rx->pending_ev == (uint8_t)WRI_RXE_FRAME || rx->pending_ev == (uint8_t)WRI_RXE_ABORTED ||
		    rx->pending_ev == (uint8_t)WRI_RXE_ERROR)
			return (wri_m2_rx_ev)rx->pending_ev; /* sticky until next_frame() / forever */
		if (sx == NULL || sx->s == NULL || sx->s->active == 0u || sx->state == WRI_M2SR_NEW || sx->state >= WRI_M2SR_DEAD)
			return (wri_m2_rx_ev)WRI_M2SR_FAIL(rx, WR_E_STATE, "secure parser state", sx != NULL ? sx->state : 0, 0, 0);
		if (rx->pending_ev == (uint8_t)WRI_RXE_SEG0) {
			rc = after_seg0(rx);
			if (rc != RC_CONT)
				return (wri_m2_rx_ev)rc;
		}
		if (sx->state == WRI_M2SR_P1)
			rc = st_p1(rx, sx, ring, prim, budget);
		else
			rc = wri_m2sr_body(rx, sx, ring, budget);
		if (rc != RC_CONT)
			return (wri_m2_rx_ev)rc;
	}
}

void wri_m2s_rx_next(wri_m2_rx *rx)
{
	wri_m2s_rx *sx = rx->sx;

	if (sx == NULL || sx->state == WRI_M2SR_DEAD)
		return; /* a dead parser stays dead */
	op_abort(sx);
	wipe_staging(sx);
	sx->nops = 0;
	sx->pos = 0;
	sx->dec = 0;
	sx->part_left = 0;
	wri_m2sr_set_state(rx, sx, WRI_M2SR_P1);
}
