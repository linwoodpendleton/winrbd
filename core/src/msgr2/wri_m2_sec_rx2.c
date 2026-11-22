/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_rx2.c - secure-mode receive parser, second half: part 2 (the rest of segment 0), part 3 (segments 1 .. 3 and the
 * epilogue block), the tags, the late-status nibble (see wri_m2_sec_rxi.h for the machine and docs/design/core-architecture.md 34.7).
 *
 * One routine decrypts every run of payload bytes, a "region": the padded stream of one segment (or of the rest of segment 0, or the
 * epilogue block). The bytes of the region are cut in two:
 *   - the whole blocks of the real data: they land in the sink as they arrive (copied from the ring, or put there by the network
 *     itself through the direct window) and are decrypted IN PLACE, a whole number of blocks at a time, as soon as they are all there;
 *   - the last block, when the segment length is not a multiple of 16, and every block of a segment that has no sink: they are
 *     collected in the 16-byte scratch block, decrypted there, and the real bytes (if any) copied out. The zero padding is decrypted
 *     (the tag covers it) and dropped; a receiver does not look at it.
 * Bytes that are decrypted but whose part has no verified tag yet are in the sink without anybody having been told: the owner hears
 * about segment 0 only at SEG0 (after the tag of the part that carried its last byte) and about the rest only at FRAME.
 */
#include "wri_ctx.h"
#include "wri_m2_sec_rxi.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

static uint32_t pad16(uint32_t x) { return (x + (WRI_M2S_BLOCK - 1u)) & ~(WRI_M2S_BLOCK - 1u); }

typedef struct region {
	uint8_t *dst;     /* where the plaintext goes (NULL: discarded) */
	uint32_t real;    /* bytes of it */
	uint32_t padded;  /* bytes on the wire (a multiple of 16) */
} region;

/* The region the state is in. The epilogue block is a region of 16 bytes without a sink. */
static void region_get(const wri_m2_rx *rx, unsigned state, region *g)
{
	const wri_m2_desc *d = &rx->desc;

	g->dst = NULL;
	g->real = 0;
	g->padded = WRI_M2S_BLOCK;
	if (state == WRI_M2SR_P2) { /* segment 0 after its first 48 bytes, which part 1 carried */
		g->dst = rx->sink[0].dst != NULL ? rx->sink[0].dst + WRI_M2S_INLINE : NULL;
		g->real = d->len[0] - WRI_M2S_INLINE;
		g->padded = pad16(d->len[0]) - WRI_M2S_INLINE;
	} else if (state == WRI_M2SR_P3) {
		g->dst = rx->sink[rx->seg].dst;
		g->real = d->len[rx->seg];
		g->padded = pad16(d->len[rx->seg]);
	}
}

#define RS_CONT 3 /* internal: progress was made, go round again (WRI_M2SR_WAIT / DONE / ERR are the other answers) */

/* The bytes the network wrote straight into the sink (rx->direct) are taken in: payload, two units each. */
static int reg_settle(wri_m2_rx *rx, wri_m2s_rx *sx, uint32_t *budget)
{
	uint32_t n = min_u32(rx->direct, *budget / 2u + (*budget & 1u)); /* a byte whenever a unit is left; the last one may be paid in part */

	if (n == 0)
		return WRI_M2SR_WAIT;
	sx->pos += n;
	rx->direct -= n;
	*budget -= min_u32(*budget, 2u * n);
	return RS_CONT;
}

/* Whole blocks have arrived (their decryption is paid): decrypt all of them, in place. */
static int reg_decrypt(wri_m2_rx *rx, wri_m2s_rx *sx, const region *g, uint32_t avail)
{
	uint8_t *p = g->dst + sx->dec;

	if (wri_m2sr_begin(rx, sx) != 0 || wri_m2sr_update(rx, sx, p, p, avail) != 0)
		return WRI_M2SR_ERR;
	sx->dec += avail;
	rx->stored[rx->seg] += avail;
	return RS_CONT;
}

/* The whole-block part, nothing to decrypt yet: take more of it from the ring into the sink. */
static int reg_whole(wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget, const region *g, uint32_t whole)
{
	uint32_t n = wri_m2sr_pull(ring, g->dst + sx->pos, whole - sx->pos, budget, 2u);

	if (n == 0)
		return WRI_M2SR_WAIT;
	sx->pos += n;
	return RS_CONT;
}

/* The scratch block: the segment's last partial block, or any block of a segment without a sink. */
static int reg_block(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget, const region *g)
{
	uint32_t k = sx->pos - sx->dec, n;

	if (k < WRI_M2S_BLOCK) {
		n = wri_m2sr_pull(ring, sx->blk + k, WRI_M2S_BLOCK - k, budget, 2u);
		if (n == 0)
			return WRI_M2SR_WAIT;
		sx->pos += n;
		if (sx->pos - sx->dec < WRI_M2S_BLOCK)
			return RS_CONT; /* (the next round finds the ring empty or the budget spent) */
	}
	if (wri_m2sr_begin(rx, sx) != 0 || wri_m2sr_update(rx, sx, sx->blk, sx->blk, WRI_M2S_BLOCK) != 0)
		return WRI_M2SR_ERR;
	if (g->dst != NULL && g->real > sx->dec) { /* the real bytes of the last block */
		k = min_u32(g->real - sx->dec, WRI_M2S_BLOCK);
		WR_MEMCPY(g->dst + sx->dec, sx->blk, k);
		rx->stored[rx->seg] += k;
	}
	sx->dec += WRI_M2S_BLOCK; /* pos == dec again */
	return RS_CONT;
}

/*
 * Run the region as far as the input and the budget allow. WRI_M2SR_DONE when all of it (to `padded`) has been decrypted; the
 * invariants while it is not: dec <= pos; dst[dec .. pos) holds ciphertext of less than a block (only below `whole`), or is empty;
 * the bytes committed straight into the sink (rx->direct) follow pos in the sink and precede everything in the ring.
 */
static int region_run(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget, const region *g)
{
	const uint32_t whole = g->dst != NULL ? (g->real & ~(WRI_M2S_BLOCK - 1u)) : 0;
	uint32_t avail;
	int rc;

	for (;;) {
		if (sx->dec >= g->padded)
			return WRI_M2SR_DONE;
		/* what has come in is decrypted first, whatever is left of the budget: it was paid for when it came in */
		avail = (min_u32(sx->pos, whole) & ~(WRI_M2S_BLOCK - 1u)) - sx->dec;
		if (sx->dec < whole && avail != 0)
			rc = reg_decrypt(rx, sx, g, avail);
		else if (rx->direct != 0)
			rc = reg_settle(rx, sx, budget);
		else if (sx->dec < whole)
			rc = reg_whole(sx, ring, budget, g, whole);
		else
			rc = reg_block(rx, sx, ring, budget, g);
		if (rc != RS_CONT)
			return rc;
	}
}

/* The epilogue's late-status nibble, after the tag of part 3 verified (the nibble is the low half of the first byte, as in crc mode). */
static int epilogue_verdict(wri_m2_rx *rx, wri_m2s_rx *sx)
{
	const unsigned late = (unsigned)(sx->blk[0] & 0x0Fu);

	wri_secure_zero(sx->blk, sizeof(sx->blk));
	if (late == WRI_M2_LATE_ABORTED)
		return wri_m2sr_frame_done(rx, sx, WRI_RXE_ABORTED); /* the sender gave up on this frame: the tag was right, the nonce advanced */
	if (late != WRI_M2_LATE_COMPLETE)
		return WRI_M2SR_FAIL(rx, WR_E_M2_FRAME_FORM, "late status", late, 0, 0);
	return wri_m2sr_frame_done(rx, sx, WRI_RXE_FRAME);
}

int wri_m2sr_body(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget)
{
	region g;
	int rc;

	for (;;) {
		switch ((unsigned)sx->state) {
		case WRI_M2SR_P2: /* the rest of segment 0 */
			region_get(rx, WRI_M2SR_P2, &g);
			rc = region_run(rx, sx, ring, budget, &g);
			if (rc == WRI_M2SR_ERR)
				return (int)WRI_RXE_ERROR;
			if (rc == WRI_M2SR_WAIT)
				return (int)WRI_RXE_NONE;
			wri_secure_zero(sx->blk, sizeof(sx->blk));
			sx->pos = 0;
			sx->dec = 0;
			wri_m2sr_set_state(rx, sx, WRI_M2SR_P2T);
			break;
		case WRI_M2SR_P2T: /* its tag; segment 0 is the owner's only after this verified */
			rc = wri_m2sr_tag(rx, sx, ring, budget, 2u);
			if (rc == WRI_M2SR_ERR)
				return (int)WRI_RXE_ERROR;
			if (rc == WRI_M2SR_WAIT)
				return (int)WRI_RXE_NONE;
			wri_m2sr_set_state(rx, sx, WRI_M2SR_P3);
			rx->seg = 1;
			rx->seg0_inline_crc_ok = 1;
			rx->pending_ev = (uint8_t)WRI_RXE_SEG0;
			return (int)WRI_RXE_SEG0;
		case WRI_M2SR_P3: /* segments 1 .. nseg-1 */
			if (rx->desc.nseg == 1u) /* a single-segment frame has no third part */
				return wri_m2sr_frame_done(rx, sx, WRI_RXE_FRAME);
			if (rx->seg >= rx->desc.nseg) {
				sx->pos = 0;
				sx->dec = 0;
				wri_m2sr_set_state(rx, sx, WRI_M2SR_P3E);
				break;
			}
			region_get(rx, WRI_M2SR_P3, &g);
			rc = region_run(rx, sx, ring, budget, &g);
			if (rc == WRI_M2SR_ERR)
				return (int)WRI_RXE_ERROR;
			if (rc == WRI_M2SR_WAIT)
				return (int)WRI_RXE_NONE;
			wri_secure_zero(sx->blk, sizeof(sx->blk));
			sx->pos = 0;
			sx->dec = 0;
			rx->seg++;
			break;
		case WRI_M2SR_P3E: /* the epilogue block: decrypted into the scratch block, looked at after the tag */
			region_get(rx, WRI_M2SR_P3E, &g);
			rc = region_run(rx, sx, ring, budget, &g);
			if (rc == WRI_M2SR_ERR)
				return (int)WRI_RXE_ERROR;
			if (rc == WRI_M2SR_WAIT)
				return (int)WRI_RXE_NONE;
			sx->pos = 0;
			sx->dec = 0;
			wri_m2sr_set_state(rx, sx, WRI_M2SR_P3T);
			break;
		case WRI_M2SR_P3T: /* the tag of part 3, verified last; then the nibble */
			rc = wri_m2sr_tag(rx, sx, ring, budget, 3u);
			if (rc == WRI_M2SR_ERR)
				return (int)WRI_RXE_ERROR;
			if (rc == WRI_M2SR_WAIT)
				return (int)WRI_RXE_NONE;
			return epilogue_verdict(rx, sx);
		default:
			return WRI_M2SR_FAIL(rx, WR_E_STATE, "secure parser state", sx->state, 0, 0);
		}
	}
}
