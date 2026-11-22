/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec.c - secure mode: key and nonce derivation, the nonce rule, frame arithmetic and the switch from crc to secure
 * (see wri_m2_sec.h; design: docs/design/core-architecture.md 34.4 and 34.5; wire facts: docs/spec/msgr2-secure-mode.md 2.6 and 2.8).
 *
 * Nothing here allocates, keeps global state or calls anything but memcpy / memset / the secure wipe of the host-independent utilities.
 * Everything secret in this file (the connection secret handed in by the caller, the key, the nonce seeds) is only ever read in place;
 * the caller owns and wipes its copy of the secret, this file wipes what it keeps.
 */
#include "wri_m2_sec.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* Offsets inside the connection secret (msgr2-secure-mode.md 2.6): the key, then the seed of one direction, then the other. */
#define SEC_OFF_KEY 0u
#define SEC_OFF_SEED_A 16u /* the client receives with it */
#define SEC_OFF_SEED_B 28u /* the client transmits with it */

/* The counter field of a nonce: bytes 4..11, little endian. Bytes 0..3 (the fixed field) are never touched in revision 1. */
#define NONCE_CTR_FIRST 4u

/* The smallest bounce buffer the transmit side can work with (and the unit of its size): see wri_m2_secure_on(). */
#define BOUNCE_MIN 256u

/* ---- nonce stream ------------------------------------------------------------------------------------ */

void wri_m2s_nonce_init(wri_m2s_nonce *n, const uint8_t seed[WRI_M2S_NONCE_LEN])
{
	if (n == NULL)
		return;
	WR_MEMSET(n, 0, sizeof(*n));
	if (seed != NULL) {
		WR_MEMCPY(n->seed, seed, WRI_M2S_NONCE_LEN);
		WR_MEMCPY(n->cur, seed, WRI_M2S_NONCE_LEN);
	}
}

/* cur + 1 on the 64-bit little-endian counter, wrapping to 0, with no carry out of it. */
static void nonce_step(uint8_t cur[WRI_M2S_NONCE_LEN])
{
	unsigned i;

	for (i = NONCE_CTR_FIRST; i < WRI_M2S_NONCE_LEN; i++) {
		cur[i] = (uint8_t)(cur[i] + 1u);
		if (cur[i] != 0u)
			break;
	}
}

wr_status wri_m2s_nonce_take(wri_m2s_nonce *n, uint64_t limit, uint8_t out[WRI_M2S_NONCE_LEN])
{
	if (n == NULL || out == NULL)
		return WR_E_INVAL;
	/* Back at the seed after a start: the counter went all the way round, the next use would repeat a nonce under the key. */
	if (n->started != 0u && wri_ct_memeq(n->cur, n->seed, WRI_M2S_NONCE_LEN) != 0)
		return WR_E_M2_NONCE;
	if (limit != 0u && n->ops >= limit)
		return WR_E_M2_NONCE;
	WR_MEMCPY(out, n->cur, WRI_M2S_NONCE_LEN);
	nonce_step(n->cur);
	n->started = 1u;
	n->ops++; /* cannot overflow: the wrap refusal above fires after exactly 2^64 takes */
	return WR_OK;
}

/* ---- per-connection state ---------------------------------------------------------------------------- */

/* Wipe both GCM directions (a host override releases its key object here) and the whole object. */
static void m2s_scrub(wri_m2s *s)
{
	wri_pgcm_wipe(&s->tx);
	wri_pgcm_wipe(&s->rx);
	wri_secure_zero(s, sizeof(*s));
}

wr_status wri_m2s_init(wri_m2s *s, const wr_prim_ops *prim, const uint8_t *secret, size_t n, int crossed)
{
	const uint8_t *seed_a, *seed_b;
	wr_status st;

	if (s == NULL)
		return WR_E_INVAL;
	/* The previous contents are never looked at (a keyed object has to be wiped before it is keyed again): the host's key object
	 * of an earlier life would be leaked, but indeterminate memory must not be taken for one. */
	WR_MEMSET(s, 0, sizeof(*s));
	if (secret == NULL || n < WRI_M2S_SECRET_MIN || n > WRI_M2S_SECRET_MAX)
		return WR_E_M2_SECRET;
	seed_a = secret + SEC_OFF_SEED_A;
	seed_b = secret + SEC_OFF_SEED_B;
	/* Equal seeds would give both directions the same nonce stream under the same key. */
	if (wri_ct_memeq(seed_a, seed_b, WRI_M2S_NONCE_LEN) != 0)
		return WR_E_M2_SECRET;
	st = wri_pgcm_setkey(&s->tx, prim, secret + SEC_OFF_KEY);
	if (st == WR_OK)
		st = wri_pgcm_setkey(&s->rx, prim, secret + SEC_OFF_KEY);
	if (st != WR_OK) {
		m2s_scrub(s); /* the status of a refusing host is returned as it came */
		return st;
	}
	/* The client (not crossed) transmits with seed B and receives with seed A; the server's view is the other way round. */
	wri_m2s_nonce_init(&s->tx_n, crossed != 0 ? seed_a : seed_b);
	wri_m2s_nonce_init(&s->rx_n, crossed != 0 ? seed_b : seed_a);
	s->ops_limit = WRI_M2S_OPS_LIMIT_DEFAULT;
	s->active = 1u;
	return WR_OK;
}

void wri_m2s_wipe(wri_m2s *s)
{
	if (s != NULL)
		m2s_scrub(s);
}

/* ---- frame arithmetic -------------------------------------------------------------------------------- */

static uint64_t pad16_u64(uint64_t x)
{
	return (x + (WRI_M2S_BLOCK - 1u)) & ~(uint64_t)(WRI_M2S_BLOCK - 1u);
}

uint64_t wri_m2s_wire_len(const uint32_t len[WRI_M2_MAX_SEGS], unsigned nseg, unsigned *nops)
{
	uint64_t total = WRI_M2S_P1_WIRE;
	unsigned ops = 1u, i;

	if (nops != NULL)
		*nops = 0;
	if (len == NULL || nseg < 1u || nseg > WRI_M2_MAX_SEGS || (nseg > 1u && len[nseg - 1u] == 0u))
		return 0;
	if (len[0] > WRI_M2S_INLINE) { /* part 2: what did not fit the first part, padded, with its own tag */
		total += pad16_u64(len[0]) - WRI_M2S_INLINE + WRI_M2S_TAG_LEN;
		ops++;
	}
	if (nseg > 1u) { /* part 3: the other segments padded, the epilogue block, one tag */
		for (i = 1; i < nseg; i++)
			total += pad16_u64(len[i]);
		total += WRI_M2S_EPI_LEN + WRI_M2S_TAG_LEN;
		ops++;
	}
	if (nops != NULL)
		*nops = ops;
	return total;
}

size_t wri_m2s_slot_bytes(void)
{
	return sizeof(wri_m2s_slot);
}

/* ---- the switch -------------------------------------------------------------------------------------- */

/* A crc parser between two frames: nothing of a frame taken, no event waiting to be released, no bytes committed straight into a sink. */
static int rx_at_frame_boundary(const wri_m2_rx *rx)
{
	return rx->state == WRI_RX_PREAMBLE && rx->seg == 0u && rx->seg_pos == 0u && rx->direct == 0u && rx->pending_ev == WRI_RXE_NONE;
}

wr_status wri_m2_secure_on(wri_m2_rx *rx, wri_m2_txq *q, wri_m2s_slot *slot, const wr_prim_ops *prim, const uint8_t *secret,
			   size_t secret_len, uint8_t *bounce, uint32_t bounce_cap)
{
	wr_status st;

	if (rx == NULL || q == NULL || slot == NULL)
		return WR_E_INVAL;
	/* Already switched (a second call): the live connection is not touched, not even its slot; the caller fails the connection. */
	if (rx->sx != NULL || q->sx != NULL)
		return WR_E_STATE;
	/* From here on a refusal leaves the slot zero (its previous contents are ignored, as in wri_m2s_init). */
	if (bounce == NULL || bounce_cap < BOUNCE_MIN || (bounce_cap % WRI_M2S_BLOCK) != 0u)
		st = WR_E_INVAL;
	else if (!rx_at_frame_boundary(rx))
		st = WR_E_STATE;
	else
		st = wri_m2s_init(&slot->s, prim, secret, secret_len, 0);
	if (st != WR_OK) {
		wri_secure_zero(slot, sizeof(*slot)); /* wri_m2s_init has already scrubbed its own part */
		return st;
	}
	/* The two halves start empty: the receive parser in its first state, the transmit side idle with the bounce buffer bound. */
	WR_MEMSET(&slot->rx, 0, sizeof(slot->rx));
	WR_MEMSET(&slot->tx, 0, sizeof(slot->tx));
	slot->rx.s = &slot->s;
	slot->tx.s = &slot->s;
	slot->tx.bounce = bounce;
	slot->tx.bounce_cap = bounce_cap;
	rx->sx = &slot->rx;
	q->sx = &slot->tx;
	wri_m2s_rx_next(rx); /* let the secure parser reset its own per-frame state, as after every released frame */
	return WR_OK;
}

void wri_m2_secure_off(wri_m2_rx *rx, wri_m2_txq *q, wri_m2s_slot *slot)
{
	if (slot != NULL) {
		if (rx != NULL && rx->sx == &slot->rx)
			rx->sx = NULL;
		if (q != NULL && q->sx == &slot->tx)
			q->sx = NULL;
		/* The bounce buffer carries the last piece of a stream (ciphertext, but also the zero padding and the epilogue block
		 * before they are encrypted): it is erased with the rest. The slot owns the pointer, not the memory. */
		if (slot->tx.bounce != NULL && slot->tx.bounce_cap != 0u)
			wri_secure_zero(slot->tx.bounce, slot->tx.bounce_cap);
		m2s_scrub(&slot->s);
		wri_secure_zero(slot, sizeof(*slot));
	}
}
