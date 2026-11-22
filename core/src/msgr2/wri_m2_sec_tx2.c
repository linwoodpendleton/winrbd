/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_tx2.c - secure-mode transmit, the stream: the third part of a frame produced piece by piece through the bounce buffer
 * (see wri_m2_sec.h, wri_m2_sec_txi.h; design: docs/design/core-architecture.md 34.6; wire facts: docs/spec/msgr2-secure-mode.md 2.8).
 *
 * The queue hands the host its encode-buffer entries first and, last, the unconsumed part of the bounce buffer. When the host has
 * consumed the bounce buffer completely, the next piece is encrypted into it. A piece is as many whole 16-byte blocks as the bounce
 * buffer holds (its size is a multiple of 16): whole blocks of a segment go from the caller's memory straight into the bounce buffer
 * through the GCM layer (one read, one write, no staging), the final partial block of a segment is assembled in the bounce buffer
 * with its zero padding (the padding is never read from the caller) and encrypted in place, then the epilogue block, then the tag.
 *
 * Reading rules for the caller's memory (only the referenced segments are in it, see wri_m2_sec_tx.c): it is only read, never written; a byte of it is read once, when the piece that carries it is
 * produced, which is before the host consumed that piece, and never again afterwards (the epilogue and the tag need nothing of it).
 *
 * Failure: a refusal from the GCM layer while a piece is produced (only a caller bug can cause one: memory that overlaps the bounce
 * buffer) drops the stream, erases the bounce buffer, kills the transmit key of the connection (its nonce is spent and the peer would
 * not decode what follows anyway) and records the status in q->err; nothing more is ever produced, and the bytes that will never come
 * are taken out of q->pending so the queue reports idle instead of waiting for them.
 */
#include "wri_m2_sec_txi.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* ---- producing a piece ----------------------------------------------------------------------------------- */

/* Whole blocks of the current segment (rem >= 16 bytes left in it) straight from the caller's memory into the bounce buffer. */
static wr_status put_whole(wri_m2s_tx *tx, uint32_t *pos, uint32_t rem)
{
	uint32_t take = rem & ~(WRI_M2S_BLOCK - 1u);
	wr_status st;

	if (take > tx->bounce_cap - *pos)
		take = tx->bounce_cap - *pos;
	st = wri_pgcm_update(&tx->s->tx, tx->src[tx->cur].p + tx->cur_off, tx->bounce + *pos, take);
	if (st == WR_OK) {
		*pos += take;
		tx->cur_off += take;
		tx->stream_left -= take;
	}
	return st;
}

/* The last partial block of the segment (0 < rem < 16): the real bytes, then zeros, assembled in the bounce buffer and encrypted in place. */
static wr_status put_tail(wri_m2s_tx *tx, uint32_t *pos, uint32_t rem)
{
	uint8_t *b = tx->bounce + *pos;
	wr_status st;

	WR_MEMCPY(b, tx->src[tx->cur].p + tx->cur_off, rem);
	WR_MEMSET(b + rem, 0, WRI_M2S_BLOCK - rem);
	st = wri_pgcm_update(&tx->s->tx, b, b, WRI_M2S_BLOCK);
	if (st == WR_OK) {
		*pos += WRI_M2S_BLOCK;
		tx->cur_off = tx->src[tx->cur].len;
		tx->stream_left -= WRI_M2S_BLOCK;
	}
	return st;
}

/* The data phase: segments in order until the bounce buffer is full or the last one is done (then the phase is the epilogue). */
static wr_status fill_data(wri_m2s_tx *tx, uint32_t *pos)
{
	wr_status st = WR_OK;

	while (*pos < tx->bounce_cap && st == WR_OK) {
		uint32_t len, off;

		if (tx->cur >= tx->nseg) {
			tx->phase = WRI_M2S_TXP_EPI;
			break;
		}
		len = tx->src[tx->cur].len;
		off = tx->cur_off;
		if (off >= len) { /* this segment is done (an empty one too): the next */
			tx->cur++;
			tx->cur_off = 0;
		} else if (len - off >= WRI_M2S_BLOCK) {
			st = put_whole(tx, pos, len - off);
		} else {
			st = put_tail(tx, pos, len - off);
		}
	}
	return st;
}

/* The epilogue block: late_status and 15 zeros, encrypted in place. */
static wr_status put_epilogue(wri_m2s_tx *tx, uint32_t *pos)
{
	uint8_t *b = tx->bounce + *pos;
	wr_status st;

	b[0] = tx->late_status;
	WR_MEMSET(b + 1u, 0, WRI_M2S_EPI_LEN - 1u);
	st = wri_pgcm_update(&tx->s->tx, b, b, WRI_M2S_EPI_LEN);
	if (st == WR_OK) {
		*pos += WRI_M2S_EPI_LEN;
		tx->stream_left -= WRI_M2S_EPI_LEN;
		tx->phase = WRI_M2S_TXP_TAG;
	}
	return st;
}

/* The tag goes last, straight into the bounce buffer. */
static wr_status put_tag(wri_m2s_tx *tx, uint32_t *pos)
{
	wr_status st = wri_pgcm_final_enc(&tx->s->tx, tx->bounce + *pos);

	if (st == WR_OK) {
		*pos += WRI_M2S_TAG_LEN;
		tx->stream_left -= WRI_M2S_TAG_LEN;
		tx->phase = WRI_M2S_TXP_IDLE;
	}
	return st;
}

/* The end of the stream: the epilogue block, then the tag, as far as the bounce buffer has room (it holds whole blocks only). */
static wr_status fill_end(wri_m2s_tx *tx, uint32_t *pos)
{
	wr_status st = WR_OK;

	if (tx->phase == WRI_M2S_TXP_EPI && *pos < tx->bounce_cap)
		st = put_epilogue(tx, pos);
	if (st == WR_OK && tx->phase == WRI_M2S_TXP_TAG && *pos < tx->bounce_cap)
		st = put_tag(tx, pos);
	return st;
}

wr_status wri_m2s_txs_refill(wri_m2s_tx *tx)
{
	uint32_t pos = 0;
	wr_status st = WR_OK;

	tx->b_off = 0;
	tx->b_len = 0;
	/* bounce_cap and pos are multiples of 16, so a block that is still to come either fits whole or waits for the next piece */
	if (tx->stream_left == 0u)
		return WR_OK;
	if (tx->phase == WRI_M2S_TXP_DATA)
		st = fill_data(tx, &pos);
	if (st == WR_OK && tx->phase != WRI_M2S_TXP_DATA)
		st = fill_end(tx, &pos);
	tx->b_len = pos;
	if (st == WR_OK && pos == 0u)
		st = WR_E_STATE; /* bytes still owed but nothing produced: not reachable, fails closed rather than spinning */
	return st;
}

/* ---- lifecycle ------------------------------------------------------------------------------------------- */

static void txs_clear(wri_m2s_tx *tx)
{
	unsigned i;

	tx->b_off = 0;
	tx->b_len = 0;
	tx->stream_left = 0;
	for (i = 0; i < WRI_M2_MAX_SEGS; i++) {
		tx->src[i].p = NULL;
		tx->src[i].len = 0;
	}
	tx->nseg = 0;
	tx->cur = 0;
	tx->phase = WRI_M2S_TXP_IDLE;
	tx->late_status = 0;
	tx->cur_off = 0;
}

void wri_m2s_txs_abort(wri_m2s_tx *tx)
{
	if (tx == NULL)
		return;
	/* A running operation holds the hash of what was encrypted so far: end it without a tag (no GHASH work, a shallow call chain). Idle: a no-op. */
	if (tx->s != NULL)
		wri_pgcm_abort(&tx->s->tx);
	if (tx->bounce != NULL && tx->bounce_cap != 0u)
		wri_secure_zero(tx->bounce, tx->bounce_cap);
	txs_clear(tx);
}

wr_status wri_m2s_txs_begin(wri_m2s_tx *tx, const uint8_t iv[WRI_M2S_NONCE_LEN], const wri_m2_seg_src *seg, unsigned nseg, unsigned first,
			    uint64_t wire, uint8_t *head, size_t head_n)
{
	unsigned i;
	wr_status st;

	if (tx == NULL || tx->s == NULL || tx->bounce == NULL || iv == NULL || seg == NULL || nseg < 2u || nseg > WRI_M2_MAX_SEGS || first < 1u ||
	    first > nseg || wire == 0u || (head_n != 0u && head == NULL) || (head_n & (WRI_M2S_BLOCK - 1u)) != 0u)
		return WR_E_INVAL;
	txs_clear(tx);
	for (i = first; i < nseg; i++) {
		tx->src[i].p = seg[i].p;
		tx->src[i].len = seg[i].len;
	}
	tx->nseg = (uint8_t)nseg;
	tx->cur = (uint8_t)first;
	tx->phase = WRI_M2S_TXP_DATA;
	tx->late_status = WRI_M2_LATE_COMPLETE;
	tx->stream_left = wire;
	st = wri_pgcm_start(&tx->s->tx, iv, 0);
	if (st == WR_OK && head_n != 0u)
		st = wri_pgcm_update(&tx->s->tx, head, head, head_n); /* the copied segments are the first bytes of the operation */
	if (st == WR_OK)
		st = wri_m2s_txs_refill(tx); /* the first piece is ready at once, so that the next peek has something to return */
	if (st != WR_OK)
		wri_m2s_txs_abort(tx);
	return st;
}

/* ---- the queue's side ------------------------------------------------------------------------------------ */

size_t wri_m2s_tx_peek_more(const wri_m2_txq *q, wr_iov *out, size_t n, size_t max)
{
	const wri_m2s_tx *tx = q->sx;

	/* The slice goes after every encode-buffer entry: when the caller's list was cut short (n < niov) it is not next in wire order. */
	if (tx == NULL || tx->b_len == 0u || n != (size_t)q->niov || n >= max || out == NULL)
		return n;
	out[n].base = tx->bounce + tx->b_off;
	out[n].len = tx->b_len;
	return n + 1u;
}

size_t wri_m2s_tx_consume(wri_m2_txq *q, size_t n)
{
	wri_m2s_tx *tx = q->sx;
	size_t take;

	if (tx == NULL)
		return n;
	take = n < (size_t)tx->b_len ? n : (size_t)tx->b_len;
	if (take > 0u) {
		tx->b_off += (uint32_t)take;
		tx->b_len -= (uint32_t)take;
		q->pending -= take;
	}
	if (tx->b_len == 0u && tx->stream_left > 0u) {
		wr_status st = wri_m2s_txs_refill(tx);

		if (st != WR_OK) {
			/* Fail closed: the rest of the frame cannot be produced. Nothing more may be encrypted with this key (the nonce is spent and the
			 * peer would not decode a later frame); what was promised and will never come leaves the count, so the queue goes idle. */
			q->pending -= tx->stream_left + tx->b_len; /* the piece that failed half way is dropped with the rest */
			if (q->err == WR_OK)
				q->err = st;
			wri_m2s_txs_abort(tx);
			wri_pgcm_wipe(&tx->s->tx);
		}
	}
	return n - take;
}

int wri_m2s_tx_done(const wri_m2_txq *q)
{
	const wri_m2s_tx *tx = q->sx;

	return tx == NULL || (tx->stream_left == 0u && tx->b_len == 0u);
}

void wri_m2s_tx_reset(wri_m2_txq *q)
{
	if (q->sx != NULL)
		wri_m2s_txs_abort(q->sx); /* the keys stay: the owner wipes them with the slot */
}
