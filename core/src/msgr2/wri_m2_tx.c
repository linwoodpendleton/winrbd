/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_tx.c - the transmit queue and the msgr2.1 crc-mode frame builder (see wri_m2_frame.h and
 * docs/spec/msgr2.md 2.3, 2.5, 2.6.1).
 *
 * The queue is an encode buffer plus at most WRI_M2_TXQ_IOV gather entries. Bytes the builder
 * writes go into the encode buffer (consecutive ones share one entry); a referenced segment gets
 * an entry of its own that points at caller memory. Appending a frame is all or nothing: a dry
 * pass over the same piece list first checks that bytes and entries fit, then a second pass writes.
 * Encode-buffer space is not reclaimed piecemeal: it comes back when the queue drains completely.
 */
#include "wri_ctx.h"
#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_m2_sec.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define CRC_SEED 0xFFFFFFFFu
#define ALIGN_DEFAULT 8u
#define ALIGN_DATA 4096u

/* ---- queue -------------------------------------------------------------------------------- */

void wri_m2_txq_init(wri_m2_txq *q, uint8_t *buf, uint32_t cap)
{
	WR_MEMSET(q, 0, sizeof(*q));
	q->buf = buf;
	q->cap = buf != NULL ? cap : 0;
}

void wri_m2_txq_reset(wri_m2_txq *q)
{
	if (q->sx != NULL)
		wri_m2s_tx_reset(q);
	q->used = 0;
	q->niov = 0;
	q->pending = 0;
	q->err = WR_OK;
}

size_t wri_m2_txq_peek(const wri_m2_txq *q, wr_iov *out, size_t max)
{
	size_t i, n = q->niov < max ? q->niov : max;

	if (out == NULL)
		return 0;
	for (i = 0; i < n; i++)
		out[i] = q->iov[i];
	if (q->sx != NULL)
		n = wri_m2s_tx_peek_more(q, out, n, max); /* the active secure stream's slice goes last */
	return n;
}

void wri_m2_txq_consume(wri_m2_txq *q, size_t n)
{
	unsigned i;

	while (n > 0 && q->niov > 0) {
		wr_iov *v = &q->iov[0];

		if (n >= v->len) {
			n -= v->len;
			q->pending -= v->len;
			for (i = 1; i < q->niov; i++)
				q->iov[i - 1] = q->iov[i];
			q->niov--;
		} else {
			v->base += n;
			v->len -= n;
			q->pending -= n;
			n = 0;
		}
	}
	if (n > 0 && q->sx != NULL)
		(void)wri_m2s_tx_consume(q, n); /* bytes beyond the entries are the active secure stream's */
	if (q->niov == 0 && (q->sx == NULL || wri_m2s_tx_done(q))) { /* drained: the whole encode buffer is free again */
		q->pending = 0;
		q->used = 0;
	}
}

/* ---- piece writer ------------------------------------------------------------------------- */

struct txw {
	wri_m2_txq *q;
	uint64_t used;    /* encode-buffer bytes in use after the pieces so far */
	uint32_t niov;    /* gather entries after the pieces so far */
	int open;         /* the last entry is a run in the encode buffer ending at buf + used */
	int dry;          /* count only, write nothing */
	wri_m2_log_fn log_fn;
	void *log;
};

static void txw_start(struct txw *w, wri_m2_txq *q, int empty_queue, int dry, wri_m2_log_fn log_fn, void *log)
{
	w->q = q;
	w->dry = dry;
	w->log_fn = log_fn;
	w->log = log;
	if (empty_queue || q->niov == 0 || q->buf == NULL) {
		w->used = empty_queue ? 0 : q->used;
		w->niov = empty_queue ? 0 : q->niov;
		w->open = 0;
		return;
	}
	w->used = q->used;
	w->niov = q->niov;
	w->open = q->iov[q->niov - 1].base + q->iov[q->niov - 1].len == q->buf + q->used;
}

/* One piece of the wire stream: copied into the encode buffer, or referenced in place. */
static void txw_piece(struct txw *w, const uint8_t *src, uint32_t n, int ref)
{
	wri_m2_txq *q = w->q;

	if (n == 0)
		return;
	if (ref) {
		if (!w->dry) {
			q->iov[w->niov].base = src;
			q->iov[w->niov].len = n;
		}
		w->niov++;
		w->open = 0;
	} else {
		if (!w->dry) {
			WR_MEMCPY(q->buf + w->used, src, n);
			if (w->open) {
				q->iov[w->niov - 1].len += n;
			} else {
				q->iov[w->niov].base = q->buf + w->used;
				q->iov[w->niov].len = n;
			}
		}
		if (!w->open)
			w->niov++;
		w->open = 1;
		w->used += n;
	}
	if (!w->dry) {
		q->pending += n;
		if (w->log_fn != NULL)
			w->log_fn(w->log, src, n);
	}
}

/* Does the piece list fit (dry pass `w` is finished)? WR_OK / WR_E_BUSY / WR_E_TOOBIG. */
static wr_status txw_verdict(const struct txw *now, const struct txw *alone, const wri_m2_txq *q)
{
	if (alone->used > q->cap || alone->niov > WRI_M2_TXQ_IOV)
		return WR_E_TOOBIG; /* would not fit even into an empty queue: waiting does not help */
	if (now->used > q->cap || now->niov > WRI_M2_TXQ_IOV)
		return WR_E_BUSY;
	return WR_OK;
}

static void txq_note(wri_m2_txq *q, wr_status st)
{
	if (st != WR_OK && st != WR_E_BUSY && q->err == WR_OK)
		q->err = st; /* first hard failure, kept for diagnostics; never blocks later appends */
}

/* ---- banner ------------------------------------------------------------------------------- */

wr_status wri_m2_tx_banner(wri_m2_txq *q, wri_m2_log_fn log_fn, void *log)
{
	uint8_t b[WRI_M2_BANNER_LEN];
	struct txw now, alone, w;
	wr_status st;

	if (q == NULL)
		return WR_E_INVAL;
	if (q->sx != NULL)
		return WR_E_STATE; /* the banner is the first plaintext of a connection; behind the switch to secure framing it would be a plaintext write */
	wri_m2_banner_build(b);
	txw_start(&now, q, 0, 1, NULL, NULL);
	txw_start(&alone, q, 1, 1, NULL, NULL);
	txw_piece(&now, b, sizeof(b), 0);
	txw_piece(&alone, b, sizeof(b), 0);
	st = txw_verdict(&now, &alone, q);
	if (st != WR_OK) {
		txq_note(q, st);
		return st;
	}
	txw_start(&w, q, 0, 0, log_fn, log);
	txw_piece(&w, b, sizeof(b), 0);
	q->used = (uint32_t)w.used;
	q->niov = w.niov;
	return WR_OK;
}

/* ---- frame -------------------------------------------------------------------------------- */

/* The piece list of one frame, in wire order. */
static void emit_frame(struct txw *w, const uint8_t pre[WRI_M2_PREAMBLE_LEN], const wri_m2_seg_src *seg,
		       unsigned nseg, const uint8_t crc0[WRI_M2_CRC_LEN], const uint8_t epi[WRI_M2_EPILOGUE_LEN])
{
	unsigned i;

	txw_piece(w, pre, WRI_M2_PREAMBLE_LEN, 0);
	if (seg[0].len != 0) {
		txw_piece(w, seg[0].p, seg[0].len, seg[0].ref != 0);
		txw_piece(w, crc0, WRI_M2_CRC_LEN, 0);
	}
	for (i = 1; i < nseg; i++)
		txw_piece(w, seg[i].p, seg[i].len, seg[i].ref != 0 || i == 3u);
	if (nseg > 1u)
		txw_piece(w, epi, WRI_M2_EPILOGUE_LEN, 0);
}

wr_status wri_m2_tx_frame(wri_m2_txq *q, const wr_prim_ops *prim, uint8_t tag, const wri_m2_seg_src *seg,
			  unsigned nseg, wri_m2_log_fn log_fn, void *log)
{
	uint8_t pre[WRI_M2_PREAMBLE_LEN], crc0[WRI_M2_CRC_LEN], epi[WRI_M2_EPILOGUE_LEN];
	struct txw now, alone, w;
	wri_m2_desc d;
	uint32_t crc;
	unsigned i;
	wr_status st;

	if (q == NULL)
		return WR_E_INVAL;
	if (seg == NULL || nseg < 1u || nseg > WRI_M2_MAX_SEGS || tag < 1u || tag > WRI_M2_TAG_MAX) {
		txq_note(q, WR_E_INVAL);
		return WR_E_INVAL;
	}
	for (i = 0; i < nseg; i++) {
		if (seg[i].len != 0 && seg[i].p == NULL) {
			txq_note(q, WR_E_INVAL);
			return WR_E_INVAL;
		}
	}
	if (nseg > 1u && seg[nseg - 1u].len == 0) { /* the last segment of a multi-segment frame is never empty */
		txq_note(q, WR_E_INVAL);
		return WR_E_INVAL;
	}
	if (q->sx != NULL) { /* secure mode: the codec seam; the transcript callback is not used any more */
		st = wri_m2s_tx_frame(q, prim, tag, seg, nseg);
		txq_note(q, st);
		return st;
	}

	/*
	 * Room check first, on the shape alone: the dry passes never read the pieces' bytes, only their
	 * lengths. A caller that retries after WR_E_BUSY must not pay for a CRC over a multi-megabyte
	 * data segment every time, so the CRCs and the preamble are computed only once the frame is
	 * known to fit.
	 */
	WR_MEMSET(pre, 0, sizeof(pre));
	WR_MEMSET(crc0, 0, sizeof(crc0));
	WR_MEMSET(epi, 0, sizeof(epi));
	txw_start(&now, q, 0, 1, NULL, NULL);
	txw_start(&alone, q, 1, 1, NULL, NULL);
	emit_frame(&now, pre, seg, nseg, crc0, epi);
	emit_frame(&alone, pre, seg, nseg, crc0, epi);
	st = txw_verdict(&now, &alone, q);
	if (st != WR_OK) {
		txq_note(q, st);
		return st;
	}

	WR_MEMSET(&d, 0, sizeof(d));
	d.tag = tag;
	d.nseg = (uint8_t)nseg;
	epi[0] = WRI_M2_LATE_COMPLETE;
	for (i = 0; i < nseg; i++) {
		d.len[i] = seg[i].len;
		d.align[i] = (uint16_t)(i == 3u ? ALIGN_DATA : ALIGN_DEFAULT);
		/* an empty segment's CRC is the seed itself */
		crc = seg[i].len != 0 ? wri_p_crc32c(prim, CRC_SEED, seg[i].p, seg[i].len) : CRC_SEED;
		if (i == 0)
			wri_le32_put(crc0, crc);
		else
			wri_le32_put(epi + 1u + 4u * (i - 1u), crc);
	}
	wri_m2_preamble_build(prim, pre, &d);

	txw_start(&w, q, 0, 0, log_fn, log);
	emit_frame(&w, pre, seg, nseg, crc0, epi);
	q->used = (uint32_t)w.used;
	q->niov = w.niov;
	return WR_OK;
}
