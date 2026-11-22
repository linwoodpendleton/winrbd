/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_tx.c - secure-mode transmit, the frame builder: a frame becomes one to three tagged parts (see wri_m2_sec.h; the stream of a
 * part 3 that does not fit is in wri_m2_sec_tx2.c). Design: docs/design/core-architecture.md 34.6; wire facts: docs/spec/msgr2-secure-mode.md
 * 2.8 and 3.3.
 *
 * Order of work, and why: (1) the shape of the frame and the room it needs are checked on lengths alone, with no side effect; (2) the
 * nonces of its operations are taken, all or none (a copy of the nonce stream is stepped and committed only when every take worked), so
 * a refused or retried frame never skips or repeats one; (3) part 1 (preamble, CRC seed 0, the first 48 bytes of segment 0), part 2
 * (the rest of segment 0) and, when it fits next to them, part 3 are built in the encode buffer and encrypted in place; (4) a part 3 that
 * does not fit is handed to the stream. The queue is updated only when everything worked, so a failure leaves it as it was.
 *
 * What the room rules are: parts 1 and 2 must fit the encode buffer now (WR_E_BUSY if not, WR_E_TOOBIG if they never can) and need at most
 * one new gather entry; part 3 goes into the encode buffer too when it fits there as well, else its tail is streamed from the caller's memory
 * (that memory must stay valid, and unchanged, until the host has consumed it). Only what the caller said it references (ref set, and
 * segment 3 always) may be streamed: a segment that is not referenced is a copy, as in the crc builder, so it is encrypted into the encode
 * buffer before this call returns and the caller may reuse its memory at once. Part 3 is one sequential operation, so everything ahead of
 * the last copied segment is encrypted at once too (the "head" of part 3) and counts towards the room the frame needs now; only the
 * referenced segments behind it, the epilogue block and the tag are streamed. A stream that is still active refuses every frame with
 * WR_E_BUSY: the stream owns the end of the wire and the order of the nonces is the order of the calls.
 *
 * A failure after the nonces were taken (a host that refuses to start an operation, memory of the caller that overlaps the bounce buffer)
 * leaves nothing on the wire and no later frame could be decoded by the peer, so the transmit key is wiped and every later frame is
 * WR_E_STATE: the connection has to fail.
 */
#include "wri_le.h"
#include "wri_m2_sec_txi.h"
#include "wri_misc.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define ALIGN_DEFAULT 8u
#define ALIGN_DATA 4096u
#define OPS_MAX 3u

static uint64_t pad16(uint64_t x)
{
	return (x + (WRI_M2S_BLOCK - 1u)) & ~(uint64_t)(WRI_M2S_BLOCK - 1u);
}

/* One GCM operation over n bytes at p, in place, with its tag appended behind them (the room is the caller's business). */
static wr_status seal(wri_pgcm *g, const uint8_t iv[WRI_M2S_NONCE_LEN], uint8_t *p, size_t n)
{
	wr_status st = wri_pgcm_start(g, iv, 0);

	if (st == WR_OK)
		st = wri_pgcm_update(g, p, p, n);
	if (st == WR_OK)
		st = wri_pgcm_final_enc(g, p + n);
	return st;
}

/* Parts 1 and 2 at p (the plaintext is built in place, then sealed); returns the bytes written through *used. */
static wr_status build_p12(wri_m2s *s, const wr_prim_ops *prim, uint8_t *p, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg,
			   uint8_t iv[OPS_MAX][WRI_M2S_NONCE_LEN], size_t *used)
{
	const uint32_t len0 = seg[0].len;
	size_t inl = len0 < WRI_M2S_INLINE ? len0 : WRI_M2S_INLINE;
	wri_m2_desc d;
	unsigned i;
	wr_status st;

	WR_MEMSET(&d, 0, sizeof(d));
	d.tag = tag;
	d.nseg = (uint8_t)nseg;
	for (i = 0; i < nseg; i++) {
		d.len[i] = seg[i].len;
		d.align[i] = (uint16_t)(i == 3u ? ALIGN_DATA : ALIGN_DEFAULT);
	}
	wri_m2_preamble_build(prim, p, &d); /* CRC-32C over bytes 0..27 with seed 0, kept in secure mode */
	if (inl > 0u)
		WR_MEMCPY(p + WRI_M2_PREAMBLE_LEN, seg[0].p, inl);
	WR_MEMSET(p + WRI_M2_PREAMBLE_LEN + inl, 0, WRI_M2S_INLINE - inl);
	st = seal(&s->tx, iv[0], p, WRI_M2S_P1_PLAIN);
	*used = WRI_M2S_P1_WIRE;
	if (st != WR_OK || len0 <= WRI_M2S_INLINE)
		return st;
	{
		const size_t rest = len0 - WRI_M2S_INLINE;
		const size_t padded = (size_t)pad16(rest);
		uint8_t *q = p + WRI_M2S_P1_WIRE;

		WR_MEMCPY(q, seg[0].p + WRI_M2S_INLINE, rest);
		WR_MEMSET(q + rest, 0, padded - rest);
		st = seal(&s->tx, iv[1], q, padded);
		*used += padded + WRI_M2S_TAG_LEN;
	}
	return st;
}

/* The segments from .. to-1 at p, each zero padded to a multiple of 16 (plaintext); returns the bytes written. */
static size_t copy_segs(uint8_t *p, const wri_m2_seg_src *seg, unsigned from, unsigned to)
{
	size_t off = 0;
	unsigned i;

	for (i = from; i < to; i++) {
		const size_t padded = (size_t)pad16(seg[i].len);

		if (seg[i].len != 0u) /* an empty segment has no pointer to copy from (memcpy of NULL is undefined even for 0 bytes) */
			WR_MEMCPY(p + off, seg[i].p, seg[i].len);
		WR_MEMSET(p + off + seg[i].len, 0, padded - seg[i].len);
		off += padded;
	}
	return off;
}

/* Part 3 at p, whole: the padded segments, the epilogue block, one operation, the tag. */
static wr_status build_p3(wri_m2s *s, uint8_t *p, const wri_m2_seg_src *seg, unsigned nseg, const uint8_t iv[WRI_M2S_NONCE_LEN],
			  size_t *used)
{
	size_t off = copy_segs(p, seg, 1u, nseg);

	p[off] = WRI_M2_LATE_COMPLETE;
	WR_MEMSET(p + off + 1u, 0, WRI_M2S_EPI_LEN - 1u);
	off += WRI_M2S_EPI_LEN;
	*used = off + WRI_M2S_TAG_LEN;
	return seal(&s->tx, iv, p, off);
}

/* The same rules as the crc builder: tag range, 1 to 4 segments, bytes need a pointer, the last of several segments is not empty. */
static int shape_ok(uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	unsigned i;

	if (seg == NULL || nseg < 1u || nseg > WRI_M2_MAX_SEGS || tag < 1u || tag > WRI_M2_TAG_MAX)
		return 0;
	for (i = 0; i < nseg; i++) {
		if (seg[i].len != 0u && seg[i].p == NULL)
			return 0;
	}
	return nseg == 1u || seg[nseg - 1u].len != 0u; /* the last segment of a multi-segment frame is never empty */
}

/* What the frame needs, worked out from its lengths and the state of the queue, before anything is touched. */
typedef struct txf {
	uint64_t wire; /* bytes of the whole frame on the wire */
	uint64_t p3;   /* bytes of part 3 (0 when the frame has one segment) */
	size_t p12;    /* bytes of parts 1 and 2 */
	uint64_t head; /* bytes of the head of part 3: the segments up to the last copied one, encrypted into the encode buffer at once */
	unsigned first; /* the first segment the stream reads from the caller's memory (1 = no head) */
	unsigned nops; /* GCM operations: 1, 2 or 3 */
	int open;      /* the new bytes extend the last gather entry */
	int inline3;   /* part 3 goes into the encode buffer too (else it is streamed) */
	uint8_t iv[OPS_MAX][WRI_M2S_NONCE_LEN];
} txf;

/* The wire arithmetic of the frame from its segment lengths (0 for an invalid shape); nothing of the queue is looked at. */
static wr_status tx_shape(const wri_m2_seg_src *seg, unsigned nseg, txf *f)
{
	uint32_t len[WRI_M2_MAX_SEGS];
	unsigned i;

	for (i = 0; i < WRI_M2_MAX_SEGS; i++)
		len[i] = i < nseg ? seg[i].len : 0u;
	f->wire = wri_m2s_wire_len(len, nseg, &f->nops);
	if (f->wire == 0u)
		return WR_E_INVAL;
	f->p3 = 0;
	f->first = 1u;
	for (i = 1; i < nseg; i++) {
		f->p3 += pad16(len[i]);
		if (seg[i].ref == 0u && i != 3u && len[i] != 0u)
			f->first = i + 1u; /* a copied segment: it and everything ahead of it must be out of the caller's memory when we return */
	}
	if (nseg > 1u)
		f->p3 += WRI_M2S_EPI_LEN + WRI_M2S_TAG_LEN;
	f->p12 = (size_t)(f->wire - f->p3);
	f->head = 0;
	for (i = 1; i < f->first; i++)
		f->head += pad16(len[i]);
	return WR_OK;
}

/* The room rules against the queue: WR_OK, WR_E_TOOBIG (what must be encrypted now can never fit) or WR_E_BUSY (it does not fit now). What must
 * be encrypted now is parts 1 and 2 and the head of part 3 (the copied segments of a streamed frame); the rest of part 3 either fits next to
 * them (all of it goes into the encode buffer) or is streamed. */
static wr_status tx_room(const wri_m2_txq *q, txf *f)
{
	const uint64_t now = (uint64_t)f->p12 + f->head;

	if (now > q->cap)
		return WR_E_TOOBIG; /* parts 1 and 2 (and the copies) alone would not fit an empty encode buffer: waiting does not help */
	/* The new bytes extend the last gather entry when it ends where they begin, else they need an entry of their own. */
	f->open = q->niov > 0u && q->iov[q->niov - 1u].base + q->iov[q->niov - 1u].len == q->buf + q->used;
	if (!f->open && q->niov >= WRI_M2_TXQ_IOV)
		return WR_E_BUSY;
	if ((uint64_t)q->used + now > q->cap)
		return WR_E_BUSY;
	f->inline3 = f->p3 == 0u || (uint64_t)q->used + f->wire <= q->cap;
	return WR_OK;
}

/* The nonces of all the frame's operations, or none: a copy of the stream is stepped and kept only when every take worked. */
static wr_status tx_nonces(wri_m2s *s, txf *f)
{
	wri_m2s_nonce nn = s->tx_n;
	unsigned i;
	wr_status st = WR_OK;

	for (i = 0; i < f->nops; i++) {
		st = wri_m2s_nonce_take(&nn, s->ops_limit, f->iv[i]);
		if (st != WR_OK)
			break; /* WR_E_M2_NONCE: nothing was changed, nothing was produced */
	}
	if (st == WR_OK)
		s->tx_n = nn;
	wri_secure_zero(&nn, sizeof(nn)); /* the copy holds the seed and the counter, which derive from the connection secret */
	return st;
}

/* Parts 1 and 2 (and part 3 when it fits) into the encode buffer at base, or the stream; *written = bytes now in the buffer. */
static wr_status tx_build(wri_m2_txq *q, const wr_prim_ops *prim, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg, txf *f,
			  size_t *written)
{
	wri_m2s_tx *tx = q->sx;
	uint8_t *base = q->buf + q->used;
	size_t w12 = 0, w3 = 0;
	wr_status st = build_p12(tx->s, prim, base, tag, seg, nseg, f->iv, &w12);

	*written = w12;
	if (st != WR_OK || f->p3 == 0u)
		return st;
	if (f->inline3) {
		st = build_p3(tx->s, base + w12, seg, nseg, f->iv[f->nops - 1u], &w3);
		*written += w3;
		return st;
	}
	/* The head of part 3 (the copied segments) goes into the encode buffer now, as plaintext: the stream starts its operation, encrypts it in
	 * place and goes on with the referenced segments behind it. It is counted as written before anything can fail, so that a failure wipes it. */
	w3 = copy_segs(base + w12, seg, 1u, f->first);
	*written += w3;
	/* The stream takes the rest: the bounce buffer holds its first piece when this returns. */
	return wri_m2s_txs_begin(tx, f->iv[f->nops - 1u], seg, nseg, f->first, f->p3 - w3, base + w12, w3);
}

wr_status wri_m2s_tx_frame(wri_m2_txq *q, const wr_prim_ops *prim, uint8_t tag, const wri_m2_seg_src *seg, unsigned nseg)
{
	txf f;
	wri_m2s *s;
	size_t written = 0;
	uint8_t *base;
	wr_status st;

	if (q == NULL || q->sx == NULL || !shape_ok(tag, seg, nseg))
		return WR_E_INVAL;
	s = q->sx->s;
	if (s == NULL || q->sx->bounce == NULL || q->buf == NULL)
		return WR_E_INVAL;
	if (!wri_m2s_tx_done(q))
		return WR_E_BUSY; /* a stream is still going out: no frame may be queued behind its unfinished part 3 */
	if (s->active == 0u || s->tx.keyed == 0u)
		return WR_E_STATE; /* the connection's secure state is gone (wiped after a failure, or never keyed) */
	st = tx_shape(seg, nseg, &f); /* shape and room, on lengths alone: nothing is written, no nonce is taken */
	if (st == WR_OK)
		st = tx_room(q, &f);
	if (st == WR_OK)
		st = tx_nonces(s, &f);
	if (st != WR_OK) {
		wri_secure_zero(f.iv, sizeof(f.iv)); /* the nonces derive from the connection secret: nothing of them is left behind */
		return st;
	}

	/* Parts 1 and 2, and part 3 when it fits next to them, are built in the encode buffer and encrypted in place. */
	base = q->buf + q->used;
	st = tx_build(q, prim, tag, seg, nseg, &f, &written);
	wri_secure_zero(f.iv, sizeof(f.iv));
	if (st != WR_OK) {
		wri_secure_zero(base, written); /* plaintext and ciphertext of a frame that never existed */
		wri_pgcm_wipe(&s->tx);          /* the nonces are spent: nothing may be sealed with this key again */
		return st;
	}

	/* The queue is updated last. */
	if (f.open) {
		q->iov[q->niov - 1u].len += written;
	} else {
		q->iov[q->niov].base = base;
		q->iov[q->niov].len = written;
		q->niov++;
	}
	q->used += (uint32_t)written;
	q->pending += f.wire; /* the stream's bytes count from the start of the frame, so the queue is idle exactly when it is all out */
	return WR_OK;
}
