/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_txi.h - private to the secure transmit side: what wri_m2_sec_tx.c (the frame builder) asks of wri_m2_sec_tx2.c (the stream
 * through the bounce buffer). Not part of any interface above the codec seam; the public face of the module is in wri_m2_sec.h.
 *
 * A stream is the third part of a frame that did not fit the encode buffer: the plaintext of the referenced segments (segment 3 and those with
 * `ref` set) stays in the caller's memory, behind the head of part 3 that was encrypted into the encode buffer at once (the copied segments), and the
 * 16-byte epilogue block and the tag follow it. The encrypted bytes are produced `bounce_cap` at a time into the bounce
 * buffer, the next piece only after the host has consumed the previous one.
 */
#ifndef WRI_M2_SEC_TXI_H
#define WRI_M2_SEC_TXI_H

#include "wri_m2_sec.h"

/* Values of wri_m2s_tx.phase. */
#define WRI_M2S_TXP_IDLE 0u  /* no stream, or everything of it already produced */
#define WRI_M2S_TXP_DATA 1u  /* segments 1 .. nseg-1 */
#define WRI_M2S_TXP_EPI 2u   /* the epilogue block */
#define WRI_M2S_TXP_TAG 3u   /* the tag */

/*
 * Start the stream of a frame: `iv` is the nonce of its third operation (already taken from the nonce stream), seg[first .. nseg-1] the
 * segments the stream reads from the caller's memory (read-only, valid until the host consumed the last byte of the data; `first` is 1 .. nseg,
 * nseg when only the epilogue block and the tag are left), `wire` the bytes the stream will produce in all (the padded segments from `first`,
 * 16 for the epilogue, 16 for the tag). The tx direction's GCM operation is started; then, when head_n is not 0, the `head_n` bytes at `head`
 * (plaintext, a multiple of 16: the copied segments 1 .. first-1 of the frame, already padded, which live in the encode buffer and are the first
 * bytes of the operation) are encrypted in place, and the first piece of the stream is produced into the bounce buffer. The stream must be idle.
 * On any failure the stream is dropped (see wri_m2s_txs_abort) and the status is returned; the nonce is spent either way, and the caller wipes
 * the head.
 */
WR_MUST_CHECK wr_status wri_m2s_txs_begin(wri_m2s_tx *tx, const uint8_t iv[WRI_M2S_NONCE_LEN], const wri_m2_seg_src *seg, unsigned nseg,
					  unsigned first, uint64_t wire, uint8_t *head, size_t head_n);
/* Produce the next piece into the (empty) bounce buffer: as many whole 16-byte blocks as fit, crossing segment ends, the epilogue
 * block and the tag when they come. WR_OK, or the status of the GCM layer (the stream is then in an undefined state: abort it). */
WR_MUST_CHECK wr_status wri_m2s_txs_refill(wri_m2s_tx *tx);
/* Forget the stream: close the running GCM operation (its tag is discarded), erase the bounce buffer, clear the stream fields. The
 * keys are not touched. Safe on an idle stream. */
void wri_m2s_txs_abort(wri_m2s_tx *tx);

#endif /* WRI_M2_SEC_TXI_H */
