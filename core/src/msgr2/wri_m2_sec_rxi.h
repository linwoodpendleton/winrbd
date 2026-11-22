/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_sec_rxi.h - module-private declarations shared by the two files of the secure receive parser (wri_m2_sec_rx.c: the seam
 * functions, part 1, the helpers; wri_m2_sec_rx2.c: part 2, part 3, the epilogue). Nothing outside those two files includes it; the
 * public face of the parser is wri_m2_sec.h (design: docs/design/core-architecture.md 34.7).
 *
 * The parser is a small machine over the states below. Every state says which bytes of the wire come next; the shared fields of
 * wri_m2_rx (desc, sink, stored, seg, direct, pending_ev, err) carry what the owner sees, wri_m2s_rx carries the rest.
 *
 *   P1   96 bytes: 80 ciphertext + tag. Staged, decrypted in place, tag verified, only then the preamble is looked at.
 *   P2   the rest of segment 0 (padded to 16), decrypted into segment 0's buffer; then
 *   P2T  its 16-byte tag; then the SEG0 event.
 *   P3   segments 1 .. nseg-1, each padded to 16, decrypted in place in its sink (or through the scratch block when it has none);
 *   P3E  the 16-byte epilogue block;
 *   P3T  the tag of part 3; then the epilogue's late-status nibble decides FRAME or ABORTED.
 *
 * Fields of wri_m2s_rx in use: `pos` = bytes of the current element taken in (ring or direct window), `dec` = bytes of it already
 * through the GCM update (dec <= pos; the bytes in between are ciphertext waiting for a whole block), `blk` = the block being
 * collected in the scratch cases, `p1` = part 1. `part_left` is not used by this parser and stays zero.
 */
#ifndef WRI_M2_SEC_RXI_H
#define WRI_M2_SEC_RXI_H

#include "wri_m2_sec.h"

enum {
	WRI_M2SR_NEW = 0, /* zero: before wri_m2s_rx_next() */
	WRI_M2SR_P1,
	WRI_M2SR_P2,
	WRI_M2SR_P2T,
	WRI_M2SR_P3,
	WRI_M2SR_P3E,
	WRI_M2SR_P3T,
	WRI_M2SR_DEAD
};

/* The largest segment length the secure parser accepts: padded to 16 it still fits 32 bits (a configured cap above it is cut here). */
#define WRI_M2SR_LEN_MAX (0xffffffffu - 16u)

/* Return values of the element helpers (a region, a tag). */
#define WRI_M2SR_WAIT 0 /* more input or more budget needed */
#define WRI_M2SR_DONE 1 /* the element is complete */
#define WRI_M2SR_ERR 2  /* a failure was recorded; the caller returns WRI_RXE_ERROR */

/* Record a failure: errinfo, the running GCM operation closed, the staged plaintext wiped, parser DEAD, ERROR sticky. Returns WRI_RXE_ERROR. */
int wri_m2sr_fail(wri_m2_rx *rx, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1, uint64_t a2);
#define WRI_M2SR_FAIL(rx, st, what, a0, a1, a2) wri_m2sr_fail((rx), (st), (unsigned)__LINE__, (what), (a0), (a1), (a2))

/* Set the parser state and keep the shared wri_m2_rx.state in step with it. */
void wri_m2sr_set_state(wri_m2_rx *rx, wri_m2s_rx *sx, unsigned state);
/*
 * Move up to `want` bytes from the ring to dst, paying `unit` budget units per byte (1 for a tag, 2 for a payload byte: its ingress and its
 * decryption are paid together, at the time it comes in). A pull affords a byte while there is a unit left (the last byte may be paid in
 * part), and charges at most what is left. Returns the bytes moved.
 */
uint32_t wri_m2sr_pull(wri_ring *ring, uint8_t *dst, uint32_t want, uint32_t *budget, uint32_t unit);
/* Start the GCM operation of the part being processed (one nonce take) unless it is already running: 0, or 1 after a recorded failure. */
int wri_m2sr_begin(wri_m2_rx *rx, wri_m2s_rx *sx);
/* One GCM decrypt update (n a multiple of 16, in == out or disjoint): 0, or 1 after a recorded failure. */
int wri_m2sr_update(wri_m2_rx *rx, wri_m2s_rx *sx, const uint8_t *in, uint8_t *out, size_t n);
/* Collect the 16-byte tag of the running operation and verify it. part = 1 .. 3 for the error record. */
int wri_m2sr_tag(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget, unsigned part);
/* The frame is over: state back to P1 (the next frame waits until the owner released this event), pending_ev = ev. Returns ev. */
int wri_m2sr_frame_done(wri_m2_rx *rx, wri_m2s_rx *sx, wri_m2_rx_ev ev);

/* States P2, P2T, P3, P3E, P3T (wri_m2_sec_rx2.c). Returns a wri_m2_rx_ev as an int (WRI_RXE_NONE: need input or budget). */
int wri_m2sr_body(wri_m2_rx *rx, wri_m2s_rx *sx, wri_ring *ring, uint32_t *budget);

#endif /* WRI_M2_SEC_RXI_H */
