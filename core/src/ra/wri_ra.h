/* SPDX-License-Identifier: MIT */
/*
 * wri_ra.h - private layout of the readahead cache (public API: wr_ra.h; design: docs/design/ipxe-driver.md section 10).
 *
 * wri_ra.c holds the cache itself (configuration, memory plan, classification of reads, the line states, writes, reset);
 * wri_ra_win.c holds the stream detector and the window planner. They share the struct below and nothing else.
 */
#ifndef WRI_RA_H
#define WRI_RA_H

#include "wr_ra.h"

/* Slot states. */
#define WRI_RA_EMPTY 0u
#define WRI_RA_PENDING 1u
#define WRI_RA_VALID 2u

/* Slot flags. STALE: a PENDING slot whose data must be dropped when it lands (a write or a reset came after its submit).
 * FAILED: an EMPTY slot whose line's prefetch failed; the planner does not ask for it again until the stream restarts. */
#define WRI_RA_STALE 1u
#define WRI_RA_FAILED 2u

#define WRI_RA_NOLINE UINT64_MAX /* lno of a slot that is not about any line */
#define WRI_RA_MAGIC 0x57525241u /* "WRRA" */

typedef struct wri_ra_slot {
	uint64_t lno;   /* line number this slot is about (valid unless WRI_RA_NOLINE) */
	uint32_t len;   /* bytes of the line (the last line of the image can be short); fixed when the prefetch was listed */
	uint8_t state;
	uint8_t flags;
	uint16_t reserved;
} wri_ra_slot;

WR_STATIC_ASSERT(sizeof(wri_ra_slot) == 16u, ra_slot_size);

struct wr_ra {
	uint32_t magic;
	uint32_t line_bytes, line_shift, lines;
	uint32_t two32;      /* 2^32 mod lines (wri_ra_slot_of) */
	uint32_t window, inflight_max, seq_trigger, seq_gap, max_reqs;
	uint32_t pend_bytes, pend_lines;
	uint64_t image_bytes;
	wri_ra_slot *slots;
	uint8_t *data;       /* lines * line_bytes bytes */
	/* the stream detector (wri_ra_win.c) */
	uint64_t prev_off, prev_end, win_end;
	uint32_t prev_len, run;
	uint8_t have_prev, win_open;
	uint8_t waiting;     /* the last read was answered WR_RA_WAIT: its lines are not given away to the window (wri_ra_win.c) */
	uint8_t reserved8;
	wr_ra_stats st;
};

/* The slot line `lno` lives in: lno modulo the slot count, exactly, with 32-bit arithmetic only (i386 iPXE has no __umoddi3): lno = hi * 2^32 + lo
 * and lines <= WR_RA_LINES_MAX (1024), so the product below is under 2^20 (two32 is 2^32 mod lines, kept at init). The low 32 bits alone would not do: with a slot count that is
 * not a power of two the lines on both sides of a multiple of 2^32 (one PiB of image at the default line size, 16 TiB at the smallest) would
 * collide inside one window. */
WR_INLINE uint32_t wri_ra_slot_of(const wr_ra *ra, uint64_t lno)
{
	uint32_t n = ra->lines;
	uint32_t hi = (uint32_t)(lno >> 32) % n;
	uint32_t lo = (uint32_t)lno % n;

	return (hi * ra->two32 + lo) % n;
}

/* Bytes of line lno inside the image: line_bytes, less for the last line, 0 beyond the end. */
WR_INLINE uint32_t wri_ra_line_len(const wr_ra *ra, uint64_t lno)
{
	uint64_t start = lno << ra->line_shift;

	if (start >= ra->image_bytes)
		return 0;
	return ra->image_bytes - start < ra->line_bytes ? (uint32_t)(ra->image_bytes - start) : ra->line_bytes;
}

/* Clear a slot to "no line". */
WR_INLINE void wri_ra_slot_clear(wri_ra_slot *s)
{
	s->lno = WRI_RA_NOLINE;
	s->len = 0;
	s->state = (uint8_t)WRI_RA_EMPTY;
	s->flags = 0;
}

/* wri_ra_win.c */
void wri_ra_win_reset(wr_ra *ra);                          /* forget the stream, close the window */
void wri_ra_seq_note(wr_ra *ra, uint64_t off, uint32_t len); /* a read was asked: advance the detector */

#endif /* WRI_RA_H */
