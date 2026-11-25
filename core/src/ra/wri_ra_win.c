/* SPDX-License-Identifier: MIT */
/*
 * wri_ra_win.c - the stream detector and the window planner of the readahead cache (docs/design/ipxe-driver.md section 10).
 *
 * Detector: a read that starts where the previous one ended (a forward gap of at most seq_gap bytes, or any jump forward that lands inside
 * what the window already covers) continues the stream; seq_trigger continuations in a row open the window; a read that does not continue
 * it closes the window (and a new stream forgets the failed lines). Planner: with the window open, the lines that cover [end of the last read, + window)
 * and are not cached are listed one at a time, never past the in-flight limit and never taking a slot that a request still owns.
 *
 * Offsets are checked against the image size (a read or write that ends past it is refused before it reaches the detector), so the
 * additions on them below cannot wrap; the one that can (the end of the window, the window size being any 32-bit number) saturates.
 */
#include "wri_ra.h"

WR_FILE_LICENCE_MIT

WR_STATIC_ASSERT(WR_RA_LINE_DEFAULT == (1u << 18), ra_line_default_is_2_18);

static uint64_t sat_add(uint64_t a, uint64_t b)
{
	return a + b < a ? UINT64_MAX : a + b;
}

void wri_ra_win_reset(wr_ra *ra)
{
	ra->have_prev = 0;
	ra->waiting = 0;
	ra->win_open = 0;
	ra->run = 0;
	ra->prev_off = ra->prev_end = ra->win_end = 0;
	ra->prev_len = 0;
}

/* Forget which lines failed: they may be tried again (when a new stream starts; while the window is closed nothing is planned anyway). */
static void forget_failed(wr_ra *ra)
{
	uint32_t i;

	for (i = 0; i < ra->lines; i++) {
		wri_ra_slot *s = &ra->slots[i];

		if (s->state == WRI_RA_EMPTY && (s->flags & WRI_RA_FAILED) != 0u)
			wri_ra_slot_clear(s);
	}
}

/* The stream broke: the window closes. */
static void win_close(wr_ra *ra)
{
	ra->win_open = 0;
	ra->win_end = 0;
}

void wri_ra_seq_note(wr_ra *ra, uint64_t off, uint32_t len)
{
	int seq = 0;

	/* the same read again is a re-query of a wait, not a second step of the stream */
	if (ra->have_prev != 0u && off == ra->prev_off && len == ra->prev_len)
		return;
	if (ra->have_prev != 0u && off >= ra->prev_end) {
		uint64_t gap = off - ra->prev_end;

		seq = gap <= ra->seq_gap || (ra->win_open != 0u && off < ra->win_end);
	}
	if (seq) {
		if (ra->run != UINT32_MAX)
			ra->run++;
	} else {
		ra->run = 0;
		if (ra->win_open != 0u)
			win_close(ra);
	}
	ra->have_prev = 1;
	ra->prev_off = off;
	ra->prev_len = len;
	ra->prev_end = off + len;
	if (ra->window != 0u && ra->run >= ra->seq_trigger && ra->win_open == 0u) {
		ra->win_open = 1;
		ra->st.windows++;
		forget_failed(ra);
	}
	if (ra->win_open != 0u)
		ra->win_end = sat_add(ra->prev_end, ra->window);
}

/* The lines the window covers: *first is the line of the stream's position, the result is how many lines to look at (0 if none): up to the end
 * of the window or of the image, and never more than the cache has slots (a window larger than the cache is a ring: the lines past the first
 * `lines` wait until the stream moves on). While the last read was answered with a wait, the ring does not reach back over its lines: the
 * lines of that read that come before `*first` (all of them when it ended on a line boundary, all but the last otherwise) are cached bytes the
 * parked command still has to copy, and taking their slots for lines ahead would turn its hit into a miss; so the ring is `lines` minus that
 * many lines (none at all when the read filled the whole cache). A hit or a miss has been copied or read directly already, nobody needs its
 * lines, and the ring stays whole (the window slides at full depth).
 * Kept apart from the loop so that every frame stays small even without an optimiser. */
static uint64_t window_span(const wr_ra *ra, uint64_t *first)
{
	uint64_t end, n, cap = ra->lines;

	*first = ra->prev_end >> ra->line_shift;
	if (ra->prev_end >= ra->image_bytes)
		return 0;
	if (ra->waiting != 0u) {
		uint64_t held = *first - (ra->prev_off >> ra->line_shift); /* lines of the parked read before the one the stream is in */

		cap = held < ra->lines ? ra->lines - held : 0u;
	}
	end = ra->win_end < ra->image_bytes ? ra->win_end : ra->image_bytes;
	n = ((end - 1u) >> ra->line_shift) - *first + 1u;
	return n > cap ? cap : n;
}

#define LINE_SKIP 0 /* nothing to do for this line */
#define LINE_TAKE 1 /* list it */
#define LINE_STOP 2 /* a limit is reached: the same for every line behind this one */

static int line_verdict(const wr_ra *ra, uint64_t j, uint32_t len, uint32_t demand_bytes)
{
	const wri_ra_slot *s = &ra->slots[wri_ra_slot_of(ra, j)];

	if (s->lno == j && s->state != WRI_RA_EMPTY)
		return LINE_SKIP; /* cached, in flight, or in flight and already dropped */
	if (s->state == WRI_RA_PENDING)
		return LINE_SKIP; /* the slot belongs to a request of another line */
	if (s->lno == j && (s->flags & WRI_RA_FAILED) != 0u)
		return LINE_SKIP; /* it failed once in this stream */
	if ((uint64_t)ra->pend_bytes + demand_bytes + len > ra->inflight_max)
		return LINE_STOP;
	if (ra->max_reqs != 0u && (uint64_t)ra->pend_lines + 2u > ra->max_reqs)
		return LINE_STOP; /* this prefetch and the demand read must fit the host's request table */
	return LINE_TAKE;
}

/* The slot of line j (EMPTY, or holding a line the stream has left behind) becomes the target of a prefetch. */
static void line_take(wr_ra *ra, uint64_t j, uint32_t len, wr_ra_pf *pf)
{
	uint32_t idx = wri_ra_slot_of(ra, j);
	wri_ra_slot *s = &ra->slots[idx];

	s->lno = j;
	s->len = len;
	s->state = (uint8_t)WRI_RA_PENDING;
	s->flags = 0;
	ra->pend_bytes += len;
	ra->pend_lines++;
	if (ra->pend_bytes > ra->st.pend_hiwater_bytes)
		ra->st.pend_hiwater_bytes = ra->pend_bytes;
	ra->st.pf_issued++;
	pf->offset = j << ra->line_shift;
	pf->len = len;
	pf->line = idx;
	pf->buf = ra->data + ((size_t)idx << ra->line_shift);
}

int wr_ra_prefetch_next(wr_ra *ra, uint32_t demand_bytes, wr_ra_pf *pf)
{
	uint64_t first, n, i;

	if (ra == NULL || ra->magic != WRI_RA_MAGIC || pf == NULL || ra->win_open == 0u)
		return 0;
	n = window_span(ra, &first);
	for (i = 0; i < n; i++) {
		uint32_t len = wri_ra_line_len(ra, first + i);
		int v = line_verdict(ra, first + i, len, demand_bytes);

		if (v == LINE_STOP)
			return 0;
		if (v == LINE_TAKE) {
			line_take(ra, first + i, len, pf);
			return 1;
		}
	}
	return 0;
}
