/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_rx.c - incremental receive parser for msgr2.1 crc-mode frames (see wri_m2_frame.h and
 * docs/spec/msgr2.md 2.2 to 2.6.1).
 *
 * Shape: the host commits bytes into a staging ring (or, for a big segment that has a sink and
 * an empty ring, straight into the sink: the "direct" window); wri_m2_rx_step() then does the
 * parsing, CRC and copy work on what was committed, bounded by a byte budget, and returns at
 * the next event. Each element (banner head, banner payload, preamble, inline CRC, epilogue) is
 * assembled in rx->stage; payload bytes of a segment are CRC'd as they land. Direct bytes are
 * always logically BEFORE any byte in the ring, so step() settles them first.
 *
 * Events and sticky state. After BANNER the parser is ready for a preamble. After SEG0 the owner
 * may call wri_m2_rx_sink(); the next step() validates the sinks and goes on. FRAME, ABORTED and
 * ERROR are sticky: step() reports the same event again until wri_m2_rx_next_frame() (FRAME and
 * ABORTED) releases it; ERROR is permanent (there is no resynchronisation). pending_ev holds the
 * event that was reported last and still has an after-action (SEG0) or is sticky.
 *
 * For the banner states desc.len[0] holds the peer's banner payload length (desc is otherwise
 * unused there). For the segment 0 states seg_pos counts payload bytes then the inline CRC bytes
 * (L0 is capped below UINT32_MAX - 4 so the sum cannot wrap).
 */
#include "wri_ctx.h"
#include "wri_le.h"
#include "wri_m2_frame.h"
#include "wri_prim.h"

WR_FILE_LICENCE_MIT

#define RC_CONT (-1) /* internal: state changed, run the loop again; any value >= 0 is a wri_m2_rx_ev */
#define CRC_SEED 0xFFFFFFFFu
/* A segment goes straight into its sink only when at least this much of it is still to come:
 * small segments are cheaper through the ring (one recv can then carry several frames). */
#define DIRECT_MIN 1024u
#define BANNER_STAGE 16u

#define RX_FAIL(rx, st, what, a0, a1, a2) rx_fail((rx), (st), (unsigned)__LINE__, (what), (a0), (a1), (a2))

static int rx_fail(wri_m2_rx *rx, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1,
		   uint64_t a2)
{
	wri_errinfo_set(&rx->err, st, WR_MOD_M2, line, what, a0, a1, a2);
	rx->state = WRI_RX_DEAD;
	rx->pending_ev = WRI_RXE_ERROR;
	return (int)WRI_RXE_ERROR;
}

static uint32_t min_u32(uint32_t a, uint32_t b) { return a < b ? a : b; }

void wri_m2_rx_init(wri_m2_rx *rx, uint8_t *seg0, uint32_t seg0_cap, uint32_t seg_cap_max)
{
	WR_MEMSET(rx, 0, sizeof(*rx));
	rx->state = WRI_RX_BANNER_HEAD;
	rx->sink[0].dst = seg0;
	rx->sink[0].cap = seg0 != NULL ? seg0_cap : 0;
	rx->seg_cap_max = seg_cap_max;
}

/* ---- window and commit -------------------------------------------------------------------- */

/* Can the next network bytes go straight into the current segment's sink? Used by window() and
 * commit() alike, so the two always agree. */
static int direct_ok(const wri_m2_rx *rx, const wri_ring *ring, uint32_t *room)
{
	uint32_t len, done;

	if (rx->pending_ev != WRI_RXE_NONE || (rx->state != WRI_RX_SEG0 && rx->state != WRI_RX_SEGS))
		return 0;
	if (ring->len != 0 || rx->seg >= WRI_M2_MAX_SEGS || rx->sink[rx->seg].dst == NULL)
		return 0;
	len = rx->desc.len[rx->seg];
	if (rx->seg_pos >= len || len - rx->seg_pos < rx->direct)
		return 0;
	done = rx->seg_pos + rx->direct;
	if (len - done < DIRECT_MIN && rx->direct == 0)
		return 0;
	*room = len - done;
	return *room != 0;
}

size_t wri_m2_rx_window(wri_m2_rx *rx, wri_ring *ring, uint8_t **ptr)
{
	uint32_t room = 0;

	if (ptr != NULL)
		*ptr = NULL;
	if (rx->state == WRI_RX_DEAD)
		return 0;
	if (direct_ok(rx, ring, &room)) {
		if (ptr != NULL)
			*ptr = rx->sink[rx->seg].dst + rx->seg_pos + rx->direct;
		return room;
	}
	return wri_ring_write_span(ring, ptr);
}

void wri_m2_rx_commit(wri_m2_rx *rx, wri_ring *ring, size_t n)
{
	uint32_t room = 0, k;

	if (rx->state == WRI_RX_DEAD || n == 0)
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

/* ---- element helpers ---------------------------------------------------------------------- */

/* Move bytes from the ring into dst[have..want) (dst NULL: discard them). Honours the budget,
 * reports the raw bytes to the transcript callback. Returns the new fill level. */
static uint32_t pull(wri_ring *ring, uint8_t *dst, uint32_t have, uint32_t want, uint32_t *budget,
		     wri_m2_log_fn log_fn, void *log)
{
	const uint8_t *p;
	uint32_t span, n;

	while (have < want && *budget > 0) {
		span = wri_ring_read_span(ring, &p);
		if (span == 0)
			break;
		n = min_u32(min_u32(span, want - have), *budget);
		if (dst != NULL)
			WR_MEMCPY(dst + have, p, n);
		if (log_fn != NULL)
			log_fn(log, p, n);
		wri_ring_drop(ring, n);
		have += n;
		*budget -= n;
	}
	return have;
}

/* Settle the bytes that were committed straight into the sink: CRC and transcript. 1 when none
 * are left, 0 when the budget ran out first. */
static int seg_settle_direct(wri_m2_rx *rx, const wr_prim_ops *prim, uint32_t *budget, wri_m2_log_fn log_fn,
			     void *log)
{
	const uint8_t *p = rx->sink[rx->seg].dst + rx->seg_pos;
	uint32_t n = min_u32(rx->direct, *budget);

	if (n != 0) {
		rx->crc = wri_p_crc32c(prim, rx->crc, p, n);
		if (log_fn != NULL)
			log_fn(log, p, n);
		rx->seg_pos += n;
		rx->stored[rx->seg] += n;
		rx->direct -= n;
		*budget -= n;
	}
	return rx->direct == 0;
}

/* Payload bytes of segment rx->seg: settle direct bytes, then take from the ring. 1 when the
 * whole payload has been received (and CRC'd), 0 when more input or budget is needed. */
static int seg_payload(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
		       wri_m2_log_fn log_fn, void *log)
{
	const uint32_t len = rx->desc.len[rx->seg];
	uint8_t *dst = rx->sink[rx->seg].dst;
	const uint8_t *p;
	uint32_t n, span;

	if (rx->direct != 0 && !seg_settle_direct(rx, prim, budget, log_fn, log))
		return 0;
	while (rx->seg_pos < len && *budget > 0) {
		span = wri_ring_read_span(ring, &p);
		if (span == 0)
			break;
		n = min_u32(min_u32(span, len - rx->seg_pos), *budget);
		if (dst != NULL) {
			WR_MEMCPY(dst + rx->seg_pos, p, n);
			rx->stored[rx->seg] += n;
		}
		rx->crc = wri_p_crc32c(prim, rx->crc, p, n);
		if (log_fn != NULL)
			log_fn(log, p, n);
		wri_ring_drop(ring, n);
		rx->seg_pos += n;
		*budget -= n;
	}
	return rx->seg_pos >= len;
}

/* ---- states ------------------------------------------------------------------------------- */

static int st_banner_head(wri_m2_rx *rx, wri_ring *ring, uint32_t *budget, wri_m2_log_fn log_fn, void *log)
{
	uint32_t plen = 0;
	wr_status st;

	rx->seg_pos = pull(ring, rx->stage, rx->seg_pos, WRI_M2_BANNER_HEAD, budget, log_fn, log);
	if (rx->seg_pos < WRI_M2_BANNER_HEAD)
		return 0;
	st = wri_m2_banner_head(rx->stage, &plen);
	if (st != WR_OK)
		return RX_FAIL(rx, st, "banner head", rx->stage[0], rx->stage[8], 0);
	rx->desc.len[0] = plen;
	rx->seg_pos = 0;
	rx->state = WRI_RX_BANNER_PAYLOAD;
	return RC_CONT;
}

static int st_banner_payload(wri_m2_rx *rx, wri_ring *ring, uint32_t *budget, wri_m2_log_fn log_fn, void *log)
{
	const uint32_t plen = rx->desc.len[0];
	wr_status st;

	if (rx->seg_pos < BANNER_STAGE) {
		rx->seg_pos = pull(ring, rx->stage, rx->seg_pos, BANNER_STAGE, budget, log_fn, log);
		if (rx->seg_pos < BANNER_STAGE)
			return 0;
	}
	if (rx->seg_pos < plen) { /* bytes past the two masks are consumed and ignored */
		rx->seg_pos = pull(ring, NULL, rx->seg_pos, plen, budget, log_fn, log);
		if (rx->seg_pos < plen)
			return 0;
	}
	st = wri_m2_banner_payload(rx->stage, BANNER_STAGE, &rx->banner);
	if (st != WR_OK)
		return RX_FAIL(rx, st, "banner features", rx->banner.supported, rx->banner.required, 0);
	WR_MEMSET(&rx->desc, 0, sizeof(rx->desc));
	rx->seg_pos = 0;
	rx->state = WRI_RX_PREAMBLE;
	return (int)WRI_RXE_BANNER;
}

/* Caps: segments 1..3 by the configured maximum, segment 0 by its buffer (or the maximum when it
 * is discarded). A sink smaller than its segment is checked once the owner chose it. */
static int preamble_caps(wri_m2_rx *rx)
{
	const wri_m2_desc *d = &rx->desc;
	uint32_t lim = rx->sink[0].dst != NULL ? rx->sink[0].cap : rx->seg_cap_max;
	unsigned i;

	if (d->len[0] > lim || d->len[0] > 0xffffffffu - WRI_M2_CRC_LEN)
		return RX_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment 0 too big", d->len[0], lim, 0);
	for (i = 1; i < d->nseg; i++) {
		if (d->len[i] > rx->seg_cap_max)
			return RX_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment too big", d->len[i], rx->seg_cap_max, i);
	}
	return RC_CONT;
}

static int st_preamble(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
		       wri_m2_log_fn log_fn, void *log)
{
	wr_status st;
	int rc;

	rx->seg_pos = pull(ring, rx->stage, rx->seg_pos, WRI_M2_PREAMBLE_LEN, budget, log_fn, log);
	if (rx->seg_pos < WRI_M2_PREAMBLE_LEN)
		return 0;
	st = wri_m2_preamble_parse(prim, rx->stage, &rx->desc);
	if (st != WR_OK)
		return RX_FAIL(rx, st, "preamble", rx->stage[0], rx->stage[1], 0);
	rc = preamble_caps(rx);
	if (rc != RC_CONT)
		return rc;
	WR_MEMSET(rx->stored, 0, sizeof(rx->stored));
	WR_MEMSET(rx->seg_crc, 0, sizeof(rx->seg_crc));
	rx->seg0_inline_crc_ok = 0;
	rx->seg = 0;
	rx->seg_pos = 0;
	rx->direct = 0;
	rx->crc = CRC_SEED;
	if (rx->desc.len[0] == 0) { /* no payload and no inline CRC at all */
		rx->state = WRI_RX_SEGS;
		rx->seg = 1;
		rx->pending_ev = WRI_RXE_SEG0;
		return (int)WRI_RXE_SEG0;
	}
	rx->state = WRI_RX_SEG0;
	return RC_CONT;
}

static int st_seg0(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
		   wri_m2_log_fn log_fn, void *log)
{
	const uint32_t len = rx->desc.len[0];
	uint32_t have;

	if (rx->seg_pos < len && !seg_payload(rx, ring, prim, budget, log_fn, log))
		return 0;
	have = pull(ring, rx->stage, rx->seg_pos - len, WRI_M2_CRC_LEN, budget, log_fn, log);
	rx->seg_pos = len + have;
	if (have < WRI_M2_CRC_LEN)
		return 0;
	if (wri_le32_get(rx->stage) != rx->crc)
		return RX_FAIL(rx, WR_E_M2_FRAME_CRC, "segment 0 crc", rx->crc, wri_le32_get(rx->stage), 0);
	rx->seg_crc[0] = rx->crc;
	rx->seg0_inline_crc_ok = 1;
	rx->state = WRI_RX_SEGS;
	rx->seg = 1;
	rx->seg_pos = 0;
	rx->crc = CRC_SEED;
	rx->pending_ev = WRI_RXE_SEG0;
	return (int)WRI_RXE_SEG0;
}

/* First step after a SEG0 event: the owner has chosen its sinks, check them against the lengths. */
static int after_seg0(wri_m2_rx *rx)
{
	unsigned i;

	for (i = 1; i < rx->desc.nseg; i++) {
		rx->seg_crc[i] = CRC_SEED; /* an empty segment passes the seed through */
		if (rx->desc.len[i] != 0 && rx->sink[i].dst != NULL && rx->desc.len[i] > rx->sink[i].cap)
			return RX_FAIL(rx, WR_E_M2_FRAME_TOOBIG, "segment exceeds its sink", rx->desc.len[i],
				       rx->sink[i].cap, i);
	}
	rx->pending_ev = WRI_RXE_NONE;
	return RC_CONT;
}

static int frame_done(wri_m2_rx *rx, wri_m2_rx_ev ev)
{
	rx->state = WRI_RX_PREAMBLE; /* ready for the next frame once next_frame() releases the event */
	rx->seg_pos = 0;
	rx->direct = 0;
	rx->pending_ev = (uint8_t)ev;
	return (int)ev;
}

static int st_segs(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
		   wri_m2_log_fn log_fn, void *log)
{
	for (;;) {
		while (rx->seg < rx->desc.nseg && rx->desc.len[rx->seg] == 0)
			rx->seg++;
		if (rx->seg >= rx->desc.nseg)
			break;
		if (!seg_payload(rx, ring, prim, budget, log_fn, log))
			return 0;
		rx->seg_crc[rx->seg] = rx->crc;
		rx->seg++;
		rx->seg_pos = 0;
		rx->crc = CRC_SEED;
	}
	if (rx->desc.nseg == 1u) /* a single-segment frame has no epilogue */
		return frame_done(rx, WRI_RXE_FRAME);
	rx->state = WRI_RX_EPILOGUE;
	rx->seg_pos = 0;
	return RC_CONT;
}

static int st_epilogue(wri_m2_rx *rx, wri_ring *ring, uint32_t *budget, wri_m2_log_fn log_fn, void *log)
{
	unsigned i;
	uint32_t got;

	rx->seg_pos = pull(ring, rx->stage, rx->seg_pos, WRI_M2_EPILOGUE_LEN, budget, log_fn, log);
	if (rx->seg_pos < WRI_M2_EPILOGUE_LEN)
		return 0;
	if ((rx->stage[0] & 0x0Fu) == WRI_M2_LATE_ABORTED)
		return frame_done(rx, WRI_RXE_ABORTED); /* the sender gave up on this frame: nothing to check */
	if ((rx->stage[0] & 0x0Fu) != WRI_M2_LATE_COMPLETE)
		return RX_FAIL(rx, WR_E_M2_FRAME_FORM, "late status", rx->stage[0], 0, 0);
	for (i = 1; i < rx->desc.nseg; i++) {
		got = wri_le32_get(rx->stage + 1u + 4u * (i - 1u));
		if (got != rx->seg_crc[i])
			return RX_FAIL(rx, WR_E_M2_FRAME_CRC, "segment crc", rx->seg_crc[i], got, i);
	}
	return frame_done(rx, WRI_RXE_FRAME);
}

wri_m2_rx_ev wri_m2_rx_step(wri_m2_rx *rx, wri_ring *ring, const wr_prim_ops *prim, uint32_t *budget,
			    wri_m2_log_fn log_fn, void *log)
{
	uint32_t unlimited = 0xffffffffu;
	int rc;

	if (budget == NULL)
		budget = &unlimited;
	for (;;) {
		if (rx->pending_ev == WRI_RXE_FRAME || rx->pending_ev == WRI_RXE_ABORTED ||
		    rx->pending_ev == WRI_RXE_ERROR)
			return (wri_m2_rx_ev)rx->pending_ev; /* sticky until next_frame() / forever */
		if (rx->pending_ev == WRI_RXE_SEG0) {
			rc = after_seg0(rx);
			if (rc != RC_CONT)
				return (wri_m2_rx_ev)rc;
		}
		switch ((unsigned)rx->state) {
		case WRI_RX_BANNER_HEAD:
			rc = st_banner_head(rx, ring, budget, log_fn, log);
			break;
		case WRI_RX_BANNER_PAYLOAD:
			rc = st_banner_payload(rx, ring, budget, log_fn, log);
			break;
		case WRI_RX_PREAMBLE:
			rc = st_preamble(rx, ring, prim, budget, log_fn, log);
			break;
		case WRI_RX_SEG0:
			rc = st_seg0(rx, ring, prim, budget, log_fn, log);
			break;
		case WRI_RX_SEGS:
			rc = st_segs(rx, ring, prim, budget, log_fn, log);
			break;
		case WRI_RX_EPILOGUE:
			rc = st_epilogue(rx, ring, budget, log_fn, log);
			break;
		default:
			rc = RX_FAIL(rx, WR_E_STATE, "parser state", rx->state, 0, 0);
			break;
		}
		if (rc != RC_CONT)
			return (wri_m2_rx_ev)rc;
	}
}

/* ---- owner interface ---------------------------------------------------------------------- */

void wri_m2_rx_sink(wri_m2_rx *rx, unsigned seg, uint8_t *dst, uint32_t cap)
{
	/* Only between a SEG0 event and the next step: that is when the lengths are known and the
	 * sink check has not run yet. Anything else would bypass the check, so it is ignored. */
	if (seg < 1u || seg >= WRI_M2_MAX_SEGS || rx->pending_ev != WRI_RXE_SEG0)
		return;
	rx->sink[seg].dst = dst;
	rx->sink[seg].cap = dst != NULL ? cap : 0;
	rx->stored[seg] = 0;
}

const wri_m2_banner *wri_m2_rx_banner(const wri_m2_rx *rx) { return &rx->banner; }

const wr_errinfo *wri_m2_rx_error(const wri_m2_rx *rx) { return &rx->err; }

void wri_m2_rx_next_frame(wri_m2_rx *rx)
{
	if (rx->pending_ev != WRI_RXE_FRAME && rx->pending_ev != WRI_RXE_ABORTED)
		return;
	WR_MEMSET(&rx->sink[1], 0, sizeof(rx->sink) - sizeof(rx->sink[0]));
	WR_MEMSET(rx->stored, 0, sizeof(rx->stored));
	WR_MEMSET(rx->seg_crc, 0, sizeof(rx->seg_crc));
	WR_MEMSET(&rx->desc, 0, sizeof(rx->desc));
	rx->seg0_inline_crc_ok = 0;
	rx->pending_ev = WRI_RXE_NONE;
	rx->state = WRI_RX_PREAMBLE;
	rx->seg = 0;
	rx->seg_pos = 0;
	rx->direct = 0;
	rx->crc = CRC_SEED;
}
