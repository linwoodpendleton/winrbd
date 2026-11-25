/* SPDX-License-Identifier: MIT */
/*
 * wri_ra.c - the readahead cache: configuration and memory plan, classification of reads, the states of the lines, writes, reset
 * (public API in wr_ra.h; design: docs/design/ipxe-driver.md section 10). The stream detector and the window planner are wri_ra_win.c.
 *
 * Nothing here copies image data, calls the host or allocates: the module only keeps books about memory the host owns.
 */
#include "wri_ra.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define HDR_ALIGN 16u

/* ---- configuration and memory ----------------------------------------------------------------------------------- */

static int is_pow2(uint32_t v)
{
	return v != 0u && (v & (v - 1u)) == 0u;
}

/* log2 of a power of two. */
static uint32_t log2_u32(uint32_t v)
{
	uint32_t n = 0;

	while (v > 1u) {
		v >>= 1;
		n++;
	}
	return n;
}

/* Validate cfg and give the normalised line size (the other defaults are applied in init). */
static wr_status check_cfg(const wr_ra_cfg *cfg, uint32_t *line_bytes)
{
	uint32_t lb, i;

	if (cfg == NULL)
		return WR_E_INVAL;
	if (cfg->size != (uint32_t)sizeof(wr_ra_cfg))
		return WR_E_ABI;
	lb = cfg->line_bytes == 0u ? WR_RA_LINE_DEFAULT : cfg->line_bytes;
	if (!is_pow2(lb) || lb < WR_RA_LINE_MIN || lb > WR_RA_LINE_MAX)
		return WR_E_INVAL;
	if (cfg->lines == 0u || cfg->lines > WR_RA_LINES_MAX)
		return WR_E_INVAL;
	if ((uint64_t)cfg->lines * lb > (uint64_t)WR_RA_CACHE_MAX)
		return WR_E_TOOBIG;
	if (cfg->image_bytes == 0u)
		return WR_E_INVAL;
	for (i = 0; i < 4u; i++)
		if (cfg->reserved[i] != 0u)
			return WR_E_INVAL;
	*line_bytes = lb;
	return WR_OK;
}

/* The struct, rounded up to 16 bytes; the slot table follows it, then the line memory (every slot is 16 bytes, so every part is aligned). */
static size_t struct_bytes(void)
{
	return ((sizeof(struct wr_ra) + HDR_ALIGN - 1u) / HDR_ALIGN) * HDR_ALIGN;
}

/* Bytes before the line memory: the struct and the slot table. */
static size_t head_bytes(uint32_t lines)
{
	return struct_bytes() + (size_t)lines * sizeof(wri_ra_slot);
}

/* Bytes of the whole region for a configuration check_cfg accepted (lb: its normalised line size). lines * lb <= WR_RA_CACHE_MAX (1 GiB), so the
 * sum fits any size_t of 32 bits or more. */
static size_t region_bytes(const wr_ra_cfg *cfg, uint32_t lb)
{
	return head_bytes(cfg->lines) + (size_t)cfg->lines * lb;
}

wr_status wr_ra_mem_required(const wr_ra_cfg *cfg, size_t *out)
{
	uint32_t lb = 0;
	wr_status st;

	if (out != NULL)
		*out = 0;
	if (out == NULL)
		return WR_E_INVAL;
	st = check_cfg(cfg, &lb);
	if (st != WR_OK)
		return st;
	*out = region_bytes(cfg, lb);
	return WR_OK;
}

/* Every slot to "no line". */
static void slots_clear(wr_ra *ra)
{
	uint32_t i;

	for (i = 0; i < ra->lines; i++)
		wri_ra_slot_clear(&ra->slots[i]);
}

/* The fields of the handle and the empty slot table (cfg and mem already checked). Kept apart from wr_ra_init, and the loop from this, so that no
 * frame is large under a sanitizer at -O0 (the build checks every frame against a limit). */
static void ra_setup(wr_ra *ra, const wr_ra_cfg *cfg, uint32_t lb, uint8_t *base)
{
	WR_MEMSET(ra, 0, sizeof(*ra));
	ra->magic = WRI_RA_MAGIC;
	ra->line_bytes = lb;
	ra->line_shift = log2_u32(lb);
	ra->lines = cfg->lines;
	ra->two32 = ((0xffffffffu % cfg->lines) + 1u) % cfg->lines;
	ra->window = cfg->window_bytes;
	ra->inflight_max = cfg->inflight_max == 0u ? WR_RA_INFLIGHT_DEFAULT : cfg->inflight_max;
	ra->seq_trigger = cfg->seq_trigger == 0u ? WR_RA_TRIGGER_DEFAULT : cfg->seq_trigger;
	ra->seq_gap = cfg->seq_gap == 0u ? lb : cfg->seq_gap;
	ra->max_reqs = cfg->max_reqs;
	ra->image_bytes = cfg->image_bytes;
	ra->slots = (wri_ra_slot *)(void *)(base + struct_bytes());
	ra->data = base + head_bytes(cfg->lines);
	slots_clear(ra);
}

wr_status wr_ra_init(const wr_ra_cfg *cfg, wr_mem_region mem, wr_ra **out)
{
	uint32_t lb = 0;
	wr_status st;

	if (out != NULL)
		*out = NULL;
	if (out == NULL)
		return WR_E_INVAL;
	st = check_cfg(cfg, &lb);
	if (st != WR_OK)
		return st;
	if (mem.base == NULL || ((uintptr_t)mem.base & (HDR_ALIGN - 1u)) != 0u)
		return WR_E_INVAL;
	if (mem.size < region_bytes(cfg, lb))
		return WR_E_BUDGET;
	ra_setup((struct wr_ra *)mem.base, cfg, lb, (uint8_t *)mem.base);
	*out = (struct wr_ra *)mem.base;
	return WR_OK;
}

wr_status wr_ra_cfg_from_kib(wr_ra_cfg *cfg, uint64_t image_bytes, uint32_t readahead_kib, uint32_t inflight_max)
{
	uint64_t bytes;
	uint32_t lines;

	if (cfg == NULL)
		return WR_E_INVAL;
	WR_MEMSET(cfg, 0, sizeof(*cfg));
	if (readahead_kib == 0u || image_bytes == 0u)
		return WR_E_INVAL;
	bytes = (uint64_t)readahead_kib * 1024u;
	if (bytes > (uint64_t)WR_RA_CACHE_MAX)
		return WR_E_TOOBIG;
	lines = (uint32_t)(bytes >> 18); /* / WR_RA_LINE_DEFAULT (2^18): a shift, no 64-bit division */
	if (lines == 0u)
		lines = 1u;
	if (lines > WR_RA_LINES_MAX)
		return WR_E_TOOBIG;
	cfg->size = (uint32_t)sizeof(*cfg);
	cfg->line_bytes = WR_RA_LINE_DEFAULT;
	cfg->lines = lines;
	cfg->window_bytes = (uint32_t)bytes;
	cfg->inflight_max = inflight_max;
	cfg->image_bytes = image_bytes;
	return WR_OK;
}

/* ---- reads ------------------------------------------------------------------------------------------------------ */

static int ra_ok(const wr_ra *ra)
{
	return ra != NULL && ra->magic == WRI_RA_MAGIC;
}

wr_status wr_ra_read(wr_ra *ra, uint64_t off, uint32_t len, wr_ra_act *act)
{
	uint64_t end, first, last, j;
	uint32_t wait_slot = 0;
	int missing = 0, waiting = 0;

	if (act != NULL) {
		act->kind = WR_RA_MISS;
		act->line = 0;
	}
	if (!ra_ok(ra) || act == NULL)
		return WR_E_INVAL;
	if (len == 0u) {
		act->kind = WR_RA_HIT;
		return WR_OK;
	}
	end = off + len;
	if (end < off || end > ra->image_bytes)
		return WR_E_RANGE;
	wri_ra_seq_note(ra, off, len);
	first = off >> ra->line_shift;
	last = (end - 1u) >> ra->line_shift;
	if (last - first >= ra->lines) {
		missing = 1; /* wider than the cache: the lines would evict each other */
	} else {
		for (j = first; j <= last && !missing; j++) {
			uint32_t idx = wri_ra_slot_of(ra, j);
			const wri_ra_slot *s = &ra->slots[idx];

			if (s->lno != j || s->state == WRI_RA_EMPTY || (s->flags & WRI_RA_STALE) != 0u)
				missing = 1;
			else if (s->state == WRI_RA_PENDING && !waiting) {
				waiting = 1;
				wait_slot = idx;
			}
		}
	}
	ra->st.reads++;
	ra->waiting = (uint8_t)(!missing && waiting);
	if (missing) {
		ra->st.misses++;
		act->kind = WR_RA_MISS;
	} else if (waiting) {
		ra->st.waits++;
		act->kind = WR_RA_WAIT;
		act->line = wait_slot;
	} else {
		ra->st.hits++;
		act->kind = WR_RA_HIT;
	}
	return WR_OK;
}

size_t wr_ra_span(const wr_ra *ra, uint64_t off, uint32_t len, const uint8_t **p)
{
	uint64_t j;
	uint32_t idx, in_line, avail;
	const wri_ra_slot *s;

	if (p != NULL)
		*p = NULL;
	if (!ra_ok(ra) || p == NULL || len == 0u || off >= ra->image_bytes)
		return 0;
	j = off >> ra->line_shift;
	idx = wri_ra_slot_of(ra, j);
	s = &ra->slots[idx];
	if (s->lno != j || s->state != WRI_RA_VALID)
		return 0;
	in_line = (uint32_t)(off & (uint64_t)(ra->line_bytes - 1u));
	if (in_line >= s->len)
		return 0;
	avail = s->len - in_line;
	if (avail > len)
		avail = len;
	*p = ra->data + ((size_t)idx << ra->line_shift) + in_line;
	return avail;
}

/* ---- the life of a line ------------------------------------------------------------------------------------------ */

/* The PENDING slot a report is about; NULL (with *st set) when there is none. */
static wri_ra_slot *pending_slot(wr_ra *ra, uint32_t line, wr_status *st)
{
	*st = WR_OK;
	if (!ra_ok(ra) || line >= ra->lines) {
		*st = WR_E_INVAL;
		return NULL;
	}
	if (ra->slots[line].state != WRI_RA_PENDING) {
		*st = WR_E_STATE;
		return NULL;
	}
	return &ra->slots[line];
}

/* The request of this slot is over: its bytes leave the in-flight count. */
static void leave_flight(wr_ra *ra, const wri_ra_slot *s)
{
	ra->pend_bytes -= s->len;
	ra->pend_lines--;
}

wr_status wr_ra_line_done(wr_ra *ra, uint32_t line, uint32_t *kept)
{
	wr_status st;
	wri_ra_slot *s = pending_slot(ra, line, &st);

	if (kept != NULL)
		*kept = 0;
	if (s == NULL)
		return st;
	leave_flight(ra, s);
	if ((s->flags & WRI_RA_STALE) != 0u) {
		wri_ra_slot_clear(s);
		ra->st.pf_dropped++;
		return WR_OK;
	}
	s->state = (uint8_t)WRI_RA_VALID;
	s->flags = 0;
	ra->st.pf_landed++;
	if (kept != NULL)
		*kept = 1;
	return WR_OK;
}

wr_status wr_ra_line_failed(wr_ra *ra, uint32_t line)
{
	wr_status st;
	wri_ra_slot *s = pending_slot(ra, line, &st);

	if (s == NULL)
		return st;
	leave_flight(ra, s);
	if ((s->flags & WRI_RA_STALE) != 0u) {
		wri_ra_slot_clear(s);
		ra->st.pf_dropped++;
		return WR_OK;
	}
	s->state = (uint8_t)WRI_RA_EMPTY; /* silent: the line stays about its lno so that the planner can see it failed */
	s->flags = (uint8_t)WRI_RA_FAILED;
	ra->st.pf_failed++;
	return WR_OK;
}

wr_status wr_ra_line_unissued(wr_ra *ra, uint32_t line)
{
	wr_status st;
	wri_ra_slot *s = pending_slot(ra, line, &st);

	if (s == NULL)
		return st;
	leave_flight(ra, s);
	wri_ra_slot_clear(s);
	ra->st.pf_issued--;
	return WR_OK;
}

/* ---- writes, reopen, counters ------------------------------------------------------------------------------------ */

uint32_t wr_ra_write(wr_ra *ra, uint64_t off, uint64_t len)
{
	uint64_t end, first, last;
	uint32_t i, n = 0;

	if (!ra_ok(ra))
		return 0;
	ra->waiting = 0; /* a command that is writing is not parked on a line (one command at a time): nothing is held for a read that was given up */
	if (len == 0u || off >= ra->image_bytes)
		return 0;
	end = off + len;
	if (end < off || end > ra->image_bytes)
		end = ra->image_bytes;
	first = off >> ra->line_shift;
	last = (end - 1u) >> ra->line_shift;
	ra->st.writes++;
	for (i = 0; i < ra->lines; i++) {
		wri_ra_slot *s = &ra->slots[i];

		if (s->lno == WRI_RA_NOLINE || s->lno < first || s->lno > last)
			continue;
		if (s->state == WRI_RA_VALID) {
			wri_ra_slot_clear(s);
			n++;
		} else if (s->state == WRI_RA_PENDING) {
			if ((s->flags & WRI_RA_STALE) == 0u)
				n++;
			s->flags |= (uint8_t)WRI_RA_STALE;
		} else { /* EMPTY: only the "failed" memory of a line the write may have changed */
			wri_ra_slot_clear(s);
		}
	}
	ra->st.lines_invalidated += n;
	return n;
}

wr_status wr_ra_reset(wr_ra *ra, uint64_t image_bytes)
{
	uint32_t i;

	if (!ra_ok(ra) || image_bytes == 0u)
		return WR_E_INVAL;
	for (i = 0; i < ra->lines; i++) {
		wri_ra_slot *s = &ra->slots[i];

		if (s->state == WRI_RA_PENDING) {
			if ((s->flags & WRI_RA_STALE) == 0u)
				ra->st.lines_invalidated++;
			s->flags |= (uint8_t)WRI_RA_STALE;
		} else {
			if (s->state == WRI_RA_VALID)
				ra->st.lines_invalidated++;
			wri_ra_slot_clear(s);
		}
	}
	ra->image_bytes = image_bytes;
	wri_ra_win_reset(ra);
	return WR_OK;
}

void wr_ra_get_stats(const wr_ra *ra, wr_ra_stats *out)
{
	uint32_t i, valid = 0;

	if (out == NULL)
		return;
	WR_MEMSET(out, 0, sizeof(*out));
	if (!ra_ok(ra))
		return;
	*out = ra->st;
	for (i = 0; i < ra->lines; i++)
		if (ra->slots[i].state == WRI_RA_VALID)
			valid++;
	out->pend_lines = ra->pend_lines;
	out->pend_bytes = ra->pend_bytes;
	out->valid_lines = valid;
}
