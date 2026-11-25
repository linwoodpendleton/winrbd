/* SPDX-License-Identifier: MIT */
/*
 * test_ra.c - the readahead cache (core/src/ra/, include/winrbd/wr_ra.h; docs/design/ipxe-driver.md section 10), alone: no engine, the test is the host.
 *
 *   cfg        configuration checks, the memory plan equals what init takes, the readahead= helper
 *   life       every transition of a line: EMPTY -> PENDING -> VALID, PENDING -> EMPTY (failure, refused submit), VALID -> EMPTY (write), PENDING
 *              dropped on landing (write, reset), wrong-state and unknown-slot reports
 *   classify   hit, wait and miss; partial coverage, a range wider than the cache, the last (short) line, the ring wrap of spans, bad arguments
 *   stream     the detector: the trigger, the gap, a repeated read is not a second step, a jump inside the window, a break closes it, window 0
 *   plan       the window planner: the in-flight limit (with the demand read), the ring clamp, busy slots, the end of the image, a failed line is
 *              not asked for again in the same stream, the slot of an old line is taken over
 *   big        line numbers beyond 2^32: the slot of a line is lno mod lines exactly (no wrap of the low 32 bits inside a window)
 *   model      a byte-model test: random reads, writes, completions, failures, refused submits and reopens over many configurations; every byte a
 *              hit would copy is compared with the model of the image, and the invariants of the module are checked at every step
 */
#include "wr_ra.h"
#include "wri_ra.h"
#include "wrt.h"

/* ---- a small host ------------------------------------------------------------------------------------------------ */

typedef struct fcfg {
	uint32_t line, lines, window, inflight, trigger, gap, max_reqs;
	uint64_t image;
} fcfg;

typedef struct fx {
	wr_ra *ra;
	wr_ra_cfg cfg;
	uint8_t *raw;  /* what malloc gave; mem is raw rounded up to 16 bytes (the module's contract) */
	uint8_t *mem;
	size_t mem_size;
	uint8_t *img; /* the image as the test models it */
} fx;

static uint8_t pat(uint64_t i)
{
	return (uint8_t)((i * 2654435761u) >> 13);
}

static int fx_open(fx *f, const fcfg *c)
{
	uint64_t i;
	size_t need = 0;

	memset(f, 0, sizeof(*f));
	f->cfg.size = (uint32_t)sizeof(f->cfg);
	f->cfg.line_bytes = c->line;
	f->cfg.lines = c->lines;
	f->cfg.window_bytes = c->window;
	f->cfg.inflight_max = c->inflight;
	f->cfg.seq_trigger = c->trigger;
	f->cfg.seq_gap = c->gap;
	f->cfg.max_reqs = c->max_reqs;
	f->cfg.image_bytes = c->image;
	if (wr_ra_mem_required(&f->cfg, &need) != WR_OK)
		return -1;
	f->mem_size = need;
	f->raw = (uint8_t *)malloc(need + 16u);
	f->mem = f->raw == NULL ? NULL : (uint8_t *)(((uintptr_t)f->raw + 15u) & ~(uintptr_t)15u);
	f->img = (uint8_t *)malloc((size_t)c->image);
	if (f->mem == NULL || f->img == NULL)
		return -2;
	memset(f->mem, 0xCD, need); /* the module must not lean on zeroed memory */
	for (i = 0; i < c->image; i++)
		f->img[i] = pat(i);
	if (wr_ra_init(&f->cfg, (wr_mem_region){f->mem, need}, &f->ra) != WR_OK)
		return -3;
	return 0;
}

static void fx_close(fx *f)
{
	free(f->raw);
	free(f->img);
}

static wr_ra_act rd(fx *f, uint64_t off, uint32_t len)
{
	wr_ra_act a;

	WRT_CHECK_STATUS(WR_OK, wr_ra_read(f->ra, off, len, &a));
	return a;
}

static unsigned drain(fx *f, uint32_t demand, wr_ra_pf *out, unsigned max)
{
	unsigned n = 0;
	wr_ra_pf pf;

	while (n < max && wr_ra_prefetch_next(f->ra, demand, &pf) != 0)
		out[n++] = pf;
	return n;
}

/* The request of pf finished well: its bytes land (the image as it is now), the line is reported. */
static uint32_t land(fx *f, const wr_ra_pf *pf)
{
	uint32_t kept = 99;

	memcpy(pf->buf, f->img + pf->offset, pf->len);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_done(f->ra, pf->line, &kept));
	return kept;
}

/* Copy a hit out with the span loop and compare it with the image; returns the number of bytes copied. */
static uint32_t copy_hit(fx *f, uint64_t off, uint32_t len, int *same)
{
	uint32_t done = 0;

	*same = 1;
	while (done < len) {
		const uint8_t *p = NULL;
		size_t n = wr_ra_span(f->ra, off + done, len - done, &p);

		if (n == 0 || p == NULL)
			break;
		if (memcmp(p, f->img + off + done, n) != 0)
			*same = 0;
		done += (uint32_t)n;
	}
	return done;
}

#define L4K 4096u

static fcfg small_cfg(void)
{
	fcfg c;

	memset(&c, 0, sizeof(c));
	c.line = L4K;
	c.lines = 4;
	c.window = 3u * L4K;
	c.inflight = 16u * L4K;
	c.trigger = 2;
	c.gap = 0;
	c.image = 20u * L4K + 100u; /* the last line is short */
	return c;
}

/* Open the stream: three back-to-back reads (a miss, then two continuations). Leaves the window open with pos at 1536. */
static void open_stream(fx *f)
{
	WRT_CHECK(rd(f, 0, 512).kind == WR_RA_MISS);
	WRT_CHECK(rd(f, 512, 512).kind == WR_RA_MISS);
	WRT_CHECK(rd(f, 1024, 512).kind == WR_RA_MISS);
}

/* ---- cfg --------------------------------------------------------------------------------------------------------- */

static void test_cfg(void)
{
	wr_ra_cfg c, d;
	size_t need = 0, need2 = 0, need8 = 0;
	fx f;
	fcfg fc = small_cfg();
	wr_ra *ra = NULL;
	uint8_t *raw, *rawmem;

	memset(&c, 0, sizeof(c));
	c.size = (uint32_t)sizeof(c);
	c.lines = 8;
	c.image_bytes = 1u << 20;
	WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&c, &need8)); /* line_bytes 0 = 256 KiB */
	WRT_CHECK(need8 > 8u * 256u * 1024u && need8 < 8u * 256u * 1024u + 4096u);

	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(NULL, &need));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&c, NULL));
	d = c, d.size = 3;
	WRT_CHECK_STATUS(WR_E_ABI, wr_ra_mem_required(&d, &need2));
	d = c, d.line_bytes = 1000;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.line_bytes = 3u * 4096u;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.line_bytes = 2048;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.line_bytes = 8u << 20;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.lines = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.lines = WR_RA_LINES_MAX + 1u;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.lines = WR_RA_LINES_MAX, d.line_bytes = WR_RA_LINE_MAX; /* 4 GiB of lines */
	WRT_CHECK_STATUS(WR_E_TOOBIG, wr_ra_mem_required(&d, &need2));
	d = c, d.image_bytes = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.max_reqs = 1; /* any value is a configuration, none changes the memory */
	WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&d, &need2));
	WRT_CHECK(need2 == need8);
	d = c, d.reserved[3] = 1;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_mem_required(&d, &need2));
	d = c, d.lines = WR_RA_LINES_MAX, d.line_bytes = WR_RA_LINE_MIN; /* the largest slot table */
	WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&d, &need2));
	WRT_CHECK(need2 > 4u * 1024u * 1024u);

	/* the plan is exactly what init takes: one byte less is refused, the exact size works and the line memory is not touched */
	WRT_CHECK(fx_open(&f, &fc) == 0);
	WRT_CHECK(f.mem != NULL);
	{
		size_t exact = 0;

		WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&f.cfg, &exact));
		rawmem = (uint8_t *)malloc(exact + 16u);
		raw = (uint8_t *)(((uintptr_t)rawmem + 15u) & ~(uintptr_t)15u);
		memset(raw, 0x5A, exact);
		WRT_CHECK_STATUS(WR_E_BUDGET, wr_ra_init(&f.cfg, (wr_mem_region){raw, exact - 1u}, &ra));
		WRT_CHECK(ra == NULL);
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_init(&f.cfg, (wr_mem_region){raw + 1, exact}, &ra));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_init(&f.cfg, (wr_mem_region){NULL, exact}, &ra));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_init(&f.cfg, (wr_mem_region){raw, exact}, NULL));
		WRT_CHECK_STATUS(WR_OK, wr_ra_init(&f.cfg, (wr_mem_region){raw, exact}, &ra));
		WRT_CHECK(ra != NULL && (uint8_t *)ra == raw);
		WRT_CHECK(raw[exact - 1u] == 0x5A && raw[exact - 4097u] == 0x5A); /* line memory untouched */
		free(rawmem);
	}
	fx_close(&f);

	/* the readahead= helper */
	WRT_CHECK_STATUS(WR_OK, wr_ra_cfg_from_kib(&c, 1u << 30, 2048, 0));
	WRT_CHECK_U64(c.lines, 8);
	WRT_CHECK_U64(c.line_bytes, WR_RA_LINE_DEFAULT);
	WRT_CHECK_U64(c.window_bytes, 2u << 20);
	WRT_CHECK_U64(c.image_bytes, 1u << 30);
	WRT_CHECK_U64(c.size, sizeof(c));
	WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&c, &need));
	WRT_CHECK_STATUS(WR_OK, wr_ra_cfg_from_kib(&c, 100, 100, 0));
	WRT_CHECK_U64(c.lines, 1); /* less than a line still gets one */
	WRT_CHECK_STATUS(WR_OK, wr_ra_cfg_from_kib(&c, 100, 16384, 123456));
	WRT_CHECK_U64(c.lines, 64);
	WRT_CHECK_U64(c.inflight_max, 123456);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_cfg_from_kib(&c, 100, 0, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_cfg_from_kib(&c, 0, 2048, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_cfg_from_kib(NULL, 100, 2048, 0));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wr_ra_cfg_from_kib(&c, 100, 2u * 1024u * 1024u, 0));
	WRT_CHECK_STATUS(WR_E_TOOBIG, wr_ra_cfg_from_kib(&c, 100, 1024u * 1024u, 0)); /* 1 GiB = 4096 lines */

	/* the defaults and the null handle */
	{
		wr_ra_act a;
		wr_ra_pf pf;
		wr_ra_stats st;

		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_read(NULL, 0, 1, &a));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_done(NULL, 0, NULL));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_failed(NULL, 0));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_unissued(NULL, 0));
		WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_reset(NULL, 1));
		WRT_CHECK(wr_ra_prefetch_next(NULL, 0, &pf) == 0);
		WRT_CHECK(wr_ra_write(NULL, 0, 1) == 0);
		wr_ra_get_stats(NULL, &st);
		WRT_CHECK_U64(st.reads, 0);
	}
}

/* ---- life -------------------------------------------------------------------------------------------------------- */

static void test_life(void)
{
	fx f;
	fcfg c = small_cfg();
	wr_ra_pf pf[8];
	wr_ra_stats st;
	wr_ra_act a;
	uint32_t kept;
	unsigned n;
	int same;

	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	/* the window opened at the third read: [1536, 1536 + 12288) = lines 0..3, all EMPTY -> PENDING, in order, each in its own slot */
	n = drain(&f, 512, pf, 8);
	WRT_CHECK_U64(n, 4);
	for (unsigned i = 0; i < n && i < 4u; i++) {
		WRT_CHECK_U64(pf[i].offset, (uint64_t)i * L4K);
		WRT_CHECK_U64(pf[i].len, L4K);
		WRT_CHECK_U64(pf[i].line, i);
		WRT_CHECK(pf[i].buf == f.ra->data + (size_t)i * L4K);
	}
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 4);
	WRT_CHECK_U64(st.pend_bytes, 4u * L4K);
	WRT_CHECK_U64(st.pf_issued, 4);
	WRT_CHECK_U64(st.valid_lines, 0);
	WRT_CHECK(wr_ra_prefetch_next(f.ra, 0, &pf[4]) == 0); /* nothing more: all four slots are busy */

	/* PENDING: a read inside is a wait for that slot; a read over two pending lines waits for the first */
	a = rd(&f, 100, 50);
	WRT_CHECK(a.kind == WR_RA_WAIT && a.line == 0);
	a = rd(&f, L4K - 10, 20);
	WRT_CHECK(a.kind == WR_RA_WAIT && a.line == 0);
	WRT_CHECK(wr_ra_span(f.ra, 100, 50, &(const uint8_t *){NULL}) == 0); /* not readable yet */

	/* PENDING -> VALID */
	WRT_CHECK_U64(land(&f, &pf[1]), 1);
	a = rd(&f, L4K - 10, 20);
	WRT_CHECK(a.kind == WR_RA_WAIT && a.line == 0); /* line 0 is still the first pending one */
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	a = rd(&f, L4K - 10, 20);
	WRT_CHECK(a.kind == WR_RA_HIT);
	WRT_CHECK_U64(copy_hit(&f, L4K - 10, 20, &same), 20);
	WRT_CHECK(same);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pf_landed, 2);
	WRT_CHECK_U64(st.valid_lines, 2);
	WRT_CHECK_U64(st.pend_lines, 2);
	WRT_CHECK_U64(st.pend_bytes, 2u * L4K);

	/* PENDING -> EMPTY on failure: silent, a read of it is a plain miss, and the same line is not asked for again in this stream */
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, pf[2].line));
	a = rd(&f, 2u * L4K + 5, 10);
	WRT_CHECK(a.kind == WR_RA_MISS);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pf_failed, 1);
	WRT_CHECK_U64(st.pend_lines, 1);

	/* a refused submit: PENDING -> EMPTY with no mark, and the issue does not count */
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_unissued(f.ra, pf[3].line));
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK_U64(st.pf_issued, 3);

	/* wrong reports */
	WRT_CHECK_STATUS(WR_E_STATE, wr_ra_line_done(f.ra, 3, &kept));  /* EMPTY */
	WRT_CHECK_U64(kept, 0);
	WRT_CHECK_STATUS(WR_E_STATE, wr_ra_line_done(f.ra, 0, &kept));  /* VALID */
	WRT_CHECK_STATUS(WR_E_STATE, wr_ra_line_failed(f.ra, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wr_ra_line_unissued(f.ra, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_done(f.ra, 4, &kept));  /* no such slot */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_failed(f.ra, 99));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_line_unissued(f.ra, 0xffffffffu));
	fx_close(&f);

	/* VALID -> EMPTY by a write; a write elsewhere leaves it; a PENDING line is marked and dropped on landing */
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 4);
	for (unsigned i = 0; i < 4u; i++)
		WRT_CHECK_U64(land(&f, &pf[i]), 1);
	a = rd(&f, 1536, 512);
	WRT_CHECK(a.kind == WR_RA_HIT);
	WRT_CHECK_U64(wr_ra_write(f.ra, 2u * L4K + 1, 1), 1);          /* line 2 only */
	WRT_CHECK_U64(wr_ra_write(f.ra, 10u * L4K, 100), 0);           /* no cached line there */
	WRT_CHECK_U64(wr_ra_write(f.ra, L4K - 1, 2), 2);               /* lines 0 and 1 across the boundary */
	WRT_CHECK_U64(wr_ra_write(f.ra, 0, 0), 0);                     /* empty write */
	WRT_CHECK_U64(wr_ra_write(f.ra, 100u * L4K, 5), 0);            /* outside the image */
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.valid_lines, 1);
	WRT_CHECK_U64(st.lines_invalidated, 3);
	WRT_CHECK(rd(&f, 100, 50).kind == WR_RA_MISS);
	WRT_CHECK(rd(&f, 3u * L4K, 50).kind == WR_RA_HIT); /* line 3 was not touched */
	fx_close(&f);

	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 4);
	WRT_CHECK_U64(wr_ra_write(f.ra, 3u * L4K, 4), 1); /* PENDING line 3 is marked */
	WRT_CHECK_U64(wr_ra_write(f.ra, 3u * L4K + 8, 4), 0); /* already marked: not counted twice */
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 4);                 /* the slot is still reserved: a request still owns the memory */
	a = rd(&f, 3u * L4K, 4);
	WRT_CHECK(a.kind == WR_RA_MISS);                 /* a dropped line is not waited for */
	WRT_CHECK(wr_ra_prefetch_next(f.ra, 0, &pf[4]) == 0); /* ... and its slot is not reused until reported */
	f.img[3u * L4K] ^= 0xFF;                         /* the write changed the image; the old request lands old bytes */
	memcpy(pf[3].buf, f.img + 3u * L4K, 8);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_done(f.ra, pf[3].line, &kept));
	WRT_CHECK_U64(kept, 0);                          /* dropped */
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pf_dropped, 1);
	WRT_CHECK_U64(st.valid_lines, 0);
	WRT_CHECK_U64(st.pend_lines, 3);
	/* a marked line that fails is dropped the same way (no failure mark either) */
	WRT_CHECK_U64(wr_ra_write(f.ra, 0, 1), 1);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, pf[0].line));
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pf_dropped, 2);
	WRT_CHECK_U64(st.pf_failed, 0);
	fx_close(&f);

	/* a write whose length reaches past the end of the image, or past 2^64, is clipped to the image: everything from its offset on goes */
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 4);
	for (unsigned i = 0; i < 4u; i++)
		WRT_CHECK_U64(land(&f, &pf[i]), 1);
	WRT_CHECK_U64(wr_ra_write(f.ra, UINT64_MAX, 5), 0);
	WRT_CHECK_U64(wr_ra_write(f.ra, c.image, UINT64_MAX), 0);
	WRT_CHECK_U64(wr_ra_write(f.ra, 3u * L4K + 7, UINT64_MAX), 1); /* 2^64 - 1 bytes from line 3: wraps, clipped: line 3 only is cached there */
	WRT_CHECK_U64(wr_ra_write(f.ra, 5, UINT64_MAX - 3u), 3);       /* off + len wraps: still everything from 5 on */
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.valid_lines, 0);
	fx_close(&f);

	/* reset: VALID lines go, PENDING ones stay reserved and are dropped on landing, the stream is forgotten */
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 4);
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	WRT_CHECK_U64(land(&f, &pf[1]), 1);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_reset(f.ra, 0));
	WRT_CHECK_STATUS(WR_OK, wr_ra_reset(f.ra, c.image));
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.valid_lines, 0);
	WRT_CHECK_U64(st.pend_lines, 2);
	WRT_CHECK_U64(st.lines_invalidated, 4);
	WRT_CHECK(rd(&f, 100, 10).kind == WR_RA_MISS);
	WRT_CHECK(wr_ra_prefetch_next(f.ra, 0, &pf[4]) == 0); /* a new stream needs the trigger again */
	WRT_CHECK_U64(land(&f, &pf[2]), 0);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, pf[3].line));
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK_U64(st.pend_bytes, 0);
	WRT_CHECK_U64(st.pf_dropped, 2);
	fx_close(&f);
}

/* ---- classify ---------------------------------------------------------------------------------------------------- */

static void test_classify(void)
{
	fx f;
	fcfg c = small_cfg();
	wr_ra_pf pf[8];
	wr_ra_act a;
	unsigned n;
	int same;
	const uint8_t *p = NULL;

	c.window = 4u * L4K;
	c.lines = 4;
	c.image = 4u * L4K + 100u; /* four full lines and a short fifth: line 4 shares slot 0 */
	WRT_CHECK(fx_open(&f, &c) == 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wr_ra_read(f.ra, c.image, 1, &a));
	WRT_CHECK_STATUS(WR_E_RANGE, wr_ra_read(f.ra, c.image - 1u, 2, &a));
	WRT_CHECK_STATUS(WR_E_RANGE, wr_ra_read(f.ra, UINT64_MAX - 1u, 4, &a));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_ra_read(f.ra, 0, 1, NULL));
	a = rd(&f, 5, 0); /* zero length: a hit with nothing to copy, and the stream is untouched */
	WRT_CHECK(a.kind == WR_RA_HIT);
	WRT_CHECK_U64(wr_ra_span(f.ra, 0, 0, &p), 0);
	WRT_CHECK_U64(f.ra->have_prev, 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 4); /* lines 0..3 (window 4 lines from 1536: up to line 4, but only four slots) */
	/* line 1 valid, lines 0 pending: a read over both is a wait for 0; with line 0 landed it is a hit that crosses a boundary */
	WRT_CHECK_U64(land(&f, &pf[1]), 1);
	a = rd(&f, L4K - 100, 200);
	WRT_CHECK(a.kind == WR_RA_WAIT && a.line == 0);
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	a = rd(&f, L4K - 100, 200);
	WRT_CHECK(a.kind == WR_RA_HIT);
	WRT_CHECK_U64(wr_ra_span(f.ra, L4K - 100, 200, &p), 100); /* the span stops at the end of the line */
	WRT_CHECK(p == (const uint8_t *)pf[0].buf + (L4K - 100u));
	WRT_CHECK_U64(copy_hit(&f, L4K - 100, 200, &same), 200);
	WRT_CHECK(same);
	/* a range with an EMPTY line among valid ones is a miss, even when the other lines are cached */
	WRT_CHECK_U64(land(&f, &pf[3]), 1);
	a = rd(&f, L4K + 10, 2u * L4K + 10u); /* lines 1, 2 (pending), 3 */
	WRT_CHECK(a.kind == WR_RA_WAIT && a.line == 2);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, pf[2].line));
	a = rd(&f, L4K + 10, 2u * L4K + 10u);
	WRT_CHECK(a.kind == WR_RA_MISS);
	/* wider than the cache: lines 0..4 are five lines in a four-slot cache, a miss without looking */
	a = rd(&f, 100, 4u * L4K);
	WRT_CHECK(a.kind == WR_RA_MISS);
	/* the short last line and the ring: line 4 maps to slot 0; once it is cached, line 0 is not */
	WRT_CHECK_U64(wr_ra_span(f.ra, 4u * L4K, 100, &p), 0);
	fx_close(&f);

	/* spans wrap around the ring: lines 3 and 4 (slots 3 and 0) are adjacent in the image and far apart in memory */
	c = small_cfg();
	c.image = 4u * L4K + 100u;
	c.window = 8u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	WRT_CHECK(rd(&f, 3u * L4K, 512).kind == WR_RA_MISS);
	WRT_CHECK(rd(&f, 3u * L4K + 512, 512).kind == WR_RA_MISS);
	WRT_CHECK(rd(&f, 3u * L4K + 1024, 512).kind == WR_RA_MISS); /* stream open, pos 3*4096+1536: lines 3, 4 (the short one) */
	n = drain(&f, 0, pf, 8);
	WRT_CHECK_U64(n, 2);
	WRT_CHECK_U64(pf[0].line, 3);
	WRT_CHECK_U64(pf[1].line, 0);
	WRT_CHECK_U64(pf[1].offset, 4u * L4K);
	WRT_CHECK_U64(pf[1].len, 100); /* the last line is short */
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	WRT_CHECK_U64(land(&f, &pf[1]), 1);
	a = rd(&f, 4u * L4K - 50, 150); /* the last 50 bytes of line 3 and the first 100 of line 4: end of image */
	WRT_CHECK(a.kind == WR_RA_HIT);
	WRT_CHECK_U64(copy_hit(&f, 4u * L4K - 50, 150, &same), 150);
	WRT_CHECK(same);
	WRT_CHECK_U64(wr_ra_span(f.ra, 4u * L4K + 99, 10, &p), 1);
	WRT_CHECK_U64(wr_ra_span(f.ra, 4u * L4K + 100, 10, &p), 0); /* past the end of the short line (and of the image) */
	fx_close(&f);
}

/* ---- stream ------------------------------------------------------------------------------------------------------ */

static unsigned count_pf(fx *f, uint32_t demand)
{
	wr_ra_pf pf[16];
	unsigned n = drain(f, demand, pf, 16);

	for (unsigned i = 0; i < n; i++)
		WRT_CHECK_STATUS(WR_OK, wr_ra_line_unissued(f->ra, pf[i].line)); /* put them back: only the count matters here */
	return n;
}

static void test_stream(void)
{
	fx f;
	fcfg c = small_cfg();
	wr_ra_stats st;

	c.line = 65536u;
	c.window = 2u * 65536u;
	c.lines = 4;
	c.inflight = 1u << 20;
	c.image = 64u << 20;

	/* the trigger: read one, read two (continuation 1), read three (continuation 2) opens it */
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, 4096, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, 8192, 4096);
	WRT_CHECK(count_pf(&f, 0) > 0);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.windows, 1);
	/* a repeat of the same read (the re-ask after a wait) is not another step */
	fx_close(&f);
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	(void)rd(&f, 4096, 4096);
	(void)rd(&f, 4096, 4096);
	(void)rd(&f, 4096, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, 8192, 4096);
	WRT_CHECK(count_pf(&f, 0) > 0);
	/* a break closes the window; it takes the trigger again; a read of the same range later is a break too (not forward) */
	(void)rd(&f, 40u << 20, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, (40u << 20) + 4096, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, (40u << 20) + 8192, 4096);
	WRT_CHECK(count_pf(&f, 0) > 0);
	(void)rd(&f, (40u << 20) + 8192 - 4096, 4096); /* backwards: breaks */
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	fx_close(&f);

	/* the gap: a forward gap up to seq_gap (one line by default) continues; one byte more breaks */
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	(void)rd(&f, 4096 + 65536, 4096);          /* gap == one line: continues */
	(void)rd(&f, 8192 + 2u * 65536, 4096);     /* continues: opens */
	WRT_CHECK(count_pf(&f, 0) > 0);
	fx_close(&f);
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	(void)rd(&f, 4096 + 65537, 4096);          /* gap one line + 1: breaks (run 0) */
	(void)rd(&f, 8192 + 65537, 4096);          /* run 1 */
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, 12288 + 65537, 4096);         /* run 2: opens */
	WRT_CHECK(count_pf(&f, 0) > 0);
	fx_close(&f);

	/* a jump forward inside the window still counts as the stream (a file with a hole): beyond the window it does not */
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	(void)rd(&f, 4096, 4096);
	(void)rd(&f, 8192, 4096); /* open, pos 12288, window to 12288 + 131072 */
	(void)rd(&f, 12288 + 100000, 4096); /* gap 100000 > 65536 but inside the window */
	WRT_CHECK(count_pf(&f, 0) > 0);
	(void)rd(&f, 12288 + 100000 + 4096 + 140000, 4096); /* past the window */
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	fx_close(&f);

	/* seq_trigger 1 opens at the first continuation, 3 at the third; window 0 never opens */
	c.trigger = 1;
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	(void)rd(&f, 4096, 4096);
	WRT_CHECK(count_pf(&f, 0) > 0);
	fx_close(&f);
	c.trigger = 3;
	WRT_CHECK(fx_open(&f, &c) == 0);
	for (unsigned i = 0; i < 3; i++) {
		(void)rd(&f, i * 4096u, 4096);
		WRT_CHECK_U64(count_pf(&f, 0), 0);
	}
	(void)rd(&f, 3u * 4096u, 4096);
	WRT_CHECK(count_pf(&f, 0) > 0);
	fx_close(&f);
	c.trigger = 2;
	c.window = 0;
	WRT_CHECK(fx_open(&f, &c) == 0);
	for (unsigned i = 0; i < 20; i++)
		(void)rd(&f, i * 4096u, 4096);
	WRT_CHECK_U64(count_pf(&f, 0), 0);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.windows, 0);
	WRT_CHECK_U64(st.misses, 20);
	fx_close(&f);
}

/* ---- plan -------------------------------------------------------------------------------------------------------- */

static void test_plan(void)
{
	fx f;
	fcfg c = small_cfg();
	wr_ra_pf pf[32];
	wr_ra_stats st;
	unsigned n;

	/* the in-flight limit counts the demand read: 5 lines of room, minus a 2-line demand = 3 prefetches */
	c.lines = 16;
	c.window = 10u * L4K;
	c.inflight = 5u * L4K;
	c.image = 100u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 2u * L4K, pf, 32);
	WRT_CHECK_U64(n, 3);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK(st.pend_bytes + 2u * L4K <= c.inflight);
	WRT_CHECK_U64(drain(&f, 2u * L4K, pf, 32), 0);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 2); /* the demand is over: the rest of the room */
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	wr_ra_get_stats(f.ra, &st);
	WRT_CHECK_U64(st.pend_bytes, 5u * L4K);
	WRT_CHECK_U64(st.pend_hiwater_bytes, 5u * L4K);
	/* a landed line frees room, and the window slides to the line after the last one: the planner asks for the next one */
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, 0)); /* the lowest line fails (silent) */
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 1); /* room for exactly one: the next line of the window (line 5), not the failed 0 */
	WRT_CHECK_U64(pf[0].offset, 5u * L4K);
	fx_close(&f);

	/* a demand larger than the limit allows nothing; so does an inflight_max below one line */
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	WRT_CHECK_U64(drain(&f, 5u * L4K, pf, 32), 0);
	WRT_CHECK_U64(drain(&f, 6u * L4K, pf, 32), 0);
	WRT_CHECK_U64(drain(&f, 0xffffffffu, pf, 32), 0); /* no overflow in the sum */
	fx_close(&f);
	c.inflight = L4K - 1u;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	fx_close(&f);

	/* a window larger than the cache is a ring: only `lines` lines are asked for, then nothing until the stream moves; and the moves free slots */
	c = small_cfg();
	c.lines = 4;
	c.window = 40u * L4K;
	c.inflight = 64u * L4K;
	c.image = 100u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f); /* pos 1536 */
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 4);
	for (unsigned i = 0; i < 4; i++)
		WRT_CHECK_U64(land(&f, &pf[i]), 1);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	/* the stream reads on: past line 0 the planner may take the slot of line 0 for line 4 (everything behind the position is free) */
	(void)rd(&f, 1536, L4K);
	(void)rd(&f, 1536 + L4K, L4K);        /* pos = 2 lines + 1536: first line of the window is 2 */
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 2); /* lines 4 and 5 take the slots of 0 and 1 */
	WRT_CHECK_U64(pf[0].offset, 4u * L4K);
	WRT_CHECK_U64(pf[0].line, 0);
	WRT_CHECK_U64(pf[1].offset, 5u * L4K);
	WRT_CHECK_U64(pf[1].line, 1);
	/* the old line 0 is gone: no hit on it any more, and the busy slots are not taken again */
	WRT_CHECK(rd(&f, 2u * L4K, L4K).kind == WR_RA_HIT);
	WRT_CHECK(rd(&f, 0, 10).kind == WR_RA_MISS);
	fx_close(&f);

	/* the range of a read that waits is protected: window and cache of four lines, a read over lines 1 (valid) and 2 (pending) waits, and the planner
	 * must not take line 1's slot for line 5 meanwhile, or the read is a miss once line 2 has landed */
	c = small_cfg();
	c.lines = 4;
	c.window = 8u * L4K;
	c.inflight = 64u * L4K;
	c.image = 100u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f); /* pos 1536 */
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 4);
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	WRT_CHECK_U64(land(&f, &pf[1]), 1);
	WRT_CHECK(rd(&f, L4K + 2048, L4K).kind == WR_RA_WAIT); /* lines 1 and 2; the stream is at line 2 now */
	{
		wr_ra_pf more[8];

		WRT_CHECK_U64(drain(&f, 0, more, 8), 1); /* line 4 takes the slot of line 0 (behind the read); line 5 would take line 1's slot: not allowed */
		WRT_CHECK_U64(more[0].offset, 4u * L4K);
		WRT_CHECK_U64(more[0].line, 0);
	}
	WRT_CHECK_U64(land(&f, &pf[2]), 1);
	{
		int same2 = 0;

		WRT_CHECK(rd(&f, L4K + 2048, L4K).kind == WR_RA_HIT);
		WRT_CHECK_U64(copy_hit(&f, L4K + 2048, L4K, &same2), L4K);
		WRT_CHECK(same2);
	}
	fx_close(&f);
	/* a read that ends on a line boundary and fills the whole cache waits for lines 0..3: the lines before the stream's position are all four,
	 * so nothing may be listed while it is parked (line 4 would take the slot of line 0, which has landed) */
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f); /* pos 1536 */
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 4);
	WRT_CHECK_U64(land(&f, &pf[0]), 1);
	WRT_CHECK(rd(&f, 1536, 4u * L4K - 1536u).kind == WR_RA_WAIT); /* lines 0..3, ends at 16384 = line 4's start */
	WRT_CHECK_U64(drain(&f, 0, pf + 4, 28), 0);
	for (unsigned i = 1; i < 4; i++)
		WRT_CHECK_U64(land(&f, &pf[i]), 1);
	WRT_CHECK_U64(drain(&f, 0, pf + 4, 28), 0);
	{
		int same3 = 0;

		WRT_CHECK(rd(&f, 1536, 4u * L4K - 1536u).kind == WR_RA_HIT); /* answered: the parked read is over, the ring is free again */
		WRT_CHECK_U64(copy_hit(&f, 1536, 4u * L4K - 1536u, &same3), 4u * L4K - 1536u);
		WRT_CHECK(same3);
	}
	WRT_CHECK_U64(drain(&f, 0, pf + 4, 28), 4); /* ... and the window slides at full depth */
	fx_close(&f);
	/* a read wider than the cache is a miss and nobody waits for it: the planner keeps the whole ring */
	c.window = 8u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 0, 512);
	(void)rd(&f, 512, 512);
	(void)rd(&f, 1024, 5u * L4K); /* five lines in four slots: a miss; ends at 1024 + 20480 = line 5 */
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 4);
	fx_close(&f);

	/* the request table: with max_reqs 4 at most three prefetches are in flight (one request stays free for the demand read), 1 lists none */
	c = small_cfg();
	c.lines = 8;
	c.window = 8u * L4K;
	c.image = 100u * L4K;
	c.max_reqs = 4;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 3);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_unissued(f.ra, pf[2].line));
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 1);
	fx_close(&f);
	c.max_reqs = 1;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	fx_close(&f);
	c.max_reqs = 0;

	/* a failed line is skipped within the stream and tried again after a break plus a new stream */
	c = small_cfg();
	c.lines = 8;
	c.window = 4u * L4K;
	c.image = 100u * L4K;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 5); /* lines 0..4 */
	for (unsigned i = 0; i < n; i++)
		if (i != 1u)
			WRT_CHECK_U64(land(&f, &pf[i]), 1);
	WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(f.ra, pf[1].line));
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);       /* not line 1 again in this stream */
	(void)rd(&f, 0, 100);                         /* backwards: the stream breaks, failures are forgotten */
	(void)rd(&f, 100, 100);
	(void)rd(&f, 200, 100);                       /* a new stream */
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 1);                          /* line 1, and only it: the others are cached */
	WRT_CHECK_U64(pf[0].offset, L4K);
	fx_close(&f);

	/* the end of the image: no lines past it, the short line is short, a window that starts at the end plans nothing */
	c = small_cfg();
	c.lines = 8;
	c.window = 20u * L4K;
	c.image = 3u * L4K + 10u;
	WRT_CHECK(fx_open(&f, &c) == 0);
	open_stream(&f);
	n = drain(&f, 0, pf, 32);
	WRT_CHECK_U64(n, 4);
	WRT_CHECK_U64(pf[3].offset, 3u * L4K);
	WRT_CHECK_U64(pf[3].len, 10);
	(void)rd(&f, 3u * L4K, 10); /* the stream ends at the end of the image */
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	fx_close(&f);
	/* a stream that reaches the end of the image before anything was requested: the last line was just read, nothing is left to ask for */
	WRT_CHECK(fx_open(&f, &c) == 0);
	(void)rd(&f, 3u * L4K - 30, 10);
	(void)rd(&f, 3u * L4K - 20, 10);
	(void)rd(&f, 3u * L4K - 10, 20); /* ends at the last byte of the image: the window opens with nothing ahead of it */
	WRT_CHECK_U64(f.ra->win_open, 1);
	WRT_CHECK_U64(drain(&f, 0, pf, 32), 0);
	fx_close(&f);
}

/* ---- big -------------------------------------------------------------------------------------------------------- */

/* Line numbers beyond 2^32 (an image of more than 16 TiB at the smallest line size): the slot of a line is lno mod lines exactly, so that the
 * lines of one window never share a slot even where the low 32 bits wrap, and the module never needs a 64-bit division. No image is allocated:
 * the test is the host and only looks at what the module lists. */
static void test_big(void)
{
	static const uint32_t counts[] = {1u, 2u, 3u, 5u, 7u, 8u, 1000u, 1023u, 1024u};
	wr_ra_pf pf[8];

	for (unsigned k = 0; k < sizeof(counts) / sizeof(counts[0]); k++) {
		wr_ra_cfg cfg;
		size_t need = 0;
		uint8_t *raw, *mem;
		wr_ra *ra = NULL;
		uint64_t base = (1ull << 32) - 3u; /* the window straddles the wrap of the low 32 bits */
		uint64_t lines_img = (1ull << 33);
		uint32_t seen = 0, slots[8];
		int dup = 0;

		memset(&cfg, 0, sizeof(cfg));
		cfg.size = (uint32_t)sizeof(cfg);
		cfg.line_bytes = L4K;
		cfg.lines = counts[k];
		cfg.window_bytes = 8u * L4K;
		cfg.inflight_max = 64u * L4K;
		cfg.image_bytes = lines_img * L4K;
		WRT_CHECK_STATUS(WR_OK, wr_ra_mem_required(&cfg, &need));
		raw = (uint8_t *)malloc(need + 16u);
		WRT_CHECK(raw != NULL);
		if (raw == NULL)
			return;
		mem = (uint8_t *)(((uintptr_t)raw + 15u) & ~(uintptr_t)15u);
		WRT_CHECK_STATUS(WR_OK, wr_ra_init(&cfg, (wr_mem_region){mem, need}, &ra));
		for (unsigned i = 0; i < 3; i++) {
			wr_ra_act a;

			WRT_CHECK_STATUS(WR_OK, wr_ra_read(ra, (base << 12) + (uint64_t)i * 512u, 512, &a));
		}
		while (seen < 8u && wr_ra_prefetch_next(ra, 0, &pf[seen]) != 0) {
			uint64_t lno = pf[seen].offset >> 12;

			slots[seen] = pf[seen].line;
			WRT_CHECK_U64(pf[seen].line, lno % counts[k]); /* exact, whatever the wrap */
			for (unsigned j = 0; j < seen; j++)
				if (slots[j] == slots[seen])
					dup = 1;
			seen++;
		}
		/* the window starts at line `base` and is eight lines, or the cache if smaller: every one of them listed, in its own slot (the
		 * in-flight room is 64 lines) */
		WRT_CHECK_U64(seen, counts[k] < 8u ? counts[k] : 8u);
		WRT_CHECK(!dup);
		free(raw);
	}
}

/* ---- model ------------------------------------------------------------------------------------------------------- */

typedef struct rng {
	uint64_t s;
} rng;

static uint64_t rnd(rng *r)
{
	r->s ^= r->s << 13;
	r->s ^= r->s >> 7;
	r->s ^= r->s << 17;
	return r->s;
}

static uint32_t rn(rng *r, uint32_t n)
{
	return n == 0u ? 0u : (uint32_t)(rnd(r) % n);
}

static uint64_t g_ra_tot[8]; /* hits, waits, landed, failed, dropped, hit bytes, refused submits, reopens: summed over the runs */

typedef struct flight {
	int used, stale;
	uint64_t off;
	uint32_t len;
	uint8_t *snap;  /* the bytes the request reads: the image at the moment it was submitted */
	void *buf;
} flight;

typedef struct mdl {
	fx f;
	fcfg c;
	rng r;
	uint8_t *truth;   /* the image: the one source of truth */
	uint64_t cap;     /* size of truth (the image may be reopened with a size up to this) */
	uint64_t size;    /* the current image size */
	flight fl[WR_RA_LINES_MAX];
	uint64_t prev_end;
	uint32_t lb;      /* the real line size */
	uint64_t n_hit_bytes, n_waits_resolved, n_fail, n_refused, n_writes, n_resets, n_dropped_ok;
} mdl;

static void m_mark_stale(mdl *m, uint64_t off, uint64_t len)
{
	for (uint32_t i = 0; i < m->c.lines; i++)
		if (m->fl[i].used && m->fl[i].off < off + len && off < m->fl[i].off + m->fl[i].len)
			m->fl[i].stale = 1;
}

/* After wr_ra_prefetch_next gave pf: every invariant of a listing. before[] is the slot table as it was. */
static void m_check_pf(mdl *m, const wr_ra_pf *pf, const wri_ra_slot *before, uint32_t demand)
{
	wr_ra *ra = m->f.ra;
	uint64_t lno = pf->offset >> ra->line_shift;

	WRT_CHECK((pf->offset & (ra->line_bytes - 1u)) == 0u);
	WRT_CHECK(pf->line < ra->lines);
	WRT_CHECK(pf->line == (uint32_t)(lno & 0xffffffffu) % ra->lines);
	WRT_CHECK(pf->len > 0u && pf->len <= ra->line_bytes && pf->offset + pf->len <= ra->image_bytes);
	WRT_CHECK(pf->len == ra->line_bytes || pf->offset + pf->len == ra->image_bytes);
	WRT_CHECK(pf->buf == ra->data + (size_t)pf->line * ra->line_bytes);
	if (pf->line < ra->lines) {
		WRT_CHECK(!m->fl[pf->line].used);                         /* a slot with a request in flight is never listed */
		WRT_CHECK(before[pf->line].state != WRI_RA_PENDING);
		WRT_CHECK(!(before[pf->line].state == WRI_RA_VALID && before[pf->line].lno == lno)); /* never a line that is cached */
		WRT_CHECK(!(before[pf->line].state == WRI_RA_EMPTY && before[pf->line].lno == lno &&
			    (before[pf->line].flags & WRI_RA_FAILED) != 0u)); /* nor one that failed in this stream */
	}
	/* inside the window */
	WRT_CHECK(ra->win_open != 0u);
	WRT_CHECK(pf->offset + ra->line_bytes > ra->prev_end && pf->offset < ra->win_end);
	/* the limits, counting the demand read */
	WRT_CHECK((uint64_t)ra->pend_bytes + demand <= ra->inflight_max);
	WRT_CHECK(ra->max_reqs == 0u || ra->pend_lines + 1u <= ra->max_reqs);
}

/* Drain prefetches after a step; the host may refuse a submit now and then. */
static void m_drain(mdl *m, uint32_t demand)
{
	wr_ra_pf pf;
	wri_ra_slot before[WR_RA_LINES_MAX];

	for (unsigned guard = 0; guard < 4u * WR_RA_LINES_MAX; guard++) {
		int got;

		memcpy(before, m->f.ra->slots, sizeof(before[0]) * m->c.lines);
		got = wr_ra_prefetch_next(m->f.ra, demand, &pf);
		if (!got)
			return;
		m_check_pf(m, &pf, before, demand);
		if (pf.line >= m->c.lines)
			return;
		if (rn(&m->r, 20) == 0) { /* the request table is full */
			WRT_CHECK_STATUS(WR_OK, wr_ra_line_unissued(m->f.ra, pf.line));
			m->n_refused++;
			return;
		}
		m->fl[pf.line].used = 1;
		m->fl[pf.line].stale = 0;
		m->fl[pf.line].off = pf.offset;
		m->fl[pf.line].len = pf.len;
		m->fl[pf.line].buf = pf.buf;
		memcpy(m->fl[pf.line].snap, m->truth + pf.offset, pf.len);
	}
	WRT_CHECK(0); /* a drain that never ends */
}

static void m_stats_check(mdl *m)
{
	wr_ra_stats st;
	uint32_t lines = 0, bytes = 0;

	wr_ra_get_stats(m->f.ra, &st);
	for (uint32_t i = 0; i < m->c.lines; i++)
		if (m->fl[i].used) {
			lines++;
			bytes += m->fl[i].len;
		}
	WRT_CHECK_U64(st.pend_lines, lines);
	WRT_CHECK_U64(st.pend_bytes, bytes);
	WRT_CHECK(st.pend_hiwater_bytes <= m->f.ra->inflight_max);
	WRT_CHECK(st.reads == st.hits + st.waits + st.misses);
}

/* One request of the model lands (ok) or fails. */
static void m_finish(mdl *m, uint32_t slot, int ok)
{
	flight *fl = &m->fl[slot];
	uint32_t kept = 7;

	if (ok) {
		memcpy(fl->buf, fl->snap, fl->len); /* the bytes the read saw when it was submitted */
		WRT_CHECK_STATUS(WR_OK, wr_ra_line_done(m->f.ra, slot, &kept));
		WRT_CHECK_U64(kept, fl->stale ? 0u : 1u);
		if (fl->stale)
			m->n_dropped_ok++;
	} else {
		WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(m->f.ra, slot));
		m->n_fail++;
	}
	fl->used = 0;
}

static void m_read(mdl *m, uint64_t off, uint32_t len)
{
	wr_ra_act a;
	uint32_t demand = 0;
	int waited = 0, failed = 0;

	for (unsigned guard = 0; guard < 64u; guard++) {
		WRT_CHECK_STATUS(WR_OK, wr_ra_read(m->f.ra, off, len, &a));
		if (a.kind == WR_RA_WAIT) {
			int ok = rn(&m->r, 8) != 0u;

			WRT_CHECK(a.line < m->c.lines && m->fl[a.line].used && !m->fl[a.line].stale); /* it waits for a live request */
			m_finish(m, a.line, ok);
			failed |= !ok;
			waited = 1;
			m->n_waits_resolved++;
			m_drain(m, 0); /* the host drains after every completion, and the lines of the parked read must survive that */
			continue;
		}
		/* a read that waited and saw every line it waited for land is a hit (nothing was written or reopened meanwhile): never a miss because
		 * the planner took a slot of its range */
		WRT_CHECK(!(waited && !failed && a.kind == WR_RA_MISS));
		if (a.kind == WR_RA_HIT) {
			uint32_t done = 0;

			while (done < len) {
				const uint8_t *p = NULL;
				size_t n = wr_ra_span(m->f.ra, off + done, len - done, &p);

				WRT_CHECK(n > 0 && p != NULL);
				if (n == 0 || p == NULL)
					return;
				WRT_CHECK(n <= len - done);
				WRT_CHECK(memcmp(p, m->truth + off + done, n) == 0); /* THE check: every byte a hit copies is the image's byte */
				done += (uint32_t)n;
			}
			m->n_hit_bytes += len;
		} else {
			WRT_CHECK(a.kind == WR_RA_MISS);
			demand = len;
		}
		break;
	}
	m_drain(m, demand);
}

static void m_write(mdl *m, uint64_t off, uint32_t len)
{
	for (uint32_t i = 0; i < len; i++)
		m->truth[off + i] = (uint8_t)rnd(&m->r);
	/* the write is submitted; the image layer orders requests behind it from now on: the model's snapshot of a later prefetch has the new bytes */
	m_mark_stale(m, off, len);
	(void)wr_ra_write(m->f.ra, off, len);
	m->n_writes++;
}

static void m_reset(mdl *m)
{
	uint64_t ns = m->size;

	/* somebody else changed the image while it was closed */
	for (unsigned k = 0, n = rn(&m->r, 4); k < n; k++) {
		uint64_t o = rnd(&m->r) % m->size;
		uint32_t l = 1u + rn(&m->r, 3u * m->lb);

		for (uint32_t i = 0; i < l && o + i < m->size; i++)
			m->truth[o + i] ^= 0x5Au;
	}
	if (rn(&m->r, 4) == 0)
		ns = m->cap / 2u + 1u + rnd(&m->r) % (m->cap / 2u);
	m->size = ns;
	for (uint32_t i = 0; i < m->c.lines; i++)
		if (m->fl[i].used)
			m->fl[i].stale = 1;
	WRT_CHECK_STATUS(WR_OK, wr_ra_reset(m->f.ra, ns));
	m->prev_end = 0;
	m->n_resets++;
}

static void m_step(mdl *m)
{
	uint32_t k = rn(&m->r, 100), L = m->lb, which;
	uint64_t off;
	uint32_t len;

	if (k < 50) { /* a read: mostly a continuation of the stream */
		static const uint32_t sizes[] = {512, 4096, 4096, 16384, 65536 - 512, 65536};

		len = sizes[rn(&m->r, 6)];
		if (rn(&m->r, 12) == 0)
			len = 1u + rn(&m->r, 3u * L);
		if (rn(&m->r, 40) == 0)
			len = 1u + rn(&m->r, (m->c.lines + 2u) * L); /* sometimes wider than the cache */
		if (len > m->size)
			len = (uint32_t)m->size;
		if (rn(&m->r, 10) < 7 && m->prev_end + len <= m->size)
			off = m->prev_end + (rn(&m->r, 6) == 0 ? rn(&m->r, L + 100u) : 0u);
		else
			off = rnd(&m->r) % m->size;
		if (off + len > m->size)
			off = m->size - len;
		m_read(m, off, len);
		m->prev_end = off + len;
	} else if (k < 70) { /* a request lands */
		which = rn(&m->r, m->c.lines);
		for (uint32_t i = 0; i < m->c.lines; i++)
			if (m->fl[(which + i) % m->c.lines].used) {
				m_finish(m, (which + i) % m->c.lines, 1);
				break;
			}
		m_drain(m, 0);
	} else if (k < 76) { /* one fails */
		which = rn(&m->r, m->c.lines);
		for (uint32_t i = 0; i < m->c.lines; i++)
			if (m->fl[(which + i) % m->c.lines].used) {
				m_finish(m, (which + i) % m->c.lines, 0);
				break;
			}
		m_drain(m, 0);
	} else if (k < 96) { /* a write */
		len = 1u + rn(&m->r, rn(&m->r, 4) == 0 ? 3u * L : 600u);
		if (len > m->size)
			len = (uint32_t)m->size;
		off = rn(&m->r, 3) == 0 ? m->prev_end - (m->prev_end > len ? len : m->prev_end) : rnd(&m->r) % m->size;
		if (off + len > m->size)
			off = m->size - len;
		m_write(m, off, len);
	} else {
		m_reset(m);
	}
	m_stats_check(m);
}

static void run_model(uint64_t seed, int variant)
{
	static const uint32_t lines_t[] = {1, 2, 3, 4, 7, 8, 16};
	static const uint32_t line_t[] = {4096, 8192, 65536};
	mdl *m = (mdl *)calloc(1, sizeof(*m));
	rng *r;
	wr_ra_stats st;
	uint32_t L;

	if (m == NULL)
		return;
	m->r.s = seed * 0x9e3779b97f4a7c15ull + 88172645463325252ull;
	r = &m->r;
	m->c.line = line_t[rn(r, 3)];
	L = m->c.line;
	m->c.lines = lines_t[rn(r, 7)];
	m->c.window = (uint32_t[]){0u, L / 2u, L, 2u * L, 5u * L, m->c.lines * L, 2u * m->c.lines * L}[rn(r, 7)];
	m->c.inflight = (uint32_t[]){L, 2u * L, 5u * L, 4u << 20, 3u * L + 77u}[rn(r, 5)];
	m->c.trigger = rn(r, 4); /* 0 = default 2 */
	m->c.gap = (uint32_t[]){0u, 1u, L / 4u, 2u * L}[rn(r, 4)];
	m->c.max_reqs = (uint32_t[]){0u, 0u, 1u, 2u, 3u, 5u, 17u}[rn(r, 7)];
	if (variant == 1) {      /* the iPXE defaults: 256 KiB lines, 8 of them */
		m->c.line = 0;
		L = WR_RA_LINE_DEFAULT;
		m->c.lines = 8;
		m->c.window = 2u << 20;
		m->c.inflight = 0;
		m->c.trigger = 0;
		m->c.gap = 0;
		m->c.max_reqs = 8;
	}
	m->lb = L;
	m->cap = (uint64_t)L * (3u + rn(r, 40)) + rn(r, L);
	m->size = m->cap;
	m->c.image = m->size;
	if (fx_open(&m->f, &m->c) != 0) {
		WRT_CHECK(0);
		free(m);
		return;
	}
	m->truth = (uint8_t *)malloc((size_t)m->cap);
	for (uint64_t i = 0; i < m->cap; i++)
		m->truth[i] = (uint8_t)rnd(r);
	memcpy(m->f.img, m->truth, (size_t)m->cap);
	for (uint32_t i = 0; i < m->c.lines; i++)
		m->fl[i].snap = (uint8_t *)malloc(m->f.ra->line_bytes);
	for (unsigned step = 0; step < 5000u; step++)
		m_step(m);
	/* settle: everything lands, the stream is read to its end; the books close */
	for (uint32_t i = 0; i < m->c.lines; i++)
		if (m->fl[i].used)
			m_finish(m, i, 1);
	m_stats_check(m);
	wr_ra_get_stats(m->f.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK_U64(st.pend_bytes, 0);
	WRT_CHECK(st.pf_issued == st.pf_landed + st.pf_failed + st.pf_dropped + st.pend_lines);
	if (getenv("WRT_RA_VERBOSE") != NULL)
		fprintf(stderr, "ra model seed %llu line %u x %u win %u inflight %u: hits %llu waits %llu misses %llu pf %llu/%llu/%llu/%llu resets %llu writes %llu refused %llu\n",
			(unsigned long long)seed, m->c.line, m->c.lines, m->c.window, m->c.inflight, (unsigned long long)st.hits,
			(unsigned long long)st.waits, (unsigned long long)st.misses, (unsigned long long)st.pf_issued,
			(unsigned long long)st.pf_landed, (unsigned long long)st.pf_failed, (unsigned long long)st.pf_dropped,
			(unsigned long long)m->n_resets, (unsigned long long)m->n_writes, (unsigned long long)m->n_refused);
	/* totals, kept for the coverage check of the whole run */
	g_ra_tot[0] += st.hits;
	g_ra_tot[1] += st.waits;
	g_ra_tot[2] += st.pf_landed;
	g_ra_tot[3] += st.pf_failed;
	g_ra_tot[4] += st.pf_dropped;
	g_ra_tot[5] += m->n_hit_bytes;
	g_ra_tot[6] += m->n_refused;
	g_ra_tot[7] += m->n_resets;
	for (uint32_t i = 0; i < m->c.lines; i++)
		free(m->fl[i].snap);
	free(m->truth);
	fx_close(&m->f);
	free(m);
}

static void test_model(void)
{
	for (uint64_t seed = 1; seed <= 70; seed++)
		run_model(seed, 0);
	for (uint64_t seed = 1000; seed < 1010; seed++)
		run_model(seed, 1);
	if (getenv("WRT_RA_VERBOSE") != NULL)
		fprintf(stderr, "ra model totals: hits %llu waits %llu landed %llu failed %llu dropped %llu hit bytes %llu refused %llu resets %llu\n",
			(unsigned long long)g_ra_tot[0], (unsigned long long)g_ra_tot[1], (unsigned long long)g_ra_tot[2],
			(unsigned long long)g_ra_tot[3], (unsigned long long)g_ra_tot[4], (unsigned long long)g_ra_tot[5],
			(unsigned long long)g_ra_tot[6], (unsigned long long)g_ra_tot[7]);
	/* the run as a whole walked every path: hits, waits, landings, failures, drops, refused submits and reopens */
	WRT_CHECK(g_ra_tot[0] > 1000);
	WRT_CHECK(g_ra_tot[1] > 100);
	WRT_CHECK(g_ra_tot[2] > 1000);
	WRT_CHECK(g_ra_tot[3] > 50);
	WRT_CHECK(g_ra_tot[4] > 20);
	WRT_CHECK(g_ra_tot[5] > 100000);
	WRT_CHECK(g_ra_tot[6] > 10);
	WRT_CHECK(g_ra_tot[7] > 100);
}

int main(void)
{
	test_cfg();
	test_life();
	test_classify();
	test_stream();
	test_plan();
	test_big();
	test_model();
	return wrt_finish();
}
