/* SPDX-License-Identifier: MIT */
/*
 * test_ra_sim.c - the readahead cache (core/src/ra/) driven the way the iPXE block device will drive it, against the WHOLE engine: a real wr_image with
 * wr_io_req prefetch and demand reads over the simulated monitor and OSDs (client_osd_rig.h), through the public API only. The test below is the
 * glue: it asks the module about every read, copies hits, submits demand reads straight into the caller's buffer, submits the listed prefetches,
 * reports every completion, and tells the module about writes and reopens.
 *
 *   stream      a sequential read of the whole image in INT 13h-sized pieces (127 sectors): every byte right, far fewer requests than without the cache,
 *               hits and waits happen, the in-flight limits hold (module and engine); a read of 4 MiB leaves no room for a prefetch; random reads
 *   writes      a write over cached lines invalidates them; a write submitted while prefetches are in flight (some of which read the old bytes) is
 *               never undone by a late landing; the read after it sees the new bytes
 *   failures    cancelled prefetches and prefetches that time out (an OSD that does not answer) are silent: every read still answers right, only the
 *               demand reads that need the dead OSD fail, and the cache recovers when the OSD is back
 *   reopen      the image is closed (abandoned, requests in flight are cancelled) and opened again after somebody else changed it: nothing stale survives
 *   table       a request table that is full refuses prefetches (the module's unissued path) and the stream still reads right; with max_reqs given to the
 *               module the host never sees a refusal
 */
#include "client_osd_rig.h"

#include "wr_ra.h"

#define IMG_ORDER 18u            /* 256 KiB objects */
#define IMG_SIZE (8u << 20)      /* 8 MiB: 32 objects, 32 lines of 256 KiB */
#define OBJ (1u << IMG_ORDER)
#define SLOTS 64u
#define INT13_READ (127u * 512u) /* the largest INT 13h read: 63.5 KiB */

typedef struct dev {
	cw *w;
	wr_image *img;
	wr_ra *ra;
	uint8_t *raw;
	wr_io_req pfq[SLOTS];
	int busy[SLOTS];
	wr_io_req dq;
	uint8_t *exp;            /* what the image should hold, byte for byte */
	uint32_t pf_timeout, demand_timeout;
	int tell_ra;             /* 1: every write is reported to the module (the glue's rule); 0: a write behind its back (another writer) */
	unsigned n_demand, n_pf, n_refused, n_hits, n_waits, n_pf_ok, n_pf_bad, n_demand_bad;
	unsigned n_wait_miss;    /* reads that waited for a line and, once it had landed, were a miss all the same (a line of their range was evicted meanwhile) */
} dev;

/* ---- the host ---------------------------------------------------------------------------------------------------- */

static void dev_collect(dev *d)
{
	for (unsigned i = 0; i < SLOTS; i++) {
		const cw_done *dn;

		if (!d->busy[i] || (dn = cw_done_of(&d->pfq[i])) == NULL)
			continue;
		if (dn->st == WR_OK) {
			WRT_CHECK_STATUS(WR_OK, wr_ra_line_done(d->ra, i, NULL));
			d->n_pf_ok++;
		} else {
			WRT_CHECK_STATUS(WR_OK, wr_ra_line_failed(d->ra, i));
			d->n_pf_bad++;
		}
		d->busy[i] = 0;
		cw_done_forget(&d->pfq[i]);
	}
}

static void dev_drain(dev *d, uint32_t demand)
{
	wr_ra_pf pf;

	if (d->ra == NULL)
		return;
	while (wr_ra_prefetch_next(d->ra, demand, &pf) != 0) {
		wr_io_req *q = &d->pfq[pf.line];
		wr_status st;

		WRT_CHECK(pf.line < SLOTS && !d->busy[pf.line]);
		*q = cw_req(WR_IO_READ, pf.offset, pf.len, pf.buf);
		q->timeout_ms = d->pf_timeout;
		st = cw_submit(d->img, q);
		if (st != WR_OK) {
			WRT_CHECK_STATUS(WR_E_BUSY, st);
			WRT_CHECK_STATUS(WR_OK, wr_ra_line_unissued(d->ra, pf.line));
			d->n_refused++;
			return;
		}
		d->busy[pf.line] = 1;
		d->n_pf++;
	}
}

/* One step of the host loop: let the engine run, collect prefetch completions, ask for more. Time moves only when nothing else did. */
static void dev_pump(dev *d, uint32_t demand)
{
	(void)cw_settle(d->w);
	dev_collect(d);
	dev_drain(d, demand);
}

static wr_status dev_read(dev *d, uint64_t off, uint32_t len, uint8_t *buf)
{
	uint64_t spent = 0;
	int waited = 0;

	for (unsigned guard = 0; guard < 4000u; guard++) {
		wr_ra_act a;
		wr_status st;
		const cw_done *dn;

		if (d->ra == NULL)
			a.kind = WR_RA_MISS, a.line = 0;
		else
			WRT_CHECK_STATUS(WR_OK, wr_ra_read(d->ra, off, len, &a));
		if (waited && a.kind == WR_RA_MISS)
			d->n_wait_miss++;
		waited = 0;
		if (a.kind == WR_RA_HIT) {
			uint32_t done = 0;

			while (done < len) {
				const uint8_t *p = NULL;
				size_t n = wr_ra_span(d->ra, off + done, len - done, &p);

				WRT_CHECK(n > 0 && p != NULL);
				if (n == 0 || p == NULL)
					return (wr_status)CW_NEVER;
				memcpy(buf + done, p, n);
				done += (uint32_t)n;
			}
			d->n_hits++;
			dev_drain(d, 0);
			return WR_OK;
		}
		if (a.kind == WR_RA_WAIT) {
			d->n_waits++;
			waited = 1;
			while (d->busy[a.line] && spent < 120000u) {
				dev_pump(d, 0);
				if (!d->busy[a.line])
					break;
				cw_tick(d->w, CW_TICK_MS);
				spent += CW_TICK_MS;
			}
			WRT_CHECK(!d->busy[a.line]);
			continue; /* ask again: the line is VALID now, or it failed and the read is a miss */
		}
		/* a miss: straight into the caller's buffer */
		d->dq = cw_req(WR_IO_READ, off, len, buf);
		d->dq.timeout_ms = d->demand_timeout;
		st = cw_submit(d->img, &d->dq);
		if (st == WR_E_BUSY) { /* the table is full of prefetches: wait for one to finish */
			dev_pump(d, 0);
			cw_tick(d->w, CW_TICK_MS);
			spent += CW_TICK_MS;
			continue;
		}
		if (st != WR_OK)
			return st;
		d->n_demand++;
		dev_drain(d, len);
		while ((dn = cw_done_of(&d->dq)) == NULL && spent < 120000u) {
			dev_pump(d, len);
			if (cw_done_of(&d->dq) != NULL)
				break;
			cw_tick(d->w, CW_TICK_MS);
			spent += CW_TICK_MS;
		}
		dn = cw_done_of(&d->dq);
		WRT_CHECK(dn != NULL);
		if (dn == NULL)
			return (wr_status)CW_NEVER;
		st = dn->st;
		cw_done_forget(&d->dq);
		if (st != WR_OK)
			d->n_demand_bad++;
		dev_pump(d, 0);
		return st;
	}
	return (wr_status)CW_NEVER;
}

/* A write: submitted, the module told right after it was accepted; wait for it unless asked not to. */
static wr_status dev_write(dev *d, wr_io_req *q, uint64_t off, uint32_t len, uint32_t seed, int wait)
{
	uint8_t *data = (uint8_t *)malloc(len);
	wr_status st;
	uint64_t spent = 0;

	cw_fill(data, seed, off, len);
	*q = cw_req(WR_IO_WRITE, off, len, data);
	st = cw_submit(d->img, q);
	if (st != WR_OK) {
		free(data);
		return st;
	}
	if (d->ra != NULL && d->tell_ra)
		(void)wr_ra_write(d->ra, off, len); /* no prefetch is drained between the submit and this call */
	memcpy(d->exp + off, data, len); /* the buffer stays valid until the write completes: keep it until then (see dev_write_wait) */
	if (wait) {
		while (cw_done_of(q) == NULL && spent < 60000u) {
			dev_pump(d, 0);
			if (cw_done_of(q) != NULL)
				break;
			cw_tick(d->w, CW_TICK_MS);
			spent += CW_TICK_MS;
		}
		st = cw_done_of(q) != NULL ? cw_done_of(q)->st : (wr_status)CW_NEVER;
		cw_done_forget(q);
		free(data);
	} else {
		q->user = data; /* freed by dev_write_wait */
	}
	return st;
}

static wr_status dev_write_wait(dev *d, wr_io_req *q)
{
	uint64_t spent = 0;
	wr_status st;

	while (cw_done_of(q) == NULL && spent < 60000u) {
		dev_pump(d, 0);
		if (cw_done_of(q) != NULL)
			break;
		cw_tick(d->w, CW_TICK_MS);
		spent += CW_TICK_MS;
	}
	st = cw_done_of(q) != NULL ? cw_done_of(q)->st : (wr_status)CW_NEVER;
	cw_done_forget(q);
	free(q->user);
	q->user = NULL;
	return st;
}

/* ---- the fixture ------------------------------------------------------------------------------------------------- */

static int dev_open(dev *d, cw *w, uint32_t eng_max_reqs, uint32_t ra_kib, uint32_t ra_max_reqs)
{
	wr_config cfg;
	wr_image_params p;
	wr_image_state fin;
	uint64_t off;

	memset(d, 0, sizeof(*d));
	cw_cfg_default(&cfg);
	cfg.max_reqs = (uint16_t)eng_max_reqs;
	if (cw_open(w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) != 0 || cw_image(w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) != 0)
		return -1;
	d->w = w;
	p = cw_params("img", 1);
	d->img = cw_open_image(w, &p, &fin);
	if (d->img == NULL || fin != WR_IMG_OPEN)
		return -2;
	d->exp = (uint8_t *)malloc(IMG_SIZE);
	d->tell_ra = 1;
	if (d->exp == NULL)
		return -3;
	/* the image holds a pattern, put into the object store directly: no engine session carries it, so a test can still decide which connections exist */
	for (off = 0; off < IMG_SIZE; off += OBJ) {
		char name[96];

		cw_fill(d->exp + off, 1, off, OBJ);
		snprintf(name, sizeof(name), "rbd_data.abc123.%016llx", (unsigned long long)(off / OBJ));
		if (sim_store_write(w->store, CW_POOL, name, 0, d->exp + off, OBJ) != WR_OK)
			return -4;
	}
	if (ra_kib != 0u) {
		wr_ra_cfg rc;
		size_t need = 0;

		if (wr_ra_cfg_from_kib(&rc, IMG_SIZE, ra_kib, 0) != WR_OK)
			return -5;
		rc.max_reqs = ra_max_reqs;
		if (wr_ra_mem_required(&rc, &need) != WR_OK)
			return -6;
		d->raw = (uint8_t *)malloc(need + 16u);
		if (d->raw == NULL ||
		    wr_ra_init(&rc, (wr_mem_region){(void *)(((uintptr_t)d->raw + 15u) & ~(uintptr_t)15u), need}, &d->ra) != WR_OK)
			return -7;
	}
	return 0;
}

static void dev_close(dev *d)
{
	free(d->exp);
	free(d->raw);
}

/* Read the whole image in pieces of `piece` bytes and compare every one with what the image should hold. Returns the number of reads that failed. */
static unsigned read_all(dev *d, uint32_t piece, uint8_t *buf)
{
	uint64_t off;
	unsigned bad = 0;

	for (off = 0; off < IMG_SIZE;) {
		uint32_t n = IMG_SIZE - off < piece ? (uint32_t)(IMG_SIZE - off) : piece;
		wr_status st;

		memset(buf, 0xEE, n);
		st = dev_read(d, off, n, buf);
		if (st != WR_OK) {
			if (getenv("WRT_RA_VERBOSE") != NULL)
				fprintf(stderr, "ra sim: read %llu+%u failed: %d (%s)\n", (unsigned long long)off, n, (int)st, wrt_status_name_(st));
			bad++;
		} else {
			WRT_CHECK(memcmp(buf, d->exp + off, n) == 0);
		}
		off += n;
	}
	return bad;
}

/* Sequential reads from `*off` until a line is in flight (a hit read lists prefetches and nothing settles them), at most 60 reads. Returns 1 if one is. */
static int read_until_pending(dev *d, uint64_t *off, uint8_t *buf)
{
	wr_ra_stats st;

	for (unsigned i = 0; i < 60u && *off + INT13_READ <= IMG_SIZE; i++) {
		WRT_CHECK_STATUS(WR_OK, dev_read(d, *off, INT13_READ, buf));
		WRT_CHECK(memcmp(buf, d->exp + *off, INT13_READ) == 0);
		*off += INT13_READ;
		wr_ra_get_stats(d->ra, &st);
		if (st.pend_lines > 0u)
			return 1;
	}
	return 0;
}

/* kill the connections to one OSD, as a peer reset would */
static void drop_osd_conns(cw *w, int osd)
{
	for (unsigned i = 0; i < CW_MAXC; i++)
		if (w->hc[i].used && w->hc[i].osd == osd)
			cw_end(w, &w->hc[i], 104);
}

/* ---- stream ------------------------------------------------------------------------------------------------------ */

static void test_stream(void)
{
	cw w, w0;
	dev d, d0;
	uint8_t *buf = (uint8_t *)malloc(4u << 20);
	wr_ra_stats st;
	wr_osd_stats os;
	uint64_t off;

	/* the baseline: no cache, one demand read per piece */
	WRT_CHECK(dev_open(&d0, &w0, 16, 0, 0) == 0);
	WRT_CHECK_U64(read_all(&d0, INT13_READ, buf), 0);
	WRT_CHECK_U64(d0.n_demand, (IMG_SIZE + INT13_READ - 1u) / INT13_READ);
	dev_close(&d0);
	cw_free(&w0);

	/* the default cache: 2 MiB = 8 lines of 256 KiB, the window the same */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	wr_ra_get_stats(d.ra, &st);
	wr_client_osd_stats(w.c, &os);
	WRT_CHECK(d.n_demand <= 6u);                                   /* the first reads, until the stream is recognised */
	WRT_CHECK(d.n_pf >= 28u && d.n_pf <= 40u);                     /* about one request per line of the image */
	WRT_CHECK(d.n_demand + d.n_pf < d0.n_demand / 2u);             /* far fewer round trips than one per piece */
	WRT_CHECK(d.n_hits > d0.n_demand / 2u);
	WRT_CHECK(st.hits == d.n_hits && st.misses == d.n_demand && st.windows >= 1u);
	WRT_CHECK(st.waits == d.n_waits);
	WRT_CHECK_U64(d.n_pf_bad, 0);
	WRT_CHECK(st.pend_hiwater_bytes <= 4u << 20);                  /* the in-flight limit of the profile */
	WRT_CHECK(os.reqs_hiwater <= 16u);                             /* ... and never a refusal from the engine's table */
	WRT_CHECK_U64(d.n_refused, 0);
	WRT_CHECK_U64(d.n_wait_miss, 0); /* a wait is always answered by the line it waited for: the planner never takes a slot of the range being waited on */
	if (getenv("WRT_RA_VERBOSE") != NULL)
		fprintf(stderr, "ra sim stream: baseline %u demand reads; with the cache %u demand + %u prefetch requests, %u hits, %u waits, hiwater %u KiB, engine reqs hiwater %u\n",
			d0.n_demand, d.n_demand, d.n_pf, d.n_hits, d.n_waits, st.pend_hiwater_bytes >> 10, os.reqs_hiwater);
	/* the same stream again, then quiet: nothing in flight, the books close */
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	for (unsigned i = 0; i < 10; i++)
		dev_pump(&d, 0);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK(st.pf_issued == st.pf_landed + st.pf_failed + st.pf_dropped);
	dev_close(&d);
	cw_free(&w);

	/* a wait: a read that jumps into a line that is still in flight answers with a wait, and the data is right once it lands */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	off = 0;
	WRT_CHECK(read_until_pending(&d, &off, buf));
	{
		unsigned slot = 0;
		unsigned waits_before = d.n_waits;

		while (slot < SLOTS && !d.busy[slot])
			slot++;
		WRT_CHECK(slot < SLOTS);
		if (slot < SLOTS) {
			uint64_t at = d.pfq[slot].offset + 1000u;

			memset(buf, 0xEE, INT13_READ);
			WRT_CHECK_STATUS(WR_OK, dev_read(&d, at, INT13_READ, buf));
			WRT_CHECK(memcmp(buf, d.exp + at, INT13_READ) == 0);
			WRT_CHECK(d.n_waits > waits_before);
		}
	}
	dev_close(&d);
	cw_free(&w);

	/* the iPXE profile's request table (8) and a module that knows it: seven lines at most and the demand read, never a refusal */
	WRT_CHECK(dev_open(&d, &w, 8, 2048, 8) == 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK_U64(d.n_refused, 0);
	WRT_CHECK(st.pend_hiwater_bytes <= 7u * 256u * 1024u);
	WRT_CHECK(d.n_pf > 0u);
	dev_close(&d);
	cw_free(&w);

	/* bigger commands: 1 MiB, 2 MiB (the whole cache) and 4 MiB (what an EFI caller may issue): always right; 1 MiB ones can hit */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	WRT_CHECK_U64(read_all(&d, 4u << 20, buf), 0);
	WRT_CHECK_U64(read_all(&d, 2u << 20, buf), 0);
	WRT_CHECK_U64(read_all(&d, 1u << 20, buf), 0);
	WRT_CHECK_U64(read_all(&d, 1u << 20, buf), 0);
	WRT_CHECK(d.n_pf > 0u && d.n_hits > 0u);
	dev_close(&d);
	cw_free(&w);

	/* random reads of random sizes: always right, with or without hits */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	{
		uint64_t s = 88172645463325252ull, last_end = 0;

		for (unsigned i = 0; i < 400; i++) {
			uint32_t len;
			uint64_t o;

			s ^= s << 13, s ^= s >> 7, s ^= s << 17;
			len = 1u + (uint32_t)(s % (600u * 1024u));
			s ^= s << 13, s ^= s >> 7, s ^= s << 17;
			o = s % (IMG_SIZE - len);
			if ((s >> 40) % 3u != 0u && last_end + len <= IMG_SIZE) /* two thirds continue the stream: streams start and stop */
				o = last_end;
			memset(buf, 0xEE, len);
			WRT_CHECK_STATUS(WR_OK, dev_read(&d, o, len, buf));
			WRT_CHECK(memcmp(buf, d.exp + o, len) == 0);
			last_end = o + len;
		}
	}
	dev_close(&d);
	cw_free(&w);
	free(buf);
}

/* ---- writes ------------------------------------------------------------------------------------------------------ */

static void test_writes(void)
{
	cw w;
	dev d;
	uint8_t *buf = (uint8_t *)malloc(4u << 20);
	wr_io_req wq;
	wr_ra_stats st;
	uint64_t off = 0;

	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	/* a stream opens, the window fills: let everything land */
	for (; off < 1u << 20; off += INT13_READ) {
		WRT_CHECK_STATUS(WR_OK, dev_read(&d, off, INT13_READ, buf));
		WRT_CHECK(memcmp(buf, d.exp + off, INT13_READ) == 0);
	}
	for (unsigned i = 0; i < 20; i++)
		dev_pump(&d, 0);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(st.valid_lines >= 4u);

	/* a write over a cached line, then the read of it: the new bytes (a stale cache would return the old ones) */
	{
		uint64_t at = 1u << 20; /* just ahead of the stream: cached */

		WRT_CHECK_STATUS(WR_OK, dev_write(&d, &wq, at + 100, 5000, 2, 1));
		wr_ra_get_stats(d.ra, &st);
		WRT_CHECK(st.lines_invalidated >= 1u);
		WRT_CHECK_STATUS(WR_OK, dev_read(&d, at, INT13_READ, buf));
		WRT_CHECK(memcmp(buf, d.exp + at, INT13_READ) == 0);
		WRT_CHECK(buf[100] == cw_pat(2, at + 100)); /* the written pattern, not the old one */
	}

	/* the race: prefetches are in flight (nothing settled since the read that listed them), a write overlaps one of them; the engine orders the
	 * write behind the earlier read, so that read lands OLD bytes: the module must drop the line instead of caching it */
	off = 3u << 20;
	WRT_CHECK(read_until_pending(&d, &off, buf));
	{
		unsigned slot = 0;
		uint64_t dropped_before;

		while (slot < SLOTS && !d.busy[slot])
			slot++;
		WRT_CHECK(slot < SLOTS);
		wr_ra_get_stats(d.ra, &st);
		dropped_before = st.pf_dropped;
		if (slot < SLOTS) {
			uint64_t at = d.pfq[slot].offset + 7u;

			/* accepted at once, nothing was pumped in between; wait for it only after another read has listed more lines */
			WRT_CHECK_STATUS(WR_OK, dev_write(&d, &wq, at, 300000, 3, 0));
			WRT_CHECK_STATUS(WR_OK, dev_write_wait(&d, &wq));
			for (unsigned i = 0; i < 20; i++)
				dev_pump(&d, 0);
			wr_ra_get_stats(d.ra, &st);
			WRT_CHECK(st.pf_dropped > dropped_before);
			WRT_CHECK_U64(st.pend_lines, 0);
			/* the range, in order, through hits and misses alike: the written bytes */
			for (uint64_t o = at & ~(uint64_t)511; o < at + 300000 && o + INT13_READ <= IMG_SIZE; o += INT13_READ) {
				WRT_CHECK_STATUS(WR_OK, dev_read(&d, o, INT13_READ, buf));
				WRT_CHECK(memcmp(buf, d.exp + o, INT13_READ) == 0);
			}
		}
	}
	/* and the whole image once more: nothing anywhere is stale */
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	WRT_CHECK_U64(read_all(&d, 1u << 20, buf), 0);
	dev_close(&d);
	cw_free(&w);
	free(buf);
}

/* ---- failures ---------------------------------------------------------------------------------------------------- */

static void test_failures(void)
{
	cw w;
	dev d;
	uint8_t *buf = (uint8_t *)malloc(4u << 20);
	wr_ra_stats st;
	uint64_t off = 0;

	/* cancelled prefetches: the host cancels them (a timeout of its own); each is a silent failure */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	WRT_CHECK(read_until_pending(&d, &off, buf));
	for (unsigned i = 0; i < SLOTS; i++)
		if (d.busy[i]) {
			wr_status cs = wr_image_cancel(d.img, &d.pfq[i]);

			WRT_CHECK(cs == WR_OK || cs == WR_E_BUSY);
		}
	for (unsigned i = 0; i < 40; i++) {
		(void)cw_settle(&w);
		dev_collect(&d);
	}
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(d.n_pf_bad > 0u && st.pf_failed == d.n_pf_bad);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0); /* the stream goes on: right answers whatever was cancelled */
	dev_close(&d);
	cw_free(&w);

	/* an OSD that does not answer: its requests time out. Prefetches fail silently, demand reads that need it report the error, and everything
	 * that does not need it is read right; with the OSD back the whole image reads right again (the failed lines are tried anew). */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	d.pf_timeout = 3000;
	d.demand_timeout = 3000;
	w.osd_down[1] = 1;
	drop_osd_conns(&w, 1);
	{
		unsigned bad = read_all(&d, INT13_READ, buf);

		WRT_CHECK(bad > 0u);                            /* objects whose primary is the dead OSD cannot be read */
		WRT_CHECK(bad < IMG_SIZE / INT13_READ);         /* the others are */
		WRT_CHECK(d.n_pf_bad > 0u);                     /* and the prefetches that needed it failed without a word */
		WRT_CHECK_U64(d.n_demand_bad, bad);
	}
	for (unsigned i = 0; i < 80; i++) {
		cw_tick(&w, 100);
		dev_collect(&d);
	}
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
	WRT_CHECK(st.pf_failed > 0u);
	w.osd_down[1] = 0;
	cw_tick(&w, 30000); /* the engine's cool-down for the OSD */
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	WRT_CHECK_U64(read_all(&d, 2u << 20, buf), 0);
	dev_close(&d);
	cw_free(&w);
	free(buf);
}

/* ---- reopen ------------------------------------------------------------------------------------------------------ */

/* The host's reopen: the image is abandoned (what is in flight comes back cancelled) and opened again; reset first, the cancelled lines are reported after. */
static void reopen(dev *d)
{
	wr_image_params p = cw_params("img", 1);
	wr_image_state fin;
	wr_ra_stats st;

	WRT_CHECK_STATUS(WR_OK, wr_image_close(d->img, WR_CLOSE_ABANDON));
	WRT_CHECK_STATUS(WR_OK, wr_ra_reset(d->ra, IMG_SIZE));
	wr_ra_get_stats(d->ra, &st);
	WRT_CHECK_U64(st.valid_lines, 0);
	d->img = cw_open_image(d->w, &p, &fin);
	WRT_CHECK(d->img != NULL && fin == WR_IMG_OPEN);
	for (unsigned i = 0; i < 40; i++) {
		(void)cw_settle(d->w);
		dev_collect(d);
	}
	wr_ra_get_stats(d->ra, &st);
	WRT_CHECK_U64(st.pend_lines, 0);
}

static void test_reopen(void)
{
	cw w;
	dev d;
	uint8_t *buf = (uint8_t *)malloc(4u << 20);
	wr_ra_stats st;
	wr_io_req wq;
	uint64_t off = 0, dropped;

	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	/* lines hold data; another writer changes the image behind the module's back; the reopen drops what the module holds */
	WRT_CHECK(read_until_pending(&d, &off, buf));
	for (unsigned i = 0; i < 10; i++)
		dev_pump(&d, 0);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(st.valid_lines >= 4u);
	d.tell_ra = 0;
	WRT_CHECK_STATUS(WR_OK, dev_write(&d, &wq, 0, 4u << 20, 6, 1)); /* not reported: the cached lines are now wrong, as the reopen assumes they may be */
	d.tell_ra = 1;
	{
		/* the setup is real: a hit on a stale line would return the old bytes */
		wr_ra_act a;
		const uint8_t *p = NULL;
		size_t n;

		WRT_CHECK_STATUS(WR_OK, wr_ra_read(d.ra, off, 100, &a));
		WRT_CHECK(a.kind == WR_RA_HIT);
		n = wr_ra_span(d.ra, off, 100, &p);
		WRT_CHECK(n > 0u && p != NULL && memcmp(p, d.exp + off, n) != 0);
	}
	reopen(&d);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0); /* the changed bytes, never the ones from before the reset */
	dev_close(&d);
	cw_free(&w);

	/* lines in flight at the reopen: they come back cancelled, are dropped (never VALID, never marked failed), and a new stream gets fresh lines */
	WRT_CHECK(dev_open(&d, &w, 16, 2048, 16) == 0);
	off = 0;
	WRT_CHECK(read_until_pending(&d, &off, buf));
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(st.pend_lines > 0u);
	dropped = st.pf_dropped;
	reopen(&d);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(st.pf_dropped > dropped);
	WRT_CHECK_U64(st.pf_failed, 0);
	WRT_CHECK_U64(st.valid_lines, 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	WRT_CHECK(d.n_hits > 0u);
	dev_close(&d);
	cw_free(&w);
	free(buf);
}

/* ---- table ------------------------------------------------------------------------------------------------------- */

static void test_table(void)
{
	cw w;
	dev d;
	uint8_t *buf = (uint8_t *)malloc(4u << 20);
	wr_ra_stats st;

	/* an engine table of 3 requests and a module that does not know: prefetches are refused now and then (the unissued path), demand reads wait their turn */
	WRT_CHECK(dev_open(&d, &w, 3, 2048, 0) == 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	WRT_CHECK(d.n_refused > 0u);
	for (unsigned i = 0; i < 10; i++)
		dev_pump(&d, 0);
	wr_ra_get_stats(d.ra, &st);
	WRT_CHECK(st.pf_issued == d.n_pf);
	WRT_CHECK_U64(st.pend_lines, 0);
	dev_close(&d);
	cw_free(&w);
	/* the same table, the module told: never a refusal, never fewer than one request for a demand read */
	WRT_CHECK(dev_open(&d, &w, 3, 2048, 3) == 0);
	WRT_CHECK_U64(read_all(&d, INT13_READ, buf), 0);
	WRT_CHECK_U64(d.n_refused, 0);
	WRT_CHECK(d.n_pf > 0u);
	dev_close(&d);
	cw_free(&w);
	free(buf);
}

int main(void)
{
	test_stream();
	test_writes();
	test_failures();
	test_reopen();
	test_table();
	return wrt_finish();
}
