/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_fence.c - the ordering rules of image I/O (design 25.4): earlier overlapping requests conflict unless both are reads, nothing is sent over the
 * range of an unanswered write, a zombie keeps its range, the flush barrier completes when the writes before it did and holds nothing back, the writer gate of
 * the header refresh. The simulator holds the replies (hold_replies) so every state in between can be looked at: what the OSD has seen is what was sent.
 */
#include "rbd_io_rig.h"

static rbio B;

#define ORDER 12u
#define OBJ (1u << ORDER)
#define IMG_SIZE (16u * OBJ)

static uint8_t model[IMG_SIZE];
static uint8_t bufs[8][3u * OBJ];

static sim_osd *osd0(void) { return B.g.w.osd[0]; }

static int open_one(const rio_params *p)
{
	if (rio_open(&B, p) != 0 || rio_image(&B, 0, "img0", IMG_SIZE, ORDER, 1) == NULL) {
		WRT_CHECK(0);
		return 0;
	}
	memset(model, 0, sizeof(model));
	return 1;
}

static uint32_t sent(void) { return sim_osd_n_requests(osd0()); }

/* The table state of a request the host holds (WRI_RQ_*), or -1 when it is not in flight. */
static int rq_state(const rio_rq *x)
{
	wri_rbd_rqpriv pv;

	memcpy(&pv, x->q.priv, sizeof(pv));
	if (pv.used != WRI_RBD_PRIV_MAGIC || pv.slot >= B.r.n_rq)
		return -1;
	return B.r.rq[pv.slot].state;
}

static unsigned count_state(wri_rq_state s)
{
	unsigned i, n = 0;

	for (i = 0; i < B.r.n_rq; i++)
		n += B.r.rq[i].state == (uint8_t)s ? 1u : 0u;
	return n;
}

static void hold(int on) { sim_osd_faults(osd0())->hold_replies = (uint8_t)on; }

/* Release the held replies of the OSD (n = 0: all) and run the layer. */
static void release(uint32_t n)
{
	(void)rio_run(&B);
	(void)sim_osd_release(osd0(), n);
	(void)rio_run(&B);
}

static void put(unsigned img, rio_rq *x, wr_io_kind kind, uint64_t off, uint64_t len, unsigned buf, uint32_t timeout_ms)
{
	if (kind == WR_IO_WRITE) {
		rio_pattern(bufs[buf], (size_t)len, buf + 100u);
		memcpy(model + off, bufs[buf], (size_t)len); /* applied in submission order, which is what the fence promises for overlapping ranges */
	} else if (kind == WR_IO_WRITE_ZEROES || kind == WR_IO_DISCARD) {
		memset(model + off, 0, (size_t)len);
	}
	WRT_CHECK(rio_go(&B, img, x, kind, off, len, kind == WR_IO_FLUSH ? NULL : bufs[buf], timeout_ms));
}

static void check_image(void)
{
	static uint8_t st[IMG_SIZE];

	WRT_CHECK(rio_store_read(&B, 0, 0, st, IMG_SIZE));
	WRT_CHECK_MEM(st, model, IMG_SIZE);
}

/* ---- the fence ---------------------------------------------------------------------------------------------------------------- */

static void test_write_then_read(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w, WR_IO_WRITE, 100, 500, 0, 0);
	memset(bufs[1], 0xAA, 500);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 300, 500, bufs[1], 0)); /* overlaps the write: [300, 600) of [100, 600) */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);                                       /* the read has not been sent: the write is unanswered */
	WRT_CHECK(rq_state(&w) == WRI_RQ_RUN && rq_state(&r) == WRI_RQ_WAIT);
	WRT_CHECK(!w.done && !r.done);
	release(1);                                                     /* the write is answered ... */
	WRT_CHECK(w.done && w.st == WR_OK);
	WRT_CHECK_U64(sent(), 2);                                       /* ... and only then is the read sent */
	WRT_CHECK(rq_state(&r) == WRI_RQ_RUN);
	release(0);
	WRT_CHECK(r.done && r.st == WR_OK);
	/* the read saw the write: bytes [300, 600) are the write's, [600, 800) are the hole behind it */
	WRT_CHECK_MEM(bufs[1], model + 300, 500);
	WRT_CHECK(w.order < r.order);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_write_then_write(void)
{
	rio_params p = rio_defaults();
	rio_rq w1, w2, w3;
	uint32_t n = 0;
	const sim_osd_rec *rec;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w1, WR_IO_WRITE, 0, 1000, 0, 0);
	put(0, &w2, WR_IO_WRITE, 999, 100, 1, 0);          /* one byte in common */
	put(0, &w3, WR_IO_WRITE, 1098, 50, 2, 0);          /* shares w2's last byte, and nothing with w1 */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	WRT_CHECK(rq_state(&w1) == WRI_RQ_RUN && rq_state(&w2) == WRI_RQ_WAIT && rq_state(&w3) == WRI_RQ_WAIT);
	release(1);
	WRT_CHECK_U64(sent(), 2);                           /* w3 conflicts with w2 only: still waiting */
	WRT_CHECK(rq_state(&w3) == WRI_RQ_WAIT);
	release(1);
	WRT_CHECK_U64(sent(), 3);
	release(0);
	WRT_CHECK(w1.done && w2.done && w3.done);
	WRT_CHECK(w1.order < w2.order && w2.order < w3.order);
	/* the OSD applied them in submission order, so the overlapping bytes are the later write's */
	rec = sim_osd_recs(osd0(), &n);
	WRT_CHECK(n == 3 && rec[0].op_off[0] == 0 && rec[1].op_off[0] == 999 && rec[2].op_off[0] == 1098);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_read_read_free(void)
{
	rio_params p = rio_defaults();
	rio_rq r1, r2, r3, w;

	if (!open_one(&p))
		return;
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r1, WR_IO_READ, 0, 1000, bufs[0], 0));
	WRT_CHECK(rio_go(&B, 0, &r2, WR_IO_READ, 500, 1000, bufs[1], 0)); /* overlaps: two reads never conflict */
	WRT_CHECK(rio_go(&B, 0, &r3, WR_IO_READ, 0, 2000, bufs[2], 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 3);
	WRT_CHECK(rq_state(&r1) == WRI_RQ_RUN && rq_state(&r2) == WRI_RQ_RUN && rq_state(&r3) == WRI_RQ_RUN);
	/* a write over them waits for all three */
	put(0, &w, WR_IO_WRITE, 900, 10, 3, 0);
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 3);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT);
	release(2);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT && !r3.done);
	WRT_CHECK_U64(sent(), 3);
	release(1);
	WRT_CHECK(r1.done && r2.done && r3.done);
	WRT_CHECK_U64(sent(), 4);
	release(0);
	WRT_CHECK(w.done && w.st == WR_OK);
	check_image();
	rio_close(&B);
}

static void test_read_then_write(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w, r2;

	if (!open_one(&p))
		return;
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[0], 0));
	put(0, &w, WR_IO_WRITE, 50, 100, 1, 0);
	/* a read after the write that overlaps the write but not the earlier read: it waits for the write */
	WRT_CHECK(rio_go(&B, 0, &r2, WR_IO_READ, 120, 100, bufs[2], 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT && rq_state(&r2) == WRI_RQ_WAIT);
	release(1);
	WRT_CHECK(r.done);
	WRT_CHECK_U64(sent(), 2);
	WRT_CHECK(rq_state(&r2) == WRI_RQ_WAIT);
	release(1);
	WRT_CHECK(w.done);
	WRT_CHECK_U64(sent(), 3);
	release(0);
	WRT_CHECK(r2.done && r2.st == WR_OK);
	WRT_CHECK_MEM(bufs[2], model + 120, 100); /* the read of [120, 220) saw the write's bytes of [120, 150) */
	WRT_CHECK(r.order < w.order && w.order < r2.order);
	check_image();
	rio_close(&B);
}

static void test_independent_ranges(void)
{
	rio_params p = rio_defaults();
	rio_rq a, b, c, d;

	if (!open_one(&p))
		return;
	hold(1);
	/* adjacent but not overlapping, other objects, other kinds: all go out at once */
	put(0, &a, WR_IO_WRITE, 0, 100, 0, 0);
	put(0, &b, WR_IO_WRITE, 100, 100, 1, 0);
	put(0, &c, WR_IO_WRITE_ZEROES, 5u * OBJ, 10, 2, 0);
	put(0, &d, WR_IO_DISCARD, 7u * OBJ, OBJ, 3, 0);
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 4);
	WRT_CHECK(rq_state(&a) == WRI_RQ_RUN && rq_state(&b) == WRI_RQ_RUN && rq_state(&c) == WRI_RQ_RUN && rq_state(&d) == WRI_RQ_RUN);
	release(0);
	WRT_CHECK(a.done && b.done && c.done && d.done);
	check_image();
	rio_close(&B);
}

static void test_discard_and_zeroes_conflict(void)
{
	rio_params p = rio_defaults();
	rio_rq w, d, z, r;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w, WR_IO_WRITE, OBJ, OBJ, 0, 0);
	put(0, &d, WR_IO_DISCARD, OBJ + 10, 20, 1, 0);        /* a discard is a write kind: waits for the write */
	put(0, &z, WR_IO_WRITE_ZEROES, OBJ + 25, 30, 2, 0);   /* waits for the discard (overlaps it from byte 25 on... [10,30) vs [25,55)) */
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, OBJ, OBJ, bufs[3], 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	release(1);
	WRT_CHECK_U64(sent(), 2);
	release(1);
	WRT_CHECK_U64(sent(), 3);
	release(1);
	WRT_CHECK_U64(sent(), 4);
	release(0);
	WRT_CHECK(w.done && d.done && z.done && r.done);
	WRT_CHECK(w.order < d.order && d.order < z.order && z.order < r.order);
	WRT_CHECK_MEM(bufs[3], model + OBJ, OBJ);
	check_image();
	rio_close(&B);
}

/* ---- zombies ------------------------------------------------------------------------------------------------------------------ */

static void test_zombie_holds_range(void)
{
	rio_params p = rio_defaults();
	rio_rq w, w2, other;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w, WR_IO_WRITE, 200, 600, 0, 1000); /* a request timeout of 1 s */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	rio_tick(&B, 1200);                         /* the host's timeout passes: the core cancels the write and completes it */
	WRT_CHECK(w.done && w.st == WR_E_TIMEOUT);
	WRT_CHECK_U64(count_state(WRI_RQ_ZOMBIE), 1); /* its completion was pulled: only the fence entry remains */
	WRT_CHECK(B.r.reqs_inflight == 1);
	/* the host retries the same range (and takes its buffer back for new bytes): it waits behind the zombie */
	put(0, &w2, WR_IO_WRITE, 200, 600, 1, 0);
	put(0, &other, WR_IO_WRITE, 5u * OBJ, 100, 2, 0); /* a different range does not wait */
	(void)rio_run(&B);
	WRT_CHECK(rq_state(&w2) == WRI_RQ_WAIT);
	WRT_CHECK_U64(sent(), 2);                    /* only `other` was sent */
	rio_tick(&B, 800);                           /* nothing answers: the fence still holds */
	WRT_CHECK(rq_state(&w2) == WRI_RQ_WAIT && count_state(WRI_RQ_ZOMBIE) == 1);
	/* the cluster answers the original write: the zombie is resolved, the retry is admitted */
	release(1);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);
	WRT_CHECK(rq_state(&w2) == WRI_RQ_RUN);
	release(0);
	WRT_CHECK(w2.done && w2.st == WR_OK && other.done);
	/* the old write was applied first and the retry over it: the bytes are the retry's */
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void tweak_no_dedup(rig *g)
{
	g->w.ocfg[0].fault.no_dedup = 1;
}

static void test_zombie_no_dedup(void)
{
	rio_params p = rio_defaults();
	rio_rq w, w2, r;
	uint8_t got[600];

	p.tweak = tweak_no_dedup;
	if (!open_one(&p))
		return;
	/* the OSD applies the write and the answer is lost: the client cannot know */
	sim_osd_faults(osd0())->drop_replies = 1;
	put(0, &w, WR_IO_WRITE, 200, 600, 0, 1000);
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	rio_tick(&B, 1200);
	WRT_CHECK(w.done && w.st == WR_E_TIMEOUT);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 1);
	/* the old bytes are in the store already; the retry has other bytes and must end up on top of them */
	put(0, &w2, WR_IO_WRITE, 200, 600, 1, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 200, 600, got, 0));
	(void)rio_run(&B);
	WRT_CHECK(rq_state(&w2) == WRI_RQ_WAIT && rq_state(&r) == WRI_RQ_WAIT);
	/* the zombie is resent after the engine's own timeout (5 s, the session is reset); with no duplicate detection it is applied AGAIN: its old
	 * bytes go over the store a second time. The retry may not have been sent before that, or the old bytes would end on top of the new. */
	rio_tick(&B, 6000);
	WRT_CHECK(rio_until(&B, &w2, 30000) && w2.st == WR_OK);
	WRT_CHECK(rio_until(&B, &r, 30000) && r.st == WR_OK);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);
	WRT_CHECK_MEM(got, bufs[1], 600);            /* the read after the retry saw the retry's bytes */
	check_image();                               /* and so does the store */
	{
		uint32_t i, n = 0, applied = 0;
		const sim_osd_rec *rec = sim_osd_recs(osd0(), &n);

		for (i = 0; i < n; i++)
			if (rec[i].executed && rec[i].mutating && rec[i].op_off[0] == 200)
				applied++;
		WRT_CHECK(applied >= 3u); /* the first (answer lost), the resend of it (no dedup), the retry */
	}
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_wait_timeout(void)
{
	rio_params p = rio_defaults();
	rio_rq w, w2, w3;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w, WR_IO_WRITE, 0, 100, 0, 0);
	/* w2 waits behind w and times out while waiting: nothing of it was sent, it completes, leaves no entry, and is not in the model */
	memset(bufs[1], 0x77, 100);
	rio_fill_req(&w2, WR_IO_WRITE, 50, 100, bufs[1], 500);
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &w2));
	put(0, &w3, WR_IO_WRITE, 120, 100, 2, 0);      /* overlaps w2 and not w: waits for w2 only */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);                       /* w only: w2 waits for w, and w3 waits for w2 (earlier, overlapping) */
	rio_tick(&B, 600);
	WRT_CHECK(w2.done && w2.st == WR_E_TIMEOUT);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);
	WRT_CHECK_U64(sent(), 2);                       /* w3 is free of w and went out as soon as w2 was gone */
	release(0);
	WRT_CHECK(w.done && w3.done && w3.st == WR_OK && w.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- flush -------------------------------------------------------------------------------------------------------------------- */

static void test_flush_ordering(void)
{
	rio_params p = rio_defaults();
	rio_rq w1, f1, w2, f2, r;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w1, WR_IO_WRITE, 0, 100, 0, 0);
	put(0, &f1, WR_IO_FLUSH, 0, 0, 0, 0);
	put(0, &w2, WR_IO_WRITE, 5u * OBJ, 100, 1, 0);
	put(0, &f2, WR_IO_FLUSH, 0, 0, 0, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 9u * OBJ, 100, bufs[2], 0));
	(void)rio_run(&B);
	/* a flush is a barrier on completion, not on submission: the later write and the read went out at once */
	WRT_CHECK_U64(sent(), 3);
	WRT_CHECK(!f1.done && !f2.done);
	WRT_CHECK(rq_state(&f1) == WRI_RQ_RUN && rq_state(&f2) == WRI_RQ_RUN);
	release(1);                                    /* w1 answered: f1 completes, f2 still waits for w2 */
	WRT_CHECK(w1.done && f1.done && f1.st == WR_OK && !w2.done && !f2.done);
	release(0);
	WRT_CHECK(w2.done && f2.done && f2.st == WR_OK && r.done);
	WRT_CHECK(w1.order < f1.order && f1.order < f2.order && w2.order < f2.order);
	/* a flush has no range: it conflicts with nothing and nothing waits for it */
	WRT_CHECK(rio_idle(&B));
	/* flush after reads only: completes at once */
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[2], 0));
	WRT_CHECK(rio_go(&B, 0, &f1, WR_IO_FLUSH, 0, 0, NULL, 0));
	WRT_CHECK(B.r.done_len == 1u);
	release(0);
	WRT_CHECK(f1.done && r.done);
	rio_close(&B);
}

static void test_flush_excludes_zombies(void)
{
	rio_params p = rio_defaults();
	rio_rq w, f, w2, f2;

	if (!open_one(&p))
		return;
	hold(1);
	put(0, &w, WR_IO_WRITE, 0, 100, 0, 500);
	(void)rio_run(&B);
	rio_tick(&B, 600);
	WRT_CHECK(w.done && w.st == WR_E_TIMEOUT && count_state(WRI_RQ_ZOMBIE) == 1);
	/* the host knows it failed: a flush behind it does not wait for the cluster's answer */
	WRT_CHECK(rio_go(&B, 0, &f, WR_IO_FLUSH, 0, 0, NULL, 0));
	WRT_CHECK(rio_run(&B) == 1 || f.done);
	WRT_CHECK(f.done && f.st == WR_OK);
	/* a flush that waits for a live write completes when that write is cancelled: the write is then a failure the host knows about */
	put(0, &w2, WR_IO_WRITE, 5u * OBJ, 100, 1, 0);
	WRT_CHECK(rio_go(&B, 0, &f2, WR_IO_FLUSH, 0, 0, NULL, 0));
	(void)rio_run(&B);
	WRT_CHECK(!f2.done);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w2.q));
	(void)rio_run(&B);
	WRT_CHECK(w2.done && w2.st == WR_E_CANCELLED && f2.done && f2.st == WR_OK);
	release(0);
	(void)rio_run(&B);
	check_image();
	rio_close(&B);
}

/* ---- the writer gate ------------------------------------------------------------------------------------------------------------ */

static void test_refresh_gate(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r, f, w2;
	wri_rbd_img *im;

	p.hdr_refresh_ms = 1000;
	if (!open_one(&p))
		return;
	im = &B.r.img[0];
	im->refreshed_ms = rio_now(&B);
	im->next_refresh_ms = rio_now(&B) + 1000;
	put(0, &w, WR_IO_WRITE, 0, 100, 0, 0);          /* fresh: admitted */
	(void)rio_run(&B);
	WRT_CHECK(w.done && w.st == WR_OK);
	rio_tick(&B, 1500);                              /* the header has not been refreshed for longer than hdr_refresh_ms: writes wait */
	put(0, &w, WR_IO_WRITE, OBJ, 100, 1, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[2], 0));   /* reads are not held */
	WRT_CHECK(rio_go(&B, 0, &f, WR_IO_FLUSH, 0, 0, NULL, 0));       /* nor flushes (this one waits for the held write, by the barrier) */
	(void)rio_run(&B);
	WRT_CHECK(r.done && r.st == WR_OK && !w.done && !f.done);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT);
	WRT_CHECK_U64(sent(), 2);                        /* the first write, the read */
	/* the refresh is under way (the image says so): still held */
	im->ros = (uint8_t)WRI_ROS_REFRESH;
	rio_tick(&B, 300);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT);
	/* the refresh is adopted: the next pass admits it */
	im->ros = (uint8_t)WRI_ROS_READY;
	im->refreshed_ms = rio_now(&B);
	im->next_refresh_ms = rio_now(&B) + 1000;
	(void)rio_run(&B);
	WRT_CHECK(w.done && w.st == WR_OK && f.done);
	/* a write held by the gate times out like any request */
	rio_tick(&B, 1500);
	put(0, &w2, WR_IO_WRITE, 2u * OBJ, 10, 3, 400);
	rio_tick(&B, 500);
	WRT_CHECK(w2.done && w2.st == WR_E_TIMEOUT);
	memset(model + 2u * OBJ, 0, 10);
	/* an image that is not refreshed at all (a reader, or hdr_refresh_ms 0) is never gated */
	im->next_refresh_ms = WR_DEADLINE_NONE;
	put(0, &w2, WR_IO_WRITE, 2u * OBJ, 10, 3, 0);
	(void)rio_run(&B);
	WRT_CHECK(w2.done && w2.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* A pending refresh holds writes whatever hdr_refresh_ms is: with 0 only the on-demand refresh (wri_rbd_open_refresh_now) exists, and its pending state is
 * the whole gate. Reads and flushes are not held; a write that is already cut is not taken back. */
static void test_refresh_gate_on_demand(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r, w2;
	wri_rbd_img *im;

	p.hdr_refresh_ms = 0;
	if (!open_one(&p))
		return;
	im = &B.r.img[0];
	put(0, &w, WR_IO_WRITE, 0, 100, 0, 0);          /* no refresh at all: never gated, however old the header */
	rio_tick(&B, 5000);
	WRT_CHECK(w.done && w.st == WR_OK);
	im->ros = (uint8_t)WRI_ROS_REFRESH;              /* what wri_rbd_open_refresh_now leaves behind */
	im->next_refresh_ms = rio_now(&B);
	put(0, &w, WR_IO_WRITE, OBJ, 100, 1, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[2], 0));
	(void)rio_run(&B);
	WRT_CHECK(r.done && r.st == WR_OK && !w.done);
	WRT_CHECK(rq_state(&w) == WRI_RQ_WAIT);
	rio_tick(&B, 2000);
	WRT_CHECK(!w.done && rq_state(&w) == WRI_RQ_WAIT);
	im->ros = (uint8_t)WRI_ROS_READY;                /* adopted */
	im->next_refresh_ms = WR_DEADLINE_NONE;
	(void)rio_run(&B);
	WRT_CHECK(w.done && w.st == WR_OK);
	/* a reader is never gated, whatever its state says */
	im->writable = 0;
	im->ros = (uint8_t)WRI_ROS_REFRESH;
	WRT_CHECK(!wri_rio_gate_closed(&B.r, im));
	im->writable = 1;
	WRT_CHECK(wri_rio_gate_closed(&B.r, im));
	im->state = (uint8_t)WR_IMG_CLOSING;             /* nor is an image that is closing */
	WRT_CHECK(!wri_rio_gate_closed(&B.r, im));
	im->state = (uint8_t)WR_IMG_OPEN;
	im->ros = (uint8_t)WRI_ROS_READY;
	put(0, &w2, WR_IO_WRITE, 2u * OBJ, 10, 3, 0);
	(void)rio_run(&B);
	WRT_CHECK(w2.done && w2.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

int main(void)
{
	test_write_then_read();
	test_write_then_write();
	test_read_read_free();
	test_read_then_write();
	test_independent_ranges();
	test_discard_and_zeroes_conflict();
	test_zombie_holds_range();
	test_zombie_no_dedup();
	test_wait_timeout();
	test_flush_ordering();
	test_flush_excludes_zombies();
	test_refresh_gate();
	test_refresh_gate_on_demand();
	return wrt_finish();
}
