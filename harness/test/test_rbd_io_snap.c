/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_snap.c - the -EOLDSNAPC path of image writes (design 22.5, 25.3; WR_OSDF_ORDERSNAP): a write whose snapshot context is older than the object's
 * is answered -EOLDSNAPC; the I/O half asks the open machine for a header refresh (wri_rbd_open_refresh_now), holds the request until the refresh is adopted
 * and cuts the extent again with the new context. The rig has no open machine: the test plays it (it sets the image's context and ros, as the adoption does).
 * Also: the retries of one request are bounded, the held request times out and cancels like any other, a discard takes the same road, and extents cut
 * inside one object (small op_bytes_max) are resent from the right place.
 */
#include "rbd_io_rig.h"

static rbio B;

#define ORDER 12u
#define OBJ (1u << ORDER)
#define IMG_SIZE (16u * OBJ)

static uint8_t model[IMG_SIZE];
static uint8_t bufs[4][8u * OBJ];

static void tweak_ordersnap(rig *g)
{
	g->w.e.x.cfg.osd_flags = (uint8_t)(g->w.e.x.cfg.osd_flags | WR_OSDF_ORDERSNAP);
}

static int open_one(uint32_t op_bytes_max)
{
	rio_params p = rio_defaults();

	p.tweak = tweak_ordersnap;
	if (op_bytes_max != 0)
		p.op_bytes_max = op_bytes_max;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "img0", IMG_SIZE, ORDER, 1) == NULL) {
		WRT_CHECK(0);
		return 0;
	}
	memset(model, 0, sizeof(model));
	return 1;
}

static void set_snapc(uint64_t seq, unsigned n, uint64_t a, uint64_t b)
{
	wri_snapc *sc = &B.r.img[0].snapc;

	sc->seq = seq;
	sc->n = n;
	if (n > 0)
		sc->snaps[0] = a;
	if (n > 1)
		sc->snaps[1] = b;
}

static void fresh(void) { set_snapc(8, 2, 8, 5); }
static void stale(void) { set_snapc(5, 1, 5, 0); }

static const wri_rbd_rq *rq_of(const rio_rq *x)
{
	wri_rbd_rqpriv pv;

	memcpy(&pv, x->q.priv, sizeof(pv));
	if (pv.used != WRI_RBD_PRIV_MAGIC || pv.slot >= B.r.n_rq)
		return NULL;
	return &B.r.rq[pv.slot];
}

/* The writes that reached the object store with the fresh context (seq 8): the objects of [0, n) were written under it, so their snapshot sequence is 8. */
static void seed_objects(uint64_t len)
{
	rio_rq x;

	fresh();
	rio_pattern(bufs[0], (size_t)len, 1);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, len, bufs[0], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	memcpy(model, bufs[0], (size_t)len);
	stale(); /* the image has not learned of snapshot 8 yet */
}

static void check_image(void)
{
	static uint8_t st[IMG_SIZE];

	WRT_CHECK(rio_store_read(&B, 0, 0, st, IMG_SIZE));
	WRT_CHECK_MEM(st, model, IMG_SIZE);
}

static uint64_t last_write_seq(void)
{
	uint32_t i, n = 0;
	const sim_osd_rec *all = sim_osd_recs(B.g.w.osd[0], &n);

	for (i = n; i != 0; i--)
		if (all[i - 1].mutating)
			return all[i - 1].snap_seq;
	return 0;
}

/* ---- the road: answer, refresh asked, held, adopted, sent again ---------------------------------------------------------------- */

static void test_resend_after_refresh(void)
{
	rio_rq x;
	wri_rbd_img *im;
	const wri_rbd_rq *q;

	if (!open_one(0))
		return;
	im = &B.r.img[0];
	seed_objects(2u * OBJ);
	/* objects 0 and 1 know snapshot 8, objects 2 and 3 are new: the write of four objects fails on the first two only */
	rio_pattern(bufs[1], 4u * OBJ, 2);
	memcpy(model, bufs[1], 4u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, 4u * OBJ, bufs[1], 0));
	(void)rio_run(&B);
	q = rq_of(&x);
	WRT_CHECK(!x.done && q != NULL && q->state == WRI_RQ_RUN && q->held == 1 && q->resnap == 1);
	WRT_CHECK(im->ros == (uint8_t)WRI_ROS_REFRESH); /* the open machine was asked */
	WRT_CHECK(q->cur == 0 || q->cur == OBJ);        /* back at the first extent that was refused */
	WRT_CHECK(B.r.n_completed == 1);                 /* the seeding write only */
	rio_tick(&B, 3000);                              /* nothing is sent while the refresh is pending */
	WRT_CHECK(!x.done && q->held == 1 && q->resnap == 1);
	/* the refresh is adopted */
	fresh();
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	WRT_CHECK(last_write_seq() == 8);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* the extents are cut inside one object (op_bytes_max 1 KiB, object 4 KiB), the request starts mid-object: the rewind goes to the start of the refused run */
static void test_resend_mid_object(void)
{
	rio_rq x;
	wri_rbd_img *im;
	const wri_rbd_rq *q;
	uint64_t off = OBJ / 2u + 100u, len = 3u * OBJ + 77u;

	if (!open_one(1024u))
		return;
	im = &B.r.img[0];
	seed_objects(5u * OBJ);
	rio_pattern(bufs[1], (size_t)len, 3);
	memcpy(model + off, bufs[1], (size_t)len);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, off, len, bufs[1], 0));
	(void)rio_run(&B);
	q = rq_of(&x);
	WRT_CHECK(!x.done && q != NULL && q->held == 1 && q->cur >= off && q->cur < off + len);
	fresh();
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* a discard takes the same road: DELETE of a whole object, TRUNCATE of a tail, ZERO of a middle */
static void test_discard_and_zeroes(void)
{
	rio_rq x;
	wri_rbd_img *im;
	const wri_rbd_rq *q;

	if (!open_one(0))
		return;
	im = &B.r.img[0];
	seed_objects(6u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_DISCARD, OBJ, 5u * OBJ - 10u, NULL, 0)); /* ZERO .. DELETE .. TRUNCATE shapes */
	(void)rio_run(&B);
	q = rq_of(&x);
	WRT_CHECK(!x.done && q != NULL && q->held == 1);
	fresh();
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	memset(model + OBJ, 0, 5u * OBJ - 10u);
	check_image();
	stale();
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE_ZEROES, 7, 2u * OBJ, NULL, 0));
	(void)rio_run(&B);
	q = rq_of(&x);
	WRT_CHECK(!x.done && q != NULL && q->held == 1);
	fresh();
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	memset(model + 7, 0, 2u * OBJ);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- bounds ------------------------------------------------------------------------------------------------------------------ */

/* a refresh that never brings a newer context: the request survives WRI_RBD_RESNAP_MAX rounds and then fails with the OSD's status */
static void test_bounded(void)
{
	rio_rq x;
	wri_rbd_img *im;
	unsigned rounds = 0;

	if (!open_one(0))
		return;
	im = &B.r.img[0];
	seed_objects(OBJ);
	rio_pattern(bufs[1], OBJ, 4);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, OBJ, bufs[1], 0));
	while (!x.done && rounds < 100) {
		(void)rio_run(&B);
		if (!x.done) {
			WRT_CHECK(im->ros == (uint8_t)WRI_ROS_REFRESH);
			im->ros = (uint8_t)WRI_ROS_READY; /* adopted, and it said the same as before */
		}
		rounds++;
	}
	WRT_CHECK(x.done && x.st == WR_E_OSD_ERRNO);
	WRT_CHECK(rounds == WRI_RBD_RESNAP_MAX + 1u);
	check_image(); /* the object was never written */
	WRT_CHECK(rio_idle(&B));
	/* a request of its own starts with a fresh count */
	fresh();
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, OBJ, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	memcpy(model, bufs[1], OBJ);
	check_image();
	rio_close(&B);
}

/* a request that is held ends like any other: timeout, host cancel, close of the image */
static void test_held_ends(void)
{
	rio_rq x, y;
	wri_rbd_img *im;

	if (!open_one(0))
		return;
	im = &B.r.img[0];
	seed_objects(2u * OBJ);
	rio_pattern(bufs[1], 2u * OBJ, 5);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, 2u * OBJ, bufs[1], 1000));
	(void)rio_run(&B);
	WRT_CHECK(!x.done && im->ros == (uint8_t)WRI_ROS_REFRESH);
	rio_tick(&B, 1500);
	WRT_CHECK(x.done && x.st == WR_E_TIMEOUT);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B));
	/* host cancel */
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_go(&B, 0, &y, WR_IO_WRITE, 0, 2u * OBJ, bufs[1], 0));
	(void)rio_run(&B);
	WRT_CHECK(!y.done && im->ros == (uint8_t)WRI_ROS_REFRESH);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &y.q));
	(void)rio_run(&B);
	WRT_CHECK(y.done && y.st == WR_E_CANCELLED);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B));
	/* the image is closed (abandon) while one is held */
	im->ros = (uint8_t)WRI_ROS_READY;
	WRT_CHECK(rio_go(&B, 0, &y, WR_IO_WRITE, 0, 2u * OBJ, bufs[1], 0));
	(void)rio_run(&B);
	WRT_CHECK(!y.done);
	wri_rbd_io_fail_image(&B.r, 0, WR_E_CANCELLED, WR_CLOSE_ABANDON);
	(void)rio_run(&B);
	WRT_CHECK(y.done && y.st == WR_E_CANCELLED);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* reads are never answered -EOLDSNAPC, and a write that is not refused is untouched by all of this */
static void test_plain_paths_unchanged(void)
{
	rio_rq x;

	if (!open_one(0))
		return;
	fresh();
	rio_pattern(bufs[1], 3u * OBJ, 6);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 5, 3u * OBJ - 5u, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	memcpy(model + 5, bufs[1], 3u * OBJ - 5u);
	WRT_CHECK(B.r.rq[0].resnap == 0 && B.r.img[0].ros == (uint8_t)WRI_ROS_READY);
	stale();
	memset(bufs[2], 0xAA, 3u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, 0, 3u * OBJ, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	WRT_CHECK_MEM(bufs[2], model, 3u * OBJ);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

int main(void)
{
	test_resend_after_refresh();
	test_resend_mid_object();
	test_discard_and_zeroes();
	test_bounded();
	test_held_ends();
	test_plain_paths_unchanged();
	return wrt_finish();
}
