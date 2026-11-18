/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_basic.c - image I/O end to end over real sessions and sim_osd: memory planning, every submit-time check, every request kind at every
 * alignment (inside an object, across two and three objects, whole objects, the last byte of the image, zero length), holes, short objects and missing
 * objects reading as zeros, what the OSD saw for each kind (operation codes, snapshot context, pool), flush, two images, the data-pool image.
 */
#include "rbd_io_rig.h"

static rbio B;

#define ORDER 12u
#define OBJ (1u << ORDER)
#define IMG_SIZE (16u * OBJ)

static uint8_t model[IMG_SIZE];

static int open_one(const rio_params *p, int writable)
{
	if (rio_open(&B, p) != 0) {
		WRT_CHECK(0);
		return 0;
	}
	if (rio_image(&B, 0, "img0", IMG_SIZE, ORDER, writable) == NULL) {
		WRT_CHECK(0);
		return 0;
	}
	memset(model, 0, sizeof(model));
	return 1;
}

/* A request run to its end; returns its status (WR_E_TIMEOUT stands for "never completed"). */
static wr_status run_req(unsigned img, wr_io_kind kind, uint64_t off, uint64_t len, void *buf)
{
	rio_rq x;

	rio_fill_req(&x, kind, off, len, buf, 0);
	if (rio_submit(&B, img, &x) != WR_OK) {
		WRT_CHECK(0);
		return WR_E_INVAL;
	}
	if (!rio_until(&B, &x, 20000)) {
		WRT_CHECK(0);
		return WR_E_TIMEOUT;
	}
	return x.st;
}

static void do_write(uint64_t off, uint64_t len, uint32_t seed)
{
	uint8_t *buf = (uint8_t *)malloc(len != 0 ? (size_t)len : 1u);

	rio_pattern(buf, (size_t)len, seed);
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE, off, len, buf));
	memcpy(model + off, buf, (size_t)len);
	free(buf);
}

static void do_read_check(uint64_t off, uint64_t len)
{
	uint8_t *buf = (uint8_t *)malloc(len != 0 ? (size_t)len : 1u);

	memset(buf, 0xAA, (size_t)len); /* a byte the read must overwrite, by data or by the zero-fill */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_READ, off, len, buf));
	WRT_CHECK_MEM(buf, model + off, (size_t)len);
	free(buf);
}

/* Image == model, through the layer and through the store. */
static void check_all(void)
{
	static uint8_t st[IMG_SIZE];

	do_read_check(0, IMG_SIZE);
	WRT_CHECK(rio_store_read(&B, 0, 0, st, IMG_SIZE));
	WRT_CHECK_MEM(st, model, IMG_SIZE);
	WRT_CHECK(rio_idle(&B));
}

/* ---- memory ------------------------------------------------------------------------------------------------------------------- */

static void test_mem(void)
{
	wr_config c;
	size_t a = 99, a2 = 0;

	memset(&c, 0, sizeof(c));
	wr_config_profile_harness(&c);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_mem(&c, &a));
	WRT_CHECK(a == 0); /* the OSD client is off */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_mem(NULL, &a));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_mem(&c, NULL));
	c.osd_sessions = 4;
	c.max_images = 2;
	c.max_reqs = 8;
	c.max_snaps = 16;
	c.img_ctl_bytes = 4096;
	c.op_bytes_max = 1u << 20;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_mem(&c, &a));
	WRT_CHECK(a > 2u * sizeof(wri_rbd_img) + 8u * sizeof(wri_rbd_rq));
	/* one more request grows the arena by the table entry and the ring entry (alignment aside) */
	c.max_reqs = 9;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_mem(&c, &a2));
	WRT_CHECK(a2 > a && a2 - a <= sizeof(wri_rbd_rq) + sizeof(uint32_t) + 32u);
	c.max_reqs = 8;
	c.max_images = 3;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_mem(&c, &a2));
	WRT_CHECK(a2 - a >= sizeof(wri_rbd_img) + 16u * sizeof(uint64_t) + 4096u + WRI_RBD_CTL_IN);
	c.max_images = 2;
	/* refused */
	c.max_images = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_mem(&c, &a));
	c.max_images = 2;
	c.max_reqs = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_mem(&c, &a));
	c.max_reqs = 8;
	c.op_bytes_max = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_mem(&c, &a));
}

static void test_init_exact(void)
{
	rio_params p = rio_defaults();
	uint32_t i, n = 0;

	if (rio_open(&B, &p) != 0) {
		WRT_CHECK(0);
		return;
	}
	/* the planned bytes are what the carve takes, to the byte, and every table is whole */
	WRT_CHECK(B.a.used == B.arena_planned);
	WRT_CHECK(B.r.n_img == p.max_images && B.r.n_rq == p.max_reqs);
	for (i = B.r.rq_free; i != WRI_NIL && n <= B.r.n_rq; i = B.r.rq[i].link)
		n++;
	WRT_CHECK(n == p.max_reqs);
	for (i = 0; i < B.r.n_img; i++) {
		const wri_rbd_img *im = &B.r.img[i];

		WRT_CHECK(im->state == (uint8_t)WR_IMG_FREE && im->slot == i && im->ctl_op == WRI_NIL);
		WRT_CHECK(im->snapc.cap == p.max_snaps && im->snapc.snaps != NULL);
		WRT_CHECK(im->ctl_in != NULL && im->ctl_out == im->ctl_in + WRI_RBD_CTL_IN);
		WRT_CHECK(i == 0 || im->ctl_in == B.r.img[i - 1u].ctl_in + WRI_RBD_CTL_IN + 4096u);
		WRT_CHECK(i == 0 || im->snapc.snaps == B.r.img[i - 1u].snapc.snaps + p.max_snaps);
	}
	/* the hook the glue bound before the carve survives it */
	rio_close(&B);
}

/* ---- submit ------------------------------------------------------------------------------------------------------------------- */

static void test_submit_checks(void)
{
	rio_params p = rio_defaults();
	rio_rq x, y;
	uint8_t buf[64];

	if (!open_one(&p, 1))
		return;
	rio_fill_req(&x, WR_IO_READ, 0, 16, buf, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(NULL, 0, &x.q));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 2, &x.q));  /* no such image */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 1, &x.q));  /* a free slot */
	x.q.kind = (wr_io_kind)0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, &x.q));
	x.q.kind = (wr_io_kind)6;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, &x.q));
	x.q.kind = WR_IO_READ;
	x.q.buf = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, &x.q));
	x.q.kind = WR_IO_WRITE;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, &x.q));
	/* flush, discard and write-zeroes need no buffer */
	rio_fill_req(&x, WR_IO_FLUSH, 0, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&B.r, 0, &x.q));
	/* the structure is the core's now: a second submit of it is refused, with nothing queued twice */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_submit(&B.r, 0, &x.q));
	WRT_CHECK_U64(B.r.reqs_inflight, 1);
	WRT_CHECK(rio_run(&B) == 1 && x.done && x.st == WR_OK);
	/* after the completion it is the host's: reusable at once, even without clearing it */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&B.r, 0, &x.q));
	x.done = 0;
	WRT_CHECK(rio_run(&B) == 1);
	/* range */
	rio_fill_req(&x, WR_IO_READ, IMG_SIZE - 15, 16, buf, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_WRITE, IMG_SIZE + 1u, 0, buf, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_DISCARD, 0, (uint64_t)IMG_SIZE + 1u, NULL, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_WRITE_ZEROES, UINT64_MAX - 3u, 8, NULL, 0); /* offset + length wraps */
	WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_READ, UINT64_MAX, 0, buf, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_READ, IMG_SIZE, 0, buf, 0); /* zero length at the very end: inside */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&B.r, 0, &x.q));
	WRT_CHECK(rio_run(&B) == 1 && x.st == WR_OK);
	/* too big: above 1 GiB for the data kinds (the range of a 64 KiB image would refuse it too, so make the image large) */
	B.r.img[0].size = 4ull << 30;
	rio_fill_req(&x, WR_IO_READ, 0, (uint64_t)WRI_RBD_IO_MAX + 1u, buf, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_WRITE, 0, (uint64_t)WRI_RBD_IO_MAX + 1u, buf, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_submit(&B.r, 0, &x.q));
	rio_fill_req(&x, WR_IO_WRITE, 0, UINT64_MAX, buf, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_submit(&B.r, 0, &x.q));
	B.r.img[0].size = IMG_SIZE;
	/* image states */
	B.r.img[0].state = (uint8_t)WR_IMG_OPENING;
	rio_fill_req(&x, WR_IO_READ, 0, 16, buf, 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_submit(&B.r, 0, &x.q));
	B.r.img[0].state = (uint8_t)WR_IMG_FAILED;
	WRT_CHECK_STATUS(WR_E_RBD_CLOSED, wri_rbd_submit(&B.r, 0, &x.q));
	B.r.img[0].state = (uint8_t)WR_IMG_CLOSING;
	WRT_CHECK_STATUS(WR_E_RBD_CLOSED, wri_rbd_submit(&B.r, 0, &x.q));
	B.r.img[0].state = (uint8_t)WR_IMG_OPEN;
	/* read-only: every write kind refuses, reads and flush do not */
	B.r.img[0].writable = 0;
	rio_fill_req(&y, WR_IO_WRITE, 0, 16, buf, 0);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, wri_rbd_submit(&B.r, 0, &y.q));
	rio_fill_req(&y, WR_IO_DISCARD, 0, 16, NULL, 0);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, wri_rbd_submit(&B.r, 0, &y.q));
	rio_fill_req(&y, WR_IO_WRITE_ZEROES, 0, 16, NULL, 0);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, wri_rbd_submit(&B.r, 0, &y.q));
	/* a READONLY refusal comes before the range check, the state check before it */
	rio_fill_req(&y, WR_IO_WRITE, IMG_SIZE, 16, buf, 0);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, wri_rbd_submit(&B.r, 0, &y.q));
	rio_fill_req(&y, WR_IO_FLUSH, 0, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&B.r, 0, &y.q));
	rio_fill_req(&x, WR_IO_READ, 0, 16, buf, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&B.r, 0, &x.q));
	WRT_CHECK(rio_run(&B) == 2 && x.st == WR_OK && y.st == WR_OK);
	/* nothing refused was queued */
	WRT_CHECK(rio_idle(&B));
	WRT_CHECK_U64(B.r.n_submitted, 5);
	rio_close(&B);
}

/* ---- kinds and alignments ------------------------------------------------------------------------------------------------------ */

static void test_empty_reads(void)
{
	rio_params p = rio_defaults();
	uint64_t off, len;
	unsigned n = 0;
	uint32_t objs;

	if (!open_one(&p, 1))
		return;
	objs = sim_store_n_objects(B.g.w.store);
	/* nothing was ever written: every object is missing, the OSD answers ENOENT, and the layer turns it into zeros and success */
	for (off = 0; off < IMG_SIZE; off += 1531)
		for (len = 1; off + len <= IMG_SIZE && len < 3u * OBJ; len = len * 3u + 1u, n++)
			do_read_check(off, len);
	do_read_check(0, IMG_SIZE);
	do_read_check(IMG_SIZE - 1, 1);
	WRT_CHECK(n > 40u);
	WRT_CHECK(sim_store_n_objects(B.g.w.store) == objs); /* reads created no data object */
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_write_grid(void)
{
	rio_params p = rio_defaults();
	static const uint64_t offs[] = {0, 1, OBJ - 1u, OBJ, OBJ + 1u, 2u * OBJ - 2u, 5u * OBJ + 17u, IMG_SIZE - 1u};
	static const uint64_t lens[] = {1, 2, OBJ - 1u, OBJ, OBJ + 1u, 2u * OBJ, 2u * OBJ + 3u, 3u * OBJ, 3u * OBJ + 1u};
	unsigned i, j, seed = 1, n = 0;

	if (!open_one(&p, 1))
		return;
	for (i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
		for (j = 0; j < sizeof(lens) / sizeof(lens[0]); j++) {
			uint64_t off = offs[i], len = lens[j];

			if (off + len > IMG_SIZE)
				continue;
			do_write(off, len, seed++);
			do_read_check(off, len);
			/* around the write too: the bytes before and after are untouched */
			{
				uint64_t lo = off > 8 ? off - 8 : 0, hi = off + len + 8 < IMG_SIZE ? off + len + 8 : IMG_SIZE;

				do_read_check(lo, hi - lo);
			}
			n++;
		}
		check_all();
	}
	WRT_CHECK(n >= 50u);
	rio_close(&B);
}

static void test_whole_objects_and_edges(void)
{
	rio_params p = rio_defaults();
	uint8_t one = 0x5a;

	if (!open_one(&p, 1))
		return;
	do_write(3u * OBJ, OBJ, 7);                   /* exactly one object */
	do_write(4u * OBJ, 2u * OBJ, 8);              /* exactly two, aligned */
	do_write(IMG_SIZE - 1u, 1, 9);                /* the last byte of the image */
	do_write(IMG_SIZE - OBJ - 1u, OBJ + 1u, 10);  /* the last object and the byte before it */
	do_write(0, IMG_SIZE, 11);                    /* the whole image */
	check_all();
	/* zero length: completes at once, at any offset up to the end, for every kind, touches nothing (not even the buffer pointer) */
	{
		static const wr_io_kind k[] = {WR_IO_READ, WR_IO_WRITE, WR_IO_DISCARD, WR_IO_WRITE_ZEROES};
		unsigned i;
		uint32_t reqs0 = sim_osd_n_requests(B.g.w.osd[0]);

		for (i = 0; i < 4; i++) {
			WRT_CHECK_STATUS(WR_OK, run_req(0, k[i], 0, 0, &one));
			WRT_CHECK_STATUS(WR_OK, run_req(0, k[i], 5000, 0, &one));
			WRT_CHECK_STATUS(WR_OK, run_req(0, k[i], IMG_SIZE, 0, &one));
		}
		WRT_CHECK_U64(sim_osd_n_requests(B.g.w.osd[0]), reqs0); /* nothing was sent */
		WRT_CHECK(one == 0x5a);
	}
	check_all();
	rio_close(&B);
}

static void test_holes_and_short_objects(void)
{
	rio_params p = rio_defaults();

	if (!open_one(&p, 1))
		return;
	do_write(0, 100, 21);                 /* object 0 holds 100 bytes and nothing behind them */
	do_write(5u * OBJ + 10, 20, 22);      /* object 5: a hole, 20 bytes, nothing behind */
	do_write(9u * OBJ + OBJ - 3u, 3, 23); /* the tail of object 9 only */
	do_read_check(0, OBJ);                /* a short answer: 100 bytes, the rest of the extent zero-filled */
	do_read_check(50, 3u * OBJ);          /* short answer in the first extent, missing objects after it */
	do_read_check(5u * OBJ, OBJ);
	do_read_check(9u * OBJ, OBJ);
	do_read_check(0, IMG_SIZE);
	/* the short object was answered with fewer bytes than asked, not with an error: the OSD's own words */
	{
		uint32_t i, n = 0, short_reads = 0;
		const sim_osd_rec *rec = sim_osd_recs(B.g.w.osd[0], &n);

		for (i = 0; i < n; i++)
			if (rec[i].n_ops == 1 && rec[i].op_code[0] == WRI_OSD_OP_READ && rec[i].op_out[0] != 0 && rec[i].op_out[0] < rec[i].op_len[0])
				short_reads++;
		WRT_CHECK(short_reads >= 2u);
	}
	check_all();
	rio_close(&B);
}

/* ---- what the OSD saw --------------------------------------------------------------------------------------------------------- */

static const sim_osd_rec *last_rec(void)
{
	uint32_t n = 0;
	const sim_osd_rec *rec = sim_osd_recs(B.g.w.osd[0], &n);

	return n != 0 ? &rec[n - 1u] : NULL;
}

static void test_discard_shapes(void)
{
	rio_params p = rio_defaults();
	const sim_osd_rec *rec;
	char name[WRI_RBD_OBJNAME_MAX];

	if (!open_one(&p, 1))
		return;
	do_write(0, IMG_SIZE, 31);
	/* a whole object: DELETE, the object is gone */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 2u * OBJ, OBJ, NULL));
	memset(model + 2u * OBJ, 0, OBJ);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->n_ops == 1 && rec->op_code[0] == WRI_OSD_OP_DELETE && rec->mutating);
	rio_oname(&B, 0, 2, name);
	WRT_CHECK(!sim_store_exists(B.g.w.store, W_POOL, name));
	do_read_check(2u * OBJ, OBJ);
	/* a tail: TRUNCATE to the start of the extent */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 3u * OBJ + 100, OBJ - 100, NULL));
	memset(model + 3u * OBJ + 100, 0, OBJ - 100);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->op_code[0] == WRI_OSD_OP_TRUNCATE && rec->op_off[0] == 100);
	rio_oname(&B, 0, 3, name);
	{
		uint64_t size = 0;

		WRT_CHECK_STATUS(WR_OK, sim_store_size(B.g.w.store, W_POOL, name, &size));
		WRT_CHECK_U64(size, 100);
	}
	/* the middle: ZERO(off, len) */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 4u * OBJ + 10, 20, NULL));
	memset(model + 4u * OBJ + 10, 0, 20);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->op_code[0] == WRI_OSD_OP_ZERO && rec->op_off[0] == 10 && rec->op_len[0] == 20);
	/* a range over several objects: an extent per object, each its own shape (tail of 5, all of 6, head of 7) */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 5u * OBJ + 1000, 2u * OBJ + 1000 + 24, NULL));
	memset(model + 5u * OBJ + 1000, 0, 2u * OBJ + 1000 + 24);
	check_all();
	rio_oname(&B, 0, 6, name);
	WRT_CHECK(!sim_store_exists(B.g.w.store, W_POOL, name));
	/* a discard of what does not exist is success (no parent) */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 2u * OBJ, OBJ, NULL));
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 6u * OBJ + 5, 77, NULL));
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 12u * OBJ, 4u * OBJ, NULL)); /* never written */
	memset(model + 12u * OBJ, 0, 4u * OBJ);
	check_all();
	rio_close(&B);
}

static void test_write_zeroes(void)
{
	rio_params p = rio_defaults();
	const sim_osd_rec *rec;
	char name[WRI_RBD_OBJNAME_MAX];

	if (!open_one(&p, 1))
		return;
	do_write(0, IMG_SIZE, 41);
	/* always ZERO, whatever the shape: a whole object stays (write-zeroes never removes it) */
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 2u * OBJ, OBJ, NULL));
	memset(model + 2u * OBJ, 0, OBJ);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->op_code[0] != WRI_OSD_OP_DELETE && rec->mutating);
	rio_oname(&B, 0, 2, name);
	WRT_CHECK(sim_store_exists(B.g.w.store, W_POOL, name));
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 3u * OBJ + 100, OBJ - 100, NULL));
	memset(model + 3u * OBJ + 100, 0, OBJ - 100);
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 5u * OBJ + 7, 33, NULL));
	memset(model + 5u * OBJ + 7, 0, 33);
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 7u * OBJ - 5u, 3u * OBJ + 11, NULL));
	memset(model + 7u * OBJ - 5u, 0, 3u * OBJ + 11);
	check_all();
	/* on objects that do not exist: success, nothing created */
	{
		uint32_t before = sim_store_n_objects(B.g.w.store);

		WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 0, IMG_SIZE, NULL)); /* now everything is gone */
		memset(model, 0, sizeof(model));
		WRT_CHECK(sim_store_n_objects(B.g.w.store) <= before);
		WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 11u * OBJ + 1, 5, NULL));
		WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, 0, IMG_SIZE, NULL));
	}
	check_all();
	rio_close(&B);
}

static void test_snapshot_context(void)
{
	rio_params p = rio_defaults();
	const sim_osd_rec *rec;
	wri_rbd_img *im;
	uint32_t i, n = 0, with_ctx = 0, writes = 0;
	const sim_osd_rec *all;

	if (!open_one(&p, 1))
		return;
	im = &B.r.img[0];
	do_write(0, 100, 51); /* no snapshots yet: an empty context */
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->snap_seq == 0 && rec->n_snaps == 0);
	/* the context is read at the time of the cut: the next write carries the image's current one */
	im->snapc.seq = 9;
	im->snapc.n = 3;
	im->snapc.snaps[0] = 9;
	im->snapc.snaps[1] = 6;
	im->snapc.snaps[2] = 2;
	do_write(OBJ, 100, 52);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->snap_seq == 9 && rec->n_snaps == 3);
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_DISCARD, 0, OBJ, NULL)); /* DELETE and ZERO carry it too */
	memset(model, 0, OBJ);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->op_code[0] == WRI_OSD_OP_DELETE && rec->snap_seq == 9 && rec->n_snaps == 3);
	WRT_CHECK_STATUS(WR_OK, run_req(0, WR_IO_WRITE_ZEROES, OBJ + 1, 5, NULL));
	memset(model + OBJ + 1, 0, 5);
	rec = last_rec();
	WRT_CHECK(rec != NULL && rec->snap_seq == 9 && rec->n_snaps == 3);
	/* the object the write found with a snapshot newer than its own made a clone: the snapshot read sees the old bytes */
	{
		char name[WRI_RBD_OBJNAME_MAX];

		rio_oname(&B, 0, 1, name);
		WRT_CHECK(sim_store_n_clones(B.g.w.store, W_POOL, name) <= 1u);
	}
	/* a read carries no context */
	do_read_check(0, 2u * OBJ);
	all = sim_osd_recs(B.g.w.osd[0], &n);
	for (i = 0; i < n; i++) {
		if (all[i].mutating) {
			writes++;
			if (all[i].snap_seq != 0)
				with_ctx++;
		} else {
			WRT_CHECK(all[i].snap_seq == 0 || all[i].n_ops == 0);
		}
	}
	WRT_CHECK(writes == 4u && with_ctx == 3u);
	check_all();
	rio_close(&B);
}

static void tweak_two_pools(rig *g)
{
	g->m.pool[1].present = 1; /* the data pool: handle 1, id W_POOL + 1 */
}

static void test_data_pool(void)
{
	rio_params p = rio_defaults();
	char name[WRI_RBD_OBJNAME_MAX];
	uint8_t st[IMG_SIZE];

	p.tweak = tweak_two_pools;
	if (!open_one(&p, 1))
		return;
	B.r.img[0].features |= WRI_RBD_F_DATA_POOL;
	B.r.img[0].data_pool_h = 1;
	B.r.img[0].data_pool_id = W_POOL + 1;
	do_write(OBJ - 10, 20, 61);
	rio_oname(&B, 0, 0, name);
	WRT_CHECK(sim_store_exists(B.g.w.store, W_POOL + 1, name));    /* the data objects are in the data pool ... */
	WRT_CHECK(!sim_store_exists(B.g.w.store, W_POOL, name));       /* ... and not in the image's own */
	do_read_check(0, 2u * OBJ);
	/* the model is the data pool's bytes */
	memset(st, 0, sizeof(st));
	{
		int exists = 0;

		WRT_CHECK_STATUS(WR_OK, sim_store_read(B.g.w.store, W_POOL + 1, name, OBJ - 10, st, 10, &exists));
		WRT_CHECK(exists);
		WRT_CHECK_MEM(st, model + OBJ - 10, 10);
	}
	rio_close(&B);
}

/* ---- flush, two images ---------------------------------------------------------------------------------------------------------- */

static void test_flush_sends_nothing(void)
{
	rio_params p = rio_defaults();
	rio_rq f[3];
	uint32_t reqs0;
	unsigned i;

	if (!open_one(&p, 1))
		return;
	do_write(0, 3000, 71);
	reqs0 = sim_osd_n_requests(B.g.w.osd[0]);
	/* nothing in flight: a flush completes at once, and sends nothing (a completed write is durable, design 25.4) */
	for (i = 0; i < 3; i++)
		WRT_CHECK(rio_go(&B, 0, &f[i], WR_IO_FLUSH, 0, 0, NULL, 0));
	WRT_CHECK(B.r.done_len == 3u); /* done before any step: no engine round trip */
	WRT_CHECK(rio_collect_done(&B) == 3u);
	for (i = 0; i < 3; i++)
		WRT_CHECK(f[i].done && f[i].st == WR_OK && f[i].order == f[0].order + i);
	(void)rio_run(&B);
	WRT_CHECK_U64(sim_osd_n_requests(B.g.w.osd[0]), reqs0);
	/* a flush whose offset and length hold rubbish is still a flush */
	rio_fill_req(&f[0], WR_IO_FLUSH, 12345, 678, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &f[0]));
	WRT_CHECK(rio_run(&B) == 1 && f[0].st == WR_OK);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_two_images(void)
{
	rio_params p = rio_defaults();
	static uint8_t a[2u * OBJ], b[2u * OBJ], got[2u * OBJ];
	rio_rq w0, w1, r0, r1;

	if (!open_one(&p, 1))
		return;
	if (rio_image(&B, 1, "img1", 8u * OBJ, ORDER, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(a, sizeof(a), 81);
	rio_pattern(b, sizeof(b), 82);
	/* the same offsets of two images do not conflict in the fence and land in their own objects */
	WRT_CHECK(rio_go(&B, 0, &w0, WR_IO_WRITE, 100, sizeof(a), a, 0));
	WRT_CHECK(rio_go(&B, 1, &w1, WR_IO_WRITE, 100, sizeof(b), b, 0));
	WRT_CHECK(rio_run(&B) == 2 && w0.st == WR_OK && w1.st == WR_OK);
	memset(got, 0, sizeof(got));
	WRT_CHECK(rio_go(&B, 0, &r0, WR_IO_READ, 100, sizeof(got), got, 0));
	WRT_CHECK(rio_run(&B) == 1);
	WRT_CHECK_MEM(got, a, sizeof(a));
	memset(got, 0, sizeof(got));
	WRT_CHECK(rio_go(&B, 1, &r1, WR_IO_READ, 100, sizeof(got), got, 0));
	WRT_CHECK(rio_run(&B) == 1);
	WRT_CHECK_MEM(got, b, sizeof(b));
	/* an offset that is inside the big image (slot 0) and outside the small one (slot 1) */
	rio_fill_req(&r1, WR_IO_READ, 10u * OBJ, 1, got, 0);
	WRT_CHECK_STATUS(WR_E_RANGE, rio_submit(&B, 1, &r1));
	rio_fill_req(&r0, WR_IO_READ, 10u * OBJ, 1, got, 0);
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &r0));
	WRT_CHECK(rio_run(&B) == 1);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- a request spanning the engine's table ----------------------------------------------------------------------------------------- */

static void test_cut_by_op_bytes(void)
{
	rio_params p = rio_defaults();
	uint32_t before, after, n = 0, i;
	const sim_osd_rec *rec;

	p.op_bytes_max = 1500; /* below the object size: an extent is cut again at 1500 bytes */
	if (!open_one(&p, 1))
		return;
	before = sim_osd_n_requests(B.g.w.osd[0]);
	do_write(OBJ - 100, 2u * OBJ + 200, 91);
	after = sim_osd_n_requests(B.g.w.osd[0]);
	/* 100 bytes of object 0, then objects 1 and 2 in three pieces each (1500 + 1500 + 1096), then 100 bytes of object 3: eight operations */
	WRT_CHECK_U64(after - before, 8);
	rec = sim_osd_recs(B.g.w.osd[0], &n);
	for (i = 0; i < n; i++)
		if (rec[i].n_ops == 1 && rec[i].op_code[0] == WRI_OSD_OP_WRITE)
			WRT_CHECK(rec[i].op_len[0] <= 1500u && rec[i].data_len <= 1500u);
	do_read_check(OBJ - 100, 2u * OBJ + 200);
	check_all();
	rio_close(&B);
}

int main(void)
{
	test_mem();
	test_init_exact();
	test_submit_checks();
	test_empty_reads();
	test_write_grid();
	test_whole_objects_and_edges();
	test_holes_and_short_objects();
	test_discard_shapes();
	test_write_zeroes();
	test_snapshot_context();
	test_data_pool();
	test_flush_sends_nothing();
	test_two_images();
	test_cut_by_op_bytes();
	return wrt_finish();
}
