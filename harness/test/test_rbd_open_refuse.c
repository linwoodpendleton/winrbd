/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_open_refuse.c - every refusal of the table of design 24.3, end to end: an image built with sim_rbd_image_create is opened through the real
 * request engine and the open must END (state FAILED) with the exact status, the numbers in errinfo (a0 .. a2) and one WR_EV_IMAGE event; the order of
 * the rules (features, then the snapshot context, then order, striping, parent, data pool, flags); the pool checks (a pool the client cannot use, a
 * writer on a pool in pool-snapshot mode, a data pool with the wrong id); and the accepted side of the same table (reader R1, writer P1), bit by bit.
 */
#include "rbd_open_rig.h"

static orig O;

typedef struct want {
	wr_status st;
	uint64_t a0, a1, a2;
	int numbers;          /* check a0 .. a2 */
} want;

/* The image is FAILED with exactly this, once, and closes cleanly. */
static void failed_with(orig *o, uint32_t slot, const want *w)
{
	wri_rbd_img *m = oimg(o, slot);

	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED);
	WRT_CHECK_STATUS(w->st, m->err.status);
	WRT_CHECK(m->err.module == WR_MOD_RBD && m->err.what != NULL);
	if (w->numbers) {
		WRT_CHECK_U64(m->err.a0, w->a0);
		WRT_CHECK_U64(m->err.a1, w->a1);
		WRT_CHECK_U64(m->err.a2, w->a2);
	}
	WRT_CHECK(m->ctl_op == WRI_NIL && m->ros == (uint8_t)WRI_ROS_IDLE && m->was_open == 0u && !m->writable);
	WRT_CHECK(orig_count_ev(o, WR_EV_IMAGE, slot) == 1u && o->ev[0].st == w->st);
	WRT_CHECK(orig_ctl_idle(o));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&o->L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && orig_count_ev(o, WR_EV_IMAGE, slot) == 2u);
}

/* Build the image, open it by name with the given data pool name (or NULL), return the slot after the machine has run. */
static uint32_t run_open(const sim_rbd_image_cfg *c, int writer, const char *data_pool, void (*prep)(orig *))
{
	wr_image_params p = oparams(OR_META, c->name, NULL, writer);
	uint32_t slot;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return WRI_NIL;
	}
	if (prep != NULL)
		prep(&O);
	oimg_make(&O, c);
	p.data_pool = data_pool;
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	return slot;
}

static void expect_refused(const sim_rbd_image_cfg *c, int writer, const char *data_pool, const want *w, void (*prep)(orig *))
{
	uint32_t slot = run_open(c, writer, data_pool, prep);

	if (slot != WRI_NIL)
		failed_with(&O, slot, w);
	orig_close(&O);
}

static void expect_accepted(const sim_rbd_image_cfg *c, int writer, const char *data_pool, void (*prep)(orig *))
{
	uint32_t slot = run_open(c, writer, data_pool, prep);

	if (slot != WRI_NIL) {
		WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
		if (oimg(&O, slot)->state != (uint8_t)WR_IMG_OPEN)
			fprintf(stderr, "  (features 0x%" PRIx64 " writer %d: status %s)\n", c->features, writer, wrt_status_name_(oimg(&O, slot)->err.status));
		WRT_CHECK(oimg(&O, slot)->writable == (writer ? 1u : 0u));
	}
	orig_close(&O);
}

/* ---- feature bits, one at a time, in both profiles ---------------------------------------------------------------------------- */

static sim_rbd_image_cfg with_bit(uint64_t bit)
{
	sim_rbd_image_cfg c = oimg_cfg("img-f", "f0f0f0f0f0f0");

	c.features = bit;
	if (bit == WRI_RBD_F_DATA_POOL)
		c.data_pool = W_POOL + 1;
	if (bit == WRI_RBD_F_STRIPINGV2) {
		c.stripe_unit = 1ull << 22;
		c.stripe_count = 1;
	}
	return c;
}

static void test_feature_bits(void)
{
	static const uint64_t bits[] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x8000, 1ull << 40, 1ull << 63};
	static const uint64_t reader_ok = 0x1ff, writer_ok = 0xa3; /* P1 and the conditional striping bit in its default form */
	unsigned i, w;

	for (w = 0; w < 2; w++) {
		for (i = 0; i < sizeof(bits) / sizeof(bits[0]); i++) {
			sim_rbd_image_cfg c = with_bit(bits[i]);
			uint64_t ok = w ? writer_ok : reader_ok;
			const char *dp = bits[i] == WRI_RBD_F_DATA_POOL ? OR_DATA : NULL;

			if ((bits[i] & ok) != 0 && (bits[i] & ~ok) == 0) {
				expect_accepted(&c, (int)w, dp, NULL);
			} else {
				want x;

				x.st = WR_E_RBD_FEATURES;
				x.a0 = bits[i];
				x.a1 = bits[i];
				x.a2 = w;
				x.numbers = 1;
				expect_refused(&c, (int)w, dp, &x, NULL);
			}
		}
	}
	/* the writer's profile bits together, and the reader's whole mask */
	{
		sim_rbd_image_cfg c = oimg_cfg("img-f", "f0f0f0f0f0f0");

		c.features = 0xa1;
		c.data_pool = W_POOL + 1;
		expect_accepted(&c, 1, OR_DATA, NULL);
		c.features = 0x1ff & ~WRI_RBD_F_STRIPINGV2;
		expect_accepted(&c, 0, OR_DATA, NULL);
	}
	/* several offending bits are reported together; the bits of the profile are not among them */
	{
		sim_rbd_image_cfg c = oimg_cfg("img-f", "f0f0f0f0f0f0");
		want x = {WR_E_RBD_FEATURES, 0x4 | 0x8 | 0x10, 0x4 | 0x8 | 0x10 | 0x21, 1, 1};

		c.features = 0x3d; /* the usual default of rbd create: layering, exclusive-lock, object-map, fast-diff, deep-flatten */
		x.a0 = 0x1c;
		x.a1 = 0x3d;
		expect_refused(&c, 1, NULL, &x, NULL);
		expect_accepted(&c, 0, NULL, NULL); /* a reader takes it: exclusive-lock and the maps are ignored */
	}
}

/* ---- layout, parent, data pool, flags ----------------------------------------------------------------------------------------- */

static void test_order(void)
{
	unsigned order;

	for (order = 10; order <= 27; order++) {
		sim_rbd_image_cfg c = oimg_cfg("img-o", "0d0d0d0d0d0d");
		int ok = order >= 12 && order <= 25;
		unsigned w;

		c.order = (uint8_t)order;
		c.size = 1ull << 30;
		for (w = 0; w < 2; w++) {
			if (ok) {
				expect_accepted(&c, (int)w, NULL, NULL);
			} else {
				want x = {WR_E_RBD_ORDER, order, 12, 25, 1};

				expect_refused(&c, (int)w, NULL, &x, NULL);
			}
		}
	}
}

static void test_striping(void)
{
	unsigned w;

	for (w = 0; w < 2; w++) {
		sim_rbd_image_cfg c = oimg_cfg("img-t", "7777777777");
		want x = {WR_E_RBD_STRIPING, 0, 0, 1ull << 22, 1};

		c.features = 0x23;
		/* a smaller stripe unit, count 1 */
		c.stripe_unit = 1ull << 20;
		c.stripe_count = 1;
		x.a0 = 1ull << 20;
		x.a1 = 1;
		expect_refused(&c, (int)w, NULL, &x, NULL);
		/* the object size as the unit, but several stripes */
		c.stripe_unit = 1ull << 22;
		c.stripe_count = 4;
		x.a0 = 1ull << 22;
		x.a1 = 4;
		expect_refused(&c, (int)w, NULL, &x, NULL);
		/* fancy striping on a small order */
		c.order = 16;
		c.stripe_unit = 4096;
		c.stripe_count = 16;
		x.a0 = 4096;
		x.a1 = 16;
		x.a2 = 1ull << 16;
		expect_refused(&c, (int)w, NULL, &x, NULL);
		/* default form at another order */
		c.stripe_unit = 1ull << 16;
		c.stripe_count = 1;
		expect_accepted(&c, (int)w, NULL, NULL);
	}
}

static void test_parent(void)
{
	unsigned w;

	for (w = 0; w < 2; w++) {
		sim_rbd_image_cfg c = oimg_cfg("img-c", "c1c1c1c1c1c1");
		want x = {WR_E_RBD_PARENT, 3, 64ull << 20, 0, 1}; /* parent_get found one and parent_overlap_get answered (the overlap is the size) */

		c.has_parent = 1;
		expect_refused(&c, (int)w, NULL, &x, NULL);
		/* only the operations bit with clone-child (the belt-and-braces rule): a reader, which reads op_features */
		if (!w) {
			want y = {WR_E_RBD_PARENT, 4, 0, 0x2, 1};

			c = oimg_cfg("img-c", "c1c1c1c1c1c1");
			c.features = 0x121;
			c.op_features = 0x2;
			expect_refused(&c, 0, NULL, &y, NULL);
		}
	}
}

static void test_data_pool_refusals(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-d", "d9d9d9d9d9d9");
	want x;

	c.features = 0xa1;
	c.data_pool = W_POOL + 1;
	/* no data pool named: the operator is told the id to look for (a0 = the image's, a1 = -1: none named) */
	x.st = WR_E_RBD_DATA_POOL;
	x.a0 = W_POOL + 1;
	x.a1 = (uint64_t)-1;
	x.a2 = 0;
	x.numbers = 1;
	expect_refused(&c, 1, NULL, &x, NULL);
	expect_refused(&c, 0, NULL, &x, NULL);
	/* the wrong name: a pool of another id (a1 = the id of the pool that was named) */
	x.a1 = W_POOL;
	expect_refused(&c, 1, OR_META, &x, NULL);
	expect_refused(&c, 0, OR_META, &x, NULL);
	/* the bit is set but the header says "no data pool" */
	c.data_pool = -1;
	x.a0 = (uint64_t)-1;
	x.a1 = 0;
	expect_refused(&c, 1, OR_DATA, &x, NULL);
	/* the right name works for both profiles */
	c.data_pool = W_POOL + 1;
	expect_accepted(&c, 1, OR_DATA, NULL);
	expect_accepted(&c, 0, OR_DATA, NULL);
	/* a pool id in the header without the bit is not judged */
	c = oimg_cfg("img-d", "d9d9d9d9d9d9");
	c.data_pool = W_POOL + 1;
	expect_accepted(&c, 1, NULL, NULL);
}

static void test_flags(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-g", "9191919191");
	unsigned f;

	for (f = 1; f <= 3; f++) {
		want x = {WR_E_RBD_FLAGS, f, 0, 0, 1};

		c.flags = f;
		expect_refused(&c, 1, NULL, &x, NULL);
		expect_accepted(&c, 0, NULL, NULL); /* a reader ignores them */
	}
}

/* ---- the snapshot context and the order of the rules --------------------------------------------------------------------------- */

static void fill_snaps(sim_rbd_image_cfg *c, unsigned n)
{
	unsigned i;

	c->snap_seq = 100;
	c->n_snaps = n;
	for (i = 0; i < n && i < 16; i++)
		c->snaps[i] = 100u - i;
}

static void test_snapc(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-n", "1212121212");
	want x = {WR_E_RBD_SNAPC, 9, 8, 1, 1}; /* a0 = what the server sent, a1 = what the profile holds (max_snaps = 8), a2 = writer */

	fill_snaps(&c, 8);
	expect_accepted(&c, 1, NULL, NULL); /* exactly max_snaps */
	fill_snaps(&c, 9);
	expect_refused(&c, 1, NULL, &x, NULL);
	expect_accepted(&c, 0, NULL, NULL); /* a reader lives without the context */
}

static void test_rule_order(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-r", "3434343434");
	want feat = {WR_E_RBD_FEATURES, 0x4, 0x6, 1, 1};
	want snap = {WR_E_RBD_SNAPC, 9, 8, 1, 1};
	want strp = {WR_E_RBD_STRIPING, 1ull << 20, 1, 1ull << 22, 1};
	want ord = {WR_E_RBD_ORDER, 11, 12, 25, 1};
	want par = {WR_E_RBD_PARENT, 3, 64ull << 20, 0, 1};
	want flg = {WR_E_RBD_FLAGS, 1, 0, 0, 1};

	/* features beat everything, and the refusal does not even need the stripe read */
	c.features = 0x6; /* exclusive-lock + striping, with a layout that is not the default */
	c.stripe_unit = 1ull << 20;
	c.stripe_count = 1;
	fill_snaps(&c, 9);
	c.order = 11;
	c.has_parent = 1;
	c.flags = 1;
	{
		uint32_t slot = run_open(&c, 1, NULL, NULL);

		if (slot != WRI_NIL)
			failed_with(&O, slot, &feat);
		WRT_CHECK(rig_nrec(&O.r, 0) == 2u); /* get_id and the header: no EXTRA read after a feature refusal */
		orig_close(&O);
	}
	/* then the snapshot context, ahead of order, striping, parent and flags */
	c.features = 0x23;
	expect_refused(&c, 1, NULL, &snap, NULL);
	/* then the order */
	fill_snaps(&c, 0);
	expect_refused(&c, 1, NULL, &ord, NULL);
	/* then striping */
	c.order = 22;
	expect_refused(&c, 1, NULL, &strp, NULL);
	/* then the parent */
	c.features = 0x21;
	c.stripe_unit = c.stripe_count = 0;
	expect_refused(&c, 1, NULL, &par, NULL);
	/* then the flags */
	c.has_parent = 0;
	expect_refused(&c, 1, NULL, &flg, NULL);
}

/* ---- pools ------------------------------------------------------------------------------------------------------------------- */

static void prep_pool0_unsupported(orig *o) { o->r.m.pool[0].status = WR_E_POOL_UNSUPPORTED; o->r.m.pool[0].flags = 0x77; }
static void prep_pool1_unsupported(orig *o) { o->r.m.pool[1].status = WR_E_POOL_UNSUPPORTED; }
static void prep_pool0_snaps(orig *o) { o->r.m.pool[0].flags = WR_POOL_F_POOL_SNAPS; }
static void prep_pool1_snaps(orig *o) { o->r.m.pool[1].flags = WR_POOL_F_POOL_SNAPS; }

static void test_pools(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-p", "4545454545");
	sim_rbd_image_cfg d = oimg_cfg("img-q", "5454545454");
	want x = {WR_E_POOL_UNSUPPORTED, 0, 0x77, 0, 0};

	d.features = 0xa1;
	d.data_pool = W_POOL + 1;
	/* a pool with a status other than OK fails the open with that status, before any I/O */
	x.numbers = 0;
	{
		uint32_t slot = run_open(&c, 0, NULL, prep_pool0_unsupported);

		if (slot != WRI_NIL)
			failed_with(&O, slot, &x);
		WRT_CHECK(rig_nrec(&O.r, 0) == 0u);
		orig_close(&O);
	}
	{
		uint32_t slot = run_open(&d, 1, OR_DATA, prep_pool1_unsupported);

		if (slot != WRI_NIL) {
			x.a0 = 1;
			failed_with(&O, slot, &x);
		}
		WRT_CHECK(rig_nrec(&O.r, 0) == 0u);
		orig_close(&O);
	}
	/* a writer refuses pool-snapshot mode (the OSD would replace its snapshot context); a reader does not care */
	{
		want y = {WR_E_POOL_UNSUPPORTED, 0, WR_POOL_F_POOL_SNAPS, 0, 1};

		expect_refused(&c, 1, NULL, &y, prep_pool0_snaps);
		expect_accepted(&c, 0, NULL, prep_pool0_snaps);
		/* with a data pool the one that takes the data decides: the image pool may be in that mode, the data pool not */
		expect_accepted(&d, 1, OR_DATA, prep_pool0_snaps);
		expect_refused(&d, 1, OR_DATA, &y, prep_pool1_snaps);
		expect_accepted(&d, 0, OR_DATA, prep_pool1_snaps);
		/* the image without the data-pool bit with a named data pool: the image pool takes the data, its mode counts */
		expect_accepted(&c, 1, OR_DATA, prep_pool1_snaps);
	}
}

int main(void)
{
	test_feature_bits();
	test_order();
	test_striping();
	test_parent();
	test_data_pool_refusals();
	test_flags();
	test_snapc();
	test_rule_order();
	test_pools();
	return wrt_finish();
}
