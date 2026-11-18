/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_budget.c - the layer inside its budgets (design 25.2, 26): a request is never expanded, so one operation slot and one request table entry
 * carry a 64 MiB request through; the bytes in flight stay inside inflight_bytes_max (an operation is clamped to fit by itself); max_reqs is a hard
 * BUSY, and a zombie fence entry counts against it; the cutting loop is fair (a small request admitted after a huge one is not starved) and bounded by its
 * budget; the control reserve of the engine is never touched by data operations.
 */
#include "rbd_io_rig.h"

static rbio B;

static sim_osd *osd0(void) { return B.g.w.osd[0]; }
static uint32_t sent(void) { return sim_osd_n_requests(osd0()); }

static void release(uint32_t n)
{
	(void)rio_run(&B);
	(void)sim_osd_release(osd0(), n);
	(void)rio_run(&B);
}

static void drain_all(void)
{
	int i;

	for (i = 0; i < 100; i++) {
		release(0);
		if (sim_osd_n_held(osd0()) == 0)
			break;
	}
}

/* ---- one slot, one request, 64 MiB ----------------------------------------------------------------------------------------------- */

#define BIG (64u << 20)

static void test_64mib_through_one_slot(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r, z, d, other;
	uint8_t *buf = (uint8_t *)malloc(BIG), *back = (uint8_t *)malloc(BIG);
	uint32_t objs;

	p.max_ops = 3;          /* one data slot (two are the control reserve) */
	p.ctl_ops = 2;
	p.max_reqs = 1;         /* one request in the table */
	p.op_bytes_max = 1u << 20;
	p.inflight_bytes_max = 1u << 20;
	if (buf == NULL || back == NULL || rio_open(&B, &p) != 0 || rio_image(&B, 0, "big", BIG, 22, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	objs = sim_store_n_objects(B.g.w.store);
	rio_pattern(buf, BIG, 5);
	WRT_CHECK(rio_go(&B, 0, &w, WR_IO_WRITE, 0, BIG, buf, 0));
	/* the table holds one request: another is BUSY (and untouched: not queued, not marked as the core's) */
	rio_fill_req(&other, WR_IO_FLUSH, 0, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &other));
	WRT_CHECK(other.q.priv[0] == 0 && other.q.priv[1] == 0);
	WRT_CHECK(rio_until(&B, &w, 600000) && w.st == WR_OK);
	WRT_CHECK(B.g.o.hiwater == 1u);             /* the engine never held more than one operation: the request was cut lazily, one extent at a time */
	WRT_CHECK(B.r.reqs_hiwater == 1u && B.g.o.n_done == 64u);
	WRT_CHECK(sent() == 64u);
	/* read it back through the same single slot */
	memset(back, 0xA5, BIG);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, BIG, back, 0));
	WRT_CHECK(rio_until(&B, &r, 600000) && r.st == WR_OK);
	WRT_CHECK(memcmp(back, buf, BIG) == 0);
	WRT_CHECK(B.g.o.hiwater == 1u);
	/* a few objects as the store has them */
	{
		static uint8_t one[1u << 20];

		WRT_CHECK(rio_store_read(&B, 0, 4u * 1048576u + 12345u, one, sizeof(one)));
		WRT_CHECK(memcmp(one, buf + 4u * 1048576u + 12345u, sizeof(one)) == 0);
		WRT_CHECK(rio_store_read(&B, 0, BIG - sizeof(one), one, sizeof(one)));
		WRT_CHECK(memcmp(one, buf + BIG - sizeof(one), sizeof(one)) == 0);
	}
	/* write-zeroes over the whole image: the objects stay and read as zeros; discard removes them */
	WRT_CHECK(rio_go(&B, 0, &z, WR_IO_WRITE_ZEROES, 0, BIG, NULL, 0));
	WRT_CHECK(rio_until(&B, &z, 600000) && z.st == WR_OK);
	memset(back, 0xA5, BIG);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, BIG, back, 0));
	WRT_CHECK(rio_until(&B, &r, 600000) && r.st == WR_OK);
	{
		uint64_t i, bad = 0;

		for (i = 0; i < BIG; i += 8)
			bad |= *(const uint64_t *)(const void *)(back + i);
		WRT_CHECK(bad == 0);
	}
	WRT_CHECK(rio_go(&B, 0, &d, WR_IO_DISCARD, 0, BIG, NULL, 0));
	WRT_CHECK(rio_until(&B, &d, 600000) && d.st == WR_OK);
	WRT_CHECK(sim_store_n_objects(B.g.w.store) == objs); /* every data object is gone */
	WRT_CHECK(B.g.o.hiwater == 1u && rio_idle(&B));
	free(buf);
	free(back);
	rio_close(&B);
}

/* ---- the bytes in flight ------------------------------------------------------------------------------------------------------------ */

static void test_byte_budget(void)
{
	rio_params p = rio_defaults();
	static uint8_t buf[1u << 20], back[1u << 20];
	rio_rq w, r;
	uint32_t i, n = 0, max_len = 0, writes = 0;
	uint32_t max_bytes = 0, max_ops = 0, steps = 0;
	const sim_osd_rec *rec;

	p.op_bytes_max = 1u << 20;   /* above what may be in flight: the cut is clamped to the budget */
	p.inflight_bytes_max = 8192;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "bytes", 1u << 20, 16, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(buf, sizeof(buf), 9);
	WRT_CHECK(rio_go(&B, 0, &w, WR_IO_WRITE, 0, sizeof(buf), buf, 0));
	while (!w.done && steps++ < 100000) {
		(void)rio_step_once(&B);
		(void)rio_collect_done(&B);
		if (B.g.o.inflight_bytes > max_bytes)
			max_bytes = B.g.o.inflight_bytes;
		if (B.g.o.n_inflight > max_ops)
			max_ops = B.g.o.n_inflight;
	}
	WRT_CHECK(w.done && w.st == WR_OK);
	WRT_CHECK(max_bytes <= 8192u && max_bytes != 0 && max_ops == 1u);
	rec = sim_osd_recs(osd0(), &n);
	for (i = 0; i < n; i++)
		if (rec[i].mutating) {
			writes++;
			if (rec[i].data_len > max_len)
				max_len = rec[i].data_len;
		}
	WRT_CHECK(writes == 128u && max_len == 8192u);
	memset(back, 0, sizeof(back));
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, sizeof(back), back, 0));
	WRT_CHECK(rio_until(&B, &r, 600000) && r.st == WR_OK);
	WRT_CHECK(memcmp(back, buf, sizeof(buf)) == 0 && B.g.o.hiwater == 1u);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- max_reqs ------------------------------------------------------------------------------------------------------------------------ */

static void test_max_reqs_busy(void)
{
	rio_params p = rio_defaults();
	rio_rq x[5], again;
	unsigned i;

	p.max_reqs = 4;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "reqs", 1u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	sim_osd_faults(osd0())->hold_replies = 1;
	{
		static uint8_t buf[4096];

		rio_pattern(buf, sizeof(buf), 3);
		for (i = 0; i < 4; i++)
			WRT_CHECK(rio_go(&B, 0, &x[i], WR_IO_WRITE, (uint64_t)i * 8192u, 100, buf, 0));
		rio_fill_req(&x[4], WR_IO_WRITE, 5u * 8192u, 100, buf, 0);
		WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &x[4]));
		WRT_CHECK(x[4].q.priv[0] == 0);
		/* zero-length and flush requests take a table entry too */
		rio_fill_req(&again, WR_IO_FLUSH, 0, 0, NULL, 0);
		WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &again));
		rio_fill_req(&again, WR_IO_READ, 0, 0, buf, 0);
		WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &again));
		WRT_CHECK(B.r.reqs_inflight == 4u && B.r.reqs_hiwater == 4u);
		(void)rio_run(&B);
		/* the first answer frees an entry */
		(void)sim_osd_release(osd0(), 1);
		(void)rio_run(&B);
		WRT_CHECK(x[0].done && !x[1].done);
		WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &x[4]));
		rio_fill_req(&again, WR_IO_READ, 0, 10, buf, 0);
		WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &again));
		drain_all();
		WRT_CHECK(x[1].done && x[2].done && x[3].done && x[4].done);
	}
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_zombie_takes_an_entry(void)
{
	rio_params p = rio_defaults();
	rio_rq a, b, c;
	static uint8_t buf[512];

	p.max_reqs = 2;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "zomb", 1u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(buf, sizeof(buf), 3);
	sim_osd_faults(osd0())->hold_replies = 1;
	WRT_CHECK(rio_go(&B, 0, &a, WR_IO_WRITE, 0, 100, buf, 0));
	WRT_CHECK(rio_go(&B, 0, &b, WR_IO_READ, 8192, 100, buf, 0));
	(void)rio_run(&B);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &a.q)); /* a sent write: a zombie, the entry stays */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &b.q)); /* a read: nothing stays */
	WRT_CHECK(rio_collect_done(&B) == 2u);
	WRT_CHECK(B.r.reqs_inflight == 1u);
	rio_fill_req(&c, WR_IO_FLUSH, 0, 0, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &c));          /* the one free entry */
	rio_fill_req(&b, WR_IO_READ, 0, 1, buf, 0);
	WRT_CHECK_STATUS(WR_E_BUSY, rio_submit(&B, 0, &b));      /* the zombie's entry and the flush's: full */
	drain_all();
	WRT_CHECK(c.done && B.r.reqs_inflight == 0u);            /* the answer of the cluster released the zombie's entry */
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &b));
	drain_all();
	WRT_CHECK(b.done && b.st == WR_OK);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- fairness and the cut budget ------------------------------------------------------------------------------------------------------ */

static void test_fairness_one_slot(void)
{
	rio_params p = rio_defaults();
	static uint8_t big[64u * 4096u], small[100];
	rio_rq a, b;
	uint32_t i, n = 0, pos = 0, found = 0;
	const sim_osd_rec *rec;
	char name[WRI_RBD_OBJNAME_MAX];

	p.max_ops = 3; /* one data slot */
	p.ctl_ops = 2;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "fair", 1u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(big, sizeof(big), 1);
	rio_pattern(small, sizeof(small), 2);
	/* a huge request (64 extents), then a small one admitted after it: the small one is served among the first extents, not after the last */
	WRT_CHECK(rio_go(&B, 0, &a, WR_IO_WRITE, 0, sizeof(big), big, 0));
	WRT_CHECK(rio_go(&B, 0, &b, WR_IO_WRITE, 100u * 4096u, sizeof(small), small, 0));
	WRT_CHECK(rio_until(&B, &a, 600000) && rio_until(&B, &b, 600000));
	WRT_CHECK(a.st == WR_OK && b.st == WR_OK);
	WRT_CHECK(b.order < a.order);
	rio_oname(&B, 0, 100, name);
	rec = sim_osd_recs(osd0(), &n);
	for (i = 0; i < n; i++)
		if (strcmp(rec[i].oid, name) == 0) {
			pos = i;
			found = 1;
		}
	WRT_CHECK(found && pos <= 3u);
	WRT_CHECK(n == 65u && B.g.o.hiwater == 1u);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_fairness_quantum(void)
{
	rio_params p = rio_defaults();
	static uint8_t big[2][200u * 4096u];
	rio_rq a, b;

	p.max_ops = 12; /* ten data slots */
	p.ctl_ops = 2;
	p.max_reqs = 4;
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "quantum", 4u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(big[0], sizeof(big[0]), 1);
	rio_pattern(big[1], sizeof(big[1]), 2);
	sim_osd_faults(osd0())->hold_replies = 1;
	WRT_CHECK(rio_go(&B, 0, &a, WR_IO_WRITE, 0, sizeof(big[0]), big[0], 0));
	WRT_CHECK(rio_go(&B, 0, &b, WR_IO_WRITE, 300u * 4096u, sizeof(big[1]), big[1], 0));
	(void)rio_run(&B);
	/* ten slots, a quantum of four per visit: a gets four, b four, a two: both are on the wire, neither has all ten */
	{
		uint32_t oa = B.r.rq[0].ops_out, ob = B.r.rq[1].ops_out;

		WRT_CHECK(oa + ob == 10u);
		WRT_CHECK(oa >= WRI_RBD_RQ_QUANTUM && ob >= WRI_RBD_RQ_QUANTUM);
	}
	drain_all();
	WRT_CHECK(a.done && b.done && a.st == WR_OK && b.st == WR_OK);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_cut_budget(void)
{
	rio_params p = rio_defaults();
	static uint8_t buf[10u * 4096u];
	rio_rq w;

	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "budget", 1u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(buf, sizeof(buf), 4);
	WRT_CHECK(rio_go(&B, 0, &w, WR_IO_WRITE, 0, sizeof(buf), buf, 0));
	/* a budget of zero admits and cuts nothing, and says there is more to do */
	WRT_CHECK(wri_rbd_io_cut(&B.r, 0) == 1);
	WRT_CHECK(B.g.o.n_inflight == 0u && B.r.rq[0].state == WRI_RQ_RUN);
	WRT_CHECK(wri_rbd_io_cut(&B.r, 3) == 1 && B.g.o.n_inflight == 3u);
	WRT_CHECK(wri_rbd_io_cut(&B.r, 3) == 1 && B.g.o.n_inflight == 6u);
	WRT_CHECK(wri_rbd_io_cut(&B.r, 3) == 1 && B.g.o.n_inflight == 9u);
	WRT_CHECK(wri_rbd_io_cut(&B.r, 3) == 0 && B.g.o.n_inflight == 10u); /* the last extent: nothing more */
	WRT_CHECK(wri_rbd_io_cut(&B.r, 3) == 0 && B.g.o.n_inflight == 10u);
	WRT_CHECK(rio_until(&B, &w, 60000) && w.st == WR_OK);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_control_reserve_untouched(void)
{
	rio_params p = rio_defaults();
	static uint8_t buf[40u * 4096u];
	rio_rq w;
	uint32_t c1, c2, c3;

	p.max_ops = 5;
	p.ctl_ops = 2; /* three data slots */
	if (rio_open(&B, &p) != 0 || rio_image(&B, 0, "ctl", 1u << 20, 12, 1) == NULL) {
		WRT_CHECK(0);
		return;
	}
	rio_pattern(buf, sizeof(buf), 4);
	sim_osd_faults(osd0())->hold_replies = 1;
	WRT_CHECK(rio_go(&B, 0, &w, WR_IO_WRITE, 0, sizeof(buf), buf, 0));
	(void)rio_run(&B);
	WRT_CHECK(B.g.o.n_inflight == 3u);                        /* the data operations took the three data slots and no more */
	/* the open machine's two control slots are still there, and the next data operation is refused until an answer comes */
	c1 = wri_osdc_alloc(&B.g.o, 1);
	c2 = wri_osdc_alloc(&B.g.o, 1);
	c3 = wri_osdc_alloc(&B.g.o, 1);
	WRT_CHECK(c1 != WRI_NIL && c2 != WRI_NIL && c3 == WRI_NIL);
	wri_osdc_release(&B.g.o, c1);
	wri_osdc_release(&B.g.o, c2);
	drain_all();
	WRT_CHECK(w.done && w.st == WR_OK && rio_idle(&B));
	rio_close(&B);
}

int main(void)
{
	test_64mib_through_one_slot();
	test_byte_budget();
	test_max_reqs_busy();
	test_zombie_takes_an_entry();
	test_fairness_one_slot();
	test_fairness_quantum();
	test_cut_budget();
	test_control_reserve_untouched();
	return wrt_finish();
}
