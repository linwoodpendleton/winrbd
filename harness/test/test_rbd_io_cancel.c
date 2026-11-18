/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_io_cancel.c - every way a request ends without all its answers (design 25.5, 25.7): the host's cancel of a read and of a write in every state
 * (waiting, cut but not sent, sent, reply landing in the buffer, partly cut), the timeout, the zombie that keeps its range and goes when the cluster answered
 * it, the case in which the zombie area has no room (WR_E_BUSY: the request ends by itself), late answers of requests that are gone, the close of an image
 * (DRAIN and ABANDON), and the statuses of OSD errors (first failure wins, a missing object, blocklisted).
 */
#include "rbd_io_rig.h"

static rbio B;

#define ORDER 12u
#define OBJ (1u << ORDER)
#define IMG_SIZE (32u * OBJ)

static uint8_t model[IMG_SIZE];
static uint8_t bufs[4][16u * OBJ];
static uint8_t big[16u * OBJ];

static sim_osd *osd0(void) { return B.g.w.osd[0]; }
static uint32_t sent(void) { return sim_osd_n_requests(osd0()); }
static void hold(int on) { sim_osd_faults(osd0())->hold_replies = (uint8_t)on; }

static int open_one(const rio_params *p)
{
	if (rio_open(&B, p) != 0 || rio_image(&B, 0, "img0", IMG_SIZE, ORDER, 1) == NULL) {
		WRT_CHECK(0);
		return 0;
	}
	memset(model, 0, sizeof(model));
	return 1;
}

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

static void release(uint32_t n)
{
	(void)rio_run(&B);
	(void)sim_osd_release(osd0(), n);
	(void)rio_run(&B);
}

/* Release every held reply until nothing is held any more (a released reply may admit a request whose reply is held in its turn). */
static void drain_all(void)
{
	int i;

	for (i = 0; i < 40; i++) {
		release(0);
		if (sim_osd_n_held(osd0()) == 0)
			break;
	}
}

/* A write request of `len` bytes of pattern `seed` at `off`; the model takes it (what the cluster ends up with, if it is applied whole). */
static void wput(rio_rq *x, uint64_t off, uint64_t len, unsigned buf, uint32_t timeout_ms)
{
	rio_pattern(bufs[buf], (size_t)len, buf + 200u);
	memcpy(model + off, bufs[buf], (size_t)len);
	WRT_CHECK(rio_go(&B, 0, x, WR_IO_WRITE, off, len, bufs[buf], timeout_ms));
}

static void check_image(void)
{
	static uint8_t st[IMG_SIZE];

	WRT_CHECK(rio_store_read(&B, 0, 0, st, IMG_SIZE));
	WRT_CHECK_MEM(st, model, IMG_SIZE);
}

/* ---- the host's cancel ------------------------------------------------------------------------------------------------------- */

static void test_cancel_arguments(void)
{
	rio_params p = rio_defaults();
	rio_rq x, y;

	if (!open_one(&p))
		return;
	rio_fill_req(&x, WR_IO_READ, 0, 10, bufs[0], 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_cancel(NULL, 0, &x.q));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_cancel(&B.r, 0, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_cancel(&B.r, 5, &x.q));
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 0, &x.q));  /* never submitted */
	WRT_CHECK_STATUS(WR_OK, rio_submit(&B, 0, &x));
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 1, &x.q));  /* another image's slot */
	/* a copy of the structure is not the request */
	y = x;
	y.q.user = NULL;
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 0, &y.q));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &x.q));
	/* cancelled and finished, not pulled yet: not "in flight" any more */
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 0, &x.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && x.done && x.st == WR_E_CANCELLED);
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 0, &x.q));  /* pulled */
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_cancel_waiting(void)
{
	rio_params p = rio_defaults();
	rio_rq w, w2, w3, r;

	if (!open_one(&p))
		return;
	hold(1);
	wput(&w, 0, 100, 0, 0);
	(void)rio_run(&B);
	/* w2 waits behind w; w3 behind w2; a read behind both */
	rio_pattern(bufs[1], 100, 1);
	WRT_CHECK(rio_go(&B, 0, &w2, WR_IO_WRITE, 50, 100, bufs[1], 0));
	wput(&w3, 120, 100, 2, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 130, 10, bufs[3], 0));
	(void)rio_run(&B);
	WRT_CHECK(rq_state(&w2) == WRI_RQ_WAIT && rq_state(&w3) == WRI_RQ_WAIT && rq_state(&r) == WRI_RQ_WAIT);
	WRT_CHECK_U64(sent(), 1);
	/* cancelling the waiting w2 completes it at once: nothing of it was sent, and nothing is left behind */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w2.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && w2.done && w2.st == WR_E_CANCELLED);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);
	/* w3 does not overlap w: it was held by w2 only and goes now; the read waits for w3 */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 2);
	WRT_CHECK(rq_state(&r) == WRI_RQ_WAIT);
	drain_all();
	WRT_CHECK(w.done && w3.done && r.done && w.st == WR_OK && w3.st == WR_OK && r.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_cancel_cut_not_sent(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r;

	if (!open_one(&p))
		return;
	wput(&w, 0, 2u * OBJ, 0, 0);
	/* admitted and cut into operations, but the engine has not run: nothing has left */
	(void)wri_rbd_io_cut(&B.r, 64);
	WRT_CHECK(B.g.o.n_inflight == 2u && sent() == 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && w.done && w.st == WR_E_CANCELLED);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0 && B.g.o.zused == 0u); /* a write that never left is dropped: no copy, no zombie */
	memset(model, 0, 2u * OBJ);                                       /* and it is never applied */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 0);
	check_image();
	/* the same for a read */
	memset(bufs[1], 0xAA, OBJ);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, OBJ, bufs[1], 0));
	(void)wri_rbd_io_cut(&B.r, 64);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && r.st == WR_E_CANCELLED);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B) && sent() == 0);
	rio_close(&B);
}

static void test_cancel_sent_write_is_a_zombie(void)
{
	rio_params p = rio_defaults();
	rio_rq w, w2;

	if (!open_one(&p))
		return;
	hold(1);
	wput(&w, 100, 3u * OBJ, 0, 0);                      /* three objects: three operations, all sent and unanswered */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 4);                           /* (100 .. 3 OBJ + 100 touches four objects) */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && w.done && w.st == WR_E_CANCELLED);
	/* the buffer is the host's: overwrite it; the cluster must still get what was in it when it was cancelled */
	memset(bufs[0], 0xEE, sizeof(bufs[0]));
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 1 && B.g.o.n_zombies == 4u && B.g.o.zused != 0u);
	WRT_CHECK(B.r.reqs_inflight == 1);                  /* the fence entry holds a table slot */
	/* a write over it waits; a write elsewhere does not */
	{
		rio_rq other;

		rio_pattern(bufs[1], 50, 9);
		WRT_CHECK(rio_go(&B, 0, &w2, WR_IO_WRITE, OBJ, 50, bufs[1], 0));
		memcpy(model + OBJ, bufs[1], 50);
		wput(&other, 10u * OBJ, 10, 2, 0);
		(void)rio_run(&B);
		WRT_CHECK(rq_state(&w2) == WRI_RQ_WAIT && sent() == 5u);
		drain_all();
		WRT_CHECK(other.done && w2.done && w2.st == WR_OK);
	}
	/* the zombies were answered and freed without a word; the area is empty again */
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0 && B.g.o.zused == 0u && B.g.o.n_zombies_done == 4u);
	/* what the cluster applied is the content at the time of the cancel (model: the write whole, then w2 on top), not the 0xEE the host wrote after */
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_cancel_read_sent_and_midrx(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w;
	uint8_t sentinel[2u * OBJ];
	unsigned k;

	if (!open_one(&p))
		return;
	rio_pattern(bufs[0], 2u * OBJ, 5);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(B.g.w.store, W_POOL, "rbd_data.id00.0000000000000000", 0, bufs[0], OBJ));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(B.g.w.store, W_POOL, "rbd_data.id00.0000000000000001", 0, bufs[0] + OBJ, OBJ));
	memcpy(model, bufs[0], 2u * OBJ);
	/* a read in flight (reply held): the cancel drops it; the late reply lands nowhere */
	hold(1);
	memset(bufs[1], 0xAA, sizeof(bufs[1]));
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 2u * OBJ, bufs[1], 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 2);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && r.st == WR_E_CANCELLED);
	memset(bufs[1], 0xBB, sizeof(bufs[1]));
	memset(sentinel, 0xBB, sizeof(sentinel));
	release(0);
	WRT_CHECK(memcmp(bufs[1], sentinel, sizeof(sentinel)) == 0);
	WRT_CHECK(rio_idle(&B));
	hold(0);
	/* a read whose reply is landing in the buffer: the session is reset first, so no byte arrives after the cancel */
	memset(bufs[1], 0xAA, sizeof(bufs[1]));
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, OBJ, bufs[1], 0));
	B.g.w.rx_budget_on = 1;
	B.g.w.rx_budget = 800;
	(void)rio_run(&B);
	{
		uint32_t s;
		int landing = 0;

		for (s = 0; s < B.g.o.sess.n; s++)
			landing |= B.g.o.sess.s[s].rx_tid != 0;
		WRT_CHECK(landing);
	}
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && r.st == WR_E_CANCELLED);
	memset(bufs[1], 0xCC, OBJ);
	memset(sentinel, 0xCC, OBJ);
	B.g.w.rx_budget_on = 0;
	for (k = 0; k < 8; k++)
		(void)rio_run(&B);
	WRT_CHECK(memcmp(bufs[1], sentinel, OBJ) == 0);
	/* and the layer works on: a new write and read over a new connection */
	wput(&w, 0, 100, 2, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[3], 0));
	WRT_CHECK(rio_until(&B, &r, 20000) && r.st == WR_OK);
	(void)rio_run(&B);
	WRT_CHECK(w.done && w.st == WR_OK);
	WRT_CHECK_MEM(bufs[3], model, 100);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* A request of 16 extents, one operation slot: cancelled with some answered, one on the wire and the rest uncut. */
static void test_cancel_partly_cut(void)
{
	rio_params p = rio_defaults();
	rio_rq w, again;
	unsigned i;

	p.max_ops = 3;
	p.ctl_ops = 2; /* one data slot */
	p.op_bytes_max = OBJ;
	if (!open_one(&p))
		return;
	hold(1);
	rio_pattern(big, sizeof(big), 77);
	WRT_CHECK(rio_go(&B, 0, &w, WR_IO_WRITE, 0, sizeof(big), big, 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);
	for (i = 0; i < 3; i++) {
		release(1);                      /* an answer frees the slot: the next extent is cut and sent */
		WRT_CHECK_U64(sent(), 2u + i);
	}
	WRT_CHECK(!w.done && B.r.rq[0].cur == 4u * OBJ && B.r.rq[0].ops_out == 1u);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK(rio_collect_done(&B) == 1 && w.st == WR_E_CANCELLED);
	/* extents 0 to 2 were answered, extent 3 is a zombie, extents 4 to 15 were never cut and are never sent */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 4);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 1);
	/* a retry of the whole range waits for the zombie, then goes whole */
	memcpy(model, big, 4u * OBJ);       /* what the cancelled write left: its first four extents */
	WRT_CHECK(rio_go(&B, 0, &again, WR_IO_WRITE, 0, 4u * OBJ, big, 0));
	(void)rio_run(&B);
	WRT_CHECK(rq_state(&again) == WRI_RQ_WAIT);
	drain_all();
	WRT_CHECK(again.done && again.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- WR_E_BUSY: no room for the copy --------------------------------------------------------------------------------------------- */

static void test_busy_ends_by_itself(void)
{
	rio_params p = rio_defaults();
	rio_rq a, b;

	p.zombie_bytes = 1024; /* room for one 800-byte write (with its context), not for two */
	if (!open_one(&p))
		return;
	hold(1);
	wput(&a, 0, 800, 0, 0);
	wput(&b, 5u * OBJ, 800, 1, 0);
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 2);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &a.q));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_rbd_cancel(&B.r, 0, &b.q)); /* the copy does not fit: nothing changed */
	WRT_CHECK(rio_collect_done(&B) == 1 && a.done && !b.done);
	WRT_CHECK(rq_state(&b) == WRI_RQ_RUN && B.g.o.zused != 0u);
	/* the host keeps b's buffer until the completion is pulled; the first answer frees the area and b is cancelled by itself */
	release(1);
	WRT_CHECK(b.done && b.st == WR_E_CANCELLED);
	WRT_CHECK_STATUS(WR_E_STATE, wri_rbd_cancel(&B.r, 0, &b.q));
	drain_all();
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0 && B.g.o.zused == 0u);
	check_image(); /* both writes were applied: the cancel never un-writes */
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_busy_answer_wins(void)
{
	rio_params p = rio_defaults();
	rio_rq a, b;

	p.zombie_bytes = 1024;
	if (!open_one(&p))
		return;
	hold(1);
	wput(&a, 0, 800, 0, 0);
	wput(&b, 5u * OBJ, 800, 1, 0);
	(void)rio_run(&B);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &a.q));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_rbd_cancel(&B.r, 0, &b.q));
	/* both answers come before the retry: b finishes with its own result (every extent of it was on the wire) */
	release(0);
	WRT_CHECK(a.done && a.st == WR_E_CANCELLED && b.done && b.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_busy_with_uncut_extents(void)
{
	rio_params p = rio_defaults();
	rio_rq w;

	p.max_ops = 3;
	p.ctl_ops = 2;        /* one data slot */
	p.zombie_bytes = 320; /* the copy of one extent (300 bytes, padded, and the snapshot context) needs 328: no room at all */
	if (!open_one(&p))
		return;
	hold(1);
	wput(&w, OBJ - 300, 600, 0, 0);       /* two extents of 300 bytes ... */
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 1);             /* ... one slot: the first is on the wire, the second not cut */
	WRT_CHECK_STATUS(WR_E_BUSY, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK(!w.done && B.r.rq[0].cancelling && B.r.rq[0].cur == B.r.rq[0].off + B.r.rq[0].len); /* no more is cut */
	/* the answer comes: the request ends, but not with success: half of it was never sent */
	release(0);
	WRT_CHECK(w.done && w.st == WR_E_CANCELLED);
	WRT_CHECK_U64(sent(), 1);
	memset(model + OBJ, 0, 300);          /* the cluster has the first extent only */
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* One extent of the request is on the wire (its copy does not fit the zombie area), the other is cut but was never sent: the cancel drops the second and cannot
 * touch the first. When the first is answered the request must not end with success: the second extent never reached the cluster and never will. */
static void test_busy_with_dropped_extent(void)
{
	rio_params p = rio_defaults();
	rio_rq w;
	int i;

	p.max_ops = 4;
	p.ctl_ops = 2;        /* two data slots */
	p.zombie_bytes = 320; /* the copy of one extent (300 bytes and the snapshot context) needs 328: no room */
	if (!open_one(&p))
		return;
	hold(1);
	wput(&w, OBJ - 300, 600, 0, 0);
	(void)wri_rbd_io_cut(&B.r, 1); /* the first extent only: the engine takes it (admission and cutting are the layer's, the sending is the engine's) */
	for (i = 0; i < 200 && sent() == 0; i++) {
		(void)w_pump(&B.g.w);
		(void)wri_osdc_step(&B.g.o, 64);
		B.g.w.e.x.now.mono_ms += 1;
	}
	WRT_CHECK_U64(sent(), 1);
	(void)wri_rbd_io_cut(&B.r, 1); /* the second one: cut, in the engine's table, not sent */
	WRT_CHECK(B.r.rq[0].ops_out == 2 && B.r.rq[0].cur == B.r.rq[0].off + B.r.rq[0].len);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK(B.r.rq[0].cancelling && B.r.rq[0].status == WR_E_CANCELLED);
	release(0);
	WRT_CHECK(w.done && w.st == WR_E_CANCELLED);
	WRT_CHECK_U64(sent(), 1);
	memset(model + OBJ, 0, 300);          /* the cluster has the first extent only */
	check_image();
	drain_all();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* The operations of the request wait for the map or for a session: not sent, so dropped by the cancel, write or read. */
static void tweak_no_map(rig *g) { g->m.epoch = 0; }

static void test_cancel_waiting_for_map_and_session(void)
{
	rio_params p = rio_defaults();
	rio_rq w, r;

	p.tweak = tweak_no_map;
	if (!open_one(&p))
		return;
	wput(&w, 0, 100, 0, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 5u * OBJ, 100, bufs[1], 0));
	(void)rio_run(&B);
	WRT_CHECK(B.g.o.n_inflight == 2u && sent() == 0 && B.g.o.op[0].state != WRI_OP_SENT);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r.q));
	WRT_CHECK(rio_collect_done(&B) == 2u && w.st == WR_E_CANCELLED && r.st == WR_E_CANCELLED);
	(void)rio_run(&B);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0 && B.g.o.zused == 0u && rio_idle(&B));
	memset(model, 0, 100); /* the write was never sent */
	/* the map arrives, but the OSD refuses connections: the operations wait for a session */
	B.g.m.epoch = 10;
	B.g.w.osd_down[0] = 1;
	wput(&w, 0, 100, 0, 0);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 5u * OBJ, 100, bufs[1], 0));
	rio_tick(&B, 500);
	WRT_CHECK(B.g.o.n_inflight == 2u && sent() == 0);
	{
		uint32_t i, waiting = 0;

		for (i = 0; i < B.g.o.n_op; i++)
			waiting += B.g.o.op[i].state == WRI_OP_WAIT_SESS ? 1u : 0u;
		WRT_CHECK(waiting == 2u);
	}
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &w.q));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r.q));
	WRT_CHECK(rio_collect_done(&B) == 2u && w.st == WR_E_CANCELLED && r.st == WR_E_CANCELLED);
	memset(model, 0, 100);
	/* the OSD is back: the next request goes through (after the cool-down) */
	B.g.w.osd_down[0] = 0;
	wput(&w, 0, 100, 2, 0);
	WRT_CHECK(rio_until(&B, &w, 60000) && w.st == WR_OK);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- timeouts ----------------------------------------------------------------------------------------------------------------- */

static void tweak_silent(rig *g) { g->w.ocfg[0].fault.silent = 1; }

static void test_timeouts_with_a_silent_osd(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w;
	uint8_t sentinel[OBJ];

	p.tweak = tweak_silent;
	if (!open_one(&p))
		return;
	memset(bufs[1], 0xAA, OBJ);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, OBJ, bufs[1], 2000));
	wput(&w, 8u * OBJ, 100, 0, 2000);
	rio_tick(&B, 1900);
	WRT_CHECK(!r.done && !w.done);
	rio_tick(&B, 200);
	/* both ended at the request's deadline, long before the engine's own 5 s: the read is dropped, the write is a zombie */
	WRT_CHECK(r.done && r.st == WR_E_TIMEOUT && w.done && w.st == WR_E_TIMEOUT);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 1);
	memset(bufs[1], 0xDD, OBJ);
	memset(sentinel, 0xDD, OBJ);
	/* the OSD wakes up: the zombie is answered, the layer is quiet */
	sim_osd_faults(osd0())->silent = 0;
	rio_tick(&B, 12000);
	WRT_CHECK(memcmp(bufs[1], sentinel, OBJ) == 0);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_late_answer_of_a_gone_request(void)
{
	rio_params p = rio_defaults();
	rio_rq r1, r2;
	wri_rbd_rqpriv pv;

	if (!open_one(&p))
		return;
	rio_pattern(bufs[0], OBJ, 4);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(B.g.w.store, W_POOL, "rbd_data.id00.0000000000000000", 0, bufs[0], OBJ));
	memcpy(model, bufs[0], OBJ);
	hold(1);
	memset(bufs[1], 0, OBJ);
	WRT_CHECK(rio_go(&B, 0, &r1, WR_IO_READ, 0, OBJ, bufs[1], 0));
	(void)rio_run(&B);
	/* cancel and pull; the engine's completion of the dropped op is in its done ring, not yet looked at */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_cancel(&B.r, 0, &r1.q));
	WRT_CHECK(B.g.o.done_len == 1u);
	WRT_CHECK(rio_collect_done(&B) == 1 && r1.st == WR_E_CANCELLED);
	/* the slot is free again and a new request takes it (same slot, next generation) before the stale completion is collected */
	memset(bufs[2], 0x11, OBJ);
	WRT_CHECK(rio_go(&B, 0, &r2, WR_IO_READ, OBJ, 100, bufs[2], 0));
	WRT_CHECK(B.g.o.done_len == 1u);
	(void)wri_rbd_io_cut(&B.r, 64);                 /* the new request is running with one operation out */
	memcpy(&pv, r2.q.priv, sizeof(pv));
	WRT_CHECK(B.r.rq[pv.slot].gen == pv.gen && pv.gen != 0 && rq_state(&r2) == WRI_RQ_RUN && B.r.rq[pv.slot].ops_out == 1u);
	WRT_CHECK(wri_rbd_io_collect(&B.r) == 1u);      /* the stale answer meets the new request: it must change nothing of it */
	WRT_CHECK(rq_state(&r2) == WRI_RQ_RUN && !r2.done && B.r.rq[pv.slot].ops_out == 1u && B.r.rq[pv.slot].status == WR_OK);
	drain_all();
	WRT_CHECK(r2.done && r2.st == WR_OK);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* ---- the close of an image ----------------------------------------------------------------------------------------------------- */

static void test_close_drain(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w1, w2, f;
	wri_rbd_img *im;

	if (!open_one(&p))
		return;
	im = &B.r.img[0];
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[3], 0));
	wput(&w1, 5u * OBJ, 100, 0, 0);
	wput(&w2, 50, 100, 1, 0);                   /* overlaps the read: waits for it */
	WRT_CHECK(rio_go(&B, 0, &f, WR_IO_FLUSH, 0, 0, NULL, 0));
	(void)rio_run(&B);
	WRT_CHECK(im->n_writes_unfinished == 2u && im->n_reqs == 4u);
	im->state = (uint8_t)WR_IMG_CLOSING;
	im->close_flags = WR_CLOSE_DRAIN;
	wri_rbd_io_fail_image(&B.r, 0, WR_E_RBD_CLOSED, WR_CLOSE_DRAIN);
	/* the read is over, the writes (and the flush behind them) are not */
	WRT_CHECK(rio_collect_done(&B) == 1 && r.done && r.st == WR_E_RBD_CLOSED);
	WRT_CHECK(!w1.done && !w2.done && !f.done && im->n_writes_unfinished == 2u);
	{
		rio_rq late;

		rio_fill_req(&late, WR_IO_READ, 0, 1, bufs[3], 0);
		WRT_CHECK_STATUS(WR_E_RBD_CLOSED, rio_submit(&B, 0, &late)); /* nothing new is accepted */
	}
	drain_all();
	WRT_CHECK(w1.done && w2.done && f.done && w1.st == WR_OK && w2.st == WR_OK && f.st == WR_OK);
	WRT_CHECK(im->n_writes_unfinished == 0u && im->n_reqs == 0u);
	check_image();
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_close_abandon(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w1, w2, w3, f;
	wri_rbd_img *im;
	rio_rq fresh;
	uint32_t i, n = 0, mutating = 0;

	if (!open_one(&p))
		return;
	im = &B.r.img[0];
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 5u * OBJ, 100, bufs[3], 0));
	wput(&w1, 0, 100, 0, 0);                    /* sent, unanswered */
	wput(&w2, 50, 100, 1, 0);                   /* waits for w1 */
	wput(&w3, 5u * OBJ, 10, 2, 0);              /* waits for the read */
	WRT_CHECK(rio_go(&B, 0, &f, WR_IO_FLUSH, 0, 0, NULL, 0));
	(void)rio_run(&B);
	WRT_CHECK_U64(sent(), 2);
	im->state = (uint8_t)WR_IMG_CLOSING;
	wri_rbd_io_fail_image(&B.r, 0, WR_E_CANCELLED, WR_CLOSE_ABANDON);
	/* everything is over at once; only the engine still carries w1 and the read's late answer */
	WRT_CHECK(rio_collect_done(&B) == 5u);
	WRT_CHECK(r.st == WR_E_CANCELLED && w1.st == WR_E_CANCELLED && w2.st == WR_E_CANCELLED && w3.st == WR_E_CANCELLED && f.st == WR_E_CANCELLED);
	WRT_CHECK(B.r.reqs_inflight == 0 && im->n_reqs == 0 && im->n_writes_unfinished == 0);
	WRT_CHECK(count_state(WRI_RQ_ZOMBIE) == 0);  /* the fence went with the image */
	WRT_CHECK(B.g.o.n_zombies == 1u);            /* w1 is the engine's now */
	/* the slot is reused by another image (generation + 1): its writes over the same range are not held by the old zombie */
	im->state = (uint8_t)WR_IMG_FREE;
	im->gen = (uint16_t)(im->gen + 1u);
	im->state = (uint8_t)WR_IMG_OPEN; /* (the slot of another image: the same objects here, which is what makes the point) */
	rio_pattern(bufs[3], 100, 33);
	WRT_CHECK(rio_go(&B, 0, &fresh, WR_IO_WRITE, 0, 100, bufs[3], 0));
	(void)rio_run(&B);
	WRT_CHECK(rq_state(&fresh) == WRI_RQ_RUN && sent() == 3u);
	release(0);
	WRT_CHECK(fresh.done && fresh.st == WR_OK);
	WRT_CHECK(B.g.o.zused == 0u && B.g.o.n_zombies_done == 1u);
	/* the cluster executed w1 (old image's bytes) then the new image's write on top */
	{
		const sim_osd_rec *rec = sim_osd_recs(osd0(), &n);

		for (i = 0; i < n; i++)
			mutating += rec[i].mutating ? 1u : 0u;
		WRT_CHECK(mutating == 2u);
	}
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

static void test_close_abandon_failed_image_statuses(void)
{
	rio_params p = rio_defaults();
	rio_rq r, w;

	if (!open_one(&p))
		return;
	hold(1);
	WRT_CHECK(rio_go(&B, 0, &r, WR_IO_READ, 0, 100, bufs[3], 0));
	wput(&w, 5u * OBJ, 100, 0, 0);
	(void)rio_run(&B);
	B.r.img[0].state = (uint8_t)WR_IMG_FAILED;
	wri_rbd_io_fail_image(&B.r, 0, WR_E_OSD_BLOCKLISTED, WR_CLOSE_ABANDON);
	WRT_CHECK(rio_collect_done(&B) == 2u && r.st == WR_E_OSD_BLOCKLISTED && w.st == WR_E_OSD_BLOCKLISTED);
	release(0);
	WRT_CHECK(rio_idle(&B));
	/* a call for an image that has no requests, or no such image, does nothing */
	wri_rbd_io_fail_image(&B.r, 0, WR_E_CANCELLED, WR_CLOSE_ABANDON);
	wri_rbd_io_fail_image(&B.r, 99, WR_E_CANCELLED, WR_CLOSE_DRAIN);
	wri_rbd_io_fail_image(NULL, 0, WR_E_CANCELLED, WR_CLOSE_DRAIN);
	rio_close(&B);
}

/* ---- OSD errors ----------------------------------------------------------------------------------------------------------------- */

static void test_osd_errors(void)
{
	rio_params p = rio_defaults();
	rio_rq x;
	sim_osd_fault *f;
	uint32_t img = 99;
	wr_status st = WR_OK;

	if (!open_one(&p))
		return;
	f = sim_osd_faults(osd0());
	/* a read of three objects fails with the first error, every extent answered with it */
	f->force_errno_op = (int32_t)WRI_OSD_OP_READ;
	f->force_errno = -WRI_ERRNO_EIO;
	memset(bufs[1], 0, 3u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, 0, 3u * OBJ, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_IO);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B));
	/* a forced ENOENT on a read is the missing object: zeros and success, the buffer is filled */
	f->force_errno = -WRI_ERRNO_ENOENT;
	memset(bufs[1], 0xAA, 3u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, 0, 3u * OBJ, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	{
		static const uint8_t zero[3u * OBJ];

		WRT_CHECK_MEM(bufs[1], zero, 3u * OBJ);
	}
	/* writes: EIO and ENOSPC map to their statuses; ENOENT of a write is a failure (it is only a hole for reads and removals) */
	f->force_errno_op = (int32_t)WRI_OSD_OP_WRITE;
	f->force_errno = -WRI_ERRNO_EIO;
	rio_pattern(bufs[2], 2u * OBJ, 6);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, OBJ / 2u, 2u * OBJ, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_IO);
	f->force_errno = -WRI_ERRNO_ENOSPC;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, OBJ, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_NOSPC);
	f->force_errno = -WRI_ERRNO_ENOENT;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, OBJ, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_NOENT);
	/* removals of what is not there are fine */
	f->force_errno_op = (int32_t)WRI_OSD_OP_DELETE;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_DISCARD, 0, 2u * OBJ, NULL, 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	f->force_errno_op = (int32_t)WRI_OSD_OP_ZERO;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE_ZEROES, 10, 20, NULL, 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	WRT_CHECK(!wri_rbd_io_take_fatal(&B.r, &img, &st) && img == 99);
	/* blocklisted: the request fails with it and the layer says the image is lost (once) */
	f->force_errno_op = (int32_t)WRI_OSD_OP_WRITE;
	f->force_errno = -WRI_ERRNO_EBLOCKLISTED;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, 100, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_BLOCKLISTED);
	WRT_CHECK(wri_rbd_io_take_fatal(&B.r, &img, &st) && img == 0 && st == WR_E_OSD_BLOCKLISTED);
	WRT_CHECK(!wri_rbd_io_take_fatal(&B.r, &img, &st));
	WRT_CHECK(!wri_rbd_io_take_fatal(NULL, &img, &st));
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

/* An answer that is not what its message result alone says: a redirect reply carries -ENOENT in its result, -EOPNOTSUPP of a data operation is an error and
 * not "no such object". Neither may read as a hole (zeros, success): the host would be handed zeros for data that exists. */
static void test_not_a_hole(void)
{
	rio_params p = rio_defaults();
	rio_rq x;
	sim_osd_fault *f;
	static const uint8_t zero[3u * OBJ];

	if (!open_one(&p))
		return;
	f = sim_osd_faults(osd0());
	rio_pattern(bufs[2], 3u * OBJ, 9);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE, 0, 3u * OBJ, bufs[2], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_OK);
	/* redirect: a read fails, and its buffer is not filled with zeros */
	f->redirect = 1;
	memset(bufs[1], 0xAA, 3u * OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, 0, 3u * OBJ, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_REDIRECT);
	WRT_CHECK(memcmp(bufs[1], zero, 3u * OBJ) != 0);
	/* the removals fail too (their -ENOENT is only success when it is the answer of the object store) */
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_DISCARD, 0, 2u * OBJ, NULL, 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_REDIRECT);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_WRITE_ZEROES, 10, 20, NULL, 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_REDIRECT);
	f->redirect = 0;
	/* -EOPNOTSUPP of a data operation: an OSD error, not a missing object */
	f->force_errno_op = (int32_t)WRI_OSD_OP_READ;
	f->force_errno = -WRI_ERRNO_EOPNOTSUPP;
	memset(bufs[1], 0xAA, OBJ);
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_READ, 0, OBJ, bufs[1], 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_ERRNO);
	f->force_errno_op = (int32_t)WRI_OSD_OP_DELETE;
	WRT_CHECK(rio_go(&B, 0, &x, WR_IO_DISCARD, 0, OBJ, NULL, 0));
	WRT_CHECK(rio_until(&B, &x, 20000) && x.st == WR_E_OSD_ERRNO);
	f->force_errno_op = 0;
	f->force_errno = 0;
	/* the data is still there, and the layer is quiet */
	WRT_CHECK(rio_store_read(&B, 0, 0, bufs[3], 3u * OBJ));
	WRT_CHECK_MEM(bufs[3], bufs[2], 3u * OBJ);
	(void)rio_run(&B);
	WRT_CHECK(rio_idle(&B));
	rio_close(&B);
}

int main(void)
{
	test_cancel_arguments();
	test_cancel_waiting();
	test_cancel_cut_not_sent();
	test_cancel_sent_write_is_a_zombie();
	test_cancel_read_sent_and_midrx();
	test_cancel_partly_cut();
	test_cancel_waiting_for_map_and_session();
	test_busy_ends_by_itself();
	test_busy_answer_wins();
	test_busy_with_uncut_extents();
	test_busy_with_dropped_extent();
	test_timeouts_with_a_silent_osd();
	test_late_answer_of_a_gone_request();
	test_close_drain();
	test_close_abandon();
	test_close_abandon_failed_image_statuses();
	test_osd_errors();
	test_not_a_hole();
	return wrt_finish();
}
