/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_open_err.c - everything that goes wrong around the open, and close: the checks of wri_rbd_open_start; a missing image, a missing header, a
 * key without class-read (EPERM), a blocklisted answer, an OSD without the rbd class; the pool rules (a pool tracked after the first map, one that does
 * not exist: failed at the full map and not at the timeout, a pool tracked before the first map, a pool that leaves the map during the open or
 * after it); open_timeout_ms with the step in errinfo.what; an id and a prefix that are not valid; the truncation sweep of the header outputs (every
 * length, every hostile record); close of an image that is opening, open, failed, with writes in flight (DRAIN waits, ABANDON does not).
 */
#include "rbd_open_rig.h"

static orig O;

static int start_open_failed(orig *o, uint32_t slot, wr_status st)
{
	wri_rbd_img *m = oimg(o, slot);

	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED);
	WRT_CHECK_STATUS(st, m->err.status);
	WRT_CHECK(m->err.module == WR_MOD_RBD && m->err.what != NULL);
	WRT_CHECK(m->ctl_op == WRI_NIL && !m->was_open);
	WRT_CHECK(orig_count_ev(o, WR_EV_IMAGE, slot) >= 1u);
	return m->state == (uint8_t)WR_IMG_FAILED && m->err.status == st;
}

/* ---- wri_rbd_open_start ------------------------------------------------------------------------------------------------------- */

static void test_start_args(void)
{
	wr_image_params p = oparams(OR_META, "x", NULL, 0);
	char longname[128], longid[128];
	uint32_t slot = 77;
	unsigned i;
	orig_cfg cfg = orig_cfg_default();

	cfg.max_images = 2;
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(NULL, &O.pools, &p, &slot));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, NULL, &p, &slot));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, NULL, &slot));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, &p, NULL));
	p.size = 4;
	WRT_CHECK_STATUS(WR_E_ABI, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(NULL, "x", NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams("", "x", NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, NULL, NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, "", NULL, 0);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, "x", NULL, 0);
	p.snap_id = 5;
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	/* lengths: an image name of 87 bytes is the longest ("rbd_id." + name must fit 95 bytes), 88 is refused */
	for (i = 0; i < 100; i++)
		longname[i] = 'n';
	longname[87] = '\0';
	p = oparams(OR_META, longname, NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	WRT_CHECK(slot == 0u && strlen(oimg(&O, 0)->name) == 87u);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, 0, WR_CLOSE_DRAIN));
	longname[87] = 'n';
	longname[88] = '\0';
	p = oparams(OR_META, longname, NULL, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	/* an id: 63 alphanumeric bytes at most; not alphanumeric is a bad id, an empty one too */
	for (i = 0; i < 100; i++)
		longid[i] = (char)('a' + (int)(i % 26u));
	longid[63] = '\0';
	p = oparams(OR_META, NULL, longid, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	longid[63] = 'x';
	longid[64] = '\0';
	p = oparams(OR_META, NULL, longid, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, NULL, "ab-c", 0);
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, NULL, "ab/c", 0);
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, NULL, "", 0);
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	/* the track call fails (image pool, data pool): nothing is taken */
	p = oparams("bad", "x", NULL, 0);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	p = oparams(OR_META, "x", NULL, 0);
	p.data_pool = "bad";
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	WRT_CHECK(oimg(&O, 0)->state == (uint8_t)WR_IMG_FREE && oimg(&O, 1)->state == (uint8_t)WR_IMG_FREE);
	/* every slot taken */
	p = oparams(OR_META, "x", NULL, 0);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	WRT_CHECK(slot == 1u);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_rbd_open_start(&O.L, &O.pools, &p, &slot));
	/* close arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_close(&O.L, 5, 0));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_close(&O.L, 0, 2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_close(NULL, 0, 0));
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, 0, WR_CLOSE_ABANDON));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_close(&O.L, 0, 0)); /* already closed */
	orig_close(&O);
}

/* ---- what the cluster answers ------------------------------------------------------------------------------------------------- */

static void test_missing(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-m", "6666666666");
	wr_image_params p = oparams(OR_META, "no-such-image", NULL, 0);
	uint32_t slot;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_RBD_NOT_FOUND)) {
		WRT_CHECK(oimg(&O, slot)->err.peer_result == -2 && oimg(&O, slot)->err.a0 == (uint64_t)WRI_ROS_GET_ID);
		WRT_CHECK(rig_nrec(&O.r, 0) == 1u); /* only the id object was asked */
	}
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
	/* the id object exists but the header is gone (by name and by id) */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	WRT_CHECK_STATUS(WR_OK, sim_store_remove(O.r.w.store, W_POOL, "rbd_header.6666666666"));
	p = oparams(OR_META, "img-m", NULL, 1);
	slot = orig_start(&O, &p, WR_OK);
	p = oparams(OR_META, NULL, "6666666666", 0);
	(void)orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_RBD_NOT_FOUND))
		WRT_CHECK(oimg(&O, slot)->err.a0 == (uint64_t)WRI_ROS_HEADER);
	start_open_failed(&O, 1, WR_E_RBD_NOT_FOUND);
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

static void fault_open(int32_t code, int32_t errno_v, wr_status want, int want_peer)
{
	sim_rbd_image_cfg c = oimg_cfg("img-x", "8888888888");
	wr_image_params p = oparams(OR_META, "img-x", NULL, 1);
	uint32_t slot;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = code;
	sim_osd_faults(O.r.w.osd[0])->force_errno = errno_v;
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, want))
		WRT_CHECK(oimg(&O, slot)->err.peer_result == want_peer);
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

static void test_errno_answers(void)
{
	fault_open(WRI_OSD_OP_CALL, -1, WR_E_OSD_PERM, -1);       /* the key has no class-read capability: EPERM */
	fault_open(WRI_OSD_OP_CALL, -108, WR_E_OSD_BLOCKLISTED, -108); /* this client is on the cluster's blocklist */
	fault_open(WRI_OSD_OP_CALL, -95, WR_E_OSD_NOENT, -95);   /* no rbd class / method (EOPNOTSUPP on a CALL) */
	fault_open(WRI_OSD_OP_CALL, -5, WR_E_OSD_IO, -5);
	fault_open(WRI_OSD_OP_CALL, -28, WR_E_OSD_NOSPC, -28);
	fault_open(WRI_OSD_OP_CALL, -61, WR_E_OSD_ERRNO, -61);
}

/* ---- pools and the map ---------------------------------------------------------------------------------------------------------- */

static void test_pool_after_first_map(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-d", "d1d1d1d1d1");
	wr_image_params p = oparams(OR_META, "img-d", NULL, 1);
	wri_rbd_img *m;
	uint32_t slot;

	c.features = 0xa1;
	c.data_pool = W_POOL + 1;
	p.data_pool = OR_DATA;
	/* the data pool is tracked after the first map: it reads as absent until the full map the engine asks for is adopted */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	O.r.m.pool[1].present = 0;
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	WRT_CHECK(m->full_need == O.n_full + 1u);
	(void)orig_settle(&O);
	orig_tick(&O, 20000);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING && m->ros == (uint8_t)WRI_ROS_POOLS && rig_nrec(&O.r, 0) == 0u); /* waiting, no I/O, no failure */
	O.r.m.pool[1].present = 1; /* the full map arrives and has the pool */
	O.n_full++;
	(void)orig_settle(&O);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->data_pool_id == W_POOL + 1);
	orig_close(&O);
	/* a pool that does not exist: still waiting before the full map, failed AT the full map, long before open_timeout_ms */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	O.r.m.pool[1].present = 0;
	p.open_timeout_ms = 60000;
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	orig_tick(&O, 10000);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING);
	O.n_full++; /* the full map is adopted, the pool is still not in it */
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND)) {
		WRT_CHECK(m->err.a0 == 1u && orig_now(&O) - O.r.t_start < 20000u); /* a0 = which pool: the data pool; 10 s of 60 */
		WRT_CHECK(orig_count_ev(&O, WR_EV_IMAGE, slot) == 1u && O.ev[0].st == WR_E_POOL_NOT_FOUND);
	}
	WRT_CHECK(rig_nrec(&O.r, 0) == 0u);
	orig_close(&O);
	/* the same for the image's own pool */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	O.r.m.pool[0].present = 0;
	p = oparams(OR_META, "x", NULL, 0);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPENING);
	O.n_full++;
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND))
		WRT_CHECK(oimg(&O, slot)->err.a0 == 0u);
	orig_close(&O);
}

/* A pool that an earlier open already tracked and that is absent: tracking it again asks for no new full map, so the full-map rule of the first
 * open cannot be what ends the wait. The verdict comes after map_stale_ms (the rule the engine applies to an operation that waits for a pool),
 * not at open_timeout_ms and not never. */
static void test_pool_retrack(void)
{
	wr_image_params p = oparams(OR_META, "x", NULL, 0);
	wri_rbd_img *m;
	uint32_t slot;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	O.r.m.pool[0].present = 0;
	slot = orig_start(&O, &p, WR_OK);
	O.n_full++; /* the full map the track asked for: the pool is not in it */
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND))
		WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	/* the second open of the same absent pool: no full map comes, the host set no open timeout */
	p.open_timeout_ms = 0;
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	orig_tick(&O, 20000);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING && m->ros == (uint8_t)WRI_ROS_POOLS);
	orig_tick(&O, 11000);
	if (start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND))
		WRT_CHECK(m->err.a0 == 0u && rig_nrec(&O.r, 0) == 0u);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	/* and the pool shows up later in an incremental that carries it: an open that waits for it goes on (the bound only ends the wait) */
	O.r.m.pool[0].present = 1;
	{
		sim_rbd_image_cfg c = oimg_cfg("x", "7a7a7a7a7a");

		oimg_make(&O, &c);
	}
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
	orig_close(&O);
}

static void test_pool_before_first_map(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-z", "2020202020");
	wr_image_params p = oparams(OR_META, "img-z", NULL, 0);
	orig_cfg cfg = orig_cfg_default();
	wri_rbd_img *m;
	uint32_t slot;

	cfg.first_map_epoch = 0;
	/* no map yet: the open waits for it (no I/O); the first map has the pool: the open goes on */
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	O.r.m.epoch = 0;
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	WRT_CHECK(m->full_need == 0u);
	orig_tick(&O, 3000);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING && m->ros == (uint8_t)WRI_ROS_POOLS && rig_nrec(&O.r, 0) == 0u);
	O.r.m.epoch = 10;
	O.n_full = 1;
	(void)orig_settle(&O);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
	orig_close(&O);
	/* the first map lacks the pool: failed at once (the map that arrived is the full one) */
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	O.r.m.epoch = 0;
	O.r.m.pool[0].present = 0;
	slot = orig_start(&O, &p, WR_OK);
	orig_tick(&O, 1000);
	O.r.m.epoch = 10;
	O.n_full = 1;
	(void)orig_settle(&O);
	(void)start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND);
	orig_close(&O);
	/* a table without the n_full hook: absent means absent */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	O.pools.n_full = NULL;
	O.r.m.pool[0].present = 0;
	slot = orig_start(&O, &p, WR_OK);
	WRT_CHECK(oimg(&O, slot)->full_need == 0u);
	(void)orig_settle(&O);
	(void)start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND);
	orig_close(&O);
}

static void test_pool_leaves(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-l", "1717171717");
	wr_image_params p = oparams(OR_META, "img-l", NULL, 0);
	uint32_t slot;

	/* during the open (the header read is held by the OSD) and after it, for a reader and for a writer */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPENING && oimg(&O, slot)->ctl_op != WRI_NIL);
	O.r.m.pool[0].present = 0;
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_POOL_NOT_FOUND))
		WRT_CHECK(oimg(&O, slot)->err.a0 == 0u);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	WRT_CHECK(orig_ctl_idle(&O)); /* the cancelled read's slot was reaped; the late reply found nothing */
	orig_close(&O);
	{
		unsigned w;

		for (w = 0; w < 2; w++) {
			if (orig_open(&O, NULL) != 0) {
				WRT_CHECK(0);
				return;
			}
			oimg_make(&O, &c);
			p = oparams(OR_META, "img-l", NULL, (int)w);
			slot = orig_start(&O, &p, WR_OK);
			(void)orig_settle(&O);
			WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
			O.r.m.pool[0].present = 0;
			(void)orig_settle(&O);
			WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_FAILED && oimg(&O, slot)->err.status == WR_E_POOL_NOT_FOUND);
			WRT_CHECK(oimg(&O, slot)->was_open == 1u && orig_count_ev(&O, WR_EV_IMAGE, slot) == 2u);
			orig_close(&O);
			/* made again under another id */
			if (orig_open(&O, NULL) != 0) {
				WRT_CHECK(0);
				return;
			}
			oimg_make(&O, &c);
			slot = orig_start(&O, &p, WR_OK);
			(void)orig_settle(&O);
			WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
			O.r.m.pool[0].id += 100;
			(void)orig_settle(&O);
			WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_FAILED && oimg(&O, slot)->err.status == WR_E_POOL_NOT_FOUND);
			orig_close(&O);
		}
	}
}

/* ---- open_timeout_ms ------------------------------------------------------------------------------------------------------------- */

static void test_timeouts(void)
{
	wr_image_params p = oparams(OR_META, "img-t", NULL, 1);
	orig_cfg cfg = orig_cfg_default();
	wri_rbd_img *m;
	uint32_t slot;

	p.open_timeout_ms = 2000;
	/* no map ever */
	cfg.first_map_epoch = 0;
	if (orig_open(&O, &cfg) != 0) {
		WRT_CHECK(0);
		return;
	}
	O.r.m.epoch = 0;
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	orig_tick(&O, 1900);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING);
	orig_tick(&O, 200);
	if (start_open_failed(&O, slot, WR_E_TIMEOUT))
		WRT_CHECK(m->err.a0 == (uint64_t)WRI_ROS_POOLS && strstr(m->err.what, "map") != NULL);
	orig_close(&O);
	/* a silent OSD: the id lookup, the header read, the extra read */
	{
		unsigned step;

		for (step = 0; step < 3; step++) {
			sim_rbd_image_cfg d = oimg_cfg("img-t", "3030303030");
			wr_image_params q = oparams(OR_META, step == 0 ? "img-t" : NULL, step == 0 ? NULL : "3030303030", 1);
			wri_ros want = step == 0 ? WRI_ROS_GET_ID : step == 1 ? WRI_ROS_HEADER : WRI_ROS_EXTRA;
			unsigned guard;

			if (orig_open(&O, NULL) != 0) {
				WRT_CHECK(0);
				return;
			}
			if (step == 2) {
				d.features = 0x23;
				d.stripe_unit = 1ull << 22;
				d.stripe_count = 1;
			}
			oimg_make(&O, &d);
			q.open_timeout_ms = 2000;
			if (step == 0 || step == 1)
				sim_osd_faults(O.r.w.osd[0])->silent = 1;
			slot = orig_start(&O, &q, WR_OK);
			m = oimg(&O, slot);
			for (guard = 0; step == 2 && guard < 200 && m->ros != (uint8_t)WRI_ROS_EXTRA; guard++)
				(void)orig_pass(&O);
			if (step == 2) {
				WRT_CHECK(m->ros == (uint8_t)WRI_ROS_EXTRA);
				sim_osd_faults(O.r.w.osd[0])->silent = 1;
			}
			(void)orig_settle(&O);
			orig_tick(&O, 1800);
			WRT_CHECK(m->state == (uint8_t)WR_IMG_OPENING);
			orig_tick(&O, 300);
			if (start_open_failed(&O, slot, WR_E_TIMEOUT))
				WRT_CHECK(m->err.a0 == (uint64_t)want);
			(void)orig_settle(&O);
			WRT_CHECK(orig_ctl_idle(&O)); /* the read in flight was cancelled and its slot given back */
			sim_osd_faults(O.r.w.osd[0])->silent = 0;
			orig_close(&O);
		}
	}
}

/* ---- ids and prefixes that are not valid ----------------------------------------------------------------------------------------- */

static void test_bad_ids(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-b", "a-b");
	wr_image_params p = oparams(OR_META, "img-b", NULL, 0);
	uint32_t slot;
	char prefix[96];

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c); /* get_id answers "a-b": not alphanumeric */
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	(void)start_open_failed(&O, slot, WR_E_RBD_BAD_ID);
	orig_close(&O);
	/* prefixes: 78 bytes is the longest, 79 is refused */
	memset(prefix, 'p', sizeof(prefix));
	prefix[78] = '\0';
	c = oimg_cfg("img-b", "b1b1b1b1b1");
	c.prefix = prefix;
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN && strlen(oimg(&O, slot)->prefix) == 78u);
	orig_close(&O);
	prefix[78] = 'p';
	prefix[79] = '\0';
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	(void)start_open_failed(&O, slot, WR_E_RBD_BAD_ID);
	orig_close(&O);
}

/* ---- the header outputs: every length, every hostile record -------------------------------------------------------------------- */

typedef struct capture {
	wri_osd_opd ops[8];
	uint8_t out[4096];
	uint32_t out_len;
} capture;

/* One real header read of an image of the sim, as the engine delivered it (a copy of the operation records and the reply data). */
static int capture_header(orig *o, const char *id, capture *cap)
{
	uint8_t in[WRI_RBD_CTL_IN];
	char oid[96];
	uint32_t idx = wri_osdc_alloc(&o->r.o, 1);
	wri_osd_op *op;
	wri_wr w;
	unsigned i;
	wr_status st;

	if (idx == WRI_NIL)
		return 0;
	op = wri_osdc_at(&o->r.o, idx);
	snprintf(oid, sizeof(oid), "rbd_header.%s", id);
	op->kind = WRI_OPK_READ;
	op->pool = 0;
	op->oid_len = (uint8_t)strlen(oid);
	memcpy(op->oid, oid, strlen(oid));
	op->owner = 0xfeed0000u;
	wri_wr_init(&w, in, sizeof(in));
	st = wri_rbd_put_get_size(&w, &op->ops[0], WRI_SNAP_NOSNAP);
	if (st == WR_OK)
		st = wri_rbd_put_get_object_prefix(&w, &op->ops[1]);
	if (st == WR_OK)
		st = wri_rbd_put_get_features(&w, &op->ops[2], WRI_SNAP_NOSNAP, 0);
	if (st == WR_OK)
		st = wri_rbd_put_get_flags(&w, &op->ops[3], WRI_SNAP_NOSNAP);
	if (st == WR_OK)
		st = wri_rbd_put_get_snapcontext(&w, &op->ops[4]);
	if (st == WR_OK)
		st = wri_rbd_put_get_data_pool(&w, &op->ops[5]);
	if (st == WR_OK)
		st = wri_rbd_put_parent_get(&w, &op->ops[6]);
	if (st == WR_OK)
		st = wri_rbd_put_parent_overlap_get(&w, &op->ops[7], WRI_SNAP_NOSNAP);
	WRT_CHECK_STATUS(WR_OK, st);
	op->n_ops = 8;
	op->data = in;
	op->data_len = (uint32_t)wri_wr_len(&w);
	op->out = cap->out;
	op->out_cap = sizeof(cap->out);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&o->r.o, idx));
	/* the I/O half pops it and leaves it DONE (control reserve) */
	for (i = 0; i < 100 && op->state != WRI_OP_DONE; i++)
		(void)orig_pass(o);
	for (i = 0; i < 100 && (op->flags & WRI_OPF_INRING) != 0; i++)
		(void)orig_pass(o);
	if (op->state != WRI_OP_DONE || op->status != WR_OK) {
		WRT_CHECK(0);
		return 0;
	}
	memcpy(cap->ops, op->ops, sizeof(cap->ops));
	cap->out_len = op->out_stored;
	wri_osdc_release(&o->r.o, idx);
	return 1;
}

static void test_decode_sweep(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-w", "f1f1f1f1f1f1");
	capture cap;
	wri_rbd_hdr h;
	uint64_t snaps[8];
	wri_snapc sc;
	uint32_t total = 0, len, k;
	unsigned i;
	uint8_t *buf;
	wri_osd_opd ops[8];

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	c.features = 0xa1;
	c.data_pool = W_POOL + 1;
	c.size = 12345ull << 12;
	c.snap_seq = 40;
	c.n_snaps = 3;
	c.snaps[0] = 40;
	c.snaps[1] = 30;
	c.snaps[2] = 7;
	oimg_make(&O, &c);
	if (!capture_header(&O, "f1f1f1f1f1f1", &cap)) {
		orig_close(&O);
		return;
	}
	memset(&sc, 0, sizeof(sc));
	sc.snaps = snaps;
	sc.cap = 8;
	/* the whole read decodes */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_header(cap.ops, 8, cap.out, cap.out_len, &h, &sc, &total));
	WRT_CHECK(h.order == 22u && h.size == (12345ull << 12) && h.features == 0xa1u && h.flags == 0u && h.data_pool_id == W_POOL + 1);
	WRT_CHECK(strcmp(h.prefix, "rbd_data.2.f1f1f1f1f1f1") == 0 && !h.has_parent && !h.has_overlap && h.overlap == 0u);
	WRT_CHECK(sc.seq == 40u && sc.n == 3u && sc.snaps[0] == 40u && sc.snaps[1] == 30u && sc.snaps[2] == 7u && total == 3u);
	/* without a context to fill: the rest alone */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_header(cap.ops, 8, cap.out, cap.out_len, &h, NULL, NULL));
	memset(&sc, 0, sizeof(sc));
	sc.snaps = snaps;
	sc.cap = 8;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_snapc(cap.ops, 8, cap.out, cap.out_len, &sc, &total));
	WRT_CHECK(sc.seq == 40u && sc.n == 3u);
	sc.cap = 2; /* more snapshots than the profile holds */
	WRT_CHECK_STATUS(WR_E_RBD_SNAPC, wri_rbd_open_decode_snapc(cap.ops, 8, cap.out, cap.out_len, &sc, &total));
	WRT_CHECK(total == 3u && sc.n == 0u && sc.seq == 0u);
	sc.cap = 8;
	/* argument checks */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_decode_header(cap.ops, 8, cap.out, cap.out_len, NULL, &sc, &total));
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(NULL, 8, cap.out, cap.out_len, &h, &sc, &total));
	WRT_CHECK(h.data_pool_id == -1 && h.size == 0u && h.prefix[0] == '\0'); /* cleared on a failure */
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(cap.ops, 7, cap.out, cap.out_len, &h, &sc, &total));
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(cap.ops, 9, cap.out, cap.out_len, &h, &sc, &total));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_decode_snapc(cap.ops, 8, cap.out, cap.out_len, NULL, &total));

	/* every length: the bytes of the reply cut at k (the operations cut the same way) never decode; the buffer is exactly k bytes (ASan sees a read past it) */
	for (len = 0; len < cap.out_len; len++) {
		uint32_t left = len;

		memcpy(ops, cap.ops, sizeof(ops));
		for (k = 0; k < 8; k++) {
			uint32_t take = left < ops[k].out_len ? left : ops[k].out_len;

			ops[k].out_len = take;
			left -= take;
		}
		buf = (uint8_t *)malloc(len != 0 ? len : 1);
		memcpy(buf, cap.out, len);
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(ops, 8, buf, len, &h, &sc, &total));
		WRT_CHECK(h.size == 0u && h.data_pool_id == -1 && sc.n == 0u);
		/* the same bytes with the operations unchanged (the lengths do not add up) */
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(cap.ops, 8, buf, len, &h, &sc, &total));
		free(buf);
	}
	/* more bytes than the records say */
	buf = (uint8_t *)malloc(cap.out_len + 1u);
	memcpy(buf, cap.out, cap.out_len);
	buf[cap.out_len] = 0;
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_header(cap.ops, 8, buf, cap.out_len + 1u, &h, &sc, &total));
	free(buf);
	/* every operation answered an error: that error is the status (the first one wins), the rest of the reply is not looked at */
	for (i = 0; i < 8; i++) {
		memcpy(ops, cap.ops, sizeof(ops));
		ops[i].rval = -2;
		ops[(i + 3u) % 8u].rval = -5;
		if ((i + 3u) % 8u < i)
			WRT_CHECK_STATUS(WR_E_OSD_IO, wri_rbd_open_decode_header(ops, 8, cap.out, cap.out_len, &h, &sc, &total));
		else
			WRT_CHECK_STATUS(WR_E_OSD_NOENT, wri_rbd_open_decode_header(ops, 8, cap.out, cap.out_len, &h, &sc, &total));
	}
	/* a positive rval is a success value (method specific) */
	memcpy(ops, cap.ops, sizeof(ops));
	ops[1].rval = 7;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_header(ops, 8, cap.out, cap.out_len, &h, &sc, &total));
	/* every single byte flipped to the worst value: the decoders may refuse or accept, they must not read out of bounds or run away */
	buf = (uint8_t *)malloc(cap.out_len);
	for (k = 0; k < cap.out_len; k++) {
		unsigned v;

		for (v = 0; v < 3; v++) {
			wr_status st;

			memcpy(buf, cap.out, cap.out_len);
			buf[k] = v == 0 ? 0x00 : v == 1 ? 0xff : (uint8_t)(buf[k] ^ 0x80u);
			st = wri_rbd_open_decode_header(cap.ops, 8, buf, cap.out_len, &h, &sc, &total);
			WRT_CHECK(st == WR_OK || st == WR_E_RBD_PROTO || st == WR_E_RBD_BAD_ID || st == WR_E_RBD_SNAPC);
		}
	}
	free(buf);
	orig_close(&O);
}

static void test_decode_extra(void)
{
	wri_rbd_hdr h;
	wri_osd_opd ops[2];
	uint8_t out[24], *buf;
	uint32_t len;

	memset(&h, 0, sizeof(h));
	memset(ops, 0, sizeof(ops));
	memset(out, 0, sizeof(out));
	wri_le64_put(out, 1ull << 22);
	wri_le64_put(out + 8, 1);
	wri_le64_put(out + 16, 0x2);
	h.features = 0x2 | 0x100;
	ops[0].out_len = 16;
	ops[1].out_len = 8;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_extra(ops, 2, out, 24, &h));
	WRT_CHECK(h.stripe_unit == (1ull << 22) && h.stripe_count == 1u && h.op_features == 2u);
	/* only the stripe read, only the op features read */
	h.features = 0x2;
	ops[0].out_len = 16;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_extra(ops, 1, out, 16, &h));
	WRT_CHECK(h.op_features == 0u && h.stripe_count == 1u);
	h.features = 0x100;
	ops[0].out_len = 8;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_open_decode_extra(ops, 1, out + 16, 8, &h));
	WRT_CHECK(h.op_features == 2u && h.stripe_unit == 0u && h.stripe_count == 0u);
	/* the number of operations must be what the feature bits ask for */
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_extra(ops, 2, out, 24, &h));
	WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_extra(ops, 0, out, 0, &h));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_rbd_open_decode_extra(ops, 1, out + 16, 8, NULL));
	/* every length */
	h.features = 0x2 | 0x100;
	for (len = 0; len < 24; len++) {
		buf = (uint8_t *)malloc(len != 0 ? len : 1);
		memcpy(buf, out, len);
		ops[0].out_len = len < 16 ? len : 16;
		ops[1].out_len = len < 16 ? 0 : len - 16;
		WRT_CHECK_STATUS(WR_E_RBD_PROTO, wri_rbd_open_decode_extra(ops, 2, buf, len, &h));
		free(buf);
	}
	ops[0].rval = -61;
	ops[0].out_len = 16;
	ops[1].out_len = 8;
	WRT_CHECK_STATUS(WR_E_OSD_ERRNO, wri_rbd_open_decode_extra(ops, 2, out, 24, &h));
}

/* ---- the control reserve and the contract with the engine's done ring -------------------------------------------------------------- */

/* The op table is full (other operations hold every slot): the control read is not a failure, it waits and looks again soon (no busy loop), a writer's
 * refresh waits its turn the same way, and everything goes on when slots are free again. */
#define HOG_MAX 64u
static unsigned hog_slots(orig *o, uint32_t *hog)
{
	unsigned n = 0;

	while (n < HOG_MAX && (hog[n] = wri_osdc_alloc(&o->r.o, 1)) != WRI_NIL)
		n++;
	return n;
}

static void hog_free(orig *o, const uint32_t *hog, unsigned n)
{
	unsigned i;

	for (i = 0; i < n; i++)
		wri_osdc_release(&o->r.o, hog[i]);
}

static void test_ctl_reserve(void)
{
	static const char *const ids[2] = {"c0c0c0c0c0c0", "c1c1c1c1c1c1"};
	static const char *const names[2] = {"img-c0", "img-c1"};
	uint32_t hog[HOG_MAX], slot[2];
	unsigned i, nh;
	uint64_t dl;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	nh = hog_slots(&O, hog);
	WRT_CHECK(nh > 0u && nh < HOG_MAX);
	for (i = 0; i < 2; i++) {
		sim_rbd_image_cfg c = oimg_cfg(names[i], ids[i]);
		wr_image_params p = oparams(OR_META, NULL, ids[i], 1);

		oimg_make(&O, &c);
		slot[i] = orig_start(&O, &p, WR_OK);
	}
	orig_tick(&O, 400);
	for (i = 0; i < 2; i++) {
		WRT_CHECK(oimg(&O, slot[i])->state == (uint8_t)WR_IMG_OPENING && oimg(&O, slot[i])->err.status == WR_OK);
		WRT_CHECK(oimg(&O, slot[i])->ctl_op == WRI_NIL && oimg(&O, slot[i])->ros == (uint8_t)WRI_ROS_HEADER);
	}
	WRT_CHECK(rig_nrec(&O.r, 0) == 0u);
	dl = WR_DEADLINE_NONE;
	(void)wri_rbd_open_step(&O.L, &dl);
	WRT_CHECK(dl <= orig_now(&O) + 50u && dl > orig_now(&O)); /* the machine asks to be run again soon, not at once */
	hog_free(&O, hog, nh);
	orig_tick(&O, 300);
	for (i = 0; i < 2; i++)
		WRT_CHECK(oimg(&O, slot[i])->state == (uint8_t)WR_IMG_OPEN);
	WRT_CHECK(orig_ctl_idle(&O));
	/* the refresh of a writer is due and finds no slot: it stays due (the gate stays shut) and goes when a slot is free */
	nh = hog_slots(&O, hog);
	orig_tick(&O, 1500);
	for (i = 0; i < 2; i++) {
		wri_rbd_img *m = oimg(&O, slot[i]);

		WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->err.status == WR_OK && m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op == WRI_NIL);
		WRT_CHECK(wri_rio_gate_closed(&O.L, m));
	}
	hog_free(&O, hog, nh);
	orig_tick(&O, 300);
	for (i = 0; i < 2; i++) {
		wri_rbd_img *m = oimg(&O, slot[i]);

		WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->ros == (uint8_t)WRI_ROS_READY && !wri_rio_gate_closed(&O.L, m));
		WRT_CHECK(orig_nrec_oid(&O, i == 0u ? "rbd_header.c0c0c0c0c0c0" : "rbd_header.c1c1c1c1c1c1") == 2u);
	}
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

/* A control read that cannot be submitted for good (not for want of a slot) fails the image with the engine's status and says where. */
static void test_submit_refused(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-s", "5d5d5d5d5d5d");
	wr_image_params p = oparams(OR_META, "img-s", NULL, 1);
	uint32_t slot;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	O.r.w.e.x.cfg.inflight_bytes_max = 64; /* the read alone (its output buffer) is above the byte budget: it could never be admitted */
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	if (start_open_failed(&O, slot, WR_E_TOOBIG))
		WRT_CHECK(strstr(oimg(&O, slot)->err.what, "could not be submitted") != NULL && oimg(&O, slot)->err.a0 == (uint64_t)WRI_ROS_GET_ID);
	WRT_CHECK(orig_ctl_idle(&O) && rig_nrec(&O.r, 0) == 0u);
	orig_close(&O);
	/* a budget that is only used up for the moment is not a failure: the read waits and goes when the bytes are free */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	O.r.w.e.x.cfg.inflight_bytes_max = 6000;
	O.r.o.inflight_bytes = 4000; /* what other operations hold */
	slot = orig_start(&O, &p, WR_OK);
	orig_tick(&O, 300);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPENING && oimg(&O, slot)->ctl_op == WRI_NIL && rig_nrec(&O.r, 0) == 0u);
	O.r.o.inflight_bytes = 0;
	orig_tick(&O, 300);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
	orig_close(&O);
}

/* The machine and the I/O half share the done ring by a contract: the I/O half pops a control read and leaves it DONE, the open machine releases it. */
static void test_done_contract(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-q", "6e6e6e6e6e6e");
	wr_image_params p = oparams(OR_META, "img-q", NULL, 1);
	wr_errinfo why;
	wri_rbd_img *m;
	uint32_t slot, idx;
	uint64_t dl = WR_DEADLINE_NONE;

	/* the read is finished and still in the ring when the image is closed: the release is ignored then, the reaper frees it after the pop */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	(void)wri_rbd_open_step(&O.L, &dl);
	WRT_CHECK(m->ctl_op != WRI_NIL);
	idx = m->ctl_op;
	{
		int i;

		for (i = 0; i < 50 && O.r.o.op[idx].state != WRI_OP_DONE; i++) {
			(void)w_pump(&O.r.w);
			(void)wri_osdc_step(&O.r.o, 64);
		}
	}
	WRT_CHECK(O.r.o.op[idx].state == WRI_OP_DONE && (O.r.o.op[idx].flags & WRI_OPF_INRING) != 0u);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && m->ctl_op == WRI_NIL);
	WRT_CHECK(O.r.o.op[idx].state == WRI_OP_DONE && O.r.o.n_ctl_used == 1u); /* still there: it is in the ring */
	(void)orig_settle(&O);
	WRT_CHECK(orig_ctl_idle(&O)); /* popped by the I/O half, released by the reaper */
	/* the same, with the read popped already (DONE, not in the ring): released at once */
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	(void)wri_rbd_open_step(&O.L, &dl);
	idx = m->ctl_op;
	{
		int i;

		for (i = 0; i < 50 && O.r.o.op[idx].state != WRI_OP_DONE; i++) {
			(void)w_pump(&O.r.w);
			(void)wri_osdc_step(&O.r.o, 64);
		}
	}
	WRT_CHECK(wri_osdc_pop_done(&O.r.o) == idx);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_ABANDON));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && O.r.o.op[idx].state == WRI_OP_FREE && orig_ctl_idle(&O));
	/* a host that releases the read behind the machine's back (the contract is broken): the image fails, it does not read another operation's slot */
	slot = orig_start(&O, &p, WR_OK);
	m = oimg(&O, slot);
	(void)wri_rbd_open_step(&O.L, &dl);
	idx = m->ctl_op;
	{
		int i;

		for (i = 0; i < 50 && O.r.o.op[idx].state != WRI_OP_DONE; i++) {
			(void)w_pump(&O.r.w);
			(void)wri_osdc_step(&O.r.o, 64);
		}
	}
	WRT_CHECK(wri_osdc_pop_done(&O.r.o) == idx);
	wri_osdc_release(&O.r.o, idx);
	(void)wri_rbd_open_step(&O.L, &dl);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->err.status == WR_E_STATE && m->ctl_op == WRI_NIL && m->err.what != NULL);
	WRT_CHECK(orig_ctl_idle(&O));
	/* a failure reported for an image that is not there, or twice, and a NULL reason */
	memset(&why, 0, sizeof(why));
	wri_rbd_img_fail(&O.L, 99u, &why);
	wri_rbd_img_fail(NULL, 0, &why);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	slot = orig_start(&O, &p, WR_OK);
	wri_rbd_img_fail(&O.L, slot, NULL);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_FAILED && oimg(&O, slot)->err.status == WR_E_STATE && oimg(&O, slot)->err.what != NULL);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	orig_close(&O);
}

/* ---- close ---------------------------------------------------------------------------------------------------------------------- */

static wr_io_req wreq(uint64_t off, uint32_t len, uint8_t *buf, void *user)
{
	wr_io_req q;

	memset(&q, 0, sizeof(q));
	q.kind = WR_IO_WRITE;
	q.offset = off;
	q.length = len;
	q.buf = buf;
	q.user = user;
	return q;
}

static void test_close(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-k", "4b4b4b4b4b");
	wr_image_params p = oparams(OR_META, "img-k", NULL, 1);
	static uint8_t data[8192];
	wr_io_req rq[3];
	uint32_t slot;
	wri_rbd_img *m;
	unsigned i, got;

	memset(data, 0x5a, sizeof(data));
	/* an image that is still opening: gone at once, its read cancelled, the slot comes back with another generation */
	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	m = oimg(&O, slot);
	WRT_CHECK(m->ctl_op != WRI_NIL);
	{
		uint16_t gen = m->gen;

		WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
		WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && m->gen != gen && m->ctl_op == WRI_NIL && m->id[0] == '\0' && m->snapc.n == 0u);
		WRT_CHECK(m->snapc.cap == 8u && m->snapc.snaps != NULL && m->ctl_in != NULL && m->ctl_out != NULL); /* the arena pointers stay */
		WRT_CHECK(orig_count_ev(&O, WR_EV_IMAGE, slot) == 1u);
		sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
		(void)sim_osd_release(O.r.w.osd[0], 0);
		(void)orig_settle(&O);
		WRT_CHECK(orig_ctl_idle(&O));
		/* the same slot opens the image again; the old reply did nothing */
		slot = orig_start(&O, &p, WR_OK);
		(void)orig_settle(&O);
		WRT_CHECK(slot == 0u && m->state == (uint8_t)WR_IMG_OPEN && m->gen != gen);
	}
	/* an open image without requests: DRAIN frees it at once */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && orig_count_ev(&O, WR_EV_IMAGE, slot) == 3u);
	/* writes in flight: DRAIN keeps the image CLOSING until they are answered, new requests are refused; the slot is freed by the step */
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	m = oimg(&O, slot);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
	for (i = 0; i < 3; i++) {
		rq[i] = wreq((uint64_t)i << 22, 4096, data, NULL);
		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, slot, &rq[i]));
	}
	WRT_CHECK(m->n_reqs == 3u && m->n_writes_unfinished == 3u);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	(void)orig_settle(&O);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_CLOSING && m->close_flags == WR_CLOSE_DRAIN);
	{
		wr_io_req late = wreq(0, 4096, data, NULL);

		WRT_CHECK_STATUS(WR_E_RBD_CLOSED, wri_rbd_submit(&O.L, slot, &late));
	}
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN)); /* again: nothing */
	(void)orig_settle(&O);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_CLOSING);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && orig_count_ev(&O, WR_EV_IMAGE, slot) == 5u);
	for (got = 0; wri_rbd_next_done(&O.L) != NULL; got++)
		;
	WRT_CHECK(got == 3u);
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_OK, rq[i].status); /* the writes finished with their real answers */
	{
		uint8_t back[4096];

		WRT_CHECK(rig_store_read(&O.r, "rbd_data.4b4b4b4b4b.0000000000000001", 0, back, sizeof(back)) == 1 && back[0] == 0x5a && back[4095] == 0x5a);
	}
	/* ABANDON: gone at once, the requests complete with a cancel; the write that was sent continues and reaches the store */
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	m = oimg(&O, slot);
	for (i = 0; i < 3; i++) {
		rq[i] = wreq(((uint64_t)i + 10u) << 22, 4096, data, NULL);
		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, slot, &rq[i]));
	}
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	(void)orig_settle(&O);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_ABANDON));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && orig_count_ev(&O, WR_EV_IMAGE, slot) == 7u);
	for (got = 0; wri_rbd_next_done(&O.L) != NULL; got++)
		;
	WRT_CHECK(got == 3u);
	for (i = 0; i < 3; i++)
		WRT_CHECK_STATUS(WR_E_CANCELLED, rq[i].status);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	{
		uint8_t back[16];

		WRT_CHECK(rig_store_read(&O.r, "rbd_data.4b4b4b4b4b.000000000000000a", 0, back, sizeof(back)) == 1 && back[0] == 0x5a); /* not abandoned: applied */
	}
	/* DRAIN escalated to ABANDON */
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	m = oimg(&O, slot);
	rq[0] = wreq(5u << 22, 4096, data, NULL);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, slot, &rq[0]));
	(void)orig_settle(&O);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_CLOSING);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_ABANDON));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	while (wri_rbd_next_done(&O.L) != NULL)
		;
	orig_close(&O);
}

/* A failed image is closed by the host: the slot is free again and can be opened again (the problem fixed). */
static void test_failed_reopen(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-r", "5c5c5c5c5c");
	wr_image_params p = oparams(OR_META, "img-r", NULL, 1);
	static uint8_t data[4096];
	wr_io_req rq;
	uint32_t slot;
	wri_rbd_img *m;

	if (orig_open(&O, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	oimg_make(&O, &c);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	m = oimg(&O, slot);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
	/* a write answered "blocklisted" fails the image (the I/O half reports it, the step glue calls wri_rbd_img_fail) */
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_WRITE;
	sim_osd_faults(O.r.w.osd[0])->force_errno = -108;
	rq = wreq(0, 4096, data, NULL);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, slot, &rq));
	(void)orig_settle(&O);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->was_open == 1u);
	WRT_CHECK_STATUS(WR_E_OSD_BLOCKLISTED, m->err.status);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_IDLE && m->next_refresh_ms == WR_DEADLINE_NONE);
	WRT_CHECK(orig_count_ev(&O, WR_EV_IMAGE, slot) == 2u && O.ev[1].st == WR_E_OSD_BLOCKLISTED);
	WRT_CHECK(wri_rbd_next_done(&O.L) == &rq && rq.status == WR_E_OSD_BLOCKLISTED);
	{
		wr_io_req more = wreq(0, 4096, data, NULL);

		WRT_CHECK_STATUS(WR_E_RBD_CLOSED, wri_rbd_submit(&O.L, slot, &more));
	}
	/* the first failure stays: a second report changes nothing, raises nothing */
	{
		wr_errinfo why;

		memset(&why, 0, sizeof(why));
		why.status = WR_E_POOL_NOT_FOUND;
		wri_rbd_img_fail(&O.L, slot, &why);
		WRT_CHECK_STATUS(WR_E_OSD_BLOCKLISTED, m->err.status);
		WRT_CHECK(orig_count_ev(&O, WR_EV_IMAGE, slot) == 2u);
	}
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = 0;
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, slot, WR_CLOSE_DRAIN));
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && m->err.status == WR_OK);
	slot = orig_start(&O, &p, WR_OK);
	(void)orig_settle(&O);
	WRT_CHECK(oimg(&O, slot)->state == (uint8_t)WR_IMG_OPEN);
	orig_close(&O);
}

int main(void)
{
	test_start_args();
	test_missing();
	test_errno_answers();
	test_pool_after_first_map();
	test_pool_retrack();
	test_pool_before_first_map();
	test_pool_leaves();
	test_timeouts();
	test_bad_ids();
	test_decode_sweep();
	test_decode_extra();
	test_ctl_reserve();
	test_submit_refused();
	test_done_contract();
	test_close();
	test_failed_reopen();
	return wrt_finish();
}
