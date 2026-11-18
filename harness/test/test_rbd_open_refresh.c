/* SPDX-License-Identifier: MIT */
/*
 * test_rbd_open_refresh.c - the header refresh of a writer (design 24.4) over the real request engine, sim_osd and the I/O half's gate: the timer
 * (every hdr_refresh_ms, never for a reader or with hdr_refresh_ms 0), the atomic adoption (a new snapshot context, a resize with its event), the
 * failures (a feature enabled behind our back, a context with too many snapshots, a pool in pool-snapshot mode, a blocklisted or missing header)
 * that leave the image FAILED without adopting anything, transient failures that do not, writes held while the header is stale (the first write
 * after an idle period waits for one header read, and carries the fresh context), and wri_rbd_open_refresh_now (the -EOLDSNAPC path).
 */
#include "rbd_open_rig.h"

static orig O;
static const char *const ID = "6d6d6d6d6d6d";
static const char *const HDR = "rbd_header.6d6d6d6d6d6d";
static uint8_t g_data[4096];

static sim_rbd_image_cfg image(void)
{
	sim_rbd_image_cfg c = oimg_cfg("img-h", ID);

	c.snap_seq = 5;
	c.n_snaps = 1;
	c.snaps[0] = 5;
	return c;
}

/* An open writer (slot 0) of the image above; 0 = ok. */
static int open_writer(const orig_cfg *cfg, int writer)
{
	sim_rbd_image_cfg c = image();
	wr_image_params p = oparams(OR_META, NULL, ID, writer);
	wri_rbd_img *m;

	if (orig_open(&O, cfg) != 0) {
		WRT_CHECK(0);
		return -1;
	}
	oimg_make(&O, &c);
	WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
	(void)orig_settle(&O);
	m = oimg(&O, 0);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->writable == (writer ? 1u : 0u));
	return m->state == (uint8_t)WR_IMG_OPEN ? 0 : -1;
}

static wr_io_req wr(uint64_t off, uint32_t len)
{
	wr_io_req q;

	memset(&q, 0, sizeof(q));
	q.kind = WR_IO_WRITE;
	q.offset = off;
	q.length = len;
	q.buf = g_data;
	return q;
}

/* Header reads and data writes the OSD has seen, in order: the position of the n-th record that is a header read (-1 = none) / a write (-1). */
static int rec_pos(int want_write, unsigned nth)
{
	uint32_t i, n = rig_nrec(&O.r, 0);
	unsigned seen = 0;

	for (i = 0; i < n; i++) {
		const sim_osd_rec *r = rig_rec(&O.r, 0, i);
		int is_hdr = strcmp(r->oid, HDR) == 0;

		if (want_write ? (r->n_ops == 1u && r->op_code[0] == WRI_OSD_OP_WRITE) : is_hdr) {
			if (seen++ == nth)
				return (int)i;
		}
	}
	return -1;
}

static unsigned n_hdr(void) { return orig_nrec_oid(&O, HDR); }

/* ---- the timer ---------------------------------------------------------------------------------------------------------------- */

static void test_timer(void)
{
	wri_rbd_img *m;
	uint64_t t0;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	t0 = m->refreshed_ms;
	WRT_CHECK(n_hdr() == 1u && m->next_refresh_ms == t0 + 1000u && !wri_rio_gate_closed(&O.L, m));
	orig_tick(&O, 900);
	WRT_CHECK(n_hdr() == 1u && m->ros == (uint8_t)WRI_ROS_READY && !wri_rio_gate_closed(&O.L, m));
	orig_tick(&O, 200); /* 1100 ms after the open: one refresh */
	WRT_CHECK(n_hdr() == 2u && m->ros == (uint8_t)WRI_ROS_READY && m->ctl_op == WRI_NIL);
	WRT_CHECK(m->refreshed_ms >= t0 + 1000u && m->refreshed_ms <= t0 + 1100u && m->next_refresh_ms == m->refreshed_ms + 1000u);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && O.n_img_ev == 1u); /* nothing changed: no event */
	WRT_CHECK(orig_ctl_idle(&O));
	orig_tick(&O, 5000);
	WRT_CHECK(n_hdr() >= 6u && n_hdr() <= 7u); /* about once a second */
	/* the refresh is the writer's profile read: eight calls, no extra */
	{
		const sim_osd_rec *r = rig_rec(&O.r, 0, (uint32_t)rec_pos(0, 1));

		WRT_CHECK(r != NULL && r->n_ops == 8u && !r->mutating && (r->flags & WRI_OSDF_READ) != 0);
	}
	orig_close(&O);
	/* a reader refreshes nothing; neither does a writer with hdr_refresh_ms 0 */
	if (open_writer(NULL, 0) != 0)
		return;
	m = oimg(&O, 0);
	WRT_CHECK(m->next_refresh_ms == WR_DEADLINE_NONE);
	orig_tick(&O, 10000);
	WRT_CHECK(n_hdr() == 1u && m->ros == (uint8_t)WRI_ROS_READY);
	wri_rbd_open_refresh_now(&O.L, 0); /* a reader: ignored */
	(void)orig_settle(&O);
	WRT_CHECK(n_hdr() == 1u && m->ros == (uint8_t)WRI_ROS_READY);
	orig_close(&O);
	{
		orig_cfg cfg = orig_cfg_default();

		cfg.hdr_refresh_ms = 0;
		if (open_writer(&cfg, 1) != 0)
			return;
		m = oimg(&O, 0);
		WRT_CHECK(m->next_refresh_ms == WR_DEADLINE_NONE);
		orig_tick(&O, 100000);
		WRT_CHECK(n_hdr() == 1u && !wri_rio_gate_closed(&O.L, m));
		/* it can still be asked for (the -EOLDSNAPC path): one read, adopted, and no timer afterwards */
		{
			uint64_t snaps[2] = {8, 5};

			WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 8, snaps, 2));
			wri_rbd_open_refresh_now(&O.L, 0);
			(void)orig_settle(&O);
			WRT_CHECK(n_hdr() == 2u && m->snapc.seq == 8u && m->snapc.n == 2u && m->ros == (uint8_t)WRI_ROS_READY);
			WRT_CHECK(m->next_refresh_ms == WR_DEADLINE_NONE && !wri_rio_gate_closed(&O.L, m));
			orig_tick(&O, 20000);
			WRT_CHECK(n_hdr() == 2u);
		}
		orig_close(&O);
	}
}

/* ---- adoption ------------------------------------------------------------------------------------------------------------------- */

static void test_adopt(void)
{
	wri_rbd_img *m;
	uint64_t snaps[3] = {12, 9, 5};
	const uint64_t *arr;
	unsigned ev;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	arr = m->snapc.snaps;
	WRT_CHECK(m->snapc.seq == 5u && m->snapc.n == 1u && m->size == (64ull << 20));
	ev = O.n_img_ev;
	/* a snapshot appears: the next refresh adopts the context (same array, nothing else changes, no event) */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 12, snaps, 3));
	orig_tick(&O, 1100);
	WRT_CHECK(m->snapc.seq == 12u && m->snapc.n == 3u && m->snapc.snaps == arr && arr[0] == 12u && arr[1] == 9u && arr[2] == 5u);
	WRT_CHECK(m->size == (64ull << 20) && O.n_img_ev == ev && m->state == (uint8_t)WR_IMG_OPEN);
	/* the last one is deleted again: the context shrinks (the seq stays high) */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 12, snaps, 2));
	orig_tick(&O, 1100);
	WRT_CHECK(m->snapc.seq == 12u && m->snapc.n == 2u && m->snapc.snaps[1] == 9u);
	/* a resize: adopted, and WR_EV_IMAGE tells (twice for two changes, once per change) */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(O.r.w.store, W_POOL, ID, 128ull << 20));
	orig_tick(&O, 1100);
	WRT_CHECK(m->size == (128ull << 20) && O.n_img_ev == ev + 1u && O.ev[O.n_ev - 1u].kind == WR_EV_IMAGE && O.ev[O.n_ev - 1u].st == WR_OK);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->err.status == WR_OK);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(O.r.w.store, W_POOL, ID, 32ull << 20));
	orig_tick(&O, 1100);
	WRT_CHECK(m->size == (32ull << 20) && O.n_img_ev == ev + 2u);
	/* the new size bounds the requests: a write beyond it is out of range */
	{
		wr_io_req q = wr(32ull << 20, 4096);

		WRT_CHECK_STATUS(WR_E_RANGE, wri_rbd_submit(&O.L, 0, &q));
	}
	orig_close(&O);
}

/* ---- failures: nothing is adopted ----------------------------------------------------------------------------------------------- */

static void failed_refresh(wr_status st, uint64_t a0)
{
	wri_rbd_img *m = oimg(&O, 0);

	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->was_open == 1u);
	WRT_CHECK_STATUS(st, m->err.status);
	WRT_CHECK(m->err.module == WR_MOD_RBD && m->err.what != NULL);
	if (a0 != (uint64_t)-1)
		WRT_CHECK_U64(m->err.a0, a0);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_IDLE && m->next_refresh_ms == WR_DEADLINE_NONE && m->ctl_op == WRI_NIL);
	WRT_CHECK(O.n_img_ev == 2u && O.ev[O.n_ev - 1u].st == st);
	WRT_CHECK(orig_ctl_idle(&O));
}

static void test_failures(void)
{
	wri_rbd_img *m;
	uint64_t snaps[16];
	unsigned i;

	/* a feature enabled behind our back (exclusive-lock): FAILED, and the size that changed with it is NOT adopted */
	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(O.r.w.store, W_POOL, ID, 0x25));
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(O.r.w.store, W_POOL, ID, 1ull << 30));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_FEATURES, 0x4);
	WRT_CHECK(m->size == (64ull << 20) && m->features == 0x21u);
	orig_close(&O);
	/* the object map as well; and a bit nobody knows */
	if (open_writer(NULL, 1) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(O.r.w.store, W_POOL, ID, 0x21 | 0x8 | 0x10));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_FEATURES, 0x18);
	orig_close(&O);
	/* a striping bit appears (it cannot on a real cluster): the geometry we use would be wrong */
	if (open_writer(NULL, 1) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(O.r.w.store, W_POOL, ID, 0x23));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_FEATURES, 0x2);
	orig_close(&O);
	/* more snapshots than the profile holds (max_snaps = 8): FAILED, nothing else adopted */
	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	for (i = 0; i < 9; i++)
		snaps[i] = 50u - i;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 50, snaps, 9));
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(O.r.w.store, W_POOL, ID, 1ull << 30));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_SNAPC, 9);
	WRT_CHECK(m->size == (64ull << 20));
	orig_close(&O);
	/* the pool went into pool-snapshot mode */
	if (open_writer(NULL, 1) != 0)
		return;
	O.r.m.pool[0].flags = WR_POOL_F_POOL_SNAPS;
	orig_tick(&O, 1100);
	failed_refresh(WR_E_POOL_UNSUPPORTED, 0);
	orig_close(&O);
	/* the header is gone (the image was removed): not found; and the key lost its class-read, and the client was blocklisted */
	if (open_writer(NULL, 1) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, sim_store_remove(O.r.w.store, W_POOL, HDR));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_NOT_FOUND, (uint64_t)-1);
	WRT_CHECK(oimg(&O, 0)->err.peer_result == -2);
	orig_close(&O);
	{
		static const struct {
			int32_t errno_v;
			wr_status st;
		} k[] = {{-108, WR_E_OSD_BLOCKLISTED}, {-1, WR_E_OSD_PERM}, {-95, WR_E_OSD_NOENT}};

		for (i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
			if (open_writer(NULL, 1) != 0)
				return;
			sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_CALL;
			sim_osd_faults(O.r.w.osd[0])->force_errno = k[i].errno_v;
			orig_tick(&O, 1100);
			failed_refresh(k[i].st, (uint64_t)-1);
			orig_close(&O);
		}
	}
	/* the failed image's requests complete with that status */
	if (open_writer(NULL, 1) != 0)
		return;
	{
		wr_io_req q = wr(0, 4096);

		/* hold the writes: the answer to the refresh makes the image fail while this write waits behind the gate */
		O.r.w.e.x.now.mono_ms += 1500;
		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
		WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(O.r.w.store, W_POOL, ID, 0x25));
		(void)orig_settle(&O);
		WRT_CHECK(oimg(&O, 0)->state == (uint8_t)WR_IMG_FAILED);
		WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_E_RBD_FEATURES);
		WRT_CHECK(rec_pos(1, 0) == -1); /* the write never left */
	}
	orig_close(&O);
}

/* What cannot change on an image that exists: if the header says it did, the image fails (identity, a flag, a parent, the data pool). */
static void omap_put_u64(const char *key, uint64_t v)
{
	uint8_t b[8];

	wri_le64_put(b, v);
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(O.r.w.store, W_POOL, HDR, key, b, 8));
}

static void test_failures_identity(void)
{
	static const uint8_t order13[1] = {13};
	uint8_t pfx[4 + 12];
	uint8_t parent[64];
	unsigned n;

	/* the object size changed */
	if (open_writer(NULL, 1) != 0)
		return;
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(O.r.w.store, W_POOL, HDR, "order", order13, 1));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_PROTO, 13);
	WRT_CHECK(oimg(&O, 0)->order == 22u);
	orig_close(&O);
	/* the object prefix changed (another image under the same id) */
	if (open_writer(NULL, 1) != 0)
		return;
	wri_le32_put(pfx, 12);
	memcpy(pfx + 4, "rbd_data.zzz", 12);
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(O.r.w.store, W_POOL, HDR, "object_prefix", pfx, 16));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_PROTO, 22);
	WRT_CHECK(strcmp(oimg(&O, 0)->prefix, "rbd_data.6d6d6d6d6d6d") == 0);
	orig_close(&O);
	/* a flag appears (the object map was marked invalid) */
	if (open_writer(NULL, 1) != 0)
		return;
	omap_put_u64("flags", 1);
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_FLAGS, 1);
	orig_close(&O);
	/* a parent appears */
	if (open_writer(NULL, 1) != 0)
		return;
	n = 0;
	parent[n++] = 2;
	parent[n++] = 2;
	wri_le32_put(parent + n, 0);
	n += 4;
	wri_le64_put(parent + n, 1);
	n += 8;
	wri_le32_put(parent + n, 0);
	n += 4;
	wri_le32_put(parent + n, 6);
	n += 4;
	memcpy(parent + n, "parent", 6);
	n += 6;
	wri_le64_put(parent + n, 2);
	n += 8;
	parent[n++] = 1;
	wri_le64_put(parent + n, 64ull << 20);
	n += 8;
	wri_le32_put(parent + 2, (uint32_t)(n - 6u));
	WRT_CHECK_STATUS(WR_OK, sim_store_omap_set(O.r.w.store, W_POOL, HDR, "parent", parent, n));
	orig_tick(&O, 1100);
	failed_refresh(WR_E_RBD_PARENT, (uint64_t)-1);
	orig_close(&O);
	/* the data pool of an image that has one is another pool now */
	{
		sim_rbd_image_cfg c = image();
		wr_image_params p = oparams(OR_META, NULL, ID, 1);

		if (orig_open(&O, NULL) != 0) {
			WRT_CHECK(0);
			return;
		}
		c.features = 0xa1;
		c.data_pool = W_POOL + 1;
		oimg_make(&O, &c);
		p.data_pool = OR_DATA;
		WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
		(void)orig_settle(&O);
		WRT_CHECK(oimg(&O, 0)->state == (uint8_t)WR_IMG_OPEN);
		omap_put_u64("data_pool_id", W_POOL + 7);
		orig_tick(&O, 1100);
		failed_refresh(WR_E_RBD_DATA_POOL, (uint64_t)(W_POOL + 7));
		orig_close(&O);
	}
}

/* ---- transient failures do not fail the image ------------------------------------------------------------------------------------ */

static void test_transient(void)
{
	wri_rbd_img *m;
	uint64_t snaps[2] = {20, 5};

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 20, snaps, 2));
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_CALL;
	sim_osd_faults(O.r.w.osd[0])->force_errno = -5; /* EIO */
	orig_tick(&O, 1100);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->err.status == WR_OK && m->ctl_op == WRI_NIL);
	WRT_CHECK(m->snapc.seq == 5u); /* nothing adopted */
	WRT_CHECK(m->next_refresh_ms > orig_now(&O) && m->next_refresh_ms <= orig_now(&O) + 250u); /* tried again soon: a quarter of the period */
	WRT_CHECK(wri_rio_gate_closed(&O.L, m) || m->ros == (uint8_t)WRI_ROS_READY); /* writes wait while the header is older than the period */
	/* the cluster recovers: the next try adopts */
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = 0;
	orig_tick(&O, 400);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->snapc.seq == 20u && m->snapc.n == 2u && m->ros == (uint8_t)WRI_ROS_READY);
	WRT_CHECK(m->refreshed_ms >= orig_now(&O) - 300u && !wri_rio_gate_closed(&O.L, m));
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

/* The age of a header is counted from the moment its read was SUBMITTED (the answer may be as old as that), not from the answer. */
static void test_age_from_submit(void)
{
	wri_rbd_img *m;
	uint64_t t_due;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	t_due = m->next_refresh_ms;
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	orig_tick(&O, 1000); /* the refresh is submitted at t_due and the OSD holds the answer */
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL && m->refresh_start_ms == t_due);
	orig_tick(&O, 300);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_READY && m->refreshed_ms == t_due && orig_now(&O) >= t_due + 300u);
	WRT_CHECK(m->next_refresh_ms == t_due + 1000u);
	orig_close(&O);
}

/* ---- writes held while the header is stale -------------------------------------------------------------------------------------- */

static void test_gate_idle(void)
{
	wri_rbd_img *m;
	uint64_t snaps[2] = {30, 5};
	wr_io_req q;
	const sim_osd_rec *w, *h;
	int pw, ph;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	/* the image sat idle for 5 s (the clock jumped: no pass ran) and a snapshot was taken meanwhile */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 30, snaps, 2));
	O.r.w.e.x.now.mono_ms += 5000;
	WRT_CHECK(wri_rio_gate_closed(&O.L, m)); /* the last read is 5 s old: the gate is shut before the step has even run */
	q = wr(4096, 4096);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
	WRT_CHECK(m->snapc.seq == 5u);
	(void)orig_settle(&O);
	/* one header read first, then the write, and the write carries the context the read brought */
	ph = rec_pos(0, 1);
	pw = rec_pos(1, 0);
	WRT_CHECK(ph > 0 && pw > ph);
	h = rig_rec(&O.r, 0, (uint32_t)ph);
	w = rig_rec(&O.r, 0, (uint32_t)pw);
	WRT_CHECK(h != NULL && w != NULL && w->snap_seq == 30u && w->n_snaps == 2u);
	WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_OK && m->snapc.seq == 30u && n_hdr() == 2u);
	WRT_CHECK(!wri_rio_gate_closed(&O.L, m));
	/* writes that follow within the period go straight out: no header read per write */
	{
		wr_io_req q2 = wr(8192, 4096), q3 = wr(12288, 4096);

		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q2));
		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q3));
		(void)orig_settle(&O);
		WRT_CHECK(wri_rbd_next_done(&O.L) != NULL && wri_rbd_next_done(&O.L) != NULL && n_hdr() == 2u);
	}
	orig_close(&O);
}

static void test_gate_unanswered(void)
{
	wri_rbd_img *m;
	wr_io_req q;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	/* the OSD stops answering: the refresh read is in flight (resent by the engine); a write submitted now waits behind the gate */
	sim_osd_faults(O.r.w.osd[0])->silent = 1;
	orig_tick(&O, 1200);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL && wri_rio_gate_closed(&O.L, m));
	q = wr(0, 4096);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
	orig_tick(&O, 3000);
	WRT_CHECK(rec_pos(1, 0) == -1 && wri_rbd_next_done(&O.L) == NULL); /* held: nothing of it reached the OSD, it is not done */
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN);
	/* the OSD answers again: the engine's resend of the read is answered, the gate opens, the write goes */
	sim_osd_faults(O.r.w.osd[0])->silent = 0;
	orig_tick(&O, 12000);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_READY && m->ctl_op == WRI_NIL && !wri_rio_gate_closed(&O.L, m));
	WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_OK);
	WRT_CHECK(rec_pos(1, 0) > rec_pos(0, 1));
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
}

/* ---- wri_rbd_open_refresh_now (the -EOLDSNAPC path) ------------------------------------------------------------------------------ */

static void test_refresh_now(void)
{
	wri_rbd_img *m;
	uint64_t snaps[2] = {44, 5};
	wr_io_req q;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 44, snaps, 2));
	/* the age is far below the period, yet the writes wait: the image was told its context is out of date */
	wri_rbd_open_refresh_now(&O.L, 0);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op == WRI_NIL && m->next_refresh_ms == orig_now(&O) && wri_rio_gate_closed(&O.L, m));
	q = wr(0, 4096);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
	(void)orig_settle(&O);
	WRT_CHECK(n_hdr() == 2u && m->snapc.seq == 44u && m->ros == (uint8_t)WRI_ROS_READY);
	WRT_CHECK(rec_pos(1, 0) > rec_pos(0, 1)); /* the write went after the read */
	{
		const sim_osd_rec *w = rig_rec(&O.r, 0, (uint32_t)rec_pos(1, 0));

		WRT_CHECK(w != NULL && w->snap_seq == 44u && w->n_snaps == 2u);
	}
	WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_OK);
	/* told twice while the read is in flight: the read that follows is a new one (the one in flight may predate the second event) */
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
	wri_rbd_open_refresh_now(&O.L, 0);
	(void)orig_settle(&O);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL && n_hdr() == 3u);
	wri_rbd_open_refresh_now(&O.L, 0);
	WRT_CHECK(m->hdr_stale == 1u);
	sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
	(void)sim_osd_release(O.r.w.osd[0], 0);
	(void)orig_settle(&O);
	WRT_CHECK(n_hdr() == 4u && m->ros == (uint8_t)WRI_ROS_READY && m->hdr_stale == 0u && !wri_rio_gate_closed(&O.L, m));
	/* ignored for an image that is not open */
	WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, 0, WR_CLOSE_DRAIN));
	wri_rbd_open_refresh_now(&O.L, 0);
	wri_rbd_open_refresh_now(&O.L, 77);
	wri_rbd_open_refresh_now(NULL, 0);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && m->ros == (uint8_t)WRI_ROS_IDLE);
	orig_close(&O);
}

/* A refresh that was asked for (the -EOLDSNAPC path) and whose read fails is not forgotten: the image stays in REFRESH, the writes stay behind the gate
 * (the header is young, so only the pending refresh holds them), the read is tried again, and the write goes out with the context that read brings. */
static void test_refresh_now_fails(void)
{
	wri_rbd_img *m;
	uint64_t snaps[2] = {44, 5};
	wr_io_req q;
	const sim_osd_rec *w;
	int pw;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 44, snaps, 2));
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_CALL;
	sim_osd_faults(O.r.w.osd[0])->force_errno = -5; /* EIO */
	wri_rbd_open_refresh_now(&O.L, 0);
	q = wr(0, 4096);
	WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
	orig_tick(&O, 700); /* two or three failed tries, a quarter of the period apart; the header is far younger than the period */
	WRT_CHECK(n_hdr() >= 3u);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->err.status == WR_OK && m->ros == (uint8_t)WRI_ROS_REFRESH && wri_rio_gate_closed(&O.L, m));
	WRT_CHECK(m->snapc.seq == 5u && rec_pos(1, 0) == -1 && wri_rbd_next_done(&O.L) == NULL); /* nothing adopted, the write has not left */
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = 0;
	orig_tick(&O, 400);
	WRT_CHECK(m->ros == (uint8_t)WRI_ROS_READY && m->snapc.seq == 44u && !wri_rio_gate_closed(&O.L, m));
	pw = rec_pos(1, 0);
	w = pw >= 0 ? rig_rec(&O.r, 0, (uint32_t)pw) : NULL;
	WRT_CHECK(w != NULL && w->snap_seq == 44u && w->n_snaps == 2u); /* the write carries the context of the read that was adopted */
	WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_OK);
	orig_close(&O);
	/* the same with hdr_refresh_ms = 0: no period to take the retry from, and the asked-for refresh is still not dropped */
	{
		orig_cfg cfg = orig_cfg_default();

		cfg.hdr_refresh_ms = 0;
		if (open_writer(&cfg, 1) != 0)
			return;
		m = oimg(&O, 0);
		sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_CALL;
		sim_osd_faults(O.r.w.osd[0])->force_errno = -5;
		wri_rbd_open_refresh_now(&O.L, 0);
		orig_tick(&O, 1000);
		WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->ros == (uint8_t)WRI_ROS_REFRESH && wri_rio_gate_closed(&O.L, m));
		WRT_CHECK(n_hdr() >= 3u && n_hdr() <= 7u); /* retried, and not in a busy loop */
		sim_osd_faults(O.r.w.osd[0])->force_errno_op = 0;
		orig_tick(&O, 300);
		WRT_CHECK(m->ros == (uint8_t)WRI_ROS_READY && m->next_refresh_ms == WR_DEADLINE_NONE && !wri_rio_gate_closed(&O.L, m));
		orig_close(&O);
	}
}

/* A reply that never fits the control buffer (an image with very many snapshots) is a protocol error of the engine each time, and each costs the OSD
 * session: the refresh gives up after WRI_RBD_PROTO_TRIES in a row instead of resetting the session every quarter period for ever. */
static void test_refresh_oversize(void)
{
	wri_rbd_img *m;
	static uint64_t snaps[700];
	unsigned i;

	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	for (i = 0; i < 700u; i++)
		snaps[i] = 800u - i;
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 800, snaps, 700)); /* 5.6 KB of ids: above img_ctl_bytes (4096) */
	orig_tick(&O, 1100);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->err.status == WR_OK && m->ctl_fails >= 1u && m->ros == (uint8_t)WRI_ROS_REFRESH);
	orig_tick(&O, 8000);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->was_open == 1u);
	WRT_CHECK_STATUS(WR_E_OSD_PROTO, m->err.status);
	WRT_CHECK(m->err.module == WR_MOD_RBD && m->err.what != NULL && m->ctl_op == WRI_NIL && m->ros == (uint8_t)WRI_ROS_IDLE);
	WRT_CHECK(n_hdr() <= 1u + WRI_RBD_PROTO_TRIES + 1u); /* the open's read, then the tries; no more */
	WRT_CHECK(orig_ctl_idle(&O));
	orig_close(&O);
	/* a protocol error in between does not add up: the count is of consecutive ones and a good read clears it */
	if (open_writer(NULL, 1) != 0)
		return;
	m = oimg(&O, 0);
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = WRI_OSD_OP_CALL;
	sim_osd_faults(O.r.w.osd[0])->force_errno = -5;
	orig_tick(&O, 1100);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->ctl_fails == 0u); /* an EIO is not counted */
	sim_osd_faults(O.r.w.osd[0])->force_errno_op = 0;
	orig_tick(&O, 400);
	WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->ros == (uint8_t)WRI_ROS_READY && m->ctl_fails == 0u);
	orig_close(&O);
}

/* The image is closed or fails while its refresh is on the wire: the read is cancelled (the engine drops the session that is receiving into the image's buffer),
 * its slot comes back, and the slot opens again at once with nothing of the old reply in it. */
static void test_leave_in_refresh(void)
{
	wri_rbd_img *m;
	uint64_t snaps[2] = {61, 5};
	wr_image_params p = oparams(OR_META, NULL, ID, 1);
	unsigned how;

	for (how = 0; how < 2; how++) {
		if (open_writer(NULL, 1) != 0)
			return;
		m = oimg(&O, 0);
		sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
		orig_tick(&O, 1100);
		WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL);
		if (how == 0) {
			WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, 0, WR_CLOSE_DRAIN));
		} else {
			wr_errinfo why;

			memset(&why, 0, sizeof(why));
			why.status = WR_E_OSD_BLOCKLISTED;
			why.module = WR_MOD_RBD;
			wri_rbd_img_fail(&O.L, 0, &why);
			WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->ctl_op == WRI_NIL && m->ros == (uint8_t)WRI_ROS_IDLE);
			WRT_CHECK_STATUS(WR_OK, wri_rbd_close(&O.L, 0, WR_CLOSE_DRAIN));
		}
		WRT_CHECK(m->state == (uint8_t)WR_IMG_FREE && m->ctl_op == WRI_NIL);
		/* a snapshot is taken while the old read is still held, then the old answer is let go */
		WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 61, snaps, 2));
		sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
		(void)sim_osd_release(O.r.w.osd[0], 0);
		(void)orig_settle(&O);
		WRT_CHECK(orig_ctl_idle(&O));
		WRT_CHECK(orig_start(&O, &p, WR_OK) == 0u);
		(void)orig_settle(&O);
		WRT_CHECK(m->state == (uint8_t)WR_IMG_OPEN && m->snapc.seq == 61u && m->snapc.n == 2u && m->ros == (uint8_t)WRI_ROS_READY);
		WRT_CHECK(m->err.status == WR_OK && m->ctl_op == WRI_NIL && orig_ctl_idle(&O));
		orig_close(&O);
	}
}

/* A refresh whose snapshot context cannot be taken (more snapshots than the profile holds, or one that is not valid) fails the image, and the live context
 * stays what it was: a write that is on the wire when the image fails lives on as a zombie that carries a copy of it, and a copy of an emptied context would
 * tell the cluster there are no snapshots. */
static void test_failed_refresh_keeps_context(void)
{
	wri_rbd_img *m;
	uint64_t snaps[9], bad[1] = {9}; /* a snapshot id above the sequence number: not a valid context */
	wr_io_req q;
	unsigned i, k, zombies;

	for (k = 0; k < 2; k++) {
		if (open_writer(NULL, 1) != 0)
			return;
		m = oimg(&O, 0);
		for (i = 0; i < 9; i++)
			snaps[i] = 50u - i;
		if (k == 0)
			WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 50, snaps, 9)); /* max_snaps is 8 */
		else
			WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(O.r.w.store, W_POOL, ID, 4, bad, 1));
		/* a write goes out and its answer is held; the refresh read is the one that is answered first */
		sim_osd_faults(O.r.w.osd[0])->hold_replies = 1;
		sim_osd_faults(O.r.w.osd[0])->reverse_release = 1;
		q = wr(0, 4096);
		WRT_CHECK_STATUS(WR_OK, wri_rbd_submit(&O.L, 0, &q));
		(void)orig_settle(&O);
		WRT_CHECK(rec_pos(1, 0) >= 0);
		orig_tick(&O, 1100);
		WRT_CHECK(m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL);
		WRT_CHECK(sim_osd_release(O.r.w.osd[0], 1) == 1u); /* newest first: the header */
		(void)orig_settle(&O);
		WRT_CHECK(m->state == (uint8_t)WR_IMG_FAILED && m->err.status == WR_E_RBD_SNAPC);
		WRT_CHECK(m->snapc.seq == 5u && m->snapc.n == 1u && m->snapc.snaps[0] == 5u && wri_snapc_valid(&m->snapc)); /* untouched */
		WRT_CHECK(wri_rbd_next_done(&O.L) == &q && q.status == WR_E_RBD_SNAPC);
		for (i = 0, zombies = 0; i < O.r.o.n_op; i++) {
			const wri_osd_op *op = &O.r.o.op[i];

			if ((op->flags & WRI_OPF_ZOMBIE) != 0) {
				zombies++;
				WRT_CHECK(op->snapc != NULL && op->snapc->seq == 5u && op->snapc->n == 1u && op->snapc->snaps[0] == 5u);
			}
		}
		WRT_CHECK(zombies == 1u);
		sim_osd_faults(O.r.w.osd[0])->hold_replies = 0;
		(void)sim_osd_release(O.r.w.osd[0], 0);
		(void)orig_settle(&O);
		orig_close(&O);
	}
}

int main(void)
{
	test_timer();
	test_adopt();
	test_failures();
	test_failures_identity();
	test_transient();
	test_age_from_submit();
	test_gate_idle();
	test_gate_unanswered();
	test_refresh_now();
	test_refresh_now_fails();
	test_refresh_oversize();
	test_leave_in_refresh();
	test_failed_refresh_keeps_context();
	return wrt_finish();
}
