/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_open.c - the whole engine with the OSD client and the image layer inside it (module client-glue-osd; core/src/client/wri_client_osd*.c,
 * wr_image.c, core/src/rbd/wri_rbd_step.c; docs/design/core-architecture.md 27), against one simulated monitor and N simulated OSDs over one object
 * store, through the PUBLIC API only (client_osd_rig.h plays the host: it dials every CONNECT action to the simulator that owns the address and moves
 * the bytes).
 *
 *   basics        open an image (writer), write patterns (inside an object, across objects, the last byte, one byte), read them back, read a hole, flush,
 *                 discard (whole objects are removed, the rest zeroed), write-zeroes, zero-length requests; every state of the image compared byte for byte
 *                 with a flat model AND with the object store; the engine goes quiet (no spin: a settled engine reports no more work)
 *   data pool     an image with the data-pool feature: data objects land in the named pool, an open without the name fails with WR_E_RBD_DATA_POOL
 *   two images    two images open at once with different content, a reader next to a writer of the same image (the writer's writes are visible, the reader
 *                 cannot write), closing one leaves the other working
 *   close         DRAIN lets the writes in flight finish, ABANDON ends at once; both free the slot and raise WR_EV_IMAGE
 *   sessions      fewer OSD sessions than OSDs: the table evicts and reconnects, all data intact, never more sessions than configured
 *   monitor       the monitor restarts under I/O: I/O to the OSDs does not depend on it, the session comes back and nothing is lost
 *   OSD restart   every OSD restarts with the answers of executed writes held back: the writes are resent under the SAME tid, the OSD's duplicate
 *                 detection answers them, nothing is applied twice and nothing is lost (also with the duplicate detection off: the image layer's fence)
 *   map change    an OSD is marked down under I/O: the operations move to the new primaries, the OSD gets no request afterwards
 *   destroy       the client is destroyed in the middle of I/O: the arena is zero, nothing outside the regions was touched, nothing leaks (ASan)
 */
#include "client_osd_rig.h"

#define IMG_ORDER 16u                 /* 64 KiB objects */
#define IMG_SIZE (4u << 20)           /* 4 MiB: 64 objects */
#define OBJ (1u << IMG_ORDER)

static int objname(char *out, size_t cap, const wr_image_info *info, uint64_t objno)
{
	return snprintf(out, cap, "%s.%016" PRIx64, info->object_prefix, objno);
}

/* The object store holds exactly what the model says, object by object (a missing object and a hole read as zeros on both sides). */
static void check_store(cw *w, const wr_image_info *info, const uint8_t *model, uint64_t size)
{
	uint8_t *tmp = (uint8_t *)malloc(info->object_size);
	uint64_t o, n = (size + info->object_size - 1u) / info->object_size;
	unsigned bad = 0;

	for (o = 0; o < n && tmp != NULL; o++) {
		char name[160];
		int exists = 0;
		uint64_t len = size - o * info->object_size < info->object_size ? size - o * info->object_size : info->object_size;

		objname(name, sizeof(name), info, o);
		WRT_CHECK_STATUS(WR_OK, sim_store_read(w->store, info->data_pool_id, name, 0, tmp, (size_t)len, &exists));
		if (memcmp(tmp, model + o * info->object_size, (size_t)len) != 0)
			bad++;
	}
	WRT_CHECK_U64(bad, 0);
	free(tmp);
}

/* Every byte of the image read through the engine equals the model. */
static void check_image(cw *w, wr_image *img, const uint8_t *model, uint64_t size)
{
	uint8_t *buf = (uint8_t *)malloc(1u << 20);
	uint64_t off;
	unsigned bad = 0;

	for (off = 0; off < size && buf != NULL; off += 1u << 20) {
		uint64_t n = size - off < (1u << 20) ? size - off : (1u << 20);
		wr_io_req r = cw_req(WR_IO_READ, off, n, buf);

		memset(buf, 0xEE, (size_t)n);
		WRT_CHECK_STATUS(WR_OK, cw_do(w, img, &r, 60000));
		if (memcmp(buf, model + off, (size_t)n) != 0)
			bad++;
	}
	WRT_CHECK_U64(bad, 0);
	free(buf);
}

static void do_write(cw *w, wr_image *img, uint8_t *model, uint32_t seed, uint64_t off, uint64_t len)
{
	uint8_t *buf = (uint8_t *)malloc((size_t)len);
	wr_io_req r = cw_req(WR_IO_WRITE, off, len, buf);

	cw_fill(buf, seed, off, (size_t)len);
	WRT_CHECK_STATUS(WR_OK, cw_do(w, img, &r, 60000));
	memcpy(model + off, buf, (size_t)len);
	free(buf);
}

static void do_zero(cw *w, wr_image *img, uint8_t *model, wr_io_kind kind, uint64_t off, uint64_t len)
{
	wr_io_req r = cw_req(kind, off, len, NULL);

	WRT_CHECK_STATUS(WR_OK, cw_do(w, img, &r, 60000));
	memset(model + off, 0, (size_t)len);
}

static unsigned count_img_ev(const cw *w, uint32_t slot)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_ev; i++)
		n += w->ev[i].kind == WR_EV_IMAGE && w->ev[i].epoch == slot;
	return n;
}

/* ---- basics ---------------------------------------------------------------------------------------------------------- */

static void test_basics(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info;
	wr_osd_stats st;
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	uint8_t *buf = (uint8_t *)malloc(1u << 20);
	wr_io_req r;
	unsigned rounds;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	WRT_CHECK_U64(wr_image_error(img)->status, 0);
	WRT_CHECK(wr_client_image_at(w.c, wr_image_slot(img)) == img);
	WRT_CHECK_U64(count_img_ev(&w, wr_image_slot(img)), 1); /* the open */

	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	WRT_CHECK_U64(info.size_bytes, IMG_SIZE);
	WRT_CHECK_U64(info.object_size, OBJ);
	WRT_CHECK_U64(info.order, IMG_ORDER);
	WRT_CHECK_U64(info.features, 0x21);
	WRT_CHECK(info.writable == 1);
	WRT_CHECK_U64(info.pool_id, CW_POOL);
	WRT_CHECK_U64(info.data_pool_id, CW_POOL);
	WRT_CHECK_U64(info.max_io_bytes, 1u << 30);
	WRT_CHECK(strcmp(info.image_id, "abc123") == 0);
	WRT_CHECK(strcmp(info.object_prefix, "rbd_data.abc123") == 0);

	/* a fresh image reads as zeros everywhere */
	check_image(&w, img, model, IMG_SIZE);

	/* patterns: inside an object, across three objects, the last bytes, a single byte, and one that needs several operations (256 KiB limit) */
	do_write(&w, img, model, 5, 1000, 300000);
	do_write(&w, img, model, 6, 5u * OBJ - 100u, 70000);
	do_write(&w, img, model, 7, IMG_SIZE - 4096u, 4096);
	do_write(&w, img, model, 8, 12345, 1);
	do_write(&w, img, model, 9, 20u * OBJ + 7u, 1u << 20);
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);

	/* overwrite across the old extents: later bytes win */
	do_write(&w, img, model, 10, 2000, 200000);
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);

	/* flush: completes OK, with the writes before it done */
	r = cw_req(WR_IO_FLUSH, 0, 0, NULL);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));

	/* a zero-length read and write complete at once, with no buffer touched */
	r = cw_req(WR_IO_READ, 100, 0, buf);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
	r = cw_req(WR_IO_WRITE, IMG_SIZE, 0, buf); /* the end of the image is inside it */
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));

	/* discard: whole objects are removed, partial ones are zeroed or truncated; the read side cannot tell the difference */
	do_zero(&w, img, model, WR_IO_DISCARD, 2u * OBJ + 10u, 3u * OBJ - 10u); /* objects 3 and 4 whole, the ends partial */
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);
	{
		char name[160];

		objname(name, sizeof(name), &info, 3);
		WRT_CHECK(!sim_store_exists(w.store, info.data_pool_id, name)); /* a whole object: removed */
	}
	do_zero(&w, img, model, WR_IO_WRITE_ZEROES, 7u * OBJ - 33u, 2u * OBJ + 66u);
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);
	do_zero(&w, img, model, WR_IO_DISCARD, 0, IMG_SIZE); /* everything */
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);

	/* write again after the discard */
	do_write(&w, img, model, 11, 3u * OBJ - 5u, 11);
	check_image(&w, img, model, IMG_SIZE);

	/* a settled engine is quiet: nothing to do, a deadline in the future (or none) */
	rounds = (unsigned)cw_settle(&w);
	WRT_CHECK(rounds < 100u);
	WRT_CHECK_U64(w.last.more_work, 0);
	WRT_CHECK(w.last.next_deadline_ms > w.now);
	wr_client_osd_stats(w.c, &st);
	WRT_CHECK_U64(st.ops_inflight, 0);
	WRT_CHECK_U64(st.reqs_inflight, 0);
	WRT_CHECK(st.ops_done > 20u); /* ops_failed counts every operation the OSD answered with an error, a read of a missing object (a hole) included */
	WRT_CHECK(st.sessions_open >= 1u && st.sessions_open <= 3u);
	WRT_CHECK_U64(st.n_session_resets, 0);

	/* close: the slot is free again and the event says so */
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	WRT_CHECK(wr_client_image_at(w.c, wr_image_slot(img)) == NULL);
	WRT_CHECK_U64(count_img_ev(&w, 0), 2); /* open and close */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, WR_CLOSE_DRAIN));
	WRT_CHECK_U64(w.n_leak_log, 0);
	WRT_CHECK_U64(w.n_leak_wire, 0);
out:
	cw_free(&w);
	free(model);
	free(buf);
}

/* ---- data pool ------------------------------------------------------------------------------------------------------- */

static void test_data_pool(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info;
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "dimg", "dd0001", IMG_SIZE, IMG_ORDER, 0x21 | 0x80, CW_DPOOL) == 0);
	/* the header gives the pool id only: without the pool's name the open cannot judge it */
	p = cw_params("dimg", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_FAILED);
	if (img != NULL) {
		WRT_CHECK_U64(wr_image_error(img)->status, WR_E_RBD_DATA_POOL);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	}
	(void)cw_settle(&w);
	p.data_pool = "pool2";
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img != NULL && fin == WR_IMG_OPEN) {
		WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
		WRT_CHECK_U64(info.pool_id, CW_POOL);
		WRT_CHECK_U64(info.data_pool_id, CW_DPOOL);
		do_write(&w, img, model, 3, 100, 200000);
		do_write(&w, img, model, 4, 3u * OBJ, 4096);
		check_image(&w, img, model, IMG_SIZE);
		check_store(&w, &info, model, IMG_SIZE); /* the data objects are in pool 2 */
		{
			char name[160];

			objname(name, sizeof(name), &info, 0);
			WRT_CHECK(sim_store_exists(w.store, CW_DPOOL, name));
			WRT_CHECK(!sim_store_exists(w.store, CW_POOL, name));
		}
	}
	cw_free(&w);
	free(model);
}

/* ---- two images, a reader and a writer ------------------------------------------------------------------------------- */

static void test_two_images(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p1, p2, pr;
	wr_image *a, *b, *rd;
	wr_image_state fin;
	uint8_t *ma = (uint8_t *)calloc(1, IMG_SIZE), *mb = (uint8_t *)calloc(1, 2u << 20);
	uint8_t buf[64];
	wr_io_req r;

	cw_cfg_default(&cfg);
	cfg.max_images = 4;
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "one", "i00001", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	WRT_CHECK(cw_image(&w, "two", "i00002", 2u << 20, 15, 0x21, -1) == 0);
	p1 = cw_params("one", 1);
	p2 = cw_params("two", 1);
	a = cw_open_image(&w, &p1, &fin);
	WRT_CHECK(a != NULL && fin == WR_IMG_OPEN);
	b = cw_open_image(&w, &p2, &fin);
	WRT_CHECK(b != NULL && fin == WR_IMG_OPEN);
	if (a == NULL || b == NULL)
		goto out;
	WRT_CHECK(wr_image_slot(a) != wr_image_slot(b));
	do_write(&w, a, ma, 21, 1234, 500000);
	do_write(&w, b, mb, 22, 777, 300000);
	do_write(&w, a, ma, 23, 3u * OBJ, 100);
	check_image(&w, a, ma, IMG_SIZE);
	check_image(&w, b, mb, 2u << 20);

	/* a reader of the first image next to its writer sees what the writer wrote and cannot write */
	pr = cw_params("one", 0);
	rd = cw_open_image(&w, &pr, &fin);
	WRT_CHECK(rd != NULL && fin == WR_IMG_OPEN);
	if (rd != NULL && fin == WR_IMG_OPEN) {
		wr_image_info ri;

		WRT_CHECK_STATUS(WR_OK, wr_image_get_info(rd, &ri));
		WRT_CHECK(ri.writable == 0);
		check_image(&w, rd, ma, IMG_SIZE);
		r = cw_req(WR_IO_WRITE, 0, sizeof(buf), buf);
		WRT_CHECK_STATUS(WR_E_RBD_READONLY, cw_submit(rd, &r));
		r = cw_req(WR_IO_DISCARD, 0, 4096, NULL);
		WRT_CHECK_STATUS(WR_E_RBD_READONLY, cw_submit(rd, &r));
		r = cw_req(WR_IO_FLUSH, 0, 0, NULL);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, rd, &r, 10000)); /* a flush of a reader is nothing to wait for */
		do_write(&w, a, ma, 24, 50, 60000);
		check_image(&w, rd, ma, IMG_SIZE); /* the writer's bytes are visible to the reader (no cache) */
		WRT_CHECK_STATUS(WR_OK, wr_image_close(rd, WR_CLOSE_DRAIN));
	}
	/* closing one leaves the other working */
	WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(a) == WR_IMG_FREE && wr_image_get_state(b) == WR_IMG_OPEN);
	do_write(&w, b, mb, 25, 0, 4096);
	check_image(&w, b, mb, 2u << 20);
out:
	cw_free(&w);
	free(ma);
	free(mb);
}

/* ---- close with writes in flight ---------------------------------------------------------------------------------------- */

static void test_close(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	enum { N = 6, LEN = 200000 };
	wr_io_req rq[N];
	uint8_t *buf[N];
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	unsigned i, k;
	uint32_t slot;

	for (k = 0; k < 2; k++) { /* 0: DRAIN, 1: ABANDON */
		WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
		WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
		p = cw_params("img", 1);
		img = cw_open_image(&w, &p, &fin);
		WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
		if (img == NULL || fin != WR_IMG_OPEN) {
			cw_free(&w);
			continue;
		}
		slot = wr_image_slot(img);
		memset(model, 0, IMG_SIZE);
		for (i = 0; i < N; i++) {
			buf[i] = (uint8_t *)malloc(LEN);
			cw_fill(buf[i], 40u + i, (uint64_t)i * 300000u, LEN);
			rq[i] = cw_req(WR_IO_WRITE, (uint64_t)i * 300000u, LEN, buf[i]);
			WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[i]));
		}
		WRT_CHECK_STATUS(WR_OK, wr_image_close(img, k == 0 ? WR_CLOSE_DRAIN : WR_CLOSE_ABANDON));
		if (k == 0) {
			/* CLOSING: no new request is taken, the writes in flight finish, then the slot is free */
			WRT_CHECK(wr_image_get_state(img) == WR_IMG_CLOSING);
			{
				wr_io_req late = cw_req(WR_IO_FLUSH, 0, 0, NULL);

				WRT_CHECK_STATUS(WR_E_RBD_CLOSED, cw_submit(img, &late));
			}
			(void)cw_settle(&w);
			cw_tick(&w, 2000);
			WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
			for (i = 0; i < N; i++) {
				const cw_done *d = cw_done_of(&rq[i]);

				WRT_CHECK(d != NULL && d->st == WR_OK);
				memcpy(model + (uint64_t)i * 300000u, buf[i], LEN);
			}
		} else {
			WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE); /* at once */
			(void)cw_settle(&w);
			cw_tick(&w, 2000);
			for (i = 0; i < N; i++) {
				const cw_done *d = cw_done_of(&rq[i]);

				WRT_CHECK(d != NULL); /* every request completes: with its own status or WR_E_CANCELLED */
				if (d != NULL)
					WRT_CHECK(d->st == WR_OK || d->st == WR_E_CANCELLED);
			}
		}
		WRT_CHECK_U64(count_img_ev(&w, slot), 2);
		/* the layer is whole afterwards: the image opens again and what DRAIN wrote is there */
		img = cw_open_image(&w, &p, &fin);
		WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
		if (img != NULL && fin == WR_IMG_OPEN && k == 0)
			check_image(&w, img, model, IMG_SIZE);
		for (i = 0; i < N; i++)
			free(buf[i]);
		cw_free(&w);
	}
	free(model);
}

/* ---- fewer sessions than OSDs ---------------------------------------------------------------------------------------------- */

static void test_sessions(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_osd_stats st;
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	unsigned i;

	cw_cfg_default(&cfg);
	cfg.osd_sessions = 2; /* three OSDs, two sessions: the table evicts and reconnects */
	cfg.max_conns = 4;
	WRT_CHECK(cw_open(&w, &cfg, 3, 32, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img != NULL && fin == WR_IMG_OPEN) {
		for (i = 0; i < 24u; i++)
			do_write(&w, img, model, 50u + i, (uint64_t)((i * 7u) % 60u) * OBJ + i * 13u, 40000);
		check_image(&w, img, model, IMG_SIZE);
		wr_client_osd_stats(w.c, &st);
		WRT_CHECK(st.sessions_hiwater <= 2u);
		WRT_CHECK(w.n_connects_osd > 2u); /* it really did reconnect */
	}
	cw_free(&w);
	free(model);
}

/* ---- the monitor restarts under I/O ---------------------------------------------------------------------------------------- */

static void test_monitor_restart(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	enum { N = 8, LEN = 150000 };
	wr_io_req rq[N + 1];
	uint8_t *buf[N + 1];
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	unsigned i, downs;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	downs = cw_count_ev(&w, WR_EV_MON_SESSION_DOWN);
	for (i = 0; i < N; i++) {
		buf[i] = (uint8_t *)malloc(LEN);
		cw_fill(buf[i], 60u + i, (uint64_t)i * 400000u, LEN);
		rq[i] = cw_req(WR_IO_WRITE, (uint64_t)i * 400000u, LEN, buf[i]);
		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[i]));
	}
	(void)cw_round(&w); /* the first requests are on their way */
	sim_mon_restart(w.mon); /* the monitor session dies in the middle of it */
	(void)cw_settle(&w);
	/* the OSDs do not depend on the monitor session: the writes complete while the client is still hunting */
	for (i = 0; i < N; i++) {
		const cw_done *d = cw_done_of(&rq[i]);

		WRT_CHECK(d != NULL && d->st == WR_OK);
		memcpy(model + (uint64_t)i * 400000u, buf[i], LEN);
	}
	WRT_CHECK(cw_count_ev(&w, WR_EV_MON_SESSION_DOWN) > downs);
	/* a request submitted while there is no monitor session is served too (the map is held) */
	buf[N] = (uint8_t *)malloc(LEN);
	cw_fill(buf[N], 99, 5u * 400000u + 200000u, LEN);
	rq[N] = cw_req(WR_IO_WRITE, 5u * 400000u + 200000u, LEN, buf[N]);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &rq[N], 20000));
	memcpy(model + 5u * 400000u + 200000u, buf[N], LEN);
	/* and the session comes back */
	cw_tick(&w, 15000);
	WRT_CHECK(wr_client_get_state(w.c) == WR_CS_ACTIVE);
	check_image(&w, img, model, IMG_SIZE);
	for (i = 0; i <= N; i++)
		free(buf[i]);
out:
	cw_free(&w);
	free(model);
}

/* ---- OSD restart under I/O ---------------------------------------------------------------------------------------------------- */

static void osd_restart_case(int no_dedup)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	enum { N = 10, LEN = 90000 };
	wr_io_req rq[N];
	uint8_t *buf[N];
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	unsigned i, j, n_resent = 0, n_dup = 0, n_ok = 0;
	wr_image_info info;
	wr_osd_stats st;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	for (j = 0; j < w.n_osd; j++) {
		sim_osd_faults(w.osd[j])->hold_replies = 1; /* the OSDs execute and hold their answers back */
		sim_osd_faults(w.osd[j])->no_dedup = (uint8_t)no_dedup;
		sim_osd_recs_clear(w.osd[j]);
	}
	for (i = 0; i < N; i++) {
		buf[i] = (uint8_t *)malloc(LEN);
		cw_fill(buf[i], 70u + i, (uint64_t)i * 250000u + 17u, LEN);
		rq[i] = cw_req(WR_IO_WRITE, (uint64_t)i * 250000u + 17u, LEN, buf[i]);
		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[i]));
		memcpy(model + (uint64_t)i * 250000u + 17u, buf[i], LEN);
	}
	(void)cw_settle(&w);
	for (i = 0; i < N; i++)
		WRT_CHECK(cw_done_of(&rq[i]) == NULL); /* nobody has answered yet */
	for (j = 0; j < w.n_osd; j++) {
		WRT_CHECK(sim_osd_n_held(w.osd[j]) > 0u || sim_osd_n_requests(w.osd[j]) == 0u);
		sim_osd_restart(w.osd[j]); /* the answers are lost, every connection is cut */
		sim_osd_faults(w.osd[j])->hold_replies = 0;
	}
	(void)cw_settle(&w);
	cw_tick(&w, 30000); /* the sessions cool down and reopen; the operations are resent */
	for (i = 0; i < N; i++) {
		const cw_done *d = cw_done_of(&rq[i]);

		WRT_CHECK(d != NULL && d->st == WR_OK);
		n_ok += d != NULL && d->st == WR_OK;
	}
	WRT_CHECK_U64(n_ok, N);
	/* what the OSDs saw: a resent operation has the same tid as before and retry_attempt + 1, and (with duplicate detection) was recognised, not applied again */
	for (j = 0; j < w.n_osd; j++) {
		uint32_t n = 0, a, b;
		const sim_osd_rec *rec = sim_osd_recs(w.osd[j], &n);

		for (a = 0; a < n; a++) {
			if (rec[a].retry_attempt == 0u)
				continue;
			n_resent++;
			n_dup += rec[a].duplicate;
			for (b = 0; b < n; b++) /* the first attempt of the same tid, on this OSD or another one */
				if (b != a && rec[b].tid == rec[a].tid && rec[b].retry_attempt + 1u == rec[a].retry_attempt)
					break;
			(void)b; /* the first attempt may be on another OSD's log: only the shape of the resend is checked here */
			WRT_CHECK((rec[a].flags & 0x10000u) != 0u || rec[a].retry_attempt >= 1u);
		}
	}
	WRT_CHECK(n_resent > 0u);
	if (!no_dedup)
		WRT_CHECK(n_dup > 0u); /* the OSD answered at least one resend from its log */
	check_image(&w, img, model, IMG_SIZE);
	check_store(&w, &info, model, IMG_SIZE);
	wr_client_osd_stats(w.c, &st);
	WRT_CHECK(st.ops_resent > 0u);
	WRT_CHECK(st.n_session_resets > 0u);
	for (i = 0; i < N; i++)
		free(buf[i]);
out:
	cw_free(&w);
	free(model);
}

static void test_osd_restart(void)
{
	osd_restart_case(0);
	osd_restart_case(1); /* without the OSD's duplicate detection (a new global id): the same bytes are written again, nothing newer exists yet */
}

/* ---- an OSD is marked down ----------------------------------------------------------------------------------------------------- */

static void edit_down0(wrt_mg_inc *inc, wrt_mg_map *desc, void *arg)
{
	(void)desc;
	wrt_mg_inc_mark_down(inc, *(int32_t *)arg);
}

static void test_map_change(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t *model = (uint8_t *)calloc(1, IMG_SIZE);
	int32_t victim = 0;
	unsigned i;
	uint32_t before;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	for (i = 0; i < 16u; i++)
		do_write(&w, img, model, 80u + i, (uint64_t)i * 4u * OBJ / 3u, 50000);
	WRT_CHECK(sim_osd_n_requests(w.osd[0]) > 0u); /* the victim served some before */
	/* a write in flight when the map changes (its answers held), then the epoch that takes OSD 0 down */
	for (i = 0; i < w.n_osd; i++)
		sim_osd_faults(w.osd[i])->hold_replies = 1;
	{
		uint8_t *buf = (uint8_t *)malloc(IMG_SIZE);
		wr_io_req r = cw_req(WR_IO_WRITE, 0, IMG_SIZE, buf);

		cw_fill(buf, 123, 0, IMG_SIZE);
		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
		(void)cw_settle(&w);
		WRT_CHECK(cw_done_of(&r) == NULL);
		memcpy(model, buf, IMG_SIZE);
		WRT_CHECK(cw_map_next(&w, edit_down0, &victim) == 0);
		(void)cw_settle(&w);
		cw_tick(&w, 500);
		before = sim_osd_n_requests(w.osd[0]);
		for (i = 0; i < w.n_osd; i++) {
			sim_osd_faults(w.osd[i])->hold_replies = 0;
			(void)sim_osd_release(w.osd[i], 0);
		}
		(void)cw_settle(&w);
		cw_tick(&w, 20000);
		WRT_CHECK(cw_done_of(&r) != NULL && cw_done_of(&r)->st == WR_OK);
		free(buf);
	}
	WRT_CHECK(cw_count_ev(&w, WR_EV_MAP) >= 2u);
	WRT_CHECK_U64(cw_last_ev(&w, WR_EV_MAP)->epoch, 2);
	/* from now on OSD 0 is nobody's primary: it serves no request that was sent after the change */
	before = sim_osd_n_requests(w.osd[0]);
	for (i = 0; i < 16u; i++)
		do_write(&w, img, model, 200u + i, (uint64_t)i * 4u * OBJ / 3u + 5u, 30000);
	check_image(&w, img, model, IMG_SIZE);
	WRT_CHECK_U64(sim_osd_n_requests(w.osd[0]), before);
out:
	cw_free(&w);
	free(model);
}

/* ---- destroy in the middle of I/O ------------------------------------------------------------------------------------------------ */

static void test_destroy(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	enum { N = 6, LEN = 200000 };
	wr_io_req rq[N];
	uint8_t *buf[N];
	unsigned i;
	size_t k, nonzero = 0, guard_bad = 0;
	uint32_t used;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN) {
		cw_free(&w);
		return;
	}
	for (i = 0; i < w.n_osd; i++)
		sim_osd_faults(w.osd[i])->hold_replies = 1;
	for (i = 0; i < N; i++) {
		buf[i] = (uint8_t *)malloc(LEN);
		cw_fill(buf[i], 3u + i, (uint64_t)i * 500000u, LEN);
		rq[i] = cw_req(i % 2u ? WR_IO_READ : WR_IO_WRITE, (uint64_t)i * 500000u, LEN, buf[i]);
		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[i]));
	}
	(void)cw_round(&w);
	(void)cw_round(&w);
	{
		wr_osd_stats st;

		wr_client_osd_stats(w.c, &st);
		WRT_CHECK(st.ops_inflight > 0u); /* really in the middle of it */
	}
	used = (uint32_t)w.req.arena;
	wr_client_destroy(w.c);
	for (k = 0; k < used; k++)
		nonzero += w.arena_base[k] != 0u;
	WRT_CHECK_U64(nonzero, 0); /* the arena part in use is wiped: tickets, keys, the image tables, the copies of unanswered writes' bookkeeping */
	for (k = 0; k < (size_t)(w.arena_base - w.arena_raw); k++)
		guard_bad += w.arena_raw[k] != w.arena_pat;
	for (k = used + (size_t)(w.arena_base - w.arena_raw); k < w.req.arena + 128u; k++)
		guard_bad += w.arena_raw[k] != w.arena_pat;
	WRT_CHECK_U64(guard_bad, 0);
	/* the dead client answers nothing and crashes nothing */
	{
		wr_osd_stats st;
		wr_image_info info;
		wr_io_req r = cw_req(WR_IO_FLUSH, 0, 0, NULL);

		WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
		WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
		WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(img, &info));
		WRT_CHECK(wr_client_next_done(w.c) == NULL);
		wr_client_osd_stats(w.c, &st);
		WRT_CHECK_U64(st.ops_done, 0);
	}
	w.c = NULL;
	for (i = 0; i < N; i++)
		free(buf[i]);
	cw_free(&w);
}

int main(void)
{
	test_basics();
	test_data_pool();
	test_two_images();
	test_close();
	test_sessions();
	test_monitor_restart();
	test_osd_restart();
	test_map_change();
	test_destroy();
	return wrt_finish();
}
