/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_api.c - the contract of the public image API (wr_image.h) on the real engine (module client-glue-osd; core/src/client/wr_image.c):
 * argument validation of every call, in the order the header lists the statuses, and what each call does to the layer. The engine is the whole one of
 * client_osd_rig.h (simulated monitor and OSDs behind the public pump).
 *
 *   wr_image_open          NULL client / parameters / out, a client without the OSD client, ABI, pool / name / id rules, lengths, characters, the snapshot id,
 *                          the image table full, the pool table full, a pool name that is too long; nothing is consumed by a refused open; both name and
 *                          id given: the id is used; a missing image fails the open (WR_E_RBD_NOT_FOUND) and says so in wr_image_error and WR_EV_IMAGE;
 *                          open_timeout_ms with every OSD dead; the OSD connect timeout is the action's timeout of an OSD connection
 *   queries                get_info (NULL, closed, OPENING, OPEN, FAILED after having been open), get_state / error / slot / image_at on stale or NULL arguments
 *   wr_image_submit        every status of the header: INVAL, STATE, RBD_CLOSED, RBD_READONLY, TOOBIG, RANGE, BUSY; a structure the core still owns
 *   wr_image_cancel        INVAL, STATE (never submitted, already pulled, another image's), a read, a sent write (the zombie copy), a write whose copy does not fit
 *   wr_image_close         INVAL (NULL, closed, unknown flags), a second close, DRAIN then ABANDON
 *   wr_client_next_done    NULL client, nothing finished
 *   stale handles          every call on the handle of a destroyed client or a closed image is WR_E_INVAL / FREE / NULL, no crash
 */
#include "client_osd_rig.h"

#define IMG_ORDER 16u
#define IMG_SIZE (4u << 20)

static wr_status open_st(cw *w, const wr_image_params *p, wr_image **out)
{
	return wr_image_open(w->c, p, out);
}

/* The replies the OSDs hold back now. */
static unsigned held_now(const cw *w)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_osd; i++)
		n += sim_osd_n_held(w->osd[i]);
	return n;
}

/* Rounds until the OSDs hold more replies than `before`: a request that was sent after that point is on the wire. */
static int wait_held(cw *w, unsigned before)
{
	unsigned k;

	for (k = 0; k < 400u; k++) {
		if (held_now(w) > before)
			return 1;
		(void)cw_round(w);
	}
	return 0;
}

/* ---- wr_image_open -------------------------------------------------------------------------------------------------------- */

static void test_open_args(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img = (wr_image *)(void *)&p, *a, *b;
	char longname[160];
	unsigned i;
	wr_image_state fin;

	cw_cfg_default(&cfg);
	cfg.max_images = 2;
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	WRT_CHECK(cw_image(&w, "img2", "abc124", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);

	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(NULL, &p, &img));
	WRT_CHECK(img == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(w.c, NULL, &img));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(w.c, &p, NULL));
	WRT_CHECK(img == NULL);

	p.size = (uint32_t)sizeof(p) + 4u;
	WRT_CHECK_STATUS(WR_E_ABI, open_st(&w, &p, &img));
	p.size = 0;
	WRT_CHECK_STATUS(WR_E_ABI, open_st(&w, &p, &img));
	p = cw_params("img", 1);

	p.pool = NULL;
	WRT_CHECK_STATUS(WR_E_INVAL, open_st(&w, &p, &img));
	p.pool = "";
	WRT_CHECK_STATUS(WR_E_INVAL, open_st(&w, &p, &img));
	p = cw_params(NULL, 1); /* neither name nor id */
	WRT_CHECK_STATUS(WR_E_INVAL, open_st(&w, &p, &img));
	p = cw_params("", 1);
	WRT_CHECK_STATUS(WR_E_INVAL, open_st(&w, &p, &img));

	memset(longname, 'n', sizeof(longname));
	longname[87] = '\0';
	p = cw_params(longname, 1); /* 87 bytes: the longest name that fits "rbd_id." + name in 95 bytes: not too long (it does not exist: the open fails later) */
	WRT_CHECK_STATUS(WR_OK, open_st(&w, &p, &a));
	if (a != NULL)
		WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_ABANDON));
	longname[88] = '\0';
	longname[87] = 'n';
	p = cw_params(longname, 1);
	WRT_CHECK_STATUS(WR_E_TOOBIG, open_st(&w, &p, &img));
	WRT_CHECK(img == NULL);
	memset(longname, 'a', sizeof(longname));
	longname[64] = '\0'; /* an id of 64 bytes */
	p = cw_params(NULL, 1);
	p.id = longname;
	WRT_CHECK_STATUS(WR_E_TOOBIG, open_st(&w, &p, &img));
	p.id = "ab-cd";
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, open_st(&w, &p, &img));
	p.id = "";
	WRT_CHECK_STATUS(WR_E_RBD_BAD_ID, open_st(&w, &p, &img)); /* an id that is given but empty is no valid id (neither name nor id is WR_E_INVAL above) */

	p = cw_params("img", 1);
	p.snap_id = 5;
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, open_st(&w, &p, &img));
	p.snap_id = 0;
	WRT_CHECK_STATUS(WR_E_UNSUPPORTED, open_st(&w, &p, &img)); /* 0 is no snapshot id this phase accepts either */

	/* a pool name over 128 bytes is the map module's WR_E_TOOBIG; a third pool name does not fit the two of the profile */
	memset(longname, 'p', sizeof(longname));
	longname[129] = '\0';
	p = cw_params("img", 1);
	p.pool = longname;
	WRT_CHECK_STATUS(WR_E_TOOBIG, open_st(&w, &p, &img));
	p = cw_params("img", 1);
	p.pool = "pool1";
	p.data_pool = "pool2";
	WRT_CHECK_STATUS(WR_OK, open_st(&w, &p, &a)); /* tracks both names: the table (map_pools = 2) is full now */
	if (a != NULL)
		WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_ABANDON));
	p = cw_params("img", 1);
	p.pool = "pool3";
	WRT_CHECK_STATUS(WR_E_BUSY, open_st(&w, &p, &img));
	WRT_CHECK(img == NULL);

	/* nothing was consumed by any of the refusals: every slot of the table is free, and the table takes exactly max_images images */
	for (i = 0; i < 2u; i++)
		WRT_CHECK(wr_client_image_at(w.c, i) == NULL);
	p = cw_params("img", 1);
	WRT_CHECK_STATUS(WR_OK, open_st(&w, &p, &a));
	p = cw_params("img2", 1);
	WRT_CHECK_STATUS(WR_OK, open_st(&w, &p, &b));
	WRT_CHECK(a != NULL && b != NULL && a != b && wr_image_slot(a) != wr_image_slot(b));
	WRT_CHECK(wr_client_image_at(w.c, wr_image_slot(a)) == a && wr_client_image_at(w.c, wr_image_slot(b)) == b);
	WRT_CHECK(wr_client_image_at(w.c, 2) == NULL && wr_client_image_at(w.c, 0xffffffffu) == NULL && wr_client_image_at(NULL, 0) == NULL);
	WRT_CHECK(wr_image_get_state(a) == WR_IMG_OPENING && wr_image_get_state(b) == WR_IMG_OPENING);
	img = NULL;
	WRT_CHECK_STATUS(WR_E_BUSY, open_st(&w, &p, &img));
	WRT_CHECK(img == NULL);
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(a) == WR_IMG_OPEN && wr_image_get_state(b) == WR_IMG_OPEN);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_OK, open_st(&w, &p, &a)); /* the slot is back */
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(a) == WR_IMG_OPEN);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_OK, wr_image_close(b, WR_CLOSE_DRAIN));

	/* both name and id given: the id is used, the name is only shown (it does not exist) */
	p = cw_params("no-such-name", 1);
	p.id = "abc123";
	a = cw_open_image(&w, &p, &fin);
	WRT_CHECK(a != NULL && fin == WR_IMG_OPEN);
	if (a != NULL) {
		wr_image_info info;

		WRT_CHECK_STATUS(WR_OK, wr_image_get_info(a, &info));
		WRT_CHECK(strcmp(info.image_id, "abc123") == 0);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	}
	cw_free(&w);
}

static void test_open_off(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img = (wr_image *)(void *)&p;
	wr_osd_stats st;
	wr_io_req r;

	cw_cfg_default(&cfg);
	cfg.osd_sessions = 0; /* the OSD client is off: the engine is what it was */
	cfg.max_conns = 4;
	cfg.max_handshakes = 2;
	WRT_CHECK(cw_open(&w, &cfg, 1, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(w.c->osd == NULL && w.c->rbd == NULL && w.c->og == NULL);
	p = cw_params("img", 1);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(w.c, &p, &img));
	WRT_CHECK(img == NULL);
	WRT_CHECK(wr_client_next_done(w.c) == NULL);
	WRT_CHECK(wr_client_image_at(w.c, 0) == NULL);
	memset(&st, 0xa5, sizeof(st));
	wr_client_osd_stats(w.c, &st);
	WRT_CHECK(st.ops_done == 0u && st.sessions_open == 0u && st.zombie_bytes_max == 0u && st.reqs_hiwater == 0u);
	r = cw_req(WR_IO_FLUSH, 0, 0, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(NULL, &r));
	(void)cw_settle(&w);
	WRT_CHECK(wr_client_get_state(w.c) == WR_CS_ACTIVE && cw_count_ev(&w, WR_EV_MAP) == 1u); /* the rest of the engine is untouched */
	cw_free(&w);
}

/* A missing image, an open that cannot finish, and the timeouts. */
static void test_open_fail(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info;
	const wr_event *e;
	unsigned i;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	p = cw_params("nosuch", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_FAILED);
	if (img != NULL) {
		WRT_CHECK_U64(wr_image_error(img)->status, WR_E_RBD_NOT_FOUND);
		WRT_CHECK(wr_image_error(img)->what != NULL);
		WRT_CHECK_STATUS(WR_E_STATE, wr_image_get_info(img, &info)); /* it was never open */
		e = cw_last_ev(&w, WR_EV_IMAGE);
		WRT_CHECK(e != NULL && e->epoch == wr_image_slot(img) && e->err.status == WR_E_RBD_NOT_FOUND);
		{
			wr_io_req r = cw_req(WR_IO_FLUSH, 0, 0, NULL);

			WRT_CHECK_STATUS(WR_E_RBD_CLOSED, cw_submit(img, &r));
		}
		WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN)); /* a failed image is freed at once */
		WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	}
	cw_free(&w);

	/* every OSD unreachable: the open fails with its own timeout, and the connects carry the OSD connect timeout */
	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	for (i = 0; i < 3u; i++)
		w.osd_down[i] = 1;
	p = cw_params("img", 1);
	p.open_timeout_ms = 4000;
	img = cw_open_image(&w, &p, &fin); /* the engine has not run yet: the deadline counts from its first run, not from the clock's zero */
	WRT_CHECK(img != NULL);
	if (img != NULL) {
		WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPENING || wr_image_get_state(img) == WR_IMG_FAILED);
		cw_tick(&w, 6000);
		WRT_CHECK(wr_image_get_state(img) == WR_IMG_FAILED);
		WRT_CHECK_U64(wr_image_error(img)->status, WR_E_TIMEOUT);
	}
	WRT_CHECK(w.n_connects_osd > 0u);
	{
		unsigned any = 0;

		for (i = 0; i < 3u; i++)
			if (w.connect_timeout_seen[i] != 0u) {
				WRT_CHECK_U64(w.connect_timeout_seen[i], w.cfg.osd_connect_timeout_ms); /* an OSD's connect is not the monitor's (5 s) */
				any++;
			}
		WRT_CHECK(any > 0u);
		WRT_CHECK_U64(w.connect_timeout_seen[3], w.cfg.connect_timeout_ms);
	}
	cw_free(&w);
}

/* ---- queries -------------------------------------------------------------------------------------------------------------- */

static void test_queries(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info, last;
	const wr_errinfo *e;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	WRT_CHECK_STATUS(WR_OK, wr_image_open(w.c, &p, &img));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPENING);
	memset(&info, 0xa5, sizeof(info));
	WRT_CHECK_STATUS(WR_E_STATE, wr_image_get_info(img, &info)); /* still opening */
	WRT_CHECK(info.size_bytes == 0u && info.image_id[0] == '\0'); /* outputs are cleared on every failure */
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(img, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(NULL, &info));
	WRT_CHECK(wr_image_get_state(NULL) == WR_IMG_FREE);
	e = wr_image_error(NULL);
	WRT_CHECK(e != NULL && e->status == WR_OK);
	e = wr_image_error(img);
	WRT_CHECK(e != NULL && e->status == WR_OK);
	WRT_CHECK_U64(wr_image_slot(NULL), 0);
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPEN);
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	last = info;

	/* a feature is enabled behind our back: the writer's next header read fails the image, and the last values stay readable */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(w.store, CW_POOL, "abc123", 0x21 | 0x4)); /* exclusive-lock */
	cw_tick(&w, 4000);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FAILED);
	WRT_CHECK(wr_image_error(img)->status != WR_OK);
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	WRT_CHECK(info.size_bytes == last.size_bytes && info.order == last.order && info.features == last.features);
	{
		wr_io_req r = cw_req(WR_IO_FLUSH, 0, 0, NULL);

		WRT_CHECK_STATUS(WR_E_RBD_CLOSED, cw_submit(img, &r));
	}
	/* closing: CLOSING is no state get_info answers in */
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(img, &info));
	WRT_CHECK(wr_image_error(img)->status == WR_OK); /* a closed image has no error of its own */
	WRT_CHECK(wr_client_image_at(w.c, wr_image_slot(img)) == NULL);
	/* the table slot of the closed image is reusable and the stale handle is the NEW image's handle (same slot): that is the contract of a slot handle */
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_features(w.store, CW_POOL, "abc123", 0x21));
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	cw_free(&w);
}

/* ---- wr_image_submit ------------------------------------------------------------------------------------------------------ */

static void test_submit_args(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img, *ro;
	wr_image_state fin;
	uint8_t buf[4096];
	wr_io_req r, rq[17];
	enum { N = 16 };
	unsigned i;
	uint8_t *wbuf[N + 1];

	cw_cfg_default(&cfg);
	cfg.max_images = 3;
	cfg.max_reqs = N;
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "big", "b00001", 4ull << 30, 22, 0x21, -1) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("big", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	p = cw_params("img", 0);
	ro = cw_open_image(&w, &p, &fin);
	WRT_CHECK(ro != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || ro == NULL) {
		cw_free(&w);
		return;
	}
	memset(buf, 0, sizeof(buf));

	r = cw_req(WR_IO_READ, 0, 10, buf);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(NULL, &r));
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, NULL));
	r = cw_req((wr_io_kind)0, 0, 10, buf);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
	r = cw_req((wr_io_kind)6, 0, 10, buf);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
	r = cw_req(WR_IO_READ, 0, 10, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
	r = cw_req(WR_IO_WRITE, 0, 10, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
	/* the order of the header: a bad kind before the state of the image, the read-only refusal before the size checks */
	r = cw_req(WR_IO_WRITE, 0, 10, buf);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, cw_submit(ro, &r));
	r = cw_req(WR_IO_WRITE_ZEROES, 0, IMG_SIZE + 1u, NULL);
	WRT_CHECK_STATUS(WR_E_RBD_READONLY, cw_submit(ro, &r));
	/* sizes: TOOBIG above 1 GiB for the kinds that carry a buffer, RANGE outside the image */
	r = cw_req(WR_IO_READ, 0, (1ull << 30) + 1u, buf);
	WRT_CHECK_STATUS(WR_E_TOOBIG, cw_submit(img, &r));
	r = cw_req(WR_IO_WRITE, 4096, UINT64_MAX, buf);
	WRT_CHECK_STATUS(WR_E_TOOBIG, cw_submit(img, &r));
	r = cw_req(WR_IO_READ, (4ull << 30) - 10u, 11, buf);
	WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
	r = cw_req(WR_IO_WRITE, (4ull << 30) + 1u, 0, buf);
	WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
	r = cw_req(WR_IO_DISCARD, 0, UINT64_MAX, NULL);
	WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
	r = cw_req(WR_IO_DISCARD, UINT64_MAX, 1, NULL);
	WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
	r = cw_req(WR_IO_WRITE_ZEROES, (4ull << 30) - 4096u, 8192, NULL);
	WRT_CHECK_STATUS(WR_E_RANGE, cw_submit(img, &r));
	/* the very end of the image is inside it; a zero length at the end too */
	r = cw_req(WR_IO_READ, (4ull << 30) - 4096u, 4096, buf);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000));
	r = cw_req(WR_IO_READ, 4ull << 30, 0, buf);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000));

	/* a structure the core still owns cannot be submitted again; a flush and a discard need no buffer */
	rq[0] = cw_req(WR_IO_WRITE, 0, 4096, buf);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[0]));
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &rq[0]));
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(ro, &rq[0]));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&rq[0]) != NULL && cw_done_of(&rq[0])->st == WR_OK);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &rq[0], 20000)); /* pulled: the structure is the host's again */
	r = cw_req(WR_IO_FLUSH, 7, 7, NULL); /* offset, length and buffer of a flush are not looked at */
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000));
	r = cw_req(WR_IO_DISCARD, 4096, 4096, NULL);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000));

	/* max_reqs in flight: the next one is BUSY, and the table takes requests again when they complete */
	for (i = 0; i < N; i++) {
		wbuf[i] = (uint8_t *)calloc(1, 4096);
		rq[i] = cw_req(WR_IO_WRITE, (uint64_t)i * 8192u, 4096, wbuf[i]);
		cw_done_forget(&rq[i]);
		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rq[i]));
	}
	wbuf[N] = (uint8_t *)calloc(1, 4096);
	rq[N] = cw_req(WR_IO_WRITE, 99u * 8192u, 4096, wbuf[N]);
	WRT_CHECK_STATUS(WR_E_BUSY, cw_submit(img, &rq[N]));
	(void)cw_settle(&w);
	for (i = 0; i < N; i++)
		WRT_CHECK(cw_done_of(&rq[i]) != NULL && cw_done_of(&rq[i])->st == WR_OK);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &rq[N], 20000));
	for (i = 0; i <= N; i++)
		free(wbuf[i]);

	/* a request on an image that is not open yet */
	p = cw_params("img", 1);
	{
		wr_image *op = NULL;

		WRT_CHECK_STATUS(WR_OK, wr_image_open(w.c, &p, &op));
		r = cw_req(WR_IO_FLUSH, 0, 0, NULL);
		WRT_CHECK_STATUS(WR_E_STATE, cw_submit(op, &r));
		(void)cw_settle(&w);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(op, WR_CLOSE_ABANDON));
	}
	cw_free(&w);
}

/* ---- wr_image_cancel ------------------------------------------------------------------------------------------------------ */

static void test_cancel_args(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img, *other;
	wr_image_state fin;
	uint8_t *buf = (uint8_t *)calloc(1, 300000), *chk = (uint8_t *)calloc(1, 300000);
	wr_io_req r, r2, rd;
	unsigned j;

	cw_cfg_default(&cfg);
	cfg.max_images = 3;
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	WRT_CHECK(cw_image(&w, "img2", "abc124", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	p = cw_params("img2", 1);
	other = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && other != NULL && wr_image_get_state(img) == WR_IMG_OPEN && wr_image_get_state(other) == WR_IMG_OPEN);
	if (img == NULL || other == NULL)
		goto out;
	r = cw_req(WR_IO_READ, 0, 100, chk);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_cancel(NULL, &r));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_cancel(img, NULL));
	WRT_CHECK_STATUS(WR_E_STATE, wr_image_cancel(img, &r)); /* never submitted */

	/* a read in flight: cancelled at once; its completion carries WR_E_CANCELLED and the buffer is the host's again */
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->hold_replies = 1;
	r = cw_req(WR_IO_READ, 0, 200000, chk);
	cw_done_forget(&r);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	(void)cw_round(&w);
	(void)cw_round(&w);
	WRT_CHECK_STATUS(WR_E_STATE, wr_image_cancel(other, &r)); /* another image's request is no request of that image */
	WRT_CHECK_STATUS(WR_OK, wr_image_cancel(img, &r));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&r) != NULL && cw_done_of(&r)->st == WR_E_CANCELLED);
	WRT_CHECK_STATUS(WR_E_STATE, wr_image_cancel(img, &r)); /* pulled */

	/* a write that was sent: it goes on as a zombie (a copy of the data in the core), the request is finished with WR_E_CANCELLED at once, and a later read
	 * of the same range waits for the zombie and sees the written bytes */
	cw_fill(buf, 31, 1000, 20000); /* one extent: a cancel of a write cut into several drops the extents that were not sent yet */
	r2 = cw_req(WR_IO_WRITE, 1000, 20000, buf);
	cw_done_forget(&r2);
	{
		unsigned before = held_now(&w);

		WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r2));
		WRT_CHECK(wait_held(&w, before));
	}
	WRT_CHECK_STATUS(WR_OK, wr_image_cancel(img, &r2));
	{
		wr_osd_stats st;

		wr_client_osd_stats(w.c, &st);
		WRT_CHECK(st.zombie_bytes_used > 0u && st.zombie_bytes_max >= st.zombie_bytes_used);
	}
	memset(buf, 0xCC, 300000); /* the host reuses its buffer: the zombie has its own copy */
	(void)cw_round(&w);
	WRT_CHECK(cw_done_of(&r2) != NULL && cw_done_of(&r2)->st == WR_E_CANCELLED);
	rd = cw_req(WR_IO_READ, 1000, 20000, chk);
	cw_done_forget(&rd);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &rd));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&rd) == NULL); /* it waits behind the zombie (answers are held) */
	for (j = 0; j < w.n_osd; j++) {
		sim_osd_faults(w.osd[j])->hold_replies = 0;
		(void)sim_osd_release(w.osd[j], 0);
	}
	(void)cw_settle(&w);
	cw_tick(&w, 3000);
	WRT_CHECK(cw_done_of(&rd) != NULL && cw_done_of(&rd)->st == WR_OK);
	WRT_CHECK(cw_diff(chk, 31, 1000, 20000) == 0); /* the zombie's copy was written, not the host's reused buffer */
out:
	cw_free(&w);
	free(buf);
	free(chk);
}

/* A write whose copy does not fit the zombie area: WR_E_BUSY, and the request ends by itself. */
static void test_cancel_busy(void)
{
	cw w;
	wr_config cfg;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t *buf = (uint8_t *)calloc(1, 100000);
	wr_io_req r;
	unsigned j;

	cw_cfg_default(&cfg);
	cfg.zombie_bytes = 0; /* no room for any copy */
	WRT_CHECK(cw_open(&w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->hold_replies = 1;
	cw_fill(buf, 9, 0, 50000);
	r = cw_req(WR_IO_WRITE, 0, 50000, buf);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	WRT_CHECK(wait_held(&w, 0));
	WRT_CHECK_STATUS(WR_E_BUSY, wr_image_cancel(img, &r)); /* the buffer is still referenced: the host keeps it */
	WRT_CHECK(cw_done_of(&r) == NULL);
	for (j = 0; j < w.n_osd; j++) {
		sim_osd_faults(w.osd[j])->hold_replies = 0;
		(void)sim_osd_release(w.osd[j], 0);
	}
	(void)cw_settle(&w);
	cw_tick(&w, 2000);
	WRT_CHECK(cw_done_of(&r) != NULL); /* it completes by itself: with its own result (answered first) or WR_E_CANCELLED */
	if (cw_done_of(&r) != NULL)
		WRT_CHECK(cw_done_of(&r)->st == WR_OK || cw_done_of(&r)->st == WR_E_CANCELLED);
out:
	cw_free(&w);
	free(buf);
}

/* ---- wr_image_close -------------------------------------------------------------------------------------------------------- */

static void test_close_args(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t buf[100];
	wr_io_req r;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(NULL, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, 2u));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, 0x80000000u));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPEN); /* a refused close changed nothing */
	/* a write in flight: DRAIN makes it CLOSING, a second DRAIN is nothing, ABANDON ends it */
	r = cw_req(WR_IO_WRITE, 0, sizeof(buf), buf);
	memset(buf, 1, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_CLOSING);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_CLOSING);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_ABANDON));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, WR_CLOSE_ABANDON));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	cw_tick(&w, 3000);
	WRT_CHECK(cw_done_of(&r) != NULL); /* the request completed whatever happened to the image */
	WRT_CHECK(wr_client_next_done(NULL) == NULL);
	WRT_CHECK(wr_client_next_done(w.c) == NULL);
out:
	cw_free(&w);
}

/* ---- stale handles --------------------------------------------------------------------------------------------------------- */

static void test_stale(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	wr_image_info info;
	wr_io_req r;
	wr_osd_stats st;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN) {
		cw_free(&w);
		return;
	}
	wr_client_destroy(w.c);
	r = cw_req(WR_IO_FLUSH, 0, 0, NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, cw_submit(img, &r));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_cancel(img, &r));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_close(img, WR_CLOSE_DRAIN));
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_get_info(img, &info));
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	WRT_CHECK(wr_image_error(img)->status == WR_OK);
	WRT_CHECK_U64(wr_image_slot(img), 0);
	WRT_CHECK(wr_client_next_done(w.c) == NULL && wr_client_image_at(w.c, 0) == NULL);
	WRT_CHECK_STATUS(WR_E_INVAL, wr_image_open(w.c, &p, &img));
	WRT_CHECK(img == NULL);
	memset(&st, 0xa5, sizeof(st));
	wr_client_osd_stats(w.c, &st);
	WRT_CHECK(st.ops_done == 0u && st.ops_inflight == 0u);
	wr_client_osd_stats(w.c, NULL); /* no crash */
	cw_free(&w);
}

int main(void)
{
	test_open_args();
	test_open_off();
	test_open_fail();
	test_queries();
	test_submit_args();
	test_cancel_args();
	test_cancel_busy();
	test_close_args();
	test_stale();
	return wrt_finish();
}
