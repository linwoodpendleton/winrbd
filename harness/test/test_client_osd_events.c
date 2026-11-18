/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_events.c - the events of the OSD client and the image layer, and key hygiene on the OSD paths, on the whole engine (module
 * client-glue-osd; client_osd_rig.h plays the host through the public API).
 *
 *   WR_EV_IMAGE        raised for an open, a failed open (err says why), a close, and a change the header refresh adopts (a resize, a new snapshot); the
 *                      event's epoch field is the image slot, the same number as wr_image_slot
 *   WR_EV_IO_STALL     an OSD that never answers: after the operation timeout the session is reset, ONE stall is raised (err WR_E_TIMEOUT, a0 = the OSD id,
 *                      epoch field 0), and ONE WR_EV_IO_RESUME when the first answer comes; the write was never abandoned and completes OK
 *   fatal              the engine ends (the random source fails when the monitor session is re-established): WR_EV_FATAL, every image FAILED with the
 *                      engine's status, the requests in flight complete with it, an open is WR_E_STATE afterwards
 *   event ring         a burst that overflows the ring (a failing engine fails every image in one run): image events outlive the informational ones, the
 *                      newest image events are what stays when only image events are left, a fatal or a map event is never lost
 *   key canary         a printable key through whole sessions with OSD connections of both key types (an OSD that refuses the authorizer included, restarts,
 *                      stalls): no log record, event or errinfo carries the key, the key never travels, the arena holds it while the client lives and
 *                      is all zero after wr_client_destroy, the bulk region holds no key byte
 */
#include "client_osd_rig.h"

#define IMG_ORDER 16u
#define IMG_SIZE (4u << 20)

static unsigned count_slot_ev(const cw *w, wr_ev_kind k, uint32_t slot)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_ev; i++)
		n += w->ev[i].kind == k && w->ev[i].epoch == slot;
	return n;
}

/* ---- WR_EV_IMAGE ------------------------------------------------------------------------------------------------------------ */

static void test_image_events(void)
{
	cw w;
	wr_image_params p;
	wr_image *img, *bad;
	wr_image_state fin;
	wr_image_info info;
	const wr_event *e;
	uint32_t slot;
	unsigned n;
	uint64_t snaps[2] = {5, 3};

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN) {
		cw_free(&w);
		return;
	}
	slot = wr_image_slot(img);
	e = cw_last_ev(&w, WR_EV_IMAGE);
	WRT_CHECK(e != NULL && e->epoch == slot && e->err.status == WR_OK);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IMAGE), 1);

	/* a second image that cannot open: its own slot, its own error */
	p = cw_params("nosuch", 1);
	bad = cw_open_image(&w, &p, &fin);
	WRT_CHECK(bad != NULL && fin == WR_IMG_FAILED);
	if (bad != NULL) {
		WRT_CHECK(wr_image_slot(bad) != slot);
		WRT_CHECK_U64(count_slot_ev(&w, WR_EV_IMAGE, wr_image_slot(bad)), 1);
		e = cw_last_ev(&w, WR_EV_IMAGE);
		WRT_CHECK(e != NULL && e->epoch == wr_image_slot(bad) && e->err.status == WR_E_RBD_NOT_FOUND);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(bad, WR_CLOSE_DRAIN));
		cw_events(&w);
		WRT_CHECK_U64(count_slot_ev(&w, WR_EV_IMAGE, wr_image_slot(bad)), 2); /* the close */
	}

	/* the image grows and gets a snapshot behind our back: the writer's header refresh (hdr_refresh_ms = 2 s) adopts both and says so */
	n = cw_count_ev(&w, WR_EV_IMAGE);
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_size(w.store, CW_POOL, "abc123", 2u * IMG_SIZE));
	WRT_CHECK_STATUS(WR_OK, sim_rbd_image_set_snapc(w.store, CW_POOL, "abc123", 5, snaps, 2));
	cw_tick(&w, 5000);
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info));
	WRT_CHECK_U64(info.size_bytes, 2u * IMG_SIZE);
	WRT_CHECK_U64(info.snap_seq, 5);
	WRT_CHECK_U64(info.n_snaps, 2);
	WRT_CHECK(cw_count_ev(&w, WR_EV_IMAGE) > n); /* the layer said something changed */
	e = cw_last_ev(&w, WR_EV_IMAGE);
	WRT_CHECK(e != NULL && e->epoch == slot && e->err.status == WR_OK);
	{
		wr_io_req r;
		uint8_t b[16];

		memset(b, 7, sizeof(b));
		r = cw_req(WR_IO_WRITE, 2u * IMG_SIZE - 16u, 16, b); /* the new end of the image is writable now */
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000));
	}

	n = cw_count_ev(&w, WR_EV_IMAGE);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IMAGE), n + 1);
	e = cw_last_ev(&w, WR_EV_IMAGE);
	WRT_CHECK(e != NULL && e->epoch == slot);
	cw_free(&w);
}

/* ---- stall and resume ------------------------------------------------------------------------------------------------------- */

static int write_done(void *a)
{
	return cw_done_of((const wr_io_req *)a) != NULL;
}

static void test_stall_resume(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t *buf = (uint8_t *)malloc(30000), *chk = (uint8_t *)malloc(30000);
	wr_io_req r, rd;
	unsigned j, k;
	const wr_event *st = NULL, *re = NULL;
	wr_osd_stats os;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_STALL), 0);
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1; /* the OSDs read and do nothing: no answer, ever */
	cw_fill(buf, 12, 4096, 30000);
	r = cw_req(WR_IO_WRITE, 4096, 30000, buf);
	cw_done_forget(&r);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	(void)cw_settle(&w);
	cw_tick(&w, 4000); /* inside the first timeout (5 s): nothing yet */
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_STALL), 0);
	cw_tick(&w, 3000); /* past it: the session is reset and the stall is raised once */
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_STALL), 1);
	st = cw_last_ev(&w, WR_EV_IO_STALL);
	WRT_CHECK(st != NULL && st->err.status == WR_E_TIMEOUT && st->epoch == 0u);
	WRT_CHECK(st != NULL && st->err.a0 < w.n_osd);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_RESUME), 0);
	wr_client_osd_stats(w.c, &os);
	WRT_CHECK(os.n_session_resets >= 1u);
	cw_tick(&w, 20000); /* more timeouts, resets, resends: still ONE stall until something is answered */
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_STALL), 1);
	WRT_CHECK(cw_done_of(&r) == NULL); /* a sent write is never given up */
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 0;
	WRT_CHECK(cw_until(&w, write_done, &r, 60000));
	WRT_CHECK(cw_done_of(&r) != NULL && cw_done_of(&r)->st == WR_OK);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_RESUME), 1);
	re = cw_last_ev(&w, WR_EV_IO_RESUME);
	WRT_CHECK(re != NULL && re->epoch == 0u);
	/* the order: the stall came first */
	for (k = 0; k < w.n_ev; k++) {
		if (w.ev[k].kind == WR_EV_IO_STALL)
			break;
		WRT_CHECK(w.ev[k].kind != WR_EV_IO_RESUME);
	}
	WRT_CHECK(k < w.n_ev);
	/* the data is there */
	rd = cw_req(WR_IO_READ, 4096, 30000, chk);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &rd, 20000));
	WRT_CHECK(cw_diff(chk, 12, 4096, 30000) == 0);
	/* an answered engine does not stall again by itself */
	cw_tick(&w, 30000);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_STALL), 1);
	WRT_CHECK_U64(cw_count_ev(&w, WR_EV_IO_RESUME), 1);
out:
	cw_free(&w);
	free(buf);
	free(chk);
}

/* ---- the engine ends ---------------------------------------------------------------------------------------------------------- */

static void test_fatal(void)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t *buf = (uint8_t *)malloc(200000);
	wr_io_req r, late;
	unsigned j;
	const wr_event *ev;
	wr_image_info info;
	wr_image *img2 = NULL;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	if (img == NULL || fin != WR_IMG_OPEN)
		goto out;
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->hold_replies = 1;
	memset(buf, 3, 200000);
	r = cw_req(WR_IO_WRITE, 0, 200000, buf);
	cw_done_forget(&r);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&r) == NULL);
	w.fail_random = 1; /* from now on the host cannot give randomness: the monitor session is re-established, and that needs some */
	sim_mon_restart(w.mon);
	cw_tick(&w, 3000);
	WRT_CHECK(wr_client_get_state(w.c) == WR_CS_FAILED);
	ev = cw_last_ev(&w, WR_EV_FATAL);
	WRT_CHECK(ev != NULL && ev->err.status == WR_E_HOST_RANDOM);
	/* the image ended with the engine, the request with it */
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FAILED);
	WRT_CHECK_U64(wr_image_error(img)->status, WR_E_HOST_RANDOM);
	WRT_CHECK(cw_done_of(&r) != NULL && cw_done_of(&r)->st == WR_E_HOST_RANDOM);
	WRT_CHECK(count_slot_ev(&w, WR_EV_IMAGE, wr_image_slot(img)) >= 2u && cw_last_ev(&w, WR_EV_IMAGE)->err.status == WR_E_HOST_RANDOM);
	WRT_CHECK_STATUS(WR_OK, wr_image_get_info(img, &info)); /* it had been open: the last values */
	WRT_CHECK_U64(info.size_bytes, IMG_SIZE);
	late = cw_req(WR_IO_FLUSH, 0, 0, NULL);
	WRT_CHECK_STATUS(WR_E_RBD_CLOSED, cw_submit(img, &late));
	p = cw_params("img", 0);
	WRT_CHECK_STATUS(WR_E_STATE, wr_image_open(w.c, &p, &img2));
	WRT_CHECK(img2 == NULL);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_DRAIN)); /* the host can still let go of it */
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FREE);
	/* the engine does nothing any more: no new connection is asked for */
	{
		unsigned c0 = w.n_connects;

		cw_tick(&w, 20000);
		WRT_CHECK_U64(w.n_connects, c0);
	}
out:
	cw_free(&w);
	free(buf);
}

/* ---- the key canary ------------------------------------------------------------------------------------------------------------- */

static int count_key_in(const uint8_t *base, size_t n, const wr_key *k)
{
	return cw_contains(base, n, k->secret, k->len < 8u ? k->len : 8u);
}

static void canary_case(unsigned key_type)
{
	cw w;
	wr_image_params p;
	wr_image *img;
	wr_image_state fin;
	uint8_t *buf = (uint8_t *)malloc(300000), *chk = (uint8_t *)malloc(300000);
	wr_io_req r;
	unsigned j;
	size_t k, nonzero = 0;

	g_cw_canary = "CANARYKEY-0123456789-ABCDEFGHIJ";
	WRT_CHECK(cw_open(&w, NULL, 3, 16, key_type) == 0);
	g_cw_canary = NULL;
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	/* the positive control: the scan can see the key while the client holds it */
	WRT_CHECK(count_key_in(w.arena_base, w.req.arena, &w.mcfg.key));
	/* one OSD refuses the authorizer for a while (a key without OSD caps): errors on the OSD path, nothing in them is the key */
	sim_osd_faults(w.osd[1])->refuse_auth = 1;
	p = cw_params("img", 1);
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	cw_tick(&w, 3000);
	cw_fill(buf, 17, 0, 300000);
	for (k = 0; k < 8u; k++) {
		r = cw_req(WR_IO_WRITE, k * 400000u, 300000, buf);
		(void)cw_do(&w, img, &r, 3000); /* may stall behind the refusing OSD: no verdict needed here */
	}
	sim_osd_faults(w.osd[1])->refuse_auth = 0;
	cw_tick(&w, 30000);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPEN);
	r = cw_req(WR_IO_READ, 0, 300000, chk);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 60000));
	/* restarts of the OSDs and of the monitor (a reclaim), a stall */
	for (j = 0; j < w.n_osd; j++)
		sim_osd_restart(w.osd[j]);
	sim_mon_restart(w.mon);
	cw_tick(&w, 20000);
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1;
	r = cw_req(WR_IO_WRITE, 0, 4096, buf);
	cw_done_forget(&r);
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	cw_tick(&w, 12000);
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 0;
	cw_tick(&w, 30000);
	WRT_CHECK(w.n_log > 0u);
	WRT_CHECK_U64(w.n_leak_log, 0);
	WRT_CHECK_U64(w.n_leak_wire, 0);
	WRT_CHECK_U64(w.n_leak_ev, 0);
	WRT_CHECK(w.n_connects_osd > 3u); /* the OSD paths were really exercised */
	WRT_CHECK(count_key_in(w.arena_base, w.req.arena, &w.mcfg.key)); /* still held */
	wr_client_destroy(w.c);
	for (k = 0; k < w.req.arena; k++)
		nonzero += w.arena_base[k] != 0u;
	WRT_CHECK_U64(nonzero, 0);
	WRT_CHECK(!count_key_in(w.bulk_base, w.req.bulk, &w.mcfg.key));
	w.c = NULL;
	cw_free(&w);
	free(buf);
	free(chk);
}

static void test_canary(void)
{
	canary_case(WR_KEY_TYPE_AES256K);
	canary_case(WR_KEY_TYPE_AES);
}

/* ---- the event ring under a burst -------------------------------------------------------------------------------------------------- */

static void test_event_ring(void)
{
	cw w;
	wr_event e;
	unsigned i, n_img = 0, n_ren = 0, last_slot = 0;
	wr_errinfo none;

	memset(&none, 0, sizeof(none));
	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	while (wr_client_next_event(w.c, &e))
		; /* nothing queued yet; drop what the create left (none) */
	/* informational events fill the ring, then five image events arrive: the informational ones make room, every image event stays */
	for (i = 0; i < WRI_EVENT_RING; i++)
		wri_client_push_event(w.c, WR_EV_TICKETS_RENEWED, 0, &none);
	for (i = 0; i < 5; i++)
		wri_client_push_event(w.c, WR_EV_IMAGE, i, &none);
	while (wr_client_next_event(w.c, &e)) {
		n_img += e.kind == WR_EV_IMAGE;
		n_ren += e.kind == WR_EV_TICKETS_RENEWED;
	}
	WRT_CHECK_U64(n_img, 5);
	WRT_CHECK_U64(n_ren, WRI_EVENT_RING - 5u);
	/* a map event and a fatal one in between are kept too, and nine image events leave the newest eight at most */
	wri_client_push_event(w.c, WR_EV_MAP, 7, &none);
	for (i = 0; i < 9; i++)
		wri_client_push_event(w.c, WR_EV_IMAGE, i, &none);
	wri_client_push_event(w.c, WR_EV_TICKETS_RENEWED, 0, &none); /* informational with a ring of protected events: lost, not queued */
	n_img = 0;
	{
		unsigned n_map = 0, total = 0;

		while (wr_client_next_event(w.c, &e)) {
			total++;
			n_map += e.kind == WR_EV_MAP;
			if (e.kind == WR_EV_IMAGE) {
				n_img++;
				last_slot = e.epoch;
			}
			WRT_CHECK(e.kind != WR_EV_TICKETS_RENEWED);
		}
		WRT_CHECK_U64(n_map, 1);
		WRT_CHECK_U64(total, WRI_EVENT_RING);
		WRT_CHECK_U64(n_img, WRI_EVENT_RING - 1u);
		WRT_CHECK_U64(last_slot, 8); /* the newest image event is there */
	}
	cw_free(&w);
}

int main(void)
{
	test_image_events();
	test_event_ring();
	test_stall_resume();
	test_fatal();
	test_canary();
	return wrt_finish();
}
