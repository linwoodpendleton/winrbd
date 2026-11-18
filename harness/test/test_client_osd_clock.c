/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_clock.c - the engine only knows the time of its last wr_client_run: a host that submits a request, opens an image or cancels
 * after a quiet period calls the engine with a clock that is old (module client-glue-osd; the whole engine of client_osd_rig.h).
 *
 *   request timeout   a request with a timeout is submitted after the clock stood still for a long time (no run in between): its timeout counts from
 *                     the next run, it is NOT expired before it was ever sent; the same request still times out when the cluster does not answer
 *   open timeout      the same for open_timeout_ms of wr_image_open (the first run of an engine is the special case: the clock was 0 before it)
 *   many requests     requests accepted in different windows between runs: each one is re-based once, by its own window, never twice
 *   stepping back     a host clock that steps back does not move any deadline
 */
#include "client_osd_rig.h"

#define IMG_ORDER 16u
#define IMG_SIZE (4u << 20)

static wr_image *open_img(cw *w)
{
	wr_image_params p = cw_params("img", 1);
	wr_image_state fin = WR_IMG_FREE;
	wr_image *img = cw_open_image(w, &p, &fin);

	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN);
	return img != NULL && fin == WR_IMG_OPEN ? img : NULL;
}

/* ---- request timeout --------------------------------------------------------------------------------------------------------- */

static void test_request_after_idle(void)
{
	cw w;
	wr_image *img;
	uint8_t buf[4096], chk[4096];
	wr_io_req r;
	unsigned j;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	img = open_img(&w);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	cw_fill(buf, 7, 5000, sizeof(buf));
	r = cw_req(WR_IO_WRITE, 5000, sizeof(buf), buf);
	r.timeout_ms = 5000;
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, img, &r, 20000)); /* a timeout that is far away: the baseline works */

	/* the host does nothing for a minute (the engine's own timers still run) ... */
	cw_tick(&w, 3000);
	w.now += 60000; /* ... and then submits with a 5 s timeout, without having called wr_client_run since the clock moved */
	memset(chk, 0, sizeof(chk));
	r = cw_req(WR_IO_READ, 5000, sizeof(chk), chk);
	r.timeout_ms = 5000;
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	(void)cw_settle(&w);
	{
		const cw_done *d = cw_done_of(&r);

		WRT_CHECK(d != NULL);
		if (d != NULL)
			WRT_CHECK_STATUS(WR_OK, d->st); /* WR_E_TIMEOUT here means the request expired against the old clock before it was sent */
	}
	WRT_CHECK_U64(cw_diff(chk, 7, 5000, sizeof(chk)), 0); /* no difference: the data is what was written */

	/* the same request still ends when the cluster is silent: the timeout was re-based, not dropped */
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1;
	cw_tick(&w, 1000);
	w.now += 30000;
	r = cw_req(WR_IO_READ, 9000, sizeof(chk), chk);
	r.timeout_ms = 5000;
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&r) == NULL); /* not expired at the first run */
	cw_tick(&w, 4000);
	WRT_CHECK(cw_done_of(&r) == NULL); /* 4 s after the run that saw it: still in time */
	cw_tick(&w, 2000);
	{
		const cw_done *d = cw_done_of(&r);

		WRT_CHECK(d != NULL);
		if (d != NULL)
			WRT_CHECK_STATUS(WR_E_TIMEOUT, d->st);
	}
	cw_free(&w);
}

/* ---- requests accepted in different windows ------------------------------------------------------------------------------------ */

static void test_many_windows(void)
{
	cw w;
	wr_image *img;
	uint8_t buf[3][512];
	wr_io_req r[3];
	unsigned j, i;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	img = open_img(&w);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1; /* nothing is ever answered: only the timeouts end the requests */
	cw_tick(&w, 500);
	/* window 1: request 0 (timeout 12 s) and request 1 (timeout 4 s), submitted together, the clock then moves 6 s before the run */
	for (i = 0; i < 3; i++) {
		memset(buf[i], 1, sizeof(buf[i]));
		r[i] = cw_req(WR_IO_READ, 100u * 1024u * (i + 1u), sizeof(buf[i]), buf[i]);
	}
	r[0].timeout_ms = 12000;
	r[1].timeout_ms = 4000;
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r[0]));
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r[1]));
	w.now += 6000;
	(void)cw_settle(&w); /* the run at +6 s: both are re-based to it */
	WRT_CHECK(cw_done_of(&r[0]) == NULL && cw_done_of(&r[1]) == NULL);
	cw_tick(&w, 3000); /* 3 s after the run: neither is due */
	WRT_CHECK(cw_done_of(&r[0]) == NULL && cw_done_of(&r[1]) == NULL);
	/* window 2: request 2 (timeout 4 s), submitted now, the clock moves another 2 s before the run */
	r[2].timeout_ms = 4000;
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r[2]));
	w.now += 2000;
	(void)cw_settle(&w); /* request 1 is 5 s old (due), request 2 is new at this run */
	WRT_CHECK(cw_done_of(&r[1]) != NULL);
	WRT_CHECK(cw_done_of(&r[0]) == NULL && cw_done_of(&r[2]) == NULL);
	cw_tick(&w, 3000); /* request 2: 3 s after its run; request 0: 8 s after its run */
	WRT_CHECK(cw_done_of(&r[2]) == NULL && cw_done_of(&r[0]) == NULL);
	cw_tick(&w, 2000); /* request 2 is due (5 s after its run, its timeout is 4 s), request 0 is not (10 s of its 12 s) */
	WRT_CHECK(cw_done_of(&r[2]) != NULL && cw_done_of(&r[0]) == NULL);
	cw_tick(&w, 3000);
	WRT_CHECK(cw_done_of(&r[0]) != NULL);
	for (i = 0; i < 3; i++) {
		const cw_done *d = cw_done_of(&r[i]);

		WRT_CHECK(d != NULL);
		if (d != NULL)
			WRT_CHECK_STATUS(WR_E_TIMEOUT, d->st);
	}
	cw_free(&w);
}

/* ---- open timeout -------------------------------------------------------------------------------------------------------------- */

static void test_open_after_idle(void)
{
	cw w;
	wr_image_params p;
	wr_image *img = NULL;
	wr_image_state fin = WR_IMG_FREE;
	unsigned j;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	(void)cw_settle(&w); /* the monitor session and the first map are in */
	cw_tick(&w, 2000);
	w.now += 90000; /* a long quiet period without a run, then the open with a 20 s timeout */
	p = cw_params("img", 1);
	p.open_timeout_ms = 20000;
	img = cw_open_image(&w, &p, &fin);
	WRT_CHECK(img != NULL && fin == WR_IMG_OPEN); /* WR_IMG_FAILED with WR_E_TIMEOUT: the open expired against the old clock */
	if (img != NULL)
		WRT_CHECK_STATUS(WR_OK, wr_image_close(img, WR_CLOSE_ABANDON));
	(void)cw_settle(&w);

	/* the open still ends when nobody answers */
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1;
	cw_tick(&w, 1000);
	w.now += 50000;
	p = cw_params("img", 1);
	p.open_timeout_ms = 8000;
	WRT_CHECK_STATUS(WR_OK, wr_image_open(w.c, &p, &img));
	(void)cw_settle(&w);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPENING);
	cw_tick(&w, 6000);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_OPENING);
	cw_tick(&w, 3000);
	WRT_CHECK(wr_image_get_state(img) == WR_IMG_FAILED);
	WRT_CHECK_U64(wr_image_error(img)->status, WR_E_TIMEOUT);
	cw_free(&w);
}

/* ---- the clock steps back ------------------------------------------------------------------------------------------------------ */

static void test_clock_back(void)
{
	cw w;
	wr_image *img;
	uint8_t buf[512];
	wr_io_req r;
	unsigned j;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	img = open_img(&w);
	if (img == NULL) {
		cw_free(&w);
		return;
	}
	for (j = 0; j < w.n_osd; j++)
		sim_osd_faults(w.osd[j])->silent = 1;
	cw_tick(&w, 1000);
	r = cw_req(WR_IO_READ, 4096, sizeof(buf), buf);
	r.timeout_ms = 6000;
	WRT_CHECK_STATUS(WR_OK, cw_submit(img, &r));
	w.now -= 5000; /* the host's clock steps back by 5 s (the engine holds its last value) */
	(void)cw_settle(&w);
	w.now += 5000;
	cw_tick(&w, 5000);
	WRT_CHECK(cw_done_of(&r) == NULL); /* 5 s after the run that saw it: not due */
	cw_tick(&w, 2000);
	{
		const cw_done *d = cw_done_of(&r);

		WRT_CHECK(d != NULL);
		if (d != NULL)
			WRT_CHECK_STATUS(WR_E_TIMEOUT, d->st);
	}
	cw_free(&w);
}

int main(void)
{
	test_request_after_idle();
	test_many_windows();
	test_open_after_idle();
	test_clock_back();
	return wrt_finish();
}
