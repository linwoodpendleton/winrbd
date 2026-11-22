/* SPDX-License-Identifier: MIT */
/*
 * test_fuzzlong_close_drain.c - a finding of the long fuzz run (design 40.4, target fuzz_client_osd): wr_image_close(WR_CLOSE_DRAIN) returns at once and
 * lets the writes in flight finish on the OLD handle (wr_image.h: "wait for the writes in flight to complete, then free the slot, WR_EV_IMAGE tells when").
 * The fence that orders overlapping requests is per handle, so a read on another (re)opened handle is not ordered behind a discard of the old one: it may see the
 * bytes the discard is about to remove. The fuzz target's model used to assume otherwise and trapped; this test pins what the contract says:
 *
 *   - the close returns WR_OK while the discard is in flight, the request is not finished and the close event is not there yet;
 *   - the discard completes by itself afterwards (nothing is lost with the old handle) and then the close event follows exactly once;
 *   - once the old handle has drained, a read of the new handle reads back zeros (the discard did its work).
 */
#include "client_osd_rig.h"

#define IMG_ORDER 14u
#define IMG_SIZE (1u << 20)

static void hold(cw *w, unsigned on)
{
	unsigned j;

	for (j = 0; j < w->n_osd; j++) {
		sim_osd_faults(w->osd[j])->hold_replies = (uint8_t)on;
		if (!on)
			(void)sim_osd_release(w->osd[j], 0);
	}
}

static unsigned image_events_of(const cw *w, uint32_t slot)
{
	unsigned i, n = 0;

	for (i = 0; i < w->n_ev; i++)
		n += w->ev[i].kind == WR_EV_IMAGE && w->ev[i].epoch == slot;
	return n;
}

static void test_discard_survives_drain_close(void)
{
	cw w;
	wr_image_params p;
	wr_image *a, *b;
	wr_image_state fin;
	wr_io_req wq, dq, rq;
	uint8_t buf[4096], chk[4096];
	uint32_t slot;
	unsigned ev_before;
	unsigned i;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	a = cw_open_image(&w, &p, &fin);
	WRT_CHECK(a != NULL && fin == WR_IMG_OPEN);
	if (a == NULL || fin != WR_IMG_OPEN) {
		cw_free(&w);
		return;
	}
	slot = wr_image_slot(a);
	/* the second handle of the same image is opened now: an open needs answers, and they are about to be held */
	b = cw_open_image(&w, &p, &fin);
	WRT_CHECK(b != NULL && fin == WR_IMG_OPEN);
	cw_fill(buf, 9, 624, sizeof(buf)); /* nonzero bytes at an offset that is not object aligned */
	wq = cw_req(WR_IO_WRITE, 624, sizeof(buf), buf);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, a, &wq, 20000));

	/* the discard goes out and the answers are held: it is in flight when the image is closed */
	hold(&w, 1);
	dq = cw_req(WR_IO_DISCARD, 0, 3281, NULL);
	cw_done_forget(&dq);
	WRT_CHECK_STATUS(WR_OK, cw_submit(a, &dq));
	(void)cw_round(&w);
	(void)cw_round(&w);
	WRT_CHECK(cw_done_of(&dq) == NULL);
	ev_before = image_events_of(&w, slot);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&dq) == NULL);                /* still in flight: the close did not wait for it, and did not cancel it */
	WRT_CHECK_U64(image_events_of(&w, slot), ev_before); /* the slot is not free yet: no close event */

	/* the answers come: the discard finishes on the old handle, then the close event, once */
	hold(&w, 0);
	(void)cw_settle(&w);
	for (i = 0; i < 40u && cw_done_of(&dq) == NULL; i++)
		cw_tick(&w, 500);
	WRT_CHECK(cw_done_of(&dq) != NULL && cw_done_of(&dq)->st == WR_OK);
	cw_events(&w);
	WRT_CHECK_U64(image_events_of(&w, slot), ev_before + 1u);

	if (b != NULL) { /* drained: the new handle reads zeros where the write had been */
		memset(chk, 0xEE, sizeof(chk));
		rq = cw_req(WR_IO_READ, 624, 2657, chk);
		WRT_CHECK_STATUS(WR_OK, cw_do(&w, b, &rq, 20000));
		for (i = 0; i < 2657u; i++)
			WRT_CHECK(chk[i] == 0);
		WRT_CHECK_STATUS(WR_OK, wr_image_close(b, WR_CLOSE_DRAIN));
	}
	cw_free(&w);
}

/* The same for a write and a write-zeroes in flight (the reopen of fuzz_client_secure: a write-zeroes still in flight at the close): both finish on the old
 * handle, the data is what the requests said, in the order of acceptance. */
static void test_write_and_zeroes_survive_drain_close(void)
{
	cw w;
	wr_image_params p;
	wr_image *a, *b;
	wr_image_state fin;
	wr_io_req w1, z1, rq;
	uint8_t buf[2048], chk[2048];
	unsigned i;

	WRT_CHECK(cw_open(&w, NULL, 3, 16, WR_KEY_TYPE_AES256K) == 0);
	WRT_CHECK(cw_image(&w, "img", "abc123", IMG_SIZE, IMG_ORDER, 0x21, -1) == 0);
	p = cw_params("img", 1);
	a = cw_open_image(&w, &p, &fin);
	WRT_CHECK(a != NULL && fin == WR_IMG_OPEN);
	b = a != NULL ? cw_open_image(&w, &p, &fin) : NULL;
	WRT_CHECK(b != NULL && fin == WR_IMG_OPEN);
	if (a == NULL || b == NULL) {
		cw_free(&w);
		return;
	}
	cw_fill(buf, 3, 5000, sizeof(buf));
	hold(&w, 1);
	w1 = cw_req(WR_IO_WRITE, 5000, sizeof(buf), buf);
	cw_done_forget(&w1);
	WRT_CHECK_STATUS(WR_OK, cw_submit(a, &w1));
	z1 = cw_req(WR_IO_WRITE_ZEROES, 5500, 100, NULL); /* zeroes inside the written range: the order of acceptance decides the bytes */
	cw_done_forget(&z1);
	WRT_CHECK_STATUS(WR_OK, cw_submit(a, &z1));
	(void)cw_round(&w);
	(void)cw_round(&w);
	WRT_CHECK(cw_done_of(&w1) == NULL && cw_done_of(&z1) == NULL);
	WRT_CHECK_STATUS(WR_OK, wr_image_close(a, WR_CLOSE_DRAIN));
	(void)cw_settle(&w);
	WRT_CHECK(cw_done_of(&w1) == NULL && cw_done_of(&z1) == NULL); /* neither cancelled nor finished by the close */
	hold(&w, 0);
	(void)cw_settle(&w);
	for (i = 0; i < 40u && (cw_done_of(&w1) == NULL || cw_done_of(&z1) == NULL); i++)
		cw_tick(&w, 500);
	WRT_CHECK(cw_done_of(&w1) != NULL && cw_done_of(&w1)->st == WR_OK);
	WRT_CHECK(cw_done_of(&z1) != NULL && cw_done_of(&z1)->st == WR_OK);
	memset(chk, 0xEE, sizeof(chk));
	rq = cw_req(WR_IO_READ, 5000, sizeof(chk), chk);
	WRT_CHECK_STATUS(WR_OK, cw_do(&w, b, &rq, 20000));
	for (i = 0; i < sizeof(chk); i++) {
		uint8_t want = (i >= 500u && i < 600u) ? 0u : buf[i];

		WRT_CHECK(chk[i] == want);
	}
	WRT_CHECK_STATUS(WR_OK, wr_image_close(b, WR_CLOSE_DRAIN));
	cw_free(&w);
}

int main(void)
{
	test_discard_survives_drain_close();
	test_write_and_zeroes_survive_drain_close();
	return wrt_finish();
}
