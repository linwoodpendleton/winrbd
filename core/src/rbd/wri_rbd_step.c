/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_step.c - the image layer's pass of one engine run (design 27), after wri_osdc_step: the open and refresh machines, the collection of finished
 * operations into their requests, the fatal answers of the I/O half, the admission and cutting of requests, and the request timeouts.
 *
 * It lives in its own file (module client-glue-osd) so that the two halves of the layer, rbd-open and rbd-io, stay testable apart: their rigs run the same
 * calls in the same order. The order matters: the open machine runs first (it may submit a control read or adopt a header the cutting must see), the
 * collection pops every finished operation (a control read is left DONE for the open machine, which takes it in the next pass: it reports `more`), a
 * fatal answer of the I/O half (blocklisted) fails its image before anything more is cut, and the cutting and the timeouts come last.
 */
#include "wri_rbd_io.h"
#include "wri_rbd_open.h"

WR_FILE_LICENCE_MIT

int wri_rbd_step(wri_rbd *r, uint32_t budget, uint64_t *deadline)
{
	uint64_t local = WR_DEADLINE_NONE;
	uint64_t *dl = deadline != NULL ? deadline : &local;
	uint32_t img;
	wr_status st;
	int more;

	if (r == NULL || r->img == NULL || r->osd == NULL || r->x == NULL)
		return 0;
	more = wri_rbd_open_step(r, dl);
	more |= wri_rbd_io_collect(r) != 0u;
	while (wri_rbd_io_take_fatal(r, &img, &st)) {
		wr_errinfo why;

		WR_MEMSET(&why, 0, sizeof(why));
		WRI_ERRINFO(&why, st, WR_MOD_RBD, "the cluster refuses this client", img, 0, 0);
		wri_rbd_img_fail(r, img, &why);
		more = 1;
	}
	more |= wri_rbd_io_cut(r, budget);
	wri_rbd_io_timeouts(r, dl);
	return more != 0;
}
