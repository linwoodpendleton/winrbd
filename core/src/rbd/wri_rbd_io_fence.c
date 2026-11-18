/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_io_fence.c - the ordering rules of image I/O (design 25.4): the overlap fence, the flush barrier, the writer gate of the header
 * refresh, and the bookkeeping of zombie fence entries.
 *
 * The fence decides when a request leaves WAIT: only when no EARLIER request of the same image that is still in the table overlaps its range
 * and conflicts with it (two reads never conflict; everything else does). "In the table" means WAIT, RUN, and the entries a cancelled write leaves
 * behind while the engine has not answered it (ZOMBIE, or FINISH with the zombie flag until the host pulled the completion). So no request is ever
 * sent over the range of a write that may still be applied: a resend of that write can never overtake a later one (design 23.7, C10).
 *
 * The table is small (max_reqs) and every test is a linear scan. The scans run only when something that could change the answer happened
 * (the dirty bits of wri_rbd): a request arrived, finished, was cancelled, or the engine answered a zombie.
 */
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

/* An entry that still holds its range in the fence. */
static int holds_range(const wri_rbd_rq *e)
{
	return e->state == WRI_RQ_WAIT || e->state == WRI_RQ_RUN || e->state == WRI_RQ_ZOMBIE || (e->state == WRI_RQ_FINISH && e->zomb != 0);
}

static int same_image(const wri_rbd_rq *a, const wri_rbd_rq *b)
{
	return a->img == b->img && a->img_gen == b->img_gen;
}

int wri_rio_blocked(const wri_rbd *r, uint32_t slot)
{
	const wri_rbd_rq *q = &r->rq[slot];
	uint32_t i;

	for (i = 0; i < r->n_rq; i++) {
		const wri_rbd_rq *e = &r->rq[i];

		if (i == slot || !holds_range(e) || !same_image(e, q) || e->seq >= q->seq || e->kind == (uint8_t)WR_IO_FLUSH)
			continue;
		if (e->kind == (uint8_t)WR_IO_READ && q->kind == (uint8_t)WR_IO_READ)
			continue; /* two reads never conflict */
		if (wri_rbd_overlap(e->off, e->len, q->off, q->len))
			return 1;
	}
	return 0;
}

/* A writer admits writes only while its last header refresh is younger than hdr_refresh_ms (design 24.4); the first write after an idle period
 * waits one round trip for a fresh snapshot context. While a refresh is pending (wri_rbd_open_refresh_now after an -EOLDSNAPC answer, or one that is due)
 * writes wait for it whatever hdr_refresh_ms is, so also with hdr_refresh_ms 0, where only the on-demand refresh exists. Reads, flushes and an image that
 * is closing are not held. */
int wri_rio_gate_closed(const wri_rbd *r, const wri_rbd_img *im)
{
	uint32_t period = r->x->cfg.hdr_refresh_ms;

	if (im->state != (uint8_t)WR_IMG_OPEN || !im->writable)
		return 0;
	if (im->ros == (uint8_t)WRI_ROS_REFRESH)
		return 1;
	if (period == 0 || im->next_refresh_ms == WR_DEADLINE_NONE)
		return 0;
	return r->x->now.mono_ms - im->refreshed_ms >= period;
}

void wri_rio_admit(wri_rbd *r)
{
	uint32_t i;

	if ((r->dirty & WRI_RIO_DIRTY_ADMIT) == 0)
		return;
	r->dirty &= ~WRI_RIO_DIRTY_ADMIT;
	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];
		const wri_rbd_img *im;

		if (q->state != WRI_RQ_WAIT)
			continue;
		im = wri_rio_img(r, q);
		if (im == NULL)
			continue; /* its image is gone: the image's failure completes it */
		if (wri_rio_is_write(q->kind) && wri_rio_gate_closed(r, im)) {
			r->dirty |= WRI_RIO_DIRTY_ADMIT; /* the refresh ends without a signal of ours: look again next pass */
			continue;
		}
		if (wri_rio_blocked(r, i))
			continue;
		q->state = WRI_RQ_RUN;
		q->cur = q->off;
	}
}

/* ---- zombies and flushes ------------------------------------------------------------------------------------------------ */

uint32_t wri_rio_live_ops(const wri_rbd *r, uint32_t tag)
{
	const wri_osdc *o = r->osd;
	uint32_t i, n = 0;

	for (i = 0; i < o->n_op; i++) {
		const wri_osd_op *op = &o->op[i];

		if (op->state == WRI_OP_FREE || op->state == WRI_OP_DONE || (op->flags & WRI_OPF_CONTROL) != 0)
			continue;
		if (op->owner == tag)
			n++;
	}
	return n;
}

static void settle_zombies(wri_rbd *r)
{
	uint32_t i;

	if ((r->dirty & WRI_RIO_DIRTY_ZOMB) == 0 && r->osd->n_zombies_done == r->zd_seen)
		return;
	r->dirty &= ~WRI_RIO_DIRTY_ZOMB;
	r->zd_seen = r->osd->n_zombies_done;
	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];

		if (q->state != WRI_RQ_ZOMBIE && !(q->state == WRI_RQ_FINISH && q->zomb != 0))
			continue;
		if (wri_rio_live_ops(r, WRI_RBD_TAG(i, q->gen)) != 0)
			continue;
		/* every operation the request handed over has been answered: the range is free again */
		if (q->state == WRI_RQ_ZOMBIE)
			wri_rio_free(r, i);
		else
			q->zomb = 0;
		r->dirty |= WRI_RIO_DIRTY_ADMIT;
	}
}

/* 1 if a write that is older than flush `q` has not completed yet (zombies are excluded: they completed towards the host). */
static int barrier_pending(const wri_rbd *r, const wri_rbd_rq *q)
{
	uint32_t i;

	for (i = 0; i < r->n_rq; i++) {
		const wri_rbd_rq *e = &r->rq[i];

		if ((e->state == WRI_RQ_WAIT || e->state == WRI_RQ_RUN) && wri_rio_is_write(e->kind) && same_image(e, q) && e->seq < q->seq)
			return 1;
	}
	return 0;
}

static void settle_flushes(wri_rbd *r)
{
	uint32_t i;

	if ((r->dirty & WRI_RIO_DIRTY_BARRIER) == 0)
		return;
	r->dirty &= ~WRI_RIO_DIRTY_BARRIER;
	for (i = 0; i < r->n_rq; i++) {
		const wri_rbd_rq *q = &r->rq[i];

		if (q->state == WRI_RQ_RUN && q->kind == (uint8_t)WR_IO_FLUSH && !barrier_pending(r, q))
			wri_rio_finish(r, i, WR_OK);
	}
}

void wri_rio_settle(wri_rbd *r)
{
	settle_zombies(r);
	settle_flushes(r);
}
