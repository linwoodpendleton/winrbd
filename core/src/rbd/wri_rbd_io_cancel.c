/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_io_cancel.c - the ways a request ends without its answers: a failure of one extent, a timeout, the host's cancel, the failure or the
 * close of its image (design 25.5, 25.7).
 *
 * The rules come from the object engine (design 23.9): a read is dropped, a write that never left is dropped, a write that was sent is not
 * abandoned: the engine copies its data and goes on resending it as a zombie. The request itself then completes at once and leaves a fence entry
 * behind (wri_rbd_io_fence.c), so a retry of the same range waits until the zombie is answered. One case does not finish at once: the zombie
 * area has no room for the copy (the engine answers WR_E_BUSY and changes nothing). The request then keeps running, stops cutting, is marked
 * `cancelling`, and every pass of the layer tries the cancel again; it ends with its cancellation as soon as the area has room, or with its
 * own result if its operations are answered first.
 */
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

/* Cancel every live object operation of a request (the data operations of this request only; control operations are the open machine's). Returns
 * how many could not be cancelled (the zombie area is full). Operations that became zombies leave the request's accounts (they will be applied); dropped ones
 * are answered with WR_E_CANCELLED into the done ring and are accounted for by `collect` (or ignored, if the request is over by then). An operation that was
 * dropped will never be applied, so a request that goes on after dropping one (the others could not be cancelled yet) can no longer end with success:
 * `st`, what the cancel ends the request with, becomes its first failure now. */
static uint32_t cancel_ops(wri_rbd *r, uint32_t slot, wr_status st)
{
	wri_rbd_rq *q = &r->rq[slot];
	wri_osdc *o = r->osd;
	uint32_t tag = WRI_RBD_TAG(slot, q->gen), i, busy = 0;

	for (i = 0; i < o->n_op; i++) {
		wri_osd_op *op = &o->op[i];
		uint32_t bytes;
		wr_status cst;

		if (op->state == WRI_OP_FREE || op->state == WRI_OP_DONE || (op->flags & (WRI_OPF_CONTROL | WRI_OPF_ZOMBIE)) != 0 || op->owner != tag)
			continue;
		bytes = op->data_len + op->out_cap;
		cst = wri_osdc_cancel(o, i);
		if (cst == WR_E_BUSY) {
			busy++;
			continue;
		}
		if (cst == WR_OK && (op->flags & WRI_OPF_ZOMBIE) == 0 && q->status == WR_OK)
			q->status = st; /* dropped: it never reached the cluster and never will */
		if (cst == WR_OK && (op->flags & WRI_OPF_ZOMBIE) != 0) {
			/* nobody will tell us when it is answered: the fence entry watches it (wri_rio_live_ops) */
			if (q->zops != 0xffffu)
				q->zops++;
			if (q->ops_out != 0)
				q->ops_out--;
			q->bytes_out = q->bytes_out > bytes ? q->bytes_out - bytes : 0u;
		}
	}
	return busy;
}

void wri_rio_fail(wri_rbd *r, uint32_t slot, wr_status st)
{
	wri_rbd_rq *q = &r->rq[slot];

	if (q->state != WRI_RQ_WAIT && q->state != WRI_RQ_RUN)
		return;
	if (q->status == WR_OK)
		q->status = st;
	q->cur = q->off + q->len; /* nothing more is cut */
	if (q->kind == (uint8_t)WR_IO_READ && q->ops_out != 0) {
		/* a failed read is not exposed to anybody: its other extents are dropped now instead of waited for (a read never needs room anywhere) */
		(void)cancel_ops(r, slot, q->status);
		q->ops_out = 0;
		q->bytes_out = 0;
	}
	if (q->ops_out == 0)
		wri_rio_finish(r, slot, q->status);
}

wr_status wri_rio_cancel_rq(wri_rbd *r, uint32_t slot, wr_status st)
{
	wri_rbd_rq *q = &r->rq[slot];
	int uncut;

	if (q->state != WRI_RQ_WAIT && q->state != WRI_RQ_RUN)
		return WR_E_STATE;
	if (q->state == WRI_RQ_WAIT) {
		wri_rio_finish(r, slot, st); /* nothing of it left the layer */
		return WR_OK;
	}
	uncut = q->cur < q->off + q->len;
	if (cancel_ops(r, slot, st) != 0) {
		/* the copy of a sent write does not fit the zombie area: the request keeps running and is cancelled by itself later */
		q->cancelling = 1;
		q->done_next = (uint32_t)st; /* what it ends with when the cancel goes through */
		if (uncut) {
			q->cur = q->off + q->len; /* its other extents are never sent: the result cannot be success any more */
			if (q->status == WR_OK)
				q->status = st;
		}
		return WR_E_BUSY;
	}
	wri_rio_finish(r, slot, st);
	return WR_OK;
}

void wri_rio_retry_cancels(wri_rbd *r)
{
	uint32_t i;

	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];

		if (q->state != WRI_RQ_RUN || !q->cancelling)
			continue;
		if (cancel_ops(r, i, (wr_status)(int32_t)q->done_next) == 0)
			wri_rio_finish(r, i, (wr_status)(int32_t)q->done_next);
	}
}

/* ---- the host's calls --------------------------------------------------------------------------------------------------- */

wr_status wri_rbd_cancel(wri_rbd *r, uint32_t img, wr_io_req *req)
{
	wri_rbd_rqpriv pv;
	wri_rbd_rq *q;
	wr_status st;

	if (r == NULL || req == NULL || r->img == NULL || img >= r->n_img)
		return WR_E_INVAL;
	WR_MEMCPY(&pv, req->priv, sizeof(pv));
	if (pv.used != WRI_RBD_PRIV_MAGIC || pv.slot >= r->n_rq || pv.img != img)
		return WR_E_STATE; /* never submitted, or already pulled */
	q = &r->rq[pv.slot];
	if (q->gen != pv.gen || q->req != req)
		return WR_E_STATE;
	st = wri_rio_cancel_rq(r, pv.slot, WR_E_CANCELLED); /* WR_E_STATE: finished already, the completion waits to be pulled */
	wri_rio_settle(r);
	return st;
}

void wri_rbd_io_timeouts(wri_rbd *r, uint64_t *deadline)
{
	uint64_t now;
	uint32_t i;

	if (r == NULL || r->rq == NULL)
		return;
	now = r->x->now.mono_ms;
	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];

		if ((q->state != WRI_RQ_WAIT && q->state != WRI_RQ_RUN) || q->cancelling || q->deadline_ms == WR_DEADLINE_NONE)
			continue;
		if (q->deadline_ms <= now)
			(void)wri_rio_cancel_rq(r, i, WR_E_TIMEOUT); /* WR_E_BUSY: it ends by itself, see the head of this file */
		else if (deadline != NULL && q->deadline_ms < *deadline)
			*deadline = q->deadline_ms;
	}
	wri_rio_retry_cancels(r);
	wri_rio_settle(r);
}

void wri_rbd_io_fail_image(wri_rbd *r, uint32_t img, wr_status st, uint32_t close_flags)
{
	uint32_t i;
	int drain = close_flags == WR_CLOSE_DRAIN;

	if (r == NULL || r->rq == NULL || img >= r->n_img)
		return;
	for (i = 0; i < r->n_rq; i++) {
		wri_rbd_rq *q = &r->rq[i];

		if (q->img != img || q->img_gen != r->img[img].gen)
			continue;
		if (q->state != WRI_RQ_WAIT && q->state != WRI_RQ_RUN)
			continue;
		/* DRAIN lets the writes finish (and the flushes that wait for them); everything else is over */
		if (drain && (wri_rio_is_write(q->kind) || q->kind == (uint8_t)WR_IO_FLUSH))
			continue;
		(void)wri_rio_cancel_rq(r, i, st);
	}
	if (!drain) {
		/* ABANDON: the image's slot goes, and with it the fence: the entries of zombie writes are released (the engine keeps resending them) */
		for (i = 0; i < r->n_rq; i++) {
			wri_rbd_rq *q = &r->rq[i];

			if (q->img != img || q->img_gen != r->img[img].gen)
				continue;
			if (q->state == WRI_RQ_ZOMBIE)
				wri_rio_free(r, i);
			else if (q->state == WRI_RQ_FINISH)
				q->zomb = 0;
		}
	}
	r->dirty |= WRI_RIO_DIRTY_ADMIT | WRI_RIO_DIRTY_BARRIER;
	wri_rio_settle(r);
}
