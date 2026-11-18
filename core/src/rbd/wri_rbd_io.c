/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_io.c - the host-facing side of image I/O: submit with its checks, the completion ring (wri_rbd_next_done), and the collection of finished
 * object operations into their requests (design 25.1, 25.3, 25.7).
 *
 * A request is accepted into the table and nothing else happens at once: the fence admits it (wri_rbd_io_fence.c), the cutting loop turns it into
 * object operations as the engine has room (wri_rbd_io_split.c), and `collect` applies each answer to its request: a read result is the data
 * (a short answer zero-fills the rest of its extent, a missing object zero-fills all of it), anything else is an error and the first one is the
 * request's status. The host's structure is touched only here: its priv words at submit and, when the completion is pulled, the status.
 */
#include "wri_rbd_io.h"

#include "wri_rbd_open.h"

WR_FILE_LICENCE_MIT

/* The priv words are read and written as a whole (no struct is laid over them: the host's array has another effective type). */
static void priv_get(const wr_io_req *req, wri_rbd_rqpriv *pv)
{
	WR_MEMCPY(pv, req->priv, sizeof(*pv));
}

static void priv_put(wr_io_req *req, const wri_rbd_rqpriv *pv)
{
	WR_MEMSET(req->priv, 0, sizeof(req->priv));
	WR_MEMCPY(req->priv, pv, sizeof(*pv));
}

/* ---- submit -------------------------------------------------------------------------------------------------------------- */

/* The submit-time errors that need no table slot, in the order of design 25.7. WR_OK if the request may be queued. */
static wr_status check_request(const wri_rbd *r, const wri_rbd_img *im, const wr_io_req *req)
{
	wri_rbd_rqpriv pv;
	unsigned kind = (unsigned)req->kind;

	priv_get(req, &pv);
	if (pv.used == WRI_RBD_PRIV_MAGIC)
		return WR_E_INVAL; /* the structure is a request the core still owns */
	if (kind < (unsigned)WR_IO_READ || kind > (unsigned)WR_IO_WRITE_ZEROES)
		return WR_E_INVAL;
	if ((kind == (unsigned)WR_IO_READ || kind == (unsigned)WR_IO_WRITE) && req->buf == NULL)
		return WR_E_INVAL;
	if (im->state != (uint8_t)WR_IMG_OPEN)
		return im->state == (uint8_t)WR_IMG_FAILED || im->state == (uint8_t)WR_IMG_CLOSING ? WR_E_RBD_CLOSED : WR_E_STATE;
	if (wri_rio_is_write((uint8_t)kind) && !im->writable)
		return WR_E_RBD_READONLY;
	if ((kind == (unsigned)WR_IO_READ || kind == (unsigned)WR_IO_WRITE) && req->length > WRI_RBD_IO_MAX)
		return WR_E_TOOBIG;
	if (kind != (unsigned)WR_IO_FLUSH && (req->offset > im->size || req->length > im->size - req->offset))
		return WR_E_RANGE;
	(void)r;
	return WR_OK;
}

/* The host's priv words of an accepted request. */
WRI_RIO_NOINLINE static void mark_priv(wr_io_req *req, uint32_t img, uint32_t slot, uint16_t gen)
{
	wri_rbd_rqpriv pv;

	WR_MEMSET(&pv, 0, sizeof(pv));
	pv.img = (uint16_t)img;
	pv.slot = (uint16_t)slot;
	pv.gen = gen;
	pv.used = WRI_RBD_PRIV_MAGIC;
	priv_put(req, &pv);
}

/* The counters that follow from an accepted request. */
WRI_RIO_NOINLINE static void count_accepted(wri_rbd *r, wri_rbd_img *im, uint8_t kind)
{
	r->reqs_inflight++;
	if (r->reqs_inflight > r->reqs_hiwater)
		r->reqs_hiwater = r->reqs_inflight;
	r->n_submitted++;
	im->n_reqs++;
	if (wri_rio_is_write(kind))
		im->n_writes_unfinished++; /* until it finishes: the flush barrier counts these */
}

/* The table entry of an accepted request. */
WRI_RIO_NOINLINE static void accept_req(wri_rbd *r, wri_rbd_img *im, uint32_t img, uint32_t slot, wr_io_req *req)
{
	wri_rbd_rq *q = &r->rq[slot];
	int flush = req->kind == WR_IO_FLUSH;

	r->rq_free = q->link;
	q->link = WRI_NIL;
	q->req = req;
	q->img = (uint16_t)img;
	q->img_gen = im->gen;
	q->kind = (uint8_t)req->kind;
	q->seq = im->seq++;
	q->status = WR_OK;
	q->off = flush ? 0u : req->offset;
	q->len = flush ? 0u : req->length;
	q->cur = q->off;
	q->deadline_ms = req->timeout_ms != 0 ? r->x->now.mono_ms + req->timeout_ms : WR_DEADLINE_NONE;
	mark_priv(req, img, slot, q->gen);
	count_accepted(r, im, q->kind);
}

wr_status wri_rbd_submit(wri_rbd *r, uint32_t img, wr_io_req *req)
{
	wri_rbd_img *im;
	wri_rbd_rq *q;
	uint32_t slot;
	wr_status st;

	if (r == NULL || req == NULL || r->img == NULL || img >= r->n_img)
		return WR_E_INVAL;
	im = &r->img[img];
	if (im->state == (uint8_t)WR_IMG_FREE)
		return WR_E_INVAL;
	st = check_request(r, im, req);
	if (st != WR_OK)
		return st;
	slot = r->rq_free;
	if (slot == WRI_NIL)
		return WR_E_BUSY;
	accept_req(r, im, img, slot, req);
	q = &r->rq[slot];
	if (q->kind == (uint8_t)WR_IO_FLUSH) {
		q->state = WRI_RQ_RUN; /* admitted at once; it completes when the writes before it did */
		if (im->n_writes_unfinished == 0)
			wri_rio_finish(r, slot, WR_OK);
		else
			r->dirty |= WRI_RIO_DIRTY_BARRIER;
	} else if (q->len == 0) {
		q->state = WRI_RQ_WAIT;
		wri_rio_finish(r, slot, WR_OK); /* nothing to do: completes at once */
	} else {
		q->state = WRI_RQ_WAIT;
		r->dirty |= WRI_RIO_DIRTY_ADMIT;
	}
	return WR_OK;
}

/* ---- completion ---------------------------------------------------------------------------------------------------------- */

wr_io_req *wri_rbd_next_done(wri_rbd *r)
{
	wri_rbd_rq *q;
	wr_io_req *req;
	uint32_t slot;

	if (r == NULL || r->done_len == 0)
		return NULL;
	slot = r->done_ring[r->done_pos];
	r->done_pos = (r->done_pos + 1u) % r->n_rq;
	r->done_len--;
	q = &r->rq[slot];
	req = q->req;
	if (req != NULL) {
		req->status = q->status;
		WR_MEMSET(req->priv, 0, sizeof(req->priv)); /* the structure is the host's again: no longer "in flight" */
	}
	q->req = NULL;
	if (q->zomb) {
		q->state = WRI_RQ_ZOMBIE; /* only the fence entry stays; the next settle drops it if the engine has answered the zombie meanwhile */
	} else {
		wri_rio_free(r, slot);
	}
	return req;
}

/* ---- results ------------------------------------------------------------------------------------------------------------- */

/* A READ that succeeded has every byte of its extent written: by the reply, or here (a short object, a hole, a missing object read as zeros). */
WRI_RIO_NOINLINE static void zero_fill(const wri_osd_op *op, int missing)
{
	uint32_t run = op->out_cap;
	uint32_t got = missing ? 0u : op->out_stored;

	if (op->out == NULL)
		return;
	if (got > run)
		got = run;
	if (got < run)
		WR_MEMSET(op->out + got, 0, run - got);
}

/* The status of an answered operation. The engine's verdict (op->status) is the answer, with one reading of its own: the status the engine derived from a
 * message result of -ENOENT is "no such object", and for a data read that is a hole (zeros), for a removal nothing to remove (wri_rbd_op_status). The message
 * result is NOT looked at first: a redirect reply carries -ENOENT in its result and ends with WR_E_OSD_REDIRECT (a cache tier answering in place of the pool),
 * and reading that -ENOENT as "a hole" would hand the host zeros for data that exists; likewise -EOPNOTSUPP of a data operation is the engine's WR_E_OSD_ERRNO,
 * never "the object is missing". */
WRI_RIO_NOINLINE static wr_status op_result(const wri_osd_op *op)
{
	int missing = 0;
	wr_status st = op->status;

	if (st == WR_E_OSD_NOENT && op->result == -WRI_ERRNO_ENOENT)
		st = wri_rbd_op_status(op->ops[0].code, op->result, &missing);
	if (st == WR_OK && op->ops[0].code == WRI_OSD_OP_READ)
		zero_fill(op, missing);
	return st;
}

/* The first byte of the image that an answered write extent covers, from the object name (its last 16 digits are the object number) and the offset in the
 * object. 0 if the name or the offset is not one this layer cut. */
WRI_RIO_NOINLINE static int extent_start(const wri_rbd_img *im, const wri_osd_op *op, uint64_t *at)
{
	uint64_t objno = 0;
	unsigned i;

	if (op->oid_len < 17u || im->order < 12u || im->order > 25u || op->ops[0].off >= ((uint64_t)1 << im->order))
		return 0;
	for (i = 0; i < 16u; i++) {
		uint8_t c = op->oid[op->oid_len - 16u + i];
		unsigned d;

		if (c >= '0' && c <= '9')
			d = (unsigned)(c - '0');
		else if (c >= 'a' && c <= 'f')
			d = (unsigned)(c - 'a') + 10u;
		else
			return 0;
		objno = (objno << 4) | d;
	}
	if (objno > (UINT64_MAX >> im->order))
		return 0;
	*at = (objno << im->order) | op->ops[0].off;
	return 1;
}

/* A write extent was answered -EOLDSNAPC (WR_OSDF_ORDERSNAP: the image's snapshot context is older than the object's): ask the open machine for a header
 * refresh and send the extent again once it is adopted. The cursor goes back to the start of that extent, so the extent and every extent cut after it are cut
 * again (the later ones that are in flight are sent twice: the same bytes at the same place, and nothing overlapping the request is admitted meanwhile, so
 * a duplicate is harmless). The request is held (no cutting) while the image's refresh is pending. The retries of one request are bounded: the next answer
 * fails it with the OSD's status. Returns 1 if the answer was taken that way. */
WRI_RIO_NOINLINE static int resnap(wri_rbd *r, uint32_t slot, const wri_osd_op *op)
{
	wri_rbd_rq *q = &r->rq[slot];
	const wri_rbd_img *im = wri_rio_img(r, q);
	uint64_t at;

	if (op->result != -WRI_ERRNO_EOLDSNAPC || op->kind != WRI_OPK_WRITE || im == NULL || q->status != WR_OK || q->cancelling != 0)
		return 0;
	if (!extent_start(im, op, &at) || at < q->off || at >= q->off + q->len)
		return 0;
	if (q->held == 0) { /* the first answer of a round: the others of the same round (several extents were in flight) are the same event */
		if (q->resnap >= WRI_RBD_RESNAP_MAX)
			return 0;
		q->resnap++;
		q->held = 1;
	}
	if (q->cur > at)
		q->cur = at;
	wri_rbd_open_refresh_now(r, q->img);
	return 1;
}

/* One answered object operation of the request in `slot` (state RUN, generation checked by the caller). */
static void apply(wri_rbd *r, uint32_t slot, const wri_osd_op *op)
{
	wri_rbd_rq *q = &r->rq[slot];
	uint32_t bytes = op->data_len + op->out_cap;
	wr_status st = op_result(op);

	if (q->ops_out != 0)
		q->ops_out--;
	q->bytes_out = q->bytes_out > bytes ? q->bytes_out - bytes : 0u;
	if (st == WR_E_OSD_BLOCKLISTED && r->fatal_img == WRI_NIL) {
		r->fatal_img = q->img;
		r->fatal_st = st;
	}
	if (st != WR_OK && !(st == WR_E_CANCELLED && q->cancelling) && !resnap(r, slot, op)) /* an operation dropped by our own cancel is no failure */
		wri_rio_fail(r, slot, st);
	if (q->state == WRI_RQ_RUN && q->cur >= q->off + q->len && q->ops_out == 0)
		wri_rio_finish(r, slot, q->status);
}

uint32_t wri_rbd_io_collect(wri_rbd *r)
{
	uint32_t n = 0, i;

	if (r == NULL || r->osd == NULL || r->rq == NULL)
		return 0;
	while ((i = wri_osdc_pop_done(r->osd)) != WRI_NIL) {
		const wri_osd_op *op = wri_osdc_at(r->osd, i);
		uint32_t slot, gen;

		if (op == NULL || (op->flags & WRI_OPF_CONTROL) != 0)
			continue; /* a control read stays DONE for the open machine, which finds it through the image's ctl_op and releases it */
		n++;
		slot = op->owner >> 16;
		gen = op->owner & 0xffffu;
		if (slot < r->n_rq && r->rq[slot].gen == gen && r->rq[slot].state == WRI_RQ_RUN)
			apply(r, slot, op);
		/* else: the answer of a request that is gone (cancelled, timed out, its image closed): nothing to store */
		wri_osdc_release(r->osd, i);
	}
	wri_rio_retry_cancels(r);
	wri_rio_settle(r);
	return n;
}
