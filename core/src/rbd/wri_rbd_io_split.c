/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_io_split.c - turning requests into object operations (design 25.2, 25.3, 25.6).
 *
 * A request is never expanded. It keeps a cursor into its byte range, and each visit of the cutting loop takes the next extent (one object, at
 * most op_bytes_max bytes; the kinds without payload are cut at object ends only) and submits ONE object operation for it, as long as the engine
 * has a free data slot and the bytes in flight allow.
 * The table of the engine, not the request's size, bounds the memory: a 64 MiB read passes through a single slot, one extent after the other.
 *
 * Fairness: the loop goes round the request table starting where the last pass stopped and cuts at most WRI_RBD_RQ_QUANTUM operations per
 * request per round, so a request of a gigabyte does not keep a small one admitted after it waiting for the whole of it.
 *
 * What an extent becomes: READ -> READ (the reply lands in the host's buffer at the extent's place, nothing is copied), WRITE -> WRITE with the
 * buffer slice as its data segment and the image's current snapshot context, DISCARD -> DELETE / TRUNCATE / ZERO by the shape of the extent
 * (wri_rbd_discard_op), WRITE_ZEROES -> ZERO. The object name is built here, at the moment of the cut.
 */
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

/* The next extent of request `slot`: object number, offset in it, run length. 0, or 2 (the request failed). */
WRI_RIO_NOINLINE static int next_extent(wri_rbd *r, uint32_t slot, const wri_rbd_img *im, wri_rbd_geom *g, uint64_t *objno, uint64_t *obj_off, uint32_t *run)
{
	const wri_rbd_rq *q = &r->rq[slot];
	const wr_config *cfg = &r->x->cfg;
	uint32_t max_run;
	wr_status st = wri_rbd_geom_init(g, im->order);

	if (st != WR_OK) {
		wri_rio_fail(r, slot, st);
		return 2;
	}
	/* A data operation must fit the engine's byte budget by itself, or it could never be admitted (WR_E_TOOBIG). A discard and a write-zeroes carry
	 * no payload: they are cut at object ends only, so a whole object stays one DELETE however small op_bytes_max is. */
	if (q->kind == (uint8_t)WR_IO_DISCARD || q->kind == (uint8_t)WR_IO_WRITE_ZEROES) {
		max_run = UINT32_MAX;
	} else {
		max_run = cfg->op_bytes_max;
		if (cfg->inflight_bytes_max != 0 && max_run > cfg->inflight_bytes_max)
			max_run = cfg->inflight_bytes_max;
	}
	wri_rbd_geom_extent(g, q->cur, q->off + q->len - q->cur, max_run, objno, obj_off, run);
	if (*run == 0) {
		wri_rio_fail(r, slot, WR_E_INVAL);
		return 2;
	}
	return 0;
}

/* The operation records of the four kinds. */
WRI_RIO_NOINLINE static void fill_read(wri_osd_op *op, const wri_rbd_rq *q, uint64_t obj_off, uint32_t run)
{
	op->kind = WRI_OPK_READ;
	op->ops[0].code = WRI_OSD_OP_READ;
	op->ops[0].off = obj_off;
	op->ops[0].len = run;
	op->out = (uint8_t *)q->req->buf + (q->cur - q->off);
	op->out_cap = run;
}

WRI_RIO_NOINLINE static void fill_write(wri_osd_op *op, const wri_rbd_rq *q, uint64_t obj_off, uint32_t run)
{
	op->kind = WRI_OPK_WRITE;
	op->ops[0].code = WRI_OSD_OP_WRITE;
	op->ops[0].off = obj_off;
	op->ops[0].len = run;
	op->ops[0].in_len = run;
	op->data = (const uint8_t *)q->req->buf + (q->cur - q->off);
	op->data_len = run;
}

/* TRUNCATE takes the new size in `off`, ZERO the range, DELETE nothing (rbd-format2.md 3.7). */
WRI_RIO_NOINLINE static void fill_discard(wri_osd_op *op, const wri_rbd_geom *g, uint64_t obj_off, uint32_t run)
{
	uint16_t code = wri_rbd_discard_op(g, obj_off, run);

	op->kind = WRI_OPK_WRITE;
	op->ops[0].code = code;
	op->ops[0].off = code == WRI_OSD_OP_DELETE ? 0u : obj_off;
	op->ops[0].len = code == WRI_OSD_OP_ZERO ? run : 0u;
}

/* Always ZERO: the object stays, write-zeroes never removes anything. */
WRI_RIO_NOINLINE static void fill_zeroes(wri_osd_op *op, uint64_t obj_off, uint32_t run)
{
	op->kind = WRI_OPK_WRITE;
	op->ops[0].code = WRI_OSD_OP_ZERO;
	op->ops[0].off = obj_off;
	op->ops[0].len = run;
}

/* The operation record of one extent (what the kind of the request makes of it). 0, or 1 for a kind that has no extents. */
static int fill_op(wri_osd_op *op, const wri_rbd_rq *q, const wri_rbd_geom *g, uint64_t obj_off, uint32_t run)
{
	op->n_ops = 1;
	switch ((wr_io_kind)q->kind) {
	case WR_IO_READ:
		fill_read(op, q, obj_off, run);
		return 0;
	case WR_IO_WRITE:
		fill_write(op, q, obj_off, run);
		return 0;
	case WR_IO_DISCARD:
		fill_discard(op, g, obj_off, run);
		return 0;
	case WR_IO_WRITE_ZEROES:
		fill_zeroes(op, obj_off, run);
		return 0;
	case WR_IO_FLUSH:
	default:
		return 1;
	}
}

/* One object operation for the next extent of request `slot`: 0 = cut, 1 = no room now (the engine's table or the bytes in flight; try after
 * a completion), 2 = the request failed (and is finished or winding down). */
static int cut_one(wri_rbd *r, uint32_t slot)
{
	wri_rbd_rq *q = &r->rq[slot];
	const wri_rbd_img *im = wri_rio_img(r, q);
	wri_rbd_geom g;
	wri_osd_op *op;
	uint64_t objno, obj_off;
	uint32_t idx, run;
	wr_status st;
	size_t n;

	if (im == NULL) {
		wri_rio_fail(r, slot, WR_E_RBD_CLOSED);
		return 2;
	}
	if (next_extent(r, slot, im, &g, &objno, &obj_off, &run) != 0)
		return 2;
	idx = wri_osdc_alloc(r->osd, 0);
	if (idx == WRI_NIL)
		return 1;
	op = wri_osdc_at(r->osd, idx);
	n = wri_rbd_obj_name((char *)op->oid, sizeof(op->oid), im->prefix, objno);
	if (n == 0 || fill_op(op, q, &g, obj_off, run) != 0) {
		wri_osdc_release(r->osd, idx);
		wri_rio_fail(r, slot, n == 0 ? WR_E_RBD_PROTO : WR_E_INVAL); /* the open checked the prefix: a name that does not fit is a damaged image record */
		return 2;
	}
	op->oid_len = (uint8_t)n;
	op->pool = (im->features & WRI_RBD_F_DATA_POOL) != 0 ? im->data_pool_h : im->pool_h;
	op->owner = WRI_RBD_TAG(slot, q->gen);
	if (op->kind == WRI_OPK_WRITE)
		op->snapc = &r->img[q->img].snapc; /* read again at every transmission: a resend carries the image's current context */
	st = wri_osdc_submit(r->osd, idx);
	if (st == WR_E_BUSY) {
		wri_osdc_release(r->osd, idx); /* the bytes in flight are at their limit: wait for an answer */
		return 1;
	}
	if (st != WR_OK) {
		wri_osdc_release(r->osd, idx);
		wri_rio_fail(r, slot, st);
		return 2;
	}
	q->cur += run;
	q->ops_out++;
	q->bytes_out += op->data_len + op->out_cap;
	return 0;
}

/* A write that an -EOLDSNAPC answer sent back to the header refresh (wri_rbd_io.c) cuts nothing while the refresh it asked for is pending. 1 if it may be cut. */
static int unheld(const wri_rbd *r, wri_rbd_rq *q)
{
	const wri_rbd_img *im;

	if (q->held == 0)
		return 1;
	im = wri_rio_img(r, q);
	if (im != NULL && im->state == (uint8_t)WR_IMG_OPEN && im->ros == (uint8_t)WRI_ROS_REFRESH)
		return 0;
	q->held = 0; /* adopted (or the image is going away: the cut then fails the request in its own way) */
	return 1;
}

int wri_rbd_io_cut(wri_rbd *r, uint32_t budget)
{
	uint32_t visited, progress, n_rq;
	int stop = 0;

	if (r == NULL || r->rq == NULL || r->osd == NULL)
		return 0;
	wri_rio_admit(r);
	n_rq = r->n_rq;
	do {
		progress = 0;
		for (visited = 0; visited < n_rq && budget != 0 && !stop; visited++) {
			uint32_t slot = (r->cut_pos + visited) % n_rq, k;
			wri_rbd_rq *q = &r->rq[slot];

			if (q->state != WRI_RQ_RUN || q->cancelling || !unheld(r, q))
				continue;
			for (k = 0; k < WRI_RBD_RQ_QUANTUM && budget != 0 && q->state == WRI_RQ_RUN && q->cur < q->off + q->len; k++) {
				int rc = cut_one(r, slot);

				if (rc == 1) {
					stop = 1;
					break;
				}
				if (rc == 2)
					break;
				budget--;
				progress++;
			}
			if (stop || budget == 0)
				r->cut_pos = (slot + 1u) % n_rq; /* the next pass starts behind the request that was served last */
		}
	} while (progress != 0 && budget != 0 && !stop);
	/* more to do now: budget ran out with extents left (a stop for want of room waits for an answer, not for another call) */
	if (budget == 0 && !stop) {
		uint32_t i;

		for (i = 0; i < n_rq; i++)
			if (r->rq[i].state == WRI_RQ_RUN && !r->rq[i].cancelling && r->rq[i].cur < r->rq[i].off + r->rq[i].len)
				return 1;
	}
	return 0;
}
