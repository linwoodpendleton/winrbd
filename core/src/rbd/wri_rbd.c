/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd.c - the image layer's memory: what it needs from the arena (wri_rbd_mem), the carving of the image table, the request table, the
 * completion ring and the per-image buffers (wri_rbd_init), and the small table operations the I/O half shares (design 25.1, 26.1).
 *
 * Everything is carved once; nothing is allocated afterwards. The request table is a free list through wri_rbd_rq.link; a slot's generation
 * grows every time it is freed, so the (slot, generation) pair in an operation's owner tag never matches a later request.
 */
#include "wri_rbd.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

/* One image's control buffers: the input of the control calls and the output of the header reads. */
static wr_status ctl_stride(const wr_config *cfg, size_t *stride)
{
	return wri_add_sz(WRI_RBD_CTL_IN, cfg->img_ctl_bytes, stride);
}

wr_status wri_rbd_mem(const wr_config *cfg, size_t *arena_bytes)
{
	size_t used = 0, stride = 0, n;
	wr_status st;

	if (cfg == NULL || arena_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	if (cfg->osd_sessions == 0)
		return WR_OK;
	if (cfg->max_images == 0 || cfg->max_reqs == 0 || cfg->op_bytes_max == 0)
		return WR_E_INVAL;
	st = ctl_stride(cfg, &stride);
	if (st == WR_OK)
		st = wri_mul_sz(cfg->max_images, stride, &n);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, cfg->max_images, sizeof(wri_rbd_img), 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, cfg->max_reqs, sizeof(wri_rbd_rq), 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, cfg->max_reqs, sizeof(uint32_t), 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, (size_t)cfg->max_images * cfg->max_snaps, sizeof(uint64_t), 16u);
	if (st == WR_OK)
		st = wri_arena_plan(&used, n, 16u);
	if (st != WR_OK)
		return st;
	*arena_bytes = used;
	return WR_OK;
}

/* The tables out of the arena (zeroed by the arena). */
WRI_RIO_NOINLINE static wr_status carve(wri_rbd *r, const wr_config *cfg, wri_arena *arena, size_t stride)
{
	size_t n_img = cfg->max_images, n_req = cfg->max_reqs, n_snap = cfg->max_snaps;

	r->img = (wri_rbd_img *)wri_arena_take_array(arena, n_img, sizeof(wri_rbd_img), 16u);
	r->rq = (wri_rbd_rq *)wri_arena_take_array(arena, n_req, sizeof(wri_rbd_rq), 16u);
	r->done_ring = (uint32_t *)wri_arena_take_array(arena, n_req, sizeof(uint32_t), 16u);
	r->snap_mem = (uint64_t *)wri_arena_take_array(arena, n_img * n_snap, sizeof(uint64_t), 16u);
	r->ctl_mem = (uint8_t *)wri_arena_take(arena, stride * n_img, 16u);
	if (r->img == NULL || r->rq == NULL || r->done_ring == NULL || r->snap_mem == NULL || r->ctl_mem == NULL)
		return WR_E_BUDGET;
	return WR_OK;
}

/* Every image slot FREE with its buffers in place, every request slot on the free list. */
WRI_RIO_NOINLINE static void init_tables(wri_rbd *r, const wr_config *cfg, size_t stride)
{
	uint32_t i, n_img = cfg->max_images, n_req = cfg->max_reqs, n_snap = cfg->max_snaps;

	r->n_img = n_img;
	r->n_rq = n_req;
	r->fatal_img = WRI_NIL;
	for (i = 0; i < n_img; i++) {
		wri_rbd_img *im = &r->img[i];

		im->slot = (uint16_t)i;
		im->snapc.cap = n_snap;
		im->snapc.snaps = n_snap != 0 ? &r->snap_mem[(size_t)i * n_snap] : NULL;
		im->ctl_in = r->ctl_mem + (size_t)i * stride;
		im->ctl_out = im->ctl_in + WRI_RBD_CTL_IN;
		im->ctl_op = WRI_NIL;
		im->open_deadline_ms = WR_DEADLINE_NONE;
		im->next_refresh_ms = WR_DEADLINE_NONE;
	}
	for (i = 0; i < n_req; i++)
		r->rq[i].link = i + 1u < n_req ? i + 1u : WRI_NIL;
	r->rq_free = n_req != 0 ? 0u : WRI_NIL;
}

wr_status wri_rbd_init(wri_rbd *r, const wri_ctx *x, wri_arena *arena, wri_osdc *osd)
{
	void (*ev)(void *, wr_ev_kind, uint32_t, const wr_errinfo *);
	void *ev_ctx;
	const struct wri_rbd_pools *pools;
	size_t need = 0, stride = 0;
	wr_status st;

	if (r == NULL || x == NULL || arena == NULL || osd == NULL)
		return WR_E_INVAL;
	st = wri_rbd_mem(&x->cfg, &need);
	if (st != WR_OK)
		return st;
	if (x->cfg.osd_sessions == 0)
		return WR_E_INVAL; /* the OSD client is off: there is no layer to make */
	st = ctl_stride(&x->cfg, &stride);
	if (st != WR_OK)
		return st;
	ev = r->event; /* the glue may have bound the hooks before the carve */
	ev_ctx = r->event_ctx;
	pools = r->pools;
	WR_MEMSET(r, 0, sizeof(*r));
	st = carve(r, &x->cfg, arena, stride);
	if (st != WR_OK) {
		WR_MEMSET(r, 0, sizeof(*r));
		return st;
	}
	r->x = x;
	r->osd = osd;
	r->event = ev;
	r->event_ctx = ev_ctx;
	r->pools = pools;
	init_tables(r, &x->cfg, stride);
	return WR_OK;
}

/* ---- the table ---------------------------------------------------------------------------------------------------------- */

int wri_rio_is_write(uint8_t kind)
{
	return kind == WR_IO_WRITE || kind == WR_IO_DISCARD || kind == WR_IO_WRITE_ZEROES;
}

wri_rbd_img *wri_rio_img(const wri_rbd *r, const wri_rbd_rq *q)
{
	wri_rbd_img *im;

	if (q->img >= r->n_img)
		return NULL;
	im = &r->img[q->img];
	if (im->state == WR_IMG_FREE || im->gen != q->img_gen)
		return NULL;
	return im;
}

void wri_rio_free(wri_rbd *r, uint32_t slot)
{
	wri_rbd_rq *q = &r->rq[slot];
	uint16_t gen = (uint16_t)(q->gen + 1u);

	WR_MEMSET(q, 0, sizeof(*q));
	q->gen = gen; /* a late answer addressed to the old request finds a different generation */
	q->link = r->rq_free;
	r->rq_free = slot;
	if (r->reqs_inflight != 0)
		r->reqs_inflight--;
}

/* The counters of the image a request leaves (it ended: answered, cancelled, failed). */
WRI_RIO_NOINLINE static void leave_image(wri_rbd *r, const wri_rbd_rq *q)
{
	wri_rbd_img *im = wri_rio_img(r, q);

	if (im == NULL)
		return;
	if (im->n_reqs != 0)
		im->n_reqs--;
	if (wri_rio_is_write(q->kind) && im->n_writes_unfinished != 0)
		im->n_writes_unfinished--;
}

void wri_rio_finish(wri_rbd *r, uint32_t slot, wr_status st)
{
	wri_rbd_rq *q = &r->rq[slot];

	if (q->state != WRI_RQ_WAIT && q->state != WRI_RQ_RUN)
		return; /* a request completes once */
	if (q->status == WR_OK)
		q->status = st;
	leave_image(r, q);
	q->state = WRI_RQ_FINISH;
	q->cancelling = 0;
	q->cur = q->off + q->len; /* nothing left to cut */
	q->ops_out = 0;
	q->bytes_out = 0;
	q->zomb = (uint8_t)(wri_rio_is_write(q->kind) && q->zops != 0);
	if (q->zomb) {
		r->n_zombie_entries++;
		r->dirty |= WRI_RIO_DIRTY_ZOMB;
	}
	r->done_ring[(r->done_pos + r->done_len) % r->n_rq] = slot;
	r->done_len++;
	r->n_completed++;
	r->dirty |= WRI_RIO_DIRTY_ADMIT | WRI_RIO_DIRTY_BARRIER;
}

int wri_rbd_io_take_fatal(wri_rbd *r, uint32_t *img, wr_status *st)
{
	if (r == NULL || r->fatal_img == WRI_NIL)
		return 0;
	if (img != NULL)
		*img = r->fatal_img;
	if (st != NULL)
		*st = r->fatal_st;
	r->fatal_img = WRI_NIL;
	r->fatal_st = WR_OK;
	return 1;
}
