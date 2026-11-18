/* SPDX-License-Identifier: MIT */
/*
 * wri_rbd_open.c - an image's life around the header reads: start (copy the strings, track the pools, the open deadline), the step that moves
 * every image on, the refresh timer of a writer, failure, close, and the release of control operations nobody waits for (design 24.2 to 24.4).
 * The submission of the control reads and the handling of their answers are in wri_rbd_open_dec.c; this file decides when.
 *
 * One control read per image is in flight at most (img->ctl_op). The machine's rule for finished reads: wri_rbd_io_collect pops them and leaves
 * them DONE, and this file releases them (the owner tag is (image slot << 16) | image generation). A read whose image failed or closed while
 * it was in flight is cancelled (its reply must not land in a buffer that may be reused) and released later as an orphan.
 */
#include "wri_rbd_open.h"

#include "wri_ctx.h"
#include "wri_rbd_io.h"

WR_FILE_LICENCE_MIT

#define RETRY_MS 50u /* when a control read could not be submitted (no free control slot, byte budget): look again */

/* ---- small helpers ------------------------------------------------------------------------------------------------------- */

static void lower(uint64_t *deadline, uint64_t t)
{
	if (deadline != NULL && t < *deadline)
		*deadline = t;
}

static void raise_image(wri_rbd *r, uint32_t slot, const wr_errinfo *e)
{
	if (r->event != NULL)
		r->event(r->event_ctx, WR_EV_IMAGE, slot, e);
}

/* The slot goes back to the free table: pointers into the arena stay, everything else is cleared, the generation moves on. */
static void img_free(wri_rbd_img *m)
{
	uint16_t slot = m->slot, gen = (uint16_t)(m->gen + 1u);
	uint64_t *snaps = m->snapc.snaps;
	uint32_t cap = m->snapc.cap;
	uint8_t *in = m->ctl_in, *out = m->ctl_out;

	if (snaps != NULL && cap != 0)
		WR_MEMSET(snaps, 0, (size_t)cap * sizeof(snaps[0]));
	WR_MEMSET(m, 0, sizeof(*m));
	m->slot = slot;
	m->gen = gen;
	m->snapc.snaps = snaps;
	m->snapc.cap = cap;
	m->ctl_in = in;
	m->ctl_out = out;
	m->ctl_op = WRI_NIL;
	m->open_deadline_ms = WR_DEADLINE_NONE;
	m->next_refresh_ms = WR_DEADLINE_NONE;
	m->refreshed_ms = WR_DEADLINE_NONE;
	m->hdr.data_pool_id = -1;
}

/* The control read of the image is given up: if it is on the wire it is cancelled (the engine resets the session when its reply is landing in
 * the image's buffer), if it is finished and popped it is released, if it is finished and still in the ring the orphan reaper has it later. */
static void cancel_ctl(wri_rbd *r, wri_rbd_img *m)
{
	uint32_t idx = m->ctl_op;
	const wri_osd_op *op;
	wr_status st;

	m->ctl_op = WRI_NIL;
	if (idx == WRI_NIL || r->osd == NULL)
		return;
	op = wri_osdc_at(r->osd, idx);
	if (op == NULL || op->state == WRI_OP_FREE)
		return;
	if (op->state == WRI_OP_DONE) {
		wri_osdc_release(r->osd, idx); /* ignored while it is still in the ring: the reaper takes it then */
		return;
	}
	st = wri_osdc_cancel(r->osd, idx); /* a READ is dropped into the done list; the answer is of no interest */
	(void)st;
}

/* Control reads that are DONE, popped and claimed by no image (their image failed, closed or timed out): give the slots back. Returns 1 when one of them is
 * still in the done ring (the I/O half pops it later in this pass): the release has to follow in the next pass, which must not wait for another event. */
static int reap_orphans(wri_rbd *r)
{
	wri_osdc *o = r->osd;
	uint32_t i, claimed = 0;
	int more = 0;

	for (i = 0; i < r->n_img; i++)
		if (r->img[i].ctl_op != WRI_NIL)
			claimed++;
	if (o->n_ctl_used <= claimed)
		return 0;
	for (i = 0; i < o->n_op; i++) {
		const wri_osd_op *op = &o->op[i];
		uint32_t slot;

		if (op->state != WRI_OP_DONE || (op->flags & WRI_OPF_CONTROL) == 0)
			continue;
		slot = op->owner >> 16;
		if (slot < r->n_img && r->img[slot].ctl_op == i)
			continue;
		if ((op->flags & WRI_OPF_INRING) != 0) {
			more = 1;
			continue;
		}
		wri_osdc_release(o, i);
	}
	return more;
}

/* ---- start ------------------------------------------------------------------------------------------------------------------ */

/* A clean image in a slot that was free: strings copied, pools set, deadline and full-map gate computed. Nothing here fails. */
static void init_image(wri_rbd *r, wri_rbd_img *m, const wri_rbd_pools *pools, const wr_image_params *p, size_t name_n, size_t id_n,
		       const wr_pool_h h[2], int named_data)
{
	uint32_t epoch;

	r->pools = pools;
	img_free(m); /* a clean slot with a new generation (the slot was free: this only makes sure) */
	m->state = (uint8_t)WR_IMG_OPENING;
	m->ros = (uint8_t)WRI_ROS_POOLS;
	m->want_write = p->want_write != 0;
	m->pool_h = h[0];
	m->data_pool_h = h[1];
	m->has_data_pool = named_data != 0;
	if (p->name != NULL && name_n != 0)
		WR_MEMCPY(m->name, p->name, name_n);
	if (p->id != NULL)
		WR_MEMCPY(m->id, p->id, id_n);
	epoch = r->osd->map.epoch(r->osd->map.ctx);
	m->full_need = epoch != 0 && pools->n_full != NULL ? pools->n_full(pools->ctx) + 1u : 0u;
	m->open_deadline_ms = p->open_timeout_ms != 0 ? r->x->now.mono_ms + p->open_timeout_ms : WR_DEADLINE_NONE;
	m->refresh_start_ms = r->x->now.mono_ms; /* the start of the open: the full-map wait of POOLS is bounded from it (wri_rbd_open_dec.c) */
}

wr_status wri_rbd_open_start(wri_rbd *r, const wri_rbd_pools *pools, const wr_image_params *p, uint32_t *slot)
{
	size_t name_n, id_n;
	wr_pool_h h[2] = {0, 0};
	wri_rbd_img *m = NULL;
	uint32_t i;
	int named_data;
	wr_status st;

	if (r == NULL || r->img == NULL || r->osd == NULL || pools == NULL || pools->track == NULL || p == NULL || slot == NULL)
		return WR_E_INVAL;
	st = wri_rbd_open_check_params(p, &name_n, &id_n);
	if (st != WR_OK)
		return st;
	for (i = 0; i < r->n_img; i++) {
		if (r->img[i].state == (uint8_t)WR_IMG_FREE) {
			m = &r->img[i];
			break;
		}
	}
	if (m == NULL)
		return WR_E_BUSY;
	st = pools->track(pools->ctx, p->pool, &h[0]);
	if (st != WR_OK)
		return st;
	named_data = p->data_pool != NULL && p->data_pool[0] != '\0';
	if (named_data) {
		st = pools->track(pools->ctx, p->data_pool, &h[1]);
		if (st != WR_OK)
			return st;
	}
	init_image(r, m, pools, p, name_n, id_n, h, named_data);
	*slot = m->slot;
	return WR_OK;
}

/* ---- failure and close -------------------------------------------------------------------------------------------------------- */

void wri_rbd_img_fail(wri_rbd *r, uint32_t slot, const wr_errinfo *why)
{
	wri_rbd_img *m;
	wr_status st;

	if (r == NULL || r->img == NULL || slot >= r->n_img)
		return;
	m = &r->img[slot];
	if (m->state == (uint8_t)WR_IMG_FREE || m->state == (uint8_t)WR_IMG_FAILED)
		return;
	if (m->err.status == WR_OK) {
		if (why != NULL && why->status != WR_OK)
			m->err = *why;
		else
			WRI_ERRINFO(&m->err, WR_E_STATE, WR_MOD_RBD, "image failed", 0, 0, 0);
	}
	if (m->state == (uint8_t)WR_IMG_CLOSING)
		return; /* the close finishes it; only the first failure is kept */
	st = m->err.status;
	m->state = (uint8_t)WR_IMG_FAILED;
	m->ros = (uint8_t)WRI_ROS_IDLE;
	m->next_refresh_ms = WR_DEADLINE_NONE;
	m->open_deadline_ms = WR_DEADLINE_NONE;
	cancel_ctl(r, m);
	/* every request completes with the failure; writes that were sent continue as zombies (the abandon rules of 25.5) */
	wri_rbd_io_fail_image(r, slot, st, WR_CLOSE_ABANDON);
	raise_image(r, slot, &m->err);
}

static void finish_close(wri_rbd *r, wri_rbd_img *m)
{
	uint32_t slot = m->slot;

	cancel_ctl(r, m);
	img_free(m);
	raise_image(r, slot, NULL);
}

wr_status wri_rbd_close(wri_rbd *r, uint32_t slot, uint32_t flags)
{
	wri_rbd_img *m;

	if (r == NULL || r->img == NULL || slot >= r->n_img || (flags & ~WR_CLOSE_ABANDON) != 0)
		return WR_E_INVAL;
	m = &r->img[slot];
	switch ((wr_image_state)m->state) {
	case WR_IMG_OPENING:
	case WR_IMG_FAILED: /* nothing to drain: no request can be in flight on an image that is not open, and a failed one completed them */
		finish_close(r, m);
		return WR_OK;
	case WR_IMG_OPEN:
		m->state = (uint8_t)WR_IMG_CLOSING;
		m->close_flags = (uint8_t)flags;
		m->next_refresh_ms = WR_DEADLINE_NONE;
		m->ros = (uint8_t)WRI_ROS_IDLE;
		cancel_ctl(r, m); /* a refresh in flight is of no interest any more */
		wri_rbd_io_fail_image(r, slot, WR_E_CANCELLED, flags);
		break;
	case WR_IMG_CLOSING:
		if ((flags & WR_CLOSE_ABANDON) == 0 || (m->close_flags & WR_CLOSE_ABANDON) != 0)
			return WR_OK;
		m->close_flags = (uint8_t)flags;
		wri_rbd_io_fail_image(r, slot, WR_E_CANCELLED, flags);
		break;
	case WR_IMG_FREE:
	default:
		return WR_E_INVAL;
	}
	if ((flags & WR_CLOSE_ABANDON) != 0 || (m->n_reqs == 0 && m->n_writes_unfinished == 0))
		finish_close(r, m);
	return WR_OK;
}

void wri_rbd_open_refresh_now(wri_rbd *r, uint32_t slot)
{
	wri_rbd_img *m;

	if (r == NULL || r->img == NULL || slot >= r->n_img)
		return;
	m = &r->img[slot];
	if (m->state != (uint8_t)WR_IMG_OPEN || !m->writable)
		return; /* works with hdr_refresh_ms == 0 too: the refresh is asked for, not periodic */
	if (m->ros == (uint8_t)WRI_ROS_REFRESH && m->ctl_op != WRI_NIL) {
		m->hdr_stale = 1; /* the read in flight may predate the event: another one follows it */
		return;
	}
	m->ros = (uint8_t)WRI_ROS_REFRESH;
	m->next_refresh_ms = r->x->now.mono_ms;
}

/* ---- the step ----------------------------------------------------------------------------------------------------------------- */

static const char *step_name(uint8_t ros)
{
	switch ((wri_ros)ros) {
	case WRI_ROS_POOLS:
		return "open timed out waiting for the OSD map and the pools";
	case WRI_ROS_GET_ID:
		return "open timed out reading the image id";
	case WRI_ROS_HEADER:
		return "open timed out reading the image header";
	case WRI_ROS_EXTRA:
		return "open timed out reading the striping / operation features";
	case WRI_ROS_IDLE:
	case WRI_ROS_READY:
	case WRI_ROS_REFRESH:
	default:
		return "open timed out";
	}
}

/* The finished control read of an image, if it is ready to be taken: -1 = none in flight, 0 = still on its way (or finished but not popped yet:
 * *more says so), 1 = taken (the slot is released after the handler ran). */
static int take_done(wri_rbd *r, wri_rbd_img *m, int *more)
{
	uint32_t idx = m->ctl_op;
	wri_osd_op *op;

	if (idx == WRI_NIL)
		return -1;
	op = wri_osdc_at(r->osd, idx);
	if (op == NULL || op->state == WRI_OP_FREE) { /* released behind our back: the contract is broken, the image cannot go on */
		wr_errinfo why;

		WR_MEMSET(&why, 0, sizeof(why));
		WRI_ERRINFO(&why, WR_E_STATE, WR_MOD_RBD, "control read vanished (released by someone else)", m->ros, idx, 0);
		m->ctl_op = WRI_NIL;
		wri_rbd_img_fail(r, m->slot, &why);
		return 0;
	}
	if (op->state != WRI_OP_DONE)
		return 0;
	if ((op->flags & WRI_OPF_INRING) != 0) {
		*more = 1; /* the I/O half pops it in this pass; the next step takes it */
		return 0;
	}
	{
		wr_errinfo why;
		int failed;

		WR_MEMSET(&why, 0, sizeof(why));
		m->ctl_op = WRI_NIL;
		failed = wri_rbd_open_complete(r, m, op, &why);
		wri_osdc_release(r->osd, idx);
		if (failed)
			wri_rbd_img_fail(r, m->slot, &why);
	}
	*more = 1;
	return 1;
}

static void submit_failed(wri_rbd *r, wri_rbd_img *m, wr_status st, uint64_t now, uint64_t *deadline)
{
	if (st == WR_E_BUSY) {
		lower(deadline, now + RETRY_MS); /* no free control slot or byte budget: the reads in flight will free them; look again soon */
		return;
	}
	{
		wr_errinfo why;

		WR_MEMSET(&why, 0, sizeof(why));
		WRI_ERRINFO(&why, st, WR_MOD_RBD, "control read could not be submitted", m->ros, 0, 0);
		wri_rbd_img_fail(r, m->slot, &why);
	}
}

static int step_opening(wri_rbd *r, wri_rbd_img *m, uint64_t *deadline)
{
	uint64_t now = r->x->now.mono_ms;
	int more = 0;
	unsigned guard;

	if (m->open_deadline_ms != WR_DEADLINE_NONE && now >= m->open_deadline_ms) {
		wr_errinfo why;

		WR_MEMSET(&why, 0, sizeof(why));
		WRI_ERRINFO(&why, WR_E_TIMEOUT, WR_MOD_RBD, step_name(m->ros), m->ros, r->x->cfg.op_timeout_ms, 0);
		wri_rbd_img_fail(r, m->slot, &why);
		return 1;
	}
	for (guard = 0; guard < 8u && m->state == (uint8_t)WR_IMG_OPENING; guard++) {
		int got = take_done(r, m, &more);

		if (got > 0)
			continue; /* a state advanced: do what the next one needs */
		if (got == 0)
			break;    /* the read is still on its way */
		if (m->ros == (uint8_t)WRI_ROS_POOLS) {
			wr_errinfo why;
			int rc;

			WR_MEMSET(&why, 0, sizeof(why));
			rc = wri_rbd_open_pools(r, m, 0, &why);
			if (rc > 0) { /* the map or the full map that has the pool: events wake the engine, the open deadline is below */
				if (m->full_need != 0 && r->x->cfg.map_stale_ms != 0 && now < m->refresh_start_ms + r->x->cfg.map_stale_ms)
					lower(deadline, m->refresh_start_ms + r->x->cfg.map_stale_ms); /* where the wait for the full map gives up */
				break;
			}
			if (rc < 0) {
				wri_rbd_img_fail(r, m->slot, &why);
				more = 1;
				break;
			}
			m->ros = (uint8_t)(m->id[0] != '\0' ? WRI_ROS_HEADER : WRI_ROS_GET_ID);
			more = 1;
			continue;
		}
		{
			wr_status st = wri_rbd_open_submit(r, m);

			if (st == WR_OK)
				more = 1; /* the engine has a new operation to target and send */
			else
				submit_failed(r, m, st, now, deadline);
			break;
		}
	}
	if (m->state == (uint8_t)WR_IMG_OPENING && m->ros != (uint8_t)WRI_ROS_POOLS) { /* a pool that left the map during the open */
		wr_errinfo why;

		WR_MEMSET(&why, 0, sizeof(why));
		if (wri_rbd_open_pools(r, m, 1, &why) < 0) {
			wri_rbd_img_fail(r, m->slot, &why);
			return 1;
		}
	}
	if (m->state == (uint8_t)WR_IMG_OPENING && m->open_deadline_ms != WR_DEADLINE_NONE)
		lower(deadline, m->open_deadline_ms);
	return more;
}

static int step_open(wri_rbd *r, wri_rbd_img *m, uint64_t *deadline)
{
	uint64_t now = r->x->now.mono_ms;
	uint32_t period = r->x->cfg.hdr_refresh_ms;
	wr_errinfo why;
	int more = 0;

	WR_MEMSET(&why, 0, sizeof(why));
	if (wri_rbd_open_pools(r, m, 1, &why) < 0) { /* the pool left the map, or was made again under another id */
		wri_rbd_img_fail(r, m->slot, &why);
		return 1;
	}
	(void)take_done(r, m, &more);
	if (m->state != (uint8_t)WR_IMG_OPEN || !m->writable)
		return more;
	if (m->ros == (uint8_t)WRI_ROS_READY) {
		if (period == 0 || m->next_refresh_ms == WR_DEADLINE_NONE)
			return more; /* no periodic refresh (it can still be asked for) */
		if (now < m->next_refresh_ms) {
			lower(deadline, m->next_refresh_ms);
			return more;
		}
		m->ros = (uint8_t)WRI_ROS_REFRESH; /* due: the gate of the I/O half closes, writes wait for the read */
	}
	if (m->ctl_op != WRI_NIL)
		return more;
	if (m->ros == (uint8_t)WRI_ROS_REFRESH && now >= m->next_refresh_ms) {
		wr_status st = wri_rbd_open_submit(r, m);

		if (st == WR_OK)
			more = 1;
		else
			submit_failed(r, m, st, now, deadline);
		return more;
	}
	lower(deadline, m->next_refresh_ms); /* a refresh that is pending but not yet due (a retry after a failure) */
	return more;
}

int wri_rbd_open_step(wri_rbd *r, uint64_t *deadline)
{
	int more = 0;
	uint32_t i;

	if (r == NULL || r->img == NULL || r->osd == NULL || r->x == NULL)
		return 0;
	for (i = 0; i < r->n_img; i++) {
		wri_rbd_img *m = &r->img[i];

		switch ((wr_image_state)m->state) {
		case WR_IMG_OPENING:
			more |= step_opening(r, m, deadline);
			break;
		case WR_IMG_OPEN:
			more |= step_open(r, m, deadline);
			break;
		case WR_IMG_CLOSING:
			if (m->n_reqs == 0 && m->n_writes_unfinished == 0) { /* the writes are answered (reads were dropped when the close began) */
				finish_close(r, m);
				more = 1;
			}
			break;
		case WR_IMG_FREE:
		case WR_IMG_FAILED:
		default:
			break;
		}
	}
	more |= reap_orphans(r);
	return more;
}
