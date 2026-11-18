/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_req.c - the object operation table (design 23.1): memory, slots with the control reserve, the free list, submission in tid order, the
 * done ring, release, the common completion of an op and the engine's deadline. Targeting is in wri_osd_req_tgt.c, sending, replies and
 * timeouts in wri_osd_req_send.c, cancel and the zombie area in wri_osd_req_zomb.c.
 *
 * Invariants kept here (and relied on by the other three files):
 *   - an op is in exactly one of: the free list (FREE, not ALLOC), the owner's hands (FREE + ALLOC), the submission list (NEW .. SENT), the done ring
 *     (DONE + INRING) or the owner's hands again after the pop (DONE);
 *   - `tid & 0xffff` is the slot; the tid counter only grows, so a tid is never reused and a reply finds its op without a search;
 *   - n_inflight and inflight_bytes count exactly the ops of the submission list, and every path that takes an op out of it goes through
 *     wri_or_complete(), so a budget cannot leak;
 *   - an op completes once: wri_or_complete() ignores an op that is not live.
 */
#include "wri_osd_req.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define OR_TID_COUNTER_MAX ((uint64_t)1 << 47) /* far above anything a client lifetime reaches; keeps counter << 16 inside 64 bits */

/* ---- memory ------------------------------------------------------------------------------------------------------------- */

wr_status wri_osdc_mem(const wr_config *cfg, size_t *arena_bytes, size_t *bulk_bytes)
{
	size_t used = 0, bulk = 0, sess = 0, total;
	wr_status st;

	if (cfg == NULL || arena_bytes == NULL || bulk_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	*bulk_bytes = 0;
	if (cfg->osd_sessions == 0)
		return WR_OK;
	if (cfg->max_ops == 0 || cfg->ctl_ops >= cfg->max_ops || cfg->op_timeout_ms == 0)
		return WR_E_INVAL;
	st = wri_arena_plan_array(&used, cfg->max_ops, sizeof(wri_osd_op), 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, cfg->max_ops, sizeof(uint32_t), 16u);
	if (st == WR_OK)
		st = wri_arena_plan(&used, cfg->osd_front_cap, 16u);
	if (st == WR_OK)
		st = wri_arena_plan_array(&used, cfg->osd_sessions, sizeof(uint32_t), 16u);
	if (st == WR_OK)
		st = wri_align_up(used, 16u, &used);
	if (st == WR_OK)
		st = wri_osd_sess_mem(cfg, &sess);
	if (st == WR_OK)
		st = wri_add_sz(used, sess, &total);
	if (st == WR_OK && cfg->zombie_bytes != 0)
		st = wri_arena_plan(&bulk, cfg->zombie_bytes, 16u);
	if (st != WR_OK)
		return st;
	*arena_bytes = total;
	*bulk_bytes = bulk;
	return WR_OK;
}

/* Carve the op table, the done ring, the scratch, the per-session marks and the zombie area (the sessions are carved by their own init). */
OR_NOINLINE static wr_status carve(wri_osdc *o, const wri_ctx *x, wri_arena *arena, wri_arena *bulk)
{
	uint32_t n = x->cfg.max_ops;

	o->op = (wri_osd_op *)wri_arena_take_array(arena, n, sizeof(wri_osd_op), 16u);
	o->done_ring = (uint32_t *)wri_arena_take_array(arena, n, sizeof(uint32_t), 16u);
	o->scratch = (uint8_t *)wri_arena_take(arena, x->cfg.osd_front_cap, 16u);
	o->sess_pass = (uint32_t *)wri_arena_take_array(arena, x->cfg.osd_sessions, sizeof(uint32_t), 16u);
	if (o->op == NULL || o->done_ring == NULL || o->scratch == NULL || o->sess_pass == NULL)
		return WR_E_BUDGET;
	if (x->cfg.zombie_bytes != 0) {
		o->zbuf = (uint8_t *)wri_arena_take(bulk, x->cfg.zombie_bytes, 16u);
		if (o->zbuf == NULL)
			return WR_E_BUDGET;
		o->zcap = x->cfg.zombie_bytes;
	}
	return WR_OK;
}

/* Every slot on the free list, nothing in flight. */
OR_NOINLINE static void reset_table(wri_osdc *o)
{
	uint32_t i, n = o->n_op;

	for (i = 0; i < n; i++) {
		o->op[i].next = i + 1u < n ? i + 1u : WRI_NIL;
		o->op[i].prev = WRI_NIL;
		o->op[i].sess = WRI_NIL;
		o->op[i].last_sess = WRI_LAST_NONE;
		o->op[i].osd = -1;
	}
	o->free_head = 0;
	o->n_free = n;
	o->n_free_ctl = o->x->cfg.ctl_ops;
	o->head = o->tail = WRI_NIL;
	o->next_tid = 1;
	o->pass = 0;
	o->sess_next_ms = WR_DEADLINE_NONE;
}

wr_status wri_osdc_init(wri_osdc *o, const wri_ctx *x, wri_arena *arena, wri_arena *bulk, const wri_osd_map_ops *map,
			const wri_osd_link *link)
{
	wri_osd_sess_up up;
	size_t need_a = 0, need_b = 0;
	wr_status st;

	if (o == NULL)
		return WR_E_INVAL;
	WR_MEMSET(o, 0, sizeof(*o));
	if (x == NULL || arena == NULL || map == NULL || link == NULL)
		return WR_E_INVAL;
	if (map->epoch == NULL || map->flags == NULL || map->pool_info == NULL || map->target == NULL)
		return WR_E_INVAL;
	st = wri_osdc_mem(&x->cfg, &need_a, &need_b);
	if (st != WR_OK)
		return st;
	if (x->cfg.osd_sessions == 0)
		return WR_E_INVAL; /* the OSD client is off: there is no engine to make */
	if (x->cfg.zombie_bytes != 0 && bulk == NULL)
		return WR_E_INVAL;
	st = carve(o, x, arena, bulk);
	if (st == WR_OK) {
		o->x = x;
		o->map = *map;
		o->n_op = x->cfg.max_ops;
		wri_or_up(o, &up);
		st = wri_osd_sess_init(&o->sess, x, arena, link, &up);
	}
	if (st != WR_OK) {
		WR_MEMSET(o, 0, sizeof(*o));
		return st;
	}
	reset_table(o);
	return WR_OK;
}

void wri_osdc_set_event(wri_osdc *o, wri_osdc_event_fn fn, void *ctx)
{
	if (o == NULL)
		return;
	o->event = fn;
	o->event_ctx = ctx;
}

void wri_or_event(wri_osdc *o, wr_ev_kind kind, uint32_t arg, const wr_errinfo *err)
{
	if (o->event != NULL)
		o->event(o->event_ctx, kind, arg, err);
}

void wri_or_note_err(wri_osdc *o, wr_status st, const char *what, uint64_t a0, uint64_t a1, uint64_t a2)
{
	WRI_ERRINFO(&o->err, st, WR_MOD_OSD, what, a0, a1, a2);
}

/* ---- slots -------------------------------------------------------------------------------------------------------------- */

wri_osd_op *wri_osdc_at(const wri_osdc *o, uint32_t idx)
{
	if (o == NULL || o->op == NULL || idx >= o->n_op)
		return NULL;
	return &o->op[idx];
}

static void reserve_update(wri_osdc *o)
{
	uint32_t ctl = o->x->cfg.ctl_ops;

	o->n_free_ctl = ctl > o->n_ctl_used ? ctl - o->n_ctl_used : 0u;
}

uint32_t wri_osdc_alloc(wri_osdc *o, int control)
{
	wri_osd_op *op;
	uint32_t idx;

	if (o == NULL || o->op == NULL || o->n_free == 0)
		return WRI_NIL;
	if (!control && o->n_free <= o->n_free_ctl)
		return WRI_NIL; /* what is left belongs to the control ops */
	idx = o->free_head;
	op = &o->op[idx];
	o->free_head = op->next;
	o->n_free--;
	WR_MEMSET(op, 0, sizeof(*op));
	op->flags = WRI_OPF_ALLOC;
	op->next = op->prev = WRI_NIL;
	op->sess = WRI_NIL;
	op->last_sess = WRI_LAST_NONE;
	op->osd = -1;
	if (control) {
		op->flags = (uint8_t)(op->flags | WRI_OPF_CONTROL);
		o->n_ctl_used++;
		reserve_update(o);
	}
	return idx;
}

void wri_or_free_slot(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = &o->op[idx];

	if ((op->flags & WRI_OPF_CONTROL) != 0 && o->n_ctl_used != 0) {
		o->n_ctl_used--;
		reserve_update(o);
	}
	WR_MEMSET(op, 0, sizeof(*op));
	op->prev = WRI_NIL;
	op->sess = WRI_NIL;
	op->last_sess = WRI_LAST_NONE;
	op->osd = -1;
	op->next = o->free_head;
	o->free_head = idx;
	o->n_free++;
}

void wri_osdc_release(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = wri_osdc_at(o, idx);

	if (op == NULL)
		return;
	if (op->state == WRI_OP_FREE && (op->flags & WRI_OPF_ALLOC) != 0) {
		wri_or_free_slot(o, idx); /* allocated, never submitted */
		return;
	}
	if (op->state == WRI_OP_DONE && (op->flags & WRI_OPF_INRING) == 0)
		wri_or_free_slot(o, idx);
	/* anything else is not the owner's to give back: a live op, a zombie, a slot still in the done ring, a free slot */
}

uint32_t wri_osdc_count_owner(const wri_osdc *o, uint32_t tag, uint32_t mask)
{
	uint32_t i, n = 0;

	if (o == NULL || o->op == NULL)
		return 0;
	for (i = 0; i < o->n_op; i++)
		if (o->op[i].state != WRI_OP_FREE && (o->op[i].owner & mask) == tag)
			n++;
	return n;
}

/* ---- the submission list and the done ring ------------------------------------------------------------------------------ */

void wri_or_link_tail(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = &o->op[idx];

	op->prev = o->tail;
	op->next = WRI_NIL;
	if (o->tail != WRI_NIL)
		o->op[o->tail].next = idx;
	else
		o->head = idx;
	o->tail = idx;
}

void wri_or_unlink(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = &o->op[idx];

	if (op->prev != WRI_NIL)
		o->op[op->prev].next = op->next;
	else
		o->head = op->next;
	if (op->next != WRI_NIL)
		o->op[op->next].prev = op->prev;
	else
		o->tail = op->prev;
	op->next = op->prev = WRI_NIL;
}

uint32_t wri_or_bytes(const wri_osd_op *op)
{
	uint64_t v = (uint64_t)op->data_len + op->out_cap;

	return v > UINT32_MAX ? UINT32_MAX : (uint32_t)v;
}

void wri_or_detach(wri_osdc *o, wri_osd_op *op)
{
	if (op->state == WRI_OP_SENT && op->sess != WRI_NIL)
		wri_osd_sess_inflight(&o->sess, op->sess, -1);
	op->sess = WRI_NIL;
}

wri_osd_op *wri_or_find(wri_osdc *o, uint32_t s, uint64_t tid)
{
	uint64_t slot = tid & 0xffffu;
	wri_osd_op *op;

	if (slot >= o->n_op)
		return NULL;
	op = &o->op[slot];
	if (op->state != WRI_OP_SENT || op->tid != tid || op->sess != s)
		return NULL;
	return op;
}

void wri_or_complete(wri_osdc *o, uint32_t idx, wr_status st)
{
	wri_osd_op *op = &o->op[idx];
	uint32_t bytes;

	if (op->state == WRI_OP_FREE || op->state == WRI_OP_DONE)
		return; /* an op completes once */
	wri_or_detach(o, op);
	wri_or_unlink(o, idx);
	bytes = wri_or_bytes(op);
	o->inflight_bytes = o->inflight_bytes > bytes ? o->inflight_bytes - bytes : 0u;
	if (o->n_inflight != 0)
		o->n_inflight--;
	if ((op->flags & WRI_OPF_ZOMBIE) != 0) { /* the owner is gone: nobody is told */
		wri_or_zombie_free(o, op);
		wri_or_free_slot(o, idx);
		o->n_zombies_done++;
		return;
	}
	op->status = st;
	op->state = WRI_OP_DONE;
	op->flags = (uint8_t)(op->flags | WRI_OPF_INRING);
	o->done_ring[(o->done_pos + o->done_len) % o->n_op] = idx;
	o->done_len++;
	o->n_done++;
	if (st == WR_OK) {
		WR_MEMSET(&o->err, 0, sizeof(o->err)); /* the first failure since the last success */
	} else if (st != WR_E_CANCELLED) {
		o->n_failed++;
		if (o->err.status == WR_OK) { /* the first failure since the last success stays: later ones only count */
			wri_or_note_err(o, st, "object operation failed", op->tid, (uint64_t)(uint32_t)op->result, idx);
			o->err.peer_result = op->result < 0 ? op->result : 0;
		}
	}
}

uint32_t wri_osdc_pop_done(wri_osdc *o)
{
	uint32_t idx;

	if (o == NULL || o->op == NULL || o->done_len == 0)
		return WRI_NIL;
	idx = o->done_ring[o->done_pos];
	o->done_pos = (o->done_pos + 1u) % o->n_op;
	o->done_len--;
	o->op[idx].flags = (uint8_t)(o->op[idx].flags & ~WRI_OPF_INRING);
	return idx;
}

/* ---- submit ------------------------------------------------------------------------------------------------------------- */

static int known_code(uint16_t c)
{
	switch (c) {
	case WRI_OSD_OP_READ:
	case WRI_OSD_OP_STAT:
	case WRI_OSD_OP_SPARSE_READ:
	case WRI_OSD_OP_WRITE:
	case WRI_OSD_OP_WRITEFULL:
	case WRI_OSD_OP_TRUNCATE:
	case WRI_OSD_OP_ZERO:
	case WRI_OSD_OP_DELETE:
	case WRI_OSD_OP_CREATE:
	case WRI_OSD_OP_SETALLOCHINT:
	case WRI_OSD_OP_GETXATTR:
	case WRI_OSD_OP_CALL:
	case WRI_OSD_OP_OMAPGETVALS:
	case WRI_OSD_OP_OMAPGETVALSBYKEYS:
		return 1;
	default:
		return 0;
	}
}

/* The shape rules of the header, in one place: WR_OK or the status submit answers. */
static wr_status check_shape(const wri_osd_op *op)
{
	uint64_t sum = 0;
	unsigned i;

	if (op->kind != WRI_OPK_READ && op->kind != WRI_OPK_WRITE)
		return WR_E_INVAL;
	if (op->n_ops == 0 || op->n_ops > WRI_OSD_OPS_MAX)
		return WR_E_INVAL;
	if (op->oid_len == 0 || op->oid_len > WRI_OSD_OID_MAX)
		return WR_E_INVAL;
	if ((op->data_len != 0 && op->data == NULL) || (op->out_cap != 0 && op->out == NULL))
		return WR_E_INVAL;
	for (i = 0; i < op->n_ops; i++) {
		const wri_osd_opd *d = &op->ops[i];

		sum += d->in_len;
		if (!known_code(d->code))
			return WR_E_UNSUPPORTED;
		if (op->kind == WRI_OPK_READ && (d->code & 0x2000u) != 0)
			return WR_E_INVAL; /* a message that may write is a write-kind message: the OSD decides by the operation codes */
		if (d->code == WRI_OSD_OP_READ && d->len > op->out_cap)
			return WR_E_INVAL; /* the answer would not fit: a reply longer than the output is a protocol error that costs the whole session */
		if (d->code == WRI_OSD_OP_CALL && (uint32_t)d->cls_class_len + d->cls_method_len > d->in_len)
			return WR_E_INVAL;
	}
	if (sum != op->data_len)
		return WR_E_INVAL;
	return WR_OK;
}

wr_status wri_osdc_submit(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = wri_osdc_at(o, idx);
	uint64_t bytes, max;
	unsigned i;
	wr_status st;

	if (op == NULL)
		return WR_E_INVAL;
	if (op->state != WRI_OP_FREE || (op->flags & WRI_OPF_ALLOC) == 0)
		return WR_E_STATE;
	st = check_shape(op);
	if (st != WR_OK)
		return st;
	if (o->next_tid >= OR_TID_COUNTER_MAX)
		return WR_E_OVERFLOW;
	bytes = wri_or_bytes(op);
	max = o->x->cfg.inflight_bytes_max;
	if (max != 0) {
		if (bytes > max)
			return WR_E_TOOBIG;
		if ((uint64_t)o->inflight_bytes + bytes > max)
			return WR_E_BUSY;
	}
	for (i = 0; i < op->n_ops; i++) { /* the outputs are the engine's to fill */
		op->ops[i].out_len = 0;
		op->ops[i].rval = 0;
	}
	op->tid = (o->next_tid++ << 16) | idx;
	op->flags = (uint8_t)(op->flags & ~WRI_OPF_ALLOC);
	op->state = WRI_OP_NEW;
	op->sess = WRI_NIL;
	op->last_sess = WRI_LAST_NONE;
	op->osd = -1;
	op->retry_attempt = 0;
	op->submit_ms = o->x->now.mono_ms;
	op->sub_epoch = o->map.epoch(o->map.ctx);
	wri_or_link_tail(o, idx);
	o->n_inflight++;
	o->inflight_bytes += (uint32_t)bytes;
	if (o->n_inflight > o->hiwater)
		o->hiwater = o->n_inflight;
	return WR_OK;
}

/* ---- the engine's deadline ---------------------------------------------------------------------------------------------- */

uint64_t wri_osdc_deadline(const wri_osdc *o)
{
	uint64_t d = WR_DEADLINE_NONE, t, now;
	uint32_t i;
	int queued = 0;

	if (o == NULL || o->op == NULL)
		return WR_DEADLINE_NONE;
	now = o->x->now.mono_ms;
	if (o->rerun)
		return now; /* a session was lost under ops that wait for another one */
	for (i = o->head; i != WRI_NIL; i = o->op[i].next) {
		const wri_osd_op *op = &o->op[i];

		switch (op->state) {
		case WRI_OP_NEW:
			return now; /* waiting to be targeted */
		case WRI_OP_WAIT_MAP:
		case WRI_OP_HOMELESS:
		case WRI_OP_PAUSED:
			if (op->sent_epoch == 0) {
				t = wri_or_stale_due(o, op);
				if (t < d)
					d = t;
			}
			break;
		case WRI_OP_QUEUED:
			queued = 1;
			break;
		case WRI_OP_SENT:
			if (op->deadline_ms < d)
				d = op->deadline_ms;
			break;
		default:
			break;
		}
	}
	if (queued && o->retry_at_ms != 0 && o->retry_at_ms < d)
		d = o->retry_at_ms;
	if (o->sess_next_ms < d)
		d = o->sess_next_ms;
	return d;
}
