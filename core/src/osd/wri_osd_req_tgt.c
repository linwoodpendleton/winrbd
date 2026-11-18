/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_req_tgt.c - where an operation goes (design 23.3), what a new map does to the ops already placed (23.4) and the map-stale rule (23.8).
 *
 * wri_or_place() only asks the map and says what the answer means; wri_or_retarget() applies it to one op, including the decision "resend or not"
 * for an op that is on the wire. The rules for an op that is SENT:
 *   - it is resent when its primary or the primary's address changed, its PG seed changed (a split or a merge), the pool's last_force_op_resend is
 *     above the epoch of its last transmission, or the epoch advanced by more than one since the last pass (`skipped`); a change of a replica only is
 *     not a reason;
 *   - it goes back to the homeless state when the PG has no usable primary (it is resent when there is one again);
 *   - a pause or a full pool never pulls back an op that is already on the wire (the flags hold unsent ops only);
 *   - a pool that vanished fails it (nothing can answer it any more), a pool with the EIO flag or an unusable status fails it too.
 * An op that is not SENT simply takes the new placement; it is sent from there.
 */
#include "wri_osd_req.h"

WR_FILE_LICENCE_MIT

static int addr_same(const wr_addr *a, const wr_addr *b)
{
	unsigned i, n;

	if (a->family != b->family || a->port != b->port || a->nonce != b->nonce)
		return 0;
	n = a->family == WR_AF_IPV4 ? 4u : (a->family == WR_AF_IPV6 ? 16u : 0u);
	for (i = 0; i < n; i++)
		if (a->ip[i] != b->ip[i])
			return 0;
	return 1;
}

/* ---- the placement of one op -------------------------------------------------------------------------------------------- */

/* The map does not have the pool: still to come, or gone? (23.3) */
static void not_found(const wri_osdc *o, const wri_osd_op *op, uint32_t epoch, wri_place *p)
{
	uint64_t stale = o->x->cfg.map_stale_ms, age = o->x->now.mono_ms - op->submit_ms;
	int gone;

	if (op->sent_epoch != 0) /* the pool was there when the op was sent: a newer map without it is a deletion */
		gone = epoch > op->sent_epoch;
	else if (stale != 0) /* a pool tracked after the first map reads as missing until the full map the engine asked for arrives */
		gone = age >= stale && epoch >= op->sub_epoch;
	else
		gone = epoch > op->sub_epoch;
	p->outcome = gone ? WRI_PL_FAIL : WRI_PL_WAIT_MAP;
	p->status = WR_E_POOL_NOT_FOUND;
}

/* Stage 1: the pool. 1 if the pool is usable; else p says what to do with the op. */
OR_NOINLINE static int place_pool(const wri_osdc *o, const wri_osd_op *op, uint32_t epoch, wri_place *p)
{
	wr_status st = o->map.pool_info(o->map.ctx, op->pool, &p->pi);

	if (st == WR_E_MAP_NONE) {
		p->outcome = WRI_PL_WAIT_MAP;
		return 0;
	}
	if (st == WR_E_POOL_NOT_FOUND) {
		not_found(o, op, epoch, p);
		return 0;
	}
	if (st != WR_OK || p->pi.status != WR_OK) { /* WR_E_POOL_UNSUPPORTED, WR_E_CRUSH_NO_RULE, ...: the op ends with that */
		p->outcome = WRI_PL_FAIL;
		p->status = st != WR_OK ? st : p->pi.status;
		return 0;
	}
	if ((p->pi.flags & WR_POOL_F_EIO) != 0) { /* SUPPORTSPOOLEIO is set on every request: the OSD stays silent, so the client answers */
		p->outcome = WRI_PL_FAIL;
		p->status = WR_E_OSD_IO;
		return 0;
	}
	return 1;
}

/* Stage 2: the object's target. 1 if there is one. */
OR_NOINLINE static int place_target(const wri_osdc *o, const wri_osd_op *op, uint32_t epoch, wri_place *p)
{
	wr_object_id oid;
	wr_status st;

	WR_MEMSET(&oid, 0, sizeof(oid));
	oid.name = op->oid;
	oid.name_len = op->oid_len;
	st = o->map.target(o->map.ctx, op->pool, &oid, &p->t);
	if (st == WR_E_MAP_NONE) {
		p->outcome = WRI_PL_WAIT_MAP;
		return 0;
	}
	if (st == WR_E_POOL_NOT_FOUND) {
		not_found(o, op, epoch, p);
		return 0;
	}
	if (st == WR_E_PLACE_UNMAPPABLE || (st == WR_OK && (p->t.primary_addr.family == 0 || p->t.acting_primary < 0))) {
		p->outcome = WRI_PL_HOMELESS;
		return 0;
	}
	if (st != WR_OK) {
		p->outcome = WRI_PL_FAIL;
		p->status = st;
		return 0;
	}
	return 1;
}

/* Stage 3: is it held back by a pause or a full pool? */
static int held_back(const wri_osdc *o, const wri_osd_op *op, uint64_t pool_flags)
{
	uint32_t mflags = o->map.flags(o->map.ctx), osdf = o->x->cfg.osd_flags;

	if ((osdf & WR_OSDF_HONOR_PAUSE) != 0 &&
	    ((op->kind == WRI_OPK_READ && (mflags & WR_MAP_F_PAUSERD) != 0) || (op->kind == WRI_OPK_WRITE && (mflags & WR_MAP_F_PAUSEWR) != 0)))
		return 1;
	/* writes carry FULL_TRY by default and are answered ENOSPC; without it a full pool would swallow them, so the client holds them */
	return op->kind == WRI_OPK_WRITE && (osdf & WR_OSDF_FULL_TRY) == 0 &&
	       ((pool_flags & (WR_POOL_F_FULL | WR_POOL_F_FULL_QUOTA)) != 0 || (mflags & WR_MAP_F_FULL) != 0);
}

void wri_or_place(const wri_osdc *o, const wri_osd_op *op, wri_place *p)
{
	uint32_t epoch = o->map.epoch(o->map.ctx);

	WR_MEMSET(p, 0, sizeof(*p));
	if (epoch == 0) {
		p->outcome = WRI_PL_WAIT_MAP;
		return;
	}
	if (!place_pool(o, op, epoch, p) || !place_target(o, op, epoch, p))
		return;
	p->outcome = held_back(o, op, p->pi.flags) ? WRI_PL_PAUSED : WRI_PL_OK;
}

/* ---- applying it -------------------------------------------------------------------------------------------------------- */

static void take_placement(wri_osd_op *op, const wr_target *t)
{
	op->osd = t->acting_primary;
	op->pool_id = t->pool_id;
	op->pg_seed = t->pg_seed;
	op->hash = t->ps;
}

int wri_or_retarget(wri_osdc *o, uint32_t idx, int changed, int skipped, wri_place *p)
{
	wri_osd_op *op = &o->op[idx];
	int sent = op->state == WRI_OP_SENT;

	if (sent && !changed)
		return 0;
	wri_or_place(o, op, p);
	switch (p->outcome) {
	case WRI_PL_FAIL:
		wri_or_quiet_prev(o, op, WRI_NIL); /* it ends without an answer: no connection may keep a reference to its buffers */
		wri_or_complete(o, idx, p->status);
		return 0;
	case WRI_PL_WAIT_MAP:
		if (!sent) {
			op->sess = WRI_NIL;
			op->state = WRI_OP_WAIT_MAP;
		}
		return 0;
	case WRI_PL_HOMELESS:
		if (sent)
			wri_or_detach(o, op); /* the primary is gone: the op leaves its session and waits for a map that names one */
		op->sess = WRI_NIL;
		op->osd = -1;
		op->state = WRI_OP_HOMELESS;
		return 0;
	case WRI_PL_PAUSED:
		if (!sent) {
			op->sess = WRI_NIL;
			op->state = WRI_OP_PAUSED;
		}
		return 0;
	default:
		break;
	}
	if (sent) { /* the address it went to is the one its session was opened to */
		const wri_osd_sess *sp = wri_osd_sess_at(&o->sess, op->sess);
		int resend = skipped || p->t.acting_primary != op->osd || p->t.pg_seed != op->pg_seed || sp == NULL ||
			     !addr_same(&p->t.primary_addr, &sp->addr) || p->pi.last_force_op_resend > op->sent_epoch;

		if (!resend)
			return 0; /* only a replica (or nothing that matters) changed */
		wri_or_detach(o, op); /* the old session loses one op in flight; it is not reset */
	}
	take_placement(op, &p->t);
	op->sess = WRI_NIL;
	op->state = WRI_OP_WAIT_SESS;
	return 1;
}

/* ---- the map-stale rule ------------------------------------------------------------------------------------------------- */

static uint32_t lo32(uint64_t ms)
{
	uint32_t v = (uint32_t)(ms & 0xffffffffu);

	return v != 0 ? v : 1u; /* 0 means "not running" */
}

uint64_t wri_or_stale_due(const wri_osdc *o, const wri_osd_op *op)
{
	uint64_t stale = o->x->cfg.map_stale_ms, now = o->x->now.mono_ms, base = op->submit_ms;

	if (stale == 0)
		return WR_DEADLINE_NONE;
	if (o->map_since_ms != 0) {
		uint64_t since = now - (uint32_t)(lo32(now) - o->map_since_ms); /* the low word back to an absolute time (wrap safe) */

		if (since > base)
			base = since;
	}
	return base + stale;
}

static int map_waiting(const wri_osd_op *op)
{
	return op->state == WRI_OP_WAIT_MAP || op->state == WRI_OP_HOMELESS || op->state == WRI_OP_PAUSED;
}

void wri_or_stale(wri_osdc *o)
{
	uint64_t now = o->x->now.mono_ms;
	uint32_t i, nxt;
	int any = 0;

	if (o->x->cfg.map_stale_ms == 0) {
		o->map_since_ms = 0;
		return;
	}
	for (i = o->head; i != WRI_NIL; i = o->op[i].next)
		if (map_waiting(&o->op[i])) {
			any = 1;
			break;
		}
	if (!any) {
		o->map_since_ms = 0; /* nothing waits for the map: the clock of "the map has not advanced" has nothing to measure */
		return;
	}
	if (o->map_since_ms == 0)
		o->map_since_ms = lo32(now);
	for (i = o->head; i != WRI_NIL; i = nxt) {
		wri_osd_op *op = &o->op[i];

		nxt = op->next;
		/* never an op that was on the wire (a write may have been applied): it waits for the map, for ever if it must */
		if (!map_waiting(op) || op->sent_epoch != 0 || (op->flags & WRI_OPF_ZOMBIE) != 0 || now < wri_or_stale_due(o, op))
			continue;
		{
			wr_errinfo e;

			WR_MEMSET(&e, 0, sizeof(e));
			WRI_ERRINFO(&e, WR_E_OSD_MAP_STALE, WR_MOD_OSD, "OSD map did not advance while an operation waited for it", o->map_epoch_seen,
				    o->x->cfg.map_stale_ms, op->state);
			if (!o->stalled) {
				o->stalled = 1;
				wri_or_event(o, WR_EV_IO_STALL, 0xffffffffu, &e);
			}
		}
		wri_or_complete(o, i, WR_E_OSD_MAP_STALE);
	}
}
