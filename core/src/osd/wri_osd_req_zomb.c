/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_req_zomb.c - cancel and the zombie area (design 23.9, osd-ops.md 3.3 item 7).
 *
 * A write that was transmitted may have been applied, so it is never abandoned (23.7): cancelling it copies what it needs to be sent again (its data
 * and its snapshot context) into the zombie area, a first-fit region of the bulk memory, and the op goes on as a ZOMBIE until the cluster answers it.
 * Everything else is simply dropped: a read, and a write that never left. The owner's buffers are free when wri_osdc_cancel() returns WR_OK; the
 * only thing that makes it refuse is a zombie area without room (WR_E_BUSY, nothing changed).
 *
 * The block of a zombie is [data, padded to 8][wri_snapc][snapshot ids] (the last two only when the op has a snapshot context); its offset and size
 * are in the op (zoff, zlen), so the area needs no table of its own: the free space is what no live zombie covers.
 */
#include "wri_osd_req.h"

WR_FILE_LICENCE_MIT

#define Z_ALIGN 8u

static uint64_t align8(uint32_t v)
{
	return ((uint64_t)v + (Z_ALIGN - 1u)) & ~(uint64_t)(Z_ALIGN - 1u); /* 64 bits: a length near 4 GiB must not wrap to 0 and read as "nothing to copy" */
}

/* Snapshot ids a context really holds (a context whose array pointer is missing holds none). */
static uint32_t snap_count(const wri_snapc *sc)
{
	return sc->snaps != NULL ? sc->n : 0u;
}

/* Bytes the block of op needs, or 0 when it needs none (no data, no context); UINT32_MAX when the sum does not fit 32 bits. */
static uint32_t block_size(const wri_osd_op *op)
{
	uint64_t v = align8(op->data_len);

	if (op->snapc != NULL) {
		v += align8((uint32_t)sizeof(wri_snapc));
		v += (uint64_t)snap_count(op->snapc) * 8u;
	}
	return v > UINT32_MAX - Z_ALIGN ? UINT32_MAX : (uint32_t)v;
}

/* The lowest offset where `need` bytes fit between the live zombies; 1 and *off, or 0. */
static int first_fit(const wri_osdc *o, uint32_t need, uint32_t *off)
{
	uint64_t cand = 0;
	uint32_t i;
	int moved;

	if (need > o->zcap || o->zbuf == NULL)
		return 0;
	do {
		moved = 0;
		for (i = 0; i < o->n_op; i++) {
			const wri_osd_op *z = &o->op[i];

			if (z->state == WRI_OP_FREE || (z->flags & WRI_OPF_ZOMBIE) == 0 || z->zlen == 0)
				continue;
			if ((uint64_t)z->zoff < cand + need && cand < (uint64_t)z->zoff + z->zlen) {
				cand = (uint64_t)z->zoff + z->zlen; /* overlaps: try right behind it */
				moved = 1;
			}
		}
		if (cand + need > o->zcap)
			return 0;
	} while (moved);
	*off = (uint32_t)cand;
	return 1;
}

void wri_or_zombie_free(wri_osdc *o, wri_osd_op *op)
{
	if (op->zlen != 0)
		o->zused = o->zused > op->zlen ? o->zused - op->zlen : 0u;
	op->zlen = 0;
	op->zoff = 0;
}

/* Copy the block of op to `off` and point the op at the copy. */
static void make_block(wri_osdc *o, wri_osd_op *op, uint32_t off, uint32_t size)
{
	uint8_t *blk = o->zbuf + off;
	uint32_t at = (uint32_t)align8(op->data_len); /* the block fits first_fit's zcap (32 bits), so this does too */

	if (op->data_len != 0) {
		WR_MEMCPY(blk, op->data, op->data_len);
		op->data = blk;
	} else {
		op->data = NULL;
	}
	if (op->snapc != NULL) {
		wri_snapc *zs = (wri_snapc *)(void *)(blk + at);
		uint64_t *ids = (uint64_t *)(void *)(blk + at + (uint32_t)align8((uint32_t)sizeof(wri_snapc)));
		uint32_t i, n = snap_count(op->snapc);

		for (i = 0; i < n; i++)
			ids[i] = op->snapc->snaps[i];
		zs->seq = op->snapc->seq;
		zs->n = n;
		zs->cap = n;
		zs->snaps = ids;
		op->snapc = zs;
	}
	op->zoff = off;
	op->zlen = size;
	o->zused += size;
	if (o->zused > o->zmax)
		o->zmax = o->zused;
}

/*
 * Stop every transport that still moves bytes of the buffers of op before they are given back: a session that is receiving the reply of this tid into
 * op->out (any session: the op may have moved on since), and every session the op was transmitted on whose transmit queue can still point into op->data
 * (a read sends no data and a write that never left has queued none, so a busy queue alone is no reason for them). Each such session is reset (orderly:
 * no cool-down; its other ops are resent). 1 if one was reset.
 */
static int quiet_buffers(wri_osdc *o, const wri_osd_op *op)
{
	uint32_t s;
	int any = 0, tx = op->data_len != 0 && op->sent_epoch != 0;

	for (s = 0; s < o->sess.n; s++) {
		int busy = tx && ((op->tx_mask >> (s & 31u)) & 1u) != 0 && !wri_osd_sess_tx_idle(&o->sess, s);

		if (o->sess.s[s].rx_tid == op->tid || busy) {
			wri_osd_sess_reset(&o->sess, s, NULL);
			o->rerun = 1; /* the other ops of that session wait for a new connection: the engine must run again at once */
			any = 1;
		}
	}
	return any;
}

wr_status wri_osdc_cancel(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = wri_osdc_at(o, idx);
	uint32_t off = 0, size = 0, bytes;

	if (op == NULL)
		return WR_E_INVAL;
	if (op->state == WRI_OP_FREE)
		return WR_E_STATE;
	if (op->state == WRI_OP_DONE || (op->flags & WRI_OPF_ZOMBIE) != 0)
		return WR_OK;
	/* a write that left may have been applied; one that never left and a read can simply be dropped */
	if (op->kind == WRI_OPK_WRITE && op->sent_epoch != 0) {
		size = block_size(op);
		if (size != 0 && !first_fit(o, size, &off))
			return WR_E_BUSY; /* no room for the copy: nothing is changed, the op stays live */
	}
	if (quiet_buffers(o, op))
		op->flags = (uint8_t)(op->flags | WRI_OPF_MIDRX);
	if (op->kind == WRI_OPK_WRITE && op->sent_epoch != 0) {
		if (size != 0)
			make_block(o, op, off, size);
		bytes = op->out_cap; /* the output is detached: it leaves the budget of the wire */
		o->inflight_bytes = o->inflight_bytes > bytes ? o->inflight_bytes - bytes : 0u;
		op->out = NULL;
		op->out_cap = 0;
		op->flags = (uint8_t)(op->flags | WRI_OPF_ZOMBIE);
		o->n_zombies++;
		return WR_OK;
	}
	wri_or_complete(o, idx, WR_E_CANCELLED);
	op->out = NULL;
	op->data = NULL;
	return WR_OK;
}

/* ---- an op that left a session ------------------------------------------------------------------------------------------ */

void wri_or_quiet_prev(wri_osdc *o, const wri_osd_op *op, uint32_t keep)
{
	uint32_t p = op->last_sess;
	const wri_osd_sess *sp;

	if (op->last_sess == WRI_LAST_NONE || p == keep)
		return; /* the same session: its queue is in order, what it sends next is behind what it holds (and the reply to the older copy is dropped as stale) */
	sp = wri_osd_sess_at(&o->sess, p);
	if (sp == NULL)
		return;
	if (sp->rx_tid == op->tid || (op->data_len != 0 && !wri_osd_sess_tx_idle(&o->sess, p))) {
		/* the old connection may still be reading the answer into op->out or sending op->data: close it (orderly, no cool-down; its other ops are resent) */
		wri_osd_sess_reset(&o->sess, p, NULL);
		o->n_quiesced++;
		o->rerun = 1; /* the ops of that session that the walk already passed are asked again by the next pass */
	}
}
