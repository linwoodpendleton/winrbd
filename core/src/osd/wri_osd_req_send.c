/* SPDX-License-Identifier: MIT */
/*
 * wri_osd_req_send.c - sending, replies, backoff and time (design 23.5, 23.6, 23.8).
 *
 * Sending. wri_osdc_step() walks the live ops in ascending tid order. An op that has a placement gets its session (acquire), waits for it to be
 * READY, is held by a backoff of that session if one covers it, and is encoded afresh (epoch, snapshot context, mtime, retry attempt, flags) and
 * handed to the session. A full transmit queue (WR_E_BUSY) leaves the op QUEUED and stops the pass for that session, so a later op never overtakes
 * an earlier one on the same connection. At most `budget` messages are encoded per call.
 *
 * Replies arrive through the session table's callbacks (the connection's step): sink (where the data of a reply goes), reply, bad_reply, ready,
 * lost, unblock. They only record what happened in the op table (state, results, the completion); the resends of the ops they free are done by the
 * next step, in tid order. The callbacks never change the submission list except by completing an op (reply, bad_reply), and those two run from the
 * connection's step, never from inside a pass of wri_osdc_step().
 *
 * Time. A SENT op has a deadline of op_timeout_ms << min(retry_attempt, 3) after its transmission. The OSD never answers a misdirected, stale-epoch or
 * backed-off request, so when a deadline passes the session is reset (a failure: it cools down), WR_EV_IO_STALL is raised once and every op of the
 * session is resent with retry_attempt + 1; WR_EV_IO_RESUME follows with the next reply. An op that lies inside a backoff of its session is not
 * silent but told to wait: its deadline is only pushed out.
 */
#include "wri_osd_req.h"

#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define OR_BUSY_RETRY_MS 10u /* a transmit queue that said BUSY is tried again after this long if the host consumed nothing sooner */

static uint64_t op_timeout(const wri_osdc *o, int32_t attempt)
{
	unsigned sh = attempt <= 0 ? 0u : (attempt >= 3 ? 3u : (unsigned)attempt);

	return (uint64_t)o->x->cfg.op_timeout_ms << sh;
}

/* ---- callbacks of the session table ------------------------------------------------------------------------------------- */

static void up_sink(void *ctx, uint32_t s, uint64_t tid, uint8_t **dst, uint32_t *cap, uint32_t *n_ops)
{
	wri_osdc *o = (wri_osdc *)ctx;
	wri_osd_op *op = wri_or_find(o, s, tid);

	if (op == NULL)
		return; /* a stray: nothing is stored */
	*n_ops = op->n_ops;
	if (op->out != NULL && op->out_cap != 0 && (op->flags & WRI_OPF_ZOMBIE) == 0) {
		*dst = op->out;
		*cap = op->out_cap;
	}
}

static void resume(wri_osdc *o)
{
	if (o->stalled) {
		o->stalled = 0;
		wri_or_event(o, WR_EV_IO_RESUME, 0xffffffffu, NULL);
	}
}

/* A reply for an op that must go again under a new tid (-EAGAIN: the OSD answered before it executed anything). */
static void resubmit(wri_osdc *o, uint32_t idx)
{
	wri_osd_op *op = &o->op[idx];

	o->n_eagain++;
	wri_or_detach(o, op);
	wri_or_unlink(o, idx);
	op->tid = (o->next_tid++ << 16) | idx;
	wri_or_link_tail(o, idx);
	op->state = WRI_OP_NEW; /* targeted again from scratch; retry_attempt is kept, so the next message already carries RETRY */
}

/* The checks of a decoded reply against the op it answers; WR_OK or the status the op ends with. */
static wr_status check_reply(const wri_osd_op *op, const wri_mosdopreply *rep, uint32_t stored)
{
	unsigned i;

	if (rep->n_ops != op->n_ops)
		return WR_E_OSD_PROTO;
	for (i = 0; i < op->n_ops; i++) {
		/* a read never returns more than it was asked for, and a negative result carries no output */
		if (op->ops[i].code == WRI_OSD_OP_READ && rep->out_len[i] > op->ops[i].len)
			return WR_E_OSD_PROTO;
	}
	if (stored > rep->out_total || (rep->out_total != 0 && op->out == NULL))
		return WR_E_OSD_PROTO; /* an op without an output buffer gets no output */
	return WR_OK;
}

static int has_call(const wri_osd_op *op)
{
	unsigned i;

	for (i = 0; i < op->n_ops; i++)
		if (op->ops[i].code == WRI_OSD_OP_CALL)
			return 1;
	return 0;
}

/* A reply that passed the stale, redirect and EAGAIN rules and matches its op: record the outputs and complete the op. */
OR_NOINLINE static void finish_reply(wri_osdc *o, uint32_t idx, const wri_mosdopreply *rep, uint32_t stored)
{
	wri_osd_op *op = &o->op[idx];
	unsigned i;
	wr_status st;

	if ((op->flags & WRI_OPF_ZOMBIE) != 0) { /* the owner is gone: the answer only ends the op */
		op->result = rep->result;
		wri_or_complete(o, idx, WR_OK);
		return;
	}
	st = check_reply(op, rep, stored);
	if (st != WR_OK) {
		wri_or_note_err(o, st, "reply does not match the operation it answers", rep->n_ops, op->n_ops, op->tid);
		wri_or_complete(o, idx, st);
		return;
	}
	for (i = 0; i < op->n_ops; i++) {
		op->ops[i].out_len = rep->out_len[i];
		op->ops[i].rval = rep->rval[i];
	}
	op->result = rep->result;
	op->user_version = rep->user_version;
	op->out_stored = stored; /* what landed: a failed message's outputs are the owner's to use or not (a header read looks at the per-operation rval) */
	st = wri_osd_errno_status(rep->result);
	if (st == WR_E_OSD_NOENT && rep->result == -WRI_ERRNO_EOPNOTSUPP && !has_call(op))
		st = WR_E_OSD_ERRNO; /* "no such class or method" is only that for a CALL: a data operation the OSD cannot do is an error, never a missing object (which reads as zeros) */
	wri_or_complete(o, idx, st);
}

static void up_reply(void *ctx, uint32_t s, uint64_t tid, const wri_mosdopreply *rep, uint32_t stored)
{
	wri_osdc *o = (wri_osdc *)ctx;
	wri_osd_op *op = wri_or_find(o, s, tid);
	uint32_t idx;

	if (op == NULL) {
		o->n_stray++; /* a reply nobody waits for says nothing about the ops that do wait: no resume */
		return;
	}
	resume(o); /* the OSD is answering */
	idx = (uint32_t)(op - o->op);
	if (rep->retry_attempt >= 0 && rep->retry_attempt != op->retry_attempt) {
		o->n_stale++; /* the answer to an earlier transmission: the one that counts is still to come */
		return;
	}
	if (rep->do_redirect) {
		o->n_redirect++;
		op->result = rep->result;
		wri_or_complete(o, idx, WR_E_OSD_REDIRECT);
		return;
	}
	if (rep->result == -WRI_ERRNO_EAGAIN) {
		resubmit(o, idx);
		return;
	}
	finish_reply(o, idx, rep, stored);
}

static void up_bad_reply(void *ctx, uint32_t s, uint64_t tid, const wr_errinfo *why)
{
	wri_osdc *o = (wri_osdc *)ctx;
	wri_osd_op *op = wri_or_find(o, s, tid);

	if (op == NULL)
		return;
	/* the answer is broken, so the op ends with that: resending to an OSD that sends garbage would only repeat it */
	wri_or_complete(o, (uint32_t)(op - o->op), why != NULL && why->status != WR_OK ? why->status : WR_E_OSD_PROTO);
}

static void up_ready(void *ctx, uint32_t s)
{
	(void)ctx;
	(void)s; /* the ops waiting for this session are sent by the next step (the connections ran before it) */
}

static void up_lost(void *ctx, uint32_t s, const wr_errinfo *why)
{
	wri_osdc *o = (wri_osdc *)ctx;
	const wri_osd_sess *sp = wri_osd_sess_at(&o->sess, s);
	uint32_t osd = sp != NULL && sp->osd >= 0 ? (uint32_t)sp->osd : 0xffffffffu;
	uint32_t i, n = 0;

	for (i = 0; i < o->n_op; i++) {
		wri_osd_op *op = &o->op[i];

		if (op->last_sess == s)
			op->last_sess = WRI_LAST_NONE; /* the connection and its queues are gone: nothing of this op is referenced there any more */
		if (op->sess != s)
			continue;
		if (op->state == WRI_OP_SENT || op->state == WRI_OP_WAIT_SESS || op->state == WRI_OP_QUEUED) {
			op->state = WRI_OP_WAIT_SESS; /* it asks for a session again (a SENT one is resent: retry_attempt + 1 at its transmission) */
			op->sess = WRI_NIL;
			n++;
		}
	}
	if (n != 0 && why != NULL && why->status != WR_OK && !o->stalled) {
		o->stalled = 1;
		wri_or_event(o, WR_EV_IO_STALL, osd, why);
	}
}

static void up_unblock(void *ctx, uint32_t s, int64_t pool, uint32_t pg_seed)
{
	wri_osdc *o = (wri_osdc *)ctx;
	uint32_t i;

	/* the OSD may have dropped what lay inside the range while the backoff stood: every op of that PG on the wire goes again (the range is not
	 * told to us; an op outside it is sent twice, which a resend always may be) */
	for (i = 0; i < o->n_op; i++) {
		wri_osd_op *op = &o->op[i];

		if (op->state != WRI_OP_SENT || op->sess != s || op->pool_id != pool || op->pg_seed != pg_seed)
			continue;
		wri_or_detach(o, op);
		op->state = WRI_OP_WAIT_SESS;
		o->n_unblock_resend++;
	}
}

void wri_or_up(wri_osdc *o, wri_osd_sess_up *up)
{
	WR_MEMSET(up, 0, sizeof(*up));
	up->ctx = o;
	up->sink = up_sink;
	up->reply = up_reply;
	up->bad_reply = up_bad_reply;
	up->ready = up_ready;
	up->lost = up_lost;
	up->unblock = up_unblock;
}

/* ---- sending ------------------------------------------------------------------------------------------------------------ */

/* The message header of op for session sp: everything about the request that is not an operation, read at this moment (design 23.5). */
OR_NOINLINE static void fill_hdr(const wri_osdc *o, const wri_osd_op *op, const wri_osd_sess *sp, uint32_t epoch, int32_t attempt, wri_mosdop_hdr *h)
{
	int write = op->kind == WRI_OPK_WRITE;
	uint64_t wall = o->x->now.wall_ms;
	uint32_t osdf = o->x->cfg.osd_flags;

	WR_MEMSET(h, 0, sizeof(*h));
	h->version = (uint8_t)sp->msg_version;
	h->pool = op->pool_id;
	h->pg_seed = op->pg_seed;
	h->hash = op->hash;
	h->map_epoch = epoch;
	h->flags = write ? WRI_OSDF_BASE_WRITE : WRI_OSDF_BASE_READ;
	if (write && (osdf & WR_OSDF_FULL_TRY) != 0)
		h->flags |= WRI_OSDF_FULL_TRY;
	if (write && (osdf & WR_OSDF_ORDERSNAP) != 0)
		h->flags |= WRI_OSDF_ORDERSNAP;
	if (write && wall != 0 && wall <= (uint64_t)INT64_MAX) { /* no wall clock: mtime 0, which the OSD stores (osd-ops.md Q4); no 64-bit division: i386 hosts */
		int64_t sec = wri_div_s64_u32((int64_t)wall, 1000u);

		if (sec <= (int64_t)UINT32_MAX) {
			h->mtime_sec = (uint32_t)sec;
			h->mtime_nsec = (uint32_t)(((int64_t)wall - sec * 1000) * 1000000);
		}
	}
	h->oid = op->oid;
	h->oid_len = op->oid_len;
	h->snapid = WRI_SNAP_NOSNAP;
	h->snapc = write ? op->snapc : NULL;
	h->retry_attempt = attempt;
	h->features = sp->features;
}

/* Encode op into the scratch and hand it to session s. WR_OK, WR_E_BUSY (the transmit queue is full) or what made the message impossible. */
OR_NOINLINE static wr_status encode_send(wri_osdc *o, wri_osd_op *op, uint32_t s, uint32_t epoch, int32_t attempt)
{
	const wri_osd_sess *sp = wri_osd_sess_at(&o->sess, s);
	wri_mosdop_hdr h;
	wri_m2_msg_out m;
	wri_wr w;
	wr_status st;

	fill_hdr(o, op, sp, epoch, attempt, &h);
	wri_wr_init(&w, o->scratch, o->x->cfg.osd_front_cap);
	st = wri_mosdop_encode(&w, &h, op->ops, op->n_ops);
	if (st != WR_OK)
		return st;
	WR_MEMSET(&m, 0, sizeof(m));
	m.type = (uint16_t)WRI_MSG_OSD_OP;
	m.priority = (uint16_t)WRI_MSG_PRIO_CLIENT;
	m.version = sp->msg_version;
	m.compat_version = (uint16_t)WRI_MOSDOP_COMPAT;
	m.tid = op->tid;
	m.front = o->scratch;
	m.front_len = (uint32_t)wri_wr_len(&w);
	m.data = op->data_len != 0 ? op->data : NULL;
	m.data_len = op->data_len;
	return wri_osd_sess_send(&o->sess, s, &m);
}

/* The session the op can be sent on now: acquire (at the address the map gave a moment ago), READY, no full queue ahead of it in this pass, no backoff over
 * it. 1 and *out, or 0 (the op's state says why it waits). */
OR_NOINLINE static int usable_session(wri_osdc *o, wri_osd_op *op, const wr_addr *addr, uint32_t *out)
{
	uint32_t s = WRI_NIL;
	wr_status st = wri_osd_sess_acquire(&o->sess, op->osd, addr, &s);

	if (st != WR_OK || s >= o->sess.n) { /* BUSY: connecting, cooling down, no slot, no ticket; the next step asks again */
		op->sess = WRI_NIL;
		op->state = WRI_OP_WAIT_SESS;
		return 0;
	}
	op->sess = s;
	if (!wri_osd_sess_ready(&o->sess, s)) {
		op->state = WRI_OP_WAIT_SESS;
		return 0;
	}
	if (o->sess_pass[s] == o->pass) { /* an earlier op of this session met a full queue in this pass: nothing overtakes it */
		op->state = WRI_OP_QUEUED;
		return 0;
	}
	if (wri_osd_sess_blocked(&o->sess, s, op->pool_id, op->pg_seed, op->hash, op->oid, op->oid_len)) {
		op->state = WRI_OP_QUEUED; /* held until the UNBLOCK (or the end of the session) */
		o->n_blocked_held++;
		return 0;
	}
	*out = s;
	return 1;
}

/* The op is on the wire: its bookkeeping. */
OR_NOINLINE static void commit_sent(wri_osdc *o, wri_osd_op *op, uint32_t s, uint32_t epoch, int32_t attempt)
{
	uint64_t now = o->x->now.mono_ms;

	op->retry_attempt = attempt;
	op->sent_epoch = epoch;
	op->sent_ms = now;
	op->deadline_ms = now + op_timeout(o, attempt);
	op->state = WRI_OP_SENT;
	op->tx_mask |= (uint32_t)1 << (s & 31u);
	op->last_sess = (uint16_t)s;
	wri_osd_sess_inflight(&o->sess, s, 1);
	if (attempt > 0)
		o->n_resent++;
}

void wri_or_send_one(wri_osdc *o, uint32_t idx, uint32_t budget, uint32_t *sent, int *more, int changed, int skipped)
{
	wri_osd_op *op = &o->op[idx];
	wri_place pl;
	uint32_t s = WRI_NIL;
	int32_t attempt;
	wr_status st;

	/* held ops (no primary, a pause) and ops on the wire only look at a new map; everything else is targeted now: a new op, one waiting for a session or for
	 * the map (the pool may have appeared), one that must go again */
	if (op->state == WRI_OP_SENT || op->state == WRI_OP_HOMELESS || op->state == WRI_OP_PAUSED) {
		if (!changed)
			return;
	}
	if (!wri_or_retarget(o, idx, changed, skipped, &pl))
		return; /* it waits for the map, ended, or is still on the wire */
	if (!usable_session(o, op, &pl.t.primary_addr, &s))
		return;
	if (*sent >= budget) {
		op->state = WRI_OP_QUEUED;
		*more = 1;
		return;
	}
	attempt = op->sent_epoch != 0 ? (op->retry_attempt < INT32_MAX ? op->retry_attempt + 1 : INT32_MAX) : 0;
	wri_or_quiet_prev(o, op, s); /* an earlier transmission on another session must not touch the buffers any more */
	st = encode_send(o, op, s, pl.t.epoch, attempt);
	if (st == WR_OK) {
		commit_sent(o, op, s, pl.t.epoch, attempt);
		(*sent)++;
	} else if (st == WR_E_BUSY) {
		op->state = WRI_OP_QUEUED;
		o->sess_pass[s] = o->pass;
		o->retry_at_ms = o->x->now.mono_ms + OR_BUSY_RETRY_MS;
	} else if (st == WR_E_STATE) { /* the session went away under us */
		op->state = WRI_OP_WAIT_SESS;
		op->sess = WRI_NIL;
	} else { /* the message cannot be made: the op ends with the reason */
		wri_or_quiet_prev(o, op, WRI_NIL);
		wri_or_complete(o, idx, st);
	}
}

/* ---- time --------------------------------------------------------------------------------------------------------------- */

void wri_or_timeouts(wri_osdc *o)
{
	uint64_t now = o->x->now.mono_ms;
	uint32_t i;

	for (i = o->head; i != WRI_NIL; i = o->op[i].next) {
		wri_osd_op *op = &o->op[i];
		wr_errinfo e;
		uint32_t s = op->sess;

		if (op->state != WRI_OP_SENT || op->deadline_ms > now)
			continue;
		if (s == WRI_NIL) {
			op->state = WRI_OP_WAIT_SESS; /* cannot happen: a SENT op has a session */
			continue;
		}
		if (wri_osd_sess_blocked(&o->sess, s, op->pool_id, op->pg_seed, op->hash, op->oid, op->oid_len)) {
			op->deadline_ms = now + op_timeout(o, op->retry_attempt); /* told to wait by the OSD: not silence */
			continue;
		}
		WR_MEMSET(&e, 0, sizeof(e));
		WRI_ERRINFO(&e, WR_E_TIMEOUT, WR_MOD_OSD, "operation unanswered: the OSD session is reset", (uint32_t)op->osd, op->tid,
			    (uint64_t)(uint32_t)op->retry_attempt);
		o->n_timeouts++;
		wri_osd_sess_reset(&o->sess, s, &e); /* every op of the session is resent (up_lost); WR_EV_IO_STALL goes out from there */
	}
}

/* ---- the pass ----------------------------------------------------------------------------------------------------------- */

int wri_osdc_step(wri_osdc *o, uint32_t budget)
{
	uint32_t epoch, seen, i, nxt, sent = 0;
	int changed, skipped, more = 0;

	if (o == NULL || o->op == NULL)
		return 0;
	if (++o->pass == 0) { /* the pass counter wrapped: forget the marks of the old passes */
		WR_MEMSET(o->sess_pass, 0, (size_t)o->sess.n * sizeof(uint32_t));
		o->pass = 1;
	}
	o->retry_at_ms = 0;
	wri_or_timeouts(o);
	o->rerun = 0; /* what the timeouts and the connections left since the last pass is handled by the walk below; a reset inside the walk sets the flag again */
	epoch = o->map.epoch(o->map.ctx);
	seen = o->map_epoch_seen;
	changed = epoch != 0 && epoch != seen;
	skipped = changed && seen != 0 && (epoch < seen || epoch - seen > 1u); /* a gap: every op on the wire goes again */
	if (changed) {
		o->map_epoch_seen = epoch;
		o->map_since_ms = 0;
	}
	for (i = o->head; i != WRI_NIL; i = nxt) {
		nxt = o->op[i].next; /* targeting and sending may complete (unlink) this op, never another one */
		wri_or_send_one(o, i, budget, &sent, &more, changed, skipped);
	}
	wri_or_stale(o);
	o->sess_next_ms = wri_osd_sess_step(&o->sess);
	return more || o->rerun != 0;
}
