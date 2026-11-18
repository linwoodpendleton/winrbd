/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_resend.c - what makes an operation go again, and what must not: the connection cut after the OSD applied a write (the answer lost) with and
 * without the OSD's duplicate detection, EAGAIN (a new tid), a redirect, stale answers of an earlier transmission, every row of the map-change table of
 * design 23.4 (primary moved, replica only, address, split, last_force_op_resend, skipped epochs, no primary, pool deleted, EIO flag, pool status), the
 * pause and full policy, resends in tid order, and the cooldown / refusal paths of the sessions as the ops see them (stall and resume events).
 * The OSD that holds the op is made silent so the op stays SENT while the test moves the map; the recorded requests of sim_osd are the oracle for tid,
 * retry_attempt, epoch, placement and order.
 */
#include "osd_req_rig.h"

static rig R;

static void tweak_silent0(rig *r)
{
	r->w.ocfg[0].fault.silent = 1;
}

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 29u + i * 11u);
}

static const wri_osd_sess *sess_of_osd(rig *r, int osd)
{
	uint32_t i;

	for (i = 0; i < r->o.sess.n; i++)
		if (r->o.sess.s[i].state != WRI_OS_FREE && r->o.sess.s[i].osd == osd)
			return &r->o.sess.s[i];
	return NULL;
}

/* Three OSDs, OSD 0 silent and primary of everything; one write of 200 bytes to `oid` is on its way and unanswered. 0 = ok. */
static int open_sent(const char *oid, uint8_t *data, uint32_t *op_i, rig_tweak tweak)
{
	if (rig_open(&R, 3, 3, tweak != NULL ? tweak : tweak_silent0) != 0) {
		WRT_CHECK(0);
		return -1;
	}
	fill(data, 200, 5);
	*op_i = rq_write(&R, oid, 0, data, 200, NULL, 0x77);
	if (*op_i == WRI_NIL)
		return -1;
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, *op_i)->state == WRI_OP_SENT && rig_nrec(&R, 0) == 1u && rq_at(&R, *op_i)->sent_epoch == 10u);
	return 0;
}

/* ---- the answer lost -------------------------------------------------------------------------------------------------------------- */

static void answer_lost(int no_dedup)
{
	uint8_t data[200], back[200];
	uint32_t i;
	uint64_t tid;
	const sim_osd_rec *a, *b;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	sim_osd_faults(R.w.osd[0])->drop_replies = 1; /* the OSD applies the write and the answer never leaves it */
	sim_osd_faults(R.w.osd[0])->no_dedup = (uint8_t)no_dedup;
	fill(data, sizeof(data), 8);
	i = rq_write(&R, "lost.obj", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(i != WRI_NIL);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	tid = op->tid;
	WRT_CHECK(op->state == WRI_OP_SENT && rig_rec(&R, 0, 0) != NULL && rig_rec(&R, 0, 0)->executed && rig_rec(&R, 0, 0)->dropped_reply);
	WRT_CHECK(rig_store_read(&R, "lost.obj", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	/* the connection is cut now (the OSD restarts): the session is lost, the op waits out the cool-down, then goes again on a new connection */
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && op->sess == WRI_NIL && R.n_stall == 1u && R.n_resume == 0u);
	WRT_CHECK(R.ev[0].kind == WR_EV_IO_STALL && R.ev[0].arg == 0u && R.ev[0].st != WR_OK);
	rig_tick(&R, 1900);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && rig_nrec(&R, 0) == 1u); /* still cooling down */
	rig_tick(&R, 300);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->tid == tid && op->retry_attempt == 1);
	WRT_CHECK(rig_nrec(&R, 0) == 2u);
	a = rig_rec(&R, 0, 0), b = rig_rec(&R, 0, 1);
	WRT_CHECK(a->tid == tid && b->tid == tid && a->retry_attempt == 0u && b->retry_attempt == 1u);
	WRT_CHECK((a->flags & WRI_OSDF_RETRY) == 0u && (b->flags & WRI_OSDF_RETRY) != 0u);
	WRT_CHECK(a->global_id == b->global_id && b->epoch == 10u && b->pg_seed == a->pg_seed && b->hash == a->hash);
	WRT_CHECK(a->conn != b->conn); /* another connection */
	if (no_dedup) {
		WRT_CHECK(b->executed && !b->duplicate); /* applied twice: the same bytes, and the engine's fence is what keeps a later write from being overtaken */
	} else {
		WRT_CHECK(b->duplicate && !b->executed); /* recognised by (global id, tid): answered from the log, not applied again */
	}
	WRT_CHECK(rig_store_read(&R, "lost.obj", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	WRT_CHECK(R.n_resume == 1u && R.n_stall == 1u && R.o.n_resent == 1u && R.o.n_timeouts == 0u);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R) && sim_osd_n_violations(R.w.osd[0]) == 0u);
	rig_close(&R);
}

static void test_answer_lost(void)
{
	answer_lost(0);
	answer_lost(1);
}

/* ---- EAGAIN, redirect, stale answers ------------------------------------------------------------------------------------------------ */

static void test_eagain(void)
{
	uint8_t data[64], back[64];
	uint32_t i;
	uint64_t tid0;
	const sim_osd_rec *a, *b;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	sim_osd_faults(R.w.osd[0])->eagain_ops = 1;
	fill(data, sizeof(data), 2);
	i = rq_write(&R, "eagain.obj", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(i != WRI_NIL);
	op = rq_at(&R, i);
	tid0 = op->tid;
	WRT_CHECK(rig_until_done(&R, i, 5000) && op->status == WR_OK);
	WRT_CHECK(rig_nrec(&R, 0) == 2u);
	a = rig_rec(&R, 0, 0), b = rig_rec(&R, 0, 1);
	/* the OSD answered before it ran anything: a new tid (same slot, a larger counter), RETRY set, attempt 1; the first try did nothing */
	WRT_CHECK(a->tid == tid0 && b->tid != tid0 && b->tid > tid0 && (b->tid & 0xffffu) == (tid0 & 0xffffu) && op->tid == b->tid);
	WRT_CHECK(!a->executed && b->executed && a->retry_attempt == 0u && b->retry_attempt == 1u && (b->flags & WRI_OSDF_RETRY) != 0u);
	WRT_CHECK(R.o.n_eagain == 1u && R.o.n_resent == 1u && R.n_stall == 0u);
	WRT_CHECK(rig_store_read(&R, "eagain.obj", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	/* the next op after it: the tid counter went on (the EAGAIN consumed one) */
	i = rq_write(&R, "eagain.obj", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rq_at(&R, i)->tid == (((uint64_t)3 << 16) | (uint64_t)i));
	WRT_CHECK(rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_redirect(void)
{
	uint8_t got[16];
	uint32_t i;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	sim_osd_faults(R.w.osd[0])->redirect = 1;
	i = rq_read(&R, "redir", 0, 16, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000));
	WRT_CHECK(rq_at(&R, i)->status == WR_E_OSD_REDIRECT && R.o.n_redirect == 1u && rig_nrec(&R, 0) == 1u); /* not followed */
	WRT_CHECK(rig_take(&R, i) == WR_E_OSD_REDIRECT);
	sim_osd_faults(R.w.osd[0])->redirect = 0;
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "redir", 0, got, 16));
	i = rq_read(&R, "redir", 0, 16, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void tweak_hold(rig *r)
{
	r->w.ocfg[0].fault.hold_replies = 1;
}

static void test_stale_answers(void)
{
	uint8_t data[40], got[40];
	uint32_t i, n;
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_hold) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "stale.obj", 0, data, sizeof(data)));
	i = rq_read(&R, "stale.obj", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && sim_osd_n_held(R.w.osd[0]) == 1u);
	/* a resend (the pool's force-resend epoch moved): attempt 1 is sent on the same connection, its answer is held too */
	R.m.pool[0].last_force = 11;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u && op->retry_attempt == 1 && sim_osd_n_held(R.w.osd[0]) == 2u && op->state == WRI_OP_SENT);
	/* the oldest answer (to attempt 0) is stale: dropped, the op stays in flight; then the right one completes it */
	WRT_CHECK(sim_osd_release(R.w.osd[0], 1) == 1u);
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_stale == 1u && op->state == WRI_OP_SENT && op->out_stored == 0u);
	WRT_CHECK(sim_osd_release(R.w.osd[0], 1) == 1u);
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->out_stored == sizeof(data) && memcmp(got, data, sizeof(data)) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	/* an answer that comes from the OSD the op has left is a stray, whatever its tid says */
	sim_osd_faults(R.w.osd[1])->silent = 1;
	i = rq_read(&R, "stale.obj", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 0 && sim_osd_n_held(R.w.osd[0]) == 1u);
	R.m.prim[mw_pg(&R.m, "stale.obj")] = 1; /* moves to OSD 1, which is silent */
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 1 && rig_nrec(&R, 1) == 1u && op->retry_attempt == 1);
	n = R.o.n_stray;
	WRT_CHECK(sim_osd_release(R.w.osd[0], 0) == 1u);
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_stray == n + 1u && op->state == WRI_OP_SENT && op->out_stored == 0u);
	sim_osd_faults(R.w.osd[1])->silent = 0;
	R.m.pool[0].last_force = 13;
	R.m.epoch = 13;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->retry_attempt == 2 && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

/* ---- the map-change table ---------------------------------------------------------------------------------------------------------- */

static void test_row_primary_moved(void)
{
	uint8_t data[200], back[200];
	uint32_t i;
	uint64_t tid;
	const sim_osd_rec *b;
	const wri_osd_sess *s0;
	wri_osd_op *op;

	if (open_sent("row.pm", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	tid = op->tid;
	s0 = sess_of_osd(&R, 0);
	WRT_CHECK(s0 != NULL && s0->state == WRI_OS_READY && s0->n_inflight == 1u);
	R.m.prim[mw_pg(&R.m, "row.pm")] = 1;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->tid == tid && op->osd == 1 && op->retry_attempt == 1);
	b = rig_rec(&R, 1, 0);
	WRT_CHECK(b != NULL && rig_nrec(&R, 1) == 1u && b->tid == tid && b->retry_attempt == 1u && b->epoch == 11u && (b->flags & WRI_OSDF_RETRY) != 0u);
	/* the old session lost one op in flight and was not reset; the old OSD saw the op once */
	s0 = sess_of_osd(&R, 0);
	WRT_CHECK(s0 != NULL && s0->state == WRI_OS_READY && s0->n_inflight == 0u && R.o.sess.n_resets == 0u && rig_nrec(&R, 0) == 1u);
	WRT_CHECK(R.n_stall == 0u && R.o.n_resent == 1u && rig_store_read(&R, "row.pm", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_row_replica_only(void)
{
	uint8_t data[200];
	uint32_t i, calls;
	wri_osd_op *op;

	if (open_sent("row.rep", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	calls = R.m.n_target;
	R.m.epoch = 11; /* a new epoch in which only a replica of the PG changed: the scripted map shows the same primary, address and PG */
	(void)rig_settle(&R);
	WRT_CHECK(R.m.n_target > calls); /* it was looked at ... */
	WRT_CHECK(op->state == WRI_OP_SENT && rig_nrec(&R, 0) == 1u && op->retry_attempt == 0 && op->sent_epoch == 10u && R.o.n_resent == 0u); /* ... and left alone */
	WRT_CHECK(R.o.map_epoch_seen == 11u && R.o.sess.n_resets == 0u);
	/* two epochs at once is the skipped-epoch rule */
	R.m.epoch = 13;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u && op->retry_attempt == 1 && op->sent_epoch == 13u && rig_rec(&R, 0, 1)->epoch == 13u);
	R.m.epoch = 14; /* and one at a time is not */
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u && op->sent_epoch == 13u);
	R.m.epoch = 12; /* a map that goes backwards (a full map from another monitor) is treated as a gap too */
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 3u && op->sent_epoch == 12u);
	rig_close(&R);
}

static void test_row_address(void)
{
	uint8_t data[200], back[200];
	uint32_t i;
	wri_osd_op *op;
	const wri_osd_sess *s;

	if (open_sent("row.addr", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	R.m.addr_of[0] = 2; /* OSD 0 is now reachable at the address of the simulator OSD 2 */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && rig_nrec(&R, 2) == 1u && rig_rec(&R, 2, 0)->retry_attempt == 1u && rig_nrec(&R, 0) == 1u);
	s = sess_of_osd(&R, 0);
	WRT_CHECK(s != NULL && s->state == WRI_OS_READY && s->addr.port == R.w.addr[2].port); /* the session was re-opened at the new address */
	WRT_CHECK(rig_store_read(&R, "row.addr", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static const char *name_that_splits(char *buf, size_t n)
{
	unsigned k;

	for (k = 0; k < 1000; k++) {
		uint32_t h;

		snprintf(buf, n, "split.%u", k);
		h = mw_hash(buf, strlen(buf));
		if ((h & 7u) != (h & 15u))
			return buf;
	}
	return buf;
}

static void test_row_split(void)
{
	uint8_t data[200];
	uint32_t i;
	char nm[32];
	wri_osd_op *op;
	const sim_osd_rec *b;

	(void)name_that_splits(nm, sizeof(nm));
	if (open_sent(nm, data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	WRT_CHECK(op->pg_seed == (mw_hash(nm, strlen(nm)) & 7u));
	R.m.pg_num = 16; /* pg_num grew: the PG of the object changed although its primary did not */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u && op->retry_attempt == 1 && op->state == WRI_OP_SENT);
	b = rig_rec(&R, 0, 1);
	WRT_CHECK(b->tid == op->tid && b->pg_seed == (mw_hash(nm, strlen(nm)) & 15u) && b->pg_seed != rig_rec(&R, 0, 0)->pg_seed && b->epoch == 11u);
	/* a merge back: the same */
	R.m.pg_num = 8;
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 3u && rig_rec(&R, 0, 2)->pg_seed == (mw_hash(nm, strlen(nm)) & 7u));
	rig_close(&R);
}

static void test_row_force_resend(void)
{
	uint8_t data[200];
	uint32_t i;
	wri_osd_op *op;

	if (open_sent("row.force", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	R.m.pool[0].last_force = 10; /* not above the epoch of the transmission (10): nothing to do */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 1u && op->sent_epoch == 10u);
	R.m.pool[0].last_force = 12; /* above: the op goes again, with the new epoch */
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u && op->sent_epoch == 12u && rig_rec(&R, 0, 1)->epoch == 12u && rig_rec(&R, 0, 1)->retry_attempt == 1u);
	R.m.epoch = 13; /* the same force epoch again: sent at 12, not below 12: left alone */
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 2u);
	rig_close(&R);
}

static void test_row_homeless(void)
{
	uint8_t data[200];
	uint32_t i, pg;
	wri_osd_op *op;
	const wri_osd_sess *s0;

	if (open_sent("row.home", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	pg = mw_pg(&R.m, "row.home");
	/* the PG has no primary (every OSD of it is down): the op leaves its session and waits for a map */
	R.m.prim[pg] = -1;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	s0 = sess_of_osd(&R, 0);
	WRT_CHECK(op->state == WRI_OP_HOMELESS && op->sess == WRI_NIL && op->osd == -1 && s0 != NULL && s0->n_inflight == 0u && R.o.n_inflight == 1u);
	WRT_CHECK(rig_nrec(&R, 0) == 1u && R.o.sess.n_resets == 0u);
	/* unmappable says the same, and so does a primary the map has no address for */
	R.m.prim[pg] = 0;
	R.m.unmappable[pg] = 1;
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_HOMELESS);
	R.m.unmappable[pg] = 0;
	R.m.addr_of[0] = -1;
	R.m.epoch = 13;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_HOMELESS);
	/* a map names a primary again: the op is resent (it was sent once: attempt 1) from the first moment */
	R.m.addr_of[0] = 0;
	R.m.prim[pg] = 1;
	R.m.epoch = 14;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->osd == 1 && op->retry_attempt == 1 && rig_nrec(&R, 1) == 1u && rig_rec(&R, 1, 0)->retry_attempt == 1u);
	WRT_CHECK(rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_row_pool(void)
{
	uint8_t data[200];
	uint32_t i;
	wri_osd_op *op;
	const wri_osd_sess *s0;

	/* the pool is deleted while the op is on the wire: nothing can answer it any more */
	if (open_sent("row.pool", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	R.m.pool[0].present = 0;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	s0 = sess_of_osd(&R, 0);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_POOL_NOT_FOUND && s0->n_inflight == 0u && rig_take(&R, i) == WR_E_POOL_NOT_FOUND && rig_idle(&R));
	rig_close(&R);
	/* the EIO flag: the OSD stays silent for such a pool (SUPPORTSPOOLEIO), so the client answers */
	if (open_sent("row.pool", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	R.m.pool[0].flags = WR_POOL_F_EIO;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_OSD_IO && rig_take(&R, i) == WR_E_OSD_IO && rig_idle(&R));
	rig_close(&R);
	/* a pool the client cannot use (changed to erasure coded, say) */
	if (open_sent("row.pool", data, &i, NULL) != 0)
		return;
	op = rq_at(&R, i);
	R.m.pool[0].status = WR_E_POOL_UNSUPPORTED;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_POOL_UNSUPPORTED && rig_take(&R, i) == WR_E_POOL_UNSUPPORTED && rig_idle(&R));
	rig_close(&R);
}

static void test_row_order(void)
{
	uint8_t data[200];
	uint32_t i[4], k, n;
	char nm[4][16];

	if (rig_open(&R, 3, 3, tweak_silent0) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	for (k = 0; k < 4; k++) {
		snprintf(nm[k], sizeof(nm[k]), "ord.%u", k);
		i[k] = rq_write(&R, nm[k], 0, data, 100, NULL, 0);
	}
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 4u);
	for (k = 0; k < MW_PG_MAX; k++)
		R.m.prim[k] = 1;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	n = rig_nrec(&R, 1);
	WRT_CHECK(n == 4u);
	for (k = 0; k < n && k < 4; k++)
		WRT_CHECK(rig_rec(&R, 1, k)->tid == rq_at(&R, i[k])->tid && rig_rec(&R, 1, k)->retry_attempt == 1u); /* ascending tid order */
	for (k = 0; k < 4; k++)
		WRT_CHECK(rig_take(&R, i[k]) == WR_OK);
	WRT_CHECK(rig_idle(&R));
	rig_close(&R);
}

/* ---- pause and full policy ----------------------------------------------------------------------------------------------------------- */

static void test_pause(void)
{
	uint8_t data[64], got[64];
	uint32_t w, r, w2;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "pz", 0, data, sizeof(data)));
	R.m.flags = WR_MAP_F_PAUSEWR;
	R.m.epoch = 11;
	w = rq_write(&R, "pz", 0, data, sizeof(data), NULL, 0);
	r = rq_read(&R, "pz", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED && rq_done(&R, r) && rig_nrec(&R, 0) == 1u); /* the read passes, the write is held */
	WRT_CHECK(rig_take(&R, r) == WR_OK && wri_osdc_deadline(&R.o) != WR_DEADLINE_NONE); /* the stale-map limit is the only deadline of a paused op */
	/* the pause is lifted: the held write goes (its first transmission: attempt 0) */
	R.m.flags = 0;
	R.m.epoch = 12;
	(void)rig_settle(&R);
	op = rq_at(&R, w);
	WRT_CHECK(rq_done(&R, w) && op->status == WR_OK && op->retry_attempt == 0 && rig_rec(&R, 0, 1)->retry_attempt == 0u && rig_take(&R, w) == WR_OK);
	/* PAUSERD holds reads and lets writes through; both flags hold both */
	R.m.flags = WR_MAP_F_PAUSERD;
	R.m.epoch = 13;
	w = rq_write(&R, "pz", 0, data, sizeof(data), NULL, 0);
	r = rq_read(&R, "pz", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, r)->state == WRI_OP_PAUSED && rq_done(&R, w) && rig_take(&R, w) == WR_OK);
	R.m.flags = WR_MAP_F_PAUSERD | WR_MAP_F_PAUSEWR;
	R.m.epoch = 14;
	w2 = rq_write(&R, "pz", 0, data, sizeof(data), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w2)->state == WRI_OP_PAUSED && rq_at(&R, r)->state == WRI_OP_PAUSED);
	/* an op that is on the wire when the flag appears stays on the wire */
	R.m.flags = 0;
	R.m.epoch = 15;
	sim_osd_faults(R.w.osd[0])->silent = 1;
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w2)->state == WRI_OP_SENT && rq_at(&R, r)->state == WRI_OP_SENT);
	R.m.flags = WR_MAP_F_PAUSERD | WR_MAP_F_PAUSEWR;
	R.m.epoch = 16;
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w2)->state == WRI_OP_SENT && rq_at(&R, r)->state == WRI_OP_SENT && R.o.n_resent == 0u);
	rig_close(&R);
}

static void tweak_no_pause(rig *r)
{
	r->w.e.x.cfg.osd_flags = WR_OSDF_FULL_TRY; /* HONOR_PAUSE off */
}

static void test_pause_off(void)
{
	uint8_t data[64];
	uint32_t w;

	if (rig_open(&R, 1, 2, tweak_no_pause) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	R.m.flags = WR_MAP_F_PAUSEWR | WR_MAP_F_PAUSERD;
	w = rq_write(&R, "pz", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, w, 5000) && rq_at(&R, w)->status == WR_OK && rig_take(&R, w) == WR_OK);
	rig_close(&R);
}

static void tweak_no_full_try(rig *r)
{
	r->w.e.x.cfg.osd_flags = WR_OSDF_HONOR_PAUSE; /* FULL_TRY off */
}

static void test_full_policy(void)
{
	uint8_t data[64], got[64];
	uint32_t w, r;

	/* with FULL_TRY (the default) a full pool is the OSD's business: the write goes and carries the flag */
	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	R.m.pool[0].flags = WR_POOL_F_FULL;
	w = rq_write(&R, "full", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, w, 5000) && rq_at(&R, w)->status == WR_OK && (rig_rec(&R, 0, 0)->flags & WRI_OSDF_FULL_TRY) != 0u);
	WRT_CHECK(rig_take(&R, w) == WR_OK);
	rig_close(&R);
	/* without it the client holds writes while the pool (or the map) is full: the OSD would swallow them */
	if (rig_open(&R, 1, 2, tweak_no_full_try) != 0) {
		WRT_CHECK(0);
		return;
	}
	R.m.pool[0].flags = WR_POOL_F_FULL_QUOTA;
	R.m.epoch = 11;
	w = rq_write(&R, "full", 0, data, sizeof(data), NULL, 0);
	r = rq_read(&R, "full", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED && rq_at(&R, r)->state == WRI_OP_DONE && rig_nrec(&R, 0) == 1u && (rig_rec(&R, 0, 0)->flags & WRI_OSDF_FULL_TRY) == 0u);
	R.m.pool[0].flags = 0;
	R.m.flags = WR_MAP_F_FULL; /* the map's flag does the same */
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, w)->state == WRI_OP_PAUSED);
	R.m.flags = 0;
	R.m.epoch = 13;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, w) && rq_at(&R, w)->status == WR_OK);
	rig_close(&R);
}

/* ---- sessions the ops depend on ---------------------------------------------------------------------------------------------------------- */

static void test_cut_resend_order(void)
{
	uint8_t data[200];
	uint32_t i[3], late, k;
	char nm[3][16];
	uint64_t t[3];

	if (rig_open(&R, 1, 2, tweak_silent0) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 6);
	for (k = 0; k < 3; k++) {
		snprintf(nm[k], sizeof(nm[k]), "cut.%u", k);
		i[k] = rq_write(&R, nm[k], 0, data, 100, NULL, 0);
		t[k] = rq_at(&R, i[k])->tid;
	}
	(void)rig_settle(&R);
	WRT_CHECK(rig_nrec(&R, 0) == 3u);
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_restart(R.w.osd[0]); /* the connection is cut: all three are in flight on it */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, i[0])->state == WRI_OP_WAIT_SESS && rq_at(&R, i[1])->state == WRI_OP_WAIT_SESS && rq_at(&R, i[2])->state == WRI_OP_WAIT_SESS);
	/* a new op arrives while the others wait out the cool-down; the old ones go first when the session is back */
	late = rq_write(&R, "cut.late", 0, data, 100, NULL, 0);
	rig_tick(&R, 2200);
	WRT_CHECK(rig_nrec(&R, 0) == 7u);
	for (k = 0; k < 3; k++)
		WRT_CHECK(rig_rec(&R, 0, 3u + k)->tid == t[k] && rig_rec(&R, 0, 3u + k)->retry_attempt == 1u);
	WRT_CHECK(rig_rec(&R, 0, 6)->tid == rq_at(&R, late)->tid && rig_rec(&R, 0, 6)->retry_attempt == 0u);
	for (k = 0; k < 3; k++)
		WRT_CHECK(rig_take(&R, i[k]) == WR_OK);
	WRT_CHECK(rig_take(&R, late) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_refused_and_down(void)
{
	uint8_t data[64];
	uint32_t i;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 2);
	/* a key without OSD caps: the authorizer round trip ends in AUTH_BAD_METHOD; the op waits, the cause is told once */
	sim_osd_faults(R.w.osd[0])->refuse_auth = 1;
	i = rq_write(&R, "auth.obj", 0, data, sizeof(data), NULL, 0);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && rig_nrec(&R, 0) == 0u && R.n_stall == 1u && R.ev[0].kind == WR_EV_IO_STALL && R.ev[0].st != WR_OK);
	rig_tick(&R, 5000);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && R.n_stall == 1u && R.n_resume == 0u); /* told once, not at every attempt */
	sim_osd_faults(R.w.osd[0])->refuse_auth = 0;
	WRT_CHECK(rig_until_done(&R, i, 20000) && op->status == WR_OK && R.n_resume == 1u && op->retry_attempt == 0); /* never transmitted before: attempt 0 */
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	/* the OSD does not accept connections at all */
	R.w.osd_down[0] = 1;
	sim_osd_restart(R.w.osd[0]);
	i = rq_write(&R, "down.obj", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 3000);
	WRT_CHECK(rq_at(&R, i)->state == WRI_OP_WAIT_SESS && R.n_stall == 2u);
	R.w.osd_down[0] = 0;
	WRT_CHECK(rig_until_done(&R, i, 30000) && rq_at(&R, i)->status == WR_OK && R.n_resume == 2u && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

/* ---- one OSD refuses connections and there are fewer sessions than OSDs ---------------------------------------------------------------- */

static void tweak_thirds(rig *r)
{
	unsigned k;

	for (k = 0; k < MW_PG_MAX; k++)
		r->m.prim[k] = (int)(k % 3u);
}

/* A name whose PG is served by `osd` under tweak_thirds. */
static const char *third_name(unsigned osd, char *buf, size_t n)
{
	unsigned k;

	for (k = 0; k < 4096u; k++) {
		snprintf(buf, n, "third%u", k);
		if (mw_pg(&R.m, buf) % 3u == osd)
			return buf;
	}
	return buf;
}

/*
 * Three OSDs, two sessions, OSD 1 refuses connections, and one read for each OSD. The two live OSDs are served at once; the dead one is dialled again
 * only when its cool-down (2 s, 4 s, 8 s, then 10 s) is over, and no dial of it takes the slot of a working session in between. The table used to hand the
 * cool-down slot of the failed OSD to the next OSD that asked, forgetting that it had failed: the read for OSD 1 then dialled it at once, evicted the
 * session of a live OSD to do so, and the two OSDs took turns without any time passing (fuzz_client_osd, regress_cooldown_slot_taken.bin).
 */
static void test_dead_osd_fewer_sessions(void)
{
	uint8_t out[3][16];
	char nm[3][24];
	uint32_t i[3];
	unsigned k, opened;
	wri_osd_op *op;

	if (rig_open(&R, 3, 2, tweak_thirds) != 0) {
		WRT_CHECK(0);
		return;
	}
	R.w.osd_down[1] = 1;
	for (k = 0; k < 3u; k++)
		(void)third_name(k, nm[k], sizeof(nm[k]));
	for (k = 0; k < 3u; k++)
		i[k] = rq_read(&R, nm[k], 0, sizeof(out[k]), out[k], k);
	(void)rig_settle(&R);
	rig_tick(&R, 500);
	WRT_CHECK(rq_done(&R, i[0]) && rq_done(&R, i[2]) && !rq_done(&R, i[1]));
	op = rq_at(&R, i[1]);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS);
	WRT_CHECK(R.o.sess.n_opened <= 4u && R.n_stall == 1u); /* OSD 0, OSD 1 (refused), OSD 2: dialled once each, the stall told once */
	opened = R.o.sess.n_opened;
	/* 30 s with OSD 1 still refusing: one dial of it per cool-down (at 2, 6, 14, 24 s), the live OSDs are not touched again */
	rig_tick(&R, 30000);
	WRT_CHECK(rq_at(&R, i[1])->state == WRI_OP_WAIT_SESS && !rq_done(&R, i[1]));
	WRT_CHECK(R.o.sess.n_opened >= opened + 4u && R.o.sess.n_opened <= opened + 5u);
	WRT_CHECK(R.o.sess.n_evicted <= 2u); /* the live OSDs shared the sessions once; the dead one never pushed a working session out after that */
	/* OSD 1 is back: its next attempt goes through */
	R.w.osd_down[1] = 0;
	WRT_CHECK(rig_until_done(&R, i[1], 30000) && rq_at(&R, i[1])->status == WR_E_OSD_NOENT && R.n_resume >= 1u); /* the objects do not exist: a read says so */
	WRT_CHECK(rig_drain(&R) == 3u && rig_idle(&R));
	rig_close(&R);
}

/* ---- an op that leaves a session must not leave a connection that still touches its buffers --------------------------------------------- */

static void tweak_odd_even(rig *r)
{
	unsigned k;

	for (k = 0; k < MW_PG_MAX; k++)
		r->m.prim[k] = (int)(k & 1u);
}

/* A name whose PG is served by `osd` under tweak_odd_even. */
static const char *pg_name(unsigned osd, const char *prefix, char *buf, size_t n)
{
	unsigned k;

	for (k = 0; k < 4096u; k++) {
		snprintf(buf, n, "%s%u", prefix, k);
		if ((mw_pg(&R.m, buf) & 1u) == osd)
			return buf;
	}
	return buf;
}

/* The write is on its way to OSD 0 (the host has not consumed the queue: it points into the owner's buffer), the PG moves to OSD 1 and OSD 1 answers.
 * The owner reuses its buffer at once; the connection to OSD 0 must not send it. */
static void test_move_quiesces_tx_queue(void)
{
	uint8_t data[1000], keep[1000], back[1000], warm[16];
	char nm[24], other[24];
	uint32_t i, w, pg;
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_odd_even) != 0) {
		WRT_CHECK(0);
		return;
	}
	(void)pg_name(0, "mq.", nm, sizeof(nm));
	(void)pg_name(1, "mqo.", other, sizeof(other));
	fill(data, sizeof(data), 9);
	memcpy(keep, data, sizeof(data));
	w = rq_write(&R, other, 0, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	w = rq_write(&R, nm, 1000, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	pg = mw_pg(&R.m, nm);
	R.w.tx_hold_only = 1; /* OSD 0's connection holds what it was given */
	i = rq_write(&R, nm, 0, data, sizeof(data), NULL, 0x31);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 0 && rig_nrec(&R, 0) == 1u && !wri_osd_sess_tx_idle(&R.o.sess, op->sess));
	R.m.prim[pg] = 1;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->osd == 1 && R.o.n_quiesced == 1u && R.o.sess.n_resets == 0u);
	WRT_CHECK(rig_take(&R, i) == WR_OK);
	for (w = 0; w < R.o.sess.n; w++) /* no connection may still hold a pointer into the owner's buffer (the host has consumed nothing from OSD 0's) */
		WRT_CHECK(R.o.sess.s[w].state != WRI_OS_READY || wri_osd_sess_tx_idle(&R.o.sess, w));
	memset(data, 0xEE, sizeof(data)); /* the owner has its buffer back */
	R.w.tx_hold_only = 0;
	rig_tick(&R, 200);
	WRT_CHECK(rig_nrec(&R, 0) == 1u); /* OSD 0 saw the warm-up only: nothing was sent from the reused buffer */
	WRT_CHECK(rig_store_read(&R, nm, 0, back, sizeof(back)) == 1 && memcmp(back, keep, sizeof(keep)) == 0);
	WRT_CHECK(rig_idle(&R) && sim_osd_n_violations(R.w.osd[0]) == 0u && sim_osd_n_violations(R.w.osd[1]) == 0u);
	rig_close(&R);
}

/* The same op, but the old connection is not holding a send: it is receiving the answer into the op's output when the op moves on. */
static void test_move_quiesces_rx(void)
{
	uint8_t data[4096], got[4096], sentinel[4096], warm[8];
	char nm[24], other[24];
	uint32_t i, w, pg, k;
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_odd_even) != 0) {
		WRT_CHECK(0);
		return;
	}
	(void)pg_name(0, "mr.", nm, sizeof(nm));
	(void)pg_name(1, "mro.", other, sizeof(other));
	fill(data, sizeof(data), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, nm, 0, data, sizeof(data)));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, other, 0, warm, sizeof(warm)));
	w = rq_read(&R, other, 0, 8, warm, 0); /* the connection to OSD 1 comes first: the pump serves it first */
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	w = rq_read(&R, nm, 0, 8, warm, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	pg = mw_pg(&R.m, nm);
	memset(got, 0xAA, sizeof(got));
	i = rq_read(&R, nm, 0, sizeof(got), got, 0);
	R.w.rx_budget_on = 1;
	R.w.rx_budget = 800;
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && R.o.sess.s[op->sess].rx_tid == op->tid && R.o.sess.s[op->sess].osd == 0);
	R.m.prim[pg] = 1;
	R.m.epoch = 11;
	R.w.rx_budget = 0; /* nothing more arrives while the engine moves the op */
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 1 && R.o.sess.s[op->sess].osd == 1);
	R.w.rx_budget = 6000; /* enough for OSD 1's whole answer, not for the rest of OSD 0's */
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && op->osd == 1 && op->out_stored == sizeof(got));
	for (k = 0; k < R.o.sess.n; k++)
		WRT_CHECK(R.o.sess.s[k].rx_tid != op->tid); /* no connection is still filling the owner's buffer */
	WRT_CHECK(memcmp(got, data, sizeof(got)) == 0 && rig_take(&R, i) == WR_OK);
	memset(got, 0xAA, sizeof(got)); /* the owner reuses it */
	memset(sentinel, 0xAA, sizeof(sentinel));
	R.w.rx_budget_on = 0;
	rig_tick(&R, 200);
	WRT_CHECK(memcmp(got, sentinel, sizeof(got)) == 0 && rig_idle(&R));
	rig_close(&R);
}

/* The op ends without an answer (the pool is deleted) while its data is still queued: the connection is closed before the owner gets its buffer back. */
static void test_pool_gone_quiesces(void)
{
	uint8_t data[1000], warm[16];
	uint32_t i, w, k;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	w = rq_write(&R, "pg.warm", 0, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	fill(data, sizeof(data), 4);
	R.w.tx_hold = 1;
	i = rq_write(&R, "pg.obj", 0, data, sizeof(data), NULL, 0x31);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && !wri_osd_sess_tx_idle(&R.o.sess, op->sess));
	R.m.pool[0].present = 0;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_E_POOL_NOT_FOUND && R.o.n_quiesced == 1u);
	for (k = 0; k < R.o.sess.n; k++)
		WRT_CHECK(R.o.sess.s[k].state != WRI_OS_READY || wri_osd_sess_tx_idle(&R.o.sess, k));
	WRT_CHECK(rig_take(&R, i) == WR_E_POOL_NOT_FOUND);
	R.w.tx_hold = 0;
	rig_close(&R);
}

/* An op that stays on the same session does not cost that session its connection (the queue is in order, the old copy is behind it). */
static void test_same_session_resend_keeps_connection(void)
{
	uint8_t data[1000], warm[16];
	uint32_t i, w;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	w = rq_write(&R, "ss.warm", 0, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	fill(data, sizeof(data), 6);
	R.w.tx_hold = 1;
	i = rq_write(&R, "ss.obj", 0, data, sizeof(data), NULL, 0x31);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT);
	R.m.pool[0].last_force = 11; /* every op goes again, to the same OSD */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_SENT && op->retry_attempt == 1 && R.o.n_quiesced == 0u && R.o.sess.s[op->sess].state == WRI_OS_READY);
	R.w.tx_hold = 0;
	rig_tick(&R, 200);
	WRT_CHECK(rq_done(&R, i) && op->status == WR_OK && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

/* The map answers the pool but fails the object's placement: the op ends with that status (never a hang), also when it was on the wire. */
static void test_target_failure(void)
{
	uint8_t data[200];
	uint32_t i;

	if (open_sent("tf.obj", data, &i, NULL) != 0)
		return;
	R.m.target_status = WR_E_CRUSH_NO_RULE;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, i) && rq_at(&R, i)->status == WR_E_CRUSH_NO_RULE && rig_take(&R, i) == WR_E_CRUSH_NO_RULE && rig_idle(&R));
	i = rq_write(&R, "tf.new", 0, data, 200, NULL, 0x78); /* and a new one never leaves */
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 1000) && rq_at(&R, i)->status == WR_E_CRUSH_NO_RULE && rig_take(&R, i) == WR_E_CRUSH_NO_RULE);
	WRT_CHECK(rig_nrec(&R, 0) == 1u);
	rig_close(&R);
}

/* The object's placement says "no map" or "no such pool" although the pool answered a moment ago (the map moved between the two questions): the op waits like
 * one that has no map; the pool-gone verdict only comes once the map-stale window has passed. */
static void test_target_vanishes(void)
{
	uint8_t data[200];
	uint32_t i;

	if (open_sent("tv.obj", data, &i, NULL) != 0)
		return;
	R.m.target_status = WR_E_MAP_NONE;
	i = rq_write(&R, "tv.new", 0, data, 200, NULL, 0x79);
	(void)rig_settle(&R);
	WRT_CHECK(i != WRI_NIL && rq_at(&R, i)->state == WRI_OP_WAIT_MAP && rig_nrec(&R, 0) == 1u);
	R.m.target_status = WR_E_POOL_NOT_FOUND;
	rig_tick(&R, 1000);
	WRT_CHECK(rq_at(&R, i)->state == WRI_OP_WAIT_MAP); /* inside the window: the pool may still appear */
	rig_tick(&R, 31000);
	WRT_CHECK(rq_done(&R, i) && rq_at(&R, i)->status == WR_E_POOL_NOT_FOUND && rig_take(&R, i) == WR_E_POOL_NOT_FOUND);
	rig_close(&R);
}

int main(void)
{
	test_answer_lost();
	test_eagain();
	test_redirect();
	test_stale_answers();
	test_row_primary_moved();
	test_row_replica_only();
	test_row_address();
	test_row_split();
	test_row_force_resend();
	test_row_homeless();
	test_row_pool();
	test_row_order();
	test_pause();
	test_pause_off();
	test_full_policy();
	test_cut_resend_order();
	test_refused_and_down();
	test_dead_osd_fewer_sessions();
	test_move_quiesces_tx_queue();
	test_move_quiesces_rx();
	test_pool_gone_quiesces();
	test_same_session_resend_keeps_connection();
	test_target_failure();
	test_target_vanishes();
	return wrt_finish();
}
