/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_backoff.c - MOSDBackoff as the request engine lives it (design 21.5, 23.5, osd-ops.md 3.7) over real sessions: an op whose PG (or object) is
 * blocked is not sent and waits QUEUED, others go on; the UNBLOCK releases it; ops that were already on the wire in that PG are sent again (the OSD may have
 * dropped them); an op inside a backoff is not "silent" (its deadline does not reset the session); a lost session forgets its backoffs and the held ops
 * go to the new connection.
 */
#include "osd_req_rig.h"

static rig R;

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 13u + i * 3u);
}

/* Names in two different PGs of the scripted map (8 PGs). */
static void two_names(char *a, char *b, size_t n)
{
	unsigned k;
	uint32_t pa;

	snprintf(a, n, "bo.a");
	pa = mw_hash(a, strlen(a)) & 7u;
	for (k = 0; k < 100; k++) {
		snprintf(b, n, "bo.b%u", k);
		if ((mw_hash(b, strlen(b)) & 7u) != pa)
			return;
	}
}

/* An engine with one READY session (a first op went through), returns the session index or WRI_NIL. */
static uint32_t open_ready(rig_tweak tw)
{
	uint8_t got[8];
	uint32_t i, k;

	if (rig_open(&R, 1, 2, tw) != 0) {
		WRT_CHECK(0);
		return WRI_NIL;
	}
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "warm", 0, got, 8));
	i = rq_read(&R, "warm", 0, 8, got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 5000) && rig_take(&R, i) == WR_OK);
	for (k = 0; k < R.o.sess.n; k++)
		if (R.o.sess.s[k].state == WRI_OS_READY)
			return k;
	WRT_CHECK(0);
	return WRI_NIL;
}

static void block_pg(uint32_t s, uint64_t id, uint32_t pg, uint8_t op)
{
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(rig_srv(&R, s), op, id, W_POOL, pg, R.m.epoch, "", 0, SIM_OSD_BO_MAX, 0));
	(void)rig_settle(&R);
}

static void block_obj(uint32_t s, uint64_t id, const char *oid, uint8_t op)
{
	uint32_t h = mw_hash(oid, strlen(oid));

	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(rig_srv(&R, s), op, id, W_POOL, mw_pg(&R.m, oid), R.m.epoch, oid, h, oid, h));
	(void)rig_settle(&R);
}

static void test_hold_and_release(void)
{
	char a[24], b[24];
	uint8_t d[64];
	uint32_t s, ia, ib, ra;
	uint32_t pa, n0;

	two_names(a, b, sizeof(a));
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	pa = mw_pg(&R.m, a);
	n0 = rig_nrec(&R, 0);
	fill(d, sizeof(d), 1);
	block_pg(s, 41, pa, WRI_BACKOFF_BLOCK);
	WRT_CHECK(sim_osd_n_acks(R.w.osd[0]) == 1u && R.o.sess.s[s].n_backoff == 1u);
	/* a write and a read into the blocked PG wait; one in another PG goes straight through */
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	ra = rq_read(&R, a, 0, 8, d, 0);
	ib = rq_write(&R, b, 0, d, sizeof(d), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED && rq_at(&R, ra)->state == WRI_OP_QUEUED && rq_done(&R, ib));
	WRT_CHECK(rig_nrec(&R, 0) == n0 + 1u && R.o.n_blocked_held >= 2u && sim_osd_n_backoff_drops(R.w.osd[0]) == 0u); /* held back, not sent into the drop */
	/* held ops have no deadline of their own: nothing to do until the UNBLOCK */
	rig_tick(&R, 20000);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED && R.o.sess.n_resets == 0u && R.n_stall == 0u && rig_nrec(&R, 0) == n0 + 1u);
	/* the UNBLOCK: both go, in tid order, as first transmissions */
	block_pg(s, 41, pa, WRI_BACKOFF_UNBLOCK);
	WRT_CHECK(rq_done(&R, ia) && rq_done(&R, ra) && rq_at(&R, ia)->retry_attempt == 0 && rq_at(&R, ra)->retry_attempt == 0);
	WRT_CHECK(rig_nrec(&R, 0) == n0 + 3u && rig_rec(&R, 0, n0 + 1u)->tid == rq_at(&R, ia)->tid && rig_rec(&R, 0, n0 + 2u)->tid == rq_at(&R, ra)->tid);
	WRT_CHECK(rig_take(&R, ib) == WR_OK && rig_take(&R, ia) == WR_OK && rig_take(&R, ra) == WR_OK && rig_idle(&R));
	WRT_CHECK(R.o.sess.s[s].n_backoff == 0u && sim_osd_n_violations(R.w.osd[0]) == 0u);
	rig_close(&R);
}

static void test_object_level(void)
{
	char a[24], b[24];
	uint8_t d[64];
	uint32_t s, ia, ib;

	/* two objects of ONE PG: only the blocked object waits */
	{
		unsigned k;

		snprintf(a, sizeof(a), "bo.a");
		for (k = 0; k < 400; k++) {
			snprintf(b, sizeof(b), "bo.c%u", k);
			if ((mw_hash(b, strlen(b)) & 7u) == (mw_hash(a, strlen(a)) & 7u))
				break;
		}
	}
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	fill(d, sizeof(d), 2);
	block_obj(s, 50, a, WRI_BACKOFF_BLOCK);
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	ib = rq_write(&R, b, 0, d, sizeof(d), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED && rq_done(&R, ib));
	block_obj(s, 50, a, WRI_BACKOFF_UNBLOCK);
	WRT_CHECK(rq_done(&R, ia) && rig_take(&R, ib) == WR_OK && rig_take(&R, ia) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_sent_ops_resent(void)
{
	char a[24], b[24];
	uint8_t d[64], got[64];
	uint32_t s, ia, ib, n0;
	uint32_t pa;
	wri_osd_op *op;

	two_names(a, b, sizeof(a));
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	fill(d, sizeof(d), 3);
	pa = mw_pg(&R.m, a);
	sim_osd_faults(R.w.osd[0])->silent = 1; /* what the OSD does to an op inside a backoff it sent: nothing */
	n0 = rig_nrec(&R, 0);
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	ib = rq_write(&R, b, 0, d, sizeof(d), NULL, 0); /* another PG, also unanswered */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_SENT && rq_at(&R, ib)->state == WRI_OP_SENT && rig_nrec(&R, 0) == n0 + 2u);
	block_pg(s, 61, pa, WRI_BACKOFF_BLOCK);
	/* inside a backoff the op is not unanswered, it was told to wait: three deadlines pass and the session is left alone */
	rig_tick(&R, 4900);
	WRT_CHECK(R.o.n_timeouts == 0u);
	op = rq_at(&R, ia);
	rig_tick(&R, 200); /* both deadlines (5 s) have passed now: the blocked one is deferred, the other one is not */
	WRT_CHECK(R.o.n_timeouts == 1u); /* ib's deadline reset the session: that is the case of a silent OSD, and it is a different PG */
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && R.o.sess.s[s].n_backoff == 0u); /* the reset took the backoff with it: the op goes again after the cool-down */
	rig_close(&R);

	/* the same with only the blocked PG on the wire: no timeout at all, however long the backoff stands */
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	sim_osd_faults(R.w.osd[0])->silent = 1;
	n0 = rig_nrec(&R, 0);
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	(void)rig_settle(&R);
	op = rq_at(&R, ia);
	WRT_CHECK(op->state == WRI_OP_SENT && rig_nrec(&R, 0) == n0 + 1u);
	block_pg(s, 61, pa, WRI_BACKOFF_BLOCK);
	rig_tick(&R, 25000);
	WRT_CHECK(R.o.n_timeouts == 0u && R.o.sess.n_resets == 0u && op->state == WRI_OP_SENT && op->retry_attempt == 0 && R.n_stall == 0u && rig_nrec(&R, 0) == n0 + 1u);
	WRT_CHECK(op->deadline_ms > rig_now(&R)); /* pushed out, not expired */
	/* the UNBLOCK: the op that was sent before is sent again (attempt 1, same tid), and now the OSD answers it */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	block_pg(s, 61, pa, WRI_BACKOFF_UNBLOCK);
	WRT_CHECK(rq_done(&R, ia) && op->status == WR_OK && op->retry_attempt == 1 && rig_nrec(&R, 0) == n0 + 2u);
	WRT_CHECK(rig_rec(&R, 0, n0 + 1u)->tid == rig_rec(&R, 0, n0)->tid && rig_rec(&R, 0, n0 + 1u)->retry_attempt == 1u && R.o.n_unblock_resend == 1u);
	WRT_CHECK((rig_rec(&R, 0, n0 + 1u)->flags & WRI_OSDF_RETRY) != 0u);
	WRT_CHECK(rig_store_read(&R, a, 0, got, sizeof(got)) == 1 && memcmp(got, d, sizeof(d)) == 0);
	WRT_CHECK(rig_take(&R, ia) == WR_OK && rig_idle(&R) && R.o.sess.s[s].n_inflight == 0u);
	rig_close(&R);
}

static void test_other_pg_unblock(void)
{
	char a[24], b[24];
	uint8_t d[64];
	uint32_t s, ia, ib, pa, pb;

	two_names(a, b, sizeof(a));
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	pa = mw_pg(&R.m, a);
	pb = mw_pg(&R.m, b);
	fill(d, sizeof(d), 4);
	block_pg(s, 71, pa, WRI_BACKOFF_BLOCK);
	block_pg(s, 72, pb, WRI_BACKOFF_BLOCK);
	WRT_CHECK(R.o.sess.s[s].n_backoff == 2u);
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	ib = rq_write(&R, b, 0, d, sizeof(d), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED && rq_at(&R, ib)->state == WRI_OP_QUEUED);
	block_pg(s, 72, pb, WRI_BACKOFF_UNBLOCK); /* only B's PG */
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED && rq_done(&R, ib));
	block_pg(s, 71, pa, WRI_BACKOFF_UNBLOCK);
	WRT_CHECK(rq_done(&R, ia) && rig_take(&R, ib) == WR_OK && rig_take(&R, ia) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_session_loss_forgets(void)
{
	char a[24], b[24];
	uint8_t d[64];
	uint32_t s, ia, n0;

	two_names(a, b, sizeof(a));
	s = open_ready(NULL);
	if (s == WRI_NIL)
		return;
	fill(d, sizeof(d), 5);
	block_pg(s, 81, mw_pg(&R.m, a), WRI_BACKOFF_BLOCK);
	ia = rq_write(&R, a, 0, d, sizeof(d), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, ia)->state == WRI_OP_QUEUED);
	n0 = rig_nrec(&R, 0);
	/* the OSD restarts: the connection and its backoffs are gone; the op goes to the new connection when the cool-down is over */
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	WRT_CHECK(R.o.sess.s[s].n_backoff == 0u && rq_at(&R, ia)->state == WRI_OP_WAIT_SESS);
	WRT_CHECK(rig_until_done(&R, ia, 10000) && rq_at(&R, ia)->status == WR_OK && rq_at(&R, ia)->retry_attempt == 0 && rig_nrec(&R, 0) == n0 + 1u);
	WRT_CHECK(rig_take(&R, ia) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

int main(void)
{
	test_hold_and_release();
	test_object_level();
	test_sent_ops_resent();
	test_other_pg_unblock();
	test_session_loss_forgets();
	return wrt_finish();
}
