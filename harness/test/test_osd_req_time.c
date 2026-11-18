/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_time.c - the engine and the clock (design 23.8): a silent OSD (the deadline of an op doubles up to x8, the session is reset, the op is resent,
 * WR_EV_IO_STALL once and WR_EV_IO_RESUME at the next answer), the cool-down in between, the stale-map rule (map_stale_ms fails ops that never left, never
 * one that was sent), the pool-not-found verdict, the transmit-queue retry, the idle close of a session, the wall clock in mtime, and the deadline the
 * engine reports.
 */
#include "osd_req_rig.h"

static rig R;

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 17u + i);
}

static void tweak_silent(rig *r)
{
	r->w.ocfg[0].fault.silent = 1;
}

/* ---- a silent OSD --------------------------------------------------------------------------------------------------------------------- */

static void test_ladder(void)
{
	uint8_t data[128], back[128];
	uint32_t i, k, nrec = 0, slot;
	uint64_t sent_at[8], t0, base;
	wri_osd_op *op;
	/* send times relative to the first one: deadline + cool-down, each doubling up to x8 and 10 s: 5+2, 10+4, 20+8, 40+10, 40+10 */
	static const uint64_t want_at[6] = {0, 7000, 21000, 49000, 99000, 149000};
	static const uint64_t want_span[6] = {5000, 10000, 20000, 40000, 40000, 40000};

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	t0 = rig_now(&R);
	i = rq_write(&R, "ladder", 0, data, sizeof(data), NULL, 0);
	slot = i;
	op = rq_at(&R, i);
	(void)rig_settle(&R);
	base = rig_now(&R);
	WRT_CHECK(t0 == base);
	for (k = 0; k < 6 && base + 200000u > rig_now(&R);) {
		uint32_t n = rig_nrec(&R, 0);

		if (n > nrec) {
			WRT_CHECK(n == nrec + 1u && k < 6u);
			sent_at[k] = rig_now(&R) - base;
			WRT_CHECK(op->retry_attempt == (int32_t)k && rig_rec(&R, 0, n - 1u)->retry_attempt == (uint32_t)k);
			WRT_CHECK(op->deadline_ms - op->sent_ms == want_span[k] && op->sent_ms == rig_now(&R));
			WRT_CHECK(wri_osdc_deadline(&R.o) == op->deadline_ms); /* the engine wants to run at the deadline of the op */
			nrec = n;
			k++;
		}
		rig_tick(&R, 100);
	}
	WRT_CHECK(k == 6u);
	for (i = 0; i < 6 && i < k; i++)
		WRT_CHECK(sent_at[i] == want_at[i]);
	WRT_CHECK(R.o.n_timeouts == 5u && R.o.sess.n_resets == 5u && R.n_stall == 1u && R.n_resume == 0u && op->state == WRI_OP_SENT);
	WRT_CHECK(R.ev[0].kind == WR_EV_IO_STALL && R.ev[0].st == WR_E_TIMEOUT && R.ev[0].arg == 0u && R.ev[0].a0 == 0u);
	WRT_CHECK(sim_osd_n_conns_accepted(R.w.osd[0]) == 6u); /* every resend on a new connection */
	/* the OSD answers again: the op completes, the stall is over, and it was written once (the recorded requests were never executed) */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	WRT_CHECK(rig_until_done(&R, slot, 60000));
	WRT_CHECK(op->status == WR_OK && R.n_resume == 1u && R.n_stall == 1u && op->retry_attempt == 6);
	WRT_CHECK(rig_store_read(&R, "ladder", 0, back, sizeof(back)) == 1 && memcmp(back, data, sizeof(data)) == 0);
	WRT_CHECK(rig_take(&R, slot) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_deadline_report(void)
{
	uint8_t data[64];
	uint32_t i;
	uint64_t t0;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 2);
	WRT_CHECK(wri_osdc_deadline(&R.o) == WR_DEADLINE_NONE);
	t0 = rig_now(&R);
	i = rq_write(&R, "dl", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(wri_osdc_deadline(&R.o) == t0); /* a new op: run now */
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && wri_osdc_deadline(&R.o) == t0 + 5000u);
	rig_tick(&R, 5000); /* the deadline: the session is reset and the op waits out the cool-down */
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && R.o.n_timeouts == 1u);
	WRT_CHECK(wri_osdc_deadline(&R.o) == t0 + 7000u && R.o.sess.s[0].state == WRI_OS_COOLDOWN && R.o.sess.s[0].cooldown_until_ms == t0 + 7000u);
	rig_tick(&R, 2000);
	WRT_CHECK(op->state == WRI_OP_SENT && op->deadline_ms == t0 + 7000u + 10000u && wri_osdc_deadline(&R.o) == op->deadline_ms);
	rig_close(&R);
}

/* a reset costs the other ops of the session a resend, not a failure; an op that timed out is not failed by anything the engine does */
static void test_reset_resends_all(void)
{
	uint8_t data[64];
	uint32_t i[3], k;
	char nm[3][16];

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	for (k = 0; k < 3; k++) {
		snprintf(nm[k], sizeof(nm[k]), "rr.%u", k);
		i[k] = rq_write(&R, nm[k], 0, data, sizeof(data), NULL, 0);
		rig_tick(&R, 1000); /* submitted one second apart: only the first one's deadline is due at 5 s */
	}
	rig_tick(&R, 2100);
	WRT_CHECK(R.o.n_timeouts == 1u && R.o.sess.n_resets == 1u);
	for (k = 0; k < 3; k++)
		WRT_CHECK(rq_at(&R, i[k])->state == WRI_OP_WAIT_SESS || rq_at(&R, i[k])->state == WRI_OP_SENT);
	sim_osd_faults(R.w.osd[0])->silent = 0;
	rig_tick(&R, 4000);
	for (k = 0; k < 3; k++)
		WRT_CHECK(rq_done(&R, i[k]) && rq_at(&R, i[k])->status == WR_OK && rq_at(&R, i[k])->retry_attempt == 1);
	WRT_CHECK(R.o.n_resent == 3u && R.n_stall == 1u && R.n_resume == 1u);
	for (k = 0; k < 3; k++)
		WRT_CHECK(rig_take(&R, i[k]) == WR_OK);
	WRT_CHECK(rig_idle(&R));
	rig_close(&R);
}

/* ---- the stale-map rule ---------------------------------------------------------------------------------------------------------------- */

static void tweak_nomap(rig *r)
{
	r->m.epoch = 0;
}

static void test_stale_no_map(void)
{
	uint8_t data[32];
	uint32_t a, b;
	uint64_t t0;

	if (rig_open(&R, 1, 2, tweak_nomap) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	t0 = rig_now(&R);
	a = rq_write(&R, "nm", 0, data, sizeof(data), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_WAIT_MAP && wri_osdc_deadline(&R.o) == t0 + 30000u);
	rig_tick(&R, 25000);
	b = rq_write(&R, "nm2", 0, data, sizeof(data), NULL, 0); /* later: it has waited less, and the limit is its own */
	rig_tick(&R, 4900);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_WAIT_MAP && R.n_stall == 0u);
	rig_tick(&R, 100);
	WRT_CHECK(rq_done(&R, a) && rq_at(&R, a)->status == WR_E_OSD_MAP_STALE && rq_at(&R, b)->state == WRI_OP_WAIT_MAP);
	WRT_CHECK(R.n_stall == 1u && R.ev[0].kind == WR_EV_IO_STALL && R.ev[0].st == WR_E_OSD_MAP_STALE && R.ev[0].arg == 0xffffffffu);
	WRT_CHECK(wri_osdc_deadline(&R.o) == t0 + 25000u + 30000u);
	rig_tick(&R, 25000);
	WRT_CHECK(rq_done(&R, b) && rq_at(&R, b)->status == WR_E_OSD_MAP_STALE && R.o.n_failed == 2u);
	WRT_CHECK(rig_take(&R, a) == WR_E_OSD_MAP_STALE && rig_take(&R, b) == WR_E_OSD_MAP_STALE && rig_idle(&R));
	WRT_CHECK(rig_nrec(&R, 0) == 0u);
	/* the map arrives in time: the op goes */
	a = rq_write(&R, "nm", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 20000);
	R.m.epoch = 5;
	WRT_CHECK(rig_until_done(&R, a, 1000) && rq_at(&R, a)->status == WR_OK && rq_at(&R, a)->sent_epoch == 5u);
	WRT_CHECK(rig_take(&R, a) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void test_stale_homeless(void)
{
	uint8_t data[32];
	uint32_t a, pg;
	wri_osd_op *op;
	uint64_t t0;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	pg = mw_pg(&R.m, "hl");
	R.m.prim[pg] = -1;
	t0 = rig_now(&R);
	a = rq_write(&R, "hl", 0, data, sizeof(data), NULL, 0);
	op = rq_at(&R, a);
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_HOMELESS);
	/* a new epoch that still has no primary: the map advanced, so the clock of "the map has not advanced" starts again */
	rig_tick(&R, 20000);
	R.m.epoch = 11;
	rig_tick(&R, 20000); /* 40 s after the submit, 20 after the last epoch */
	WRT_CHECK(op->state == WRI_OP_HOMELESS && R.n_stall == 0u);
	WRT_CHECK(wri_osdc_deadline(&R.o) == t0 + 20100u + 30000u); /* from the pass that saw the epoch */
	rig_tick(&R, 10100);
	WRT_CHECK(rq_done(&R, a) && op->status == WR_E_OSD_MAP_STALE && rig_take(&R, a) == WR_E_OSD_MAP_STALE && rig_idle(&R));
	rig_close(&R);
}

static void test_stale_paused(void)
{
	uint8_t data[32];
	uint32_t a, b;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	R.m.flags = WR_MAP_F_PAUSEWR;
	R.m.epoch = 11;
	a = rq_write(&R, "pz", 0, data, sizeof(data), NULL, 0);
	b = rq_read(&R, "pz", 0, 8, data, 0);
	(void)rig_settle(&R);
	op = rq_at(&R, a);
	WRT_CHECK(op->state == WRI_OP_PAUSED && rq_done(&R, b) && rq_at(&R, b)->status == WR_E_OSD_NOENT);
	rig_tick(&R, 30000);
	WRT_CHECK(rq_done(&R, a) && op->status == WR_E_OSD_MAP_STALE);
	WRT_CHECK(rig_take(&R, b) == WR_E_OSD_NOENT && rig_take(&R, a) == WR_E_OSD_MAP_STALE && rig_idle(&R));
	rig_close(&R);
}

/* The rule never touches an op that was on the wire: a write may have been applied, so it waits for the map for as long as it takes. */
static void test_stale_spares_sent(void)
{
	uint8_t data[32];
	uint32_t a, b, pg;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	pg = mw_pg(&R.m, "sp");
	a = rq_write(&R, "sp", 0, data, sizeof(data), NULL, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_SENT);
	R.m.prim[pg] = -1; /* the PG loses its primary; the op leaves the wire for the homeless list */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	b = rq_write(&R, "sp", 32, data, sizeof(data), NULL, 0); /* never sent */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_HOMELESS && rq_at(&R, b)->state == WRI_OP_HOMELESS);
	rig_tick(&R, 100000);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_HOMELESS && rq_done(&R, b) && rq_at(&R, b)->status == WR_E_OSD_MAP_STALE);
	WRT_CHECK(rig_take(&R, b) == WR_E_OSD_MAP_STALE);
	/* the primary comes back: the old write goes again and completes (the real OSD answers now) */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	R.m.prim[pg] = 0;
	R.m.epoch = 12;
	WRT_CHECK(rig_until_done(&R, a, 20000) && rq_at(&R, a)->status == WR_OK && rq_at(&R, a)->retry_attempt >= 1);
	WRT_CHECK(rig_take(&R, a) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

static void tweak_stale_off(rig *r)
{
	r->w.e.x.cfg.map_stale_ms = 0;
	r->m.epoch = 0;
}

static void test_stale_off(void)
{
	uint8_t data[32];
	uint32_t a;

	if (rig_open(&R, 1, 2, tweak_stale_off) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	a = rq_write(&R, "off", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 200000);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_WAIT_MAP && wri_osdc_deadline(&R.o) == WR_DEADLINE_NONE); /* 0 = never: nothing to wake for */
	R.m.epoch = 3;
	WRT_CHECK(rig_until_done(&R, a, 1000) && rq_at(&R, a)->status == WR_OK && rig_take(&R, a) == WR_OK);
	rig_close(&R);
}

/* ---- the pool is not in the map ------------------------------------------------------------------------------------------------------- */

static void tweak_no_pool(rig *r)
{
	r->m.pool[0].present = 0;
}

static void test_pool_not_found(void)
{
	uint8_t data[32];
	uint32_t a, b;

	/* a pool tracked after the first map reads as missing until the full map arrives: the op waits for it ... */
	if (rig_open(&R, 1, 2, tweak_no_pool) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	a = rq_write(&R, "np", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 10000);
	R.m.epoch = 11; /* a newer map that still lacks the pool does not settle it inside the window */
	rig_tick(&R, 10000);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_WAIT_MAP);
	R.m.pool[0].present = 1; /* ... and goes when the pool shows up */
	WRT_CHECK(rig_until_done(&R, a, 1000) && rq_at(&R, a)->status == WR_OK && rig_take(&R, a) == WR_OK);
	/* a pool that is not coming: after the window the answer is POOL_NOT_FOUND, not the generic stale-map error */
	R.m.pool[0].present = 0;
	R.m.epoch = 12;
	b = rq_write(&R, "np", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 29900);
	WRT_CHECK(rq_at(&R, b)->state == WRI_OP_WAIT_MAP);
	rig_tick(&R, 100);
	WRT_CHECK(rq_done(&R, b) && rq_at(&R, b)->status == WR_E_POOL_NOT_FOUND && rig_take(&R, b) == WR_E_POOL_NOT_FOUND && rig_idle(&R));
	rig_close(&R);
}

static void tweak_no_pool_no_stale(rig *r)
{
	r->m.pool[0].present = 0;
	r->w.e.x.cfg.map_stale_ms = 0;
}

static void test_pool_not_found_no_window(void)
{
	uint8_t data[32];
	uint32_t a;

	if (rig_open(&R, 1, 2, tweak_no_pool_no_stale) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	a = rq_write(&R, "np", 0, data, sizeof(data), NULL, 0);
	rig_tick(&R, 100000);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_WAIT_MAP); /* same epoch as the submit: it may still be the full map that is on its way */
	R.m.epoch = 11; /* a newer map without the pool: deleted */
	(void)rig_settle(&R);
	WRT_CHECK(rq_done(&R, a) && rq_at(&R, a)->status == WR_E_POOL_NOT_FOUND && rig_take(&R, a) == WR_E_POOL_NOT_FOUND && rig_idle(&R));
	rig_close(&R);
}

/* ---- the transmit queue, the idle close, the wall clock ------------------------------------------------------------------------------- */

static void test_tx_busy_retry(void)
{
	enum { N = 12 };
	uint8_t data[1024];
	uint32_t i[N], k, sent_now = 0;
	char nm[N][16];
	uint64_t t0, prev = 0;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 4);
	i[0] = rq_write(&R, "tx.warm", 0, data, 16, NULL, 0); /* the session first: the handshake needs the host to consume its frames */
	WRT_CHECK(i[0] != WRI_NIL && rig_until_done(&R, i[0], 1000) && rig_take(&R, i[0]) == WR_OK);
	R.w.tx_hold = 1; /* the host does not consume what the engine queues: the transmit queue fills */
	t0 = rig_now(&R);
	for (k = 0; k < N; k++) {
		snprintf(nm[k], sizeof(nm[k]), "tx.%u", k);
		i[k] = rq_write(&R, nm[k], 0, data, sizeof(data), NULL, 0);
	}
	(void)rig_settle(&R);
	for (k = 0; k < N; k++)
		sent_now += rq_at(&R, i[k])->state == WRI_OP_SENT ? 1u : 0u;
	WRT_CHECK(sent_now >= 1u && sent_now < (uint32_t)N); /* the queue holds a few messages */
	WRT_CHECK(rq_at(&R, i[N - 1])->state == WRI_OP_QUEUED);
	/* the ones that were sent are the first ones: nothing overtook an op that met the full queue */
	for (k = 0; k < N; k++) {
		int s = rq_at(&R, i[k])->state == WRI_OP_SENT;

		if (k != 0 && s)
			WRT_CHECK(rq_at(&R, i[k - 1])->state == WRI_OP_SENT);
	}
	WRT_CHECK(wri_osdc_deadline(&R.o) == t0 + 10u && R.o.retry_at_ms == t0 + 10u); /* retry soon: the retry beats the 5 s deadlines */
	WRT_CHECK(!wri_osd_sess_tx_idle(&R.o.sess, 0));
	R.w.tx_hold = 0;
	rig_tick(&R, 10);
	for (k = 0; k < N; k++)
		WRT_CHECK(rq_done(&R, i[k]) && rq_at(&R, i[k])->retry_attempt == 0 && rq_at(&R, i[k])->status == WR_OK);
	/* every connection saw ascending tids, and only first transmissions */
	{
		uint32_t n = rig_nrec(&R, 0), j;

		WRT_CHECK(n == (uint32_t)N + 1u);
		for (j = 0; j < n; j++) {
			WRT_CHECK(rig_rec(&R, 0, j)->tid > prev && rig_rec(&R, 0, j)->retry_attempt == 0u);
			prev = rig_rec(&R, 0, j)->tid;
		}
	}
	WRT_CHECK(R.o.n_resent == 0u && R.o.n_timeouts == 0u);
	for (k = 0; k < N; k++)
		WRT_CHECK(rig_take(&R, i[k]) == WR_OK);
	WRT_CHECK(rig_idle(&R));
	rig_close(&R);
}

static void tweak_idle(rig *r)
{
	r->w.e.x.cfg.osd_idle_ms = 3000;
}

static void test_idle_close(void)
{
	uint8_t data[32];
	uint32_t a, b;
	uint64_t t0;

	if (rig_open(&R, 1, 2, tweak_idle) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	a = rq_write(&R, "idle", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, a, 1000) && rig_take(&R, a) == WR_OK);
	t0 = rig_now(&R);
	WRT_CHECK(R.o.sess.s[0].state == WRI_OS_READY && wri_osdc_deadline(&R.o) == t0 + 3000u);
	rig_tick(&R, 3000);
	WRT_CHECK(R.o.sess.s[0].state == WRI_OS_FREE && R.o.sess.n_idle_closed == 1u && R.n_stall == 0u && wri_osdc_deadline(&R.o) == WR_DEADLINE_NONE);
	/* an orderly close has no cool-down: the next op connects at once */
	b = rq_write(&R, "idle", 32, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, b, 100) && rq_at(&R, b)->status == WR_OK && sim_osd_n_conns_accepted(R.w.osd[0]) == 2u && rig_take(&R, b) == WR_OK);
	rig_close(&R);
}

static void test_wall_clock(void)
{
	uint8_t data[32];
	uint32_t a;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	R.w.e.x.now.wall_ms = 1700000000123ull; /* a host with a wall clock: mtime is its seconds and nanoseconds */
	a = rq_write(&R, "wall", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, a, 1000) && rq_at(&R, a)->status == WR_OK && rig_take(&R, a) == WR_OK);
	R.w.e.x.now.wall_ms = 0; /* a host without one: 0, which the OSD takes */
	a = rq_write(&R, "wall", 0, data, sizeof(data), NULL, 0);
	WRT_CHECK(rig_until_done(&R, a, 1000) && rq_at(&R, a)->status == WR_OK && rig_take(&R, a) == WR_OK);
	WRT_CHECK(sim_osd_n_violations(R.w.osd[0]) == 0u && rig_idle(&R));
	rig_close(&R);
}

int main(void)
{
	test_ladder();
	test_deadline_report();
	test_reset_resends_all();
	test_stale_no_map();
	test_stale_homeless();
	test_stale_paused();
	test_stale_spares_sent();
	test_stale_off();
	test_pool_not_found();
	test_pool_not_found_no_window();
	test_tx_busy_retry();
	test_idle_close();
	test_wall_clock();
	return wrt_finish();
}
