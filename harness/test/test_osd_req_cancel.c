/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_cancel.c - wri_osdc_cancel in every state (design 23.9, osd-ops.md 3.3 item 7). A read, and a write that never left, are dropped (completed
 * with WR_E_CANCELLED); a read whose reply is being received into its buffer resets the session first; a write that was transmitted becomes a ZOMBIE with a
 * copy of its data and of its snapshot context, is resent until answered and then freed without a word; a zombie that does not fit the first-fit area is
 * BUSY; a write whose data is still referenced by a transmit queue resets the session before the copy is made. The owner's buffer is overwritten after
 * every cancel that returned WR_OK: nothing may ever read it again.
 */
#include "osd_req_rig.h"

static rig R;

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 23u + i * 5u + 1u);
}

static void tweak_silent(rig *r)
{
	r->w.ocfg[0].fault.silent = 1;
}

static uint32_t live_sess(rig *r)
{
	uint32_t i;

	for (i = 0; i < r->o.sess.n; i++)
		if (r->o.sess.s[i].state == WRI_OS_READY || r->o.sess.s[i].state == WRI_OS_OPENING)
			return i;
	return WRI_NIL;
}

/* Pop the one completion that must be `i` and check its status. */
static void expect_cancelled(uint32_t i)
{
	wri_osd_op *op = rq_at(&R, i);

	WRT_CHECK(op->state == WRI_OP_DONE && op->status == WR_E_CANCELLED && op->sess == WRI_NIL && op->out == NULL);
	WRT_CHECK(rig_take(&R, i) == WR_E_CANCELLED);
}

/* ---- reads: every state ----------------------------------------------------------------------------------------------------------- */

typedef enum st_make { MK_NEW, MK_WAIT_MAP, MK_HOMELESS, MK_PAUSED, MK_WAIT_SESS, MK_QUEUED, MK_SENT } st_make;

static void tweak_for(rig *r, st_make k)
{
	if (k == MK_WAIT_MAP)
		r->m.epoch = 0;
	if (k == MK_SENT)
		sim_osd_faults(r->w.osd[0])->silent = 1; /* the simulator exists already: change its live plan */
}

/* Bring a fresh read of "cx.obj" into the state `k`; returns its slot (the rig is open). */
static uint32_t make_read(st_make k, uint8_t *buf)
{
	uint32_t i, pg = mw_pg(&R.m, "cx.obj"), s;
	uint8_t warm[8];

	if (k == MK_QUEUED) { /* a READY session and a backoff over the PG */
		WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "cx.obj", 0, buf, 64));
		i = rq_read(&R, "cx.obj", 0, 8, warm, 0);
		WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 1000) && rig_take(&R, i) == WR_OK);
		s = live_sess(&R);
		WRT_CHECK(sim_osd_send_backoff(rig_srv(&R, s), WRI_BACKOFF_BLOCK, 5, W_POOL, pg, R.m.epoch, "", 0, SIM_OSD_BO_MAX, 0) == WR_OK);
		(void)rig_settle(&R);
	}
	if (k == MK_HOMELESS)
		R.m.prim[pg] = -1;
	if (k == MK_PAUSED)
		R.m.flags = WR_MAP_F_PAUSERD;
	if (k == MK_WAIT_SESS)
		R.w.osd_down[0] = 1;
	i = rq_read(&R, "cx.obj", 0, 64, buf, 0x44);
	if (k != MK_NEW)
		(void)rig_settle(&R);
	return i;
}

static void test_read_every_state(void)
{
	static const wri_op_state want[7] = {WRI_OP_NEW, WRI_OP_WAIT_MAP, WRI_OP_HOMELESS, WRI_OP_PAUSED, WRI_OP_WAIT_SESS, WRI_OP_QUEUED, WRI_OP_SENT};
	unsigned k;

	for (k = 0; k < 7; k++) {
		uint8_t buf[64];
		uint32_t i;
		wri_osd_op *op;
		uint32_t n_before;

		if (rig_open(&R, 1, 2, NULL) != 0) {
			WRT_CHECK(0);
			return;
		}
		tweak_for(&R, (st_make)k);
		fill(buf, sizeof(buf), k);
		i = make_read((st_make)k, buf);
		op = rq_at(&R, i);
		WRT_CHECK(i != WRI_NIL && op->state == want[k]);
		n_before = R.o.n_inflight;
		WRT_CHECK(n_before == 1u && R.o.n_zombies == 0u);
		WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
		WRT_CHECK(R.o.n_inflight == 0u && R.o.inflight_bytes == 0u && R.o.n_zombies == 0u && wri_osdc_count_owner(&R.o, 0x44, 0xffffffffu) == 1u);
		WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i)); /* idempotent: it is done already */
		WRT_CHECK(wri_osdc_pop_done(&R.o) == i);
		WRT_CHECK(op->state == WRI_OP_DONE && op->status == WR_E_CANCELLED && op->out == NULL && op->sess == WRI_NIL);
		wri_osdc_release(&R.o, i);
		WRT_CHECK_STATUS(WR_E_STATE, wri_osdc_cancel(&R.o, i)); /* a free slot */
		WRT_CHECK(wri_osdc_count_owner(&R.o, 0x44, 0xffffffffu) == 0u);
		/* nothing is left on the session either */
		{
			uint32_t s = live_sess(&R);

			if (s != WRI_NIL)
				WRT_CHECK(R.o.sess.s[s].n_inflight == 0u);
		}
		/* and the engine goes on: the freed slot, the map and the session are as good as before */
		R.w.osd_down[0] = 0;
		R.m.flags = 0;
		R.m.epoch = 20;
		R.m.prim[mw_pg(&R.m, "cx.obj")] = 0;
		sim_osd_faults(R.w.osd[0])->silent = 0;
		if (k == MK_QUEUED && live_sess(&R) != WRI_NIL)
			WRT_CHECK(sim_osd_send_backoff(rig_srv(&R, live_sess(&R)), WRI_BACKOFF_UNBLOCK, 5, W_POOL, mw_pg(&R.m, "cx.obj"), R.m.epoch, "", 0,
						       SIM_OSD_BO_MAX, 0) == WR_OK);
		(void)rig_settle(&R);
		{
			uint32_t j = rq_read(&R, "cx.obj", 0, 8, buf, 0);

			WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "cx.obj", 0, buf, 8));
			WRT_CHECK(j != WRI_NIL && rig_until_done(&R, j, 30000) && rig_take(&R, j) == WR_OK && rig_idle(&R));
		}
		rig_close(&R);
	}
}

/* ---- a late reply finds nothing --------------------------------------------------------------------------------------------------------- */

static void tweak_hold(rig *r)
{
	r->w.ocfg[0].fault.hold_replies = 1;
}

static void test_late_reply_discarded(void)
{
	uint8_t data[64], got[64], sentinel[64];
	uint32_t i, n;

	if (rig_open(&R, 1, 2, tweak_hold) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 1);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "late", 0, data, sizeof(data)));
	memset(got, 0, sizeof(got));
	i = rq_read(&R, "late", 0, sizeof(got), got, 0);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, i)->state == WRI_OP_SENT && sim_osd_n_held(R.w.osd[0]) == 1u);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK(R.o.sess.s[live_sess(&R)].n_inflight == 0u && R.o.sess.n_resets == 0u); /* no reset: nothing was arriving */
	memset(got, 0xAA, sizeof(got));
	memset(sentinel, 0xAA, sizeof(sentinel));
	n = R.o.n_stray;
	WRT_CHECK(sim_osd_release(R.w.osd[0], 0) == 1u);
	(void)rig_settle(&R);
	WRT_CHECK(memcmp(got, sentinel, sizeof(got)) == 0 && R.o.n_stray == n + 1u); /* the data was discarded, not stored */
	expect_cancelled(i);
	/* the slot is reused by an op with a new tid: the late reply of the old one cannot be taken for it (the tid carries the counter) */
	sim_osd_faults(R.w.osd[0])->hold_replies = 0;
	i = rq_read(&R, "late", 0, sizeof(got), got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 1000) && memcmp(got, data, sizeof(data)) == 0 && rig_take(&R, i) == WR_OK && rig_idle(&R));
	rig_close(&R);
}

/* ---- a read whose reply is being received -------------------------------------------------------------------------------------------------- */

static void test_read_mid_reply(void)
{
	uint8_t data[4096], got[4096], sentinel[4096], warm[8];
	uint32_t i, s, w;
	wri_osd_op *op;
	size_t k;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "mid", 0, data, sizeof(data)));
	w = rq_read(&R, "mid", 0, 8, warm, 0); /* the session first */
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	s = live_sess(&R);
	/* the connection delivers only the first bytes of the reply: the header and a part of the data are in */
	memset(got, 0xAA, sizeof(got));
	i = rq_read(&R, "mid", 0, sizeof(got), got, 0);
	R.w.rx_budget_on = 1;
	R.w.rx_budget = 800;
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && R.o.sess.s[s].rx_tid == op->tid);
	/* the cancel has to stop the bytes before the buffer goes back: the session is reset (orderly: no penalty, no cool-down) */
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK((op->flags & WRI_OPF_MIDRX) != 0 && R.o.sess.s[s].state == WRI_OS_FREE && R.o.sess.n_resets == 0u && R.n_stall == 0u);
	memset(got, 0xAA, sizeof(got)); /* the owner has its buffer back ... */
	memset(sentinel, 0xAA, sizeof(sentinel));
	R.w.rx_budget_on = 0; /* ... and the rest of the reply is delivered to a connection that no longer exists */
	(void)rig_settle(&R);
	for (k = 0; k < 8; k++)
		(void)rig_settle(&R);
	WRT_CHECK(memcmp(got, sentinel, sizeof(got)) == 0);
	expect_cancelled(i);
	/* a new op connects at once and reads the object whole */
	i = rq_read(&R, "mid", 0, sizeof(got), got, 0);
	WRT_CHECK(i != WRI_NIL && rig_until_done(&R, i, 100) && memcmp(got, data, sizeof(data)) == 0 && rig_take(&R, i) == WR_OK && rig_idle(&R));
	WRT_CHECK(sim_osd_n_conns_accepted(R.w.osd[0]) == 2u);
	rig_close(&R);
}

/* ---- writes -------------------------------------------------------------------------------------------------------------------------------- */

static void test_write_never_sent_is_dropped(void)
{
	uint8_t data[100];
	uint32_t i;
	unsigned k;

	for (k = 0; k < 4; k++) {
		if (rig_open(&R, 1, 2, NULL) != 0) {
			WRT_CHECK(0);
			return;
		}
		fill(data, sizeof(data), k);
		if (k == 1)
			R.m.epoch = 0;
		if (k == 2)
			R.m.flags = WR_MAP_F_PAUSEWR;
		if (k == 3)
			R.w.osd_down[0] = 1; /* WAIT_SESS: the session never opens */
		i = rq_write(&R, "wnever", 0, data, sizeof(data), NULL, 0x55);
		if (k != 0)
			(void)rig_settle(&R);
		WRT_CHECK(rq_at(&R, i)->sent_epoch == 0u);
		WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
		memset(data, 0xEE, sizeof(data));
		WRT_CHECK((rq_at(&R, i)->flags & WRI_OPF_ZOMBIE) == 0 && R.o.n_zombies == 0u && R.o.zused == 0u);
		expect_cancelled(i);
		WRT_CHECK(rig_idle(&R) && rig_nrec(&R, 0) == 0u && sim_store_n_objects(R.w.store) == 0u);
		rig_close(&R);
	}
}

static void test_write_zombie(void)
{
	uint8_t data[300], keep[300], back[300];
	uint64_t ids[3] = {7, 5, 2};
	wri_snapc sc;
	uint32_t i, free_before;
	uint64_t tid;
	wri_osd_op *op;
	const sim_osd_rec *rec;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(&sc, 0, sizeof(sc));
	sc.seq = 7, sc.n = 3, sc.cap = 3, sc.snaps = ids;
	fill(data, sizeof(data), 7);
	memcpy(keep, data, sizeof(data));
	i = rq_write(&R, "zomb", 0, data, sizeof(data), &sc, 0x66);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	tid = op->tid;
	WRT_CHECK(op->state == WRI_OP_SENT && rig_nrec(&R, 0) == 1u);
	free_before = R.o.n_free;
	/* the owner gives up: the write may have been applied, so the engine keeps it and the owner's buffers are free at once */
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK((op->flags & WRI_OPF_ZOMBIE) != 0 && R.o.n_zombies == 1u && R.o.zused >= 300u + 24u + 24u && R.o.zused == op->zlen && R.o.zmax == R.o.zused);
	WRT_CHECK(op->data >= R.o.zbuf && op->data < R.o.zbuf + R.o.zcap && op->data != data && op->out == NULL);
	WRT_CHECK((const uint8_t *)op->snapc >= R.o.zbuf && (const uint8_t *)op->snapc < R.o.zbuf + R.o.zcap && op->snapc != &sc && op->snapc->n == 3u);
	WRT_CHECK(wri_osdc_pop_done(&R.o) == WRI_NIL && R.o.n_free == free_before && wri_osdc_count_owner(&R.o, 0x66, 0xffffffffu) == 1u);
	WRT_CHECK(R.o.n_inflight == 1u && R.o.inflight_bytes == 300u);
	wri_osdc_release(&R.o, i); /* not the owner's any more: ignored */
	WRT_CHECK(R.o.n_free == free_before && op->state == WRI_OP_SENT);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i)); /* idempotent */
	WRT_CHECK(R.o.n_zombies == 1u);
	memset(data, 0xEE, sizeof(data)); /* the owner reuses its memory: ... */
	ids[0] = 99, ids[1] = 98, ids[2] = 97, sc.seq = 99;
	/* ... and the zombie is sent again (the OSD restarts), from its copy: the original bytes and the original snapshot context */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	rig_tick(&R, 2100);
	WRT_CHECK(rig_nrec(&R, 0) == 2u);
	rec = rig_rec(&R, 0, 1);
	WRT_CHECK(rec->tid == tid && rec->retry_attempt == 1u && rec->snap_seq == 7u && rec->n_snaps == 3u && rec->data_len == 300u && rec->executed);
	WRT_CHECK(rig_store_read(&R, "zomb", 0, back, sizeof(back)) == 1 && memcmp(back, keep, sizeof(keep)) == 0);
	/* answered: freed without a completion, the copy's room is back, nothing of it remains */
	WRT_CHECK(wri_osdc_pop_done(&R.o) == WRI_NIL && R.o.n_zombies_done == 1u && R.o.zused == 0u && R.o.zmax >= 348u && rig_idle(&R));
	WRT_CHECK(wri_osdc_count_owner(&R.o, 0x66, 0xffffffffu) == 0u && R.o.n_free == R.o.n_op && R.o.n_failed == 0u);
	WRT_CHECK(R.n_stall == 1u && R.n_resume == 1u);
	rig_close(&R);
}

static void test_zombie_after_loss_and_eagain(void)
{
	uint8_t data[64], keep[64], back[64];
	uint32_t i;
	uint64_t tid;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 2);
	memcpy(keep, data, sizeof(data));
	i = rq_write(&R, "zl", 0, data, sizeof(data), NULL, 0x12);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	tid = op->tid;
	/* the connection is cut first: the op waits for a session, and it still counts as sent (it may have been applied) */
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_WAIT_SESS && op->sent_epoch != 0u);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK((op->flags & WRI_OPF_ZOMBIE) != 0 && wri_osdc_pop_done(&R.o) == WRI_NIL);
	memset(data, 0xEE, sizeof(data));
	/* the first answer is EAGAIN: the zombie takes a new tid and goes again; its second answer ends it */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_faults(R.w.osd[0])->eagain_ops = 1;
	rig_tick(&R, 2200);
	WRT_CHECK(rig_nrec(&R, 0) == 3u && rig_rec(&R, 0, 1)->tid == tid && rig_rec(&R, 0, 2)->tid > tid && (rig_rec(&R, 0, 2)->tid & 0xffffu) == (tid & 0xffffu));
	WRT_CHECK(rig_rec(&R, 0, 2)->retry_attempt == 2u && rig_rec(&R, 0, 2)->executed && R.o.n_eagain == 1u);
	WRT_CHECK(rig_store_read(&R, "zl", 0, back, sizeof(back)) == 1 && memcmp(back, keep, sizeof(keep)) == 0);
	WRT_CHECK(R.o.n_zombies_done == 1u && rig_idle(&R) && wri_osdc_pop_done(&R.o) == WRI_NIL);
	rig_close(&R);
}

static void tweak_small_zombies(rig *r)
{
	r->w.ocfg[0].fault.silent = 1;
	r->w.e.x.cfg.zombie_bytes = 256;
}

static void test_zombie_does_not_fit(void)
{
	uint8_t d1[200], d2[200], k2[200], back[200];
	uint32_t a, b;
	wri_osd_op *oa, *ob;

	if (rig_open(&R, 1, 2, tweak_small_zombies) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(d1, sizeof(d1), 1);
	fill(d2, sizeof(d2), 2);
	memcpy(k2, d2, sizeof(d2));
	a = rq_write(&R, "zf.a", 0, d1, sizeof(d1), NULL, 0x01);
	b = rq_write(&R, "zf.b", 0, d2, sizeof(d2), NULL, 0x02);
	(void)rig_settle(&R);
	oa = rq_at(&R, a), ob = rq_at(&R, b);
	WRT_CHECK(oa->state == WRI_OP_SENT && ob->state == WRI_OP_SENT);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, a));
	WRT_CHECK((oa->flags & WRI_OPF_ZOMBIE) != 0 && oa->zoff == 0u && oa->zlen == 200u && R.o.zused == 200u);
	/* 56 bytes are left: the second copy does not fit; nothing changes, the owner keeps its buffer and the op stays live */
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osdc_cancel(&R.o, b));
	WRT_CHECK((ob->flags & WRI_OPF_ZOMBIE) == 0 && ob->state == WRI_OP_SENT && ob->data == d2 && R.o.n_zombies == 1u && R.o.zused == 200u && R.o.sess.n_resets == 0u);
	/* the OSD comes back (a restart cuts the connection): the zombie is answered and freed, and b, which was never abandoned, completes normally */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	rig_tick(&R, 2200);
	WRT_CHECK(R.o.n_zombies_done == 1u && R.o.zused == 0u && rq_done(&R, b)); /* b was never abandoned: it completed normally */
	WRT_CHECK(rig_take(&R, b) == WR_OK && rig_idle(&R));
	WRT_CHECK(rig_store_read(&R, "zf.b", 0, back, sizeof(back)) == 1 && memcmp(back, k2, sizeof(k2)) == 0);
	rig_close(&R);
}

static void tweak_three_silent(rig *r)
{
	unsigned i;

	for (i = 0; i < 3; i++)
		r->w.ocfg[i].fault.silent = 1;
	r->w.e.x.cfg.zombie_bytes = 2048;
	for (i = 0; i < MW_PG_MAX; i++)
		r->m.prim[i] = (int)(i % 3u);
}

static const char *name_on_osd(unsigned osd, unsigned nth, char *buf, size_t n)
{
	unsigned k, seen = 0;

	for (k = 0; k < 1000; k++) {
		snprintf(buf, n, "ff.%u", k);
		if ((mw_hash(buf, strlen(buf)) & 7u) % 3u == osd && seen++ == nth)
			break;
	}
	return buf;
}

static void test_first_fit(void)
{
	uint8_t d[3][300], e[250], f[400];
	char nm[3][24], ne[24], nf[24];
	uint32_t i[3], x, y, k;

	if (rig_open(&R, 3, 3, tweak_three_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	for (k = 0; k < 3; k++) {
		(void)name_on_osd(k, 0, nm[k], sizeof(nm[k]));
		fill(d[k], 300, k);
		i[k] = rq_write(&R, nm[k], 0, d[k], 300, NULL, 0x10u + k);
	}
	(void)rig_settle(&R);
	for (k = 0; k < 3; k++)
		WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i[k]));
	WRT_CHECK(rq_at(&R, i[0])->zoff == 0u && rq_at(&R, i[1])->zoff == 304u && rq_at(&R, i[2])->zoff == 608u && rq_at(&R, i[1])->zlen == 304u && R.o.zused == 912u);
	/* the one in the middle is answered (OSD 1 comes back and is cut once): its hole is the first fit for a smaller copy, a bigger one goes behind */
	sim_osd_faults(R.w.osd[1])->silent = 0;
	sim_osd_restart(R.w.osd[1]);
	rig_tick(&R, 2300);
	WRT_CHECK(R.o.n_zombies_done == 1u && R.o.zused == 608u && (rq_at(&R, i[1])->flags & WRI_OPF_ZOMBIE) == 0);
	(void)name_on_osd(0, 1, ne, sizeof(ne));
	(void)name_on_osd(0, 2, nf, sizeof(nf));
	fill(e, sizeof(e), 8);
	fill(f, sizeof(f), 9);
	x = rq_write(&R, ne, 0, e, sizeof(e), NULL, 0x20);
	y = rq_write(&R, nf, 0, f, sizeof(f), NULL, 0x21);
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, x)->state == WRI_OP_SENT && rq_at(&R, y)->state == WRI_OP_SENT);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, y)); /* 400 bytes do not fit the 304 byte hole: behind the last zombie */
	WRT_CHECK(rq_at(&R, y)->zoff == 912u && rq_at(&R, y)->zlen == 400u);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, x)); /* 250 bytes (256 with the padding) fit the hole */
	WRT_CHECK(rq_at(&R, x)->zoff == 304u && rq_at(&R, x)->zlen == 256u && R.o.zused == 608u + 256u + 400u && R.o.zmax >= R.o.zused);
	/* blocks never overlap */
	{
		uint32_t a, b;
		uint32_t z[4] = {i[0], i[2], x, y};

		for (a = 0; a < 4; a++)
			for (b = a + 1u; b < 4; b++) {
				const wri_osd_op *p = rq_at(&R, z[a]), *q = rq_at(&R, z[b]);

				WRT_CHECK(p->zoff + p->zlen <= q->zoff || q->zoff + q->zlen <= p->zoff);
			}
	}
	rig_close(&R);
}

static void test_tx_queue_references_data(void)
{
	uint8_t data[1000], keep[1000], back[1000], warm[16];
	uint32_t i, w, s, other;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 5);
	memcpy(keep, data, sizeof(data));
	w = rq_write(&R, "txq.warm", 0, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	s = live_sess(&R);
	R.w.tx_hold = 1; /* the host holds what it was given: the queue points into the owner's buffer */
	i = rq_write(&R, "txq.obj", 0, data, sizeof(data), NULL, 0x31);
	other = rq_read(&R, "txq.other", 0, 8, warm, 0x32);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && !wri_osd_sess_tx_idle(&R.o.sess, s) && rig_nrec(&R, 0) == 1u);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK(wri_osdc_deadline(&R.o) == rig_now(&R)); /* the reset left the session's other op without a connection: the engine asks to run at once */
	/* the session was reset first (orderly), which dropped the queue; the copy was made from the buffer while it was still valid */
	WRT_CHECK((op->flags & WRI_OPF_ZOMBIE) != 0 && (op->flags & WRI_OPF_MIDRX) != 0 && R.o.sess.s[s].state != WRI_OS_READY && R.o.sess.n_resets == 0u);
	WRT_CHECK(op->data != data && memcmp(op->data, keep, sizeof(keep)) == 0);
	memset(data, 0xEE, sizeof(data));
	R.w.tx_hold = 0;
	rig_tick(&R, 100);
	WRT_CHECK(rig_store_read(&R, "txq.obj", 0, back, sizeof(back)) == 1 && memcmp(back, keep, sizeof(keep)) == 0);
	WRT_CHECK(R.o.n_zombies_done == 1u && rq_done(&R, other) && rq_at(&R, other)->status == WR_E_OSD_NOENT && rq_at(&R, other)->retry_attempt == 1);
	WRT_CHECK(rig_take(&R, other) == WR_E_OSD_NOENT && rig_idle(&R) && sim_osd_n_violations(R.w.osd[0]) == 0u);
	rig_close(&R);
}

static void test_zombie_ends_with_the_pool(void)
{
	uint8_t data[64];
	uint32_t i, pass;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(data, sizeof(data), 4);
	i = rq_write(&R, "zp", 0, data, sizeof(data), NULL, 0x71);
	(void)rig_settle(&R);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	/* a zombie is never failed by the stale-map rule, however long the map is silent */
	R.m.prim[mw_pg(&R.m, "zp")] = -1;
	R.m.epoch = 11;
	for (pass = 0; pass < 4; pass++)
		rig_tick(&R, 60000);
	WRT_CHECK(R.o.n_zombies == 1u && R.o.n_zombies_done == 0u && rq_at(&R, i)->state == WRI_OP_HOMELESS && R.o.zused == 64u && R.o.n_failed == 0u);
	/* the pool is deleted: nothing can answer it, so it ends, quietly */
	R.m.pool[0].present = 0;
	R.m.epoch = 12;
	(void)rig_settle(&R);
	WRT_CHECK(R.o.n_zombies_done == 1u && R.o.zused == 0u && wri_osdc_pop_done(&R.o) == WRI_NIL && rig_idle(&R));
	rig_close(&R);
}

static void test_cancel_arguments(void)
{
	uint8_t buf[16];
	uint32_t i;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_cancel(&R.o, 9999));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osdc_cancel(NULL, 0));
	WRT_CHECK_STATUS(WR_E_STATE, wri_osdc_cancel(&R.o, 0)); /* free */
	i = wri_osdc_alloc(&R.o, 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_osdc_cancel(&R.o, i)); /* allocated, never submitted: the owner just releases it */
	wri_osdc_release(&R.o, i);
	i = rq_read(&R, "x", 0, 16, buf, 0);
	WRT_CHECK(rig_until_done(&R, i, 1000));
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i)); /* a finished op: nothing to cancel, its completion stands */
	WRT_CHECK(rq_at(&R, i)->status == WR_E_OSD_NOENT && rig_take(&R, i) == WR_E_OSD_NOENT && rig_idle(&R));
	rig_close(&R);
}


/* A name whose PG is served by `osd` in the map where PG k is on OSD (k & 1). */
static const char *name_for(unsigned osd, const char *prefix, char *buf, size_t n)
{
	unsigned k;

	for (k = 0; k < 1000; k++) {
		snprintf(buf, n, "%s%u", prefix, k);
		if ((mw_hash(buf, strlen(buf)) & 1u) == osd)
			break;
	}
	return buf;
}

static void tweak_odd_even(rig *r)
{
	unsigned k;

	for (k = 0; k < MW_PG_MAX; k++)
		r->m.prim[k] = (int)(k & 1u);
}

/* The op has left its session (no primary any more) while the reply of its transmission is still arriving into its buffer: the cancel must stop THAT connection. */
static void test_read_moved_mid_reply(void)
{
	uint8_t data[4096], got[4096], sentinel[4096], warm[8];
	char nm[24];
	uint32_t i, w, s0, pg;
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_odd_even) != 0) {
		WRT_CHECK(0);
		return;
	}
	(void)name_for(0, "mvr.", nm, sizeof(nm));
	fill(data, sizeof(data), 3);
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, nm, 0, data, sizeof(data)));
	w = rq_read(&R, nm, 0, 8, warm, 0); /* the session to OSD 0 first */
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	pg = mw_pg(&R.m, nm);
	memset(got, 0xAA, sizeof(got));
	i = rq_read(&R, nm, 0, sizeof(got), got, 0);
	R.w.rx_budget_on = 1;
	R.w.rx_budget = 800;
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	s0 = op->sess;
	WRT_CHECK(op->state == WRI_OP_SENT && R.o.sess.s[s0].rx_tid == op->tid && R.o.sess.s[s0].osd == 0);
	R.m.unmappable[pg] = 1; /* the PG has no primary: the op leaves the session (it is not reset) while OSD 0's reply is half received */
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_HOMELESS && op->sess == WRI_NIL && R.o.sess.s[s0].rx_tid == op->tid && R.o.sess.s[s0].state == WRI_OS_READY);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK(R.o.sess.s[s0].state != WRI_OS_READY && (op->flags & WRI_OPF_MIDRX) != 0); /* the old connection is the one that was stopped */
	memset(got, 0xAA, sizeof(got));
	memset(sentinel, 0xAA, sizeof(sentinel));
	R.w.rx_budget_on = 0;
	(void)rig_settle(&R);
	rig_tick(&R, 100);
	WRT_CHECK(memcmp(got, sentinel, sizeof(got)) == 0);
	expect_cancelled(i);
	WRT_CHECK(rig_idle(&R));
	rig_close(&R);
}

/* The write was sent to one OSD, moved to another and both transmit queues held its data (the host has consumed nothing): the first is reset when the op moves, the second before the copy. */
static void test_write_data_in_two_queues(void)
{
	uint8_t data[1000], keep[1000], back[1000], warm[16];
	char nm[24], other[24];
	uint32_t i, w, pg;
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_odd_even) != 0) {
		WRT_CHECK(0);
		return;
	}
	(void)name_for(0, "tq.", nm, sizeof(nm));
	(void)name_for(1, "tqo.", other, sizeof(other));
	fill(data, sizeof(data), 5);
	memcpy(keep, data, sizeof(data));
	w = rq_write(&R, other, 0, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	w = rq_write(&R, nm, 1000, warm, 16, NULL, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	pg = mw_pg(&R.m, nm);
	R.w.tx_hold = 1;
	i = rq_write(&R, nm, 0, data, sizeof(data), NULL, 0x31);
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 0 && rig_nrec(&R, 0) == 1u);
	R.m.prim[pg] = 1;
	R.m.epoch = 11;
	(void)rig_settle(&R);
	WRT_CHECK(op->state == WRI_OP_SENT && op->osd == 1 && op->tx_mask == 3u);
	/* the connection the op left was closed when it went to the other one (its queue pointed into the buffer); the new one holds it now */
	WRT_CHECK(R.o.n_quiesced == 1u && R.o.sess.s[1u - op->sess].state != WRI_OS_READY && !wri_osd_sess_tx_idle(&R.o.sess, op->sess));
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK((op->flags & WRI_OPF_ZOMBIE) != 0 && R.o.sess.n_resets == 0u);
	WRT_CHECK(R.o.sess.s[0].state != WRI_OS_READY && R.o.sess.s[1].state != WRI_OS_READY); /* neither connection may deliver the owner's bytes any more */
	memset(data, 0xEE, sizeof(data));
	R.w.tx_hold = 0;
	rig_tick(&R, 200);
	WRT_CHECK(rig_nrec(&R, 0) == 1u && rig_nrec(&R, 1) == 2u); /* only the warm one at OSD 0; the zombie went to OSD 1, once, from its copy */
	WRT_CHECK(rig_store_read(&R, nm, 0, back, sizeof(back)) == 1 && memcmp(back, keep, sizeof(keep)) == 0);
	WRT_CHECK(R.o.n_zombies_done == 1u && rig_idle(&R) && sim_osd_n_violations(R.w.osd[0]) == 0u && sim_osd_n_violations(R.w.osd[1]) == 0u);
	rig_close(&R);
}

/* A write without data (a discard) that was sent: the zombie keeps its snapshot context and nothing else; it still goes out with that context. */
static void test_zombie_without_data(void)
{
	uint64_t ids[2] = {9, 4};
	wri_snapc sc;
	uint32_t i;
	wri_osd_op *op;
	const sim_osd_rec *rec;

	if (rig_open(&R, 1, 2, tweak_silent) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(&sc, 0, sizeof(sc));
	sc.seq = 9, sc.n = 2, sc.cap = 2, sc.snaps = ids;
	i = rq_plain(&R, "zomb.trunc", WRI_OSD_OP_TRUNCATE, 0, 0, 0x67);
	rq_at(&R, i)->snapc = &sc;
	(void)rig_settle(&R);
	op = rq_at(&R, i);
	WRT_CHECK(op->state == WRI_OP_SENT && rig_nrec(&R, 0) == 1u);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, i));
	WRT_CHECK((op->flags & WRI_OPF_ZOMBIE) != 0 && op->data == NULL && op->data_len == 0u && op->zlen == 24u + 16u && R.o.zused == op->zlen);
	WRT_CHECK((const uint8_t *)op->snapc >= R.o.zbuf && op->snapc != &sc && op->snapc->n == 2u && op->snapc->snaps[0] == 9u && op->snapc->snaps[1] == 4u);
	ids[0] = 99, ids[1] = 98, sc.seq = 99; /* the owner's context moves on */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_restart(R.w.osd[0]);
	(void)rig_settle(&R);
	rig_tick(&R, 2100);
	WRT_CHECK(rig_nrec(&R, 0) == 2u);
	rec = rig_rec(&R, 0, 1);
	WRT_CHECK(rec->snap_seq == 9u && rec->n_snaps == 2u && rec->data_len == 0u && rec->executed);
	WRT_CHECK(R.o.n_zombies_done == 1u && R.o.zused == 0u && rig_idle(&R));
	rig_close(&R);
}

int main(void)
{
	test_read_every_state();
	test_late_reply_discarded();
	test_read_mid_reply();
	test_write_never_sent_is_dropped();
	test_write_zombie();
	test_zombie_after_loss_and_eagain();
	test_zombie_does_not_fit();
	test_first_fit();
	test_tx_queue_references_data();
	test_zombie_ends_with_the_pool();
	test_read_moved_mid_reply();
	test_write_data_in_two_queues();
	test_zombie_without_data();
	test_cancel_arguments();
	return wrt_finish();
}
