/* SPDX-License-Identifier: MIT */
/*
 * test_osd_req_budget.c - the engine at the edges of its budgets, with real sessions: inflight_bytes_max to the byte, a table of four slots cycled hundreds of
 * times (tids, the done ring, the free list), the control reserve that keeps an open alive while data ops fill the table, the per-call send budget, a session
 * pool smaller than the cluster (eviction, ops waiting for a session), a full transmit queue (QUEUED, tid order on the wire), and a randomised storm of
 * submits, cancels, map moves, OSD restarts and clock steps that ends with every op completed once, every zombie answered and every byte accounted for.
 */
#include "osd_req_rig.h"

static rig R;

static void fill(uint8_t *p, size_t n, unsigned seed)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (uint8_t)(seed * 37u + i * 3u);
}

/* ---- bytes on the wire -------------------------------------------------------------------------------------------------------------- */

static void tweak_1000(rig *r)
{
	r->w.e.x.cfg.inflight_bytes_max = 1000;
	r->w.ocfg[0].fault.silent = 1; /* nothing completes while the test counts */
}

static void test_inflight_bytes(void)
{
	uint8_t d[2000], got[2000];
	uint32_t a, b, c, i;
	wri_osd_op *op;

	if (rig_open(&R, 1, 2, tweak_1000) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(d, sizeof(d), 1);
	a = rq_write(&R, "b.a", 0, d, 600, NULL, 0);
	WRT_CHECK(a != WRI_NIL && R.o.inflight_bytes == 600u);
	/* exactly the budget: fits */
	b = rq_write(&R, "b.b", 0, d, 400, NULL, 0);
	WRT_CHECK(b != WRI_NIL && R.o.inflight_bytes == 1000u);
	/* one more byte: BUSY, and the slot stays the owner's */
	i = rq_alloc(&R, WRI_OPK_WRITE, "b.c", 0, 0);
	op = rq_at(&R, i);
	op->ops[0].code = WRI_OSD_OP_WRITE;
	op->ops[0].len = op->ops[0].in_len = 1;
	op->data = d;
	op->data_len = 1;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osdc_submit(&R.o, i));
	WRT_CHECK(op->state == WRI_OP_FREE && (op->flags & WRI_OPF_ALLOC) != 0 && R.o.n_inflight == 2u && R.o.inflight_bytes == 1000u && op->tid == 0u);
	/* a read counts its output room */
	wri_osdc_release(&R.o, i);
	i = rq_alloc(&R, WRI_OPK_READ, "b.r", 0, 0);
	op = rq_at(&R, i);
	op->ops[0].code = WRI_OSD_OP_READ;
	op->ops[0].len = 1;
	op->out = got;
	op->out_cap = 1;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osdc_submit(&R.o, i));
	/* one op that could never fit, whatever else is in flight */
	op->ops[0].len = 1001;
	op->out_cap = 1001;
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_osdc_submit(&R.o, i));
	wri_osdc_release(&R.o, i);
	/* the first op leaves (cancelled: it never completed on the wire, so it is a zombie and keeps its bytes) ... */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, a)->state == WRI_OP_SENT);
	WRT_CHECK_STATUS(WR_OK, wri_osdc_cancel(&R.o, a));
	WRT_CHECK(R.o.inflight_bytes == 1000u); /* a zombie is still on the wire */
	/* ... the second one is a read that completes: its bytes come back */
	sim_osd_faults(R.w.osd[0])->silent = 0;
	sim_osd_restart(R.w.osd[0]);
	rig_tick(&R, 2300);
	WRT_CHECK(rq_done(&R, b) && R.o.inflight_bytes == 0u && R.o.n_zombies_done == 1u);
	WRT_CHECK(rig_take(&R, b) == WR_OK && rig_idle(&R));
	/* read plus write bytes of one op add up (a CALL with input and output) */
	i = rq_alloc(&R, WRI_OPK_READ, "b.call", 0, 0);
	op = rq_at(&R, i);
	op->ops[0].code = WRI_OSD_OP_CALL;
	op->ops[0].in_len = 9;
	op->ops[0].cls_class_len = 3;
	op->ops[0].cls_method_len = 6;
	op->data = (const uint8_t *)"rbdget_id";
	op->data_len = 9;
	op->out = got;
	op->out_cap = 100;
	c = rq_submit(&R, i);
	WRT_CHECK(c == i && R.o.inflight_bytes == 109u);
	(void)rig_until_done(&R, c, 1000);
	WRT_CHECK(rq_done(&R, c) && R.o.inflight_bytes == 0u && rig_take(&R, c) == WR_E_OSD_NOENT);
	rig_close(&R);
}

/* ---- a table of four slots, cycled -------------------------------------------------------------------------------------------------------- */

static void tweak_four(rig *r)
{
	r->w.e.x.cfg.max_ops = 4;
	r->w.e.x.cfg.ctl_ops = 1;
}

static void test_tiny_table(void)
{
	enum { TOTAL = 300 };
	uint8_t d[64];
	uint32_t submitted = 0, completed = 0, k;
	uint64_t last_tid = 0;
	unsigned rounds = 0;

	if (rig_open(&R, 1, 2, tweak_four) != 0) {
		WRT_CHECK(0);
		return;
	}
	fill(d, sizeof(d), 2);
	while (completed < (uint32_t)TOTAL && rounds++ < 5000) {
		uint32_t i;

		/* fill the table (three data slots), then let the engine run and drain */
		while (submitted < (uint32_t)TOTAL) {
			char nm[16];

			snprintf(nm, sizeof(nm), "tiny.%u", submitted);
			i = wri_osdc_alloc(&R.o, 0);
			if (i == WRI_NIL)
				break;
			{
				wri_osd_op *op = rq_at(&R, i);

				op->kind = WRI_OPK_WRITE;
				op->oid_len = (uint8_t)strlen(nm);
				memcpy(op->oid, nm, strlen(nm));
				op->n_ops = 1;
				op->ops[0].code = WRI_OSD_OP_WRITE;
				op->ops[0].len = op->ops[0].in_len = sizeof(d);
				op->data = d;
				op->data_len = sizeof(d);
				op->owner = submitted;
			}
			WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, i));
			WRT_CHECK(rq_at(&R, i)->tid > last_tid);
			last_tid = rq_at(&R, i)->tid;
			submitted++;
		}
		WRT_CHECK(R.o.n_inflight <= 3u && R.o.n_free + R.o.n_inflight + R.o.done_len == 4u);
		(void)rig_settle(&R);
		while ((i = wri_osdc_pop_done(&R.o)) != WRI_NIL) {
			WRT_CHECK(rq_at(&R, i)->status == WR_OK && rq_at(&R, i)->owner == completed); /* completion order = submission order on one OSD */
			wri_osdc_release(&R.o, i);
			completed++;
		}
	}
	WRT_CHECK(completed == (uint32_t)TOTAL && submitted == (uint32_t)TOTAL && rig_idle(&R) && R.o.next_tid == (uint64_t)TOTAL + 1u && R.o.hiwater == 3u);
	/* every object was written */
	for (k = 0; k < (uint32_t)TOTAL; k += 37) {
		char nm[16];
		uint8_t back[64];

		snprintf(nm, sizeof(nm), "tiny.%u", k);
		WRT_CHECK(rig_store_read(&R, nm, 0, back, sizeof(back)) == 1 && memcmp(back, d, sizeof(d)) == 0);
	}
	rig_close(&R);
}

/* ---- the control reserve --------------------------------------------------------------------------------------------------------------- */

static void tweak_reserve(rig *r)
{
	r->w.e.x.cfg.max_ops = 4;
	r->w.e.x.cfg.ctl_ops = 1;
	r->w.ocfg[0].fault.silent = 1; /* OSD 0 never answers: the data ops pile up */
}

static void test_control_reserve(void)
{
	uint8_t buf[8], in[9], out[64];
	uint32_t i[3], c, k;
	char nm_data[3][16], nm_ctl[16];
	wri_osd_op *op;

	if (rig_open(&R, 2, 2, tweak_reserve) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(out, 1, sizeof(out));
	/* two kinds of names: PGs of OSD 0 (silent, data) and of OSD 1 (control) */
	for (k = 0; k < MW_PG_MAX; k++)
		R.m.prim[k] = (k & 1u) ? 1 : 0;
	for (k = 0; k < 3; k++) {
		unsigned j;

		for (j = 0; j < 1000; j++) {
			snprintf(nm_data[k], sizeof(nm_data[k]), "rs.d%u.%u", k, j);
			if ((mw_hash(nm_data[k], strlen(nm_data[k])) & 1u) == 0u)
				break;
		}
	}
	for (k = 0; k < 1000; k++) {
		snprintf(nm_ctl, sizeof(nm_ctl), "rs.c%u", k);
		if ((mw_hash(nm_ctl, strlen(nm_ctl)) & 1u) == 1u)
			break;
	}
	for (k = 0; k < 3; k++)
		i[k] = rq_read(&R, nm_data[k], 0, 8, buf, 0);
	WRT_CHECK(i[0] != WRI_NIL && i[1] != WRI_NIL && i[2] != WRI_NIL);
	WRT_CHECK(rq_read(&R, nm_data[0], 0, 8, buf, 0) == WRI_NIL); /* the fourth data op: the table has only the reserve left */
	(void)rig_settle(&R);
	WRT_CHECK(rq_at(&R, i[0])->state == WRI_OP_SENT && wri_osdc_alloc(&R.o, 0) == WRI_NIL);
	/* the open's control read still gets through, to the OSD that answers */
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, nm_ctl, 0, out, 64));
	c = wri_osdc_alloc(&R.o, 1);
	WRT_CHECK(c != WRI_NIL);
	op = rq_at(&R, c);
	op->kind = WRI_OPK_READ;
	op->oid_len = (uint8_t)strlen(nm_ctl);
	memcpy(op->oid, nm_ctl, strlen(nm_ctl));
	op->n_ops = 1;
	op->ops[0].code = WRI_OSD_OP_READ;
	op->ops[0].len = 8;
	op->out = in;
	op->out_cap = 8;
	WRT_CHECK_STATUS(WR_OK, wri_osdc_submit(&R.o, c));
	WRT_CHECK(rig_until_done(&R, c, 1000) && op->status == WR_OK && (op->flags & WRI_OPF_CONTROL) != 0);
	WRT_CHECK(rig_take(&R, c) == WR_OK && R.o.n_free == 1u && wri_osdc_alloc(&R.o, 0) == WRI_NIL); /* the reserve is still the reserve */
	rig_close(&R);
}

/* ---- the send budget of one call ------------------------------------------------------------------------------------------------------- */

static void test_step_budget(void)
{
	enum { N = 6 };
	uint8_t warm[8], buf[N][8];
	uint32_t i[N], k, w, before;
	int more;

	if (rig_open(&R, 1, 2, NULL) != 0) {
		WRT_CHECK(0);
		return;
	}
	memset(warm, 7, sizeof(warm));
	WRT_CHECK_STATUS(WR_OK, sim_store_write(R.w.store, W_POOL, "sb.warm", 0, warm, sizeof(warm)));
	w = rq_read(&R, "sb.warm", 0, 8, warm, 0);
	WRT_CHECK(w != WRI_NIL && rig_until_done(&R, w, 1000) && rig_take(&R, w) == WR_OK);
	before = rig_nrec(&R, 0);
	for (k = 0; k < N; k++) {
		char nm[16];

		snprintf(nm, sizeof(nm), "sb.%u", k);
		i[k] = rq_read(&R, nm, 0, 8, buf[k], 0);
	}
	/* budget 0 sends nothing and says there is more */
	more = wri_osdc_step(&R.o, 0);
	(void)w_pump(&R.w);
	WRT_CHECK(more == 1 && rig_nrec(&R, 0) == before);
	for (k = 0; k < (uint32_t)N; k++)
		WRT_CHECK(rq_at(&R, i[k])->state == WRI_OP_QUEUED);
	/* two per call, in tid order, until the table is empty */
	more = wri_osdc_step(&R.o, 2);
	(void)w_pump(&R.w);
	WRT_CHECK(more == 1 && rig_nrec(&R, 0) == before + 2u && rig_rec(&R, 0, before)->tid == rq_at(&R, i[0])->tid && rig_rec(&R, 0, before + 1u)->tid == rq_at(&R, i[1])->tid);
	more = wri_osdc_step(&R.o, 2);
	(void)w_pump(&R.w);
	WRT_CHECK(more == 1 && rig_nrec(&R, 0) == before + 4u);
	more = wri_osdc_step(&R.o, 2);
	(void)w_pump(&R.w);
	WRT_CHECK(more == 0 && rig_nrec(&R, 0) == before + 6u); /* the last two fit exactly: nothing is left */
	for (k = 0; k < (uint32_t)N; k++)
		WRT_CHECK(rig_rec(&R, 0, before + k)->tid == rq_at(&R, i[k])->tid);
	(void)rig_settle(&R);
	for (k = 0; k < (uint32_t)N; k++)
		WRT_CHECK(rig_take(&R, i[k]) == WR_E_OSD_NOENT);
	WRT_CHECK(rig_idle(&R));
	rig_close(&R);
}

/* ---- fewer sessions than OSDs ------------------------------------------------------------------------------------------------------------ */

static void tweak_two_osds(rig *r)
{
	unsigned k;

	for (k = 0; k < MW_PG_MAX; k++)
		r->m.prim[k] = (int)(k & 1u);
}

static void test_session_pool_pressure(void)
{
	uint8_t d[64];
	enum { N = 20 };
	uint32_t i[N], k;
	char nm[N][16];

	if (rig_open(&R, 2, 1, tweak_two_osds) != 0) { /* one session for two OSDs */
		WRT_CHECK(0);
		return;
	}
	fill(d, sizeof(d), 3);
	for (k = 0; k < (uint32_t)N; k++) {
		snprintf(nm[k], sizeof(nm[k]), "sp.%u", k);
		i[k] = rq_write(&R, nm[k], 0, d, sizeof(d), NULL, 0);
	}
	(void)rig_settle(&R);
	for (k = 0; k < (uint32_t)N; k++) {
		if (!rq_done(&R, i[k]))
			(void)rig_until_done(&R, i[k], 5000);
		WRT_CHECK(rq_done(&R, i[k]) && rq_at(&R, i[k])->status == WR_OK && rq_at(&R, i[k])->retry_attempt == 0);
	}
	WRT_CHECK(R.o.sess.hiwater == 1u && R.o.sess.n_evicted >= 1u && R.w.live_max <= 2u); /* never more than one session: the old one is closed to make room */
	WRT_CHECK(R.o.n_resent == 0u && R.o.n_timeouts == 0u);
	WRT_CHECK(rig_drain(&R) == (unsigned)N && rig_idle(&R)); /* the order of completion is not the order of submission here: the OSDs answer in turns */
	rig_close(&R);
}

/* ---- a full transmit queue: tid order on every connection ------------------------------------------------------------------------------------ */

static void tweak_big_table(rig *r)
{
	r->w.e.x.cfg.max_ops = 128;
}

static void test_tid_order_under_busy(void)
{
	enum { N = 60 };
	uint8_t d[512], got[N][8];
	uint32_t i, k, osd, j;
	char nm[N][16];
	uint32_t seed = 12345;

	if (rig_open(&R, 3, 3, tweak_big_table) != 0) {
		WRT_CHECK(0);
		return;
	}
	for (k = 0; k < MW_PG_MAX; k++)
		R.m.prim[k] = (int)(k % 3u);
	fill(d, sizeof(d), 1);
	for (k = 0; k < 20; k++) { /* sessions to every OSD first */
		char wn[16];

		snprintf(wn, sizeof(wn), "to.warm%u", k);
		(void)rq_write(&R, wn, 0, d, 8, NULL, 0);
	}
	(void)rig_settle(&R);
	(void)rig_drain(&R);
	for (k = 0; k < (uint32_t)N; k++) {
		snprintf(nm[k], sizeof(nm[k]), "to.%u", k);
		seed = seed * 1103515245u + 12345u;
		R.w.tx_hold = (seed >> 16) % 3u == 0u; /* the host consumes in bursts */
		if ((seed >> 20) % 2u == 0u)
			i = rq_write(&R, nm[k], 0, d, 200u + (seed >> 8) % 300u, NULL, 0);
		else
			i = rq_read(&R, nm[k], 0, 8, got[k], 0);
		WRT_CHECK(i != WRI_NIL);
		(void)rig_settle(&R);
	}
	R.w.tx_hold = 0;
	for (j = 0; j < 20 && R.o.n_inflight != 0u; j++)
		rig_tick(&R, 20);
	WRT_CHECK(R.o.n_inflight == 0u && R.o.n_resent == 0u && R.o.n_timeouts == 0u);
	/* on every connection of every OSD the tids that were sent are strictly ascending, and every op was sent once */
	for (osd = 0; osd < 3; osd++) {
		uint32_t n = rig_nrec(&R, osd);
		uint64_t last[SIM_OSD_MAX_CONNS];

		memset(last, 0, sizeof(last));
		for (j = 0; j < n; j++) {
			const sim_osd_rec *rec = rig_rec(&R, osd, j);

			WRT_CHECK(rec->conn < SIM_OSD_MAX_CONNS && rec->tid > last[rec->conn] && rec->retry_attempt == 0u);
			last[rec->conn] = rec->tid;
		}
	}
	WRT_CHECK(rig_nrec(&R, 0) + rig_nrec(&R, 1) + rig_nrec(&R, 2) == (uint32_t)N + 20u);
	(void)rig_drain(&R);
	WRT_CHECK(rig_idle(&R) && sim_osd_n_violations(R.w.osd[0]) == 0u);
	rig_close(&R);
}

/* ---- a storm ----------------------------------------------------------------------------------------------------------------------------- */

static uint32_t lcg(uint32_t *s)
{
	*s = *s * 1664525u + 1013904223u;
	return *s >> 8;
}

typedef struct stormop {
	uint32_t slot;
	int is_write, cancelled, popped, zombie;
	char nm[24];
	uint8_t data[96], rbuf[8];
	int ok;
} stormop;

static void storm(uint32_t seed0)
{
	enum { MAXOPS = 400 };
	static stormop ops[MAXOPS];
	uint32_t seed = seed0, n = 0, step, k;
	uint8_t back[96];
	unsigned n_ok = 0;

	if (rig_open(&R, 3, 2, NULL) != 0) { /* two sessions for three OSDs: eviction in the mix */
		WRT_CHECK(0);
		return;
	}
	for (k = 0; k < MW_PG_MAX; k++)
		R.m.prim[k] = (int)(k % 3u);
	memset(ops, 0, sizeof(ops));
	for (step = 0; step < 900; step++) {
		uint32_t r = lcg(&seed) % 100u;

		if (r < 38u && n < (uint32_t)MAXOPS) { /* submit a write or a read */
			stormop *o = &ops[n];
			uint32_t i;

			snprintf(o->nm, sizeof(o->nm), "st.%u.%u", seed0, n);
			o->is_write = (lcg(&seed) & 3u) != 0u;
			fill(o->data, sizeof(o->data), n);
			if (o->is_write)
				i = rq_write(&R, o->nm, 0, o->data, sizeof(o->data), NULL, 0x1000u + n);
			else
				i = rq_read(&R, o->nm, 0, sizeof(o->rbuf), o->rbuf, 0x1000u + n);
			if (i != WRI_NIL) { /* WRI_NIL: the table is full, which is a fine answer */
				o->slot = i;
				n++;
			}
		} else if (r < 52u && n != 0) { /* cancel something that is still live */
			stormop *o = &ops[lcg(&seed) % n];
			wri_osd_op *op = rq_at(&R, o->slot);

			if (!o->popped && !o->cancelled && op->tid != 0 && op->state != WRI_OP_DONE && op->state != WRI_OP_FREE && (op->flags & WRI_OPF_ZOMBIE) == 0) {
				wr_status st = wri_osdc_cancel(&R.o, o->slot);

				if (st == WR_OK) {
					o->cancelled = 1;
					o->zombie = (op->flags & WRI_OPF_ZOMBIE) != 0;
					if (!o->zombie)
						WRT_CHECK(op->state == WRI_OP_DONE && op->status == WR_E_CANCELLED);
				}
			}
		} else if (r < 60u) { /* move a PG's primary, the epoch always forward, sometimes by more than one */
			R.m.prim[lcg(&seed) % 8u] = (int)(lcg(&seed) % 3u);
			R.m.epoch += 1u + (lcg(&seed) % 4u == 0u ? 2u : 0u);
		} else if (r < 64u) { /* an OSD restarts: its connections are cut */
			sim_osd_restart(R.w.osd[lcg(&seed) % 3u]);
		} else if (r < 70u) { /* the cluster is unreachable for a while, or comes back */
			uint32_t o = lcg(&seed) % 3u;

			sim_osd_faults(R.w.osd[o])->silent = (uint8_t)!sim_osd_faults(R.w.osd[o])->silent;
		} else if (r < 74u) { /* a backoff of a whole PG on a live session ... */
			uint32_t s, pg = lcg(&seed) % 8u;
			uint8_t op = (lcg(&seed) & 1u) ? WRI_BACKOFF_BLOCK : WRI_BACKOFF_UNBLOCK;

			for (s = 0; s < R.o.sess.n; s++)
				if (R.o.sess.s[s].state == WRI_OS_READY && rig_srv(&R, s) != NULL)
					(void)sim_osd_send_backoff(rig_srv(&R, s), op, 900u + pg, W_POOL, pg, R.m.epoch, "", 0, SIM_OSD_BO_MAX, 0);
		} else {
			rig_tick(&R, (lcg(&seed) % 3u == 0u) ? 1700u : 100u);
		}
		(void)rig_settle(&R);
		/* invariants at every step: the accounting never goes negative or past the budgets, the done ring holds each op once */
		WRT_CHECK(R.o.n_inflight <= R.o.n_op && R.o.inflight_bytes <= R.w.e.x.cfg.inflight_bytes_max && R.o.zused <= R.o.zcap);
		WRT_CHECK(R.o.n_free + R.o.n_inflight + R.o.done_len == R.o.n_op && R.o.sess.hiwater <= 2u);
		/* drain completions as the owner would */
		for (;;) {
			uint32_t i = wri_osdc_pop_done(&R.o);
			uint32_t m;

			if (i == WRI_NIL)
				break;
			for (m = n; m != 0 && ops[m - 1u].slot != i; m--)
				;
			m = m != 0 ? m - 1u : n; /* the latest op of that slot: the slot of an older one was reused */
			WRT_CHECK(m < n && !ops[m].popped); /* completes once */
			if (m < n) {
				ops[m].popped = 1;
				ops[m].ok = rq_at(&R, i)->status == WR_OK;
				n_ok += (unsigned)ops[m].ok;
			}
			wri_osdc_release(&R.o, i);
		}
	}
	/* quiesce: every fault off, every PG back on a live OSD, time enough for every cool-down and deadline */
	for (k = 0; k < 3; k++)
		sim_osd_faults(R.w.osd[k])->silent = 0;
	for (k = 0; k < R.o.sess.n; k++)
		wri_osd_sess_reset(&R.o.sess, k, NULL); /* an orderly close forgets every backoff a storm left standing */
	R.m.epoch += 5;
	for (k = 0; k < 400 && (R.o.n_inflight != 0u || R.o.done_len != 0u); k++) {
		uint32_t i;

		rig_tick(&R, 500);
		while ((i = wri_osdc_pop_done(&R.o)) != WRI_NIL) {
			uint32_t m;

			for (m = n; m != 0 && ops[m - 1u].slot != i; m--)
				;
			m = m != 0 ? m - 1u : n; /* the latest op of that slot: the slot of an older one was reused */
			WRT_CHECK(m < n && !ops[m].popped);
			if (m < n) {
				ops[m].popped = 1;
				ops[m].ok = rq_at(&R, i)->status == WR_OK;
				n_ok += (unsigned)ops[m].ok;
			}
			wri_osdc_release(&R.o, i);
		}
	}
	/* everything ended: nothing live, no zombie, no byte accounted, the free list whole */
	WRT_CHECK(rig_idle(&R) && R.o.n_zombies == R.o.n_zombies_done);
	/* ... and the store agrees with the history: a write that completed OK, or that became a zombie (sent before it was given up), was applied; one that
	 * was dropped before it was ever sent was not; a write that failed was not applied (the only failures here are the stale-map ones, for writes that
	 * never left) */
	for (k = 0; k < n; k++) {
		stormop *o = &ops[k];
		int has;

		if (!o->is_write)
			continue;
		has = rig_store_read(&R, o->nm, 0, back, sizeof(back)) == 1;
		WRT_CHECK(o->popped || o->zombie); /* every op ended one way or the other */
		if (o->zombie || o->ok)
			WRT_CHECK(has && memcmp(back, o->data, sizeof(back)) == 0);
		else if (o->cancelled)
			WRT_CHECK(!has); /* dropped before it was ever sent */
		if (has)
			WRT_CHECK(memcmp(back, o->data, sizeof(back)) == 0);
	}
	WRT_CHECK(n_ok > 5u && sim_osd_n_violations(R.w.osd[0]) == 0u && sim_osd_n_violations(R.w.osd[1]) == 0u && sim_osd_n_violations(R.w.osd[2]) == 0u);
	rig_close(&R);
}

static void test_storms(void)
{
	storm(1);
	storm(2);
	storm(3);
	storm(4);
}

int main(void)
{
	test_inflight_bytes();
	test_tiny_table();
	test_control_reserve();
	test_step_budget();
	test_session_pool_pressure();
	test_tid_order_under_busy();
	test_storms();
	return wrt_finish();
}
