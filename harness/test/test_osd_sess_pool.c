/* SPDX-License-Identifier: MIT */
/*
 * test_osd_sess_pool.c - the session table of core/src/osd/wri_osd_sess.c over a scripted engine link (design 21.1 to 21.3): memory plan and
 * init, acquire (existing session, address change, free / cool-down / LRU slots, BUSY), the gates (no ticket, no handshake slot, no
 * connection), cool-down growth, cap and reset, the idle reaper, send / inflight / reset / tx_idle, the feature check at READY, and a random
 * model run that holds the table's invariants (never more than osd_sessions connections, one entry per OSD, ...).
 */
#include <time.h>

#include "osd_sess_rig.h"

#define T0 100000u

static osr R;

static int fresh(unsigned n, unsigned fcap, unsigned bo)
{
	osr_free(&R);
	if (osr_init(&R, n, fcap, bo) != 0) {
		WRT_CHECK(0);
		return -1;
	}
	return 0;
}

/* The invariants of the table that no sequence may break. */
static void check_invariants(const osr *o)
{
	const wri_osd_sess_tab *t = &o->t;
	uint32_t i, j, live = 0;

	for (i = 0; i < t->n; i++) {
		const wri_osd_sess *a = &t->s[i];

		if (a->state == WRI_OS_OPENING || a->state == WRI_OS_READY) {
			live++;
			WRT_CHECK(a->conn_slot != WRI_OS_NOSLOT && a->conn_slot < o->f.n_slots);
			WRT_CHECK(a->osd >= 0);
		} else {
			WRT_CHECK(a->conn_slot == WRI_OS_NOSLOT);
			WRT_CHECK(a->n_inflight == 0 && a->n_backoff == 0 && a->rx_tid == 0);
		}
		WRT_CHECK(a->state != WRI_OS_CLOSING);
		if (a->state == WRI_OS_FREE)
			WRT_CHECK(a->osd == -1);
		for (j = i + 1u; j < t->n; j++) {
			const wri_osd_sess *b = &t->s[j];

			if (a->state != WRI_OS_FREE && b->state != WRI_OS_FREE)
				WRT_CHECK(a->osd != b->osd); /* one entry per OSD */
			if ((a->state == WRI_OS_OPENING || a->state == WRI_OS_READY) && (b->state == WRI_OS_OPENING || b->state == WRI_OS_READY))
				WRT_CHECK(a->conn_slot != b->conn_slot);
		}
	}
	WRT_CHECK(live <= t->n);
	WRT_CHECK(t->hiwater <= t->n);
}

/* ---- memory and init ----------------------------------------------------------------------------------------------------- */

static void test_mem_init(void)
{
	wr_config c;
	size_t need = 99, used;
	wri_ctx x;
	wri_arena a;
	uint8_t *raw;
	wri_osd_link l;
	wri_osd_sess_up u;
	osr o;
	fk f;
	orec r;
	unsigned n, fc, bo;

	memset(&c, 0, sizeof(c));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_mem(NULL, &need));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_mem(&c, NULL));
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_mem(&c, &need));
	WRT_CHECK(need == 0u); /* the OSD client is off */
	c.osd_sessions = 4;
	c.osd_front_cap = WRI_OSD_FRONT_MIN - 1u;
	c.backoff_slots = 8;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_mem(&c, &need));
	WRT_CHECK(need == 0u);
	c.osd_front_cap = WRI_OSD_FRONT_MIN;
	c.backoff_slots = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_mem(&c, &need));
	c.backoff_slots = 1;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_mem(&c, &need));
	WRT_CHECK(need > 4u * WRI_OSD_FRONT_MIN);

	/* the three profile sizes of the design (6 / 16 / 48 sessions, front 2048 / 4096 / 8192, 8 / 32 / 128 slots): the plan is what init takes */
	{
		static const unsigned prof[3][3] = {{6, 2048, 8}, {16, 4096, 32}, {48, 8192, 128}};
		unsigned k;

		for (k = 0; k < 3u; k++) {
			memset(&o, 0, sizeof(o));
			osr_cfg(&o.x, prof[k][0], prof[k][1], prof[k][2]);
			WRT_CHECK_STATUS(WR_OK, wri_osd_sess_mem(&o.x.cfg, &need));
			printf("sess mem: %u sessions, front %u, %u backoff slots: %zu bytes (%zu per session; sizeof sess %zu, backoff %zu)\n", prof[k][0],
			       prof[k][1], prof[k][2], need, need / prof[k][0], sizeof(wri_osd_sess), sizeof(wri_backoff));
			WRT_CHECK(need >= (size_t)prof[k][0] * (sizeof(wri_osd_sess) + prof[k][1] + (size_t)prof[k][2] * sizeof(wri_backoff)));
			WRT_CHECK(need <= (size_t)prof[k][0] * (sizeof(wri_osd_sess) + prof[k][1] + (size_t)prof[k][2] * sizeof(wri_backoff)) + 64u);
		}
	}

	/* exactness over random configurations, with a 64-aligned base: nothing less is enough and exactly this is taken */
	for (n = 1; n <= 9; n += 4) {
		for (fc = WRI_OSD_FRONT_MIN; fc <= 2999; fc += 997) {
			for (bo = 1; bo <= 33; bo += 16) {
				memset(&x, 0, sizeof(x));
				memset(&f, 0, sizeof(f));
				memset(&r, 0, sizeof(r));
				osr_cfg(&x, n, fc, bo);
				WRT_CHECK_STATUS(WR_OK, wri_osd_sess_mem(&x.cfg, &need));
				raw = (uint8_t *)calloc(1, need + 128u);
				WRT_CHECK(raw != NULL);
				if (raw == NULL)
					return;
				{
					uint8_t *base = (uint8_t *)(((uintptr_t)raw + 63u) & ~(uintptr_t)63u);
					wri_osd_sess_tab t;

					l = fk_link(&f);
					u = orec_up(&r);
					wri_arena_init(&a, base, need - 1u);
					WRT_CHECK_STATUS(WR_E_BUDGET, wri_osd_sess_init(&t, &x, &a, &l, &u));
					WRT_CHECK(t.s == NULL && t.n == 0u);
					wri_arena_init(&a, base, need);
					WRT_CHECK_STATUS(WR_OK, wri_osd_sess_init(&t, &x, &a, &l, &u));
					used = a.used;
					WRT_CHECK(used == need);
					WRT_CHECK(t.n == n);
					WRT_CHECK(t.s[n - 1u].front == t.s[0].front + (size_t)(n - 1u) * fc);
					WRT_CHECK(t.s[n - 1u].bo == t.s[0].bo + (size_t)(n - 1u) * bo);
					WRT_CHECK(t.s[0].tab == &t);
				}
				free(raw);
			}
		}
	}

	/* argument checks of init */
	WRT_CHECK(fresh(2, 640, 4) == 0);
	{
		wri_osd_sess_tab t;
		wri_arena a2;
		uint8_t buf[4096];
		wri_osd_link l2 = fk_link(&R.f);
		wri_osd_sess_up u2 = orec_up(&R.r);
		wri_osd_link bad = l2;

		wri_arena_init(&a2, buf, sizeof(buf));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(NULL, &R.x, &a2, &l2, &u2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, NULL, &a2, &l2, &u2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, NULL, &l2, &u2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, &a2, NULL, &u2));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, &a2, &l2, NULL));
		bad.open = NULL;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, &a2, &bad, &u2));
		bad = l2, bad.handshake_free = NULL;
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, &a2, &bad, &u2));
		bad = l2, bad.features = NULL; /* optional */
		{
			size_t need2 = 0;
			uint8_t *buf2;

			WRT_CHECK_STATUS(WR_OK, wri_osd_sess_mem(&R.x.cfg, &need2));
			buf2 = (uint8_t *)calloc(1, need2 + 64u);
			wri_arena_init(&a2, (uint8_t *)(((uintptr_t)buf2 + 63u) & ~(uintptr_t)63u), need2);
			WRT_CHECK_STATUS(WR_OK, wri_osd_sess_init(&t, &R.x, &a2, &bad, &u2));
			free(buf2);
		}
		{
			wri_osd_sess_up ub = u2;

			ub.reply = NULL;
			wri_arena_init(&a2, buf, sizeof(buf));
			WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &R.x, &a2, &l2, &ub));
		}
	}
	/* a table over a configuration with the OSD client off is refused */
	memset(&x, 0, sizeof(x));
	wr_config_profile_harness(&x.cfg);
	{
		wri_osd_sess_tab t;
		uint8_t buf[256];

		wri_arena_init(&a, buf, sizeof(buf));
		l = fk_link(&R.f);
		u = orec_up(&R.r);
		WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_init(&t, &x, &a, &l, &u));
	}
	/* accessors on bad input */
	WRT_CHECK(wri_osd_sess_at(NULL, 0) == NULL);
	WRT_CHECK(wri_osd_sess_at(&R.t, 2) == NULL);
	WRT_CHECK(wri_osd_sess_at(&R.t, 1) == &R.t.s[1]);
	WRT_CHECK(wri_osd_sess_index(&R.t, &R.t.s[1]) == 1u);
	WRT_CHECK(wri_osd_sess_index(&R.t, NULL) == WRI_NIL);
	WRT_CHECK(!wri_osd_sess_ready(&R.t, 0) && !wri_osd_sess_ready(&R.t, 99) && !wri_osd_sess_ready(NULL, 0));
}

/* ---- acquire ------------------------------------------------------------------------------------------------------------- */

static void test_acquire_basic(void)
{
	wr_addr a = osr_addr(3);
	uint32_t s = WRI_NIL, s2 = WRI_NIL;
	wri_eaddr want;

	WRT_CHECK(fresh(3, 1024, 4) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &a, &s));
	WRT_CHECK(s < 3u);
	WRT_CHECK(R.f.n_open == 1u);
	WRT_CHECK(R.t.s[s].state == WRI_OS_OPENING && R.t.s[s].osd == 3);
	WRT_CHECK(!wri_osd_sess_ready(&R.t, s));
	/* the connection was opened to the map's address, as the msgr2 type 2 entity, with this table's upper layer and the entry as context */
	wri_eaddr_from_wr(&want, &a, WRI_EADDR_TYPE_MSGR2);
	WRT_CHECK(wri_eaddr_equal(&want, &R.f.last_open_addr));
	WRT_CHECK(R.f.slot[R.f.last_open_slot].up == wri_osd_sess_upper());
	WRT_CHECK(R.f.slot[R.f.last_open_slot].up_ctx == &R.t.s[s]);
	WRT_CHECK(R.t.s[s].conn_slot == R.f.last_open_slot);
	/* again: the same session, no second connection */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &a, &s2));
	WRT_CHECK(s2 == s && R.f.n_open == 1u);
	osr_ready(&R, s, ALL_FEATURES);
	WRT_CHECK(wri_osd_sess_ready(&R.t, s));
	WRT_CHECK(R.r.n_ready == 1u && R.r.ready_s[0] == s);
	WRT_CHECK(R.t.s[s].features == ALL_FEATURES && R.t.s[s].msg_version == WRI_MOSDOP_VERSION);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &a, &s2));
	WRT_CHECK(s2 == s && R.f.n_open == 1u);
	/* a second OSD gets another session */
	a = osr_addr(4);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 4, &a, &s2));
	WRT_CHECK(s2 != s && R.f.n_open == 2u);
	/* bad arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(NULL, 4, &a, &s2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(&R.t, 4, NULL, &s2));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(&R.t, 4, &a, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(&R.t, -1, &a, &s2));
	a.family = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(&R.t, 4, &a, &s2));
	WRT_CHECK(R.f.n_open == 2u);
	check_invariants(&R);
}

static void test_gates(void)
{
	wr_addr a = osr_addr(1), b = osr_addr(2);
	uint32_t s = WRI_NIL, s2 = WRI_NIL;

	WRT_CHECK(fresh(2, 1024, 4) == 0);
	/* no OSD ticket: nothing is opened, nothing is touched */
	R.f.have_ticket = 0;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	WRT_CHECK(R.f.n_open == 0u && R.t.s[0].state == WRI_OS_FREE && R.t.s[1].state == WRI_OS_FREE);
	R.f.have_ticket = 1;
	/* no handshake slot */
	R.f.handshake_free = 0;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	WRT_CHECK(R.f.n_open == 0u);
	R.f.handshake_free = 1;
	/* no connection (the engine says BUSY): the entry stays free and the next try works */
	R.f.open_st = WR_E_BUSY;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	WRT_CHECK(R.t.s[0].state == WRI_OS_FREE && R.t.s[1].state == WRI_OS_FREE && R.t.hiwater == 0u && R.t.n_opened == 0u);
	R.f.open_st = WR_OK;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	/* another error of the link is passed on, the entry is not taken */
	R.f.open_st = WR_E_INVAL;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_acquire(&R.t, 2, &b, &s2));
	WRT_CHECK(R.t.s[1].state == WRI_OS_FREE || R.t.s[0].state == WRI_OS_FREE);
	R.f.open_st = WR_OK;
	/* an existing session needs neither gate */
	R.f.have_ticket = 0;
	R.f.handshake_free = 0;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s2));
	WRT_CHECK(s2 == s);
	/* the gates are checked before anything is evicted for a connection that cannot be opened now */
	R.f.have_ticket = 1;
	R.f.handshake_free = 1;
	osr_ready(&R, s, ALL_FEATURES);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &b, &s2)); /* second entry */
	osr_ready(&R, s2, ALL_FEATURES);
	{
		wr_addr c = osr_addr(9);
		uint32_t s3;
		unsigned closes = R.f.n_close;

		R.f.handshake_free = 0;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 9, &c, &s3));
		WRT_CHECK(R.f.n_close == closes && R.t.n_evicted == 0u); /* nobody was evicted */
		R.f.handshake_free = 1;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 9, &c, &s3));
		WRT_CHECK(R.t.n_evicted == 1u);
	}
	check_invariants(&R);
}

static void test_lru_and_busy(void)
{
	wr_addr a[6];
	uint32_t s[6], x = WRI_NIL, ev = WRI_NIL;
	unsigned i;

	WRT_CHECK(fresh(3, 1024, 4) == 0);
	for (i = 0; i < 6; i++)
		a[i] = osr_addr(i);
	for (i = 0; i < 3; i++) {
		R.x.now.mono_ms = T0 + 10u * i;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, (int32_t)i, &a[i], &s[i]));
	}
	/* all three are OPENING: none can be evicted */
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 3, &a[3], &x));
	WRT_CHECK(R.f.n_open == 3u && R.t.n_evicted == 0u);
	for (i = 0; i < 3; i++)
		osr_ready(&R, s[i], ALL_FEATURES);
	/* READY with operations in flight: still none */
	wri_osd_sess_inflight(&R.t, s[0], 1);
	wri_osd_sess_inflight(&R.t, s[1], 2);
	wri_osd_sess_inflight(&R.t, s[2], 1);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 3, &a[3], &x));
	WRT_CHECK(R.t.n_evicted == 0u && R.f.n_close == 0u);
	/* session 1 is idle again and the others are not: it is the one that goes, whatever its age */
	wri_osd_sess_inflight(&R.t, s[1], -2);
	WRT_CHECK(R.t.s[1].n_inflight == 0u);
	R.x.now.mono_ms = T0 + 100u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &a[3], &x));
	WRT_CHECK(x == s[1] && R.t.n_evicted == 1u && R.f.n_close == 1u && R.t.s[x].osd == 3 && R.t.s[x].state == WRI_OS_OPENING);
	WRT_CHECK(R.r.n_lost == 1u && R.r.lost[0].s == s[1] && R.r.lost[0].st == WR_OK); /* an orderly close: the request layer re-asks */
	WRT_CHECK(R.f.slot[R.t.s[0].conn_slot].n_close == 0u);
	/* the oldest idle READY session goes first, a use makes a session young */
	osr_ready(&R, x, ALL_FEATURES);
	wri_osd_sess_inflight(&R.t, s[0], -1);
	wri_osd_sess_inflight(&R.t, s[2], -1);
	R.x.now.mono_ms = T0 + 200u;
	R.t.s[s[0]].last_used_ms = T0 + 50u;
	R.t.s[s[2]].last_used_ms = T0 + 20u;
	R.t.s[x].last_used_ms = T0 + 120u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 4, &a[4], &ev));
	WRT_CHECK(ev == s[2]); /* last_used T0 + 20 is the oldest */
	osr_ready(&R, ev, ALL_FEATURES);
	/* acquiring an existing session counts as use */
	R.x.now.mono_ms = T0 + 300u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 0, &a[0], &x)); /* session of OSD 0 touched now */
	WRT_CHECK(R.t.s[x].last_used_ms == T0 + 300u);
	R.x.now.mono_ms = T0 + 310u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a[5], &ev));
	WRT_CHECK(R.t.s[ev].osd == 5);
	WRT_CHECK(R.t.s[x].osd == 0); /* the touched one stayed */
	/* send counts as use and is refused until READY */
	{
		wri_m2_msg_out m;

		memset(&m, 0, sizeof(m));
		WRT_CHECK(R.t.s[ev].state == WRI_OS_OPENING);
		WRT_CHECK_STATUS(WR_E_STATE, wri_osd_sess_send(&R.t, ev, &m));
		osr_ready(&R, ev, ALL_FEATURES);
		R.x.now.mono_ms = T0 + 400u;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_send(&R.t, ev, &m));
		WRT_CHECK(R.t.s[ev].last_used_ms == T0 + 400u && R.f.n_send == 1u);
	}
	WRT_CHECK(R.f.max_live_seen <= 3u); /* never more than osd_sessions connections */
	WRT_CHECK(R.t.hiwater == 3u);
	check_invariants(&R);
}

static void test_engine_slot_still_closing(void)
{
	wr_addr a = osr_addr(0), b = osr_addr(1), c = osr_addr(2);
	uint32_t s0, s1, x;

	/* the engine has exactly as many connection slots as sessions and frees a slot a run after the close */
	WRT_CHECK(fresh(2, 1024, 4) == 0);
	R.f.n_slots = 2;
	R.f.closing_holds_slot = 1;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 0, &a, &s0));
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &b, &s1));
	osr_ready(&R, s0, ALL_FEATURES);
	osr_ready(&R, s1, ALL_FEATURES);
	R.x.now.mono_ms += 5;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 2, &c, &x)); /* evicted, but the slot is not free yet */
	WRT_CHECK(R.t.n_evicted == 1u && R.f.n_close == 1u);
	WRT_CHECK(R.t.s[s0].state == WRI_OS_FREE && R.t.s[s0].osd == -1);
	WRT_CHECK(R.r.n_lost == 1u);
	WRT_CHECK(fk_live(&R.f) == 2u); /* the closing one still holds its engine slot, the table has one live session */
	{
		unsigned i;

		for (i = 0; i < 2; i++)
			if (R.f.slot[i].closing)
				fk_free_slot(&R.f, i);
	}
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &c, &x));
	WRT_CHECK(R.t.n_evicted == 1u);
	WRT_CHECK(fk_live(&R.f) <= 2u);
	check_invariants(&R);
}

static void test_address_change(void)
{
	wr_addr a = osr_addr(1), moved = osr_addr(1);
	uint32_t s, s2;
	uint16_t old_slot;

	WRT_CHECK(fresh(2, 1024, 4) == 0);
	R.f.closing_holds_slot = 1; /* keep the old slot visible after the close */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	old_slot = R.t.s[s].conn_slot;
	moved.port = 7000;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &moved, &s2));
	WRT_CHECK(R.f.slot[old_slot].n_close == 1u && R.f.slot[old_slot].close_why == WR_OK);
	WRT_CHECK(R.r.n_lost == 1u && R.r.lost[0].st == WR_OK);
	WRT_CHECK(R.f.n_open == 2u && R.t.s[s2].state == WRI_OS_OPENING && R.t.s[s2].addr.port == 7000);
	WRT_CHECK(R.t.s[s2].osd == 1);
	R.f.closing_holds_slot = 0;
	fk_free_slot(&R.f, old_slot);
	/* a different nonce is a different address too (the server compares it byte for byte) */
	osr_ready(&R, s2, ALL_FEATURES);
	moved.nonce++;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &moved, &s2));
	WRT_CHECK(R.f.n_open == 3u && R.r.n_lost == 2u);
	/* IPv6 compares all 16 bytes, IPv4 only 4 (the rest of the field is not part of the address) */
	{
		wr_addr v6, v6b;
		uint32_t t1, t2;

		memset(&v6, 0, sizeof(v6));
		v6.family = WR_AF_IPV6;
		v6.ip[15] = 1;
		v6.port = 6801;
		v6b = v6;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 7, &v6, &t1));
		v6b.ip[9] = 0x55;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 7, &v6b, &t2));
		WRT_CHECK(R.f.n_open == 5u); /* the second call replaced the connection */
	}
	{
		wr_addr v4 = osr_addr(2), v4b;
		uint32_t t1, t2;
		unsigned opens;

		WRT_CHECK(fresh(2, 1024, 4) == 0);
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &v4, &t1));
		v4b = v4;
		v4b.ip[10] = 0x77; /* garbage in the unused bytes of an IPv4 address */
		opens = R.f.n_open;
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &v4b, &t2));
		WRT_CHECK(t1 == t2 && R.f.n_open == opens);
	}
	check_invariants(&R);
}

/* ---- cool-down ----------------------------------------------------------------------------------------------------------- */

static void test_cooldown(void)
{
	wr_addr a = osr_addr(5);
	uint32_t s = WRI_NIL, x = WRI_NIL;
	static const uint64_t want[] = {2000, 4000, 8000, 10000, 10000, 10000};
	unsigned i;
	uint64_t t_fail;

	WRT_CHECK(fresh(3, 1024, 4) == 0);
	R.x.now.mono_ms = T0;
	for (i = 0; i < 6; i++) {
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
		t_fail = R.x.now.mono_ms;
		osr_closed(&R, s, WR_E_NET_CLOSED); /* connect refused */
		WRT_CHECK(R.t.s[s].state == WRI_OS_COOLDOWN && R.t.s[s].osd == 5);
		WRT_CHECK(R.t.s[s].cooldown_until_ms == t_fail + want[i]);
		WRT_CHECK(R.t.s[s].fail_streak == i + 1u);
		WRT_CHECK(R.r.n_lost == i + 1u && R.r.lost[i].st == WR_E_NET_CLOSED);
		/* until the end of the cool-down the answer is BUSY and nothing is opened; at the last millisecond of it and not after */
		R.x.now.mono_ms = t_fail + 1u;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 5, &a, &x));
		R.x.now.mono_ms = t_fail + want[i] - 1u;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 5, &a, &x));
		WRT_CHECK(R.f.n_open == i + 1u);
		R.x.now.mono_ms = t_fail + want[i];
	}
	WRT_CHECK(R.t.n_resets == 6u);
	/* the cool-down is reported as the time the table wants to run next while it runs, and not any more when it has passed */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(wri_osd_sess_step(&R.t) == R.x.now.mono_ms + 10000u);
	R.x.now.mono_ms += 10000u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == WR_DEADLINE_NONE);
	/* a connection that is READY and answers once starts the streak over; one that is READY and says nothing does not */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	WRT_CHECK(R.t.s[s].fail_streak == 7u); /* kept through the entry */
	osr_ready(&R, s, ALL_FEATURES);
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(R.t.s[s].cooldown_until_ms == R.x.now.mono_ms + 10000u && R.t.s[s].fail_streak == 8u);
	R.x.now.mono_ms += 10000u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	{
		rframe f;
		uint32_t plen[1] = {0};

		rf_reply(&f, "rbd_header.1", 1, plen, 0, 0);
		WRT_CHECK_STATUS(WR_OK, osr_frame(&R, s, WRI_MSG_OSD_OPREPLY, 77, 8, 2, f.b, f.n, NULL, 0, NULL, 0, NULL));
		WRT_CHECK(R.r.n_reply == 1u && R.t.s[s].fail_streak == 0u && R.t.s[s].replied);
	}
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(R.t.s[s].fail_streak == 1u && R.t.s[s].cooldown_until_ms == R.x.now.mono_ms + 2000u);
	/* a new address ends the cool-down at once, with a fresh streak */
	{
		wr_addr moved = a;

		moved.port = 7777;
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 5, &a, &x));
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &moved, &x));
		WRT_CHECK(R.t.s[x].fail_streak == 0u && R.t.s[x].state == WRI_OS_OPENING);
	}
	check_invariants(&R);
}

/* A zero connect timeout is a legal if odd configuration: the cool-down is zero at every streak, and working it out never loops once per earlier
 * failure (a streak near 2^32 would spin for billions of iterations); the streak saturates; a huge timeout is its own cap. */
static void test_cooldown_extremes(void)
{
	wr_addr a = osr_addr(5);
	uint32_t s = WRI_NIL;
	clock_t t_start;

	WRT_CHECK(fresh(2, 1024, 4) == 0);
	R.x.cfg.osd_connect_timeout_ms = 0;
	R.x.now.mono_ms = T0;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(R.t.s[s].state == WRI_OS_COOLDOWN && R.t.s[s].cooldown_until_ms == T0 && R.t.s[s].fail_streak == 1u);
	R.t.s[s].fail_streak = UINT32_MAX - 1u; /* the entry remembers a huge streak */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s)); /* a zero cool-down is over at once */
	WRT_CHECK(R.t.s[s].fail_streak == UINT32_MAX - 1u);
	t_start = clock();
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(clock() - t_start < CLOCKS_PER_SEC / 2); /* a spinning cool-down takes tens of seconds */
	WRT_CHECK(R.t.s[s].fail_streak == UINT32_MAX && R.t.s[s].cooldown_until_ms == T0);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(R.t.s[s].fail_streak == UINT32_MAX && R.t.s[s].cooldown_until_ms == T0); /* saturated, not wrapped to 0 */
	/* a timeout above the 10 s cap is its own cap: it is never doubled */
	R.x.cfg.osd_connect_timeout_ms = UINT32_MAX;
	R.t.s[s].fail_streak = 3;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 5, &a, &s));
	osr_closed(&R, s, WR_E_NET_CLOSED);
	WRT_CHECK(R.t.s[s].cooldown_until_ms == (uint64_t)T0 + UINT32_MAX && R.t.s[s].fail_streak == 4u);
	check_invariants(&R);
}

/* WRI_OSD_FRONT_MIN is what the table promises: the largest reply front the decoder takes (eight echoed operations, a 95 byte object name) and the
 * largest backoff the table keeps exactly (two 96 byte names) arrive on a table of exactly that front capacity and are delivered / kept. */
static void test_front_min_holds_largest(void)
{
	wr_addr a = osr_addr(4);
	uint32_t s = WRI_NIL, plen[8] = {0, 0, 0, 0, 0, 0, 0, 0}, i, n;
	char nm[97];
	rframe f;
	uint8_t sinkbuf[8], bo[600];
	wri_mbackoff m;

	WRT_CHECK(fresh(2, WRI_OSD_FRONT_MIN, 4) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 4, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	memset(nm, 'n', 95);
	nm[95] = 0;
	rf_reply(&f, nm, 8, plen, 0, 0);
	WRT_CHECK(f.n <= WRI_OSD_FRONT_MIN && f.n >= 520u); /* 533 bytes: the bound is tight, not slack */
	R.r.sink_dst = sinkbuf;
	R.r.sink_cap = sizeof(sinkbuf);
	R.r.sink_n_ops = 8;
	WRT_CHECK_STATUS(WR_OK, osr_frame(&R, s, WRI_MSG_OSD_OPREPLY, 5, 8, 2, f.b, f.n, NULL, 0, NULL, 0, NULL));
	WRT_CHECK(R.r.n_reply == 1u && R.r.reply[0].rep.n_ops == 8u && R.r.n_lost == 0u && R.t.s[s].state == WRI_OS_READY);
	memset(nm, 'b', 96);
	nm[96] = 0;
	memset(&m, 0, sizeof(m));
	m.pool = 2;
	m.pg_seed = 3;
	m.map_epoch = 9;
	m.id = 1;
	m.begin.pool = m.end.pool = 2;
	m.begin.oid = m.end.oid = (const uint8_t *)nm;
	m.begin.oid_len = m.end.oid_len = 96;
	m.begin.hash = 0x10u;
	m.end.hash = 0x20u;
	n = rf_backoff(bo, sizeof(bo), &m, WRI_BACKOFF_BLOCK);
	WRT_CHECK(n != 0u && n <= WRI_OSD_FRONT_MIN);
	WRT_CHECK_STATUS(WR_OK, osr_frame(&R, s, WRI_MSG_OSD_BACKOFF, 0, 1, 1, bo, n, NULL, 0, NULL, 0, NULL));
	WRT_CHECK(R.t.s[s].n_backoff == 1u && R.r.n_lost == 0u && R.t.n_backoff_noack == 0u);
	for (i = 0; i < 4u; i++)
		if (R.t.s[s].bo[i].used)
			WRT_CHECK(!R.t.s[s].bo[i].coarse && R.t.s[s].bo[i].begin_len == 96u);
	check_invariants(&R);
}

/* A cool-down entry is the table's only record that an OSD just failed. It is taken for another OSD only when its time has passed (after the free slots,
 * before a working session is evicted); until then a session with nothing in flight is evicted instead, and with none the answer is BUSY. Taking it early
 * lets the next operation for the failed OSD dial it again at once, evict a working session to do so, and repeat that for ever without time passing
 * (fuzz_client_osd, regress_cooldown_slot_taken.bin: two sessions, three OSDs, one refusing connections). */
static void test_cooldown_slot_taken(void)
{
	wr_addr a0 = osr_addr(0), a1 = osr_addr(1), a2 = osr_addr(2), a3 = osr_addr(3);
	uint32_t s0, s1, s2, x;
	unsigned opens, i;

	WRT_CHECK(fresh(2, 1024, 4) == 0);
	R.x.now.mono_ms = T0;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 0, &a0, &s0));
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a1, &s1));
	osr_ready(&R, s1, ALL_FEATURES);
	wri_osd_sess_inflight(&R.t, s1, 1); /* a request is on its way: not evictable */
	osr_closed(&R, s0, WR_E_NET_CLOSED); /* OSD 0 refuses connections */
	WRT_CHECK(R.t.s[s0].state == WRI_OS_COOLDOWN && R.t.s[s0].cooldown_until_ms == T0 + 2000u);
	/* inside the cool-down neither OSD 0 nor a new OSD gets a slot, nothing is dialled, nothing is evicted, and the record stays */
	opens = R.f.n_open;
	for (i = 0; i < 100u; i++) {
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 2, &a2, &x));
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 0, &a0, &x));
	}
	WRT_CHECK(R.f.n_open == opens && R.t.n_evicted == 0u && R.t.s[s1].state == WRI_OS_READY);
	WRT_CHECK(R.t.s[s0].state == WRI_OS_COOLDOWN && R.t.s[s0].osd == 0 && R.t.s[s0].fail_streak == 1u);
	R.x.now.mono_ms = T0 + 1999u;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 2, &a2, &x)); /* the last millisecond of it */
	/* the time has passed: the slot goes to OSD 2, the working session stays */
	R.x.now.mono_ms = T0 + 2000u;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &a2, &s2));
	WRT_CHECK(s2 == s0 && R.t.n_evicted == 0u && R.t.s[s1].state == WRI_OS_READY && R.t.s[s2].osd == 2);
	/* OSD 0 is back to a clean slate: no memory of its failure, so it asks for a slot like a new OSD (here none: one OPENING, one in flight) */
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 0, &a0, &x));
	/* a session with nothing in flight is evicted before a cool-down that is still running is touched */
	wri_osd_sess_inflight(&R.t, s1, -1);
	osr_ready(&R, s2, ALL_FEATURES);
	osr_closed(&R, s2, WR_E_NET_CLOSED); /* OSD 2 fails at once: its record is the unexpired one now */
	WRT_CHECK(R.t.s[s2].state == WRI_OS_COOLDOWN && R.t.s[s2].cooldown_until_ms > R.x.now.mono_ms);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &a3, &x));
	WRT_CHECK(x == s1 && R.t.n_evicted == 1u && R.t.s[s2].state == WRI_OS_COOLDOWN && R.t.s[s2].osd == 2);
	/* the failed OSD itself still waits out its own cool-down */
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 2, &a2, &x));
	/* two cool-downs: of those whose time has passed, the one that ended first is taken first */
	WRT_CHECK(fresh(3, 1024, 4) == 0);
	{
		uint32_t q[3];
		wr_addr ad[4];

		for (i = 0; i < 4; i++)
			ad[i] = osr_addr(i);
		R.x.now.mono_ms = T0;
		for (i = 0; i < 3; i++) {
			WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, (int32_t)i, &ad[i], &q[i]));
			R.x.now.mono_ms += 100;
		}
		osr_closed(&R, q[2], WR_E_NET_CLOSED); /* fails first, so it ends first */
		R.x.now.mono_ms += 100;
		osr_closed(&R, q[0], WR_E_NET_CLOSED);
		R.x.now.mono_ms += 100;
		osr_closed(&R, q[1], WR_E_NET_CLOSED);
		WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_acquire(&R.t, 3, &ad[3], &x)); /* all three still cooling down */
		R.x.now.mono_ms = T0 + 2350u; /* q[2] has ended (T0 + 2300), the other two (T0 + 2400, T0 + 2500) have not */
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 3, &ad[3], &x));
		WRT_CHECK(x == q[2]);
		R.x.now.mono_ms = T0 + 5000u; /* both of the others have ended: the one that ended first goes first */
		osr_closed(&R, x, WR_E_NET_CLOSED);
		WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 4, &ad[0], &x));
		WRT_CHECK(x == q[0]);
	}
	check_invariants(&R);
}

/* ---- idle reaper and step ------------------------------------------------------------------------------------------------- */

static void test_idle(void)
{
	wr_addr a = osr_addr(1), b = osr_addr(2);
	uint32_t s1, s2;

	WRT_CHECK(fresh(3, 1024, 4) == 0);
	R.x.cfg.osd_idle_ms = 0; /* never: LRU alone frees sessions */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s1));
	osr_ready(&R, s1, ALL_FEATURES);
	R.x.now.mono_ms += 1000000u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == WR_DEADLINE_NONE && R.t.s[s1].state == WRI_OS_READY);
	R.x.cfg.osd_idle_ms = 5000;
	R.x.now.mono_ms += 100;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &b, &s2));
	osr_ready(&R, s2, ALL_FEATURES);
	{
		uint64_t d = wri_osd_sess_step(&R.t);

		/* s1 was last used 1000000 ms ago: closed by this very step; s2 wants a wake-up at last_used + idle */
		WRT_CHECK(R.t.s[s1].state == WRI_OS_FREE && R.t.n_idle_closed == 1u);
		WRT_CHECK(R.r.n_lost == 1u && R.r.lost[0].s == s1 && R.r.lost[0].st == WR_OK && R.f.n_close == 1u);
		WRT_CHECK(d == R.t.s[s2].last_used_ms + 5000u);
	}
	/* operations in flight keep a session; using it moves the deadline */
	wri_osd_sess_inflight(&R.t, s2, 1);
	R.x.now.mono_ms += 6000u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == WR_DEADLINE_NONE && R.t.s[s2].state == WRI_OS_READY);
	R.t.s[s2].last_used_ms = R.x.now.mono_ms; /* its reply arrives: that is a use (the up layer does this on every reply) */
	wri_osd_sess_inflight(&R.t, s2, -1);
	R.x.now.mono_ms += 4999u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == R.t.s[s2].last_used_ms + 5000u && R.t.s[s2].state == WRI_OS_READY);
	R.x.now.mono_ms += 1u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == WR_DEADLINE_NONE && R.t.s[s2].state == WRI_OS_FREE && R.t.n_idle_closed == 2u);
	/* an orderly close is no failure: no cool-down, the next acquire opens at once, and it counts as no reset */
	WRT_CHECK(R.t.n_resets == 0u);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 2, &b, &s2));
	WRT_CHECK(R.t.s[s2].fail_streak == 0u);
	/* an OPENING session is never closed by the reaper (the handshake has its own timeout) */
	R.x.now.mono_ms += 100000u;
	WRT_CHECK(wri_osd_sess_step(&R.t) == WR_DEADLINE_NONE && R.t.s[s2].state == WRI_OS_OPENING);
	WRT_CHECK(wri_osd_sess_step(NULL) == WR_DEADLINE_NONE);
	check_invariants(&R);
}

/* ---- send, inflight, reset, tx_idle -------------------------------------------------------------------------------------- */

static void test_use(void)
{
	wr_addr a = osr_addr(1), b = osr_addr(2);
	uint32_t s, s2;
	wri_m2_msg_out m;
	wr_errinfo why;

	WRT_CHECK(fresh(2, 1024, 4) == 0);
	memset(&m, 0, sizeof(m));
	m.type = 42;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_send(NULL, 0, &m));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_osd_sess_send(&R.t, 9, &m));
	WRT_CHECK_STATUS(WR_E_STATE, wri_osd_sess_send(&R.t, 0, &m)); /* a free entry */
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_send(&R.t, s, &m));
	WRT_CHECK(R.f.sent[0].m.type == 42 && R.f.sent[0].slot == R.t.s[s].conn_slot);
	R.f.send_st = WR_E_BUSY;
	R.x.now.mono_ms += 77;
	WRT_CHECK_STATUS(WR_E_BUSY, wri_osd_sess_send(&R.t, s, &m)); /* the transmit queue is full: not a use of the session */
	WRT_CHECK(R.t.s[s].last_used_ms != R.x.now.mono_ms);
	R.f.send_st = WR_OK;
	/* inflight: a count that cannot go below zero or wrap */
	wri_osd_sess_inflight(&R.t, s, 3);
	WRT_CHECK(R.t.s[s].n_inflight == 3u);
	wri_osd_sess_inflight(&R.t, s, -1);
	wri_osd_sess_inflight(&R.t, s, -100);
	WRT_CHECK(R.t.s[s].n_inflight == 0u);
	wri_osd_sess_inflight(&R.t, s, -2147483647 - 1);
	WRT_CHECK(R.t.s[s].n_inflight == 0u);
	R.t.s[s].n_inflight = UINT32_MAX - 1u;
	wri_osd_sess_inflight(&R.t, s, 5);
	WRT_CHECK(R.t.s[s].n_inflight == UINT32_MAX);
	R.t.s[s].n_inflight = 0;
	wri_osd_sess_inflight(&R.t, 55, 1); /* out of range: ignored */
	wri_osd_sess_inflight(NULL, 0, 1);
	/* tx_idle follows the link; no connection means idle */
	R.f.tx_idle = 0;
	WRT_CHECK(!wri_osd_sess_tx_idle(&R.t, s));
	R.f.tx_idle = 1;
	WRT_CHECK(wri_osd_sess_tx_idle(&R.t, s));
	WRT_CHECK(wri_osd_sess_tx_idle(&R.t, 1) && wri_osd_sess_tx_idle(&R.t, 77) && wri_osd_sess_tx_idle(NULL, 0));
	R.f.tx_idle = 0;
	WRT_CHECK(wri_osd_sess_tx_idle(&R.t, 1)); /* a free entry has no queue to ask */
	R.f.tx_idle = 1;
	/* reset with a cause: counted, the link closes with that status, lost once, cool-down starts */
	wri_osd_sess_inflight(&R.t, s, 4);
	memset(&why, 0, sizeof(why));
	why.status = WR_E_OSD_PROTO;
	why.what = "test";
	wri_osd_sess_reset(&R.t, s, &why);
	WRT_CHECK(R.f.n_close == 1u && R.f.slot[0].close_why == WR_E_OSD_PROTO);
	WRT_CHECK(R.t.n_resets == 1u && R.r.n_lost == 1u && R.r.lost[0].st == WR_E_OSD_PROTO);
	WRT_CHECK(R.t.s[s].state == WRI_OS_COOLDOWN && R.t.s[s].n_inflight == 0u && R.t.s[s].conn_slot == WRI_OS_NOSLOT);
	wri_osd_sess_reset(&R.t, s, &why); /* a second reset of the same session does nothing */
	WRT_CHECK(R.f.n_close == 1u && R.r.n_lost == 1u && R.t.n_resets == 1u);
	wri_osd_sess_reset(&R.t, 55, &why);
	wri_osd_sess_reset(NULL, 0, &why);
	/* a late callback of the old connection finds the entry gone from it */
	{
		wr_errinfo e;
		wri_m2_conn dead;

		memset(&e, 0, sizeof(e));
		e.status = WR_E_NET_CLOSED;
		memset(&dead, 0, sizeof(dead));
		dead.slot = 0;
		wri_osd_sess_upper()->closed(&R.t.s[s], &dead, &e);
		WRT_CHECK(R.r.n_lost == 1u && R.t.n_resets == 1u);
	}
	/* a deliberate reset (a cancel): no penalty at all */
	R.x.now.mono_ms += 2000;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	wri_osd_sess_reset(&R.t, s, NULL);
	WRT_CHECK(R.t.s[s].state == WRI_OS_FREE && R.t.n_resets == 1u && R.r.n_lost == 2u && R.r.lost[1].st == WR_OK);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s2)); /* at once */
	osr_ready(&R, s2, ALL_FEATURES);
	memset(&why, 0, sizeof(why));
	wri_osd_sess_reset(&R.t, s2, &why);
	WRT_CHECK(R.t.s[s2].state == WRI_OS_FREE && R.t.n_resets == 1u);
	(void)b;
	check_invariants(&R);
}

/* ---- the feature check at READY ------------------------------------------------------------------------------------------ */

static void test_features(void)
{
	wr_addr a = osr_addr(1);
	uint32_t s;
	static const struct {
		uint64_t drop;       /* bits taken from the full word */
		int ok;
		uint8_t version;
	} cases[] = {
		{0, 1, 9},
		{(1ull << 49), 1, 8},                                /* no SERVER_SQUID bit: v8 */
		{(1ull << 49) | (1ull << 50), 1, 8},
		{(1ull << 50), 1, 9},                                /* TENTACLE is not needed */
		{(1ull << 8), 0, 0},                                 /* OBJECTLOCATOR */
		{(1ull << 9), 0, 0},                                 /* PGID64 */
		{(1ull << 21), 0, 0},                                /* RESEND_ON_SPLIT, bit 21 */
		{(1ull << 56), 0, 0},                                /* NEW_OSDOP_ENCODING */
		{(1ull << 58), 0, 0},                                /* NEW_OSDOPREPLY_ENCODING */
		{(1ull << 57), 0, 0},                                /* the incarnation marker of RESEND_ON_SPLIT and SERVER_SQUID */
		{(1ull << 8) | (1ull << 9) | (1ull << 56), 0, 0},
	};
	unsigned i, pass;

	for (pass = 0; pass < 2; pass++) { /* with and without the link's features hook */
		WRT_CHECK(fresh(2, 1024, 4) == 0);
		R.t.link.features = pass ? NULL : fk_features;
		R.f.features_hook = !pass;
		for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			uint64_t feats = ALL_FEATURES & ~cases[i].drop;
			unsigned lost = R.r.n_lost;

			R.x.now.mono_ms += 20000;
			WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
			osr_ready(&R, s, feats);
			if (cases[i].ok) {
				WRT_CHECK(wri_osd_sess_ready(&R.t, s) && R.t.s[s].msg_version == cases[i].version && R.t.s[s].features == feats);
				wri_osd_sess_reset(&R.t, s, NULL);
			} else {
				WRT_CHECK(!wri_osd_sess_ready(&R.t, s) && R.t.s[s].state == WRI_OS_COOLDOWN);
				WRT_CHECK(R.r.n_lost == lost + 1u && R.r.lost[lost].st == WR_E_OSD_VERSION);
				WRT_CHECK(R.r.lost[lost].a0 == (WRI_OSDFEAT_NEED & ~feats)); /* the missing bits, for the message */
				WRT_CHECK(R.r.lost[lost].a0 != 0u);
				WRT_CHECK(R.f.n_close == R.f.n_open); /* the connection was closed too */
			}
		}
	}
	/* the connection is closed with the same status the request layer sees */
	WRT_CHECK(fresh(2, 1024, 4) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	osr_ready(&R, s, ALL_FEATURES & ~(1ull << 58));
	WRT_CHECK(R.f.slot[0].close_why == WR_E_OSD_VERSION);
	/* the link's word wins over the connection's own when the hook exists */
	WRT_CHECK(fresh(2, 1024, 4) == 0);
	R.f.features_hook = 1;
	R.t.link.features = fk_features;
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	{
		uint16_t slot = R.t.s[s].conn_slot;

		R.f.feat = ALL_FEATURES & ~(1ull << 49);
		R.f.slot[slot].conn.features = 0; /* the connection says nothing, the link says v8 */
		R.f.slot[slot].up->ready(R.f.slot[slot].up_ctx, &R.f.slot[slot].conn);
		WRT_CHECK(wri_osd_sess_ready(&R.t, s) && R.t.s[s].msg_version == WRI_MOSDOP_VERSION_V8);
	}
	/* ready() for a session that is not OPENING (a stale callback, a repeated one) does nothing */
	WRT_CHECK(fresh(2, 1024, 4) == 0);
	WRT_CHECK_STATUS(WR_OK, wri_osd_sess_acquire(&R.t, 1, &a, &s));
	osr_ready(&R, s, ALL_FEATURES);
	{
		unsigned n = R.r.n_ready;
		uint16_t slot = R.t.s[s].conn_slot;

		R.f.slot[slot].up->ready(R.f.slot[slot].up_ctx, &R.f.slot[slot].conn);
		WRT_CHECK(R.r.n_ready == n);
	}
	check_invariants(&R);
}

/* ---- a random model run --------------------------------------------------------------------------------------------------- */

static uint64_t rng_s = 0x9e3779b97f4a7c15ull;

static uint32_t rnd(uint32_t n)
{
	rng_s ^= rng_s << 13;
	rng_s ^= rng_s >> 7;
	rng_s ^= rng_s << 17;
	return (uint32_t)((rng_s >> 11) % n);
}

static void test_random_model(void)
{
	unsigned iter, n_osd = 7, round;

	for (round = 0; round < 3; round++) {
		unsigned n_sess = 2u + round * 2u;

		WRT_CHECK(fresh(n_sess, 1024, 4) == 0);
		R.f.n_slots = n_sess;           /* the engine has no connection to spare */
		R.f.closing_holds_slot = 1;     /* and frees a closed one only when told */
		R.x.cfg.osd_idle_ms = round == 1 ? 3000u : 0u;
		for (iter = 0; iter < 30000; iter++) {
			uint32_t op = rnd(100), osd = rnd(n_osd), s;
			wr_addr a = osr_addr(osd);

			R.x.now.mono_ms += rnd(300);
			R.f.have_ticket = rnd(20) != 0;
			R.f.handshake_free = rnd(15) != 0;
			if (op < 40) {
				if (wri_osd_sess_acquire(&R.t, (int32_t)osd, &a, &s) == WR_OK) {
					WRT_CHECK(R.t.s[s].osd == (int32_t)osd);
					if (R.t.s[s].state == WRI_OS_OPENING && rnd(3) != 0)
						osr_ready(&R, s, rnd(8) == 0 ? ALL_FEATURES & ~(1ull << 9) : ALL_FEATURES);
				}
			} else if (op < 55) {
				s = rnd(n_sess);
				if (R.t.s[s].state == WRI_OS_READY || R.t.s[s].state == WRI_OS_OPENING)
					osr_closed(&R, s, rnd(2) ? WR_E_NET_CLOSED : WR_E_M2_HANDSHAKE_TIMEOUT);
			} else if (op < 70) {
				s = rnd(n_sess);
				wri_osd_sess_inflight(&R.t, s, rnd(2) ? 1 : -1);
			} else if (op < 78) {
				s = rnd(n_sess);
				wri_osd_sess_reset(&R.t, s, rnd(2) ? NULL : &(wr_errinfo){.status = WR_E_OSD_PROTO});
			} else if (op < 90) {
				(void)wri_osd_sess_step(&R.t);
			} else { /* the engine frees the slots whose sockets the host closed */
				unsigned i;

				for (i = 0; i < R.f.n_slots; i++)
					if (R.f.slot[i].used && R.f.slot[i].closing)
						fk_free_slot(&R.f, i);
			}
			check_invariants(&R);
			WRT_CHECK(fk_live(&R.f) <= n_sess); /* never more connections than osd_sessions, not even the ones still closing */
			if (wrt_failures != 0)
				return;
		}
		WRT_CHECK(R.f.max_live_seen <= n_sess);
		WRT_CHECK(R.t.hiwater <= n_sess);
		printf("random model (%u sessions): %u opens, %u evictions, %u idle closes, %u resets, hiwater %u\n", n_sess, R.f.n_open,
		       R.t.n_evicted, R.t.n_idle_closed, R.t.n_resets, R.t.hiwater);
	}
}

int main(void)
{
	test_mem_init();
	test_acquire_basic();
	test_gates();
	test_lru_and_busy();
	test_engine_slot_still_closing();
	test_address_change();
	test_cooldown();
	test_cooldown_extremes();
	test_front_min_holds_largest();
	test_cooldown_slot_taken();
	test_idle();
	test_use();
	test_features();
	test_random_model();
	osr_free(&R);
	return wrt_finish();
}
