/* SPDX-License-Identifier: MIT */
/*
 * test_client_osd_link.c - the OSD session layer's view of the engine's connection table, called directly (module client-glue-osd;
 * core/src/client/wri_client_osd_conn.c and wri_client_conn_open of wri_client_conn.c; client_osd_rig.h builds the engine, nothing here dials):
 *
 *   gates          an open needs an OSD ticket (WR_E_BUSY before the login), a live client with the OSD client on (WR_E_INVAL), a free connection slot AND a
 *                  free handshake slot (WR_E_BUSY, each of the two on its own), and an engine that has not failed (WR_E_BUSY); NULL arguments are WR_E_INVAL
 *   slots          every open gets its own slot and its own cephx context; a close is told to the upper layer once; a connection that never reached the host
 *                  frees its slot and handshake slot at the next housekeeping and wipes its cephx context; the lowest free slot is reused
 *   queries        tx_idle of a slot that is not there is 1, send to it is WR_E_STATE, a close of it does nothing, nothing crashes for slot 0xffff
 */
#include "client_osd_rig.h"

typedef struct up_rec {
	unsigned closed, ready, plan, msg;
	wr_status last;
} up_rec;

static wr_status d_plan(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t seglen[3], wri_m2_sink sink[3])
{
	(void)c;
	(void)hdr;
	(void)seglen;
	(void)sink;
	((up_rec *)ctx)->plan++;
	return WR_E_INVAL;
}

static void d_message(void *ctx, wri_m2_conn *c, const wri_m2_hdr2 *hdr, const uint32_t stored[3])
{
	(void)c;
	(void)hdr;
	(void)stored;
	((up_rec *)ctx)->msg++;
}

static void d_ready(void *ctx, wri_m2_conn *c)
{
	(void)c;
	((up_rec *)ctx)->ready++;
}

static void d_closed(void *ctx, wri_m2_conn *c, const wr_errinfo *err)
{
	(void)c;
	((up_rec *)ctx)->closed++;
	((up_rec *)ctx)->last = err != NULL ? err->status : WR_OK;
}

static const wri_m2_upper g_up = {d_plan, d_message, d_ready, d_closed};

static int hs_is_zero(const cw *w, unsigned slot)
{
	const uint8_t *p = (const uint8_t *)&w->c->og->hs[slot];
	size_t i;

	for (i = 0; i < sizeof(w->c->og->hs[slot]); i++)
		if (p[i] != 0u)
			return 0;
	return 1;
}

/* An engine with the OSD client on and logged in: the OSD ticket is held. */
static int open_world(cw *w, unsigned max_conns, unsigned max_hs)
{
	wr_config cfg;

	cw_cfg_default(&cfg);
	cfg.max_conns = (uint16_t)max_conns;
	cfg.max_handshakes = (uint16_t)max_hs;
	if (cw_open(w, &cfg, 3, 16, WR_KEY_TYPE_AES256K) != 0)
		return -1;
	return 0;
}

static void test_gates_and_slots(void)
{
	cw w;
	wri_osd_link L;
	wri_eaddr ea;
	up_rec rec;
	wr_action act;
	uint16_t a = 0, b = 0, x = 0;

	WRT_CHECK(open_world(&w, 8, 2) == 0);
	memset(&rec, 0, sizeof(rec));
	wri_client_osd_link(w.c, &L);
	WRT_CHECK(L.ctx == w.c && L.open != NULL && L.close != NULL && L.send != NULL && L.tx_idle != NULL && L.have_ticket != NULL &&
		  L.handshake_free != NULL && L.features == NULL);
	wri_eaddr_from_wr(&ea, &w.addr[0], WRI_EADDR_TYPE_MSGR2);

	/* before the engine ever ran: no ticket */
	WRT_CHECK(!L.have_ticket(L.ctx));
	WRT_CHECK(L.handshake_free(L.ctx));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_client_conn_open_osd(w.c, &ea, &g_up, &rec, &x));
	WRT_CHECK_STATUS(WR_E_BUSY, L.open(L.ctx, &ea, &g_up, &rec, &x));
	/* arguments */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open_osd(NULL, &ea, &g_up, &rec, &x));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open_osd(w.c, NULL, &g_up, &rec, &x));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open_osd(w.c, &ea, NULL, &rec, &x));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open_osd(w.c, &ea, &g_up, &rec, NULL));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open(w.c, 0, &ea, &g_up, &rec, &x));   /* a role that is neither the monitor nor an OSD */
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open(w.c, 99, &ea, &g_up, &rec, &x));

	(void)cw_settle(&w); /* the login: the monitor session is up, the OSD ticket is held */
	WRT_CHECK(L.have_ticket(L.ctx));
	WRT_CHECK(L.handshake_free(L.ctx)); /* the monitor's handshake slot went back to the pool */

	/* two opens: two slots, two handshake slots, then no handshake slot is free although connection slots are */
	WRT_CHECK_STATUS(WR_OK, L.open(L.ctx, &ea, &g_up, &rec, &a));
	WRT_CHECK_STATUS(WR_OK, L.open(L.ctx, &ea, &g_up, &rec, &b));
	WRT_CHECK(a != b && a < w.c->n_slot && b < w.c->n_slot);
	WRT_CHECK(w.c->slot[a].in_use && w.c->slot[b].in_use);
	WRT_CHECK(w.c->slot[a].conn.role == WRI_ENTITY_OSD && w.c->slot[b].conn.role == WRI_ENTITY_OSD);
	WRT_CHECK(!hs_is_zero(&w, a) && !hs_is_zero(&w, b)); /* each has a cephx context of its own, bound to the cephx client */
	WRT_CHECK(!L.handshake_free(L.ctx));
	WRT_CHECK_STATUS(WR_E_BUSY, L.open(L.ctx, &ea, &g_up, &rec, &x));
	WRT_CHECK_U64(w.c->pa_in_use, 2);

	/* a connection nobody has told the host about is closed and released by the engine alone, once, and its context is wiped */
	L.close(L.ctx, a, WR_E_TIMEOUT);
	WRT_CHECK_U64(rec.closed, 1);
	WRT_CHECK_U64(rec.last, WR_E_TIMEOUT);
	L.close(L.ctx, a, WR_E_STATE); /* a second close of the same connection: nothing more is told */
	WRT_CHECK_U64(rec.closed, 1);
	L.close(L.ctx, b, WR_OK);
	WRT_CHECK_U64(rec.closed, 2);
	WRT_CHECK(L.tx_idle(L.ctx, a) && L.tx_idle(L.ctx, b)); /* nothing queued on a dead connection */
	WRT_CHECK(wr_client_next_action(w.c, &act) == 0); /* housekeeping runs here; no socket was ever asked for, so the host owes nothing */
	WRT_CHECK(!w.c->slot[a].in_use && !w.c->slot[b].in_use);
	WRT_CHECK(hs_is_zero(&w, a) && hs_is_zero(&w, b));
	WRT_CHECK(L.handshake_free(L.ctx));
	WRT_CHECK_U64(w.c->pa_in_use, 0);
	WRT_CHECK_U64(rec.closed, 2); /* the release told nobody a second time */
	/* the lowest free slot is reused */
	x = 0xffffu;
	WRT_CHECK_STATUS(WR_OK, L.open(L.ctx, &ea, &g_up, &rec, &x));
	WRT_CHECK_U64(x, a < b ? a : b);
	L.close(L.ctx, x, WR_OK);
	(void)wr_client_next_action(w.c, &act);

	/* slots that are not there */
	WRT_CHECK(L.tx_idle(L.ctx, 0xffffu) == 1);
	WRT_CHECK(L.tx_idle(L.ctx, (uint16_t)w.c->n_slot) == 1);
	WRT_CHECK(L.tx_idle(L.ctx, a) == 1);
	{
		wri_m2_msg_out m;

		memset(&m, 0, sizeof(m));
		WRT_CHECK_STATUS(WR_E_STATE, L.send(L.ctx, 0xffffu, &m));
		WRT_CHECK_STATUS(WR_E_STATE, L.send(L.ctx, a, &m));
		L.close(L.ctx, 0xffffu, WR_OK); /* nothing happens */
		L.close(L.ctx, a, WR_OK);
	}
	WRT_CHECK_U64(rec.plan + rec.msg + rec.ready, 0); /* nothing was ever received: no host moved a byte */
	cw_free(&w);
}

static void test_no_free_slot(void)
{
	cw w;
	wri_osd_link L;
	wri_eaddr ea;
	up_rec rec;
	wr_action act;
	uint16_t s[16];
	unsigned n = 0, i;
	wr_status st = WR_OK;

	WRT_CHECK(open_world(&w, 8, 8) == 0); /* handshake slots for every connection: only the connection table can run out */
	memset(&rec, 0, sizeof(rec));
	wri_client_osd_link(w.c, &L);
	wri_eaddr_from_wr(&ea, &w.addr[1], WRI_EADDR_TYPE_MSGR2);
	(void)cw_settle(&w);
	WRT_CHECK(L.have_ticket(L.ctx));
	while (n < 16u && (st = L.open(L.ctx, &ea, &g_up, &rec, &s[n])) == WR_OK)
		n++;
	WRT_CHECK_STATUS(WR_E_BUSY, st);
	WRT_CHECK_U64(n, 7); /* 8 slots, one of them the monitor's */
	for (i = 0; i < n; i++)
		WRT_CHECK(w.c->slot[s[i]].in_use);
	/* all the slots are different */
	for (i = 1; i < n; i++) {
		unsigned j;

		for (j = 0; j < i; j++)
			WRT_CHECK(s[i] != s[j]);
	}
	for (i = 0; i < n; i++)
		L.close(L.ctx, s[i], WR_OK);
	(void)wr_client_next_action(w.c, &act);
	WRT_CHECK_STATUS(WR_OK, L.open(L.ctx, &ea, &g_up, &rec, &s[0])); /* room again */
	L.close(L.ctx, s[0], WR_OK);
	cw_free(&w);
}

static void test_off_and_failed(void)
{
	cw w;
	wr_config cfg;
	wri_eaddr ea;
	up_rec rec;
	uint16_t x = 0;

	/* the OSD client is off: no cephx contexts exist, so neither role 'OSD' nor the link works; the monitor role does */
	cw_cfg_default(&cfg);
	cfg.osd_sessions = 0;
	cfg.max_conns = 4;
	cfg.max_handshakes = 2;
	WRT_CHECK(cw_open(&w, &cfg, 1, 16, WR_KEY_TYPE_AES256K) == 0);
	memset(&rec, 0, sizeof(rec));
	wri_eaddr_from_wr(&ea, &w.addr[0], WRI_EADDR_TYPE_MSGR2);
	(void)cw_settle(&w);
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open(w.c, WRI_ENTITY_OSD, &ea, &g_up, &rec, &x));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_client_conn_open_osd(w.c, &ea, &g_up, &rec, &x));
	cw_free(&w);

	/* an engine that has failed gives no connection to anybody */
	WRT_CHECK(open_world(&w, 8, 2) == 0);
	memset(&rec, 0, sizeof(rec));
	wri_eaddr_from_wr(&ea, &w.addr[0], WRI_EADDR_TYPE_MSGR2);
	(void)cw_settle(&w);
	WRT_CHECK_STATUS(WR_OK, wri_client_conn_open_osd(w.c, &ea, &g_up, &rec, &x)); /* alive: fine */
	w.fail_random = 1;
	sim_mon_restart(w.mon);
	cw_tick(&w, 3000);
	WRT_CHECK(wr_client_get_state(w.c) == WR_CS_FAILED);
	WRT_CHECK_STATUS(WR_E_BUSY, wri_client_conn_open_osd(w.c, &ea, &g_up, &rec, &x));
	WRT_CHECK_STATUS(WR_E_BUSY, wri_client_conn_open(w.c, WRI_ENTITY_OSD, &ea, &g_up, &rec, &x));
	cw_free(&w);
}

int main(void)
{
	test_gates_and_slots();
	test_no_free_slot();
	test_off_and_failed();
	return wrt_finish();
}
