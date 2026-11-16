/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake monitor, part 3: renewal and the fault hooks. In-session renewal (MAuth with
 * CEPHX_GET_PRINCIPAL_SESSION_KEY -> MAuthReply with a ticket reply under the AUTH session key, short TTLs)
 * and its refusals; restart (every session cut at once, queued bytes never delivered, the monmap epoch
 * up, the global id reclaimed afterwards with the old ticket); maps held back and released in order;
 * an oversized MOSDMap front; a cut after N client messages; sim_m2 faults applied per connection; two
 * clients at once. docs/spec/cephx.md 3.5 to 3.8, mon-client.md 3.7, 3.8.
 */
#include "sim_mon_tc.h"

#define SLOT_AUTH 5u
#define SLOT_OSD 2u

static sim_mon *mk(const sim_mon_cfg *cfg)
{
	sim_mon *m = sim_mon_new(cfg);

	if (m == NULL) {
		fprintf(stderr, "sim_mon_new failed\n");
		abort();
	}
	return m;
}

static void login(sim_mon *m, const sim_mon_cfg *cfg, mc *c)
{
	if (mc_init(c, m, &cfg->key, "winrbd") != 0 || mc_login(c, 0x24) != MC_OK) {
		fprintf(stderr, "login failed\n");
		abort();
	}
	mc_clear_frames(c);
}

static void sub1(mc *c, const char *what, uint64_t start, uint8_t flags)
{
	wri_sub_item it;

	it.what = what, it.start = start, it.flags = flags;
	mc_send_subscribe(c, &it, 1);
}

/* the k-th message as an MAuthReply: header checked, fields decoded */
static int reply_at(mc *c, size_t k, wri_mauth_reply *r)
{
	mc_msg g;

	if (!mc_msg_at(c, k, &g))
		return 0;
	WRT_CHECK_U64(g.h.type, 18);
	WRT_CHECK_U64(g.h.version, 1);
	WRT_CHECK_U64(g.h.compat_version, 1);
	WRT_CHECK_U64(g.h.priority, 196);
	WRT_CHECK_STATUS(WR_OK, wri_mauth_reply_decode(g.front, g.flen, r));
	return 1;
}

/* ---- renewal ------------------------------------------------------------------------------------------------ */

static void renewal(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	wri_mauth_reply r;
	uint32_t n = 0;
	wri_rd rd;
	uint8_t first_osd_blob[SIM_MON_BLOB_MAX];
	uint32_t first_osd_len;
	unsigned k;

	mt_cfg(&cfg, type);
	cfg.tkt[0].validity_s = 60; /* MON, OSD and MGR tickets live 60 s: renewals are due after 45 s */
	cfg.tkt[SLOT_OSD].validity_s = 60;
	cfg.tkt[4].validity_s = 60;
	m = mk(&cfg);
	login(m, &cfg, &c);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_s, 60);
	memcpy(first_osd_blob, c.svc[SLOT_OSD].blob, c.svc[SLOT_OSD].blob_len);
	first_osd_len = c.svc[SLOT_OSD].blob_len;
	for (k = 0; k < 3; k++) { /* three renewals in a row on the same session, as the 60 s capture shows */
		memset(&c.svc[0], 0, sizeof(c.svc));
		mc_send_renew(&c, k == 2 ? 0x35u : 0x15u); /* MON, OSD, MGR; the AUTH bit is not asked for (and ignored if it is) */
		WRT_CHECK_U64(mc_nmsgs(&c), (size_t)k + 1u);
		WRT_CHECK(reply_at(&c, k, &r));
		WRT_CHECK_U64(r.protocol, 2);
		WRT_CHECK_U64(r.result, 0);
		WRT_CHECK_U64(r.global_id, c.gid);
		wri_rd_init(&rd, r.payload, r.payload_len);
		WRT_CHECK_U64(wri_rd_u16(&rd), WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY);
		WRT_CHECK_U64(wri_rd_i32(&rd), 0);
		WRT_CHECK_STATUS(WR_OK, mc_parse_ticket_reply(&c, &rd, &c.auth_key, NULL, &n));
		WRT_CHECK_U64(n, 3);
		WRT_CHECK_U64(wri_rd_left(&rd), 0);
		WRT_CHECK(c.svc[0].have && c.svc[SLOT_OSD].have && c.svc[4].have && !c.svc[SLOT_AUTH].have);
		WRT_CHECK_U64(c.svc[SLOT_OSD].validity_s, 60);
		WRT_CHECK_U64(c.svc[SLOT_OSD].enc, 0); /* ticket_enc is 0 in a renewal */
		WRT_CHECK_U64(c.svc[SLOT_OSD].key.type, type);
		WRT_CHECK(sim_mon_ticket_valid(m, WRI_CX_SERVICE_OSD, c.svc[SLOT_OSD].blob, c.svc[SLOT_OSD].blob_len));
		WRT_CHECK(c.svc[SLOT_OSD].blob_len != first_osd_len || memcmp(c.svc[SLOT_OSD].blob, first_osd_blob, first_osd_len) != 0);
		WRT_CHECK_MEM(c.svc[SLOT_OSD].key.secret, m->last[SLOT_OSD].key.secret, c.svc[SLOT_OSD].key.len);
		WRT_CHECK_U64(m->last_renew_mask, 0x15);
	}
	WRT_CHECK_U64(m->n_renewals, 3);
	WRT_CHECK_U64(c.conn->n_authreply_sent, 3);
	WRT_CHECK_U64(c.conn->stage, 2);
	/* the monitor sent nothing but answers (mon-client.md 2.2: it never speaks first) */
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	mc_free(&c);
	sim_mon_free(m);
}

static void send_raw_mauth(mc *c, uint32_t protocol, const uint8_t *payload, size_t n)
{
	uint8_t front[256];
	wri_wr w;

	wri_wr_init(&w, front, sizeof(front));
	wri_mauth_encode(&w, protocol, payload, n, 0);
	if (!wri_wr_ok(&w))
		abort();
	mc_send(c, 17, front, (uint32_t)wri_wr_len(&w));
}

static void renewal_refusals(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c, other;
	wri_mauth_reply r;
	size_t k = 0;
	wr_key wrong;
	mt_ticket forged;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	login(m, &cfg, &c);
	/* an authorizer proof under the wrong key, a wrong global id, a ticket nobody issued, a challenge flag */
	mt_key(&wrong, WR_KEY_TYPE_AES256K, 77);
	mc_send_renew_ex(&c, 0x15, c.gid, &c.auth, &wrong, 0);
	mc_send_renew_ex(&c, 0x15, c.gid + 1u, &c.auth, &c.auth_key, 0);
	forged = c.auth;
	forged.blob[0] ^= 1;
	mc_send_renew_ex(&c, 0x15, c.gid, &forged, &c.auth_key, 0);
	mc_send_renew_ex(&c, 0x15, c.gid, &c.auth, &c.auth_key, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 4);
	for (k = 0; k < 4; k++) {
		WRT_CHECK(reply_at(&c, k, &r));
		WRT_CHECK_U64((uint32_t)r.result, (uint32_t)-13);
		WRT_CHECK_U64(r.payload_len, 0);
		WRT_CHECK_U64(r.global_id, c.gid);
	}
	WRT_CHECK_U64(m->n_renewals_denied, 4);
	WRT_CHECK_U64(m->n_renewals, 0);
	/* a protocol other than cephx, and something that cannot be decoded: -95 / dropped */
	send_raw_mauth(&c, 1, (const uint8_t *)"abc", 3);
	WRT_CHECK_U64(mc_nmsgs(&c), 5);
	WRT_CHECK(reply_at(&c, 4, &r));
	WRT_CHECK_U64((uint32_t)r.result, (uint32_t)-95);
	mc_send(&c, 17, (const uint8_t *)"short", 5);
	WRT_CHECK_U64(mc_nmsgs(&c), 5);
	WRT_CHECK_U64(c.conn->n_malformed, 1);
	/* a payload that is not a CEPHX_GET_PRINCIPAL_SESSION_KEY request: -EPERM */
	send_raw_mauth(&c, 2, (const uint8_t *)"\x00\x01zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", 42);
	WRT_CHECK_U64(mc_nmsgs(&c), 6);
	WRT_CHECK(reply_at(&c, 5, &r));
	WRT_CHECK_U64((uint32_t)r.result, (uint32_t)-1);
	/* another session's ticket does not renew this one */
	WRT_CHECK(mc_init(&other, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&other, 0x24), MC_OK);
	mc_clear_frames(&other);
	mc_send_renew_ex(&other, 0x15, other.gid, &c.auth, &other.auth_key, 0);
	WRT_CHECK_U64(mc_nmsgs(&other), 1);
	WRT_CHECK(reply_at(&other, 0, &r));
	WRT_CHECK_U64((uint32_t)r.result, (uint32_t)-13);
	mc_send_renew(&other, 0x15); /* its own works */
	WRT_CHECK_U64(mc_nmsgs(&other), 2);
	WRT_CHECK(reply_at(&other, 1, &r));
	WRT_CHECK_U64(r.result, 0);
	mc_free(&other);
	/* tickets expired by the monitor: the renewal is refused too */
	sim_mon_expire_tickets(m);
	mc_clear_frames(&c);
	mc_send_renew(&c, 0x15);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(reply_at(&c, 0, &r));
	WRT_CHECK_U64((uint32_t)r.result, (uint32_t)-13);
	mc_free(&c);
	/* a silent monitor does not answer renewals */
	sim_mon_free(m);
	cfg.n_plans = 1;
	cfg.plans[0].silent = 1;
	m = mk(&cfg);
	login(m, &cfg, &c);
	mc_send_renew(&c, 0x15);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_U64(c.conn->n_auth_msgs, 1);
	mc_free(&c);
	sim_mon_free(m);
}

/* ---- restart -------------------------------------------------------------------------------------------------- */

static void restart(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc a, b, d;
	uint8_t drain[64];
	mc_msg g;
	const uint8_t *mb;
	size_t mbn;
	wri_monmap mm;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	login(m, &cfg, &a);
	login(m, &cfg, &d); /* two sessions: both are cut */
	mc_send_getmap(&a);
	sub1(&a, "osdmap", 0, 0);
	sub1(&a, "monmap", 0, 0);
	WRT_CHECK_U64(mc_nmsgs(&a), 3); /* MMonMap (GetMap), MOSDMap, MMonMap (the subscription) */
	WRT_CHECK_U64(m->monmap_epoch, 3);
	mc_clear_frames(&a);
	/* output still queued when the monitor goes down is never delivered */
	sub1(&d, "osdmap", 0, 1);
	WRT_CHECK(sim_m2_pending(d.conn->m2) != 0);
	sim_mon_restart(m);
	WRT_CHECK_U64(m->n_restarts, 1);
	WRT_CHECK_U64(m->monmap_epoch, 4);
	WRT_CHECK(sim_mon_closed(a.conn));
	WRT_CHECK(sim_mon_closed(d.conn));
	WRT_CHECK_U64(sim_mon_drain(d.conn, drain, sizeof(drain)), 0);
	WRT_CHECK_U64(sim_mon_feed(a.conn, (const uint8_t *)"x", 1), 0);
	WRT_CHECK_U64(sim_m2_error(a.conn->m2)->status, 0); /* a clean end for the client: EOF */
	WRT_CHECK_U64(mc_nmsgs(&d), 0);
	/* new sessions work, and reclaim the old global id with the old ticket (ticket_enc = 1) */
	WRT_CHECK(mc_init(&b, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&b, &a);
	WRT_CHECK_U64(mc_login(&b, 0x24), MC_OK);
	WRT_CHECK_U64(b.gid, a.gid);
	WRT_CHECK_U64(b.auth.enc, 1);
	WRT_CHECK_U64(m->n_reclaims, 1);
	mc_clear_frames(&b);
	/* the subscriptions died with the session; the monmap now has the next epoch, subscribed for held + 1 = 4 */
	mc_send_getmap(&b);
	sub1(&b, "monmap", 4, 0);
	WRT_CHECK_U64(mc_nmsgs(&b), 2);
	WRT_CHECK(mc_msg_at(&b, 0, &g));
	WRT_CHECK_STATUS(WR_OK, wri_mmonmap_front(g.front, g.flen, &mb, &mbn));
	WRT_CHECK_STATUS(WR_OK, wri_monmap_decode(mb, mbn, &mm));
	WRT_CHECK_U64(mm.epoch, 4);
	WRT_CHECK_U64(a.conn->n_osdmap_sent, 1);
	mc_free(&a);
	mc_free(&b);
	mc_free(&d);
	sim_mon_free(m);
	/* restart_keeps_epoch: the epoch stays, the sessions still go */
	cfg.restart_keeps_epoch = 1;
	m = mk(&cfg);
	login(m, &cfg, &a);
	sim_mon_restart(m);
	WRT_CHECK_U64(m->monmap_epoch, 3);
	WRT_CHECK(sim_mon_closed(a.conn));
	mc_free(&a);
	sim_mon_free(m);
}

/* ---- held maps, oversize, cuts, two clients ----------------------------------------------------------------------- */

static void held_maps(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	unsigned i;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	cfg.n_plans = 1;
	cfg.plans[0].hold_maps = 1; /* a slow monitor: maps are queued until released */
	m = mk(&cfg);
	login(m, &cfg, &c);
	mc_send_getmap(&c);
	sub1(&c, "osdmap", 0, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_U64(c.conn->n_held, 2);
	WRT_CHECK_U64(sim_mon_release(c.conn, 1), 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	WRT_CHECK_U64(g.h.type, 4); /* in the order they were produced: the MMonMap first */
	WRT_CHECK_U64(sim_mon_release(c.conn, 0), 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 2);
	WRT_CHECK(mc_msg_at(&c, 1, &g));
	WRT_CHECK_U64(g.h.type, 41);
	WRT_CHECK_U64(g.h.seq, 2);
	WRT_CHECK_U64(sim_mon_release(c.conn, 0), 0);
	/* the hold is bounded: more than SIM_MON_HELD messages are refused loudly, not dropped quietly */
	for (i = 0; i < SIM_MON_HELD + 2u; i++)
		mc_send_getmap(&c);
	mc_pull(&c);
	WRT_CHECK_U64(c.conn->n_held, SIM_MON_HELD);
	WRT_CHECK_STATUS(WR_E_BUDGET, c.conn->send_err);
	mc_free(&c);
	sim_mon_free(m);
}

static void oversize_front(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	wri_mosdmap_info info;

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.osdmap_pad = 100u * 1024u; /* still inside the client's 1 MiB cap: trailing zeros are ignored by a decoder */
	m = mk(&cfg);
	login(m, &cfg, &c);
	sub1(&c, "osdmap", 0, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	WRT_CHECK(g.flen > 100u * 1024u);
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(g.front, g.flen, g.h.version, &info));
	WRT_CHECK_U64(info.newest_map, 42);
	mc_free(&c);
	sim_mon_free(m);
	/* a front beyond what the client accepts for a segment: its frame parser refuses it */
	cfg.osdmap_pad = 2u << 20;
	m = mk(&cfg);
	login(m, &cfg, &c);
	sub1(&c, "osdmap", 0, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_TOOBIG, c.t.rx_err);
	mc_free(&c);
	sim_mon_free(m);
}

static void cuts_and_faults(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c, e;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	cfg.n_plans = 3;
	cfg.plans[0].close_after_msgs = 2;
	cfg.plans[1].has_fault = 1;
	cfg.plans[1].fault.corrupt_frame = 3; /* AUTH_DONE with a damaged CRC */
	cfg.plans[2].has_fault = 1;
	cfg.plans[2].fault.out_limit = 100; /* the stream ends inside the handshake */
	cfg.plans[2].fault.out_limit_close = 1;
	m = mk(&cfg);
	/* cut after two client messages: the answer to the second is never delivered, the first was */
	login(m, &cfg, &c);
	mc_send_getmap(&c);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	sub1(&c, "monmap", 0, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(sim_mon_closed(c.conn));
	WRT_CHECK(c.conn->killed);
	mc_free(&c);
	/* a sim_m2 fault of the connection: corrupt CRC of frame 3 */
	WRT_CHECK(mc_init(&e, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK(mc_login(&e, 0x24) != MC_OK);
	WRT_CHECK_STATUS(WR_E_M2_FRAME_CRC, e.t.rx_err);
	mc_free(&e);
	WRT_CHECK(mc_init(&e, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK(mc_login(&e, 0x24) != MC_OK);
	WRT_CHECK(sim_mon_closed(e.conn));
	mc_free(&e);
	/* beyond the plans: the default plan again */
	login(m, &cfg, &c);
	WRT_CHECK(!sim_mon_closed(c.conn));
	mc_free(&c);
	sim_mon_free(m);
}

/* Maps delivered one epoch per message, a byte at a time in both directions: nothing is lost or reordered. */
static void fragmented_maps(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	wri_mosdmap_info info;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	cfg.osd_map_message_max = 1;
	cfg.n_plans = 1;
	cfg.plans[0].has_fault = 1;
	cfg.plans[0].fault.out_chunk = 1;
	m = mk(&cfg);
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m)); /* epochs 42 and 43 are committed */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	c.t.feed_chunk = 1;
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	mc_clear_frames(&c);
	mc_send_getmap(&c);
	sub1(&c, "monmap", 0, 1);
	sub1(&c, "osdmap", 42, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 4);
	WRT_CHECK_U64(c.t.rx_err, 0);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	WRT_CHECK_U64(g.h.type, 4);
	WRT_CHECK(mc_msg_at(&c, 1, &g));
	WRT_CHECK_U64(g.h.type, 4);
	WRT_CHECK(mc_msg_at(&c, 2, &g));
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(g.front, g.flen, g.h.version, &info));
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK(mc_msg_at(&c, 3, &g));
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(g.front, g.flen, g.h.version, &info));
	WRT_CHECK_U64(info.first_epoch, 43);
	WRT_CHECK_U64(info.newest_map, 43);
	WRT_CHECK_U64(g.h.seq, 4);
	mc_free(&c);
	sim_mon_free(m);
}

static void two_clients(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc a, b;
	mc_msg g;
	wri_mosdmap_info info;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	login(m, &cfg, &a);
	login(m, &cfg, &b);
	WRT_CHECK(a.gid != b.gid);
	WRT_CHECK_U64(a.gid, 4100);
	WRT_CHECK_U64(b.gid, 4101);
	sub1(&a, "osdmap", 43, 0);
	sub1(&b, "osdmap", 43, 1);
	WRT_CHECK_U64(mc_nmsgs(&a) + mc_nmsgs(&b), 0);
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m)); /* both are served by one commit */
	WRT_CHECK_U64(mc_nmsgs(&a), 1);
	WRT_CHECK_U64(mc_nmsgs(&b), 1);
	WRT_CHECK(mc_msg_at(&b, 0, &g));
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(g.front, g.flen, g.h.version, &info));
	WRT_CHECK_U64(info.first_epoch, 43);
	WRT_CHECK_U64(m->n_osdmap_sent, 2);
	/* one going away does not disturb the other */
	sim_mon_conn_free(b.conn);
	b.conn = NULL;
	tc_free(&b.t);
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_push_epoch(m));
	WRT_CHECK_STATUS(WR_OK, sim_mon_send_message(a.conn, 99, 2, 1, (const uint8_t *)"hello", 5));
	WRT_CHECK_U64(mc_nmsgs(&a), 2);
	WRT_CHECK(mc_msg_at(&a, 1, &g));
	WRT_CHECK_U64(g.h.type, 99);
	WRT_CHECK_U64(g.h.priority, 196);
	WRT_CHECK_U64(g.h.version, 2);
	WRT_CHECK_U64(g.h.compat_version, 1);
	WRT_CHECK_U64(g.flen, 5);
	/* before the handshake finished there is no session to send on */
	{
		sim_mon_conn *raw = sim_mon_accept(m);

		WRT_CHECK(raw != NULL);
		WRT_CHECK_STATUS(WR_E_STATE, sim_mon_send_message(raw, 99, 1, 1, (const uint8_t *)"x", 1));
		sim_mon_conn_free(raw);
	}
	mc_free(&a);
	sim_mon_free(m);
}

int main(void)
{
	renewal(WR_KEY_TYPE_AES);
	renewal(WR_KEY_TYPE_AES256K);
	renewal_refusals();
	restart(WR_KEY_TYPE_AES);
	restart(WR_KEY_TYPE_AES256K);
	held_maps();
	oversize_front();
	cuts_and_faults();
	fragmented_maps();
	two_clients();
	return wrt_finish();
}
