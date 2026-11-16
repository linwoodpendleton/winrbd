/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake monitor, part 2: the monitor messages (docs/spec/mon-client.md 2.2 to 2.6, 3.3 to 3.5).
 * MMonGetMap and the "monmap" subscription give the two MMonMap of a fresh session, byte for byte the
 * vector mmonmap-e3; the "osdmap" subscription gives MOSDMap v4 messages built from the vectors
 * (mosdmap-v4-full-e42 for start 0, the synthetic incremental vector for later starts) following the table
 * of 3.5.1: start 0, start N, start older than the store, start in the future, continuous versus ONETIME,
 * the epochs per message, a hole, a full map where no incremental is stored, a pushed epoch. Headers carry
 * what a real monitor sends (priority 196, flags 3, MMonMap 1/1, MOSDMap 4/3). Unknown subscription names
 * are ignored, a malformed subscribe is dropped, a silent plan answers nothing.
 */
#include "sim_mon_tc.h"

static sim_mon *mk(const sim_mon_cfg *cfg)
{
	sim_mon *m = sim_mon_new(cfg);

	if (m == NULL) {
		fprintf(stderr, "sim_mon_new failed\n");
		abort();
	}
	return m;
}

/* A client logged in on the monitor, the frames of the handshake forgotten. */
static void login(sim_mon *m, const sim_mon_cfg *cfg, mc *c)
{
	if (mc_init(c, m, &cfg->key, "winrbd") != 0 || mc_login(c, 0x24) != MC_OK) {
		fprintf(stderr, "login failed\n");
		abort();
	}
	mc_clear_frames(c);
}

static uint8_t *vec_hex(const char *rel, const char *key, size_t *n)
{
	wrt_json j;
	uint8_t *b = NULL;

	WRT_CHECK(wrt_json_load_vec(&j, rel) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, wrt_json_root(&j), key, &b, n) == 0);
	wrt_json_free(&j);
	return b;
}

static void check_hdr(const mc_msg *g, uint16_t type, uint16_t version, uint16_t compat)
{
	WRT_CHECK_U64(g->h.type, type);
	WRT_CHECK_U64(g->h.version, version);
	WRT_CHECK_U64(g->h.compat_version, compat);
	WRT_CHECK_U64(g->h.priority, 196); /* what a monitor sends (mon-client.md 2.1) */
	WRT_CHECK_U64(g->h.flags, 3);
	WRT_CHECK_U64(g->h.tid, 0);
	WRT_CHECK_U64(g->h.data_off, 0);
}

static void sub1(mc *c, const char *what, uint64_t start, uint8_t flags)
{
	wri_sub_item it;

	it.what = what, it.start = start, it.flags = flags;
	mc_send_subscribe(c, &it, 1);
}

/* the k-th message as an MOSDMap: header checked, fields decoded */
static int osd_msg(mc *c, size_t k, wri_mosdmap_info *info, mc_msg *g)
{
	if (!mc_msg_at(c, k, g))
		return 0;
	check_hdr(g, 41, 4, 3);
	WRT_CHECK_STATUS(WR_OK, wri_mosdmap_info_decode(g->front, g->flen, g->h.version, info));
	return 1;
}

/* ---- MMonMap -------------------------------------------------------------------------------------------- */

static void monmap_messages(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	size_t fn, mn;
	uint8_t *front = vec_hex("monclient/mmonmap-e3.json", "front_hex", &fn), *blob = vec_hex("monclient/mmonmap-e3.json", "monmap_hex", &mn);
	wri_monmap mm;
	const uint8_t *mb;
	size_t mbn;
	wri_sub_item it;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	login(m, &cfg, &c);
	/* a fresh session sends MMonGetMap and the first MMonSubscribe together: two MMonMap come back */
	mc_send_getmap(&c);
	it.what = "monmap", it.start = 0, it.flags = 0;
	mc_send_subscribe(&c, &it, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 2);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	check_hdr(&g, 4, 1, 1);
	WRT_CHECK_U64(g.h.seq, 1);
	WRT_CHECK_U64(g.h.ack_seq, 1); /* the first of ours had been received */
	WRT_CHECK_U64(g.flen, fn);
	WRT_CHECK_MEM(g.front, front, fn); /* byte for byte the captured MMonMap */
	WRT_CHECK_STATUS(WR_OK, wri_mmonmap_front(g.front, g.flen, &mb, &mbn));
	WRT_CHECK_U64(mbn, mn);
	WRT_CHECK_MEM(mb, blob, mn);
	WRT_CHECK_STATUS(WR_OK, wri_monmap_decode(mb, mbn, &mm));
	WRT_CHECK_U64(mm.epoch, 3);
	WRT_CHECK_U64(mm.n_mons, 1);
	WRT_CHECK(mm.rank_valid[0]);
	WRT_CHECK(mc_msg_at(&c, 1, &g));
	check_hdr(&g, 4, 1, 1);
	WRT_CHECK_U64(g.h.seq, 2);
	WRT_CHECK_U64(g.h.ack_seq, 2);
	WRT_CHECK_MEM(g.front, front, fn); /* the second one is the same map: handling it must be idempotent */
	WRT_CHECK_U64(c.conn->n_getmap, 1);
	WRT_CHECK_U64(c.conn->n_subscribe, 1);
	WRT_CHECK_U64(c.conn->n_last_sub, 1);
	WRT_CHECK(strcmp(c.conn->last_sub[0].name, "monmap") == 0);
	WRT_CHECK_U64(c.conn->last_sub[0].start, 0);
	WRT_CHECK(strcmp(c.conn->last_host, "host1") == 0);
	WRT_CHECK_U64(c.conn->n_monmap_sent, 2);
	WRT_CHECK_U64(sim_m2_error(c.conn->m2)->status, 0);
	/* the subscription is continuous: a new epoch is pushed (the blob carries the new epoch) */
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	WRT_CHECK(mc_msg_at(&c, 2, &g));
	check_hdr(&g, 4, 1, 1);
	WRT_CHECK_STATUS(WR_OK, wri_mmonmap_front(g.front, g.flen, &mb, &mbn));
	WRT_CHECK_STATUS(WR_OK, wri_monmap_decode(mb, mbn, &mm));
	WRT_CHECK_U64(mm.epoch, 4);
	WRT_CHECK_U64(c.conn->sub_monmap.start, 5); /* held epoch + 1 */
	mc_free(&c);

	/* a reconnect after a restart subscribes with held + 1 = 4: MMonGetMap is answered, the subscription is not (yet) */
	login(m, &cfg, &c);
	mc_send_getmap(&c);
	sub1(&c, "monmap", 5, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 2);
	/* ONETIME (the same name again replaces the continuous one): served once, then gone */
	sub1(&c, "monmap", 0, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(m));
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	WRT_CHECK(!c.conn->sub_monmap.active);
	mc_free(&c);
	free(front);
	free(blob);
	sim_mon_free(m);
}

/* ---- MOSDMap ---------------------------------------------------------------------------------------------- */

static void osdmap_start0(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	wri_mosdmap_info info;
	size_t fn;
	uint8_t *front = vec_hex("monclient/mosdmap-v4-full-e42.json", "front_hex", &fn);

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	login(m, &cfg, &c);
	sub1(&c, "osdmap", 0, 1); /* ONETIME, start 0: what the stock client sends */
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(g.flen, fn);
	WRT_CHECK_MEM(g.front, front, fn); /* byte for byte the captured MOSDMap: one full map, epoch 42 */
	WRT_CHECK_U64(info.n_full, 1);
	WRT_CHECK_U64(info.n_incremental, 0);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK_U64(info.last_epoch, 42);
	WRT_CHECK_U64(info.newest_map, 42);
	WRT_CHECK_U64(info.oldest_map, 1);
	WRT_CHECK_MEM(info.fsid, m->fsid, 16);
	WRT_CHECK(!c.conn->sub_osdmap.active); /* ONETIME: gone */
	/* committing epoch 43 pushes nothing to it */
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_push_epoch(m)); /* nothing stored for 44 */
	/* start 0 again: epoch 43 has only an incremental, so the reply is the latest full map plus what follows it */
	sub1(&c, "osdmap", 0, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 2);
	WRT_CHECK(osd_msg(&c, 1, &info, &g));
	WRT_CHECK_U64(info.n_full, 1);
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK_U64(info.last_epoch, 43);
	WRT_CHECK_U64(info.newest_map, 43);
	mc_free(&c);
	free(front);
	sim_mon_free(m);
}

static void osdmap_from_n(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	wri_mosdmap_info info;
	size_t fn;
	uint8_t *inc_front = vec_hex("monclient/mosdmap-v4-inc-e42-e43-synthetic.json", "front_hex", &fn);

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	login(m, &cfg, &c);
	/* start 43 while the newest committed epoch is 42: nothing yet; committing 43 serves it, ONETIME ends it */
	sub1(&c, "osdmap", 43, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK(c.conn->sub_osdmap.active);
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.n_full, 0);
	WRT_CHECK_U64(info.first_epoch, 43);
	WRT_CHECK_U64(info.newest_map, 43);
	WRT_CHECK(!c.conn->sub_osdmap.active);
	mc_clear_frames(&c);
	/* start 42 inside the store: the incrementals of 42 and 43 in one message, byte for byte the synthetic vector */
	sub1(&c, "osdmap", 42, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(g.flen, fn);
	WRT_CHECK_MEM(g.front, inc_front, fn);
	WRT_CHECK_U64(info.n_incremental, 2);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK_U64(info.last_epoch, 43);
	mc_clear_frames(&c);
	/* older than anything stored: the first full map alone, then the incrementals after it (two messages for ONETIME) */
	sub1(&c, "osdmap", 10, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 2);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(info.n_full, 1);
	WRT_CHECK_U64(info.n_incremental, 0);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK(osd_msg(&c, 1, &info, &g));
	WRT_CHECK_U64(info.n_full, 0);
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.first_epoch, 43);
	WRT_CHECK(!c.conn->sub_osdmap.active);
	mc_clear_frames(&c);
	/* start in the future: nothing, then served when the epoch exists; a continuous one stays and follows the next */
	sub1(&c, "osdmap", 44, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 44, NULL, 0, inc_front + 16 + 4 + 8, 100)); /* any incremental bytes */
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(info.first_epoch, 44);
	WRT_CHECK_U64(info.last_epoch, 44);
	WRT_CHECK_U64(info.newest_map, 44);
	WRT_CHECK(c.conn->sub_osdmap.active);
	WRT_CHECK_U64(c.conn->sub_osdmap.start, 45);
	/* a full map where no incremental is stored, an incremental after it */
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 45, inc_front + 16 + 4 + 8, 90, NULL, 0));
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 46, NULL, 0, inc_front + 30, 50));
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	WRT_CHECK(osd_msg(&c, 1, &info, &g));
	WRT_CHECK_U64(info.n_full, 1);
	WRT_CHECK_U64(info.first_epoch, 45);
	WRT_CHECK(osd_msg(&c, 2, &info, &g));
	WRT_CHECK_U64(info.n_incremental, 1);
	WRT_CHECK_U64(info.first_epoch, 46);
	/* the same name again replaces the subscription (one entry, new start) */
	sub1(&c, "osdmap", 46, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 4);
	WRT_CHECK(!c.conn->sub_osdmap.active);
	/* a hole in the store ends the run: epoch 48 has nothing, 47 is served, 49 never */
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 47, NULL, 0, inc_front + 16 + 4 + 8, 80));
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 49, NULL, 0, inc_front + 16 + 4 + 8, 80));
	WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_push_epoch(m)); /* 48 is the hole */
	mc_free(&c);
	free(inc_front);
	sim_mon_free(m);
}

static void osdmap_chunks(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	mc_msg g;
	wri_mosdmap_info info;
	uint8_t blob[64];
	uint32_t e;

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.osd_map_message_max = 3; /* a message holds at most three epochs */
	m = mk(&cfg);
	memset(blob, 0x77, sizeof(blob));
	for (e = 44; e <= 51; e++) {
		WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, e, NULL, 0, blob, sizeof(blob)));
		WRT_CHECK_STATUS(WR_OK, sim_mon_push_epoch(m)); /* 43 is committed first by the loop's first push */
	}
	WRT_CHECK_U64(m->osd_newest, 50); /* 43 .. 50 committed (the loop's first push committed 43) */
	login(m, &cfg, &c);
	/* continuous from 42: chunks of three epochs up to 50 (42..44, 45..47, 48..50), the subscription waits for 51 */
	sub1(&c, "osdmap", 42, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 3);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(info.n_incremental, 3);
	WRT_CHECK_U64(info.first_epoch, 42);
	WRT_CHECK_U64(info.last_epoch, 44);
	WRT_CHECK(osd_msg(&c, 2, &info, &g));
	WRT_CHECK_U64(info.first_epoch, 48);
	WRT_CHECK_U64(info.last_epoch, 50);
	WRT_CHECK_U64(info.newest_map, 50);
	WRT_CHECK(c.conn->sub_osdmap.active);
	WRT_CHECK_U64(c.conn->sub_osdmap.start, 51);
	mc_clear_frames(&c);
	/* ONETIME gets one chunk and is removed even though more epochs exist */
	sub1(&c, "osdmap", 42, 1);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(osd_msg(&c, 0, &info, &g));
	WRT_CHECK_U64(info.last_epoch, 44);
	WRT_CHECK(!c.conn->sub_osdmap.active);
	mc_free(&c);
	sim_mon_free(m);
	/* an empty store (no default maps): nothing to send, nothing sent, nothing crashes */
	cfg.no_default_osdmaps = 1;
	m = mk(&cfg);
	login(m, &cfg, &c);
	sub1(&c, "osdmap", 0, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_push_epoch(m));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 0, blob, 10, NULL, 0));
	mc_free(&c);
	sim_mon_free(m);
}

/* ---- odd clients ---------------------------------------------------------------------------------------------- */

static void odd_clients(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	wri_sub_item it[3];
	uint8_t bad[5] = {2, 0, 0, 0, 9};

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	cfg.n_plans = 1;
	cfg.plans[0].silent = 1; /* connection 0 never answers */
	m = mk(&cfg);
	login(m, &cfg, &c);
	mc_send_getmap(&c);
	sub1(&c, "osdmap", 0, 0);
	sub1(&c, "monmap", 0, 0);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_U64(c.conn->n_getmap, 1);
	WRT_CHECK_U64(c.conn->n_subscribe, 2); /* recorded all the same */
	WRT_CHECK_U64(c.conn->m2->n_msgs, 3);
	mc_free(&c);
	/* connection 1: the names a stock client adds are ignored, a malformed subscribe is dropped and counted */
	login(m, &cfg, &c);
	it[0].what = "config", it[0].start = 0, it[0].flags = 0;
	it[1].what = "mgrmap", it[1].start = 0, it[1].flags = 0;
	it[2].what = "weird", it[2].start = 5, it[2].flags = 1;
	mc_send_subscribe(&c, it, 3);
	mc_send(&c, 15, bad, sizeof(bad));
	mc_send(&c, 6, NULL, 0); /* MMonGetOSDMap: not served here, counted */
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	WRT_CHECK_U64(c.conn->n_subscribe, 1);
	WRT_CHECK_U64(c.conn->n_last_sub, 3);
	WRT_CHECK(strcmp(c.conn->last_sub[2].name, "weird") == 0);
	WRT_CHECK_U64(c.conn->last_sub[2].flags, 1);
	WRT_CHECK_U64(c.conn->n_malformed, 1);
	WRT_CHECK_U64(c.conn->n_other, 1);
	WRT_CHECK_U64(sim_m2_error(c.conn->m2)->status, 0);
	/* keepalives are answered by the msgr2 layer under it */
	{
		wri_m2_seg_src seg;
		uint8_t stamp[8] = {1, 0, 0, 0, 2, 0, 0, 0};
		size_t before = c.t.nfr;

		seg.p = stamp, seg.len = 8, seg.ref = 0;
		(void)tc_send(&c.t, c.conn->m2, WRI_M2_TAG_KEEPALIVE2, &seg, 1);
		mc_pull(&c);
		WRT_CHECK_U64(c.t.nfr, before + 1u);
		WRT_CHECK(c.t.nfr == before + 1u && c.t.fr[before].tag == WRI_M2_TAG_KEEPALIVE2_ACK);
		WRT_CHECK(c.t.nfr == before + 1u && memcmp(c.t.fr[before].seg[0], stamp, 8) == 0);
	}
	mc_free(&c);
	sim_mon_free(m);
}

int main(void)
{
	monmap_messages(WR_KEY_TYPE_AES);
	monmap_messages(WR_KEY_TYPE_AES256K);
	osdmap_start0(WR_KEY_TYPE_AES);
	osdmap_start0(WR_KEY_TYPE_AES256K);
	osdmap_from_n();
	osdmap_chunks();
	odd_clients();
	return wrt_finish();
}
