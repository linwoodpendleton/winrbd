/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake monitor (harness/test/support/sim_mon*.{h,c}), part 1: the cephx handshake.
 * A scripted client (sim_mon_tc.h: m2-frame, m2-ctl, cephx-cipher and mon-msgs pieces, NOT the client
 * machines of the product) completes the monitor handshake with both key types and reads what a
 * monitor documents (docs/spec/cephx.md 2.7, 3.2, 3.4, 3.7, 3.8): the AUTH ticket reply under the
 * principal key, the connection-secret blob, `extra` with the OSD ticket (or a zero-length blob),
 * both AUTH_SIGNATURE frames, the refusals (-13 after the challenge, -95, silent close), reclaim of a
 * global id with ticket_enc = 1, ticket configuration (key types, validity, blob size, omitted services).
 * Messages are in test_sim_mon_msgs.c; renewal and fault hooks in test_sim_mon_faults.c.
 */
#include "sim_mon_tc.h"

#define SLOT_AUTH 5u
#define SLOT_OSD 2u

static sim_mon *mk(const sim_mon_cfg *cfg)
{
	sim_mon *m = sim_mon_new(cfg);

	WRT_CHECK(m != NULL);
	if (m == NULL)
		abort();
	return m;
}

/* ---- happy paths, both key types -------------------------------------------------------------------- */

static void login_ok(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	size_t ct;
	const sim_mon_issued *ia, *io;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	WRT_CHECK_STATUS(WR_OK, c.err);
	WRT_CHECK_U64(c.gid, 4100);
	WRT_CHECK_U64(c.conn_mode, 1);
	WRT_CHECK(c.sig_ok);
	WRT_CHECK_U64(c.conn->m2->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(c.conn->m2->global_id, 4100);
	WRT_CHECK_U64(m->n_logins, 1);
	/* the frames, in order: HELLO, AUTH_REPLY_MORE (the challenge, 13 bytes), AUTH_DONE, AUTH_SIGNATURE, SERVER_IDENT */
	WRT_CHECK_U64(c.t.nfr, 5);
	WRT_CHECK_U64(c.t.fr[0].tag, WRI_M2_TAG_HELLO);
	WRT_CHECK_U64(c.t.fr[1].tag, WRI_M2_TAG_AUTH_REPLY_MORE);
	WRT_CHECK_U64(c.t.fr[2].tag, WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(c.t.fr[3].tag, WRI_M2_TAG_AUTH_SIGNATURE);
	WRT_CHECK_U64(c.t.fr[4].tag, WRI_M2_TAG_SERVER_IDENT);
	WRT_CHECK(c.server_challenge != 0);
	/* the AUTH ticket: 72 h, a session key of the principal's own type, a 151-byte opaque blob */
	ia = &m->last[SLOT_AUTH];
	WRT_CHECK(c.auth.have && ia->have);
	WRT_CHECK_U64(c.auth.service, WRI_CX_SERVICE_AUTH);
	WRT_CHECK_U64(c.auth.validity_s, 259200);
	WRT_CHECK_U64(c.auth.validity_ns, 0);
	WRT_CHECK_U64(c.auth.enc, 0);
	WRT_CHECK_U64(c.auth.key.type, type);
	WRT_CHECK_U64(c.auth.key.len, type == WR_KEY_TYPE_AES ? 16 : 32);
	WRT_CHECK_MEM(c.auth.key.secret, ia->key.secret, c.auth.key.len);
	WRT_CHECK_U64(c.auth.blob_len, 151);
	WRT_CHECK_MEM(c.auth.blob, ia->blob, 151);
	WRT_CHECK_U64(c.auth.secret_id, ia->secret_id);
	WRT_CHECK(c.auth.secret_id != 0);
	WRT_CHECK(sim_mon_ticket_valid(m, WRI_CX_SERVICE_AUTH, c.auth.blob, c.auth.blob_len));
	c.auth.blob[3] ^= 1;
	WRT_CHECK(!sim_mon_ticket_valid(m, WRI_CX_SERVICE_AUTH, c.auth.blob, c.auth.blob_len));
	WRT_CHECK(!sim_mon_ticket_valid(m, WRI_CX_SERVICE_OSD, ia->blob, ia->blob_len));
	/* cbl: an encrypted empty string in crc mode (u32 inner length + ciphertext of 9 + 4 bytes) */
	ct = wri_cx_cipher_len(type, 13);
	WRT_CHECK_U64(c.secret_len, 0);
	WRT_CHECK_U64(c.done_cbl_len, 4 + ct);
	/* extra: one ticket, the OSD's, under the AUTH session key, 1 h */
	io = &m->last[SLOT_OSD];
	WRT_CHECK_U64(c.n_tickets_in_done, 2);
	WRT_CHECK(c.svc[SLOT_OSD].have && io->have);
	WRT_CHECK_U64(c.svc[SLOT_OSD].service, WRI_CX_SERVICE_OSD);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_s, 3600);
	WRT_CHECK_U64(c.svc[SLOT_OSD].enc, 0);
	WRT_CHECK_U64(c.svc[SLOT_OSD].key.type, type);
	WRT_CHECK_MEM(c.svc[SLOT_OSD].key.secret, io->key.secret, io->key.len);
	WRT_CHECK_U64(c.svc[SLOT_OSD].blob_len, 151);
	WRT_CHECK_MEM(c.svc[SLOT_OSD].blob, io->blob, 151);
	WRT_CHECK(!c.svc[0].have && !c.svc[4].have); /* no MON, no MGR ticket was asked for */
	WRT_CHECK(sim_mon_ticket_valid(m, WRI_CX_SERVICE_OSD, io->blob, io->blob_len));
	WRT_CHECK(memcmp(c.svc[SLOT_OSD].key.secret, c.auth.key.secret, c.auth.key.len) != 0);
	WRT_CHECK_U64(io->global_id, 4100);
	mc_free(&c);
	sim_mon_free(m);
}

static void login_masks(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	/* only AUTH asked for: `extra` is a zero-length blob (not a reply with zero tickets), the cbl is still there */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x20), MC_OK);
	WRT_CHECK_U64(c.done_extra_len, 0);
	WRT_CHECK_U64(c.n_tickets_in_done, 1);
	WRT_CHECK_U64(c.secret_len, 0);
	WRT_CHECK(!c.svc[SLOT_OSD].have);
	mc_free(&c);
	/* the stock client's second connection: MON, OSD, MGR and AUTH (0x35) -> exactly three more tickets */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x35), MC_OK);
	WRT_CHECK_U64(c.n_tickets_in_done, 4);
	WRT_CHECK(c.svc[0].have && c.svc[SLOT_OSD].have && c.svc[4].have && !c.svc[1].have);
	WRT_CHECK_U64(c.svc[0].service, 0x01);
	WRT_CHECK_U64(c.svc[4].service, 0x10);
	WRT_CHECK_U64(c.gid, 4101); /* the second new session: the next id */
	mc_free(&c);
	/* nothing asked for: no cbl, no extra */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0), MC_OK);
	WRT_CHECK_U64(c.done_cbl_len, 0xffffffffu);
	WRT_CHECK_U64(c.done_extra_len, 0xffffffffu);
	WRT_CHECK_U64(c.n_tickets_in_done, 1);
	mc_free(&c);
	sim_mon_free(m);
}

/* Frame sizes against the captured handshake of a stock client (msgr2/handshake-skeletons.json, connection 0: a monitor
 * connection that asked for the AUTH ticket only, key type aes256k): HELLO, AUTH_REPLY_MORE 13, AUTH_DONE 372. */
static void sizes_match_capture(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	wrt_json j;
	wrt_tok st;
	int k, ok = 0;

	WRT_CHECK(wrt_json_load_vec(&j, "msgr2/handshake-skeletons.json") == 0);
	st = wrt_json_at(&j, wrt_json_get(&j, wrt_json_at(&j, wrt_json_get(&j, wrt_json_root(&j), "connections"), 0), "streams"), 1);
	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x20), MC_OK);
	for (k = 0; k < 3 && k < (int)c.t.nfr; k++) {
		wrt_tok f = wrt_json_at(&j, wrt_json_get(&j, st, "frames"), (size_t)k);

		WRT_CHECK_U64(c.t.fr[k].tag, wrt_json_int(&j, wrt_json_get(&j, f, "tag"), &ok));
		WRT_CHECK_U64(c.t.fr[k].len[0], wrt_json_int(&j, wrt_json_at(&j, wrt_json_get(&j, f, "segment_lengths"), 0), &ok));
	}
	WRT_CHECK_U64(c.t.fr[2].len[0], 372);
	WRT_CHECK(ok);
	mc_free(&c);
	sim_mon_free(m);
	wrt_json_free(&j);
}

/* ---- refusals ---------------------------------------------------------------------------------------- */

static void expect_denied(mc *c, int32_t result)
{
	WRT_CHECK_U64(c->bm.method, 2);
	WRT_CHECK_U64((uint32_t)c->bm.result, (uint32_t)result);
	WRT_CHECK_U64(c->bm.n_methods, 1);
	WRT_CHECK_U64(c->bm.allowed_methods[0], 2);
	WRT_CHECK_U64(c->bm.n_modes, 2);
	WRT_CHECK_U64(c->bm.allowed_modes[0], 2);
	WRT_CHECK_U64(c->bm.allowed_modes[1], 1);
	WRT_CHECK(!sim_mon_closed(c->conn)); /* the connection stays: the client may try again */
}

static void wrong_key_and_friends(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	wr_key other;
	unsigned other_type = type == WR_KEY_TYPE_AES ? WR_KEY_TYPE_AES256K : WR_KEY_TYPE_AES;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	/* wrong key of the right type: HELLO, AUTH_REPLY_MORE (the challenge comes first), then BAD_METHOD -13 */
	mt_key(&other, type, 99);
	WRT_CHECK(mc_init(&c, m, &other, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	WRT_CHECK_U64(c.t.nfr, 3);
	WRT_CHECK_U64(c.t.fr[0].tag, WRI_M2_TAG_HELLO);
	WRT_CHECK_U64(c.t.fr[1].tag, WRI_M2_TAG_AUTH_REPLY_MORE);
	WRT_CHECK_U64(c.t.fr[2].tag, WRI_M2_TAG_AUTH_BAD_METHOD);
	expect_denied(&c, -13);
	WRT_CHECK_U64(m->n_denied, 1);
	WRT_CHECK_U64(m->n_logins, 0);
	mc_free(&c);
	/* a key of the other type */
	mt_key(&other, other_type, 1);
	WRT_CHECK(mc_init(&c, m, &other, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	expect_denied(&c, -13);
	mc_free(&c);
	/* unknown entity with a valid proof for the configured key: still -13 after the challenge */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "somebody") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	WRT_CHECK_U64(c.t.nfr, 3);
	expect_denied(&c, -13);
	mc_free(&c);
	/* a mode byte outside 10..19: an access error at once, no challenge */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	c.mode_byte = 9;
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	WRT_CHECK_U64(c.t.nfr, 2);
	expect_denied(&c, -13);
	mc_free(&c);
	sim_mon_free(m);
	/* a key type the monmap does not allow, whatever the proof */
	cfg.allowed_key_types = 1u << other_type;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	expect_denied(&c, -13);
	mc_free(&c);
	sim_mon_free(m);
}

static void plans_and_garbage(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	tb p;
	size_t before;
	uint8_t buf[64];

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	/* connection 0: -EBUSY style (silent close at AUTH_REQUEST); 1: -95 at once; 2: denied whatever the key (-1 set); 3 normal */
	cfg.n_plans = 3;
	cfg.plans[0].auth = SIM_MON_AUTH_BUSY;
	cfg.plans[1].auth = SIM_MON_AUTH_BAD_METHOD;
	cfg.plans[2].auth = SIM_MON_AUTH_DENY;
	cfg.plans[2].auth_result = -1;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_CLOSED);
	WRT_CHECK_U64(c.t.nfr, 1); /* only HELLO */
	WRT_CHECK(sim_mon_closed(c.conn));
	WRT_CHECK_U64(sim_m2_error(c.conn->m2)->status, 0); /* not a protocol error: a quiet close */
	WRT_CHECK_U64(sim_mon_feed(c.conn, (const uint8_t *)"x", 1), 0);
	WRT_CHECK_U64(m->n_busy, 1);
	mc_free(&c);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD);
	WRT_CHECK_U64(c.t.nfr, 2); /* HELLO, BAD_METHOD: no challenge */
	WRT_CHECK_U64((uint32_t)c.bm.result, (uint32_t)-95);
	mc_free(&c);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_BAD_METHOD); /* correct key, refused all the same, after the challenge */
	WRT_CHECK_U64(c.t.nfr, 3);
	WRT_CHECK_U64((uint32_t)c.bm.result, (uint32_t)-1);
	mc_free(&c);
	/* connection 3 follows plan_default: normal; a second AUTH_REQUEST on the same connection is a new attempt */
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login_ex(&c, 0x24, 1), MC_OK); /* stops after the challenge */
	WRT_CHECK_U64(c.conn->stage, 1);
	/* AUTH_REQUEST_MORE that cannot be decoded: -EPERM (-1), not -EACCES */
	p.n = 0;
	tb_u32(&p, 5);
	memset(buf, 0x55, sizeof(buf));
	tb_bytes(&p, buf, 5);
	before = c.t.nfr;
	(void)tc_send_ctl(&c.t, c.conn->m2, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	mc_pull(&c);
	WRT_CHECK(c.t.nfr == before + 1u && c.t.fr[before].tag == WRI_M2_TAG_AUTH_BAD_METHOD);
	if (c.t.nfr == before + 1u) {
		wri_rd r;
		wri_m2_bad_method bm;

		wri_rd_init(&r, c.t.fr[before].seg[0], c.t.fr[before].len[0]);
		WRT_CHECK_STATUS(WR_OK, wri_m2_bad_method_decode(&r, &bm));
		WRT_CHECK_U64((uint32_t)bm.result, (uint32_t)-1);
	}
	mc_free(&c);
	sim_mon_free(m);
}

/* ---- reclaim -------------------------------------------------------------------------------------------- */

static void reclaim(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc a, b, d;
	uint8_t first_blob[SIM_MON_BLOB_MAX];

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&a, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&a, 0x24), MC_OK);
	memcpy(first_blob, a.auth.blob, a.auth.blob_len);
	/* the same id again, proving it with the first AUTH ticket: same id, the new blob comes as ticket_enc = 1 */
	WRT_CHECK(mc_init(&b, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&b, &a);
	WRT_CHECK_U64(mc_login(&b, 0x24), MC_OK);
	WRT_CHECK_STATUS(WR_OK, b.err);
	WRT_CHECK_U64(b.gid, a.gid);
	WRT_CHECK_U64(b.auth.enc, 1);
	WRT_CHECK_U64(b.svc[SLOT_OSD].enc, 0); /* the other tickets are never encrypted twice */
	WRT_CHECK(memcmp(b.auth.blob, first_blob, 151) != 0);
	WRT_CHECK(memcmp(b.auth_key.secret, a.auth_key.secret, b.auth_key.len) != 0);
	WRT_CHECK_U64(m->n_reclaims, 1);
	WRT_CHECK_U64(m->last[SLOT_AUTH].reissued, 1);
	WRT_CHECK_U64(m->n_logins, 2);
	/* a client that does not hold the previous session key cannot read the blob */
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&d, &a);
	d.have_prev = 0;
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_ERR);
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, d.err);
	mc_free(&d);
	/* refusals: no ticket, a damaged one, somebody else's id, an id nobody holds */
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	d.want_gid = a.gid;
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_BAD_METHOD);
	expect_denied(&d, -13);
	mc_free(&d);
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&d, &a);
	d.old_blob[10] ^= 0x40;
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_BAD_METHOD);
	expect_denied(&d, -13);
	mc_free(&d);
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&d, &a);
	d.want_gid = a.gid + 1u;
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_BAD_METHOD);
	expect_denied(&d, -13);
	mc_free(&d);
	/* a superfluous old ticket on a first contact is an error too */
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&d, &a);
	d.want_gid = 0;
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_BAD_METHOD);
	expect_denied(&d, -13);
	mc_free(&d);
	/* tickets that expired (the rotating key rolled): the reclaim is refused, a fresh login is not */
	sim_mon_expire_tickets(m);
	WRT_CHECK(!sim_mon_ticket_valid(m, WRI_CX_SERVICE_AUTH, b.auth.blob, b.auth.blob_len));
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&d, &b);
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_BAD_METHOD);
	expect_denied(&d, -13);
	mc_free(&d);
	WRT_CHECK(mc_init(&d, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&d, 0x24), MC_OK);
	WRT_CHECK(sim_mon_ticket_valid(m, WRI_CX_SERVICE_AUTH, d.auth.blob, d.auth.blob_len));
	mc_free(&d);
	mc_free(&a);
	mc_free(&b);
	sim_mon_free(m);
}

/* ---- ticket configuration ---------------------------------------------------------------------------------- */

static void ticket_config(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	sim_mon *m2 = NULL;
	mc c;
	size_t i;
	uint8_t fixed[32];

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	/* a type-1 AUTH session key wrapped by a type-2 principal key, an OSD session key of type 2 under it
	 * (cephx.md 3.4: msg_a of type X wraps a session key of type Y) */
	cfg.tkt[SLOT_AUTH].key_type = WR_KEY_TYPE_AES;
	cfg.tkt[SLOT_OSD].key_type = WR_KEY_TYPE_AES256K;
	cfg.tkt[SLOT_OSD].validity_s = 60; /* short TTLs for renewal tests */
	cfg.tkt[SLOT_OSD].validity_ns = 500000000u;
	cfg.tkt[SLOT_OSD].blob_len = 200;
	cfg.tkt[SLOT_OSD].secret_id = 99;
	for (i = 0; i < sizeof(fixed); i++)
		fixed[i] = (uint8_t)(0xa0 + i);
	cfg.tkt[SLOT_OSD].key_len = 32;
	memcpy(cfg.tkt[SLOT_OSD].key, fixed, 32);
	cfg.tkt[SLOT_AUTH].validity_s = 120;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	WRT_CHECK_U64(c.auth.key.type, WR_KEY_TYPE_AES);
	WRT_CHECK_U64(c.auth.key.len, 16);
	WRT_CHECK_U64(c.auth.validity_s, 120);
	WRT_CHECK_U64(c.svc[SLOT_OSD].key.type, WR_KEY_TYPE_AES256K);
	WRT_CHECK_MEM(c.svc[SLOT_OSD].key.secret, fixed, 32);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_s, 60);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_ns, 500000000u);
	WRT_CHECK_U64(c.svc[SLOT_OSD].blob_len, 200);
	WRT_CHECK_U64(c.svc[SLOT_OSD].secret_id, 99);
	WRT_CHECK(c.sig_ok); /* the pre-auth signature uses the type-1 AUTH session key */
	mc_free(&c);
	sim_mon_free(m);

	/* an OSD ticket the monitor forgets: `extra` is empty even though OSD was asked for */
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.omit_services = WRI_CX_SERVICE_OSD;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	WRT_CHECK(!c.svc[SLOT_OSD].have);
	WRT_CHECK_U64(c.done_extra_len, 0);
	mc_free(&c);
	sim_mon_free(m);

	/* the generator is seeded: the same seed, the same session keys and challenge; another seed, other ones */
	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	{
		sim_mon *ms[3];
		uint8_t keys[3][32];
		uint64_t chal[3];
		unsigned k;

		ms[0] = mk(&cfg);
		ms[1] = mk(&cfg);
		cfg.seed = 7;
		ms[2] = mk(&cfg);
		for (k = 0; k < 3; k++) {
			WRT_CHECK(mc_init(&c, ms[k], &cfg.key, "winrbd") == 0);
			WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
			memcpy(keys[k], c.auth.key.secret, 32);
			chal[k] = c.server_challenge;
			mc_free(&c);
			sim_mon_free(ms[k]);
		}
		WRT_CHECK_MEM(keys[1], keys[0], 32);
		WRT_CHECK_U64(chal[1], chal[0]);
		WRT_CHECK(memcmp(keys[2], keys[0], 32) != 0);
		WRT_CHECK(chal[2] != chal[0]);
	}
	(void)m2;
}

/* ---- byte-at-a-time both ways, and bad configuration ----------------------------------------------------------- */

static void one_byte_chunks(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;

	mt_cfg(&cfg, type);
	cfg.n_plans = 1;
	cfg.plans[0].has_fault = 1;
	cfg.plans[0].fault.out_chunk = 1;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	c.t.feed_chunk = 1;
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	WRT_CHECK(c.sig_ok);
	WRT_CHECK(c.svc[SLOT_OSD].have);
	WRT_CHECK_U64(c.t.rx_err, 0);
	mc_free(&c);
	sim_mon_free(m);
}

static void bad_config(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.key.len = 15; /* shorter than a type-1 key */
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.n_plans = SIM_MON_MAX_PLANS + 1u;
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.user[0] = '\0';
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	WRT_CHECK(sim_mon_new(NULL) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.tkt[SLOT_OSD].blob_len = 8; /* below the 16 bytes a ticket blob needs: the login fails loudly, not silently */
	m = mk(&cfg);
	{
		mc c;

		WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
		WRT_CHECK(mc_login(&c, 0x24) != MC_OK);
		WRT_CHECK_STATUS(WR_E_RANGE, m->build_err);
		mc_free(&c);
	}
	sim_mon_free(m);
	/* the connection table is bounded */
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	m = mk(&cfg);
	{
		sim_mon_conn *cs[SIM_MON_MAX_CONNS];
		unsigned i;

		for (i = 0; i < SIM_MON_MAX_CONNS; i++) {
			cs[i] = sim_mon_accept(m);
			WRT_CHECK(cs[i] != NULL);
		}
		WRT_CHECK(sim_mon_accept(m) == NULL);
		sim_mon_conn_free(cs[3]);
		cs[3] = sim_mon_accept(m);
		WRT_CHECK(cs[3] != NULL);
		WRT_CHECK_U64(m->n_accepted, SIM_MON_MAX_CONNS + 1u);
	}
	sim_mon_free(m); /* frees the connections still open */
}


/* ---- hostile input: every length from the network, the proof, the issued-ticket memory ---------------------------- */

/* HELLO exchange only, so a test can put any payload into AUTH_REQUEST. */
static int raw_hello(mc *c)
{
	tb p;
	size_t before;

	tc_pull(&c->t, c->conn->m2);
	if (!c->t.got_banner)
		return -1;
	(void)tc_send_banner(&c->t, c->conn->m2, 1, 0);
	tc_pay_hello(&p, SIM_M2_ENT_CLIENT, 3300);
	(void)tc_send_ctl(&c->t, c->conn->m2, WRI_M2_TAG_HELLO, &p);
	before = c->t.nfr;
	tc_pull(&c->t, c->conn->m2);
	return mc_find(c, before, WRI_M2_TAG_HELLO) != NULL ? 0 : -1;
}

/* What the monitor answered to the frame sent after `before`: the AUTH_BAD_METHOD result, 1000 + tag for any other
 * frame, 0 for no frame at all. */
static int32_t answer_after(mc *c, size_t before)
{
	const tc_frame *f;
	wri_rd r;

	mc_pull(c);
	if (c->t.nfr == before)
		return 0;
	f = &c->t.fr[before];
	if (f->tag != WRI_M2_TAG_AUTH_BAD_METHOD)
		return 1000 + (int32_t)f->tag;
	wri_rd_init(&r, f->seg[0], f->len[0]);
	if (wri_m2_bad_method_decode(&r, &c->bm) != WR_OK)
		return 999;
	return c->bm.result;
}

static int32_t send_auth_request(mc *c, const uint8_t *pl, size_t n)
{
	tb p;
	size_t before = c->t.nfr;

	p.n = 0;
	tb_u32(&p, 2);
	tb_u32(&p, 1);
	tb_u32(&p, 1);
	tb_u32(&p, (uint32_t)n);
	tb_bytes(&p, pl, n);
	(void)tc_send_ctl(&c->t, c->conn->m2, WRI_M2_TAG_AUTH_REQUEST, &p);
	return answer_after(c, before);
}

static int32_t send_auth_more(mc *c, const uint8_t *pl, size_t n)
{
	tb p;
	size_t before = c->t.nfr;

	p.n = 0;
	tb_u32(&p, (uint32_t)n);
	tb_bytes(&p, pl, n);
	(void)tc_send_ctl(&c->t, c->conn->m2, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	return answer_after(c, before);
}

static void auth_request_payload(tb *pl, uint8_t mode, uint32_t idlen_claim, const char *user, size_t user_n)
{
	pl->n = 0;
	tb_u8(pl, mode);
	tb_u32(pl, 8);
	tb_u32(pl, idlen_claim);
	tb_bytes(pl, user, user_n);
	tb_u64(pl, 0);
}

/* A CephXAuthenticate request; `mut` says what to break. */
enum { M_NONE, M_V1, M_V0, M_REQ_PRINCIPAL, M_OLEN_HUGE, M_OLEN_OVER_MAX, M_TRAILING, M_PROOF_BIT };

static void auth_more_payload(mc *c, tb *pl, int mut, unsigned bit, uint32_t want)
{
	uint64_t proof = 0;

	if (wri_cx_challenge_proof(&c->x, &c->key, c->server_challenge, c->client_challenge, &proof) != WR_OK)
		abort();
	if (mut == M_PROOF_BIT)
		proof ^= 1ull << bit;
	pl->n = 0;
	tb_bytes(pl, mut == M_REQ_PRINCIPAL ? "\x00\x02" : "\x00\x01", 2);
	tb_u8(pl, mut == M_V1 ? 1 : mut == M_V0 ? 0 : 3);
	tb_u64(pl, c->client_challenge);
	tb_u64(pl, proof);
	tb_u8(pl, 1);
	tb_u64(pl, 0);
	tb_u32(pl, mut == M_OLEN_HUGE ? 0xffffffffu : mut == M_OLEN_OVER_MAX ? SIM_MON_BLOB_MAX + 1u : 0u);
	if (mut == M_OLEN_OVER_MAX)
		tb_fill(pl, 0, SIM_MON_BLOB_MAX + 1u);
	if (mut != M_V1 && mut != M_V0)
		tb_u32(pl, want);
	if (mut == M_TRAILING)
		tb_u8(pl, 0);
}

static void hostile_auth(unsigned type)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	tb pl;
	size_t k, full;
	static const char user[] = "winrbd";
	int mut;
	unsigned bit;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	/* AUTH_REQUEST cut at every length, with a lying name length, and with a byte too many: -EPERM, never a crash */
	auth_request_payload(&pl, 10, 6, user, 6);
	full = pl.n;
	for (k = 0; k < full; k++) {
		tb cut;

		WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && raw_hello(&c) == 0);
		cut.n = 0;
		tb_bytes(&cut, pl.b, k);
		WRT_CHECK_U64((uint32_t)send_auth_request(&c, cut.b, cut.n), (uint32_t)-1);
		WRT_CHECK(!sim_mon_closed(c.conn));
		mc_free(&c);
	}
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && raw_hello(&c) == 0);
	auth_request_payload(&pl, 10, 6, user, 6);
	tb_u8(&pl, 0);
	WRT_CHECK_U64((uint32_t)send_auth_request(&c, pl.b, pl.n), (uint32_t)-1);
	mc_free(&c);
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && raw_hello(&c) == 0);
	auth_request_payload(&pl, 10, 0xffffffffu, user, 6);
	WRT_CHECK_U64((uint32_t)send_auth_request(&c, pl.b, pl.n), (uint32_t)-1);
	mc_free(&c);
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && raw_hello(&c) == 0);
	auth_request_payload(&pl, 19, 6, user, 6); /* 19 is still a monitor mode, 20 is not */
	WRT_CHECK_U64(send_auth_request(&c, pl.b, pl.n), 1000 + WRI_M2_TAG_AUTH_REPLY_MORE);
	mc_free(&c);
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && raw_hello(&c) == 0);
	auth_request_payload(&pl, 20, 6, user, 6);
	WRT_CHECK_U64((uint32_t)send_auth_request(&c, pl.b, pl.n), (uint32_t)-13);
	mc_free(&c);
	/* AUTH_REQUEST_MORE cut at every length: -EPERM */
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && mc_login_ex(&c, 0x24, 1) == MC_OK);
	auth_more_payload(&c, &pl, M_NONE, 0, 0x24);
	full = pl.n;
	mc_free(&c);
	for (k = 0; k < full; k++) {
		WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && mc_login_ex(&c, 0x24, 1) == MC_OK);
		auth_more_payload(&c, &pl, M_NONE, 0, 0x24);
		WRT_CHECK_U64((uint32_t)send_auth_more(&c, pl.b, k), (uint32_t)-1);
		mc_free(&c);
	}
	/* the other ways to break it, each on a fresh connection: -EPERM too */
	for (mut = M_V1; mut <= M_TRAILING; mut++) {
		WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && mc_login_ex(&c, 0x24, 1) == MC_OK);
		auth_more_payload(&c, &pl, mut, 0, 0x24);
		WRT_CHECK_U64((uint32_t)send_auth_more(&c, pl.b, pl.n), (uint32_t)-1);
		/* and the same request again, now that the attempt is over: the msgr2 layer wants a new AUTH_REQUEST first, so
		 * this is a protocol violation, answered with nothing and a closed connection */
		auth_more_payload(&c, &pl, M_NONE, 0, 0x24);
		WRT_CHECK_U64(send_auth_more(&c, pl.b, pl.n), 0);
		WRT_CHECK(sim_mon_closed(c.conn));
		WRT_CHECK_U64(m->n_logins, 0);
		mc_free(&c);
	}
	/* the proof is all-or-nothing: every single flipped bit is refused (-13), the right one is accepted */
	for (bit = 0; bit < 64; bit++) {
		WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && mc_login_ex(&c, 0x24, 1) == MC_OK);
		auth_more_payload(&c, &pl, M_PROOF_BIT, bit, 0x24);
		WRT_CHECK_U64((uint32_t)send_auth_more(&c, pl.b, pl.n), (uint32_t)-13);
		mc_free(&c);
	}
	WRT_CHECK_U64(m->n_logins, 0);
	WRT_CHECK(mc_init(&c, m, &cfg.key, user) == 0 && mc_login_ex(&c, 0x24, 1) == MC_OK);
	auth_more_payload(&c, &pl, M_NONE, 0, 0x24);
	WRT_CHECK_U64(send_auth_more(&c, pl.b, pl.n), 1000 + WRI_M2_TAG_AUTH_DONE);
	WRT_CHECK_U64(m->n_logins, 1);
	mc_free(&c);
	sim_mon_free(m);
}

/* Reclaim needs the AUTH ticket in the monitor's memory: it must not fall out after a handful of other logins. */
static void reclaim_after_many_logins(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc first, other, again;
	unsigned i;

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&first, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&first, 0x24), MC_OK);
	for (i = 0; i < SIM_MON_ISSUED / 4u; i++) { /* 2 tickets each: the first one is still among the newest SIM_MON_ISSUED */
		WRT_CHECK(mc_init(&other, m, &cfg.key, "winrbd") == 0);
		WRT_CHECK_U64(mc_login(&other, 0x24), MC_OK);
		mc_free(&other);
	}
	WRT_CHECK(mc_init(&again, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&again, &first);
	WRT_CHECK_U64(mc_login(&again, 0x24), MC_OK);
	WRT_CHECK_U64(again.gid, first.gid);
	WRT_CHECK_U64(again.auth.enc, 1);
	mc_free(&again);
	/* the memory IS bounded: a ticket pushed out of it by newer ones is refused like an expired one */
	for (i = 0; i < SIM_MON_ISSUED; i++) {
		WRT_CHECK(mc_init(&other, m, &cfg.key, "winrbd") == 0);
		WRT_CHECK_U64(mc_login(&other, 0x24), MC_OK);
		mc_free(&other);
	}
	WRT_CHECK(mc_init(&again, m, &cfg.key, "winrbd") == 0);
	mc_reclaim_from(&again, &first);
	WRT_CHECK_U64(mc_login(&again, 0x24), MC_BAD_METHOD);
	mc_free(&again);
	mc_free(&first);
	sim_mon_free(m);
}

/* A ticket with validity 0 (cephx.md 3.5: a client must treat it as an error) can be asked for. */
static void zero_validity(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.tkt[SLOT_OSD].zero_validity = 1;
	cfg.tkt[SLOT_OSD].validity_s = 77; /* ignored */
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	WRT_CHECK(c.svc[SLOT_OSD].have);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_s, 0);
	WRT_CHECK_U64(c.svc[SLOT_OSD].validity_ns, 0);
	WRT_CHECK_U64(c.auth.validity_s, 259200); /* the AUTH ticket was not asked to be broken */
	mc_free(&c);
	sim_mon_free(m);
}

/* Messages from a hostile client: nothing but the documented counters moves, and the monitor still serves afterwards. */
static uint64_t fz_next(uint64_t *s)
{
	*s ^= *s >> 12;
	*s ^= *s << 25;
	*s ^= *s >> 27;
	return *s * 0x2545f4914f6cdd1dull;
}

static void hostile_messages(unsigned type)
{
	static const uint32_t counts[] = {0, 1, 2, 3, 31, 32, 33, 255, 0x7fffffffu, 0xffffffffu};
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	uint64_t rng = 0x9e3779b97f4a7c15ull + type;
	unsigned it, k;
	uint8_t f[320];
	size_t n;
	uint32_t before_getmap;
	mc_msg g;

	mt_cfg(&cfg, type);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	for (it = 0; it < 1500; it++) {
		uint64_t r = fz_next(&rng);
		static const uint16_t types[] = {4, 5, 15, 17, 41, 99, 16, 2, 6, 19};
		uint16_t t = types[(r >> 8) % (sizeof(types) / sizeof(types[0]))];

		n = (size_t)(fz_next(&rng) % sizeof(f));
		for (k = 0; k < n; k++)
			f[k] = (uint8_t)(fz_next(&rng) >> 24);
		if (t == 15 && n >= 4) { /* a plausible subscribe: a count from the nasty list, then noise */
			wri_le32_put(f, counts[(r >> 16) % (sizeof(counts) / sizeof(counts[0]))]);
		} else if (t == 17 && n >= 18u + 8u + 4u) { /* a plausible MAuth: paxos prefix, protocol, payload length, payload, epoch */
			memset(f, 0, 18);
			wri_le32_put(f + 18, (r >> 20) % 3u == 0 ? 1u : 2u);
			wri_le32_put(f + 22, (r >> 24) % 2u != 0 ? (uint32_t)(n - 30u) : counts[(r >> 28) % (sizeof(counts) / sizeof(counts[0]))]);
		}
		if (t == 5 || t == 4 || t == 41)
			n = (r >> 40) % 2u != 0 ? 0 : n; /* a GetMap carries no body, a monitor-only type is simply ignored */
		mc_send(&c, t, f, (uint32_t)n);
		if (it % 16u == 15u) {
			mc_pull(&c);
			mc_clear_frames(&c);
		}
	}
	mc_pull(&c);
	WRT_CHECK_U64(sim_m2_error(c.conn->m2)->status, 0);
	WRT_CHECK(!sim_mon_closed(c.conn));
	WRT_CHECK_U64(c.t.rx_err, 0);
	WRT_CHECK_U64(c.conn->n_msgs, 1500);
	WRT_CHECK(c.conn->n_malformed > 0);
	WRT_CHECK_U64(m->n_logins, 1);
	/* and it still answers what is valid */
	mc_clear_frames(&c);
	before_getmap = c.conn->n_getmap;
	mc_send_getmap(&c);
	WRT_CHECK_U64(c.conn->n_getmap, before_getmap + 1u);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	WRT_CHECK_U64(g.h.type, 4);
	mc_free(&c);
	sim_mon_free(m);
}

/* Subscribe names and counts that a stock client never sends but a monitor accepts. */
static void odd_subscribe(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;
	tb p;
	unsigned i;
	mc_msg g;
	static const char longname[] = "a-subscription-name-longer-than-sixteen";

	mt_cfg(&cfg, WR_KEY_TYPE_AES256K);
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK_U64(mc_login(&c, 0x24), MC_OK);
	mc_clear_frames(&c);
	/* a long name, a name with a NUL inside that starts like "monmap", then osdmap ONETIME: the long name is ignored
	 * as any unknown name is, the NUL one is NOT "monmap", and the osdmap subscription is served */
	p.n = 0;
	tb_u32(&p, 3);
	tb_u32(&p, (uint32_t)strlen(longname)), tb_bytes(&p, longname, strlen(longname)), tb_u64(&p, 0), tb_u8(&p, 0);
	tb_u32(&p, 8), tb_bytes(&p, "monmap\0x", 8), tb_u64(&p, 0), tb_u8(&p, 0);
	tb_u32(&p, 6), tb_bytes(&p, "osdmap", 6), tb_u64(&p, 0), tb_u8(&p, 1u /* ONETIME */);
	tb_u32(&p, 5), tb_bytes(&p, "host1", 5);
	mc_send(&c, 15, p.b, (uint32_t)p.n);
	WRT_CHECK_U64(c.conn->n_malformed, 0);
	WRT_CHECK_U64(c.conn->n_subscribe, 1);
	WRT_CHECK_U64(c.conn->n_last_sub, 3);
	WRT_CHECK_U64(strlen(c.conn->last_sub[0].name), 15);
	WRT_CHECK(strcmp(c.conn->last_sub[1].name, "monmap?x") == 0);
	WRT_CHECK(!c.conn->sub_monmap.active);
	WRT_CHECK_U64(mc_nmsgs(&c), 1);
	WRT_CHECK(mc_msg_at(&c, 0, &g));
	WRT_CHECK_U64(g.h.type, 41);
	/* a name cut at 15 bytes must not become "osdmap" either: its first 15 bytes are not the whole name */
	mc_clear_frames(&c);
	p.n = 0;
	tb_u32(&p, 1);
	tb_u32(&p, 20), tb_bytes(&p, "osdmap\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 20), tb_u64(&p, 0), tb_u8(&p, 0);
	tb_u32(&p, 0);
	mc_send(&c, 15, p.b, (uint32_t)p.n);
	WRT_CHECK_U64(mc_nmsgs(&c), 0);
	/* the most items we keep, and one more: both decode (a monitor takes any number) up to the limit we store */
	p.n = 0;
	tb_u32(&p, SIM_MON_SUBS);
	for (i = 0; i < SIM_MON_SUBS; i++) {
		tb_u32(&p, 3), tb_bytes(&p, "x", 1), tb_bytes(&p, "0", 1), tb_bytes(&p, "1", 1), tb_u64(&p, i), tb_u8(&p, 0);
	}
	tb_u32(&p, 0);
	mc_send(&c, 15, p.b, (uint32_t)p.n);
	WRT_CHECK_U64(c.conn->n_last_sub, SIM_MON_SUBS);
	WRT_CHECK_U64(c.conn->n_malformed, 0);
	p.n = 0;
	tb_u32(&p, SIM_MON_SUBS + 1u);
	for (i = 0; i < SIM_MON_SUBS + 1u; i++) {
		tb_u32(&p, 3), tb_bytes(&p, "x", 1), tb_bytes(&p, "0", 1), tb_bytes(&p, "1", 1), tb_u64(&p, i), tb_u8(&p, 0);
	}
	tb_u32(&p, 0);
	mc_send(&c, 15, p.b, (uint32_t)p.n);
	WRT_CHECK_U64(c.conn->n_malformed, 1); /* more than the monitor keeps: dropped and counted, like any undecodable one */
	mc_free(&c);
	sim_mon_free(m);
}

/* The map store: limits and a failed insert that changes nothing. */
static void store_limits(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	uint8_t blob[40];
	uint32_t e;
	uint8_t mm[40];

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.no_default_osdmaps = 1;
	m = mk(&cfg);
	WRT_CHECK_U64(m->n_maps, 0);
	memset(blob, 0xab, sizeof(blob));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 0, blob, 10, NULL, 0));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 5, NULL, 0, NULL, 0));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 5, blob, 0, NULL, 0));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 5, NULL, 0, blob, 0));
	WRT_CHECK_STATUS(WR_E_RANGE, sim_mon_add_epoch(m, 5, blob, (33u << 20), NULL, 0));
	WRT_CHECK_U64(m->n_maps, 0);
	for (e = SIM_MON_MAX_EPOCHS; e >= 1; e--) /* descending: every insert shifts the table */
		WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, e, NULL, 0, blob, sizeof(blob)));
	WRT_CHECK_U64(m->n_maps, SIM_MON_MAX_EPOCHS);
	for (e = 1; e <= SIM_MON_MAX_EPOCHS; e++)
		WRT_CHECK_U64(m->maps[e - 1u].epoch, e);
	WRT_CHECK_STATUS(WR_E_BUDGET, sim_mon_add_epoch(m, SIM_MON_MAX_EPOCHS + 1u, NULL, 0, blob, sizeof(blob)));
	WRT_CHECK_STATUS(WR_E_BUDGET, sim_mon_add_epoch(m, 0x7fffffffu, blob, sizeof(blob), NULL, 0));
	WRT_CHECK_U64(m->n_maps, SIM_MON_MAX_EPOCHS);
	/* a full table still takes a new part for an epoch it holds, and keeps the other part */
	WRT_CHECK_STATUS(WR_OK, sim_mon_add_epoch(m, 10, blob, 20, NULL, 0));
	WRT_CHECK(m->maps[9].full != NULL && m->maps[9].inc != NULL);
	WRT_CHECK_U64(m->maps[9].full_len, 20);
	WRT_CHECK_U64(m->maps[9].inc_len, sizeof(blob));
	sim_mon_free(m);
	/* a configured monmap: too short is refused, a minimal one is served with its epoch */
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	memset(mm, 0, sizeof(mm));
	cfg.monmap = mm;
	cfg.monmap_len = 25;
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	cfg.monmap_len = 26;
	wri_le32_put(mm + 22, 9);
	cfg.no_default_osdmaps = 1;
	m = mk(&cfg);
	WRT_CHECK_U64(m->monmap_epoch, 9);
	WRT_CHECK_STATUS(WR_OK, sim_mon_bump_monmap(m));
	WRT_CHECK_U64(wri_le32_get(m->monmap + 22), 10);
	WRT_CHECK_U64(wri_le32_get(mm + 22), 9); /* the caller's buffer is a copy source only */
	sim_mon_free(m);
	/* more bad configuration */
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.osd_map_message_max = 0;
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.osdmap_pad = (64u << 20) + 1u;
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	memset(cfg.user, 'u', sizeof(cfg.user)); /* no terminator */
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.key.type = 3;
	WRT_CHECK(sim_mon_new(&cfg) == NULL);
}

/* A session key that cannot be built (a configured key longer than WR_KEY_MAX, a key type that does not exist) closes the
 * login loudly instead of handing out garbage. */
static void bad_ticket_keys(void)
{
	sim_mon_cfg cfg;
	sim_mon *m;
	mc c;

	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.tkt[SLOT_OSD].key_len = 200;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK(mc_login(&c, 0x24) != MC_OK);
	WRT_CHECK(m->build_err != WR_OK);
	mc_free(&c);
	sim_mon_free(m);
	mt_cfg(&cfg, WR_KEY_TYPE_AES);
	cfg.tkt[SLOT_OSD].key_type = 7;
	m = mk(&cfg);
	WRT_CHECK(mc_init(&c, m, &cfg.key, "winrbd") == 0);
	WRT_CHECK(mc_login(&c, 0x24) != MC_OK);
	WRT_CHECK_STATUS(WR_E_AUTH_KEY_TYPE, m->build_err);
	WRT_CHECK(sim_mon_closed(c.conn));
	mc_free(&c);
	sim_mon_free(m);
}

int main(void)
{
	login_ok(WR_KEY_TYPE_AES);
	login_ok(WR_KEY_TYPE_AES256K);
	login_masks();
	sizes_match_capture();
	wrong_key_and_friends(WR_KEY_TYPE_AES);
	wrong_key_and_friends(WR_KEY_TYPE_AES256K);
	plans_and_garbage();
	reclaim(WR_KEY_TYPE_AES);
	reclaim(WR_KEY_TYPE_AES256K);
	ticket_config();
	one_byte_chunks(WR_KEY_TYPE_AES);
	one_byte_chunks(WR_KEY_TYPE_AES256K);
	bad_config();
	hostile_auth(WR_KEY_TYPE_AES);
	hostile_auth(WR_KEY_TYPE_AES256K);
	reclaim_after_many_logins();
	zero_validity();
	hostile_messages(WR_KEY_TYPE_AES);
	hostile_messages(WR_KEY_TYPE_AES256K);
	odd_subscribe();
	store_limits();
	bad_ticket_keys();
	return wrt_finish();
}
