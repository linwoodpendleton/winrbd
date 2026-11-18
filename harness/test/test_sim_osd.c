/* SPDX-License-Identifier: MIT */
/*
 * Self-test of the fake OSD (harness/test/support/sim_osd*.{h,c}), part 1: the connection and the fault hooks. A hand-driven client
 * (sim_osd_rig.h: its own MOSDOp encoder, reply decoder and authorizer builder, NOT the product's client modules) walks what docs/spec/cephx.md
 * 3.3 / 3.8 and osd-ops.md 2.9 to 3.8 describe from the server's side:
 *   - the OSD cephx handshake against the tickets of a sim_mon, both key types: the challenge round trip, AUTH_DONE with nonce + 1, the signatures;
 *     every refusal (-13, methods [2], modes [1, 2]): a foreign, expired or another client's ticket, a wrong challenge answer, a changed nonce, a key
 *     without OSD caps (after the round trip);
 *   - message framing (header version / compat / priority of the reply, segments) and sequence number enforcement;
 *   - every fault hook of sim_osd_fault: silence, dropped replies with the write applied and the resend answered from the dedup log (and no_dedup),
 *     the abrupt cut, EAGAIN, redirect, forced errno, held replies released in order and reversed, a reply with a damaged length, min_epoch,
 *     the full pool, epoch parking, the primary check, v8-only features;
 *   - requests the real OSD would crash on or could not decode close the connection (violations); every single-byte change and every truncation of
 *     a valid front is thrown at it (it never crashes, answers or closes);
 *   - MOSDBackoff BLOCK / ACK / UNBLOCK with the hobject ordering, MOSDMap pushes, restart (the dedup log survives), the dedup log shared by two OSDs,
 *     the connection limit, a 4 MiB write and read.
 * The operations themselves are in test_sim_osd_ops.c and the object classes in test_sim_osd_cls.c.
 */
#include "sim_osd_rig.h"

#define POOL OR_POOL

static void up(ore *e, orc *c, unsigned type)
{
	ore_prep(e, type);
	ore_start(e);
	orc_up(c, e);
}

static void down(ore *e, orc *c)
{
	orc_free(c);
	ore_free(e);
}

static uint32_t n_recs(ore *e)
{
	uint32_t n;

	(void)sim_osd_recs(e->osd, &n);
	return n;
}

static const sim_osd_rec *rec_at(ore *e, uint32_t i)
{
	uint32_t n;
	const sim_osd_rec *r = sim_osd_recs(e->osd, &n);

	return i < n ? &r[i] : &r[0];
}

static const sim_osd_rec *last_rec(ore *e)
{
	uint32_t n;
	const sim_osd_rec *r = sim_osd_recs(e->osd, &n);

	return &r[n != 0 ? n - 1u : 0u];
}

/* a write of `n` bytes of pattern `v` at `off` */
static or_req wreq(const char *oid, uint64_t off, uint8_t *buf, uint32_t n, uint8_t v)
{
	or_req r;

	memset(buf, v, n);
	or_req_init(&r, POOL, oid);
	or_req_add(&r, or_write(off, buf, n));
	return r;
}

/* ---- the handshake ----------------------------------------------------------------------------------------------------------- */

static void handshake_ok(unsigned type)
{
	ore e;
	orc c;
	sim_m2 *s;
	int rc;

	ore_prep(&e, type);
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	WRT_CHECK(sim_osd_n_conns_accepted(e.osd) == 1u);
	rc = orc_open(&c);
	WRT_CHECK_U64(rc, OR_OK);
	WRT_CHECK(c.sig_ok);
	WRT_CHECK(c.challenge != 0);
	s = sim_osd_conn_m2(c.conn);
	WRT_CHECK_U64(s->state, SIM_M2_ST_READY);
	WRT_CHECK_U64(s->global_id, e.gid);        /* the identity of the session is the one of the ticket */
	WRT_CHECK_U64(s->conn_mode, 1);
	WRT_CHECK_U64(s->cfg.entity_type, SIM_M2_ENT_OSD);
	WRT_CHECK_U64(s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST], 1);      /* one authorizer, then the same one again with the answer */
	WRT_CHECK_U64(s->n_rx_by_tag[WRI_M2_TAG_AUTH_REQUEST_MORE], 1);
	WRT_CHECK_U64(s->n_rx_by_tag[WRI_M2_TAG_AUTH_SIGNATURE], 1);
	WRT_CHECK_U64(s->n_rx_by_tag[WRI_M2_TAG_CLIENT_IDENT], 1);
	WRT_CHECK_U64(c.version, 9);                                    /* SERVER_SQUID advertised */
	WRT_CHECK_U64(c.srv_supported, 0x3f07fffffffdffffull);
	WRT_CHECK_U64(e.okey.type, type);
	/* the ticket worked again: a second connection of the same client, with the same nonce */
	{
		orc c2;

		orc_init(&c2, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c2), OR_OK);
		WRT_CHECK_U64(sim_osd_n_conns_accepted(e.osd), 2);
		orc_free(&c2);
	}
	orc_free(&c);
	ore_free(&e);
}

static void refusal(unsigned tamper, int upto_second, const char *what)
{
	ore e;
	orc c;
	int rc;

	(void)what;
	ore_prep(&e, WR_KEY_TYPE_AES256K);
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	c.tamper = tamper;
	rc = orc_open(&c);
	WRT_CHECK_U64(rc, OR_BAD_METHOD);
	WRT_CHECK(c.bm.result == -13);
	WRT_CHECK(c.bm.n_methods == 1u && c.bm.allowed_methods[0] == 2u);
	WRT_CHECK(c.bm.n_modes == 2u && c.bm.allowed_modes[0] == 1u && c.bm.allowed_modes[1] == 2u);
	WRT_CHECK(upto_second ? c.challenge != 0 : c.challenge == 0); /* the challenge went out first, or not */
	WRT_CHECK(!c.ready);
	/* the next connection with nothing wrong is accepted: nothing is remembered about the refusal */
	{
		orc c2;

		orc_init(&c2, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c2), OR_OK);
		orc_free(&c2);
	}
	orc_free(&c);
	ore_free(&e);
}

static void refusals(void)
{
	ore e;
	orc c;

	refusal(OR_T_FOREIGN_TICKET, 0, "a ticket this monitor did not issue");
	refusal(OR_T_WRONG_GID, 0, "another client's global id in the authorizer");
	refusal(OR_T_WRONG_KEY, 0, "a proof sealed with another key");
	refusal(OR_T_NO_CHALLENGE_STEP, 0, "a first authorizer that already answers a challenge");
	refusal(OR_T_WRONG_PLUS_ONE, 1, "a wrong challenge answer");
	refusal(OR_T_CHANGED_NONCE, 1, "another nonce in the second authorizer");
	/* a method other than cephx */
	ore_prep(&e, WR_KEY_TYPE_AES);
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	c.tamper = OR_T_METHOD;
	{
		int rc = orc_open(&c);

		WRT_CHECK(rc == OR_BAD_METHOD || rc == OR_CLOSED);
		if (rc == OR_BAD_METHOD)
			WRT_CHECK(c.bm.result == -95 || c.bm.result == -13);
	}
	orc_free(&c);
	/* a ticket the monitor stopped accepting (expired): refused at the first authorizer; a new login makes a good one */
	sim_mon_expire_tickets(e.mon);
	orc_init(&c, &e, e.osd);
	WRT_CHECK_U64(orc_open(&c), OR_BAD_METHOD);
	WRT_CHECK(c.bm.result == -13);
	orc_free(&c);
	{
		mc l2;
		const mt_ticket *t;
		orc c2;

		WRT_CHECK(mc_init(&l2, e.mon, &e.login.key, "winrbd") == 0);
		WRT_CHECK_U64(mc_login(&l2, 0x24), MC_OK);
		t = &l2.svc[OR_OSD_SLOT];
		e.okey = t->key;
		memcpy(e.blob, t->blob, t->blob_len);
		e.blob_len = t->blob_len;
		e.secret_id = t->secret_id;
		e.gid = l2.gid;
		orc_init(&c2, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c2), OR_OK);
		orc_free(&c2);
		mc_free(&l2);
	}
	/* the AUTH ticket is not an OSD ticket: the service in the authorizer is 4 but the blob belongs to service 0x20 */
	{
		orc c3;
		const mt_ticket *a = &e.login.auth;

		memcpy(e.blob, a->blob, a->blob_len);
		e.blob_len = a->blob_len;
		e.secret_id = a->secret_id;
		e.okey = a->key;
		orc_init(&c3, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c3), OR_BAD_METHOD);
		orc_free(&c3);
	}
	ore_free(&e);
	/* a key without OSD caps: the round trip is completed, then -13 */
	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.fault.refuse_auth = 1;
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	WRT_CHECK_U64(orc_open(&c), OR_BAD_METHOD);
	WRT_CHECK(c.challenge != 0);
	WRT_CHECK(c.bm.result == -13);
	WRT_CHECK(c.bm.n_modes == 2u && c.bm.allowed_modes[0] == 1u && c.bm.allowed_modes[1] == 2u);
	sim_osd_faults(e.osd)->refuse_auth = 0;
	{
		orc c2;

		orc_init(&c2, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c2), OR_OK);
		orc_free(&c2);
	}
	orc_free(&c);
	ore_free(&e);
}

/* ---- framing and sequence numbers ---------------------------------------------------------------------------------------------- */

static void framing(void)
{
	ore e;
	orc c;
	or_req r;
	uint8_t buf[64];
	const or_reply *p;
	const sim_osd_rec *rec;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	r = wreq("obj-a", 0, buf, 64, 0x11);
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok);
	if (p == NULL || !p->ok) {
		down(&e, &c);
		return;
	}
	WRT_CHECK_U64(p->version, 8);
	WRT_CHECK_U64(p->compat, 2);
	WRT_CHECK_U64(p->priority, 127);
	WRT_CHECK_U64(p->tid, 1);
	WRT_CHECK_U64(c.msg[0].seq, 1);
	WRT_CHECK_U64(c.msg[0].nseg, 2);       /* a reply without data has two segments: header and front */
	WRT_CHECK(strcmp(p->oid, "obj-a") == 0);
	WRT_CHECK_U64(p->pool, POOL);
	WRT_CHECK_U64(p->seed, 0x12345678u % 32u);
	WRT_CHECK_U64(p->epoch, 42);           /* no map of its own: the request's epoch comes back */
	WRT_CHECK_U64(p->flags, 0x08400024u | 1u);
	r = or_one("obj-a", or_read(0, 64));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->dlen == 64u);
	WRT_CHECK_U64(c.msg[1].nseg, 4);       /* with data: four segments, the middle one empty */
	WRT_CHECK_U64(c.msg[1].seq, 2);
	WRT_CHECK_U64(p->flags, 0x08400014u | 1u);
	rec = last_rec(&e);
	WRT_CHECK_U64(rec->version, 9);
	WRT_CHECK_U64(rec->tid, 2);
	WRT_CHECK_U64(rec->global_id, e.gid);
	WRT_CHECK(strcmp(rec->oid, "obj-a") == 0);
	WRT_CHECK_U64(rec->n_ops, 1);
	WRT_CHECK_U64(rec->op_code[0], 0x1201);
	WRT_CHECK_U64(rec->op_len[0], 64);
	WRT_CHECK_U64(rec->epoch, 42);
	WRT_CHECK(rec->executed && !rec->duplicate && !rec->dropped_reply && !rec->mutating);
	WRT_CHECK_U64(rec->result, 0);
	WRT_CHECK_U64(rec_at(&e, 0)->mutating, 1);
	/* a v8 request is decoded as well (an OSD without SERVER_SQUID asks for it) */
	r = or_one("obj-a", or_read(0, 64));
	r.no_otel = 1;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->dlen == 64u);
	WRT_CHECK_U64(last_rec(&e)->version, 8);
	/* the retry flag and attempt are echoed */
	r = or_one("obj-a", or_read(0, 64));
	r.retry = 3;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->retry == 3);
	WRT_CHECK_U64(last_rec(&e)->retry_attempt, 3);
	WRT_CHECK_U64(sim_osd_n_violations(e.osd), 0);
	down(&e, &c);
}

static void seq_rules(void)
{
	ore e;
	orc c;
	or_req r;
	sim_m2 *s;

	up(&e, &c, WR_KEY_TYPE_AES);
	r = or_one("o", or_stat());
	(void)orc_send(&c, &r, 0);
	/* the next message skips a number: the connection is closed (a lossy session does not tolerate gaps) */
	{
		uint8_t *front = (uint8_t *)malloc(4096), *data = (uint8_t *)malloc(64);
		uint32_t dl = 0, fl = or_encode(&r, 9, front, 4096, data, 64, &dl);

		orc_send_raw(&c, 42, 9, 3, 2, front, fl, NULL, 0, data, dl, 5);
		free(front);
		free(data);
	}
	orc_pull(&c);
	s = sim_osd_conn_m2(c.conn);
	WRT_CHECK_STATUS(WR_E_M2_SEQ, sim_m2_error(s)->status);
	WRT_CHECK(sim_osd_closed(c.conn));
	WRT_CHECK(orc_find(&c, 2, 43) == NULL);
	WRT_CHECK_U64(sim_osd_n_requests(e.osd), 1);
	down(&e, &c);
	/* the same number twice */
	up(&e, &c, WR_KEY_TYPE_AES);
	r = or_one("o", or_stat());
	(void)orc_send(&c, &r, 0);
	{
		uint8_t *front = (uint8_t *)malloc(4096), *data = (uint8_t *)malloc(64);
		uint32_t dl = 0, fl = or_encode(&r, 9, front, 4096, data, 64, &dl);

		orc_send_raw(&c, 42, 9, 3, 2, front, fl, NULL, 0, data, dl, 1);
		free(front);
		free(data);
	}
	WRT_CHECK_STATUS(WR_E_M2_SEQ, sim_m2_error(sim_osd_conn_m2(c.conn))->status);
	down(&e, &c);
	/* with the stock policy a duplicate is skipped silently and the connection stops being read */
	ore_prep(&e, WR_KEY_TYPE_AES);
	e.cfg.m2.seq_policy = SIM_M2_SEQ_STOCK;
	ore_start(&e);
	orc_up(&c, &e);
	r = or_one("o", or_stat());
	(void)orc_send(&c, &r, 0);
	WRT_CHECK_U64(sim_osd_n_requests(e.osd), 1);
	orc_send_raw(&c, 42, 9, 3, 7, NULL, 0, NULL, 0, NULL, 0, 1);
	WRT_CHECK_U64(sim_osd_conn_m2(c.conn)->n_seq_dups, 1);
	down(&e, &c);
}

/* ---- fault hooks -------------------------------------------------------------------------------------------------------------- */

static void fault_silent(void)
{
	ore e;
	orc c;
	or_req r;
	uint8_t buf[100];
	uint64_t t1;
	const sim_osd_rec *rec;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->silent = 1;
	r = wreq("obj-s", 0, buf, 100, 0x31);
	t1 = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t1) == NULL);
	rec = last_rec(&e);
	WRT_CHECK(!rec->executed && rec->result == INT32_MIN && rec->mutating);
	WRT_CHECK(!sim_store_exists(e.store, POOL, "obj-s"));          /* nothing was done either */
	WRT_CHECK_U64(sim_osd_n_requests(e.osd), 1);
	sim_osd_faults(e.osd)->silent = 0;
	r.retry = 1;
	WRT_CHECK(orc_send(&c, &r, t1) == t1);                          /* the same tid, as a resend */
	{
		const or_reply *p = orc_reply(&c, t1);

		WRT_CHECK(p != NULL && p->ok && p->result == 0 && p->retry == 1);
	}
	WRT_CHECK(sim_store_exists(e.store, POOL, "obj-s"));
	WRT_CHECK(last_rec(&e)->executed && !last_rec(&e)->duplicate);
	sim_osd_recs_clear(e.osd);
	WRT_CHECK_U64(n_recs(&e), 0);
	down(&e, &c);
}

static void fault_drop_replies(void)
{
	ore e;
	orc c;
	or_req r, rd;
	uint8_t buf[100];
	uint64_t t1;
	uint64_t v0;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->drop_replies = 1;
	r = wreq("obj-d", 0, buf, 100, 0x41);
	t1 = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t1) == NULL);
	WRT_CHECK(last_rec(&e)->executed && last_rec(&e)->dropped_reply && last_rec(&e)->result == 0);
	WRT_CHECK(sim_store_exists(e.store, POOL, "obj-d"));            /* applied, the answer is lost */
	v0 = sim_store_version(e.store, POOL, "obj-d");
	WRT_CHECK(sim_store_dedup_has(e.store, e.gid, t1));
	WRT_CHECK_U64(sim_store_dedup_count(e.store), 1);
	/* the resend: recognised, answered with the stored result, applied once */
	r.retry = 1;
	WRT_CHECK(orc_send(&c, &r, t1) == t1);
	{
		const or_reply *p = orc_reply(&c, t1);

		WRT_CHECK(p != NULL && p->ok && p->result == 0 && p->retry == 1 && p->n_ops == 1u && p->rval[0] == 0 && p->dlen == 0);
		if (p != NULL)
			WRT_CHECK(p->replay_ver != 0 && p->user_version == v0);
	}
	WRT_CHECK(last_rec(&e)->duplicate && !last_rec(&e)->executed);
	WRT_CHECK_U64(sim_store_version(e.store, POOL, "obj-d"), v0);
	/* a different data buffer under the same tid shows that the second copy is not applied */
	memset(buf, 0x55, sizeof(buf));
	r.retry = 2;
	(void)orc_send(&c, &r, t1);
	WRT_CHECK(orc_reply(&c, t1) != NULL);
	rd = or_one("obj-d", or_read(0, 100));
	{
		const or_reply *p = orc_call(&c, &rd);

		WRT_CHECK(p != NULL && p->ok && p->dlen == 100u);
		if (p != NULL && p->dlen == 100u)
			WRT_CHECK(p->data[0] == 0x41 && p->data[99] == 0x41);
	}
	/* a read is not mutating: no dedup, executed every time */
	WRT_CHECK(!last_rec(&e)->duplicate);
	/* no_dedup: the second copy is executed again */
	sim_osd_faults(e.osd)->no_dedup = 1;
	r.retry = 3;
	(void)orc_send(&c, &r, t1);
	WRT_CHECK(orc_reply(&c, t1) != NULL);
	WRT_CHECK(last_rec(&e)->executed && !last_rec(&e)->duplicate);
	WRT_CHECK(sim_store_version(e.store, POOL, "obj-d") > v0);
	{
		uint8_t b2[100];
		int ex = 0;

		(void)sim_store_read(e.store, POOL, "obj-d", 0, b2, 100, &ex);
		WRT_CHECK(ex && b2[0] == 0x55);
	}
	/* N dropped replies */
	sim_osd_faults(e.osd)->no_dedup = 0;
	sim_osd_faults(e.osd)->drop_replies = 2;
	rd = or_one("obj-d", or_stat());
	WRT_CHECK(orc_call(&c, &rd) == NULL);
	WRT_CHECK(orc_call(&c, &rd) == NULL);
	WRT_CHECK(orc_call(&c, &rd) != NULL);
	down(&e, &c);
}

static void fault_cut(void)
{
	ore e;
	orc c;
	or_req r;
	uint8_t buf[32];
	uint64_t t1, t2;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->cut_after_ops = 2;
	r = wreq("obj-c1", 0, buf, 32, 0x61);
	t1 = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t1) != NULL);
	r = wreq("obj-c2", 0, buf, 32, 0x62);
	t2 = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t2) == NULL);                           /* handled (applied) and then cut: the reply is lost */
	WRT_CHECK(sim_store_exists(e.store, POOL, "obj-c2"));
	WRT_CHECK(last_rec(&e)->executed);
	WRT_CHECK(sim_osd_closed(c.conn));
	WRT_CHECK_U64(sim_osd_faults(e.osd)->cut_after_ops, 0);         /* one shot */
	r = wreq("obj-c3", 0, buf, 32, 0x63);
	(void)orc_send(&c, &r, 0);
	WRT_CHECK(!sim_store_exists(e.store, POOL, "obj-c3"));          /* nobody reads this connection any more */
	/* a new connection works, and the resend of the lost write is answered from the log */
	{
		orc c2;

		orc_init(&c2, &e, e.osd);
		WRT_CHECK_U64(orc_open(&c2), OR_OK);
		r = wreq("obj-c2", 0, buf, 32, 0x62);
		r.retry = 1;
		(void)orc_send(&c2, &r, t2);
		{
			const or_reply *p = orc_reply(&c2, t2);

			WRT_CHECK(p != NULL && p->ok && p->result == 0);
		}
		WRT_CHECK(last_rec(&e)->duplicate);
		orc_free(&c2);
	}
	down(&e, &c);
}

static void fault_eagain_redirect_errno(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint8_t buf[16];

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->eagain_ops = 2;
	r = wreq("obj-e", 0, buf, 16, 0x71);
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == -11 && p->rval[0] == 0 && p->dlen == 0 && (p->flags & 1) == 0);
	WRT_CHECK(!sim_store_exists(e.store, POOL, "obj-e"));          /* before executing it */
	WRT_CHECK(!last_rec(&e)->executed);
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -11);
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && sim_store_exists(e.store, POOL, "obj-e"));
	/* a redirect reply: do_redirect, an object locator of another pool, nothing executed */
	sim_osd_faults(e.osd)->redirect = 1;
	r = or_one("obj-e", or_read(0, 16));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->do_redirect == 1u && p->redirect_pool == POOL + 1 && p->result == -2 && !last_rec(&e)->executed);
	sim_osd_faults(e.osd)->redirect = 0;
	/* a forced errno for one op code fails the whole message before it runs */
	sim_osd_faults(e.osd)->force_errno_op = 0x2201;
	sim_osd_faults(e.osd)->force_errno = -108;
	r = wreq("obj-e2", 0, buf, 16, 0x72);
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == -108 && p->rval[0] == 0 && !sim_store_exists(e.store, POOL, "obj-e2"));
	WRT_CHECK(!last_rec(&e)->executed);
	r = or_one("obj-e", or_read(0, 16));                           /* other codes are not affected */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 16u);
	down(&e, &c);
}

static void fault_hold(void)
{
	ore e;
	orc c;
	or_req r;
	uint64_t t[4];
	uint8_t buf[8];
	int i;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->hold_replies = 1;
	for (i = 0; i < 3; i++) {
		r = wreq(i == 0 ? "h0" : i == 1 ? "h1" : "h2", 0, buf, 8, (uint8_t)(0x80 + i));
		t[i] = orc_send(&c, &r, 0);
	}
	orc_pull(&c);
	WRT_CHECK_U64(c.n_msg, 0);
	WRT_CHECK_U64(sim_osd_n_held(e.osd), 3);
	WRT_CHECK(sim_store_exists(e.store, POOL, "h2"));              /* executed, the replies are held */
	WRT_CHECK(rec_at(&e, 0)->held);
	WRT_CHECK_U64(sim_osd_release(e.osd, 1), 1);
	orc_pull(&c);
	WRT_CHECK(c.n_msg == 1u && c.msg[0].tid == t[0]);
	WRT_CHECK_U64(sim_osd_release(e.osd, 0), 2);
	orc_pull(&c);
	WRT_CHECK(c.n_msg == 3u && c.msg[1].tid == t[1] && c.msg[2].tid == t[2]);
	WRT_CHECK_U64(sim_osd_release(e.osd, 0), 0);
	orc_forget(&c);
	/* newest first */
	sim_osd_faults(e.osd)->reverse_release = 1;
	for (i = 0; i < 3; i++) {
		r = or_one("h0", or_stat());
		t[i] = orc_send(&c, &r, 0);
	}
	WRT_CHECK_U64(sim_osd_release(e.osd, 0), 3);
	orc_pull(&c);
	WRT_CHECK(c.n_msg == 3u && c.msg[0].tid == t[2] && c.msg[1].tid == t[1] && c.msg[2].tid == t[0]);
	WRT_CHECK(c.msg[0].seq < c.msg[1].seq && c.msg[1].seq < c.msg[2].seq); /* the sequence numbers follow the order of sending */
	{
		const or_reply *p = orc_reply(&c, t[0]);

		WRT_CHECK(p != NULL && p->ok && p->result == 0);
	}
	/* a restart loses what is held */
	sim_osd_faults(e.osd)->reverse_release = 0;
	r = or_one("h0", or_stat());
	(void)orc_send(&c, &r, 0);
	WRT_CHECK_U64(sim_osd_n_held(e.osd), 1);
	sim_osd_restart(e.osd);
	WRT_CHECK_U64(sim_osd_n_held(e.osd), 0);
	WRT_CHECK_U64(sim_osd_release(e.osd, 0), 0);
	down(&e, &c);
}

static void fault_bad_len(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint8_t buf[100];

	up(&e, &c, WR_KEY_TYPE_AES256K);
	r = wreq("obj-b", 0, buf, 100, 0x91);
	(void)orc_call(&c, &r);
	sim_osd_faults(e.osd)->bad_reply_len = 1;
	r = or_one("obj-b", or_read(0, 100));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->payload_len[0] == 100u && p->dlen == 99u);
	WRT_CHECK(p != NULL && p->sum_payload == p->dlen + 1u);
	r = wreq("obj-b", 0, buf, 100, 0x92);                          /* nothing to cut: the record claims a byte that is not there */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->payload_len[0] == 1u && p->dlen == 0u);
	down(&e, &c);
}

static void fault_epochs_and_full(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint8_t buf[16];
	uint64_t t;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	/* min_epoch: the OSD is "ahead" and drops what is older */
	sim_osd_faults(e.osd)->min_epoch = 50;
	r = wreq("o-me", 0, buf, 16, 1);
	WRT_CHECK(orc_call(&c, &r) == NULL);
	WRT_CHECK(!last_rec(&e)->executed && last_rec(&e)->result == INT32_MIN);
	r.epoch = 50;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	sim_osd_faults(e.osd)->min_epoch = 0;
	/* the full pool: without FULL_TRY a write is dropped, with it -ENOSPC, with FULL_FORCE it goes through; reads and a delete are not affected */
	sim_osd_faults(e.osd)->pool_full_drop = 1;
	r = wreq("o-full", 0, buf, 16, 2);
	WRT_CHECK(orc_call(&c, &r) == NULL);
	WRT_CHECK(!sim_store_exists(e.store, POOL, "o-full"));
	r.flags = 0x08c00024u;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == -28 && (p->flags & 1) == 0 && !sim_store_exists(e.store, POOL, "o-full"));
	r.flags = 0x09400024u;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == 0 && sim_store_exists(e.store, POOL, "o-full"));
	r = or_one("o-full", or_read(0, 16));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->dlen == 16u);
	r = or_one("o-full", or_delete());
	r.flags = 0x08c00024u;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "o-full"));
	/* what the real OSD refuses is what makes data grow, found out by running the operations: an overwrite in place, a ZERO, a TRUNCATE down and a
	 * DELETE are served without any FULL flag, a write that extends the object or a message that creates one is dropped (-ENOSPC with FULL_TRY) and
	 * a message that does both an overwrite and an extension is not applied at all */
	sim_osd_faults(e.osd)->pool_full_drop = 0;
	r = wreq("o-full2", 0, buf, 16, 4);
	WRT_CHECK(orc_call(&c, &r) != NULL);
	sim_osd_faults(e.osd)->pool_full_drop = 1;
	r = wreq("o-full2", 4, buf, 8, 5);                                  /* inside the 16 bytes: no growth */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == 0 && (p->flags & 5) == 5);
	r = or_one("o-full2", or_zero(2, 4));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	r = or_one("o-full2", or_truncate(12));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0);
	r = wreq("o-full2", 8, buf, 16, 6);                                 /* reaches 24 > 12: grows */
	WRT_CHECK(orc_call(&c, &r) == NULL);
	WRT_CHECK(!last_rec(&e)->executed && last_rec(&e)->result == INT32_MIN);
	{
		uint64_t sz = 0;
		uint8_t back[32];
		int ex = 0;

		WRT_CHECK(sim_store_size(e.store, POOL, "o-full2", &sz) == WR_OK && sz == 12u);
		r = wreq("o-full2", 0, buf, 4, 7);                              /* an overwrite followed by an extension: nothing of it is applied */
		or_req_add(&r, or_write(20, buf, 4));
		r.flags = 0x08c00024u;
		p = orc_call(&c, &r);
		WRT_CHECK(p != NULL && p->result == -28 && (p->flags & 1) == 0);
		(void)sim_store_read(e.store, POOL, "o-full2", 0, back, 12, &ex);
		WRT_CHECK(sim_store_size(e.store, POOL, "o-full2", &sz) == WR_OK && sz == 12u && back[0] != 7u);
	}
	/* the same on the lab with a full quota: WRITEFULL smaller served, bigger refused; TRUNCATE up and a zero-length write past the end refused */
	r = or_one("o-full2", or_writefull(buf, 8));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == 0);
	r = or_one("o-full2", or_writefull(buf, 16));
	WRT_CHECK(orc_call(&c, &r) == NULL);
	r = or_one("o-full2", or_truncate(5000));
	WRT_CHECK(orc_call(&c, &r) == NULL);
	r = or_one("o-full2", or_write(5000, buf, 0));
	r.flags = 0x08c00024u;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -28);
	{
		uint64_t sz = 0;

		WRT_CHECK(sim_store_size(e.store, POOL, "o-full2", &sz) == WR_OK && sz == 8u);
	}
	r = or_one("o-full3", or_create(0));                                /* a new object: grows */
	WRT_CHECK(orc_call(&c, &r) == NULL);
	WRT_CHECK(!sim_store_exists(e.store, POOL, "o-full3"));
	r = or_one("o-full2", or_delete());                                 /* a DELETE without FULL_TRY is served */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && !sim_store_exists(e.store, POOL, "o-full2"));
	sim_osd_faults(e.osd)->pool_full_drop = 0;
	down(&e, &c);

	/* epoch parking: a request from the future waits for the map */
	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.epoch = 10;
	ore_start(&e);
	orc_up(&c, &e);
	r = wreq("o-park", 0, buf, 16, 3);
	r.epoch = 12;
	t = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t) == NULL);
	WRT_CHECK_U64(sim_osd_n_parked(e.osd), 1);
	WRT_CHECK(last_rec(&e)->parked && !last_rec(&e)->executed);
	sim_osd_set_epoch(e.osd, 11);
	WRT_CHECK_U64(sim_osd_n_parked(e.osd), 1);                       /* still short of 12 */
	WRT_CHECK(orc_reply(&c, t) == NULL);
	sim_osd_set_epoch(e.osd, 12);
	WRT_CHECK_U64(sim_osd_n_parked(e.osd), 0);
	p = orc_reply(&c, t);
	WRT_CHECK(p != NULL && p->ok && p->result == 0 && p->epoch == 12u);
	WRT_CHECK(sim_store_exists(e.store, POOL, "o-park"));
	WRT_CHECK(rec_at(&e, 1)->executed && rec_at(&e, 1)->parked);
	r.epoch = 5;                                                     /* an older request is served at once, the reply carries the OSD's epoch */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == 0 && p->epoch == 12u);
	WRT_CHECK_U64(sim_osd_epoch(e.osd), 12);
	/* a connection that goes away takes its parked requests with it */
	r.epoch = 20;
	(void)orc_send(&c, &r, 0);
	WRT_CHECK_U64(sim_osd_n_parked(e.osd), 1);
	orc_free(&c);
	WRT_CHECK_U64(sim_osd_n_parked(e.osd), 0);
	ore_free(&e);
}

typedef struct primary_ctx {
	uint32_t calls;
	int32_t osd;
	int64_t pool;
	uint32_t seed, hash, epoch;
	int answer;
} primary_ctx;

static int is_primary_cb(void *ctx, int32_t osd, int64_t pool, uint32_t pg_seed, uint32_t hash, uint32_t epoch)
{
	primary_ctx *p = (primary_ctx *)ctx;

	p->calls++;
	p->osd = osd;
	p->pool = pool;
	p->seed = pg_seed;
	p->hash = hash;
	p->epoch = epoch;
	return p->answer;
}

static void primary_check(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	primary_ctx pc;

	memset(&pc, 0, sizeof(pc));
	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.check_primary = 1;
	e.cfg.is_primary = is_primary_cb;
	e.cfg.is_primary_ctx = &pc;
	e.cfg.id = 3;
	ore_start(&e);
	orc_up(&c, &e);
	r = or_one("o-pr", or_stat());
	pc.answer = 0;
	WRT_CHECK(orc_call(&c, &r) == NULL);                              /* not the primary: no answer at all */
	WRT_CHECK(pc.calls == 1u && pc.osd == 3 && pc.pool == POOL && pc.hash == 0x12345678u && pc.seed == 0x12345678u % 32u && pc.epoch == 42u);
	WRT_CHECK(!last_rec(&e)->executed);
	pc.answer = 1;
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == -2);                 /* served (the object is not there) */
	e.cfg.check_primary = 0;
	down(&e, &c);
}

static void v8_only(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;

	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.v8_only = 1;
	ore_start(&e);
	orc_init(&c, &e, e.osd);
	WRT_CHECK_U64(orc_open(&c), OR_OK);
	WRT_CHECK_U64(c.version, 8);
	WRT_CHECK_U64(c.srv_supported & (1ull << 49), 0);
	WRT_CHECK_U64(c.srv_supported & (1ull << 57), 1ull << 57);        /* the incarnation bit stays: RESEND_ON_SPLIT is still there */
	r = or_one("o-v8", or_stat());
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == -2);
	WRT_CHECK_U64(last_rec(&e)->version, 8);
	/* a v9 body to an OSD that cannot decode it */
	{
		uint8_t front[512], data[8];
		uint32_t dl = 0, fl = or_encode(&r, 9, front, sizeof(front), data, sizeof(data), &dl);

		orc_send_raw(&c, 42, 9, 3, 77, front, fl, NULL, 0, NULL, 0, 0);
	}
	WRT_CHECK_U64(sim_osd_n_violations(e.osd), 1);
	WRT_CHECK(sim_osd_closed(c.conn));
	down(&e, &c);
}

/* requests the real OSD would crash on or fail to decode: the connection is closed and the reason kept */
static void violation_case(int which)
{
	ore e;
	orc c;
	or_req r;
	uint8_t front[1024], data[256];
	uint32_t dl = 0, fl;
	uint8_t pad = 0;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	r = or_one("o-v", or_write(0, "abcd", 4));
	if (which == 0)
		r.reqid_inc_bad = 1;
	fl = or_encode(&r, 9, front, sizeof(front), data, sizeof(data), &dl);
	switch (which) {
	case 1: front[fl++] = 0; break;                                     /* a byte after the last field */
	case 2: fl -= 3; break;                                             /* a short front */
	case 3: dl = 3; break;                                              /* the payload lengths do not add up to the data segment */
	case 4: pad = 1; break;                                             /* a middle segment */
	case 5: break;                                                      /* version 7 */
	default: break;
	}
	orc_send_raw(&c, 42, which == 5 ? 7 : 9, 3, 1, front, fl, pad ? &pad : NULL, pad ? 1u : 0u, data, dl, 0);
	orc_pull(&c);
	WRT_CHECK_U64(sim_osd_n_violations(e.osd), 1);
	WRT_CHECK(sim_m2_error(sim_osd_conn_m2(c.conn))->status == WR_E_OSD_PROTO);
	WRT_CHECK(sim_osd_closed(c.conn));
	WRT_CHECK(c.n_msg == 0u);
	WRT_CHECK(sim_osd_recs(e.osd, &fl) != NULL && fl == 0u);          /* nothing recorded, nothing executed */
	down(&e, &c);
}

/* A valid front with one byte changed (three ways) and every truncation of it, each on a connection of its own: the OSD never crashes, never reads
 * outside the message, and either answers, stays silent or closes the connection with its reason; afterwards it still serves a good request. */
static void hostile_fronts(void)
{
	ore e;
	orc c;
	or_req r;
	uint8_t front[1024], data[128], mut[1024];
	uint32_t dl = 0, fl, i, mode, answered = 0, closed = 0, silent = 0;

	ore_prep(&e, WR_KEY_TYPE_AES256K);
	e.cfg.m2.seg_cap = 64u << 10; /* small messages only: cheap connections, there are hundreds of them */
	ore_start(&e);
	or_client_seg_cap = 64u << 10;
	or_req_init(&r, POOL, "hostile");
	or_req_add(&r, or_allochint());
	or_req_add(&r, or_write(4, "01234567", 8));
	or_req_add(&r, or_stat());
	r.snap_seq = 5;
	r.n_snaps = 2;
	r.snaps[0] = 5, r.snaps[1] = 3;
	fl = or_encode(&r, 9, front, sizeof(front), data, sizeof(data), &dl);
	for (i = 0; i <= fl; i++) {
		for (mode = 0; mode < 4u; mode++) {
			uint32_t n = fl;

			if (mode == 3u) { /* a truncation to i bytes */
				if (i == fl)
					continue;
				n = i;
				memcpy(mut, front, fl);
			} else {
				if (i == fl)
					continue;
				memcpy(mut, front, fl);
				mut[i] = mode == 0 ? (uint8_t)(front[i] ^ 0xffu) : mode == 1 ? 0xffu : 0x00u;
				if (mut[i] == front[i])
					continue;
			}
			orc_init(&c, &e, e.osd);
			if (orc_open(&c) != OR_OK) {
				WRT_CHECK(!"handshake of a hostile test connection");
				orc_free(&c);
				continue;
			}
			orc_send_raw(&c, 42, 9, 3, 1, mut, n, NULL, 0, data, dl, 0);
			orc_pull(&c);
			if (orc_find(&c, 1, 43) != NULL)
				answered++;
			else if (sim_osd_closed(c.conn))
				closed++;
			else
				silent++;
			orc_free(&c);
		}
	}
	WRT_CHECK(answered + closed + silent > 500u);
	WRT_CHECK(closed > 100u && answered > 20u);
	WRT_CHECK(sim_osd_n_violations(e.osd) >= closed);
	or_client_seg_cap = 5u << 20;
	orc_up(&c, &e);
	r = or_one("hostile-after", or_stat());
	{
		const or_reply *p = orc_call(&c, &r);

		WRT_CHECK(p != NULL && p->ok && p->result == -2);
	}
	orc_free(&c);
	ore_free(&e);
}

/* ---- backoff and map pushes ----------------------------------------------------------------------------------------------------- */

static void backoff(void)
{
	ore e;
	orc c;
	or_req r;
	const or_msg *m;
	wri_rd rd;
	wri_env sp;
	uint64_t id;
	const or_reply *p;
	uint8_t ack[256];
	wri_wr w;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	/* BLOCK of one object: the OSD says so, remembers the entry, and drops covered requests once the client acknowledged it */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 1, 77, POOL, 0x12345678u % 32u, 42, "o-bo", 0x12345678u, "o-bo", 0x12345678u));
	orc_pull(&c);
	m = orc_find(&c, 0, 61);
	WRT_CHECK(m != NULL && m->version == 1u && m->compat == 1u);
	if (m != NULL) {
		wri_rd_init(&rd, m->front, m->flen);
		WRT_CHECK(wri_env_open(&rd, 1, &sp) == WR_OK);
		WRT_CHECK_U64(wri_rd_u32(&rd), 42);
		WRT_CHECK_U64(wri_rd_u8(&rd), 1);
		id = wri_rd_u64(&rd);
		WRT_CHECK_U64(id, 77);
	}
	r = or_one("o-bo", or_stat());
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);                           /* between BLOCK and the ack the OSD may still accept */
	/* ACK_BLOCK: spg_t, epoch of the BLOCK, op 2, id, begin, end */
	wri_wr_init(&w, ack, sizeof(ack));
	wri_wr_u8(&w, 1);
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, 18);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, POOL);
	wri_wr_u32(&w, 0x12345678u % 32u);
	wri_wr_i32(&w, -1);
	wri_wr_u8(&w, 0xff);
	wri_wr_u32(&w, 42);
	wri_wr_u8(&w, 2);
	wri_wr_u64(&w, 77);
	orc_send_raw(&c, 61, 1, 1, 0, ack, (uint32_t)wri_wr_len(&w), NULL, 0, NULL, 0, 0);
	WRT_CHECK_U64(sim_osd_n_acks(e.osd), 1);
	p = orc_call(&c, &r);
	WRT_CHECK(p == NULL);                                              /* covered and acknowledged: dropped silently */
	WRT_CHECK(last_rec(&e)->backoff_drop && !last_rec(&e)->executed);
	WRT_CHECK_U64(sim_osd_n_backoff_drops(e.osd), 1);
	r = or_one("o-other", or_stat());                                  /* another object of the same PG is not covered */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);
	r = or_one("o-bo", or_stat());
	r.hash = 0x12345679u;                                              /* the same name with another hash is another object */
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL);
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 3, 77, POOL, 0x12345678u % 32u, 42, "o-bo", 0x12345678u, "o-bo", 0x12345678u));
	r = or_one("o-bo", or_stat());
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->result == -2);                           /* UNBLOCK: served again */
	WRT_CHECK_U64(orc_count(&c, 61), 2);

	/* a range [a, z) of the same hash: names between are covered, the end is not */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 1, 78, POOL, 0x12345678u % 32u, 42, "a", 0x12345678u, "z", 0x12345678u));
	wri_wr_init(&w, ack, sizeof(ack));
	wri_wr_u8(&w, 1);
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, 18);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, POOL);
	wri_wr_u32(&w, 0x12345678u % 32u);
	wri_wr_i32(&w, -1);
	wri_wr_u8(&w, 0xff);
	wri_wr_u32(&w, 42);
	wri_wr_u8(&w, 2);
	wri_wr_u64(&w, 78);
	orc_send_raw(&c, 61, 1, 1, 0, ack, (uint32_t)wri_wr_len(&w), NULL, 0, NULL, 0, 0);
	r = or_one("m", or_stat());
	WRT_CHECK(orc_call(&c, &r) == NULL);
	r = or_one("a", or_stat());
	WRT_CHECK(orc_call(&c, &r) == NULL);                               /* begin is inside */
	r = or_one("z", or_stat());
	WRT_CHECK(orc_call(&c, &r) != NULL);                               /* end is outside */
	r = or_one("zz", or_stat());
	WRT_CHECK(orc_call(&c, &r) != NULL);
	/* the end of the last PG of a pool is the "max" position (a default hobject_t with the max flag, pool INT64_MIN): the flag goes on the wire and
	 * a range that ends there covers everything after its begin */
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 3, 78, POOL, 0x12345678u % 32u, 42, "a", 0x12345678u, "z", 0x12345678u));
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 1, 79, POOL, 0x12345678u % 32u, 43, "", 0, SIM_OSD_BO_MAX, 0));
	orc_pull(&c);
	{
		const or_msg *last = NULL;
		uint32_t i;

		for (i = 0; i < c.n_msg; i++)
			if (c.msg[i].type == 61)
				last = &c.msg[i];
		WRT_CHECK(last != NULL);
		if (last != NULL) {
			wri_env he[2];
			uint32_t kl, ol, nl, hash[2];
			uint8_t mx[2];
			uint64_t snap[2];
			int64_t pool[2];
			int k;

			wri_rd_init(&rd, last->front, last->flen);
			WRT_CHECK(wri_env_open(&rd, 1, &sp) == WR_OK);
			WRT_CHECK_U64(wri_rd_u32(&rd), 43);
			WRT_CHECK_U64(wri_rd_u8(&rd), 1);
			WRT_CHECK_U64(wri_rd_u64(&rd), 79);
			for (k = 0; k < 2; k++) {
				WRT_CHECK(wri_env_open(&rd, 4, &he[k]) == WR_OK);
				(void)wri_denc_blob(&he[k].body, &kl, 64);
				(void)wri_denc_blob(&he[k].body, &ol, 64);
				snap[k] = wri_rd_u64(&he[k].body);
				hash[k] = wri_rd_u32(&he[k].body);
				mx[k] = wri_rd_u8(&he[k].body);
				(void)wri_denc_blob(&he[k].body, &nl, 64);
				pool[k] = wri_rd_i64(&he[k].body);
				WRT_CHECK(wri_rd_ok(&he[k].body) && kl == 0 && nl == 0);
				WRT_CHECK(k == 1 ? ol == 0 : ol == 0);
			}
			WRT_CHECK(mx[0] == 0u && pool[0] == POOL && snap[0] == 0u && hash[0] == 0u);
			WRT_CHECK(mx[1] == 1u && pool[1] == INT64_MIN && snap[1] == 0u && hash[1] == 0u);
			WRT_CHECK(wri_rd_left(&rd) == 0u);
		}
	}
	wri_wr_init(&w, ack, sizeof(ack));
	wri_wr_u8(&w, 1);
	wri_wr_u8(&w, 1);
	wri_wr_u32(&w, 18);
	wri_wr_u8(&w, 1);
	wri_wr_u64(&w, POOL);
	wri_wr_u32(&w, 0x12345678u % 32u);
	wri_wr_i32(&w, -1);
	wri_wr_u8(&w, 0xff);
	wri_wr_u32(&w, 43);
	wri_wr_u8(&w, 2);
	wri_wr_u64(&w, 79);
	orc_send_raw(&c, 61, 1, 1, 0, ack, (uint32_t)wri_wr_len(&w), NULL, 0, NULL, 0, 0);
	r = or_one("q", or_stat());
	WRT_CHECK(orc_call(&c, &r) == NULL);                               /* after begin and before the end of the pool: covered */
	r = or_one("zzz", or_stat());
	r.hash = 0x12345678u + 32u;                                         /* another hash of the same PG */
	WRT_CHECK(orc_call(&c, &r) == NULL);
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_backoff(c.conn, 3, 79, POOL, 0x12345678u % 32u, 43, "", 0, SIM_OSD_BO_MAX, 0));
	r = or_one("q", or_stat());
	WRT_CHECK(orc_call(&c, &r) != NULL);                               /* UNBLOCK: served again */
	/* a restart forgets the table */
	sim_osd_restart(e.osd);
	down(&e, &c);
}

static void map_push_and_other(void)
{
	ore e;
	orc c;
	uint8_t front[100];
	const or_msg *m;
	uint8_t junk[8];

	up(&e, &c, WR_KEY_TYPE_AES256K);
	memset(front, 0x5a, sizeof(front));
	WRT_CHECK_STATUS(WR_OK, sim_osd_send_map_push(c.conn, front, sizeof(front)));
	orc_pull(&c);
	m = orc_find(&c, 0, 41);
	WRT_CHECK(m != NULL && m->version == 4u && m->compat == 3u && m->flen == 100u && m->nseg == 2u);
	if (m != NULL)
		WRT_CHECK(memcmp(m->front, front, 100) == 0);
	/* a message of another type is counted and ignored */
	memset(junk, 1, sizeof(junk));
	orc_send_raw(&c, 99, 1, 1, 0, junk, sizeof(junk), NULL, 0, NULL, 0, 0);
	WRT_CHECK_U64(sim_osd_n_other(e.osd), 1);
	WRT_CHECK_U64(sim_osd_n_requests(e.osd), 0);
	WRT_CHECK(!sim_osd_closed(c.conn));
	down(&e, &c);
}

/* ---- restart, two OSDs, limits, big messages ------------------------------------------------------------------------------------ */

static void restart_and_two_osds(void)
{
	ore e;
	orc c, c2, c3;
	or_req r;
	uint8_t buf[40];
	uint64_t t1;
	sim_osd *o2;
	sim_osd_cfg cfg2;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	sim_osd_faults(e.osd)->drop_replies = 1;
	r = wreq("obj-r", 0, buf, 40, 0xa1);
	t1 = orc_send(&c, &r, 0);
	WRT_CHECK(orc_reply(&c, t1) == NULL);
	sim_osd_restart(e.osd);
	WRT_CHECK(sim_osd_closed(c.conn));
	WRT_CHECK(sim_store_dedup_has(e.store, e.gid, t1));                /* the log of the PG survives the daemon */
	orc_init(&c2, &e, e.osd);
	WRT_CHECK_U64(orc_open(&c2), OR_OK);
	WRT_CHECK_U64(sim_osd_n_conns_accepted(e.osd), 2);
	r.retry = 1;
	(void)orc_send(&c2, &r, t1);
	{
		const or_reply *p = orc_reply(&c2, t1);

		WRT_CHECK(p != NULL && p->result == 0);
	}
	WRT_CHECK(last_rec(&e)->duplicate);
	/* a second OSD on the same store (the PG moved to another primary): the same resend is recognised there too */
	cfg2 = e.cfg;
	cfg2.id = 1;
	cfg2.seed = 99;
	o2 = sim_osd_new(&cfg2);
	WRT_CHECK(o2 != NULL);
	if (o2 != NULL) {
		orc_init(&c3, &e, o2);
		WRT_CHECK_U64(orc_open(&c3), OR_OK);
		(void)orc_send(&c3, &r, t1);
		{
			const or_reply *p = orc_reply(&c3, t1);

			WRT_CHECK(p != NULL && p->result == 0);
		}
		{
			uint32_t n;
			const sim_osd_rec *rr = sim_osd_recs(o2, &n);

			WRT_CHECK(n == 1u && rr[0].duplicate);
		}
		/* a request with another tid is applied by the second OSD to the same store */
		r = wreq("obj-r", 8, buf, 8, 0xa2);
		{
			const or_reply *p = orc_call(&c3, &r);

			WRT_CHECK(p != NULL && p->result == 0);
		}
		orc_free(&c3);
		sim_osd_free(o2);
	}
	orc_free(&c2);
	down(&e, &c);
}

static void conn_limit(void)
{
	ore e;
	sim_osd_conn *cs[SIM_OSD_MAX_CONNS + 1u];
	uint32_t i;

	ore_prep(&e, WR_KEY_TYPE_AES);
	ore_start(&e);
	for (i = 0; i < SIM_OSD_MAX_CONNS; i++) {
		cs[i] = sim_osd_accept(e.osd);
		WRT_CHECK(cs[i] != NULL);
	}
	WRT_CHECK(sim_osd_accept(e.osd) == NULL);
	sim_osd_conn_free(cs[5]);
	cs[5] = sim_osd_accept(e.osd);
	WRT_CHECK(cs[5] != NULL);
	WRT_CHECK(sim_osd_accept(e.osd) == NULL);
	WRT_CHECK_U64(sim_osd_n_conns_accepted(e.osd), SIM_OSD_MAX_CONNS + 1u);
	for (i = 0; i < SIM_OSD_MAX_CONNS; i++)
		sim_osd_conn_free(cs[i]);
	ore_free(&e);
	/* configurations that cannot work */
	{
		sim_osd_cfg cfg;
		sim_osd *o;

		sim_osd_cfg_default(&cfg);
		WRT_CHECK(sim_osd_new(&cfg) == NULL);                         /* no monitor, no store */
		WRT_CHECK(sim_osd_new(NULL) == NULL);
		ore_prep(&e, WR_KEY_TYPE_AES);
		cfg = e.cfg;
		cfg.max_object_bytes = 0;
		WRT_CHECK(sim_osd_new(&cfg) == NULL);
		cfg = e.cfg;
		o = sim_osd_new(&cfg);
		WRT_CHECK(o != NULL);
		sim_osd_free(o);
		sim_osd_free(NULL);
		sim_store_free(NULL);
		ore_free(&e);
	}
}

static void big_io(void)
{
	ore e;
	orc c;
	or_req r;
	const or_reply *p;
	uint8_t *buf, *back;
	uint32_t n = 4u << 20, i;
	int ex = 0;

	up(&e, &c, WR_KEY_TYPE_AES256K);
	buf = (uint8_t *)malloc(n);
	back = (uint8_t *)malloc(n);
	for (i = 0; i < n; i++)
		buf[i] = (uint8_t)((i * 7u + 3u) % 251u);
	or_req_init(&r, POOL, "rbd_data.big.0000000000000000");
	or_req_add(&r, or_allochint());
	or_req_add(&r, or_write(0, buf, n));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == 0 && p->n_ops == 2u && p->dlen == 0u);
	(void)sim_store_read(e.store, POOL, "rbd_data.big.0000000000000000", 0, back, n, &ex);
	WRT_CHECK(ex && memcmp(buf, back, n) == 0);
	r = or_one("rbd_data.big.0000000000000000", or_read(0, n));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->result == 0 && p->dlen == n);
	if (p != NULL && p->dlen == n)
		WRT_CHECK(memcmp(p->data, buf, n) == 0);
	r = or_one("rbd_data.big.0000000000000000", or_sparse(0, n));
	p = orc_call(&c, &r);
	WRT_CHECK(p != NULL && p->ok && p->dlen == n + 4u + 16u + 4u);
	if (p != NULL && p->dlen == n + 24u) {
		WRT_CHECK(wri_le32_get(p->data) == 1u && wri_le64_get(p->data + 4) == 0 && wri_le64_get(p->data + 12) == n && wri_le32_get(p->data + 20) == n);
		WRT_CHECK(memcmp(p->data + 24, buf, n) == 0);
	}
	free(buf);
	free(back);
	down(&e, &c);
}

int main(void)
{
	handshake_ok(WR_KEY_TYPE_AES256K);
	handshake_ok(WR_KEY_TYPE_AES);
	refusals();
	framing();
	seq_rules();
	fault_silent();
	fault_drop_replies();
	fault_cut();
	fault_eagain_redirect_errno();
	fault_hold();
	fault_bad_len();
	fault_epochs_and_full();
	primary_check();
	v8_only();
	{
		int k;

		for (k = 0; k <= 5; k++)
			violation_case(k);
	}
	hostile_fronts();
	backoff();
	map_push_and_other();
	restart_and_two_osds();
	conn_limit();
	big_io();
	return wrt_finish();
}
