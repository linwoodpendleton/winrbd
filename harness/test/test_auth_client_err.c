/* SPDX-License-Identifier: MIT */
/*
 * Error table and special paths of the cephx client machine: wrong key, global id 0, validity 0,
 * oversize ticket, every truncation of a reply, bad magic, status != 0, empty extra, mixed key types,
 * reclaim with the old ticket (ticket_enc 1), secure-mode refusals, and the OSD authorizer (byte
 * layout, challenge round trip, every refusal). The replies are written by the small server-side
 * builder of auth_cx_srv.h, which test_auth_client.c has checked against the committed vectors.
 */
#include "auth_cx_srv.h"

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* A fresh environment with a type-`pt` principal; AUTH session key type `at`, OSD key type `ot`. */
typedef struct cx {
	cxt_env e;
	wr_key ak, ok;
	cxt_dopt o;
	uint8_t buf[4096];
	size_t n;
} cx;

static void cx_new(cx *t, unsigned pt, unsigned at, unsigned ot, uint32_t ticket_cap)
{
	wr_key pk = cxt_key(pt, 11);

	WRT_CHECK(cxt_env_init(&t->e, "client.tester", &pk, ticket_cap) == 0);
	t->ak = cxt_key(at, 21);
	t->ok = cxt_key(ot, 31);
	cxt_rng_free();
	cxt_dopt_default(&t->e, &t->o, &t->ak, &t->ok);
	t->o.extra[0].msga_key = &t->ak;
	t->o.auth.msga_key = &t->e.c.principal;
}

static wr_status cx_run(cx *t, uint64_t gid)
{
	t->n = cxt_build_done(&t->e, &t->o, t->buf, sizeof(t->buf));
	WRT_CHECK(t->n != 0);
	return cxt_mon_hs(&t->e, t->buf, t->n, gid, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL);
}

/* after a failed AUTH_DONE the machine holds nothing */
static void expect_clean(cx *t, wr_status st)
{
	WRT_CHECK(t->e.c.st == WRI_CX_FAILED);
	WRT_CHECK(t->e.c.err.status == st);
	WRT_CHECK(!t->e.c.ticket[0].have && !t->e.c.ticket[1].have && t->e.c.global_id == 0);
	WRT_CHECK(all_zero(t->e.c.ticket[0].session_key.secret, WR_KEY_MAX));
	WRT_CHECK(all_zero(t->e.c.ticket[0].blob, t->e.x.cfg.ticket_cap));
	WRT_CHECK(all_zero(t->e.c.scratch, t->e.c.scratch_cap));
	{
		const uint8_t *k = (const uint8_t *)1;
		size_t kn = 1;

		wri_cx_ops()->session_key(&t->e.c, &k, &kn);
		WRT_CHECK(k == NULL && kn == 0);
	}
}

static void test_mon_errors(unsigned pt, unsigned at, unsigned ot)
{
	cx t;
	unsigned i;

	/* the good case first, with these key types */
	cx_new(&t, pt, at, ot, 0);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	WRT_CHECK(t.e.c.global_id == 900 && t.e.c.st == WRI_CX_DONE);
	WRT_CHECK(t.e.c.ticket[0].session_key.type == at && t.e.c.ticket[1].session_key.type == ot);
	WRT_CHECK(memcmp(t.e.c.ticket[1].session_key.secret, t.ok.secret, t.ok.len) == 0);
	cxt_env_free(&t.e);

	/* wrong key: the server sealed msg_a with another key */
	cx_new(&t, pt, at, ot, 0);
	{
		wr_key other = cxt_key(pt, 99);

		t.o.auth.msga_key = &other;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, cx_run(&t, 900));
		expect_clean(&t, WR_E_AUTH_DECRYPT);
	}
	cxt_env_free(&t.e);

	/* bad magic under the right key (the only integrity check of type 1) */
	cx_new(&t, pt, at, ot, 0);
	{
		uint8_t item[64], ct[160], blob[200], payload[512];
		wri_wr w;
		size_t cn = 0, bn;
		uint8_t plain[80];

		wri_wr_init(&w, item, sizeof(item));
		wri_wr_u8(&w, 1);
		wri_wr_u16(&w, t.ak.type);
		wri_wr_zero(&w, 8);
		wri_wr_u16(&w, t.ak.len);
		wri_wr_bytes(&w, t.ak.secret, t.ak.len);
		wri_wr_u32(&w, 3600);
		wri_wr_u32(&w, 0);
		plain[0] = 1;
		wri_le64_put(plain + 1, WRI_CX_MAGIC ^ 1u);
		memcpy(plain + 9, item, wri_wr_len(&w));
		WRT_CHECK_STATUS(WR_OK, wri_cx_encrypt(&t.e.x, &t.e.c.principal, WRI_CX_USAGE_TICKET_SESSION_KEY, plain,
						       9 + wri_wr_len(&w), ct, sizeof(ct), &cn));
		bn = cxt_blob(blob, 1, 50, 7);
		wri_wr_init(&w, payload, sizeof(payload));
		wri_wr_u16(&w, WRI_CX_REQ_GET_AUTH_SESSION_KEY);
		wri_wr_i32(&w, 0);
		wri_wr_u8(&w, 1);
		wri_wr_u32(&w, 1);
		wri_wr_u32(&w, WRI_CX_SERVICE_AUTH);
		wri_wr_u8(&w, 1);
		wri_wr_u32(&w, (uint32_t)cn);
		wri_wr_bytes(&w, ct, cn);
		wri_wr_u8(&w, 0);
		wri_wr_u32(&w, (uint32_t)bn);
		wri_wr_bytes(&w, blob, bn);
		t.e.c.want_mask = WRI_CX_SERVICE_AUTH;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, cxt_mon_hs(&t.e, payload, wri_wr_len(&w), 5, 1, NULL, NULL, NULL, NULL));
		expect_clean(&t, WR_E_AUTH_DECRYPT);
	}
	cxt_env_free(&t.e);

	/* global id 0 */
	cx_new(&t, pt, at, ot, 0);
	WRT_CHECK_STATUS(WR_E_AUTH_GID0, cx_run(&t, 0));
	expect_clean(&t, WR_E_AUTH_GID0);
	cxt_env_free(&t.e);

	/* validity 0, for the AUTH ticket and for the OSD ticket */
	cx_new(&t, pt, at, ot, 0);
	t.o.auth.val_s = 0;
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_TICKET_EXPIRED);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.o.extra[0].val_s = 0;
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_TICKET_EXPIRED);
	cxt_env_free(&t.e);

	/* nanoseconds out of range */
	cx_new(&t, pt, at, ot, 0);
	t.o.auth.val_ns = 1000000000u;
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* oversize ticket: ticket_cap 200 holds 13 + 150, not 13 + 188 */
	cx_new(&t, pt, at, ot, 200);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 200);
	t.o.extra[0].blob_data = 188;
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_TOOBIG, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_TICKET_TOOBIG);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 200);
	t.o.auth.blob_data = 188;
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_TOOBIG, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* status != 0 and a response for another request */
	cx_new(&t, pt, at, ot, 0);
	t.o.status = -13;
	WRT_CHECK_STATUS(WR_E_AUTH_RESULT, cx_run(&t, 900));
	WRT_CHECK(t.e.c.err.peer_result == -13);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.o.rtype = WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY;
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* every strict prefix of a good reply fails (want mask 0x24 needs the OSD ticket) */
	cx_new(&t, pt, at, ot, 0);
	t.n = cxt_build_done(&t.e, &t.o, t.buf, sizeof(t.buf));
	cxt_env_free(&t.e);
	for (i = 0; i < t.n; i++) {
		cx fresh;
		wr_status st;

		cx_new(&fresh, pt, at, ot, 0);
		/* the machine is deterministic, so the same bytes re-derive; rebuild with the same keys */
		st = cxt_mon_hs(&fresh.e, t.buf, i, 900, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL);
		WRT_CHECK(st != WR_OK);
		WRT_CHECK(!fresh.e.c.ticket[0].have && !fresh.e.c.ticket[1].have);
		cxt_env_free(&fresh.e);
	}
	/* ... and the whole thing, built on a machine with the same principal key, succeeds */
	cx_new(&t, pt, at, ot, 0);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* corrupted bytes anywhere inside the ciphertexts: never accepted as a different valid state */
	cx_new(&t, pt, at, ot, 0);
	t.n = cxt_build_done(&t.e, &t.o, t.buf, sizeof(t.buf));
	cxt_env_free(&t.e);
	for (i = 20; i < t.n; i += 7) {
		cx fresh;
		uint8_t save = t.buf[i];
		wr_status st;

		cx_new(&fresh, pt, at, ot, 0);
		t.buf[i] = (uint8_t)(save ^ 0x40);
		st = cxt_mon_hs(&fresh.e, t.buf, t.n, 900, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL);
		t.buf[i] = save;
		/* a flip in a ticket blob (opaque filler) is legal; anything in a ciphertext must fail */
		if (st == WR_OK) {
			WRT_CHECK(fresh.e.c.ticket[0].have && fresh.e.c.ticket[1].have);
		} else {
			WRT_CHECK(!fresh.e.c.ticket[0].have && !fresh.e.c.ticket[1].have);
		}
		cxt_env_free(&fresh.e);
	}

	/* extra: zero length is legal when only AUTH was asked for, missing OSD ticket otherwise */
	cx_new(&t, pt, at, ot, 0);
	t.o.n_extra = 0;
	t.e.c.want_mask = WRI_CX_SERVICE_AUTH;
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	WRT_CHECK(t.e.c.ticket[0].have && !t.e.c.ticket[1].have && t.e.c.st == WRI_CX_DONE);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.o.n_extra = 0;
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_PROTO);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.o.tail = 0; /* no cbl / extra at all */
	t.e.c.want_mask = WRI_CX_SERVICE_AUTH;
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* the MAuth-style empty cbl is fine; an AUTH ticket inside extra is not */
	cx_new(&t, pt, at, ot, 0);
	t.o.cbl_empty = 1;
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.o.extra[0].service = WRI_CX_SERVICE_AUTH;
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cx_run(&t, 900));
	cxt_env_free(&t.e);

	/* MON and MGR tickets in extra are skipped, the OSD one is kept */
	cx_new(&t, pt, at, ot, 0);
	t.o.n_extra = 3;
	t.o.extra[1] = t.o.extra[0];
	t.o.extra[1].service = WRI_CX_SERVICE_MON;
	t.o.extra[2] = t.o.extra[0];
	t.o.extra[2].service = 0x10;
	t.o.extra[2].key = cxt_key(1, 77);
	t.e.c.want_mask = 0x35;
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 900));
	WRT_CHECK(t.e.c.ticket[1].have && t.e.c.ticket[1].service == WRI_CX_SERVICE_OSD);
	cxt_env_free(&t.e);

	/* secure mode (architecture 34.3; the whole table is in test_auth_secret.c): a connection secret in crc mode
	 * is a protocol error, a secure mode without one is WR_E_M2_SECRET, and neither is silently accepted */
	cx_new(&t, pt, at, ot, 0);
	t.o.secret_len = 64;
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_PROTO);
	cxt_env_free(&t.e);
	cx_new(&t, pt, at, ot, 0);
	t.n = cxt_build_done(&t.e, &t.o, t.buf, sizeof(t.buf)); /* an empty secret string */
	WRT_CHECK_STATUS(WR_E_M2_SECRET, cxt_mon_hs(&t.e, t.buf, t.n, 900, WRI_CONN_MODE_SECURE, NULL, NULL, NULL, NULL));
	expect_clean(&t, WR_E_M2_SECRET);
	cxt_env_free(&t.e);

	/* extra signed with the wrong key (the principal key instead of the AUTH session key) */
	cx_new(&t, pt, at, ot, 0);
	t.o.extra[0].msga_key = &t.e.c.principal;
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, cx_run(&t, 900));
	expect_clean(&t, WR_E_AUTH_DECRYPT);
	cxt_env_free(&t.e);
}

/* ---- reclaim, ticket_enc 1, identity change ------------------------------------------------------------- */

static void test_reclaim(unsigned kt)
{
	cx t;
	wr_key ak2 = cxt_key(kt, 61), ok2 = cxt_key(kt, 62);
	uint8_t req[256], more[256];
	size_t rn = 0, mn = 0;
	uint8_t old_blob[200];
	uint32_t old_len;
	cxt_dopt o2;
	cxt_tk save;

	cx_new(&t, kt, kt, kt, 0);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 4711));
	WRT_CHECK(t.e.c.req_new_gid == 1 && wri_cx_ops()->ident_gid(&t.e.c, WRI_ENTITY_MON) == -1);
	old_len = t.e.c.ticket[0].blob_len;
	memcpy(old_blob, t.e.c.ticket[0].blob, old_len);

	/* the second connection reclaims: global id in AUTH_REQUEST, the held ticket as the old ticket */
	cxt_dopt_default(&t.e, &o2, &ak2, &ok2);
	o2.auth.enc = 1;
	o2.auth.enc_key = &t.e.c.ticket[0].session_key;
	o2.auth.secret_id = 3;
	o2.auth.blob_data = 140;
	o2.extra[0].msga_key = &ak2;
	{
		wr_key prev = t.e.c.ticket[0].session_key; /* the reply blob is sealed with the PREVIOUS key */
		uint8_t pay[4096];
		size_t pn;

		o2.auth.enc_key = &prev;
		pn = cxt_build_done(&t.e, &o2, pay, sizeof(pay));
		t.e.x.now.mono_ms += 1000;
		WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&t.e, pay, pn, 4711, WRI_CONN_MODE_CRC, req, &rn, more, &mn));
	}
	WRT_CHECK(rn == 1u + 4u + 4u + 6u + 8u && wri_le64_get(req + rn - 8) == 4711);
	WRT_CHECK(mn == 36u - 13u + old_len && memcmp(more + 19, old_blob, old_len) == 0);
	WRT_CHECK(wri_le32_get(more + mn - 4) == 0x24u);
	WRT_CHECK(t.e.c.req_new_gid == 0 && wri_cx_ops()->ident_gid(&t.e.c, WRI_ENTITY_MON) == 4711);
	WRT_CHECK(t.e.c.global_id == 4711);
	WRT_CHECK(memcmp(t.e.c.ticket[0].session_key.secret, ak2.secret, ak2.len) == 0);
	WRT_CHECK(t.e.c.ticket[0].secret_id == 3 && t.e.c.ticket[0].blob_len == 13u + 140u);
	WRT_CHECK(t.e.c.ticket[1].secret_id == 7 && t.e.c.ticket[1].service == WRI_CX_SERVICE_OSD);

	/* enc = 1 sealed with the wrong key, and enc = 1 with no previous key at all */
	{
		wr_key bad = cxt_key(kt, 88);
		uint8_t pay[4096];
		size_t pn;

		save = o2.auth;
		o2.auth.enc_key = &bad;
		pn = cxt_build_done(&t.e, &o2, pay, sizeof(pay));
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, cxt_mon_hs(&t.e, pay, pn, 4711, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
		expect_clean(&t, WR_E_AUTH_DECRYPT);
		o2.auth = save;
		o2.auth.enc_key = &t.ak; /* a first contact holds no AUTH ticket: enc 1 cannot be opened */
		pn = cxt_build_done(&t.e, &o2, pay, sizeof(pay));
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cxt_mon_hs(&t.e, pay, pn, 4711, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	}
	cxt_env_free(&t.e);

	/* a reclaim that comes back with another global id drops the old OSD ticket (it is not ours) */
	cx_new(&t, kt, kt, kt, 0);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 4711));
	{
		cxt_dopt o3;
		uint8_t pay[4096];
		size_t pn;
		wr_key prev = t.e.c.ticket[0].session_key;

		cxt_dopt_default(&t.e, &o3, &ak2, &ok2);
		o3.auth.enc = 1;
		o3.auth.enc_key = &prev;
		o3.n_extra = 0;
		o3.extra[0].msga_key = &ak2;
		t.e.c.want_mask = WRI_CX_SERVICE_AUTH;
		pn = cxt_build_done(&t.e, &o3, pay, sizeof(pay));
		WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&t.e, pay, pn, 4712, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
		WRT_CHECK(t.e.c.global_id == 4712 && !t.e.c.ticket[1].have);
		WRT_CHECK(all_zero(t.e.c.ticket[1].blob, t.e.x.cfg.ticket_cap));
	}
	cxt_env_free(&t.e);

	/* an expired AUTH ticket is not presented: the next connection asks for a new session */
	cx_new(&t, kt, kt, kt, 0);
	WRT_CHECK_STATUS(WR_OK, cx_run(&t, 4711));
	t.e.x.now.mono_ms = CXT_T0 + 259200000ull;
	{
		uint8_t b[128];
		wri_wr w;

		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_cx_ops()->begin(&t.e.c, WRI_ENTITY_MON, &w));
		WRT_CHECK(t.e.c.req_new_gid == 1 && wri_le64_get(b + wri_wr_len(&w) - 8) == 0);
	}
	cxt_env_free(&t.e);
}

/* ---- OSD authorizer ----------------------------------------------------------------------------------------- */

typedef struct osd {
	cx t;
	uint64_t gid;
} osd;

static void osd_new(osd *o, unsigned pt, unsigned ot)
{
	cx_new(&o->t, pt, pt, ot, 0);
	o->gid = 9001;
	WRT_CHECK_STATUS(WR_OK, cx_run(&o->t, o->gid));
}

/* server challenge ciphertext, raw (no length prefix), under the OSD key */
static size_t srv_challenge(osd *o, uint64_t chal, uint32_t usage, uint8_t *out, size_t cap)
{
	uint8_t item[9];
	size_t n = 0;

	(void)cap;
	item[0] = 1;
	wri_le64_put(item + 1, chal);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&o->t.e.x, &o->t.ok, usage, item, sizeof(item), out, cap, &n));
	return n;
}

static size_t srv_reply(osd *o, uint8_t v, uint64_t npo, uint32_t secret, uint32_t usage, uint8_t *out, size_t cap)
{
	uint8_t item[96], ct[200];
	size_t n = 0, il = 9;

	(void)cap;
	item[0] = v;
	wri_le64_put(item + 1, npo);
	if (v >= 2) {
		wri_le32_put(item + 9, secret);
		memset(item + 13, 0x33, secret);
		il = 13u + secret;
	}
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&o->t.e.x, &o->t.ok, usage, item, il, ct, sizeof(ct), &n));
	wri_le32_put(out, (uint32_t)n);
	memcpy(out + 4, ct, n);
	return n + 4;
}

/* open a client authorizer proof and return the CephXAuthorize fields */
static void open_proof(osd *o, const uint8_t *az, size_t n, uint64_t *nonce, int *have, uint64_t *po, size_t *proof_ct)
{
	const wri_cx_ticket *t = &o->t.e.c.ticket[1];
	wri_rd r;
	uint32_t pn;
	const uint8_t *pl, *item = NULL;
	size_t il = 0;
	uint8_t scratch[256];

	wri_rd_init(&r, az, n);
	WRT_CHECK(wri_rd_u8(&r) == 1);
	WRT_CHECK(wri_rd_u64(&r) == o->gid);
	WRT_CHECK(wri_rd_u32(&r) == WRI_CX_SERVICE_OSD);
	WRT_CHECK(memcmp(wri_rd_bytes(&r, t->blob_len), t->blob, t->blob_len) == 0); /* the ticket, verbatim */
	pn = wri_rd_u32(&r);
	pl = wri_rd_bytes(&r, pn);
	WRT_CHECK(wri_rd_ok(&r) && wri_rd_left(&r) == 0);
	*proof_ct = pn;
	WRT_CHECK_STATUS(WR_OK, wri_cx_open(&o->t.e.x, &o->t.ok, WRI_CX_USAGE_AUTHORIZE, pl, pn, scratch, sizeof(scratch), &item, &il));
	WRT_CHECK(il == 18 && item[0] == 2);
	*nonce = wri_le64_get(item + 1);
	*have = item[9];
	*po = wri_le64_get(item + 10);
}

static void test_osd(unsigned pt, unsigned ot)
{
	osd o;
	const wri_auth_ops *ops = wri_cx_ops();
	uint8_t a1[512], a2[512], ch[128], rep[256];
	wri_wr w;
	size_t n1, n2, cn, rn, pc1, pc2;
	uint64_t nonce1, nonce2, po1, po2;
	int h1, h2;
	const uint8_t *k;
	size_t kn;

	osd_new(&o, pt, ot);
	/* first authorizer: one proof ciphertext of the size the captures show (32 for type 1, 67 for type 2) */
	wri_wr_init(&w, a1, sizeof(a1));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
	n1 = wri_wr_len(&w);
	open_proof(&o, a1, n1, &nonce1, &h1, &po1, &pc1);
	WRT_CHECK(pc1 == (ot == 1 ? 32u : 67u) && h1 == 0 && po1 == 0);
	WRT_CHECK(o.t.e.c.st == WRI_CX_OSD_SENT_AUTHORIZER);
	/* challenge round trip: same prefix, same nonce, have_challenge 1, plus_one = challenge + 1 */
	cn = srv_challenge(&o, 0xFFFFFFFFFFFFFFFFull, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, ch, sizeof(ch)); /* wraps */
	wri_wr_init(&w, a2, sizeof(a2));
	WRT_CHECK_STATUS(WR_OK, ops->more(&o.t.e.c, ch, cn, &w));
	n2 = wri_wr_len(&w);
	open_proof(&o, a2, n2, &nonce2, &h2, &po2, &pc2);
	WRT_CHECK(nonce2 == nonce1 && h2 == 1 && po2 == 0 && pc2 == pc1);
	WRT_CHECK(n1 - pc1 == n2 - pc2 && memcmp(a1, a2, n1 - pc1) == 0);
	WRT_CHECK(o.t.e.c.st == WRI_CX_OSD_SENT_CHALLENGE);
	/* the reply */
	rn = srv_reply(&o, 1, nonce1 + 1u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
	WRT_CHECK_STATUS(WR_OK, ops->done(&o.t.e.c, o.gid, WRI_CONN_MODE_CRC, rep, rn));
	ops->session_key(&o.t.e.c, &k, &kn);
	WRT_CHECK(k != NULL && kn == o.t.ok.len && memcmp(k, o.t.ok.secret, kn) == 0);
	WRT_CHECK(ops->ident_gid(&o.t.e.c, WRI_ENTITY_OSD) == (int64_t)o.gid);
	WRT_CHECK(o.t.e.c.authorizer_nonce == 0);
	cxt_env_free(&o.t.e);

	/* refusals. Each on a fresh handshake up to the point of the fault. */
	{
		unsigned c;

		for (c = 0; c < 9; c++) {
			wr_status want = WR_OK, got;
			uint64_t nn;

			osd_new(&o, pt, ot);
			wri_wr_init(&w, a1, sizeof(a1));
			WRT_CHECK_STATUS(WR_OK, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
			open_proof(&o, a1, wri_wr_len(&w), &nn, &h1, &po1, &pc1);
			cn = srv_challenge(&o, 77, c == 0 ? WRI_CX_USAGE_AUTHORIZE_REPLY : WRI_CX_USAGE_AUTHORIZE_CHALLENGE, ch, sizeof(ch));
			if (c == 1)
				ch[cn / 2] ^= 1; /* damaged challenge */
			if (c == 2)
				cn -= 1; /* truncated challenge */
			wri_wr_init(&w, a2, sizeof(a2));
			if (c == 0 || c == 1 || c == 2) {
				/* type 1 has no usage: a wrong usage only fails for type 2 */
				got = ops->more(&o.t.e.c, ch, cn, &w);
				want = (c == 0 && ot == 1) ? WR_OK : WR_E_AUTH_DECRYPT;
				WRT_CHECK_STATUS(want, got);
				if (got != WR_OK)
					WRT_CHECK(o.t.e.c.st == WRI_CX_FAILED && o.t.e.c.authorizer_nonce == 0);
				cxt_env_free(&o.t.e);
				continue;
			}
			WRT_CHECK_STATUS(WR_OK, ops->more(&o.t.e.c, ch, cn, &w));
			if (c == 3) { /* answers nonce + 2 */
				rn = srv_reply(&o, 1, nn + 2u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, ops->done(&o.t.e.c, o.gid, 1, rep, rn));
			} else if (c == 4) { /* a connection secret in crc mode */
				rn = srv_reply(&o, 2, nn + 1u, 64, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->done(&o.t.e.c, o.gid, 1, rep, rn));
			} else if (c == 5) { /* the mode is secure and the reply (version 1) has no secret */
				rn = srv_reply(&o, 1, nn + 1u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				WRT_CHECK_STATUS(WR_E_M2_SECRET, ops->done(&o.t.e.c, o.gid, WRI_CONN_MODE_SECURE, rep, rn));
			} else if (c == 6) { /* length prefix does not match */
				rn = srv_reply(&o, 1, nn + 1u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->done(&o.t.e.c, o.gid, 1, rep, rn - 1));
			} else if (c == 7) { /* the ticket was swapped under the handshake */
				wri_cx_slot_clear(&o.t.e.c, WRI_CX_SLOT_OSD);
				rn = srv_reply(&o, 1, nn + 1u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				WRT_CHECK_STATUS(WR_E_STATE, ops->done(&o.t.e.c, o.gid, 1, rep, rn));
			} else { /* done straight after begin without the challenge round */
				rn = srv_reply(&o, 1, nn + 1u, 0, WRI_CX_USAGE_AUTHORIZE_REPLY, rep, sizeof(rep));
				wri_wr_init(&w, a1, sizeof(a1));
				WRT_CHECK_STATUS(WR_OK, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
				WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->done(&o.t.e.c, o.gid, 1, rep, rn));
			}
			WRT_CHECK(o.t.e.c.st == WRI_CX_FAILED);
			{
				const uint8_t *kk = (const uint8_t *)1;
				size_t kkn = 1;

				ops->session_key(&o.t.e.c, &kk, &kkn);
				WRT_CHECK(kk == NULL && kkn == 0);
			}
			cxt_env_free(&o.t.e);
		}
	}

	/* no global id (cannot happen after a monitor handshake, but the machine checks) */
	osd_new(&o, pt, ot);
	o.t.e.c.global_id = 0;
	wri_wr_init(&w, a1, sizeof(a1));
	WRT_CHECK_STATUS(WR_E_AUTH_GID0, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
	/* writer too small for the authorizer */
	o.t.e.c.global_id = o.gid;
	wri_wr_init(&w, a1, 40);
	WRT_CHECK_STATUS(WR_E_TOOBIG, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
	/* a failing RNG */
	g_rng.strict = 1;
	g_rng.n = 0;
	wri_wr_init(&w, a1, sizeof(a1));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, ops->begin(&o.t.e.c, WRI_ENTITY_OSD, &w));
	cxt_env_free(&o.t.e);
}

int main(void)
{
	unsigned pt, ot;

	/* principal type, AUTH session key type (= principal's, cephx.md 3.4), OSD session key type */
	test_mon_errors(1, 1, 1);
	test_mon_errors(2, 2, 2);
	test_mon_errors(2, 2, 1); /* a type-2 principal with a type-1 OSD ticket (upgraded cluster) */
	test_mon_errors(1, 1, 2);
	test_reclaim(1);
	test_reclaim(2);
	for (pt = 1; pt <= 2; pt++)
		for (ot = 1; ot <= 2; ot++)
			test_osd(pt, ot);
	return wrt_finish();
}
