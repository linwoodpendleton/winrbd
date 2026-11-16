/* SPDX-License-Identifier: MIT */
/*
 * Tests of the cephx client machine (core/src/auth/wri_cx_client.c, wri_cx_ticket.c): replay of the
 * three connections of vectors/cephx/session-type{1,2}-crc.json with the host RNG scripted so the
 * client bytes equal the vector, the AUTH_SIGNATURE keys, ticket times with a fake clock, the real
 * captured AUTH_REQUEST / AUTH_REQUEST_MORE structure, init / budget / wipe behaviour.
 * Error paths and reclaim are in test_auth_client_err.c.
 */
#include "auth_cx_srv.h"

/* ---- stream parsing ----------------------------------------------------------------------------- */

typedef struct frame {
	uint8_t tag;
	const uint8_t *seg;
	uint32_t len;
	size_t end; /* offset just after the frame (segment and its inline crc) */
} frame;

/* One single-segment frame at p (32 byte preamble | segment | 4 byte crc when non-empty). */
static int frame_at(const uint8_t *b, size_t n, size_t p, frame *f)
{
	if (p + 32 > n)
		return -1;
	f->tag = b[p];
	f->len = wri_le32_get(b + p + 2);
	f->seg = b + p + 32;
	f->end = p + 32 + f->len + (f->len != 0 ? 4u : 0u);
	return f->end <= n ? 0 : -1;
}

static size_t parse_stream(const uint8_t *b, size_t n, frame *out, size_t max)
{
	size_t p, k = 0;

	if (n < 10 || memcmp(b, "ceph v2\n", 8) != 0)
		return 0;
	p = 10u + wri_le16_get(b + 8);
	while (p < n && k < max) {
		if (frame_at(b, n, p, &out[k]) != 0)
			return 0;
		p = out[k].end;
		k++;
	}
	return k;
}

static const frame *find(const frame *f, size_t n, uint8_t tag)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (f[i].tag == tag)
			return &f[i];
	return NULL;
}

/* A blob (u32 len | bytes) filling the whole segment. */
static int seg_blob(const frame *f, const uint8_t **p, size_t *n)
{
	wri_rd r;

	wri_rd_init(&r, f->seg, f->len);
	*n = wri_rd_u32(&r);
	*p = wri_rd_bytes(&r, *n);
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

static uint64_t jhex64(const wrt_json *j, wrt_tok o, const char *key)
{
	char *s = wrt_json_strdup(j, wrt_json_get(j, o, key));
	uint64_t v = s != NULL ? strtoull(s, NULL, 16) : 0;

	free(s);
	return v;
}

/* det(label, 16 or 8): SHA-256("winrbd-vector|<label>|0") truncated, as the vector generator does. */
static void det(const char *label, uint8_t *out, size_t n)
{
	char buf[96];
	uint8_t d[32];
	wri_sha256_ctx c;

	snprintf(buf, sizeof(buf), "winrbd-vector|%s|0", label);
	wri_sha256_init(&c);
	wri_sha256_update(&c, (const uint8_t *)buf, strlen(buf));
	wri_sha256_final(&c, d);
	memcpy(out, d, n);
}

static void hmac256(const uint8_t *key, size_t kn, const uint8_t *p, size_t n, uint8_t out[32])
{
	wr_iov iov;

	iov.base = p;
	iov.len = n;
	wri_hmac_sha256(key, kn, &iov, 1, out);
}

/* ---- replay of one connection --------------------------------------------------------------------- */

typedef struct conn_in {
	const uint8_t *cs, *ss;
	size_t cn, sn;
	wrt_json *j;
	wrt_tok ex;
} conn_in;

static void check_signatures(const conn_in *ci, const frame *cf, size_t ncf, const frame *sf, size_t nsf,
			     const uint8_t *key, size_t klen)
{
	uint8_t want[32], got[32], *exp;
	size_t en = 0;
	const frame *done = find(sf, nsf, 6), *more = find(cf, ncf, 5);

	/* the client signs what it received through the end of AUTH_DONE, the server what it received
	 * through the end of the last AUTH_REQUEST(_MORE) (cephx.md 2.9) */
	hmac256(key, klen, ci->ss, done->end, got);
	WRT_CHECK(wrt_json_get_hex(ci->j, ci->ex, "auth_signature_client", &exp, &en) == 0 && en == 32);
	memcpy(want, exp, 32);
	free(exp);
	WRT_CHECK_MEM(got, want, 32);
	hmac256(key, klen, ci->cs, more->end, got);
	WRT_CHECK(wrt_json_get_hex(ci->j, ci->ex, "auth_signature_server", &exp, &en) == 0 && en == 32);
	memcpy(want, exp, 32);
	free(exp);
	WRT_CHECK_MEM(got, want, 32);
}

/* Both directions of the AUTH_REQUEST frame: payload blob of the client's AUTH_REQUEST. */
static int areq_payload(const frame *f, const uint8_t **p, size_t *n)
{
	wri_rd r;
	uint32_t i, nm;

	wri_rd_init(&r, f->seg, f->len);
	(void)wri_rd_u32(&r);
	nm = wri_rd_count(&r, 16, 4);
	for (i = 0; i < nm; i++)
		(void)wri_rd_u32(&r);
	*n = wri_rd_u32(&r);
	*p = wri_rd_bytes(&r, *n);
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? 0 : -1;
}

/* mon connection: one fresh machine per call unless `e` is passed in already initialised. */
static void replay_conn(cxt_env *e, const conn_in *ci, unsigned ktype, uint64_t gid_prev_unused)
{
	frame cf[8], sf[8];
	size_t ncf = parse_stream(ci->cs, ci->cn, cf, 8), nsf = parse_stream(ci->ss, ci->sn, sf, 8);
	const wri_auth_ops *ops = wri_cx_ops();
	const frame *areq, *amore, *rmore, *done;
	const uint8_t *want, *pl;
	size_t wn, pn, ksn = 0;
	uint8_t out[1024], *ks = NULL;
	wri_wr w;
	char *kind = wrt_json_strdup(ci->j, wrt_json_get(ci->j, ci->ex, "kind"));
	int is_mon = kind != NULL && strcmp(kind, "mon") == 0;
	uint64_t gid;
	char label[48];
	uint8_t tmp[16];

	(void)gid_prev_unused;
	free(kind);
	WRT_CHECK(ncf >= 4 && nsf >= 4);
	areq = find(cf, ncf, 2);
	amore = find(cf, ncf, 5);
	rmore = find(sf, nsf, 4);
	done = find(sf, nsf, 6);
	if (!areq || !amore || !rmore || !done)
		return;
	gid = (uint64_t)wrt_json_int(ci->j, wrt_json_get(ci->j, ci->ex, "global_id"), NULL);

	cxt_rng_free();
	if (is_mon) {
		cxt_rng_push_u64(jhex64(ci->j, ci->ex, "client_challenge"));
		e->c.want_mask = (uint32_t)wrt_json_int(ci->j, wrt_json_get(ci->j, ci->ex, "request_mask"), NULL);
	} else {
		cxt_rng_push_u64(jhex64(ci->j, ci->ex, "nonce"));
		if (ktype == 2) { /* the two confounders of the type-2 proofs, in the order they are drawn */
			snprintf(label, sizeof(label), "t%u-m1-osd-c1", ktype);
			det(label, tmp, 16);
			cxt_rng_push(tmp, 16);
			snprintf(label, sizeof(label), "t%u-m1-osd-c2", ktype);
			det(label, tmp, 16);
			cxt_rng_push(tmp, 16);
		}
	}

	/* begin */
	WRT_CHECK(areq_payload(areq, &want, &wn) == 0);
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e->c, is_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD, &w));
	WRT_CHECK(wri_wr_len(&w) == wn);
	if (wri_wr_len(&w) == wn)
		WRT_CHECK_MEM(out, want, wn);

	/* more */
	WRT_CHECK(seg_blob(rmore, &pl, &pn) == 0);
	WRT_CHECK(seg_blob(amore, &want, &wn) == 0);
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->more(&e->c, pl, pn, &w));
	WRT_CHECK(wri_wr_len(&w) == wn);
	if (wri_wr_len(&w) == wn)
		WRT_CHECK_MEM(out, want, wn);

	/* done */
	{
		wri_rd r;
		uint64_t dgid;
		uint32_t mode;

		wri_rd_init(&r, done->seg, done->len);
		dgid = wri_rd_u64(&r);
		mode = wri_rd_u32(&r);
		pn = wri_rd_u32(&r);
		pl = wri_rd_bytes(&r, pn);
		WRT_CHECK(wri_rd_ok(&r) && dgid == gid);
		WRT_CHECK_STATUS(WR_OK, ops->done(&e->c, dgid, mode, pl, pn));
	}
	WRT_CHECK(g_rng.bad == 0 && g_rng.i == g_rng.n);
	WRT_CHECK(e->c.st == WRI_CX_DONE);

	/* session key == the vector's, and signs the transcripts to the vector's signatures */
	{
		const uint8_t *k = NULL;
		size_t kn = 0;

		ops->session_key(&e->c, &k, &kn);
		WRT_CHECK(k != NULL && kn != 0);
		if (is_mon) {
			WRT_CHECK(wrt_json_get_hex(ci->j, ci->ex, "auth_session_key_secret", &ks, &ksn) == 0);
			WRT_CHECK(kn == ksn && k != NULL && memcmp(k, ks, kn) == 0);
			WRT_CHECK((unsigned)e->c.ticket[WRI_CX_SLOT_AUTH].session_key.type ==
				  (unsigned)wrt_json_int(ci->j, wrt_json_get(ci->j, ci->ex, "auth_session_key_type"), NULL));
			free(ks);
		}
		if (k != NULL)
			check_signatures(ci, cf, ncf, sf, nsf, k, kn);
	}
	WRT_CHECK_U64(e->c.global_id, gid);
	WRT_CHECK(ops->ident_gid(&e->c, is_mon ? WRI_ENTITY_MON : WRI_ENTITY_OSD) == (is_mon ? -1 : (int64_t)gid));
}

static void check_tickets(cxt_env *e, const conn_in *ci)
{
	wrt_tok tl = wrt_json_get(ci->j, ci->ex, "tickets");
	size_t i, nt = wrt_json_count(ci->j, tl);
	uint32_t mask = (uint32_t)wrt_json_int(ci->j, wrt_json_get(ci->j, ci->ex, "request_mask"), NULL);
	const wri_cx_ticket *t = wri_cx_ticket_get(&e->c, WRI_CX_SERVICE_AUTH);

	/* AUTH: 259200 s validity as a duration from receipt, renew at 3/4 of it */
	WRT_CHECK(t != NULL);
	if (t != NULL) {
		WRT_CHECK_U64(t->valid_until_ms, CXT_T0 + 259200000ull);
		WRT_CHECK_U64(t->renew_at_ms, CXT_T0 + 259200000ull - 64800000ull);
		WRT_CHECK_U64(t->secret_id, 2);
		WRT_CHECK(t->blob_len == 13u + 150u && t->blob[0] == 1);
	}
	for (i = 0; i < nt; i++) {
		wrt_tok ti = wrt_json_at(ci->j, tl, i);
		uint32_t sid = (uint32_t)wrt_json_int(ci->j, wrt_json_get(ci->j, ti, "service_id"), NULL);
		uint8_t *sk = NULL;
		size_t skn = 0;
		const wri_cx_ticket *o = wri_cx_ticket_get(&e->c, sid);

		if (sid != WRI_CX_SERVICE_OSD) { /* MON and MGR tickets are not kept */
			WRT_CHECK(o == NULL);
			continue;
		}
		WRT_CHECK((mask & sid) != 0 && o != NULL);
		WRT_CHECK(wrt_json_get_hex(ci->j, ti, "session_key_secret", &sk, &skn) == 0);
		if (o != NULL) {
			WRT_CHECK(o->session_key.len == skn && memcmp(o->session_key.secret, sk, skn) == 0);
			WRT_CHECK_U64(o->valid_until_ms, CXT_T0 + 3600000ull);
			WRT_CHECK_U64(o->renew_at_ms, CXT_T0 + 3600000ull - 900000ull);
		}
		free(sk);
	}
	WRT_CHECK_U64(wri_cx_next_renew_ms(&e->c), nt > 0 ? CXT_T0 + 3600000ull - 900000ull : CXT_T0 + 259200000ull - 64800000ull);
}

static void test_vector_file(const char *rel, unsigned ktype)
{
	wrt_json j;
	wrt_tok root, conns;
	char *b64, *ent;
	wr_key pk;
	cxt_env e0, e1;
	size_t i;
	uint8_t *cs[3], *ss[3];
	size_t cn[3], sn[3];

	if (wrt_json_load_vec(&j, rel) != 0) {
		WRT_CHECK(!"vector file loads");
		return;
	}
	root = wrt_json_root(&j);
	conns = wrt_json_get(&j, root, "connections");
	b64 = wrt_json_strdup(&j, wrt_json_get(&j, root, "keyring_key_base64"));
	ent = wrt_json_strdup(&j, wrt_json_get(&j, root, "entity"));
	WRT_CHECK(b64 && ent && wrt_json_count(&j, conns) == 3);
	WRT_CHECK_STATUS(WR_OK, wr_key_parse_base64(&pk, b64, strlen(b64)));
	WRT_CHECK(pk.type == ktype);
	for (i = 0; i < 3; i++) {
		wrt_tok c = wrt_json_at(&j, conns, i);
		WRT_CHECK(wrt_json_get_hex(&j, c, "client_stream", &cs[i], &cn[i]) == 0);
		WRT_CHECK(wrt_json_get_hex(&j, c, "server_stream", &ss[i], &sn[i]) == 0);
	}
	/* machine 0: the mask-0x35 monitor connection, then the OSD authorizer that uses its OSD ticket */
	WRT_CHECK(cxt_env_init(&e0, ent, &pk, 0) == 0);
	{
		conn_in ci;

		ci.j = &j;
		ci.cs = cs[0]; ci.cn = cn[0]; ci.ss = ss[0]; ci.sn = sn[0];
		ci.ex = wrt_json_get(&j, wrt_json_at(&j, conns, 0), "expect");
		replay_conn(&e0, &ci, ktype, 0);
		check_tickets(&e0, &ci);
		ci.cs = cs[2]; ci.cn = cn[2]; ci.ss = ss[2]; ci.sn = sn[2];
		ci.ex = wrt_json_get(&j, wrt_json_at(&j, conns, 2), "expect");
		replay_conn(&e0, &ci, ktype, 0);
		/* the OSD ticket and the AUTH ticket are untouched by the OSD handshake */
		WRT_CHECK(wri_cx_have(&e0.c, WRI_CX_SERVICE_OSD, CXT_T0 + 1000));
	}
	/* machine 1: AUTH only (mask 0x20, empty extra) */
	WRT_CHECK(cxt_env_init(&e1, ent, &pk, 0) == 0);
	{
		conn_in ci;

		ci.j = &j;
		ci.cs = cs[1]; ci.cn = cn[1]; ci.ss = ss[1]; ci.sn = sn[1];
		ci.ex = wrt_json_get(&j, wrt_json_at(&j, conns, 1), "expect");
		replay_conn(&e1, &ci, ktype, 0);
		WRT_CHECK(wri_cx_ticket_get(&e1.c, WRI_CX_SERVICE_OSD) == NULL);
		WRT_CHECK(wri_cx_ticket_get(&e1.c, WRI_CX_SERVICE_AUTH) != NULL);
	}
	cxt_env_free(&e0);
	cxt_env_free(&e1);
	for (i = 0; i < 3; i++) {
		free(cs[i]);
		free(ss[i]);
	}
	free(b64);
	free(ent);
	wrt_json_free(&j);
}

/* ---- real captured structure ------------------------------------------------------------------------ */

static void test_captured(void)
{
	wrt_json j;
	wrt_tok fr;
	uint8_t *areq = NULL, *amore = NULL;
	size_t an = 0, mn = 0;
	frame f1, f2;
	const uint8_t *want, *pl;
	size_t wn;
	wr_key pk = cxt_key(WR_KEY_TYPE_AES256K, 9);
	cxt_env e;
	uint8_t out[128], chal[9];
	wri_wr w;
	const wri_auth_ops *ops = wri_cx_ops();

	if (wrt_json_load_vec(&j, "cephx/captured-scrubbed-frames.json") != 0) {
		WRT_CHECK(!"captured frames load");
		return;
	}
	fr = wrt_json_get(&j, wrt_json_get(&j, wrt_json_root(&j), "frames"), "k2-rbd-info-v1");
	WRT_CHECK(wrt_json_get_hex(&j, fr, "auth_request", &areq, &an) == 0);
	WRT_CHECK(wrt_json_get_hex(&j, fr, "auth_request_more", &amore, &mn) == 0);
	WRT_CHECK(frame_at(areq, an, 0, &f1) == 0 && frame_at(amore, mn, 0, &f2) == 0);
	WRT_CHECK(cxt_env_init(&e, "client.winrbd", &pk, 0) == 0);
	cxt_rng_free();
	cxt_rng_push_u64(0x99aabbccddeeff00ull);

	/* a real AUTH_REQUEST for client.winrbd: 1 + 4 + (4 + 6) + 8 = 23 byte payload, global id 0 */
	WRT_CHECK(areq_payload(&f1, &want, &wn) == 0 && wn == 23);
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	WRT_CHECK(wri_wr_len(&w) == wn);
	if (wri_wr_len(&w) == wn)
		WRT_CHECK_MEM(out, want, wn);

	/* the real AUTH_REQUEST_MORE: everything but the proof (8 bytes after header, version, challenge) */
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, ops->more(&e.c, chal, sizeof(chal), &w));
	WRT_CHECK(seg_blob(&f2, &pl, &wn) == 0 && wn == 36);
	WRT_CHECK(wri_wr_len(&w) == 36);
	if (wri_wr_len(&w) == 36 && wn == 36) {
		WRT_CHECK_MEM(out, pl, 11);           /* request header 0x0100, v 3, client challenge */
		WRT_CHECK_MEM(out + 19, pl + 19, 13); /* the empty old ticket */
		/* the stock client asks for AUTH only (0x20) on this connection; this client asks for AUTH | OSD */
		WRT_CHECK(wri_le32_get(pl + 32) == 0x20u && wri_le32_get(out + 32) == 0x24u);
	}
	cxt_env_free(&e);
	free(areq);
	free(amore);
	wrt_json_free(&j);
}

/* ---- init, budget, wipe ---------------------------------------------------------------------------- */

static int all_zero(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

static void test_init_wipe(void)
{
	wr_key k1 = cxt_key(WR_KEY_TYPE_AES, 1), k2 = cxt_key(WR_KEY_TYPE_AES256K, 2), bad;
	cxt_env e;
	size_t need = 0;
	wr_config cfg;
	wri_arena a;
	wri_cx_client c;
	uint8_t *blob;
	uint8_t mem[256] = {0};

	/* mem() equals what init takes; the user prefix is stripped */
	WRT_CHECK(cxt_env_init(&e, "client.alice", &k2, 0) == 0);
	WRT_CHECK(strcmp(e.c.user, "alice") == 0 && e.c.user_len == 5);
	WRT_CHECK_STATUS(WR_OK, wri_cx_client_mem(&e.x.cfg, &need));
	WRT_CHECK(e.a.used == need && need > 2u * e.x.cfg.ticket_cap);
	WRT_CHECK(e.c.want_mask == 0x24u && e.c.principal.type == 2 && e.c.st == WRI_CX_IDLE);
	cxt_env_free(&e);
	WRT_CHECK(cxt_env_init(&e, "bob", &k1, 0) == 0);
	WRT_CHECK(strcmp(e.c.user, "bob") == 0);
	cxt_env_free(&e);
	WRT_CHECK(cxt_env_init(&e, "client.x.y", &k1, 0) == 0 && strcmp(e.c.user, "x.y") == 0);
	cxt_env_free(&e);

	/* bad user / key / ticket_cap: refused, and *c is zero */
	WRT_CHECK(cxt_env_init(&e, "client.", &k1, 0) != 0);
	cxt_env_free(&e);
	WRT_CHECK(cxt_env_init(&e, "", &k1, 0) != 0);
	cxt_env_free(&e);
	bad = k1;
	bad.type = 7;
	WRT_CHECK(cxt_env_init(&e, "a", &bad, 0) != 0);
	cxt_env_free(&e);
	bad = k2;
	bad.len = 31;
	WRT_CHECK(cxt_env_init(&e, "a", &bad, 0) != 0);
	cxt_env_free(&e);
	wr_config_profile_harness(&cfg);
	cfg.ticket_cap = 12;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_mem(&cfg, &need));
	cfg.ticket_cap = 0;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_mem(&cfg, &need));
	cfg.ticket_cap = 65537;
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_mem(&cfg, &need));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_mem(NULL, &need));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_mem(&cfg, NULL));

	/* arena too small: WR_E_BUDGET, key and user wiped from *c, nothing half-initialised */
	{
		cxt_env t;

		memset(&t, 0, sizeof(t));
		wr_config_profile_harness(&t.x.cfg);
		t.x.host.size = (uint32_t)sizeof(t.x.host);
		t.x.host.random = cxt_random;
		wri_arena_init(&a, mem, sizeof(mem));
		memset(&c, 0xAA, sizeof(c));
		strncpy(t.spec.user, "carol", sizeof(t.spec.user) - 1);
		t.spec.key = k2;
		WRT_CHECK_STATUS(WR_E_BUDGET, wri_cx_client_init(&c, &t.x, &a, &t.spec));
		WRT_CHECK(all_zero((const uint8_t *)&c, sizeof(c)));
		WRT_CHECK(all_zero(mem, sizeof(mem)));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_init(&c, NULL, &a, &t.spec));
		WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_client_init(NULL, &t.x, &a, &t.spec));
	}

	/* after a handshake: forget keeps the principal and clears every ticket byte; wipe clears all */
	WRT_CHECK(cxt_env_init(&e, "client.dave", &k2, 0) == 0);
	{
		wr_key ak = cxt_key(2, 40), ok = cxt_key(1, 50);

		cxt_rng_free();
		WRT_CHECK_STATUS(WR_OK, cxt_good_mon(&e, &ak, &ok, 4242));
	}
	blob = e.c.ticket[WRI_CX_SLOT_AUTH].blob;
	WRT_CHECK(!all_zero(blob, e.c.ticket[WRI_CX_SLOT_AUTH].blob_len));
	wri_cx_forget(&e.c);
	WRT_CHECK(all_zero(blob, e.x.cfg.ticket_cap) && all_zero(e.c.ticket[1].blob, e.x.cfg.ticket_cap));
	WRT_CHECK(all_zero(e.c.scratch, e.c.scratch_cap));
	WRT_CHECK(!e.c.ticket[0].have && !e.c.ticket[1].have && e.c.global_id == 0);
	WRT_CHECK(all_zero(e.c.ticket[0].session_key.secret, WR_KEY_MAX) && e.c.principal.type == 2);
	WRT_CHECK(wri_cx_next_renew_ms(&e.c) == WR_DEADLINE_NONE);
	{
		wr_key ak = cxt_key(2, 41), ok = cxt_key(2, 51);

		cxt_rng_free();
		WRT_CHECK_STATUS(WR_OK, cxt_good_mon(&e, &ak, &ok, 4243));
	}
	WRT_CHECK(!all_zero(e.mem, e.a.used));
	wri_cx_client_wipe(&e.c);
	WRT_CHECK(all_zero((const uint8_t *)&e.c, sizeof(e.c)));
	WRT_CHECK(all_zero(e.mem, e.a.used)); /* every ticket blob and the scratch are zero again */
	/* a wiped machine refuses, it does not crash */
	{
		wri_wr w;
		uint8_t b[64];

		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK(wri_cx_ops()->begin(&e.c, WRI_ENTITY_MON, &w) != WR_OK);
	}
	free(e.raw);
}

/* ---- ticket clock ------------------------------------------------------------------------------------ */

static void test_clock(void)
{
	wr_key pk = cxt_key(2, 3), ak = cxt_key(2, 4), ok = cxt_key(2, 5);
	cxt_env e;
	cxt_dopt o;
	uint8_t buf[4096];
	size_t n;
	const wri_cx_ticket *t;

	WRT_CHECK(cxt_env_init(&e, "u", &pk, 0) == 0);
	e.x.now.mono_ms = 5000; /* an arbitrary monotonic epoch */
	cxt_dopt_default(&e, &o, &ak, &ok);
	o.auth.val_s = 3601;       /* quarter is real valued: 900.25 s */
	o.extra[0].val_s = 10;     /* ... and with a nanosecond part that does not count towards it */
	o.extra[0].val_ns = 500000000;
	o.extra[0].msga_key = &ak;
	n = cxt_build_done(&e, &o, buf, sizeof(buf));
	cxt_rng_free();
	WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	t = wri_cx_ticket_get(&e.c, WRI_CX_SERVICE_AUTH);
	WRT_CHECK(t != NULL);
	if (t != NULL) {
		WRT_CHECK_U64(t->valid_until_ms, 5000ull + 3601000ull);
		WRT_CHECK_U64(t->renew_at_ms, 5000ull + 3601000ull - 900250ull);
	}
	t = wri_cx_ticket_get(&e.c, WRI_CX_SERVICE_OSD);
	WRT_CHECK(t != NULL);
	if (t != NULL) {
		WRT_CHECK_U64(t->valid_until_ms, 5000ull + 10500ull);
		WRT_CHECK_U64(t->renew_at_ms, 5000ull + 10500ull - 2500ull);
	}
	WRT_CHECK_U64(wri_cx_next_renew_ms(&e.c), 5000ull + 10500ull - 2500ull);
	/* held while now < valid_until */
	WRT_CHECK(wri_cx_have(&e.c, WRI_CX_SERVICE_OSD, 5000 + 10499));
	WRT_CHECK(!wri_cx_have(&e.c, WRI_CX_SERVICE_OSD, 5000 + 10500));
	WRT_CHECK(wri_cx_have(&e.c, WRI_CX_SERVICE_AUTH, 5000 + 10500));
	WRT_CHECK(!wri_cx_have(&e.c, WRI_CX_SERVICE_MON, 5000));
	WRT_CHECK(wri_cx_ticket_get(&e.c, WRI_CX_SERVICE_MON) == NULL);

	/* an expired OSD ticket is never used: begin refuses */
	{
		uint8_t b[512];
		wri_wr w;

		e.x.now.mono_ms = 5000 + 10500;
		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_ops()->begin(&e.c, WRI_ENTITY_OSD, &w));
		WRT_CHECK(e.c.st == WRI_CX_FAILED && e.c.err.status == WR_E_AUTH_TICKET_EXPIRED);
		e.x.now.mono_ms = 5000 + 10499;
		wri_wr_init(&w, b, sizeof(b));
		WRT_CHECK_STATUS(WR_OK, wri_cx_ops()->begin(&e.c, WRI_ENTITY_OSD, &w));
	}
	cxt_env_free(&e);
}

/* ---- stale tickets and hostile ticket-reply shapes ---------------------------------------------------- */

static int all_zero_bytes(const uint8_t *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (p[i] != 0)
			return 0;
	return 1;
}

/* After a refused AUTH_DONE the machine holds nothing (the reply is never half used). */
static void expect_forgotten(cxt_env *e, wr_status st)
{
	WRT_CHECK(e->c.st == WRI_CX_FAILED);
	WRT_CHECK(e->c.err.status == st);
	WRT_CHECK(!e->c.ticket[0].have && !e->c.ticket[1].have && e->c.global_id == 0);
	WRT_CHECK(all_zero_bytes(e->c.ticket[0].session_key.secret, WR_KEY_MAX));
	WRT_CHECK(all_zero_bytes(e->c.ticket[1].session_key.secret, WR_KEY_MAX));
	WRT_CHECK(all_zero_bytes(e->c.scratch, e->c.scratch_cap));
}

/* A reply that leaves an OSD ticket from an earlier session in place must not look complete once that
 * ticket has expired: "held" means unexpired. */
static void test_stale_osd_ticket(unsigned kt)
{
	wr_key pk = cxt_key(kt, 3), ak = cxt_key(kt, 4), ok = cxt_key(kt, 5), ak2 = cxt_key(kt, 14);
	cxt_env e;
	cxt_dopt o;
	uint8_t buf[4096];
	size_t n;

	WRT_CHECK(cxt_env_init(&e, "u", &pk, 0) == 0);
	cxt_rng_free();
	cxt_dopt_default(&e, &o, &ak, &ok);
	o.extra[0].msga_key = &ak;
	n = cxt_build_done(&e, &o, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	WRT_CHECK(wri_cx_have(&e.c, WRI_CX_SERVICE_OSD, e.x.now.mono_ms));

	/* the OSD ticket (1 h) has run out, the AUTH ticket (72 h) has not; the monitor hands back the same
	 * global id with a fresh AUTH ticket (ticket_enc 0) and no OSD ticket at all */
	e.x.now.mono_ms = CXT_T0 + 3600000ull;
	WRT_CHECK(!wri_cx_have(&e.c, WRI_CX_SERVICE_OSD, e.x.now.mono_ms) && e.c.ticket[1].have);
	cxt_dopt_default(&e, &o, &ak2, &ok);
	o.n_extra = 0;
	o.extra[0].msga_key = &ak2;
	n = cxt_build_done(&e, &o, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	expect_forgotten(&e, WR_E_AUTH_PROTO);
	cxt_env_free(&e);

	/* ... while a still valid old OSD ticket is kept when only AUTH is renewed */
	WRT_CHECK(cxt_env_init(&e, "u", &pk, 0) == 0);
	cxt_rng_free();
	cxt_dopt_default(&e, &o, &ak, &ok);
	o.extra[0].msga_key = &ak;
	n = cxt_build_done(&e, &o, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	e.x.now.mono_ms = CXT_T0 + 1000ull;
	cxt_dopt_default(&e, &o, &ak2, &ok);
	o.n_extra = 0;
	n = cxt_build_done(&e, &o, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
	WRT_CHECK(e.c.ticket[1].have && e.c.ticket[1].secret_id == 7);
	cxt_env_free(&e);
}

/* Ticket counts and lengths from the wire are capped before they size anything. */
static void test_reply_limits(unsigned kt)
{
	wr_key pk = cxt_key(kt, 3), ak = cxt_key(kt, 4), ok = cxt_key(kt, 5);
	enum { CASES = 9 };
	unsigned c;

	for (c = 0; c < CASES; c++) {
		cxt_env e;
		cxt_dopt o;
		uint8_t buf[8192], ex[2048], big[600];
		size_t n, xn = 0;
		wr_status st;

		WRT_CHECK(cxt_env_init(&e, "u", &pk, 0) == 0);
		cxt_rng_free();
		cxt_dopt_default(&e, &o, &ak, &ok);
		o.extra[0].msga_key = &ak;
		memset(ex, 0, sizeof(ex));
		memset(big, 0x5A, sizeof(big));
		if (c <= 2) { /* the first reply must carry exactly one ticket: 0, 2 and a hostile count */
			wri_wr w;

			wri_wr_init(&w, buf, sizeof(buf));
			wri_wr_u16(&w, WRI_CX_REQ_GET_AUTH_SESSION_KEY);
			wri_wr_i32(&w, 0);
			wri_wr_u8(&w, 1);
			wri_wr_u32(&w, c == 0 ? 0u : c == 1 ? 2u : 0xFFFFFFFFu);
			wri_wr_zero(&w, 64);
			n = wri_wr_len(&w);
			WRT_CHECK(wri_wr_ok(&w));
		} else {
			wri_wr w;

			o.tail = 0;
			n = cxt_build_done(&e, &o, buf, sizeof(buf));
			wri_wr_init(&w, ex, sizeof(ex));
			wri_wr_u8(&w, 1);
			if (c == 3) { /* nine tickets: more than any reply has services */
				wri_wr_u32(&w, 9);
				wri_wr_zero(&w, 9 * 20);
			} else if (c == 4) { /* a count the bytes behind it cannot hold */
				wri_wr_u32(&w, 8);
				wri_wr_zero(&w, 30);
			} else if (c == 5) { /* msg_a longer than any ticket key can be */
				wri_wr_u32(&w, 1);
				wri_wr_u32(&w, WRI_CX_SERVICE_OSD);
				wri_wr_u8(&w, 1);
				wri_wr_u32(&w, 513);
				wri_wr_bytes(&w, big, 513 <= sizeof(big) ? 513 : sizeof(big));
				wri_wr_zero(&w, 20);
				wri_wr_u8(&w, 0);
				wri_wr_u32(&w, 13);
				wri_wr_zero(&w, 13);
			} else if (c == 6) { /* msg_a length that runs past the reply */
				wri_wr_u32(&w, 1);
				wri_wr_u32(&w, WRI_CX_SERVICE_OSD);
				wri_wr_u8(&w, 1);
				wri_wr_u32(&w, 0xFFFFFFF0u);
				wri_wr_zero(&w, 40);
			} else if (c == 7) { /* an encryption flag that is neither 0 nor 1 */
				wri_wr_u32(&w, 1);
				wri_wr_u32(&w, WRI_CX_SERVICE_OSD);
				wri_wr_u8(&w, 1);
				wri_wr_u32(&w, 48);
				wri_wr_zero(&w, 48);
				wri_wr_u8(&w, 2);
				wri_wr_u32(&w, 13);
				wri_wr_zero(&w, 13);
			} else { /* blob length that runs past the reply */
				wri_wr_u32(&w, 1);
				wri_wr_u32(&w, WRI_CX_SERVICE_OSD);
				wri_wr_u8(&w, 1);
				wri_wr_u32(&w, 48);
				wri_wr_zero(&w, 48);
				wri_wr_u8(&w, 0);
				wri_wr_u32(&w, 0xFFFFFFFFu);
				wri_wr_zero(&w, 13);
			}
			WRT_CHECK(wri_wr_ok(&w));
			xn = wri_wr_len(&w);
			wri_le32_put(buf + n, 0); /* cbl: empty */
			wri_le32_put(buf + n + 4, (uint32_t)xn);
			memcpy(buf + n + 8, ex, xn);
			n += 8 + xn;
		}
		st = cxt_mon_hs(&e, buf, n, 77, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL);
		WRT_CHECK(st != WR_OK);
		if (c == 0 || c == 1) {
			WRT_CHECK_STATUS(WR_E_AUTH_PROTO, st);
		} else if (c == 2 || c == 3 || c == 4) {
			WRT_CHECK_STATUS(WR_E_TOOBIG, st);
		} else if (c == 5 || c == 7) {
			WRT_CHECK_STATUS(WR_E_AUTH_PROTO, st);
		}
		expect_forgotten(&e, st);
		cxt_env_free(&e);
	}
}

/* ---- machine basics ------------------------------------------------------------------------------------- */

static void test_basics(void)
{
	wr_key pk = cxt_key(1, 3);
	cxt_env e;
	const wri_auth_ops *ops = wri_cx_ops();
	const uint8_t *k = (const uint8_t *)1;
	size_t kn = 5;
	uint8_t b[512];
	wri_wr w;
	uint8_t chal[9] = {1, 1, 0, 0, 0, 0, 0, 0, 0};

	WRT_CHECK(ops->begin && ops->more && ops->done && ops->session_key && ops->ident_gid);
	WRT_CHECK(cxt_env_init(&e, "u", &pk, 0) == 0);
	cxt_rng_free();
	/* no key and gid -1 before anything finished */
	ops->session_key(&e.c, &k, &kn);
	WRT_CHECK(k == NULL && kn == 0);
	WRT_CHECK(ops->ident_gid(&e.c, WRI_ENTITY_MON) == -1);
	/* more / done out of order */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->more(&e.c, chal, sizeof(chal), &w));
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->done(&e.c, 1, 1, b, 0));
	/* only monitors and OSDs */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_INVAL, ops->begin(&e.c, WRI_ENTITY_CLIENT, &w));
	/* an OSD handshake needs a ticket */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, ops->begin(&e.c, WRI_ENTITY_OSD, &w));
	/* AUTH_REQUEST payload for a new session; output too small is an error, not an overrun */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	WRT_CHECK(wri_wr_len(&w) == 1u + 4u + 5u + 8u && b[0] == 10 && wri_le32_get(b + 1) == 8u);
	WRT_CHECK(e.c.st == WRI_CX_MON_SENT_REQ && e.c.req_new_gid == 1);
	wri_wr_init(&w, b, 10);
	WRT_CHECK_STATUS(WR_E_TOOBIG, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	/* a second AUTH_REPLY_MORE, a zero challenge, a short challenge */
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	wri_wr_init(&w, b, sizeof(b));
	memset(chal + 1, 0, 8);
	WRT_CHECK_STATUS(WR_E_AUTH_PROTO, ops->more(&e.c, chal, sizeof(chal), &w));
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_TRUNCATED, ops->more(&e.c, chal, 5, &w));
	/* the host RNG failing is reported, never replaced by something weaker */
	cxt_rng_free();
	g_rng.strict = 1;
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_OK, ops->begin(&e.c, WRI_ENTITY_MON, &w));
	chal[1] = 1;
	wri_wr_init(&w, b, sizeof(b));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, ops->more(&e.c, chal, sizeof(chal), &w));
	cxt_env_free(&e);
}

int main(void)
{
	test_vector_file("cephx/session-type1-crc.json", 1);
	test_vector_file("cephx/session-type2-crc.json", 2);
	test_captured();
	test_init_wipe();
	test_clock();
	test_stale_osd_ticket(1);
	test_stale_osd_ticket(2);
	test_reply_limits(1);
	test_reply_limits(2);
	test_basics();
	return wrt_finish();
}
