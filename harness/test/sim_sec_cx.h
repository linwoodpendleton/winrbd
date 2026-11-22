/* SPDX-License-Identifier: MIT */
/*
 * sim_sec_cx.h - the cephx half of the scripted client of sim_sec_tc.h: a monitor login (CEPHX_GET_AUTH_SESSION_KEY) and an OSD
 * login (authorizer, challenge round trip) written from docs/spec/cephx.md 2.4 to 2.10 and 3.2 / 3.3, including the two ways the
 * secure-mode connection secret reaches a client (the monitor's `cbl`, the OSD's reply of version 2).
 *
 * Type 1 keys (AES-128-CBC, the fixed IV, PKCS#7) are implemented here with the AES of ref_gcm.h. The cipher of type 2 (AES-256 CTS
 * with HMAC-SHA384, RFC 8009) is a different job than the one under test: it goes through the cipher layer of the core
 * (wri_cx_encrypt / wri_cx_decrypt), the same layer the simulators seal with. Everything else, the structures, the proofs, the
 * transcripts and the signatures, is this file.
 */
#ifndef SIM_SEC_CX_H
#define SIM_SEC_CX_H

#include "sim_sec_tc.h"

#include "ref_gcm.h"
#include "wr_key.h"
#include "wri_ctx.h"
#include "wri_cx.h"

#define TC_MAGIC 0xff009cad8826aa55ull

typedef struct tkey {
	uint8_t type; /* 1 = aes, 2 = aes256k */
	uint8_t len;
	uint8_t s[32];
} tkey;

/* The key the monitor of sim_mon_cfg (mt_key(.., salt)) holds: bytes salt + 7 i. */
static inline void tc_key(tkey *k, unsigned type, uint8_t salt)
{
	unsigned i;

	memset(k, 0, sizeof(*k));
	k->type = (uint8_t)type;
	k->len = type == 1u ? 16u : 32u;
	for (i = 0; i < k->len; i++)
		k->s[i] = (uint8_t)(salt + i * 7u);
}

static inline void tc_wrkey(const tkey *k, wr_key *w)
{
	if (wr_key_from_raw(w, k->type, k->s, k->len) != WR_OK)
		abort();
}

static inline wr_status tc_random(void *ctx, uint8_t *out, size_t n)
{
	static uint64_t st = 0x7e57c11e47ull;
	size_t i;

	(void)ctx;
	for (i = 0; i < n; i++) {
		st ^= st << 13;
		st ^= st >> 7;
		st ^= st << 17;
		out[i] = (uint8_t)(st >> 24);
	}
	return WR_OK;
}

/* The cipher context of the core's cephx layer (type 2 only): its host table supplies the confounder of a seal. */
static inline wri_ctx *tc_xr(void)
{
	static wri_ctx x;
	static int init;

	if (!init) {
		x.host.size = (uint32_t)sizeof(x.host);
		x.host.random = tc_random;
		init = 1;
	}
	return &x;
}

/* ---- ciphers --------------------------------------------------------------------------------------------------------------- */

static const uint8_t TC_IV[16] = {0x63, 0x65, 0x70, 0x68, 0x73, 0x61, 0x67, 0x65, 0x79, 0x75, 0x64, 0x61, 0x67, 0x72, 0x65, 0x67};

/* AES-128-CBC, fixed IV, PKCS#7 (a full block of padding when aligned): out holds 16 * (n / 16 + 1) bytes. */
static inline size_t tc_t1_encrypt(const tkey *k, const uint8_t *in, size_t n, uint8_t *out)
{
	ref_aes a;
	size_t total = 16u * (n / 16u + 1u), i, b;
	uint8_t prev[16], blk[16];

	if (ref_aes_init(&a, k->s, 16) != 0)
		return 0;
	memcpy(prev, TC_IV, 16);
	for (b = 0; b < total; b += 16) {
		for (i = 0; i < 16; i++) {
			size_t at = b + i;

			blk[i] = (uint8_t)((at < n ? in[at] : (uint8_t)(total - n)) ^ prev[i]);
		}
		ref_aes_encrypt_block(&a, blk, out + b);
		memcpy(prev, out + b, 16);
	}
	return total;
}

static inline int tc_t1_decrypt(const tkey *k, const uint8_t *in, size_t n, uint8_t *out, size_t *outn)
{
	ref_aes a;
	size_t b, i;
	uint8_t prev[16], blk[16];

	if (n == 0 || n % 16u != 0 || ref_aes_init(&a, k->s, 16) != 0)
		return -1;
	memcpy(prev, TC_IV, 16);
	for (b = 0; b < n; b += 16) {
		ref_aes_decrypt_block(&a, in + b, blk);
		for (i = 0; i < 16; i++)
			out[b + i] = (uint8_t)(blk[i] ^ prev[i]);
		memcpy(prev, in + b, 16);
	}
	if (out[n - 1] < 1u || out[n - 1] > 16u)
		return -1;
	*outn = n - out[n - 1];
	return 0;
}

/* Seal item as the envelope u8 1 | u64 magic | item under (key, usage): appends the raw ciphertext to out. 0 or -1. */
static inline int tc_seal(const tkey *k, uint32_t usage, const uint8_t *item, size_t n, stc_buf *out)
{
	stc_buf plain = {0, 0, 0};
	uint8_t *ct;
	size_t cn = 0, cap = n + 9u + 16u + 64u;
	int rc = 0;

	w8(&plain, 1);
	w64(&plain, TC_MAGIC);
	stc_buf_add(&plain, item, n);
	ct = (uint8_t *)malloc(cap);
	if (k->type == 1u) {
		cn = tc_t1_encrypt(k, plain.p, plain.n, ct);
		rc = cn == 0 ? -1 : 0;
	} else {
		wr_key wk;

		tc_wrkey(k, &wk);
		rc = wri_cx_encrypt(tc_xr(), &wk, usage, plain.p, plain.n, ct, cap, &cn) == WR_OK ? 0 : -1;
		wr_key_wipe(&wk);
	}
	if (rc == 0)
		stc_buf_add(out, ct, cn);
	free(ct);
	stc_buf_free(&plain);
	return rc;
}

/* Open a raw ciphertext; checks the magic. *item points into `plain` (a buffer of at least n + 16 bytes). 0 or -1. */
static inline int tc_open(const tkey *k, uint32_t usage, const uint8_t *ct, size_t n, uint8_t *plain, const uint8_t **item, size_t *item_len)
{
	size_t pn = 0;

	if (k->type == 1u) {
		if (tc_t1_decrypt(k, ct, n, plain, &pn) != 0)
			return -1;
	} else {
		wr_key wk;
		wr_status st;

		tc_wrkey(k, &wk);
		st = wri_cx_decrypt(tc_xr(), &wk, usage, ct, n, plain, n + 16u, &pn);
		wr_key_wipe(&wk);
		if (st != WR_OK)
			return -1;
	}
	if (pn < 9u || ld32le(plain + 1) != (uint32_t)TC_MAGIC || ld32le(plain + 5) != (uint32_t)(TC_MAGIC >> 32))
		return -1;
	*item = plain + 9;
	*item_len = pn - 9u;
	return 0;
}

/* The proof of CEPHX_GET_AUTH_SESSION_KEY (cephx.md 2.8). */
static inline uint64_t tc_proof(const tkey *k, uint64_t srv, uint64_t cli)
{
	stc_buf blob = {0, 0, 0}, ct = {0, 0, 0};
	uint8_t words[36], dig[32];
	uint64_t x = 0;
	unsigned i, j;

	w64(&blob, srv);
	w64(&blob, cli);
	if (k->type == 1u) {
		(void)tc_seal(k, 0, blob.p, blob.n, &ct); /* the "encode + encrypt" shape: u32 len | ct, 36 bytes */
		words[0] = (uint8_t)ct.n, words[1] = 0, words[2] = 0, words[3] = 0;
		memcpy(words + 4, ct.p, 32);
		for (i = 0; i < 4u; i++) {
			uint64_t v = 0;

			for (j = 0; j < 8u; j++)
				v |= (uint64_t)words[8u * i + j] << (8u * j);
			x ^= v;
		}
	} else {
		stc_hmac256(k->s, k->len, blob.p, blob.n, dig);
		for (i = 0; i < 4u; i++) {
			uint64_t v = 0;

			for (j = 0; j < 8u; j++)
				v |= (uint64_t)dig[8u * i + j] << (8u * j);
			x ^= v;
		}
	}
	stc_buf_free(&blob);
	stc_buf_free(&ct);
	return x;
}

/* ---- tickets ---------------------------------------------------------------------------------------------------------------- */

typedef struct tticket {
	int have;
	uint32_t service;
	tkey key;
	uint8_t blob[1100]; /* the CephXTicketBlob as received: u8 v | u64 secret_id | u32 len | data */
	uint32_t blob_len;
	uint8_t enc;
} tticket;

/* A CryptoKey: u16 type | utime (8) | u16 len | secret. */
static inline int tc_rd_key(stc_rd *r, tkey *k)
{
	uint16_t type = rd16(r), len;
	const uint8_t *s;

	(void)rd64(r); /* created */
	len = rd16(r);
	s = rd_take(r, len);
	if (r->bad || (type != 1u && type != 2u) || len > 32u || s == NULL)
		return -1;
	memset(k, 0, sizeof(*k));
	k->type = (uint8_t)type;
	k->len = (uint8_t)len;
	memcpy(k->s, s, len);
	return 0;
}

/* A ticket reply (cephx.md 2.7): reply_v | u32 n | per ticket. msg_a is opened with `wrap`. Tickets go into out[service slot]. */
static inline int tc_parse_tickets(stc_rd *r, const tkey *wrap, tticket *out, unsigned max, unsigned *count)
{
	uint32_t n, i;
	uint8_t plain[512];

	(void)rd8(r);
	n = rd32(r);
	if (r->bad || n > max)
		return -1;
	for (i = 0; i < n; i++) {
		uint32_t svc = rd32(r), ctl, bl;
		const uint8_t *ct, *item, *bp;
		size_t ilen;
		tticket *t = &out[i];
		stc_rd ir;

		(void)rd8(r); /* ticket_v */
		ct = rd_blob(r, &ctl);
		if (ct == NULL || tc_open(wrap, WRI_CX_USAGE_TICKET_SESSION_KEY, ct, ctl, plain, &item, &ilen) != 0)
			return -1;
		memset(t, 0, sizeof(*t));
		t->service = svc;
		rd_init(&ir, item, ilen);
		(void)rd8(&ir);
		if (tc_rd_key(&ir, &t->key) != 0)
			return -1;
		t->enc = rd8(r);
		if (t->enc != 0)
			return -1; /* a login never gets a re-issued ticket */
		bp = rd_blob(r, &bl);
		if (bp == NULL || bl > sizeof(t->blob))
			return -1;
		memcpy(t->blob, bp, bl);
		t->blob_len = bl;
		t->have = 1;
	}
	*count = n;
	return r->bad ? -1 : 0;
}

/* ---- the login ---------------------------------------------------------------------------------------------------------------- */

enum { TL_NONE = 0, TL_OK = 1, TL_BAD_METHOD, TL_CLOSED, TL_ERR };

typedef struct tlogin {
	int outcome;
	const char *err;
	uint32_t mode;           /* AUTH_DONE's connection mode */
	uint64_t gid;
	tkey key;                /* the session key the signatures use: the AUTH key (monitor) or the ticket's (OSD) */
	uint8_t secret[512];     /* the connection secret as delivered */
	uint32_t secret_len;
	int have_secret;         /* a non-empty secret came with AUTH_DONE */
	int reply_version;       /* OSD: the version of CephXAuthorizeReply */
	tticket tickets[4];      /* monitor: the tickets that came in `extra` */
	unsigned ntickets;
	int32_t bm_result;       /* AUTH_BAD_METHOD */
	uint32_t bm_methods[8], bm_nmethods, bm_modes[8], bm_nmodes;
	int sig_ok;              /* the server's signature verified (tc_finish) */
	int signed_ok;           /* both signature frames went by */
} tlogin;

static inline int tc_fail(tlogin *L, int outcome, const char *why)
{
	L->outcome = outcome;
	L->err = why;
	return 0;
}

/* Banner and HELLO, both ways. The client offers REVISION_1 only (no compression frames then). */
static inline int tc_connect(stc *c, tlogin *L)
{
	uint64_t sup = 0, req = 0;
	int r;

	stc_send_banner(c, c->banner_supported, 0);
	r = stc_recv_banner(c, &sup, &req);
	if (r != 1 || (sup & 1u) == 0)
		return tc_fail(L, TL_ERR, "no usable server banner");
	if (!stc_hello(c))
		return tc_fail(L, TL_ERR, "no HELLO");
	return 1;
}

static inline int tc_bad_method(stc *c, tlogin *L)
{
	stc_rd r;
	uint32_t i;

	rd_init(&r, c->seg[0].p, c->seg[0].n);
	(void)rd32(&r); /* method */
	L->bm_result = (int32_t)rd32(&r);
	L->bm_nmethods = rd32(&r);
	for (i = 0; i < L->bm_nmethods && i < 8u; i++)
		L->bm_methods[i] = rd32(&r);
	L->bm_nmodes = rd32(&r);
	for (i = 0; i < L->bm_nmodes && i < 8u; i++)
		L->bm_modes[i] = rd32(&r);
	if (r.bad || L->bm_nmethods > 8u || L->bm_nmodes > 8u)
		return tc_fail(L, TL_ERR, "malformed AUTH_BAD_METHOD");
	L->outcome = TL_BAD_METHOD;
	return 0;
}

/* The next frame of the handshake: its tag, or 0 with L filled in when the connection closed or nothing came. */
static inline int tc_next_auth(stc *c, tlogin *L)
{
	int r = stc_recv(c);

	if (r == 0) {
		stc_pull(c);
		if (c->eof)
			tc_fail(L, TL_CLOSED, "connection closed");
		else
			tc_fail(L, TL_ERR, "no answer");
		return 0;
	}
	if (r < 0) {
		tc_fail(L, TL_ERR, "frame error");
		return 0;
	}
	return c->tag;
}

/* The monitor's AUTH_DONE: response header, the AUTH ticket, `cbl` (the connection secret), `extra` (the other tickets). */
static inline int tc_parse_mon_done(stc *c, const tkey *principal, tlogin *L)
{
	stc_rd r, tr;
	uint32_t plen, cbl_len, extra_len, il;
	const uint8_t *pl, *cbl, *extra;
	tticket auth[2];
	unsigned n = 0;
	uint8_t plain[1024];
	const uint8_t *item;
	size_t ilen;

	rd_init(&r, c->seg[0].p, c->seg[0].n);
	L->gid = rd64(&r);
	L->mode = rd32(&r);
	pl = rd_blob(&r, &plen);
	if (r.bad || r.pos != r.n)
		return tc_fail(L, TL_ERR, "malformed AUTH_DONE");
	rd_init(&tr, pl, plen);
	if (rd16(&tr) != WRI_CX_REQ_GET_AUTH_SESSION_KEY || (int32_t)rd32(&tr) != 0)
		return tc_fail(L, TL_ERR, "bad response header");
	if (tc_parse_tickets(&tr, principal, auth, 2, &n) != 0 || n != 1 || auth[0].service != WRI_CX_SERVICE_AUTH)
		return tc_fail(L, TL_ERR, "AUTH ticket reply does not parse");
	L->key = auth[0].key;
	cbl = rd_blob(&tr, &cbl_len);
	if (cbl == NULL)
		return tc_fail(L, TL_ERR, "no cbl");
	/* cbl: u32 inner length | ciphertext (usage 0x03 under the AUTH session key) -> u32 len | secret */
	{
		stc_rd cr;
		const uint8_t *ct;

		rd_init(&cr, cbl, cbl_len);
		ct = rd_blob(&cr, &il);
		if (ct == NULL || tc_open(&L->key, WRI_CX_USAGE_CONN_SECRET, ct, il, plain, &item, &ilen) != 0)
			return tc_fail(L, TL_ERR, "cbl does not decrypt");
		rd_init(&cr, item, ilen);
		L->secret_len = rd32(&cr);
		if (cr.bad || L->secret_len > sizeof(L->secret) || rd_take(&cr, L->secret_len) == NULL)
			return tc_fail(L, TL_ERR, "cbl secret does not parse");
		memcpy(L->secret, item + 4, L->secret_len);
		L->have_secret = L->secret_len != 0;
	}
	extra = rd_blob(&tr, &extra_len);
	if (extra == NULL || tr.bad)
		return tc_fail(L, TL_ERR, "no extra");
	if (extra_len != 0) {
		stc_rd er;

		rd_init(&er, extra, extra_len);
		if (tc_parse_tickets(&er, &L->key, L->tickets, 4, &L->ntickets) != 0)
			return tc_fail(L, TL_ERR, "extra tickets do not parse");
	}
	L->outcome = TL_OK;
	return 1;
}

/* The whole monitor login up to and including AUTH_DONE: banner, HELLO, AUTH_REQUEST (mon mode 10, entity, gid 0), the challenge,
 * CephXAuthenticate v3 (proof, empty old ticket, other_keys), AUTH_DONE or AUTH_BAD_METHOD. */
static inline int tc_mon_login(stc *c, const tkey *key, const char *user, const uint32_t *offer, unsigned noffer, uint32_t other, tlogin *L)
{
	stc_buf p = {0, 0, 0}, q = {0, 0, 0};
	int tag, rc = 0;
	uint64_t srv, cli = 0x1122334455667788ull;
	stc_rd r;

	memset(L, 0, sizeof(*L));
	if (!tc_connect(c, L))
		return 0;
	w8(&p, 10);
	w32(&p, 8);
	wblob(&p, user, strlen(user));
	w64(&p, 0);
	if (stc_auth_request(c, 2, offer, noffer, p.p, (uint32_t)p.n) != 0)
		return tc_fail(L, TL_ERR, "send failed");
	tag = tc_next_auth(c, L);
	if (tag == 3) {
		rc = tc_bad_method(c, L);
		goto out;
	}
	if (tag != 4) {
		if (tag != 0)
			tc_fail(L, TL_ERR, "expected AUTH_REPLY_MORE");
		goto out;
	}
	rd_init(&r, c->seg[0].p, c->seg[0].n);
	{
		uint32_t pl;
		const uint8_t *chal = rd_blob(&r, &pl);
		stc_rd cr;

		if (chal == NULL || pl != 9)
			return tc_fail(L, TL_ERR, "bad challenge");
		rd_init(&cr, chal, pl);
		(void)rd8(&cr);
		srv = rd64(&cr);
	}
	w16(&q, WRI_CX_REQ_GET_AUTH_SESSION_KEY);
	w8(&q, 3);
	w64(&q, cli);
	w64(&q, tc_proof(key, srv, cli));
	w8(&q, 1); /* old_ticket: empty CephXTicketBlob */
	w64(&q, 0);
	w32(&q, 0);
	w32(&q, other);
	if (stc_auth_more(c, q.p, (uint32_t)q.n) != 0)
		return tc_fail(L, TL_ERR, "send failed");
	tag = tc_next_auth(c, L);
	if (tag == 3) {
		rc = tc_bad_method(c, L);
		goto out;
	}
	if (tag != 6) {
		if (tag != 0)
			tc_fail(L, TL_ERR, "expected AUTH_DONE");
		goto out;
	}
	c->log_on = 0; /* the transcripts end with AUTH_DONE (the signatures follow) */
	rc = tc_parse_mon_done(c, key, L);
out:
	stc_buf_free(&p);
	stc_buf_free(&q);
	return rc;
}

/* The authorizer of cephx.md 2.7: u8 1 | u64 gid | u32 service | ticket blob | u32 len + sealed CephXAuthorize v2. */
static inline void tc_authorizer(stc_buf *out, uint64_t gid, const tticket *t, uint64_t nonce, int have_chal, uint64_t plus_one)
{
	stc_buf item = {0, 0, 0}, ct = {0, 0, 0};

	w8(out, 1);
	w64(out, gid);
	w32(out, t->service);
	stc_buf_add(out, t->blob, t->blob_len);
	w8(&item, 2);
	w64(&item, nonce);
	w8(&item, (uint8_t)have_chal);
	w64(&item, plus_one);
	(void)tc_seal(&t->key, WRI_CX_USAGE_AUTHORIZE, item.p, item.n, &ct);
	wblob(out, ct.p, ct.n);
	stc_buf_free(&item);
	stc_buf_free(&ct);
}

/* OSD login: AUTH_REQUEST (authorizer), the challenge, the authorizer again, AUTH_DONE with the sealed CephXAuthorizeReply. */
static inline int tc_osd_login(stc *c, const tticket *t, uint64_t gid, const uint32_t *offer, unsigned noffer, tlogin *L)
{
	stc_buf p = {0, 0, 0};
	int tag, rc = 0;
	uint64_t nonce = 0xa1b2c3d4e5f60718ull, chal = 0;
	uint8_t plain[512];
	const uint8_t *item;
	size_t ilen;

	memset(L, 0, sizeof(*L));
	if (!tc_connect(c, L))
		return 0;
	tc_authorizer(&p, gid, t, nonce, 0, 0);
	if (stc_auth_request(c, 2, offer, noffer, p.p, (uint32_t)p.n) != 0)
		return tc_fail(L, TL_ERR, "send failed");
	tag = tc_next_auth(c, L);
	if (tag == 3) {
		rc = tc_bad_method(c, L);
		goto out;
	}
	if (tag != 4) {
		if (tag != 0)
			tc_fail(L, TL_ERR, "expected AUTH_REPLY_MORE");
		goto out;
	}
	{ /* the challenge: raw ciphertext, usage 0x11 */
		stc_rd cr;

		if (tc_open(&t->key, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, c->seg[0].p + 4, c->seg[0].n - 4u, plain, &item, &ilen) != 0)
			return tc_fail(L, TL_ERR, "challenge does not decrypt"); /* AUTH_REPLY_MORE's payload is a blob: u32 len | ciphertext */
		rd_init(&cr, item, ilen);
		(void)rd8(&cr);
		chal = rd64(&cr);
	}
	p.n = 0;
	tc_authorizer(&p, gid, t, nonce, 1, chal + 1u);
	if (stc_auth_more(c, p.p, (uint32_t)p.n) != 0)
		return tc_fail(L, TL_ERR, "send failed");
	tag = tc_next_auth(c, L);
	if (tag == 3) {
		rc = tc_bad_method(c, L);
		goto out;
	}
	if (tag != 6) {
		if (tag != 0)
			tc_fail(L, TL_ERR, "expected AUTH_DONE");
		goto out;
	}
	c->log_on = 0;
	{
		stc_rd r, ar;
		uint32_t plen, il;
		const uint8_t *pl, *ct;

		rd_init(&r, c->seg[0].p, c->seg[0].n);
		L->gid = rd64(&r);
		L->mode = rd32(&r);
		pl = rd_blob(&r, &plen);
		if (r.bad || r.pos != r.n)
			return tc_fail(L, TL_ERR, "malformed AUTH_DONE");
		rd_init(&ar, pl, plen);
		ct = rd_blob(&ar, &il);
		if (ct == NULL || tc_open(&t->key, WRI_CX_USAGE_AUTHORIZE_REPLY, ct, il, plain, &item, &ilen) != 0)
			return tc_fail(L, TL_ERR, "reply does not decrypt");
		rd_init(&ar, item, ilen);
		L->reply_version = rd8(&ar);
		if (rd64(&ar) != nonce + 1u)
			return tc_fail(L, TL_ERR, "wrong nonce_plus_one");
		if (L->reply_version >= 2) {
			L->secret_len = rd32(&ar);
			if (ar.bad || L->secret_len > sizeof(L->secret) || rd_take(&ar, L->secret_len) == NULL)
				return tc_fail(L, TL_ERR, "reply secret does not parse");
			memcpy(L->secret, item + 13, L->secret_len);
			L->have_secret = L->secret_len != 0;
		}
		if (ar.bad)
			return tc_fail(L, TL_ERR, "reply does not parse");
		L->key = t->key;
		L->outcome = TL_OK;
		rc = 1;
	}
out:
	stc_buf_free(&p);
	return rc;
}

/* After AUTH_DONE: switch to secure framing when the mode is secure (and a usable secret came), send our signature, verify the
 * server's, then CLIENT_IDENT / SERVER_IDENT. 1 = the session is up. */
static inline int tc_finish(stc *c, tlogin *L, int do_ident)
{
	if (L->outcome != TL_OK)
		return 0;
	if (L->mode == SIM_M2_MODE_SECURE) {
		if (!L->have_secret || stc_go_secure(c, L->secret, L->secret_len) != 0)
			return tc_fail(L, TL_ERR, "secure mode without a usable secret"), 0;
	}
	if (!stc_signatures(c, L->key.s, L->key.len, &L->sig_ok))
		return tc_fail(L, TL_ERR, "signature exchange failed"), 0;
	L->signed_ok = 1;
	if (!L->sig_ok)
		return tc_fail(L, TL_ERR, "server signature does not match"), 0;
	if ((c->banner_supported & 2u) != 0 && !stc_compression(c)) /* both banners advertised it: the compression stage, in the mode's framing */
		return tc_fail(L, TL_ERR, "compression stage failed"), 0;
	if (do_ident && !stc_ident(c))
		return tc_fail(L, TL_ERR, "no SERVER_IDENT"), 0;
	return 1;
}

#endif /* SIM_SEC_CX_H */
