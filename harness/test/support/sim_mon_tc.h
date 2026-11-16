/* SPDX-License-Identifier: MIT */
/*
 * sim_mon_tc.h - a scripted monitor CLIENT for the sim_mon tests (test_sim_mon*.c). Like sim_m2_tc.h it is
 * not a client of the product: it walks the monitor handshake by hand from the notes (cephx.md 3.2,
 * mon-client.md 3.3 to 3.8) with the frame builder / parser of m2-frame, the control payload codecs of
 * m2-ctl, the cipher / envelope layer of cephx-cipher and the message codecs of mon-msgs, and keeps what it
 * learned in plain structs for the tests to check. Everything is static inline, so every test executable
 * carries its own copy.
 */
#ifndef SIM_MON_TC_H
#define SIM_MON_TC_H

#include "sim_m2_tc.h"
#include "sim_mon.h"
#include "wri_cursor.h"
#include "wri_ctx.h"
#include "wri_cx.h"
#include "wri_denc.h"
#include "wri_m2_ctl.h"
#include "wri_misc.h"
#include "wri_mon.h"

/* A test key of the given type (a function of `salt`) and a default monitor configuration around it. */
static inline void mt_key(wr_key *k, unsigned type, uint8_t salt)
{
	uint8_t raw[32];
	size_t i, len = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < len; i++)
		raw[i] = (uint8_t)(salt + i * 7u);
	if (wr_key_from_raw(k, type, raw, len) != WR_OK)
		abort();
}

static inline void mt_cfg(sim_mon_cfg *c, unsigned type)
{
	sim_mon_cfg_default(c);
	mt_key(&c->key, type, 1);
}

/* ---- what the client learned -------------------------------------------------------------------------- */

typedef struct mt_ticket {
	uint8_t have;
	uint8_t enc;            /* ticket_enc as it came */
	uint32_t service;
	wr_key key;
	uint32_t validity_s, validity_ns;
	uint64_t secret_id;
	uint8_t blob[SIM_MON_BLOB_MAX];
	uint32_t blob_len;
} mt_ticket;

enum { /* mc_login outcomes */
	MC_OK = 1,      /* AUTH_DONE parsed, signatures exchanged, SERVER_IDENT received */
	MC_BAD_METHOD,  /* AUTH_BAD_METHOD (mc.bm) */
	MC_CLOSED,      /* the connection ended without any frame for the step */
	MC_ERR          /* a reply that does not parse (mc.err) */
};

typedef struct mc {
	sim_mon *mon;
	sim_mon_conn *conn;
	tc t;
	wri_ctx x;
	uint64_t rng;
	wr_key key;               /* the key the client holds (may differ from the monitor's) */
	char user[32];
	uint8_t mode_byte;        /* first byte of the AUTH_REQUEST payload, default 10 */
	uint64_t client_challenge;
	uint64_t want_gid;        /* global id asked for in AUTH_REQUEST (0 = new) */
	uint8_t old_blob[SIM_MON_BLOB_MAX];
	uint32_t old_blob_len;
	uint64_t old_secret_id;
	wr_key prev_auth;         /* the previous AUTH session key (to open a ticket_enc = 1 blob) */
	uint8_t have_prev;
	/* learned */
	uint64_t gid;             /* from AUTH_DONE */
	uint32_t conn_mode;
	uint64_t server_challenge;
	wr_key auth_key;
	mt_ticket auth;
	mt_ticket svc[SIM_MON_TSLOTS];
	uint32_t secret_len;      /* connection secret length from cbl, 0xffffffff = no cbl */
	uint32_t done_extra_len;  /* length of `extra`, 0xffffffff = absent */
	uint32_t done_cbl_len;
	uint32_t n_tickets_in_done;
	wri_m2_bad_method bm;
	wr_status err;
	int sig_ok;
	uint64_t seq;             /* client message seq */
	size_t msg_from;          /* first frame index mc_msg() counts from */
} mc;

static inline wr_status mc_random(void *ctx, uint8_t *out, size_t n)
{
	mc *m = (mc *)ctx;
	size_t i;

	for (i = 0; i < n; i++) {
		m->rng ^= m->rng >> 12;
		m->rng ^= m->rng << 25;
		m->rng ^= m->rng >> 27;
		out[i] = (uint8_t)((m->rng * 0x2545f4914f6cdd1dull) >> 56);
	}
	return WR_OK;
}

/* A client for a connection that is accepted now. */
static inline int mc_init(mc *m, sim_mon *mon, const wr_key *key, const char *user)
{
	memset(m, 0, sizeof(*m));
	m->mon = mon;
	m->conn = sim_mon_accept(mon);
	if (m->conn == NULL)
		return -1;
	tc_init(&m->t, 1u << 20);
	m->rng = 0x1234567887654321ull;
	m->x.host.size = (uint32_t)sizeof(m->x.host);
	m->x.host.ctx = m;
	m->x.host.random = mc_random;
	m->key = *key;
	strncpy(m->user, user, sizeof(m->user) - 1u);
	m->mode_byte = 10;
	m->client_challenge = 0x1122334455667788ull;
	m->secret_len = 0xffffffffu;
	m->done_extra_len = 0xffffffffu;
	m->done_cbl_len = 0xffffffffu;
	return 0;
}

static inline void mc_free(mc *m)
{
	tc_free(&m->t);
	sim_mon_conn_free(m->conn);
	wr_key_wipe(&m->key);
	wr_key_wipe(&m->auth_key);
	wr_key_wipe(&m->prev_auth);
}

static inline void mc_pull(mc *m) { tc_pull(&m->t, m->conn->m2); }

/* The new frames since index `from`: the first one with this tag, or NULL. */
static inline const tc_frame *mc_find(const mc *m, size_t from, uint8_t tag)
{
	size_t i;

	for (i = from; i < m->t.nfr; i++)
		if (m->t.fr[i].tag == tag)
			return &m->t.fr[i];
	return NULL;
}

/* Forget the frames seen so far (they are copies); the next mc_msg() counts from the start. */
static inline void mc_clear_frames(mc *m)
{
	size_t i, j;

	for (i = 0; i < m->t.nfr; i++)
		for (j = 0; j < 4; j++) {
			free(m->t.fr[i].seg[j]);
			m->t.fr[i].seg[j] = NULL;
		}
	m->t.nfr = 0;
	m->msg_from = 0;
}

/* ---- parsing what the monitor sent -------------------------------------------------------------------- */

static inline wr_status mt_parse_blob(mt_ticket *t, const uint8_t *p, size_t n)
{
	wri_rd r;
	uint32_t len;
	const uint8_t *d;

	wri_rd_init(&r, p, n);
	(void)wri_rd_u8(&r);
	t->secret_id = wri_rd_u64(&r);
	len = wri_rd_u32(&r);
	d = len <= sizeof(t->blob) ? wri_rd_bytes(&r, len) : NULL;
	if (!wri_rd_ok(&r) || d == NULL)
		return WR_E_ENCODING;
	memcpy(t->blob, d, len);
	t->blob_len = len;
	return WR_OK;
}

/* A ticket reply (cephx.md 2.7): msg_a opened under `wrap`, usage 4; blobs under `prev` when ticket_enc = 1. */
static inline wr_status mc_parse_ticket_reply(mc *m, wri_rd *r, const wr_key *wrap, const wr_key *prev, uint32_t *count)
{
	uint32_t num, i;
	uint8_t scratch[2048];

	(void)wri_rd_u8(r);
	num = wri_rd_count(r, 8, 4u + 1u + 4u + 1u + 4u);
	*count = num;
	for (i = 0; i < num && wri_rd_ok(r); i++) {
		mt_ticket t;
		uint32_t service = wri_rd_u32(r), alen, klen, bl_len;
		const uint8_t *ma, *item = NULL, *bl;
		size_t ilen = 0;
		wri_rd ir;
		uint16_t ktype;
		wr_status st;
		unsigned slot;

		memset(&t, 0, sizeof(t));
		t.service = service;
		(void)wri_rd_u8(r);
		alen = wri_rd_u32(r);
		ma = alen <= 4096u ? wri_rd_bytes(r, alen) : NULL;
		t.enc = wri_rd_u8(r);
		if (ma == NULL)
			return wri_rd_ok(r) ? WR_E_TOOBIG : r->err;
		st = wri_cx_open(&m->x, wrap, WRI_CX_USAGE_TICKET_SESSION_KEY, ma, alen, scratch, sizeof(scratch), &item, &ilen);
		if (st != WR_OK)
			return st;
		wri_rd_init(&ir, item, ilen);
		(void)wri_rd_u8(&ir);
		ktype = wri_rd_u16(&ir);
		(void)wri_rd_u64(&ir);
		klen = wri_rd_u16(&ir);
		bl = wri_rd_bytes(&ir, klen);
		t.validity_s = 0;
		if (bl == NULL)
			return WR_E_ENCODING;
		st = wr_key_from_raw(&t.key, ktype, bl, klen);
		if (st != WR_OK)
			return st;
		t.validity_s = wri_rd_u32(&ir);
		t.validity_ns = wri_rd_u32(&ir);
		if (!wri_rd_ok(&ir) || wri_rd_left(&ir) != 0)
			return WR_E_ENCODING;
		wri_secure_zero(scratch, sizeof(scratch));
		bl_len = wri_rd_u32(r);
		bl = bl_len <= 4096u ? wri_rd_bytes(r, bl_len) : NULL;
		if (bl == NULL)
			return wri_rd_ok(r) ? WR_E_TOOBIG : r->err;
		if (t.enc == 0) {
			st = mt_parse_blob(&t, bl, bl_len);
		} else {
			if (prev == NULL)
				return WR_E_AUTH_PROTO;
			st = wri_cx_open(&m->x, prev, WRI_CX_USAGE_TICKET_BLOB, bl, bl_len, scratch, sizeof(scratch), &item, &ilen);
			if (st == WR_OK) { /* the item is a bufferlist: u32 length + the blob */
				wri_rd br;
				uint32_t l2;
				const uint8_t *b2;

				wri_rd_init(&br, item, ilen);
				l2 = wri_rd_u32(&br);
				b2 = wri_rd_bytes(&br, l2);
				st = b2 != NULL && wri_rd_left(&br) == 0 ? mt_parse_blob(&t, b2, l2) : WR_E_ENCODING;
			}
		}
		if (st != WR_OK)
			return st;
		t.have = 1;
		slot = sim_mon_slot(service);
		if (service == WRI_CX_SERVICE_AUTH)
			m->auth = t;
		else if (slot < SIM_MON_TSLOTS)
			m->svc[slot] = t;
		else
			return WR_E_AUTH_PROTO;
	}
	return wri_rd_ok(r) ? WR_OK : r->err;
}

/* The AUTH_DONE payload, as a client reads it (cephx.md 3.2 step 4). */
static inline wr_status mc_parse_done(mc *m, const uint8_t *p, uint32_t n)
{
	wri_rd r;
	wr_status st;
	uint32_t cnt = 0;
	uint8_t scratch[2048];

	wri_rd_init(&r, p, n);
	if (wri_rd_u16(&r) != WRI_CX_REQ_GET_AUTH_SESSION_KEY || wri_rd_i32(&r) != 0)
		return WR_E_AUTH_PROTO;
	st = mc_parse_ticket_reply(m, &r, &m->key, m->have_prev ? &m->prev_auth : NULL, &cnt);
	if (st != WR_OK)
		return st;
	m->n_tickets_in_done = cnt;
	if (cnt != 1u || !m->auth.have)
		return WR_E_AUTH_PROTO;
	wr_key_wipe(&m->auth_key);
	m->auth_key = m->auth.key;
	if (wri_rd_left(&r) == 0)
		return WR_OK;
	{ /* cbl: u32 length, then u32 length + ciphertext of the connection secret (a string) */
		uint32_t cl = wri_rd_u32(&r), il;
		wri_rd cr, ir;
		const uint8_t *cb = cl <= 4096u ? wri_rd_bytes(&r, cl) : NULL, *ct, *item = NULL;
		size_t ilen = 0;

		m->done_cbl_len = cl;
		if (cb == NULL)
			return WR_E_ENCODING;
		if (cl != 0) {
			wri_rd_init(&cr, cb, cl);
			il = wri_rd_u32(&cr);
			ct = wri_rd_bytes(&cr, il);
			if (ct == NULL || wri_rd_left(&cr) != 0)
				return WR_E_ENCODING;
			st = wri_cx_open(&m->x, &m->auth_key, WRI_CX_USAGE_CONN_SECRET, ct, il, scratch, sizeof(scratch), &item, &ilen);
			if (st != WR_OK)
				return st;
			wri_rd_init(&ir, item, ilen);
			m->secret_len = wri_rd_u32(&ir);
			if (!wri_rd_ok(&ir) || wri_rd_left(&ir) != m->secret_len)
				return WR_E_ENCODING;
		}
	}
	{ /* extra: a ticket reply of the other services, or a zero-length blob */
		uint32_t el = wri_rd_u32(&r);
		const uint8_t *eb = el <= 8192u ? wri_rd_bytes(&r, el) : NULL;
		wri_rd er;

		m->done_extra_len = el;
		if (eb == NULL)
			return WR_E_ENCODING;
		if (el != 0) {
			wri_rd_init(&er, eb, el);
			st = mc_parse_ticket_reply(m, &er, &m->auth_key, NULL, &cnt);
			if (st != WR_OK || wri_rd_left(&er) != 0)
				return st != WR_OK ? st : WR_E_ENCODING;
			m->n_tickets_in_done += cnt;
		}
	}
	return wri_rd_ok(&r) && wri_rd_left(&r) == 0 ? WR_OK : WR_E_ENCODING;
}

/* ---- the login ---------------------------------------------------------------------------------------- */

/* Banner, HELLO, AUTH_REQUEST (stops at the server's first answer when `upto_challenge`). */
static inline int mc_login_ex(mc *m, uint32_t want, int upto_challenge)
{
	sim_m2 *s = m->conn->m2;
	tc *t = &m->t;
	tb p, pl;
	size_t before;
	const tc_frame *f;
	uint64_t proof = 0;
	wri_rd r;
	uint32_t plen;
	const uint8_t *pb;
	uint8_t sig[32];
	size_t sent_before;

	tc_pull(t, s);
	if (!t->got_banner)
		return MC_CLOSED;
	(void)tc_send_banner(t, s, 1, 0);
	tc_pay_hello(&p, SIM_M2_ENT_CLIENT, 3300);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_HELLO, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (mc_find(m, before, WRI_M2_TAG_HELLO) == NULL)
		return MC_CLOSED;
	/* AUTH_REQUEST: method 2, preferred modes [crc], payload = mode byte, entity name, global id */
	pl.n = 0;
	tb_u8(&pl, m->mode_byte);
	tb_u32(&pl, 8);
	tb_u32(&pl, (uint32_t)strlen(m->user));
	tb_bytes(&pl, m->user, strlen(m->user));
	tb_u64(&pl, m->want_gid);
	p.n = 0;
	tb_u32(&p, 2);
	tb_u32(&p, 1);
	tb_u32(&p, 1);
	tb_u32(&p, (uint32_t)pl.n);
	tb_bytes(&p, pl.b, pl.n);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before)
		return MC_CLOSED;
	f = &t->fr[before];
	if (f->tag == WRI_M2_TAG_AUTH_BAD_METHOD) {
		wri_rd_init(&r, f->seg[0], f->len[0]);
		m->err = wri_m2_bad_method_decode(&r, &m->bm);
		return m->err == WR_OK ? MC_BAD_METHOD : MC_ERR;
	}
	if (f->tag != WRI_M2_TAG_AUTH_REPLY_MORE || f->len[0] != 13u || f->seg[0][4] != 1u)
		return MC_ERR;
	m->server_challenge = wri_le64_get(f->seg[0] + 5);
	if (upto_challenge)
		return MC_OK;
	m->err = wri_cx_challenge_proof(&m->x, &m->key, m->server_challenge, m->client_challenge, &proof);
	if (m->err != WR_OK)
		return MC_ERR;
	/* AUTH_REQUEST_MORE: request header 0x0100, CephXAuthenticate v3 */
	pl.n = 0;
	tb_bytes(&pl, "\x00\x01", 2);
	tb_u8(&pl, 3);
	tb_u64(&pl, m->client_challenge);
	tb_u64(&pl, proof);
	tb_u8(&pl, 1);
	tb_u64(&pl, m->old_secret_id);
	tb_u32(&pl, m->old_blob_len);
	tb_bytes(&pl, m->old_blob, m->old_blob_len);
	tb_u32(&pl, want);
	p.n = 0;
	tb_u32(&p, (uint32_t)pl.n);
	tb_bytes(&p, pl.b, pl.n);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_REQUEST_MORE, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (t->nfr == before)
		return MC_CLOSED;
	f = &t->fr[before];
	if (f->tag == WRI_M2_TAG_AUTH_BAD_METHOD) {
		wri_rd_init(&r, f->seg[0], f->len[0]);
		m->err = wri_m2_bad_method_decode(&r, &m->bm);
		return m->err == WR_OK ? MC_BAD_METHOD : MC_ERR;
	}
	if (f->tag != WRI_M2_TAG_AUTH_DONE || f->len[0] < 16u)
		return MC_ERR;
	m->gid = wri_le64_get(f->seg[0]);
	m->conn_mode = wri_le32_get(f->seg[0] + 8);
	plen = wri_le32_get(f->seg[0] + 12);
	pb = f->seg[0] + 16;
	if (plen != f->len[0] - 16u)
		return MC_ERR;
	m->err = mc_parse_done(m, pb, plen);
	if (m->err != WR_OK)
		return MC_ERR;
	/* AUTH_SIGNATURE: HMAC over what we received up to AUTH_DONE; the server's covers what we sent */
	tc_hmac(m->auth_key.secret, m->auth_key.len, t->log, t->log_len, sig);
	sent_before = t->sent_len;
	p.n = 0;
	tb_bytes(&p, sig, 32);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_AUTH_SIGNATURE, &p);
	before = t->nfr;
	tc_pull(t, s);
	f = mc_find(m, before, WRI_M2_TAG_AUTH_SIGNATURE);
	if (f == NULL || f->len[0] != 32u)
		return MC_CLOSED;
	tc_hmac(m->auth_key.secret, m->auth_key.len, t->sent, sent_before, sig);
	m->sig_ok = memcmp(sig, f->seg[0], 32) == 0;
	if (!m->sig_ok)
		return MC_ERR;
	/* the session handshake: CLIENT_IDENT -> SERVER_IDENT */
	tc_pay_ident(&p, 0x3f07fffffffdffffull, 1, 0x1234);
	(void)tc_send_ctl(t, s, WRI_M2_TAG_CLIENT_IDENT, &p);
	before = t->nfr;
	tc_pull(t, s);
	if (mc_find(m, before, WRI_M2_TAG_SERVER_IDENT) == NULL)
		return MC_CLOSED;
	return MC_OK;
}

static inline int mc_login(mc *m, uint32_t want) { return mc_login_ex(m, want, 0); }

/* Take over the AUTH ticket and session key of an earlier login to reclaim its global id. */
static inline void mc_reclaim_from(mc *m, const mc *old)
{
	m->want_gid = old->gid;
	memcpy(m->old_blob, old->auth.blob, old->auth.blob_len);
	m->old_blob_len = old->auth.blob_len;
	m->old_secret_id = old->auth.secret_id;
	m->prev_auth = old->auth_key;
	m->have_prev = 1;
}

#include "sim_mon_tc_msg.h"

#endif /* SIM_MON_TC_H */
