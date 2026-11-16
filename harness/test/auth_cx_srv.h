/* SPDX-License-Identifier: MIT */
/*
 * auth_cx_srv.h - shared helpers of the cephx client tests (test_auth_client*.c, test_auth_renew.c):
 * a test environment (context with an injectable RNG, arena, client), and a tiny server-side
 * builder that writes the structures of docs/spec/cephx.md 2.7 so the client can be driven with
 * replies the committed vectors do not contain (wrong key, zero validity, oversize ticket, ...).
 * The builders use the core's own seal, so they are checked against the vectors by the replay test
 * before they are trusted anywhere else.
 */
#ifndef AUTH_CX_SRV_H
#define AUTH_CX_SRV_H

#include <stdlib.h>

#include "wrt.h"

#include "wri_cx.h"
#include "wri_hash.h"
#include "wri_le.h"
#include "wri_m2_ctl.h"

#define CXT_T0 1000000ull /* the fake clock at "receipt" */

/* ---- injectable RNG --------------------------------------------------------------------------- */

typedef struct cxt_rng {
	int strict;          /* 1: only the scripted draws, each of exactly the scripted length */
	unsigned n, i;
	size_t len[8];
	uint8_t val[8][32];
	int bad;             /* draws that did not match the script */
	uint32_t ctr;        /* free mode: xorshift state */
} cxt_rng;

static cxt_rng g_rng;

static WRT_UNUSED wr_status cxt_random(void *ctx, uint8_t *out, size_t n)
{
	size_t i;

	(void)ctx;
	if (g_rng.strict) {
		if (g_rng.i >= g_rng.n || g_rng.len[g_rng.i] != n) {
			g_rng.bad++;
			return WR_E_HOST_RANDOM;
		}
		memcpy(out, g_rng.val[g_rng.i++], n);
		return WR_OK;
	}
	for (i = 0; i < n; i++) {
		g_rng.ctr ^= g_rng.ctr << 13;
		g_rng.ctr ^= g_rng.ctr >> 17;
		g_rng.ctr ^= g_rng.ctr << 5;
		out[i] = (uint8_t)g_rng.ctr;
	}
	return WR_OK;
}

static WRT_UNUSED void cxt_rng_free(void)
{
	memset(&g_rng, 0, sizeof(g_rng));
	g_rng.ctr = 0x2545F491u;
}

static WRT_UNUSED void cxt_rng_push(const uint8_t *p, size_t n)
{
	g_rng.strict = 1;
	g_rng.len[g_rng.n] = n;
	memcpy(g_rng.val[g_rng.n++], p, n);
}

static WRT_UNUSED void cxt_rng_push_u64(uint64_t v)
{
	uint8_t b[8];

	wri_le64_put(b, v);
	cxt_rng_push(b, 8);
}

/* ---- environment ---------------------------------------------------------------------------- */

typedef struct cxt_env {
	wri_ctx x;
	uint8_t *raw, *mem; /* raw malloc block, 64-byte aligned start inside it */
	size_t memsz;
	wri_arena a;
	wri_cx_client c;
	wr_cluster_spec spec;
} cxt_env;

/* user: id or "client.id"; key: the principal key; ticket_cap 0 = the harness profile's. */
static WRT_UNUSED int cxt_env_init(cxt_env *e, const char *user, const wr_key *key, uint32_t ticket_cap)
{
	size_t need = 0;
	uintptr_t a;

	memset(e, 0, sizeof(*e));
	wr_config_profile_harness(&e->x.cfg);
	if (ticket_cap != 0)
		e->x.cfg.ticket_cap = ticket_cap;
	e->x.host.size = (uint32_t)sizeof(e->x.host);
	e->x.host.random = cxt_random;
	e->x.now.mono_ms = CXT_T0;
	if (wri_cx_client_mem(&e->x.cfg, &need) != WR_OK)
		return -1;
	e->memsz = need + 64;
	e->raw = (uint8_t *)calloc(1, e->memsz + 64);
	if (e->raw == NULL)
		return -1;
	a = ((uintptr_t)e->raw + 63u) & ~(uintptr_t)63u;
	e->mem = (uint8_t *)a;
	wri_arena_init(&e->a, e->mem, e->memsz);
	strncpy(e->spec.user, user, sizeof(e->spec.user) - 1);
	e->spec.key = *key;
	return (int)wri_cx_client_init(&e->c, &e->x, &e->a, &e->spec);
}

static WRT_UNUSED void cxt_env_free(cxt_env *e)
{
	wri_cx_client_wipe(&e->c);
	free(e->raw);
	e->raw = NULL;
}

static WRT_UNUSED wr_key cxt_key(unsigned type, uint8_t seed)
{
	wr_key k;
	uint8_t s[32];
	size_t i, n = type == WR_KEY_TYPE_AES ? 16u : 32u;

	for (i = 0; i < n; i++)
		s[i] = (uint8_t)(seed + 7u * i);
	if (wr_key_from_raw(&k, type, s, n) != WR_OK)
		memset(&k, 0, sizeof(k));
	return k;
}

/* ---- server-side builders --------------------------------------------------------------------- */

/* A CephXTicketBlob of data_len filler bytes: u8 1 | u64 secret_id | u32 len | data. Returns its size. */
static WRT_UNUSED size_t cxt_blob(uint8_t *out, uint64_t secret_id, uint32_t data_len, uint8_t fill)
{
	out[0] = 1;
	wri_le64_put(out + 1, secret_id);
	wri_le32_put(out + 9, data_len);
	memset(out + 13, fill, data_len);
	return 13u + data_len;
}

/* The sealed CephXServiceTicket (msg_a) for session key sk, under key mk. Returns the ciphertext size. */
static WRT_UNUSED size_t cxt_msga(cxt_env *e, const wr_key *mk, const wr_key *sk, uint32_t sec, uint32_t nsec,
				  uint8_t *out, size_t cap)
{
	uint8_t item[128];
	wri_wr w;
	size_t n = 0;

	wri_wr_init(&w, item, sizeof(item));
	wri_wr_u8(&w, 1);
	wri_wr_u16(&w, sk->type);
	wri_wr_zero(&w, 8);
	wri_wr_u16(&w, sk->len);
	wri_wr_bytes(&w, sk->secret, sk->len);
	wri_wr_u32(&w, sec);
	wri_wr_u32(&w, nsec);
	WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&e->x, mk, WRI_CX_USAGE_TICKET_SESSION_KEY, item, wri_wr_len(&w), out, cap, &n));
	return n;
}

typedef struct cxt_tk { /* one ticket of a reply */
	uint32_t service;
	wr_key key;               /* its session key */
	uint32_t val_s, val_ns;   /* validity */
	uint32_t blob_data;       /* data bytes of the CephXTicketBlob */
	uint64_t secret_id;
	uint8_t enc;              /* ticket_enc */
	const wr_key *enc_key;    /* for enc = 1: the previous AUTH session key */
	const wr_key *msga_key;   /* key msg_a is sealed under (the principal key, or the AUTH session key) */
} cxt_tk;

static WRT_UNUSED void cxt_put_ticket(cxt_env *e, wri_wr *w, const cxt_tk *t)
{
	uint8_t msga[256], blob[3400], bl[3500], ct[3700];
	size_t an, bn, cn = 0;

	an = cxt_msga(e, t->msga_key, &t->key, t->val_s, t->val_ns, msga, sizeof(msga));
	bn = cxt_blob(blob, t->secret_id, t->blob_data, 0xB0);
	wri_wr_u32(w, t->service);
	wri_wr_u8(w, 1);
	wri_wr_u32(w, (uint32_t)an);
	wri_wr_bytes(w, msga, an);
	wri_wr_u8(w, t->enc);
	if (t->enc == 0) {
		wri_wr_u32(w, (uint32_t)bn);
		wri_wr_bytes(w, blob, bn);
	} else {
		wri_le32_put(bl, (uint32_t)bn);
		memcpy(bl + 4, blob, bn);
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&e->x, t->enc_key, WRI_CX_USAGE_TICKET_BLOB, bl, bn + 4, ct, sizeof(ct), &cn));
		wri_wr_u32(w, (uint32_t)cn);
		wri_wr_bytes(w, ct, cn);
	}
}

/* u8 1 | u32 n | the tickets */
static WRT_UNUSED void cxt_put_ticket_reply(cxt_env *e, wri_wr *w, const cxt_tk *t, unsigned n)
{
	unsigned i;

	wri_wr_u8(w, 1);
	wri_wr_u32(w, n);
	for (i = 0; i < n; i++)
		cxt_put_ticket(e, w, &t[i]);
}

/* Options of a synthetic AUTH_DONE payload of the monitor (cephx.md 2.7). */
typedef struct cxt_dopt {
	uint16_t rtype;
	int32_t status;
	cxt_tk auth;
	int tail;            /* 0: stop after the AUTH ticket reply; 1: cbl and extra follow */
	uint32_t secret_len; /* connection secret length inside cbl (0 = crc) */
	int cbl_empty;       /* cbl is a zero-length blob (the MAuth path) */
	int n_extra;         /* tickets in extra: 0 = zero-length blob */
	cxt_tk extra[3];
} cxt_dopt;

static WRT_UNUSED void cxt_dopt_default(cxt_env *e, cxt_dopt *o, const wr_key *auth_key, const wr_key *osd_key)
{
	memset(o, 0, sizeof(*o));
	o->rtype = WRI_CX_REQ_GET_AUTH_SESSION_KEY;
	o->auth.service = WRI_CX_SERVICE_AUTH;
	o->auth.key = *auth_key;
	o->auth.val_s = 259200;
	o->auth.blob_data = 150;
	o->auth.secret_id = 2;
	o->auth.msga_key = &e->c.principal;
	o->tail = 1;
	o->n_extra = 1;
	o->extra[0].service = WRI_CX_SERVICE_OSD;
	o->extra[0].key = *osd_key;
	o->extra[0].val_s = 3600;
	o->extra[0].blob_data = 150;
	o->extra[0].secret_id = 7;
	o->extra[0].msga_key = auth_key; /* a pointer into o: callers keep o alive */
}

/* Build the payload; returns its length. */
static WRT_UNUSED size_t cxt_build_done(cxt_env *e, const cxt_dopt *o, uint8_t *out, size_t cap)
{
	uint8_t sec[80], cbl_item[96], cbl_ct[160], cbl[168], ex[4096];
	wri_wr w, wx;
	size_t cn = 0, i, exn;

	wri_wr_init(&w, out, cap);
	wri_wr_u16(&w, o->rtype);
	wri_wr_i32(&w, o->status);
	cxt_put_ticket_reply(e, &w, &o->auth, 1);
	if (!o->tail)
		return wri_wr_len(&w);
	/* cbl: u32 outer | u32 inner | sealed(string secret) under the new AUTH session key */
	if (o->cbl_empty) {
		wri_wr_u32(&w, 0);
	} else {
		memset(sec, 0x5C, sizeof(sec));
		wri_le32_put(cbl_item, o->secret_len);
		memcpy(cbl_item + 4, sec, o->secret_len);
		WRT_CHECK_STATUS(WR_OK, wri_cx_seal(&e->x, &o->auth.key, WRI_CX_USAGE_CONN_SECRET, cbl_item,
						    4u + o->secret_len, cbl_ct, sizeof(cbl_ct), &cn));
		wri_le32_put(cbl, (uint32_t)cn);
		memcpy(cbl + 4, cbl_ct, cn);
		wri_wr_u32(&w, (uint32_t)(cn + 4));
		wri_wr_bytes(&w, cbl, cn + 4);
	}
	if (o->n_extra == 0) {
		wri_wr_u32(&w, 0);
	} else {
		wri_wr_init(&wx, ex, sizeof(ex));
		wri_wr_u8(&wx, 1);
		wri_wr_u32(&wx, (uint32_t)o->n_extra);
		for (i = 0; i < (size_t)o->n_extra; i++)
			cxt_put_ticket(e, &wx, &o->extra[i]);
		exn = wri_wr_len(&wx);
		wri_wr_u32(&w, (uint32_t)exn);
		wri_wr_bytes(&w, ex, exn);
	}
	return wri_wr_ok(&w) ? wri_wr_len(&w) : 0;
}

/* ---- driving the client ----------------------------------------------------------------------- */

#define CXT_CHAL 0x1122334455667788ull

/* begin + more + done of a monitor connection; req / more_out get the client payloads (may be NULL). */
static WRT_UNUSED wr_status cxt_mon_hs(cxt_env *e, const uint8_t *done, size_t dn, uint64_t gid, uint32_t mode,
				       uint8_t *req, size_t *reqn, uint8_t *more, size_t *moren)
{
	const wri_auth_ops *ops = wri_cx_ops();
	uint8_t b1[512], b2[512], chal[9];
	wri_wr w;
	wr_status st;

	wri_wr_init(&w, b1, sizeof(b1));
	st = ops->begin(&e->c, WRI_ENTITY_MON, &w);
	if (req != NULL && st == WR_OK) {
		memcpy(req, b1, wri_wr_len(&w));
		*reqn = wri_wr_len(&w);
	}
	if (st != WR_OK)
		return st;
	chal[0] = 1;
	wri_le64_put(chal + 1, CXT_CHAL);
	wri_wr_init(&w, b2, sizeof(b2));
	st = ops->more(&e->c, chal, sizeof(chal), &w);
	if (more != NULL && st == WR_OK) {
		memcpy(more, b2, wri_wr_len(&w));
		*moren = wri_wr_len(&w);
	}
	if (st != WR_OK)
		return st;
	return ops->done(&e->c, gid, mode, done, dn);
}

/* A full, valid first handshake (mask 0x24): returns the done status. */
static WRT_UNUSED wr_status cxt_good_mon(cxt_env *e, const wr_key *auth_key, const wr_key *osd_key, uint64_t gid)
{
	cxt_dopt o;
	uint8_t buf[4096];
	size_t n;

	cxt_dopt_default(e, &o, auth_key, osd_key);
	o.extra[0].msga_key = auth_key;
	n = cxt_build_done(e, &o, buf, sizeof(buf));
	return cxt_mon_hs(e, buf, n, gid, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL);
}

#endif /* AUTH_CX_SRV_H */
