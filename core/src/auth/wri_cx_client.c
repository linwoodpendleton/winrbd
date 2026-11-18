/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_client.c - the cephx client behind wri_cx_ops(): the monitor path of part A, with its one
 * (embedded, slot-0) handshake, plus the authorizer builder shared by the handshake machine and renewal.
 *
 * The machine itself is in wri_cx_hs.c (docs/spec/cephx.md 3.2, 3.3; architecture 21.2): one handshake with
 * its state in a wri_cx_hs. wri_cx_ops() keeps its part A contract, a wri_cx_client * as the `a` argument,
 * by running that machine on the handshake fields embedded in the client under their part A names (st,
 * target_type, req_new_gid, challenges, authorizer_nonce, osd_gen, sess_key, err): each call copies them
 * into a stack slot bound to the client, runs the step, copies them back and wipes the copy. The copy
 * holds secrets (challenges, nonce) only for the length of one call.
 *
 * A connection that wants an authentication of its own in parallel with others uses wri_cx_hs_ops()
 * with a wri_cx_hs of its handshake slot instead; both tables share the client's tickets, principal key and
 * global id, and nothing else. This file also holds the slots' memory (wri_cx_hs_mem / _carve / _init / _wipe)
 * and the copy between a slot and the embedded fields.
 *
 * session_key(): the AUTH session key on a monitor connection, the OSD ticket session key on an OSD
 * connection (AUTH_SIGNATURE, cephx.md 2.9). ident_gid(): -1 on a monitor connection that asked for a
 * new id, the reclaimed id when it carried one, the monitor-assigned id on an OSD connection.
 *
 * Secrets: nothing is logged.
 */
#include "wri_cx.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CX_AUTHORIZE_V 2u
#define CX_ITEM_AUTHORIZE_LEN 18u /* u8 v | u64 nonce | u8 have_challenge | u64 plus_one */

static wri_cx_client *cx_of(void *a)
{
	wri_cx_client *c = (wri_cx_client *)a;

	return (c != NULL && c->x != NULL) ? c : NULL;
}

static wr_status cx_wr_status(wri_wr *w)
{
	return wri_wr_ok(w) ? WR_OK : w->err;
}

/* ---- authorizer (shared with renewal) ---------------------------------------------------------- */

wr_status wri_cx_put_authorizer(const wri_cx_client *c, uint32_t service, const wri_cx_ticket *t, uint64_t nonce,
				int have_challenge, uint64_t plus_one, wri_wr *w)
{
	uint8_t item[CX_ITEM_AUTHORIZE_LEN];
	size_t ct_n, got = 0;
	uint8_t *p;
	wr_status st;

	if (c == NULL || t == NULL || w == NULL || !t->have)
		return WR_E_INVAL;
	item[0] = (uint8_t)CX_AUTHORIZE_V;
	wri_le64_put(item + 1, nonce);
	item[9] = have_challenge ? 1u : 0u;
	wri_le64_put(item + 10, plus_one);
	ct_n = wri_cx_cipher_len(t->session_key.type, CX_ITEM_AUTHORIZE_LEN + 9u);
	if (ct_n == 0 || ct_n > 0xffffffffu) {
		wri_secure_zero(item, sizeof(item));
		return WR_E_AUTH_KEY_TYPE;
	}
	wri_wr_u8(w, (uint8_t)WRI_CX_AUTHORIZER_V);
	wri_wr_u64(w, c->global_id);
	wri_wr_u32(w, service);
	wri_wr_bytes(w, t->blob, t->blob_len);
	wri_wr_u32(w, (uint32_t)ct_n);
	p = wri_wr_reserve(w, ct_n);
	st = cx_wr_status(w);
	if (st == WR_OK)
		st = wri_cx_seal(c->x, &t->session_key, WRI_CX_USAGE_AUTHORIZE, item, sizeof(item), p, ct_n, &got);
	if (st == WR_OK && got != ct_n)
		st = WR_E_CRYPTO_LEN;
	wri_secure_zero(item, sizeof(item));
	return st;
}

/* ---- slots: memory, init, wipe ---------------------------------------------------------------- */

wr_status wri_cx_hs_mem(const wr_config *cfg, size_t *arena_bytes)
{
	size_t used = 0;
	wr_status st;

	if (arena_bytes == NULL)
		return WR_E_INVAL;
	*arena_bytes = 0;
	if (cfg == NULL || cfg->max_handshakes < 1u)
		return WR_E_INVAL;
	st = wri_arena_plan_array(&used, cfg->max_handshakes, sizeof(wri_cx_hs), 16u);
	if (st == WR_OK)
		*arena_bytes = used;
	return st;
}

wr_status wri_cx_hs_carve(wri_arena *a, const wr_config *cfg, wri_cx_hs **hs, uint32_t *n)
{
	wri_cx_hs *p;

	if (hs == NULL || n == NULL)
		return WR_E_INVAL;
	*hs = NULL;
	*n = 0;
	if (a == NULL || cfg == NULL || cfg->max_handshakes < 1u)
		return WR_E_INVAL;
	p = (wri_cx_hs *)wri_arena_take_array(a, cfg->max_handshakes, sizeof(wri_cx_hs), 16u);
	if (p == NULL)
		return WR_E_BUDGET;
	*hs = p; /* the arena hands out zeroed memory: every slot starts unbound */
	*n = cfg->max_handshakes;
	return WR_OK;
}

wr_status wri_cx_hs_init(wri_cx_hs *h, wri_cx_client *c)
{
	if (h == NULL || c == NULL)
		return WR_E_INVAL;
	wri_secure_zero(h, sizeof(*h));
	h->cl = c;
	h->st = WRI_CX_IDLE;
	return WR_OK;
}

void wri_cx_hs_wipe(wri_cx_hs *h)
{
	if (h == NULL)
		return;
	wri_secure_zero(h, sizeof(*h)); /* challenges, nonce, key view, error, the binding */
}

void wri_cx_hs_load(wri_cx_hs *h, wri_cx_client *c)
{
	h->cl = c;
	h->st = c->st;
	h->target_type = c->target_type;
	h->req_new_gid = c->req_new_gid;
	h->server_challenge = c->server_challenge;
	h->client_challenge = c->client_challenge;
	h->authorizer_nonce = c->authorizer_nonce;
	h->osd_gen = c->osd_gen;
	h->sess_key = c->sess_key;
	h->sess_key_len = c->sess_key_len;
	h->key_gen = c->key_gen;
	h->gid = c->gid;
	h->err = c->err;
}

void wri_cx_hs_store(wri_cx_client *c, const wri_cx_hs *h)
{
	c->st = h->st;
	c->target_type = h->target_type;
	c->req_new_gid = h->req_new_gid;
	c->server_challenge = h->server_challenge;
	c->client_challenge = h->client_challenge;
	c->authorizer_nonce = h->authorizer_nonce;
	c->osd_gen = h->osd_gen;
	c->sess_key = h->sess_key;
	c->sess_key_len = h->sess_key_len;
	c->key_gen = h->key_gen;
	c->gid = h->gid;
	c->err = h->err;
}

/* ---- the auth ops of a slot (wri_cx_hs_ops) ------------------------------------------------------ */

static wri_cx_hs *hs_of(void *a)
{
	wri_cx_hs *h = (wri_cx_hs *)a;

	return (h != NULL && h->cl != NULL && h->cl->x != NULL) ? h : NULL;
}

static wr_status hso_begin(void *a, uint8_t target_type, wri_wr *out)
{
	return wri_cx_hs_do_begin(hs_of(a), target_type, out);
}

static wr_status hso_more(void *a, const uint8_t *reply, size_t n, wri_wr *out)
{
	return wri_cx_hs_do_more(hs_of(a), reply, n, out);
}

static wr_status hso_done(void *a, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n)
{
	return wri_cx_hs_do_done(hs_of(a), global_id, mode, payload, n);
}

static void hso_session_key(void *a, const uint8_t **key, size_t *len)
{
	wri_cx_hs_do_session_key(hs_of(a), key, len);
}

static int64_t hso_ident_gid(void *a, uint8_t target_type)
{
	return wri_cx_hs_do_ident_gid(hs_of(a), target_type);
}

const wri_auth_ops *wri_cx_hs_ops(void)
{
	static const wri_auth_ops ops = {hso_begin, hso_more, hso_done, hso_session_key, hso_ident_gid};

	return &ops;
}

/* ---- the embedded handshake behind wri_cx_ops() ------------------------------------------------ */

/* A stack slot loaded from the client's embedded handshake fields. */
static void emb_load(wri_cx_hs *h, wri_cx_client *c)
{
	WR_MEMSET(h, 0, sizeof(*h));
	wri_cx_hs_load(h, c);
}

static void emb_drop(wri_cx_hs *h)
{
	wri_secure_zero(h, sizeof(*h)); /* challenges and nonce must not outlive the call on the stack */
}

static wr_status cx_begin(void *a, uint8_t target_type, wri_wr *out)
{
	wri_cx_client *c = cx_of(a);
	wri_cx_hs h;
	wr_status st;

	if (c == NULL || out == NULL)
		return WR_E_INVAL;
	emb_load(&h, c);
	st = wri_cx_hs_do_begin(&h, target_type, out);
	wri_cx_hs_store(c, &h);
	emb_drop(&h);
	return st;
}

static wr_status cx_more(void *a, const uint8_t *reply, size_t n, wri_wr *out)
{
	wri_cx_client *c = cx_of(a);
	wri_cx_hs h;
	wr_status st;

	if (c == NULL || out == NULL || (reply == NULL && n != 0))
		return WR_E_INVAL;
	emb_load(&h, c);
	st = wri_cx_hs_do_more(&h, reply, n, out);
	wri_cx_hs_store(c, &h);
	emb_drop(&h);
	return st;
}

static wr_status cx_done(void *a, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n)
{
	wri_cx_client *c = cx_of(a);
	wri_cx_hs h;
	wr_status st;

	if (c == NULL || (payload == NULL && n != 0))
		return WR_E_INVAL;
	emb_load(&h, c);
	st = wri_cx_hs_do_done(&h, global_id, mode, payload, n);
	wri_cx_hs_store(c, &h);
	emb_drop(&h);
	return st;
}

static void cx_session_key(void *a, const uint8_t **key, size_t *len)
{
	wri_cx_client *c = cx_of(a);
	wri_cx_hs h;

	if (key == NULL || len == NULL)
		return;
	if (c == NULL) {
		*key = NULL;
		*len = 0;
		return;
	}
	emb_load(&h, c);
	wri_cx_hs_do_session_key(&h, key, len);
	emb_drop(&h);
}

static int64_t cx_ident_gid(void *a, uint8_t target_type)
{
	wri_cx_client *c = cx_of(a);
	wri_cx_hs h;
	int64_t gid;

	if (c == NULL)
		return -1;
	emb_load(&h, c);
	gid = wri_cx_hs_do_ident_gid(&h, target_type);
	emb_drop(&h);
	return gid;
}

const wri_auth_ops *wri_cx_ops(void)
{
	static const wri_auth_ops ops = {cx_begin, cx_more, cx_done, cx_session_key, cx_ident_gid};

	return &ops;
}
