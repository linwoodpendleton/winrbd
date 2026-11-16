/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_client.c - the cephx client machine behind wri_cx_ops() (docs/spec/cephx.md 3.2, 3.3).
 *
 * One machine serves every connection of the client, one handshake at a time; the connection calls
 * begin / more / done through the wri_auth_ops table and session_key / ident_gid afterwards.
 *
 * Monitor peer (CEPHX_GET_AUTH_SESSION_KEY):
 *   begin  AUTH_REQUEST payload: u8 10 | EntityName (u32 8, string id) | u64 global_id. The global id is
 *          the held one only when an unexpired AUTH ticket is held too (a reclaim has to prove itself
 *          with that ticket); otherwise 0 asks for a new session.
 *   more   AUTH_REPLY_MORE = CephXServerChallenge (u8 1, u64 challenge, must be non-zero); answer =
 *          request header 0x0100 | CephXAuthenticate {v 3, client challenge from the host RNG, proof
 *          (wri_cx_challenge_proof), old ticket (empty, or the held AUTH ticket when reclaiming),
 *          other_keys = want_mask}.
 *   done   AUTH_DONE payload: response header (0x0100, status 0), the AUTH ticket reply (msg_a under
 *          the principal key), then if bytes remain `cbl` (the connection secret, empty in crc mode)
 *          and `extra` (the second ticket reply under the new AUTH session key; zero length when
 *          only AUTH was asked for). Secure mode (a non-empty secret, or mode != crc) is refused with
 *          WR_E_M2_MODE. Global id 0 is WR_E_AUTH_GID0. After a successful done every service in
 *          want_mask that this client keeps must be held, else WR_E_AUTH_PROTO. ANY failure of done
 *          drops all tickets and the global id (wri_cx_forget): the next attempt starts clean and
 *          nothing here retries (cephx.md 3.8).
 *
 * OSD peer (authorizer, always one challenge round trip):
 *   begin  authorizer: u8 1 | u64 global_id | u32 4 | ticket blob | sealed CephXAuthorize{nonce, no
 *          challenge} under the OSD ticket session key, usage 0x10. Needs a held, unexpired OSD ticket.
 *   more   AUTH_REPLY_MORE = RAW ciphertext of CephXAuthorizeChallenge (usage 0x11); answer = the same
 *          authorizer with the same nonce and have_challenge 1, plus_one = challenge + 1.
 *   done   AUTH_DONE payload = u32 len | ciphertext of CephXAuthorizeReply (usage 0x12); requires
 *          nonce_plus_one == nonce + 1 (else WR_E_AUTH_DECRYPT). A connection secret in it is secure
 *          mode: WR_E_M2_MODE. The ticket slot must not have been replaced since begin (WR_E_STATE).
 *
 * session_key(): the AUTH session key on a monitor connection, the OSD ticket session key on an OSD
 * connection (AUTH_SIGNATURE, cephx.md 2.9). ident_gid(): -1 on a monitor connection that asked for a
 * new id, the reclaimed id when it carried one, the monitor-assigned id on an OSD connection.
 *
 * Secrets: nothing is logged; the nonce and every decrypted byte are wiped when the handshake ends.
 */
#include "wri_cx.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CX_AUTHENTICATE_V 3u
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

/* ---- begin ---------------------------------------------------------------------------------------- */

static wr_status cx_begin_mon(wri_cx_client *c, wri_wr *out)
{
	uint64_t gid = 0;
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_AUTH];

	/* A held global id is reclaimed only together with a usable old AUTH ticket (cephx.md 3.7). */
	if (c->global_id != 0 && t->have && c->x->now.mono_ms < t->valid_until_ms)
		gid = c->global_id;
	c->req_new_gid = (uint8_t)(gid == 0);
	wri_wr_u8(out, (uint8_t)WRI_CX_MON_AUTH_MODE);
	wri_wr_u32(out, WRI_ENTITY_CLIENT);
	wri_wr_u32(out, c->user_len);
	wri_wr_bytes(out, (const uint8_t *)c->user, c->user_len);
	wri_wr_u64(out, gid);
	if (!wri_wr_ok(out))
		return WRI_CX_FAIL(c, out->err, "AUTH_REQUEST payload does not fit", 0, 0, 0);
	c->st = WRI_CX_MON_SENT_REQ;
	return WR_OK;
}

static wr_status cx_begin_osd(wri_cx_client *c, wri_wr *out)
{
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	uint8_t rnd[8];
	wr_status st;

	if (!t->have || c->x->now.mono_ms >= t->valid_until_ms)
		return WRI_CX_FAIL(c, WR_E_AUTH_TICKET_EXPIRED, "no usable OSD ticket", t->have, t->valid_until_ms,
				   c->x->now.mono_ms);
	if (c->global_id == 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_GID0, "no global id to present to the OSD", 0, 0, 0);
	st = wri_random(c->x, rnd, sizeof(rnd));
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "no random for the authorizer nonce", 0, 0, 0);
	c->authorizer_nonce = wri_le64_get(rnd);
	wri_secure_zero(rnd, sizeof(rnd));
	c->osd_gen = t->gen;
	st = wri_cx_put_authorizer(c, WRI_CX_SERVICE_OSD, t, c->authorizer_nonce, 0, 0, out);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "authorizer could not be built", 0, 0, 0);
	c->st = WRI_CX_OSD_SENT_AUTHORIZER;
	return WR_OK;
}

static wr_status cx_begin(void *a, uint8_t target_type, wri_wr *out)
{
	wri_cx_client *c = cx_of(a);
	wr_status st;

	if (c == NULL || out == NULL)
		return WR_E_INVAL;
	/* A new connection: forget the previous handshake (tickets and the global id stay). */
	WR_MEMSET(&c->err, 0, sizeof(c->err));
	c->st = WRI_CX_IDLE;
	c->target_type = target_type;
	c->server_challenge = 0;
	c->client_challenge = 0;
	c->authorizer_nonce = 0;
	c->sess_key = NULL;
	c->sess_key_len = 0;
	if (target_type == WRI_ENTITY_MON)
		st = cx_begin_mon(c, out);
	else if (target_type == WRI_ENTITY_OSD)
		st = cx_begin_osd(c, out);
	else
		st = WRI_CX_FAIL(c, WR_E_INVAL, "cephx connects to monitors and OSDs only", target_type, 0, 0);
	if (st != WR_OK) {
		c->authorizer_nonce = 0;
		c->st = WRI_CX_FAILED;
	}
	return st;
}

/* ---- more ----------------------------------------------------------------------------------------- */

static wr_status cx_more_mon(wri_cx_client *c, const uint8_t *reply, size_t n, wri_wr *out)
{
	const wri_cx_ticket *old = &c->ticket[WRI_CX_SLOT_AUTH];
	uint8_t rnd[8];
	uint64_t proof = 0;
	wri_rd r;
	wr_status st;

	if (c->st != WRI_CX_MON_SENT_REQ)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "unexpected AUTH_REPLY_MORE", c->st, 0, 0);
	wri_rd_init(&r, reply, n);
	(void)wri_rd_u8(&r); /* struct version */
	c->server_challenge = wri_rd_u64(&r);
	if (!wri_rd_ok(&r))
		return WRI_CX_FAIL(c, r.err, "server challenge truncated", n, 0, 0);
	if (c->server_challenge == 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "server challenge is zero", 0, 0, 0);
	st = wri_random(c->x, rnd, sizeof(rnd));
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "no random for the client challenge", 0, 0, 0);
	c->client_challenge = wri_le64_get(rnd);
	wri_secure_zero(rnd, sizeof(rnd));
	st = wri_cx_challenge_proof(c->x, &c->principal, c->server_challenge, c->client_challenge, &proof);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, st, "challenge proof failed", c->principal.type, 0, 0);
	if (!c->req_new_gid && !old->have)
		return WRI_CX_FAIL(c, WR_E_STATE, "old ticket dropped during the handshake", 0, 0, 0);

	wri_wr_u16(out, (uint16_t)WRI_CX_REQ_GET_AUTH_SESSION_KEY);
	wri_wr_u8(out, (uint8_t)CX_AUTHENTICATE_V);
	wri_wr_u64(out, c->client_challenge);
	wri_wr_u64(out, proof);
	if (c->req_new_gid) { /* empty CephXTicketBlob: v 1, secret_id 0, no data */
		wri_wr_u8(out, 1u);
		wri_wr_u64(out, 0);
		wri_wr_u32(out, 0);
	} else {
		wri_wr_bytes(out, old->blob, old->blob_len);
	}
	wri_wr_u32(out, c->want_mask);
	if (!wri_wr_ok(out))
		return WRI_CX_FAIL(c, out->err, "AUTH_REQUEST_MORE payload does not fit", 0, 0, 0);
	c->st = WRI_CX_MON_SENT_AUTH;
	return WR_OK;
}

static wr_status cx_more_osd(wri_cx_client *c, const uint8_t *reply, size_t n, wri_wr *out)
{
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	const uint8_t *item = NULL;
	size_t ilen = 0;
	wri_rd r;
	uint64_t chal;
	wr_status st;

	if (c->st != WRI_CX_OSD_SENT_AUTHORIZER)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "unexpected AUTH_REPLY_MORE", c->st, 0, 0);
	if (!t->have || t->gen != c->osd_gen)
		return WRI_CX_FAIL(c, WR_E_STATE, "OSD ticket replaced during the handshake", 0, 0, 0);
	st = wri_cx_open(c->x, &t->session_key, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, reply, n, c->scratch,
			 c->scratch_cap, &item, &ilen);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "authorizer challenge does not decrypt",
				   (uint64_t)(-(int64_t)st), n, 0);
	wri_rd_init(&r, item, ilen);
	(void)wri_rd_u8(&r);
	chal = wri_rd_u64(&r);
	if (!wri_rd_ok(&r)) {
		st = WRI_CX_FAIL(c, r.err, "authorizer challenge truncated", ilen, 0, 0);
	} else {
		c->server_challenge = chal;
		st = wri_cx_put_authorizer(c, WRI_CX_SERVICE_OSD, t, c->authorizer_nonce, 1, chal + 1u, out);
		if (st != WR_OK)
			st = WRI_CX_FAIL(c, st, "second authorizer could not be built", 0, 0, 0);
	}
	wri_secure_zero(c->scratch, c->scratch_cap);
	if (st == WR_OK)
		c->st = WRI_CX_OSD_SENT_CHALLENGE;
	return st;
}

static wr_status cx_more(void *a, const uint8_t *reply, size_t n, wri_wr *out)
{
	wri_cx_client *c = cx_of(a);
	wr_status st;

	if (c == NULL || out == NULL || (reply == NULL && n != 0))
		return WR_E_INVAL;
	if (c->target_type == WRI_ENTITY_MON)
		st = cx_more_mon(c, reply, n, out);
	else if (c->target_type == WRI_ENTITY_OSD)
		st = cx_more_osd(c, reply, n, out);
	else
		st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "AUTH_REPLY_MORE before begin", 0, 0, 0);
	if (st != WR_OK) {
		c->authorizer_nonce = 0;
		c->st = WRI_CX_FAILED;
	}
	return st;
}

/* ---- done ----------------------------------------------------------------------------------------- */

/* `cbl`: u32 inner_len | sealed (string connection_secret), usage 0x03 under the AUTH session key. */
static wr_status cx_open_cbl(wri_cx_client *c, const uint8_t *cbl, size_t n)
{
	const uint8_t *item = NULL, *ct;
	size_t ilen = 0;
	wri_rd r, ri;
	uint32_t inner, slen;
	wr_status st;

	wri_rd_init(&r, cbl, n);
	inner = wri_rd_u32(&r);
	ct = wri_rd_bytes(&r, inner);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "connection secret blob malformed", n, inner, 0);
	st = wri_cx_open(c->x, &c->ticket[WRI_CX_SLOT_AUTH].session_key, WRI_CX_USAGE_CONN_SECRET, ct, inner,
			 c->scratch, c->scratch_cap, &item, &ilen);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "connection secret does not decrypt", (uint64_t)(-(int64_t)st),
				   inner, 0);
	wri_rd_init(&ri, item, ilen);
	slen = wri_rd_u32(&ri);
	if (!wri_rd_ok(&ri) || slen > wri_rd_left(&ri))
		st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "connection secret malformed", ilen, slen, 0);
	else if (slen != 0)
		st = WRI_CX_FAIL(c, WR_E_M2_MODE, "server sent a connection secret: secure mode is not supported", slen,
				 0, 0);
	wri_secure_zero(c->scratch, c->scratch_cap);
	return st;
}

static wr_status cx_done_mon_body(wri_cx_client *c, uint64_t gid, uint32_t mode, const uint8_t *payload, size_t n)
{
	wri_rd r, sub;
	uint32_t stored = 0, more = 0, cbl_n, extra_n, svc;
	const uint8_t *cbl, *extra;
	uint64_t prev_gid = c->global_id;
	unsigned slot;
	uint16_t rtype;
	int32_t rstatus;
	wr_status st;

	if (c->st != WRI_CX_MON_SENT_AUTH)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "unexpected AUTH_DONE", c->st, 0, 0);
	if (mode != WRI_CONN_MODE_CRC)
		return WRI_CX_FAIL(c, WR_E_M2_MODE, "connection mode is not crc", mode, 0, 0);
	if (gid == 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_GID0, "server assigned global id 0", 0, 0, 0);

	wri_rd_init(&r, payload, n);
	rtype = wri_rd_u16(&r);
	rstatus = wri_rd_i32(&r);
	if (!wri_rd_ok(&r))
		return WRI_CX_FAIL(c, r.err, "response header truncated", n, 0, 0);
	if (rtype != WRI_CX_REQ_GET_AUTH_SESSION_KEY)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "response is not for GET_AUTH_SESSION_KEY", rtype, 0, 0);
	if (rstatus != 0) {
		st = WRI_CX_FAIL(c, WR_E_AUTH_RESULT, "server reported an error status", (uint64_t)(int64_t)rstatus, 0, 0);
		if (c->err.status == WR_E_AUTH_RESULT)
			c->err.peer_result = rstatus;
		return st;
	}
	st = wri_cx_ticket_reply(c, &r, WRI_CX_TR_INITIAL, &stored);
	if (st != WR_OK)
		return st;
	if (prev_gid != 0 && prev_gid != gid) /* a different identity: the old OSD ticket is not ours any more */
		wri_cx_slot_clear(c, WRI_CX_SLOT_OSD);

	if (wri_rd_left(&r) != 0) { /* cbl and extra, both or neither (cephx.md 2.7) */
		cbl_n = wri_rd_u32(&r);
		cbl = wri_rd_bytes(&r, cbl_n);
		extra_n = wri_rd_u32(&r);
		extra = wri_rd_bytes(&r, extra_n);
		if (!wri_rd_ok(&r))
			return WRI_CX_FAIL(c, r.err, "connection secret / extra tickets truncated", n, r.pos, 0);
		if (cbl_n != 0) {
			st = cx_open_cbl(c, cbl, cbl_n);
			if (st != WR_OK)
				return st;
		}
		if (extra_n != 0) {
			wri_rd_init(&sub, extra, extra_n);
			st = wri_cx_ticket_reply(c, &sub, WRI_CX_TR_SERVICES, &more);
			stored |= more;
			if (st != WR_OK)
				return st;
		}
	}
	/*
	 * Every ticket we asked for and keep must be held afterwards (the reference client fails the same
	 * way). "Held" means unexpired: an old OSD ticket that outlived its validity and that this reply did
	 * not replace must not make the handshake look complete.
	 */
	for (slot = 0; slot < WRI_CX_NTICKETS; slot++) {
		svc = slot == WRI_CX_SLOT_AUTH ? WRI_CX_SERVICE_AUTH : WRI_CX_SERVICE_OSD;
		if ((c->want_mask & svc) != 0 && !wri_cx_have(c, svc, c->x->now.mono_ms))
			return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "a requested ticket is missing from the reply", svc,
					   c->want_mask, stored);
	}
	c->global_id = gid;
	c->sess_key = c->ticket[WRI_CX_SLOT_AUTH].session_key.secret;
	c->sess_key_len = c->ticket[WRI_CX_SLOT_AUTH].session_key.len;
	return WR_OK;
}

static wr_status cx_done_osd_body(wri_cx_client *c, uint32_t mode, const uint8_t *payload, size_t n)
{
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	const uint8_t *item = NULL, *ct;
	size_t ilen = 0;
	wri_rd r, ri;
	uint32_t clen, slen = 0;
	uint8_t v;
	uint64_t npo;
	wr_status st;

	if (c->st != WRI_CX_OSD_SENT_CHALLENGE)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "unexpected AUTH_DONE", c->st, 0, 0);
	if (mode != WRI_CONN_MODE_CRC)
		return WRI_CX_FAIL(c, WR_E_M2_MODE, "connection mode is not crc", mode, 0, 0);
	if (!t->have || t->gen != c->osd_gen)
		return WRI_CX_FAIL(c, WR_E_STATE, "OSD ticket replaced during the handshake", 0, 0, 0);
	wri_rd_init(&r, payload, n);
	clen = wri_rd_u32(&r);
	ct = wri_rd_bytes(&r, clen);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "authorizer reply malformed", n, clen, 0);
	st = wri_cx_open(c->x, &t->session_key, WRI_CX_USAGE_AUTHORIZE_REPLY, ct, clen, c->scratch, c->scratch_cap,
			 &item, &ilen);
	if (st != WR_OK)
		return WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "authorizer reply does not decrypt", (uint64_t)(-(int64_t)st),
				   clen, 0);
	wri_rd_init(&ri, item, ilen);
	v = wri_rd_u8(&ri);
	npo = wri_rd_u64(&ri);
	if (v >= 2u)
		slen = wri_rd_u32(&ri); /* the connection secret of secure mode */
	if (!wri_rd_ok(&ri))
		st = WRI_CX_FAIL(c, ri.err, "authorizer reply truncated", ilen, 0, 0);
	else if (npo != c->authorizer_nonce + 1u)
		st = WRI_CX_FAIL(c, WR_E_AUTH_DECRYPT, "authorizer reply answers a different nonce", 0, 0, 0);
	else if (slen != 0)
		st = WRI_CX_FAIL(c, WR_E_M2_MODE, "server sent a connection secret: secure mode is not supported", slen,
				 0, 0);
	wri_secure_zero(c->scratch, c->scratch_cap);
	if (st == WR_OK) {
		c->authorizer_nonce = 0;
		c->sess_key = t->session_key.secret;
		c->sess_key_len = t->session_key.len;
	}
	return st;
}

static wr_status cx_done(void *a, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n)
{
	wri_cx_client *c = cx_of(a);
	wr_status st;

	if (c == NULL || (payload == NULL && n != 0))
		return WR_E_INVAL;
	if (c->target_type == WRI_ENTITY_MON) {
		st = cx_done_mon_body(c, global_id, mode, payload, n);
		if (st != WR_OK)
			wri_cx_forget(c); /* never reuse half a reply; the next attempt starts clean */
	} else if (c->target_type == WRI_ENTITY_OSD) {
		st = cx_done_osd_body(c, mode, payload, n);
		(void)global_id; /* the OSD echoes our own id; the reference client ignores it too */
	} else {
		st = WRI_CX_FAIL(c, WR_E_AUTH_PROTO, "AUTH_DONE before begin", 0, 0, 0);
	}
	if (st != WR_OK) {
		c->authorizer_nonce = 0;
		c->sess_key = NULL;
		c->sess_key_len = 0;
		c->st = WRI_CX_FAILED;
	} else {
		c->st = WRI_CX_DONE;
	}
	return st;
}

static void cx_session_key(void *a, const uint8_t **key, size_t *len)
{
	wri_cx_client *c = cx_of(a);

	if (key == NULL || len == NULL)
		return;
	if (c != NULL && c->st == WRI_CX_DONE && c->sess_key != NULL) {
		*key = c->sess_key;
		*len = c->sess_key_len;
	} else {
		*key = NULL;
		*len = 0;
	}
}

static int64_t cx_ident_gid(void *a, uint8_t target_type)
{
	wri_cx_client *c = cx_of(a);

	if (c == NULL || c->st != WRI_CX_DONE)
		return -1;
	if (target_type == WRI_ENTITY_MON && c->req_new_gid)
		return -1;
	return (int64_t)c->global_id;
}

const wri_auth_ops *wri_cx_ops(void)
{
	static const wri_auth_ops ops = {cx_begin, cx_more, cx_done, cx_session_key, cx_ident_gid};

	return &ops;
}
