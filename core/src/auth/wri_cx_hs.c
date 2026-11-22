/* SPDX-License-Identifier: MIT */
/*
 * wri_cx_hs.c - one cephx handshake, with its state in its own slot (docs/spec/cephx.md 3.2, 3.3;
 * docs/design/core-architecture.md 21.2).
 *
 * The principal key, the ticket store, the global id and the renewal state belong to the client
 * (wri_cx_client); the state of ONE handshake belongs to a wri_cx_hs: the step, the peer kind, the two
 * challenges, the OSD authorizer nonce, the ticket generation seen at begin, the view of the session key, the
 * connection secret of secure mode (wri_cx_secret.c) and the first failure. Several slots may be in flight
 * against one client at once and interleave freely; no operation on one touches another's fields.
 *
 * Monitor peer (CEPHX_GET_AUTH_SESSION_KEY):
 *   begin  AUTH_REQUEST payload: u8 10 | EntityName (u32 8, string id) | u64 global_id. The global id is
 *          the held one only when an unexpired AUTH ticket is held too (a reclaim has to prove itself
 *          with that ticket); otherwise 0 asks for a new session.
 *   more   AUTH_REPLY_MORE = CephXServerChallenge (u8 1, u64 challenge, must be non-zero); answer =
 *          request header 0x0100 | CephXAuthenticate {v 3, client challenge from the host RNG, proof
 *          (wri_cx_challenge_proof), old ticket (empty, or the held AUTH ticket when reclaiming),
 *          other_keys = want_mask}.
 *   done   AUTH_DONE payload: response header (0x0100, status 0), the AUTH ticket reply (msg_a under the
 *          principal key), then if bytes remain `cbl` (the connection secret, empty in crc mode) and `extra`
 *          (the second ticket reply under the new AUTH session key; zero length when only AUTH was asked for).
 *          A mode other than crc or secure is WR_E_M2_MODE. The secret (architecture 34.3): crc with one is
 *          WR_E_AUTH_PROTO; secure without one, or with fewer than WRI_CX_SECRET_MIN or more than
 *          WRI_CX_SECRET_MAX bytes, is WR_E_M2_SECRET; a good one is kept in the slot for conn_secret. Global id
 *          0 is WR_E_AUTH_GID0. After a successful done every service in want_mask that this client keeps must
 *          be held, else WR_E_AUTH_PROTO. ANY failure of done drops all tickets and the global id
 *          (wri_cx_forget): the next attempt starts clean and nothing here retries (cephx.md 3.8). That rule is
 *          the client's, not the slot's, so it reaches every handshake: one in flight fails with WR_E_STATE.
 *
 * OSD peer (authorizer, always one challenge round trip):
 *   begin  authorizer: u8 1 | u64 global_id | u32 4 | ticket blob | sealed CephXAuthorize{nonce, no
 *          challenge} under the OSD ticket session key, usage 0x10. Needs a held, unexpired OSD ticket.
 *   more   AUTH_REPLY_MORE = RAW ciphertext of CephXAuthorizeChallenge (usage 0x11); answer = the same
 *          authorizer with the same nonce and have_challenge 1, plus_one = challenge + 1.
 *   done   AUTH_DONE payload = u32 len | ciphertext of CephXAuthorizeReply (usage 0x12); requires
 *          nonce_plus_one == nonce + 1 (else WR_E_AUTH_DECRYPT). Version 2 of the reply carries the
 *          connection secret (u32 len | bytes; version 1 has none), judged like the monitor's. The ticket
 *          slot must not have been replaced since begin (WR_E_STATE).
 *
 * session_key(): the AUTH session key on a monitor connection, the OSD ticket session key on an OSD connection
 * (AUTH_SIGNATURE, cephx.md 2.9); NULL once the ticket it points into was replaced or forgotten. ident_gid():
 * -1 on a monitor connection that asked for a new id, else the slot's own copy of the id it ended with.
 *
 * The decrypt scratch of the client is shared by every slot: safe because the auth callbacks run to completion,
 * one at a time (wri_m2_conn.h), and it is wiped after every use. Secrets: nothing is logged; the nonce, the
 * challenges, the connection secret and every decrypted byte are wiped when the handshake ends, fails or its
 * slot is wiped (the secret of a good secure handshake stays until the connection has taken it, see wri_cx.h).
 * The embedded handshake of wri_cx_ops() (wri_cx_client.c) runs this machine on a stack copy of its fields.
 */
#include "wri_cx.h"

#include "wri_le.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CX_AUTHENTICATE_V 3u

static wr_status hs_fail(wri_cx_hs *h, wr_status st, unsigned line, const char *what, uint64_t a0, uint64_t a1,
			 uint64_t a2)
{
	wri_errinfo_set(&h->err, st, WR_MOD_AUTH, line, what, a0, a1, a2);
	return st;
}
#define HS_FAIL(h, st, what, a0, a1, a2) \
	hs_fail((h), (st), (unsigned)__LINE__, (what), (uint64_t)(a0), (uint64_t)(a1), (uint64_t)(a2))

/* Drop what a handshake that ended (or never began) must not keep: the challenges, the nonce, the key view. */
static void hs_scrub(wri_cx_hs *h)
{
	h->server_challenge = 0;
	h->client_challenge = 0;
	h->authorizer_nonce = 0;
	h->sess_key = NULL;
	h->sess_key_len = 0;
	h->key_gen = 0;
	h->gid = 0;
	wri_cx_sec_wipe(&h->sec);
}

/* ---- begin ---------------------------------------------------------------------------------------- */

static wr_status hs_begin_mon(wri_cx_hs *h, wri_wr *out)
{
	wri_cx_client *c = h->cl;
	uint64_t gid = 0;
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_AUTH];

	/* A held global id is reclaimed only together with a usable old AUTH ticket (cephx.md 3.7). */
	if (c->global_id != 0 && t->have && c->x->now.mono_ms < t->valid_until_ms)
		gid = c->global_id;
	h->req_new_gid = (uint8_t)(gid == 0);
	wri_wr_u8(out, (uint8_t)WRI_CX_MON_AUTH_MODE);
	wri_wr_u32(out, WRI_ENTITY_CLIENT);
	wri_wr_u32(out, c->user_len);
	wri_wr_bytes(out, (const uint8_t *)c->user, c->user_len);
	wri_wr_u64(out, gid);
	if (!wri_wr_ok(out))
		return HS_FAIL(h, out->err, "AUTH_REQUEST payload does not fit", 0, 0, 0);
	h->st = WRI_CX_MON_SENT_REQ;
	return WR_OK;
}

static wr_status hs_begin_osd(wri_cx_hs *h, wri_wr *out)
{
	wri_cx_client *c = h->cl;
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	uint8_t rnd[8] = {0};
	wr_status st;

	if (!t->have || c->x->now.mono_ms >= t->valid_until_ms)
		return HS_FAIL(h, WR_E_AUTH_TICKET_EXPIRED, "no usable OSD ticket", t->have, t->valid_until_ms,
			       c->x->now.mono_ms);
	if (c->global_id == 0)
		return HS_FAIL(h, WR_E_AUTH_GID0, "no global id to present to the OSD", 0, 0, 0);
	st = wri_random(c->x, rnd, sizeof(rnd));
	if (st != WR_OK)
		return HS_FAIL(h, st, "no random for the authorizer nonce", 0, 0, 0);
	h->authorizer_nonce = wri_le64_get(rnd);
	wri_secure_zero(rnd, sizeof(rnd));
	h->osd_gen = t->gen;
	st = wri_cx_put_authorizer(c, WRI_CX_SERVICE_OSD, t, h->authorizer_nonce, 0, 0, out);
	if (st != WR_OK)
		return HS_FAIL(h, st, "authorizer could not be built", 0, 0, 0);
	h->st = WRI_CX_OSD_SENT_AUTHORIZER;
	return WR_OK;
}

wr_status wri_cx_hs_do_begin(wri_cx_hs *h, uint8_t target_type, wri_wr *out)
{
	wr_status st;

	if (h == NULL || h->cl == NULL || h->cl->x == NULL || out == NULL)
		return WR_E_INVAL;
	/* A new connection in this slot: forget the slot's previous handshake (tickets and the global id stay,
	 * and so does every other slot). */
	WR_MEMSET(&h->err, 0, sizeof(h->err));
	h->st = WRI_CX_IDLE;
	h->target_type = target_type;
	hs_scrub(h);
	if (target_type == WRI_ENTITY_MON)
		st = hs_begin_mon(h, out);
	else if (target_type == WRI_ENTITY_OSD)
		st = hs_begin_osd(h, out);
	else
		st = HS_FAIL(h, WR_E_INVAL, "cephx connects to monitors and OSDs only", target_type, 0, 0);
	if (st != WR_OK) {
		hs_scrub(h);
		h->st = WRI_CX_FAILED;
	}
	return st;
}

/* ---- more ----------------------------------------------------------------------------------------- */

static wr_status hs_more_mon(wri_cx_hs *h, const uint8_t *reply, size_t n, wri_wr *out)
{
	wri_cx_client *c = h->cl;
	const wri_cx_ticket *old = &c->ticket[WRI_CX_SLOT_AUTH];
	uint8_t rnd[8] = {0};
	uint64_t proof = 0;
	wri_rd r;
	wr_status st;

	if (h->st != WRI_CX_MON_SENT_REQ)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "unexpected AUTH_REPLY_MORE", h->st, 0, 0);
	/* other_keys is want_mask and must not be 0: a monitor sends no connection secret then (sec.md 2.5). */
	if (c->want_mask == 0)
		return HS_FAIL(h, WR_E_INVAL, "no service ticket requested (other_keys would be 0)", 0, 0, 0);
	wri_rd_init(&r, reply, n);
	(void)wri_rd_u8(&r); /* struct version */
	h->server_challenge = wri_rd_u64(&r);
	if (!wri_rd_ok(&r))
		return HS_FAIL(h, r.err, "server challenge truncated", n, 0, 0);
	if (h->server_challenge == 0)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "server challenge is zero", 0, 0, 0);
	st = wri_random(c->x, rnd, sizeof(rnd));
	if (st != WR_OK)
		return HS_FAIL(h, st, "no random for the client challenge", 0, 0, 0);
	h->client_challenge = wri_le64_get(rnd);
	wri_secure_zero(rnd, sizeof(rnd));
	st = wri_cx_challenge_proof(c->x, &c->principal, h->server_challenge, h->client_challenge, &proof);
	if (st != WR_OK)
		return HS_FAIL(h, st, "challenge proof failed", c->principal.type, 0, 0);
	if (!h->req_new_gid && !old->have)
		return HS_FAIL(h, WR_E_STATE, "old ticket dropped during the handshake", 0, 0, 0);

	wri_wr_u16(out, (uint16_t)WRI_CX_REQ_GET_AUTH_SESSION_KEY);
	wri_wr_u8(out, (uint8_t)CX_AUTHENTICATE_V);
	wri_wr_u64(out, h->client_challenge);
	wri_wr_u64(out, proof);
	if (h->req_new_gid) { /* empty CephXTicketBlob: v 1, secret_id 0, no data */
		wri_wr_u8(out, 1u);
		wri_wr_u64(out, 0);
		wri_wr_u32(out, 0);
	} else {
		wri_wr_bytes(out, old->blob, old->blob_len);
	}
	wri_wr_u32(out, c->want_mask);
	if (!wri_wr_ok(out))
		return HS_FAIL(h, out->err, "AUTH_REQUEST_MORE payload does not fit", 0, 0, 0);
	h->st = WRI_CX_MON_SENT_AUTH;
	return WR_OK;
}

static wr_status hs_more_osd(wri_cx_hs *h, const uint8_t *reply, size_t n, wri_wr *out)
{
	wri_cx_client *c = h->cl;
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	const uint8_t *item = NULL;
	size_t ilen = 0;
	wri_rd r;
	uint64_t chal;
	wr_status st;

	if (h->st != WRI_CX_OSD_SENT_AUTHORIZER)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "unexpected AUTH_REPLY_MORE", h->st, 0, 0);
	if (!t->have || t->gen != h->osd_gen)
		return HS_FAIL(h, WR_E_STATE, "OSD ticket replaced during the handshake", 0, 0, 0);
	st = wri_cx_open(c->x, &t->session_key, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, reply, n, c->scratch, c->scratch_cap,
			 &item, &ilen);
	if (st != WR_OK)
		return HS_FAIL(h, WR_E_AUTH_DECRYPT, "authorizer challenge does not decrypt", (uint64_t)(-(int64_t)st), n,
			       0);
	wri_rd_init(&r, item, ilen);
	(void)wri_rd_u8(&r);
	chal = wri_rd_u64(&r);
	if (!wri_rd_ok(&r)) {
		st = HS_FAIL(h, r.err, "authorizer challenge truncated", ilen, 0, 0);
	} else {
		h->server_challenge = chal;
		st = wri_cx_put_authorizer(c, WRI_CX_SERVICE_OSD, t, h->authorizer_nonce, 1, chal + 1u, out);
		if (st != WR_OK)
			st = HS_FAIL(h, st, "second authorizer could not be built", 0, 0, 0);
	}
	wri_secure_zero(c->scratch, c->scratch_cap);
	if (st == WR_OK)
		h->st = WRI_CX_OSD_SENT_CHALLENGE;
	return st;
}

wr_status wri_cx_hs_do_more(wri_cx_hs *h, const uint8_t *reply, size_t n, wri_wr *out)
{
	wr_status st;

	if (h == NULL || h->cl == NULL || h->cl->x == NULL || out == NULL || (reply == NULL && n != 0))
		return WR_E_INVAL;
	if (h->target_type == WRI_ENTITY_MON)
		st = hs_more_mon(h, reply, n, out);
	else if (h->target_type == WRI_ENTITY_OSD)
		st = hs_more_osd(h, reply, n, out);
	else
		st = HS_FAIL(h, WR_E_AUTH_PROTO, "AUTH_REPLY_MORE before begin", 0, 0, 0);
	if (st != WR_OK) {
		hs_scrub(h);
		h->st = WRI_CX_FAILED;
	}
	return st;
}

/* ---- done ----------------------------------------------------------------------------------------- */

/* The ticket store records failures in the client's err (shared with renewal); a slot must not write that: run the
 * call against a clean err, move what it recorded into the slot, put the client's err back. */
static wr_status hs_ticket_reply(wri_cx_hs *h, wri_rd *r, unsigned kind, uint32_t *stored)
{
	wri_cx_client *c = h->cl;
	wr_errinfo saved = c->err;
	wr_status st;

	WR_MEMSET(&c->err, 0, sizeof(c->err));
	st = wri_cx_ticket_reply(c, r, kind, stored);
	if (st != WR_OK) {
		if (h->err.status == WR_OK && c->err.status != WR_OK)
			h->err = c->err;
		(void)HS_FAIL(h, st, "ticket reply refused", 0, 0, 0); /* no-op when the store said why */
	}
	c->err = saved;
	return st;
}

/* `cbl`: u32 inner_len | sealed (string connection_secret), usage 0x03 under the AUTH session key. */
static wr_status hs_open_cbl(wri_cx_hs *h, const uint8_t *cbl, size_t n, uint32_t mode)
{
	wri_cx_client *c = h->cl;
	const uint8_t *item = NULL, *ct, *sbytes;
	size_t ilen = 0;
	wri_rd r, ri;
	uint32_t inner, slen;
	wr_status st = WR_OK;

	wri_rd_init(&r, cbl, n);
	inner = wri_rd_u32(&r);
	ct = wri_rd_bytes(&r, inner);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "connection secret blob malformed", n, inner, 0);
	st = wri_cx_open(c->x, &c->ticket[WRI_CX_SLOT_AUTH].session_key, WRI_CX_USAGE_CONN_SECRET, ct, inner,
			 c->scratch, c->scratch_cap, &item, &ilen);
	if (st != WR_OK)
		return HS_FAIL(h, WR_E_AUTH_DECRYPT, "connection secret does not decrypt", (uint64_t)(-(int64_t)st),
			       inner, 0);
	wri_rd_init(&ri, item, ilen);
	slen = wri_rd_u32(&ri);
	sbytes = wri_rd_ok(&ri) && slen <= wri_rd_left(&ri) ? wri_rd_bytes(&ri, slen) : NULL;
	if (sbytes == NULL)
		st = HS_FAIL(h, WR_E_AUTH_PROTO, "connection secret malformed", ilen, slen, 0);
	else
		st = wri_cx_hs_take_secret(h, mode, sbytes, slen);
	wri_secure_zero(c->scratch, c->scratch_cap); /* the plaintext item held the secret */
	return st;
}

static wr_status hs_done_mon_body(wri_cx_hs *h, uint64_t gid, uint32_t mode, const uint8_t *payload, size_t n)
{
	wri_cx_client *c = h->cl;
	wri_rd r, sub;
	uint32_t stored = 0, more = 0, cbl_n = 0, extra_n = 0, svc;
	const uint8_t *cbl = NULL, *extra = NULL; /* absent: a reply that stops after the AUTH ticket */
	uint64_t prev_gid = c->global_id;
	unsigned slot;
	uint16_t rtype;
	int32_t rstatus;
	wr_status st;

	if (h->st != WRI_CX_MON_SENT_AUTH)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "unexpected AUTH_DONE", h->st, 0, 0);
	if (mode != WRI_CONN_MODE_CRC && mode != WRI_CONN_MODE_SECURE)
		return HS_FAIL(h, WR_E_M2_MODE, "connection mode is neither crc nor secure", mode, 0, 0);
	if (gid == 0)
		return HS_FAIL(h, WR_E_AUTH_GID0, "server assigned global id 0", 0, 0, 0);
	if ((gid >> 63) != 0) /* CLIENT_IDENT carries it as int64, where -1 means "none" */
		return HS_FAIL(h, WR_E_AUTH_PROTO, "server assigned a global id above 2^63", gid, 0, 0);

	wri_rd_init(&r, payload, n);
	rtype = wri_rd_u16(&r);
	rstatus = wri_rd_i32(&r);
	if (!wri_rd_ok(&r))
		return HS_FAIL(h, r.err, "response header truncated", n, 0, 0);
	if (rtype != WRI_CX_REQ_GET_AUTH_SESSION_KEY)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "response is not for GET_AUTH_SESSION_KEY", rtype, 0, 0);
	if (rstatus != 0) {
		st = HS_FAIL(h, WR_E_AUTH_RESULT, "server reported an error status", (uint64_t)(int64_t)rstatus, 0, 0);
		if (h->err.status == WR_E_AUTH_RESULT)
			h->err.peer_result = rstatus;
		return st;
	}
	st = hs_ticket_reply(h, &r, WRI_CX_TR_INITIAL, &stored);
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
			return HS_FAIL(h, r.err, "connection secret / extra tickets truncated", n, r.pos, 0);
	}
	/* The secret comes first on the wire and is judged first. Secure mode needs one: with no cbl, an empty cbl or
	 * an empty string in it the connection cannot be keyed (the reference client aborts later, sec.md 2.5). */
	if (cbl_n != 0) {
		st = hs_open_cbl(h, cbl, cbl_n, mode);
		if (st != WR_OK)
			return st;
	}
	if (mode == WRI_CONN_MODE_SECURE && h->sec.len == 0)
		return HS_FAIL(h, WR_E_M2_SECRET, "secure mode without a connection secret", 0, 0, 0);
	if (extra_n != 0) {
		wri_rd_init(&sub, extra, extra_n);
		st = hs_ticket_reply(h, &sub, WRI_CX_TR_SERVICES, &more);
		stored |= more;
		if (st != WR_OK)
			return st;
	}
	/* Every ticket we asked for and keep must be held afterwards (the reference client fails the same way); "held"
	 * means unexpired: an old OSD ticket that outlived its validity must not make the handshake look complete. */
	for (slot = 0; slot < WRI_CX_NTICKETS; slot++) {
		svc = slot == WRI_CX_SLOT_AUTH ? WRI_CX_SERVICE_AUTH : WRI_CX_SERVICE_OSD;
		if ((c->want_mask & svc) != 0 && !wri_cx_have(c, svc, c->x->now.mono_ms))
			return HS_FAIL(h, WR_E_AUTH_PROTO, "a requested ticket is missing from the reply", svc,
				       c->want_mask, stored);
	}
	c->global_id = gid;
	h->gid = gid;
	h->key_gen = c->ticket[WRI_CX_SLOT_AUTH].gen;
	h->sess_key = c->ticket[WRI_CX_SLOT_AUTH].session_key.secret;
	h->sess_key_len = c->ticket[WRI_CX_SLOT_AUTH].session_key.len;
	return WR_OK;
}

static wr_status hs_done_osd_body(wri_cx_hs *h, uint32_t mode, const uint8_t *payload, size_t n)
{
	wri_cx_client *c = h->cl;
	const wri_cx_ticket *t = &c->ticket[WRI_CX_SLOT_OSD];
	const uint8_t *item = NULL, *ct, *sbytes = NULL;
	size_t ilen = 0;
	wri_rd r, ri;
	uint32_t clen, slen = 0;
	uint8_t v;
	uint64_t npo;
	wr_status st;

	if (h->st != WRI_CX_OSD_SENT_CHALLENGE)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "unexpected AUTH_DONE", h->st, 0, 0);
	if (mode != WRI_CONN_MODE_CRC && mode != WRI_CONN_MODE_SECURE)
		return HS_FAIL(h, WR_E_M2_MODE, "connection mode is neither crc nor secure", mode, 0, 0);
	if (!t->have || t->gen != h->osd_gen)
		return HS_FAIL(h, WR_E_STATE, "OSD ticket replaced during the handshake", 0, 0, 0);
	wri_rd_init(&r, payload, n);
	clen = wri_rd_u32(&r);
	ct = wri_rd_bytes(&r, clen);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0)
		return HS_FAIL(h, WR_E_AUTH_PROTO, "authorizer reply malformed", n, clen, 0);
	st = wri_cx_open(c->x, &t->session_key, WRI_CX_USAGE_AUTHORIZE_REPLY, ct, clen, c->scratch, c->scratch_cap,
			 &item, &ilen);
	if (st != WR_OK)
		return HS_FAIL(h, WR_E_AUTH_DECRYPT, "authorizer reply does not decrypt", (uint64_t)(-(int64_t)st), clen,
			       0);
	wri_rd_init(&ri, item, ilen);
	v = wri_rd_u8(&ri);
	npo = wri_rd_u64(&ri);
	if (v >= 2u) { /* version 2 carries the connection secret (version 1 has none) */
		slen = wri_rd_u32(&ri);
		sbytes = wri_rd_bytes(&ri, slen);
	}
	if (!wri_rd_ok(&ri))
		st = HS_FAIL(h, ri.err, "authorizer reply truncated", ilen, 0, 0);
	else if (npo != h->authorizer_nonce + 1u)
		st = HS_FAIL(h, WR_E_AUTH_DECRYPT, "authorizer reply answers a different nonce", 0, 0, 0);
	else
		st = wri_cx_hs_take_secret(h, mode, sbytes, slen);
	wri_secure_zero(c->scratch, c->scratch_cap); /* the plaintext item held the secret */
	if (st == WR_OK) {
		h->authorizer_nonce = 0;
		h->gid = c->global_id; /* the id the authorizer carried: the ticket (checked above) was not replaced since begin */
		h->key_gen = t->gen;
		h->sess_key = t->session_key.secret;
		h->sess_key_len = t->session_key.len;
	}
	return st;
}

wr_status wri_cx_hs_do_done(wri_cx_hs *h, uint64_t global_id, uint32_t mode, const uint8_t *payload, size_t n)
{
	wr_status st;

	if (h == NULL || h->cl == NULL || h->cl->x == NULL || (payload == NULL && n != 0))
		return WR_E_INVAL;
	if (h->target_type == WRI_ENTITY_MON) {
		st = hs_done_mon_body(h, global_id, mode, payload, n);
		if (st != WR_OK) {
			wri_cx_forget(h->cl); /* never reuse half a reply; the next attempt starts clean */
			h->req_new_gid = 0;   /* as the forget of the embedded handshake leaves it */
		}
	} else if (h->target_type == WRI_ENTITY_OSD) {
		st = hs_done_osd_body(h, mode, payload, n);
		(void)global_id; /* the OSD echoes our own id; the reference client ignores it too */
	} else {
		st = HS_FAIL(h, WR_E_AUTH_PROTO, "AUTH_DONE before begin", 0, 0, 0);
	}
	if (st != WR_OK) {
		hs_scrub(h);
		h->st = WRI_CX_FAILED;
	} else {
		h->st = WRI_CX_DONE;
	}
	return st;
}

void wri_cx_hs_do_session_key(const wri_cx_hs *h, const uint8_t **key, size_t *len)
{
	if (key == NULL || len == NULL)
		return;
	/* The view points into the ticket store, which other handshakes and renewals rewrite in place: it is
	 * handed out only while the ticket it points into is still the one the handshake ended with. */
	if (h != NULL && h->cl != NULL && h->st == WRI_CX_DONE && h->sess_key != NULL) {
		const wri_cx_ticket *t = &h->cl->ticket[h->target_type == WRI_ENTITY_MON ? WRI_CX_SLOT_AUTH : WRI_CX_SLOT_OSD];

		if (t->have && t->gen == h->key_gen && h->sess_key == t->session_key.secret) {
			*key = h->sess_key;
			*len = h->sess_key_len;
			return;
		}
	}
	*key = NULL;
	*len = 0;
}

int64_t wri_cx_hs_do_ident_gid(const wri_cx_hs *h, uint8_t target_type)
{
	if (h == NULL || h->cl == NULL || h->st != WRI_CX_DONE)
		return -1;
	if (target_type == WRI_ENTITY_MON && h->req_new_gid)
		return -1;
	return (int64_t)h->gid; /* the slot's own copy: a forget or a new id in the client does not reach it */
}
