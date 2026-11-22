/* SPDX-License-Identifier: MIT */
/*
 * wri_m2_conn_hs.c - the handshake half of a msgr2 client connection: from the peer's banner to
 * SERVER_IDENT (docs/spec/msgr2.md 3.1 to 3.6, architecture doc 8.1).
 *
 * Rules every handler here follows (see the handler contract in wri_m2_conn.h):
 *   - decode and check first, change state last; a handler that returns WR_E_BUSY has changed nothing,
 *     so the same frame can be handled again once the transmit queue has room;
 *   - the two steps that cannot be repeated (auth->more() and auth->done()) only run after the room
 *     for the answer is known; frames that carry an authentication payload are built in place in the
 *     upper part of the (then empty) encode buffer and copied once into the queue;
 *   - the pre-auth transcripts are stopped before our AUTH_SIGNATURE is built, the signature the
 *     server must send is computed at that moment (the key is never kept), and both transcripts are
 *     wiped as soon as the server's signature has been compared in constant time.
 *   - secure mode (34.4): AUTH_DONE is the last plaintext frame. A secure answer switches the codec at once
 *     (wri_m2c_sec_switch), before our AUTH_SIGNATURE is built, so the signatures and everything after them
 *     are sealed; the room checks of the frames sent after the switch use the secure frame size.
 */
#include "wri_m2_conn.h"
#include "wri_m2_modes.h"
#include "wri_misc.h"

WR_FILE_LICENCE_MIT

#define CLIENT_FEATURES 0x3f07fffffffdffffull  /* CEPH_FEATURES_ALL of the reference release (msgr2.md 4.4) */
#define CLIENT_REQUIRED 0x0800000000000000ull  /* MSG_ADDR2 */
#define CLIENT_FLAG_LOSSY 1u
#define FRAME_FIXED (WRI_M2_PREAMBLE_LEN + WRI_M2_CRC_LEN) /* a single-segment frame minus its payload */
#define SIG_PAYLOAD 32u
#define IDENT_PAYLOAD_MAX 160u /* IPv6 CLIENT_IDENT: 52 + 47 + 5 * 8 + 8 */
#define HELLO_FRAME_MAX (FRAME_FIXED + 1u + WRI_EADDR_MAX_WIRE)

#define FAIL(x, c, st, what, a0, a1, a2) \
	(WRI_M2C_FAIL((x), (c), (st), (what), (a0), (a1), (a2)), (st))
#define FAIL0(x, c, st, what) FAIL((x), (c), (st), (what), 0, 0, 0)

/* The decoders keep large structures on the stack (SERVER_IDENT: eight addresses); the handlers must not be
 * folded into one another or the frame of the dispatcher adds them up (the core builds with a 1 KiB frame
 * limit). */
#if defined(__GNUC__) || defined(__clang__)
#define HS_NOINLINE __attribute__((noinline))
#else
#define HS_NOINLINE
#endif

/* ---- scratch for payloads that are built in place ----------------------------------------- */

/*
 * The upper half of the encode buffer, usable only while the queue is empty (then the whole buffer is
 * free). A frame of payload length n occupies 36 + n bytes from the start of the buffer; the scratch
 * starts at cap - half with half = (cap - 36) / 2, so for n <= half the frame ends before the scratch
 * starts and the copy never overlaps its source. WR_E_BUSY while output is pending.
 */
static wr_status scratch_get(const wri_m2_conn *c, uint8_t **p, uint32_t *cap)
{
	uint32_t half;

	if (c->tx.buf == NULL || c->tx.pending != 0 || c->tx.used != 0 || c->tx.niov != 0)
		return WR_E_BUSY;
	if (c->tx.cap <= FRAME_FIXED + 16u)
		return WR_E_TOOBIG;
	half = (c->tx.cap - FRAME_FIXED) / 2u;
	*p = c->tx.buf + (c->tx.cap - half);
	*cap = half;
	return WR_OK;
}

/* Send the frame whose payload sits at sp[0..n) and wipe the scratch. */
static wr_status scratch_send(const wri_ctx *x, wri_m2_conn *c, uint8_t tag, uint8_t *sp, uint32_t n)
{
	wr_status st = wri_m2c_send(x, c, tag, sp, n);

	wri_secure_zero(sp, n);
	return st;
}

/* ---- banner and HELLO --------------------------------------------------------------------- */

wr_status wri_m2c_hs_banner(const wri_ctx *x, wri_m2_conn *c)
{
	wri_m2_hello h;
	wri_wr w;
	uint8_t b[1u + WRI_EADDR_MAX_WIRE];
	wr_status st;

	if (c->state != WRI_M2_BANNER)
		return FAIL(x, c, WR_E_M2_STATE, "banner in the wrong state", c->state, 0, 0);
	st = wri_m2c_need_room(x, c, HELLO_FRAME_MAX);
	if (st != WR_OK)
		return st;
	h.entity_type = WRI_ENTITY_CLIENT;
	h.peer_addr = c->target;
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_hello_encode(&w, &h);
	if (!wri_wr_ok(&w))
		return FAIL0(x, c, w.err, "HELLO does not encode");
	st = wri_m2c_send(x, c, WRI_M2_TAG_HELLO, b, (uint32_t)wri_wr_len(&w));
	if (st == WR_E_BUSY)
		return st;
	if (st != WR_OK)
		return FAIL0(x, c, st, "HELLO could not be queued");
	c->revision1 = 1; /* the parser only reports a banner that advertises REVISION_1 */
	c->state = WRI_M2_HELLO;
	return WR_OK;
}

HS_NOINLINE static wr_status send_auth_request(const wri_ctx *x, wri_m2_conn *c)
{
	wri_wr w;
	uint8_t *sp = NULL;
	uint32_t scap = 0, modes[2];
	size_t plen = 0, nmodes, hdr, i;
	wr_status st = scratch_get(c, &sp, &scap);

	if (st == WR_E_BUSY)
		return st;
	if (st != WR_OK)
		return FAIL(x, c, st, "transmit buffer too small for AUTH_REQUEST", c->tx.cap, 0, 0);
	nmodes = wri_m2_offer_list(wri_m2c_offer(c), modes); /* the preferred modes, in our order of preference: crc only unless the slot says more */
	wri_wr_init(&w, sp, scap);
	wri_wr_u32(&w, WRI_AUTH_METHOD_CEPHX);
	wri_wr_u32(&w, (uint32_t)nmodes);
	for (i = 0; i < nmodes; i++)
		wri_wr_u32(&w, modes[i]);
	wri_wr_u32(&w, 0); /* payload length, patched below */
	hdr = wri_wr_len(&w);
	st = c->auth->begin(c->auth_ctx, c->role, &w);
	if (st == WR_OK && !wri_wr_ok(&w))
		st = w.err;
	if (st == WR_OK) {
		plen = wri_wr_len(&w) - hdr;
		if (plen > WRI_M2_AUTH_BLOB_MAX)
			st = WR_E_TOOBIG;
	}
	if (st != WR_OK) {
		wri_secure_zero(sp, wri_wr_len(&w));
		return FAIL(x, c, st, "authentication request could not be built", c->role, 0, 0);
	}
	wri_wr_patch_u32(&w, hdr - 4u, (uint32_t)plen);
	st = scratch_send(x, c, WRI_M2_TAG_AUTH_REQUEST, sp, (uint32_t)wri_wr_len(&w));
	if (st != WR_OK)
		return FAIL0(x, c, st, "AUTH_REQUEST could not be queued");
	c->state = WRI_M2_AUTH;
	return WR_OK;
}

HS_NOINLINE static wr_status on_hello(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	wri_m2_hello h;
	wr_status st = wri_m2_hello_decode(r, &h);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed HELLO");
	if (h.entity_type != c->role)
		return FAIL(x, c, WR_E_M2_HELLO, "peer entity type is not the one dialled", c->role, h.entity_type, 0);
	if (h.peer_addr.family != WR_AF_IPV4 && h.peer_addr.family != WR_AF_IPV6)
		return FAIL(x, c, WR_E_M2_HELLO, "HELLO does not tell us our address", h.peer_addr.family, 0, 0);
	c->my_family = h.peer_addr.family;
	WR_MEMCPY(c->my_ip, h.peer_addr.ip, sizeof(c->my_ip));
	return send_auth_request(x, c);
}

/* ---- authentication ----------------------------------------------------------------------- */

HS_NOINLINE static wr_status on_reply_more(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	const uint8_t *reply = NULL;
	uint32_t rlen = 0, scap = 0;
	uint8_t *sp = NULL;
	wri_wr w;
	wr_status st;

	if (c->auth_rounds >= WRI_M2C_AUTH_ROUNDS)
		return FAIL(x, c, WR_E_M2_STATE, "too many AUTH_REPLY_MORE rounds", c->auth_rounds, 0, 0);
	st = wri_m2_auth_more_decode(r, &reply, &rlen);
	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed AUTH_REPLY_MORE");
	st = scratch_get(c, &sp, &scap);
	if (st == WR_E_BUSY)
		return st;
	if (st != WR_OK)
		return FAIL(x, c, st, "transmit buffer too small for AUTH_REQUEST_MORE", c->tx.cap, 0, 0);
	c->auth_rounds++;
	wri_wr_init(&w, sp, scap);
	wri_wr_u32(&w, 0); /* payload length, patched below */
	st = c->auth->more(c->auth_ctx, reply, rlen, &w);
	if (st == WR_OK && !wri_wr_ok(&w))
		st = w.err;
	if (st != WR_OK) {
		wri_secure_zero(sp, wri_wr_len(&w));
		return FAIL(x, c, st, "authentication step failed", c->auth_rounds, 0, 0);
	}
	if (wri_wr_len(&w) - 4u > WRI_M2_AUTH_BLOB_MAX) { /* the same cap as for AUTH_REQUEST and for what we accept */
		wri_secure_zero(sp, wri_wr_len(&w));
		return FAIL(x, c, WR_E_TOOBIG, "authentication step failed", c->auth_rounds, wri_wr_len(&w) - 4u, 0);
	}
	wri_wr_patch_u32(&w, 0, (uint32_t)(wri_wr_len(&w) - 4u));
	wri_secure_zero(c->ctl_buf, c->rx.desc.len[0]); /* the server's challenge is spent */
	st = scratch_send(x, c, WRI_M2_TAG_AUTH_REQUEST_MORE, sp, (uint32_t)wri_wr_len(&w));
	if (st != WR_OK)
		return FAIL0(x, c, st, "AUTH_REQUEST_MORE could not be queued");
	return WR_OK;
}

static uint64_t list_mask(const uint32_t *v, uint32_t n)
{
	uint64_t m = 0;
	uint32_t i;

	for (i = 0; i < n; i++)
		if (v[i] < 64u)
			m |= (uint64_t)1 << v[i];
	return m;
}

HS_NOINLINE static wr_status on_bad_method(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	wri_m2_bad_method b;
	wr_status st = wri_m2_bad_method_decode(r, &b);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed AUTH_BAD_METHOD");
	c->err.peer_result = b.result; /* set before the failure is reported to the upper layer */
	return FAIL(x, c, WR_E_M2_BAD_METHOD, "server refused the authentication method or mode",
		    list_mask(b.allowed_methods, b.n_methods), list_mask(b.allowed_modes, b.n_modes), b.method);
}

/* Our AUTH_SIGNATURE out, the server's expected one computed (the key is not kept). In secure mode the codec is already switched on, so the
 * queue seals the frame; the session key is read here, after the switch: reading it is what makes the auth layer forget the secret. */
HS_NOINLINE static wr_status sign_and_send(const wri_ctx *x, wri_m2_conn *c)
{
	const uint8_t *key = NULL;
	size_t klen = 0;
	uint8_t ours[32];
	wr_status st;

	wri_m2_preauth_stop(c->pa); /* neither signature frame may enter a transcript */
	st = c->pa->err;
	if (st != WR_OK) /* (a local copy: failing releases the transcripts) */
		return FAIL(x, c, st, "pre-auth transcript too large", c->pa->cap, c->pa->rx_len, c->pa->tx_len);
	c->auth->session_key(c->auth_ctx, &key, &klen);
	if (key == NULL || klen == 0) /* a signature without a key proves nothing, and we only ever offer cephx */
		return FAIL0(x, c, WR_E_CRYPTO_KEY, "no session key after AUTH_DONE");
	wri_m2_sig_ours(x->host.prim, c->pa, key, klen, ours);
	wri_m2_sig_expected(x->host.prim, c->pa, key, klen, c->sig_want);
	st = wri_m2c_send(x, c, WRI_M2_TAG_AUTH_SIGNATURE, ours, sizeof(ours));
	wri_secure_zero(ours, sizeof(ours));
	if (st != WR_OK)
		return FAIL0(x, c, st, "AUTH_SIGNATURE could not be queued");
	return WR_OK;
}

HS_NOINLINE static wr_status on_auth_done(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	wri_m2_auth_done d;
	int secure;
	wr_status st = wri_m2_auth_done_decode(r, &d);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed AUTH_DONE");
	secure = d.mode == WRI_CONN_MODE_SECURE;
	if (wri_m2c_sec_check_mode(x, c, d.mode) != WR_OK) /* only a mode we offered (the check has failed the connection otherwise) */
		return WR_E_M2_MODE;
	if (secure && (c->auth->conn_secret == NULL || c->sec == NULL))
		return FAIL0(x, c, WR_E_M2_SECRET, "secure mode but the authentication has no connection secret"); /* before done(): nothing was consumed */
	/* our signature is the next frame, in the framing of the mode just chosen (a secure one is at least 96 bytes); the 16 is slack as before */
	st = wri_m2c_need_room(x, c, wri_m2c_frame_bytes(secure, SIG_PAYLOAD) + 16u);
	if (st != WR_OK)
		return st;
	/* from here on nothing is repeated */
	st = c->auth->done(c->auth_ctx, d.global_id, d.mode, d.payload, d.payload_len);
	wri_secure_zero(c->ctl_buf, c->rx.desc.len[0]); /* tickets and the like: not needed any more */
	if (st != WR_OK)
		return FAIL0(x, c, st, "authentication did not complete");
	c->global_id = d.global_id;
	c->mode = (uint8_t)d.mode;
	if (secure) {
		st = wri_m2c_sec_switch(x, c); /* the secret, the release of this frame, the codec; fails the connection itself */
		if (st != WR_OK)
			return st;
	}
	st = sign_and_send(x, c);
	if (st != WR_OK)
		return st;
	c->state = WRI_M2_SIG;
	return WR_OK;
}

/* ---- identification ----------------------------------------------------------------------- */

HS_NOINLINE static wr_status send_client_ident(const wri_ctx *x, wri_m2_conn *c)
{
	wri_m2_client_ident ci;
	wr_addr me;
	wri_wr w;
	uint8_t b[256];
	wr_status st;

	WR_MEMSET(&ci, 0, sizeof(ci));
	WR_MEMSET(&me, 0, sizeof(me));
	me.family = c->my_family;
	WR_MEMCPY(me.ip, c->my_ip, sizeof(me.ip));
	me.port = 0;
	me.nonce = c->my_nonce;
	wri_eaddr_from_wr(&ci.addrs[0], &me, WRI_EADDR_TYPE_ANY);
	ci.target = c->target; /* byte for byte what the map gave us (msgr2.md 3.6) */
	ci.gid = c->auth->ident_gid(c->auth_ctx, c->role);
	ci.global_seq = c->global_seq;
	ci.supported = CLIENT_FEATURES;
	ci.required = CLIENT_REQUIRED;
	ci.flags = CLIENT_FLAG_LOSSY;
	ci.cookie = 0;
	wri_wr_init(&w, b, sizeof(b));
	wri_m2_client_ident_encode(&w, &ci);
	if (!wri_wr_ok(&w))
		return FAIL0(x, c, w.err, "CLIENT_IDENT does not encode");
	st = wri_m2c_send(x, c, WRI_M2_TAG_CLIENT_IDENT, b, (uint32_t)wri_wr_len(&w));
	if (st == WR_E_BUSY)
		return st;
	if (st != WR_OK)
		return FAIL0(x, c, st, "CLIENT_IDENT could not be queued");
	return WR_OK;
}

HS_NOINLINE static wr_status on_signature(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	uint8_t got[32];
	wr_status st = wri_m2_auth_sig_decode(r, got);
	int eq;

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed AUTH_SIGNATURE");
	eq = wri_ct_memeq(c->sig_want, got, sizeof(got));
	wri_secure_zero(got, sizeof(got));
	if (!eq)
		return FAIL0(x, c, WR_E_M2_SIGNATURE, "server signature does not match our transcript");
	st = wri_m2c_need_room(x, c, wri_m2c_frame_bytes(c->tx.sx != NULL, IDENT_PAYLOAD_MAX)); /* BUSY: the comparison is repeatable, nothing was wiped yet */
	if (st != WR_OK)
		return st;
	st = send_client_ident(x, c);
	if (st != WR_OK)
		return st;
	wri_secure_zero(c->sig_want, sizeof(c->sig_want));
	wri_m2_preauth_wipe(c->pa);
	c->pa = NULL; /* the client takes the handshake slot back */
	c->state = WRI_M2_IDENT;
	return WR_OK;
}

HS_NOINLINE static wr_status on_server_ident(const wri_ctx *x, wri_m2_conn *c, wri_rd *r)
{
	wri_m2_server_ident si;
	size_t i;
	int found = 0;
	wr_status st = wri_m2_server_ident_decode(r, &si);

	if (st != WR_OK)
		return FAIL0(x, c, st, "malformed SERVER_IDENT");
	for (i = 0; i < si.n_addrs && !found; i++)
		found = wri_eaddr_equal(&si.addrs[i], &c->target);
	if (!found)
		return FAIL(x, c, WR_E_M2_ADDR, "SERVER_IDENT addresses do not contain the dialled address", si.n_addrs,
			    c->target.port, 0);
	c->peer_gid = si.gid;
	c->features = si.supported & CLIENT_FEATURES;
	c->server_flags = si.flags;
	c->server_cookie = si.cookie;
	c->deadline_ms = WR_DEADLINE_NONE;
	c->state = WRI_M2_READY;
	WRI_LOG(x, WR_LOG_INFO, WR_MOD_M2, c->id, WR_OK, "msgr2 session ready", c->role, (uint64_t)si.gid, si.flags, c->mode);
	c->up->ready(c->up_ctx, c);
	return WR_OK;
}

wr_status wri_m2c_hs_frame(const wri_ctx *x, wri_m2_conn *c)
{
	wri_rd r;
	uint64_t v = 0;
	wr_status st;

	/* segment 0 is exactly the control payload (rev-1 crc mode has no padding) */
	wri_rd_init(&r, c->ctl_buf, c->rx.desc.len[0]);
	switch (c->rx.desc.tag) {
	case WRI_M2_TAG_HELLO:
		return on_hello(x, c, &r);
	case WRI_M2_TAG_AUTH_REPLY_MORE:
		return on_reply_more(x, c, &r);
	case WRI_M2_TAG_AUTH_BAD_METHOD:
		return on_bad_method(x, c, &r);
	case WRI_M2_TAG_AUTH_DONE:
		return on_auth_done(x, c, &r);
	case WRI_M2_TAG_AUTH_SIGNATURE:
		return on_signature(x, c, &r);
	case WRI_M2_TAG_SERVER_IDENT:
		return on_server_ident(x, c, &r);
	case WRI_M2_TAG_IDENT_MISSING_FEATURES:
		st = wri_m2_u64_decode(&r, &v);
		if (st != WR_OK)
			return FAIL0(x, c, st, "malformed IDENT_MISSING_FEATURES");
		return FAIL(x, c, WR_E_M2_MISSING_FEATURES, "server requires features we do not advertise", v,
			    CLIENT_FEATURES, 0);
	case WRI_M2_TAG_WAIT:
		return FAIL0(x, c, WR_E_M2_WAIT, "server asked us to wait (connection race)");
	default:
		return FAIL(x, c, WR_E_M2_STATE, "frame not allowed in this state", c->state, c->rx.desc.tag, 0);
	}
}
