/* SPDX-License-Identifier: MIT */
/*
 * sim_m2_hs.c - handshake handlers of the msgr2 test server (HELLO, AUTH_REQUEST / REQUEST_MORE,
 * AUTH_SIGNATURE, COMPRESSION_REQUEST, CLIENT_IDENT) and the scripted auth callback set.
 * See sim_m2.h and docs/spec/msgr2.md 3.1 to 3.5.
 */
#include "sim_m2_int.h"

#include "wri_hash.h"
#include "wri_misc.h"

/* ---- pre-auth signature --------------------------------------------------------------------- */

static void sign(const sim_m2 *s, const uint8_t *log, size_t n, uint8_t out[32])
{
	wr_iov v;

	if (s->key_len == 0) {
		memset(out, 0, 32); /* no session key: 32 zero bytes (msgr2.md 3.3) */
		return;
	}
	v.base = log;
	v.len = n;
	wri_hmac_sha256(s->key, s->key_len, &v, 1, out);
}


/* ---- handshake handlers ------------------------------------------------------------------------ */

static int in_list(const uint32_t *v, uint32_t n, uint32_t x)
{
	uint32_t i;

	for (i = 0; i < n; i++)
		if (v[i] == x)
			return 1;
	return 0;
}

static void on_hello(sim_m2 *s, const uint8_t *p, size_t n)
{
	sr r;
	uint32_t alen = 0;
	const uint8_t *a;
	sw w;
	uint8_t addr[SIM_M2_ADDR4_LEN];

	r.p = p, r.n = n, r.pos = 0, r.bad = 0;
	s->client_hello_type = sr_u8(&r);
	a = sr_addr(&r, &alen);
	if (r.bad || r.pos != n) {
		sim_m2_die(s, WR_E_ENCODING, "sim: malformed HELLO", n, 0);
		return;
	}
	memcpy(s->client_hello_addr, a, alen);
	s->client_hello_addr_len = alen;
	sim_m2_put_addr4(addr, 2, 0, s->cfg.client_ip, s->cfg.client_port);
	w = sim_m2_ctl_writer(s);
	sw_u8(&w, s->cfg.entity_type);
	sw_bytes(&w, addr, sizeof(addr));
	sim_m2_emit_ctl(s, WRI_M2_TAG_HELLO, &w);
	sim_m2_next_state(s, SIM_M2_ST_AUTH);
}

static void answer_bad_method(sim_m2 *s, uint32_t method, const sim_m2_auth_reply *rep)
{
	sw w = sim_m2_ctl_writer(s);
	/* no reply = the server itself refuses the method / mode (-EOPNOTSUPP); a callback verdict without a
	 * result is a failed authentication (-EACCES), as documented in sim_m2.h */
	int32_t result = rep == NULL ? -95 : rep->result != 0 ? rep->result : -13;
	const uint32_t *ms = s->cfg.methods, *md = s->cfg.modes;
	uint32_t nms = s->cfg.n_methods, nmd = s->cfg.n_modes;

	if (rep != NULL && rep->n_methods != 0)
		ms = rep->methods, nms = rep->n_methods;
	if (rep != NULL && rep->n_modes != 0)
		md = rep->modes, nmd = rep->n_modes;
	if (nms > SIM_M2_LIST_MAX || nmd > SIM_M2_LIST_MAX) { /* a callback bug: the arrays hold LIST_MAX entries */
		sim_m2_die(s, WR_E_INVAL, "sim: auth reply list longer than SIM_M2_LIST_MAX", nms, nmd);
		return;
	}
	sw_u32(&w, method);
	sw_u32(&w, (uint32_t)result);
	sw_list(&w, ms, nms);
	sw_list(&w, md, nmd);
	sim_m2_emit_ctl(s, WRI_M2_TAG_AUTH_BAD_METHOD, &w);
	s->await_more = 0;
}

static void apply_auth(sim_m2 *s, int verdict, const sim_m2_auth_reply *rep, uint32_t method)
{
	sw w = sim_m2_ctl_writer(s);

	switch (verdict) {
	case SIM_AUTH_MORE:
		sw_blob(&w, rep->payload, rep->payload != NULL ? rep->payload_len : 0);
		sim_m2_emit_ctl(s, WRI_M2_TAG_AUTH_REPLY_MORE, &w);
		s->await_more = 1;
		break;
	case SIM_AUTH_DONE: {
		uint32_t mode = s->cfg.f.done_mode != 0 ? s->cfg.f.done_mode : rep->mode != 0 ? rep->mode : s->negotiated_mode;

		s->key_len = rep->key_len > SIM_M2_KEY_MAX ? SIM_M2_KEY_MAX : rep->key_len;
		memcpy(s->key, rep->key, s->key_len);
		s->global_id = rep->global_id != 0 ? rep->global_id : s->cfg.global_id;
		s->conn_mode = mode;
		s->await_more = 0;
		sw_u64(&w, s->global_id);
		sw_u32(&w, mode);
		sw_blob(&w, rep->payload, rep->payload != NULL ? rep->payload_len : 0);
		sim_m2_emit_ctl(s, WRI_M2_TAG_AUTH_DONE, &w);
		s->tx_log_on = 0; /* the log of what we sent ends with AUTH_DONE */
		sim_m2_next_state(s, mode == SIM_M2_MODE_CRC ? SIM_M2_ST_SIGNATURE : SIM_M2_ST_REFUSED);
		break;
	}
	case SIM_AUTH_BAD_METHOD:
		answer_bad_method(s, method, rep);
		break;
	case SIM_AUTH_CLOSE:
		s->state = SIM_M2_ST_DEAD;
		s->close_pending = 1;
		break;
	default:
		sim_m2_die(s, WR_E_INVAL, "sim: unknown auth verdict", (uint64_t)verdict, 0);
	}
}

static void on_auth_request(sim_m2 *s, const uint8_t *p, size_t n)
{
	sr r;
	uint32_t method, nm, i, plen, modes[SIM_M2_LIST_MAX];
	const uint8_t *pl;
	sim_m2_auth_reply rep;
	int verdict = SIM_AUTH_DONE;

	r.p = p, r.n = n, r.pos = 0, r.bad = 0;
	method = sr_u32(&r);
	nm = sr_u32(&r);
	if (nm > SIM_M2_LIST_MAX) {
		sim_m2_die(s, WR_E_ENCODING, "sim: too many preferred modes", nm, 0);
		return;
	}
	for (i = 0; i < nm; i++)
		modes[i] = sr_u32(&r);
	plen = sr_u32(&r);
	pl = sr_take(&r, plen);
	if (r.bad || r.pos != n) {
		sim_m2_die(s, WR_E_ENCODING, "sim: malformed AUTH_REQUEST", n, 0);
		return;
	}
	s->auth_method = method;
	memset(&rep, 0, sizeof(rep));
	s->negotiated_mode = 0;
	for (i = 0; i < nm && s->negotiated_mode == 0; i++) /* the first of the client's modes we allow */
		if (in_list(s->cfg.modes, s->cfg.n_modes, modes[i]))
			s->negotiated_mode = modes[i];
	if (!in_list(s->cfg.methods, s->cfg.n_methods, method) || s->negotiated_mode == 0) {
		answer_bad_method(s, method, NULL);
		return;
	}
	if (s->auth.request != NULL)
		verdict = s->auth.request(s->auth.ctx, method, modes, nm, pl, plen, &rep);
	apply_auth(s, verdict, &rep, method);
}

static void on_auth_more(sim_m2 *s, const uint8_t *p, size_t n)
{
	sr r;
	uint32_t plen;
	const uint8_t *pl;
	sim_m2_auth_reply rep;
	int verdict = SIM_AUTH_DONE;

	r.p = p, r.n = n, r.pos = 0, r.bad = 0;
	plen = sr_u32(&r);
	pl = sr_take(&r, plen);
	if (r.bad || r.pos != n || !s->await_more) {
		sim_m2_die(s, r.bad || r.pos != n ? WR_E_ENCODING : WR_E_M2_STATE, "sim: bad AUTH_REQUEST_MORE", n, 0);
		return;
	}
	memset(&rep, 0, sizeof(rep));
	if (s->auth.more != NULL)
		verdict = s->auth.more(s->auth.ctx, pl, plen, &rep);
	apply_auth(s, verdict, &rep, s->auth_method);
}

static void on_signature(sim_m2 *s, const uint8_t *p, size_t n)
{
	uint8_t want[32], ours[32];
	sw w;

	if (n != 32) {
		sim_m2_die(s, WR_E_M2_FRAME_FORM, "sim: AUTH_SIGNATURE is not 32 bytes", n, 0);
		return;
	}
	sign(s, s->tx_log, s->tx_log_len, want);
	if (!wri_ct_memeq(want, p, 32)) { /* a MAC: compared in constant time even in a test server */
		sim_m2_die(s, WR_E_M2_SIGNATURE, "sim: client AUTH_SIGNATURE does not match what we sent", 0, 0);
		return;
	}
	s->rx_log_len = s->frame_start; /* our own signature covers what we received BEFORE the client's */
	s->rx_log_on = 0;
	sign(s, s->rx_log, s->rx_log_len, ours);
	if (s->cfg.f.bad_signature)
		ours[0] ^= 0x01;
	w = sim_m2_ctl_writer(s);
	sw_bytes(&w, ours, 32);
	sim_m2_emit_ctl(s, WRI_M2_TAG_AUTH_SIGNATURE, &w);
	sim_m2_next_state(s, s->expect_compression ? SIM_M2_ST_COMPRESSION : SIM_M2_ST_IDENT);
}

static void on_compression(sim_m2 *s, const uint8_t *p, size_t n)
{
	sr r;
	uint32_t cnt, i;
	sw w;

	r.p = p, r.n = n, r.pos = 0, r.bad = 0;
	(void)sr_u8(&r);
	cnt = sr_u32(&r);
	for (i = 0; i < cnt && !r.bad; i++)
		(void)sr_u32(&r);
	if (r.bad || r.pos != n) {
		sim_m2_die(s, WR_E_ENCODING, "sim: malformed COMPRESSION_REQUEST", n, 0);
		return;
	}
	s->compression_requested = 1;
	w = sim_m2_ctl_writer(s);
	sw_u8(&w, 0); /* is_compress = false */
	sw_u32(&w, 0); /* method none */
	sim_m2_emit_ctl(s, WRI_M2_TAG_COMPRESSION_DONE, &w);
	sim_m2_next_state(s, SIM_M2_ST_IDENT);
}

static int addr_blank(const uint8_t *a, uint32_t len)
{
	uint32_t elen = wri_le32_get(a + 15);

	return wri_le32_get(a + 7) == 0 && wri_le32_get(a + 11) == 0 && (elen == 0 || len < 21 || wri_le16_get(a + 19) == 0);
}

static void on_ident(sim_m2 *s, const uint8_t *p, size_t n)
{
	sr r;
	sim_m2_ident *id = &s->ident;
	uint32_t cnt, i, len, tlen = 0, first_len = 0;
	const uint8_t *a, *t;
	uint8_t me[SIM_M2_ADDR4_LEN], legacy[SIM_M2_ADDR_MAX];
	uint64_t missing;
	sw w;

	r.p = p, r.n = n, r.pos = 0, r.bad = 0;
	memset(id, 0, sizeof(*id));
	if (sr_u8(&r) != 2) { /* addrvec marker */
		sim_m2_die(s, WR_E_ENCODING, "sim: CLIENT_IDENT addrvec marker", 0, 0);
		return;
	}
	cnt = sr_u32(&r);
	if (cnt == 0 || cnt > 2) {
		sim_m2_die(s, WR_E_M2_IDENT, "sim: CLIENT_IDENT addrvec is empty or too long", cnt, 0);
		return;
	}
	for (i = 0; i < cnt && !r.bad; i++) {
		a = sr_addr(&r, &len);
		if (a == NULL)
			break;
		if (i == 0) {
			first_len = len;
			if (addr_blank(a, len)) {
				sim_m2_die(s, WR_E_M2_IDENT, "sim: CLIENT_IDENT first address is blank", 0, 0);
				return;
			}
		}
		memcpy(id->addrs + id->addrs_len, a, len);
		id->addrs_len += len;
	}
	id->n_addrs = cnt;
	t = sr_addr(&r, &tlen);
	id->gid = (int64_t)sr_u64(&r);
	id->global_seq = sr_u64(&r);
	id->supported = sr_u64(&r);
	id->required = sr_u64(&r);
	id->flags = sr_u64(&r);
	id->cookie = sr_u64(&r);
	if (r.bad || r.pos != n || t == NULL || first_len == 0) {
		sim_m2_die(s, WR_E_ENCODING, "sim: malformed CLIENT_IDENT", n, 0);
		return;
	}
	memcpy(id->target, t, tlen);
	id->target_len = tlen;
	sim_m2_put_addr4(me, 2, s->cfg.server_nonce, s->cfg.server_ip, s->cfg.server_port);
	if (s->cfg.check_target && (tlen != sizeof(me) || memcmp(t, me, sizeof(me)) != 0)) {
		sim_m2_die(s, WR_E_M2_ADDR, "sim: CLIENT_IDENT target_addr is not our address", tlen, 0);
		return;
	}
	w = sim_m2_ctl_writer(s);
	if (s->cfg.f.send_wait) {
		sim_m2_emit_ctl(s, WRI_M2_TAG_WAIT, &w); /* one empty segment */
		sim_m2_next_state(s, SIM_M2_ST_REFUSED);
		return;
	}
	missing = s->cfg.f.missing_features != 0 ? s->cfg.f.missing_features : (s->cfg.ident_required & ~id->supported);
	if (missing != 0) {
		sw_u64(&w, missing);
		sim_m2_emit_ctl(s, WRI_M2_TAG_IDENT_MISSING_FEATURES, &w);
		sim_m2_next_state(s, SIM_M2_ST_REFUSED);
		return;
	}
	/* addrs = [the dialled address echoed byte for byte, the same host as a legacy (type 1) address] */
	memcpy(legacy, t, tlen);
	wri_le32_put(legacy + 7, 1);
	if (tlen >= 23)
		wri_be16_put(legacy + 21, s->cfg.legacy_port);
	sw_u8(&w, 2);
	sw_u32(&w, 2);
	sw_bytes(&w, t, tlen);
	sw_bytes(&w, legacy, tlen);
	sw_u64(&w, (uint64_t)s->cfg.server_gid);
	sw_u64(&w, s->cfg.server_global_seq != 0 ? s->cfg.server_global_seq : id->global_seq);
	sw_u64(&w, s->cfg.ident_supported);
	sw_u64(&w, s->cfg.ident_required);
	sw_u64(&w, s->cfg.ident_flags);
	sw_u64(&w, s->cfg.ident_cookie);
	sim_m2_emit_ctl(s, WRI_M2_TAG_SERVER_IDENT, &w);
	sim_m2_next_state(s, SIM_M2_ST_READY);
}

int sim_m2_hs_frame(sim_m2 *s, uint8_t tag, const uint8_t *p, size_t n)
{
	switch (s->state) {
	case SIM_M2_ST_HELLO:
		if (tag == WRI_M2_TAG_HELLO)
			return on_hello(s, p, n), 1;
		break;
	case SIM_M2_ST_AUTH:
		if (tag == WRI_M2_TAG_AUTH_REQUEST)
			return on_auth_request(s, p, n), 1;
		if (tag == WRI_M2_TAG_AUTH_REQUEST_MORE)
			return on_auth_more(s, p, n), 1;
		break;
	case SIM_M2_ST_SIGNATURE:
		if (tag == WRI_M2_TAG_AUTH_SIGNATURE)
			return on_signature(s, p, n), 1;
		break;
	case SIM_M2_ST_COMPRESSION:
		if (tag == WRI_M2_TAG_COMPRESSION_REQUEST)
			return on_compression(s, p, n), 1;
		break;
	case SIM_M2_ST_IDENT:
		if (tag == WRI_M2_TAG_CLIENT_IDENT)
			return on_ident(s, p, n), 1;
		break;
	default:
		break;
	}
	return 0;
}

/* ---- scripted auth callbacks ------------------------------------------------------------------------ */

static int script_finish(sim_m2_auth_script *sc, sim_m2_auth_reply *rep)
{
	if (sc->fail_result != 0) {
		rep->result = sc->fail_result;
		return SIM_AUTH_BAD_METHOD;
	}
	rep->payload = sc->done_payload;
	rep->payload_len = sc->done_len < sizeof(sc->done_payload) ? sc->done_len : (uint32_t)sizeof(sc->done_payload);
	rep->key_len = sc->key_len < SIM_M2_KEY_MAX ? sc->key_len : SIM_M2_KEY_MAX; /* lengths past the arrays are cut */
	memcpy(rep->key, sc->key, rep->key_len);
	rep->mode = sc->mode;
	return SIM_AUTH_DONE;
}

static int script_request(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			  uint32_t n, sim_m2_auth_reply *rep)
{
	sim_m2_auth_script *sc = (sim_m2_auth_script *)ctx;
	uint32_t i;

	sc->n_request++;
	sc->last_method = method;
	sc->last_nmodes = nmodes;
	for (i = 0; i < nmodes && i < SIM_M2_LIST_MAX; i++)
		sc->last_modes[i] = modes[i];
	sc->last_request_len = n;
	memcpy(sc->last_request, p, n < sizeof(sc->last_request) ? n : sizeof(sc->last_request));
	sc->step = 0;
	if (sc->rounds > 0) {
		rep->payload = sc->more_payload;
		rep->payload_len = sc->more_len < sizeof(sc->more_payload) ? sc->more_len : (uint32_t)sizeof(sc->more_payload);
		return SIM_AUTH_MORE;
	}
	return script_finish(sc, rep);
}

static int script_more(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep)
{
	sim_m2_auth_script *sc = (sim_m2_auth_script *)ctx;

	sc->n_more++;
	sc->last_more_len = n;
	memcpy(sc->last_more, p, n < sizeof(sc->last_more) ? n : sizeof(sc->last_more));
	if (++sc->step < sc->rounds) {
		rep->payload = sc->more_payload;
		rep->payload_len = sc->more_len < sizeof(sc->more_payload) ? sc->more_len : (uint32_t)sizeof(sc->more_payload);
		return SIM_AUTH_MORE;
	}
	return script_finish(sc, rep);
}

void sim_m2_auth_script_ops(sim_m2_auth_ops *ops, sim_m2_auth_script *sc)
{
	ops->ctx = sc;
	ops->request = script_request;
	ops->more = script_more;
}

