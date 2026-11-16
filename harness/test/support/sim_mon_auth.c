/* SPDX-License-Identifier: MIT */
/*
 * sim_mon_auth.c - the cephx server side of the fake monitor (docs/spec/cephx.md 2.7, 2.8, 3.2, 3.6, 3.7,
 * 3.8) and the in-session renewal (MAuth / MAuthReply, 2.11, mon-client.md 3.8). It seals and opens with the
 * cipher / envelope layer of the cephx module; every structure around it is encoded here, field by field,
 * from the notes. Test code: libc allowed.
 */
#include "sim_mon_int.h"

#define CX_SERVICES_MASK 0x1fu /* the service ids a ticket is made for besides AUTH (0x20): bits 0..4 */

static const uint32_t k_methods[1] = {2};
static const uint32_t k_modes[2] = {2, 1};

static void deny(sim_mon_conn *c, sim_m2_auth_reply *rep, int32_t result)
{
	memset(rep, 0, sizeof(*rep));
	rep->result = result;
	memcpy(rep->methods, k_methods, sizeof(k_methods));
	rep->n_methods = 1;
	memcpy(rep->modes, k_modes, sizeof(k_modes));
	rep->n_modes = 2;
	c->mon->n_denied++;
	c->stage = 0;
}

/* ---- tickets ------------------------------------------------------------------------------------------ */

static wr_status gen_key(sim_mon *m, const sim_mon_tkt_cfg *tc, unsigned wrap_type, wr_key *out)
{
	unsigned type = tc->key_type != 0 ? tc->key_type : wrap_type;
	uint8_t raw[WR_KEY_MAX];
	size_t len = type == WR_KEY_TYPE_AES ? 16u : type == WR_KEY_TYPE_AES256K ? 32u : 0u;
	wr_status st;

	if (tc->key_len != 0)
		return wr_key_from_raw(out, type, tc->key, tc->key_len);
	if (len == 0)
		return WR_E_AUTH_KEY_TYPE;
	sim_mon_rand(m, raw, len);
	st = wr_key_from_raw(out, type, raw, len);
	wri_secure_zero(raw, sizeof(raw));
	return st;
}

/* u32 length | encrypt(u8 1, magic, item) under (key, usage): the "length-prefixed" shape of cephx.md 2.6 */
static wr_status put_sealed(sim_mon *m, wri_wr *w, const wr_key *k, uint32_t usage, const uint8_t *item, size_t n)
{
	size_t ct_len = wri_cx_cipher_len(k->type, 9u + n), out_n = 0;
	uint8_t *dst;
	wr_status st;

	if (ct_len == 0)
		return WR_E_AUTH_KEY_TYPE;
	dst = wri_wr_reserve(w, 4u + ct_len);
	if (dst == NULL)
		return w->err != WR_OK ? w->err : WR_E_TOOBIG;
	st = wri_cx_seal(sim_mon_ctx(m), k, usage, item, n, dst + 4, ct_len, &out_n);
	if (st == WR_OK && out_n != ct_len)
		st = WR_E_CRYPTO_LEN;
	wri_le32_put(dst, (uint32_t)ct_len);
	return st;
}

/* CephXTicketBlob: u8 v = 1, u64 secret_id, blob data */
static size_t encode_blob(uint8_t *out, uint64_t secret_id, const uint8_t *data, uint32_t len)
{
	out[0] = 1;
	wri_le64_put(out + 1, secret_id);
	wri_le32_put(out + 9, len);
	memcpy(out + 13, data, len);
	return 13u + len;
}

/*
 * One ticket of a ticket reply (cephx.md 2.7): service_id, ticket_v = 1, msg_a = CephXServiceTicket sealed under
 * `wrap` (usage 4), ticket_enc, then the opaque blob: a bufferlist holding a CephXTicketBlob, or, for a reclaim
 * (`prev` != NULL, only used for the AUTH ticket), that bufferlist sealed under the previous AUTH session key
 * (usage 5). Remembers what it handed out in m->last[] and m->ring[].
 */
static wr_status put_ticket_in(sim_mon *m, wri_wr *w, uint32_t service, uint64_t gid, const wr_key *wrap,
			       const sim_mon_issued *prev, sim_mon_issued *ep, uint8_t *item, size_t item_cap)
{
	unsigned slot = sim_mon_slot(service);
	const sim_mon_tkt_cfg *tc;
	sim_mon_issued *e = ep; /* the caller wipes it, on every path */
	uint8_t tb[13 + SIM_MON_BLOB_MAX + 4];
	size_t tb_len;
	wri_wr iw;
	wr_status st;

	if (slot >= SIM_MON_TSLOTS)
		return WR_E_INVAL;
	tc = &m->cfg.tkt[slot];
	memset(e, 0, sizeof(*e));
	e->have = 1;
	e->service = service;
	e->global_id = gid;
	e->gen = m->gen;
	e->secret_id = tc->secret_id != 0 ? tc->secret_id : m->next_secret_id++;
	if (tc->zero_validity) { /* a monitor that hands out a ticket that is already over (cephx.md 3.5: an error for the client) */
		e->validity_s = 0;
		e->validity_ns = 0;
	} else {
		e->validity_s = tc->validity_s != 0 ? tc->validity_s : (service == WRI_CX_SERVICE_AUTH ? 259200u : 3600u);
		e->validity_ns = tc->validity_ns;
	}
	e->blob_len = tc->blob_len != 0 ? tc->blob_len : 151u;
	if (e->blob_len < 16u || e->blob_len > SIM_MON_BLOB_MAX)
		return WR_E_RANGE;
	e->reissued = prev != NULL;
	sim_mon_rand(m, e->blob, e->blob_len);
	st = gen_key(m, tc, wrap->type, &e->key);
	if (st != WR_OK)
		return st;
	/* CephXServiceTicket: u8 v = 1, CryptoKey {u16 type, utime created, u16 len, secret}, utime validity */
	wri_wr_init(&iw, item, item_cap);
	wri_wr_u8(&iw, 1);
	wri_wr_u16(&iw, e->key.type);
	wri_wr_u32(&iw, 1700000000u);
	wri_wr_u32(&iw, 0);
	wri_wr_u16(&iw, e->key.len);
	wri_wr_bytes(&iw, e->key.secret, e->key.len);
	wri_wr_u32(&iw, e->validity_s);
	wri_wr_u32(&iw, e->validity_ns);
	if (!wri_wr_ok(&iw))
		return iw.err;
	wri_wr_u32(w, service);
	wri_wr_u8(w, 1);
	st = put_sealed(m, w, wrap, WRI_CX_USAGE_TICKET_SESSION_KEY, item, wri_wr_len(&iw));
	if (st != WR_OK)
		return st;
	tb_len = encode_blob(tb + 4, e->secret_id, e->blob, e->blob_len);
	wri_le32_put(tb, (uint32_t)tb_len); /* tb now holds a bufferlist: u32 length + the CephXTicketBlob */
	wri_wr_u8(w, prev != NULL ? 1u : 0u);
	if (prev == NULL)
		wri_wr_bytes(w, tb, 4u + tb_len);
	else
		st = put_sealed(m, w, &prev->key, WRI_CX_USAGE_TICKET_BLOB, tb, 4u + tb_len);
	if (st != WR_OK || !wri_wr_ok(w))
		return st != WR_OK ? st : w->err;
	m->ring[m->ring_pos++ % SIM_MON_ISSUED] = *e;
	m->last[slot] = *e;
	return WR_OK;
}

static wr_status put_ticket(sim_mon *m, wri_wr *w, uint32_t service, uint64_t gid, const wr_key *wrap,
			    const sim_mon_issued *prev)
{
	sim_mon_issued e;
	uint8_t item[96]; /* CephXServiceTicket: 1 + 2 + 8 + 2 + at most WR_KEY_MAX + 8 bytes */
	wr_status st = put_ticket_in(m, w, service, gid, wrap, prev, &e, item, sizeof(item));

	wri_secure_zero(&e, sizeof(e)); /* session keys: no copy stays on the stack, whatever the outcome */
	wri_secure_zero(item, sizeof(item));
	return st;
}

/* A ticket reply for the services in `mask` (ascending bit order, AUTH excluded, omit_services removed),
 * every ticket wrapped under `wrap`, ticket_enc = 0. Returns the number of tickets through *n. */
static wr_status put_ticket_reply(sim_mon *m, wri_wr *w, uint32_t mask, uint64_t gid, const wr_key *wrap, uint32_t *n)
{
	uint32_t bit, cnt = 0;
	size_t at;
	wr_status st = WR_OK;

	wri_wr_u8(w, 1); /* reply_v */
	at = wri_wr_len(w);
	wri_wr_u32(w, 0);
	for (bit = 1; bit <= 0x10u && st == WR_OK; bit <<= 1) {
		if ((mask & bit) == 0 || (m->cfg.omit_services & bit) != 0)
			continue;
		st = put_ticket(m, w, bit, gid, wrap, NULL);
		cnt++;
	}
	wri_wr_patch_u32(w, at, cnt);
	*n = cnt;
	return st;
}

static const sim_mon_issued *find_issued(const sim_mon *m, uint32_t service, const uint8_t *blob, size_t n,
					 uint64_t secret_id)
{
	uint32_t i;

	for (i = 0; i < SIM_MON_ISSUED; i++) {
		const sim_mon_issued *e = &m->ring[i];

		if (e->have && e->service == service && e->secret_id == secret_id && e->blob_len == n && n != 0 &&
		    memcmp(e->blob, blob, n) == 0)
			return e;
	}
	return NULL;
}

int sim_mon_ticket_valid(const sim_mon *m, uint32_t service, const uint8_t *blob, size_t n)
{
	uint32_t i;

	for (i = 0; i < SIM_MON_ISSUED; i++) {
		const sim_mon_issued *e = &m->ring[i];

		if (e->have && e->service == service && e->gen == m->gen && e->blob_len == n && n != 0 &&
		    memcmp(e->blob, blob, n) == 0)
			return 1;
	}
	return 0;
}

/* ---- AUTH_REQUEST / AUTH_REQUEST_MORE ------------------------------------------------------------------- */

int sim_mon_auth_request(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p,
			 uint32_t n, sim_m2_auth_reply *rep)
{
	sim_mon_conn *c = (sim_mon_conn *)ctx;
	sim_mon *m = c->mon;
	wri_rd r;
	uint32_t etype, idlen;
	const uint8_t *id;
	uint8_t mode;

	(void)method, (void)modes, (void)nmodes;
	memset(rep, 0, sizeof(*rep));
	if (c->plan.auth == SIM_MON_AUTH_BUSY) { /* no quorum yet: the connection is dropped without a word */
		m->n_busy++;
		return SIM_AUTH_CLOSE;
	}
	if (c->plan.auth == SIM_MON_AUTH_BAD_METHOD) {
		deny(c, rep, c->plan.auth_result != 0 ? c->plan.auth_result : -95);
		return SIM_AUTH_BAD_METHOD;
	}
	c->stage = 0;
	c->bad_entity = 0;
	wri_rd_init(&r, p, n);
	mode = wri_rd_u8(&r);
	etype = wri_rd_u32(&r);
	idlen = wri_rd_u32(&r);
	id = wri_rd_bytes(&r, idlen);
	c->req_global_id = wri_rd_u64(&r);
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0 || id == NULL) {
		deny(c, rep, -1);
		return SIM_AUTH_BAD_METHOD;
	}
	if (mode < 10u || mode > 19u) { /* the monitor accepts 10 to 19 and answers anything else with an access error */
		deny(c, rep, -13);
		return SIM_AUTH_BAD_METHOD;
	}
	/* an unknown entity is not refused yet: the challenge goes out first (cephx.md 3.8) */
	c->bad_entity = etype != 8u || idlen != strlen(m->cfg.user) || memcmp(id, m->cfg.user, idlen) != 0;
	do
		c->server_challenge = sim_mon_rand64(m);
	while (c->server_challenge == 0);
	c->payload[0] = 1; /* CephXServerChallenge: v = 1, u64 */
	wri_le64_put(c->payload + 1, c->server_challenge);
	rep->payload = c->payload;
	rep->payload_len = 9;
	c->stage = 1;
	return SIM_AUTH_MORE;
}

/* AUTH_DONE payload of a CEPHX_GET_AUTH_SESSION_KEY (cephx.md 2.7): response header, the AUTH ticket, and, as the
 * request asked for other keys, the connection-secret blob and `extra`. */
static wr_status build_done(sim_mon_conn *c, uint32_t other, const sim_mon_issued *old, wri_wr *w)
{
	sim_mon *m = c->mon;
	wr_status st;
	uint8_t item[4] = {0, 0, 0, 0}; /* the connection secret as a string: empty in crc mode */
	size_t ct_len;
	uint32_t n;

	wri_wr_u16(w, WRI_CX_REQ_GET_AUTH_SESSION_KEY);
	wri_wr_i32(w, 0);
	wri_wr_u8(w, 1); /* reply_v */
	wri_wr_u32(w, 1);
	st = put_ticket(m, w, WRI_CX_SERVICE_AUTH, c->global_id, &m->cfg.key, old);
	if (st != WR_OK)
		return st;
	wr_key_wipe(&c->auth_key);
	c->auth_key = m->last[sim_mon_slot(WRI_CX_SERVICE_AUTH)].key;
	if (other == 0)
		return w->err;
	ct_len = wri_cx_cipher_len(c->auth_key.type, 9u + sizeof(item));
	wri_wr_u32(w, (uint32_t)(4u + ct_len)); /* cbl: u32 inner length + the ciphertext */
	st = put_sealed(m, w, &c->auth_key, WRI_CX_USAGE_CONN_SECRET, item, sizeof(item));
	if (st != WR_OK)
		return st;
	if ((other & CX_SERVICES_MASK & ~m->cfg.omit_services) == 0) {
		wri_wr_u32(w, 0); /* only AUTH was asked for (or nothing is granted): a zero-length blob, not an empty reply */
	} else {
		wri_wr ew;
		uint8_t *tmp = (uint8_t *)malloc(SIM_MON_PAYLOAD);

		if (tmp == NULL)
			return WR_E_BUDGET;
		wri_wr_init(&ew, tmp, SIM_MON_PAYLOAD);
		st = put_ticket_reply(m, &ew, other & CX_SERVICES_MASK, c->global_id, &c->auth_key, &n);
		if (st == WR_OK && wri_wr_ok(&ew))
			wri_denc_put_blob(w, tmp, wri_wr_len(&ew));
		else if (st == WR_OK)
			st = ew.err;
		free(tmp);
	}
	return st != WR_OK ? st : w->err;
}

int sim_mon_auth_more(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep)
{
	sim_mon_conn *c = (sim_mon_conn *)ctx;
	sim_mon *m = c->mon;
	wri_rd r;
	wri_wr w;
	uint16_t req;
	uint8_t v, tv;
	uint64_t cc, proof, want_proof = 0, osecret;
	int proof_ok;
	uint32_t olen, other = 0;
	const uint8_t *odata;
	const sim_mon_issued *old = NULL;
	wr_status st;

	memset(rep, 0, sizeof(*rep));
	wri_rd_init(&r, p, n);
	req = wri_rd_u16(&r);
	v = wri_rd_u8(&r);
	cc = wri_rd_u64(&r);
	proof = wri_rd_u64(&r);
	tv = wri_rd_u8(&r);
	osecret = wri_rd_u64(&r);
	olen = wri_rd_u32(&r);
	odata = olen <= SIM_MON_BLOB_MAX ? wri_rd_bytes(&r, olen) : NULL;
	if (v >= 2u)
		other = wri_rd_u32(&r);
	(void)tv; /* the ticket blob version is not checked, as for every cephx struct */
	if (c->stage != 1 || !wri_rd_ok(&r) || wri_rd_left(&r) != 0 || odata == NULL || v < 2u ||
	    req != WRI_CX_REQ_GET_AUTH_SESSION_KEY) {
		deny(c, rep, -1); /* a request the monitor cannot decode is -EPERM, not -EACCES */
		return SIM_AUTH_BAD_METHOD;
	}
	if (c->plan.auth == SIM_MON_AUTH_DENY) {
		deny(c, rep, c->plan.auth_result != 0 ? c->plan.auth_result : -13);
		return SIM_AUTH_BAD_METHOD;
	}
	st = wri_cx_challenge_proof(sim_mon_ctx(m), &m->cfg.key, c->server_challenge, cc, &want_proof);
	{
		uint8_t pa[8], pb[8];

		wri_le64_put(pa, proof);
		wri_le64_put(pb, want_proof);
		proof_ok = wri_ct_memeq(pa, pb, sizeof(pa)); /* a proof is compared like a MAC: time independent of the contents */
	}
	if (st != WR_OK || c->bad_entity || (m->cfg.allowed_key_types & (1u << m->cfg.key.type)) == 0 || !proof_ok) {
		deny(c, rep, -13); /* unknown entity, wrong key or a key type the monmap does not allow */
		return SIM_AUTH_BAD_METHOD;
	}
	if (c->req_global_id == 0) {
		if (olen != 0) { /* a superfluous old ticket on a first contact is an error */
			deny(c, rep, -13);
			return SIM_AUTH_BAD_METHOD;
		}
		c->global_id = m->next_gid++;
	} else {
		old = find_issued(m, WRI_CX_SERVICE_AUTH, odata, olen, osecret);
		if (old == NULL || old->global_id != c->req_global_id || old->gen != m->gen) {
			deny(c, rep, -13); /* reclaim without a valid, current AUTH ticket for that id */
			return SIM_AUTH_BAD_METHOD;
		}
		c->global_id = c->req_global_id;
	}
	wri_wr_init(&w, c->payload, SIM_MON_PAYLOAD);
	{
		sim_mon_issued prev;

		memset(&prev, 0, sizeof(prev));
		if (old != NULL)
			prev = *old; /* put_ticket may overwrite the ring slot `old` points into */
		st = build_done(c, other, old != NULL ? &prev : NULL, &w);
		wri_secure_zero(&prev, sizeof(prev));
	}
	if (st != WR_OK || !wri_wr_ok(&w)) {
		if (m->build_err == WR_OK)
			m->build_err = st != WR_OK ? st : w.err;
		return SIM_AUTH_CLOSE;
	}
	rep->payload = c->payload;
	rep->payload_len = (uint32_t)wri_wr_len(&w);
	rep->key_len = c->auth_key.len;
	memcpy(rep->key, c->auth_key.secret, c->auth_key.len);
	rep->global_id = c->global_id;
	c->stage = 2;
	m->n_logins++;
	if (old != NULL)
		m->n_reclaims++;
	return SIM_AUTH_DONE;
}

/* ---- renewal ---------------------------------------------------------------------------------------------- */

static void send_auth_reply(sim_mon_conn *c, int32_t result, const uint8_t *bl, uint32_t bl_len, const char *msg)
{
	sim_mon *m = c->mon;
	size_t need = 4u + 4u + 8u + 4u + bl_len + 4u + strlen(msg);
	uint8_t *buf = sim_mon_scratch(m, need);
	wri_wr w;

	if (buf == NULL)
		return;
	wri_wr_init(&w, buf, need);
	wri_wr_u32(&w, WRI_AUTH_METHOD_CEPHX); /* protocol */
	wri_wr_i32(&w, result);
	wri_wr_u64(&w, c->global_id);
	wri_denc_put_blob(&w, bl, bl_len);
	wri_denc_put_blob(&w, (const uint8_t *)msg, strlen(msg));
	if (wri_wr_ok(&w) && sim_mon_send_message(c, (uint16_t)SIM_MSG_AUTH_REPLY, 1, 1, buf, (uint32_t)wri_wr_len(&w)) == WR_OK)
		c->n_authreply_sent++;
}

static void refuse_renewal(sim_mon_conn *c, int32_t result, const char *why)
{
	c->mon->n_renewals_denied++;
	send_auth_reply(c, result, NULL, 0, why);
}

void sim_mon_on_mauth(sim_mon_conn *c, const uint8_t *front, uint32_t n)
{
	sim_mon *m = c->mon;
	wri_rd r, pr;
	uint32_t protocol, plen, svc, tlen, proof_len, keys, mask, cnt = 0;
	const uint8_t *pl, *tdata, *proof;
	uint64_t secret_id, nonce, plus1;
	uint8_t av, rv, have_chal;
	uint16_t req;
	const sim_mon_issued *tk;
	uint8_t plain[256];
	uint64_t gid;
	const uint8_t *item = NULL;
	size_t item_len = 0;
	wri_rd ir;
	wri_wr w;

	wri_rd_init(&r, front, n);
	wri_rd_skip(&r, 8u + 2u + 8u); /* the PaxosServiceMessage prefix: version, session_mon, session_mon_tid */
	protocol = wri_rd_u32(&r);
	plen = wri_rd_u32(&r);
	pl = plen <= SIM_MON_PAYLOAD ? wri_rd_bytes(&r, plen) : NULL;
	(void)wri_rd_u32(&r); /* monmap_epoch */
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0 || pl == NULL) {
		c->n_malformed++; /* the monitor fails the decode and drops the message */
		return;
	}
	if (protocol != WRI_AUTH_METHOD_CEPHX || c->stage != 2) {
		refuse_renewal(c, -95, "protocol not supported");
		return;
	}
	wri_rd_init(&pr, pl, plen);
	req = wri_rd_u16(&pr);
	/* the authorizer for service AUTH: version, global_id, service_id, the AUTH ticket blob, the proof */
	av = wri_rd_u8(&pr);
	gid = wri_rd_u64(&pr);
	svc = wri_rd_u32(&pr);
	(void)wri_rd_u8(&pr);
	secret_id = wri_rd_u64(&pr);
	tlen = wri_rd_u32(&pr);
	tdata = tlen <= SIM_MON_BLOB_MAX ? wri_rd_bytes(&pr, tlen) : NULL;
	proof_len = wri_rd_u32(&pr);
	proof = proof_len <= 4096u ? wri_rd_bytes(&pr, proof_len) : NULL;
	rv = wri_rd_u8(&pr);
	keys = wri_rd_u32(&pr);
	(void)rv;
	if (!wri_rd_ok(&pr) || wri_rd_left(&pr) != 0 || tdata == NULL || proof == NULL ||
	    req != WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY) {
		refuse_renewal(c, -1, "cannot decode the cephx request");
		return;
	}
	tk = find_issued(m, WRI_CX_SERVICE_AUTH, tdata, tlen, secret_id);
	if (av != WRI_CX_AUTHORIZER_V || svc != WRI_CX_SERVICE_AUTH || gid != c->global_id || tk == NULL ||
	    tk->global_id != c->global_id || tk->gen != m->gen) {
		refuse_renewal(c, -13, "ticket refused");
		return;
	}
	if (wri_cx_open(sim_mon_ctx(m), &c->auth_key, WRI_CX_USAGE_AUTHORIZE, proof, proof_len, plain, sizeof(plain),
			&item, &item_len) != WR_OK) {
		refuse_renewal(c, -13, "authorizer does not decrypt");
		return;
	}
	wri_rd_init(&ir, item, item_len);
	(void)wri_rd_u8(&ir);
	nonce = wri_rd_u64(&ir);
	have_chal = wri_rd_u8(&ir);
	plus1 = wri_rd_u64(&ir);
	(void)nonce, (void)plus1;
	wri_secure_zero(plain, sizeof(plain));
	if (!wri_rd_ok(&ir) || have_chal != 0) { /* no challenge round trip in a renewal */
		refuse_renewal(c, -13, "unexpected challenge in the authorizer");
		return;
	}
	mask = keys & CX_SERVICES_MASK;
	wri_wr_init(&w, c->payload, SIM_MON_PAYLOAD);
	wri_wr_u16(&w, WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY);
	wri_wr_i32(&w, 0);
	if (put_ticket_reply(m, &w, mask, c->global_id, &c->auth_key, &cnt) != WR_OK || !wri_wr_ok(&w)) {
		if (m->build_err == WR_OK)
			m->build_err = WR_E_TOOBIG;
		return;
	}
	m->n_renewals++;
	m->last_renew_mask = mask & ~m->cfg.omit_services;
	send_auth_reply(c, 0, c->payload, (uint32_t)wri_wr_len(&w), "");
}
