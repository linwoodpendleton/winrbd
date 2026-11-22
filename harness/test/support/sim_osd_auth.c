/* SPDX-License-Identifier: MIT */
/*
 * sim_osd_auth.c - the cephx server side of the OSD service (docs/spec/cephx.md 2.7, 3.3, 3.8): the authorizer a client sends in AUTH_REQUEST
 * (u8 1, global id, service 4, the OSD ticket blob, the proof sealed under the ticket's session key), verified against the tickets the
 * monitor of the cluster issued; always one challenge round trip (AUTH_REPLY_MORE with the raw sealed challenge, AUTH_REQUEST_MORE with the
 * same authorizer and the answer, AUTH_DONE with the sealed nonce + 1). A ticket the monitor did not issue, one it no longer accepts (expired),
 * a global id that is not the one the ticket was issued to, a wrong challenge answer: AUTH_BAD_METHOD -13 (methods [2], modes [1, 2]).
 * fault.refuse_auth refuses after the round trip, like a key without OSD caps. Test code: libc allowed.
 */
#include "sim_osd_int.h"

static const uint32_t k_methods[1] = {2};
static const uint32_t k_modes[2] = {1, 2};

static int deny(sim_osd_conn *c, sim_m2_auth_reply *rep, int32_t result)
{
	memset(rep, 0, sizeof(*rep));
	rep->result = result;
	memcpy(rep->methods, k_methods, sizeof(k_methods));
	rep->n_methods = 1;
	memcpy(rep->modes, k_modes, sizeof(k_modes));
	rep->n_modes = 2;
	c->stage = 0;
	return SIM_AUTH_BAD_METHOD;
}

typedef struct so_authz {
	uint64_t gid, secret_id, nonce, plus_one;
	uint32_t service, tlen;
	const uint8_t *tdata;
	uint8_t have_challenge;
	const sim_mon_issued *tk;
	wr_key key;
} so_authz;

/* Decodes the authorizer and checks it against the monitor's tickets; 0 = ok. */
static int authz_parse(sim_osd_conn *c, const uint8_t *p, uint32_t n, so_authz *z)
{
	sim_mon *mon = c->osd->cfg.mon;
	wri_rd r, ir;
	uint8_t av, plain[512];
	uint32_t plen, i;
	const uint8_t *proof, *item = NULL;
	size_t item_len = 0;

	memset(z, 0, sizeof(*z));
	wri_rd_init(&r, p, n);
	av = wri_rd_u8(&r);
	z->gid = wri_rd_u64(&r);
	z->service = wri_rd_u32(&r);
	(void)wri_rd_u8(&r); /* the ticket blob version is not checked, as for every cephx struct */
	z->secret_id = wri_rd_u64(&r);
	z->tlen = wri_rd_u32(&r);
	z->tdata = z->tlen <= 1024u ? wri_rd_bytes(&r, z->tlen) : NULL;
	plen = wri_rd_u32(&r);
	proof = plen <= sizeof(plain) ? wri_rd_bytes(&r, plen) : NULL;
	if (!wri_rd_ok(&r) || wri_rd_left(&r) != 0 || z->tdata == NULL || proof == NULL || av < 1u || av > 9u)
		return -1;
	if (z->service != WRI_CX_SERVICE_OSD)
		return -1;
	for (i = 0; i < SIM_MON_ISSUED; i++) {
		const sim_mon_issued *e = &mon->ring[i];

		if (e->have && e->service == z->service && e->secret_id == z->secret_id && e->gen == mon->gen && e->blob_len == z->tlen &&
		    z->tlen != 0 && memcmp(e->blob, z->tdata, z->tlen) == 0) {
			z->tk = e;
			break;
		}
	}
	if (z->tk == NULL || z->tk->global_id != z->gid)
		return -1;
	z->key = z->tk->key;
	if (wri_cx_open(so_ctx(c->osd), &z->key, WRI_CX_USAGE_AUTHORIZE, proof, plen, plain, sizeof(plain), &item, &item_len) != WR_OK)
		return -1;
	wri_rd_init(&ir, item, item_len);
	(void)wri_rd_u8(&ir); /* CephXAuthorize version */
	z->nonce = wri_rd_u64(&ir);
	z->have_challenge = wri_rd_u8(&ir);
	z->plus_one = wri_rd_u64(&ir);
	wri_secure_zero(plain, sizeof(plain));
	if (!wri_rd_ok(&ir))
		return -1;
	return 0;
}

int so_auth_request(void *ctx, uint32_t method, const uint32_t *modes, uint32_t nmodes, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep)
{
	sim_osd_conn *c = (sim_osd_conn *)ctx;
	so_authz z;
	uint8_t item[9];
	size_t out_n = 0;

	(void)modes, (void)nmodes;
	c->stage = 0;
	/* a seed of its own per connection AND per OSD, and not the monitor's: two daemons that issued the same secret to their first connection
	 * would let a client that mixes up the contexts of two connections go unnoticed (every secret decrypts every connection) */
	sim_m2_sec_setup(c->m2, &c->osd->sec_log,
			 (c->osd->cfg.seed ^ 0x05d5ec12e7c0ffeeull) + ((uint64_t)(uint32_t)c->osd->cfg.id + 1u) * 0xc2b2ae3d27d4eb4full +
				 (uint64_t)(c->index + 1u) * 0x9e3779b97f4a7c15ull);
	if (method != 2u)
		return deny(c, rep, -95);
	if (authz_parse(c, p, n, &z) != 0 || z.have_challenge != 0) { /* a first authorizer carries no challenge answer */
		wri_secure_zero(&z, sizeof(z));
		return deny(c, rep, -13);
	}
	c->gid = z.gid;
	c->nonce = z.nonce;
	c->key = z.key;
	c->tkt_len = z.tlen;
	memcpy(c->tkt_blob, z.tdata, z.tlen);
	do
		c->challenge = so_rand64(c->osd);
	while (c->challenge == 0);
	item[0] = 1; /* CephXAuthorizeChallenge: v = 1, u64 */
	wri_le64_put(item + 1, c->challenge);
	memset(rep, 0, sizeof(*rep));
	if (wri_cx_seal(so_ctx(c->osd), &c->key, WRI_CX_USAGE_AUTHORIZE_CHALLENGE, item, sizeof(item), c->pay, sizeof(c->pay), &out_n) != WR_OK) {
		wri_secure_zero(&z, sizeof(z));
		return deny(c, rep, -13);
	}
	rep->payload = c->pay; /* raw ciphertext: no length prefix (cephx.md 3.3 step 2) */
	rep->payload_len = (uint32_t)out_n;
	c->stage = 1;
	wri_secure_zero(&z, sizeof(z));
	return SIM_AUTH_MORE;
}

int so_auth_more(void *ctx, const uint8_t *p, uint32_t n, sim_m2_auth_reply *rep)
{
	sim_osd_conn *c = (sim_osd_conn *)ctx;
	so_authz z;
	uint8_t item[13 + SIM_SEC_SECRET_MAX];
	size_t out_n = 0, item_len = 9;
	uint32_t slen = 0;
	const uint8_t *sec;

	if (c->stage != 1 || authz_parse(c, p, n, &z) != 0) {
		wri_secure_zero(&z, sizeof(z));
		return deny(c, rep, -13);
	}
	if (z.have_challenge != 1 || z.plus_one != c->challenge + 1u || z.nonce != c->nonce || z.gid != c->gid || z.tlen != c->tkt_len ||
	    memcmp(z.tdata, c->tkt_blob, z.tlen) != 0 || c->osd->cfg.fault.refuse_auth) {
		wri_secure_zero(&z, sizeof(z));
		return deny(c, rep, -13);
	}
	/* CephXAuthorizeReply: v = 1 (no connection secret: crc mode), u64 nonce + 1; v = 2 adds the secret as a string (secure) */
	sec = sim_m2_conn_secret(c->m2, &slen);
	item[0] = sec != NULL ? 2u : 1u;
	wri_le64_put(item + 1, c->nonce + 1u);
	if (sec != NULL) {
		wri_le32_put(item + 9, slen);
		memcpy(item + 13, sec, slen);
		item_len = 13u + slen;
	}
	memset(rep, 0, sizeof(*rep));
	wri_le32_put(c->pay, 0);
	if (wri_cx_seal(so_ctx(c->osd), &c->key, WRI_CX_USAGE_AUTHORIZE_REPLY, item, item_len, c->pay + 4, sizeof(c->pay) - 4u, &out_n) !=
	    WR_OK) {
		wri_secure_zero(item, sizeof(item));
		wri_secure_zero(&z, sizeof(z));
		return deny(c, rep, -13);
	}
	wri_secure_zero(item, sizeof(item));
	wri_le32_put(c->pay, (uint32_t)out_n); /* length-prefixed (cephx.md 3.3 step 4) */
	rep->payload = c->pay;
	rep->payload_len = (uint32_t)(4u + out_n);
	rep->key_len = c->key.len;
	memcpy(rep->key, c->key.secret, c->key.len);
	rep->global_id = c->gid;
	c->stage = 2;
	wri_secure_zero(&z, sizeof(z));
	return SIM_AUTH_DONE;
}

const sim_sec_log *sim_osd_secrets(const sim_osd *o) { return &o->sec_log; }
