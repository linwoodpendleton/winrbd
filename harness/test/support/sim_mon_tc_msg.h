/* SPDX-License-Identifier: MIT */
/*
 * sim_mon_tc_msg.h - the message half of the scripted monitor client (see sim_mon_tc.h, which includes
 * this file at its end): sending MMonGetMap, MMonSubscribe and a renewal MAuth, and reading the MESSAGE
 * frames the monitor sent. Not to be included on its own.
 */
#ifndef SIM_MON_TC_MSG_H
#define SIM_MON_TC_MSG_H

/* ---- messages -------------------------------------------------------------------------------------------- */

static inline void mc_send(mc *m, uint16_t type, const uint8_t *front, uint32_t flen)
{
	(void)tc_send_msg(&m->t, m->conn->m2, ++m->seq, 0, type, front, flen, NULL, 0, NULL, 0);
}

static inline void mc_send_getmap(mc *m) { mc_send(m, 5, NULL, 0); }

static inline void mc_send_subscribe(mc *m, const wri_sub_item *items, size_t n)
{
	uint8_t buf[512];
	wri_wr w;

	wri_wr_init(&w, buf, sizeof(buf));
	wri_mmonsubscribe_encode(&w, items, n, "host1");
	if (!wri_wr_ok(&w))
		abort();
	mc_send(m, 15, buf, (uint32_t)wri_wr_len(&w));
}

/* MAuth for a renewal (cephx.md 3.6 B): request 0x0200, authorizer for AUTH with the held AUTH ticket, the
 * service request. `gid` / `blob` / `proof_key` let a test forge a bad one. */
static inline void mc_send_renew_ex(mc *m, uint32_t mask, uint64_t gid, const mt_ticket *ticket, const wr_key *proof_key,
				    uint8_t have_challenge)
{
	uint8_t item[32], ct[256], pay[2048], front[2200], blob[SIM_MON_BLOB_MAX + 16];
	size_t ct_n = 0, bl_n;
	wri_wr w, pw;

	wri_wr_init(&w, item, sizeof(item));
	wri_wr_u8(&w, 2);
	wri_wr_u64(&w, 0xabcdef0102030405ull); /* nonce */
	wri_wr_u8(&w, have_challenge);
	wri_wr_u64(&w, 0);
	if (wri_cx_seal(&m->x, proof_key, WRI_CX_USAGE_AUTHORIZE, item, wri_wr_len(&w), ct, sizeof(ct), &ct_n) != WR_OK)
		abort();
	blob[0] = 1;
	wri_le64_put(blob + 1, ticket->secret_id);
	wri_le32_put(blob + 9, ticket->blob_len);
	memcpy(blob + 13, ticket->blob, ticket->blob_len);
	bl_n = 13u + ticket->blob_len;
	wri_wr_init(&pw, pay, sizeof(pay));
	wri_wr_u16(&pw, WRI_CX_REQ_GET_PRINCIPAL_SESSION_KEY);
	wri_wr_u8(&pw, WRI_CX_AUTHORIZER_V);
	wri_wr_u64(&pw, gid);
	wri_wr_u32(&pw, WRI_CX_SERVICE_AUTH);
	wri_wr_bytes(&pw, blob, bl_n);
	wri_wr_u32(&pw, (uint32_t)ct_n);
	wri_wr_bytes(&pw, ct, ct_n);
	wri_wr_u8(&pw, 1);
	wri_wr_u32(&pw, mask);
	wri_wr_init(&w, front, sizeof(front));
	wri_mauth_encode(&w, WRI_AUTH_METHOD_CEPHX, pay, wri_wr_len(&pw), 0);
	if (!wri_wr_ok(&pw) || !wri_wr_ok(&w))
		abort();
	mc_send(m, 17, front, (uint32_t)wri_wr_len(&w));
}

static inline void mc_send_renew(mc *m, uint32_t mask) { mc_send_renew_ex(m, mask, m->gid, &m->auth, &m->auth_key, 0); }

/* A server MESSAGE seen by the client: header2 decoded and the front. */
typedef struct mc_msg {
	wri_m2_hdr2 h;
	const uint8_t *front;
	uint32_t flen;
} mc_msg;

/* Pull, then return the number of MESSAGE frames received since the last mc_clear_frames(). */
static inline size_t mc_nmsgs(mc *m)
{
	size_t i, k = 0;

	mc_pull(m);
	for (i = 0; i < m->t.nfr; i++)
		if (m->t.fr[i].tag == WRI_M2_TAG_MESSAGE)
			k++;
	return k;
}

/* The k-th MESSAGE since the last mc_clear_frames(); returns 0 when there is none. */
static inline int mc_msg_at(const mc *m, size_t k, mc_msg *out)
{
	size_t i;

	for (i = 0; i < m->t.nfr; i++) {
		const tc_frame *f = &m->t.fr[i];

		if (f->tag != WRI_M2_TAG_MESSAGE)
			continue;
		if (k-- != 0)
			continue;
		if (f->len[0] != WRI_M2_HDR2_LEN || wri_m2_hdr2_decode(f->seg[0], f->len[0], &out->h) != WR_OK)
			return 0;
		out->front = f->nseg > 1 ? f->seg[1] : NULL;
		out->flen = f->nseg > 1 ? f->len[1] : 0;
		return 1;
	}
	return 0;
}

#endif /* SIM_MON_TC_MSG_H */
