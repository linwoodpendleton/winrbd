/* SPDX-License-Identifier: MIT */
/*
 * In-session renewal (core/src/auth/wri_cx_renew.c, docs/spec/cephx.md 3.6 B, 2.11): the request
 * structure against vectors/monclient/mauth-renewal-scrubbed.json and the reply handling against
 * vectors/monclient/mauthreply-renewal-scrubbed.json.
 *
 * The vectors are scrubbed: tickets and ciphertexts are 0xEE filler. The request is compared on every
 * byte outside the scrubbed regions, and its authorizer proof is opened with the session key and
 * checked field by field. The reply is replayed twice: as scrubbed (it must be refused as undecryptable
 * and change nothing) and with each scrubbed msg_a / ticket blob replaced by a valid one of the very
 * same length, which exercises the exact sizes and the layout of a real three-ticket reply.
 */
#include "auth_cx_srv.h"

#define MAUTH_FRONT_PAYLOAD 26u  /* paxos prefix 18 + protocol 4 + blob length 4 */
#define MAUTHREPLY_BL 20u        /* protocol 4 + result 4 + global_id 8 + blob length 4 */

typedef struct region {
	size_t off, len;
} region;

static int regions(const wrt_json *j, wrt_tok root, region *out, size_t max, size_t *n)
{
	wrt_tok l = wrt_json_get(j, root, "scrubbed_regions");
	size_t i;

	*n = wrt_json_count(j, l);
	if (*n > max)
		return -1;
	for (i = 0; i < *n; i++) {
		wrt_tok r = wrt_json_at(j, l, i);

		out[i].off = (size_t)wrt_json_int(j, wrt_json_get(j, r, "offset"), NULL);
		out[i].len = (size_t)wrt_json_int(j, wrt_json_get(j, r, "length"), NULL);
	}
	return 0;
}

/* A client holding an AUTH ticket like the one of the capture: type-2 keys, 151 data bytes, id 2. */
static void make_client(cxt_env *e, wr_key *ak, wr_key *ok, uint64_t gid)
{
	wr_key pk = cxt_key(WR_KEY_TYPE_AES256K, 5);
	cxt_dopt o;
	uint8_t buf[4096];
	size_t n;

	WRT_CHECK(cxt_env_init(e, "client.winrbd", &pk, 0) == 0);
	*ak = cxt_key(WR_KEY_TYPE_AES256K, 6);
	*ok = cxt_key(WR_KEY_TYPE_AES256K, 7);
	cxt_rng_free();
	cxt_dopt_default(e, &o, ak, ok);
	o.auth.blob_data = 151;
	o.auth.secret_id = 2;
	o.extra[0].msga_key = ak;
	n = cxt_build_done(e, &o, buf, sizeof(buf));
	WRT_CHECK_STATUS(WR_OK, cxt_mon_hs(e, buf, n, gid, WRI_CONN_MODE_CRC, NULL, NULL, NULL, NULL));
}

static void test_request(void)
{
	wrt_json j;
	wrt_tok root;
	uint8_t *front = NULL;
	size_t fn = 0, plen, i;
	region rg[4];
	size_t nrg = 0;
	cxt_env e;
	wr_key ak, ok;
	uint8_t out[512];
	wri_wr w;
	const uint8_t *pay;
	uint64_t nonce1 = 0, nonce2;

	if (wrt_json_load_vec(&j, "monclient/mauth-renewal-scrubbed.json") != 0) {
		WRT_CHECK(!"renewal request vector loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "front_hex", &front, &fn) == 0);
	WRT_CHECK(regions(&j, root, rg, 4, &nrg) == 0 && nrg == 2);
	/* auth_payload = blob inside the front: paxos prefix, protocol, then u32 length */
	plen = wri_le32_get(front + MAUTH_FRONT_PAYLOAD - 4);
	WRT_CHECK(plen == 255 && fn == MAUTH_FRONT_PAYLOAD + plen + 4);
	pay = front + MAUTH_FRONT_PAYLOAD;

	make_client(&e, &ak, &ok, 0x3c84); /* the global id of the capture */
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, wri_cx_renew_build(&e.c, 0x15, &w));
	WRT_CHECK(wri_wr_len(&w) == plen);
	if (wri_wr_len(&w) == plen) {
		/* every byte outside the 0xEE regions is the same: header 0x0200, authorizer v 1, global id,
		 * service 0x20, the ticket header (v, id 2, length 151), proof length 67, request v 1, mask 0x15 */
		for (i = 0; i < plen; i++) {
			int scrubbed = 0;
			size_t k;

			for (k = 0; k < nrg; k++)
				if (i + MAUTH_FRONT_PAYLOAD >= rg[k].off && i + MAUTH_FRONT_PAYLOAD < rg[k].off + rg[k].len)
					scrubbed = 1;
			if (!scrubbed && out[i] != pay[i]) {
				WRT_CHECK(!"renewal request differs outside the scrubbed regions");
				fprintf(stderr, "  offset %zu: %02x vs %02x\n", i, out[i], pay[i]);
				break;
			}
		}
		WRT_CHECK(wri_le16_get(out) == 0x0200);
		/* the ticket is the held one, verbatim, and the proof opens under the AUTH session key */
		WRT_CHECK(memcmp(out + 2 + 1 + 8 + 4, e.c.ticket[0].blob, e.c.ticket[0].blob_len) == 0);
		{
			const uint8_t *item = NULL;
			size_t il = 0;
			uint8_t scratch[256];

			WRT_CHECK_STATUS(WR_OK, wri_cx_open(&e.x, &ak, WRI_CX_USAGE_AUTHORIZE, out + rg[1].off - MAUTH_FRONT_PAYLOAD,
							    rg[1].len, scratch, sizeof(scratch), &item, &il));
			WRT_CHECK(il == 18 && item[0] == 2 && item[9] == 0 && wri_le64_get(item + 10) == 0);
			nonce1 = il == 18 ? wri_le64_get(item + 1) : 0;
		}
	}
	WRT_CHECK(e.c.renew_mask == 0x15u);

	/* a second request draws a fresh nonce; mask 0 means the configured mask without AUTH; the AUTH bit is dropped */
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, wri_cx_renew_build(&e.c, 0, &w));
	WRT_CHECK(wri_le32_get(out + wri_wr_len(&w) - 4) == 0x04u && out[wri_wr_len(&w) - 5] == 1);
	{
		const uint8_t *item = NULL;
		size_t il = 0;
		uint8_t scratch[256];

		WRT_CHECK_STATUS(WR_OK, wri_cx_open(&e.x, &ak, WRI_CX_USAGE_AUTHORIZE, out + wri_wr_len(&w) - 5 - 67, 67,
						    scratch, sizeof(scratch), &item, &il));
		nonce2 = il == 18 ? wri_le64_get(item + 1) : nonce1;
		WRT_CHECK(nonce2 != nonce1);
	}
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_OK, wri_cx_renew_build(&e.c, 0x35, &w));
	WRT_CHECK(wri_le32_get(out + wri_wr_len(&w) - 4) == 0x15u);

	/* refusals */
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_renew_build(&e.c, WRI_CX_SERVICE_AUTH, &w));
	wri_wr_init(&w, out, 100);
	WRT_CHECK_STATUS(WR_E_TOOBIG, wri_cx_renew_build(&e.c, 0x15, &w));
	g_rng.strict = 1;
	g_rng.n = 0;
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_E_HOST_RANDOM, wri_cx_renew_build(&e.c, 0x15, &w));
	cxt_rng_free();
	e.x.now.mono_ms = CXT_T0 + 259200000ull; /* the AUTH ticket is gone */
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_renew_build(&e.c, 0x15, &w));
	e.x.now.mono_ms = CXT_T0 + 1;
	e.c.global_id = 0;
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_E_AUTH_GID0, wri_cx_renew_build(&e.c, 0x15, &w));
	wri_cx_forget(&e.c);
	wri_wr_init(&w, out, sizeof(out));
	WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_renew_build(&e.c, 0x15, &w));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_renew_build(NULL, 0x15, &w));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_renew_build(&e.c, 0x15, NULL));
	cxt_env_free(&e);
	free(front);
	wrt_json_free(&j);
}

static void test_reply(void)
{
	wrt_json j;
	wrt_tok root;
	uint8_t *front = NULL, *bl;
	size_t fn = 0, bn, i, nrg = 0;
	region rg[8];
	cxt_env e;
	wr_key ak, ok, nk;
	uint8_t old_osd_blob[200], sess_copy[WR_KEY_MAX];
	uint32_t old_len;
	wri_rd r;

	if (wrt_json_load_vec(&j, "monclient/mauthreply-renewal-scrubbed.json") != 0) {
		WRT_CHECK(!"renewal reply vector loads");
		return;
	}
	root = wrt_json_root(&j);
	WRT_CHECK(wrt_json_get_hex(&j, root, "front_hex", &front, &fn) == 0);
	WRT_CHECK(regions(&j, root, rg, 8, &nrg) == 0 && nrg == 6);
	WRT_CHECK(wri_le32_get(front) == 2 && wri_le32_get(front + 4) == 0); /* protocol 2, result 0 */
	bn = wri_le32_get(front + 16);
	WRT_CHECK(fn >= MAUTHREPLY_BL + bn);
	bl = (uint8_t *)malloc(bn);
	WRT_CHECK(bl != NULL);
	memcpy(bl, front + MAUTHREPLY_BL, bn);

	/* structure: response header 0x0200 / 0, reply v 1, three tickets MON, OSD, MGR with ticket_enc 0 */
	wri_rd_init(&r, bl, bn);
	WRT_CHECK(wri_rd_u16(&r) == 0x0200 && wri_rd_i32(&r) == 0 && wri_rd_u8(&r) == 1 && wri_rd_u32(&r) == 3);

	make_client(&e, &ak, &ok, 0x3c84);
	/* no request pending: a reply (here the scrubbed one, which would be refused anyway) is WR_E_STATE first */
	WRT_CHECK(e.c.renew_mask == 0);
	WRT_CHECK_STATUS(WR_E_STATE, wri_cx_renew_handle(&e.c, bl, bn));
	WRT_CHECK(e.c.err.status == WR_E_STATE);
	memset(&e.c.err, 0, sizeof(e.c.err));
	e.c.renew_mask = 0x15;
	old_len = e.c.ticket[1].blob_len;
	memcpy(old_osd_blob, e.c.ticket[1].blob, old_len);
	memcpy(sess_copy, e.c.ticket[1].session_key.secret, WR_KEY_MAX);

	/* scrubbed as it is: msg_a is filler, so it is refused and the OSD ticket stays as it was */
	WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_renew_handle(&e.c, bl, bn));
	WRT_CHECK(e.c.ticket[1].blob_len == old_len && memcmp(e.c.ticket[1].blob, old_osd_blob, old_len) == 0);
	WRT_CHECK(memcmp(e.c.ticket[1].session_key.secret, sess_copy, WR_KEY_MAX) == 0);
	{
		wri_cx_client *c = &e.c;

		memset(&c->err, 0, sizeof(c->err));
	}

	/* repair the filler: valid msg_a (same length) under the AUTH session key and a valid blob header */
	nk = cxt_key(WR_KEY_TYPE_AES256K, 90);
	e.x.now.mono_ms = 7000000;
	for (i = 0; i < 3; i++) {
		const region *ma = &rg[2 * i], *tb = &rg[2 * i + 1];
		uint8_t tmp[256], blob[256];
		size_t n = cxt_msga(&e, &ak, &nk, 3600, 0, tmp, sizeof(tmp));

		WRT_CHECK(n == ma->len);
		memcpy(bl + ma->off - MAUTHREPLY_BL, tmp, ma->len);
		(void)cxt_blob(blob, 100 + i, (uint32_t)tb->len - 13u, 0xC0);
		memcpy(bl + tb->off - MAUTHREPLY_BL, blob, tb->len);
	}
	/* the shapes of the capture: msg_a 102, blobs 179 / 191 / 164 */
	WRT_CHECK(rg[0].len == 102 && rg[1].len == 179 && rg[3].len == 191 && rg[5].len == 164);
	/* every strict prefix is refused and changes nothing */
	for (i = 0; i < bn; i++) {
		WRT_CHECK(wri_cx_renew_handle(&e.c, bl, i) != WR_OK);
		WRT_CHECK(memcmp(e.c.ticket[1].session_key.secret, sess_copy, WR_KEY_MAX) == 0 || i > 400);
	}
	WRT_CHECK_STATUS(WR_OK, wri_cx_renew_handle(&e.c, bl, bn));
	{
		const wri_cx_ticket *t = &e.c.ticket[1];

		WRT_CHECK(t->have && t->service == WRI_CX_SERVICE_OSD && t->secret_id == 101);
		WRT_CHECK(t->blob_len == 191 && t->blob[0] == 1 && wri_le32_get(t->blob + 9) == 191 - 13);
		WRT_CHECK(memcmp(t->session_key.secret, nk.secret, nk.len) == 0 && t->session_key.type == 2);
		WRT_CHECK_U64(t->valid_until_ms, 7000000ull + 3600000ull);
		WRT_CHECK_U64(t->renew_at_ms, 7000000ull + 3600000ull - 900000ull); /* 3/4 of the validity */
	}
	WRT_CHECK(e.c.renew_mask == 0);
	/* the same reply again (a replay on the monitor session) is not a pending answer: refused, nothing changes */
	{
		uint32_t gen = e.c.ticket[1].gen;
		uint64_t until = e.c.ticket[1].valid_until_ms;

		e.x.now.mono_ms += 600000;
		WRT_CHECK_STATUS(WR_E_STATE, wri_cx_renew_handle(&e.c, bl, bn));
		WRT_CHECK(e.c.ticket[1].gen == gen && e.c.ticket[1].valid_until_ms == until);
		e.x.now.mono_ms -= 600000;
	}
	WRT_CHECK(e.c.ticket[0].session_key.type == 2 && memcmp(e.c.ticket[0].session_key.secret, ak.secret, ak.len) == 0);
	/* MON and MGR tickets were not kept; the AUTH ticket is untouched */
	WRT_CHECK(wri_cx_ticket_get(&e.c, WRI_CX_SERVICE_MON) == NULL && e.c.ticket[0].secret_id == 2);

	/* header problems */
	{
		uint8_t save[8];

		memcpy(save, bl, 8);
		e.c.renew_mask = 0x15;
		wri_le16_put(bl, 0x0100);
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, wri_cx_renew_handle(&e.c, bl, bn));
		memcpy(bl, save, 8);
		wri_le16_put(bl, 0x0200);
		wri_le32_put(bl + 2, (uint32_t)-13);
		WRT_CHECK_STATUS(WR_E_AUTH_RESULT, wri_cx_renew_handle(&e.c, bl, bn));
		WRT_CHECK(e.c.err.status != WR_OK);
		memcpy(bl, save, 8);
	}
	/* the request asked for the OSD ticket and the reply has none: refused, not silently ignored */
	{
		cxt_tk t[1];
		uint8_t pay[1024];
		wri_wr w;

		memset(t, 0, sizeof(t));
		t[0].service = WRI_CX_SERVICE_MON;
		t[0].key = nk;
		t[0].val_s = 60;
		t[0].blob_data = 40;
		t[0].msga_key = &ak;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		cxt_put_ticket_reply(&e, &w, t, 1);
		e.c.renew_mask = 0x15;
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
		e.c.renew_mask = 0x01; /* a request for MON only: nothing of ours to store, fine */
		WRT_CHECK_STATUS(WR_OK, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
		/* a ticket for the AUTH service, an encrypted blob, a zero validity, an oversize ticket */
		t[0].service = WRI_CX_SERVICE_AUTH;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		cxt_put_ticket_reply(&e, &w, t, 1);
		e.c.renew_mask = 0x15;
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
		t[0].service = WRI_CX_SERVICE_OSD;
		t[0].enc = 1;
		t[0].enc_key = &ak;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		cxt_put_ticket_reply(&e, &w, t, 1);
		e.c.renew_mask = 0x15;
		WRT_CHECK_STATUS(WR_E_AUTH_PROTO, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
		t[0].enc = 0;
		t[0].val_s = 0;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		cxt_put_ticket_reply(&e, &w, t, 1);
		e.c.renew_mask = 0x15;
		WRT_CHECK_STATUS(WR_E_AUTH_TICKET_EXPIRED, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
		t[0].val_s = 60;
		t[0].blob_data = 3000;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		{
			uint8_t big[4096];
			wri_wr wb;

			wri_wr_init(&wb, big, sizeof(big));
			wri_wr_u16(&wb, 0x0200);
			wri_wr_i32(&wb, 0);
			cxt_put_ticket_reply(&e, &wb, t, 1);
			e.c.renew_mask = 0x15;
			WRT_CHECK_STATUS(WR_E_AUTH_TICKET_TOOBIG, wri_cx_renew_handle(&e.c, big, wri_wr_len(&wb)));
		}
		/* a ticket sealed with the principal key instead of the AUTH session key */
		t[0].blob_data = 40;
		t[0].msga_key = &e.c.principal;
		wri_wr_init(&w, pay, sizeof(pay));
		wri_wr_u16(&w, 0x0200);
		wri_wr_i32(&w, 0);
		cxt_put_ticket_reply(&e, &w, t, 1);
		e.c.renew_mask = 0x15;
		WRT_CHECK_STATUS(WR_E_AUTH_DECRYPT, wri_cx_renew_handle(&e.c, pay, wri_wr_len(&w)));
	}
	/* with no AUTH session key there is nothing to open the reply with */
	wri_cx_forget(&e.c);
	WRT_CHECK_STATUS(WR_E_STATE, wri_cx_renew_handle(&e.c, bl, bn));
	WRT_CHECK_STATUS(WR_E_INVAL, wri_cx_renew_handle(NULL, bl, bn));
	cxt_env_free(&e);
	free(bl);
	free(front);
	wrt_json_free(&j);
}

int main(void)
{
	test_request();
	test_reply();
	return wrt_finish();
}
